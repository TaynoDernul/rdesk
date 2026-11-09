//! Connections by device ID, through iroh.
//!
//! A PC is dialled by its ID, which is the public half of its host key. iroh
//! finds the PC through n0's discovery service, then tries to connect directly
//! with hole punching. When that fails, packets go through an n0 relay server.
//! Either way the QUIC connection is encrypted end to end and the relay only
//! forwards ciphertext. During the handshake iroh also checks that the other
//! side holds the private key for the ID, so the ID itself pins the host.

use crate::identity::Trust;
use crate::proto::{ALPN_PAIR, ALPN_SESSION};
use anyhow::{anyhow, Result};
use iroh::endpoint::{
    presets, AfterHandshakeOutcome, Connection, EndpointHooks, QuicTransportConfig, Side, VarInt,
};
use iroh::{Endpoint, EndpointId, RelayMode, RelayUrl, SecretKey};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, OnceCell};

pub const DATAGRAM_BUFFER: usize = 8 * 1024 * 1024;
/// Kept small on purpose: on a slow path a deep queue only adds seconds of
/// delay. The video loop skips frames well before this fills.
pub const DATAGRAM_SEND_BUFFER: usize = 2 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ONLINE_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_DELAY: Duration = Duration::from_secs(2);
/// Test switch: the client may only use relays, to exercise the internet path.
const RELAY_ONLY_ENV: &str = "RDESK_RELAY_ONLY";

const CODE_REJECTED: u32 = 1;
const CODE_UNAVAILABLE: u32 = 3;
const NOT_PAIRED: &str = "это устройство не добавлено на удалённом ПК";
const PAIRING_CLOSED: &str = "на удалённом ПК не запущено добавление устройства";
const NOT_LISTENING: &str = "на удалённом ПК не включены подключения";
/// rdesk PCs announce themselves on the local network under this name, so
/// they are found there without the internet and listed for adding.
const MDNS_SERVICE: &str = "rdesk";

/// Checks a relay address typed in the settings. Empty means n0's relays.
pub fn parse_relay(text: &str) -> Result<Option<RelayUrl>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if !text.starts_with("https://") && !text.starts_with("http://") {
        return Err(anyhow!("адрес ретранслятора должен начинаться с https://"));
    }
    text.parse().map(Some).map_err(|_| anyhow!("неверный адрес ретранслятора"))
}

/// The user's own relay server from the settings, if one is set.
pub fn custom_relay() -> Option<RelayUrl> {
    let text = crate::system::ui_setting("relay")?;
    parse_relay(text.as_str()?).ok().flatten()
}

/// Internet endpoints: n0's discovery, the chosen relay, and the local network.
fn internet_builder(advertise: bool) -> iroh::endpoint::Builder {
    let mut builder = Endpoint::builder(presets::N0)
        .address_lookup(MdnsAddressLookup::builder().service_name(MDNS_SERVICE).advertise(advertise));
    if let Some(url) = custom_relay() {
        builder = builder.relay_mode(RelayMode::custom([url]));
    }
    builder
}

/// IDs of rdesk PCs that accept connections on this local network.
pub async fn scan_local(wait: Duration) -> Result<Vec<String>> {
    use n0_future::StreamExt;
    let mut seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
        .map_err(|_| anyhow!("system RNG failed"))?;
    let me = SecretKey::from_bytes(&seed).public();
    let mdns = MdnsAddressLookup::builder()
        .service_name(MDNS_SERVICE)
        .advertise(false)
        .build(me)
        .map_err(|e| anyhow!("поиск в сети недоступен: {e}"))?;
    let mut events = mdns.subscribe().await;
    let mut found = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        if let DiscoveryEvent::Discovered { endpoint_info, .. } = event {
            let id = endpoint_info.endpoint_id.to_string();
            if !found.contains(&id) {
                found.push(id);
            }
        }
    }
    Ok(found)
}

fn transport() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER)
        .keep_alive_interval(Duration::from_secs(3))
        .build()
}

fn reject(reason: &str) -> AfterHandshakeOutcome {
    AfterHandshakeOutcome::Reject {
        error_code: VarInt::from_u32(CODE_REJECTED),
        reason: reason.as_bytes().to_vec(),
    }
}

/// Decides right after the handshake, before any stream is opened, whether a
/// peer may stay connected.
#[derive(Debug)]
struct Gate {
    pairing_open: Arc<AtomicBool>,
}

impl Gate {
    fn decide(&self, incoming: bool, alpn: &[u8], remote: &str) -> AfterHandshakeOutcome {
        if !incoming {
            return AfterHandshakeOutcome::accept();
        }
        if alpn == ALPN_SESSION {
            // Read on every handshake so a revoked device is refused at once,
            // and an unreadable or forged list refuses everyone.
            if Trust::load().is_ok_and(|t| t.is_client_allowed(remote)) {
                return AfterHandshakeOutcome::accept();
            }
            crate::log_event(&format!("rejected unpaired client {}", crate::identity::short_id(remote)));
            return reject(NOT_PAIRED);
        }
        if alpn == ALPN_PAIR {
            if self.pairing_open.load(Ordering::SeqCst) {
                return AfterHandshakeOutcome::accept();
            }
            return reject(PAIRING_CLOSED);
        }
        reject("unknown protocol")
    }
}

impl EndpointHooks for Gate {
    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        let incoming = matches!(conn.side(), Side::Server);
        let outcome = self.decide(incoming, conn.alpn(), &conn.remote_id().to_string());
        async move { outcome }
    }
}

type Slot = Mutex<Option<mpsc::UnboundedSender<Connection>>>;

/// The accepting side of this PC. One per process, because one ID must not be
/// announced by two endpoints. Sessions and pairing share it and are told
/// apart by protocol name.
pub struct HostNode {
    endpoint: Endpoint,
    pairing_open: Arc<AtomicBool>,
    sessions: Slot,
    pairings: Slot,
}

static HOST: OnceCell<Arc<HostNode>> = OnceCell::const_new();

/// Starts this PC's host endpoint on first use and returns it afterwards.
pub async fn host_node(key: &SecretKey) -> Result<Arc<HostNode>> {
    HOST.get_or_try_init(|| async {
        let pairing_open = Arc::new(AtomicBool::new(false));
        let endpoint = bind_host(key.clone(), pairing_open.clone(), false).await?;
        // Other devices find this PC through the address it publishes once a
        // relay is reached. Handing out a code before that makes them fail.
        if tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online()).await.is_err() {
            crate::log_event("no relay reached yet; only direct connections may work");
        }
        let node = Arc::new(HostNode {
            endpoint,
            pairing_open,
            sessions: Mutex::new(None),
            pairings: Mutex::new(None),
        });
        tokio::spawn(accept_loop(node.clone()));
        Ok::<_, anyhow::Error>(node)
    })
    .await
    .cloned()
}

async fn bind_host(key: SecretKey, pairing_open: Arc<AtomicBool>, local_only: bool) -> Result<Endpoint> {
    let builder = if local_only {
        Endpoint::builder(presets::Minimal).relay_mode(iroh::RelayMode::Disabled)
    } else {
        internet_builder(true)
    };
    builder
        .secret_key(key)
        .alpns(vec![ALPN_SESSION.to_vec(), ALPN_PAIR.to_vec()])
        .transport_config(transport())
        .hooks(Gate { pairing_open })
        .bind()
        .await
        .map_err(|e| anyhow!("не удалось запустить сеть: {e}"))
}

async fn accept_loop(node: Arc<HostNode>) {
    while let Some(incoming) = node.endpoint.accept().await {
        let node = node.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else { return };
            match accepting.await {
                Ok(conn) => node.route(conn),
                // Mostly devices the gate turned away.
                Err(e) => crate::log_event(&format!("handshake failed: {e}")),
            }
        });
    }
}

impl HostNode {
    pub fn id(&self) -> String {
        self.endpoint.id().to_string()
    }

    fn route(&self, conn: Connection) {
        let slot = if conn.alpn() == ALPN_SESSION {
            &self.sessions
        } else if conn.alpn() == ALPN_PAIR {
            &self.pairings
        } else {
            return conn.close(VarInt::from_u32(CODE_REJECTED), b"unknown protocol");
        };
        let sender = slot.lock().expect("slot lock").clone();
        let unhandled = match sender {
            Some(sender) => sender.send(conn).err().map(|e| e.0),
            None => Some(conn),
        };
        if let Some(conn) = unhandled {
            conn.close(VarInt::from_u32(CODE_UNAVAILABLE), NOT_LISTENING.as_bytes());
        }
    }

    /// From now on, session connections arrive on the returned channel.
    pub fn listen_sessions(&self) -> mpsc::UnboundedReceiver<Connection> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.sessions.lock().expect("slot lock") = Some(tx);
        rx
    }

    pub fn stop_sessions(&self) {
        *self.sessions.lock().expect("slot lock") = None;
    }

    /// Lets unknown devices complete a handshake for pairing until closed.
    pub fn open_pairing(&self) -> mpsc::UnboundedReceiver<Connection> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.pairings.lock().expect("slot lock") = Some(tx);
        self.pairing_open.store(true, Ordering::SeqCst);
        rx
    }

    pub fn close_pairing(&self) {
        self.pairing_open.store(false, Ordering::SeqCst);
        *self.pairings.lock().expect("slot lock") = None;
    }
}

/// An endpoint for connecting out with this PC's client key.
pub async fn client_endpoint(key: &SecretKey) -> Result<Endpoint> {
    let mut builder = internet_builder(false).secret_key(key.clone()).transport_config(transport());
    if std::env::var_os(RELAY_ONLY_ENV).is_some() {
        builder = builder.clear_ip_transports();
    }
    builder.bind().await.map_err(|e| anyhow!("не удалось запустить сеть: {e}"))
}

pub fn parse_id(text: &str) -> Result<EndpointId> {
    text.trim().parse().map_err(|_| anyhow!("неверный ID удалённого ПК"))
}

/// Retries until the deadline: a PC that has just come online may not have
/// published its address yet, and lookups can briefly fail. Rejections by the
/// host arrive after the handshake, as a closed connection, so they are not
/// retried here.
pub async fn dial(endpoint: &Endpoint, host_id: &str, alpn: &[u8]) -> Result<Connection> {
    let id = parse_id(host_id)?;
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let mut last_error = None;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, endpoint.connect(id, alpn)).await {
            Ok(Ok(conn)) => return Ok(conn),
            Ok(Err(e)) => last_error = Some(e.to_string()),
            Err(_) => break,
        }
        tokio::time::sleep(RETRY_DELAY.min(deadline.saturating_duration_since(tokio::time::Instant::now()))).await;
    }
    crate::log_event(&format!("dial failed: {}", last_error.as_deref().unwrap_or("timeout")));
    Err(anyhow!(
        "удалённый ПК не найден: он выключен, без интернета или в rdesk на нём не включены подключения"
    ))
}

pub fn peer_id(conn: &Connection) -> String {
    conn.remote_id().to_string()
}

/// Round-trip time of the path in use and whether it goes through a relay.
pub fn route_info(conn: &Connection) -> Option<(Duration, bool)> {
    conn.paths().iter().find(|p| p.is_selected()).map(|p| (p.rtt(), p.is_relay()))
}

fn relay_report(endpoint: &Endpoint) -> String {
    use iroh::Watcher;
    let statuses = endpoint.home_relay_status().get();
    if statuses.is_empty() {
        return "ретранслятор не выбран".to_string();
    }
    statuses
        .iter()
        .map(|s| match (s.is_connected(), s.last_error()) {
            (true, _) => format!("{}: подключён", s.url()),
            (false, Some(e)) => format!("{}: ошибка {e}", s.url()),
            (false, None) => format!("{}: не подключён", s.url()),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Checks each step a real connection depends on, with throwaway keys:
/// reaching a relay, publishing an address, and dialling by ID alone.
pub async fn self_check() -> Result<String> {
    const ALPN_CHECK: &[u8] = b"rdesk-check/1";
    let random = || -> Result<SecretKey> {
        let mut bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
            .map_err(|_| anyhow!("system RNG failed"))?;
        Ok(SecretKey::from_bytes(&bytes))
    };
    let mut report = Vec::new();

    let listener = Endpoint::builder(presets::N0)
        .secret_key(random()?)
        .alpns(vec![ALPN_CHECK.to_vec()])
        .bind()
        .await
        .map_err(|e| anyhow!("не удалось запустить сеть: {e}"))?;
    let online = tokio::time::timeout(Duration::from_secs(15), listener.online()).await.is_ok();
    report.push(format!("1. Связь с ретранслятором: {}", if online { "есть" } else { "НЕТ за 15 с" }));
    report.push(format!("   {}", relay_report(&listener)));

    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move {
            let incoming = listener.accept().await?;
            incoming.accept().ok()?.await.ok()
        })
    };
    // Publishing happens in the background once the relay is known.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let dialer = client_endpoint(&random()?).await?;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(30), dialer.connect(listener.id(), ALPN_CHECK)).await;
    match result {
        Ok(Ok(conn)) => {
            let path = match route_info(&conn) {
                Some((rtt, true)) => format!("через ретранслятор, RTT {} мс", rtt.as_millis()),
                Some((rtt, false)) => format!("напрямую, RTT {} мс", rtt.as_millis()),
                None => "путь неизвестен".to_string(),
            };
            report.push(format!(
                "2. Подключение только по ID: УСПЕШНО за {:.1} с ({path})",
                started.elapsed().as_secs_f64()
            ));
            conn.close(0u32.into(), b"check done");
        }
        Ok(Err(e)) => report.push(format!("2. Подключение только по ID: ОШИБКА: {e}")),
        Err(_) => report.push("2. Подключение только по ID: нет ответа за 30 с".to_string()),
    }
    report.push(format!("   ретранслятор подключающейся стороны: {}", relay_report(&dialer)));
    accepting.abort();
    dialer.close().await;
    listener.close().await;
    Ok(report.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::EndpointAddr;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Tests point APPDATA at their own folder, so they must not overlap.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn profile(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rdesk-net-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("APPDATA", &dir);
        dir
    }

    /// Local endpoints only: no relay or discovery, so tests need no internet.
    async fn local_pair(pairing: bool) -> (Endpoint, Endpoint, EndpointAddr, Arc<AtomicBool>) {
        let open = Arc::new(AtomicBool::new(pairing));
        let host = bind_host(key(1), open.clone(), true).await.unwrap();
        let client = Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .secret_key(key(2))
            .transport_config(transport())
            .bind()
            .await
            .unwrap();
        let port = host.bound_sockets().iter().find(|a| a.is_ipv4()).unwrap().port();
        let addr = EndpointAddr::new(host.id())
            .with_ip_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        (host, client, addr, open)
    }

    fn trust_client(id: String) {
        let mut trust = Trust::default();
        trust.add_client("laptop".into(), id);
        trust.save().unwrap();
    }

    async fn close_reason(conn: &Connection) -> String {
        match tokio::time::timeout(Duration::from_secs(5), conn.closed()).await {
            Ok(iroh::endpoint::ConnectionError::ApplicationClosed(close)) => {
                String::from_utf8_lossy(&close.reason).into_owned()
            }
            other => format!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn paired_device_gets_a_working_session_connection() {
        let _guard = SERIAL.lock().unwrap();
        let dir = profile("paired");
        trust_client(key(2).public().to_string());
        let (host, client, addr, _) = local_pair(false).await;

        let server = tokio::spawn(async move {
            let conn = host.accept().await.unwrap().accept().unwrap().await.unwrap();
            let datagram = conn.read_datagram().await.unwrap();
            (conn, datagram, host)
        });
        let conn = client.connect(addr, ALPN_SESSION).await.unwrap();
        // The host's key is checked by iroh: the dialled ID is who answered.
        assert_eq!(conn.remote_id(), key(1).public());
        conn.send_datagram(bytes::Bytes::from_static(b"frame")).unwrap();
        let (server_conn, datagram, _host) = server.await.unwrap();
        assert_eq!(&datagram[..], b"frame");
        assert_eq!(peer_id(&server_conn), key(2).public().to_string());
        assert!(conn.max_datagram_size().unwrap() > 1000);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_crosses_a_session_connection_intact() {
        let _guard = SERIAL.lock().unwrap();
        let dir = profile("file");
        trust_client(key(2).public().to_string());
        let (host, client, addr, _) = local_pair(false).await;
        let accepting = tokio::spawn(async move {
            let conn = host.accept().await.unwrap().accept().unwrap().await.unwrap();
            (conn, host)
        });
        let conn = client.connect(addr, ALPN_SESSION).await.unwrap();
        let (server, _host) = accepting.await.unwrap();

        let source = dir.join("payload.bin");
        let payload: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&source, &payload).unwrap();
        let downloads = dir.join("downloads");
        std::fs::create_dir_all(&downloads).unwrap();

        // Downloads land in USERPROFILE\Downloads\rdesk; point it at the test folder.
        std::env::set_var("USERPROFILE", &downloads);
        let progress = Arc::new(crate::files::Progress::default());
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let notify: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |t| { let _ = tx.send(t); });
        tokio::spawn(crate::files::receive_all(server.clone(), progress.clone(), notify));
        let sent = crate::files::send_paths(&conn, &[source], false, &progress).await.unwrap();
        assert_eq!(sent, (1, payload.len() as u64));
        let note = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.unwrap().unwrap();
        assert!(note.contains("payload.bin"), "{note}");
        let saved = downloads.join("Downloads").join("rdesk").join("payload.bin");
        assert_eq!(std::fs::read(&saved).unwrap(), payload);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unpaired_device_is_closed_before_any_stream() {
        let _guard = SERIAL.lock().unwrap();
        let dir = profile("unpaired");
        trust_client("someone-else".into());
        let (host, client, addr, _) = local_pair(false).await;
        let _accepting = tokio::spawn(async move {
            while let Some(incoming) = host.accept().await {
                if let Ok(accepting) = incoming.accept() {
                    let _ = accepting.await;
                }
            }
        });
        match client.connect(addr, ALPN_SESSION).await {
            Ok(conn) => {
                let reason = close_reason(&conn).await;
                assert!(reason.contains(NOT_PAIRED), "{reason}");
            }
            Err(e) => assert!(!e.to_string().is_empty()),
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_protocol_is_refused_unless_open() {
        let _guard = SERIAL.lock().unwrap();
        let dir = profile("pairing");
        let (host, client, addr, open) = local_pair(false).await;
        let _accepting = tokio::spawn(async move {
            let mut kept = Vec::new();
            while let Some(incoming) = host.accept().await {
                if let Ok(accepting) = incoming.accept() {
                    if let Ok(conn) = accepting.await {
                        // Keep accepted connections alive for the test.
                        kept.push(conn);
                    }
                }
            }
        });
        if let Ok(conn) = client.connect(addr.clone(), ALPN_PAIR).await {
            let reason = close_reason(&conn).await;
            assert!(reason.contains(PAIRING_CLOSED), "{reason}");
        }
        open.store(true, Ordering::SeqCst);
        let conn = client.connect(addr, ALPN_PAIR).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(500), conn.closed()).await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn gate_lets_outgoing_connections_through() {
        let gate = Gate { pairing_open: Arc::new(AtomicBool::new(false)) };
        assert!(matches!(gate.decide(false, ALPN_SESSION, "x"), AfterHandshakeOutcome::Accept));
        assert!(matches!(gate.decide(true, b"other", "x"), AfterHandshakeOutcome::Reject { .. }));
    }

    /// A PC announcing itself on the local network shows up in a scan,
    /// with no relay or internet involved.
    #[tokio::test(flavor = "multi_thread")]
    async fn local_scan_finds_an_announcing_pc() {
        let host = Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .secret_key(key(9))
            .address_lookup(MdnsAddressLookup::builder().service_name(MDNS_SERVICE))
            .bind()
            .await
            .unwrap();
        let found = scan_local(Duration::from_secs(5)).await.unwrap();
        assert!(found.contains(&host.id().to_string()), "found {found:?}");
        host.close().await;
    }

    /// Needs a relay server: RDESK_TEST_RELAY=http://127.0.0.1:3341/?token=...
    /// cargo test custom_relay -- --ignored
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn custom_relay_carries_a_connection() {
        const ALPN: &[u8] = b"rdesk-test/1";
        let relay = parse_relay(&std::env::var("RDESK_TEST_RELAY").unwrap()).unwrap().unwrap();
        let host = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::custom([relay.clone()]))
            .secret_key(key(11))
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), host.online()).await.expect("host reached the relay");
        let accepting = {
            let host = host.clone();
            tokio::spawn(async move { host.accept().await.unwrap().accept().unwrap().await.unwrap() })
        };
        let client = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::custom([relay.clone()]))
            .clear_ip_transports()
            .secret_key(key(12))
            .bind()
            .await
            .unwrap();
        let conn = client.connect(EndpointAddr::new(host.id()).with_relay_url(relay), ALPN).await.unwrap();
        let _server = accepting.await.unwrap();
        assert_eq!(route_info(&conn).map(|(_, relayed)| relayed), Some(true));
    }

    /// The host endpoint as the program builds it reaches the relay from the
    /// settings. Needs RDESK_TEST_RELAY like the test above.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn host_uses_the_relay_from_settings() {
        let _guard = SERIAL.lock().unwrap();
        let dir = profile("relay-setting");
        let url = std::env::var("RDESK_TEST_RELAY").unwrap();
        std::fs::create_dir_all(dir.join("rdesk")).unwrap();
        crate::system::save_ui_setting("relay", serde_json::json!(url)).unwrap();
        assert!(custom_relay().is_some());
        let host = bind_host(key(13), Arc::new(AtomicBool::new(false)), false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(15), host.online()).await.expect("host reached the relay");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn relay_addresses_are_checked() {
        assert_eq!(parse_relay("  ").unwrap(), None);
        let url = parse_relay("https://relay.example.com").unwrap().unwrap();
        assert!(url.to_string().starts_with("https://relay.example.com"));
        assert!(parse_relay("relay.example.com").is_err());
        assert!(parse_relay("https://").is_err());
    }

    #[test]
    fn ids_parse_from_hex_only_when_valid() {
        let id = key(5).public().to_string();
        assert_eq!(parse_id(&format!("  {id}\n")).unwrap(), key(5).public());
        assert!(parse_id("not-an-id").is_err());
        assert!(parse_id(&id[..60]).is_err());
    }
}
