//! The side being controlled: checks the PIN, then runs one session at a time.
//! Unpaired devices never get this far: the gate in `net` closes them right
//! after the handshake.

mod encoder;
mod indicator;
mod input;
mod video;

use crate::identity::{short_id, Identity, Trust};
use crate::pin::{PinGuard, PinRecord};
use crate::proto::{read_msg, safe_file_name, write_msg, ClientMsg, FileHeader, HostMsg};
use crate::{clipboard, log_event, net};
use anyhow::{anyhow, bail, Context, Result};
use iroh::endpoint::{Connection, RecvStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Notify};
use video::VideoShared;

pub use net::DATAGRAM_SEND_BUFFER;

static LISTENING: AtomicBool = AtomicBool::new(false);
static SESSION: Mutex<Option<String>> = Mutex::new(None);
static NOTE: Mutex<Option<String>> = Mutex::new(None);

/// (accepting connections, name of the connected device) for the window.
pub fn status() -> (bool, Option<String>) {
    (LISTENING.load(Ordering::Relaxed), SESSION.lock().expect("session lock").clone())
}

/// A message for whoever sits at this PC, such as a received file.
pub fn set_note(text: String) {
    *NOTE.lock().expect("note lock") = Some(text);
}

pub fn take_note() -> Option<String> {
    NOTE.lock().expect("note lock").take()
}

struct ListeningGuard;

impl Drop for ListeningGuard {
    fn drop(&mut self) {
        LISTENING.store(false, Ordering::Relaxed);
    }
}

/// The connection of the running session, so turning connections off can end it.
static ACTIVE: Mutex<Option<Connection>> = Mutex::new(None);

struct SessionGuard;

impl SessionGuard {
    fn new(peer: &str, conn: &Connection) -> Self {
        *SESSION.lock().expect("session lock") = Some(peer.to_string());
        *ACTIVE.lock().expect("active lock") = Some(conn.clone());
        SessionGuard
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        *SESSION.lock().expect("session lock") = None;
        *ACTIVE.lock().expect("active lock") = None;
    }
}

/// Serves until `stop` fires, then ends any session.
pub async fn run(id: &Identity, stats: bool, stop: Arc<Notify>) -> Result<()> {
    // Fail closed before announcing anything if the list cannot be trusted.
    let trust = Trust::load()?;
    let node = net::host_node(&id.host_key).await?;
    let mut sessions = node.listen_sessions();
    LISTENING.store(true, Ordering::Relaxed);
    let _listening = ListeningGuard;
    println!("Подключения включены. ID этого ПК: {}", node.id());
    if trust.clients.is_empty() {
        println!("Добавленных устройств пока нет. Выполните: rdesk pair");
    }
    println!("Подключиться смогут только добавленные устройства с PIN. Остановить: Ctrl+C");
    log_event("host started");

    let busy = Arc::new(AtomicBool::new(false));
    loop {
        let conn = tokio::select! {
            _ = stop.notified() => break,
            conn = sessions.recv() => conn,
        };
        let Some(conn) = conn else { break };
        if busy.swap(true, Ordering::SeqCst) {
            conn.close(4u32.into(), "на удалённом ПК уже идёт сеанс".as_bytes());
            continue;
        }
        let busy = busy.clone();
        tokio::spawn(async move {
            if let Err(e) = session(conn, stats).await {
                log_event(&format!("session error: {e:#}"));
                eprintln!("Сеанс завершён с ошибкой: {e:#}");
            }
            busy.store(false, Ordering::SeqCst);
        });
    }

    node.stop_sessions();
    let active = ACTIVE.lock().expect("active lock").clone();
    if let Some(conn) = active {
        conn.close(0u32.into(), "подключения на удалённом ПК выключены".as_bytes());
    }
    // The session sees the closed connection and cleans up: keys, banner, video.
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        while busy.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    log_event("host stopped");
    Ok(())
}

static PIN_GUARD: Mutex<PinGuard> = Mutex::new(PinGuard::new());

/// Returns the reason shown to the client when the session must not start.
async fn check_pin(record: Option<&PinRecord>, pin: String, peer: &str) -> Result<(), String> {
    let Some(record) = record.cloned() else {
        log_event(&format!("refused '{peer}': no PIN is set on this PC"));
        set_note("Подключение отклонено: задайте PIN.".to_string());
        return Err("на удалённом ПК не задан PIN".to_string());
    };
    let locked = PIN_GUARD.lock().expect("pin lock").lock_remaining(Instant::now());
    if let Some(wait) = locked {
        log_event(&format!("refused '{peer}': PIN entry is locked"));
        return Err(format!("вход заблокирован ещё на {} с из-за неверных PIN", wait.as_secs() + 1));
    }
    // PBKDF2 is slow on purpose, so it stays off the network threads.
    let matches = tokio::task::spawn_blocking(move || record.verify(&pin)).await.unwrap_or(false);
    let mut guard = PIN_GUARD.lock().expect("pin lock");
    if matches {
        guard.record_success();
        return Ok(());
    }
    let left = guard.record_failure(Instant::now());
    log_event(&format!("wrong PIN from '{peer}', attempts left: {left}"));
    set_note(format!("Неверный PIN с устройства «{peer}»."));
    Err(if left > 0 {
        format!("неверный PIN, осталось попыток: {left}")
    } else {
        "неверный PIN, вход временно заблокирован".to_string()
    })
}

async fn session(conn: Connection, stats: bool) -> Result<()> {
    let peer_id = net::peer_id(&conn);
    let trust = Trust::load()?;
    let peer = trust
        .client_name(&peer_id)
        .ok_or_else(|| anyhow!("device lost its pairing during the handshake"))?;
    log_event(&format!("session started: '{peer}' {}", short_id(&peer_id)));
    println!("Подключено: {peer}");

    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
        .await
        .context("client did not open the control stream")??;
    let hello: ClientMsg = read_msg(&mut recv).await?;
    let ClientMsg::Hello { max_bitrate_kbps, fps, clipboard: clipboard_on, pin } = hello else {
        bail!("expected Hello");
    };

    // Nothing is captured or accepted from this device before this check.
    if let Err(reason) = check_pin(trust.pin.as_ref(), pin, &peer).await {
        conn.close(2u32.into(), reason.as_bytes());
        return Ok(());
    }
    write_msg(&mut send, &HostMsg::Accepted).await?;

    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<HostMsg>();
    let writer = tokio::spawn(async move {
        while let Some(msg) = ctl_rx.recv().await {
            if write_msg(&mut send, &msg).await.is_err() {
                break;
            }
        }
    });

    let disconnect = Arc::new(Notify::new());
    let banner = indicator::start(&peer, disconnect.clone(), clipboard_on.then(|| ctl_tx.clone()));
    if banner.is_none() {
        // Unattended control without the visible banner is not allowed.
        conn.close(1u32.into(), b"indicator failed");
        bail!("cannot show the session banner");
    }
    let _session = SessionGuard::new(&peer, &conn);

    let shared = Arc::new(VideoShared {
        stop: AtomicBool::new(false),
        force_key: AtomicBool::new(true),
        restart: AtomicBool::new(false),
        monitor: AtomicUsize::new(0),
        rect: Mutex::new(Default::default()),
        max_kbps: max_bitrate_kbps.clamp(1_000, 200_000),
        fps: fps.clamp(10, 240),
        stats,
        frame_id: AtomicU64::new(0),
        current_kbps: AtomicU32::new(0),
        current_fps: AtomicU32::new(0),
    });
    let video_thread = {
        let (conn, shared, ctl) = (conn.clone(), shared.clone(), ctl_tx.clone());
        std::thread::Builder::new()
            .name("video".into())
            .spawn(move || video::run(conn, &shared, ctl))?
    };

    let files = tokio::spawn(receive_files(conn.clone(), peer.clone()));
    let result = tokio::select! {
        r = input_loop(&mut recv, &shared) => r,
        _ = disconnect.notified() => {
            conn.close(0u32.into(), "отключено на удалённом ПК".as_bytes());
            Ok(())
        }
        e = conn.closed() => {
            log_event(&format!("connection closed: {e}"));
            Ok(())
        }
    };

    shared.stop.store(true, Ordering::Relaxed);
    conn.close(0u32.into(), b"session ended");
    files.abort();
    writer.abort();
    if let Some(banner) = banner {
        banner.close();
    }
    tokio::task::spawn_blocking(move || {
        let _ = video_thread.join();
    })
    .await?;
    log_event(&format!("session ended: '{peer}'"));
    println!("Сеанс завершён: {peer}");
    result
}

async fn input_loop(recv: &mut RecvStream, shared: &VideoShared) -> Result<()> {
    // Dropping the injector releases held keys on every exit path.
    let mut injector = input::Injector::default();
    loop {
        let msg: ClientMsg = match read_msg(recv).await {
            Ok(msg) => msg,
            // A closed stream is a normal end of session.
            Err(_) => return Ok(()),
        };
        match msg {
            ClientMsg::MouseMove { x, y } => {
                let monitor = *shared.rect.lock().expect("rect lock");
                injector.mouse_move(x, y, monitor);
            }
            ClientMsg::MouseButton { button, down } => injector.mouse_button(button, down),
            ClientMsg::Wheel { delta, horizontal } => injector.wheel(delta, horizontal),
            ClientMsg::Key { scan, extended, down } => injector.key(scan, extended, down),
            ClientMsg::ReleaseAll => injector.release_all(),
            ClientMsg::RequestKeyframe => shared.force_key.store(true, Ordering::Relaxed),
            ClientMsg::SelectMonitor { index } => {
                shared.monitor.store(index as usize, Ordering::Relaxed);
                shared.restart.store(true, Ordering::Relaxed);
            }
            ClientMsg::Clipboard { text } => {
                if let Err(e) = clipboard::set_remote_text(&text) {
                    log_event(&format!("clipboard: {e:#}"));
                }
            }
            ClientMsg::Hello { .. } => bail!("duplicate Hello"),
        }
    }
}

fn download_dir() -> Result<PathBuf> {
    let base = std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?;
    let dir = PathBuf::from(base).join("Downloads").join("rdesk");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Picks a name that does not exist yet, so a transfer never overwrites a file.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let source = Path::new(name);
    let stem = source.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = source.extension().and_then(|s| s.to_str());
    (1..)
        .map(|i| match ext {
            Some(ext) => dir.join(format!("{stem} ({i}).{ext}")),
            None => dir.join(format!("{stem} ({i})")),
        })
        .find(|p| !p.exists())
        .expect("unbounded search finds a free name")
}

async fn receive_files(conn: Connection, peer: String) {
    while let Ok(mut stream) = conn.accept_uni().await {
        let peer = peer.clone();
        tokio::spawn(async move {
            if let Err(e) = receive_file(&mut stream, &peer).await {
                log_event(&format!("file transfer failed: {e:#}"));
            }
        });
    }
}

async fn receive_file(stream: &mut RecvStream, peer: &str) -> Result<()> {
    receive_file_into(stream, peer, &download_dir()?).await.map(|_| ())
}

pub(crate) async fn receive_file_into(
    stream: &mut RecvStream,
    peer: &str,
    dir: &Path,
) -> Result<PathBuf> {
    let header: FileHeader = read_msg(stream).await?;
    let name = safe_file_name(&header.name).ok_or_else(|| anyhow!("unsafe file name"))?;
    let target = unique_path(dir, &name);
    let partial = target.with_extension(format!(
        "{}.part",
        target.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));

    let copy = async {
        let mut file = tokio::fs::File::create(&partial).await?;
        let mut received = 0u64;
        let mut buffer = vec![0u8; 256 * 1024];
        while let Some(n) = stream.read(&mut buffer).await? {
            received += n as u64;
            if received > header.size {
                bail!("sender exceeded the declared size");
            }
            file.write_all(&buffer[..n]).await?;
        }
        if received != header.size {
            bail!("transfer ended early: {received} of {} bytes", header.size);
        }
        file.flush().await?;
        Ok(())
    };
    if let Err(e) = copy.await {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(e);
    }
    tokio::fs::rename(&partial, &target).await?;
    log_event(&format!("file from '{peer}' saved: {}", target.display()));
    println!("Получен файл: {}", target.display());
    set_note(format!("Получен файл от «{peer}»: {}", target.display()));
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_path_never_reuses_a_name() {
        let dir = std::env::temp_dir().join(format!("rdesk-unique-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (1).txt"));
        std::fs::write(dir.join("a (1).txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
