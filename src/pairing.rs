//! First-time trust between two devices. The host's ID already proves which
//! PC answered, so the one-time code proves the other direction: that the
//! device asking to be added belongs to whoever can see the host's screen.
//! SPAKE2 turns the short code into a strong key, and an HMAC over both IDs
//! binds that proof to this exact pair of devices. Someone recording traffic
//! cannot test code guesses offline; online guesses are limited.

use crate::identity::{short_id, Identity, Trust};
use crate::net::{self, HostNode};
use crate::proto::{read_msg, write_msg, ALPN_PAIR};
use anyhow::{anyhow, bail, Context, Result};
use iroh::endpoint::Connection;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity as SpakeId, Password, Spake2};
use std::time::Duration;

const MAX_ATTEMPTS: u32 = 3;
const WINDOW: Duration = Duration::from_secs(120);
const SPAKE_ID: &[u8] = b"rdesk-pair-v2";
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Serialize, Deserialize)]
struct Spake {
    message: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ClientProof {
    tag: Vec<u8>,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct HostProof {
    tag: Vec<u8>,
}

pub fn generate_code() -> Result<String> {
    let rng = SystemRandom::new();
    // Rejection sampling keeps all 10^8 values equally likely.
    let value = loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b).map_err(|_| anyhow!("system RNG failed"))?;
        let v = u32::from_le_bytes(b);
        if v < u32::MAX - (u32::MAX % 100_000_000) {
            break v % 100_000_000;
        }
    };
    let s = format!("{value:08}");
    Ok(format!("{}-{}", &s[..4], &s[4..]))
}

fn normalize_code(code: &str) -> String {
    code.chars().filter(char::is_ascii_digit).collect()
}

fn tag_key(shared: &[u8]) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, shared)
}

fn transcript(label: &str, client_id: &str, host_id: &str) -> Vec<u8> {
    format!("rdesk-pair-v2|{label}|{client_id}|{host_id}").into_bytes()
}

fn start(code: &str) -> (spake2::Spake2<Ed25519Group>, Vec<u8>) {
    Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(normalize_code(code).as_bytes()),
        &SpakeId::new(SPAKE_ID),
    )
}

/// Command-line pairing on the host.
pub async fn run_host(id: &Identity) -> Result<()> {
    let node = net::host_node(&id.host_key).await?;
    let code = generate_code()?;
    println!("ID этого ПК: {}", node.id());
    println!("Код добавления: {code}");
    println!("На другом ПК выполните: rdesk pair-with <ID> --name <название>");
    println!("Код действует {} секунд и не более {MAX_ATTEMPTS} попыток.", WINDOW.as_secs());
    let name = serve(&node, &code).await?;
    println!("Устройство «{name}» добавлено.");
    Ok(())
}

/// Closes pairing however `serve` ends, including when the window cancels it.
struct PairingWindow<'a>(&'a HostNode);

impl Drop for PairingWindow<'_> {
    fn drop(&mut self) {
        self.0.close_pairing();
    }
}

/// Accepts one device that knows `code`, and returns its name.
pub async fn serve(node: &HostNode, code: &str) -> Result<String> {
    let mut incoming = node.open_pairing();
    let _window = PairingWindow(node);
    let host_id = node.id();

    tokio::time::timeout(WINDOW, async {
        let mut failures = 0;
        while let Some(conn) = incoming.recv().await {
            let attempt = tokio::time::timeout(STEP_TIMEOUT, host_exchange(&host_id, &conn, code));
            match attempt.await.unwrap_or_else(|_| Err(anyhow!("время ожидания истекло"))) {
                Ok(name) => {
                    // Give the final packets time to reach the client.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    return Ok(name);
                }
                Err(e) => {
                    failures += 1;
                    conn.close(1u32.into(), b"pairing failed");
                    crate::log_event(&format!("pairing attempt failed: {e:#}"));
                    eprintln!("Неудачная попытка {failures} из {MAX_ATTEMPTS}: {e:#}");
                    if failures >= MAX_ATTEMPTS {
                        bail!("слишком много неудачных попыток, код аннулирован");
                    }
                }
            }
        }
        bail!("добавление устройства остановлено")
    })
    .await
    .map_err(|_| anyhow!("время действия кода истекло"))?
}

async fn host_exchange(host_id: &str, conn: &Connection, code: &str) -> Result<String> {
    let client_id = net::peer_id(conn);
    let (mut send, mut recv) = conn.accept_bi().await?;

    let peer: Spake = read_msg(&mut recv).await?;
    let (state, message) = start(code);
    write_msg(&mut send, &Spake { message }).await?;
    let shared = state.finish(&peer.message).map_err(|e| anyhow!("SPAKE2: {e:?}"))?;
    let key = tag_key(&shared);

    let proof: ClientProof = read_msg(&mut recv).await?;
    hmac::verify(&key, &transcript("client", &client_id, host_id), &proof.tag)
        .map_err(|_| anyhow!("неверный код"))?;

    let name: String = proof.name.chars().filter(|c| !c.is_control()).take(64).collect();
    let name = if name.trim().is_empty() { short_id(&client_id).to_string() } else { name };

    let mut trust = Trust::load()?;
    trust.add_client(name.clone(), client_id.clone());
    trust.save()?;
    crate::log_event(&format!("paired client '{name}' {}", short_id(&client_id)));

    let tag = hmac::sign(&key, &transcript("host", &client_id, host_id));
    write_msg(&mut send, &HostProof { tag: tag.as_ref().to_vec() }).await?;
    send.finish()?;
    let _ = send.stopped().await;
    Ok(name)
}

/// Command-line pairing on the client.
pub async fn run_client(id: &Identity, host_id: &str, name: &str) -> Result<()> {
    print!("Введите код с удалённого ПК: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    pair_with(id, host_id, name, &code).await?;
    println!("Компьютер «{name}» добавлен.");
    println!("Теперь подключайтесь так: rdesk connect {name}");
    Ok(())
}

/// Pairs with a host using `code` and saves it.
pub async fn pair_with(id: &Identity, host_id: &str, name: &str, code: &str) -> Result<()> {
    if normalize_code(code).len() != 8 {
        bail!("код должен состоять из 8 цифр");
    }
    let host_id = net::parse_id(host_id)?.to_string();
    let endpoint = net::client_endpoint(&id.client_key).await?;
    let result = async {
        let conn = net::dial(&endpoint, &host_id, ALPN_PAIR)
            .await
            .context("не удалось связаться с удалённым ПК")?;
        tokio::time::timeout(STEP_TIMEOUT, client_exchange(&id.client_id(), &host_id, &conn, code, name))
            .await
            .map_err(|_| anyhow!("удалённый ПК не ответил вовремя"))??;
        conn.close(0u32.into(), b"done");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    endpoint.close().await;
    result?;

    let mut trust = Trust::load()?;
    trust.add_host(name.to_string(), host_id);
    trust.save()?;
    Ok(())
}

async fn client_exchange(
    client_id: &str,
    host_id: &str,
    conn: &Connection,
    code: &str,
    name: &str,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;

    let (state, message) = start(code);
    write_msg(&mut send, &Spake { message }).await?;
    let peer: Spake = read_msg(&mut recv).await?;
    let shared = state.finish(&peer.message).map_err(|e| anyhow!("SPAKE2: {e:?}"))?;
    let key = tag_key(&shared);

    let tag = hmac::sign(&key, &transcript("client", client_id, host_id));
    write_msg(&mut send, &ClientProof { tag: tag.as_ref().to_vec(), name: name.to_string() })
        .await?;

    let proof: HostProof = read_msg(&mut recv)
        .await
        .map_err(|_| anyhow!("неверный код или он уже не действует"))?;
    hmac::verify(&key, &transcript("host", client_id, host_id), &proof.tag)
        .map_err(|_| anyhow!("удалённый ПК не подтвердил код"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_have_expected_format_and_vary() {
        let a = generate_code().unwrap();
        let b = generate_code().unwrap();
        assert_eq!(a.len(), 9);
        assert_eq!(normalize_code(&a).len(), 8);
        assert_ne!(a, b);
    }

    #[test]
    fn same_code_derives_same_key() {
        let (s1, m1) = start("1234-5678");
        let (s2, m2) = start("12345678");
        assert_eq!(s1.finish(&m2).unwrap(), s2.finish(&m1).unwrap());
    }

    #[test]
    fn wrong_code_derives_different_key() {
        let (s1, m1) = start("1234-5678");
        let (s2, m2) = start("1234-5679");
        assert_ne!(s1.finish(&m2).unwrap(), s2.finish(&m1).unwrap());
    }

    #[test]
    fn transcript_binds_both_ids() {
        assert_ne!(transcript("client", "a", "b"), transcript("client", "a", "c"));
        assert_ne!(transcript("client", "a", "b"), transcript("host", "a", "b"));
    }
}
