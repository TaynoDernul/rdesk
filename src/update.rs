//! Updates from the project's GitHub releases. Nothing is downloaded without
//! the user pressing the button, and the new file must match the SHA-256
//! that GitHub lists for it before it replaces this one.

use anyhow::{anyhow, bail, Context, Result};
use ring::digest::{Context as Hasher, SHA256};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const LATEST: &str = "https://api.github.com/repos/TaynoDernul/rdesk/releases/latest";
const ASSET: &str = "rdesk.exe";
/// A real build is a few tens of megabytes; anything far larger is refused.
const MAX_SIZE: u64 = 200 * 1024 * 1024;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
    /// "sha256:<hex>", filled in by GitHub for uploaded files.
    digest: Option<String>,
}

/// A newer version that can be installed.
#[derive(Clone, Debug)]
pub struct Available {
    pub version: String,
    url: String,
    size: u64,
    sha256: String,
}

/// "v0.2.1" or "0.2.1" as numbers; anything else is not a version.
fn parse_version(text: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = text.trim().trim_start_matches('v').split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|p| !p.is_empty())
}

fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

fn client() -> Result<reqwest::Client> {
    // iroh brings rustls with ring; requests to GitHub use the same, with
    // certificates checked against the Windows store.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .tls_backend_rustls()
        .user_agent(concat!("rdesk/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("cannot start HTTPS")
}

/// Asks GitHub for the latest release. None when this copy is up to date.
pub async fn check() -> Result<Option<Available>> {
    let release: Release = client()?
        .get(LATEST)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("GitHub не отвечает")?
        .error_for_status()
        .context("GitHub вернул ошибку")?
        .json()
        .await
        .context("непонятный ответ GitHub")?;
    if !is_newer(&release.tag_name, env!("CARGO_PKG_VERSION")) {
        return Ok(None);
    }
    let asset = release
        .assets
        .into_iter()
        .find(|a| a.name.eq_ignore_ascii_case(ASSET))
        .ok_or_else(|| anyhow!("в выпуске {} нет файла {ASSET}", release.tag_name))?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|h| h.len() == 64)
        .ok_or_else(|| anyhow!("у файла в выпуске нет контрольной суммы; скачайте его со страницы выпуска"))?
        .to_ascii_lowercase();
    Ok(Some(Available {
        version: release.tag_name.trim_start_matches('v').to_string(),
        url: asset.browser_download_url,
        size: asset.size,
        sha256,
    }))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Hasher::new(&SHA256);
    h.update(bytes);
    hex::encode(h.finish().as_ref())
}

/// The running file is renamed aside (Windows allows that) and the new one
/// takes its place. The old copy is removed on the next start.
fn old_path(exe: &Path) -> PathBuf {
    exe.with_file_name("rdesk.old.exe")
}

/// Downloads, checks and puts the new version in place of this file.
/// Returns the path to start. The caller restarts the program.
pub async fn install(update: &Available) -> Result<PathBuf> {
    if update.size > MAX_SIZE {
        bail!("файл обновления подозрительно большой");
    }
    let bytes = client()?
        .get(&update.url)
        .send()
        .await
        .context("не удалось скачать обновление")?
        .error_for_status()?
        .bytes()
        .await
        .context("загрузка прервалась")?;
    if bytes.len() as u64 != update.size {
        bail!("файл скачан не полностью");
    }
    let actual = sha256_hex(&bytes);
    if actual != update.sha256 {
        bail!("контрольная сумма не совпала: файл повреждён или подменён, обновление отменено");
    }
    let exe = std::env::current_exe()?;
    let fresh = exe.with_file_name("rdesk.new.exe");
    tokio::fs::write(&fresh, &bytes).await?;
    let old = old_path(&exe);
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old).context("не удалось освободить место для новой версии")?;
    if let Err(e) = std::fs::rename(&fresh, &exe) {
        // Put the running version back so the program still starts next time.
        let _ = std::fs::rename(&old, &exe);
        return Err(anyhow!(e).context("не удалось установить новую версию"));
    }
    crate::log_event(&format!("updated to {}", update.version));
    Ok(exe)
}

/// Removes the copy left from the last update, once it is no longer running.
pub fn clean_up() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(old_path(&exe));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("v1.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.0.9", "0.1.0"));
        assert!(!is_newer("nightly", "0.1.0"));
        assert!(!is_newer("", "0.1.0"));
    }

    /// Asks the real GitHub; run by hand: cargo test github_answers -- --ignored
    #[tokio::test]
    #[ignore]
    async fn github_answers_the_version_question() {
        let found = check().await.expect("GitHub answered");
        println!("newer release: {:?}", found.map(|f| f.version));
    }

    #[test]
    fn hashes_are_lowercase_hex() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
