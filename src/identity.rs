//! Device keys and the list of trusted peers.
//!
//! Each PC has two Ed25519 keys. The host key's public half is the PC's ID:
//! other devices dial it, and iroh proves during the handshake that the other
//! side holds the matching private key. The client key identifies this PC when
//! it connects out. Two keys keep the window process (which accepts) and a
//! session process (which connects) from announcing the same ID at once.
//! Private keys are encrypted with DPAPI, so they only open under this Windows
//! account on this machine.

use crate::pin::PinRecord;
use anyhow::{anyhow, bail, Context, Result};
use iroh::SecretKey;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

pub struct Identity {
    pub host_key: SecretKey,
    pub client_key: SecretKey,
}

impl Identity {
    /// The ID other PCs use to reach this one.
    pub fn host_id(&self) -> String {
        self.host_key.public().to_string()
    }

    /// How hosts recognise this PC when it connects to them.
    pub fn client_id(&self) -> String {
        self.client_key.public().to_string()
    }
}

/// The first characters of an ID, enough to tell devices apart in lists.
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

#[derive(Serialize, Deserialize, Default)]
struct StoredIdentity {
    #[serde(default)]
    host_key_dpapi_hex: Option<String>,
    #[serde(default)]
    client_key_dpapi_hex: Option<String>,
}

pub fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}

pub fn config_dir() -> Result<PathBuf> {
    let base = std::env::var_os("APPDATA").context("APPDATA is not set")?;
    let dir = PathBuf::from(base).join("rdesk");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn load_or_create() -> Result<Identity> {
    load_or_create_at(&config_dir()?.join("identity.json"))
}

fn random_key() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).map_err(|_| anyhow!("system RNG failed"))?;
    Ok(bytes)
}

fn open_key(wrapped_hex: &str) -> Result<SecretKey> {
    let plain = dpapi_unprotect(&hex::decode(wrapped_hex)?)
        .context("cannot decrypt the device key; was it created by another Windows user?")?;
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| anyhow!("device key has a wrong length"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Keys missing from the file are created and saved. A file from an older
/// version, which held a certificate instead, gains both keys this way.
fn load_or_create_at(path: &Path) -> Result<Identity> {
    let mut stored: StoredIdentity = if path.exists() {
        serde_json::from_slice(&fs::read(path)?)
            .with_context(|| format!("cannot parse {}", path.display()))?
    } else {
        StoredIdentity::default()
    };
    let mut changed = false;
    let mut take = |slot: &mut Option<String>| -> Result<SecretKey> {
        if let Some(hex) = slot.as_deref() {
            return open_key(hex);
        }
        let bytes = random_key()?;
        *slot = Some(hex::encode(dpapi_protect(&bytes)?));
        changed = true;
        Ok(SecretKey::from_bytes(&bytes))
    };
    let host_key = take(&mut stored.host_key_dpapi_hex)?;
    let client_key = take(&mut stored.client_key_dpapi_hex)?;
    if changed {
        write_atomic(path, &serde_json::to_vec_pretty(&stored)?)?;
    }
    Ok(Identity { host_key, client_key })
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB { cbData: plain.len() as u32, pbData: plain.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)?;
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(result)
    }
}

fn dpapi_unprotect(cipher: &[u8]) -> Result<Vec<u8>> {
    let input =
        CRYPT_INTEGER_BLOB { cbData: cipher.len() as u32, pbData: cipher.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)?;
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(result)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrustedClient {
    pub name: String,
    /// The client key's public half, as text.
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrustedHost {
    pub name: String,
    /// The host's ID, which is also how it is reached.
    pub id: String,
}

/// Clients allowed to connect here, hosts this machine can connect to, and the
/// settings an attacker would most like to change.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Trust {
    pub clients: Vec<TrustedClient>,
    pub hosts: Vec<TrustedHost>,
    /// Asked of every device connecting here. Without one, all sessions are refused.
    #[serde(default)]
    pub pin: Option<PinRecord>,
    /// Clipboard sync when connecting from the window.
    #[serde(default)]
    pub clipboard: bool,
    /// Someone at this PC must allow each session; kept in the signed list
    /// so that malware editing a file cannot quietly turn it off.
    #[serde(default)]
    pub confirm: bool,
}

/// On-disk form: the JSON body plus an HMAC keyed by a DPAPI-protected secret.
#[derive(Serialize, Deserialize)]
struct SealedTrust {
    body: String,
    mac: String,
}

const TAMPERED: &str =
    "список устройств изменён не этой программой или повреждён, доступ закрыт";

fn trust_mac_key(key: &[u8]) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, key)
}

/// The version label also invalidates lists from releases that identified
/// devices differently, so they cannot be mistaken for current ones.
fn trust_mac_input(body: &str) -> Vec<u8> {
    format!("rdesk-trust-v2|{body}").into_bytes()
}

fn seal_trust(trust: &Trust, key: &[u8]) -> Result<Vec<u8>> {
    let body = serde_json::to_string(trust)?;
    let tag = hmac::sign(&trust_mac_key(key), &trust_mac_input(&body));
    Ok(serde_json::to_vec_pretty(&SealedTrust { body, mac: hex::encode(tag) })?)
}

/// Rejects anything not written by `seal_trust` with this key. That includes
/// files with no signature at all, because otherwise an attacker would only
/// have to remove it.
fn unseal_trust(bytes: &[u8], key: &[u8]) -> Result<Trust> {
    let sealed: SealedTrust = serde_json::from_slice(bytes).map_err(|_| anyhow!(TAMPERED))?;
    let tag = hex::decode(&sealed.mac).map_err(|_| anyhow!(TAMPERED))?;
    hmac::verify(&trust_mac_key(key), &trust_mac_input(&sealed.body), &tag)
        .map_err(|_| anyhow!(TAMPERED))?;
    serde_json::from_str(&sealed.body).map_err(|_| anyhow!(TAMPERED))
}

fn read_trust_key(path: &Path) -> Result<Vec<u8>> {
    let wrapped = hex::decode(fs::read_to_string(path)?.trim())?;
    dpapi_unprotect(&wrapped)
}

/// A missing or unreadable key is replaced, which also invalidates any list
/// signed with the old one. Used only when writing.
fn read_or_create_trust_key(path: &Path) -> Result<Vec<u8>> {
    if let Ok(key) = read_trust_key(path) {
        return Ok(key);
    }
    let key = random_key()?.to_vec();
    write_atomic(path, hex::encode(dpapi_protect(&key)?).as_bytes())?;
    Ok(key)
}

impl Trust {
    pub fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("trust.json"))
    }

    fn key_path() -> Result<PathBuf> {
        Ok(config_dir()?.join("trust.key"))
    }

    /// A damaged or altered file is an error rather than an empty list:
    /// failing closed refuses every device until the user decides what to do.
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::path()?, &Self::key_path()?)
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::path()?, &Self::key_path()?)
    }

    fn load_from(path: &Path, key_path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let key = read_trust_key(key_path).map_err(|_| anyhow!(TAMPERED))?;
        unseal_trust(&fs::read(path)?, &key)
    }

    fn save_to(&self, path: &Path, key_path: &Path) -> Result<()> {
        write_atomic(path, &seal_trust(self, &read_or_create_trust_key(key_path)?)?)
    }

    /// True when the file exists but cannot be trusted.
    pub fn is_tampered() -> bool {
        Self::load().is_err()
    }

    pub fn is_client_allowed(&self, id: &str) -> bool {
        self.clients.iter().any(|c| c.id == id)
    }

    pub fn client_name(&self, id: &str) -> Option<String> {
        self.clients.iter().find(|c| c.id == id).map(|c| c.name.clone())
    }

    pub fn add_client(&mut self, name: String, id: String) {
        self.clients.retain(|c| c.id != id);
        self.clients.push(TrustedClient { name, id });
    }

    pub fn add_host(&mut self, name: String, id: String) {
        self.hosts.retain(|h| h.name != name && h.id != id);
        self.hosts.push(TrustedHost { name, id });
    }

    /// Removes peers whose name matches exactly or whose ID starts with
    /// `who` (at least 8 characters). Returns how many were removed.
    pub fn revoke(&mut self, who: &str) -> Result<usize> {
        if who.is_empty() {
            bail!("empty name");
        }
        let lower = who.to_ascii_lowercase();
        let matches = |name: &str, id: &str| name == who || (who.len() >= 8 && id.starts_with(&lower));
        let before = self.clients.len() + self.hosts.len();
        self.clients.retain(|c| !matches(&c.name, &c.id));
        self.hosts.retain(|h| !matches(&h.name, &h.id));
        Ok(before - self.clients.len() - self.hosts.len())
    }

    pub fn find_host(&self, name_or_id: &str) -> Result<TrustedHost> {
        self.hosts
            .iter()
            .find(|h| h.name == name_or_id || h.id == name_or_id)
            .cloned()
            .ok_or_else(|| anyhow!("компьютер «{name_or_id}» не добавлен"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip() {
        let secret = b"device private key".to_vec();
        let wrapped = dpapi_protect(&secret).unwrap();
        assert_ne!(wrapped, secret);
        assert_eq!(dpapi_unprotect(&wrapped).unwrap(), secret);
    }

    #[test]
    fn dpapi_rejects_tampering() {
        let mut wrapped = dpapi_protect(b"secret").unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xFF;
        assert!(dpapi_unprotect(&wrapped).is_err());
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rdesk-id-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keys_survive_reload_and_are_never_stored_plain() {
        let dir = temp_dir("reload");
        let path = dir.join("identity.json");
        let first = load_or_create_at(&path).unwrap();
        let second = load_or_create_at(&path).unwrap();
        assert_eq!(first.host_id(), second.host_id());
        assert_eq!(first.client_id(), second.client_id());
        assert_ne!(first.host_id(), first.client_id());
        assert_eq!(first.host_id().len(), 64);

        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains(&hex::encode(first.host_key.to_bytes())));
        assert!(!on_disk.contains(&hex::encode(first.client_key.to_bytes())));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn old_identity_file_gains_keys() {
        let dir = temp_dir("old");
        let path = dir.join("identity.json");
        fs::write(&path, br#"{"cert_hex":"00","key_dpapi_hex":"00"}"#).unwrap();
        let identity = load_or_create_at(&path).unwrap();
        assert_eq!(load_or_create_at(&path).unwrap().host_id(), identity.host_id());
        fs::remove_dir_all(dir).unwrap();
    }

    fn trust_dir(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let dir = temp_dir(&format!("trust-{name}"));
        let (path, key) = (dir.join("trust.json"), dir.join("trust.key"));
        (dir, path, key)
    }

    fn sample_trust() -> Trust {
        let mut t = Trust::default();
        t.add_client("laptop".into(), "aaaa".into());
        t.clipboard = true;
        t
    }

    #[test]
    fn signed_list_round_trips() {
        let (dir, path, key) = trust_dir("ok");
        sample_trust().save_to(&path, &key).unwrap();
        let loaded = Trust::load_from(&path, &key).unwrap();
        assert!(loaded.is_client_allowed("aaaa"));
        assert_eq!(loaded.client_name("aaaa").as_deref(), Some("laptop"));
        assert!(loaded.clipboard);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_list_is_empty_and_creates_no_key() {
        let (dir, path, key) = trust_dir("none");
        assert!(Trust::load_from(&path, &key).unwrap().clients.is_empty());
        assert!(!key.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn edited_list_is_refused() {
        let (dir, path, key) = trust_dir("edit");
        sample_trust().save_to(&path, &key).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let forged = text.replace("aaaa", "bbbb");
        assert_ne!(text, forged);
        fs::write(&path, forged).unwrap();
        assert!(Trust::load_from(&path, &key).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unsigned_list_is_refused() {
        let (dir, path, key) = trust_dir("unsigned");
        sample_trust().save_to(&path, &key).unwrap();
        // The attack that accepting unsigned files would allow: drop the signature.
        fs::write(&path, serde_json::to_vec(&sample_trust()).unwrap()).unwrap();
        assert!(Trust::load_from(&path, &key).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_signed_by_an_older_version_is_refused() {
        let (dir, path, key) = trust_dir("v1");
        let raw_key = read_or_create_trust_key(&key).unwrap();
        let body = serde_json::to_string(&sample_trust()).unwrap();
        let tag = hmac::sign(&trust_mac_key(&raw_key), format!("rdesk-trust-v1|{body}").as_bytes());
        let old = SealedTrust { body, mac: hex::encode(tag) };
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(Trust::load_from(&path, &key).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deleted_or_replaced_key_is_refused() {
        let (dir, path, key) = trust_dir("key");
        sample_trust().save_to(&path, &key).unwrap();
        let original = fs::read(&path).unwrap();

        fs::remove_file(&key).unwrap();
        assert!(Trust::load_from(&path, &key).is_err());

        // A new key cannot validate a list signed by the old one.
        Trust::default().save_to(&dir.join("other.json"), &key).unwrap();
        fs::write(&path, original).unwrap();
        assert!(Trust::load_from(&path, &key).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_from_another_profile_is_refused() {
        let (dir_a, path_a, key_a) = trust_dir("a");
        let (dir_b, path_b, key_b) = trust_dir("b");
        sample_trust().save_to(&path_a, &key_a).unwrap();
        Trust::default().save_to(&path_b, &key_b).unwrap();
        fs::copy(&path_a, &path_b).unwrap();
        assert!(Trust::load_from(&path_b, &key_b).is_err());
        fs::remove_dir_all(dir_a).unwrap();
        fs::remove_dir_all(dir_b).unwrap();
    }

    #[test]
    fn saving_recovers_from_a_refused_list() {
        let (dir, path, key) = trust_dir("reset");
        fs::write(&path, b"garbage").unwrap();
        assert!(Trust::load_from(&path, &key).is_err());
        Trust::default().save_to(&path, &key).unwrap();
        assert!(Trust::load_from(&path, &key).unwrap().clients.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn revoke_matches_name_or_long_prefix_only() {
        let mut t = Trust::default();
        t.add_client("laptop".into(), "abcdef0123456789".into());
        t.add_host("home".into(), "1234567890abcdef".into());
        assert_eq!(t.revoke("abc").unwrap(), 0); // prefix too short
        assert_eq!(t.revoke("ABCDEF01").unwrap(), 1);
        assert!(!t.is_client_allowed("abcdef0123456789"));
        assert_eq!(t.revoke("home").unwrap(), 1);
        assert!(t.find_host("home").is_err());
    }

    #[test]
    fn adding_a_host_replaces_same_name_or_id() {
        let mut t = Trust::default();
        t.add_host("home".into(), "id1".into());
        t.add_host("home".into(), "id2".into());
        t.add_host("work".into(), "id2".into());
        assert_eq!(t.hosts, vec![TrustedHost { name: "work".into(), id: "id2".into() }]);
    }
}
