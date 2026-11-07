//! The PIN asked for on every connection. A paired device alone is not enough,
//! so someone using a stolen, unlocked laptop still cannot reach the host.
//! Only a salted PBKDF2 hash is stored, and the client never saves the PIN.

use anyhow::{anyhow, bail, Context, Result};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
};

pub const MIN_LEN: usize = 6;
const MAX_LEN: usize = 128;
const ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
const FREE_ATTEMPTS: u32 = 5;
const FIRST_LOCK_SECS: u64 = 60;
const MAX_LOCK_SECS: u64 = 3600;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PinRecord {
    pub salt_hex: String,
    pub iterations: u32,
    pub hash_hex: String,
}

/// Returns the reason a new PIN is unacceptable.
pub fn validate(pin: &str) -> Result<()> {
    let length = pin.chars().count();
    if length < MIN_LEN {
        bail!("PIN должен содержать не меньше {MIN_LEN} символов");
    }
    if length > MAX_LEN {
        bail!("PIN слишком длинный");
    }
    Ok(())
}

impl PinRecord {
    pub fn new(pin: &str) -> Result<Self> {
        validate(pin)?;
        Self::with_iterations(pin, ITERATIONS)
    }

    fn with_iterations(pin: &str, iterations: u32) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        SystemRandom::new().fill(&mut salt).map_err(|_| anyhow!("system RNG failed"))?;
        let count = NonZeroU32::new(iterations).context("zero iterations")?;
        let mut hash = [0u8; HASH_LEN];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, count, &salt, pin.as_bytes(), &mut hash);
        Ok(Self { salt_hex: hex::encode(salt), iterations, hash_hex: hex::encode(hash) })
    }

    /// Constant-time comparison. A malformed record never matches.
    pub fn verify(&self, pin: &str) -> bool {
        if pin.chars().count() > MAX_LEN {
            return false;
        }
        let (Ok(salt), Ok(hash), Some(count)) = (
            hex::decode(&self.salt_hex),
            hex::decode(&self.hash_hex),
            NonZeroU32::new(self.iterations),
        ) else {
            return false;
        };
        // ring compares only as many bytes as are given, so a cut-down hash
        // would otherwise make guessing far easier.
        if hash.len() != HASH_LEN {
            return false;
        }
        pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, count, &salt, pin.as_bytes(), &hash).is_ok()
    }
}

/// Slows down guessing: free attempts, then a lock that doubles on each miss.
#[derive(Debug)]
pub struct PinGuard {
    failures: u32,
    locked_until: Option<Instant>,
}

impl PinGuard {
    pub const fn new() -> Self {
        Self { failures: 0, locked_until: None }
    }

    /// How long this attempt must still wait, if at all.
    pub fn lock_remaining(&self, now: Instant) -> Option<Duration> {
        self.locked_until.filter(|until| *until > now).map(|until| until - now)
    }

    /// Returns attempts left before a lock, or 0 if a lock has just started.
    pub fn record_failure(&mut self, now: Instant) -> u32 {
        self.failures = self.failures.saturating_add(1);
        if self.failures < FREE_ATTEMPTS {
            return FREE_ATTEMPTS - self.failures;
        }
        let doublings = (self.failures - FREE_ATTEMPTS).min(16);
        let secs = (FIRST_LOCK_SECS << doublings).min(MAX_LOCK_SECS);
        self.locked_until = Some(now + Duration::from_secs(secs));
        0
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.locked_until = None;
    }
}

/// Reads one line from stdin without echoing it to a console. The window
/// passes the PIN this way, so it never appears in a process command line.
pub fn read_secret(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::Write::flush(&mut std::io::stdout())?;
    let restore = unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE).ok();
        let mut mode = CONSOLE_MODE::default();
        match handle {
            Some(h) if GetConsoleMode(h, &mut mode).is_ok() => {
                let _ = SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
                Some((h, mode))
            }
            _ => None,
        }
    };
    let mut line = String::new();
    let result = std::io::stdin().read_line(&mut line);
    if let Some((handle, mode)) = restore {
        let _ = unsafe { SetConsoleMode(handle, mode) };
        println!();
    }
    result?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: u32 = 1000;

    #[test]
    fn right_pin_matches_and_wrong_pin_does_not() {
        let record = PinRecord::with_iterations("секрет1", FAST).unwrap();
        assert!(record.verify("секрет1"));
        assert!(!record.verify("секрет2"));
        assert!(!record.verify(""));
    }

    #[test]
    fn same_pin_gets_a_different_hash_each_time() {
        let a = PinRecord::with_iterations("123456", FAST).unwrap();
        let b = PinRecord::with_iterations("123456", FAST).unwrap();
        assert_ne!(a.salt_hex, b.salt_hex);
        assert_ne!(a.hash_hex, b.hash_hex);
    }

    #[test]
    fn record_never_contains_the_pin() {
        let record = PinRecord::with_iterations("654321", FAST).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("654321"));
        assert!(!json.contains(&hex::encode("654321")));
    }

    #[test]
    fn real_cost_is_used_for_new_pins() {
        assert_eq!(PinRecord::new("123456").unwrap().iterations, ITERATIONS);
    }

    #[test]
    fn malformed_records_never_match() {
        let good = PinRecord::with_iterations("123456", FAST).unwrap();
        let mut bad = good.clone();
        bad.hash_hex = "zz".into();
        assert!(!bad.verify("123456"));
        let mut bad = good.clone();
        bad.iterations = 0;
        assert!(!bad.verify("123456"));
        let mut bad = good;
        bad.hash_hex.truncate(10);
        assert!(!bad.verify("123456"));
    }

    #[test]
    fn short_and_huge_pins_are_rejected() {
        assert!(validate("12345").is_err());
        assert!(validate("123456").is_ok());
        assert!(validate("пинкод").is_ok());
        assert!(validate(&"1".repeat(MAX_LEN + 1)).is_err());
    }

    #[test]
    fn guard_locks_after_free_attempts_and_doubles() {
        let start = Instant::now();
        let mut guard = PinGuard::new();
        for left in (1..FREE_ATTEMPTS).rev() {
            assert_eq!(guard.record_failure(start), left);
            assert!(guard.lock_remaining(start).is_none());
        }
        assert_eq!(guard.record_failure(start), 0);
        assert_eq!(guard.lock_remaining(start), Some(Duration::from_secs(60)));
        assert!(guard.lock_remaining(start + Duration::from_secs(60)).is_none());

        let later = start + Duration::from_secs(61);
        guard.record_failure(later);
        assert_eq!(guard.lock_remaining(later), Some(Duration::from_secs(120)));
    }

    #[test]
    fn guard_lock_is_capped_and_success_clears_it() {
        let now = Instant::now();
        let mut guard = PinGuard::new();
        for _ in 0..100 {
            guard.record_failure(now);
        }
        assert_eq!(guard.lock_remaining(now), Some(Duration::from_secs(MAX_LOCK_SECS)));
        guard.record_success();
        assert!(guard.lock_remaining(now).is_none());
    }
}
