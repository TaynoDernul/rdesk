//! Windows integration used by the launcher: firewall rule and start at login.

use anyhow::{bail, Result};
use ring::digest;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HWND};
use windows::Win32::System::Registry::{
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_DWORD,
    RRF_RT_REG_SZ,
};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUN_VALUE: &str = "rdesk";
/// Lets automated checks of the window run without a UAC prompt.
const SKIP_FIREWALL_ENV: &str = "RDESK_SKIP_FIREWALL";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One rule per exe path. The name is derived from the path because netsh
/// prints in the OEM code page, which makes comparing non-ASCII paths unreliable.
fn firewall_rule_name(exe: &str) -> String {
    let hash = digest::digest(&digest::SHA256, exe.to_lowercase().as_bytes());
    format!("rdesk-{}", hex::encode(&hash.as_ref()[..6]))
}

fn firewall_rule_exists(name: &str) -> bool {
    Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule"])
        .arg(format!("name={name}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .is_ok_and(|s| s.success())
}

fn firewall_add_arguments(rule: &str, exe: &str) -> String {
    format!(
        "advfirewall firewall add rule name=\"{rule}\" dir=in action=allow protocol=UDP program=\"{exe}\""
    )
}

fn add_firewall_rule(rule: &str, exe: &str, owner: HWND) -> Result<()> {
    let parameters = wide(&firewall_add_arguments(rule, exe));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: owner,
        lpVerb: w!("runas"),
        lpFile: w!("netsh.exe"),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        ShellExecuteExW(&mut info)?;
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        if code != 0 {
            bail!("netsh exit code {code}");
        }
    }
    Ok(())
}

/// Makes sure other PCs can reach this exe. When `may_ask` is false, nothing
/// prompts: this applies to the automatic start at login. Returns a warning
/// to show if the rule is missing. Only UDP traffic to this exe is allowed,
/// and rdesk itself still refuses devices that are not paired.
pub fn ensure_firewall(may_ask: bool, owner: isize) -> Option<String> {
    if std::env::var_os(SKIP_FIREWALL_ENV).is_some() {
        return None;
    }
    let exe = std::env::current_exe().ok()?.to_string_lossy().into_owned();
    let rule = firewall_rule_name(&exe);
    if firewall_rule_exists(&rule) {
        return None;
    }
    const WARNING: &str = "Брандмауэр не настроен: с других ПК подключиться может не получиться.";
    if !may_ask {
        return Some(WARNING.to_string());
    }
    match add_firewall_rule(&rule, &exe, HWND(owner as *mut _)) {
        Ok(()) => None,
        Err(e) => {
            crate::log_event(&format!("firewall rule not added: {e:#}"));
            Some(WARNING.to_string())
        }
    }
}

fn autostart_command(exe: &str) -> String {
    format!("\"{exe}\" background")
}

fn read_string(subkey: &str, name: &str) -> Result<Option<String>> {
    let (subkey, name) = (wide(subkey), wide(name));
    let mut buffer = vec![0u16; 2048];
    let mut size = (buffer.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr() as *mut _),
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        bail!("registry read failed: {status:?}");
    }
    let units = (size as usize / 2).saturating_sub(1);
    Ok(Some(String::from_utf16_lossy(&buffer[..units])))
}

fn write_string(subkey: &str, name: &str, value: &str) -> Result<()> {
    let (subkey, name, value) = (wide(subkey), wide(name), wide(value));
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            REG_SZ.0,
            Some(value.as_ptr() as *const _),
            (value.len() * 2) as u32,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("registry write failed: {status:?}");
    }
    Ok(())
}

fn delete_value(subkey: &str, name: &str) -> Result<()> {
    let (subkey, name) = (wide(subkey), wide(name));
    let status = unsafe {
        RegDeleteKeyValueW(HKEY_CURRENT_USER, PCWSTR(subkey.as_ptr()), PCWSTR(name.as_ptr()))
    };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        bail!("registry delete failed: {status:?}");
    }
    Ok(())
}

fn ui_settings_path() -> Result<std::path::PathBuf> {
    Ok(crate::identity::config_dir()?.join("ui.json"))
}

/// 0 = like Windows, 1 = light, 2 = dark. A missing or odd file means 0.
pub fn theme_setting() -> u8 {
    let read = || -> Option<u8> {
        let text = std::fs::read_to_string(ui_settings_path().ok()?).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        value.get("theme")?.as_u64().filter(|t| *t <= 2).map(|t| t as u8)
    };
    read().unwrap_or(0)
}

pub fn save_theme_setting(theme: u8) -> Result<()> {
    let body = serde_json::json!({ "theme": theme.min(2) });
    std::fs::write(ui_settings_path()?, serde_json::to_vec_pretty(&body)?)?;
    Ok(())
}

fn read_dword(subkey: &str, name: &str) -> Option<u32> {
    let (subkey, name) = (wide(subkey), wide(name));
    let mut value = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut value as *mut u32 as *mut _),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then_some(value)
}

/// The chosen theme, or the Windows app theme when following the system.
pub fn prefers_dark() -> bool {
    match theme_setting() {
        1 => false,
        2 => true,
        _ => read_dword(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "AppsUseLightTheme",
        ) == Some(0),
    }
}

/// Gives a Win32 window a title bar that matches the theme.
pub fn apply_title_theme(hwnd: HWND) {
    use windows::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE};
    let dark = windows::Win32::Foundation::BOOL::from(prefers_dark());
    let _ = unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark as *const _ as *const _,
            std::mem::size_of_val(&dark) as u32,
        )
    };
}

fn current_exe_string() -> Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().into_owned())
}

/// True only if the entry starts this exe; a moved exe reads as "off".
pub fn autostart_enabled() -> bool {
    let Ok(exe) = current_exe_string() else { return false };
    matches!(read_string(RUN_KEY, RUN_VALUE), Ok(Some(v)) if v == autostart_command(&exe))
}

pub fn set_autostart(enabled: bool) -> Result<()> {
    if enabled {
        write_string(RUN_KEY, RUN_VALUE, &autostart_command(&current_exe_string()?))
    } else {
        delete_value(RUN_KEY, RUN_VALUE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "Software\\rdesk-test";

    #[test]
    fn firewall_rule_name_is_stable_and_path_specific() {
        let a = firewall_rule_name("C:\\Tools\\rdesk.exe");
        assert_eq!(a, firewall_rule_name("c:\\tools\\RDESK.EXE"));
        assert_ne!(a, firewall_rule_name("D:\\Загрузки\\rdesk.exe"));
        assert!(a.starts_with("rdesk-") && a.is_ascii());
    }

    #[test]
    fn firewall_rule_is_limited_to_inbound_udp_for_this_program() {
        let args = firewall_add_arguments("rdesk-1", "C:\\Program Files\\rdesk.exe");
        assert!(args.contains("dir=in"));
        assert!(args.contains("protocol=UDP"));
        assert!(args.contains("program=\"C:\\Program Files\\rdesk.exe\""));
    }

    #[test]
    fn checking_a_missing_rule_reports_absent() {
        assert!(!firewall_rule_exists("rdesk-no-such-rule-for-test"));
    }

    #[test]
    fn registry_value_round_trip() {
        let value = "\"C:\\Папка с пробелом\\rdesk.exe\" background";
        write_string(TEST_KEY, "v", value).unwrap();
        assert_eq!(read_string(TEST_KEY, "v").unwrap().as_deref(), Some(value));
        delete_value(TEST_KEY, "v").unwrap();
        assert_eq!(read_string(TEST_KEY, "v").unwrap(), None);
        delete_value(TEST_KEY, "v").unwrap(); // Removing twice is not an error.
    }

    #[test]
    fn autostart_command_quotes_the_path() {
        assert_eq!(autostart_command("C:\\A B\\r.exe"), "\"C:\\A B\\r.exe\" background");
    }
}
