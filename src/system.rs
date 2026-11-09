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

/// Window preferences in ui.json. They are not security settings, so unlike
/// the device list they are not signed; a missing or odd file means defaults.
fn ui_settings() -> serde_json::Map<String, serde_json::Value> {
    let read = || -> Option<serde_json::Map<String, serde_json::Value>> {
        let text = std::fs::read_to_string(ui_settings_path().ok()?).ok()?;
        serde_json::from_str::<serde_json::Value>(&text).ok()?.as_object().cloned()
    };
    read().unwrap_or_default()
}

pub fn ui_setting(key: &str) -> Option<serde_json::Value> {
    ui_settings().remove(key)
}

/// Changes one preference and keeps the others.
pub fn save_ui_setting(key: &str, value: serde_json::Value) -> Result<()> {
    let mut all = ui_settings();
    all.insert(key.to_string(), value);
    std::fs::write(ui_settings_path()?, serde_json::to_vec_pretty(&all)?)?;
    Ok(())
}

/// MAC addresses of this PC's wired and wireless adapters that are up, for
/// waking it over the network later. Virtual adapters are left out.
pub fn local_macs() -> Vec<[u8; 6]> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::AF_UNSPEC;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024u32;
    let mut buffer: Vec<u64> = Vec::new();
    for _ in 0..3 {
        buffer = vec![0u64; size as usize / 8 + 1];
        let status = unsafe {
            GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buffer.as_mut_ptr() as *mut _), &mut size)
        };
        if status == ERROR_SUCCESS.0 {
            break;
        }
        if status != windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW.0 {
            return Vec::new();
        }
    }
    let mut macs = Vec::new();
    let mut next = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while let Some(adapter) = unsafe { next.as_ref() } {
        let physical = matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211);
        let description = unsafe { adapter.Description.to_string() }.unwrap_or_default().to_lowercase();
        let is_virtual = ["virtual", "hyper-v", "vmware", "virtualbox", "tap-", "wintun", "wireguard", "vpn"]
            .iter()
            .any(|word| description.contains(word));
        if physical && !is_virtual && adapter.OperStatus == IfOperStatusUp && adapter.PhysicalAddressLength == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&adapter.PhysicalAddress[..6]);
            if !macs.contains(&mac) {
                macs.push(mac);
            }
        }
        next = adapter.Next;
    }
    macs
}

/// The Wake-on-LAN magic packet: six 0xFF bytes and the address 16 times.
pub fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut packet = vec![0xFF; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    packet
}

/// Sends magic packets as broadcasts. They reach the sleeping PC only on the
/// same local network, and only if waking is enabled in its BIOS and adapter.
pub fn wake(macs: &[[u8; 6]]) -> Result<()> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
    socket.set_broadcast(true)?;
    for _ in 0..3 {
        for mac in macs {
            let packet = magic_packet(*mac);
            for port in [9u16, 7] {
                socket.send_to(&packet, ("255.255.255.255", port))?;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}

/// "08.11 14:03" in this PC's time zone, for the connection log.
pub fn local_time_text(unix_secs: u64) -> String {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    let ticks = (unix_secs + 11_644_473_600) * 10_000_000;
    let file = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let (mut utc, mut local) = (SYSTEMTIME::default(), SYSTEMTIME::default());
    let converted = unsafe {
        FileTimeToSystemTime(&file, &mut utc).is_ok()
            && SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).is_ok()
    };
    if !converted {
        return String::new();
    }
    format!("{:02}.{:02} {:02}:{:02}", local.wDay, local.wMonth, local.wHour, local.wMinute)
}

pub fn ui_flag(key: &str, default: bool) -> bool {
    ui_setting(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// 0 = like Windows, 1 = light, 2 = dark. A missing or odd file means 0.
pub fn theme_setting() -> u8 {
    ui_setting("theme").and_then(|v| v.as_u64()).filter(|t| *t <= 2).map_or(0, |t| t as u8)
}

pub fn save_theme_setting(theme: u8) -> Result<()> {
    save_ui_setting("theme", serde_json::json!(theme.min(2)))
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

    #[test]
    fn magic_packet_has_the_standard_layout() {
        let mac = [1, 2, 3, 4, 5, 6];
        let packet = magic_packet(mac);
        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        assert!(packet[6..].chunks(6).all(|c| c == mac));
    }

    #[test]
    fn this_pc_reports_its_adapters() {
        // A test machine has a network adapter; none of them may be all zeros.
        assert!(local_macs().iter().all(|m| m != &[0u8; 6]));
    }

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
