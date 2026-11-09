//! rdesk: personal low-latency remote desktop for Windows.
//! A double click opens the window; arguments select the command-line mode.

// No console window on double click. Tests keep the console for their output.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod audio;
mod chat;
mod client;
mod clipboard;
mod d3d;
mod fec;
mod files;
mod gui;
mod host;
mod identity;
mod net;
mod pairing;
mod pin;
mod proto;
mod system;
mod update;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::Notify;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
    STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

#[derive(Parser)]
#[command(name = "rdesk", version, about = "Удалённый рабочий стол по ID: 60 FPS, сквозное шифрование")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start hidden in the tray and accept connections (used at Windows login)
    #[command(hide = true)]
    Background,
    /// Разрешить подключения к этому ПК (только добавленным устройствам)
    Host {
        /// Печатать статистику кодирования раз в секунду
        #[arg(long)]
        stats: bool,
    },
    /// Показать ID и одноразовый код, чтобы добавить новое устройство
    Pair,
    /// Добавить удалённый ПК, на котором запущена команда pair
    PairWith {
        /// ID удалённого ПК
        id: String,
        /// Название, под которым запомнить этот ПК
        #[arg(long)]
        name: String,
    },
    /// Подключиться к добавленному ПК
    Connect {
        /// Название, заданное при добавлении
        name: String,
        /// Максимальный битрейт, кбит/с
        #[arg(long, default_value_t = 20_000)]
        bitrate: u32,
        #[arg(long, default_value_t = 60)]
        fps: u32,
        /// Отключить синхронизацию буфера обмена
        #[arg(long)]
        no_clipboard: bool,
        /// Не передавать звук с удалённого ПК
        #[arg(long)]
        no_audio: bool,
        /// Только H.264, даже если доступен H.265
        #[arg(long)]
        h264: bool,
        /// Печатать статистику раз в секунду
        #[arg(long)]
        stats: bool,
        /// Завершиться через указанное число секунд (для замеров)
        #[arg(long, hide = true)]
        duration: Option<u64>,
        /// Сообщать об ошибках окнами (при запуске из графического интерфейса)
        #[arg(long, hide = true)]
        dialogs: bool,
    },
    /// Задать PIN, который будут вводить при подключении к этому ПК
    SetPin,
    /// Показать ID этого ПК и списки добавленных устройств
    List,
    /// Проверить, работает ли связь по ID через интернет
    NetCheck,
    /// Отозвать доступ по названию или началу ID
    Revoke { who: String },
}

/// Appends to the audit log. Logging must never take down a session.
pub fn log_event(message: &str) {
    let Ok(dir) = identity::config_dir() else { return };
    let Ok(mut file) =
        std::fs::OpenOptions::new().create(true).append(true).open(dir.join("rdesk.log"))
    else {
        return;
    };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(file, "{secs} {message}");
}

pub fn message_box(text: &str) {
    let text: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { MessageBoxW(None, PCWSTR(text.as_ptr()), w!("rdesk"), MB_OK | MB_ICONINFORMATION) };
}

/// A windows-subsystem program gets no console. In command-line mode, this
/// borrows the console of the terminal it was started from. Handles that are
/// already valid, such as redirected output, are left alone.
fn attach_console() {
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return;
        }
        let connect = |kind: STD_HANDLE, name: PCWSTR, access: u32| {
            if GetStdHandle(kind).is_ok_and(|h| !h.is_invalid()) {
                return;
            }
            let opened: windows::core::Result<HANDLE> = CreateFileW(
                name,
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            );
            if let Ok(handle) = opened {
                let _ = SetStdHandle(kind, handle);
            }
        };
        let both = GENERIC_READ.0 | GENERIC_WRITE.0;
        connect(STD_INPUT_HANDLE, w!("CONIN$"), both);
        connect(STD_OUTPUT_HANDLE, w!("CONOUT$"), both);
        connect(STD_ERROR_HANDLE, w!("CONOUT$"), both);
    }
}

fn main() {
    let command_line = std::env::args_os().count() > 1;
    if command_line {
        attach_console();
    }
    let cli = Cli::parse();
    let dialogs = !command_line || matches!(cli.command, Some(Command::Connect { dialogs: true, .. }));
    if let Err(e) = run(cli) {
        if dialogs {
            message_box(&format!("{e:#}"));
        } else {
            eprintln!("Ошибка: {e:#}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    unsafe {
        // Without this, DXGI duplication and mouse mapping break on scaled displays.
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let id = identity::load_or_create()?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    let Some(command) = cli.command else {
        return gui::run(runtime, id, false);
    };
    match command {
        Command::Background => gui::run(runtime, id, true),
        Command::Host { stats } => {
            runtime.block_on(host::run(&id, stats, Arc::new(Notify::new())))
        }
        Command::Pair => runtime.block_on(pairing::run_host(&id)),
        Command::PairWith { id: host_id, name } => {
            runtime.block_on(pairing::run_client(&id, &host_id, &name))
        }
        Command::Connect { name, bitrate, fps, no_clipboard, no_audio, h264, stats, duration, dialogs } => {
            client::run(
                runtime,
                id,
                client::Options {
                    target: name,
                    bitrate_kbps: bitrate,
                    fps,
                    clipboard: !no_clipboard,
                    audio: !no_audio,
                    hevc: !h264,
                    stats,
                    duration,
                    dialogs,
                },
            )
        }
        Command::SetPin => {
            let mut trust = identity::Trust::load()?;
            let pin = pin::read_secret("Новый PIN: ")?;
            trust.pin = Some(pin::PinRecord::new(&pin)?);
            trust.save()?;
            log_event("PIN changed");
            println!("PIN сохранён.");
            Ok(())
        }
        Command::List => {
            let trust = identity::Trust::load()?;
            println!("ID этого ПК: {}", id.host_id());
            println!("Устройства, которым разрешён вход сюда:");
            for c in &trust.clients {
                println!("  {}  {}", c.name, c.id);
            }
            println!("ПК, к которым можно подключиться:");
            for h in &trust.hosts {
                println!("  {}  {}", h.name, h.id);
            }
            Ok(())
        }
        Command::NetCheck => {
            println!("{}", runtime.block_on(net::self_check())?);
            Ok(())
        }
        Command::Revoke { who } => {
            let mut trust = identity::Trust::load()?;
            let removed = trust.revoke(&who)?;
            trust.save()?;
            log_event(&format!("revoked '{who}': {removed} entries"));
            println!("Удалено записей: {removed}");
            Ok(())
        }
    }
}
