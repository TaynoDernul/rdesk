//! The controlling side. The UI thread owns the window, a decode thread owns
//! the GPU, and network I/O runs on Tokio.

mod decoder;
mod render;
mod toolbar;
mod window;

use crate::fec::{Assembler, Frame};
use crate::identity::{Identity, Trust};
use crate::files::{self, Progress};
use crate::proto::{read_msg, write_msg, ClientMsg, HostMsg, ALPN_SESSION};
use crate::{audio, clipboard, log_event, net};
use anyhow::{anyhow, Result};
use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const KEYFRAME_RETRY: Duration = Duration::from_millis(500);
const ASSEMBLER_TICK: Duration = Duration::from_millis(10);

/// Frames waiting for the decode thread, used to skip stale presents.
pub static QUEUED: AtomicUsize = AtomicUsize::new(0);

pub struct Options {
    pub target: String,
    pub bitrate_kbps: u32,
    pub fps: u32,
    pub clipboard: bool,
    pub audio: bool,
    pub stats: bool,
    pub duration: Option<u64>,
    /// Started from the window, so there is no console to report to.
    pub dialogs: bool,
}

/// Why the session ended, when the user did not close it themself.
static END_REASON: Mutex<Option<String>> = Mutex::new(None);
/// Latest host message, shown in the title because there may be no console.
static NOTICE: Mutex<String> = Mutex::new(String::new());

pub fn set_end_reason(text: String) {
    *END_REASON.lock().expect("reason lock") = Some(text);
}

/// Text for a closed connection, or None when this side closed it.
fn describe_close(reason: &ConnectionError) -> Option<String> {
    match reason {
        ConnectionError::LocallyClosed => None,
        ConnectionError::ApplicationClosed(close) => {
            Some(String::from_utf8_lossy(&close.reason).into_owned())
        }
        ConnectionError::TimedOut => Some("связь с удалённым ПК потеряна".to_string()),
        other => Some(other.to_string()),
    }
}

fn route_text(conn: &Connection) -> (f64, &'static str) {
    match net::route_info(conn) {
        Some((rtt, true)) => (rtt.as_secs_f64() * 1000.0, "через ретранслятор"),
        Some((rtt, false)) => (rtt.as_secs_f64() * 1000.0, "напрямую"),
        None => (0.0, "соединение"),
    }
}

#[derive(Default)]
pub struct Stats {
    pub decoded: AtomicU64,
    pub presented: AtomicU64,
    pub decode_us: AtomicU64,
    pub bytes: AtomicU64,
    pub audio_bytes: AtomicU64,
    pub lost: AtomicU64,
    pub recovered: AtomicU64,
    pub latency_sum_us: AtomicI64,
    pub latency_count: AtomicU64,
}

impl Stats {
    /// Capture-to-present time. Comparable only if both clocks agree, as they
    /// do when host and client are the same PC or are synced closely by NTP.
    pub fn record_latency(&self, capture_us: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        self.latency_sum_us.fetch_add(now - capture_us as i64, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn run(runtime: tokio::runtime::Runtime, id: Identity, options: Options) -> Result<()> {
    let host = Trust::load()?.find_host(&options.target)?;
    let pin = crate::pin::read_secret("PIN удалённого ПК: ")?;
    if pin.is_empty() {
        return Err(anyhow!("PIN не введён"));
    }
    println!("Подключение к «{}»…", host.name);
    let endpoint = runtime.block_on(net::client_endpoint(&id.client_key))?;
    let connected = runtime.block_on(async {
        let conn = net::dial(&endpoint, &host.id, ALPN_SESSION).await?;
        // Checked before any window opens, so a wrong PIN shows only the message.
        let control = authenticate(&conn, &options, pin).await?;
        Ok::<_, anyhow::Error>((conn, control))
    });
    let (conn, (control_send, control_recv)) = match connected {
        Ok(connected) => connected,
        Err(e) => {
            runtime.block_on(endpoint.close());
            return Err(e);
        }
    };
    let (_, route) = route_text(&conn);
    println!("Подключено ({route}). Шифрование сквозное, ключ удалённого ПК подтверждён.");
    println!("Ctrl+Alt+Shift+F: полный экран; +M: следующий монитор; +Q: выход.");
    println!("Перетащите файл в окно, чтобы отправить его на удалённый ПК.");
    log_event(&format!("connected to '{}' ({route})", host.name));

    let (outbox_tx, outbox_rx) = mpsc::unbounded_channel::<ClientMsg>();
    let (files_tx, files_rx) = mpsc::unbounded_channel::<Vec<PathBuf>>();
    let (clip_tx, clip_rx) = mpsc::unbounded_channel::<clipboard::Change>();
    let progress = Arc::new(Progress::default());
    let (frames_tx, frames_rx) = std::sync::mpsc::channel::<Frame>();
    let stats = Arc::new(Stats::default());

    let hwnd = window::create(
        &format!("rdesk: {}", host.name),
        outbox_tx.clone(),
        files_tx,
        clip_tx,
        options.clipboard,
        options.bitrate_kbps,
        options.audio,
    )?;

    {
        let outbox = outbox_tx.clone();
        crate::chat::start(
            &format!("rdesk: чат с «{}»", host.name),
            Box::new(move |text| {
                let _ = outbox.send(ClientMsg::Chat { text });
            }),
        );
    }
    runtime.block_on(start_control(control_send, control_recv, options.clipboard, outbox_rx, host.name.clone()));
    let hello_done = outbox_tx.clone();
    // Playback runs for the whole session; with sound off it just stays silent.
    let player = audio::Player::start();
    runtime.spawn(receive_video(conn.clone(), frames_tx, hello_done, stats.clone(), player));
    runtime.spawn(send_files(conn.clone(), files_rx, progress.clone()));
    runtime.spawn(forward_clipboard(clip_rx, conn.clone(), outbox_tx.clone(), progress.clone()));
    let notify: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|text: String| {
        println!("{text}");
        *NOTICE.lock().expect("notice lock") = text;
    });
    runtime.spawn(files::receive_all(conn.clone(), progress.clone(), notify));
    runtime.spawn(report_stats(conn.clone(), stats.clone(), host.name.clone(), options.stats, progress));
    if let Some(seconds) = options.duration {
        runtime.spawn(async move {
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            window::request_close();
        });
    }
    {
        let conn = conn.clone();
        runtime.spawn(async move {
            let reason = conn.closed().await;
            println!("Соединение закрыто: {reason}");
            if let Some(text) = describe_close(&reason) {
                set_end_reason(text);
            }
            window::request_close();
        });
    }

    // Window handles are plain integers in this direction; only this thread
    // and the decode thread use the handle while the window exists.
    let hwnd_value = hwnd.0 as isize;
    let decode_stats = stats.clone();
    let fps = options.fps;
    let video_thread = std::thread::Builder::new().name("decode".into()).spawn(move || {
        let hwnd = windows::Win32::Foundation::HWND(hwnd_value as *mut _);
        render::run(hwnd, fps, frames_rx, decode_stats);
    })?;

    window::message_loop();

    let _ = outbox_tx.send(ClientMsg::ReleaseAll);
    runtime.block_on(async {
        // Lets ReleaseAll leave before the connection closes.
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    conn.close(0u32.into(), b"client closed");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), conn.closed()).await.ok();
        tokio::time::timeout(Duration::from_secs(2), endpoint.close()).await.ok();
    });
    let _ = video_thread.join();
    crate::chat::close();
    log_event("client session ended");
    if options.dialogs {
        if let Some(reason) = END_REASON.lock().expect("reason lock").take() {
            crate::message_box(&format!("Сеанс завершён: {reason}"));
        }
    }
    Ok(())
}

/// Sends the PIN and waits for the host's answer. A refusal arrives as the
/// connection closing with a reason, which becomes the error text.
async fn authenticate(
    conn: &Connection,
    options: &Options,
    pin: String,
) -> Result<(SendStream, RecvStream)> {
    let opened = conn.open_bi().await;
    let (mut send, mut recv) = match opened {
        Ok(streams) => streams,
        // The host's gate may already have closed us, with the reason.
        Err(e) => return Err(anyhow!(describe_close(&e).unwrap_or_else(|| e.to_string()))),
    };
    write_msg(
        &mut send,
        &ClientMsg::Hello {
            max_bitrate_kbps: options.bitrate_kbps,
            fps: options.fps,
            clipboard: options.clipboard,
            audio: options.audio,
            pin,
        },
    )
    .await?;
    match read_msg::<_, HostMsg>(&mut recv).await {
        Ok(HostMsg::Accepted) => Ok((send, recv)),
        Ok(_) => Err(anyhow!("хост ответил не по протоколу")),
        Err(_) => {
            let reason = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
            let text = reason.ok().and_then(|r| describe_close(&r));
            Err(anyhow!(text.unwrap_or_else(|| "хост не ответил".to_string())))
        }
    }
}

async fn start_control(
    mut send: SendStream,
    mut recv: RecvStream,
    clipboard_on: bool,
    mut outbox: mpsc::UnboundedReceiver<ClientMsg>,
    host_name: String,
) {
    tokio::spawn(async move {
        while let Some(msg) = outbox.recv().await {
            if write_msg(&mut send, &msg).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        loop {
            let msg: HostMsg = match read_msg(&mut recv).await {
                Ok(msg) => msg,
                Err(_) => break,
            };
            match msg {
                HostMsg::Accepted => {}
                HostMsg::VideoInfo { monitor, monitors, width, height } => {
                    println!("Удалённый экран {}/{monitors}: {width}x{height}", monitor + 1);
                    window::set_monitor_info(monitor, monitors);
                    NOTICE.lock().expect("notice lock").clear();
                }
                HostMsg::CursorVisible { visible } => window::set_cursor_visible(visible),
                HostMsg::CursorShape(shape) => window::set_cursor_shape(shape),
                HostMsg::Clipboard { text } => {
                    if clipboard_on {
                        if let Err(e) = clipboard::set_remote_text(&text) {
                            log_event(&format!("clipboard: {e:#}"));
                        }
                    }
                }
                HostMsg::Notice { text } => {
                    println!("Хост: {text}");
                    *NOTICE.lock().expect("notice lock") = text;
                }
                HostMsg::Chat { text } => crate::chat::incoming(&host_name, &text),
            }
        }
    });
}

async fn receive_video(
    conn: Connection,
    frames: std::sync::mpsc::Sender<Frame>,
    outbox: mpsc::UnboundedSender<ClientMsg>,
    stats: Arc<Stats>,
    player: audio::Player,
) {
    let mut assembler = Assembler::new();
    let mut tick = tokio::time::interval(ASSEMBLER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_request = Instant::now();
    // Allow the host's opening keyframe to arrive before asking for another.
    let mut received_any = false;

    loop {
        let ready = tokio::select! {
            datagram = conn.read_datagram() => {
                let Ok(datagram) = datagram else { return };
                stats.bytes.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                if audio::is_audio(&datagram) {
                    stats.audio_bytes.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                    player.push(&datagram);
                    continue;
                }
                received_any = true;
                match assembler.push(&datagram, Instant::now()) {
                    Ok(frames) => frames,
                    Err(e) => {
                        log_event(&format!("bad video packet: {e:#}"));
                        Vec::new()
                    }
                }
            }
            _ = tick.tick() => assembler.tick(Instant::now()),
        };
        for frame in ready {
            QUEUED.fetch_add(1, Ordering::Relaxed);
            if frames.send(frame).is_err() {
                return;
            }
        }
        stats.lost.store(assembler.frames_lost, Ordering::Relaxed);
        stats.recovered.store(assembler.shards_recovered, Ordering::Relaxed);

        if received_any && assembler.needs_keyframe() && last_request.elapsed() >= KEYFRAME_RETRY {
            last_request = Instant::now();
            let _ = outbox.send(ClientMsg::RequestKeyframe);
        }
    }
}

async fn send_files(conn: Connection, mut batches: mpsc::UnboundedReceiver<Vec<PathBuf>>, progress: Arc<Progress>) {
    while let Some(paths) = batches.recv().await {
        let (conn, progress) = (conn.clone(), progress.clone());
        tokio::spawn(async move {
            let text = match files::send_paths(&conn, &paths, false, &progress).await {
                Ok((count, bytes)) => format!("Отправлено файлов: {count} ({} МБ)", bytes / 1_000_000),
                Err(e) => format!("Не удалось отправить: {e:#}"),
            };
            println!("{text}");
            *NOTICE.lock().expect("notice lock") = text;
        });
    }
}

/// Sends what is copied on this PC: text on the control stream, pictures and
/// files on streams of their own.
async fn forward_clipboard(
    mut changes: mpsc::UnboundedReceiver<clipboard::Change>,
    conn: Connection,
    outbox: mpsc::UnboundedSender<ClientMsg>,
    progress: Arc<Progress>,
) {
    while let Some(change) = changes.recv().await {
        let result = match change {
            clipboard::Change::Text(text) => {
                let _ = outbox.send(ClientMsg::Clipboard { text });
                Ok(())
            }
            clipboard::Change::Image(dib) => files::send_image(&conn, &dib).await,
            clipboard::Change::Files(paths) => {
                files::send_paths(&conn, &paths, true, &progress).await.map(|_| ())
            }
        };
        if let Err(e) = result {
            *NOTICE.lock().expect("notice lock") = format!("буфер обмена: {e:#}");
        }
    }
}
async fn report_stats(conn: Connection, stats: Arc<Stats>, name: String, print: bool, progress: Arc<Progress>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await;
    let (mut decoded, mut presented, mut decode_us, mut bytes, mut audio_bytes) = (0, 0, 0, 0, 0);
    let (mut latency_sum, mut latency_count) = (0i64, 0u64);
    loop {
        tick.tick().await;
        let d = stats.decoded.load(Ordering::Relaxed);
        let p = stats.presented.load(Ordering::Relaxed);
        let us = stats.decode_us.load(Ordering::Relaxed);
        let b = stats.bytes.load(Ordering::Relaxed);
        let ab = stats.audio_bytes.load(Ordering::Relaxed);
        let ls = stats.latency_sum_us.load(Ordering::Relaxed);
        let lc = stats.latency_count.load(Ordering::Relaxed);
        let (frames, shown) = (d - decoded, p - presented);
        let mbit = (b - bytes) as f64 * 8.0 / 1e6;
        let (rtt, route) = route_text(&conn);
        let lost = stats.lost.load(Ordering::Relaxed);
        let notice = NOTICE.lock().expect("notice lock").clone();
        let notice = match progress.text() {
            Some(moving) => format!("  |  {moving}"),
            None if notice.is_empty() => notice,
            None => format!("  |  {notice}"),
        };
        window::set_title(&format!(
            "rdesk: {name}  |  {shown} FPS  |  {mbit:.1} Мбит/с  |  {route}, {rtt:.0} мс  |  потеряно {lost}{notice}"
        ));
        if print {
            let decode_ms = (us - decode_us) as f64 / frames.max(1) as f64 / 1000.0;
            let latency_ms = (ls - latency_sum) as f64 / (lc - latency_count).max(1) as f64 / 1000.0;
            println!(
                "client: декодировано {frames}, показано {shown} FPS, {mbit:.1} Мбит/с, {route} RTT {rtt:.1} мс, декодирование {decode_ms:.2} мс, захват→показ {latency_ms:.1} мс, потеряно {lost}, восстановлено {}, звук {} кбит/с",
                stats.recovered.load(Ordering::Relaxed),
                (ab - audio_bytes) * 8 / 1000
            );
        }
        audio_bytes = ab;
        (decoded, presented, decode_us, bytes, latency_sum, latency_count) = (d, p, us, b, ls, lc);
    }
}
