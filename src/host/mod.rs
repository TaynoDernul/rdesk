//! The side being controlled: checks the PIN, then runs one session at a time.
//! Unpaired devices never get this far: the gate in `net` closes them right
//! after the handshake.

mod encoder;
mod indicator;
mod input;
mod video;

use crate::identity::{short_id, Identity, Trust};
use crate::pin::{PinGuard, PinRecord};
use crate::files::{self, Progress};
use crate::proto::{read_msg, write_msg, ClientMsg, HostMsg};
use crate::{audio, clipboard, log_event, net};
use anyhow::{anyhow, bail, Context, Result};
use iroh::endpoint::{Connection, RecvStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
    let ClientMsg::Hello { max_bitrate_kbps, fps, clipboard: clipboard_on, audio: audio_on, pin } = hello else {
        bail!("expected Hello");
    };

    // Nothing is captured or accepted from this device before this check.
    if let Err(reason) = check_pin(trust.pin.as_ref(), pin, &peer).await {
        conn.close(2u32.into(), reason.as_bytes());
        return Ok(());
    }
    let mut view_only = false;
    if trust.confirm {
        match ask_permission(&peer, Duration::from_secs(30)).await {
            Some(only_view) => view_only = only_view,
            None => {
                log_event(&format!("session from '{peer}' refused at this PC"));
                conn.close(2u32.into(), "на удалённом ПК подключение не разрешили".as_bytes());
                return Ok(());
            }
        }
        log_event(&format!("session from '{peer}' allowed at this PC{}", if view_only { ", view only" } else { "" }));
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

    let progress = Arc::new(Progress::default());
    let (clip_tx, clip_rx) = mpsc::unbounded_channel::<clipboard::Change>();
    let disconnect = Arc::new(Notify::new());
    let banner = indicator::start(&peer, disconnect.clone(), clipboard_on.then_some(clip_tx));
    if banner.is_none() {
        // Unattended control without the visible banner is not allowed.
        conn.close(1u32.into(), b"indicator failed");
        bail!("cannot show the session banner");
    }
    let _session = SessionGuard::new(&peer, &conn);
    if view_only {
        let _ = ctl_tx.send(HostMsg::Notice { text: "разрешён только просмотр".to_string() });
    }
    {
        let ctl = ctl_tx.clone();
        crate::chat::start(
            &format!("rdesk: чат с «{peer}»"),
            Box::new(move |text| {
                let _ = ctl.send(HostMsg::Chat { text });
            }),
        );
    }

    let shared = Arc::new(VideoShared {
        stop: AtomicBool::new(false),
        force_key: AtomicBool::new(true),
        restart: AtomicBool::new(false),
        monitor: AtomicUsize::new(0),
        rect: Mutex::new(Default::default()),
        max_kbps: AtomicU32::new(max_bitrate_kbps.clamp(1_000, 200_000)),
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

    let sound = Mutex::new(audio_on.then(|| audio::Capture::start(conn.clone())));
    let notify: Arc<dyn Fn(String) + Send + Sync> = Arc::new(set_note);
    let files = tokio::spawn(files::receive_all(conn.clone(), progress.clone(), notify));
    let clip = tokio::spawn(forward_clipboard(clip_rx, conn.clone(), ctl_tx.clone(), progress.clone()));
    let context = Session {
        conn: conn.clone(),
        shared: shared.clone(),
        ctl: ctl_tx.clone(),
        progress,
        peer: peer.clone(),
        view_only,
    };
    let result = tokio::select! {
        r = input_loop(&mut recv, &context, &sound) => r,
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
    let sound = sound.lock().expect("sound lock").take();
    tokio::task::spawn_blocking(move || drop(sound)).await?;
    files.abort();
    clip.abort();
    crate::chat::close();
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

/// What the message loop needs besides the stream it reads.
struct Session {
    conn: Connection,
    shared: Arc<VideoShared>,
    ctl: mpsc::UnboundedSender<HostMsg>,
    progress: Arc<Progress>,
    peer: String,
    /// Allowed to watch only: input from the other side is ignored.
    view_only: bool,
}

/// Asks whoever sits at this PC. Some(false) allows control, Some(true)
/// allows watching only, None refuses, and so does no answer in time.
async fn ask_permission(peer: &str, wait: Duration) -> Option<bool> {
    use windows::Win32::UI::WindowsAndMessaging::*;
    let text = format!(
        "Устройство «{peer}» хочет подключиться к этому компьютеру.\n\n\
         Да: разрешить управление\nНет: только просмотр экрана\nОтмена: отклонить\n\n\
         Без ответа через 30 секунд подключение будет отклонено."
    );
    let thread = Arc::new(AtomicU32::new(0));
    let asking = {
        let thread = thread.clone();
        tokio::task::spawn_blocking(move || {
            thread.store(unsafe { windows::Win32::System::Threading::GetCurrentThreadId() }, Ordering::SeqCst);
            let text: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                MessageBoxW(
                    None,
                    windows::core::PCWSTR(text.as_ptr()),
                    windows::core::w!("rdesk: запрос подключения"),
                    MB_YESNOCANCEL | MB_ICONQUESTION | MB_DEFBUTTON3 | MB_TOPMOST | MB_SETFOREGROUND,
                )
            }
        })
    };
    tokio::pin!(asking);
    let answer = match tokio::time::timeout(wait, &mut asking).await {
        Ok(answer) => answer.ok(),
        Err(_) => {
            // Press Cancel for the absent user, then collect the result.
            unsafe extern "system" fn cancel(hwnd: windows::Win32::Foundation::HWND, _: windows::Win32::Foundation::LPARAM) -> windows::Win32::Foundation::BOOL {
                let _ = PostMessageW(hwnd, WM_COMMAND, windows::Win32::Foundation::WPARAM(IDCANCEL.0 as usize), windows::Win32::Foundation::LPARAM(0));
                true.into()
            }
            let _ = unsafe { EnumThreadWindows(thread.load(Ordering::SeqCst), Some(cancel), windows::Win32::Foundation::LPARAM(0)) };
            let _ = asking.await;
            None
        }
    };
    match answer {
        Some(IDYES) => Some(false),
        Some(IDNO) => Some(true),
        _ => None,
    }
}

/// Sends what is copied on this PC: text on the control stream, pictures and
/// files on streams of their own.
async fn forward_clipboard(
    mut changes: mpsc::UnboundedReceiver<clipboard::Change>,
    conn: Connection,
    ctl: mpsc::UnboundedSender<HostMsg>,
    progress: Arc<Progress>,
) {
    while let Some(change) = changes.recv().await {
        let result = match change {
            clipboard::Change::Text(text) => {
                let _ = ctl.send(HostMsg::Clipboard { text });
                Ok(())
            }
            clipboard::Change::Image(dib) => files::send_image(&conn, &dib).await,
            clipboard::Change::Files(paths) => {
                files::send_paths(&conn, &paths, true, &progress).await.map(|_| ())
            }
        };
        if let Err(e) = result {
            let _ = ctl.send(HostMsg::Notice { text: format!("буфер обмена: {e:#}") });
        }
    }
}

/// Opens the file picker on this PC's screen, which the other side sees and
/// controls, and sends what is chosen there.
async fn send_requested(session: &Session, folder: bool) {
    let title = if folder { "Выберите папку для отправки" } else { "Выберите файлы для отправки" };
    let picked = tokio::task::spawn_blocking(move || {
        let _ = unsafe {
            windows::Win32::System::Com::CoInitializeEx(None, windows::Win32::System::Com::COINIT_APARTMENTTHREADED)
        };
        files::pick(None, folder, title)
    })
    .await
    .unwrap_or_default();
    if picked.is_empty() {
        return;
    }
    let text = match files::send_paths(&session.conn, &picked, false, &session.progress).await {
        Ok((count, bytes)) => {
            log_event(&format!("sent {count} files ({bytes} bytes) to the other side"));
            return;
        }
        Err(e) => format!("не удалось отправить: {e:#}"),
    };
    let _ = session.ctl.send(HostMsg::Notice { text });
}

async fn input_loop(
    recv: &mut RecvStream,
    session: &Session,
    sound: &Mutex<Option<audio::Capture>>,
) -> Result<()> {
    let shared = &session.shared;
    // Dropping the injector releases held keys on every exit path.
    let mut injector = input::Injector::default();
    loop {
        let msg: ClientMsg = match read_msg(recv).await {
            Ok(msg) => msg,
            // A closed stream is a normal end of session.
            Err(_) => return Ok(()),
        };
        match msg {
            ClientMsg::MouseMove { .. }
            | ClientMsg::MouseButton { .. }
            | ClientMsg::Wheel { .. }
            | ClientMsg::Key { .. }
                if session.view_only => {}
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
            ClientMsg::SetQuality { kbps } => {
                let kbps = kbps.clamp(1_000, 200_000);
                shared.max_kbps.store(kbps, Ordering::Relaxed);
                // Start the new pipeline at the new ceiling; rate control
                // lowers it again if the network cannot carry it.
                shared.current_kbps.store(kbps, Ordering::Relaxed);
                shared.restart.store(true, Ordering::Relaxed);
            }
            ClientMsg::SetAudio { on } => {
                let mut sound = sound.lock().expect("sound lock");
                if on && sound.is_none() {
                    *sound = Some(audio::Capture::start(session.conn.clone()));
                } else if !on {
                    // Stopping joins a thread that wakes every 10 ms.
                    drop(sound.take());
                }
            }
            ClientMsg::RequestFiles { folder } => {
                // The picker waits for the user; the session goes on meanwhile.
                let session = Session {
                    conn: session.conn.clone(),
                    shared: session.shared.clone(),
                    ctl: session.ctl.clone(),
                    progress: session.progress.clone(),
                    peer: session.peer.clone(),
                    view_only: session.view_only,
                };
                tokio::spawn(async move { send_requested(&session, folder).await });
            }
            ClientMsg::Chat { text } => crate::chat::incoming(&session.peer, &text),
            ClientMsg::Hello { .. } => bail!("duplicate Hello"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shows a real question box for a second, so it is not run by default:
    /// cargo test unanswered_question -- --ignored
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn unanswered_question_refuses_and_closes() {
        let started = std::time::Instant::now();
        assert_eq!(ask_permission("тест", Duration::from_secs(1)).await, None);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}