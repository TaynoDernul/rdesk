//! Always-on-top banner shown for the whole session, so anyone at this PC can
//! see that it is being controlled and end the session with one click.
//! It also watches the clipboard, since that needs a window anyway.

use crate::proto::HostMsg;
use std::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Notify;
use std::sync::Arc;
use windows::core::w;
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::DataExchange::{AddClipboardFormatListener, RemoveClipboardFormatListener};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::*;

const WIDTH: i32 = 430;
const HEIGHT: i32 = 36;
const BUTTON_ID: usize = 1;
const WM_CLIPBOARDUPDATE: u32 = 0x031D;

struct State {
    disconnect: Arc<Notify>,
    clipboard: Option<UnboundedSender<HostMsg>>,
    label: Vec<u16>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// A window handle that the session task can use to close the banner.
#[derive(Clone, Copy)]
pub struct Handle(isize);

impl Handle {
    pub fn close(self) {
        let _ = unsafe { PostMessageW(HWND(self.0 as *mut _), WM_CLOSE, WPARAM(0), LPARAM(0)) };
    }
}

/// Starts the banner thread and returns once the window exists.
pub fn start(
    peer: &str,
    disconnect: Arc<Notify>,
    clipboard: Option<UnboundedSender<HostMsg>>,
) -> Option<Handle> {
    let label = format!("Удалённый сеанс: {peer}");
    let label: Vec<u16> = label.encode_utf16().collect();
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new().name("indicator".into()).spawn(move || {
        *STATE.lock().expect("state lock") = Some(State { disconnect, clipboard, label });
        let hwnd = create_window();
        let _ = tx.send(hwnd.map(|h| Handle(h.0 as isize)));
        if hwnd.is_some() {
            let mut msg = MSG::default();
            unsafe {
                while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }
        *STATE.lock().expect("state lock") = None;
    });
    spawned.ok()?;
    rx.recv().ok().flatten()
}

fn create_window() -> Option<HWND> {
    unsafe {
        let instance = GetModuleHandleW(None).ok()?;
        let class = w!("rdesk-indicator");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: class,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            ..Default::default()
        };
        RegisterClassW(&wc);
        let x = (GetSystemMetrics(SM_CXSCREEN) - WIDTH) / 2;
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            class,
            w!("rdesk"),
            WS_POPUP | WS_VISIBLE,
            x,
            0,
            WIDTH,
            HEIGHT,
            None,
            None,
            instance,
            None,
        )
        .ok()?;
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("BUTTON"),
            w!("Отключить"),
            WINDOW_STYLE(BS_PUSHBUTTON as u32) | WS_CHILD | WS_VISIBLE,
            WIDTH - 104,
            5,
            98,
            26,
            hwnd,
            HMENU(BUTTON_ID as *mut _),
            instance,
            None,
        );
        let _ = AddClipboardFormatListener(hwnd);
        Some(hwnd)
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND if wparam.0 & 0xFFFF == BUTTON_ID => {
            if let Some(state) = STATE.lock().expect("state lock").as_ref() {
                crate::log_event("session ended from the banner on this PC");
                state.disconnect.notify_one();
            }
            LRESULT(0)
        }
        WM_CLIPBOARDUPDATE => {
            let sender = STATE
                .lock()
                .expect("state lock")
                .as_ref()
                .and_then(|s| s.clipboard.clone());
            if let Some(sender) = sender {
                if let Some(text) = crate::clipboard::take_local_change() {
                    let _ = sender.send(HostMsg::Clipboard { text });
                }
            }
            LRESULT(0)
        }
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let dc = BeginPaint(hwnd, &mut ps);
            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);
            let brush = CreateSolidBrush(COLORREF(0x002A_1EB4)); // BGR: strong red
            FillRect(dc, &client, brush);
            let _ = DeleteObject(brush);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, COLORREF(0x00FF_FFFF));
            let font = HFONT(GetStockObject(DEFAULT_GUI_FONT).0);
            SelectObject(dc, font);
            let mut area = RECT { left: 12, top: 0, right: WIDTH - 110, bottom: HEIGHT };
            if let Some(state) = STATE.lock().expect("state lock").as_ref() {
                let mut label = state.label.clone();
                DrawTextW(dc, &mut label, &mut area, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
            }
            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        WM_DESTROY => {
            let _ = RemoveClipboardFormatListener(hwnd);
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
