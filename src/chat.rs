//! A small chat window, the same on both sides of a session. It runs on its
//! own thread, stays hidden until opened or until a message arrives, and is
//! closed with the session.

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Mutex;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, CLEARTYPE_QUALITY, COLOR_WINDOW, DEFAULT_CHARSET, FW_NORMAL, HFONT,
};
use windows::Win32::UI::Controls::{EM_REPLACESEL, EM_SETLIMITTEXT, EM_SETSEL};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{SetFocus, VK_RETURN};
use windows::Win32::UI::WindowsAndMessaging::*;

pub const MAX_MESSAGE: usize = 4000;
const WM_APP_SHOW: u32 = WM_APP + 20;
const WM_APP_LINE: u32 = WM_APP + 21;
const ID_SEND: usize = 1;

type Sender = Box<dyn Fn(String) + Send>;

struct State {
    send: Sender,
    pending: Vec<String>,
    history: HWND,
    input: HWND,
    font: HFONT,
}

// Window handles cross threads as integers; only the chat thread uses them.
unsafe impl Send for State {}

static STATE: Mutex<Option<State>> = Mutex::new(None);
static WINDOW: AtomicIsize = AtomicIsize::new(0);

fn window() -> HWND {
    HWND(WINDOW.load(Ordering::Relaxed) as *mut _)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn clock() -> String {
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!("{:02}:{:02}", t.wHour, t.wMinute)
}

/// One history line, with Windows line breaks so the edit box shows them.
fn line(who: &str, text: &str) -> String {
    let text: String = text.chars().take(MAX_MESSAGE).collect();
    format!("[{}] {who}: {}\r\n", clock(), text.replace("\r\n", "\n").replace('\n', "\r\n    "))
}

/// Creates the hidden chat window. `send` is called with each typed message.
pub fn start(title: &str, send: Sender) {
    if !window().0.is_null() {
        // The last session's window has not closed yet: it serves this one.
        if let Some(state) = STATE.lock().expect("chat lock").as_mut() {
            state.send = send;
        }
        return;
    }
    let title = wide(title);
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new().name("chat".into()).spawn(move || {
        *STATE.lock().expect("chat lock") = Some(State {
            send,
            pending: Vec::new(),
            history: HWND::default(),
            input: HWND::default(),
            font: HFONT::default(),
        });
        let created = unsafe { create(&title) };
        let _ = tx.send(());
        if created {
            unsafe {
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
                    // Enter in the input box sends instead of beeping.
                    let input = STATE.lock().expect("chat lock").as_ref().map(|s| s.input);
                    if msg.message == WM_KEYDOWN && msg.wParam.0 == VK_RETURN.0 as usize && Some(msg.hwnd) == input {
                        submit();
                        continue;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }
        WINDOW.store(0, Ordering::Relaxed);
        if let Some(state) = STATE.lock().expect("chat lock").take() {
            let _ = unsafe { DeleteObject(state.font) };
        }
    });
    if spawned.is_ok() {
        let _ = rx.recv();
    }
}

unsafe fn create(title: &[u16]) -> bool {
    let Ok(instance) = GetModuleHandleW(None) else { return false };
    let class = w!("rdesk-chat");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wndproc),
        hInstance: instance.into(),
        lpszClassName: class,
        hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
        hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH((COLOR_WINDOW.0 + 1) as isize as *mut _),
        hIcon: LoadIconW(instance, PCWSTR(1 as *const u16)).unwrap_or_default(),
        ..Default::default()
    };
    RegisterClassW(&wc);
    let Ok(hwnd) = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        PCWSTR(title.as_ptr()),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        460,
        380,
        None,
        None,
        instance,
        None,
    ) else {
        return false;
    };
    WINDOW.store(hwnd.0 as isize, Ordering::Relaxed);
    crate::system::apply_title_theme(hwnd);
    let dpi = GetDpiForWindow(hwnd).max(96) as i32;
    let _ = SetWindowPos(hwnd, None, 0, 0, 460 * dpi / 96, 380 * dpi / 96, SWP_NOMOVE | SWP_NOZORDER);
    let font = CreateFontW(
        -15 * dpi / 96, 0, 0, 0, FW_NORMAL.0 as i32, 0, 0, 0, DEFAULT_CHARSET.0 as u32, 0, 0,
        CLEARTYPE_QUALITY.0 as u32, 0, w!("Segoe UI"),
    );
    let child = |class: PCWSTR, text: PCWSTR, style: WINDOW_STYLE, id: usize| {
        CreateWindowExW(
            WS_EX_CLIENTEDGE,
            class,
            text,
            style | WS_CHILD | WS_VISIBLE,
            0,
            0,
            10,
            10,
            hwnd,
            HMENU(id as *mut _),
            instance,
            None,
        )
        .unwrap_or_default()
    };
    let history = child(
        w!("EDIT"),
        w!(""),
        WINDOW_STYLE((ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32) | WS_VSCROLL,
        10,
    );
    let input = child(w!("EDIT"), w!(""), WINDOW_STYLE(ES_AUTOHSCROLL as u32) | WS_TABSTOP, 11);
    let button = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        w!("BUTTON"),
        w!("Отправить"),
        WINDOW_STYLE(BS_DEFPUSHBUTTON as u32) | WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        0,
        0,
        10,
        10,
        hwnd,
        HMENU(ID_SEND as *mut _),
        instance,
        None,
    )
    .unwrap_or_default();
    for control in [history, input, button] {
        SendMessageW(control, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }
    let _ = SendMessageW(input, EM_SETLIMITTEXT, WPARAM(MAX_MESSAGE), LPARAM(0));
    if let Some(state) = STATE.lock().expect("chat lock").as_mut() {
        state.history = history;
        state.input = input;
        state.font = font;
    }
    layout(hwnd);
    true
}

unsafe fn layout(hwnd: HWND) {
    let Some((history, input)) = STATE.lock().expect("chat lock").as_ref().map(|s| (s.history, s.input)) else {
        return;
    };
    let mut r = RECT::default();
    let _ = GetClientRect(hwnd, &mut r);
    let dpi = GetDpiForWindow(hwnd).max(96) as i32;
    let s = |v: i32| v * dpi / 96;
    let (pad, row, button_w) = (s(10), s(30), s(110));
    let bottom = r.bottom - pad - row;
    let _ = MoveWindow(history, pad, pad, r.right - 2 * pad, bottom - 2 * pad, true);
    let _ = MoveWindow(input, pad, bottom, r.right - 3 * pad - button_w, row, true);
    if let Ok(button) = GetDlgItem(hwnd, ID_SEND as i32) {
        let _ = MoveWindow(button, r.right - pad - button_w, bottom, button_w, row, true);
    }
}

unsafe fn append(text: &str) {
    let Some(history) = STATE.lock().expect("chat lock").as_ref().map(|s| s.history) else { return };
    let len = GetWindowTextLengthW(history);
    let _ = SendMessageW(history, EM_SETSEL, WPARAM(len as usize), LPARAM(len as isize));
    let text = wide(text);
    let _ = SendMessageW(history, EM_REPLACESEL, WPARAM(0), LPARAM(text.as_ptr() as isize));
}

unsafe fn submit() {
    let mut guard = STATE.lock().expect("chat lock");
    let Some(state) = guard.as_mut() else { return };
    let len = GetWindowTextLengthW(state.input) as usize;
    let mut buffer = vec![0u16; len + 1];
    let copied = GetWindowTextW(state.input, &mut buffer) as usize;
    let text = String::from_utf16_lossy(&buffer[..copied]).trim().to_string();
    if text.is_empty() {
        return;
    }
    let _ = SetWindowTextW(state.input, w!(""));
    (state.send)(text.clone());
    drop(guard);
    append(&line("Вы", &text));
}

/// Shows the window, for example from the session menu.
pub fn show() {
    let _ = unsafe { PostMessageW(window(), WM_APP_SHOW, WPARAM(0), LPARAM(0)) };
}

/// Adds a message from the other side and brings the window up.
pub fn incoming(who: &str, text: &str) {
    if let Some(state) = STATE.lock().expect("chat lock").as_mut() {
        state.pending.push(line(who, text));
    }
    let _ = unsafe { PostMessageW(window(), WM_APP_LINE, WPARAM(0), LPARAM(0)) };
}

pub fn close() {
    let _ = unsafe { PostMessageW(window(), WM_CLOSE, WPARAM(0), LPARAM(1)) };
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_SIZE => {
            layout(hwnd);
            LRESULT(0)
        }
        WM_COMMAND if wparam.0 & 0xFFFF == ID_SEND => {
            submit();
            LRESULT(0)
        }
        WM_APP_SHOW => {
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
            let _ = SetForegroundWindow(hwnd);
            if let Some(input) = STATE.lock().expect("chat lock").as_ref().map(|s| s.input) {
                let _ = SetFocus(input);
            }
            LRESULT(0)
        }
        WM_APP_LINE => {
            let lines = STATE.lock().expect("chat lock").as_mut().map(|s| std::mem::take(&mut s.pending));
            for text in lines.unwrap_or_default() {
                append(&text);
            }
            // Shown without stealing focus from whatever is being typed.
            if !IsWindowVisible(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            }
            let _ = FlashWindow(hwnd, true);
            LRESULT(0)
        }
        // The close box only hides it; the session closes it for real.
        WM_CLOSE if lparam.0 != 1 => {
            let _ = ShowWindow(hwnd, SW_HIDE);
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_use_windows_breaks_and_are_capped() {
        let l = line("Вы", "a\nb");
        assert!(l.ends_with("Вы: a\r\n    b\r\n"), "{l}");
        let long = "x".repeat(MAX_MESSAGE + 50);
        assert!(line("Вы", &long).matches('x').count() == MAX_MESSAGE);
    }
}
