//! Client window, input capture and remote cursor. The mouse pointer is drawn
//! locally using the shape sent by the host, so it never lags behind the hand.

use crate::d3d;
use crate::proto::{ClientMsg, CursorShape};
use anyhow::{anyhow, bail, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc::UnboundedSender;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateBitmap, DeleteObject, GetMonitorInfoW, MonitorFromWindow, HBITMAP, MONITORINFO,
    MONITOR_DEFAULTTONEAREST,
};
use windows::Win32::System::DataExchange::{AddClipboardFormatListener, RemoveClipboardFormatListener};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture, VK_CONTROL, VK_LCONTROL, VK_LMENU, VK_LSHIFT, VK_MENU, VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_SHIFT};
use windows::Win32::UI::Shell::{DragAcceptFiles, DragFinish, DragQueryFileW, HDROP};
use windows::Win32::UI::WindowsAndMessaging::*;

const WM_APP_CURSOR: u32 = WM_APP + 1;
const WM_CLIPBOARDUPDATE: u32 = 0x031D;
const LLKHF_EXTENDED_BIT: u32 = 0x01;
const LLKHF_INJECTED_BIT: u32 = 0x10;
const LLKHF_UP_BIT: u32 = 0x80;
const KEY_F: u32 = 0x46;
const KEY_M: u32 = 0x4D;
const KEY_Q: u32 = 0x51;

static OUTBOX: OnceLock<UnboundedSender<ClientMsg>> = OnceLock::new();
static FILES: OnceLock<UnboundedSender<PathBuf>> = OnceLock::new();
static HWND_VALUE: AtomicIsize = AtomicIsize::new(0);
static VIDEO_W: AtomicU32 = AtomicU32::new(0);
static VIDEO_H: AtomicU32 = AtomicU32::new(0);
static CURSOR_VISIBLE: AtomicBool = AtomicBool::new(true);
static CURSOR: AtomicIsize = AtomicIsize::new(0);
static PENDING_SHAPE: Mutex<Option<CursorShape>> = Mutex::new(None);
static CLIPBOARD_ON: AtomicBool = AtomicBool::new(true);
static MONITOR: AtomicU8 = AtomicU8::new(0);
static MONITORS: AtomicU8 = AtomicU8::new(1);
static CTRL: AtomicBool = AtomicBool::new(false);
static ALT: AtomicBool = AtomicBool::new(false);
static SHIFT: AtomicBool = AtomicBool::new(false);
static BUTTONS_DOWN: AtomicU32 = AtomicU32::new(0);
static SAVED_PLACEMENT: Mutex<Option<(WINDOW_STYLE, RECT)>> = Mutex::new(None);
static CLOSING: AtomicBool = AtomicBool::new(false);

/// True once the window is going away; presenting to it then fails harmlessly.
pub fn is_closing() -> bool {
    CLOSING.load(Ordering::Relaxed)
}

fn send(msg: ClientMsg) {
    if let Some(outbox) = OUTBOX.get() {
        let _ = outbox.send(msg);
    }
}

fn hwnd() -> HWND {
    HWND(HWND_VALUE.load(Ordering::Relaxed) as *mut _)
}

pub fn set_video_size(w: u32, h: u32) {
    VIDEO_W.store(w, Ordering::Relaxed);
    VIDEO_H.store(h, Ordering::Relaxed);
}

pub fn video_size() -> Option<(u32, u32)> {
    let (w, h) = (VIDEO_W.load(Ordering::Relaxed), VIDEO_H.load(Ordering::Relaxed));
    (w > 0 && h > 0).then_some((w, h))
}

pub fn set_monitor_info(monitor: u8, monitors: u8) {
    MONITOR.store(monitor, Ordering::Relaxed);
    MONITORS.store(monitors.max(1), Ordering::Relaxed);
}

pub fn set_cursor_visible(visible: bool) {
    CURSOR_VISIBLE.store(visible, Ordering::Relaxed);
    post(WM_APP_CURSOR);
}

pub fn set_cursor_shape(shape: CursorShape) {
    *PENDING_SHAPE.lock().expect("cursor lock") = Some(shape);
    post(WM_APP_CURSOR);
}

fn post(message: u32) {
    let _ = unsafe { PostMessageW(hwnd(), message, WPARAM(0), LPARAM(0)) };
}

pub fn request_close() {
    post(WM_CLOSE);
}

pub fn set_title(text: &str) {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    // Called from the stats task only, so a busy UI thread cannot stall video.
    unsafe {
        let _ = SetWindowTextW(hwnd(), PCWSTR(wide.as_ptr()));
    }
}

pub fn create(
    title: &str,
    outbox: UnboundedSender<ClientMsg>,
    files: UnboundedSender<PathBuf>,
    clipboard: bool,
) -> Result<HWND> {
    OUTBOX.set(outbox).map_err(|_| anyhow!("window already created"))?;
    FILES.set(files).map_err(|_| anyhow!("window already created"))?;
    CLIPBOARD_ON.store(clipboard, Ordering::Relaxed);
    let wide_title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = w!("rdesk-client");
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassW(&wc);
        let (sw, sh) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        let (w, h) = (sw * 4 / 5, sh * 4 / 5);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            PCWSTR(wide_title.as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            (sw - w) / 2,
            (sh - h) / 2,
            w,
            h,
            None,
            None,
            instance,
            None,
        )?;
        HWND_VALUE.store(hwnd.0 as isize, Ordering::Relaxed);
        DragAcceptFiles(hwnd, true);
        if clipboard {
            let _ = AddClipboardFormatListener(hwnd);
        }
        Ok(hwnd)
    }
}

/// Runs the message loop until the window closes. The low-level hook is what
/// lets Win, Alt+Tab and similar keys reach the remote PC instead of this one.
pub fn message_loop() {
    unsafe {
        let hook = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(keyboard_hook),
            GetModuleHandleW(None).map(|m| m.into()).unwrap_or(windows::Win32::Foundation::HINSTANCE(HMODULE::default().0)),
            0,
        );
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if let Ok(hook) = hook {
            let _ = UnhookWindowsHookEx(hook);
        }
    }
}

unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code < 0 || GetForegroundWindow() != hwnd() {
        return CallNextHookEx(None, code, wparam, lparam);
    }
    let info = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
    // Injected events pass through: with host and client on one PC, forwarding
    // them would feed the host's own SendInput back to itself without end.
    if info.flags.0 & LLKHF_INJECTED_BIT != 0 {
        return CallNextHookEx(None, code, wparam, lparam);
    }
    let down = info.flags.0 & LLKHF_UP_BIT == 0;
    let vk = info.vkCode;
    let matches_key = |list: &[u16]| list.contains(&(vk as u16));
    if matches_key(&[VK_CONTROL.0, VK_LCONTROL.0, VK_RCONTROL.0]) {
        CTRL.store(down, Ordering::Relaxed);
    } else if matches_key(&[VK_MENU.0, VK_LMENU.0, VK_RMENU.0]) {
        ALT.store(down, Ordering::Relaxed);
    } else if matches_key(&[VK_SHIFT.0, VK_LSHIFT.0, VK_RSHIFT.0]) {
        SHIFT.store(down, Ordering::Relaxed);
    }

    let combo = CTRL.load(Ordering::Relaxed) && ALT.load(Ordering::Relaxed) && SHIFT.load(Ordering::Relaxed);
    if combo && matches!(vk, KEY_Q | KEY_F | KEY_M) {
        if down {
            send(ClientMsg::ReleaseAll);
            match vk {
                KEY_Q => post(WM_CLOSE),
                KEY_F => toggle_fullscreen(),
                _ => next_monitor(),
            }
        }
        return LRESULT(1);
    }

    send(ClientMsg::Key {
        scan: info.scanCode as u16,
        extended: info.flags.0 & LLKHF_EXTENDED_BIT != 0,
        down,
    });
    LRESULT(1)
}

fn next_monitor() {
    let count = MONITORS.load(Ordering::Relaxed).max(1);
    let next = (MONITOR.load(Ordering::Relaxed) + 1) % count;
    send(ClientMsg::SelectMonitor { index: next });
}

fn toggle_fullscreen() {
    unsafe {
        let hwnd = hwnd();
        let mut saved = SAVED_PLACEMENT.lock().expect("placement lock");
        if let Some((style, rect)) = saved.take() {
            SetWindowLongPtrW(hwnd, GWL_STYLE, style.0 as isize);
            let _ = SetWindowPos(
                hwnd,
                HWND_NOTOPMOST,
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_FRAMECHANGED | SWP_NOOWNERZORDER,
            );
        } else {
            let style = WINDOW_STYLE(GetWindowLongPtrW(hwnd, GWL_STYLE) as u32);
            let mut rect = RECT::default();
            let _ = GetWindowRect(hwnd, &mut rect);
            *saved = Some((style, rect));
            let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            let mut info = MONITORINFO { cbSize: std::mem::size_of::<MONITORINFO>() as u32, ..Default::default() };
            if GetMonitorInfoW(monitor, &mut info).as_bool() {
                let m = info.rcMonitor;
                SetWindowLongPtrW(hwnd, GWL_STYLE, (WS_POPUP | WS_VISIBLE).0 as isize);
                let _ = SetWindowPos(
                    hwnd,
                    HWND_TOP,
                    m.left,
                    m.top,
                    m.right - m.left,
                    m.bottom - m.top,
                    SWP_FRAMECHANGED | SWP_NOOWNERZORDER,
                );
            }
        }
    }
}

/// Converts a window position to 0..=65535 inside the letterboxed picture.
pub fn normalize(x: i32, y: i32, video: (u32, u32), window: (u32, u32)) -> (u16, u16) {
    let area = d3d::letterbox(video, window);
    let axis = |value: i32, start: i32, end: i32| -> u16 {
        let span = (end - start - 1).max(1) as i64;
        let v = (value - start).clamp(0, end - start - 1).max(0) as i64;
        (v * 65535 / span) as u16
    };
    (axis(x, area.left, area.right), axis(y, area.top, area.bottom))
}

fn mouse_position(lparam: LPARAM) -> (i32, i32) {
    let x = (lparam.0 & 0xFFFF) as u16 as i16 as i32;
    let y = ((lparam.0 >> 16) & 0xFFFF) as u16 as i16 as i32;
    (x, y)
}

unsafe fn send_mouse_move(hwnd: HWND, lparam: LPARAM) {
    let Some(video) = video_size() else { return };
    let mut client = RECT::default();
    let _ = GetClientRect(hwnd, &mut client);
    let (x, y) = mouse_position(lparam);
    let (nx, ny) = normalize(x, y, video, (client.right.max(1) as u32, client.bottom.max(1) as u32));
    send(ClientMsg::MouseMove { x: nx, y: ny });
}

unsafe fn button(hwnd: HWND, index: u8, down: bool, lparam: LPARAM) {
    send_mouse_move(hwnd, lparam);
    send(ClientMsg::MouseButton { button: index, down });
    // Keeps receiving mouse-up when a drag leaves the window.
    let bit = 1u32 << index;
    if down {
        if BUTTONS_DOWN.fetch_or(bit, Ordering::Relaxed) == 0 {
            SetCapture(hwnd);
        }
    } else if BUTTONS_DOWN.fetch_and(!bit, Ordering::Relaxed) == bit {
        let _ = ReleaseCapture();
    }
}

unsafe fn apply_cursor() {
    if let Some(shape) = PENDING_SHAPE.lock().expect("cursor lock").take() {
        if let Ok(new_cursor) = build_cursor(&shape) {
            let old = CURSOR.swap(new_cursor.0 as isize, Ordering::Relaxed);
            SetCursor(new_cursor);
            if old != 0 {
                let _ = DestroyIcon(HICON(old as *mut _));
            }
        }
    }
    show_cursor();
}

unsafe fn show_cursor() {
    if CURSOR_VISIBLE.load(Ordering::Relaxed) {
        let current = CURSOR.load(Ordering::Relaxed);
        if current != 0 {
            SetCursor(HCURSOR(current as *mut _));
        } else {
            SetCursor(LoadCursorW(None, IDC_ARROW).unwrap_or_default());
        }
    } else {
        SetCursor(None);
    }
}

/// Validates sizes first: this buffer comes from the network.
fn cursor_rows(shape: &CursorShape, rows: u32, row_bytes: u32) -> Result<()> {
    if shape.width == 0 || shape.height == 0 || shape.width > 512 || shape.height > 1024 {
        bail!("unreasonable cursor size");
    }
    if shape.pitch < row_bytes || (shape.pitch as u64 * rows as u64) > shape.data.len() as u64 {
        bail!("cursor buffer is too small");
    }
    Ok(())
}

fn build_cursor(shape: &CursorShape) -> Result<HCURSOR> {
    let (w, h) = (shape.width, shape.height);
    unsafe {
        let (color, mask): (Option<HBITMAP>, HBITMAP) = match shape.kind {
            // Monochrome: AND and XOR masks stacked in one double-height bitmap.
            1 => {
                let row = w.div_ceil(8);
                cursor_rows(shape, h, row)?;
                let aligned = row.div_ceil(2) * 2;
                let mut bits = vec![0u8; (aligned * h) as usize];
                for y in 0..h as usize {
                    let from = y * shape.pitch as usize;
                    let to = y * aligned as usize;
                    bits[to..to + row as usize].copy_from_slice(&shape.data[from..from + row as usize]);
                }
                let mask = CreateBitmap(w as i32, h as i32, 1, 1, Some(bits.as_ptr() as *const _));
                (None, mask)
            }
            kind @ (2 | 4) => {
                cursor_rows(shape, h, w * 4)?;
                let mut pixels = Vec::with_capacity((w * h * 4) as usize);
                for y in 0..h as usize {
                    let start = y * shape.pitch as usize;
                    for px in shape.data[start..start + (w * 4) as usize].chunks_exact(4) {
                        if kind == 2 {
                            pixels.extend_from_slice(px);
                        } else if px[3] == 0 {
                            // Masked color, opaque pixel.
                            pixels.extend_from_slice(&[px[0], px[1], px[2], 0xFF]);
                        } else if px[0] | px[1] | px[2] == 0 {
                            pixels.extend_from_slice(&[0, 0, 0, 0]);
                        } else {
                            // True XOR is not representable with alpha: use white.
                            pixels.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
                        }
                    }
                }
                let color = CreateBitmap(w as i32, h as i32, 1, 32, Some(pixels.as_ptr() as *const _));
                let mask_bits = vec![0u8; (w.div_ceil(16) * 2 * h) as usize];
                let mask = CreateBitmap(w as i32, h as i32, 1, 1, Some(mask_bits.as_ptr() as *const _));
                (Some(color), mask)
            }
            other => bail!("unknown cursor type {other}"),
        };
        let info = ICONINFO {
            fIcon: false.into(),
            xHotspot: shape.hot_x,
            yHotspot: shape.hot_y,
            hbmMask: mask,
            hbmColor: color.unwrap_or_default(),
        };
        let icon = CreateIconIndirect(&info);
        let _ = DeleteObject(mask);
        if let Some(color) = color {
            let _ = DeleteObject(color);
        }
        Ok(HCURSOR(icon?.0))
    }
}

unsafe fn handle_drop(hdrop: HDROP) {
    let count = DragQueryFileW(hdrop, u32::MAX, None);
    for i in 0..count {
        let len = DragQueryFileW(hdrop, i, None) as usize;
        let mut buffer = vec![0u16; len + 1];
        let copied = DragQueryFileW(hdrop, i, Some(&mut buffer)) as usize;
        let path = PathBuf::from(String::from_utf16_lossy(&buffer[..copied]));
        if let Some(files) = FILES.get() {
            let _ = files.send(path);
        }
    }
    DragFinish(hdrop);
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_MOUSEMOVE => {
            send_mouse_move(hwnd, lparam);
            LRESULT(0)
        }
        WM_LBUTTONDOWN => { button(hwnd, 0, true, lparam); LRESULT(0) }
        WM_LBUTTONUP => { button(hwnd, 0, false, lparam); LRESULT(0) }
        WM_RBUTTONDOWN => { button(hwnd, 1, true, lparam); LRESULT(0) }
        WM_RBUTTONUP => { button(hwnd, 1, false, lparam); LRESULT(0) }
        WM_MBUTTONDOWN => { button(hwnd, 2, true, lparam); LRESULT(0) }
        WM_MBUTTONUP => { button(hwnd, 2, false, lparam); LRESULT(0) }
        WM_XBUTTONDOWN | WM_XBUTTONUP => {
            let index = if (wparam.0 >> 16) & 0xFFFF == 1 { 3 } else { 4 };
            button(hwnd, index, msg == WM_XBUTTONDOWN, lparam);
            LRESULT(1)
        }
        WM_MOUSEWHEEL | WM_MOUSEHWHEEL => {
            let delta = ((wparam.0 >> 16) & 0xFFFF) as u16 as i16;
            send(ClientMsg::Wheel { delta, horizontal: msg == WM_MOUSEHWHEEL });
            LRESULT(0)
        }
        // Dropping focus must not leave modifiers held on the remote PC.
        WM_KILLFOCUS => {
            CTRL.store(false, Ordering::Relaxed);
            ALT.store(false, Ordering::Relaxed);
            SHIFT.store(false, Ordering::Relaxed);
            send(ClientMsg::ReleaseAll);
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_SETCURSOR => {
            if (lparam.0 & 0xFFFF) as u32 == HTCLIENT {
                show_cursor();
                LRESULT(1)
            } else {
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
        }
        WM_APP_CURSOR => {
            apply_cursor();
            LRESULT(0)
        }
        WM_DROPFILES => {
            handle_drop(HDROP(wparam.0 as *mut _));
            LRESULT(0)
        }
        WM_CLIPBOARDUPDATE => {
            if CLIPBOARD_ON.load(Ordering::Relaxed) {
                if let Some(text) = crate::clipboard::take_local_change() {
                    send(ClientMsg::Clipboard { text });
                }
            }
            LRESULT(0)
        }
        // The swap chain covers the whole client area.
        WM_ERASEBKGND => LRESULT(1),
        WM_DESTROY => {
            CLOSING.store(true, Ordering::Relaxed);
            let _ = RemoveClipboardFormatListener(hwnd);
            send(ClientMsg::ReleaseAll);
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
    fn normalize_accounts_for_letterbox_bars() {
        // 1920x1080 in a 1000x1000 window: picture spans y = 219..781.
        assert_eq!(normalize(0, 219, (1920, 1080), (1000, 1000)), (0, 0));
        assert_eq!(normalize(999, 780, (1920, 1080), (1000, 1000)), (65535, 65535));
        // Clicks on the bars clamp to the picture edge.
        assert_eq!(normalize(500, 0, (1920, 1080), (1000, 1000)).1, 0);
        assert_eq!(normalize(500, 999, (1920, 1080), (1000, 1000)).1, 65535);
    }

    fn shape(kind: u32, width: u32, height: u32, pitch: u32, len: usize) -> CursorShape {
        CursorShape { kind, width, height, pitch, hot_x: 0, hot_y: 0, data: vec![0; len] }
    }

    #[test]
    fn cursor_validation_rejects_short_and_huge_buffers() {
        assert!(cursor_rows(&shape(2, 32, 32, 128, 4096), 32, 128).is_ok());
        assert!(cursor_rows(&shape(2, 32, 32, 128, 4095), 32, 128).is_err());
        assert!(cursor_rows(&shape(2, 32, 32, 64, 4096), 32, 128).is_err());
        assert!(cursor_rows(&shape(2, 5000, 32, 20000, 640000), 32, 20000).is_err());
        assert!(cursor_rows(&shape(2, 0, 32, 128, 4096), 32, 128).is_err());
    }
}
