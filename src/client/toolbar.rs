//! A small tab at the top left of the session window. A click opens the
//! session menu. It stays on screen in full screen, where there is no title
//! bar, and is half transparent until the mouse is over it.

use std::sync::atomic::{AtomicIsize, Ordering};
use windows::core::w;
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT};
use windows::Win32::UI::WindowsAndMessaging::*;

const WIDTH: i32 = 132;
const HEIGHT: i32 = 22;
const IDLE_ALPHA: u8 = 140;
const WM_MOUSELEAVE: u32 = 0x02A3;

static TAB: AtomicIsize = AtomicIsize::new(0);
static OWNER: AtomicIsize = AtomicIsize::new(0);

fn tab() -> HWND {
    HWND(TAB.load(Ordering::Relaxed) as *mut _)
}

fn owner() -> HWND {
    HWND(OWNER.load(Ordering::Relaxed) as *mut _)
}

fn scale(value: i32, hwnd: HWND) -> i32 {
    let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96) as i32;
    value * dpi / 96
}

/// Creates the tab above `owner`. An owned window always stays above its
/// owner, so it needs no topmost flag and hides when the owner is minimised.
pub fn create(owner: HWND) {
    OWNER.store(owner.0 as isize, Ordering::Relaxed);
    unsafe {
        let Ok(instance) = GetModuleHandleW(None) else { return };
        let class = w!("rdesk-session-tab");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: class,
            hCursor: LoadCursorW(None, IDC_HAND).unwrap_or_default(),
            ..Default::default()
        };
        RegisterClassW(&wc);
        let created = CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_LAYERED | WS_EX_NOACTIVATE,
            class,
            w!("rdesk"),
            WS_POPUP,
            0,
            0,
            scale(WIDTH, owner),
            scale(HEIGHT, owner),
            owner,
            None,
            instance,
            None,
        );
        let Ok(hwnd) = created else { return };
        TAB.store(hwnd.0 as isize, Ordering::Relaxed);
        let _ = SetLayeredWindowAttributes(hwnd, COLORREF(0), IDLE_ALPHA, LWA_ALPHA);
        follow();
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    }
}

/// Keeps the tab at the top left of the owner's picture area.
pub fn follow() {
    let (tab, owner) = (tab(), owner());
    if tab.0.is_null() {
        return;
    }
    unsafe {
        let mut client = RECT::default();
        let _ = GetClientRect(owner, &mut client);
        let mut origin = POINT::default();
        let _ = ClientToScreen(owner, &mut origin);
        let (w, h) = (scale(WIDTH, owner), scale(HEIGHT, owner));
        // Left of centre: the remote PC's own banner sits at the top centre
        // of the picture, and the tab must not cover it.
        let x = origin.x + scale(16, owner).min((client.right - w).max(0));
        let _ = SetWindowPos(tab, None, x, origin.y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

fn paint(hwnd: HWND) {
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let dc = BeginPaint(hwnd, &mut ps);
        let mut client = RECT::default();
        let _ = GetClientRect(hwnd, &mut client);
        let brush = CreateSolidBrush(COLORREF(0x0030_2B2B));
        FillRect(dc, &client, brush);
        let _ = DeleteObject(brush);
        let font = CreateFontW(
            -scale(13, hwnd), 0, 0, 0, FW_SEMIBOLD.0 as i32, 0, 0, 0,
            DEFAULT_CHARSET.0 as u32, OUT_DEFAULT_PRECIS.0 as u32, CLIP_DEFAULT_PRECIS.0 as u32,
            CLEARTYPE_QUALITY.0 as u32,(DEFAULT_PITCH.0 | FF_SWISS.0) as u32, w!("Segoe UI"),
        );
        let old = SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, COLORREF(0x00FF_FFFF));
        let mut label: Vec<u16> = "☰  Меню сеанса".encode_utf16().collect();
        DrawTextW(dc, &mut label, &mut client, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
        SelectObject(dc, old);
        let _ = DeleteObject(font);
        let _ = EndPaint(hwnd, &ps);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            paint(hwnd);
            LRESULT(0)
        }
        WM_MOUSEACTIVATE => LRESULT(MA_NOACTIVATE as isize),
        WM_MOUSEMOVE => {
            let mut track = TRACKMOUSEEVENT {
                cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                dwFlags: TME_LEAVE,
                hwndTrack: hwnd,
                dwHoverTime: 0,
            };
            let _ = TrackMouseEvent(&mut track);
            let _ = SetLayeredWindowAttributes(hwnd, COLORREF(0), 255, LWA_ALPHA);
            LRESULT(0)
        }
        WM_MOUSELEAVE => {
            let _ = SetLayeredWindowAttributes(hwnd, COLORREF(0), IDLE_ALPHA, LWA_ALPHA);
            LRESULT(0)
        }
        WM_LBUTTONUP | WM_RBUTTONUP => {
            let mut rect = RECT::default();
            let _ = GetWindowRect(hwnd, &mut rect);
            super::window::show_menu(rect.left, rect.bottom);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
