//! Replays the client's mouse and keyboard through SendInput. Everything still
//! held is tracked, so a dropped connection can never leave a key stuck down.

use std::collections::HashSet;
use windows::Win32::Foundation::RECT;
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

const XBUTTON1: u32 = 1;
const XBUTTON2: u32 = 2;

#[derive(Default)]
pub struct Injector {
    keys: HashSet<(u16, bool)>,
    buttons: HashSet<u8>,
}

impl Injector {
    pub fn mouse_move(&self, x: u16, y: u16, monitor: RECT) {
        let (ax, ay) = unsafe {
            to_absolute(
                x,
                y,
                monitor,
                (
                    GetSystemMetrics(SM_XVIRTUALSCREEN),
                    GetSystemMetrics(SM_YVIRTUALSCREEN),
                    GetSystemMetrics(SM_CXVIRTUALSCREEN),
                    GetSystemMetrics(SM_CYVIRTUALSCREEN),
                ),
            )
        };
        send_mouse(ax, ay, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
    }

    pub fn mouse_button(&mut self, button: u8, down: bool) {
        let Some((flags, data)) = button_flags(button, down) else { return };
        if down {
            self.buttons.insert(button);
        } else {
            self.buttons.remove(&button);
        }
        send_mouse(0, 0, data, flags);
    }

    pub fn wheel(&self, delta: i16, horizontal: bool) {
        let flags = if horizontal { MOUSEEVENTF_HWHEEL } else { MOUSEEVENTF_WHEEL };
        send_mouse(0, 0, delta as i32 as u32, flags);
    }

    pub fn key(&mut self, scan: u16, extended: bool, down: bool) {
        if down {
            self.keys.insert((scan, extended));
        } else {
            self.keys.remove(&(scan, extended));
        }
        send_key(scan, extended, down);
    }

    pub fn release_all(&mut self) {
        for (scan, extended) in std::mem::take(&mut self.keys) {
            send_key(scan, extended, false);
        }
        for button in std::mem::take(&mut self.buttons) {
            if let Some((flags, data)) = button_flags(button, false) {
                send_mouse(0, 0, data, flags);
            }
        }
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        self.release_all();
    }
}

/// Maps 0..=65535 on one monitor to SendInput's 0..=65535 virtual desktop.
fn to_absolute(x: u16, y: u16, monitor: RECT, (vx, vy, vw, vh): (i32, i32, i32, i32)) -> (i32, i32) {
    let scale = |n: u16, start: i32, size: i32, vstart: i32, vsize: i32| -> i32 {
        let pixel = start as i64 + (n as i64 * (size - 1).max(0) as i64) / 65535;
        (((pixel - vstart as i64) * 65535) / (vsize - 1).max(1) as i64) as i32
    };
    (
        scale(x, monitor.left, monitor.right - monitor.left, vx, vw),
        scale(y, monitor.top, monitor.bottom - monitor.top, vy, vh),
    )
}

fn button_flags(button: u8, down: bool) -> Option<(MOUSE_EVENT_FLAGS, u32)> {
    Some(match (button, down) {
        (0, true) => (MOUSEEVENTF_LEFTDOWN, 0),
        (0, false) => (MOUSEEVENTF_LEFTUP, 0),
        (1, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
        (1, false) => (MOUSEEVENTF_RIGHTUP, 0),
        (2, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
        (2, false) => (MOUSEEVENTF_MIDDLEUP, 0),
        (3, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
        (3, false) => (MOUSEEVENTF_XUP, XBUTTON1),
        (4, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
        (4, false) => (MOUSEEVENTF_XUP, XBUTTON2),
        _ => return None,
    })
}

fn send_mouse(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) {
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: data, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    };
    unsafe { SendInput(&[input], std::mem::size_of::<INPUT>() as i32) };
}

fn send_key(scan: u16, extended: bool, down: bool) {
    let mut flags = KEYEVENTF_SCANCODE;
    if extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    if !down {
        flags |= KEYEVENTF_KEYUP;
    }
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe { SendInput(&[input], std::mem::size_of::<INPUT>() as i32) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
        RECT { left, top, right, bottom }
    }

    #[test]
    fn single_monitor_maps_corners_to_full_range() {
        let m = r(0, 0, 1920, 1080);
        let v = (0, 0, 1920, 1080);
        assert_eq!(to_absolute(0, 0, m, v), (0, 0));
        assert_eq!(to_absolute(65535, 65535, m, v), (65535, 65535));
    }

    #[test]
    fn second_monitor_maps_inside_virtual_desktop() {
        // A second 1920-wide display placed to the left of the primary.
        let m = r(-1920, 0, 0, 1080);
        let v = (-1920, 0, 3840, 1080);
        assert_eq!(to_absolute(0, 0, m, v).0, 0);
        let (right_edge, _) = to_absolute(65535, 0, m, v);
        assert!((32700..=32768).contains(&right_edge), "{right_edge}");
    }

    /// Touches real keyboard state, so it runs only on request:
    /// cargo test -- --ignored injected_key
    #[test]
    #[ignore]
    fn injected_key_reaches_windows_and_is_released() {
        const SCROLL_LOCK_SCAN: u16 = 0x46;
        let held = || unsafe { GetAsyncKeyState(VK_SCROLL.0 as i32) } as u16 & 0x8000 != 0;
        let mut injector = Injector::default();

        injector.key(SCROLL_LOCK_SCAN, false, true);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(held(), "key press did not reach Windows");

        // A lost connection releases whatever is still held.
        injector.release_all();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!held(), "release_all left the key down");

        // Second press and release puts the Scroll Lock toggle back.
        injector.key(SCROLL_LOCK_SCAN, false, true);
        injector.key(SCROLL_LOCK_SCAN, false, false);
    }

    #[test]
    fn unknown_mouse_button_is_ignored() {
        assert!(button_flags(9, true).is_none());
    }
}
