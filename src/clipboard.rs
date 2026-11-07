//! Text clipboard access, with echo suppression so a value received from the
//! other side is not immediately sent back.

use anyhow::{anyhow, Result};
use std::sync::Mutex;
use std::time::Duration;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};

const CF_UNICODETEXT: u32 = 13;
pub const MAX_TEXT: usize = 4 * 1024 * 1024;

static LAST: Mutex<Option<String>> = Mutex::new(None);

struct Open;

impl Open {
    fn acquire() -> Result<Self> {
        // Another application may hold the clipboard for a moment.
        for _ in 0..10 {
            if unsafe { OpenClipboard(HWND::default()) }.is_ok() {
                return Ok(Open);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(anyhow!("clipboard is busy"))
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        let _ = unsafe { CloseClipboard() };
    }
}

fn read() -> Result<Option<String>> {
    let _open = Open::acquire()?;
    unsafe {
        let Ok(handle) = GetClipboardData(CF_UNICODETEXT) else { return Ok(None) };
        let global = HGLOBAL(handle.0);
        let units = GlobalSize(global) / 2;
        let ptr = GlobalLock(global) as *const u16;
        if ptr.is_null() {
            return Ok(None);
        }
        let slice = std::slice::from_raw_parts(ptr, units);
        let len = slice.iter().position(|c| *c == 0).unwrap_or(units);
        let text = String::from_utf16_lossy(&slice[..len]);
        let _ = GlobalUnlock(global);
        Ok(Some(text))
    }
}

/// Returns the clipboard text if it changed locally and should be sent.
pub fn take_local_change() -> Option<String> {
    let text = read().ok()??;
    if text.is_empty() || text.len() > MAX_TEXT {
        return None;
    }
    let mut last = LAST.lock().ok()?;
    if last.as_deref() == Some(text.as_str()) {
        return None;
    }
    *last = Some(text.clone());
    Some(text)
}

pub fn set_remote_text(text: &str) -> Result<()> {
    if text.len() > MAX_TEXT {
        return Err(anyhow!("clipboard text is too large"));
    }
    if let Ok(mut last) = LAST.lock() {
        *last = Some(text.to_string());
    }
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let _open = Open::acquire()?;
    unsafe {
        EmptyClipboard()?;
        let global = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2)?;
        let ptr = GlobalLock(global) as *mut u16;
        if ptr.is_null() {
            let _ = GlobalFree(global);
            return Err(anyhow!("GlobalLock failed"));
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        let _ = GlobalUnlock(global);
        // On success the system owns the memory.
        if let Err(e) = SetClipboardData(CF_UNICODETEXT, HANDLE(global.0)) {
            let _ = GlobalFree(global);
            return Err(e.into());
        }
    }
    Ok(())
}
