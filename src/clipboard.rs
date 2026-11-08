//! Clipboard access: text, pictures and copied files. What was just received
//! from the other side is remembered, so it is not sent straight back.

use anyhow::{anyhow, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::UI::Shell::{DragQueryFileW, HDROP};

const CF_DIB: u32 = 8;
const CF_UNICODETEXT: u32 = 13;
const CF_HDROP: u32 = 15;
pub const MAX_TEXT: usize = 4 * 1024 * 1024;

/// A local clipboard change worth sending to the other side.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Change {
    Text(String),
    /// A device-independent bitmap, as Windows stores pictures.
    Image(Vec<u8>),
    Files(Vec<PathBuf>),
}

impl Change {
    fn fingerprint(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        h.finish()
    }
}

static LAST: Mutex<Option<u64>> = Mutex::new(None);

fn remember(change: &Change) {
    if let Ok(mut last) = LAST.lock() {
        *last = Some(change.fingerprint());
    }
}

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

/// Copies a clipboard handle's memory. The caller holds the clipboard open.
unsafe fn global_bytes(format: u32) -> Option<Vec<u8>> {
    let handle = GetClipboardData(format).ok()?;
    let global = HGLOBAL(handle.0);
    let size = GlobalSize(global);
    let ptr = GlobalLock(global) as *const u8;
    if ptr.is_null() {
        return None;
    }
    let bytes = std::slice::from_raw_parts(ptr, size).to_vec();
    let _ = GlobalUnlock(global);
    Some(bytes)
}

fn read() -> Result<Option<Change>> {
    let _open = Open::acquire()?;
    unsafe {
        // Explorer offers copied files as a list; that comes first, since the
        // same copy may also carry a picture or text of the names.
        if IsClipboardFormatAvailable(CF_HDROP).is_ok() {
            if let Ok(handle) = GetClipboardData(CF_HDROP) {
                let drop = HDROP(handle.0);
                let count = DragQueryFileW(drop, u32::MAX, None);
                let mut files = Vec::new();
                for i in 0..count {
                    let len = DragQueryFileW(drop, i, None) as usize;
                    let mut buffer = vec![0u16; len + 1];
                    let copied = DragQueryFileW(drop, i, Some(&mut buffer)) as usize;
                    files.push(PathBuf::from(String::from_utf16_lossy(&buffer[..copied])));
                }
                if !files.is_empty() {
                    return Ok(Some(Change::Files(files)));
                }
            }
        }
        if IsClipboardFormatAvailable(CF_DIB).is_ok() {
            if let Some(dib) = global_bytes(CF_DIB) {
                if dib.len() as u64 <= crate::files::MAX_IMAGE {
                    return Ok(Some(Change::Image(dib)));
                }
            }
        }
        let Some(bytes) = global_bytes(CF_UNICODETEXT) else { return Ok(None) };
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let len = units.iter().position(|c| *c == 0).unwrap_or(units.len());
        Ok(Some(Change::Text(String::from_utf16_lossy(&units[..len]))))
    }
}

/// Returns the clipboard contents if they changed locally and should be sent.
pub fn take_local_change() -> Option<Change> {
    let change = read().ok()??;
    if let Change::Text(text) = &change {
        if text.is_empty() || text.len() > MAX_TEXT {
            return None;
        }
    }
    let mut last = LAST.lock().ok()?;
    let print = change.fingerprint();
    if *last == Some(print) {
        return None;
    }
    *last = Some(print);
    Some(change)
}

/// Puts bytes on the clipboard in one format; the system then owns them.
fn put(format: u32, bytes: &[u8]) -> Result<()> {
    let _open = Open::acquire()?;
    unsafe {
        EmptyClipboard()?;
        let global = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1))?;
        let ptr = GlobalLock(global) as *mut u8;
        if ptr.is_null() {
            let _ = GlobalFree(global);
            return Err(anyhow!("GlobalLock failed"));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        let _ = GlobalUnlock(global);
        if let Err(e) = SetClipboardData(format, HANDLE(global.0)) {
            let _ = GlobalFree(global);
            return Err(e.into());
        }
    }
    Ok(())
}

pub fn set_remote_text(text: &str) -> Result<()> {
    if text.len() > MAX_TEXT {
        return Err(anyhow!("clipboard text is too large"));
    }
    remember(&Change::Text(text.to_string()));
    let bytes: Vec<u8> = text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect();
    put(CF_UNICODETEXT, &bytes)
}

pub fn set_remote_image(dib: &[u8]) -> Result<()> {
    // A bitmap header is 40 bytes at least; anything shorter is not a picture.
    if dib.len() < 40 {
        return Err(anyhow!("not a picture"));
    }
    remember(&Change::Image(dib.to_vec()));
    put(CF_DIB, dib)
}

/// The DROPFILES layout Explorer pastes from: a header, then wide paths each
/// ending in a zero, and one more zero at the end.
fn drop_files_bytes(files: &[PathBuf]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&20u32.to_le_bytes()); // offset of the list
    bytes.extend_from_slice(&[0u8; 12]); // drop point and non-client flag
    bytes.extend_from_slice(&1u32.to_le_bytes()); // wide characters
    for file in files {
        for unit in file.to_string_lossy().encode_utf16().chain(std::iter::once(0)) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

pub fn set_remote_files(files: &[PathBuf]) -> Result<()> {
    remember(&Change::Files(files.to_vec()));
    put(CF_HDROP, &drop_files_bytes(files))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_files_layout_matches_windows() {
        let bytes = drop_files_bytes(&[PathBuf::from("C:\\a"), PathBuf::from("b")]);
        assert_eq!(&bytes[0..4], &20u32.to_le_bytes());
        assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
        let units: Vec<u16> = bytes[20..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let expected: Vec<u16> = "C:\\a\0b\0\0".encode_utf16().collect();
        assert_eq!(units, expected);
    }

    #[test]
    fn same_contents_have_the_same_fingerprint() {
        let a = Change::Files(vec![PathBuf::from("x")]);
        assert_eq!(a.fingerprint(), Change::Files(vec![PathBuf::from("x")]).fingerprint());
        assert_ne!(a.fingerprint(), Change::Text("x".into()).fingerprint());
    }
}
