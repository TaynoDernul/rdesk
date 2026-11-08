//! File and folder transfer in both directions, and the clipboard contents
//! that are too big for the control stream (pictures and copied files).
//! Each file travels on its own QUIC stream, so a large transfer never holds
//! up mouse and keyboard messages.

use crate::proto::{read_msg, safe_file_name, write_msg};
use anyhow::{anyhow, bail, Context, Result};
use iroh::endpoint::{Connection, RecvStream};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Copied files are sent eagerly, so the clipboard takes only modest amounts.
pub const MAX_CLIPBOARD_FILES: u64 = 200 * 1024 * 1024;
pub const MAX_IMAGE: u64 = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_FILES: usize = 100_000;

/// Sent first on each stream.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StreamHeader {
    File {
        /// Files sent together share a batch, so a folder lands in one place.
        batch: u64,
        count: u32,
        /// Relative, with '/' between folders. Every part is checked on arrival.
        path: String,
        size: u64,
        /// Goes to the clipboard as a file list once the batch is complete.
        clipboard: bool,
    },
    /// A clipboard picture as a device-independent bitmap.
    ClipboardImage { size: u64 },
}

/// Bytes queued and done in each direction, for progress in the title.
#[derive(Default)]
pub struct Progress {
    pub send_total: AtomicU64,
    pub send_done: AtomicU64,
    pub recv_total: AtomicU64,
    pub recv_done: AtomicU64,
}

impl Progress {
    /// "Передача файлов: 40%" while anything is moving, otherwise None.
    pub fn text(&self) -> Option<String> {
        let part = |done: &AtomicU64, total: &AtomicU64| {
            let (d, t) = (done.load(Ordering::Relaxed), total.load(Ordering::Relaxed));
            (t > 0 && d < t).then(|| d * 100 / t)
        };
        match (part(&self.send_done, &self.send_total), part(&self.recv_done, &self.recv_total)) {
            (Some(s), Some(r)) => Some(format!("отправка {s}%, приём {r}%")),
            (Some(s), None) => Some(format!("отправка файлов {s}%")),
            (None, Some(r)) => Some(format!("приём файлов {r}%")),
            (None, None) => None,
        }
    }
}

pub fn download_dir() -> Result<PathBuf> {
    let base = std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?;
    let dir = PathBuf::from(base).join("Downloads").join("rdesk");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn clipboard_dir(batch: u64) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("rdesk-clipboard").join(format!("{batch:016x}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Picks a name that does not exist yet, so a transfer never overwrites.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let source = Path::new(name);
    let stem = source.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = source.extension().and_then(|s| s.to_str());
    (1..)
        .map(|i| match ext {
            Some(ext) => dir.join(format!("{stem} ({i}).{ext}")),
            None => dir.join(format!("{stem} ({i})")),
        })
        .find(|p| !p.exists())
        .expect("unbounded search finds a free name")
}

/// Splits a relative path from the other side into checked parts. Nothing
/// it returns can lead outside the folder it is joined to.
pub fn safe_relative(path: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty() || parts.len() > MAX_DEPTH {
        return None;
    }
    parts
        .iter()
        .map(|p| {
            // safe_file_name strips directories; a part that had any is refused.
            let clean = safe_file_name(p)?;
            (clean == *p).then_some(clean)
        })
        .collect()
}

/// Every file under the given paths, with the path to send for each.
pub fn collect(paths: &[PathBuf]) -> Result<Vec<(PathBuf, String, u64)>> {
    fn walk(dir: &Path, rel: &str, depth: usize, out: &mut Vec<(PathBuf, String, u64)>) -> Result<()> {
        if depth > MAX_DEPTH {
            bail!("слишком глубокая вложенность папок");
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = format!("{rel}/{name}");
            let kind = entry.file_type()?;
            // Links are skipped: following them could leave the chosen folder.
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                walk(&entry.path(), &rel, depth + 1, out)?;
            } else if kind.is_file() {
                out.push((entry.path(), rel, entry.metadata()?.len()));
            }
            if out.len() > MAX_FILES {
                bail!("слишком много файлов");
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("некорректное имя: {}", path.display()))?
            .to_string();
        let meta = std::fs::metadata(path)?;
        if meta.is_dir() {
            walk(path, &name, 1, &mut out)?;
        } else {
            out.push((path.clone(), name, meta.len()));
        }
    }
    Ok(out)
}

fn new_batch() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes);
    u64::from_le_bytes(bytes)
}

/// Sends files and folders; returns how many files and bytes went out.
pub async fn send_paths(
    conn: &Connection,
    paths: &[PathBuf],
    clipboard: bool,
    progress: &Progress,
) -> Result<(usize, u64)> {
    let list = {
        let paths = paths.to_vec();
        tokio::task::spawn_blocking(move || collect(&paths)).await??
    };
    let total: u64 = list.iter().map(|(_, _, size)| size).sum();
    if clipboard && total > MAX_CLIPBOARD_FILES {
        bail!("для буфера обмена слишком много данных; перетащите файлы в окно");
    }
    progress.send_total.fetch_add(total, Ordering::Relaxed);
    let batch = new_batch();
    let count = list.len() as u32;
    let mut sent = 0u64;
    for (source, path, size) in &list {
        let header = StreamHeader::File { batch, count, path: path.clone(), size: *size, clipboard };
        let result = send_one(conn, source, &header, progress).await;
        sent += size;
        if let Err(e) = result {
            // Keep the progress honest about what will never arrive.
            let left: u64 = total - sent;
            progress.send_done.fetch_add(left, Ordering::Relaxed);
            return Err(e.context(format!("не удалось отправить {path}")));
        }
    }
    Ok((list.len(), total))
}

async fn send_one(conn: &Connection, source: &Path, header: &StreamHeader, progress: &Progress) -> Result<()> {
    let mut stream = conn.open_uni().await?;
    write_msg(&mut stream, header).await?;
    let mut file = tokio::fs::File::open(source).await?;
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        stream.write_all(&buffer[..n]).await?;
        progress.send_done.fetch_add(n as u64, Ordering::Relaxed);
    }
    stream.finish()?;
    stream.stopped().await?;
    Ok(())
}

pub async fn send_image(conn: &Connection, dib: &[u8]) -> Result<()> {
    let mut stream = conn.open_uni().await?;
    write_msg(&mut stream, &StreamHeader::ClipboardImage { size: dib.len() as u64 }).await?;
    stream.write_all(dib).await?;
    stream.finish()?;
    stream.stopped().await?;
    Ok(())
}

/// Where one batch is being written.
struct Batch {
    base: PathBuf,
    /// First part of each sent path, mapped to the name it got here.
    tops: HashMap<String, PathBuf>,
    received: u32,
}

/// Receives everything the other side sends, until the connection closes.
/// `notify` gets a line for the person at this PC after each completed batch.
pub async fn receive_all(conn: Connection, progress: Arc<Progress>, notify: Arc<dyn Fn(String) + Send + Sync>) {
    let batches: Arc<Mutex<HashMap<u64, Batch>>> = Arc::default();
    while let Ok(mut stream) = conn.accept_uni().await {
        let (batches, progress, notify) = (batches.clone(), progress.clone(), notify.clone());
        tokio::spawn(async move {
            if let Err(e) = receive_one(&mut stream, &batches, &progress, notify.as_ref()).await {
                crate::log_event(&format!("transfer failed: {e:#}"));
                notify(format!("Передача не удалась: {e:#}"));
            }
        });
    }
}

async fn receive_one(
    stream: &mut RecvStream,
    batches: &Mutex<HashMap<u64, Batch>>,
    progress: &Progress,
    notify: &(dyn Fn(String) + Send + Sync),
) -> Result<()> {
    match read_msg::<_, StreamHeader>(stream).await? {
        StreamHeader::ClipboardImage { size } => {
            if size > MAX_IMAGE {
                bail!("picture is too large");
            }
            let mut dib = Vec::with_capacity(size as usize);
            stream.take(size + 1).read_to_end(&mut dib).await?;
            if dib.len() as u64 != size {
                bail!("picture ended early");
            }
            tokio::task::spawn_blocking(move || crate::clipboard::set_remote_image(&dib)).await??;
            Ok(())
        }
        StreamHeader::File { batch, count, path, size, clipboard } => {
            let parts = safe_relative(&path).ok_or_else(|| anyhow!("unsafe path: {path}"))?;
            progress.recv_total.fetch_add(size, Ordering::Relaxed);
            let target = {
                let mut all = batches.lock().expect("batch lock");
                if !all.contains_key(&batch) {
                    let base = if clipboard { clipboard_dir(batch)? } else { download_dir()? };
                    all.insert(batch, Batch { base, tops: HashMap::new(), received: 0 });
                }
                let entry = all.get_mut(&batch).expect("inserted above");
                let top = match entry.tops.get(&parts[0]) {
                    Some(top) => top.clone(),
                    None => {
                        let top = unique_path(&entry.base, &parts[0]);
                        entry.tops.insert(parts[0].clone(), top.clone());
                        top
                    }
                };
                parts[1..].iter().fold(top, |p, part| p.join(part))
            };
            let written = write_file(stream, &target, size, progress).await;
            if written.is_err() {
                progress.recv_done.fetch_add(size, Ordering::Relaxed);
            }
            written?;

            let finished = {
                let mut all = batches.lock().expect("batch lock");
                let entry = all.get_mut(&batch).expect("batch exists");
                entry.received += 1;
                (entry.received >= count).then(|| {
                    let done = all.remove(&batch).expect("batch exists");
                    (done.base, done.tops.into_values().collect::<Vec<_>>())
                })
            };
            if let Some((base, tops)) = finished {
                if clipboard {
                    tokio::task::spawn_blocking(move || crate::clipboard::set_remote_files(&tops)).await??;
                    notify(format!("Файлы скопированы в буфер обмена: {count}"));
                } else {
                    crate::log_event(&format!("received {count} files into {}", base.display()));
                    let what = match tops.as_slice() {
                        [one] if count == 1 => one.display().to_string(),
                        _ => format!("{count} в {}", base.display()),
                    };
                    notify(format!("Получены файлы: {what}"));
                }
            }
            Ok(())
        }
    }
}

async fn write_file(stream: &mut RecvStream, target: &Path, size: u64, progress: &Progress) -> Result<()> {
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let partial = target.with_extension(format!(
        "{}.part",
        target.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    let copy = async {
        let mut file = tokio::fs::File::create(&partial).await?;
        let mut received = 0u64;
        let mut buffer = vec![0u8; 256 * 1024];
        while let Some(n) = stream.read(&mut buffer).await? {
            received += n as u64;
            if received > size {
                bail!("sender exceeded the declared size");
            }
            file.write_all(&buffer[..n]).await?;
            progress.recv_done.fetch_add(n as u64, Ordering::Relaxed);
        }
        if received != size {
            bail!("transfer ended early: {received} of {size} bytes");
        }
        file.flush().await?;
        Ok(())
    };
    if let Err(e) = copy.await {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(e);
    }
    tokio::fs::rename(&partial, target).await?;
    Ok(())
}

/// The standard Windows picker on this PC's screen: several files, or one folder.
pub fn pick(owner: Option<windows::Win32::Foundation::HWND>, folder: bool, title: &str) -> Vec<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Com::{CoCreateInstance, CoTaskMemFree, CLSCTX_INPROC_SERVER};
    use windows::Win32::UI::Shell::{
        FileOpenDialog, IFileOpenDialog, FOS_ALLOWMULTISELECT, FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS,
        SIGDN_FILESYSPATH,
    };
    let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let picked = || -> windows::core::Result<Vec<PathBuf>> {
        unsafe {
            let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)?;
            let extra = if folder { FOS_PICKFOLDERS } else { FOS_ALLOWMULTISELECT };
            dialog.SetOptions(dialog.GetOptions()? | extra | FOS_FORCEFILESYSTEM)?;
            dialog.SetTitle(PCWSTR(title.as_ptr()))?;
            dialog.Show(owner.unwrap_or_default())?;
            let items = dialog.GetResults()?;
            let mut paths = Vec::new();
            for i in 0..items.GetCount()? {
                let name = items.GetItemAt(i)?.GetDisplayName(SIGDN_FILESYSPATH)?;
                paths.push(PathBuf::from(name.to_string()?));
                CoTaskMemFree(Some(name.0 as *const _));
            }
            Ok(paths)
        }
    };
    // Cancelling is an error too; either way nothing is sent.
    picked().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_cannot_escape() {
        assert_eq!(safe_relative("a/b/c.txt"), Some(vec!["a".into(), "b".into(), "c.txt".into()]));
        assert_eq!(safe_relative("file.txt"), Some(vec!["file.txt".into()]));
        assert!(safe_relative("../x").is_none());
        assert!(safe_relative("a/../../x").is_none());
        assert!(safe_relative("a\\..\\x").is_none());
        assert!(safe_relative("C:/x").is_none());
        assert!(safe_relative("/abs").is_none());
        assert!(safe_relative("a//b").is_none());
        assert!(safe_relative("a/CON").is_none());
        assert!(safe_relative(&"d/".repeat(40)).is_none());
    }

    #[test]
    fn unique_path_never_reuses_a_name() {
        let dir = std::env::temp_dir().join(format!("rdesk-unique-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (1).txt"));
        std::fs::write(dir.join("a (1).txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn folders_are_collected_with_relative_paths() {
        let dir = std::env::temp_dir().join(format!("rdesk-collect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("top").join("sub")).unwrap();
        std::fs::write(dir.join("top").join("a.txt"), b"12").unwrap();
        std::fs::write(dir.join("top").join("sub").join("b.txt"), b"345").unwrap();
        std::fs::write(dir.join("single.bin"), b"6").unwrap();
        let mut list = collect(&[dir.join("top"), dir.join("single.bin")]).unwrap();
        list.sort_by(|a, b| a.1.cmp(&b.1));
        let rel: Vec<(&str, u64)> = list.iter().map(|(_, r, s)| (r.as_str(), *s)).collect();
        assert_eq!(rel, vec![("single.bin", 1), ("top/a.txt", 2), ("top/sub/b.txt", 3)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn progress_text_only_while_moving() {
        let p = Progress::default();
        assert_eq!(p.text(), None);
        p.send_total.store(200, Ordering::Relaxed);
        p.send_done.store(50, Ordering::Relaxed);
        assert_eq!(p.text().as_deref(), Some("отправка файлов 25%"));
        p.send_done.store(200, Ordering::Relaxed);
        assert_eq!(p.text(), None);
    }
}
