//! Messages on the reliable control stream, framed as u32 length + postcard.

use anyhow::{bail, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN_SESSION: &[u8] = b"rdesk/3";
pub const ALPN_PAIR: &[u8] = b"rdesk-pair/2";
const MAX_MESSAGE: usize = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ClientMsg {
    Hello { max_bitrate_kbps: u32, fps: u32, clipboard: bool, pin: String },
    /// Normalized to 0..=65535 across the captured monitor.
    MouseMove { x: u16, y: u16 },
    MouseButton { button: u8, down: bool },
    Wheel { delta: i16, horizontal: bool },
    Key { scan: u16, extended: bool, down: bool },
    ReleaseAll,
    RequestKeyframe,
    SelectMonitor { index: u8 },
    Clipboard { text: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HostMsg {
    /// The PIN was right. Nothing else is sent, and no screen is captured, before this.
    Accepted,
    VideoInfo { width: u32, height: u32, monitor: u8, monitors: u8 },
    CursorVisible { visible: bool },
    CursorShape(CursorShape),
    Clipboard { text: String },
    Notice { text: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    /// 1 = monochrome AND/XOR mask, 2 = BGRA, 4 = masked color (DXGI values).
    pub kind: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub data: Vec<u8>,
}

/// Sent first on each unidirectional file stream.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub name: String,
    pub size: u64,
}

pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = postcard::to_stdvec(msg)?;
    if body.len() > MAX_MESSAGE {
        bail!("message too large: {} bytes", body.len());
    }
    let mut buf = Vec::with_capacity(body.len() + 4);
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    Ok(())
}

pub async fn read_msg<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE {
        bail!("message too large: {len} bytes");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(postcard::from_bytes(&body)?)
}

/// Strips any directory from a name supplied by the remote side, so a received
/// file cannot be written outside the download folder.
pub fn safe_file_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next()?.trim().trim_end_matches(['.', ' ']);
    if base.is_empty() || base == ".." || base.contains(':') {
        return None;
    }
    if base.chars().any(|c| c.is_control() || "<>\"|?*".contains(c)) {
        return None;
    }
    let stem = base.split('.').next().unwrap_or("").to_ascii_uppercase();
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        return None;
    }
    Some(base.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn message_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let m = ClientMsg::Key { scan: 30, extended: true, down: false };
        write_msg(&mut a, &m).await.unwrap();
        let got: ClientMsg = read_msg(&mut b).await.unwrap();
        assert_eq!(got, m);
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        assert!(read_msg::<_, ClientMsg>(&mut b).await.is_err());
    }

    #[test]
    fn file_names_cannot_escape_the_folder() {
        assert_eq!(safe_file_name("report.pdf").as_deref(), Some("report.pdf"));
        assert_eq!(safe_file_name("..\\..\\evil.exe").as_deref(), Some("evil.exe"));
        assert_eq!(safe_file_name("C:\\Windows\\a.txt").as_deref(), Some("a.txt"));
        assert_eq!(safe_file_name("/etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(safe_file_name(".."), None);
        assert_eq!(safe_file_name("dir/"), None);
        assert_eq!(safe_file_name("a.txt:stream"), None);
        assert_eq!(safe_file_name("CON.txt"), None);
        assert_eq!(safe_file_name("a?b"), None);
    }
}
