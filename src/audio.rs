//! Sound from the remote PC. The host records what its speakers play with
//! WASAPI loopback and compresses it to AAC with the encoder built into
//! Windows; the client decodes it the same way and plays it. Each AAC frame
//! (about 21 ms) travels as one datagram: a lost one is a short gap, never a
//! delay, so sound stays in step with the picture.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use iroh::endpoint::Connection;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows::core::GUID;
use windows::Win32::Media::Audio::*;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};

/// Marks an audio datagram. Video shards keep this bit clear in the same byte.
pub const FLAG_AUDIO: u8 = 0x80;
const HEADER: usize = crate::fec::HEADER;
const SAMPLE_RATE: u32 = 48_000;
const CHANNELS: u32 = 2;
const BYTES_PER_FRAME: usize = 4; // 16-bit stereo
/// 160 kbit/s: transparent for speech, music and game sound.
const AAC_BYTES_PER_SECOND: u32 = 20_000;
/// AAC-LC, 48 kHz, stereo, as an AudioSpecificConfig.
const AUDIO_SPECIFIC_CONFIG: [u8; 2] = [0x11, 0x90];
/// Playback aims to keep this much sound queued: enough to ride out jitter.
const TARGET_LATENCY: Duration = Duration::from_millis(60);
/// More than this queued means the clocks drifted or a burst arrived late;
/// the oldest sound is dropped so it never lags behind the picture.
const MAX_LATENCY: Duration = Duration::from_millis(180);
const HNS_PER_SECOND: i64 = 10_000_000;
/// Microsoft's AAC encoder transform (not exported by the windows crate).
const CLSID_AAC_ENCODER: GUID = GUID::from_u128(0x93af0c51_2275_45d2_a35b_f2ba21caed00);

pub fn is_audio(datagram: &[u8]) -> bool {
    datagram.len() > HEADER && datagram[HEADER - 1] & FLAG_AUDIO != 0
}

fn pack(seq: u32, frame: &[u8]) -> Bytes {
    let mut out = vec![0u8; HEADER + frame.len()];
    out[0..4].copy_from_slice(&seq.to_le_bytes());
    out[HEADER - 1] = FLAG_AUDIO;
    out[HEADER..].copy_from_slice(frame);
    Bytes::from(out)
}

fn unpack(datagram: &[u8]) -> Option<(u32, &[u8])> {
    if !is_audio(datagram) {
        return None;
    }
    let seq = u32::from_le_bytes(datagram[0..4].try_into().ok()?);
    Some((seq, &datagram[HEADER..]))
}

fn pcm_format() -> WAVEFORMATEX {
    WAVEFORMATEX {
        wFormatTag: 1, // WAVE_FORMAT_PCM
        nChannels: CHANNELS as u16,
        nSamplesPerSec: SAMPLE_RATE,
        nAvgBytesPerSec: SAMPLE_RATE * BYTES_PER_FRAME as u32,
        nBlockAlign: BYTES_PER_FRAME as u16,
        wBitsPerSample: 16,
        cbSize: 0,
    }
}

fn duration_bytes(d: Duration) -> usize {
    (d.as_secs_f64() * SAMPLE_RATE as f64) as usize * BYTES_PER_FRAME
}

/// COM and Media Foundation for one audio thread.
struct ThreadInit;

impl ThreadInit {
    fn new() -> Self {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let _ = MFStartup(MF_VERSION, MFSTARTUP_FULL);
        }
        ThreadInit
    }
}

impl Drop for ThreadInit {
    fn drop(&mut self) {
        unsafe {
            let _ = MFShutdown();
            CoUninitialize();
        }
    }
}

fn pcm_type() -> Result<IMFMediaType> {
    unsafe {
        let t = MFCreateMediaType()?;
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)?;
        t.SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_PCM)?;
        t.SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, 16)?;
        t.SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, SAMPLE_RATE)?;
        t.SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, CHANNELS)?;
        t.SetUINT32(&MF_MT_AUDIO_BLOCK_ALIGNMENT, BYTES_PER_FRAME as u32)?;
        t.SetUINT32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND, SAMPLE_RATE * BYTES_PER_FRAME as u32)?;
        Ok(t)
    }
}

fn aac_type(with_config: bool) -> Result<IMFMediaType> {
    unsafe {
        let t = MFCreateMediaType()?;
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)?;
        t.SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_AAC)?;
        t.SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, 16)?;
        t.SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, SAMPLE_RATE)?;
        t.SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, CHANNELS)?;
        t.SetUINT32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND, AAC_BYTES_PER_SECOND)?;
        // Raw frames, no ADTS headers: the decoder learns the format below.
        t.SetUINT32(&MF_MT_AAC_PAYLOAD_TYPE, 0)?;
        if with_config {
            // The HEAACWAVEINFO fields after WAVEFORMATEX, then the config.
            let mut info = vec![0u8; 12];
            info[2] = 0xFE; // audio profile: not specified
            info.extend_from_slice(&AUDIO_SPECIFIC_CONFIG);
            t.SetBlob(&MF_MT_USER_DATA, &info)?;
        }
        Ok(t)
    }
}

/// One Media Foundation audio transform: the AAC encoder or decoder.
struct Codec {
    mft: IMFTransform,
    time: i64,
}

impl Codec {
    fn encoder() -> Result<Self> {
        unsafe {
            let mft: IMFTransform = CoCreateInstance(&CLSID_AAC_ENCODER, None, CLSCTX_INPROC_SERVER)?;
            // The encoder wants its output type first.
            mft.SetOutputType(0, &aac_type(false)?, 0)?;
            mft.SetInputType(0, &pcm_type()?, 0)?;
            Self::start(mft)
        }
    }

    fn decoder() -> Result<Self> {
        unsafe {
            let mft: IMFTransform = CoCreateInstance(&CLSID_MSAACDecMFT, None, CLSCTX_INPROC_SERVER)?;
            mft.SetInputType(0, &aac_type(true)?, 0)?;
            mft.SetOutputType(0, &pcm_type()?, 0)?;
            Self::start(mft)
        }
    }

    fn start(mft: IMFTransform) -> Result<Self> {
        unsafe {
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }
        Ok(Self { mft, time: 0 })
    }

    /// Feeds data in and collects every output buffer it produces.
    fn process(&mut self, data: &[u8], duration: i64, out: &mut Vec<Vec<u8>>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        unsafe {
            let buffer = MFCreateMemoryBuffer(data.len() as u32)?;
            let mut ptr = std::ptr::null_mut();
            buffer.Lock(&mut ptr, None, None)?;
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(data.len() as u32)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(self.time)?;
            sample.SetSampleDuration(duration)?;
            self.time += duration;
            loop {
                match self.mft.ProcessInput(0, &sample, 0) {
                    Ok(()) => break,
                    Err(e) if e.code() == MF_E_NOTACCEPTING => self.drain(out)?,
                    Err(e) => return Err(e.into()),
                }
            }
            self.drain(out)
        }
    }

    fn drain(&mut self, out: &mut Vec<Vec<u8>>) -> Result<()> {
        unsafe {
            let info = self.mft.GetOutputStreamInfo(0)?;
            let provides = info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 != 0;
            loop {
                let own = if provides {
                    None
                } else {
                    let buffer = MFCreateMemoryBuffer(info.cbSize.max(64 * 1024))?;
                    let sample = MFCreateSample()?;
                    sample.AddBuffer(&buffer)?;
                    Some(sample)
                };
                let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: std::mem::ManuallyDrop::new(own),
                    dwStatus: 0,
                    pEvents: std::mem::ManuallyDrop::new(None),
                }];
                let mut status = 0u32;
                let result = self.mft.ProcessOutput(0, &mut buffers, &mut status);
                let sample = std::mem::ManuallyDrop::take(&mut buffers[0].pSample);
                drop(std::mem::ManuallyDrop::take(&mut buffers[0].pEvents));
                match result {
                    Ok(()) => {}
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
                let Some(sample) = sample else { continue };
                let buffer = sample.ConvertToContiguousBuffer()?;
                let mut ptr = std::ptr::null_mut();
                let mut len = 0u32;
                buffer.Lock(&mut ptr, None, Some(&mut len))?;
                if len > 0 {
                    out.push(std::slice::from_raw_parts(ptr, len as usize).to_vec());
                }
                buffer.Unlock()?;
            }
        }
    }
}

impl Drop for Codec {
    fn drop(&mut self) {
        let _ = unsafe { self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0) };
    }
}

fn default_device() -> Result<IMMDevice> {
    unsafe {
        let enumerator: IMMDeviceEnumerator = CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
        Ok(enumerator.GetDefaultAudioEndpoint(eRender, eConsole)?)
    }
}

/// Opens the default speakers in shared mode with Windows converting to and
/// from 48 kHz 16-bit stereo, whatever the device itself uses.
fn open_client(device: &IMMDevice, loopback: bool) -> Result<IAudioClient> {
    unsafe {
        let client: IAudioClient = device.Activate(CLSCTX_ALL, None)?;
        let mut flags = AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
        if loopback {
            flags |= AUDCLNT_STREAMFLAGS_LOOPBACK;
        }
        let format = pcm_format();
        client.Initialize(AUDCLNT_SHAREMODE_SHARED, flags, HNS_PER_SECOND / 5, 0, &format, None::<*const GUID>)?;
        Ok(client)
    }
}

/// The host's sound capture, running on its own thread while it exists.
pub struct Capture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Capture {
    pub fn start(conn: Connection) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("audio-capture".into())
            .spawn(move || {
                let _init = ThreadInit::new();
                let mut seq = 0u32;
                let mut reported = false;
                crate::log_event("audio capture started");
                while !flag.load(Ordering::Relaxed) {
                    // Switching speakers or headphones invalidates the device:
                    // start over on the new default one.
                    let mut sink = |frame: &[u8]| match conn.send_datagram(pack(seq, frame)) {
                        Ok(()) => {
                            seq = seq.wrapping_add(1);
                            true
                        }
                        Err(iroh::endpoint::SendDatagramError::ConnectionLost(_)) => false,
                        // Too large for the path or a full queue: skip one frame.
                        Err(_) => true,
                    };
                    if let Err(e) = capture(&mut sink, &flag) {
                        if !reported {
                            crate::log_event(&format!("audio capture: {e:#}"));
                            reported = true;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .ok();
        Self { stop, thread }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Records the default speakers until `stop`, handing each AAC frame to
/// `sink`. A sink returning false ends the capture.
fn capture(sink: &mut dyn FnMut(&[u8]) -> bool, stop: &AtomicBool) -> Result<()> {
    let device = default_device()?;
    let client = open_client(&device, true)?;
    let mut encoder = Codec::encoder()?;
    let mut frames = Vec::new();
    let mut pcm = Vec::new();
    unsafe {
        let reader: IAudioCaptureClient = client.GetService()?;
        client.Start()?;
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
            pcm.clear();
            while reader.GetNextPacketSize()? > 0 {
                let mut data = std::ptr::null_mut();
                let (mut count, mut flags) = (0u32, 0u32);
                reader.GetBuffer(&mut data, &mut count, &mut flags, None, None)?;
                let len = count as usize * BYTES_PER_FRAME;
                if flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 || data.is_null() {
                    pcm.resize(pcm.len() + len, 0);
                } else {
                    pcm.extend_from_slice(std::slice::from_raw_parts(data, len));
                }
                reader.ReleaseBuffer(count)?;
            }
            let duration = (pcm.len() / BYTES_PER_FRAME) as i64 * HNS_PER_SECOND / SAMPLE_RATE as i64;
            encoder.process(&pcm, duration, &mut frames)?;
            for frame in frames.drain(..) {
                if !sink(&frame) {
                    let _ = client.Stop();
                    return Ok(());
                }
            }
        }
        let _ = client.Stop();
    }
    Ok(())
}

/// The client's playback: decodes on its own thread and keeps a short queue.
pub struct Player {
    frames: std::sync::mpsc::Sender<Vec<u8>>,
}

impl Player {
    /// The thread ends when the player is dropped.
    pub fn start() -> Self {
        let (frames, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let _ = std::thread::Builder::new().name("audio-play".into()).spawn(move || {
            let _init = ThreadInit::new();
            if let Err(e) = play(&rx) {
                crate::log_event(&format!("audio playback: {e:#}"));
            }
        });
        Self { frames }
    }

    /// Takes one datagram; anything that is not sound is ignored.
    pub fn push(&self, datagram: &[u8]) {
        if let Some((_, frame)) = unpack(datagram) {
            let _ = self.frames.send(frame.to_vec());
        }
    }

}

/// Drops the oldest sound when the queue grew past the limit, down to the
/// target, so playback catches up instead of drifting behind the picture.
fn trim_queue(queue: &mut VecDeque<u8>, max: usize, target: usize) {
    if queue.len() > max {
        let excess = (queue.len() - target) / BYTES_PER_FRAME * BYTES_PER_FRAME;
        queue.drain(..excess);
    }
}

fn play(frames: &std::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
    let mut decoder = Codec::decoder()?;
    let mut queue: VecDeque<u8> = VecDeque::new();
    let mut decoded = Vec::new();
    let frame_hns = 1024 * HNS_PER_SECOND / SAMPLE_RATE as i64;
    let (max, target) = (duration_bytes(MAX_LATENCY), duration_bytes(TARGET_LATENCY));
    let mut output: Option<(IAudioClient, IAudioRenderClient, u32)> = None;
    let mut retry_at = Instant::now();
    let mut started = false;

    loop {
        match frames.recv_timeout(Duration::from_millis(5)) {
            Ok(frame) => {
                if let Err(e) = decoder.process(&frame, frame_hns, &mut decoded) {
                    // A broken frame must not end playback; start the decoder over.
                    crate::log_event(&format!("audio decode: {e:#}"));
                    decoder = Codec::decoder()?;
                }
                for pcm in decoded.drain(..) {
                    queue.extend(pcm);
                }
                while let Ok(frame) = frames.try_recv() {
                    let _ = decoder.process(&frame, frame_hns, &mut decoded);
                    for pcm in decoded.drain(..) {
                        queue.extend(pcm);
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        trim_queue(&mut queue, max, target);

        if output.is_none() && Instant::now() >= retry_at {
            output = (|| -> Result<_> {
                let client = open_client(&default_device()?, false)?;
                let size = unsafe { client.GetBufferSize()? };
                let render: IAudioRenderClient = unsafe { client.GetService()? };
                Ok((client, render, size))
            })()
            .map_err(|e| crate::log_event(&format!("audio output: {e:#}")))
            .ok();
            retry_at = Instant::now() + Duration::from_secs(2);
            started = false;
        }
        let Some((client, render, size)) = &output else { continue };
        // Wait for a little sound before starting, so the first gap is not heard.
        if !started && queue.len() < target {
            continue;
        }
        let written = unsafe {
            (|| -> windows::core::Result<()> {
                let padding = client.GetCurrentPadding()?;
                let room = (size - padding) as usize;
                let count = room.min(queue.len() / BYTES_PER_FRAME);
                if count > 0 {
                    let data = render.GetBuffer(count as u32)?;
                    let target = std::slice::from_raw_parts_mut(data, count * BYTES_PER_FRAME);
                    for (slot, byte) in target.iter_mut().zip(queue.drain(..count * BYTES_PER_FRAME)) {
                        *slot = byte;
                    }
                    render.ReleaseBuffer(count as u32, 0)?;
                }
                if !started {
                    client.Start()?;
                    started = true;
                }
                Ok(())
            })()
        };
        if let Err(e) = written {
            // Headphones unplugged and the like: reopen the new default device.
            crate::log_event(&format!("audio output lost: {e}"));
            output = None;
        }
    }
    if let Some((client, _, _)) = output {
        let _ = unsafe { client.Stop() };
    }
    Ok(())
}

/// Checks that the built-in AAC codecs exist, for a clear message if not.
#[allow(dead_code)]
pub fn codecs_available() -> Result<()> {
    let _init = ThreadInit::new();
    Codec::encoder().map_err(|e| anyhow!("AAC encoder: {e:#}"))?;
    Codec::decoder().map_err(|e| anyhow!("AAC decoder: {e:#}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_datagrams_are_told_apart_from_video() {
        let packet = pack(7, b"aac");
        assert!(is_audio(&packet));
        assert_eq!(unpack(&packet), Some((7, &b"aac"[..])));
        let mut video = vec![0u8; HEADER + 10];
        video[HEADER - 1] = crate::fec::FLAG_KEY;
        assert!(!is_audio(&video));
        assert!(unpack(&video).is_none());
        assert!(!is_audio(&[FLAG_AUDIO; 4]));
    }

    #[test]
    fn queue_is_trimmed_to_the_target_when_too_long() {
        let mut queue: VecDeque<u8> = (0..1000u32).map(|i| i as u8).collect();
        trim_queue(&mut queue, 2000, 100);
        assert_eq!(queue.len(), 1000);
        trim_queue(&mut queue, 800, 100);
        assert_eq!(queue.len(), 100);
        assert_eq!(queue.len() % BYTES_PER_FRAME, 0);
    }

    /// Loopback capture records what this PC plays: here, silence played by
    /// the test itself, which keeps the speakers busy without a sound.
    #[test]
    fn loopback_captures_what_is_played() -> Result<()> {
        let _init = ThreadInit::new();
        let device = default_device()?;
        let output = open_client(&device, false)?;
        let render: IAudioRenderClient = unsafe { output.GetService()? };
        let size = unsafe { output.GetBufferSize()? };
        unsafe {
            let data = render.GetBuffer(size)?;
            std::ptr::write_bytes(data, 0, size as usize * BYTES_PER_FRAME);
            render.ReleaseBuffer(size, 0)?;
            output.Start()?;
        }
        let stop = AtomicBool::new(false);
        let started = Instant::now();
        let mut frames = 0;
        let mut sink = |_: &[u8]| {
            frames += 1;
            // Keep the speakers fed with silence while recording.
            unsafe {
                if let Ok(padding) = output.GetCurrentPadding() {
                    let room = size - padding;
                    if room > 0 {
                        if let Ok(data) = render.GetBuffer(room) {
                            std::ptr::write_bytes(data, 0, room as usize * BYTES_PER_FRAME);
                            let _ = render.ReleaseBuffer(room, 0);
                        }
                    }
                }
            }
            started.elapsed() < Duration::from_millis(1500)
        };
        capture(&mut sink, &stop)?;
        unsafe { output.Stop()? };
        assert!(frames > 20, "only {frames} AAC frames in 1.5 s");
        Ok(())
    }

    /// A tone through the real Windows encoder and decoder comes back as
    /// sound of about the same length.
    #[test]
    fn aac_round_trip_through_windows_codecs() -> Result<()> {
        let _init = ThreadInit::new();
        let mut encoder = Codec::encoder()?;
        let mut decoder = Codec::decoder()?;
        let samples = SAMPLE_RATE as usize; // one second
        let mut pcm = Vec::with_capacity(samples * BYTES_PER_FRAME);
        for i in 0..samples {
            let v = ((i as f64 * 440.0 * std::f64::consts::TAU / SAMPLE_RATE as f64).sin() * 8000.0) as i16;
            pcm.extend_from_slice(&v.to_le_bytes());
            pcm.extend_from_slice(&v.to_le_bytes());
        }
        let mut frames = Vec::new();
        for chunk in pcm.chunks(480 * BYTES_PER_FRAME) {
            let hns = (chunk.len() / BYTES_PER_FRAME) as i64 * HNS_PER_SECOND / SAMPLE_RATE as i64;
            encoder.process(chunk, hns, &mut frames)?;
        }
        if frames.is_empty() {
            anyhow::bail!("encoder produced nothing");
        }
        let bytes: usize = frames.iter().map(Vec::len).sum();
        assert!(bytes < pcm.len() / 10, "AAC should be much smaller: {bytes}");
        let mut out = Vec::new();
        for frame in &frames {
            decoder.process(frame, 1024 * HNS_PER_SECOND / SAMPLE_RATE as i64, &mut out)?;
        }
        let decoded: usize = out.iter().map(Vec::len).sum();
        assert!(decoded > pcm.len() * 8 / 10, "decoded {decoded} of {}", pcm.len());
        let peak = out.iter().flat_map(|b| b.chunks_exact(2)).map(|s| i16::from_le_bytes([s[0], s[1]]).unsigned_abs()).max();
        assert!(peak.unwrap_or(0) > 4000, "tone lost: {peak:?}");
        Ok(())
    }
}
