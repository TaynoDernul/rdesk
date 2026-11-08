//! Capture → convert → encode → send, all on one high-priority thread.
//! The loop never blocks longer than about a millisecond, so a finished frame
//! leaves the machine as soon as the encoder produces it.

use super::encoder::Encoder;
use crate::d3d;
use crate::fec::{Packetizer, FLAG_KEY};
use crate::proto::{CursorShape, HostMsg};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use iroh::endpoint::{Connection, SendDatagramError};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use windows::core::Interface;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_NV12};
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Media::MediaFoundation::{MFShutdown, MFStartup, MFSTARTUP_FULL, MF_VERSION};
use windows::Win32::Media::{timeBeginPeriod, timeEndPeriod};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_HIGHEST,
};

const FEC_PERCENT: usize = 15;
const NV12_POOL: usize = 6;
/// Repeats of an unchanged frame: CBR refines text sharpness once motion stops.
const REFINE_FRAMES: u32 = 10;
const REFINE_INTERVAL: Duration = Duration::from_millis(33);
/// Frames are skipped while more than this much playback time is queued.
const QUEUE_MS: usize = 120;
const MIN_QUEUE_BYTES: usize = 96 * 1024;
const MIN_KBPS: u32 = 1_500;
/// A relay path is usually far slower than a direct one; start low and grow.
const RELAY_START_KBPS: u32 = 6_000;
/// Each keyframe is large; on a lossy path, answering every request would
/// only cause more loss.
const MIN_KEYFRAME_INTERVAL: Duration = Duration::from_secs(1);

const MIN_FPS: u32 = 15;
const KEY_FEC_PERCENT: usize = 35;
/// Datagrams leave at this multiple of the stream's rate, never as a burst.
const PACE_FACTOR: f64 = 2.0;
/// Lets a few packets go at once, so a frame is not spread over many loops.
const PACE_BURST: Duration = Duration::from_millis(4);

/// Spreads datagrams out in time. Relays forward them over TCP and keep only
/// a short queue per peer, so a keyframe sent as one burst loses its tail.
/// The bytes waiting here also tell the loop when the path cannot keep up.
struct Pacer {
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    tokens: f64,
    last: Instant,
}

impl Pacer {
    fn new(now: Instant) -> Self {
        Self { queue: VecDeque::new(), queued_bytes: 0, tokens: 0.0, last: now }
    }

    fn push(&mut self, datagram: Bytes) {
        self.queued_bytes += datagram.len();
        self.queue.push_back(datagram);
    }

    fn backlog(&self) -> usize {
        self.queued_bytes
    }

    fn flush<E>(
        &mut self,
        now: Instant,
        kbps: u32,
        mut send: impl FnMut(Bytes) -> Result<(), E>,
    ) -> Result<(), E> {
        let rate = kbps as f64 * 1000.0 / 8.0 * PACE_FACTOR;
        let burst = (rate * PACE_BURST.as_secs_f64()).max(3000.0);
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        // Sending while the balance is positive lets one large datagram go
        // and keeps the long-run rate exact through the debt it leaves.
        while self.tokens > 0.0 {
            let Some(datagram) = self.queue.pop_front() else { break };
            self.queued_bytes -= datagram.len();
            self.tokens -= datagram.len() as f64;
            send(datagram)?;
        }
        if self.queue.is_empty() {
            self.tokens = self.tokens.min(burst);
        }
        Ok(())
    }
}
const DECREASE_EVERY: Duration = Duration::from_millis(400);
const INCREASE_EVERY: Duration = Duration::from_secs(2);
const RESTART_AFTER_IGNORED_WINDOWS: u32 = 3;
const MIN_RESTART_INTERVAL: Duration = Duration::from_secs(5);
const CALM_BEFORE_RAISE: Duration = Duration::from_secs(4);
const SUSTAINED_CONGESTION: Duration = Duration::from_millis(500);

/// Bytes that take about `QUEUE_MS` to send at `kbps`.
fn queue_limit(kbps: u32) -> usize {
    (kbps as usize * 1000 / 8 * QUEUE_MS / 1000).max(MIN_QUEUE_BYTES)
}

/// Picks bitrate and frame rate from what the network shows.
///
/// Two signals count as congestion: our own send queue growing, and the
/// round-trip time rising above its minimum. The second matters on relay
/// paths, which run over TCP: there packets queue up instead of being lost, so
/// QUIC's loss-based control never slows down by itself. Bitrate is the first
/// lever; frame rate is the second, because some hardware encoders ignore
/// bitrate changes made while running.
struct RateControl {
    max_kbps: u32,
    max_fps: u32,
    kbps: u32,
    fps: u32,
    encoder_kbps: u32,
    min_rtt: Option<Duration>,
    last_change: Instant,
    window_start: Instant,
    window_bytes: u64,
    /// What the encoder actually produced in the last full second.
    sent_kbps: u32,
    last_congestion: Instant,
    /// Start of the current unbroken stretch of congestion.
    congested_since: Option<Instant>,
    ignored_windows: u32,
    last_restart: Instant,
}

impl RateControl {
    fn new(max_kbps: u32, max_fps: u32, kbps: u32, fps: u32, now: Instant) -> Self {
        Self {
            max_kbps,
            max_fps,
            kbps,
            fps: fps.clamp(MIN_FPS.min(max_fps), max_fps),
            encoder_kbps: kbps,
            min_rtt: None,
            last_change: now,
            window_start: now,
            window_bytes: 0,
            sent_kbps: 0,
            last_congestion: now,
            congested_since: None,
            ignored_windows: 0,
            last_restart: now,
        }
    }

    fn interval(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.fps as f64)
    }

    /// The rate the stream really runs at. Pacing and the queue limit follow
    /// this rather than the target, or an encoder that overshoots its target
    /// would make the queue look full forever and drag the rate to the floor.
    fn effective_kbps(&self) -> u32 {
        self.kbps.max(self.sent_kbps)
    }

    fn pace_kbps(&self) -> u32 {
        self.effective_kbps()
    }

    fn record_sent(&mut self, bytes: usize) {
        self.window_bytes += bytes as u64;
    }

    fn delay_congested(&mut self, rtt: Option<Duration>) -> bool {
        let Some(rtt) = rtt else { return false };
        let min = *self.min_rtt.get_or_insert(rtt);
        if rtt < min {
            self.min_rtt = Some(rtt);
            return false;
        }
        rtt > min + (min / 2).max(Duration::from_millis(40))
    }

    /// Returns (skip frames now, new bitrate to give the encoder). Only a
    /// local backlog skips frames: a rising RTT only lowers the rate, since
    /// sending nothing would also stop the RTT from ever updating again.
    fn update(&mut self, now: Instant, queued: usize, rtt: Option<Duration>) -> (bool, Option<u32>) {
        let backlog = queued > queue_limit(self.effective_kbps());
        let congested = backlog || self.delay_congested(rtt);
        if congested {
            self.last_congestion = now;
            self.congested_since.get_or_insert(now);
        } else {
            self.congested_since = None;
        }
        // A blip, such as the switch from relay to direct path, is not a
        // reason to cut: only congestion that lasts is.
        let sustained = self
            .congested_since
            .is_some_and(|since| now.duration_since(since) >= SUSTAINED_CONGESTION);

        // Once a second, compare what was sent with what was asked for.
        let elapsed = now.duration_since(self.window_start);
        let mut sent_kbps = None;
        if elapsed >= Duration::from_secs(1) {
            sent_kbps = Some((self.window_bytes * 8 / elapsed.as_millis().max(1) as u64) as u32);
            self.window_bytes = 0;
            self.window_start = now;
        }
        if let Some(sent) = sent_kbps {
            self.sent_kbps = sent;
            if sent > self.kbps + self.kbps / 2 {
                self.ignored_windows += 1;
            } else {
                self.ignored_windows = 0;
            }
        }

        let since_change = now.duration_since(self.last_change);
        if sustained && since_change >= DECREASE_EVERY {
            self.last_change = now;
            let before = self.kbps;
            self.kbps = (self.kbps * 7 / 10).max(MIN_KBPS);
            // The encoder may not follow; fewer frames always means fewer bytes.
            if self.ignored_windows > 0 || before == self.kbps {
                self.fps = (self.fps * 3 / 4).max(MIN_FPS.min(self.max_fps));
            }
            return (backlog, (self.kbps != before).then_some(self.kbps));
        }
        if !congested && since_change >= INCREASE_EVERY {
            self.last_change = now;
            if self.fps < self.max_fps {
                self.fps = (self.fps + 10).min(self.max_fps);
            } else if self.kbps < self.max_kbps {
                self.kbps = (self.kbps + self.kbps / 4 + 1).min(self.max_kbps);
                return (false, Some(self.kbps));
            }
        }
        (backlog, None)
    }

    /// True when the encoder should be rebuilt at the current target: either
    /// it keeps overshooting a lowered target, or the path has been calm and
    /// the target has grown well past what the encoder was created with.
    /// Some encoders ignore bitrate changes in both directions.
    fn wants_restart(&mut self, now: Instant) -> bool {
        let differs = self.encoder_kbps.abs_diff(self.kbps) > self.encoder_kbps / 4;
        let overshooting = self.ignored_windows >= RESTART_AFTER_IGNORED_WINDOWS && differs;
        let room_to_grow = self.kbps >= self.encoder_kbps + self.encoder_kbps * 3 / 10
            && now.duration_since(self.last_congestion) >= CALM_BEFORE_RAISE;
        if (overshooting || room_to_grow) && now.duration_since(self.last_restart) >= MIN_RESTART_INTERVAL {
            self.last_restart = now;
            self.ignored_windows = 0;
            return true;
        }
        false
    }
}

pub struct VideoShared {
    pub stop: AtomicBool,
    pub force_key: AtomicBool,
    pub restart: AtomicBool,
    pub monitor: AtomicUsize,
    pub rect: Mutex<RECT>,
    pub max_kbps: AtomicU32,
    pub fps: u32,
    pub stats: bool,
    pub frame_id: AtomicU64,
    /// Rate chosen so far, kept across pipeline restarts (0 = not chosen yet).
    pub current_kbps: AtomicU32,
    pub current_fps: AtomicU32,
}

pub fn run(conn: Connection, shared: &VideoShared, ctl: UnboundedSender<HostMsg>) {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let _ = MFStartup(MF_VERSION, MFSTARTUP_FULL);
        timeBeginPeriod(1);
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    }
    let mut notified = false;
    while !shared.stop.load(Ordering::Relaxed) {
        shared.restart.store(false, Ordering::Relaxed);
        match pipeline(&conn, shared, &ctl) {
            Ok(()) => notified = false,
            Err(e) => {
                // The lock screen, UAC prompts and mode changes all land here;
                // keep retrying until the desktop can be captured again.
                crate::log_event(&format!("capture interrupted: {e:#}"));
                if !notified {
                    notified = true;
                    eprintln!("Захват прерван: {e:#}");
                    crate::host::set_note(format!("Захват экрана приостановлен: {e:#}"));
                    let _ = ctl.send(HostMsg::Notice {
                        text: format!("Захват экрана приостановлен: {e}"),
                    });
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    unsafe {
        timeEndPeriod(1);
        let _ = MFShutdown();
        CoUninitialize();
    }
}

struct Monitor {
    adapter: IDXGIAdapter1,
    output: IDXGIOutput1,
    rect: RECT,
}

fn monitors() -> Result<Vec<Monitor>> {
    let mut found = Vec::new();
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
        let mut a = 0;
        while let Ok(adapter) = factory.EnumAdapters1(a) {
            a += 1;
            let mut o = 0;
            while let Ok(output) = adapter.EnumOutputs(o) {
                o += 1;
                let desc = output.GetDesc()?;
                if desc.AttachedToDesktop.as_bool() {
                    found.push(Monitor {
                        adapter: adapter.clone(),
                        output: output.cast()?,
                        rect: desc.DesktopCoordinates,
                    });
                }
            }
        }
    }
    Ok(found)
}

fn unix_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

fn pipeline(
    conn: &Connection,
    shared: &VideoShared,
    ctl: &UnboundedSender<HostMsg>,
) -> Result<()> {
    let monitors = monitors()?;
    if monitors.is_empty() {
        return Err(anyhow!("no active monitors"));
    }
    let index = shared.monitor.load(Ordering::Relaxed).min(monitors.len() - 1);
    let monitor = &monitors[index];
    *shared.rect.lock().expect("rect lock") = monitor.rect;

    // The encoder needs even dimensions.
    let width = ((monitor.rect.right - monitor.rect.left) as u32) & !1;
    let height = ((monitor.rect.bottom - monitor.rect.top) as u32) & !1;

    let adapter: IDXGIAdapter = monitor.adapter.cast()?;
    let (device, context) = d3d::create_device(Some(&adapter))?;
    let duplication = unsafe { monitor.output.DuplicateOutput(&device) }
        .context("DuplicateOutput failed (lock screen or UAC prompt active?)")?;
    let adapter_desc = unsafe { monitor.adapter.GetDesc1()? };

    let converter = d3d::Converter::new(
        &device,
        &context,
        (width, height),
        (width, height),
        shared.fps,
        d3d::COLOR_RGB_FULL,
        d3d::COLOR_YUV_709_LIMITED,
    )?;
    let bgra = d3d::create_texture(&device, width, height, DXGI_FORMAT_B8G8R8A8_UNORM)?;
    let input_view = converter.input_view(&bgra)?;
    let mut pool = Vec::with_capacity(NV12_POOL);
    for _ in 0..NV12_POOL {
        let texture = d3d::create_texture(&device, width, height, DXGI_FORMAT_NV12)?;
        let view = converter.output_view(&texture)?;
        pool.push((texture, view));
    }

    let relayed = crate::net::route_info(conn).is_some_and(|(_, relay)| relay);
    let max_kbps = shared.max_kbps.load(Ordering::Relaxed);
    let kbps = match shared.current_kbps.load(Ordering::Relaxed) {
        0 if relayed => max_kbps.min(RELAY_START_KBPS),
        0 => max_kbps,
        chosen => chosen.min(max_kbps),
    };
    let fps = match shared.current_fps.load(Ordering::Relaxed) {
        0 => shared.fps,
        chosen => chosen,
    };
    let mut rate = RateControl::new(max_kbps, shared.fps, kbps, fps, Instant::now());
    let mut encoder =
        Encoder::new(&device, adapter_desc.AdapterLuid, width, height, shared.fps, kbps)
            .context("cannot start hardware H.264 encoder")?;
    crate::log_event(&format!("encoder: {} {width}x{height}@{} {kbps} kbps", encoder.name, shared.fps));
    println!("Кодировщик: {}, {width}x{height}@{}", encoder.name, shared.fps);

    let _ = ctl.send(HostMsg::VideoInfo {
        width,
        height,
        monitor: index as u8,
        monitors: monitors.len() as u8,
    });
    // A new encoder always starts at a keyframe the client can join on.
    shared.force_key.store(true, Ordering::Relaxed);

    let whole = d3d::rect(0, 0, width as i32, height as i32);
    let mut rtt = None;
    let mut rtt_sampled = Instant::now();
    let mut on_relay = relayed;
    let mut packetizer = Packetizer::new(FEC_PERCENT).with_key_fec(KEY_FEC_PERCENT);
    let mut pacer = Pacer::new(Instant::now());
    let mut outputs: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut in_flight: VecDeque<(Instant, u64)> = VecDeque::new();
    let mut pointer_buffer: Vec<u8> = Vec::new();
    let mut cursor_visible = true;

    let mut next_due = Instant::now();
    let mut dirty = true; // Send the first frame even on a static screen.
    let mut refine_left = 0u32;
    let mut last_submit = Instant::now();
    let mut pool_index = 0usize;

    let mut last_forced_key: Option<Instant> = None;
    let mut stats_since = Instant::now();
    let (mut stat_frames, mut stat_bytes, mut stat_encode_us, mut stat_skipped) = (0u32, 0u64, 0u128, 0u32);

    loop {
        if shared.stop.load(Ordering::Relaxed) || shared.restart.load(Ordering::Relaxed) {
            return Ok(());
        }

        // 1. Send whatever the encoder finished.
        encoder.poll(&mut outputs)?;
        for (data, encoder_key) in outputs.drain(..) {
            let Some((submitted, capture_us)) = in_flight.pop_front() else { continue };
            stat_encode_us += submitted.elapsed().as_micros();
            stat_frames += 1;
            stat_bytes += data.len() as u64;
            rate.record_sent(data.len());
            let max = conn.max_datagram_size().ok_or_else(|| anyhow!("peer refuses datagrams"))?;
            let id = shared.frame_id.fetch_add(1, Ordering::Relaxed) as u32;
            let flags = if encoder_key { FLAG_KEY } else { 0 };
            packetizer.packetize(&data, id, flags, capture_us, max, |shard| pacer.push(Bytes::from(shard)))?;
        }
        match pacer.flush(Instant::now(), rate.pace_kbps(), |d| conn.send_datagram(d)) {
            Ok(()) => {}
            Err(SendDatagramError::ConnectionLost(_)) | Err(SendDatagramError::Disabled) => {
                shared.stop.store(true, Ordering::Relaxed);
                return Ok(());
            }
            // The path MTU shrank: a frame is gone, so restart cleanly.
            Err(_) => shared.force_key.store(true, Ordering::Relaxed),
        }

        // 2. Wait up to 1 ms for a new desktop frame.
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource = None;
        match unsafe { duplication.AcquireNextFrame(1, &mut info, &mut resource) } {
            Ok(()) => {
                let frame = resource.take().expect("AcquireNextFrame succeeded");
                let source: ID3D11Texture2D = frame.cast()?;
                if info.LastPresentTime != 0 {
                    // Copied so the desktop frame can be released at once.
                    unsafe { context.CopySubresourceRegion(&bgra, 0, 0, 0, 0, &source, 0, Some(&D3D11_BOX {
                        left: 0, top: 0, front: 0, right: width, bottom: height, back: 1,
                    })) };
                    dirty = true;
                }
                send_pointer(&duplication, &info, &mut pointer_buffer, &mut cursor_visible, ctl);
                unsafe { duplication.ReleaseFrame()? };
            }
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {}
            // ACCESS_LOST and similar: rebuild the pipeline from the top.
            Err(e) => return Err(e.into()),
        }

        // 3. Adapt to the network before spending encoder time on a frame.
        if rtt_sampled.elapsed() >= Duration::from_millis(250) {
            let route = crate::net::route_info(conn);
            rtt = route.map(|(rtt, _)| rtt);
            rtt_sampled = Instant::now();
            // iroh starts on a relay and moves to a direct path once hole
            // punching succeeds. What was learned on the relay says nothing
            // about the new path, so start over at full quality.
            if on_relay && route.is_some_and(|(_, relay)| !relay) {
                crate::log_event("moved to a direct path; restarting at full bitrate");
                shared.current_kbps.store(max_kbps, Ordering::Relaxed);
                shared.current_fps.store(shared.fps, Ordering::Relaxed);
                shared.force_key.store(true, Ordering::Relaxed);
                return Ok(());
            }
            on_relay = route.is_some_and(|(_, relay)| relay);
        }
        let queued = pacer.backlog()
            + crate::host::DATAGRAM_SEND_BUFFER.saturating_sub(conn.datagram_send_buffer_space());
        let (congested, new_kbps) = rate.update(Instant::now(), queued, rtt);
        if let Some(kbps) = new_kbps {
            encoder.set_bitrate(kbps);
        }
        if rate.wants_restart(Instant::now()) {
            // This encoder does not follow bitrate changes: rebuild it.
            crate::log_event(&format!("encoder ignores bitrate; restarting at {} kbps", rate.kbps));
            shared.current_kbps.store(rate.kbps, Ordering::Relaxed);
            shared.current_fps.store(rate.fps, Ordering::Relaxed);
            return Ok(());
        }
        let interval = rate.interval();

        // 4. Submit when a frame is due.
        let now = Instant::now();
        let refine = !dirty && refine_left > 0 && now.duration_since(last_submit) >= REFINE_INTERVAL;
        if encoder.can_accept() && now >= next_due && (dirty || refine) {
            if congested {
                // Skipping before the encoder keeps the reference chain intact.
                stat_skipped += 1;
                next_due = now + interval;
            } else {
                let (texture, view) = &pool[pool_index];
                pool_index = (pool_index + 1) % pool.len();
                converter.blit(&input_view, view, whole, whole, whole)?;
                let key_allowed = last_forced_key.is_none_or(|t| t.elapsed() >= MIN_KEYFRAME_INTERVAL);
                if key_allowed && shared.force_key.swap(false, Ordering::Relaxed) {
                    encoder.force_keyframe();
                    last_forced_key = Some(now);
                }
                let capture_us = unix_micros();
                encoder.submit(texture)?;
                in_flight.push_back((now, capture_us));
                if dirty {
                    refine_left = REFINE_FRAMES;
                } else {
                    refine_left -= 1;
                }
                dirty = false;
                last_submit = now;
                // Step from the schedule, not from "now", so 60 FPS holds on average.
                next_due += interval;
                if next_due + interval < now {
                    next_due = now;
                }
            }
        }

        if shared.stats && stats_since.elapsed() >= Duration::from_secs(1) {
            let n = stat_frames.max(1) as u128;
            println!(
                "host: {stat_frames} fps, {:.1} Мбит/с, кодирование {:.2} мс, пропущено {stat_skipped}, цель {} кбит/с при {} fps, RTT {} мс",
                stat_bytes as f64 * 8.0 / 1e6,
                (stat_encode_us / n) as f64 / 1000.0,
                rate.kbps,
                rate.fps,
                rtt.map_or(0, |r| r.as_millis()),
            );
            stats_since = Instant::now();
            (stat_frames, stat_bytes, stat_encode_us, stat_skipped) = (0, 0, 0, 0);
        }
    }
}

fn send_pointer(
    duplication: &IDXGIOutputDuplication,
    info: &DXGI_OUTDUPL_FRAME_INFO,
    buffer: &mut Vec<u8>,
    visible: &mut bool,
    ctl: &UnboundedSender<HostMsg>,
) {
    if info.LastMouseUpdateTime != 0 {
        let now_visible = info.PointerPosition.Visible.as_bool();
        if now_visible != *visible {
            *visible = now_visible;
            let _ = ctl.send(HostMsg::CursorVisible { visible: now_visible });
        }
    }
    if info.PointerShapeBufferSize == 0 {
        return;
    }
    buffer.resize(info.PointerShapeBufferSize as usize, 0);
    let mut required = 0u32;
    let mut shape = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
    let result = unsafe {
        duplication.GetFramePointerShape(
            buffer.len() as u32,
            buffer.as_mut_ptr() as *mut _,
            &mut required,
            &mut shape,
        )
    };
    if result.is_ok() {
        let _ = ctl.send(HostMsg::CursorShape(CursorShape {
            kind: shape.Type,
            width: shape.Width,
            height: shape.Height,
            pitch: shape.Pitch,
            hot_x: shape.HotSpot.x.max(0) as u32,
            hot_y: shape.HotSpot.y.max(0) as u32,
            data: buffer[..required as usize].to_vec(),
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn pacer_spreads_a_burst_at_the_target_rate() {
        let t0 = Instant::now();
        let mut pacer = Pacer::new(t0);
        for _ in 0..100 {
            pacer.push(Bytes::from(vec![0u8; 1200]));
        }
        assert_eq!(pacer.backlog(), 120_000);
        // 6 Mbit/s stream, paced at 12 Mbit/s = 1500 bytes per millisecond.
        let mut sent = 0usize;
        for ms_step in 1..=40 {
            pacer
                .flush(t0 + ms(ms_step), 6_000, |d| {
                    sent += d.len();
                    Ok::<(), ()>(())
                })
                .unwrap();
        }
        assert!((55_000..=66_000).contains(&sent), "sent {sent}");
        assert_eq!(pacer.backlog(), 120_000 - sent);
    }

    #[test]
    fn pacer_reports_send_errors() {
        let t0 = Instant::now();
        let mut pacer = Pacer::new(t0);
        pacer.push(Bytes::from_static(b"x"));
        let result = pacer.flush(t0 + ms(10), 8_000, |_| Err("lost"));
        assert_eq!(result, Err("lost"));
    }

    #[test]
    fn rising_rtt_lowers_rate_but_does_not_stop_sending() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 10_000, 60, t0);
        rate.update(t0, 0, Some(ms(50)));
        let (skip, _) = rate.update(t0 + ms(500), 0, Some(ms(400)));
        assert!(!skip, "a stale RTT must never freeze the stream");
        let (skip, new) = rate.update(t0 + ms(1100), 0, Some(ms(400)));
        assert!(!skip);
        assert_eq!(new, Some(7_000));
    }

    #[test]
    fn a_short_blip_does_not_cut_the_rate() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 20_000, 60, t0);
        rate.update(t0, 0, Some(ms(1)));
        rate.update(t0 + ms(500), 0, Some(ms(300)));
        let (_, new) = rate.update(t0 + ms(700), 0, Some(ms(1)));
        assert_eq!(new, None);
        assert_eq!(rate.kbps, 20_000);
    }

    #[test]
    fn queue_limit_scales_with_bitrate() {
        assert_eq!(queue_limit(1_000), MIN_QUEUE_BYTES);
        assert_eq!(queue_limit(20_000), 300_000);
    }

    #[test]
    fn small_rtt_jitter_is_not_congestion() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 10_000, 60, t0);
        rate.update(t0, 0, Some(ms(50)));
        assert!(!rate.update(t0 + ms(500), 0, Some(ms(80))).0);
    }

    #[test]
    fn long_send_queue_is_congestion() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 8_000, 60, t0);
        assert!(rate.update(t0 + ms(500), 1_000_000, None).0);
    }

    #[test]
    fn frame_rate_drops_when_encoder_ignores_bitrate() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 6_000, 60, t0);
        rate.update(t0, 0, Some(ms(50)));
        // One second at 12 Mbit/s against a 6 Mbit/s target.
        rate.record_sent(1_500_000);
        rate.update(t0 + ms(1000), 0, Some(ms(400)));
        rate.update(t0 + ms(1600), 0, Some(ms(400)));
        assert!(rate.kbps < 6_000);
        assert!(rate.fps < 60, "fps {}", rate.fps);
    }

    #[test]
    fn encoder_is_rebuilt_after_ignoring_bitrate_for_seconds() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 8_000, 60, t0);
        rate.update(t0, 0, Some(ms(50)));
        for second in 1..=6 {
            rate.record_sent(2_000_000); // 16 Mbit/s, well above any target here
            rate.update(t0 + Duration::from_secs(second), 0, Some(ms(400)));
        }
        assert!(rate.kbps < 6_000);
        assert!(rate.wants_restart(t0 + Duration::from_secs(6)));
        assert!(!rate.wants_restart(t0 + Duration::from_secs(7)), "rate-limited");
    }

    #[test]
    fn recovery_restores_frame_rate_before_bitrate() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 4_000, 30, t0);
        rate.update(t0, 0, Some(ms(50)));
        let (_, new) = rate.update(t0 + Duration::from_secs(3), 0, Some(ms(50)));
        assert_eq!((rate.fps, new), (40, None));
        rate.update(t0 + Duration::from_secs(6), 0, Some(ms(50)));
        rate.update(t0 + Duration::from_secs(9), 0, Some(ms(50)));
        assert_eq!(rate.fps, 60);
        let (_, new) = rate.update(t0 + Duration::from_secs(12), 0, Some(ms(50)));
        assert!(new.is_some_and(|k| k > 4_000));
    }

    #[test]
    fn overshooting_encoder_does_not_drag_the_queue_limit_down() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 2_000, 60, t0);
        rate.update(t0, 0, Some(ms(1)));
        // The encoder really produces 20 Mbit/s despite a 2 Mbit/s target.
        rate.record_sent(2_500_000);
        rate.update(t0 + ms(1000), 0, Some(ms(1)));
        assert_eq!(rate.effective_kbps(), 20_000);
        // A normal 200 KB keyframe burst is then not mistaken for congestion.
        let (skip, _) = rate.update(t0 + ms(1100), 200_000, Some(ms(1)));
        assert!(!skip);
    }

    #[test]
    fn calm_path_rebuilds_encoder_at_a_higher_bitrate() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 6_000, 60, t0);
        rate.update(t0, 0, Some(ms(1)));
        for second in 1..=8 {
            rate.update(t0 + Duration::from_secs(second), 0, Some(ms(1)));
        }
        assert!(rate.kbps >= 7_800, "target grew to {}", rate.kbps);
        assert!(rate.wants_restart(t0 + Duration::from_secs(8)));
    }

    #[test]
    fn no_raise_restart_right_after_congestion() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 6_000, 60, t0);
        rate.kbps = 10_000;
        rate.update(t0 + Duration::from_secs(5), 1_000_000, None);
        assert!(!rate.wants_restart(t0 + Duration::from_secs(6)));
    }

    #[test]
    fn bitrate_never_falls_below_the_floor() {
        let t0 = Instant::now();
        let mut rate = RateControl::new(20_000, 60, 2_000, 60, t0);
        for i in 1..30 {
            rate.update(t0 + ms(500 * i), 1_000_000, None);
        }
        assert_eq!(rate.kbps, MIN_KBPS);
        assert_eq!(rate.fps, MIN_FPS);
    }
}
