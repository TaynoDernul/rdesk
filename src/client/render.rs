//! Decode thread: decodes every frame, but presents only the newest one when
//! several are queued, so a network hiccup does not leave the view behind.

use super::decoder::{Decoded, Decoder};
use super::window;
use super::Stats;
use crate::d3d;
use crate::fec::Frame;
use anyhow::Result;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::Interface;
use windows::Win32::Foundation::{FALSE, HWND, RECT};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Media::MediaFoundation::{MFShutdown, MFStartup, MFSTARTUP_FULL, MF_VERSION};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_HIGHEST,
};
use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

const SWAP_FLAGS_BASE: u32 = 0;

struct Target {
    converter: d3d::Converter,
    input: ID3D11VideoProcessorInputView,
    output: ID3D11VideoProcessorOutputView,
    nv12: ID3D11Texture2D,
    video: (u32, u32),
    window: (u32, u32),
}

struct Renderer {
    hwnd: HWND,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    swapchain: IDXGISwapChain1,
    tearing: bool,
    target: Option<Target>,
    size: (u32, u32),
    fps: u32,
}

impl Renderer {
    fn new(hwnd: HWND, fps: u32) -> Result<Self> {
        let (device, context) = d3d::create_device(None)?;
        unsafe {
            let dxgi: IDXGIDevice1 = device.cast()?;
            // Never let frames pile up in the driver's present queue.
            dxgi.SetMaximumFrameLatency(1)?;
            let adapter = dxgi.GetAdapter()?;
            let factory: IDXGIFactory2 = adapter.GetParent()?;

            let tearing = factory.cast::<IDXGIFactory5>().is_ok_and(|f| {
                let mut allowed = FALSE;
                f.CheckFeatureSupport(
                    DXGI_FEATURE_PRESENT_ALLOW_TEARING,
                    &mut allowed as *mut _ as *mut _,
                    std::mem::size_of_val(&allowed) as u32,
                )
                .is_ok()
                    && allowed.as_bool()
            });

            let size = client_size(hwnd);
            let desc = DXGI_SWAP_CHAIN_DESC1 {
                Width: size.0,
                Height: size.1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: 2,
                Scaling: DXGI_SCALING_NONE,
                SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
                AlphaMode: DXGI_ALPHA_MODE_IGNORE,
                Flags: swap_flags(tearing),
                ..Default::default()
            };
            let swapchain = factory.CreateSwapChainForHwnd(&device, hwnd, &desc, None, None)?;
            // Fullscreen is handled by our own borderless window.
            factory.MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER)?;
            Ok(Self { hwnd, device, context, swapchain, tearing, target: None, size, fps })
        }
    }

    fn sync_size(&mut self) -> Result<()> {
        let size = client_size(self.hwnd);
        if size != self.size && size.0 > 0 && size.1 > 0 {
            // Views of the back buffer must be gone before ResizeBuffers.
            self.target = None;
            unsafe {
                self.context.ClearState();
                self.context.Flush();
                self.swapchain.ResizeBuffers(
                    0,
                    size.0,
                    size.1,
                    DXGI_FORMAT_UNKNOWN,
                    DXGI_SWAP_CHAIN_FLAG(swap_flags(self.tearing) as i32),
                )?;
            }
            self.size = size;
        }
        Ok(())
    }

    fn target(&mut self, video: (u32, u32)) -> Result<&Target> {
        let current = self.target.as_ref().is_some_and(|t| t.video == video && t.window == self.size);
        if !current {
            let converter = d3d::Converter::new(
                &self.device,
                &self.context,
                video,
                self.size,
                self.fps,
                d3d::COLOR_YUV_709_LIMITED,
                d3d::COLOR_RGB_FULL,
            )?;
            let nv12 = d3d::create_texture(&self.device, video.0, video.1, DXGI_FORMAT_NV12)?;
            let input = converter.input_view(&nv12)?;
            let back: ID3D11Texture2D = unsafe { self.swapchain.GetBuffer(0)? };
            let output = converter.output_view(&back)?;
            self.target = Some(Target { converter, input, output, nv12, video, window: self.size });
        }
        Ok(self.target.as_ref().expect("target created above"))
    }

    fn store(&mut self, picture: &Decoded) -> Result<()> {
        // Decoder surfaces belong to a texture array the decoder may reuse, so
        // the picture is copied out. This also allows redraw after a resize.
        self.sync_size()?;
        let (w, h) = (picture.width & !1, picture.height & !1);
        let context = self.context.clone();
        let target = self.target((w, h))?;
        let area = D3D11_BOX { left: 0, top: 0, front: 0, right: w, bottom: h, back: 1 };
        unsafe {
            context.CopySubresourceRegion(
                &target.nv12,
                0,
                0,
                0,
                0,
                &picture.texture,
                picture.subresource,
                Some(&area),
            );
        }
        window::set_video_size(w, h);
        Ok(())
    }

    fn present(&mut self) -> Result<()> {
        self.sync_size()?;
        let Some(video) = self.target.as_ref().map(|t| t.video).or_else(window::video_size) else {
            return Ok(());
        };
        let size = self.size;
        let tearing = self.tearing;
        let swapchain = self.swapchain.clone();
        let target = self.target(video)?;
        let source = d3d::rect(0, 0, video.0 as i32, video.1 as i32);
        let dest: RECT = d3d::letterbox(video, size);
        let whole = d3d::rect(0, 0, size.0 as i32, size.1 as i32);
        target.converter.blit(&target.input, &target.output, source, dest, whole)?;
        unsafe {
            // Sync interval 0: show now. The host already paces frames at 60 FPS.
            let flags = if tearing { DXGI_PRESENT_ALLOW_TEARING } else { DXGI_PRESENT(0) };
            swapchain.Present(0, flags).ok()?;
        }
        Ok(())
    }
}

fn swap_flags(tearing: bool) -> u32 {
    SWAP_FLAGS_BASE | if tearing { DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING.0 as u32 } else { 0 }
}

fn client_size(hwnd: HWND) -> (u32, u32) {
    let mut r = RECT::default();
    let _ = unsafe { GetClientRect(hwnd, &mut r) };
    (((r.right - r.left).max(1)) as u32, ((r.bottom - r.top).max(1)) as u32)
}

pub fn run(hwnd: HWND, fps: u32, frames: Receiver<Frame>, stats: Arc<Stats>) {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let _ = MFStartup(MF_VERSION, MFSTARTUP_FULL);
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    }
    if let Err(e) = decode_loop(hwnd, fps, &frames, &stats) {
        if !window::is_closing() {
            crate::log_event(&format!("video error: {e:#}"));
            eprintln!("Ошибка видео: {e:#}");
            super::set_end_reason(format!("ошибка видео: {e:#}"));
            window::request_close();
        }
    }
    unsafe {
        let _ = MFShutdown();
        CoUninitialize();
    }
}

fn decode_loop(hwnd: HWND, fps: u32, frames: &Receiver<Frame>, stats: &Stats) -> Result<()> {
    let mut renderer = Renderer::new(hwnd, fps)?;
    let mut decoder = Decoder::new(&renderer.device, false)?;
    let mut stored = false;
    let mut last_size = renderer.size;

    loop {
        let frame = match frames.recv_timeout(Duration::from_millis(16)) {
            Ok(frame) => frame,
            Err(RecvTimeoutError::Timeout) => {
                // A paused stream still has to redraw after a window resize.
                if stored && client_size(hwnd) != last_size {
                    renderer.present()?;
                    last_size = renderer.size;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };

        super::QUEUED.fetch_sub(1, Ordering::Relaxed);
        let capture_us = frame.timestamp_us;
        let started = Instant::now();
        // The host picks the codec; follow it at the keyframe where it changes.
        if frame.hevc != decoder.hevc {
            decoder = Decoder::new(&renderer.device, frame.hevc)?;
        }
        for picture in decoder.decode(&frame.data)? {
            renderer.store(&picture)?;
            stored = true;
        }
        stats.decode_us.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        stats.decoded.fetch_add(1, Ordering::Relaxed);

        if stored && frames.is_empty_hint() {
            renderer.present()?;
            last_size = renderer.size;
            stats.presented.fetch_add(1, Ordering::Relaxed);
            stats.record_latency(capture_us);
        }
    }
}

/// `Receiver` has no is_empty; the channel depth is tracked by `Stats` instead.
trait EmptyHint {
    fn is_empty_hint(&self) -> bool;
}

impl EmptyHint for Receiver<Frame> {
    fn is_empty_hint(&self) -> bool {
        super::QUEUED.load(Ordering::Relaxed) == 0
    }
}
