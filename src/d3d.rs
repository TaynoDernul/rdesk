//! Shared Direct3D 11 helpers. The fixed-function video processor converts
//! between BGRA and NV12 on the GPU, so no shaders need to be compiled.

use anyhow::Result;
use std::mem::ManuallyDrop;
use windows::core::Interface;
use windows::Win32::Foundation::{BOOL, HMODULE, RECT, TRUE};
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT, DXGI_RATIONAL, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::IDXGIAdapter;

/// Bit layout of D3D11_VIDEO_PROCESSOR_COLOR_SPACE: full-range RGB.
pub const COLOR_RGB_FULL: u32 = 0;
/// YCbCr_Matrix = BT.709 (bit 2), Nominal_Range = 16-235 (bits 4-5).
pub const COLOR_YUV_709_LIMITED: u32 = (1 << 2) | (1 << 4);

pub fn create_device(adapter: Option<&IDXGIAdapter>) -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
    let driver = if adapter.is_some() { D3D_DRIVER_TYPE_UNKNOWN } else { D3D_DRIVER_TYPE_HARDWARE };
    let levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
    let mut device = None;
    let mut context = None;
    unsafe {
        D3D11CreateDevice(
            adapter,
            driver,
            HMODULE::default(),
            flags,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?;
        let device: ID3D11Device = device.expect("D3D11CreateDevice succeeded");
        let context: ID3D11DeviceContext = context.expect("D3D11CreateDevice succeeded");
        // Media Foundation transforms use this device from their own threads.
        let _ = device.cast::<ID3D11Multithread>()?.SetMultithreadProtected(TRUE);
        Ok((device, context))
    }
}

pub fn create_texture(
    device: &ID3D11Device,
    width: u32,
    height: u32,
    format: DXGI_FORMAT,
) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: format,
        SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
        CPUAccessFlags: 0,
        MiscFlags: 0,
    };
    let mut texture = None;
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture))? };
    Ok(texture.expect("CreateTexture2D succeeded"))
}

pub struct Converter {
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
}

impl Converter {
    pub fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        (in_w, in_h): (u32, u32),
        (out_w, out_h): (u32, u32),
        fps: u32,
        in_color: u32,
        out_color: u32,
    ) -> Result<Self> {
        let video_device: ID3D11VideoDevice = device.cast()?;
        let video_context: ID3D11VideoContext = context.cast()?;
        let rate = DXGI_RATIONAL { Numerator: fps, Denominator: 1 };
        let desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: rate,
            InputWidth: in_w,
            InputHeight: in_h,
            OutputFrameRate: rate,
            OutputWidth: out_w,
            OutputHeight: out_h,
            Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
        };
        unsafe {
            let enumerator = video_device.CreateVideoProcessorEnumerator(&desc)?;
            let processor = video_device.CreateVideoProcessor(&enumerator, 0)?;
            video_context.VideoProcessorSetStreamFrameFormat(
                &processor,
                0,
                D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            );
            video_context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, BOOL(0));
            let input = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: in_color };
            let output = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: out_color };
            video_context.VideoProcessorSetStreamColorSpace(&processor, 0, &input);
            video_context.VideoProcessorSetOutputColorSpace(&processor, &output);
            Ok(Self { video_device, video_context, enumerator, processor })
        }
    }

    pub fn input_view(&self, texture: &ID3D11Texture2D) -> Result<ID3D11VideoProcessorInputView> {
        let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPIV { MipSlice: 0, ArraySlice: 0 },
            },
        };
        let mut view = None;
        unsafe {
            self.video_device.CreateVideoProcessorInputView(
                texture,
                &self.enumerator,
                &desc,
                Some(&mut view),
            )?
        };
        Ok(view.expect("CreateVideoProcessorInputView succeeded"))
    }

    pub fn output_view(&self, texture: &ID3D11Texture2D) -> Result<ID3D11VideoProcessorOutputView> {
        let desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
            },
        };
        let mut view = None;
        unsafe {
            self.video_device.CreateVideoProcessorOutputView(
                texture,
                &self.enumerator,
                &desc,
                Some(&mut view),
            )?
        };
        Ok(view.expect("CreateVideoProcessorOutputView succeeded"))
    }

    pub fn blit(
        &self,
        input: &ID3D11VideoProcessorInputView,
        output: &ID3D11VideoProcessorOutputView,
        source: RECT,
        dest: RECT,
        target: RECT,
    ) -> Result<()> {
        unsafe {
            let ctx = &self.video_context;
            ctx.VideoProcessorSetStreamSourceRect(&self.processor, 0, TRUE, Some(&source));
            ctx.VideoProcessorSetStreamDestRect(&self.processor, 0, TRUE, Some(&dest));
            ctx.VideoProcessorSetOutputTargetRect(&self.processor, TRUE, Some(&target));
            let mut stream = D3D11_VIDEO_PROCESSOR_STREAM {
                Enable: TRUE,
                OutputIndex: 0,
                InputFrameOrField: 0,
                PastFrames: 0,
                FutureFrames: 0,
                ppPastSurfaces: std::ptr::null_mut(),
                pInputSurface: ManuallyDrop::new(Some(input.clone())),
                ppFutureSurfaces: std::ptr::null_mut(),
                ppPastSurfacesRight: std::ptr::null_mut(),
                pInputSurfaceRight: ManuallyDrop::new(None),
                ppFutureSurfacesRight: std::ptr::null_mut(),
            };
            let result = ctx.VideoProcessorBlt(
                &self.processor,
                output,
                0,
                std::slice::from_ref(&stream),
            );
            ManuallyDrop::drop(&mut stream.pInputSurface);
            result?;
        }
        Ok(())
    }
}

pub fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
    RECT { left, top, right, bottom }
}

/// Largest rectangle with the video's aspect ratio centred in the window.
pub fn letterbox(video: (u32, u32), window: (u32, u32)) -> RECT {
    let (vw, vh) = (video.0.max(1) as u64, video.1.max(1) as u64);
    let (ww, wh) = (window.0.max(1) as u64, window.1.max(1) as u64);
    let (w, h) = if ww * vh <= wh * vw { (ww, ww * vh / vw) } else { (wh * vw / vh, wh) };
    let x = (ww - w) / 2;
    let y = (wh - h) / 2;
    rect(x as i32, y as i32, (x + w) as i32, (y + h) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letterbox_preserves_aspect_and_centres() {
        let r = letterbox((1920, 1080), (1000, 1000));
        assert_eq!((r.left, r.right), (0, 1000));
        assert_eq!((r.top, r.bottom), (219, 781));

        let r = letterbox((1920, 1080), (1920, 1200));
        assert_eq!((r.left, r.top, r.right, r.bottom), (0, 60, 1920, 1140));

        let r = letterbox((1000, 1000), (1920, 1080));
        assert_eq!((r.left, r.top, r.right, r.bottom), (420, 0, 1500, 1080));
    }

    #[test]
    fn letterbox_survives_zero_sizes() {
        let r = letterbox((0, 0), (0, 0));
        assert!(r.right >= r.left && r.bottom >= r.top);
    }
}
