//! H.264 decoding with DXVA through Microsoft's decoder transform, in low
//! latency mode so a frame comes out as soon as it goes in.

use anyhow::{anyhow, Result};
use windows::core::{Interface, VARIANT};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

pub struct Decoded {
    pub texture: ID3D11Texture2D,
    pub subresource: u32,
    pub width: u32,
    pub height: u32,
}

pub struct Decoder {
    mft: IMFTransform,
    _manager: IMFDXGIDeviceManager,
    width: u32,
    height: u32,
    sample_time: i64,
}

impl Decoder {
    pub fn new(device: &ID3D11Device) -> Result<Self> {
        unsafe {
            let mft: IMFTransform = CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER)?;
            let attrs = mft.GetAttributes()?;
            let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            if let Ok(api) = mft.cast::<ICodecAPI>() {
                let _ = api.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(1u32));
            }

            let mut token = 0u32;
            let mut manager = None;
            MFCreateDXGIDeviceManager(&mut token, &mut manager)?;
            let manager = manager.expect("MFCreateDXGIDeviceManager succeeded");
            manager.ResetDevice(device, token)?;
            mft.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize)?;

            let input = MFCreateMediaType()?;
            input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            input.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            mft.SetInputType(0, &input, 0)?;

            let mut decoder = Self { mft, _manager: manager, width: 0, height: 0, sample_time: 0 };
            decoder.select_output()?;
            decoder.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            decoder.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
            Ok(decoder)
        }
    }

    fn select_output(&mut self) -> Result<()> {
        unsafe {
            let mut index = 0;
            loop {
                let kind = self.mft.GetOutputAvailableType(0, index)?;
                if kind.GetGUID(&MF_MT_SUBTYPE)? == MFVideoFormat_NV12 {
                    self.mft.SetOutputType(0, &kind, 0)?;
                    let size = kind.GetUINT64(&MF_MT_FRAME_SIZE).unwrap_or(0);
                    self.width = (size >> 32) as u32;
                    self.height = size as u32;
                    // Coded size is rounded up to 16 pixels; the aperture is real.
                    let mut area = MFVideoArea::default();
                    let bytes = std::slice::from_raw_parts_mut(
                        &mut area as *mut MFVideoArea as *mut u8,
                        std::mem::size_of::<MFVideoArea>(),
                    );
                    if kind.GetBlob(&MF_MT_MINIMUM_DISPLAY_APERTURE, bytes, None).is_ok()
                        && area.Area.cx > 0
                        && area.Area.cy > 0
                    {
                        self.width = area.Area.cx as u32;
                        self.height = area.Area.cy as u32;
                    }
                    return Ok(());
                }
                index += 1;
            }
        }
    }

    /// Decodes one access unit and returns every picture it produced.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Decoded>> {
        let mut pictures = Vec::with_capacity(1);
        unsafe {
            let buffer = MFCreateMemoryBuffer(data.len() as u32)?;
            let mut ptr = std::ptr::null_mut();
            buffer.Lock(&mut ptr, None, None)?;
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(data.len() as u32)?;

            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(self.sample_time)?;
            self.sample_time += 166_667;

            loop {
                match self.mft.ProcessInput(0, &sample, 0) {
                    Ok(()) => break,
                    // Output must be drained first; then the input is accepted.
                    Err(e) if e.code() == MF_E_NOTACCEPTING => self.drain(&mut pictures)?,
                    Err(e) => return Err(e.into()),
                }
            }
            self.drain(&mut pictures)?;
        }
        Ok(pictures)
    }

    fn drain(&mut self, pictures: &mut Vec<Decoded>) -> Result<()> {
        unsafe {
            loop {
                let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: std::mem::ManuallyDrop::new(None),
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
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                        // New resolution, for example after switching monitors.
                        self.select_output()?;
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }

                let sample = sample.ok_or_else(|| anyhow!("decoder returned no sample"))?;
                let buffer = sample.GetBufferByIndex(0)?;
                let dxgi: IMFDXGIBuffer = buffer.cast()?;
                let mut raw = std::ptr::null_mut();
                dxgi.GetResource(&ID3D11Texture2D::IID, &mut raw)?;
                let texture = ID3D11Texture2D::from_raw(raw);
                pictures.push(Decoded {
                    texture,
                    subresource: dxgi.GetSubresourceIndex()?,
                    width: self.width,
                    height: self.height,
                });
            }
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        let _ = unsafe { self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0) };
    }
}
