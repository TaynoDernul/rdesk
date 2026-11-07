//! Hardware H.264 through an asynchronous Media Foundation transform. AMD,
//! NVIDIA and Intel drivers all expose their encoders this way.

use anyhow::{anyhow, bail, Context, Result};
use std::time::Instant;
use windows::core::{Interface, GUID, VARIANT};
use windows::Win32::Foundation::{E_NOTIMPL, LUID};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::CoTaskMemFree;

const CLEAN_POINT_FALSE: u32 = 0;
const RATE_CONTROL_CBR: u32 = 0;
const H264_PROFILE_HIGH: u32 = 100;
const GOP_FRAMES: u32 = 600;
const NAL_SPS: u8 = 7;
const NAL_AUD: u8 = 9;

pub struct Encoder {
    mft: IMFTransform,
    events: IMFMediaEventGenerator,
    codec: Option<ICodecAPI>,
    activate: IMFActivate,
    _manager: IMFDXGIDeviceManager,
    sequence_header: Vec<u8>,
    provides_samples: bool,
    output_size: u32,
    started: Instant,
    frame_duration: i64,
    need_input: u32,
    pub name: String,
}

impl Encoder {
    pub fn new(
        device: &ID3D11Device,
        adapter: LUID,
        width: u32,
        height: u32,
        fps: u32,
        kbps: u32,
    ) -> Result<Self> {
        let mut last_error = anyhow!("no hardware H.264 encoder on this adapter");
        for activate in enumerate(adapter)? {
            match Self::open(activate, device, width, height, fps, kbps) {
                Ok(encoder) => return Ok(encoder),
                Err(e) => last_error = e,
            }
        }
        Err(last_error)
    }

    fn open(
        activate: IMFActivate,
        device: &ID3D11Device,
        width: u32,
        height: u32,
        fps: u32,
        kbps: u32,
    ) -> Result<Self> {
        unsafe {
            let name = friendly_name(&activate);
            let mft: IMFTransform = activate.ActivateObject()?;
            let attrs = mft.GetAttributes()?;
            attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)?;
            attrs.SetUINT32(&MF_LOW_LATENCY, 1)?;

            let mut token = 0u32;
            let mut manager = None;
            MFCreateDXGIDeviceManager(&mut token, &mut manager)?;
            let manager = manager.expect("MFCreateDXGIDeviceManager succeeded");
            manager.ResetDevice(device, token)?;
            mft.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize)
                .context("encoder rejected the D3D device")?;

            let codec: Option<ICodecAPI> = mft.cast().ok();
            if let Some(api) = &codec {
                // Optional tuning: drivers differ, so a refused value is not fatal.
                let set = |id: &GUID, value: u32| {
                    let _ = api.SetValue(id, &VARIANT::from(value));
                };
                set(&CODECAPI_AVEncCommonRateControlMode, RATE_CONTROL_CBR);
                set(&CODECAPI_AVEncCommonMeanBitRate, kbps * 1000);
                set(&CODECAPI_AVLowLatencyMode, 1);
                set(&CODECAPI_AVEncMPVDefaultBPictureCount, 0);
                set(&CODECAPI_AVEncMPVGOPSize, GOP_FRAMES);
            }

            let (mut input_ids, mut output_ids) = ([0u32; 1], [0u32; 1]);
            match mft.GetStreamIDs(&mut input_ids, &mut output_ids) {
                // Most transforms have fixed stream ids 0/0 and return E_NOTIMPL.
                Err(e) if e.code() != E_NOTIMPL => return Err(e.into()),
                _ => {}
            }

            let output = MFCreateMediaType()?;
            output.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            output.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            output.SetUINT32(&MF_MT_AVG_BITRATE, kbps * 1000)?;
            output.SetUINT64(&MF_MT_FRAME_SIZE, pack(width, height))?;
            output.SetUINT64(&MF_MT_FRAME_RATE, pack(fps, 1))?;
            output.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
            output.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            output.SetUINT32(&MF_MT_MPEG2_PROFILE, H264_PROFILE_HIGH)?;
            mft.SetOutputType(0, &output, 0).context("encoder rejected the output format")?;

            let input = MFCreateMediaType()?;
            input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            input.SetUINT64(&MF_MT_FRAME_SIZE, pack(width, height))?;
            input.SetUINT64(&MF_MT_FRAME_RATE, pack(fps, 1))?;
            input.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
            input.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            mft.SetInputType(0, &input, 0).context("encoder rejected NV12 input")?;

            let sequence_header = read_sequence_header(&mft);
            let info = mft.GetOutputStreamInfo(0)?;
            let provides_samples =
                info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 != 0;

            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;

            let events: IMFMediaEventGenerator = mft.cast()?;
            Ok(Self {
                mft,
                events,
                codec,
                activate,
                _manager: manager,
                sequence_header,
                provides_samples,
                output_size: info.cbSize.max(1024 * 1024),
                started: Instant::now(),
                frame_duration: 10_000_000 / fps as i64,
                need_input: 0,
                name,
            })
        }
    }

    pub fn can_accept(&self) -> bool {
        self.need_input > 0
    }

    /// Handles queued encoder events without blocking; completed frames are
    /// appended to `out` as (Annex B bytes, is keyframe).
    pub fn poll(&mut self, out: &mut Vec<(Vec<u8>, bool)>) -> Result<()> {
        loop {
            let event = match unsafe { self.events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(event) => event,
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            let kind = unsafe { event.GetType()? };
            if kind == METransformNeedInput.0 as u32 {
                self.need_input += 1;
            } else if kind == METransformHaveOutput.0 as u32 {
                if let Some(frame) = self.read_output()? {
                    out.push(frame);
                }
            }
        }
    }

    pub fn submit(&mut self, texture: &ID3D11Texture2D) -> Result<()> {
        if self.need_input == 0 {
            bail!("encoder is not ready for input");
        }
        unsafe {
            let buffer = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, texture, 0, false)?;
            let flat: IMF2DBuffer = buffer.cast()?;
            buffer.SetCurrentLength(flat.GetContiguousLength()?)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(self.started.elapsed().as_nanos() as i64 / 100)?;
            sample.SetSampleDuration(self.frame_duration)?;
            self.mft.ProcessInput(0, &sample, 0)?;
        }
        self.need_input -= 1;
        Ok(())
    }

    fn read_output(&mut self) -> Result<Option<(Vec<u8>, bool)>> {
        unsafe {
            let sample = if self.provides_samples {
                None
            } else {
                let sample = MFCreateSample()?;
                sample.AddBuffer(&MFCreateMemoryBuffer(self.output_size)?)?;
                Some(sample)
            };
            let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(sample),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            }];
            let mut status = 0u32;
            let result = self.mft.ProcessOutput(0, &mut buffers, &mut status);
            let sample = std::mem::ManuallyDrop::take(&mut buffers[0].pSample);
            drop(std::mem::ManuallyDrop::take(&mut buffers[0].pEvents));

            match result {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    let kind = self.mft.GetOutputAvailableType(0, 0)?;
                    self.mft.SetOutputType(0, &kind, 0)?;
                    self.sequence_header = read_sequence_header(&self.mft);
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }

            let sample = sample.ok_or_else(|| anyhow!("encoder returned no sample"))?;
            let key = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(CLEAN_POINT_FALSE) != 0;
            let buffer = sample.ConvertToContiguousBuffer()?;
            let mut ptr = std::ptr::null_mut();
            let mut len = 0u32;
            buffer.Lock(&mut ptr, None, Some(&mut len))?;
            let bytes = std::slice::from_raw_parts(ptr, len as usize);
            let mut data = Vec::with_capacity(bytes.len() + self.sequence_header.len());
            // A decoder joining at this keyframe needs SPS/PPS in the stream.
            if key && !begins_with_sps(bytes) {
                data.extend_from_slice(&self.sequence_header);
            }
            data.extend_from_slice(bytes);
            buffer.Unlock()?;
            Ok(Some((data, key)))
        }
    }

    pub fn set_bitrate(&self, kbps: u32) {
        if let Some(api) = &self.codec {
            let _ = unsafe { api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(kbps * 1000)) };
        }
    }

    pub fn force_keyframe(&self) {
        if let Some(api) = &self.codec {
            let _ = unsafe { api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32)) };
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        unsafe {
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
            // Hardware encoder sessions are limited; hand this one back.
            let _ = self.activate.ShutdownObject();
        }
    }
}

fn pack(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

fn enumerate(adapter: LUID) -> Result<Vec<IMFActivate>> {
    unsafe {
        let attrs = {
            let mut attrs = None;
            MFCreateAttributes(&mut attrs, 1)?;
            attrs.expect("MFCreateAttributes succeeded")
        };
        // Bound to the capturing adapter, so frames need no copy between GPUs.
        let luid = std::slice::from_raw_parts(
            &adapter as *const LUID as *const u8,
            std::mem::size_of::<LUID>(),
        );
        attrs.SetBlob(&MFT_ENUM_ADAPTER_LUID, luid)?;

        let output = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: MFVideoFormat_H264,
        };
        let mut list = std::ptr::null_mut();
        let mut count = 0u32;
        MFTEnum2(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            None,
            Some(&output),
            &attrs,
            &mut list,
            &mut count,
        )?;
        let mut found = Vec::with_capacity(count as usize);
        if !list.is_null() {
            for item in std::slice::from_raw_parts_mut(list, count as usize) {
                if let Some(activate) = item.take() {
                    found.push(activate);
                }
            }
            CoTaskMemFree(Some(list as *const _));
        }
        Ok(found)
    }
}

fn friendly_name(activate: &IMFActivate) -> String {
    unsafe {
        let mut ptr = windows::core::PWSTR::null();
        let mut len = 0u32;
        if activate.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut ptr, &mut len).is_ok() {
            let name = ptr.to_string().unwrap_or_default();
            CoTaskMemFree(Some(ptr.0 as *const _));
            return name;
        }
        "H.264 encoder".to_string()
    }
}

fn read_sequence_header(mft: &IMFTransform) -> Vec<u8> {
    unsafe {
        let Ok(kind) = mft.GetOutputCurrentType(0) else { return Vec::new() };
        let Ok(size) = kind.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) else { return Vec::new() };
        let mut buf = vec![0u8; size as usize];
        match kind.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None) {
            Ok(()) if buf.starts_with(&[0, 0]) => buf,
            _ => Vec::new(),
        }
    }
}

/// True if SPS comes first, optionally after an access unit delimiter.
fn begins_with_sps(data: &[u8]) -> bool {
    let mut seen = 0;
    let mut i = 0;
    while i + 3 < data.len() && seen < 2 {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            match data[i + 3] & 0x1F {
                NAL_SPS => return true,
                NAL_AUD => seen += 1,
                _ => return false,
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sps_at_stream_start() {
        assert!(begins_with_sps(&[0, 0, 0, 1, 0x67, 0x42]));
        assert!(begins_with_sps(&[0, 0, 1, 0x67, 0x42]));
        // After an access unit delimiter.
        assert!(begins_with_sps(&[0, 0, 0, 1, 0x09, 0x10, 0, 0, 0, 1, 0x67, 0x42]));
    }

    #[test]
    fn rejects_streams_without_leading_sps() {
        assert!(!begins_with_sps(&[0, 0, 0, 1, 0x65, 0x88])); // IDR slice
        assert!(!begins_with_sps(&[1, 2, 3]));
        assert!(!begins_with_sps(&[]));
    }

    #[test]
    fn packs_media_foundation_pairs() {
        assert_eq!(pack(1920, 1080), 0x0000_0780_0000_0438);
    }
}
