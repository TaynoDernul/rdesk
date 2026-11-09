//! Splits encoded frames into QUIC datagrams with Reed-Solomon parity and
//! reassembles them on the receiver. A lost shard is rebuilt from parity with
//! no retransmission, so one dropped packet costs no extra round trip.

use anyhow::{bail, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

pub const HEADER: usize = 24;
pub const FLAG_KEY: u8 = 1;
/// The frame is H.265 rather than H.264.
pub const FLAG_HEVC: u8 = 2;
const MAX_DATA_SHARDS: usize = 64;
const MAX_FRAME: usize = 32 * 1024 * 1024;
/// How many newer frames may arrive before a missing one is declared lost.
const REORDER_WINDOW: u32 = 3;
/// A frame with no new shard for this long is given up. Measured from the
/// latest shard, not the first: a paced keyframe legitimately takes longer.
const FRAME_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    frame_id: u32,
    frame_len: u32,
    timestamp_us: u64,
    block: u16,
    blocks: u16,
    shard: u8,
    data: u8,
    parity: u8,
    flags: u8,
}

impl Header {
    fn write(&self, b: &mut [u8]) {
        b[0..4].copy_from_slice(&self.frame_id.to_le_bytes());
        b[4..8].copy_from_slice(&self.frame_len.to_le_bytes());
        b[8..16].copy_from_slice(&self.timestamp_us.to_le_bytes());
        b[16..18].copy_from_slice(&self.block.to_le_bytes());
        b[18..20].copy_from_slice(&self.blocks.to_le_bytes());
        b[20] = self.shard;
        b[21] = self.data;
        b[22] = self.parity;
        b[23] = self.flags;
    }

    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() <= HEADER {
            bail!("short datagram");
        }
        let h = Header {
            frame_id: u32::from_le_bytes(b[0..4].try_into()?),
            frame_len: u32::from_le_bytes(b[4..8].try_into()?),
            timestamp_us: u64::from_le_bytes(b[8..16].try_into()?),
            block: u16::from_le_bytes(b[16..18].try_into()?),
            blocks: u16::from_le_bytes(b[18..20].try_into()?),
            shard: b[20],
            data: b[21],
            parity: b[22],
            flags: b[23],
        };
        if h.frame_len as usize > MAX_FRAME
            || h.blocks == 0
            || h.block >= h.blocks
            || h.data == 0
            || h.data as usize > MAX_DATA_SHARDS
            || h.parity == 0
            || h.shard as usize >= h.data as usize + h.parity as usize
        {
            bail!("invalid shard header");
        }
        Ok(h)
    }
}

pub struct Packetizer {
    cache: HashMap<(usize, usize), ReedSolomon>,
    fec_percent: usize,
    key_fec_percent: usize,
}

impl Packetizer {
    pub fn new(fec_percent: usize) -> Self {
        Self { cache: HashMap::new(), fec_percent, key_fec_percent: fec_percent }
    }

    /// Extra parity for keyframes: losing one costs a long freeze, while
    /// losing an ordinary frame only costs the wait for the next keyframe.
    pub fn with_key_fec(mut self, percent: usize) -> Self {
        self.key_fec_percent = percent;
        self
    }

    /// `max_datagram` is the current path limit reported by QUIC.
    pub fn packetize(
        &mut self,
        frame: &[u8],
        frame_id: u32,
        flags: u8,
        timestamp_us: u64,
        max_datagram: usize,
        mut out: impl FnMut(Vec<u8>),
    ) -> Result<()> {
        if max_datagram <= HEADER + 64 {
            bail!("datagram limit too small: {max_datagram}");
        }
        if frame.is_empty() || frame.len() > MAX_FRAME {
            bail!("invalid frame size: {}", frame.len());
        }
        let shard_size = max_datagram - HEADER;
        let data_shards = frame.len().div_ceil(shard_size);
        let blocks = data_shards.div_ceil(MAX_DATA_SHARDS);
        if blocks > u16::MAX as usize {
            bail!("frame needs too many blocks");
        }

        let mut offset = 0;
        for block in 0..blocks {
            let k = (data_shards - block * MAX_DATA_SHARDS).min(MAX_DATA_SHARDS);
            let percent = if flags & FLAG_KEY != 0 { self.key_fec_percent } else { self.fec_percent };
            let p = (k * percent).div_ceil(100).max(1);
            let mut shards = Vec::with_capacity(k + p);
            for _ in 0..k {
                let mut s = vec![0u8; HEADER + shard_size];
                let end = (offset + shard_size).min(frame.len());
                s[HEADER..HEADER + end - offset].copy_from_slice(&frame[offset..end]);
                offset = end;
                shards.push(s);
            }
            for _ in 0..p {
                shards.push(vec![0u8; HEADER + shard_size]);
            }

            let rs = match self.cache.entry((k, p)) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => e.insert(ReedSolomon::new(k, p)?),
            };
            let mut payloads: Vec<&mut [u8]> =
                shards.iter_mut().map(|s| &mut s[HEADER..]).collect();
            rs.encode(&mut payloads)?;
            drop(payloads);

            for (i, mut s) in shards.into_iter().enumerate() {
                Header {
                    frame_id,
                    frame_len: frame.len() as u32,
                    timestamp_us,
                    block: block as u16,
                    blocks: blocks as u16,
                    shard: i as u8,
                    data: k as u8,
                    parity: p as u8,
                    flags,
                }
                .write(&mut s);
                out(s);
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub id: u32,
    pub timestamp_us: u64,
    pub key: bool,
    pub hevc: bool,
    pub data: Vec<u8>,
}

struct Block {
    data: usize,
    parity: usize,
    shards: Vec<Option<Vec<u8>>>,
    received: usize,
    decoded: bool,
}

struct Partial {
    frame_len: usize,
    timestamp_us: u64,
    key: bool,
    hevc: bool,
    blocks: Vec<Option<Block>>,
    decoded_blocks: usize,
    complete: Option<Vec<u8>>,
    last_seen: Instant,
}

/// Delivers complete frames strictly in order. After an unrecoverable loss it
/// drops everything until the next keyframe, because H.264 P-frames would
/// otherwise decode against a missing reference and show corruption.
pub struct Assembler {
    next: u32,
    highest: u32,
    partial: BTreeMap<u32, Partial>,
    cache: HashMap<(usize, usize), ReedSolomon>,
    waiting_for_key: bool,
    pub frames_lost: u64,
    pub shards_recovered: u64,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            next: 0,
            highest: 0,
            partial: BTreeMap::new(),
            cache: HashMap::new(),
            // A stream can only start at a keyframe.
            waiting_for_key: true,
            frames_lost: 0,
            shards_recovered: 0,
        }
    }

    /// True while the decoder has no valid reference; the caller should keep
    /// asking the host for a keyframe at a limited rate.
    pub fn needs_keyframe(&self) -> bool {
        self.waiting_for_key
    }

    pub fn push(&mut self, packet: &[u8], now: Instant) -> Result<Vec<Frame>> {
        let h = Header::parse(packet)?;
        if h.frame_id >= self.next {
            self.highest = self.highest.max(h.frame_id);
            self.insert(&h, &packet[HEADER..], now)?;
        }
        Ok(self.drain(now))
    }

    /// Lets a frame time out when no newer packet arrives to trigger it.
    pub fn tick(&mut self, now: Instant) -> Vec<Frame> {
        self.drain(now)
    }

    fn insert(&mut self, h: &Header, payload: &[u8], now: Instant) -> Result<()> {
        let partial = self.partial.entry(h.frame_id).or_insert_with(|| Partial {
            frame_len: h.frame_len as usize,
            timestamp_us: h.timestamp_us,
            key: h.flags & FLAG_KEY != 0,
            hevc: h.flags & FLAG_HEVC != 0,
            blocks: (0..h.blocks).map(|_| None).collect(),
            decoded_blocks: 0,
            complete: None,
            last_seen: now,
        });
        partial.last_seen = now;
        if partial.complete.is_some() {
            return Ok(());
        }
        if partial.blocks.len() != h.blocks as usize || partial.frame_len != h.frame_len as usize {
            bail!("shard disagrees with its frame");
        }

        let (k, p) = (h.data as usize, h.parity as usize);
        let block = partial.blocks[h.block as usize].get_or_insert_with(|| Block {
            data: k,
            parity: p,
            shards: vec![None; k + p],
            received: 0,
            decoded: false,
        });
        if block.data != k || block.parity != p {
            bail!("shard disagrees with its block");
        }
        if block.decoded || block.shards[h.shard as usize].is_some() {
            return Ok(());
        }
        if let Some(existing) = block.shards.iter().flatten().next() {
            if existing.len() != payload.len() {
                bail!("shard size mismatch");
            }
        }
        block.shards[h.shard as usize] = Some(payload.to_vec());
        block.received += 1;

        if block.received >= k {
            let missing = block.shards[..k].iter().filter(|s| s.is_none()).count();
            if missing > 0 {
                let rs = match self.cache.entry((k, p)) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(ReedSolomon::new(k, p)?)
                    }
                };
                rs.reconstruct_data(&mut block.shards)?;
                self.shards_recovered += missing as u64;
            }
            block.decoded = true;
            partial.decoded_blocks += 1;
        }

        if partial.decoded_blocks == partial.blocks.len() {
            let mut out = Vec::with_capacity(partial.frame_len + 2048);
            for b in partial.blocks.iter().flatten() {
                for s in b.shards[..b.data].iter().flatten() {
                    out.extend_from_slice(s);
                }
            }
            if out.len() < partial.frame_len {
                bail!("frame shorter than declared");
            }
            out.truncate(partial.frame_len);
            partial.complete = Some(out);
            partial.blocks.clear();
        }
        Ok(())
    }

    fn drain(&mut self, now: Instant) -> Vec<Frame> {
        let mut out = Vec::new();
        loop {
            // A complete keyframe supersedes every older frame.
            let key_ahead = self
                .partial
                .iter()
                .find(|(_, p)| p.key && p.complete.is_some())
                .map(|(id, _)| *id)
                .filter(|id| *id > self.next);
            let front_ready =
                self.partial.get(&self.next).is_some_and(|p| p.complete.is_some());

            if front_ready {
                let p = self.partial.remove(&self.next).expect("checked above");
                let id = self.next;
                self.next += 1;
                if self.waiting_for_key && !p.key {
                    continue;
                }
                if p.key {
                    self.waiting_for_key = false;
                }
                out.push(Frame {
                    id,
                    timestamp_us: p.timestamp_us,
                    key: p.key,
                    hevc: p.hevc,
                    data: p.complete.expect("checked above"),
                });
                continue;
            }

            if let Some(id) = key_ahead {
                if self.waiting_for_key {
                    // Normal path while recovering: skip straight to the key.
                } else {
                    self.frames_lost += (id - self.next) as u64;
                }
                self.partial.retain(|k, _| *k >= id);
                self.next = id;
                continue;
            }

            if self.next > self.highest {
                break;
            }
            let timed_out = self
                .partial
                .get(&self.next)
                .is_some_and(|p| now.duration_since(p.last_seen) >= FRAME_TIMEOUT);
            if self.highest - self.next >= REORDER_WINDOW || timed_out {
                if !self.waiting_for_key {
                    self.frames_lost += 1;
                }
                self.waiting_for_key = true;
                self.partial.remove(&self.next);
                self.next += 1;
                continue;
            }
            break;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: usize = 1200;

    fn sample(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    fn packets(p: &mut Packetizer, data: &[u8], id: u32, key: bool) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        p.packetize(data, id, if key { FLAG_KEY } else { 0 }, 7, MTU, |x| v.push(x)).unwrap();
        v
    }

    #[test]
    fn delivers_lossless_frames_in_order() {
        let mut p = Packetizer::new(10);
        let mut a = Assembler::new();
        let now = Instant::now();
        let f0 = sample(5000, 1);
        let f1 = sample(300, 2);
        let mut got = Vec::new();
        for s in packets(&mut p, &f0, 0, true) {
            got.extend(a.push(&s, now).unwrap());
        }
        for s in packets(&mut p, &f1, 1, false) {
            got.extend(a.push(&s, now).unwrap());
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].data, f0);
        assert!(got[0].key);
        assert_eq!(got[1].data, f1);
        assert_eq!(got[1].timestamp_us, 7);
    }

    #[test]
    fn large_frame_spans_blocks() {
        let mut p = Packetizer::new(10);
        let mut a = Assembler::new();
        let now = Instant::now();
        let f = sample(400_000, 3);
        let mut got = Vec::new();
        for s in packets(&mut p, &f, 0, true) {
            got.extend(a.push(&s, now).unwrap());
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, f);
    }

    #[test]
    fn rebuilds_lost_shard_from_parity() {
        let mut p = Packetizer::new(20);
        let mut a = Assembler::new();
        let now = Instant::now();
        let f = sample(20_000, 4);
        let mut pk = packets(&mut p, &f, 0, true);
        pk.remove(3);
        let mut got = Vec::new();
        for s in pk {
            got.extend(a.push(&s, now).unwrap());
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, f);
        assert_eq!(a.shards_recovered, 1);
    }

    #[test]
    fn keyframes_carry_more_parity_and_survive_heavier_loss() {
        let mut p = Packetizer::new(10).with_key_fec(35);
        let f = sample(60_000, 6);
        let key = packets(&mut p, &f, 0, true);
        let delta = packets(&mut p, &f, 1, false);
        assert!(key.len() > delta.len() + 10, "{} vs {}", key.len(), delta.len());

        // Drop every fourth shard: 25% loss, beyond what 10% parity can repair.
        let mut a = Assembler::new();
        let now = Instant::now();
        let got: Vec<_> = key
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 4 != 0)
            .flat_map(|(_, s)| a.push(s, now).unwrap())
            .collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, f);
    }

    #[test]
    fn tolerates_shard_reordering() {
        let mut p = Packetizer::new(10);
        let mut a = Assembler::new();
        let now = Instant::now();
        let f = sample(10_000, 5);
        let mut pk = packets(&mut p, &f, 0, true);
        pk.reverse();
        let got: Vec<_> = pk.iter().flat_map(|s| a.push(s, now).unwrap()).collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, f);
    }

    #[test]
    fn unrecoverable_loss_waits_for_keyframe() {
        let mut p = Packetizer::new(10);
        let mut a = Assembler::new();
        let now = Instant::now();
        let mut got = Vec::new();
        for s in packets(&mut p, &sample(100, 0), 0, true) {
            got.extend(a.push(&s, now).unwrap());
        }
        assert_eq!(got.len(), 1);
        assert!(!a.needs_keyframe());

        // Frame 1 vanishes; frames 2..=5 must not reach the decoder.
        got.clear();
        for id in 2..=5 {
            for s in packets(&mut p, &sample(100, id as u8), id, false) {
                got.extend(a.push(&s, now).unwrap());
            }
        }
        assert!(got.is_empty());
        assert!(a.needs_keyframe());
        assert_eq!(a.frames_lost, 1);

        let key = sample(200, 9);
        for s in packets(&mut p, &key, 6, true) {
            got.extend(a.push(&s, now).unwrap());
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, 6);
        assert_eq!(got[0].data, key);
        assert!(!a.needs_keyframe());
    }

    #[test]
    fn stalled_frame_times_out_on_tick() {
        let mut p = Packetizer::new(10);
        let mut a = Assembler::new();
        let start = Instant::now();
        for s in packets(&mut p, &sample(100, 0), 0, true) {
            a.push(&s, start).unwrap();
        }
        let mut pk = packets(&mut p, &sample(20_000, 1), 1, false);
        pk.truncate(2);
        for s in &pk {
            a.push(s, start).unwrap();
        }
        assert!(!a.needs_keyframe());
        // Shards still trickling in keep the frame alive past the timeout...
        let later = start + FRAME_TIMEOUT - Duration::from_millis(1);
        let more = packets(&mut p, &sample(20_000, 1), 1, false);
        a.push(&more[5], later).unwrap();
        assert!(a.tick(start + FRAME_TIMEOUT).is_empty());
        assert!(!a.needs_keyframe());
        // ...and only silence gives it up.
        assert!(a.tick(later + FRAME_TIMEOUT).is_empty());
        assert!(a.needs_keyframe());
    }

    #[test]
    fn rejects_malformed_packets() {
        let mut a = Assembler::new();
        let now = Instant::now();
        assert!(a.push(&[0u8; 5], now).is_err());
        assert!(a.push(&[0u8; 40], now).is_err()); // zero blocks and shards

        let mut p = Packetizer::new(10);
        let mut pk = packets(&mut p, &sample(100, 0), 0, true).remove(0);
        pk[20] = 250; // shard index beyond data + parity
        assert!(a.push(&pk, now).is_err());
    }
}
