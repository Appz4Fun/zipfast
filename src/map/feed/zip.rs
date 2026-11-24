// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

//! The feed decoder's ZIP layer: Deflate (method 8) and Deflate64 (method 9) members, plain, under ZipCrypto or
//! under WinZip AES, and stored members under ZipCrypto. (Plain and WinZip AES stored members map output to packed
//! offsets and use the stored lanes, which skip holes.)
//!
//! Deflate has no restart point a decoder can find without the bytes before it (a block's start is a bit offset
//! known only by decoding up to it), and ZipCrypto's keystream depends on every byte before, so the main decode reads
//! the packed bytes in order and waits at a hole until its bytes come; nothing is lost, repaired or decoded twice.
//!
//! A checkpoint is the last block boundary the main decode passed with its output written: the boundary's bit
//! offset in the packed stream and the output offset there. It holds no window: a restore reads the window (32 KiB
//! for Deflate, 64 KiB for Deflate64) back from the sink ([`FeedSink::read_held`]) and decodes from the boundary, so
//! it decodes again at most one block. ZipCrypto restores read the packed bytes before the checkpoint again (the
//! keystream only, nothing decoded or written). WinZip AES checks its authentication code (HMAC-SHA1 over the
//! ciphertext, after it) in order as it reads; a restore that does not start at the data's start cannot check it.

use super::*;
use crate::crypto::{HmacSha1, ZipCrypto};
use crate::inflate64::{Inflater, Variant};
use crate::rar5::unpack::Sink as _;

/// Bytes of the ZipCrypto encryption header before the data.
const ZC_HEADER: u64 = 12;
/// Output decoded per inflater step.
const OUT_CHUNK: usize = 64 << 10;

enum ZipCipher {
    Plain,
    ZipCrypto {
        check: u8,
        /// the keystream, from the stream's start; None until a pass starts
        keys: Option<ZipCrypto>,
        header: Vec<u8>,
    },
    Aes {
        aes: Box<AesKey>,
        mac_key: Vec<u8>,
        /// the authentication code over the ciphertext read in order from the data's start; None when this pass did
        /// not start there (a restore)
        hmac: Option<Box<HmacSha1>>,
    },
}

/// A block boundary: its bit offset in the packed stream, and the output offset there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Checkpoint {
    bit: u64,
    out: u64,
}

pub(super) struct Zip {
    /// None: stored (under ZipCrypto)
    variant: Option<Variant>,
    cipher: ZipCipher,
    /// the packed stream range holding the compressed (or stored) data: after a ZipCrypto header or the WinZip AES
    /// salt and verifier, before the authentication code
    data: Range<u64>,
    inf: Option<Box<Inflater>>,
    /// the current pass is set up (inflater, keystream, lane)
    started: bool,
    /// decrypted data not yet taken by the inflater: `pending[pend_at..]`, the first at stream offset `in_pos`
    pending: Vec<u8>,
    pend_at: usize,
    in_pos: u64,
    /// the output offset decoded up to
    out: u64,
    /// output before this was written before a restore: decoded again, not written
    write_from: u64,
    /// the last block boundary passed with its output written (the restart point of a restore)
    cp: Checkpoint,
    /// a pass that starts before its checkpoint (a restore, or ZipCrypto from the stream's start) drops the data
    /// before this bit offset; None once passed
    skip_to: Option<u64>,
    /// the data is all decoded (the final block ended, or stored data all copied)
    inflated: bool,
    tag: Vec<u8>,
    /// whether the authentication code matched; None before it is read, or when it cannot be checked
    auth: Option<bool>,
    stalled: bool,
    /// the stream offset of the hole the main decode waits at, counted once
    hole_at: Option<u64>,
    outbuf: Vec<u8>,
}

impl Zip {
    pub(super) fn frontier(&self) -> u64 {
        self.out.max(self.write_from)
    }

    pub(super) fn stalled(&self) -> bool {
        self.stalled
    }

    pub(super) fn auth(&self) -> Option<bool> {
        self.auth
    }

    /// Whether this member has an authentication code to check.
    pub(super) fn authenticated(&self) -> bool {
        matches!(self.cipher, ZipCipher::Aes { .. })
    }

    /// The first packed stream offset a restore from this decoder's state reads (in this session, before any
    /// replay from the stream's start), or what the main decode reads next when that is earlier.
    pub(super) fn keep_from(&self, lane_pos: u64) -> u64 {
        lane_pos.min(self.cp.bit / 8)
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&self.cp.bit.to_le_bytes());
        out.extend_from_slice(&self.cp.out.to_le_bytes());
        out.extend_from_slice(&self.frontier().to_le_bytes());
        out.push(match self.auth {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
        out
    }

    pub(super) fn restore(&mut self, blob: &[u8], size: u64) -> Result<(), FeedError> {
        let mut r = Reader(blob);
        if r.u8()? != 1 {
            return Err(FeedError::Snapshot("unknown ZIP layer version"));
        }
        let cp = Checkpoint { bit: r.u64()?, out: r.u64()? };
        let frontier = r.u64()?;
        let auth = match r.u8()? {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(FeedError::Snapshot("bad flag")),
        };
        let bits = self.data.start.saturating_mul(8)..=self.data.end.saturating_mul(8);
        if !r.0.is_empty() || cp.out > frontier || frontier > size || !bits.contains(&cp.bit) {
            return Err(FeedError::Snapshot("out of range"));
        }
        if self.variant.is_none() && cp.bit != (self.data.start + cp.out) * 8 {
            return Err(FeedError::Snapshot("out of range"));
        }
        self.cp = cp;
        self.write_from = frontier;
        self.out = cp.out;
        self.auth = auth;
        self.started = false;
        self.inf = None;
        Ok(())
    }
}

impl FeedDecoder {
    /// A decoder of a ZIP Deflate or Deflate64 member (plain, ZipCrypto or WinZip AES), or a stored ZipCrypto one.
    pub(super) fn new_zip(
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
        begin: Begin,
    ) -> Result<Self, FeedError> {
        if !matches!(begin, Begin::Fresh | Begin::Restore) {
            return Err(FeedError::Unsupported(FeedUnsupported::Solid));
        }
        let member = &map.members[index];
        let variant = match member.method {
            MapMethod::Compressed { id: 8 } => Some(Variant::Deflate),
            MapMethod::Compressed { id: 9 } => Some(Variant::Deflate64),
            MapMethod::Compressed { id } => return Err(FeedError::Unsupported(FeedUnsupported::Compressed { id })),
            MapMethod::Coders => return Err(FeedError::Unsupported(FeedUnsupported::Coders)),
            MapMethod::Stored => None,
        };
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        if !member.complete {
            return Err(FeedError::IncompleteMember);
        }
        let mut next = 0u64;
        for p in &member.pieces {
            if p.packed.start > p.packed.end || p.stream_offset != next {
                return Err(FeedError::Malformed("pieces are not contiguous from stream offset 0"));
            }
            next = next.checked_add(p.packed.end - p.packed.start).ok_or(FeedError::Malformed("piece offsets"))?;
        }
        let geometry = Geometry::new(member);
        let stream_len = geometry.covered();
        if stream_len != member.packed_size {
            return Err(FeedError::IncompleteMember);
        }
        let usage = Usage::new(options.limits.clone());
        let derive = |mapping| {
            derive_keys(member, mapping, options.password.as_deref(), &options.limits, &usage, &options.control)
                .map_err(FeedError::from_extract)
        };
        let (cipher, data) = match (&member.cipher, member.encrypted) {
            (_, false) => (ZipCipher::Plain, 0..stream_len),
            (Some(CipherParams::ZipCrypto { .. }), true) => {
                if stream_len < ZC_HEADER {
                    return Err(FeedError::Malformed("ZipCrypto header size"));
                }
                match derive(OutputMapping::Sequential { skip: ZC_HEADER })?.key {
                    MemberKey::ZipCrypto { check } => {
                        (ZipCipher::ZipCrypto { check, keys: None, header: Vec::new() }, ZC_HEADER..stream_len)
                    }
                    _ => return Err(FeedError::Malformed("cipher parameters do not match the member")),
                }
            }
            (Some(CipherParams::WinZipAes { salt, .. }), true) => {
                let skip = salt.len() as u64 + 2;
                if stream_len < skip + AES_TAG {
                    return Err(FeedError::Malformed("WinZip AES data size"));
                }
                match derive(OutputMapping::Counter { skip })?.key {
                    MemberKey::Ctr { aes, mac_key, .. } => {
                        (ZipCipher::Aes { aes: Box::new(aes), mac_key, hmac: None }, skip..stream_len - AES_TAG)
                    }
                    _ => return Err(FeedError::Malformed("cipher parameters do not match the member")),
                }
            }
            _ => return Err(FeedError::Unsupported(FeedUnsupported::UnmappedCipher)),
        };
        if variant.is_none() && data.end - data.start != size {
            return Err(FeedError::Malformed("a stored member's data is not its size"));
        }
        let aes = matches!(cipher, ZipCipher::Aes { .. });
        let checks = member.checks.filter(|c| c.crc32.is_some());
        let chunk = options.read_chunk.clamp(16, 64 << 20);
        let start = Checkpoint { bit: data.start * 8, out: 0 };
        let mut d = Self {
            size,
            stream_len,
            geometry,
            cipher: StoredCipher::Plain,
            tag: LayerTag::Zip,
            want_crc: checks.and_then(|c| c.crc32),
            hash_key: None,
            keyed: false,
            main: None,
            lost: RangeSet::default(),
            blocked: BTreeMap::new(),
            crc: CrcRuns::default(),
            stats: FeedStats::default(),
            released: RangeSet::default(),
            identity: member_identity(member),
            options,
            buf: vec![0; chunk],
            scratch: Vec::new(),
            run_written: 0,
            failed: false,
            status: FeedStatus::default(),
            index: 0,
            stream_start: 0,
            // the authentication code proves WinZip AES output, once read after it
            unproven: aes,
            suspect: None,
            seeded: None,
            rar5: None,
            lzma2: None,
            rar4: None,
            zip: Some(Box::new(Zip {
                variant,
                cipher,
                data,
                inf: None,
                started: false,
                pending: Vec::new(),
                pend_at: 0,
                in_pos: 0,
                out: 0,
                write_from: 0,
                cp: start,
                skip_to: None,
                inflated: false,
                tag: Vec::new(),
                auth: None,
                stalled: false,
                hole_at: None,
                outbuf: Vec::new(),
            })),
            mac: None,
        };
        d.main = Some(d.packed_lane(0, stream_len));
        d.status = d.make_status(Vec::new(), false);
        Ok(d)
    }

    pub(super) fn run_zip(
        &mut self,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<super::rar5::RunOut, FeedError> {
        let mut z = self.zip.take().expect("ZIP state");
        let result = self.run_zip_with(&mut z, source, sink);
        self.zip = Some(z);
        result
    }

    /// Sets up a pass from the checkpoint: the inflater (its window read back from the sink), the keystream and
    /// where the lane reads from.
    fn start_zip(&mut self, z: &mut Zip, sink: &mut dyn FeedSink, lane: &mut Lane) -> Result<(), FeedError> {
        let cp = z.cp;
        let fresh = cp.bit == z.data.start * 8;
        z.inf = match z.variant {
            None => None,
            Some(variant) => {
                let mut inf = if cp.out == 0 {
                    Inflater::new(variant)
                } else {
                    let window = if variant == Variant::Deflate64 { 64 << 10 } else { 32 << 10 };
                    let history = read_stream(sink, 0, cp.out.saturating_sub(window)..cp.out)?;
                    Inflater::resume(variant, &history, cp.out)
                };
                inf.set_block_stops(true);
                Some(inf)
            }
        };
        let from = match &mut z.cipher {
            ZipCipher::Plain => cp.bit / 8,
            ZipCipher::ZipCrypto { keys, header, .. } => {
                let password = self.options.password.as_deref().unwrap_or_default();
                let control = &self.options.control;
                let k = ZipCrypto::new_cancellable(password, || if control.is_canceled() { Err(()) } else { Ok(()) })
                    .map_err(|()| FeedError::Canceled)?;
                *keys = Some(k);
                header.clear();
                0
            }
            ZipCipher::Aes { mac_key, hmac, .. } => {
                // a pass from a later checkpoint does not read the ciphertext before it again: the code cannot be
                // checked then
                *hmac = fresh.then(|| Box::new(HmacSha1::new(mac_key)));
                cp.bit / 8
            }
        };
        *lane = self.packed_lane(from, self.stream_len);
        z.skip_to = (from * 8 < cp.bit).then_some(cp.bit);
        z.pending.clear();
        z.pend_at = 0;
        z.in_pos = cp.bit.div_ceil(8);
        z.out = cp.out;
        z.inflated = z.variant.is_none() && cp.out == self.size;
        z.tag.clear();
        z.outbuf.resize(OUT_CHUNK, 0);
        z.started = true;
        Ok(())
    }

    fn run_zip_with(
        &mut self,
        z: &mut Zip,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<super::rar5::RunOut, FeedError> {
        let (mut next, mut more, mut gap) = (Vec::new(), false, None);
        z.stalled = false;
        let Some(mut lane) = self.main.take() else { return Ok((next, Vec::new(), more, gap)) };
        if !z.started {
            self.start_zip(z, sink, &mut lane)?;
        }
        let mut buf = std::mem::take(&mut self.buf);
        let result = (|| -> Result<(), FeedError> {
            loop {
                if self.options.control.is_canceled() {
                    return Err(FeedError::Canceled);
                }
                if lane.pos >= lane.end {
                    return self.finish_zip(z);
                }
                if self.options.run_budget.is_some_and(|b| self.run_written >= b) {
                    more = true;
                    self.main = Some(lane.clone());
                    return Ok(());
                }
                let span =
                    self.geometry.locate(lane.pos).ok_or(FeedError::Malformed("stream offset outside the pieces"))?;
                let piece_left = span.stream.end.min(lane.end) - lane.pos;
                let left = piece_left.min(buf.len() as u64) as usize;
                let (volume, packed) = (span.volume, span.packed_start + (lane.pos - span.stream.start));
                let read = source.read_packed(volume, packed, &mut buf[..left]);
                match read {
                    PackedRead::Data(n) => {
                        if n == 0 || n > left {
                            return Err(FeedError::SourceContract("Data count of 0 or past the buffer"));
                        }
                        let at = lane.pos;
                        lane.pos += n as u64;
                        self.stats.packed_read += n as u64;
                        self.zip_bytes(z, at, &mut buf[..n], sink)?;
                        if z.inflated && !z.authenticated() && lane.pos >= z.data.start {
                            // nothing after the data's end is read: no authentication code follows
                            lane.end = lane.pos;
                        }
                    }
                    PackedRead::NotYet { len } | PackedRead::Hole { len } => {
                        let hole = matches!(read, PackedRead::Hole { .. });
                        let len = len.clamp(1, piece_left);
                        if hole {
                            // no restart point inside a ZIP member: the main decode waits at the hole
                            z.stalled = true;
                            if z.hole_at != Some(lane.pos) {
                                z.hole_at = Some(lane.pos);
                                self.stats.holes += 1;
                            }
                        }
                        self.push_needs(&mut next, lane.pos..lane.pos + len, NeedKind::Next);
                        gap = Some(lane.pos + len..lane.end);
                        self.main = Some(lane.clone());
                        return Ok(());
                    }
                }
            }
        })();
        self.buf = buf;
        result?;
        Ok((next, Vec::new(), more, gap))
    }

    /// The main decode read the whole packed stream: the data must have decoded to the member's size, and the
    /// authentication code is checked.
    fn finish_zip(&mut self, z: &mut Zip) -> Result<(), FeedError> {
        let corrupt = |out, what| FeedError::Decode { out, error: crate::Error::Corrupt(what) };
        if !z.inflated {
            return Err(corrupt(z.out, "the deflate stream ends before its final block"));
        }
        if z.out != self.size {
            return Err(corrupt(z.out, "the member decodes to another size"));
        }
        if let ZipCipher::Aes { hmac: Some(hmac), .. } = &z.cipher
            && z.auth.is_none()
        {
            use subtle::ConstantTimeEq;
            let ok = z.tag.len() as u64 == AES_TAG && bool::from(hmac.finish()[..AES_TAG as usize].ct_eq(&z.tag));
            z.auth = Some(ok);
        }
        self.main = None;
        Ok(())
    }

    /// Packed bytes `bytes` read at stream offset `at`, in order: decrypted, then decoded.
    fn zip_bytes(&mut self, z: &mut Zip, at: u64, bytes: &mut [u8], sink: &mut dyn FeedSink) -> Result<(), FeedError> {
        let end = at + bytes.len() as u64;
        // the authentication code after the data
        if end > z.data.end {
            let from = at.max(z.data.end);
            let tag_end = end.min(z.data.end + AES_TAG);
            if from < tag_end && z.tag.len() as u64 == from - z.data.end {
                z.tag.extend_from_slice(&bytes[(from - at) as usize..(tag_end - at) as usize]);
            }
        }
        let data_end = end.min(z.data.end);
        if at >= data_end {
            return Ok(());
        }
        let bytes = &mut bytes[..(data_end - at) as usize];
        // the ZipCrypto header, then the data
        let (at, bytes) = match &mut z.cipher {
            ZipCipher::Plain => (at, bytes),
            ZipCipher::ZipCrypto { check, keys, header } => {
                let keys = keys.as_mut().expect("keystream set up");
                let mut at = at;
                let mut bytes = bytes;
                if at < ZC_HEADER {
                    let take = ((ZC_HEADER - at) as usize).min(bytes.len());
                    header.extend_from_slice(&bytes[..take]);
                    (at, bytes) = (at + take as u64, &mut bytes[take..]);
                    if header.len() as u64 == ZC_HEADER {
                        let mut plain = header.clone();
                        keys.decrypt(&mut plain);
                        if plain[11] != *check {
                            return Err(FeedError::WrongPassword);
                        }
                    }
                }
                keys.decrypt(bytes);
                (at, bytes)
            }
            ZipCipher::Aes { aes, hmac, .. } => {
                if let Some(h) = hmac {
                    h.update(bytes).ok_or(FeedError::Malformed("WinZip AES data size"))?;
                }
                ctr_xor(aes, at - z.data.start, bytes);
                (at, &mut bytes[..])
            }
        };
        if bytes.is_empty() || z.inflated {
            return Ok(());
        }
        // a pass that starts before its checkpoint drops what lies before it
        let mut at = at;
        let mut bytes: &[u8] = bytes;
        if let Some(bit) = z.skip_to {
            let byte = bit / 8;
            let end = at + bytes.len() as u64;
            if end <= byte {
                return Ok(());
            }
            let drop = byte.saturating_sub(at) as usize;
            (at, bytes) = (at + drop as u64, &bytes[drop..]);
            let used = (bit % 8) as u32;
            if used > 0 {
                z.inf.as_mut().expect("a stored member's checkpoints are whole bytes").preload(bytes[0], used);
                (at, bytes) = (at + 1, &bytes[1..]);
            }
            z.skip_to = None;
        }
        if z.pend_at == z.pending.len() {
            z.pending.clear();
            z.pend_at = 0;
            z.in_pos = at;
        }
        debug_assert_eq!(z.in_pos + (z.pending.len() - z.pend_at) as u64, at);
        if z.variant.is_none() {
            // stored: the data is the output
            self.zip_emit(z, bytes, sink)?;
            z.in_pos = at + bytes.len() as u64;
            z.cp = Checkpoint { bit: z.in_pos * 8, out: z.out };
            z.inflated = z.out == self.size;
            return Ok(());
        }
        z.pending.extend_from_slice(bytes);
        self.inflate(z, sink)
    }

    /// Writes decoded output at `z.out` (what lies before `z.write_from` is decoded again, not written).
    fn zip_emit(&mut self, z: &mut Zip, bytes: &[u8], sink: &mut dyn FeedSink) -> Result<(), FeedError> {
        let end = z.out + bytes.len() as u64;
        if end > self.size {
            return Err(FeedError::Decode {
                out: z.out,
                error: crate::Error::Corrupt("the member decodes past its size"),
            });
        }
        let mut out = self.out_sink(sink, z.out, z.write_from..self.size);
        let put = out.put(bytes).map_err(|e| out.fail(e));
        z.out = out.at;
        put
    }

    /// Runs the inflater over the pending data, noting each block boundary passed as the checkpoint.
    fn inflate(&mut self, z: &mut Zip, sink: &mut dyn FeedSink) -> Result<(), FeedError> {
        let mut outbuf = std::mem::take(&mut z.outbuf);
        let result = (|| -> Result<(), FeedError> {
            loop {
                if self.options.control.is_canceled() {
                    return Err(FeedError::Canceled);
                }
                let inf = z.inf.as_mut().expect("inflater set up");
                let blocks = inf.blocks();
                let step = inf.step(&z.pending[z.pend_at..], &mut outbuf).map_err(|e| FeedError::Decode {
                    out: z.out,
                    error: crate::Error::Corrupt(match e {
                        crate::inflate64::Error::BlockType => "deflate: reserved block type",
                        crate::inflate64::Error::StoredLength => "deflate: stored block length check fails",
                        crate::inflate64::Error::Distance => "deflate: distance too far back",
                        _ => "deflate data does not decode",
                    }),
                })?;
                let progressed = step.consumed > 0 || step.produced > 0 || inf.blocks() != blocks;
                let boundary = inf.boundary();
                z.pend_at += step.consumed;
                z.in_pos += step.consumed as u64;
                if step.produced > 0 {
                    self.zip_emit(z, &outbuf[..step.produced], sink)?;
                }
                if let Some(count) = boundary {
                    z.cp = Checkpoint { bit: z.in_pos * 8 - u64::from(count), out: z.out };
                }
                if step.done {
                    z.inflated = true;
                    return Ok(());
                }
                if !progressed {
                    return Ok(());
                }
            }
        })();
        z.outbuf = outbuf;
        // keep the pending data compact
        if z.pend_at == z.pending.len() {
            z.pending.clear();
            z.pend_at = 0;
        } else if z.pend_at >= 1 << 16 {
            z.pending.drain(..z.pend_at);
            z.pend_at = 0;
        }
        result
    }
}
