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
//! The one exception is a later stored block, found by its LEN/NLEN pair, see [`Resync`].
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
    /// the last packed byte the main inflater consumed
    last_byte: u8,
    /// a restart after the hole the main decode waits at (see [`Resync`])
    rs: Option<Box<Resync>>,
}

/// The restart a hole may get: the next stored block after it, found by its LEN/NLEN pair.
///
/// A stored block's header is BFINAL, BTYPE 00, padding to a byte, LEN and NLEN (its complement); nothing else in a
/// Deflate stream has a shape a scan can find. A pair is a candidate when it checks out and the byte before it can
/// hold a stored header (its top bits are padding, zero in every encoder this knows). The search is then:
///
/// 1. **Count.** Decode the candidate to the member's data end with a window of zeros, throwing the output away: a
///    false candidate dies on the Deflate syntax, or does not end exactly at the data's end. A match's length does
///    not depend on the window, so the output counted is exact, and the output offset of the restart is the
///    member's size less that count. A restart that would begin before the output already written is refused.
/// 2. **Ahead.** Decode and write from the stored block, the output marked `unproven`. A later block that is not
///    stored decodes only once its window (the 32 KiB or 64 KiB of output before it) is the output since the restart
///    or held by the sink; the lost output before the restart is not.
/// 3. **Resolve.** When the hole's bytes come the main decode goes on, output limited to the restart's offset. If it
///    reaches a block boundary at exactly that offset whose stored header ends at the candidate's byte, the
///    candidate is confirmed (the main decode decodes what the ahead decode wrote again, without writing it, then
///    goes on). Anything else refutes it: what the ahead decode wrote is reported lost again and the main decode
///    writes it as a repair (the sink gets those bytes a second time; this is the one case where it does).
struct Resync {
    /// the first byte of the hole
    hole: u64,
    /// the output the main decode had written when it met the hole
    f0: u64,
    /// where the candidate search goes on if the current candidate fails
    resume: u64,
    phase: Phase,
    /// the restart is taken (the lost range recorded, output written) and awaits its resolution
    active: bool,
}

enum Phase {
    /// find the end of the lost bytes (the first byte after them not lost)
    Edge {
        end: u64,
    },
    Scan(Scan),
    Count(Box<Count>),
    Ahead(Box<Ahead>),
    /// no candidate decodes to the member's end
    Exhausted,
}

struct Scan {
    /// plaintext from stream offset `at`
    buf: Vec<u8>,
    at: u64,
    /// the next candidate: the byte offset of its LEN
    next: u64,
}

struct Count {
    /// the candidate's LEN offset
    p: u64,
    inf: Box<Inflater>,
    /// the next stream byte to read
    at: u64,
    primed: bool,
    /// output counted from the stored block on
    count: u64,
    /// the stream ends with the first block (BFINAL)
    last: bool,
}

struct Ahead {
    p: u64,
    restart_out: u64,
    inf: Box<Inflater>,
    primed: bool,
    pending: Vec<u8>,
    pend_at: usize,
    /// the next stream byte to read
    at: u64,
    /// the output offset written up to
    out: u64,
    /// the last byte the inflater consumed (the start of the next block header may lie in it)
    last_byte: u8,
    /// the window before the next block is complete: held by the sink, or produced since the restart
    window_ok: bool,
    done: bool,
    /// the CRC runs of what it wrote, joined to the member's once confirmed
    crc: CrcRuns,
}

impl Zip {
    /// The output written in order by the main decode, and past a lost range by a restart.
    pub(super) fn frontier(&self) -> u64 {
        let ahead = match self.rs.as_deref() {
            Some(Resync { phase: Phase::Ahead(a), active: true, .. }) => a.out,
            _ => 0,
        };
        self.out.max(self.write_from).max(ahead)
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
        // a restart past a hole is not saved: the restored decoder writes what it wrote again
        out.extend_from_slice(&self.out.max(self.write_from).to_le_bytes());
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
        self.rs = None;
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
            held_prefix: 0,
            open_from: 0,
            crc_floor: 0,
            open_iv: None,
            keys: None,
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
                last_byte: 0,
                rs: None,
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
                        // the hole's bytes are here: a restart not taken is not needed
                        if z.rs.as_ref().is_some_and(|r| !r.active) {
                            z.rs = None;
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
                        let mut ahead = Vec::new();
                        let mut gap_from = lane.pos + len;
                        let mut active = false;
                        if hole {
                            if z.hole_at != Some(lane.pos) {
                                z.hole_at = Some(lane.pos);
                                self.stats.holes += 1;
                            }
                            // a stored block after the hole may restart the decode; otherwise it waits here
                            if z.resync_ok() {
                                let run = self.resync(z, source, sink, lane.pos, &mut ahead, &mut more)?;
                                active = run.active;
                                gap_from = run.gap_from.unwrap_or(gap_from);
                            }
                            z.stalled = !active;
                        }
                        let kind = if active { NeedKind::Repair } else { NeedKind::Next };
                        self.push_needs(&mut next, lane.pos..lane.pos + len, kind);
                        next.extend(ahead);
                        gap = Some(gap_from.min(lane.end)..lane.end);
                        if more {
                            self.main = Some(lane.clone());
                            return Ok(());
                        }
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
        if z.rs.as_ref().is_some_and(|r| r.active) {
            self.rs_refute(z);
        }
        z.rs = None;
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
        let from = z.out;
        let mut out = self.out_sink(sink, z.out, z.write_from..self.size);
        let put = out.put(bytes).map_err(|e| out.fail(e));
        z.out = out.at;
        // what a repair writes is no longer lost
        let (s, e) = (from.max(z.write_from), z.out);
        if s < e && !self.lost.is_empty() {
            self.lost.remove(s..e);
        }
        put
    }

    /// Runs the inflater over the pending data, noting each block boundary passed as the checkpoint.
    fn inflate(&mut self, z: &mut Zip, sink: &mut dyn FeedSink) -> Result<(), FeedError> {
        let mut outbuf = std::mem::take(&mut z.outbuf);
        let result = (|| -> Result<(), FeedError> {
            self.rs_check(z);
            loop {
                if self.options.control.is_canceled() {
                    return Err(FeedError::Canceled);
                }
                let inf = z.inf.as_mut().expect("inflater set up");
                let blocks = inf.blocks();
                // while a restart awaits its resolution the output stops at its offset
                let room = match z.rs.as_deref() {
                    Some(r) if r.active => (restart_of(r) - z.out).min(outbuf.len() as u64) as usize,
                    _ => outbuf.len(),
                };
                let step = inf.step(&z.pending[z.pend_at..], &mut outbuf[..room]).map_err(|e| FeedError::Decode {
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
                if step.consumed > 0 {
                    z.last_byte = z.pending[z.pend_at + step.consumed - 1];
                }
                z.pend_at += step.consumed;
                z.in_pos += step.consumed as u64;
                if step.produced > 0 {
                    self.zip_emit(z, &outbuf[..step.produced], sink)?;
                }
                if let Some(count) = boundary {
                    z.cp = Checkpoint { bit: z.in_pos * 8 - u64::from(count), out: z.out };
                }
                self.rs_check(z);
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

// ---- Restarts at stored blocks after a hole ----

/// Packed bytes the candidate search reads (scan and count) in one run before it hands control back.
const SEARCH_BUDGET: u64 = 32 << 20;

/// A run of the search: whether a restart is taken, the stream offset the bytes it waits for end at.
struct RsRun {
    active: bool,
    gap_from: Option<u64>,
}

/// What reading packed bytes for the search gave.
enum Got {
    Data(usize),
    Blocked { at: u64, len: u64 },
}

fn restart_of(r: &Resync) -> u64 {
    match &r.phase {
        Phase::Ahead(a) => a.restart_out,
        _ => 0,
    }
}

impl Zip {
    /// Whether a hole may be searched for a restart: a Deflate or Deflate64 member whose bytes decrypt on their own.
    fn resync_ok(&self) -> bool {
        self.variant.is_some()
            && matches!(self.cipher, ZipCipher::Plain | ZipCipher::Aes { .. })
            && self.started
            && self.out >= self.write_from
            && !self.inflated
    }

    fn window(&self) -> u64 {
        if self.variant == Some(Variant::Deflate64) { 64 << 10 } else { 32 << 10 }
    }

    /// Decrypts the packed data bytes `bytes` read at stream offset `at` (WinZip AES counter mode; plain is as is).
    fn decrypt(&self, at: u64, bytes: &mut [u8]) {
        if let ZipCipher::Aes { aes, .. } = &self.cipher {
            ctr_xor(aes, at - self.data.start, bytes);
        }
    }
}

/// Whether a stored block's header may end right before LEN: the byte before it holds the header's last bits and
/// the padding, which is zero.
fn plausible(prev: u8, len: u16, nlen: u16) -> bool {
    len ^ nlen == 0xFFFF && prev <= 0x3F
}

impl FeedDecoder {
    /// Reads packed bytes at stream offset `pos` (before `end`) into `out`: up to `max`, within one piece.
    fn rs_read(
        &mut self,
        source: &mut dyn PackedSource,
        pos: u64,
        end: u64,
        out: &mut Vec<u8>,
        max: usize,
    ) -> Result<Got, FeedError> {
        let span = self.geometry.locate(pos).ok_or(FeedError::Malformed("stream offset outside the pieces"))?;
        if pos >= end {
            return Err(FeedError::Malformed("a search read past the data"));
        }
        let piece_left = span.stream.end.min(end) - pos;
        let left = piece_left.min(max as u64) as usize;
        let old = out.len();
        out.resize(old + left, 0);
        match source.read_packed(span.volume, span.packed_start + (pos - span.stream.start), &mut out[old..]) {
            PackedRead::Data(n) => {
                if n == 0 || n > left {
                    return Err(FeedError::SourceContract("Data count of 0 or past the buffer"));
                }
                out.truncate(old + n);
                self.stats.packed_read += n as u64;
                Ok(Got::Data(n))
            }
            PackedRead::NotYet { len } | PackedRead::Hole { len } => {
                out.truncate(old);
                Ok(Got::Blocked { at: pos, len: len.clamp(1, piece_left) })
            }
        }
    }

    /// Advances the restart search or the decode from a restart, at a hole starting at `at`.
    fn resync(
        &mut self,
        z: &mut Zip,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        at: u64,
        needs: &mut Vec<NeedBytes>,
        more: &mut bool,
    ) -> Result<RsRun, FeedError> {
        let mut rs = match z.rs.take() {
            Some(rs) if rs.active || rs.hole == at => rs,
            _ => Box::new(Resync { hole: at, f0: z.out, resume: 0, phase: Phase::Edge { end: at }, active: false }),
        };
        let result = self.rs_drive(z, &mut rs, source, sink, needs, more);
        let run = RsRun { active: rs.active, gap_from: result.as_ref().ok().copied().flatten() };
        z.rs = Some(rs);
        result.map(|_| run)
    }

    /// Drives the search as far as the bytes held allow; Some(end of the bytes it waits for) when it waits.
    fn rs_drive(
        &mut self,
        z: &mut Zip,
        rs: &mut Resync,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        needs: &mut Vec<NeedBytes>,
        more: &mut bool,
    ) -> Result<Option<u64>, FeedError> {
        let mut scanned = 0u64;
        let chunk = self.options.read_chunk.clamp(4096, 1 << 20);
        let mut outbuf = vec![0u8; OUT_CHUNK];
        let data_end = z.data.end;
        let window = z.window();
        loop {
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            if scanned >= SEARCH_BUDGET || self.options.run_budget.is_some_and(|b| self.run_written >= b) {
                *more = true;
                return Ok(None);
            }
            match &mut rs.phase {
                Phase::Exhausted => return Ok(None),
                Phase::Edge { end } => {
                    if *end >= data_end {
                        rs.phase = Phase::Exhausted;
                        continue;
                    }
                    let mut one = Vec::with_capacity(1);
                    match self.rs_read(source, *end, data_end, &mut one, 1)? {
                        Got::Data(_) => {
                            let at = *end;
                            rs.resume = at + 1;
                            rs.phase = Phase::Scan(Scan { buf: Vec::new(), at, next: at + 1 });
                        }
                        Got::Blocked { at, len } => {
                            // lost bytes go on, bytes not arrived yet are waited for
                            if source_is_lost(source, self, at) {
                                *end += len;
                                if *end >= data_end {
                                    rs.phase = Phase::Exhausted;
                                }
                            } else {
                                self.push_needs(needs, at..at + len, NeedKind::Next);
                                return Ok(Some(at + len));
                            }
                        }
                    }
                }
                Phase::Scan(s) => {
                    let mut found = None;
                    while s.next + 4 <= s.at + s.buf.len() as u64 {
                        let i = (s.next - s.at) as usize;
                        let len = u16::from_le_bytes([s.buf[i], s.buf[i + 1]]);
                        let nlen = u16::from_le_bytes([s.buf[i + 2], s.buf[i + 3]]);
                        if plausible(s.buf[i - 1], len, nlen) && s.next + 4 + u64::from(len) <= data_end {
                            found = Some((s.next, len));
                            break;
                        }
                        s.next += 1;
                    }
                    if let Some((p, len)) = found {
                        rs.resume = p + 1;
                        let mut inf = Inflater::resume(z.variant.expect("deflate"), &vec![0; window as usize], window);
                        inf.set_block_stops(false);
                        let last = p + 4 + u64::from(len) == data_end;
                        rs.phase = Phase::Count(Box::new(Count { p, inf, at: p, primed: false, count: 0, last }));
                        continue;
                    }
                    // what is before the next candidate's predecessor is not needed again
                    let keep_from = s.next.saturating_sub(1);
                    let drop = (keep_from - s.at).min(s.buf.len() as u64) as usize;
                    s.buf.drain(..drop);
                    s.at += drop as u64;
                    if s.next + 4 > data_end {
                        rs.phase = Phase::Exhausted;
                        continue;
                    }
                    let from = s.at + s.buf.len() as u64;
                    let old = s.buf.len();
                    match self.rs_read(source, from, data_end, &mut s.buf, chunk)? {
                        Got::Data(n) => {
                            scanned += n as u64;
                            z.decrypt(from, &mut s.buf[old..]);
                        }
                        Got::Blocked { at, len } => {
                            self.push_needs(needs, at..at + len, NeedKind::Next);
                            return Ok(Some(at + len));
                        }
                    }
                }
                Phase::Count(c) => {
                    let mut buf = Vec::new();
                    let got = self.rs_read(source, c.at, data_end, &mut buf, chunk)?;
                    let n = match got {
                        Got::Data(n) => n,
                        Got::Blocked { at, len } => {
                            self.push_needs(needs, at..at + len, NeedKind::Next);
                            return Ok(Some(at + len));
                        }
                    };
                    scanned += n as u64;
                    z.decrypt(c.at, &mut buf);
                    c.at += n as u64;
                    let verdict = count_chunk(c, &buf, &mut outbuf, self.size - rs.f0, c.at == data_end);
                    match verdict {
                        Verdict::More => {}
                        Verdict::Reject => {
                            let from = rs.resume;
                            rs.phase = Phase::Scan(Scan { buf: Vec::new(), at: from - 1, next: from });
                        }
                        Verdict::Accept => {
                            let (p, restart_out) = (c.p, self.size - c.count);
                            let variant = z.variant.expect("deflate");
                            let want = restart_out.min(window);
                            let held = read_stream(sink, 0, restart_out - want..restart_out).ok();
                            let window_ok = held.is_some() || want == 0;
                            let history = held.unwrap_or_else(|| vec![0; want as usize]);
                            let mut inf = Inflater::resume(variant, &history, restart_out);
                            inf.set_block_stops(true);
                            let first = if c.last { 1u8 } else { 0 };
                            rs.phase = Phase::Ahead(Box::new(Ahead {
                                p,
                                restart_out,
                                inf,
                                primed: false,
                                pending: vec![first],
                                pend_at: 0,
                                at: p,
                                out: restart_out,
                                last_byte: first,
                                window_ok,
                                done: false,
                                crc: CrcRuns::default(),
                            }));
                            if rs.f0 < restart_out {
                                self.lost.insert(rs.f0..restart_out);
                            }
                            rs.active = true;
                            self.unproven = true;
                        }
                    }
                }
                Phase::Ahead(a) => {
                    if a.done {
                        return Ok(None);
                    }
                    match self.ahead_run(z, a, source, sink, &mut outbuf, chunk)? {
                        AStop::Done | AStop::Paused => return Ok(None),
                        AStop::Budget => {
                            *more = true;
                            return Ok(None);
                        }
                        AStop::Blocked { at, len } => {
                            self.push_needs(needs, at..at + len, NeedKind::Next);
                            return Ok(Some(at + len));
                        }
                    }
                }
            }
        }
    }

    /// Decodes and writes from the stored block of a taken restart as far as the bytes held and the windows allow.
    fn ahead_run(
        &mut self,
        z: &Zip,
        a: &mut Ahead,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        outbuf: &mut [u8],
        chunk: usize,
    ) -> Result<AStop, FeedError> {
        let window = z.window();
        loop {
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            if self.options.run_budget.is_some_and(|b| self.run_written >= b) {
                return Ok(AStop::Budget);
            }
            // decode what is pending
            loop {
                if let Some(count) = a.inf.boundary()
                    && !a.window_ok
                {
                    // a block that is not stored needs the window before the restart
                    match peek_stored(count, a.last_byte, a.pending.get(a.pend_at).copied()) {
                        Some(true) => {}
                        Some(false) => return Ok(AStop::Paused),
                        None => break,
                    }
                }
                let blocks = a.inf.blocks();
                let step = a.inf.step(&a.pending[a.pend_at..], outbuf).map_err(|_| FeedError::Decode {
                    out: a.out,
                    error: crate::Error::Corrupt("deflate data does not decode"),
                })?;
                let progressed = step.consumed > 0 || step.produced > 0 || a.inf.blocks() != blocks;
                if step.consumed > 0 {
                    a.last_byte = a.pending[a.pend_at + step.consumed - 1];
                    a.primed = true;
                }
                a.pend_at += step.consumed;
                if step.produced > 0 {
                    self.ahead_emit(a, &outbuf[..step.produced], sink)?;
                    if a.out - a.restart_out >= window {
                        a.window_ok = true;
                    }
                }
                if step.done {
                    a.done = true;
                    return Ok(AStop::Done);
                }
                if !progressed {
                    break;
                }
            }
            if a.pend_at == a.pending.len() {
                a.pending.clear();
                a.pend_at = 0;
            }
            if a.at >= z.data.end {
                // the count passed this stream to its end: nothing more to read
                return Ok(AStop::Done);
            }
            let old = a.pending.len();
            match self.rs_read(source, a.at, z.data.end, &mut a.pending, chunk)? {
                Got::Data(n) => {
                    z.decrypt(a.at, &mut a.pending[old..]);
                    a.at += n as u64;
                }
                Got::Blocked { at, len } => return Ok(AStop::Blocked { at, len }),
            }
        }
    }

    /// Writes ahead output at `a.out`, its CRC kept apart from the member's until the restart is confirmed.
    fn ahead_emit(&mut self, a: &mut Ahead, bytes: &[u8], sink: &mut dyn FeedSink) -> Result<(), FeedError> {
        if a.out + bytes.len() as u64 > self.size {
            return Err(FeedError::Decode {
                out: a.out,
                error: crate::Error::Corrupt("the member decodes past its size"),
            });
        }
        std::mem::swap(&mut self.crc, &mut a.crc);
        let mut out = self.out_sink(sink, a.out, a.restart_out..self.size);
        let put = out.put(bytes).map_err(|e| out.fail(e));
        a.out = out.at;
        std::mem::swap(&mut self.crc, &mut a.crc);
        put
    }

    /// The main decode, held at the restart's output offset, resolves it where it stands: confirmed at a block
    /// boundary whose stored header ends at the candidate's byte, refuted at anything else. A boundary before the
    /// candidate (an empty block) is passed.
    fn rs_check(&mut self, z: &mut Zip) {
        let Some(rs) = z.rs.as_deref().filter(|r| r.active) else { return };
        let Phase::Ahead(a) = &rs.phase else { return };
        if z.out != a.restart_out {
            return;
        }
        let Some(inf) = z.inf.as_ref() else { return };
        if inf.unflushed() > 0 {
            self.rs_refute(z);
            return;
        }
        if let Some(count) = inf.boundary() {
            let q = (z.in_pos * 8 - u64::from(count) + 3).div_ceil(8);
            if q == a.p {
                self.rs_confirm(z);
            } else if q > a.p {
                self.rs_refute(z);
            }
        }
    }

    fn rs_confirm(&mut self, z: &mut Zip) {
        let Some(rs) = z.rs.take() else { return };
        if let Phase::Ahead(a) = rs.phase {
            for (&s, &(e, crc)) in &a.crc.runs {
                self.crc.add_run(s, e, crc);
            }
            // the main decode decodes what the restart wrote again, without writing it
            z.write_from = z.write_from.max(a.out);
        }
    }

    fn rs_refute(&mut self, z: &mut Zip) {
        let Some(rs) = z.rs.take() else { return };
        if let Phase::Ahead(a) = rs.phase
            && a.out > a.restart_out
        {
            self.lost.insert(a.restart_out..a.out);
        }
    }
}

enum AStop {
    Done,
    /// the next block needs a window that is not there yet
    Paused,
    Budget,
    Blocked {
        at: u64,
        len: u64,
    },
}

enum Verdict {
    More,
    Reject,
    Accept,
}

/// Whether the next block is stored, from the header bits: `count` unused bits of `last`, then `next`.
fn peek_stored(count: u32, last: u8, next: Option<u8>) -> Option<bool> {
    let (mut v, mut n) = if count > 0 { (u32::from(last >> (8 - count)), count) } else { (0, 0) };
    if n < 3 {
        v |= u32::from(next?) << n;
        n += 8;
    }
    let _ = n;
    Some((v >> 1) & 3 == 0)
}

/// Feeds `bytes` of a candidate's stream to its counting decode.
fn count_chunk(c: &mut Count, bytes: &[u8], outbuf: &mut [u8], limit: u64, at_end: bool) -> Verdict {
    if !c.primed {
        c.primed = true;
        // the stored block's header bits, as the byte before LEN holds them
        let head = [u8::from(c.last)];
        if c.inf.step(&head, outbuf).is_err() {
            return Verdict::Reject;
        }
    }
    let mut off = 0;
    loop {
        match c.inf.step(&bytes[off..], outbuf) {
            Err(_) => return Verdict::Reject,
            Ok(step) => {
                off += step.consumed;
                c.count += step.produced as u64;
                if c.count > limit {
                    return Verdict::Reject;
                }
                if step.done {
                    // it must end with the data's last byte
                    return if at_end && off == bytes.len() { Verdict::Accept } else { Verdict::Reject };
                }
                if step.consumed == 0 && step.produced == 0 {
                    break;
                }
            }
        }
    }
    if at_end { Verdict::Reject } else { Verdict::More }
}

/// Whether the source reports the bytes at `at` as lost (rather than not arrived).
fn source_is_lost(source: &mut dyn PackedSource, d: &FeedDecoder, at: u64) -> bool {
    let Some(span) = d.geometry.locate(at) else { return false };
    let mut one = [0u8; 1];
    matches!(
        source.read_packed(span.volume, span.packed_start + (at - span.stream.start), &mut one),
        PackedRead::Hole { .. }
    )
}
