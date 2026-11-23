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

//! The feed decoder's compressed RAR 5.0 layer: the main decode keeps a checkpoint at the last block boundary it
//! passed; a hole either waits (no plaintext past it) or is skipped with [`resync_near`] over held plaintext, and
//! its repair decodes from the checkpoint before it to the restart, never from the member's start.

use super::*;
use crate::rar5::unpack::{
    CHECKPOINT_LENS, NearOptions, SeenFilterRec, Sink, UnpackCheckpoint, Unpacker, Window, resync_near, window_for,
};

/// The most held output read past a hole to skip it.
const DONOR_MAX: u64 = 32 << 20;
/// Less held output past a hole than this (short of the member's end) does not try a skip.
const DONOR_MIN: u64 = 64 << 10;
/// The most packed bytes after a hole read to find the restart.
const AFTER_MAX: u64 = 8 << 20;
/// The work one restart search of a skip may spend (`NearOptions::work`; 2^30 is about a second), so a skip costs
/// the same however loaded the machine is.
const SKIP_WORK: u64 = 1 << 30;

/// A restart point: the decoder state between two blocks and the stream offset of the next block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cp {
    packed: u64,
    state: UnpackCheckpoint,
}

impl Cp {
    fn start() -> Self {
        Cp {
            packed: 0,
            state: UnpackCheckpoint { sp: 0, history: [0; 4], last_len: 0, lens: None, filters: Vec::new() },
        }
    }
}

/// A skipped hole: decoding from `from` to stream offset `until_packed` writes the lost output `lost`, which ends at
/// `until_out`, where the main decode restarted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Repair {
    from: Cp,
    until_packed: u64,
    until_out: u64,
    lost: Range<u64>,
    /// the stream offset the last attempt stopped at, missing
    blocked: Option<u64>,
}

pub(super) struct Rar5 {
    window: Window,
    /// the main decoder; None until it is restored from `base` (after a snapshot, or at the start)
    dec: Option<Box<Unpacker>>,
    /// the main decode's last checkpoint
    base: Cp,
    /// the main decode's output offset, and the stream offset of the bytes it was fed
    out: u64,
    fed: u64,
    /// output before this was written before a restore: decoded again, not written
    write_from: u64,
    repairs: Vec<Repair>,
    stalled: bool,
    /// a skip that failed: the hole's end, the held output and the packed bytes after the hole it had
    skip_failed: Option<(u64, usize, usize)>,
    /// unpacked / packed, for estimates
    ratio: f64,
}

/// An [`Sink`] writing the part of the decoder's output inside `write` to the feed sink.
struct OutSink<'a> {
    sink: &'a mut dyn FeedSink,
    at: u64,
    write: Range<u64>,
    crc: &'a mut CrcRuns,
    stats: &'a mut FeedStats,
    run_written: &'a mut u64,
    io: Option<io::Error>,
}

impl Sink for OutSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> crate::Result<()> {
        let start = self.at;
        let end = start + bytes.len() as u64;
        self.at = end;
        let (s, e) = (start.max(self.write.start), end.min(self.write.end));
        let written = if s < e {
            let b = &bytes[(s - start) as usize..(e - start) as usize];
            if let Err(err) = self.sink.write_at(s, b) {
                self.io = Some(err);
                return Err(crate::Error::Corrupt("output sink failed"));
            }
            self.crc.add(s, b);
            *self.run_written += e - s;
            e - s
        } else {
            0
        };
        self.stats.written += written;
        self.stats.redecoded += bytes.len() as u64 - written;
        Ok(())
    }
}

impl OutSink<'_> {
    fn fail(&mut self, error: crate::Error) -> FeedError {
        match self.io.take() {
            Some(error) => FeedError::Write { out: self.at, error },
            None => FeedError::Decode { out: self.at, error },
        }
    }
}

/// Reads held output `range` from the sink, all of it or an error naming it.
fn read_back(sink: &mut dyn FeedSink, range: Range<u64>) -> Result<Vec<u8>, FeedError> {
    let len = usize::try_from(range.end - range.start).map_err(|_| FeedError::HeldOutput { range: range.clone() })?;
    let mut buf = vec![0; len];
    let mut got = 0;
    while got < len {
        let n = sink
            .read_held(range.start + got as u64, &mut buf[got..])
            .map_err(|_| FeedError::HeldOutput { range: range.clone() })?;
        if n == 0 || n > len - got {
            return Err(FeedError::HeldOutput { range });
        }
        got += n;
    }
    Ok(buf)
}

/// Reads up to `max` bytes of held output from `at`, stopping where the sink holds no more.
fn read_some(sink: &mut dyn FeedSink, at: u64, max: u64) -> Vec<u8> {
    let mut buf = vec![0; max as usize];
    let mut got = 0;
    while got < buf.len() {
        match sink.read_held(at + got as u64, &mut buf[got..]) {
            Ok(n) if n > 0 && n <= buf.len() - got => got += n,
            _ => break,
        }
    }
    buf.truncate(got);
    buf
}

impl Rar5 {
    pub(super) fn frontier(&self) -> u64 {
        self.out.max(self.write_from)
    }

    pub(super) fn stalled(&self) -> bool {
        self.stalled
    }

    /// The stream ranges a restore of the main decode or a repair may read again: from the main checkpoint on, and
    /// each repair's from its checkpoint to its restart.
    pub(super) fn needed(&self, d: &FeedDecoder) -> Vec<Range<u64>> {
        let mut out = Vec::new();
        if d.main.is_some() {
            out.push(d.packed_lane(self.base.packed, d.stream_len).pos..d.stream_len);
        }
        for r in &self.repairs {
            let lane = d.packed_lane(r.from.packed, r.until_packed);
            out.push(lane.pos..lane.end);
        }
        out
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_cp(&mut out, &self.base);
        out.extend_from_slice(&self.frontier().to_le_bytes());
        out.extend_from_slice(&(self.repairs.len() as u64).to_le_bytes());
        for r in &self.repairs {
            put_cp(&mut out, &r.from);
            for v in [r.until_packed, r.until_out, r.lost.start, r.lost.end] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        out
    }

    pub(super) fn restore(&mut self, blob: &[u8], size: u64, stream_len: u64) -> Result<(), FeedError> {
        let mut r = Reader(blob);
        let bad = || FeedError::Snapshot("out of range");
        let base = get_cp(&mut r)?;
        let frontier = r.u64()?;
        if base.packed > stream_len || base.state.sp > frontier || frontier > size {
            return Err(bad());
        }
        let n = r.count(8 * 4 + 8 * 7 + 4)?;
        let mut repairs = Vec::with_capacity(n);
        for _ in 0..n {
            let from = get_cp(&mut r)?;
            let (until_packed, until_out, s, e) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?);
            if from.packed > until_packed || until_packed > stream_len || from.state.sp > s || s > e || e != until_out {
                return Err(bad());
            }
            repairs.push(Repair { from, until_packed, until_out, lost: s..e, blocked: None });
        }
        if !r.0.is_empty() {
            return Err(FeedError::Snapshot("trailing bytes"));
        }
        self.dec = None;
        self.base = base;
        self.out = frontier;
        self.fed = self.base.packed;
        self.write_from = frontier;
        self.repairs = repairs;
        Ok(())
    }
}

fn put_cp(out: &mut Vec<u8>, cp: &Cp) {
    let s = &cp.state;
    out.extend_from_slice(&cp.packed.to_le_bytes());
    out.extend_from_slice(&s.sp.to_le_bytes());
    for h in s.history {
        out.extend_from_slice(&h.to_le_bytes());
    }
    out.extend_from_slice(&s.last_len.to_le_bytes());
    match &s.lens {
        None => out.push(0),
        Some(lens) => {
            out.push(1);
            out.extend_from_slice(&lens[..]);
        }
    }
    out.extend_from_slice(&(s.filters.len() as u64).to_le_bytes());
    for f in &s.filters {
        out.extend_from_slice(&f.start.to_le_bytes());
        out.extend_from_slice(&f.len.to_le_bytes());
        out.push(f.code());
    }
}

fn get_cp(r: &mut Reader<'_>) -> Result<Cp, FeedError> {
    let packed = r.u64()?;
    let sp = r.u64()?;
    let history = [r.u64()?, r.u64()?, r.u64()?, r.u64()?];
    let last_len = r.u32()?;
    let lens = match r.u8()? {
        0 => None,
        1 => Some(Box::new(r.take(CHECKPOINT_LENS)?.try_into().expect("table lengths"))),
        _ => return Err(FeedError::Snapshot("bad flag")),
    };
    let n = r.count(17)?;
    let mut filters = Vec::with_capacity(n);
    for _ in 0..n {
        let (start, len, code) = (r.u64()?, r.u64()?, r.u8()?);
        filters.push(SeenFilterRec::from_code(start, len, code).ok_or(FeedError::Snapshot("bad filter"))?);
    }
    Ok(Cp { packed, state: UnpackCheckpoint { sp, history, last_len, lens, filters } })
}

/// What one run of the compressed layer found: needs for the main decode and for repairs, whether the budget
/// stopped it, and the stream range after the main decode's gap (for lookahead needs).
type RunOut = (Vec<NeedBytes>, Vec<NeedBytes>, bool, Option<Range<u64>>);

impl FeedDecoder {
    /// A decoder of a compressed RAR 5.0 member.
    pub(super) fn new_rar5(member: &MapMember, options: FeedOptions) -> Result<Self, FeedError> {
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        if member.solid {
            return Err(FeedError::Unsupported(FeedUnsupported::Solid));
        }
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
        let dictionary = member.dictionary.ok_or(FeedError::Malformed("RAR 5.0 member without a dictionary size"))?;
        let window = window_for(dictionary, Some(size), false).map_err(|error| FeedError::Decode { out: 0, error })?;
        if window.size > options.max_window {
            return Err(FeedError::Unsupported(FeedUnsupported::Window { size: window.size }));
        }
        let usage = Usage::new(options.limits.clone());
        let mut hash_key = None;
        let cipher = if member.encrypted {
            if !stream_len.is_multiple_of(16) {
                return Err(FeedError::Malformed("an encrypted packed stream is not whole blocks"));
            }
            let keys = derive_keys(
                member,
                OutputMapping::CbcBlocks,
                options.password.as_deref(),
                &options.limits,
                &usage,
                &options.control,
            )
            .map_err(FeedError::from_extract)?;
            hash_key = keys.hash_key;
            match keys.key {
                MemberKey::Cbc { aes, iv } => StoredCipher::Cbc { aes, iv },
                _ => return Err(FeedError::Malformed("cipher parameters do not match the member")),
            }
        } else {
            StoredCipher::Plain
        };
        let checks = member.checks.filter(|c| c.crc32.is_some());
        let chunk = options.read_chunk.clamp(16, 64 << 20);
        let ratio = if stream_len > 0 { size as f64 / stream_len as f64 } else { 1.0 };
        let mut d = Self {
            size,
            stream_len,
            geometry,
            cipher,
            tag: LayerTag::Rar5,
            want_crc: checks.and_then(|c| c.crc32),
            hash_key,
            keyed: checks.is_some_and(|c| c.keyed),
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
            rar5: Some(Box::new(Rar5 {
                window,
                dec: None,
                base: Cp::start(),
                out: 0,
                fed: 0,
                write_from: 0,
                repairs: Vec::new(),
                stalled: false,
                skip_failed: None,
                ratio,
            })),
        };
        if size > 0 {
            d.main = Some(d.packed_lane(0, stream_len));
        }
        d.status = d.make_status(Vec::new(), false);
        Ok(d)
    }

    /// A lane reading the packed stream from `from` (decrypted bytes before it are dropped by the feed) to `end`.
    pub(super) fn packed_lane(&self, from: u64, end: u64) -> Lane {
        match self.cipher {
            StoredCipher::Cbc { iv, .. } => {
                let block = from & !15;
                let end = end.checked_next_multiple_of(16).unwrap_or(u64::MAX).min(self.stream_len);
                if block == 0 {
                    Lane { pos: 0, end, next: 0, iv: Some(iv), rem: Vec::new() }
                } else {
                    Lane { pos: block - 16, end, next: block, iv: None, rem: Vec::new() }
                }
            }
            _ => Lane { pos: from, end, next: from, iv: None, rem: Vec::new() },
        }
    }

    /// A decoder restarted at `cp`, its window read back from the sink.
    fn restore_dec(&self, window: Window, cp: &Cp, sink: &mut dyn FeedSink) -> Result<Box<Unpacker>, FeedError> {
        let sp = cp.state.sp;
        let from = cp.state.filters.iter().map(|f| f.start).fold(sp.saturating_sub(window.reach), u64::min);
        let known = if sp > from { read_back(sink, from..sp)? } else { Vec::new() };
        let mut dec = Unpacker::from_checkpoint(window, &cp.state, Some(self.size), from, &known)
            .map_err(|error| FeedError::Decode { out: sp, error })?;
        dec.set_threads(0, u64::MAX);
        Ok(Box::new(dec))
    }

    pub(super) fn run_rar5(
        &mut self,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<RunOut, FeedError> {
        let mut r = self.rar5.take().expect("RAR 5.0 state");
        let result = self.run_rar5_with(&mut r, source, sink);
        self.rar5 = Some(r);
        result
    }

    fn run_rar5_with(
        &mut self,
        r: &mut Rar5,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<RunOut, FeedError> {
        let (mut next, mut repair, mut more, mut gap) = (Vec::new(), Vec::new(), false, None);
        r.stalled = false;
        if let Some(mut lane) = self.main.take() {
            let mut dec = match r.dec.take() {
                Some(dec) => dec,
                None => {
                    let base = r.base.clone();
                    let dec = self.restore_dec(r.window, &base, sink)?;
                    lane = self.packed_lane(base.packed, self.stream_len);
                    r.fed = base.packed;
                    r.out = base.state.sp;
                    dec
                }
            };
            loop {
                let write = r.write_from..self.size;
                let stop = self.pump5(
                    &mut lane,
                    &mut dec,
                    (&mut r.fed, &mut r.out),
                    write.clone(),
                    Some(&mut r.base),
                    source,
                    sink,
                )?;
                match stop {
                    Stop::Reached => {
                        let mut out = self.out_sink(sink, r.out, write);
                        let ended = dec.finish(&mut out).map_err(|e| out.fail(e));
                        r.out = out.at;
                        ended?;
                        break;
                    }
                    Stop::Budget => {
                        more = true;
                        self.main = Some(lane);
                        r.dec = Some(dec);
                        break;
                    }
                    Stop::Missing { stream, len, hole } => {
                        if hole && let Some((d2, l2)) = self.skip_hole(r, stream + len, source, sink)? {
                            dec = d2;
                            lane = l2;
                            continue;
                        }
                        r.stalled = hole;
                        self.push_needs(&mut next, stream..stream + len, NeedKind::Next);
                        gap = Some(stream + len..lane.end);
                        self.main = Some(lane);
                        r.dec = Some(dec);
                        break;
                    }
                }
            }
        }
        if !more {
            let mut i = 0;
            while i < r.repairs.len() {
                match self.repair5(r, i, source, sink, &mut repair)? {
                    Some(true) => {
                        let done = r.repairs.remove(i);
                        self.lost.remove(done.lost);
                    }
                    Some(false) => i += 1,
                    None => {
                        more = true;
                        break;
                    }
                }
            }
        }
        Ok((next, repair, more, gap))
    }

    fn out_sink<'a>(&'a mut self, sink: &'a mut dyn FeedSink, at: u64, write: Range<u64>) -> OutSink<'a> {
        OutSink {
            sink,
            at,
            write,
            crc: &mut self.crc,
            stats: &mut self.stats,
            run_written: &mut self.run_written,
            io: None,
        }
    }

    /// Tries repair `i`: Some(true) when its lost output is written, Some(false) when bytes are still missing (its
    /// need is added), None when the run's budget ran out.
    fn repair5(
        &mut self,
        r: &mut Rar5,
        i: usize,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        needs: &mut Vec<NeedBytes>,
    ) -> Result<Option<bool>, FeedError> {
        let rep = r.repairs[i].clone();
        if let Some(b) = rep.blocked
            && let Some(len) = self.probe(b, rep.until_packed, source)?
        {
            self.push_needs(needs, b..b + len, NeedKind::Repair);
            return Ok(Some(false));
        }
        // the bytes it waited for are there: it goes on, and may pass them
        r.repairs[i].blocked = None;
        let mut dec = self.restore_dec(r.window, &rep.from, sink)?;
        let mut lane = self.packed_lane(rep.from.packed, rep.until_packed);
        let (mut fed, mut out) = (rep.from.packed, rep.from.state.sp);
        let feed_end = rep.until_packed;
        let mut cp = rep.from.clone();
        let stop = self.pump5_until(
            &mut lane,
            &mut dec,
            (&mut fed, &mut out),
            rep.lost.clone(),
            Some(&mut cp),
            feed_end,
            source,
            sink,
        )?;
        // what a repair that stops wrote is no longer lost, and the next attempt starts from its last checkpoint
        let keep = |r: &mut Rar5, lost: &mut RangeSet| {
            let written = out.clamp(rep.lost.start, rep.lost.end);
            lost.remove(rep.lost.start..written);
            let rp = &mut r.repairs[i];
            rp.lost.start = written;
            if cp.state.sp <= written {
                rp.from = cp.clone();
            }
        };
        match stop {
            Stop::Reached => {
                if out != rep.until_out || fed != rep.until_packed {
                    return Err(FeedError::Decode {
                        out,
                        error: crate::Error::Corrupt("a repair did not meet the restart after its hole"),
                    });
                }
                Ok(Some(true))
            }
            Stop::Budget => {
                keep(r, &mut self.lost);
                Ok(None)
            }
            Stop::Missing { stream, len, .. } => {
                keep(r, &mut self.lost);
                r.repairs[i].blocked = Some(stream);
                self.push_needs(needs, stream..stream + len, NeedKind::Repair);
                Ok(Some(false))
            }
        }
    }

    /// Skips the hole that ends at stream offset `hole_end` when the sink holds the output past the main decode's
    /// frontier: finds the restart after the hole in the packed bytes after it ([`resync_near`]) and starts a decoder
    /// there, recording the lost output and its repair. None when it cannot (yet).
    fn skip_hole(
        &mut self,
        r: &mut Rar5,
        hole_end: u64,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Option<(Box<Unpacker>, Lane)>, FeedError> {
        let out_h = r.out;
        let donor = read_some(sink, out_h, (self.size - out_h).min(DONOR_MAX));
        if (donor.len() as u64) < DONOR_MIN.min(self.size - out_h) || donor.is_empty() {
            return Ok(None);
        }

        // the packed bytes after the hole, decrypted
        // under CBC the first block after the hole is the IV of the next
        let after = match self.cipher {
            StoredCipher::Cbc { .. } => hole_end.checked_next_multiple_of(16).unwrap_or(u64::MAX).saturating_add(16),
            _ => hole_end,
        };
        if after >= self.stream_len {
            return Ok(None);
        }
        let mut lane = self.packed_lane(after, self.stream_len);
        let want = (donor.len() as f64 / r.ratio.max(1e-3) * 2.0) as u64 + (1 << 20);
        lane.end = lane.end.min(lane.pos.saturating_add(want.min(AFTER_MAX)));
        let mut packed = Vec::new();
        let first = after;
        let mut buf = std::mem::take(&mut self.buf);
        let mut scratch = Vec::new();
        while lane.pos < lane.end {
            let Some(span) = self.geometry.locate(lane.pos) else { break };
            let left = (span.stream.end.min(lane.end) - lane.pos).min(buf.len() as u64) as usize;
            match source.read_packed(span.volume, span.packed_start + (lane.pos - span.stream.start), &mut buf[..left])
            {
                PackedRead::Data(n) if n > 0 && n <= left => {
                    let at = lane.pos;
                    lane.pos += n as u64;
                    self.stats.packed_read += n as u64;
                    match self.cipher {
                        StoredCipher::Cbc { aes, .. } => {
                            let s = cbc_step(&aes, &mut lane, &buf[..n], &mut scratch);
                            let skip = first.saturating_sub(s).min(scratch.len() as u64) as usize;
                            packed.extend_from_slice(&scratch[skip..]);
                        }
                        _ => {
                            let skip = first.saturating_sub(at).min(n as u64) as usize;
                            packed.extend_from_slice(&buf[skip..n]);
                        }
                    }
                }
                PackedRead::Data(_) => {
                    self.buf = buf;
                    return Err(FeedError::SourceContract("Data count of 0 or past the buffer"));
                }
                _ => break,
            }
        }
        self.buf = buf;
        if packed.is_empty() {
            return Ok(None);
        }
        // a search that failed is tried again only once more is held: output past the frontier or packed bytes
        let tried = (hole_end, donor.len(), packed.len());
        let grown =
            |held: usize, after: usize| tried.1 > held || tried.2 >= after.saturating_mul(2).min(after + (4 << 20));
        if r.skip_failed.is_some_and(|(end, held, after)| end == hole_end && !grown(held, after)) {
            return Ok(None);
        }
        r.skip_failed = Some(tried);
        // the window before the frontier and the held output past it
        let base = out_h.saturating_sub(r.window.reach);
        let mut known = match read_back(sink, base..out_h) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        known.extend_from_slice(&donor);
        let known_end = out_h + donor.len() as u64;
        // The restart is the last block start at or before the target, and the search must follow the packed bytes
        // to the target: so targets just past where the hole's output is thought to end, nearest first (a restart
        // close after the hole loses the least), then as far as the packed bytes held after it are thought to reach.
        let hole_len = first.saturating_sub(r.fed);
        let ratio = r.ratio.max(1e-3);
        let covered = ((hole_len + packed.len() as u64) as f64 * ratio) as u64;
        let reach = out_h.saturating_add((covered as f64 * 0.95) as u64).min(known_end);
        let hole_out = out_h.saturating_add((hole_len as f64 * ratio) as u64);
        let mut targets: Vec<u64> = [128u64 << 10, 512 << 10, 2 << 20, 8 << 20]
            .iter()
            .map(|d| hole_out.saturating_add(*d))
            .filter(|&t| t < reach)
            .collect();
        targets.push(reach);
        let mut found = None;
        for target in targets {
            if target <= out_h {
                continue;
            }
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            let estimate = (((target - out_h) as f64 / ratio) as u64).saturating_sub(hole_len);
            let options = NearOptions {
                estimate: Some(estimate.min(packed.len() as u64) as usize),
                guard: false,
                work: SKIP_WORK,
                ..NearOptions::default()
            };
            let res = resync_near(&packed, base, &known, r.window, target, &options);
            if let Ok(near) = res
                && near.resync.output_offset > out_h
            {
                found = Some(near);
                break;
            }
        }
        let Some(near) = found else { return Ok(None) };
        let restart = near.resync;
        // Seeded from the held output, noting rather than refusing what a filter the search did not see may have
        // changed: the member's CRC decides (`crc_ok`).
        let dec = Unpacker::resume_seeded(r.window, &restart, 0, base, &known, Some(self.size), false);
        let Ok(mut dec) = dec else { return Ok(None) };
        dec.set_threads(0, u64::MAX);
        dec.record_filters_from(&restart);
        let until_packed = first + restart.packed_offset as u64;
        let until_out = restart.output_offset;
        r.repairs.push(Repair { from: r.base.clone(), until_packed, until_out, lost: out_h..until_out, blocked: None });
        self.lost.insert(out_h..until_out);
        self.stats.holes += 1;
        r.skip_failed = None;
        r.fed = until_packed;
        r.out = until_out;
        Ok(Some((Box::new(dec), self.packed_lane(until_packed, self.stream_len))))
    }

    #[allow(clippy::too_many_arguments)]
    fn pump5(
        &mut self,
        lane: &mut Lane,
        dec: &mut Unpacker,
        pos: (&mut u64, &mut u64),
        write: Range<u64>,
        base: Option<&mut Cp>,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Stop, FeedError> {
        let end = self.stream_len;
        self.pump5_until(lane, dec, pos, write, base, end, source, sink)
    }

    /// Reads a lane and feeds its (decrypted) bytes before stream offset `feed_end` to `dec`, from `*fed` on;
    /// output inside `write` goes to the sink. With `base`, keeps it at the latest checkpoint.
    #[allow(clippy::too_many_arguments)]
    fn pump5_until(
        &mut self,
        lane: &mut Lane,
        dec: &mut Unpacker,
        (fed, out): (&mut u64, &mut u64),
        write: Range<u64>,
        mut base: Option<&mut Cp>,
        feed_end: u64,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Stop, FeedError> {
        let mut buf = std::mem::take(&mut self.buf);
        let mut scratch = std::mem::take(&mut self.scratch);
        let result = (|| loop {
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            if dec.ended() || lane.pos >= lane.end || *fed >= feed_end {
                return Ok(Stop::Reached);
            }
            if self.options.run_budget.is_some_and(|b| self.run_written >= b) {
                return Ok(Stop::Budget);
            }
            let span =
                self.geometry.locate(lane.pos).ok_or(FeedError::Malformed("stream offset outside the pieces"))?;
            let piece_left = span.stream.end.min(lane.end) - lane.pos;
            let left = piece_left.min(buf.len() as u64) as usize;
            let (volume, packed) = (span.volume, span.packed_start + (lane.pos - span.stream.start));
            match source.read_packed(volume, packed, &mut buf[..left]) {
                PackedRead::Data(n) => {
                    if n == 0 || n > left {
                        return Err(FeedError::SourceContract("Data count of 0 or past the buffer"));
                    }
                    let at = lane.pos;
                    lane.pos += n as u64;
                    self.stats.packed_read += n as u64;
                    let (at, bytes): (u64, &[u8]) = match self.cipher {
                        StoredCipher::Cbc { aes, .. } => {
                            let s = cbc_step(&aes, lane, &buf[..n], &mut scratch);
                            (s, &scratch[..])
                        }
                        _ => (at, &buf[..n]),
                    };
                    let from = (*fed).max(at);
                    let to = (at + bytes.len() as u64).min(feed_end);
                    if from < to {
                        let chunk = &bytes[(from - at) as usize..(to - at) as usize];
                        let mut o = self.out_sink(sink, *out, write.clone());
                        let fedr = dec.feed(chunk, &mut o).and_then(|()| dec.flush_now(&mut o)).map_err(|e| o.fail(e));
                        *out = o.at;
                        fedr?;
                        *fed = to;
                        if let Some(b) = base.as_deref_mut()
                            && let Some(cp) = dec.checkpoint()
                        {
                            *b = Cp { packed: *fed - dec.pending_input() as u64, state: cp };
                        }
                    }
                }
                PackedRead::NotYet { len } => {
                    return Ok(Stop::Missing { stream: lane.pos, len: len.clamp(1, piece_left), hole: false });
                }
                PackedRead::Hole { len } => {
                    return Ok(Stop::Missing { stream: lane.pos, len: len.clamp(1, piece_left), hole: true });
                }
            }
        })();
        self.buf = buf;
        self.scratch = scratch;
        result
    }
}
