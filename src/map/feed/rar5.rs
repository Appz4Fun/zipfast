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
    /// The start of a stream (at stream offset `sp`, for a restore placeholder of a solid successor).
    fn start(sp: u64) -> Self {
        Cp { packed: 0, state: UnpackCheckpoint { sp, history: [0; 4], last_len: 0, lens: None, filters: Vec::new() } }
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

/// What became of the main decode after an abandoned seeded restart.
enum Abandoned {
    /// restarted: decode on with this decoder, reading this lane
    Restart(Box<Unpacker>, Lane),
    /// no restart yet: wait for more packed bytes and search again
    Wait,
    /// the search read all it may: the rest is one repair, and the main decode is over
    Over,
}

/// What a RAR 5.0 skip attempt read at a hole: the held output past the frontier, the decrypted packed bytes after
/// the hole with the lane positioned after them, and the window before the frontier.
struct SkipCache {
    hole_end: u64,
    out: u64,
    donor: Vec<u8>,
    packed: Vec<u8>,
    lane: Lane,
    window: Vec<u8>,
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
    /// the main decode runs from a seeded restart whose output is still checked against the held output: the
    /// checkpoint before the hole it skipped (trusted, unlike the seeded state) and the output offset the check ends at
    seeded_skip: Option<(Cp, u64)>,
    /// what the last skip attempt at a hole read, kept for the next attempt at the same hole
    skip_cache: Option<SkipCache>,
    /// the main decode waits to restart after a seeded restart it abandoned (its state is untrusted from `fed`):
    /// the checkpoint before the hole first skipped, which the repairs start from
    resync: Option<Cp>,
    /// seeded restarts abandoned in a row: each pushes the next search further past the trouble (a filter's reach)
    abandons: u32,
    /// the last skip search that failed had read every packed byte it may read: more will not help
    skip_exhausted: bool,
    /// unpacked / packed, for estimates
    ratio: f64,
    /// where the member's output starts in its solid stream's (0 alone; checkpoints count stream offsets), and the
    /// starts of the stream's members up to this one (a recorded filter addresses from its member's start)
    start: u64,
    starts: Vec<u64>,
    /// a solid member follows: the main decoder is kept at the end for a hand-off ([`FeedDecoder::next_solid`]),
    /// its state there as a checkpoint at the successor's start
    successor: bool,
    ended: Option<Box<Unpacker>>,
    carry: Option<Cp>,
}

/// An [`Sink`] writing the part of the decoder's output inside `write` to the feed sink.
pub(super) struct OutSink<'a> {
    sink: &'a mut dyn FeedSink,
    pub(super) at: u64,
    write: Range<u64>,
    crc: &'a mut CrcRuns,
    stats: &'a mut FeedStats,
    run_written: &'a mut u64,
    /// every byte put, written or not, goes through this hash (an earlier solid member decoded again)
    replay: Option<&'a mut crc32fast::Hasher>,
    io: Option<io::Error>,
}

impl Sink for OutSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> crate::Result<()> {
        let start = self.at;
        let end = start + bytes.len() as u64;
        self.at = end;
        if let Some(h) = self.replay.as_mut() {
            h.update(bytes);
        }
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

impl<'a> OutSink<'a> {
    /// Hashes all output put through this sink, written or not.
    pub(super) fn hashing(mut self, hasher: &'a mut crc32fast::Hasher) -> Self {
        self.replay = Some(hasher);
        self
    }

    pub(super) fn fail(&mut self, error: crate::Error) -> FeedError {
        match self.io.take() {
            Some(error) => FeedError::Write { out: self.at, error },
            None => FeedError::Decode { out: self.at, error },
        }
    }
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
    /// Ends the main decode: the caller holds the output from its frontier to the member's end.
    pub(super) fn end_main(&mut self, size: u64) {
        self.dec = None;
        self.seeded_skip = None;
        self.skip_cache = None;
        self.stalled = false;
        self.out = size;
    }

    /// Drops lost output `range` (held by the caller) from the repairs: a repair keeps only the parts of its lost
    /// range outside it, still decoding to its restart but writing only those.
    pub(super) fn retire(&mut self, range: &Range<u64>) {
        let mut kept = Vec::with_capacity(self.repairs.len() + 1);
        for rep in self.repairs.drain(..) {
            if rep.lost.end <= range.start || rep.lost.start >= range.end {
                kept.push(rep);
                continue;
            }
            if rep.lost.start < range.start {
                kept.push(Repair { lost: rep.lost.start..range.start, ..rep.clone() });
            }
            if range.end < rep.lost.end {
                kept.push(Repair { lost: range.end..rep.lost.end, ..rep });
            }
        }
        self.repairs = kept;
    }

    pub(super) fn frontier(&self) -> u64 {
        self.out.max(self.write_from)
    }

    pub(super) fn reach(&self) -> u64 {
        self.window.reach
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

    /// The member output offset of a checkpoint (its stream offset less the member's start).
    fn cp_out(&self, cp: &Cp) -> u64 {
        cp.state.sp - self.start
    }

    /// The carry for a solid successor: its start and the checkpoint there, serialized.
    pub(super) fn carry_blob(&self) -> Option<(u64, Vec<u8>)> {
        let cp = self.carry.as_ref()?;
        let mut out = Vec::new();
        put_cp(&mut out, cp);
        Some((cp.state.sp, out))
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
        // a finished member with a solid successor keeps the successor's start
        if let Some(cp) = &self.carry {
            put_cp(&mut out, cp);
        }
        out
    }

    pub(super) fn restore(&mut self, blob: &[u8], size: u64, stream_len: u64) -> Result<(), FeedError> {
        let mut r = Reader(blob);
        let bad = || FeedError::Snapshot("out of range");
        let start = self.start;
        let base = get_cp(&mut r, &self.starts)?;
        let frontier = r.u64()?;
        if base.packed > stream_len || base.state.sp < start || base.state.sp - start > frontier || frontier > size {
            return Err(bad());
        }
        let n = r.count(8 * 4 + 8 * 7 + 4)?;
        let mut repairs = Vec::with_capacity(n);
        for _ in 0..n {
            let from = get_cp(&mut r, &self.starts)?;
            let (until_packed, until_out, s, e) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?);
            if from.packed > until_packed
                || until_packed > stream_len
                || from.state.sp < start
                || from.state.sp - start > s
                || s > e
                || e != until_out
            {
                return Err(bad());
            }
            repairs.push(Repair { from, until_packed, until_out, lost: s..e, blocked: None });
        }
        let carry = if r.0.is_empty() {
            None
        } else {
            let mut starts = self.starts.clone();
            starts.push(start + size);
            let cp = get_cp(&mut r, &starts)?;
            if !self.successor || cp.packed != 0 || cp.state.sp != start + size || frontier != size {
                return Err(bad());
            }
            Some(cp)
        };
        if !r.0.is_empty() {
            return Err(FeedError::Snapshot("trailing bytes"));
        }
        self.carry = carry;
        self.ended = None;
        self.dec = None;
        self.base = base;
        self.out = frontier;
        self.fed = self.base.packed;
        self.write_from = frontier;
        self.repairs = repairs;
        Ok(())
    }
}

/// The checkpoint a carry holds, checked against the successor's place.
fn carry_cp(carry: &SolidCarry, starts: &[u64]) -> Result<Cp, FeedError> {
    let mut r = Reader(&carry.cp);
    let cp = get_cp(&mut r, starts)?;
    if !r.0.is_empty() || cp.packed != 0 || cp.state.sp != carry.next_start {
        return Err(FeedError::Snapshot("a carry that does not decode"));
    }
    Ok(cp)
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

/// A checkpoint as [`put_cp`] wrote it; `starts` are the member starts of its solid stream, ascending, which give each
/// recorded filter its member.
fn get_cp(r: &mut Reader<'_>, starts: &[u64]) -> Result<Cp, FeedError> {
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
        // a recorded filter ran before the checkpoint: its output ends at or before it
        if start.checked_add(len).is_none_or(|end| end > sp) {
            return Err(FeedError::Snapshot("filter past its checkpoint"));
        }
        let base = starts.iter().rev().copied().find(|&s| s <= start).unwrap_or(0);
        filters.push(SeenFilterRec::from_code(start, len, code, base).ok_or(FeedError::Snapshot("bad filter"))?);
    }
    Ok(Cp { packed, state: UnpackCheckpoint { sp, history, last_len, lens, filters } })
}

/// What one run of the compressed layer found: needs for the main decode and for repairs, whether the budget
/// stopped it, and the stream range after the main decode's gap (for lookahead needs).
pub(super) type RunOut = (Vec<NeedBytes>, Vec<NeedBytes>, bool, Option<Range<u64>>);

impl FeedDecoder {
    /// A decoder of a compressed RAR 5.0 member: at its start, or for a solid successor from the state the member
    /// before left (`begin`).
    pub(super) fn new_rar5(
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
        begin: Begin,
    ) -> Result<Self, FeedError> {
        let member = &map.members[index];
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        let run = solid_run(map, index)?;
        let solid = run.prev.is_some();
        // a successor starts at the carry's checkpoint (a decoder handed over in-session is installed after)
        let base = match begin {
            Begin::Fresh if solid => return Err(FeedError::Unsupported(FeedUnsupported::Solid)),
            Begin::Fresh => Cp::start(0),
            Begin::Restore => Cp::start(run.start),
            Begin::Carry(carry) => {
                // taken at the end of the member before, in this stream
                let prev = run.prev.ok_or(FeedError::Handoff("a carry for a member that is not a solid successor"))?;
                let prev_start = run.starts[run.starts.len() - 2];
                if carry.next_start != run.start || carry.from != solid_identity(&map.members[prev], prev_start) {
                    return Err(FeedError::Handoff("a carry of another stream or place in it"));
                }
                carry_cp(&carry, &run.starts)?
            }
            _ => return Err(FeedError::Handoff("a hand-off from another layer")),
        };
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
        // a solid stream's members share one window, sized for its largest dictionary
        let stream = solid || run.successor;
        let dictionary = if stream { run.dictionary.unwrap_or(dictionary).max(dictionary) } else { dictionary };
        let window = window_for(dictionary, Some(size), stream).map_err(|error| FeedError::Decode { out: 0, error })?;
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
            identity: solid_identity(member, run.start),
            options,
            buf: vec![0; chunk],
            scratch: Vec::new(),
            run_written: 0,
            held_prefix: 0,
            failed: false,
            status: FeedStatus::default(),
            index: 0,
            stream_start: run.start,
            unproven: false,
            suspect: None,
            seeded: None,
            rar5: Some(Box::new(Rar5 {
                window,
                dec: None,
                base,
                out: 0,
                fed: 0,
                write_from: 0,
                repairs: Vec::new(),
                stalled: false,
                skip_failed: None,
                seeded_skip: None,
                skip_cache: None,
                resync: None,
                abandons: 0,
                skip_exhausted: false,
                ratio,
                start: run.start,
                starts: run.starts.clone(),
                successor: run.successor,
                ended: None,
                carry: None,
            })),
            lzma2: None,
            rar4: None,
            zip: None,
            mac: None,
        };
        // An empty member of a solid stream still has its blocks decoded: they may set the tables the next member's
        // first block goes on with. One without packed bytes passes the stream on as it got it.
        let feeds = size > 0 || (stream_len > 0 && (solid || run.successor));
        let r = d.rar5.as_mut().expect("RAR 5.0 state");
        if !feeds && r.successor {
            r.carry = Some(r.base.clone());
        }
        if feeds {
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

    /// A decoder restarted at `cp`, its window read back from the sink (and from the earlier members' output, for a
    /// solid successor whose window reaches before it).
    fn restore_dec(&self, r: &Rar5, cp: &Cp, sink: &mut dyn FeedSink) -> Result<Box<Unpacker>, FeedError> {
        let (window, start) = (r.window, r.start);
        let sp = cp.state.sp;
        let from = cp.state.filters.iter().map(|f| f.start).fold(sp.saturating_sub(window.reach), u64::min);
        let known = if sp > from { read_stream(sink, start, from..sp)? } else { Vec::new() };
        let mut dec = Unpacker::from_checkpoint(window, &cp.state, start, Some(self.size), from, &known)
            .map_err(|error| FeedError::Decode { out: sp.saturating_sub(start), error })?;
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
            'main: {
                let mut dec = match (r.resync.take(), r.dec.take()) {
                    // waiting to restart after an abandoned seeded restart: search again
                    (Some(origin), _) => match self.after_abandon(r, origin, source, sink)? {
                        Abandoned::Restart(d, l) => {
                            lane = l;
                            d
                        }
                        Abandoned::Over => break 'main,
                        Abandoned::Wait => {
                            r.stalled = true;
                            gap = Some(r.fed..self.stream_len);
                            self.main = Some(lane);
                            break 'main;
                        }
                    },
                    (None, Some(dec)) => dec,
                    (None, None) => {
                        let base = r.base.clone();
                        let dec = self.restore_dec(r, &base, sink)?;
                        lane = self.packed_lane(base.packed, self.stream_len);
                        r.fed = base.packed;
                        r.out = r.cp_out(&base);
                        dec
                    }
                };
                loop {
                    let write = r.write_from..self.size;
                    let pumped = self.pump5(
                        &mut lane,
                        &mut dec,
                        (&mut r.fed, &mut r.out),
                        write.clone(),
                        Some(&mut r.base),
                        source,
                        sink,
                    );
                    let stop = match pumped {
                        // A seeded restart that disagrees with the held output (a filter the search did not see, a
                        // false restart, held output that differs): what it wrote so far matched, but its state cannot
                        // be trusted from here. Search again from the bytes after it; the repair of what lies between
                        // starts from the checkpoint before the hole skipped, which the seeded state never touched.
                        Err(FeedError::Decode { .. }) if r.seeded_skip.is_some() => {
                            let (origin, _) = r.seeded_skip.take().expect("a seeded skip");
                            r.abandons = r.abandons.saturating_add(1);
                            match self.after_abandon(r, origin, source, sink)? {
                                Abandoned::Restart(d, l) => {
                                    dec = d;
                                    lane = l;
                                    continue;
                                }
                                Abandoned::Over => break,
                                Abandoned::Wait => {
                                    r.stalled = true;
                                    gap = Some(r.fed..self.stream_len);
                                    self.main = Some(self.packed_lane(r.fed, self.stream_len));
                                    break;
                                }
                            }
                        }
                        other => other?,
                    };
                    if r.seeded_skip.as_ref().is_some_and(|&(_, end)| r.out >= end) {
                        r.seeded_skip = None;
                        r.abandons = 0;
                    }
                    match stop {
                        Stop::Reached => {
                            let mut out = self.out_sink(sink, r.out, write);
                            let ended = dec.finish(&mut out).map_err(|e| out.fail(e));
                            r.out = out.at;
                            ended?;
                            if r.successor {
                                // the next file of the stream starts here: the decoder goes on, or a successor restarts
                                // from its state at this point
                                dec.next_file(None);
                                let cp = dec.checkpoint().ok_or(FeedError::Decode {
                                    out: r.out,
                                    error: crate::Error::Corrupt("no restart point at the end of a solid member"),
                                })?;
                                r.carry = Some(Cp { packed: 0, state: cp });
                                r.ended = Some(dec);
                            }
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

    pub(super) fn out_sink<'a>(&'a mut self, sink: &'a mut dyn FeedSink, at: u64, write: Range<u64>) -> OutSink<'a> {
        OutSink {
            sink,
            at,
            write,
            crc: &mut self.crc,
            stats: &mut self.stats,
            run_written: &mut self.run_written,
            replay: None,
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
        let mut dec = self.restore_dec(r, &rep.from, sink)?;
        let mut lane = self.packed_lane(rep.from.packed, rep.until_packed);
        let (mut fed, mut out) = (rep.from.packed, r.cp_out(&rep.from));
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
            let cp_out = r.cp_out(&cp);
            let rp = &mut r.repairs[i];
            rp.lost.start = written;
            if cp_out <= written {
                rp.from = cp.clone();
            }
        };
        match stop {
            Stop::Reached => {
                // a repair to the member's end (the rest after an abandoned seeded restart) flushes the decoder as the
                // main decode does at its end; it may stop at the end of the data, before a cipher's padding
                let to_end = rep.until_out == self.size && rep.until_packed == self.stream_len;
                if to_end {
                    let mut o = self.out_sink(sink, out, rep.lost.clone());
                    let ended = dec.finish(&mut o).map_err(|e| o.fail(e));
                    out = o.at;
                    ended?;
                }
                if out != rep.until_out || (fed != rep.until_packed && !to_end) {
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

    /// After a seeded restart was abandoned (its output disagreed with the held output from `r.out` on): search for
    /// another restart from the packed bytes after it, with the repairs starting from `origin`, the checkpoint
    /// before the hole first skipped. Without one yet the main decode waits for more packed bytes and searches
    /// again on a later run (the retry gate decides); only once the search has read every packed byte it may is
    /// the rest handed to one repair from `origin` (the main decode is over; nothing is written twice).
    fn after_abandon(
        &mut self,
        r: &mut Rar5,
        origin: Cp,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Abandoned, FeedError> {
        r.base = origin.clone();
        r.skip_exhausted = false;
        if let Some((dec, lane)) = self.skip_hole(r, r.fed, source, sink)? {
            return Ok(Abandoned::Restart(dec, lane));
        }
        if !r.skip_exhausted {
            r.resync = Some(origin);
            return Ok(Abandoned::Wait);
        }
        let at = r.out;
        if at < self.size && !r.repairs.iter().any(|x| x.lost.start < self.size && at < x.lost.end) {
            r.repairs.push(Repair {
                from: origin,
                until_packed: self.stream_len,
                until_out: self.size,
                lost: at..self.size,
                blocked: None,
            });
            self.lost.insert(at..self.size);
        }
        Ok(Abandoned::Over)
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
        // A retry at the same hole keeps what the last attempt read (held output, decrypted packed bytes and the
        // lane after them, the window): it reads only what is new, and asks the retry gate before searching again.
        let cached = r.skip_cache.take().filter(|c| c.hole_end == hole_end && c.out == out_h);
        let (mut donor, mut packed, lane, window) = match cached {
            Some(c) => (c.donor, c.packed, Some(c.lane), Some(c.window)),
            None => (Vec::new(), Vec::new(), None, None),
        };
        let held_max = (self.size - out_h).min(DONOR_MAX);
        // Held output is read in two steps: enough to know a skip is worth trying, then (below) only as far as the
        // packed bytes read after the hole can reach, not up to DONOR_MAX.
        let mut extend = |donor: &mut Vec<u8>, to: u64| {
            let to = to.min(held_max);
            if (donor.len() as u64) < to {
                let more = read_some(sink, out_h + donor.len() as u64, to - donor.len() as u64);
                donor.extend_from_slice(&more);
            }
        };
        extend(&mut donor, DONOR_MIN);
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
        let first = after;
        let mut lane = lane.unwrap_or_else(|| self.packed_lane(after, self.stream_len));
        let want = (held_max as f64 / r.ratio.max(1e-3) * 2.0) as u64 + (1 << 20);
        lane.end = self.stream_len.min(first.saturating_add(want.min(AFTER_MAX)));
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
        // every packed byte the search may read is read (up to AFTER_MAX or the stream's end): more will not help
        let full = lane.pos >= lane.end;
        if packed.is_empty() {
            return Ok(None);
        }
        // the held output the packed bytes after the hole can reach (the search's farthest target), with a margin
        let span = first.saturating_sub(r.fed) + packed.len() as u64;
        extend(&mut donor, (span as f64 * r.ratio.max(1e-3) * 1.25) as u64 + (1 << 20));
        // the window before the frontier, at stream offsets (a solid successor's window reaches into the earlier
        // members' output): read once per hole
        let s0 = r.start;
        let at = s0 + out_h;
        let base = at.saturating_sub(r.window.reach);
        let window = match window {
            Some(w) => w,
            None => match read_stream(sink, s0, base..at) {
                Ok(k) => k,
                Err(_) => return Ok(None),
            },
        };
        // a search that failed is tried again only once more is held: output past the frontier or packed bytes
        let tried = (hole_end, donor.len(), packed.len());
        let grown =
            |held: usize, after: usize| tried.1 > held || tried.2 >= after.saturating_mul(2).min(after + (4 << 20));
        let keep = |r: &mut Rar5, donor: Vec<u8>, packed: Vec<u8>, lane: Lane, window: Vec<u8>| {
            r.skip_cache = Some(SkipCache { hole_end, out: out_h, donor, packed, lane, window });
        };
        if r.skip_failed.is_some_and(|(end, held, after)| end == hole_end && !grown(held, after)) {
            r.skip_exhausted = full;
            keep(r, donor, packed, lane, window);
            return Ok(None);
        }
        r.skip_failed = Some(tried);
        let mut known = Vec::with_capacity(window.len() + donor.len());
        known.extend_from_slice(&window);
        known.extend_from_slice(&donor);
        let known_end = at + donor.len() as u64;
        // The restart is the last block start at or before the target, and the search must follow the packed bytes
        // to the target: so targets just past where the hole's output is thought to end, nearest first (a restart
        // close after the hole loses the least), then as far as the packed bytes held after it are thought to reach.
        let hole_len = first.saturating_sub(r.fed);
        let ratio = r.ratio.max(1e-3);
        let covered = ((hole_len + packed.len() as u64) as f64 * ratio) as u64;
        let reach = at.saturating_add((covered as f64 * 0.95) as u64).min(known_end);
        let hole_out = at.saturating_add((hole_len as f64 * ratio) as u64);
        // after seeded restarts abandoned in a row, past where they went wrong: a filter there reaches further
        let push = if r.abandons > 0 { (128u64 << 10) << r.abandons.min(6) } else { 0 };
        let mut targets: Vec<u64> = [128u64 << 10, 512 << 10, 2 << 20, 8 << 20]
            .iter()
            .map(|d| hole_out.saturating_add(*d + push))
            .filter(|&t| t < reach)
            .collect();
        targets.push(reach);
        let mut found = None;
        let end = s0 + self.size;
        let mut i = 0;
        while i < targets.len() {
            let target = targets[i];
            i += 1;
            if target <= at {
                continue;
            }
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            let estimate = (((target - at) as f64 / ratio) as u64).saturating_sub(hole_len);
            let options = NearOptions {
                estimate: Some(estimate.min(packed.len() as u64) as usize),
                guard: false,
                work: SKIP_WORK,
                ..NearOptions::default()
            };
            let res = resync_near(&packed, base, &known, r.window, target, &options);
            match res {
                // a restart at the member's end has no block after it (under AES only the cipher's padding): the
                // last block before it then
                Ok(near) if near.resync.output_offset >= end => {
                    if i == targets.len() && end - 1 > at {
                        targets.push(end - 1);
                    }
                }
                Ok(near) if near.resync.output_offset > at => {
                    found = Some(near);
                    break;
                }
                _ => {}
            }
        }
        let Some(near) = found else {
            r.skip_exhausted = full;
            keep(r, donor, packed, lane, window);
            return Ok(None);
        };
        let restart = near.resync;
        // Seeded from the held output, noting rather than refusing what a filter the search did not see may have
        // changed: the member's CRC decides (`crc_ok`).
        let dec = Unpacker::resume_seeded(r.window, &restart, s0, base, &known, Some(self.size), false);
        let Ok(mut dec) = dec else { return Ok(None) };
        dec.set_threads(0, u64::MAX);
        dec.record_filters_from(&restart);
        let until_packed = first + restart.packed_offset as u64;
        let until_out = restart.output_offset - s0;
        // Repairs never overlap, so no output byte is written twice: output an earlier repair already covers (a
        // hole skipped again after a restore) is left to it.
        let origin = r.base.clone();
        let mut from_out = out_h;
        for x in &r.repairs {
            if x.lost.start <= from_out && from_out < x.lost.end {
                from_out = x.lost.end;
            }
        }
        if from_out < until_out && !r.repairs.iter().any(|x| x.lost.start < until_out && from_out < x.lost.end) {
            r.repairs.push(Repair {
                from: r.base.clone(),
                until_packed,
                until_out,
                lost: from_out..until_out,
                blocked: None,
            });
            self.lost.insert(from_out..until_out);
        }
        // The restart is a checkpoint at once, before a block after it can leave a filter pending: a restore never
        // goes back before the hole just skipped.
        if let Some(cp) = dec.checkpoint() {
            r.base = Cp { packed: until_packed, state: cp };
        }
        self.stats.holes += 1;
        // what follows was decoded from held output: unproven until the member's CRC matches; the window holds that
        // output until it is pushed out of reach, whatever the CRC says (a successor inherits it)
        self.unproven = true;
        self.seeded = self.seeded.max(Some(restart.output_offset));
        r.skip_failed = None;
        r.seeded_skip = Some((origin, known_end - s0));
        r.fed = until_packed;
        r.out = until_out;
        Ok(Some((Box::new(dec), self.packed_lane(until_packed, self.stream_len))))
    }

    /// [`FeedDecoder::next_solid`] for a RAR 5.0 member: the decoder kept at the member's end goes on into the next
    /// member, or (restored from a snapshot since) the next member restarts from the state saved there.
    pub(super) fn handoff_rar5(
        &mut self,
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
    ) -> Result<FeedDecoder, FeedError> {
        if index >= map.members.len() {
            return Err(FeedError::NoSuchMember { index });
        }
        if solid_run(map, index)?.prev != Some(self.index) {
            return Err(FeedError::Handoff("not the next member of the solid stream"));
        }
        let carry = self.solid_carry().ok_or(FeedError::Handoff("the main decode has not finished"))?;
        // the successor is set up (keys, limits) before the live decoder leaves this one: a failure keeps it here
        let mut next = FeedDecoder::new_begin(map, index, options, Begin::Carry(carry.clone()))?;
        let r = self.rar5.as_mut().expect("RAR 5.0 state");
        if let Some(dec) = r.ended.take()
            && let Err(dec) = next.install_rar5(dec)
        {
            r.ended = Some(dec);
        }
        next.inherit(carry.suspect);
        Ok(next)
    }

    /// Makes `dec`, the decoder the member before kept at its end, this successor's main decoder (it then goes on
    /// without reading its window back). Gives it back when it does not fit.
    fn install_rar5(&mut self, mut dec: Box<Unpacker>) -> Result<(), Box<Unpacker>> {
        let size = self.size;
        let feeds = self.main.is_some();
        let r = self.rar5.as_mut().expect("RAR 5.0 state");
        if dec.window_size() != r.window.size || r.dec.is_some() {
            return Err(dec);
        }
        dec.next_file(Some(size));
        if feeds {
            r.dec = Some(dec);
        } else if r.successor {
            r.ended = Some(dec);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn with_filter(sp: u64, start: u64, len: u64) -> Result<Cp, FeedError> {
        let mut cp = Cp::start(0);
        cp.state.sp = sp;
        let mut out = Vec::new();
        put_cp(&mut out, &cp);
        // the filter count and one filter, written by hand: a recorded filter cannot be made past its checkpoint
        out.truncate(out.len() - 8);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.push(1);
        get_cp(&mut Reader(&out), &[0])
    }

    #[test]
    fn checkpoint_filters_must_end_before_the_checkpoint() {
        assert!(with_filter(1 << 20, 1000, 4000).is_ok());
        assert!(with_filter(5000, 1000, 4000).is_ok());
        assert!(matches!(with_filter(1, 2, 4), Err(FeedError::Snapshot(_))));
        assert!(matches!(with_filter(5000, 1000, 4001), Err(FeedError::Snapshot(_))));
        assert!(matches!(with_filter(u64::MAX, u64::MAX - 1, 4), Err(FeedError::Snapshot(_))));
    }
}
