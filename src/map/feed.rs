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

//! A feed-driven decoder for one member of a [`MemberMap`]: it takes packed bytes as they arrive, in any order,
//! writes the member's output as far as the bytes allow, never blocks, and says which packed bytes it needs next
//! ([`NeedBytes`]). Holes are skipped where the layer allows and repaired when their bytes come; the decoder's state
//! can be saved and restored. See `docs/feed-decoder.md`.

use super::member_reader::{MemberKey, derive_keys, validate};
use super::{CipherParams, ExtractFromError, MapMember, MapMethod, MemberMap, OutputMapping, UnsupportedRead};
use crate::crypto::AesKey;
use crate::progressive::{ProgressiveLimits, SessionControl, Usage};
use std::collections::BTreeMap;
use std::io;
use std::ops::Range;

mod lzma2;
mod rar4;
mod rar5;

/// What a [`PackedSource`] answers for a read of packed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedRead {
    /// The first `n` bytes of the buffer were filled (`0 < n <= buf.len()`).
    Data(usize),
    /// The bytes at the offset have not arrived. `len` bytes from the offset are absent, as far as the source knows
    /// (at least 1; `u64::MAX` when it knows of nothing later). The decoder clips it to what it reads.
    NotYet { len: u64 },
    /// `len` bytes from the offset are lost (an article that will not come, a damaged or missing volume) until the
    /// source holds them again, which repairs the hole. At least 1; the decoder clips it.
    Hole { len: u64 },
}

/// Where a [`FeedDecoder`] reads packed bytes: the caller's article store. It never waits: bytes that have not
/// arrived are [`PackedRead::NotYet`], and the decoder is run again once more have.
///
/// Offsets are a volume's own byte offsets, as [`super::MapPiece::packed`] gives them. [`ArticleBuffer`] is an
/// in-memory implementation that takes articles in any order.
pub trait PackedSource {
    /// Reads packed bytes of volume `volume` from byte `offset` into `buf` (never empty).
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> PackedRead;

    /// The parts of `range` of volume `volume` the source does not hold, in order, when it can tell without
    /// reading. The decoder lists them as [`NeedKind::Ahead`]. The default, None, lists nothing ahead.
    fn absent(&self, volume: u32, range: Range<u64>) -> Option<Vec<Range<u64>>> {
        let _ = (volume, range);
        None
    }

    /// The decoder will not read `range` of volume `volume` again (unless it is restored from an earlier
    /// [`FeedSnapshot`]), so the source may let those bytes go. A hint; the default keeps them.
    ///
    /// The hint is per decoder. A source shared by several decoders whose members share packed bytes, as every
    /// member of a 7z folder reads the folder's packed stream ([`super::MapFolder::packed`]; the members' own
    /// `pieces` are empty), must keep bytes until no decoder reads them: count releases per decoder, or ignore them
    /// ([`ArticleBuffer`] drops what it is told).
    fn release(&mut self, volume: u32, range: Range<u64>) {
        let _ = (volume, range);
    }
}

/// Where a [`FeedDecoder`] writes the member's output.
pub trait FeedSink {
    /// The plaintext of member output offsets `offset..offset + bytes.len()`. The main decode writes in order; a
    /// repair writes a range reported lost earlier ([`FeedStatus::lost`]). No output byte is written twice.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()>;

    /// Output already held from `offset` on: bytes this decoder wrote, or plaintext of the member known from
    /// elsewhere (another copy of the file). Fills the start of `buf` and returns how many bytes from `offset` it
    /// holds, 0 for none. Compressed layers read back the output before a restart point to fill their window (only
    /// output they wrote, or that they reported lost after a skip, which came from here), and the output past a hole
    /// to skip it (see `docs/feed-decoder.md`). The default holds nothing: compressed members then wait at holes and
    /// cannot be restored from a snapshot.
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (offset, buf);
        Ok(0)
    }

    /// Output of the earlier members of the member's solid stream (RAR) at offsets in that stream's output, before
    /// the member's own start ([`FeedDecoder::stream_start`]): what their decoders wrote, or plaintext known from
    /// elsewhere. Fills the start of `buf` and returns how many bytes from `stream_offset` it holds, 0 for none.
    /// Asked only when a window reaches back into earlier members: a solid successor started from a
    /// [`SolidCarry`], or restored from a snapshot, or a restart, repair or hole skip close after its start. The
    /// default holds nothing; those then fail with [`FeedError::EarlierOutput`] (a skip waits instead).
    fn read_earlier(&mut self, stream_offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (stream_offset, buf);
        Ok(0)
    }
}

impl FeedSink for Vec<u8> {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(|_| io::Error::other("output offset past memory"))?;
        let end = at.checked_add(bytes.len()).ok_or_else(|| io::Error::other("output offset past memory"))?;
        if self.len() < end {
            self.resize(end, 0);
        }
        self[at..end].copy_from_slice(bytes);
        Ok(())
    }

    /// The bytes up to the vector's length: what was written, and what the caller put there before (a donor).
    /// Only meaningful for output this decoder wrote or the caller filled.
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(at) = usize::try_from(offset).ok().filter(|&at| at < self.len()) else { return Ok(0) };
        let n = self.len().saturating_sub(at).min(buf.len());
        buf[..n].copy_from_slice(&self[at..at + n]);
        Ok(n)
    }
}

/// Packed bytes a [`FeedDecoder`] needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeedBytes {
    /// The volume (as [`super::MapPiece::volume`] numbers them).
    pub volume: u32,
    /// The volume's byte range.
    pub range: Range<u64>,
    pub kind: NeedKind,
}

/// Why packed bytes are needed. [`FeedStatus::needs`] lists them in this order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NeedKind {
    /// The main decode waits for them: the output cannot go on in order without them.
    Next,
    /// They repair output reported lost ([`FeedStatus::lost`]).
    Repair,
    /// The main decode will read them later; the source does not hold them yet ([`PackedSource::absent`]).
    Ahead,
}

/// Where the decoder stands after [`FeedDecoder::run`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct FeedStatus {
    /// The main decode's output offset: every byte before it was written or is in [`Self::lost`].
    pub frontier: u64,
    /// Output ranges lost to holes and not yet repaired, in order.
    pub lost: Vec<Range<u64>>,
    /// The packed bytes the decoder needs, in priority order: [`NeedKind::Next`], then [`NeedKind::Repair`] in
    /// output order, then [`NeedKind::Ahead`]; at most [`FeedOptions::max_needs`].
    pub needs: Vec<NeedBytes>,
    /// The run stopped at [`FeedOptions::run_budget`] with more to do: run again.
    pub more: bool,
    /// Every output byte was written.
    pub done: bool,
    /// A compressed main decode waits at a hole it cannot skip (no held output past it, see
    /// [`FeedSink::read_held`]): its bytes are the first [`NeedKind::Next`] need.
    pub stalled: bool,
    /// Once done: whether the output matched the member's CRC32 (keyed with the password where the map says the
    /// checks are keyed). None when the member records none, or before done.
    pub crc_ok: Option<bool>,
    /// Output written so far was decoded from a window not proven yet: seeded from held output past a hole (a RAR
    /// 5.0 skip), or handed over from an earlier solid member that was not done with its CRC matched (a hole it
    /// skipped, a repair still to come). Cleared once the member is done with `crc_ok` true; a member without a CRC
    /// stays unproven.
    pub unproven: bool,
}

/// Work counters over the decoder's life (restored with a snapshot).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct FeedStats {
    /// Packed bytes read from the source.
    pub packed_read: u64,
    /// Output bytes written to the sink.
    pub written: u64,
    /// Holes met (each [`PackedRead::Hole`] answer to the main decode; a compressed decode waiting at one counts it
    /// once when it skips it).
    pub holes: u64,
    /// Output decoded again without being written: a compressed repair from its checkpoint up to the lost range,
    /// a restored decode from its checkpoint up to the frontier it had reached, and a 7z member's folder output from
    /// the last reset before it.
    pub redecoded: u64,
}

/// How a [`FeedDecoder`] runs.
#[derive(Clone)]
pub struct FeedOptions {
    /// The password of an encrypted member.
    pub password: Option<String>,
    /// Bounds the key derivation (KDF work, password sizes), as for maps.
    pub limits: ProgressiveLimits,
    /// Cancels a run between reads, and a key derivation in progress.
    pub control: SessionControl,
    /// The most packed bytes asked of the source in one read (default 256 KiB; at least 16).
    pub read_chunk: usize,
    /// The most [`NeedBytes`] a status lists (default 64).
    pub max_needs: usize,
    /// The most output bytes one run writes before it returns with [`FeedStatus::more`] (default unlimited), so a
    /// caller can interleave other work.
    pub run_budget: Option<u64>,
    /// The largest RAR 5.0 window (dictionary) a compressed member may allocate (default 1 GiB). A repair runs a
    /// second decoder with its own window while it lasts.
    pub max_window: u64,
}

impl Default for FeedOptions {
    fn default() -> Self {
        Self {
            password: None,
            limits: ProgressiveLimits::default(),
            control: SessionControl::default(),
            read_chunk: 256 << 10,
            max_needs: 64,
            run_budget: None,
            max_window: 1 << 30,
        }
    }
}

impl FeedOptions {
    /// Defaults with `password`.
    pub fn new(password: Option<&str>) -> Self {
        Self { password: password.map(str::to_owned), ..Self::default() }
    }
}

/// Why a member cannot be fed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeedUnsupported {
    /// Compressed data of a format or method without a feed decoder.
    Compressed { id: u16 },
    /// 7z data coded by its folder's coders.
    Coders,
    /// ZipCrypto: its keystream depends on every earlier byte, so a hole loses the rest of the member.
    SequentialCipher,
    /// RAR 4.x encryption other than AES-128.
    LegacyRar4Cipher,
    /// Encryption the map does not map.
    UnmappedCipher,
    /// No recorded unpacked size.
    UnknownSize,
    /// A solid member after the first of its stream, created without the state the member before it left: start it
    /// with [`FeedDecoder::next_solid`] or [`FeedDecoder::resume_solid`] (RAR 5.0). Also a hand-off of a layer without
    /// one.
    Solid,
    /// The member's dictionary is larger than [`FeedOptions::max_window`].
    Window { size: u64 },
}

/// A typed failure of a [`FeedDecoder`]. Missing bytes are never an error: they are [`FeedStatus::needs`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FeedError {
    NoSuchMember {
        index: usize,
    },
    Unsupported(FeedUnsupported),
    /// The map lists only some of the member's pieces (`complete: false`).
    IncompleteMember,
    PasswordRequired,
    WrongPassword,
    /// The key derivation failed otherwise (a limit, cancellation).
    Key(ExtractFromError),
    /// The map is inconsistent.
    Malformed(&'static str),
    /// The source broke the [`PackedSource`] contract (a `Data` count of 0 or past the buffer).
    SourceContract(&'static str),
    /// The sink failed writing output offset `out`.
    Write {
        out: u64,
        error: io::Error,
    },
    Canceled,
    /// A snapshot that does not decode or belongs to another member or layer.
    Snapshot(&'static str),
    /// An earlier run failed; the decoder is unusable (restore a snapshot instead).
    AlreadyFailed,
    /// The compressed data does not decode (at output offset `out`), or a repair did not meet the restart it was
    /// to reach.
    Decode {
        out: u64,
        error: crate::Error,
    },
    /// Restoring a compressed decoder at a checkpoint needs the output `range`, which [`FeedSink::read_held`] does
    /// not give.
    HeldOutput {
        range: Range<u64>,
    },
    /// A window reaching back into the earlier members of a solid stream needs their output `range` (stream
    /// offsets), which [`FeedSink::read_earlier`] does not give.
    EarlierOutput {
        range: Range<u64>,
    },
    /// A solid hand-off ([`FeedDecoder::next_solid`], [`FeedDecoder::resume_solid`]) that does not fit: not the next
    /// member of the stream, the main decode not finished yet, already handed over, or a carry of another stream.
    Handoff(&'static str),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchMember { index } => write!(f, "no member {index}"),
            Self::Unsupported(what) => write!(f, "member cannot be fed: {what:?}"),
            Self::IncompleteMember => f.write_str("the map lists only some of the member's pieces"),
            Self::PasswordRequired => f.write_str("password required"),
            Self::WrongPassword => f.write_str("wrong password"),
            Self::Key(e) => write!(f, "key derivation: {e}"),
            Self::Malformed(what) => write!(f, "inconsistent map: {what}"),
            Self::SourceContract(what) => write!(f, "packed source contract: {what}"),
            Self::Write { out, error } => write!(f, "writing output at {out}: {error}"),
            Self::Canceled => f.write_str("canceled"),
            Self::Snapshot(what) => write!(f, "snapshot: {what}"),
            Self::AlreadyFailed => f.write_str("the decoder failed earlier"),
            Self::Decode { out, error } => write!(f, "decoding at output {out}: {error}"),
            Self::HeldOutput { range } => write!(f, "restoring needs held output {range:?}"),
            Self::EarlierOutput { range } => write!(f, "needs earlier solid members' output {range:?}"),
            Self::Handoff(what) => write!(f, "solid hand-off: {what}"),
        }
    }
}

impl std::error::Error for FeedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(e) => Some(e),
            Self::Write { error, .. } => Some(error),
            Self::Decode { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl FeedError {
    fn from_extract(e: ExtractFromError) -> Self {
        match e {
            ExtractFromError::PasswordRequired => Self::PasswordRequired,
            ExtractFromError::WrongPassword => Self::WrongPassword,
            ExtractFromError::Malformed(what) => Self::Malformed(what),
            ExtractFromError::Unsupported(UnsupportedRead::UnmappedCipher) => {
                Self::Unsupported(FeedUnsupported::UnmappedCipher)
            }
            ExtractFromError::Source(f) if matches!(f.kind, crate::progressive::FailureKind::Canceled) => {
                Self::Canceled
            }
            other => Self::Key(other),
        }
    }
}

// ---- An in-memory article store ----

/// [`ArticleBuffer::insert`] would hold more than the buffer's limit; nothing was stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferFull {
    pub held: usize,
    pub limit: usize,
}

impl std::fmt::Display for BufferFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "article buffer full: {} of {} bytes held", self.held, self.limit)
    }
}

impl std::error::Error for BufferFull {}

#[derive(Default)]
struct VolumeBytes {
    /// start -> bytes; never overlapping
    chunks: BTreeMap<u64, Vec<u8>>,
    lost: RangeSet,
}

/// A [`PackedSource`] holding articles in memory, inserted in any order, up to a byte limit. Bytes not held are
/// [`PackedRead::NotYet`], or [`PackedRead::Hole`] inside a range marked lost; inserting them repairs it. It lets go
/// of bytes the decoder [releases](PackedSource::release).
pub struct ArticleBuffer {
    volumes: BTreeMap<u32, VolumeBytes>,
    held: usize,
    limit: usize,
}

impl ArticleBuffer {
    /// An empty buffer holding at most `limit` bytes.
    pub fn new(limit: usize) -> Self {
        Self { volumes: BTreeMap::new(), held: 0, limit }
    }

    /// Bytes held.
    pub fn held(&self) -> usize {
        self.held
    }

    /// Holds `bytes` at `offset` of volume `volume`. Bytes already held are kept as they are; a range marked lost
    /// that they cover is no longer lost. Fails, storing nothing, when the new bytes would pass the limit: the caller
    /// then holds them itself and inserts them when the decoder asks ([`NeedBytes`]).
    pub fn insert(&mut self, volume: u32, offset: u64, bytes: &[u8]) -> Result<(), BufferFull> {
        let end = offset.saturating_add(bytes.len() as u64);
        let v = self.volumes.entry(volume).or_default();
        // the gaps of what is held, inside offset..end
        let mut gaps = Vec::new();
        let mut at = offset;
        let first = v.chunks.range(..offset).next_back().map(|(&s, c)| s + c.len() as u64).filter(|&e| e > offset);
        if let Some(e) = first {
            at = e.min(end);
        }
        for (&s, c) in v.chunks.range(offset..end) {
            if s > at {
                gaps.push(at..s);
            }
            at = at.max(s + c.len() as u64);
        }
        if at < end {
            gaps.push(at..end);
        }
        let new: u64 = gaps.iter().map(|g| g.end - g.start).sum();
        let new = usize::try_from(new).unwrap_or(usize::MAX);
        if self.held.saturating_add(new) > self.limit {
            return Err(BufferFull { held: self.held, limit: self.limit });
        }
        for g in gaps {
            let piece = bytes[(g.start - offset) as usize..(g.end - offset) as usize].to_vec();
            v.chunks.insert(g.start, piece);
        }
        v.lost.remove(offset..end);
        self.held += new;
        Ok(())
    }

    /// Marks `range` of volume `volume` lost: reads of bytes not held there answer [`PackedRead::Hole`].
    pub fn mark_lost(&mut self, volume: u32, range: Range<u64>) {
        if range.start < range.end {
            self.volumes.entry(volume).or_default().lost.insert(range);
        }
    }
}

impl PackedSource for ArticleBuffer {
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> PackedRead {
        let Some(v) = self.volumes.get(&volume) else {
            return PackedRead::NotYet { len: u64::MAX - offset };
        };
        if let Some((&s, c)) = v.chunks.range(..=offset).next_back()
            && offset < s + c.len() as u64
        {
            let from = (offset - s) as usize;
            let n = (c.len() - from).min(buf.len());
            buf[..n].copy_from_slice(&c[from..from + n]);
            return PackedRead::Data(n);
        }
        let next_held = v.chunks.range(offset..).next().map_or(u64::MAX, |(&s, _)| s);
        if let Some(lost) = v.lost.containing(offset) {
            return PackedRead::Hole { len: lost.end.min(next_held) - offset };
        }
        let next_lost = v.lost.next_start(offset).unwrap_or(u64::MAX);
        PackedRead::NotYet { len: next_held.min(next_lost) - offset }
    }

    fn absent(&self, volume: u32, range: Range<u64>) -> Option<Vec<Range<u64>>> {
        let Some(v) = self.volumes.get(&volume) else { return Some(vec![range]) };
        let mut out = Vec::new();
        let mut at = range.start;
        if let Some((&s, c)) = v.chunks.range(..range.start).next_back() {
            at = at.max(s + c.len() as u64);
        }
        for (&s, c) in v.chunks.range(range.start..range.end) {
            if s > at {
                out.push(at..s);
            }
            at = at.max(s + c.len() as u64);
        }
        if at < range.end {
            out.push(at..range.end);
        }
        Some(out)
    }

    fn release(&mut self, volume: u32, range: Range<u64>) {
        let Some(v) = self.volumes.get_mut(&volume) else { return };
        let mut touched: Vec<u64> = v.chunks.range(range.start..range.end).map(|(&s, _)| s).collect();
        if let Some((&s, c)) = v.chunks.range(..range.start).next_back()
            && s + c.len() as u64 > range.start
        {
            touched.insert(0, s);
        }
        for s in touched {
            let c = v.chunks.remove(&s).expect("chunk");
            let e = s + c.len() as u64;
            self.held -= c.len();
            if s < range.start {
                let keep = c[..(range.start - s) as usize].to_vec();
                self.held += keep.len();
                v.chunks.insert(s, keep);
            }
            if e > range.end {
                let keep = c[(range.end - s) as usize..].to_vec();
                self.held += keep.len();
                v.chunks.insert(range.end, keep);
            }
        }
    }
}

// ---- Range bookkeeping ----

/// Disjoint, non-adjacent ranges: start -> end.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RangeSet(BTreeMap<u64, u64>);

impl RangeSet {
    fn insert(&mut self, r: Range<u64>) {
        if r.start >= r.end {
            return;
        }
        let (mut s, mut e) = (r.start, r.end);
        if let Some((&ps, &pe)) = self.0.range(..=s).next_back()
            && pe >= s
        {
            s = ps;
            e = e.max(pe);
        }
        let inside: Vec<u64> = self.0.range(s..=e).map(|(&k, _)| k).collect();
        for k in inside {
            e = e.max(self.0.remove(&k).expect("range"));
        }
        self.0.insert(s, e);
    }

    fn remove(&mut self, r: Range<u64>) {
        if r.start >= r.end {
            return;
        }
        let mut hit: Vec<(u64, u64)> = self.0.range(r.start..r.end).map(|(&s, &e)| (s, e)).collect();
        if let Some((&s, &e)) = self.0.range(..r.start).next_back()
            && e > r.start
        {
            hit.insert(0, (s, e));
        }
        for (s, e) in hit {
            self.0.remove(&s);
            if s < r.start {
                self.0.insert(s, r.start);
            }
            if e > r.end {
                self.0.insert(r.end, e);
            }
        }
    }

    fn containing(&self, at: u64) -> Option<Range<u64>> {
        self.0.range(..=at).next_back().filter(|&(_, &e)| e > at).map(|(&s, &e)| s..e)
    }

    fn next_start(&self, after: u64) -> Option<u64> {
        self.0.range(after..).next().map(|(&s, _)| s)
    }

    fn ranges(&self) -> Vec<Range<u64>> {
        self.0.iter().map(|(&s, &e)| s..e).collect()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// CRC32s of the output written, per run of contiguous output: start -> (end, crc).
#[derive(Clone, Debug, Default)]
struct CrcRuns {
    runs: BTreeMap<u64, (u64, u32)>,
    /// output was written twice (a broken sink contract): no verdict
    broken: bool,
}

impl CrcRuns {
    fn add(&mut self, start: u64, bytes: &[u8]) {
        if bytes.is_empty() || self.broken {
            return;
        }
        let end = start + bytes.len() as u64;
        let overlaps = self.runs.range(..end).next_back().is_some_and(|(_, &(e, _))| e > start);
        if overlaps {
            self.broken = true;
            return;
        }
        let (mut s, mut e, mut crc) = (start, end, crc32fast::hash(bytes));
        if let Some((&ps, &(pe, pc))) = self.runs.range(..start).next_back()
            && pe == start
        {
            self.runs.remove(&ps);
            crc = crate::crc32::combine(pc, crc, e - s);
            s = ps;
        }
        if let Some(&(ne, nc)) = self.runs.get(&end) {
            self.runs.remove(&end);
            crc = crate::crc32::combine(crc, nc, ne - end);
            e = ne;
        }
        self.runs.insert(s, (e, crc));
    }

    /// The CRC32 of `0..size` once it is one run.
    fn whole(&self, size: u64) -> Option<u32> {
        if self.broken {
            return None;
        }
        if size == 0 {
            return Some(0);
        }
        match self.runs.get(&0) {
            Some(&(e, crc)) if e == size => Some(crc),
            _ => None,
        }
    }
}

// ---- Geometry ----

/// One piece of the member's packed stream.
#[derive(Clone, Debug)]
struct Span {
    stream: Range<u64>,
    volume: u32,
    packed_start: u64,
}

#[derive(Clone, Debug)]
struct Geometry {
    spans: Vec<Span>,
}

impl Geometry {
    fn new(member: &MapMember) -> Self {
        let spans = member
            .pieces
            .iter()
            .filter(|p| p.packed.end > p.packed.start)
            .map(|p| Span {
                stream: p.stream_offset..p.stream_offset + (p.packed.end - p.packed.start),
                volume: p.volume,
                packed_start: p.packed.start,
            })
            .collect();
        Self { spans }
    }

    fn covered(&self) -> u64 {
        self.spans.last().map_or(0, |s| s.stream.end)
    }

    fn locate(&self, stream: u64) -> Option<&Span> {
        let i = self.spans.partition_point(|s| s.stream.end <= stream);
        self.spans.get(i).filter(|s| s.stream.start <= stream)
    }

    /// The per-volume packed ranges of a stream range, in stream order.
    fn volume_ranges(&self, stream: Range<u64>) -> Vec<(u32, Range<u64>)> {
        let mut out = Vec::new();
        let i = self.spans.partition_point(|s| s.stream.end <= stream.start);
        for s in &self.spans[i..] {
            if s.stream.start >= stream.end {
                break;
            }
            let from = stream.start.max(s.stream.start);
            let to = stream.end.min(s.stream.end);
            let at = |x: u64| s.packed_start + (x - s.stream.start);
            out.push((s.volume, at(from)..at(to)));
        }
        out
    }
}

/// Reads held output at stream offsets `range` of a member whose output starts at stream offset `start`: before the
/// member from [`FeedSink::read_earlier`], from its start on from [`FeedSink::read_held`] (member offsets). All of
/// it, or the error naming what is not held.
pub(super) fn read_stream(sink: &mut dyn FeedSink, start: u64, range: Range<u64>) -> Result<Vec<u8>, FeedError> {
    let whole = || FeedError::HeldOutput { range: range.start.saturating_sub(start)..range.end.saturating_sub(start) };
    let len = usize::try_from(range.end.saturating_sub(range.start)).map_err(|_| whole())?;
    let mut buf = vec![0; len];
    let mut got = 0;
    while got < len {
        let at = range.start + got as u64;
        let (read, limit) = if at < start {
            let limit = ((start - at).min((len - got) as u64)) as usize;
            (sink.read_earlier(at, &mut buf[got..got + limit]), limit)
        } else {
            (sink.read_held(at - start, &mut buf[got..]), len - got)
        };
        match read {
            Ok(n) if n > 0 && n <= limit => got += n,
            _ if at < start => return Err(FeedError::EarlierOutput { range: at..range.end.min(start) }),
            _ => return Err(FeedError::HeldOutput { range: at - start..range.end - start }),
        }
    }
    Ok(buf)
}

// ---- Stored layers ----

/// How stream bytes become output in a stored member.
#[derive(Clone, Copy)]
enum StoredCipher {
    Plain,
    Cbc { aes: AesKey, iv: [u8; 16] },
    Ctr { aes: AesKey, skip: u64 },
}

/// A reader of a stretch of the packed stream that writes the output it carries.
#[derive(Clone, Debug)]
struct Lane {
    /// stream offset of the next byte to read
    pos: u64,
    /// stream offset to stop reading at
    end: u64,
    /// CBC: stream (and output) offset of `rem[0]`, block aligned; otherwise unused
    next: u64,
    /// CBC: the IV of the block at `next`, once read
    iv: Option<[u8; 16]>,
    /// CBC: ciphertext short of a block, or the IV block being collected
    rem: Vec<u8>,
}

/// Why a lane stopped.
enum Stop {
    /// It read to its end.
    Reached,
    /// Stream bytes `stream..stream + len` are not there (`hole`: lost, else not yet).
    Missing { stream: u64, len: u64, hole: bool },
    /// The run's output budget is spent.
    Budget,
}

/// Which layer a decoder decodes, for snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayerTag {
    Plain = 1,
    Cbc = 2,
    Ctr = 3,
    Rar5 = 4,
    Lzma2 = 5,
    Rar4 = 6,
}

/// A feed-driven decoder of one member. See the module docs and `docs/feed-decoder.md`.
///
/// Supported: stored members whose output maps directly to packed offsets (plain stored RAR, ZIP and 7z Copy;
/// AES-CBC stored RAR 5.0, RAR 4.x and 7zAES over Copy; WinZip AES stored). A hole costs exactly its own output
/// (widened to whole blocks, plus one block, under CBC), and repairing it reads and writes only that.
pub struct FeedDecoder {
    size: u64,
    stream_len: u64,
    geometry: Geometry,
    cipher: StoredCipher,
    tag: LayerTag,
    /// the member's CRC32 as the output's CRC32 compares to it
    want_crc: Option<u32>,
    hash_key: Option<[u8; 32]>,
    keyed: bool,
    main: Option<Lane>,
    lost: RangeSet,
    /// lost output start -> the stream offset its repair stopped at in the last run
    blocked: BTreeMap<u64, u64>,
    crc: CrcRuns,
    stats: FeedStats,
    /// stream ranges released to the source
    released: RangeSet,
    /// the member's fingerprint, binding snapshots to it
    identity: u64,
    options: FeedOptions,
    buf: Vec<u8>,
    scratch: Vec<u8>,
    run_written: u64,
    failed: bool,
    status: FeedStatus,
    /// the member's index in the map
    index: usize,
    /// where the member's output starts in its solid stream's (RAR) output; 0 otherwise
    stream_start: u64,
    /// output written was decoded from a window not proven yet ([`FeedStatus::unproven`])
    unproven: bool,
    /// a compressed RAR 5.0 member's decoder state
    rar5: Option<Box<rar5::Rar5>>,
    /// a 7z LZMA2 folder member's decoder state
    lzma2: Option<Box<lzma2::Lz>>,
    /// a compressed RAR 4.x member's decoder state
    rar4: Option<Box<rar4::Rar4>>,
}

impl std::fmt::Debug for FeedDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedDecoder")
            .field("size", &self.size)
            .field("layer", &self.tag)
            .field("status", &self.status)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl FeedDecoder {
    /// A decoder of member `index` of `map`. Derives the member's key now (when encrypted), so a wrong password
    /// shows here where the member records a check value.
    pub fn new(map: &MemberMap, index: usize, options: FeedOptions) -> Result<Self, FeedError> {
        Self::new_begin(map, index, options, Begin::Fresh)
    }

    fn new_begin(map: &MemberMap, index: usize, options: FeedOptions, begin: Begin) -> Result<Self, FeedError> {
        let mut d = Self::new_inner(map, index, options, begin)?;
        d.index = index;
        Ok(d)
    }

    fn new_inner(map: &MemberMap, index: usize, options: FeedOptions, begin: Begin) -> Result<Self, FeedError> {
        let member = map.members.get(index).ok_or(FeedError::NoSuchMember { index })?;
        if matches!(member.method, MapMethod::Compressed { .. }) && map.format == super::MapFormat::Rar5 {
            return Self::new_rar5(map, index, options, begin);
        }
        if matches!(member.method, MapMethod::Compressed { .. }) && map.format == super::MapFormat::Rar4 {
            return Self::new_rar4(map, index, options, begin);
        }
        if member.method == MapMethod::Coders && map.format == super::MapFormat::SevenZip {
            return Self::new_lzma2(map, member, options, begin);
        }
        if !matches!(begin, Begin::Fresh | Begin::Restore) {
            return Err(FeedError::Unsupported(FeedUnsupported::Solid));
        }
        match member.method {
            MapMethod::Compressed { id } => return Err(FeedError::Unsupported(FeedUnsupported::Compressed { id })),
            MapMethod::Coders => return Err(FeedError::Unsupported(FeedUnsupported::Coders)),
            MapMethod::Stored => {}
        }
        let mapping = member.mapping;
        let tag = match mapping {
            OutputMapping::Direct => LayerTag::Plain,
            OutputMapping::CbcBlocks => LayerTag::Cbc,
            OutputMapping::Counter { .. } => LayerTag::Ctr,
            OutputMapping::Sequential { .. } => {
                return Err(FeedError::Unsupported(FeedUnsupported::SequentialCipher));
            }
            OutputMapping::None => {
                return Err(FeedError::Unsupported(match member.cipher {
                    Some(CipherParams::Rar4Legacy { .. }) => FeedUnsupported::LegacyRar4Cipher,
                    _ => FeedUnsupported::UnmappedCipher,
                }));
            }
        };
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        validate(member, mapping, size).map_err(FeedError::from_extract)?;
        if !member.complete {
            return Err(FeedError::IncompleteMember);
        }
        let overflow = FeedError::Malformed("member size overflows");
        let stream_len = match mapping {
            OutputMapping::CbcBlocks => size.checked_next_multiple_of(16).ok_or(overflow)?,
            OutputMapping::Counter { skip } => skip.checked_add(size).ok_or(overflow)?,
            _ => size,
        };
        let geometry = Geometry::new(member);
        if geometry.covered() < stream_len {
            return Err(FeedError::IncompleteMember);
        }
        let usage = Usage::new(options.limits.clone());
        let mut hash_key = None;
        // an empty member needs no key, unless its CRC is keyed with the password
        let keyed_crc = member.checks.is_some_and(|c| c.keyed && c.crc32.is_some());
        let cipher = if member.encrypted && (size > 0 || keyed_crc) {
            let keys =
                derive_keys(member, mapping, options.password.as_deref(), &options.limits, &usage, &options.control)
                    .map_err(FeedError::from_extract)?;
            hash_key = keys.hash_key;
            match keys.key {
                MemberKey::Cbc { aes, iv } => StoredCipher::Cbc { aes, iv },
                MemberKey::Ctr { aes, skip, .. } => StoredCipher::Ctr { aes, skip },
                MemberKey::None | MemberKey::ZipCrypto { .. } => {
                    return Err(FeedError::Malformed("cipher parameters do not match the output mapping"));
                }
            }
        } else {
            match mapping {
                // an empty encrypted member needs no key: nothing is read
                OutputMapping::Counter { skip } => StoredCipher::Ctr { aes: AesKey::new(&[0; 16]).expect("key"), skip },
                OutputMapping::CbcBlocks => StoredCipher::Cbc { aes: AesKey::new(&[0; 16]).expect("key"), iv: [0; 16] },
                _ => StoredCipher::Plain,
            }
        };
        let checks = member.checks.filter(|c| c.crc32.is_some());
        let chunk = options.read_chunk.clamp(16, 64 << 20);
        let mut decoder = Self {
            size,
            stream_len,
            geometry,
            cipher,
            tag,
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
            index: 0,
            stream_start: 0,
            unproven: false,
            rar5: None,
            lzma2: None,
            rar4: None,
        };
        if size > 0 {
            decoder.main = Some(decoder.lane_at(0, size));
        }
        decoder.status = decoder.make_status(Vec::new(), false);
        Ok(decoder)
    }

    /// The member's output size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The status as of the last run (or construction).
    pub fn status(&self) -> &FeedStatus {
        &self.status
    }

    /// Work counters.
    pub fn stats(&self) -> FeedStats {
        self.stats
    }

    /// Reads what the source holds and writes the output it allows: the main decode in order as far as the bytes
    /// are contiguous (skipping holes), then repairs of lost output whose bytes are back. Never waits.
    pub fn run(&mut self, source: &mut dyn PackedSource, sink: &mut dyn FeedSink) -> Result<FeedStatus, FeedError> {
        if self.failed {
            return Err(FeedError::AlreadyFailed);
        }
        let result = self.run_inner(source, sink);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn run_inner(&mut self, source: &mut dyn PackedSource, sink: &mut dyn FeedSink) -> Result<FeedStatus, FeedError> {
        self.run_written = 0;
        let mut next = Vec::new();
        let mut repair = Vec::new();
        let mut more = false;
        let mut next_gap = None;
        if self.rar5.is_some() {
            (next, repair, more, next_gap) = self.run_rar5(source, sink)?;
        }
        if self.lzma2.is_some() {
            (next, repair, more, next_gap) = self.run_lzma2(source, sink)?;
        }
        if self.rar4.is_some() {
            (next, repair, more, next_gap) = self.run_rar4(source, sink)?;
        }
        // the main decode
        while !self.layered()
            && let Some(mut lane) = self.main.take()
        {
            match self.pump(&mut lane, source, sink)? {
                Stop::Reached => break,
                Stop::Budget => {
                    self.main = Some(lane);
                    more = true;
                    break;
                }
                Stop::Missing { stream, len, hole: false } => {
                    self.push_needs(&mut next, stream..stream + len, NeedKind::Next);
                    next_gap = Some(stream + len..lane.end);
                    self.main = Some(lane);
                    break;
                }
                Stop::Missing { stream, len, hole: true } => {
                    self.stats.holes += 1;
                    let from = self.lane_out(&lane);
                    let restart = self.restart_after(stream + len);
                    self.lost.insert(from..restart);
                    if restart < self.size {
                        self.main = Some(self.lane_at(restart, self.size));
                    }
                }
            }
        }
        // repairs
        if !more && !self.layered() {
            let blocked = std::mem::take(&mut self.blocked);
            'repairs: for range in self.lost.ranges() {
                let mut at = range.start;
                while at < range.end {
                    let mut lane = self.lane_at(at, range.end);
                    // a repair that stopped at missing bytes last time waits there until they come, without reading
                    // again what it read before them
                    if let Some(&stream) = blocked.get(&at)
                        && let Some(len) = self.probe(stream, lane.end, source)?
                    {
                        self.blocked.insert(at, stream);
                        self.push_needs(&mut repair, stream..stream + len, NeedKind::Repair);
                        at = self.restart_after(stream + len).max(at + 1);
                        continue;
                    }
                    match self.pump(&mut lane, source, sink)? {
                        Stop::Reached => {
                            self.lost.remove(at..range.end);
                            break;
                        }
                        Stop::Budget => {
                            self.lost.remove(at..self.lane_out(&lane));
                            more = true;
                            break 'repairs;
                        }
                        Stop::Missing { stream, len, .. } => {
                            let reached = self.lane_out(&lane);
                            self.lost.remove(at..reached);
                            self.blocked.insert(reached, stream);
                            self.push_needs(&mut repair, stream..stream + len, NeedKind::Repair);
                            at = self.restart_after(stream + len).max(reached);
                        }
                    }
                }
            }
        }
        let mut needs = next;
        needs.extend(repair);
        if let Some(gap) = next_gap {
            for (volume, range) in self.geometry.volume_ranges(gap) {
                if needs.len() >= self.options.max_needs {
                    break;
                }
                for r in source.absent(volume, range).unwrap_or_default() {
                    needs.push(NeedBytes { volume, range: r, kind: NeedKind::Ahead });
                }
            }
        }
        needs.truncate(self.options.max_needs);
        self.release(source);
        self.status = self.make_status(needs, more);
        Ok(self.status.clone())
    }

    /// Whether stream byte `stream` is still missing, and for how long (up to `end`), without consuming it.
    fn probe(&mut self, stream: u64, end: u64, source: &mut dyn PackedSource) -> Result<Option<u64>, FeedError> {
        let span = self.geometry.locate(stream).ok_or(FeedError::Malformed("stream offset outside the pieces"))?;
        let left = span.stream.end.min(end).saturating_sub(stream).max(1);
        let mut one = [0u8; 1];
        match source.read_packed(span.volume, span.packed_start + (stream - span.stream.start), &mut one) {
            PackedRead::Data(1) => Ok(None),
            PackedRead::Data(_) => Err(FeedError::SourceContract("Data count of 0 or past the buffer")),
            PackedRead::NotYet { len } | PackedRead::Hole { len } => Ok(Some(len.clamp(1, left))),
        }
    }

    fn push_needs(&self, out: &mut Vec<NeedBytes>, stream: Range<u64>, kind: NeedKind) {
        for (volume, range) in self.geometry.volume_ranges(stream) {
            out.push(NeedBytes { volume, range, kind });
        }
    }

    /// Whether a compressed layer decodes the member (rather than the stored lanes).
    fn layered(&self) -> bool {
        self.rar5.is_some() || self.lzma2.is_some() || self.rar4.is_some()
    }

    fn make_status(&self, needs: Vec<NeedBytes>, more: bool) -> FeedStatus {
        let frontier = match (&self.rar5, &self.lzma2, &self.rar4) {
            (Some(r), _, _) => r.frontier(),
            (_, Some(l), _) => l.frontier(),
            (_, _, Some(r)) if self.main.is_some() => r.frontier(),
            _ => self.main.as_ref().map_or(self.size, |l| self.lane_out(l)),
        };
        let done = self.main.is_none() && self.lost.is_empty() && self.lzma2.as_ref().is_none_or(|l| l.done());
        let crc_ok = if done {
            self.want_crc.and_then(|want| {
                let crc = self.crc.whole(self.size)?;
                let crc = match (self.keyed, &self.hash_key) {
                    (true, Some(k)) => crate::crypto::rar5_tweak_crc32(crc, k),
                    _ => crc,
                };
                Some(crc == want)
            })
        } else {
            None
        };
        let stalled = self.rar5.as_ref().is_some_and(|r| r.stalled())
            || self.lzma2.as_ref().is_some_and(|l| l.stalled())
            || self.rar4.as_ref().is_some_and(|r| r.stalled());
        let unproven = self.unproven && !(done && crc_ok == Some(true));
        FeedStatus { frontier, lost: self.lost.ranges(), needs, more, done, stalled, crc_ok, unproven }
    }

    /// Tells the source which stream bytes no lane will read again: everything before the main decode except what
    /// the repairs of lost ranges read.
    fn release(&mut self, source: &mut dyn PackedSource) {
        let mut keep = RangeSet::default();
        if let Some(r) = &self.rar5 {
            for range in r.needed(self) {
                keep.insert(range);
            }
        } else if let Some(l) = &self.lzma2 {
            for range in l.needed(matches!(self.cipher, StoredCipher::Cbc { .. })) {
                keep.insert(range);
            }
        } else if self.rar4.is_some() {
            // nothing before the main decode is read again (a restore reads the member from its start again)
            if let Some(l) = &self.main {
                keep.insert(l.pos..self.stream_len);
            }
        } else {
            if let Some(l) = &self.main {
                // a lane restored from a snapshot reads again from the start of its partial block; a CBC lane keeps
                // the block before it too, though it holds that IV itself: a hole met inside the partial block
                // starts its lost range there, and the repair reads its IV from the source
                let from = match (self.cipher, l.iv) {
                    (StoredCipher::Cbc { .. }, Some(_)) => l.next.saturating_sub(16),
                    (StoredCipher::Cbc { .. }, None) => self.lane_at(l.next, self.size).pos,
                    _ => l.pos,
                };
                keep.insert(from..self.stream_len);
            }
            for r in self.lost.ranges() {
                let lane = self.lane_at(r.start, r.end);
                keep.insert(lane.pos..lane.end);
            }
        }
        let mut free = RangeSet::default();
        free.insert(0..self.stream_len);
        for r in keep.ranges().into_iter().chain(self.released.ranges()) {
            free.remove(r);
        }
        for r in free.ranges() {
            for (volume, range) in self.geometry.volume_ranges(r.clone()) {
                source.release(volume, range);
            }
            self.released.insert(r);
        }
    }

    /// A lane that writes output `out..out_end` (`out` block aligned under CBC).
    fn lane_at(&self, out: u64, out_end: u64) -> Lane {
        match self.cipher {
            StoredCipher::Plain => Lane { pos: out, end: out_end, next: out, iv: None, rem: Vec::new() },
            StoredCipher::Ctr { skip, .. } => {
                Lane { pos: out + skip, end: out_end + skip, next: out, iv: None, rem: Vec::new() }
            }
            StoredCipher::Cbc { iv, .. } => {
                let end = out_end.checked_next_multiple_of(16).unwrap_or(u64::MAX).min(self.stream_len);
                if out == 0 {
                    Lane { pos: 0, end, next: 0, iv: Some(iv), rem: Vec::new() }
                } else {
                    Lane { pos: out - 16, end, next: out, iv: None, rem: Vec::new() }
                }
            }
        }
    }

    /// The output offset a lane has written up to.
    fn lane_out(&self, lane: &Lane) -> u64 {
        let out = match self.cipher {
            StoredCipher::Plain => lane.pos,
            StoredCipher::Ctr { skip, .. } => lane.pos.saturating_sub(skip),
            StoredCipher::Cbc { .. } => lane.next,
        };
        out.min(self.size)
    }

    /// The first output offset decodable once stream bytes before `stream_end` are missing.
    fn restart_after(&self, stream_end: u64) -> u64 {
        let out = match self.cipher {
            StoredCipher::Plain => stream_end,
            StoredCipher::Ctr { skip, .. } => stream_end.saturating_sub(skip),
            // the block after the missing bytes is the IV of the one after it
            StoredCipher::Cbc { .. } => stream_end.checked_next_multiple_of(16).unwrap_or(u64::MAX).saturating_add(16),
        };
        out.min(self.size)
    }

    /// Reads and decodes a lane until it ends, misses bytes or spends the run's budget.
    fn pump(
        &mut self,
        lane: &mut Lane,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Stop, FeedError> {
        let mut buf = std::mem::take(&mut self.buf);
        let result = self.pump_with(lane, source, sink, &mut buf);
        self.buf = buf;
        result
    }

    fn pump_with(
        &mut self,
        lane: &mut Lane,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        buf: &mut [u8],
    ) -> Result<Stop, FeedError> {
        loop {
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            if lane.pos >= lane.end {
                return Ok(Stop::Reached);
            }
            if self.options.run_budget.is_some_and(|b| self.run_written >= b) {
                return Ok(Stop::Budget);
            }
            let span =
                self.geometry.locate(lane.pos).ok_or(FeedError::Malformed("stream offset outside the pieces"))?;
            let left = (span.stream.end.min(lane.end) - lane.pos).min(buf.len() as u64) as usize;
            let (volume, packed) = (span.volume, span.packed_start + (lane.pos - span.stream.start));
            let piece_left = span.stream.end.min(lane.end) - lane.pos;
            match source.read_packed(volume, packed, &mut buf[..left]) {
                PackedRead::Data(n) => {
                    if n == 0 || n > left {
                        return Err(FeedError::SourceContract("Data count of 0 or past the buffer"));
                    }
                    let at = lane.pos;
                    lane.pos += n as u64;
                    self.stats.packed_read += n as u64;
                    self.absorb(lane, at, &mut buf[..n], sink)?;
                }
                PackedRead::NotYet { len } => {
                    return Ok(Stop::Missing { stream: lane.pos, len: len.clamp(1, piece_left), hole: false });
                }
                PackedRead::Hole { len } => {
                    return Ok(Stop::Missing { stream: lane.pos, len: len.clamp(1, piece_left), hole: true });
                }
            }
        }
    }

    /// Decodes stream bytes `bytes` read at stream offset `at` and writes their output.
    fn absorb(&mut self, lane: &mut Lane, at: u64, bytes: &mut [u8], sink: &mut dyn FeedSink) -> Result<(), FeedError> {
        match self.cipher {
            StoredCipher::Plain => self.emit(at, bytes, sink),
            StoredCipher::Ctr { aes, skip } => {
                ctr_xor(&aes, at - skip, bytes);
                self.emit(at - skip, bytes, sink)
            }
            StoredCipher::Cbc { aes, .. } => {
                let mut scratch = std::mem::take(&mut self.scratch);
                let out = cbc_step(&aes, lane, bytes, &mut scratch);
                let result = self.emit(out, &scratch, sink);
                self.scratch = scratch;
                result
            }
        }
    }

    /// Writes output at `out`, clipped to the member.
    fn emit(&mut self, out: u64, bytes: &[u8], sink: &mut dyn FeedSink) -> Result<(), FeedError> {
        let end = (out + bytes.len() as u64).min(self.size);
        if out >= end {
            return Ok(());
        }
        let bytes = &bytes[..(end - out) as usize];
        sink.write_at(out, bytes).map_err(|error| FeedError::Write { out, error })?;
        self.crc.add(out, bytes);
        self.stats.written += bytes.len() as u64;
        self.run_written += bytes.len() as u64;
        Ok(())
    }

    /// The decoder's state, to restore later ([`Self::restore`]) or keep across a restart
    /// ([`FeedSnapshot::to_bytes`]). Taken between runs, it resumes exactly where the decoder stands: the main
    /// decode at its frontier (bytes read past it, short of a block, are read again) and every lost range still
    /// lost.
    pub fn snapshot(&self) -> FeedSnapshot {
        FeedSnapshot {
            tag: self.tag as u8,
            size: self.size,
            stream_len: self.stream_len,
            want_crc: self.want_crc,
            main: self.main.as_ref().map(|l| match self.cipher {
                StoredCipher::Cbc { .. } => (l.next, l.iv),
                _ => (l.pos, None),
            }),
            lost: self.lost.ranges(),
            crc: self.crc.runs.iter().map(|(&s, &(e, c))| (s, e, c)).collect(),
            crc_broken: self.crc.broken,
            stats: self.stats,
            identity: self.identity,
            unproven: self.unproven,
            layer: match (&self.rar5, &self.lzma2, &self.rar4) {
                (Some(r), _, _) => Some(r.to_bytes()),
                (_, Some(l), _) => Some(l.to_bytes()),
                (_, _, Some(r)) => Some(r.to_bytes()),
                _ => None,
            },
        }
    }

    /// A decoder of member `index` of `map` in the state `snapshot` recorded. The key is derived again from
    /// `options`; the snapshot never holds keys or plaintext.
    pub fn restore(
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
        snapshot: &FeedSnapshot,
    ) -> Result<Self, FeedError> {
        let mut d = Self::new_begin(map, index, options, Begin::Restore)?;
        if snapshot.tag != d.tag as u8 {
            return Err(FeedError::Snapshot("another layer"));
        }
        if snapshot.identity != d.identity
            || snapshot.size != d.size
            || snapshot.stream_len != d.stream_len
            || snapshot.want_crc != d.want_crc
        {
            return Err(FeedError::Snapshot("another member"));
        }
        let size = d.size;
        let bad = || FeedError::Snapshot("out of range");
        if let Some(r) = d.rar5.as_mut() {
            let blob = snapshot.layer.as_deref().ok_or(FeedError::Snapshot("no RAR 5.0 state"))?;
            r.restore(blob, size, d.stream_len)?;
            if snapshot.main.is_none() {
                d.main = None;
            }
        }
        if let Some(l) = d.lzma2.as_mut() {
            l.restore(snapshot.layer.as_deref().ok_or(FeedError::Snapshot("no LZMA2 state"))?)?;
        }
        if let Some(r) = d.rar4.as_mut() {
            r.restore(snapshot.layer.as_deref().ok_or(FeedError::Snapshot("no RAR 4.x state"))?, size)?;
            if snapshot.main.is_none() {
                d.main = None;
            }
        }
        d.main = match snapshot.main {
            _ if d.layered() => d.main.take(),
            None => None,
            Some((at, iv)) => Some(match d.cipher {
                StoredCipher::Cbc { .. } => {
                    if at % 16 != 0 || at >= size {
                        return Err(bad());
                    }
                    let mut lane = d.lane_at(at, size);
                    if let Some(iv) = iv {
                        lane.pos = at;
                        lane.iv = Some(iv);
                    }
                    lane
                }
                StoredCipher::Ctr { skip, .. } => {
                    if at < skip || at - skip >= size {
                        return Err(bad());
                    }
                    d.lane_at(at - skip, size)
                }
                StoredCipher::Plain => {
                    if at >= size {
                        return Err(bad());
                    }
                    d.lane_at(at, size)
                }
            }),
        };
        let mut lost = RangeSet::default();
        for r in &snapshot.lost {
            let aligned = !matches!(d.cipher, StoredCipher::Cbc { .. }) || r.start % 16 == 0 || d.layered();
            if r.start >= r.end || r.end > size || !aligned {
                return Err(bad());
            }
            lost.insert(r.clone());
        }
        d.lost = lost;
        let mut crc = CrcRuns { broken: snapshot.crc_broken, ..CrcRuns::default() };
        for &(s, e, c) in &snapshot.crc {
            if s >= e || e > size {
                return Err(bad());
            }
            crc.runs.insert(s, (e, c));
        }
        d.crc = crc;
        d.stats = snapshot.stats;
        d.unproven = snapshot.unproven;
        d.status = d.make_status(Vec::new(), false);
        Ok(d)
    }

    /// Where the member's output starts in its solid stream's output ([`FeedSink::read_earlier`] offsets count from
    /// there): for RAR the sizes of the compressed members before it back to the stream's first; 0 for a member that
    /// is not a solid successor, and for other formats.
    pub fn stream_start(&self) -> u64 {
        self.stream_start
    }

    /// A decoder of member `index`, the next member of this one's RAR 5.0 solid stream, going on from this decoder's
    /// state: the decoder with its window, tables and match history, so nothing before the new member is decoded
    /// again. Once this decoder's main decode has finished (its frontier at its size), however
    /// its repairs stand: this decoder keeps its lost ranges and repairs them as before, and the new one reads from
    /// where this one stopped.
    ///
    /// The new decoder is [`FeedStatus::unproven`] while this one is not done with its CRC matched and this one
    /// skipped a hole over held output (or failed its CRC). A RAR 5.0 decoder restored from a snapshot after it
    /// finished hands over from the state it saved at its end (as [`Self::resume_solid`]); others refuse
    /// ([`FeedError::Handoff`]).
    pub fn next_solid(&mut self, map: &MemberMap, index: usize, options: FeedOptions) -> Result<Self, FeedError> {
        if self.rar5.is_some() {
            return self.handoff_rar5(map, index, options);
        }
        Err(FeedError::Unsupported(FeedUnsupported::Solid))
    }

    /// Whether the output this decoder hands to a solid successor was decoded from an unproven window.
    fn carried_unproven(&self) -> bool {
        let s = &self.status;
        match (s.done, s.crc_ok) {
            (true, Some(true)) => false,
            (true, Some(false)) => true,
            _ => self.unproven,
        }
    }

    /// RAR 5.0: the state a solid successor starts from, once this member's main decode has finished (and kept in
    /// this decoder's snapshots from then on): the decoder state between this member's last block and the next
    /// member's first, without the window. [`Self::resume_solid`] starts the next member from it, in this process or
    /// a later one, reading the window back from the earlier members' output ([`FeedSink::read_earlier`]). None
    /// before then, for a member with no solid successor, and for other layers.
    pub fn solid_carry(&self) -> Option<SolidCarry> {
        let r = self.rar5.as_ref()?;
        r.carry_blob().map(|(next_start, cp)| SolidCarry {
            tag: LayerTag::Rar5 as u8,
            next_start,
            unproven: self.carried_unproven(),
            cp,
        })
    }

    /// A decoder of member `index`, a RAR 5.0 solid successor, starting from `carry` (taken from the member before
    /// it with [`Self::solid_carry`]). Its first run reads the window (the dictionary's worth of output before the
    /// member) back from [`FeedSink::read_earlier`], and fails with [`FeedError::EarlierOutput`] when it is not held.
    /// The decoder state is exact, so the output is as proven as the earlier members' output it copies from (see
    /// [`SolidCarry::unproven`]).
    pub fn resume_solid(
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
        carry: &SolidCarry,
    ) -> Result<Self, FeedError> {
        if carry.tag != LayerTag::Rar5 as u8 {
            return Err(FeedError::Handoff("a carry of another layer"));
        }
        let mut d = Self::new_begin(map, index, options, Begin::Carry(carry.clone()))?;
        d.unproven = carry.unproven;
        d.status = d.make_status(Vec::new(), false);
        Ok(d)
    }
}

/// How a decoder starts.
enum Begin {
    /// at the member's start
    Fresh,
    /// in [`FeedDecoder::restore`]: the snapshot gives the state
    Restore,
    /// a RAR 5.0 solid successor from a carry
    Carry(SolidCarry),
    /// a RAR 5.0 solid successor going on from the decoder of the member before
    Rar5(Box<crate::rar5::unpack::Unpacker>, SolidCarry),
}

/// The state a RAR 5.0 solid successor starts from ([`FeedDecoder::solid_carry`]): about 500 bytes, no plaintext
/// or keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolidCarry {
    tag: u8,
    /// the successor's start in the solid stream's output
    next_start: u64,
    unproven: bool,
    /// the decoder state at the successor's start
    cp: Vec<u8>,
}

const CARRY_MAGIC: &[u8; 4] = b"ZFSC";

impl SolidCarry {
    /// Where the next member starts in the solid stream's output.
    pub fn next_start(&self) -> u64 {
        self.next_start
    }

    /// Whether the earlier members' output was unproven when it was taken: a hole skipped over held output whose
    /// member was not done with its CRC matched yet. The successor reports [`FeedStatus::unproven`] then.
    pub fn unproven(&self) -> bool {
        self.unproven
    }

    /// The serialized form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + self.cp.len());
        out.extend_from_slice(CARRY_MAGIC);
        out.push(1);
        out.push(self.tag);
        out.extend_from_slice(&self.next_start.to_le_bytes());
        out.push(u8::from(self.unproven));
        out.extend_from_slice(&(self.cp.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.cp);
        out
    }

    /// Decodes [`Self::to_bytes`]; [`FeedDecoder::resume_solid`] checks it against the member.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FeedError> {
        let mut r = Reader(bytes);
        if r.take(4)? != CARRY_MAGIC {
            return Err(FeedError::Snapshot("not a solid carry"));
        }
        if r.u8()? != 1 {
            return Err(FeedError::Snapshot("unknown version"));
        }
        let tag = r.u8()?;
        let next_start = r.u64()?;
        let unproven = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(FeedError::Snapshot("bad flag")),
        };
        let n = usize::try_from(r.u64()?).map_err(|_| FeedError::Snapshot("bad count"))?;
        let cp = r.take(n)?.to_vec();
        if !r.0.is_empty() {
            return Err(FeedError::Snapshot("trailing bytes"));
        }
        Ok(Self { tag, next_start, unproven, cp })
    }
}

/// A member's place in its RAR solid stream.
struct SolidRun {
    /// the member's start in the stream's output
    start: u64,
    /// the starts of the stream's members up to this one, ascending (this one's last)
    starts: Vec<u64>,
    /// the compressed member before this one in the stream, when this one is a solid successor
    prev: Option<usize>,
    /// a solid member follows this one
    successor: bool,
    /// the largest dictionary of the stream's members
    dictionary: Option<u64>,
}

/// Where member `index` lies in its RAR solid stream. Only compressed files take part (directories and stored
/// members pass the decoder by, as extraction treats them); a compressed member without the solid flag starts a
/// new stream.
fn solid_run(map: &MemberMap, index: usize) -> Result<SolidRun, FeedError> {
    let decodes = |m: &MapMember| !m.is_dir && matches!(m.method, MapMethod::Compressed { .. });
    let members = &map.members;
    let mut first = index;
    if members[index].solid {
        for i in (0..index).rev() {
            if decodes(&members[i]) {
                first = i;
                if !members[i].solid {
                    break;
                }
            }
        }
    }
    let mut starts = Vec::new();
    let mut at = 0u64;
    let mut prev = None;
    for (i, m) in members.iter().enumerate().take(index).skip(first) {
        if !decodes(m) {
            continue;
        }
        starts.push(at);
        prev = Some(i);
        let size = m.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        at = at.checked_add(size).ok_or(FeedError::Malformed("solid stream size overflows"))?;
    }
    starts.push(at);
    // the stream runs on to the last solid member after this one; its window fits the largest dictionary
    let mut dictionary = None;
    for (i, m) in members.iter().enumerate().skip(first) {
        if i != index && !decodes(m) {
            continue;
        }
        if i > index && !m.solid {
            break;
        }
        dictionary = dictionary.max(m.dictionary);
    }
    let successor = members[index + 1..].iter().find(|m| decodes(m)).is_some_and(|m| m.solid);
    Ok(SolidRun { start: at, starts, prev, successor, dictionary })
}

/// [`member_identity`] of a solid successor, bound to its place in the stream too (the sizes before it).
fn solid_identity(m: &MapMember, stream_start: u64) -> u64 {
    let h = member_identity(m);
    if stream_start == 0 { h } else { (h ^ stream_start).wrapping_mul(0x0000_0100_0000_01b3) }
}

/// A fingerprint of a member as the map describes it (name, sizes, method, cipher parameters and where its pieces
/// lie), so a snapshot restores only onto the member it was taken of: FNV-1a over those fields.
fn member_identity(m: &MapMember) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let mut eat = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    eat(&(m.raw_name.len() as u64).to_le_bytes());
    eat(&m.raw_name);
    eat(&m.unpacked_size.unwrap_or(u64::MAX).to_le_bytes());
    eat(&m.packed_size.to_le_bytes());
    eat(format!("{:?}|{:?}|{:?}|{:?}", m.method, m.mapping, m.cipher, m.checks).as_bytes());
    for p in &m.pieces {
        for v in [u64::from(p.volume), p.packed.start, p.packed.end, p.stream_offset] {
            eat(&v.to_le_bytes());
        }
    }
    h
}

/// Decrypts CBC stream bytes read by `lane` into `scratch` (cleared first): whole blocks only, the rest kept in the
/// lane, the first 16 bytes after a restart taken as the IV. Returns the stream offset of `scratch[0]`.
fn cbc_step(aes: &AesKey, lane: &mut Lane, mut bytes: &[u8], scratch: &mut Vec<u8>) -> u64 {
    scratch.clear();
    if lane.iv.is_none() {
        let take = (16 - lane.rem.len()).min(bytes.len());
        lane.rem.extend_from_slice(&bytes[..take]);
        bytes = &bytes[take..];
        if lane.rem.len() < 16 {
            return lane.next;
        }
        lane.iv = Some(lane.rem[..].try_into().expect("one block"));
        lane.rem.clear();
    }
    scratch.extend_from_slice(&lane.rem);
    scratch.extend_from_slice(bytes);
    let aligned = scratch.len() & !15;
    lane.rem.clear();
    lane.rem.extend_from_slice(&scratch[aligned..]);
    scratch.truncate(aligned);
    aes.decrypt_cbc_in_place(lane.iv.as_mut().expect("IV known"), scratch);
    let out = lane.next;
    lane.next += aligned as u64;
    out
}

/// XORs WinZip AES keystream into `data`, whose first byte is ciphertext offset `offset` (after the salt and
/// verifier). Blocks count from 1, little-endian.
fn ctr_xor(aes: &AesKey, mut offset: u64, data: &mut [u8]) {
    let mut done = 0;
    while done < data.len() {
        let block = offset / 16;
        let within = (offset % 16) as usize;
        let keystream = aes.encrypt_block(&(u128::from(block) + 1).to_le_bytes());
        let take = (16 - within).min(data.len() - done);
        for (byte, key) in data[done..done + take].iter_mut().zip(&keystream[within..]) {
            *byte ^= key;
        }
        done += take;
        offset += take as u64;
    }
}

/// A [`FeedDecoder`]'s saved state: positions, lost ranges and running CRCs, never keys or plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedSnapshot {
    tag: u8,
    size: u64,
    stream_len: u64,
    want_crc: Option<u32>,
    /// the main lane: its stream position (CBC: its block-aligned output and the IV of that block)
    main: Option<(u64, Option<[u8; 16]>)>,
    lost: Vec<Range<u64>>,
    crc: Vec<(u64, u64, u32)>,
    crc_broken: bool,
    stats: FeedStats,
    /// the member's fingerprint ([`member_identity`])
    identity: u64,
    /// [`FeedStatus::unproven`] before done
    unproven: bool,
    /// a compressed layer's state: RAR 5.0 checkpoints and repairs, LZMA2 restart points and repairs
    layer: Option<Vec<u8>>,
}

const SNAPSHOT_MAGIC: &[u8; 4] = b"ZFFD";
const SNAPSHOT_VERSION: u8 = 3;
/// The most lost ranges or CRC runs a snapshot may list.
const SNAPSHOT_MAX_RANGES: u64 = 1 << 20;

impl FeedSnapshot {
    /// Output ranges lost when it was taken.
    pub fn lost(&self) -> &[Range<u64>] {
        &self.lost
    }

    /// The serialized form, for keeping across a restart.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + 16 * self.lost.len() + 20 * self.crc.len());
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.push(SNAPSHOT_VERSION);
        out.push(self.tag);
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.stream_len.to_le_bytes());
        match self.want_crc {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.to_le_bytes());
            }
            None => out.push(0),
        }
        match self.main {
            None => out.push(0),
            Some((at, None)) => {
                out.push(1);
                out.extend_from_slice(&at.to_le_bytes());
            }
            Some((at, Some(iv))) => {
                out.push(2);
                out.extend_from_slice(&at.to_le_bytes());
                out.extend_from_slice(&iv);
            }
        }
        out.extend_from_slice(&(self.lost.len() as u64).to_le_bytes());
        for r in &self.lost {
            out.extend_from_slice(&r.start.to_le_bytes());
            out.extend_from_slice(&r.end.to_le_bytes());
        }
        out.push(u8::from(self.crc_broken));
        out.extend_from_slice(&(self.crc.len() as u64).to_le_bytes());
        for &(s, e, c) in &self.crc {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&c.to_le_bytes());
        }
        for v in [self.stats.packed_read, self.stats.written, self.stats.holes, self.identity, self.stats.redecoded] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        match &self.layer {
            None => out.push(0),
            Some(blob) => {
                out.push(1);
                out.extend_from_slice(&(blob.len() as u64).to_le_bytes());
                out.extend_from_slice(blob);
            }
        }
        out.push(u8::from(self.unproven));
        out
    }

    /// Decodes [`Self::to_bytes`]. [`FeedDecoder::restore`] checks it against the member.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FeedError> {
        let mut r = Reader(bytes);
        if r.take(4)? != SNAPSHOT_MAGIC {
            return Err(FeedError::Snapshot("not a feed decoder snapshot"));
        }
        let version = r.u8()?;
        if !(1..=SNAPSHOT_VERSION).contains(&version) {
            return Err(FeedError::Snapshot("unknown version"));
        }
        let tag = r.u8()?;
        let size = r.u64()?;
        let stream_len = r.u64()?;
        let want_crc = match r.u8()? {
            0 => None,
            1 => Some(r.u32()?),
            _ => return Err(FeedError::Snapshot("bad flag")),
        };
        let main = match r.u8()? {
            0 => None,
            1 => Some((r.u64()?, None)),
            2 => Some((r.u64()?, Some(r.take(16)?.try_into().expect("16 bytes")))),
            _ => return Err(FeedError::Snapshot("bad flag")),
        };
        let n = r.count(16)?;
        let mut lost = Vec::with_capacity(n);
        for _ in 0..n {
            lost.push(r.u64()?..r.u64()?);
        }
        let crc_broken = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(FeedError::Snapshot("bad flag")),
        };
        let n = r.count(20)?;
        let mut crc = Vec::with_capacity(n);
        for _ in 0..n {
            crc.push((r.u64()?, r.u64()?, r.u32()?));
        }
        let mut stats = FeedStats { packed_read: r.u64()?, written: r.u64()?, holes: r.u64()?, redecoded: 0 };
        let identity = r.u64()?;
        let mut layer = None;
        if version >= 2 {
            stats.redecoded = r.u64()?;
            match r.u8()? {
                0 => {}
                1 => {
                    // checked against the bytes left only: its own counts are checked as it is decoded
                    let n = usize::try_from(r.u64()?).map_err(|_| FeedError::Snapshot("bad count"))?;
                    layer = Some(r.take(n)?.to_vec());
                }
                _ => return Err(FeedError::Snapshot("bad flag")),
            }
        }
        let unproven = version >= 3
            && match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(FeedError::Snapshot("bad flag")),
            };
        if !r.0.is_empty() {
            return Err(FeedError::Snapshot("trailing bytes"));
        }
        Ok(Self { tag, size, stream_len, want_crc, main, lost, crc, crc_broken, stats, identity, unproven, layer })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FeedError> {
        if self.0.len() < n {
            return Err(FeedError::Snapshot("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, FeedError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, FeedError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn u64(&mut self) -> Result<u64, FeedError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
    /// A count of items of `each` bytes, checked against the bytes left.
    fn count(&mut self, each: u64) -> Result<usize, FeedError> {
        let n = self.u64()?;
        if n > SNAPSHOT_MAX_RANGES || n.saturating_mul(each) > self.0.len() as u64 {
            return Err(FeedError::Snapshot("bad count"));
        }
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_set_merges_and_splits() {
        let mut s = RangeSet::default();
        s.insert(10..20);
        s.insert(30..40);
        s.insert(20..30);
        assert_eq!(s.ranges(), vec![10..40]);
        s.remove(15..25);
        assert_eq!(s.ranges(), vec![10..15, 25..40]);
        s.remove(0..100);
        assert!(s.is_empty());
    }

    #[test]
    fn crc_runs_combine_in_any_order() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let mut c = CrcRuns::default();
        c.add(500, &data[500..]);
        c.add(0, &data[..200]);
        assert_eq!(c.whole(1000), None);
        c.add(200, &data[200..500]);
        assert_eq!(c.whole(1000), Some(crc32fast::hash(&data)));
    }

    #[test]
    fn article_buffer_answers_and_releases() {
        let mut b = ArticleBuffer::new(100);
        b.insert(0, 10, &[1; 10]).unwrap();
        b.mark_lost(0, 30..40);
        let mut buf = [0u8; 64];
        assert_eq!(b.read_packed(0, 0, &mut buf), PackedRead::NotYet { len: 10 });
        assert_eq!(b.read_packed(0, 15, &mut buf), PackedRead::Data(5));
        assert_eq!(b.read_packed(0, 20, &mut buf), PackedRead::NotYet { len: 10 });
        assert_eq!(b.read_packed(0, 32, &mut buf), PackedRead::Hole { len: 8 });
        assert_eq!(b.absent(0, 0..50), Some(vec![0..10, 20..50]));
        b.insert(0, 5, &[2; 30]).unwrap();
        assert_eq!(b.held(), 30);
        assert_eq!(b.read_packed(0, 32, &mut buf), PackedRead::Data(3));
        assert!(b.insert(0, 100, &[0; 80]).is_err());
        b.release(0, 0..12);
        assert_eq!(b.held(), 23);
        assert_eq!(b.read_packed(0, 11, &mut buf), PackedRead::NotYet { len: 1 });
    }
}
