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

//! The feed decoder's 7z LZMA2 layer: a folder of one LZMA2 coder (7zAES under it allowed). The main decode reads
//! the chunks in order, from chunk headers walked from the folder's first byte (the only proof of the framing). At
//! a hole it restarts at the next chunk it can decode without the lost bytes: a stored chunk (its payload is the
//! output), a chunk that resets the dictionary, or one that resets the state with held output as the dictionary.
//! The lost output is repaired later from the restart point before the hole (a chunk start plus its dictionary, read
//! back from the sink), or copied straight from the packed bytes when it lies in a stored chunk.

use super::*;
use crate::map::lzma2::{header_len, lzma2_dict, parse_chunk, props_valid};
use crate::map::{Lzma2Chunk, Lzma2ChunkKind, Lzma2Reset};

/// The decoder's output buffer.
const OUT_BUF: usize = 64 << 10;
/// Packed bytes kept before the main decode's read position for a repair or a restore from its restart point (a
/// single-threaded 7-Zip folder resets only at its start); bytes further back are released and asked for again
/// when a repair needs them.
const KEEP_BACK: u64 = 64 << 20;

/// Output between two restart points taken inside the dictionary window of the member's start: a restart point whose
/// dictionary reaches into earlier members (read back with `FeedSink::read_earlier`) is only recorded this far past the
/// one before it. A decoder restarting at the nearest restart point before a hole then decodes at most this much (plus
/// the run to the next state reset) again, where it would otherwise decode from the folder's start.
const CP_INTERVAL: u64 = 1 << 20;

/// A restart point: a chunk start where a decoder can begin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Cp {
    /// the plain packed offset of the chunk's header
    packed: u64,
    /// its folder output offset
    out: u64,
    /// the LZMA props in effect before it (a state reset without props takes them)
    props: Option<u8>,
    /// the chunk only resets the state: the dictionary before `out` comes from held output
    seeded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    /// lost output in one stored chunk: plain packed bytes from `plain`, byte for byte
    Stored { plain: u64 },
    /// decoded from `cp`, reading the plain packed stream up to `until`; `seed` is the lost range's own first chunk
    /// when it resets the state: once the output before it is held (a stored repair before it done, say), the repair
    /// starts there instead, decoding nothing twice
    Decoded { cp: Cp, until: u64, seed: Option<Cp> },
}

struct Repair {
    kind: Kind,
    /// folder output offsets
    lost: Range<u64>,
    /// the packed stream offset the last attempt stopped at, missing
    blocked: Option<u64>,
    /// a decoded repair that stopped at missing bytes keeps its decoder, and goes on where it stood (at most
    /// [`LIVE_REPAIRS`] of them; the others start again from their restart point)
    lane: Option<Lane2>,
}

/// The most repairs that keep their decoder between runs.
const LIVE_REPAIRS: usize = 8;

/// liblzma's raw LZMA2 decoder, fed the chunks from a restart point.
struct Live {
    stream: liblzma::stream::Stream,
}

/// Whether the sink gives back member output `r` (output written to a write-only sink is not held): its first and
/// last bytes, a cheap probe before relying on it as a dictionary.
fn held_probe(sink: &mut dyn FeedSink, r: Range<u64>) -> bool {
    let mut one = [0u8; 1];
    r.start >= r.end || [r.start, r.end - 1].into_iter().all(|at| matches!(sink.read_held(at, &mut one), Ok(1)))
}

fn corrupt(out: u64, what: &'static str) -> FeedError {
    FeedError::Decode { out, error: crate::Error::Corrupt(what) }
}

impl Live {
    fn new(prop: u8) -> Result<Self, FeedError> {
        let mut filters = liblzma::stream::Filters::new();
        filters.lzma2_properties(&[prop]).map_err(|_| corrupt(0, "LZMA2 decoder setup"))?;
        let stream =
            liblzma::stream::Stream::new_raw_decoder(&filters).map_err(|_| corrupt(0, "LZMA2 decoder setup"))?;
        Ok(Self { stream })
    }

    /// A decoder whose dictionary is `dict` (the output just before chunk `c`, which resets the LZMA state), set up
    /// to decode `c`'s payload next: the dictionary goes in as stored chunks, then `c`'s header setting `props`.
    fn seeded(prop: u8, dict: &[u8], c: &Lzma2Chunk, props: u8, buf: &mut [u8]) -> Result<Self, FeedError> {
        let mut live = Self::new(prop)?;
        let mut prefix = Vec::with_capacity(dict.len() + dict.len() / 65_536 * 3 + 9);
        for (i, piece) in dict.chunks(65_536).enumerate() {
            let size = piece.len() - 1;
            prefix.extend_from_slice(&[if i == 0 { 0x01 } else { 0x02 }, (size >> 8) as u8, size as u8]);
            prefix.extend_from_slice(piece);
        }
        let (mut hdr, _) = header_bytes(c);
        hdr[0] = 0xC0 | (hdr[0] & 0x1F);
        hdr[5] = props;
        prefix.extend_from_slice(&hdr);
        let mut echoed = 0u64;
        live.feed(&prefix, buf, c.unpacked_offset, &mut |b| {
            echoed += b.len() as u64;
            Ok(())
        })?;
        if echoed != dict.len() as u64 {
            return Err(corrupt(c.unpacked_offset, "LZMA2 dictionary seed"));
        }
        Ok(live)
    }

    /// Feeds `input` and hands every output byte it gives to `emit`.
    fn feed(
        &mut self,
        mut input: &[u8],
        buf: &mut [u8],
        out: u64,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), FeedError>,
    ) -> Result<(), FeedError> {
        loop {
            let (i, o) = (self.stream.total_in(), self.stream.total_out());
            let status = self.stream.process(input, buf, liblzma::stream::Action::Run);
            let consumed = (self.stream.total_in() - i) as usize;
            let produced = (self.stream.total_out() - o) as usize;
            input = &input[consumed..];
            if produced > 0 {
                emit(&buf[..produced])?;
            }
            match status {
                Err(_) => return Err(corrupt(out, "LZMA2 data does not decode")),
                // the end marker is never fed: the folder's members end before it
                Ok(liblzma::stream::Status::StreamEnd) => return Err(corrupt(out, "LZMA2 stream ends early")),
                Ok(_) => {}
            }
            if input.is_empty() && produced < buf.len() {
                return Ok(());
            }
            if consumed == 0 && produced == 0 {
                return Err(corrupt(out, "LZMA2 decoder stuck"));
            }
        }
    }
}

/// A chunk's header bytes, rebuilt from the chunk (they are what the walk read), and their length.
fn header_bytes(c: &Lzma2Chunk) -> ([u8; 6], usize) {
    let u = c.unpacked_len - 1;
    match c.kind {
        Lzma2ChunkKind::Stored => {
            ([if c.reset == Lzma2Reset::Dict { 0x01 } else { 0x02 }, (u >> 8) as u8, u as u8, 0, 0, 0], 3)
        }
        Lzma2ChunkKind::Lzma => {
            let p = c.packed_len - c.header_len() - 1;
            let reset = match c.reset {
                Lzma2Reset::None | Lzma2Reset::Dict => 0u8,
                Lzma2Reset::State => 1,
                Lzma2Reset::StateProps => 2,
                Lzma2Reset::DictStateProps => 3,
            };
            let control = 0x80 | (reset << 5) | ((u >> 16) as u8 & 0x1F);
            ([control, (u >> 8) as u8, u as u8, (p >> 8) as u8, p as u8, c.props.unwrap_or(0)], c.header_len() as usize)
        }
    }
}

/// A reader of the chunks from some point: the main decode or a repair.
struct Lane2 {
    /// the plain packed offset of the next byte to read
    pos: u64,
    /// the folder output offset of the next byte
    out: u64,
    /// the chunk being read, once its header was
    chunk: Option<Lzma2Chunk>,
    /// the last LZMA props set
    props: Option<u8>,
    live: Option<Live>,
    /// where `live` can be recreated; without `live`, a decoder from here reaches the lane passing lost bytes
    cp: Option<Cp>,
    /// the next header must start a decoder at `cp` (a restore or a repair)
    restart: bool,
}

impl Lane2 {
    fn at_cp(cp: Cp) -> Self {
        Self { pos: cp.packed, out: cp.out, chunk: None, props: cp.props, live: None, cp: Some(cp), restart: true }
    }
}

/// The LZMA2 state a member hands to the next member of its folder ([`FeedDecoder::next_solid`]).
pub(super) struct Handoff {
    /// the main decode where this member's ended (at or past the next member's start), when it goes on: None when
    /// everything from a hole to the folder's end is lost
    lane: Option<Lane2>,
    /// output the main decode decoded past this member's end (folder offsets from it on)
    spill: Vec<u8>,
    /// lost output past this member's end and its repair
    overflow: Vec<(Range<u64>, Kind)>,
    /// chunk headers walked
    walked: BTreeMap<u64, Lzma2Chunk>,
    /// packed (cipher) bytes before this offset may still be read by the members before: never released
    floor: u64,
    /// no restart point to go on from (a decoder restored without one): the next member finds its start from the
    /// folder's, as on its own
    seek: bool,
}

pub(super) struct Lz {
    /// the member's first and end folder output offsets
    ss: u64,
    end: u64,
    folder_size: u64,
    /// the LZMA2 stream's length (under 7zAES, the AES coder's output size) and the packed stream's
    plain_len: u64,
    cipher_len: u64,
    /// the coder's dictionary size, and the property byte of the decoder allocated (no larger than the folder)
    dict: u64,
    dec_prop: u8,
    encrypted: bool,
    main: Option<Lane2>,
    /// a member after its folder's first: the main decode starts once the headers before it are walked
    seek: bool,
    /// output before this is not written (a restore decodes it again)
    write_from: u64,
    repairs: Vec<Repair>,
    /// chunk headers walked (from the folder's start, through chains of headers), by plain packed offset
    walked: BTreeMap<u64, Lzma2Chunk>,
    stalled: bool,
    out_buf: Vec<u8>,
    /// the main decoder as it stood at a hole in a stored chunk, when the main decode went on copying without it: a
    /// chunk after it that needs the lost bytes is repaired from here rather than from the restart point
    parked: Option<Lane2>,
    /// the next member of the folder starts at this one's end: the main decode keeps what it decodes past the end
    /// (`spill`), walks past it for restarts, records lost output past it (`overflow`), and leaves its state for a
    /// hand-off (`handoff`) when it ends
    successor: bool,
    spill: Vec<u8>,
    overflow: Vec<(Range<u64>, Kind)>,
    handoff: Option<Box<Handoff>>,
    /// output a hand-off gave, from this member's start, still to be written
    pending: Vec<u8>,
    /// packed (cipher) offsets this decoder never releases: before `floor` (the members before may still read
    /// them) and from `cap` on (handed to the next member)
    floor: u64,
    cap: Option<u64>,
    /// the folder's index in the map
    folder: u32,
    /// the dictionary reset the main decode began at (or passed): a decoder from here needs nothing held. A restart
    /// point whose dictionary lies in earlier members (see [`CP_INTERVAL`]) falls back to it when the sink no longer
    /// gives that output. None for a decoder restored or handed over past its last dictionary reset.
    base: Option<Cp>,
}

impl Lz {
    pub(super) fn frontier(&self) -> u64 {
        match &self.main {
            _ if self.seek || !self.pending.is_empty() => 0,
            Some(l) => l.out.max(self.write_from).clamp(self.ss, self.end) - self.ss,
            None => self.end - self.ss,
        }
    }

    pub(super) fn reach(&self) -> u64 {
        self.dict
    }

    /// Ends the main decode (the caller holds the output from its frontier to the member's end); false while the
    /// folder is still being walked for a restart, when there is no main decode to end yet.
    pub(super) fn end_main(&mut self) -> bool {
        if self.seek || !self.pending.is_empty() {
            return false;
        }
        self.main = None;
        self.stalled = false;
        true
    }

    pub(super) fn stalled(&self) -> bool {
        self.stalled
    }

    pub(super) fn done(&self) -> bool {
        self.main.is_none() && !self.seek
    }

    /// How far the main decode walks for a restart: past the member's end into the next member's output when one
    /// follows (the lost output past the end is handed over).
    fn walk_end(&self) -> u64 {
        if self.successor { self.folder_size } else { self.end }
    }

    /// The packed ranges never to release ([`Self::floor`], [`Self::cap`]).
    pub(super) fn pinned(&self, cbc: bool) -> Vec<Range<u64>> {
        let mut out = Vec::new();
        if self.floor > 0 {
            out.push(0..self.floor);
        }
        if let Some(cap) = self.cap {
            out.push(self.cipher_range(cap..cap + 1, cbc).start..self.cipher_len);
        }
        out
    }

    /// The plain packed range `r` as packed stream offsets (under CBC with the block before).
    fn cipher_range(&self, r: Range<u64>, cbc: bool) -> Range<u64> {
        if cbc {
            (r.start & !15).saturating_sub(16)
                ..r.end.checked_next_multiple_of(16).unwrap_or(u64::MAX).min(self.cipher_len)
        } else {
            r
        }
    }

    /// The packed stream ranges a restore or a repair may read again.
    pub(super) fn needed(&self, cbc: bool) -> Vec<Range<u64>> {
        let mut out = Vec::new();
        if self.seek {
            out.push(0..self.cipher_len);
        } else if let Some(l) = &self.main {
            let from = l.cp.map_or(l.pos, |c| c.packed).min(l.pos).max(l.pos.saturating_sub(KEEP_BACK));
            out.push(self.cipher_range(from..self.plain_len, cbc));
        }
        for r in &self.repairs {
            let range = match r.kind {
                Kind::Stored { plain } => plain..plain + (r.lost.end - r.lost.start),
                Kind::Decoded { cp, until, .. } => cp.packed..until.max(cp.packed + 1),
            };
            out.push(self.cipher_range(range, cbc));
        }
        out
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let u64s = |out: &mut Vec<u8>, v: &[u64]| v.iter().for_each(|x| out.extend_from_slice(&x.to_le_bytes()));
        match &self.main {
            // output handed over and not written yet: a restore goes on from the handed-over restart point (the
            // packed bytes from it on are kept for this member), decoding that output again
            Some(l) if !self.seek && !self.pending.is_empty() && l.cp.is_some() => {
                let cp = l.cp.expect("checked");
                out.push(2);
                u64s(&mut out, &[cp.packed, cp.out]);
                out.push(0);
                out.push(cp.props.unwrap_or(0xFF));
                put_opt_cp(&mut out, Some(cp));
                out.push(1);
            }
            // otherwise a restore finds the member's start again
            _ if self.seek || !self.pending.is_empty() => out.push(1),
            None => out.push(0),
            Some(l) => {
                out.push(2);
                u64s(&mut out, &[l.pos, l.out]);
                match &l.chunk {
                    None => out.push(0),
                    Some(c) => {
                        out.push(1);
                        put_chunk(&mut out, c);
                    }
                }
                out.push(l.props.unwrap_or(0xFF));
                put_opt_cp(&mut out, l.cp);
                out.push(u8::from(l.live.is_some() || l.restart));
            }
        }
        u64s(&mut out, &[self.write_from, self.repairs.len() as u64]);
        for r in &self.repairs {
            put_kind(&mut out, &r.kind);
            u64s(&mut out, &[r.lost.start, r.lost.end]);
        }
        // what a member handed over keeps pinned (the members before it, the member after it)
        if self.floor > 0 || self.cap.is_some() || self.handoff.is_some() || self.base.is_some() {
            u64s(&mut out, &[self.floor, self.cap.unwrap_or(u64::MAX)]);
        }
        // a finished main decode's state still to be handed to the next member: where it goes on (a live decoder as
        // its restart point, decoding again what it decoded past this member's end) and the lost output past the end
        if let Some(h) = &self.handoff {
            out.push(1);
            match &h.lane {
                None => out.push(0),
                Some(l) if l.live.is_none() && !l.restart && h.spill.is_empty() => {
                    out.push(2);
                    u64s(&mut out, &[l.pos, l.out]);
                    match &l.chunk {
                        None => out.push(0),
                        Some(c) => {
                            out.push(1);
                            put_chunk(&mut out, c);
                        }
                    }
                    out.push(l.props.unwrap_or(0xFF));
                    put_opt_cp(&mut out, l.cp);
                }
                Some(l) => match l.cp {
                    Some(cp) => {
                        out.push(1);
                        put_opt_cp(&mut out, Some(cp));
                    }
                    // nowhere to restart: the next member finds its start from the folder's
                    None => out.push(3),
                },
            }
            u64s(&mut out, &[h.overflow.len() as u64]);
            for (lost, kind) in &h.overflow {
                put_kind(&mut out, kind);
                u64s(&mut out, &[lost.start, lost.end]);
            }
            u64s(&mut out, &[h.floor]);
        }
        // the dictionary reset a restart point reaching into earlier members falls back to, kept apart from the
        // active restart points (those may all be past it)
        if let Some(base) = self.base {
            out.push(2);
            put_opt_cp(&mut out, Some(base));
        }
        out
    }

    pub(super) fn restore(&mut self, blob: &[u8]) -> Result<(), FeedError> {
        let mut r = Reader(blob);
        let bad = || FeedError::Snapshot("out of range");
        let mut write_from_min = 0;
        let (main, seek) = match r.u8()? {
            0 => (None, false),
            1 => (None, true),
            2 => {
                let (pos, out) = (r.u64()?, r.u64()?);
                let chunk = match r.u8()? {
                    0 => None,
                    1 => Some(get_chunk(&mut r)?),
                    _ => return Err(FeedError::Snapshot("bad flag")),
                };
                let props = match r.u8()? {
                    0xFF => None,
                    p if props_valid(p) => Some(p),
                    _ => return Err(bad()),
                };
                let cp = get_opt_cp(&mut r)?;
                let live = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(FeedError::Snapshot("bad flag")),
                };
                if pos > self.plain_len || out > self.end {
                    return Err(bad());
                }
                if let Some(c) = cp
                    && (c.packed > pos || c.out > out)
                {
                    return Err(bad());
                }
                let lane = if live {
                    // decoded again from its restart point, written from where it stood
                    write_from_min = out;
                    Lane2::at_cp(cp.ok_or(bad())?)
                } else {
                    if let Some(c) = &chunk
                        && (c.kind != Lzma2ChunkKind::Stored
                            || !(c.payload().start..=c.packed().end).contains(&pos)
                            || out != c.unpacked_offset + (pos - c.payload().start))
                    {
                        return Err(bad());
                    }
                    Lane2 { pos, out, chunk, props, live: None, cp, restart: false }
                };
                (Some(lane), false)
            }
            _ => return Err(FeedError::Snapshot("bad flag")),
        };
        let write_from = r.u64()?;
        let n = r.count(1 + 8 + 16)?;
        let mut repairs = Vec::with_capacity(n);
        for _ in 0..n {
            let kind = get_kind(&mut r)?;
            let lost = r.u64()?..r.u64()?;
            if lost.start >= lost.end || lost.start < self.ss || lost.end > self.end {
                return Err(bad());
            }
            match kind {
                Kind::Stored { plain }
                    if plain.checked_add(lost.end - lost.start).is_none_or(|e| e > self.plain_len) =>
                {
                    return Err(bad());
                }
                Kind::Decoded { cp, until, .. }
                    if cp.out > lost.start || until > self.plain_len || cp.packed > until =>
                {
                    return Err(bad());
                }
                _ => {}
            }
            repairs.push(Repair { kind, lost, blocked: None, lane: None });
        }
        let (floor, cap) = if r.0.is_empty() { (0, u64::MAX) } else { (r.u64()?, r.u64()?) };
        let handoff = if r.0.is_empty() || r.0[0] == 2 {
            None
        } else {
            if r.u8()? != 1 || !self.successor || main.is_some() || seek {
                return Err(bad());
            }
            let (lane, seek_next) = match r.u8()? {
                0 => (None, false),
                1 => (Some(Lane2::at_cp(get_opt_cp(&mut r)?.ok_or(bad())?)), false),
                2 => {
                    let (pos, out) = (r.u64()?, r.u64()?);
                    let chunk = match r.u8()? {
                        0 => None,
                        1 => Some(get_chunk(&mut r)?),
                        _ => return Err(FeedError::Snapshot("bad flag")),
                    };
                    let props = match r.u8()? {
                        0xFF => None,
                        p if props_valid(p) => Some(p),
                        _ => return Err(bad()),
                    };
                    let cp = get_opt_cp(&mut r)?;
                    if pos > self.plain_len || out < self.end || out > self.folder_size {
                        return Err(bad());
                    }
                    (Some(Lane2 { pos, out, chunk, props, live: None, cp, restart: false }), false)
                }
                3 => (None, true),
                _ => return Err(FeedError::Snapshot("bad flag")),
            };
            if let Some(cp) = lane.as_ref().and_then(|l| l.cp)
                && (cp.packed > self.plain_len || cp.out > self.folder_size)
            {
                return Err(bad());
            }
            let n = r.count(1 + 8 + 16)?;
            let mut overflow = Vec::with_capacity(n);
            for _ in 0..n {
                let kind = get_kind(&mut r)?;
                let lost = r.u64()?..r.u64()?;
                if lost.start >= lost.end || lost.start < self.end || lost.end > self.folder_size {
                    return Err(bad());
                }
                overflow.push((lost, kind));
            }
            let floor = r.u64()?;
            Some(Box::new(Handoff {
                lane,
                spill: Vec::new(),
                overflow,
                walked: BTreeMap::new(),
                floor,
                seek: seek_next,
            }))
        };
        let saved_base = if r.0.first() == Some(&2) {
            r.u8()?;
            let cp = get_opt_cp(&mut r)?.ok_or(bad())?;
            if cp.seeded || cp.packed > self.plain_len || cp.out > self.folder_size {
                return Err(bad());
            }
            Some(cp)
        } else {
            None
        };
        if !r.0.is_empty() {
            return Err(FeedError::Snapshot("trailing bytes"));
        }
        self.handoff = handoff;
        if floor > self.cipher_len || (cap != u64::MAX && cap > self.plain_len) {
            return Err(bad());
        }
        self.floor = floor;
        self.cap = (cap != u64::MAX).then_some(cap);
        if write_from > self.end {
            return Err(bad());
        }
        // a dictionary reset a restored lane or repair restarts at (nothing else needs to be held for it)
        self.base = saved_base.or_else(|| {
            main.as_ref()
                .and_then(|l| l.cp)
                .into_iter()
                .chain(repairs.iter().filter_map(|r| match r.kind {
                    Kind::Decoded { cp, .. } => Some(cp),
                    Kind::Stored { .. } => None,
                }))
                .filter(|cp| !cp.seeded)
                .min_by_key(|cp| cp.out)
        });
        self.main = main;
        self.seek = seek;
        self.write_from = write_from.max(write_from_min).max(self.ss);
        self.repairs = repairs;
        self.walked.clear();
        Ok(())
    }
}

fn put_opt_cp(out: &mut Vec<u8>, cp: Option<Cp>) {
    match cp {
        None => out.push(0),
        Some(c) => {
            out.push(1);
            out.extend_from_slice(&c.packed.to_le_bytes());
            out.extend_from_slice(&c.out.to_le_bytes());
            out.push(c.props.unwrap_or(0xFF));
            out.push(u8::from(c.seeded));
        }
    }
}

fn get_opt_cp(r: &mut Reader<'_>) -> Result<Option<Cp>, FeedError> {
    match r.u8()? {
        0 => Ok(None),
        1 => {
            let (packed, out) = (r.u64()?, r.u64()?);
            let props = match r.u8()? {
                0xFF => None,
                p if props_valid(p) => Some(p),
                _ => return Err(FeedError::Snapshot("bad props")),
            };
            let seeded = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(FeedError::Snapshot("bad flag")),
            };
            Ok(Some(Cp { packed, out, props, seeded }))
        }
        _ => Err(FeedError::Snapshot("bad flag")),
    }
}

fn put_kind(out: &mut Vec<u8>, kind: &Kind) {
    match *kind {
        Kind::Stored { plain } => {
            out.push(0);
            out.extend_from_slice(&plain.to_le_bytes());
        }
        Kind::Decoded { cp, until, seed } => {
            out.push(1);
            put_opt_cp(out, Some(cp));
            out.extend_from_slice(&until.to_le_bytes());
            put_opt_cp(out, seed);
        }
    }
}

fn get_kind(r: &mut Reader<'_>) -> Result<Kind, FeedError> {
    Ok(match r.u8()? {
        0 => Kind::Stored { plain: r.u64()? },
        1 => {
            let cp = get_opt_cp(r)?.ok_or(FeedError::Snapshot("out of range"))?;
            let until = r.u64()?;
            Kind::Decoded { cp, until, seed: get_opt_cp(r)? }
        }
        _ => return Err(FeedError::Snapshot("bad flag")),
    })
}

fn put_chunk(out: &mut Vec<u8>, c: &Lzma2Chunk) {
    let (hdr, n) = header_bytes(c);
    for v in [c.packed_offset, c.unpacked_offset] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&hdr[..n]);
}

fn get_chunk(r: &mut Reader<'_>) -> Result<Lzma2Chunk, FeedError> {
    let (packed, unpacked) = (r.u64()?, r.u64()?);
    let control = r.u8()?;
    let n = header_len(control).filter(|&n| n > 1).ok_or(FeedError::Snapshot("bad chunk"))?;
    let mut hdr = [control, 0, 0, 0, 0, 0];
    hdr[1..n].copy_from_slice(r.take(n - 1)?);
    if n == 6 && !props_valid(hdr[5]) {
        return Err(FeedError::Snapshot("bad props"));
    }
    Ok(parse_chunk(&hdr, packed, unpacked))
}

/// What a read of plain packed bytes gave.
enum Got {
    Data(usize),
    /// packed stream bytes `cipher` are absent (`hole`: lost)
    Missing {
        cipher: Range<u64>,
        hole: bool,
    },
}

/// What reading a chunk header gave.
enum Hdr {
    Chunk(Lzma2Chunk),
    /// the end marker, or the stream's end
    End,
    Missing {
        cipher: Range<u64>,
        hole: bool,
    },
}

/// Why a lane stopped.
enum Step {
    /// its output reached the end asked for
    Reached,
    Budget,
    Missing {
        cipher: Range<u64>,
        hole: bool,
    },
    /// the next chunk (whose header was read) needs a decoder the lane does not have
    Undecodable,
    /// the stream ended first
    End,
}

/// What a walk of headers for a restart found.
enum Walk {
    /// a chunk to restart at, and the props in effect before it
    Found(Lzma2Chunk, Option<u8>),
    Blocked {
        cipher: Range<u64>,
        hole: bool,
    },
    /// none before the member's end
    NoRestart,
}

/// Why the main decode cannot go on past a hole yet: the packed ranges to name, and whether it waits at a hole.
struct Wait {
    needs: Vec<Range<u64>>,
    stalled: bool,
}

enum Skip {
    Skipped,
    /// the rest of the member is lost and left to a repair
    Finished,
    Wait(Wait),
}

impl FeedDecoder {
    /// A decoder of a member of a 7z folder whose coders are one LZMA2 coder, alone or over 7zAES.
    pub(super) fn handoff_lzma2(
        &mut self,
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
    ) -> Result<FeedDecoder, FeedError> {
        let lz = self.lzma2.as_mut().expect("LZMA2 state");
        let member = map.members.get(index).ok_or(FeedError::NoSuchMember { index })?;
        if member.folder.is_none_or(|f| f.index != lz.folder || f.offset != lz.end) {
            return Err(FeedError::Handoff("not the next member of the folder"));
        }
        if lz.handoff.is_none() {
            return Err(FeedError::Handoff("the main decode has not finished, or was handed over"));
        }
        // the next member is set up (keys, limits) before the state leaves this one: a failure keeps it here
        let suspect = self.carried_suspect();
        let mut next = FeedDecoder::new_begin(map, index, options, Begin::Lzma2)?;
        let h = self.lzma2.as_mut().expect("LZMA2 state").handoff.take().expect("checked above");
        next.install_lzma2(h);
        next.inherit(suspect);
        Ok(next)
    }

    /// Goes on from the state the member before handed over: its main decode, the output it decoded past its end,
    /// and the lost output past its end with its repairs.
    fn install_lzma2(&mut self, h: Box<Handoff>) {
        let size = self.size;
        let mut lz = self.lzma2.take().expect("LZMA2 state");
        let successor = lz.successor;
        let Handoff { lane, spill, overflow, walked, floor, seek } = *h;
        lz.main = lane.filter(|_| size > 0 || successor);
        lz.base = lz.main.as_ref().and_then(|l| l.cp).filter(|cp| !cp.seeded);
        lz.seek = seek && (size > 0 || successor);
        lz.walked = walked;
        lz.floor = floor;
        lz.pending = spill;
        for (lost, kind) in overflow {
            self.lz_lose(&mut lz, lost, kind);
        }
        // a hole's restart past this member's end (it skipped this member whole): the main decode is already done
        // here, and its lane is the next member's (so a snapshot never holds a main lane past the member's end)
        if lz.pending.is_empty() && lz.main.as_ref().is_some_and(|l| l.out >= lz.end) {
            let lane = lz.main.take();
            self.lz_stash(&mut lz, lane);
        }
        if lz.main.is_none() && !lz.seek && successor && lz.handoff.is_none() {
            // nothing goes on here (lost to the folder's end): the next member gets the rest
            lz.handoff = Some(Box::new(Handoff {
                lane: None,
                spill: Vec::new(),
                overflow: std::mem::take(&mut lz.overflow),
                walked: BTreeMap::new(),
                floor,
                seek: false,
            }));
        }
        self.lzma2 = Some(lz);
        self.status = self.make_status(Vec::new(), false);
    }

    /// Leaves the main decode's end state for the next member of the folder, when one follows: `lane` where the main
    /// decode stopped (None when everything to the folder's end is lost).
    fn lz_stash(&self, lz: &mut Lz, lane: Option<Lane2>) {
        if !lz.successor {
            return;
        }
        let cbc = matches!(self.cipher, StoredCipher::Cbc { .. });
        // what this member's repairs may read stays with it; what the next member reads is its own
        let floor = lz.needed(cbc).iter().map(|r| r.end).max().unwrap_or(0).max(lz.floor);
        let mut cap = u64::MAX;
        let walked = match &lane {
            Some(l) => {
                let from = l.cp.map_or(l.pos, |c| c.packed).min(l.pos);
                cap = cap.min(from);
                lz.walked.range(from..).map(|(&k, &c)| (k, c)).collect()
            }
            None => BTreeMap::new(),
        };
        for (_, kind) in &lz.overflow {
            cap = cap.min(match kind {
                Kind::Stored { plain } => *plain,
                Kind::Decoded { cp, .. } => cp.packed,
            });
        }
        lz.cap = (cap != u64::MAX).then_some(cap);
        lz.handoff = Some(Box::new(Handoff {
            lane,
            spill: std::mem::take(&mut lz.spill),
            overflow: std::mem::take(&mut lz.overflow),
            walked,
            floor,
            seek: false,
        }));
    }

    pub(super) fn new_lzma2(
        map: &MemberMap,
        member: &MapMember,
        options: FeedOptions,
        begin: Begin,
    ) -> Result<Self, FeedError> {
        // a member handed the state of the one before gets it installed after it is set up
        let handed = match begin {
            Begin::Fresh | Begin::Restore => false,
            Begin::Lzma2 => true,
            _ => return Err(FeedError::Handoff("a hand-off from another layer")),
        };
        let slot = member.folder.ok_or(FeedError::Malformed("7z member without a folder"))?;
        let folder = map.folders.get(slot.index as usize).ok_or(FeedError::Malformed("7z member's folder"))?;
        let (dict_prop, encrypted) = super::super::open_at::lzma2_coders(&folder.coders)
            .ok_or(FeedError::Unsupported(FeedUnsupported::Coders))?;
        if folder.pack_sizes.len() != 1 || folder.packed_streams.len() != 1 {
            return Err(FeedError::Unsupported(FeedUnsupported::Coders));
        }
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        if !member.complete {
            return Err(FeedError::IncompleteMember);
        }
        if dict_prop > 40 {
            return Err(FeedError::Malformed("LZMA2 dictionary property above 40"));
        }
        let cipher_len = folder.pack_sizes[0];
        let plain_len = if encrypted {
            let aes = folder.coders.iter().position(|c| c.kind == super::super::CoderKind::Aes).expect("7zAES coder");
            let out: u64 = folder.coders[..aes].iter().map(|c| u64::from(c.out_streams)).sum();
            let len = *folder.unpack_sizes.get(out as usize).ok_or(FeedError::Malformed("7zAES output size"))?;
            if !cipher_len.is_multiple_of(16) || len > cipher_len {
                return Err(FeedError::Malformed("7zAES packed stream is not whole blocks"));
            }
            len
        } else {
            cipher_len
        };
        let mut spans = Vec::new();
        let mut next = 0u64;
        for s in &folder.packed {
            if s.stream.start != next || s.packed.end - s.packed.start != s.stream.end - s.stream.start {
                return Err(FeedError::IncompleteMember);
            }
            next = s.stream.end;
            if s.stream.end > s.stream.start {
                spans.push(Span { stream: s.stream.clone(), volume: s.volume, packed_start: s.packed.start });
            }
        }
        let geometry = Geometry { spans };
        if geometry.covered() < cipher_len {
            return Err(FeedError::IncompleteMember);
        }
        let folder_size = folder.unpacked_size;
        let end = slot.offset.checked_add(size).filter(|&e| e <= folder_size);
        let end = end.ok_or(FeedError::Malformed("member runs past its folder's output"))?;
        // the next member of the folder in the map starts where this one ends (a zero-length one at the folder's end
        // too)
        let after = map.members.iter().position(|m| std::ptr::eq(m, member)).map_or(map.members.len(), |i| i + 1);
        let successor = map.members[after..]
            .iter()
            .find_map(|m| m.folder.filter(|f| f.index == slot.index))
            .is_some_and(|f| f.offset == end);
        let dict = lzma2_dict(dict_prop);
        let need = folder_size.max(4096);
        let dec_prop = (0..=dict_prop).find(|&p| lzma2_dict(p) >= need).unwrap_or(dict_prop);
        if lzma2_dict(dec_prop) > options.max_window {
            return Err(FeedError::Unsupported(FeedUnsupported::Window { size: lzma2_dict(dec_prop) }));
        }
        // an empty member a member follows still reads the stream (to hand it over)
        let cipher = if encrypted && (size > 0 || successor) {
            let usage = Usage::new(options.limits.clone());
            let keys = derive_keys(
                member,
                OutputMapping::CbcBlocks,
                options.password.as_deref(),
                &options.limits,
                &usage,
                &options.control,
            )
            .map_err(FeedError::from_extract)?;
            match keys.key {
                MemberKey::Cbc { aes, iv } => StoredCipher::Cbc { aes, iv },
                _ => return Err(FeedError::Malformed("cipher parameters do not match the folder")),
            }
        } else {
            StoredCipher::Plain
        };
        let checks = member.checks.filter(|c| c.crc32.is_some());
        let chunk = options.read_chunk.clamp(16, 64 << 20);
        // the member's fingerprint covers its folder: its packed bytes and coders
        let mut identity = member_identity(member);
        for v in [slot.offset, folder_size, cipher_len, plain_len, u64::from(dict_prop), u64::from(slot.index)]
            .into_iter()
            .chain(folder.packed.iter().flat_map(|s| [u64::from(s.volume), s.packed.start, s.packed.end]))
        {
            identity = (identity ^ v).wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut d = Self {
            size,
            stream_len: cipher_len,
            geometry,
            cipher,
            tag: LayerTag::Lzma2,
            want_crc: checks.and_then(|c| c.crc32),
            hash_key: None,
            keyed: false,
            main: None,
            lost: RangeSet::default(),
            blocked: BTreeMap::new(),
            crc: CrcRuns::default(),
            stats: FeedStats::default(),
            released: RangeSet::default(),
            identity,
            options,
            buf: vec![0; chunk],
            scratch: Vec::new(),
            run_written: 0,
            held_prefix: 0,
            failed: false,
            status: FeedStatus::default(),
            index: 0,
            stream_start: 0,
            unproven: false,
            suspect: None,
            seeded: None,
            rar5: None,
            rar4: None,
            zip: None,
            mac: None,
            lzma2: Some(Box::new(Lz {
                ss: slot.offset,
                end,
                folder_size,
                plain_len,
                cipher_len,
                dict,
                dec_prop,
                encrypted,
                main: None,
                seek: false,
                write_from: slot.offset,
                repairs: Vec::new(),
                walked: BTreeMap::new(),
                stalled: false,
                out_buf: vec![0; OUT_BUF],
                parked: None,
                successor,
                spill: Vec::new(),
                overflow: Vec::new(),
                handoff: None,
                pending: Vec::new(),
                floor: 0,
                cap: None,
                folder: slot.index,
                base: None,
            })),
        };
        d.stream_start = slot.offset;
        if !handed && (size > 0 || successor) {
            // an empty member a member follows still runs its main decode (to its own start) to hand it over
            let lz = d.lzma2.as_mut().expect("LZMA2 state");
            if slot.offset == 0 {
                lz.main =
                    Some(Lane2 { pos: 0, out: 0, chunk: None, props: None, live: None, cp: None, restart: false });
                lz.base = Some(Cp { packed: 0, out: 0, props: None, seeded: false });
            } else {
                lz.seek = true;
            }
        }
        d.status = d.make_status(Vec::new(), false);
        Ok(d)
    }

    pub(super) fn run_lzma2(
        &mut self,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<super::rar5::RunOut, FeedError> {
        let mut lz = self.lzma2.take().expect("LZMA2 state");
        let result = self.run_lz(&mut lz, source, sink);
        // headers before every lane's position are not read again
        if !lz.seek {
            let mut floor = lz.main.as_ref().map_or(u64::MAX, |l| l.pos);
            for r in &lz.repairs {
                floor = floor.min(match r.kind {
                    Kind::Stored { plain } => plain,
                    Kind::Decoded { cp, .. } => cp.packed,
                });
            }
            lz.walked = lz.walked.split_off(&floor);
        }
        self.lzma2 = Some(lz);
        result
    }

    fn run_lz(
        &mut self,
        lz: &mut Lz,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<super::rar5::RunOut, FeedError> {
        let (mut next, mut repair, mut more, mut gap) = (Vec::new(), Vec::new(), false, None);
        lz.stalled = false;
        if lz.seek
            && let Some((cipher, hole)) = self.lz_seek(lz, source)?
        {
            lz.stalled = hole;
            self.push_needs(&mut next, cipher.clone(), NeedKind::Next);
            gap = Some(cipher.end..self.stream_len);
        }
        if !lz.pending.is_empty() {
            // output the member before decoded past its end: this member's first bytes
            let bytes = std::mem::take(&mut lz.pending);
            let (ss, end) = (lz.ss, lz.end);
            self.lz_emit((ss, end), end, &(lz.write_from..end), ss, &bytes, sink)?;
            if lz.successor && bytes.len() as u64 > end - ss {
                lz.spill.extend_from_slice(&bytes[(end - ss) as usize..]);
            }
            if lz.main.is_none() {
                self.lz_stash(lz, None);
            }
        }
        while !lz.seek
            && let Some(mut lane) = lz.main.take()
        {
            let write = lz.write_from..lz.end;
            match self.lz_step(lz, &mut lane, write, lz.end, true, source, sink)? {
                Step::Reached => {
                    self.lz_stash(lz, Some(lane));
                    break;
                }
                Step::End => return Err(corrupt(lane.out, "LZMA2 stream ends before the member")),
                Step::Budget => {
                    more = true;
                    lz.main = Some(lane);
                    break;
                }
                Step::Missing { cipher, hole: false } => {
                    self.push_needs(&mut next, cipher.clone(), NeedKind::Next);
                    gap = Some(cipher.end..self.stream_len);
                    lz.main = Some(lane);
                    break;
                }
                Step::Missing { cipher, hole: true } => {
                    match self.lz_skip(lz, &mut lane, Some(cipher), source, sink)? {
                        Skip::Skipped => lz.main = Some(lane),
                        Skip::Finished => {
                            self.lz_stash(lz, None);
                            break;
                        }
                        Skip::Wait(w) => {
                            lz.stalled = w.stalled;
                            for r in &w.needs {
                                self.push_needs(&mut next, r.clone(), NeedKind::Next);
                            }
                            gap = w.needs.last().map(|r| r.end..self.stream_len);
                            lz.main = Some(lane);
                            break;
                        }
                    }
                }
                Step::Undecodable => match self.lz_skip(lz, &mut lane, None, source, sink)? {
                    Skip::Skipped => lz.main = Some(lane),
                    Skip::Finished => {
                        self.lz_stash(lz, None);
                        break;
                    }
                    Skip::Wait(w) => {
                        lz.stalled = w.stalled;
                        for r in &w.needs {
                            self.push_needs(&mut next, r.clone(), NeedKind::Next);
                        }
                        gap = w.needs.last().map(|r| r.end..self.stream_len);
                        lz.main = Some(lane);
                        break;
                    }
                },
            }
        }
        if lz.main.as_ref().is_none_or(|l| l.live.is_some()) {
            lz.parked = None;
        }
        if !more {
            let mut i = 0;
            while i < lz.repairs.len() {
                match self.lz_repair(lz, i, source, sink, &mut repair)? {
                    Some(true) => {
                        let done = lz.repairs.remove(i);
                        self.lost.remove(done.lost.start - lz.ss..done.lost.end - lz.ss);
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

    /// Walks the headers from the folder's start to the member's: the main decode starts at the last chunk at or
    /// before the member's first byte that resets the dictionary. The missing bytes it waits for, if any.
    fn lz_seek(&mut self, lz: &mut Lz, source: &mut dyn PackedSource) -> Result<Option<(Range<u64>, bool)>, FeedError> {
        let (mut pos, mut out, mut start) = (0u64, 0u64, None);
        loop {
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            let c = match self.lz_header(lz, source, pos, out)? {
                Hdr::Chunk(c) => c,
                Hdr::End => return Err(corrupt(out, "LZMA2 stream ends before the member")),
                Hdr::Missing { cipher, hole } => return Ok(Some((cipher, hole))),
            };
            if c.reset.resets_dictionary() {
                start = Some(c);
            }
            if c.unpacked().end > lz.ss {
                let d = start.ok_or_else(|| corrupt(0, "LZMA2 stream does not start with a dictionary reset"))?;
                lz.main = Some(Lane2 {
                    pos: d.packed_offset,
                    out: d.unpacked_offset,
                    chunk: None,
                    props: None,
                    live: None,
                    cp: None,
                    restart: false,
                });
                lz.base = Some(Cp { packed: d.packed_offset, out: d.unpacked_offset, props: None, seeded: false });
                lz.seek = false;
                lz.write_from = lz.ss;
                return Ok(None);
            }
            pos = c.packed().end;
            out = c.unpacked().end;
        }
    }

    fn lz_bad(&self, lz: &Lz, pos: u64, out: u64, what: &'static str) -> FeedError {
        // 7zAES records no password check: a wrong key shows as a first header that cannot be one
        if lz.encrypted && pos == 0 { FeedError::WrongPassword } else { corrupt(out, what) }
    }

    /// The chunk whose header is at plain packed offset `pos` (output offset `out`), from the walk's cache or read.
    fn lz_header(&mut self, lz: &mut Lz, source: &mut dyn PackedSource, pos: u64, out: u64) -> Result<Hdr, FeedError> {
        if self.options.control.is_canceled() {
            return Err(FeedError::Canceled);
        }
        if let Some(c) = lz.walked.get(&pos) {
            if c.unpacked_offset != out {
                return Err(corrupt(out, "LZMA2 chunk framing"));
            }
            return Ok(Hdr::Chunk(*c));
        }
        if pos >= lz.plain_len {
            return Ok(Hdr::End);
        }
        let mut hdr = [0u8; 6];
        let mut have = 0;
        loop {
            let need = if have == 0 {
                1
            } else {
                header_len(hdr[0]).ok_or_else(|| self.lz_bad(lz, pos, out, "bad LZMA2 control byte"))?
            };
            if have >= need {
                break;
            }
            if pos + need as u64 > lz.plain_len {
                return Err(corrupt(out, "LZMA2 chunk header runs past the stream"));
            }
            match self.lz_read(lz, source, pos + have as u64, &mut hdr[have..need])? {
                Got::Data(n) => have += n,
                Got::Missing { cipher, hole } => return Ok(Hdr::Missing { cipher, hole }),
            }
        }
        if hdr[0] == 0x00 {
            return Ok(Hdr::End);
        }
        let c = parse_chunk(&hdr, pos, out);
        if c.props.is_some_and(|p| !props_valid(p)) {
            return Err(self.lz_bad(lz, pos, out, "bad LZMA props"));
        }
        if pos == 0 && !c.reset.resets_dictionary() {
            return Err(self.lz_bad(lz, pos, out, "LZMA2 stream does not start with a dictionary reset"));
        }
        if c.unpacked().end > lz.folder_size {
            return Err(corrupt(out, "LZMA2 chunk runs past the folder's output"));
        }
        lz.walked.insert(pos, c);
        Ok(Hdr::Chunk(c))
    }

    /// Reads plain packed bytes at `pos` (under 7zAES decrypting whole blocks, the block before as IV).
    fn lz_read(&mut self, lz: &Lz, source: &mut dyn PackedSource, pos: u64, buf: &mut [u8]) -> Result<Got, FeedError> {
        if self.options.control.is_canceled() {
            return Err(FeedError::Canceled);
        }
        let want = (buf.len() as u64).min(lz.plain_len.saturating_sub(pos)) as usize;
        if want == 0 {
            return Err(FeedError::Malformed("read past the LZMA2 stream"));
        }
        let read = |s: &mut Self, source: &mut dyn PackedSource, at: u64, buf: &mut [u8]| -> Result<Got, FeedError> {
            let span = s.geometry.locate(at).ok_or(FeedError::Malformed("stream offset outside the pieces"))?;
            let left = (span.stream.end - at).min(buf.len() as u64) as usize;
            let piece_left = span.stream.end - at;
            match source.read_packed(span.volume, span.packed_start + (at - span.stream.start), &mut buf[..left]) {
                PackedRead::Data(n) if n > 0 && n <= left => {
                    s.stats.packed_read += n as u64;
                    Ok(Got::Data(n))
                }
                PackedRead::Data(_) => Err(FeedError::SourceContract("Data count of 0 or past the buffer")),
                PackedRead::NotYet { len } => {
                    Ok(Got::Missing { cipher: at..at + len.clamp(1, piece_left), hole: false })
                }
                PackedRead::Hole { len } => Ok(Got::Missing { cipher: at..at + len.clamp(1, piece_left), hole: true }),
            }
        };
        match self.cipher {
            StoredCipher::Cbc { aes, iv } => {
                let block = pos & !15;
                let from = block.saturating_sub(16);
                let end = (pos + want as u64).checked_next_multiple_of(16).unwrap_or(u64::MAX).min(lz.cipher_len);
                let mut cipher = std::mem::take(&mut self.scratch);
                cipher.clear();
                cipher.resize((end - from) as usize, 0);
                let mut have = 0usize;
                let mut miss = None;
                while (have as u64) < end - from {
                    match read(self, source, from + have as u64, &mut cipher[have..])? {
                        Got::Data(n) => have += n,
                        m @ Got::Missing { .. } => {
                            miss = Some(m);
                            break;
                        }
                    }
                }
                let usable = (from + have as u64) & !15;
                let iv_ok = block == 0 || have >= 16;
                if !iv_ok || usable <= pos {
                    self.scratch = cipher;
                    return Ok(miss.expect("a short read stops at missing bytes"));
                }
                let (mut iv, data) = if block == 0 {
                    (iv, &mut cipher[..(usable - block) as usize])
                } else {
                    let (head, rest) = cipher.split_at_mut(16);
                    (head.try_into().expect("one block"), &mut rest[..(usable - block) as usize])
                };
                aes.decrypt_cbc_in_place(&mut iv, data);
                let skip = (pos - block) as usize;
                let n = (usable - pos).min(want as u64) as usize;
                buf[..n].copy_from_slice(&data[skip..skip + n]);
                self.scratch = cipher;
                Ok(Got::Data(n))
            }
            _ => read(self, source, pos, &mut buf[..want]),
        }
    }

    /// Whether `r` (member output offsets) lies in output already written.
    fn lz_written(&self, r: Range<u64>) -> bool {
        r.start >= r.end
            || self.crc.runs.range(..=r.start).next_back().is_some_and(|(_, &(e, _))| e >= r.end) && !self.crc.broken
    }

    /// The dictionary a decoder restarting at folder output `o` (a state reset) needs: the output before it, held
    /// by the sink. None when not all of it is held (or it reaches before the member).
    fn lz_dict(&self, lz: &Lz, sink: &mut dyn FeedSink, o: u64) -> Option<Vec<u8>> {
        let d = lz.dict.min(o);
        // before the member: the folder's earlier members' output, when the sink gives it
        read_stream(sink, lz.ss, o - d..o).ok()
    }

    /// Whether a decoder could restart at state reset `o` from held output: written, or the sink holds it.
    fn lz_dict_held(&self, lz: &Lz, sink: &mut dyn FeedSink, o: u64) -> bool {
        let d = lz.dict.min(o);
        if o - d < lz.ss {
            return self.lz_dict(lz, sink, o).is_some();
        }
        let r = o - d - lz.ss..o - lz.ss;
        (self.lz_written(r.clone()) && held_probe(sink, r)) || self.lz_dict(lz, sink, o).is_some()
    }

    /// Whether the dictionary of a decoder restarting at state reset `o` (folder offsets, reaching before the member's
    /// start) looks held: samples of the earlier members' part through `read_earlier`, and the member's own part
    /// (written, probed at both ends). A probe, not a proof: the restart reads it all, and falls back to the
    /// dictionary reset when it fails.
    fn lz_probe_earlier(&self, lz: &Lz, sink: &mut dyn FeedSink, o: u64) -> bool {
        let from = o - lz.dict.min(o);
        let mut one = [0u8; 1];
        let early = from..o.min(lz.ss);
        let (a, b) = (early.start, early.end - 1);
        if ![a, a + (b - a) / 2, b].into_iter().all(|at| matches!(sink.read_earlier(at, &mut one), Ok(1))) {
            return false;
        }
        if o <= lz.ss {
            return true;
        }
        let r = from.max(lz.ss) - lz.ss..o - lz.ss;
        self.lz_written(r.clone()) && held_probe(sink, r)
    }

    /// Writes decoded output at folder offset `at`: the part inside `write` and the member, the rest counted as
    /// decoded again. Output at or past `end_out` is not counted.
    #[allow(clippy::too_many_arguments)]
    fn lz_emit(
        &mut self,
        (ss, member_end): (u64, u64),
        end_out: u64,
        write: &Range<u64>,
        at: u64,
        bytes: &[u8],
        sink: &mut dyn FeedSink,
    ) -> Result<(), FeedError> {
        let end = (at + bytes.len() as u64).min(end_out).min(member_end);
        if at >= end {
            return Ok(());
        }
        let (s, e) = (at.max(write.start).max(ss), end.min(write.end));
        let mut written = 0;
        if s < e {
            let b = &bytes[(s - at) as usize..(e - at) as usize];
            sink.write_at(s - ss, b).map_err(|error| FeedError::Write { out: s - ss, error })?;
            self.crc.add(s - ss, b);
            written = e - s;
            self.stats.written += written;
            self.run_written += written;
        }
        self.stats.redecoded += (end - at) - written;
        Ok(())
    }

    /// Reads and decodes a lane until its output reaches `end_out` or it stops; output inside `write` (folder
    /// offsets) is written. The main decode (`main`) of a member the next member of its folder follows keeps the
    /// output it decodes past the member's end (`Lz::spill`).
    #[allow(clippy::too_many_arguments)]
    fn lz_step(
        &mut self,
        lz: &mut Lz,
        lane: &mut Lane2,
        write: Range<u64>,
        end_out: u64,
        main: bool,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Step, FeedError> {
        let mut buf = std::mem::take(&mut self.buf);
        let mut out_buf = std::mem::take(&mut lz.out_buf);
        let mut spill = (main && lz.successor).then(|| std::mem::take(&mut lz.spill));
        let result = self.lz_step_with(lz, lane, write, end_out, &mut spill, source, sink, &mut buf, &mut out_buf);
        self.buf = buf;
        lz.out_buf = out_buf;
        if let Some(spill) = spill {
            lz.spill = spill;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn lz_step_with(
        &mut self,
        lz: &mut Lz,
        lane: &mut Lane2,
        write: Range<u64>,
        end_out: u64,
        spill: &mut Option<Vec<u8>>,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        buf: &mut [u8],
        out_buf: &mut [u8],
    ) -> Result<Step, FeedError> {
        let bounds = (lz.ss, lz.end);
        let member_end = lz.end;
        // output past the member's end, kept for the next member
        let keep = |spill: &mut Option<Vec<u8>>, at: u64, b: &[u8]| {
            if let Some(sp) = spill.as_mut()
                && at + b.len() as u64 > member_end
            {
                sp.extend_from_slice(&b[member_end.saturating_sub(at) as usize..]);
            }
        };
        loop {
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            if lane.out >= end_out {
                return Ok(Step::Reached);
            }
            if self.options.run_budget.is_some_and(|b| self.run_written >= b) {
                return Ok(Step::Budget);
            }
            let Some(c) = lane.chunk else {
                let c = match self.lz_header(lz, source, lane.pos, lane.out)? {
                    Hdr::Chunk(c) => c,
                    Hdr::End => return Ok(Step::End),
                    Hdr::Missing { cipher, hole } => return Ok(Step::Missing { cipher, hole }),
                };
                let state =
                    c.kind == Lzma2ChunkKind::Lzma && matches!(c.reset, Lzma2Reset::State | Lzma2Reset::StateProps);
                let props_before = lane.props;
                if lane.live.is_none() {
                    if c.reset.resets_dictionary() {
                        let mut live = Live::new(lz.dec_prop)?;
                        live.feed(&header_bytes(&c).0[..header_bytes(&c).1], out_buf, c.unpacked_offset, &mut |_| {
                            Ok(())
                        })?;
                        lane.live = Some(live);
                        lane.cp =
                            Some(Cp { packed: c.packed_offset, out: c.unpacked_offset, props: None, seeded: false });
                        lz.base = lane.cp;
                    } else if state {
                        let props =
                            c.props.or(props_before).ok_or_else(|| corrupt(lane.out, "LZMA2 chunk without props"))?;
                        match self.lz_dict(lz, sink, c.unpacked_offset) {
                            Some(dict) => {
                                // a dictionary this decoder did not write (another copy's output, or an earlier
                                // member's) is not proven until the member's CRC matches
                                let from = c.unpacked_offset - dict.len() as u64;
                                if from < lz.ss || !self.lz_written(from - lz.ss..c.unpacked_offset - lz.ss) {
                                    self.unproven = true;
                                    // the dictionary holds that output until it is pushed out of reach, whatever
                                    // this member's CRC says (a successor inherits it)
                                    self.seeded = self.seeded.max(Some(c.unpacked_offset));
                                }
                                lane.live = Some(Live::seeded(lz.dec_prop, &dict, &c, props, out_buf)?);
                                lane.cp = Some(Cp {
                                    packed: c.packed_offset,
                                    out: c.unpacked_offset,
                                    props: props_before,
                                    seeded: true,
                                });
                            }
                            // a restored restart point whose dictionary the sink no longer gives (earlier members'
                            // output): go back to the dictionary reset, which needs nothing held
                            None if lane.restart && lz.base.is_some_and(|b| b.out < c.unpacked_offset) => {
                                *lane = Lane2::at_cp(lz.base.expect("checked"));
                                continue;
                            }
                            None if lane.restart => {
                                let d = lz.dict.min(c.unpacked_offset);
                                let from = (c.unpacked_offset - d).saturating_sub(lz.ss);
                                return Err(FeedError::HeldOutput {
                                    range: from..c.unpacked_offset.saturating_sub(lz.ss),
                                });
                            }
                            None => return Ok(Step::Undecodable),
                        }
                    } else if c.kind == Lzma2ChunkKind::Lzma || lane.restart {
                        if lane.restart {
                            return Err(corrupt(lane.out, "a restart point that is not one"));
                        }
                        return Ok(Step::Undecodable);
                    }
                    // otherwise a stored chunk, copied as it is
                    lane.restart = false;
                } else {
                    if c.reset.resets_dictionary() {
                        lane.cp =
                            Some(Cp { packed: c.packed_offset, out: c.unpacked_offset, props: None, seeded: false });
                        lz.base = lane.cp;
                    } else if state {
                        let d = lz.dict.min(c.unpacked_offset);
                        let from = c.unpacked_offset - d;
                        // a restart point must be restorable: the sink gives the output written in the member back, and
                        // (before the member's start) the earlier members' output, probed here and recorded only
                        // every CP_INTERVAL of output and with a dictionary reset to fall back to
                        let held = if from >= lz.ss {
                            let r = from - lz.ss..c.unpacked_offset - lz.ss;
                            self.lz_written(r.clone()) && held_probe(sink, r)
                        } else {
                            lz.base.is_some()
                                && lane.cp.is_none_or(|cp| c.unpacked_offset - cp.out >= CP_INTERVAL)
                                && self.lz_probe_earlier(lz, sink, c.unpacked_offset)
                        };
                        if held {
                            lane.cp = Some(Cp {
                                packed: c.packed_offset,
                                out: c.unpacked_offset,
                                props: props_before,
                                seeded: true,
                            });
                        }
                    }
                    let (hdr, n) = header_bytes(&c);
                    let Some(live) = lane.live.as_mut() else { return Err(corrupt(lane.out, "no LZMA2 decoder")) };
                    let out = &mut lane.out;
                    live.feed(&hdr[..n], out_buf, *out, &mut |b| {
                        let at = *out;
                        *out += b.len() as u64;
                        keep(spill, at, b);
                        self.lz_emit(bounds, end_out, &write, at, b, sink)
                    })?;
                }
                lane.props = c.props.or(lane.props);
                lane.pos = c.payload().start;
                lane.chunk = Some(c);
                continue;
            };
            let want = ((c.packed().end - lane.pos) as usize).min(buf.len());
            let n = match self.lz_read(lz, source, lane.pos, &mut buf[..want])? {
                Got::Data(n) => n,
                Got::Missing { cipher, hole } => return Ok(Step::Missing { cipher, hole }),
            };
            let bytes = &buf[..n];
            let out = &mut lane.out;
            match lane.live.as_mut() {
                Some(live) => live.feed(bytes, out_buf, *out, &mut |b| {
                    let at = *out;
                    *out += b.len() as u64;
                    keep(spill, at, b);
                    self.lz_emit(bounds, end_out, &write, at, b, sink)
                })?,
                None => {
                    let at = *out;
                    *out += n as u64;
                    keep(spill, at, bytes);
                    self.lz_emit(bounds, end_out, &write, at, bytes, sink)?;
                }
            }
            lane.pos += n as u64;
            if lane.pos == c.packed().end {
                if lane.out != c.unpacked().end {
                    return Err(corrupt(lane.out, "LZMA2 chunk decodes to another size than its header states"));
                }
                lane.chunk = None;
            }
        }
    }

    /// Walks the headers from chunk boundary `pos` (output `out`, `props` in effect) for the first chunk at or after
    /// plain packed offset `after` that a decoder can start at without the bytes before it.
    #[allow(clippy::too_many_arguments)]
    fn lz_walk(
        &mut self,
        lz: &mut Lz,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        mut pos: u64,
        mut out: u64,
        mut props: Option<u8>,
        after: u64,
    ) -> Result<Walk, FeedError> {
        loop {
            if self.options.control.is_canceled() {
                return Err(FeedError::Canceled);
            }
            if out >= lz.walk_end() {
                return Ok(Walk::NoRestart);
            }
            let c = match self.lz_header(lz, source, pos, out)? {
                Hdr::Chunk(c) => c,
                Hdr::End => return Ok(Walk::NoRestart),
                Hdr::Missing { cipher, hole } => return Ok(Walk::Blocked { cipher, hole }),
            };
            if c.packed_offset >= after {
                let ok = match (c.kind, c.reset) {
                    (Lzma2ChunkKind::Stored, _) | (_, Lzma2Reset::DictStateProps) => true,
                    (Lzma2ChunkKind::Lzma, Lzma2Reset::State | Lzma2Reset::StateProps) => {
                        c.props.or(props).is_some() && self.lz_dict_held(lz, sink, c.unpacked_offset)
                    }
                    _ => false,
                };
                if ok {
                    return Ok(Walk::Found(c, props));
                }
            }
            props = c.props.or(props);
            pos = c.packed().end;
            out = c.unpacked().end;
        }
    }

    /// Records lost output `lost` (folder offsets, clipped to what the main decode writes) and its repair. Lost
    /// output past the member's end is kept for the next member of the folder, when one follows.
    fn lz_lose(&mut self, lz: &mut Lz, lost: Range<u64>, kind: Kind) -> bool {
        if lz.successor && lost.end > lz.end {
            let from = lost.start.max(lz.end);
            let kind = match kind {
                Kind::Stored { plain } => Kind::Stored { plain: plain + (from - lost.start) },
                ref k => k.clone(),
            };
            lz.overflow.push((from..lost.end, kind));
        }
        let start = lost.start.max(lz.write_from);
        let end = lost.end.min(lz.end);
        if start >= end {
            return false;
        }
        let kind = match kind {
            Kind::Stored { plain } => Kind::Stored { plain: plain + (start - lost.start) },
            k => k,
        };
        self.lost.insert(start - lz.ss..end - lz.ss);
        lz.repairs.push(Repair { kind, lost: start..end, blocked: None, lane: None });
        true
    }

    /// Takes the main decode past a hole at its position (`hole`, the packed bytes missing) or past a chunk it cannot
    /// decode without the output it lost earlier (`None`).
    fn lz_skip(
        &mut self,
        lz: &mut Lz,
        lane: &mut Lane2,
        hole: Option<Range<u64>>,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Skip, FeedError> {
        let Some(m) = hole else {
            // at a chunk the lane cannot decode: everything up to the next restart is lost
            let c = *lz.walked.get(&lane.pos).ok_or_else(|| corrupt(lane.out, "LZMA2 chunk framing"))?;
            let cp = lane.cp.ok_or_else(|| corrupt(lane.out, "LZMA2 chunk needs output before the stream"))?;
            let props = c.props.or(lane.props);
            let state = c.kind == Lzma2ChunkKind::Lzma && matches!(c.reset, Lzma2Reset::State | Lzma2Reset::StateProps);
            let seed = (state && props.is_some()).then_some(Cp {
                packed: c.packed_offset,
                out: c.unpacked_offset,
                props: lane.props,
                seeded: true,
            });
            return match self.lz_walk(lz, source, sink, c.packed().end, c.unpacked().end, props, 0)? {
                Walk::Found(r, props) => {
                    let lost = self.lz_lose(
                        lz,
                        c.unpacked_offset..r.unpacked_offset,
                        Kind::Decoded { cp, until: r.packed_offset, seed },
                    );
                    // the decoder parked at the stored hole before goes on from there
                    if lost && let Some(p) = lz.parked.take_if(|p| p.cp == Some(cp)) {
                        lz.repairs.last_mut().expect("repair").lane = Some(p);
                    }
                    *lane = Lane2 {
                        pos: r.packed_offset,
                        out: r.unpacked_offset,
                        chunk: None,
                        props,
                        live: None,
                        cp: Some(cp),
                        restart: false,
                    };
                    Ok(Skip::Skipped)
                }
                Walk::NoRestart => {
                    let to = lz.walk_end();
                    let lost = self.lz_lose(lz, c.unpacked_offset..to, Kind::Decoded { cp, until: lz.plain_len, seed });
                    if lost && let Some(p) = lz.parked.take_if(|p| p.cp == Some(cp)) {
                        lz.repairs.last_mut().expect("repair").lane = Some(p);
                    }
                    Ok(Skip::Finished)
                }
                Walk::Blocked { cipher, hole } => Ok(Skip::Wait(Wait { needs: vec![cipher], stalled: hole })),
            };
        };
        // the plain packed bytes the hole leaves unusable end at `after` (under CBC the block after it as well)
        let after = match self.cipher {
            StoredCipher::Cbc { .. } => {
                m.end.checked_next_multiple_of(16).unwrap_or(u64::MAX).saturating_add(16).min(lz.plain_len)
            }
            _ => m.end.min(lz.plain_len),
        };
        let stall = Skip::Wait(Wait { needs: vec![m.clone()], stalled: true });
        // a hole in a header hides the framing after it: wait for it
        let Some(c) = lane.chunk else { return Ok(stall) };
        if c.kind == Lzma2ChunkKind::Stored && after < c.packed().end {
            // inside a stored chunk: exactly the hole's output is lost, and copying goes on after it
            let out = c.unpacked_offset + (after - c.payload().start);
            self.lz_lose(lz, lane.out..out, Kind::Stored { plain: lane.pos });
            if lane.live.is_some() {
                let (pos, out, cp) = (after, out, lane.cp);
                let parked = std::mem::replace(
                    lane,
                    Lane2 { pos, out, chunk: Some(c), props: lane.props, live: None, cp, restart: false },
                );
                lz.parked = Some(parked);
            } else {
                lane.pos = after;
                lane.out = out;
            }
            self.stats.holes += 1;
            return Ok(Skip::Skipped);
        }
        match self.lz_walk(lz, source, sink, c.packed().end, c.unpacked().end, lane.props, after)? {
            Walk::Found(r, props) => {
                let kind = if c.kind == Lzma2ChunkKind::Stored && r.packed_offset == c.packed().end {
                    Kind::Stored { plain: lane.pos }
                } else {
                    match lane.cp {
                        Some(cp) => Kind::Decoded { cp, until: r.packed_offset, seed: None },
                        None => return Ok(stall),
                    }
                };
                let decoded = matches!(kind, Kind::Decoded { .. });
                let lost = self.lz_lose(lz, lane.out..r.unpacked_offset, kind);
                let cp = lane.cp;
                let parked = std::mem::replace(
                    lane,
                    Lane2 {
                        pos: r.packed_offset,
                        out: r.unpacked_offset,
                        chunk: None,
                        props,
                        live: None,
                        cp,
                        restart: false,
                    },
                );
                // The main decoder, stopped at the hole, is the repair's: it goes on from there once the hole's bytes
                // come, decoding nothing twice (while few repairs hold one; the others start from the restart point).
                if lost
                    && decoded
                    && parked.live.is_some()
                    && lz.repairs.iter().filter(|r| r.lane.is_some()).count() < LIVE_REPAIRS
                {
                    lz.repairs.last_mut().expect("repair").lane = Some(parked);
                } else if !decoded && parked.live.is_some() {
                    lz.parked = Some(parked);
                }
                self.stats.holes += 1;
                Ok(Skip::Skipped)
            }
            // headers after the hole not here yet: they come first, then the hole
            Walk::Blocked { cipher, hole: false } => Ok(Skip::Wait(Wait { needs: vec![cipher, m], stalled: false })),
            Walk::Blocked { hole: true, .. } | Walk::NoRestart => Ok(stall),
        }
    }

    /// The bytes still missing that another repair is blocked on, when they lie in the packed range a decoder
    /// restarting at packed offset `from` reads to reach folder output `out_end` (at most `until`): such a decoder
    /// cannot get past them either.
    fn lz_shared_block(
        &mut self,
        lz: &Lz,
        i: usize,
        from: u64,
        until: u64,
        out_end: u64,
        source: &mut dyn PackedSource,
    ) -> Result<Option<Range<u64>>, FeedError> {
        // the chunk holding the last lost byte ends the packed range read (when its header is still walked)
        let to = lz
            .walked
            .values()
            .find(|c| c.unpacked().contains(&(out_end - 1)))
            .map_or(until, |c| c.packed().end.min(until));
        for (j, r) in lz.repairs.iter().enumerate() {
            if let (true, Some(b)) = (j != i, r.blocked)
                && (from..to).contains(&b)
                && let Some(len) = self.probe(b, self.stream_len, source)?
            {
                return Ok(Some(b..b + len));
            }
        }
        Ok(None)
    }

    /// Tries repair `i`: Some(true) when its lost output is written, Some(false) when bytes are still missing (its
    /// need is added), None when the run's budget ran out.
    fn lz_repair(
        &mut self,
        lz: &mut Lz,
        i: usize,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        needs: &mut Vec<NeedBytes>,
    ) -> Result<Option<bool>, FeedError> {
        let (kind, lost, blocked) = (lz.repairs[i].kind.clone(), lz.repairs[i].lost.clone(), lz.repairs[i].blocked);
        if let Some(b) = blocked
            && let Some(len) = self.probe(b, self.stream_len, source)?
        {
            self.push_needs(needs, b..b + len, NeedKind::Repair);
            return Ok(Some(false));
        }
        lz.repairs[i].blocked = None;
        let mut kept = None;
        let (reached, stop, cp) = match kind {
            Kind::Stored { plain } => {
                let mut buf = std::mem::take(&mut self.buf);
                let (mut pos, mut out) = (plain, lost.start);
                let stop = loop {
                    if out >= lost.end {
                        break None;
                    }
                    if self.options.run_budget.is_some_and(|b| self.run_written >= b) {
                        break Some(None);
                    }
                    let want = ((lost.end - out) as usize).min(buf.len());
                    match self.lz_read(lz, source, pos, &mut buf[..want]) {
                        Ok(Got::Data(n)) => {
                            let r = self.lz_emit((lz.ss, lz.end), lost.end, &lost, out, &buf[..n], sink);
                            if let Err(e) = r {
                                self.buf = buf;
                                return Err(e);
                            }
                            pos += n as u64;
                            out += n as u64;
                        }
                        Ok(Got::Missing { cipher, .. }) => break Some(Some(cipher)),
                        Err(e) => {
                            self.buf = buf;
                            return Err(e);
                        }
                    }
                };
                self.buf = buf;
                if stop.is_some() {
                    lz.repairs[i].kind = Kind::Stored { plain: pos };
                }
                (out, stop, None)
            }
            Kind::Decoded { cp, seed, until } => {
                let seed = seed.filter(|s| s.out == lost.start && self.lz_dict_held(lz, sink, s.out));
                // a decoder started afresh passes the packed bytes from its restart point to the chunk holding the end of
                // the lost range; where another repair is already blocked on bytes still missing in there, it would only
                // decode up to them again (the repairs of one folder often share a restart point), so it waits for them
                if seed.is_none()
                    && lz.repairs[i].lane.is_none()
                    && let Some(need) = self.lz_shared_block(lz, i, cp.packed, until, lost.end, source)?
                {
                    self.push_needs(needs, need, NeedKind::Repair);
                    return Ok(Some(false));
                }
                let mut lane = match seed {
                    Some(s) => {
                        lz.repairs[i].lane = None;
                        lz.repairs[i].kind = Kind::Decoded { cp: s, until, seed: None };
                        Lane2::at_cp(s)
                    }
                    None => match lz.repairs[i].lane.take() {
                        Some(lane) => lane,
                        None => {
                            // a restart point whose dictionary lies in earlier members: the sink may not give it
                            // any more (a restore with another sink), then the dictionary reset serves
                            let reaches = cp.seeded && cp.out - lz.dict.min(cp.out) < lz.ss;
                            match lz.base {
                                Some(base) if reaches && base.out <= cp.out && !self.lz_dict_held(lz, sink, cp.out) => {
                                    lz.repairs[i].kind = Kind::Decoded { cp: base, until, seed: None };
                                    Lane2::at_cp(base)
                                }
                                _ => Lane2::at_cp(cp),
                            }
                        }
                    },
                };
                let stop = match self.lz_step(lz, &mut lane, lost.clone(), lost.end, false, source, sink)? {
                    Step::Reached => None,
                    Step::Budget => Some(None),
                    Step::Missing { cipher, .. } => Some(Some(cipher)),
                    Step::Undecodable | Step::End => {
                        return Err(corrupt(lane.out, "a repair did not reach the restart after its hole"));
                    }
                };
                let (out, cp) = (lane.out, lane.cp);
                kept = Some(lane);
                (out, stop, cp)
            }
        };
        let Some(stop) = stop else { return Ok(Some(true)) };
        // what a repair that stops wrote is no longer lost, and the next attempt starts from its last restart point
        let written = reached.clamp(lost.start, lost.end);
        self.lost.remove(lost.start - lz.ss..written - lz.ss);
        let r = &mut lz.repairs[i];
        r.lost.start = written;
        if let (Kind::Decoded { cp: old, .. }, Some(cp)) = (&mut r.kind, cp)
            && cp.out <= written
        {
            *old = cp;
        }
        let live = lz.repairs.iter().filter(|r| r.lane.is_some()).count();
        let r = &mut lz.repairs[i];
        if live < LIVE_REPAIRS {
            r.lane = kept;
        }
        match stop {
            None => Ok(None),
            Some(cipher) => {
                r.blocked = Some(cipher.start);
                self.push_needs(needs, cipher, NeedKind::Repair);
                Ok(Some(false))
            }
        }
    }
}
