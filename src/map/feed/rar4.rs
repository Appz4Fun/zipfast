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

//! The feed decoder's compressed RAR 4.x layer (unpack versions 1.5, 2.0, 2.6 and 2.9: LZ, audio, PPMd, filters;
//! AES-128 under them). RAR 4.x has no restart point inside a member (no block resync, and the decoder's state, a
//! PPMd model of up to 256 MiB plus Huffman tables and filters, cannot be checkpointed cheaply), so the main decode
//! feeds the packed bytes in order and waits at a hole until its bytes come. A restore decodes again from the member's
//! start up to where the snapshot stood, writing nothing before it (counted in `redecoded`).
//!
//! A solid successor goes on from the decoder the member before it left ([`FeedDecoder::next_solid`]): window,
//! tables, distances, PPMd model. Created on its own (or restored), it decodes the solid stream's earlier members
//! again first, writing nothing, then its own member.

use super::rar5::OutSink;
use super::*;
use crate::rar5::unpack::rar4::{CoreFrame, Rar4DecodeError, Rar4Decoder};

/// An earlier member of the solid stream, decoded again (nothing written) before a successor that was not handed
/// the decoder.
struct Pre {
    geometry: Geometry,
    stream_len: u64,
    cipher: StoredCipher,
    size: u64,
    frame: CoreFrame,
}

pub(super) struct Rar4 {
    /// the decoder; None until it is started at the member's start (at first, or after a restore)
    dec: Option<Box<Rar4Decoder>>,
    /// the output offset reached, and the packed stream offset fed
    out: u64,
    fed: u64,
    /// output before this was written before a restore: decoded again, not written
    write_from: u64,
    stalled: bool,
    dictionary: u64,
    version: u8,
    /// the member's frame, for a decoder handed over to it
    frame: CoreFrame,
    /// the stream's earlier members to decode again first, and how many of them are done
    prefix: Vec<Pre>,
    pre_at: usize,
    pre_lane: Option<Lane>,
    /// a solid member follows: the finished decoder is kept for a hand-off
    successor: bool,
    ended: Option<Box<Rar4Decoder>>,
}

impl Rar4 {
    pub(super) fn frontier(&self) -> u64 {
        // while the stream's earlier members are decoded again, `out` counts their output, not this member's
        if self.pre_at < self.prefix.len() { self.write_from } else { self.out.max(self.write_from) }
    }

    pub(super) fn reach(&self) -> u64 {
        self.dictionary
    }

    pub(super) fn stalled(&self) -> bool {
        self.stalled
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        self.frontier().to_le_bytes().to_vec()
    }

    pub(super) fn restore(&mut self, blob: &[u8], size: u64) -> Result<(), FeedError> {
        let mut r = Reader(blob);
        let frontier = r.u64()?;
        if frontier > size || !r.0.is_empty() {
            return Err(FeedError::Snapshot("out of range"));
        }
        self.dec = None;
        self.out = 0;
        self.fed = 0;
        self.write_from = frontier;
        self.pre_at = 0;
        self.pre_lane = None;
        self.ended = None;
        Ok(())
    }
}

fn decode_error(e: Rar4DecodeError, out: &mut OutSink<'_>) -> FeedError {
    match e {
        Rar4DecodeError::Sink(error) => out.fail(error),
        Rar4DecodeError::Canceled => FeedError::Canceled,
        Rar4DecodeError::Malformed(what) => FeedError::Decode { out: out.at, error: crate::Error::Corrupt(what) },
        Rar4DecodeError::Unsupported(_) => {
            FeedError::Decode { out: out.at, error: crate::Error::Unsupported("RAR 4.x VM filter".into()) }
        }
        _ => FeedError::Decode { out: out.at, error: crate::Error::Corrupt("RAR 4.x data does not decode") },
    }
}

impl FeedDecoder {
    /// A decoder of a compressed RAR 4.x member.
    pub(super) fn new_rar4(
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
        begin: Begin,
    ) -> Result<Self, FeedError> {
        let member = &map.members[index];
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        let run = solid_run(map, index)?;
        // a successor handed the decoder in-session gets it installed after it is set up
        let handed = match begin {
            Begin::Fresh | Begin::Restore => false,
            Begin::Rar4 if run.prev.is_some() => true,
            _ => return Err(FeedError::Handoff("a hand-off from another layer or place")),
        };
        // one budget for every key this decoder derives: its member's and the earlier members' it decodes again
        let usage = Usage::new(options.limits.clone());
        let (geometry, stream_len, cipher, frame) = Self::rar4_parts(member, &options, &usage)?;
        // a solid stream's decoder holds the largest window its members ask for
        let dictionary = match run.dictionary {
            Some(most) if run.successor || run.prev.is_some() => most.max(frame.dictionary),
            _ => frame.dictionary,
        };
        if dictionary > options.max_window {
            return Err(FeedError::Unsupported(FeedUnsupported::Window { size: dictionary }));
        }
        let version = frame.unpack_version;
        // a successor not handed the decoder decodes the stream's earlier members again first
        let mut prefix = Vec::new();
        if !handed && run.prev.is_some() {
            let decodes = |m: &MapMember| !m.is_dir && matches!(m.method, MapMethod::Compressed { .. });
            for m in map.members[run.first..index].iter().filter(|m| decodes(m)) {
                let (geometry, stream_len, cipher, frame) = Self::rar4_parts(m, &options, &usage)?;
                let size = m.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
                prefix.push(Pre { geometry, stream_len, cipher, size, frame });
            }
        }
        let checks = member.checks.filter(|c| c.crc32.is_some());
        let chunk = options.read_chunk.clamp(16, 64 << 20);
        let mut d = Self {
            size,
            stream_len,
            geometry,
            cipher,
            tag: LayerTag::Rar4,
            want_crc: checks.and_then(|c| c.crc32),
            hash_key: None,
            keyed: false,
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
            failed: false,
            status: FeedStatus::default(),
            index: 0,
            stream_start: 0,
            unproven: false,
            suspect: None,
            seeded: None,
            rar5: None,
            lzma2: None,
            rar4: Some(Box::new(Rar4 {
                dec: None,
                out: 0,
                fed: 0,
                write_from: 0,
                stalled: false,
                dictionary,
                version,
                frame,
                prefix,
                pre_at: 0,
                pre_lane: None,
                successor: run.successor,
                ended: None,
            })),
        };
        d.stream_start = run.start;
        // an empty member of a solid stream still has its end-of-file marker read, which says where the next starts
        let feeds = size > 0 || run.successor || run.prev.is_some();
        if feeds {
            d.main = Some(d.packed_lane(0, stream_len));
        }
        d.status = d.make_status(Vec::new(), false);
        Ok(d)
    }

    /// A RAR 4.x member's pieces, packed length, cipher and frame.
    fn rar4_parts(
        member: &MapMember,
        options: &FeedOptions,
        usage: &Usage,
    ) -> Result<(Geometry, u64, StoredCipher, CoreFrame), FeedError> {
        if !member.complete {
            return Err(FeedError::IncompleteMember);
        }
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        let version = member.unpack_version.ok_or(FeedError::Malformed("RAR 4.x member without an unpack version"))?;
        let id = match member.method {
            MapMethod::Compressed { id } => id,
            _ => return Err(FeedError::Malformed("not a compressed member")),
        };
        if !matches!(version, 15 | 20 | 26 | 29) {
            return Err(FeedError::Unsupported(FeedUnsupported::Compressed { id }));
        }
        let dictionary = member.dictionary.ok_or(FeedError::Malformed("RAR 4.x member without a dictionary size"))?;
        if dictionary > options.max_window {
            return Err(FeedError::Unsupported(FeedUnsupported::Window { size: dictionary }));
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
        let cipher = match &member.cipher {
            None => StoredCipher::Plain,
            Some(CipherParams::Rar4 { .. }) => {
                if !stream_len.is_multiple_of(16) {
                    return Err(FeedError::Malformed("an encrypted packed stream is not whole blocks"));
                }
                let keys = derive_keys(
                    member,
                    OutputMapping::CbcBlocks,
                    options.password.as_deref(),
                    &options.limits,
                    usage,
                    &options.control,
                )
                .map_err(FeedError::from_extract)?;
                match keys.key {
                    MemberKey::Cbc { aes, iv } => StoredCipher::Cbc { aes, iv },
                    _ => return Err(FeedError::Malformed("cipher parameters do not match the member")),
                }
            }
            Some(CipherParams::Rar4Legacy { .. }) => {
                return Err(FeedError::Unsupported(FeedUnsupported::LegacyRar4Cipher));
            }
            Some(_) => return Err(FeedError::Unsupported(FeedUnsupported::UnmappedCipher)),
        };
        let frame = CoreFrame {
            ordinal: member.ordinal,
            packed: stream_len,
            unpacked: size,
            unpack_version: version,
            method: u8::try_from(id).unwrap_or(0),
            dictionary,
        };
        Ok((geometry, stream_len, cipher, frame))
    }

    /// [`FeedDecoder::next_solid`] for a RAR 4.x member: the decoder kept at the member's end starts the next one.
    pub(super) fn handoff_rar4(
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
        if self.rar4.as_ref().expect("RAR 4.x state").ended.is_none() {
            return Err(FeedError::Handoff(
                "the main decode has not finished, was handed over, or was restored (a RAR 4.x successor then decodes \
                 the stream again: FeedDecoder::new)",
            ));
        }
        // the successor is set up (keys, limits) before the decoder leaves this one: a failure keeps it here
        let suspect = self.carried_suspect();
        let mut next = FeedDecoder::new_begin(map, index, options, Begin::Rar4)?;
        let mut dec = self.rar4.as_mut().expect("RAR 4.x state").ended.take().expect("checked above");
        let frame = next.rar4.as_ref().expect("RAR 4.x state").frame;
        dec.next_solid_member(frame)
            .map_err(|_| FeedError::Handoff("the RAR 4.x decoder does not go on into this member"))?;
        // canceled through the new member's session control from now on, not the earlier member's
        dec.set_cancel(Some(next.options.control.cancellation_token()));
        next.rar4.as_mut().expect("RAR 4.x state").dec = Some(dec);
        next.inherit(suspect);
        Ok(next)
    }

    /// A decoder at the solid stream's start: its first member's (an earlier one's when decoding them again).
    fn start_rar4(&self, r: &Rar4) -> Result<Box<Rar4Decoder>, FeedError> {
        let fail = |_| FeedError::Decode { out: 0, error: crate::Error::Corrupt("RAR 4.x decoder setup") };
        let cancel = Some(self.options.control.cancellation_token());
        let (packed, size, version) = match r.prefix.first() {
            Some(p) => (p.stream_len, p.size, p.frame.unpack_version),
            None => (self.stream_len, self.size, r.version),
        };
        let mut dec =
            Rar4Decoder::new_with_cancel(r.dictionary, packed, size, self.options.max_window, cancel).map_err(fail)?;
        dec.set_version(version).map_err(fail)?;
        if r.successor || !r.prefix.is_empty() {
            // each member's end-of-file marker says where the next one starts
            dec.track_boundary();
        }
        Ok(Box::new(dec))
    }

    pub(super) fn run_rar4(
        &mut self,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<super::rar5::RunOut, FeedError> {
        let mut r = self.rar4.take().expect("RAR 4.x state");
        let result = self.run_rar4_with(&mut r, source, sink);
        self.rar4 = Some(r);
        result
    }

    /// Decodes the stream's earlier members again (nothing written), as far as their bytes allow: Some(true) once
    /// they are all done, Some(false) waiting for bytes (the need is added), None at the run's budget.
    fn rar4_prefix(
        &mut self,
        r: &mut Rar4,
        dec: &mut Rar4Decoder,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        next: &mut Vec<NeedBytes>,
    ) -> Result<Option<bool>, FeedError> {
        while r.pre_at < r.prefix.len() {
            let i = r.pre_at;
            // the earlier member's pieces and cipher stand in for this member's while it is read
            std::mem::swap(&mut self.geometry, &mut r.prefix[i].geometry);
            std::mem::swap(&mut self.stream_len, &mut r.prefix[i].stream_len);
            std::mem::swap(&mut self.cipher, &mut r.prefix[i].cipher);
            let mut lane = r.pre_lane.take().unwrap_or_else(|| self.packed_lane(0, self.stream_len));
            let stop = self.pump4(&mut lane, dec, r, 0..0, source, sink);
            let mut waits = None;
            if let Ok(Stop::Missing { stream, len, hole }) = &stop {
                self.push_needs(next, *stream..*stream + *len, NeedKind::Next);
                waits = Some(*hole);
            }
            let ranges = self.geometry.volume_ranges(0..self.stream_len);
            std::mem::swap(&mut self.geometry, &mut r.prefix[i].geometry);
            std::mem::swap(&mut self.stream_len, &mut r.prefix[i].stream_len);
            std::mem::swap(&mut self.cipher, &mut r.prefix[i].cipher);
            match stop? {
                Stop::Reached => {
                    let mut out = self.out_sink(sink, r.out, 0..0);
                    let ended = dec.finish_logical(&mut out).map(|_| ()).map_err(|e| decode_error(e, &mut out));
                    r.out = out.at;
                    ended?;
                    if r.out != r.prefix[i].size {
                        return Err(FeedError::Decode {
                            out: 0,
                            error: crate::Error::Corrupt("an earlier solid member decodes to another size"),
                        });
                    }
                    let frame = r.prefix.get(i + 1).map_or(r.frame, |p| p.frame);
                    dec.next_solid_member(frame).map_err(|_| FeedError::Decode {
                        out: 0,
                        error: crate::Error::Corrupt("the solid stream does not go on into the next member"),
                    })?;
                    for (volume, range) in ranges {
                        source.release(volume, range);
                    }
                    r.pre_at += 1;
                    r.out = 0;
                    r.fed = 0;
                }
                Stop::Budget => {
                    r.pre_lane = Some(lane);
                    return Ok(None);
                }
                Stop::Missing { .. } => {
                    r.stalled = waits == Some(true);
                    r.pre_lane = Some(lane);
                    return Ok(Some(false));
                }
            }
        }
        Ok(Some(true))
    }

    fn run_rar4_with(
        &mut self,
        r: &mut Rar4,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<super::rar5::RunOut, FeedError> {
        let (mut next, mut more, mut gap) = (Vec::new(), false, None);
        r.stalled = false;
        let Some(mut lane) = self.main.take() else { return Ok((next, Vec::new(), more, gap)) };
        let mut dec = match r.dec.take() {
            Some(dec) => dec,
            None => {
                // at the start, or restored: from the solid stream's start
                lane = self.packed_lane(0, self.stream_len);
                r.out = 0;
                r.fed = 0;
                r.pre_at = 0;
                r.pre_lane = None;
                self.start_rar4(r)?
            }
        };
        match self.rar4_prefix(r, &mut dec, source, sink, &mut next)? {
            Some(true) => {}
            waiting => {
                more = waiting.is_none();
                self.main = Some(lane);
                r.dec = Some(dec);
                return Ok((next, Vec::new(), more, gap));
            }
        }
        let write = r.write_from..self.size;
        match self.pump4(&mut lane, &mut dec, r, write.clone(), source, sink)? {
            Stop::Reached => {
                let mut out = self.out_sink(sink, r.out, write);
                let ended = dec.finish_logical(&mut out).map(|_| ()).map_err(|e| decode_error(e, &mut out));
                r.out = out.at;
                ended?;
                if r.out != self.size {
                    return Err(FeedError::Decode {
                        out: r.out,
                        error: crate::Error::Corrupt("RAR 4.x member decodes to another size"),
                    });
                }
                if r.successor && dec.has_boundary() {
                    r.ended = Some(dec);
                }
            }
            Stop::Budget => {
                more = true;
                self.main = Some(lane);
                r.dec = Some(dec);
            }
            Stop::Missing { stream, len, hole } => {
                // no restart point inside a RAR 4.x member: the main decode waits at the hole
                r.stalled = hole;
                self.push_needs(&mut next, stream..stream + len, NeedKind::Next);
                gap = Some(stream + len..lane.end);
                self.main = Some(lane);
                r.dec = Some(dec);
            }
        }
        Ok((next, Vec::new(), more, gap))
    }

    /// Reads the lane and feeds its (decrypted) bytes to the decoder; output inside `write` goes to the sink.
    fn pump4(
        &mut self,
        lane: &mut Lane,
        dec: &mut Rar4Decoder,
        r: &mut Rar4,
        write: Range<u64>,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
    ) -> Result<Stop, FeedError> {
        let mut buf = std::mem::take(&mut self.buf);
        let mut scratch = std::mem::take(&mut self.scratch);
        let result = (|| loop {
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
                    let from = r.fed.max(at);
                    let to = at + bytes.len() as u64;
                    if from < to {
                        let chunk = &bytes[(from - at) as usize..(to - at) as usize];
                        let mut o = self.out_sink(sink, r.out, write.clone());
                        let fed = dec.feed(chunk, &mut o).map(|_| ()).map_err(|e| decode_error(e, &mut o));
                        r.out = o.at;
                        fed?;
                        r.fed = to;
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

    /// A successor decoding its stream's earlier members again has not begun its own output: its frontier, and the
    /// one a snapshot keeps, are where its own output stands (0, or the frontier it was restored at).
    #[test]
    fn replaying_earlier_members_is_not_progress_through_this_one() {
        let frame = CoreFrame {
            ordinal: 0,
            packed: 10,
            unpacked: 100_000,
            unpack_version: 29,
            method: 0x33,
            dictionary: 1 << 22,
        };
        let pre = Pre {
            geometry: Geometry { spans: Vec::new() },
            stream_len: 10,
            cipher: StoredCipher::Plain,
            size: 100_000,
            frame,
        };
        let mut r = Rar4 {
            dec: None,
            out: 65_536,
            fed: 7_000,
            write_from: 0,
            stalled: false,
            dictionary: 1 << 22,
            version: 29,
            frame,
            prefix: vec![pre],
            pre_at: 0,
            pre_lane: None,
            successor: false,
            ended: None,
        };
        assert_eq!(r.frontier(), 0);
        assert_eq!(r.to_bytes(), 0u64.to_le_bytes());
        r.write_from = 500;
        assert_eq!(r.frontier(), 500);
        // the replay done, the member's own output counts
        r.pre_at = 1;
        r.out = 700;
        assert_eq!(r.frontier(), 700);
    }
}
