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

use super::rar5::OutSink;
use super::*;
use crate::rar5::unpack::rar4::{Rar4DecodeError, Rar4Decoder};

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
}

impl Rar4 {
    pub(super) fn frontier(&self) -> u64 {
        self.out.max(self.write_from)
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
    /// A decoder of a compressed RAR 4.x member, not solid.
    pub(super) fn new_rar4(
        map: &MemberMap,
        index: usize,
        options: FeedOptions,
        begin: Begin,
    ) -> Result<Self, FeedError> {
        let member = &map.members[index];
        if !matches!(begin, Begin::Fresh | Begin::Restore) {
            return Err(FeedError::Unsupported(FeedUnsupported::Solid));
        }
        let size = member.unpacked_size.ok_or(FeedError::Unsupported(FeedUnsupported::UnknownSize))?;
        if member.solid {
            return Err(FeedError::Unsupported(FeedUnsupported::Solid));
        }
        if !member.complete {
            return Err(FeedError::IncompleteMember);
        }
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
                    _ => return Err(FeedError::Malformed("cipher parameters do not match the member")),
                }
            }
            Some(CipherParams::Rar4Legacy { .. }) => {
                return Err(FeedError::Unsupported(FeedUnsupported::LegacyRar4Cipher));
            }
            Some(_) => return Err(FeedError::Unsupported(FeedUnsupported::UnmappedCipher)),
        };
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
            })),
        };
        if size > 0 {
            d.main = Some(d.packed_lane(0, stream_len));
        }
        d.status = d.make_status(Vec::new(), false);
        Ok(d)
    }

    fn start_rar4(&self, r: &Rar4) -> Result<Box<Rar4Decoder>, FeedError> {
        let fail = |_| FeedError::Decode { out: 0, error: crate::Error::Corrupt("RAR 4.x decoder setup") };
        let cancel = Some(self.options.control.cancellation_token());
        let mut dec =
            Rar4Decoder::new_with_cancel(r.dictionary, self.stream_len, self.size, self.options.max_window, cancel)
                .map_err(fail)?;
        dec.set_version(r.version).map_err(fail)?;
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
                // at the start, or restored: from the member's start
                lane = self.packed_lane(0, self.stream_len);
                r.out = 0;
                r.fed = 0;
                self.start_rar4(r)?
            }
        };
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
