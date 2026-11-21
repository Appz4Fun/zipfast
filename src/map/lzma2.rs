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

//! LZMA2 chunk indexes: where each chunk of an LZMA2 stream sits, read from the chunk headers alone.
//!
//! An LZMA2 stream is a run of chunks. Each starts with a control byte:
//!
//! | control | chunk | header |
//! |---|---|---|
//! | `0x00` | end of stream | 1 byte |
//! | `0x01` | stored, dictionary reset | 3 bytes: control, payload size - 1 (big-endian 16 bits) |
//! | `0x02` | stored, no reset | 3 bytes |
//! | `0x80..=0xFF` | LZMA: bits 5-6 are the reset (none, state, state and props, dictionary state and props), bits 0-4 the top bits of the unpacked size - 1 | 5 bytes: control, unpacked size - 1 (low 16 bits), packed size - 1; 6 with the props byte when the chunk sets props (`0xC0` and up) |
//!
//! [`Lzma2Index`] lists the chunks with their packed and unpacked offsets. It is built from the headers only
//! (at most 6 bytes per chunk), so payloads are never fetched: a stored chunk's payload is the plain output and can
//! be copied straight from the packed bytes ([`Lzma2Index::plan`]), and an LZMA chunk is decoded from the last
//! dictionary reset before it ([`Lzma2Decoder`], [`Lzma2Index::read_range`]). See `docs/member-map.md`.

use super::{MapFolder, MapInput, MemberMap, MemoryInput, Opened, PackedSpan, SourceInput, read_range};
use crate::progressive::{FailureKind, ProgressiveFailure, RangeSource, SessionControl, VolumeRequest, VolumeSource};
use std::{
    ffi::OsString,
    ops::Range,
    task::{Context, Poll, Waker},
};

/// The largest unpacked size of one LZMA chunk (21 bits).
pub const LZMA2_MAX_LZMA_UNPACKED: u64 = 1 << 21;
/// The largest payload of one chunk, stored or LZMA (16 bits).
pub const LZMA2_MAX_PAYLOAD: u64 = 1 << 16;

/// What a chunk holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lzma2ChunkKind {
    /// Control `0x01` or `0x02`: the payload is the output, byte for byte.
    Stored,
    /// Control `0x80` and up: LZMA-coded.
    Lzma,
}

/// What a chunk resets before it is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lzma2Reset {
    /// Nothing (`0x02`, `0x80..=0x9F`).
    None,
    /// The dictionary, for a stored chunk (`0x01`). The next LZMA chunk must set props (`0xC0` and up).
    Dict,
    /// The LZMA state (`0xA0..=0xBF`).
    State,
    /// The LZMA state and new props (`0xC0..=0xDF`).
    StateProps,
    /// The dictionary, the LZMA state and new props (`0xE0..=0xFF`).
    DictStateProps,
}

impl Lzma2Reset {
    /// Whether decoding can start at a chunk with this reset: it resets the dictionary.
    pub fn resets_dictionary(self) -> bool {
        matches!(self, Self::Dict | Self::DictStateProps)
    }
}

/// One chunk of an LZMA2 stream. Packed offsets count from the stream's first byte (or from where a resumed walk
/// started, see [`Lzma2Start::Resume`]); unpacked offsets count over the stream's output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lzma2Chunk {
    /// Offset of the control byte.
    pub packed_offset: u64,
    /// Header and payload.
    pub packed_len: u64,
    /// Offset of the chunk's first output byte.
    pub unpacked_offset: u64,
    pub unpacked_len: u64,
    pub kind: Lzma2ChunkKind,
    pub reset: Lzma2Reset,
    /// The LZMA props byte (`(pb * 5 + lp) * 9 + lc`) for chunks that set props.
    pub props: Option<u8>,
}

impl Lzma2Chunk {
    /// The header's length: 3 for stored chunks, 5 or 6 (with props) for LZMA chunks.
    pub fn header_len(&self) -> u64 {
        match (self.kind, self.props) {
            (Lzma2ChunkKind::Stored, _) => 3,
            (Lzma2ChunkKind::Lzma, None) => 5,
            (Lzma2ChunkKind::Lzma, Some(_)) => 6,
        }
    }
    /// The chunk's packed bytes, header included.
    pub fn packed(&self) -> Range<u64> {
        self.packed_offset..self.packed_offset + self.packed_len
    }
    /// The payload's packed bytes. For a stored chunk, they are output bytes [`Self::unpacked`].
    pub fn payload(&self) -> Range<u64> {
        self.packed_offset + self.header_len()..self.packed_offset + self.packed_len
    }
    /// The chunk's output range.
    pub fn unpacked(&self) -> Range<u64> {
        self.unpacked_offset..self.unpacked_offset + self.unpacked_len
    }
}

/// A position in an LZMA2 stream at a chunk boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lzma2Position {
    pub packed: u64,
    pub unpacked: u64,
}

/// Why a walk stopped at a chunk header it could not accept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Lzma2Damage {
    /// A control byte in `0x03..=0x7F`.
    BadControl(u8),
    /// The stream's first chunk does not reset the dictionary (`0x01` or `0xE0` and up).
    NoDictionaryReset,
    /// An LZMA chunk without new props (below `0xC0`) where props are needed: first after a dictionary reset.
    MissingProps,
    /// A props byte of 225 or more, or with `lc + lp > 4`.
    BadProps(u8),
    /// The chunk's output would end past [`Lzma2IndexOptions::expected_unpacked`] or overflow 64 bits.
    UnpackedOverflow,
}

impl std::fmt::Display for Lzma2Damage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadControl(c) => write!(f, "bad LZMA2 control byte 0x{c:02X}"),
            Self::NoDictionaryReset => write!(f, "first LZMA2 chunk does not reset the dictionary"),
            Self::MissingProps => write!(f, "LZMA2 chunk without props after a dictionary reset"),
            Self::BadProps(p) => write!(f, "bad LZMA props byte 0x{p:02X}"),
            Self::UnpackedOverflow => write!(f, "LZMA2 chunk runs past the unpacked size"),
        }
    }
}

/// Where and why a walk ended. Offsets are packed offsets of the chunk header concerned.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Lzma2End {
    /// The end marker (`0x00`) at `offset`. The stream is complete.
    EndMarker { offset: u64 },
    /// The packed range ended exactly at a chunk boundary, without an end marker.
    RangeEnd { offset: u64 },
    /// The packed range ended inside the chunk at `offset`. `partial` is that chunk when its header was read (its
    /// payload runs past the range end), None when the range ended inside the header.
    Truncated { offset: u64, partial: Option<Lzma2Chunk> },
    /// The source reported a hole at `offset`, inside the header of the chunk at `chunk`.
    Hole { chunk: u64, offset: u64 },
    /// Volume `volume`, holding the header of the chunk at `offset`, is missing.
    MissingVolume { offset: u64, volume: u32 },
    /// The header at `offset` is not one this stream can have.
    Damaged { offset: u64, damage: Lzma2Damage },
    /// [`Lzma2IndexOptions::max_chunks`] chunks were listed; the next starts at `offset`.
    ChunkLimit { offset: u64 },
}

impl Lzma2End {
    /// The packed offset where the walk stopped.
    pub fn offset(&self) -> u64 {
        match *self {
            Self::EndMarker { offset }
            | Self::RangeEnd { offset }
            | Self::Truncated { offset, .. }
            | Self::MissingVolume { offset, .. }
            | Self::Damaged { offset, .. }
            | Self::ChunkLimit { offset } => offset,
            Self::Hole { chunk, .. } => chunk,
        }
    }
}

/// Where a walk starts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Lzma2Start {
    /// The stream's first byte: the first chunk must reset the dictionary, and props are checked.
    #[default]
    StreamStart,
    /// A chunk header known by other means (after a hole, a chain found with [`find_stored_chunk_chains`] whose
    /// output position the caller matched): `packed` is its offset in the packed range and `unpacked` its output
    /// offset. Nothing before it is known, so no reset is required and props are not checked until a dictionary
    /// reset. Chunk offsets are reported in the same terms.
    Resume(Lzma2Position),
}

/// Options for building an [`Lzma2Index`].
#[derive(Clone, Debug)]
pub struct Lzma2IndexOptions {
    /// At most this many chunks are listed (the walk ends [`Lzma2End::ChunkLimit`]). Default 1 << 20: 48 MiB of
    /// index covering at least 64 GiB of output.
    pub max_chunks: usize,
    /// The stream's output size when known (a 7z coder's unpack size): a chunk running past it is
    /// [`Lzma2Damage::UnpackedOverflow`]. Unpacked offsets never overflow 64 bits regardless.
    pub expected_unpacked: Option<u64>,
    pub start: Lzma2Start,
}

impl Default for Lzma2IndexOptions {
    fn default() -> Self {
        Self { max_chunks: 1 << 20, expected_unpacked: None, start: Lzma2Start::StreamStart }
    }
}

/// The chunks of an LZMA2 stream, as far as the walk got.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lzma2Index {
    /// Where the walk started.
    pub start: Lzma2Position,
    /// The chunks in stream order, back to back from `start`.
    pub chunks: Vec<Lzma2Chunk>,
    pub end: Lzma2End,
}

/// A failure that stops a walk without an index: the source failed or broke its contract.
#[derive(Debug)]
#[non_exhaustive]
pub enum Lzma2Error {
    /// The source failed, broke its contract, or was canceled.
    Source(Box<ProgressiveFailure>),
    /// The volume source answered [`VolumeAnswer::Abort`](crate::progressive::VolumeAnswer::Abort).
    Aborted { volume: u32 },
    /// The folder has no LZMA2 coder reading a packed stream ([`MapFolder::lzma2_stage`] is None), or the index is
    /// out of range.
    NotLzma2Folder,
    /// The builder already returned its result.
    AlreadyFinished,
}

impl std::fmt::Display for Lzma2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(failure) => write!(f, "source failure: {failure}"),
            Self::Aborted { volume } => write!(f, "source aborted at volume {volume}"),
            Self::NotLzma2Folder => write!(f, "not a 7z folder with an LZMA2 coder over a packed stream"),
            Self::AlreadyFinished => write!(f, "LZMA2 index already returned"),
        }
    }
}

impl std::error::Error for Lzma2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(failure) => Some(failure.as_ref()),
            _ => None,
        }
    }
}

// ---- The walk ----

/// What a packed read gave.
enum Fetched {
    Filled(usize),
    NotYet,
    Hole,
    Eof,
    Missing { volume: u32 },
}

/// The walker's view of the packed bytes: offsets relative to the walk's packed range.
trait PackedInput {
    /// Bytes in the range, as far as currently known.
    fn len(&self) -> u64;
    fn fetch(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> Result<Fetched, Lzma2Error>;
}

struct SliceInput<'a>(&'a [u8]);

impl PackedInput for SliceInput<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn fetch(&mut self, offset: u64, buf: &mut [u8], _: &mut Context<'_>) -> Result<Fetched, Lzma2Error> {
        let Some(rest) = usize::try_from(offset).ok().and_then(|at| self.0.get(at..)).filter(|r| !r.is_empty()) else {
            return Ok(Fetched::Eof);
        };
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(Fetched::Filled(n))
    }
}

struct RangeInput {
    source: Box<dyn RangeSource>,
    range: Range<u64>,
}

impl PackedInput for RangeInput {
    fn len(&self) -> u64 {
        let have = self.source.info().length.value();
        self.range.end.min(have).saturating_sub(self.range.start)
    }
    fn fetch(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> Result<Fetched, Lzma2Error> {
        let n = buf.len().min(usize::try_from(self.len().saturating_sub(offset)).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(Fetched::Eof);
        }
        let got = read_range(self.source.as_mut(), self.range.start + offset, &mut buf[..n], cx);
        Ok(got_to_fetched(got.map_err(source_error)?))
    }
}

fn got_to_fetched(got: super::Got) -> Fetched {
    match got {
        super::Got::Filled(n) => Fetched::Filled(n),
        super::Got::NotYet => Fetched::NotYet,
        super::Got::Hole => Fetched::Hole,
        super::Got::Eof => Fetched::Eof,
    }
}

fn source_error(failure: ProgressiveFailure) -> Lzma2Error {
    Lzma2Error::Source(Box::new(failure))
}

/// A packed range over volumes: per-volume spans whose `stream` offsets are relative to the range.
struct VolumesInput<I: MapInput> {
    input: I,
    spans: Vec<PackedSpan>,
    names: Vec<OsString>,
    current: Option<u32>,
}

impl<I: MapInput> VolumesInput<I> {
    fn new(input: I, spans: Vec<PackedSpan>, first_name: OsString) -> Self {
        Self { input, spans, names: vec![first_name], current: None }
    }

    fn name(&mut self, index: u32) -> OsString {
        while self.names.len() <= index as usize {
            let next = super::next_volume_name(self.names.last().expect("first name"));
            self.names.push(next);
        }
        self.names[index as usize].clone()
    }
}

impl<I: MapInput> PackedInput for VolumesInput<I> {
    fn len(&self) -> u64 {
        self.spans.last().map_or(0, |s| s.stream.end)
    }
    fn fetch(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> Result<Fetched, Lzma2Error> {
        let Some(span) = self.spans.iter().find(|s| s.stream.contains(&offset)).cloned() else {
            return Ok(Fetched::Eof);
        };
        if self.current != Some(span.volume) {
            let request = VolumeRequest { index: span.volume, expected: self.name(span.volume) };
            match self.input.open(&request, cx).map_err(source_error)? {
                Opened::Ready => self.current = Some(span.volume),
                Opened::Wait => return Ok(Fetched::NotYet),
                Opened::Missing => return Ok(Fetched::Missing { volume: span.volume }),
                Opened::Abort => return Err(Lzma2Error::Aborted { volume: span.volume }),
            }
        }
        let n = buf.len().min(usize::try_from(span.stream.end - offset).unwrap_or(usize::MAX));
        let at = span.packed.start + (offset - span.stream.start);
        let got = self.input.read(at, &mut buf[..n], cx).map_err(source_error)?;
        Ok(got_to_fetched(got))
    }
}

/// Header length for control byte `c`; None for a bad control byte.
fn header_len(c: u8) -> Option<usize> {
    match c {
        0x00 => Some(1),
        0x01 | 0x02 => Some(3),
        0x03..=0x7F => None,
        0x80..=0xBF => Some(5),
        0xC0..=0xFF => Some(6),
    }
}

/// Whether LZMA props byte `p` is valid in LZMA2.
fn props_valid(p: u8) -> bool {
    if p >= 225 {
        return false;
    }
    let lc = p % 9;
    let lp = (p / 9) % 5;
    lc + lp <= 4
}

/// Parses a complete chunk header (`hdr` holds at least its header length) at `pos`/`unpacked`.
fn parse_chunk(hdr: &[u8], pos: u64, unpacked: u64) -> Lzma2Chunk {
    let c = hdr[0];
    if c < 0x80 {
        let size = (u64::from(hdr[1]) << 8 | u64::from(hdr[2])) + 1;
        return Lzma2Chunk {
            packed_offset: pos,
            packed_len: 3 + size,
            unpacked_offset: unpacked,
            unpacked_len: size,
            kind: Lzma2ChunkKind::Stored,
            reset: if c == 0x01 { Lzma2Reset::Dict } else { Lzma2Reset::None },
            props: None,
        };
    }
    let unpacked_len = (u64::from(c & 0x1F) << 16 | u64::from(hdr[1]) << 8 | u64::from(hdr[2])) + 1;
    let payload = (u64::from(hdr[3]) << 8 | u64::from(hdr[4])) + 1;
    let (reset, props) = match (c >> 5) & 3 {
        0 => (Lzma2Reset::None, None),
        1 => (Lzma2Reset::State, None),
        2 => (Lzma2Reset::StateProps, Some(hdr[5])),
        _ => (Lzma2Reset::DictStateProps, Some(hdr[5])),
    };
    let header = if props.is_some() { 6 } else { 5 };
    Lzma2Chunk {
        packed_offset: pos,
        packed_len: header + payload,
        unpacked_offset: unpacked,
        unpacked_len,
        kind: Lzma2ChunkKind::Lzma,
        reset,
        props,
    }
}

struct Walker {
    options: Lzma2IndexOptions,
    start: Lzma2Position,
    chunks: Vec<Lzma2Chunk>,
    pos: u64,
    unpacked: u64,
    /// The next chunk must reset the dictionary.
    need_dict: bool,
    /// The next LZMA chunk must set props.
    need_props: bool,
    hdr: [u8; 6],
    have: usize,
    end: Option<Lzma2End>,
}

impl Walker {
    fn new(options: Lzma2IndexOptions) -> Self {
        let (start, checked) = match options.start {
            Lzma2Start::StreamStart => (Lzma2Position::default(), true),
            Lzma2Start::Resume(at) => (at, false),
        };
        Self {
            options,
            start,
            chunks: Vec::new(),
            pos: start.packed,
            unpacked: start.unpacked,
            need_dict: checked,
            need_props: checked,
            hdr: [0; 6],
            have: 0,
            end: None,
        }
    }

    fn poll(&mut self, input: &mut dyn PackedInput, cx: &mut Context<'_>) -> Poll<Result<(), Lzma2Error>> {
        while self.end.is_none() {
            let need = if self.have == 0 {
                1
            } else {
                match header_len(self.hdr[0]) {
                    Some(n) => n,
                    None => {
                        let damage = Lzma2Damage::BadControl(self.hdr[0]);
                        self.end = Some(Lzma2End::Damaged { offset: self.pos, damage });
                        break;
                    }
                }
            };
            if self.have < need {
                let len = input.len();
                let at = self.pos + self.have as u64;
                if at >= len {
                    self.end = Some(if self.have == 0 {
                        Lzma2End::RangeEnd { offset: self.pos }
                    } else {
                        Lzma2End::Truncated { offset: self.pos, partial: None }
                    });
                    break;
                }
                let want = (6 - self.have).min(usize::try_from(len - at).unwrap_or(usize::MAX));
                match input.fetch(at, &mut self.hdr[self.have..self.have + want], cx)? {
                    Fetched::Filled(n) if n > 0 && n <= want => self.have += n,
                    Fetched::Filled(_) => {
                        return Poll::Ready(Err(source_error(ProgressiveFailure::new(FailureKind::SourceContract))));
                    }
                    Fetched::NotYet => return Poll::Pending,
                    Fetched::Hole => self.end = Some(Lzma2End::Hole { chunk: self.pos, offset: at }),
                    // The range said more bytes were there (`at < len`): the source ended early.
                    Fetched::Eof => self.end = Some(Lzma2End::Truncated { offset: self.pos, partial: None }),
                    Fetched::Missing { volume } => {
                        self.end = Some(Lzma2End::MissingVolume { offset: self.pos, volume })
                    }
                }
                continue;
            }
            if self.hdr[0] == 0x00 {
                self.end = Some(Lzma2End::EndMarker { offset: self.pos });
                break;
            }
            let chunk = parse_chunk(&self.hdr, self.pos, self.unpacked);
            self.have = 0;
            if self.chunks.len() >= self.options.max_chunks {
                self.end = Some(Lzma2End::ChunkLimit { offset: self.pos });
                break;
            }
            if let Some(damage) = self.check(&chunk) {
                self.end = Some(Lzma2End::Damaged { offset: self.pos, damage });
                break;
            }
            if chunk.reset.resets_dictionary() {
                self.need_dict = false;
                self.need_props = true;
            }
            if chunk.props.is_some() {
                self.need_props = false;
            }
            let next = self.pos + chunk.packed_len;
            if next > input.len() {
                self.end = Some(Lzma2End::Truncated { offset: self.pos, partial: Some(chunk) });
                break;
            }
            self.pos = next;
            self.unpacked += chunk.unpacked_len;
            self.chunks.push(chunk);
        }
        Poll::Ready(Ok(()))
    }

    fn check(&self, chunk: &Lzma2Chunk) -> Option<Lzma2Damage> {
        if self.need_dict && !chunk.reset.resets_dictionary() {
            return Some(Lzma2Damage::NoDictionaryReset);
        }
        if let Some(p) = chunk.props
            && !props_valid(p)
        {
            return Some(Lzma2Damage::BadProps(p));
        }
        if chunk.kind == Lzma2ChunkKind::Lzma && self.need_props && chunk.props.is_none() {
            return Some(Lzma2Damage::MissingProps);
        }
        let end = self.unpacked.checked_add(chunk.unpacked_len);
        if end.is_none_or(|end| self.options.expected_unpacked.is_some_and(|limit| end > limit)) {
            return Some(Lzma2Damage::UnpackedOverflow);
        }
        None
    }

    fn finish(&mut self) -> Lzma2Index {
        Lzma2Index {
            start: self.start,
            chunks: std::mem::take(&mut self.chunks),
            end: self.end.take().expect("walk ended"),
        }
    }
}

/// Builds an [`Lzma2Index`] from a source whose bytes may arrive late.
///
/// [`RangeRead::NotYet`](crate::progressive::RangeRead::NotYet) (and
/// [`VolumeAnswer::Wait`](crate::progressive::VolumeAnswer::Wait)) make [`Self::poll_index`] return `Pending`; the
/// provider wakes the task and the parked read is retried. Each chunk costs one read of at most 6 bytes (a few more
/// when a read comes back short). A hole in a payload is never seen; a hole in a header ends the index with
/// [`Lzma2End::Hole`].
pub struct Lzma2IndexBuilder {
    input: Box<dyn PackedInput + Send>,
    walker: Walker,
    done: bool,
}

impl Lzma2IndexBuilder {
    /// A builder over `packed`, a byte range of `source` holding an LZMA2 stream. Offsets in the index are relative
    /// to `packed.start`. The range is clipped to the source's length; a source shorter than the range ends the
    /// walk as if the range ended there.
    pub fn new(source: Box<dyn RangeSource>, packed: Range<u64>, options: Lzma2IndexOptions) -> Self {
        let input = RangeInput { source, range: packed };
        Self { input: Box::new(input), walker: Walker::new(options), done: false }
    }

    /// A builder over the LZMA2 stage of a 7z folder (see [`MapFolder::lzma2_stage`]), reading its packed stream
    /// through `source` with volumes named from `first_name` as [`MemberReader`](super::MemberReader) does. Offsets
    /// in the index are relative to the stage's packed stream. `options.expected_unpacked`, when None, is the
    /// stage's unpack size.
    pub fn for_folder(
        source: Box<dyn VolumeSource>,
        folder: &MapFolder,
        first_name: impl Into<OsString>,
        mut options: Lzma2IndexOptions,
    ) -> Result<Self, Lzma2Error> {
        let stage = folder.lzma2_stage().ok_or(Lzma2Error::NotLzma2Folder)?;
        options.expected_unpacked = options.expected_unpacked.or(Some(stage.unpacked_size));
        let spans = stage.relative_spans(folder);
        let input = VolumesInput::new(SourceInput::new(source), spans, first_name.into());
        Ok(Self { input: Box::new(input), walker: Walker::new(options), done: false })
    }

    /// Walks on. `Ready(Ok(index))` once the walk ends, for whatever reason [`Lzma2Index::end`] gives.
    pub fn poll_index(&mut self, cx: &mut Context<'_>) -> Poll<Result<Lzma2Index, Lzma2Error>> {
        if self.done {
            return Poll::Ready(Err(Lzma2Error::AlreadyFinished));
        }
        match self.walker.poll(self.input.as_mut(), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.done = true;
                Poll::Ready(result.map(|()| self.walker.finish()))
            }
        }
    }

    /// The chunks listed so far, while the walk is pending.
    pub fn chunks(&self) -> &[Lzma2Chunk] {
        &self.walker.chunks
    }
}

impl Lzma2Index {
    /// Indexes the LZMA2 stream in `packed` (offset 0 is its first byte).
    pub fn from_bytes(packed: &[u8], options: Lzma2IndexOptions) -> Lzma2Index {
        let mut walker = Walker::new(options);
        let mut cx = Context::from_waker(Waker::noop());
        match walker.poll(&mut SliceInput(packed), &mut cx) {
            Poll::Ready(Ok(())) => walker.finish(),
            Poll::Ready(Err(_)) | Poll::Pending => unreachable!("slice input never fails or waits"),
        }
    }

    /// Whether the end marker was reached.
    pub fn complete(&self) -> bool {
        matches!(self.end, Lzma2End::EndMarker { .. })
    }

    /// Where the listed chunks end.
    pub fn end_position(&self) -> Lzma2Position {
        match self.chunks.last() {
            Some(c) => Lzma2Position { packed: c.packed().end, unpacked: c.unpacked().end },
            None => self.start,
        }
    }

    /// Output bytes held by stored chunks: those that can be copied without decoding.
    pub fn stored_bytes(&self) -> u64 {
        self.chunks.iter().filter(|c| c.kind == Lzma2ChunkKind::Stored).map(|c| c.unpacked_len).sum()
    }

    /// The chunk holding output byte `unpacked`.
    pub fn chunk_at(&self, unpacked: u64) -> Option<usize> {
        let i = self.chunks.partition_point(|c| c.unpacked().end <= unpacked);
        (i < self.chunks.len() && self.chunks[i].unpacked_offset <= unpacked).then_some(i)
    }

    /// The chunk decoding must start at to produce chunk `chunk`: the last dictionary reset at or before it. None
    /// when the index has none (a resumed walk).
    pub fn decode_start(&self, chunk: usize) -> Option<usize> {
        self.chunks.get(..=chunk)?.iter().rposition(|c| c.reset.resets_dictionary())
    }

    /// Splits output range `unpacked` into stored payloads to copy, LZMA runs to decode, and what the index does
    /// not cover, in output order. Stored pieces are cut at chunk boundaries; consecutive LZMA chunks form one
    /// [`Lzma2Piece::Decode`], and a chunk that resets the dictionary starts a new one.
    pub fn plan(&self, unpacked: Range<u64>) -> Vec<Lzma2Piece> {
        let mut pieces = Vec::new();
        let mut at = unpacked.start;
        let end = unpacked.end;
        if at >= end {
            return pieces;
        }
        if at < self.start.unpacked {
            let to = end.min(self.start.unpacked);
            pieces.push(Lzma2Piece::Unindexed { unpacked: at..to });
            at = to;
        }
        let mut i = self.chunks.partition_point(|c| c.unpacked().end <= at);
        while at < end && i < self.chunks.len() {
            let c = &self.chunks[i];
            let to = end.min(c.unpacked().end);
            match c.kind {
                Lzma2ChunkKind::Stored => {
                    let p = c.payload().start + (at - c.unpacked_offset);
                    pieces.push(Lzma2Piece::Stored { unpacked: at..to, packed: p..p + (to - at), chunk: i });
                }
                Lzma2ChunkKind::Lzma => match pieces.last_mut() {
                    Some(Lzma2Piece::Decode { unpacked, chunks, .. })
                        if chunks.end == i && !c.reset.resets_dictionary() =>
                    {
                        unpacked.end = to;
                        chunks.end = i + 1;
                    }
                    _ => pieces.push(Lzma2Piece::Decode {
                        unpacked: at..to,
                        chunks: i..i + 1,
                        from: self.decode_start(i),
                    }),
                },
            }
            at = to;
            i += 1;
        }
        if at < end {
            pieces.push(Lzma2Piece::Unindexed { unpacked: at..end });
        }
        pieces
    }

    /// Decodes chunks `chunks` (the first must reset the dictionary) from `packed`, whose byte 0 is packed offset
    /// `packed_base` and which covers them. Returns their output, at most `options.max_output` bytes.
    pub fn decode_chunks(
        &self,
        chunks: Range<usize>,
        packed: &[u8],
        packed_base: u64,
        dict_prop: u8,
        options: &Lzma2DecodeOptions,
    ) -> Result<Vec<u8>, Lzma2DecodeError> {
        let run = self.chunks.get(chunks).ok_or(Lzma2DecodeError::NotContiguous)?;
        let total = run.iter().map(|c| c.unpacked_len).sum::<u64>();
        decode_run(run, packed, packed_base, dict_prop, options, run.first().map_or(0, |c| c.unpacked_offset)..u64::MAX)
            .and_then(|out| check_output(out, total))
    }

    /// The output of chunk `chunk`, decoded from the last dictionary reset before it ([`Self::decode_start`]),
    /// discarding the earlier output as it streams. `packed` (byte 0 at `packed_base`) must cover the chunks from
    /// that reset to `chunk`.
    pub fn decode_chunk(
        &self,
        chunk: usize,
        packed: &[u8],
        packed_base: u64,
        dict_prop: u8,
        options: &Lzma2DecodeOptions,
    ) -> Result<Vec<u8>, Lzma2DecodeError> {
        let target = *self.chunks.get(chunk).ok_or(Lzma2DecodeError::NotContiguous)?;
        let from =
            self.decode_start(chunk).ok_or(Lzma2DecodeError::NotDictionaryReset { offset: target.packed_offset })?;
        decode_run(&self.chunks[from..=chunk], packed, packed_base, dict_prop, options, target.unpacked())
    }

    /// The LZMA props byte in effect for chunk `chunk`: its own, or the last one set before it. None when no chunk
    /// up to it sets props (a resumed walk).
    pub fn props_for(&self, chunk: usize) -> Option<u8> {
        self.chunks.get(..=chunk)?.iter().rev().find_map(|c| c.props)
    }

    /// Decodes chunks `chunks` from a state reset, with the dictionary supplied by the caller instead of decoded from
    /// the last dictionary reset: the plaintext before the first chunk's output is known (from another copy of the
    /// file, say), so decoding can restart after a hole without the chunks before it.
    ///
    /// The first chunk must reset the LZMA state (`0xA0` and up); one that also resets the dictionary needs no
    /// dictionary and decodes as in [`Self::decode_chunks`]. `dictionary` is the output just before that chunk, up to
    /// its offset; only its last bytes, as many as the coder's dictionary size (`dict_prop`), are used. The LZMA
    /// props of a chunk that does not set them come from the last chunk that did ([`Self::props_for`]). `packed`
    /// (byte 0 at `packed_base`) must cover the chunks. Returns their output; a wrong dictionary decodes to wrong
    /// bytes or fails with [`Lzma2DecodeError::Data`], so check the result (the file's CRC).
    pub fn decode_with_dictionary(
        &self,
        chunks: Range<usize>,
        packed: &[u8],
        packed_base: u64,
        dict_prop: u8,
        dictionary: &[u8],
        options: &Lzma2DecodeOptions,
    ) -> Result<Vec<u8>, Lzma2DecodeError> {
        let start = chunks.start;
        let run = self.chunks.get(chunks.clone()).ok_or(Lzma2DecodeError::NotContiguous)?;
        let first = *run.first().ok_or(Lzma2DecodeError::NotContiguous)?;
        if first.reset.resets_dictionary() {
            return self.decode_chunks(chunks, packed, packed_base, dict_prop, options);
        }
        let props = match first.reset {
            Lzma2Reset::State | Lzma2Reset::StateProps if first.kind == Lzma2ChunkKind::Lzma => self.props_for(start),
            _ => None,
        }
        .ok_or(Lzma2DecodeError::NotStateReset { offset: first.packed_offset })?;
        if dict_prop > 40 {
            return Err(Lzma2DecodeError::BadDictionaryProp(dict_prop));
        }
        let last = run.last().expect("nonempty");
        let input = slice(packed, packed_base, first.packed_offset..last.packed().end)?;
        // The dictionary as stored chunks (the first resets the dictionary), then the first chunk with its control
        // byte setting props so the decoder starts the LZMA state from them, then the rest as they are.
        let keep = dictionary.len().min(usize::try_from(lzma2_dict(dict_prop)).unwrap_or(usize::MAX));
        let dict = &dictionary[dictionary.len() - keep..];
        bound(Lzma2Bound::Dictionary, options.max_dictionary, dict.len() as u64)?;
        let mut stream = Vec::new();
        stream.try_reserve_exact(dict.len() + dict.len() / 65_536 * 3 + 3 + input.len() + 1).map_err(|_| {
            Lzma2DecodeError::Limit {
                bound: Lzma2Bound::Output,
                limit: options.max_output,
                attempted: dict.len() as u64,
            }
        })?;
        for (i, piece) in dict.chunks(65_536).enumerate() {
            let size = piece.len() - 1;
            stream.extend_from_slice(&[if i == 0 { 0x01 } else { 0x02 }, (size >> 8) as u8, size as u8]);
            stream.extend_from_slice(piece);
        }
        let header = first.header_len() as usize;
        let hdr = &input[..header];
        if dict.is_empty() {
            // No dictionary: the chunk must not refer back, so it starts the stream with a dictionary reset.
            stream.extend_from_slice(&[0xE0 | (hdr[0] & 0x1F), hdr[1], hdr[2], hdr[3], hdr[4], props]);
        } else {
            stream.extend_from_slice(&[0xC0 | (hdr[0] & 0x1F), hdr[1], hdr[2], hdr[3], hdr[4], props]);
        }
        stream.extend_from_slice(&input[header..]);
        // Index the made-up stream and decode it, keeping the run's output.
        let mut synthetic = Vec::with_capacity(run.len() + dict.len() / 65_536 + 1);
        let (mut pos, mut out) = (0usize, 0u64);
        while pos < stream.len() {
            let c = parse_chunk(&stream[pos..pos + 6.min(stream.len() - pos)], pos as u64, out);
            pos += c.packed_len as usize;
            out += c.unpacked_len;
            synthetic.push(c);
        }
        let total = run.iter().map(|c| c.unpacked_len).sum::<u64>();
        let skip = dict.len() as u64;
        decode_run(&synthetic, &stream, 0, dict_prop, options, skip..skip + total)
            .and_then(|out| check_output(out, total))
    }

    /// Output range `unpacked`: stored payloads copied from `packed`, LZMA runs decoded from their dictionary reset
    /// (streaming, keeping only the wanted bytes). `packed` (byte 0 at `packed_base`) must cover the packed bytes
    /// the [`Self::plan`] pieces need, including the runs from each `from` chunk. Fails with
    /// [`Lzma2DecodeError::Unindexed`] when part of the range is not indexed or cannot be decoded.
    pub fn read_range(
        &self,
        unpacked: Range<u64>,
        packed: &[u8],
        packed_base: u64,
        dict_prop: u8,
        options: &Lzma2DecodeOptions,
    ) -> Result<Vec<u8>, Lzma2DecodeError> {
        let len = unpacked.end.saturating_sub(unpacked.start);
        bound(Lzma2Bound::Output, options.max_output, len)?;
        let mut out = Vec::with_capacity(len as usize);
        for piece in self.plan(unpacked) {
            match piece {
                Lzma2Piece::Stored { packed: range, .. } => out.extend_from_slice(slice(packed, packed_base, range)?),
                Lzma2Piece::Decode { unpacked, chunks, from: Some(from) } => {
                    let run = &self.chunks[from..chunks.end];
                    out.extend(decode_run(run, packed, packed_base, dict_prop, options, unpacked)?);
                }
                Lzma2Piece::Decode { unpacked, from: None, .. } | Lzma2Piece::Unindexed { unpacked } => {
                    return Err(Lzma2DecodeError::Unindexed { unpacked: unpacked.start });
                }
            }
        }
        Ok(out)
    }
}

/// One piece of an output range, from [`Lzma2Index::plan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lzma2Piece {
    /// Output `unpacked` is packed bytes `packed`, byte for byte: the payload of stored chunk `chunk`.
    Stored { unpacked: Range<u64>, packed: Range<u64>, chunk: usize },
    /// Output `unpacked` lies in LZMA chunks `chunks`. Decoding starts at chunk `from` (the last dictionary reset,
    /// None when the index has none before them) and runs to the end of `chunks`; the output before
    /// `unpacked.start` is discarded.
    Decode { unpacked: Range<u64>, chunks: Range<usize>, from: Option<usize> },
    /// Output the index does not cover: before a resumed walk's start or past where the walk ended.
    Unindexed { unpacked: Range<u64> },
}

/// Finds runs of stored chunk headers in `bytes`, a window of an LZMA2 stream at an unknown chunk alignment: the
/// positions where `links` stored chunk headers (`0x01` or `0x02` with a size) follow one another and the header
/// after them is a plausible control byte (`0x00`, `0x01`, `0x02` or `0x80` and up). Random bytes almost never
/// chain 3 links. Each run is reported once, at its first header.
///
/// This re-synchronizes after a hole or in a window fetched mid-stream; the output offset of a candidate is not
/// known from the headers, so the caller fixes it by other means (matching a payload against bytes it already has)
/// and resumes a walk there with [`Lzma2Start::Resume`].
pub fn find_stored_chunk_chains(bytes: &[u8], links: usize) -> Vec<usize> {
    let stored_at = |pos: usize| -> Option<usize> {
        let h = bytes.get(pos..pos + 3)?;
        matches!(h[0], 0x01 | 0x02).then(|| ((usize::from(h[1]) << 8) | usize::from(h[2])) + 1)
    };
    let chain = |pos: usize| -> bool {
        let mut p = pos;
        for _ in 0..links.max(1) {
            let Some(n) = stored_at(p) else { return false };
            p += 3 + n;
        }
        bytes.get(p).is_some_and(|&c| c <= 0x02 || c >= 0x80)
    };
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 3 <= bytes.len() {
        if chain(pos) {
            out.push(pos);
            pos += 3 + stored_at(pos).unwrap_or(0);
        } else {
            pos += 1;
        }
    }
    out
}

// ---- Decoding ----

/// Bounds and cancellation for decoding.
#[derive(Clone)]
pub struct Lzma2DecodeOptions {
    /// The largest dictionary allocated. The dictionary is the coder's (from the 7z property byte) shrunk to the
    /// run's output size, so a stated 4 GiB dictionary never allocates more than the run needs. Default 256 MiB.
    pub max_dictionary: u64,
    /// The most output returned in one buffer by [`Lzma2Index::decode_chunks`], [`Lzma2Index::decode_chunk`] and
    /// [`Lzma2Index::read_range`]: the bytes kept, not the output decoded and discarded before them. Default
    /// 256 MiB.
    pub max_output: u64,
    /// The most output a run may decode, from its dictionary reset to its end, kept or discarded (discarded output
    /// streams through a 64 KiB buffer). A [`Lzma2Decoder`] run is checked against it. Default 16 GiB, the 7z folder
    /// cap: 7-Zip and xz usually reset the dictionary only at the start, so a byte near the end of a large folder
    /// decodes through the whole folder.
    pub max_streamed: u64,
    /// Cancels the in-memory decodes between 64 KiB steps ([`Lzma2DecodeError::Canceled`]).
    pub control: SessionControl,
}

impl Default for Lzma2DecodeOptions {
    fn default() -> Self {
        Self {
            max_dictionary: 256 << 20,
            max_output: 256 << 20,
            max_streamed: 16 << 30,
            control: SessionControl::default(),
        }
    }
}

impl std::fmt::Debug for Lzma2DecodeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lzma2DecodeOptions")
            .field("max_dictionary", &self.max_dictionary)
            .field("max_output", &self.max_output)
            .field("max_streamed", &self.max_streamed)
            .field("canceled", &self.control.is_canceled())
            .finish()
    }
}

/// Which bound [`Lzma2DecodeError::Limit`] hit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lzma2Bound {
    Dictionary,
    /// [`Lzma2DecodeOptions::max_output`]: bytes returned.
    Output,
    /// [`Lzma2DecodeOptions::max_streamed`]: bytes decoded by a run.
    Streamed,
}

/// A failure to decode LZMA2 chunks.
#[derive(Debug)]
#[non_exhaustive]
pub enum Lzma2DecodeError {
    /// Decoding cannot start at the chunk at packed offset `offset`: it does not reset the dictionary.
    NotDictionaryReset {
        offset: u64,
    },
    /// [`Lzma2Index::decode_with_dictionary`] cannot start at the chunk at packed offset `offset`: it resets neither
    /// the dictionary nor the LZMA state (or no chunk before it set the LZMA props).
    NotStateReset {
        offset: u64,
    },
    /// The chunks given are not consecutive, or out of range.
    NotContiguous,
    /// The 7z LZMA2 property byte is above 40.
    BadDictionaryProp(u8),
    Limit {
        bound: Lzma2Bound,
        limit: u64,
        attempted: u64,
    },
    /// The packed bytes given do not cover packed offset `offset`.
    MissingPacked {
        offset: u64,
    },
    /// Output offset `unpacked` is not indexed, or no dictionary reset precedes it.
    Unindexed {
        unpacked: u64,
    },
    /// The data does not decode, or decodes to other sizes than the chunk headers state. `produced` output bytes
    /// of the run came before.
    Data {
        produced: u64,
    },
    /// liblzma refused to set up a decoder.
    Decoder(String),
    /// [`Lzma2DecodeOptions::control`] was canceled.
    Canceled,
}

impl std::fmt::Display for Lzma2DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDictionaryReset { offset } => write!(f, "LZMA2 chunk at {offset} does not reset the dictionary"),
            Self::NotStateReset { offset } => write!(f, "LZMA2 chunk at {offset} does not reset the LZMA state"),
            Self::NotContiguous => write!(f, "LZMA2 chunks are not consecutive"),
            Self::BadDictionaryProp(b) => write!(f, "bad LZMA2 dictionary property {b}"),
            Self::Limit { bound, limit, attempted } => {
                write!(f, "LZMA2 {bound:?} limit exceeded ({attempted} > {limit})")
            }
            Self::MissingPacked { offset } => write!(f, "packed bytes at {offset} not given"),
            Self::Unindexed { unpacked } => write!(f, "output offset {unpacked} is not indexed or decodable"),
            Self::Data { produced } => write!(f, "LZMA2 data does not decode (after {produced} output bytes)"),
            Self::Decoder(why) => write!(f, "LZMA2 decoder: {why}"),
            Self::Canceled => write!(f, "LZMA2 decode canceled"),
        }
    }
}

impl std::error::Error for Lzma2DecodeError {}

fn bound(bound: Lzma2Bound, limit: u64, attempted: u64) -> Result<(), Lzma2DecodeError> {
    if attempted > limit { Err(Lzma2DecodeError::Limit { bound, limit, attempted }) } else { Ok(()) }
}

fn slice(packed: &[u8], base: u64, range: Range<u64>) -> Result<&[u8], Lzma2DecodeError> {
    let missing = Lzma2DecodeError::MissingPacked { offset: range.start.max(base) };
    let a = range.start.checked_sub(base).ok_or(Lzma2DecodeError::MissingPacked { offset: range.start })?;
    let b = range.end - base;
    let (a, b) = (usize::try_from(a).map_err(|_| missing)?, usize::try_from(b).unwrap_or(usize::MAX));
    packed.get(a..b).ok_or(Lzma2DecodeError::MissingPacked { offset: base + packed.len() as u64 })
}

fn check_output(out: Vec<u8>, total: u64) -> Result<Vec<u8>, Lzma2DecodeError> {
    if out.len() as u64 == total { Ok(out) } else { Err(Lzma2DecodeError::Data { produced: out.len() as u64 }) }
}

/// Decodes the run `run` from `packed` and returns its output within `keep` (output offsets).
fn decode_run(
    run: &[Lzma2Chunk],
    packed: &[u8],
    base: u64,
    dict_prop: u8,
    options: &Lzma2DecodeOptions,
    keep: Range<u64>,
) -> Result<Vec<u8>, Lzma2DecodeError> {
    let first = run.first().ok_or(Lzma2DecodeError::NotContiguous)?;
    let last = run.last().expect("nonempty");
    let keep = keep.start.max(first.unpacked_offset)..keep.end.min(last.unpacked().end);
    let keep_len = keep.end.saturating_sub(keep.start);
    bound(Lzma2Bound::Output, options.max_output, keep_len)?;
    let input = slice(packed, base, first.packed_offset..last.packed().end)?;
    let mut decoder = Lzma2Decoder::new(run, dict_prop, options)?;
    let mut out = Vec::with_capacity(keep_len as usize);
    let mut scratch = vec![0u8; 64 << 10];
    let mut at = first.unpacked_offset;
    let mut consumed = 0;
    while !decoder.is_finished() {
        if options.control.is_canceled() {
            return Err(Lzma2DecodeError::Canceled);
        }
        let step = decoder.decode(&input[consumed..], &mut scratch)?;
        consumed += step.consumed;
        let produced = &scratch[..step.produced];
        let a = keep.start.clamp(at, at + produced.len() as u64) - at;
        let b = keep.end.clamp(at, at + produced.len() as u64) - at;
        out.extend_from_slice(&produced[a as usize..b as usize]);
        at += produced.len() as u64;
        if at >= keep.end {
            break;
        }
        if step.consumed == 0 && step.produced == 0 && !decoder.is_finished() {
            return Err(Lzma2DecodeError::Data { produced: decoder.produced() });
        }
    }
    Ok(out)
}

/// LZMA2's dictionary size for property byte `b` (at most 40).
fn lzma2_dict(b: u8) -> u64 {
    if b >= 40 { u64::from(u32::MAX) } else { (2 | u64::from(b & 1)) << (b / 2 + 11) }
}

/// What one [`Lzma2Decoder::decode`] call did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lzma2Step {
    /// Packed bytes taken from the input.
    pub consumed: usize,
    /// Output bytes written.
    pub produced: usize,
}

/// A streaming decoder over a run of consecutive chunks that starts with a dictionary reset.
///
/// It feeds liblzma's raw LZMA2 decoder a stream made of the run's chunks and an end marker, so state and props
/// resets inside the run (and later dictionary resets) are handled as in a whole stream. The run's packed and
/// unpacked sizes come from the index: the decoder takes exactly the run's packed bytes, writes exactly its
/// output, and fails with [`Lzma2DecodeError::Data`] when the data disagrees with the headers.
pub struct Lzma2Decoder {
    stream: liblzma::stream::Stream,
    packed_left: u64,
    out_left: u64,
    produced: u64,
    marker_fed: bool,
    finished: bool,
}

impl Lzma2Decoder {
    /// A decoder for `run`, consecutive chunks from an index whose first resets the dictionary. `dict_prop` is the
    /// 7z LZMA2 coder's property byte ([`Lzma2Stage::dict_prop`]); the dictionary allocated is the smaller of that
    /// and the run's output size, checked against `options.max_dictionary`. The run's output is checked against
    /// `options.max_streamed`; the decoder writes into the caller's buffers, so `max_output` does not apply.
    pub fn new(run: &[Lzma2Chunk], dict_prop: u8, options: &Lzma2DecodeOptions) -> Result<Self, Lzma2DecodeError> {
        let first = run.first().ok_or(Lzma2DecodeError::NotContiguous)?;
        if !first.reset.resets_dictionary() {
            return Err(Lzma2DecodeError::NotDictionaryReset { offset: first.packed_offset });
        }
        if run
            .windows(2)
            .any(|w| w[0].packed().end != w[1].packed_offset || w[0].unpacked().end != w[1].unpacked_offset)
        {
            return Err(Lzma2DecodeError::NotContiguous);
        }
        if dict_prop > 40 {
            return Err(Lzma2DecodeError::BadDictionaryProp(dict_prop));
        }
        let packed = run.iter().map(|c| c.packed_len).sum::<u64>();
        let unpacked = run.iter().map(|c| c.unpacked_len).sum::<u64>();
        bound(Lzma2Bound::Streamed, options.max_streamed, unpacked)?;
        let need = unpacked.max(4096);
        let prop = (0..=dict_prop).find(|&s| lzma2_dict(s) >= need).unwrap_or(dict_prop);
        bound(Lzma2Bound::Dictionary, options.max_dictionary, lzma2_dict(prop))?;
        let mut filters = liblzma::stream::Filters::new();
        filters.lzma2_properties(&[prop]).map_err(|e| Lzma2DecodeError::Decoder(e.to_string()))?;
        let stream =
            liblzma::stream::Stream::new_raw_decoder(&filters).map_err(|e| Lzma2DecodeError::Decoder(e.to_string()))?;
        Ok(Self { stream, packed_left: packed, out_left: unpacked, produced: 0, marker_fed: false, finished: false })
    }

    /// Decodes from `packed`, the run's packed bytes continuing where the last call stopped, into `out`. Bytes past
    /// the run's end in `packed` are not taken. A call that takes and writes nothing needs more input or room.
    pub fn decode(&mut self, packed: &[u8], out: &mut [u8]) -> Result<Lzma2Step, Lzma2DecodeError> {
        if self.finished {
            return Ok(Lzma2Step { consumed: 0, produced: 0 });
        }
        let room = out.len().min(usize::try_from(self.out_left).unwrap_or(usize::MAX));
        let marker = [0u8];
        let from_packed = self.packed_left > 0;
        let input: &[u8] = if from_packed {
            &packed[..packed.len().min(usize::try_from(self.packed_left).unwrap_or(usize::MAX))]
        } else if !self.marker_fed {
            &marker
        } else {
            &[]
        };
        let (i, o) = (self.stream.total_in(), self.stream.total_out());
        let status = self.stream.process(input, &mut out[..room], liblzma::stream::Action::Run);
        let consumed = (self.stream.total_in() - i) as usize;
        let produced = (self.stream.total_out() - o) as usize;
        self.out_left -= produced as u64;
        self.produced += produced as u64;
        if from_packed {
            self.packed_left -= consumed as u64;
        } else if consumed > 0 {
            self.marker_fed = true;
        }
        match status {
            Err(_) => return Err(Lzma2DecodeError::Data { produced: self.produced }),
            Ok(liblzma::stream::Status::StreamEnd) => {
                if self.out_left != 0 || self.packed_left != 0 {
                    return Err(Lzma2DecodeError::Data { produced: self.produced });
                }
                self.finished = true;
            }
            Ok(_) => {
                // Stuck on output the headers did not announce: the data disagrees with them.
                if self.out_left == 0 && consumed == 0 && produced == 0 && !input.is_empty() {
                    return Err(Lzma2DecodeError::Data { produced: self.produced });
                }
            }
        }
        Ok(Lzma2Step { consumed: if from_packed { consumed } else { 0 }, produced })
    }

    /// Whether the run's output is complete and the stream ended where the headers said.
    pub fn is_finished(&self) -> bool {
        self.finished
    }
    /// Output written so far.
    pub fn produced(&self) -> u64 {
        self.produced
    }
    /// Packed bytes of the run not yet taken.
    pub fn packed_left(&self) -> u64 {
        self.packed_left
    }
    /// Output of the run not yet written.
    pub fn output_left(&self) -> u64 {
        self.out_left
    }
}

// ---- 7z folders ----

/// The LZMA2 coder of a 7z folder that reads a packed stream directly, from [`MapFolder::lzma2_stage`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lzma2Stage {
    /// Index into [`MapFolder::coders`].
    pub coder: usize,
    /// The coder's property byte: the dictionary size.
    pub dict_prop: u8,
    /// The LZMA2 stream's packed bytes, as offsets over the folder's packed streams (`PackedSpan::stream` of
    /// [`MapFolder::packed`]).
    pub packed: Range<u64>,
    /// The coder's output size.
    pub unpacked_size: u64,
    /// Whether the coder's output is the folder's output, so LZMA2 unpacked offsets are folder offsets
    /// ([`FolderSlot::offset`](super::FolderSlot::offset)). False in a chain (BCJ or Delta over LZMA2): stored chunk
    /// payloads are then the next coder's input, not member bytes.
    pub folder_output: bool,
}

impl Lzma2Stage {
    /// The per-volume packed spans of `packed`, a range of the LZMA2 stream's packed offsets (as in the index), with
    /// `stream` offsets in the same terms.
    pub fn spans(&self, folder: &MapFolder, packed: Range<u64>) -> Vec<PackedSpan> {
        let base = self.packed.start;
        let end = packed.end.min(self.packed.end - base);
        folder
            .packed_spans(base + packed.start..base + end)
            .into_iter()
            .map(|s| PackedSpan { stream: s.stream.start - base..s.stream.end - base, ..s })
            .collect()
    }

    fn relative_spans(&self, folder: &MapFolder) -> Vec<PackedSpan> {
        self.spans(folder, 0..self.packed.end - self.packed.start)
    }
}

impl MapFolder {
    /// The folder's LZMA2 coder whose input is a packed stream (a single LZMA2 coder, or the LZMA2 stage of a chain
    /// such as BCJ over LZMA2). None when there is no such coder: other methods, or 7zAES over LZMA2, whose packed
    /// stream is ciphertext.
    pub fn lzma2_stage(&self) -> Option<Lzma2Stage> {
        let mut in_index = 0u64;
        let mut out_index = 0u64;
        for (i, coder) in self.coders.iter().enumerate() {
            let (input, output) = (in_index, out_index);
            in_index += u64::from(coder.in_streams);
            out_index += u64::from(coder.out_streams);
            if coder.kind != super::CoderKind::Lzma2 || coder.in_streams != 1 || coder.out_streams != 1 {
                continue;
            }
            let &[dict_prop] = coder.properties.as_slice() else { continue };
            let Some(stream) = self.packed_streams.iter().position(|&s| s == input) else { continue };
            let start = self.pack_sizes.get(..stream)?.iter().try_fold(0u64, |a, &b| a.checked_add(b))?;
            let end = start.checked_add(*self.pack_sizes.get(stream)?)?;
            let unpacked_size = *self.unpack_sizes.get(usize::try_from(output).ok()?)?;
            let folder_output = !self.bind_pairs.iter().any(|&(_, out)| out == output);
            return Some(Lzma2Stage { coder: i, dict_prop, packed: start..end, unpacked_size, folder_output });
        }
        None
    }

    /// The per-volume spans of `stream`, a range of offsets over the folder's packed streams, cut at volume
    /// boundaries. Only the folder's spans present in the map are covered.
    pub fn packed_spans(&self, stream: Range<u64>) -> Vec<PackedSpan> {
        let mut spans = Vec::new();
        for span in &self.packed {
            let a = stream.start.max(span.stream.start);
            let b = stream.end.min(span.stream.end);
            if a < b {
                let at = span.packed.start + (a - span.stream.start);
                spans.push(PackedSpan { volume: span.volume, packed: at..at + (b - a), stream: a..b });
            }
        }
        spans
    }
}

impl MemberMap {
    /// The chunk index of the LZMA2 stage of folder `folder` (an index into [`Self::folders`]; a member's is
    /// [`MapMember::folder`](super::MapMember::folder)), reading the archive's volumes in memory (in order, from the
    /// first; volumes the folder does not use may be empty). Offsets are relative to the stage's packed stream; see
    /// [`Lzma2IndexBuilder::for_folder`] for a [`VolumeSource`].
    pub fn lzma2_chunks(
        &self,
        folder: usize,
        volumes: &[&[u8]],
        mut options: Lzma2IndexOptions,
    ) -> Result<Lzma2Index, Lzma2Error> {
        let folder = self.folders.get(folder).ok_or(Lzma2Error::NotLzma2Folder)?;
        let stage = folder.lzma2_stage().ok_or(Lzma2Error::NotLzma2Folder)?;
        options.expected_unpacked = options.expected_unpacked.or(Some(stage.unpacked_size));
        let mut input = VolumesInput::new(MemoryInput::new(volumes), stage.relative_spans(folder), OsString::new());
        let mut walker = Walker::new(options);
        let mut cx = Context::from_waker(Waker::noop());
        match walker.poll(&mut input, &mut cx) {
            Poll::Ready(result) => result.map(|()| walker.finish()),
            Poll::Pending => unreachable!("memory input never waits"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parse_and_props() {
        let c = parse_chunk(&[0xE0, 0x00, 0xFF, 0x00, 0x09, 0x5D], 10, 100);
        assert_eq!((c.unpacked_len, c.packed_len, c.props, c.reset), (256, 16, Some(0x5D), Lzma2Reset::DictStateProps));
        assert_eq!(c.payload(), 16..26);
        let s = parse_chunk(&[0x02, 0x00, 0x00], 0, 0);
        assert_eq!((s.unpacked_len, s.packed_len, s.kind), (1, 4, Lzma2ChunkKind::Stored));
        assert!(props_valid(0x5D));
        assert!(!props_valid(225));
        assert!(!props_valid(4 + 9));
        assert_eq!(lzma2_dict(0), 4096);
        assert_eq!(lzma2_dict(18), 2 << 20);
    }

    fn coder(kind: super::super::CoderKind, id: u64, properties: Vec<u8>) -> super::super::MapCoder {
        super::super::MapCoder { kind, id, properties, in_streams: 1, out_streams: 1 }
    }

    fn folder(coders: Vec<super::super::MapCoder>, bind_pairs: Vec<(u64, u64)>, packed_streams: Vec<u64>) -> MapFolder {
        let unpack_sizes = (0..coders.len() as u64).map(|i| 1000 + i).collect();
        MapFolder {
            index: 0,
            coders,
            bind_pairs,
            packed_streams,
            pack_sizes: vec![500],
            packed: vec![
                PackedSpan { volume: 0, packed: 100..300, stream: 0..200 },
                PackedSpan { volume: 1, packed: 0..300, stream: 200..500 },
            ],
            unpack_sizes,
            unpacked_size: 1000,
            crc32: None,
            members: 1,
            cipher: None,
        }
    }

    #[test]
    fn lzma2_stage_follows_the_coder_graph() {
        use super::super::CoderKind;
        // A single LZMA2 coder.
        let single = folder(vec![coder(CoderKind::Lzma2, 0x21, vec![16])], vec![], vec![0]);
        let stage = single.lzma2_stage().unwrap();
        assert_eq!(
            stage,
            Lzma2Stage { coder: 0, dict_prop: 16, packed: 0..500, unpacked_size: 1000, folder_output: true }
        );
        assert_eq!(
            stage.spans(&single, 150..260),
            vec![
                PackedSpan { volume: 0, packed: 250..300, stream: 150..200 },
                PackedSpan { volume: 1, packed: 0..60, stream: 200..260 },
            ]
        );
        // BCJ over LZMA2: the LZMA2 output (stream 1) feeds the BCJ input (stream 0).
        let chain = folder(
            vec![coder(CoderKind::Bcj, 0x0303_0103, vec![]), coder(CoderKind::Lzma2, 0x21, vec![20])],
            vec![(0, 1)],
            vec![1],
        );
        let stage = chain.lzma2_stage().unwrap();
        assert_eq!((stage.coder, stage.dict_prop, stage.unpacked_size, stage.folder_output), (1, 20, 1001, false));
        // 7zAES under LZMA2: the packed stream is ciphertext.
        let aes = folder(
            vec![coder(CoderKind::Aes, 0x06F1_0701, vec![]), coder(CoderKind::Lzma2, 0x21, vec![20])],
            vec![(1, 0)],
            vec![0],
        );
        assert_eq!(aes.lzma2_stage(), None);
        // More packed streams named than sizes recorded (a hand-built folder): no stage, no panic.
        let short = folder(vec![coder(CoderKind::Lzma2, 0x21, vec![16])], vec![], vec![9, 9, 0]);
        assert_eq!(short.lzma2_stage(), None);
        // Bad properties.
        let bad = folder(vec![coder(CoderKind::Lzma2, 0x21, vec![])], vec![], vec![0]);
        assert_eq!(bad.lzma2_stage(), None);
    }
}
