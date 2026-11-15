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

//! Member maps: a typed listing of an archive's headers that says where each member's bytes sit.
//!
//! A [`MemberMap`] is built from archive bytes in memory ([`MemberMap::from_memory`]) or from a
//! [`VolumeSource`](crate::progressive::VolumeSource) whose ranges may arrive late ([`MapBuilder`]). Only headers are
//! read: member data is skipped, never fetched. Each member lists its [`MapPiece`]s, one per part header, with the
//! volume, the packed data range in that volume, the header's own wire range and, for stored members, the exact
//! output range the piece carries. [`MapMember::packed_spans`] turns an output range of a stored member into the
//! per-volume packed spans that must be fetched to produce it.
//!
//! RAR 5.0 and RAR 4.x (including headers encrypted with `-hp` when a password is given) and single-disk ZIP are
//! mapped. Passwords and keys never appear in a map; cipher parameters (salts, IVs, KDF counts, check values) do.
//! See `docs/member-map.md`.

mod zip;

use crate::progressive::{
    FailureKind, ProgressiveFailure, ProgressiveLimits, RangeRead, RangeSource, Resource, SessionControl, VolumeAnswer,
    VolumeRequest, VolumeSource,
};
use std::{
    ffi::{OsStr, OsString},
    ops::Range,
    task::{Context, Poll, Waker},
};

/// The container format of a mapped archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MapFormat {
    Rar4,
    Rar5,
    Zip,
}

/// How a mapped walk ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapEnd {
    /// The archive's final end header was read.
    Complete,
    /// Volume `volume` (zero-based) was not available. Every earlier volume was read to its end header.
    MissingVolume { volume: u32 },
    /// Volume `volume` ended at `offset` before its headers did, for example a buffer holding only a volume's
    /// first bytes. Pieces whose headers were read are listed even when their data lies past the end.
    Truncated { volume: u32, offset: u64 },
}

/// A listing of an archive's members and where their bytes are.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MemberMap {
    pub format: MapFormat,
    /// Whether the headers themselves are encrypted (RAR `-hp`).
    pub header_encrypted: bool,
    /// Parameters of the header encryption, when the format records them.
    pub header_cipher: Option<CipherParams>,
    /// Whether the archive's final end header was seen. False exactly when `end` is not [`MapEnd::Complete`].
    pub complete: bool,
    pub end: MapEnd,
    /// Volumes whose headers were read, counting a truncated last one.
    pub volumes: u32,
    pub members: Vec<MapMember>,
}

/// How a member's data was packed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MapMethod {
    /// Data stored as is (possibly encrypted).
    Stored,
    /// Compressed. `id` is the format's own method number: RAR 5.0 levels 1 to 5, the RAR 4.x method byte
    /// (0x31 to 0x35), or the ZIP method number.
    Compressed { id: u16 },
}

/// How output offsets of a member relate to its packed stream, the concatenation of all its pieces' packed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OutputMapping {
    /// Output byte `o` is stream byte `o` (plain stored data).
    Direct,
    /// AES-CBC with 16-byte blocks and no prefix (encrypted RAR stored data). Output byte `o` is stream byte `o`;
    /// the stream is padded to whole blocks and the padding maps to no output. Decrypting block `k` needs
    /// ciphertext block `k - 1`, or the member IV for block 0.
    CbcBlocks,
    /// A counter-mode cipher after a `skip`-byte prefix (WinZip AES: salt and verifier). Output byte `o` is stream
    /// byte `o + skip` and decrypts on its own. Trailing authentication bytes map to no output.
    Counter { skip: u64 },
    /// A stream cipher after a `skip`-byte prefix whose state depends on every earlier byte (ZipCrypto). Output
    /// byte `o` is stream byte `o + skip`, but producing it needs the stream from its start.
    Sequential { skip: u64 },
    /// Compressed data: output offsets do not map to packed offsets. Restart points inside compressed data are
    /// future work.
    None,
}

/// Cipher parameters of encrypted data or headers. Never keys or passwords.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CipherParams {
    /// RAR 5.0: AES-256-CBC, key from PBKDF2-HMAC-SHA256 with `2^kdf_count` rounds over `salt`.
    Rar5 {
        kdf_count: u8,
        salt: [u8; 16],
        /// The data IV. None for header encryption, where each header carries its own.
        iv: Option<[u8; 16]>,
        /// Password check value and its 4-byte checksum, when recorded.
        check: Option<([u8; 8], [u8; 4])>,
        /// Whether the member's CRC32/BLAKE2sp checks are keyed with the password.
        keyed_checks: bool,
    },
    /// RAR 4.x: AES-128-CBC, key and IV derived from the password and this salt (2^18 SHA-1 rounds).
    Rar4 { salt: [u8; 8] },
    /// Traditional PKWARE encryption. `check` is the byte the 12-byte encryption header must decrypt to last.
    ZipCrypto { check: u8 },
    /// WinZip AES in counter mode. `strength` is 1, 2 or 3 (AES-128, -192, -256).
    WinZipAes { strength: u8, vendor_version: u16, salt: Vec<u8>, verifier: [u8; 2] },
}

/// Checksums a header declares. For a final piece or a member they cover the output; RAR intermediate parts
/// declare checks of their packed bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MapChecks {
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
    /// Whether the values are keyed with the password (RAR 5.0 encrypted members).
    pub keyed: bool,
}

/// One part of a member: its bytes in one volume.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MapPiece {
    /// Zero-based volume index.
    pub volume: u32,
    /// The packed data bytes in that volume.
    pub packed: Range<u64>,
    /// The wire extent of the header (or ZIP local header) that announced them.
    pub header: Range<u64>,
    /// Offset of `packed.start` within the member's packed stream (all pieces' packed bytes in order).
    pub stream_offset: u64,
    /// Output bytes these packed bytes carry: exact for [`OutputMapping::Direct`], [`OutputMapping::CbcBlocks`]
    /// with a known size and [`OutputMapping::Counter`]; None otherwise.
    pub out: Option<Range<u64>>,
    /// Checks declared by this part's header.
    pub checks: MapChecks,
    /// Whether this is the member's last part.
    pub final_part: bool,
}

/// A packed byte range in one volume, as returned by [`MapMember::packed_spans`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedSpan {
    pub volume: u32,
    pub packed: Range<u64>,
    /// The same bytes as offsets in the member's packed stream.
    pub stream: Range<u64>,
}

/// One logical member, in archive order.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MapMember {
    /// Zero-based position among the archive's members.
    pub ordinal: u64,
    /// The name exactly as stored. For ZIP, the UTF-8 bytes of the decoded name.
    pub raw_name: Vec<u8>,
    /// The name decoded by the format's rules, when it decodes.
    pub name: Option<String>,
    pub is_dir: bool,
    pub unpacked_size: Option<u64>,
    /// Packed bytes over the pieces seen.
    pub packed_size: u64,
    pub method: MapMethod,
    pub mapping: OutputMapping,
    pub solid: bool,
    pub encrypted: bool,
    pub cipher: Option<CipherParams>,
    /// Final member checks, once the final piece is seen.
    pub checks: Option<MapChecks>,
    /// Modification time as seconds since 1970 and nanoseconds.
    pub mtime: Option<(i64, u32)>,
    /// Raw attributes as the host recorded them.
    pub attributes: u64,
    /// Unix permission and type bits, when the host was Unix.
    pub unix_mode: Option<u32>,
    /// Whether the final piece was seen.
    pub complete: bool,
    pub pieces: Vec<MapPiece>,
}

fn floor_block(offset: u64) -> u64 {
    offset & !15
}
fn ceil_block(offset: u64) -> u64 {
    offset.checked_next_multiple_of(16).unwrap_or(!15)
}

impl OutputMapping {
    /// Output offsets carried by the stream range `stream` of a member of size `size`.
    pub(crate) fn out_of(self, stream: Range<u64>, size: Option<u64>) -> Option<Range<u64>> {
        let clip = |r: Range<u64>| match size {
            Some(size) => r.start.min(size)..r.end.min(size),
            None => r,
        };
        match self {
            Self::Direct => Some(clip(stream)),
            Self::CbcBlocks => size.map(|_| clip(stream)),
            Self::Counter { skip } => {
                size.map(|_| clip(stream.start.saturating_sub(skip)..stream.end.saturating_sub(skip)))
            }
            Self::Sequential { .. } | Self::None => None,
        }
    }
}

impl MapMember {
    /// The per-volume packed spans needed to produce output range `out` of a stored member, in stream order.
    ///
    /// `out` is clipped to the unpacked size. Spans are cut at piece boundaries, and only pieces present in the map
    /// are covered: for a map with `complete: false`, compare the spans' `stream` ranges with what you asked for.
    ///
    /// - [`OutputMapping::Direct`]: exactly the bytes of `out`.
    /// - [`OutputMapping::CbcBlocks`]: widened to whole 16-byte blocks, plus the block before the first one, whose
    ///   ciphertext is the IV of the first block. When the first block is block 0 its IV is the member IV
    ///   ([`CipherParams::Rar5`]) or derived from the password (RAR 4.x), and no earlier block is included. The
    ///   end may include padding bytes past the unpacked size. Restart points of stored members are exactly these
    ///   spans: decryption can start at any block boundary.
    /// - [`OutputMapping::Counter`]: exactly the bytes of `out`, shifted past the prefix. The salt and verifier
    ///   at stream offset 0 are part of the cipher parameters.
    /// - [`OutputMapping::Sequential`]: everything from stream offset 0 to the end of `out`.
    ///
    /// Returns None for compressed members (restart points inside compressed data are future work) and for
    /// encrypted members whose size is unknown.
    pub fn packed_spans(&self, out: Range<u64>) -> Option<Vec<PackedSpan>> {
        let size = self.unpacked_size;
        let (start, end) = match size {
            Some(size) => (out.start.min(size), out.end.min(size)),
            None => (out.start, out.end),
        };
        if start >= end {
            return match self.mapping {
                OutputMapping::None => None,
                _ => Some(Vec::new()),
            };
        }
        let stream = match self.mapping {
            OutputMapping::Direct => start..end,
            OutputMapping::CbcBlocks => {
                size?;
                let first = floor_block(start);
                first.saturating_sub(16)..ceil_block(end)
            }
            OutputMapping::Counter { skip } => {
                size?;
                start.checked_add(skip)?..end.checked_add(skip)?
            }
            OutputMapping::Sequential { skip } => {
                size?;
                0..end.checked_add(skip)?
            }
            OutputMapping::None => return None,
        };
        let mut spans = Vec::new();
        for piece in &self.pieces {
            let len = piece.packed.end - piece.packed.start;
            let piece_end = piece.stream_offset + len;
            let a = stream.start.max(piece.stream_offset);
            let b = stream.end.min(piece_end);
            if a < b {
                let at = piece.packed.start + (a - piece.stream_offset);
                spans.push(PackedSpan { volume: piece.volume, packed: at..at + (b - a), stream: a..b });
            }
        }
        Some(spans)
    }
}

/// A typed failure to build a map.
#[derive(Debug)]
#[non_exhaustive]
pub enum MapError {
    /// The bytes are not an archive this module maps.
    NotArchive,
    /// The first volume is not available.
    MissingFirstVolume,
    /// Encrypted headers need a password.
    PasswordRequired,
    /// The password does not open the encrypted headers.
    WrongPassword,
    /// The source reported a permanent hole inside header bytes.
    HeaderHole { volume: u32, offset: u64 },
    /// Headers are corrupt or inconsistent.
    Malformed { volume: u32, failure: Box<ProgressiveFailure> },
    /// A header uses a feature this module does not map.
    Unsupported { volume: u32, failure: Box<ProgressiveFailure> },
    /// A budget in [`ProgressiveLimits`] was exhausted.
    Limit { resource: Resource, limit: u64, attempted: u64 },
    /// The source failed, broke its contract, or the walk was canceled.
    Source(Box<ProgressiveFailure>),
    /// The volume source answered [`VolumeAnswer::Abort`].
    Aborted { volume: u32 },
    /// The builder already returned its result.
    AlreadyFinished,
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotArchive => write!(f, "not a RAR or ZIP archive"),
            Self::MissingFirstVolume => write!(f, "the first volume is not available"),
            Self::PasswordRequired => write!(f, "encrypted headers need a password"),
            Self::WrongPassword => write!(f, "wrong password for the encrypted headers"),
            Self::HeaderHole { volume, offset } => write!(f, "hole in headers of volume {volume} at {offset}"),
            Self::Malformed { volume, failure } => write!(f, "malformed headers in volume {volume}: {failure}"),
            Self::Unsupported { volume, failure } => write!(f, "unsupported header in volume {volume}: {failure}"),
            Self::Limit { resource, limit, attempted } => {
                write!(f, "map limit {resource:?} exceeded ({attempted} > {limit})")
            }
            Self::Source(failure) => write!(f, "source failure: {failure}"),
            Self::Aborted { volume } => write!(f, "source aborted at volume {volume}"),
            Self::AlreadyFinished => write!(f, "map already returned"),
        }
    }
}

impl std::error::Error for MapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed { failure, .. } | Self::Unsupported { failure, .. } | Self::Source(failure) => {
                Some(failure.as_ref())
            }
            _ => None,
        }
    }
}

impl MapError {
    /// Classifies a progressive failure raised while reading volume `volume`.
    pub(crate) fn from_failure(volume: u32, failure: ProgressiveFailure) -> Self {
        use crate::error::RarFailure;
        match &failure.kind {
            FailureKind::PasswordRequired => Self::PasswordRequired,
            FailureKind::WrongPassword => Self::WrongPassword,
            FailureKind::Limit { resource, limit, attempted } => {
                Self::Limit { resource: *resource, limit: *limit, attempted: *attempted }
            }
            FailureKind::Rar(rar) => match rar.as_ref() {
                RarFailure::NotRar => Self::NotArchive,
                RarFailure::PasswordRequired { .. } => Self::PasswordRequired,
                RarFailure::WrongPassword { .. } => Self::WrongPassword,
                RarFailure::Unsupported(_) => Self::Unsupported { volume, failure: Box::new(failure) },
                RarFailure::Canceled => Self::Source(Box::new(failure)),
                _ => Self::Malformed { volume, failure: Box::new(failure) },
            },
            FailureKind::UnsupportedMethod => Self::Unsupported { volume, failure: Box::new(failure) },
            FailureKind::Input { .. }
            | FailureKind::SourceChanged
            | FailureKind::SourceContract
            | FailureKind::Canceled
            | FailureKind::InvalidCapability => Self::Source(Box::new(failure)),
            _ => Self::Malformed { volume, failure: Box::new(failure) },
        }
    }
}

/// Options for building a map.
#[derive(Clone)]
pub struct MapOptions {
    /// Name of the first volume. It names the volumes asked of a [`VolumeSource`] and appears in failures.
    pub first_name: OsString,
    /// Password for encrypted headers. Data encryption needs none: its parameters are listed without it.
    pub password: Option<String>,
    /// Header byte, metadata, name, entry, part, request and KDF budgets.
    pub limits: ProgressiveLimits,
    /// Cancels a walk, including a key derivation in progress.
    pub control: SessionControl,
}

impl MapOptions {
    pub fn new(first_name: impl Into<OsString>) -> Self {
        Self {
            first_name: first_name.into(),
            password: None,
            limits: ProgressiveLimits::default(),
            control: SessionControl::default(),
        }
    }

    pub fn password(mut self, password: Option<&str>) -> Self {
        self.password = password.map(str::to_owned);
        self
    }
}

/// What opening a volume gave.
pub(crate) enum Opened {
    Ready,
    Wait,
    Missing,
    Abort,
}

/// What a read gave. `Eof` means the offset is at or past the volume's end.
pub(crate) enum Got {
    Filled(usize),
    NotYet,
    Hole,
    Eof,
}

/// The walkers' view of their input: one current volume at a time.
pub(crate) trait MapInput {
    fn open(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> Result<Opened, ProgressiveFailure>;
    fn read(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> Result<Got, ProgressiveFailure>;
    /// Length of the current volume.
    fn len(&self) -> u64;
}

struct MemoryInput<'a> {
    volumes: &'a [&'a [u8]],
    current: Option<&'a [u8]>,
}

impl MapInput for MemoryInput<'_> {
    fn open(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> Result<Opened, ProgressiveFailure> {
        self.current = self.volumes.get(request.index as usize).copied();
        Ok(if self.current.is_some() { Opened::Ready } else { Opened::Missing })
    }
    fn read(&mut self, offset: u64, buf: &mut [u8], _: &mut Context<'_>) -> Result<Got, ProgressiveFailure> {
        let data = self.current.ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?;
        let Some(rest) = usize::try_from(offset).ok().and_then(|at| data.get(at..)).filter(|r| !r.is_empty()) else {
            return Ok(Got::Eof);
        };
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(Got::Filled(n))
    }
    fn len(&self) -> u64 {
        self.current.map_or(0, |d| d.len() as u64)
    }
}

struct SourceInput {
    source: Box<dyn VolumeSource>,
    current: Option<Box<dyn RangeSource>>,
}

impl MapInput for SourceInput {
    fn open(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> Result<Opened, ProgressiveFailure> {
        self.current = None;
        Ok(match self.source.volume(request, cx)? {
            VolumeAnswer::Ready(source) => {
                self.current = Some(source);
                Opened::Ready
            }
            VolumeAnswer::Wait => Opened::Wait,
            VolumeAnswer::Missing => Opened::Missing,
            VolumeAnswer::Abort => Opened::Abort,
        })
    }
    fn read(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> Result<Got, ProgressiveFailure> {
        let source = self.current.as_mut().ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?;
        let len = source.info().length.value();
        if offset >= len {
            return Ok(Got::Eof);
        }
        let n = buf.len().min(usize::try_from(len - offset).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(Got::Filled(0));
        }
        Ok(match source.read_at(offset, &mut buf[..n], cx)? {
            RangeRead::Filled { count } if count > 0 && count <= n => Got::Filled(count),
            RangeRead::Filled { .. } | RangeRead::Hole { len: 0 } => {
                return Err(ProgressiveFailure::new(FailureKind::SourceContract));
            }
            RangeRead::NotYet => Got::NotYet,
            RangeRead::Hole { .. } => Got::Hole,
        })
    }
    fn len(&self) -> u64 {
        self.current.as_ref().map_or(0, |s| s.info().length.value())
    }
}

/// Reads through `input`, charging one source request per call and one provider wake per `NotYet`.
pub(crate) fn read(
    input: &mut dyn MapInput,
    usage: &crate::progressive::Usage,
    offset: u64,
    buf: &mut [u8],
    cx: &mut Context<'_>,
) -> Result<Got, ProgressiveFailure> {
    usage.charge(Resource::SourceRequests, 1)?;
    let got = input.read(offset, buf, cx)?;
    if matches!(got, Got::NotYet) {
        usage.charge(Resource::ProviderWakes, 1)?;
    }
    Ok(got)
}

enum Engine {
    Start,
    Detect,
    Rar(Box<crate::rar5::map::RarWalker>),
    Zip(Box<zip::ZipWalker>),
    Done,
}

/// The format-independent part of a walk: options, the first volume and format detection.
struct Core {
    options: MapOptions,
    usage: crate::progressive::Usage,
    engine: Engine,
    parked: Option<usize>,
    magic: Vec<u8>,
}

impl Core {
    fn new(options: MapOptions) -> Self {
        let usage = crate::progressive::Usage::new(options.limits.clone());
        Self { options, usage, engine: Engine::Start, parked: None, magic: Vec::new() }
    }

    fn poll(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<MemberMap, MapError>> {
        let result = self.poll_inner(input, cx);
        if matches!(result, Poll::Ready(_)) {
            self.engine = Engine::Done;
        }
        result
    }

    fn poll_inner(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<MemberMap, MapError>> {
        loop {
            if self.options.control.is_canceled() {
                return Poll::Ready(Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled)))));
            }
            match &mut self.engine {
                Engine::Start => {
                    let request = VolumeRequest { index: 0, expected: self.options.first_name.clone() };
                    match input.open(&request, cx) {
                        Err(e) => return Poll::Ready(Err(MapError::from_failure(0, e))),
                        Ok(Opened::Ready) => self.engine = Engine::Detect,
                        Ok(Opened::Wait) => return Poll::Pending,
                        Ok(Opened::Missing) => return Poll::Ready(Err(MapError::MissingFirstVolume)),
                        Ok(Opened::Abort) => return Poll::Ready(Err(MapError::Aborted { volume: 0 })),
                    }
                }
                Engine::Detect => {
                    let mut buf = [0u8; 4];
                    let at = self.magic.len();
                    let n = self.parked.take().unwrap_or(4 - at);
                    let format = match read(input, &self.usage, at as u64, &mut buf[..n], cx) {
                        Err(e) => return Poll::Ready(Err(MapError::from_failure(0, e))),
                        Ok(Got::NotYet) => {
                            self.parked = Some(n);
                            return Poll::Pending;
                        }
                        Ok(Got::Hole) => {
                            return Poll::Ready(Err(MapError::HeaderHole { volume: 0, offset: at as u64 }));
                        }
                        Ok(Got::Filled(count)) => {
                            self.magic.extend_from_slice(&buf[..count]);
                            if self.magic.len() < 4 {
                                continue;
                            }
                            if self.magic == b"PK\x03\x04" || self.magic == b"PK\x05\x06" {
                                MapFormat::Zip
                            } else {
                                MapFormat::Rar5
                            }
                        }
                        Ok(Got::Eof) if self.magic.is_empty() => return Poll::Ready(Err(MapError::NotArchive)),
                        Ok(Got::Eof) => MapFormat::Rar5,
                    };
                    self.engine = match format {
                        MapFormat::Zip => Engine::Zip(Box::new(zip::ZipWalker::new(self.usage.clone()))),
                        _ => Engine::Rar(Box::new(crate::rar5::map::RarWalker::new(&self.options, self.usage.clone()))),
                    };
                }
                Engine::Rar(walker) => return walker.poll(input, cx),
                Engine::Zip(walker) => return walker.poll(input, cx, &self.options),
                Engine::Done => return Poll::Ready(Err(MapError::AlreadyFinished)),
            }
        }
    }
}

impl MemberMap {
    /// Maps an archive whose volumes are in memory, in order, starting with the first. A volume may be cut short
    /// and later volumes may be absent: the map then has `complete: false` and lists what was seen.
    pub fn from_memory(
        volumes: &[&[u8]],
        first_name: impl AsRef<OsStr>,
        password: Option<&str>,
    ) -> Result<MemberMap, MapError> {
        Self::from_memory_with(volumes, MapOptions::new(first_name.as_ref()).password(password))
    }

    /// [`Self::from_memory`] with explicit options.
    pub fn from_memory_with(volumes: &[&[u8]], options: MapOptions) -> Result<MemberMap, MapError> {
        let mut input = MemoryInput { volumes, current: None };
        let mut core = Core::new(options);
        let mut cx = Context::from_waker(Waker::noop());
        match core.poll(&mut input, &mut cx) {
            Poll::Ready(result) => result,
            Poll::Pending => unreachable!("memory input never waits"),
        }
    }
}

/// Builds a [`MemberMap`] from a [`VolumeSource`], reading only header bytes.
///
/// [`RangeRead::NotYet`] and [`VolumeAnswer::Wait`] make [`Self::poll_map`] return `Pending`; the provider wakes the
/// task's waker when a retry is warranted, and the parked read is retried with the same length. A
/// [`RangeRead::Hole`] inside header bytes is [`MapError::HeaderHole`]. [`VolumeAnswer::Missing`] after the first
/// volume ends the map with `complete: false`.
pub struct MapBuilder {
    input: SourceInput,
    core: Core,
}

impl MapBuilder {
    pub fn new(source: Box<dyn VolumeSource>, options: MapOptions) -> Self {
        Self { input: SourceInput { source, current: None }, core: Core::new(options) }
    }

    pub fn poll_map(&mut self, cx: &mut Context<'_>) -> Poll<Result<MemberMap, MapError>> {
        self.core.poll(&mut self.input, cx)
    }
}
