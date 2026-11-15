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
//! A [`VolumeMap`] lists the headers of one RAR volume read on its own, at any position in its set and possibly cut
//! short ([`MemberMap::from_volume`], [`VolumeMapBuilder`]).
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
    /// Compressed data, or a cipher this module does not map: output offsets do not map to packed offsets.
    /// Restart points inside compressed data are future work.
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
    /// RAR 4.x data encryption other than AES (an older unpack version's cipher, or version 29 without a salt).
    /// Not mapped: such members get [`OutputMapping::None`].
    Rar4Legacy { unpack_version: u8, salt: Option<[u8; 8]> },
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

/// How a single-volume walk ([`MemberMap::from_volume`]) ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeEnd {
    /// The volume's end header was read.
    Complete,
    /// The bytes ended at `offset` before the volume's headers did; `offset` is the start of the header being read,
    /// which lies past the end when the last member's data does. Members whose headers were read are listed.
    Truncated { offset: u64 },
    /// The headers from `offset` on are encrypted (RAR `-hp`) and no password was given. No members are listed.
    /// For RAR 5.0 the main header is among them, so the volume facts are unknown; RAR 4.x keeps its main
    /// header in the clear.
    Locked { offset: u64 },
}

/// The headers of one RAR volume, read on their own: any volume of a set, or only its first bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeMap {
    /// [`MapFormat::Rar4`] or [`MapFormat::Rar5`].
    pub format: MapFormat,
    /// Whether the main header was read. False only for [`VolumeEnd::Locked`] RAR 5.0 volumes and bytes that end
    /// inside the main header; the volume facts below are then defaults.
    pub main_read: bool,
    /// Zero-based position in the set. RAR 5.0: the main header's volume number, 0 when it records none (only
    /// the first volume omits it). RAR 4.x: the end header's volume number when it records one, else 0 for a
    /// first volume and None otherwise. A non-volume archive is volume 0.
    pub volume_number: Option<u32>,
    /// Whether this is the first volume, or a single-volume archive. RAR 4.x: the main header's first-volume flag
    /// (`MHD_FIRSTVOLUME`, written since RAR 3.0) or a volume number of 0.
    pub first_volume: bool,
    /// Whether the archive is a volume set (the main header's volume flag).
    pub multi_volume: bool,
    /// Whether the set is named `name.partNN.rar` rather than `name.rar`, `name.r00`, ... Always true for
    /// RAR 5.0; RAR 4.x `MHD_NEWNUMBERING`.
    pub new_naming: bool,
    /// The end header's "not last volume" flag. False when the end header was not reached.
    pub has_next_volume: bool,
    /// Whether the archive is solid (the main header's flag).
    pub solid: bool,
    /// Whether the headers are encrypted (RAR `-hp`).
    pub header_encrypted: bool,
    /// Parameters of the header encryption, as far as they were read.
    pub header_cipher: Option<CipherParams>,
    pub end: VolumeEnd,
    /// One entry per file header, in volume order. Service headers are not listed.
    pub members: Vec<VolumeMember>,
}

/// One file header of a volume: one part of a member.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeMember {
    /// The name exactly as stored.
    pub raw_name: Vec<u8>,
    /// The name decoded by the format's rules, when it decodes.
    pub name: Option<String>,
    pub is_dir: bool,
    /// The member's unpacked size (every part header records the whole member's), when known.
    pub unpacked_size: Option<u64>,
    /// Packed bytes of this part in this volume: `packed.end - packed.start`.
    pub packed_size: u64,
    /// This part's data offsets in this volume, as declared. They may run past the end of truncated bytes.
    pub packed: Range<u64>,
    /// The wire extent of the header, including the IV and padding of an encrypted header.
    pub header: Range<u64>,
    /// The member continues from the previous volume.
    pub split_before: bool,
    /// The member continues in the next volume.
    pub split_after: bool,
    pub method: MapMethod,
    /// How the member's output offsets relate to its packed stream (see [`MapMember::mapping`]). Where this
    /// part falls in that stream depends on earlier volumes' parts.
    pub mapping: OutputMapping,
    pub solid: bool,
    pub encrypted: bool,
    pub cipher: Option<CipherParams>,
    /// Checks as stored in this header: of this part's packed bytes for a part with `split_after`, of the member's
    /// output otherwise.
    pub part_checks: MapChecks,
    /// The member's final checks: `Some(part_checks)` exactly when this is the member's last part.
    pub checks: Option<MapChecks>,
    /// Modification time as seconds since 1970 and nanoseconds.
    pub mtime: Option<(i64, u32)>,
    /// Raw attributes as the host recorded them.
    pub attributes: u64,
    /// Unix permission and type bits, when the host was Unix.
    pub unix_mode: Option<u32>,
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
        read_range(source.as_mut(), offset, buf, cx)
    }
    fn len(&self) -> u64 {
        self.current.as_ref().map_or(0, |s| s.info().length.value())
    }
}

/// One read of a range source, bounded by its current length.
fn read_range(
    source: &mut dyn RangeSource,
    offset: u64,
    buf: &mut [u8],
    cx: &mut Context<'_>,
) -> Result<Got, ProgressiveFailure> {
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

/// How far from the end a ZIP end record is looked for: the record and a comment of up to 1 KiB.
const TAIL_WINDOW: u64 = 22 + 1024;

/// Whether `tail`, the last bytes of a volume, ends with a ZIP end-of-central-directory record.
fn has_zip_end(tail: &[u8]) -> bool {
    (0..tail.len().saturating_sub(21)).rev().any(|at| {
        tail[at..].starts_with(b"PK\x05\x06")
            && usize::from(u16::from_le_bytes([tail[at + 20], tail[at + 21]])) == tail.len() - at - 22
    })
}

/// What a walk produced: a whole-archive map or a single-volume map.
pub(crate) enum Walked {
    Map(MemberMap),
    Volume(VolumeMap),
}

enum Engine {
    Start,
    Detect,
    Tail,
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
    tail: Vec<u8>,
    tail_at: u64,
    /// Map one RAR volume on its own ([`VolumeMap`]) instead of a whole archive.
    single: bool,
}

impl Core {
    fn new(options: MapOptions, single: bool) -> Self {
        let usage = crate::progressive::Usage::new(options.limits.clone());
        Self {
            options,
            usage,
            engine: Engine::Start,
            parked: None,
            magic: Vec::new(),
            tail: Vec::new(),
            tail_at: 0,
            single,
        }
    }

    fn rar(&self) -> Engine {
        Engine::Rar(Box::new(crate::rar5::map::RarWalker::new(&self.options, self.usage.clone(), self.single)))
    }

    fn poll_map(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<MemberMap, MapError>> {
        self.poll(input, cx).map_ok(|walked| match walked {
            Walked::Map(map) => map,
            Walked::Volume(_) => unreachable!("whole-archive walks produce member maps"),
        })
    }

    fn poll_volume(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<VolumeMap, MapError>> {
        self.poll(input, cx).map_ok(|walked| match walked {
            Walked::Volume(map) => map,
            Walked::Map(_) => unreachable!("single-volume walks produce volume maps"),
        })
    }

    fn poll(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<Walked, MapError>> {
        let result = self.poll_inner(input, cx);
        if matches!(result, Poll::Ready(_)) {
            self.engine = Engine::Done;
        }
        result
    }

    fn poll_inner(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<Walked, MapError>> {
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
                                if self.single {
                                    return Poll::Ready(Err(MapError::NotArchive));
                                }
                                MapFormat::Zip
                            } else if self.magic == b"Rar!" {
                                MapFormat::Rar5
                            } else if self.single {
                                // A self-extracting stub: only RAR volumes are mapped one by one.
                                MapFormat::Rar5
                            } else {
                                // A self-extracting stub: look for a ZIP end record before scanning for RAR.
                                let len = input.len();
                                self.tail_at = len.saturating_sub(TAIL_WINDOW);
                                self.engine = Engine::Tail;
                                continue;
                            }
                        }
                        Ok(Got::Eof) if self.magic.is_empty() => return Poll::Ready(Err(MapError::NotArchive)),
                        Ok(Got::Eof) => MapFormat::Rar5,
                    };
                    self.engine = match format {
                        MapFormat::Zip => {
                            Engine::Zip(Box::new(zip::ZipWalker::new(self.usage.clone(), &self.options.limits)))
                        }
                        _ => self.rar(),
                    };
                }
                Engine::Tail => {
                    let mut buf = [0u8; 1024];
                    let at = self.tail_at + self.tail.len() as u64;
                    let want = (input.len().saturating_sub(at)).min(buf.len() as u64) as usize;
                    let n = self.parked.take().unwrap_or(want);
                    let zip = match read(input, &self.usage, at, &mut buf[..n], cx) {
                        Err(e) => return Poll::Ready(Err(MapError::from_failure(0, e))),
                        Ok(Got::NotYet) => {
                            self.parked = Some(n);
                            return Poll::Pending;
                        }
                        Ok(Got::Filled(count)) => {
                            self.tail.extend_from_slice(&buf[..count]);
                            if at + (count as u64) < input.len() {
                                continue;
                            }
                            has_zip_end(&self.tail)
                        }
                        // The tail is not there to tell: the RAR scanner decides.
                        Ok(Got::Hole | Got::Eof) => false,
                    };
                    self.tail = Vec::new();
                    self.engine = if zip {
                        Engine::Zip(Box::new(zip::ZipWalker::new(self.usage.clone(), &self.options.limits)))
                    } else {
                        self.rar()
                    };
                }
                Engine::Rar(walker) => return walker.poll(input, cx),
                Engine::Zip(walker) => return walker.poll(input, cx, &self.options).map_ok(Walked::Map),
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
        let mut core = Core::new(options, false);
        let mut cx = Context::from_waker(Waker::noop());
        match core.poll_map(&mut input, &mut cx) {
            Poll::Ready(result) => result,
            Poll::Pending => unreachable!("memory input never waits"),
        }
    }

    /// Maps one RAR volume on its own: any volume of a set (a `.part07.rar`, or an obfuscated file that is
    /// really volume 12), or only its first bytes (a single Usenet article).
    ///
    /// Volume 0 is not needed and the volume's position is not checked against anything: it is reported in
    /// [`VolumeMap::volume_number`]. Bytes that end inside member data or inside a header give
    /// [`VolumeEnd::Truncated`] with what was read. Encrypted headers (`-hp`) are decrypted with
    /// [`MapOptions::password`]; without one (or with an empty one) the map ends [`VolumeEnd::Locked`] with no
    /// members. A wrong password is [`MapError::WrongPassword`] where it can be told; bytes ending inside the first
    /// encrypted header are a cut ([`VolumeEnd::Truncated`]) unless its decrypted start is not a plausible header,
    /// so without a password check value (always for RAR 4.x) a wrong password can go unnoticed in a short prefix. `options.first_name` names this volume in
    /// failures; the volume in [`MapError`] variants is 0. ZIP is [`MapError::NotArchive`].
    pub fn from_volume(bytes: &[u8], options: MapOptions) -> Result<VolumeMap, MapError> {
        let volumes = [bytes];
        let mut input = MemoryInput { volumes: &volumes, current: None };
        let mut core = Core::new(options, true);
        let mut cx = Context::from_waker(Waker::noop());
        match core.poll_volume(&mut input, &mut cx) {
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
        Self { input: SourceInput { source, current: None }, core: Core::new(options, false) }
    }

    pub fn poll_map(&mut self, cx: &mut Context<'_>) -> Poll<Result<MemberMap, MapError>> {
        self.core.poll_map(&mut self.input, cx)
    }
}

/// One volume behind a [`RangeSource`].
struct RangeInput {
    source: Box<dyn RangeSource>,
}

impl MapInput for RangeInput {
    fn open(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> Result<Opened, ProgressiveFailure> {
        Ok(Opened::Ready)
    }
    fn read(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> Result<Got, ProgressiveFailure> {
        read_range(self.source.as_mut(), offset, buf, cx)
    }
    fn len(&self) -> u64 {
        self.source.info().length.value()
    }
}

/// Builds a [`VolumeMap`] of one RAR volume from a [`RangeSource`], reading only header bytes: the pollable form of
/// [`MemberMap::from_volume`].
///
/// [`RangeRead::NotYet`] makes [`Self::poll_map`] return `Pending`; the provider wakes the task's waker when a retry
/// is warranted, and the parked read is retried with the same length. A [`RangeRead::Hole`] inside header bytes is
/// [`MapError::HeaderHole`]. The source's current length is where the volume ends: reads past it give
/// [`VolumeEnd::Truncated`].
pub struct VolumeMapBuilder {
    input: RangeInput,
    core: Core,
}

impl VolumeMapBuilder {
    pub fn new(source: Box<dyn RangeSource>, options: MapOptions) -> Self {
        Self { input: RangeInput { source }, core: Core::new(options, true) }
    }

    pub fn poll_map(&mut self, cx: &mut Context<'_>) -> Poll<Result<VolumeMap, MapError>> {
        self.core.poll_volume(&mut self.input, cx)
    }
}
