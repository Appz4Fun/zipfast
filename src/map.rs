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
//! RAR 5.0 and RAR 4.x (including headers encrypted with `-hp` when a password is given), single-disk ZIP, split
//! ZIP sets (`name.z01`, ..., `name.zip`, passed in that order) and 7z (single files and plain byte splits
//! `.7z.001`, `.7z.002`, ..., including encoded and `-mhe` encrypted headers) are mapped. Passwords and keys never
//! appear in a map; cipher parameters (salts, IVs, KDF counts, check values) do.
//! See `docs/member-map.md`.
//!
//! [`MemberReader`] and [`extract_member_from`] stream a stored member's plaintext from any output offset, reading
//! only the packed bytes that offset needs, for example to fill the rest of a partial output from another copy. See
//! `docs/extract-member-from.md`.

mod member_reader;
pub(crate) mod sevenzip;
pub(crate) mod zip;
pub(crate) mod zip_split;

pub use member_reader::{
    ExtractFromError, ExtractedFrom, MemberReader, UnsupportedRead, extract_member_from, extract_member_from_with,
};

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
    /// 7z, a single file or a plain byte split (`.7z.001`, `.7z.002`, ...).
    SevenZip,
}

/// How a mapped walk ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MapEnd {
    /// The archive's final end header was read.
    Complete,
    /// Volume `volume` (zero-based) was not available. Every earlier volume was read to its end header.
    MissingVolume { volume: u32 },
    /// Volume `volume` ended at `offset` before its headers did, for example a buffer holding only a volume's
    /// first bytes. Pieces whose headers were read are listed even when their data lies past the end. 7z: only
    /// bytes that end inside the signature header.
    Truncated { volume: u32, offset: u64 },
    /// The header at `offset` in volume `volume` is damaged or unsupported, after volume 0's main header was read.
    /// The walk stops there; members and pieces whose headers came before it are listed.
    Damaged { volume: u32, offset: u64, reason: HeaderDamage },
    /// 7z: the archive's header, at archive offset `offset` near the end of the set, is not in the bytes available.
    /// Volume `volume` (zero-based) is missing, or ends before its advertised length (a cut set, where only the
    /// first pieces are present). Nothing but the start header was read, so no members are listed.
    ///
    /// `suspect` is a hint, not a finding: the first volume opened that is shorter than a later one. A split cut at
    /// one size makes only the last volume short, so that volume may have lost bytes (and the set may be complete
    /// after all); but 7-Zip also writes splits of several sizes (`-v1000b -v2000b`), where it is honest. Which
    /// volume was cut cannot be told from the lengths alone.
    HeaderUnavailable { volume: u32, offset: u64, suspect: Option<u32> },
}

/// What is wrong with the header a walk stopped at ([`MapEnd::Damaged`], [`VolumeEnd::Damaged`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeaderDamage {
    /// The header failed its checksum.
    Checksum,
    /// The header's fields or sizes are inconsistent, or it cannot stand where it is. The text says what.
    Malformed(&'static str),
    /// The header uses a feature this module does not map. The text names it.
    Unsupported(&'static str),
}

impl HeaderDamage {
    /// The damage a walk failure describes, if it is damage to a header: a header checksum, framing or field failure,
    /// a header out of order or inconsistent with an earlier one, or a RAR 4.x header feature not mapped. Limits,
    /// allocation failures, internal invariants and everything else are not.
    pub(crate) fn of(error: &MapError) -> Option<Self> {
        use crate::error::{RarFailure, RarIntegrityReason, RarUnsupported};
        use crate::progressive::ChecksumScope;
        match error {
            MapError::Malformed { failure, .. } => match &failure.kind {
                FailureKind::ChecksumMismatch { scope: ChecksumScope::Header, .. } => Some(Self::Checksum),
                // The walker's own header order and consistency checks, and the parser's framing.
                FailureKind::Malformed(what) => Some(Self::Malformed(what)),
                // A field running past its header's declared size.
                FailureKind::Truncated => Some(Self::Malformed("header fields run past the header size")),
                FailureKind::Rar(rar) => match rar.as_ref() {
                    RarFailure::Integrity { reason, .. } | RarFailure::EncryptedIntegrity { reason, .. } => {
                        match reason {
                            RarIntegrityReason::HeaderCrc => Some(Self::Checksum),
                            RarIntegrityReason::HeaderFraming(what) => Some(Self::Malformed(what)),
                            RarIntegrityReason::MalformedEncryptionRecord => Some(Self::Malformed("encryption record")),
                            RarIntegrityReason::ChangedContinuationEncoding
                            | RarIntegrityReason::SplitSizeMismatch { .. } => {
                                Some(Self::Malformed("member continuation"))
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                },
                _ => None,
            },
            MapError::Unsupported { failure, .. } => match &failure.kind {
                FailureKind::Rar(rar) => match rar.as_ref() {
                    RarFailure::Unsupported(RarUnsupported::Rar4Feature(what)) => Some(Self::Unsupported(what)),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }
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
    /// Volumes whose headers were read, counting a truncated last one. 7z: volumes opened, which is every volume
    /// of the set when the header was read.
    pub volumes: u32,
    pub members: Vec<MapMember>,
    /// 7z: the archive's folders (its coded streams), in archive order. Empty for other formats.
    pub folders: Vec<MapFolder>,
}

/// A 7z folder: one coded stream, the output of a chain of coders over one or more packed streams, holding the
/// data of one or more members back to back.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MapFolder {
    /// Zero-based position among the archive's folders ([`FolderSlot::index`]).
    pub index: u32,
    /// The coders as stored. Their order is not the decoding order: follow [`Self::packed_streams`] and
    /// [`Self::bind_pairs`]. 7-Zip stores 7zAES first, so LZMA over 7zAES is `[Aes, Lzma]` with bind pair `(1, 0)`
    /// (the 7zAES output feeds the LZMA input) and the packed stream feeding input 0.
    pub coders: Vec<MapCoder>,
    /// Bind pairs as stored: `(in_index, out_index)`, coder input stream `in_index` is fed by coder output stream
    /// `out_index`. Stream indexes count over all coders in order.
    pub bind_pairs: Vec<(u64, u64)>,
    /// The coder input streams fed by packed streams, in packed stream order.
    pub packed_streams: Vec<u64>,
    /// The size of each packed stream, in order.
    pub pack_sizes: Vec<u64>,
    /// The folder's packed bytes, all its packed streams back to back, cut at volume boundaries. `stream` counts
    /// over that concatenation.
    pub packed: Vec<PackedSpan>,
    /// The size of every coder output stream, in stream order.
    pub unpack_sizes: Vec<u64>,
    /// The size of the folder's output, the one coder output stream not bound to an input.
    pub unpacked_size: u64,
    /// The CRC32 of the folder's output, when recorded.
    pub crc32: Option<u32>,
    /// How many members have their data in this folder.
    pub members: u64,
    /// The 7zAES parameters when a coder is 7zAES.
    pub cipher: Option<CipherParams>,
}

/// One coder of a 7z folder.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MapCoder {
    pub kind: CoderKind,
    /// The method id as stored, big-endian bytes read as a number (LZMA is 0x030101).
    pub id: u64,
    /// The coder properties as stored (LZMA: 5 bytes, LZMA2: 1 byte of dictionary size, 7zAES: cycles, salt, IV).
    pub properties: Vec<u8>,
    pub in_streams: u32,
    pub out_streams: u32,
}

/// The method of a 7z coder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CoderKind {
    /// 0x00.
    Copy,
    /// 0x030101.
    Lzma,
    /// 0x21.
    Lzma2,
    /// 0x030401.
    Ppmd,
    /// 0x040202.
    Bzip2,
    /// 0x040108.
    Deflate,
    /// 0x040109.
    Deflate64,
    /// 0x06F10701.
    Aes,
    /// x86 BCJ, 0x03030103.
    Bcj,
    /// 0x0303011B.
    Bcj2,
    /// 0x03.
    Delta,
    /// 0x03030205.
    PowerPc,
    /// 0x03030401.
    Ia64,
    /// 0x03030501.
    Arm,
    /// 0x03030701.
    ArmThumb,
    /// 0x0A.
    Arm64,
    /// 0x03030805.
    Sparc,
    /// 0x0B.
    RiscV,
    /// Any other method id, kept raw.
    Other(u64),
}

impl CoderKind {
    /// The kind of method id `id`.
    pub fn from_id(id: u64) -> Self {
        match id {
            0x00 => Self::Copy,
            0x03_0101 => Self::Lzma,
            0x21 => Self::Lzma2,
            0x03_0401 => Self::Ppmd,
            0x04_0202 => Self::Bzip2,
            0x04_0108 => Self::Deflate,
            0x04_0109 => Self::Deflate64,
            0x06F1_0701 => Self::Aes,
            0x0303_0103 => Self::Bcj,
            0x0303_011B => Self::Bcj2,
            0x03 => Self::Delta,
            0x0303_0205 => Self::PowerPc,
            0x0303_0401 => Self::Ia64,
            0x0303_0501 => Self::Arm,
            0x0303_0701 => Self::ArmThumb,
            0x0A => Self::Arm64,
            0x0303_0805 => Self::Sparc,
            0x0B => Self::RiscV,
            other => Self::Other(other),
        }
    }
}

/// Where a 7z member's data sits: which folder, and where in the folder's output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FolderSlot {
    /// Index into [`MemberMap::folders`].
    pub index: u32,
    /// Offset of the member's first byte in the folder's output (its substream position).
    pub offset: u64,
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
    /// 7z: coded by the folder's coder chain (anything but Copy, or 7zAES over Copy); see
    /// [`MapMember::folder`] and [`MapFolder::coders`].
    Coders,
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
    /// 7zAES: AES-256-CBC, key from SHA-256 over `2^num_cycles_power` rounds of the salt, the UTF-16LE password
    /// and an 8-byte round counter (0x3F: no hashing, the key is the salt and password). `salt` is 0 to 16 bytes;
    /// `iv` is the stored IV zero-padded to 16 bytes. No password check value is recorded.
    SevenZipAes { num_cycles_power: u8, salt: Vec<u8>, iv: [u8; 16] },
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
    /// The wire extent of the header (or ZIP local header) that announced them. 7z: empty, at 0 (the archive's one
    /// header describes every member).
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
#[non_exhaustive]
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
    /// The header at `offset` is damaged or unsupported, after the main header was read. The walk stops there;
    /// members whose headers came before it are listed, and the volume facts are the main header's.
    Damaged { offset: u64, reason: HeaderDamage },
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
    /// RAR 4.x: the header's DOS date and time exactly as stored (time in the low 16 bits, date in the high), even
    /// when it is not a valid date and `mtime` is None. None for other formats.
    pub dos_time: Option<u32>,
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
    /// Zero-based position among the archive's members. 7z: among the members listed, which leaves out anti items,
    /// so it is not the raw file index of the 7z header.
    pub ordinal: u64,
    /// The name exactly as stored. For ZIP, the UTF-8 bytes of the decoded name. For RAR5,
    /// [`crate::rar5::unrar_name`] gives the name UnRAR reads from them.
    pub raw_name: Vec<u8>,
    /// The name decoded by the format's rules, when it decodes.
    pub name: Option<String>,
    pub is_dir: bool,
    pub unpacked_size: Option<u64>,
    /// Packed bytes: for RAR over the pieces seen; for ZIP the size the directory declares, even when only some
    /// pieces are present (the pieces show what is).
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
    /// RAR 4.x: the header's DOS date and time exactly as stored (time in the low 16 bits, date in the high), even
    /// when it is not a valid date and `mtime` is None. None for other formats.
    pub dos_time: Option<u32>,
    /// Raw attributes as the host recorded them.
    pub attributes: u64,
    /// Unix permission and type bits, when the host was Unix.
    pub unix_mode: Option<u32>,
    /// Whether the final piece was seen.
    pub complete: bool,
    /// 7z members with [`OutputMapping::None`] (coded folders, and later members of a 7zAES folder) have no
    /// pieces: their bytes are the folder's, listed once in `map.folders[slot.index].packed` (see
    /// [`Self::folder`]), and their `packed_size` is 0.
    pub pieces: Vec<MapPiece>,
    /// 7z: the folder holding the member's data and its offset there. None for members without data (directories
    /// and empty files) and for other formats.
    pub folder: Option<FolderSlot>,
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
    /// A split ZIP's end of central directory record, or a volume holding part of its central directory, is not
    /// available: the volume is missing or cut short. `volume` is the zero-based index looked at: in memory, the last
    /// slice; through a source whose last volume is missing, the first of the indexes in a row without a volume.
    MissingDirectory { volume: u32 },
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotArchive => write!(f, "not a RAR, ZIP or 7z archive"),
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
            Self::MissingDirectory { volume } => {
                write!(f, "split ZIP directory or end record not available (volume {volume})")
            }
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

/// Options for building a map, or for reading a member with [`MemberReader`].
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
    /// [`MemberReader`] only: the most output a checked part may carry for its plaintext to be held back in memory
    /// until its check passes. The hold is charged to `limits.temp_bytes` while it lasts. A larger part, or one whose
    /// hold the budget or the allocator refuses, is streamed unchecked and reported after the fact (see
    /// [`ExtractFromError::PartBad`]). Default 256 MiB.
    pub part_hold_bytes: u64,
}

impl MapOptions {
    pub fn new(first_name: impl Into<OsString>) -> Self {
        Self {
            first_name: first_name.into(),
            password: None,
            limits: ProgressiveLimits::default(),
            control: SessionControl::default(),
            part_hold_bytes: 256 << 20,
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
    /// Keeps the current volume under `slot`, so that [`Self::select`] can make it current again after other volumes
    /// were opened, without asking the source again. A later call for the same volume moves it to the new slot.
    fn keep(&mut self, _slot: u32) {}
    /// Makes the volume kept under `slot` current. False when nothing is kept there.
    fn select(&mut self, _slot: u32) -> bool {
        false
    }
    /// Closes the volume kept under `slot`. Kept volumes otherwise stay open until the walk ends; walkers bound how
    /// many they keep by [`ProgressiveLimits::volume_handles`].
    fn release(&mut self, _slot: u32) {}
    /// How many volumes the input holds, when it knows (volumes in memory).
    fn count(&self) -> Option<u32> {
        None
    }
}

struct MemoryInput<'a> {
    volumes: &'a [&'a [u8]],
    current: Option<&'a [u8]>,
    current_slot: Option<u32>,
    kept: Vec<Option<&'a [u8]>>,
}

impl<'a> MemoryInput<'a> {
    fn new(volumes: &'a [&'a [u8]]) -> Self {
        Self { volumes, current: None, current_slot: None, kept: Vec::new() }
    }
}

impl MapInput for MemoryInput<'_> {
    fn count(&self) -> Option<u32> {
        u32::try_from(self.volumes.len()).ok()
    }
    fn release(&mut self, slot: u32) {
        if let Some(kept) = self.kept.get_mut(slot as usize) {
            *kept = None;
        }
        if self.current_slot == Some(slot) {
            self.current = None;
            self.current_slot = None;
        }
    }
    fn keep(&mut self, slot: u32) {
        if let Some(old) = self.current_slot.replace(slot) {
            self.kept[old as usize] = None;
        }
        let slot = slot as usize;
        if self.kept.len() <= slot {
            self.kept.resize(slot + 1, None);
        }
        self.kept[slot] = self.current;
    }
    fn select(&mut self, slot: u32) -> bool {
        match self.kept.get(slot as usize).copied().flatten() {
            Some(volume) => {
                self.current = Some(volume);
                self.current_slot = Some(slot);
                true
            }
            None => false,
        }
    }
    fn open(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> Result<Opened, ProgressiveFailure> {
        self.current_slot = None;
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
    /// The slot the current volume is kept under, if any.
    current_slot: Option<u32>,
    kept: Vec<Option<Box<dyn RangeSource>>>,
}

impl SourceInput {
    pub(crate) fn new(source: Box<dyn VolumeSource>) -> Self {
        Self { source, current: None, current_slot: None, kept: Vec::new() }
    }

    /// Puts the current volume back in its slot, or drops it when it is not kept.
    fn put_back(&mut self) {
        let current = self.current.take();
        if let Some(slot) = self.current_slot.take() {
            self.kept[slot as usize] = current;
        }
    }
}

impl MapInput for SourceInput {
    fn release(&mut self, slot: u32) {
        if self.current_slot == Some(slot) {
            self.current = None;
            self.current_slot = None;
        } else if let Some(kept) = self.kept.get_mut(slot as usize) {
            *kept = None;
        }
    }
    fn keep(&mut self, slot: u32) {
        self.current_slot = Some(slot);
        let slot = slot as usize;
        if self.kept.len() <= slot {
            self.kept.resize_with(slot + 1, || None);
        }
    }
    fn select(&mut self, slot: u32) -> bool {
        if self.current_slot == Some(slot) {
            return self.current.is_some();
        }
        if self.kept.get(slot as usize).is_none_or(Option::is_none) {
            return false;
        }
        self.put_back();
        self.current = self.kept[slot as usize].take();
        self.current_slot = Some(slot);
        true
    }
    fn open(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> Result<Opened, ProgressiveFailure> {
        self.put_back();
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

/// The name of the volume after `last`: [`crate::volume::next_volume_os`], or for a name ending in digits
/// (`name.7z.001`) the same number of digits counting up, or else `last` with `.next` appended. Providers usually
/// key on [`VolumeRequest::index`] instead.
pub(crate) fn next_volume_name(last: &OsStr) -> OsString {
    if let Some(next) = crate::volume::next_volume_os(last) {
        return next;
    }
    if let Some(text) = last.to_str() {
        let digits = text.bytes().rev().take_while(u8::is_ascii_digit).count();
        let start = text.len() - digits;
        if (1..=18).contains(&digits) && text[..start].ends_with('.') {
            let n: u64 = text[start..].parse().unwrap_or(0);
            let next = format!("{}{:0width$}", &text[..start], n + 1, width = digits);
            if next.len() == text.len() {
                return next.into();
            }
        }
    }
    let mut name = last.to_os_string();
    name.push(".next");
    name
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
    ZipSplit(Box<zip_split::ZipSplitWalker>),
    SevenZip(Box<sevenzip::SevenZipWalker>),
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
                            if self.magic == sevenzip::MAGIC[..4] {
                                if self.single {
                                    return Poll::Ready(Err(MapError::NotArchive));
                                }
                                self.engine = Engine::SevenZip(Box::new(sevenzip::SevenZipWalker::new(
                                    &self.options,
                                    self.usage.clone(),
                                )));
                                continue;
                            }
                            let split_start = self.magic == zip_split::SPLIT_MARKER
                                || (self.magic == b"PK\x03\x04" && zip_split::is_split_name(&self.options.first_name));
                            if split_start && !self.single {
                                self.engine = Engine::ZipSplit(Box::new(zip_split::ZipSplitWalker::new(
                                    self.usage.clone(),
                                    &self.options,
                                )));
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
                        MapFormat::SevenZip => {
                            Engine::SevenZip(Box::new(sevenzip::SevenZipWalker::new(&self.options, self.usage.clone())))
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
                Engine::ZipSplit(walker) => return walker.poll(input, cx, &self.options).map_ok(Walked::Map),
                Engine::SevenZip(walker) => return walker.poll(input, cx, &self.options).map_ok(Walked::Map),
                Engine::Done => return Poll::Ready(Err(MapError::AlreadyFinished)),
            }
        }
    }
}

impl MemberMap {
    /// Maps an archive whose volumes are in memory, in order, starting with the first. A volume may be cut short
    /// and later volumes may be absent: the map then has `complete: false` and lists what was seen.
    ///
    /// A split ZIP set is passed as `.z01`, `.z02`, ..., `.zip`: the last slice must be the `.zip`, whose end record
    /// gives the volume count, and a missing middle volume is an empty slice. See `docs/member-map.md`.
    pub fn from_memory(
        volumes: &[&[u8]],
        first_name: impl AsRef<OsStr>,
        password: Option<&str>,
    ) -> Result<MemberMap, MapError> {
        Self::from_memory_with(volumes, MapOptions::new(first_name.as_ref()).password(password))
    }

    /// [`Self::from_memory`] with explicit options.
    pub fn from_memory_with(volumes: &[&[u8]], options: MapOptions) -> Result<MemberMap, MapError> {
        let mut input = MemoryInput::new(volumes);
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
        let mut input = MemoryInput::new(&volumes);
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
///
/// A split ZIP set's volumes are asked for in order, volume `i` first as `name.z{i+1}` and, when that is missing, as
/// `name.zip` (names derived from [`MapOptions::first_name`], `name.z01`); see `docs/member-map.md`.
pub struct MapBuilder {
    input: SourceInput,
    core: Core,
}

impl MapBuilder {
    pub fn new(source: Box<dyn VolumeSource>, options: MapOptions) -> Self {
        Self { input: SourceInput::new(source), core: Core::new(options, false) }
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

#[cfg(test)]
mod damage_tests {
    use super::*;
    use crate::error::{RarFailure, RarInternal, RarResource};

    fn malformed(kind: FailureKind) -> MapError {
        MapError::Malformed { volume: 0, failure: Box::new(ProgressiveFailure::new(kind)) }
    }

    #[test]
    fn only_header_failures_are_damage() {
        let limit = RarFailure::Limit { resource: RarResource::CatalogueAllocation, requested: None, allowed: None };
        for error in [
            malformed(FailureKind::Rar(Box::new(limit))),
            malformed(FailureKind::Rar(Box::new(RarFailure::Internal(RarInternal::Invariant("x"))))),
            malformed(FailureKind::IncompleteOutput),
            MapError::Unsupported {
                volume: 0,
                failure: Box::new(ProgressiveFailure::new(FailureKind::Rar(Box::new(RarFailure::Unsupported(
                    crate::error::RarUnsupported::NameEncoding,
                ))))),
            },
            MapError::Limit { resource: Resource::HeaderBytes, limit: 1, attempted: 2 },
            MapError::WrongPassword,
        ] {
            assert_eq!(HeaderDamage::of(&error), None, "{error:?}");
        }
        assert_eq!(HeaderDamage::of(&malformed(FailureKind::Malformed("why"))), Some(HeaderDamage::Malformed("why")));
    }
}
