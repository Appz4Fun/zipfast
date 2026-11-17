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

//! RAR 5.0 archive blocks, read from the published archive layout: the signature, the main header, file and service
//! headers with their extra records, and the end of archive header.

pub(crate) mod framing;
pub(crate) mod map;
pub(crate) mod member;
pub(crate) mod physical;
pub mod reader;
pub mod session;
pub(crate) mod source;
#[doc(hidden)]
pub mod testenc;
pub mod unpack;
mod unrar_name;

pub use unrar_name::{unrar_name, unrar_name_to_string};

use crate::error::{Error, Result};

pub const SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
/// The older format's signature, recognised only to say it isn't this one.
pub const SIGNATURE_V4: &[u8; 7] = b"Rar!\x1a\x07\x00";
/// How far into a file a self-extracting module may push the signature.
pub const MAX_SFX: u64 = 1 << 20;
/// A header size field is at most 3 bytes long, so a header is under 2 MiB.
pub const MAX_HEADER: u64 = 1 << 21;

pub const HEAD_MAIN: u64 = 1;
pub const HEAD_FILE: u64 = 2;
pub const HEAD_SERVICE: u64 = 3;
pub const HEAD_CRYPT: u64 = 4;
pub const HEAD_END: u64 = 5;

pub const HFL_EXTRA: u64 = 0x0001;
pub const HFL_DATA: u64 = 0x0002;
pub const HFL_SPLIT_BEFORE: u64 = 0x0008;
pub const HFL_SPLIT_AFTER: u64 = 0x0010;

pub const MHFL_VOLUME: u64 = 0x0001;
pub const MHFL_VOLNUMBER: u64 = 0x0002;
pub const MHFL_SOLID: u64 = 0x0004;
pub const MHFL_PROTECT: u64 = 0x0008;
pub const MHFL_LOCK: u64 = 0x0010;
/// Main header extra record: the original archive name and time.
pub const MHEXTRA_LOCATOR: u64 = 0x01;
pub const MHEXTRA_METADATA: u64 = 0x02;

pub const FHFL_DIRECTORY: u64 = 0x0001;
pub const FHFL_UTIME: u64 = 0x0002;
pub const FHFL_CRC32: u64 = 0x0004;
pub const FHFL_UNPUNKNOWN: u64 = 0x0008;

pub const EOAFL_MORE_VOLUMES: u64 = 0x0001;

pub const FHEXTRA_CRYPT: u64 = 0x01;
pub const FHEXTRA_HASH: u64 = 0x02;
pub const FHEXTRA_HTIME: u64 = 0x03;
pub const FHEXTRA_VERSION: u64 = 0x04;
pub const FHEXTRA_REDIR: u64 = 0x05;
pub const FHEXTRA_SUBDATA: u64 = 0x07;

/// A cursor over one header's bytes. Every read is checked; running off the end is corruption, since the header's
/// own size said the bytes were there.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or(Error::Corrupt("header field"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    /// Seven bits per byte, low bits first, high bit set while more follow. Ten bytes at most.
    pub fn vint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            let bits = u64::from(b & 0x7f);
            if i == 9 && b > 1 {
                return Err(Error::Corrupt("variable length integer overflows 64 bits"));
            }
            value |= bits << (7 * i);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::Corrupt("variable length integer too long"))
    }

    pub fn vsize(&mut self) -> Result<usize> {
        usize::try_from(self.vint()?).map_err(|_| Error::Corrupt("size too large"))
    }
}

/// The fields shared by every block, and where the block's data area sits in its volume.
#[derive(Clone, Debug)]
pub struct BlockHead {
    pub kind: u64,
    pub flags: u64,
    pub data_size: u64,
    /// absolute offset of the data area in the volume
    pub data_at: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MainHeader {
    pub flags: u64,
    pub volume_number: u64,
    /// The RAR4 main header's own flags (`MHD_*`), before normalization into `flags`. None for RAR 5.0.
    pub rar4_flags: Option<u16>,
    /// RAR 5.0 only: the archive name stored by `-ams` (the metadata record of the main header extra area).
    pub original_name: Option<Vec<u8>>,
    /// RAR 5.0 only: the archive creation time stored by `-ams`.
    pub original_time: Option<RarTime>,
    /// RAR 2.x only (`MHD_COMMENT`): the comment block embedded in the main header, from its `COMM_HEAD` on, as
    /// stored. Kept by catalogues only.
    pub embedded_comment: Option<Vec<u8>>,
    /// RAR 5.0 only: the locator record of the main header extra area, when present.
    pub locator: Option<RarLocator>,
    /// RAR 5.0 only: the main header's extra records in their stored order.
    pub extra_records: Vec<RarExtraRecord>,
}

/// One record of a RAR 5.0 header's extra area, in stored order: its type and its bytes after the type.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct RarExtraRecord {
    pub kind: u64,
    pub data: Vec<u8>,
}

/// The RAR 5.0 main header locator record (type 0x01): where the quick open service header and the recovery record
/// start, as offsets from the start of the main header. 7-Zip lists them in its `-slt` archive properties.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct RarLocator {
    /// Raw flags: 0x1 the quick open offset is present, 0x2 the recovery record offset is.
    pub flags: u64,
    pub quick_open: Option<u64>,
    pub recovery: Option<u64>,
}

/// The end of archive header as stored. RAR 5.0: its flags (0x1 more volumes follow). RAR 4.x: the header flags
/// (`EARC_NEXT_VOLUME` 0x1, `EARC_DATACRC` 0x2, `EARC_REVSPACE` 0x4, `EARC_VOLNUMBER` 0x8) and the fields they add.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct RarEndRecord {
    pub flags: u64,
    /// RAR 4.x `EARC_DATACRC`: the CRC32 of the volume's data.
    pub data_crc: Option<u32>,
    /// RAR 4.x `EARC_VOLNUMBER`: the volume number.
    pub volume_number: Option<u64>,
    /// Where the header starts in the volume.
    pub offset: u64,
}

/// The records of a RAR 5.0 extra area in stored order; stops at the first that does not parse.
pub(crate) fn extra_records(extra: &[u8]) -> Vec<RarExtraRecord> {
    let mut out = Vec::new();
    let mut c = Cursor::new(extra);
    while c.remaining() > 0 && out.len() < 64 {
        let Ok(size) = c.vsize() else { break };
        let Ok(record) = c.bytes(size) else { break };
        let mut r = Cursor::new(record);
        let Ok(kind) = r.vint() else { break };
        out.push(RarExtraRecord { kind, data: record[r.pos()..].to_vec() });
    }
    out
}

/// The locator record of a RAR 5.0 main header extra area.
pub(crate) fn main_locator(records: &[RarExtraRecord]) -> Option<RarLocator> {
    let record = records.iter().find(|r| r.kind == MHEXTRA_LOCATOR)?;
    let mut r = Cursor::new(&record.data);
    let flags = r.vint().ok()?;
    let quick_open = if flags & 1 != 0 { Some(r.vint().ok()?) } else { None };
    let recovery = if flags & 2 != 0 { Some(r.vint().ok()?) } else { None };
    Some(RarLocator { flags, quick_open, recovery })
}

/// A timestamp as a header stores it. `resolution_nanos` is the step the stored form can express: 2 s for an MS-DOS
/// time, 1 s for a Unix time, 100 ns for a FILETIME, 1 ns for a Unix time with nanoseconds, and for a RAR 4.x
/// extended time 1 s or 100 ns scaled by the fraction bytes it omits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RarTime {
    /// Seconds since 1970. RAR 4.x times are local wall-clock times projected as UTC.
    pub seconds: i64,
    pub nanos: u32,
    pub resolution_nanos: u32,
}

/// RAR4 main header flag: volumes are named `NAME.partN.rar` rather than `NAME.rar`, `NAME.r00`, ...
pub const MHD_NEWNUMBERING: u16 = 0x0010;

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHFL_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHFL_SOLID != 0
    }
}

/// How a file system object is to be recreated other than as a regular file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Redirection {
    UnixSymlink(String),
    WindowsSymlink(String),
    Junction(String),
    HardLink(String),
    FileCopy(String),
    Unknown(u64),
}

impl Redirection {
    /// The redirection record's type: 1 Unix symbolic link, 2 Windows symbolic link, 3 junction, 4 hard link,
    /// 5 file copy, or the unknown type as stored.
    pub fn kind(&self) -> u64 {
        match self {
            Self::UnixSymlink(_) => 1,
            Self::WindowsSymlink(_) => 2,
            Self::Junction(_) => 3,
            Self::HardLink(_) => 4,
            Self::FileCopy(_) => 5,
            Self::Unknown(kind) => *kind,
        }
    }
}

/// Archive format governing the member's wire fields and payload decoder.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RarFormat {
    Rar4,
    #[default]
    Rar5,
}

/// RAR4 wire metadata retained alongside normalized session fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rar4Metadata {
    pub flags: u16,
    pub host: u8,
    pub method: u8,
    pub unpack_version: u8,
    /// Local DOS wall-clock bits. The normalized timestamp projects these as UTC.
    pub dos_time: u32,
    /// The encryption salt, when the header carries one.
    pub salt: Option<[u8; 8]>,
}

impl Rar4Metadata {
    pub(crate) fn unsupported(self, attributes: u64) -> Option<crate::error::RarUnsupported> {
        // Split and solid members decode on: the parts of a split one feed one decoder, and a solid one goes on from
        // the history the member before it left.
        let feature = if self.flags & 4 != 0 && self.unpack_version != 29 {
            "encrypted payload"
        } else if !(0x30..=0x35).contains(&self.method) {
            "compression method"
        } else if !matches!(self.unpack_version, 15 | 20 | 26 | 29) {
            "unpack version"
        // A host above Unix (MacOS 4, BeOS 5, or later) is a plain member with no mode (its host is normalized to 2,
        // neither Unix nor Windows). An old file revision (LHD_VERSION) is written under its stored name, `;n` suffix
        // included, as UnRAR does with `-ver` (taken from reading UnRAR's extract.cpp, not checked against a run of
        // UnRAR; without `-ver` UnRAR skips old revisions).
        } else if self.host == 3 && !matches!(attributes & 0o170000, 0 | 0o100000 | 0o040000 | 0o120000) {
            "special file"
        } else if self.host == 3
            && attributes & 0o170000 != 0
            && (self.flags & 0xe0 == 0xe0) != (attributes & 0o170000 == 0o040000)
        {
            "file type flags"
        } else {
            return None;
        };
        Some(crate::error::RarUnsupported::Rar4Feature(feature))
    }
}

/// The leading fields of a RAR 5.0 file encryption record (extra record 0x01), as stored. 7-Zip lists them in the
/// method string as `AES:<kdf_count>:<flags>`, flags included even when they are 0 (`AES:15:3`, `AES:15:0`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct Rar5CryptRecord {
    /// Encryption version: 0 is AES-256.
    pub version: u64,
    /// Raw flags: 0x1 a password check value is stored, 0x2 checksums are keyed with the password.
    pub flags: u64,
    /// Base-2 logarithm of the PBKDF2 iteration count.
    pub kdf_count: u8,
}

/// A file or service header.
#[derive(Clone, Debug, Default)]
pub struct FileHeader {
    pub format: RarFormat,
    pub rar4: Option<Rar4Metadata>,
    pub service: bool,
    pub block_flags: u64,
    pub file_flags: u64,
    pub packed_size: u64,
    pub data_at: u64,
    pub unpacked_size: u64,
    pub attributes: u64,
    /// seconds since 1970, from the header or the high precision time record
    pub mtime: Option<i64>,
    pub mtime_nanos: u32,
    /// The step `mtime` can express, in nanoseconds; see [`RarTime`]. Zero without an mtime.
    pub mtime_resolution: u32,
    pub ctime: Option<RarTime>,
    pub atime: Option<RarTime>,
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
    /// 0 for RAR 5.0's algorithm, 1 for RAR 7.0's
    pub algorithm: u8,
    pub solid: bool,
    /// 0 is stored, 1 to 5 are compression levels
    pub method: u8,
    /// bytes of history the decoder must keep
    pub dictionary: u64,
    pub host_os: u64,
    pub name: String,
    pub encrypted: bool,
    pub crypt: Option<crate::crypto::Rar5CryptParams>,
    /// RAR 5.0: the version, flags and KDF count of the file encryption record as stored, even when `crypt` is
    /// None because the record is unsupported (a KDF count over 24, a newer version). None without the record.
    pub crypt_record: Option<Rar5CryptRecord>,
    /// RAR 5.0: the redirection record's flags as stored (0x1: the target is a directory, which 7-Zip lists as
    /// `:D`). Zero without the record.
    pub redirection_flags: u64,
    /// RAR 5.0, catalogues only: the extra records in their stored order (7-Zip lists their types in that order).
    pub extra_records: Vec<RarExtraRecord>,
    pub redirection: Option<Redirection>,
    /// set on an older revision of a file kept alongside the current one
    pub version: Option<u64>,
    /// A service header's SubData: the stream name of an `STM` header, the `Protect+` tag of a RAR 4.x `RR`, and
    /// so on. Empty for file headers.
    pub sub_data: Vec<u8>,
}

impl FileHeader {
    pub(crate) fn rar4_unsupported(&self) -> Option<crate::error::RarUnsupported> {
        let raw = self.rar4?;
        raw.unsupported(self.attributes).or_else(|| self.rar4_common_unsupported()).or_else(|| {
            if self.encrypted && self.is_dir() {
                Some(crate::error::RarUnsupported::Rar4Feature("encrypted directory"))
            } else if self.encrypted && raw.salt.is_none() {
                Some(crate::error::RarUnsupported::Rar4Feature("legacy encryption scheme or salt"))
            } else {
                None
            }
        })
    }

    fn rar4_common_unsupported(&self) -> Option<crate::error::RarUnsupported> {
        if self.is_dir() && (self.packed_size != 0 || self.unpacked_size != 0 || self.crc32.is_some_and(|crc| crc != 0))
        {
            Some(crate::error::RarUnsupported::Rar4Feature("directory payload"))
        } else {
            None
        }
    }

    pub(crate) fn rar4_progressive_unsupported(
        &self,
        legacy: Option<LegacyCrypt>,
    ) -> Option<crate::error::RarUnsupported> {
        let raw = self.rar4?;
        // Admission precedes every disposition, including directory creation and skip.
        if self.encrypted && raw.unpack_version == 29 {
            if self.is_dir() {
                return Some(crate::error::RarUnsupported::Rar4Feature("encrypted directory"));
            }
            if let Err(reason) = LegacyCrypt::stored_salt(legacy) {
                return Some(reason);
            }
        }
        if raw.method != 0x30 {
            // Independent modern LZ only. Reject unsupported geometry before every disposition.
            return raw.unsupported(self.attributes).or_else(|| self.rar4_common_unsupported()).or_else(|| {
                if self.is_dir() {
                    Some(crate::error::RarUnsupported::Rar4Feature("compressed directory"))
                } else if self.unpacked_size == u64::MAX || self.unpacked_size == u64::from(u32::MAX) {
                    Some(crate::error::RarUnsupported::Rar4Feature("unknown unpacked size"))
                } else {
                    None
                }
            });
        }
        if self.encrypted {
            if self.is_dir() {
                return Some(crate::error::RarUnsupported::Rar4Feature("encrypted directory"));
            }
            if let Err(reason) = LegacyCrypt::stored_salt(legacy) {
                return Some(reason);
            }
        }
        let independent =
            Rar4Metadata { flags: raw.flags & !(3 | if raw.unpack_version == 29 { 4 } else { 0 }), ..raw };
        independent.unsupported(self.attributes).or_else(|| self.rar4_common_unsupported()).or_else(|| {
            if self.unpacked_size == u64::MAX || self.unpacked_size == u64::from(u32::MAX) {
                Some(crate::error::RarUnsupported::Rar4Feature("unknown unpacked size"))
            } else {
                None
            }
        })
    }
    pub fn is_dir(&self) -> bool {
        self.file_flags & FHFL_DIRECTORY != 0
    }

    pub fn split_before(&self) -> bool {
        self.block_flags & HFL_SPLIT_BEFORE != 0
    }

    pub fn split_after(&self) -> bool {
        self.block_flags & HFL_SPLIT_AFTER != 0
    }

    pub fn size_unknown(&self) -> bool {
        self.file_flags & FHFL_UNPUNKNOWN != 0
    }

    pub fn is_unix(&self) -> bool {
        self.host_os == 1
    }

    /// The name this member is written under; see [`crate::path::rar_output_name`].
    pub(crate) fn output_name(&self) -> Option<std::borrow::Cow<'_, str>> {
        crate::path::rar_output_name(&self.name, self.format == RarFormat::Rar4)
    }

    /// A RAR 4.x Unix symbolic link: a Unix-host member whose mode is `S_IFLNK`. Its data is the link's target.
    pub fn is_rar4_symlink(&self) -> bool {
        self.rar4.is_some_and(|raw| raw.host == 3) && self.attributes & 0o170000 == 0o120000
    }

    /// Whether `attributes` holds Windows attribute bits: RAR 5.0 host
    /// Windows, or RAR 4.x host MS-DOS, OS/2 or Win32 (all normalized to 0).
    pub fn is_windows(&self) -> bool {
        self.host_os == 0
    }

    /// The raw Windows attribute bits, when the archiver's host stores them.
    pub fn windows_attributes(&self) -> Option<u32> {
        self.is_windows().then_some(self.attributes as u32)
    }

    /// Which clock `mtime` was read from. RAR 5.0 stores a Unix time or a
    /// FILETIME, both UTC. RAR 4.x stores a local MS-DOS date and time; its
    /// extended-time record only adds precision to those fields (UnRAR reads
    /// the DOS time as local, adds the optional second and the fraction, and
    /// sets the result as local time), so it stays a local wall-clock time.
    pub fn mtime_origin(&self) -> Option<crate::extract::MtimeOrigin> {
        self.mtime.map(|_| match self.format {
            RarFormat::Rar4 => crate::extract::MtimeOrigin::LocalWallClock,
            RarFormat::Rar5 => crate::extract::MtimeOrigin::Utc,
        })
    }
}

/// The body of a file or service header, from the file flags on. `extra` is the extra area, if any.
pub fn parse_file(head: &BlockHead, body: &[u8], extra: &[u8]) -> Result<FileHeader> {
    parse_file_detailed(head, body, extra).map(|(file, _)| file)
}

pub(crate) type MemberCrypt =
    Option<std::result::Result<crate::crypto::Rar5CryptParams, crate::crypto::Rar5CryptError>>;

pub(crate) fn parse_file_detailed(head: &BlockHead, body: &[u8], extra: &[u8]) -> Result<(FileHeader, MemberCrypt)> {
    match parse_file_impl(head, body, extra, false, None) {
        Ok((file, crypt, _)) => Ok((file, crypt)),
        Err(FileParseError::Format(error)) => Err(error),
        Err(FileParseError::Allocation) => unreachable!("legacy names use the legacy allocation path"),
        Err(FileParseError::Progressive(_)) => unreachable!("legacy names have no progressive admission"),
    }
}

enum FileParseError {
    Progressive(crate::progressive::ProgressiveFailure),
    Format(Error),
    Allocation,
}

impl From<Error> for FileParseError {
    fn from(error: Error) -> Self {
        Self::Format(error)
    }
}

pub(crate) const RAW_NAME_OWNER_BYTES: usize = std::mem::size_of::<Vec<u8>>() + 2 * std::mem::size_of::<usize>();

// Raw legacy transport never contains derived keys or passwords.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyCrypt {
    pub(crate) version: u8,
    pub(crate) salt: Option<[u8; 8]>,
}
impl LegacyCrypt {
    pub(crate) fn stored_salt(crypt: Option<Self>) -> std::result::Result<[u8; 8], crate::error::RarUnsupported> {
        crypt
            .filter(|c| c.version == 29)
            .and_then(|c| c.salt)
            .ok_or(crate::error::RarUnsupported::Rar4Feature("legacy encryption scheme or salt"))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyWire {
    pub(crate) salt: Option<[u8; 8]>,
    pub(crate) flags: u16,
    pub(crate) version: u8,
    pub(crate) method: u8,
    pub(crate) dictionary: u64,
    pub(crate) packed_size: u64,
    pub(crate) unpacked_size: u64,
    pub(crate) crypt: Option<LegacyCrypt>,
}
pub(super) struct FileWire {
    pub(super) legacy: Option<LegacyWire>,
    pub(super) name: std::sync::Arc<Vec<u8>>,
    pub(super) compression: u64,
    pub(super) extent: std::ops::Range<u64>,
}

fn parse_file_impl(
    head: &BlockHead,
    body: &[u8],
    extra: &[u8],
    catalogue: bool,
    usage: Option<&crate::progressive::Usage>,
) -> std::result::Result<(FileHeader, MemberCrypt, Option<FileWire>), FileParseError> {
    let mut c = Cursor::new(body);
    let mut f = FileHeader {
        service: head.kind == HEAD_SERVICE,
        block_flags: head.flags,
        packed_size: head.data_size,
        data_at: head.data_at,
        ..FileHeader::default()
    };
    f.file_flags = c.vint()?;
    f.unpacked_size = c.vint()?;
    f.attributes = c.vint()?;
    if f.file_flags & FHFL_UTIME != 0 {
        f.mtime = Some(i64::from(c.u32()?));
        f.mtime_resolution = 1_000_000_000;
    }
    if f.file_flags & FHFL_CRC32 != 0 {
        f.crc32 = Some(c.u32()?);
    }
    let info = c.vint()?;
    f.algorithm = (info & 0x3f) as u8;
    f.solid = info & 0x40 != 0;
    f.method = ((info >> 7) & 7) as u8;
    let power = (info >> 10) & 0x1f;
    let mut dictionary = (128u64 * 1024).checked_shl(power as u32).unwrap_or(u64::MAX);
    if f.algorithm == 1 {
        let fraction = (info >> 15) & 0x1f;
        dictionary = dictionary.saturating_add(dictionary / 32 * fraction);
        if info & 0x10_0000 != 0 {
            // dictionary sized for the newer algorithm, data packed with the older one
            f.algorithm = 0;
        }
    }
    f.dictionary = dictionary;
    f.host_os = c.vint()?;
    let name_len = c.vsize()?;
    let name = c.bytes(name_len)?;
    f.name = display_name_admitted(name, catalogue, usage)?;
    let crypt = parse_file_extra(&mut f, extra, catalogue, usage)?;
    let wire = if catalogue && !f.service {
        if let Some(usage) = usage {
            usage
                .charge(crate::progressive::Resource::NameBytes, name.len() as u64)
                .map_err(FileParseError::Progressive)?;
            usage
                .charge(crate::progressive::Resource::MetadataBytes, name.len() as u64)
                .map_err(FileParseError::Progressive)?;
        }
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(name.len()).map_err(|_| FileParseError::Allocation)?;
        if let Some(usage) = usage {
            usage
                .charge(crate::progressive::Resource::MetadataBytes, (encoded.capacity() - name.len()) as u64)
                .map_err(FileParseError::Progressive)?;
        }
        encoded.extend_from_slice(name);
        if let Some(usage) = usage {
            usage
                .charge(crate::progressive::Resource::MetadataBytes, RAW_NAME_OWNER_BYTES as u64)
                .map_err(FileParseError::Progressive)?;
        }
        Some(FileWire {
            legacy: None,
            name: std::sync::Arc::new(encoded),
            compression: info,
            extent: head.data_at..head.data_at,
        })
    } else {
        None
    };
    Ok((f, crypt, wire))
}

fn display_name_admitted(
    bytes: &[u8],
    catalogue: bool,
    usage: Option<&crate::progressive::Usage>,
) -> std::result::Result<String, FileParseError> {
    if !catalogue {
        return Ok(String::from_utf8_lossy(bytes).into_owned());
    }
    let len = bytes
        .utf8_chunks()
        .try_fold(0usize, |len, chunk| {
            len.checked_add(chunk.valid().len())?.checked_add(if chunk.invalid().is_empty() {
                0
            } else {
                '\u{fffd}'.len_utf8()
            })
        })
        .ok_or(FileParseError::Allocation)?;
    if let Some(usage) = usage {
        usage.charge(crate::progressive::Resource::NameBytes, len as u64).map_err(FileParseError::Progressive)?;
        usage.charge(crate::progressive::Resource::MetadataBytes, len as u64).map_err(FileParseError::Progressive)?;
    }
    let mut text = String::new();
    text.try_reserve_exact(len).map_err(|_| FileParseError::Allocation)?;
    if let Some(usage) = usage {
        usage
            .charge(crate::progressive::Resource::MetadataBytes, (text.capacity() - len) as u64)
            .map_err(FileParseError::Progressive)?;
    }
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            text.push('\u{fffd}');
        }
    }
    Ok(text)
}

fn parse_file_extra(
    f: &mut FileHeader,
    extra: &[u8],
    catalogue: bool,
    usage: Option<&crate::progressive::Usage>,
) -> std::result::Result<MemberCrypt, FileParseError> {
    if catalogue {
        f.extra_records = extra_records(extra);
    }
    let mut crypt = None;
    let mut c = Cursor::new(extra);
    while c.remaining() > 0 {
        let size = c.vsize()?;
        let record = c.bytes(size)?;
        let mut r = Cursor::new(record);
        let kind = r.vint()?;
        match kind {
            FHEXTRA_CRYPT => {
                f.encrypted = true;
                let record = r.bytes(r.remaining())?;
                let mut lead = Cursor::new(record);
                if let (Ok(version), Ok(flags)) = (lead.vint(), lead.vint())
                    && let Some(&kdf_count) = record.get(lead.pos())
                {
                    f.crypt_record = Some(Rar5CryptRecord { version, flags, kdf_count });
                }
                let parsed = crate::crypto::parse_rar5_crypt(record, crate::crypto::Rar5CryptLayout::Member);
                f.crypt = parsed.ok();
                crypt = Some(parsed);
            }
            FHEXTRA_HASH => {
                if r.vint()? == 0 {
                    f.blake2sp = Some(r.bytes(32)?.try_into().unwrap());
                }
            }
            FHEXTRA_HTIME => parse_htime(f, &mut r)?,
            FHEXTRA_VERSION => {
                let _flags = r.vint()?;
                f.version = Some(r.vint()?);
            }
            FHEXTRA_REDIR => {
                let kind = r.vint()?;
                f.redirection_flags = r.vint()?;
                let len = r.vsize()?;
                let target = r.bytes(len)?;
                if catalogue && !(1..=5).contains(&kind) {
                    f.redirection = Some(Redirection::Unknown(kind));
                    continue;
                }
                let target = display_name_admitted(target, catalogue, usage)?;
                f.redirection = Some(match kind {
                    1 => Redirection::UnixSymlink(target),
                    2 => Redirection::WindowsSymlink(target),
                    3 => Redirection::Junction(target),
                    4 => Redirection::HardLink(target),
                    5 => Redirection::FileCopy(target),
                    other => Redirection::Unknown(other),
                });
            }
            FHEXTRA_SUBDATA if f.service && catalogue => {
                let data = r.bytes(r.remaining())?;
                f.sub_data.try_reserve_exact(data.len()).map_err(|_| FileParseError::Allocation)?;
                f.sub_data.extend_from_slice(data);
            }
            // owner, service data of other passes and anything newer are skipped
            _ => {}
        }
    }
    Ok(crypt)
}

/// Windows FILETIME is 100 ns ticks since 1601.
const FILETIME_TO_UNIX: i64 = 11_644_473_600;

fn parse_htime(f: &mut FileHeader, r: &mut Cursor<'_>) -> Result<()> {
    let flags = r.vint()?;
    let unix = flags & 1 != 0;
    let read = |r: &mut Cursor<'_>| -> Result<RarTime> {
        if unix {
            Ok(RarTime { seconds: i64::from(r.u32()?), nanos: 0, resolution_nanos: 1_000_000_000 })
        } else {
            let ticks = r.u64()?;
            let seconds = (ticks / 10_000_000) as i64 - FILETIME_TO_UNIX;
            Ok(RarTime { seconds, nanos: ((ticks % 10_000_000) * 100) as u32, resolution_nanos: 100 })
        }
    };
    let mtime = if flags & 2 != 0 { Some(read(r)?) } else { None };
    let mut ctime = if flags & 4 != 0 { Some(read(r)?) } else { None };
    let mut atime = if flags & 8 != 0 { Some(read(r)?) } else { None };
    if let Some(time) = mtime {
        f.mtime = Some(time.seconds);
        f.mtime_nanos = time.nanos;
        f.mtime_resolution = time.resolution_nanos;
        if unix && flags & 0x10 != 0 {
            f.mtime_nanos = r.u32()?.min(999_999_999);
            f.mtime_resolution = 1;
        }
    }
    // The nanoseconds of the other times follow in the same order. They are listing metadata only, so a record
    // too short to hold them keeps the whole seconds.
    if unix && flags & 0x10 != 0 {
        for time in [&mut ctime, &mut atime].into_iter().flatten() {
            let Ok(nanos) = r.u32() else { break };
            time.nanos = nanos.min(999_999_999);
            time.resolution_nanos = 1;
        }
    }
    f.ctime = ctime;
    f.atime = atime;
    Ok(())
}

/// The original archive name and time from a RAR 5.0 main header extra area. Listing metadata only: a record that
/// does not parse is ignored rather than failing the archive.
pub(crate) fn main_metadata(extra: &[u8]) -> (Option<Vec<u8>>, Option<RarTime>) {
    let mut c = Cursor::new(extra);
    while c.remaining() > 0 {
        let Ok(size) = c.vsize() else { break };
        let Ok(record) = c.bytes(size) else { break };
        let mut r = Cursor::new(record);
        if r.vint().ok() != Some(MHEXTRA_METADATA) {
            continue;
        }
        let parse = |r: &mut Cursor<'_>| -> Result<(Option<Vec<u8>>, Option<RarTime>)> {
            let flags = r.vint()?;
            let name = if flags & 1 != 0 {
                let len = r.vsize()?;
                let bytes = r.bytes(len)?;
                // UnRAR stops at a NUL inside the stored name.
                Some(bytes.split(|&b| b == 0).next().unwrap_or_default().to_vec())
            } else {
                None
            };
            let time = if flags & 2 == 0 {
                None
            } else if flags & 4 != 0 {
                if flags & 8 != 0 {
                    let nanos = r.u64()?;
                    Some(RarTime {
                        seconds: (nanos / 1_000_000_000) as i64,
                        nanos: (nanos % 1_000_000_000) as u32,
                        resolution_nanos: 1,
                    })
                } else {
                    Some(RarTime { seconds: i64::from(r.u32()?), nanos: 0, resolution_nanos: 1_000_000_000 })
                }
            } else {
                let ticks = r.u64()?;
                Some(RarTime {
                    seconds: (ticks / 10_000_000) as i64 - FILETIME_TO_UNIX,
                    nanos: ((ticks % 10_000_000) * 100) as u32,
                    resolution_nanos: 100,
                })
            };
            Ok((name, time))
        };
        return parse(&mut r).unwrap_or_default();
    }
    (None, None)
}
