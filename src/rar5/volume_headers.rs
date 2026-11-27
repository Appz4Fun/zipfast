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

//! Rebuilds every header byte of a lost RAR 5.0 volume from a sibling volume of the same set.
//!
//! A downloader that borrows a dead volume's packed data from another copy of the release (the same member in
//! another post) can write the volume back exactly as rar wrote it, so the set's par2 files verify it, when the
//! volume holds one part of the same member as an intact sibling. Everything around the packed data then follows
//! from the sibling's headers, the target's number, its length and the hashes of its part:
//!
//! * the signature and main header (the sibling's, with the target's volume number and quick open locator);
//! * the file header (the sibling's, with the split flags, the data size, and the CRC32 and BLAKE2sp the volume
//!   records: of the part's packed bytes for a part that continues, of the whole file for the last part);
//! * the quick open service header caching that file header, the end of archive header with its "more volumes"
//!   flag, and the zero padding up to the volume's length (see [`super::tail`]).
//!
//! [`rebuild_volume_headers`] returns those bytes and where the packed data goes between them, or a
//! [`VolumeHeadersError`] saying why the result cannot be proven exact.
//!
//! Written from the RAR 5.0 archive format description and checked against volume sets made by rar 7.30.

use std::io::{Read, Seek, SeekFrom};

use super::frame::{self, MainHeader, put_vint_min, read_block, read_vint};
use super::tail::{QuickOpenMode, TailDoubt, rebuild_volume_tail_with};
use super::{
    FHEXTRA_CRYPT, FHEXTRA_HASH, FHFL_CRC32, FHFL_DIRECTORY, FHFL_UTIME, HEAD_CRYPT, HEAD_END, HEAD_FILE, HEAD_MAIN,
    HEAD_SERVICE, HFL_DATA, HFL_EXTRA, HFL_SPLIT_AFTER, HFL_SPLIT_BEFORE, MHFL_PROTECT, MHFL_VOLUME, SIGNATURE,
};

/// rar's default quick open mode caches a file header only when the file has more than this much packed data in
/// the volume.
const SMALL_PIECE: u64 = 4096;
/// The longest sibling tail (bytes after its packed data) accepted. rar's quick open header, end header and padding
/// take about a hundred bytes per cached header; anything near this holds records that cannot be rebuilt.
pub const MAX_SIBLING_TAIL: u64 = 1 << 20;
/// The most bytes read from the start of a sibling volume looking for its file header (the format's header limit
/// is 2 MiB).
const MAX_SIBLING_HEAD: u64 = 3 << 20;
/// Crypt record flag: the file's checksums are converted with a key derived from the password.
const CRYPT_MAC: u64 = 0x2;
/// Hash record type BLAKE2sp.
const HASH_BLAKE2SP: u64 = 0;

/// What the caller knows of the volume to rebuild.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TargetVolume {
    /// The volume's number in its set, 0-based (`name.part3.rar` is 2).
    pub index: u64,
    /// The volume's exact length in bytes: from the par2 file description or the yEnc `=ybegin size=`, not from the
    /// NZB.
    pub volume_len: u64,
    /// Whether this is the set's last volume. The member's last part is in it, and its end header says no more
    /// volumes follow.
    pub last: bool,
    /// The hashes the volume's file header records. See [`PartHashes`].
    pub hashes: PartHashes,
    /// The length of the packed data the caller will lay in, when known. Checked against the length the volume's
    /// size leaves for it. Required for a first volume that is not the last (rar writes an archive comment only into
    /// the first volume, and only the data length shows that none is there), and for a middle volume rebuilt from
    /// the set's last volume.
    pub data_len: Option<u64>,
    /// Where this part's packed data starts in the member's packed data, when known. For a stored member it proves
    /// the layout: the part continues from a previous volume exactly when this is not 0, and the member ends in the
    /// volume exactly when the set's last volume is the target.
    pub packed_offset: Option<u64>,
}

/// The hashes a RAR 5.0 file header records.
///
/// For a part that continues in the next volume rar records the CRC32 (and with `-htb` the BLAKE2sp) of the part's
/// packed bytes in this volume, the bytes the caller lays in. For the member's last part it records the whole
/// file's unpacked CRC32 or BLAKE2sp: take it from another copy of the same file (the last volume of the alt
/// release's own set, an SFV), never from the part. Only the hash the sibling's header carries is needed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PartHashes {
    /// The CRC32.
    pub crc32: Option<u32>,
    /// The BLAKE2sp digest.
    pub blake2sp: Option<[u8; 32]>,
}

impl PartHashes {
    /// The CRC32 and BLAKE2sp of everything `data` yields: the hashes of a continuing part, from its packed bytes.
    pub fn of_reader(data: &mut dyn Read) -> std::io::Result<PartHashes> {
        let mut crc = crate::crc32::Hasher::new();
        let mut blake = crate::blake2sp::Blake2sp::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = match data.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            crc.update(&buf[..n]);
            blake.update(&buf[..n]);
        }
        Ok(PartHashes { crc32: Some(crc.finalize()), blake2sp: Some(blake.finish()) })
    }

    /// [`Self::of_reader`] over bytes in memory.
    pub fn of_bytes(data: &[u8]) -> PartHashes {
        let mut blake = crate::blake2sp::Blake2sp::new();
        blake.update(data);
        PartHashes { crc32: Some(crate::crc32::hash(data)), blake2sp: Some(blake.finish()) }
    }
}

/// A rebuilt volume: `head`, then `data_len` bytes of packed data at `data_offset`, then `tail`, `volume_len` bytes
/// in all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeFrame {
    /// The volume from offset 0 up to its packed data: signature, main header, file header.
    pub head: Vec<u8>,
    /// Where the packed data starts (`head.len()`).
    pub data_offset: u64,
    /// How many bytes of packed data follow.
    pub data_len: u64,
    /// The volume after its packed data, to its end: the quick open service header (when the set has one and the
    /// part is cached), the end of archive header, and the zero padding.
    pub tail: Vec<u8>,
    /// How many of `tail`'s last bytes are zero padding.
    pub padding: u64,
    /// Whether the rebuilt file header says the part continues from the previous volume.
    pub split_before: bool,
    /// Whether it says the part continues in the next volume.
    pub split_after: bool,
}

/// Which hash a refusal is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashKind {
    /// The file header's CRC32 field.
    Crc32,
    /// The BLAKE2sp hash record (`-htb`).
    Blake2sp,
}

/// Why a volume's headers cannot be rebuilt exactly.
#[derive(Debug)]
#[non_exhaustive]
pub enum VolumeHeadersError {
    /// The sibling is not a RAR 5.0 volume starting at offset 0 (a RAR 4.x volume, say).
    NotRar5,
    /// The sibling ends before its file header or its tail does.
    Truncated,
    /// The sibling's headers are damaged (a checksum or size fails).
    Corrupt(&'static str),
    /// The set's headers are encrypted (`-hp`): each starts with a random IV, so no rebuild can match.
    EncryptedHeaders,
    /// The set has a recovery record (`-rr`): its data covers each volume's own bytes.
    RecoveryRecord,
    /// The sibling holds a header whose content differs per volume or that is not rebuilt: an archive comment or
    /// other service header before its file, or anything but the quick open data and the end header after it.
    PerVolumeRecord(&'static str),
    /// The sibling does not hold exactly one part of a member split across volumes, or that member cannot have a
    /// part in the target the way it has one in the sibling (it starts or ends between them, or the target's
    /// [`TargetVolume::packed_offset`] contradicts the layout).
    LayoutDiffers(&'static str),
    /// The sibling's header records this hash and [`TargetVolume::hashes`] does not give it.
    MissingHash(HashKind),
    /// The member is data-encrypted (`-p`) and the target holds its last part: rar converts that part's checksums
    /// with a key derived from the password.
    EncryptedFinalPart,
    /// The target's length leaves no consistent room for its packed data, or that room is not
    /// [`TargetVolume::data_len`].
    SizeMismatch {
        /// The packed data length the volume's size leaves, when one fits.
        derived: Option<u64>,
        /// The length the caller gave.
        given: Option<u64>,
    },
    /// The target is the set's first volume and not its last, and [`TargetVolume::data_len`] was not given or the
    /// sibling is the set's last volume: an archive comment in it shows only as packed data shorter than the room
    /// the volume leaves after rar's reserve, which only a middle (or first) sibling shows.
    FirstVolumeUnproven,
    /// The target is a middle volume, the sibling is the set's last, and [`TargetVolume::data_len`] was not given:
    /// how much room rar reserved after a middle volume's data shows only in another middle (or the first) volume.
    ReserveUnknown,
    /// The target's quick open data depends on the set's quick open mode, which the sibling does not show (its part
    /// is large, the target's 4096 bytes or less), and [`TargetVolume::data_len`] was not given to decide.
    QuickOpenMode,
    /// The rebuilt tail is not certain (see [`TailDoubt`]).
    Doubt(TailDoubt),
    /// Reading the sibling failed.
    Io(std::io::Error),
}

impl std::fmt::Display for VolumeHeadersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRar5 => f.write_str("the sibling is not a RAR 5.0 volume"),
            Self::Truncated => f.write_str("the sibling volume is truncated"),
            Self::Corrupt(what) => write!(f, "the sibling volume is corrupt: {what}"),
            Self::EncryptedHeaders => f.write_str("encrypted RAR 5.0 headers cannot be rebuilt exactly"),
            Self::RecoveryRecord => f.write_str("a RAR 5.0 recovery record cannot be rebuilt"),
            Self::PerVolumeRecord(what) => write!(f, "the sibling holds a record that differs per volume: {what}"),
            Self::LayoutDiffers(what) => write!(f, "the target's layout differs from the sibling's: {what}"),
            Self::MissingHash(HashKind::Crc32) => f.write_str("the part's CRC32 is needed"),
            Self::MissingHash(HashKind::Blake2sp) => f.write_str("the part's BLAKE2sp is needed"),
            Self::EncryptedFinalPart => f.write_str("the last part of an encrypted member has keyed checksums"),
            Self::SizeMismatch { derived, given } => {
                write!(f, "the volume's size leaves {derived:?} bytes of packed data, given {given:?}")
            }
            Self::FirstVolumeUnproven => f.write_str("a first volume needs its data length to rule out a comment"),
            Self::ReserveUnknown => f.write_str("a middle volume cannot be rebuilt from the last volume"),
            Self::QuickOpenMode => f.write_str("the set's quick open mode is not known"),
            Self::Doubt(doubt) => write!(f, "the rebuilt tail is not certain: {doubt:?}"),
            Self::Io(e) => write!(f, "reading the sibling volume: {e}"),
        }
    }
}

impl std::error::Error for VolumeHeadersError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VolumeHeadersError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof { Self::Truncated } else { Self::Io(e) }
    }
}

type Result<T> = std::result::Result<T, VolumeHeadersError>;

/// Rebuilds the headers of volume `target` of a RAR 5.0 set from an intact `sibling` volume of the same set.
///
/// `sibling_head` is the sibling from offset 0 up to its packed data (through its file header) and
/// `sibling_tail` the sibling after its packed data, to its end. The packed data itself is not needed.
///
/// The target is taken to hold one part of the same member as the sibling, filling the volume the way the
/// sibling's part fills it, which is how rar lays out a member spanning many volumes. Give
/// [`TargetVolume::packed_offset`] to have a stored member's layout checked.
pub fn rebuild_volume_headers(sibling_head: &[u8], sibling_tail: &[u8], target: &TargetVolume) -> Result<VolumeFrame> {
    let sibling = Sibling::parse(sibling_head, sibling_tail)?;
    sibling.rebuild(target)
}

/// [`rebuild_volume_headers`] reading the sibling volume from `sibling`: its start up to the packed data, then
/// everything after the data. The data is skipped, not read.
pub fn rebuild_volume_headers_from<R: Read + Seek + ?Sized>(
    sibling: &mut R,
    target: &TargetVolume,
) -> Result<VolumeFrame> {
    let (head, tail) = read_sibling(sibling)?;
    rebuild_volume_headers(&head, &tail, target)
}

/// The sibling's bytes before and after its packed data.
fn read_sibling<R: Read + Seek + ?Sized>(r: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    r.seek(SeekFrom::Start(0))?;
    let mut head = Vec::new();
    let mut want = 4096u64;
    let (data_at, data_len) = loop {
        let have = head.len() as u64;
        if want > have {
            Read::take(&mut *r, want - have).read_to_end(&mut head)?;
        }
        match find_file_header(&head)? {
            Some(found) => break found,
            None if (head.len() as u64) < want => return Err(VolumeHeadersError::Truncated),
            None if want >= MAX_SIBLING_HEAD => return Err(VolumeHeadersError::Corrupt("headers too long")),
            None => want = (want * 4).min(MAX_SIBLING_HEAD),
        }
    };
    head.truncate(data_at);
    let data_end = (data_at as u64).checked_add(data_len).ok_or(VolumeHeadersError::Corrupt("data size"))?;
    let len = r.seek(SeekFrom::End(0))?;
    if len < data_end {
        return Err(VolumeHeadersError::Truncated);
    }
    if len - data_end > MAX_SIBLING_TAIL {
        return Err(VolumeHeadersError::PerVolumeRecord("more than the quick open data after the packed data"));
    }
    r.seek(SeekFrom::Start(data_end))?;
    let mut tail = Vec::with_capacity((len - data_end) as usize);
    Read::take(&mut *r, len - data_end).read_to_end(&mut tail)?;
    if (tail.len() as u64) != len - data_end {
        return Err(VolumeHeadersError::Truncated);
    }
    Ok((head, tail))
}

/// Where the first file header's data starts and its length, walking the headers from the signature. `None` when
/// `bytes` ends first.
fn find_file_header(bytes: &[u8]) -> Result<Option<(usize, u64)>> {
    if bytes.len() < SIGNATURE.len() {
        return if SIGNATURE.starts_with(bytes) { Ok(None) } else { Err(VolumeHeadersError::NotRar5) };
    }
    if &bytes[..SIGNATURE.len()] != SIGNATURE {
        return Err(VolumeHeadersError::NotRar5);
    }
    let mut at = SIGNATURE.len();
    loop {
        let Some(block) = read_block(bytes, at).map_err(corrupt)? else { return Ok(None) };
        match block.kind {
            HEAD_FILE => return Ok(Some((block.header_end, block.data_len))),
            HEAD_CRYPT => return Err(VolumeHeadersError::EncryptedHeaders),
            HEAD_MAIN if at == SIGNATURE.len() => {}
            HEAD_SERVICE => return Err(VolumeHeadersError::PerVolumeRecord("a service header before the file")),
            _ => return Err(VolumeHeadersError::Corrupt("unexpected header before the file")),
        }
        if block.data_len != 0 {
            return Err(VolumeHeadersError::Corrupt("main header with data"));
        }
        at = block.header_end;
    }
}

fn corrupt(e: crate::error::Error) -> VolumeHeadersError {
    match e {
        crate::error::Error::Corrupt(what) => VolumeHeadersError::Corrupt(what),
        crate::error::Error::Truncated => VolumeHeadersError::Truncated,
        crate::error::Error::NotAnArchive => VolumeHeadersError::NotRar5,
        crate::error::Error::Unsupported(_) => VolumeHeadersError::Corrupt("unsupported RAR 5.0 header"),
        _ => VolumeHeadersError::Corrupt("RAR 5.0 header"),
    }
}

/// The sibling's file header, split into the pieces a target's header is built from.
struct FileHeader<'a> {
    /// Header flags.
    flags: u64,
    /// Width of the header size, header flags and data size fields as the sibling has them.
    size_width: usize,
    flags_width: usize,
    data_width: usize,
    /// The header type and the extra area size field, raw.
    kind_raw: &'a [u8],
    extra_size_raw: &'a [u8],
    /// Everything after the data size field: file flags through the extra area, raw.
    rest: &'a [u8],
    /// Offsets in `rest` of the CRC32 field, the BLAKE2sp digest and the crypt record's flags byte.
    crc_at: Option<usize>,
    blake_at: Option<usize>,
    crypt_flags_at: Option<(usize, u64)>,
    unpacked: u64,
    stored: bool,
}

impl<'a> FileHeader<'a> {
    fn parse(block: &'a [u8]) -> Result<FileHeader<'a>> {
        let bad = VolumeHeadersError::Corrupt;
        let (_, size_width) = read_vint(block, 4).ok_or(bad("header size"))?;
        let mut at = 4 + size_width;
        let kind_start = at;
        let (_, n) = read_vint(block, at).ok_or(bad("header type"))?;
        at += n;
        let kind_raw = &block[kind_start..at];
        let (flags, flags_width) = read_vint(block, at).ok_or(bad("header flags"))?;
        at += flags_width;
        let extra_start = at;
        let mut extra_len = 0u64;
        if flags & HFL_EXTRA != 0 {
            let (v, n) = read_vint(block, at).ok_or(bad("extra size"))?;
            extra_len = v;
            at += n;
        }
        let extra_size_raw = &block[extra_start..at];
        if flags & HFL_DATA == 0 {
            return Err(VolumeHeadersError::LayoutDiffers("the sibling's file has no data"));
        }
        let (_, data_width) = read_vint(block, at).ok_or(bad("data size"))?;
        at += data_width;
        let rest = &block[at..];
        let extra_len = usize::try_from(extra_len).ok().filter(|&e| e <= rest.len()).ok_or(bad("extra size"))?;
        let fields_len = rest.len() - extra_len;
        // File flags, unpacked size, attributes, mtime, CRC32, compression info, host OS, name.
        let mut p = 0usize;
        let next = |p: &mut usize, what: &'static str| -> Result<u64> {
            let (v, n) = read_vint(&rest[..fields_len], *p).ok_or(bad(what))?;
            *p += n;
            Ok(v)
        };
        let file_flags = next(&mut p, "file flags")?;
        if file_flags & FHFL_DIRECTORY != 0 {
            return Err(VolumeHeadersError::LayoutDiffers("the sibling's file is a directory"));
        }
        let unpacked = next(&mut p, "unpacked size")?;
        next(&mut p, "attributes")?;
        if file_flags & FHFL_UTIME != 0 {
            p = p.checked_add(4).filter(|&e| e <= fields_len).ok_or(bad("mtime"))?;
        }
        let mut crc_at = None;
        if file_flags & FHFL_CRC32 != 0 {
            crc_at = Some(p);
            p = p.checked_add(4).filter(|&e| e <= fields_len).ok_or(bad("data CRC32"))?;
        }
        let compression = next(&mut p, "compression information")?;
        next(&mut p, "host OS")?;
        let name_len = next(&mut p, "name length")?;
        let name_end = usize::try_from(name_len)
            .ok()
            .and_then(|n| p.checked_add(n))
            .filter(|&e| e == fields_len)
            .ok_or(bad("name length"))?;
        let _ = name_end;
        // Extra records.
        let mut blake_at = None;
        let mut crypt_flags_at = None;
        let mut q = fields_len;
        while q < rest.len() {
            let (size, n) = read_vint(rest, q).ok_or(bad("extra record"))?;
            let start = q + n;
            let end = usize::try_from(size)
                .ok()
                .and_then(|s| start.checked_add(s))
                .filter(|&e| e <= rest.len() && size > 0)
                .ok_or(bad("extra record"))?;
            let (kind, n) = read_vint(&rest[..end], start).ok_or(bad("extra record"))?;
            let body = start + n;
            match kind {
                FHEXTRA_CRYPT => {
                    let (_, n) = read_vint(&rest[..end], body).ok_or(bad("crypt record"))?;
                    let (crypt_flags, w) = read_vint(&rest[..end], body + n).ok_or(bad("crypt record"))?;
                    if w != 1 {
                        return Err(bad("crypt record flags"));
                    }
                    crypt_flags_at = Some((body + n, crypt_flags));
                }
                FHEXTRA_HASH => {
                    let (hash_kind, n) = read_vint(&rest[..end], body).ok_or(bad("hash record"))?;
                    if hash_kind != HASH_BLAKE2SP || end - (body + n) != 32 || blake_at.is_some() {
                        return Err(bad("hash record"));
                    }
                    blake_at = Some(body + n);
                }
                _ => {}
            }
            q = end;
        }
        Ok(FileHeader {
            flags,
            size_width,
            flags_width,
            data_width,
            kind_raw,
            extra_size_raw,
            rest,
            crc_at,
            blake_at,
            crypt_flags_at,
            unpacked,
            stored: (compression >> 7) & 0x7 == 0,
        })
    }

    /// The target's file header block.
    fn encode(&self, split_before: bool, split_after: bool, data_len: u64, hashes: &PartHashes) -> Result<Vec<u8>> {
        let mut rest = self.rest.to_vec();
        if let Some(at) = self.crc_at {
            let crc = hashes.crc32.ok_or(VolumeHeadersError::MissingHash(HashKind::Crc32))?;
            rest[at..at + 4].copy_from_slice(&crc.to_le_bytes());
        }
        if let Some(at) = self.blake_at {
            let digest = hashes.blake2sp.ok_or(VolumeHeadersError::MissingHash(HashKind::Blake2sp))?;
            rest[at..at + 32].copy_from_slice(&digest);
        }
        if let Some((at, crypt_flags)) = self.crypt_flags_at {
            // rar keys the checksums of an encrypted member's last part only; a continuing part records them plain.
            if !split_after {
                return Err(VolumeHeadersError::EncryptedFinalPart);
            }
            rest[at] = (crypt_flags & !CRYPT_MAC) as u8;
        }
        let mut flags = self.flags & !(HFL_SPLIT_BEFORE | HFL_SPLIT_AFTER);
        if split_before {
            flags |= HFL_SPLIT_BEFORE;
        }
        if split_after {
            flags |= HFL_SPLIT_AFTER;
        }
        let mut fields = Vec::with_capacity(self.rest.len() + 16);
        fields.extend_from_slice(self.kind_raw);
        put_vint_min(&mut fields, flags, self.flags_width);
        fields.extend_from_slice(self.extra_size_raw);
        put_vint_min(&mut fields, data_len, self.data_width);
        fields.extend_from_slice(&rest);
        let mut sized = Vec::with_capacity(fields.len() + 8);
        put_vint_min(&mut sized, fields.len() as u64, self.size_width);
        sized.extend_from_slice(&fields);
        let mut out = Vec::with_capacity(sized.len() + 4);
        out.extend_from_slice(&crate::crc32::hash(&sized).to_le_bytes());
        out.extend_from_slice(&sized);
        Ok(out)
    }
}

/// A parsed sibling volume.
struct Sibling<'a> {
    main: MainHeader,
    file: FileHeader<'a>,
    /// The sibling's index, from its main header.
    index: u64,
    /// Whether its end header says more volumes follow.
    more: bool,
    /// The bytes after its packed data, padding included: rar's reserve when the sibling is not the last volume.
    reserve: u64,
    /// The set's quick open mode, when the sibling shows it.
    mode: Option<QuickOpenMode>,
    /// Whether the set writes quick open data at all.
    quick_open: bool,
}

impl<'a> Sibling<'a> {
    fn parse(head: &'a [u8], tail: &[u8]) -> Result<Sibling<'a>> {
        let (data_at, data_len) = find_file_header(head)?.ok_or(VolumeHeadersError::Truncated)?;
        if data_at != head.len() {
            return Err(VolumeHeadersError::Corrupt("the sibling's head does not end at its packed data"));
        }
        let main_block = read_block(head, SIGNATURE.len()).map_err(corrupt)?.ok_or(VolumeHeadersError::Truncated)?;
        let main = MainHeader::parse(&head[SIGNATURE.len()..]).map_err(corrupt)?;
        if main.archive_flags & MHFL_PROTECT != 0 || main.locator.is_some_and(|l| l.recovery.is_some()) {
            return Err(VolumeHeadersError::RecoveryRecord);
        }
        if main.archive_flags & MHFL_VOLUME == 0 {
            return Err(VolumeHeadersError::LayoutDiffers("the sibling is not a volume of a set"));
        }
        let file_at = main_block.header_end;
        let file_block = read_block(head, file_at).map_err(corrupt)?.ok_or(VolumeHeadersError::Truncated)?;
        if file_block.kind != HEAD_FILE || file_block.header_end != head.len() {
            return Err(VolumeHeadersError::PerVolumeRecord("a header between the main and file headers"));
        }
        let file = FileHeader::parse(&head[file_at..])?;
        if file.flags & (HFL_SPLIT_BEFORE | HFL_SPLIT_AFTER) == 0 {
            return Err(VolumeHeadersError::LayoutDiffers("the sibling's file is not split across volumes"));
        }
        // The sibling's own tail must be exactly what the rebuild writes: the quick open data, the end header and
        // zeros. A recovery record, a further file or any other service header there is refused.
        let more = tail_end_flag(tail)?;
        let sibling_len = (head.len() as u64)
            .checked_add(data_len)
            .and_then(|l| l.checked_add(tail.len() as u64))
            .ok_or(VolumeHeadersError::Corrupt("data size"))?;
        let quick_open = main.locator.is_some_and(|l| l.quick_open.is_some());
        let cached = main.locator.and_then(|l| l.quick_open).is_some_and(|(offset, _)| offset != 0);
        let mode = match (quick_open, data_len <= SMALL_PIECE, cached) {
            (true, true, true) => Some(QuickOpenMode::All),
            (true, true, false) => Some(QuickOpenMode::LargeFiles),
            _ => None,
        };
        let rebuilt = rebuild_volume_tail_with(head, sibling_len, Some(more), mode.or(Some(QuickOpenMode::All)))
            .map_err(|e| match e {
                crate::error::Error::Unsupported(_) => {
                    VolumeHeadersError::PerVolumeRecord("a record the rebuild does not write")
                }
                e => corrupt(e),
            })?;
        let padding = usize::try_from(rebuilt.padding).map_err(|_| VolumeHeadersError::Corrupt("padding"))?;
        if rebuilt.bytes.len().checked_add(padding) != Some(tail.len())
            || tail[..rebuilt.bytes.len()] != rebuilt.bytes[..]
            || tail[rebuilt.bytes.len()..].iter().any(|&b| b != 0)
        {
            return Err(VolumeHeadersError::PerVolumeRecord("more than the quick open data after the packed data"));
        }
        if more != (file.flags & HFL_SPLIT_AFTER != 0) {
            return Err(VolumeHeadersError::LayoutDiffers("the sibling's member ends in a middle volume"));
        }
        Ok(Sibling {
            index: main.volume_number.unwrap_or(0),
            main,
            file,
            more,
            reserve: tail.len() as u64,
            mode,
            quick_open,
        })
    }

    fn rebuild(&self, target: &TargetVolume) -> Result<VolumeFrame> {
        let layout = VolumeHeadersError::LayoutDiffers;
        let sibling_first_part = self.file.flags & HFL_SPLIT_BEFORE == 0;
        if target.index == self.index {
            return Err(layout("the target is the sibling"));
        }
        if sibling_first_part && target.index < self.index {
            return Err(layout("the member starts in the sibling, after the target"));
        }
        if !self.more && target.index > self.index {
            return Err(layout("the sibling is the set's last volume, before the target"));
        }
        if target.last && target.index < self.index {
            return Err(layout("the target is the last volume, before the sibling"));
        }
        let split_before = match target.packed_offset {
            Some(offset) => offset != 0,
            None => target.index > 0,
        };
        if split_before && target.index == 0 {
            return Err(layout("a first volume cannot continue a member"));
        }
        if !split_before && target.index > self.index {
            return Err(layout("the member starts in the target, after the sibling's part"));
        }
        let split_after = !target.last;
        if target.index == 0 && !target.last && (target.data_len.is_none() || !self.more) {
            return Err(VolumeHeadersError::FirstVolumeUnproven);
        }
        let modes: &[QuickOpenMode] = match self.mode {
            Some(QuickOpenMode::All) => &[QuickOpenMode::All],
            Some(QuickOpenMode::LargeFiles) => &[QuickOpenMode::LargeFiles],
            None => &[QuickOpenMode::All, QuickOpenMode::LargeFiles],
        };
        // Each quick open mode the sibling leaves open gives a frame; a given data length picks among them.
        let mut frames: Vec<VolumeFrame> = Vec::new();
        let mut last_err = None;
        for &mode in modes {
            match self.solve(target, split_before, split_after, mode) {
                Ok(frame) if !frames.contains(&frame) => frames.push(frame),
                Ok(_) => {}
                Err(e) => last_err = Some(e),
            }
        }
        let derived = frames.first().map(|f| f.data_len);
        if let Some(given) = target.data_len {
            frames.retain(|f| f.data_len == given);
        }
        let frame = match frames.len() {
            1 => frames.pop().expect("one frame"),
            0 if derived.is_some() => {
                return Err(VolumeHeadersError::SizeMismatch { derived, given: target.data_len });
            }
            0 => return Err(last_err.unwrap_or(VolumeHeadersError::SizeMismatch { derived: None, given: None })),
            _ => return Err(VolumeHeadersError::QuickOpenMode),
        };
        if self.file.stored
            && let Some(offset) = target.packed_offset
        {
            let end = offset.checked_add(frame.data_len);
            let ends_here = end == Some(self.file.unpacked);
            if end.is_none_or(|e| e > self.file.unpacked) || ends_here != target.last {
                return Err(layout("the stored member does not end where the target's layout needs"));
            }
        }
        Ok(frame)
    }

    /// The target's frame in quick open mode `mode`. The packed data length is whatever makes the volume's length
    /// add up: the sibling's reserve after a middle volume's data, nothing after the last volume's end header. With
    /// the set's last volume as the sibling, a middle target's reserve is unknown and its data length must be given.
    fn solve(&self, target: &TargetVolume, before: bool, after: bool, mode: QuickOpenMode) -> Result<VolumeFrame> {
        let mismatch = |derived| VolumeHeadersError::SizeMismatch { derived, given: target.data_len };
        let overflow = || VolumeHeadersError::SizeMismatch { derived: None, given: target.data_len };
        // The head for packed data length `data`. The locator names the quick open header's offset from the main
        // header (or 0 without one), which moves with the main header's own length: settled in a few rounds.
        let head_for = |data: u64| -> Result<Vec<u8>> {
            let file = self.file.encode(before, after, data, &target.hashes)?;
            let mut main = self.main.for_volume(target.index);
            let cached = mode == QuickOpenMode::All || data > SMALL_PIECE;
            let mut settled = false;
            for _ in 0..4 {
                let main_len = main.encode().len() as u64;
                let Some((value, width)) = main.locator.and_then(|l| l.quick_open) else {
                    settled = true;
                    break;
                };
                let offset = if cached {
                    main_len.checked_add(file.len() as u64).and_then(|o| o.checked_add(data)).ok_or_else(overflow)?
                } else {
                    0
                };
                if offset == value {
                    settled = true;
                    break;
                }
                if let Some(locator) = main.locator.as_mut() {
                    locator.quick_open = Some((offset, width));
                }
            }
            if !settled {
                return Err(overflow());
            }
            let mut head = SIGNATURE.to_vec();
            head.extend(main.encode());
            head.extend(file);
            Ok(head)
        };
        let reserve_known = !after || self.more;
        let (head, data) = if reserve_known {
            let mut data = 0u64;
            let mut tail_len = if after { self.reserve } else { 0 };
            let mut settled = None;
            for _ in 0..8 {
                let head = head_for(data)?;
                let want = target
                    .volume_len
                    .checked_sub(head.len() as u64)
                    .and_then(|r| r.checked_sub(tail_len))
                    .ok_or(mismatch(None))?;
                if want == data {
                    settled = Some(head);
                    break;
                }
                data = want;
                if !after {
                    // The last volume's tail is the quick open data and end header, sized by the data in it.
                    let head = head_for(data)?;
                    // Only its headers' length matters here, so no volume length is imposed yet.
                    let tail = rebuild_volume_tail_with(&head, u64::MAX, Some(false), Some(mode))
                        .map_err(|_| mismatch(Some(data)))?;
                    tail_len = tail.bytes.len() as u64;
                }
            }
            (settled.ok_or(mismatch(None))?, data)
        } else {
            let data = target.data_len.ok_or(VolumeHeadersError::ReserveUnknown)?;
            (head_for(data)?, data)
        };
        let tail = rebuild_volume_tail_with(&head, target.volume_len, Some(after), Some(mode))
            .map_err(|_| mismatch(Some(data)))?;
        if (head.len() as u64).checked_add(data) != Some(tail.offset) {
            return Err(mismatch(Some(data)));
        }
        if !after && tail.padding != 0 {
            return Err(mismatch(Some(data)));
        }
        if after && reserve_known && (tail.bytes.len() as u64).checked_add(tail.padding) != Some(self.reserve) {
            return Err(mismatch(Some(data)));
        }
        if let Some(doubt) = tail.doubt {
            // A middle volume's padding equal to the sibling's reserve is proven by the sibling: rar's usual bound
            // on it does not apply.
            if !(after && reserve_known && doubt == TailDoubt::UnexpectedPadding) {
                return Err(VolumeHeadersError::Doubt(doubt));
            }
        }
        if !self.quick_open && tail.bytes.len() != frame::end_of_archive(after).len() {
            return Err(mismatch(Some(data)));
        }
        let padding =
            usize::try_from(tail.padding).ok().filter(|&p| p as u64 <= MAX_SIBLING_TAIL).ok_or(mismatch(Some(data)))?;
        let mut bytes = tail.bytes;
        bytes.resize(bytes.len() + padding, 0);
        Ok(VolumeFrame {
            data_offset: head.len() as u64,
            head,
            data_len: data,
            tail: bytes,
            padding: tail.padding,
            split_before: before,
            split_after: after,
        })
    }
}

/// The "more volumes" flag of the end header in a sibling's tail, found by walking its headers.
fn tail_end_flag(tail: &[u8]) -> Result<bool> {
    let mut at = 0usize;
    loop {
        let block = read_block(tail, at).map_err(corrupt)?.ok_or(VolumeHeadersError::Truncated)?;
        match block.kind {
            HEAD_END => {
                let mut c = super::Cursor::new(&tail[block.fields.clone()]);
                let flags = c.vint().map_err(corrupt)?;
                return Ok(flags & super::EOAFL_MORE_VOLUMES != 0);
            }
            HEAD_SERVICE => {}
            HEAD_FILE => return Err(VolumeHeadersError::LayoutDiffers("the sibling holds more than one file")),
            _ => return Err(VolumeHeadersError::PerVolumeRecord("an unknown header after the packed data")),
        }
        at = block
            .data_end()
            .and_then(|e| usize::try_from(e).ok())
            .filter(|&e| e <= tail.len())
            .ok_or(VolumeHeadersError::Truncated)?;
    }
}
