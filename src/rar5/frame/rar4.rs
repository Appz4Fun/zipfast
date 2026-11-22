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

//! RAR 1.5 to 4.x header blocks, read and written byte for byte: the marker, the main header, file and service
//! headers, the end of archive block, and the 16-bit header checksum.
//!
//! Every block starts with `HEAD_CRC` (u16), `HEAD_TYPE` (u8), `HEAD_FLAGS` (u16) and `HEAD_SIZE` (u16, the whole
//! header). `HEAD_CRC` is the low 16 bits of the CRC32 of the header from `HEAD_TYPE` on ([`header_crc`]). A file or
//! service header is followed by its packed data; other blocks with flag 0x8000 by `ADD_SIZE` (u32) bytes of data.

use crate::error::{Error, Result};

/// The RAR 1.5-4.x marker block, which starts every volume.
pub const MARKER: [u8; 7] = *b"Rar!\x1a\x07\x00";

/// Block types.
pub const HEAD_MAIN: u8 = 0x73;
pub const HEAD_FILE: u8 = 0x74;
pub const HEAD_SERVICE: u8 = 0x7a;
pub const HEAD_END: u8 = 0x7b;

/// Block flag: data of `ADD_SIZE` bytes follows the header (always set on file and service headers).
pub const LONG_BLOCK: u16 = 0x8000;
/// Block flag: a reader that does not know the block may skip it.
pub const SKIP_IF_UNKNOWN: u16 = 0x4000;

/// Main header flags.
pub const MHD_VOLUME: u16 = 0x0001;
pub const MHD_COMMENT: u16 = 0x0002;
pub const MHD_LOCK: u16 = 0x0004;
pub const MHD_SOLID: u16 = 0x0008;
pub const MHD_NEWNUMBERING: u16 = 0x0010;
pub const MHD_PROTECT: u16 = 0x0040;
pub const MHD_PASSWORD: u16 = 0x0080;
pub const MHD_FIRSTVOLUME: u16 = 0x0100;
pub const MHD_ENCRYPTVER: u16 = 0x0200;

/// File header flags.
pub const LHD_SPLIT_BEFORE: u16 = 0x0001;
pub const LHD_SPLIT_AFTER: u16 = 0x0002;
pub const LHD_PASSWORD: u16 = 0x0004;
/// A RAR 2.x file comment follows the header's fields (inside the header).
pub const LHD_COMMENT: u16 = 0x0008;
pub const LHD_SOLID: u16 = 0x0010;
pub const LHD_DIRECTORY: u16 = 0x00e0;
pub const LHD_LARGE: u16 = 0x0100;
pub const LHD_UNICODE: u16 = 0x0200;
pub const LHD_SALT: u16 = 0x0400;
pub const LHD_EXTTIME: u16 = 0x1000;

/// End of archive flags.
pub const EARC_NEXT_VOLUME: u16 = 0x0001;
pub const EARC_DATACRC: u16 = 0x0002;
pub const EARC_REVSPACE: u16 = 0x0004;
pub const EARC_VOLNUMBER: u16 = 0x0008;

/// The 16-bit checksum of the header at the start of `block`: the low 16 bits of the CRC32 of its bytes from
/// `HEAD_TYPE` to `HEAD_SIZE`, except for RAR 2.x headers holding a comment, whose checksum covers only what precedes
/// it (as RAR 2.x writes and UnRAR checks): a main header with [`MHD_COMMENT`] its first 13 bytes, a file header
/// with [`LHD_COMMENT`] its fields up to the end of the name, salt and extended time. `None` when `block` is shorter
/// than its `HEAD_SIZE` says, or that is under 7, or a commented file header's fields run past it.
pub fn header_crc(block: &[u8]) -> Option<u16> {
    let size = usize::from(u16::from_le_bytes(block.get(5..7)?.try_into().ok()?));
    (size >= 7).then_some(())?;
    let header = block.get(..size)?;
    let flags = u16::from_le_bytes([header[3], header[4]]);
    let end = match header[2] {
        HEAD_MAIN if flags & MHD_COMMENT != 0 => size.min(13),
        HEAD_FILE if flags & LHD_COMMENT != 0 => file_fields_end(header, flags).ok()?,
        _ => size,
    };
    Some(crate::crc32::hash(&header[2..end]) as u16)
}

/// Where a file header's parsed fields end: after its name, salt and extended time.
fn file_fields_end(header: &[u8], flags: u16) -> Result<usize> {
    let mut f = Fields { bytes: header, at: 7 + 19 };
    let name_len = usize::from(f.u16()?);
    f.u32()?; // attributes
    if flags & LHD_LARGE != 0 {
        f.take(8)?;
    }
    f.take(name_len)?;
    if flags & LHD_SALT != 0 {
        f.take(8)?;
    }
    if flags & LHD_EXTTIME != 0 {
        let times = f.u16()?;
        for index in 0..4u16 {
            let mode = (times >> ((3 - index) * 4)) & 15;
            if mode & 8 == 0 {
                continue;
            }
            if index != 0 {
                f.u32()?;
            }
            f.take(usize::from(mode & 3))?;
        }
    }
    Ok(f.at)
}

/// Sets `HEAD_CRC` of the header at the start of `block` from its contents, after a field was patched.
pub fn seal(block: &mut [u8]) -> Result<()> {
    let crc = header_crc(block).ok_or(Error::Truncated)?;
    block[..2].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// A header block from its type, flags and the fields after `HEAD_SIZE`: `HEAD_SIZE` and `HEAD_CRC` are filled in.
/// Fails when the header would be longer than 65,535 bytes.
pub fn block(head_type: u8, flags: u16, fields: &[u8]) -> Result<Vec<u8>> {
    let size =
        u16::try_from(7 + fields.len()).map_err(|_| Error::Unsupported("a RAR 4.x header over 64 KiB".into()))?;
    let mut out = Vec::with_capacity(usize::from(size));
    out.extend_from_slice(&[0, 0, head_type]);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(fields);
    seal(&mut out)?;
    Ok(out)
}

/// One RAR 4.x block as [`read_block`] found it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Block {
    /// Where the block starts (its `HEAD_CRC`).
    pub offset: usize,
    pub head_type: u8,
    pub flags: u16,
    /// The header's length, `HEAD_SIZE`.
    pub head_size: u16,
    /// Where the header ends and its data starts.
    pub header_end: usize,
    /// The data after the header: a file or service header's packed size (with its high 32 bits under
    /// [`LHD_LARGE`]), else `ADD_SIZE` under [`LONG_BLOCK`], else 0.
    pub data_len: u64,
}

impl Block {
    /// The header, `HEAD_CRC` included.
    pub fn header<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.offset..self.header_end]
    }
    /// Where the data ends: the next block's offset. `None` on overflow.
    pub fn data_end(&self) -> Option<u64> {
        (self.header_end as u64).checked_add(self.data_len)
    }
}

/// Reads the block at `at`. `Ok(None)` when `bytes` ends inside its header; [`Error::Corrupt`] when `HEAD_SIZE` is
/// impossible or [`header_crc`] differs from `HEAD_CRC`. The data is not read and need not be present. Encrypted
/// headers (after a main header with [`MHD_PASSWORD`]) cannot be read this way.
pub fn read_block(bytes: &[u8], at: usize) -> Result<Option<Block>> {
    let Some(head) = bytes.get(at..at.saturating_add(7)).filter(|h| h.len() == 7) else { return Ok(None) };
    let head_type = head[2];
    let flags = u16::from_le_bytes([head[3], head[4]]);
    let head_size = u16::from_le_bytes([head[5], head[6]]);
    if head_size < 7 {
        return Err(Error::Corrupt("RAR 4.x header size"));
    }
    let header_end = at + usize::from(head_size);
    let Some(header) = bytes.get(at..header_end) else { return Ok(None) };
    if header_crc(header) != Some(u16::from_le_bytes([head[0], head[1]])) {
        return Err(Error::Corrupt("RAR 4.x header checksum"));
    }
    let u32_at = |p: usize| header.get(p..p + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let data_len = if head_type == HEAD_FILE || head_type == HEAD_SERVICE {
        let low = u32_at(7).ok_or(Error::Corrupt("RAR 4.x file header size"))?;
        let high =
            if flags & LHD_LARGE != 0 { u32_at(32).ok_or(Error::Corrupt("RAR 4.x file header size"))? } else { 0 };
        u64::from(low) | (u64::from(high) << 32)
    } else if flags & LONG_BLOCK != 0 {
        u64::from(u32_at(7).ok_or(Error::Corrupt("RAR 4.x block size"))?)
    } else {
        0
    };
    Ok(Some(Block { offset: at, head_type, flags, head_size, header_end, data_len }))
}

/// The main archive header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainHeader {
    /// [`MHD_VOLUME`], [`MHD_SOLID`], [`MHD_NEWNUMBERING`], [`MHD_FIRSTVOLUME`] and the rest.
    pub flags: u16,
    /// Reserved fields `HighPosAV` and `PosAV` (zero in rar's output).
    pub high_pos_av: u16,
    pub pos_av: u32,
    /// The encryption version byte present under [`MHD_ENCRYPTVER`].
    pub encrypt_version: Option<u8>,
    /// Bytes after the known fields (a RAR 2.x comment block under [`MHD_COMMENT`], which the header checksum does
    /// not cover), kept as they are.
    pub rest: Vec<u8>,
}

impl MainHeader {
    /// A plain main header with `flags` and zero reserved fields, as rar writes it.
    pub fn new(flags: u16) -> MainHeader {
        MainHeader { flags, high_pos_av: 0, pos_av: 0, encrypt_version: None, rest: Vec::new() }
    }

    /// Parses the main header at the start of `header` (its bytes up to `HEAD_SIZE`; checksum checked).
    pub fn parse(header: &[u8]) -> Result<MainHeader> {
        let b = read_block(header, 0)?.ok_or(Error::Truncated)?;
        if b.head_type != HEAD_MAIN {
            return Err(Error::Corrupt("not a RAR 4.x main header"));
        }
        let h = &header[..b.header_end];
        let mut f = Fields { bytes: h, at: 7 };
        let high_pos_av = f.u16()?;
        let pos_av = f.u32()?;
        let encrypt_version = if b.flags & MHD_ENCRYPTVER != 0 { Some(f.byte()?) } else { None };
        Ok(MainHeader { flags: b.flags, high_pos_av, pos_av, encrypt_version, rest: h[f.at..].to_vec() })
    }

    /// The header block. Fails when [`Self::encrypt_version`] disagrees with [`MHD_ENCRYPTVER`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.encrypt_version.is_some() != (self.flags & MHD_ENCRYPTVER != 0) {
            return Err(Error::Unsupported("RAR 4.x main header: encryption version and flag disagree".into()));
        }
        let mut fields = Vec::with_capacity(7 + self.rest.len());
        fields.extend_from_slice(&self.high_pos_av.to_le_bytes());
        fields.extend_from_slice(&self.pos_av.to_le_bytes());
        fields.extend(self.encrypt_version);
        fields.extend_from_slice(&self.rest);
        block(HEAD_MAIN, self.flags, &fields)
    }
}

/// A file header (type `0x74`) or service header (type `0x7a`, such as a comment `CMT` or a recovery record `RR`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileHeader {
    /// [`HEAD_FILE`] or [`HEAD_SERVICE`].
    pub head_type: u8,
    /// [`LHD_SPLIT_BEFORE`], [`LHD_SPLIT_AFTER`], [`LHD_PASSWORD`], [`LHD_SOLID`], the dictionary bits,
    /// [`LHD_LARGE`], [`LHD_UNICODE`], [`LHD_SALT`], [`LHD_EXTTIME`]; [`LONG_BLOCK`] is always written.
    pub flags: u16,
    /// Packed bytes of this part, in this volume.
    pub packed_size: u64,
    /// The whole file's unpacked size.
    pub unpacked_size: u64,
    /// 0 MS-DOS, 1 OS/2, 2 Windows, 3 Unix, 4 Mac OS, 5 BeOS.
    pub host_os: u8,
    /// CRC32 of this part's packed data for a part continuing in the next volume, else of the whole unpacked file.
    pub crc: u32,
    /// The modification time, MS-DOS format.
    pub dos_time: u32,
    /// The version needed to unpack, times ten (29 for RAR 2.9 to 4.x).
    pub unpack_version: u8,
    /// 0x30 stored to 0x35 best.
    pub method: u8,
    pub attributes: u32,
    /// The name field as stored: a legacy (OEM) name, or under [`LHD_UNICODE`] the legacy name, a NUL and the
    /// encoded Unicode name ([`unicode_name_field`]). Directories are separated by backslashes.
    pub name: Vec<u8>,
    /// The 8-byte salt present under [`LHD_SALT`].
    pub salt: Option<[u8; 8]>,
    /// The extended time field present under [`LHD_EXTTIME`], whole (its 16-bit flags and the times).
    pub ext_time: Option<Vec<u8>>,
    /// Bytes after the known fields, kept as they are: a service header's SubData (the recovery record's tag), or
    /// a RAR 2.x file comment under [`LHD_COMMENT`] (not covered by the header checksum).
    pub rest: Vec<u8>,
}

impl FileHeader {
    /// Parses the file or service header at the start of `header` (its bytes up to `HEAD_SIZE`; checksum checked).
    pub fn parse(header: &[u8]) -> Result<FileHeader> {
        let b = read_block(header, 0)?.ok_or(Error::Truncated)?;
        if b.head_type != HEAD_FILE && b.head_type != HEAD_SERVICE {
            return Err(Error::Corrupt("not a RAR 4.x file header"));
        }
        let h = &header[..b.header_end];
        let mut f = Fields { bytes: h, at: 7 };
        let mut packed_size = u64::from(f.u32()?);
        let mut unpacked_size = u64::from(f.u32()?);
        let host_os = f.byte()?;
        let crc = f.u32()?;
        let dos_time = f.u32()?;
        let unpack_version = f.byte()?;
        let method = f.byte()?;
        let name_len = usize::from(f.u16()?);
        let attributes = f.u32()?;
        if b.flags & LHD_LARGE != 0 {
            packed_size |= u64::from(f.u32()?) << 32;
            unpacked_size |= u64::from(f.u32()?) << 32;
        }
        let name = f.take(name_len)?.to_vec();
        let salt = if b.flags & LHD_SALT != 0 { Some(f.take(8)?.try_into().unwrap()) } else { None };
        let ext_time = if b.flags & LHD_EXTTIME != 0 {
            let start = f.at;
            let times = f.u16()?;
            for index in 0..4u16 {
                let mode = (times >> ((3 - index) * 4)) & 15;
                if mode & 8 == 0 {
                    continue;
                }
                if index != 0 {
                    f.u32()?;
                }
                f.take(usize::from(mode & 3))?;
            }
            Some(h[start..f.at].to_vec())
        } else {
            None
        };
        Ok(FileHeader {
            head_type: b.head_type,
            flags: b.flags,
            packed_size,
            unpacked_size,
            host_os,
            crc,
            dos_time,
            unpack_version,
            method,
            attributes,
            name,
            salt,
            ext_time,
            rest: h[f.at..].to_vec(),
        })
    }

    /// The header block. Fails when a size needs more than 32 bits without [`LHD_LARGE`], [`Self::salt`] or
    /// [`Self::ext_time`] disagrees with its flag, or the name is longer than 65,535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bad = |what: &str| Error::Unsupported(format!("RAR 4.x file header: {what}"));
        let large = self.flags & LHD_LARGE != 0;
        if !large && (self.packed_size > u64::from(u32::MAX) || self.unpacked_size > u64::from(u32::MAX)) {
            return Err(bad("a size over 4 GiB needs LHD_LARGE"));
        }
        if self.salt.is_some() != (self.flags & LHD_SALT != 0) {
            return Err(bad("salt and flag disagree"));
        }
        if self.ext_time.is_some() != (self.flags & LHD_EXTTIME != 0) {
            return Err(bad("extended time and flag disagree"));
        }
        let name_len = u16::try_from(self.name.len()).map_err(|_| bad("a name over 64 KiB"))?;
        let mut fields = Vec::with_capacity(40 + self.name.len());
        fields.extend_from_slice(&(self.packed_size as u32).to_le_bytes());
        fields.extend_from_slice(&(self.unpacked_size as u32).to_le_bytes());
        fields.push(self.host_os);
        fields.extend_from_slice(&self.crc.to_le_bytes());
        fields.extend_from_slice(&self.dos_time.to_le_bytes());
        fields.push(self.unpack_version);
        fields.push(self.method);
        fields.extend_from_slice(&name_len.to_le_bytes());
        fields.extend_from_slice(&self.attributes.to_le_bytes());
        if large {
            fields.extend_from_slice(&((self.packed_size >> 32) as u32).to_le_bytes());
            fields.extend_from_slice(&((self.unpacked_size >> 32) as u32).to_le_bytes());
        }
        fields.extend_from_slice(&self.name);
        if let Some(salt) = &self.salt {
            fields.extend_from_slice(salt);
        }
        if let Some(ext) = &self.ext_time {
            fields.extend_from_slice(ext);
        }
        fields.extend_from_slice(&self.rest);
        block(self.head_type, self.flags | LONG_BLOCK, &fields)
    }
}

/// The end of archive block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndOfArchive {
    /// [`EARC_NEXT_VOLUME`], [`EARC_DATACRC`], [`EARC_REVSPACE`], [`EARC_VOLNUMBER`], and [`SKIP_IF_UNKNOWN`] as
    /// rar sets it.
    pub flags: u16,
    /// Under [`EARC_DATACRC`]: the CRC32 of the volume's bytes before this block.
    pub data_crc: Option<u32>,
    /// Under [`EARC_VOLNUMBER`]: the volume's number, 0-based.
    pub volume_number: Option<u16>,
}

impl EndOfArchive {
    /// The 7-byte block of an archive or volume without volume fields (rar 2.x and 3.x before volume numbers),
    /// "next volume" set when `next_volume`.
    pub fn new(next_volume: bool) -> EndOfArchive {
        EndOfArchive {
            flags: SKIP_IF_UNKNOWN | if next_volume { EARC_NEXT_VOLUME } else { 0 },
            data_crc: None,
            volume_number: None,
        }
    }

    /// The 20-byte block WinRAR 3.x and later end a volume with: "next volume" when `next_volume`, the CRC32 of the
    /// volume's bytes before the block (`data_crc`), the volume number and 7 reserved zero bytes.
    pub fn volume(next_volume: bool, data_crc: u32, volume_number: u16) -> EndOfArchive {
        EndOfArchive {
            flags: SKIP_IF_UNKNOWN
                | EARC_DATACRC
                | EARC_REVSPACE
                | EARC_VOLNUMBER
                | if next_volume { EARC_NEXT_VOLUME } else { 0 },
            data_crc: Some(data_crc),
            volume_number: Some(volume_number),
        }
    }

    /// Parses the end block at the start of `header` (checksum checked). Reserved bytes must be zero.
    pub fn parse(header: &[u8]) -> Result<EndOfArchive> {
        let b = read_block(header, 0)?.ok_or(Error::Truncated)?;
        if b.head_type != HEAD_END {
            return Err(Error::Corrupt("not a RAR 4.x end of archive block"));
        }
        let h = &header[..b.header_end];
        let mut f = Fields { bytes: h, at: 7 };
        let data_crc = if b.flags & EARC_DATACRC != 0 { Some(f.u32()?) } else { None };
        let volume_number = if b.flags & EARC_VOLNUMBER != 0 { Some(f.u16()?) } else { None };
        if b.flags & EARC_REVSPACE != 0 && f.take(7)?.iter().any(|&c| c != 0) {
            return Err(Error::Unsupported("RAR 4.x end of archive block with reserved data".into()));
        }
        if f.at != h.len() {
            return Err(Error::Unsupported("RAR 4.x end of archive block with unknown fields".into()));
        }
        Ok(EndOfArchive { flags: b.flags, data_crc, volume_number })
    }

    /// The block. Fails when a field disagrees with its flag.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.data_crc.is_some() != (self.flags & EARC_DATACRC != 0)
            || self.volume_number.is_some() != (self.flags & EARC_VOLNUMBER != 0)
        {
            return Err(Error::Unsupported("RAR 4.x end of archive block: a field and its flag disagree".into()));
        }
        let mut fields = Vec::with_capacity(13);
        if let Some(crc) = self.data_crc {
            fields.extend_from_slice(&crc.to_le_bytes());
        }
        if let Some(number) = self.volume_number {
            fields.extend_from_slice(&number.to_le_bytes());
        }
        if self.flags & EARC_REVSPACE != 0 {
            fields.extend_from_slice(&[0; 7]);
        }
        block(HEAD_END, self.flags & !LONG_BLOCK, &fields)
    }
}

/// A file header's name field for `name` ('/' or '\\' separating directories) and whether it needs
/// [`LHD_UNICODE`]: an ASCII name as it is (with backslashes), any other as a legacy name (each non-ASCII character
/// as '_'), a NUL, and the Unicode name in RAR's compact encoding, which any RAR 3.x+ reader decodes. (WinRAR's own
/// encoder picks other, equally valid, codes, so its field for the same name can differ.)
pub fn unicode_name_field(name: &str) -> (Vec<u8>, bool) {
    let mapped: String = name.chars().map(|c| if c == '/' { '\\' } else { c }).collect();
    if mapped.is_ascii() {
        return (mapped.into_bytes(), false);
    }
    let units: Vec<u16> = mapped.encode_utf16().collect();
    let mut field: Vec<u8> =
        mapped.chars().flat_map(|c| if c.is_ascii() { vec![c as u8] } else { vec![b'_'; c.len_utf16()] }).collect();
    field.push(0);
    // The high byte shared by most units above 0xff: those take one byte each.
    let mut counts = std::collections::HashMap::<u8, usize>::new();
    for &u in units.iter().filter(|&&u| u > 0xff) {
        *counts.entry((u >> 8) as u8).or_default() += 1;
    }
    let high = counts.into_iter().max_by_key(|&(h, n)| (n, std::cmp::Reverse(h))).map_or(0, |(h, _)| h);
    field.push(high);
    for chunk in units.chunks(4) {
        let mut flags = 0u8;
        let mut ops = Vec::with_capacity(8);
        for (i, &u) in chunk.iter().enumerate() {
            let code = if u <= 0xff {
                ops.push(u as u8);
                0
            } else if (u >> 8) as u8 == high {
                ops.push(u as u8);
                1
            } else {
                ops.extend_from_slice(&u.to_le_bytes());
                2
            };
            flags |= code << (6 - 2 * i);
        }
        field.push(flags);
        field.extend_from_slice(&ops);
    }
    (field, true)
}

struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end =
            self.at.checked_add(n).filter(|&e| e <= self.bytes.len()).ok_or(Error::Corrupt("RAR 4.x header field"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_blocks_match_rar() {
        // multi_newnaming_rar300 part 1 (7 bytes, next volume) and part 2 (last).
        let next = EndOfArchive::new(true).encode().unwrap();
        assert_eq!(&next[2..], [0x7b, 0x01, 0x40, 0x07, 0x00]);
        assert_eq!(EndOfArchive::parse(&next).unwrap(), EndOfArchive::new(true));
        let last = EndOfArchive::new(false).encode().unwrap();
        assert_eq!(&last[2..], [0x7b, 0x00, 0x40, 0x07, 0x00]);
        // WinRAR's volume block: rarinfo multi.part1.rar.
        let vol = EndOfArchive::volume(true, 0x4d51_3221, 0).encode().unwrap();
        assert_eq!(vol.len(), 20);
        assert_eq!(&vol[2..7], [0x7b, 0x0f, 0x40, 0x14, 0x00]);
        assert_eq!(&vol[7..13], [0x21, 0x32, 0x51, 0x4d, 0x00, 0x00]);
    }

    #[test]
    fn hostile_blocks_never_panic() {
        let mut state = 0x2545_f491u32;
        for _ in 0..20_000 {
            let len = (state % 64) as usize;
            let mut bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            if bytes.len() >= 7 {
                let size = bytes.len() as u16;
                bytes[5..7].copy_from_slice(&size.to_le_bytes());
                bytes[2] = [HEAD_MAIN, HEAD_FILE, HEAD_SERVICE, HEAD_END][(state % 4) as usize];
                let _ = seal(&mut bytes);
            }
            let _ = read_block(&bytes, 0);
            let _ = MainHeader::parse(&bytes);
            let _ = FileHeader::parse(&bytes);
            let _ = EndOfArchive::parse(&bytes);
        }
    }
}
