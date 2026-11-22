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

//! Reading and writing RAR header blocks byte for byte: the pieces a caller needs to rebuild or patch a volume's
//! headers (a volume number, a part checksum, an end-of-archive flag) without its own copy of the format.
//!
//! RAR 5.0: [`put_vint`] / [`put_vint_min`] / [`read_vint`] for the variable length integers, [`seal_header`] for a
//! block's CRC32 and size, [`read_block`] to walk blocks, [`MainHeader`] for the main archive header and
//! [`end_of_archive`] for the end header. RAR 1.5 to 4.x: the [`rar4`] module.
//!
//! See `docs/rar-frames.md`. Written from the RAR 5.0 and RAR 1.5-4.x archive format descriptions and checked
//! against rar- and WinRAR-made archives.

pub mod rar4;

use crate::error::{Error, Result};
use std::ops::Range;

/// The RAR 5.0 signature.
pub const SIGNATURE: &[u8; 8] = super::SIGNATURE;

/// The longest RAR 5.0 variable length integer: ten bytes hold 64 bits.
pub const MAX_VINT_LEN: usize = 10;

/// Appends `value` as a RAR 5.0 variable length integer in as few bytes as it takes: seven bits per byte, low bits
/// first, the high bit set on every byte but the last.
pub fn put_vint(out: &mut Vec<u8>, value: u64) {
    put_vint_min(out, value, 1);
}

/// Appends `value` as a RAR 5.0 variable length integer of at least `min_len` bytes, padding with continuation
/// bytes (`0x80`, then a final `0x00`), as rar writes fields it fills in later (the locator's quick open offset, the
/// quick open header's data size). `min_len` past [`MAX_VINT_LEN`] is treated as [`MAX_VINT_LEN`].
pub fn put_vint_min(out: &mut Vec<u8>, mut value: u64, min_len: usize) {
    let min_len = min_len.clamp(1, MAX_VINT_LEN);
    let mut written = 0;
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        written += 1;
        if value == 0 && written >= min_len {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// How many bytes [`put_vint`] writes for `value`.
pub fn vint_len(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7).max(1)
}

/// Reads the variable length integer at `at`: its value and how many bytes it took (padding included). `None` when
/// `bytes` ends inside it, it is longer than ten bytes, or it overflows 64 bits.
pub fn read_vint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..MAX_VINT_LEN {
        let b = *bytes.get(at.checked_add(i)?)?;
        if i == MAX_VINT_LEN - 1 && b > 1 {
            return None;
        }
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// A RAR 5.0 header block from its fields (type, flags and on, everything the header size counts): the CRC32 of
/// the size and fields, the size as a minimal variable length integer, then the fields.
pub fn seal_header(fields: &[u8]) -> Vec<u8> {
    let mut sized = Vec::with_capacity(fields.len() + 4);
    put_vint(&mut sized, fields.len() as u64);
    sized.extend_from_slice(fields);
    let mut out = Vec::with_capacity(sized.len() + 4);
    out.extend_from_slice(&crate::crc32::hash(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out
}

/// Recomputes the CRC32 of the header block at the start of `block` in place, after a field in it was patched to a
/// value of the same width. Fails when `block` does not hold a whole header.
pub fn reseal_header(block: &mut [u8]) -> Result<()> {
    let (size, size_len) = read_vint(block, 4).ok_or(Error::Truncated)?;
    let end = usize::try_from(size)
        .ok()
        .and_then(|s| (4 + size_len).checked_add(s))
        .filter(|&e| e <= block.len())
        .ok_or(Error::Truncated)?;
    let crc = crate::crc32::hash(&block[4..end]);
    block[..4].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// One RAR 5.0 header block as [`read_block`] found it. Ranges are offsets into the bytes it was read from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Where the block starts (its CRC32).
    pub offset: usize,
    /// The header type: 1 main, 2 file, 3 service, 4 encryption, 5 end of archive.
    pub kind: u64,
    /// The header flags: 0x1 extra area, 0x2 data area, 0x4 skip if unknown, 0x8 continues from the previous
    /// volume, 0x10 continues in the next.
    pub flags: u64,
    /// The type-specific fields: after the type, flags, extra area size and data size, up to the extra area.
    pub fields: Range<usize>,
    /// The extra area (empty when the header has none).
    pub extra: Range<usize>,
    /// The size of the data area that follows the header (0 without one).
    pub data_len: u64,
    /// Where the header ends and its data area starts.
    pub header_end: usize,
}

impl Block {
    /// Where the data area ends: the next block's offset. `None` when that overflows.
    pub fn data_end(&self) -> Option<u64> {
        (self.header_end as u64).checked_add(self.data_len)
    }

    /// The whole header block, CRC32 included.
    pub fn header<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.offset..self.header_end]
    }
}

/// The longest header [`read_block`] accepts (the format's own limit, 2 MiB).
pub const MAX_HEADER: u64 = super::MAX_HEADER;

/// Reads the header block at `at`. `Ok(None)` when `bytes` ends inside it; an error when its CRC32 fails
/// ([`Error::Corrupt`]) or its sizes are impossible. Its data area is not read and need not be present.
pub fn read_block(bytes: &[u8], at: usize) -> Result<Option<Block>> {
    if bytes.len().saturating_sub(at) < 5 {
        return Ok(None);
    }
    let Some((size, size_len)) = read_vint(bytes, at + 4) else {
        return if bytes.len() - at - 4 < MAX_VINT_LEN { Ok(None) } else { Err(Error::Corrupt("RAR 5.0 header size")) };
    };
    if size == 0 || size > MAX_HEADER {
        return Err(Error::Corrupt("RAR 5.0 header size"));
    }
    let start = at + 4 + size_len;
    let Some(end) = start.checked_add(size as usize).filter(|&e| e <= bytes.len()) else { return Ok(None) };
    let crc = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    if crate::crc32::hash(&bytes[at + 4..end]) != crc {
        return Err(Error::Corrupt("RAR 5.0 header checksum"));
    }
    let header = &bytes[start..end];
    let mut c = super::Cursor::new(header);
    let kind = c.vint()?;
    let flags = c.vint()?;
    let extra_len = if flags & super::HFL_EXTRA != 0 { c.vint()? } else { 0 };
    let data_len = if flags & super::HFL_DATA != 0 { c.vint()? } else { 0 };
    let fields_start = start + c.pos();
    let extra_len = usize::try_from(extra_len)
        .ok()
        .filter(|&e| e <= end - fields_start)
        .ok_or(Error::Corrupt("RAR 5.0 extra area size"))?;
    Ok(Some(Block {
        offset: at,
        kind,
        flags,
        fields: fields_start..end - extra_len,
        extra: end - extra_len..end,
        data_len,
        header_end: end,
    }))
}

/// The end of archive header, as rar writes it: header flags "skip if unknown" and the end flags with "more volumes"
/// set when `more_volumes`.
pub fn end_of_archive(more_volumes: bool) -> Vec<u8> {
    let mut fields = Vec::with_capacity(3);
    put_vint(&mut fields, super::HEAD_END);
    put_vint(&mut fields, 0x4); // skip if unknown
    put_vint(&mut fields, u64::from(more_volumes) * super::EOAFL_MORE_VOLUMES);
    seal_header(&fields)
}

/// The main archive header's locator record: where the quick open and recovery record headers are, as offsets
/// from the main header's start, and how wide rar wrote each (it pads them to fill in later).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Locator {
    /// The quick open service header's offset from the main header, and its field's width in bytes. Rar writes 0
    /// when the volume has no quick open data.
    pub quick_open: Option<(u64, usize)>,
    /// The recovery record header's offset from the main header, and its field's width.
    pub recovery: Option<(u64, usize)>,
}

/// A RAR 5.0 main archive header, field by field, so it can be patched and written back byte for byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainHeader {
    /// The header flags (rar writes 0x5: an extra area, skip if unknown; 0x4 without an extra area).
    pub header_flags: u64,
    /// The archive flags: 0x1 volume, 0x2 volume number present, 0x4 solid, 0x8 recovery record, 0x10 locked.
    /// [`Self::encode`] sets or clears 0x2 to match [`Self::volume_number`].
    pub archive_flags: u64,
    /// The volume number, present from the second volume on (0-based: the second volume is 1).
    pub volume_number: Option<u64>,
    /// The locator record, if the header has one.
    pub locator: Option<Locator>,
    /// The extra records other than the locator, each whole (size, type and data), kept in order. The locator is
    /// written first, as rar does, then these.
    pub other_extra: Vec<Vec<u8>>,
}

impl MainHeader {
    /// Parses the main header block at the start of `block` (after the signature). Fails unless it is one, with a
    /// sound CRC32.
    pub fn parse(block: &[u8]) -> Result<MainHeader> {
        let b = read_block(block, 0)?.ok_or(Error::Truncated)?;
        if b.kind != super::HEAD_MAIN {
            return Err(Error::Corrupt("not a RAR 5.0 main header"));
        }
        if b.data_len != 0 {
            return Err(Error::Corrupt("RAR 5.0 main header with a data area"));
        }
        let mut c = super::Cursor::new(&block[b.fields.clone()]);
        let archive_flags = c.vint()?;
        let volume_number = if archive_flags & super::MHFL_VOLNUMBER != 0 { Some(c.vint()?) } else { None };
        if c.remaining() != 0 {
            return Err(Error::Corrupt("RAR 5.0 main header fields"));
        }
        let mut locator = None;
        let mut other_extra = Vec::new();
        let extra = &block[b.extra.clone()];
        let mut at = 0;
        while at < extra.len() {
            let (size, size_len) = read_vint(extra, at).ok_or(Error::Corrupt("RAR 5.0 extra record"))?;
            let end = usize::try_from(size)
                .ok()
                .and_then(|s| (at + size_len).checked_add(s))
                .filter(|&e| e <= extra.len() && size > 0)
                .ok_or(Error::Corrupt("RAR 5.0 extra record"))?;
            let record = &extra[at + size_len..end];
            let (kind, kind_len) = read_vint(record, 0).ok_or(Error::Corrupt("RAR 5.0 extra record"))?;
            if kind == super::MHEXTRA_LOCATOR && locator.is_none() {
                let mut p = kind_len;
                let (flags, n) = read_vint(record, p).ok_or(Error::Corrupt("RAR 5.0 locator"))?;
                p += n;
                let mut field = |present: bool| -> Result<Option<(u64, usize)>> {
                    if !present {
                        return Ok(None);
                    }
                    let (v, n) = read_vint(record, p).ok_or(Error::Corrupt("RAR 5.0 locator"))?;
                    p += n;
                    Ok(Some((v, n)))
                };
                let quick_open = field(flags & 0x1 != 0)?;
                let recovery = field(flags & 0x2 != 0)?;
                if p != record.len() || flags & !0x3 != 0 {
                    // A locator with fields this does not know: kept whole so it is written back as it was.
                    other_extra.push(extra[at..end].to_vec());
                } else {
                    locator = Some(Locator { quick_open, recovery });
                    if !other_extra.is_empty() {
                        // rar writes the locator first; one after other records could not be written back in place.
                        return Err(Error::Unsupported("a RAR 5.0 locator after other extra records".into()));
                    }
                }
            } else {
                other_extra.push(extra[at..end].to_vec());
            }
            at = end;
        }
        Ok(MainHeader { header_flags: b.flags, archive_flags, volume_number, locator, other_extra })
    }

    /// The header block, CRC32 and size included. The extra area flag in [`Self::header_flags`] is set when there
    /// are extra records and cleared otherwise; the data area flag is always cleared.
    pub fn encode(&self) -> Vec<u8> {
        let mut extra = Vec::new();
        if let Some(locator) = &self.locator {
            let mut record = Vec::new();
            put_vint(&mut record, super::MHEXTRA_LOCATOR);
            let flags = u64::from(locator.quick_open.is_some()) | (u64::from(locator.recovery.is_some()) << 1);
            put_vint(&mut record, flags);
            for (value, width) in [locator.quick_open, locator.recovery].into_iter().flatten() {
                put_vint_min(&mut record, value, width);
            }
            put_vint(&mut extra, record.len() as u64);
            extra.extend_from_slice(&record);
        }
        for record in &self.other_extra {
            extra.extend_from_slice(record);
        }
        let mut header_flags = self.header_flags & !super::HFL_DATA;
        if extra.is_empty() {
            header_flags &= !super::HFL_EXTRA;
        } else {
            header_flags |= super::HFL_EXTRA;
        }
        let mut fields = Vec::new();
        put_vint(&mut fields, super::HEAD_MAIN);
        put_vint(&mut fields, header_flags);
        if !extra.is_empty() {
            put_vint(&mut fields, extra.len() as u64);
        }
        let archive_flags = match self.volume_number {
            Some(_) => self.archive_flags | super::MHFL_VOLNUMBER,
            None => self.archive_flags & !super::MHFL_VOLNUMBER,
        };
        put_vint(&mut fields, archive_flags);
        if let Some(number) = self.volume_number {
            put_vint(&mut fields, number);
        }
        fields.extend_from_slice(&extra);
        seal_header(&fields)
    }

    /// The header of volume `index` (0-based) of the same set: the volume number set as rar writes it (none for the
    /// first volume) and everything else kept. The locator's offsets describe this header's volume: set them for
    /// the other volume separately.
    pub fn for_volume(&self, index: u64) -> MainHeader {
        MainHeader { volume_number: (index > 0).then_some(index), ..self.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vints_round_trip_and_pad() {
        for value in [0u64, 1, 127, 128, 16_383, 16_384, u32::MAX as u64, u64::MAX] {
            let mut out = Vec::new();
            put_vint(&mut out, value);
            assert_eq!(out.len(), vint_len(value), "{value}");
            assert_eq!(read_vint(&out, 0), Some((value, out.len())));
            for min in 1..=MAX_VINT_LEN {
                let mut padded = Vec::new();
                put_vint_min(&mut padded, value, min);
                assert_eq!(padded.len(), vint_len(value).max(min));
                assert_eq!(read_vint(&padded, 0), Some((value, padded.len())));
            }
        }
        assert_eq!(read_vint(&[0x80; 10], 0), None);
        assert_eq!(read_vint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02], 0), None);
        assert_eq!(read_vint(&[0x80], 0), None);
    }

    #[test]
    fn the_end_of_archive_header_matches_rar() {
        assert_eq!(end_of_archive(true), [0x8b, 0x47, 0x51, 0x26, 0x03, 0x05, 0x04, 0x01]);
        let last = end_of_archive(false);
        assert_eq!(&last[4..], [0x03, 0x05, 0x04, 0x00]);
        assert!(read_block(&last, 0).unwrap().is_some());
    }

    #[test]
    fn a_main_header_round_trips_and_moves_to_another_volume() {
        // rar 7.30 `qo-plus/set.part2.rar`: volume 1, locator with a 5-byte quick open offset.
        let bytes = [
            0x2e, 0xd5, 0x9b, 0x10, 0x0d, 0x01, 0x05, 0x08, 0x03, 0x01, 0x07, 0x01, 0x01, 0x9d, 0x9f, 0x86, 0x80, 0x00,
        ];
        let main = MainHeader::parse(&bytes).unwrap();
        assert_eq!(main.volume_number, Some(1));
        assert_eq!(main.locator.unwrap().quick_open.unwrap().1, 5);
        assert_eq!(main.encode(), bytes);
        let first = main.for_volume(0).encode();
        let reparsed = MainHeader::parse(&first).unwrap();
        assert_eq!((reparsed.volume_number, reparsed.archive_flags), (None, 0x1));
        assert_eq!(first.len(), bytes.len() - 1);
    }

    #[test]
    fn hostile_blocks_are_refused_without_panics() {
        assert!(read_block(&[], 0).unwrap().is_none());
        assert!(read_block(&[0, 0, 0, 0, 0], 0).is_err());
        let mut good = end_of_archive(true);
        good[5] ^= 1;
        assert!(read_block(&good, 0).is_err());
        assert!(MainHeader::parse(&end_of_archive(false)).is_err());
        let mut state = 0x1234_5678u32;
        for _ in 0..20_000 {
            let len = (state % 40) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            let _ = read_block(&bytes, 0);
            let _ = MainHeader::parse(&bytes);
            let mut copy = bytes.clone();
            let _ = reseal_header(&mut copy);
        }
    }
}
