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

//! RAR4 framing from the documented fixed fields and independent fixtures.

use super::*;
use crate::error::RarUnsupported;
use crate::rar5::session::{ScanBudget, allocation};

impl HeaderParser {
    fn rar4_header(&self) -> &[u8] {
        if matches!(self.phase, Phase::LegacyBody) { &self.buffer[8..8 + self.size] } else { &self.buffer[..] }
    }
    fn rar4_mismatch(&self) -> bool {
        let header = self.rar4_header();
        self.rar4_crc_end(header)
            .is_some_and(|end| crate::crc32::hash(&header[2..end]) as u16 != u16::from_le_bytes([header[0], header[1]]))
    }
    pub(super) fn parse_rar4(
        &mut self,
        budget: Option<&ScanBudget<'_>>,
    ) -> std::result::Result<PhysicalFrame, FramingError> {
        // DamagedInput::Salvage: a clear header that fails its checksum is read as it stands, as UnRAR does; a
        // feature it then seems to use is damage, not something unsupported.
        let damaged = self.salvage && !self.legacy_headers && self.rar4_mismatch();
        self.parse_rar4_checked(budget, damaged).map_err(|error| match error {
            FramingError::Rar(fault) if damaged && matches!(*fault.failure, RarFailure::Unsupported(_)) => {
                self.framing("damaged RAR4 header", Error::Corrupt("damaged RAR4 header")).into()
            }
            other => other,
        })
    }
    fn parse_rar4_checked(
        &mut self,
        budget: Option<&ScanBudget<'_>>,
        damaged: bool,
    ) -> std::result::Result<PhysicalFrame, FramingError> {
        let mismatch = !damaged && self.rar4_mismatch();
        let header =
            if matches!(self.phase, Phase::LegacyBody) { &self.buffer[8..8 + self.size] } else { &self.buffer[..] };
        let kind = header[2];
        let flags = u16::from_le_bytes([header[3], header[4]]);
        let size = header.len();
        if mismatch {
            return Err(self
                .fault(RarIntegrityReason::HeaderCrc, Error::BadChecksum("RAR4 header CRC".into()), true)
                .into());
        }
        if self.embedded_comment(kind, flags) {
            return Err(self.rar4_unsupported("embedded comment").into());
        }
        let mut cursor = Fields::new(header, 7);
        // Map walks follow unrar's ReadHeader15 on which blocks have data after the header: the old subblock (0x77)
        // and old recovery record (0x78) always start with its size, the main, old comment and end headers never
        // have any, and every other block has it exactly when LONG_BLOCK is set. A salvaging run sizes the old-style
        // blocks the same way, as UnRAR 7.30 was seen to pass them over; 7-Zip 26.06 (and everything else) goes by
        // LONG_BLOCK alone.
        let unrar_sizes = self.map_lenient || self.salvage;
        let sized = match kind {
            0x77 | 0x78 if unrar_sizes => true,
            0x75 if unrar_sizes => false,
            0x73 | 0x7b if self.map_lenient => false,
            _ => flags & 0x8000 != 0,
        };
        let packed = if sized { u64::from(cursor.u32().map_err(|e| self.parse_fault(e))?) } else { 0 };
        let data_at = self
            .at
            .checked_add(self.need as u64)
            .ok_or_else(|| self.framing("RAR4 header size", Error::Corrupt("RAR4 header size")))?;
        let data_end = data_at
            .checked_add(packed)
            .ok_or_else(|| self.framing("RAR4 data size", Error::Corrupt("RAR4 data size")))?;
        let mut frame = PhysicalFrame {
            block: Block::Unknown,
            crypt: None,
            wire: None,
            extent: self.at..data_at,
            data_end,
            header_crypt: None,
            end_record: None,
            damaged,
        };
        frame.block = match kind {
            0x73 => {
                if self.rar4_main.is_some() {
                    return Err(self
                        .framing("duplicate RAR4 main header", Error::Corrupt("duplicate RAR4 main header"))
                        .into());
                }
                // MHD_ENCRYPTVER (0x200) adds a byte: the version of the header encryption. A map walk also accepts
                // a longer header (a RAR 2.x embedded comment, or fields it does not know) and ignores the rest.
                let fixed = 13 + usize::from(flags & 0x200 != 0);
                // A catalogue keeps a RAR 2.x comment block (`COMM_HEAD`, 13 bytes and the comment) for
                // `RarSession::comment`; it is decoded only when asked for.
                let comment = self.catalogue_main_comment(flags);
                if comment && size < 13 + 13 {
                    return Err(self.framing("RAR4 comment header size", Error::Corrupt("RAR4 comment size")).into());
                }
                if (self.map_lenient && size < fixed) || (!self.map_lenient && !comment && size != 13 && size != fixed)
                {
                    return Err(self.framing("RAR4 main header size", Error::Corrupt("RAR4 main header size")).into());
                }
                if flags & 0x80 != 0 {
                    // RAR 3.x headers are always encrypted the RAR 2.9 way; unrar 3.x refuses a version above its
                    // own (36) and unrar 5 ignores the byte. Map walks accept what unrar 3.x accepts.
                    if flags & 0x200 != 0 && !(self.map_lenient && header[13] <= 36) {
                        return Err(self.rar4_unsupported("header encryption version").into());
                    }
                    self.legacy_headers = true;
                }
                let mut normalized = 0;
                if flags & 1 != 0 {
                    normalized |= MHFL_VOLUME;
                }
                if flags & 8 != 0 {
                    normalized |= MHFL_SOLID;
                }
                let embedded_comment = if comment {
                    let block = &header[13..];
                    let mut kept = Vec::new();
                    kept.try_reserve_exact(block.len()).map_err(|_| allocation())?;
                    kept.extend_from_slice(block);
                    Some(kept)
                } else {
                    None
                };
                let main = MainHeader {
                    embedded_comment,
                    flags: normalized,
                    volume_number: 0,
                    rar4_flags: Some(flags),
                    ..MainHeader::default()
                };
                self.rar4_main = Some(main.clone());
                Block::Main(main)
            }
            0x74 | 0x7a => {
                if flags & 0x8000 == 0 {
                    return Err(self.framing("RAR4 file data flag", Error::Corrupt("RAR4 file data flag")).into());
                }
                if let Some(budget) = budget
                    && let Some(size) = header.get(26..28)
                {
                    budget.names(u64::from(u16::from_le_bytes([size[0], size[1]])))?;
                }
                let (file, wire) = self.rar4_file(header, flags, packed, data_at, budget)?;
                frame.data_end = file
                    .data_at
                    .checked_add(file.packed_size)
                    .ok_or_else(|| self.framing("RAR4 data size", Error::Corrupt("RAR4 data size")))?;
                frame.wire = Some(wire);
                if kind == 0x74 { Block::File(file) } else { Block::Service(file) }
            }
            0x7b => {
                let expected = 7
                    + usize::from(flags & 2 != 0) * 4
                    + usize::from(flags & 4 != 0) * 7
                    + usize::from(flags & 8 != 0) * 2;
                // A map walk takes any size, as unrar does: bytes past the fields are ignored, and a field the header
                // is too short to hold is absent.
                if size != expected && !self.map_lenient {
                    return Err(self
                        .framing("RAR4 end header fields", Error::Corrupt("RAR4 end header fields"))
                        .into());
                }
                // EARC_VOLNUMBER: a 16-bit volume number after the optional data CRC.
                let at = 7 + usize::from(flags & 2 != 0) * 4;
                let volume_number = (flags & 8 != 0)
                    .then(|| header.get(at..at + 2))
                    .flatten()
                    .map(|n| u64::from(u16::from_le_bytes([n[0], n[1]])));
                let data_crc = (flags & 2 != 0)
                    .then(|| header.get(7..11))
                    .flatten()
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
                frame.end_record = Some(crate::rar5::RarEndRecord {
                    flags: u64::from(flags),
                    data_crc,
                    volume_number,
                    offset: self.at,
                });
                Block::End { more_volumes: flags & 1 != 0, volume_number }
            }
            // Old comment, AV, old subblock, old recovery record and sign blocks hold no members. A map walk skips
            // them by their declared sizes, already bounded above, like unknown blocks marked skippable.
            0x75..=0x79 if self.map_lenient => Block::Unknown,
            // A damaged header of a type that holds no member is passed over by its size, as UnRAR does.
            0x75..=0x79 if damaged && !self.resync => Block::Unknown,
            _ if damaged && self.resync => {
                return Err(self.framing("damaged RAR4 header", Error::Corrupt("damaged RAR4 header")).into());
            }
            _ if damaged && !matches!(kind, 0x73 | 0x74 | 0x7a | 0x7b) => Block::Unknown,
            // UnRAR 7.30 and 7-Zip 26.06 pass a sound old-style block over too.
            0x75..=0x79 if self.salvage || self.legacy_unchecked => Block::Unknown,
            0x75..=0x79 => return Err(self.rar4_unsupported("legacy service block").into()),
            _ if flags & 0x4000 != 0 => Block::Unknown,
            _ => return Err(self.rar4_unsupported("header type").into()),
        };
        if self.complete_len.is_some_and(|len| frame.data_end > len) {
            return Err(self.fault(RarIntegrityReason::TruncatedData, Error::Truncated, false).into());
        }
        Ok(frame)
    }
    /// Where a header's CRC ends, None when it is not checked. Map walks follow unrar's `ReadHeader15`: a main header
    /// with `MHD_COMMENT` is checked over its 13 fixed bytes only, a file header with `LHD_COMMENT` over the fields
    /// it parses (checked in `rar4_file`), and the AV, sign and Unix-owner old subblocks, which old versions wrote
    /// with a CRC not set properly, not at all. Encrypted headers are always checked whole: the CRC is what tells a
    /// wrong password.
    fn rar4_crc_end(&self, header: &[u8]) -> Option<usize> {
        let (kind, flags) = (header[2], u16::from_le_bytes([header[3], header[4]]));
        if self.catalogue_main_comment(flags) && kind == 0x73 {
            // As RAR 2.x writes it and UnRAR checks it, the CRC covers the fixed fields before the comment.
            return Some(header.len().min(13));
        }
        if self.legacy_headers {
            return Some(header.len());
        }
        // The old-style blocks, as observed: 7-Zip 26.06 checks none of them (DamagedInput::SevenZip), UnRAR 7.30
        // (salvaging runs) not the AV (0x76) and sign (0x79) blocks.
        if ((0x75..=0x79).contains(&kind) && self.legacy_unchecked) || (matches!(kind, 0x76 | 0x79) && self.salvage) {
            return None;
        }
        if !self.map_lenient {
            return Some(header.len());
        }
        match kind {
            0x76 | 0x79 => None,
            // UO_HEAD (0x0101): the subtype after the data size.
            0x77 if header.get(11..13) == Some(&[0x01, 0x01]) => None,
            0x73 if flags & 2 != 0 => Some(header.len().min(13)),
            0x74 if flags & 8 != 0 => None,
            _ => Some(header.len()),
        }
    }
    /// A file header whose CRC covers only its parsed fields: one with a RAR 2.x comment, in a clear map walk.
    fn file_comment(&self, header: &[u8]) -> bool {
        self.map_lenient
            && !self.legacy_headers
            && header[2] == 0x74
            && u16::from_le_bytes([header[3], header[4]]) & 8 != 0
    }
    /// A RAR 2.x comment embedded in the main header (`MHD_COMMENT`) or a file header (`LHD_COMMENT`) that this
    /// parser refuses. Map walks accept both: the main header's comment lies past its fixed fields, and a file
    /// header's after the name, where unrar leaves it unread too.
    pub(super) fn embedded_comment(&self, kind: u8, flags: u16) -> bool {
        !self.map_lenient
            && ((kind == 0x73 && flags & 2 != 0 && !self.catalogue_main_comment(flags))
                || (kind == 0x74 && flags & 8 != 0))
    }
    /// A catalogue accepts a RAR 2.x comment embedded in a clear main header without `MHD_ENCRYPTVER`, which RAR
    /// 2.x never writes with one.
    fn catalogue_main_comment(&self, flags: u16) -> bool {
        self.catalogue && !self.map_lenient && flags & 0x0002 != 0 && flags & 0x0280 == 0
    }
    pub(super) fn rar4_unsupported(&self, feature: &'static str) -> RarFault {
        RarFault::new(
            RarFailure::Unsupported(RarUnsupported::Rar4Feature(feature)),
            Error::Unsupported(format!("RAR4 {feature}")),
        )
    }

    fn rar4_file(
        &self,
        bytes: &[u8],
        flags: u16,
        mut packed: u64,
        data_at: u64,
        budget: Option<&ScanBudget<'_>>,
    ) -> std::result::Result<(FileHeader, FileWire), FramingError> {
        let result: std::result::Result<_, FileParseError> = (|| {
            let mut fields = Fields::new(bytes, 11);
            let mut unpacked = u64::from(fields.u32()?);
            let host = fields.byte()?;
            let crc = fields.u32()?;
            let dos = fields.u32()?;
            let version = fields.byte()?;
            let method = fields.byte()?;
            let name_len = usize::from(fields.u16()?);
            let attributes = u64::from(fields.u32()?);
            if flags & 0x100 != 0 {
                packed |= u64::from(fields.u32()?) << 32;
                unpacked |= u64::from(fields.u32()?) << 32;
            }
            // As UnRAR reads it: all ones (both halves with the large-file flag) means the size is unknown.
            let size_unknown = if flags & 0x100 != 0 { unpacked == u64::MAX } else { unpacked == 0xffff_ffff };
            let encoded = fields.take(name_len)?;
            let name = match decode_name(encoded, flags & 0x200 != 0, self.map_lenient, self.usage.as_ref()) {
                // A legacy (OEM) name that is not UTF-8: a map walk lists it by its raw bytes, with an empty decoded
                // name, which no decoded name can be (see below).
                // Also a Unicode-flagged field that fell back to its legacy part (the bytes before the NUL).
                Err(FileParseError::Format(Error::Unsupported(_)))
                    if self.map_lenient && encoded.split(|&byte| byte == 0).next().is_some_and(|l| !l.is_empty()) =>
                {
                    String::new()
                }
                result => {
                    let name = result?;
                    if name.is_empty() || name.contains('\0') {
                        return Err(Error::Corrupt("RAR4 member name").into());
                    }
                    name
                }
            };
            let salt = if flags & 0x400 != 0 { Some(fields.take(8)?.try_into().unwrap()) } else { None };
            let mut mtime = dos_timestamp(dos);
            let mut nanos = 0;
            let mut resolution = 2_000_000_000;
            let mut other = [None; 2];
            if flags & 0x1000 != 0 {
                let times = fields.u16()?;
                for index in 0..4 {
                    let mode = (times >> ((3 - index) * 4)) & 15;
                    if mode & 8 == 0 {
                        continue;
                    }
                    let clock = if index == 0 { dos } else { fields.u32()? };
                    let mut seconds = dos_timestamp(clock);
                    if mode & 4 != 0 {
                        seconds = seconds.and_then(|value| value.checked_add(1));
                    }
                    let count = usize::from(mode & 3);
                    let fraction = fields
                        .take(count)?
                        .iter()
                        .enumerate()
                        .fold(0u32, |value, (index, &byte)| value | (u32::from(byte) << ((index + 3 - count) * 8)));
                    if fraction >= 10_000_000 {
                        return Err(Error::Corrupt("RAR4 extended time").into());
                    }
                    // Each omitted fraction byte coarsens the stored 100 ns step by 256.
                    let step = if count == 0 { 1_000_000_000 } else { 100u32 << ((3 - count) * 8) };
                    if index == 0 {
                        mtime = seconds;
                        nanos = fraction * 100;
                        resolution = step;
                    } else if index < 3
                        && let Some(seconds) = seconds
                    {
                        other[index - 1] =
                            Some(crate::rar5::RarTime { seconds, nanos: fraction * 100, resolution_nanos: step });
                    }
                }
            }
            if self.file_comment(bytes)
                && crate::crc32::hash(&bytes[2..fields.at]) as u16 != u16::from_le_bytes([bytes[0], bytes[1]])
            {
                return Err(Error::BadChecksum("RAR4 header CRC".into()).into());
            }
            // Bytes past the parsed fields of a service header are its SubData (the recovery record's "Protect+"
            // tag, the Unix owner names), which unrar keeps beside the header and this parser has no use for; the
            // header CRC above still covers them. A file header has no such field, so only a map walk ignores them.
            if fields.at != bytes.len() && !self.map_lenient && bytes[2] != 0x7a {
                return Err(Error::Unsupported("RAR4 trailing header fields".into()).into());
            }
            let mut sub_data = Vec::new();
            if bytes[2] == 0x7a && self.catalogue && self.usage.is_none() {
                let data = &bytes[fields.at..];
                sub_data.try_reserve_exact(data.len()).map_err(|_| FileParseError::Allocation)?;
                sub_data.extend_from_slice(data);
            }
            let directory = flags & 0xe0 == 0xe0;
            let normalized_host = match host {
                0..=2 => 0,
                3 => 1,
                _ => 2,
            };
            let header = FileHeader {
                format: RarFormat::Rar4,
                service: bytes[2] == 0x7a,
                sub_data,
                rar4: Some(Rar4Metadata {
                    flags,
                    host,
                    method,
                    unpack_version: version,
                    dos_time: dos,
                    salt,
                    stored_crc: crc,
                }),
                block_flags: (u64::from(flags & 1 != 0) * HFL_SPLIT_BEFORE)
                    | (u64::from(flags & 2 != 0) * HFL_SPLIT_AFTER),
                file_flags: (u64::from(directory) * FHFL_DIRECTORY)
                    | (u64::from(size_unknown && !directory) * FHFL_UNPUNKNOWN),
                packed_size: packed,
                data_at,
                unpacked_size: unpacked,
                attributes,
                mtime,
                mtime_nanos: nanos,
                mtime_resolution: if mtime.is_some() { resolution } else { 0 },
                ctime: other[0],
                atime: other[1],
                // Before RAR 2.0 a non-final part's CRC field holds no hash of its packed data; UnRAR checks it only
                // from unpack version 20 on. A caller that opted in may also store 0 there for a part whose packed
                // bytes it does not yet have (ProgressiveOptions::rar4_unknown_part_crc); the member check in the
                // final part (flag 2 clear) is never affected.
                crc32: (flags & 2 == 0 || (version >= 20 && !(self.rar4_unknown_part_crc && crc == 0))).then_some(crc),
                algorithm: 0,
                method: method.checked_sub(0x30).unwrap_or(255),
                dictionary: if directory { 0 } else { 65_536u64 << ((flags >> 5) & 7) },
                host_os: normalized_host,
                name,
                encrypted: flags & 4 != 0,
                // As UnRAR: a member goes on from the history before it when its own flag says so. The first member of a
                // solid archive starts the stream.
                solid: flags & 0x10 != 0,
                ..FileHeader::default()
            };
            Ok((header, encoded, salt))
        })();
        let (header, encoded, salt) = result.map_err(|error| match error {
            FileParseError::Allocation => allocation().into(),
            FileParseError::Progressive(error) => FramingError::Progressive(error),
            FileParseError::Format(error @ Error::BadChecksum(_)) => {
                self.fault(RarIntegrityReason::HeaderCrc, error, true).into()
            }
            FileParseError::Format(Error::Unsupported(_)) => {
                self.rar4_unsupported("header extension or name encoding").into()
            }
            FileParseError::Format(error) => self.parse_fault(error).into(),
        })?;
        if let Some(budget) = budget {
            budget.names((encoded.len() + header.name.len()) as u64)?;
        }
        if let Some(usage) = &self.usage {
            usage.charge(crate::progressive::Resource::NameBytes, encoded.len() as u64)?;
            usage.charge(crate::progressive::Resource::MetadataBytes, (encoded.len() + RAW_NAME_OWNER_BYTES) as u64)?;
        }
        let mut name = Vec::new();
        name.try_reserve_exact(encoded.len()).map_err(|_| allocation())?;
        if let Some(usage) = &self.usage {
            usage.charge(crate::progressive::Resource::MetadataBytes, (name.capacity() - encoded.len()) as u64)?;
        }
        name.extend_from_slice(encoded);
        let legacy = LegacyWire {
            salt,
            flags,
            version: header.rar4.unwrap().unpack_version,
            method: header.rar4.unwrap().method,
            dictionary: header.dictionary,
            packed_size: header.packed_size,
            unpacked_size: header.unpacked_size,
            crypt: header.encrypted.then_some(LegacyCrypt { version: header.rar4.unwrap().unpack_version, salt }),
        };
        Ok((
            header,
            FileWire {
                legacy: Some(legacy),
                name: std::sync::Arc::new(name),
                compression: 0,
                extent: self.at..data_at,
            },
        ))
    }
}

struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(len).ok_or(Error::Corrupt("RAR4 field size"))?;
        let bytes = self.bytes.get(self.at..end).ok_or(Error::Truncated)?;
        self.at = end;
        Ok(bytes)
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

/// Decode the flag-directed RAR4 Unicode stream with bounded legacy references.
/// `lenient` (map walks only) decodes as unrar does; otherwise malformed encodings are refused.
fn decode_name(
    encoded: &[u8],
    unicode: bool,
    lenient: bool,
    usage: Option<&crate::progressive::Usage>,
) -> std::result::Result<String, FileParseError> {
    if !unicode || !encoded.contains(&0) {
        return legacy_name(encoded, lenient, usage);
    }
    let split = encoded.iter().position(|&byte| byte == 0).ok_or(Error::Corrupt("RAR4 Unicode separator"))?;
    let legacy = &encoded[..split];
    // As unrar: the encoded Unicode part is decoded only when the name field is longer than the legacy name and its
    // NUL; otherwise, or when it decodes to nothing, the legacy name is used.
    if split + 1 >= encoded.len() {
        return legacy_name(legacy, lenient, usage);
    }
    let units = if lenient {
        // A port of unrar's EncodeFileName::Decode: it stops quietly where the encoded data runs out, copies runs from
        // the raw name field up to its end, and decodes at most MAX_UNITS units.
        const MAX_UNITS: usize = 2048;
        let raw = |i: usize| encoded.get(i).copied().unwrap_or(0);
        let enc = &encoded[split + 1..];
        let mut at = 0;
        let high = u16::from(enc[at]) << 8;
        at += 1;
        let mut units: Vec<u16> = Vec::new();
        units.try_reserve_exact(encoded.len().min(MAX_UNITS)).map_err(|_| FileParseError::Allocation)?;
        let mut flags = 0u8;
        let mut bits = 0u8;
        'decode: while at < enc.len() && units.len() < MAX_UNITS {
            if bits == 0 {
                flags = enc[at];
                at += 1;
                bits = 8;
            }
            match flags >> 6 {
                0 => {
                    let Some(&byte) = enc.get(at) else { break 'decode };
                    units.push(u16::from(byte));
                    at += 1;
                }
                1 => {
                    let Some(&byte) = enc.get(at) else { break 'decode };
                    units.push(high | u16::from(byte));
                    at += 1;
                }
                2 => {
                    // As unrar's switch-level break: an incomplete 16-bit op consumes nothing and decoding goes on.
                    if at + 1 < enc.len() {
                        units.push(u16::from_le_bytes([enc[at], enc[at + 1]]));
                        at += 2;
                    }
                }
                _ => {
                    let Some(&length) = enc.get(at) else { break 'decode };
                    at += 1;
                    let correction = if length & 0x80 != 0 {
                        let Some(&correction) = enc.get(at) else { break 'decode };
                        at += 1;
                        Some(correction)
                    } else {
                        None
                    };
                    let count = usize::from(length & 0x7f) + 2;
                    for _ in 0..count {
                        // unrar's run stops at the end of the name field (and at its unit cap).
                        if units.len() >= MAX_UNITS || units.len() >= encoded.len() {
                            break;
                        }
                        let byte = raw(units.len());
                        units.push(match correction {
                            Some(correction) => high | u16::from(byte.wrapping_add(correction)),
                            None => u16::from(byte),
                        });
                    }
                }
            }
            flags <<= 2;
            bits -= 2;
        }
        // unrar ends the name at its first NUL unit.
        if let Some(nul) = units.iter().position(|&unit| unit == 0) {
            units.truncate(nul);
        }
        units
    } else {
        let mut fields = Fields::new(encoded, split + 1);
        let high = u16::from(fields.byte()?) << 8;
        let mut units = Vec::new();
        units.try_reserve_exact(encoded.len()).map_err(|_| FileParseError::Allocation)?;
        while fields.at < encoded.len() {
            let flags = fields.byte()?;
            for shift in [6, 4, 2, 0] {
                if fields.at == encoded.len() {
                    break;
                }
                match (flags >> shift) & 3 {
                    0 => units.push(u16::from(fields.byte()?)),
                    1 => units.push(high | u16::from(fields.byte()?)),
                    2 => units.push(fields.u16()?),
                    3 => {
                        let length = fields.byte()?;
                        let correction = if length & 128 != 0 { Some(fields.byte()?) } else { None };
                        let count = usize::from(length & 127) + 2;
                        let end = units.len().checked_add(count).ok_or(Error::Corrupt("RAR4 Unicode run"))?;
                        let source = legacy.get(units.len()..end).ok_or(Error::Corrupt("RAR4 Unicode run"))?;
                        units.extend(source.iter().map(|&byte| match correction {
                            Some(correction) => high | u16::from(byte.wrapping_add(correction)),
                            None => u16::from(byte),
                        }));
                    }
                    _ => unreachable!(),
                }
            }
        }
        units
    };
    if units.is_empty() {
        return legacy_name(legacy, lenient, usage);
    }
    let length = char::decode_utf16(units.iter().copied()).try_fold(0usize, |length, scalar| {
        let scalar = scalar.map_err(|_| Error::Corrupt("RAR4 Unicode surrogate"))?;
        length.checked_add(scalar.len_utf8()).ok_or(FileParseError::Allocation)
    })?;
    admit_name(usage, length)?;
    let mut name = String::new();
    name.try_reserve_exact(length).map_err(|_| FileParseError::Allocation)?;
    if let Some(usage) = usage {
        usage
            .charge(crate::progressive::Resource::MetadataBytes, (name.capacity() - length) as u64)
            .map_err(FileParseError::Progressive)?;
    }
    for scalar in char::decode_utf16(units) {
        // U+FFFE marks a name mapped from bytes that aren't UTF-8; a stored one would pass for that mark, so it
        // lists as the noncharacter U+FFFF, which no name is written under (`crate::path::rar_output_name`)
        let c = separator(scalar.map_err(|_| Error::Corrupt("RAR4 Unicode surrogate"))?);
        name.push(if c == '\u{FFFE}' { '\u{FFFF}' } else { c });
    }
    Ok(name)
}

/// RAR 1.5 to 4.x names separate directories with a backslash whatever the host, and unrar reads both a backslash
/// and a slash as a separator in them (`ConvertFileHeader`), so `dir\file` from a Unix rar lists as `dir/file`.
/// Mapped here once, a name then splits the same way for every host; both are one byte, so lengths are unchanged.
fn separator(c: char) -> char {
    if c == '\\' { '/' } else { c }
}

/// A RAR4 name without (usable) Unicode encoding. Stored bytes that aren't UTF-8 read as UnRAR on Unix reads them
/// (`CharToWideMap` in a UTF-8 locale): U+FFFE marks the name, then each byte that doesn't start a valid sequence
/// becomes U+E000 plus its value. A name so marked lists as UnRAR lists it, and is written under its private-use
/// characters (`crate::path::rar_output_name`). Map walks (`lenient`) keep such a name by its raw bytes instead.
fn legacy_name(
    encoded: &[u8],
    lenient: bool,
    usage: Option<&crate::progressive::Usage>,
) -> std::result::Result<String, FileParseError> {
    let mapped: String;
    let mut mapped_ptr = std::ptr::null();
    let value = match std::str::from_utf8(encoded) {
        Ok(value) => value,
        Err(_) if lenient => return Err(Error::Unsupported("RAR4 legacy name encoding".into()).into()),
        Err(_) => {
            mapped = unrar_mapped_name(encoded).ok_or(Error::Corrupt("RAR4 member name"))?;
            mapped_ptr = mapped.as_ptr();
            &mapped
        }
    };
    admit_name(usage, value.len())?;
    let mut name = String::new();
    name.try_reserve_exact(value.len()).map_err(|_| FileParseError::Allocation)?;
    if let Some(usage) = usage {
        usage
            .charge(crate::progressive::Resource::MetadataBytes, (name.capacity() - value.len()) as u64)
            .map_err(FileParseError::Progressive)?;
    }
    // a stored U+FFFE lists as U+FFFF, as in a Unicode name; such a name is never written
    let stored_mark = |c: char| if c == '\u{FFFE}' && value.as_ptr() != mapped_ptr { '\u{FFFF}' } else { c };
    name.extend(value.chars().map(stored_mark).map(separator));
    Ok(name)
}

/// A RAR 4.x Unix symbolic link's target bytes as the link is written: mapped as member names are written
/// (`crate::path::rar_output_name`), so a target naming a member whose raw name isn't UTF-8 points at that member
/// where it was extracted. A stored U+FFFE stands for itself and is refused, as in a name. None when the target
/// can't keep its meaning that way.
pub(crate) fn link_target(bytes: &[u8]) -> Option<Vec<u8>> {
    let decoded = match std::str::from_utf8(bytes) {
        Ok(text) => text.replace('\u{FFFE}', "\u{FFFF}"),
        Err(_) => unrar_mapped_name(bytes)?,
    };
    crate::path::rar_output_name(&decoded, true).map(|name| name.into_owned().into_bytes())
}

/// `bytes`, which aren't UTF-8, as UnRAR's `CharToWideMap` reads them in a UTF-8 locale: U+FFFE marks the name
/// before the first byte that doesn't start a valid sequence, and each such byte becomes U+E000 plus its value.
/// None where UnRAR stops (an ASCII byte it can't convert, which can't happen in a name already split at its
/// first NUL).
///
/// One difference keeps the name writable one to one (`crate::path::rar_output_name`): a character U+E080..U+E0FF
/// spelled out in valid UTF-8 is mapped byte by byte too, as if its bytes were invalid, so every such character of
/// the result stands for one raw byte. UnRAR would keep it as it is.
fn unrar_mapped_name(mut bytes: &[u8]) -> Option<String> {
    const MAPPED_STRING_MARK: char = '\u{FFFE}';
    const MAP_AREA_START: u32 = 0xe000;
    let mut name = String::new();
    let mut marked = false;
    let mut map = |name: &mut String, raw: &[u8]| {
        if !marked {
            name.push(MAPPED_STRING_MARK);
            marked = true;
        }
        name.extend(raw.iter().map(|&b| char::from_u32(MAP_AREA_START + u32::from(b)).expect("private-use character")));
    };
    while !bytes.is_empty() {
        let (valid, rest) = match std::str::from_utf8(bytes) {
            Ok(all) => (all, &[][..]),
            Err(error) => {
                let (valid, rest) = bytes.split_at(error.valid_up_to());
                (std::str::from_utf8(valid).expect("valid prefix"), rest)
            }
        };
        for c in valid.chars() {
            if ('\u{E080}'..='\u{E0FF}').contains(&c) {
                map(&mut name, c.to_string().as_bytes());
            } else {
                name.push(c);
            }
        }
        let Some(&byte) = rest.first() else { break };
        if byte < 0x80 {
            return None;
        }
        map(&mut name, &rest[..1]);
        bytes = &rest[1..];
    }
    Some(name)
}

fn dos_timestamp(bits: u32) -> Option<i64> {
    let date = (bits >> 16) as u16;
    let year = 1980 + u32::from(date >> 9);
    let month = (date >> 5) & 15;
    let day = date & 31;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return None,
    };
    if day == 0 || day > days {
        return None;
    }
    // RAR 4.x DOS times, the extended-time records built on them included, are local wall clock, as UnRAR reads them
    crate::zip::dos_time(bits as u16, date).map(crate::localtime::local_to_utc)
}

fn admit_name(usage: Option<&crate::progressive::Usage>, len: usize) -> std::result::Result<(), FileParseError> {
    if let Some(usage) = usage {
        usage.charge(crate::progressive::Resource::NameBytes, len as u64).map_err(FileParseError::Progressive)?;
        usage.charge(crate::progressive::Resource::MetadataBytes, len as u64).map_err(FileParseError::Progressive)?;
    }
    Ok(())
}
