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
    pub(super) fn parse_rar4(
        &mut self,
        budget: Option<&ScanBudget<'_>>,
    ) -> std::result::Result<PhysicalFrame, FramingError> {
        let header =
            if matches!(self.phase, Phase::LegacyBody) { &self.buffer[8..8 + self.size] } else { &self.buffer[..] };
        let kind = header[2];
        let flags = u16::from_le_bytes([header[3], header[4]]);
        let size = header.len();
        if crate::crc32::hash(&header[2..]) as u16 != u16::from_le_bytes([header[0], header[1]]) {
            return Err(self
                .fault(RarIntegrityReason::HeaderCrc, Error::BadChecksum("RAR4 header CRC".into()), true)
                .into());
        }
        if (kind == 0x73 && flags & 2 != 0) || (kind == 0x74 && flags & 8 != 0) {
            return Err(self.rar4_unsupported("embedded comment").into());
        }
        let mut cursor = Fields::new(header, 7);
        let packed = if flags & 0x8000 != 0 { u64::from(cursor.u32().map_err(|e| self.parse_fault(e))?) } else { 0 };
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
        };
        frame.block = match kind {
            0x73 => {
                if self.rar4_main.is_some() {
                    return Err(self
                        .framing("duplicate RAR4 main header", Error::Corrupt("duplicate RAR4 main header"))
                        .into());
                }
                if size != 13 && !(size == 14 && flags & 0x200 != 0) {
                    return Err(self.framing("RAR4 main header size", Error::Corrupt("RAR4 main header size")).into());
                }
                if flags & 0x80 != 0 {
                    if self.usage.is_none() {
                        return Err(self.rar4_unsupported("encrypted headers").into());
                    }
                    if flags & 0x200 != 0 {
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
                let main = MainHeader { flags: normalized, volume_number: 0 };
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
                if size != expected {
                    return Err(self
                        .framing("RAR4 end header fields", Error::Corrupt("RAR4 end header fields"))
                        .into());
                }
                Block::End { more_volumes: flags & 1 != 0 }
            }
            0x75..=0x79 => return Err(self.rar4_unsupported("legacy service block").into()),
            _ if flags & 0x4000 != 0 => Block::Unknown,
            _ => return Err(self.rar4_unsupported("header type").into()),
        };
        if self.complete_len.is_some_and(|len| frame.data_end > len) {
            return Err(self.fault(RarIntegrityReason::TruncatedData, Error::Truncated, false).into());
        }
        Ok(frame)
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
            let encoded = fields.take(name_len)?;
            let name = decode_name(encoded, flags & 0x200 != 0, self.usage.as_ref())?;
            if name.is_empty() || name.contains('\0') {
                return Err(Error::Corrupt("RAR4 member name").into());
            }
            let salt = if flags & 0x400 != 0 { Some(fields.take(8)?.try_into().unwrap()) } else { None };
            let mut mtime = dos_timestamp(dos);
            let mut nanos = 0;
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
                    if index == 0 {
                        mtime = seconds;
                        nanos = fraction * 100;
                    }
                }
            }
            if fields.at != bytes.len() {
                return Err(Error::Unsupported("RAR4 trailing header fields".into()).into());
            }
            let directory = flags & 0xe0 == 0xe0;
            let normalized_host = match host {
                0..=2 => 0,
                3 => 1,
                _ => 2,
            };
            let header = FileHeader {
                format: RarFormat::Rar4,
                rar4: Some(Rar4Metadata { flags, host, method, unpack_version: version, dos_time: dos }),
                block_flags: (u64::from(flags & 1 != 0) * HFL_SPLIT_BEFORE)
                    | (u64::from(flags & 2 != 0) * HFL_SPLIT_AFTER),
                file_flags: u64::from(directory) * FHFL_DIRECTORY,
                packed_size: packed,
                data_at,
                unpacked_size: unpacked,
                attributes,
                mtime,
                mtime_nanos: nanos,
                crc32: Some(crc),
                algorithm: 0,
                method: method.checked_sub(0x30).unwrap_or(255),
                dictionary: if directory { 0 } else { 65_536u64 << ((flags >> 5) & 7) },
                host_os: normalized_host,
                name,
                encrypted: flags & 4 != 0,
                solid: flags & 0x10 != 0 || self.rar4_main.as_ref().is_some_and(MainHeader::is_solid),
                ..FileHeader::default()
            };
            Ok((header, encoded, salt))
        })();
        let (header, encoded, salt) = result.map_err(|error| match error {
            FileParseError::Allocation => allocation().into(),
            FileParseError::Progressive(error) => FramingError::Progressive(error),
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
fn decode_name(
    encoded: &[u8],
    unicode: bool,
    usage: Option<&crate::progressive::Usage>,
) -> std::result::Result<String, FileParseError> {
    if !unicode || !encoded.contains(&0) {
        let value = std::str::from_utf8(encoded).map_err(|_| Error::Unsupported("RAR4 legacy name encoding".into()))?;
        admit_name(usage, value.len())?;
        let mut name = String::new();
        name.try_reserve_exact(value.len()).map_err(|_| FileParseError::Allocation)?;
        if let Some(usage) = usage {
            usage
                .charge(crate::progressive::Resource::MetadataBytes, (name.capacity() - value.len()) as u64)
                .map_err(FileParseError::Progressive)?;
        }
        name.push_str(value);
        return Ok(name);
    }
    let split = encoded.iter().position(|&byte| byte == 0).ok_or(Error::Corrupt("RAR4 Unicode separator"))?;
    let legacy = &encoded[..split];
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
        name.push(scalar.map_err(|_| Error::Corrupt("RAR4 Unicode surrogate"))?);
    }
    Ok(name)
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
    crate::zip::dos_time(bits as u16, date)
}

fn admit_name(usage: Option<&crate::progressive::Usage>, len: usize) -> std::result::Result<(), FileParseError> {
    if let Some(usage) = usage {
        usage.charge(crate::progressive::Resource::NameBytes, len as u64).map_err(FileParseError::Progressive)?;
        usage.charge(crate::progressive::Resource::MetadataBytes, len as u64).map_err(FileParseError::Progressive)?;
    }
    Ok(())
}
