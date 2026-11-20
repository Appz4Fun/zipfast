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

//! Incremental physical framing. This module never reads or owns an input source.
use super::reader::Block;
use super::*;
use crate::error::{RarFailure, RarFault, RarIntegrityReason, RarInternal, RarPasswordEvidence, RarScope};
use crate::progressive::{FailureKind, ProgressiveFailure, ProgressiveResult};
use std::{ops::Range, path::PathBuf};

#[path = "reader/rar4.rs"]
mod rar4;

#[derive(Debug)]
pub(crate) enum FramingError {
    Rar(RarFault),
    Progressive(ProgressiveFailure),
    Checksum { fault: RarFault, expected: u32, actual: u32 },
}
impl From<RarFault> for FramingError {
    fn from(fault: RarFault) -> Self {
        Self::Rar(fault)
    }
}
impl From<ProgressiveFailure> for FramingError {
    fn from(fault: ProgressiveFailure) -> Self {
        Self::Progressive(fault)
    }
}
impl FramingError {
    pub(crate) fn legacy(self) -> RarFault {
        match self {
            Self::Rar(fault) | Self::Checksum { fault, .. } => fault,
            Self::Progressive(_) => unreachable!("legacy parser has no progressive budget"),
        }
    }
    fn progressive(self) -> ProgressiveFailure {
        match self {
            Self::Rar(fault) => progressive_fault(fault),
            Self::Progressive(fault) => fault,
            Self::Checksum { expected, actual, .. } => ProgressiveFailure::new(FailureKind::ChecksumMismatch {
                algorithm: crate::progressive::ChecksumAlgorithm::Crc32,
                scope: crate::progressive::ChecksumScope::Header,
                expected: Box::new(crate::progressive::ChecksumValue::Crc32(expected.to_le_bytes())),
                actual: Box::new(crate::progressive::ChecksumValue::Crc32(actual.to_le_bytes())),
            }),
        }
    }
}

pub(crate) struct PhysicalFrame {
    pub(crate) block: Block,
    pub(crate) crypt: MemberCrypt,
    pub(crate) wire: Option<FileWire>,
    pub(crate) extent: Range<u64>,
    pub(crate) data_end: u64,
    pub(crate) header_crypt: Option<std::result::Result<crate::crypto::Rar5CryptParams, crate::crypto::Rar5CryptError>>,
    /// The end of archive header's fields, for an end frame.
    pub(crate) end_record: Option<super::RarEndRecord>,
}
#[allow(
    clippy::large_enum_variant,
    reason = "fixed by-value parser interface avoids a heap allocation for every frame"
)]
pub(crate) enum ParserStep {
    Need { offset: u64, len: usize },
    LegacyKeyRequired { salt: [u8; 8] },
    Frame(PhysicalFrame),
    End,
}
#[derive(Clone, Copy)]
enum Phase {
    Prefix,
    Size,
    Body,
    EncryptedFirst,
    EncryptedBody,
    Rar4Prefix,
    Rar4Body,
    LegacySalt,
    LegacyKey,
    LegacyFirst,
    LegacyBody,
}

pub(crate) struct HeaderParser {
    path: PathBuf,
    at: u64,
    complete_len: Option<u64>,
    catalogue: bool,
    buffer: Vec<u8>,
    need: usize,
    phase: Phase,
    size: usize,
    size_len: usize,
    cipher: Option<crate::crypto::AesKey>,
    iv: [u8; 16],
    evidence: RarPasswordEvidence,
    ended: bool,
    allocation_limit: u64,
    usage: Option<crate::progressive::Usage>,
    volume_bytes: u64,
    counted: bool,
    failed: bool,
    signature: Option<SignatureParser>,
    fault_path_admitted: bool,
    format: RarFormat,
    rar4_main: Option<MainHeader>,
    legacy_headers: bool,
    /// Map walks only (see [`HeaderParser::lenient_map`]). Sessions, catalogues and extraction never set it.
    map_lenient: bool,
    /// Progressive sessions that opted in through [`crate::progressive::ProgressiveOptions::rar4_unknown_part_crc`]:
    /// a RAR 4.x file part that continues into the next volume and stores 0 as its CRC has no part check.
    rar4_unknown_part_crc: bool,
}
impl HeaderParser {
    pub(crate) fn new(path: PathBuf, at: u64, complete_len: Option<u64>, catalogue: bool) -> Self {
        Self {
            path,
            at,
            complete_len,
            catalogue,
            buffer: Vec::new(),
            need: 4,
            phase: Phase::Prefix,
            size: 0,
            size_len: 0,
            cipher: None,
            iv: [0; 16],
            evidence: RarPasswordEvidence::NotEncrypted,
            ended: false,
            allocation_limit: MAX_HEADER + 48,
            usage: None,
            volume_bytes: 0,
            counted: false,
            failed: false,
            signature: None,
            fault_path_admitted: false,
            format: RarFormat::Rar5,
            rar4_main: None,
            legacy_headers: false,
            map_lenient: false,
            rar4_unknown_part_crc: false,
        }
    }
    pub(crate) fn format(&self) -> RarFormat {
        self.format
    }
    /// See [`crate::progressive::ProgressiveOptions::rar4_unknown_part_crc`].
    pub(crate) fn set_rar4_unknown_part_crc(&mut self, on: bool) {
        self.rar4_unknown_part_crc = on;
    }
    pub(crate) fn set_format(&mut self, format: RarFormat) {
        self.format = format;
        self.reset();
    }
    pub(crate) fn progressive(path: PathBuf, at: u64, usage: crate::progressive::Usage) -> Self {
        let mut parser = Self::new(path, at, None, true);
        parser.usage = Some(usage);
        parser
    }
    pub(crate) fn from_start(path: PathBuf, usage: crate::progressive::Usage) -> Self {
        let mut parser = Self::progressive(path, 0, usage);
        parser.signature = Some(SignatureParser::default());
        parser
    }
    /// Accepts what a header map may list but extraction refuses, on RAR 4.x: a legacy name that is not UTF-8
    /// (kept as raw bytes, with an empty decoded name), the legacy service blocks 0x75..=0x79 (skipped by their
    /// declared sizes), embedded comments, bytes left over inside a header's declared size (ignored), an end
    /// header of any size, and `MHD_ENCRYPTVER` on an encrypted-header archive.
    pub(crate) fn lenient_map(mut self) -> Self {
        self.map_lenient = true;
        self
    }
    pub(crate) fn enable_encryption(
        &mut self,
        password: &str,
        params: crate::crypto::Rar5CryptParams,
        usage: &crate::progressive::Usage,
        control: &crate::progressive::SessionControl,
    ) -> ProgressiveResult<()> {
        let keys = super::member::controlled_keys(password, params, usage, control, self.scope())?;
        self.set_encryption(&keys);
        Ok(())
    }
    pub(crate) fn set_encryption(&mut self, keys: &crate::crypto::Rar5Keys) {
        self.cipher = crate::crypto::AesKey::new(&keys.key);
        self.evidence = keys.evidence;
        self.reset();
    }
    pub(crate) fn set_legacy_keys(&mut self, key: &[u8; 16], iv: [u8; 16]) -> ProgressiveResult<()> {
        if !matches!(self.phase, Phase::LegacyKey) {
            return Err(ProgressiveFailure::new(FailureKind::Malformed("unexpected legacy key")));
        }
        self.cipher = crate::crypto::AesKey::new(key);
        self.iv = iv;
        self.evidence = RarPasswordEvidence::VerifierUnavailable(crate::error::RarVerifierUnavailable::Absent);
        self.phase = Phase::LegacyFirst;
        self.resized_need(24).map_err(FramingError::progressive)
    }
    /// Whether the decrypted first block of the encrypted header being read looks like a header that can follow a
    /// main header: a RAR 4.x file, service or end header, or a RAR 5.0 main, file, service or end header. None
    /// before that block is decrypted. A wrong key passes by chance about once in a hundred.
    pub(crate) fn encrypted_start_plausible(&self) -> Option<bool> {
        match self.phase {
            Phase::LegacyBody => {
                let b = &self.buffer;
                let (kind, flags) = (b[10], u16::from_le_bytes([b[11], b[12]]));
                Some((matches!(kind, 0x74 | 0x7a) && flags & 0x8000 != 0) || kind == 0x7b)
            }
            Phase::EncryptedBody => Some(matches!(self.buffer.get(20 + self.size_len), Some(1 | 2 | 3 | 5))),
            _ => None,
        }
    }
    /// Where the header being parsed starts (after the signature scan, the end of the signature).
    pub(crate) fn header_offset(&self) -> u64 {
        self.at
    }
    /// Whether the parser is still looking for the archive signature.
    pub(crate) fn scanning(&self) -> bool {
        self.signature.is_some()
    }
    /// At the first byte of a RAR4 block, with nothing of it read: where an archive older than RAR 2.9, which
    /// writes no end-of-archive block, may simply end.
    pub(crate) fn at_rar4_block_start(&self) -> bool {
        self.signature.is_none()
            && self.format == RarFormat::Rar4
            && matches!(self.phase, Phase::Rar4Prefix)
            && self.buffer.is_empty()
    }
    pub(crate) fn encrypted(&self) -> bool {
        self.legacy_headers || self.cipher.is_some()
    }
    pub(crate) fn truncated(&self) -> ProgressiveFailure {
        if self.legacy_headers {
            progressive_fault(self.fault(RarIntegrityReason::TruncatedHeader, Error::Truncated, true))
        } else {
            ProgressiveFailure::new(FailureKind::Truncated)
        }
    }
    fn reset(&mut self) {
        self.buffer.clear();
        self.size = 0;
        self.size_len = 0;
        self.counted = false;
        self.phase = if self.legacy_headers {
            self.cipher = None;
            Phase::LegacySalt
        } else if self.format == RarFormat::Rar4 {
            Phase::Rar4Prefix
        } else if self.encrypted() {
            Phase::EncryptedFirst
        } else {
            Phase::Prefix
        };
        self.need = if self.legacy_headers {
            8
        } else if self.format == RarFormat::Rar4 {
            7
        } else if self.encrypted() {
            32
        } else {
            4
        };
    }
    pub(crate) fn advance(&mut self, bytes: &[u8]) -> ProgressiveResult<(usize, ParserStep)> {
        self.advance_core(bytes).map_err(|error| {
            let mut failure = error.progressive();
            failure.context.packed_offset = Some(self.at);
            if !self.path.as_os_str().is_empty() {
                failure.context.expected = Some(std::mem::take(&mut self.path).into_os_string());
            }
            failure
        })
    }
    fn scope(&self) -> RarScope {
        RarScope::Header { volume: self.path.clone() }
    }
    fn fault(&self, reason: RarIntegrityReason, legacy: Error, dependent: bool) -> RarFault {
        RarFault::new(RarFailure::integrity(self.scope(), reason, self.evidence, dependent), legacy)
    }
    fn framing(&self, reason: &'static str, legacy: Error) -> RarFault {
        self.fault(RarIntegrityReason::HeaderFraming(reason), legacy, true)
    }
    fn parse_fault(&self, error: Error) -> RarFault {
        match error {
            Error::Truncated => self.fault(RarIntegrityReason::TruncatedHeader, error, true),
            Error::Corrupt(reason) => self.framing(reason, error),
            _ => RarFault::new(RarFailure::Internal(RarInternal::Invariant("unexpected RAR header error")), error),
        }
    }
    fn resized_need(&mut self, need: usize) -> std::result::Result<(), FramingError> {
        if let Some(usage) = &self.usage {
            usage.check(crate::progressive::Resource::HeaderAllocation, need as u64)?;
        }
        if need as u64 > self.allocation_limit {
            return Err(super::session::allocation().into());
        }
        let end = self
            .at
            .checked_add(need as u64)
            .ok_or_else(|| self.framing("header size", Error::Corrupt("header size")))?;
        if self.complete_len.is_some_and(|len| end > len) {
            return Err(self.fault(RarIntegrityReason::TruncatedHeader, Error::Truncated, self.encrypted()).into());
        }
        self.buffer
            .try_reserve_exact(need.saturating_sub(self.buffer.len()))
            .map_err(|_| super::session::allocation())?;
        self.need = need;
        Ok(())
    }
    /// Canonical core; the complete adapter retains its exact RarFault without conversion.
    pub(crate) fn advance_core(&mut self, bytes: &[u8]) -> std::result::Result<(usize, ParserStep), FramingError> {
        self.advance_core_budget(bytes, None)
    }
    pub(super) fn advance_core_budget(
        &mut self,
        bytes: &[u8],
        budget: Option<&super::session::ScanBudget<'_>>,
    ) -> std::result::Result<(usize, ParserStep), FramingError> {
        if self.failed {
            if self.usage.is_some() {
                return Err(FramingError::Progressive(ProgressiveFailure::new(FailureKind::Malformed(
                    "parser stopped after failure",
                ))));
            }
            return Err(self
                .framing("parser stopped after failure", Error::Corrupt("parser stopped after failure"))
                .into());
        }
        let result = self.advance_core_impl(bytes, budget);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn advance_core_impl(
        &mut self,
        bytes: &[u8],
        budget: Option<&super::session::ScanBudget<'_>>,
    ) -> std::result::Result<(usize, ParserStep), FramingError> {
        if let Some(usage) = &self.usage
            && !self.fault_path_admitted
        {
            // Reserve the sole native-name copy made by an owning structural fault.
            usage.charge(crate::progressive::Resource::MetadataBytes, self.path.capacity() as u64)?;
            self.fault_path_admitted = true;
        }
        if let Some(signature) = &mut self.signature {
            let (used, found) = signature.advance(bytes);
            if let Some((at, format)) = found {
                self.set_format(format);
                self.signature = None;
                self.at = at;
                let (n, step) = self.advance_core_budget(&bytes[used..], budget)?;
                return Ok((used + n, step));
            }
            if signature.offset >= MAX_SFX + SIGNATURE.len() as u64 {
                return Err(RarFault::new(RarFailure::NotRar, Error::NotAnArchive).into());
            }
            return Ok((used, ParserStep::Need { offset: signature.offset, len: 1 }));
        }
        if self.ended || self.complete_len.is_some_and(|len| self.at >= len) {
            return Ok((0, ParserStep::End));
        }
        if let Some(usage) = &self.usage
            && !self.counted
            && !bytes.is_empty()
        {
            usage.check(crate::progressive::Resource::HeaderAllocation, self.need as u64)?;
            usage.charge(crate::progressive::Resource::HeaderBlocks, 1)?;
            self.counted = true;
        }
        let mut used = 0;
        loop {
            let n = (self.need - self.buffer.len()).min(bytes.len() - used);
            if let Some(usage) = &self.usage {
                let attempted = self.volume_bytes.saturating_add(n as u64);
                usage.check(crate::progressive::Resource::VolumeHeaderBytes, attempted)?;
                usage.charge(crate::progressive::Resource::HeaderBytes, n as u64)?;
                self.volume_bytes = attempted;
            }
            self.buffer.try_reserve_exact(n).map_err(|_| super::session::allocation())?;
            if let Some(usage) = &self.usage {
                usage.check(crate::progressive::Resource::HeaderAllocation, self.buffer.capacity() as u64)?;
            }
            self.buffer.extend_from_slice(&bytes[used..used + n]);
            used += n;
            if self.buffer.len() < self.need {
                let offset = self
                    .at
                    .checked_add(self.buffer.len() as u64)
                    .ok_or_else(|| self.framing("header offset", Error::Corrupt("header offset")))?;
                return Ok((used, ParserStep::Need { offset, len: self.need - self.buffer.len() }));
            }
            match self.phase {
                Phase::LegacySalt | Phase::LegacyKey => {
                    self.phase = Phase::LegacyKey;
                    return Ok((used, ParserStep::LegacyKeyRequired { salt: self.buffer[..8].try_into().unwrap() }));
                }
                Phase::LegacyFirst => {
                    self.cipher.as_ref().unwrap().decrypt_cbc_in_place(&mut self.iv, &mut self.buffer[8..24]);
                    self.size = usize::from(u16::from_le_bytes([self.buffer[13], self.buffer[14]]));
                    if self.size < 7 {
                        return Err(self.framing("RAR4 encrypted header size", Error::Encrypted).into());
                    }
                    if let Some(usage) = &self.usage {
                        usage.check(crate::progressive::Resource::HeaderAllocation, self.size as u64 * 12)?;
                    }
                    self.phase = Phase::LegacyBody;
                    self.resized_need(8 + self.size.next_multiple_of(16))?;
                }
                Phase::LegacyBody => {
                    self.cipher.as_ref().unwrap().decrypt_cbc_in_place(&mut self.iv, &mut self.buffer[24..]);
                    let frame = self.parse_rar4(budget)?;
                    self.ended = matches!(frame.block, Block::End { .. });
                    self.at = frame.data_end;
                    self.reset();
                    return Ok((used, ParserStep::Frame(frame)));
                }
                Phase::Rar4Prefix => {
                    let kind = self.buffer[2];
                    let flags = u16::from_le_bytes([self.buffer[3], self.buffer[4]]);
                    let size = usize::from(u16::from_le_bytes([self.buffer[5], self.buffer[6]]));
                    if size < 7
                        || self
                            .at
                            .checked_add(size as u64)
                            .is_none_or(|end| self.complete_len.is_some_and(|len| end > len))
                    {
                        return Err(self.framing("RAR4 header size", Error::Corrupt("RAR4 header size")).into());
                    }
                    if self.embedded_comment(kind, flags) {
                        return Err(self.rar4_unsupported("embedded comment").into());
                    }
                    if let Some(budget) = budget {
                        budget.temporary(size as u64 * 12)?;
                    }
                    if let Some(usage) = &self.usage {
                        usage.check(crate::progressive::Resource::HeaderAllocation, size as u64 * 12)?;
                    }
                    self.phase = Phase::Rar4Body;
                    self.resized_need(size)?;
                }
                Phase::Rar4Body => {
                    let frame = self.parse_rar4(budget)?;
                    self.ended = matches!(frame.block, Block::End { .. });
                    self.at = frame.data_end;
                    self.reset();
                    return Ok((used, ParserStep::Frame(frame)));
                }
                Phase::Prefix => {
                    self.phase = Phase::Size;
                    self.resized_need(5)?;
                }
                Phase::Size => {
                    let b = self.buffer[4 + self.size_len];
                    self.size |= usize::from(b & 0x7f) << (7 * self.size_len);
                    self.size_len += 1;
                    if b & 0x80 != 0 {
                        if self.size_len == 3 {
                            return Err(self
                                .framing("header size field too long", Error::Corrupt("header size field too long"))
                                .into());
                        }
                        self.resized_need(self.need + 1)?;
                    } else {
                        if self.size == 0 || self.size as u64 > MAX_HEADER {
                            return Err(self.framing("header size", Error::Corrupt("header size")).into());
                        }
                        self.phase = Phase::Body;
                        self.resized_need(4 + self.size_len + self.size)?;
                    }
                }
                Phase::EncryptedFirst => {
                    self.iv.copy_from_slice(&self.buffer[..16]);
                    self.cipher.as_ref().unwrap().decrypt_cbc_in_place(&mut self.iv, &mut self.buffer[16..32]);
                    for i in 0..3 {
                        let b = self.buffer[20 + i];
                        self.size |= usize::from(b & 0x7f) << (7 * i);
                        self.size_len = i + 1;
                        if b & 0x80 == 0 {
                            break;
                        }
                        if i == 2 {
                            return Err(self.framing("encrypted header size", Error::Encrypted).into());
                        }
                    }
                    if self.size == 0 || self.size as u64 > MAX_HEADER {
                        return Err(self.framing("encrypted header size", Error::Encrypted).into());
                    }
                    self.phase = Phase::EncryptedBody;
                    self.resized_need(16 + (4 + self.size_len + self.size).next_multiple_of(16))?;
                }
                Phase::EncryptedBody | Phase::Body => {
                    let base = if self.encrypted() { 16 } else { 0 };
                    if let Some(cipher) = &self.cipher {
                        cipher.decrypt_cbc_in_place(&mut self.iv, &mut self.buffer[32..]);
                    }
                    let plain_end = base + 4 + self.size_len + self.size;
                    let stored = u32::from_le_bytes(self.buffer[base..base + 4].try_into().unwrap());
                    let actual = crate::crc32::hash(&self.buffer[base + 4..plain_end]);
                    if actual != stored {
                        return Err(FramingError::Checksum {
                            expected: stored,
                            actual,
                            fault: self.fault(
                                RarIntegrityReason::HeaderCrc,
                                if self.encrypted() {
                                    Error::Encrypted
                                } else {
                                    Error::Corrupt("header checksum mismatch")
                                },
                                self.encrypted(),
                            ),
                        });
                    }
                    let header_end = self.at + self.need as u64;
                    let frame = self.parse(&self.buffer[base + 4 + self.size_len..plain_end], header_end)?;
                    self.ended = matches!(frame.block, Block::End { .. });
                    self.at = frame.data_end;
                    self.reset();
                    return Ok((used, ParserStep::Frame(frame)));
                }
            }
        }
    }
    fn parse(&self, body: &[u8], header_end: u64) -> std::result::Result<PhysicalFrame, FramingError> {
        let mut c = Cursor::new(body);
        let kind = c.vint().map_err(|e| self.parse_fault(e))?;
        let flags = c.vint().map_err(|e| self.parse_fault(e))?;
        let extra_size = if flags & HFL_EXTRA != 0 { c.vsize().map_err(|e| self.parse_fault(e))? } else { 0 };
        let data_size = if flags & HFL_DATA != 0 { c.vint().map_err(|e| self.parse_fault(e))? } else { 0 };
        let fields_end = body
            .len()
            .checked_sub(extra_size)
            .filter(|&e| e >= c.pos())
            .ok_or_else(|| self.framing("extra area size", Error::Corrupt("extra area size")))?;
        let fields = &body[c.pos()..fields_end];
        let extra = &body[fields_end..];
        let data_end =
            header_end.checked_add(data_size).ok_or_else(|| self.framing("data size", Error::Corrupt("data size")))?;
        if self.complete_len.is_some_and(|len| data_end > len) {
            return Err(self.fault(RarIntegrityReason::TruncatedData, Error::Truncated, false).into());
        }
        let head = BlockHead { kind, flags, data_size, data_at: header_end };
        let mut frame = PhysicalFrame {
            block: Block::Unknown,
            crypt: None,
            wire: None,
            extent: self.at..header_end,
            data_end,
            header_crypt: None,
            end_record: None,
        };
        frame.block = match kind {
            HEAD_MAIN => {
                let mut f = Cursor::new(fields);
                let flags = f.vint().map_err(|e| self.parse_fault(e))?;
                let volume_number =
                    if flags & MHFL_VOLNUMBER != 0 { f.vint().map_err(|e| self.parse_fault(e))? } else { 0 };
                let (original_name, original_time) = super::main_metadata(extra);
                let extra_records = super::extra_records(extra);
                Block::Main(MainHeader {
                    flags,
                    volume_number,
                    rar4_flags: None,
                    original_name,
                    original_time,
                    embedded_comment: None,
                    locator: super::main_locator(&extra_records),
                    extra_records,
                })
            }
            HEAD_FILE | HEAD_SERVICE => {
                let (h, crypt, wire) = parse_file_impl(&head, fields, extra, self.catalogue, self.usage.as_ref())
                    .map_err(|e| match e {
                        FileParseError::Format(e) => FramingError::Rar(self.parse_fault(e)),
                        FileParseError::Allocation => FramingError::Rar(super::session::allocation()),
                        FileParseError::Progressive(e) => FramingError::Progressive(e),
                    })?;
                frame.crypt = crypt;
                frame.wire = wire;
                if let Some(wire) = &mut frame.wire {
                    wire.extent = frame.extent.clone();
                }
                if kind == HEAD_FILE { Block::File(h) } else { Block::Service(h) }
            }
            HEAD_CRYPT => {
                frame.header_crypt =
                    Some(crate::crypto::parse_rar5_crypt(fields, crate::crypto::Rar5CryptLayout::Header));
                Block::Crypt
            }
            HEAD_END => {
                let mut f = Cursor::new(fields);
                let flags =
                    if self.catalogue { f.vint().map_err(|e| self.parse_fault(e))? } else { f.vint().unwrap_or(0) };
                frame.end_record =
                    Some(super::RarEndRecord { flags, data_crc: None, volume_number: None, offset: self.at });
                Block::End { more_volumes: flags & EOAFL_MORE_VOLUMES != 0, volume_number: None }
            }
            _ => Block::Unknown,
        };
        Ok(frame)
    }
}

pub(crate) fn progressive_fault(fault: RarFault) -> ProgressiveFailure {
    let kind = match *fault.failure {
        RarFailure::PasswordRequired { .. } => FailureKind::PasswordRequired,
        RarFailure::WrongPassword { .. } => FailureKind::WrongPassword,
        RarFailure::Canceled => FailureKind::Canceled,
        RarFailure::Integrity {
            reason: RarIntegrityReason::TruncatedHeader | RarIntegrityReason::TruncatedData,
            ..
        } => FailureKind::Truncated,
        other => FailureKind::Rar(Box::new(other)),
    };
    ProgressiveFailure::new(kind)
}

/// Bounded signature scanner shared with the File adapter, including SFX prefixes.
#[derive(Default)]
pub(crate) struct SignatureParser {
    tail: [u8; 8],
    held: usize,
    offset: u64,
}
impl SignatureParser {
    pub(crate) fn advance(&mut self, bytes: &[u8]) -> (usize, Option<(u64, RarFormat)>) {
        let mut used = 0;
        for &byte in bytes {
            if self.offset >= MAX_SFX + SIGNATURE.len() as u64 {
                break;
            }
            if self.held == self.tail.len() {
                self.tail.copy_within(1.., 0);
                self.held -= 1;
            }
            self.tail[self.held] = byte;
            self.held += 1;
            self.offset += 1;
            used += 1;
            if self.held >= 7 && self.offset - 7 <= MAX_SFX && &self.tail[self.held - 7..self.held] == SIGNATURE_V4 {
                return (used, Some((self.offset, RarFormat::Rar4)));
            }
            if self.held == 8 && &self.tail == SIGNATURE {
                return (used, Some((self.offset, RarFormat::Rar5)));
            }
        }
        (used, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progressive::{ProgressiveLimits, Resource, Usage};
    fn vint(mut n: u64, bytes: &mut Vec<u8>) {
        loop {
            let b = (n & 127) as u8;
            n >>= 7;
            bytes.push(b | if n > 0 { 128 } else { 0 });
            if n == 0 {
                break;
            }
        }
    }
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut sized = Vec::new();
        vint(body.len() as u64, &mut sized);
        sized.extend_from_slice(body);
        let mut out = crate::crc32::hash(&sized).to_le_bytes().to_vec();
        out.extend(sized);
        out
    }
    #[test]
    fn signatures_and_crc_vints_resume_at_every_byte_without_early_metadata() {
        for signature in [SIGNATURE.as_slice(), SIGNATURE_V4.as_slice()] {
            let mut scanner = SignatureParser::default();
            for byte in b"prefix" {
                assert!(scanner.advance(&[*byte]).1.is_none());
            }
            for (i, byte) in signature.iter().enumerate() {
                let result = scanner.advance(&[*byte]);
                assert_eq!(result.0, 1);
                assert_eq!(result.1.is_some(), i + 1 == signature.len());
            }
        }
        let mut parser = HeaderParser::from_start(PathBuf::new(), Usage::new(ProgressiveLimits::default()));
        let mut archive = SIGNATURE.to_vec();
        archive.extend(frame(&[1, 0, 0]));
        for (i, byte) in archive.iter().enumerate() {
            let (_, step) = parser.advance(&[*byte]).unwrap();
            assert_eq!(matches!(step, ParserStep::Frame(_)), i + 1 == archive.len());
        }
        // Two-byte length, plus a non-UTF8 name: raw allocation must survive lossy public display.
        let name = vec![0xff; 140];
        let mut body = vec![2, 0, 0, 0, 0, 0, 0];
        vint(name.len() as u64, &mut body);
        body.extend(&name);
        let wire = frame(&body);
        let mut parser = HeaderParser::progressive(PathBuf::new(), 8, Usage::new(ProgressiveLimits::default()));
        for (i, byte) in wire.iter().enumerate() {
            let (used, step) = parser.advance(&[*byte]).unwrap();
            assert_eq!(used, 1);
            match step {
                ParserStep::Need { offset, len } => {
                    assert!(i + 1 < wire.len());
                    for _ in 0..3 {
                        assert!(
                            matches!(parser.advance(&[]).unwrap(),(0,ParserStep::Need { offset:o,len:n }) if o==offset&&n==len)
                        );
                    }
                }
                ParserStep::Frame(frame) => {
                    assert_eq!(i + 1, wire.len());
                    assert_eq!(*frame.wire.unwrap().name, name);
                    assert_eq!(frame.extent, 8..8 + wire.len() as u64);
                }
                ParserStep::LegacyKeyRequired { .. } => panic!("unexpected legacy encryption"),
                ParserStep::End => panic!("early end"),
            }
        }
    }
    #[test]
    fn encrypted_iv_and_header_are_retained_at_every_byte() {
        let keys = crate::crypto::derive_rar5_keys("secret", 3, &[7; 16], None).unwrap();
        let mut plain = frame(&[1, 0, 0]);
        plain.resize(plain.len().next_multiple_of(16), 0);
        let iv = [9; 16];
        let mut wire = iv.to_vec();
        wire.extend(crate::crypto::encrypt_cbc(&keys.key, &iv, &plain).unwrap());
        for split in 0..=wire.len() {
            let mut parser = HeaderParser::new(PathBuf::new(), 8, None, true);
            parser.set_encryption(&keys);
            let mut at = 0;
            let mut seen = 0;
            for chunk in [&wire[..split], &wire[split..]] {
                let (used, step) = parser.advance(chunk).unwrap();
                at += used;
                if let ParserStep::Frame(frame) = step {
                    seen += 1;
                    assert!(matches!(frame.block, Block::Main(_)));
                }
            }
            assert_eq!(at, wire.len());
            assert_eq!(seen, 1);
        }
        let mut bad = wire;
        bad[0] ^= 1;
        let mut parser = HeaderParser::new(PathBuf::new(), 8, None, true);
        parser.set_encryption(&keys);
        assert!(parser.advance(&bad).is_err());
    }
    #[test]
    fn malformed_sizes_and_header_budgets_fail_before_metadata() {
        let mut parser = HeaderParser::new(PathBuf::new(), 0, None, true);
        assert!(parser.advance(&[0, 0, 0, 0, 128, 128, 128]).is_err());
        assert!(parser.advance(&[]).is_err());
        let mut overflow = HeaderParser::new(PathBuf::new(), u64::MAX, None, true);
        assert!(overflow.advance(&[0]).is_err());
        for resource in [
            Resource::HeaderAllocation,
            Resource::HeaderBytes,
            Resource::VolumeHeaderBytes,
            Resource::HeaderBlocks,
            Resource::NameBytes,
        ] {
            let mut limits = ProgressiveLimits::default();
            match resource {
                Resource::HeaderAllocation => limits.header_allocation = 0,
                Resource::HeaderBytes => limits.header_bytes = 0,
                Resource::VolumeHeaderBytes => limits.volume_header_bytes = 0,
                Resource::HeaderBlocks => limits.header_blocks = 0,
                Resource::NameBytes => limits.name_bytes = 0,
                _ => unreachable!(),
            }
            let mut parser = HeaderParser::progressive(PathBuf::new(), 0, Usage::new(limits));
            let wire = frame(&[2, 0, 0, 0, 0, 0, 0, 1, b'f']);
            assert!(
                matches!(parser.advance(&wire),Err(ProgressiveFailure { kind:FailureKind::Limit {resource:actual,..},.. }) if actual==resource)
            );
        }
        eprintln!(
            "FailureKind bytes={}, ProgressiveFailure bytes={}",
            std::mem::size_of::<FailureKind>(),
            std::mem::size_of::<ProgressiveFailure>()
        );
    }
}
