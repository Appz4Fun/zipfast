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

//! The RAR walker behind [`crate::map`]: drives the push parser over a map input and accumulates its own model,
//! one [`MapMember`] per logical member and one [`MapPiece`] per part header.
use super::framing::{HeaderParser, ParserStep, PhysicalFrame};
use super::physical::{PhysicalMember, PhysicalPart, continuation_issue};
use super::reader::Block;
use super::{FileHeader, FileWire, MemberCrypt, RarFormat};
use crate::map::{
    CipherParams, Got, MapChecks, MapEnd, MapError, MapFormat, MapInput, MapMember, MapMethod, MapOptions, MapPiece,
    MemberMap, Opened, OutputMapping, read,
};
use crate::progressive::{FailureKind, ProgressiveFailure, Resource, SessionControl, Usage, VolumeRequest};
use std::{
    ffi::OsString,
    task::{Context, Poll},
};

const READ_CHUNK: u64 = 64 << 10;

enum Phase {
    Open,
    Header,
}

pub(crate) struct RarWalker {
    usage: Usage,
    control: SessionControl,
    password: Option<String>,
    volume: u32,
    expected: OsString,
    parser: HeaderParser,
    phase: Phase,
    parked: Option<usize>,
    buffer: Vec<u8>,
    main_seen: bool,
    format: Option<RarFormat>,
    header_encrypted: Option<bool>,
    header_cipher: Option<CipherParams>,
    volume_set: Option<bool>,
    solid_archive: Option<bool>,
    /// Keys were supplied on this volume and no header has decrypted since.
    unproven: bool,
    /// A header decrypted on this volume.
    proven: bool,
    rar5_keys: Option<(u8, [u8; 16], crate::crypto::Rar5Keys)>,
    rar4_keys: Option<([u8; 8], [u8; 16], [u8; 16])>,
    members: Vec<MapMember>,
    open: Option<PhysicalMember>,
}

impl RarWalker {
    pub(crate) fn new(options: &MapOptions, usage: Usage) -> Self {
        let chunk = options.limits.read_chunk.clamp(1, READ_CHUNK) as usize;
        Self {
            parser: HeaderParser::from_start(options.first_name.clone().into(), usage.clone()),
            usage,
            control: options.control.clone(),
            password: options.password.clone(),
            volume: 0,
            expected: options.first_name.clone(),
            phase: Phase::Header,
            parked: None,
            buffer: vec![0; chunk],
            main_seen: false,
            format: None,
            header_encrypted: None,
            header_cipher: None,
            volume_set: None,
            solid_archive: None,
            unproven: false,
            proven: false,
            rar5_keys: None,
            rar4_keys: None,
            members: Vec::new(),
            open: None,
        }
    }

    fn malformed(&self, reason: &'static str) -> MapError {
        MapError::Malformed {
            volume: self.volume,
            failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(reason))),
        }
    }

    fn fail(&self, failure: ProgressiveFailure) -> MapError {
        if self.unproven && header_integrity(&failure) {
            return MapError::WrongPassword;
        }
        MapError::from_failure(self.volume, failure)
    }

    fn finish(&mut self, end: MapEnd) -> MemberMap {
        MemberMap {
            format: if self.format == Some(RarFormat::Rar4) { MapFormat::Rar4 } else { MapFormat::Rar5 },
            header_encrypted: self.header_encrypted.unwrap_or(false),
            header_cipher: self.header_cipher.clone(),
            complete: end == MapEnd::Complete,
            end,
            volumes: match end {
                MapEnd::MissingVolume { volume } => volume,
                _ => self.volume + 1,
            },
            members: std::mem::take(&mut self.members),
        }
    }

    pub(crate) fn poll(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<MemberMap, MapError>> {
        match self.poll_inner(input, cx) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(map)) => Poll::Ready(Ok(map)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_inner(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Result<Poll<MemberMap>, MapError> {
        loop {
            if self.control.is_canceled() {
                return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled))));
            }
            match self.phase {
                Phase::Open => {
                    let request = VolumeRequest { index: self.volume, expected: self.expected.clone() };
                    match input.open(&request, cx).map_err(|e| MapError::from_failure(self.volume, e))? {
                        Opened::Ready => {
                            self.parser = HeaderParser::from_start(self.expected.clone().into(), self.usage.clone());
                            self.main_seen = false;
                            self.unproven = false;
                            self.proven = false;
                            self.phase = Phase::Header;
                        }
                        Opened::Wait => return Ok(Poll::Pending),
                        Opened::Missing => {
                            return Ok(Poll::Ready(self.finish(MapEnd::MissingVolume { volume: self.volume })));
                        }
                        Opened::Abort => return Err(MapError::Aborted { volume: self.volume }),
                    }
                }
                Phase::Header => {
                    let (_, step) = self.parser.advance(&[]).map_err(|e| self.fail(e))?;
                    let (offset, len) = match step {
                        ParserStep::LegacyKeyRequired { salt } => {
                            self.legacy_keys(salt)?;
                            continue;
                        }
                        ParserStep::Need { offset, len } => (offset, len),
                        ParserStep::End => return Err(self.fail(self.parser.truncated())),
                        ParserStep::Frame(_) => unreachable!("frames require input"),
                    };
                    let n = self.parked.take().unwrap_or_else(|| len.min(self.buffer.len()));
                    match read(input, &self.usage, offset, &mut self.buffer[..n], cx)
                        .map_err(|e| MapError::from_failure(self.volume, e))?
                    {
                        Got::NotYet => {
                            self.parked = Some(n);
                            return Ok(Poll::Pending);
                        }
                        Got::Hole => return Err(MapError::HeaderHole { volume: self.volume, offset }),
                        Got::Eof => {
                            if self.unproven {
                                // A wrong key turns the first encrypted header's size into noise that usually runs
                                // past the end; a volume cut inside that header cannot be told apart from it.
                                return Err(MapError::WrongPassword);
                            }
                            if self.parser.scanning() {
                                return Err(if self.volume == 0 {
                                    MapError::NotArchive
                                } else {
                                    self.malformed("volume without a RAR signature")
                                });
                            }
                            return Ok(Poll::Ready(self.finish(MapEnd::Truncated { volume: self.volume, offset })));
                        }
                        Got::Filled(count) => {
                            let count = count.min(n);
                            let (used, step) = self.parser.advance(&self.buffer[..count]).map_err(|e| self.fail(e))?;
                            if used != count {
                                return Err(MapError::Source(Box::new(ProgressiveFailure::new(
                                    FailureKind::SourceContract,
                                ))));
                            }
                            if let ParserStep::Frame(frame) = step
                                && let Some(map) = self.frame(frame)?
                            {
                                return Ok(Poll::Ready(map));
                            }
                        }
                    }
                }
            }
        }
    }

    fn legacy_keys(&mut self, salt: [u8; 8]) -> Result<(), MapError> {
        let (key, iv) = match self.rar4_keys {
            Some((cached, key, iv)) if cached == salt => (key, iv),
            _ => {
                let password = self.password.as_deref().filter(|p| !p.is_empty()).ok_or(MapError::PasswordRequired)?;
                let (key, iv) = super::member::controlled_legacy_keys(password, &salt, &self.usage, &self.control)
                    .map_err(|e| MapError::from_failure(self.volume, e))?;
                self.rar4_keys = Some((salt, key, iv));
                (key, iv)
            }
        };
        if self.header_cipher.is_none() {
            self.header_cipher = Some(CipherParams::Rar4 { salt });
        }
        self.parser.set_legacy_keys(&key, iv).map_err(|e| self.fail(e))?;
        self.unproven = !self.proven;
        Ok(())
    }

    fn header_keys(&mut self, params: crate::crypto::Rar5CryptParams) -> Result<(), MapError> {
        let verified;
        if let Some((kdf, salt, keys)) = &self.rar5_keys
            && *kdf == params.kdf_count
            && *salt == params.salt
        {
            let keys = crate::crypto::Rar5Keys { key: keys.key, hash_key: keys.hash_key, evidence: keys.evidence };
            self.parser.set_encryption(&keys);
            verified = keys.evidence == crate::error::RarPasswordEvidence::VerifierMatched;
        } else {
            let password = self.password.as_deref().ok_or(MapError::PasswordRequired)?;
            let scope = crate::error::RarScope::Header { volume: self.expected.clone().into() };
            let keys = super::member::controlled_keys(password, params, &self.usage, &self.control, scope)
                .map_err(|e| MapError::from_failure(self.volume, e))?;
            self.parser.set_encryption(&keys);
            verified = keys.evidence == crate::error::RarPasswordEvidence::VerifierMatched;
            self.rar5_keys = Some((params.kdf_count, params.salt, keys));
        }
        // A matched check value proves the password; otherwise the first decrypted header has to.
        self.unproven = !self.proven && !verified;
        Ok(())
    }

    /// Accounts one frame. Returns the finished map at the archive's last end header.
    fn frame(&mut self, frame: PhysicalFrame) -> Result<Option<MemberMap>, MapError> {
        // Keys are supplied after the frame that calls for them, so any frame seen while unproven decrypted.
        if self.unproven {
            self.unproven = false;
            self.proven = true;
        }
        match frame.block {
            Block::Crypt => {
                if self.main_seen || self.parser.encrypted() {
                    return Err(self.malformed("encryption header order"));
                }
                let params = frame
                    .header_crypt
                    .ok_or_else(|| self.malformed("encryption header"))?
                    .map_err(|e| self.crypt_error(e))?;
                if self.header_cipher.is_none() {
                    self.header_cipher = Some(CipherParams::Rar5 {
                        kdf_count: params.kdf_count,
                        salt: params.salt,
                        iv: None,
                        check: params.check,
                        keyed_checks: params.tweaked_crc,
                    });
                }
                self.header_keys(params)?;
            }
            Block::Main(main) => {
                let format = self.parser.format();
                if self.format.is_some_and(|prior| prior != format) {
                    return Err(self.malformed("volume archive format changed"));
                }
                self.format = Some(format);
                let encrypted = self.parser.encrypted();
                if self.header_encrypted.is_some_and(|initial| initial != encrypted) {
                    return Err(self.malformed("volume header encryption changed"));
                }
                self.header_encrypted = Some(encrypted);
                if self.main_seen
                    || (main.flags & super::MHFL_VOLNUMBER != 0 && main.volume_number != u64::from(self.volume))
                    || (self.volume > 0 && !main.is_volume())
                    || self.volume_set.is_some_and(|v| v != main.is_volume())
                {
                    return Err(self.malformed("volume main identity/order"));
                }
                if self.solid_archive.is_some_and(|solid| solid != main.is_solid()) {
                    return Err(self.malformed("volume solid flag changed"));
                }
                self.solid_archive = Some(main.is_solid());
                self.volume_set = Some(main.is_volume());
                self.main_seen = true;
            }
            Block::File(header) => {
                if !self.main_seen {
                    return Err(self.malformed("member before main"));
                }
                let wire = frame.wire.ok_or_else(|| self.malformed("missing member wire identity"))?;
                self.file(header, frame.crypt, wire)?;
            }
            Block::End { more_volumes } => {
                if !self.main_seen {
                    return Err(self.malformed("end before main"));
                }
                if more_volumes {
                    self.volume = self.volume.checked_add(1).ok_or_else(|| {
                        MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::SourceContract)))
                    })?;
                    self.expected = crate::volume::next_volume_os(&self.expected).unwrap_or_else(|| {
                        let mut name = self.expected.clone();
                        name.push(".next");
                        name
                    });
                    self.usage
                        .charge(Resource::MetadataBytes, self.expected.len() as u64)
                        .map_err(|e| MapError::from_failure(self.volume, e))?;
                    self.phase = Phase::Open;
                } else {
                    if self.open.is_some() {
                        return Err(self.malformed("archive ends inside a split member"));
                    }
                    return Ok(Some(self.finish(MapEnd::Complete)));
                }
            }
            Block::Service(_) | Block::Unknown => {
                if !self.main_seen {
                    return Err(self.malformed("block before main"));
                }
            }
        }
        Ok(None)
    }

    fn crypt_error(&self, error: crate::crypto::Rar5CryptError) -> MapError {
        use crate::crypto::Rar5CryptError;
        let failure = super::framing::progressive_fault(crate::error::RarFault::new(
            crate::error::RarFailure::crypt(
                error,
                crate::error::RarScope::Header { volume: self.expected.clone().into() },
            ),
            crate::Error::Encrypted,
        ));
        match error {
            Rar5CryptError::UnsupportedVersion(_) | Rar5CryptError::KdfLimit(_) => {
                MapError::Unsupported { volume: self.volume, failure: Box::new(failure) }
            }
            _ => MapError::Malformed { volume: self.volume, failure: Box::new(failure) },
        }
    }

    fn charge(&self, resource: Resource, amount: u64) -> Result<(), MapError> {
        self.usage.charge(resource, amount).map_err(|e| MapError::from_failure(self.volume, e))
    }

    fn file(&mut self, header: FileHeader, crypt: MemberCrypt, wire: FileWire) -> Result<(), MapError> {
        let params = match crypt {
            Some(Err(error)) => return Err(self.crypt_error(error)),
            Some(Ok(params)) => Some(params),
            None => None,
        };
        let part = PhysicalPart::new(self.volume as usize, &header, crypt, &wire);
        self.charge(Resource::Parts, 1)?;
        self.charge(Resource::MetadataBytes, std::mem::size_of::<MapPiece>() as u64)?;
        let checks = MapChecks { crc32: part.checks.crc32, blake2sp: part.checks.blake2sp, keyed: part.checks.keyed };
        let packed = part.data_offset
            ..part.data_offset.checked_add(part.packed_size).ok_or_else(|| self.malformed("data size"))?;
        if let Some(mut open) = self.open.take() {
            if open.complete
                || !open.matches_continuation(&header, &wire)
                || continuation_issue(&open, &header).is_some()
                || open.wire.compression != wire.compression
                || open.wire.legacy.and_then(|w| w.crypt) != wire.legacy.and_then(|w| w.crypt)
            {
                return Err(self.malformed("member continuation identity"));
            }
            let stream_offset = open.packed_size;
            open.append(&header, &part).map_err(|e| self.fail(super::framing::progressive_fault(e)))?;
            let unpacked = open.unpacked_size;
            let total = open.packed_size;
            let member = self.members.last_mut().expect("open member is listed");
            member.unpacked_size = unpacked;
            member.packed_size = total;
            let out = member.mapping.out_of(stream_offset..total, unpacked);
            // A size learned late (RAR5 unknown size) fixes earlier pieces' output ranges too.
            for piece in &mut member.pieces {
                let len = piece.packed.end - piece.packed.start;
                piece.out = member.mapping.out_of(piece.stream_offset..piece.stream_offset + len, unpacked);
            }
            member.pieces.push(MapPiece {
                volume: self.volume,
                packed,
                header: wire.extent.clone(),
                stream_offset,
                out,
                checks,
                final_part: part.final_part,
            });
            if part.final_part {
                member.checks = Some(checks);
                member.complete = true;
            } else {
                self.open = Some(open);
            }
            return Ok(());
        }
        if header.split_before() {
            return Err(self.malformed("orphan continuation"));
        }
        self.charge(Resource::Entries, 1)?;
        let name = match header.format {
            RarFormat::Rar5 => String::from_utf8(wire.name.to_vec()).ok(),
            RarFormat::Rar4 => Some(header.name.clone()),
        };
        self.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<MapMember>() + wire.name.len() + name.as_ref().map_or(0, String::len)) as u64,
        )?;
        let stored = header.method == 0;
        let method = if stored {
            MapMethod::Stored
        } else {
            MapMethod::Compressed { id: header.rar4.map_or(u16::from(header.method), |r| u16::from(r.method)) }
        };
        let cipher = if let Some(params) = params {
            Some(CipherParams::Rar5 {
                kdf_count: params.kdf_count,
                salt: params.salt,
                iv: Some(params.iv),
                check: params.check,
                keyed_checks: params.tweaked_crc,
            })
        } else {
            wire.legacy.and_then(|w| w.crypt).and_then(|c| c.salt).map(|salt| CipherParams::Rar4 { salt })
        };
        let encrypted = header.encrypted;
        let mapping = match (stored, encrypted) {
            (false, _) => OutputMapping::None,
            (true, false) => OutputMapping::Direct,
            (true, true) => OutputMapping::CbcBlocks,
        };
        let unpacked_size = (!header.size_unknown()).then_some(header.unpacked_size);
        let out = mapping.out_of(0..part.packed_size, unpacked_size);
        let unix_mode = header.is_unix().then_some((header.attributes & 0xffff_ffff) as u32);
        let member = MapMember {
            ordinal: self.members.len() as u64,
            raw_name: wire.name.to_vec(),
            name,
            is_dir: header.is_dir(),
            unpacked_size,
            packed_size: part.packed_size,
            method,
            mapping,
            solid: header.solid,
            encrypted,
            cipher,
            checks: part.final_part.then_some(checks),
            mtime: header.mtime.map(|s| (s, header.mtime_nanos)),
            attributes: header.attributes,
            unix_mode,
            complete: part.final_part,
            pieces: vec![MapPiece {
                volume: self.volume,
                packed,
                header: wire.extent.clone(),
                stream_offset: 0,
                out,
                checks,
                final_part: part.final_part,
            }],
        };
        self.members.try_reserve(1).map_err(|_| self.malformed("member allocation"))?;
        self.members.push(member);
        if !part.final_part {
            let physical = PhysicalMember::new(header, wire, 0, &part)
                .map_err(|e| self.fail(super::framing::progressive_fault(e)))?;
            self.open = Some(physical);
        }
        Ok(())
    }
}

/// Failures a wrong key produces on the first header it decrypts.
fn header_integrity(failure: &ProgressiveFailure) -> bool {
    use crate::error::{RarFailure, RarIntegrityReason};
    match &failure.kind {
        FailureKind::ChecksumMismatch { scope: crate::progressive::ChecksumScope::Header, .. } => true,
        FailureKind::Rar(rar) => matches!(
            rar.as_ref(),
            RarFailure::Integrity { reason: RarIntegrityReason::HeaderCrc | RarIntegrityReason::HeaderFraming(_), .. }
                | RarFailure::EncryptedIntegrity { .. }
        ),
        _ => false,
    }
}
