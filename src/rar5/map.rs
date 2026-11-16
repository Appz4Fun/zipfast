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
//! one [`MapMember`] per logical member and one [`MapPiece`] per part header. In single-volume mode it reads one
//! volume of any position and lists its file headers as they are ([`VolumeMap`]).
use super::framing::{HeaderParser, ParserStep, PhysicalFrame};
use super::physical::{PhysicalMember, PhysicalPart, continuation_issue};
use super::reader::Block;
use super::{FileHeader, FileWire, MemberCrypt, RarFormat};
use crate::map::{
    CipherParams, Got, HeaderDamage, MapChecks, MapEnd, MapError, MapFormat, MapInput, MapMember, MapMethod,
    MapOptions, MapPiece, MemberMap, Opened, OutputMapping, VolumeEnd, VolumeMap, VolumeMember, Walked, read,
};
use crate::progressive::{FailureKind, ProgressiveFailure, Resource, SessionControl, Usage, VolumeRequest};
use std::{
    ffi::OsString,
    task::{Context, Poll},
};

const READ_CHUNK: u64 = 64 << 10;
const SCAN_CHUNK: usize = 4 << 10;

enum Phase {
    Open,
    Header,
}

/// What a single-volume walk has learned about its volume.
#[derive(Default)]
struct Single {
    main_read: bool,
    volume_number: Option<u32>,
    first_volume: bool,
    multi_volume: bool,
    new_naming: bool,
    has_next_volume: bool,
    members: Vec<VolumeMember>,
}

/// What a member's header says, shared by both modes.
struct Described {
    name: Option<String>,
    method: MapMethod,
    cipher: Option<CipherParams>,
    mapping: OutputMapping,
    unpacked_size: Option<u64>,
    unix_mode: Option<u32>,
}

/// RAR4 main header flags (`MHD_*`).
const MHD_NEWNUMBERING: u16 = 0x0010;
const MHD_FIRSTVOLUME: u16 = 0x0100;

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
    /// A header decrypted under the password, on any volume: later failures are damage, not a wrong password.
    proven: bool,
    /// Offset of the header being read on the current volume.
    header_start: Option<u64>,
    /// Offset of the last header parsed on the current volume, where a failure found in its frame lies.
    frame_start: Option<u64>,
    rar5_keys: Option<(u8, [u8; 16], crate::crypto::Rar5Keys)>,
    rar4_keys: Option<([u8; 8], [u8; 16], [u8; 16])>,
    members: Vec<MapMember>,
    open: Option<PhysicalMember>,
    /// Single-volume mode: one volume, read without regard to its position.
    single: Option<Box<Single>>,
}

impl RarWalker {
    pub(crate) fn new(options: &MapOptions, usage: Usage, single: bool) -> Self {
        let chunk = options.limits.read_chunk.clamp(1, READ_CHUNK) as usize;
        Self {
            parser: HeaderParser::from_start(options.first_name.clone().into(), usage.clone()).lenient_map(),
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
            header_start: None,
            frame_start: None,
            rar5_keys: None,
            rar4_keys: None,
            members: Vec::new(),
            open: None,
            single: single.then(Box::default),
        }
    }

    fn malformed(&self, reason: &'static str) -> MapError {
        MapError::Malformed {
            volume: self.volume,
            failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(reason))),
        }
    }

    /// A member list that could not grow: an allocation failure, never damage.
    fn allocation(&self) -> MapError {
        MapError::from_failure(self.volume, super::framing::progressive_fault(super::session::allocation()))
    }

    fn fail(&self, failure: ProgressiveFailure) -> MapError {
        if self.unproven && header_integrity(&failure) {
            return MapError::WrongPassword;
        }
        MapError::from_failure(self.volume, failure)
    }

    /// The archive format: the main header's, or the signature's when no main header was read. A walk finishes
    /// only after the signature has been found.
    fn map_format(&self) -> MapFormat {
        match self.format.unwrap_or_else(|| self.parser.format()) {
            RarFormat::Rar4 => MapFormat::Rar4,
            RarFormat::Rar5 => MapFormat::Rar5,
        }
    }

    fn finish(&mut self, end: MapEnd) -> Walked {
        if self.single.is_some() {
            return self.finish_volume(match end {
                MapEnd::Truncated { offset, .. } => VolumeEnd::Truncated { offset },
                _ => VolumeEnd::Complete,
            });
        }
        Walked::Map(MemberMap {
            format: self.map_format(),
            header_encrypted: self.header_encrypted.unwrap_or(false),
            header_cipher: self.header_cipher.clone(),
            complete: end == MapEnd::Complete,
            end,
            volumes: match end {
                MapEnd::MissingVolume { volume } => volume,
                _ => self.volume + 1,
            },
            members: std::mem::take(&mut self.members),
        })
    }

    fn finish_volume(&mut self, end: VolumeEnd) -> Walked {
        let single = self.single.take().expect("single-volume mode");
        Walked::Volume(VolumeMap {
            format: self.map_format(),
            main_read: single.main_read,
            volume_number: single.volume_number,
            first_volume: single.first_volume,
            multi_volume: single.multi_volume,
            new_naming: single.new_naming,
            has_next_volume: single.has_next_volume,
            solid: self.solid_archive.unwrap_or(false),
            header_encrypted: self.header_encrypted.unwrap_or(false),
            header_cipher: self.header_cipher.clone(),
            end,
            members: single.members,
        })
    }

    pub(crate) fn poll(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<Walked, MapError>> {
        match self.poll_inner(input, cx) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(map)) => Poll::Ready(Ok(map)),
            Err(e) => Poll::Ready(self.damaged(e)),
        }
    }

    /// Ends the walk at a damaged header once the main header (of volume 0, for a whole-archive walk) has been
    /// read, keeping what was read before it. Other failures, and damage before that point, fail the walk.
    fn damaged(&mut self, error: MapError) -> Result<Walked, MapError> {
        let started = match &self.single {
            Some(single) => single.main_read,
            None => self.volume > 0 || self.main_seen,
        };
        let Some(reason) = HeaderDamage::of(&error).filter(|_| started) else {
            return Err(error);
        };
        let offset = self.header_start.or(self.frame_start).unwrap_or_else(|| self.parser.header_offset());
        Ok(if self.single.is_some() {
            self.finish_volume(VolumeEnd::Damaged { offset, reason })
        } else {
            self.finish(MapEnd::Damaged { volume: self.volume, offset, reason })
        })
    }

    fn poll_inner(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Result<Poll<Walked>, MapError> {
        loop {
            if self.control.is_canceled() {
                return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled))));
            }
            match self.phase {
                Phase::Open => {
                    let request = VolumeRequest { index: self.volume, expected: self.expected.clone() };
                    match input.open(&request, cx).map_err(|e| MapError::from_failure(self.volume, e))? {
                        Opened::Ready => {
                            self.parser = HeaderParser::from_start(self.expected.clone().into(), self.usage.clone())
                                .lenient_map();
                            self.main_seen = false;
                            self.unproven = false;
                            self.header_start = None;
                            self.frame_start = None;
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
                            if let Some(walked) = self.legacy_keys(salt)? {
                                return Ok(Poll::Ready(walked));
                            }
                            continue;
                        }
                        ParserStep::Need { offset, len } => (offset, len),
                        ParserStep::End => return Err(self.fail(self.parser.truncated())),
                        ParserStep::Frame(_) => unreachable!("frames require input"),
                    };
                    let header_start = *self.header_start.get_or_insert(offset);
                    // The signature scan asks for one byte at a time; read it in whole chunks instead.
                    let want = if self.parser.scanning() { SCAN_CHUNK } else { len }.min(self.buffer.len());
                    let n = self.parked.take().unwrap_or(want);
                    match read(input, &self.usage, offset, &mut self.buffer[..n], cx)
                        .map_err(|e| MapError::from_failure(self.volume, e))?
                    {
                        Got::NotYet => {
                            self.parked = Some(n);
                            return Ok(Poll::Pending);
                        }
                        Got::Hole => return Err(MapError::HeaderHole { volume: self.volume, offset }),
                        Got::Eof => {
                            // A wrong key turns the first encrypted header's size into noise that usually runs past
                            // the end; a volume cut inside that header looks the same. Whole-archive walks call it a
                            // wrong password. Single-volume walks, whose input is often a prefix, call it a cut
                            // unless the decrypted start of the header is not a header a volume can hold there.
                            if self.unproven
                                && (self.single.is_none() || self.parser.encrypted_start_plausible() == Some(false))
                            {
                                return Err(MapError::WrongPassword);
                            }
                            if self.parser.scanning() {
                                return Err(if self.volume == 0 {
                                    MapError::NotArchive
                                } else {
                                    self.malformed("volume without a RAR signature")
                                });
                            }
                            return Ok(Poll::Ready(
                                self.finish(MapEnd::Truncated { volume: self.volume, offset: header_start }),
                            ));
                        }
                        Got::Filled(count) => {
                            if let Some(map) = self.feed(offset, count.min(n))? {
                                return Ok(Poll::Ready(map));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Feeds `count` buffered bytes read at `offset`. A chunk read during the signature scan can run past what
    /// the parser needs next; the rest is fed on while the parser keeps asking for the very next byte, and dropped
    /// once it skips ahead (over member data).
    fn feed(&mut self, offset: u64, count: usize) -> Result<Option<Walked>, MapError> {
        let mut at = 0;
        loop {
            let scanning = self.parser.scanning();
            let (used, step) = self.parser.advance(&self.buffer[at..count]).map_err(|e| self.fail(e))?;
            at += used;
            if scanning && !self.parser.scanning() {
                // The signature is behind us: the first header starts where it ends.
                self.header_start = Some(self.parser.header_offset());
            }
            let progressed = used > 0 || matches!(step, ParserStep::Frame(_) | ParserStep::LegacyKeyRequired { .. });
            match step {
                ParserStep::Frame(frame) => {
                    self.frame_start = Some(frame.extent.start);
                    self.header_start = None;
                    if let Some(map) = self.frame(frame)? {
                        return Ok(Some(map));
                    }
                }
                ParserStep::LegacyKeyRequired { salt } => {
                    if let Some(walked) = self.legacy_keys(salt)? {
                        return Ok(Some(walked));
                    }
                }
                ParserStep::Need { .. } | ParserStep::End => {}
            }
            if at == count || !matches!(self.phase, Phase::Header) {
                return Ok(None);
            }
            match self.parser.advance(&[]).map_err(|e| self.fail(e))?.1 {
                ParserStep::Need { offset: next, .. } if next == offset + at as u64 => {
                    self.header_start.get_or_insert(next);
                }
                ParserStep::LegacyKeyRequired { .. } => {}
                _ => return Ok(None),
            }
            if !progressed {
                return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::SourceContract))));
            }
        }
    }

    /// Supplies the RAR4 header key for `salt`. Returns the finished map when a single-volume walk has no password.
    fn legacy_keys(&mut self, salt: [u8; 8]) -> Result<Option<Walked>, MapError> {
        if self.header_cipher.is_none() {
            self.header_cipher = Some(CipherParams::Rar4 { salt });
        }
        let (key, iv) = match self.rar4_keys {
            Some((cached, key, iv)) if cached == salt => (key, iv),
            _ => {
                let Some(password) = self.password.as_deref().filter(|p| !p.is_empty()) else {
                    if self.single.is_some() {
                        // The salt that precedes the header has been read; the header starts at the salt.
                        let offset = self.header_start.unwrap_or(0);
                        return Ok(Some(self.finish_volume(VolumeEnd::Locked { offset })));
                    }
                    return Err(MapError::PasswordRequired);
                };
                let (key, iv) = super::member::controlled_legacy_keys(password, &salt, &self.usage, &self.control)
                    .map_err(|e| MapError::from_failure(self.volume, e))?;
                self.rar4_keys = Some((salt, key, iv));
                (key, iv)
            }
        };
        self.parser.set_legacy_keys(&key, iv).map_err(|e| self.fail(e))?;
        self.unproven = !self.proven;
        Ok(None)
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
    fn frame(&mut self, frame: PhysicalFrame) -> Result<Option<Walked>, MapError> {
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
                // An empty password is no password, as for RAR4.
                if self.single.is_some() && self.password.as_deref().is_none_or(str::is_empty) {
                    self.header_encrypted = Some(true);
                    return Ok(Some(self.finish_volume(VolumeEnd::Locked { offset: frame.extent.end })));
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
                if self.single.is_some() {
                    if self.main_seen {
                        return Err(self.malformed("duplicate main header"));
                    }
                    self.single_main(format, &main)?;
                } else if self.main_seen
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
                let wire = frame.wire.ok_or_else(|| {
                    MapError::from_failure(
                        self.volume,
                        super::framing::progressive_fault(crate::error::RarFault::new(
                            crate::error::RarFailure::Internal(crate::error::RarInternal::Invariant(
                                "missing member wire identity",
                            )),
                            crate::Error::Corrupt("missing member wire identity"),
                        )),
                    )
                })?;
                if self.single.is_some() {
                    self.volume_file(header, frame.crypt, wire)?;
                } else {
                    self.file(header, frame.crypt, wire)?;
                }
            }
            Block::End { more_volumes, volume_number } => {
                if !self.main_seen {
                    return Err(self.malformed("end before main"));
                }
                if self.single.is_some() {
                    let number =
                        volume_number.map(u32::try_from).transpose().map_err(|_| self.malformed("volume number"))?;
                    let single = self.single.as_mut().expect("single-volume mode");
                    single.has_next_volume = more_volumes;
                    // Only a volume of a set has a meaningful number; a stray one in a non-volume archive is ignored.
                    if let Some(number) = number.filter(|_| single.multi_volume) {
                        // RAR 2.x first volumes lack MHD_FIRSTVOLUME: a number of 0 makes the volume first. A first
                        // volume numbered otherwise contradicts itself.
                        if single.first_volume && number != 0 {
                            return Err(self.malformed("first volume with a nonzero volume number"));
                        }
                        single.volume_number = Some(number);
                        single.first_volume = number == 0;
                    }
                    return Ok(Some(self.finish_volume(VolumeEnd::Complete)));
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

    /// Whether a continuation part's RAR5 encryption record names the same key (KDF count and salt) as the
    /// member's first part. All parts are one CBC stream, so only the first part's IV is used and a later part
    /// restating a different one is accepted.
    fn same_cipher(&self, params: Option<&crate::crypto::Rar5CryptParams>) -> bool {
        let first = self.members.last().and_then(|m| m.cipher.as_ref());
        match (params, first) {
            (None, Some(CipherParams::Rar5 { .. })) => false,
            (None, _) => true,
            (Some(p), Some(CipherParams::Rar5 { kdf_count, salt, .. })) => *kdf_count == p.kdf_count && *salt == p.salt,
            (Some(_), _) => false,
        }
    }

    /// Name, method, cipher and output mapping of a member as its header states them. Charges `owner` bytes plus
    /// the names as metadata.
    fn describe(
        &self,
        header: &FileHeader,
        wire: &FileWire,
        params: Option<&crate::crypto::Rar5CryptParams>,
        owner: usize,
    ) -> Result<Described, MapError> {
        let name = match header.format {
            RarFormat::Rar5 => String::from_utf8(wire.name.to_vec()).ok(),
            // The lenient map parser leaves a legacy name that is not UTF-8 undecoded (empty); a decoded RAR 4.x
            // name is never empty.
            RarFormat::Rar4 => Some(header.name.clone()).filter(|name| !name.is_empty()),
        };
        self.charge(Resource::MetadataBytes, (owner + wire.name.len() + name.as_ref().map_or(0, String::len)) as u64)?;
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
            // As the extractor admits it: only version 29 with a salt is AES-128-CBC.
            wire.legacy.and_then(|w| w.crypt).map(|crypt| match super::LegacyCrypt::stored_salt(Some(crypt)) {
                Ok(salt) => CipherParams::Rar4 { salt },
                Err(_) => CipherParams::Rar4Legacy { unpack_version: crypt.version, salt: crypt.salt },
            })
        };
        let cbc = matches!(cipher, Some(CipherParams::Rar5 { .. } | CipherParams::Rar4 { .. }));
        let mapping = match (stored, header.encrypted) {
            (false, _) => OutputMapping::None,
            (true, false) => OutputMapping::Direct,
            (true, true) if cbc => OutputMapping::CbcBlocks,
            (true, true) => OutputMapping::None,
        };
        Ok(Described {
            name,
            method,
            cipher,
            mapping,
            unpacked_size: (!header.size_unknown()).then_some(header.unpacked_size),
            unix_mode: header.is_unix().then_some((header.attributes & 0xffff_ffff) as u32),
        })
    }

    /// Records a single-volume walk's main header facts. The volume's position is reported, never checked.
    fn single_main(&mut self, format: RarFormat, main: &super::MainHeader) -> Result<(), MapError> {
        let volume_number = match format {
            RarFormat::Rar5 if main.flags & super::MHFL_VOLNUMBER != 0 => {
                Some(u32::try_from(main.volume_number).map_err(|_| self.malformed("volume number"))?)
            }
            // Only the first volume leaves the number out.
            RarFormat::Rar5 => Some(0),
            RarFormat::Rar4 => None,
        };
        let rar4 = main.rar4_flags.unwrap_or(0);
        let single = self.single.as_mut().expect("single-volume mode");
        single.main_read = true;
        single.multi_volume = main.is_volume();
        match format {
            RarFormat::Rar5 => {
                single.volume_number = volume_number;
                single.first_volume = volume_number == Some(0);
                single.new_naming = true;
            }
            RarFormat::Rar4 => {
                single.first_volume = !main.is_volume() || rar4 & MHD_FIRSTVOLUME != 0;
                single.volume_number = single.first_volume.then_some(0);
                single.new_naming = rar4 & MHD_NEWNUMBERING != 0;
            }
        }
        Ok(())
    }

    /// Lists one file header of a single-volume walk as it is: no continuation is matched against anything.
    fn volume_file(&mut self, header: FileHeader, crypt: MemberCrypt, wire: FileWire) -> Result<(), MapError> {
        let params = match crypt {
            Some(Err(error)) => return Err(self.crypt_error(error)),
            Some(Ok(params)) => Some(params),
            None => None,
        };
        let part = PhysicalPart::new(0, &header, crypt, &wire);
        self.charge(Resource::Parts, 1)?;
        self.charge(Resource::Entries, 1)?;
        let Described { name, method, cipher, mapping, unpacked_size, unix_mode } =
            self.describe(&header, &wire, params.as_ref(), std::mem::size_of::<VolumeMember>())?;
        let part_checks =
            MapChecks { crc32: part.checks.crc32, blake2sp: part.checks.blake2sp, keyed: part.checks.keyed };
        let packed = part.data_offset
            ..part.data_offset.checked_add(part.packed_size).ok_or_else(|| self.malformed("data size"))?;
        let member = VolumeMember {
            raw_name: wire.name.to_vec(),
            name,
            is_dir: header.is_dir(),
            unpacked_size,
            packed_size: part.packed_size,
            packed,
            header: wire.extent.clone(),
            split_before: header.split_before(),
            split_after: header.split_after(),
            method,
            mapping,
            solid: header.solid,
            encrypted: header.encrypted,
            cipher,
            part_checks,
            checks: part.final_part.then_some(part_checks),
            mtime: header.mtime.map(|s| (s, header.mtime_nanos)),
            dos_time: header.rar4.map(|r| r.dos_time),
            attributes: header.attributes,
            unix_mode,
        };
        let members = &mut self.single.as_mut().expect("single-volume mode").members;
        if members.try_reserve(1).is_err() {
            return Err(self.allocation());
        }
        members.push(member);
        Ok(())
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
                || !self.same_cipher(params.as_ref())
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
        let Described { name, method, cipher, mapping, unpacked_size, unix_mode } =
            self.describe(&header, &wire, params.as_ref(), std::mem::size_of::<MapMember>())?;
        let encrypted = header.encrypted;
        let out = mapping.out_of(0..part.packed_size, unpacked_size);
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
            dos_time: header.rar4.map(|r| r.dos_time),
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
        self.members.try_reserve(1).map_err(|_| self.allocation())?;
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
