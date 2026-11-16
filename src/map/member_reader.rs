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

//! Streams a stored member's plaintext from an arbitrary output offset, reading only the packed bytes that offset
//! needs. See `docs/extract-member-from.md`.

use super::{
    CipherParams, Got, MapInput, MapMember, MapMethod, MapOptions, MemberMap, MemoryInput, Opened, OutputMapping,
    SourceInput, read,
};
use crate::progressive::{
    ChecksumAlgorithm, FailureKind, ProgressiveFailure, Resource, Usage, VolumeRequest, VolumeSource,
};
use std::{
    ffi::OsString,
    io::Write,
    ops::Range,
    task::{Context, Poll, Waker},
};

/// Bytes of the WinZip AES authentication code that follows the ciphertext.
const AES_TAG: u64 = 10;
/// Bytes of the ZipCrypto encryption header that precedes the data.
const ZIPCRYPTO_HEADER: u64 = 12;

/// Why a member cannot be read from an output offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnsupportedRead {
    /// Compressed data: output offsets do not map to packed offsets. Restart points are future work.
    Compressed { id: u16 },
    /// 7z data coded by its folder's coder chain ([`MapMethod::Coders`]).
    Coders,
    /// The member's unpacked size is not recorded, so where its output (and an encrypted stream's padding) ends is
    /// unknown.
    UnknownSize,
    /// ZipCrypto: each byte's keystream depends on all earlier plaintext, so only output offset 0 (or the end) can
    /// be read.
    SequentialCipher,
    /// RAR 4.x encryption other than AES-128 (an older unpack version, or version 29 without a salt).
    LegacyRar4Cipher,
    /// Encryption the map does not map, such as ZIP strong encryption or WinZip AES without a valid extra field.
    UnmappedCipher,
}

/// A typed failure to stream a member from an output offset.
///
/// Errors that happen while streaming carry `out`, the offset to resume from: every byte from the starting offset
/// up to `out` was returned (or written to the sink) and is correct as far as the reader could check. A caller
/// switching to another copy resumes at `out`. The one exception is [`Self::PartBad`] with `released: true`, where
/// bytes past `out` were returned too and must be discarded.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExtractFromError {
    /// The map has no member with this index.
    NoSuchMember { index: usize },
    /// The member cannot be read from this offset.
    Unsupported(UnsupportedRead),
    /// The starting offset lies past the member's end.
    OffsetPastEnd { offset: u64, size: u64 },
    /// The map lists the member's pieces only up to output offset `out` (a map with `complete: false`), short of
    /// its end.
    IncompleteMember { out: u64 },
    /// The member is encrypted and no password was given.
    PasswordRequired,
    /// The password check value (RAR 5.0), password verifier (WinZip AES) or check byte (ZipCrypto) rejects the
    /// password. RAR 4.x records none: a wrong password gives wrong plaintext, which only a check of the whole
    /// output (offset 0, or the caller's own verify) catches.
    WrongPassword,
    /// The source reported a permanent hole at `packed` in volume `volume`. Inside a checked part, whose plaintext
    /// is held back until its check passes, `out` is where that part's output starts.
    Hole { out: u64, volume: u32, packed: u64 },
    /// The volume source answered [`VolumeAnswer::Missing`](crate::progressive::VolumeAnswer::Missing) for
    /// `volume`.
    MissingVolume { out: u64, volume: u32 },
    /// Volume `volume` ended at `packed`, inside the member's data.
    Truncated { out: u64, volume: u32, packed: u64 },
    /// A part the stream covered from its first byte failed its own check: `part` is the index into
    /// [`MapMember::pieces`], `volume` its volume. RAR part checks cover packed bytes (ciphertext for encrypted
    /// members), so the bad bytes are in that volume. Plaintext of the part may already have been returned:
    /// `bad` is the output range it carries (for CBC, one more block, which decrypts with the part's last
    /// ciphertext block), clipped to what this reader produces. RAR 5.0 encrypted members' checks are keyed with
    /// the password: without a password check value, a wrong password fails them too.
    ///
    /// A checked part's plaintext is held back until its check passes, so none of `bad` was returned
    /// (`released: false`) and `out` is the offset reached. A part carrying more than
    /// [`MapOptions::part_hold_bytes`], or whose hold `temp_bytes` or the allocator refuses, is streamed unchecked
    /// instead (`released: true`): its bytes up to the reader's
    /// position were already returned, and `out` is `bad.start`, the offset the caller must rewind to and discard
    /// everything written from.
    PartBad { out: u64, released: bool, volume: u32, part: usize, which: ChecksumAlgorithm, bad: Range<u64> },
    /// Reading from offset 0 covered the whole member and its declared checksum does not match. Every byte was
    /// returned before the check.
    MemberBad { which: ChecksumAlgorithm },
    /// Reading from offset 0 covered the whole WinZip AES member and its authentication code does not match.
    AuthenticationFailed,
    /// The map's description of the member is inconsistent.
    Malformed(&'static str),
    /// A budget in [`ProgressiveLimits`](crate::progressive::ProgressiveLimits) was exhausted.
    Limit { resource: Resource, limit: u64, attempted: u64 },
    /// The source failed or broke its contract, or the read was canceled.
    Source(Box<ProgressiveFailure>),
    /// The volume source answered [`VolumeAnswer::Abort`](crate::progressive::VolumeAnswer::Abort).
    Aborted { volume: u32 },
    /// Writing to the sink failed. Bytes before `out` were written.
    Write { out: u64, error: std::io::Error },
    /// The reader already returned an error.
    AlreadyFailed,
}

impl std::fmt::Display for ExtractFromError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchMember { index } => write!(f, "no member {index} in the map"),
            Self::Unsupported(reason) => write!(f, "member cannot be read from an offset: {reason:?}"),
            Self::OffsetPastEnd { offset, size } => write!(f, "offset {offset} is past the member's end {size}"),
            Self::IncompleteMember { out } => write!(f, "the map lists the member only up to output {out}"),
            Self::PasswordRequired => write!(f, "the member is encrypted and needs a password"),
            Self::WrongPassword => write!(f, "wrong password for the member"),
            Self::Hole { out, volume, packed } => {
                write!(f, "hole in volume {volume} at {packed} (output reached {out})")
            }
            Self::MissingVolume { out, volume } => write!(f, "volume {volume} is missing (output reached {out})"),
            Self::Truncated { out, volume, packed } => {
                write!(f, "volume {volume} ends at {packed} inside member data (output reached {out})")
            }
            Self::PartBad { volume, part, which, bad, .. } => {
                write!(f, "part {part} in volume {volume} failed its {which:?} check (output {bad:?})")
            }
            Self::MemberBad { which } => write!(f, "member failed its {which:?} check"),
            Self::AuthenticationFailed => write!(f, "member failed its authentication code"),
            Self::Malformed(reason) => write!(f, "malformed member map: {reason}"),
            Self::Limit { resource, limit, attempted } => {
                write!(f, "limit {resource:?} exceeded ({attempted} > {limit})")
            }
            Self::Source(failure) => write!(f, "source failure: {failure}"),
            Self::Aborted { volume } => write!(f, "source aborted at volume {volume}"),
            Self::Write { out, error } => write!(f, "writing output at {out} failed: {error}"),
            Self::AlreadyFailed => write!(f, "the reader already failed"),
        }
    }
}

impl std::error::Error for ExtractFromError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(failure) => Some(failure.as_ref()),
            Self::Write { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl ExtractFromError {
    fn from_failure(failure: ProgressiveFailure) -> Self {
        use crate::error::RarFailure;
        match &failure.kind {
            FailureKind::PasswordRequired => Self::PasswordRequired,
            FailureKind::WrongPassword => Self::WrongPassword,
            FailureKind::Limit { resource, limit, attempted } => {
                Self::Limit { resource: *resource, limit: *limit, attempted: *attempted }
            }
            FailureKind::Rar(rar) => match rar.as_ref() {
                RarFailure::PasswordRequired { .. } => Self::PasswordRequired,
                RarFailure::WrongPassword { .. } => Self::WrongPassword,
                _ => Self::Source(Box::new(failure)),
            },
            _ => Self::Source(Box::new(failure)),
        }
    }
}

/// What the requested output range needs from the member's packed stream.
#[derive(Clone)]
struct Plan {
    mapping: OutputMapping,
    size: u64,
    out_offset: u64,
    /// Stream bytes to read.
    stream: Range<u64>,
    /// Whether the read covers the whole member, so its final checks apply.
    whole: bool,
}

impl Plan {
    fn new(member: &MapMember, out_offset: u64) -> Result<Self, ExtractFromError> {
        match member.method {
            MapMethod::Compressed { id } => {
                return Err(ExtractFromError::Unsupported(UnsupportedRead::Compressed { id }));
            }
            MapMethod::Coders => return Err(ExtractFromError::Unsupported(UnsupportedRead::Coders)),
            MapMethod::Stored => {}
        }
        let mapping = member.mapping;
        if mapping == OutputMapping::None {
            return Err(ExtractFromError::Unsupported(match member.cipher {
                Some(CipherParams::Rar4Legacy { .. }) => UnsupportedRead::LegacyRar4Cipher,
                _ => UnsupportedRead::UnmappedCipher,
            }));
        }
        let size = member.unpacked_size.ok_or(ExtractFromError::Unsupported(UnsupportedRead::UnknownSize))?;
        validate(member, mapping, size)?;
        if out_offset > size {
            return Err(ExtractFromError::OffsetPastEnd { offset: out_offset, size });
        }
        let overflow = ExtractFromError::Malformed("member size overflows");
        let whole = out_offset == 0;
        let stream = match mapping {
            OutputMapping::Direct => out_offset..size,
            OutputMapping::CbcBlocks => {
                let end = size.checked_next_multiple_of(16).ok_or(overflow)?;
                let block = out_offset & !15;
                if out_offset == size { end..end } else { block.saturating_sub(16)..end }
            }
            OutputMapping::Counter { skip } => {
                let end = skip.checked_add(size).ok_or(overflow)?;
                let tag = if whole { AES_TAG } else { 0 };
                skip + out_offset..end.checked_add(tag).ok_or(ExtractFromError::Malformed("member size overflows"))?
            }
            OutputMapping::Sequential { skip } => {
                if out_offset != 0 && out_offset != size {
                    return Err(ExtractFromError::Unsupported(UnsupportedRead::SequentialCipher));
                }
                0..skip.checked_add(size).ok_or(overflow)?
            }
            OutputMapping::None => unreachable!("refused above"),
        };
        let plan = Self { mapping, size, out_offset, stream, whole };
        if out_offset == size {
            return Ok(Self { stream: plan.stream.start..plan.stream.start, ..plan });
        }
        // The pieces are contiguous in stream order; the last one has to reach the end of the read.
        let covered = member.pieces.last().map_or(0, |p| p.stream_offset + (p.packed.end - p.packed.start));
        if covered < plan.stream.end {
            return Err(ExtractFromError::IncompleteMember { out: plan.out_of(covered) });
        }
        if let OutputMapping::Counter { skip } = mapping
            && whole
            && member.complete
            && member.packed_size != skip + size + AES_TAG
        {
            return Err(ExtractFromError::Malformed("WinZip AES data size"));
        }
        if let OutputMapping::Sequential { skip } = mapping
            && skip != ZIPCRYPTO_HEADER
        {
            return Err(ExtractFromError::Malformed("ZipCrypto header size"));
        }
        Ok(plan)
    }

    /// The output offset a stream offset maps to, clipped to the member.
    fn out_of(&self, stream: u64) -> u64 {
        let out = match self.mapping {
            OutputMapping::Counter { skip } | OutputMapping::Sequential { skip } => stream.saturating_sub(skip),
            _ => stream,
        };
        out.min(self.size)
    }
}

/// Checks that a map member (a public type the caller may have built or edited) describes a readable stream: pieces
/// contiguous from stream offset 0 with ordered ranges, encryption consistent with the mapping and the cipher, and
/// each piece's output range the one its stream range carries.
fn validate(member: &MapMember, mapping: OutputMapping, size: u64) -> Result<(), ExtractFromError> {
    use ExtractFromError::Malformed;
    let encrypted_mapping = !matches!(mapping, OutputMapping::Direct);
    if member.encrypted != encrypted_mapping {
        return Err(Malformed("encryption flag does not match the output mapping"));
    }
    let cipher_fits = matches!(
        (mapping, &member.cipher),
        (OutputMapping::Direct, None)
            | (
                OutputMapping::CbcBlocks,
                Some(
                    CipherParams::Rar5 { iv: Some(_), .. }
                        | CipherParams::Rar4 { .. }
                        | CipherParams::SevenZipAes { .. }
                )
            )
            | (OutputMapping::Counter { .. }, Some(CipherParams::WinZipAes { .. }))
            | (OutputMapping::Sequential { .. }, Some(CipherParams::ZipCrypto { .. }))
    );
    if !cipher_fits {
        return Err(Malformed("cipher parameters do not match the output mapping"));
    }
    let last = member.pieces.len().saturating_sub(1);
    if member.pieces.iter().take(last).any(|p| p.final_part) {
        return Err(Malformed("a piece before the last is marked final"));
    }
    let mut next = 0u64;
    for piece in &member.pieces {
        if piece.packed.start > piece.packed.end {
            return Err(Malformed("piece packed range is inverted"));
        }
        if piece.stream_offset != next {
            return Err(Malformed("pieces are not contiguous from stream offset 0"));
        }
        let len = piece.packed.end - piece.packed.start;
        next = next.checked_add(len).ok_or(Malformed("piece stream offsets overflow"))?;
        if piece.out != mapping.out_of(piece.stream_offset..next, Some(size)) {
            return Err(Malformed("piece output range does not match its stream range"));
        }
    }
    // The packed stream the mapping implies: no piece may reach past it, and a complete member fills it exactly.
    let overflow = Malformed("member size overflows");
    let expected = match mapping {
        OutputMapping::Direct => size,
        OutputMapping::CbcBlocks => size.checked_next_multiple_of(16).ok_or(overflow)?,
        OutputMapping::Counter { skip } => {
            skip.checked_add(size).and_then(|n| n.checked_add(AES_TAG)).ok_or(overflow)?
        }
        OutputMapping::Sequential { skip } => skip.checked_add(size).ok_or(overflow)?,
        OutputMapping::None => unreachable!("refused before validation"),
    };
    if next > expected {
        return Err(Malformed("pieces reach past the member's packed stream"));
    }
    if member.complete && (next != expected || member.pieces.last().is_some_and(|p| !p.final_part)) {
        return Err(Malformed("a complete member's pieces do not fill its packed stream"));
    }
    Ok(())
}

enum Cipher {
    Plain,
    Cbc {
        aes: crate::crypto::AesKey,
        /// The IV of the next block, once known.
        iv: Option<[u8; 16]>,
        /// Bytes of the previous ciphertext block collected while `iv` is None.
        collect: Vec<u8>,
        /// Ciphertext bytes short of a whole block.
        rem: Vec<u8>,
        /// Stream offset of `rem[0]`.
        rem_at: u64,
    },
    Ctr {
        aes: crate::crypto::AesKey,
        skip: u64,
        hmac: Option<crate::crypto::HmacSha1>,
        tag: Vec<u8>,
        ct_end: u64,
    },
    ZipCrypto {
        state: crate::crypto::ZipCrypto,
        check: u8,
        header: Vec<u8>,
    },
}

struct PartHash {
    crc: crate::crc32::Hasher,
    blake: Option<crate::blake2sp::Blake2sp>,
}

impl PartHash {
    fn new(blake: bool) -> Self {
        Self { crc: crate::crc32::Hasher::new(), blake: blake.then(crate::blake2sp::Blake2sp::new) }
    }
    fn update(&mut self, bytes: &[u8]) {
        self.crc.update(bytes);
        if let Some(blake) = &mut self.blake {
            blake.update(bytes);
        }
    }
    /// The first check that fails, if any.
    fn verify(self, checks: &super::MapChecks, key: Option<&[u8; 32]>) -> Option<ChecksumAlgorithm> {
        if let Some(want) = checks.crc32 {
            let raw = self.crc.finalize();
            if key.map_or(raw, |k| crate::crypto::rar5_tweak_crc32(raw, k)) != want {
                return Some(ChecksumAlgorithm::Crc32);
            }
        }
        if let (Some(want), Some(blake)) = (checks.blake2sp, self.blake) {
            let digest = blake.finish();
            if key.map_or(digest, |k| crate::crypto::rar5_tweak_blake2sp(&digest, k)) != want {
                return Some(ChecksumAlgorithm::Blake2sp);
            }
        }
        None
    }
}

enum Phase {
    Keys,
    Run,
    Done,
    Failed,
}

/// The format-independent reader over a [`MapInput`].
struct Core {
    member: MapMember,
    plan: Plan,
    options: MapOptions,
    usage: Usage,
    phase: Phase,
    cipher: Cipher,
    hash_key: Option<[u8; 32]>,
    /// The volume open on the input, and the name of the last volume asked for.
    volume: Option<u32>,
    names: Vec<OsString>,
    /// The volume count of a split ZIP set, whose volumes are named `.z01`, ..., `.zip`.
    split_zip: Option<u32>,
    piece: usize,
    stream_pos: u64,
    parked: Option<usize>,
    buffer: Vec<u8>,
    scratch: Vec<u8>,
    ready: Vec<u8>,
    ready_pos: usize,
    /// Output offset of the next byte to return.
    reached: u64,
    /// Output offset of the next plaintext byte to be produced.
    produced: u64,
    part: Option<PartHash>,
    /// Plaintext of the part being checked, held back until its check passes.
    held: Option<Vec<u8>>,
    /// `TempBytes` charged for `held`'s reservation while the part lasts.
    held_lease: Option<crate::progressive::Lease>,
    member_hash: Option<PartHash>,
    /// Whether the password is shown right: no encryption, a matching check value, or a passing check that
    /// covers plaintext or is keyed with the password.
    password_verified: bool,
}

impl Core {
    fn new(map: &MemberMap, index: usize, out_offset: u64, options: MapOptions) -> Result<Self, ExtractFromError> {
        let member = map.members.get(index).ok_or(ExtractFromError::NoSuchMember { index })?.clone();
        let plan = Plan::new(&member, out_offset)?;
        if member.encrypted && !plan.stream.is_empty() && options.password.as_deref().is_none_or(str::is_empty) {
            return Err(ExtractFromError::PasswordRequired);
        }
        let usage = Usage::new(options.limits.clone());
        let chunk = options.limits.read_chunk.clamp(16, 1 << 20) as usize;
        let piece = member
            .pieces
            .iter()
            .position(|p| plan.stream.start < p.stream_offset + (p.packed.end - p.packed.start))
            .unwrap_or(member.pieces.len());
        let member_hash = (plan.whole && !plan.stream.is_empty())
            .then(|| member.checks.filter(|c| c.crc32.is_some() || c.blake2sp.is_some()))
            .flatten()
            .map(|c| PartHash::new(c.blake2sp.is_some()));
        let mut core = Self {
            names: vec![options.first_name.clone()],
            split_zip: (map.format == super::MapFormat::Zip && map.volumes > 1).then_some(map.volumes),
            stream_pos: plan.stream.start,
            reached: out_offset,
            produced: plan.out_of(plan.stream.start),
            member,
            plan,
            options,
            usage,
            phase: Phase::Keys,
            cipher: Cipher::Plain,
            hash_key: None,
            volume: None,
            piece,
            parked: None,
            buffer: Vec::new(),
            scratch: Vec::new(),
            ready: Vec::new(),
            ready_pos: 0,
            part: None,
            held: None,
            held_lease: None,
            member_hash,
            password_verified: false,
        };
        core.password_verified = !core.member.encrypted;
        if core.plan.stream.is_empty() {
            core.phase = Phase::Done;
        } else {
            core.buffer.try_reserve_exact(chunk).map_err(|_| ExtractFromError::Malformed("read buffer"))?;
            core.buffer.resize(chunk, 0);
            core.start_part();
        }
        Ok(core)
    }

    /// Starts hashing the current piece when the read covers it from its first byte and it has its own checks.
    /// Its plaintext is held back until the check passes when the part carries at most
    /// [`MapOptions::part_hold_bytes`] of output.
    fn start_part(&mut self) {
        self.part = self.member.pieces.get(self.piece).and_then(|p| {
            let own = !p.final_part && (p.checks.crc32.is_some() || p.checks.blake2sp.is_some());
            (own && self.stream_pos == p.stream_offset).then(|| PartHash::new(p.checks.blake2sp.is_some()))
        });
        drop(self.take_held());
        if self.part.is_some() {
            let len = self.member.pieces[self.piece].packed.end - self.member.pieces[self.piece].packed.start;
            // Plaintext from the previous part's last partial CBC block can land here too.
            let reserve = len.saturating_add(16);
            // A reservation the budget or the allocator refuses streams the part unchecked instead: its check
            // still runs, and a failure reports `released: true`.
            if len <= self.options.part_hold_bytes
                && let Ok(lease) = self.usage.lease(Resource::TempBytes, reserve)
            {
                let mut held = Vec::new();
                if held.try_reserve_exact(reserve as usize).is_ok() {
                    self.held = Some(held);
                    self.held_lease = Some(lease);
                }
            }
        }
    }

    /// Ends the hold of the current part, returning its budget.
    fn take_held(&mut self) -> Option<Vec<u8>> {
        self.held_lease = None;
        self.held.take()
    }

    fn password(&self) -> Result<&str, ExtractFromError> {
        self.options.password.as_deref().filter(|p| !p.is_empty()).ok_or(ExtractFromError::PasswordRequired)
    }

    fn keys(&mut self) -> Result<(), ExtractFromError> {
        let plan = &self.plan;
        let cipher = match (&self.member.cipher, plan.mapping) {
            (_, OutputMapping::Direct) => Cipher::Plain,
            (Some(CipherParams::Rar5 { kdf_count, salt, iv, check, keyed_checks }), OutputMapping::CbcBlocks) => {
                let member_iv = iv.ok_or(ExtractFromError::Malformed("RAR 5.0 member without a data IV"))?;
                let params = crate::crypto::Rar5CryptParams {
                    kdf_count: *kdf_count,
                    salt: *salt,
                    iv: member_iv,
                    check: *check,
                    tweaked_crc: *keyed_checks,
                };
                let scope = crate::error::RarScope::Member { index: Some(self.member.ordinal) };
                let keys = crate::rar5::member::controlled_keys(
                    self.password()?,
                    params,
                    &self.usage,
                    &self.options.control,
                    scope,
                )
                .map_err(ExtractFromError::from_failure)?;
                self.hash_key = Some(keys.hash_key);
                if keys.evidence == crate::error::RarPasswordEvidence::VerifierMatched {
                    self.password_verified = true;
                }
                let aes = crate::crypto::AesKey::new(&keys.key).expect("AES-256 key");
                self.cbc(aes, member_iv)
            }
            (Some(CipherParams::Rar4 { salt }), OutputMapping::CbcBlocks) => {
                let (key, iv) = crate::rar5::member::controlled_legacy_keys(
                    self.password()?,
                    salt,
                    &self.usage,
                    &self.options.control,
                )
                .map_err(ExtractFromError::from_failure)?;
                self.cbc(crate::crypto::AesKey::new(&key).expect("AES-128 key"), iv)
            }
            (Some(CipherParams::SevenZipAes { num_cycles_power, salt, iv }), OutputMapping::CbcBlocks) => {
                let password = self.password()?;
                let fail = ExtractFromError::from_failure;
                self.usage.check(Resource::PasswordUtf8Bytes, password.len() as u64).map_err(fail)?;
                self.usage
                    .check(Resource::PasswordEncodedBytes, password.encode_utf16().count() as u64 * 2)
                    .map_err(fail)?;
                self.options.limits.check_seven_zip_kdf(*num_cycles_power).map_err(fail)?;
                let mut meter = crate::rar5::member::KdfMeter::new(&self.usage, &self.options.control);
                let key = match crate::crypto::derive_7z_key_controlled(password, salt, *num_cycles_power, &mut meter) {
                    None => return Err(ExtractFromError::Unsupported(UnsupportedRead::UnmappedCipher)),
                    Some(Ok(key)) => key,
                    Some(Err(crate::crypto::KdfControlError::Canceled)) => {
                        return Err(ExtractFromError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled))));
                    }
                    Some(Err(crate::crypto::KdfControlError::Limit { resource, limit, attempted })) => {
                        return Err(ExtractFromError::Limit { resource, limit, attempted });
                    }
                };
                let iv = *iv;
                self.cbc(crate::crypto::AesKey::new(&key).expect("AES-256 key"), iv)
            }
            (Some(CipherParams::WinZipAes { strength, salt, verifier, .. }), OutputMapping::Counter { skip }) => {
                if !(1..=3).contains(strength) {
                    return Err(ExtractFromError::Malformed("WinZip AES strength"));
                }
                let key_len = (usize::from(*strength) + 1) * 8;
                self.usage
                    .check(Resource::PasswordUtf8Bytes, self.password()?.len() as u64)
                    .map_err(ExtractFromError::from_failure)?;
                // PBKDF2-HMAC-SHA1, 1,000 rounds per 20-byte output block, about four SHA-1 compressions a round.
                let blocks = ((2 * key_len + 2).div_ceil(20) * 1000 * 4 + 4) as u64;
                crate::crypto::KdfControl::charge(
                    &mut crate::rar5::member::KdfMeter::new(&self.usage, &self.options.control),
                    blocks,
                )
                .map_err(|e| match e {
                    crate::crypto::KdfControlError::Canceled => {
                        ExtractFromError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled)))
                    }
                    crate::crypto::KdfControlError::Limit { resource, limit, attempted } => {
                        ExtractFromError::Limit { resource, limit, attempted }
                    }
                })?;
                let derived = crate::crypto::aes_derive(self.password()?.as_bytes(), salt, key_len)
                    .ok_or(ExtractFromError::Malformed("WinZip AES key derivation"))?;
                use subtle::ConstantTimeEq;
                if !bool::from(derived[2 * key_len..2 * key_len + 2].ct_eq(verifier)) {
                    return Err(ExtractFromError::WrongPassword);
                }
                self.password_verified = true;
                let aes = crate::crypto::AesKey::new(&derived[..key_len]).expect("WinZip AES key");
                let hmac = plan.whole.then(|| crate::crypto::HmacSha1::new(&derived[key_len..2 * key_len]));
                Cipher::Ctr { aes, skip, hmac, tag: Vec::new(), ct_end: skip + plan.size }
            }
            (Some(CipherParams::ZipCrypto { check }), OutputMapping::Sequential { .. }) => {
                let password = self.password()?;
                self.usage
                    .check(Resource::PasswordUtf8Bytes, password.len() as u64)
                    .map_err(ExtractFromError::from_failure)?;
                Cipher::ZipCrypto { state: crate::crypto::ZipCrypto::new(password), check: *check, header: Vec::new() }
            }
            _ => return Err(ExtractFromError::Malformed("cipher parameters do not match the output mapping")),
        };
        self.cipher = cipher;
        Ok(())
    }

    fn cbc(&self, aes: crate::crypto::AesKey, member_iv: [u8; 16]) -> Cipher {
        let start = self.plan.stream.start;
        // Block 0 decrypts with the member IV; any later block with the ciphertext block before it, read first.
        let iv = (start == 0).then_some(member_iv);
        let rem_at = if start == 0 { 0 } else { start + 16 };
        Cipher::Cbc { aes, iv, collect: Vec::new(), rem: Vec::new(), rem_at }
    }

    fn volume_name(&mut self, index: u32) -> Result<OsString, ExtractFromError> {
        if let Some(count) = self.split_zip {
            if index == 0 {
                return Ok(self.options.first_name.clone());
            }
            let name = super::zip_split::split_volume_name(&self.options.first_name, index, index + 1 == count);
            self.usage.charge(Resource::MetadataBytes, name.len() as u64).map_err(ExtractFromError::from_failure)?;
            return Ok(name);
        }
        while self.names.len() <= index as usize {
            let next = super::next_volume_name(self.names.last().expect("first name"));
            self.usage.charge(Resource::MetadataBytes, next.len() as u64).map_err(ExtractFromError::from_failure)?;
            self.names.push(next);
        }
        Ok(self.names[index as usize].clone())
    }

    /// Makes plaintext ready, or finishes. Returns true when `ready` holds bytes, false at the verified end.
    fn poll_fill(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<bool, ExtractFromError>> {
        match self.poll_fill_inner(input, cx) {
            Poll::Ready(Err(e)) => {
                self.phase = Phase::Failed;
                Poll::Ready(Err(e))
            }
            other => other,
        }
    }

    fn poll_fill_inner(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
    ) -> Poll<Result<bool, ExtractFromError>> {
        loop {
            if self.ready_pos < self.ready.len() {
                return Poll::Ready(Ok(true));
            }
            if matches!(self.phase, Phase::Failed) {
                return Poll::Ready(Err(ExtractFromError::AlreadyFailed));
            }
            if matches!(self.phase, Phase::Done) {
                return Poll::Ready(Ok(false));
            }
            if self.options.control.is_canceled() {
                return Poll::Ready(Err(ExtractFromError::Source(Box::new(ProgressiveFailure::new(
                    FailureKind::Canceled,
                )))));
            }
            self.ready.clear();
            self.ready_pos = 0;
            // A released hold became `ready`; once returned, drop back to the read chunk's size.
            self.ready.shrink_to(2 * self.buffer.len());
            match self.phase {
                Phase::Keys => {
                    if let Err(e) = self.keys() {
                        return Poll::Ready(Err(e));
                    }
                    self.phase = Phase::Run;
                }
                Phase::Run if self.stream_pos >= self.plan.stream.end => {
                    if let Err(e) = self.finish() {
                        return Poll::Ready(Err(e));
                    }
                    self.phase = Phase::Done;
                }
                Phase::Run => match self.step(input, cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                },
                Phase::Done | Phase::Failed => unreachable!("handled above"),
            }
        }
    }

    /// Reads one chunk of the current piece and turns it into plaintext.
    fn step(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Poll<Result<(), ExtractFromError>> {
        let Some(piece) = self.member.pieces.get(self.piece) else {
            return Poll::Ready(Err(ExtractFromError::IncompleteMember { out: self.reached }));
        };
        let (volume, packed_start, piece_start) = (piece.volume, piece.packed.start, piece.stream_offset);
        let piece_end = piece_start + (piece.packed.end - packed_start);
        if self.stream_pos >= piece_end {
            self.piece += 1;
            self.start_part();
            return Poll::Ready(Ok(()));
        }
        if self.volume != Some(volume) {
            let expected = match self.volume_name(volume) {
                Ok(name) => name,
                Err(e) => return Poll::Ready(Err(e)),
            };
            let request = VolumeRequest { index: volume, expected };
            match input.open(&request, cx) {
                Err(e) => return Poll::Ready(Err(ExtractFromError::from_failure(e))),
                Ok(Opened::Ready) => self.volume = Some(volume),
                Ok(Opened::Wait) => return Poll::Pending,
                Ok(Opened::Missing) => {
                    return Poll::Ready(Err(ExtractFromError::MissingVolume { out: self.reached, volume }));
                }
                Ok(Opened::Abort) => return Poll::Ready(Err(ExtractFromError::Aborted { volume })),
            }
        }
        let want = (piece_end.min(self.plan.stream.end) - self.stream_pos).min(self.buffer.len() as u64) as usize;
        let n = self.parked.take().unwrap_or(want);
        let at = packed_start + (self.stream_pos - piece_start);
        let mut buffer = std::mem::take(&mut self.buffer);
        let got = read(input, &self.usage, at, &mut buffer[..n], cx);
        let result = match got {
            Err(e) => Err(ExtractFromError::from_failure(e)),
            Ok(Got::NotYet) => {
                self.parked = Some(n);
                self.buffer = buffer;
                return Poll::Pending;
            }
            Ok(Got::Hole) => Err(ExtractFromError::Hole { out: self.reached, volume, packed: at }),
            Ok(Got::Eof) => Err(ExtractFromError::Truncated { out: self.reached, volume, packed: at }),
            Ok(Got::Filled(count)) => {
                let count = count.min(n);
                self.usage
                    .charge(Resource::SourceBytes, count as u64)
                    .map_err(ExtractFromError::from_failure)
                    .and_then(|()| self.absorb(&buffer[..count], piece_end))
            }
        };
        self.buffer = buffer;
        Poll::Ready(result)
    }

    /// Accounts `bytes` read at the current stream offset, all inside the current piece ending at `piece_end`.
    fn absorb(&mut self, bytes: &[u8], piece_end: u64) -> Result<(), ExtractFromError> {
        let start = self.stream_pos;
        self.stream_pos += bytes.len() as u64;
        if let Some(part) = &mut self.part {
            part.update(bytes);
            if self.stream_pos == piece_end {
                let part = self.part.take().expect("hashing this part");
                let held = self.take_held();
                let piece = &self.member.pieces[self.piece];
                let key = self.hash_key.as_ref().filter(|_| piece.checks.keyed);
                if let Some(which) = part.verify(&piece.checks, key) {
                    let out = piece.out.clone().unwrap_or(self.reached..self.reached);
                    let tail = if self.plan.mapping == OutputMapping::CbcBlocks { 16 } else { 0 };
                    let bad = out.start.max(self.plan.out_offset)..(out.end + tail).min(self.plan.size);
                    return Err(ExtractFromError::PartBad {
                        out: self.reached.min(bad.start),
                        released: held.is_none(),
                        volume: piece.volume,
                        part: self.piece,
                        which,
                        bad,
                    });
                }
                if key.is_some() {
                    self.password_verified = true;
                }
                if let Some(held) = held {
                    // Plaintext is read only once `ready` was drained, so the held buffer simply becomes it.
                    if self.ready.is_empty() {
                        self.ready = held;
                        self.ready_pos = 0;
                    } else {
                        self.ready.extend_from_slice(&held);
                    }
                }
            }
        }
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.clear();
        let result = self.decrypt(start, bytes, &mut scratch);
        self.scratch = scratch;
        result
    }

    fn decrypt(&mut self, start: u64, bytes: &[u8], scratch: &mut Vec<u8>) -> Result<(), ExtractFromError> {
        match &mut self.cipher {
            Cipher::Plain => {
                let at = self.produced;
                self.emit(at, bytes);
            }
            Cipher::Cbc { aes, iv, collect, rem, rem_at } => {
                let mut bytes = bytes;
                if iv.is_none() {
                    let take = (16 - collect.len()).min(bytes.len());
                    collect.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if collect.len() < 16 {
                        return Ok(());
                    }
                    *iv = Some(collect[..].try_into().expect("one block"));
                }
                scratch.extend_from_slice(rem);
                scratch.extend_from_slice(bytes);
                let aligned = scratch.len() & !15;
                rem.clear();
                rem.extend_from_slice(&scratch[aligned..]);
                scratch.truncate(aligned);
                aes.decrypt_cbc_in_place(iv.as_mut().expect("IV known"), scratch);
                let at = *rem_at;
                *rem_at += aligned as u64;
                self.emit(at, scratch);
            }
            Cipher::Ctr { aes, skip, hmac, tag, ct_end } => {
                // Ciphertext runs to `skip + size`; with the whole member read, the authentication code follows.
                let ct_len = (*ct_end).saturating_sub(start).min(bytes.len() as u64) as usize;
                let (ct, rest) = bytes.split_at(ct_len);
                tag.extend_from_slice(rest);
                if let Some(hmac) = hmac {
                    hmac.update(ct).ok_or(ExtractFromError::Malformed("WinZip AES data size"))?;
                }
                scratch.extend_from_slice(ct);
                let mut offset = start - *skip;
                let mut done = 0;
                while done < scratch.len() {
                    let block = offset / 16;
                    let within = (offset % 16) as usize;
                    // WinZip AES counts blocks from 1, little-endian.
                    let counter = (u128::from(block) + 1).to_le_bytes();
                    let keystream = aes.encrypt_block(&counter);
                    let take = (16 - within).min(scratch.len() - done);
                    for (byte, key) in scratch[done..done + take].iter_mut().zip(&keystream[within..]) {
                        *byte ^= key;
                    }
                    done += take;
                    offset += take as u64;
                }
                let at = start - *skip;
                self.emit(at, scratch);
            }
            Cipher::ZipCrypto { state, check, header } => {
                let mut bytes = bytes;
                if (header.len() as u64) < ZIPCRYPTO_HEADER {
                    let take = (ZIPCRYPTO_HEADER as usize - header.len()).min(bytes.len());
                    header.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if (header.len() as u64) < ZIPCRYPTO_HEADER {
                        return Ok(());
                    }
                    let mut decrypted = header.clone();
                    state.decrypt(&mut decrypted);
                    if decrypted[11] != *check {
                        return Err(ExtractFromError::WrongPassword);
                    }
                }
                scratch.extend_from_slice(bytes);
                state.decrypt(scratch);
                let at = self.produced;
                self.emit(at, scratch);
            }
        }
        Ok(())
    }

    /// Queues plaintext whose first byte is output offset `at`, clipped to the requested range.
    fn emit(&mut self, at: u64, plain: &[u8]) {
        let end = at + plain.len() as u64;
        self.produced = self.produced.max(end.min(self.plan.size));
        let from = at.max(self.plan.out_offset);
        let to = end.min(self.plan.size);
        if from >= to {
            return;
        }
        let bytes = &plain[(from - at) as usize..(to - at) as usize];
        if let Some(hash) = &mut self.member_hash {
            hash.update(bytes);
        }
        match &mut self.held {
            Some(held) => held.extend_from_slice(bytes),
            None => self.ready.extend_from_slice(bytes),
        }
    }

    /// Final checks once every stream byte was read.
    fn finish(&mut self) -> Result<(), ExtractFromError> {
        match &self.cipher {
            Cipher::Cbc { iv: None, .. } => return Err(ExtractFromError::Malformed("encrypted stream ends early")),
            Cipher::Cbc { rem, .. } if !rem.is_empty() => {
                return Err(ExtractFromError::Malformed("encrypted stream is not whole blocks"));
            }
            Cipher::Ctr { hmac: Some(hmac), tag, .. } => {
                use subtle::ConstantTimeEq;
                if tag.len() as u64 != AES_TAG || !bool::from(hmac.finish()[..AES_TAG as usize].ct_eq(tag)) {
                    return Err(ExtractFromError::AuthenticationFailed);
                }
                self.password_verified = true;
            }
            _ => {}
        }
        if self.part.is_some() || self.held.is_some() {
            return Err(ExtractFromError::Malformed("stream ended inside a checked part"));
        }
        if self.produced != self.plan.size || self.reached != self.plan.size {
            return Err(ExtractFromError::Malformed("stream ended before the member's size"));
        }
        if let (Some(hash), Some(checks)) = (self.member_hash.take(), self.member.checks) {
            let key = self.hash_key.as_ref().filter(|_| checks.keyed);
            if let Some(which) = hash.verify(&checks, key) {
                return Err(ExtractFromError::MemberBad { which });
            }
            // The checks cover the plaintext (or are keyed): a wrong password could not pass them.
            self.password_verified = true;
        }
        Ok(())
    }

    fn poll_read(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ExtractFromError>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_fill(input, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(true)) => {
                let ready = &self.ready[self.ready_pos..];
                let n = ready.len().min(buf.len());
                buf[..n].copy_from_slice(&ready[..n]);
                self.ready_pos += n;
                self.reached += n as u64;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_write_to(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        sink: &mut dyn Write,
    ) -> Poll<Result<u64, ExtractFromError>> {
        loop {
            match self.poll_fill(input, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(self.reached - self.plan.out_offset)),
                Poll::Ready(Ok(true)) => {
                    let ready = &self.ready[self.ready_pos..];
                    if let Err(error) = sink.write_all(ready) {
                        self.phase = Phase::Failed;
                        return Poll::Ready(Err(ExtractFromError::Write { out: self.reached, error }));
                    }
                    self.reached += ready.len() as u64;
                    self.ready_pos = self.ready.len();
                }
            }
        }
    }
}

/// Streams a stored member's plaintext from output offset `out_offset` to its end, reading only the packed bytes
/// that range needs through a [`VolumeSource`].
///
/// Built from a [`MemberMap`] of the archive (usually another copy of a release than the one that failed) and a
/// member index. [`RangeRead::NotYet`](crate::progressive::RangeRead::NotYet) and
/// [`VolumeAnswer::Wait`](crate::progressive::VolumeAnswer::Wait) make [`Self::poll_read`] return `Pending`; the
/// provider wakes the task, and the parked read is retried with the same length. A
/// [`RangeRead::Hole`](crate::progressive::RangeRead::Hole) is [`ExtractFromError::Hole`] with the output offset
/// reached, so the caller can switch copies again from there.
///
/// Supported: stored members, plain or encrypted with RAR 5.0 AES-256-CBC, RAR 4.x AES-128-CBC or WinZip AES, and
/// ZipCrypto from offset 0. See `docs/extract-member-from.md` for what is verified while streaming.
pub struct MemberReader {
    input: SourceInput,
    core: Core,
}

impl MemberReader {
    /// A reader of member `member` of `map` from output offset `out_offset`. `options` names the first volume (later
    /// volumes are asked for with the names [`next_volume_os`](crate::volume::next_volume_os) derives; `name.z02`,
    /// ..., `name.zip` for a split ZIP set; for another name ending in `.` and digits that `next_volume_os` does not
    /// handle (`set.7z.001`), the same number of digits counting up; else the name with `.next` appended. Providers
    /// usually key on [`VolumeRequest::index`]). `options` also carries the password, limits and cancellation.
    /// 7zAES members have no password check: a wrong password from a mid-member offset yields wrong plaintext
    /// without an error, so verify such output.
    ///
    /// Fails at once, before any read, when the member cannot be read from that offset.
    pub fn new(
        source: Box<dyn VolumeSource>,
        map: &MemberMap,
        member: usize,
        out_offset: u64,
        options: MapOptions,
    ) -> Result<Self, ExtractFromError> {
        Ok(Self { input: SourceInput::new(source), core: Core::new(map, member, out_offset, options)? })
    }

    /// Reads plaintext into `buf`. `Ok(0)` (for a nonempty `buf`) is the end of the member, after the checks
    /// that could run passed.
    pub fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, ExtractFromError>> {
        self.core.poll_read(&mut self.input, cx, buf)
    }

    /// Writes plaintext to `sink` until the member's end, returning the bytes written by this reader in total.
    /// It can be called again after `Pending`.
    pub fn poll_write_to(&mut self, cx: &mut Context<'_>, sink: &mut dyn Write) -> Poll<Result<u64, ExtractFromError>> {
        self.core.poll_write_to(&mut self.input, cx, sink)
    }

    /// The output offset of the next byte this reader returns.
    pub fn position(&self) -> u64 {
        self.core.reached
    }

    /// The member's size: the output offset where this reader ends.
    pub fn end(&self) -> u64 {
        self.core.plan.size
    }

    /// Whether the password is known to be right: the member is not encrypted, or its password check value (RAR
    /// 5.0) or verifier (WinZip AES, 16 bits) matched, or a check keyed with the password or covering the plaintext
    /// passed (a RAR 5.0 keyed part check, or the member check or authentication code read from offset 0).
    ///
    /// False after a successful read means the plaintext is unverified: RAR 4.x AES from an offset other than 0, or
    /// RAR 5.0 without a check value when the read covered no whole part, decrypts a wrong password to garbage
    /// without any error. The caller's verify of the finished output (`PartialFile::poll_verify`) settles it.
    pub fn password_verified(&self) -> bool {
        self.core.password_verified
    }
}

/// Writes the plaintext of member `member` of `map` from output offset `out_offset` to its end into `sink`, reading
/// volumes held in memory (in order, starting with the first; a volume the read does not need may be empty).
/// See [`MemberReader`].
pub fn extract_member_from(
    volumes: &[&[u8]],
    map: &MemberMap,
    member: usize,
    out_offset: u64,
    password: Option<&str>,
    sink: &mut impl Write,
) -> Result<ExtractedFrom, ExtractFromError> {
    extract_member_from_with(volumes, map, member, out_offset, MapOptions::new("").password(password), sink)
}

/// [`extract_member_from`] with explicit options.
pub fn extract_member_from_with(
    volumes: &[&[u8]],
    map: &MemberMap,
    member: usize,
    out_offset: u64,
    options: MapOptions,
    sink: &mut dyn Write,
) -> Result<ExtractedFrom, ExtractFromError> {
    let mut input = MemoryInput::new(volumes);
    let mut core = Core::new(map, member, out_offset, options)?;
    let mut cx = Context::from_waker(Waker::noop());
    match core.poll_write_to(&mut input, &mut cx, sink) {
        Poll::Ready(result) => {
            result.map(|written| ExtractedFrom { written, password_verified: core.password_verified })
        }
        Poll::Pending => unreachable!("memory input never waits"),
    }
}

/// What [`extract_member_from`] wrote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExtractedFrom {
    /// Plaintext bytes written to the sink.
    pub written: u64,
    /// Whether the password is known to be right; see [`MemberReader::password_verified`].
    pub password_verified: bool,
}
