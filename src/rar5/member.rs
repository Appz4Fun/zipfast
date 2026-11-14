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

//! Source-independent member cipher and decoder state, shared with complete extraction.
use super::unpack::{Sink, Unpacker};
use crate::batch;
use crate::error::{Error, RarFailure, RarIntegrityReason, Result};
use crate::extract::EntryContext;

pub(crate) struct PendingCipher {
    pub(crate) aes: crate::crypto::AesKey,
    pub(crate) iv: [u8; 16],
    pub(crate) rem: Vec<u8>,
    pub(crate) hash_key: [u8; 32],
    pub(crate) stored_padding: Option<StoredCipherPadding>,
    pub(crate) blocks: Option<CipherBlocks>,
}

pub(crate) struct StoredCipherPadding {
    pub(crate) size: u64,
    pub(crate) skipped: usize,
}

#[derive(Default)]
pub(crate) struct CipherBlocks {
    header: Vec<u8>,
    left: usize,
    last: bool,
    ended: bool,
    padding: usize,
}

impl CipherBlocks {
    pub(crate) fn feed(&mut self, mut data: &[u8], decoder: &mut Unpacker, sink: &mut dyn Sink) -> Result<()> {
        while !data.is_empty() {
            if self.ended {
                if data.len() > 15 - self.padding {
                    return Err(Error::Corrupt("excess encrypted RAR5 padding"));
                }
                self.padding += data.len();
                return Ok(());
            }
            if self.left > 0 {
                let count = self.left.min(data.len());
                decoder.feed(&data[..count], sink)?;
                data = &data[count..];
                self.left -= count;
                self.ended = self.last && self.left == 0;
                continue;
            }
            self.header.push(data[0]);
            data = &data[1..];
            if let Some((_, payload, flags)) = crate::rar5::unpack::block_header(&self.header)? {
                decoder.feed(&self.header, sink)?;
                self.header.clear();
                self.left = payload;
                self.last = flags & 0x40 != 0;
                self.ended = self.last && self.left == 0;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if !self.ended || self.left != 0 || !self.header.is_empty() {
            return Err(Error::Truncated);
        }
        Ok(())
    }
}

impl PendingCipher {
    pub(crate) fn decrypt_selected(&mut self, chunk: &[u8], scratch: &mut Vec<u8>) {
        scratch.clear();
        scratch.extend_from_slice(&self.rem);
        scratch.extend_from_slice(chunk);
        let aligned = scratch.len() & !15;
        self.rem.clear();
        self.rem.extend_from_slice(&scratch[aligned..]);
        scratch.truncate(aligned);
        self.aes.decrypt_cbc_in_place(&mut self.iv, scratch);
    }

    pub(crate) fn take_blocks(&mut self) -> Option<CipherBlocks> {
        self.blocks.take()
    }

    pub(crate) fn put_blocks(&mut self, blocks: Option<CipherBlocks>) {
        self.blocks = blocks;
    }

    pub(crate) fn finish_selected(&self, context: &EntryContext) -> std::result::Result<(), RarFailure> {
        if !self.rem.is_empty() {
            return Err(context.integrity(RarIntegrityReason::IncompleteCipherBlock, false));
        }
        self.blocks
            .as_ref()
            .map_or(Ok(()), CipherBlocks::finish)
            .map_err(|error| *batch::decoder_failure(error, context.scope(), context.password).failure)
    }
}

/// Decoded evidence shared by progressive members and legacy Pending sinks.
pub(crate) struct InnerChecks {
    pub(crate) hasher: crate::crc32::Hasher,
    pub(crate) decoder_crc: bool,
    pub(crate) crc: Option<u32>,
    pub(crate) blake: Option<crate::blake2sp::Blake2sp>,
    pub(crate) bytes: u64,
}
impl InnerChecks {
    pub(crate) fn new(header: &super::FileHeader) -> Self {
        Self {
            hasher: crate::crc32::Hasher::new(),
            decoder_crc: header.format == super::RarFormat::Rar5 && header.method != 0 && !header.encrypted,
            crc: None,
            blake: header.blake2sp.map(|_| crate::blake2sp::Blake2sp::new()),
            bytes: 0,
        }
    }
    pub(crate) fn verify(
        &mut self,
        context: &EntryContext,
        size: Option<u64>,
        crc32: Option<u32>,
        blake2sp: Option<[u8; 32]>,
        hash_key: Option<&[u8; 32]>,
    ) -> std::result::Result<(), RarFailure> {
        let raw_crc = if self.decoder_crc { self.crc } else { Some(self.hasher.clone().finalize()) };
        let got_crc = hash_key.map_or(raw_crc, |key| raw_crc.map(|crc| crate::crypto::rar5_tweak_crc32(crc, key)));
        let crc_bad = crc32.is_some_and(|want| got_crc != Some(want));
        let blake_bad = match (blake2sp, self.blake.take()) {
            (Some(want), Some(got)) => {
                let digest = got.finish();
                hash_key.map_or(digest, |key| crate::crypto::rar5_tweak_blake2sp(&digest, key)) != want
            }
            (Some(_), None) => return Err(context.integrity(RarIntegrityReason::DeclaredHashUnavailable, false)),
            _ => false,
        };
        if crc_bad || blake_bad {
            return Err(
                context.integrity(RarIntegrityReason::FinalChecks { crc32: crc_bad, blake2sp: blake_bad }, true)
            );
        }
        if let Some(expected) = size
            && self.bytes != expected
        {
            return Err(context.integrity(RarIntegrityReason::DecodedSize { expected, actual: self.bytes }, true));
        }
        Ok(())
    }
}

impl PendingCipher {
    pub(crate) fn trim_stored<'a>(&mut self, chunk: &'a [u8], bytes: u64) -> Result<&'a [u8]> {
        let Some(padding) = &mut self.stored_padding else {
            return Ok(chunk);
        };
        let count = padding.size.saturating_sub(bytes).min(chunk.len() as u64) as usize;
        let skipped = chunk.len() - count;
        if skipped > 15 - padding.skipped {
            return Err(Error::Corrupt("excess encrypted RAR5 padding"));
        }
        padding.skipped += skipped;
        Ok(&chunk[..count])
    }
}

/// Pausing between calls leaves the AES remainder, CBC IV, compressed block header,
/// decoder window and checks in this object. A part boundary never resets CBC.
pub(crate) struct MemberMachine {
    pub(crate) cipher: Option<PendingCipher>,
    pub(crate) decoder: Option<Unpacker>,
    pub(crate) inner: Option<InnerChecks>,
    scratch: Vec<u8>,
    delivered: u64,
    part_crc: crate::crc32::Hasher,
    part_blake: Option<crate::blake2sp::Blake2sp>,
    part_bytes: u64,
    part_checks: bool,
    context: EntryContext,
    decoded_finished: bool,
    failed: bool,
}
impl MemberMachine {
    pub(crate) fn from_state(
        header: &super::FileHeader,
        context: EntryContext,
        cipher: Option<PendingCipher>,
        decoder: Option<Unpacker>,
        delivered: u64,
    ) -> Self {
        Self {
            cipher,
            decoder,
            inner: None,
            scratch: Vec::new(),
            delivered,
            part_crc: crate::crc32::Hasher::new(),
            part_blake: header.blake2sp.filter(|_| header.split_after()).map(|_| crate::blake2sp::Blake2sp::new()),
            part_bytes: 0,
            part_checks: header.split_after(),
            context,
            decoded_finished: false,
            failed: false,
        }
    }
    pub(crate) fn begin_part(&mut self, part: &super::physical::PhysicalPart) {
        self.part_crc = crate::crc32::Hasher::new();
        self.part_blake = (!part.final_part && part.checks.blake2sp.is_some()).then(crate::blake2sp::Blake2sp::new);
        self.part_bytes = 0;
        self.part_checks = !part.final_part;
    }
    fn packed(&mut self, bytes: &[u8]) -> Result<()> {
        self.part_bytes =
            self.part_bytes.checked_add(bytes.len() as u64).ok_or(Error::Corrupt("packed size overflow"))?;
        if self.part_checks {
            self.part_crc.update(bytes);
            if let Some(hash) = &mut self.part_blake {
                hash.update(bytes);
            }
        }
        Ok(())
    }
    pub(crate) fn feed_core(&mut self, bytes: &[u8], sink: &mut dyn Sink) -> Result<()> {
        self.packed(bytes)?;
        if let Some(cipher) = &mut self.cipher {
            cipher.decrypt_selected(bytes, &mut self.scratch);
            match &mut self.decoder {
                Some(decoder) => cipher.blocks.as_mut().ok_or(Error::Corrupt("missing encrypted block state"))?.feed(
                    &self.scratch,
                    decoder,
                    sink,
                ),
                None => {
                    let plain = cipher.trim_stored(&self.scratch, self.delivered)?;
                    if plain.is_empty() {
                        return Ok(());
                    }
                    sink.put(plain)?;
                    self.delivered = self
                        .delivered
                        .checked_add(plain.len() as u64)
                        .ok_or(Error::Corrupt("decoded size overflow"))?;
                    Ok(())
                }
            }
        } else {
            match &mut self.decoder {
                Some(decoder) => decoder.feed(bytes, sink),
                None => sink.put(bytes),
            }
        }
    }
    pub(crate) fn feed_shared_core(
        &mut self,
        piece: &std::sync::Arc<super::reader::Piece>,
        range: std::ops::Range<usize>,
        sink: &mut dyn Sink,
    ) -> Result<()> {
        if self.cipher.is_some() {
            return self.feed_core(&piece.bytes()[range], sink);
        }
        self.packed(&piece.bytes()[range.clone()])?;
        match &mut self.decoder {
            Some(decoder) => decoder.feed_shared(piece, range, sink),
            None => sink.put(&piece.bytes()[range]),
        }
    }
    pub(crate) fn feed(&mut self, bytes: &[u8], sink: &mut dyn Sink) -> crate::progressive::ProgressiveResult<()> {
        if self.failed {
            return Err(crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput));
        }
        // The same feed core serves the legacy sink, which owns its InnerChecks.
        let mut checks = self.inner.take().ok_or_else(|| {
            crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput)
        })?;
        let result = self.feed_core(bytes, &mut CheckingSink { checks: &mut checks, sink });
        self.inner = Some(checks);
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(|e| {
            super::framing::progressive_fault(batch::decoder_failure(e, self.context.scope(), self.context.password))
        })
    }
    pub(crate) fn finish_part(
        &mut self,
        part: &super::physical::PhysicalPart,
    ) -> crate::progressive::ProgressiveResult<()> {
        let result = self.finish_part_core(part);
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(|failure| {
            super::framing::progressive_fault(crate::error::RarFault::new(
                failure,
                Error::Corrupt("packed member part"),
            ))
        })
    }
    pub(crate) fn finish_part_core(
        &mut self,
        part: &super::physical::PhysicalPart,
    ) -> std::result::Result<(), RarFailure> {
        if self.part_bytes != part.packed_size {
            return Err(self.context.integrity(RarIntegrityReason::TruncatedData, false));
        }
        if part.final_part {
            return Ok(());
        }
        let key = self.cipher.as_ref().filter(|_| part.checks.keyed).map(|c| &c.hash_key);
        verify_packed(&self.context, part.checks, self.part_crc.clone(), self.part_blake.take(), key)
    }
    pub(crate) fn finish_member(
        &mut self,
        member: &super::physical::PhysicalMember,
    ) -> crate::progressive::ProgressiveResult<()> {
        if self.failed || !self.decoded_finished {
            return Err(crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput));
        }
        if !member.complete {
            return Err(crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Truncated));
        }
        if let Some(cipher) = &self.cipher {
            cipher.finish_selected(&self.context).map_err(|e| {
                crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Rar(Box::new(e)))
            })?;
        }
        let checks = member.final_checks.ok_or_else(|| {
            crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput)
        })?;
        let key = self.cipher.as_ref().filter(|_| checks.keyed).map(|c| &c.hash_key);
        self.inner
            .as_mut()
            .ok_or_else(|| {
                crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput)
            })?
            .verify(&self.context, member.unpacked_size, checks.crc32, checks.blake2sp, key)
            .map_err(|e| crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Rar(Box::new(e))))
    }
    pub(crate) fn finish_decode(&mut self, sink: &mut dyn Sink) -> crate::progressive::ProgressiveResult<()> {
        if let Some(cipher) = &self.cipher {
            cipher.finish_selected(&self.context).map_err(|e| {
                crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Rar(Box::new(e)))
            })?;
        }
        if let Some(decoder) = &mut self.decoder {
            decoder
                .finish(&mut CheckingSink {
                    checks: self.inner.as_mut().ok_or_else(|| {
                        crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput)
                    })?,
                    sink,
                })
                .map_err(|e| {
                    super::framing::progressive_fault(batch::decoder_failure(
                        e,
                        self.context.scope(),
                        self.context.password,
                    ))
                })?;
        }
        self.decoded_finished = true;
        Ok(())
    }
    pub(crate) fn into_part_hashes(self) -> (crate::crc32::Hasher, Option<crate::blake2sp::Blake2sp>) {
        (self.part_crc, self.part_blake)
    }
}
struct CheckingSink<'a> {
    checks: &'a mut InnerChecks,
    sink: &'a mut dyn Sink,
}
impl Sink for CheckingSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let next = self.checks.bytes.checked_add(bytes.len() as u64).ok_or(Error::Corrupt("decoded size overflow"))?;
        self.sink.put(bytes)?;
        if !self.checks.decoder_crc {
            self.checks.hasher.update(bytes);
        }
        if let Some(hash) = &mut self.checks.blake {
            hash.update(bytes);
        }
        self.checks.bytes = next;
        Ok(())
    }
    fn wants_crc(&self) -> bool {
        self.checks.decoder_crc
    }
    fn crc(&mut self, crc: u32) {
        self.checks.crc = Some(crc);
    }
}
pub(crate) fn verify_packed(
    context: &EntryContext,
    checks: super::session::RarChecks,
    crc: crate::crc32::Hasher,
    blake: Option<crate::blake2sp::Blake2sp>,
    key: Option<&[u8; 32]>,
) -> std::result::Result<(), RarFailure> {
    let crc_bad = checks.crc32.is_some_and(|want| {
        let raw = crc.finalize();
        key.map_or(raw, |k| crate::crypto::rar5_tweak_crc32(raw, k)) != want
    });
    let blake_bad = match (checks.blake2sp, blake) {
        (Some(want), Some(hash)) => {
            let digest = hash.finish();
            key.map_or(digest, |k| crate::crypto::rar5_tweak_blake2sp(&digest, k)) != want
        }
        (Some(_), None) => return Err(context.integrity(RarIntegrityReason::DeclaredHashUnavailable, false)),
        _ => false,
    };
    if crc_bad || blake_bad {
        return Err(context.integrity(
            RarIntegrityReason::PackedPiece { crc32: crc_bad, blake2sp: blake_bad, keyed: key.is_some() },
            key.is_some(),
        ));
    }
    Ok(())
}

/// Shared production KDF meter. A fresh instance scopes derivation work while Usage
/// retains the cumulative session count; neither lock is held during hashing.
pub(crate) struct KdfMeter<'a> {
    pub(crate) usage: &'a crate::progressive::Usage,
    pub(crate) control: &'a crate::progressive::SessionControl,
    blocks: u64,
}
impl crate::crypto::KdfControl for KdfMeter<'_> {
    fn charge(&mut self, blocks: u64) -> std::result::Result<(), crate::crypto::KdfControlError> {
        use crate::crypto::KdfControlError;
        use crate::progressive::{FailureKind, Resource};
        if self.control.is_canceled() {
            return Err(KdfControlError::Canceled);
        }
        let attempted = self.blocks.checked_add(blocks).ok_or(crate::crypto::KdfControlError::Limit {
            resource: crate::progressive::Resource::KdfDerivationBlocks,
            limit: 1 << 22,
            attempted: u64::MAX,
        })?;
        let map = |e: crate::progressive::ProgressiveFailure| match e.kind {
            FailureKind::Limit { resource, limit, attempted } => KdfControlError::Limit { resource, limit, attempted },
            _ => unreachable!("Usage reports typed resource limits"),
        };
        self.usage.check(Resource::KdfDerivationBlocks, attempted).map_err(map)?;
        self.usage.charge(Resource::KdfSessionBlocks, blocks).map_err(map)?;
        self.blocks = attempted;
        Ok(())
    }
}
pub(crate) fn controlled_keys(
    password: &str,
    params: crate::crypto::Rar5CryptParams,
    usage: &crate::progressive::Usage,
    control: &crate::progressive::SessionControl,
    scope: crate::error::RarScope,
) -> crate::progressive::ProgressiveResult<crate::crypto::Rar5Keys> {
    use crate::progressive::{FailureKind, ProgressiveFailure, Resource};
    if control.is_canceled() {
        return Err(ProgressiveFailure::new(FailureKind::Canceled));
    }
    usage.check(Resource::PasswordUtf8Bytes, password.len() as u64)?;
    usage.check(Resource::PasswordEncodedBytes, password.len() as u64)?;
    usage.check(Resource::KdfExponent, u64::from(params.kdf_count))?;
    crate::crypto::derive_rar5_keys_controlled(
        password,
        params.kdf_count,
        &params.salt,
        params.check,
        &mut KdfMeter { usage, control, blocks: 0 },
    )
    .map_err(|error| match error {
        crate::crypto::ControlledKdfError::Crypt(error) => super::framing::progressive_fault(
            crate::error::RarFault::new(RarFailure::crypt(error, scope), Error::Encrypted),
        ),
        crate::crypto::ControlledKdfError::Control(crate::crypto::KdfControlError::Canceled) => {
            ProgressiveFailure::new(FailureKind::Canceled)
        }
        crate::crypto::ControlledKdfError::Control(crate::crypto::KdfControlError::Limit {
            resource,
            limit,
            attempted,
        }) => ProgressiveFailure::new(FailureKind::Limit { resource, limit, attempted }),
    })
}
impl PendingCipher {
    pub(crate) fn from_keys(
        params: crate::crypto::Rar5CryptParams,
        keys: crate::crypto::Rar5Keys,
        compressed: bool,
        size: Option<u64>,
    ) -> Self {
        Self {
            aes: crate::crypto::AesKey::new(&keys.key).expect("RAR5 key is AES256"),
            iv: params.iv,
            rem: Vec::new(),
            hash_key: keys.hash_key,
            stored_padding: if compressed { None } else { size.map(|size| StoredCipherPadding { size, skipped: 0 }) },
            blocks: compressed.then(CipherBlocks::default),
        }
    }
}
impl MemberMachine {
    pub(crate) fn new(
        header: &super::FileHeader,
        mut context: EntryContext,
        password: Option<&str>,
        usage: &crate::progressive::Usage,
        control: &crate::progressive::SessionControl,
    ) -> crate::progressive::ProgressiveResult<Self> {
        use crate::progressive::{FailureKind, ProgressiveFailure, Resource};
        if header.format != super::RarFormat::Rar5 || header.algorithm != 0 || header.method > 5 || header.solid {
            return Err(ProgressiveFailure::new(FailureKind::UnsupportedMethod));
        }
        let size = (!header.size_unknown()).then_some(header.unpacked_size);
        let cipher = if header.encrypted {
            let params = header
                .crypt
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::Malformed("member encryption record")))?;
            let password = password
                .filter(|p| !p.is_empty())
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?;
            let keys = controlled_keys(password, params, usage, control, context.scope())?;
            context.password = keys.evidence;
            Some(PendingCipher::from_keys(params, keys, header.method != 0, size))
        } else {
            None
        };
        let decoder = if header.method != 0 {
            let window = super::unpack::window_for_detailed(header.dictionary, size, false)
                .map_err(|e| super::framing::progressive_fault(e.detailed(context.scope())))?;
            usage.check(Resource::DecoderWindow, window.size)?;
            let mut decoder = Unpacker::new_detailed(window)
                .map_err(|e| super::framing::progressive_fault(e.detailed(context.scope())))?;
            decoder.next_file(size);
            Some(decoder)
        } else {
            None
        };
        let mut machine = Self::from_state(header, context, cipher, decoder, 0);
        machine.inner = Some(InnerChecks::new(header));
        Ok(machine)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        framing::{HeaderParser, ParserStep},
        physical::{PhysicalMember, PhysicalModel, PhysicalPart},
        reader::{Block, Volume},
    };
    use super::*;
    use crate::progressive::{FailureKind, ProgressiveLimits, Resource, SessionControl, Usage};
    fn context() -> EntryContext {
        EntryContext {
            entry: crate::extract::RarEntryIdentity { index: Some(0), order: 0, name: String::new() },
            method: 0,
            password: crate::error::RarPasswordEvidence::NotEncrypted,
        }
    }
    #[test]
    fn production_kdf_meter_enforces_configured_fields_and_cumulative_session_work() {
        let params = crate::crypto::Rar5CryptParams {
            kdf_count: 3,
            salt: [7; 16],
            iv: [0; 16],
            check: None,
            tweaked_crc: false,
        };
        for resource in [Resource::PasswordUtf8Bytes, Resource::PasswordEncodedBytes, Resource::KdfExponent] {
            let mut limits = ProgressiveLimits::default();
            match resource {
                Resource::PasswordUtf8Bytes => limits.password_utf8_bytes = 0,
                Resource::PasswordEncodedBytes => limits.password_encoded_bytes = 0,
                Resource::KdfExponent => limits.kdf_exponent = 0,
                _ => unreachable!(),
            }
            assert!(
                matches!(controlled_keys("secret",params,&Usage::new(limits),&SessionControl::default(),context().scope()),
                Err(crate::progressive::ProgressiveFailure {kind:FailureKind::Limit {resource:actual,..},..}) if actual==resource)
            );
        }
        let usage = Usage::new(ProgressiveLimits { kdf_session_blocks: 50, ..ProgressiveLimits::default() });
        let control = SessionControl::default();
        controlled_keys("secret", params, &usage, &control, context().scope()).unwrap();
        assert!(matches!(
            controlled_keys("secret", params, &usage, &control, context().scope()),
            Err(crate::progressive::ProgressiveFailure {
                kind: FailureKind::Limit { resource: Resource::KdfSessionBlocks, .. },
                ..
            })
        ));
        control.cancel();
        assert!(matches!(
            controlled_keys("secret", params, &usage, &control, context().scope()),
            Err(crate::progressive::ProgressiveFailure { kind: FailureKind::Canceled, .. })
        ));
    }
    #[test]
    fn stored_cbc_keeps_remainder_padding_and_inner_checks_across_non_aligned_parts() {
        let params = crate::crypto::Rar5CryptParams {
            kdf_count: 1,
            salt: [7; 16],
            iv: [9; 16],
            check: None,
            tweaked_crc: false,
        };
        for size in [0, 1, 15, 16, 17, 31, 32, 33] {
            let plain = vec![b'a'; size];
            let mut padded = plain.clone();
            padded.resize(size.next_multiple_of(16), 0);
            let keys = crate::crypto::derive_rar5_keys("secret", 1, &params.salt, None).unwrap();
            let ciphertext = crate::crypto::encrypt_cbc(&keys.key, &params.iv, &padded).unwrap();
            for split in 0..=ciphertext.len() {
                let mut first = super::super::FileHeader {
                    name: "f".into(),
                    unpacked_size: size as u64,
                    encrypted: true,
                    crypt: Some(params),
                    packed_size: split as u64,
                    crc32: Some(crate::crc32::hash(&ciphertext[..split])),
                    block_flags: super::super::HFL_SPLIT_AFTER,
                    ..Default::default()
                };
                let wire =
                    super::super::FileWire { name: std::sync::Arc::new(b"f".to_vec()), compression: 0, extent: 0..0 };
                let part1 = PhysicalPart::new(0, &first, Some(Ok(params)), &wire);
                let mut member = PhysicalMember::new(first.clone(), wire, 0, &part1).unwrap();
                let usage = Usage::new(ProgressiveLimits::default());
                let control = SessionControl::default();
                let mut machine = MemberMachine::new(&first, context(), Some("secret"), &usage, &control).unwrap();
                let mut output = Vec::new();
                let mut sink = |bytes: &[u8]| {
                    output.extend_from_slice(bytes);
                    Ok(())
                };
                machine.begin_part(&part1);
                for byte in &ciphertext[..split] {
                    machine.feed(&[*byte], &mut sink).unwrap();
                }
                machine.finish_part(&part1).unwrap();
                first.block_flags = super::super::HFL_SPLIT_BEFORE;
                first.packed_size = (ciphertext.len() - split) as u64;
                first.crc32 = Some(crate::crc32::hash(&plain));
                // Deliberately different continuation IV: RAR5 CBC must continue the initial stream.
                first.crypt.as_mut().unwrap().iv = [55; 16];
                let part2 = PhysicalPart::new(1, &first, Some(Ok(params)), &member.wire);
                member.append(&first, &part2).unwrap();
                machine.begin_part(&part2);
                for byte in &ciphertext[split..] {
                    machine.feed(&[*byte], &mut sink).unwrap();
                }
                machine.finish_part(&part2).unwrap();
                machine.finish_decode(&mut sink).unwrap();
                machine.finish_member(&member).unwrap();
                assert_eq!(output, plain, "size={size} split={split}");
            }
        }
    }
    #[test]
    #[ignore = "requires private six-volume fixture and pinned independent gold directories"]
    fn private_encrypted_fixtures_resume_at_every_cipher_and_compressed_header_position() {
        let fixtures =
            std::path::PathBuf::from(std::env::var_os("ZIPFAST_PRIVATE_RAR5_DIR").expect("fixture directory"));
        let gold = std::path::PathBuf::from(std::env::var_os("ZIPFAST_PRIVATE_RAR5_GOLD").expect("gold directory"));
        for set in ["encnam", "encdata"] {
            let usage = Usage::new(ProgressiveLimits::default());
            let control = SessionControl::default();
            let mut model = PhysicalModel::default();
            let mut volumes = Vec::new();
            for volume in 0..3 {
                let path = fixtures.join(format!("testfile5{set}.part{:02}.rar", volume + 1));
                let bytes = std::fs::read(&path).unwrap();
                assert_eq!(&bytes[..8], super::super::SIGNATURE);
                let mut parser = HeaderParser::progressive(path.clone(), 8, usage.clone());
                let mut at = 8;
                let mut complete = Volume::open_with_password(&path, Some("123")).unwrap();
                let mut legacy_files = Vec::new();
                while let Some(block) = complete.next_block().unwrap() {
                    if let Block::File(h) = block {
                        legacy_files.push(h);
                    }
                }
                let mut file_index = 0;
                while at < bytes.len() {
                    let (used, step) = parser.advance(&bytes[at..at + 1]).unwrap();
                    at += used;
                    match step {
                        ParserStep::Need { offset, len } => {
                            assert_eq!(offset, at as u64);
                            // No source callback is supplied while parked. Re-observing the state consumes nothing.
                            assert!(
                                matches!(parser.advance(&[]).unwrap(),(0,ParserStep::Need {offset:o,len:n}) if o==offset&&n==len)
                            );
                        }
                        ParserStep::Frame(frame) => {
                            at = frame.data_end as usize;
                            match frame.block {
                                Block::Crypt => parser
                                    .enable_encryption("123", frame.header_crypt.unwrap().unwrap(), &usage, &control)
                                    .unwrap(),
                                Block::File(header) => {
                                    assert_eq!(format!("{header:?}"), format!("{:?}", legacy_files[file_index]));
                                    file_index += 1;
                                    let wire = frame.wire.unwrap();
                                    assert_eq!(wire.extent, frame.extent);
                                    assert_eq!(wire.extent.end, header.data_at);
                                    let part = PhysicalPart::new(volume, &header, frame.crypt, &wire);
                                    if let Some(member) = model.members.last_mut() {
                                        assert_eq!(member.wire.name, wire.name);
                                        assert!(super::super::physical::continuation_issue(member, &header).is_none());
                                        member.append(&header, &part).unwrap();
                                    } else {
                                        model.members.push(PhysicalMember::new(header, wire, 0, &part).unwrap());
                                    }
                                    model.parts.push(part);
                                }
                                Block::End { .. } => break,
                                _ => {}
                            }
                        }
                        ParserStep::End => break,
                    }
                }
                assert_eq!(file_index, legacy_files.len());
                volumes.push(bytes);
            }
            assert_eq!(model.members.len(), 1);
            assert_eq!(model.parts.len(), 3);
            let member = &model.members[0];
            let expected = std::fs::read(gold.join(format!("{set}-unrar/testfile5{set}.dat"))).unwrap();
            let old = std::fs::read(gold.join(format!("{set}-zipfast/testfile5{set}.dat"))).unwrap();
            assert_eq!(expected, old);
            let current = tempfile::tempdir().unwrap();
            let options = crate::extract::Options {
                mode: crate::extract::Mode::Extract,
                dest: current.path().to_path_buf(),
                overwrite: crate::extract::Overwrite::Always,
                flatten: false,
                threads: Some(1),
                protected_paths: Default::default(),
                parallel_min: None,
            };
            let run = crate::extract::run_with_password(
                &fixtures.join(format!("testfile5{set}.part01.rar")),
                &options,
                Some("123"),
                |_| {},
            )
            .unwrap();
            assert_eq!(run.files, 1);
            assert!(run.errors.is_empty());
            assert_eq!(std::fs::read(current.path().join(format!("testfile5{set}.dat"))).unwrap(), expected);

            for chunk in 1..=16 {
                let usage = Usage::new(ProgressiveLimits::default());
                let mut machine = MemberMachine::new(&member.header, context(), Some("123"), &usage, &control).unwrap();
                let mut output = Vec::new();
                let mut sink = |bytes: &[u8]| {
                    output.extend_from_slice(bytes);
                    Ok(())
                };
                for part in &model.parts {
                    machine.begin_part(part);
                    let data = &volumes[part.volume]
                        [part.data_offset as usize..(part.data_offset + part.packed_size) as usize];
                    for bytes in data.chunks(chunk) {
                        machine.feed(bytes, &mut sink).unwrap();
                    }
                    machine.finish_part(part).unwrap();
                }
                machine.finish_decode(&mut sink).unwrap();
                machine.finish_member(member).unwrap();
                assert_eq!(output, expected, "{set} chunk={chunk}");
                assert_eq!(machine.inner.as_ref().unwrap().bytes, 68161);
            }
            eprintln!(
                "{set}: 3 physical volumes, raw names/header fields/wire extents equal; 16 chunk schedules; 68161 exact bytes equal complete Zipfast and pinned UnRAR gold"
            );
        }
    }
}
