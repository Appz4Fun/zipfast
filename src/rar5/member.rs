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
mod decoder;
use super::unpack::{Sink, Unpacker};
use crate::batch;
use crate::error::{Error, RarFailure, RarIntegrityReason, Result};
use crate::extract::EntryContext;
pub(crate) use decoder::{MemberDecoder, Rar4Owner, Rar4Stream};

pub(crate) struct PendingCipher {
    pub(crate) aes: crate::crypto::AesKey,
    pub(crate) iv: [u8; 16],
    pub(crate) rem: Vec<u8>,
    hash_key: Option<[u8; 32]>,
    pub(crate) stored_padding: Option<StoredCipherPadding>,
    pub(crate) blocks: Option<CipherBlocks>,
    recovery: Option<CbcAvailability>,
}

/// Availability belongs to cipher blocks, not physical volumes.
struct CbcAvailability {
    block: [u8; 16],
    used: usize,
    known: bool,
    previous_known: bool,
}
pub(crate) trait RecoverySink: Sink {
    fn hole(&mut self, len: u64) -> Result<()>;
    /// Ciphertext of the block at ciphertext stream offset `offset` that a later fill of an encrypted hole needs:
    /// the block just before a run of unavailable blocks, or a `CipherNeighbour` block whose own ciphertext
    /// arrived but whose previous block did not. Called before the hole run that needs it is flushed.
    fn cipher_block(&mut self, _offset: u64, _block: &[u8; 16]) -> Result<()> {
        Ok(())
    }
}
/// Where [`MemberMachine::resume_stored`] continues a stored member.
#[cfg(feature = "persistent-partials")]
pub(crate) struct StoredResume {
    pub delivered: u64,
    pub part_bytes: u64,
    pub member: Option<(crate::crc32::Hasher, Option<crate::blake2sp::Blake2sp>)>,
    pub part: Option<(crate::crc32::Hasher, Option<crate::blake2sp::Blake2sp>)>,
    pub iv: Option<[u8; 16]>,
    pub padding: usize,
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
        if !self.rem.is_empty() || self.recovery.as_ref().is_some_and(|r| r.used != 0) {
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
    pub(crate) decoder: Option<MemberDecoder>,
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
    pub(crate) missing: bool,
    part_missing: bool,
    /// Resumed after a restart: check mismatches mark the part or member missing instead of failing.
    resumed: bool,
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
            decoder: decoder.map(MemberDecoder::Rar5),
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
            missing: false,
            part_missing: false,
            resumed: false,
        }
    }
    /// Treats bytes already fed as missing after the fact (caller-declared damage), exactly as a hole fed in
    /// their place would be: the member's whole-content checks, and the current part's packed checks when the
    /// damage falls in it, are no longer evaluated against those bytes.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn declare_missing(&mut self, current_part: bool) {
        self.missing = true;
        if current_part {
            self.part_missing = true;
        }
    }
    /// Late damage on ciphertext already fed to a stored encrypted member: `range` is in ciphertext stream
    /// offsets. Output already produced is the caller's to invalidate; this taints the CBC state still pending, so
    /// the block being assembled and the block after the last complete one come out as holes.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn declare_cipher_damage(&mut self, range: std::ops::Range<u64>) {
        let start = self.delivered;
        if let Some(state) = self.cipher.as_mut().and_then(|cipher| cipher.recovery.as_mut()) {
            if start >= 16 && range.start < start && start - 16 < range.end {
                state.previous_known = false;
            }
            if range.start < start + state.used as u64 && start < range.end {
                state.known = false;
            }
        }
    }
    /// Continues a stored member a previous session left at output offset `delivered`, without feeding the bytes
    /// before it again. `part_bytes` are the current part's packed bytes before the resume point. `member` and
    /// `part` are the hash states of the output already produced (whole member, and the current part's share);
    /// `None` where that output has holes or fills, so the check is not judged while streaming, as after a hole.
    /// `iv` is an encrypted member's previous ciphertext block (`None` when it is unavailable, which makes the next
    /// block a hole), and `padding` the final padding bytes already behind the resume point.
    ///
    /// The machine starts the current part `part` first (it never saw the parts before it). Its checks of the
    /// resumed member are judged leniently: a mismatch marks the part (or member) missing instead of failing, so
    /// `poll_verify` reports it as `PartBad` or `Bad` from the output, and the session goes on with other members.
    /// Output before the resume point may come from fills that were never streamed, so a mismatch there must not
    /// end the session, as it would not without the restart.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn resume_stored(
        &mut self,
        part: &super::physical::PhysicalPart,
        resume: StoredResume,
    ) -> crate::progressive::ProgressiveResult<()> {
        use crate::progressive::{FailureKind, ProgressiveFailure};
        if self.failed || self.decoder.is_some() || self.delivered != 0 || self.part_bytes != 0 {
            return Err(ProgressiveFailure::new(FailureKind::InvalidCapability));
        }
        self.begin_part(part);
        self.resumed = true;
        let checks = self.inner.as_mut().ok_or_else(|| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
        match resume.member {
            Some((crc, blake)) => {
                checks.hasher = crc;
                if checks.blake.is_some() {
                    checks.blake = Some(blake.ok_or_else(|| ProgressiveFailure::new(FailureKind::InvalidCapability))?);
                }
            }
            None => self.missing = true,
        }
        checks.bytes = resume.delivered;
        self.delivered = resume.delivered;
        self.part_bytes = resume.part_bytes;
        match resume.part {
            Some((crc, blake)) => {
                self.part_crc = crc;
                if self.part_blake.is_some() {
                    self.part_blake = blake;
                    if self.part_blake.is_none() {
                        self.part_missing = true;
                    }
                }
            }
            None => self.part_missing = true,
        }
        if let Some(cipher) = &mut self.cipher {
            if !cipher.rem.is_empty() || cipher.recovery.is_some() {
                return Err(ProgressiveFailure::new(FailureKind::InvalidCapability));
            }
            if let Some(padding) = &mut cipher.stored_padding {
                padding.skipped = resume.padding;
            }
            let previous_known = match resume.iv {
                Some(iv) => {
                    cipher.iv = iv;
                    true
                }
                None => false,
            };
            cipher.recovery = Some(CbcAvailability { block: [0; 16], used: 0, known: true, previous_known });
        }
        Ok(())
    }
    pub(crate) fn part_missing(&self) -> bool {
        self.part_missing
    }
    pub(crate) fn reserve_progressive_scratch(
        &mut self,
        count: usize,
        usage: &crate::progressive::Usage,
    ) -> crate::progressive::ProgressiveResult<()> {
        use crate::progressive::{FailureKind, ProgressiveFailure, Resource};
        if let Some(cipher) = &mut self.cipher {
            let wanted =
                count.checked_add(16).ok_or_else(|| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
            if self.scratch.capacity() < wanted {
                let old = self.scratch.capacity();
                usage.charge(Resource::MetadataBytes, (wanted - old) as u64)?;
                self.scratch
                    .try_reserve_exact(wanted - self.scratch.len())
                    .map_err(|_| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
                usage.charge(Resource::MetadataBytes, self.scratch.capacity().saturating_sub(wanted) as u64)?;
            }
            if cipher.rem.capacity() < 16 {
                usage.charge(Resource::MetadataBytes, (16 - cipher.rem.capacity()) as u64)?;
                cipher
                    .rem
                    .try_reserve_exact(16 - cipher.rem.len())
                    .map_err(|_| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
                usage.charge(Resource::MetadataBytes, cipher.rem.capacity().saturating_sub(16) as u64)?;
            }
        }
        Ok(())
    }
    pub(crate) fn recovery_context(&self) -> EntryContext {
        self.context.clone()
    }
    pub(crate) fn begin_part(&mut self, part: &super::physical::PhysicalPart) {
        self.part_crc = crate::crc32::Hasher::new();
        self.part_blake = (!part.final_part && part.checks.blake2sp.is_some()).then(crate::blake2sp::Blake2sp::new);
        self.part_bytes = 0;
        self.part_checks = !part.final_part;
        self.part_missing = false;
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
                    decoder.rar5_mut()?,
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
                Some(decoder) => decoder.rar5_mut()?.feed(bytes, sink),
                None => sink.put(bytes),
            }
        }
    }
    /// Stored input with explicit availability. The ordinary cipher and packed-check
    /// state remain authoritative; only unavailable blocks suppress inner checks.
    pub(crate) fn feed_stored(
        &mut self,
        data: Option<&[u8]>,
        len: usize,
        sink: &mut dyn RecoverySink,
    ) -> crate::progressive::ProgressiveResult<()> {
        use crate::progressive::{FailureKind, ProgressiveFailure};
        if self.failed || self.decoder.is_some() || data.is_some_and(|d| d.len() != len) {
            return Err(ProgressiveFailure::new(FailureKind::InvalidCapability));
        }
        if data.is_none() && self.cipher.as_ref().is_some_and(|c| c.stored_padding.is_none()) {
            return Err(ProgressiveFailure::new(FailureKind::DataHole));
        }
        // Extraction admits the bounded scratch before entering this producer.
        // A feed can complete up to one retained CBC block in addition to len.
        // A hole decrypts nothing (every block it touches is unknown), so only data needs scratch.
        let decrypted = if data.is_some() { len } else { 0 };
        if self.cipher.is_some() && decrypted.checked_add(16).is_none_or(|n| n > self.scratch.capacity()) {
            return Err(ProgressiveFailure::new(FailureKind::InvalidCapability));
        }
        let result = (|| -> Result<()> {
            if let Some(bytes) = data {
                self.packed(bytes)?;
            } else {
                self.part_bytes =
                    self.part_bytes.checked_add(len as u64).ok_or(Error::Corrupt("packed size overflow"))?;
                self.part_missing = true;
                self.missing = true;
            }
            let checks = self.inner.as_mut().ok_or(Error::Corrupt("missing inner checks"))?;
            if let Some(cipher) = &mut self.cipher {
                let mut state = cipher.recovery.take().unwrap_or(CbcAvailability {
                    block: [0; 16],
                    used: 0,
                    known: true,
                    previous_known: true,
                });
                self.scratch.clear();
                let mut hole = 0;
                // Trimming follows processed blocks; evidence/delivered follow
                // successful sink flushes, which may fail after a partial write.
                let mut processed = self.delivered;
                let mut at = 0;
                let result = (|| -> Result<()> {
                    while at < len {
                        // A run of whole blocks with known ciphertext before it decrypts in one call, so the
                        // hardware AES path decrypts eight blocks at a time; it emits exactly what the block
                        // loop below would (no CBC neighbour records: every block and its predecessor are known).
                        if let Some(bytes) = data
                            && state.used == 0
                            && state.known
                            && state.previous_known
                        {
                            let whole = (len - at) / 16 * 16;
                            if whole >= 32 {
                                if hole != 0 {
                                    flush_stored_run(&mut self.scratch, &mut hole, checks, &mut self.delivered, sink)?;
                                }
                                // Capacity was admitted before processing (len plus one retained block).
                                if self.scratch.capacity() - self.scratch.len() < whole {
                                    return Err(Error::Corrupt("unadmitted Stored scratch"));
                                }
                                let start = self.scratch.len();
                                let run = &bytes[at..at + whole];
                                self.scratch.extend_from_slice(run);
                                state.block.copy_from_slice(&run[whole - 16..]);
                                cipher.aes.decrypt_cbc_in_place(&mut cipher.iv, &mut self.scratch[start..]);
                                let kept = cipher.trim_stored(&self.scratch[start..], processed)?.len();
                                self.scratch.truncate(start + kept);
                                processed =
                                    processed.checked_add(kept as u64).ok_or(Error::Corrupt("inner size overflow"))?;
                                at += whole;
                                continue;
                            }
                        }
                        let n = (16 - state.used).min(len - at);
                        if let Some(bytes) = data {
                            state.block[state.used..state.used + n].copy_from_slice(&bytes[at..at + n]);
                        } else {
                            state.known = false;
                        }
                        state.used += n;
                        at += n;
                        if state.used != 16 {
                            continue;
                        }
                        let valid = state.known && state.previous_known;
                        // `processed` is the stream offset of this block: only the final block is trimmed.
                        if !state.known && state.previous_known && processed >= 16 {
                            sink.cipher_block(processed - 16, &cipher.iv)?;
                        } else if state.known && !state.previous_known {
                            sink.cipher_block(processed, &state.block)?;
                        }
                        let mut plain = state.block;
                        if state.known {
                            if state.previous_known {
                                cipher.aes.decrypt_cbc_in_place(&mut cipher.iv, &mut plain);
                            } else {
                                cipher.iv = state.block;
                            }
                        }
                        state.previous_known = state.known;
                        state.used = 0;
                        state.known = true;
                        let bytes = cipher.trim_stored(&plain, processed)?;
                        processed =
                            processed.checked_add(bytes.len() as u64).ok_or(Error::Corrupt("inner size overflow"))?;
                        if !bytes.is_empty() {
                            if valid {
                                if hole != 0 || self.scratch.capacity() - self.scratch.len() < bytes.len() {
                                    flush_stored_run(&mut self.scratch, &mut hole, checks, &mut self.delivered, sink)?;
                                }
                                // Capacity was admitted before processing; never
                                // let extend allocate in the block loop.
                                if self.scratch.capacity() - self.scratch.len() < bytes.len() {
                                    return Err(Error::Corrupt("unadmitted Stored scratch"));
                                }
                                self.scratch.extend_from_slice(bytes);
                            } else {
                                if !self.scratch.is_empty() {
                                    flush_stored_run(&mut self.scratch, &mut hole, checks, &mut self.delivered, sink)?;
                                }
                                hole = hole
                                    .checked_add(bytes.len() as u64)
                                    .ok_or(Error::Corrupt("inner size overflow"))?;
                            }
                        }
                    }
                    // No output run survives this feed or a source/poll boundary.
                    flush_stored_run(&mut self.scratch, &mut hole, checks, &mut self.delivered, sink)
                })();
                self.scratch.clear();
                cipher.recovery = Some(state);
                result?;
            } else {
                if let Some(bytes) = data {
                    sink.put(bytes)?;
                    checks.hasher.update(bytes);
                    if let Some(b) = &mut checks.blake {
                        b.update(bytes);
                    }
                } else {
                    sink.hole(len as u64)?;
                }
                checks.bytes = checks.bytes.checked_add(len as u64).ok_or(Error::Corrupt("inner size overflow"))?;
                self.delivered = checks.bytes;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(|e| {
            super::framing::progressive_fault(batch::decoder_failure(e, self.context.scope(), self.context.password))
        })
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
            Some(decoder) => decoder.rar5_mut()?.feed_shared(piece, range, sink),
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
        let result = if matches!(self.decoder, Some(MemberDecoder::Rar4(_))) {
            self.packed(bytes)
                .map_err(|e| {
                    super::framing::progressive_fault(batch::decoder_failure(
                        e,
                        self.context.scope(),
                        self.context.password,
                    ))
                })
                .and_then(|()| {
                    let Some(MemberDecoder::Rar4(decoder)) = &mut self.decoder else { unreachable!() };
                    let bytes = match &mut self.cipher {
                        Some(cipher) => {
                            cipher.decrypt_selected(bytes, &mut self.scratch);
                            self.scratch.as_slice()
                        }
                        None => bytes,
                    };
                    decoder
                        .feed(bytes, &mut CheckingSink { checks: &mut checks, sink })
                        .map(|_| ())
                        .map_err(|e| super::framing::progressive_fault(e.detailed(self.context.scope())))
                })
        } else {
            self.feed_core(bytes, &mut CheckingSink { checks: &mut checks, sink }).map_err(|e| {
                super::framing::progressive_fault(batch::decoder_failure(
                    e,
                    self.context.scope(),
                    self.context.password,
                ))
            })
        };
        self.inner = Some(checks);
        if result.is_err() {
            self.failed = true;
        }
        result
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
        if part.final_part || self.part_missing {
            return Ok(());
        }
        let key = self.cipher.as_ref().filter(|_| part.checks.keyed).and_then(PendingCipher::checksum_key);
        let result = verify_packed(&self.context, part.checks, self.part_crc.clone(), self.part_blake.take(), key);
        if result.is_err() && self.resumed {
            self.part_missing = true;
            return Ok(());
        }
        result
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
        let key = self.cipher.as_ref().filter(|_| checks.keyed).and_then(PendingCipher::checksum_key);
        if self.missing {
            let actual = self.inner.as_ref().map_or(0, |c| c.bytes);
            if member.unpacked_size.is_some_and(|n| n != actual) {
                return Err(crate::progressive::ProgressiveFailure::new(
                    crate::progressive::FailureKind::IncompleteOutput,
                ));
            }
            return Ok(());
        }
        let inner = self.inner.as_mut().ok_or_else(|| {
            crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput)
        })?;
        let bytes = inner.bytes;
        let result = inner.verify(&self.context, member.unpacked_size, checks.crc32, checks.blake2sp, key);
        if result.is_err() && self.resumed && member.unpacked_size.is_none_or(|n| n == bytes) {
            self.missing = true;
            return Ok(());
        }
        result
            .map_err(|e| crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Rar(Box::new(e))))
    }
    pub(crate) fn finish_decode(&mut self, sink: &mut dyn Sink) -> crate::progressive::ProgressiveResult<()> {
        if let Some(cipher) = &self.cipher {
            cipher.finish_selected(&self.context).map_err(|e| {
                crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Rar(Box::new(e)))
            })?;
        }
        if let Some(decoder) = &mut self.decoder {
            let mut sink = CheckingSink {
                checks: self.inner.as_mut().ok_or_else(|| {
                    crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::IncompleteOutput)
                })?,
                sink,
            };
            let result = match decoder {
                MemberDecoder::Rar5(d) => d
                    .finish(&mut sink)
                    .map_err(|e| batch::decoder_failure(e, self.context.scope(), self.context.password)),
                // the decoder stays open: a solid successor may go on from it
                MemberDecoder::Rar4(d) => {
                    d.finish_logical(&mut sink).map(|_| ()).map_err(|e| e.detailed(self.context.scope()))
                }
            };
            if result.is_err() {
                self.failed = true;
            }
            result.map_err(super::framing::progressive_fault)?;
        }
        self.decoded_finished = true;
        Ok(())
    }
    pub(crate) fn into_part_hashes(self) -> (crate::crc32::Hasher, Option<crate::blake2sp::Blake2sp>) {
        (self.part_crc, self.part_blake)
    }
}
/// Only successful whole sink runs contribute checks. A sink can commit a
/// shorter native prefix before failing; its Stage owns that prefix and the
/// failed member can never finish verification.
fn flush_stored_run(
    bytes: &mut Vec<u8>,
    hole: &mut u64,
    checks: &mut InnerChecks,
    delivered: &mut u64,
    sink: &mut dyn RecoverySink,
) -> Result<()> {
    let len = if *hole != 0 { *hole } else { bytes.len() as u64 };
    if len == 0 {
        return Ok(());
    }
    let end = checks.bytes.checked_add(len).ok_or(Error::Corrupt("inner size overflow"))?;
    if *hole != 0 {
        sink.hole(*hole)?;
        *hole = 0;
    } else {
        sink.put(bytes)?;
        checks.hasher.update(bytes);
        if let Some(blake) = &mut checks.blake {
            blake.update(bytes);
        }
        bytes.clear();
    }
    checks.bytes = end;
    *delivered = end;
    Ok(())
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
impl<'a> KdfMeter<'a> {
    #[cfg_attr(not(feature = "persistent-partials"), allow(dead_code))]
    pub(crate) fn new(usage: &'a crate::progressive::Usage, control: &'a crate::progressive::SessionControl) -> Self {
        Self { usage, control, blocks: 0 }
    }
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
pub(crate) fn controlled_legacy_keys(
    password: &str,
    salt: &[u8; 8],
    usage: &crate::progressive::Usage,
    control: &crate::progressive::SessionControl,
) -> crate::progressive::ProgressiveResult<([u8; 16], [u8; 16])> {
    use crate::progressive::{FailureKind, ProgressiveFailure, Resource};
    if control.is_canceled() {
        return Err(ProgressiveFailure::new(FailureKind::Canceled));
    }
    usage.check(Resource::PasswordUtf8Bytes, password.len() as u64)?;
    usage.check(Resource::PasswordEncodedBytes, password.encode_utf16().count() as u64 * 2)?;
    crate::crypto::derive_rar4_key_iv_controlled(password, salt, &mut KdfMeter { usage, control, blocks: 0 }).map_err(
        |error| {
            ProgressiveFailure::new(match error {
                crate::crypto::KdfControlError::Canceled => FailureKind::Canceled,
                crate::crypto::KdfControlError::Limit { resource, limit, attempted } => {
                    FailureKind::Limit { resource, limit, attempted }
                }
            })
        },
    )
}
impl PendingCipher {
    pub(crate) fn checksum_key(&self) -> Option<&[u8; 32]> {
        self.hash_key.as_ref()
    }
    /// RAR 3.x AES-128-CBC. A stored file's padding is trimmed from its output; a compressed one's is read past by
    /// its decoder.
    pub(crate) fn from_legacy(key: [u8; 16], iv: [u8; 16], size: u64, compressed: bool) -> Self {
        Self {
            aes: crate::crypto::AesKey::new(&key).expect("RAR4 AES128 key"),
            iv,
            rem: Vec::new(),
            hash_key: None,
            stored_padding: (!compressed).then_some(StoredCipherPadding { size, skipped: 0 }),
            blocks: None,
            recovery: None,
        }
    }
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
            hash_key: Some(keys.hash_key),
            stored_padding: if compressed { None } else { size.map(|size| StoredCipherPadding { size, skipped: 0 }) },
            blocks: compressed.then(CipherBlocks::default),
            recovery: None,
        }
    }
}
/// Serial stream preparation shared by complete and progressive extraction.
pub(crate) fn continue_decoder(stream: &mut Option<Unpacker>, dictionary: u64, size: Option<u64>) -> bool {
    if let Some(decoder) = stream.as_mut().filter(|u| dictionary <= u.reach()) {
        decoder.next_file(size);
        true
    } else {
        false
    }
}
pub(crate) fn reset_decoder(
    stream: &mut Option<Unpacker>,
    window: super::unpack::Window,
    size: Option<u64>,
    threads: Option<usize>,
    parallel_min: Option<u64>,
) -> std::result::Result<(), super::unpack::WindowError> {
    if let Some(decoder) = stream.as_mut().filter(|u| u.fits(window)) {
        decoder.restart(window, size);
    } else {
        let mut decoder = Unpacker::new_detailed(window)?;
        if threads.is_some() || parallel_min.is_some() {
            let workers = threads.map_or_else(|| decoder.threads(), |n| n.saturating_sub(1));
            decoder.set_threads(workers, parallel_min.unwrap_or(decoder.parallel_min()));
        }
        decoder.reset(size);
        *stream = Some(decoder);
    }
    Ok(())
}
impl MemberMachine {
    #[cfg(test)]
    pub(crate) fn new(
        header: &super::FileHeader,
        context: EntryContext,
        password: Option<&str>,
        usage: &crate::progressive::Usage,
        control: &crate::progressive::SessionControl,
    ) -> crate::progressive::ProgressiveResult<Self> {
        Self::new_with_history(header, context, password, usage, control, None, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_history(
        header: &super::FileHeader,
        mut context: EntryContext,
        password: Option<&str>,
        usage: &crate::progressive::Usage,
        control: &crate::progressive::SessionControl,
        decoder: Option<Unpacker>,
        legacy: Option<super::LegacyCrypt>,
    ) -> crate::progressive::ProgressiveResult<Self> {
        use crate::progressive::{FailureKind, ProgressiveFailure, Resource};
        if header.format == super::RarFormat::Rar4 {
            if let Some(reason) = header.rar4_progressive_unsupported(legacy) {
                return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(RarFailure::Unsupported(reason)))));
            }
        } else if header.algorithm != 0 || header.method > 5 {
            return Err(ProgressiveFailure::new(FailureKind::UnsupportedMethod));
        }
        if header.format == super::RarFormat::Rar4 && header.method != 0 {
            // RAR4 compressed construction requires its source-bound exact CoreFrame.
            return Err(ProgressiveFailure::new(FailureKind::InvalidCapability));
        }
        let size = (!header.size_unknown()).then_some(header.unpacked_size);
        let cipher = if header.encrypted {
            if header.format == super::RarFormat::Rar4 {
                let salt = super::LegacyCrypt::stored_salt(legacy).map_err(|reason| {
                    ProgressiveFailure::new(FailureKind::Rar(Box::new(RarFailure::Unsupported(reason))))
                })?;
                // RAR 3.x has no check value, so an empty password is still an attempt.
                let password = password.ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?;
                let (key, iv) = controlled_legacy_keys(password, &salt, usage, control)?;
                context.password = crate::error::RarPasswordEvidence::VerifierUnavailable(
                    crate::error::RarVerifierUnavailable::Absent,
                );
                Some(PendingCipher::from_legacy(key, iv, header.unpacked_size, header.method != 0))
            } else {
                let params = header
                    .crypt
                    .ok_or_else(|| ProgressiveFailure::new(FailureKind::Malformed("member encryption record")))?;
                let password = password
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?;
                let keys = controlled_keys(password, params, usage, control, context.scope())?;
                context.password = keys.evidence;
                Some(PendingCipher::from_keys(params, keys, header.method != 0, size))
            }
        } else {
            None
        };
        let decoder = if header.method != 0 && decoder.is_none() {
            if header.solid {
                return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(RarFailure::SolidHistoryUnavailable {
                    predecessor: None,
                    cause: None,
                }))));
            }
            let window = super::unpack::window_for_detailed(header.dictionary, size, false)
                .map_err(|e| super::framing::progressive_fault(e.detailed(context.scope())))?;
            usage.check(Resource::DecoderWindow, window.size)?;
            let mut decoder = Unpacker::new_detailed(window)
                .map_err(|e| super::framing::progressive_fault(e.detailed(context.scope())))?;
            decoder.next_file(size);
            Some(decoder)
        } else {
            decoder
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
            renamed: None,
            link: None,
        }
    }
    fn recovery_fixture(size: usize) -> (super::super::FileHeader, Vec<u8>, Vec<u8>) {
        let params = crate::crypto::Rar5CryptParams {
            kdf_count: 1,
            salt: [7; 16],
            iv: [9; 16],
            check: None,
            tweaked_crc: false,
        };
        let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut padded = plain.clone();
        padded.resize(size.next_multiple_of(16), 0);
        let keys = crate::crypto::derive_rar5_keys("secret", 1, &params.salt, None).unwrap();
        let ciphertext = crate::crypto::encrypt_cbc(&keys.key, &params.iv, &padded).unwrap();
        let header = super::super::FileHeader {
            name: "f".into(),
            unpacked_size: size as u64,
            encrypted: true,
            crypt: Some(params),
            packed_size: ciphertext.len() as u64,
            crc32: Some(crate::crc32::hash(&plain)),
            ..Default::default()
        };
        (header, ciphertext, plain)
    }
    #[derive(Default)]
    struct RecoveryRecorder {
        output: Vec<Option<u8>>,
        puts: usize,
        holes: usize,
    }
    impl Sink for RecoveryRecorder {
        fn put(&mut self, bytes: &[u8]) -> Result<()> {
            self.puts += 1;
            self.output.extend(bytes.iter().copied().map(Some));
            Ok(())
        }
    }
    impl RecoverySink for RecoveryRecorder {
        fn hole(&mut self, len: u64) -> Result<()> {
            self.holes += 1;
            self.output.resize(self.output.len() + len as usize, None);
            Ok(())
        }
    }
    /// Whole-block runs decrypt in one call; whatever the feed sizes and holes, the output is what feeding one byte
    /// at a time (which never takes that path) gives.
    #[test]
    fn stored_runs_decrypt_like_single_bytes_at_any_split_and_hole() {
        let size = 4096 + 7;
        let (header, ciphertext, plain) = recovery_fixture(size);
        let packed = ciphertext.len();
        let run = |feeds: &[(usize, bool)]| {
            let usage = Usage::new(ProgressiveLimits::default());
            let mut machine =
                MemberMachine::new(&header, context(), Some("secret"), &usage, &SessionControl::default()).unwrap();
            let mut sink = RecoveryRecorder::default();
            let mut at = 0;
            for &(len, absent) in feeds {
                let len = len.min(packed - at);
                machine.reserve_progressive_scratch(len, &usage).unwrap();
                machine.feed_stored((!absent).then_some(&ciphertext[at..at + len]), len, &mut sink).unwrap();
                at += len;
            }
            assert_eq!(at, packed);
            sink.output
        };
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for round in 0..40u32 {
            let mut feeds = Vec::new();
            let mut at = 0;
            while at < packed {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let len = 1 + (x % 700) as usize;
                let absent = !round.is_multiple_of(2) && x.is_multiple_of(9);
                feeds.push((len.min(packed - at), absent));
                at += len.min(packed - at);
            }
            // the reference: the same holes, fed one byte at a time
            let singles: Vec<(usize, bool)> =
                feeds.iter().flat_map(|&(len, absent)| (0..len).map(move |_| (1, absent))).collect();
            let got = run(&feeds);
            assert_eq!(got, run(&singles), "round {round}");
            assert_eq!(got.len(), size);
            if round.is_multiple_of(2) {
                assert!(got.iter().zip(&plain).all(|(g, p)| *g == Some(*p)), "round {round}: no hole, exact plaintext");
            }
        }
    }
    #[test]
    fn stored_recovery_coalesces_actual_sink_calls() {
        let (header, ciphertext, plain) = recovery_fixture(65_536);
        let usage = Usage::new(ProgressiveLimits::default());
        let mut machine =
            MemberMachine::new(&header, context(), Some("secret"), &usage, &SessionControl::default()).unwrap();
        let mut sink = RecoveryRecorder::default();
        for (data, len) in [(Some(&ciphertext[..16]), 16), (None, 16), (Some(&ciphertext[32..]), 65_504)] {
            machine.reserve_progressive_scratch(len, &usage).unwrap();
            machine.feed_stored(data, len, &mut sink).unwrap();
        }
        assert_eq!(sink.output.len(), 65_536);
        for (at, byte) in sink.output.iter().enumerate() {
            assert_eq!(*byte, if (16..48).contains(&at) { None } else { Some(plain[at]) });
        }
        eprintln!("actual recovery sink calls: puts={} holes={}", sink.puts, sink.holes);
        assert!(sink.puts <= 2 && sink.holes <= 2, "bounded runs, not cipher-block IO");
    }
    #[test]
    fn stored_recovery_scratch_exact_budget_and_one_under() {
        let (header, ciphertext, plain) = recovery_fixture(64);
        for (budget, missing) in [(95, false), (96, false), (95, true), (96, true)] {
            let usage = Usage::new(ProgressiveLimits { metadata_bytes: budget, ..ProgressiveLimits::default() });
            let mut machine =
                MemberMachine::new(&header, context(), Some("secret"), &usage, &SessionControl::default()).unwrap();
            let mut sink = RecoveryRecorder::default();
            let admission = machine.reserve_progressive_scratch(64, &usage);
            if budget == 95 {
                assert!(matches!(
                    admission.unwrap_err().kind,
                    FailureKind::Limit { resource: Resource::MetadataBytes, limit: 95, attempted: 96 }
                ));
                assert_eq!(machine.delivered, 0);
                assert_eq!(machine.part_bytes, 0);
                assert!(sink.output.is_empty());
            } else {
                admission.unwrap();
                machine.feed_stored((!missing).then_some(ciphertext.as_slice()), 64, &mut sink).unwrap();
                let expected = if missing { vec![None; 64] } else { plain.iter().copied().map(Some).collect() };
                assert_eq!(sink.output, expected);
                assert_eq!(machine.scratch.capacity(), 80);
                assert_eq!(machine.cipher.as_ref().unwrap().rem.capacity(), 16);
            }
        }
        let mut plain_header = header;
        plain_header.encrypted = false;
        plain_header.crypt = None;
        let usage = Usage::new(ProgressiveLimits { metadata_bytes: 0, ..ProgressiveLimits::default() });
        let mut machine =
            MemberMachine::new(&plain_header, context(), None, &usage, &SessionControl::default()).unwrap();
        machine.reserve_progressive_scratch(64, &usage).unwrap();
        let mut sink = RecoveryRecorder::default();
        machine.feed_stored(Some(&plain), 64, &mut sink).unwrap();
        assert_eq!(machine.scratch.capacity(), 0);
        assert_eq!(sink.output, plain.iter().copied().map(Some).collect::<Vec<_>>());
    }
    #[test]
    fn stored_recovery_requires_admitted_scratch_before_processing() {
        let (header, ciphertext, _) = recovery_fixture(64);
        let usage = Usage::new(ProgressiveLimits::default());
        for missing in [false, true] {
            let mut machine =
                MemberMachine::new(&header, context(), Some("secret"), &usage, &SessionControl::default()).unwrap();
            let mut sink = RecoveryRecorder::default();
            assert!(matches!(
                machine.feed_stored((!missing).then_some(ciphertext.as_slice()), 64, &mut sink).unwrap_err().kind,
                FailureKind::InvalidCapability
            ));
            assert_eq!(machine.part_bytes, 0);
            assert_eq!(machine.delivered, 0);
            assert!(sink.output.is_empty());
            assert!(machine.cipher.as_ref().unwrap().recovery.is_none());
        }
    }
    #[test]
    fn stored_recovery_runs_preserve_taint_across_every_short_part_split() {
        for (missing, expected) in
            [(17..18, 16..48), (16..32, 16..48), (0..1, 0..32), (63..65, 48..79), (79..80, 64..79)]
        {
            for split in 0..=80 {
                let (mut header, ciphertext, plain) = recovery_fixture(79);
                header.block_flags = super::super::HFL_SPLIT_AFTER;
                header.packed_size = split as u64;
                header.crc32 = Some(crate::crc32::hash(&ciphertext[..split]));
                let wire = super::super::FileWire {
                    legacy: None,
                    name: std::sync::Arc::new(b"f".to_vec()),
                    compression: 0,
                    extent: 0..0,
                };
                let part = PhysicalPart::new(0, &header, header.crypt.map(Ok), &wire);
                let mut member = PhysicalMember::new(header.clone(), wire, 0, &part).unwrap();
                let usage = Usage::new(ProgressiveLimits::default());
                let mut machine =
                    MemberMachine::new(&header, context(), Some("secret"), &usage, &SessionControl::default()).unwrap();
                let mut sink = RecoveryRecorder::default();
                for (volume, range) in [(0, 0..split), (1, split..80)] {
                    let part = if volume == 0 {
                        PhysicalPart::new(0, &header, header.crypt.map(Ok), &member.wire)
                    } else {
                        header.block_flags = super::super::HFL_SPLIT_BEFORE;
                        header.packed_size = (80 - split) as u64;
                        header.crc32 = Some(crate::crc32::hash(&plain));
                        header.crypt.as_mut().unwrap().iv = [55; 16];
                        let part = PhysicalPart::new(1, &header, header.crypt.map(Ok), &member.wire);
                        member.append(&header, &part).unwrap();
                        part
                    };
                    machine.begin_part(&part);
                    let mut at = range.start;
                    while at < range.end {
                        let absent = missing.contains(&at);
                        let end = range.end.min(if absent {
                            missing.end
                        } else if at < missing.start {
                            missing.start
                        } else {
                            range.end
                        });
                        machine.reserve_progressive_scratch(end - at, &usage).unwrap();
                        machine.feed_stored((!absent).then_some(&ciphertext[at..end]), end - at, &mut sink).unwrap();
                        assert_eq!(machine.delivered as usize, sink.output.len(), "each feed flushes");
                        at = end;
                    }
                    machine.finish_part(&part).unwrap();
                }
                machine.finish_decode(&mut sink).unwrap();
                machine.finish_member(&member).unwrap();
                assert_eq!(sink.output.len(), 79);
                for (at, byte) in sink.output.iter().enumerate() {
                    assert_eq!(
                        *byte,
                        if expected.contains(&at) { None } else { Some(plain[at]) },
                        "split={split} missing={missing:?}"
                    );
                }
                assert!(sink.puts + sink.holes <= 8);
            }
        }
    }
    #[test]
    fn stored_recovery_unknown_geometry_and_failed_flush_are_closed() {
        let (mut header, ciphertext, plain) = recovery_fixture(64);
        header.file_flags |= super::super::FHFL_UNPUNKNOWN;
        let usage = Usage::new(ProgressiveLimits::default());
        let mut machine =
            MemberMachine::new(&header, context(), Some("secret"), &usage, &SessionControl::default()).unwrap();
        machine.reserve_progressive_scratch(64, &usage).unwrap();
        let mut sink = RecoveryRecorder::default();
        machine.feed_stored(Some(&ciphertext), 64, &mut sink).unwrap();
        assert_eq!(sink.puts, 1);
        assert_eq!(sink.output, plain.iter().copied().map(Some).collect::<Vec<_>>());
        assert!(matches!(machine.feed_stored(None, 16, &mut sink).unwrap_err().kind, FailureKind::DataHole));
        assert_eq!(sink.output.len(), 64);

        struct FailsAfterPrefix(Vec<u8>);
        impl Sink for FailsAfterPrefix {
            fn put(&mut self, bytes: &[u8]) -> Result<()> {
                self.0.extend_from_slice(&bytes[..3]);
                Err(Error::Corrupt("sink committed a prefix then failed"))
            }
        }
        impl RecoverySink for FailsAfterPrefix {
            fn hole(&mut self, _: u64) -> Result<()> {
                panic!("no holes")
            }
        }
        let mut failed =
            MemberMachine::new(&header, context(), Some("secret"), &usage, &SessionControl::default()).unwrap();
        failed.reserve_progressive_scratch(64, &usage).unwrap();
        let mut sink = FailsAfterPrefix(Vec::new());
        assert!(failed.feed_stored(Some(&ciphertext), 64, &mut sink).is_err());
        assert_eq!(sink.0, &plain[..3]);
        assert_eq!(failed.delivered, 0);
        assert_eq!(failed.inner.as_ref().unwrap().bytes, 0);
        assert_eq!(failed.inner.as_ref().unwrap().hasher.clone().finalize(), crate::crc32::hash(&[]));
        assert!(failed.failed);
        assert!(failed.scratch.is_empty());
        assert!(failed.feed_stored(Some(&ciphertext), 64, &mut sink).is_err());
        assert_eq!(sink.0.len(), 3);
    }
    #[test]
    fn stored_recovery_native_short_write_then_limit_keeps_committed_prefix() {
        use crate::progressive::*;
        use std::task::{Context, Poll, Waker};
        fn block(body: &[u8], data: &[u8]) -> Vec<u8> {
            assert!(body.len() < 128);
            let mut sized = vec![body.len() as u8];
            sized.extend(body);
            let mut bytes = crate::crc32::hash(&sized).to_le_bytes().to_vec();
            bytes.extend(sized);
            bytes.extend(data);
            bytes
        }
        let (header, ciphertext, plain) = recovery_fixture(96);
        let params = header.crypt.unwrap();
        let mut extra = vec![36, 1, 0, 0, 1];
        extra.extend(params.salt);
        extra.extend(params.iv);
        let mut body = vec![2, 3, 37, 96, 4, 96, 0];
        body.extend(crate::crc32::hash(&plain).to_le_bytes());
        body.extend([0, 0, 5]);
        body.extend(b"inner");
        body.extend(extra);
        let mut data = b"Rar!\x1a\x07\x01\x00".to_vec();
        data.extend(block(&[1, 0, 0], &[]));
        data.extend(block(&body, &ciphertext));
        data.extend(block(&[5, 0, 0], &[]));
        for short in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let mut opts = ProgressiveOptions::new(
                crate::extract::Options {
                    mode: crate::extract::Mode::Extract,
                    dest: dir.path().into(),
                    overwrite: crate::extract::Overwrite::Always,
                    flatten: false,
                    threads: Some(1),
                    protected_paths: Default::default(),
                    parallel_min: None,
                    select: None,
                    windows_safe_names: false,
                    special_entries: Default::default(),
                    fallback_mtime: None,
                    compressed_tar: Default::default(),
                    version_naming: Default::default(),
                    preexisting_links: Default::default(),
                    refused_link_placeholder: false,
                    restart_from_first_volume: false,
                    replace_placed_links: false,
                    keep_broken: false,
                },
                "a.rar".into(),
            );
            opts.set_password(Some("secret".into())).unwrap();
            opts.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
            opts.artifact_aftermath = ArtifactAftermath::RetainProvisional;
            opts.limits.output_write_bytes = 100;
            let mut session =
                ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), data.clone().into_boxed_slice())], opts)
                    .unwrap();
            crate::output::OWNED_STAGE_FAULT.with(|slot| {
                *slot.borrow_mut() =
                    Some((crate::output::OwnedOperation::Write, if short { Ok(Some(3)) } else { Err(libc::ENOSPC) }))
            });
            let mut terminated = false;
            for _ in 0..100 {
                match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                    Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                        failure,
                        artifact,
                        cleanup_failure,
                    }))) => {
                        let committed = if short { 3 } else { 0 };
                        assert_eq!(failure.context.inner_offset, Some(committed));
                        if short {
                            assert!(matches!(
                                failure.kind,
                                FailureKind::Limit { resource: Resource::OutputWriteBytes, limit: 100, attempted: 189 }
                            ));
                        } else {
                            assert!(matches!(
                                failure.kind,
                                FailureKind::Output { operation: OutputOperation::Write, .. }
                            ));
                            let range = failure.context.output_range.unwrap();
                            assert_eq!(range.completed, 0);
                        }
                        assert!(cleanup_failure.is_none());
                        let mut artifact = artifact.unwrap();
                        assert_eq!(artifact.produced_extent(), committed);
                        assert_eq!(artifact.evidence(), ArtifactEvidence::Provisional);
                        let mut got = [0; 96];
                        if short {
                            assert_eq!(artifact.read_at(0, &mut got).unwrap(), ArtifactRead::Filled { count: 3 });
                            assert_eq!(&got[..3], &plain[..3]);
                        }
                        assert_eq!(artifact.read_at(committed, &mut got).unwrap(), ArtifactRead::End);
                        assert!(!dir.path().join("inner").exists());
                        artifact.discard().unwrap();
                        terminated = true;
                        break;
                    }
                    Poll::Ready(Err(e)) => panic!("{e}"),
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => panic!("failed write published"),
                    _ => {}
                }
            }
            assert!(terminated);
            assert!(crate::output::OWNED_STAGE_FAULT.with(|slot| slot.borrow().is_none()));
        }
    }
    #[test]
    fn legacy_kdf_session_budget_is_cumulative_and_meter_does_not_wrap() {
        use crate::crypto::KdfControl;
        let control = SessionControl::default();
        let usage = Usage::new(ProgressiveLimits { kdf_session_blocks: 100, ..Default::default() });
        for _ in 0..2 {
            assert!(matches!(
                controlled_legacy_keys("pw", &[1; 8], &usage, &control),
                Err(crate::progressive::ProgressiveFailure {
                    kind: FailureKind::Limit { resource: Resource::KdfSessionBlocks, limit: 100, attempted: 101 },
                    ..
                })
            ));
        }
        let untouched = Usage::new(ProgressiveLimits { kdf_session_blocks: 1, ..Default::default() });
        let mut meter = KdfMeter { usage: &untouched, control: &control, blocks: u64::MAX };
        assert!(matches!(meter.charge(1), Err(crate::crypto::KdfControlError::Limit { attempted: u64::MAX, .. })));
        untouched.charge(Resource::KdfSessionBlocks, 1).unwrap();
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
    /// A member resumed in a later part checks that part as the part declares, not as the first part did, and a
    /// mismatch marks the part missing (verification reports it) instead of failing the machine.
    #[cfg(feature = "persistent-partials")]
    #[test]
    fn resumed_member_checks_the_current_part_and_is_lenient() {
        let data: Vec<u8> = (0..64u8).collect();
        let mut right = crate::blake2sp::Blake2sp::new();
        right.update(&data[32..48]);
        let right = right.finish();
        for (declared, missing) in [(right, false), ([7; 32], true)] {
            let wire = super::super::FileWire {
                legacy: None,
                name: std::sync::Arc::new(b"f".to_vec()),
                compression: 0,
                extent: 0..0,
            };
            // Part 0 declares no BLAKE2sp; part 1 does.
            let first = super::super::FileHeader {
                name: "f".into(),
                unpacked_size: 64,
                packed_size: 32,
                crc32: Some(crate::crc32::hash(&data[..32])),
                block_flags: super::super::HFL_SPLIT_AFTER,
                ..Default::default()
            };
            let second = super::super::FileHeader {
                packed_size: 16,
                crc32: Some(crate::crc32::hash(&data[32..48])),
                blake2sp: Some(declared),
                block_flags: super::super::HFL_SPLIT_BEFORE | super::super::HFL_SPLIT_AFTER,
                ..first.clone()
            };
            let part = PhysicalPart::new(1, &second, None, &wire);
            let usage = Usage::new(ProgressiveLimits::default());
            let control = SessionControl::default();
            let mut machine = MemberMachine::new(&first, context(), None, &usage, &control).unwrap();
            let mut member_crc = crate::crc32::Hasher::new();
            member_crc.update(&data[..36]);
            let mut part_crc = crate::crc32::Hasher::new();
            part_crc.update(&data[32..36]);
            let mut part_blake = crate::blake2sp::Blake2sp::new();
            part_blake.update(&data[32..36]);
            machine
                .resume_stored(
                    &part,
                    StoredResume {
                        delivered: 36,
                        part_bytes: 4,
                        member: Some((member_crc, None)),
                        part: Some((part_crc, Some(part_blake))),
                        iv: None,
                        padding: 0,
                    },
                )
                .unwrap();
            let mut sink = |_: &[u8]| Ok(());
            machine.feed(&data[36..48], &mut sink).unwrap();
            machine.finish_part(&part).unwrap();
            assert_eq!(machine.part_missing(), missing, "declared {declared:?}");
        }
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
                let wire = super::super::FileWire {
                    legacy: None,
                    name: std::sync::Arc::new(b"f".to_vec()),
                    compression: 0,
                    extent: 0..0,
                };
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
                        ParserStep::LegacyKeyRequired { .. } => panic!("unexpected legacy encryption"),
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
                select: None,
                windows_safe_names: false,
                special_entries: Default::default(),
                fallback_mtime: None,
                compressed_tar: Default::default(),
                version_naming: Default::default(),
                preexisting_links: Default::default(),
                refused_link_placeholder: false,
                restart_from_first_volume: false,
                replace_placed_links: false,
                keep_broken: false,
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
