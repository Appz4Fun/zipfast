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

//! Stream geometry, keys and ciphertext bookkeeping of encrypted (AES-256-CBC) RAR5 stored members.
//!
//! All parts of a member form one ciphertext stream; a part boundary never resets CBC. Stream offset `c` is
//! output offset `c` clipped at the unpacked size, so a plain member is the special case where the stream is the
//! output. Plaintext block `k` needs ciphertext blocks `k` and `k - 1` (the header IV for block 0).
use super::state::{CipherBlock, Snapshot};
use super::*;

pub(super) fn floor_block(offset: u64) -> u64 {
    offset & !15
}
pub(super) fn ceil_block(offset: u64) -> u64 {
    offset.checked_next_multiple_of(16).unwrap_or(!15)
}

/// In-memory keys of an encrypted member. Derived from the password or taken from the extraction; never written
/// to the state or the journal.
#[derive(Clone)]
pub(crate) struct MemberKeys {
    pub aes: crate::crypto::AesKey,
    pub hash: [u8; 32],
    /// The first IV of a RAR4 member, derived with its key; a RAR5 member's is in its header.
    pub iv: Option<[u8; 16]>,
}
impl MemberKeys {
    pub(crate) fn new(aes: crate::crypto::AesKey, hash: [u8; 32]) -> Self {
        Self { aes, hash, iv: None }
    }
    pub(crate) fn with_iv(mut self, iv: [u8; 16]) -> Self {
        self.iv = Some(iv);
        self
    }
    /// Derives the RAR 3.x AES-128 key and IV of a RAR4 member from `password` and its 8-byte salt.
    pub(super) fn derive_rar4(
        password: &str,
        salt: &[u8; 8],
        budget: &PartialBudget,
        control: &SessionControl,
    ) -> PartialResult<Self> {
        canceled(control)?;
        let (key, iv) = crate::rar5::member::controlled_legacy_keys(password, salt, &budget.usage, control)?;
        let aes = crate::crypto::AesKey::new(&key).ok_or_else(|| err(PartialErrorKind::UnsupportedMethod))?;
        Ok(Self::new(aes, [0; 32]).with_iv(iv))
    }
    /// Derives the keys from `password` and the member's header witness parameters, with KDF work metered by the
    /// budget and cancellable by `control`.
    pub(super) fn derive(
        password: &str,
        params: &crate::crypto::Rar5CryptParams,
        budget: &PartialBudget,
        control: &SessionControl,
    ) -> PartialResult<Self> {
        use crate::crypto::{ControlledKdfError, KdfControlError, Rar5CryptError};
        canceled(control)?;
        budget.usage.check(Resource::PasswordUtf8Bytes, password.len() as u64)?;
        budget.usage.check(Resource::PasswordEncodedBytes, password.len() as u64)?;
        budget.usage.check(Resource::KdfExponent, u64::from(params.kdf_count))?;
        let keys = crate::crypto::derive_rar5_keys_controlled(
            password,
            params.kdf_count,
            &params.salt,
            params.check,
            &mut crate::rar5::member::KdfMeter::new(&budget.usage, control),
        )
        .map_err(|error| match error {
            ControlledKdfError::Crypt(Rar5CryptError::WrongPassword) => err(PartialErrorKind::WrongPassword),
            ControlledKdfError::Crypt(_) => err(PartialErrorKind::UnsupportedMethod),
            ControlledKdfError::Control(KdfControlError::Canceled) => err(PartialErrorKind::Canceled),
            ControlledKdfError::Control(KdfControlError::Limit { resource, limit, attempted }) => {
                crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Limit {
                    resource,
                    limit,
                    attempted,
                })
                .into()
            }
        })?;
        let aes = crate::crypto::AesKey::new(&keys.key).ok_or_else(|| err(PartialErrorKind::UnsupportedMethod))?;
        Ok(Self::new(aes, keys.hash_key))
    }
}

/// Each part with the stream offset where it starts.
pub(super) fn parts_with_stream(snapshot: &Snapshot) -> impl Iterator<Item = (&PlainPart, u64)> {
    snapshot.evidence.parts.iter().scan(0u64, |at, part| {
        let start = *at;
        *at = at.saturating_add(part.packed.range.end - part.packed.range.start);
        Some((part, start))
    })
}
/// Ciphertext stream length of the parts known so far.
pub(super) fn stream_total(snapshot: &Snapshot) -> u64 {
    snapshot
        .evidence
        .parts
        .iter()
        .fold(0u64, |sum, part| sum.saturating_add(part.packed.range.end - part.packed.range.start))
}
/// Stream bytes whose output is produced. For an encrypted member this includes the final padding once the last
/// block is produced.
pub(super) fn stream_produced(snapshot: &Snapshot) -> u64 {
    if snapshot.crypt.is_some() && snapshot.head.produced >= snapshot.head.size {
        stream_total(snapshot)
    } else {
        snapshot.head.produced
    }
}
/// The ciphertext stream range a fill of output `out` needs: the output itself for a plain member, whole blocks
/// (including the final padding) for an encrypted one.
fn stream_for(snapshot: &Snapshot, out: &Range<u64>) -> Range<u64> {
    if snapshot.crypt.is_none() {
        return out.clone();
    }
    let total = stream_total(snapshot);
    let end = if out.end >= snapshot.head.size { total } else { ceil_block(out.end).min(total) };
    floor_block(out.start).min(end)..end
}
/// Exact packed spans of output `out`, one per volume piece.
pub(super) fn packed_spans(
    budget: &PartialBudget,
    snapshot: &Snapshot,
    out: &Range<u64>,
) -> PartialResult<Vec<PackedSpan>> {
    let mut spans = budget.vector(packed_span_count(snapshot, out))?;
    push_packed_spans(snapshot, out, &mut spans);
    Ok(spans)
}
/// How many spans [`packed_spans`] returns for `out`.
pub(super) fn packed_span_count(snapshot: &Snapshot, out: &Range<u64>) -> usize {
    let stream = stream_for(snapshot, out);
    parts_with_stream(snapshot)
        .filter(|(part, start)| {
            let end = start + (part.packed.range.end - part.packed.range.start);
            stream.start < end && *start < stream.end
        })
        .count()
}
/// Appends the spans of `out` to `spans`, which the caller sized and charged.
pub(super) fn push_packed_spans(snapshot: &Snapshot, out: &Range<u64>, spans: &mut Vec<PackedSpan>) {
    let stream = stream_for(snapshot, out);
    for (part, start) in parts_with_stream(snapshot) {
        let end = start + (part.packed.range.end - part.packed.range.start);
        let a = stream.start.max(start);
        let b = stream.end.min(end);
        if a < b {
            spans.push(PackedSpan {
                volume: part.packed.volume,
                range: part.packed.range.start + (a - start)..part.packed.range.start + (b - start),
            });
        }
    }
}
/// Whether output `range` (clipped to produced output) has bytes that are not known with archive authority.
/// With `alt`, alt output counts as unresolved too.
pub(super) fn unresolved(snapshot: &Snapshot, range: Range<u64>, alt: bool) -> bool {
    let range = range.start..range.end.min(snapshot.head.produced);
    if range.start >= range.end {
        return false;
    }
    let known = &snapshot.known;
    let mut at = range.start;
    let first = known.partition_point(|leaf| leaf.range.end <= at);
    for leaf in &known[first..] {
        if leaf.range.start > at || (alt && leaf.provenance == state::Provenance::Alt) {
            return true;
        }
        at = leaf.range.end;
        if at >= range.end {
            return false;
        }
    }
    at < range.end
}
fn block_out(snapshot: &Snapshot, offset: u64) -> Range<u64> {
    offset.min(snapshot.head.size)..offset.saturating_add(16).min(snapshot.head.size)
}
/// A kept block stays useful while its own output or the next block's output (which it decrypts) is a hole or
/// alt output, so archive bytes can still fill or correct it.
pub(super) fn useful(snapshot: &Snapshot, offset: u64) -> bool {
    unresolved(snapshot, block_out(snapshot, offset), true)
        || unresolved(snapshot, block_out(snapshot, offset.saturating_add(16)), true)
}
/// Drops kept blocks that no hole needs any more.
pub(super) fn prune(budget: &PartialBudget, snapshot: &mut Snapshot) -> PartialResult<()> {
    budget.usage.charge(Resource::SourceBookkeeping, snapshot.cipher.len() as u64)?;
    let mut cipher = std::mem::take(&mut snapshot.cipher);
    cipher.retain(|block| useful(snapshot, block.offset));
    snapshot.cipher = cipher;
    Ok(())
}
/// Merges block fragments into the kept set: whole blocks replace, fragments that touch or overlap join, and the
/// newer fragment wins otherwise.
pub(super) fn merge(
    budget: &PartialBudget,
    cipher: &mut Vec<CipherBlock>,
    blocks: &[CipherBlock],
) -> PartialResult<()> {
    budget.usage.check(Resource::HoleIntervals, cipher.len().saturating_add(blocks.len()) as u64)?;
    budget.metadata(std::mem::size_of_val(blocks) as u64)?;
    cipher.try_reserve(blocks.len()).map_err(|_| malformed())?;
    for block in blocks {
        budget.usage.charge(Resource::SourceBookkeeping, 1)?;
        match cipher.binary_search_by_key(&block.offset, |b| b.offset) {
            Ok(index) => cipher[index] = join(&cipher[index], block),
            Err(index) => cipher.insert(index, block.clone()),
        }
    }
    Ok(())
}
/// Drops kept blocks whose ciphertext overlaps a `damaged` stream range: declared damage makes that ciphertext
/// untrusted, and decrypting a neighbour with it would write wrong output with archive authority. Returns whether
/// any block was dropped.
pub(super) fn forget(
    budget: &PartialBudget,
    cipher: &mut Vec<CipherBlock>,
    damaged: &[Range<u64>],
) -> PartialResult<bool> {
    let before = cipher.len();
    for range in damaged {
        budget.usage.charge(Resource::SourceBookkeeping, 1)?;
        let first = cipher.partition_point(|block| block.offset.saturating_add(16) <= range.start);
        let last = first + cipher[first..].partition_point(|block| block.offset < range.end);
        cipher.drain(first..last);
    }
    Ok(cipher.len() != before)
}
fn join(old: &CipherBlock, new: &CipherBlock) -> CipherBlock {
    if new.whole() || new.have.end < old.have.start || old.have.end < new.have.start {
        return new.clone();
    }
    let mut bytes = old.bytes;
    let have = old.have.start.min(new.have.start)..old.have.end.max(new.have.end);
    bytes[new.have.start as usize..new.have.end as usize]
        .copy_from_slice(&new.bytes[new.have.start as usize..new.have.end as usize]);
    CipherBlock { offset: old.offset, have, bytes }
}
/// The bytes of the block at `offset` known from `supply` (covering stream `at..`) joined with the kept block.
fn assemble(cipher: &[CipherBlock], offset: u64, at: u64, supply: &[u8]) -> Option<CipherBlock> {
    let end = at + supply.len() as u64;
    let a = offset.max(at);
    let b = (offset + 16).min(end);
    let supplied = (a < b).then(|| {
        let mut bytes = [0; 16];
        bytes[(a - offset) as usize..(b - offset) as usize]
            .copy_from_slice(&supply[(a - at) as usize..(b - at) as usize]);
        CipherBlock { offset, have: (a - offset) as u8..(b - offset) as u8, bytes }
    });
    let kept = cipher.binary_search_by_key(&offset, |b| b.offset).ok().map(|index| &cipher[index]);
    match (kept, supplied) {
        (Some(kept), Some(supplied)) => Some(join(kept, &supplied)),
        (kept, supplied) => supplied.or_else(|| kept.cloned()),
    }
}

/// Decrypted archive bytes ready to write, and what could not be decrypted.
pub(super) struct Decrypted {
    /// Decrypted output, as contiguous runs `(output offset, range of plain)`.
    pub plain: Vec<u8>,
    pub runs: Vec<(u64, Range<usize>)>,
    pub undecryptable: Vec<Range<u64>>,
    /// Charge for `plain`, held as long as it lives: the buffer is freed when the fill ends.
    _lease: Option<crate::progressive::Lease>,
}
/// Decrypts ciphertext `supply` starting at stream offset `at` into produced output, using the header IV for
/// stream offset 0 and otherwise the previous ciphertext block from the supply or the kept blocks. The block right
/// after the supply is decrypted too when its ciphertext is kept, since the supply holds its previous block.
pub(super) fn decrypt(
    budget: &PartialBudget,
    snapshot: &Snapshot,
    keys: &MemberKeys,
    at: u64,
    supply: &[u8],
) -> PartialResult<Decrypted> {
    let crypt = snapshot.crypt.as_ref().ok_or_else(malformed)?;
    let size = snapshot.head.size;
    let limit = stream_produced(snapshot);
    let end = (at + supply.len() as u64).min(limit);
    let mut result = Decrypted { plain: Vec::new(), runs: Vec::new(), undecryptable: Vec::new(), _lease: None };
    if at >= end {
        return Ok(result);
    }
    let supply = &supply[..(end - at) as usize];
    let first = floor_block(at);
    let last = ceil_block(end).saturating_add(16).min(ceil_block(limit));
    budget.usage.charge(Resource::VerifyWorkBytes, last - first)?;
    // Bookkeeping follows the runs and intervals produced, not the blocks visited: a fill over mostly known output
    // costs what a plain fill does.
    budget.usage.charge(Resource::SourceBookkeeping, 1)?;
    let (plain, lease) = budget.leased_vector((last.min(size) - first.min(size)) as usize)?;
    result.plain = plain;
    result._lease = Some(lease);
    let mut run: Option<(u64, usize)> = None;
    let mut previous = if first == 0 {
        Some(CipherBlock { offset: 0, have: 0..16, bytes: keys.iv.unwrap_or(crypt.iv) })
    } else {
        assemble(&snapshot.cipher, first - 16, at, supply)
    };
    let mut offset = first;
    while offset < last {
        let block = assemble(&snapshot.cipher, offset, at, supply);
        let out = block_out(snapshot, offset);
        let decrypted = match (&block, &previous) {
            (Some(block), Some(previous)) if block.whole() && previous.whole() => {
                let mut bytes = keys.aes.decrypt_block(&block.bytes);
                for (b, p) in bytes.iter_mut().zip(previous.bytes) {
                    *b ^= p;
                }
                Some(bytes)
            }
            _ => None,
        };
        match decrypted {
            Some(bytes) if !out.is_empty() => {
                if run.is_none() {
                    budget.usage.charge(Resource::SourceBookkeeping, 1)?;
                    run = Some((out.start, result.plain.len()));
                }
                result.plain.extend_from_slice(&bytes[..(out.end - out.start) as usize]);
            }
            _ => {
                if let Some((start, from)) = run.take() {
                    result.runs.push((start, from..result.plain.len()));
                }
                if decrypted.is_none() && offset < end && unresolved(snapshot, out.clone(), true) {
                    match result.undecryptable.last_mut() {
                        Some(last) if last.end == out.start => last.end = out.end,
                        _ => {
                            budget.usage.check(Resource::HoleIntervals, result.undecryptable.len() as u64 + 1)?;
                            budget.usage.charge(Resource::SourceBookkeeping, 1)?;
                            result.undecryptable.push(out.clone());
                        }
                    }
                }
            }
        }
        previous = block;
        offset += 16;
    }
    if let Some((start, from)) = run {
        result.runs.push((start, from..result.plain.len()));
    }
    Ok(result)
}
/// Blocks of `supply` (at stream offset `at`) worth keeping after a fill: those a remaining hole still needs and
/// whose known bytes the kept set does not already hold.
pub(super) fn keep(
    budget: &PartialBudget,
    snapshot: &Snapshot,
    at: u64,
    supply: &[u8],
) -> PartialResult<Vec<CipherBlock>> {
    let end = (at + supply.len() as u64).min(stream_produced(snapshot));
    let mut blocks = Vec::new();
    if at >= end {
        return Ok(blocks);
    }
    let supply = &supply[..(end - at) as usize];
    let mut offset = floor_block(at);
    // Charged per block kept, like `merge`, not per block visited.
    budget.usage.charge(Resource::SourceBookkeeping, 1)?;
    while offset < end {
        if useful(snapshot, offset)
            && let Some(block) = assemble(&snapshot.cipher, offset, at, supply)
            && snapshot.cipher.binary_search_by_key(&offset, |b| b.offset).map_or(true, |i| snapshot.cipher[i] != block)
        {
            budget.usage.check(Resource::HoleIntervals, blocks.len() as u64 + 1)?;
            budget.usage.charge(Resource::SourceBookkeeping, 1)?;
            budget.metadata(std::mem::size_of::<CipherBlock>() as u64)?;
            blocks.try_reserve(1).map_err(|_| malformed())?;
            blocks.push(block);
        }
        offset += 16;
    }
    Ok(blocks)
}
/// Produced output runs that are holes or alt output, in order. The list is charged to the returned lease, held as
/// long as the caller keeps the list.
pub(super) fn unresolved_runs(
    budget: &PartialBudget,
    snapshot: &Snapshot,
) -> PartialResult<(Vec<Range<u64>>, crate::progressive::Lease)> {
    let produced = snapshot.head.produced;
    budget.usage.charge(Resource::SourceBookkeeping, snapshot.known.len() as u64)?;
    let mut runs: Vec<Range<u64>> = Vec::new();
    let mut lease = budget.metadata_lease(0)?;
    let mut push = |range: Range<u64>| -> PartialResult<()> {
        if range.start >= range.end {
            return Ok(());
        }
        match runs.last_mut() {
            Some(last) if last.end == range.start => last.end = range.end,
            _ => {
                budget.usage.check(Resource::HoleIntervals, runs.len() as u64 + 1)?;
                lease.absorb(budget.metadata_lease(std::mem::size_of::<Range<u64>>() as u64)?);
                runs.try_reserve(1).map_err(|_| malformed())?;
                runs.push(range);
            }
        }
        Ok(())
    };
    let mut at = 0;
    for leaf in &snapshot.known {
        if leaf.range.start >= produced {
            break;
        }
        push(at..leaf.range.start)?;
        if leaf.provenance == state::Provenance::Alt {
            push(leaf.range.start..leaf.range.end.min(produced))?;
        }
        at = leaf.range.end;
    }
    push(at..produced)?;
    Ok((runs, lease))
}
