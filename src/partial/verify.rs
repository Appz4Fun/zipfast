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

use super::*;
use crate::progressive::ChecksumAlgorithm;
use std::task::{Context, Poll};

pub(super) struct Verification {
    pub revision: u64,
    pub parts: Vec<PartCheck>,
    member_crc: CheckResult,
    member_blake: CheckResult,
    active: Option<Readback>,
    readback: Option<VerifyPath>,
    /// Hash key for an encrypted member whose RAR5 checks are keyed (tweaked) with it.
    key: Option<[u8; 32]>,
    /// The member checks are keyed but this handle has no password.
    password_required: bool,
    _lease: Reservation,
    _metadata: crate::progressive::Lease,
}
// BLAKE2sp holds eight fixed lanes and a 512-byte round. Reserve a conservative
// 4096 bytes for those internal allocations before constructing the existing hasher.
const BLAKE_STORAGE: u64 = 4096;
struct Readback {
    range: Range<u64>,
    at: u64,
    hash: crate::blake2sp::Blake2sp,
    buffer: Vec<u8>,
    _lease: Reservation,
}
fn complete(snapshot: &Snapshot, range: &Range<u64>) -> bool {
    let mut at = range.start;
    for leaf in &snapshot.known {
        if leaf.range.end <= at {
            continue;
        }
        if leaf.range.start > at {
            break;
        }
        at = leaf.range.end;
        if at >= range.end {
            return true;
        }
    }
    at >= range.end
}
fn crc(
    snapshot: &Snapshot,
    range: &Range<u64>,
    expected: Option<u32>,
    key: Option<&[u8; 32]>,
    budget: &PartialBudget,
) -> PartialResult<CheckResult> {
    let Some(expected) = expected else { return Ok(CheckResult::Missing) };
    if !complete(snapshot, range) {
        return Ok(CheckResult::Pending);
    }
    let mut combined = crate::crc32::Hasher::new();
    for leaf in &snapshot.known {
        if leaf.range.end <= range.start || leaf.range.start >= range.end {
            continue;
        }
        if leaf.range.start < range.start || leaf.range.end > range.end {
            return Err(malformed());
        }
        budget.usage.charge(Resource::VerifyWorkBytes, leaf.range.end - leaf.range.start)?;
        combined.combine(&leaf.hasher);
    }
    let raw = combined.finalize();
    let crc = key.map_or(raw, |key| crate::crypto::rar5_tweak_crc32(raw, key));
    Ok(if crc == expected { CheckResult::Passed } else { CheckResult::Failed })
}
impl Verification {
    /// Fresh checks, reusing nothing.
    #[cfg(test)]
    pub fn new(snapshot: &Snapshot, budget: &PartialBudget, hash_key: Option<&[u8; 32]>) -> PartialResult<Self> {
        Self::after(Vec::new(), &[], snapshot, budget, hash_key)
    }
    /// The checks of `snapshot`, after a write that changed only output `changed`
    /// (empty when `previous` already matches these known leaves). A part
    /// CRC result in `previous` (computed for the known leaves before the
    /// write) whose range lies outside every changed range still holds: it
    /// depends only on the known leaves inside its range. Each write then
    /// re-combines only the parts it touched, instead of every part.
    ///
    /// Encrypted parts carry checks over their ciphertext, keyed with the password: they never check plaintext
    /// output, so they report `Missing`. Keyed member checks need `hash_key`; without it they stay unevaluated and
    /// verification reports [`PartialErrorKind::PasswordRequired`] once nothing else is missing.
    pub fn after(
        previous: Vec<PartCheck>,
        changed: &[Range<u64>],
        snapshot: &Snapshot,
        budget: &PartialBudget,
        hash_key: Option<&[u8; 32]>,
    ) -> PartialResult<Self> {
        let keyed = snapshot.crypt.is_some_and(|crypt| crypt.tweaked_crc);
        let password_required = keyed
            && hash_key.is_none()
            && (snapshot.head.checks.crc32.is_some() || snapshot.head.checks.blake2sp.is_some());
        let key = hash_key.filter(|_| keyed).copied();
        let encrypted = snapshot.crypt.is_some();
        budget.usage.check(Resource::Parts, snapshot.evidence.parts.len() as u64)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(
                snapshot.evidence.parts.len().checked_mul(std::mem::size_of::<PartCheck>()).ok_or_else(malformed)?,
            )
            .ok_or_else(malformed)?;
        let lease = budget.reserve(PartialResource::LedgerBytes, bytes as u64)?;
        // A verification is replaced after every write; charge it while it lives.
        let mut metadata = budget.metadata_lease(std::mem::size_of::<Self>() as u64)?;
        let (mut parts, vector) = budget.leased_vector(snapshot.evidence.parts.len())?;
        metadata.absorb(vector);
        for (i, part) in snapshot.evidence.parts.iter().enumerate() {
            let range = if part.final_part { 0..snapshot.head.size } else { part.out.clone() };
            budget.usage.charge(Resource::SourceBookkeeping, 1 + changed.len() as u64)?;
            let kept = previous
                .get(i)
                .filter(|old| {
                    old.part == part.ordinal
                        && old.volume == part.packed.volume
                        && old.range == range
                        && changed.iter().all(|c| c.end <= range.start || c.start >= range.end)
                })
                .map(|old| old.crc32.clone());
            parts.push(PartCheck {
                volume: part.packed.volume,
                part: part.ordinal,
                crc32: if encrypted {
                    CheckResult::Missing
                } else if let Some(kept) = kept {
                    kept
                } else {
                    crc(snapshot, &range, part.crc32, None, budget)?
                },
                blake2sp: if part.blake2sp.is_some() && !encrypted {
                    CheckResult::Pending
                } else {
                    CheckResult::Missing
                },
                range,
            });
        }
        // An unkeyed final part spanning the whole member with the member's
        // expected CRC is the same check; reuse its result instead of combining
        // every leaf a second time.
        let whole = 0..snapshot.head.size;
        // Only a part check that actually ran can stand in for the member check: encrypted parts are never
        // checked on plaintext (their result is Missing), so they must not short-circuit the member CRC.
        let same = parts.iter().zip(&snapshot.evidence.parts).find(|(check, part)| {
            part.final_part
                && key.is_none()
                && snapshot.crypt.is_none()
                && matches!(check.crc32, CheckResult::Passed | CheckResult::Failed)
                && check.range == whole
                && part.crc32 == snapshot.head.checks.crc32
        });
        let member_crc = if password_required {
            CheckResult::Missing
        } else if let Some((check, _)) = same {
            check.crc32.clone()
        } else {
            crc(snapshot, &whole, snapshot.head.checks.crc32, key.as_ref(), budget)?
        };
        Ok(Self {
            active: None,
            readback: None,
            revision: snapshot.head.revision,
            parts,
            member_crc,
            member_blake: if snapshot.head.checks.blake2sp.is_some() && !password_required {
                CheckResult::Pending
            } else {
                CheckResult::Missing
            },
            key,
            password_required,
            _lease: lease,
            _metadata: metadata,
        })
    }
    #[cfg(test)]
    pub(super) fn member_crc(&self) -> &CheckResult {
        &self.member_crc
    }
    pub fn needs_verification(&self) -> bool {
        self.password_required
            || self.parts.iter().any(|p| p.crc32 == CheckResult::Pending || p.blake2sp == CheckResult::Pending)
            || self.member_crc == CheckResult::Pending
            || self.member_blake == CheckResult::Pending
    }
    fn read_one(&mut self, core: &PartialCore, snapshot: &Snapshot) -> PartialResult<bool> {
        if self.active.is_none() {
            let range = self
                .parts
                .iter()
                .find(|p| p.blake2sp == CheckResult::Pending && complete(snapshot, &p.range))
                .map(|p| p.range.clone())
                .or_else(|| {
                    (self.member_blake == CheckResult::Pending && complete(snapshot, &(0..snapshot.head.size)))
                        .then_some(0..snapshot.head.size)
                });
            let Some(range) = range else { return Ok(false) };
            if core.read_chunk == 0 && !range.is_empty() {
                return Err(err(PartialErrorKind::InvalidOptions));
            }
            let n = (range.end - range.start).min(core.read_chunk as u64) as usize;
            let lease = core.budget.reserve(PartialResource::LedgerBytes, BLAKE_STORAGE + n as u64)?;
            core.budget.metadata(BLAKE_STORAGE)?;
            let mut buffer = core.budget.vector(n)?;
            buffer.resize(n, 0);
            self.active = Some(Readback {
                at: range.start,
                range,
                hash: crate::blake2sp::Blake2sp::new(),
                buffer,
                _lease: lease,
            });
        }
        let active = self.active.as_mut().unwrap();
        if active.at < active.range.end {
            canceled(&core.control)?;
            let n = (active.range.end - active.at).min(active.buffer.len() as u64) as usize;
            core.budget.usage.charge(Resource::VerifyBytes, n as u64)?;
            core.budget.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
            let count = crate::output::range::read_at(&core.native.output.file, active.at, &mut active.buffer[..n])
                .map_err(|e| io_error(OutputOperation::Read, e))?;
            if count == 0 {
                return Err(err(PartialErrorKind::OutputChanged));
            }
            active.hash.update(&active.buffer[..count]);
            active.at += count as u64;
            if self.readback != Some(VerifyPath::WholeReadback) {
                self.readback = Some(if active.range == (0..snapshot.head.size) {
                    VerifyPath::WholeReadback
                } else {
                    VerifyPath::TargetedReadback
                });
            }
        }
        if active.at == active.range.end {
            let active = self.active.take().unwrap();
            let hash = active.hash.finish();
            for (checks, part) in self.parts.iter_mut().zip(&snapshot.evidence.parts) {
                if checks.range == active.range
                    && let Some(expected) = part.blake2sp
                {
                    checks.blake2sp = if hash == expected { CheckResult::Passed } else { CheckResult::Failed };
                }
            }
            if active.range == (0..snapshot.head.size)
                && let Some(expected) = snapshot.head.checks.blake2sp
            {
                let hash = self.key.as_ref().map_or(hash, |key| crate::crypto::rar5_tweak_blake2sp(&hash, key));
                self.member_blake = if hash == expected { CheckResult::Passed } else { CheckResult::Failed };
            }
        }
        Ok(self.active.is_some()
            || self.parts.iter().any(|p| p.blake2sp == CheckResult::Pending && complete(snapshot, &p.range))
            || (self.member_blake == CheckResult::Pending && complete(snapshot, &(0..snapshot.head.size))))
    }
    fn bad(&self, snapshot: &Snapshot) -> Option<Verdict> {
        for (part, checks) in snapshot.evidence.parts.iter().zip(&self.parts) {
            for (result, which) in
                [(&checks.crc32, ChecksumAlgorithm::Crc32), (&checks.blake2sp, ChecksumAlgorithm::Blake2sp)]
            {
                if *result == CheckResult::Failed {
                    return Some(if part.final_part {
                        Verdict::Bad { revision: self.revision, which }
                    } else {
                        Verdict::PartBad { revision: self.revision, volume: checks.volume, part: checks.part, which }
                    });
                }
            }
        }
        for (result, which) in
            [(&self.member_crc, ChecksumAlgorithm::Crc32), (&self.member_blake, ChecksumAlgorithm::Blake2sp)]
        {
            if *result == CheckResult::Failed {
                return Some(Verdict::Bad { revision: self.revision, which });
            }
        }
        None
    }
}
impl PartialCore {
    fn verify_now(&self) -> PartialResult<Poll<Verdict>> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.reconcile(&mut op)?;
        if op.verification.as_ref().is_none_or(|v| v.revision != op.snapshot.head.revision) {
            let previous = self.part_results(&mut op);
            op.verification = Some(Verification::after(previous, &[], &op.snapshot, &self.budget, self.hash_key())?);
        }
        if let Some(bad) = op.verification.as_ref().unwrap().bad(&op.snapshot) {
            return Ok(Poll::Ready(bad));
        }
        let data = op.data.as_mut().unwrap();
        let pending = data.verification.as_mut().unwrap().read_one(self, &data.snapshot)?;
        self.check(&op)?;
        if pending {
            return Ok(Poll::Pending);
        }
        let verification = op.verification.as_ref().unwrap();
        if let Some(bad) = verification.bad(&op.snapshot) {
            return Ok(Poll::Ready(bad));
        }
        let mut parts = self.budget.vector(verification.parts.len())?;
        parts.extend_from_slice(&verification.parts);
        let missing_checks = op.snapshot.head.checks.crc32.is_none() && op.snapshot.head.checks.blake2sp.is_none();
        let password_required = verification.password_required;
        let pending = verification.needs_verification() && !password_required;
        let revision = verification.revision;
        let readback = verification.readback;
        let size = op.snapshot.head.size;
        let holes = ledger::Ledger { known: &mut op.snapshot.known, size, budget: &self.budget }.remaining()?;
        self.check(&op)?;
        if password_required && op.snapshot.head.member_finished && holes.is_empty() && !pending {
            return Err(err(PartialErrorKind::PasswordRequired));
        }
        if !op.snapshot.head.member_finished || !holes.is_empty() || missing_checks || pending || password_required {
            Ok(Poll::Ready(Verdict::Incomplete { revision, holes, parts, missing_checks }))
        } else {
            // The operation token excludes mutation; callbacks have completed and
            // this stamp was checked for the same revision immediately above.
            let result = crate::extract::finish_file_checked(&self.native.output.file, &op.snapshot.evidence.metadata);
            let attribute = |result: Option<std::io::Result<()>>| match result {
                None => AttributeResult::NotRequested,
                Some(Ok(())) => AttributeResult::Applied,
                Some(Err(error)) => AttributeResult::Failed(error),
            };
            let metadata =
                MetadataResult { modified: attribute(result.modified), permissions: attribute(result.permissions) };
            (|| {
                op.stamp = stamp(&self.native)?;
                self.check(&op)
            })()
            .map_err(|mut error| {
                error.committed = Some(op.state.anchor().clone());
                error
            })?;
            Ok(Poll::Ready(Verdict::Ok {
                revision,
                parts,
                path: readback.unwrap_or(if op.reopened {
                    VerifyPath::ReopenRehash
                } else {
                    VerifyPath::ExtentCombine
                }),
                metadata,
            }))
        }
    }
}
impl PartialFile {
    /// Verifies the current revision using retained CRC hashers and bounded local BLAKE readback.
    /// Eligible parts finish even while other output remains missing; no source provider is called.
    pub fn poll_verify(&mut self, cx: &mut Context<'_>) -> Poll<PartialResult<Verdict>> {
        match self.core.verify_now() {
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(e) => Poll::Ready(Err(e)),
            Ok(Poll::Pending) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
