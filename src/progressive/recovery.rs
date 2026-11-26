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

//! Bounded recovery of owned stored-member stages.
use super::*;
use crate::progressive::output::{ArtifactPublication, Publication, out, out_range};
use crate::rar5::{member::InnerChecks, source::SourceStamp};

/// Whole-inner caller digest. Caller evidence never overrides archive failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedInner {
    Crc32 { digest: u32, label: Arc<str> },
    Blake2sp { digest: [u8; 32], label: Arc<str> },
}
impl ExpectedInner {
    fn label(&self) -> &str {
        match self {
            Self::Crc32 { label, .. } | Self::Blake2sp { label, .. } => label,
        }
    }
    fn checksum(&self) -> ChecksumValue {
        match self {
            Self::Crc32 { digest, .. } => ChecksumValue::Crc32(digest.to_le_bytes()),
            Self::Blake2sp { digest, .. } => ChecksumValue::Blake2sp(*digest),
        }
    }
}
#[derive(Default)]
pub(crate) struct Assessment {
    pub(crate) evidence: Option<Verification>,
    expected: Option<ExpectedInner>,
    revision: u64,
    failed: bool,
    pub(crate) stamp: Option<SourceStamp>,
    pub(crate) evidence_epoch: u64,
}
pub(crate) struct Record {
    model: PhysicalModel,
    target: Target,
    key: Option<[u8; 32]>,
    context: crate::extract::EntryContext,
    missing: bool,
    header_encrypted: bool,
    wires: Vec<WireSnapshot>,
    epoch: Arc<AtomicU64>,
    part_evidence: Vec<PackedEvidence>,
}
impl Record {
    pub(crate) fn required_volumes(&self) -> impl Iterator<Item = u32> + '_ {
        self.wires.iter().filter(|_| self.model.members[0].header.encrypted && self.missing).map(|w| w.volume)
    }
    pub(crate) fn evidence_current(&self, stage: &Stage) -> bool {
        self.epoch.load(Ordering::Acquire) == stage.assessment.borrow().evidence_epoch
    }
    fn new(
        model: PhysicalModel,
        target: Target,
        machine: &MemberMachine,
        header_encrypted: bool,
        wires: Vec<WireSnapshot>,
        epoch: Arc<AtomicU64>,
        part_evidence: Vec<PackedEvidence>,
    ) -> Self {
        Self {
            model,
            target,
            key: machine.cipher.as_ref().and_then(|c| c.checksum_key().copied()),
            context: machine.recovery_context(),
            missing: machine.missing,
            header_encrypted,
            wires,
            epoch,
            part_evidence,
        }
    }
}
pub(crate) struct VerifyJob {
    member: MemberId,
    generation: u64,
    revision: u64,
    stamp: SourceStamp,
    offset: u64,
    crc: crate::crc32::Hasher,
    /// Only when a member BLAKE2sp is declared or expected; otherwise it is not computed.
    blake: Option<crate::blake2sp::Blake2sp>,
    part: usize,
    part_offset: u64,
    part_crc: crate::crc32::Hasher,
    part_blake: Option<crate::blake2sp::Blake2sp>,
    /// Output bytes read back from the stage; parts already proven by their part CRC are combined, not read.
    read_back: u64,
    replay: Option<Replay>,
    verdict: Option<Verification>,
    replacement_revision: u64,
}
fn invalid() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::InvalidCapability)
}
fn incomplete() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::IncompleteOutput)
}
fn stamp(stage: &Stage) -> ProgressiveResult<SourceStamp> {
    SourceStamp::from_metadata(stage.native.file().metadata().map_err(|e| out(OutputOperation::Metadata, e, 0))?)
        .map_err(|e| out(OutputOperation::Metadata, e, 0))
}
impl ProgressiveSession {
    pub(super) fn recovery_record(&mut self, machine: &MemberMachine) -> ProgressiveResult<Record> {
        let parts = &self.model.parts;
        let mut wires = Vec::new();
        for volume in &self.witnesses {
            self.usage.charge(Resource::SourceBookkeeping, parts.len() as u64 + 1)?;
            if parts.iter().any(|p| p.volume == volume.volume as usize) {
                self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<WireSnapshot>() as u64)?;
                wires.try_reserve_exact(1).map_err(|_| invalid())?;
                let count = volume.witnesses.lock().unwrap().len();
                wires.push(WireSnapshot { volume: volume.volume, witnesses: volume.witnesses.clone(), count });
            }
        }
        Ok(Record::new(
            std::mem::take(&mut self.model),
            self.target.take().ok_or_else(invalid)?,
            machine,
            self.parser.encrypted(),
            wires,
            self.replacement_epoch.clone(),
            std::mem::take(&mut self.part_evidence),
        ))
    }
    /// Admit an explicit verification generation (a replacement lane) for `volume`.
    ///
    /// Encrypted stored replay requires every member-part volume
    /// ([`Artifact::required_verification_volumes`](super::Artifact::required_verification_volumes)).
    ///
    /// Only an [`ImmutableFileSource`](super::ImmutableFileSource) lane can authorize publication. The session
    /// recognises that concrete type (through `Any`, so a wrapper around it does not count) and then binds the
    /// replacement's path, descriptor and stamp and protects it from aliasing with the output, like an original
    /// immutable volume. Any other `RangeSource`, including one whose `backing_files` returns real files, can still
    /// produce `Strict` content evidence, but the artifact stays
    /// [`ArtifactPublication::Unpublished`](super::ArtifactPublication::Unpublished), also if recovered
    /// publication is requested later. One such lane is enough to withhold publication for the whole artifact. The
    /// original whole-set authority (a Complete native declaration or sealed memory) is still required too.
    pub fn supply_verification_source(&mut self, volume: u32, source: Box<dyn RangeSource>) -> ProgressiveResult<()> {
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if self.recovery_closed {
            return Err(invalid());
        }
        let next = self.replacement_revision.checked_add(1).ok_or_else(invalid)?;
        self.usage.charge(Resource::SourceBookkeeping, 1)?;
        self.verify_job = None;
        self.driver.abort_replacement_reads()?;
        self.driver.supply_replacement(volume, source)?;
        self.replacement_revision = next;
        self.replacement_epoch.store(next, Ordering::Release);
        Ok(())
    }

    fn recovery_stage<'a>(&self, artifact: &'a Artifact) -> ProgressiveResult<&'a Stage> {
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if artifact.receipt.is_some() || self.recovery_closed {
            return Err(invalid());
        }
        let stage = artifact.stage.as_ref().ok_or_else(invalid)?;
        if stage.member.session != self.nonce || artifact.recovery.is_none() {
            return Err(invalid());
        }
        stage.mutation()?;
        Ok(stage)
    }
    /// Supply a caller checksum with explicit provenance; this invalidates older verdicts.
    pub fn set_expected_inner(&mut self, artifact: &Artifact, expected: ExpectedInner) -> ProgressiveResult<()> {
        let stage = self.recovery_stage(artifact)?;
        self.driver.validate_current()?;
        if expected.label().len() > 1024 {
            return Err(ProgressiveFailure::new(FailureKind::Limit {
                resource: Resource::NameBytes,
                limit: 1024,
                attempted: expected.label().len() as u64,
            }));
        }
        if self.verify_job.as_ref().is_some_and(|j| j.member != stage.member) {
            return Err(invalid());
        }
        self.usage.charge(
            Resource::MetadataBytes,
            expected.label().len() as u64 + std::mem::size_of::<ExpectedInner>() as u64,
        )?;
        self.usage.charge(Resource::SourceBookkeeping, 1)?;
        let mut assessment = stage.assessment.borrow_mut();
        if assessment.failed {
            return Err(incomplete());
        }
        assessment.revision = assessment.revision.checked_add(1).ok_or_else(invalid)?;
        assessment.expected = Some(expected);
        assessment.evidence = None;
        drop(assessment);
        self.verify_job = None;
        self.driver.abort_replacement_reads()?;
        Ok(())
    }
    /// Patch one current hole. Validity commits only when every byte was written.
    pub fn patch(&mut self, artifact: &mut Artifact, offset: u64, bytes: &[u8]) -> ProgressiveResult<()> {
        let member = artifact.member();
        self.patch_inner(artifact, offset, bytes).map_err(|mut error| {
            error.context.member = member;
            error.context.inner_offset = Some(offset);
            error
                .context
                .output_range
                .get_or_insert_with(|| Box::new(OutputRange { offset, attempted: bytes.len() as u64, completed: 0 }));
            error
        })
    }
    fn patch_inner(&mut self, artifact: &mut Artifact, offset: u64, bytes: &[u8]) -> ProgressiveResult<()> {
        let stage = self.recovery_stage(artifact)?;
        if self.verify_job.as_ref().is_some_and(|j| j.member != stage.member) {
            return Err(invalid());
        }
        self.driver.validate_current()?;
        if artifact.recovery.as_ref().unwrap().model.members[0].header.method != 0
            || stage.assessment.borrow().failed
            || bytes.is_empty()
        {
            return Err(invalid());
        }
        self.usage.check(Resource::ReadChunk, bytes.len() as u64)?;
        if bytes.len() > 1 << 20 {
            return Err(invalid());
        }
        let end = offset.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
        if stage.size.is_none_or(|size| end > size) {
            return Err(invalid());
        }
        let at = stage.holes.partition_point(|h| h.offset <= offset);
        self.usage.charge(Resource::SourceBookkeeping, (stage.holes.len().checked_ilog2().unwrap_or(0) + 1) as u64)?;
        let index = at.checked_sub(1).ok_or_else(invalid)?;
        let hole = stage.holes[index];
        let hole_end = hole.offset.checked_add(hole.len).ok_or_else(invalid)?;
        if end > hole_end {
            return Err(invalid());
        }
        let split = offset > hole.offset && end < hole_end;
        self.usage.check(Resource::HoleIntervals, stage.holes.len() as u64 + u64::from(split))?;
        self.usage.charge(Resource::SourceBookkeeping, (stage.holes.len() - index) as u64)?;
        self.verify_job = None;
        self.driver.abort_replacement_reads()?;
        let stage = artifact.stage.as_mut().unwrap();
        if split && stage.holes.len() == stage.holes.capacity() {
            self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<OutputHole>() as u64)?;
            let old = stage.holes.capacity();
            stage.holes.try_reserve_exact(1).map_err(|_| invalid())?;
            self.usage.charge(
                Resource::MetadataBytes,
                (stage.holes.capacity().saturating_sub(old + 1) * std::mem::size_of::<OutputHole>()) as u64,
            )?;
        }
        stage.generation = stage.generation.checked_add(1).ok_or_else(invalid)?;
        stage.assessment.get_mut().evidence = None;
        let held = stage.untrust_for_write();
        let mut completed = 0;
        while completed < bytes.len() {
            let scope = |mut e: ProgressiveFailure| {
                e.context.output_range =
                    Some(Box::new(OutputRange { offset, attempted: bytes.len() as u64, completed: completed as u64 }));
                e
            };
            stage.mutation().map_err(scope)?;
            self.usage.charge(Resource::OutputWriteBytes, (bytes.len() - completed) as u64).map_err(scope)?;
            let n = stage
                .native
                .write_at(offset + completed as u64, &bytes[completed..])
                .map_err(|e| out_range(OutputOperation::Write, e, offset, bytes.len() as u64, completed as u64))?;
            if n == 0 {
                return Err(out_range(
                    OutputOperation::Write,
                    std::io::ErrorKind::WriteZero.into(),
                    offset,
                    bytes.len() as u64,
                    completed as u64,
                ));
            }
            completed += n;
        }
        stage.check_identity()?;
        if split {
            stage.holes[index].len = offset - hole.offset;
            stage.holes.insert(index + 1, OutputHole { offset: end, len: hole_end - end });
        } else if offset == hole.offset && end == hole_end {
            stage.holes.remove(index);
        } else if offset == hole.offset {
            stage.holes[index] = OutputHole { offset: end, len: hole_end - end };
        } else {
            stage.holes[index].len = offset - hole.offset;
        }
        stage.valid = stage.valid.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
        artifact.stage.as_mut().unwrap().trust_written(held);
        Ok(())
    }
    /// Rescan the complete private stage. A strict pass may publish through the
    /// original checked target; successful content checks alone do not grant authority.
    pub fn poll_verify(
        &mut self,
        artifact: &mut Artifact,
        cx: &mut Context<'_>,
    ) -> Poll<ProgressiveResult<Verification>> {
        if self.extraction_active || self.verify_job.as_ref().is_some_and(|j| artifact.member() != Some(j.member)) {
            return Poll::Ready(Err(invalid()));
        }
        self.control.register(cx.waker());
        let result = self.verify_inner(artifact, cx);
        if let Err(e) = &result {
            if artifact.receipt.is_none()
                && let Some(stage) = artifact.stage.as_mut().filter(|s| s.member.session == self.nonce)
            {
                let assessment = stage.assessment.get_mut();
                assessment.failed |= matches!(e.kind, FailureKind::Rar(_) | FailureKind::ChecksumMismatch { .. });
                assessment.evidence = None;
                assessment.stamp = None;
            }
            self.verify_job = None;
            let _ = self.driver.abort_replacement_reads();
        }
        match result {
            Ok(p) => p,
            Err(mut e) => {
                e.context.member = e.context.member.or(artifact.member());
                Poll::Ready(Err(e))
            }
        }
    }
    fn verify_inner(
        &mut self,
        artifact: &mut Artifact,
        cx: &mut Context<'_>,
    ) -> ProgressiveResult<Poll<ProgressiveResult<Verification>>> {
        let stage = self.recovery_stage(artifact)?;
        if self.verify_job.as_ref().is_some_and(|j| j.member != stage.member) {
            return Ok(Poll::Ready(Err(invalid())));
        }
        if !self.driver.replacement_retry_ready(cx)? {
            return Ok(Poll::Pending);
        }
        // Starting a verification is an authority point. A poll that continues the same job is a step, like a
        // header or data step of extraction: it gets the bounded rotating recheck, so a job that polls once per
        // replacement read does not cost polls x the whole inventory. Recording the verdict and publication run the
        // full validation again.
        if self.verify_job.is_some() {
            self.driver.validate_step()?;
        } else {
            self.driver.validate_current()?;
        }
        if !stage.holes.is_empty() || stage.size != Some(stage.produced) || stage.length != stage.produced {
            return Err(incomplete());
        }
        let revision = stage.assessment.borrow().revision;
        if stage.assessment.borrow().failed {
            return Err(incomplete());
        }
        if self.verify_job.is_none() {
            self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<VerifyJob>() as u64)?;
            self.usage.charge(Resource::SourceBookkeeping, 1)?;
            let record = artifact.recovery.as_ref().unwrap();
            let blake_wanted = record.model.members[0].final_checks.is_none_or(|c| c.blake2sp.is_some())
                || matches!(stage.assessment.borrow().expected, Some(ExpectedInner::Blake2sp { .. }));
            let part_blake = |part: usize| record.model.parts.get(part).is_some_and(|p| p.checks.blake2sp.is_some());
            self.verify_job = Some(VerifyJob {
                member: stage.member,
                generation: stage.generation,
                revision,
                stamp: stamp(stage)?,
                offset: 0,
                crc: crate::crc32::Hasher::new(),
                blake: blake_wanted.then(crate::blake2sp::Blake2sp::new),
                part: 0,
                part_offset: 0,
                part_crc: crate::crc32::Hasher::new(),
                part_blake: part_blake(0).then(crate::blake2sp::Blake2sp::new),
                read_back: 0,
                replay: None,
                verdict: None,
                replacement_revision: self.replacement_revision,
            });
        }
        let mut job = self.verify_job.take().unwrap();
        let stage = artifact.stage.as_mut().unwrap();
        if job.generation != stage.generation
            || job.revision != revision
            || job.replacement_revision != self.replacement_revision
            || job.stamp != stamp(stage)?
        {
            return Err(invalid());
        }
        let record = artifact.recovery.as_ref().unwrap();
        let size = stage.size.unwrap();
        if let Some(mut replay) = job.replay.take() {
            let progress = replay
                .poll(
                    record,
                    stage,
                    &mut self.driver,
                    &self.usage,
                    &self.control,
                    self.options.password(),
                    &mut self.buffer,
                    cx,
                )
                .map_err(|mut e| {
                    e.context.member = e.context.member.or(Some(stage.member));
                    let (volume, offset) = replay.position(record);
                    e.context.volume_index = e.context.volume_index.or(volume);
                    e.context.packed_offset = e.context.packed_offset.or(offset);
                    e.context.inner_offset = e.context.inner_offset.or(Some(replay.inner_offset));
                    e
                })?;
            if progress.is_pending() {
                job.replay = Some(replay);
                self.verify_job = Some(job);
                return Ok(Poll::Pending);
            }
            self.driver.validate_replacements()?;
            if job.stamp != stamp(stage)? {
                return Err(invalid());
            }
            let mut v = job.verdict.take().expect("inner verdict");
            v.packed = PackedEvidence::Passed;
            v.replacement_revision = Some(self.replacement_revision);
            if v.checksum.is_some() {
                v.level = VerificationLevel::Strict;
            }
            stage.assessment.get_mut().evidence = Some(v.clone());
            stage.assessment.get_mut().stamp = Some(job.stamp);
            stage.assessment.get_mut().evidence_epoch = self.replacement_revision;
            if v.level == VerificationLevel::Strict {
                self.publish_artifact(artifact, &v, false, job.generation, job.stamp)?;
            }
            return Ok(Poll::Ready(Ok(v)));
        }
        let plain_store = !record.model.members[0].header.encrypted && record.model.members[0].header.method == 0;
        // A non-final plain stored part that passed its declared part CRC during extraction holds exactly those
        // bytes: patches only ever write into holes, and holes make a part's evidence Missing. Its CRC is combined
        // instead of read back, unless a BLAKE2sp must be computed over the whole member.
        if plain_store
            && job.blake.is_none()
            && stage.trusted == Some(job.stamp)
            && record.part_evidence.len() == record.model.parts.len()
        {
            while job.part_offset == 0
                && let Some(part) = record.model.parts.get(job.part)
                && !part.final_part
                && part.checks.blake2sp.is_none()
                && let Some(crc) = part.checks.crc32
                && record.part_evidence[job.part] == PackedEvidence::Passed
                && job.offset.checked_add(part.packed_size).is_some_and(|end| end <= size)
            {
                self.usage.charge(Resource::SourceBookkeeping, 1)?;
                job.crc.combine(&crate::crc32::Hasher::from_parts(crc, part.packed_size));
                job.offset += part.packed_size;
                job.part += 1;
                job.part_blake = record
                    .model
                    .parts
                    .get(job.part)
                    .is_some_and(|p| p.checks.blake2sp.is_some())
                    .then(crate::blake2sp::Blake2sp::new);
            }
        }
        if plain_store
            && let Some(part) = record.model.parts.get(job.part)
            && job.part_offset == part.packed_size
        {
            self.usage.charge(Resource::SourceBookkeeping, 1)?;
            if !part.final_part {
                crate::rar5::member::verify_packed(
                    &record.context,
                    part.checks,
                    job.part_crc.clone(),
                    job.part_blake.clone(),
                    None,
                )
                .map_err(|e| ProgressiveFailure::new(FailureKind::Rar(Box::new(e))))?;
            }
            job.part += 1;
            job.part_offset = 0;
            job.part_crc = crate::crc32::Hasher::new();
            job.part_blake = record
                .model
                .parts
                .get(job.part)
                .is_some_and(|p| p.checks.blake2sp.is_some())
                .then(crate::blake2sp::Blake2sp::new);
            self.verify_job = Some(job);
            cx.waker().wake_by_ref();
            return Ok(Poll::Pending);
        }
        if job.offset < size {
            let part_left = if plain_store {
                let part = record.model.parts.get(job.part).ok_or_else(incomplete)?;
                part.packed_size - job.part_offset
            } else {
                u64::MAX
            };
            let n = (size - job.offset)
                .min(part_left)
                .min(self.buffer.len() as u64)
                .min(self.options.limits.packed_work_per_poll.min(1 << 20)) as usize;
            self.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
            let ArtifactRead::Filled { count } = stage.read_at(job.offset, &mut self.buffer[..n])? else {
                return Err(incomplete());
            };
            job.crc.update(&self.buffer[..count]);
            if let Some(blake) = &mut job.blake {
                blake.update(&self.buffer[..count]);
            }
            if plain_store {
                job.part_crc.update(&self.buffer[..count]);
                if let Some(blake) = &mut job.part_blake {
                    blake.update(&self.buffer[..count]);
                }
                job.part_offset += count as u64;
            }
            job.offset += count as u64;
            job.read_back += count as u64;
            if self.control.is_canceled() {
                return Err(ProgressiveFailure::new(FailureKind::Canceled));
            }
            if job.stamp != stamp(stage)? {
                return Err(invalid());
            }
            self.verify_job = Some(job);
            cx.waker().wake_by_ref();
            return Ok(Poll::Pending);
        }
        if plain_store && job.part != record.model.parts.len() {
            return Err(incomplete());
        }
        let member = &record.model.members[0];
        let checks = member.final_checks.ok_or_else(incomplete)?;
        let mut inner = InnerChecks {
            hasher: job.crc.clone(),
            decoder_crc: false,
            crc: None,
            blake: job.blake.clone(),
            bytes: size,
        };
        if let Err(e) = inner.verify(
            &record.context,
            Some(size),
            checks.crc32,
            checks.blake2sp,
            record.key.as_ref().filter(|_| checks.keyed),
        ) {
            stage.assessment.get_mut().failed = true;
            return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(e))));
        }
        let label_bytes = stage.assessment.borrow().expected.as_ref().map_or(0, |e| e.label().len());
        self.usage.charge(Resource::MetadataBytes, (label_bytes * 3) as u64)?;
        let expected = stage.assessment.borrow().expected.clone();
        if let Some(expected) = &expected {
            let actual = match expected {
                ExpectedInner::Crc32 { .. } => ChecksumValue::Crc32(job.crc.clone().finalize().to_le_bytes()),
                ExpectedInner::Blake2sp { .. } => {
                    ChecksumValue::Blake2sp(job.blake.clone().ok_or_else(incomplete)?.finish())
                }
            };
            if actual != expected.checksum() {
                stage.assessment.get_mut().failed = true;
                return Err(ProgressiveFailure::new(FailureKind::ChecksumMismatch {
                    algorithm: actual.algorithm(),
                    scope: ChecksumScope::Member,
                    expected: Box::new(expected.checksum()),
                    actual: Box::new(actual),
                }));
            }
        }
        let archive = checks
            .blake2sp
            .map(ChecksumValue::Blake2sp)
            .or_else(|| checks.crc32.map(|c| ChecksumValue::Crc32(c.to_le_bytes())));
        let checksum = archive.clone().or_else(|| expected.as_ref().map(ExpectedInner::checksum));
        let packed =
            if member.header.encrypted && (record.missing || record.part_evidence.contains(&PackedEvidence::Missing)) {
                PackedEvidence::Missing
            } else {
                PackedEvidence::Passed
            };
        if expected.is_some() {
            self.usage.charge(
                Resource::MetadataBytes,
                (std::mem::size_of::<ExpectedInner>() + 2 * std::mem::size_of::<usize>()) as u64,
            )?;
        }
        let v = Verification {
            inner_size: size,
            read_back: job.read_back,
            checksum,
            replacement_revision: None,
            caller: expected.clone().map(Arc::new),
            size: CheckVerdict::Passed,
            crc32: if checks.crc32.is_some() { CheckVerdict::Passed } else { CheckVerdict::Missing },
            blake2sp: if checks.blake2sp.is_some() { CheckVerdict::Passed } else { CheckVerdict::Missing },
            level: if archive.is_none() && expected.is_none() {
                VerificationLevel::Unverified
            } else if packed == PackedEvidence::Missing {
                VerificationLevel::InnerOnly
            } else {
                VerificationLevel::Strict
            },
            origin: if archive.is_some() {
                EvidenceOrigin::Archive
            } else {
                expected
                    .as_ref()
                    .map_or(EvidenceOrigin::Archive, |e| EvidenceOrigin::Caller { label: e.label().into() })
            },
            packed,
            authentication: if member.header.encrypted || record.header_encrypted {
                AuthenticationEvidence::CbcChecksOnly
            } else {
                AuthenticationEvidence::NotApplicable
            },
        };
        self.driver.validate_current()?;
        if job.generation != stage.generation || job.stamp != stamp(stage)? {
            return Err(invalid());
        }
        stage.assessment.get_mut().evidence = Some(v.clone());
        stage.assessment.get_mut().stamp = Some(job.stamp);
        stage.assessment.get_mut().evidence_epoch = self.replacement_revision;
        let mut replacements_complete = member.header.encrypted && record.missing;
        if replacements_complete {
            for wire in &record.wires {
                if !self.driver.has_replacement(wire.volume)? {
                    replacements_complete = false;
                    break;
                }
            }
        }
        if replacements_complete {
            job.replay = Some(Replay::new(record, &self.usage, &self.control, self.options.password())?);
            job.verdict = Some(v);
            self.verify_job = Some(job);
            cx.waker().wake_by_ref();
            return Ok(Poll::Pending);
        }
        if v.level == VerificationLevel::Strict {
            self.publish_artifact(artifact, &v, false, job.generation, job.stamp)?;
        }
        Ok(Poll::Ready(Ok(v)))
    }
    fn publish_artifact(
        &mut self,
        artifact: &mut Artifact,
        v: &Verification,
        recovered: bool,
        generation: u64,
        verified_stamp: SourceStamp,
    ) -> ProgressiveResult<bool> {
        let stage = artifact.stage.as_mut().ok_or_else(invalid)?;
        let permit = stage.bind_verification_at(v.clone(), generation, verified_stamp)?;
        let record = artifact.recovery.as_mut().ok_or_else(invalid)?;
        match stage.publish_policy(&mut record.target, &permit, &mut self.driver, recovered)? {
            Publication::Provisional => Ok(false),
            Publication::Published { cleanup_failure } => {
                artifact.receipt = Some((
                    if recovered { ArtifactPublication::RecoveredInner } else { ArtifactPublication::Strict },
                    v.clone(),
                ));
                if let Some(e) = cleanup_failure {
                    self.recovery_closed = true;
                    self.phase = Phase::Done;
                    return Err(e);
                }
                artifact.stage.take();
                artifact.recovery.take();
                Ok(true)
            }
        }
    }
    pub fn publish_recovered(&mut self, artifact: &mut Artifact) -> ProgressiveResult<Verification> {
        if self.extraction_active {
            return Err(invalid());
        }
        let stage = self.recovery_stage(artifact)?;
        if self.verify_job.is_some() || self.options.recovery_publication != RecoveryPublication::VerifiedInner {
            return Err(invalid());
        }
        let cached_stamp = stage.assessment.borrow().stamp;
        if cached_stamp != Some(stamp(stage)?) || !artifact.recovery.as_ref().unwrap().evidence_current(stage) {
            return Err(invalid());
        }
        let v = stage.assessment.borrow().evidence.clone().ok_or_else(incomplete)?;
        if v.replacement_revision.is_some_and(|r| r != self.replacement_revision) {
            return Err(invalid());
        }
        if v.level != VerificationLevel::InnerOnly
            || v.packed == PackedEvidence::Failed
            || v.authentication == AuthenticationEvidence::Incomplete
        {
            return Err(invalid());
        }
        let generation = stage.generation;
        if !self.publish_artifact(artifact, &v, true, generation, cached_stamp.ok_or_else(invalid)?)? {
            return Err(ProgressiveFailure::new(FailureKind::PublicationAuthorityRequired));
        }
        Ok(v)
    }
}

#[derive(Clone, Copy)]
struct WireWitness {
    offset: u64,
    len: u64,
    digest: [u8; 32],
}
pub(crate) struct WireVolume {
    volume: u32,
    witnesses: Arc<std::sync::Mutex<Vec<WireWitness>>>,
}
pub(super) struct WireSnapshot {
    volume: u32,
    witnesses: Arc<std::sync::Mutex<Vec<WireWitness>>>,
    count: usize,
}
impl WireSnapshot {
    /// Binds the existing witness owner and admitted prefix. This is private
    /// framing bookkeeping, not integrity evidence or restart authority.
    pub(super) fn capture_current(volumes: &[WireVolume], volume: u32, usage: &Usage) -> ProgressiveResult<Self> {
        usage.charge(Resource::MetadataBytes, std::mem::size_of::<Self>() as u64)?;
        usage.charge(Resource::SourceBookkeeping, 1)?;
        let current = volumes.last().filter(|v| v.volume == volume).ok_or_else(invalid)?;
        let count = current.witnesses.lock().unwrap().len();
        Ok(Self { volume, witnesses: current.witnesses.clone(), count })
    }
    pub(super) fn matches_current(
        &self,
        volumes: &[WireVolume],
        volume: u32,
        usage: &Usage,
    ) -> ProgressiveResult<bool> {
        usage.charge(Resource::SourceBookkeeping, 1)?;
        let Some(current) = volumes.last() else { return Ok(false) };
        Ok(self.volume == volume
            && current.volume == volume
            && Arc::ptr_eq(&self.witnesses, &current.witnesses)
            && current.witnesses.lock().unwrap().len() == self.count)
    }
}
pub(super) fn record_header(
    volumes: &mut Vec<WireVolume>,
    volume: u32,
    offset: u64,
    bytes: &[u8],
    usage: &Usage,
) -> ProgressiveResult<()> {
    if volumes.last().is_none_or(|v| v.volume != volume) {
        usage.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<WireVolume>() + std::mem::size_of::<Vec<WireWitness>>() + 64) as u64,
        )?;
        volumes.try_reserve_exact(1).map_err(|_| invalid())?;
        volumes.push(WireVolume { volume, witnesses: Arc::new(std::sync::Mutex::new(Vec::new())) });
    }
    let mut hash = crate::blake2sp::Blake2sp::new();
    hash.update(bytes);
    let mut list = volumes.last().unwrap().witnesses.lock().unwrap();
    usage.charge(Resource::SourceBookkeeping, 1)?;
    if list.len() == list.capacity() {
        let old = list.capacity();
        let wanted = old.saturating_mul(2).max(4);
        usage.charge(Resource::SourceBookkeeping, old as u64)?;
        usage.charge(Resource::MetadataBytes, ((wanted - old) * std::mem::size_of::<WireWitness>()) as u64)?;
        list.try_reserve_exact(wanted - old).map_err(|_| invalid())?;
        usage.charge(
            Resource::MetadataBytes,
            (list.capacity().saturating_sub(wanted) * std::mem::size_of::<WireWitness>()) as u64,
        )?;
    }
    list.push(WireWitness { offset, len: bytes.len() as u64, digest: hash.finish() });
    Ok(())
}
struct Replay {
    volume: usize,
    witness: usize,
    witness_offset: u64,
    hash: crate::blake2sp::Blake2sp,
    parser: Option<HeaderParser>,
    part: usize,
    packed_offset: u64,
    inner_offset: u64,
    machine: MemberMachine,
    compare: Vec<u8>,
    compared: usize,
    finished: bool,
}
impl Replay {
    fn position(&self, record: &Record) -> (Option<u32>, Option<u64>) {
        if let Some(volume) = record.wires.get(self.volume) {
            let witness = volume.witnesses.lock().unwrap().get(self.witness).copied();
            (Some(volume.volume), witness.map(|w| w.offset + self.witness_offset))
        } else if let Some(part) = record.model.parts.get(self.part) {
            (Some(part.volume as u32), Some(part.data_offset + self.packed_offset))
        } else {
            (None, None)
        }
    }
    fn new(
        record: &Record,
        usage: &Usage,
        control: &SessionControl,
        password: Option<&str>,
    ) -> ProgressiveResult<Self> {
        let member = &record.model.members[0];
        if member.header.method != 0 {
            return Err(ProgressiveFailure::new(FailureKind::UnsupportedMethod));
        }
        usage.charge(Resource::MetadataBytes, std::mem::size_of::<Self>() as u64)?;
        let machine = MemberMachine::new_with_history(
            &member.header,
            record.context.clone(),
            password,
            usage,
            control,
            None,
            member.wire.legacy.and_then(|w| w.crypt),
        )?;
        Ok(Self {
            volume: 0,
            witness: 0,
            witness_offset: 0,
            hash: crate::blake2sp::Blake2sp::new(),
            parser: None,
            part: 0,
            packed_offset: 0,
            inner_offset: 0,
            machine,
            compare: Vec::new(),
            compared: 0,
            finished: false,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn poll(
        &mut self,
        record: &Record,
        stage: &mut Stage,
        driver: &mut SourceDriver,
        usage: &Usage,
        control: &SessionControl,
        password: Option<&str>,
        buffer: &mut [u8],
        cx: &mut Context<'_>,
    ) -> ProgressiveResult<Poll<()>> {
        if control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if self.compared < self.compare.len() {
            let n = (self.compare.len() - self.compared).min(buffer.len());
            usage.charge(Resource::VerifyWorkBytes, n as u64)?;
            let ArtifactRead::Filled { count } = stage.read_at(self.inner_offset, &mut buffer[..n])? else {
                return Err(incomplete());
            };
            if buffer[..count] != self.compare[self.compared..self.compared + count] {
                return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
            }
            self.inner_offset += count as u64;
            self.compared += count;
            if self.compared == self.compare.len() {
                self.compare.clear();
                self.compared = 0;
            }
            if control.is_canceled() {
                return Err(ProgressiveFailure::new(FailureKind::Canceled));
            }
            cx.waker().wake_by_ref();
            return Ok(Poll::Pending);
        }
        if self.finished {
            return Ok(Poll::Ready(()));
        }
        if self.volume < record.wires.len() {
            let volume = &record.wires[self.volume];
            if self.witness == volume.count {
                self.volume += 1;
                self.witness = 0;
                self.parser = None;
                cx.waker().wake_by_ref();
                return Ok(Poll::Pending);
            }
            if self.parser.is_none() {
                self.parser = Some(HeaderParser::from_start(
                    format!("verification-volume-{}", volume.volume).into(),
                    usage.clone(),
                ));
            }
            let witness = volume.witnesses.lock().unwrap()[self.witness];
            let n = (witness.len - self.witness_offset).min(buffer.len() as u64) as usize;
            let offset = witness.offset + self.witness_offset;
            let count = match driver.poll_replacement(volume.volume, offset, cx, &mut buffer[..n]) {
                Poll::Pending => return Ok(Poll::Pending),
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Ready(Ok(SourceStep::Filled { count, .. })) => count,
                Poll::Ready(Ok(SourceStep::Hole { .. })) => {
                    return Err(ProgressiveFailure::new(FailureKind::HeaderHole));
                }
                _ => return Err(ProgressiveFailure::new(FailureKind::Truncated)),
            };
            usage.charge(Resource::VerifyWorkBytes, count as u64)?;
            self.hash.update(&buffer[..count]);
            if self.witness_offset + count as u64 == witness.len && self.hash.clone().finish() != witness.digest {
                return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
            }
            let parser = self.parser.as_mut().unwrap();
            let (used, step) = parser.advance(&buffer[..count]).map_err(|e| match e.kind {
                FailureKind::Limit { .. } | FailureKind::Canceled => e,
                _ => ProgressiveFailure::new(FailureKind::SourceChanged),
            })?;
            if used != count {
                return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
            }
            if let ParserStep::LegacyKeyRequired { salt } = step {
                let password = password
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?;
                let (key, iv) = crate::rar5::member::controlled_legacy_keys(password, &salt, usage, control)?;
                parser.set_legacy_keys(&key, iv)?;
            }
            if let ParserStep::Frame(frame) = step {
                if self.witness_offset + count as u64 != witness.len {
                    return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
                }
                if matches!(frame.block, Block::Crypt) {
                    let params = frame.header_crypt.ok_or_else(invalid)?.map_err(|_| invalid())?;
                    parser.enable_encryption(
                        password.ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?,
                        params,
                        usage,
                        control,
                    )?;
                }
                usage.charge(Resource::SourceBookkeeping, record.model.parts.len() as u64)?;
                if let Block::File(ref header) = frame.block
                    && let Some(part) = record
                        .model
                        .parts
                        .iter()
                        .find(|p| p.volume == volume.volume as usize && p.data_offset == header.data_at)
                {
                    usage.charge(Resource::SourceBookkeeping, record.model.parts.len() as u64)?;
                    let wire = frame.wire.as_ref().ok_or_else(invalid)?;
                    if part.packed_size != header.packed_size
                        || part.wire_extent != wire.extent
                        || part.crypt != frame.crypt
                        || part.legacy != wire.legacy
                        || part.raw_flags != header.block_flags
                        || part.raw_compression != wire.compression
                        || wire.name != record.model.members[0].wire.name
                    {
                        return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
                    }
                }
            }
            self.witness_offset += count as u64;
            if self.witness_offset == witness.len {
                if std::mem::take(&mut self.hash).finish() != witness.digest {
                    return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
                }
                self.witness += 1;
                self.witness_offset = 0;
            }
            cx.waker().wake_by_ref();
            return Ok(Poll::Pending);
        }
        if self.part == record.model.parts.len() {
            let mut sink = ReplaySink { buffer: &mut self.compare, usage, failure: None };
            let result = self.machine.finish_decode(&mut sink);
            if let Some(e) = sink.failure {
                return Err(e);
            }
            result?;
            self.machine.finish_member(&record.model.members[0])?;
            if self.inner_offset + self.compare.len() as u64 != stage.size.ok_or_else(incomplete)? {
                return Err(incomplete());
            }
            self.finished = true;
            if !self.compare.is_empty() {
                cx.waker().wake_by_ref();
                return Ok(Poll::Pending);
            }
            return Ok(Poll::Ready(()));
        }
        let part = &record.model.parts[self.part];
        if self.packed_offset == 0 {
            self.machine.begin_part(part);
        }
        if self.packed_offset == part.packed_size {
            self.machine.finish_part(part)?;
            self.part += 1;
            self.packed_offset = 0;
            cx.waker().wake_by_ref();
            return Ok(Poll::Pending);
        }
        let n = (part.packed_size - self.packed_offset).min(buffer.len() as u64) as usize;
        let count = match driver.poll_replacement(
            part.volume as u32,
            part.data_offset + self.packed_offset,
            cx,
            &mut buffer[..n],
        ) {
            Poll::Pending => return Ok(Poll::Pending),
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Ready(Ok(SourceStep::Filled { count, .. })) => count,
            Poll::Ready(Ok(SourceStep::Hole { .. })) => return Err(ProgressiveFailure::new(FailureKind::DataHole)),
            _ => return Err(ProgressiveFailure::new(FailureKind::Truncated)),
        };
        usage.charge(Resource::VerifyWorkBytes, count as u64)?;
        let mut sink = ReplaySink { buffer: &mut self.compare, usage, failure: None };
        self.machine.reserve_progressive_scratch(count, usage)?;
        let result = self.machine.feed(&buffer[..count], &mut sink);
        if let Some(e) = sink.failure {
            return Err(e);
        }
        result?;
        self.packed_offset += count as u64;
        cx.waker().wake_by_ref();
        Ok(Poll::Pending)
    }
}
struct ReplaySink<'a> {
    buffer: &'a mut Vec<u8>,
    usage: &'a Usage,
    failure: Option<ProgressiveFailure>,
}
impl crate::rar5::unpack::Sink for ReplaySink<'_> {
    fn put(&mut self, bytes: &[u8]) -> crate::error::Result<()> {
        let result = (|| -> ProgressiveResult<()> {
            let wanted = self.buffer.len().checked_add(bytes.len()).ok_or_else(invalid)?;
            if wanted > (1 << 20) + 16 {
                return Err(incomplete());
            }
            if self.buffer.capacity() < wanted {
                let old = self.buffer.capacity();
                self.usage.charge(Resource::MetadataBytes, (wanted - old) as u64)?;
                self.buffer.try_reserve_exact(wanted - self.buffer.len()).map_err(|_| invalid())?;
                self.usage.charge(Resource::MetadataBytes, self.buffer.capacity().saturating_sub(wanted) as u64)?;
            }
            self.buffer.extend_from_slice(bytes);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                self.failure = Some(e);
                Err(crate::Error::Corrupt("replacement comparison stopped"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_archive() -> Vec<u8> {
        fn block(body: &[u8]) -> Vec<u8> {
            let mut checked = vec![body.len() as u8];
            checked.extend(body);
            let mut result = crc32fast::hash(&checked).to_le_bytes().to_vec();
            result.extend(checked);
            result
        }
        let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
        archive.extend(block(&[1, 0, 0]));
        let mut body = vec![2, 2, 10, 4, 10, 0x20];
        body.extend(crc32fast::hash(b"0123456789").to_le_bytes());
        body.extend([0, 0, 5]);
        body.extend(b"inner");
        archive.extend(block(&body));
        archive.extend(b"0123456789");
        archive.extend(block(&[5, 0, 0]));
        archive
    }

    use std::{fs::File, sync::Mutex, task::Waker};
    struct Missing {
        bytes: Vec<u8>,
        start: u64,
        file: File,
        attack: Arc<Mutex<Option<(usize, File)>>>,
        pause: Option<Arc<Mutex<TestPause>>>,
    }
    struct TestPause {
        offset: u64,
        ready: bool,
        waker: Option<Waker>,
    }
    impl RangeSource for Missing {
        fn info(&self) -> SourceInfo {
            let mut attack = self.attack.lock().unwrap();
            if let Some((remaining, file)) = &mut *attack {
                *remaining -= 1;
                if *remaining == 0 {
                    use std::os::unix::fs::FileExt;
                    file.write_all_at(b"XXXXXXXXXX", 0).unwrap();
                    *attack = None;
                }
            }
            SourceInfo {
                id: SourceId(1),
                generation: 0,
                extent: self.bytes.len() as u64,
                length: SourceLength::Final(self.bytes.len() as u64),
            }
        }
        fn backing_files(&self) -> &[File] {
            std::slice::from_ref(&self.file)
        }
        fn read_at(&mut self, at: u64, b: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            let mut available = b.len();
            if let Some(pause) = &self.pause {
                let mut pause = pause.lock().unwrap();
                if !pause.ready {
                    if at >= pause.offset {
                        pause.waker = Some(cx.waker().clone());
                        return Ok(RangeRead::NotYet);
                    }
                    available = available.min((pause.offset - at) as usize);
                }
            }
            let b = &mut b[..available];
            if at >= self.start && at < self.start + 4 {
                return Ok(RangeRead::Hole { len: (self.start + 4 - at).min(b.len() as u64) });
            }
            let end = (at + b.len() as u64).min(self.bytes.len() as u64).min(if at < self.start {
                self.start
            } else {
                u64::MAX
            });
            let n = (end - at) as usize;
            b[..n].copy_from_slice(&self.bytes[at as usize..end as usize]);
            Ok(RangeRead::Filled { count: n })
        }
    }
    struct Provider {
        source: Option<Missing>,
        declaration: ProtectionDeclaration,
    }
    impl VolumeSource for Provider {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Ready(Box::new(self.source.take().unwrap())))
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            Ok(self.declaration.clone())
        }
    }
    fn setup(
        dir: &std::path::Path,
        write_budget: u64,
        overwrite: crate::extract::Overwrite,
    ) -> (ProgressiveSession, Artifact) {
        setup_attack(dir, write_budget, overwrite, true, Arc::new(Mutex::new(None)))
    }
    fn setup_attack(
        dir: &std::path::Path,
        write_budget: u64,
        overwrite: crate::extract::Overwrite,
        authorized: bool,
        attack: Arc<Mutex<Option<(usize, File)>>>,
    ) -> (ProgressiveSession, Artifact) {
        setup_case(dir, write_budget, overwrite, authorized, attack, test_archive(), None)
    }
    fn setup_case(
        dir: &std::path::Path,
        write_budget: u64,
        overwrite: crate::extract::Overwrite,
        authorized: bool,
        attack: Arc<Mutex<Option<(usize, File)>>>,
        bytes: Vec<u8>,
        pause: Option<(Arc<Mutex<TestPause>>, ArtifactAftermath)>,
    ) -> (ProgressiveSession, Artifact) {
        let start = bytes.windows(10).position(|w| w == b"0123456789").unwrap() as u64 + 3;
        let path = dir.join("source.rar");
        std::fs::write(&path, &bytes).unwrap();
        let file = File::open(&path).unwrap();
        let declaration = ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: vec![ProtectedVolume {
                    index: 0,
                    name: "a.rar".into(),
                    backing: VolumeBacking::Native(vec![ProtectedPath {
                        path,
                        file: Some(Arc::new(file.try_clone().unwrap())),
                    }]),
                }],
                auxiliary_paths: vec![],
            },
        };
        let mut opts = ProgressiveOptions::new(
            crate::extract::Options {
                mode: crate::extract::Mode::Extract,
                dest: dir.join("out"),
                overwrite,
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
                attempt_continued_members: false,
                damaged_input: Default::default(),
                unsupported_filters: Default::default(),
                salvage_truncated_zip: false,
                unix_modes: Default::default(),
                backslashes: Default::default(),
            },
            "a.rar".into(),
        );
        opts.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
        opts.limits.output_write_bytes = write_budget;
        if let Some((_, aftermath)) = &pause {
            opts.artifact_aftermath = *aftermath;
        }
        let pause = pause.map(|(p, _)| p);
        let mut session = ProgressiveSession::new(
            Box::new(Provider {
                source: Some(Missing { bytes, start, file, attack, pause }),
                declaration: if authorized { declaration } else { ProtectionDeclaration::Opaque },
            }),
            opts,
        )
        .unwrap();
        loop {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Pending => {}
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::Partial(a), ..
                }))) => return (session, a),
                Poll::Ready(Err(e)) => panic!("{e}"),
                _ => {}
            }
        }
    }
    fn verify(session: &mut ProgressiveSession, artifact: &mut Artifact) -> ProgressiveResult<Verification> {
        loop {
            if let Poll::Ready(v) = session.poll_verify(artifact, &mut Context::from_waker(Waker::noop())) {
                return v;
            }
        }
    }
    fn fault(operation: crate::output::OwnedOperation, result: Result<Option<usize>, i32>) {
        crate::output::OWNED_STAGE_FAULT.with(|slot| *slot.borrow_mut() = Some((operation, result)));
    }
    #[test]
    fn replacement_comparison_work_is_precharged_separately() {
        for limit in [2, 3] {
            let dir = tempfile::tempdir().unwrap();
            let (mut session, mut artifact) = setup(dir.path(), 100, crate::extract::Overwrite::Always);
            let usage = Usage::new(ProgressiveLimits { verify_work_bytes: limit, ..Default::default() });
            let record = artifact.recovery.as_ref().unwrap();
            let mut replay = Replay::new(record, &usage, &session.control, None).unwrap();
            replay.compare = b"012".to_vec();
            let stage = artifact.stage.as_mut().unwrap();
            let read_usage = Usage::new(ProgressiveLimits { verify_bytes: 3, ..Default::default() });
            stage.usage = read_usage.clone();
            let result = replay.poll(
                record,
                stage,
                &mut session.driver,
                &usage,
                &session.control,
                None,
                &mut [0; 3],
                &mut Context::from_waker(Waker::noop()),
            );
            if limit == 2 {
                assert!(matches!(
                    result,
                    Err(ProgressiveFailure {
                        kind: FailureKind::Limit { resource: Resource::VerifyWorkBytes, limit: 2, attempted: 3 },
                        ..
                    })
                ));
                read_usage.charge(Resource::VerifyBytes, 3).unwrap(); // No attempted stage read.
                assert_eq!(replay.inner_offset, 0);
            } else {
                assert!(matches!(result, Ok(Poll::Pending)));
                assert_eq!(replay.inner_offset, 3);
                assert!(read_usage.charge(Resource::VerifyBytes, 1).is_err());
                assert!(usage.charge(Resource::VerifyWorkBytes, 1).is_err());
            }
        }
    }
    struct NeverCalled;
    impl RangeSource for NeverCalled {
        fn info(&self) -> SourceInfo {
            panic!("closed recovery called provider")
        }
        fn backing_files(&self) -> &[File] {
            panic!("closed recovery called provider")
        }
        fn read_at(&mut self, _: u64, _: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            panic!("closed recovery read")
        }
    }
    #[test]
    fn closed_recovery_rejects_replacement_before_callbacks_and_cancel_has_priority() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _a) = setup(dir.path(), 100, crate::extract::Overwrite::Always);
        s.terminate(ProgressiveFailure::new(FailureKind::Malformed("test terminal failure"))).unwrap();
        assert!(s.recovery_closed);
        s.usage = Usage::new(ProgressiveLimits { source_bookkeeping: 0, ..Default::default() });
        let revision = s.replacement_revision;
        let epoch = s.replacement_epoch.load(Ordering::Acquire);
        assert!(matches!(
            s.supply_verification_source(0, Box::new(NeverCalled)),
            Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. })
        ));
        assert_eq!(s.replacement_revision, revision);
        assert_eq!(s.replacement_epoch.load(Ordering::Acquire), epoch);
        s.control.cancel();
        assert!(matches!(
            s.supply_verification_source(0, Box::new(NeverCalled)),
            Err(ProgressiveFailure { kind: FailureKind::Canceled, .. })
        ));
    }

    #[test]
    fn r1_verification_conflict_preserves_parked_extraction_and_cleanup() {
        for aftermath in [ArtifactAftermath::RetainProvisional, ArtifactAftermath::Remove] {
            for finish_second in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let mut bytes = test_archive();
                bytes.truncate(bytes.len() - 8); // retain first member, replace archive end
                let mut second = test_archive();
                let name = second.windows(5).position(|w| w == b"inner").unwrap();
                // Rebuild the CRC-covered file header with a distinct target name.
                second[name..name + 5].copy_from_slice(b"other");
                let header_end = second.windows(10).position(|w| w == b"0123456789").unwrap();
                let crc = crate::crc32::hash(&second[20..header_end]);
                second[16..20].copy_from_slice(&crc.to_le_bytes());
                let pause_at = (bytes.len() + header_end - 16 + 2) as u64;
                bytes.extend_from_slice(&second[16..]);
                let pause = Arc::new(Mutex::new(TestPause { offset: pause_at, ready: false, waker: None }));
                let (mut s, mut a) = setup_case(
                    dir.path(),
                    100,
                    crate::extract::Overwrite::Skip,
                    true,
                    Arc::new(Mutex::new(None)),
                    bytes,
                    Some((pause.clone(), aftermath)),
                );
                s.patch(&mut a, 3, b"3456").unwrap();
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..100 {
                    assert!(!matches!(s.poll_event(&mut cx), Poll::Ready(Err(_))));
                    if pause.lock().unwrap().waker.is_some() {
                        break;
                    }
                }
                assert!(pause.lock().unwrap().waker.is_some());
                let second_member = s.stage.as_ref().unwrap().member;
                assert_eq!(s.stage.as_ref().unwrap().produced, 2);
                fault(crate::output::OwnedOperation::Remove, Err(libc::EACCES));
                assert!(matches!(
                    s.poll_verify(&mut a, &mut cx),
                    Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. }))
                ));
                assert!(s.verify_job.is_none());
                assert_eq!(s.stage.as_ref().unwrap().member, second_member);
                assert_eq!(a.publication(), ArtifactPublication::Unpublished);
                assert!(s.poll_event(&mut cx).is_pending());
                // The rejected publication never consumed the fault or B's wait.
                crate::output::OWNED_STAGE_FAULT.with(|slot| assert!(slot.borrow_mut().take().is_some()));
                if !finish_second {
                    s.control().cancel();
                    let Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                        failure,
                        artifact,
                        cleanup_failure,
                    }))) = s.poll_event(&mut cx)
                    else {
                        panic!("B must receive terminal aftermath");
                    };
                    assert!(matches!(failure.kind, FailureKind::Canceled));
                    assert!(cleanup_failure.is_none());
                    match (aftermath, artifact) {
                        (ArtifactAftermath::RetainProvisional, Some(mut b)) => {
                            assert_eq!(b.member(), Some(second_member));
                            assert_eq!(b.produced_extent(), 2);
                            let mut prefix = [0; 2];
                            assert_eq!(b.read_at(0, &mut prefix).unwrap(), ArtifactRead::Filled { count: 2 });
                            assert_eq!(&prefix, b"01");
                            b.discard().unwrap();
                        }
                        (ArtifactAftermath::Remove, None) => {}
                        _ => panic!("wrong B aftermath"),
                    }
                    assert_eq!(a.publication(), ArtifactPublication::Unpublished);
                    assert!(!dir.path().join("out/other").exists());
                    a.discard().unwrap();
                    continue;
                }
                let wake = {
                    let mut pause = pause.lock().unwrap();
                    pause.ready = true;
                    pause.waker.take().unwrap()
                };
                wake.wake();
                loop {
                    match s.poll_event(&mut cx) {
                        Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                            member,
                            outcome: MemberOutcome::Verified(_),
                        }))) => {
                            assert_eq!(member, second_member);
                            break;
                        }
                        Poll::Ready(Err(e)) => panic!("{e}"),
                        _ => {}
                    }
                }
                assert_eq!(std::fs::read(dir.path().join("out/other")).unwrap(), b"0123456789");
                fault(crate::output::OwnedOperation::Remove, Err(libc::EACCES));
                assert!(matches!(
                    verify(&mut s, &mut a).unwrap_err().kind,
                    FailureKind::Output { operation: OutputOperation::Remove, .. }
                ));
                assert_eq!(a.publication(), ArtifactPublication::Strict);
                a.discard().unwrap();
                assert_eq!(std::fs::read(dir.path().join("out/inner")).unwrap(), b"0123456789");
                assert!(matches!(s.poll_event(&mut cx), Poll::Ready(Ok(None))));
            }
        }
    }
    fn final_info_mutation(authorized: bool) {
        let dir = tempfile::tempdir().unwrap();
        let attack = Arc::new(Mutex::new(None));
        let (mut s, mut a) =
            setup_attack(dir.path(), 100, crate::extract::Overwrite::Always, authorized, attack.clone());
        s.patch(&mut a, 3, b"3456").unwrap();
        if !authorized {
            verify(&mut s, &mut a).unwrap();
            assert!(matches!(a.evidence(), ArtifactEvidence::Verified(_)));
        }
        let mut cx = Context::from_waker(Waker::noop());
        while !s.verify_job.as_ref().is_some_and(|job| job.offset == 10 && job.part == 1) {
            assert!(s.poll_verify(&mut a, &mut cx).is_pending());
        }
        // One start-of-poll info check, then the final validation callback.
        *attack.lock().unwrap() = Some((2, a.stage.as_ref().unwrap().native.file().try_clone().unwrap()));
        assert!(matches!(
            s.poll_verify(&mut a, &mut cx),
            Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. }))
        ));
        assert!(attack.lock().unwrap().is_none(), "the final info callback ran");
        assert_eq!(a.publication(), ArtifactPublication::Unpublished);
        assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
        assert!(!dir.path().join("out/inner").exists());
    }
    #[test]
    fn r1_final_info_mutation_cannot_publish_old_digest() {
        final_info_mutation(true);
    }
    #[test]
    fn r1_final_info_mutation_cannot_return_provisional_verified_digest() {
        final_info_mutation(false);
    }
    #[test]
    fn failed_short_patch_retains_whole_hole_and_invalidates_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, mut a) = setup(dir.path(), 10, crate::extract::Overwrite::Always);
        let old = a.stage.as_ref().unwrap().generation;
        fault(crate::output::OwnedOperation::Write, Ok(Some(1)));
        let error = s.patch(&mut a, 3, b"3456").unwrap_err();
        assert!(matches!(error.kind, FailureKind::Limit { resource: Resource::OutputWriteBytes, .. }));
        assert_eq!(error.context.output_range.as_deref(), Some(&OutputRange { offset: 3, attempted: 4, completed: 1 }));
        assert_eq!(a.holes(), &[OutputHole { offset: 3, len: 4 }]);
        assert!(a.stage.as_ref().unwrap().generation > old);
        assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
        let mut b = [0; 4];
        a.stage.as_ref().unwrap().native.read_at(3, &mut b).unwrap();
        assert_eq!(b[0], b'3');
        assert_eq!(a.read_at(3, &mut b).unwrap(), ArtifactRead::Hole { len: 4 });
    }
    #[test]
    fn enospc_patch_retains_range_and_retry_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, mut a) = setup(dir.path(), 100, crate::extract::Overwrite::Always);
        fault(crate::output::OwnedOperation::Write, Err(libc::ENOSPC));
        let e = s.patch(&mut a, 3, b"3456").unwrap_err();
        assert_eq!(e.context.output_range.as_deref(), Some(&OutputRange { offset: 3, attempted: 4, completed: 0 }));
        assert_eq!(a.holes(), &[OutputHole { offset: 3, len: 4 }]);
        s.patch(&mut a, 3, b"3456").unwrap();
        verify(&mut s, &mut a).unwrap();
        assert_eq!(a.publication(), ArtifactPublication::Strict);
        assert!(a.read_at(0, &mut [0]).is_err());
    }
    #[test]
    fn recovery_hardlink_cleanup_failure_has_published_receipt_and_stage_only_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, mut a) = setup(dir.path(), 100, crate::extract::Overwrite::Skip);
        s.patch(&mut a, 3, b"3456").unwrap();
        fault(crate::output::OwnedOperation::Remove, Err(libc::EACCES));
        let e = verify(&mut s, &mut a).unwrap_err();
        assert!(matches!(e.kind, FailureKind::Output { operation: OutputOperation::Remove, .. }));
        assert_eq!(a.publication(), ArtifactPublication::Strict);
        assert!(matches!(a.evidence(), ArtifactEvidence::Verified(_)));
        assert_eq!(std::fs::read(dir.path().join("out/inner")).unwrap(), b"0123456789");
        assert!(a.read_at(0, &mut [0]).is_err());
        assert!(s.patch(&mut a, 3, b"3456").is_err());
        let revision = s.replacement_revision;
        assert!(matches!(
            s.supply_verification_source(0, Box::new(NeverCalled)),
            Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. })
        ));
        assert_eq!(s.replacement_revision, revision);
        a.discard().unwrap();
        drop(a);
        assert_eq!(std::fs::read(dir.path().join("out/inner")).unwrap(), b"0123456789");
        assert!(matches!(s.poll_event(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(None))));
    }
}
