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

//! Owned provisional outputs. Archive engines alone bind verification and publication.
use super::limits::Usage;
use super::*;
use crate::output::OwnedStage;
use crate::rar5::source::SourceStamp;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    task::Context,
};
pub(crate) mod native;
mod policy;
mod quota;
pub(crate) use policy::DirectoryVerdict;
use policy::Policy;
pub(crate) use quota::Capacity;
use quota::{Lease, Quota};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HoleFill {
    #[default]
    Sparse,
    Zero,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HolePolicy {
    #[default]
    Fail,
    PartialStored {
        fill: HoleFill,
    },
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ArtifactAftermath {
    #[default]
    Remove,
    RetainProvisional,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RecoveryPublication {
    #[default]
    Strict,
    VerifiedInner,
}
/// Owned settings; password is never included in Debug output.
pub struct ProgressiveOptions {
    pub extract: crate::extract::Options,
    pub first_name: OsString,
    pub limits: ProgressiveLimits,
    pub hole_policy: HolePolicy,
    pub artifact_aftermath: ArtifactAftermath,
    pub recovery_publication: RecoveryPublication,
    /// Off by default. When true, a RAR 4.x file part that continues into the next volume and stores 0 as its CRC
    /// is read as having no part check, as a RAR 5.0 part without a data CRC is. This lets a caller present a
    /// volume it rebuilt before it has every packed byte, reporting the missing ranges as
    /// [`super::RangeRead::Hole`] and patching them later: RAR 4.x stores a CRC of each part's packed bytes in
    /// every part but the last, which the caller can't know yet.
    ///
    /// The member's own check, the CRC in its final part over the whole unpacked file, still runs, and so does
    /// [`crate::partial::PartialFile::poll_verify`] after a refill. A part whose real CRC happens to be 0 also loses
    /// its part check when this is on. With it off, a part CRC that does not match is an error as before.
    pub rar4_unknown_part_crc: bool,
    password: Option<String>,
}
impl ProgressiveOptions {
    pub fn new(extract: crate::extract::Options, first_name: OsString) -> Self {
        Self {
            extract,
            first_name,
            limits: ProgressiveLimits::default(),
            hole_policy: HolePolicy::default(),
            artifact_aftermath: ArtifactAftermath::default(),
            recovery_publication: RecoveryPublication::default(),
            rar4_unknown_part_crc: false,
            password: None,
        }
    }
    pub(crate) fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    pub fn set_password(&mut self, password: Option<String>) -> ProgressiveResult<()> {
        if let Some(p) = &password {
            let limit = self.limits.password_utf8_bytes.min(4096);
            if p.len() as u64 > limit {
                return Err(ProgressiveFailure::new(FailureKind::Limit {
                    resource: Resource::PasswordUtf8Bytes,
                    limit,
                    attempted: p.len() as u64,
                }));
            }
        }
        self.password = password;
        Ok(())
    }
}
impl std::fmt::Debug for ProgressiveOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressiveOptions")
            .field("extract", &self.extract)
            .field("first_name", &self.first_name)
            .field("limits", &self.limits)
            .field("hole_policy", &self.hole_policy)
            .field("artifact_aftermath", &self.artifact_aftermath)
            .field("rar4_unknown_part_crc", &self.rar4_unknown_part_crc)
            .field("recovery_publication", &self.recovery_publication)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRead {
    Filled { count: usize },
    Hole { len: u64 },
    End,
}
/// Actual publication receipt, distinct from content verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArtifactPublication {
    Unpublished,
    Strict,
    RecoveredInner,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactEvidence {
    Provisional,
    Verified(Verification),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceOrigin {
    Archive,
    Caller { label: Arc<str> },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedEvidence {
    Passed,
    Missing,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationEvidence {
    NotApplicable,
    CbcChecksOnly,
    Authenticated,
    Incomplete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationLevel {
    Strict,
    InnerOnly,
    Unverified,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckVerdict {
    Passed,
    Missing,
    Failed,
}

/// Engine-produced evidence; public callers cannot construct a verification permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verification {
    pub(crate) inner_size: u64,
    pub(crate) read_back: u64,
    pub(crate) checksum: Option<ChecksumValue>,
    pub(crate) replacement_revision: Option<u64>,
    pub(crate) caller: Option<Arc<ExpectedInner>>,
    pub(crate) size: CheckVerdict,
    pub(crate) crc32: CheckVerdict,
    pub(crate) blake2sp: CheckVerdict,
    pub(crate) level: VerificationLevel,
    pub(crate) origin: EvidenceOrigin,
    pub(crate) packed: PackedEvidence,
    pub(crate) authentication: AuthenticationEvidence,
}
impl Verification {
    pub fn inner_size(&self) -> u64 {
        self.inner_size
    }
    /// Output bytes this verification read back. Below `inner_size` when plain stored parts already proven by their
    /// per-part CRC were combined (CRC-32 combine) instead of re-read; equal to it for a whole readback, which is
    /// used whenever a BLAKE2sp has to be computed. Zero when the member was verified while it was extracted.
    pub fn read_back(&self) -> u64 {
        self.read_back
    }
    pub fn checksum(&self) -> Option<&ChecksumValue> {
        self.checksum.as_ref()
    }
    /// Explicit replacement generation that supplied packed evidence, if any.
    pub fn replacement_revision(&self) -> Option<u64> {
        self.replacement_revision
    }
    /// A caller digest checked in addition to every declared archive check.
    pub fn caller_expected(&self) -> Option<&ExpectedInner> {
        self.caller.as_deref()
    }
    pub fn origin(&self) -> &EvidenceOrigin {
        &self.origin
    }
    pub fn size_verdict(&self) -> CheckVerdict {
        self.size
    }
    pub fn crc32_verdict(&self) -> CheckVerdict {
        self.crc32
    }
    pub fn blake2sp_verdict(&self) -> CheckVerdict {
        self.blake2sp
    }
    pub fn level(&self) -> VerificationLevel {
        self.level
    }
    pub fn packed(&self) -> PackedEvidence {
        self.packed
    }
    pub fn authentication(&self) -> AuthenticationEvidence {
        self.authentication
    }
}
pub(crate) struct VerifiedStage {
    member: MemberId,
    generation: u64,
    stamp: SourceStamp,
    verification: Verification,
}
#[derive(Debug)]
pub(crate) enum Publication {
    Provisional,
    Published { cleanup_failure: Option<ProgressiveFailure> },
}
pub(crate) struct Target {
    path: PathBuf,
    initial: Option<TargetStamp>,
    directory: bool,
    parent_path: PathBuf,
    parent: fs::File,
    parent_identity: native::Identity,
    parent_unbound: bool,
    member: MemberId,
    stage_identity: Option<native::Identity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputHole {
    pub offset: u64,
    pub len: u64,
}
struct Authority {
    control: SessionControl,
}
pub(crate) struct Termination {
    pub(crate) failure: ProgressiveFailure,
    pub(crate) artifact: Option<Artifact>,
    pub(crate) cleanup_failure: Option<ProgressiveFailure>,
}
pub(crate) struct OutputContext {
    root: Arc<Root>,
    usage: Usage,
    quota: Quota,
    authority: Arc<Authority>,
    aftermath: ArtifactAftermath,
    directories: Vec<policy::Directory>,
    /// the files this session published or tested: the files a RAR 5.0 hard link or file copy may take
    pub(crate) extracted: crate::extract::link::Extracted,
}
struct Root {
    path: PathBuf,
    file: fs::File,
    identity: native::Identity,
    flatten: bool,
    overwrite: crate::extract::Overwrite,
    protected: Vec<(PathBuf, Option<native::Identity>)>,
}
impl OutputContext {
    pub(crate) fn new(options: &ProgressiveOptions, usage: Usage, control: SessionControl) -> ProgressiveResult<Self> {
        let root_reservation = options.extract.dest.as_os_str().len().checked_add(4096).ok_or_else(invalid)?;
        usage.charge(Resource::MetadataBytes, root_reservation as u64)?;
        let path = std::path::absolute(if options.extract.dest.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &options.extract.dest
        })
        .map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        usage.charge(Resource::MetadataBytes, path.capacity().saturating_sub(root_reservation) as u64)?;
        fs::create_dir_all(&path).map_err(|e| out(OutputOperation::Create, e, 0))?;
        let file = open_directory(&path)?;
        let identity = native::Identity::file(&file).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        let mut protected = Vec::new();
        usage.charge(Resource::ProtectionPaths, options.extract.protected_paths.len() as u64)?;
        usage.charge(
            Resource::MetadataBytes,
            (options.extract.protected_paths.len() * std::mem::size_of::<(PathBuf, Option<native::Identity>)>()) as u64,
        )?;
        protected.try_reserve_exact(options.extract.protected_paths.len()).map_err(|_| invalid())?;
        for p in &options.extract.protected_paths {
            usage.charge(Resource::SourceBookkeeping, (path.as_os_str().len() + p.as_os_str().len() + 2) as u64)?;
            usage.charge(Resource::MetadataBytes, (path.as_os_str().len() + p.as_os_str().len() + 2) as u64)?;
            let p = std::path::absolute(p).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
            usage.charge(Resource::ProtectionPathBytes, p.capacity() as u64)?;
            let id = match fs::metadata(&p) {
                Ok(m) => Some(native::Identity::metadata(&m).map_err(|e| out(OutputOperation::Metadata, e, 0))?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            };
            protected.push((p, id));
        }
        Ok(Self {
            root: Arc::new(Root {
                path,
                file,
                identity,
                flatten: options.extract.flatten,
                overwrite: options.extract.overwrite,
                protected,
            }),
            usage,
            quota: Quota::new(options.limits.retained_artifacts, options.limits.active_outputs),
            authority: Arc::new(Authority { control }),
            aftermath: options.artifact_aftermath,
            directories: Vec::new(),
            extracted: Default::default(),
        })
    }
    pub(crate) fn terminate(&self, mut stage: Stage, failure: ProgressiveFailure) -> Termination {
        if stage.lease.is_none() {
            return Termination { failure, artifact: None, cleanup_failure: None };
        }
        if self.aftermath == ArtifactAftermath::RetainProvisional {
            return Termination { failure, artifact: Some(stage.into_artifact()), cleanup_failure: None };
        }
        match stage.discard() {
            Ok(()) => Termination { failure, artifact: None, cleanup_failure: None },
            Err(cleanup_failure) => {
                Termination { failure, artifact: Some(stage.into_artifact()), cleanup_failure: Some(cleanup_failure) }
            }
        }
    }
    pub(crate) fn poll_capacity(&self, cx: &mut Context<'_>) -> ProgressiveResult<Capacity> {
        self.authority.control.register(cx.waker());
        if self.authority.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        Ok(self.quota.poll(cx))
    }
    pub(crate) fn create(&mut self, member: MemberId, size: Option<u64>) -> ProgressiveResult<Stage> {
        if self.authority.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        let lease = self.quota.acquire()?;
        self.root.check()?;
        self.usage.charge(
            Resource::MetadataBytes,
            (self.root.path.as_os_str().len() as u64).saturating_add(256).saturating_mul(2),
        )?;
        self.usage.charge(
            Resource::SourceBookkeeping,
            (self.root.path.as_os_str().len() as u64).saturating_mul(2).saturating_add(1),
        )?;
        let native = OwnedStage::create(&self.root.path).map_err(|e| out(OutputOperation::Create, e, 0))?;
        Ok(Stage {
            native,
            root: self.root.clone(),
            member,
            size,
            produced: 0,
            valid: 0,
            length: 0,
            reserved: 0,
            generation: 0,
            published: false,
            assessment: Default::default(),
            target_created: false,
            metadata: None,
            holes: Vec::new(),
            zero_pending: None,
            usage: self.usage.clone(),
            lease: Some(lease),
            authority: Arc::downgrade(&self.authority),
            trusted: None,
        })
        .map(|mut stage| {
            stage.trusted = stage.current_stamp();
            stage
        })
    }
}
impl Drop for OutputContext {
    fn drop(&mut self) {
        self.quota.clear_registration();
    }
}
impl Root {
    fn check(&self) -> ProgressiveResult<()> {
        guard::check_directory(&self.path, &self.file, self.identity)
    }
}
pub(crate) struct Stage {
    pub(super) native: OwnedStage,
    root: Arc<Root>,
    pub(super) member: MemberId,
    pub(super) size: Option<u64>,
    pub(super) produced: u64,
    pub(super) valid: u64,
    pub(super) length: u64,
    reserved: u64,
    pub(super) generation: u64,
    pub(super) published: bool,
    pub(super) assessment: std::cell::RefCell<super::session::recovery::Assessment>,
    target_created: bool,
    metadata: Option<crate::extract::Meta>,
    pub(super) holes: Vec<OutputHole>,
    zero_pending: Option<(u64, u64)>,
    /// The stamp after the library's own last write, kept only while every write since creation found the stamp
    /// it left. Any other writer breaks the chain for good, so verify must then read everything back.
    pub(super) trusted: Option<crate::rar5::source::SourceStamp>,
    pub(super) usage: Usage,
    lease: Option<Lease>,
    authority: Weak<Authority>,
}
impl Stage {
    pub(super) fn current_stamp(&self) -> Option<crate::rar5::source::SourceStamp> {
        crate::rar5::source::SourceStamp::from_metadata(self.native.file().metadata().ok()?).ok()
    }
    /// Call before each library write: keeps the chain only if nobody else wrote since the last one. Returns
    /// whether the chain held; the stamp stays cleared until `trust_written` restores it after a full write.
    pub(super) fn untrust_for_write(&mut self) -> bool {
        let held = self.trusted.is_some_and(|t| self.current_stamp() == Some(t));
        self.trusted = None;
        held
    }
    pub(super) fn trust_written(&mut self, held: bool) {
        if held {
            self.trusted = self.current_stamp();
        }
    }
    pub(super) fn mutation(&self) -> ProgressiveResult<()> {
        if self.published {
            return Err(invalid());
        }
        let authority = self.authority.upgrade().ok_or_else(invalid)?;
        if authority.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        self.check_identity()
    }
    pub(crate) fn check_identity(&self) -> ProgressiveResult<()> {
        self.usage.charge(Resource::SourceBookkeeping, 4)?;
        self.root.check()?;
        self.native.check(self.length).map_err(|e| out(OutputOperation::Metadata, e, 0))
    }
    fn extent(&mut self, end: u64) -> ProgressiveResult<()> {
        if self.size.is_some_and(|n| end > n) {
            return Err(invalid());
        }
        let growth = end.saturating_sub(self.reserved);
        self.usage.output_extent(growth)?;
        self.reserved = self.reserved.max(end);
        Ok(())
    }
    pub(crate) fn write_at(&mut self, offset: u64, bytes: &[u8]) -> ProgressiveResult<usize> {
        self.mutation()?;
        if offset != self.produced || bytes.is_empty() {
            return Err(invalid());
        }
        self.usage.check(Resource::ReadChunk, bytes.len() as u64)?;
        let next_generation = self.generation.checked_add(1).ok_or_else(invalid)?;
        let end = offset.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
        self.extent(end)?;
        self.usage.charge(Resource::OutputWriteBytes, bytes.len() as u64)?;
        let held = self.untrust_for_write();
        let count = self
            .native
            .write_at(offset, bytes)
            .map_err(|e| out_range(OutputOperation::Write, e, offset, bytes.len() as u64, 0))?;
        self.trust_written(held);
        if count == 0 {
            return Err(out_range(
                OutputOperation::Write,
                std::io::ErrorKind::WriteZero.into(),
                offset,
                bytes.len() as u64,
                0,
            ));
        }
        self.assessment.get_mut().evidence = None;
        self.produced = offset + count as u64;
        self.valid += count as u64;
        self.length = self.length.max(self.produced);
        self.generation = next_generation;
        Ok(count)
    }
    #[allow(dead_code, reason = "recovery stage operations are consumed by Task5")]
    pub(crate) fn set_len(&mut self, length: u64) -> ProgressiveResult<()> {
        self.mutation()?;
        if length < self.length {
            return Err(invalid());
        }
        let next_generation = self.generation.checked_add(1).ok_or_else(invalid)?;
        self.extent(length)?;
        let held = self.untrust_for_write();
        self.native.set_len(length).map_err(|e| out(OutputOperation::Write, e, self.length))?;
        self.trust_written(held);
        self.assessment.get_mut().evidence = None;
        self.length = length;
        self.generation = next_generation;
        Ok(())
    }
    #[allow(dead_code, reason = "recovery stage operations are consumed by Task5")]
    pub(crate) fn hole(&mut self, offset: u64, len: u64, fill: HoleFill) -> ProgressiveResult<()> {
        self.mutation()?;
        if offset != self.produced || len == 0 {
            return Err(invalid());
        }
        let end = offset.checked_add(len).ok_or_else(invalid)?;
        let coalesce = self.holes.last().is_some_and(|h| h.offset + h.len == offset);
        self.usage.charge(Resource::SourceBookkeeping, 1)?;
        if !coalesce {
            self.usage.check(Resource::HoleIntervals, self.holes.len() as u64 + 1)?;
            if self.holes.len() == self.holes.capacity() {
                let old = self.holes.capacity();
                let wanted = old.saturating_mul(2).max(4);
                self.usage.charge(Resource::SourceBookkeeping, old as u64)?;
                self.usage
                    .charge(Resource::MetadataBytes, ((wanted - old) * std::mem::size_of::<OutputHole>()) as u64)?;
                self.holes.try_reserve_exact(wanted - old).map_err(|_| invalid())?;
                self.usage.charge(
                    Resource::MetadataBytes,
                    (self.holes.capacity().saturating_sub(wanted) * std::mem::size_of::<OutputHole>()) as u64,
                )?;
            }
        }
        self.set_len(self.length.max(end))?;
        // Record invalidity before any zero write can partially fail.
        if coalesce {
            self.holes.last_mut().expect("adjacent hole").len += len;
        } else {
            self.holes.push(OutputHole { offset, len });
        }
        self.produced = end;
        if fill == HoleFill::Zero {
            self.zero_pending = Some(match self.zero_pending {
                Some((start, previous)) if previous == offset => (start, end),
                None => (offset, end),
                _ => return Err(invalid()),
            });
        }
        Ok(())
    }
    /// One bounded zero-fill attempt. Invalidity was already recorded by hole().
    pub(crate) fn fill_step(&mut self, maximum: usize) -> ProgressiveResult<usize> {
        let Some((at, end)) = self.zero_pending else { return Ok(0) };
        self.mutation()?;
        let n = (end - at).min(maximum as u64).min(8192) as usize;
        if n == 0 {
            return Err(invalid());
        }
        self.usage.charge(Resource::OutputWriteBytes, n as u64)?;
        self.generation = self.generation.checked_add(1).ok_or_else(invalid)?;
        self.assessment.get_mut().evidence = None;
        let held = self.untrust_for_write();
        let written = self
            .native
            .write_at(at, &[0; 8192][..n])
            .map_err(|e| out_range(OutputOperation::Write, e, at, n as u64, 0))?;
        self.trust_written(held);
        if written == 0 {
            return Err(out_range(OutputOperation::Write, std::io::ErrorKind::WriteZero.into(), at, n as u64, 0));
        }
        self.zero_pending = (at + (written as u64) < end).then_some((at + written as u64, end));
        Ok(written)
    }
    #[cfg(test)]
    pub(crate) fn target(&mut self, name: &str, windows_names: bool) -> ProgressiveResult<Target> {
        self.mutation()?;
        let mut target = Policy { root: &self.root, usage: &self.usage }.target(self.member, name, windows_names)?;
        self.bind_target(&mut target)?;
        Ok(target)
    }
    pub(crate) fn bind_target(&mut self, target: &mut Target) -> ProgressiveResult<()> {
        self.mutation()?;
        if self.target_created || target.member != self.member || target.stage_identity.is_some() {
            return Err(invalid());
        }
        target.stage_identity =
            Some(native::Identity::file(self.native.file()).map_err(|e| out(OutputOperation::Metadata, e, 0))?);
        self.target_created = true;
        Ok(())
    }
    pub(crate) fn set_metadata(&mut self, meta: crate::extract::Meta) {
        self.metadata = Some(meta);
    }
    /// Reconcile authoritative geometry after member finalization. This never
    /// resizes the file or changes an earlier known size declaration.
    pub(crate) fn reconcile_final_size(&mut self, size: u64) -> ProgressiveResult<()> {
        self.mutation()?;
        if self.size.is_some_and(|known| known != size) || self.produced != size || self.length != size {
            return Err(ProgressiveFailure::new(FailureKind::IncompleteOutput));
        }
        if self.size.is_none() {
            let generation = self.generation.checked_add(1).ok_or_else(invalid)?;
            self.size = Some(size);
            self.generation = generation;
            self.assessment.get_mut().evidence = None;
        }
        Ok(())
    }
    /// Called only by an engine after its complete content/evidence verification pass.
    pub(crate) fn bind_verification(&mut self, verification: Verification) -> ProgressiveResult<VerifiedStage> {
        self.mutation()?;
        let stamp = SourceStamp::from_metadata(
            self.native.file().metadata().map_err(|e| out(OutputOperation::Metadata, e, 0))?,
        )
        .map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        self.bind_verification_at(verification, self.generation, stamp)
    }
    /// Recovery carries the stamp under which its whole-inner digest was scanned.
    pub(crate) fn bind_verification_at(
        &mut self,
        verification: Verification,
        generation: u64,
        expected_stamp: SourceStamp,
    ) -> ProgressiveResult<VerifiedStage> {
        self.mutation()?;
        if self.generation != generation {
            return Err(invalid());
        }
        if !self.holes.is_empty()
            || self.produced != self.length
            || self.size != Some(self.produced)
            || verification.inner_size != self.produced
        {
            return Err(ProgressiveFailure::new(FailureKind::IncompleteOutput));
        }
        let stamp = SourceStamp::from_metadata(
            self.native.file().metadata().map_err(|e| out(OutputOperation::Metadata, e, 0))?,
        )
        .map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        if stamp != expected_stamp
            || verification.level == VerificationLevel::Unverified
            || verification.checksum.is_none()
        {
            return Err(invalid());
        }
        self.assessment.get_mut().evidence = Some(verification.clone());
        self.assessment.get_mut().stamp = Some(stamp);
        Ok(VerifiedStage { member: self.member, generation: self.generation, stamp, verification })
    }
    pub(crate) fn publish(
        &mut self,
        target: &mut Target,
        verified: &VerifiedStage,
        source: &mut super::source::SourceDriver,
    ) -> ProgressiveResult<Publication> {
        self.publish_policy(target, verified, source, false)
    }
    pub(super) fn publish_policy(
        &mut self,
        target: &mut Target,
        verified: &VerifiedStage,
        source: &mut super::source::SourceDriver,
        recovered: bool,
    ) -> ProgressiveResult<Publication> {
        self.mutation()?;
        if target.member != self.member
            || Some(native::Identity::file(self.native.file()).map_err(|e| out(OutputOperation::Metadata, e, 0))?)
                != target.stage_identity
        {
            return Err(invalid());
        }
        if verified.member != self.member
            || verified.generation != self.generation
            || verified.verification.level
                != if recovered { VerificationLevel::InnerOnly } else { VerificationLevel::Strict }
            || verified.verification.size != CheckVerdict::Passed
            || if recovered {
                verified.verification.packed == PackedEvidence::Failed
            } else {
                verified.verification.packed != PackedEvidence::Passed
            }
            || verified.verification.authentication == AuthenticationEvidence::Incomplete
        {
            return Err(invalid());
        }
        let stamp = SourceStamp::from_metadata(
            self.native.file().metadata().map_err(|e| out(OutputOperation::Metadata, e, 0))?,
        )
        .map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        if stamp != verified.stamp {
            return Err(invalid());
        }
        let policy = Policy { root: &self.root, usage: &self.usage };
        let authorized = policy.check_target(target, source)?;
        self.mutation()?;
        let current = SourceStamp::from_metadata(
            self.native.file().metadata().map_err(|e| out(OutputOperation::Metadata, e, 0))?,
        )
        .map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        if current != verified.stamp {
            return Err(invalid());
        }
        if !authorized {
            return Ok(Publication::Provisional);
        }
        target.check_parent()?;
        policy.prepare_parents(target, source)?;
        target.check_parent()?;
        policy.parents(&target.path)?;
        if target_stamp(&target.path, target.directory)? != target.initial {
            return Err(invalid());
        }
        // Provider authorization can run caller code; the checked stage stamp must
        // still match after every such callback and immediately before publication.
        self.mutation()?;
        let current = SourceStamp::from_metadata(
            self.native.file().metadata().map_err(|e| out(OutputOperation::Metadata, e, 0))?,
        )
        .map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        if current != verified.stamp {
            return Err(invalid());
        }
        let replace = matches!(self.root.overwrite, crate::extract::Overwrite::Always);
        let cleanup_failure = self
            .native
            .publish_observed(&target.path, replace, |file| {
                if let Some(meta) = &self.metadata {
                    crate::extract::finish_file(file, meta);
                }
            })
            .map_err(|e| out_range(OutputOperation::Publish, e, 0, self.produced, 0))?
            .map(|e| out(OutputOperation::Remove, e, 0));
        self.published = true;
        if cleanup_failure.is_none() {
            self.lease.take();
        }
        Ok(Publication::Published { cleanup_failure })
    }
    #[allow(dead_code, reason = "recovery stage operations are consumed by Task5")]
    pub(crate) fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> ProgressiveResult<ArtifactRead> {
        read_stage(self, offset, buf)
    }
    pub(crate) fn into_artifact(mut self) -> Artifact {
        self.lease.as_mut().expect("slot").deliver();
        let receipt = if self.published {
            Some((ArtifactPublication::Strict, self.assessment.get_mut().evidence.clone().expect("published verdict")))
        } else {
            None
        };
        Artifact { stage: Some(self), recovery: None, receipt }
    }
    pub(crate) fn discard(&mut self) -> ProgressiveResult<()> {
        self.native.discard().map_err(|e| out(OutputOperation::Remove, e, 0))?;
        self.lease.take();
        Ok(())
    }
}
/// A single owned provisional output. No pathname or writable descriptor is exposed.
pub struct Artifact {
    pub(super) stage: Option<Stage>,
    pub(super) recovery: Option<super::session::recovery::Record>,
    pub(super) receipt: Option<(ArtifactPublication, Verification)>,
}
impl Artifact {
    pub fn member(&self) -> Option<MemberId> {
        self.stage.as_ref().map(|s| s.member)
    }
    pub fn size(&self) -> Option<u64> {
        self.stage.as_ref().and_then(|s| s.size)
    }
    pub fn produced_extent(&self) -> u64 {
        self.stage.as_ref().map_or(0, |s| s.produced)
    }
    pub fn holes(&self) -> &[OutputHole] {
        self.stage.as_ref().map_or(&[], |s| s.holes.as_slice())
    }
    pub fn evidence(&self) -> ArtifactEvidence {
        let v = self.receipt.as_ref().map(|(_, v)| v.clone()).or_else(|| {
            self.stage.as_ref().and_then(|s| {
                if self.recovery.as_ref().is_some_and(|r| !r.evidence_current(s)) {
                    None
                } else {
                    s.assessment.borrow().evidence.clone()
                }
            })
        });
        match v {
            Some(v) if v.level != VerificationLevel::Unverified => ArtifactEvidence::Verified(v),
            _ => ArtifactEvidence::Provisional,
        }
    }
    /// All volume indices needed for strict encrypted stored replacement replay.
    pub fn required_verification_volumes(&self) -> impl Iterator<Item = u32> + '_ {
        self.recovery.iter().flat_map(|r| r.required_volumes())
    }
    pub fn publication(&self) -> ArtifactPublication {
        self.receipt.as_ref().map_or(ArtifactPublication::Unpublished, |(p, _)| *p)
    }
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> ProgressiveResult<ArtifactRead> {
        if self.receipt.is_some() {
            return Err(invalid());
        }
        let stage = self.stage.as_mut().ok_or_else(invalid)?;
        let member = stage.member;
        read_stage(stage, offset, buf).map_err(|mut failure| {
            failure.context.member = Some(member);
            failure
        })
    }
    pub fn discard(&mut self) -> ProgressiveResult<()> {
        let stage = self.stage.as_mut().ok_or_else(invalid)?;
        let member = stage.member;
        stage.discard().map_err(|mut failure| {
            failure.context.member = Some(member);
            failure
        })?;
        self.stage.take();
        self.recovery.take();
        Ok(())
    }
}
fn read_stage(stage: &mut Stage, offset: u64, buf: &mut [u8]) -> ProgressiveResult<ArtifactRead> {
    stage.check_identity()?;
    stage.usage.check(Resource::ReadChunk, buf.len() as u64)?;
    if buf.len() > 1048576 {
        return Err(ProgressiveFailure::new(FailureKind::Limit {
            resource: Resource::ReadChunk,
            limit: 1048576,
            attempted: buf.len() as u64,
        }));
    }
    if offset >= stage.produced {
        return Ok(ArtifactRead::End);
    }
    let mut end = stage.produced.min(offset.saturating_add(buf.len() as u64));
    for hole in &stage.holes {
        stage.usage.charge(Resource::SourceBookkeeping, 1)?;
        if hole.offset <= offset && offset < hole.offset + hole.len {
            let len = (hole.offset + hole.len - offset).min(buf.len() as u64);
            return Ok(ArtifactRead::Hole { len });
        }
        if hole.offset > offset {
            end = end.min(hole.offset);
            break;
        }
    }
    let n = (end - offset) as usize;
    stage.usage.charge(Resource::VerifyBytes, n as u64)?;
    let count = stage.native.read_at(offset, &mut buf[..n]).map_err(|e| out(OutputOperation::Read, e, offset))?;
    if count == 0 && n != 0 {
        return Err(out(OutputOperation::Read, std::io::ErrorKind::UnexpectedEof.into(), offset));
    }
    stage.check_identity()?;
    Ok(ArtifactRead::Filled { count })
}
fn invalid() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::InvalidCapability)
}
pub(super) fn out(operation: OutputOperation, cause: std::io::Error, offset: u64) -> ProgressiveFailure {
    let mut e = ProgressiveFailure::new(FailureKind::Output { operation, cause });
    e.context.inner_offset = Some(offset);
    e
}
use guard::open_directory;
#[cfg(all(test, unix))]
mod tests;

#[derive(Clone, Copy, Eq, PartialEq)]
enum TargetStamp {
    Regular(SourceStamp),
    Directory(native::Identity),
}
impl TargetStamp {
    fn identity(self) -> native::Identity {
        match self {
            Self::Regular(s) => native::Identity(s.device, s.inode),
            Self::Directory(id) => id,
        }
    }
}
fn target_stamp(path: &Path, directory: bool) -> ProgressiveResult<Option<TargetStamp>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
    };
    if meta.file_type().is_symlink() || (directory && !meta.is_dir()) || (!directory && !meta.is_file()) {
        return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
    }
    if directory {
        native::Identity::metadata(&meta)
            .map(|id| Some(TargetStamp::Directory(id)))
            .map_err(|e| out(OutputOperation::Metadata, e, 0))
    } else {
        SourceStamp::from_metadata(meta)
            .map(|s| Some(TargetStamp::Regular(s)))
            .map_err(|e| out(OutputOperation::Metadata, e, 0))
    }
}

pub(super) fn out_range(
    operation: OutputOperation,
    cause: std::io::Error,
    offset: u64,
    attempted: u64,
    completed: u64,
) -> ProgressiveFailure {
    let mut failure = out(operation, cause, offset);
    failure.context.output_range = Some(Box::new(OutputRange { offset, attempted, completed }));
    failure
}

impl Target {
    /// Native identity of the stage file bound to this target, which publication renames into place.
    pub(crate) fn stage_identity(&self) -> Option<native::Identity> {
        self.stage_identity
    }
    fn check_parent(&self) -> ProgressiveResult<()> {
        if self.parent_unbound {
            return Err(invalid());
        }
        let bound = fs::symlink_metadata(&self.parent_path).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        if !bound.is_dir()
            || native::Identity::metadata(&bound).map_err(|e| out(OutputOperation::Metadata, e, 0))?
                != self.parent_identity
            || native::Identity::file(&self.parent).map_err(|e| out(OutputOperation::Metadata, e, 0))?
                != self.parent_identity
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) mod guard;
