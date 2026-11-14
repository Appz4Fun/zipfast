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
mod quota;
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
            password: None,
        }
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactEvidence {
    Provisional,
    Verified(Verification),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceOrigin {
    Archive,
    Caller,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackedEvidence {
    Complete,
    Missing,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationEvidence {
    NotEncrypted,
    RarChecks,
    WinZipAuthenticated,
    Missing,
}
/// Engine-produced evidence; public callers cannot construct a verification permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verification {
    pub(crate) inner_size: u64,
    pub(crate) checksum: ChecksumValue,
    pub(crate) origin: EvidenceOrigin,
    pub(crate) packed: PackedEvidence,
    pub(crate) authentication: AuthenticationEvidence,
}
impl Verification {
    pub fn inner_size(&self) -> u64 {
        self.inner_size
    }
    pub fn checksum(&self) -> &ChecksumValue {
        &self.checksum
    }
    pub fn origin(&self) -> EvidenceOrigin {
        self.origin
    }
    pub fn packed(&self) -> PackedEvidence {
        self.packed
    }
    pub fn authentication(&self) -> AuthenticationEvidence {
        self.authentication
    }
}
#[allow(dead_code)]
pub(crate) struct VerifiedStage {
    member: MemberId,
    generation: u64,
    stamp: SourceStamp,
    verification: Verification,
}
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum Publication {
    Provisional,
    Published { cleanup_failure: Option<ProgressiveFailure> },
}
#[allow(dead_code)]
pub(crate) struct Target {
    path: PathBuf,
    initial: Option<SourceStamp>,
    parent_path: PathBuf,
    parent: fs::File,
    parent_identity: native::Identity,
    parent_unbound: bool,
    member: MemberId,
    stage_identity: native::Identity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputHole {
    pub offset: u64,
    pub len: u64,
}
struct Authority {
    control: SessionControl,
}
#[allow(dead_code)]
pub(crate) struct Termination {
    pub(crate) failure: ProgressiveFailure,
    pub(crate) artifact: Option<Artifact>,
    pub(crate) cleanup_failure: Option<ProgressiveFailure>,
}
#[allow(dead_code)]
pub(crate) struct OutputContext {
    root: Arc<Root>,
    usage: Usage,
    quota: Quota,
    authority: Arc<Authority>,
    aftermath: ArtifactAftermath,
}
struct Root {
    path: PathBuf,
    file: fs::File,
    identity: native::Identity,
    flatten: bool,
    overwrite: crate::extract::Overwrite,
    protected: Vec<(PathBuf, Option<native::Identity>)>,
}
#[allow(dead_code)]
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
            length: 0,
            reserved: 0,
            generation: 0,
            published: false,
            evidence: None,
            target_created: false,
            holes: Vec::new(),
            usage: self.usage.clone(),
            lease: Some(lease),
            authority: Arc::downgrade(&self.authority),
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
        let meta = fs::symlink_metadata(&self.path).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        if !meta.is_dir()
            || native::Identity::metadata(&meta).map_err(|e| out(OutputOperation::Metadata, e, 0))? != self.identity
            || native::Identity::file(&self.file).map_err(|e| out(OutputOperation::Metadata, e, 0))? != self.identity
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[allow(dead_code)]
pub(crate) struct Stage {
    native: OwnedStage,
    root: Arc<Root>,
    member: MemberId,
    size: Option<u64>,
    produced: u64,
    length: u64,
    reserved: u64,
    generation: u64,
    published: bool,
    evidence: Option<Verification>,
    target_created: bool,
    holes: Vec<OutputHole>,
    usage: Usage,
    lease: Option<Lease>,
    authority: Weak<Authority>,
}
#[allow(dead_code)]
impl Stage {
    fn mutation(&self) -> ProgressiveResult<()> {
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
        let count = self
            .native
            .write_at(offset, bytes)
            .map_err(|e| out_range(OutputOperation::Write, e, offset, bytes.len() as u64, 0))?;
        if count == 0 {
            return Err(out_range(
                OutputOperation::Write,
                std::io::ErrorKind::WriteZero.into(),
                offset,
                bytes.len() as u64,
                0,
            ));
        }
        self.evidence = None;
        self.produced = offset + count as u64;
        self.length = self.length.max(self.produced);
        self.generation = next_generation;
        Ok(count)
    }
    pub(crate) fn set_len(&mut self, length: u64) -> ProgressiveResult<()> {
        self.mutation()?;
        if length < self.length {
            return Err(invalid());
        }
        let next_generation = self.generation.checked_add(1).ok_or_else(invalid)?;
        self.extent(length)?;
        self.native.set_len(length).map_err(|e| out(OutputOperation::Write, e, self.length))?;
        self.evidence = None;
        self.length = length;
        self.generation = next_generation;
        Ok(())
    }
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
            let zero = [0; 8192];
            let mut at = offset;
            while at < end {
                self.mutation()?;
                let n = (end - at).min(zero.len() as u64) as usize;
                self.usage.charge(Resource::OutputWriteBytes, n as u64)?;
                let written = self
                    .native
                    .write_at(at, &zero[..n])
                    .map_err(|e| out_range(OutputOperation::Write, e, at, n as u64, 0))?;
                if written == 0 {
                    return Err(out_range(
                        OutputOperation::Write,
                        std::io::ErrorKind::WriteZero.into(),
                        at,
                        n as u64,
                        0,
                    ));
                }
                at += written as u64;
            }
        }
        Ok(())
    }
    pub(crate) fn target(&mut self, name: &str, windows_names: bool) -> ProgressiveResult<Target> {
        self.mutation()?;
        self.usage.charge(Resource::SourceBookkeeping, (name.len() as u64).saturating_mul(8))?;
        self.usage.charge(Resource::NameBytes, name.len() as u64)?;
        self.usage
            .charge(Resource::MetadataBytes, (name.len() * 3 + self.root.path.as_os_str().len() * 2 + 4) as u64)?;
        let relative = crate::path::sanitize_fallible(name, windows_names)
            .map_err(|_| ProgressiveFailure::new(FailureKind::UnsafePath))?;
        let relative =
            if self.root.flatten { Path::new(relative.file_name().ok_or_else(invalid)?) } else { relative.as_path() };
        let path = self.root.path.join(relative);
        self.parents(&path)?;
        let initial = target_stamp(&path)?;
        if self.target_created {
            return Err(invalid());
        }
        let mut parent_path = path.parent().ok_or_else(invalid)?.to_path_buf();
        loop {
            self.usage.charge(Resource::SourceBookkeeping, 1 + parent_path.as_os_str().len() as u64)?;
            match fs::symlink_metadata(&parent_path) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !parent_path.pop() {
                        return Err(invalid());
                    }
                }
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            }
        }
        let parent = open_directory(&parent_path)?;
        let parent_identity = native::Identity::file(&parent).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        let stage_identity =
            native::Identity::file(self.native.file()).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        self.target_created = true;
        Ok(Target {
            path,
            initial,
            parent_path,
            parent,
            parent_identity,
            parent_unbound: false,
            member: self.member,
            stage_identity,
        })
    }
    fn parents(&self, path: &Path) -> ProgressiveResult<()> {
        self.root.check()?;
        let relative = path.parent().ok_or_else(invalid)?.strip_prefix(&self.root.path).map_err(|_| invalid())?;
        self.usage.charge(Resource::MetadataBytes, (path.as_os_str().len() as u64).saturating_mul(2))?;
        let mut at = self.root.path.clone();
        for component in relative.components() {
            self.usage.charge(Resource::SourceBookkeeping, 1 + at.as_os_str().len() as u64)?;
            at.push(component);
            let meta = match fs::symlink_metadata(&at) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            };
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        Ok(())
    }
    fn prepare_parents(&self, target: &mut Target, source: &mut super::source::SourceDriver) -> ProgressiveResult<()> {
        target.check_parent()?;
        let relative =
            target.path.parent().ok_or_else(invalid)?.strip_prefix(&target.parent_path).map_err(|_| invalid())?;
        self.usage.charge(Resource::MetadataBytes, (target.path.as_os_str().len() as u64).saturating_mul(2))?;
        let mut at = target.parent_path.clone();
        for component in relative.components() {
            self.root.check()?;
            target.check_parent()?;
            at.push(component);
            self.usage.charge(Resource::SourceBookkeeping, 8 + at.as_os_str().len() as u64)?;
            self.usage.charge(Resource::MetadataBytes, at.as_os_str().len() as u64)?;
            let bound_path = at.clone();
            self.usage
                .charge(Resource::MetadataBytes, bound_path.capacity().saturating_sub(at.as_os_str().len()) as u64)?;
            match fs::symlink_metadata(&at) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                Ok(_) => return Err(ProgressiveFailure::new(FailureKind::UnsafePath)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    for (protected, _) in &self.root.protected {
                        self.usage.charge(
                            Resource::SourceBookkeeping,
                            1 + (protected.as_os_str().len() + at.as_os_str().len()) as u64,
                        )?;
                        if protected == &at {
                            return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
                        }
                    }
                    if !source.publication_check(&at, None)? {
                        return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                    }
                    // If creation/open/check cannot finish, a retry must never adopt
                    // an unbound directory left by this attempt or its replacement.
                    target.parent_unbound = true;
                    fs::create_dir(&at).map_err(|e| out(OutputOperation::Create, e, 0))?;
                }
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            }
            target.parent_unbound = true;
            let parent = open_directory(&at)?;
            let identity = native::Identity::file(&parent).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
            let meta = fs::symlink_metadata(&at).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
            if !meta.is_dir()
                || native::Identity::metadata(&meta).map_err(|e| out(OutputOperation::Metadata, e, 0))? != identity
            {
                return Err(invalid());
            }
            // One retained parent descriptor, plus the transient replacement above.
            // Each successfully prepared prefix survives errors in later components.
            target.parent_path = bound_path;
            target.parent = parent;
            target.parent_identity = identity;
            target.parent_unbound = false;
        }
        Ok(())
    }
    /// Called only by an engine after its complete content/evidence verification pass.
    pub(crate) fn bind_verification(&mut self, verification: Verification) -> ProgressiveResult<VerifiedStage> {
        self.mutation()?;
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
        self.evidence = Some(verification.clone());
        Ok(VerifiedStage { member: self.member, generation: self.generation, stamp, verification })
    }
    pub(crate) fn publish(
        &mut self,
        target: &mut Target,
        verified: &VerifiedStage,
        source: &mut super::source::SourceDriver,
    ) -> ProgressiveResult<Publication> {
        self.mutation()?;
        if target.member != self.member
            || native::Identity::file(self.native.file()).map_err(|e| out(OutputOperation::Metadata, e, 0))?
                != target.stage_identity
        {
            return Err(invalid());
        }
        if verified.member != self.member
            || verified.generation != self.generation
            || verified.verification.packed != PackedEvidence::Complete
            || verified.verification.authentication == AuthenticationEvidence::Missing
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
        self.parents(&target.path)?;
        target.check_parent()?;
        if target_stamp(&target.path)? != target.initial {
            return Err(invalid());
        }
        let identity = target.initial.map(|s| native::Identity(s.device, s.inode));
        let mut unresolved_protected = false;
        for (path, old) in &self.root.protected {
            self.usage.charge(
                Resource::SourceBookkeeping,
                1 + (path.as_os_str().len() + target.path.as_os_str().len()) as u64,
            )?;
            let now = match fs::metadata(path) {
                Ok(m) => Some(native::Identity::metadata(&m).map_err(|e| out(OutputOperation::Metadata, e, 0))?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            };
            unresolved_protected |= old.is_none() || now.is_none();
            if old.is_some() && old != &now {
                return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
            }
            if path == &target.path || (identity.is_some() && (identity == *old || identity == now)) {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        if !source.publication_check(&target.path, identity)? || unresolved_protected {
            return Ok(Publication::Provisional);
        }
        self.mutation()?;
        target.check_parent()?;
        self.prepare_parents(target, source)?;
        target.check_parent()?;
        self.parents(&target.path)?;
        if target_stamp(&target.path)? != target.initial {
            return Err(invalid());
        }
        let replace = matches!(self.root.overwrite, crate::extract::Overwrite::Always);
        let cleanup_failure = self
            .native
            .publish(&target.path, replace)
            .map_err(|e| out_range(OutputOperation::Publish, e, 0, self.produced, 0))?
            .map(|e| out(OutputOperation::Remove, e, 0));
        self.published = true;
        if cleanup_failure.is_none() {
            self.lease.take();
        }
        Ok(Publication::Published { cleanup_failure })
    }
    pub(crate) fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> ProgressiveResult<ArtifactRead> {
        read_stage(self, offset, buf)
    }
    pub(crate) fn into_artifact(mut self) -> Artifact {
        self.lease.as_mut().expect("slot").deliver();
        let evidence = self.evidence.clone().map_or(ArtifactEvidence::Provisional, ArtifactEvidence::Verified);
        Artifact { stage: Some(self), evidence }
    }
    pub(crate) fn discard(&mut self) -> ProgressiveResult<()> {
        self.native.discard().map_err(|e| out(OutputOperation::Remove, e, 0))?;
        self.lease.take();
        Ok(())
    }
}
/// A single owned provisional output. No pathname or writable descriptor is exposed.
pub struct Artifact {
    stage: Option<Stage>,
    evidence: ArtifactEvidence,
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
    pub fn evidence(&self) -> &ArtifactEvidence {
        &self.evidence
    }
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> ProgressiveResult<ArtifactRead> {
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
            stage.usage.charge(Resource::VerifyBytes, len)?;
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
fn out(operation: OutputOperation, cause: std::io::Error, offset: u64) -> ProgressiveFailure {
    let mut e = ProgressiveFailure::new(FailureKind::Output { operation, cause });
    e.context.inner_offset = Some(offset);
    e
}
fn open_directory(path: &Path) -> ProgressiveResult<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    o.open(path).map_err(|e| out(OutputOperation::Create, e, 0))
}
#[cfg(all(test, unix))]
mod tests;

fn target_stamp(path: &Path) -> ProgressiveResult<Option<SourceStamp>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
    }
    SourceStamp::from_metadata(meta).map(Some).map_err(|e| out(OutputOperation::Metadata, e, 0))
}

fn out_range(
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
