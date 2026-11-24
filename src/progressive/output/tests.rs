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
use std::num::NonZeroU64;
use std::task::{Context, Waker};

fn member(n: u64) -> MemberId {
    MemberId { session: NonZeroU64::new(1).unwrap(), ordinal: n }
}
fn setup(dir: &Path) -> OutputContext {
    let options = ProgressiveOptions::new(
        crate::extract::Options {
            mode: crate::extract::Mode::Extract,
            dest: dir.to_path_buf(),
            overwrite: crate::extract::Overwrite::Always,
            flatten: false,
            threads: None,
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
        },
        "input.rar".into(),
    );
    OutputContext::new(&options, Usage::new(options.limits.clone()), SessionControl::default()).unwrap()
}
#[test]
fn partial_output_is_not_final() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(10)).unwrap();
    assert_eq!(s.write_at(0, b"abc").unwrap(), 3);
    let mut a = s.into_artifact();
    let mut bytes = [99; 8];
    assert_eq!(a.read_at(0, &mut bytes).unwrap(), ArtifactRead::Filled { count: 3 });
    assert_eq!(&bytes[..3], b"abc");
    assert_eq!(a.read_at(3, &mut bytes).unwrap(), ArtifactRead::End);
    assert_eq!(a.produced_extent(), 3);
    assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    a.discard().unwrap();
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    assert!(matches!(a.read_at(0, &mut bytes).unwrap_err().kind, FailureKind::InvalidCapability));
}
#[test]
fn artifact_drop_releases_capacity() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut artifacts = Vec::new();
    for i in 0..16 {
        artifacts.push(c.create(member(i), None).unwrap().into_artifact());
    }
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(c.poll_capacity(&mut cx).unwrap(), Capacity::Needed { retained: 16 });
    assert_eq!(c.poll_capacity(&mut cx).unwrap(), Capacity::Pending);
    assert!(matches!(
        c.create(member(16), None).err().unwrap().kind,
        FailureKind::Limit { resource: Resource::RetainedArtifacts, .. }
    ));
    drop(artifacts.pop());
    assert_eq!(c.poll_capacity(&mut cx).unwrap(), Capacity::Ready);
    let mut s = c.create(member(17), None).unwrap();
    s.write_at(0, b"survives").unwrap();
    let mut a = s.into_artifact();
    drop(c);
    let mut b = [0; 8];
    assert_eq!(a.read_at(0, &mut b).unwrap(), ArtifactRead::Filled { count: 8 });
    assert_eq!(&b, b"survives");
    a.discard().unwrap();
}
#[test]
fn temp_limit_counts_sparse_length() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.usage = Usage::new(ProgressiveLimits { temp_bytes: 9, ..Default::default() });
    let mut s = c.create(member(0), Some(10)).unwrap();
    let error = s.set_len(10).unwrap_err();
    assert!(matches!(error.kind, FailureKind::Limit { resource: Resource::TempBytes, limit: 9, attempted: 10 }));
    assert_eq!(s.native.file().metadata().unwrap().len(), 0);
}
#[test]
fn holes_are_not_valid_bytes() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(8)).unwrap();
    s.write_at(0, b"ab").unwrap();
    s.hole(2, 4, HoleFill::Sparse).unwrap();
    s.write_at(6, b"gh").unwrap();
    let mut a = s.into_artifact();
    let mut b = [77; 8];
    assert_eq!(a.read_at(0, &mut b).unwrap(), ArtifactRead::Filled { count: 2 });
    assert_eq!(a.read_at(2, &mut b).unwrap(), ArtifactRead::Hole { len: 4 });
    assert_eq!(&b[2..], &[77; 6]);
    assert_eq!(a.read_at(6, &mut b).unwrap(), ArtifactRead::Filled { count: 2 });
    assert_eq!(&b[..2], b"gh");
}

struct Provider {
    declaration: ProtectionDeclaration,
}
impl VolumeSource for Provider {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Missing)
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.declaration.clone())
    }
}
fn driver(declaration: ProtectionDeclaration) -> super::super::source::SourceDriver {
    super::super::source::SourceDriver::new(
        Box::new(Provider { declaration }),
        "input.rar".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap()
}
fn complete(paths: Vec<ProtectedPath>) -> ProtectionDeclaration {
    ProtectionDeclaration::Complete {
        epoch: 1,
        inventory: ProtectionInventory {
            volumes: vec![ProtectedVolume {
                index: 0,
                name: "input.rar".into(),
                backing: VolumeBacking::Native(paths),
            }],
            auxiliary_paths: vec![],
        },
    }
}
fn verify(s: &mut Stage) -> VerifiedStage {
    s.bind_verification(Verification {
        inner_size: s.produced,
        read_back: 0,
        checksum: Some(ChecksumValue::Crc32([0; 4])),
        replacement_revision: None,
        caller: None,
        origin: EvidenceOrigin::Archive,
        size: CheckVerdict::Passed,
        crc32: CheckVerdict::Passed,
        blake2sp: CheckVerdict::Missing,
        level: VerificationLevel::Strict,
        packed: PackedEvidence::Passed,
        authentication: AuthenticationEvidence::NotApplicable,
    })
    .unwrap()
}
#[test]
fn stage_never_aliases_source_or_diagnostic() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("input.rar");
    fs::write(&source, b"input").unwrap();
    let diag = d.path().join("diagnostic");
    fs::write(&diag, b"log").unwrap();
    let alias = d.path().join("alias");
    fs::hard_link(&source, &alias).unwrap();
    let mut declaration =
        complete(vec![ProtectedPath { path: source.clone(), file: Some(Arc::new(fs::File::open(&source).unwrap())) }]);
    if let ProtectionDeclaration::Complete { inventory, .. } = &mut declaration {
        inventory
            .auxiliary_paths
            .push(ProtectedPath { path: diag.clone(), file: Some(Arc::new(fs::File::open(&diag).unwrap())) });
    }
    for name in ["input.rar", "alias", "diagnostic"] {
        let mut source = driver(declaration.clone());
        let mut c = setup(d.path());
        let mut s = c.create(member(0), Some(3)).unwrap();
        s.write_at(0, b"new").unwrap();
        let v = verify(&mut s);
        let mut target = s.target(name, false).unwrap();
        assert!(matches!(s.publish(&mut target, &v, &mut source).unwrap_err().kind, FailureKind::UnsafePath));
    }
    assert_eq!(fs::read(source).unwrap(), b"input");
    assert_eq!(fs::read(alias).unwrap(), b"input");
    assert_eq!(fs::read(diag).unwrap(), b"log");
}
#[test]
fn early_member_cannot_replace_unopened_volume() {
    let d = tempfile::tempdir().unwrap();
    let future = d.path().join("input.part2.rar");
    let mut source = driver(complete(vec![ProtectedPath { path: future.clone(), file: None }]));
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut target = s.target("input.part2.rar", false).unwrap();
    assert!(matches!(s.publish(&mut target, &v, &mut source).unwrap_err().kind, FailureKind::UnsafePath));
    assert!(!future.exists());
}
#[test]
fn opaque_and_incomplete_inventory_never_publish() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("target"), b"old").unwrap();
    for declaration in [
        ProtectionDeclaration::Opaque,
        ProtectionDeclaration::Complete { epoch: 1, inventory: ProtectionInventory::default() },
    ] {
        let mut source = driver(declaration);
        let mut c = setup(d.path());
        let mut s = c.create(member(0), Some(3)).unwrap();
        s.write_at(0, b"new").unwrap();
        let v = verify(&mut s);
        let mut target = s.target("target", false).unwrap();
        let result = s.publish(&mut target, &v, &mut source);
        assert!(!matches!(result, Ok(Publication::Published { .. })));
        assert_eq!(fs::read(d.path().join("target")).unwrap(), b"old");
    }
}
#[test]
fn stage_replaced_before_publish() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut target = s.target("target", false).unwrap();
    let stage = fs::read_dir(d.path()).unwrap().next().unwrap().unwrap().path();
    fs::rename(&stage, d.path().join("original-stage")).unwrap();
    fs::write(&stage, b"foreign").unwrap();
    let mut source = driver(ProtectionDeclaration::Opaque);
    assert!(s.publish(&mut target, &v, &mut source).is_err());
    drop(s);
    assert_eq!(fs::read(stage).unwrap(), b"foreign");
    assert!(!d.path().join("target").exists());
}

fn non_file_complete() -> ProtectionDeclaration {
    ProtectionDeclaration::Complete {
        epoch: 7,
        inventory: ProtectionInventory {
            volumes: vec![ProtectedVolume { index: 0, name: "input.rar".into(), backing: VolumeBacking::NonFile }],
            auxiliary_paths: vec![],
        },
    }
}
fn fault(op: crate::output::OwnedOperation, result: Result<Option<usize>, i32>) {
    crate::output::OWNED_STAGE_FAULT.with(|s| *s.borrow_mut() = Some((op, result)));
}
#[test]
fn short_write_and_enospc_preserve_exact_ranges_and_extent_budget() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.usage = Usage::new(ProgressiveLimits {
        logical_output_bytes: 3,
        temp_bytes: 3,
        output_write_bytes: 8,
        ..Default::default()
    });
    let mut s = c.create(member(0), Some(3)).unwrap();
    fault(crate::output::OwnedOperation::Write, Ok(Some(1)));
    assert_eq!(s.write_at(0, b"abc").unwrap(), 1);
    assert_eq!(s.produced, 1);
    fault(crate::output::OwnedOperation::Write, Err(libc::ENOSPC));
    let e = s.write_at(1, b"bc").unwrap_err();
    assert!(
        matches!(e.kind,FailureKind::Output{operation:OutputOperation::Write,ref cause} if cause.raw_os_error()==Some(libc::ENOSPC))
    );
    assert_eq!(e.context.output_range.as_deref(), Some(&OutputRange { offset: 1, attempted: 2, completed: 0 }));
    assert_eq!(s.produced, 1);
    assert_eq!(s.write_at(1, b"bc").unwrap(), 2);
    let mut a = s.into_artifact();
    let mut b = [0; 3];
    a.read_at(0, &mut b).unwrap();
    assert_eq!(&b, b"abc");
}
#[test]
fn rename_failure_preserves_target_and_retry_ownership() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("target"), b"old").unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut target = s.target("target", false).unwrap();
    let mut source = driver(native_complete(d.path()));
    fault(crate::output::OwnedOperation::Publish, Err(libc::EACCES));
    let e = s.publish(&mut target, &v, &mut source).unwrap_err();
    assert!(matches!(e.kind, FailureKind::Output { operation: OutputOperation::Publish, .. }));
    assert_eq!(fs::read(&target.path).unwrap(), b"old");
    assert!(matches!(
        s.publish(&mut target, &v, &mut source).unwrap(),
        Publication::Published { cleanup_failure: None }
    ));
    assert_eq!(fs::read(&target.path).unwrap(), b"new");
}
#[test]
fn cancel_remove_and_retain() {
    for retain in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let mut c = setup(d.path());
        c.aftermath = if retain { ArtifactAftermath::RetainProvisional } else { ArtifactAftermath::Remove };
        let mut s = c.create(member(0), Some(8)).unwrap();
        s.write_at(0, b"abc").unwrap();
        c.authority.control.cancel();
        assert!(matches!(s.write_at(3, b"def").unwrap_err().kind, FailureKind::Canceled));
        let termination = c.terminate(s, ProgressiveFailure::new(FailureKind::Canceled));
        assert!(termination.cleanup_failure.is_none());
        assert!(matches!(termination.failure.kind, FailureKind::Canceled));
        drop(c);
        if retain {
            let mut a = termination.artifact.unwrap();
            let mut b = [0; 8];
            assert_eq!(a.read_at(0, &mut b).unwrap(), ArtifactRead::Filled { count: 3 });
            assert_eq!(&b[..3], b"abc");
            a.discard().unwrap();
        } else {
            assert!(termination.artifact.is_none());
        }
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }
}
#[test]
fn cleanup_failure_keeps_artifact_and_quota_for_retry() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"abc").unwrap();
    fault(crate::output::OwnedOperation::Remove, Err(libc::EACCES));
    let termination = c.terminate(s, ProgressiveFailure::new(FailureKind::Canceled));
    assert!(matches!(
        termination.cleanup_failure.unwrap().kind,
        FailureKind::Output { operation: OutputOperation::Remove, .. }
    ));
    let mut a = termination.artifact.unwrap();
    drop(c);
    let mut b = [0; 3];
    a.read_at(0, &mut b).unwrap();
    assert_eq!(&b, b"abc");
    fault(crate::output::OwnedOperation::Remove, Err(libc::EACCES));
    assert!(a.discard().is_err());
    assert!(a.member().is_some());
    a.discard().unwrap();
    assert!(a.member().is_none());
}
#[test]
fn changed_inventory_revokes_authority() {
    struct Changes(u8, ProtectionDeclaration);
    impl VolumeSource for Changes {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Missing)
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            self.0 += 1;
            let mut d = self.1.clone();
            if let ProtectionDeclaration::Complete { epoch, .. } = &mut d {
                *epoch = u64::from(self.0);
            }
            Ok(d)
        }
    }
    let d = tempfile::tempdir().unwrap();
    let mut source = super::super::source::SourceDriver::new(
        Box::new(Changes(0, native_complete(d.path()))),
        "input.rar".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap();
    let target = d.path().join("target");
    assert!(source.publication_check(&target, None).unwrap());
    assert!(matches!(source.publication_check(&target, None).unwrap_err().kind, FailureKind::SourceChanged));
    assert!(source.publication_check(&target, None).is_err());
    assert!(!target.exists());
}
#[test]
fn publication_cleanup_failure_reports_published_without_rollback() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    Arc::get_mut(&mut c.root).unwrap().overwrite = crate::extract::Overwrite::Skip;
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut target = s.target("target", false).unwrap();
    let mut source = driver(native_complete(d.path()));
    fault(crate::output::OwnedOperation::Remove, Err(libc::EACCES));
    assert!(matches!(
        s.publish(&mut target, &v, &mut source).unwrap(),
        Publication::Published {
            cleanup_failure: Some(ProgressiveFailure {
                kind: FailureKind::Output { operation: OutputOperation::Remove, .. },
                ..
            })
        }
    ));
    assert_eq!(fs::read(&target.path).unwrap(), b"new");
    s.discard().unwrap();
    assert_eq!(fs::read(&target.path).unwrap(), b"new");
}

#[test]
fn native_binding_survives_growth_and_rejects_rebinding() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("input.rar");
    fs::write(&path, b"a").unwrap();
    let held = Arc::new(fs::File::open(&path).unwrap());
    let declaration = complete(vec![ProtectedPath { path: path.clone(), file: Some(held) }]);
    let mut native = native::NativeProtection::new(&Usage::new(ProgressiveLimits::default())).unwrap();
    let mut usage = Usage::new(ProgressiveLimits::default());
    native.refresh(&declaration, &mut usage, 0).unwrap();
    use std::io::Write;
    fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"more").unwrap();
    native.refresh(&declaration, &mut usage, 0).unwrap();
    fs::rename(&path, d.path().join("old")).unwrap();
    fs::write(&path, b"new").unwrap();
    assert!(matches!(native.refresh(&declaration, &mut usage, 0).unwrap_err().kind, FailureKind::SourceChanged));
}
#[test]
fn opaque_native_retention_is_finite_and_checks_upgrade() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("input.rar");
    fs::write(&path, b"old").unwrap();
    let mut usage = Usage::new(ProgressiveLimits { volume_handles: 1, ..Default::default() });
    let mut guard = native::NativeProtection::new(&usage).unwrap();
    let file = fs::File::open(&path).unwrap();
    assert!(matches!(
        guard.admit(0, std::slice::from_ref(&file), &ProtectionDeclaration::Opaque, &mut usage, 0).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::VolumeHandles, .. }
    ));
    let mut usage = Usage::new(ProgressiveLimits::default());
    let mut guard = native::NativeProtection::new(&usage).unwrap();
    guard.admit(0, std::slice::from_ref(&file), &ProtectionDeclaration::Opaque, &mut usage, 0).unwrap();
    drop(file);
    fs::rename(&path, d.path().join("old")).unwrap();
    fs::write(&path, b"new").unwrap();
    let declaration =
        complete(vec![ProtectedPath { path: path.clone(), file: Some(Arc::new(fs::File::open(path).unwrap())) }]);
    assert!(matches!(guard.refresh(&declaration, &mut usage, 0).unwrap_err().kind, FailureKind::SourceContract));
}
#[test]
fn write_budget_charges_failures_and_zero_fill() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.usage = Usage::new(ProgressiveLimits { output_write_bytes: 3, ..Default::default() });
    let mut s = c.create(member(0), Some(4)).unwrap();
    fault(crate::output::OwnedOperation::Write, Err(libc::ENOSPC));
    assert!(s.write_at(0, b"abc").is_err());
    assert!(matches!(
        s.write_at(0, b"a").unwrap_err().kind,
        FailureKind::Limit { resource: Resource::OutputWriteBytes, limit: 3, attempted: 4 }
    ));
    assert_eq!(s.native.file().metadata().unwrap().len(), 0);
    drop(s);
    let mut c = setup(d.path());
    c.usage = Usage::new(ProgressiveLimits { output_write_bytes: 3, ..Default::default() });
    let mut s = c.create(member(1), Some(4)).unwrap();
    s.hole(0, 4, HoleFill::Zero).unwrap();
    assert!(matches!(
        s.fill_step(4).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::OutputWriteBytes, .. }
    ));
    let mut a = s.into_artifact();
    let mut b = [77; 4];
    assert_eq!(a.read_at(0, &mut b).unwrap(), ArtifactRead::Hole { len: 4 });
    assert_eq!(b, [77; 4]);
}
#[test]
fn configured_artifact_capacity_above_default_is_honored() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.quota = Quota::new(17, 1);
    let mut artifacts = Vec::new();
    for i in 0..17 {
        artifacts.push(c.create(member(i), None).unwrap().into_artifact());
    }
    assert!(c.create(member(18), None).is_err());
}
#[test]
fn missing_nested_parent_is_created_only_for_verified_authorized_output() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut t = s.target("nested/deep/file", false).unwrap();
    assert!(!d.path().join("nested").exists());
    let mut opaque = driver(ProtectionDeclaration::Opaque);
    assert!(matches!(s.publish(&mut t, &v, &mut opaque).unwrap(), Publication::Provisional));
    assert!(!d.path().join("nested").exists());
    let mut complete = driver(native_complete(d.path()));
    assert!(matches!(s.publish(&mut t, &v, &mut complete).unwrap(), Publication::Published { cleanup_failure: None }));
    assert_eq!(fs::read(d.path().join("nested/deep/file")).unwrap(), b"new");
}

#[test]
fn adjacent_holes_coalesce_before_member_limit() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.usage = Usage::new(ProgressiveLimits { hole_intervals: 1, ..Default::default() });
    let mut s = c.create(member(0), Some(4)).unwrap();
    s.hole(0, 2, HoleFill::Sparse).unwrap();
    s.hole(2, 2, HoleFill::Sparse).unwrap();
    let mut a = s.into_artifact();
    assert_eq!(a.holes(), &[OutputHole { offset: 0, len: 4 }]);
    let mut b = [77; 4];
    assert_eq!(a.read_at(0, &mut b).unwrap(), ArtifactRead::Hole { len: 4 });
    assert_eq!(b, [77; 4]);
}
#[test]
fn verify_budget_is_shared_after_session_drop() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.usage = Usage::new(ProgressiveLimits { verify_bytes: 3, ..Default::default() });
    let mut artifacts = Vec::new();
    for i in 0..2 {
        let mut s = c.create(member(i), Some(3)).unwrap();
        s.write_at(0, b"abc").unwrap();
        artifacts.push(s.into_artifact());
    }
    drop(c);
    let mut b = [0; 3];
    assert!(artifacts[0].read_at(0, &mut b).is_ok());
    assert!(matches!(
        artifacts[1].read_at(0, &mut b).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::VerifyBytes, limit: 3, attempted: 6 }
    ));
}
#[test]
fn capacity_wake_does_not_retry_provider_and_cancel_uses_latest_waker() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Poll, Wake};
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Waiting(Arc<AtomicUsize>);
    impl VolumeSource for Waiting {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(VolumeAnswer::Wait)
        }
    }
    let control = SessionControl::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut driver = super::super::source::SourceDriver::new(
        Box::new(Waiting(calls.clone())),
        "input.rar".into(),
        ProgressiveLimits::default(),
        control.clone(),
    )
    .unwrap();
    let a = Arc::new(Count(AtomicUsize::new(0)));
    let b = Arc::new(Count(AtomicUsize::new(0)));
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    let mut cx = Context::from_waker(&wa);
    assert!(driver.poll_step(&mut cx, &mut [0; 1]).is_pending());
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.authority = Arc::new(Authority { control: control.clone() });
    c.quota = Quota::new(1, 1);
    let artifact = c.create(member(0), None).unwrap().into_artifact();
    assert_eq!(c.poll_capacity(&mut cx).unwrap(), Capacity::Needed { retained: 1 });
    let mut cx = Context::from_waker(&wb);
    assert_eq!(c.poll_capacity(&mut cx).unwrap(), Capacity::Pending);
    drop(artifact);
    assert_eq!(a.0.load(Ordering::SeqCst), 0);
    assert_eq!(b.0.load(Ordering::SeqCst), 1);
    assert!(driver.poll_step(&mut cx, &mut [0; 1]).is_pending());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    control.cancel();
    assert_eq!(b.0.load(Ordering::SeqCst), 2);
    assert!(matches!(
        driver.poll_step(&mut cx, &mut [0; 1]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
    ));
}
#[test]
fn root_and_target_parent_rebinding_preserve_foreign_names() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("root");
    fs::create_dir_all(root.join("nested")).unwrap();
    let mut c = setup(&root);
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut t = s.target("nested/file", false).unwrap();
    fs::rename(root.join("nested"), root.join("old-nested")).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    let mut source = driver(native_complete(d.path()));
    assert!(s.publish(&mut t, &v, &mut source).is_err());
    assert!(!root.join("nested/file").exists());
    fs::rename(&root, d.path().join("old-root")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("foreign"), b"keep").unwrap();
    assert!(s.write_at(3, b"x").is_err());
    drop(s);
    assert_eq!(fs::read(root.join("foreign")).unwrap(), b"keep");
}
#[test]
fn symlink_targets_and_parents_are_rejected() {
    use std::os::unix::fs::symlink;
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("input"), b"old").unwrap();
    symlink(d.path().join("input"), d.path().join("link")).unwrap();
    symlink(d.path(), d.path().join("parent")).unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    for name in ["link", "parent/new", "../escape"] {
        assert!(s.target(name, false).is_err());
    }
    assert_eq!(fs::read(d.path().join("input")).unwrap(), b"old");
}
#[test]
fn cwd_is_pinned_in_bounded_child() {
    const KEY: &str = "ZIPFAST_PROGRESSIVE_CWD_CHILD";
    if std::env::var_os(KEY).is_some() {
        let d = tempfile::tempdir().unwrap();
        std::env::set_current_dir(d.path()).unwrap();
        fs::write("input", b"abc").unwrap();
        let mut source = ImmutableFileSource::open(Path::new("input")).unwrap();
        let mut c = setup(Path::new("out"));
        let mut s = c.create(member(0), Some(3)).unwrap();
        s.write_at(0, b"new").unwrap();
        let v = verify(&mut s);
        let mut t = s.target("target", false).unwrap();
        let other = tempfile::tempdir().unwrap();
        std::env::set_current_dir(other.path()).unwrap();
        let mut b = [0; 3];
        source.read_at(0, &mut b, &mut Context::from_waker(Waker::noop())).unwrap();
        assert_eq!(&b, b"abc");
        let mut provider = driver(native_complete(d.path()));
        assert!(matches!(
            s.publish(&mut t, &v, &mut provider).unwrap(),
            Publication::Published { cleanup_failure: None }
        ));
        assert_eq!(fs::read(d.path().join("out/target")).unwrap(), b"new");
        assert!(!other.path().join("out").exists());
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "progressive::output::tests::cwd_is_pinned_in_bounded_child", "--nocapture"])
        .env(KEY, "1")
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("CWD child exceeded deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn stage_mode_single_active_and_read_chunk_bounds() {
    use std::os::unix::fs::MetadataExt;
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(1)).unwrap();
    assert_eq!(s.native.file().metadata().unwrap().mode() & 0o777, 0o600);
    assert!(matches!(
        c.create(member(1), None).err().unwrap().kind,
        FailureKind::Limit { resource: Resource::ActiveOutputs, .. }
    ));
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    s.write_at(0, b"x").unwrap();
    let mut a = s.into_artifact();
    let mut large = vec![77; 1048577];
    assert!(matches!(
        a.read_at(0, &mut large).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::ReadChunk, .. }
    ));
    assert!(large.iter().all(|&b| b == 77));
}
#[test]
fn verification_is_bound_to_member_stage_and_generation() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut target = s.target("target", false).unwrap();
    s.set_len(3).unwrap();
    let mut provider = driver(native_complete(d.path()));
    assert!(matches!(s.publish(&mut target, &v, &mut provider).unwrap_err().kind, FailureKind::InvalidCapability));
    let artifact = s.into_artifact();
    assert_eq!(artifact.evidence(), ArtifactEvidence::Provisional);
    assert!(!target.path.exists());
}
#[test]
fn complete_absent_binding_can_appear_but_cannot_rebind() {
    let d = tempfile::tempdir().unwrap();
    let future = d.path().join("future");
    let target = d.path().join("target");
    let mut usage = Usage::new(ProgressiveLimits::default());
    let mut guard = native::NativeProtection::new(&usage).unwrap();
    let mut declaration = complete(vec![ProtectedPath { path: future.clone(), file: None }]);
    guard.refresh(&declaration, &mut usage, 0).unwrap();
    assert!(!guard.resolved_for_publication(&usage).unwrap());
    guard.check_target(&target, None, &mut usage).unwrap();
    fs::write(&future, b"source").unwrap();
    if let ProtectionDeclaration::Complete { inventory, .. } = &mut declaration
        && let VolumeBacking::Native(paths) = &mut inventory.volumes[0].backing
    {
        paths[0].file = Some(Arc::new(fs::File::open(&future).unwrap()));
    }
    guard.refresh(&declaration, &mut usage, 0).unwrap();
    assert!(guard.resolved_for_publication(&usage).unwrap());
    fs::rename(&future, d.path().join("old")).unwrap();
    fs::write(&future, b"foreign").unwrap();
    assert!(matches!(guard.refresh(&declaration, &mut usage, 0).unwrap_err().kind, FailureKind::SourceChanged));
}

#[test]
fn delivered_artifact_does_not_retain_capacity_task_after_context_drop() {
    struct Task;
    impl std::task::Wake for Task {
        fn wake(self: Arc<Self>) {
            panic!("context teardown must drop registration without waking task");
        }
    }
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    c.quota = Quota::new(1, 1);
    let mut stage = c.create(member(0), Some(3)).unwrap();
    stage.write_at(0, b"abc").unwrap();
    let mut artifact = stage.into_artifact();
    let task = Arc::new(Task);
    let weak = Arc::downgrade(&task);
    let waker = Waker::from(task);
    let mut cx = Context::from_waker(&waker);
    assert_eq!(c.poll_capacity(&mut cx).unwrap(), Capacity::Needed { retained: 1 });
    drop(waker);
    drop(c);
    assert!(weak.upgrade().is_none(), "delivered artifact must not retain a parked task");
    let mut b = [0; 3];
    artifact.read_at(0, &mut b).unwrap();
    assert_eq!(&b, b"abc");
    artifact.discard().unwrap();
}

#[test]
fn immutable_growth_after_last_read_and_volume_switch_blocks_publication() {
    use std::io::Write;
    struct Files {
        paths: Vec<PathBuf>,
        handles: Vec<Arc<fs::File>>,
    }
    impl VolumeSource for Files {
        fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Ready(Box::new(ImmutableFileSource::open(&self.paths[r.index as usize])?)))
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            Ok(ProtectionDeclaration::Complete {
                epoch: 1,
                inventory: ProtectionInventory {
                    volumes: self
                        .paths
                        .iter()
                        .zip(&self.handles)
                        .enumerate()
                        .map(|(i, (p, f))| ProtectedVolume {
                            index: i as u32,
                            name: if i == 0 { "input.rar".into() } else { "input.r00".into() },
                            backing: VolumeBacking::Native(vec![ProtectedPath {
                                path: p.clone(),
                                file: Some(f.clone()),
                            }]),
                        })
                        .collect(),
                    auxiliary_paths: vec![],
                },
            })
        }
    }
    for switch in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let paths = vec![d.path().join("input.rar"), d.path().join("input.r00")];
        for p in &paths {
            fs::write(p, b"abc").unwrap();
        }
        let handles = paths.iter().map(|p| Arc::new(fs::File::open(p).unwrap())).collect();
        let mut provider = super::super::source::SourceDriver::new(
            Box::new(Files { paths: paths.clone(), handles }),
            "input.rar".into(),
            ProgressiveLimits::default(),
            SessionControl::default(),
        )
        .unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            provider.poll_step(&mut cx, &mut [0; 3]),
            std::task::Poll::Ready(Ok(super::super::source::SourceStep::VolumeOpened { .. }))
        ));
        assert!(matches!(
            provider.poll_step(&mut cx, &mut [0; 3]),
            std::task::Poll::Ready(Ok(super::super::source::SourceStep::Filled { count: 3, .. }))
        ));
        if switch {
            provider.select_volume(VolumeRequest { index: 1, expected: "input.r00".into() }).unwrap();
            assert!(matches!(
                provider.poll_step(&mut cx, &mut [0; 3]),
                std::task::Poll::Ready(Ok(super::super::source::SourceStep::VolumeOpened { index: 1, .. }))
            ));
        }
        fs::write(d.path().join("target"), b"old").unwrap();
        let mut c = setup(d.path());
        let mut stage = c.create(member(0), Some(3)).unwrap();
        stage.write_at(0, b"new").unwrap();
        let verdict = verify(&mut stage);
        let mut target = stage.target("target", false).unwrap();
        fs::OpenOptions::new().append(true).open(&paths[0]).unwrap().write_all(b"growth").unwrap();
        assert!(matches!(
            stage.publish(&mut target, &verdict, &mut provider).unwrap_err().kind,
            FailureKind::SourceChanged
        ));
        assert_eq!(fs::read(d.path().join("target")).unwrap(), b"old");
    }
}

fn native_complete(root: &Path) -> ProtectionDeclaration {
    let path = root.join("protected-input.rar");
    fs::write(&path, b"source").unwrap();
    let file = Some(Arc::new(fs::File::open(&path).unwrap()));
    complete(vec![ProtectedPath { path, file }])
}

fn assert_custom_non_file_cannot_publish(kind: u8) {
    let d = tempfile::tempdir().unwrap();
    let native = native_complete(d.path());
    let mut declaration = non_file_complete();
    if let ProtectionDeclaration::Complete { inventory, .. } = &mut declaration
        && let ProtectionDeclaration::Complete { inventory: native_inventory, .. } = native
        && let VolumeBacking::Native(paths) = native_inventory.volumes[0].backing.clone()
    {
        if kind == 1 {
            inventory.auxiliary_paths = paths;
        } else if kind == 2 {
            inventory.volumes.push(ProtectedVolume {
                index: 1,
                name: "input.part2.rar".into(),
                backing: VolumeBacking::Native(paths),
            });
        }
    }
    fs::write(d.path().join("target"), b"old").unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"new").unwrap();
    let v = verify(&mut s);
    let mut t = s.target("target", false).unwrap();
    let mut source = driver(declaration);
    assert!(matches!(s.publish(&mut t, &v, &mut source).unwrap(), Publication::Provisional), "kind {kind}");
    assert_eq!(fs::read(&t.path).unwrap(), b"old");
}
#[test]
fn custom_non_file_declaration_cannot_publish() {
    assert_custom_non_file_cannot_publish(0);
}
#[test]
fn custom_non_file_with_native_auxiliary_cannot_publish() {
    assert_custom_non_file_cannot_publish(1);
}
#[test]
fn custom_mixed_native_and_non_file_cannot_publish() {
    assert_custom_non_file_cannot_publish(2);
}

#[test]
fn created_parent_rebinding_after_publish_failure_is_rejected() {
    for rebind in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let mut source = driver(native_complete(d.path()));
        let mut c = setup(d.path());
        let mut s = c.create(member(0), Some(3)).unwrap();
        s.write_at(0, b"new").unwrap();
        let v = verify(&mut s);
        let mut t = s.target("nested/deep/file", false).unwrap();
        fault(crate::output::OwnedOperation::Publish, Err(libc::EACCES));
        assert!(matches!(
            s.publish(&mut t, &v, &mut source).unwrap_err().kind,
            FailureKind::Output { operation: OutputOperation::Publish, .. }
        ));
        assert!(d.path().join("nested/deep").is_dir());
        if !rebind {
            assert!(matches!(
                s.publish(&mut t, &v, &mut source).unwrap(),
                Publication::Published { cleanup_failure: None }
            ));
            assert_eq!(fs::read(&t.path).unwrap(), b"new");
            continue;
        }
        fs::rename(d.path().join("nested"), d.path().join("original")).unwrap();
        fs::create_dir_all(d.path().join("nested/deep")).unwrap();
        fs::write(d.path().join("nested/deep/foreign"), b"keep").unwrap();
        assert!(s.publish(&mut t, &v, &mut source).is_err());
        assert!(!t.path.exists());
        assert!(!d.path().join("original/deep/file").exists());
        assert_eq!(fs::read(d.path().join("nested/deep/foreign")).unwrap(), b"keep");
    }
}

#[test]
fn zero_fill_write_zero_reports_exact_range_and_keeps_hole_invalid() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(5)).unwrap();
    s.write_at(0, b"ab").unwrap();
    fault(crate::output::OwnedOperation::Write, Ok(Some(0)));
    s.hole(2, 3, HoleFill::Zero).unwrap();
    let e = s.fill_step(3).unwrap_err();
    assert!(matches!(e.kind, FailureKind::Output { operation: OutputOperation::Write, ref cause }
        if cause.kind() == std::io::ErrorKind::WriteZero));
    assert_eq!(e.context.output_range.as_deref(), Some(&OutputRange { offset: 2, attempted: 3, completed: 0 }));
    let mut a = s.into_artifact();
    let mut b = [77; 3];
    assert_eq!(a.read_at(2, &mut b).unwrap(), ArtifactRead::Hole { len: 3 });
    assert_eq!(b, [77; 3]);
}

#[test]
fn final_size_reconciliation_never_resizes_or_replaces_a_known_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let mut context = setup(dir.path());
    let mut stage = context.create(member(0), None).unwrap();
    stage.write_at(0, b"abc").unwrap();
    let generation = stage.generation;
    for size in [2, 4] {
        assert!(matches!(stage.reconcile_final_size(size).unwrap_err().kind, FailureKind::IncompleteOutput));
        assert_eq!((stage.size, stage.produced, stage.length, stage.generation), (None, 3, 3, generation));
        assert_eq!(stage.native.file().metadata().unwrap().len(), 3);
    }
    stage.reconcile_final_size(3).unwrap();
    assert_eq!((stage.size, stage.produced, stage.length, stage.generation), (Some(3), 3, 3, generation + 1));
    assert!(stage.assessment.borrow().evidence.is_none());
    stage.reconcile_final_size(3).unwrap();
    assert_eq!(stage.generation, generation + 1);
    stage.discard().unwrap();
    let mut known = context.create(member(1), Some(4)).unwrap();
    known.write_at(0, b"abc").unwrap();
    assert!(matches!(known.reconcile_final_size(3).unwrap_err().kind, FailureKind::IncompleteOutput));
    assert_eq!((known.size, known.produced, known.length), (Some(4), 3, 3));
    assert_eq!(known.native.file().metadata().unwrap().len(), 3);
}
#[test]
fn final_size_reconciliation_checks_physical_length_before_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let mut context = setup(dir.path());
    let mut stage = context.create(member(0), None).unwrap();
    stage.write_at(0, b"abc").unwrap();
    stage.native.file().set_len(4).unwrap();
    assert!(matches!(
        stage.reconcile_final_size(3).unwrap_err().kind,
        FailureKind::Output { operation: OutputOperation::Metadata, .. }
    ));
    assert_eq!((stage.size, stage.produced, stage.length), (None, 3, 3));
    assert_eq!(stage.native.file().metadata().unwrap().len(), 4);
}

#[test]
fn task4b_metadata_waits_for_publication_and_cleanup_failure_keeps_published_fact() {
    use std::os::unix::fs::PermissionsExt;
    for cleanup_failure in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let mut c = setup(d.path());
        Arc::get_mut(&mut c.root).unwrap().overwrite = crate::extract::Overwrite::Skip;
        let mut stage = c.create(member(0), Some(3)).unwrap();
        stage.write_at(0, b"new").unwrap();
        stage.set_metadata(crate::extract::Meta { mtime: Some(1_700_000_000), nanos: 0, mode: Some(0o4751) });
        let permit = verify(&mut stage);
        let mut target = stage.target("target", false).unwrap();
        let mut source = driver(native_complete(d.path()));
        fault(crate::output::OwnedOperation::Publish, Err(libc::EACCES));
        assert!(stage.publish(&mut target, &permit, &mut source).is_err());
        assert_eq!(stage.native.file().metadata().unwrap().permissions().mode() & 0o7777, 0o600);
        assert!(!target.path.exists());
        if cleanup_failure {
            fault(crate::output::OwnedOperation::Remove, Err(libc::EACCES));
        }
        let Publication::Published { cleanup_failure: actual } =
            stage.publish(&mut target, &permit, &mut source).unwrap()
        else {
            panic!("published")
        };
        assert_eq!(actual.is_some(), cleanup_failure);
        assert!(stage.published);
        assert_eq!(fs::metadata(&target.path).unwrap().permissions().mode() & 0o7777, 0o751);
        assert_eq!(fs::read(&target.path).unwrap(), b"new");
        if cleanup_failure {
            stage.discard().unwrap();
        }
    }
}

#[test]
fn task4b_directory_rebound_during_authority_refresh_is_not_adopted() {
    use std::os::unix::fs::PermissionsExt;
    struct Rebind {
        calls: usize,
        root: PathBuf,
        declaration: ProtectionDeclaration,
    }
    impl VolumeSource for Rebind {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Missing)
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            self.calls += 1;
            if self.calls == 2 {
                fs::rename(self.root.join("directory"), self.root.join("original")).unwrap();
                fs::create_dir(self.root.join("directory")).unwrap();
                fs::set_permissions(self.root.join("directory"), fs::Permissions::from_mode(0o700)).unwrap();
            }
            Ok(self.declaration.clone())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("directory")).unwrap();
    let declaration = native_complete(dir.path());
    let mut source = crate::progressive::source::SourceDriver::new(
        Box::new(Rebind { calls: 0, root: dir.path().into(), declaration }),
        "input.rar".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap();
    let mut output = setup(dir.path());
    let header =
        crate::rar5::FileHeader { name: "directory".into(), host_os: 1, attributes: 0o500, ..Default::default() };
    let admitted = output.directory(member(0), &header, &mut source);
    assert!(dir.path().join("original").exists(), "the provider replacement must actually run");
    assert!(admitted.is_err());
    output.finish_directories(&mut source).unwrap();
    assert_eq!(fs::metadata(dir.path().join("directory")).unwrap().permissions().mode() & 0o777, 0o700);
}

#[test]
fn task4b_directory_finalization_budget_is_finite_and_one_shot() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mut source = driver(native_complete(dir.path()));
    let mut output = setup(dir.path());
    let header =
        crate::rar5::FileHeader { name: "directory".into(), host_os: 1, attributes: 0o500, ..Default::default() };
    assert!(matches!(
        output.directory(member(0), &header, &mut source).unwrap(),
        DirectoryVerdict::Done { created: true }
    ));
    fs::set_permissions(dir.path().join("directory"), fs::Permissions::from_mode(0o700)).unwrap();
    output.usage = Usage::new(ProgressiveLimits { source_bookkeeping: 0, ..Default::default() });
    assert!(matches!(
        output.finish_directories(&mut source).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::SourceBookkeeping, .. }
    ));
    output.finish_directories(&mut source).unwrap();
    assert_eq!(fs::metadata(dir.path().join("directory")).unwrap().permissions().mode() & 0o777, 0o700);
}

fn check_finalization_ancestor(attack: Option<&str>) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Rebind {
        armed: Arc<AtomicBool>,
        from: PathBuf,
        saved: PathBuf,
        declaration: ProtectionDeclaration,
    }
    impl VolumeSource for Rebind {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Missing)
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            if self.armed.swap(false, Ordering::SeqCst) {
                fs::rename(&self.from, &self.saved).unwrap();
                symlink(&self.saved, &self.from).unwrap();
            }
            Ok(self.declaration.clone())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("out");
    fs::create_dir_all(root.join("parent/directory")).unwrap();
    let leaf = root.join("parent/directory");
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
    let file = fs::File::open(&leaf).unwrap();
    file.set_times(
        fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000)),
    )
    .unwrap();
    let before = file.metadata().unwrap();
    let from = if attack == Some("parent") { root.join("parent") } else { root.clone() };
    let saved = temp.path().join("saved");
    let armed = Arc::new(AtomicBool::new(false));
    let mut source = crate::progressive::source::SourceDriver::new(
        Box::new(Rebind {
            armed: armed.clone(),
            from: from.clone(),
            saved: saved.clone(),
            declaration: native_complete(temp.path()),
        }),
        "input.rar".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap();
    let mut output = setup(&root);
    let header = crate::rar5::FileHeader {
        name: "parent/directory".into(),
        host_os: 1,
        attributes: 0o500,
        mtime: Some(1_700_000_000),
        ..Default::default()
    };
    assert!(matches!(
        output.directory(member(0), &header, &mut source).unwrap(),
        DirectoryVerdict::Done { created: false }
    ));
    armed.store(attack.is_some(), Ordering::SeqCst);
    let result = output.finish_directories(&mut source);
    let after = file.metadata().unwrap();
    if attack.is_some() {
        assert!(saved.is_dir(), "callback must move the ancestor");
        assert!(fs::symlink_metadata(&from).unwrap().is_symlink());
        assert_eq!(
            (after.mode(), after.mtime(), after.mtime_nsec()),
            (before.mode(), before.mtime(), before.mtime_nsec()),
            "revoked ancestor must prevent metadata restoration: {attack:?}"
        );
        assert!(result.is_err());
    } else {
        result.unwrap();
        assert_eq!(after.mode() & 0o777, 0o500);
        assert_eq!(after.mtime(), 1_700_000_000);
    }
    output.finish_directories(&mut source).unwrap();
}

#[test]
fn task4b_r1_finalization_root_rebind() {
    check_finalization_ancestor(Some("root"));
}
#[test]
fn task4b_r1_finalization_parent_rebind() {
    check_finalization_ancestor(Some("parent"));
}
#[test]
fn task4b_r1_finalization_safe_control() {
    check_finalization_ancestor(None);
}

#[test]
fn recovery_exact_default_interval_limit_preserves_last_valid_extent() {
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(131_074)).unwrap();
    for i in 0..65_536u64 {
        s.hole(i * 2, 1, HoleFill::Sparse).unwrap();
        s.write_at(i * 2 + 1, b"v").unwrap();
    }
    assert_eq!(s.holes.len(), 65_536);
    assert_eq!(s.valid, 65_536);
    assert_eq!(s.produced, 131_072);
    let error = s.hole(131_072, 1, HoleFill::Sparse).unwrap_err();
    assert!(matches!(
        error.kind,
        FailureKind::Limit { resource: Resource::HoleIntervals, limit: 65_536, attempted: 65_537 }
    ));
    assert_eq!(s.length, 131_072);
    assert_eq!(s.native.file().metadata().unwrap().len(), 131_072);
}

#[test]
fn recovery_publication_rechecks_stage_stamp_after_authorization_callback() {
    struct Mutating {
        file: Option<fs::File>,
        declaration: ProtectionDeclaration,
    }
    impl VolumeSource for Mutating {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Missing)
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            if let Some(file) = self.file.take() {
                use std::os::unix::fs::FileExt;
                file.write_at(b"bad", 0).unwrap();
            }
            Ok(self.declaration.clone())
        }
    }
    let d = tempfile::tempdir().unwrap();
    let mut c = setup(d.path());
    let mut s = c.create(member(0), Some(3)).unwrap();
    s.write_at(0, b"abc").unwrap();
    let permit = verify(&mut s);
    let mut target = s.target("final", false).unwrap();
    let mut driver = super::super::source::SourceDriver::new(
        Box::new(Mutating { file: Some(s.native.file().try_clone().unwrap()), declaration: native_complete(d.path()) }),
        "input.rar".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap();
    assert!(matches!(s.publish(&mut target, &permit, &mut driver).unwrap_err().kind, FailureKind::InvalidCapability));
    assert!(!d.path().join("final").exists());
}
