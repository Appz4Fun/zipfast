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

#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
mod common;
#[path = "common/partial_state.rs"]
mod partial_state;
use std::{
    ffi::OsString,
    fs::{self, File},
    ops::Range,
    path::Path,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::partial::*;
use zipfast::progressive::*;

type ReadHook = Arc<Mutex<Option<Box<dyn FnMut(u32, u64) -> Option<File> + Send>>>>;
#[derive(Default)]
struct WaitGate(Mutex<Option<Waker>>);
struct Source {
    index: u32,
    bytes: Vec<u8>,
    holes: Vec<Range<u64>>,
    backing: Vec<File>,
    hook: ReadHook,
    wait: Option<(u64, Arc<WaitGate>)>,
    reads: Arc<Mutex<Vec<(u32, u64, usize)>>>,
}
impl RangeSource for Source {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.index as u128 + 1),
            generation: 0,
            extent: self.bytes.len() as u64,
            length: SourceLength::Final(self.bytes.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &self.backing
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.reads.lock().unwrap().push((self.index, at, buf.len()));
        if self.wait.as_ref().is_some_and(|(offset, _)| *offset == at) {
            let (_, gate) = self.wait.take().unwrap();
            *gate.0.lock().unwrap() = Some(cx.waker().clone());
            return Ok(RangeRead::NotYet);
        }
        if let Some(hook) = self.hook.lock().unwrap().as_mut()
            && let Some(file) = hook(self.index, at)
        {
            self.backing.push(file);
        }
        let mut end = (at + buf.len() as u64).min(self.bytes.len() as u64);
        for hole in &self.holes {
            if hole.start <= at && at < hole.end {
                return Ok(RangeRead::Hole { len: (hole.end - at).min(buf.len() as u64) });
            }
            if hole.start > at {
                end = end.min(hole.start);
            }
        }
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.bytes[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}
struct Provider {
    volumes: Vec<Option<Source>>,
    protection: ProtectionDeclaration,
    wait: Option<Arc<WaitGate>>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    protection_hook: Option<Box<dyn FnMut() + Send>>,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        if let Some(hook) = &mut self.protection_hook {
            hook();
        }
        Ok(self.protection.clone())
    }
    fn volume(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(gate) = self.wait.take() {
            *gate.0.lock().unwrap() = Some(cx.waker().clone());
            return Ok(VolumeAnswer::Wait);
        }
        assert_eq!(request.expected, volume_name(request.index));
        Ok(VolumeAnswer::Ready(Box::new(
            self.volumes[request.index as usize].take().expect("no original reacquisition"),
        )))
    }
}
fn volume_name(index: u32) -> OsString {
    format!("set.part{:02}.rar", index + 1).into()
}
struct Fixture {
    data: [Vec<u8>; 2],
    volumes: Vec<Option<Source>>,
    reads: Arc<Mutex<Vec<(u32, u64, usize)>>>,
    payloads: Vec<Range<u64>>,
}
impl Fixture {
    // Ten volumes, two members, ten 700-byte articles/member, exactly one missing article/member.
    // A's missing logical article crosses a physical volume boundary.
    fn new() -> Self {
        Self::configured(|_, _| {})
    }
    fn configured(mut configure: impl FnMut(usize, &mut common::FileSpec<'_>)) -> Self {
        let data = std::array::from_fn(|member| {
            (0..7000).map(|i| ((i * 31 + member * 19 + 7) % 251) as u8).collect::<Vec<_>>()
        });
        let reads = Arc::new(Mutex::new(Vec::new()));
        let mut volumes = Vec::new();
        let mut payloads = Vec::new();
        for index in 0..10 {
            let member = index / 5;
            let part = index % 5;
            let out = part * 1400..(part + 1) * 1400;
            let name = if member == 0 { "a.bin" } else { "b.bin" };
            let mut spec = common::FileSpec::new(name, &data[member]);
            configure(index, &mut spec);
            let scope = if part == 4 { data[member].as_slice() } else { &data[member][out.clone()] };
            let file =
                common::file_block(&spec, &data[member][out.clone()], crc32fast::hash(scope), part != 0, part != 4);
            let mut bytes = common::SIG.to_vec();
            bytes.extend(common::main_block(true, Some(index as u64)));
            let start = bytes.len() + file.len() - 1400;
            let payload = start as u64..(start + 1400) as u64;
            bytes.extend(file);
            bytes.extend(common::end_block(index != 9));
            let missing = if member == 0 { 1300..2000 } else { 3500..4200 };
            let a = out.start.max(missing.start);
            let b = out.end.min(missing.end);
            let holes = if a < b {
                std::iter::once(start as u64 + (a - out.start) as u64..start as u64 + (b - out.start) as u64).collect()
            } else {
                Vec::new()
            };
            payloads.push(payload.clone());
            volumes.push(Some(Source {
                index: index as u32,
                bytes,
                holes,
                reads: reads.clone(),
                backing: Vec::new(),
                hook: Arc::new(Mutex::new(None)),
                wait: None,
            }));
        }
        Self { data, volumes, reads, payloads }
    }
    fn provider(&mut self) -> Provider {
        let protection = ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..10)
                    .map(|index| ProtectedVolume { index, name: volume_name(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        };
        Provider {
            volumes: std::mem::take(&mut self.volumes),
            protection,
            wait: None,
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            protection_hook: None,
        }
    }
}
fn options(dest: &Path) -> ProgressiveOptions {
    let mut options = ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: dest.into(),
            overwrite: zipfast::extract::Overwrite::Always,
            flatten: false,
            threads: Some(1),
            protected_paths: Default::default(),
            parallel_min: None,
        },
        volume_name(0),
    );
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    options
}
#[derive(Default)]
struct Anchors(Mutex<Vec<StateAnchor>>);
impl StateAnchorStore for Anchors {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        Ok(self.0.lock().unwrap().iter().find(|a| a.member() == member).cloned())
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        let mut anchors = self.0.lock().unwrap();
        let index = anchors.iter().position(|a| a.member() == member);
        if index.map(|i| &anchors[i]) != expected {
            return Err(PartialError::new(PartialErrorKind::AnchorConflict));
        }
        if let Some(index) = index {
            anchors[index] = next.clone();
        } else {
            anchors.push(next.clone());
        }
        Ok(())
    }
}
fn partial_options(state: &Path) -> PartialOptions {
    PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: state.into(),
        limits: PartialLimits::default(),
        anchors: Arc::new(Anchors::default()),
        control: SessionControl::default(),
    }
}
fn early_named_output(persistent: bool) {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let mut fixture = Fixture::new();
    let mut session = if persistent {
        ProgressiveSession::new_partial(
            Box::new(fixture.provider()),
            options(&dest),
            partial_options(&dir.path().join("state")),
        )
        .unwrap()
    } else {
        ProgressiveSession::new(Box::new(fixture.provider()), options(&dest)).unwrap()
    };
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => {
                assert!(
                    fixture
                        .reads
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|(volume, at, _)| !fixture.payloads[*volume as usize].contains(at)),
                    "early handle must precede any payload read"
                );
                if persistent {
                    assert_eq!(
                        fs::metadata(dest.join("a.bin"))
                            .expect("persistent named output must exist before payload reads")
                            .len(),
                        fixture.data[0].len() as u64
                    );
                } else {
                    assert!(!dest.join("a.bin").exists(), "legacy output remains staged");
                }
                return;
            }
            Poll::Ready(Err(error)) => panic!("unexpected source/parser failure: {error:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                panic!("unexpected termination: {failure:?}")
            }
            _ => {}
        }
    }
    panic!("member never started")
}

#[test]
fn early_named_full_size_precedes_payload() {
    early_named_output(true);
}
#[test]
fn legacy_output_remains_staged_before_payload() {
    early_named_output(false);
}

fn verify(file: &mut PartialFile) -> Verdict {
    for _ in 0..10000 {
        if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            return result.unwrap();
        }
    }
    panic!("local verification failed to complete")
}
#[test]
fn plain_stored_reports_holes_before_finish_and_a_fills_while_b_progresses() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state = dir.path().join("state");
    let mut fixture = Fixture::new();
    let mut partial = partial_options(&state);
    partial.limits.events = 1;
    let mut session = ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dest), partial).unwrap();
    let mut files = Vec::new();
    let mut holes = Vec::new();
    let mut part_events = Vec::new();
    let mut finished = 0;
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => {}
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, state }))) => {
                assert_eq!(state.anchor().member(), &member);
                files.push(session.partial_file(&member).unwrap());
                if member.ordinal() == 1 {
                    let before = fixture.reads.lock().unwrap().len();
                    let result = files[0].fill(1300, &fixture.data[0][1300..2000]).unwrap();
                    assert_eq!(result.applied, vec![1300..2000]);
                    assert!(result.part_checks.iter().any(|p| p.part == 0 && p.crc32 == CheckResult::Passed));
                    assert!(matches!(verify(&mut files[0]), Verdict::Ok { .. }));
                    assert_eq!(
                        fixture.reads.lock().unwrap().len(),
                        before,
                        "standalone fill/verify cannot call original providers"
                    );
                    assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
                }
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => {
                let (volume, at, _) = *fixture.reads.lock().unwrap().last().unwrap();
                assert_eq!(report.packed.len(), 1);
                assert_eq!(report.packed[0].volume, volume);
                assert_eq!(report.packed[0].range.start, at, "hole must be delivered before any later source read");
                assert_eq!(report.packed[0].range.end - at, report.out.end - report.out.start);
                assert!(matches!(report.cause, HoleCause::Missing));
                holes.push((report.member.ordinal(), report.out));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::PartVerified { member, check }))) => {
                assert_eq!(check.crc32, CheckResult::Passed);
                part_events.push((member.ordinal(), check.part));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => {
                assert!(matches!(outcome, MemberOutcome::PersistentPartial { .. }));
                finished += 1;
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(error)) => panic!("{error:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    assert_eq!(finished, 2);
    assert_eq!(holes, vec![(0, 1300..1400), (0, 1400..2000), (1, 3500..4200)]);
    assert!(part_events.contains(&(0, 2)), "completed non-final part check must be exposed before member completion");
    assert!(part_events.contains(&(1, 0)));
    let before = fixture.reads.lock().unwrap().len();
    drop(session);
    files[1].fill(3500, &fixture.data[1][3500..4200]).unwrap();
    assert!(matches!(verify(&mut files[1]), Verdict::Ok { .. }));
    assert_eq!(fixture.reads.lock().unwrap().len(), before);
    assert_eq!(fs::read(dest.join("b.bin")).unwrap(), fixture.data[1]);
}
#[test]
fn predictable_core_capacity_failure_creates_no_parent_directories() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("missing/out");
    let state = dir.path().join("missing-state/anchors");
    let mut fixture = Fixture::new();
    let mut partial = partial_options(&state);
    partial.limits.open_partials = 0;
    let mut session = ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dest), partial).unwrap();
    let mut failed = false;
    for _ in 0..10000 {
        if let Poll::Ready(Err(error)) = session.poll_event(&mut Context::from_waker(Waker::noop())) {
            assert!(
                matches!(error.kind,FailureKind::Partial(ref p) if matches!(p.kind,PartialErrorKind::Limit {resource:PartialResource::OpenPartials,..}))
            );
            failed = true;
            break;
        }
    }
    assert!(failed);
    assert!(!dir.path().join("missing").exists());
    assert!(!dir.path().join("missing-state").exists());
}

#[test]
fn waits_are_not_damage_and_require_the_original_wake() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::new();
    let read_gate = Arc::new(WaitGate::default());
    fixture.volumes[0].as_mut().unwrap().wait = Some((fixture.payloads[0].start, read_gate.clone()));
    let volume_gate = Arc::new(WaitGate::default());
    let mut provider = fixture.provider();
    provider.wait = Some(volume_gate.clone());
    let calls = provider.calls.clone();
    let mut session = ProgressiveSession::new_partial(
        Box::new(provider),
        options(&dir.path().join("out")),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
    for _ in 0..20 {
        assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(fixture.reads.lock().unwrap().is_empty());
    volume_gate.0.lock().unwrap().take().unwrap().wake();
    let mut ready = None;
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => break,
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                ready = Some(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(_)))) => panic!("wait became hole"),
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    let reads = fixture.reads.lock().unwrap().len();
    for _ in 0..20 {
        assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    assert_eq!(fixture.reads.lock().unwrap().len(), reads);
    assert_eq!(ready.unwrap().remaining().unwrap(), vec![0..7000]);
    read_gate.0.lock().unwrap().take().unwrap().wake();
    assert!(matches!(
        session.poll_event(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { valid_bytes: 1300, .. })))
    ));
}
fn next_partial(session: &mut ProgressiveSession) -> (MemberKey, PartialFile) {
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                let file = session.partial_file(&member).unwrap();
                return (member, file);
            }
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    panic!("no partial")
}
#[test]
fn callback_fill_of_a_and_postcallback_output_or_page_aliases() {
    for alias in [None, Some(false), Some(true)] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let state = dir.path().join("state");
        let mut fixture = Fixture::new();
        let hook = fixture.volumes[5].as_ref().unwrap().hook.clone();
        let data = fixture.data[0].clone();
        let mut session =
            ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dest), partial_options(&state))
                .unwrap();
        let (_, mut a) = next_partial(&mut session);
        let output = dest.join("a.bin");
        let link = dir.path().join("source-link");
        let mut used = false;
        *hook.lock().unwrap() = Some(Box::new(move |_, _| {
            if used {
                return None;
            }
            used = true;
            a.fill(1300, &data[1300..2000]).unwrap();
            if let Some(page) = alias {
                let path = if page {
                    let bundle = fs::read_dir(&state).unwrap().next().unwrap().unwrap().path();
                    fs::read_dir(bundle)
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("p-"))
                        .unwrap()
                } else {
                    output.clone()
                };
                fs::hard_link(path, &link).unwrap();
                Some(File::open(&link).unwrap())
            } else {
                None
            }
        }));
        // One callback, after A's final header but before B accepts any header byte.
        let mut failure = None;
        let mut b_ready = false;
        for _ in 0..10000 {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Err(e)) => {
                    failure = Some(e);
                    break;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) if member.ordinal() == 1 => {
                    b_ready = true;
                    break;
                }
                _ => {}
            }
            if fixture.reads.lock().unwrap().last().is_some_and(|(v, _, _)| *v == 5) {
                *hook.lock().unwrap() = None;
            }
        }
        if alias.is_some() {
            assert!(matches!(failure.unwrap().kind, FailureKind::UnsafePath));
            assert!(!dest.join("b.bin").exists());
        } else {
            assert!(b_ready);
            assert!(failure.is_none());
            assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
        }
    }
}
#[test]
fn persistent_clean_member_has_no_publication_receipt_and_metadata_repeats() {
    use std::os::unix::fs::PermissionsExt;
    for absent in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let mut fixture = Fixture::configured(|_, spec| {
            if absent {
                spec.mtime = None;
                spec.unix_mode = None;
            }
        });
        for source in fixture.volumes.iter_mut().flatten() {
            source.holes.clear();
        }
        let mut session = ProgressiveSession::new_partial(
            Box::new(fixture.provider()),
            options(&dest),
            partial_options(&dir.path().join("state")),
        )
        .unwrap();
        let (_, mut file) = next_partial(&mut session);
        assert_eq!(fs::metadata(dest.join("a.bin")).unwrap().permissions().mode() & 0o777, 0o600);
        let mut complete = false;
        for _ in 0..10000 {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => {
                    let MemberOutcome::PersistentComplete { verdict: Verdict::Ok { metadata, .. }, .. } = outcome
                    else {
                        panic!("persistent output minted a legacy receipt or was incomplete")
                    };
                    assert!(if absent {
                        matches!(metadata.modified, AttributeResult::NotRequested)
                            && matches!(metadata.permissions, AttributeResult::NotRequested)
                    } else {
                        matches!(metadata.modified, AttributeResult::Applied)
                            && matches!(metadata.permissions, AttributeResult::Applied)
                    });
                    complete = true;
                    break;
                }
                Poll::Ready(Err(e)) => panic!("{e:?}"),
                _ => {}
            }
        }
        assert!(complete);
        drop(session);
        for _ in 0..2 {
            assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
        }
        assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
        assert_eq!(
            fs::metadata(dest.join("a.bin")).unwrap().permissions().mode() & 0o777,
            if absent { 0o600 } else { 0o644 }
        );
    }
}

fn creation_with_cap(metadata: u64, files: u32) -> (bool, bool) {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("missing/out");
    let state = dir.path().join("missing-state/anchors");
    let mut fixture = Fixture::new();
    let mut options = options(&dest);
    options.limits.metadata_bytes = metadata;
    let mut partial = partial_options(&state);
    partial.limits.open_files = files;
    let mut session = match ProgressiveSession::new_partial(Box::new(fixture.provider()), options, partial) {
        Ok(s) => s,
        Err(_) => return (false, false),
    };
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => return (true, true),
            Poll::Ready(Err(e)) => {
                eprintln!("creation cap metadata={metadata}, files={files}: {e:?}");
                assert!(matches!(e.kind, FailureKind::Limit { .. } | FailureKind::Partial(_)));
                return (false, dir.path().join("missing").exists() || dir.path().join("missing-state").exists());
            }
            _ => {}
        }
    }
    panic!("creation never settled")
}
#[test]
fn genesis_metadata_and_transient_descriptors_admit_before_directory_effects() {
    for descriptor in [false, true] {
        let mut low = 0;
        let mut high = if descriptor { 64 } else { 2_000_000 };
        assert!(
            creation_with_cap(if descriptor { 2_000_000 } else { high }, if descriptor { high as u32 } else { 64 }).0
        );
        while low + 1 < high {
            let middle = (low + high) / 2;
            let (success, effect) = creation_with_cap(
                if descriptor { 2_000_000 } else { middle },
                if descriptor { middle as u32 } else { 64 },
            );
            assert!(success || !effect, "predictable cap {middle} (descriptor={descriptor}) created parent names");
            if success {
                high = middle;
            } else {
                low = middle;
            }
        }
        assert!(
            creation_with_cap(if descriptor { 2_000_000 } else { high }, if descriptor { high as u32 } else { 64 }).0
        );
        assert_eq!(
            creation_with_cap(if descriptor { 2_000_000 } else { low }, if descriptor { low as u32 } else { 64 }),
            (false, false)
        );
    }
}

#[test]
fn deferred_part_success_survives_session_drop_and_reopen() {
    for reopen in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let state_root = dir.path().join("state");
        let mut fixture = Fixture::configured(|index, spec| {
            let part = index % 5;
            let scope = if part == 4 { spec.data } else { &spec.data[part * 1400..(part + 1) * 1400] };
            spec.extra = common::blake_record(common::blake(scope));
        });
        let anchors = Arc::new(Anchors::default());
        let mut partial = partial_options(&state_root);
        partial.anchors = anchors.clone();
        let provider = fixture.provider();
        let protection = provider.protection.clone();
        let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
        let (key, mut file) = next_partial(&mut session);
        loop {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { logical_end: 7000, .. }))) => break,
                Poll::Ready(Err(e)) => panic!("{e:?}"),
                _ => {}
            }
        }
        let reads = fixture.reads.lock().unwrap().len();
        drop(session);
        if reopen {
            let state = partial_state::roundtrip(&file.close().unwrap());
            let expected_anchor = anchors.current(&key).unwrap().unwrap();
            let progressive_limits = ProgressiveLimits { read_chunk: 17, ..Default::default() };
            file = PartialFile::open(
                state,
                PartialOpenContext {
                    output_root: dest.clone(),
                    state_root: state_root.clone(),
                    expected_member: key,
                    expected_anchor,
                    protection,
                    limits: PartialLimits::default(),
                    progressive_limits,
                    anchors,
                    control: SessionControl::default(),
                },
            )
            .unwrap();
        }
        let Verdict::Incomplete { parts, holes, .. } = verify(&mut file) else {
            panic!("known parts must verify despite other holes")
        };
        assert_eq!(holes, vec![1300..2000]);
        assert_eq!(parts[2].blake2sp, CheckResult::Passed);
        assert_eq!(parts[0].blake2sp, CheckResult::Pending);
        file.fill(1300, &fixture.data[0][1300..2000]).unwrap();
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
        assert_eq!(fixture.reads.lock().unwrap().len(), reads);
        assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
    }
}
fn failure_before_output(
    mut fixture: Fixture,
    change: impl FnOnce(&mut Provider, &mut PartialOptions, &mut ProgressiveOptions),
) -> PartialErrorKind {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state = dir.path().join("state");
    let mut provider = fixture.provider();
    let mut partial = partial_options(&state);
    let mut options = options(&dest);
    change(&mut provider, &mut partial, &mut options);
    let result = ProgressiveSession::new_partial(Box::new(provider), options, partial);
    let error = match result {
        Err(e) => e,
        Ok(mut session) => loop {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Err(e)) => break e,
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => {
                    panic!("unsupported member created output")
                }
                Poll::Ready(Ok(None)) => panic!("unsupported archive accepted"),
                _ => {}
            }
        },
    };
    assert!(!dest.exists());
    assert!(!state.exists());
    let FailureKind::Partial(error) = error.kind else { panic!("not typed partial refusal: {error:?}") };
    error.kind
}
#[test]
fn known_unsupported_members_and_invalid_options_refuse_before_effects() {
    assert!(matches!(
        failure_before_output(Fixture::configured(|_, s| s.method = 1), |_, _, _| {}),
        PartialErrorKind::UnsupportedMethod
    ));
    assert!(matches!(
        failure_before_output(Fixture::configured(|_, s| s.size_unknown = true), |_, _, _| {}),
        PartialErrorKind::UnknownMemberSize
    ));
    assert!(matches!(
        failure_before_output(Fixture::new(), |_, p, _| p.limits.events = 0),
        PartialErrorKind::InvalidOptions
    ));
    assert!(matches!(
        failure_before_output(Fixture::new(), |_, _, o| o.extract.mode = zipfast::extract::Mode::Test),
        PartialErrorKind::InvalidOptions
    ));
    assert!(matches!(
        failure_before_output(Fixture::new(), |p, _, _| p.protection = ProtectionDeclaration::Opaque),
        PartialErrorKind::InvalidOptions
    ));
    let redirection = Fixture::configured(|_, s| {
        let mut record = Vec::new();
        common::vint(5, &mut record);
        common::vint(1, &mut record);
        common::vint(0, &mut record);
        common::vint(1, &mut record);
        record.push(b'x');
        common::vint(record.len() as u64, &mut s.extra);
        s.extra.extend(record);
    });
    assert!(matches!(failure_before_output(redirection, |_, _, _| {}), PartialErrorKind::UnsupportedMethod));
    let mut rar4 = Fixture::new();
    let block = |kind: u8, flags: u16, body: &[u8]| {
        let mut bytes = vec![0, 0, kind];
        bytes.extend(flags.to_le_bytes());
        bytes.extend(((body.len() + 7) as u16).to_le_bytes());
        bytes.extend(body);
        let crc = crc32fast::hash(&bytes[2..]) as u16;
        bytes[..2].copy_from_slice(&crc.to_le_bytes());
        bytes
    };
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    bytes.extend(block(0x7b, 0x4000, &[]));
    rar4.volumes[0].as_mut().unwrap().bytes = bytes;
    assert!(matches!(failure_before_output(rar4, |_, _, _| {}), PartialErrorKind::UnsupportedFormat));
    let mut aes = Fixture::new();
    let mut params = Vec::new();
    common::vint(0, &mut params);
    common::vint(0, &mut params);
    params.push(1);
    params.extend([0u8; 16]);
    let mut bytes = common::SIG.to_vec();
    bytes.extend(common::block(4, 0, &params, &[], &[], false));
    aes.volumes[0].as_mut().unwrap().bytes = bytes;
    assert!(matches!(failure_before_output(aes, |_, _, _| {}), PartialErrorKind::UnsupportedMethod));
}

#[test]
fn complete_catalogue_and_future_source_aliases() {
    for suffix in [false, true] {
        let kind = failure_before_output(Fixture::new(), |provider, partial, options| {
            let name = if suffix {
                partial.naming = PartialNaming::Suffix(".part".into());
                "a.bin.part"
            } else {
                "a.bin"
            };
            let ProtectionDeclaration::Complete { inventory, .. } = &mut provider.protection else { unreachable!() };
            inventory.auxiliary_paths.push(ProtectedPath { path: options.extract.dest.join(name), file: None });
        });
        assert!(matches!(kind,PartialErrorKind::Progressive(e) if matches!(e.kind,FailureKind::UnsafePath)));
    }
}
#[test]
fn nested_parent_preparation_refuses_symlinks_nondirectories_and_existing_output() {
    use std::os::unix::fs::symlink;
    for mode in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let state = dir.path().join("state");
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        if mode == 1 {
            symlink(&outside, &dest).unwrap();
        } else if mode == 2 {
            fs::write(&dest, b"existing").unwrap();
        } else if mode == 3 {
            fs::create_dir(&dest).unwrap();
            fs::create_dir(dest.join("nested")).unwrap();
            fs::write(dest.join("nested/a.bin"), b"keep").unwrap();
        }
        let mut fixture =
            Fixture::configured(|index, spec| spec.name = if index < 5 { "nested/a.bin" } else { "nested/b.bin" });
        let mut session =
            ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dest), partial_options(&state))
                .unwrap();
        let mut success = false;
        let mut failed = false;
        for _ in 0..10000 {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { .. }))) => {
                    success = true;
                    break;
                }
                Poll::Ready(Err(_)) => {
                    failed = true;
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(success, mode == 0);
        assert_eq!(failed, mode != 0);
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
        if mode == 0 {
            assert_eq!(fs::metadata(dest.join("nested/a.bin")).unwrap().len(), 7000);
        } else {
            assert!(!state.exists());
        }
        if mode == 3 {
            assert_eq!(fs::read(dest.join("nested/a.bin")).unwrap(), b"keep");
        }
    }
}
struct ArmStore {
    inner: Anchors,
    armed: Arc<std::sync::atomic::AtomicBool>,
}
impl StateAnchorStore for ArmStore {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.current(member)
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        self.inner.compare_exchange(member, expected, next)
    }
}
#[test]
fn held_parent_swap_in_provider_callback_is_rejected_before_output_effects() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state = dir.path().join("state");
    fs::create_dir(&dest).unwrap();
    fs::create_dir(&state).unwrap();
    let moved = dir.path().join("moved");
    let armed = Arc::new(AtomicBool::new(false));
    let mut fixture = Fixture::new();
    let mut provider = fixture.provider();
    let old = dest.clone();
    let new = moved.clone();
    let flag = armed.clone();
    let mut calls = 0;
    provider.protection_hook = Some(Box::new(move || {
        if flag.load(Ordering::SeqCst) {
            calls += 1;
            if calls == 2 {
                fs::rename(&old, &new).unwrap();
                fs::create_dir(&old).unwrap();
            }
        }
    }));
    let mut partial = partial_options(&state);
    partial.anchors = Arc::new(ArmStore { inner: Anchors::default(), armed });
    let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
    let mut failed = false;
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(_)) => {
                failed = true;
                break;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { .. }))) => panic!("swapped parent accepted"),
            _ => {}
        }
    }
    assert!(failed);
    assert!(!dest.join("a.bin").exists());
    assert!(!moved.join("a.bin").exists());
    assert!(fs::read_dir(state).unwrap().next().is_none());
}

#[test]
fn native_source_path_swap_after_read_callback_precedes_acceptance_and_output() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let archive = dir.path().join("set.part01.rar");
    let retired = dir.path().join("retired.rar");
    let mut fixture = Fixture::new();
    fs::write(&archive, &fixture.volumes[0].as_ref().unwrap().bytes).unwrap();
    fixture.volumes[0].as_mut().unwrap().backing.push(File::open(&archive).unwrap());
    let hook = fixture.volumes[0].as_ref().unwrap().hook.clone();
    let start = fixture.payloads[0].start;
    let path = archive.clone();
    let mut replaced = false;
    *hook.lock().unwrap() = Some(Box::new(move |_, at| {
        if at == start && !replaced {
            replaced = true;
            fs::rename(&path, &retired).unwrap();
            fs::write(&path, b"different native object").unwrap();
        }
        None
    }));
    let mut provider = fixture.provider();
    let ProtectionDeclaration::Complete { inventory, .. } = &mut provider.protection else { unreachable!() };
    inventory.volumes[0].backing = VolumeBacking::Native(vec![ProtectedPath {
        path: archive.clone(),
        file: Some(Arc::new(File::open(&archive).unwrap())),
    }]);
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&dir.path().join("state"));
    partial.anchors = anchors.clone();
    let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
    let (member, file) = next_partial(&mut session);
    let before = anchors.current(&member).unwrap();
    let Poll::Ready(Err(error)) = session.poll_event(&mut Context::from_waker(Waker::noop())) else {
        panic!("native callback swap accepted")
    };
    assert!(matches!(error.kind, FailureKind::SourceChanged));
    // The independent core also refuses operations while its declared native
    // source binding is changed. Restore that binding to inspect unchanged state.
    assert!(matches!(file.remaining().unwrap_err().kind,
        PartialErrorKind::Progressive(cause) if matches!(cause.kind, FailureKind::SourceChanged)));
    fs::rename(&archive, dir.path().join("replacement-retained.rar")).unwrap();
    fs::rename(dir.path().join("retired.rar"), &archive).unwrap();
    assert_eq!(
        file.remaining().unwrap(),
        vec![0..7000],
        "callback source identity must be rechecked before any output transaction"
    );
    assert_eq!(anchors.current(&member).unwrap(), before);
    assert!(fs::read(dest.join("a.bin")).unwrap().iter().all(|b| *b == 0));
}

struct CommitHookStore {
    inner: Anchors,
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl StateAnchorStore for CommitHookStore {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        self.inner.current(member)
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        self.inner.compare_exchange(member, expected, next)?;
        if next.sequence() == 2 {
            let hook = self.hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        Ok(())
    }
}
#[test]
fn native_source_alias_from_anchor_callback_precedes_output_write() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let archive = dir.path().join("set.part01.rar");
    let retired = dir.path().join("retired.rar");
    let mut fixture = Fixture::new();
    fs::write(&archive, &fixture.volumes[0].as_ref().unwrap().bytes).unwrap();
    fixture.volumes[0].as_mut().unwrap().backing.push(File::open(&archive).unwrap());
    let mut provider = fixture.provider();
    let ProtectionDeclaration::Complete { inventory, .. } = &mut provider.protection else { unreachable!() };
    inventory.volumes[0].backing = VolumeBacking::Native(vec![ProtectedPath {
        path: archive.clone(),
        file: Some(Arc::new(File::open(&archive).unwrap())),
    }]);
    let output = dest.join("a.bin");
    let path = output.clone();
    let anchors = Arc::new(CommitHookStore {
        inner: Anchors::default(),
        hook: Mutex::new(Some(Box::new(move || {
            fs::rename(&archive, &retired).unwrap();
            std::os::unix::fs::symlink(path, &archive).unwrap();
        }))),
    });
    let mut partial = partial_options(&dir.path().join("state"));
    partial.anchors = anchors.clone();
    let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
    let (member, _file) = next_partial(&mut session);
    let Poll::Ready(Err(error)) = session.poll_event(&mut Context::from_waker(Waker::noop())) else {
        panic!("anchor callback alias accepted")
    };
    assert!(
        fs::read(&output).unwrap().iter().all(|b| *b == 0),
        "a declared input became an output alias during CAS; no output write is permitted"
    );
    let FailureKind::Partial(error) = error.kind else { panic!("not a core failure") };
    assert_eq!(error.committed.as_ref(), anchors.current(&member).unwrap().as_ref());
    assert_eq!(error.committed.unwrap().sequence(), 2);
}

#[test]
fn long_default_limit_extraction_reclaim_superseded_state() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let mut fixture = Fixture::new();
    for source in fixture.volumes.iter_mut().flatten() {
        source.holes.clear();
    }
    let mut options = options(&dest);
    options.limits.read_chunk = 32;
    let mut session = ProgressiveSession::new_partial(
        Box::new(fixture.provider()),
        options,
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    let mut finished = 0;
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. },
                ..
            }))) => finished += 1,
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(error)) => panic!("default live-state caps must permit a long member: {error:?}"),
            _ => {}
        }
    }
    assert_eq!(finished, 2);
    assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
    assert_eq!(fs::read(dest.join("b.bin")).unwrap(), fixture.data[1]);
}
#[test]
fn many_standalone_fills_reclaim_superseded_state() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state_root = dir.path().join("state");
    let mut fixture = Fixture::new();
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&state_root);
    partial.anchors = anchors.clone();
    let provider = fixture.provider();
    let protection = provider.protection.clone();
    let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
    let (key, mut file) = next_partial(&mut session);
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => break,
            Poll::Ready(Err(error)) => panic!("{error:?}"),
            _ => {}
        }
    }
    drop(session);
    let mut revision = 0;
    for at in (1300..2000).step_by(5) {
        let result =
            file.fill(at as u64, &fixture.data[0][at..at + 5]).expect("many small fills must reclaim superseded pages");
        assert!(result.revision > revision);
        revision = result.revision;
    }
    assert!(matches!(verify(&mut file),Verdict::Ok {revision:r,..} if r==revision));
    let state = file.close().unwrap();
    let latest = anchors.current(&key).unwrap().unwrap();
    assert_eq!(state.anchor(), &latest);
    let mut file = PartialFile::open(
        partial_state::roundtrip(&state),
        PartialOpenContext {
            output_root: dest.clone(),
            state_root,
            expected_member: key,
            expected_anchor: latest,
            protection,
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors,
            control: SessionControl::default(),
        },
    )
    .unwrap();
    assert!(matches!(verify(&mut file),Verdict::Ok {revision:r,..} if r==revision));
    assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
}

#[derive(Default)]
struct MaintenanceStore {
    inner: Anchors,
    calls: std::sync::atomic::AtomicUsize,
    fault: Mutex<Option<(bool, Option<SessionControl>)>>,
}
impl StateAnchorStore for MaintenanceStore {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        self.inner.current(member)
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let fault = self.fault.lock().unwrap().take();
        if fault.as_ref().is_none_or(|(persist, _)| *persist) {
            self.inner.compare_exchange(member, expected, next)?;
        }
        if let Some((_, cancel)) = fault {
            if let Some(control) = cancel {
                control.cancel();
            } else {
                return Err(PartialError::new(PartialErrorKind::AnchorCommitUncertain));
            }
        }
        Ok(())
    }
}
// First locate real automatic maintenance by its extra acknowledged sequence,
// then inject at exactly that public fill in fresh real sessions. No wire-format
// knowledge or fabricated compaction call is used by this regression.
#[test]
fn automatic_compaction_uncertainty_cancel_receipts_and_reopen() {
    let mut maintenance_at = None;
    for scenario in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let state_root = dir.path().join("state");
        let mut fixture = Fixture::new();
        let anchors = Arc::new(MaintenanceStore::default());
        let mut partial = partial_options(&state_root);
        partial.anchors = anchors.clone();
        let control = partial.control.clone();
        let provider = fixture.provider();
        let protection = provider.protection.clone();
        let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
        let (key, mut file) = next_partial(&mut session);
        loop {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => break,
                Poll::Ready(Err(error)) => panic!("{error:?}"),
                _ => {}
            }
        }
        drop(session);
        let mut previous_revision = match verify(&mut file) {
            Verdict::Incomplete { revision, .. } => revision,
            other => panic!("{other:?}"),
        };
        for at in (1300..2000).step_by(5) {
            let before = anchors.current(&key).unwrap().unwrap();
            if scenario != 0 && Some(at) == maintenance_at {
                let output_before = fs::read(dest.join("a.bin")).unwrap();
                let calls = anchors.calls.load(std::sync::atomic::Ordering::SeqCst);
                *anchors.fault.lock().unwrap() = Some((scenario != 1, (scenario == 3).then(|| control.clone())));
                let error = file.fill(at as u64, &fixture.data[0][at..at + 5]).unwrap_err();
                let latest = anchors.current(&key).unwrap().unwrap();
                assert_eq!(anchors.calls.load(std::sync::atomic::Ordering::SeqCst), calls + 1, "no implicit CAS retry");
                assert_eq!(fs::read(dest.join("a.bin")).unwrap(), output_before, "maintenance precedes output writes");
                if scenario == 3 {
                    assert!(matches!(error.kind, PartialErrorKind::Canceled));
                    assert_eq!(error.committed.as_ref(), Some(&latest));
                } else {
                    assert!(matches!(error.kind, PartialErrorKind::AnchorCommitUncertain));
                    assert_eq!(error.committed.as_ref(), Some(&before));
                }
                assert_eq!(latest.sequence(), before.sequence() + u64::from(scenario != 1));
                // Ambiguous or canceled acknowledgement never retires the old
                // bundle; both its manifest and referenced pages remain usable.
                let old = PartialState::load(&state_root, &before, &PartialLimits::default()).unwrap();
                assert_eq!(old.anchor(), &before);
                if scenario == 2 {
                    // Explicit caller retry confirms trusted-current maintenance.
                    let filled = file.fill(at as u64, &fixture.data[0][at..at + 5]).unwrap();
                    assert_eq!(filled.revision, previous_revision + 1);
                    previous_revision = filled.revision;
                    continue;
                }
                drop(file);
                let state = PartialState::load(&state_root, &latest, &PartialLimits::default()).unwrap();
                file = PartialFile::open(
                    partial_state::roundtrip(&state),
                    PartialOpenContext {
                        output_root: dest.clone(),
                        state_root: state_root.clone(),
                        expected_member: key.clone(),
                        expected_anchor: latest,
                        protection: protection.clone(),
                        limits: PartialLimits::default(),
                        progressive_limits: ProgressiveLimits::default(),
                        anchors: anchors.clone(),
                        control: SessionControl::default(),
                    },
                )
                .unwrap();
            }
            let result = file.fill(at as u64, &fixture.data[0][at..at + 5]).unwrap();
            assert_eq!(result.revision, previous_revision + 1, "maintenance must not change logical revision");
            previous_revision = result.revision;
            if scenario == 0 && result.state.anchor().sequence() == before.sequence() + 3 && maintenance_at.is_none() {
                maintenance_at = Some(at);
            }
        }
        assert!(maintenance_at.is_some(), "fixture must actually exercise automatic maintenance");
        assert!(matches!(verify(&mut file), Verdict::Ok {revision, ..} if revision == previous_revision));
        assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
    }
}

#[test]
fn repeated_source_callback_fills_are_bounded_and_session_cancel_preserves_handle() {
    for cancel in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let mut fixture = Fixture::new();
        let hook = fixture.volumes[5].as_ref().unwrap().hook.clone();
        let source_bytes = fixture.volumes.iter().flatten().map(|s| s.bytes.len() as u64).sum();
        let mut opts = options(&dest);
        opts.limits.read_chunk = 64;
        opts.limits.source_bytes = source_bytes;
        opts.limits.source_requests = 10_000;
        let mut session = ProgressiveSession::new_partial(
            Box::new(fixture.provider()),
            opts,
            partial_options(&dir.path().join("state")),
        )
        .unwrap();
        let (key, mut file) = next_partial(&mut session);
        let mut callback_file = session.partial_file(&key).unwrap();
        let control = session.control();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let data = fixture.data[0].clone();
        *hook.lock().unwrap() = Some(Box::new(move |_, _| {
            let call = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call < 140 {
                callback_file.fill((1300 + call * 5) as u64, &data[1300 + call * 5..1305 + call * 5]).unwrap();
            }
            if cancel && call == 3 {
                control.cancel();
            }
            None
        }));
        let mut terminal = false;
        for _ in 0..10000 {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Err(error)) => {
                    assert!(cancel && matches!(error.kind, FailureKind::Canceled));
                    terminal = true;
                    break;
                }
                Poll::Ready(Ok(None)) => {
                    assert!(!cancel);
                    terminal = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(terminal);
        let count = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(if cancel { count == 4 } else { count > 4 && count < 100 });
        let read_count = fixture.reads.lock().unwrap().len();
        drop(session);
        file.fill(1300, &fixture.data[0][1300..2000]).unwrap();
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
        assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
        assert_eq!(fixture.reads.lock().unwrap().len(), read_count);
    }
}

fn creation_with_bookkeeping(cap: u64, native: bool) -> (bool, bool) {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("missing/out");
    let state = dir.path().join("missing-state/anchors");
    let mut fixture = Fixture::new();
    let mut opts = options(&dest);
    opts.limits.source_bookkeeping = cap;
    let archive = dir.path().join("input.rar");
    if native {
        fs::write(&archive, &fixture.volumes[0].as_ref().unwrap().bytes).unwrap();
        fixture.volumes[0].as_mut().unwrap().backing.push(File::open(&archive).unwrap());
    }
    let mut provider = fixture.provider();
    if native {
        let ProtectionDeclaration::Complete { inventory, .. } = &mut provider.protection else { unreachable!() };
        inventory.volumes[0].backing = VolumeBacking::Native(vec![ProtectedPath {
            path: archive.clone(),
            file: Some(Arc::new(File::open(&archive).unwrap())),
        }]);
    }
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&state);
    partial.anchors = anchors.clone();
    let mut session = match ProgressiveSession::new_partial(Box::new(provider), opts, partial) {
        Ok(s) => s,
        Err(_) => return (false, false),
    };
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => return (true, true),
            Poll::Ready(Err(error)) => {
                let kind = match &error.kind {
                    FailureKind::Partial(e) => match &e.kind {
                        PartialErrorKind::Progressive(e) => &e.kind,
                        _ => panic!("{error:?}"),
                    },
                    k => k,
                };
                assert!(
                    matches!(kind, FailureKind::Limit {resource: Resource::SourceBookkeeping, limit, ..} if *limit == cap)
                );
                assert!(anchors.0.lock().unwrap().is_empty(), "predictable work rejection must precede genesis CAS");
                return (false, dir.path().join("missing").exists() || dir.path().join("missing-state").exists());
            }
            _ => {}
        }
    }
    panic!("creation never settled")
}
#[test]
fn genesis_bookkeeping_exact_and_one_under_precede_parent_names() {
    for native in [false, true] {
        let mut low = 0;
        let mut high = 1_000_000;
        assert!(creation_with_bookkeeping(high, native).0);
        while low + 1 < high {
            let middle = (low + high) / 2;
            let (success, effect) = creation_with_bookkeeping(middle, native);
            assert!(success || !effect, "SourceBookkeeping cap {middle} created parent names");
            if success {
                high = middle;
            } else {
                low = middle;
            }
        }
        assert_eq!(creation_with_bookkeeping(high, native), (true, true));
        assert_eq!(creation_with_bookkeeping(low, native), (false, false));
        eprintln!("genesis SourceBookkeeping native={native} exact={high}, one-under={low}");
    }
}
