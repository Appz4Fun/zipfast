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
type BackingHook = Arc<Mutex<Option<Box<dyn FnMut() + Send>>>>;
struct Source {
    generation: Arc<std::sync::atomic::AtomicU64>,
    backing_hook: BackingHook,
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
            generation: self.generation.load(std::sync::atomic::Ordering::SeqCst),
            extent: self.bytes.len() as u64,
            length: SourceLength::Final(self.bytes.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        if let Some(hook) = self.backing_hook.lock().unwrap().as_mut() {
            hook();
        }
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
                generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                backing_hook: Arc::new(Mutex::new(None)),
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
                volumes: (0..self.volumes.len() as u32)
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
#[test]
fn continuation_part_resumes_after_wait_with_header_work_in_same_poll() {
    // A continuation part's first payload read follows its headers in the same poll, so its length is
    // reduced by that header work; the resumed read after the wake must still be accepted.
    let dir = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::new();
    let read_gate = Arc::new(WaitGate::default());
    fixture.volumes[1].as_mut().unwrap().wait = Some((fixture.payloads[1].start, read_gate.clone()));
    let mut opts = options(&dir.path().join("out"));
    opts.limits.packed_work_per_poll = 1024;
    let mut session =
        ProgressiveSession::new_partial(Box::new(fixture.provider()), opts, partial_options(&dir.path().join("state")))
            .unwrap();
    let mut woke = false;
    for _ in 0..100_000 {
        if !woke && let Some(waker) = read_gate.0.lock().unwrap().take() {
            waker.wake();
            woke = true;
        }
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(None)) => {
                assert!(woke, "the continuation part never waited");
                return;
            }
            Poll::Ready(Err(e)) => panic!("resumed continuation read failed: {e:?}"),
            _ => {}
        }
    }
    panic!("session did not finish");
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
        // The next poll finishes the canonical machine and durably commits
        // completion, then yields before starting deferred BLAKE readback.
        assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
        let before_readback = file.fill(0, &[]).unwrap();
        assert!(before_readback.applied.is_empty());
        assert!(before_readback.part_checks.iter().all(|part| part.blake2sp == CheckResult::Pending));
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
                    password: None,
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
            password: None,
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
                        password: None,
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

#[test]
fn backing_callback_generation_change_precedes_public_payload_acceptance() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for hole in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let mut fixture = Fixture::new();
        let payload = fixture.payloads[0].clone();
        let source = fixture.volumes[0].as_mut().unwrap();
        if hole {
            source.holes = std::iter::once(payload.clone()).collect();
        }
        let generation = source.generation.clone();
        let arm = Arc::new(AtomicBool::new(false));
        let armed = arm.clone();
        *source.hook.lock().unwrap() = Some(Box::new(move |_, at| {
            if at == payload.start {
                armed.store(true, Ordering::SeqCst);
            }
            None
        }));
        *source.backing_hook.lock().unwrap() = Some(Box::new(move || {
            if arm.swap(false, Ordering::SeqCst) {
                generation.fetch_add(1, Ordering::SeqCst);
            }
        }));
        let anchors = Arc::new(Anchors::default());
        let mut partial = partial_options(&dir.path().join("state"));
        partial.anchors = anchors.clone();
        let mut session =
            ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dest), partial).unwrap();
        let (key, file) = next_partial(&mut session);
        let before = anchors.current(&key).unwrap();
        let Poll::Ready(Err(error)) = session.poll_event(&mut Context::from_waker(Waker::noop())) else {
            panic!("changed generation yielded a success event");
        };
        assert!(matches!(error.kind, FailureKind::SourceChanged));
        assert_eq!(anchors.current(&key).unwrap(), before, "changed generation committed a payload transaction");
        assert_eq!(file.remaining().unwrap(), vec![0..7000]);
        assert!(fs::read(dest.join("a.bin")).unwrap().iter().all(|b| *b == 0));
    }
}

fn versioned_skip_with_successor(empty: bool, split: bool) {
    for persistent in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let state = dir.path().join("state");
        let old = if empty { &b""[..] } else { &b"older contents"[..] };
        let clean = b"clean successor";
        let mut skipped = common::FileSpec::new("old.bin", old);
        skipped.extra = vec![3, 4, 0, 1]; // record size, VERSION, flags, version
        let successor = common::FileSpec::new("clean.bin", clean);
        let archives = if split {
            let middle = old.len() / 2;
            let mut first = common::SIG.to_vec();
            first.extend(common::main_block(true, Some(0)));
            first.extend(common::file_block(&skipped, &old[..middle], crc32fast::hash(&old[..middle]), false, true));
            first.extend(common::end_block(true));
            let mut second = common::SIG.to_vec();
            second.extend(common::main_block(true, Some(1)));
            second.extend(common::file_block(&skipped, &old[middle..], crc32fast::hash(old), true, false));
            second.extend(common::file_block(&successor, clean, crc32fast::hash(clean), false, false));
            second.extend(common::end_block(false));
            vec![first, second]
        } else {
            vec![common::archive(&[skipped, successor])]
        };
        let mut fixture = Fixture::new();
        fixture.volumes.truncate(archives.len());
        for (source, bytes) in fixture.volumes.iter_mut().zip(archives) {
            let source = source.as_mut().unwrap();
            source.bytes = bytes;
            source.holes.clear();
        }
        let anchors = Arc::new(Anchors::default());
        let mut partial = partial_options(&state);
        partial.anchors = anchors.clone();
        let provider = fixture.provider();
        let mut session = if persistent {
            ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap()
        } else {
            ProgressiveSession::new(Box::new(provider), options(&dest)).unwrap()
        };
        let mut skipped_count = 0;
        let mut completed = 0;
        let mut ready = 0;
        let mut terminal = false;
        for _ in 0..1000 {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                    assert!(persistent);
                    assert_eq!(member.ordinal(), 1);
                    ready += 1;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::Skipped(zipfast::extract::RarSkipReason::OlderVersion(1)),
                    ..
                }))) => {
                    skipped_count += 1;
                    assert!(!dest.join("old.bin").exists());
                    assert!(!state.exists());
                    assert!(anchors.0.lock().unwrap().is_empty());
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::PersistentComplete { member, verdict: Verdict::Ok { .. }, .. },
                    ..
                }))) => {
                    assert!(persistent);
                    assert_eq!(member.ordinal(), 1);
                    let mut handle = session.partial_file(&member).unwrap();
                    assert!(matches!(verify(&mut handle), Verdict::Ok { .. }));
                    assert_eq!(fs::read(dest.join("clean.bin")).unwrap(), clean);
                    completed += 1;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::Provisional(mut artifact),
                    ..
                }))) => {
                    assert!(!persistent);
                    let mut bytes = vec![0; clean.len()];
                    assert!(
                        matches!(artifact.read_at(0, &mut bytes).unwrap(), ArtifactRead::Filled { count: n } if n == clean.len())
                    );
                    assert_eq!(bytes, clean);
                    completed += 1;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => panic!("unexpected member outcome"),
                Poll::Ready(Err(error)) => panic!("{error:?}"),
                Poll::Ready(Ok(None)) => {
                    terminal = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(terminal);
        assert_eq!((skipped_count, completed, ready), (1, 1, usize::from(persistent)));
        assert_eq!(anchors.0.lock().unwrap().len(), usize::from(persistent));
        assert!(!dest.join("old.bin").exists());
    }
}
#[test]
fn versioned_nonempty_skip_preserves_clean_successor() {
    versioned_skip_with_successor(false, false);
}
#[test]
fn versioned_empty_skip_preserves_clean_successor() {
    versioned_skip_with_successor(true, false);
}
#[test]
fn versioned_split_skip_preserves_clean_successor() {
    versioned_skip_with_successor(false, true);
}

#[path = "../docs/persistent-anchor-store.rs"]
mod anchor_store;

#[test]
fn durable_anchor_store_requires_preprovisioned_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("missing");
    assert!(anchor_store::DurableAnchors::open(&root).is_err());
    assert!(!root.exists());
}

#[test]
fn durable_anchor_store_recovers_sync_before_compaction_retirement() {
    let mut maintenance_at = None;
    for inject in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let state_root = dir.path().join("state");
        let trusted = dir.path().join("trusted");
        // Caller provisioning: persist each newly created root's parent link.
        fs::create_dir(&trusted).unwrap();
        File::open(dir.path()).unwrap().sync_all().unwrap();
        File::open(dir.path().parent().unwrap()).unwrap().sync_all().unwrap();
        let anchors = Arc::new(anchor_store::DurableAnchors::open(&trusted).unwrap());
        let mut fixture = Fixture::new();
        let provider = fixture.provider();
        let protection = provider.protection.clone();
        let mut partial = partial_options(&state_root);
        partial.anchors = anchors.clone();
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
        let mut revision = match verify(&mut file) {
            Verdict::Incomplete { revision, .. } => revision,
            other => panic!("{other:?}"),
        };
        for at in (1300..2000).step_by(5) {
            let before = anchors.current(&key).unwrap().unwrap();
            if inject && Some(at) == maintenance_at {
                let output_before = fs::read(dest.join("a.bin")).unwrap();
                let bundle = fs::read_dir(&state_root).unwrap().next().unwrap().unwrap().path();
                let digest: String = before.digest().iter().map(|b| format!("{b:02x}")).collect();
                let old_record = bundle.join(format!("r-{digest}"));
                assert!(old_record.exists());
                anchors.fail_after_rename(2);
                let first = file.fill(at as u64, &fixture.data[0][at..at + 5]).unwrap_err();
                assert!(matches!(first.kind, PartialErrorKind::AnchorCommitUncertain));
                assert_eq!(first.committed.as_ref(), Some(&before));
                let visible = anchors.visible(&key).unwrap().unwrap();
                assert_eq!(visible.sequence(), before.sequence() + 1);
                assert!(old_record.exists());
                let retry = file.fill(at as u64, &fixture.data[0][at..at + 5]);
                assert!(old_record.exists(), "visible but unsynced candidate retired trusted old record");
                let retry = retry.unwrap_err();
                assert!(matches!(retry.kind, PartialErrorKind::Io { operation: OutputOperation::Flush, ref cause }
                    if cause.to_string() == "injected anchor directory sync failure"));
                assert_eq!(anchors.visible(&key).unwrap(), Some(visible.clone()), "failed current must not CAS");
                assert_eq!(fs::read(dest.join("a.bin")).unwrap(), output_before);
                // Only successful current directory sync can acknowledge the rename.
                assert_eq!(anchors.current(&key).unwrap(), Some(visible));
                let filled = file.fill(at as u64, &fixture.data[0][at..at + 5]).unwrap();
                assert_eq!(filled.revision, revision + 1);
                revision = filled.revision;
                assert!(!old_record.exists(), "durability recovery must allow retirement");
                continue;
            }
            let result = file.fill(at as u64, &fixture.data[0][at..at + 5]).unwrap();
            assert_eq!(result.revision, revision + 1);
            revision = result.revision;
            if !inject && maintenance_at.is_none() && result.state.anchor().sequence() == before.sequence() + 3 {
                maintenance_at = Some(at);
            }
        }
        assert!(maintenance_at.is_some());
        assert!(matches!(verify(&mut file), Verdict::Ok {revision: r, ..} if r == revision));
        drop(file);
        let latest = anchors.current(&key).unwrap().unwrap();
        drop(anchors); // release the real process lock before reopen
        let anchors = Arc::new(anchor_store::DurableAnchors::open(&trusted).unwrap());
        assert_eq!(anchors.current(&key).unwrap(), Some(latest.clone()));
        let state = PartialState::load(&state_root, &latest, &PartialLimits::default()).unwrap();
        let mut file = PartialFile::open(
            state,
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
                password: None,
            },
        )
        .unwrap();
        assert!(matches!(verify(&mut file), Verdict::Ok {revision: r, ..} if r == revision));
        assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
    }
}

#[test]
fn paused_member_cannot_verify_or_apply_metadata_before_canonical_finish() {
    use std::os::unix::fs::PermissionsExt;
    for empty in [false, true] {
        for drop_before_finish in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path().join("out");
            let state_root = dir.path().join("state");
            let bytes = if empty { &b""[..] } else { &b"canonical finish must precede final metadata"[..] };
            let mut fixture = Fixture::new();
            fixture.volumes.truncate(1);
            let source = fixture.volumes[0].as_mut().unwrap();
            source.bytes = common::archive(&[common::FileSpec::new("a.bin", bytes)]);
            source.holes.clear();
            let provider = fixture.provider();
            let protection = provider.protection.clone();
            let anchors = Arc::new(Anchors::default());
            let mut partial = partial_options(&state_root);
            partial.anchors = anchors.clone();
            let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
            let (key, mut file) = next_partial(&mut session);
            if !empty {
                loop {
                    match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                        Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { logical_end, .. })))
                            if logical_end == bytes.len() as u64 =>
                        {
                            break;
                        }
                        Poll::Ready(Err(error)) => panic!("{error:?}"),
                        Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => {
                            panic!("lost pause before canonical finalization")
                        }
                        _ => {}
                    }
                }
            }
            assert!(file.remaining().unwrap().is_empty());
            let path = dest.join("a.bin");
            let before = fs::metadata(&path).unwrap();
            let verdict = verify(&mut file);
            let after = fs::metadata(&path).unwrap();
            assert_eq!(
                after.modified().unwrap(),
                before.modified().unwrap(),
                "unfinished member applied archive mtime: {verdict:?}"
            );
            assert_eq!(
                after.permissions().mode(),
                before.permissions().mode(),
                "unfinished member applied archive permissions"
            );
            assert!(matches!(verdict, Verdict::Incomplete { ref holes, .. } if holes.is_empty()));
            if !drop_before_finish {
                loop {
                    match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                        Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                            outcome: MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. },
                            ..
                        }))) => break,
                        Poll::Ready(Err(error)) => panic!("{error:?}"),
                        Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => {
                            panic!("canonical completion must verify")
                        }
                        _ => {}
                    }
                }
                assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
            }
            drop(session);
            let state = file.close().unwrap();
            let latest = anchors.current(&key).unwrap().unwrap();
            assert_eq!(state.anchor(), &latest);
            let mut reopened = PartialFile::open(
                state,
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
                    password: None,
                },
            )
            .unwrap();
            let verdict = verify(&mut reopened);
            if drop_before_finish {
                assert!(matches!(verdict, Verdict::Incomplete { ref holes, .. } if holes.is_empty()));
                assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before.modified().unwrap());
            } else {
                assert!(matches!(verdict, Verdict::Ok { .. }));
                assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
            }
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}

#[test]
fn canonical_finish_failure_never_commits_completion_or_metadata() {
    use std::os::unix::fs::PermissionsExt;
    for checksum_failure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let state_root = dir.path().join("state");
        let data = b"actual canonical checksum failure at member finish";
        let mut fixture = Fixture::new();
        fixture.volumes.truncate(1);
        let source = fixture.volumes[0].as_mut().unwrap();
        source.bytes = common::archive(&[common::FileSpec::new("a.bin", data)]);
        source.holes.clear();
        if checksum_failure {
            let start = source.bytes.windows(data.len()).position(|part| part == data).unwrap();
            source.bytes[start] ^= 1;
        }
        let generation = source.generation.clone();
        let provider = fixture.provider();
        let protection = provider.protection.clone();
        let anchors = Arc::new(Anchors::default());
        let mut partial = partial_options(&state_root);
        partial.anchors = anchors.clone();
        let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
        let (key, mut file) = next_partial(&mut session);
        loop {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { logical_end, .. })))
                    if logical_end == data.len() as u64 =>
                {
                    break;
                }
                Poll::Ready(Err(error)) => panic!("{error:?}"),
                _ => {}
            }
        }
        let path = dest.join("a.bin");
        let before = fs::metadata(&path).unwrap();
        let anchor = anchors.current(&key).unwrap().unwrap();
        let verdict = verify(&mut file);
        if checksum_failure {
            assert!(matches!(verdict, Verdict::Bad { which: ChecksumAlgorithm::Crc32, .. }));
        } else {
            assert!(matches!(verdict, Verdict::Incomplete {ref holes, ..} if holes.is_empty()));
            generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let Poll::Ready(Err(error)) = session.poll_event(&mut Context::from_waker(Waker::noop())) else {
            panic!("finalization must fail");
        };
        if checksum_failure {
            assert!(
                matches!(error.kind, FailureKind::Rar(ref failure) if matches!(failure.as_ref(), zipfast::error::RarFailure::Integrity {reason:zipfast::error::RarIntegrityReason::FinalChecks {crc32:true, ..}, ..}))
            );
        } else {
            assert!(matches!(error.kind, FailureKind::SourceChanged));
        }
        assert_eq!(
            anchors.current(&key).unwrap(),
            Some(anchor.clone()),
            "failed finalization committed a completion transition"
        );
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before.modified().unwrap());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode(), before.permissions().mode());
        drop(session);
        let state = file.close().unwrap();
        let mut file = PartialFile::open(
            state,
            PartialOpenContext {
                output_root: dest,
                state_root,
                expected_member: key,
                expected_anchor: anchor,
                protection,
                limits: PartialLimits::default(),
                progressive_limits: ProgressiveLimits::default(),
                anchors,
                control: SessionControl::default(),
                password: None,
            },
        )
        .unwrap();
        let verdict = verify(&mut file);
        if checksum_failure {
            assert!(matches!(verdict, Verdict::Bad { .. }));
        } else {
            assert!(matches!(verdict, Verdict::Incomplete {ref holes, ..} if holes.is_empty()));
        }
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), before.modified().unwrap());
    }
}

/// Drives a session to its end, returning every hole report and the partial handle of each member.
fn run_to_end(session: &mut ProgressiveSession) -> (Vec<HoleReport>, Vec<PartialFile>) {
    let mut holes = Vec::new();
    let mut files = Vec::new();
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => holes.push(report),
            Poll::Ready(Ok(None)) => return (holes, files),
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    panic!("session did not finish")
}

#[test]
fn declare_hole_after_extraction_reopens_output_and_fill_verifies() {
    for reopen in [false, true] {
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
        let (_, mut files) = run_to_end(&mut session);
        let mut a = files.remove(0);
        a.fill(1300, &fixture.data[0][1300..2000]).unwrap();
        assert!(matches!(verify(&mut a), Verdict::Ok { .. }));

        // Volume 3 carries a.bin 4200..5600. Ten header bytes before its payload map to no output.
        let p3 = fixture.payloads[3].start;
        let receipt = session.declare_hole(3, p3 - 10..p3 + 300).unwrap();
        assert_eq!(receipt.holes.len(), 1);
        let report = &receipt.holes[0];
        assert_eq!(report.out, 4200..4500);
        assert_eq!(report.packed.len(), 1);
        assert_eq!((report.packed[0].volume, report.packed[0].range.clone()), (3, p3..p3 + 300));
        assert!(matches!(report.cause, HoleCause::DeclaredBad));
        assert_eq!(receipt.unmapped.len(), 1);
        assert_eq!((receipt.unmapped[0].volume, receipt.unmapped[0].range.clone()), (3, p3 - 10..p3));
        assert!(receipt.pending.is_empty());

        // The handle held since extraction sees the new hole; the verified member is incomplete again.
        assert_eq!(a.remaining().unwrap(), vec![4200..4500]);
        let Verdict::Incomplete { holes, .. } = verify(&mut a) else {
            panic!("declared damage must reopen the member")
        };
        assert_eq!(holes, vec![4200..4500]);
        drop(session);
        if reopen {
            let key = report.member.clone();
            let state = partial_state::roundtrip(&a.close().unwrap());
            let expected_anchor = anchors.current(&key).unwrap().unwrap();
            a = PartialFile::open(
                state,
                PartialOpenContext {
                    output_root: dest.clone(),
                    state_root: state_root.clone(),
                    expected_member: key,
                    expected_anchor,
                    protection: protection.clone(),
                    limits: PartialLimits::default(),
                    progressive_limits: ProgressiveLimits::default(),
                    anchors: anchors.clone(),
                    control: SessionControl::default(),
                    password: None,
                },
            )
            .unwrap();
            assert_eq!(a.remaining().unwrap(), vec![4200..4500]);
        }
        a.fill(4200, &fixture.data[0][4200..4500]).unwrap();
        assert!(matches!(verify(&mut a), Verdict::Ok { .. }));
        assert_eq!(fs::read(dest.join("a.bin")).unwrap(), fixture.data[0]);
    }
}

#[test]
fn declare_hole_reports_only_output_that_was_still_known() {
    let dir = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::new();
    let mut session = ProgressiveSession::new_partial(
        Box::new(fixture.provider()),
        options(&dir.path().join("out")),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    let (_, mut files) = run_to_end(&mut session);
    // a.bin 1300..1400 in volume 0 is already a Missing hole; only 1200..1300 is newly damaged.
    let p0 = fixture.payloads[0].start;
    let receipt = session.declare_hole(0, p0 + 1200..p0 + 1400).unwrap();
    assert_eq!(receipt.holes.iter().map(|h| h.out.clone()).collect::<Vec<_>>(), vec![1200..1300]);
    assert!(receipt.unmapped.is_empty());
    assert_eq!(files[0].remaining().unwrap(), vec![1200..2000]);
    // Declaring the same bytes again changes nothing.
    assert!(session.declare_hole(0, p0 + 1200..p0 + 1400).unwrap().holes.is_empty());
    // A PartialFile can declare damage on its own after the session is gone.
    drop(session);
    let reports = files[0].declare_hole(4, fixture.payloads[4].start..fixture.payloads[4].start + 1).unwrap();
    assert_eq!(reports.iter().map(|h| h.out.clone()).collect::<Vec<_>>(), vec![5600..5601]);
    files[0].fill(1200, &fixture.data[0][1200..2000]).unwrap();
    files[0].fill(5600, &fixture.data[0][5600..5601]).unwrap();
    assert!(matches!(verify(&mut files[0]), Verdict::Ok { .. }));
}

#[test]
fn declare_hole_before_bytes_are_read_skips_them_without_reading() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let mut fixture = Fixture::new();
    let mut session = ProgressiveSession::new_partial(
        Box::new(fixture.provider()),
        options(&dest),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    // Volume 8 carries b.bin 4200..5600.
    let p8 = fixture.payloads[8].start;
    let receipt = session.declare_hole(8, p8 + 100..p8 + 300).unwrap();
    assert!(receipt.holes.is_empty() && receipt.unmapped.is_empty());
    assert_eq!(receipt.pending.len(), 1);
    assert_eq!((receipt.pending[0].volume, receipt.pending[0].range.clone()), (8, p8 + 100..p8 + 300));
    let (holes, mut files) = run_to_end(&mut session);
    let declared = holes.iter().find(|h| matches!(h.cause, HoleCause::DeclaredBad)).expect("declared hole event");
    assert_eq!(declared.member.ordinal(), 1);
    assert_eq!(declared.out, 4300..4500);
    assert_eq!((declared.packed[0].volume, declared.packed[0].range.clone()), (8, p8 + 100..p8 + 300));
    assert!(
        fixture
            .reads
            .lock()
            .unwrap()
            .iter()
            .all(|&(volume, at, len)| volume != 8 || at + len as u64 <= p8 + 100 || at >= p8 + 300),
        "declared bytes must not be read from the provider"
    );
    let b = &mut files[1];
    assert_eq!(b.remaining().unwrap(), vec![3500..4200, 4300..4500]);
    b.fill(3500, &fixture.data[1][3500..4200]).unwrap();
    b.fill(4300, &fixture.data[1][4300..4500]).unwrap();
    assert!(matches!(verify(b), Verdict::Ok { .. }));
    assert_eq!(fs::read(dest.join("b.bin")).unwrap(), fixture.data[1]);
}

#[test]
fn declare_hole_on_bytes_just_streamed_skips_their_checks_and_member_still_finishes() {
    // An article that turns out bad right after zipfast consumed it: the bytes really are corrupt, so the
    // part CRC would fail unless the declared damage reaches the member machine.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let mut fixture = Fixture::new();
    let p5 = fixture.payloads[5].start;
    fixture.volumes[5].as_mut().unwrap().bytes[p5 as usize + 10] ^= 0x55;
    let mut session = ProgressiveSession::new_partial(
        Box::new(fixture.provider()),
        options(&dest),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    let mut files = Vec::new();
    let mut in_volume_5 = false;
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index: 5, .. }))) => in_volume_5 = true,
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. }))) if in_volume_5 => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    let receipt = session.declare_hole(5, p5 + 10..p5 + 11).unwrap();
    assert_eq!(receipt.holes.iter().map(|h| h.out.clone()).collect::<Vec<_>>(), vec![10..11]);
    let (_, more) = run_to_end(&mut session);
    files.extend(more);
    let b = &mut files[1];
    assert_eq!(b.remaining().unwrap(), vec![10..11, 3500..4200]);
    b.fill(10, &fixture.data[1][10..11]).unwrap();
    b.fill(3500, &fixture.data[1][3500..4200]).unwrap();
    assert!(matches!(verify(b), Verdict::Ok { .. }));
    assert_eq!(fs::read(dest.join("b.bin")).unwrap(), fixture.data[1]);
}

#[test]
fn declare_hole_releases_a_read_parked_on_the_declared_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::new();
    let p8 = fixture.payloads[8].start;
    let gate = Arc::new(WaitGate::default());
    fixture.volumes[8].as_mut().unwrap().wait = Some((p8, gate.clone()));
    let mut session = ProgressiveSession::new_partial(
        Box::new(fixture.provider()),
        options(&dir.path().join("out")),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    let mut files = Vec::new();
    // Run until the provider parks on volume 8's payload; its gate is never woken.
    while gate.0.lock().unwrap().is_none() {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    for _ in 0..5 {
        assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    let receipt = session.declare_hole(8, p8..p8 + 1400).unwrap();
    assert_eq!(receipt.pending.len(), 1);
    let (holes, more) = run_to_end(&mut session);
    files.extend(more);
    assert!(holes.iter().any(|h| h.out == (4200..5600) && matches!(h.cause, HoleCause::DeclaredBad)));
    assert_eq!(files[1].remaining().unwrap(), vec![3500..5600]);
}

#[test]
fn declare_hole_ignores_members_without_parts_on_the_volume() {
    // a.bin has no bytes on volume 5; its output being moved away must not fail damage declared for b.bin.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let mut fixture = Fixture::new();
    let mut session = ProgressiveSession::new_partial(
        Box::new(fixture.provider()),
        options(&dest),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    let (_, files) = run_to_end(&mut session);
    fs::rename(dest.join("a.bin"), dir.path().join("moved.bin")).unwrap();
    let p5 = fixture.payloads[5].start;
    let receipt = session.declare_hole(5, p5 + 10..p5 + 11).unwrap();
    assert_eq!(
        receipt.holes.iter().map(|h| (h.member.ordinal(), h.out.clone())).collect::<Vec<_>>(),
        vec![(1, 10..11)]
    );
    assert_eq!(files[1].remaining().unwrap(), vec![10..11, 3500..4200]);
}

fn volume_bytes(fixture: &Fixture) -> Vec<Vec<u8>> {
    fixture.volumes.iter().map(|v| v.as_ref().unwrap().bytes.clone()).collect()
}
fn extracted(dir: &Path) -> (Fixture, Vec<Vec<u8>>, ProgressiveSession, Vec<PartialFile>) {
    let dest = dir.join("out");
    let mut fixture = Fixture::new();
    let volumes = volume_bytes(&fixture);
    let provider = fixture.provider();
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial_options(&dir.join("state")))
            .unwrap();
    let (_, files) = run_to_end(&mut session);
    (fixture, volumes, session, files)
}
struct CountingReader {
    inner: std::io::Cursor<Vec<u8>>,
    read: u64,
}
impl std::io::Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}
impl std::io::Seek for CountingReader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn fill_packed_with_whole_volumes_fills_only_the_holes_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let (fixture, volumes, _session, mut files) = extracted(dir.path());
    let mut a = files.remove(0);
    let mut b = files.remove(0);
    // a.bin's hole 1300..2000 spans volume 0 (out 0..1400) and volume 1 (out 1400..2800). Whole volume files act
    // like oversized par2 blocks: headers and good bytes are covered too.
    let (p0, p1) = (fixture.payloads[0].clone(), fixture.payloads[1].clone());
    let first = a.fill_packed(0, 0, &volumes[0]).unwrap();
    assert_eq!(first.applied, vec![1300..1400]);
    assert!(first.corrected.is_empty());
    let unmapped: Vec<_> = first.unmapped.iter().map(|s| (s.volume, s.range.clone())).collect();
    assert_eq!(unmapped, vec![(0, 0..p0.start), (0, p0.end..volumes[0].len() as u64)]);
    assert_eq!(a.remaining().unwrap(), vec![1400..2000]);
    let second = a.fill_packed(1, 0, &volumes[1]).unwrap();
    assert_eq!(second.applied, vec![1400..2000]);
    assert_eq!(second.unmapped.len(), 2);
    assert!(a.remaining().unwrap().is_empty());
    assert!(matches!(verify(&mut a), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), fixture.data[0]);
    // Packed bytes of another member's volume map to nothing here.
    let other = b.fill_packed(1, p1.start, &volumes[1][p1.start as usize..p1.end as usize]).unwrap();
    assert!(other.applied.is_empty());
    assert_eq!(other.unmapped.len(), 1);
}

#[test]
fn packed_bytes_win_over_wrong_alt_bytes_and_flag_them() {
    let dir = tempfile::tempdir().unwrap();
    let (fixture, volumes, _session, mut files) = extracted(dir.path());
    let mut a = files.remove(0);
    let wrong: Vec<u8> = fixture.data[0][1300..2000].iter().map(|b| b ^ 0x5a).collect();
    a.fill(1300, &wrong).unwrap();
    assert!(!matches!(verify(&mut a), Verdict::Ok { .. }));
    // A right alt fill of the same range would have been refused; packed bytes replace the wrong ones.
    let p1 = fixture.payloads[1].clone();
    let fixed = a.fill_packed(1, p1.start - 20, &volumes[1][p1.start as usize - 20..p1.start as usize + 1000]).unwrap();
    assert_eq!(fixed.corrected, vec![1400..2000]);
    assert_eq!(fixed.applied, vec![1400..2000]);
    let fixed = a.fill_packed(0, 0, &volumes[0]).unwrap();
    assert_eq!(fixed.corrected, vec![1300..1400]);
    assert!(matches!(verify(&mut a), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), fixture.data[0]);
    // Once corrected, the same packed bytes are a no-op.
    let again = a.fill_packed(0, 0, &volumes[0]).unwrap();
    assert!(again.applied.is_empty() && again.corrected.is_empty());
}

#[test]
fn packed_bytes_that_disagree_with_original_output_are_refused_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (fixture, mut volumes, _session, mut files) = extracted(dir.path());
    let mut a = files.remove(0);
    let p0 = fixture.payloads[0].clone();
    volumes[0][p0.start as usize + 10] ^= 1;
    let error = a.fill_packed(0, 0, &volumes[0]).unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::OverlapMismatch { .. }), "{error:?}");
    assert_eq!(a.remaining().unwrap(), vec![1300..2000]);
    let out = fs::read(dir.path().join("out/a.bin")).unwrap();
    assert_eq!(out[..1300], fixture.data[0][..1300]);
}

#[test]
fn refill_from_packed_reads_only_the_damaged_bytes_of_a_repaired_volume() {
    let dir = tempfile::tempdir().unwrap();
    let (fixture, volumes, _session, mut files) = extracted(dir.path());
    let mut a = files.remove(0);
    // The alt for 1300..1400 was wrong; 1400..2000 is still a hole. Volume 0 and 1 are now repaired on disk.
    let wrong: Vec<u8> = fixture.data[0][1300..1400].iter().map(|b| b.wrapping_add(1)).collect();
    a.fill(1300, &wrong).unwrap();
    let mut reader = CountingReader { inner: std::io::Cursor::new(volumes[0].clone()), read: 0 };
    let first = a.refill_from_packed(0, 0..volumes[0].len() as u64, &mut reader).unwrap();
    assert_eq!(reader.read, 100);
    assert_eq!(first.corrected, vec![1300..1400]);
    let mut reader = CountingReader { inner: std::io::Cursor::new(volumes[1].clone()), read: 0 };
    let second = a.refill_from_packed(1, 0..volumes[1].len() as u64, &mut reader).unwrap();
    assert_eq!(reader.read, 600);
    assert_eq!(second.applied, vec![1400..2000]);
    assert!(matches!(verify(&mut a), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), fixture.data[0]);
    // Nothing left to change: a further refill reads nothing.
    let mut reader = CountingReader { inner: std::io::Cursor::new(volumes[1].clone()), read: 0 };
    let none = a.refill_from_packed(1, 0..volumes[1].len() as u64, &mut reader).unwrap();
    assert_eq!(reader.read, 0);
    assert!(none.applied.is_empty());
}

fn extracted_with(dir: &Path, limits: PartialLimits) -> (Fixture, ProgressiveSession, Vec<PartialFile>) {
    let dest = dir.join("out");
    let mut fixture = Fixture::new();
    let provider = fixture.provider();
    let mut partial = partial_options(&dir.join("state"));
    partial.limits = limits;
    let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
    let (_, files) = run_to_end(&mut session);
    (fixture, session, files)
}

// Catches streaming fills that need the whole range in memory or lose bytes at transaction boundaries.
#[test]
fn fill_writer_streams_an_alt_tail_through_bounded_transactions() {
    let dir = tempfile::tempdir().unwrap();
    let limits = PartialLimits { fill_bytes: 2048, ..PartialLimits::default() };
    let (fixture, _session, mut files) = extracted_with(dir.path(), limits);
    let mut a = files.remove(0);
    // RustyGet's alt switch: everything from an offset to the end comes from the alt, known bytes included.
    let mut writer = a.fill_writer(1000).unwrap();
    for piece in fixture.data[0][1000..].chunks(100) {
        std::io::Write::write_all(&mut writer, piece).unwrap();
    }
    assert_eq!(writer.position(), 7000);
    let result = writer.finish().unwrap();
    assert_eq!(result.applied, vec![1300..2000]);
    assert!(a.remaining().unwrap().is_empty());
    assert!(matches!(verify(&mut a), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), fixture.data[0]);
}

#[test]
fn fill_writer_reports_the_typed_error_and_accepts_nothing_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let limits = PartialLimits { fill_bytes: 2048, ..PartialLimits::default() };
    let (fixture, _session, mut files) = extracted_with(dir.path(), limits);
    let mut a = files.remove(0);
    let mut alt = fixture.data[0].clone();
    alt[1100] ^= 1; // a known byte: the alt disagrees with the archive output
    let mut writer = a.fill_writer(1000).unwrap();
    let mut failed = false;
    for piece in alt[1000..].chunks(100) {
        if std::io::Write::write_all(&mut writer, piece).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed);
    assert!(std::io::Write::write(&mut writer, b"x").is_err());
    let error = writer.finish().unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::OverlapMismatch { .. }), "{error:?}");
    assert_eq!(a.remaining().unwrap(), vec![1300..2000]);
}

#[test]
fn fill_from_stops_on_short_input_with_committed_progress() {
    let dir = tempfile::tempdir().unwrap();
    let limits = PartialLimits { fill_bytes: 2048, ..PartialLimits::default() };
    let (fixture, _session, mut files) = extracted_with(dir.path(), limits);
    let mut a = files.remove(0);
    // The alt stream for 0..7000 ends after 5000 bytes: two 2048-byte transactions (holding the hole) committed.
    let mut input = &fixture.data[0][..5000];
    let error = a.fill_from(0, 7000, &mut input).unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::FillRead(_)), "{error:?}");
    let output = error.output.unwrap();
    assert_eq!((output.offset, output.attempted, output.completed), (0, 7000, 4096));
    assert!(a.remaining().unwrap().is_empty());
    assert!(matches!(verify(&mut a), Verdict::Ok { .. }));
}

// Catches each streamed fill permanently spending the session's shared metadata budget.
#[test]
fn many_streamed_fills_do_not_exhaust_the_metadata_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (fixture, _session, mut files) = extracted_with(dir.path(), PartialLimits::default());
    let mut a = files.remove(0);
    for _ in 0..300 {
        let mut input = &fixture.data[0][..];
        a.fill_from(0, 7000, &mut input).unwrap();
    }
    assert!(matches!(verify(&mut a), Verdict::Ok { .. }));
}

// ---- Encrypted (AES-256-CBC) RAR5 stored members ----

type Reads = Arc<Mutex<Vec<(u32, u64, usize)>>>;
fn hole(range: Range<u64>) -> Vec<Range<u64>> {
    std::iter::once(range).collect()
}
const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let mut inner: Vec<u8> = padded.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(message);
    let mut outer: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&zipfast::crypto::sha256(&inner));
    zipfast::crypto::sha256(&outer)
}
/// The RAR5 password check value: PBKDF2-HMAC-SHA256 continued 32 rounds past the key, folded to 8 bytes.
fn password_check(password: &str, kdf_count: u8) -> [u8; 8] {
    let mut block = SALT.to_vec();
    block.extend(1u32.to_be_bytes());
    let mut u = hmac(password.as_bytes(), &block);
    let mut sum = u;
    for _ in 1..(1u32 << kdf_count) + 32 {
        u = hmac(password.as_bytes(), &u);
        sum.iter_mut().zip(u).for_each(|(s, b)| *s ^= b);
    }
    let mut folded = [0u8; 8];
    sum.iter().enumerate().for_each(|(i, b)| folded[i % 8] ^= b);
    folded
}
struct Encrypted {
    plain: Vec<u8>,
    cipher: Vec<u8>,
    volumes: Vec<Vec<u8>>,
    /// Ciphertext payload of each volume, and the ciphertext stream offset where it starts.
    payloads: Vec<Range<u64>>,
    starts: Vec<u64>,
}
impl Encrypted {
    /// One encrypted stored member "e.bin" of `size` bytes, its ciphertext cut at the stream offsets `cuts`
    /// (one part per volume), with keyed (tweaked) checks and, with `check`, a password check value.
    fn new(size: usize, cuts: &[usize], check: bool) -> Self {
        let plain: Vec<u8> = (0..size).map(|i| ((i * 7 + 3) % 253) as u8).collect();
        let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
        let mut padded = plain.clone();
        padded.resize(size.div_ceil(16) * 16, 0);
        let cipher = zipfast::crypto::encrypt_cbc(&key, &IV, &padded).unwrap();
        let mut extra = vec![if check { 48 } else { 36 }, 1, 0, if check { 3 } else { 2 }, 1];
        extra.extend(SALT);
        extra.extend(IV);
        if check {
            let value = password_check("pw", 1);
            extra.extend(value);
            extra.extend(&zipfast::crypto::sha256(&value)[..4]);
        }
        let mut spec = common::FileSpec::new("e.bin", &cipher);
        spec.size = Some(size as u64);
        spec.extra = extra;
        let bounds: Vec<usize> = std::iter::once(0).chain(cuts.iter().copied()).chain([cipher.len()]).collect();
        let (mut volumes, mut payloads, mut starts) = (Vec::new(), Vec::new(), Vec::new());
        for (index, pair) in bounds.windows(2).enumerate() {
            let part = &cipher[pair[0]..pair[1]];
            let last = pair[1] == cipher.len();
            let crc = crc32fast::hash(if last { &plain } else { part });
            let crc = zipfast::crypto::rar5_tweak_crc32(crc, &hash_key);
            let mut bytes = common::SIG.to_vec();
            bytes.extend(common::main_block(true, Some(index as u64)));
            let file = common::file_block(&spec, part, crc, index > 0, !last);
            let start = (bytes.len() + file.len() - part.len()) as u64;
            bytes.extend(file);
            bytes.extend(common::end_block(!last));
            volumes.push(bytes);
            payloads.push(start..start + part.len() as u64);
            starts.push(pair[0] as u64);
        }
        Self { plain, cipher, volumes, payloads, starts }
    }
    /// Packed spans of ciphertext stream `range`, one per volume piece.
    fn packed(&self, range: Range<u64>) -> Vec<(u32, Range<u64>)> {
        let mut spans = Vec::new();
        for (volume, payload) in self.payloads.iter().enumerate() {
            let start = self.starts[volume];
            let end = start + (payload.end - payload.start);
            let (a, b) = (range.start.max(start), range.end.min(end));
            if a < b {
                spans.push((volume as u32, payload.start + (a - start)..payload.start + (b - start)));
            }
        }
        spans
    }
    /// A provider whose sources answer the ciphertext stream ranges `holes` as holes.
    fn provider(&self, holes: &[Range<u64>]) -> (Provider, Reads) {
        let reads = Arc::new(Mutex::new(Vec::new()));
        let volumes = (0..self.volumes.len())
            .map(|index| {
                let holes = holes
                    .iter()
                    .flat_map(|hole| self.packed(hole.clone()))
                    .filter(|(volume, _)| *volume == index as u32)
                    .map(|(_, range)| range)
                    .collect();
                Some(Source {
                    generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    backing_hook: Arc::new(Mutex::new(None)),
                    index: index as u32,
                    bytes: self.volumes[index].clone(),
                    holes,
                    reads: reads.clone(),
                    backing: Vec::new(),
                    hook: Arc::new(Mutex::new(None)),
                    wait: None,
                })
            })
            .collect();
        let protection = ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..self.volumes.len() as u32)
                    .map(|index| ProtectedVolume { index, name: volume_name(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        };
        let provider = Provider {
            volumes,
            protection,
            wait: None,
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            protection_hook: None,
        };
        (provider, reads)
    }
}
struct EncryptedRun {
    holes: Vec<HoleReport>,
    file: PartialFile,
    key: MemberKey,
    anchors: Arc<Anchors>,
    protection: ProtectionDeclaration,
    session: ProgressiveSession,
}
fn extract_encrypted(dir: &Path, fixture: &Encrypted, holes: &[Range<u64>]) -> EncryptedRun {
    let (provider, _) = fixture.provider(holes);
    let protection = provider.protection.clone();
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&dir.join("state"));
    partial.anchors = anchors.clone();
    let mut opts = options(&dir.join("out"));
    opts.set_password(Some("pw".into())).unwrap();
    let mut session = ProgressiveSession::new_partial(Box::new(provider), opts, partial).unwrap();
    let mut outcome = None;
    let mut reports = Vec::new();
    let mut files = Vec::new();
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push((member.clone(), session.partial_file(&member).unwrap()))
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => reports.push(report),
            Poll::Ready(Ok(Some(ProgressiveEvent::PartVerified { .. }))) => {
                panic!("encrypted part checks cover ciphertext and have no plaintext mirror")
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome: o, .. }))) => outcome = Some(o),
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    let outcome = outcome.expect("member finished");
    if holes.is_empty() {
        assert!(matches!(outcome, MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }));
    } else {
        assert!(matches!(outcome, MemberOutcome::PersistentPartial { .. }));
    }
    let (key, file) = files.pop().unwrap();
    EncryptedRun { holes: reports, file, key, anchors, protection, session }
}
#[allow(clippy::result_large_err, reason = "the public partial error type")]
fn reopen(dir: &Path, run: EncryptedRun, password: Option<&str>) -> PartialResult<PartialFile> {
    reopen_with(dir, run, password, ProgressiveLimits::default())
}
#[allow(clippy::result_large_err, reason = "the public partial error type")]
fn reopen_with(
    dir: &Path,
    run: EncryptedRun,
    password: Option<&str>,
    progressive_limits: ProgressiveLimits,
) -> PartialResult<PartialFile> {
    drop(run.session);
    let state = partial_state::roundtrip(&run.file.close().unwrap());
    let expected_anchor = run.anchors.current(&run.key).unwrap().unwrap();
    PartialFile::open(
        state,
        PartialOpenContext {
            output_root: dir.join("out"),
            state_root: dir.join("state"),
            expected_member: run.key,
            expected_anchor,
            protection: run.protection,
            limits: PartialLimits::default(),
            progressive_limits,
            anchors: run.anchors,
            control: SessionControl::default(),
            password: password.map(Into::into),
        },
    )
}
#[allow(clippy::result_large_err, reason = "the public partial error type")]
fn verify_result(file: &mut PartialFile) -> PartialResult<Verdict> {
    for _ in 0..10000 {
        if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            return result;
        }
    }
    panic!("local verification failed to complete")
}
/// (output, cause) of each report, with consecutive reports of one cause joined.
fn joined(reports: &[HoleReport]) -> Vec<(Range<u64>, HoleCause)> {
    let mut out: Vec<(Range<u64>, HoleCause)> = Vec::new();
    for report in reports {
        match out.last_mut() {
            Some((range, cause)) if range.end == report.out.start && *cause == report.cause => {
                range.end = report.out.end
            }
            _ => out.push((report.out.clone(), report.cause.clone())),
        }
    }
    out
}
fn spans(report: &HoleReport) -> Vec<(u32, Range<u64>)> {
    report.packed.iter().map(|s| (s.volume, s.range.clone())).collect()
}
fn fill_plain(file: &mut PartialFile, fixture: &Encrypted) {
    for hole in file.remaining().unwrap() {
        file.fill(hole.start, &fixture.plain[hole.start as usize..hole.end as usize]).unwrap();
    }
}
const CUTS: [usize; 2] = [1001, 2004];

#[test]
fn encrypted_split_hole_reports_are_block_widened_with_a_cipher_neighbour_and_alt_fill_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    // One hole straddles the boundary of volumes 0 and 1, one lies inside volume 1.
    let mut run = extract_encrypted(dir.path(), &fixture, &[990..1010, 1500..1510]);
    assert_eq!(
        joined(&run.holes),
        vec![
            (976..1024, HoleCause::Missing),
            (1024..1040, HoleCause::CipherNeighbour),
            (1488..1520, HoleCause::Missing),
            (1520..1536, HoleCause::CipherNeighbour),
        ]
    );
    // Every report's packed spans are exactly its whole ciphertext blocks, one span per volume piece.
    for report in &run.holes {
        assert_eq!(report.out.start % 16, 0);
        assert_eq!(report.out.end % 16, 0);
        assert_eq!(spans(report), fixture.packed(report.out.clone()), "{report:?}");
    }
    let straddling = run.holes.iter().find(|r| r.out.contains(&992)).unwrap();
    assert_eq!(straddling.packed.len(), 2, "a block cut by a volume boundary has one span per volume");
    let file = &mut run.file;
    assert_eq!(file.remaining().unwrap(), vec![976..1040, 1488..1536]);
    assert!(matches!(verify(file), Verdict::Incomplete { .. }));
    fill_plain(file, &fixture);
    let Verdict::Ok { parts, .. } = verify(file) else { panic!("alt plaintext must verify the keyed member CRC") };
    assert!(parts.iter().all(|p| p.crc32 == CheckResult::Missing), "encrypted part checks are never plaintext checks");
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_member_without_holes_verifies_ok_during_extraction() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let run = extract_encrypted(dir.path(), &fixture, &[]);
    assert!(run.holes.is_empty());
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_reopen_with_password_fills_from_an_alt_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let run = extract_encrypted(dir.path(), &fixture, &[990..1010, 1500..1510]);
    let mut file = reopen(dir.path(), run, Some("pw")).unwrap();
    assert_eq!(file.remaining().unwrap(), vec![976..1040, 1488..1536]);
    fill_plain(&mut file, &fixture);
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_reopen_without_or_with_a_wrong_password() {
    // With a password check value, a wrong password is refused at open.
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
    let error = reopen(dir.path(), run, Some("wrong")).err().expect("wrong password");
    assert!(matches!(error.kind, PartialErrorKind::WrongPassword), "{error:?}");

    // Without a password, plaintext fills work but the keyed member check and decryption need the password.
    let dir = tempfile::tempdir().unwrap();
    let run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
    let p1 = fixture.payloads[1].start;
    let mut file = reopen(dir.path(), run, None).unwrap();
    let error = file.fill_packed(1, 0, &fixture.volumes[1]).unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::PasswordRequired), "{error:?}");
    assert!(matches!(verify_result(&mut file).unwrap(), Verdict::Incomplete { .. }), "holes come first");
    fill_plain(&mut file, &fixture);
    let error = verify_result(&mut file).unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::PasswordRequired), "{error:?}");
    assert!(p1 > 0);

    // Without a check value a wrong password cannot be refused at open; the keyed member CRC then fails.
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, false);
    let run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
    let mut file = reopen(dir.path(), run, Some("wrong")).unwrap();
    fill_plain(&mut file, &fixture);
    assert!(matches!(verify_result(&mut file).unwrap(), Verdict::Bad { .. }));
}

#[test]
fn encrypted_fill_packed_with_whole_volumes_decrypts_across_volume_boundaries_and_verifies() {
    for reopened in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Encrypted::new(3000, &CUTS, true);
        let run = extract_encrypted(dir.path(), &fixture, &[990..1010, 1500..1510]);
        let mut file = if reopened { reopen(dir.path(), run, Some("pw")).unwrap() } else { run.file };
        // Volume 0 ends inside block 992..1008: that block cannot be decrypted from volume 0 alone. Its first
        // bytes are kept, so the next volume completes it.
        let first = file.fill_packed(0, 0, &fixture.volumes[0]).unwrap();
        assert_eq!(first.applied, vec![976..992]);
        assert_eq!(first.undecryptable, vec![992..1008]);
        let p0 = fixture.payloads[0].clone();
        let unmapped: Vec<_> = first.unmapped.iter().map(|s| (s.volume, s.range.clone())).collect();
        assert_eq!(unmapped, vec![(0, 0..p0.start), (0, p0.end..fixture.volumes[0].len() as u64)]);
        assert_eq!(file.remaining().unwrap(), vec![992..1040, 1488..1536]);
        let second = file.fill_packed(1, 0, &fixture.volumes[1]).unwrap();
        assert_eq!(second.applied, vec![992..1040, 1488..1536]);
        assert!(second.undecryptable.is_empty() && second.corrected.is_empty());
        assert!(file.remaining().unwrap().is_empty());
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
        assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
        // Volume 2 overlaps only original output: it must match and changes nothing.
        let third = file.fill_packed(2, 0, &fixture.volumes[2]).unwrap();
        assert!(third.applied.is_empty() && third.undecryptable.is_empty());
    }
}

#[test]
fn encrypted_fill_packed_reports_blocks_whose_previous_ciphertext_block_is_missing() {
    for reopened in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Encrypted::new(3000, &CUTS, true);
        let mut run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
        let block = |offset: u64| {
            let (volume, range) = fixture.packed(offset..offset + 16).remove(0);
            (volume, range.start, &fixture.cipher[offset as usize..offset as usize + 16])
        };
        // Block 1504's previous block 1488 is itself a hole: it cannot be decrypted. The kept neighbour block
        // 1520 decrypts with 1504 as its previous block.
        let (volume, at, bytes) = block(1504);
        let result = run.file.fill_packed(volume, at, bytes).unwrap();
        assert_eq!(result.undecryptable, vec![1504..1520]);
        assert_eq!(result.applied, vec![1520..1536]);
        assert_eq!(run.file.remaining().unwrap(), vec![1488..1520]);
        // Kept ciphertext blocks are durable state: they survive a reopen.
        let mut file = if reopened { reopen(dir.path(), run, Some("pw")).unwrap() } else { run.file };
        // Block 1488 decrypts with the block kept from before the hole, and 1504, now kept, decrypts with it.
        let (volume, at, bytes) = block(1488);
        let result = file.fill_packed(volume, at, bytes).unwrap();
        assert!(result.undecryptable.is_empty());
        assert_eq!(result.applied, vec![1488..1520]);
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
        assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
    }
}

#[test]
fn encrypted_exact_report_spans_correct_wrong_alt_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let mut run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
    let wrong: Vec<u8> = fixture.plain[1488..1536].iter().map(|b| b ^ 0x5a).collect();
    run.file.fill(1488, &wrong).unwrap();
    // A twin post of exactly the reported packed spans: the kept block before the hole decrypts the first.
    for report in run.holes.clone() {
        for span in &report.packed {
            let bytes = &fixture.volumes[span.volume as usize][span.range.start as usize..span.range.end as usize];
            let result = run.file.fill_packed(span.volume, span.range.start, bytes).unwrap();
            assert!(result.undecryptable.is_empty());
        }
    }
    assert!(matches!(verify(&mut run.file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_corrupt_packed_bytes_over_original_output_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let mut run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
    let mut volume = fixture.volumes[1].clone();
    volume[fixture.payloads[1].start as usize + 10] ^= 1;
    let error = run.file.fill_packed(1, 0, &volume).unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::OverlapMismatch { .. }), "{error:?}");
    assert_eq!(run.file.remaining().unwrap(), vec![1488..1536]);
}

#[test]
fn encrypted_packed_bytes_correct_wrong_alt_bytes_and_refill_reads_whole_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let mut run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
    let file = &mut run.file;
    let wrong: Vec<u8> = fixture.plain[1488..1536].iter().map(|b| b ^ 0x5a).collect();
    file.fill(1488, &wrong).unwrap();
    assert!(matches!(verify(file), Verdict::Bad { .. }));
    // A repaired volume 1: the refill reads the alt blocks plus the block before them, nothing else.
    let mut reader = CountingReader { inner: std::io::Cursor::new(fixture.volumes[1].clone()), read: 0 };
    let result = file.refill_from_packed(1, 0..fixture.volumes[1].len() as u64, &mut reader).unwrap();
    assert_eq!(reader.read, 16 + 48);
    assert_eq!(result.corrected, vec![1488..1536]);
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_hole_at_stream_offset_zero_decrypts_with_the_header_iv() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let mut run = extract_encrypted(dir.path(), &fixture, &hole(0..5));
    assert_eq!(joined(&run.holes), vec![(0..16, HoleCause::Missing), (16..32, HoleCause::CipherNeighbour)]);
    let missing = &run.holes[0];
    assert_eq!(spans(missing), fixture.packed(0..16));
    let (volume, range) = (missing.packed[0].volume, missing.packed[0].range.clone());
    let result = run.file.fill_packed(volume, range.start, &fixture.cipher[..16]).unwrap();
    assert!(result.undecryptable.is_empty());
    assert_eq!(result.applied, vec![0..32]);
    assert!(matches!(verify(&mut run.file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_final_padding_hole_maps_to_no_output_past_the_size() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    // Only padding bytes are lost, but CBC loses the whole last block: its output ends at the size.
    let mut run = extract_encrypted(dir.path(), &fixture, &hole(3002..3008));
    assert_eq!(joined(&run.holes), vec![(2992..3000, HoleCause::Missing)]);
    let report = &run.holes[0];
    let last = fixture.payloads[2].clone();
    assert_eq!(spans(report), vec![(2, last.end - 16..last.end)], "the packed span keeps the padding");
    // The end-of-archive header after the padding maps to nothing.
    let at = last.end - 16;
    let result = run.file.fill_packed(2, at, &fixture.volumes[2][at as usize..]).unwrap();
    assert_eq!(result.applied, vec![2992..3000]);
    let unmapped: Vec<_> = result.unmapped.iter().map(|s| (s.volume, s.range.clone())).collect();
    assert_eq!(unmapped, vec![(2, last.end..fixture.volumes[2].len() as u64)]);
    assert!(matches!(verify(&mut run.file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_declared_damage_widens_to_blocks_with_a_cipher_neighbour() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let mut run = extract_encrypted(dir.path(), &fixture, &[]);
    let p0 = fixture.payloads[0].start;
    let receipt = run.session.declare_hole(0, p0 + 100..p0 + 101).unwrap();
    assert_eq!(joined(&receipt.holes), vec![(96..112, HoleCause::DeclaredBad), (112..128, HoleCause::CipherNeighbour)]);
    assert!(receipt.unmapped.is_empty() && receipt.pending.is_empty());
    assert_eq!(run.file.remaining().unwrap(), vec![96..128]);
    fill_plain(&mut run.file, &fixture);
    assert!(matches!(verify(&mut run.file), Verdict::Ok { .. }));
}

#[test]
fn encrypted_damage_declared_before_it_is_read_is_a_declared_hole() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let (provider, _) = fixture.provider(&[]);
    let mut opts = options(&dir.path().join("out"));
    opts.set_password(Some("pw".into())).unwrap();
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), opts, partial_options(&dir.path().join("state"))).unwrap();
    let p1 = fixture.payloads[1].start;
    // Stream 1500..1510 lies in volume 1.
    let receipt = session.declare_hole(1, p1 + 499..p1 + 509).unwrap();
    assert_eq!(receipt.pending.len(), 1);
    let (holes, mut files) = run_to_end(&mut session);
    assert_eq!(joined(&holes), vec![(1488..1520, HoleCause::DeclaredBad), (1520..1536, HoleCause::CipherNeighbour)]);
    fill_plain(&mut files[0], &fixture);
    assert!(matches!(verify(&mut files[0]), Verdict::Ok { .. }));
}

#[test]
fn encrypted_damage_declared_on_bytes_still_in_the_cipher_state_becomes_holes() {
    // Damage on the block still being assembled, then on the last complete block, which decrypts the next one.
    for previous in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Encrypted::new(3000, &CUTS, true);
        let (provider, reads) = fixture.provider(&[]);
        let mut opts = options(&dir.path().join("out"));
        opts.set_password(Some("pw".into())).unwrap();
        let mut session =
            ProgressiveSession::new_partial(Box::new(provider), opts, partial_options(&dir.path().join("state")))
                .unwrap();
        let mut files = Vec::new();
        let mut in_volume_1 = false;
        loop {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                    files.push(session.partial_file(&member).unwrap())
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index: 1, .. }))) => in_volume_1 = true,
                Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. }))) if in_volume_1 => break,
                Poll::Ready(Err(e)) => panic!("{e:?}"),
                _ => {}
            }
        }
        // The last byte fed: its block is still being assembled, so no output holds it yet.
        let (volume, at, len) = *reads.lock().unwrap().last().unwrap();
        assert_eq!(volume, 1);
        let fed = fixture.starts[1] + (at + len as u64 - fixture.payloads[1].start);
        assert_ne!(fed % 16, 0, "the fixture must leave a partial block");
        let block = (fed & !15) - if previous { 16 } else { 0 };
        // Damage the first byte of the block: the partial block holds only `fed % 16` bytes.
        let packed = fixture.payloads[1].start + (block - fixture.starts[1]);
        let receipt = session.declare_hole(1, packed..packed + 1).unwrap();
        assert!(receipt.unmapped.is_empty() && receipt.pending.is_empty());
        let (holes, more) = run_to_end(&mut session);
        files.extend(more);
        let mut all = receipt.holes.clone();
        all.extend(holes);
        assert_eq!(
            joined(&all),
            vec![(block..block + 16, HoleCause::DeclaredBad), (block + 16..block + 32, HoleCause::CipherNeighbour)]
        );
        fill_plain(&mut files[0], &fixture);
        assert!(matches!(verify(&mut files[0]), Verdict::Ok { .. }));
        assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
    }
}

#[test]
fn encrypted_declared_damage_drops_the_kept_block_it_covers() {
    // Byte 1475 is corrupt in the extraction's copy of volume 1, and 1500..1510 is missing. Extraction keeps
    // block 1472, the block before the hole run, with the corrupt byte in it.
    for via_session in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Encrypted::new(3000, &CUTS, true);
        let mut bad = Encrypted::new(3000, &CUTS, true);
        let corrupt = fixture.packed(1475..1476).remove(0);
        assert_eq!(corrupt.0, 1);
        bad.volumes[1][corrupt.1.start as usize] ^= 1;
        let mut run = extract_encrypted(dir.path(), &bad, &hole(1500..1510));
        assert_eq!(
            joined(&run.holes),
            vec![(1488..1520, HoleCause::Missing), (1520..1536, HoleCause::CipherNeighbour)]
        );
        let holes = if via_session {
            run.session.declare_hole(1, corrupt.1.clone()).unwrap().holes
        } else {
            run.file.declare_hole(1, corrupt.1.clone()).unwrap()
        };
        assert_eq!(joined(&holes), vec![(1472..1488, HoleCause::DeclaredBad)]);
        // Good twin bytes of the Missing report's spans: block 1488 needs block 1472, which is now untrusted.
        for (volume, range) in fixture.packed(1488..1520) {
            let bytes = &fixture.volumes[volume as usize][range.start as usize..range.end as usize];
            let result = run.file.fill_packed(volume, range.start, bytes).unwrap();
            assert_eq!(result.undecryptable, vec![1488..1504], "decrypted with the damaged kept block");
            assert_eq!(result.applied, vec![1504..1536]);
        }
        // The DeclaredBad report's spans, plus one block before them, fill the rest.
        let (volume, range) = fixture.packed(1456..1488).remove(0);
        run.file
            .fill_packed(
                volume,
                range.start,
                &fixture.volumes[volume as usize][range.start as usize..range.end as usize],
            )
            .unwrap();
        let (volume, range) = fixture.packed(1472..1504).remove(0);
        run.file
            .fill_packed(
                volume,
                range.start,
                &fixture.volumes[volume as usize][range.start as usize..range.end as usize],
            )
            .unwrap();
        assert!(run.file.remaining().unwrap().is_empty());
        assert!(matches!(verify(&mut run.file), Verdict::Ok { .. }));
        assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
    }
}

#[test]
fn encrypted_whole_volume_fill_over_known_output_costs_bookkeeping_per_run() {
    // About 25,000 blocks of volume 1 are already known; the fill must not charge bookkeeping for each.
    let size = 1 << 20;
    let cuts = [300_001, 700_004];
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(size, &cuts, true);
    let run = extract_encrypted(dir.path(), &fixture, &hole(500_000..500_010));
    let limits = ProgressiveLimits { source_bookkeeping: 4_000, ..ProgressiveLimits::default() };
    let mut file = reopen_with(dir.path(), run, Some("pw"), limits).unwrap();
    for _ in 0..3 {
        let result = file.fill_packed(1, 0, &fixture.volumes[1]).unwrap();
        assert!(result.undecryptable.is_empty());
    }
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

#[test]
fn encrypted_packed_fill_without_a_check_value_needs_a_proven_password() {
    let fixture = Encrypted::new(3000, &CUTS, false);
    let bytes = |stream: Range<u64>| {
        let (volume, range) = fixture.packed(stream).remove(0);
        (volume, range.start, &fixture.volumes[volume as usize][range.start as usize..range.end as usize])
    };
    for password in ["wrong", "pw"] {
        let dir = tempfile::tempdir().unwrap();
        let run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
        assert_eq!(
            joined(&run.holes),
            vec![(1488..1520, HoleCause::Missing), (1520..1536, HoleCause::CipherNeighbour)]
        );
        let mut file = reopen(dir.path(), run, Some(password)).unwrap();
        // The Missing report's exact spans decrypt only hole blocks (with the kept blocks 1472 and 1520): nothing
        // shows the password is right.
        let (volume, at, missing) = bytes(1488..1520);
        let error = file.fill_packed(volume, at, missing).unwrap_err();
        assert!(matches!(error.kind, PartialErrorKind::PasswordUnverified), "{error:?}");
        assert_eq!(file.remaining().unwrap(), vec![1488..1536]);
        // Block 1456 decrypts with 1440 to original output: it proves (or refutes) the password.
        let (proof_volume, proof_at, proof) = bytes(1440..1472);
        let result = file.fill_packed(proof_volume, proof_at, proof);
        if password == "wrong" {
            let error = result.unwrap_err();
            assert!(matches!(error.kind, PartialErrorKind::WrongPassword), "{error:?}");
            assert_eq!(file.remaining().unwrap(), vec![1488..1536]);
            continue;
        }
        assert!(result.unwrap().applied.is_empty());
        assert_eq!(file.fill_packed(volume, at, missing).unwrap().applied, vec![1488..1536]);
        assert!(file.remaining().unwrap().is_empty());
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
        assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
    }
}

#[test]
fn encrypted_cipher_neighbour_hole_precedes_the_bytes_written_past_it() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let (provider, _) = fixture.provider(&hole(1500..1510));
    let mut opts = options(&dir.path().join("out"));
    opts.set_password(Some("pw".into())).unwrap();
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), opts, partial_options(&dir.path().join("state"))).unwrap();
    // Holes and written bytes must arrive in output order.
    let mut cursor = 0;
    let mut neighbour = false;
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => {
                assert_eq!(report.out.start, cursor, "{report:?}");
                neighbour |= report.cause == HoleCause::CipherNeighbour;
                cursor = report.out.end;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { valid_bytes, logical_end, .. }))) => {
                assert_eq!(
                    logical_end - valid_bytes,
                    cursor,
                    "a hole below logical_end {logical_end} is not delivered"
                );
                cursor = logical_end;
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    assert!(neighbour);
    assert_eq!(cursor, 3000);
}

#[test]
fn encrypted_refill_without_a_check_value_proves_the_password_from_an_earlier_block() {
    let fixture = Encrypted::new(3000, &CUTS, false);
    for password in ["wrong", "pw"] {
        let dir = tempfile::tempdir().unwrap();
        let run = extract_encrypted(dir.path(), &fixture, &hole(1500..1510));
        let mut file = reopen(dir.path(), run, Some(password)).unwrap();
        let mut reader = CountingReader { inner: std::io::Cursor::new(fixture.volumes[1].clone()), read: 0 };
        let result = file.refill_from_packed(1, 0..fixture.volumes[1].len() as u64, &mut reader);
        if password == "wrong" {
            let error = result.unwrap_err();
            assert!(matches!(error.kind, PartialErrorKind::WrongPassword), "{error:?}");
            assert_eq!(file.remaining().unwrap(), vec![1488..1536]);
            continue;
        }
        // Blocks 1456 and 1472 before the 48-byte hole: 1472 decrypts with 1456 to original output.
        assert_eq!(result.unwrap().applied, vec![1488..1536]);
        assert_eq!(reader.read, 32 + 48);
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
        assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
    }
}
