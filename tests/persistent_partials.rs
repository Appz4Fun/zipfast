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
    /// Answers each hole whole, from the read offset to its end, rather than capped at the buffer; and, when
    /// `slow`, every other read `NotYet` first.
    long_holes: bool,
    slow: bool,
    ticks: usize,
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
        self.ticks += 1;
        if self.slow && self.ticks % 2 == 1 {
            cx.waker().wake_by_ref();
            return Ok(RangeRead::NotYet);
        }
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
                let len = if self.long_holes { hole.end - at } else { (hole.end - at).min(buf.len() as u64) };
                return Ok(RangeRead::Hole { len });
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
                long_holes: false,
                slow: false,
                ticks: 0,
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
            salvage_truncated_zip: false,
            unix_modes: Default::default(),
            backslashes: Default::default(),
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
/// Runs a session whose every member is refused: each is skipped, and nothing is created.
fn refused_without_effects(mut fixture: Fixture) -> Vec<RefusalReason> {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state = dir.path().join("state");
    let mut session =
        ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dest), partial_options(&state)).unwrap();
    let mut reasons = Vec::new();
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { .. }))) => panic!("refused member created output"),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Refused { reason },
                ..
            }))) => reasons.push(reason),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => panic!("member not refused"),
            Poll::Ready(Ok(None)) => break,
            _ => {}
        }
    }
    assert!(!dest.exists());
    assert!(!state.exists());
    reasons
}
#[test]
fn known_unsupported_members_and_invalid_options_refuse_before_effects() {
    // Unsupported members are refused one by one; the session skips them and ends without effects.
    assert_eq!(
        refused_without_effects(Fixture::configured(|_, s| s.method = 1)),
        [RefusalReason::Compressed { method: 1 }; 2]
    );
    assert_eq!(
        refused_without_effects(Fixture::configured(|_, s| s.size_unknown = true)),
        [RefusalReason::UnknownSize; 2]
    );
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
    assert_eq!(refused_without_effects(redirection), [RefusalReason::Redirection; 2]);
    // RAR4 stored members are admitted; tests/persistent_partials_rar4.rs covers the RAR4 refusals.
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
/// Arms once genesis preparation asks for the member's anchor: the second lookup, after the session's own check
/// for an anchor an earlier session left (adoption).
struct ArmStore {
    inner: Anchors,
    armed: Arc<std::sync::atomic::AtomicBool>,
    lookups: std::sync::atomic::AtomicUsize,
}
impl StateAnchorStore for ArmStore {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        if self.lookups.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1 {
            self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
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
    partial.anchors = Arc::new(ArmStore { inner: Anchors::default(), armed, lookups: Default::default() });
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

/// The output's directory swapped during a source read, after the exclusions cached their directory proof (reads
/// share it until the next anchor change), is still refused before anything is written under it or anchored.
#[test]
fn output_directory_swap_during_a_read_is_refused_before_output_or_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let moved = dir.path().join("moved");
    let mut fixture = Fixture::new();
    let hook = fixture.volumes[0].as_ref().unwrap().hook.clone();
    let start = fixture.payloads[0].start;
    let (old, new) = (dest.clone(), moved.clone());
    let mut swapped = false;
    *hook.lock().unwrap() = Some(Box::new(move |_, at| {
        if at == start && !swapped {
            swapped = true;
            fs::rename(&old, &new).unwrap();
            fs::create_dir(&old).unwrap();
        }
        None
    }));
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&dir.path().join("state"));
    partial.anchors = anchors.clone();
    let mut session = ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dest), partial).unwrap();
    let (member, file) = next_partial(&mut session);
    let before = anchors.current(&member).unwrap();
    let mut failed = false;
    for _ in 0..10000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(_)) | Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { .. }))) => {
                failed = true;
                break;
            }
            Poll::Ready(Ok(None)) => break,
            _ => {}
        }
    }
    assert!(failed, "the swapped output directory was accepted");
    assert_eq!(anchors.current(&member).unwrap(), before, "nothing after the swap is anchored");
    assert!(fs::read(moved.join("a.bin")).unwrap().iter().all(|b| *b == 0), "no output written");
    assert!(!dest.join("a.bin").exists());
    drop(file);
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
        let verdict = verify(&mut file);
        // Verification commits the extraction's open group first; the anchor after it is the one finalization
        // must leave alone.
        let anchor = anchors.current(&key).unwrap().unwrap();
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
                    long_holes: false,
                    slow: false,
                    ticks: 0,
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
    extract_encrypted_with(dir, fixture, holes, PartialLimits::default())
}
fn extract_encrypted_with(
    dir: &Path,
    fixture: &Encrypted,
    holes: &[Range<u64>],
    limits: PartialLimits,
) -> EncryptedRun {
    let (provider, _) = fixture.provider(holes);
    let protection = provider.protection.clone();
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&dir.join("state"));
    partial.anchors = anchors.clone();
    partial.limits = limits;
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
    reopen_limited(dir, run, password, PartialLimits::default(), progressive_limits)
}
#[allow(clippy::result_large_err, reason = "the public partial error type")]
fn reopen_limited(
    dir: &Path,
    run: EncryptedRun,
    password: Option<&str>,
    limits: PartialLimits,
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
            limits,
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

/// How a growing provider answers a request for a volume its declaration does not name yet.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Grow {
    /// Declares the whole set while answering, then answers Ready.
    OnRequest,
    /// Answers Wait; the test extends the declaration and wakes the request.
    Wait,
    /// Answers Ready before declaring; the test extends the declaration and wakes the request.
    ReadyFirst,
}
/// What a growing provider declares: the first `count` volumes at `epoch`, plus any auxiliary paths.
struct Declared {
    epoch: u64,
    count: u32,
    names: Vec<OsString>,
    /// A native backing path per volume; None declares the volume NonFile.
    native: Vec<Option<ProtectedPath>>,
    auxiliary: Vec<ProtectedPath>,
}
impl Declared {
    fn declaration(&self) -> ProtectionDeclaration {
        ProtectionDeclaration::Complete {
            epoch: self.epoch,
            inventory: ProtectionInventory {
                volumes: (0..self.count)
                    .map(|index| ProtectedVolume {
                        index,
                        name: self.names[index as usize].clone(),
                        backing: match &self.native[index as usize] {
                            Some(path) => VolumeBacking::Native(vec![path.clone()]),
                            None => VolumeBacking::NonFile,
                        },
                    })
                    .collect(),
                auxiliary_paths: self.auxiliary.clone(),
            },
        }
    }
}
/// A change a growing provider applies to its declaration.
type Extension = Box<dyn FnOnce(&mut Declared) + Send>;
/// RustyGet's case: the set's size is known but not every final name, so volumes are declared as they become
/// known, each time with a higher epoch.
struct GrowingProvider {
    inner: Provider,
    declared: Arc<Mutex<Declared>>,
    grow: Grow,
    /// The extension `OnRequest` applies: the whole set at the next epoch, unless the test replaced it.
    extension: Option<Extension>,
    waker: Arc<Mutex<Option<Waker>>>,
    requests: Arc<Mutex<Vec<u32>>>,
    /// Whether it opts in to a growing declaration.
    extends: bool,
}
impl VolumeSource for GrowingProvider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.declared.lock().unwrap().declaration())
    }
    fn extends_protection(&self) -> bool {
        self.extends
    }
    fn volume(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        self.requests.lock().unwrap().push(request.index);
        let declared = self.declared.lock().unwrap().count > request.index;
        if !declared {
            match self.grow {
                Grow::OnRequest => {
                    let extend = self.extension.take().expect("one extension");
                    extend(&mut self.declared.lock().unwrap());
                }
                Grow::Wait => {
                    *self.waker.lock().unwrap() = Some(cx.waker().clone());
                    return Ok(VolumeAnswer::Wait);
                }
                Grow::ReadyFirst => *self.waker.lock().unwrap() = Some(cx.waker().clone()),
            }
        }
        self.inner.volume(request, cx)
    }
}
struct Growing {
    fixture: Fixture,
    declared: Arc<Mutex<Declared>>,
    waker: Arc<Mutex<Option<Waker>>>,
    requests: Arc<Mutex<Vec<u32>>>,
}
impl Growing {
    fn new() -> Self {
        let declared = Declared {
            epoch: 1,
            count: 5,
            names: (0..10).map(volume_name).collect(),
            native: vec![None; 10],
            auxiliary: Vec::new(),
        };
        Self {
            fixture: Fixture::new(),
            declared: Arc::new(Mutex::new(declared)),
            waker: Arc::default(),
            requests: Arc::default(),
        }
    }
    fn provider(&mut self, grow: Grow) -> GrowingProvider {
        self.provider_with(grow, |declared| {
            declared.epoch += 1;
            declared.count = 10;
        })
    }
    fn provider_with(&mut self, grow: Grow, extend: impl FnOnce(&mut Declared) + Send + 'static) -> GrowingProvider {
        GrowingProvider {
            inner: self.fixture.provider(),
            declared: self.declared.clone(),
            grow,
            extension: Some(Box::new(extend)),
            waker: self.waker.clone(),
            requests: self.requests.clone(),
            extends: true,
        }
    }
    /// The whole set at epoch 2, as the extension declares it.
    fn extended(&self) -> ProtectionDeclaration {
        let declared = self.declared.lock().unwrap();
        Declared {
            epoch: 2,
            count: 10,
            names: declared.names.clone(),
            native: declared.native.clone(),
            auxiliary: declared.auxiliary.clone(),
        }
        .declaration()
    }
}
/// Polls up to `polls` times, collecting handles and holes. Returns the session's end, or None if still running.
fn drive(
    session: &mut ProgressiveSession,
    files: &mut Vec<(MemberKey, PartialFile)>,
    polls: usize,
) -> Option<Result<(), ProgressiveFailure>> {
    for _ in 0..polls {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                let file = session.partial_file(&member).unwrap();
                files.push((member, file));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => return Some(Err(failure)),
            Poll::Ready(Ok(None)) => return Some(Ok(())),
            Poll::Ready(Err(e)) => return Some(Err(e)),
            _ => {}
        }
    }
    None
}
/// Fills both fixture members' missing articles and checks each verifies Ok with the expected bytes.
fn fill_and_verify(fixture: &Fixture, dest: &Path, files: &mut [(MemberKey, PartialFile)]) {
    assert_eq!(files.len(), 2);
    for ((_, file), (member, hole, name)) in
        files.iter_mut().zip([(0, 1300..2000u64, "a.bin"), (1, 3500..4200, "b.bin")])
    {
        assert_eq!(file.remaining().unwrap(), vec![hole.clone()]);
        file.fill(hole.start, &fixture.data[member][hole.start as usize..hole.end as usize]).unwrap();
        assert!(matches!(verify(file), Verdict::Ok { .. }));
        assert_eq!(fs::read(dest.join(name)).unwrap(), fixture.data[member]);
    }
}

#[test]
fn persistent_session_declares_later_volumes_with_a_higher_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let mut growing = Growing::new();
    let provider = growing.provider(Grow::OnRequest);
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial_options(&dir.path().join("state")))
            .unwrap();
    let mut files = Vec::new();
    assert!(matches!(drive(&mut session, &mut files, 100_000), Some(Ok(()))));
    // Volume 5 was requested once, under the five-volume declaration, which it then extended.
    assert_eq!(*growing.requests.lock().unwrap(), (0..10).collect::<Vec<_>>());
    assert_eq!(growing.declared.lock().unwrap().epoch, 2);
    fill_and_verify(&growing.fixture, &dest, &mut files);
}

#[test]
fn a_request_for_an_undeclared_volume_waits_until_the_declaration_names_it() {
    for grow in [Grow::Wait, Grow::ReadyFirst] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let mut growing = Growing::new();
        let provider = growing.provider(grow);
        let mut session = ProgressiveSession::new_partial(
            Box::new(provider),
            options(&dest),
            partial_options(&dir.path().join("state")),
        )
        .unwrap();
        let mut files = Vec::new();
        // The session reaches volume 5 and waits there without failing, however often it is polled.
        assert!(drive(&mut session, &mut files, 20_000).is_none(), "the session must wait, not end");
        assert_eq!(growing.requests.lock().unwrap().last(), Some(&5));
        let requests = growing.requests.lock().unwrap().len();
        assert!(drive(&mut session, &mut files, 1000).is_none());
        assert_eq!(growing.requests.lock().unwrap().len(), requests, "a parked request is not asked again unwoken");
        assert_eq!(files.len(), 1, "only a.bin, on volumes 0-4, has started");
        // A wake without a larger declaration keeps it waiting.
        growing.waker.lock().unwrap().as_ref().unwrap().wake_by_ref();
        assert!(drive(&mut session, &mut files, 1000).is_none());
        if grow == Grow::Wait {
            assert_eq!(growing.requests.lock().unwrap().len(), requests + 1, "the woken request is asked again");
        } else {
            assert_eq!(growing.requests.lock().unwrap().len(), requests, "the held source is not asked for again");
        }
        {
            let mut declared = growing.declared.lock().unwrap();
            declared.epoch = 2;
            declared.count = 10;
        }
        growing.waker.lock().unwrap().as_ref().unwrap().wake_by_ref();
        assert!(matches!(drive(&mut session, &mut files, 100_000), Some(Ok(()))));
        fill_and_verify(&growing.fixture, &dest, &mut files);
    }
}

#[test]
fn an_extension_that_changes_or_shrinks_the_declaration_is_refused() {
    type Change = fn(&mut Declared);
    let changes: [(&str, Change); 4] = [
        ("renamed volume", |d| {
            d.epoch += 1;
            d.count = 10;
            d.names[2] = "renamed.part03.rar".into();
        }),
        ("same epoch", |d| d.count = 10),
        ("lower epoch", |d| {
            d.epoch -= 1;
            d.count = 10;
        }),
        ("shrunk", |d| {
            d.epoch += 1;
            d.count = 4;
        }),
    ];
    for (what, change) in changes {
        let dir = tempfile::tempdir().unwrap();
        let mut growing = Growing::new();
        let provider = growing.provider_with(Grow::OnRequest, change);
        let mut session = ProgressiveSession::new_partial(
            Box::new(provider),
            options(&dir.path().join("out")),
            partial_options(&dir.path().join("state")),
        )
        .unwrap();
        let mut files = Vec::new();
        let Some(Err(failure)) = drive(&mut session, &mut files, 100_000) else { panic!("{what}: must be refused") };
        assert!(matches!(failure.kind, FailureKind::SourceChanged), "{what}: {failure:?}");
        // The member created under the first declaration keeps working.
        let (_, a) = &mut files[0];
        a.fill(1300, &growing.fixture.data[0][1300..2000]).unwrap();
        assert!(matches!(verify(a), Verdict::Ok { .. }), "{what}");
    }
}

#[test]
fn an_extension_may_not_declare_an_existing_partial_output() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let output = std::path::absolute(dest.join("a.bin")).unwrap();
    let mut growing = Growing::new();
    let provider = growing.provider_with(Grow::OnRequest, move |d| {
        d.epoch += 1;
        d.count = 10;
        d.auxiliary.push(ProtectedPath { path: output, file: None });
    });
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial_options(&dir.path().join("state")))
            .unwrap();
    let mut files = Vec::new();
    let Some(Err(failure)) = drive(&mut session, &mut files, 100_000) else {
        panic!("an output alias must be refused")
    };
    assert!(matches!(failure.kind, FailureKind::UnsafePath), "{failure:?}");
    assert_eq!(files.len(), 1);
}

#[test]
fn members_reopen_and_repair_under_the_extended_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state_root = dir.path().join("state");
    let mut growing = Growing::new();
    let volumes = volume_bytes(&growing.fixture);
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&state_root);
    partial.anchors = anchors.clone();
    let mut session =
        ProgressiveSession::new_partial(Box::new(growing.provider(Grow::OnRequest)), options(&dest), partial).unwrap();
    let mut files = Vec::new();
    assert!(matches!(drive(&mut session, &mut files, 100_000), Some(Ok(()))));
    // a.bin was created under the five-volume declaration, b.bin under the extended one; both stay live in the
    // session after the extension.
    let p6 = growing.fixture.payloads[6].start;
    let receipt = session.declare_hole(6, p6..p6 + 100).unwrap();
    assert_eq!(receipt.holes.len(), 1);
    drop(session);
    let extended = growing.extended();
    let mut reopened = Vec::new();
    for (key, file) in files {
        let state = partial_state::roundtrip(&file.close().unwrap());
        let expected_anchor = anchors.current(&key).unwrap().unwrap();
        let file = PartialFile::open(
            state,
            PartialOpenContext {
                output_root: dest.clone(),
                state_root: state_root.clone(),
                expected_member: key.clone(),
                expected_anchor,
                protection: extended.clone(),
                limits: PartialLimits::default(),
                progressive_limits: ProgressiveLimits::default(),
                anchors: anchors.clone(),
                control: SessionControl::default(),
                password: None,
            },
        )
        .unwrap();
        reopened.push((key, file));
    }
    let (_, b) = &mut reopened[1];
    assert_eq!(b.remaining().unwrap(), vec![1400..1500, 3500..4200]);
    // b.bin's declared damage on volume 6 comes back from archive bytes; its missing article from plaintext.
    let packed = b.fill_packed(6, 0, &volumes[6]).unwrap();
    assert_eq!(packed.applied, vec![1400..1500]);
    fill_and_verify(&growing.fixture, &dest, &mut reopened);
}

#[test]
fn a_frozen_declaration_is_unchanged_outside_persistent_sessions() {
    // An ordinary session keeps today's contract: a Complete declaration never grows, and a volume it does not
    // name is a contract failure.
    let dir = tempfile::tempdir().unwrap();
    let mut growing = Growing::new();
    let mut session =
        ProgressiveSession::new(Box::new(growing.provider(Grow::OnRequest)), options(&dir.path().join("out"))).unwrap();
    let failure = loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) | Poll::Ready(Err(failure)) => {
                break failure;
            }
            Poll::Ready(Ok(None)) => panic!("an undeclared volume must not be admitted"),
            _ => {}
        }
    };
    assert!(matches!(failure.kind, FailureKind::SourceContract), "{failure:?}");
    assert_eq!(growing.requests.lock().unwrap().last(), Some(&5));
}

#[test]
fn appended_native_paths_bind_beside_the_old_ones_and_protect_later_outputs() {
    // Old bindings keep their identities when appended paths sort before them: the set completes.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let inputs = std::path::absolute(dir.path().join("inputs")).unwrap();
    fs::create_dir(&inputs).unwrap();
    // Existing native paths are declared with their open handles.
    let held = |name: &str| {
        let path = inputs.join(name);
        fs::write(&path, name).unwrap();
        ProtectedPath { file: Some(Arc::new(File::open(&path).unwrap())), path }
    };
    let mut growing = Growing::new();
    growing.declared.lock().unwrap().auxiliary.push(held("m-aux"));
    let first = held("a-aux");
    let volumes: Vec<_> = (5..10).map(|index| held(&format!("v{index}"))).collect();
    let provider = growing.provider_with(Grow::OnRequest, move |d| {
        d.epoch += 1;
        d.count = 10;
        d.auxiliary.insert(0, first);
        for (index, path) in (5..10).zip(volumes) {
            d.native[index] = Some(path);
        }
    });
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial_options(&dir.path().join("state")))
            .unwrap();
    let mut files = Vec::new();
    assert!(matches!(drive(&mut session, &mut files, 100_000), Some(Ok(()))));
    fill_and_verify(&growing.fixture, &dest, &mut files);

    // An appended native path is protected like a first-epoch one: b.bin may not be created over it.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let target = std::path::absolute(dest.join("b.bin")).unwrap();
    let mut growing = Growing::new();
    let provider = growing.provider_with(Grow::OnRequest, move |d| {
        d.epoch += 1;
        d.count = 10;
        d.native[6] = Some(ProtectedPath { path: target, file: None });
    });
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial_options(&dir.path().join("state")))
            .unwrap();
    let mut files = Vec::new();
    let Some(Err(failure)) = drive(&mut session, &mut files, 100_000) else { panic!("b.bin must be refused") };
    // Refused while preparing b.bin's genesis, so the guard's failure arrives inside the partial error.
    assert!(
        matches!(&failure.kind, FailureKind::Partial(e)
            if matches!(&e.kind, PartialErrorKind::Progressive(e) if matches!(e.kind, FailureKind::UnsafePath))),
        "{failure:?}"
    );
    assert_eq!(files.len(), 1);
    assert!(!dest.join("b.bin").exists());
}

#[test]
fn a_persistent_provider_that_does_not_opt_in_keeps_a_frozen_declaration() {
    // Without `extends_protection`, a persistent session keeps the frozen contract exactly: an undeclared volume
    // answered Ready fails at once instead of being held, and an extension is not accepted.
    for grow in [Grow::OnRequest, Grow::ReadyFirst] {
        let dir = tempfile::tempdir().unwrap();
        let mut growing = Growing::new();
        let mut provider = growing.provider(grow);
        provider.extends = false;
        let mut session = ProgressiveSession::new_partial(
            Box::new(provider),
            options(&dir.path().join("out")),
            partial_options(&dir.path().join("state")),
        )
        .unwrap();
        let mut files = Vec::new();
        let Some(Err(failure)) = drive(&mut session, &mut files, 100_000) else {
            panic!("{grow:?}: an undeclared volume must fail, not wait")
        };
        assert!(matches!(failure.kind, FailureKind::SourceContract), "{grow:?}: {failure:?}");
        assert_eq!(growing.requests.lock().unwrap().last(), Some(&5));
        assert_eq!(files.len(), 1);
    }
}

/// Declares every volume at epoch 1. Once volume 5 is requested, the `at`th declaration read after it grows to
/// epoch 2 and declares `auxiliary`.
struct LateAuxiliary {
    inner: Provider,
    declared: Declared,
    auxiliary: Option<ProtectedPath>,
    at: usize,
    reads: Arc<std::sync::atomic::AtomicUsize>,
    armed: bool,
}
impl VolumeSource for LateAuxiliary {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        if self.armed && self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.at {
            self.declared.epoch = 2;
            self.declared.auxiliary.push(self.auxiliary.take().unwrap());
        }
        Ok(self.declared.declaration())
    }
    fn extends_protection(&self) -> bool {
        true
    }
    fn volume(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        self.armed |= request.index == 5;
        self.inner.volume(request, cx)
    }
}

#[test]
fn an_extension_while_a_member_is_created_cannot_declare_its_output() {
    // Whichever declaration read the extension lands on, b.bin is never handed out live at a path a declaration
    // already named when it was created: either its creation is refused, or the extension comes after it and is
    // refused itself.
    let mut refused_creation = false;
    for at in 1.. {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let mut fixture = Fixture::new();
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = LateAuxiliary {
            inner: fixture.provider(),
            declared: Declared {
                epoch: 1,
                count: 10,
                names: (0..10).map(volume_name).collect(),
                native: vec![None; 10],
                auxiliary: Vec::new(),
            },
            auxiliary: Some(ProtectedPath { path: std::path::absolute(dest.join("b.bin")).unwrap(), file: None }),
            at,
            reads: reads.clone(),
            armed: false,
        };
        let mut session = ProgressiveSession::new_partial(
            Box::new(provider),
            options(&dest),
            partial_options(&dir.path().join("state")),
        )
        .unwrap();
        let mut files = Vec::new();
        let mut ready_at = None;
        let failure = loop {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                    if !files.is_empty() {
                        ready_at = Some(reads.load(std::sync::atomic::Ordering::SeqCst));
                    }
                    files.push((member.clone(), session.partial_file(&member).unwrap()));
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. })))
                | Poll::Ready(Err(failure)) => break Some(failure),
                Poll::Ready(Ok(None)) => break None,
                _ => {}
            }
        };
        let Some(failure) = failure else {
            // Fewer than `at` reads followed volume 5's request, so the extension never landed: every read is done.
            assert!(reads.load(std::sync::atomic::Ordering::SeqCst) < at, "at {at}: the extension must be refused");
            assert!(at > 1);
            break;
        };
        let unsafe_path = matches!(&failure.kind, FailureKind::UnsafePath)
            || matches!(&failure.kind, FailureKind::Partial(e)
                if matches!(&e.kind, PartialErrorKind::Progressive(e) if matches!(e.kind, FailureKind::UnsafePath)));
        match ready_at {
            Some(reads) => assert!(reads < at, "at {at}: b.bin was handed out after read {at} declared it"),
            None => {
                refused_creation = true;
                assert_eq!(files.len(), 1, "at {at}");
            }
        }
        assert!(unsafe_path, "at {at}: {failure:?}");
    }
    assert!(refused_creation, "some read must land while b.bin is being created");
}

#[test]
fn an_extension_may_not_declare_a_state_bundle_through_a_symlinked_directory() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&state, &alias).unwrap();
    let mut growing = Growing::new();
    let state_dir = state.clone();
    let provider = growing.provider_with(Grow::OnRequest, move |d| {
        // a.bin's bundle exists by now; name a file inside it through the alias.
        let bundle = fs::read_dir(&state_dir)
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.file_type().unwrap().is_dir())
            .expect("a.bin's state bundle")
            .file_name();
        d.epoch += 1;
        d.count = 10;
        d.auxiliary
            .push(ProtectedPath { path: std::path::absolute(alias.join(bundle).join("journal")).unwrap(), file: None });
    });
    let mut session =
        ProgressiveSession::new_partial(Box::new(provider), options(&dir.path().join("out")), partial_options(&state))
            .unwrap();
    let mut files = Vec::new();
    let Some(Err(failure)) = drive(&mut session, &mut files, 100_000) else { panic!("a bundle alias must be refused") };
    assert!(matches!(failure.kind, FailureKind::UnsafePath), "{failure:?}");
    assert_eq!(files.len(), 1);
}

#[test]
fn an_unrelated_extension_while_a_member_is_created_is_accepted() {
    // Creation prepares again under the grown declaration instead of failing, wherever the extension lands.
    for at in 1..=12 {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let mut fixture = Fixture::new();
        let provider = LateAuxiliary {
            inner: fixture.provider(),
            declared: Declared {
                epoch: 1,
                count: 10,
                names: (0..10).map(volume_name).collect(),
                native: vec![None; 10],
                auxiliary: Vec::new(),
            },
            auxiliary: Some(ProtectedPath {
                path: std::path::absolute(dir.path().join("elsewhere.par2")).unwrap(),
                file: None,
            }),
            at,
            reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            armed: false,
        };
        let mut session = ProgressiveSession::new_partial(
            Box::new(provider),
            options(&dest),
            partial_options(&dir.path().join("state")),
        )
        .unwrap();
        let mut files = Vec::new();
        assert!(matches!(drive(&mut session, &mut files, 100_000), Some(Ok(()))), "at {at}");
        fill_and_verify(&fixture, &dest, &mut files);
    }
}

/// One stored member over `volumes` in-memory volumes, declared Complete NonFile.
struct Spanning {
    volumes: Vec<Option<Vec<u8>>>,
}
struct SpanningSource {
    index: u32,
    bytes: Vec<u8>,
}
impl RangeSource for SpanningSource {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.index as u128 + 1),
            generation: 0,
            extent: self.bytes.len() as u64,
            length: SourceLength::Final(self.bytes.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let end = (at as usize + buf.len()).min(self.bytes.len());
        buf[..end - at as usize].copy_from_slice(&self.bytes[at as usize..end]);
        Ok(RangeRead::Filled { count: end - at as usize })
    }
}
impl VolumeSource for Spanning {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..self.volumes.len() as u32)
                    .map(|index| ProtectedVolume { index, name: volume_name(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        })
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        assert_eq!(request.expected, volume_name(request.index));
        let bytes = self.volumes[request.index as usize].take().expect("each volume is opened once");
        Ok(VolumeAnswer::Ready(Box::new(SpanningSource { index: request.index, bytes })))
    }
}
#[test]
fn long_persistent_extraction_fits_default_limits() {
    // Every write commits a state transaction. Scratch copies of the state and
    // ledger, the overlap compare buffer, journal file names and exclusions
    // used to be charged for good, and each new part re-combined every earlier
    // part's CRC, so MetadataBytes, ProtectionPathBytes (hard 1 MiB cap) and
    // VerifyWorkBytes grew with commits until a long member failed. Small
    // chunks make this run commit about 640 times, well past the old
    // ProtectionPathBytes failure (about 450 commits), with default limits.
    const CHUNK: usize = 4096;
    let data: Vec<u8> = (0..5 << 19).map(|i: usize| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let volumes = common::volumes(&common::FileSpec::new("big.bin", &data), data.len() / 8);
    assert_eq!(volumes.len(), 8);
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let mut opts = options(&dest);
    opts.limits.read_chunk = CHUNK as u64;
    let mut partial = partial_options(&dir.path().join("state"));
    partial.limits.fill_bytes = CHUNK as u32;
    let mut session = ProgressiveSession::new_partial(
        Box::new(Spanning { volumes: volumes.into_iter().map(Some).collect() }),
        opts,
        partial,
    )
    .unwrap();
    let (holes, mut files) = run_to_end(&mut session);
    assert!(holes.is_empty());
    assert_eq!(files.len(), 1);
    assert!(matches!(verify(&mut files[0]), Verdict::Ok { .. }));
    assert_eq!(fs::read(dest.join("big.bin")).unwrap(), data);
}

// Catches written output that stays uncommitted while the session waits on a slow provider: once the open group
// is older than `group_commit_interval`, the session commits it before waiting again.
#[test]
fn provider_wait_commits_a_group_older_than_the_interval() {
    let dir = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::new();
    for source in fixture.volumes.iter_mut().flatten() {
        source.holes.clear();
    }
    let gate = Arc::new(WaitGate::default());
    fixture.volumes[2].as_mut().unwrap().wait = Some((fixture.payloads[2].start, gate.clone()));
    let anchors = Arc::new(Anchors::default());
    let mut partial = partial_options(&dir.path().join("state"));
    partial.anchors = anchors.clone();
    partial.limits.group_commit_interval = std::time::Duration::from_millis(200);
    let mut session =
        ProgressiveSession::new_partial(Box::new(fixture.provider()), options(&dir.path().join("out")), partial)
            .unwrap();
    let (key, file) = next_partial(&mut session);
    let started = std::time::Instant::now();
    while session.poll_event(&mut Context::from_waker(Waker::noop())).is_ready() {}
    assert!(gate.0.lock().unwrap().is_some(), "the session waits at volume 3");
    // Two parts are written into the open group; only its intent is anchored.
    let open = anchors.current(&key).unwrap().unwrap();
    if started.elapsed() < std::time::Duration::from_millis(200) {
        assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_eq!(anchors.current(&key).unwrap().unwrap(), open, "a young group stays open while waiting");
    }
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
    let committed = anchors.current(&key).unwrap().unwrap();
    assert_eq!(committed.sequence(), open.sequence() + 1, "the wait committed the group");
    assert_eq!(file.state().unwrap().anchor(), &committed);
    assert_eq!(file.remaining().unwrap(), vec![2800..7000]);
    gate.0.lock().unwrap().take().unwrap().wake();
    let (_, _) = run_to_end(&mut session);
    assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), fixture.data[0]);
}

// Restart resume: a new persistent session over the same roots and anchor store adopts the members an earlier
// session created, skips the finished ones without reading their data, and continues the member that was
// mid-extraction from its committed `produced`.

/// What a session reported, in event order.
#[derive(Default)]
struct Seen {
    /// Adopted members: (member, committed produced, finished).
    adopted: Vec<(MemberKey, u64, bool)>,
    /// Handles of every member created or adopted.
    files: Vec<(MemberKey, PartialFile)>,
    holes: Vec<HoleReport>,
    /// (member ordinal, outcome) of each finished member.
    outcomes: Vec<(u64, MemberOutcome)>,
    /// `logical_end` of the last `BytesWritten` of the newest member.
    written: u64,
    events: usize,
}
/// Polls until the session ends (true) or `stop` events were delivered (false). Panics on a failure.
fn run_events(session: &mut ProgressiveSession, seen: &mut Seen, stop: Option<usize>) -> bool {
    for _ in 0..1_000_000 {
        if stop.is_some_and(|stop| seen.events >= stop) {
            return false;
        }
        let event = match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => continue,
            Poll::Ready(Ok(None)) => return true,
            Poll::Ready(Ok(Some(event))) => event,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
        };
        seen.events += 1;
        match event {
            ProgressiveEvent::PartialReady { member, .. } => {
                seen.written = 0;
                seen.files.push((member.clone(), session.partial_file(&member).unwrap()));
            }
            ProgressiveEvent::PartialAdopted { member, produced, finished, .. } => {
                seen.written = produced;
                seen.files.push((member.clone(), session.partial_file(&member).unwrap()));
                seen.adopted.push((member, produced, finished));
            }
            ProgressiveEvent::BytesWritten { logical_end, .. } => seen.written = logical_end,
            ProgressiveEvent::Hole(report) => seen.holes.push(report),
            ProgressiveEvent::MemberFinished { outcome, .. } => {
                let ordinal = seen.files.last().unwrap().0.ordinal();
                seen.outcomes.push((ordinal, outcome));
            }
            ProgressiveEvent::SessionTerminated { failure, .. } => panic!("{failure:?}"),
            _ => {}
        }
    }
    panic!("session did not finish")
}
/// Polls until one more event was delivered; false while the session runs.
fn step(session: &mut ProgressiveSession, seen: &mut Seen) -> bool {
    let stop = seen.events + 1;
    run_events(session, seen, Some(stop))
}
/// The first failure of a session, as its partial error kind.
fn run_failure(session: &mut ProgressiveSession) -> PartialErrorKind {
    for _ in 0..1_000_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(failure)) | Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                return match failure.kind {
                    FailureKind::Partial(error) => error.kind,
                    other => panic!("{other:?}"),
                };
            }
            Poll::Ready(Ok(None)) => panic!("the session finished"),
            _ => {}
        }
    }
    panic!("session did not fail")
}
/// Drops `value` as a crash leaves it: an open group is not committed, so output written after its intent is not
/// claimed by the anchored state. (Drop skips that commit while the thread unwinds.)
fn crash<T>(value: T) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = value;
        std::panic::resume_unwind(Box::new("simulated crash"));
    }));
}
/// The ten-volume, two-member fixture with every byte available.
fn whole_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    for source in fixture.volumes.iter_mut().flatten() {
        source.holes.clear();
    }
    fixture
}
/// A session over `fixture` with 512-byte reads; `group` is `group_commit_bytes` (0 commits every write).
fn resume_session(fixture: &mut Fixture, dir: &Path, anchors: &Arc<Anchors>, group: u64) -> ProgressiveSession {
    let mut opts = options(&dir.join("out"));
    opts.limits.read_chunk = 512;
    let mut partial = partial_options(&dir.join("state"));
    partial.anchors = anchors.clone();
    partial.limits.group_commit_bytes = group;
    ProgressiveSession::new_partial(Box::new(fixture.provider()), opts, partial).unwrap()
}
/// Output offset of a payload read of the plain fixture, and the member it belongs to.
fn payload_read(fixture: &Fixture, volume: u32, at: u64) -> Option<(u64, u64)> {
    let payload = &fixture.payloads[volume as usize];
    payload.contains(&at).then(|| (volume as u64 / 5, (volume as u64 % 5) * 1400 + (at - payload.start)))
}
fn assert_ok_outcomes(seen: &Seen, members: usize) {
    assert_eq!(seen.outcomes.len(), members);
    for (_, outcome) in &seen.outcomes {
        assert!(
            matches!(outcome, MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }),
            "{:?}",
            match outcome {
                MemberOutcome::PersistentComplete { verdict, .. } => format!("{verdict:?}"),
                _ => "not complete".into(),
            }
        );
    }
}

#[test]
fn restart_adopts_finished_members_and_resumes_the_mid_member_at_every_crash_point() {
    let total = {
        let dir = tempfile::tempdir().unwrap();
        let mut session = resume_session(&mut whole_fixture(), dir.path(), &Arc::default(), 0);
        let mut seen = Seen::default();
        assert!(run_events(&mut session, &mut seen, None));
        seen.events
    };
    let mut boundary = false;
    let mut inside = false;
    // Every commit syncs, so crash at every other event (at least one at a part boundary and inside a part).
    for crash_at in (1..total).step_by(2) {
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut session = resume_session(&mut whole_fixture(), dir.path(), &anchors, 0);
        let mut before = Seen::default();
        assert!(!run_events(&mut session, &mut before, Some(crash_at)));
        let finished_before: Vec<u64> = before.outcomes.iter().map(|(ordinal, _)| *ordinal).collect();
        let created: Vec<MemberKey> = before.files.iter().map(|(key, _)| key.clone()).collect();
        let written = before.written;
        crash((session, std::mem::take(&mut before.files)));

        let mut fixture = whole_fixture();
        let mut session = resume_session(&mut fixture, dir.path(), &anchors, 0);
        let mut after = Seen::default();
        assert!(run_events(&mut session, &mut after, None), "crash at {crash_at}");
        // A member whose `PartialReady` was not delivered yet may already exist: its genesis precedes the event.
        assert!((created.len()..=created.len() + 1).contains(&after.adopted.len()), "crash at {crash_at}");
        assert!(after.holes.is_empty());
        assert_ok_outcomes(&after, 2);
        for (member, name) in [(0, "a.bin"), (1, "b.bin")] {
            assert_eq!(fs::read(dir.path().join("out").join(name)).unwrap(), fixture.data[member]);
        }
        for (key, produced, finished) in &after.adopted {
            let ordinal = key.ordinal();
            if finished_before.contains(&ordinal) {
                assert!(*finished && *produced == 7000, "crash at {crash_at}");
            } else if !created.contains(key) {
                assert_eq!((*produced, *finished), (0, false), "crash at {crash_at}");
            } else {
                // Every write is committed (group_commit_bytes 0), so the newest member resumes where its last
                // write ended; it may already have committed its canonical finish.
                assert_eq!(*produced, written, "crash at {crash_at}");
                assert!(!*finished || written == 7000);
                boundary |= !finished && produced % 1400 == 0 && *produced > 0 && *produced < 7000;
                inside |= produced % 1400 != 0;
            }
            for &(volume, at, _) in fixture.reads.lock().unwrap().iter() {
                if let Some((member, out)) = payload_read(&fixture, volume, at)
                    && member == ordinal
                {
                    assert!(!finished, "a finished member's data is never read again (crash at {crash_at})");
                    assert!(out >= *produced, "read {out} below the resume point {produced} (crash at {crash_at})");
                }
            }
        }
        // Handles of adopted members verify Ok too.
        for (_, file) in &mut after.files {
            assert!(matches!(verify(file), Verdict::Ok { .. }));
        }
    }
    assert!(boundary && inside, "resumed both at a part boundary and inside a part");
}

#[test]
fn restart_re_extracts_an_uncommitted_group_tail_and_keeps_earlier_holes() {
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    // The holed fixture with grouped commits: a's hole 1300..2000 commits the group before it and then itself,
    // and the writes after it stay in an open group.
    let mut first = Fixture::new();
    let mut session = resume_session(&mut first, dir.path(), &anchors, 64 << 20);
    let mut before = Seen::default();
    while before.written < 3000 {
        assert!(!step(&mut session, &mut before));
    }
    assert!(!before.holes.is_empty() && before.holes.iter().all(|h| h.out.start >= 1300 && h.out.end <= 2000));
    let (key, _) = &before.files[0];
    let key = key.clone();
    crash((session, std::mem::take(&mut before.files)));
    // The written tail was never committed: the anchored state ends at the hole.
    let latest = anchors.current(&key).unwrap().unwrap();
    let state = PartialState::load(&dir.path().join("state"), &latest, &PartialLimits::default()).unwrap();
    let probe = PartialFile::open(
        state,
        PartialOpenContext {
            output_root: dir.path().join("out"),
            state_root: dir.path().join("state"),
            expected_member: key.clone(),
            expected_anchor: latest,
            protection: Fixture::new().provider().protection,
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors: anchors.clone(),
            control: SessionControl::default(),
            password: None,
        },
    )
    .unwrap();
    assert_eq!(probe.remaining().unwrap(), vec![1300..7000]);
    drop(probe.close().unwrap());

    let mut fixture = whole_fixture();
    let mut session = resume_session(&mut fixture, dir.path(), &anchors, 64 << 20);
    let mut after = Seen::default();
    assert!(run_events(&mut session, &mut after, None));
    assert_eq!(after.adopted, vec![(key.clone(), 2000, false)]);
    // The tail 2000..3000 was read and written again; nothing below the resume point was read.
    let reads = fixture.reads.lock().unwrap().clone();
    assert!(reads.iter().any(|&(v, at, _)| payload_read(&fixture, v, at) == Some((0, 2000))));
    assert!(reads.iter().all(|&(v, at, _)| payload_read(&fixture, v, at).is_none_or(|(m, out)| m != 0 || out >= 2000)));
    // The hole recorded before the crash stays a hole, and is filled afterwards.
    assert!(matches!(&after.outcomes[0].1, MemberOutcome::PersistentPartial { .. }));
    assert!(matches!(&after.outcomes[1].1, MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }));
    let (_, a) = after.files.iter_mut().find(|(k, _)| *k == key).unwrap();
    assert_eq!(a.remaining().unwrap(), vec![1300..2000]);
    assert!(matches!(verify(a), Verdict::Incomplete { .. }));
    a.fill(1300, &fixture.data[0][1300..2000]).unwrap();
    assert!(matches!(verify(a), Verdict::Ok { .. }));
    for (member, name) in [(0, "a.bin"), (1, "b.bin")] {
        assert_eq!(fs::read(dir.path().join("out").join(name)).unwrap(), fixture.data[member]);
    }
}

#[test]
fn a_crash_during_the_resumed_session_is_recoverable_too() {
    for (first, second) in [(5, 6), (9, 20), (20, 8)] {
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut session = resume_session(&mut whole_fixture(), dir.path(), &anchors, 0);
        let mut seen = Seen::default();
        assert!(!run_events(&mut session, &mut seen, Some(first)));
        crash((session, std::mem::take(&mut seen.files)));
        let mut session = resume_session(&mut whole_fixture(), dir.path(), &anchors, 0);
        let mut seen = Seen::default();
        assert!(!run_events(&mut session, &mut seen, Some(second)));
        assert!(!seen.adopted.is_empty());
        crash((session, std::mem::take(&mut seen.files)));
        let mut fixture = whole_fixture();
        let mut session = resume_session(&mut fixture, dir.path(), &anchors, 0);
        let mut seen = Seen::default();
        assert!(run_events(&mut session, &mut seen, None));
        assert_ok_outcomes(&seen, 2);
        for (member, name) in [(0, "a.bin"), (1, "b.bin")] {
            assert_eq!(fs::read(dir.path().join("out").join(name)).unwrap(), fixture.data[member]);
        }
    }
}

#[test]
fn adoption_refuses_a_different_archive_with_the_same_names_and_a_modified_output() {
    // Crash inside b, after a finished.
    let crashed = |dir: &Path, anchors: &Arc<Anchors>| {
        let mut session = resume_session(&mut whole_fixture(), dir, anchors, 0);
        let mut seen = Seen::default();
        while seen.outcomes.is_empty() || seen.written < 3000 {
            assert!(!step(&mut session, &mut seen));
        }
        crash((session, std::mem::take(&mut seen.files)));
    };
    // Another archive whose members have the same names (here a different modification time): its members are
    // other members, so the existing outputs are neither adopted nor overwritten.
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    crashed(dir.path(), &anchors);
    let a = fs::read(dir.path().join("out/a.bin")).unwrap();
    let mut other = Fixture::configured(|_, spec| spec.mtime = Some(12345));
    for source in other.volumes.iter_mut().flatten() {
        source.holes.clear();
    }
    let mut session = resume_session(&mut other, dir.path(), &anchors, 0);
    assert!(matches!(run_failure(&mut session), PartialErrorKind::AlreadyExists));
    drop(session);
    assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), a);
    // The same archive still resumes.
    let mut fixture = whole_fixture();
    let mut session = resume_session(&mut fixture, dir.path(), &anchors, 0);
    let mut seen = Seen::default();
    assert!(run_events(&mut session, &mut seen, None));
    assert_ok_outcomes(&seen, 2);

    // An output changed behind the store's back is refused at its adoption.
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    crashed(dir.path(), &anchors);
    let path = dir.path().join("out/a.bin");
    let mut bytes = fs::read(&path).unwrap();
    bytes[100] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let mut session = resume_session(&mut whole_fixture(), dir.path(), &anchors, 0);
    assert!(matches!(run_failure(&mut session), PartialErrorKind::OutputChanged));
    drop(session);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn restart_resumes_under_a_growing_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let anchors = Arc::new(Anchors::default());
    let start = |growing: &mut Growing| {
        for source in growing.fixture.volumes.iter_mut().flatten() {
            source.holes.clear();
        }
        let mut partial = partial_options(&dir.path().join("state"));
        partial.anchors = anchors.clone();
        partial.limits.group_commit_bytes = 0;
        ProgressiveSession::new_partial(Box::new(growing.provider(Grow::OnRequest)), options(&dest), partial).unwrap()
    };
    // The first session knows five volumes, crashes inside a, before the declaration grows.
    let mut growing = Growing::new();
    let mut session = start(&mut growing);
    let mut seen = Seen::default();
    while seen.written < 2800 {
        assert!(!step(&mut session, &mut seen));
    }
    crash((session, std::mem::take(&mut seen.files)));
    // The restarted provider again starts with the first five volumes and declares the rest when asked.
    let mut growing = Growing::new();
    let mut session = start(&mut growing);
    let mut seen = Seen::default();
    assert!(run_events(&mut session, &mut seen, None));
    assert_eq!(seen.adopted.len(), 1);
    assert!(seen.adopted[0].1 >= 2800);
    assert_eq!(growing.declared.lock().unwrap().epoch, 2);
    assert_ok_outcomes(&seen, 2);
    for (member, name) in [(0, "a.bin"), (1, "b.bin")] {
        assert_eq!(fs::read(dest.join(name)).unwrap(), growing.fixture.data[member]);
    }
}

#[test]
fn encrypted_restart_resumes_at_every_crash_point() {
    let fixture = Encrypted::new(3000, &CUTS, true);
    let session = |dir: &Path, anchors: &Arc<Anchors>| {
        let (provider, reads) = fixture.provider(&[]);
        let mut opts = options(&dir.join("out"));
        opts.set_password(Some("pw".into())).unwrap();
        // 16-byte reads put resume points everywhere, including just past a part boundary that cuts a block.
        opts.limits.read_chunk = 16;
        let mut partial = partial_options(&dir.join("state"));
        partial.anchors = anchors.clone();
        partial.limits.group_commit_bytes = 0;
        (ProgressiveSession::new_partial(Box::new(provider), opts, partial).unwrap(), reads)
    };
    let total = {
        let dir = tempfile::tempdir().unwrap();
        let (mut session, _) = session(dir.path(), &Arc::default());
        let mut seen = Seen::default();
        assert!(run_events(&mut session, &mut seen, None));
        seen.events
    };
    let mut straddled = false;
    // Every commit syncs; crash at a spread of points, and at every point near the part boundaries.
    for crash_at in (2..total).filter(|n| n % 11 == 0 || (60..72).contains(n) || (122..134).contains(n)) {
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let (mut first, _) = session(dir.path(), &anchors);
        let mut before = Seen::default();
        assert!(!run_events(&mut first, &mut before, Some(crash_at)));
        let written = before.written;
        crash((first, std::mem::take(&mut before.files)));
        let (mut second, reads) = session(dir.path(), &anchors);
        let mut after = Seen::default();
        assert!(run_events(&mut second, &mut after, None), "crash at {crash_at}");
        assert_eq!(after.adopted.len(), 1);
        let (_, produced, finished) = after.adopted[0].clone();
        assert_eq!(produced, written);
        assert_ok_outcomes(&after, 1);
        assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
        // Only the previous ciphertext block and the bytes after the resume point are read again.
        for &(volume, at, _) in reads.lock().unwrap().iter() {
            let payload = &fixture.payloads[volume as usize];
            if payload.contains(&at) {
                let stream = fixture.starts[volume as usize] + (at - payload.start);
                assert!(!finished && produced < 3000 && stream + 16 >= produced, "crash at {crash_at}");
            }
        }
        straddled |= CUTS.iter().any(|&cut| (produced as usize) > cut && (produced as usize) - 16 < cut);
        drop(second);
        let (_, mut file) = after.files.pop().unwrap();
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    }
    assert!(straddled, "a previous ciphertext block cut by a part boundary was read from two volumes");
}

#[test]
fn a_wrong_fill_before_the_crash_is_judged_by_verification_not_the_resumed_stream() {
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    // a's hole 1300..2000 is filled with one wrong byte, then the session dies inside a.
    let mut session = resume_session(&mut Fixture::new(), dir.path(), &anchors, 0);
    let mut seen = Seen::default();
    while seen.written < 3500 {
        assert!(!step(&mut session, &mut seen));
    }
    let mut fill = Fixture::new().data[0][1300..2000].to_vec();
    fill[10] ^= 1;
    seen.files[0].1.fill(1300, &fill).unwrap();
    crash((session, std::mem::take(&mut seen.files)));
    // The restart neither fails nor wedges: a verifies PartBad (the wrong byte is in part 0), b is extracted.
    for _ in 0..2 {
        let mut fixture = whole_fixture();
        let mut session = resume_session(&mut fixture, dir.path(), &anchors, 0);
        let mut seen = Seen::default();
        assert!(run_events(&mut session, &mut seen, None));
        assert_eq!(seen.outcomes.len(), 2);
        assert!(matches!(
            &seen.outcomes[0].1,
            MemberOutcome::PersistentComplete { verdict: Verdict::PartBad { part: 0, .. }, .. }
        ));
        assert!(matches!(&seen.outcomes[1].1, MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }));
        assert_eq!(fs::read(dir.path().join("out/b.bin")).unwrap(), fixture.data[1]);
    }
}

#[test]
fn damage_declared_on_bytes_the_resume_walk_skips_becomes_holes() {
    // Crash inside a (the declared bytes lie before its resume point) and inside b (a is finished).
    for (stop_in_b, written) in [(false, 3500), (true, 3500)] {
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut session = resume_session(&mut whole_fixture(), dir.path(), &anchors, 0);
        let mut seen = Seen::default();
        while (stop_in_b && seen.outcomes.is_empty()) || seen.written < written {
            assert!(!step(&mut session, &mut seen));
        }
        crash((session, std::mem::take(&mut seen.files)));
        let mut fixture = whole_fixture();
        let payload = fixture.payloads[1].clone();
        let mut session = resume_session(&mut fixture, dir.path(), &anchors, 0);
        let mut seen = Seen::default();
        assert!(!step(&mut session, &mut seen));
        // Volume 1 is not open yet: the damage is pending, and lies on a's part 1 (output 1410..1420).
        let receipt = session.declare_hole(1, payload.start + 10..payload.start + 20).unwrap();
        assert_eq!(receipt.pending.len(), 1);
        assert!(run_events(&mut session, &mut seen, None));
        let holes: Vec<_> = seen.holes.iter().map(|h| (h.out.clone(), h.cause.clone())).collect();
        assert_eq!(holes, vec![(1410..1420, HoleCause::DeclaredBad)], "stop in b: {stop_in_b}");
        assert!(matches!(&seen.outcomes[0].1, MemberOutcome::PersistentPartial { .. }));
        let (_, a) = seen.files.iter_mut().find(|(k, _)| k.ordinal() == 0).unwrap();
        assert_eq!(a.remaining().unwrap(), vec![1410..1420]);
        a.fill(1410, &fixture.data[0][1410..1420]).unwrap();
        assert!(matches!(verify(a), Verdict::Ok { .. }));
    }
}

#[test]
fn encrypted_damage_on_the_previous_ciphertext_block_makes_the_next_block_a_hole() {
    let fixture = Encrypted::new(3000, &CUTS, true);
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let session = |provider: Provider| {
        let mut opts = options(&dir.path().join("out"));
        opts.set_password(Some("pw".into())).unwrap();
        opts.limits.read_chunk = 16;
        let mut partial = partial_options(&dir.path().join("state"));
        partial.anchors = anchors.clone();
        partial.limits.group_commit_bytes = 0;
        ProgressiveSession::new_partial(Box::new(provider), opts, partial).unwrap()
    };
    // Crash at produced 1008: the block before it, 992..1008, is cut by the volume boundary at 1001.
    let mut first = session(fixture.provider(&[]).0);
    let mut seen = Seen::default();
    while seen.written < 1008 {
        assert!(!step(&mut first, &mut seen));
    }
    assert_eq!(seen.written, 1008);
    crash((first, std::mem::take(&mut seen.files)));
    // The restart reads 992..1001 from volume 0, then waits for volume 1's bytes 1001..1008.
    let (mut provider, _) = fixture.provider(&[]);
    let gate = Arc::new(WaitGate::default());
    provider.volumes[1].as_mut().unwrap().wait = Some((fixture.payloads[1].start, gate.clone()));
    let mut second = session(provider);
    let mut seen = Seen::default();
    for _ in 0..100_000 {
        if gate.0.lock().unwrap().is_some() {
            break;
        }
        if let Poll::Ready(Ok(Some(ProgressiveEvent::PartialAdopted { member, .. }))) =
            second.poll_event(&mut Context::from_waker(Waker::noop()))
        {
            seen.files.push((member.clone(), second.partial_file(&member).unwrap()));
        }
    }
    assert!(gate.0.lock().unwrap().is_some(), "waiting inside the previous block");
    // Damage on the half of the block already read.
    let piece = fixture.packed(992..1001);
    second.declare_hole(piece[0].0, piece[0].1.clone()).unwrap();
    gate.0.lock().unwrap().take().unwrap().wake();
    assert!(run_events(&mut second, &mut seen, None));
    let (_, file) = seen.files.last_mut().unwrap();
    let remaining = file.remaining().unwrap();
    assert!(remaining.iter().any(|r| r.start <= 1008 && 1024 <= r.end), "{remaining:?}");
    fill_plain(file, &fixture);
    assert!(matches!(verify(file), Verdict::Ok { .. }));
}

#[test]
fn encrypted_damage_declared_before_polling_on_the_previous_block_is_a_declared_hole() {
    let fixture = Encrypted::new(3000, &CUTS, true);
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let session = |provider: Provider| {
        let mut opts = options(&dir.path().join("out"));
        opts.set_password(Some("pw".into())).unwrap();
        opts.limits.read_chunk = 16;
        let mut partial = partial_options(&dir.path().join("state"));
        partial.anchors = anchors.clone();
        partial.limits.group_commit_bytes = 0;
        ProgressiveSession::new_partial(Box::new(provider), opts, partial).unwrap()
    };
    let mut first = session(fixture.provider(&[]).0);
    let mut seen = Seen::default();
    while seen.written < 400 {
        assert!(!step(&mut first, &mut seen));
    }
    assert_eq!(seen.written, 400);
    crash((first, std::mem::take(&mut seen.files)));
    // Before the restart reads anything, damage on ciphertext 384..388: the block the resume reads for its CBC
    // state, from which the earlier session decrypted output 384..400.
    let mut second = session(fixture.provider(&[]).0);
    let piece = fixture.packed(384..388);
    let receipt = second.declare_hole(piece[0].0, piece[0].1.clone()).unwrap();
    assert_eq!(receipt.pending.len(), 1);
    let mut seen = Seen::default();
    assert!(run_events(&mut second, &mut seen, None));
    assert_eq!(joined(&seen.holes), vec![(384..400, HoleCause::DeclaredBad), (400..416, HoleCause::CipherNeighbour)]);
    let (_, file) = seen.files.last_mut().unwrap();
    assert_eq!(file.remaining().unwrap(), vec![384..416]);
    fill_plain(file, &fixture);
    assert!(matches!(verify(file), Verdict::Ok { .. }));
}

/// RustyGet's case on RAR 5.0: a stored member whose middle volume's whole data area (110 MiB) is answered as
/// holes, one read buffer per Hole. The session finishes within the default limits, each hole costs a small fixed
/// amount of metadata however much output came before it, and a refill from the repaired volume verifies.
#[test]
fn a_rar5_volume_answered_entirely_as_holes_stays_within_default_limits_and_refills() {
    const MIB: usize = 1 << 20;
    let data: Vec<u8> = (0..127 * MIB).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let bounds = [0, 16 * MIB, 126 * MIB, 127 * MIB];
    let reads = Arc::new(Mutex::new(Vec::new()));
    let (mut volumes, mut bytes_of, mut payloads) = (Vec::new(), Vec::new(), Vec::new());
    for index in 0..3 {
        let out = bounds[index]..bounds[index + 1];
        let last = index == 2;
        let spec = common::FileSpec::new("big.bin", &data);
        let scope = if last { data.as_slice() } else { &data[out.clone()] };
        let file = common::file_block(&spec, &data[out.clone()], crc32fast::hash(scope), index != 0, !last);
        let mut bytes = common::SIG.to_vec();
        bytes.extend(common::main_block(true, Some(index as u64)));
        let start = bytes.len() + file.len() - out.len();
        payloads.push(start as u64..(start + out.len()) as u64);
        bytes.extend(file);
        bytes.extend(common::end_block(!last));
        bytes_of.push(bytes.clone());
        volumes.push(Some(Source {
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            backing_hook: Arc::new(Mutex::new(None)),
            long_holes: false,
            slow: false,
            ticks: 0,
            index: index as u32,
            bytes,
            holes: if index == 1 { vec![payloads[1].clone()] } else { Vec::new() },
            reads: reads.clone(),
            backing: Vec::new(),
            hook: Arc::new(Mutex::new(None)),
            wait: None,
        }));
    }
    let provider = Provider {
        volumes,
        protection: ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..3)
                    .map(|index| ProtectedVolume { index, name: volume_name(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        },
        wait: None,
        calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        protection_hook: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut session = ProgressiveSession::new_partial(
        Box::new(provider),
        options(&dir.path().join("out")),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    let (mut holes, mut files, mut at_tenth, mut last) = (0usize, Vec::new(), 0, 0);
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(_)))) => {
                holes += 1;
                last = session.resource_usage(Resource::MetadataBytes).used;
                if holes == 10 {
                    at_tenth = last;
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    assert!(holes >= 100, "{holes} holes");
    let per_hole = (last - at_tenth) / (holes as u64 - 10);
    assert!(per_hole < 8 << 10, "{per_hole} metadata bytes per hole");
    let metadata = session.resource_usage(Resource::MetadataBytes);
    assert!(metadata.used < metadata.limit / 16, "{metadata:?}");
    let file = &mut files[0];
    assert_eq!(file.remaining().unwrap(), vec![16 * MIB as u64..126 * MIB as u64]);
    let mut reader = std::io::Cursor::new(bytes_of[1].clone());
    file.refill_from_packed(1, 0..bytes_of[1].len() as u64, &mut reader).unwrap();
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), data);
}

/// A RAR5 set (4, 40 and 1 MiB of output) whose middle volume's whole data area is a hole its source answers whole;
/// `slow` answers every other read `NotYet` first, and `declared` (relative to the dead data area) is declared with
/// `declare_hole` before the session reads it. Returns the `Hole` events, the handle, the dead volume's bytes, the
/// output and the session's directory.
fn long_hole_rar5(
    slow: bool,
    declared: Option<Range<u64>>,
) -> (Vec<HoleReport>, PartialFile, Vec<u8>, Range<u64>, Vec<u8>, tempfile::TempDir) {
    const MIB: usize = 1 << 20;
    let data: Vec<u8> = (0..45 * MIB).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let bounds = [0, 4 * MIB, 44 * MIB, 45 * MIB];
    let reads = Arc::new(Mutex::new(Vec::new()));
    let (mut volumes, mut bytes_of, mut payloads) = (Vec::new(), Vec::new(), Vec::new());
    for index in 0..3 {
        let out = bounds[index]..bounds[index + 1];
        let last = index == 2;
        let spec = common::FileSpec::new("big.bin", &data);
        let scope = if last { data.as_slice() } else { &data[out.clone()] };
        let file = common::file_block(&spec, &data[out.clone()], crc32fast::hash(scope), index != 0, !last);
        let mut bytes = common::SIG.to_vec();
        bytes.extend(common::main_block(true, Some(index as u64)));
        let start = bytes.len() + file.len() - out.len();
        payloads.push(start as u64..(start + out.len()) as u64);
        bytes.extend(file);
        bytes.extend(common::end_block(!last));
        bytes_of.push(bytes.clone());
        volumes.push(Some(Source {
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            backing_hook: Arc::new(Mutex::new(None)),
            long_holes: true,
            slow,
            ticks: 0,
            index: index as u32,
            bytes,
            holes: if index == 1 { vec![payloads[1].clone()] } else { Vec::new() },
            reads: reads.clone(),
            backing: Vec::new(),
            hook: Arc::new(Mutex::new(None)),
            wait: None,
        }));
    }
    let provider = Provider {
        volumes,
        protection: ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..3)
                    .map(|index| ProtectedVolume { index, name: volume_name(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        },
        wait: None,
        calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        protection_hook: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut session = ProgressiveSession::new_partial(
        Box::new(provider),
        options(&dir.path().join("out")),
        partial_options(&dir.path().join("state")),
    )
    .unwrap();
    if let Some(range) = declared {
        let p1 = payloads[1].start;
        session.declare_hole(1, p1 + range.start..p1 + range.end).unwrap();
    }
    let (mut holes, mut files) = (Vec::new(), Vec::new());
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => holes.push(report),
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    (holes, files.pop().unwrap(), bytes_of[1].clone(), payloads[1].clone(), data, dir)
}

/// RAR5, a fast and a slow (still downloading) source: the dead middle volume answered with one `Hole` is one
/// event, and refilling it in pieces verifies.
#[test]
fn a_rar5_dead_volume_answered_with_one_hole_is_one_event_and_refills_in_pieces() {
    for slow in [false, true] {
        let (holes, mut file, volume, payload, data, dir) = long_hole_rar5(slow, None);
        assert_eq!(holes.len(), 1, "slow {slow}: {holes:?}");
        assert_eq!(holes[0].packed, vec![PackedSpan { volume: 1, range: payload }], "slow {slow}");
        let mut at = 0;
        while at < volume.len() as u64 {
            let end = (at + (5 << 20)).min(volume.len() as u64);
            file.refill_from_packed(1, at..end, &mut std::io::Cursor::new(volume.as_slice())).unwrap();
            at = end;
        }
        assert!(file.remaining().unwrap().is_empty(), "slow {slow}");
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }), "slow {slow}");
        assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), data, "slow {slow}");
    }
}

/// Damage declared within one read buffer (1 MiB) of the cursor still lets the source answer the whole dead range:
/// the answer is trimmed at the declaration, not refused as a source contract violation.
#[test]
fn a_long_hole_stops_at_damage_declared_within_the_read_buffer() {
    let (holes, mut file, volume, payload, data, dir) = long_hole_rar5(false, Some((512 << 10)..(1536 << 10)));
    let causes: Vec<_> = holes.iter().map(|h| h.cause.clone()).collect();
    assert_eq!(causes, [HoleCause::Missing, HoleCause::DeclaredBad, HoleCause::Missing], "{holes:?}");
    let p = payload.start;
    let spans: Vec<_> = holes.iter().map(|h| h.packed[0].range.clone()).collect();
    assert_eq!(spans, [p..p + (512 << 10), p + (512 << 10)..p + (1536 << 10), p + (1536 << 10)..payload.end]);
    file.refill_from_packed(1, 0..volume.len() as u64, &mut std::io::Cursor::new(volume.as_slice())).unwrap();
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), data);
}

/// Damage declared inside the dead range splits the source's one answer: the hole is accepted up to the declared
/// range (the source cannot see it), the declared range is a `DeclaredBad` hole, and the rest is read again.
#[test]
fn a_long_hole_stops_at_damage_declared_inside_it() {
    let (holes, mut file, volume, payload, data, dir) = long_hole_rar5(false, Some((10 << 20)..(11 << 20)));
    let causes: Vec<_> = holes.iter().map(|h| h.cause.clone()).collect();
    assert_eq!(causes, [HoleCause::Missing, HoleCause::DeclaredBad, HoleCause::Missing], "{holes:?}");
    let p = payload.start;
    let spans: Vec<_> = holes.iter().map(|h| h.packed[0].range.clone()).collect();
    assert_eq!(spans, [p..p + (10 << 20), p + (10 << 20)..p + (11 << 20), p + (11 << 20)..payload.end]);
    file.refill_from_packed(1, 0..volume.len() as u64, &mut std::io::Cursor::new(volume.as_slice())).unwrap();
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), data);
}

/// Catches a grouped refill of an encrypted member paying a transaction per fill, and one losing the plaintext or
/// the kept ciphertext across a close and reopen. Both volumes refill in one open group, committed at close.
#[test]
fn encrypted_grouped_refills_share_one_commit_and_survive_a_reopen() {
    let fill_all = |limits: PartialLimits, dir: &Path| {
        let fixture = Encrypted::new(3000, &CUTS, true);
        let mut run = extract_encrypted_with(dir, &fixture, &[990..1010, 1500..1510], limits);
        let before = zipfast::partial::durable_sync_count_this_thread();
        for (volume, bytes) in fixture.volumes.iter().take(2).enumerate() {
            let mut reader = std::io::Cursor::new(bytes.clone());
            run.file.refill_from_packed(volume as u32, 0..bytes.len() as u64, &mut reader).unwrap();
        }
        (fixture, run, zipfast::partial::durable_sync_count_this_thread() - before)
    };
    let plain_dir = tempfile::tempdir().unwrap();
    let (_, _, plain_syncs) = fill_all(PartialLimits::default(), plain_dir.path());
    let dir = tempfile::tempdir().unwrap();
    let (fixture, run, grouped_syncs) =
        fill_all(PartialLimits { group_refills: true, ..PartialLimits::default() }, dir.path());
    assert!(grouped_syncs < plain_syncs, "grouped {grouped_syncs} syncs, ungrouped {plain_syncs}");
    let mut file = reopen(dir.path(), run, Some("pw")).unwrap();
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/e.bin")).unwrap(), fixture.plain);
}

/// Catches a grouped encrypted refill dropping the progress it already made: the plaintext is written (and the
/// group committed, `group_commit_bytes` being 1) before the ciphertext blocks a remaining hole needs are retained,
/// and a failure there (the interval limit) must still report what was applied, as `fill_packed` does.
#[test]
fn a_grouped_encrypted_refill_reports_progress_when_retaining_ciphertext_fails() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Encrypted::new(3000, &CUTS, true);
    let run = extract_encrypted_with(dir.path(), &fixture, &[990..1010, 1500..1510], PartialLimits::default());
    let limits = PartialLimits { group_refills: true, group_commit_bytes: 1, ..PartialLimits::default() };
    // enough intervals to reopen and plan the refill, too few to retain the blocks the refill leaves needed
    let tight = ProgressiveLimits { hole_intervals: 4, ..ProgressiveLimits::default() };
    let mut file = reopen_limited(dir.path(), run, Some("pw"), limits, tight).unwrap();
    let before = file.remaining().unwrap();
    let mut reader = std::io::Cursor::new(fixture.volumes[0].clone());
    let error = file.refill_from_packed(0, 0..fixture.volumes[0].len() as u64, &mut reader).unwrap_err();
    assert!(
        matches!(&error.kind, PartialErrorKind::Progressive(f) if matches!(f.kind, FailureKind::Limit { resource: Resource::HoleIntervals, .. })),
        "{error:?}"
    );
    let progress = error.packed_progress.expect("the plaintext written before the failure is reported");
    assert_eq!(progress.applied, vec![976..992]);
    // what was reported is what the output holds
    let after = file.remaining().unwrap();
    assert_ne!(before, after, "the refill wrote output");
    assert!(after.iter().all(|r| r.start >= 992 || r.end <= 976), "{after:?}");
    assert_eq!(&fs::read(dir.path().join("out/e.bin")).unwrap()[976..992], &fixture.plain[976..992]);
}
