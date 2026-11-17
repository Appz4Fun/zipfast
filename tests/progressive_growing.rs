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

//! `GrowingFileVolumes` over real files that the test creates and appends while a session runs.
#![cfg(unix)]
mod common;
use common::{FileSpec, SIG, end_block, file_block, main_block};
use std::{
    ffi::OsString,
    fs,
    io::Write,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    thread::Thread,
    time::{Duration, Instant},
};
use zipfast::progressive::*;

const NAMES: [&str; 3] = ["g.part1.rar", "g.part2.rar", "g.part3.rar"];

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// Three volumes: `first.bin` whole in volume 0, `big.bin` split over all three, and `last.bin` in volume 2.
struct Set {
    volumes: Vec<Vec<u8>>,
    members: Vec<(&'static str, Vec<u8>)>,
}
fn set() -> Set {
    let first = payload(1, 3000);
    let big = payload(2, 9000);
    let last = payload(3, 2000);
    let parts = [&big[..3000], &big[3000..6000], &big[6000..]];
    let mut volumes = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let mut out = SIG.to_vec();
        out.extend(main_block(true, (i > 0).then_some(i as u64)));
        if i == 0 {
            out.extend(file_block(&FileSpec::new("first.bin", &first), &first, crc32fast::hash(&first), false, false));
        }
        let crc = if i == 2 { crc32fast::hash(&big) } else { crc32fast::hash(part) };
        out.extend(file_block(&FileSpec::new("big.bin", &big), part, crc, i > 0, i < 2));
        if i == 2 {
            out.extend(file_block(&FileSpec::new("last.bin", &last), &last, crc32fast::hash(&last), false, false));
        }
        out.extend(end_block(i < 2));
        volumes.push(out);
    }
    Set { volumes, members: vec![("first.bin", first), ("big.bin", big), ("last.bin", last)] }
}

fn options(dest: &Path) -> ProgressiveOptions {
    ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: dest.to_owned(),
            overwrite: zipfast::extract::Overwrite::Always,
            flatten: false,
            threads: Some(1),
            protected_paths: Default::default(),
            parallel_min: None,
            select: None,
            windows_safe_names: false,
        },
        OsString::from(NAMES[0]),
    )
}
fn growing(poll: Option<Duration>, idle: Duration) -> GrowingOptions {
    let mut options = GrowingOptions::default();
    options.poll_interval = poll;
    options.idle_timeout = idle;
    options.check_block = 64;
    options.check_every = 1;
    options
}

fn append(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
}

/// A waker that unparks the polling thread and counts its wakes.
struct Unpark {
    thread: Thread,
    woken: AtomicBool,
    wakes: AtomicUsize,
}
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        self.woken.store(true, Ordering::SeqCst);
        self.thread.unpark();
    }
}

#[derive(Default)]
struct Run {
    published: Vec<(String, Vec<u8>, VerificationLevel, ArtifactPublication)>,
    opened: Vec<u32>,
    failure: Option<ProgressiveFailure>,
    polls: usize,
    pending: usize,
    wakes: usize,
}
/// Polls `session` like a minimal executor: on `Pending` it calls `between` (which may append and notify) and
/// then parks the thread until the session's waker fires. It never re-polls without a wake.
fn drive(
    session: &mut ProgressiveSession,
    dest: &Path,
    limit: Duration,
    mut between: impl FnMut(),
    mut on_member: impl FnMut(&str),
) -> Run {
    let unpark =
        Arc::new(Unpark { thread: std::thread::current(), woken: AtomicBool::new(false), wakes: AtomicUsize::new(0) });
    let waker = Waker::from(unpark.clone());
    let mut run = Run::default();
    let mut names = Vec::new();
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < limit, "session did not finish in {limit:?}");
        run.polls += 1;
        match session.poll_event(&mut Context::from_waker(&waker)) {
            Poll::Pending => {
                run.pending += 1;
                between();
                while !unpark.woken.swap(false, Ordering::SeqCst) {
                    assert!(start.elapsed() < limit, "no wake within {limit:?}");
                    std::thread::park_timeout(Duration::from_millis(50));
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(event))) => match event {
                ProgressiveEvent::VolumeOpened { index, .. } => run.opened.push(index),
                ProgressiveEvent::MemberStarted { name, .. } => names.push(String::from_utf8_lossy(&name).into_owned()),
                ProgressiveEvent::MemberFinished { outcome, .. } => {
                    let name = names.last().unwrap().clone();
                    match outcome {
                        MemberOutcome::Verified(v) => {
                            let bytes = fs::read(dest.join(&name)).unwrap();
                            run.published.push((name.clone(), bytes, v.level(), ArtifactPublication::Strict));
                        }
                        MemberOutcome::Provisional(a) => {
                            run.published.push((
                                name.clone(),
                                Vec::new(),
                                VerificationLevel::Unverified,
                                a.publication(),
                            ));
                        }
                        _ => panic!("{name}: unexpected outcome"),
                    }
                    on_member(&name);
                }
                ProgressiveEvent::SessionTerminated { failure, .. } => {
                    run.failure = Some(failure);
                    break;
                }
                _ => {}
            },
            Poll::Ready(Err(failure)) => {
                run.failure = Some(failure);
                break;
            }
        }
    }
    run.wakes = unpark.wakes.load(Ordering::SeqCst);
    run
}

struct Fixture {
    _tmp: tempfile::TempDir,
    inputs: PathBuf,
    dest: PathBuf,
}
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let inputs = tmp.path().join("in");
    let dest = tmp.path().join("out");
    fs::create_dir(&inputs).unwrap();
    Fixture { _tmp: tmp, inputs, dest }
}
fn assert_strict(run: &Run, set: &Set) {
    assert!(run.failure.is_none(), "{:?}", run.failure);
    assert_eq!(run.opened, vec![0, 1, 2]);
    assert_eq!(run.published.len(), set.members.len());
    for ((name, bytes, level, publication), (expected_name, expected)) in run.published.iter().zip(&set.members) {
        assert_eq!(name, expected_name);
        assert_eq!(*publication, ArtifactPublication::Strict, "{name} must publish Strict");
        assert_eq!(*level, VerificationLevel::Strict);
        assert_eq!(bytes, expected, "{name}");
    }
}

#[test]
fn volumes_created_and_appended_between_polls_extract_and_publish_strict() {
    let f = fixture();
    let set = set();
    let provider = GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(None, Duration::from_secs(30))).unwrap();
    assert_eq!(provider.first_name(), NAMES[0]);
    let notifier = provider.notifier();
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.dest)).unwrap();
    // Every volume arrives in small chunks, the next one only once the session has parked on the one before.
    let mut chunks = std::collections::VecDeque::new();
    for (i, volume) in set.volumes.iter().enumerate() {
        for chunk in volume.chunks(700) {
            chunks.push_back((i, chunk.to_vec()));
        }
    }
    let inputs = f.inputs.clone();
    let run = drive(
        &mut session,
        &f.dest,
        Duration::from_secs(60),
        || {
            if let Some((i, chunk)) = chunks.pop_front() {
                append(&inputs.join(NAMES[i]), &chunk);
            }
            notifier.notify();
        },
        |name| {
            if name == "first.bin" {
                // Published Strict while later volumes did not exist yet.
                assert!(!inputs.join(NAMES[1]).exists() && !inputs.join(NAMES[2]).exists());
            }
        },
    );
    assert_strict(&run, &set);
    assert!(run.pending > 20, "the session parked on the growing files ({} times)", run.pending);
    for (i, volume) in set.volumes.iter().enumerate() {
        assert_eq!(&fs::read(f.inputs.join(NAMES[i])).unwrap(), volume, "inputs are untouched");
    }
}

#[test]
fn a_background_writer_with_a_poll_interval_is_not_busy_polled() {
    let f = fixture();
    let set = set();
    let interval = Duration::from_millis(20);
    let provider =
        GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(Some(interval), Duration::from_secs(30))).unwrap();
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.dest)).unwrap();
    let volumes = set.volumes.clone();
    let inputs = f.inputs.clone();
    let writer = std::thread::spawn(move || {
        for (i, volume) in volumes.iter().enumerate() {
            std::thread::sleep(Duration::from_millis(60));
            for chunk in volume.chunks(1500) {
                append(&inputs.join(NAMES[i]), chunk);
                std::thread::sleep(Duration::from_millis(15));
            }
        }
    });
    let start = Instant::now();
    let run = drive(&mut session, &f.dest, Duration::from_secs(60), || {}, |_| {});
    let elapsed = start.elapsed();
    writer.join().unwrap();
    assert_strict(&run, &set);
    // Without a wake the executor never polls again, so each pending poll costs one timer (or work-yield) wake.
    // A busy loop would poll thousands of times; a timer bounded by the interval polls about elapsed / interval.
    let timer_bound = (elapsed.as_millis() / interval.as_millis()) as usize + 1;
    assert!(run.pending > 0);
    assert!(
        run.pending <= 2 * timer_bound + 10,
        "{} pending polls in {elapsed:?} exceeds the poll-interval bound {timer_bound}",
        run.pending
    );
    assert!(run.wakes <= run.pending + 10, "{} wakes for {} pending polls", run.wakes, run.pending);
}

#[test]
fn an_absent_volume_waits_until_it_appears() {
    let f = fixture();
    let set = set();
    fs::write(f.inputs.join(NAMES[0]), &set.volumes[0]).unwrap();
    let provider = GrowingFileVolumes::new(
        f.inputs.join(NAMES[0]),
        growing(Some(Duration::from_millis(10)), Duration::from_secs(30)),
    )
    .unwrap();
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.dest)).unwrap();
    let volumes = set.volumes.clone();
    let inputs = f.inputs.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        fs::write(inputs.join(NAMES[1]), &volumes[1]).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        fs::write(inputs.join(NAMES[2]), &volumes[2]).unwrap();
    });
    let run = drive(&mut session, &f.dest, Duration::from_secs(60), || {}, |_| {});
    writer.join().unwrap();
    assert_strict(&run, &set);
    assert!(run.pending >= 2, "the session waited for the absent volumes");
}

#[test]
fn a_volume_that_never_appears_is_missing_after_the_idle_timeout() {
    let f = fixture();
    let set = set();
    fs::write(f.inputs.join(NAMES[0]), &set.volumes[0]).unwrap();
    let idle = Duration::from_millis(200);
    let provider = GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(None, idle)).unwrap();
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.dest)).unwrap();
    let start = Instant::now();
    let run = drive(&mut session, &f.dest, Duration::from_secs(30), || {}, |_| {});
    // With no poll interval the idle deadline alone wakes the session: it neither spins nor hangs.
    assert!(start.elapsed() >= idle);
    let failure = run.failure.expect("missing volume");
    assert!(matches!(failure.kind, FailureKind::MissingVolume), "{failure:?}");
    assert_eq!(failure.context.volume_index, Some(1));
    assert!(run.pending <= 4, "{} pending polls for one idle wait", run.pending);
    assert_eq!(run.published.len(), 1, "first.bin was still published");
}

#[test]
fn a_read_with_no_growth_fails_with_an_idle_timeout() {
    let f = fixture();
    let set = set();
    // Volume 0 stops in the middle of big.bin's data and never grows again.
    fs::write(f.inputs.join(NAMES[0]), &set.volumes[0][..set.volumes[0].len() - 500]).unwrap();
    let idle = Duration::from_millis(200);
    let provider =
        GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(Some(Duration::from_millis(25)), idle)).unwrap();
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.dest)).unwrap();
    let run = drive(&mut session, &f.dest, Duration::from_secs(30), || {}, |_| {});
    let failure = run.failure.expect("idle timeout");
    assert!(matches!(failure.kind, FailureKind::IdleTimeout { idle: i } if i == idle), "{failure:?}");
    assert_eq!(failure.context.volume_index, Some(0));
    assert!(run.pending <= 20, "{} pending polls for a 200 ms stall at 25 ms", run.pending);
}

/// Writes volume 0 up to `split`, runs the session until it parks there, applies `tamper`, then appends the rest
/// in small chunks; returns the session's failure.
fn tampered(split: usize, tamper: impl FnOnce(&Path, &[u8])) -> ProgressiveFailure {
    let f = fixture();
    let set = set();
    let path = f.inputs.join(NAMES[0]);
    fs::write(&path, &set.volumes[0][..split]).unwrap();
    let provider = GrowingFileVolumes::new(&path, growing(None, Duration::from_secs(30))).unwrap();
    let notifier = provider.notifier();
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.dest)).unwrap();
    let mut tamper = Some(tamper);
    let rest = set.volumes[0][split..].to_vec();
    let mut chunks = rest.chunks(32);
    let original = set.volumes[0].clone();
    let run = drive(
        &mut session,
        &f.dest,
        Duration::from_secs(60),
        || {
            if let Some(tamper) = tamper.take() {
                tamper(&path, &original);
            } else if let Some(chunk) = chunks.next() {
                append(&path, chunk);
            }
            notifier.notify();
        },
        |_| {},
    );
    run.failure.expect("tampering must fail closed")
}

#[test]
fn rewriting_bytes_already_read_fails_closed() {
    // Change one byte of first.bin's header, long since parsed, without changing the length.
    let failure = tampered(1200, |path, original| {
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.write_at(&[original[20] ^ 0xff], 20).unwrap();
    });
    assert!(matches!(failure.kind, FailureKind::SourceChanged), "{failure:?}");
}

#[test]
fn truncating_a_growing_volume_fails_closed() {
    let failure = tampered(1200, |path, _| {
        fs::OpenOptions::new().write(true).open(path).unwrap().set_len(600).unwrap();
    });
    assert!(matches!(failure.kind, FailureKind::SourceChanged), "{failure:?}");
}

#[test]
fn replacing_a_growing_volume_by_rename_fails_closed() {
    let failure = tampered(1200, |path, original| {
        // Same bytes, new inode: identity, not content, is what binds the volume.
        let staged = path.with_extension("tmp");
        fs::write(&staged, original).unwrap();
        fs::rename(&staged, path).unwrap();
    });
    assert!(matches!(failure.kind, FailureKind::SourceChanged), "{failure:?}");
}

/// One volume whose only member is named like volume 1 of its own set.
fn aliasing_set() -> (Vec<u8>, Vec<u8>) {
    let data = b"would replace an input volume".to_vec();
    let mut first = SIG.to_vec();
    first.extend(main_block(true, None));
    first.extend(file_block(&FileSpec::new(NAMES[1], &data), &data, crc32fast::hash(&data), false, false));
    first.extend(end_block(true));
    let mut second = SIG.to_vec();
    second.extend(main_block(true, Some(1)));
    second.extend(end_block(false));
    (first, second)
}

#[test]
fn an_output_cannot_overwrite_a_volume_that_exists() {
    let f = fixture();
    let (first, second) = aliasing_set();
    fs::write(f.inputs.join(NAMES[0]), &first).unwrap();
    fs::write(f.inputs.join(NAMES[1]), &second).unwrap();
    let provider = GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(None, Duration::from_secs(30))).unwrap();
    // Extract into the input directory itself.
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.inputs)).unwrap();
    let run = drive(&mut session, &f.inputs, Duration::from_secs(30), || {}, |_| {});
    let failure = run.failure.expect("alias");
    assert!(matches!(failure.kind, FailureKind::UnsafePath), "{failure:?}");
    assert_eq!(fs::read(f.inputs.join(NAMES[0])).unwrap(), first);
    assert_eq!(fs::read(f.inputs.join(NAMES[1])).unwrap(), second);
}

#[test]
fn an_output_published_where_a_later_volume_appears_is_never_read_as_input() {
    let f = fixture();
    let (first, _) = aliasing_set();
    fs::write(f.inputs.join(NAMES[0]), &first).unwrap();
    let provider = GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(None, Duration::from_secs(30))).unwrap();
    let mut session = ProgressiveSession::new(Box::new(provider), options(&f.inputs)).unwrap();
    // The member publishes at volume 1's name before that volume exists; the session must refuse to read it back.
    let run = drive(&mut session, &f.inputs, Duration::from_secs(30), || {}, |_| {});
    let failure = run.failure.expect("output named as input");
    assert!(matches!(failure.kind, FailureKind::UnsafePath), "{failure:?}");
    assert_eq!(failure.context.volume_index, Some(1));
    assert_eq!(fs::read(f.inputs.join(NAMES[0])).unwrap(), first);
}

#[test]
fn growth_is_still_refused_from_custom_providers_in_ordinary_sessions() {
    // The library-owned provider grows; a custom provider that only opts in keeps the frozen contract.
    // It forwards everything a provider can say, and even shares the inner provider's address
    // (`repr(transparent)`); ownership is the boxed concrete type, which a wrapper cannot forward.
    #[repr(transparent)]
    struct Custom(GrowingFileVolumes);
    impl VolumeSource for Custom {
        fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            self.0.volume(r, cx)
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            self.0.protection()
        }
        fn extends_protection(&self) -> bool {
            true
        }
    }
    let f = fixture();
    let set = set();
    fs::write(f.inputs.join(NAMES[0]), &set.volumes[0]).unwrap();
    let inner = GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(None, Duration::from_secs(30))).unwrap();
    let notifier = inner.notifier();
    let mut session = ProgressiveSession::new(Box::new(Custom(inner)), options(&f.dest)).unwrap();
    let inputs = f.inputs.clone();
    let mut written = false;
    let run = drive(
        &mut session,
        &f.dest,
        Duration::from_secs(30),
        || {
            if !written {
                written = true;
                fs::write(inputs.join(NAMES[1]), &set.volumes[1]).unwrap();
            }
            notifier.notify();
        },
        |_| {},
    );
    let failure = run.failure.expect("frozen declaration");
    assert!(matches!(failure.kind, FailureKind::SourceChanged), "{failure:?}");
}

#[test]
fn a_long_wait_for_an_absent_volume_costs_constant_bookkeeping_per_wake() {
    // 20,000 notify-driven wakes while volume 1 is absent, under a bookkeeping budget the old per-wake cost
    // (about 220 units, growing with the declared volumes) would have exhausted 4 times over.
    const WAKES: usize = 20_000;
    let f = fixture();
    let set = set();
    fs::write(f.inputs.join(NAMES[0]), &set.volumes[0]).unwrap();
    let provider = GrowingFileVolumes::new(f.inputs.join(NAMES[0]), growing(None, Duration::from_secs(600))).unwrap();
    let notifier = provider.notifier();
    let mut options = options(&f.dest);
    options.limits.source_bookkeeping = 1_000_000;
    options.limits.provider_wakes = 2 * WAKES as u64;
    let mut session = ProgressiveSession::new(Box::new(provider), options).unwrap();
    let inputs = f.inputs.clone();
    let mut waits = 0;
    let run = drive(
        &mut session,
        &f.dest,
        Duration::from_secs(120),
        || {
            waits += 1;
            if waits == WAKES {
                fs::write(inputs.join(NAMES[1]), &set.volumes[1]).unwrap();
                fs::write(inputs.join(NAMES[2]), &set.volumes[2]).unwrap();
            }
            notifier.notify();
        },
        |_| {},
    );
    assert_strict(&run, &set);
    assert!(run.pending >= WAKES);
}

#[cfg(feature = "persistent-partials")]
mod persistent {
    use super::*;
    use std::sync::Mutex;
    use zipfast::partial::*;

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
            match index {
                Some(index) => anchors[index] = next.clone(),
                None => anchors.push(next.clone()),
            }
            Ok(())
        }
    }

    #[test]
    fn a_persistent_session_follows_the_same_growing_set() {
        let f = fixture();
        let set = set();
        // A persistent session needs a Complete declaration when it starts, so volume 0 must exist (even empty).
        fs::write(f.inputs.join(NAMES[0]), b"").unwrap();
        let provider = GrowingFileVolumes::new(
            f.inputs.join(NAMES[0]),
            growing(Some(Duration::from_millis(10)), Duration::from_secs(30)),
        )
        .unwrap();
        let mut session = ProgressiveSession::new_partial(
            Box::new(provider),
            options(&f.dest),
            PartialOptions {
                binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
                naming: PartialNaming::ArchivePath,
                state_dir: f.inputs.with_file_name("state"),
                limits: PartialLimits::default(),
                anchors: Arc::new(Anchors::default()),
                control: SessionControl::default(),
            },
        )
        .unwrap();
        let volumes = set.volumes.clone();
        let inputs = f.inputs.clone();
        let writer = std::thread::spawn(move || {
            for (i, volume) in volumes.iter().enumerate() {
                for chunk in volume.chunks(1000) {
                    append(&inputs.join(NAMES[i]), chunk);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        let unpark = Arc::new(Unpark {
            thread: std::thread::current(),
            woken: AtomicBool::new(false),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(unpark.clone());
        let start = Instant::now();
        let mut opened = Vec::new();
        let mut ready = 0;
        loop {
            assert!(start.elapsed() < Duration::from_secs(60));
            match session.poll_event(&mut Context::from_waker(&waker)) {
                Poll::Pending => {
                    while !unpark.woken.swap(false, Ordering::SeqCst) {
                        assert!(start.elapsed() < Duration::from_secs(60), "no wake");
                        std::thread::park_timeout(Duration::from_millis(50));
                    }
                }
                Poll::Ready(Ok(None)) => break,
                Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index, .. }))) => opened.push(index),
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { .. }))) => ready += 1,
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. })))
                | Poll::Ready(Err(failure)) => {
                    panic!("{failure:?}")
                }
                Poll::Ready(Ok(Some(_))) => {}
            }
        }
        writer.join().unwrap();
        assert_eq!(opened, vec![0, 1, 2]);
        assert_eq!(ready, set.members.len());
        for (name, bytes) in &set.members {
            assert_eq!(&fs::read(f.dest.join(name)).unwrap(), bytes, "{name}");
        }
    }
}
