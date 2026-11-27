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

//! `RarSession` decodes a big RAR 5.0 member on worker threads, as the whole-archive run does: its thread settings
//! (`RarSessionOptions::threads`/`parallel_min`, or extraction's `Options::threads`/`parallel_min`) follow
//! `extract::Options`, the output is the same on any number of threads, `Some(1)` decodes on the calling thread only,
//! and cancelling with blocks still on the workers stops the run. The fixtures are in
//! `tests/fixtures/rar5-threads/README.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use zipfast::error::RarFailure;
use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite, RarOutcome, UnverifiedOutput};
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The tests here count the process's decoder threads, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn fixture(rel: &str) -> PathBuf {
    Path::new(FIXTURES).join(rel)
}

fn sha256(bytes: &[u8]) -> String {
    zipfast::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// A set, and each member's name, size and SHA-256.
struct Set {
    first: &'static str,
    members: &'static [(&'static str, usize, &'static str)],
}

const S_TXT: (&str, usize, &str) = ("s.txt", 6, "4c47b3e816fbe7d40cef9f665ba8f0be1ae68b5e8e7ed70f5b6bab7f70528e8f");

const SETS: &[Set] = &[
    // non-solid, the big member over three volumes
    Set {
        first: "rar5-threads/big.part01.rar",
        members: &[("a.txt", 4_400_000, "f19b51f7837c390ae15837cac5036bb00b7c7bb3c328262badf19a809748dab4"), S_TXT],
    },
    // solid: two big members with a small one between them
    Set {
        first: "rar5-threads/solid.rar",
        members: &[
            ("b.txt", 4_200_000, "f6539c680f8bc88f4198bb4e851d6f2e511d0e991e14500106050972cd443cb1"),
            ("c.txt", 600_000, "024dcef7cef915c5cf19d36130cade0ed5f7e3373c2c98b28a424e71f1089b8e"),
            ("d.txt", 4_300_000, "55f5bb3ce5e2007f051496f7c9876a587804ff164fdb03a744056a9fdebe0774"),
            S_TXT,
        ],
    },
];

fn options(dest: &Path, threads: Option<usize>, parallel_min: Option<u64>) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads,
        protected_paths: Default::default(),
        parallel_min,
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
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

fn session_options(threads: Option<usize>, parallel_min: Option<u64>) -> RarSessionOptions {
    RarSessionOptions { threads, parallel_min, ..RarSessionOptions::default() }
}

fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name().into_string().unwrap(), fs::read(entry.path()).unwrap())
        })
        .collect()
}

fn assert_set(set: &Set, got: &BTreeMap<String, Vec<u8>>, what: &str) {
    assert_eq!(got.len(), set.members.len(), "{what}: {:?}", got.keys().collect::<Vec<_>>());
    for &(name, len, sha) in set.members {
        let bytes = got.get(name).unwrap_or_else(|| panic!("{what}: {name} missing"));
        assert_eq!(bytes.len(), len, "{what}: {name} length");
        assert_eq!(sha256(bytes), sha, "{what}: {name} bytes");
    }
}

/// The decoder's worker threads in this process now (Linux names them in /proc); None elsewhere.
fn decoder_threads() -> Option<usize> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let tasks = fs::read_dir("/proc/self/task").ok()?;
    Some(
        tasks
            .filter_map(|task| fs::read_to_string(task.ok()?.path().join("comm")).ok())
            .filter(|name| name.starts_with("rar5-decode"))
            .count(),
    )
}

fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// Extraction, printing and testing through a session give the members' bytes on the default threads, on one
/// thread, and on workers for every member, as the whole-archive run does.
#[test]
fn session_output_is_the_same_on_any_threads_and_matches_the_whole_archive_run() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let settings: &[(Option<usize>, Option<u64>)] = &[(None, None), (Some(1), None), (Some(4), Some(0))];
    for (n, set) in SETS.iter().enumerate() {
        let first = fixture(set.first);
        let runner = dir.path().join(format!("run-{n}"));
        fs::create_dir_all(&runner).unwrap();
        extract::run(&first, &options(&runner, None, None), |_| {}).unwrap();
        assert_set(set, &tree(&runner), &format!("{} run", set.first));
        for &(threads, parallel_min) in settings {
            let what = format!("{} {threads:?} {parallel_min:?}", set.first);
            // extraction, its options' settings
            let out = dir.path().join(format!("session-{n}-{threads:?}-{parallel_min:?}"));
            fs::create_dir_all(&out).unwrap();
            let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
            let all = session.select(|_| true).unwrap();
            let opts = options(&out, threads, parallel_min);
            let summary = session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
            assert_eq!((summary.files, summary.failed), (set.members.len() as u64, 0), "{what}");
            assert_set(set, &tree(&out), &format!("{what} extract"));
            // printing and testing, the session's settings
            let mut session = RarSession::open(&first, None, session_options(threads, parallel_min)).unwrap();
            let all = session.select(|_| true).unwrap();
            let mut printed = Vec::new();
            let mut sizes = Vec::new();
            session
                .print_selected(&all, &mut printed, &RarPrintOptions::default(), |event| match &event.outcome {
                    RarOutcome::Verified { bytes, .. } => sizes.push(*bytes),
                    other => panic!("{what}: {other:?}"),
                })
                .unwrap();
            let mut at = 0;
            for (&(name, len, sha), &size) in set.members.iter().zip(&sizes) {
                assert_eq!(size, len as u64, "{what}: {name} printed");
                assert_eq!(sha256(&printed[at..at + len]), sha, "{what}: {name} printed");
                at += len;
            }
            assert_eq!((sizes.len(), at), (set.members.len(), printed.len()), "{what}: printed");
            let summary = session
                .test_selected(&all, RarDecodeLimits::default(), |event| {
                    assert!(matches!(event.outcome, RarOutcome::Verified { .. }), "{what}: {:?}", event.outcome)
                })
                .unwrap();
            assert_eq!(summary.failed, 0, "{what}");
        }
    }
}

/// By default a session decodes a big member on worker threads; with `Some(1)` it starts none, and with `Some(n)` at
/// most `n - 1`.
#[test]
fn session_threads_decide_the_decoder_workers() {
    let _serial = serial();
    if decoder_threads().is_none() || cores() < 2 {
        eprintln!("decoder threads can't be counted here");
        return;
    }
    assert_eq!(decoder_threads(), Some(0), "none before");
    let first = fixture("rar5-threads/solid.rar");
    for (threads, most) in [(None, (cores() - 1).min(16)), (Some(1), 0), (Some(3), 2)] {
        let mut session = RarSession::open(&first, None, session_options(threads, None)).unwrap();
        let all = session.select(|member| member.name() == "b.txt").unwrap();
        let mut seen = Vec::new();
        // the run's decoder (and its workers) is still there when each member's outcome is reported
        session.test_selected(&all, RarDecodeLimits::default(), |_| seen.push(decoder_threads().unwrap())).unwrap();
        let [seen] = seen.as_slice() else { panic!("{seen:?}") };
        if most == 0 {
            assert_eq!(*seen, 0, "{threads:?}: decoded on the calling thread only");
        } else {
            assert!((1..=most).contains(seen), "{threads:?}: {seen} workers, at most {most}");
        }
        assert_eq!(decoder_threads(), Some(0), "{threads:?}: the workers stop with the run");
    }
}

/// Cancelling while a member's blocks are still with the workers stops the run as canceled, and the workers stop.
#[test]
fn cancelling_with_blocks_on_the_workers_stops_the_run() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let first = fixture("rar5-threads/solid.rar");
    let mut mid_member = false;
    for attempt in 0..20 {
        let out = dir.path().join(format!("cancel-{attempt}"));
        fs::create_dir_all(&out).unwrap();
        let cancel = Cancellation::default();
        let options_session = RarSessionOptions { cancel: cancel.clone(), ..session_options(Some(4), Some(0)) };
        let mut session = RarSession::open(&first, None, options_session).unwrap();
        let all = session.select(|_| true).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        // cancel once some output of the first member is out, with its later blocks still being decoded
        let watcher = {
            let (out, done, cancel) = (out.clone(), Arc::clone(&done), cancel.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    let written: u64 = fs::read_dir(&out)
                        .into_iter()
                        .flatten()
                        .filter_map(|entry| entry.ok()?.metadata().ok())
                        .map(|meta| meta.len())
                        .sum();
                    if written > 0 {
                        cancel.cancel();
                        return Some(written);
                    }
                }
                None
            })
        };
        let result = session.extract_selected(&all, &options(&out, None, None), RarDecodeLimits::default(), |_| {});
        done.store(true, Ordering::Relaxed);
        let written = watcher.join().unwrap();
        if let Some(threads) = decoder_threads() {
            assert_eq!(threads, 0, "the workers stop with the run");
        }
        match result {
            Err(error) => {
                assert!(matches!(error.failure.as_ref(), RarFailure::Canceled), "{:?}", error.failure);
                let entry = error.entry.as_ref().map(|entry| entry.name.as_str());
                if written.is_some_and(|w| w < 4_200_000) && entry == Some("b.txt") {
                    mid_member = true;
                    break;
                }
            }
            Ok(summary) => assert_eq!(summary.failed, 0),
        }
    }
    assert!(mid_member, "no run was canceled inside its first member");
}

/// UnRAR's cut at the end of a member's data (`unrar p` of a member a missing volume cuts off) needs its blocks
/// decoded on the calling thread: a session decodes such a member there whatever its thread settings.
#[test]
fn a_member_cut_off_prints_what_unrar_prints_on_any_threads() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let cuts = [
        ("r5-partial.part1.rar", (55043, "11c38a4de906c15f93a2be9e54c2a1a353a74f54bc174ba4cd1b79b5b2d7a06e")),
        ("r5-edge.part1.rar", (51611, "9e56b78c9855adba0d200b971714afe00bd67cd2ed08c26d6d5b753dbd6d2a64")),
    ];
    for (volume, (len, sha)) in cuts {
        // the first volume alone, so the next one is missing
        let path = dir.path().join(volume);
        fs::copy(fixture(&format!("unverified-output/{volume}")), &path).unwrap();
        for (threads, parallel_min) in [(Some(1), None), (Some(4), Some(0)), (None, Some(0))] {
            let what = format!("{volume} {threads:?} {parallel_min:?}");
            let mut session = RarSession::open(&path, None, session_options(threads, parallel_min)).unwrap();
            let all = session.select(|member| member.name() == "text.txt").unwrap();
            let options = RarPrintOptions { unverified_output: UnverifiedOutput::Emit, ..RarPrintOptions::default() };
            let mut output = Vec::new();
            let summary = session.print_selected(&all, &mut output, &options, |_| {}).unwrap();
            assert_eq!(summary.failed, 1, "{what}");
            assert_eq!((output.len(), sha256(&output).as_str()), (len, sha), "{what}");
        }
    }
}
