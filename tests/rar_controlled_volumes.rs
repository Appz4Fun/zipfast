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

//! `RarSession::extract_selected_controlled` checks the volumes a member depends on around each callback, not the
//! whole set: its control work grows with the volumes, not with volumes x members, and a volume a callback swaps
//! is still caught before any member's output depends on it.
#![cfg(unix)]
mod common;
use common::*;
use std::{
    fs,
    path::{Path, PathBuf},
};
use zipfast::error::RarFailure;
use zipfast::extract::{Mode, Options, Overwrite, RarEntryOutcome};
use zipfast::rar5::session::*;
use zipfast::rar5::testenc::Op;

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite: Overwrite::Skip,
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
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

fn volume_path(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("set.part{:03}.rar", i + 1))
}

/// A volume set holding one whole member per volume: `(spec, CRC of the unpacked data)`.
fn write_set(dir: &Path, members: &[(FileSpec<'_>, u32)], solid: bool) -> Vec<PathBuf> {
    let n = members.len();
    members
        .iter()
        .enumerate()
        .map(|(i, (spec, crc))| {
            let mut out = SIG.to_vec();
            out.extend(main_block_flags(true, if i == 0 { None } else { Some(i as u64) }, solid));
            out.extend(file_block(spec, spec.data, *crc, false, false));
            out.extend(end_block(i + 1 != n));
            let path = volume_path(dir, i);
            fs::write(&path, out).unwrap();
            path
        })
        .collect()
}

fn stored_set(dir: &Path, names: &[String]) -> Vec<PathBuf> {
    let specs: Vec<_> =
        names.iter().map(|name| (FileSpec::new(name, name.as_bytes()), crc32fast::hash(name.as_bytes()))).collect();
    write_set(dir, &specs, false)
}

/// Rewrite a volume in place with bytes of another length: its stamp no longer matches.
fn tamper(path: &Path) {
    fs::write(path, b"not the volume the session opened").unwrap();
}

fn source_changed(failure: &RarFailure) -> bool {
    matches!(failure, RarFailure::SourceChanged { .. })
}

/// Swaps `swap` (once) when the member named `at` reaches the hook, `overwrite` or `entry`.
struct Swap {
    at: &'static str,
    in_overwrite: bool,
    swap: PathBuf,
    done: bool,
}
impl Swap {
    fn fire(&mut self, name: &str) {
        if !self.done && name == self.at {
            self.done = true;
            tamper(&self.swap);
        }
    }
}
impl RarExtractObserver for Swap {
    fn overwrite(
        &mut self,
        conflict: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        if self.in_overwrite {
            self.fire(&conflict.entry.name.clone());
        }
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, event: &RarEntryOutcome, _: RarDiagnostic<'_>) {
        if !self.in_overwrite {
            self.fire(&event.entry.name.clone());
        }
    }
}

struct Count(usize);
impl RarExtractObserver for Count {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {
        self.0 += 1;
    }
}

fn run(first: &Path, out: &Path, mode: RarOverwriteMode, observer: &mut impl RarExtractObserver) -> RarExtractFinished {
    run_limited(first, out, mode, observer, RarExtractControlLimits::default())
}

fn run_limited(
    first: &Path,
    out: &Path,
    mode: RarOverwriteMode,
    observer: &mut impl RarExtractObserver,
    limits: RarExtractControlLimits,
) -> RarExtractFinished {
    let mut session_options = RarSessionOptions::default();
    session_options.limits.volumes = 4096;
    let mut s = RarSession::open(first, None, session_options).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, mode, limits);
    s.extract_selected_controlled(&selected, &options(out), RarDecodeLimits::default(), &mut c, observer).finish()
}

#[test]
fn control_work_grows_linearly_with_the_volumes() {
    let d = tempfile::tempdir().unwrap();
    let measure = |n: usize| {
        let dir = d.path().join(format!("n{n}"));
        fs::create_dir_all(&dir).unwrap();
        let names: Vec<String> = (0..n).map(|i| format!("f{i:04}")).collect();
        let paths = stored_set(&dir, &names);
        let out = dir.join("out");
        let mut observer = Count(0);
        let result = run(&paths[0], &out, RarOverwriteMode::Always, &mut observer);
        assert_eq!(result.outcome.as_ref().unwrap().files, n as u64, "{:?}", result.outcome);
        assert_eq!(observer.0, n);
        for name in &names {
            assert_eq!(fs::read(out.join(name)).unwrap(), name.as_bytes());
        }
        result.usage
    };
    let (small, large) = (measure(20), measure(200));
    // one stat triple after the publication check and one after the entry callback, per member: the whole-set
    // check made this about 6 x volumes x members (240,000 attempts for 200 volumes)
    assert!(large.io_attempts <= 8 * 200, "io attempts {} for 200 volumes", large.io_attempts);
    assert!(large.io_attempts <= 11 * small.io_attempts, "{} vs {}", large.io_attempts, small.io_attempts);
    assert!(large.work <= 11 * small.work, "work {} vs {}", large.work, small.work);
}

#[test]
fn an_entry_callback_swapping_a_later_members_volume_fails_that_member() {
    let d = tempfile::tempdir().unwrap();
    let names: Vec<String> = ["a", "b", "c"].map(String::from).to_vec();
    let paths = stored_set(d.path(), &names);
    let out = d.path().join("out");
    let mut observer = Swap { at: "a", in_overwrite: false, swap: paths[2].clone(), done: false };
    let result = run(&paths[0], &out, RarOverwriteMode::Always, &mut observer);
    assert!(observer.done);
    let Err(RarExtractError::Native(error)) = &result.outcome else { panic!("{:?}", result.outcome) };
    assert!(source_changed(&error.failure), "{:?}", error.failure);
    // `b` reads only its own untouched volume; `c` reads the swapped one and is refused before it is written
    assert_eq!(error.entry.as_ref().map(|e| e.name.as_str()), Some("c"));
    assert_eq!(error.partial.files, 2);
    assert_eq!(fs::read(out.join("a")).unwrap(), b"a");
    assert_eq!(fs::read(out.join("b")).unwrap(), b"b");
    assert!(!out.join("c").exists());
}

#[test]
fn an_entry_callback_swapping_the_reported_members_volume_stops_the_run() {
    let d = tempfile::tempdir().unwrap();
    let names: Vec<String> = ["a", "b", "c"].map(String::from).to_vec();
    let paths = stored_set(d.path(), &names);
    let out = d.path().join("out");
    let mut observer = Swap { at: "b", in_overwrite: false, swap: paths[1].clone(), done: false };
    let result = run(&paths[0], &out, RarOverwriteMode::Always, &mut observer);
    let Err(RarExtractError::Native(error)) = &result.outcome else { panic!("{:?}", result.outcome) };
    assert!(source_changed(&error.failure), "{:?}", error.failure);
    assert_eq!(error.entry.as_ref().map(|e| e.name.as_str()), Some("b"));
    assert_eq!(error.partial.files, 2);
    assert!(!out.join("c").exists());
}

#[test]
fn an_overwrite_callback_swapping_the_members_own_volume_publishes_nothing() {
    let d = tempfile::tempdir().unwrap();
    let names: Vec<String> = ["a", "b", "c"].map(String::from).to_vec();
    let paths = stored_set(d.path(), &names);
    let out = d.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("b"), b"old").unwrap();
    let mut observer = Swap { at: "b", in_overwrite: true, swap: paths[1].clone(), done: false };
    let result = run(&paths[0], &out, RarOverwriteMode::Ask, &mut observer);
    assert!(observer.done);
    let Err(RarExtractError::Native(error)) = &result.outcome else { panic!("{:?}", result.outcome) };
    assert!(source_changed(&error.failure), "{:?}", error.failure);
    assert_eq!(error.entry.as_ref().map(|e| e.name.as_str()), Some("b"));
    assert_eq!(fs::read(out.join("b")).unwrap(), b"old");
    assert!(!out.join("c").exists());
}

#[test]
fn an_overwrite_callback_swapping_solid_history_fails_the_member() {
    let d = tempfile::tempdir().unwrap();
    // `b` continues `a`'s solid stream from the previous volume: its bytes depend on volume 1
    let first_ops: Vec<Op> = b"shared words in a solid archive ".iter().map(|&b| Op::Lit(b)).collect();
    let (s1, p1) = packed("a", &first_ops);
    let second_ops = [Op::Match(20, 32), Op::Lit(b'!')];
    let s2 = zipfast::rar5::testenc::block(&second_ops, true, true);
    let p2 = {
        let mut all = first_ops.clone();
        all.extend(second_ops.iter().cloned());
        zipfast::rar5::testenc::model(&all)[p1.len()..].to_vec()
    };
    let a = FileSpec { method: 3, size: Some(p1.len() as u64), ..FileSpec::new("a", &s1) };
    let b = FileSpec { method: 3, size: Some(p2.len() as u64), solid: true, ..FileSpec::new("b", &s2) };
    let paths = write_set(d.path(), &[(a, crc32fast::hash(&p1)), (b, crc32fast::hash(&p2))], true);

    // untouched, the pair extracts through the controlled route
    let clean = d.path().join("clean");
    let result = run(&paths[0], &clean, RarOverwriteMode::Always, &mut Count(0));
    assert_eq!(result.outcome.as_ref().unwrap().files, 2, "{:?}", result.outcome);
    assert_eq!(fs::read(clean.join("b")).unwrap(), p2);

    let out = d.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("b"), b"old").unwrap();
    let mut observer = Swap { at: "b", in_overwrite: true, swap: paths[0].clone(), done: false };
    let result = run(&paths[0], &out, RarOverwriteMode::Ask, &mut observer);
    assert!(observer.done);
    let Err(RarExtractError::Native(error)) = &result.outcome else { panic!("{:?}", result.outcome) };
    assert!(source_changed(&error.failure), "{:?}", error.failure);
    assert_eq!(error.entry.as_ref().map(|e| e.name.as_str()), Some("b"));
    assert_eq!(fs::read(out.join("a")).unwrap(), p1);
    assert_eq!(fs::read(out.join("b")).unwrap(), b"old");
}

#[test]
fn deep_volume_paths_keep_control_work_linear() {
    let d = tempfile::tempdir().unwrap();
    // each volume's path is over 600 bytes long, and the whole-set checks charged that for every volume per member:
    // about 108 million work units here, where a budget of 16 KiB per volume is ample for the checks that matter
    let mut dir = d.path().to_path_buf();
    while dir.as_os_str().len() < 600 {
        dir.push("deep-directory-component-for-long-paths");
    }
    fs::create_dir_all(&dir).unwrap();
    let names: Vec<String> = (0..300).map(|i| format!("f{i:04}")).collect();
    let paths = stored_set(&dir, &names);
    let out = d.path().join("out");
    let limits = RarExtractControlLimits { work: 300 * 16 * 1024, ..RarExtractControlLimits::default() };
    let result = run_limited(&paths[0], &out, RarOverwriteMode::Always, &mut Count(0), limits);
    assert_eq!(result.outcome.as_ref().unwrap().files, 300, "{:?}", result.outcome);
}
