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

//! The controlled route's diagnostic guard costs the same per member however many came before (Prybar: diagnostics
//! ran out of proof work near 1,000 single-member volumes and every writer was refused after that).
#![cfg(unix)]
mod common;
use common::*;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zipfast::extract::{Mode, Options, Overwrite, RarEntryOutcome};
use zipfast::rar5::session::*;

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
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// Logs one line at every outcome, as Prybar does, and counts the writers it was refused.
struct Logger {
    written: u64,
    refused: u64,
}
impl RarExtractObserver for Logger {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
        match diagnostic.writer() {
            Some(file) => {
                file.write_all(b"entry\n").unwrap();
                self.written += 1;
            }
            None => self.refused += 1,
        }
    }
}

/// `n` volumes `v.partNNNN.rar`, each holding one whole stored member `fNNNN`.
fn single_member_volumes(dir: &Path, n: usize) -> PathBuf {
    let names: Vec<String> = (0..n).map(|i| format!("f{i:04}")).collect();
    for (i, name) in names.iter().enumerate() {
        let spec = FileSpec::new(name, name.as_bytes());
        let mut out = SIG.to_vec();
        out.extend(main_block(true, if i == 0 { None } else { Some(i as u64) }));
        out.extend(file_block(&spec, spec.data, crc32fast::hash(spec.data), false, false));
        out.extend(end_block(i + 1 != n));
        fs::write(dir.join(format!("v.part{:04}.rar", i + 1)), out).unwrap();
    }
    dir.join("v.part0001.rar")
}

/// One archive holding `n` stored members `d/fNNNN`, so every target shares the same parents.
fn many_members(dir: &Path, n: usize) -> PathBuf {
    let names: Vec<String> = (0..n).map(|i| format!("d/f{i:04}")).collect();
    let specs: Vec<FileSpec<'_>> = names.iter().map(|name| FileSpec::new(name, name.as_bytes())).collect();
    let path = dir.join("many.rar");
    fs::write(&path, archive(&specs)).unwrap();
    path
}

fn raise_descriptor_limit(wanted: libc::rlim_t) {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
    if limit.rlim_cur < wanted {
        assert!(limit.rlim_max >= wanted, "this test needs {wanted} descriptors, the hard limit is lower");
        limit.rlim_cur = wanted;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    }
}

/// Runs the controlled route over the set at `first` with a distinct regular log and returns the proof work charged.
fn diagnostic_work(dir: &Path, first: &Path, members: u64, overwrite: bool) -> u64 {
    let mut session_options = RarSessionOptions::default();
    session_options.limits.volumes = 4096;
    let mut session = RarSession::open(first, None, session_options).unwrap();
    let selected = session.select(|_| true).unwrap();
    let dest = dir.join("out");
    if overwrite {
        // every target already exists, so each member replaces an incumbent the guard must account for
        let mut control = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
        let report = session.extract_selected_controlled(
            &selected,
            &options(&dest),
            RarDecodeLimits::default(),
            &mut control,
            &mut Logger { written: 0, refused: 0 },
        );
        assert_eq!(report.finish().outcome.unwrap().files, members);
    }
    let log = dir.join("log");
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let mut observer = Logger { written: 0, refused: 0 };
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut observer,
    );
    assert_eq!(report.outcome().as_ref().unwrap().files, members);
    let terminal = report.diagnostic().writer().map(|file| file.write_all(b"terminal\n").unwrap()).is_some();
    let finished = report.finish();
    // running out of proof work is reported, never only a quiet refusal
    assert!(
        finished.diagnostic_failure.is_none(),
        "{members} members: {:?} after {} work",
        finished.diagnostic_failure,
        finished.usage.diagnostics.work
    );
    assert!(terminal, "{members} members");
    assert_eq!((observer.written, observer.refused), (members, 0), "{members} members");
    assert_eq!(fs::read(&log).unwrap().len() as u64, members * 6 + 9);
    finished.usage.diagnostics.work
}

fn assert_linear(small: u64, large: u64, what: &str) {
    // 10x the members may cost at most ~12x the proof work: anything quadratic is ~100x
    assert!(large <= small * 12, "{what}: proof work {small} at 200 members but {large} at 2000");
}

#[test]
fn diagnostic_work_is_linear_in_single_member_volumes() {
    raise_descriptor_limit(4500);
    let mut work = [0; 2];
    for (slot, n) in [200, 2000].into_iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let first = single_member_volumes(dir.path(), n);
        work[slot] = diagnostic_work(dir.path(), &first, n as u64, false);
    }
    assert_linear(work[0], work[1], "single-member volumes");
}

#[test]
fn diagnostic_work_is_linear_in_members_sharing_parents() {
    for overwrite in [false, true] {
        let mut work = [0; 2];
        for (slot, n) in [200, 2000].into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let first = many_members(dir.path(), n);
            work[slot] = diagnostic_work(dir.path(), &first, n as u64, overwrite);
        }
        assert_linear(work[0], work[1], if overwrite { "replacing members" } else { "new members" });
    }
}

/// Changes the namespace at one outcome, then asks for a writer at every outcome.
struct Tamperer<F: FnMut()> {
    at: u64,
    tamper: F,
    lent: Vec<bool>,
}
impl<F: FnMut()> RarExtractObserver for Tamperer<F> {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, entry: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
        if entry.entry.order == self.at {
            (self.tamper)();
        }
        self.lent.push(diagnostic.writer().map(|file| file.write_all(b"entry\n").unwrap()).is_some());
    }
}

const TAMPERED: usize = 40;

/// Extracts `TAMPERED` members `d/fNNNN` (more than a refresh re-validates in rotation) with `tamper` run at member
/// `at`'s outcome, and returns which outcomes were lent a writer, whether the terminal writer was, and the failure.
fn tampered(
    at: u64,
    tamper: impl FnMut(&Path, &Path),
) -> (Vec<bool>, bool, Option<RarDiagnosticFailure>, Vec<u8>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let first = many_members(dir.path(), TAMPERED);
    let dest = dir.path().join("out");
    let log = dir.path().join("log");
    let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let mut tamper = tamper;
    let (out, log_path) = (dest.clone(), log.clone());
    let mut observer = Tamperer { at, tamper: move || tamper(&out, &log_path), lent: Vec::new() };
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut observer,
    );
    let terminal = report.diagnostic().writer().map(|file| file.write_all(b"terminal\n").unwrap()).is_some();
    let finished = report.finish();
    let written = fs::read(&log).unwrap();
    (observer.lent, terminal, finished.diagnostic_failure, written, dir)
}

/// Every outcome before `at` was lent a writer, and none from `at` on.
fn refused_from(lent: &[bool], at: usize) {
    assert_eq!(lent.len(), TAMPERED);
    assert!(lent[..at].iter().all(|&lent| lent), "{lent:?}");
    assert!(lent[at..].iter().all(|&lent| !lent), "{lent:?}");
}

#[test]
fn the_current_members_target_rebound_to_the_log_is_refused_at_once() {
    let (lent, terminal, failure, written, _dir) = tampered(20, |out, log| {
        let target = out.join("d/f0020");
        fs::remove_file(&target).unwrap();
        fs::hard_link(log, &target).unwrap();
    });
    refused_from(&lent, 20);
    assert!(!terminal);
    assert!(matches!(failure, Some(RarDiagnosticFailure::AliasTarget { ordinal: 20 })), "{failure:?}");
    assert_eq!(written, b"entry\n".repeat(20));
}

#[test]
fn the_current_members_target_replaced_is_refused_at_once() {
    let (lent, terminal, failure, written, _dir) = tampered(20, |out, _| {
        let other = out.join("other");
        fs::write(&other, b"foreign").unwrap();
        fs::rename(&other, out.join("d/f0020")).unwrap();
    });
    refused_from(&lent, 20);
    assert!(!terminal);
    assert!(matches!(failure, Some(RarDiagnosticFailure::BindingChanged { ordinal: Some(20) })), "{failure:?}");
    assert_eq!(written, b"entry\n".repeat(20));
}

#[test]
fn a_shared_parent_replaced_under_the_current_member_is_refused_at_once() {
    let (lent, terminal, failure, written, _dir) = tampered(20, |out, _| {
        fs::rename(out.join("d"), out.join("d.moved")).unwrap();
        fs::create_dir(out.join("d")).unwrap();
    });
    refused_from(&lent, 20);
    assert!(!terminal);
    // the parent was first admitted by member 0, which it is reported under, as before
    assert!(matches!(failure, Some(RarDiagnosticFailure::BindingChanged { ordinal: Some(0) })), "{failure:?}");
    assert_eq!(written, b"entry\n".repeat(20));
}

#[test]
fn an_older_target_rebound_to_the_log_is_still_reported_by_the_run_end() {
    // an older member's target is re-validated in rotation and by every terminal writer
    let (lent, terminal, failure, _, dir) = tampered(30, |out, log| {
        let target = out.join("d/f0001");
        fs::remove_file(&target).unwrap();
        fs::hard_link(log, &target).unwrap();
    });
    assert!(lent[..30].iter().all(|&lent| lent), "{lent:?}");
    assert!(!terminal);
    assert!(matches!(failure, Some(RarDiagnosticFailure::AliasTarget { ordinal: 1 })), "{failure:?}");
    // published targets the run still owned are untouched by diagnostics
    for i in 2..TAMPERED {
        let name = format!("d/f{i:04}");
        assert_eq!(fs::read(dir.path().join("out").join(&name)).unwrap(), name.as_bytes());
    }
}

#[test]
fn running_out_of_proof_work_is_reported_not_only_a_refused_writer() {
    struct Snapshots(Vec<RarDiagnosticState>);
    impl RarExtractObserver for Snapshots {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            Ok(RarOverwriteDecision::Replace)
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            let _ = diagnostic.writer();
            self.0.push(diagnostic.snapshot().state);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let first = many_members(dir.path(), 20);
    let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut limits = RarExtractControlLimits::default();
    limits.diagnostics.work = 500_000;
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(dir.path().join("log")).unwrap()),
        RarOverwriteMode::Always,
        limits,
    );
    let mut observer = Snapshots(Vec::new());
    let report = session.extract_selected_controlled(
        &selected,
        &options(&dir.path().join("out")),
        RarDecodeLimits::default(),
        &mut control,
        &mut observer,
    );
    // the run itself is unaffected; the observer sees why writers stopped, and so does the report
    assert_eq!(report.outcome().as_ref().unwrap().files, 20);
    let muted = RarDiagnosticState::Muted(RarDiagnosticFailureKind::Limit);
    assert_eq!(observer.0.first(), Some(&RarDiagnosticState::AllowedByBindings));
    assert_eq!(observer.0.last(), Some(&muted));
    assert!(matches!(report.diagnostic_failure(), Some(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Work))));
    let finished = report.finish();
    assert!(matches!(finished.diagnostic_failure, Some(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Work))));
    assert!(finished.usage.diagnostics.work <= 500_000);
}
