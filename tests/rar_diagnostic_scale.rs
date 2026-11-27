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

//! The controlled route's default diagnostic limits are floors that grow with the prepared selection (Prybar: with
//! stderr on a regular file, 2,200 members under an ~1,850-byte-deep destination ran out of proof work, and 20,000
//! members ran out of parents, though extraction completed).
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
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// Logs one line at every outcome, as Prybar does, and counts the writers it was lent.
struct Logger {
    written: u64,
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
        if let Some(file) = diagnostic.writer() {
            file.write_all(b"entry\n").unwrap();
            self.written += 1;
        }
    }
}

/// Extracts `members` stored members `d/fNNNNN` under a destination nested to at least `depth_bytes` (in folders of
/// `folder` bytes) through the controlled route, with a regular log and `limits`, and returns how it finished.
fn run(members: usize, folder: usize, depth_bytes: usize, limits: RarExtractControlLimits) -> RarExtractFinished {
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..members).map(|i| format!("d/f{i:05}")).collect();
    let specs: Vec<FileSpec<'_>> = names.iter().map(|name| FileSpec::new(name, name.as_bytes())).collect();
    let path = dir.path().join("many.rar");
    fs::write(&path, archive(&specs)).unwrap();
    let mut dest = dir.path().join("out");
    let segment = "a".repeat(folder);
    while dest.as_os_str().len() < depth_bytes {
        dest.push(&segment);
    }
    fs::create_dir_all(&dest).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let log = dir.path().join("log");
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
        RarOverwriteMode::Always,
        limits,
    );
    let mut observer = Logger { written: 0 };
    let report = session.extract_selected_controlled(
        &selected,
        &options(&dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut observer,
    );
    let finished = report.finish();
    assert_eq!(finished.outcome.as_ref().unwrap().files, members as u64);
    let last: PathBuf = dest.join(&names[members - 1]);
    assert_eq!(fs::read(last).unwrap(), names[members - 1].as_bytes());
    if finished.diagnostic_failure.is_none() {
        assert_eq!(observer.written, members as u64);
        assert_eq!(fs::read(&log).unwrap().len(), members * 6);
    }
    finished
}

fn assert_not_limited(finished: &RarExtractFinished, what: &str) {
    assert!(
        finished.diagnostic_failure.is_none(),
        "{what}: {:?} after {:?}",
        finished.diagnostic_failure,
        finished.usage.diagnostics
    );
    assert!(!matches!(finished.last_diagnostic.state, RarDiagnosticState::Muted(_)), "{what}");
}

#[test]
fn diagnostics_last_through_2200_members_under_a_deep_destination() {
    // The proof work per member grows with its path's length times its depth. A probe names the whole absolute
    // path, which macOS limits to 1,024 bytes (Linux to 4,096), so there the destination is ~900 bytes deep.
    let depth_bytes = if cfg!(target_os = "linux") { 1850 } else { 900 };
    let finished = run(2200, 8, depth_bytes, RarExtractControlLimits::default());
    assert_not_limited(&finished, "deep destination");
    // the old fixed default was spent several times over
    assert!(finished.usage.diagnostics.work > RarDiagnosticLimits::DEFAULT_WORK, "{:?}", finished.usage.diagnostics);
}

#[test]
fn diagnostics_last_through_20000_members() {
    // each member admits a parent per component of its absolute target, ~10 here: past the 131,072 default
    let finished = run(20_000, 8, 0, RarExtractControlLimits::default());
    assert_not_limited(&finished, "20,000 members");
}

#[test]
fn explicit_diagnostic_limits_stay_exact() {
    for (limit, expected) in [
        (RarDiagnosticLimits { parents: 50, ..Default::default() }, RarDiagnosticLimit::Parents),
        (RarDiagnosticLimits { targets: 5, ..Default::default() }, RarDiagnosticLimit::Targets),
        (RarDiagnosticLimits { work: 200_000, ..Default::default() }, RarDiagnosticLimit::Work),
    ] {
        let limits = RarExtractControlLimits { diagnostics: limit, ..Default::default() };
        let finished = run(20, 8, 0, limits);
        assert!(
            matches!(finished.diagnostic_failure, Some(RarDiagnosticFailure::Limit(found)) if found == expected),
            "{expected:?}: {:?}",
            finished.diagnostic_failure
        );
    }
}

/// Codex on #305: the scaling pass is proof work too. Against an explicit work limit it is charged name by name, so
/// a tiny limit over many members is reported as spent (never exceeded) before the pass runs through them all.
#[test]
fn a_tiny_explicit_work_limit_covers_the_scaling_pass() {
    let limits = RarExtractControlLimits {
        diagnostics: RarDiagnosticLimits { work: 50, ..Default::default() },
        ..Default::default()
    };
    let finished = run(2000, 8, 0, limits);
    assert!(
        matches!(finished.diagnostic_failure, Some(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Work))),
        "{:?}",
        finished.diagnostic_failure
    );
    assert!(finished.usage.diagnostics.work <= 50, "{:?}", finished.usage.diagnostics);
}
