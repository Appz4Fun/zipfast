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

//! Controlled RAR extraction lends the diagnostic writer for every failure line of a large run in which every
//! member fails its checksum, and a diagnostic limit that does run out is reported, never a silent stop.
#![cfg(unix)]
mod common;
use common::*;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
use zipfast::extract::{Mode, Options, Overwrite, RarEntryOutcome, RarOutcome};
use zipfast::rar5::session::*;

fn options(dest: &Path, keep_broken: bool) -> Options {
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
        keep_broken,
        attempt_continued_members: false,
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        unsupported_filters: Default::default(),
        damaged_input: Default::default(),
        encrypted_links: Default::default(),
        unverified_output: Default::default(),
        hard_link_targets: Default::default(),
        seven_zip_strict: Default::default(),
        rar4_raw_names: false,
        folder_times: Default::default(),
    }
}

/// Logs one line per outcome through the lent writer, as Prybar does, and keeps what it wrote.
struct Logger {
    lines: u64,
    failed: u64,
    expected: Vec<u8>,
}
impl RarExtractObserver for Logger {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, outcome: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
        if matches!(outcome.outcome, RarOutcome::Failed(_)) {
            self.failed += 1;
        }
        let line = format!("{}: {:?}\n", outcome.entry.name, outcome.outcome);
        if let Some(file) = diagnostic.writer() {
            file.write_all(line.as_bytes()).unwrap();
            self.lines += 1;
            self.expected.extend_from_slice(line.as_bytes());
        }
    }
}

/// Extracts `members` stored members, every one failing its CRC, through the controlled route with a regular log and
/// `limits`, and returns how it finished, the observer, and the log's bytes.
fn run(members: usize, keep_broken: bool, limits: RarExtractControlLimits) -> (RarExtractFinished, Logger, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..members).map(|i| format!("d/f{i:05}")).collect();
    let specs: Vec<(FileSpec<'_>, u32)> =
        names.iter().map(|name| (FileSpec::new(name, name.as_bytes()), crc32fast::hash(b"not the data"))).collect();
    let path = dir.path().join("bad.rar");
    fs::write(&path, archive_with(&specs, false)).unwrap();
    let dest = dir.path().join("out");
    fs::create_dir_all(&dest).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let log = dir.path().join("log");
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
        RarOverwriteMode::Always,
        limits,
    );
    let mut observer = Logger { lines: 0, failed: 0, expected: Vec::new() };
    let report = session.extract_selected_controlled(
        &selected,
        &options(&dest, keep_broken),
        RarDecodeLimits::default(),
        &mut control,
        &mut observer,
    );
    let finished = report.finish();
    let summary = finished.outcome.as_ref().unwrap();
    assert_eq!((summary.files, summary.failed), (0, members as u64), "keep_broken {keep_broken}");
    assert_eq!(observer.failed, members as u64);
    assert_eq!(fs::read(dest.join(&names[members - 1])).is_ok(), keep_broken);
    let written = fs::read(&log).unwrap();
    (finished, observer, written)
}

/// Prybar (`unrar x`, stderr on a regular file): a 2,500-member RAR whose every member fails its CRC seemed to stop
/// its diagnostics after ~1,309 members. That cut was Prybar's own message budget; this pins that zipfast lends the
/// writer for every failure line of such a run, with default limits, whether broken files are kept or not.
#[test]
fn diagnostics_last_through_2500_failing_members() {
    for keep_broken in [false, true] {
        let (finished, observer, written) = run(2500, keep_broken, RarExtractControlLimits::default());
        assert!(
            finished.diagnostic_failure.is_none(),
            "keep_broken {keep_broken}: {:?} after {:?}",
            finished.diagnostic_failure,
            finished.usage.diagnostics
        );
        assert!(!matches!(finished.last_diagnostic.state, RarDiagnosticState::Muted(_)), "keep_broken {keep_broken}");
        assert_eq!(observer.lines, 2500, "keep_broken {keep_broken}");
        assert_eq!(written, observer.expected, "keep_broken {keep_broken}");
        assert_eq!(written.iter().filter(|&&b| b == b'\n').count(), 2500);
        assert!(written.ends_with(b"\n"));
    }
}

/// A deliberately tiny explicit I/O-attempt limit over a failing run is reported as that limit, and the log holds
/// only the whole lines written before it.
#[test]
fn a_tiny_io_attempt_limit_over_failing_members_is_reported() {
    let limits = RarExtractControlLimits {
        diagnostics: RarDiagnosticLimits { io_attempts: 200, ..Default::default() },
        ..Default::default()
    };
    let (finished, observer, written) = run(200, false, limits);
    assert!(
        matches!(finished.diagnostic_failure, Some(RarDiagnosticFailure::Limit(RarDiagnosticLimit::IoAttempts))),
        "{:?}",
        finished.diagnostic_failure
    );
    assert!(matches!(finished.last_diagnostic.state, RarDiagnosticState::Muted(RarDiagnosticFailureKind::Limit)));
    assert!(observer.lines < 200, "{}", observer.lines);
    assert_eq!(written, observer.expected);
    assert!(written.is_empty() || written.ends_with(b"\n"));
}
