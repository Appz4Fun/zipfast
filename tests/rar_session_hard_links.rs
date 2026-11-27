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

//! `RarSession::extract_selected` and `extract_selected_controlled` honour `extract::Options::hard_link_targets`, or
//! `RarSessionOptions::hard_link_targets` where the options keep the default, as the whole-archive RAR runner does
//! (see `docs/compat-options.md`, `hard_link_targets`). `hl.rar` holds `t/hard66` and the hard link
//! `t/9iv20ci0cx -> t/hard66`; with `t/hard66` (`OLD`) in the destination before the run, UnRAR 7.30 links
//! `t/9iv20ci0cx` to the old file under `x -or`, `x -o-` and `e -or`, and exits 0.
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod common;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use common::{FileSpec, archive};
use zipfast::extract::{self, HardLinkTargets, Mode, Options, Overwrite, RenameStyle};
use zipfast::rar5::session::{
    RarDecisionError, RarDecodeLimits, RarDiagnostic, RarExtractControl, RarExtractControlLimits, RarExtractObserver,
    RarOverwriteConflict, RarOverwriteDecision, RarOverwriteMode, RarSession, RarSessionOptions,
};

/// A RAR 5.0 hard link redirection extra record to `target`.
fn hard_link_record(target: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for v in [5, 4, 0, target.len() as u64] {
        common::vint(v, &mut body);
    }
    body.extend(target.as_bytes());
    let mut extra = Vec::new();
    common::vint(body.len() as u64, &mut extra);
    extra.extend(body);
    extra
}

fn hl_rar(dir: &Path) -> PathBuf {
    let rar = dir.join("hl.rar");
    let files = [
        FileSpec { mtime: Some(1_600_000_000), ..FileSpec::new("t/hard66", b"new") },
        FileSpec { extra: hard_link_record("t/hard66"), ..FileSpec::new("t/9iv20ci0cx", b"") },
    ];
    fs::write(&rar, archive(&files)).unwrap();
    rar
}

fn options(dest: &Path, overwrite: Overwrite, flatten: bool, hard_link_targets: HardLinkTargets) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite,
        flatten,
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
        rar4_raw_names: false,
        folder_times: Default::default(),
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets,
    }
}

/// Where the setting comes from.
#[derive(Clone, Copy, Debug)]
enum Via {
    Options,
    Session,
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Selected,
    Controlled,
}

/// Answers no question (the options' rename mode or the control's mode settles each conflict) and writes a line of
/// the diagnostic file for every outcome.
#[derive(Default)]
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
        panic!("no conflict is asked about")
    }
    fn entry(&mut self, _: &extract::RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
        match diagnostic.writer() {
            Some(file) => {
                file.write_all(b"entry\n").unwrap();
                self.written += 1;
            }
            None => self.refused += 1,
        }
    }
}

/// Extracts `rar` into `out` through `route`, with `targets` set `via` the options or the session, and returns the
/// members that failed.
fn run(
    rar: &Path,
    out: &Path,
    route: Route,
    via: Via,
    overwrite: Overwrite,
    flatten: bool,
    targets: HardLinkTargets,
) -> u64 {
    let (in_options, in_session) = match via {
        Via::Options => (targets, HardLinkTargets::Extracted),
        Via::Session => (HardLinkTargets::Extracted, targets),
    };
    let session_options = RarSessionOptions { hard_link_targets: in_session, ..RarSessionOptions::default() };
    let mut session = RarSession::open(rar, None, session_options).unwrap();
    let selection = session.select(|_| true).unwrap();
    match route {
        Route::Selected => {
            // Overwrite::Skip is the options' own in this route
            let opts = options(out, overwrite, flatten, in_options);
            let summary = session.extract_selected(&selection, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
            summary.failed
        }
        Route::Controlled => {
            // here the control's mode skips; the options' rename mode settles conflicts itself
            let (legacy, mode) = match overwrite {
                Overwrite::Skip => (Overwrite::Always, RarOverwriteMode::Skip),
                other => (other, RarOverwriteMode::Always),
            };
            let opts = options(out, legacy, flatten, in_options);
            // with a diagnostic file, so its guard checks what the hard link touched as the run's own change
            let log = out.with_extension("log");
            let file = OpenOptions::new().create_new(true).append(true).open(&log).unwrap();
            let mut control = RarExtractControl::new(Some(file), mode, RarExtractControlLimits::default());
            let mut observer = Logger::default();
            let report = session.extract_selected_controlled(
                &selection,
                &opts,
                RarDecodeLimits::default(),
                &mut control,
                &mut observer,
            );
            let failed = report.outcome().as_ref().unwrap().failed;
            let finished = report.finish();
            assert!(finished.diagnostic_failure.is_none(), "{:?}", finished.diagnostic_failure);
            assert_eq!((observer.written, observer.refused), (2, 0));
            failed
        }
    }
}

fn inode(path: &Path) -> u64 {
    fs::symlink_metadata(path).unwrap().ino()
}

const ROUTES: [(Route, Via); 4] = [
    (Route::Selected, Via::Options),
    (Route::Selected, Via::Session),
    (Route::Controlled, Via::Options),
    (Route::Controlled, Via::Session),
];

/// prybar: UnRAR mode `x -or` with `t/hard66` there: the new file lands as `t/hard66(1)` and the link goes to the
/// old `t/hard66`, as UnRAR 7.30 makes it. The default links to the renamed new file.
#[test]
fn rename_new_links_to_the_file_at_the_stored_name() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = hl_rar(tmp.path());
    let rename = Overwrite::RenameNew(RenameStyle::Parenthesized);
    for (i, (route, via)) in ROUTES.into_iter().enumerate() {
        for targets in [HardLinkTargets::Extracted, HardLinkTargets::StoredName] {
            let out = tmp.path().join(format!("or-{i}-{targets:?}"));
            fs::create_dir_all(out.join("t")).unwrap();
            fs::write(out.join("t/hard66"), b"OLD").unwrap();
            let failed = run(&rar, &out, route, via, rename, false, targets);
            assert_eq!(failed, 0, "{route:?} {via:?} {targets:?}");
            assert_eq!(fs::read(out.join("t/hard66(1)")).unwrap(), b"new");
            let linked = if targets == HardLinkTargets::StoredName { "t/hard66" } else { "t/hard66(1)" };
            assert_eq!(inode(&out.join("t/9iv20ci0cx")), inode(&out.join(linked)), "{route:?} {via:?} {targets:?}");
        }
    }
}

/// prybar: UnRAR mode `x -o-` with `t/hard66` there: the target member is skipped and the link goes to what is
/// there, exit 0 (zipfast's default fails the link: its target wasn't extracted).
#[test]
fn skip_existing_links_to_the_file_left_there() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = hl_rar(tmp.path());
    for (i, (route, via)) in ROUTES.into_iter().enumerate() {
        for targets in [HardLinkTargets::Extracted, HardLinkTargets::StoredName] {
            let out = tmp.path().join(format!("skip-{i}-{targets:?}"));
            fs::create_dir_all(out.join("t")).unwrap();
            fs::write(out.join("t/hard66"), b"OLD").unwrap();
            let failed = run(&rar, &out, route, via, Overwrite::Skip, false, targets);
            assert_eq!(fs::read(out.join("t/hard66")).unwrap(), b"OLD");
            if targets == HardLinkTargets::StoredName {
                assert_eq!(failed, 0, "{route:?} {via:?}");
                assert_eq!(inode(&out.join("t/9iv20ci0cx")), inode(&out.join("t/hard66")), "{route:?} {via:?}");
            } else {
                assert_eq!(failed, 1, "{route:?} {via:?}");
                assert!(fs::symlink_metadata(out.join("t/9iv20ci0cx")).is_err(), "{route:?} {via:?}");
            }
        }
    }
}

/// prybar: UnRAR mode `e -or` with `hard66` there: flattened, the link `9iv20ci0cx` goes to the old `hard66`.
#[test]
fn flattened_rename_links_to_the_flattened_name() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = hl_rar(tmp.path());
    let rename = Overwrite::RenameNew(RenameStyle::Parenthesized);
    for (i, (route, via)) in ROUTES.into_iter().enumerate() {
        let out = tmp.path().join(format!("e-{i}"));
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("hard66"), b"OLD").unwrap();
        let failed = run(&rar, &out, route, via, rename, true, HardLinkTargets::StoredName);
        assert_eq!(failed, 0, "{route:?} {via:?}");
        assert_eq!(fs::read(out.join("hard66(1)")).unwrap(), b"new");
        assert_eq!(inode(&out.join("9iv20ci0cx")), inode(&out.join("hard66")), "{route:?} {via:?}");
    }
}

/// The link-safety rules hold in the session too: a symbolic link or a folder at the target's name is never linked
/// to, and nothing outside the destination is touched.
#[test]
fn symbolic_links_and_folders_at_the_stored_name_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = hl_rar(tmp.path());
    let outside = tmp.path().join("outside.txt");
    fs::write(&outside, b"secret").unwrap();
    let rename = Overwrite::RenameNew(RenameStyle::Parenthesized);
    for (i, (route, via)) in ROUTES.into_iter().enumerate() {
        for what in ["symlink", "folder"] {
            let out = tmp.path().join(format!("{what}-{i}"));
            fs::create_dir_all(out.join("t")).unwrap();
            match what {
                "symlink" => std::os::unix::fs::symlink(&outside, out.join("t/hard66")).unwrap(),
                _ => fs::create_dir(out.join("t/hard66")).unwrap(),
            }
            let failed = run(&rar, &out, route, via, rename, false, HardLinkTargets::StoredName);
            // the link fails; under a symbolic link `t/hard66` itself fails too, renamed or not
            assert!(failed >= 1, "{what} {route:?} {via:?}");
            assert!(fs::symlink_metadata(out.join("t/9iv20ci0cx")).is_err(), "{what} {route:?} {via:?}");
        }
    }
    assert_eq!(fs::read(&outside).unwrap(), b"secret");
    assert_eq!(fs::metadata(&outside).unwrap().nlink(), 1);
}

/// Options' StoredName wins over a session keeping the default, and nothing in the way gives the same link either way.
#[test]
fn nothing_in_the_way_links_to_the_extracted_file() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = hl_rar(tmp.path());
    for (i, (route, via)) in ROUTES.into_iter().enumerate() {
        let out = tmp.path().join(format!("plain-{i}"));
        let failed = run(&rar, &out, route, via, Overwrite::Always, false, HardLinkTargets::StoredName);
        assert_eq!(failed, 0, "{route:?} {via:?}");
        assert_eq!(inode(&out.join("t/9iv20ci0cx")), inode(&out.join("t/hard66")));
        assert_eq!(fs::read(out.join("t/9iv20ci0cx")).unwrap(), b"new");
    }
}

/// Codex on #335: with the archive inside the destination, a hard link to the archive's own name never links it
/// (nor sets its time under `UnixModes::Masked`): the member is refused and the run goes on to the next one. (Linked,
/// the session would find its volume changed and stop.)
#[test]
fn the_archive_itself_is_never_a_stored_name_link_target() {
    let tmp = tempfile::tempdir().unwrap();
    let files = [
        FileSpec { extra: hard_link_record("in.rar"), ..FileSpec::new("alias", b"") },
        FileSpec::new("after", b"after"),
    ];
    let bytes = archive(&files);
    for (i, route) in [None, Some(Route::Selected), Some(Route::Controlled)].into_iter().enumerate() {
        let out = tmp.path().join(format!("self-{i}"));
        fs::create_dir_all(&out).unwrap();
        let rar = out.join("in.rar");
        fs::write(&rar, &bytes).unwrap();
        let before = fs::metadata(&rar).unwrap();
        let mut session = RarSession::open(&rar, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let opts = Options {
            unix_modes: extract::UnixModes::Masked { umask: 0o022 },
            ..options(&out, Overwrite::Always, false, HardLinkTargets::StoredName)
        };
        let (files, failed) = match route {
            // the whole-archive runner protects its archive the same way
            None => {
                let summary = extract::run_with_password(&rar, &opts, None, |_| {}).unwrap();
                (summary.files, summary.errors.len() as u64)
            }
            Some(Route::Selected) => {
                let summary = session.extract_selected(&selection, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
                (summary.files, summary.failed)
            }
            Some(Route::Controlled) => {
                let mut control =
                    RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
                let report = session.extract_selected_controlled(
                    &selection,
                    &opts,
                    RarDecodeLimits::default(),
                    &mut control,
                    &mut Logger::default(),
                );
                let summary = report.outcome().as_ref().unwrap();
                (summary.files, summary.failed)
            }
        };
        assert_eq!((files, failed), (1, 1), "{route:?}");
        assert!(fs::symlink_metadata(out.join("alias")).is_err(), "{route:?}");
        assert_eq!(fs::read(out.join("after")).unwrap(), b"after");
        let after = fs::metadata(&rar).unwrap();
        assert_eq!((after.nlink(), after.mtime(), after.ctime()), (1, before.mtime(), before.ctime()), "{route:?}");
    }
}
