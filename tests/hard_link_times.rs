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

//! The modification time of a hard-linked file. Both names share one inode, so one time. UnRAR 7.30 (`x`, `x -o-`)
//! and GNU tar never set a hard link member's own time: the file keeps the time its target was given, or the time of
//! a file already there. 7-Zip 26.06 (`x`, `x -aos`, RAR 5.0 and tar alike) sets the link member's time on the file
//! after linking, a file that was there before the run too. zipfast keeps UnRAR's (the default) and takes 7-Zip's
//! under `UnixModes::Masked`, 7-Zip's metadata. See `docs/compat-options.md`.
//!
//! In `hl.rar` and `hl.tar` the target `t/hard66` has time 1_600_000_000 (mode 0644) and the hard link
//! `t/9iv20ci0cx` has 1_700_000_000 (mode 0600); a `t/hard66` already in the destination has 1_577_865_600 (0640).
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use common::{FileSpec, archive};
use zipfast::extract::{self, HardLinkTargets, Mode, Options, Overwrite, UnixModes};
use zipfast::rar5::session::{
    RarDecisionError, RarDecodeLimits, RarDiagnostic, RarExtractControl, RarExtractControlLimits, RarExtractObserver,
    RarOverwriteConflict, RarOverwriteDecision, RarOverwriteMode, RarSession, RarSessionOptions,
};

const TARGET: i64 = 1_600_000_000;
const LINK: i64 = 1_700_000_000;
const BEFORE: i64 = 1_577_865_600;
const MASKED: UnixModes = UnixModes::Masked { umask: 0o022 };

fn hl_rar(dir: &Path) -> PathBuf {
    let mut body = Vec::new();
    for v in [5, 4, 0, 8] {
        common::vint(v, &mut body);
    }
    body.extend(b"t/hard66");
    let mut extra = Vec::new();
    common::vint(body.len() as u64, &mut extra);
    extra.extend(body);
    let rar = dir.join("hl.rar");
    let files = [
        FileSpec { mtime: Some(TARGET as u32), ..FileSpec::new("t/hard66", b"new") },
        FileSpec { extra, mtime: Some(LINK as u32), unix_mode: Some(0o600), ..FileSpec::new("t/9iv20ci0cx", b"") },
    ];
    fs::write(&rar, archive(&files)).unwrap();
    rar
}

/// A ustar archive of `t/hard66` and the hard link `t/9iv20ci0cx` to it, each with its own time.
fn hl_tar(dir: &Path) -> PathBuf {
    let mut out = Vec::new();
    for (name, kind, mtime, body) in
        [("t/hard66", b'0', TARGET, &b"new"[..]), ("t/9iv20ci0cx", b'1', LINK, &b"t/hard66"[..])]
    {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let size = if kind == b'0' { body.len() } else { 0 };
        let mut octal = |at: usize, width: usize, v: u64| {
            h[at..at + width].copy_from_slice(format!("{v:0w$o}\0", w = width - 1).as_bytes());
        };
        octal(100, 8, if kind == b'0' { 0o644 } else { 0o600 });
        octal(108, 8, 0);
        octal(116, 8, 0);
        octal(124, 12, size as u64);
        octal(136, 12, mtime as u64);
        h[156] = kind;
        if kind == b'1' {
            h[157..157 + body.len()].copy_from_slice(body);
        }
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend(h);
        if kind == b'0' {
            out.extend(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
    }
    out.extend([0u8; 1024]);
    let tar = dir.join("hl.tar");
    fs::write(&tar, out).unwrap();
    tar
}

fn options(dest: &Path, overwrite: Overwrite, unix_modes: UnixModes) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite,
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
        rar4_raw_names: false,
        folder_times: Default::default(),
        unix_modes,
        backslashes: Default::default(),
        hard_link_targets: HardLinkTargets::StoredName,
    }
}

#[derive(Clone, Copy, Debug)]
enum Runner {
    /// `extract::run_with_password`, the whole-archive runner
    Run,
    Selected,
    Controlled,
}

struct Replace;
impl RarExtractObserver for Replace {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, _: &extract::RarEntryOutcome, _: RarDiagnostic<'_>) {}
}

/// Extracts `archive` into `out` with `overwrite` (`Always` or `Skip`) and `unix_modes`; returns the members failed.
fn run(runner: Runner, archive: &Path, out: &Path, overwrite: Overwrite, unix_modes: UnixModes) -> u64 {
    match runner {
        Runner::Run => {
            let summary = extract::run_with_password(archive, &options(out, overwrite, unix_modes), None, |_| {});
            summary.unwrap().errors.len() as u64
        }
        Runner::Selected => {
            let mut session = RarSession::open(archive, None, RarSessionOptions::default()).unwrap();
            let selection = session.select(|_| true).unwrap();
            let opts = options(out, overwrite, unix_modes);
            session.extract_selected(&selection, &opts, RarDecodeLimits::default(), |_| {}).unwrap().failed
        }
        Runner::Controlled => {
            let mut session = RarSession::open(archive, None, RarSessionOptions::default()).unwrap();
            let selection = session.select(|_| true).unwrap();
            let mode = if overwrite == Overwrite::Skip { RarOverwriteMode::Skip } else { RarOverwriteMode::Always };
            // with a diagnostic file, so its guard checks what setting the time touched as the run's own change
            let log = fs::File::options().create_new(true).append(true).open(out.with_extension("log")).unwrap();
            let mut control = RarExtractControl::new(Some(log), mode, RarExtractControlLimits::default());
            let opts = options(out, Overwrite::Always, unix_modes);
            let report = session.extract_selected_controlled(
                &selection,
                &opts,
                RarDecodeLimits::default(),
                &mut control,
                &mut Replace,
            );
            let failed = report.outcome().as_ref().unwrap().failed;
            let finished = report.finish();
            assert!(finished.diagnostic_failure.is_none(), "{:?}", finished.diagnostic_failure);
            failed
        }
    }
}

fn mtime(path: &Path) -> i64 {
    fs::symlink_metadata(path).unwrap().mtime()
}

fn check(archive: &Path, out: &Path, runner: Runner, unix_modes: UnixModes, before: bool) {
    if before {
        fs::create_dir_all(out.join("t")).unwrap();
        fs::write(out.join("t/hard66"), b"OLD").unwrap();
        let at = UNIX_EPOCH + Duration::from_secs(BEFORE as u64);
        let file = fs::File::options().write(true).open(out.join("t/hard66")).unwrap();
        file.set_modified(at).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o640)).unwrap();
    }
    let overwrite = if before { Overwrite::Skip } else { Overwrite::Always };
    let failed = run(runner, archive, out, overwrite, unix_modes);
    let what = format!("{runner:?} {unix_modes:?} before={before} {archive:?}");
    assert_eq!(failed, 0, "{what}");
    let (link, target) = (out.join("t/9iv20ci0cx"), out.join("t/hard66"));
    assert_eq!(fs::symlink_metadata(&link).unwrap().ino(), fs::symlink_metadata(&target).unwrap().ino(), "{what}");
    let expected = match (unix_modes, before) {
        (UnixModes::Stored, false) => TARGET,
        (UnixModes::Stored, true) => BEFORE,
        _ => LINK,
    };
    assert_eq!((mtime(&link), mtime(&target)), (expected, expected), "{what}");
    // the link member's own mode (0600) is never set on the shared file, as 7-Zip leaves it (UnRAR sets it)
    let mode = fs::symlink_metadata(&target).unwrap().mode() & 0o777;
    assert_eq!(mode, if before { 0o640 } else { 0o644 }, "{what}");
}

/// `x` and `x -o-`/`-aos` of `hl.rar`, through the whole-archive runner and both `RarSession` routes.
#[test]
fn rar_hard_links_take_their_own_time_only_as_seven_zip_sets_it() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = hl_rar(tmp.path());
    for (i, runner) in [Runner::Run, Runner::Selected, Runner::Controlled].into_iter().enumerate() {
        for (j, unix_modes) in [UnixModes::Stored, MASKED].into_iter().enumerate() {
            for before in [false, true] {
                check(&rar, &tmp.path().join(format!("rar-{i}-{j}-{before}")), runner, unix_modes, before);
            }
        }
    }
}

/// The same with `hl.tar`: 7-Zip sets a tar hard link's time as it does a RAR one's; GNU tar leaves it as UnRAR does.
#[test]
fn tar_hard_links_take_their_own_time_only_as_seven_zip_sets_it() {
    let tmp = tempfile::tempdir().unwrap();
    let tar = hl_tar(tmp.path());
    for (j, unix_modes) in [UnixModes::Stored, MASKED].into_iter().enumerate() {
        for before in [false, true] {
            check(&tar, &tmp.path().join(format!("tar-{j}-{before}")), Runner::Run, unix_modes, before);
        }
    }
}
