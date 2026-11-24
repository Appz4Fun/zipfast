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

//! `Overwrite::RenameNew` and `Overwrite::RenameExisting` (7-Zip `-aou`/`-aot`, UnRAR `-or`) through every runner.
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use common::{FileSpec, archive as rar_archive};
use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite, RenameStyle, RenamedOutput};
use zipfast::rar5::session::{
    RarDecisionError, RarDecodeLimits, RarDiagnostic, RarExtractControl, RarExtractControlLimits, RarExtractObserver,
    RarOverwriteConflict, RarOverwriteDecision, RarOverwriteMode, RarSession, RarSessionOptions,
};
use zipfast::zip::ZipRunEvent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Zip,
    Tar,
    Rar,
}

/// Every runner that takes `extract::Options` and supports the rename modes.
#[derive(Clone, Copy, Debug)]
enum Runner {
    /// `extract::run`: the legacy ZIP, tar or RAR runner.
    Run(Family),
    /// `extract::run_with_zip_policy`: checked ZIP, or the legacy tar and RAR runners reporting through events.
    Policy(Family),
    /// `extract::run_with_zip_context`.
    Context(Family),
    RarOutcomes,
    RarSelected,
    RarControlled,
}

const RUNNERS: [Runner; 12] = [
    Runner::Run(Family::Zip),
    Runner::Run(Family::Tar),
    Runner::Run(Family::Rar),
    Runner::Policy(Family::Zip),
    Runner::Policy(Family::Tar),
    Runner::Policy(Family::Rar),
    Runner::Context(Family::Zip),
    Runner::Context(Family::Tar),
    Runner::Context(Family::Rar),
    Runner::RarOutcomes,
    Runner::RarSelected,
    Runner::RarControlled,
];

impl Runner {
    fn family(self) -> Family {
        match self {
            Self::Run(f) | Self::Policy(f) | Self::Context(f) => f,
            Self::RarOutcomes | Self::RarSelected | Self::RarControlled => Family::Rar,
        }
    }
}

/// What a run reported, the same way for every runner.
#[derive(Debug, Default)]
struct Report {
    files: u64,
    failed: u64,
    renames: Vec<(PathBuf, PathBuf, Option<PathBuf>)>,
    /// a terminal error, if the run stopped
    terminal: Option<String>,
    /// the legacy report lines, for `extract::run`
    lines: Vec<String>,
    /// the renames the typed RAR runners delivered with each member's outcome, in order
    live: Vec<(PathBuf, PathBuf, Option<PathBuf>)>,
}

/// Records the rename a typed RAR runner delivers with a member's outcome, checking it is already on disk when the
/// outcome arrives (so it reached the caller as the member finished, not after the run).
fn live(outcome: &extract::RarEntryOutcome, seen: &mut Vec<(PathBuf, PathBuf, Option<PathBuf>)>) {
    if let Some(r) = &outcome.renamed {
        if matches!(outcome.outcome, extract::RarOutcome::Verified { .. }) {
            assert!(fs::symlink_metadata(&r.path).is_ok(), "{r:?} not written when its outcome arrived");
        }
        if let Some(moved) = &r.existing {
            assert!(fs::symlink_metadata(moved).is_ok(), "{r:?} not moved when its outcome arrived");
        }
        seen.push((r.requested.clone(), r.path.clone(), r.existing.clone()));
    }
}

fn renames(list: &[RenamedOutput]) -> Vec<(PathBuf, PathBuf, Option<PathBuf>)> {
    list.iter().map(|r| (r.requested.clone(), r.path.clone(), r.existing.clone())).collect()
}

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in members {
        let crc = zipfast::crc32::hash(data);
        let offset = out.len() as u32;
        let common = |out: &mut Vec<u8>| {
            out.extend(20u16.to_le_bytes()); // version needed
            out.extend(0x0800u16.to_le_bytes()); // UTF-8 names
            out.extend(0u16.to_le_bytes()); // stored
            out.extend(0u16.to_le_bytes()); // time
            out.extend(0x21u16.to_le_bytes()); // 1980-01-01
            out.extend(crc.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes()); // extra
        };
        out.extend(0x04034b50u32.to_le_bytes());
        common(&mut out);
        out.extend(name.as_bytes());
        out.extend(*data);
        central.extend(0x02014b50u32.to_le_bytes());
        central.extend(0x0314u16.to_le_bytes()); // made on Unix
        common(&mut central);
        central.extend([0; 6]); // comment, disk, internal attributes
        central.extend((0o100644u32 << 16).to_le_bytes());
        central.extend(offset.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let start = out.len() as u32;
    out.extend(&central);
    out.extend(0x06054b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(start.to_le_bytes());
    out.extend([0; 2]);
    out
}

fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in members {
        if name.len() > 100 {
            // a GNU long-name record carries a name ustar's 100 bytes can't
            let mut long = name.as_bytes().to_vec();
            long.push(0);
            out.extend(tar_header("././@LongLink", long.len(), b'L'));
            out.extend(&long);
            out.resize(out.len().next_multiple_of(512), 0);
        }
        out.extend(tar_header(&name[..name.len().min(100)], data.len(), b'0'));
        out.extend(*data);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn tar_header(name: &str, size: usize, kind: u8) -> [u8; 512] {
    {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        header[136..148].copy_from_slice(b"14000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = kind;
        header[257..265].copy_from_slice(b"ustar\x0000");
        let sum: u32 = header.iter().map(|&b| b as u32).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }
}

fn build(family: Family, members: &[(&str, &[u8])]) -> Vec<u8> {
    match family {
        Family::Zip => zip(members),
        Family::Tar => tar(members),
        Family::Rar => {
            let specs: Vec<_> = members.iter().map(|(name, data)| FileSpec::new(name, data)).collect();
            rar_archive(&specs)
        }
    }
}

fn options(dest: &Path, overwrite: Overwrite) -> Options {
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
    }
}

#[derive(Default)]
struct NoQuestions(Vec<(PathBuf, PathBuf, Option<PathBuf>)>);
impl RarExtractObserver for NoQuestions {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        panic!("a rename mode settles conflicts without asking")
    }
    fn entry(&mut self, outcome: &extract::RarEntryOutcome, _: RarDiagnostic<'_>) {
        live(outcome, &mut self.0);
    }
}

fn run(runner: Runner, archive: &Path, opts: &Options) -> Report {
    let mut report = Report::default();
    match runner {
        Runner::Run(_) => {
            let mut lines = Vec::new();
            match extract::run_with_renames(archive, opts, None, |line| lines.push(line.to_string())) {
                Ok(summary) => {
                    report.files = summary.files;
                    report.failed = summary.errors.len() as u64;
                    report.renames = renames(&summary.renames);
                }
                Err(error) => {
                    report.renames = renames(&error.renames);
                    report.terminal = Some(error.to_string());
                }
            }
            report.lines = lines;
        }
        Runner::Policy(_) | Runner::Context(_) => {
            let mut seen = Vec::new();
            let observe = |event: ZipRunEvent<'_>| {
                if let ZipRunEvent::MemberRenamed { renamed, .. } = event {
                    seen.push(renamed.clone());
                }
                Ok(())
            };
            let cancel = Cancellation::default();
            let result = if matches!(runner, Runner::Policy(_)) {
                extract::run_with_zip_policy(archive, opts, None, &cancel, &Default::default(), observe)
            } else {
                let mut context = zipfast::zip::EncryptedReadContext::new(Default::default()).unwrap();
                extract::run_with_zip_context(archive, opts, None, &cancel, &mut context, observe)
            };
            match result {
                Ok(done) => {
                    report.files = done.files();
                    report.failed = done.failed();
                }
                Err(error) => report.terminal = Some(format!("{error:?}")),
            }
            report.renames = renames(&seen);
        }
        Runner::RarOutcomes => match extract::run_rar_with_outcomes(archive, opts, None, |o| live(o, &mut report.live))
        {
            Ok(summary) => {
                report.files = summary.files;
                report.failed = summary.failed;
                report.renames = renames(&summary.renames);
            }
            Err(error) => {
                report.renames = renames(&error.partial.renames);
                report.terminal = Some(error.to_string());
            }
        },
        Runner::RarSelected => {
            let mut session = RarSession::open(archive, None, RarSessionOptions::default()).unwrap();
            let selection = session.select(|_| true).unwrap();
            match session.extract_selected(&selection, opts, RarDecodeLimits::default(), |o| live(o, &mut report.live))
            {
                Ok(summary) => {
                    report.files = summary.files;
                    report.failed = summary.failed;
                    report.renames = renames(&summary.renames);
                }
                Err(error) => {
                    report.renames = renames(&error.partial.renames);
                    report.terminal = Some(error.to_string());
                }
            }
        }
        Runner::RarControlled => {
            let mut session = RarSession::open(archive, None, RarSessionOptions::default()).unwrap();
            let selection = session.select(|_| true).unwrap();
            // The control's own mode is never consulted for a conflict: the options' rename mode settles it.
            let mut control = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
            let mut observer = NoQuestions::default();
            let result = session.extract_selected_controlled(
                &selection,
                opts,
                RarDecodeLimits::default(),
                &mut control,
                &mut observer,
            );
            report.live = std::mem::take(&mut observer.0);
            match result.outcome() {
                Ok(summary) => {
                    report.files = summary.files;
                    report.failed = summary.failed;
                    report.renames = renames(&summary.renames);
                }
                Err(error) => report.terminal = Some(format!("{error:?}")),
            }
        }
    }
    report
}

/// Every file under `root`, by relative path, with its content.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Members covering an existing target, a free target, two duplicates of an existing target, no extension, a
/// multi-dot name, a leading-dot name and a name in a subdirectory.
const MEMBERS: [(&str, &[u8]); 8] = [
    ("a.txt", b"new a"),
    ("fresh.txt", b"new fresh"),
    ("dup.txt", b"new dup 1"),
    ("noext", b"new noext"),
    ("b.tar.gz", b"new b"),
    (".bashrc", b"new bashrc"),
    ("d/sub.txt", b"new sub"),
    ("dup.txt", b"new dup 2"),
];

/// The files that are already in the destination.
const EXISTING: [(&str, &[u8]); 6] = [
    ("a.txt", b"old a"),
    ("dup.txt", b"old dup"),
    ("noext", b"old noext"),
    ("b.tar.gz", b"old b"),
    (".bashrc", b"old bashrc"),
    ("d/sub.txt", b"old sub"),
];

/// The renamed spelling of `name` (relative, maybe in a folder) for number `n`.
fn spelled(name: &str, n: u32, style: RenameStyle) -> String {
    let (dir, leaf) = name.rsplit_once('/').map_or(("", name), |(d, l)| (d, l));
    let leaf = extract::renamed_name(leaf.as_ref(), n, style).into_string().unwrap();
    if dir.is_empty() { leaf } else { format!("{dir}/{leaf}") }
}

/// What the destination holds after the run, and the renames reported, worked out by hand from 7-Zip's and UnRAR's
/// recorded behaviour.
type Expected = (BTreeMap<String, Vec<u8>>, Vec<(String, String, Option<String>)>);

fn expected(overwrite: Overwrite) -> Expected {
    let mut files: BTreeMap<String, Vec<u8>> = EXISTING.iter().map(|(n, d)| (n.to_string(), d.to_vec())).collect();
    let mut renames = Vec::new();
    for (name, data) in MEMBERS {
        if !files.contains_key(name) {
            files.insert(name.into(), data.to_vec());
            continue;
        }
        let (style, existing) = match overwrite {
            Overwrite::RenameNew(style) => (style, false),
            Overwrite::RenameExisting(style) => (style, true),
            _ => unreachable!(),
        };
        let free = (1..).map(|n| spelled(name, n, style)).find(|c| !files.contains_key(c)).unwrap();
        if existing {
            let old = files.insert(name.into(), data.to_vec()).unwrap();
            files.insert(free.clone(), old);
            renames.push((name.to_string(), name.to_string(), Some(free)));
        } else {
            files.insert(free.clone(), data.to_vec());
            renames.push((name.to_string(), free, None));
        }
    }
    (files, renames)
}

const MODES: [Overwrite; 4] = [
    Overwrite::RenameNew(RenameStyle::Underscore),
    Overwrite::RenameNew(RenameStyle::Parenthesized),
    Overwrite::RenameExisting(RenameStyle::Underscore),
    Overwrite::RenameExisting(RenameStyle::Parenthesized),
];

#[test]
fn every_runner_renames_like_7zip_and_unrar() {
    for runner in RUNNERS {
        for overwrite in MODES {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.bin");
            fs::write(&archive, build(runner.family(), &MEMBERS)).unwrap();
            let dest = dir.path().join("out");
            fs::create_dir_all(dest.join("d")).unwrap();
            for (name, data) in EXISTING {
                fs::write(dest.join(name), data).unwrap();
            }
            let report = run(runner, &archive, &options(&dest, overwrite));
            let context = format!("{runner:?} {overwrite:?}: {report:?}");
            assert_eq!(report.terminal, None, "{context}");
            assert_eq!((report.files, report.failed), (MEMBERS.len() as u64, 0), "{context}");
            let (files, renamed) = expected(overwrite);
            assert_eq!(tree(&dest), files, "{context}");
            let absolute = |rel: &String| dest.join(rel);
            let renamed: Vec<_> =
                renamed.iter().map(|(r, p, e)| (absolute(r), absolute(p), e.as_ref().map(absolute))).collect();
            assert_eq!(report.renames, renamed, "{context}");
            if typed_rar(runner) {
                assert_eq!(report.live, renamed, "{context}: each rename arrives with its member's outcome");
            }
        }
    }
}

/// The runners that report each RAR member's outcome as it finishes.
fn typed_rar(runner: Runner) -> bool {
    matches!(runner, Runner::RarOutcomes | Runner::RarSelected | Runner::RarControlled)
}

#[test]
fn the_names_match_the_recorded_reference_behaviour() {
    let (files, renames) = expected(Overwrite::RenameNew(RenameStyle::Underscore));
    for name in ["a_1.txt", "dup_1.txt", "dup_2.txt", "noext_1", "b.tar_1.gz", ".bashrc_1", "d/sub_1.txt"] {
        assert!(files.contains_key(name), "{name}");
    }
    assert_eq!(renames.len(), 7);
    let (files, _) = expected(Overwrite::RenameNew(RenameStyle::Parenthesized));
    for name in ["a(1).txt", "dup(1).txt", "dup(2).txt", "noext(1)", "b.tar(1).gz", "(1).bashrc", "d/sub(1).txt"] {
        assert!(files.contains_key(name), "{name}");
    }
    // -aot: the existing file is moved to the renamed name and keeps its content; the new one takes the name
    let (files, _) = expected(Overwrite::RenameExisting(RenameStyle::Underscore));
    assert_eq!(files["a.txt"], b"new a");
    assert_eq!(files["a_1.txt"], b"old a");
    assert_eq!(files["dup.txt"], b"new dup 2");
    assert_eq!(files["dup_1.txt"], b"old dup");
    assert_eq!(files["dup_2.txt"], b"new dup 1");
}

#[test]
fn a_free_target_is_written_in_place_and_reports_no_rename() {
    for runner in RUNNERS {
        for overwrite in MODES {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.bin");
            fs::write(&archive, build(runner.family(), &[("only.txt", b"data")])).unwrap();
            let dest = dir.path().join("out");
            fs::create_dir(&dest).unwrap();
            let report = run(runner, &archive, &options(&dest, overwrite));
            assert_eq!((report.files, report.failed, &report.terminal), (1, 0, &None), "{runner:?} {report:?}");
            assert!(report.renames.is_empty());
            assert_eq!(tree(&dest), BTreeMap::from([("only.txt".to_string(), b"data".to_vec())]));
        }
    }
}

#[test]
fn a_protected_target_is_refused_by_rename_existing_and_written_past_by_rename_new() {
    for runner in RUNNERS {
        for overwrite in MODES {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.bin");
            fs::write(&archive, build(runner.family(), &[("keep.txt", b"new"), ("link.txt", b"new link")])).unwrap();
            let dest = dir.path().join("out");
            fs::create_dir(&dest).unwrap();
            let keep = dest.join("keep.txt");
            fs::write(&keep, b"protected").unwrap();
            // a symlink to the archive at a member's target: an alias of a protected input
            std::os::unix::fs::symlink(&archive, dest.join("link.txt")).unwrap();
            let mut opts = options(&dest, overwrite);
            opts.protected_paths.insert(keep.clone());
            let report = run(runner, &archive, &opts);
            let context = format!("{runner:?} {overwrite:?}: {report:?}");
            assert_eq!(report.terminal, None, "{context}");
            assert_eq!(fs::read(&keep).unwrap(), b"protected", "{context}");
            assert!(fs::symlink_metadata(dest.join("link.txt")).unwrap().file_type().is_symlink(), "{context}");
            let names: Vec<_> = fs::read_dir(&dest).unwrap().map(|e| e.unwrap().file_name()).collect();
            match overwrite {
                // the symlink is refused either way; RenameNew writes past the protected file, replacing nothing
                Overwrite::RenameNew(style) => {
                    let beside = dest.join(spelled("keep.txt", 1, style));
                    assert_eq!((report.files, report.failed), (1, 1), "{context}");
                    assert_eq!(report.renames, [(keep.clone(), beside.clone(), None)], "{context}");
                    assert_eq!(fs::read(&beside).unwrap(), b"new", "{context}");
                    assert_eq!(names.len(), 3, "{context}: {names:?}");
                }
                _ => {
                    assert_eq!((report.files, report.failed), (0, 2), "{context}");
                    assert!(report.renames.is_empty(), "{context}");
                    assert_eq!(names.len(), 2, "{context}: {names:?}");
                }
            }
            assert_eq!(
                fs::read(&archive).unwrap(),
                build(runner.family(), &[("keep.txt", b"new"), ("link.txt", b"new link")])
            );
        }
    }
}

#[test]
fn a_directory_in_the_way_is_renamed_around_or_moved_aside() {
    // Recorded by Prybar from 7-Zip 26.06: a file member `noext` over a folder `noext/` holding `k`. `-aou` writes
    // the member as `noext_1` and leaves the folder alone; `-aot` moves the folder, contents and all, to `noext_1/`
    // with a no-replace rename and writes the member as `noext`.
    for runner in RUNNERS {
        for overwrite in MODES {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.bin");
            fs::write(&archive, build(runner.family(), &[("noext", b"file where a folder is")])).unwrap();
            let dest = dir.path().join("out");
            fs::create_dir_all(dest.join("noext")).unwrap();
            fs::write(dest.join("noext/k"), b"kept").unwrap();
            let report = run(runner, &archive, &options(&dest, overwrite));
            let context = format!("{runner:?} {overwrite:?}: {report:?}");
            assert_eq!(report.terminal, None, "{context}");
            assert_eq!((report.files, report.failed), (1, 0), "{context}");
            let (requested, (style, moved)) = (
                dest.join("noext"),
                match overwrite {
                    Overwrite::RenameNew(style) => (style, false),
                    Overwrite::RenameExisting(style) => (style, true),
                    _ => unreachable!(),
                },
            );
            let beside = dest.join(spelled("noext", 1, style));
            let want: BTreeMap<String, Vec<u8>> = if moved {
                assert!(beside.is_dir(), "{context}");
                assert_eq!(report.renames, [(requested.clone(), requested.clone(), Some(beside.clone()))], "{context}");
                [
                    (format!("{}/k", spelled("noext", 1, style)), b"kept".to_vec()),
                    ("noext".into(), b"file where a folder is".to_vec()),
                ]
                .into()
            } else {
                assert!(requested.is_dir(), "{context}");
                assert_eq!(report.renames, [(requested.clone(), beside.clone(), None)], "{context}");
                [
                    ("noext/k".to_string(), b"kept".to_vec()),
                    (spelled("noext", 1, style), b"file where a folder is".to_vec()),
                ]
                .into()
            };
            assert_eq!(tree(&dest), want, "{context}");
            if typed_rar(runner) {
                assert_eq!(report.live, report.renames, "{context}");
            }
        }
    }
}

#[test]
fn a_directory_holding_a_protected_path_is_never_moved() {
    for runner in RUNNERS {
        for overwrite in MODES {
            // the folder in the way holds a protected file, or the archive itself
            for archive_inside in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let dest = dir.path().join("out");
                fs::create_dir_all(dest.join("noext")).unwrap();
                let archive =
                    if archive_inside { dest.join("noext/archive.bin") } else { dir.path().join("archive.bin") };
                let bytes = build(runner.family(), &[("noext", b"new")]);
                fs::write(&archive, &bytes).unwrap();
                let mut opts = options(&dest, overwrite);
                if !archive_inside {
                    fs::write(dest.join("noext/k"), b"protected").unwrap();
                    opts.protected_paths.insert(dest.join("noext/k"));
                }
                let report = run(runner, &archive, &opts);
                let context = format!("{runner:?} {overwrite:?} archive inside {archive_inside}: {report:?}");
                assert_eq!(report.terminal, None, "{context}");
                assert!(dest.join("noext").is_dir(), "{context}");
                assert_eq!(fs::read(&archive).unwrap(), bytes, "{context}");
                match overwrite {
                    Overwrite::RenameNew(style) => {
                        assert_eq!((report.files, report.failed), (1, 0), "{context}");
                        assert_eq!(fs::read(dest.join(spelled("noext", 1, style))).unwrap(), b"new", "{context}");
                    }
                    _ => {
                        assert_eq!((report.files, report.failed), (0, 1), "{context}");
                        assert!(report.renames.is_empty(), "{context}");
                        assert_eq!(fs::read_dir(&dest).unwrap().count(), 1, "{context}");
                    }
                }
            }
        }
    }
}

#[test]
fn a_member_named_like_the_archive_beside_it() {
    // 7-Zip's `-aou` writes `self.zip` from inside `self.zip` as `self_1.zip`; `-aot` would have to move the
    // archive, so it is refused.
    for runner in RUNNERS {
        for overwrite in MODES {
            let dir = tempfile::tempdir().unwrap();
            let name = match runner.family() {
                Family::Zip => "self.zip",
                Family::Tar => "self.tar",
                Family::Rar => "self.rar",
            };
            let bytes = build(runner.family(), &[(name, b"inner")]);
            let archive = dir.path().join(name);
            fs::write(&archive, &bytes).unwrap();
            let report = run(runner, &archive, &options(dir.path(), overwrite));
            let context = format!("{runner:?} {overwrite:?}: {report:?}");
            assert_eq!(report.terminal, None, "{context}");
            assert_eq!(fs::read(&archive).unwrap(), bytes, "{context}");
            match overwrite {
                Overwrite::RenameNew(style) => {
                    let beside = dir.path().join(spelled(name, 1, style));
                    assert_eq!((report.files, report.failed), (1, 0), "{context}");
                    assert_eq!(report.renames, [(archive.clone(), beside.clone(), None)], "{context}");
                    assert_eq!(fs::read(&beside).unwrap(), b"inner", "{context}");
                    if typed_rar(runner) {
                        assert_eq!(report.live, report.renames, "{context}");
                    }
                }
                _ => {
                    assert_eq!((report.files, report.failed), (0, 1), "{context}");
                    assert!(report.renames.is_empty(), "{context}");
                    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1, "{context}");
                }
            }
        }
    }
}

#[test]
fn a_member_under_a_moved_directory_does_not_follow_it() {
    // `noext/a` makes the folder, `noext` moves it aside and takes its name, and `noext/b` then finds a file where
    // its folder was: it is refused (alone, or by stopping a runner that always stops there), and nothing is written
    // into the moved folder.
    for runner in RUNNERS {
        let overwrite = Overwrite::RenameExisting(RenameStyle::Underscore);
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.bin");
        fs::write(&archive, build(runner.family(), &[("noext/a", b"a"), ("noext", b"file"), ("noext/b", b"b")]))
            .unwrap();
        let dest = dir.path().join("out");
        fs::create_dir_all(dest.join("noext")).unwrap();
        let report = run(runner, &archive, &options(&dest, overwrite));
        let context = format!("{runner:?}: {report:?}");
        match &report.terminal {
            // a runner may stop the run at a file where a folder should be, as it does without a rename mode
            Some(terminal) => assert!(
                ["a file is in the way", "ParentIsFile", "parent is a symlink or nondirectory"]
                    .iter()
                    .any(|why| terminal.contains(why)),
                "{context}"
            ),
            None => assert_eq!((report.files, report.failed), (2, 1), "{context}"),
        }
        let want: BTreeMap<String, Vec<u8>> =
            [("noext_1/a".to_string(), b"a".to_vec()), ("noext".to_string(), b"file".to_vec())].into();
        assert_eq!(tree(&dest), want, "{context}");
    }
}

#[test]
fn a_directory_member_merges_with_an_existing_folder() {
    // A folder member over an existing folder is reused, never renamed.
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("archive.rar");
    let folder = FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("folder", b"") };
    fs::write(&archive, rar_archive(&[folder, FileSpec::new("folder/x", b"x")])).unwrap();
    let dest = dir.path().join("out");
    fs::create_dir_all(dest.join("folder")).unwrap();
    for runner in [Runner::Run(Family::Rar), Runner::RarSelected] {
        let report = run(runner, &archive, &options(&dest, Overwrite::RenameNew(RenameStyle::Underscore)));
        assert_eq!(report.failed, 0, "{report:?}");
    }
    assert_eq!(tree(&dest).keys().collect::<Vec<_>>(), ["folder/x", "folder/x_1"]);
}

#[test]
fn a_protected_candidate_name_is_passed_over() {
    for runner in [Runner::Run(Family::Rar), Runner::Run(Family::Tar), Runner::Run(Family::Zip), Runner::RarSelected] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.bin");
        fs::write(&archive, build(runner.family(), &[("a.txt", b"new")])).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("a.txt"), b"old").unwrap();
        let mut opts = options(&dest, Overwrite::RenameNew(RenameStyle::Underscore));
        opts.protected_paths.insert(dest.join("a_1.txt"));
        let report = run(runner, &archive, &opts);
        assert_eq!(report.renames, [(dest.join("a.txt"), dest.join("a_2.txt"), None)], "{runner:?}");
        assert!(!dest.join("a_1.txt").exists());
    }
}

#[test]
fn rename_existing_reports_the_moved_file_when_the_new_member_fails() {
    // The second member's data is damaged: its existing target was already moved aside by the time that shows.
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("archive.rar");
    let members =
        [(FileSpec::new("good.txt", b"new"), zipfast::crc32::hash(b"new")), (FileSpec::new("bad.txt", b"damaged"), 0)];
    fs::write(&archive, common::archive_with(&members, false)).unwrap();
    for runner in [Runner::Run(Family::Rar), Runner::RarOutcomes, Runner::RarSelected] {
        let dest = dir.path().join(format!("out-{runner:?}"));
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("bad.txt"), b"old bad").unwrap();
        let report = run(runner, &archive, &options(&dest, Overwrite::RenameExisting(RenameStyle::Underscore)));
        assert_eq!((report.files, report.failed), (1, 1), "{runner:?} {report:?}");
        let moved = dest.join("bad_1.txt");
        let staged = matches!(runner, Runner::RarSelected);
        if staged {
            // selected extraction verifies before it moves anything: the existing file is untouched
            assert!(report.renames.is_empty());
            assert_eq!(fs::read(dest.join("bad.txt")).unwrap(), b"old bad");
        } else {
            assert_eq!(report.renames, [(dest.join("bad.txt"), dest.join("bad.txt"), Some(moved.clone()))]);
            assert_eq!(fs::read(&moved).unwrap(), b"old bad");
            assert!(!dest.join("bad.txt").exists(), "the failed member's partial output is removed");
        }
    }
}

#[test]
fn running_out_of_names_fails_only_that_member_in_every_runner() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("a"), b"old").unwrap();
    for n in 1..=extract::RENAME_LIMIT {
        fs::File::create(dest.join(format!("a_{n}"))).unwrap();
    }
    let before = fs::read_dir(&dest).unwrap().count();
    for runner in RUNNERS {
        let archive = dir.path().join("archive.bin");
        fs::write(&archive, build(runner.family(), &[("a", b"new"), ("z", b"later")])).unwrap();
        for overwrite in
            [Overwrite::RenameNew(RenameStyle::Underscore), Overwrite::RenameExisting(RenameStyle::Underscore)]
        {
            let report = run(runner, &archive, &options(&dest, overwrite));
            let context = format!("{runner:?} {overwrite:?}: {report:?}");
            assert_eq!(report.terminal, None, "{context}");
            assert_eq!((report.files, report.failed), (1, 1), "{context}");
            assert!(report.renames.is_empty(), "{context}");
            assert_eq!(fs::read(dest.join("a")).unwrap(), b"old", "{context}");
            assert_eq!(fs::read(dest.join("z")).unwrap(), b"later", "{context}");
            fs::remove_file(dest.join("z")).unwrap();
            assert_eq!(fs::read_dir(&dest).unwrap().count(), before, "{context}");
        }
    }
    // the typed reason, from the whole-archive and the selected RAR runs
    let archive = dir.path().join("archive.rar");
    fs::write(&archive, rar_archive(&[FileSpec::new("a", b"new")])).unwrap();
    let opts = options(&dest, Overwrite::RenameNew(RenameStyle::Underscore));
    let mut reasons = Vec::new();
    extract::run_rar_with_outcomes(&archive, &opts, None, |e| reasons.push(format!("{:?}", e.outcome))).unwrap();
    let mut session = RarSession::open(&archive, None, RarSessionOptions::default()).unwrap();
    let selection = session.select(|_| true).unwrap();
    session
        .extract_selected(&selection, &opts, RarDecodeLimits::default(), |e| reasons.push(format!("{:?}", e.outcome)))
        .unwrap();
    assert_eq!(reasons.len(), 2);
    assert!(reasons.iter().all(|r| r.contains("RenameExhausted")), "{reasons:?}");
}

#[test]
fn a_name_too_long_to_number_is_shortened_and_the_run_goes_on() {
    let long = format!("{}.txt", "\u{e9}".repeat(125)); // 254 bytes
    for runner in RUNNERS {
        for overwrite in MODES {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.bin");
            fs::write(&archive, build(runner.family(), &[(&long, b"new long"), ("after.txt", b"after")])).unwrap();
            let dest = dir.path().join("out");
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join(&long), b"old long").unwrap();
            let report = run(runner, &archive, &options(&dest, overwrite));
            let context = format!("{runner:?} {overwrite:?}: {report:?}");
            assert_eq!(report.terminal, None, "{context}");
            assert_eq!((report.files, report.failed), (2, 0), "{context}");
            let style = match overwrite {
                Overwrite::RenameNew(style) | Overwrite::RenameExisting(style) => style,
                _ => unreachable!(),
            };
            let renamed = extract::renamed_name(long.as_ref(), 1, style);
            assert!(renamed.len() <= extract::RENAME_NAME_MAX && renamed.to_str().is_some(), "{context}");
            let (new, old) = if matches!(overwrite, Overwrite::RenameNew(_)) {
                (dest.join(&renamed), dest.join(&long))
            } else {
                (dest.join(&long), dest.join(&renamed))
            };
            assert_eq!(fs::read(new).unwrap(), b"new long", "{context}");
            assert_eq!(fs::read(old).unwrap(), b"old long", "{context}");
            assert_eq!(fs::read(dest.join("after.txt")).unwrap(), b"after", "{context}");
            assert_eq!(report.renames.len(), 1, "{context}");
        }
    }
}

#[test]
fn a_terminal_error_still_reports_a_moved_file() {
    // The second member's parent folder is a file in the destination, which stops the legacy runners; the first
    // member had already moved the user's b.txt aside.
    let members: [(&str, &[u8]); 2] = [("b.txt", b"new b"), ("blocker/x", b"x")];
    for runner in RUNNERS {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.bin");
        fs::write(&archive, build(runner.family(), &members)).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("b.txt"), b"old b").unwrap();
        fs::write(dest.join("blocker"), b"a file").unwrap();
        let report = run(runner, &archive, &options(&dest, Overwrite::RenameExisting(RenameStyle::Underscore)));
        let context = format!("{runner:?}: {report:?}");
        assert!(report.terminal.is_some() || report.failed == 1, "{context}");
        assert_eq!(fs::read(dest.join("b_1.txt")).unwrap(), b"old b", "{context}");
        assert_eq!(report.renames, [(dest.join("b.txt"), dest.join("b.txt"), Some(dest.join("b_1.txt")))], "{context}");
        if let Runner::Run(_) = runner {
            let line =
                format!("{}: existing file moved to {}", dest.join("b.txt").display(), dest.join("b_1.txt").display());
            assert!(report.lines.contains(&line), "{context}");
        }
    }
}

#[test]
fn a_standalone_compressed_stream_is_renamed() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("note.txt.gz");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(b"new note").unwrap();
    fs::write(&archive, gz.finish().unwrap()).unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("note.txt"), b"old note").unwrap();
    let summary =
        extract::run(&archive, &options(&dest, Overwrite::RenameNew(RenameStyle::Parenthesized)), |_| {}).unwrap();
    assert_eq!(renames(&summary.renames), [(dest.join("note.txt"), dest.join("note(1).txt"), None)]);
    assert_eq!(fs::read(dest.join("note(1).txt")).unwrap(), b"new note");
    assert_eq!(fs::read(dest.join("note.txt")).unwrap(), b"old note");
}

#[test]
fn progressive_sessions_refuse_the_rename_modes_before_anything() {
    use zipfast::progressive::{FailureKind, ProgressiveOptions, ProgressiveSession};
    for overwrite in MODES {
        let dir = tempfile::tempdir().unwrap();
        let bytes = rar_archive(&[FileSpec::new("one", b"data")]);
        let opts = ProgressiveOptions::new(options(dir.path(), overwrite), "a.rar".into());
        let refused = ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), bytes.into_boxed_slice())], opts);
        assert!(matches!(refused.err().unwrap().kind, FailureKind::InvalidCapability));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn a_file_where_a_folder_should_be_fails_only_the_members_below_it() {
    // `sub` is written as a file, so `sub/g` and `sub/deeper/h` find a file where their folder should be. Like 7-Zip,
    // each runner fails just those members and goes on: `noext` after them is still extracted.
    for runner in RUNNERS {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.bin");
        let members: [(&str, &[u8]); 4] = [("sub", b"file"), ("sub/g", b"g"), ("sub/deeper/h", b"h"), ("noext", b"n")];
        fs::write(&archive, build(runner.family(), &members)).unwrap();
        let dest = dir.path().join("out");
        let report = run(runner, &archive, &options(&dest, Overwrite::Always));
        let context = format!("{runner:?}: {report:?}");
        assert_eq!(report.terminal, None, "{context}");
        assert_eq!((report.files, report.failed), (2, 2), "{context}");
        let want: BTreeMap<String, Vec<u8>> =
            [("sub".to_string(), b"file".to_vec()), ("noext".to_string(), b"n".to_vec())].into();
        assert_eq!(tree(&dest), want, "{context}");
    }
}

#[test]
fn a_file_on_a_folder_members_path_fails_only_that_folder() {
    // The checked ZIP runner makes folder members itself: `sub/` over the file `sub` fails that member alone.
    for runner in [Runner::Policy(Family::Zip), Runner::Context(Family::Zip)] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.zip");
        fs::write(&archive, zip(&[("sub", b"file"), ("sub/", b""), ("sub/inner/", b""), ("noext", b"n")])).unwrap();
        let dest = dir.path().join("out");
        let report = run(runner, &archive, &options(&dest, Overwrite::Always));
        let context = format!("{runner:?}: {report:?}");
        assert_eq!(report.terminal, None, "{context}");
        assert_eq!((report.files, report.failed), (2, 2), "{context}");
        let want: BTreeMap<String, Vec<u8>> =
            [("sub".to_string(), b"file".to_vec()), ("noext".to_string(), b"n".to_vec())].into();
        assert_eq!(tree(&dest), want, "{context}");
    }
}
