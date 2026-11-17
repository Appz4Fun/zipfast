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

//! RAR 4.x members split over volumes, solid streams and encrypted members, written by real archivers, extracted
//! through every route and compared with what UnRAR extracts from them (`tests/fixtures/rar4-unrar`).
//!
//! With `ZIPFAST_RAR4_CORPUS` naming a directory laid out as Prybar's RAR4 reference corpus (`in/<set>/<archive>` and
//! UnRAR's `out/<name>.sha256`), `prybar_corpus_matches_unrar` extracts the whole corpus the same way.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use zipfast::crc32::hash;
use zipfast::crypto::sha256;
use zipfast::error::RarFailure;
use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite, RarEntryOutcome, RarOutcome};
use zipfast::progressive::*;
use zipfast::rar5::session::*;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a file must hold.
#[derive(Clone, Debug)]
enum Expect {
    Sha256(String),
    Crc32(u32),
}

type Manifest = BTreeMap<String, Expect>;

/// `sha256sum` output, as the reference corpus records it.
fn manifest(text: &str) -> Manifest {
    text.lines()
        .filter_map(|line| line.split_once("  "))
        .map(|(sum, name)| (name.trim_start_matches("./").to_owned(), Expect::Sha256(sum.to_owned())))
        .collect()
}

fn unrar_manifest(name: &str) -> Manifest {
    manifest(&fs::read_to_string(fixtures().join("rar4-unrar").join(format!("{name}.sha256"))).unwrap())
}

/// Every regular file under `dir`, by its path relative to it.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                walk(root, &path, out);
            } else if kind.is_file() {
                // a member's stored attributes may leave its file unreadable to its owner
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn check_tree(label: &str, dir: &Path, want: &Manifest) {
    let got = tree(dir);
    assert_eq!(got.keys().collect::<Vec<_>>(), want.keys().collect::<Vec<_>>(), "{label}: extracted names");
    for (name, expect) in want {
        let bytes = &got[name];
        match expect {
            Expect::Sha256(sum) => assert_eq!(&hex(&sha256(bytes)), sum, "{label}: {name}"),
            Expect::Crc32(crc) => assert_eq!(hash(bytes), *crc, "{label}: {name}"),
        }
    }
}

struct Case {
    /// volumes in order
    volumes: Vec<PathBuf>,
    password: Option<&'static str>,
    want: Manifest,
}

fn paths(volumes: &[&str]) -> Vec<PathBuf> {
    volumes.iter().map(|v| fixtures().join(v)).collect()
}

fn case(volumes: &[&str], password: Option<&'static str>, unrar: &str) -> Case {
    Case { volumes: paths(volumes), password, want: unrar_manifest(unrar) }
}

fn cases() -> Vec<Case> {
    vec![
        case(
            &["rar4-volumes/multi.part1.rar", "rar4-volumes/multi.part2.rar", "rar4-volumes/multi.part3.rar"],
            None,
            "in_rarinfo_multi.part1.rar",
        ),
        case(
            &[
                "rar4-rar300/compressed_multivol_prng_rar300.rar",
                "rar4-rar300/compressed_multivol_prng_rar300.r00",
                "rar4-rar300/compressed_multivol_prng_rar300.r01",
                "rar4-rar300/compressed_multivol_prng_rar300.r02",
                "rar4-rar300/compressed_multivol_prng_rar300.r03",
            ],
            None,
            "in_rar300_compressed_multivol_prng_rar300.rar",
        ),
        case(
            &["rar4-rar300/multivol_oldnaming_rar300.rar", "rar4-rar300/multivol_oldnaming_rar300.r00"],
            None,
            "in_rar300_multivol_oldnaming_rar300.rar",
        ),
        case(
            &["rar4-rar300/multivol_newnaming_rar300.part01.rar", "rar4-rar300/multivol_newnaming_rar300.part02.rar"],
            None,
            "in_rar300_multivol_newnaming_rar300.part01.rar",
        ),
        case(
            &[
                "rar4-archiver/mac-oldvol.rar",
                "rar4-archiver/mac-oldvol.r00",
                "rar4-archiver/mac-oldvol.r01",
                "rar4-archiver/mac-oldvol.r02",
            ],
            None,
            "in_rar4-archiver_mac-oldvol.rar",
        ),
        case(
            &[
                "rar4-archiver/win-encvol.rar",
                "rar4-archiver/win-encvol.r00",
                "rar4-archiver/win-encvol.r01",
                "rar4-archiver/win-encvol.r02",
            ],
            Some("testpw123"),
            "in_rar4-archiver_win-encvol.rar",
        ),
        case(&["rar4/solid.rar"], None, "in_rarinfo_solid.rar"),
        // PPMd variant H, with a solid member going on from the first one's model
        case(&["rar4/latest_winrar.rar"], None, "in_rarinfo_latest_winrar.rar"),
        // the six VM standard filters
        case(&["rar4-rar300/rarvm_x86_e8_rar300.rar"], None, "in_rar300_rarvm_x86_e8_rar300.rar"),
        case(&["rar4-rar300/rarvm_x86_e8e9_rar300.rar"], None, "in_rar300_rarvm_x86_e8e9_rar300.rar"),
        case(&["rar4-rar300/rarvm_itanium_synthetic_rar300.rar"], None, "in_rar300_rarvm_itanium_synthetic_rar300.rar"),
        case(&["rar4-rar300/rarvm_delta_4ch_rar300.rar"], None, "in_rar300_rarvm_delta_4ch_rar300.rar"),
        case(&["rar4-rar300/rarvm_rgb_gradient_rar300.rar"], None, "in_rar300_rarvm_rgb_gradient_rar300.rar"),
        case(&["rar4-rar300/rarvm_audio_stereo_rar300.rar"], None, "in_rar300_rarvm_audio_stereo_rar300.rar"),
        // a solid PPMd stream, and an E8 filter whose block offset counts from its own member in a solid stream
        case(&["rar4-rar300/ppmd_solid_rar300.rar"], None, "rars_ppmd_solid_rar300.rar"),
        case(&["rar4-rar300/solid_e8_filter_member_offset.rar"], None, "rars_solid_e8_filter_member_offset.rar"),
        case(&["rar4-rar300/solid_simple_rar300.rar"], None, "in_rar300_solid_simple_rar300.rar"),
        // solid_simple_rar300.rar with its headers patched (see the fixtures README): members from MacOS (host 4)
        // and BeOS (host 5), and an old file revision (LHD_VERSION) stored as `one.txt;1`, written under that name
        case(&["rar4-rar300/hosts_macos_beos_rar300.rar"], None, "in_rar300_solid_simple_rar300.rar"),
        Case {
            volumes: paths(&["rar4-rar300/old_revision_rar300.rar"]),
            password: None,
            want: unrar_manifest("in_rar300_solid_simple_rar300.rar")
                .into_iter()
                .map(|(name, expect)| (if name == "one.txt" { "one.txt;1".to_owned() } else { name }, expect))
                .collect(),
        },
        case(&["rar4-rar300/solid_rar300.rar"], None, "in_rar300_solid_rar300.rar"),
        Case {
            volumes: paths(&["rar4-rar300/per_file_rar300_password.rar"]),
            password: Some("password"),
            want: [("hello.txt".to_owned(), Expect::Crc32(0xa538_535e))].into(),
        },
        Case {
            volumes: paths(&["rar4-rar300/rar4_junrar_password.rar"]),
            password: Some("junrar"),
            want: [("file1.txt".to_owned(), Expect::Sha256(hex(&sha256(b"file1\n"))))].into(),
        },
        // encrypted headers (`-hp`): stored, and compressed over old- and new-style volumes. UnRAR's reference run
        // has no password for the RAR 3.00 pair, whose member is the one `multivol_oldnaming_rar300` holds.
        case(&["rar4-archiver/win-enchdr.rar"], Some("testpw123"), "in_rar4-archiver_win-enchdr.rar"),
        Case {
            password: Some("password"),
            ..case(
                &[
                    "rar4-rar300/header_encrypted_multivol_rar300.rar",
                    "rar4-rar300/header_encrypted_multivol_rar300.r00",
                ],
                None,
                "in_rar300_multivol_oldnaming_rar300.rar",
            )
        },
        Case {
            password: Some("password"),
            ..case(
                &[
                    "rar4-rar300/header_encrypted_newnaming_rar300.part01.rar",
                    "rar4-rar300/header_encrypted_newnaming_rar300.part02.rar",
                ],
                None,
                "in_rar300_multivol_oldnaming_rar300.rar",
            )
        },
    ]
}

/// Encrypted headers without the password, or with a wrong one: as UnRAR, nothing is listed or extracted. Every
/// route fails typed: a password is required, or the decrypted headers fail their checks.
#[test]
fn encrypted_headers_without_the_password_extract_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let archives: &[(&[&str], Option<&'static str>)] = &[
        (&["rar4/encrypted_headers.rar"], None),
        (&["rar4/secret-crypted-none.rar"], None),
        (&["rar4-archiver/win-enchdr.rar"], None),
        (&["rar4-archiver/win-enchdr.rar"], Some("wrong")),
        (
            &["rar4-rar300/header_encrypted_multivol_rar300.rar", "rar4-rar300/header_encrypted_multivol_rar300.r00"],
            None,
        ),
        (
            &[
                "rar4-rar300/header_encrypted_newnaming_rar300.part01.rar",
                "rar4-rar300/header_encrypted_newnaming_rar300.part02.rar",
            ],
            Some("wrong"),
        ),
    ];
    for (n, (volumes, password)) in archives.iter().enumerate() {
        let case = Case { volumes: paths(volumes), password: *password, want: Manifest::new() };
        let dest = tmp.path().join(format!("{n}-run"));
        assert!(extract::run_with_password(&first(&case), &options(&dest), case.password, |_| {}).is_err());
        assert!(tree(&dest).is_empty(), "{}", label(&case, "run"));
        let error = RarSession::open(&first(&case), case.password, RarSessionOptions::default()).err().unwrap();
        match case.password {
            None => assert!(matches!(error.failure.as_ref(), RarFailure::PasswordRequired { .. }), "{error:?}"),
            Some(_) => assert!(matches!(error.failure.as_ref(), RarFailure::EncryptedIntegrity { .. }), "{error:?}"),
        }
        let dest = tmp.path().join(format!("{n}-progressive"));
        let volumes = case
            .volumes
            .iter()
            .map(|path| (OsString::from(path.file_name().unwrap()), fs::read(path).unwrap().into_boxed_slice()))
            .collect();
        let mut session = ProgressiveSession::from_sealed_memory(volumes, progressive_options(&case, &dest)).unwrap();
        let problems = drive(&mut session, || {});
        let want = if case.password.is_some() { "EncryptedIntegrity" } else { "PasswordRequired" };
        assert!(problems.len() == 1 && problems[0].contains(want), "{}: {problems:?}", label(&case, "progressive"));
        assert!(tree(&dest).is_empty(), "{}", label(&case, "progressive"));
    }
}

/// Copies a case's volumes into `dir`, keeping their names.
fn stage(case: &Case, dir: &Path) -> Vec<PathBuf> {
    fs::create_dir_all(dir).unwrap();
    case.volumes
        .iter()
        .map(|from| {
            let to = dir.join(from.file_name().unwrap());
            fs::copy(from, &to).unwrap();
            to
        })
        .collect()
}

fn first(case: &Case) -> PathBuf {
    case.volumes[0].clone()
}

fn label(case: &Case, route: &str) -> String {
    format!("{} via {route}", case.volumes[0].display())
}

#[derive(Default)]
struct Events {
    failures: Vec<String>,
}

/// Extracts through `extract::run` / `run_with_password`.
fn via_run(case: &Case, dest: &Path) {
    let mut events = Events::default();
    let summary = match case.password {
        None => extract::run(&first(case), &options(dest), |m| events.failures.push(m.into())),
        Some(pw) => {
            extract::run_with_password(&first(case), &options(dest), Some(pw), |m| events.failures.push(m.into()))
        }
    }
    .unwrap_or_else(|e| panic!("{}: {e}", label(case, "run")));
    assert!(summary.errors.is_empty() && events.failures.is_empty(), "{}: {:?}", label(case, "run"), summary.errors);
    assert_eq!(summary.files as usize, case.want.len(), "{}", label(case, "run"));
}

fn via_outcomes(case: &Case, dest: &Path) {
    let mut outcomes = Vec::new();
    let summary = extract::run_rar_with_outcomes(&first(case), &options(dest), case.password, |o: &RarEntryOutcome| {
        outcomes.push(format!("{:?}", o.outcome))
    })
    .unwrap_or_else(|e| panic!("{}: {e:?}", label(case, "outcomes")));
    assert_eq!(
        (summary.files as usize, summary.failed),
        (case.want.len(), 0),
        "{}: {outcomes:?}",
        label(case, "outcomes")
    );
}

fn via_zip_policy(case: &Case, dest: &Path) {
    let report = extract::run_with_zip_policy(
        &first(case),
        &options(dest),
        case.password,
        &Cancellation::default(),
        &Default::default(),
        |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
    )
    .unwrap_or_else(|e| panic!("{}: {e:?}", label(case, "zip policy")));
    assert_eq!((report.files() as usize, report.failed()), (case.want.len(), 0), "{}", label(case, "zip policy"));
}

fn session(case: &Case) -> RarSession {
    RarSession::open(&first(case), case.password, RarSessionOptions::default()).unwrap()
}

fn via_selected(case: &Case, dest: &Path) {
    let mut session = session(case);
    let all = session.select(|_| true).unwrap();
    let summary = session.extract_selected(&all, &options(dest), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files as usize, summary.failed), (case.want.len(), 0), "{}", label(case, "selected"));
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
    fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {}
}

fn via_controlled(case: &Case, dest: &Path) {
    let mut session = session(case);
    let all = session.select(|_| true).unwrap();
    let mut control = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
    let report = session.extract_selected_controlled(
        &all,
        &options(dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut Replace,
    );
    let summary = report.finish().outcome.unwrap();
    assert_eq!((summary.files as usize, summary.failed), (case.want.len(), 0), "{}", label(case, "controlled"));
}

fn progressive_options(case: &Case, dest: &Path) -> ProgressiveOptions {
    let name = case.volumes[0].file_name().unwrap().to_owned();
    let mut opts = ProgressiveOptions::new(options(dest), name);
    if let Some(pw) = case.password {
        opts.set_password(Some(pw.into())).unwrap();
    }
    opts
}

struct Unpark {
    thread: std::thread::Thread,
    woken: AtomicBool,
}
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.woken.store(true, Ordering::SeqCst);
        self.thread.unpark();
    }
}

/// Polls a progressive session to its end; `between` runs whenever it waits. Returns each member's outcome.
fn drive(session: &mut ProgressiveSession, mut between: impl FnMut()) -> Vec<String> {
    let unpark = Arc::new(Unpark { thread: std::thread::current(), woken: AtomicBool::new(false) });
    let waker = Waker::from(unpark.clone());
    let start = Instant::now();
    let mut problems = Vec::new();
    loop {
        assert!(start.elapsed() < Duration::from_secs(60), "progressive session stalled");
        match session.poll_event(&mut Context::from_waker(&waker)) {
            Poll::Pending => {
                between();
                while !unpark.woken.swap(false, Ordering::SeqCst) {
                    std::thread::park_timeout(Duration::from_millis(20));
                    assert!(start.elapsed() < Duration::from_secs(60), "no wake");
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => match outcome {
                MemberOutcome::Verified(_) | MemberOutcome::Directory { .. } => {}
                MemberOutcome::Skipped(reason) => problems.push(format!("Skipped {reason:?}")),
                MemberOutcome::Stopped { failure, .. } => problems.push(format!("stopped: {failure:?}")),
                _ => problems.push("other outcome".into()),
            },
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                problems.push(format!("terminated: {failure:?}"));
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(failure)) => {
                problems.push(format!("failed: {failure:?}"));
                break;
            }
        }
    }
    problems
}

/// A progressive session over the complete volumes, held in memory.
fn via_progressive(case: &Case, dest: &Path) {
    let volumes = case
        .volumes
        .iter()
        .map(|path| (OsString::from(path.file_name().unwrap()), fs::read(path).unwrap().into_boxed_slice()))
        .collect();
    let mut session = ProgressiveSession::from_sealed_memory(volumes, progressive_options(case, dest)).unwrap();
    let problems = drive(&mut session, || {});
    assert!(problems.is_empty(), "{}: {problems:?}", label(case, "progressive"));
}

fn growing() -> GrowingOptions {
    let mut options = GrowingOptions::default();
    options.poll_interval = Some(Duration::from_millis(10));
    options.idle_timeout = Duration::from_secs(20);
    options
}

/// Following the volumes as they arrive (`--follow`): only the first exists when the session starts; each later
/// one appears while the session waits for it.
fn via_follow(case: &Case, dest: &Path, inputs: &Path) {
    let staged = stage(case, &inputs.join("all"));
    let live = inputs.join("live");
    fs::create_dir_all(&live).unwrap();
    let place = |i: usize| fs::copy(&staged[i], live.join(staged[i].file_name().unwrap())).unwrap();
    place(0);
    let mut next = 1;
    let provider = GrowingFileVolumes::new(live.join(staged[0].file_name().unwrap()), growing()).unwrap();
    let mut session = ProgressiveSession::new(Box::new(provider), progressive_options(case, dest)).unwrap();
    let problems = drive(&mut session, || {
        if next < staged.len() {
            place(next);
            next += 1;
        }
    });
    assert!(problems.is_empty(), "{}: {problems:?}", label(case, "follow"));
    assert_eq!(next, staged.len(), "{}: every volume was read", label(case, "follow"));
}

/// Each route extracts each fixture as UnRAR does.
#[test]
fn every_route_extracts_split_solid_and_encrypted_rar4_like_unrar() {
    let tmp = tempfile::tempdir().unwrap();
    type Route = fn(&Case, &Path);
    let routes: [(&str, Route); 7] = [
        ("run", via_run),
        ("outcomes", via_outcomes),
        ("zip policy", via_zip_policy),
        ("selected", via_selected),
        ("controlled", via_controlled),
        ("progressive", via_progressive),
        ("follow", |case, dest| via_follow(case, dest, &dest.with_extension("in"))),
    ];
    for (n, case) in cases().iter().enumerate() {
        for (route, extract) in routes {
            let dest = tmp.path().join(format!("{n}-{}", route.replace(' ', "-")));
            extract(case, &dest);
            check_tree(&label(case, route), &dest, &case.want);
        }
    }
}

/// Selecting only a later member of a solid stream still decodes the ones before it, unwritten.
#[test]
fn a_later_solid_member_alone_extracts_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    for case in cases().iter().filter(|c| c.volumes.len() == 1 && c.want.len() > 1) {
        let (last, expect) = case.want.iter().next_back().unwrap();
        let want: Manifest = [(last.clone(), expect.clone())].into();
        // whole-archive extraction with a member filter
        let dest = tmp.path().join(format!("filter-{}", want.len()));
        let _ = fs::remove_dir_all(&dest);
        let mut opts = options(&dest);
        let keep = last.clone();
        opts.select = Some(extract::MemberFilter::new(move |m| m.name == keep));
        let summary = extract::run_with_password(&first(case), &opts, case.password, |_| {}).unwrap();
        assert!(summary.errors.is_empty(), "{:?}", summary.errors);
        check_tree(&label(case, "filtered run"), &dest, &want);
        // a session selecting only that member
        let dest = tmp.path().join("selected-last");
        let _ = fs::remove_dir_all(&dest);
        let mut session = session(case);
        let keep = last.clone();
        let selected = session.select(|m| m.name() == keep).unwrap();
        let summary = session.extract_selected(&selected, &options(&dest), RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!((summary.files, summary.failed), (1, 0));
        check_tree(&label(case, "selected last"), &dest, &want);
        // the single-entry reader, by listing index
        let index = session.entries().position(|e| e.name() == last).unwrap();
        let mut bytes = Vec::new();
        extract::SelectedEntry::open(&first(case), index, case.password, 1 << 20)
            .unwrap()
            .read(None, |chunk| {
                bytes.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        match expect {
            Expect::Sha256(sum) => assert_eq!(&hex(&sha256(&bytes)), sum, "{}", label(case, "entry reader")),
            Expect::Crc32(crc) => assert_eq!(hash(&bytes), *crc),
        }
        // a progressive session that skips the earlier members: they are decoded, not written
        let dest = tmp.path().join("progressive-last");
        let _ = fs::remove_dir_all(&dest);
        fs::create_dir_all(&dest).unwrap();
        let volume = fs::read(first(case)).unwrap().into_boxed_slice();
        let name = OsString::from(first(case).file_name().unwrap());
        let mut opts = progressive_options(case, &dest);
        opts.extract.overwrite = Overwrite::Skip;
        for other in case.want.keys().filter(|n| *n != last) {
            fs::write(dest.join(other), b"keep").unwrap();
        }
        let mut session = ProgressiveSession::from_sealed_memory(vec![(name, volume)], opts).unwrap();
        let problems = drive(&mut session, || {});
        assert!(problems.iter().all(|p| p.starts_with("Skipped")), "{problems:?}");
        let bytes = fs::read(dest.join(last)).unwrap();
        match expect {
            Expect::Sha256(sum) => assert_eq!(&hex(&sha256(&bytes)), sum),
            Expect::Crc32(crc) => assert_eq!(hash(&bytes), *crc),
        }
    }
}

fn multi_parts(dir: &Path) -> Vec<PathBuf> {
    let case = &cases()[0];
    stage(case, dir)
}

/// A damaged continuation volume is a typed failure of the split member, never wrong output.
#[test]
fn corrupt_and_truncated_continuations_fail_typed() {
    let tmp = tempfile::tempdir().unwrap();
    // flip a byte in the packed data of the second volume's continuation
    let dir = tmp.path().join("corrupt");
    let parts = multi_parts(&dir);
    let mut bytes = fs::read(&parts[1]).unwrap();
    let at = bytes.len() - 200;
    bytes[at] ^= 0x55;
    fs::write(&parts[1], bytes).unwrap();
    let dest = tmp.path().join("corrupt-out");
    let mut failed = Vec::new();
    extract::run_rar_with_outcomes(&parts[0], &options(&dest), None, |o: &RarEntryOutcome| {
        if let RarOutcome::Failed(failure) = &o.outcome {
            failed.push((o.entry.name.clone(), Arc::clone(failure)));
        }
    })
    .unwrap();
    assert!(!failed.is_empty(), "a damaged part must fail its member");
    for (_, failure) in &failed {
        assert!(matches!(failure.as_ref(), RarFailure::Integrity { .. }), "{failure:?}");
    }
    let mut session = RarSession::open(&parts[0], None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let summary = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap();
    assert!(summary.failed >= 1);

    // cut the last volume short
    let dir = tmp.path().join("truncated");
    let parts = multi_parts(&dir);
    let bytes = fs::read(&parts[2]).unwrap();
    fs::write(&parts[2], &bytes[..bytes.len() / 2]).unwrap();
    let dest = tmp.path().join("truncated-out");
    let result = extract::run_rar_with_outcomes(&parts[0], &options(&dest), None, |_| {});
    assert!(result.is_err() || result.as_ref().is_ok_and(|s| s.failed > 0), "{result:?}");
    if let Err(error) = &result {
        assert!(
            matches!(error.failure.as_ref(), RarFailure::Integrity { .. } | RarFailure::Input { .. }),
            "{:?}",
            error.failure
        );
    }

    // and a missing last volume
    let dir = tmp.path().join("missing");
    let parts = multi_parts(&dir);
    fs::remove_file(&parts[2]).unwrap();
    let dest = tmp.path().join("missing-out");
    let result = extract::run_rar_with_outcomes(&parts[0], &options(&dest), None, |_| {});
    assert!(result.is_err() || result.as_ref().is_ok_and(|s| s.failed > 0), "{result:?}");
}

/// `multi_broken.part1.rar` without its second volume: as UnRAR, `file1.txt` extracts and `file2.txt`, split into
/// the missing volume, fails on its own (`unrar t`: "Cannot find volume", then its checksum error). Every route
/// extracts what UnRAR extracts.
#[test]
fn a_missing_later_volume_fails_only_the_member_split_into_it() {
    let tmp = tempfile::tempdir().unwrap();
    let first = fixtures().join("rar4/multi_broken.part1.rar");
    let missing = fixtures().join("rar4/multi_broken.part2.rar");
    let want = unrar_manifest("in_rarinfo_multi_broken.part1.rar");
    let tested = fs::read_to_string(fixtures().join("rar4-unrar/in_rarinfo_multi_broken.part1.rar.t")).unwrap();
    assert!(tested.contains("Cannot find volume") && tested.contains("file2.txt            - checksum error"));
    let is_missing = |failure: &RarFailure| matches!(failure, RarFailure::MissingVolume { path } if *path == missing);

    let dest = tmp.path().join("run");
    let mut failed = Vec::new();
    let summary = extract::run_rar_with_outcomes(&first, &options(&dest), None, |o: &RarEntryOutcome| {
        if let RarOutcome::Failed(failure) = &o.outcome {
            failed.push((o.entry.name.clone(), Arc::clone(failure)));
        }
    })
    .unwrap();
    assert_eq!((summary.files, summary.failed), (1, 1));
    assert!(failed.len() == 1 && failed[0].0 == "file2.txt" && is_missing(&failed[0].1), "{failed:?}");
    check_tree("run", &dest, &want);

    let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.archive().missing_volume(), Some(missing.as_path()));
    assert_eq!(session.entries().map(|e| e.name().to_owned()).collect::<Vec<_>>(), ["file1.txt", "file2.txt"]);
    assert!(session.entries().nth(1).unwrap().payload_issue().is_some_and(is_missing));
    let all = session.select(|_| true).unwrap();
    let dest = tmp.path().join("selected");
    let mut failed = Vec::new();
    let summary = session
        .extract_selected(&all, &options(&dest), RarDecodeLimits::default(), |o| {
            if let RarOutcome::Failed(failure) = &o.outcome {
                failed.push(Arc::clone(failure));
            }
        })
        .unwrap();
    assert_eq!((summary.files, summary.failed), (1, 1));
    assert!(is_missing(&failed[0]));
    check_tree("selected", &dest, &want);
    let summary = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 1));

    // a progressive session extracts file1.txt, then stops at the missing volume for file2.txt
    let case = Case { volumes: vec![first.clone()], password: None, want: want.clone() };
    let dest = tmp.path().join("progressive");
    let volumes = vec![(OsString::from("multi_broken.part1.rar"), fs::read(&first).unwrap().into_boxed_slice())];
    let mut session = ProgressiveSession::from_sealed_memory(volumes, progressive_options(&case, &dest)).unwrap();
    let problems = drive(&mut session, || {});
    assert!(problems.len() == 1 && problems[0].contains("MissingVolume"), "{problems:?}");
    check_tree("progressive", &dest, &want);
}

/// Canceling a session that waits in the middle of a compressed split member for its next volume stops it, typed,
/// and publishes nothing.
#[test]
fn cancellation_mid_member_stops_typed() {
    let tmp = tempfile::tempdir().unwrap();
    let case = &cases()[2]; // multivol_oldnaming: one 64 KiB member over two volumes
    let staged = stage(case, &tmp.path().join("all"));
    let live = tmp.path().join("live");
    fs::create_dir_all(&live).unwrap();
    fs::copy(&staged[0], live.join(staged[0].file_name().unwrap())).unwrap();
    let dest = tmp.path().join("out");
    let provider = GrowingFileVolumes::new(live.join(staged[0].file_name().unwrap()), growing()).unwrap();
    let mut session = ProgressiveSession::new(Box::new(provider), progressive_options(case, &dest)).unwrap();
    let control = session.control();
    let mut started = false;
    let mut canceled = false;
    let problems = drive(&mut session, || {
        // the first wait after the member started is for the volume its second part is in
        if started && !canceled {
            control.cancel();
            canceled = true;
        }
        started = true;
    });
    assert!(canceled);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("Canceled"), "{problems:?}");
    assert!(tree(&dest).is_empty(), "nothing is published");
}

/// Rewrites a RAR 3.x archive as `rar -p` would have written it: each file header gains a salt and the
/// encryption flag, and each member's packed data is padded to whole AES blocks and encrypted with the keys for
/// `password` and that salt.
fn encrypt_rar4(archive: &[u8], password: &str, salt: [u8; 8]) -> Vec<u8> {
    let (key, iv) = zipfast::crypto::derive_rar4_key_iv(password, &salt);
    let mut out = archive[..7].to_vec();
    let mut at = 7;
    while at + 7 <= archive.len() {
        let kind = archive[at + 2];
        let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
        let mut header = archive[at..at + size].to_vec();
        let data_len = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        let mut data = archive[at + size..at + size + data_len].to_vec();
        if kind == 0x74 {
            assert_eq!(flags & 0x100, 0, "no high sizes in these fixtures");
            let name_len = usize::from(u16::from_le_bytes([header[26], header[27]]));
            header.splice(32 + name_len..32 + name_len, salt);
            header[3..5].copy_from_slice(&(flags | 0x404).to_le_bytes());
            header[5..7].copy_from_slice(&((size + 8) as u16).to_le_bytes());
            data.resize(data.len().next_multiple_of(16), 0);
            data = zipfast::crypto::encrypt_cbc(&key, &iv, &data).unwrap();
            header[7..11].copy_from_slice(&(data.len() as u32).to_le_bytes());
            let crc = hash(&header[2..]) as u16;
            header[..2].copy_from_slice(&crc.to_le_bytes());
        }
        out.extend(header);
        out.extend(data);
        at += size + data_len;
    }
    out
}

/// A solid `-s -p` archive whose earlier members a run doesn't take: they are still decrypted and decoded, so the
/// member taken gets its history (every route).
#[test]
fn an_encrypted_solid_archive_extracts_a_later_member_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("solid-encrypted.rar");
    let plain = fs::read(fixtures().join("rar4/solid.rar")).unwrap();
    fs::write(&path, encrypt_rar4(&plain, "secret", *b"saltsalt")).unwrap();
    let want = unrar_manifest("in_rarinfo_solid.rar");
    // every member, through every route
    let case = Case { volumes: vec![path.clone()], password: Some("secret"), want: want.clone() };
    for (route, extract) in
        [("run", via_run as fn(&Case, &Path)), ("selected", via_selected), ("progressive", via_progressive)]
    {
        let dest = tmp.path().join(format!("all-{route}"));
        extract(&case, &dest);
        check_tree(&label(&case, route), &dest, &want);
    }
    let last = "unrardll.txt".to_owned();
    let only: Manifest = [(last.clone(), want[&last].clone())].into();
    // whole-archive extraction with a member filter
    let dest = tmp.path().join("filtered");
    let mut opts = options(&dest);
    let keep = last.clone();
    opts.select = Some(extract::MemberFilter::new(move |m| m.name == keep));
    let summary = extract::run_with_password(&path, &opts, Some("secret"), |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    check_tree("filtered run", &dest, &only);
    // a session selecting only that member
    let dest = tmp.path().join("selected");
    let mut session = RarSession::open(&path, Some("secret"), RarSessionOptions::default()).unwrap();
    let keep = last.clone();
    let selected = session.select(|m| m.name() == keep).unwrap();
    let summary = session.extract_selected(&selected, &options(&dest), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 0));
    check_tree("selected", &dest, &only);
    // the single-entry reader
    let mut bytes = Vec::new();
    extract::SelectedEntry::open(&path, 1, Some("secret"), 1 << 20)
        .unwrap()
        .read(Some("secret"), |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert!(matches!(&want[&last], Expect::Sha256(sum) if *sum == hex(&sha256(&bytes))));
    // a progressive session skipping the first member, whose output exists
    let dest = tmp.path().join("progressive");
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join("tese.txt"), b"keep").unwrap();
    let mut opts = progressive_options(&case, &dest);
    opts.extract.overwrite = Overwrite::Skip;
    let volume = fs::read(&path).unwrap().into_boxed_slice();
    let mut session =
        ProgressiveSession::from_sealed_memory(vec![(OsString::from("solid-encrypted.rar"), volume)], opts).unwrap();
    let problems = drive(&mut session, || {});
    assert!(problems.iter().all(|p| p.starts_with("Skipped")), "{problems:?}");
    assert!(matches!(&want[&last], Expect::Sha256(sum) if *sum == hex(&sha256(&fs::read(dest.join(&last)).unwrap()))));
}

/// A later part that changes the member's dictionary or salt is a changed continuation, not more of the member.
#[test]
fn a_continuation_with_another_dictionary_or_salt_fails_typed() {
    let tmp = tempfile::tempdir().unwrap();
    for mutation in ["dictionary", "salt"] {
        let dir = tmp.path().join(mutation);
        let parts = if mutation == "salt" {
            let case = &cases()[5]; // win-encvol: one encrypted stored member over four volumes
            stage(case, &dir)
        } else {
            multi_parts(&dir)
        };
        // the second volume's first file header continues the first volume's split member
        let mut bytes = fs::read(&parts[1]).unwrap();
        let main_size = usize::from(u16::from_le_bytes([bytes[7 + 5], bytes[7 + 6]]));
        let at = 7 + main_size;
        assert_eq!(bytes[at + 2], 0x74);
        let flags = u16::from_le_bytes([bytes[at + 3], bytes[at + 4]]);
        assert_ne!(flags & 1, 0, "a continuation");
        if mutation == "dictionary" {
            let dictionary = (flags >> 5) & 7;
            let changed = (flags & !0xe0) | (if dictionary == 0 { 1 } else { dictionary - 1 } << 5);
            assert_ne!(changed, flags);
            bytes[at + 3..at + 5].copy_from_slice(&changed.to_le_bytes());
        } else {
            let name_len = usize::from(u16::from_le_bytes([bytes[at + 26], bytes[at + 27]]));
            bytes[at + 32 + name_len] ^= 1;
        }
        let size = usize::from(u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]));
        let crc = hash(&bytes[at + 2..at + size]) as u16;
        bytes[at..at + 2].copy_from_slice(&crc.to_le_bytes());
        fs::write(&parts[1], bytes).unwrap();
        let password = (mutation == "salt").then_some("testpw123");
        let mut failures = Vec::new();
        extract::run_rar_with_outcomes(&parts[0], &options(&dir.join("out")), password, |o: &RarEntryOutcome| {
            if let RarOutcome::Failed(failure) = &o.outcome {
                failures.push(Arc::clone(failure));
            }
        })
        .unwrap();
        assert!(
            failures.iter().any(|f| matches!(
                f.as_ref(),
                RarFailure::Integrity { reason: zipfast::error::RarIntegrityReason::ChangedContinuationEncoding, .. }
            )),
            "{mutation}: {failures:?}"
        );
        let mut session = RarSession::open(&parts[0], password, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        assert!(session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap().failed >= 1, "{mutation}");
    }
}

/// The archive's own final CRC-32 for each regular file, as the expected output.
fn crc_manifest(first: &Path) -> Manifest {
    let session = RarSession::open(first, None, RarSessionOptions::default()).unwrap();
    session
        .entries()
        .filter(|e| !e.is_directory())
        .map(|e| (e.name().to_owned(), Expect::Crc32(e.final_checks().unwrap().crc32.unwrap())))
        .collect()
}

/// RAR 1.5 (unpack version 15) and RAR 2.0 (20) compression, solid streams and an old split set, through every
/// route.
#[test]
fn rar15_and_rar20_compression_extracts_through_every_route() {
    let tmp = tempfile::tempdir().unwrap();
    let sets: &[&[&str]] = &[
        &["rar4-legacy/readme_154_normal.rar"],
        &["rar4-legacy/readme_154_store_solid.rar"],
        &["rar4-legacy/rars-compressed.rar"],
        &["rar4-legacy/rars-solid.rar"],
        &["rar4-legacy/rars-split-store.rar", "rar4-legacy/rars-split-store.r00", "rar4-legacy/rars-split-store.r01"],
        &["rar4-legacy/SOLID.RAR"],
        &["rar4-legacy/AUDIO.RAR"],
        &["rar4-legacy/AUTOREJ.RAR"],
        &["rar4-legacy/BIGLZ.RAR"],
        &["rar4-legacy/unpack20_multiblock.rar"],
    ];
    // Archives this old write no end-of-archive block: a progressive session over complete volumes ends them at a
    // block boundary, as UnRAR does, but one following growing files can't tell that end from a pause.
    type Route = fn(&Case, &Path);
    let routes: [(&str, Route); 5] = [
        ("run", via_run),
        ("outcomes", via_outcomes),
        ("selected", via_selected),
        ("controlled", via_controlled),
        ("progressive", via_progressive),
    ];
    for (n, volumes) in sets.iter().enumerate() {
        let volumes = paths(volumes);
        let want = crc_manifest(&volumes[0]);
        assert!(!want.is_empty());
        let case = Case { volumes, password: None, want };
        for (route, extract) in routes {
            let dest = tmp.path().join(format!("legacy-{n}-{route}"));
            extract(&case, &dest);
            check_tree(&label(&case, route), &dest, &case.want);
        }
    }
}

/// A filter record inside a PPMd block: the member's CRC holds only if the filter ran.
#[test]
fn a_filter_inside_a_ppm_block_runs() {
    let path = fixtures().join("rar4-rar300/ppmd_embedded_vm_filter.rar");
    let tmp = tempfile::tempdir().unwrap();
    let summary = extract::run(&path, &options(tmp.path()), |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(summary.files, 1);
}

/// A progressive session over complete volumes ends an archive older than RAR 2.9, which has no end-of-archive
/// block, at a block boundary; a RAR 2.9+ archive cut at a block boundary is still truncated.
#[test]
fn only_archives_older_than_rar_2_9_may_end_without_an_end_block() {
    let tmp = tempfile::tempdir().unwrap();
    let run = |name: &str, bytes: Vec<u8>| {
        let dest = tmp.path().join(name);
        let case = Case { volumes: vec![PathBuf::from(name)], password: None, want: Manifest::new() };
        let mut session = ProgressiveSession::from_sealed_memory(
            vec![(OsString::from(name), bytes.into_boxed_slice())],
            progressive_options(&case, &dest),
        )
        .unwrap();
        drive(&mut session, || {})
    };
    // RAR 1.54 writes no end block
    let old = fs::read(fixtures().join("rar4-legacy/readme_154_normal.rar")).unwrap();
    assert!(run("old.rar", old).is_empty());
    // a RAR 3.x archive without its end block
    let mut modern = fs::read(fixtures().join("rar4/solid.rar")).unwrap();
    assert_eq!(modern[modern.len() - 5], 0x7b, "ends with the end-of-archive block");
    modern.truncate(modern.len() - 7);
    let problems = run("modern.rar", modern);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("Truncated"), "{problems:?}");
}

/// A PPM block asks for its model's memory up front; a progressive session's decoder window bounds it, typed.
#[test]
fn a_ppm_model_larger_than_the_progressive_window_is_a_typed_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = fixtures().join("rar4/latest_winrar.rar");
    let case = Case { volumes: vec![path.clone()], password: None, want: Manifest::new() };
    let mut opts = progressive_options(&case, tmp.path());
    // the LZ dictionary (1 MiB) fits; the PPM model and filter memory don't
    opts.limits.decoder_window = 1 << 20;
    let volume = fs::read(&path).unwrap().into_boxed_slice();
    let mut session =
        ProgressiveSession::from_sealed_memory(vec![(OsString::from("latest_winrar.rar"), volume)], opts).unwrap();
    let problems = drive(&mut session, || {});
    assert!(!problems.is_empty() && problems.iter().any(|p| p.contains("Limit")), "{problems:?}");
    assert!(tree(tmp.path()).is_empty());
}

/// The whole Prybar reference corpus, when `ZIPFAST_RAR4_CORPUS` names it: every archive UnRAR extracts must
/// extract identically, except the shapes listed as not yet supported.
#[test]
fn prybar_corpus_matches_unrar() {
    let Some(root) = std::env::var_os("ZIPFAST_RAR4_CORPUS").map(PathBuf::from) else {
        eprintln!("ZIPFAST_RAR4_CORPUS is not set: skipping the reference corpus");
        return;
    };
    // Not supported yet, with the reason; each still must not extract anything UnRAR doesn't.
    let pending: &[(&str, &str)] = &[];
    let tmp = tempfile::tempdir().unwrap();
    let mut matched = Vec::new();
    let mut waiting = Vec::new();
    let mut mismatched = Vec::new();
    let mut sets: Vec<_> = fs::read_dir(root.join("in")).unwrap().flatten().map(|e| e.path()).collect();
    sets.sort();
    for set in sets {
        let mut archives: Vec<_> = fs::read_dir(&set).unwrap().flatten().map(|e| e.path()).collect();
        archives.sort();
        for archive in archives {
            let file = archive.file_name().unwrap().to_string_lossy().into_owned();
            let later_part = file
                .rsplit_once(".part")
                .is_some_and(|(_, n)| n.trim_end_matches(".rar").trim_start_matches('0') != "1");
            if !file.ends_with(".rar") || later_part {
                continue;
            }
            let rel = archive.strip_prefix(&root).unwrap().to_string_lossy().replace('/', "_");
            let Ok(status) = fs::read_to_string(root.join("out").join(format!("{rel}.xstatus"))) else { continue };
            if status.trim() != "status=0" {
                continue;
            }
            let want = manifest(&fs::read_to_string(root.join("out").join(format!("{rel}.sha256"))).unwrap());
            let password = file.starts_with("win-enc").then_some("testpw123");
            let mut volumes = vec![archive.clone()];
            while let Some(next) = zipfast::volume::next_volume(volumes.last().unwrap()).filter(|p| p.exists()) {
                volumes.push(next);
            }
            let case = Case { volumes, password, want };
            // whole-archive, selected-session and progressive extraction must all agree with UnRAR
            let same = ["run", "selected", "progressive"].iter().all(|route| {
                let dest = tmp.path().join(&rel).join(route);
                match *route {
                    "run" => drop(extract::run_with_password(&archive, &options(&dest), password, |_| {})),
                    "selected" => {
                        if let Ok(mut session) = RarSession::open(&archive, password, RarSessionOptions::default()) {
                            let all = session.select(|_| true).unwrap();
                            let _ = session.extract_selected(&all, &options(&dest), RarDecodeLimits::default(), |_| {});
                        }
                    }
                    _ => {
                        let volumes = case
                            .volumes
                            .iter()
                            .map(|p| (OsString::from(p.file_name().unwrap()), fs::read(p).unwrap().into_boxed_slice()))
                            .collect();
                        if let Ok(mut session) =
                            ProgressiveSession::from_sealed_memory(volumes, progressive_options(&case, &dest))
                        {
                            drive(&mut session, || {});
                        }
                    }
                }
                // UnRAR's listing has regular files only (symbolic links are a later step)
                let got = tree(&dest);
                got.len() == case.want.len()
                    && case.want.iter().all(|(name, expect)| {
                        got.get(name).is_some_and(|bytes| match expect {
                            Expect::Sha256(sum) => &hex(&sha256(bytes)) == sum,
                            Expect::Crc32(crc) => hash(bytes) == *crc,
                        })
                    })
            });
            let reason = pending.iter().find(|(prefix, _)| rel.starts_with(prefix)).map(|(_, why)| *why);
            match (same, reason) {
                (true, _) => matched.push(rel),
                (false, Some(why)) => waiting.push(format!("{rel}: {why}")),
                (false, None) => mismatched.push(rel),
            }
        }
    }
    eprintln!("RAR4 corpus: {} identical to UnRAR, {} not yet supported", matched.len(), waiting.len());
    for line in &waiting {
        eprintln!("  pending {line}");
    }
    assert!(mismatched.is_empty(), "differ from UnRAR: {mismatched:?}");
    assert!(!matched.is_empty());
}

fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}
/// A RAR 2.0 stored member.
fn rar20_stored(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(data).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([20, 0x30]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut wire = rar4_block(0x74, 0x8000, &body);
    wire.extend(data);
    wire
}
/// A volume of a RAR 2.0 set (main header `MHD_VOLUME`) holding whole members only.
fn rar20_volume(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut wire = b"Rar!\x1a\x07\0".to_vec();
    wire.extend(rar4_block(0x73, 0x0001, &[0; 6]));
    for (name, data) in members {
        wire.extend(rar20_stored(name, data));
    }
    wire
}

/// Serves the first volume of a set from memory, and answers the next one with `next`.
struct FirstOnly {
    first: Option<Box<[u8]>>,
    next: fn() -> VolumeAnswer,
}
struct Memory(Box<[u8]>);
impl RangeSource for Memory {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(1),
            generation: 0,
            extent: self.0.len() as u64,
            length: SourceLength::Final(self.0.len() as u64),
        }
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let bytes = &self.0[offset as usize..];
        let count = bytes.len().min(buf.len());
        buf[..count].copy_from_slice(&bytes[..count]);
        Ok(RangeRead::Filled { count })
    }
    fn backing_files(&self) -> &[fs::File] {
        &[]
    }
}
impl VolumeSource for FirstOnly {
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(match (request.index, self.first.take()) {
            (0, Some(first)) => VolumeAnswer::Ready(Box::new(Memory(first))),
            _ => (self.next)(),
        })
    }
}

/// A RAR 2.x volume carries no end-of-archive block, so one whose main header says it is part of a set (MHD_VOLUME)
/// and that ends exactly between members is not the end of the set: the next volume is asked for.
#[test]
fn a_rar_2_x_set_split_between_members_goes_on_to_the_next_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let (x, y) = (b"first member, in the first volume".as_slice(), b"second member, in the second".as_slice());
    let v0 = rar20_volume(&[(b"x.txt", x)]);
    let v1 = rar20_volume(&[(b"y.txt", y)]);
    let options = |dest: &Path| ProgressiveOptions::new(options(dest), OsString::from("set.rar"));

    // Every volume given up front: both members extract and the set ends after the last volume.
    let dest = tmp.path().join("sealed");
    let mut session = ProgressiveSession::from_sealed_memory(
        vec![("set.rar".into(), v0.clone().into_boxed_slice()), ("set.r00".into(), v1.into_boxed_slice())],
        options(&dest),
    )
    .unwrap();
    assert!(drive(&mut session, || {}).is_empty());
    assert_eq!(fs::read(dest.join("x.txt")).unwrap(), x);
    assert_eq!(fs::read(dest.join("y.txt")).unwrap(), y);

    // The next volume has not arrived: the session waits for it instead of reporting the set complete.
    let provider = FirstOnly { first: Some(v0.clone().into_boxed_slice()), next: || VolumeAnswer::Wait };
    let mut session = ProgressiveSession::new(Box::new(provider), options(&tmp.path().join("wait"))).unwrap();
    let mut finished = 0;
    let mut pending = 0;
    for _ in 0..10_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => {
                pending += 1;
                if pending > 3 {
                    break;
                }
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => finished += 1,
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Ok(None)) => panic!("the set ended before its next volume"),
            Poll::Ready(Err(e)) => panic!("{e:?}"),
        }
    }
    assert_eq!((finished, pending), (1, 4));

    // A last volume cut off between members (the next one is missing) is not complete either.
    let provider = FirstOnly { first: Some(v0.into_boxed_slice()), next: || VolumeAnswer::Missing };
    let mut session = ProgressiveSession::new(Box::new(provider), options(&tmp.path().join("missing"))).unwrap();
    let problems = drive(&mut session, || {});
    // (An opaque provider's member is provisional, an "other outcome" here.)
    assert!(problems.last().is_some_and(|p| p.contains("MissingVolume")), "{problems:?}");
}

/// Files on disk declared Complete: the inventory names every volume of the set.
struct Declared {
    paths: Vec<PathBuf>,
    handles: Vec<Arc<fs::File>>,
}
impl VolumeSource for Declared {
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(match self.paths.get(request.index as usize) {
            Some(path) => VolumeAnswer::Ready(Box::new(ImmutableFileSource::open(path)?)),
            None => VolumeAnswer::Missing,
        })
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        let volumes = self
            .paths
            .iter()
            .zip(&self.handles)
            .enumerate()
            .map(|(i, (path, file))| ProtectedVolume {
                index: i as u32,
                name: path.file_name().unwrap().into(),
                backing: VolumeBacking::Native(vec![ProtectedPath { path: path.clone(), file: Some(file.clone()) }]),
            })
            .collect();
        Ok(ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory { volumes, auxiliary_paths: vec![] },
        })
    }
}

/// A Complete declaration names every volume, so the last one it names ends the set even between members.
#[test]
fn a_rar_2_x_set_declared_complete_ends_after_its_last_declared_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let (x, y) = (b"first member, in the first volume".as_slice(), b"second member, in the second".as_slice());
    let input = tmp.path().join("in");
    fs::create_dir_all(&input).unwrap();
    let paths = vec![input.join("set.rar"), input.join("set.r00")];
    fs::write(&paths[0], rar20_volume(&[(b"x.txt", x)])).unwrap();
    fs::write(&paths[1], rar20_volume(&[(b"y.txt", y)])).unwrap();
    let handles = paths.iter().map(|p| Arc::new(fs::File::open(p).unwrap())).collect();
    let dest = tmp.path().join("out");
    let options = ProgressiveOptions::new(options(&dest), OsString::from("set.rar"));
    let mut session = ProgressiveSession::new(Box::new(Declared { paths, handles }), options).unwrap();
    let problems = drive(&mut session, || {});
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(fs::read(dest.join("x.txt")).unwrap(), x);
    assert_eq!(fs::read(dest.join("y.txt")).unwrap(), y);
}

/// Listing shows members from hosts above Unix with no Unix mode, and an old file revision under its stored name.
#[test]
fn hosts_above_unix_and_old_revisions_list() {
    let hosts = extract::list(&fixtures().join("rar4-rar300/hosts_macos_beos_rar300.rar")).unwrap();
    let got: Vec<_> = hosts.iter().map(|e| (e.name.as_str(), e.mode)).collect();
    assert_eq!(got, [("one.txt", None), ("two.txt", None)]);
    let old = extract::list(&fixtures().join("rar4-rar300/old_revision_rar300.rar")).unwrap();
    assert_eq!(old.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["one.txt;1", "two.txt"]);
}
