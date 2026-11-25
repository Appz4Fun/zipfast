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

//! Held output: `PartialFile::held_output` on a live handle and `partial::load_held` on a closed state directory,
//! read-only and without the archive or its binding.
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
#![allow(dead_code)]
mod common;
use std::{
    ffi::OsString,
    fs::File,
    path::Path,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::map::{MapOptions, MemberMap, MemberReader};
use zipfast::partial::*;
use zipfast::progressive::*;

/// One volume in memory.
struct Source {
    index: u32,
    bytes: Vec<u8>,
}
impl RangeSource for Source {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.index as u128 + 1),
            generation: 0,
            extent: self.bytes.len() as u64,
            length: SourceLength::Final(self.bytes.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let end = (at as usize + buf.len()).min(self.bytes.len());
        let n = end.saturating_sub(at as usize);
        buf[..n].copy_from_slice(&self.bytes[at as usize..end]);
        Ok(RangeRead::Filled { count: n })
    }
}
/// The first `available` volumes of a set; later ones are missing, as when the primary download dies.
struct Provider {
    volumes: Vec<Vec<u8>>,
    available: usize,
    names: fn(u32) -> OsString,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..self.volumes.len() as u32)
                    .map(|index| ProtectedVolume { index, name: (self.names)(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        })
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let index = request.index as usize;
        if index >= self.available.min(self.volumes.len()) {
            return Ok(VolumeAnswer::Missing);
        }
        Ok(VolumeAnswer::Ready(Box::new(Source { index: request.index, bytes: self.volumes[index].clone() })))
    }
}
fn primary_name(index: u32) -> OsString {
    format!("set.part{:02}.rar", index + 1).into()
}
fn alt_name(index: u32) -> OsString {
    format!("alt.part{}.rar", index + 1).into()
}
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

fn gold(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}
/// The alt: the same member stored in volumes of another size.
fn alt(gold: &[u8]) -> Vec<Vec<u8>> {
    common::volumes(&common::FileSpec::new("movie.bin", gold), 1700)
}
fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
}

struct Primary {
    session: ProgressiveSession,
    file: PartialFile,
    key: MemberKey,
    anchors: Arc<Anchors>,
}
fn session(
    dir: &Path,
    volumes: &[Vec<u8>],
    available: usize,
    anchors: &Arc<Anchors>,
    password: Option<&str>,
) -> ProgressiveSession {
    let mut options = ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: dir.join("out"),
            overwrite: zipfast::extract::Overwrite::Always,
            flatten: false,
            threads: Some(1),
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
        },
        primary_name(0),
    );
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    options.set_password(password.map(String::from)).unwrap();
    let partial = PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: dir.join("state"),
        limits: PartialLimits::default(),
        anchors: anchors.clone(),
        control: SessionControl::default(),
    };
    let provider = Provider { volumes: volumes.to_vec(), available, names: primary_name };
    ProgressiveSession::new_partial(Box::new(provider), options, partial).unwrap()
}
/// Runs the primary until its download dies (a missing volume) and returns the member's handle.
fn primary_dies(dir: &Path, volumes: &[Vec<u8>], available: usize, password: Option<&str>) -> Primary {
    let anchors = Arc::new(Anchors::default());
    let mut session = session(dir, volumes, available, &anchors, password);
    let mut file = None;
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                file = Some((member.clone(), session.partial_file(&member).unwrap()))
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => panic!("the primary finished the member"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { .. }))) | Poll::Ready(Err(_)) => break,
            Poll::Ready(Ok(None)) => panic!("the primary ended without failing"),
            _ => {}
        }
    }
    let (key, file) = file.expect("member created");
    Primary { session, file, key, anchors }
}
fn verify(file: &mut PartialFile) -> Verdict {
    for _ in 0..100_000 {
        if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            return result.unwrap();
        }
    }
    panic!("verification did not complete")
}
/// The committed output offset the alt takes over from: the start of the abandoned tail hole.
fn reached(report: &HoleReport) -> u64 {
    assert_eq!(report.cause, HoleCause::TailAbandoned);
    report.out.start
}
fn checks(size: usize, crc32: u32) -> MemberChecks {
    MemberChecks { size: size as u64, crc32: Some(crc32), blake2sp: None }
}
fn alt_checks(alt: &[Vec<u8>]) -> (u64, u32) {
    let map = MemberMap::from_memory(&refs(alt), alt_name(0), None).unwrap();
    let member = &map.members[0];
    let checks = member.checks.as_ref().unwrap();
    assert!(!checks.keyed);
    (member.unpacked_size.unwrap(), checks.crc32.unwrap())
}
/// Streams `[reached, end)` of the alt into the partial through `MemberReader`, polled like a download.
fn fill_from_alt(file: &mut PartialFile, alt: &[Vec<u8>], reached: u64) -> u64 {
    let map = MemberMap::from_memory(&refs(alt), alt_name(0), None).unwrap();
    let provider = Provider { volumes: alt.to_vec(), available: usize::MAX, names: alt_name };
    let mut reader = MemberReader::new(Box::new(provider), &map, 0, reached, MapOptions::new(alt_name(0))).unwrap();
    let mut writer = file.fill_writer(reached).unwrap();
    let written = loop {
        match reader.poll_write_to(&mut Context::from_waker(Waker::noop()), &mut writer) {
            Poll::Ready(result) => break result.unwrap(),
            Poll::Pending => continue,
        }
    };
    writer.finish().unwrap();
    written
}

const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];
/// One RAR5 AES-256 stored member "movie.bin" (password "pw", keyed checks, no check value), its ciphertext in
/// volumes of `chunk` bytes.
fn encrypted(plain: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
    let mut padded = plain.to_vec();
    padded.resize(plain.len().div_ceil(16) * 16, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &IV, &padded).unwrap();
    let mut extra = vec![36, 1, 0, 2, 1];
    extra.extend(SALT);
    extra.extend(IV);
    let mut spec = common::FileSpec::new("movie.bin", &cipher);
    spec.size = Some(plain.len() as u64);
    spec.extra = extra;
    let parts: Vec<&[u8]> = cipher.chunks(chunk).collect();
    parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let last = index + 1 == parts.len();
            let crc = zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(if last { plain } else { part }), &hash_key);
            let mut bytes = common::SIG.to_vec();
            bytes.extend(common::main_block(true, Some(index as u64)));
            bytes.extend(common::file_block(&spec, part, crc, index > 0, !last));
            bytes.extend(common::end_block(!last));
            bytes
        })
        .collect()
}

/// Every file under `dir` with its bytes and modification time, sorted by path.
fn listing(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            if meta.is_dir() {
                out.push((entry.path(), Vec::new(), meta.modified().unwrap()));
                stack.push(entry.path());
            } else {
                out.push((entry.path(), std::fs::read(entry.path()).unwrap(), meta.modified().unwrap()));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}
/// `good` and `remaining` partition the member's output.
fn assert_partition(good: &[std::ops::Range<u64>], remaining: &[std::ops::Range<u64>], size: u64) {
    let mut all: Vec<_> = good.iter().chain(remaining).cloned().collect();
    all.sort_by_key(|r| r.start);
    let mut at = 0;
    for r in &all {
        assert_eq!(r.start, at, "good {good:?} and remaining {remaining:?} must tile 0..{size}");
        at = r.end;
    }
    assert_eq!(at, size);
}
fn scan(dir: &Path, rehash: bool) -> HeldScan {
    load_held(&dir.join("state"), &dir.join("out"), &HeldOptions { rehash, ..HeldOptions::default() }).unwrap()
}
/// The output range volume `volume`'s piece of member 0 carries, with its packed range.
fn piece(volumes: &[Vec<u8>], volume: u32) -> (std::ops::Range<u64>, std::ops::Range<u64>) {
    let map = MemberMap::from_memory(&refs(volumes), primary_name(0), None).unwrap();
    let piece = map.members[0].pieces.iter().find(|p| p.volume == volume).unwrap();
    (piece.out.clone().unwrap(), piece.packed.clone())
}

#[test]
fn a_live_handle_reports_its_committed_output_without_its_holes() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, mut file, key, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let held = file.held_output().unwrap();
    assert_eq!(held.output_path.canonicalize().unwrap(), dir.path().join("out/movie.bin").canonicalize().unwrap());
    assert_eq!(held.relative_output, Path::new("movie.bin"));
    assert_eq!(held.member, key);
    assert_eq!(&*held.name, b"movie.bin");
    assert_eq!(held.size, gold.len() as u64);
    assert!(!held.finished);
    let (out3, _) = piece(&primary, 3);
    assert_eq!(held.good, vec![0..out3.end], "four volumes' output");
    assert_partition(&held.good, &file.remaining().unwrap(), held.size);
    // A late bad article in volume 1 takes its output out of `good`.
    let (out1, packed1) = piece(&primary, 1);
    file.declare_hole(1, packed1.start + 100..packed1.start + 300).unwrap();
    let held = file.held_output().unwrap();
    assert_eq!(held.good, vec![0..out1.start + 100, out1.start + 300..out3.end]);
    assert_partition(&held.good, &file.remaining().unwrap(), held.size);
    // Filling the hole with the right plaintext brings it back.
    let at = out1.start + 100;
    file.fill(at, &gold[at as usize..at as usize + 200]).unwrap();
    assert_eq!(file.held_output().unwrap().good, vec![0..out3.end]);
}

#[test]
fn an_abandoned_tail_is_held_as_unknown_until_filled() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let alt = alt(&gold);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, mut file, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let before = file.held_output().unwrap();
    let report = file.abandon_tail(Some(checks(gold.len(), zipfast::crc32::hash(&gold)))).unwrap();
    let held = file.held_output().unwrap();
    assert!(held.finished);
    assert_eq!(held.good, before.good);
    assert_eq!(held.good, vec![0..reached(&report)]);
    assert_eq!(held.checks, Some(checks(gold.len(), zipfast::crc32::hash(&gold))));
    fill_from_alt(&mut file, &alt, reached(&report));
    assert_eq!(file.held_output().unwrap().good, vec![0..gold.len() as u64]);
}

#[test]
fn load_held_reads_a_closed_state_like_the_live_handle_and_changes_nothing() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, mut file, key, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let (_, packed1) = piece(&primary, 1);
    file.declare_hole(1, packed1.start + 100..packed1.start + 300).unwrap();
    // While the handle lives the bundle is held: skipped as Busy.
    let busy = scan(dir.path(), false);
    assert!(busy.held.is_empty());
    assert!(matches!(busy.skipped[0].error.kind, PartialErrorKind::Busy), "{:?}", busy.skipped);
    let live = file.held_output().unwrap();
    drop(file);
    let before = listing(dir.path());
    for rehash in [false, true] {
        let scanned = scan(dir.path(), rehash);
        assert!(scanned.skipped.is_empty(), "{:?}", scanned.skipped);
        assert_eq!(scanned.held.len(), 1);
        let held = &scanned.held[0];
        assert_eq!(held.member, key);
        assert_eq!(held.good, live.good, "rehash {rehash}");
        assert_eq!(held.size, live.size);
        assert_eq!(held.checks, live.checks);
        assert_eq!(held.relative_output, live.relative_output);
        assert_eq!(
            std::fs::canonicalize(&held.output_path).unwrap(),
            std::fs::canonicalize(&live.output_path).unwrap()
        );
    }
    assert!(listing(dir.path()) == before, "load_held changed the state or output directory");
}

#[test]
fn load_held_rehashes_an_output_that_is_not_the_recorded_file() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, file, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let live = file.held_output().unwrap();
    drop(file);
    // A copy (another inode) with one byte changed inside volume 2's output.
    let output = dir.path().join("out/movie.bin");
    let mut bytes = std::fs::read(&output).unwrap();
    let (out2, _) = piece(&primary, 2);
    bytes[out2.start as usize + 5] ^= 1;
    std::fs::remove_file(&output).unwrap();
    std::fs::write(&output, &bytes).unwrap();
    let scanned = scan(dir.path(), false);
    let good = &scanned.held[0].good;
    assert!(good.iter().all(|r| r.end <= out2.start || r.start >= out2.end), "{good:?} keeps the changed leaf");
    assert!(good.iter().any(|r| r.start == 0), "{good:?}");
    assert!(good.len() <= live.good.len() + 1);
}

#[test]
fn load_held_skips_a_damaged_bundle_and_ignores_a_torn_record() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, file, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let live = file.held_output().unwrap();
    drop(file);
    let bundle = std::fs::read_dir(dir.path().join("state")).unwrap().next().unwrap().unwrap().path();
    // A record cut short by a crash during its write is ignored.
    std::fs::write(bundle.join(format!("r-{}", "a".repeat(64))), b"ZFPART1\0torn").unwrap();
    let scanned = scan(dir.path(), false);
    assert!(scanned.skipped.is_empty(), "{:?}", scanned.skipped);
    assert_eq!(scanned.held[0].good, live.good);
    // A damaged page the newest record names makes the bundle unreadable: skipped, never guessed at.
    for entry in std::fs::read_dir(&bundle).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap().to_str().unwrap().starts_with("p-") {
            let mut bytes = std::fs::read(&path).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            std::fs::write(&path, bytes).unwrap();
        }
    }
    let scanned = scan(dir.path(), false);
    assert!(scanned.held.is_empty());
    assert_eq!(scanned.skipped.len(), 1);
    assert_eq!(scanned.skipped[0].bundle, bundle);
    // Entries that are not bundles are ignored.
    std::fs::write(dir.path().join("state/notes.txt"), b"x").unwrap();
    assert_eq!(scan(dir.path(), false).skipped.len(), 1);
}

#[test]
fn an_encrypted_member_with_keyed_checks_reports_no_plaintext_checks() {
    let gold = gold(10_000);
    let primary = encrypted(&gold, 1008);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, file, .. } = primary_dies(dir.path(), &primary, 4, Some("pw"));
    drop(session);
    let held = file.held_output().unwrap();
    assert_eq!(held.checks, None);
    assert!(!held.good.is_empty());
    assert_partition(&held.good, &file.remaining().unwrap(), held.size);
    drop(file);
    let scanned = scan(dir.path(), false);
    assert!(scanned.skipped.is_empty(), "{:?}", scanned.skipped);
    assert_eq!(scanned.held[0].good, held.good);
    assert_eq!(scanned.held[0].checks, None);
}

/// A closed primary: four of ten volumes extracted, the handle dropped. Returns the tempdir, the live held output
/// and the bundle directory.
fn closed_primary() -> (tempfile::TempDir, HeldOutput, std::path::PathBuf) {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, file, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let live = file.held_output().unwrap();
    drop(file);
    let bundle = std::fs::read_dir(dir.path().join("state")).unwrap().next().unwrap().unwrap().path();
    (dir, live, bundle)
}
/// The bundle's newest record: its path and bytes.
fn newest_record(bundle: &Path) -> (std::path::PathBuf, Vec<u8>) {
    let mut best: Option<(u64, std::path::PathBuf, Vec<u8>)> = None;
    for entry in std::fs::read_dir(bundle).unwrap() {
        let path = entry.unwrap().path();
        if !path.file_name().unwrap().to_str().unwrap().starts_with("r-") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        // magic (8), version (2), kind (1), then the sequence
        let sequence = u64::from_le_bytes(bytes[11..19].try_into().unwrap());
        if best.as_ref().is_none_or(|(s, _, _)| sequence > *s) {
            best = Some((sequence, path, bytes));
        }
    }
    let (_, path, bytes) = best.unwrap();
    (path, bytes)
}
/// `bytes` (a record) after `edit`, with its checksum recomputed, written next to the others under its digest name.
fn write_record(bundle: &Path, mut bytes: Vec<u8>, edit: impl FnOnce(&mut [u8])) {
    let split = bytes.len() - 4;
    edit(&mut bytes[..split]);
    let crc = crc32fast::hash(&bytes[..split]);
    bytes[split..].copy_from_slice(&crc.to_le_bytes());
    let digest: String = zipfast::crypto::sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(bundle.join(format!("r-{digest}")), bytes).unwrap();
}

#[test]
fn load_held_reads_state_it_cannot_write() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, live, bundle) = closed_primary();
    let files: Vec<_> = std::fs::read_dir(&bundle).unwrap().map(|e| e.unwrap().path()).collect();
    for path in &files {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o555)).unwrap();
    let scanned = scan(dir.path(), false);
    std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o700)).unwrap();
    for path in &files {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(scanned.skipped.is_empty(), "{:?}", scanned.skipped);
    assert_eq!(scanned.held[0].good, live.good);
}

#[test]
fn a_newer_record_of_an_unknown_version_or_kind_skips_the_bundle() {
    for (what, field, value) in [("version", 8..10, vec![2u8, 0]), ("kind", 10..11, vec![9u8])] {
        let (dir, _, bundle) = closed_primary();
        let (_, bytes) = newest_record(&bundle);
        write_record(&bundle, bytes, |b| {
            let sequence = u64::from_le_bytes(b[11..19].try_into().unwrap()) + 1;
            b[11..19].copy_from_slice(&sequence.to_le_bytes());
            b[field.clone()].copy_from_slice(&value);
        });
        let scanned = scan(dir.path(), false);
        assert!(scanned.held.is_empty(), "{what}: an older record was used in its place");
        let kind = &scanned.skipped[0].error.kind;
        match what {
            "version" => assert!(matches!(kind, PartialErrorKind::StateVersion), "{kind:?}"),
            _ => assert!(matches!(kind, PartialErrorKind::StateMalformed), "{kind:?}"),
        }
    }
}

#[test]
fn a_fifo_in_place_of_the_lock_or_a_record_is_skipped_without_blocking() {
    for name in ["lock".to_string(), format!("r-{}", "b".repeat(64))] {
        let (dir, _, bundle) = closed_primary();
        let path = bundle.join(&name);
        let _ = std::fs::remove_file(&path);
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        let (done, wait) = std::sync::mpsc::channel();
        let root = dir.path().to_path_buf();
        std::thread::spawn(move || done.send(scan(&root, false)).unwrap());
        let scanned = wait.recv_timeout(std::time::Duration::from_secs(20)).expect("load_held blocked on a FIFO");
        assert!(scanned.held.is_empty(), "{name}");
        assert!(matches!(scanned.skipped[0].error.kind, PartialErrorKind::UnsafePath), "{name}: {:?}", scanned.skipped);
    }
}

#[test]
fn tied_newest_records_charge_their_shared_leaves_once() {
    let (dir, live, bundle) = closed_primary();
    let with = |leaves: u32| {
        let options =
            HeldOptions { limits: PartialLimits { crc_leaves: leaves, ..PartialLimits::default() }, rehash: false };
        load_held(&dir.path().join("state"), &dir.path().join("out"), &options).unwrap()
    };
    // The fewest leaves one record needs.
    let needed = (1..1000).find(|&n| !with(n).held.is_empty()).unwrap();
    // Another record at the same sequence naming the same pages (an intent retried after a failed anchor update).
    let (_, bytes) = newest_record(&bundle);
    write_record(&bundle, bytes, |b| {
        let transaction = u64::from_le_bytes(b[19..27].try_into().unwrap()) ^ 0x5555;
        b[19..27].copy_from_slice(&transaction.to_le_bytes());
    });
    let scanned = with(needed);
    assert!(scanned.skipped.is_empty(), "{:?}", scanned.skipped);
    assert_eq!(scanned.held[0].good, live.good);
}

#[test]
fn a_bundle_over_the_journal_limits_is_skipped_with_the_limit() {
    let (dir, live, bundle) = closed_primary();
    let records = std::fs::read_dir(&bundle)
        .unwrap()
        .filter(|e| e.as_ref().unwrap().file_name().to_str().unwrap().starts_with("r-"))
        .count();
    if records < 2 {
        // A second record (a tie of the newest) so a one-record bound is exceeded.
        let (_, bytes) = newest_record(&bundle);
        write_record(&bundle, bytes, |b| b[19] ^= 0x55);
    }
    let with = |limits: PartialLimits| {
        load_held(&dir.path().join("state"), &dir.path().join("out"), &HeldOptions { limits, rehash: false }).unwrap()
    };
    for (what, limits, resource) in [
        ("records", PartialLimits { journal_records: 1, ..PartialLimits::default() }, PartialResource::JournalRecords),
        ("bytes", PartialLimits { journal_bytes: 0, ..PartialLimits::default() }, PartialResource::JournalBytes),
    ] {
        let scanned = with(limits);
        assert!(scanned.held.is_empty(), "{what}");
        assert!(
            matches!(&scanned.skipped[0].error.kind, PartialErrorKind::Limit { resource: r, .. } if *r == resource),
            "{what}: {:?}",
            scanned.skipped
        );
    }
    assert_eq!(with(PartialLimits::default()).held[0].good, live.good);
}
