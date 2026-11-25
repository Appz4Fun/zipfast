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

//! Alt takeover of a persistent member whose primary download died mid-member: `PartialFile::abandon_tail` ends it
//! at its committed `produced`, and `[produced, size)` is filled with plaintext from a copy packed differently.
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
mod common;
#[path = "common/partial_state.rs"]
mod partial_state;
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

#[test]
fn rar5_stored_primary_killed_partway_is_taken_over_by_a_differently_packed_alt() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let alt = alt(&gold);
    let dir = tempfile::tempdir().unwrap();
    // Volumes 1 to 4 arrive; the fifth never does.
    let Primary { session, mut file, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let output = dir.path().join("out/movie.bin");
    let inode = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&output).unwrap());
    // Before the abandon, a fill past `produced` is refused.
    assert!(file.fill(9_000, &gold[9_000..]).is_err());
    let (size, crc32) = alt_checks(&alt);
    assert_eq!(size, gold.len() as u64);
    let report = file.abandon_tail(Some(checks(gold.len(), crc32))).unwrap();
    let reached = reached(&report);
    assert!(reached > 0 && reached <= 4_000, "reached {reached}");
    assert_eq!(report.out, reached..gold.len() as u64);
    assert_eq!(file.tail_checks().unwrap(), Some(TailChecks::Supplied));
    assert!(matches!(verify(&mut file), Verdict::Incomplete { .. }));
    assert_eq!(file.remaining().unwrap(), vec![reached..gold.len() as u64]);
    assert_eq!(fill_from_alt(&mut file, &alt, reached), gold.len() as u64 - reached);
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(std::fs::read(&output).unwrap(), gold);
    assert_eq!(std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&output).unwrap()), inode);
    // Abandoning again with the same checks changes nothing; with others it is refused.
    file.abandon_tail(Some(checks(gold.len(), crc32))).unwrap();
    let error = file.abandon_tail(Some(checks(gold.len(), crc32 ^ 1))).unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::TailAbandoned), "{error:?}");
}

#[test]
fn a_wrong_supplied_crc_verifies_bad() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let alt = alt(&gold);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, mut file, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let report = file.abandon_tail(Some(checks(gold.len(), zipfast::crc32::hash(&gold) ^ 1))).unwrap();
    fill_from_alt(&mut file, &alt, reached(&report));
    assert!(matches!(verify(&mut file), Verdict::Bad { which: ChecksumAlgorithm::Crc32, .. }));
}

#[test]
fn supplied_checks_must_be_usable() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, mut file, .. } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let crc32 = zipfast::crc32::hash(&gold);
    for supplied in [
        None,
        Some(checks(gold.len() + 1, crc32)),
        Some(MemberChecks { size: gold.len() as u64, crc32: None, blake2sp: None }),
    ] {
        let error = file.abandon_tail(supplied).unwrap_err();
        assert!(matches!(error.kind, PartialErrorKind::InvalidOptions), "{error:?}");
    }
    assert_eq!(file.tail_checks().unwrap(), None);
}

#[test]
fn restart_between_abandon_and_fill_resumes_the_takeover() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let alt = alt(&gold);
    let dir = tempfile::tempdir().unwrap();
    let Primary { session, mut file, key, anchors } = primary_dies(dir.path(), &primary, 4, None);
    drop(session);
    let crc32 = zipfast::crc32::hash(&gold);
    let report = file.abandon_tail(Some(checks(gold.len(), crc32))).unwrap();
    let reached = reached(&report);
    // A first partial fill of the tail, then the process goes away.
    file.fill(reached, &gold[reached as usize..reached as usize + 500]).unwrap();
    let state = partial_state::roundtrip(&file.close().unwrap());
    // A restarted primary (#125), now with every volume, adopts the member as finished and walks past its tail.
    let mut resumed = self::session(dir.path(), &primary, usize::MAX, &anchors, None);
    let mut adopted = None;
    for _ in 0..100_000 {
        match resumed.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialAdopted { finished, produced, .. }))) => {
                adopted = Some((finished, produced))
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    assert_eq!(adopted, Some((true, gold.len() as u64)));
    drop(resumed);
    let expected_anchor = anchors.current(&key).unwrap().unwrap();
    let mut file = PartialFile::open(
        state,
        PartialOpenContext {
            output_root: dir.path().join("out"),
            state_root: dir.path().join("state"),
            expected_member: key,
            expected_anchor,
            protection: Provider { volumes: primary.clone(), available: 0, names: primary_name }.protection().unwrap(),
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors,
            control: SessionControl::default(),
            password: None,
        },
    )
    .unwrap();
    assert_eq!(file.tail_checks().unwrap(), Some(TailChecks::Supplied));
    assert_eq!(file.remaining().unwrap(), vec![reached + 500..gold.len() as u64]);
    fill_from_alt(&mut file, &alt, reached + 500);
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(std::fs::read(dir.path().join("out/movie.bin")).unwrap(), gold);
}

#[test]
fn a_session_still_extracting_the_member_cannot_write_past_an_abandon() {
    let gold = gold(10_000);
    let primary = common::volumes(&common::FileSpec::new("movie.bin", &gold), 1000);
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = session(dir.path(), &primary, usize::MAX, &anchors, None);
    let mut file = None;
    let mut failure = None;
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                let mut handle = session.partial_file(&member).unwrap();
                handle.abandon_tail(Some(checks(gold.len(), zipfast::crc32::hash(&gold)))).unwrap();
                file = Some(handle);
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure: f, .. }))) => {
                failure = Some(format!("{f:?}"));
                break;
            }
            Poll::Ready(Err(f)) => {
                failure = Some(format!("{f:?}"));
                break;
            }
            Poll::Ready(Ok(None)) => break,
            _ => {}
        }
    }
    let failure = failure.expect("the extraction must stop");
    assert!(failure.contains("TailAbandoned"), "{failure}");
    let mut file = file.unwrap();
    fill_from_alt(&mut file, &alt(&gold), 0);
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
}

// --- Encrypted primary -----------------------------------------------------------------------------------------

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

#[test]
fn encrypted_primary_tail_is_filled_with_plaintext_and_verified_with_the_supplied_crc() {
    let gold = gold(10_000);
    let primary = encrypted(&gold, 1008);
    let alt = alt(&gold);
    let (_, crc32) = alt_checks(&alt);
    for wrong in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let Primary { session, mut file, .. } = primary_dies(dir.path(), &primary, 4, Some("pw"));
        drop(session);
        let report = file.abandon_tail(Some(checks(gold.len(), if wrong { crc32 ^ 1 } else { crc32 }))).unwrap();
        let reached = reached(&report);
        // An encrypted member resumes on a block boundary.
        assert_eq!(reached % 16, 0);
        assert_eq!(file.tail_checks().unwrap(), Some(TailChecks::Supplied));
        fill_from_alt(&mut file, &alt, reached);
        let verdict = verify(&mut file);
        if wrong {
            assert!(matches!(verdict, Verdict::Bad { which: ChecksumAlgorithm::Crc32, .. }));
        } else {
            assert!(matches!(verdict, Verdict::Ok { .. }));
            assert_eq!(std::fs::read(dir.path().join("out/movie.bin")).unwrap(), gold);
        }
    }
}

/// An encrypted member whose final (keyed) checks were already read: abandoning its tail with plaintext checks
/// accepts them without comparing them with the keyed values, and repeating the same call is idempotent.
#[test]
fn repeating_an_abandon_with_keyed_archive_checks_is_idempotent() {
    let gold = gold(10_000);
    let primary = encrypted(&gold, 1 << 20);
    assert_eq!(primary.len(), 1);
    let crc32 = zipfast::crc32::hash(&gold);
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = session(dir.path(), &primary, usize::MAX, &anchors, Some("pw"));
    let mut abandoned = None;
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                let mut handle = session.partial_file(&member).unwrap();
                let first = handle.abandon_tail(Some(checks(gold.len(), crc32))).unwrap();
                assert_eq!(handle.tail_checks().unwrap(), Some(TailChecks::Archive));
                let again = handle.abandon_tail(Some(checks(gold.len(), crc32))).unwrap();
                assert_eq!(again.out, first.out);
                abandoned = Some(handle);
                break;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => panic!("finished before the abandon"),
            Poll::Ready(Ok(None)) | Poll::Ready(Err(_)) => break,
            _ => {}
        }
    }
    assert!(abandoned.is_some(), "the member was abandoned");
}
