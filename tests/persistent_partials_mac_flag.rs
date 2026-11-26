//! rar (7.00) sets the RAR 5.0 encryption record's "tweaked checksums" flag only in a split AES member's final part:
//! earlier parts carry plain CRCs of their ciphertext and no flag, the final part keyed member checks and the flag.
//! A persistent session must take those parts as one member (no `BindingMismatch`) and verify the keyed checks.
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

const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];

/// A RAR 5.0 AES-256 stored member "movie.bin" (password "pw") split into volumes of `chunk` ciphertext bytes, as
/// rar 7.00 writes it: only the final part's encryption record has the tweaked-checksum flag and a keyed CRC of the
/// plaintext; the earlier parts have flags 0 and plain CRCs of their ciphertext. `last_kdf` changes the final
/// part's KDF count (a different member).
fn rar_style(plain: &[u8], chunk: usize, last_kdf: u8) -> Vec<Vec<u8>> {
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
    let mut padded = plain.to_vec();
    padded.resize(plain.len().div_ceil(16) * 16, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &IV, &padded).unwrap();
    let record = |flags: u8, kdf: u8| {
        let mut extra = vec![36, 1, 0, flags, kdf];
        extra.extend(SALT);
        extra.extend(IV);
        extra
    };
    let parts: Vec<&[u8]> = cipher.chunks(chunk).collect();
    parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let last = index + 1 == parts.len();
            let mut spec = common::FileSpec::new("movie.bin", &cipher);
            spec.size = Some(plain.len() as u64);
            spec.extra = if last { record(2, last_kdf) } else { record(0, 1) };
            let crc = if last {
                zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(plain), &hash_key)
            } else {
                crc32fast::hash(part)
            };
            let mut bytes = common::SIG.to_vec();
            bytes.extend(common::main_block(true, Some(index as u64)));
            bytes.extend(common::file_block(&spec, part, crc, index > 0, !last));
            bytes.extend(common::end_block(!last));
            bytes
        })
        .collect()
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
    names: fn(u32) -> OsString,
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
            replace_placed_links: false,
            keep_broken: false,
            attempt_continued_members: false,
            salvage_truncated_zip: false,
            unix_modes: Default::default(),
            backslashes: Default::default(),
        },
        names(0),
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
    let provider = Provider { volumes: volumes.to_vec(), available, names };
    ProgressiveSession::new_partial(Box::new(provider), options, partial).unwrap()
}
fn verify(file: &mut PartialFile) -> Verdict {
    for _ in 0..100_000 {
        if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            return result.unwrap();
        }
    }
    panic!("verification did not complete")
}

/// Runs a persistent session over every volume: the member's handle, and the first error the session reported.
fn run(dir: &Path, volumes: &[Vec<u8>]) -> (Option<PartialFile>, Option<String>) {
    run_with(dir, volumes, "pw", primary_name)
}

fn run_with(
    dir: &Path,
    volumes: &[Vec<u8>],
    password: &str,
    names: fn(u32) -> OsString,
) -> (Option<PartialFile>, Option<String>) {
    let anchors = Arc::new(Anchors::default());
    let mut session = session(dir, volumes, usize::MAX, &anchors, Some(password), names);
    let mut file = None;
    let mut error = None;
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                file = Some(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => match outcome {
                MemberOutcome::PersistentComplete { .. } => {}
                MemberOutcome::Refused { reason, .. } => {
                    error.get_or_insert(format!("refused: {reason:?}"));
                }
                _ => {
                    error.get_or_insert("member not completed as a persistent partial".into());
                }
            },
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                error.get_or_insert(format!("terminated: {failure:?}"));
                break;
            }
            Poll::Ready(Err(e)) => {
                error.get_or_insert(format!("{e:?}"));
                break;
            }
            Poll::Ready(Ok(None)) => break,
            _ => {}
        }
    }
    (file, error)
}

#[test]
fn a_split_aes_member_flagged_keyed_only_in_its_final_part_is_one_member() {
    let dir = tempfile::tempdir().unwrap();
    let plain = gold(10_000);
    let volumes = rar_style(&plain, 3_000, 1);
    // A member map reports the member's checks keyed, as its final part says, and each piece as its own part says.
    let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
    let map = zipfast::map::MemberMap::from_memory(&refs, primary_name(0), None).unwrap();
    let member = &map.members[0];
    assert!(matches!(member.cipher, Some(zipfast::map::CipherParams::Rar5 { keyed_checks: true, .. })));
    assert!(member.pieces.iter().map(|p| p.checks.keyed).eq([false, false, false, true]));
    let (file, error) = run(dir.path(), &volumes);
    assert_eq!(error, None, "the session took every part as the member's");
    let mut file = file.expect("member created");
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }), "keyed member checks verified");
    assert_eq!(std::fs::read(dir.path().join("out/movie.bin")).unwrap(), plain);
    // The final part's flag makes the member's checks keyed, so a handle reopened from the state keeps them keyed.
    let state = file.close().unwrap();
    assert_eq!(state.member().ordinal(), 0);
}

#[test]
fn a_final_part_naming_another_kdf_count_is_still_another_member() {
    let dir = tempfile::tempdir().unwrap();
    let volumes = rar_style(&gold(10_000), 3_000, 2);
    let (_, error) = run(dir.path(), &volumes);
    assert!(error.is_some(), "a different KDF count in the final part is not accepted");
}

fn fixture_name(index: u32) -> OsString {
    format!("r.part{}.rar", index + 1).into()
}

/// RustyGet's z-fixtures (set `ZIPFAST_Z_FIXTURES` to the sets directory): rar 7.00 AES stored sets, where only the
/// last part flags keyed checks. A persistent session extracts the whole member and verifies it.
#[test]
fn rar_made_aes_stored_sets_extract_persistently() {
    let Some(sets) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(std::path::PathBuf::from) else {
        eprintln!("skipped: set ZIPFAST_Z_FIXTURES to the z-fixtures sets directory");
        return;
    };
    let manifest = std::fs::read_to_string(sets.join("MANIFEST.json")).unwrap();
    let password = manifest.split("\"password\"").nth(1).and_then(|s| s.split('"').nth(1)).unwrap().to_owned();
    let payload = std::fs::read(sets.join("cabac.mkv")).unwrap();
    // F02 (the same with `-hp`) is left out: persistent sessions refuse encrypted headers (`UnsupportedMethod`).
    let set = "F01_rar5_store_aes";
    let volumes: Vec<Vec<u8>> = (0..)
        .map(|i| sets.join(set).join(fixture_name(i)))
        .take_while(|p| p.exists())
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    assert!(volumes.len() > 1, "{set}: a split set");
    let dir = tempfile::tempdir().unwrap();
    let (file, error) = run_with(dir.path(), &volumes, &password, fixture_name);
    assert_eq!(error, None, "{set}: no BindingMismatch at the last volume");
    let mut file = file.unwrap_or_else(|| panic!("{set}: member created"));
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }), "{set}: verified");
    assert_eq!(std::fs::read(file.output_path()).unwrap(), payload, "{set}: output");
}
