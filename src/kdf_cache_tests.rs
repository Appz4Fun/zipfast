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

//! RAR 5.0 key derivation runs once per (password, salt, count) for a run or session: every route counted with
//! [`crate::crypto::rar5_derivations`], on real `rar` archives (`tests/fixtures/rar5-kdf-cache`). The password
//! `kdfcache` is used by no other unit test, so the counts are this test's own.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::rar5_derivations;
use crate::extract::{self, Mode, Options, Overwrite};
use crate::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};

const PASSWORD: &str = "kdfcache";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar5-kdf-cache");

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(FIXTURES).join(name)
}

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
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
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
        unverified_output: Default::default(),
        encrypted_links: Default::default(),
    }
}

/// The derivations `work` starts for [`PASSWORD`].
fn derivations(work: impl FnOnce()) -> u64 {
    let before = rar5_derivations(PASSWORD);
    work();
    rar5_derivations(PASSWORD) - before
}

fn progressive(path: &[PathBuf], dest: &Path, password: &str) -> (usize, usize) {
    use crate::progressive::*;
    use std::task::{Context, Poll};
    let volumes =
        path.iter().map(|p| (p.file_name().unwrap().to_owned(), fs::read(p).unwrap().into_boxed_slice())).collect();
    let mut opts = ProgressiveOptions::new(options(dest), path[0].file_name().unwrap().to_owned());
    opts.set_password(Some(password.into())).unwrap();
    let mut session = ProgressiveSession::from_sealed_memory(volumes, opts).unwrap();
    let waker = std::task::Waker::noop();
    let (mut verified, mut failed) = (0, 0);
    loop {
        match session.poll_event(&mut Context::from_waker(waker)) {
            Poll::Pending => std::thread::yield_now(),
            Poll::Ready(Ok(None)) => return (verified, failed),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => {
                if matches!(outcome, MemberOutcome::Verified(_)) {
                    verified += 1;
                } else {
                    failed += 1;
                }
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { .. }))) | Poll::Ready(Err(_)) => {
                return (verified, failed + 1);
            }
            Poll::Ready(Ok(Some(_))) => {}
        }
    }
}

fn vint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// A RAR 5.0 block: CRC32, size, type, flags, then `extra` and `data` (both flagged when present).
fn block(kind: u64, fields: &[u8], extra: &[u8], data: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    vint(kind, &mut body);
    vint(u64::from(!extra.is_empty()) | if data.is_some() { 2 } else { 0 }, &mut body);
    if !extra.is_empty() {
        vint(extra.len() as u64, &mut body);
    }
    if let Some(data) = data {
        vint(data.len() as u64, &mut body);
    }
    body.extend_from_slice(fields);
    body.extend_from_slice(extra);
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(&body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out.extend_from_slice(data.unwrap_or_default());
    out
}

const KDF_COUNT: u8 = 4;

/// A RAR 5.0 archive of stored members encrypted with `password`, member `i` keyed with salt `[salts[i]; 16]`
/// and carrying its password check value, as `rar` writes members added in separate sessions.
fn mixed_salts(password: &str, salts: &[u8]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    out.extend(block(1, &[0], &[], None));
    for (i, &salt) in salts.iter().enumerate() {
        let salt = [salt; 16];
        let iv = [i as u8; 16];
        let name = format!("m{i}.txt");
        let plain = format!("member {i}\n").into_bytes();
        let material = crate::crypto::rar5_material(password.as_bytes(), KDF_COUNT, &salt, FOLD, &mut NoLimit).unwrap();
        let keys = material.keys(None).unwrap();
        let mut padded = plain.clone();
        padded.resize(plain.len().next_multiple_of(16), 0);
        let data = crate::crypto::encrypt_cbc(&keys.key, &iv, &padded).unwrap();
        let check = material.check_value().unwrap();
        let mut record = vec![1, 0, 1, KDF_COUNT]; // type, version, flags (check value), count
        record.extend(salt);
        record.extend(iv);
        record.extend(check);
        record.extend(&crate::crypto::sha256(&check)[..4]);
        let mut extra = Vec::new();
        vint(record.len() as u64, &mut extra);
        extra.extend(record);
        let mut fields = Vec::new();
        vint(0x4, &mut fields); // the CRC32 is present
        vint(plain.len() as u64, &mut fields);
        vint(0x20, &mut fields);
        fields.extend(crc32fast::hash(&plain).to_le_bytes());
        vint(0, &mut fields); // stored
        vint(0, &mut fields); // Windows
        vint(name.len() as u64, &mut fields);
        fields.extend(name.as_bytes());
        out.extend(block(2, &fields, &extra, Some(&data)));
    }
    out.extend(block(5, &[0], &[], None));
    out
}

/// A check value whose checksum holds, so the derivation folds the real one (which a test then reads).
const FOLD: Option<([u8; 8], [u8; 4])> = Some(([0; 8], [0xaf, 0x55, 0x70, 0xf5])); // sha256([0; 8])[..4]

struct NoLimit;
impl crate::crypto::KdfControl for NoLimit {
    fn charge(&mut self, _: u64) -> Result<(), crate::crypto::KdfControlError> {
        Ok(())
    }
}

/// Members salted 1, 1, 2, 1, 2, 3: three salts.
const MIXED: [u8; 6] = [1, 1, 2, 1, 2, 3];

/// `hp3.rar` (`-hp`, three members) and `vols.part*.rar` (`-hp`, four volumes) carry one salt in every encrypted
/// header and file record, as `rar` writes them, and `p3.rar` (`-p`) in every file record; the synthetic archive
/// salts its members three ways. Each route derives once per salt: before the cache, once per volume with encrypted
/// headers and once more per member.
#[test]
fn rar5_keys_are_derived_once_per_salt_on_every_route() {
    let dir = tempfile::tempdir().unwrap();
    let mixed = dir.path().join("mixed.rar");
    fs::write(&mixed, mixed_salts(PASSWORD, &MIXED)).unwrap();
    let vols: Vec<PathBuf> = (1..=4).map(|n| fixture(&format!("vols.part{n}.rar"))).collect();
    for (name, paths, members, salts) in [
        ("hp3.rar", vec![fixture("hp3.rar")], 3, 1),
        ("p3.rar", vec![fixture("p3.rar")], 3, 1),
        ("vols", vols, 3, 1),
        ("mixed salts", vec![mixed.clone()], 6, 3),
    ] {
        let first = &paths[0];

        // the whole-archive runner
        let out = dir.path().join(format!("run-{name}"));
        let n = derivations(|| {
            let summary = extract::run_with_password(first, &options(&out), Some(PASSWORD), |_| {}).unwrap();
            assert!(summary.errors.is_empty(), "{name}: {:?}", summary.errors);
            assert_eq!(summary.files, members, "{name}");
        });
        assert_eq!(n, salts, "{name}: whole-archive run");

        // listing: only encrypted headers need a key
        let n = derivations(|| {
            let listed = extract::list_with_password(first, Some(PASSWORD)).unwrap();
            assert_eq!(listed.len() as u64, members, "{name}");
        });
        assert_eq!(n, u64::from(name != "p3.rar" && name != "mixed salts"), "{name}: listing");

        // RarSession: catalogue, then extraction of every member, sharing the catalogue's keys
        let out = dir.path().join(format!("selected-{name}"));
        let n = derivations(|| {
            let mut session = RarSession::open(first, Some(PASSWORD), RarSessionOptions::default()).unwrap();
            let all = session.select(|_| true).unwrap();
            let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
            assert_eq!((summary.files, summary.failed), (members, 0), "{name}: {summary:?}");
        });
        assert_eq!(n, salts, "{name}: RarSession");

        // the progressive session
        let out = dir.path().join(format!("progressive-{name}"));
        let n = derivations(|| assert_eq!(progressive(&paths, &out, PASSWORD), (members as usize, 0), "{name}"));
        assert_eq!(n, salts, "{name}: progressive session");
    }
}

/// The cache keeps the derived check value, not a verdict: with a wrong password every encrypted member still
/// fails its own check, on one derivation per salt.
#[test]
fn a_wrong_password_fails_every_member_on_one_derivation_per_salt() {
    const WRONG: &str = "kdfcache-wrong";
    let dir = tempfile::tempdir().unwrap();
    let mixed = dir.path().join("mixed.rar");
    // made with a password of its own: building it derives nothing another test counts
    fs::write(&mixed, mixed_salts("kdfcache-mixed", &MIXED)).unwrap();
    for (path, members, salts) in [(fixture("p3.rar"), 3, 1), (mixed, 6, 3)] {
        let before = rar5_derivations(WRONG);
        let out = dir.path().join("run");
        let summary = extract::run_with_password(&path, &options(&out), Some(WRONG), |_| {}).unwrap();
        assert_eq!(summary.files, 0);
        assert_eq!(summary.errors.len(), members, "{:?}", summary.errors);
        assert!(summary.errors.iter().all(|e| e.contains("wrong password")), "{:?}", summary.errors);
        assert_eq!(rar5_derivations(WRONG) - before, salts);

        let before = rar5_derivations(WRONG);
        let mut session = RarSession::open(&path, Some(WRONG), RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let out = dir.path().join("selected");
        let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!((summary.files, summary.failed), (0, members as u64), "{summary:?}");
        assert_eq!(rar5_derivations(WRONG) - before, salts);
        assert!(!out.join("m0.txt").exists() && !out.join("a1.txt").exists());
    }
}

/// The cache is keyed by password as well as salt and count, keeps at most [`KdfCache::KEPT`] inputs (the least
/// recently used dropped first), and a hit compares the member's own check value.
#[test]
fn the_cache_is_keyed_bounded_and_checks_each_member() {
    use crate::crypto::{KdfCache, Rar5CryptError, Rar5CryptParams, Rar5KeyCache};
    use crate::error::RarPasswordEvidence;
    const PW: &str = "kdfcache-unit";
    let params = |salt: u8, check: Option<([u8; 8], [u8; 4])>| Rar5CryptParams {
        kdf_count: 2,
        salt: [salt; 16],
        iv: [0; 16],
        check,
        tweaked_crc: false,
    };
    let checked = |password: &str, salt: u8| {
        let check = crate::crypto::rar5_material(password.as_bytes(), 2, &[salt; 16], FOLD, &mut NoLimit)
            .unwrap()
            .check_value()
            .unwrap();
        Some((check, <[u8; 4]>::try_from(&crate::crypto::sha256(&check)[..4]).unwrap()))
    };
    let own = checked(PW, 1);
    let mut cache = Rar5KeyCache::default();
    let before = rar5_derivations(PW);
    let first = cache.keys(PW, &params(1, own), None).unwrap();
    assert_eq!(first.evidence, RarPasswordEvidence::VerifierMatched);
    let fresh = crate::crypto::derive_rar5_keys(PW, 2, &[1; 16], None).unwrap();
    assert_eq!((first.key, first.hash_key), (fresh.key, fresh.hash_key));
    assert_eq!(rar5_derivations(PW) - before, 2, "the cache's run and the reference one");
    // a hit: no derivation; still each member's own check, or its absence, decides
    let again = cache.keys(PW, &params(1, None), None).unwrap();
    assert_eq!(again.evidence, RarPasswordEvidence::VerifierUnavailable(crate::error::RarVerifierUnavailable::Absent));
    assert!(matches!(
        cache.keys(PW, &params(1, checked("other", 1)), None),
        Err(crate::crypto::ControlledKdfError::Crypt(Rar5CryptError::WrongPassword))
    ));
    let bad_sum = Some((checked("other", 1).unwrap().0, [0; 4]));
    assert!(cache.keys(PW, &params(1, bad_sum), None).is_ok(), "a check value that fails its checksum proves nothing");
    assert_eq!(rar5_derivations(PW) - before, 2);
    // another password with the same salt is its own input
    assert!(matches!(
        cache.keys("kdfcache-unit2", &params(1, own), None),
        Err(crate::crypto::ControlledKdfError::Crypt(Rar5CryptError::WrongPassword))
    ));
    // bounded: KEPT more salts push salt 1 out, so it derives again
    for salt in 2..2 + KdfCache::<(u8, [u8; 16]), crate::crypto::Rar5Derived>::KEPT as u8 {
        cache.keys(PW, &params(salt, None), None).unwrap();
    }
    assert_eq!(cache.len(), Rar5KeyCache::KEPT);
    let n = rar5_derivations(PW);
    cache.keys(PW, &params(1, None), None).unwrap();
    assert_eq!(rar5_derivations(PW) - n, 1);
    assert_eq!(cache.len(), Rar5KeyCache::KEPT);
    // least recently used: salt 1 was just used, so the oldest other one goes first
    let n = rar5_derivations(PW);
    cache.keys(PW, &params(1, None), None).unwrap();
    cache.keys(PW, &params(200, None), None).unwrap();
    cache.keys(PW, &params(1, None), None).unwrap();
    assert_eq!(rar5_derivations(PW) - n, 1);
    // material derived for a member without a check value can't verify a later one with it: that one derives again
    let own77 = checked(PW, 77);
    let wrong77 = checked("other", 77);
    let n = rar5_derivations(PW);
    cache.keys(PW, &params(77, None), None).unwrap();
    let verified = cache.keys(PW, &params(77, own77), None).unwrap();
    assert_eq!(verified.evidence, RarPasswordEvidence::VerifierMatched);
    assert!(matches!(
        cache.keys(PW, &params(77, wrong77), None),
        Err(crate::crypto::ControlledKdfError::Crypt(Rar5CryptError::WrongPassword))
    ));
    assert_eq!(rar5_derivations(PW) - n, 2);
    // canceled before a derivation stops it; a hit has nothing to cancel
    let canceled = crate::extract::Cancellation::default();
    canceled.cancel();
    assert!(cache.keys(PW, &params(1, None), Some(&canceled)).is_ok());
    assert!(matches!(
        cache.keys(PW, &params(250, None), Some(&canceled)),
        Err(crate::crypto::ControlledKdfError::Control(crate::crypto::KdfControlError::Canceled))
    ));
}

/// Progressive sessions cache through their [`crate::progressive::Usage`]: a repeated input charges no KDF work,
/// for RAR 5.0, RAR 3.x and 7zAES alike, and a new salt is charged in full.
#[test]
fn progressive_usage_charges_kdf_work_once_per_input() {
    use crate::progressive::{ProgressiveLimits, Resource, SessionControl, Usage};
    let usage = Usage::new(ProgressiveLimits::default());
    let control = SessionControl::default();
    let used = || usage.used(Resource::KdfSessionBlocks);
    let params = |salt: u8| crate::crypto::Rar5CryptParams {
        kdf_count: 3,
        salt: [salt; 16],
        iv: [0; 16],
        check: None,
        tweaked_crc: false,
    };
    let rar5 = crate::rar5::member::session_rar5_keys("pw", &params(1), &usage, &control).unwrap();
    let one = used();
    assert!(one > 0);
    let again = crate::rar5::member::session_rar5_keys("pw", &params(1), &usage, &control).unwrap();
    assert_eq!((again.key, used()), (rar5.key, one));
    crate::rar5::member::session_rar5_keys("pw", &params(2), &usage, &control).unwrap();
    assert_eq!(used(), 2 * one);
    crate::rar5::member::session_rar5_keys("pw2", &params(1), &usage, &control).unwrap();
    assert_eq!(used(), 3 * one, "another password derives for itself");

    let base = used();
    let rar4 = crate::rar5::member::controlled_legacy_keys("pw", &[1; 8], &usage, &control).unwrap();
    let rar4_cost = used() - base;
    assert!(rar4_cost > 0);
    assert_eq!(crate::rar5::member::controlled_legacy_keys("pw", &[1; 8], &usage, &control).unwrap(), rar4);
    assert_eq!(rar4, crate::crypto::derive_rar4_key_iv("pw", &[1; 8]));
    assert_eq!(used() - base, rar4_cost);

    let base = used();
    let key = crate::rar5::member::session_7z_key("pw", &[7; 8], 6, &usage, &control).unwrap().unwrap();
    let seven_cost = used() - base;
    assert!(seven_cost > 0);
    assert_eq!(crate::rar5::member::session_7z_key("pw", &[7; 8], 6, &usage, &control).unwrap().unwrap(), key);
    assert_eq!(key, crate::crypto::derive_7z_key("pw", &[7; 8], 6).unwrap());
    assert_eq!(used() - base, seven_cost);
    // a canceled session stops before a cached RAR 5.0 input too, as it did before the cache
    control.cancel();
    assert!(
        crate::rar5::member::controlled_keys(
            "pw",
            params(1),
            &usage,
            &control,
            crate::error::RarScope::Member { index: None }
        )
        .is_err()
    );
}
