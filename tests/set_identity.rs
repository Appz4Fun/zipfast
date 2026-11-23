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

//! A set's identity from the held bytes of its first volume, its last volume or both (`map::set_identity`).
mod common;

use common::FileSpec;
use std::path::Path;
use zipfast::map::*;

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(path)).unwrap()
}

fn held(bytes: &[u8], head: usize, tail: usize) -> HeldVolume<'_> {
    let head = head.min(bytes.len());
    let tail = tail.min(bytes.len());
    HeldVolume::new(&bytes[..head], &bytes[bytes.len() - tail..], bytes.len() as u64).unwrap()
}

fn id(first: Option<HeldVolume<'_>>, last: Option<HeldVolume<'_>>, password: Option<&str>) -> SetIdentity {
    set_identity(first, last, MapOptions::new("set").password(password)).unwrap()
}

#[test]
fn rar5_split_member_gets_its_name_from_the_first_volume_and_its_crc_from_the_last() {
    let data: Vec<u8> = (0..50_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let spec = FileSpec::new("movie.mkv", &data);
    let vols = common::volumes(&spec, 20_000);
    let (first, last) = (&vols[0], vols.last().unwrap());
    let crc = crc32fast::hash(&data);
    // Only the first volume's first bytes: name, size and method, but a split member's checks are in its last part.
    let a = id(Some(held(first, 200, 0)), None, None);
    let m = &a.members[0];
    assert_eq!((a.format, m.name.as_deref(), m.unpacked_size), (MapFormat::Rar5, Some("movie.mkv"), Some(50_000)));
    assert_eq!((m.method, m.size_from, m.encrypted), (Some(MapMethod::Stored), Some(FactSource::First), Some(false)));
    assert_eq!(m.dictionary, Some(128 << 10));
    assert!(m.checks.is_none() && m.checks_from.is_none());
    // Only the last volume's first bytes: everything, the checks from its last part.
    let b = id(None, Some(held(last, 200, 0)), None);
    assert_eq!(b.members[0].checks.and_then(|c| c.crc32), Some(crc));
    assert_eq!(b.members[0].unpacked_size, Some(50_000));
    // Both: one member, size from the first volume, checks from the last.
    let c = id(Some(held(first, 200, 0)), Some(held(last, 200, 0)), None);
    assert_eq!(c.members.len(), 1);
    let m = &c.members[0];
    assert_eq!((m.size_from, m.checks_from), (Some(FactSource::First), Some(FactSource::Last)));
    assert_eq!(m.checks.and_then(|c| c.crc32), Some(crc));
    // The same file in another container agrees in size and CRC32.
    let single = common::archive(&[FileSpec::new("movie.mkv", &data)]);
    let s = id(Some(HeldVolume::whole(&single)), Some(HeldVolume::whole(&single)), None);
    assert_eq!((s.members[0].unpacked_size, s.members[0].checks.and_then(|c| c.crc32)), (Some(50_000), Some(crc)));
}

#[test]
fn neither_volume_is_not_an_archive() {
    assert!(matches!(set_identity(None, None, MapOptions::new("x")), Err(MapError::NotArchive)));
}

#[test]
fn rar4_volumes_agree_with_their_listing() {
    let first = fixture("rar4-volumes/multi.part1.rar");
    let last = fixture("rar4-volumes/multi.part3.rar");
    let s = id(Some(HeldVolume::whole(&first)), Some(HeldVolume::whole(&last)), None);
    assert_eq!(s.format, MapFormat::Rar4);
    assert!(!s.members.is_empty());
    for m in &s.members {
        assert!(m.unpacked_size.is_some() && m.method.is_some(), "{:?}", m.name);
    }
    // Every member that ends in the last volume has its final CRC from there.
    let full =
        MemberMap::from_memory(&[&first, &fixture("rar4-volumes/multi.part2.rar"), &last], "multi.part1.rar", None)
            .unwrap();
    for m in &full.members {
        let got = s.members.iter().find(|x| x.raw_name == m.raw_name).expect("listed");
        assert_eq!(got.unpacked_size, m.unpacked_size, "{:?}", m.name);
        if got.checks.is_some() {
            assert_eq!(got.checks.and_then(|c| c.crc32), m.checks.and_then(|c| c.crc32), "{:?}", m.name);
        }
    }
}

#[test]
fn seven_zip_reads_its_end_header_and_coder_dictionary() {
    let lzma2 = fixture("7z-extract/lzma2.7z");
    let s = id(None, Some(HeldVolume::whole(&lzma2)), None);
    assert_eq!(s.format, MapFormat::SevenZip);
    let file = s.members.iter().find(|m| !m.is_dir).unwrap();
    assert_eq!(file.method, Some(MapMethod::Coders));
    assert!(file.dictionary.is_some_and(|d| d >= 4096), "{:?}", file.dictionary);
    assert!(file.checks.and_then(|c| c.crc32).is_some());
    // A single volume given as the first alone is read as a last volume.
    let alone = id(Some(HeldVolume::whole(&lzma2)), None, None);
    let facts =
        |s: &SetIdentity| s.members.iter().map(|m| (m.unpacked_size, m.checks, m.dictionary)).collect::<Vec<_>>();
    assert_eq!(facts(&alone), facts(&s));
    assert!(alone.members.iter().all(|m| m.checks_from == Some(FactSource::First)));
    let copy = fixture("7z-extract/copy.7z");
    let c = id(None, Some(HeldVolume::whole(&copy)), None);
    assert!(
        c.members.iter().filter(|m| !m.is_dir).all(|m| m.method == Some(MapMethod::Stored) && m.dictionary.is_none())
    );
    // The last piece of a split holds the end header.
    let tail = fixture("7z-extract/split.7z.003");
    let t = id(None, Some(held(&tail, 0, tail.len())), None);
    assert!(!t.members.is_empty());
    // Encrypted headers need the password.
    let enc = fixture("7z-extract/aes_hdr.7z");
    assert!(set_identity(None, Some(HeldVolume::whole(&enc)), MapOptions::new("e")).is_err());
    let e = id(None, Some(HeldVolume::whole(&enc)), Some("password"));
    assert!(e.members.iter().any(|m| m.encrypted == Some(true) && m.checks.is_some()));
}

#[test]
fn zip_reads_its_central_directory() {
    let last = fixture("zip-split/deflated.zip");
    let s = id(Some(HeldVolume::whole(&fixture("zip-split/deflated.z01"))), Some(HeldVolume::whole(&last)), None);
    assert_eq!(s.format, MapFormat::Zip);
    assert!(!s.members.is_empty());
    for m in s.members.iter().filter(|m| !m.is_dir) {
        assert_eq!(m.checks_from, Some(FactSource::Last));
        assert!(matches!(m.method, Some(MapMethod::Compressed { id: 8 }) | Some(MapMethod::Stored)), "{:?}", m.method);
        assert_eq!(m.dictionary, None);
    }
}

/// RustyGet's z-fixtures (env ZIPFAST_Z_FIXTURES = the sets directory): one 750,000-byte article at each end.
#[test]
fn z_fixtures_identify_from_one_article_at_each_end() {
    let Some(dir) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(std::path::PathBuf::from) else {
        eprintln!("skipped: ZIPFAST_Z_FIXTURES unset");
        return;
    };
    const ARTICLE: usize = 750_000;
    let password = "RG-test-pw-2026";
    let vols = |set: &str| -> Vec<Vec<u8>> {
        let mut names: Vec<_> = std::fs::read_dir(dir.join(set))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                let n = p.file_name().unwrap().to_string_lossy().to_string();
                n.contains(".part") || n.contains(".7z")
            })
            .collect();
        names.sort();
        names.iter().map(|p| std::fs::read(p).unwrap()).collect()
    };
    let ends = |set: &str| -> SetIdentity {
        let v = vols(set);
        let (first, last) = (&v[0], v.last().unwrap());
        id(Some(held(first, ARTICLE, 0)), Some(held(last, ARTICLE, ARTICLE)), Some(password))
    };
    let key = |s: &SetIdentity| -> Vec<(u64, u32)> {
        s.members
            .iter()
            .filter(|m| !m.is_dir)
            .map(|m| (m.unpacked_size.unwrap(), m.checks.and_then(|c| c.crc32).unwrap_or(0)))
            .collect()
    };
    // The same payload packed twice (rar -m3 and a re-rar) identifies identically.
    let (a, b) = (ends("F03_rar5_m3_video"), ends("F03b_rar5_m3_video_rerar"));
    assert_eq!(key(&a), key(&b));
    assert!(a.members.iter().all(|m| m.checks_from == Some(FactSource::Last) && m.method_from.is_some()));
    // AES data and -hp headers with the password; keyed checks are noted.
    for set in ["F01_rar5_store_aes", "F02_rar5_store_aes_hp", "F04_rar5_m3_aes", "F05_rar5_m5_mixed"] {
        let s = ends(set);
        assert!(!s.members.is_empty(), "{set}");
        for m in &s.members {
            assert!(m.unpacked_size.is_some() && m.checks.is_some() && m.method.is_some(), "{set} {:?}", m.name);
        }
        eprintln!("{set}: {:?}", key(&s));
    }
    // 7z: the end header is in the last volume's last article.
    for set in ["F07_7z_lzma2_video", "F09_7z_copy_aes_mhe"] {
        let s = ends(set);
        assert!(!s.members.is_empty(), "{set}");
        eprintln!("{set}: {:?}", key(&s));
    }
    // The video payload with plain checks agrees across containers: RAR5 -m3, its re-rar, RAR5 -hp stored (-hp
    // keeps checks plain), 7z LZMA2 and 7z Copy+AES with encrypted headers. AES data members of RAR5 carry keyed
    // checks (rar 7 sets the flag on the final part), which are noted and differ.
    let video = key(&a);
    for set in ["F02_rar5_store_aes_hp", "F07_7z_lzma2_video", "F09_7z_copy_aes_mhe"] {
        assert_eq!(key(&ends(set)), video, "{set}");
    }
    let keyed = ends("F01_rar5_store_aes");
    assert!(keyed.members.iter().all(|m| m.checks.is_some_and(|c| c.keyed)));
    assert_eq!(keyed.members[0].unpacked_size, Some(video[0].0));
}
