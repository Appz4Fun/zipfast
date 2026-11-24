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

/// A stored ZIP holding `entries` (name, data) as written, duplicates included.
fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    stored_zip_at(0, entries)
}

/// [`stored_zip`] for appending after `base` bytes (a self-extracting stub): offsets count from the file's start.
fn stored_zip_at(base: usize, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let at = (base + out.len()) as u32;
        let crc = crc32fast::hash(data);
        let fixed = |sig: u32, out: &mut Vec<u8>, central_dir: bool| {
            out.extend(sig.to_le_bytes());
            if central_dir {
                out.extend(20u16.to_le_bytes());
            }
            out.extend(20u16.to_le_bytes());
            out.extend(0u16.to_le_bytes()); // flags
            out.extend(0u16.to_le_bytes()); // stored
            out.extend(0u32.to_le_bytes()); // time and date
            out.extend(crc.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes()); // extra
        };
        fixed(0x0403_4b50, &mut out, false);
        out.extend(name.as_bytes());
        out.extend(*data);
        fixed(0x0201_4b50, &mut central, true);
        central.extend(0u16.to_le_bytes()); // comment
        central.extend(0u16.to_le_bytes()); // disk
        central.extend(0u16.to_le_bytes()); // internal attributes
        central.extend(0u32.to_le_bytes()); // external attributes
        central.extend(at.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let dir_at = (base + out.len()) as u32;
    let dir_len = central.len() as u32;
    out.extend(central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend(dir_len.to_le_bytes());
    out.extend(dir_at.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

#[test]
fn entries_sharing_a_name_stay_separate() {
    let (a, b) = (b"first copy".to_vec(), b"second, different".to_vec());
    // RAR: two members named movie.mkv in one archive, given as both volumes.
    let rar = common::archive(&[FileSpec::new("movie.mkv", &a), FileSpec::new("movie.mkv", &b)]);
    for s in [
        id(Some(HeldVolume::whole(&rar)), Some(HeldVolume::whole(&rar)), None),
        id(Some(HeldVolume::whole(&rar)), None, None),
        id(None, Some(HeldVolume::whole(&rar)), None),
    ] {
        let facts: Vec<_> = s.members.iter().map(|m| (m.unpacked_size, m.checks.and_then(|c| c.crc32))).collect();
        assert_eq!(
            facts,
            [(Some(a.len() as u64), Some(crc32fast::hash(&a))), (Some(b.len() as u64), Some(crc32fast::hash(&b)))]
        );
    }
    // ZIP with a duplicate name.
    let zip = stored_zip(&[("movie.mkv", &a), ("movie.mkv", &b)]);
    let s = id(Some(HeldVolume::whole(&zip)), Some(HeldVolume::whole(&zip)), None);
    let crcs: Vec<_> = s.members.iter().map(|m| m.checks.and_then(|c| c.crc32)).collect();
    assert_eq!(crcs, [Some(crc32fast::hash(&a)), Some(crc32fast::hash(&b))]);
}

#[test]
fn a_stubbed_first_volume_gives_its_split_member() {
    let data: Vec<u8> = (0..50_000u32).map(|i| (i * 13 % 251) as u8).collect();
    let vols = common::volumes(&FileSpec::new("movie.mkv", &data), 20_000);
    let mut stubbed = b"MZ".to_vec();
    stubbed.resize(5000, 0x90);
    stubbed.extend(&vols[0]);
    let s = id(Some(HeldVolume::whole(&stubbed)), None, None);
    assert_eq!(s.format, MapFormat::Rar5);
    let m = &s.members[0];
    assert_eq!(
        (m.name.as_deref(), m.unpacked_size, m.method),
        (Some("movie.mkv"), Some(50_000), Some(MapMethod::Stored))
    );
    assert!(m.checks.is_none(), "a split member's checks are in its last part");
    // With the last volume too, one member with both.
    let last = vols.last().unwrap();
    let both = id(Some(HeldVolume::whole(&stubbed)), Some(HeldVolume::whole(last)), None);
    assert_eq!(both.members.len(), 1);
    assert_eq!(both.members[0].checks.and_then(|c| c.crc32), Some(crc32fast::hash(&data)));
}

/// An Info-ZIP split set: `.z01` (spanning signature, then a stored member `name` holding `data`) and `.zip`
/// holding the central directory and end record.
fn split_zip(name: &str, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let crc = crc32fast::hash(data);
    let mut z01 = 0x0807_4b50u32.to_le_bytes().to_vec();
    let local_at = z01.len() as u32;
    z01.extend(0x0403_4b50u32.to_le_bytes());
    z01.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z01.extend(crc.to_le_bytes());
    z01.extend((data.len() as u32).to_le_bytes());
    z01.extend((data.len() as u32).to_le_bytes());
    z01.extend((name.len() as u16).to_le_bytes());
    z01.extend(0u16.to_le_bytes());
    z01.extend(name.as_bytes());
    z01.extend(data);
    let mut cd = 0x0201_4b50u32.to_le_bytes().to_vec();
    cd.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    cd.extend(crc.to_le_bytes());
    cd.extend((data.len() as u32).to_le_bytes());
    cd.extend((data.len() as u32).to_le_bytes());
    cd.extend((name.len() as u16).to_le_bytes());
    cd.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // extra, comment, disk 0, attributes
    cd.extend(local_at.to_le_bytes());
    cd.extend(name.as_bytes());
    let mut zip = cd.clone();
    zip.extend(0x0605_4b50u32.to_le_bytes());
    zip.extend(1u16.to_le_bytes()); // this disk
    zip.extend(1u16.to_le_bytes()); // directory's disk
    zip.extend(1u16.to_le_bytes());
    zip.extend(1u16.to_le_bytes());
    zip.extend((cd.len() as u32).to_le_bytes());
    zip.extend(0u32.to_le_bytes());
    zip.extend(0u16.to_le_bytes());
    (z01, zip)
}

#[test]
fn a_last_volume_directory_decides_over_a_rar_stored_in_the_first() {
    let inner = common::archive(&[FileSpec::new("inside.bin", b"nested payload")]);
    let (z01, zip) = split_zip("inner.rar", &inner);
    // The first volume alone finds the stored RAR (its scanner looks past the prefix), as before.
    let s = id(Some(HeldVolume::whole(&z01)), Some(HeldVolume::whole(&zip)), None);
    assert_eq!(s.format, MapFormat::Zip);
    let names: Vec<_> = s.members.iter().map(|m| m.name.clone().unwrap()).collect();
    assert_eq!(names, ["inner.rar"]);
    assert_eq!(s.members[0].checks.and_then(|c| c.crc32), Some(crc32fast::hash(&inner)));
}

#[test]
fn many_members_match_in_linear_time() {
    // Work-bound rather than wall-clock: identifying four times the members must take about four times the matching
    // steps, not sixteen.
    fn archive_of(n: usize) -> Vec<u8> {
        let names: Vec<String> = (0..n).map(|i| format!("f{i:06}")).collect();
        let specs: Vec<FileSpec<'_>> = names.iter().map(|n| FileSpec::new(n, b"x")).collect();
        common::archive(&specs)
    }
    let mut options = MapOptions::new("big.rar");
    options.limits.entries = 1 << 20;
    options.limits.header_bytes = 1 << 30;
    options.limits.volume_header_bytes = 1 << 30;
    options.limits.header_blocks = 1 << 20;
    options.limits.name_bytes = 1 << 30;
    options.limits.header_allocation = 1 << 30;
    options.limits.metadata_bytes = 1 << 30;
    options.limits.parts = 1 << 20;
    // Matching work is counted, not timed: one step per lookup or compare, so it grows with the member count.
    let steps = |rar: &[u8], n: usize| -> u64 {
        zipfast::work::take(zipfast::work::Work::SetIdentitySteps);
        let s = set_identity(Some(HeldVolume::whole(rar)), Some(HeldVolume::whole(rar)), options.clone()).unwrap();
        assert_eq!(s.members.len(), n, "each member matched with itself, none duplicated");
        assert!(s.members.iter().all(|m| m.checks.is_some() && m.size_from == Some(FactSource::First)));
        zipfast::work::take(zipfast::work::Work::SetIdentitySteps)
    };
    let (small, large) = (archive_of(4_000), archive_of(16_000));
    let (w_small, w_large) = (steps(&small, 4_000), steps(&large, 16_000));
    assert!(w_small >= 4_000, "the counter sees the matching ({w_small})");
    // Linear work gives exactly 4x; matching every member against all earlier ones gives near 16x.
    assert!(w_large <= w_small * 5, "4x the members took {w_large} steps against {w_small}");
    // Cancellation is honoured.
    options.control.cancel();
    assert!(set_identity(Some(HeldVolume::whole(&large)), Some(HeldVolume::whole(&large)), options).is_err());
}

#[test]
fn an_unreadable_rar_stored_in_the_first_volume_does_not_hide_the_zip_directory() {
    // An -hp RAR (password unknown), stored in a split ZIP's .z01; the ZIP itself is not encrypted.
    let inner = fixture("rar4/encrypted_headers.rar");
    let (z01, zip) = split_zip("locked.rar", &inner);
    let s = id(Some(HeldVolume::whole(&z01)), Some(HeldVolume::whole(&zip)), Some("not the password"));
    assert_eq!(s.format, MapFormat::Zip);
    assert_eq!(s.members.len(), 1);
    assert_eq!(s.members[0].name.as_deref(), Some("locked.rar"));
    assert_eq!(s.members[0].checks.and_then(|c| c.crc32), Some(crc32fast::hash(&inner)));
    // With only the first volume there is nothing else to go on: the RAR's error stands.
    let alone =
        set_identity(Some(HeldVolume::whole(&z01)), None, MapOptions::new("x").password(Some("not the password")));
    assert!(alone.is_err(), "{alone:?}");
}
/// A legacy RAR 4.x volume: no first-volume flag and end headers without numbers, so no volume number is stated.
fn rar4_volume(files: &[(&str, &[u8], u16, u32, u64)], next: bool) -> Vec<u8> {
    use zipfast::rar5::frame::rar4::*;
    let mut out = MARKER.to_vec();
    out.extend(MainHeader::new(MHD_VOLUME).encode().unwrap());
    for &(name, data, flags, crc, size) in files {
        let header = FileHeader {
            head_type: HEAD_FILE,
            flags: flags | LONG_BLOCK,
            packed_size: data.len() as u64,
            unpacked_size: size,
            host_os: 2,
            crc,
            dos_time: 0x5a21_6000,
            unpack_version: 29,
            method: 0x30,
            attributes: 0x20,
            name: name.as_bytes().to_vec(),
            salt: None,
            ext_time: None,
            rest: Vec::new(),
        };
        out.extend(header.encode().unwrap());
        out.extend(data);
    }
    out.extend(EndOfArchive::new(next).encode().unwrap());
    out
}

#[test]
fn unnumbered_volumes_are_not_taken_for_the_same_volume() {
    use zipfast::rar5::frame::rar4::{LHD_SPLIT_AFTER, LHD_SPLIT_BEFORE};
    let movie: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
    let (p1, p2) = movie.split_at(2000);
    let (a, b) = (b"notes in the first volume".as_slice(), b"other notes, same name, last volume".as_slice());
    let crc = crc32fast::hash;
    let first = rar4_volume(
        &[("notes.txt", a, 0, crc(a), a.len() as u64), ("movie.mkv", p1, LHD_SPLIT_AFTER, crc(p1), 4000)],
        true,
    );
    let last = rar4_volume(
        &[("movie.mkv", p2, LHD_SPLIT_BEFORE, crc(&movie), 4000), ("notes.txt", b, 0, crc(b), b.len() as u64)],
        false,
    );
    let s = id(Some(HeldVolume::whole(&first)), Some(HeldVolume::whole(&last)), None);
    assert_eq!(s.format, MapFormat::Rar4);
    let facts: Vec<_> = s.members.iter().map(|m| (m.name.clone().unwrap(), m.checks.and_then(|c| c.crc32))).collect();
    assert_eq!(
        facts,
        [
            ("notes.txt".to_string(), Some(crc(a))),
            ("movie.mkv".to_string(), Some(crc(&movie))),
            ("notes.txt".to_string(), Some(crc(b))),
        ],
        "the two notes.txt are different files; the split movie joins up"
    );
}

#[test]
fn a_whole_self_extracting_zip_given_as_the_first_volume_reads_its_directory() {
    let inner = common::archive(&[FileSpec::new("inside.bin", b"nested payload")]);
    let mut sfx = b"MZ".to_vec();
    sfx.resize(4096, 0x90);
    sfx.extend(stored_zip_at(4096, &[("inner.rar", &inner)]));
    let as_last = id(None, Some(HeldVolume::whole(&sfx)), None);
    assert_eq!(as_last.format, MapFormat::Zip, "the tail holds the ZIP directory");
    let as_first = id(Some(HeldVolume::whole(&sfx)), None, None);
    assert_eq!(as_first.format, MapFormat::Zip);
    let names = |s: &SetIdentity| s.members.iter().map(|m| m.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&as_first), names(&as_last));
    assert_eq!(names(&as_first), [Some("inner.rar".to_string())]);
}

#[test]
fn spanning_members_of_one_name_join_only_when_their_facts_agree() {
    use zipfast::rar5::frame::rar4::{LHD_SPLIT_AFTER, LHD_SPLIT_BEFORE};
    // One movie.mkv starts in the first volume and ends in a middle one; another starts in the middle volume and
    // ends in the last. They share a name, and both look like the member that spans, but their sizes differ.
    let early = vec![1u8; 3000];
    let late = vec![2u8; 5000];
    let crc = crc32fast::hash;
    let first = rar4_volume(&[("movie.mkv", &early[..1500], LHD_SPLIT_AFTER, crc(&early[..1500]), 3000)], true);
    let last = rar4_volume(&[("movie.mkv", &late[2500..], LHD_SPLIT_BEFORE, crc(&late), 5000)], false);
    let s = id(Some(HeldVolume::whole(&first)), Some(HeldVolume::whole(&last)), None);
    let facts: Vec<_> = s.members.iter().map(|m| (m.unpacked_size, m.checks.and_then(|c| c.crc32))).collect();
    assert_eq!(facts, [(Some(3000), None), (Some(5000), Some(crc(&late)))], "kept apart: no size mixed with a CRC");
    // The same layout with agreeing sizes is one member continuing through.
    let first = rar4_volume(&[("movie.mkv", &late[..2500], LHD_SPLIT_AFTER, crc(&late[..2500]), 5000)], true);
    let s = id(Some(HeldVolume::whole(&first)), Some(HeldVolume::whole(&last)), None);
    let facts: Vec<_> = s.members.iter().map(|m| (m.unpacked_size, m.checks.and_then(|c| c.crc32))).collect();
    assert_eq!(facts, [(Some(5000), Some(crc(&late)))]);
}
