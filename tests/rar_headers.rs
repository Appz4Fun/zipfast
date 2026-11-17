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

//! Per-volume header listing (`RarSession::headers`), as UnRAR's `l`, `lt` and `v` need it.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::*;
use zipfast::rar5::RarFormat;
use zipfast::rar5::session::{RarHeader, RarSession, RarSessionOptions};

fn single() -> RarSessionOptions {
    RarSessionOptions { follow_volumes: false, ..RarSessionOptions::default() }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-volumes")
}

/// UnRAR's listing totals: packed bytes of every file header, unpacked bytes and count only without SplitBefore.
fn totals<'a>(headers: impl Iterator<Item = RarHeader<'a>>) -> (u64, u64, usize) {
    let (mut unpacked, mut packed, mut count) = (0, 0, 0);
    for header in headers.filter(|h| !h.is_service()) {
        packed += header.packed_size();
        if !header.split_before() {
            unpacked += header.unpacked_size().unwrap_or(0);
            count += 1;
        }
    }
    (unpacked, packed, count)
}

fn service_block(name: &str, data: &[u8]) -> Vec<u8> {
    let mut fields = Vec::new();
    vint(0x4, &mut fields);
    vint(data.len() as u64, &mut fields);
    vint(0, &mut fields);
    fields.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    vint(0, &mut fields);
    vint(0, &mut fields);
    vint(name.len() as u64, &mut fields);
    fields.extend_from_slice(name.as_bytes());
    block(3, 0, &fields, &[], data, true)
}

#[test]
fn rar4_orphan_continuation_is_listed_alone() {
    let session = RarSession::open(&fixtures().join("multi.part2.rar"), None, single()).unwrap();
    assert_eq!(session.volumes().len(), 1);
    let headers: Vec<_> = session.headers().collect();
    assert!(!headers.is_empty());
    let first = headers[0];
    // file2.txt began in part1 (Pack-CRC32 there); part2 holds only its continuation.
    assert_eq!(first.name(), "file2.txt");
    assert!(first.split_before());
    assert_eq!(first.volume(), 0);
    assert_eq!(first.format(), RarFormat::Rar4);
    // The orphan stays out of the members but is counted, and out of the unpacked totals.
    assert!(session.entries().all(|member| member.name() != "file2.txt"));
    assert!(session.archive().orphan_continuations() >= 1);
    let (unpacked, packed, count) = totals(session.headers());
    let whole: Vec<_> = headers.iter().filter(|h| !h.split_before() && !h.is_service()).collect();
    assert_eq!(count, whole.len());
    assert_eq!(unpacked, whole.iter().map(|h| h.unpacked_size().unwrap()).sum::<u64>());
    assert_eq!(packed, headers.iter().filter(|h| !h.is_service()).map(|h| h.packed_size()).sum::<u64>());
    let volume = session.volumes().next().unwrap();
    assert!(volume.is_volume());
    assert!(!volume.first_volume());
    assert_eq!(volume.rar5_volume_number(), None);
    assert_eq!(volume.header_range(), 0..headers.len());
}

#[test]
fn rar4_first_volume_matches_unrar_lt() {
    // UnRAR 7.30 `lt multi.part1.rar`: file1.txt 18/18 CRC32 52B28202, file2.txt 17704/4850 Pack-CRC32 E0222912.
    let session = RarSession::open(&fixtures().join("multi.part1.rar"), None, single()).unwrap();
    assert_eq!(session.volumes().len(), 1);
    let headers: Vec<_> = session.headers().collect();
    assert_eq!(headers.len(), 2);
    let (one, two) = (headers[0], headers[1]);
    assert_eq!((one.name(), one.unpacked_size(), one.packed_size()), ("file1.txt", Some(18), 18));
    assert_eq!((one.crc32(), one.pack_crc32()), (Some(0x52B2_8202), None));
    assert_eq!(one.modified().unwrap().nanos, 53_055_000);
    assert_eq!(one.host_os(), 0);
    assert_eq!(one.rar4_metadata().unwrap().unpack_version, 29);
    assert_eq!((one.method(), one.dictionary()), (0, 128 << 10));
    assert_eq!((two.name(), two.unpacked_size(), two.packed_size()), ("file2.txt", Some(17704), 4850));
    assert!(!two.split_before() && two.split_after());
    assert_eq!((two.crc32(), two.pack_crc32()), (None, Some(0xE022_2912)));
    assert_eq!(two.method(), 3);
    assert_eq!(two.modified().unwrap().nanos, 374_072_100);
    // Without following, the member split into part2 is catalogued but incomplete.
    let member = session.entries().find(|m| m.name() == "file2.txt").unwrap();
    assert!(!member.is_complete());
    assert_eq!(totals(session.headers()), (18 + 17704, 18 + 4850, 2));
    let volume = session.volumes().next().unwrap();
    assert!(volume.first_volume() && volume.more_volumes());
    assert!(!volume.protected() && !volume.locked() && !volume.is_solid());
    assert_eq!(volume.sfx_size(), 0);
}

#[test]
fn followed_rar4_set_lists_every_part_with_per_volume_sizes() {
    let session = RarSession::open(&fixtures().join("multi.part1.rar"), None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.volumes().len(), 3);
    let member = session.entries().find(|m| m.name() == "file2.txt").unwrap();
    let parts: Vec<_> = session.headers().filter(|h| h.name() == "file2.txt").collect();
    assert!(parts.len() >= 2);
    assert_eq!(parts.iter().map(|h| h.packed_size()).sum::<u64>(), member.packed_size());
    for (i, part) in parts.iter().enumerate() {
        assert_eq!(part.split_before(), i > 0);
        assert_eq!(part.split_after(), i + 1 < parts.len());
        assert_eq!(part.pack_crc32().is_some(), part.split_after());
    }
    for (index, volume) in session.volumes().enumerate() {
        for header in session.volume_headers(index) {
            assert_eq!(header.volume(), index);
        }
        assert_eq!(session.volume_headers(index).len(), volume.header_range().len());
    }
    let total: usize = (0..3).map(|i| session.volume_headers(i).len()).sum();
    assert_eq!(total, session.headers().len());
}

fn rar5_set(dir: &Path) -> (PathBuf, PathBuf) {
    let data: Vec<u8> = (0..10_240u32).map(|i| (i * 7) as u8).collect();
    let big = FileSpec::new("big.bin", &data);
    let small = FileSpec::new("small.txt", b"hello");
    let one = dir.join("s.part1.rar");
    let two = dir.join("s.part2.rar");
    let mut first = SIG.to_vec();
    first.extend(main_block(true, None));
    first.extend(service_block("CMT", b"a comment"));
    first.extend(file_block(&small, b"hello", crc32fast::hash(b"hello"), false, false));
    first.extend(file_block(&big, &data[..4000], crc32fast::hash(&data[..4000]), false, true));
    first.extend(end_block(true));
    fs::write(&one, first).unwrap();
    let mut second = SIG.to_vec();
    second.extend(main_block(true, Some(1)));
    second.extend(file_block(&big, &data[4000..], crc32fast::hash(&data), true, false));
    second.extend(service_block("QO", b"quick open"));
    second.extend(end_block(false));
    fs::write(&two, second).unwrap();
    (one, two)
}

#[test]
fn rar5_continuation_only_volume_lists_with_zero_totals() {
    let dir = tempfile::tempdir().unwrap();
    let (_, two) = rar5_set(dir.path());
    let session = RarSession::open(&two, None, single()).unwrap();
    let headers: Vec<_> = session.headers().collect();
    assert_eq!(headers.len(), 2);
    assert_eq!((headers[0].name(), headers[0].unpacked_size()), ("big.bin", Some(10_240)));
    assert!(headers[0].split_before() && !headers[0].split_after());
    assert_eq!(headers[0].packed_size(), 6_240);
    assert_eq!(headers[0].crc32(), Some(crc32fast::hash(&(0..10_240u32).map(|i| (i * 7) as u8).collect::<Vec<_>>())));
    assert_eq!(headers[1].service_name(), Some("QO"));
    // UnRAR: "big.bin 10240" listed, but the footer shows total 0 and count 0.
    assert_eq!(totals(session.headers()), (0, 6_240, 0));
    assert_eq!(session.entries().len(), 0);
    assert_eq!(session.archive().orphan_continuations(), 1);
    let volume = session.volumes().next().unwrap();
    // "RAR 5, volume 2": the main header's zero-based number plus one.
    assert_eq!(volume.rar5_volume_number(), Some(1));
    assert!(!volume.first_volume());
    assert_eq!(volume.rar4_end_volume_number(), None);
    assert!(!volume.rar4_store_vol_number());
    assert_eq!(volume.comment_header(), None);
}

#[test]
fn rar5_service_headers_comment_and_follow() {
    let dir = tempfile::tempdir().unwrap();
    let (one, _) = rar5_set(dir.path());
    let session = RarSession::open(&one, None, single()).unwrap();
    assert_eq!(session.volumes().len(), 1);
    let names: Vec<_> = session.headers().map(|h| (h.name().to_owned(), h.is_service())).collect();
    assert_eq!(names, [("CMT".to_owned(), true), ("small.txt".to_owned(), false), ("big.bin".to_owned(), false)]);
    let cmt = session.headers().next().unwrap();
    assert_eq!(cmt.service_name(), Some("CMT"));
    assert_eq!(cmt.raw_name(), b"CMT");
    let volume = session.volumes().next().unwrap();
    assert_eq!(volume.rar5_volume_number(), Some(0));
    assert!(volume.first_volume());
    assert_eq!(volume.comment_header(), Some(0));
    assert_eq!(session.comment(0).unwrap().as_deref(), Some(&b"a comment"[..]));
    assert_eq!(session.comment(1).unwrap(), None);
    let big = session.headers().nth(2).unwrap();
    assert_eq!(big.pack_crc32(), Some(crc32fast::hash(&(0..4000u32).map(|i| (i * 7) as u8).collect::<Vec<_>>())));
    assert_eq!(big.modified().unwrap().resolution_nanos, 1_000_000_000);

    let session = RarSession::open(&one, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.volumes().len(), 2);
    let listed: Vec<_> = session.headers().map(|h| (h.volume(), h.name().to_owned())).collect();
    assert_eq!(
        listed,
        [
            (0, "CMT".to_owned()),
            (0, "small.txt".to_owned()),
            (0, "big.bin".to_owned()),
            (1, "big.bin".to_owned()),
            (1, "QO".to_owned())
        ]
    );
    // Merged member and per-header view agree on the pack sizes.
    let member = session.entries().find(|m| m.name() == "big.bin").unwrap();
    assert_eq!(member.packed_size(), 4000 + 6240);
    assert!(member.is_complete());
    assert_eq!(session.volumes().nth(1).unwrap().rar5_volume_number(), Some(1));
}

#[test]
fn rar5_high_precision_times() {
    let dir = tempfile::tempdir().unwrap();
    // HTIME record: Unix times with nanoseconds for mtime, ctime and atime.
    let mut record = Vec::new();
    vint(3, &mut record);
    vint(0x1 | 0x2 | 0x4 | 0x8 | 0x10, &mut record);
    for seconds in [1_700_000_001u32, 1_700_000_002, 1_700_000_003] {
        record.extend_from_slice(&seconds.to_le_bytes());
    }
    for nanos in [11u32, 22, 33] {
        record.extend_from_slice(&nanos.to_le_bytes());
    }
    let mut extra = Vec::new();
    vint(record.len() as u64, &mut extra);
    extra.extend(record);
    let spec = FileSpec { extra, ..FileSpec::new("t", b"x") };
    let path = dir.path().join("t.rar");
    fs::write(&path, archive(&[spec])).unwrap();
    let session = RarSession::open(&path, None, single()).unwrap();
    let header = session.headers().next().unwrap();
    let modified = header.modified().unwrap();
    assert_eq!((modified.seconds, modified.nanos, modified.resolution_nanos), (1_700_000_001, 11, 1));
    let created = header.created().unwrap();
    assert_eq!((created.seconds, created.nanos), (1_700_000_002, 22));
    let accessed = header.accessed().unwrap();
    assert_eq!((accessed.seconds, accessed.nanos), (1_700_000_003, 33));
}

#[test]
fn rar4_end_header_volume_number() {
    let dir = tempfile::tempdir().unwrap();
    // A RAR 4.x volume whose end header stores EARC_VOLNUMBER (StoreVolNumber) = 4, and no data CRC.
    let mut bytes = b"Rar!\x1a\x07\x00".to_vec();
    let mut main = vec![0, 0, 0x73, 0x01, 0x00, 13, 0, 0, 0, 0, 0, 0, 0];
    let crc = crc32fast::hash(&main[2..]) as u16;
    main[..2].copy_from_slice(&crc.to_le_bytes());
    bytes.extend(main);
    let mut end = vec![0, 0, 0x7b, 0x09, 0x00, 9, 0, 4, 0];
    let crc = crc32fast::hash(&end[2..]) as u16;
    end[..2].copy_from_slice(&crc.to_le_bytes());
    bytes.extend(end);
    let path = dir.path().join("v.part5.rar");
    fs::write(&path, bytes).unwrap();
    let session = RarSession::open(&path, None, single()).unwrap();
    let volume = session.volumes().next().unwrap();
    assert_eq!(volume.rar4_end_volume_number(), Some(4));
    assert!(volume.rar4_store_vol_number());
    assert!(volume.more_volumes());
    assert_eq!(volume.rar5_volume_number(), None);
    assert_eq!(session.headers().len(), 0);
}

// Comparison with UnRAR 7.30 `lt` output, when `ZIPFAST_RAR4_CORPUS` names the reference corpus (not shipped).

fn civil(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}", rem / 3600, rem / 60 % 60, rem % 60)
}

#[derive(Default, Debug)]
struct Listed {
    name: String,
    kind: String,
    size: Option<u64>,
    packed: Option<u64>,
    mtime: Option<String>,
    crc: Option<String>,
    pack_crc: Option<String>,
    target: Option<String>,
}

fn parse_lt(text: &str) -> Vec<Listed> {
    let mut out: Vec<Listed> = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(": ") else { continue };
        let value = value.trim_end();
        match key.trim() {
            "Name" => out.push(Listed { name: value.to_owned(), ..Listed::default() }),
            _ if out.is_empty() => {}
            "Type" => out.last_mut().unwrap().kind = value.to_owned(),
            "Size" => out.last_mut().unwrap().size = value.parse().ok(),
            "Packed size" => out.last_mut().unwrap().packed = value.parse().ok(),
            "mtime" => out.last_mut().unwrap().mtime = Some(value.to_owned()),
            "CRC32" => out.last_mut().unwrap().crc = Some(value.to_owned()),
            "Target" => out.last_mut().unwrap().target = Some(value.to_owned()),
            "Pack-CRC32" => out.last_mut().unwrap().pack_crc = Some(value.to_owned()),
            _ => {}
        }
    }
    out
}

#[test]
fn matches_unrar_lt_reference_corpus() {
    // Prybar's reference corpus: `in/<set>/<archive>` and UnRAR 7.30 `lt` output in `out/*.lt`.
    let Some(root) = std::env::var_os("ZIPFAST_RAR4_CORPUS").map(PathBuf::from) else {
        eprintln!("ZIPFAST_RAR4_CORPUS is not set: skipping the UnRAR lt comparison");
        return;
    };
    let listing = fs::read_dir(root.join("out")).expect("ZIPFAST_RAR4_CORPUS has an out directory");
    let mut compared = 0;
    for entry in listing {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "lt") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let Some(archive) = text.lines().next().and_then(|l| l.strip_prefix("### ")) else { continue };
        if !text.contains("status=0") {
            continue;
        }
        let Ok(session) = RarSession::open(&root.join(archive), None, single()) else {
            eprintln!("skipped {archive}");
            continue;
        };
        let details = text.lines().find_map(|l| l.strip_prefix("Details: ")).unwrap();
        let volume = session.volumes().next().unwrap();
        let mut words =
            vec![if volume.format() == RarFormat::Rar4 { "RAR 1.5".to_owned() } else { "RAR 5".to_owned() }];
        if volume.is_volume() {
            words.push(match volume.rar5_volume_number() {
                Some(n) => format!("volume {}", n + 1),
                None => "volume".to_owned(),
            });
        }
        for (flag, word) in [
            (volume.is_solid(), "solid"),
            (volume.locked(), "lock"),
            (volume.protected(), "recovery record"),
            (volume.sfx_size() > 0, "SFX"),
            (volume.encrypted_headers(), "encrypted headers"),
        ] {
            if flag {
                words.push(word.to_owned());
            }
        }
        assert_eq!(words.join(", "), details, "{archive}: details");
        let expected = parse_lt(&text);
        let got: Vec<_> = session.headers().collect();
        assert_eq!(got.len(), expected.len(), "{archive}: header count");
        for (header, listed) in got.iter().zip(&expected) {
            let what = format!("{archive}: {}", listed.name);
            if !header.name().is_empty() {
                assert_eq!(header.name(), listed.name, "{what}");
            }
            let kind = if header.is_service() {
                "Service"
            } else if header.is_directory() {
                "Directory"
            } else if header.redirection().is_some() || listed.kind.contains("link") {
                // RAR 4.x keeps a Unix link in its attributes; UnRAR names the link kind.
                assert!(header.redirection().is_some() || header.attributes() & 0o170000 == 0o120000, "{what}");
                continue;
            } else {
                "File"
            };
            if listed.kind == "NTFS alternate data stream" {
                assert_eq!(header.service_name(), Some("STM"), "{what}");
                let target = listed.target.as_deref().unwrap();
                let data = header.service_data();
                let stream = match header.format() {
                    // RAR 3.x writes the stream name as UTF-16LE.
                    RarFormat::Rar4 => String::from_utf16_lossy(
                        &data.as_chunks::<2>().0.iter().map(|p| u16::from_le_bytes(*p)).collect::<Vec<_>>(),
                    ),
                    RarFormat::Rar5 => String::from_utf8_lossy(data).into_owned(),
                };
                assert!(target.ends_with(stream.trim_start_matches(':')), "{what}: {target} vs {stream}");
            } else {
                assert_eq!(kind, listed.kind, "{what}: type");
            }
            if let Some(size) = listed.size {
                assert_eq!(header.unpacked_size(), Some(size), "{what}: size");
            }
            if let Some(packed) = listed.packed {
                assert_eq!(header.packed_size(), packed, "{what}: packed");
            }
            if let Some(crc) = &listed.crc {
                assert_eq!(header.crc32().map(|c| format!("{c:08X}")).as_ref(), Some(crc), "{what}: crc");
            }
            if let Some(crc) = &listed.pack_crc {
                assert_eq!(header.pack_crc32().map(|c| format!("{c:08X}")).as_ref(), Some(crc), "{what}: pack crc");
            }
            if let (Some(mtime), Some(time)) = (&listed.mtime, header.modified()) {
                assert_eq!(&format!("{},{:09}", civil(time.seconds), time.nanos), mtime, "{what}: mtime");
            }
        }
        compared += 1;
    }
    eprintln!("compared {compared} reference listings");
    assert!(compared > 10, "only {compared} reference listings compared");
}

#[test]
fn orphan_continuation_names_are_charged_to_capacity() {
    use zipfast::error::{RarFailure, RarResource};
    let dir = tempfile::tempdir().unwrap();
    let name = "n".repeat(60_000);
    let spec = FileSpec::new(&name, b"");
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(true, Some(1)));
    for _ in 0..64 {
        bytes.extend(file_block(&spec, b"x", 0, true, true));
    }
    bytes.extend(end_block(false));
    let path = dir.path().join("o.part2.rar");
    fs::write(&path, bytes).unwrap();
    let session = RarSession::open(&path, None, single()).unwrap();
    assert_eq!(session.headers().len(), 64);
    assert_eq!(session.entries().len(), 0);
    // Each orphan keeps a raw and a decoded name of 60,000 bytes, with no member to own either.
    assert!(session.usage().capacity >= 64 * 120_000, "{}", session.usage().capacity);
    let mut options = single();
    options.limits.capacity = 64 * 60_000;
    let failure = RarSession::open(&path, None, options).err().unwrap();
    assert!(
        matches!(failure.failure.as_ref(), RarFailure::Limit { resource: RarResource::CatalogueCapacity, .. }),
        "{:?}",
        failure.failure
    );
}

#[test]
fn redirection_flags_and_file_flags() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("links.rar");
    // A Unix symlink to a directory: redirection record (type 5), kind 1, flags 1 (target is a directory).
    let target = b"sub";
    let mut body = vec![5, 1, 1, target.len() as u8];
    body.extend(target);
    let mut extra = Vec::new();
    vint(body.len() as u64, &mut extra);
    extra.extend(body);
    let link = FileSpec { extra, ..FileSpec::new("link", b"") };
    let plain = FileSpec::new("plain", b"data");
    fs::write(&path, archive(&[link, plain])).unwrap();
    let session = RarSession::open(&path, None, single()).unwrap();
    let members: Vec<_> = session.entries().collect();
    assert!(members[0].redirection().is_some());
    assert_eq!((members[0].redirection_flags(), members[1].redirection_flags()), (1, 0));
    assert_eq!(members[1].rar5_file_flags().map(|f| f & 0x4), Some(0x4));
    assert_eq!(session.volume_paths().collect::<Vec<_>>(), [path.as_path()]);
}

#[test]
fn rar5_extra_records_locator_and_end_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.rar");
    // Main header with a locator (quick open at 0x40, recovery at 0x1234) then an unknown record type 9.
    let mut extra = Vec::new();
    for body in [vec![1u8, 3, 0x40, 0xb4, 0x24], vec![9u8, 0xaa]] {
        vint(body.len() as u64, &mut extra);
        extra.extend(body);
    }
    let mut fields = Vec::new();
    vint(0, &mut fields);
    let main = block(1, 0, &fields, &extra, &[], false);
    // A file with a redirection record and then a version record: their order is kept.
    let mut file_extra = Vec::new();
    for body in [vec![5u8, 1, 0, 1, b't'], vec![4u8, 0, 7]] {
        vint(body.len() as u64, &mut file_extra);
        file_extra.extend(body);
    }
    let file = file_block(&FileSpec { extra: file_extra, ..FileSpec::new("link", b"") }, b"", 0, false, false);
    let bytes = [SIG.to_vec(), main, file, end_block(false)].concat();
    fs::write(&path, bytes).unwrap();
    let session = RarSession::open(&path, None, single()).unwrap();
    let volume = session.volumes().next().unwrap();
    let locator = volume.main_locator().unwrap();
    assert_eq!((locator.flags, locator.quick_open, locator.recovery), (3, Some(0x40), Some(0x1234)));
    let kinds: Vec<_> = volume.main_extra_records().iter().map(|r| r.kind).collect();
    assert_eq!(kinds, [1, 9]);
    let member = session.entries().next().unwrap();
    let records: Vec<_> = member.extra_records().iter().map(|r| (r.kind, r.data.clone())).collect();
    assert_eq!(records, [(5, vec![1, 0, 1, b't']), (4, vec![0, 7])]);
    let end = volume.end_record().unwrap();
    assert_eq!((end.flags, end.data_crc, end.volume_number), (0, None, None));
    assert!(end.offset > 0);
}

#[test]
fn rar4_end_records_carry_flags_crc_and_volume_number() {
    let session = RarSession::open(&fixtures().join("multi.part1.rar"), None, RarSessionOptions::default()).unwrap();
    let ends: Vec<_> = session.volumes().map(|v| v.end_record().unwrap()).collect();
    assert_eq!(ends.len(), 3);
    for (i, end) in ends.iter().enumerate() {
        assert_eq!(end.flags & 1 != 0, i < 2, "{end:?}");
        assert_eq!(end.volume_number, (end.flags & 8 != 0).then_some(i as u64), "{end:?}");
        assert_eq!(end.data_crc.is_some(), end.flags & 2 != 0, "{end:?}");
    }
}
