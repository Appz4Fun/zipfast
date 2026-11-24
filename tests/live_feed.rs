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

//! Smoke test of the `live_feed` example's core (`examples/live_feed/sim.rs`) on small sets: a generated RAR 5.0
//! stored set (a persistent partial with the `persistent-partials` feature), the RAR 4.x and 7z volume fixtures,
//! each delivered out of order with articles dropped and repaired later, checked against a straight extraction.

mod common;
#[path = "../examples/live_feed/sim.rs"]
mod sim;

use std::path::{Path, PathBuf};
use zipfast::map::NeedKind;

fn fixture(dir: &str, names: &[&str]) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(dir);
    names.iter().map(|n| root.join(n)).collect()
}

/// A stored RAR 5.0 member of `size` bytes over volumes of `chunk` data bytes, written to `dir`.
fn rar5_stored_set(dir: &Path, size: usize, chunk: usize) -> Vec<PathBuf> {
    std::fs::create_dir_all(dir).unwrap();
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let data: Vec<u8> = (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let mut spec = common::FileSpec::new("payload.bin", &data);
    spec.size = Some(size as u64);
    common::volumes(&spec, chunk)
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| {
            let path = dir.join(format!("set.part{}.rar", i + 1));
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect()
}

fn config(volumes: Vec<PathBuf>, work: &Path, article: u64) -> sim::Config {
    let mut config = sim::Config::new(volumes, work.into());
    config.article = article;
    config.drop = 0.2;
    config.lateness = Some(5);
    config.window = 3;
    config
}

fn check(report: &sim::Report) {
    eprintln!("{}", report.tsv("smoke"));
    assert!(report.crc_ok, "{report:?}");
    assert_eq!(report.verified, Some(true), "{report:?}");
    assert!(report.fed >= 1 && report.dropped >= 1, "{report:?}");
    assert_eq!(report.tsv("x").split('\t').count(), sim::Report::HEADER.split('\t').count());
}

#[test]
fn rar5_stored_set_through_the_live_feed() {
    let tmp = tempfile::tempdir().unwrap();
    let volumes = rar5_stored_set(&tmp.path().join("set"), 300_000, 70_000);
    for (i, sink) in [sim::SinkKind::Auto, sim::SinkKind::File].into_iter().enumerate() {
        for repair_delay in [None, Some(3)] {
            let work = tmp.path().join(format!("work-{i}-{repair_delay:?}"));
            let mut config = config(volumes.clone(), &work, 9_000);
            config.sink = sink;
            config.repair_delay = repair_delay;
            config.group_holes = true;
            let report = sim::run(&config).unwrap();
            check(&report);
            // stored data skips holes and repairs them when the articles come back
            assert!(report.holes >= 1 && report.refills >= 1, "{report:?}");
            let expect =
                if cfg!(feature = "persistent-partials") && sink == sim::SinkKind::Auto { "partial" } else { "file" };
            assert_eq!(report.sink, expect);
        }
    }
}

#[test]
fn rar4_and_7z_volume_fixtures_through_the_live_feed() {
    let tmp = tempfile::tempdir().unwrap();
    let sets = [
        fixture("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]),
        fixture("7z", &["multi_volume.7z.001", "multi_volume.7z.002"]),
    ];
    for (i, volumes) in sets.into_iter().enumerate() {
        for seed in 1..4 {
            let mut config = config(volumes.clone(), &tmp.path().join(format!("work-{i}-{seed}")), 700);
            config.seed = seed;
            config.lateness = None;
            check(&sim::run(&config).unwrap());
        }
    }
}

/// `count` stored RAR 5.0 members over two volumes (the middle one split across them), written to `dir`. Two of
/// them flatten to the same name, `d_x.bin`.
fn rar5_many_members(dir: &Path, count: usize) -> Vec<PathBuf> {
    std::fs::create_dir_all(dir).unwrap();
    let names: Vec<String> = (0..count)
        .map(|i| match i {
            0 => "d/x.bin".to_owned(),
            1 => "d_x.bin".to_owned(),
            _ => format!("m{i:02}.bin"),
        })
        .collect();
    let datas: Vec<Vec<u8>> = (0..count).map(|i| (0..3_000 + i * 37).map(|j| (j * 7 + i) as u8).collect()).collect();
    let split = count / 2;
    let mut volumes = vec![common::SIG.to_vec(), common::SIG.to_vec()];
    volumes[0].extend(common::main_block(true, None));
    volumes[1].extend(common::main_block(true, Some(1)));
    for i in 0..count {
        let data = &datas[i];
        let mut spec = common::FileSpec::new(&names[i], data);
        spec.size = Some(data.len() as u64);
        let crc = crc32fast::hash(data);
        if i == split {
            let (a, b) = data.split_at(data.len() / 2);
            volumes[0].extend(common::file_block(&spec, a, crc32fast::hash(a), false, true));
            volumes[1].extend(common::file_block(&spec, b, crc, true, false));
        } else {
            volumes[usize::from(i > split)].extend(common::file_block(&spec, data, crc, false, false));
        }
    }
    volumes[0].extend(common::end_block(true));
    volumes[1].extend(common::end_block(false));
    volumes
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| {
            let path = dir.join(format!("many.part{}.rar", i + 1));
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect()
}

// Catches a set of more members than the default partial limits keep open (16 partials, 64 files), and plain-file
// outputs of two members whose names flatten alike colliding.
#[test]
fn a_set_of_many_stored_members_feeds_every_member() {
    let tmp = tempfile::tempdir().unwrap();
    let volumes = rar5_many_members(&tmp.path().join("set"), 20);
    for (i, sink) in [sim::SinkKind::Auto, sim::SinkKind::File].into_iter().enumerate() {
        let mut config = config(volumes.clone(), &tmp.path().join(format!("work-{i}")), 2_000);
        config.sink = sink;
        let report = sim::run(&config).unwrap();
        check(&report);
        assert_eq!((report.members, report.fed), (20, 20), "{report:?}");
    }
}

// Catches a repair of a trailing hole (the member's last data article dropped) not counting as a refill: it starts
// at the end of everything written before.
#[test]
fn a_repaired_trailing_hole_counts_as_a_refill() {
    let tmp = tempfile::tempdir().unwrap();
    let volumes = rar5_stored_set(&tmp.path().join("set"), 100_000, 40_000);
    let lens: Vec<u64> = volumes.iter().map(|p| std::fs::metadata(p).unwrap().len()).collect();
    let articles = sim::Articles::cut(&lens, 8_000);
    // the last volume's last article holds the end block; the one before it the member's last data bytes
    let last = articles.list.len() - 2;
    let mut config = config(volumes, &tmp.path().join("work"), 8_000);
    config.drop_articles = Some(vec![last]);
    config.lateness = Some(0);
    let report = sim::run(&config).unwrap();
    check(&report);
    assert!(report.refills >= 1 && report.refill_bytes >= 1, "{report:?}");
}

// Catches releases left on for members of one 7z folder: their pieces are empty (the bytes are the folder's), and
// one member's decoder releasing the folder's bytes starves the others.
#[test]
fn members_of_one_solid_7z_folder_share_its_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let whole = std::fs::read(fixture("7z", &["lzma2_chunks.7z"]).remove(0)).unwrap();
    let dir = tmp.path().join("set");
    std::fs::create_dir_all(&dir).unwrap();
    let volumes: Vec<PathBuf> = whole
        .chunks(whole.len().div_ceil(3))
        .enumerate()
        .map(|(i, part)| {
            let path = dir.join(format!("chunks.7z.{:03}", i + 1));
            std::fs::write(&path, part).unwrap();
            path
        })
        .collect();
    for seed in 1..4 {
        let mut config = config(volumes.clone(), &tmp.path().join(format!("work-{seed}")), 4_000);
        config.seed = seed;
        let report = sim::run(&config).unwrap();
        check(&report);
        assert_eq!(report.fed, 3, "{report:?}");
    }
}

// Catches verification looking for a backslash name at a path extraction does not write: a Windows-made `d\x` is
// `d/x`, a Unix-made one keeps its backslash.
#[test]
fn backslash_names_verify_against_what_extraction_wrote() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (vec![1u8; 5_000], vec![2u8; 6_000]);
    let mut windows = common::FileSpec::new("d\\x.bin", &a);
    windows.unix_mode = None;
    let unix = common::FileSpec::new("e\\y.bin", &b);
    let path = tmp.path().join("names.rar");
    std::fs::write(&path, common::archive(&[windows, unix])).unwrap();
    let report = sim::run(&config(vec![path], &tmp.path().join("work"), 1_000)).unwrap();
    check(&report);
    assert_eq!(report.fed, 2);
}

// Catches plain-file outputs named after the member: a 250-byte name plus a prefix passes the 255-byte limit of a
// path component.
#[test]
fn a_member_name_of_250_bytes_feeds() {
    let tmp = tempfile::tempdir().unwrap();
    let data = vec![7u8; 9_000];
    let name = format!("{}.bin", "n".repeat(246));
    let path = tmp.path().join("long.rar");
    std::fs::write(&path, common::archive(&[common::FileSpec::new(&name, &data)])).unwrap();
    for (i, sink) in [sim::SinkKind::Auto, sim::SinkKind::File].into_iter().enumerate() {
        let mut config = config(vec![path.clone()], &tmp.path().join(format!("work-{i}")), 1_000);
        config.sink = sink;
        check(&sim::run(&config).unwrap());
    }
}

// Catches the plain-file fallback sharing a directory with the persistent partials: stored members named as a
// compressed member's fallback output is (`00001-c.bin` by the old naming, `plain/member-00001.out` by the new).
#[test]
fn stored_and_compressed_members_with_a_colliding_name_feed() {
    use zipfast::rar5::testenc;
    let tmp = tempfile::tempdir().unwrap();
    let stored = vec![3u8; 7_000];
    let plain: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8 ^ (i / 997) as u8).collect();
    let stream = testenc::tuned_stream(&testenc::lz(&plain, 1 << 16, 4), 1_500);
    let compressed =
        common::FileSpec { method: 3, size: Some(plain.len() as u64), ..common::FileSpec::new("c.bin", &stream) };
    let files = [
        (common::FileSpec::new("00001-c.bin", &stored), crc32fast::hash(&stored)),
        (compressed, crc32fast::hash(&plain)),
        (common::FileSpec::new("plain/member-00001.out", &stored), crc32fast::hash(&stored)),
    ];
    let path = tmp.path().join("mixed.rar");
    std::fs::write(&path, common::archive_with(&files, false)).unwrap();
    let report = sim::run(&config(vec![path], &tmp.path().join("work"), 1_000)).unwrap();
    check(&report);
    assert_eq!(report.fed, 3, "{report:?}");
    // every fed member gets a persistent partial, the compressed one too
    if cfg!(feature = "persistent-partials") {
        assert_eq!(report.sink, "partial");
    }
}

#[test]
fn old_style_volume_names_go_on_past_r99() {
    let tmp = tempfile::tempdir().unwrap();
    let mut expect = vec!["a.rar".to_owned()];
    expect.extend((0..100).map(|i| format!("a.r{i:02}")));
    expect.extend(["a.s00".to_owned(), "a.s01".to_owned()]);
    for name in expect.iter().chain(&["a.par2".to_owned(), "notes.txt".to_owned()]) {
        std::fs::write(tmp.path().join(name), b"").unwrap();
    }
    let found = sim::volumes_in(tmp.path()).unwrap();
    let names: Vec<_> = found.iter().map(|p| p.file_name().unwrap().to_str().unwrap().to_owned()).collect();
    assert_eq!(names, expect);
}

#[test]
fn needs_map_to_articles_in_priority_order() {
    let articles = sim::Articles::cut(&[2_500, 1_000], 1_000);
    assert_eq!(articles.list.len(), 4);
    assert_eq!(articles.covering(0, 999..1_001), 0..2);
    assert_eq!(articles.covering(0, 2_000..2_500), 2..3);
    assert_eq!(articles.covering(1, 0..1), 3..4);
    assert_eq!(articles.covering(1, 5_000..6_000), 4..4);
    // Next before Repair before Ahead, over both members; an article keeps its most urgent place
    let need = |volume, range, kind| zipfast::map::NeedBytes { volume, range, kind };
    let mut a = zipfast::map::FeedStatus::default();
    a.needs = vec![need(0, 2_100..2_200, NeedKind::Repair), need(1, 0..10, NeedKind::Ahead)];
    let mut b = zipfast::map::FeedStatus::default();
    b.needs = vec![need(0, 500..1_500, NeedKind::Next), need(0, 2_000..2_050, NeedKind::Ahead)];
    assert_eq!(sim::priority([&a, &b].into_iter(), &articles), vec![0, 1, 2, 3]);
    b.needs[0] = need(0, 1_500..1_600, NeedKind::Next);
    assert_eq!(sim::priority([&a, &b].into_iter(), &articles), vec![1, 2, 3]);
    let volumes = sim::volumes_in(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-volumes")).unwrap();
    let names: Vec<_> = volumes.iter().map(|p| p.file_name().unwrap().to_str().unwrap().to_owned()).collect();
    assert_eq!(names, ["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]);
}

// Catches a restart losing persistent output or a decoder not resuming from its partial's cursor: every format
// gets persistent partials (with the feature), the run restarts part way, and the output must still be exact.
#[test]
fn a_restart_mid_feed_resumes_every_member() {
    let tmp = tempfile::tempdir().unwrap();
    let sets = [
        rar5_stored_set(&tmp.path().join("set"), 300_000, 70_000),
        fixture("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]),
        fixture("7z", &["multi_volume.7z.001", "multi_volume.7z.002"]),
    ];
    for (i, volumes) in sets.into_iter().enumerate() {
        for (j, sink) in [sim::SinkKind::Auto, sim::SinkKind::File].into_iter().enumerate() {
            let article = if i == 0 { 9_000 } else { 700 };
            let mut config = config(volumes.clone(), &tmp.path().join(format!("work-{i}-{j}")), article);
            config.sink = sink;
            config.restart_at = Some(6);
            let report = sim::run(&config).unwrap();
            check(&report);
            assert!(report.restart > std::time::Duration::ZERO, "{report:?}");
            let expect =
                if cfg!(feature = "persistent-partials") && sink == sim::SinkKind::Auto { "partial" } else { "file" };
            assert_eq!(report.sink, expect);
        }
    }
}

/// A ZIP holding a Deflate member, a WinZip AES Deflate member, a ZipCrypto Deflate member and a ZipCrypto stored
/// one (password "pw"), written forward (data descriptors: sizes only in the central directory).
fn zip_mixed() -> Vec<u8> {
    use std::io::Cursor;
    use zipfast::zip::write::*;
    let text: Vec<u8> = (0..400_000u32).flat_map(|i| format!("{} line {}\n", i % 977, i / 3).into_bytes()).collect();
    let mut w = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    for (i, name) in ["plain.txt", "aes.txt", "crypt.txt", "stored.txt"].into_iter().enumerate() {
        let options = EntryOptions {
            name: EntryName::Utf8(name),
            method: if i == 3 { Method::Stored } else { Method::Deflate(DeflateLevel::new(6).unwrap()) },
            modified: DosDateTime::default(),
            extended_mtime: None,
            permissions: Permissions::new(0o644).unwrap(),
            comment: b"",
        };
        let plain = &text[i * 1_000..text.len() - i * 50_000];
        let len = InputLength::Exact(plain.len() as u64);
        let mut input = Cursor::new(plain);
        match i {
            0 => drop(w.add_file(options, &mut input, len).unwrap()),
            1 => {
                let request = WinZipAesRequest::new("pw", AesStrength::Aes256, AesVariant::Ae1).unwrap();
                w.add_winzip_aes_file(options, &mut input, len, request, |s| {
                    s.fill(5);
                    Ok(())
                })
                .unwrap();
            }
            _ => drop(
                w.add_zipcrypto_file(options, &mut input, len, "pw", |r| {
                    r.fill(9);
                    Ok(())
                })
                .unwrap(),
            ),
        }
    }
    w.finish().unwrap().sink
}

#[test]
fn zip_sets_through_the_live_feed() {
    let tmp = tempfile::tempdir().unwrap();
    let zip = zip_mixed();
    let one = tmp.path().join("one");
    std::fs::create_dir_all(&one).unwrap();
    std::fs::write(one.join("mixed.zip"), &zip).unwrap();
    // the same ZIP as a byte split of 300,000-byte pieces
    let split = tmp.path().join("split");
    std::fs::create_dir_all(&split).unwrap();
    for (i, piece) in zip.chunks(300_000).enumerate() {
        std::fs::write(split.join(format!("mixed.zip.{:03}", i + 1)), piece).unwrap();
    }
    let sets = [
        (sim::volumes_in(&one).unwrap(), Some("pw")),
        (sim::volumes_in(&split).unwrap(), Some("pw")),
        (fixture("zip-split", &["deflated.z01", "deflated.zip"]), None),
        (fixture("zip-split", &["crypt.z01", "crypt.zip"]), Some("password")),
    ];
    assert!(sets[1].0.len() > 2 && sets[1].0[0].ends_with("mixed.zip.001"));
    for (i, (volumes, password)) in sets.into_iter().enumerate() {
        for seed in 1..3 {
            let mut config = config(volumes.clone(), &tmp.path().join(format!("work-{i}-{seed}")), 9_000);
            config.seed = seed;
            config.password = password.map(str::to_owned);
            let report = sim::run(&config).unwrap();
            check(&report);
            assert_eq!(report.format, "zip");
            assert_eq!(report.fed, report.members, "{report:?}");
            // Deflate and ZipCrypto wait at holes; nothing is decoded twice without a restart
            assert_eq!(report.redecoded, 0, "{report:?}");
        }
        // a restart part way: Deflate members restore at a block boundary (their window read back from the partial),
        // ZipCrypto members read their packed bytes before it again
        let mut config = config(volumes.clone(), &tmp.path().join(format!("work-{i}-restart")), 9_000);
        config.password = password.map(str::to_owned);
        config.restart_at = Some(if i < 2 { 600 } else { 5 });
        let report = sim::run(&config).unwrap();
        check(&report);
    }
}
