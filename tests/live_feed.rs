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
