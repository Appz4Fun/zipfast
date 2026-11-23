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

//! `map::ContainerRebuilder` on RustyGet's z-fixture sets: every volume of the stored sets (F01 RAR 5.0 store + AES,
//! F02 the same with `-hp`, F09 7z Copy + 7zAES with `-mhe`, F11 RAR 5.0 store + AES with two files) rebuilt from
//! the payloads and compared byte for byte with the real volume, plus ranges cutting through AES blocks and held
//! output with holes. Compressed sets (F03, F07) report what a handover plan skips.
//!
//! Skipped unless `ZIPFAST_Z_FIXTURES` names the sets directory (holding `MANIFEST.json`, the payloads and a
//! directory per set). Run it in release:
//!
//! ```text
//! ZIPFAST_Z_FIXTURES=~/rustyget-requests/z-fixtures/sets cargo test --release --test container_rebuild_z -- --nocapture
//! ```
//!
//! Header bytes come from the volume itself, but only what a downloader holds of it: the tail is rebuilt from the
//! volume's headers before its last data (member data zeroed), the start from the bytes after its last data.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Instant;

use zipfast::map::{
    ByteState, ContainerRebuilder, Crc32Check, HeldMembers, KnownBytes, MapFormat, MemberMap, Missing, OpenAtOptions,
    RebuildOptions, RebuiltRange, Seed, VolumeHeaders, open_at,
};

const ARTICLE: u64 = 750_000;

struct Set {
    name: String,
    vols: Vec<Vec<u8>>,
    map: MemberMap,
    password: String,
    payloads: Vec<(String, Vec<u8>)>,
}

fn load(dir: &Path, name: &str, password: &str, payloads: &[(String, Vec<u8>)]) -> Set {
    let set_dir = dir.join(name);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&set_dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    let vols: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
    let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
    let first = files[0].file_name().unwrap().to_owned();
    let map = MemberMap::from_memory(&refs, first, Some(password)).unwrap();
    Set { name: name.into(), vols, map, password: password.into(), payloads: payloads.to_vec() }
}

impl Set {
    /// Each data member's payload, matched by name or size.
    fn held(&self) -> Vec<(usize, &[u8])> {
        self.map
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.is_dir && m.unpacked_size.unwrap_or(0) > 0)
            .map(|(i, m)| {
                let base = m.name.as_deref().unwrap_or("").rsplit(['/', '\\']).next().unwrap_or("").to_owned();
                let p = self
                    .payloads
                    .iter()
                    .find(|(n, _)| *n == base)
                    .or_else(|| self.payloads.iter().find(|(_, p)| Some(p.len() as u64) == m.unpacked_size))
                    .unwrap_or_else(|| panic!("{}: no payload for {:?}", self.name, m.name));
                (i, p.1.as_slice())
            })
            .collect()
    }

    fn held_members(&self, good: Option<Vec<Range<u64>>>) -> HeldMembers<'_> {
        let mut h = HeldMembers::new();
        for (i, p) in self.held() {
            h = h.with(i, p, good.clone());
        }
        h
    }

    /// Data ranges of volume `v` (RAR pieces, 7z folder spans).
    fn data(&self, v: u32) -> Vec<Range<u64>> {
        let mut out: Vec<Range<u64>> = if self.map.format == MapFormat::SevenZip {
            self.map
                .folders
                .iter()
                .flat_map(|f| f.packed.iter())
                .filter(|s| s.volume == v)
                .map(|s| s.packed.clone())
                .collect()
        } else {
            self.map
                .members
                .iter()
                .flat_map(|m| m.pieces.iter())
                .filter(|p| p.volume == v)
                .map(|p| p.packed.clone())
                .collect()
        };
        out.sort_by_key(|r| r.start);
        out
    }

    fn headers_end(&self, v: u32) -> u64 {
        self.map
            .members
            .iter()
            .flat_map(|m| m.pieces.iter())
            .filter(|p| p.volume == v)
            .map(|p| p.header.end)
            .max()
            .unwrap_or(0)
    }

    fn checks(&self, v: u32) -> Vec<Crc32Check> {
        let vol = &self.vols[v as usize];
        (0..vol.len() as u64)
            .step_by(ARTICLE as usize)
            .map(|a| {
                let b = (a + ARTICLE).min(vol.len() as u64);
                Crc32Check { volume: v, range: a..b, crc32: crc32fast::hash(&vol[a as usize..b as usize]) }
            })
            .collect()
    }
}

fn assert_exact(got: &RebuiltRange, volume: &[u8], what: &str) -> u64 {
    let mut n = 0;
    let mut wrong = 0u64;
    for r in &got.regions {
        if matches!(r.state, ByteState::Rebuilt(_)) {
            for o in r.range.clone() {
                if got.bytes[(o - got.range.start) as usize] != volume[o as usize] {
                    wrong += 1;
                }
            }
            n += r.range.end - r.range.start;
        }
    }
    assert_eq!(wrong, 0, "{what}: rebuilt bytes differ from the volume");
    assert!(got.conflicts.is_empty(), "{what}: {:?}", got.conflicts);
    n
}

fn summary(got: &RebuiltRange) -> String {
    let mut by: BTreeMap<String, u64> = BTreeMap::new();
    for r in got.missing() {
        let ByteState::Missing(m) = &r.state else { continue };
        let key = match m {
            Missing::Header(g) => format!("header ({g:?})"),
            other => format!("{other:?}"),
        };
        *by.entry(key).or_default() += r.range.end - r.range.start;
    }
    by.iter().map(|(k, v)| format!("{v} {k}")).collect::<Vec<_>>().join(", ")
}

fn overlap(a: &Range<u64>, b: &Range<u64>) -> u64 {
    a.end.min(b.end).saturating_sub(a.start.max(b.start))
}

fn whole_volumes(set: &Set) {
    let mut rb = ContainerRebuilder::new(&set.map, Some(&set.password));
    let mut held = set.held_members(None);
    let n = set.vols.len();
    let (mut total, mut rebuilt) = (0u64, 0u64);
    let started = Instant::now();
    for (v, vol) in set.vols.iter().enumerate() {
        let vi = v as u32;
        let data = set.data(vi);
        // what a downloader holds of the headers: before the last data (data zeroed), and after it
        let head_end = set.headers_end(vi) as usize;
        let mut head = vol[..head_end].to_vec();
        for d in &data {
            let (a, b) = (d.start as usize, (d.end as usize).min(head_end));
            if a < b {
                head[a..b].fill(0);
            }
        }
        let tail_at = data.last().map_or(vol.len(), |d| d.end as usize);
        let sib = (v + 1) % n;
        let sibling = &set.vols[sib][..set.data(sib as u32).first().map_or(0, |d| d.start as usize).min(4096)];
        let headers = VolumeHeaders {
            volume_len: vol.len() as u64,
            head: Some(&head),
            tail: Some(&vol[tail_at..]),
            more_volumes: Some(v + 1 < n),
            quick_open: None,
            sibling: Some(sibling),
        };
        // Encrypted headers (-hp, -mhe) cannot be rebuilt, so the articles holding them are downloaded: give their
        // header bytes as known, so the final block's article CRC can still decide its padding.
        let mut known = Vec::new();
        if set.map.header_encrypted {
            let mut at = 0u64;
            for d in data.iter().chain(std::iter::once(&(vol.len() as u64..vol.len() as u64))) {
                if at < d.start {
                    known.push(KnownBytes { volume: vi, offset: at, bytes: &vol[at as usize..d.start as usize] });
                }
                at = at.max(d.end);
            }
        }
        let mut options =
            RebuildOptions { headers: Some(headers), checks: set.checks(vi), known, ..Default::default() };
        let got = rb.rebuild(vi, 0..vol.len() as u64, &mut held, &mut options).unwrap();
        let ok = assert_exact(&got, vol, &format!("{} volume {v}", set.name));
        let data_len: u64 = data.iter().map(|d| d.end - d.start).sum();
        let data_rebuilt: u64 = got
            .regions
            .iter()
            .filter(|r| matches!(r.state, ByteState::Rebuilt(_)))
            .map(|r| data.iter().map(|d| overlap(d, &r.range)).sum::<u64>())
            .sum();
        assert_eq!(data_rebuilt, data_len, "{} volume {v}: all member data rebuilt ({})", set.name, summary(&got));
        println!(
            "{} vol {:>2}: {:>8} / {:>8} bytes rebuilt ({:>6.2}%), data {}/{}; missing: {}",
            set.name,
            v,
            ok,
            vol.len(),
            100.0 * ok as f64 / vol.len() as f64,
            data_rebuilt,
            data_len,
            summary(&got)
        );
        total += vol.len() as u64;
        rebuilt += ok;
    }
    println!(
        "{}: {rebuilt} / {total} bytes rebuilt ({:.4}%) in {:.2?}",
        set.name,
        100.0 * rebuilt as f64 / total as f64,
        started.elapsed()
    );
}

fn ranges(set: &Set) {
    let mut held = set.held_members(None);
    let v = 2u32.min(set.vols.len() as u32 - 1);
    let vol = &set.vols[v as usize];
    let len = vol.len() as u64;
    for r in [3 * ARTICLE + 5..4 * ARTICLE + 5, 12_345..54_321, 7..23, len - 1_000_017..len - 3] {
        // a fresh rebuilder: the previous block is chained from the member's IV through the held output
        let mut rb = ContainerRebuilder::new(&set.map, Some(&set.password));
        let got = rb.rebuild(v, r.clone(), &mut held, &mut RebuildOptions::default()).unwrap();
        let n = assert_exact(&got, vol, &format!("{} volume {v} {r:?}", set.name));
        let want: u64 = set.data(v).iter().map(|d| overlap(d, &r)).sum();
        assert_eq!(n, want, "{} volume {v} {r:?}: {}", set.name, summary(&got));
        println!("{} vol {v} {r:?}: {n} data bytes rebuilt of {}", set.name, r.end - r.start);
    }
}

fn holes(set: &Set) {
    let held_list = set.held();
    let (member, payload) = held_list[0];
    let size = payload.len() as u64;
    // output 9_000_000..9_000_100 lost from the held copy
    let hole = 9_000_000..9_000_100;
    let mut held = set.held_members(Some(vec![0..hole.start, hole.end..size]));
    let mut rb = ContainerRebuilder::new(&set.map, Some(&set.password));
    // which volume carries the hole
    let (v, at) = (0..set.vols.len() as u32)
        .find_map(|v| {
            let got =
                rb.rebuild(v, 0..set.vols[v as usize].len() as u64, &mut held, &mut RebuildOptions::default()).ok()?;
            got.regions.iter().find(|r| r.state == ByteState::Missing(Missing::NotHeld)).map(|r| (v, r.clone()))
        })
        .expect("a volume carries the hole");
    assert_eq!(at.member, Some(member));
    let out = at.output.clone().unwrap();
    assert!(out.start <= hole.start && out.end >= hole.end && out.end - out.start < 100 + 32, "{out:?}");
    // the bytes after it: chain broken, unless the volume bytes before the requested range are known
    let vol = &set.vols[v as usize];
    let from = (at.range.end + 1_000).min(vol.len() as u64 - 2_000);
    let range = from..(from + ARTICLE).min(vol.len() as u64);
    let mut rb = ContainerRebuilder::new(&set.map, Some(&set.password));
    let got = rb.rebuild(v, range.clone(), &mut held, &mut RebuildOptions::default()).unwrap();
    assert_exact(&got, vol, "after the hole");
    let chain = got.len_where(|s| *s == ByteState::Missing(Missing::Chain));
    let known = vec![KnownBytes { volume: v, offset: from - 64, bytes: &vol[from as usize - 64..from as usize] }];
    let mut options = RebuildOptions { known, ..Default::default() };
    let got2 = rb.rebuild(v, range.clone(), &mut held, &mut options).unwrap();
    let n = assert_exact(&got2, vol, "after the hole, with known bytes");
    let want: u64 = set.data(v).iter().map(|d| overlap(d, &range)).sum();
    assert_eq!(n, want);
    println!(
        "{}: hole at output {hole:?} -> volume {v} {:?} not held; next article: {chain} bytes without the previous \
         block, {n} rebuilt with 64 known bytes before it",
        set.name, at.range
    );
}

fn compressed(set: &Set) {
    let member = set.held()[0].0;
    let size = set.map.members[member].unpacked_size.unwrap();
    // a handover seeded from the held output, which fetches least
    let options = OpenAtOptions { seed: Seed::HeldPlaintext { strict: false }, ..Default::default() };
    let plan = open_at(&set.map, member, size * 6 / 10, &options).unwrap();
    let plans = [plan];
    let mut rb = ContainerRebuilder::new(&set.map, Some(&set.password));
    let mut held = set.held_members(None);
    let (mut unneeded, mut total) = (0, 0);
    for (v, vol) in set.vols.iter().enumerate() {
        let mut options = RebuildOptions { plans: &plans, ..Default::default() };
        let got = rb.rebuild(v as u32, 0..vol.len() as u64, &mut held, &mut options).unwrap();
        assert_eq!(got.rebuilt_len(), 0);
        unneeded += got.unneeded_len();
        total += vol.len() as u64;
    }
    println!(
        "{}: handover at 60% of the output: {unneeded} of {total} volume bytes unneeded (restart fetch from packed {})",
        set.name, plans[0].fetch_from
    );
    assert!(unneeded > 0);
}

#[test]
fn z_fixture_sets_rebuild_byte_for_byte() {
    let Some(dir) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(PathBuf::from) else {
        eprintln!("skipped: set ZIPFAST_Z_FIXTURES to the z-fixtures sets directory");
        return;
    };
    let manifest = std::fs::read_to_string(dir.join("MANIFEST.json")).unwrap();
    let password = manifest.split("\"password\": \"").nth(1).and_then(|s| s.split('"').next()).unwrap().to_owned();
    let payloads: Vec<(String, Vec<u8>)> =
        ["cabac.mkv", "mixed.mkv"].iter().map(|n| (n.to_string(), std::fs::read(dir.join(n)).unwrap())).collect();
    let only = std::env::var("Z_REBUILD_SETS").ok();
    let wanted = |name: &str| only.as_deref().is_none_or(|o| o.split(',').any(|p| name.starts_with(p)));
    for name in ["F01_rar5_store_aes", "F02_rar5_store_aes_hp", "F09_7z_copy_aes_mhe", "F11_rar5_store_aes_solid2"] {
        if !wanted(name) {
            continue;
        }
        let set = load(&dir, name, &password, &payloads);
        whole_volumes(&set);
        ranges(&set);
        holes(&set);
    }
    for name in ["F03_rar5_m3_video", "F07_7z_lzma2_video"] {
        if wanted(name) {
            compressed(&load(&dir, name, &password, &payloads));
        }
    }
}
