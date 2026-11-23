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

//! The feed decoder over compressed RAR 4.x members (the fixtures under `tests/fixtures/rar4*`): articles fed
//! shuffled, some missing and supplied later. RAR 4.x has no restart point inside a member: the decoder waits at
//! each hole and goes on when its bytes come.

use std::path::{Path, PathBuf};
use zipfast::map::*;

const PASSWORDS: [Option<&str>; 4] = [None, Some("password"), Some("junrar"), Some("testpw123")];

/// The volumes of every set whose first volume is in `dir`: `x.rar` with `x.r00`, `x.r01`, ... or `x.part1.rar`,
/// `x.part2.rar`, ...
fn sets(dir: &Path) -> Vec<Vec<PathBuf>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.to_ascii_lowercase().ends_with(".rar"))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let lower = name.to_ascii_lowercase();
        let stem = &name[..name.len() - 4];
        let mut vols = vec![dir.join(&name)];
        if let Some(i) = lower.rfind(".part") {
            let digits = &lower[i + 5..lower.len() - 4];
            if digits.trim_start_matches('0') != "1" {
                continue;
            }
            for k in 2.. {
                let next = format!("{}.part{:0width$}.rar", &name[..i], k, width = digits.len());
                if !dir.join(&next).exists() {
                    break;
                }
                vols.push(dir.join(next));
            }
        } else {
            for k in 0.. {
                let next = dir.join(format!("{stem}.r{k:02}"));
                if !next.exists() {
                    break;
                }
                vols.push(next);
            }
        }
        out.push(vols);
    }
    out
}

struct Out {
    bytes: Vec<u8>,
    seen: Vec<bool>,
    written: u64,
}

impl FeedSink for Out {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        let (s, e) = (offset as usize, offset as usize + bytes.len());
        assert!(self.seen[s..e].iter().all(|w| !w), "output {s}..{e} written twice");
        self.seen[s..e].iter_mut().for_each(|w| *w = true);
        self.written += bytes.len() as u64;
        self.bytes[s..e].copy_from_slice(bytes);
        Ok(())
    }
}

fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut x = seed | 1;
    for i in (1..v.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.swap(i, (x % (i as u64 + 1)) as usize);
    }
}

type Article = (u32, u64, Vec<u8>);

/// Feeds member `i` from shuffled articles of `size` bytes, every `every`th missing until the rest are in, with a
/// snapshot round trip half way through the missing ones; checks the output.
fn feed(map: &MemberMap, i: usize, vols: &[Vec<u8>], password: Option<&str>, size: usize, every: usize) -> FeedStats {
    let options = || FeedOptions { max_needs: usize::MAX, read_chunk: 64, ..FeedOptions::new(password) };
    let mut d = FeedDecoder::new(map, i, options()).unwrap();
    let n = d.size() as usize;
    let mut out = Out { bytes: vec![0; n], seen: vec![false; n], written: 0 };
    let mut all: Vec<Article> = Vec::new();
    for (v, bytes) in vols.iter().enumerate() {
        for (k, chunk) in bytes.chunks(size).enumerate() {
            all.push((v as u32, (k * size) as u64, chunk.to_vec()));
        }
    }
    shuffle(&mut all, 0xA11 ^ size as u64 ^ i as u64);
    let (missing, present): (Vec<_>, Vec<_>) = all.into_iter().enumerate().partition(|(k, _)| k % every == 1);
    let mut source = ArticleBuffer::new(usize::MAX);
    for (_, (v, off, b)) in &missing {
        source.mark_lost(*v, *off..*off + b.len() as u64);
    }
    for (_, (v, off, b)) in &present {
        source.insert(*v, *off, b).unwrap();
        d.run(&mut source, &mut out).unwrap();
    }
    let s = d.status().clone();
    if !s.done {
        // waiting: at a hole (its bytes first), or for bytes not here yet
        let first = &s.needs[0];
        assert_eq!(first.kind, NeedKind::Next);
        // inside the missing articles (adjacent ones are named together)
        let mut at = first.range.start;
        while at < first.range.end {
            let a =
                missing.iter().find(|(_, (v, off, b))| *v == first.volume && *off <= at && at < off + b.len() as u64);
            let Some((_, (_, off, b))) = a else { panic!("{first:?} at {at}") };
            at = off + b.len() as u64;
        }
        assert!(s.stalled);
        assert!(s.lost.is_empty());
    }
    let half = missing.len() / 2;
    let mut at_snapshot = 0;
    for (k, (_, (v, off, b))) in missing.iter().enumerate() {
        if k == half {
            at_snapshot = d.status().frontier;
            let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
            let before = d.stats().redecoded;
            d = FeedDecoder::restore(map, i, options(), &snap).unwrap();
            assert_eq!(d.stats().redecoded, before);
            assert_eq!(d.status().frontier, at_snapshot);
            // the bytes passed were released: the restored decoder reads the member from its start again, so it
            // asks for them first, and the caller (holding its articles on disk) gives them again
            let s = d.run(&mut source, &mut out).unwrap();
            let start = &map.members[i].pieces[0];
            if at_snapshot > 0
                && let Some(need) = s.needs.first()
            {
                assert_eq!(
                    (need.kind, need.volume, need.range.start),
                    (NeedKind::Next, start.volume, start.packed.start)
                );
            }
            for (_, (v, off, b)) in &present {
                source.insert(*v, *off, b).unwrap();
            }
            for (_, (v, off, b)) in &missing[..k] {
                source.insert(*v, *off, b).unwrap();
            }
        }
        source.insert(*v, *off, b).unwrap();
        d.run(&mut source, &mut out).unwrap();
    }
    let s = d.status();
    assert!(s.done, "{s:?}");
    assert_eq!(s.crc_ok, Some(true));
    assert_eq!(out.written, n as u64, "each output byte written once");
    assert!(out.seen.iter().all(|&w| w));
    // a restore decodes again from the member's start up to where the snapshot stood, and nothing else does
    assert!(d.stats().redecoded <= at_snapshot, "{} > {at_snapshot}", d.stats().redecoded);
    d.stats()
}

/// The output of member `i`, fed whole and in order.
fn whole(map: &MemberMap, i: usize, vols: &[Vec<u8>], password: Option<&str>) -> Vec<u8> {
    let mut d = FeedDecoder::new(map, i, FeedOptions::new(password)).unwrap();
    let n = d.size() as usize;
    let mut out = Out { bytes: vec![0; n], seen: vec![false; n], written: 0 };
    let mut source = ArticleBuffer::new(usize::MAX);
    for (v, b) in vols.iter().enumerate() {
        source.insert(v as u32, 0, b).unwrap();
    }
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert_eq!(d.stats().redecoded, 0);
    out.bytes
}

#[test]
fn compressed_rar4_fixtures_feed_shuffled_and_wait_at_holes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut fed = 0;
    let mut versions = std::collections::BTreeSet::new();
    for dir in ["rar4", "rar4-legacy", "rar4-rar300", "rar4-archiver", "rar4-unrar", "rar4-volumes"] {
        let Ok(_) = std::fs::read_dir(root.join(dir)) else { continue };
        for set in sets(&root.join(dir)) {
            let vols: Vec<Vec<u8>> = set.iter().map(|p| std::fs::read(p).unwrap()).collect();
            let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
            let first = set[0].file_name().unwrap();
            for password in PASSWORDS {
                let Ok(map) = MemberMap::from_memory(&refs, first, password) else { continue };
                if map.format != MapFormat::Rar4 {
                    break;
                }
                let mut any = false;
                for (i, m) in map.members.iter().enumerate() {
                    if !matches!(m.method, MapMethod::Compressed { .. }) || m.unpacked_size.is_none_or(|s| s == 0) {
                        continue;
                    }
                    let Ok(mut probe) = FeedDecoder::new(&map, i, FeedOptions::new(password)) else { continue };
                    // members this password does not open, or that do not decode (damaged fixtures), are left out
                    let mut source = ArticleBuffer::new(usize::MAX);
                    for (v, b) in vols.iter().enumerate() {
                        source.insert(v as u32, 0, b).unwrap();
                    }
                    let n = probe.size() as usize;
                    let mut sink = Out { bytes: vec![0; n], seen: vec![false; n], written: 0 };
                    match probe.run(&mut source, &mut sink) {
                        Ok(s) if s.crc_ok == Some(true) => {}
                        _ => continue,
                    }
                    any = true;
                    let plain = whole(&map, i, &vols, password);
                    let packed = m.packed_size as usize;
                    for (size, every) in [(97usize, 5usize), (packed.div_ceil(6).max(16), 3)] {
                        let stats = feed(&map, i, &vols, password, size, every);
                        eprintln!(
                            "{dir}/{} member {i} (v{:?}, {} bytes): articles of {size}: read {}, decoded again {}",
                            first.to_string_lossy(),
                            m.unpack_version,
                            plain.len(),
                            stats.packed_read,
                            stats.redecoded
                        );
                    }
                    versions.insert(m.unpack_version);
                    fed += 1;
                }
                if any {
                    break;
                }
            }
        }
    }
    eprintln!("{fed} members fed, unpack versions {versions:?}");
    assert!(fed >= 10, "{fed} members");
    assert!(versions.len() >= 2, "{versions:?}");
}

#[test]
fn rar4_solid_successors_and_legacy_ciphers_are_refused() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4");
    let bytes = std::fs::read(root.join("solid.rar")).unwrap();
    let map = MemberMap::from_memory(&[&bytes], "solid.rar", None).unwrap();
    let solid = map.members.iter().position(|m| m.solid).expect("a solid successor");
    assert!(matches!(
        FeedDecoder::new(&map, solid, FeedOptions::default()),
        Err(FeedError::Unsupported(FeedUnsupported::Solid))
    ));
}

#[test]
fn an_encrypted_rar4_member_needs_its_password() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-rar300");
    let bytes = std::fs::read(root.join("per_file_rar300_password.rar")).unwrap();
    let map = MemberMap::from_memory(&[&bytes], "per_file_rar300_password.rar", None).unwrap();
    let i = map.members.iter().position(|m| m.encrypted).unwrap();
    assert!(matches!(FeedDecoder::new(&map, i, FeedOptions::default()), Err(FeedError::PasswordRequired)));
    let vols = vec![bytes.clone()];
    assert!(!whole(&map, i, &vols, Some("password")).is_empty());
}
