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

//! The feed decoder over RustyGet's z-fixtures: every set's volumes cut into 750,000-byte articles, fed shuffled
//! with some missing, the missing ones supplied later.
//!
//! Skipped unless `ZIPFAST_Z_FIXTURES` names the sets directory (holding `MANIFEST.json`, the payloads and a
//! directory per set). Run it in release:
//!
//! ```text
//! ZIPFAST_Z_FIXTURES=~/rustyget-requests/z-fixtures/sets cargo test --release --test feed_decoder_z -- --nocapture
//! ```

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Instant;

use zipfast::map::{ArticleBuffer, FeedDecoder, FeedOptions, FeedSink, MemberMap, NeedKind, PackedRead, PackedSource};

const ARTICLE: usize = 750_000;

/// An [`ArticleBuffer`] shared by several members' decoders: it keeps what one decoder releases.
struct Keep(ArticleBuffer);

impl PackedSource for Keep {
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> PackedRead {
        self.0.read_packed(volume, offset, buf)
    }
    fn absent(&self, volume: u32, range: Range<u64>) -> Option<Vec<Range<u64>>> {
        self.0.absent(volume, range)
    }
}

/// Output written at most once per byte.
struct Out {
    bytes: Vec<u8>,
    written: u64,
}

impl FeedSink for Out {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.written += bytes.len() as u64;
        self.bytes[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
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

fn run_set(dir: &Path, name: &str, password: &str, payloads: &[(String, Vec<u8>)]) {
    let set_dir = dir.join(name);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&set_dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    let vols: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
    let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, files[0].file_name().unwrap(), Some(password)).unwrap();
    let mut articles: Vec<(u32, u64, &[u8])> = Vec::new();
    for (v, bytes) in vols.iter().enumerate() {
        for (i, chunk) in bytes.chunks(ARTICLE).enumerate() {
            articles.push((v as u32, (i * ARTICLE) as u64, chunk));
        }
    }
    shuffle(&mut articles, 0x5EED ^ name.len() as u64);
    // every seventh article is missing at first
    let (missing, present): (Vec<_>, Vec<_>) = articles.into_iter().enumerate().partition(|(i, _)| i % 7 == 3);
    let members: Vec<usize> =
        (0..map.members.len()).filter(|&i| !map.members[i].is_dir && map.members[i].unpacked_size > Some(0)).collect();
    let mut decoders: Vec<(usize, FeedDecoder, Out)> = members
        .iter()
        .map(|&i| {
            let m = &map.members[i];
            let options = FeedOptions { max_needs: usize::MAX, ..FeedOptions::new(Some(password)) };
            let d = FeedDecoder::new(&map, i, options).unwrap_or_else(|e| panic!("{name} member {i}: {e}"));
            (i, d, Out { bytes: vec![0; m.unpacked_size.unwrap() as usize], written: 0 })
        })
        .collect();
    let mut source = Keep(ArticleBuffer::new(usize::MAX));
    for (_, (v, off, bytes)) in &missing {
        source.0.mark_lost(*v, *off..*off + bytes.len() as u64);
    }
    let start = Instant::now();
    for (_, (v, off, bytes)) in &present {
        source.0.insert(*v, *off, bytes).unwrap();
        for (_, d, out) in &mut decoders {
            d.run(&mut source, out).unwrap();
        }
    }
    let first = start.elapsed();
    for (i, d, _) in &decoders {
        let s = d.status();
        assert!(s.needs.iter().all(|n| n.kind == NeedKind::Repair), "{name} {i}: {:?}", s.needs);
        // what is needed lies inside the missing articles (adjacent ones may be named together)
        for n in &s.needs {
            let mut at = n.range.start;
            while at < n.range.end {
                let a =
                    missing.iter().find(|(_, (v, off, b))| *v == n.volume && *off <= at && at < off + b.len() as u64);
                let Some((_, (_, off, b))) = a else { panic!("{name} {i}: {n:?} at {at}") };
                at = off + b.len() as u64;
            }
        }
        eprintln!(
            "{name} member {i}: {} holes, {} lost ranges ({} bytes), {} needs",
            d.stats().holes,
            s.lost.len(),
            s.lost.iter().map(|r| r.end - r.start).sum::<u64>(),
            s.needs.len()
        );
    }
    let start = Instant::now();
    for (_, (v, off, bytes)) in &missing {
        source.0.insert(*v, *off, bytes).unwrap();
        for (_, d, out) in &mut decoders {
            d.run(&mut source, out).unwrap();
        }
    }
    let repair = start.elapsed();
    for (i, d, out) in &decoders {
        let m = &map.members[*i];
        let s = d.status();
        assert!(s.done, "{name} {i}: {s:?}");
        assert_eq!(s.crc_ok, Some(true), "{name} {i}");
        let base = m.name.as_deref().unwrap_or("").rsplit(['/', '\\']).next().unwrap_or("").to_owned();
        let payload = payloads
            .iter()
            .find(|(n, _)| *n == base)
            .or_else(|| payloads.iter().find(|(_, p)| Some(p.len() as u64) == m.unpacked_size))
            .unwrap();
        assert!(out.bytes == payload.1, "{name} {i}: output differs from {}", payload.0);
        // no output byte decoded twice
        assert_eq!(out.written, m.unpacked_size.unwrap(), "{name} {i}");
        eprintln!(
            "{name} member {i}: exact; read {} of {} packed bytes; feed {:.0?}, repairs {:.0?}",
            d.stats().packed_read,
            m.packed_size,
            first,
            repair
        );
    }
}

#[test]
fn z_fixture_sets_feed_shuffled_with_holes() {
    let Some(dir) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(PathBuf::from) else {
        eprintln!("skipped: set ZIPFAST_Z_FIXTURES to the z-fixtures sets directory");
        return;
    };
    let manifest = std::fs::read_to_string(dir.join("MANIFEST.json")).unwrap();
    let password = manifest.split("\"password\": \"").nth(1).and_then(|s| s.split('"').next()).unwrap().to_owned();
    let payloads: Vec<(String, Vec<u8>)> =
        ["cabac.mkv", "mixed.mkv"].iter().map(|n| (n.to_string(), std::fs::read(dir.join(n)).unwrap())).collect();
    let only = std::env::var("Z_FEED_SETS").ok();
    for name in ["F01_rar5_store_aes", "F02_rar5_store_aes_hp", "F11_rar5_store_aes_solid2"] {
        if only.as_deref().is_none_or(|o| o.split(',').any(|p| name.starts_with(p))) {
            run_set(&dir, name, &password, &payloads);
        }
    }
}
