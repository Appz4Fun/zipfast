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

//! Times RAR 5.0 compressed decoding of a whole archive held in memory, the way RustyGet decodes once every
//! article is in: a [`FeedDecoder`] per member reading through a [`PackedSource`], output to a sink that drops it
//! (the decoder still checks the member's CRC32).
//! `cargo run --release --example rar5_feed_bench -- [--runs N] [--member I] <volume>...`
//! Prints the median, best and worst of N runs for each compressed member, in unpacked MB/s.

use std::io;
use std::time::Instant;
use zipfast::map::{FeedDecoder, FeedOptions, FeedSink, MemberMap, PackedRead, PackedSource};

struct Memory<'a>(&'a [Vec<u8>]);

impl PackedSource for Memory<'_> {
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> PackedRead {
        let Some(v) = self.0.get(volume as usize) else { return PackedRead::Hole { len: u64::MAX } };
        let at = offset as usize;
        if at >= v.len() {
            return PackedRead::Hole { len: u64::MAX };
        }
        let n = buf.len().min(v.len() - at);
        buf[..n].copy_from_slice(&v[at..at + n]);
        PackedRead::Data(n)
    }
}

struct Discard(u64);

impl FeedSink for Discard {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        assert_eq!(offset, self.0, "output out of order");
        self.0 += bytes.len() as u64;
        Ok(())
    }
}

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let (mut runs, mut only) = (5usize, None);
    let mut paths = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--runs" => runs = args.next().unwrap().parse().unwrap(),
            "--member" => only = Some(args.next().unwrap().parse::<usize>().unwrap()),
            _ => paths.push(a),
        }
    }
    assert!(!paths.is_empty(), "usage: rar5_feed_bench [--runs N] [--member I] <volume>...");
    let volumes: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, &paths[0], None).unwrap();
    for (i, m) in map.members.iter().enumerate() {
        if only.is_some_and(|o| o != i) || m.is_dir || m.solid {
            continue;
        }
        let Some(size) = m.unpacked_size.filter(|&s| s > 0) else { continue };
        let mut times = Vec::new();
        for _ in 0..runs {
            let t = Instant::now();
            let mut d = FeedDecoder::new(&map, i, FeedOptions::default()).unwrap();
            let mut sink = Discard(0);
            let status = d.run(&mut Memory(&volumes), &mut sink).unwrap();
            let s = t.elapsed().as_secs_f64();
            assert!(status.done && status.crc_ok != Some(false), "member {i}: {status:?}");
            assert_eq!(sink.0, size);
            times.push(s);
        }
        times.sort_by(f64::total_cmp);
        let mbs = |s: f64| size as f64 / s / 1e6;
        println!(
            "member {i} {:?}: {} MB unpacked, {:.1}% packed, {runs} runs: median {:.0} MB/s (best {:.0}, worst {:.0})",
            m.name.as_deref().unwrap_or("?"),
            size / 1_000_000,
            100.0 * m.packed_size as f64 / size as f64,
            mbs(times[runs / 2]),
            mbs(times[0]),
            mbs(times[runs - 1]),
        );
    }
}
