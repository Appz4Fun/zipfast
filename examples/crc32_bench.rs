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

//! Times CRC-32 against `crc32fast` over buffers of 4 KiB to 64 MiB: `cargo run --release --example crc32_bench
//! [runs]`. Each size is hashed repeatedly (about 1 GiB a run) and the best run is kept.
//! Run with `ZIPFAST_CRC32=portable` to send `zipfast::crc32` to `crc32fast` as well.

use std::hint::black_box;
use std::time::Instant;
use zipfast::crc32::{crc32_backend, hash};

fn mbps(runs: usize, buf: &[u8], f: impl Fn(&[u8]) -> u32) -> (f64, u32) {
    let reps = ((1usize << 30) / buf.len()).max(1);
    let mut best = f64::MAX;
    let mut crc = 0;
    for _ in 0..runs {
        let t = Instant::now();
        for _ in 0..reps {
            crc = f(black_box(buf));
        }
        best = best.min(t.elapsed().as_secs_f64());
    }
    ((reps * buf.len()) as f64 / best / 1e6, crc)
}

fn main() {
    let runs: usize = std::env::args().nth(1).map_or(5, |s| s.parse().unwrap());
    let data: Vec<u8> = (0..64u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    println!("{:>8}  {:>12}  {:>12}  (zipfast: {})", "size", "crc32fast", "zipfast", crc32_backend());
    for size in [4 << 10, 64 << 10, 1 << 20, 64 << 20] {
        let buf = &data[..size];
        let (base, want) = mbps(runs, buf, crc32fast::hash);
        let (ours, got) = mbps(runs, buf, hash);
        assert_eq!(got, want);
        println!("{:>8}  {:>9.0} MB/s  {:>9.0} MB/s  ({:.2}x)", size, base, ours, ours / base);
    }
}
