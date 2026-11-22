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

//! Times BLAKE2sp over 256 MiB in 1 MiB updates: `cargo run --release --example blake2sp_bench [runs]`.
//! Run with `ZIPFAST_BLAKE2SP=scalar` for the portable rounds.

use std::time::Instant;
use zipfast::blake2sp::{Blake2sp, blake2sp_backend};

fn main() {
    let runs: usize = std::env::args().nth(1).map_or(3, |s| s.parse().unwrap());
    let data: Vec<u8> = (0..256u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let mut best = f64::MAX;
    let mut digest = [0u8; 32];
    for _ in 0..runs {
        let t = Instant::now();
        let mut h = Blake2sp::new();
        for chunk in data.chunks(1 << 20) {
            h.update(chunk);
        }
        digest = h.finish();
        best = best.min(t.elapsed().as_secs_f64());
    }
    println!(
        "{}: {:.0} MB/s (digest {:02x}{:02x}..)",
        blake2sp_backend(),
        data.len() as f64 / best / 1e6,
        digest[0],
        digest[1]
    );
}
