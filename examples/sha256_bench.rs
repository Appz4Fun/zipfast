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

//! SHA-256 throughput, and the KDFs built on it, with the hardware rounds against the portable ones.
//!
//! `cargo run --release --example sha256_bench [MiB] [runs]` measures the backend this machine picks, then runs
//! itself again with `ZIPFAST_SHA256=scalar` for the portable rounds.

use std::time::{Duration, Instant};

const CHILD: &str = "ZIPFAST_SHA256_BENCH_CHILD";

fn best(runs: usize, mut f: impl FnMut()) -> Duration {
    (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .min()
        .unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mib: usize = args.get(1).map_or(256, |s| s.parse().unwrap());
    let runs: usize = args.get(2).map_or(5, |s| s.parse().unwrap());
    let data: Vec<u8> = (0..mib << 20).map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3]).collect();
    let backend = zipfast::crypto::sha256_backend();

    let mut digest = [0u8; 32];
    let bulk = best(runs, || digest = zipfast::crypto::sha256(std::hint::black_box(&data)));
    let small = best(runs, || {
        let mut h = zipfast::crypto::Sha256::new();
        for piece in data[..data.len().min(64 << 20)].chunks(1500) {
            h.update(piece);
        }
        digest = h.finalize();
    });
    let small_bytes = data.len().min(64 << 20);
    let sevenzip = best(runs, || {
        std::hint::black_box(zipfast::crypto::derive_7z_key("password123", &[7; 16], 19));
    });
    let rar5 = best(runs, || {
        std::hint::black_box(zipfast::crypto::derive_rar5_key("password123", 15, &[7; 16], None));
    });
    println!(
        "{backend:>8}: one-shot {:7.1} MB/s, 1500-byte updates {:7.1} MB/s, 7zAES KDF (2^19) {:6.1} ms, \
         RAR5 KDF (2^15) {:6.2} ms  [{:02x}{:02x}..]",
        data.len() as f64 / bulk.as_secs_f64() / 1e6,
        small_bytes as f64 / small.as_secs_f64() / 1e6,
        sevenzip.as_secs_f64() * 1e3,
        rar5.as_secs_f64() * 1e3,
        digest[0],
        digest[1],
    );

    if std::env::var_os(CHILD).is_none() && backend != "scalar" {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(&args[1..])
            .env(CHILD, "1")
            .env("ZIPFAST_SHA256", "scalar")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
