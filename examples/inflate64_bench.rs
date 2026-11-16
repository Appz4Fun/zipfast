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
//! Raw inflate throughput: zipfast's Deflate64 decoder against flate2 (miniz_oxide) on the same input.
//!
//! `cargo run --release --example inflate64_bench FILE [DEFLATE64.zip] [runs]` compresses FILE with flate2 (level 6)
//! and decodes it with both decoders as plain Deflate. With a ZIP whose first member is FILE packed as Deflate64
//! (`7zz a -tzip -mm=Deflate64 out.zip FILE`), it also decodes that member's stream.

use std::io::Write;
use std::time::{Duration, Instant};

use zipfast::inflate64::{Inflater, Variant};

fn best(runs: usize, mut f: impl FnMut() -> usize) -> Duration {
    (0..runs)
        .map(|_| {
            let t = Instant::now();
            std::hint::black_box(f());
            t.elapsed()
        })
        .min()
        .unwrap()
}

/// Decodes `packed` with zipfast into a 1 MiB buffer, returning the CRC-free byte count.
fn zipfast(variant: Variant, packed: &[u8], out: &mut [u8], check: Option<&[u8]>) -> usize {
    let mut inflater = Inflater::new(variant);
    let (mut at, mut total) = (0, 0);
    loop {
        let step = inflater.step(&packed[at..], out).expect("decodes");
        if let Some(want) = check {
            assert_eq!(&out[..step.produced], &want[total..total + step.produced]);
        }
        at += step.consumed;
        total += step.produced;
        if step.done {
            return total;
        }
        assert!(step.consumed + step.produced != 0, "truncated");
    }
}

fn flate2(packed: &[u8], out: &mut [u8]) -> usize {
    let mut z = flate2::Decompress::new(false);
    loop {
        let before = z.total_in() as usize;
        let status = z.decompress(&packed[before..], out, flate2::FlushDecompress::None).expect("decodes");
        if status == flate2::Status::StreamEnd {
            return z.total_out() as usize;
        }
    }
}

/// The first local member's packed bytes.
fn first_member(zip: &[u8]) -> (u16, &[u8]) {
    let le16 = |o: usize| usize::from(u16::from_le_bytes([zip[o], zip[o + 1]]));
    let packed = u32::from_le_bytes(zip[18..22].try_into().unwrap()) as usize;
    let start = 30 + le16(26) + le16(28);
    (le16(8) as u16, &zip[start..start + packed])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&args[1]).expect("input file");
    let runs: usize = args.get(3).map_or(5, |s| s.parse().unwrap());
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    e.write_all(&data).unwrap();
    let deflated = e.finish().unwrap();
    let mut out = vec![0u8; 1 << 20];
    let mb = data.len() as f64 / 1e6;
    let rate = |d: Duration| mb / d.as_secs_f64();
    println!("input {:.1} MB, Deflate {:.1} MB", mb, deflated.len() as f64 / 1e6);
    assert_eq!(zipfast(Variant::Deflate, &deflated, &mut out, Some(&data)), data.len());
    let f = best(runs, || flate2(&deflated, &mut out));
    let z = best(runs, || zipfast(Variant::Deflate, &deflated, &mut out, None));
    println!("Deflate   flate2  {:7.0} MB/s", rate(f));
    println!("Deflate   zipfast {:7.0} MB/s", rate(z));
    if let Some(zip) = args.get(2) {
        let zip = std::fs::read(zip).expect("zip file");
        let (method, raw) = first_member(&zip);
        assert_eq!(method, 9, "the first member is not Deflate64");
        println!("Deflate64 {:.1} MB", raw.len() as f64 / 1e6);
        assert_eq!(zipfast(Variant::Deflate64, raw, &mut out, Some(&data)), data.len());
        let d = best(runs, || zipfast(Variant::Deflate64, raw, &mut out, None));
        println!("Deflate64 zipfast {:7.0} MB/s", rate(d));
    }
}
