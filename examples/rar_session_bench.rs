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

//! Times RAR 5.0 extraction of a whole set two ways: the whole-archive run (`extract::run`) and a `RarSession`
//! (`extract_selected` of every member, or `test_selected`, which writes nothing).
//! `cargo run --release --example rar_session_bench -- [--runs N] [--threads N] <run|session|test> <first volume> <dest>`
//! Prints each run's wall seconds, then the median, best and worst.

use std::path::Path;
use std::time::Instant;
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};

fn options(dest: &Path, threads: Option<usize>) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads,
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: false,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut runs, mut threads) = (5usize, None);
    let mut rest = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--runs" => runs = args.next().unwrap().parse().unwrap(),
            "--threads" => threads = Some(args.next().unwrap().parse().unwrap()),
            _ => rest.push(a),
        }
    }
    let [mode, first, dest] = rest.as_slice() else {
        panic!("usage: [--runs N] [--threads N] <run|session|test> <first volume> <dest>")
    };
    let (first, dest) = (Path::new(first), Path::new(dest));
    let opts = options(dest, threads);
    let mut times = Vec::new();
    for _ in 0..runs {
        let _ = std::fs::remove_dir_all(dest);
        std::fs::create_dir_all(dest).unwrap();
        let start = Instant::now();
        let (files, failed) = match mode.as_str() {
            "run" => {
                let summary = extract::run(first, &opts, |_| {}).unwrap();
                (summary.files, summary.errors.len() as u64)
            }
            "session" | "test" => {
                let mut session =
                    RarSession::open(first, None, RarSessionOptions { threads, ..RarSessionOptions::default() })
                        .unwrap();
                let all = session.select(|_| true).unwrap();
                let summary = if mode == "session" {
                    session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap()
                } else {
                    session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap()
                };
                (summary.files, summary.failed)
            }
            other => panic!("unknown mode {other}"),
        };
        let secs = start.elapsed().as_secs_f64();
        assert_eq!(failed, 0, "{mode}: failures");
        println!("{mode} {}: {files} files in {secs:.3} s", first.display());
        times.push(secs);
    }
    let _ = std::fs::remove_dir_all(dest);
    times.sort_by(f64::total_cmp);
    println!(
        "{mode}: median {:.3} s, best {:.3} s, worst {:.3} s over {runs} runs",
        times[times.len() / 2],
        times[0],
        times[times.len() - 1]
    );
}
