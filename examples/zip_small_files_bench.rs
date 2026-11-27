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

//! Per-member overhead on a many-small-files ZIP: RustyGet's `ReadSession` + `EncryptedReadContext::for_session` +
//! `read_with_context` loop, and the checked `run_with_policy` extraction (native, forced portable backend, and `Publication::Bulk`), against the legacy `zip::run`.
//!
//! `cargo run --release --example zip_small_files_bench -- <work dir> [files] [rounds] [session|policy|portable|bulk|test|legacy|all]`
//!
//! The archive (`files` members of 1-4 KiB, half Deflate and half stored) is written once into `<work dir>` and
//! reused. Every extraction goes to a fresh directory under `<work dir>` that is removed afterwards, so `<work dir>`
//! picks the filesystem under test. Each mode reports the best of `rounds` runs and the cost per member.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zipfast::extract::{Cancellation, Mode, Options, Overwrite};
use zipfast::zip::write::{
    DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions, WriterOptions,
    ZipStreamWriter,
};
use zipfast::zip::*;

fn generate(dir: &Path, files: usize) -> PathBuf {
    let path = dir.join(format!("small-{files}.zip"));
    if path.exists() {
        return path;
    }
    let tmp = dir.join(format!("small-{files}.zip.part"));
    let mut writer = ZipStreamWriter::new(std::fs::File::create(&tmp).unwrap(), WriterOptions::default()).unwrap();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..files {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = 1024 + (state % 3072) as usize;
        // Half-compressible text-like bytes.
        let data: Vec<u8> = (0..len).map(|j| b"abcdefghijklmnop"[(j ^ (state as usize >> (j % 32))) & 15]).collect();
        let name = format!("d{:03}/f{i:06}.txt", i % 200);
        let method = if i % 2 == 0 { Method::Deflate(DeflateLevel::new(6).unwrap()) } else { Method::Stored };
        writer
            .add_file(
                EntryOptions {
                    name: EntryName::Utf8(&name),
                    method,
                    modified: DosDateTime::default(),
                    extended_mtime: None,
                    permissions: Permissions::new(0o644).unwrap(),
                    comment: b"",
                },
                &mut data.as_slice(),
                InputLength::Exact(len as u64),
            )
            .unwrap();
    }
    writer.finish().unwrap().sink.sync_all().unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

fn options(dest: &Path, mode: Mode) -> Options {
    Options {
        mode,
        dest: dest.into(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
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
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// RustyGet's loop: one session, then a context, a selection and a checked read per member.
fn session(archive: &Path) -> u64 {
    let cancel = Cancellation::default();
    let mut session = ReadSession::open(archive).unwrap();
    let metadata = session.metadata();
    let mut bytes = 0u64;
    for ordinal in 0..metadata.len() {
        let id = metadata.entry_id(ordinal).unwrap();
        if metadata.entry(&id).unwrap().is_dir() {
            continue;
        }
        let mut context = EncryptedReadContext::for_session(
            &mut session,
            &id,
            None,
            ZipReadOutput::Callback,
            None,
            &Default::default(),
            &cancel,
        )
        .unwrap();
        session
            .select(&id, u64::MAX, cancel.clone())
            .unwrap()
            .read_with_context(None, &mut context, |b| {
                bytes += b.len() as u64;
                Ok(())
            })
            .unwrap();
    }
    bytes
}

fn policy(archive: &Path, dest: &Path, mode: Mode, storage: StagedStorage, publication: Publication) -> u64 {
    let mut overrides = EncryptedReadOverrides::default();
    overrides.staged_storage = storage;
    overrides.publication = publication;
    let report = run_with_policy(
        archive,
        &options(dest, mode),
        None,
        &Cancellation::default(),
        &overrides,
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.failed(), 0);
    report.files()
}

fn legacy(archive: &Path, dest: &Path) -> u64 {
    zipfast::zip::run(archive, &options(dest, Mode::Extract), |_| {}).unwrap().files
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let work = PathBuf::from(args.get(1).expect("usage: zip_small_files_bench <work dir> [files] [rounds] [mode]"));
    let files: usize = args.get(2).map_or(20_000, |s| s.parse().unwrap());
    let rounds: usize = args.get(3).map_or(3, |s| s.parse().unwrap());
    let which = args.get(4).map_or("all", String::as_str);
    std::fs::create_dir_all(&work).unwrap();
    let archive = generate(&work, files);
    let modes: &[&str] =
        if which == "all" { &["session", "policy", "portable", "bulk", "test", "legacy"] } else { &[which] };
    for &mode in modes {
        let mut best = Duration::MAX;
        for round in 0..rounds {
            let dest = work.join(format!("out-{mode}-{round}"));
            let _ = std::fs::remove_dir_all(&dest);
            std::fs::create_dir_all(&dest).unwrap();
            let start = Instant::now();
            let count = match mode {
                "session" => session(&archive),
                "policy" => policy(&archive, &dest, Mode::Extract, StagedStorage::Auto, Publication::Staged),
                "bulk" => policy(&archive, &dest, Mode::Extract, StagedStorage::Auto, Publication::Bulk),
                "portable" => policy(&archive, &dest, Mode::Extract, StagedStorage::PortableOnly, Publication::Staged),
                "test" => policy(&archive, &dest, Mode::Test, StagedStorage::Auto, Publication::Staged),
                "legacy" => legacy(&archive, &dest),
                other => panic!("unknown mode {other}"),
            };
            best = best.min(start.elapsed());
            std::hint::black_box(count);
            std::fs::remove_dir_all(&dest).unwrap();
        }
        println!(
            "{mode:>8}: {files} members  best {:8.1} ms  {:6.2} us/member",
            best.as_secs_f64() * 1e3,
            best.as_secs_f64() * 1e6 / files as f64
        );
    }
}
