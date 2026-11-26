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

//! The catalogue's default capacity is a floor that grows with the archive's headers (Prybar: a single-volume RAR
//! of 40,000 members failed to open with `CatalogueCapacity`, ~3.3 KB of catalogue per member, which UnRAR
//! extracts), and each member's header is kept once rather than again for the header listing.
mod common;
use common::*;
use std::{fs, path::Path};
use zipfast::error::{RarFailure, RarResource};
use zipfast::extract::{Mode, Options, Overwrite};
use zipfast::rar5::session::*;

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
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
        damaged_input: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// One single-volume archive at `dir/many.rar` holding a one-byte stored member under each of `names`.
fn write_archive(dir: &Path, names: &[String]) -> std::path::PathBuf {
    let specs: Vec<FileSpec<'_>> = names.iter().map(|name| FileSpec::new(name, b"x")).collect();
    let path = dir.join("many.rar");
    fs::write(&path, archive(&specs)).unwrap();
    path
}

#[test]
fn forty_thousand_members_with_long_names_open_and_extract_with_default_limits() {
    const MEMBERS: usize = 40_000;
    // two shared folders of 205 bytes each, so a name is 418 bytes, as in the reported archive's deep paths
    let folder = format!("{}/{}", "a".repeat(205), "b".repeat(205));
    let names: Vec<String> = (0..MEMBERS).map(|i| format!("{folder}/f{i:05}")).collect();
    let name_len = names[0].len() as u64;
    let dir = tempfile::tempdir().unwrap();
    let path = write_archive(dir.path(), &names);
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.entries().len(), MEMBERS);
    let usage = session.usage();
    // what a member retains: its slot in the member, part and header vectors, its decoded and stored name (each
    // kept once) and the name's owner; ~1.7 KB here, where it was ~3.3 KB with the header listing's own copy
    let per_member = usage.capacity / MEMBERS as u64;
    eprintln!("catalogue: {} bytes, {per_member} per member", usage.capacity);
    assert!(per_member <= 1024 + 2 * name_len, "{per_member} bytes per member");
    // every member checks out; writing 40,000 files takes ~14 s in a debug build, so every 40th is extracted
    let all = session.select(|_| true).unwrap();
    let tested = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((tested.files, tested.failed), (MEMBERS as u64, 0));
    let some = session.select(|member| member.ordinal() % 40 == 39).unwrap();
    let dest = dir.path().join("out");
    let summary = session.extract_selected(&some, &options(&dest), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (MEMBERS as u64 / 40, 0));
    assert_eq!(fs::read(dest.join(&names[MEMBERS - 1])).unwrap(), b"x");
}

#[test]
fn a_catalogue_past_the_default_floor_opens_and_an_explicit_capacity_stays_exact() {
    // ~150 MB of catalogue: past the 128 MiB floor, but well within what 160,000 header blocks justify
    const MEMBERS: usize = 160_000;
    let names: Vec<String> = (0..MEMBERS).map(|i| format!("d/f{i:06}")).collect();
    let dir = tempfile::tempdir().unwrap();
    let path = write_archive(dir.path(), &names);
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.entries().len(), MEMBERS);
    let usage = session.usage();
    assert!(usage.capacity > RarCatalogueLimits::DEFAULT_CAPACITY, "{usage:?}");
    let justified = usage.header_blocks * RarCatalogueLimits::CAPACITY_PER_BLOCK
        + usage.read_bytes * RarCatalogueLimits::CAPACITY_PER_HEADER_BYTE;
    assert!(usage.capacity <= justified, "{usage:?}");
    session.select(|_| true).unwrap();
    drop(session);

    // any value other than the default is an exact cap
    let mut options = RarSessionOptions::default();
    options.limits.capacity = RarCatalogueLimits::DEFAULT_CAPACITY - 1;
    let failure = RarSession::open(&path, None, options).err().unwrap();
    assert!(
        matches!(failure.failure.as_ref(), RarFailure::Limit { resource: RarResource::CatalogueCapacity, .. }),
        "{failure:?}"
    );
}
