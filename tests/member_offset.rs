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

//! `RarMember::locate` and `MapMember::locate`: a stored member's inner offset as (volume, offset in it), on RAR4
//! and RAR 5.0 sets, checked byte for byte against what extraction writes.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::map::MemberMap;
use zipfast::rar5::session::{RarSession, RarSessionOptions};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
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
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// Every boundary offset and a stride through the member resolve to the byte extraction wrote, on both APIs; the
/// size itself and beyond resolve to nothing.
fn check(volumes: &[PathBuf], password: Option<&str>) {
    let tmp = tempfile::tempdir().unwrap();
    extract::run_with_password(&volumes[0], &options(tmp.path()), password, |_| {}).unwrap();
    let session = RarSession::open(&volumes[0], password, RarSessionOptions::default()).unwrap();
    let member = session.entries().next().unwrap();
    let gold = fs::read(tmp.path().join(member.name())).unwrap();
    let bytes: Vec<Vec<u8>> = volumes.iter().map(|p| fs::read(p).unwrap()).collect();
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let name = volumes[0].file_name().unwrap().to_str().unwrap();
    let map = MemberMap::from_memory(&refs, name, password).unwrap();
    let mapped = &map.members[0];
    assert!(member.parts().len() > 1, "a split member");

    let size = gold.len() as u64;
    let mut offsets: Vec<u64> = (0..size).step_by(97).collect();
    let mut start = 0;
    for part in member.parts() {
        start += part.packed_size();
        offsets.extend([start.saturating_sub(1), start]);
    }
    offsets.extend([0, size - 1]);
    for offset in offsets.into_iter().filter(|&o| o < size) {
        let (volume, at) = member.locate(offset).unwrap_or_else(|| panic!("offset {offset}"));
        assert_eq!(bytes[volume][at as usize], gold[offset as usize], "session, offset {offset}");
        assert_eq!(mapped.locate(offset), Some((volume as u32, at)), "map, offset {offset}");
    }
    // a part boundary is the first byte of the next part
    let first = member.parts().next().unwrap();
    let second = member.parts().nth(1).unwrap();
    assert_eq!(member.locate(first.packed_size()), Some((second.volume(), second.data_offset())));
    for past in [size, size + 1, u64::MAX] {
        assert_eq!(member.locate(past), None);
        assert_eq!(mapped.locate(past), None);
    }
}

#[test]
fn rar4_stored_split_member_offsets_resolve() {
    let names = ["mac-oldvol.rar", "mac-oldvol.r00", "mac-oldvol.r01", "mac-oldvol.r02"];
    check(&names.map(|n| fixture("rar4-archiver").join(n)), None);
}

#[test]
fn rar5_stored_split_member_offsets_resolve() {
    let tmp = tempfile::tempdir().unwrap();
    let gold: Vec<u8> = (0..10_000).map(|i| (i * 31 % 251) as u8).collect();
    let volumes: Vec<PathBuf> = common::volumes(&common::FileSpec::new("big.bin", &gold), 2600)
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| {
            let path = tmp.path().join(format!("big.part{}.rar", i + 1));
            fs::write(&path, bytes).unwrap();
            path
        })
        .collect();
    check(&volumes, None);
}

/// Encrypted members are refused: a byte of AES-CBC ciphertext needs its block and the one before it, which
/// `MapMember::packed_spans` describes.
#[test]
fn an_encrypted_stored_member_is_refused() {
    let names = ["win-encvol.rar", "win-encvol.r00", "win-encvol.r01", "win-encvol.r02"];
    let volumes = names.map(|n| fixture("rar4-archiver").join(n));
    let session = RarSession::open(&volumes[0], Some("testpw123"), RarSessionOptions::default()).unwrap();
    assert_eq!(session.entries().next().unwrap().locate(0), None);
    let bytes: Vec<Vec<u8>> = volumes.iter().map(|p| fs::read(p).unwrap()).collect();
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, "win-encvol.rar", Some("testpw123")).unwrap();
    assert_eq!(map.members[0].locate(0), None);
    assert!(map.members[0].packed_spans(0..1).is_some_and(|spans| !spans.is_empty()));
}

/// A compressed member has no byte-for-byte mapping.
#[test]
fn a_compressed_member_is_refused() {
    let path = fixture("rar4/solid.rar");
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.entries().next().unwrap().locate(0), None);
}
