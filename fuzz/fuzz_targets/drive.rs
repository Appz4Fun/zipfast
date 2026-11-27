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

//! Shared driver: write the fuzz input as an archive (one or two volumes) into a RAM-backed scratch directory and
//! run every whole-archive entry point over it. Nothing may panic, hang or allocate without bound.
#![allow(dead_code)]
use std::path::{Path, PathBuf};
use zipfast::extract::{self, Mode, Options};

pub fn scratch() -> PathBuf {
    let base = if Path::new("/dev/shm").is_dir() { PathBuf::from("/dev/shm") } else { std::env::temp_dir() };
    let dir = base.join(format!("zf-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn options(dest: PathBuf, mode: Mode, bits: u8) -> Options {
    Options {
        mode,
        dest,
        overwrite: extract::Overwrite::Always,
        flatten: false,
        threads: Some(1 + usize::from(bits & 1)),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: bits & 2 != 0,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: bits & 4 != 0,
        replace_placed_links: false,
        keep_broken: bits & 8 != 0,
        attempt_continued_members: bits & 16 != 0,
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: bits & 32 != 0,
        seven_zip_strict: bits & 64 != 0,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

/// `data[0]`: option bits; `data[1]`: password choice (bit 0) and split (bit 1); then the archive. When split, the
/// next two bytes give the first volume's length.
pub fn drive(data: &[u8], magic: &[u8], names: (&str, &str)) {
    if data.len() < 4 {
        return;
    }
    let (bits, flags) = (data[0], data[1]);
    let mut body = data[2..].to_vec();
    if !magic.is_empty() && !body.starts_with(magic) {
        let mut v = magic.to_vec();
        v.extend_from_slice(&body);
        body = v;
    }
    let dir = scratch();
    let first = dir.join(names.0);
    let mut volumes = vec![(first.clone(), body.clone())];
    if flags & 2 != 0 && body.len() > 8 {
        let cut = (usize::from(body[magic.len() % body.len()]) * 257 + body.len() / 2) % body.len();
        let cut = cut.max(1);
        volumes = vec![(first.clone(), body[..cut].to_vec()), (dir.join(names.1), body[cut..].to_vec())];
    }
    for (p, b) in &volumes {
        let _ = std::fs::write(p, b);
    }
    let password = if flags & 1 != 0 { Some("pw") } else { None };
    let _ = extract::list_detailed(&first, password);
    let _ = extract::inspect_with_password(&first, password);
    let mode = if bits & 128 != 0 { Mode::Extract } else { Mode::Test };
    let dest = dir.join("out");
    let _ = extract::run_with_password(&first, &options(dest.clone(), mode, bits), password, |_| {});
    let _ = std::fs::remove_dir_all(&dest);
    for (p, _) in &volumes {
        let _ = std::fs::remove_file(p);
    }
}
