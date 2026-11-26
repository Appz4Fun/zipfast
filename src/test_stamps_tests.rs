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

//! Tests for the file-stamp granularity helpers.

use crate::test_stamps::*;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::Ordering;

#[test]
fn answer_is_cached_for_the_process() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let first = fine_grained_stamps(a.path());
    assert_eq!(fine_grained_stamps(b.path()), first);
    assert_eq!(fine_grained_stamps(a.path()), first);
    assert_eq!(PROBES.load(Ordering::Relaxed), 1, "the answer is probed once per process");
    assert_eq!(std::fs::read_dir(a.path()).unwrap().count(), 0, "the probe removes its file");
}

// APFS keeps nanosecond file times, and so do Linux kernels with multigrain timestamps (6.13 on ext4, xfs,
// btrfs and tmpfs); 6.12-era Linux hosts move on a coarse tick, so only macOS asserts the answer.
#[cfg(target_os = "macos")]
#[test]
fn macos_file_times_are_fine_grained() {
    let dir = tempfile::tempdir().unwrap();
    assert!(fine_grained_stamps(dir.path()));
    assert!(probe(dir.path()).unwrap());
}

#[test]
fn same_size_rewrite_after_the_tick_changes_the_stamp() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, [0; 64]).unwrap();
    for i in 1..=REWRITES {
        let before = Stamp::of(&std::fs::metadata(&path).unwrap());
        let file = File::options().write(true).open(&path).unwrap();
        if i % 2 == 0 {
            await_stamp_tick(&path);
        } else {
            await_file_stamp_tick(dir.path(), &file);
        }
        file.write_all_at(&[i as u8; 64], 0).unwrap();
        assert_ne!(Stamp::of(&std::fs::metadata(&path).unwrap()), before, "rewrite {i}");
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "tick files are removed");
}
