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

//! File-stamp granularity helpers for tests: the library's unit tests use it as `crate::test_stamps`, the integration
//! tests as `common::stamps` (the same file, through `#[path]`).
//!
//! zipfast notices that a file changed under it by comparing a stamp of its device, inode, size, mtime, ctime and mode
//! (`zip::create::unix::Stamp`). Where file times move on a coarse tick (Linux before multigrain timestamps, 6.12-era
//! kernels and earlier, and filesystems without them) a same-size rewrite within one tick leaves that stamp unchanged.
//! Tests that make a change and expect it to be refused call [`await_stamp_tick`] first, so the change lands in a later
//! tick and stays visible on every filesystem. A test whose point is the same-tick case itself checks
//! [`fine_grained_stamps`] and skips, with a printed note, where it is false.

use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Same-size rewrites the probe makes; each one must change the stamp.
pub(crate) const REWRITES: usize = 8;
/// Longest wait for a tick; coarse ticks are a few milliseconds (one jiffy), and 2 s for FAT-like filesystems.
const TICK_DEADLINE: Duration = Duration::from_secs(5);

static FINE: OnceLock<bool> = OnceLock::new();
/// Probes made for the cached answer (one per process).
pub(crate) static PROBES: AtomicUsize = AtomicUsize::new(0);

/// The stamp fields zipfast compares when it checks a regular file for a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    pub(crate) fn of(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

/// Whether a same-size rewrite always changes a file's stamp on the filesystem holding `dir`.
///
/// The first call probes `dir`: it writes a file there and rewrites it [`REWRITES`] times in quick succession with the
/// same size, checking that each rewrite changes the stamp. The answer is cached for the process (tests keep their
/// files under one temporary directory), so later calls return it without touching `dir`.
pub(crate) fn fine_grained_stamps(dir: &Path) -> bool {
    *FINE.get_or_init(|| {
        PROBES.fetch_add(1, Ordering::Relaxed);
        let fine = probe(dir).unwrap_or_else(|e| panic!("probing file stamps under {}: {e}", dir.display()));
        if !fine {
            eprintln!(
                "note: file times (probed under {}) move on a coarse tick, so a same-size rewrite within one tick is \
                 invisible to zipfast's change checks: change tests wait for the next tick",
                dir.display()
            );
        }
        fine
    })
}

pub(crate) fn probe(dir: &Path) -> io::Result<bool> {
    let file = tempfile::Builder::new().prefix(".zipfast-stamp-probe").tempfile_in(dir)?;
    let file = file.as_file();
    file.write_all_at(&[0; 64], 0)?;
    let mut last = Stamp::of(&file.metadata()?);
    for i in 1..=REWRITES {
        file.write_all_at(&[i as u8; 64], 0)?;
        let now = Stamp::of(&file.metadata()?);
        if now == last {
            return Ok(false);
        }
        last = now;
    }
    Ok(true)
}

/// Returns once the file times of `path`'s filesystem have moved past `path`'s current ctime, so that any change made
/// to `path` afterwards (a same-size rewrite, an mtime restore, a new link) shows in its stamp. Returns at once where
/// [`fine_grained_stamps`] holds.
pub(crate) fn await_stamp_tick(path: &Path) {
    let dir = path.parent().expect("a file path has a parent directory");
    await_tick(dir, || std::fs::metadata(path));
}

/// [`await_stamp_tick`] for an open `file` (one with no path to hand, such as a stage) on the filesystem holding `dir`.
pub(crate) fn await_file_stamp_tick(dir: &Path, file: &File) {
    await_tick(dir, || file.metadata());
}

fn await_tick(dir: &Path, target: impl FnOnce() -> io::Result<Metadata>) {
    if fine_grained_stamps(dir) {
        return;
    }
    let before = Stamp::of(&target().expect("stat the file to change")).changed;
    let tick = tempfile::Builder::new().prefix(".zipfast-stamp-tick").tempfile_in(dir).expect("create a tick file");
    let tick: &File = tick.as_file();
    let deadline = Instant::now() + TICK_DEADLINE;
    loop {
        tick.write_all_at(b"t", 0).expect("touch the tick file");
        if Stamp::of(&tick.metadata().expect("stat the tick file")).changed > before {
            return;
        }
        assert!(Instant::now() < deadline, "file times under {} did not move in {TICK_DEADLINE:?}", dir.display());
        std::thread::sleep(Duration::from_millis(1));
    }
}
