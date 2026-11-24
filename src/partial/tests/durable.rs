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

use super::state::Fixture;
use crate::partial::*;
use crate::progressive::*;
use std::sync::{Arc, Mutex};

/// An in-memory anchor store that records, at each CAS, how many syncs of this thread no device flush covers.
#[derive(Default)]
struct Checking {
    value: Mutex<Option<StateAnchor>>,
    cas: Mutex<Vec<usize>>,
}
impl StateAnchorStore for Checking {
    fn current(&self, _: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        Ok(self.value.lock().unwrap().clone())
    }
    fn compare_exchange(&self, _: &MemberKey, expected: Option<&StateAnchor>, next: &StateAnchor) -> PartialResult<()> {
        self.cas.lock().unwrap().push(durable::unflushed_here());
        let mut value = self.value.lock().unwrap();
        if value.as_ref() != expected {
            return Err(err(PartialErrorKind::AnchorConflict));
        }
        *value = Some(next.clone());
        Ok(())
    }
}

// Catches an anchor CAS that runs while a sync it depends on is not device durable yet (on macOS, a plain fsync not
// yet covered by an F_FULLFSYNC), and the group commit paying a device flush per file again: through genesis, two
// group commits, a hole, a refill and a compaction, every CAS finds every earlier sync of the thread flushed, and
// the thread issues at most one device flush per anchor change (one device here).
#[test]
fn every_anchor_change_follows_one_device_flush_of_every_earlier_sync() {
    let f = Fixture::new();
    let store = Arc::new(Checking::default());
    let mut options = f.options(
        PartialLimits { group_commit_bytes: 8, ..Default::default() },
        ProgressiveLimits { read_chunk: 4, ..Default::default() },
        SessionControl::default(),
    );
    options.anchors = store.clone();
    let (flushes, syncs) = durable::HERE.with(|h| h.get());
    let core = PartialCore::create(f.spec(), f.checks.clone(), options).unwrap();
    for at in (0..8).step_by(4) {
        core.write_original(at, &b"abcdefghijklmnop"[at as usize..at as usize + 4]).unwrap();
    }
    core.compact().unwrap();
    for at in (8..16).step_by(4) {
        core.write_original(at, &b"abcdefghijklmnop"[at as usize..at as usize + 4]).unwrap();
    }
    core.state().unwrap();
    let cas = store.cas.lock().unwrap().clone();
    assert!(cas.len() >= 7, "genesis, two groups and a compaction: {cas:?}");
    assert!(cas.iter().all(|&n| n == 0), "a CAS ran before its syncs were flushed: {cas:?}");
    let (flushes, syncs) = durable::HERE.with(|h| (h.get().0 - flushes, h.get().1 - syncs));
    // Elsewhere every sync is a device-durable fsync and there is nothing to defer.
    if cfg!(target_vendor = "apple") {
        assert!(flushes <= cas.len() as u64, "{flushes} device flushes for {} anchor changes", cas.len());
        assert!(syncs >= 2 * cas.len() as u64, "{syncs} deferred syncs for {} anchor changes", cas.len());
    }
}

// Catches a device whose flush failed staying pending for, or blocking, members that never synced on it, and a
// barrier skipping a device whose last flush failed: a barrier over files of a device with nothing unflushed issues
// no flush, and a sync newer than every flush is flushed by the next barrier that holds that device.
#[cfg(target_vendor = "apple")]
#[test]
fn a_barrier_flushes_only_devices_of_its_files_with_unflushed_syncs() {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join("f")).unwrap();
    durable::barrier(&[&file]).unwrap();
    let before = durable::HERE.with(|h| h.get().0);
    durable::barrier(&[&file, &file]).unwrap();
    // Other tests may sync on this device meanwhile; then one flush is due, never more.
    assert!(durable::HERE.with(|h| h.get().0) - before <= 1);
    durable::sync(&file).unwrap();
    assert!(durable::unflushed_here() > 0);
    durable::barrier(&[]).unwrap();
    assert!(durable::unflushed_here() > 0, "a barrier without the device's files leaves it alone");
    durable::barrier(&[&file]).unwrap();
    assert_eq!(durable::unflushed_here(), 0);
}
