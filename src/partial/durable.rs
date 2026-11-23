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

//! File syncs of persistent output, with the device cache flush deferred to the next anchor change.
//!
//! Every sync of an output, journal file or directory goes through [`sync`], and every anchor CAS first calls
//! [`barrier`]. Nothing durable is claimed except through an anchor, so the only point where earlier writes must be
//! on stable storage is just before the CAS that names them; between anchor changes a sync only has to move the
//! file's data and metadata to the device.
//!
//! On macOS `fsync(2)` does exactly that, and `F_FULLFSYNC` is `fsync` plus a flush of the drive's whole write
//! cache (fcntl(2): "Does the same thing as fsync(2) then asks the drive to flush all buffered data to the
//! permanent storage device"). So [`sync`] issues a plain `fsync` and remembers the file's device, and [`barrier`]
//! issues one `F_FULLFSYNC` per device synced since the last barrier, which makes every earlier `fsync` of that
//! device durable. A group commit that synced three journal files, the journal directory and the output then
//! costs one `F_FULLFSYNC` (two when the output and the state directory are on different devices) instead of
//! five. Ordering among the plain syncs does not matter, so no `F_BARRIERFSYNC` is needed either: whatever they
//! wrote is unanchored until the barrier, and recovery ignores unanchored records, pages and output bytes.
//!
//! Elsewhere `fsync` is already a device-durable sync, so [`sync`] is `File::sync_all` and [`barrier`] does
//! nothing.
use std::fs::File;
use std::sync::atomic::{AtomicU64, Ordering};

/// Device-durable syncs: `F_FULLFSYNC` on macOS, `fsync` elsewhere.
pub(super) static DURABLE: AtomicU64 = AtomicU64::new(0);
/// Plain `fsync`s on macOS whose flush was deferred to a barrier; always 0 elsewhere.
pub(super) static ORDERED: AtomicU64 = AtomicU64::new(0);

#[cfg(target_vendor = "apple")]
mod imp {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::sync::Mutex;

    /// One descriptor per device synced since the last barrier. The lock is held across the flushes, so a
    /// barrier returns only once every flush that covers its syncs has completed, whichever thread issued it.
    static PENDING: Mutex<Vec<(u64, File)>> = Mutex::new(Vec::new());

    fn full(file: &File) -> std::io::Result<()> {
        DURABLE.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        tests::HERE.with(|h| h.set((h.get().0 + 1, h.get().1)));
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    pub(in crate::partial) fn sync(file: &File) -> std::io::Result<()> {
        ORDERED.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        tests::HERE.with(|h| h.set((h.get().0, h.get().1 + 1)));
        if unsafe { libc::fsync(file.as_raw_fd()) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(test)]
        let seq = tests::synced();
        let device = file.metadata()?.dev();
        let mut pending = PENDING.lock().unwrap();
        if !pending.iter().any(|(d, _)| *d == device) {
            match file.try_clone() {
                Ok(held) => pending.push((device, held)),
                // Out of descriptors: flush now rather than defer.
                Err(_) => {
                    drop(pending);
                    full(file)?;
                    #[cfg(test)]
                    tests::flushed(device, seq + 1);
                    return Ok(());
                }
            }
        }
        #[cfg(test)]
        tests::remember(device, seq);
        Ok(())
    }
    pub(in crate::partial) fn barrier() -> std::io::Result<()> {
        let mut pending = PENDING.lock().unwrap();
        while let Some((device, file)) = pending.last() {
            #[cfg(test)]
            let upto = tests::now();
            full(file)?;
            #[cfg(test)]
            tests::flushed(*device, upto);
            let _ = device;
            pending.pop();
        }
        Ok(())
    }

    /// Bookkeeping that lets a test ask whether every sync this thread issued is covered by a completed flush.
    #[cfg(test)]
    pub(in crate::partial) mod tests {
        use std::collections::HashMap;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        static FLUSHED: Mutex<Option<HashMap<u64, u64>>> = Mutex::new(None);
        thread_local! {
            /// Device flushes and plain syncs issued on this thread.
            pub(in crate::partial) static HERE: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
            static MINE: std::cell::RefCell<Vec<(u64, u64)>> = const { std::cell::RefCell::new(Vec::new()) };
        }
        pub(super) fn synced() -> u64 {
            SEQ.fetch_add(1, Ordering::SeqCst)
        }
        pub(super) fn now() -> u64 {
            SEQ.load(Ordering::SeqCst)
        }
        pub(super) fn remember(device: u64, seq: u64) {
            MINE.with(|m| m.borrow_mut().push((device, seq)));
        }
        /// Every sync numbered below `upto` on `device` completed before this flush began.
        pub(super) fn flushed(device: u64, upto: u64) {
            let mut map = FLUSHED.lock().unwrap();
            let entry = map.get_or_insert_with(HashMap::new).entry(device).or_insert(0);
            *entry = (*entry).max(upto);
        }
        /// Syncs issued on this thread that no completed device flush covers yet.
        pub(in crate::partial) fn unflushed_here() -> usize {
            let map = FLUSHED.lock().unwrap();
            MINE.with(|m| {
                let mut mine = m.borrow_mut();
                mine.retain(|(device, seq)| map.as_ref().and_then(|f| f.get(device)).is_none_or(|upto| seq >= upto));
                mine.len()
            })
        }
    }
}

#[cfg(not(target_vendor = "apple"))]
mod imp {
    use super::*;
    pub(in crate::partial) fn sync(file: &File) -> std::io::Result<()> {
        DURABLE.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        tests::HERE.with(|h| h.set((h.get().0 + 1, h.get().1)));
        file.sync_all()
    }
    pub(in crate::partial) fn barrier() -> std::io::Result<()> {
        Ok(())
    }
    #[cfg(test)]
    pub(in crate::partial) mod tests {
        thread_local! {
            /// Device-durable syncs and deferred syncs (none here) issued on this thread.
            pub(in crate::partial) static HERE: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
        }
        /// Every sync is durable when it returns.
        pub(in crate::partial) fn unflushed_here() -> usize {
            0
        }
    }
}

#[cfg(test)]
pub(super) use imp::tests::{HERE, unflushed_here};
pub(super) use imp::{barrier, sync};
