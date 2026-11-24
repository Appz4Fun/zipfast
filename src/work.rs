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

//! Work counters for tests that assert an algorithm stays linear without reading a clock.
//!
//! Each counter is thread-local (tests run side by side and must not see each other's work) and costs one
//! non-atomic add where it is bumped, always outside per-byte loops. Not a public interface.

use std::cell::Cell;

/// What is counted.
#[derive(Clone, Copy)]
pub enum Work {
    /// Steps of matching members across the first and last volume in `set_identity`: one per lookup or compare.
    SetIdentitySteps,
    /// Bytes of symbol names scanned or copied while reading an ar symbol table.
    ArNameBytes,
    /// Hard links a cpio reader handled while they waited for, or never got, their data.
    CpioWaitingLinks,
    /// Folders an ISO 9660 reader scheduled to be read.
    IsoFolders,
}

thread_local! {
    static COUNTS: [Cell<u64>; 4] = const { [Cell::new(0), Cell::new(0), Cell::new(0), Cell::new(0)] };
}

/// Adds `n` to a counter of the calling thread.
#[inline]
pub fn add(work: Work, n: u64) {
    COUNTS.with(|c| {
        let cell = &c[work as usize];
        cell.set(cell.get().wrapping_add(n));
    });
}

/// Returns the calling thread's count and resets it.
pub fn take(work: Work) -> u64 {
    COUNTS.with(|c| c[work as usize].replace(0))
}
