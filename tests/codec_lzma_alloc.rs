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

//! Peak memory of `lzma_decode` without a stated size: the output may not overshoot `max_output`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};
use zipfast::codec::{LzmaError, lzma_decode};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        PEAK.fetch_max(live, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Count only the change, so that the peak is the largest capacity held rather than the copy in flight.
        if new_size > layout.size() {
            let live = LIVE.fetch_add(new_size - layout.size(), Ordering::SeqCst) + new_size - layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[test]
fn output_never_grows_far_past_the_cap() {
    // 32 MiB of zeros packs to a few KiB; raw LZMA2 with a 64 KiB dictionary.
    let data = vec![0u8; 32 << 20];
    let mut options = LzmaOptions::new_preset(1).unwrap();
    options.dict_size(1 << 16);
    let mut filters = Filters::new();
    filters.lzma2(&options);
    let mut stream = Stream::new_raw_encoder(&filters).unwrap();
    let mut packed = Vec::with_capacity(1 << 20);
    let mut consumed = 0;
    while stream.process_vec(&data[consumed..], &mut packed, Action::Finish).unwrap() != Status::StreamEnd {
        consumed = stream.total_in() as usize;
        packed.reserve(1 << 16);
    }
    drop((data, stream));

    // A 5 MiB cap: growing the output by doubling would reach 8 MiB of capacity.
    let cap = 5 << 20;
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    assert_eq!(lzma_decode(&[8], &packed, None, cap), Err(LzmaError::OutputLimit { limit: cap }));
    let peak = PEAK.load(Ordering::SeqCst) - base;
    // The output (at most cap + 1), the 64 KiB chunk and the decoder's state.
    assert!(peak < cap as usize + (1 << 20), "peak {peak} for a {cap}-byte cap");
}
