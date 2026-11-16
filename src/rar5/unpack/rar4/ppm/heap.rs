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

//! A PPMd model's memory. The stream sizes it, up to 256 MiB, but only what the model writes is kept: pages come
//! as they're first written, so a header asking for a big model costs nothing until it's used.

const PAGE_BITS: u32 = 16;
const PAGE: usize = 1 << PAGE_BITS;

#[derive(Default, Clone)]
pub(crate) struct Heap {
    len: usize,
    pages: Vec<Option<Box<[u8]>>>,
    kept: usize,
}

impl Heap {
    /// `len` zero bytes, none of them kept yet
    pub(crate) fn new(len: usize) -> Heap {
        Heap { len, pages: (0..len.div_ceil(PAGE)).map(|_| None).collect(), kept: 0 }
    }

    #[cfg(test)]
    pub(crate) fn size(&self) -> usize {
        self.len
    }

    /// Out of range reads give 0.
    pub(crate) fn get(&self, at: usize) -> u8 {
        match self.pages.get(at >> PAGE_BITS) {
            Some(Some(page)) if at < self.len => page[at & (PAGE - 1)],
            _ => 0,
        }
    }

    /// Out of range writes go nowhere.
    pub(crate) fn set(&mut self, at: usize, v: u8) {
        if at >= self.len {
            return;
        }
        let slot = &mut self.pages[at >> PAGE_BITS];
        if slot.is_none() {
            // a page never written reads as zeros already
            if v == 0 {
                return;
            }
            self.kept += PAGE;
            *slot = Some(vec![0; PAGE].into_boxed_slice());
        }
        if let Some(page) = slot {
            page[at & (PAGE - 1)] = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_what_is_written_and_honors_models_past_64_mib() {
        let mut h = Heap::new(128 << 20);
        assert_eq!(h.get(5), 0);
        h.set(5, 0);
        assert_eq!(h.kept, 0);
        h.set(5, 7);
        h.set(h.size() - 1, 9);
        assert_eq!((h.get(5), h.get(h.size() - 1), h.get(h.size()), h.kept), (7, 9, 0, 2 * PAGE));
        h.set(h.size(), 1);
        let past_64_mib = (64 << 20) / PAGE + 4;
        for page in 0..past_64_mib {
            h.set(page * PAGE + 1, 0x5a);
        }
        assert_eq!(h.get((past_64_mib - 1) * PAGE + 1), 0x5a);
        assert_eq!(h.kept, (past_64_mib + 1) * PAGE);
    }
}
