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

//! A PPMd model's memory. The stream sizes it, up to 256 MiB. It is one zeroed allocation, which the allocator
//! hands over as untouched pages: a header asking for a big model costs address space, not resident memory,
//! until the model writes to it.

#[derive(Default)]
pub(crate) struct Heap {
    mem: Vec<u8>,
}

impl Heap {
    /// `len` zero bytes, or None when the allocator can't supply them.
    pub(crate) fn new(len: usize) -> Option<Heap> {
        crate::ppmd8::zeroed_heap(len).map(|mem| Heap { mem })
    }

    #[cfg(test)]
    pub(crate) fn size(&self) -> usize {
        self.mem.len()
    }

    // Addresses are the model's 32-bit offsets. A value that runs past the heap's end is read and written a byte
    // at a time, its addresses wrapping as 32-bit ones do.

    /// Out of range reads give 0.
    #[inline]
    pub(crate) fn get(&self, at: u32) -> u32 {
        u32::from(self.mem.get(at as usize).copied().unwrap_or(0))
    }

    /// Out of range writes go nowhere.
    #[inline]
    pub(crate) fn set(&mut self, at: u32, v: u32) {
        if let Some(b) = self.mem.get_mut(at as usize) {
            *b = v as u8;
        }
    }

    /// Little-endian.
    #[inline]
    pub(crate) fn get16(&self, at: u32) -> u32 {
        let i = at as usize;
        match self.mem.get(i..i.wrapping_add(2)) {
            Some(s) => u32::from(u16::from_le_bytes([s[0], s[1]])),
            None => self.get(at) | self.get(at.wrapping_add(1)) << 8,
        }
    }

    /// Little-endian.
    #[inline]
    pub(crate) fn get32(&self, at: u32) -> u32 {
        let i = at as usize;
        match self.mem.get(i..i.wrapping_add(4)) {
            Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            None => self.get16(at) | self.get16(at.wrapping_add(2)) << 16,
        }
    }

    /// Little-endian; the low 16 bits of `v`.
    #[inline]
    pub(crate) fn set16(&mut self, at: u32, v: u32) {
        let i = at as usize;
        match self.mem.get_mut(i..i.wrapping_add(2)) {
            Some(s) => s.copy_from_slice(&(v as u16).to_le_bytes()),
            None => {
                self.set(at, v);
                self.set(at.wrapping_add(1), v >> 8);
            }
        }
    }

    /// Little-endian.
    #[inline]
    pub(crate) fn set32(&mut self, at: u32, v: u32) {
        let i = at as usize;
        match self.mem.get_mut(i..i.wrapping_add(4)) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => {
                self.set16(at, v);
                self.set16(at.wrapping_add(2), v >> 16);
            }
        }
    }

    /// The `n` bytes at `at`, when they're all in the heap.
    #[inline]
    pub(crate) fn slice(&self, at: u32, n: u32) -> Option<&[u8]> {
        let i = at as usize;
        self.mem.get(i..i.checked_add(n as usize)?)
    }

    /// Copies `n` bytes from `from` to `to` in increasing order, as a byte loop would.
    pub(crate) fn copy(&mut self, to: u32, from: u32, n: u32) {
        let (t, f, n_) = (to as usize, from as usize, n as usize);
        let len = self.mem.len();
        // a forward byte loop over overlapping ranges with `to` past `from` repeats bytes; copy_within doesn't
        let fits = |at: usize| at.checked_add(n_).is_some_and(|e| e <= len);
        if fits(f) && fits(t) && (t <= f || t - f >= n_) {
            self.mem.copy_within(f..f + n_, t);
            return;
        }
        for i in 0..n {
            let v = self.get(from.wrapping_add(i));
            self.set(to.wrapping_add(i), v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_past_the_end_give_zeros_and_writes_there_go_nowhere() {
        let mut h = Heap::new(128 << 20).unwrap();
        let end = h.size() as u32;
        assert_eq!(h.get(5), 0);
        h.set(5, 7);
        h.set(end - 1, 9);
        assert_eq!((h.get(5), h.get(end - 1), h.get(end)), (7, 9, 0));
        h.set(end, 1);
        assert_eq!(h.get(end), 0);
        h.set32(end - 2, 0x4433_2211);
        assert_eq!((h.get32(end - 2), h.get16(end - 1)), (0x2211, 0x22));
        h.set16(end - 1, 0xbbaa);
        assert_eq!(h.get32(end - 4), 0xaa11_0000);
        // past u32::MAX the addresses wrap to the heap's start
        h.set32(u32::MAX - 1, 0x1234_5678);
        assert_eq!((h.get32(u32::MAX - 1), h.get16(0)), (0x1234_0000, 0x1234));
        h.set32(100, 0xdead_beef);
        assert_eq!((h.get32(100), h.get16(102), h.get(103)), (0xdead_beef, 0xdead, 0xde));
    }

    #[test]
    fn copies_match_a_forward_byte_loop() {
        let mut h = Heap::new(64).unwrap();
        for i in 0..8 {
            h.set(i, i + 1);
        }
        h.copy(2, 0, 6);
        assert_eq!((0..8).map(|i| h.get(i)).collect::<Vec<_>>(), [1, 2, 1, 2, 1, 2, 1, 2]);
        h.copy(60, 0, 8);
        assert_eq!((60..64).map(|i| h.get(i)).collect::<Vec<_>>(), [1, 2, 1, 2]);
        h.copy(0, 4, 4);
        assert_eq!(h.get32(0), 0x0201_0201);
    }
}
