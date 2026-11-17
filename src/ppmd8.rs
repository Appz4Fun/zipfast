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

//! PPMd variant I revision 1 (PPMd8), as ZIP method 98 stores it: Dmitry Shkarin's model with its own memory
//! allocator and Dmitry Subbotin's carryless range coder. Written from 7-Zip's public-domain `Ppmd8.c` and
//! `Ppmd8Dec.c` (without the FREEZE restore method, which 7-Zip leaves out too).
//!
//! The model's choices depend on when its memory runs out, so the allocator is the original's, over one byte heap
//! with 12-byte units and 32-bit offsets for pointers (0 is null), laid out little-endian as 7-Zip lays it out on
//! little-endian machines. Every heap access is checked: an access outside the heap marks the model broken and the
//! next symbol fails, instead of panicking.
#![allow(clippy::needless_range_loop, reason = "kept close to the original's indexed loops")]

/// The smallest and largest model orders.
pub(crate) const MIN_ORDER: u32 = 2;
pub(crate) const MAX_ORDER: u32 = 16;
/// The restore methods: start over, or cut the model back. 7-Zip refuses FREEZE (2).
pub(crate) const RESTORE_RESTART: u32 = 0;
pub(crate) const RESTORE_CUT_OFF: u32 = 1;

const MAX_FREQ: u32 = 124;
const UNIT_SIZE: u32 = 12;
const N_INDEXES: usize = 38;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const BIN_SCALE: u32 = 1 << (INT_BITS + PERIOD_BITS);
const EMPTY_NODE: u32 = 0xFFFF_FFFF;
const K_TOP: u32 = 1 << 24;
const K_BOT: u32 = 1 << 15;
const FLAG_RESCALED: u8 = 1 << 2;
const FLAG_PREV_HIGH: u8 = 1 << 4;
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const INIT_BIN_ESC: [u16; 8] = [0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051];

/// What [`Ppmd8::decode_symbol`] found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Symbol {
    Byte(u8),
    /// the end marker
    End,
    /// damaged data
    Error,
}

/// The input bytes, one at a time. Past the end it gives 0 and remembers that it ran out (7-Zip's `Extra`).
pub(crate) trait ByteIn {
    fn byte(&mut self) -> u8;
}

#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

/// A SEE context: one of `see`, or the dummy one.
#[derive(Clone, Copy)]
enum SeeRef {
    Dummy,
    At(usize, usize),
}

#[inline]
fn hi_bits_prepare(sym: u32) -> u32 {
    sym + 0xC0
}
#[inline]
fn hi_bits_3(flags: u32) -> u32 {
    (flags >> (8 - 3)) & (1 << 3)
}
#[inline]
fn hi_bits_4(flags: u32) -> u32 {
    (flags >> (8 - 4)) & (1 << 4)
}
#[inline]
fn hi_flag_3(sym: u32) -> u8 {
    hi_bits_3(hi_bits_prepare(sym)) as u8
}
#[inline]
fn hi_flag_4(sym: u32) -> u8 {
    hi_bits_4(hi_bits_prepare(sym)) as u8
}

/// `size` zero bytes, or None when the allocator can't supply them. The allocator hands over zeroed pages
/// without the decoder touching each one, so a header that asks for 256 MiB in front of a few bytes of garbage costs
/// address space, not resident memory.
fn zeroed_heap(size: usize) -> Option<Vec<u8>> {
    if size == 0 {
        return Some(Vec::new());
    }
    let layout = std::alloc::Layout::array::<u8>(size).ok()?;
    // SAFETY: the layout is nonzero in size and passed its size check.
    let allocation = unsafe { std::alloc::alloc_zeroed(layout) };
    if allocation.is_null() {
        return None;
    }
    // SAFETY: the global allocator returned `size` initialized bytes with u8 alignment; the Vec frees them with
    // the same layout.
    Some(unsafe { Vec::from_raw_parts(allocation, size, size) })
}

pub(crate) struct Ppmd8 {
    heap: Vec<u8>,
    /// set when a heap access fell outside it: the stream is damaged (or the port wrong); decoding stops
    broken: bool,
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    restore_method: u32,
    run_length: i32,
    init_rl: i32,
    size: u32,
    glue_count: u32,
    align_offset: u32,
    lo_unit: u32,
    hi_unit: u32,
    text: u32,
    units_start: u32,
    range: u32,
    code: u32,
    low: u32,
    indx2units: [u8; N_INDEXES + 2],
    units2indx: [u8; 128],
    free_list: [u32; N_INDEXES],
    stamps: [u32; N_INDEXES],
    ns2bsindx: [u8; 256],
    ns2indx: [u8; 260],
    dummy_see: See,
    see: [[See; 32]; 24],
    bin_summ: [[u16; 64]; 25],
    /// tests: how often the model ran out of memory and restarted or was cut back
    #[cfg(test)]
    restores: (u32, u32),
}

impl Ppmd8 {
    /// A model of `size` bytes (the caller has checked it against its limits), for `max_order` and
    /// `restore_method`. None when the memory can't be had.
    pub(crate) fn new(size: u32, max_order: u32, restore_method: u32) -> Option<Box<Self>> {
        let align_offset = 4u32.wrapping_sub(size) & 3;
        let total = (align_offset + size) as usize;
        let heap = zeroed_heap(total)?;
        let mut p = Box::new(Ppmd8 {
            heap,
            broken: false,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order,
            restore_method,
            run_length: 0,
            init_rl: 0,
            size,
            glue_count: 0,
            align_offset,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            range: 0,
            code: 0,
            low: 0,
            indx2units: [0; N_INDEXES + 2],
            units2indx: [0; 128],
            free_list: [0; N_INDEXES],
            stamps: [0; N_INDEXES],
            ns2bsindx: [0; 256],
            ns2indx: [0; 260],
            dummy_see: See::default(),
            see: [[See::default(); 32]; 24],
            bin_summ: [[0; 64]; 25],
            #[cfg(test)]
            restores: (0, 0),
        });
        p.construct();
        p.restart_model();
        Some(p)
    }

    fn construct(&mut self) {
        let mut k = 0usize;
        for i in 0..N_INDEXES {
            let mut step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            loop {
                self.units2indx[k] = i as u8;
                k += 1;
                step -= 1;
                if step == 0 {
                    break;
                }
            }
            self.indx2units[i] = k as u8;
        }
        self.ns2bsindx[0] = 0;
        self.ns2bsindx[1] = 2;
        self.ns2bsindx[2..11].fill(4);
        self.ns2bsindx[11..].fill(6);
        let mut i = 0usize;
        while i < 5 {
            self.ns2indx[i] = i as u8;
            i += 1;
        }
        let (mut m, mut k) = (i as u32, 1u32);
        while i < 260 {
            self.ns2indx[i] = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 4;
            }
            i += 1;
        }
    }

    // ---- checked heap access ----

    #[inline]
    fn b(&mut self, at: u32) -> u8 {
        match self.heap.get(at as usize) {
            Some(&v) => v,
            None => {
                self.broken = true;
                0
            }
        }
    }
    #[inline]
    fn set_b(&mut self, at: u32, v: u8) {
        match self.heap.get_mut(at as usize) {
            Some(slot) => *slot = v,
            None => self.broken = true,
        }
    }
    #[inline]
    fn u16(&mut self, at: u32) -> u16 {
        let at = at as usize;
        match self.heap.get(at..at + 2) {
            Some(s) => u16::from_le_bytes([s[0], s[1]]),
            None => {
                self.broken = true;
                0
            }
        }
    }
    #[inline]
    fn set_u16(&mut self, at: u32, v: u16) {
        let at = at as usize;
        match self.heap.get_mut(at..at + 2) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.broken = true,
        }
    }
    #[inline]
    fn u32(&mut self, at: u32) -> u32 {
        let at = at as usize;
        match self.heap.get(at..at + 4) {
            Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            None => {
                self.broken = true;
                0
            }
        }
    }
    #[inline]
    fn set_u32(&mut self, at: u32, v: u32) {
        let at = at as usize;
        match self.heap.get_mut(at..at + 4) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.broken = true,
        }
    }
    /// Copies `units` 12-byte units from `src` to `dest`.
    fn copy_units(&mut self, dest: u32, src: u32, units: u32) {
        let (d, s, n) = (dest as usize, src as usize, (units * UNIT_SIZE) as usize);
        if s + n <= self.heap.len() && d + n <= self.heap.len() {
            self.heap.copy_within(s..s + n, d);
        } else {
            self.broken = true;
        }
    }

    // States (6 bytes): symbol, freq, successor (u32 in two halves).
    #[inline]
    fn st_sym(&mut self, s: u32) -> u32 {
        u32::from(self.b(s))
    }
    #[inline]
    fn st_freq(&mut self, s: u32) -> u32 {
        u32::from(self.b(s + 1))
    }
    #[inline]
    fn set_st_freq(&mut self, s: u32, v: u32) {
        self.set_b(s + 1, v as u8)
    }
    #[inline]
    fn succ(&mut self, s: u32) -> u32 {
        self.u32(s + 2)
    }
    #[inline]
    fn set_succ(&mut self, s: u32, v: u32) {
        self.set_u32(s + 2, v)
    }
    fn copy_state(&mut self, dest: u32, src: u32) {
        for i in 0..6 {
            let v = self.b(src + i);
            self.set_b(dest + i, v);
        }
    }
    fn swap_states(&mut self, a: u32, b: u32) {
        for i in 0..6 {
            let (x, y) = (self.b(a + i), self.b(b + i));
            self.set_b(a + i, y);
            self.set_b(b + i, x);
        }
    }

    // Contexts (12 bytes): NumStats, Flags, SummFreq (or the one state's symbol and freq), Stats (or the one
    // state's successor), Suffix.
    #[inline]
    fn num_stats(&mut self, c: u32) -> u32 {
        u32::from(self.b(c))
    }
    #[inline]
    fn set_num_stats(&mut self, c: u32, v: u32) {
        self.set_b(c, v as u8)
    }
    #[inline]
    fn flags(&mut self, c: u32) -> u8 {
        self.b(c + 1)
    }
    #[inline]
    fn set_flags(&mut self, c: u32, v: u8) {
        self.set_b(c + 1, v)
    }
    #[inline]
    fn summ_freq(&mut self, c: u32) -> u32 {
        u32::from(self.u16(c + 2))
    }
    #[inline]
    fn set_summ_freq(&mut self, c: u32, v: u32) {
        self.set_u16(c + 2, v as u16)
    }
    #[inline]
    fn stats(&mut self, c: u32) -> u32 {
        self.u32(c + 4)
    }
    #[inline]
    fn set_stats(&mut self, c: u32, v: u32) {
        self.set_u32(c + 4, v)
    }
    #[inline]
    fn suffix(&mut self, c: u32) -> u32 {
        self.u32(c + 8)
    }
    #[inline]
    fn set_suffix(&mut self, c: u32, v: u32) {
        self.set_u32(c + 8, v)
    }
    /// The one state of a binary context, stored at byte 2.
    #[inline]
    fn one_state(c: u32) -> u32 {
        c + 2
    }

    // Free-list nodes (12 bytes): Stamp, Next, NU.
    #[inline]
    fn i2u(&self, indx: usize) -> u32 {
        u32::from(self.indx2units[indx])
    }
    #[inline]
    fn u2i(&self, nu: u32) -> usize {
        match self.units2indx.get((nu as usize).wrapping_sub(1)) {
            Some(&i) => usize::from(i),
            None => N_INDEXES - 1,
        }
    }
    #[inline]
    fn u2b(nu: u32) -> u32 {
        nu * UNIT_SIZE
    }

    fn insert_node(&mut self, node: u32, indx: usize) {
        self.set_u32(node, EMPTY_NODE);
        let next = self.free_list[indx];
        self.set_u32(node + 4, next);
        let nu = self.i2u(indx);
        self.set_u32(node + 8, nu);
        self.free_list[indx] = node;
        self.stamps[indx] = self.stamps[indx].wrapping_add(1);
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        self.free_list[indx] = self.u32(node + 4);
        self.stamps[indx] = self.stamps[indx].wrapping_sub(1);
        node
    }

    fn split_block(&mut self, ptr: u32, old_indx: usize, new_indx: usize) {
        let nu = self.i2u(old_indx) - self.i2u(new_indx);
        let ptr = ptr + Self::u2b(self.i2u(new_indx));
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i -= 1;
            let k = self.i2u(i);
            self.insert_node(ptr + Self::u2b(k), (nu - k - 1) as usize);
        }
        self.insert_node(ptr, i);
    }

    fn glue_free_blocks(&mut self) {
        self.glue_count = 1 << 13;
        self.stamps = [0; N_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.set_u32(self.lo_unit, 0);
        }
        // Glue free blocks into one chain, `n`, linked through Next; `prev` is where the next link goes (None: n).
        let mut n = 0u32;
        let mut prev: Option<u32> = None;
        for i in 0..N_INDEXES {
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                let node = next;
                let mut nu = self.u32(node + 8);
                match prev {
                    None => n = next,
                    Some(at) => self.set_u32(at, next),
                }
                next = self.u32(node + 4);
                if nu != 0 {
                    prev = Some(node + 4);
                    loop {
                        let node2 = node.wrapping_add(nu.wrapping_mul(UNIT_SIZE));
                        if self.u32(node2) != EMPTY_NODE || self.broken {
                            break;
                        }
                        nu = nu.wrapping_add(self.u32(node2 + 8));
                        self.set_u32(node2 + 8, 0);
                        self.set_u32(node + 8, nu);
                    }
                }
            }
        }
        match prev {
            None => n = 0,
            Some(at) => self.set_u32(at, 0),
        }
        // Fill the free lists again.
        while n != 0 && !self.broken {
            let mut node = n;
            let mut nu = self.u32(node + 8);
            n = self.u32(node + 4);
            if nu == 0 {
                continue;
            }
            while nu > 128 {
                self.insert_node(node, N_INDEXES - 1);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i -= 1;
                let k = self.i2u(i);
                self.insert_node(node + k * UNIT_SIZE, (nu - k - 1) as usize);
            }
            self.insert_node(node, i);
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[indx] != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == N_INDEXES {
                let num_bytes = Self::u2b(self.i2u(indx));
                let us = self.units_start;
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if us.wrapping_sub(self.text) > num_bytes {
                    self.units_start = us - num_bytes;
                    self.units_start
                } else {
                    0
                };
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let block = self.remove_node(i);
        self.split_block(block, i, indx);
        block
    }

    fn alloc_units(&mut self, indx: usize) -> u32 {
        if self.free_list[indx] != 0 {
            return self.remove_node(indx);
        }
        let num_bytes = Self::u2b(self.i2u(indx));
        let lo = self.lo_unit;
        if self.hi_unit.wrapping_sub(lo) >= num_bytes {
            self.lo_unit = lo + num_bytes;
            return lo;
        }
        self.alloc_units_rare(indx)
    }

    fn shrink_units(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.free_list[i1] != 0 {
            let ptr = self.remove_node(i1);
            self.copy_units(ptr, old_ptr, new_nu);
            self.insert_node(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }

    fn free_units(&mut self, ptr: u32, nu: u32) {
        let i = self.u2i(nu);
        self.insert_node(ptr, i);
    }

    fn special_free_unit(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert_node(ptr, 0);
        } else {
            self.units_start += UNIT_SIZE;
        }
    }

    fn expand_text_area(&mut self) {
        let mut count = [0u32; N_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.set_u32(self.lo_unit, 0);
        }
        let mut node = self.units_start;
        while self.u32(node) == EMPTY_NODE && !self.broken {
            let nu = self.u32(node + 8);
            self.set_u32(node, 0);
            let i = self.u2i(nu);
            count[i] += 1;
            node = node.wrapping_add(nu.wrapping_mul(UNIT_SIZE));
        }
        self.units_start = node;
        for i in 0..N_INDEXES {
            let mut cnt = count[i];
            if cnt == 0 {
                continue;
            }
            // `prev`: None is the list head itself
            let mut prev: Option<u32> = None;
            let mut n = self.free_list[i];
            self.stamps[i] = self.stamps[i].wrapping_sub(cnt);
            loop {
                if self.broken {
                    return;
                }
                let node = n;
                n = self.u32(node + 4);
                if self.u32(node) != 0 {
                    prev = Some(node + 4);
                    continue;
                }
                match prev {
                    None => self.free_list[i] = n,
                    Some(at) => self.set_u32(at, n),
                }
                cnt -= 1;
                if cnt == 0 {
                    break;
                }
            }
        }
    }

    fn restart_model(&mut self) {
        self.free_list = [0; N_INDEXES];
        self.stamps = [0; N_INDEXES];
        self.text = self.align_offset;
        self.hi_unit = self.text + self.size;
        self.lo_unit = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.units_start = self.lo_unit;
        self.glue_count = 0;
        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        let mut s = self.lo_unit;
        self.lo_unit += Self::u2b(256 / 2);
        self.max_context = mc;
        self.min_context = mc;
        self.found_state = s;
        self.set_flags(mc, 0);
        self.set_num_stats(mc, 255);
        self.set_summ_freq(mc, 256 + 1);
        self.set_stats(mc, s);
        self.set_suffix(mc, 0);
        for i in 0..256u32 {
            self.set_b(s, i as u8);
            self.set_b(s + 1, 1);
            self.set_succ(s, 0);
            s += 6;
        }

        let mut i = 0usize;
        for m in 0..25usize {
            while usize::from(self.ns2indx[i]) == m {
                i += 1;
            }
            for k in 0..8 {
                let val = (BIN_SCALE - u32::from(INIT_BIN_ESC[k]) / (i as u32 + 1)) as u16;
                let mut r = 0;
                while r < 64 {
                    self.bin_summ[m][k + r] = val;
                    r += 8;
                }
            }
        }
        let mut i = 0usize;
        for m in 0..24usize {
            while usize::from(self.ns2indx[i + 3]) == m + 3 {
                i += 1;
            }
            let summ = ((2 * i as u32 + 5) << (PERIOD_BITS - 4)) as u16;
            for k in 0..32 {
                self.see[m][k] = See { summ, shift: (PERIOD_BITS - 4) as u8, count: 7 };
            }
        }
        self.dummy_see = See { summ: 0, shift: PERIOD_BITS as u8, count: 64 };
    }

    fn refresh(&mut self, ctx: u32, old_nu: u32, scale: u32) {
        let mut i = self.num_stats(ctx);
        let stats = self.stats(ctx);
        let mut s = self.shrink_units(stats, old_nu, (i + 2) >> 1);
        self.set_stats(ctx, s);
        let scale = scale | u32::from(self.summ_freq(ctx) >= 1 << 15);
        let mut flags = hi_bits_prepare(self.st_sym(s));
        let mut freq = self.st_freq(s);
        let mut esc_freq = self.summ_freq(ctx).wrapping_sub(freq);
        freq = (freq + scale) >> scale;
        let mut sum_freq = freq;
        self.set_st_freq(s, freq);
        loop {
            s += 6;
            let mut freq = self.st_freq(s);
            esc_freq = esc_freq.wrapping_sub(freq);
            freq = (freq + scale) >> scale;
            sum_freq += freq;
            self.set_st_freq(s, freq);
            flags |= hi_bits_prepare(self.st_sym(s));
            i -= 1;
            if i == 0 || self.broken {
                break;
            }
        }
        self.set_summ_freq(ctx, sum_freq.wrapping_add(esc_freq.wrapping_add(scale) >> scale));
        let f = self.flags(ctx);
        let keep = FLAG_PREV_HIGH + FLAG_RESCALED * scale as u8;
        self.set_flags(ctx, (f & keep).wrapping_add(hi_bits_3(flags) as u8));
    }

    fn cut_off(&mut self, ctx: u32, order: u32) -> u32 {
        if self.broken {
            return 0;
        }
        let mut ns = self.num_stats(ctx) as i32;
        if ns == 0 {
            let s = Self::one_state(ctx);
            let mut successor = self.succ(s);
            if successor >= self.units_start {
                successor = if order < self.max_order { self.cut_off(successor, order + 1) } else { 0 };
                self.set_succ(s, successor);
                if successor != 0 || order <= 9 {
                    return ctx;
                }
            }
            self.special_free_unit(ctx);
            return 0;
        }
        let nu = (ns as u32 + 2) >> 1;
        let indx = self.u2i(nu);
        let mut stats = self.stats(ctx);
        if stats.wrapping_sub(self.units_start) <= (1 << 14) && stats <= self.free_list[indx] {
            let ptr = self.remove_node(indx);
            self.set_stats(ctx, ptr);
            self.copy_units(ptr, stats, nu);
            if stats != self.units_start {
                self.insert_node(stats, indx);
            } else {
                self.units_start += Self::u2b(self.i2u(indx));
            }
            stats = ptr;
        }
        let mut s = stats + ns as u32 * 6;
        loop {
            let successor = self.succ(s);
            if successor < self.units_start {
                let s2 = stats + ns as u32 * 6;
                ns -= 1;
                if order != 0 {
                    if s != s2 {
                        self.copy_state(s, s2);
                    }
                } else {
                    self.swap_states(s, s2);
                    self.set_succ(s2, 0);
                }
            } else if order < self.max_order {
                let cut = self.cut_off(successor, order + 1);
                self.set_succ(s, cut);
            } else {
                self.set_succ(s, 0);
            }
            if s == stats || self.broken {
                break;
            }
            s -= 6;
        }
        if ns != self.num_stats(ctx) as i32 && order != 0 {
            if ns < 0 {
                self.free_units(stats, nu);
                self.special_free_unit(ctx);
                return 0;
            }
            self.set_num_stats(ctx, ns as u32);
            if ns == 0 {
                let sym = self.st_sym(stats);
                let f = self.flags(ctx);
                self.set_flags(ctx, (f & FLAG_PREV_HIGH).wrapping_add(hi_flag_3(sym)));
                self.set_b(ctx + 2, sym as u8);
                let freq = self.st_freq(stats);
                self.set_b(ctx + 3, ((freq + 11) >> 3) as u8);
                let succ = self.succ(stats);
                self.set_u32(ctx + 4, succ);
                self.free_units(stats, nu);
            } else {
                let summ = self.summ_freq(ctx);
                self.refresh(ctx, nu, u32::from(summ > 16 * ns as u32));
            }
        }
        ctx
    }

    fn used_memory(&self) -> u32 {
        let mut v = 0u32;
        for i in 0..N_INDEXES {
            v = v.wrapping_add(self.stamps[i].wrapping_mul(self.i2u(i)));
        }
        self.size
            .wrapping_sub(self.hi_unit.wrapping_sub(self.lo_unit))
            .wrapping_sub(self.units_start.wrapping_sub(self.text))
            .wrapping_sub(Self::u2b(v))
    }

    fn restore_model(&mut self, ctx_error: u32) {
        self.text = self.align_offset;
        let mut c = self.max_context;
        while c != ctx_error && !self.broken {
            let ns = self.num_stats(c).wrapping_sub(1) & 0xFF;
            self.set_num_stats(c, ns);
            if ns == 0 {
                let s = self.stats(c);
                let sym = self.st_sym(s);
                let f = self.flags(c);
                self.set_flags(c, (f & FLAG_PREV_HIGH).wrapping_add(hi_flag_3(sym)));
                self.set_b(c + 2, sym as u8);
                let freq = self.st_freq(s);
                self.set_b(c + 3, ((freq + 11) >> 3) as u8);
                let succ = self.succ(s);
                self.set_u32(c + 4, succ);
                self.special_free_unit(s);
            } else {
                self.refresh(c, (ns + 3) >> 1, 0);
            }
            c = self.suffix(c);
        }
        while c != self.min_context && !self.broken {
            let ns = self.num_stats(c);
            if ns == 0 {
                let freq = u32::from(self.b(c + 3));
                self.set_b(c + 3, ((freq + 1) >> 1) as u8);
            } else {
                let summ = self.summ_freq(c) + 4;
                self.set_summ_freq(c, summ);
                if (summ & 0xFFFF) > 128 + 4 * ns {
                    self.refresh(c, (ns + 2) >> 1, 1);
                }
            }
            c = self.suffix(c);
        }
        if self.restore_method == RESTORE_RESTART || self.used_memory() < (self.size >> 1) {
            #[cfg(test)]
            {
                self.restores.0 += 1;
            }
            self.restart_model();
        } else {
            #[cfg(test)]
            {
                self.restores.1 += 1;
            }
            loop {
                let s = self.suffix(self.max_context);
                if s == 0 || self.broken {
                    break;
                }
                self.max_context = s;
            }
            loop {
                let mc = self.max_context;
                self.cut_off(mc, 0);
                self.expand_text_area();
                if self.used_memory() <= 3 * (self.size >> 2) || self.broken {
                    break;
                }
            }
            self.glue_count = 0;
            self.order_fall = self.max_order;
        }
        self.min_context = self.max_context;
    }

    fn create_successors(&mut self, skip: bool, mut s1: u32, mut c: u32) -> u32 {
        let up_branch = self.succ(self.found_state);
        let mut ps = [0u32; MAX_ORDER as usize + 1];
        let mut num_ps = 0usize;
        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }
        loop {
            let suffix = self.suffix(c);
            if suffix == 0 || self.broken {
                break;
            }
            c = suffix;
            let s;
            if s1 != 0 {
                s = s1;
                s1 = 0;
            } else if self.num_stats(c) != 0 {
                let sym = self.st_sym(self.found_state);
                let mut t = self.stats(c);
                let mut guard = 0;
                while self.st_sym(t) != sym {
                    t += 6;
                    guard += 1;
                    if guard > 256 {
                        self.broken = true;
                        return 0;
                    }
                }
                s = t;
                if self.st_freq(s) < MAX_FREQ - 9 {
                    let f = self.st_freq(s);
                    self.set_st_freq(s, f + 1);
                    let sf = self.summ_freq(c);
                    self.set_summ_freq(c, sf + 1);
                }
            } else {
                let suffix = self.suffix(c);
                let temp = u32::from(self.num_stats(suffix) == 0);
                s = Self::one_state(c);
                let f = self.st_freq(s);
                self.set_st_freq(s, f + (temp & u32::from(f < 24)));
            }
            let successor = self.succ(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return c;
                }
                break;
            }
            if num_ps >= ps.len() {
                self.broken = true;
                return 0;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }
        let new_sym = u32::from(self.b(up_branch));
        let up_branch = up_branch.wrapping_add(1);
        let flags = hi_flag_4(self.st_sym(self.found_state)).wrapping_add(hi_flag_3(new_sym));
        let new_freq: u8 = if self.num_stats(c) == 0 {
            self.b(c + 3)
        } else {
            let mut s = self.stats(c);
            let mut guard = 0;
            while self.st_sym(s) != new_sym {
                s += 6;
                guard += 1;
                if guard > 256 {
                    self.broken = true;
                    return 0;
                }
            }
            let cf = self.st_freq(s).wrapping_sub(1);
            let s0 = self.summ_freq(c).wrapping_sub(self.num_stats(c)).wrapping_sub(cf);
            let v = if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                match cf.wrapping_add(2 * s0).wrapping_sub(3).checked_div(s0) {
                    Some(v) => v,
                    None => {
                        self.broken = true;
                        return 0;
                    }
                }
            };
            (1 + v) as u8
        };
        loop {
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                let c1 = self.alloc_units_rare(0);
                if c1 == 0 {
                    return 0;
                }
                c1
            };
            self.set_flags(c1, flags);
            self.set_num_stats(c1, 0);
            self.set_b(c1 + 2, new_sym as u8);
            self.set_b(c1 + 3, new_freq);
            self.set_succ(Self::one_state(c1), up_branch);
            self.set_suffix(c1, c);
            num_ps -= 1;
            self.set_succ(ps[num_ps], c1);
            c = c1;
            if num_ps == 0 || self.broken {
                break;
            }
        }
        c
    }

    fn reduce_order(&mut self, mut s1: u32, mut c: u32) -> u32 {
        let mut s: u32;
        let c1 = c;
        let up_branch = self.text;
        self.set_succ(self.found_state, up_branch);
        self.order_fall += 1;
        loop {
            if self.broken {
                return 0;
            }
            if s1 != 0 {
                c = self.suffix(c);
                s = s1;
                s1 = 0;
            } else {
                let suffix = self.suffix(c);
                if suffix == 0 {
                    return c;
                }
                c = suffix;
                if self.num_stats(c) != 0 {
                    let sym = self.st_sym(self.found_state);
                    s = self.stats(c);
                    let mut guard = 0;
                    while self.st_sym(s) != sym {
                        s += 6;
                        guard += 1;
                        if guard > 256 {
                            self.broken = true;
                            return 0;
                        }
                    }
                    if self.st_freq(s) < MAX_FREQ - 9 {
                        let f = self.st_freq(s);
                        self.set_st_freq(s, f + 2);
                        let sf = self.summ_freq(c);
                        self.set_summ_freq(c, sf + 2);
                    }
                } else {
                    s = Self::one_state(c);
                    let f = self.st_freq(s);
                    self.set_st_freq(s, f + u32::from(f < 32));
                }
            }
            if self.succ(s) != 0 {
                break;
            }
            self.set_succ(s, up_branch);
            self.order_fall += 1;
        }
        if self.succ(s) <= up_branch {
            let s2 = self.found_state;
            self.found_state = s;
            let successor = self.create_successors(false, 0, c);
            self.set_succ(s, successor);
            self.found_state = s2;
        }
        let successor = self.succ(s);
        if self.order_fall == 1 && c1 == self.max_context {
            self.set_succ(self.found_state, successor);
            self.text = self.text.wrapping_sub(1);
        }
        successor
    }

    fn update_model(&mut self) {
        let mut min_successor = self.succ(self.found_state);
        let f_freq = self.st_freq(self.found_state);
        let f_symbol = self.st_sym(self.found_state);
        let mut s = 0u32;
        if f_freq < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            let c = self.suffix(self.min_context);
            if self.num_stats(c) == 0 {
                s = Self::one_state(c);
                let f = self.st_freq(s);
                if f < 32 {
                    self.set_st_freq(s, f + 1);
                }
            } else {
                s = self.stats(c);
                if self.st_sym(s) != f_symbol {
                    let mut guard = 0;
                    loop {
                        s += 6;
                        guard += 1;
                        if self.st_sym(s) == f_symbol || guard > 256 {
                            break;
                        }
                    }
                    if guard > 256 {
                        self.broken = true;
                        return;
                    }
                    if self.st_freq(s) >= self.st_freq(s - 6) {
                        self.swap_states(s, s - 6);
                        s -= 6;
                    }
                }
                if self.st_freq(s) < MAX_FREQ - 9 {
                    let f = self.st_freq(s);
                    self.set_st_freq(s, f + 2);
                    let sf = self.summ_freq(c);
                    self.set_summ_freq(c, sf + 2);
                }
            }
        }
        let mut c = self.max_context;
        if self.order_fall == 0 && min_successor != 0 {
            let cs = self.create_successors(true, s, self.min_context);
            if cs == 0 {
                self.set_succ(self.found_state, 0);
                self.restore_model(c);
                return;
            }
            self.set_succ(self.found_state, cs);
            self.min_context = cs;
            self.max_context = cs;
            return;
        }
        let text = self.text;
        self.set_b(text, f_symbol as u8);
        let text = text + 1;
        self.text = text;
        if text >= self.units_start {
            self.restore_model(c);
            return;
        }
        let mut max_successor = text;
        if min_successor == 0 {
            let cs = self.reduce_order(s, self.min_context);
            if cs == 0 {
                self.restore_model(c);
                return;
            }
            min_successor = cs;
        } else if min_successor < self.units_start {
            let cs = self.create_successors(false, s, self.min_context);
            if cs == 0 {
                self.restore_model(c);
                return;
            }
            min_successor = cs;
        }
        self.order_fall = self.order_fall.wrapping_sub(1);
        if self.order_fall == 0 {
            max_successor = min_successor;
            self.text = self.text.wrapping_sub(u32::from(self.max_context != self.min_context));
        }
        let flag = hi_flag_3(f_symbol);
        let ns = self.num_stats(self.min_context);
        let s0 = self.summ_freq(self.min_context).wrapping_sub(ns).wrapping_sub(f_freq);
        while c != self.min_context {
            if self.broken {
                return;
            }
            let ns1 = self.num_stats(c);
            let mut sum;
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    let old_nu = (ns1 + 1) >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restore_model(c);
                            return;
                        }
                        let old_ptr = self.stats(c);
                        self.copy_units(ptr, old_ptr, old_nu);
                        self.insert_node(old_ptr, i);
                        self.set_stats(c, ptr);
                    }
                }
                sum = self.summ_freq(c);
                sum += u32::from(3 * ns1 + 1 < ns);
            } else {
                let s = self.alloc_units(0);
                if s == 0 {
                    self.restore_model(c);
                    return;
                }
                let mut freq = u32::from(self.b(c + 3));
                let sym = self.b(c + 2);
                self.set_b(s, sym);
                let succ = self.u32(c + 4);
                self.set_succ(s, succ);
                self.set_stats(c, s);
                if freq < MAX_FREQ / 4 - 1 {
                    freq <<= 1;
                } else {
                    freq = MAX_FREQ - 4;
                }
                self.set_st_freq(s, freq);
                sum = freq + self.init_esc + u32::from(ns > 2);
            }
            let s = self.stats(c) + (ns1 + 1) * 6;
            let mut cf = 2 * (sum + 6) * f_freq;
            let sf = s0.wrapping_add(sum);
            self.set_b(s, f_symbol as u8);
            self.set_num_stats(c, ns1 + 1);
            self.set_succ(s, max_successor);
            let fl = self.flags(c);
            self.set_flags(c, fl | flag);
            if cf < 6 * sf {
                cf = 1 + u32::from(cf > sf) + u32::from(cf >= 4 * sf);
                sum += 4;
            } else {
                cf = 4 + u32::from(cf > 9 * sf) + u32::from(cf > 12 * sf) + u32::from(cf > 15 * sf);
                sum += cf;
            }
            self.set_summ_freq(c, sum);
            self.set_st_freq(s, cf);
            c = self.suffix(c);
        }
        self.max_context = min_successor;
        self.min_context = min_successor;
    }

    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.stats(mc);
        let mut s = self.found_state;
        if s != stats {
            let mut tmp = [0u8; 6];
            for (k, b) in tmp.iter_mut().enumerate() {
                *b = self.b(s + k as u32);
            }
            while s != stats && !self.broken {
                self.copy_state(s, s - 6);
                s -= 6;
            }
            for (k, b) in tmp.iter().enumerate() {
                self.set_b(s + k as u32, *b);
            }
        }
        let mut sum_freq = self.st_freq(s);
        let mut esc_freq = self.summ_freq(mc).wrapping_sub(sum_freq);
        let adder = u32::from(self.order_fall != 0);
        sum_freq = (sum_freq + 4 + adder) >> 1;
        let mut i = self.num_stats(mc);
        self.set_st_freq(s, sum_freq);
        loop {
            s += 6;
            let mut freq = self.st_freq(s);
            esc_freq = esc_freq.wrapping_sub(freq);
            freq = (freq + adder) >> 1;
            sum_freq += freq;
            self.set_st_freq(s, freq);
            if freq > self.st_freq(s - 6) {
                let mut tmp = [0u8; 6];
                for (k, b) in tmp.iter_mut().enumerate() {
                    *b = self.b(s + k as u32);
                }
                let mut s1 = s;
                loop {
                    self.copy_state(s1, s1 - 6);
                    s1 -= 6;
                    if s1 == stats || freq <= self.st_freq(s1 - 6) || self.broken {
                        break;
                    }
                }
                for (k, b) in tmp.iter().enumerate() {
                    self.set_b(s1 + k as u32, *b);
                }
            }
            i -= 1;
            if i == 0 || self.broken {
                break;
            }
        }
        if self.st_freq(s) == 0 {
            let mut i = 0u32;
            loop {
                i += 1;
                s -= 6;
                if self.st_freq(s) != 0 || self.broken {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(i);
            let num_stats = self.num_stats(mc);
            let num_stats_new = num_stats - i;
            self.set_num_stats(mc, num_stats_new);
            let n0 = (num_stats + 2) >> 1;
            if num_stats_new == 0 {
                if esc_freq == 0 {
                    self.broken = true;
                    return;
                }
                let mut freq = (2 * self.st_freq(stats)).div_ceil(esc_freq);
                if freq > MAX_FREQ / 3 {
                    freq = MAX_FREQ / 3;
                }
                let sym = self.st_sym(stats);
                let f = self.flags(mc);
                self.set_flags(mc, (f & FLAG_PREV_HIGH).wrapping_add(hi_flag_3(sym)));
                let one = Self::one_state(mc);
                self.copy_state(one, stats);
                self.set_st_freq(one, freq);
                self.found_state = one;
                let i = self.u2i(n0);
                self.insert_node(stats, i);
                return;
            }
            let n1 = (num_stats_new + 2) >> 1;
            if n0 != n1 {
                let shrunk = self.shrink_units(stats, n0, n1);
                self.set_stats(mc, shrunk);
            }
        }
        self.set_summ_freq(mc, sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1));
        let f = self.flags(mc);
        self.set_flags(mc, f | FLAG_RESCALED);
        self.found_state = self.stats(mc);
    }

    fn make_esc_freq(&mut self, num_masked1: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let num_stats = self.num_stats(mc);
        if num_stats != 0xFF {
            let row = usize::from(self.ns2indx[num_stats as usize + 2]).wrapping_sub(3);
            let suffix = self.suffix(mc);
            let suffix_stats = self.num_stats(suffix);
            let col = usize::from(self.summ_freq(mc) > 11 * (num_stats + 1))
                + 2 * usize::from(2 * num_stats < suffix_stats + num_masked1)
                + usize::from(self.flags(mc));
            let Some(see) = self.see.get_mut(row).and_then(|r| r.get_mut(col)) else {
                self.broken = true;
                return (SeeRef::Dummy, 1);
            };
            let r = see.summ >> see.shift;
            see.summ = see.summ.wrapping_sub(r);
            (SeeRef::At(row, col), u32::from(r) + u32::from(r == 0))
        } else {
            (SeeRef::Dummy, 1)
        }
    }

    fn see_mut(&mut self, r: SeeRef) -> &mut See {
        match r {
            SeeRef::Dummy => &mut self.dummy_see,
            SeeRef::At(row, col) => &mut self.see[row][col],
        }
    }

    fn next_context(&mut self) {
        let c = self.succ(self.found_state);
        if self.order_fall == 0 && c >= self.units_start {
            self.max_context = c;
            self.min_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let s = self.found_state;
        let freq = self.st_freq(s) + 4;
        let mc = self.min_context;
        let sf = self.summ_freq(mc);
        self.set_summ_freq(mc, sf + 4);
        self.set_st_freq(s, freq);
        if freq > self.st_freq(s - 6) {
            self.swap_states(s, s - 6);
            self.found_state = s - 6;
            if freq > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let s = self.found_state;
        let mc = self.min_context;
        let freq = self.st_freq(s);
        let summ_freq = self.summ_freq(mc);
        self.prev_success = u32::from(2 * freq >= summ_freq);
        self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
        self.set_summ_freq(mc, summ_freq + 4);
        let freq = freq + 4;
        self.set_st_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update2(&mut self) {
        let s = self.found_state;
        let freq = self.st_freq(s) + 4;
        self.run_length = self.init_rl;
        let mc = self.min_context;
        let sf = self.summ_freq(mc);
        self.set_summ_freq(mc, sf + 4);
        self.set_st_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.update_model();
    }

    // ---- range decoder ----

    /// Starts the range decoder: false when the first four bytes can't begin a stream.
    pub(crate) fn init_range(&mut self, input: &mut impl ByteIn) -> bool {
        self.code = 0;
        self.range = 0xFFFF_FFFF;
        self.low = 0;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(input.byte());
        }
        self.code < 0xFFFF_FFFF
    }

    /// Whether the range decoder ended cleanly after the end marker (7-Zip's `Ppmd8_RangeDec_IsFinishedOK`).
    pub(crate) fn finished_ok(&self) -> bool {
        self.code == 0
    }

    fn norm(&mut self, input: &mut impl ByteIn) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= K_TOP {
                if self.range >= K_BOT {
                    break;
                }
                self.range = 0u32.wrapping_sub(self.low) & (K_BOT - 1);
            }
            self.code = (self.code << 8) | u32::from(input.byte());
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    fn rc_decode(&mut self, start: u32, size: u32) {
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.code = self.code.wrapping_sub(start);
        self.range = self.range.wrapping_mul(size);
    }

    fn threshold(&mut self, total: u32) -> Option<u32> {
        if total == 0 {
            return None;
        }
        self.range /= total;
        if self.range == 0 {
            return None;
        }
        Some(self.code / self.range)
    }

    fn bin_summ_index(&mut self) -> (usize, usize) {
        let mc = self.min_context;
        let freq = u32::from(self.b(mc + 3));
        let row = usize::from(self.ns2indx[(freq as usize).saturating_sub(1).min(259)]);
        let suffix = self.suffix(mc);
        let sn = self.num_stats(suffix) as usize;
        let col = self.prev_success as usize
            + ((self.run_length >> 26) & 0x20) as usize
            + usize::from(self.ns2bsindx[sn.min(255)])
            + usize::from(self.flags(mc));
        (row, col)
    }

    /// The next symbol.
    pub(crate) fn decode_symbol(&mut self, input: &mut impl ByteIn) -> Symbol {
        if self.broken {
            return Symbol::Error;
        }
        let symbol = self.decode_inner(input);
        if self.broken { Symbol::Error } else { symbol }
    }

    fn decode_inner(&mut self, input: &mut impl ByteIn) -> Symbol {
        let mut char_mask = [0xFFu8; 256];
        let mc = self.min_context;
        if self.num_stats(mc) != 0 {
            let mut s = self.stats(mc);
            let mut summ_freq = self.summ_freq(mc);
            if summ_freq > self.range {
                summ_freq = self.range;
            }
            let Some(mut count) = self.threshold(summ_freq) else { return Symbol::Error };
            let hi_cnt = count;
            let freq = self.st_freq(s);
            if (count.wrapping_sub(freq) as i32) < 0 {
                self.rc_decode(0, freq);
                self.norm(input);
                self.found_state = s;
                let sym = self.st_sym(s) as u8;
                self.update1_0();
                return Symbol::Byte(sym);
            }
            count = count.wrapping_sub(freq);
            self.prev_success = 0;
            let mut i = self.num_stats(mc);
            loop {
                s += 6;
                let freq = self.st_freq(s);
                count = count.wrapping_sub(freq);
                if (count as i32) < 0 {
                    self.rc_decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);
                    self.norm(input);
                    self.found_state = s;
                    let sym = self.st_sym(s) as u8;
                    self.update1();
                    return Symbol::Byte(sym);
                }
                i -= 1;
                if i == 0 || self.broken {
                    break;
                }
            }
            if hi_cnt >= summ_freq {
                return Symbol::Error;
            }
            let hi_cnt = hi_cnt.wrapping_sub(count);
            self.rc_decode(hi_cnt, summ_freq - hi_cnt);
            let last = s;
            let mut s2 = self.stats(mc);
            char_mask[self.st_sym(last) as usize] = 0;
            loop {
                let sym0 = self.st_sym(s2) as usize;
                let sym1 = self.st_sym(s2 + 6) as usize;
                s2 += 12;
                char_mask[sym0] = 0;
                char_mask[sym1] = 0;
                if s2 >= last || self.broken {
                    break;
                }
            }
        } else {
            let s = Self::one_state(mc);
            let (row, col) = self.bin_summ_index();
            let Some(&prob) = self.bin_summ.get(row).and_then(|r| r.get(col)) else { return Symbol::Error };
            let mut pr = u32::from(prob);
            let size0 = (self.range >> 14).wrapping_mul(pr);
            pr = pr - ((pr + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS);
            if self.code < size0 {
                self.bin_summ[row][col] = (pr + (1 << INT_BITS)) as u16;
                self.range = size0;
                self.norm(input);
                let freq = self.st_freq(s);
                let c = self.succ(s);
                let sym = self.st_sym(s) as u8;
                self.found_state = s;
                self.prev_success = 1;
                self.run_length = self.run_length.wrapping_add(1);
                self.set_st_freq(s, freq + u32::from(freq < 196));
                if self.order_fall == 0 && c >= self.units_start {
                    self.max_context = c;
                    self.min_context = c;
                } else {
                    self.update_model();
                }
                return Symbol::Byte(sym);
            }
            self.bin_summ[row][col] = pr as u16;
            self.init_esc = u32::from(EXP_ESCAPE[(pr >> 10) as usize & 15]);
            self.low = self.low.wrapping_add(size0);
            self.code = self.code.wrapping_sub(size0);
            self.range = (self.range & !(BIN_SCALE - 1)).wrapping_sub(size0);
            let sym = self.st_sym(s) as usize;
            char_mask[sym] = 0;
            self.prev_success = 0;
        }
        loop {
            if self.broken {
                return Symbol::Error;
            }
            self.norm(input);
            let mut mc = self.min_context;
            let num_masked = self.num_stats(mc);
            loop {
                self.order_fall += 1;
                let suffix = self.suffix(mc);
                if suffix == 0 {
                    return Symbol::End;
                }
                mc = suffix;
                if self.num_stats(mc) != num_masked || self.broken {
                    break;
                }
            }
            let mut s = self.stats(mc);
            let mut hi_cnt;
            {
                let mut num = self.num_stats(mc) + 1;
                let mut num2 = num / 2;
                num &= 1;
                let sym = self.st_sym(s) as usize;
                hi_cnt = (self.st_freq(s) & u32::from(char_mask[sym])) & 0u32.wrapping_sub(num);
                s += num * 6;
                self.min_context = mc;
                while num2 > 0 {
                    let sym0 = self.st_sym(s) as usize;
                    let sym1 = self.st_sym(s + 6) as usize;
                    hi_cnt += self.st_freq(s) & u32::from(char_mask[sym0]);
                    hi_cnt += self.st_freq(s + 6) & u32::from(char_mask[sym1]);
                    s += 12;
                    num2 -= 1;
                }
            }
            let (see, esc) = self.make_esc_freq(num_masked);
            let freq_sum = esc.wrapping_add(hi_cnt);
            let mut freq_sum2 = freq_sum;
            if freq_sum2 > self.range {
                freq_sum2 = self.range;
            }
            let Some(mut count) = self.threshold(freq_sum2) else { return Symbol::Error };
            if count < hi_cnt {
                let mut s = self.stats(self.min_context);
                let hi = count;
                let mut guard = 0;
                loop {
                    let sym = self.st_sym(s) as usize;
                    count = count.wrapping_sub(self.st_freq(s) & u32::from(char_mask[sym]));
                    s += 6;
                    guard += 1;
                    if (count as i32) < 0 {
                        break;
                    }
                    if guard > 256 || self.broken {
                        return Symbol::Error;
                    }
                }
                s -= 6;
                let freq = self.st_freq(s);
                self.rc_decode(hi.wrapping_sub(count).wrapping_sub(freq), freq);
                self.norm(input);
                {
                    let see = self.see_mut(see);
                    if u32::from(see.shift) < PERIOD_BITS {
                        see.count = see.count.wrapping_sub(1);
                        if see.count == 0 {
                            see.summ <<= 1;
                            see.count = (3u32 << see.shift) as u8;
                            see.shift += 1;
                        }
                    }
                }
                self.found_state = s;
                let sym = self.st_sym(s) as u8;
                self.update2();
                return Symbol::Byte(sym);
            }
            if count >= freq_sum2 {
                return Symbol::Error;
            }
            self.rc_decode(hi_cnt, freq_sum2 - hi_cnt);
            {
                let see = self.see_mut(see);
                see.summ = see.summ.wrapping_add(freq_sum as u16);
            }
            let mut s = self.stats(self.min_context);
            let n = self.num_stats(self.min_context) + 1;
            for _ in 0..n {
                let sym = self.st_sym(s) as usize;
                char_mask[sym] = 0;
                s += 6;
            }
        }
    }
}

/// The two-byte PPMd header ZIP puts before the data: the model order, its memory and the restore method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub(crate) order: u32,
    /// the model's memory in bytes, 1 to 256 MiB
    pub(crate) memory: u32,
    pub(crate) restore: u32,
}

/// Why a header is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeaderError {
    Malformed,
    /// FREEZE (2), which 7-Zip does not implement either, or a value past it
    Unsupported,
}

impl Header {
    pub(crate) fn parse(bytes: [u8; 2]) -> Result<Self, HeaderError> {
        let v = u32::from(u16::from_le_bytes(bytes));
        let order = (v & 0xF) + 1;
        let memory = (((v >> 4) & 0xFF) + 1) << 20;
        let restore = v >> 12;
        if order < MIN_ORDER || restore > 2 {
            return Err(HeaderError::Malformed);
        }
        if restore != RESTORE_RESTART && restore != RESTORE_CUT_OFF {
            return Err(HeaderError::Unsupported);
        }
        Ok(Self { order, memory, restore })
    }
}

/// One symbol never reads more than this many input bytes (each of at most 17 orders normalizes a few bytes).
const LOOKAHEAD: usize = 512;

/// A buffer of input bytes as [`ByteIn`]: past its end it gives 0 and counts how many it made up.
struct Window<'a> {
    data: &'a [u8],
    pos: usize,
    extra: usize,
}

impl ByteIn for Window<'_> {
    fn byte(&mut self) -> u8 {
        match self.data.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                b
            }
            None => {
                self.extra += 1;
                0
            }
        }
    }
}

/// A PPMd8 stream decoder that takes its input in pieces: the ZIP header, then the data up to the end marker, as
/// 7-Zip's `NPpmdZip::CDecoder` in full-file mode reads it. The model's memory must be at most `memory_limit`.
pub(crate) struct Decoder {
    memory_limit: u64,
    pending: Vec<u8>,
    model: Option<Box<Ppmd8>>,
    /// the end marker was decoded and the range coder ended cleanly
    ended: bool,
    /// input went past the end marker
    trailing: bool,
}

/// Why decoding stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    Malformed,
    Unsupported,
    /// the header asks for more memory than the limit
    Memory {
        asked: u64,
        limit: u64,
    },
    /// the memory could not be had
    Allocation,
    /// the input ended inside the stream
    Truncated,
}

impl Decoder {
    pub(crate) fn new(memory_limit: u64) -> Self {
        Self { memory_limit, pending: Vec::new(), model: None, ended: false, trailing: false }
    }

    /// Whether input was given past the end marker.
    pub(crate) fn trailing(&self) -> bool {
        self.trailing
    }

    /// Whether the end marker has been decoded.
    pub(crate) fn ended(&self) -> bool {
        self.ended
    }

    /// Takes `input` and fills `output`; `last` says no more input follows. Returns the bytes taken and made.
    /// After the end marker, further input is refused as trailing data by the caller.
    pub(crate) fn step(&mut self, input: &[u8], output: &mut [u8], last: bool) -> Result<(usize, usize), Fault> {
        // Hold at most a little more than one symbol's input beyond what is needed.
        let room = (LOOKAHEAD * 8).saturating_sub(self.pending.len());
        let take = if self.ended { 0 } else { input.len().min(room) };
        self.pending.extend_from_slice(&input[..take]);
        let all_in = last && take == input.len();
        let mut window = Window { data: &self.pending, pos: 0, extra: 0 };
        if self.model.is_none() {
            if window.data.len() < 6 && !all_in {
                return Ok((take, 0));
            }
            let header = Header::parse([window.byte(), window.byte()]).map_err(|e| match e {
                HeaderError::Malformed => Fault::Malformed,
                HeaderError::Unsupported => Fault::Unsupported,
            })?;
            if u64::from(header.memory) > self.memory_limit {
                return Err(Fault::Memory { asked: header.memory.into(), limit: self.memory_limit });
            }
            let mut model = Ppmd8::new(header.memory, header.order, header.restore).ok_or(Fault::Allocation)?;
            if !model.init_range(&mut window) {
                return Err(Fault::Malformed);
            }
            if window.extra > 0 {
                return Err(Fault::Truncated);
            }
            self.model = Some(model);
        }
        let model = self.model.as_mut().expect("model started");
        let mut made = 0;
        while !self.ended && made < output.len() {
            // decode a symbol only with a full lookahead, or once all the input is here
            if window.data.len() - window.pos < LOOKAHEAD && !all_in {
                break;
            }
            match model.decode_symbol(&mut window) {
                Symbol::Byte(b) => {
                    output[made] = b;
                    made += 1;
                }
                Symbol::End => {
                    if !model.finished_ok() {
                        return Err(Fault::Malformed);
                    }
                    self.ended = true;
                }
                Symbol::Error => return Err(Fault::Malformed),
            }
            if window.extra > 0 {
                return Err(Fault::Truncated);
            }
        }
        let used = window.pos;
        self.pending.drain(..used);
        if self.ended && !self.pending.is_empty() {
            // bytes past the end marker
            self.trailing = true;
            self.pending.clear();
        }
        if self.ended && take < input.len() {
            self.trailing = true;
        }
        Ok((take, made))
    }
}

/// [`Decoder`] behind `Read`, over the whole packed data of an entry. It ends at the end marker; anything after it,
/// or the input ending first, is an error.
pub(crate) struct Reader<R> {
    input: R,
    decoder: Decoder,
    buf: Vec<u8>,
    at: usize,
    eof: bool,
}

const READ_CHUNK: usize = 64 << 10;

impl<R: std::io::Read> Reader<R> {
    pub(crate) fn new(input: R, memory_limit: u64) -> Self {
        Self { input, decoder: Decoder::new(memory_limit), buf: Vec::new(), at: 0, eof: false }
    }
}

fn io_fault(f: Fault) -> std::io::Error {
    use std::io::{Error, ErrorKind};
    match f {
        Fault::Truncated => Error::new(ErrorKind::UnexpectedEof, "PPMd data ends early"),
        Fault::Memory { .. } => Error::new(ErrorKind::OutOfMemory, "PPMd model memory over the limit"),
        Fault::Allocation => Error::new(ErrorKind::OutOfMemory, "PPMd model memory"),
        Fault::Unsupported => Error::new(ErrorKind::Unsupported, "PPMd restore method"),
        Fault::Malformed => Error::new(ErrorKind::InvalidData, "PPMd data"),
    }
}

impl<R: std::io::Read> std::io::Read for Reader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Error, ErrorKind};
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.decoder.ended() {
                return Ok(0);
            }
            if self.at == self.buf.len() && !self.eof {
                self.buf.resize(READ_CHUNK, 0);
                let n = self.input.read(&mut self.buf)?;
                self.buf.truncate(n);
                self.at = 0;
                self.eof = n == 0;
            }
            let (taken, made) = self.decoder.step(&self.buf[self.at..], out, self.eof).map_err(io_fault)?;
            self.at += taken;
            if self.decoder.ended()
                && (self.decoder.trailing()
                    || self.at != self.buf.len()
                    || !self.eof && self.input.read(&mut [0u8; 1])? != 0)
            {
                return Err(Error::new(ErrorKind::InvalidData, "data after the PPMd end marker"));
            }
            if made > 0 {
                return Ok(made);
            }
            if self.eof && taken == 0 && !self.decoder.ended() {
                return Err(Error::new(ErrorKind::UnexpectedEof, "PPMd data ends early"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// The packed data of `w150.txt` in a fixture (local headers without data descriptors).
    fn first_member(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip-ppmd").join(name);
        let zip = std::fs::read(path).unwrap();
        let mut at = 0;
        while &zip[at..at + 4] == b"PK\x03\x04" {
            let packed = u32::from_le_bytes(zip[at + 18..at + 22].try_into().unwrap()) as usize;
            let n = u16::from_le_bytes([zip[at + 26], zip[at + 27]]) as usize;
            let e = u16::from_le_bytes([zip[at + 28], zip[at + 29]]) as usize;
            let data = at + 30 + n + e;
            if &zip[at + 30..at + 30 + n] == b"w150.txt" {
                return zip[data..data + packed].to_vec();
            }
            at = data + packed;
        }
        panic!("no w150.txt in {name}");
    }

    fn decode(data: &[u8], limit: u64) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Reader::new(data, limit).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn headers() {
        // order 8, 1 MiB, cut-off: (8 - 1) | (1 - 1) << 4 | 1 << 12
        assert_eq!(Header::parse(0x1007u16.to_le_bytes()), Ok(Header { order: 8, memory: 1 << 20, restore: 1 }));
        assert_eq!(Header::parse(0x0FF5u16.to_le_bytes()).unwrap().memory, 256 << 20);
        assert_eq!(Header::parse(0x0000u16.to_le_bytes()), Err(HeaderError::Malformed), "order 1");
        assert_eq!(Header::parse(0x2007u16.to_le_bytes()), Err(HeaderError::Unsupported), "FREEZE");
        assert_eq!(Header::parse(0x3007u16.to_le_bytes()), Err(HeaderError::Malformed));
    }

    #[test]
    fn the_models_memory_is_held_to_the_limit_before_it_is_allocated() {
        let mut data = 0x0FF7u16.to_le_bytes().to_vec(); // 256 MiB
        data.extend([0; 8]);
        let e = decode(&data, 16 << 20).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::OutOfMemory);
        let mut d = Decoder::new(16 << 20);
        assert_eq!(d.step(&data, &mut [0; 8], true), Err(Fault::Memory { asked: 256 << 20, limit: 16 << 20 }));
    }

    #[test]
    fn both_restore_methods_run_out_of_memory_and_carry_on() {
        for (name, restart, cut) in [("ppmd-o6-restart.zip", true, false), ("ppmd-o8-cutoff.zip", false, true)] {
            let data = first_member(name);
            let mut reader = Reader::new(&data[..], 1 << 20);
            let mut out = Vec::new();
            reader.read_to_end(&mut out).unwrap();
            assert_eq!(out.len(), 150_000, "{name}");
            let restores = reader.decoder.model.as_ref().unwrap().restores;
            assert_eq!((restores.0 > 0, restores.1 > 0), (restart, cut), "{name}: {restores:?}");
        }
    }

    #[test]
    fn data_cut_short_or_running_on_fails() {
        let data = first_member("ppmd-o8-cutoff.zip");
        assert!(decode(&data[..data.len() - 1], 1 << 20).is_err());
        let mut longer = data.clone();
        longer.push(0);
        assert!(decode(&longer, 1 << 20).is_err());
    }

    #[test]
    fn fuzz_smoke_never_panics() {
        // Byte flips in a real stream and random streams under every header: each decode ends in an error or
        // in output, bounded by the end marker or by the input running out.
        let data = first_member("ppmd-o16-cutoff.zip");
        let head = &data[..data.len().min(6000)];
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..200 {
            let mut bytes = head.to_vec();
            for _ in 0..1 + next() % 6 {
                let at = 2 + (next() as usize) % (bytes.len() - 2);
                bytes[at] = next() as u8;
            }
            let _ = decode(&bytes, 1 << 20);
        }
        for _ in 0..200 {
            let order = 1 + next() % 16;
            let restore = next() % 2;
            let header = ((order - 1) | (restore << 12)) as u16;
            let mut bytes = header.to_le_bytes().to_vec();
            bytes.extend((0..(next() % 3000)).map(|_| next() as u8));
            let mut d = Decoder::new(1 << 20);
            let mut out = vec![0u8; 1 << 16];
            let mut at = 0;
            for _ in 0..64 {
                match d.step(&bytes[at..], &mut out, true) {
                    Ok((taken, made)) => {
                        at += taken;
                        if d.ended() || (taken == 0 && made == 0) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}
