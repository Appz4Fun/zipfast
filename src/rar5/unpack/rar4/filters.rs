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

//! RAR 3.x VM standard filters, recognised as UnRAR does by their program's length and CRC-32, run natively: E8,
//! E8E9, ITANIUM, DELTA, RGB and AUDIO. A program of any other kind would need the VM itself and is refused.
//! Ported from RustyGet's `archive_native/rar3.rs`.

use super::ppm::Bits;

/// The VM's memory: no block is longer.
pub(super) const VM_MEM: usize = 0x40000;
/// Filters defined, and blocks waiting, at most.
const MAX_FILTERS: usize = 8192;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Kind {
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
    /// a program of its own
    Other,
}

fn kind_of(code: &[u8]) -> Kind {
    let xor = code.iter().skip(1).fold(0u8, |x, b| x ^ b);
    if code.first() != Some(&xor) {
        return Kind::Other;
    }
    match (code.len(), crate::crc32::hash(code)) {
        (53, 0xad57_6887) => Kind::E8,
        (57, 0x3cd7_e57e) => Kind::E8E9,
        (120, 0x3769_893f) => Kind::Itanium,
        (29, 0x0e06_077d) => Kind::Delta,
        (149, 0x1c2c_5dc8) => Kind::Rgb,
        (216, 0xbc85_e701) => Kind::Audio,
        _ => Kind::Other,
    }
}

/// A block of the stream to filter before it is written: `start` is its position in the whole solid stream.
#[derive(Clone, Debug)]
pub(super) struct Block {
    pub(super) kind: Kind,
    pub(super) start: u64,
    pub(super) len: usize,
    regs: [u32; 7],
}

impl Block {
    pub(super) fn end(&self) -> u64 {
        self.start + self.len as u64
    }
}

/// The filters a stream has defined, which a solid stream keeps from member to member, and the blocks waiting.
#[derive(Default)]
pub(super) struct Filters {
    kinds: Vec<Kind>,
    old_lengths: Vec<u32>,
    last: usize,
    pub(super) pending: std::collections::VecDeque<Block>,
}

fn vm_number(bits: &mut Bits<'_>) -> u32 {
    let data = bits.peek16();
    match data & 0xc000 {
        0 => {
            bits.skip(6);
            (data >> 10) & 15
        }
        0x4000 => {
            if data & 0x3c00 == 0 {
                bits.skip(14);
                0xffff_ff00 | ((data >> 2) & 0xff)
            } else {
                bits.skip(10);
                (data >> 6) & 0xff
            }
        }
        0x8000 => {
            bits.skip(2);
            let v = bits.peek16();
            bits.skip(16);
            v
        }
        _ => {
            bits.skip(2);
            let high = bits.peek16() << 16;
            bits.skip(16);
            let v = high | bits.peek16();
            bits.skip(16);
            v
        }
    }
}

impl Filters {
    /// A new member that doesn't go on from the one before: no filter carries over.
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    /// A member starts: blocks of the one before never reach into it.
    pub(super) fn next_member(&mut self) {
        self.pending.clear();
    }

    /// Parses one filter record (the VM code the stream carries) whose block is placed relative to `at`, the
    /// stream position of the next byte decoded.
    pub(super) fn add(&mut self, first: u32, code: &[u8], at: u64) -> Result<(), &'static str> {
        let mut bits = Bits { data: code, addr: 0, bit: 0 };
        let mut pos = if first & 0x80 != 0 {
            let n = vm_number(&mut bits) as usize;
            if n == 0 {
                self.kinds.clear();
                self.old_lengths.clear();
                self.last = 0;
                0
            } else {
                n - 1
            }
        } else {
            self.last
        };
        if pos > self.kinds.len() || self.pending.len() >= MAX_FILTERS {
            return Err("RAR4 filter number");
        }
        self.last = pos;
        let new = pos == self.kinds.len();
        if new {
            if pos >= MAX_FILTERS {
                return Err("RAR4 filter count");
            }
            self.kinds.push(Kind::Other);
            self.old_lengths.push(0);
        }
        let mut start = u64::from(vm_number(&mut bits));
        if first & 0x40 != 0 {
            start += 258;
        }
        let len = if first & 0x20 != 0 {
            let l = vm_number(&mut bits);
            self.old_lengths[pos] = l;
            l
        } else {
            self.old_lengths[pos]
        };
        let mut regs = [0u32; 7];
        regs[4] = len;
        if first & 0x10 != 0 {
            let mask = bits.peek16() >> 9;
            bits.skip(7);
            for (i, r) in regs.iter_mut().enumerate() {
                if mask & (1 << i) != 0 {
                    *r = vm_number(&mut bits);
                }
            }
        }
        if new {
            let size = vm_number(&mut bits) as usize;
            if size == 0 || size >= 0x10000 || bits.addr + size > code.len() {
                return Err("RAR4 filter program");
            }
            let program: Vec<u8> = (0..size).map(|_| bits.take(8) as u8).collect();
            self.kinds[pos] = kind_of(&program);
        }
        if bits.past_end() {
            return Err("RAR4 filter record");
        }
        pos = pos.min(self.kinds.len() - 1);
        let kind = self.kinds[pos];
        if kind == Kind::Other {
            return Err("RAR4 VM program other than a standard filter");
        }
        let len = len as usize;
        if len > VM_MEM {
            return Err("RAR4 filter block longer than VM memory");
        }
        let start = at + start;
        if self.pending.back().is_some_and(|b| start < b.start) {
            return Err("RAR4 filter blocks out of order");
        }
        self.pending.push_back(Block { kind, start, len, regs });
        Ok(())
    }
}

/// Runs one standard filter on its block. `offset` is where the block starts in its member's output.
pub(super) fn run(f: &Block, mut data: Vec<u8>, offset: u64) -> Result<Vec<u8>, &'static str> {
    let size = f.regs[4] as usize;
    if size != data.len() || size > VM_MEM {
        return Err("RAR4 filter block size");
    }
    let offset = offset as u32;
    Ok(match f.kind {
        Kind::E8 | Kind::E8E9 => {
            if size >= 4 {
                const FILE_SIZE: u32 = 0x100_0000;
                let mut i = 0usize;
                while i < size - 4 {
                    let b = data[i];
                    i += 1;
                    if b == 0xe8 || (f.kind == Kind::E8E9 && b == 0xe9) {
                        let at = (i as u32).wrapping_add(offset);
                        let addr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                        if addr & 0x8000_0000 != 0 {
                            if addr.wrapping_add(at) & 0x8000_0000 == 0 {
                                data[i..i + 4].copy_from_slice(&addr.wrapping_add(FILE_SIZE).to_le_bytes());
                            }
                        } else if addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0 {
                            data[i..i + 4].copy_from_slice(&addr.wrapping_sub(at).to_le_bytes());
                        }
                        i += 4;
                    }
                }
            }
            data
        }
        Kind::Itanium => {
            if size >= 21 {
                const MASKS: [u8; 16] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
                let mut file = offset >> 4;
                let mut at = 0;
                while at < size - 21 {
                    let b = i32::from(data[at] & 0x1f) - 0x10;
                    if b >= 0 {
                        let mask = MASKS[b as usize];
                        for slot in 0..3 {
                            if mask & (1 << slot) != 0 {
                                let start = slot * 41 + 5;
                                if bundle_bits(&data[at..], start + 37, 4) == 5 {
                                    let v = bundle_bits(&data[at..], start + 13, 20);
                                    set_bundle_bits(&mut data[at..], v.wrapping_sub(file) & 0xfffff, start + 13, 20);
                                }
                            }
                        }
                    }
                    at += 16;
                    file = file.wrapping_add(1);
                }
            }
            data
        }
        Kind::Delta => {
            let channels = f.regs[0] as usize;
            if size > VM_MEM / 2 || channels == 0 || channels > 1024 {
                return Ok(data);
            }
            let mut out = vec![0u8; size];
            let mut src = 0;
            for ch in 0..channels {
                let mut prev = 0u8;
                let mut d = ch;
                while d < size {
                    prev = prev.wrapping_sub(data[src]);
                    out[d] = prev;
                    src += 1;
                    d += channels;
                }
            }
            out
        }
        Kind::Rgb => {
            let width = (f.regs[0] as usize).wrapping_sub(3);
            let pos_r = f.regs[1] as usize;
            if !(3..=VM_MEM / 2).contains(&size) || width > size || pos_r > 2 {
                return Ok(data);
            }
            let mut out = vec![0u8; size];
            let mut src = 0;
            for ch in 0..3 {
                let mut prev = 0u32;
                let mut i = ch;
                while i < size {
                    let predicted = if i >= width + 3 {
                        let upper = u32::from(out[i - width]);
                        let upper_left = u32::from(out[i - width - 3]);
                        let p = prev.wrapping_add(upper).wrapping_sub(upper_left);
                        let pa = (p.wrapping_sub(prev) as i32).unsigned_abs();
                        let pb = (p.wrapping_sub(upper) as i32).unsigned_abs();
                        let pc = (p.wrapping_sub(upper_left) as i32).unsigned_abs();
                        if pa <= pb && pa <= pc {
                            prev
                        } else if pb <= pc {
                            upper
                        } else {
                            upper_left
                        }
                    } else {
                        prev
                    };
                    let b = (predicted as u8).wrapping_sub(data[src]);
                    src += 1;
                    out[i] = b;
                    prev = u32::from(b);
                    i += 3;
                }
            }
            let mut i = pos_r;
            while i + 2 < size {
                let g = out[i + 1];
                out[i] = out[i].wrapping_add(g);
                out[i + 2] = out[i + 2].wrapping_add(g);
                i += 3;
            }
            out
        }
        Kind::Audio => {
            let channels = f.regs[0] as usize;
            if size > VM_MEM / 2 || channels == 0 || channels > 128 {
                return Ok(data);
            }
            let mut out = vec![0u8; size];
            let mut src = 0;
            for ch in 0..channels {
                let (mut prev_byte, mut prev_delta) = (0u32, 0i32);
                let mut dif = [0u32; 7];
                let (mut d1, mut d2) = (0i32, 0i32);
                let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
                let mut i = ch;
                let mut count = 0u32;
                while i < size {
                    let d3 = d2;
                    d2 = prev_delta - d1;
                    d1 = prev_delta;
                    let predicted = (8 * prev_byte as i32 + k1 * d1 + k2 * d2 + k3 * d3) as u32;
                    let predicted = (predicted >> 3) & 0xff;
                    let cur = data[src];
                    src += 1;
                    let b = predicted.wrapping_sub(u32::from(cur)) as u8;
                    out[i] = b;
                    prev_delta = i32::from(b.wrapping_sub(prev_byte as u8) as i8);
                    prev_byte = u32::from(b);
                    let d = i32::from(cur as i8) << 3;
                    dif[0] += d.unsigned_abs();
                    dif[1] += (d - d1).unsigned_abs();
                    dif[2] += (d + d1).unsigned_abs();
                    dif[3] += (d - d2).unsigned_abs();
                    dif[4] += (d + d2).unsigned_abs();
                    dif[5] += (d - d3).unsigned_abs();
                    dif[6] += (d + d3).unsigned_abs();
                    if count & 0x1f == 0 {
                        adapt(&mut dif, &mut [&mut k1, &mut k2, &mut k3]);
                    }
                    count += 1;
                    i += channels;
                }
            }
            out
        }
        Kind::Other => return Err("RAR4 VM program other than a standard filter"),
    })
}

/// Every 32 bytes the audio predictors lean toward whichever coefficient would have erred least.
fn adapt(dif: &mut [u32], k: &mut [&mut i32]) {
    let mut min = dif[0];
    let mut which = 0;
    dif[0] = 0;
    for (j, d) in dif.iter_mut().enumerate().skip(1) {
        if *d < min {
            min = *d;
            which = j;
        }
        *d = 0;
    }
    if which > 0 {
        let c = &mut *k[(which - 1) / 2];
        if which % 2 == 1 {
            if *c >= -16 {
                *c -= 1;
            }
        } else if *c < 16 {
            *c += 1;
        }
    }
}

fn bundle_bits(data: &[u8], pos: usize, count: u32) -> u32 {
    let at = pos / 8;
    let v = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) >> (pos & 7);
    v & (u32::MAX >> (32 - count))
}

fn set_bundle_bits(data: &mut [u8], value: u32, pos: usize, count: u32) {
    let at = pos / 8;
    let bit = pos & 7;
    let mut and = !((u32::MAX >> (32 - count)) << bit);
    let mut value = value << bit;
    for b in &mut data[at..at + 4] {
        *b = (u32::from(*b) & and) as u8 | value as u8;
        and = (and >> 8) | 0xff00_0000;
        value >>= 8;
    }
}
