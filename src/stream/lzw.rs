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

//! Unix `compress` (`.Z`): LZW with codes of 9 up to 9-16 bits, in block mode (where code 256 clears the table)
//! or not. It decodes as `compress -d` and gzip do, including their quirk: codes are read in groups of eight, and
//! when the code width changes or the table is cleared, the rest of the current group is passed over.

use std::io::{self, BufRead, Read};

const CLEAR: u16 = 256;

fn bad(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

pub(crate) struct ZReader<R> {
    r: R,
    max_bits: u32,
    block_mode: bool,
    n_bits: u32,
    /// the most codes the current width holds before it grows
    max_code: u32,
    free: u32,
    old: Option<u16>,
    fin: u8,
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    /// bits read since the start of the data, and where the current group of codes started
    pos: u64,
    group_start: u64,
    acc: u64,
    acc_bits: u32,
    eof: bool,
    out: Vec<u8>,
    at: usize,
    started: bool,
}

impl<R: BufRead> ZReader<R> {
    pub(crate) fn new(r: R) -> Self {
        ZReader {
            r,
            max_bits: 0,
            block_mode: false,
            n_bits: 9,
            max_code: 511,
            free: 256,
            old: None,
            fin: 0,
            prefix: Vec::new(),
            suffix: Vec::new(),
            pos: 0,
            group_start: 0,
            acc: 0,
            acc_bits: 0,
            eof: false,
            out: Vec::new(),
            at: 0,
            started: false,
        }
    }

    fn header(&mut self) -> io::Result<()> {
        let mut h = [0u8; 3];
        self.r.read_exact(&mut h).map_err(|_| bad("a compress (.Z) file is cut short in its header"))?;
        if h[..2] != [0x1f, 0x9d] {
            return Err(bad("not a compress (.Z) file"));
        }
        self.max_bits = u32::from(h[2] & 0x1f);
        if !(9..=16).contains(&self.max_bits) {
            return Err(bad("a compress (.Z) file's code width is outside 9 to 16 bits"));
        }
        self.block_mode = h[2] & 0x80 != 0;
        self.free = if self.block_mode { 257 } else { 256 };
        let size = 1usize << self.max_bits;
        self.prefix = vec![0; size];
        self.suffix = (0..size).map(|i| i as u8).collect();
        self.started = true;
        Ok(())
    }

    /// Tops up the bit buffer to at least `n` bits, unless the input ends.
    fn fill(&mut self, n: u32) -> io::Result<()> {
        while self.acc_bits < n && !self.eof {
            let buf = self.r.fill_buf()?;
            if buf.is_empty() {
                self.eof = true;
                break;
            }
            let take = (((64 - self.acc_bits) / 8) as usize).min(buf.len());
            if take == 0 {
                break;
            }
            for (i, &b) in buf[..take].iter().enumerate() {
                self.acc |= u64::from(b) << (self.acc_bits + 8 * i as u32);
            }
            self.acc_bits += 8 * take as u32;
            self.r.consume(take);
        }
        Ok(())
    }

    /// The next code, or None at the end of the data (a partial code at the end is padding).
    fn code(&mut self) -> io::Result<Option<u16>> {
        self.fill(self.n_bits)?;
        if self.acc_bits < self.n_bits {
            return Ok(None);
        }
        let code = (self.acc & ((1 << self.n_bits) - 1)) as u16;
        self.acc >>= self.n_bits;
        self.acc_bits -= self.n_bits;
        self.pos += u64::from(self.n_bits);
        Ok(Some(code))
    }

    /// Passes over the rest of the current group of eight codes, as the width changes or the table clears.
    fn realign(&mut self) -> io::Result<()> {
        let group = 8 * u64::from(self.n_bits);
        let into = (self.pos - self.group_start) % group;
        if into != 0 {
            let mut skip = group - into;
            self.pos += skip;
            while skip > 0 {
                self.fill(56)?;
                let n = (skip.min(u64::from(self.acc_bits))) as u32;
                if n == 0 {
                    break;
                }
                self.acc = self.acc.checked_shr(n).unwrap_or(0);
                self.acc_bits -= n;
                skip -= u64::from(n);
            }
        }
        self.group_start = self.pos;
        Ok(())
    }

    /// Decodes the next code (or several, past clears and width changes) into `out`. Leaves `out` empty at the end.
    fn step(&mut self) -> io::Result<()> {
        loop {
            // as compress does: with 9-bit codes at most, the width still grows to 10 once the table is full,
            // because the first width's limit is 511 where every later last width's is the table's size
            if self.free > self.max_code {
                self.realign()?;
                self.n_bits += 1;
                self.max_code = if self.n_bits == self.max_bits { 1 << self.max_bits } else { (1 << self.n_bits) - 1 };
            }
            let Some(code) = self.code()? else { return Ok(()) };
            // the width can pass the table's (9-bit files grow to 10), but no code may
            if u32::from(code) >= 1 << self.max_bits {
                return Err(bad("a compress (.Z) file is corrupt"));
            }
            let Some(old) = self.old else {
                if code >= 256 {
                    return Err(bad("a compress (.Z) file starts with an invalid code"));
                }
                self.old = Some(code);
                self.fin = code as u8;
                self.out.push(self.fin);
                return Ok(());
            };
            if code == CLEAR && self.block_mode {
                self.realign()?;
                self.free = 256;
                self.n_bits = 9;
                self.max_code = 511;
                continue;
            }
            let mut c = u32::from(code);
            let start = self.out.len();
            if c >= self.free {
                // the one code not in the table yet is the next one, and only while there is room for it
                if c > self.free || self.free >= 1 << self.max_bits {
                    return Err(bad("a compress (.Z) file is corrupt"));
                }
                self.out.push(self.fin);
                c = u32::from(old);
            }
            while c >= 256 {
                self.out.push(self.suffix[c as usize]);
                c = u32::from(self.prefix[c as usize]);
            }
            self.fin = self.suffix[c as usize];
            self.out.push(self.fin);
            self.out[start..].reverse();
            if self.free < 1 << self.max_bits {
                self.prefix[self.free as usize] = old;
                self.suffix[self.free as usize] = self.fin;
                self.free += 1;
            }
            self.old = Some(code);
            return Ok(());
        }
    }
}

impl<R: BufRead> Read for ZReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.started {
            self.header()?;
        }
        loop {
            if self.at < self.out.len() {
                let n = buf.len().min(self.out.len() - self.at);
                buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            self.out.clear();
            self.at = 0;
            // a few codes at a time, so a read gets more than one string's worth
            while self.out.len() < 32 << 10 {
                let before = self.out.len();
                self.step()?;
                if self.out.len() == before {
                    break;
                }
            }
            if self.out.is_empty() {
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        ZReader::new(bytes).read_to_end(&mut out)?;
        Ok(out)
    }

    /// Codes packed least significant bit first, at the given widths, without compress's group padding.
    fn pack(codes: &[(u32, u32)]) -> Vec<u8> {
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u64, 0u32);
        for &(code, width) in codes {
            acc |= u64::from(code) << bits;
            bits += width;
            while bits >= 8 {
                out.push(acc as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            out.push(acc as u8);
        }
        out
    }

    /// A 9-bit file whose table fills: the width grows to 10, and code 512 (past the table) is refused, not
    /// taken as the next code to come.
    #[test]
    fn a_code_past_a_full_nine_bit_table_is_refused() {
        for flags in [0x09u8, 0x89] {
            let first = if flags & 0x80 != 0 { 257 } else { 256 };
            // literals fill the table to 512, in 9 bits, then compress's group padding before 10-bit codes
            let literals = 512 - first + 1;
            let mut codes: Vec<(u32, u32)> = (0..literals).map(|i| ((i % 256) as u32, 9)).collect();
            while !codes.len().is_multiple_of(8) {
                codes.push((0, 9));
            }
            codes.extend([(512, 10), (512, 10), (512, 10)]);
            let mut bytes = vec![0x1f, 0x9d, flags];
            bytes.extend(pack(&codes));
            let error = decode(&bytes).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{flags:#x}");
        }
    }

    /// Literal codes that fill the table at `max_bits`, growing the width (with compress's group padding) as the
    /// decoder will, then `tail` random codes at the last width: the edge where a full table meets bad codes.
    fn filled(max_bits: u32, block: bool, tail: &mut dyn FnMut() -> u64, n: usize) -> Vec<u8> {
        let (mut codes, mut since_align) = (Vec::new(), 0usize);
        let (mut width, mut free, mut max_code) = (9u32, if block { 257u32 } else { 256 }, 511u32);
        let emit = |code: u32, width: u32, codes: &mut Vec<(u32, u32)>, since: &mut usize| {
            codes.push((code, width));
            *since += 1;
        };
        let mut first = true;
        while free < 1 << max_bits {
            if free > max_code {
                while !since_align.is_multiple_of(8) {
                    emit(0, width, &mut codes, &mut since_align);
                }
                width += 1;
                max_code = if width == max_bits { 1 << max_bits } else { (1 << width) - 1 };
            }
            emit(u32::from(tail() as u8), width, &mut codes, &mut since_align);
            if !first {
                free += 1;
            }
            first = false;
        }
        if free > max_code {
            while !since_align.is_multiple_of(8) {
                emit(0, width, &mut codes, &mut since_align);
            }
            width += 1;
        }
        // codes at the table's edge (the last entry, one past it) as often as random ones
        for _ in 0..n {
            let r = tail();
            let code = match r % 4 {
                0 => 1 << max_bits,
                1 => (1 << max_bits) - 1,
                _ => (r >> 8) as u32,
            };
            codes.push((code & ((1 << width) - 1), width));
        }
        let mut bytes = vec![0x1f, 0x9d, max_bits as u8 | if block { 0x80 } else { 0 }];
        bytes.extend(pack(&codes));
        bytes
    }

    /// Full tables at every width up to 12 bits, then random codes: errors or data, never a panic.
    #[test]
    fn random_codes_after_a_full_table_never_panic() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for bits in 9..=12u32 {
            for block in [false, true] {
                for _ in 0..50 {
                    let bytes = filled(bits, block, &mut next, 64);
                    let _ = decode(&bytes);
                }
            }
        }
    }

    /// Random codes after every header compress writes: errors, never a panic.
    #[test]
    fn random_codes_at_every_width_never_panic() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for bits in 9..=16u8 {
            for flags in [bits, bits | 0x80] {
                for round in 0..200 {
                    let len = (next() % 4096) as usize;
                    let mut bytes = vec![0x1f, 0x9d, flags];
                    // mostly small codes, so the table fills and the width grows before the stream goes wrong
                    let small = round % 2 == 0;
                    bytes.extend((0..len).map(|_| {
                        let v = next() as u8;
                        if small { v & 0x7f } else { v }
                    }));
                    let _ = decode(&bytes);
                }
            }
        }
    }
}
