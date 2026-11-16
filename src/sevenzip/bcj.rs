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

//! The 7z filters that run behind a compressor: the branch converters (BCJ) for x86, PowerPC, IA-64, ARM, ARM Thumb,
//! SPARC and ARM64, Delta, and the byte swaps. Written from the xz file format, XZ Utils' public-domain filters and
//! 7-Zip's `Bra*.c`; the branch converters match both. Each one undoes, from the front of the stream, what the
//! encoder did, and reports how many leading bytes are final: the last few bytes a branch could still start in wait
//! for more input or for the end of the stream, where they pass through as they are.
use std::io::{self, Read};

/// A branch converter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Arch {
    X86,
    PowerPc,
    Ia64,
    Arm,
    ArmThumb,
    Sparc,
    Arm64,
}

/// The x86 converter's state between calls.
#[derive(Clone, Copy, Debug, Default)]
struct X86State {
    prev_mask: u32,
    prev_pos: u32,
}

/// Undoes `arch` on `buf`, whose first byte is at stream position `now`, returning how many bytes are final.
fn undo(arch: Arch, buf: &mut [u8], now: u32, x86: &mut X86State) -> usize {
    match arch {
        Arch::X86 => x86_undo(buf, now, x86),
        Arch::PowerPc => powerpc(buf, now),
        Arch::Ia64 => ia64(buf, now),
        Arch::Arm => arm(buf, now),
        Arch::ArmThumb => arm_thumb(buf, now),
        Arch::Sparc => sparc(buf, now),
        Arch::Arm64 => arm64(buf, now),
    }
}

fn x86_undo(buf: &mut [u8], now: u32, state: &mut X86State) -> usize {
    const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
    const BIT: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
    let ms = |b: u8| b == 0 || b == 0xFF;
    if buf.len() < 5 {
        return 0;
    }
    let (mut prev_mask, mut prev_pos) = (state.prev_mask, state.prev_pos);
    if now.wrapping_sub(prev_pos) > 5 {
        prev_pos = now.wrapping_sub(5);
    }
    let mut i = 0usize;
    while i <= buf.len() - 5 {
        let b = buf[i];
        if b != 0xE8 && b != 0xE9 {
            i += 1;
            continue;
        }
        let pos = now.wrapping_add(i as u32);
        let offset = pos.wrapping_sub(prev_pos);
        prev_pos = pos;
        if offset > 5 {
            prev_mask = 0;
        } else {
            for _ in 0..offset {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }
        let b4 = buf[i + 4];
        if ms(b4) && ALLOWED[((prev_mask >> 1) & 7) as usize] && (prev_mask >> 1) < 0x10 {
            let mut src = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], b4]);
            let mut dest;
            loop {
                dest = src.wrapping_sub(pos.wrapping_add(5));
                if prev_mask == 0 {
                    break;
                }
                let n = BIT[(prev_mask >> 1) as usize];
                if !ms((dest >> (24 - n * 8)) as u8) {
                    break;
                }
                src = dest ^ ((1u32 << (32 - n * 8)) - 1);
            }
            buf[i + 4] = !(((dest >> 24) & 1).wrapping_sub(1)) as u8;
            buf[i + 1..i + 4].copy_from_slice(&dest.to_le_bytes()[..3]);
            i += 5;
            prev_mask = 0;
        } else {
            i += 1;
            prev_mask |= 1;
            if ms(b4) {
                prev_mask |= 0x10;
            }
        }
    }
    state.prev_mask = prev_mask;
    state.prev_pos = prev_pos;
    i
}

fn powerpc(buf: &mut [u8], now: u32) -> usize {
    let mut i = 0;
    while i + 4 <= buf.len() {
        if buf[i] >> 2 == 0x12 && buf[i + 3] & 3 == 1 {
            let src = u32::from_be_bytes([buf[i] & 3, buf[i + 1], buf[i + 2], buf[i + 3] & !3]);
            let dest = src.wrapping_sub(now.wrapping_add(i as u32));
            buf[i] = 0x48 | ((dest >> 24) & 3) as u8;
            buf[i + 1] = (dest >> 16) as u8;
            buf[i + 2] = (dest >> 8) as u8;
            buf[i + 3] = (buf[i + 3] & 3) | dest as u8;
        }
        i += 4;
    }
    i
}

fn ia64(buf: &mut [u8], now: u32) -> usize {
    const BRANCH: [u32; 32] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
    let mut i = 0;
    while i + 16 <= buf.len() {
        let mask = BRANCH[usize::from(buf[i] & 0x1F)];
        let mut bit_pos = 5u32;
        for slot in 0..3 {
            if (mask >> slot) & 1 != 0 {
                let byte_pos = i + (bit_pos >> 3) as usize;
                let bit_res = bit_pos & 7;
                let mut instruction = 0u64;
                for j in 0..6 {
                    instruction |= u64::from(buf[byte_pos + j]) << (8 * j);
                }
                let mut norm = instruction >> bit_res;
                if (norm >> 37) & 0xF == 5 && (norm >> 9) & 7 == 0 {
                    let mut src = ((norm >> 13) & 0xF_FFFF) as u32;
                    src |= (((norm >> 36) & 1) as u32) << 20;
                    src <<= 4;
                    let dest = src.wrapping_sub(now.wrapping_add(i as u32)) >> 4;
                    norm &= !(0x8F_FFFFu64 << 13);
                    norm |= u64::from(dest & 0xF_FFFF) << 13;
                    norm |= u64::from(dest & 0x10_0000) << (36 - 20);
                    instruction &= (1u64 << bit_res) - 1;
                    instruction |= norm << bit_res;
                    for j in 0..6 {
                        buf[byte_pos + j] = (instruction >> (8 * j)) as u8;
                    }
                }
            }
            bit_pos += 41;
        }
        i += 16;
    }
    i
}

fn arm(buf: &mut [u8], now: u32) -> usize {
    let mut i = 0;
    while i + 4 <= buf.len() {
        if buf[i + 3] == 0xEB {
            let src = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], 0]) << 2;
            let dest = src.wrapping_sub(now.wrapping_add(i as u32 + 8)) >> 2;
            buf[i..i + 3].copy_from_slice(&dest.to_le_bytes()[..3]);
        }
        i += 4;
    }
    i
}

fn arm_thumb(buf: &mut [u8], now: u32) -> usize {
    let mut i = 0;
    while i + 4 <= buf.len() {
        if buf[i + 1] & 0xF8 == 0xF0 && buf[i + 3] & 0xF8 == 0xF8 {
            let src = (u32::from(buf[i + 1] & 7) << 19)
                | (u32::from(buf[i]) << 11)
                | (u32::from(buf[i + 3] & 7) << 8)
                | u32::from(buf[i + 2]);
            let dest = (src << 1).wrapping_sub(now.wrapping_add(i as u32 + 4)) >> 1;
            buf[i + 1] = 0xF0 | ((dest >> 19) & 7) as u8;
            buf[i] = (dest >> 11) as u8;
            buf[i + 3] = 0xF8 | ((dest >> 8) & 7) as u8;
            buf[i + 2] = dest as u8;
            i += 2;
        }
        i += 2;
    }
    i
}

fn sparc(buf: &mut [u8], now: u32) -> usize {
    let mut i = 0;
    while i + 4 <= buf.len() {
        if (buf[i] == 0x40 && buf[i + 1] & 0xC0 == 0) || (buf[i] == 0x7F && buf[i + 1] & 0xC0 == 0xC0) {
            let src = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) << 2;
            let mut dest = src.wrapping_sub(now.wrapping_add(i as u32)) >> 2;
            dest = ((0u32.wrapping_sub((dest >> 22) & 1) << 22) & 0x3FFF_FFFF) | (dest & 0x3F_FFFF) | 0x4000_0000;
            buf[i..i + 4].copy_from_slice(&dest.to_be_bytes());
        }
        i += 4;
    }
    i
}

fn arm64(buf: &mut [u8], now: u32) -> usize {
    let mut i = 0;
    while i + 4 <= buf.len() {
        let pc = now.wrapping_add(i as u32);
        let instr = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        if instr >> 26 == 0x25 {
            // BL
            let out = 0x9400_0000 | (instr.wrapping_sub(pc >> 2) & 0x03FF_FFFF);
            buf[i..i + 4].copy_from_slice(&out.to_le_bytes());
        } else if instr & 0x9F00_0000 == 0x9000_0000 {
            // ADRP
            let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);
            if src.wrapping_add(0x0002_0000) & 0x001C_0000 == 0 {
                let dest = src.wrapping_sub(pc >> 12);
                let mut out = instr & 0x9000_001F;
                out |= (dest & 3) << 29;
                out |= (dest & 0x0003_FFFC) << 3;
                out |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00E0_0000;
                buf[i..i + 4].copy_from_slice(&out.to_le_bytes());
            }
        }
        i += 4;
    }
    i
}

const BUF: usize = 64 << 10;

/// A branch converter over a stream.
pub(crate) struct BranchReader<R> {
    inner: R,
    arch: Arch,
    x86: X86State,
    /// Stream position of `buf[0]`.
    now: u32,
    buf: Box<[u8]>,
    /// `buf[out..ready]` is final and not yet handed out; `buf[ready..filled]` waits for more bytes.
    out: usize,
    ready: usize,
    filled: usize,
    eof: bool,
}

impl<R: Read> BranchReader<R> {
    /// `start` is the stream position the encoder started counting from (the coder's optional 4-byte property).
    pub(crate) fn new(inner: R, arch: Arch, start: u32) -> Self {
        Self {
            inner,
            arch,
            x86: X86State { prev_mask: 0, prev_pos: start.wrapping_sub(5) },
            now: start,
            buf: vec![0; BUF].into_boxed_slice(),
            out: 0,
            ready: 0,
            filled: 0,
            eof: false,
        }
    }
}

impl<R: Read> Read for BranchReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.out < self.ready {
                let n = (self.ready - self.out).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.out..self.out + n]);
                self.out += n;
                return Ok(n);
            }
            if self.ready == self.filled && self.eof {
                return Ok(0);
            }
            // Move the unsettled tail to the front, then top up.
            self.buf.copy_within(self.ready..self.filled, 0);
            self.now = self.now.wrapping_add(self.ready as u32);
            self.filled -= self.ready;
            self.out = 0;
            self.ready = 0;
            while !self.eof && self.filled < self.buf.len() {
                match self.inner.read(&mut self.buf[self.filled..]) {
                    Ok(0) => self.eof = true,
                    Ok(n) => {
                        self.filled += n;
                        // Enough to make progress; keep reading only for a tiny tail.
                        if self.filled >= 16 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            self.ready = if self.eof {
                // The stream's end settles the tail: whatever could not be a whole branch stays as it is.
                undo(self.arch, &mut self.buf[..self.filled], self.now, &mut self.x86);
                self.filled
            } else {
                undo(self.arch, &mut self.buf[..self.filled], self.now, &mut self.x86)
            };
        }
    }
}

/// Delta: each byte is stored as its difference from the one `dist` back.
pub(crate) struct DeltaReader<R> {
    inner: R,
    dist: usize,
    history: [u8; 256],
    pos: usize,
}

impl<R: Read> DeltaReader<R> {
    /// `dist` is 1 to 256.
    pub(crate) fn new(inner: R, dist: usize) -> Self {
        Self { inner, dist: dist.clamp(1, 256), history: [0; 256], pos: 0 }
    }
}

impl<R: Read> Read for DeltaReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(out)?;
        for byte in &mut out[..n] {
            // history[pos] is the byte `dist` back.
            let value = byte.wrapping_add(self.history[self.pos]);
            self.history[self.pos] = value;
            *byte = value;
            self.pos += 1;
            if self.pos == self.dist {
                self.pos = 0;
            }
        }
        Ok(n)
    }
}

/// Swap2 and Swap4: the byte order of each 2- or 4-byte word is reversed; a short tail is left as it is.
pub(crate) struct SwapReader<R> {
    inner: R,
    width: usize,
    /// Bytes of an incomplete word, held until it fills or the stream ends.
    held: [u8; 4],
    held_len: usize,
    /// Swapped bytes not yet handed out.
    pending: [u8; 4],
    pending_at: usize,
    pending_len: usize,
    eof: bool,
}

impl<R: Read> SwapReader<R> {
    pub(crate) fn new(inner: R, width: usize) -> Self {
        Self { inner, width, held: [0; 4], held_len: 0, pending: [0; 4], pending_at: 0, pending_len: 0, eof: false }
    }
}

impl<R: Read> Read for SwapReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pending_at < self.pending_len {
            let n = (self.pending_len - self.pending_at).min(out.len());
            out[..n].copy_from_slice(&self.pending[self.pending_at..self.pending_at + n]);
            self.pending_at += n;
            return Ok(n);
        }
        let w = self.width;
        loop {
            if self.eof {
                // The tail is not a whole word: it passes as it is.
                let n = self.held_len.min(out.len());
                out[..n].copy_from_slice(&self.held[..n]);
                self.held.copy_within(n..self.held_len, 0);
                self.held_len -= n;
                return Ok(n);
            }
            if out.len() < w {
                // Swap one word into `pending`.
                while self.held_len < w {
                    let n = self.inner.read(&mut self.held[self.held_len..w])?;
                    if n == 0 {
                        self.eof = true;
                        break;
                    }
                    self.held_len += n;
                }
                if self.eof {
                    continue;
                }
                self.pending[..w].copy_from_slice(&self.held[..w]);
                self.pending[..w].reverse();
                self.held_len = 0;
                self.pending_at = 0;
                self.pending_len = w;
                return self.read(out);
            }
            out[..self.held_len].copy_from_slice(&self.held[..self.held_len]);
            let mut have = self.held_len;
            self.held_len = 0;
            let n = self.inner.read(&mut out[have..])?;
            if n == 0 {
                self.eof = true;
                self.held[..have].copy_from_slice(&out[..have]);
                self.held_len = have;
                continue;
            }
            have += n;
            let whole = have / w * w;
            for word in out[..whole].chunks_exact_mut(w) {
                word.reverse();
            }
            self.held[..have - whole].copy_from_slice(&out[whole..have]);
            self.held_len = have - whole;
            if whole > 0 {
                return Ok(whole);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(arch: Arch, start: u32, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        BranchReader::new(input, arch, start).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn x86_call_becomes_relative() {
        // An absolute call target 5 at position 0 is the relative offset 0.
        assert_eq!(
            run(Arch::X86, 0, &[0xE8, 5, 0, 0, 0, 0x90, 0x90, 0x90, 0x90]),
            [0xE8, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90]
        );
        // A negative target: absolute 0 from position 0x10 is -0x15.
        let mut input = vec![0x90; 0x10];
        input.extend([0xE8, 0, 0, 0, 0]);
        input.extend([0x90; 4]);
        let out = run(Arch::X86, 0, &input);
        assert_eq!(&out[0x10..0x15], &[0xE8, 0xEB, 0xFF, 0xFF, 0xFF]);
        // Too close to the end to be a whole call: left as it is.
        assert_eq!(run(Arch::X86, 0, &[0x90, 0xE8, 5, 0]), [0x90, 0xE8, 5, 0]);
    }

    #[test]
    fn arm_branches() {
        assert_eq!(run(Arch::Arm, 0, &[2, 0, 0, 0xEB]), [0, 0, 0, 0xEB]);
        assert_eq!(run(Arch::ArmThumb, 0, &[0, 0xF0, 2, 0xF8]), [0, 0xF0, 0, 0xF8]);
        // BL at pc 4 to absolute word 1 is relative 0.
        assert_eq!(run(Arch::Arm64, 0, &[0, 0, 0, 0, 1, 0, 0, 0x94]), [0, 0, 0, 0, 0, 0, 0, 0x94]);
        // ADRP page 3 from pc 0x2000 is page +1.
        assert_eq!(run(Arch::Arm64, 0x2000, &0xF000_0000u32.to_le_bytes()), 0xB000_0000u32.to_le_bytes());
    }

    #[test]
    fn powerpc_and_sparc_branches() {
        assert_eq!(run(Arch::PowerPc, 0, &[0x60, 0, 0, 0, 0x48, 0, 0, 9]), [0x60, 0, 0, 0, 0x48, 0, 0, 5]);
        assert_eq!(run(Arch::Sparc, 0, &[1, 0, 0, 0, 0x40, 0, 0, 2]), [1, 0, 0, 0, 0x40, 0, 0, 1]);
    }

    #[test]
    fn ia64_branch() {
        // Template 0x10 has a branch in slot 2 (bits 87..128); opcode 5, btype 0, imm20 1 (target 16).
        let slot: u128 = (5 << 37) | (1 << 13);
        let bundle = (slot << 87) | 0x10;
        let out = run(Arch::Ia64, 16, &bundle.to_le_bytes());
        let slot_out = u128::from_le_bytes(out.try_into().unwrap()) >> 87;
        assert_eq!((slot_out >> 13) & 0xF_FFFF, 0, "target 16 from position 16 is relative 0");
        assert_eq!(slot_out >> 37 & 0xF, 5);
    }

    #[test]
    fn chunking_does_not_change_the_output() {
        let mut seed = 0x9E37_79B9u32;
        let raw: Vec<u8> = (0..20_000)
            .map(|i| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                match i % 17 {
                    0 => 0xE8,
                    4 => 0xFF,
                    7 => 0xEB,
                    _ => (seed >> 24) as u8,
                }
            })
            .collect();
        struct Dribble<'a>(&'a [u8], usize);
        impl Read for Dribble<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let n = self.1.min(out.len()).min(self.0.len());
                out[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        for arch in [Arch::X86, Arch::PowerPc, Arch::Ia64, Arch::Arm, Arch::ArmThumb, Arch::Sparc, Arch::Arm64] {
            let whole = run(arch, 0, &raw);
            for step in [1usize, 3, 7, 16, 4099] {
                let mut out = Vec::new();
                BranchReader::new(Dribble(&raw, step), arch, 0).read_to_end(&mut out).unwrap();
                assert_eq!(out, whole, "{arch:?} step {step}");
                // Reading out in small pieces too.
                let mut small = Vec::new();
                let mut reader = BranchReader::new(Dribble(&raw, step), arch, 0);
                let mut piece = [0u8; 5];
                loop {
                    let n = reader.read(&mut piece).unwrap();
                    if n == 0 {
                        break;
                    }
                    small.extend_from_slice(&piece[..n]);
                }
                assert_eq!(small, whole, "{arch:?} step {step}, small reads");
            }
        }
    }

    #[test]
    fn delta_adds_back() {
        let mut out = Vec::new();
        DeltaReader::new(&[1u8, 1, 1, 1][..], 1).read_to_end(&mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        let mut out = Vec::new();
        DeltaReader::new(&[1u8, 2, 1, 1, 1, 1][..], 2).read_to_end(&mut out).unwrap();
        assert_eq!(out, [1, 2, 2, 3, 3, 4]);
    }

    #[test]
    fn swaps_reverse_words_and_keep_the_tail() {
        let input: Vec<u8> = (0..11).collect();
        let mut out = Vec::new();
        SwapReader::new(&input[..], 4).read_to_end(&mut out).unwrap();
        assert_eq!(out, [3, 2, 1, 0, 7, 6, 5, 4, 8, 9, 10]);
        let mut out = Vec::new();
        SwapReader::new(&input[..], 2).read_to_end(&mut out).unwrap();
        assert_eq!(out, [1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 10]);
        let mut small = Vec::new();
        let mut reader = SwapReader::new(&input[..], 4);
        let mut one = [0u8; 1];
        while reader.read(&mut one).unwrap() == 1 {
            small.push(one[0]);
        }
        assert_eq!(small, [3, 2, 1, 0, 7, 6, 5, 4, 8, 9, 10]);
    }
}
