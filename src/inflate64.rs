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

//! A streaming raw Deflate64 ("Enhanced Deflate") decoder: ZIP method 9 and 7z coder `040109`.
//!
//! Deflate64 is Deflate (RFC 1951) with three changes: a 64 KiB window, length code 285 taking 16 extra bits for
//! lengths 3 to 65538, and distance codes 30 and 31 (14 extra bits each, bases 32769 and 49153). The same decoder
//! reads plain raw Deflate with [`Variant::Deflate`].
//!
//! Memory is fixed: a 64 KiB history, 128 KiB of decoded bytes not yet handed out, and three Huffman tables, about
//! 200 KiB in one allocation. Damaged input gives an [`Error`]; it never panics and never loops without consuming
//! input or producing output.
use std::io::{self, BufRead, Read};

/// History a match may reach back into.
const HIST: usize = 1 << 16;
/// The decode buffer: history, then room for bytes decoded ahead of the caller.
const WIN: usize = HIST + (2 << 16);
/// Room past `WIN` for match copies that write whole 16-byte chunks.
const SLACK: usize = 16;
/// Codes up to this long decode with one table lookup; longer ones walk the canonical code.
const FAST_BITS: u32 = 10;
const MAX_BITS: usize = 15;

/// Which format the stream is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Raw Deflate: 32 KiB window, length code 285 is 258.
    Deflate,
    /// Deflate64.
    Deflate64,
}

/// Why a stream does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Block type 3, which is reserved.
    BlockType,
    /// A stored block whose length and its complement disagree.
    StoredLength,
    /// More literal/length or distance codes than the format has.
    CodeCount,
    /// Code lengths that do not form a prefix code (over-subscribed, or incomplete where that is not allowed), a
    /// repeat with nothing before it, or a repeat past the end of the lengths.
    CodeLengths,
    /// The end-of-block code has no code.
    NoEndOfBlock,
    /// A literal/length or distance code that is not valid in this stream.
    Symbol,
    /// A distance back past the start of the output.
    Distance,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BlockType => "deflate: reserved block type",
            Self::StoredLength => "deflate: stored block length check fails",
            Self::CodeCount => "deflate: too many length or distance codes",
            Self::CodeLengths => "deflate: invalid code lengths",
            Self::NoEndOfBlock => "deflate: no end-of-block code",
            Self::Symbol => "deflate: invalid code",
            Self::Distance => "deflate: distance too far back",
        })
    }
}

impl std::error::Error for Error {}

/// What one [`Inflater::step`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    /// Input bytes used. The rest of the input must be offered again.
    pub consumed: usize,
    /// Output bytes written.
    pub produced: usize,
    /// The final block has ended and all of its output has been handed out. `consumed` then stops right after the
    /// stream's last byte.
    pub done: bool,
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577, 32769, 49153,
];
const DIST_EXTRA: [u8; 32] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14];
/// The order code length code lengths are sent in.
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Which code a table is for; they differ in which incomplete codes are allowed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    CodeLengths,
    Symbols,
}

/// A canonical prefix code: a direct table for short codes, counts and sorted symbols for the rest.
struct Huffman {
    /// Indexed by the next `FAST_BITS` input bits: `symbol << 4 | length`, or 0 for a longer or invalid code.
    fast: [u16; 1 << FAST_BITS],
    count: [u16; MAX_BITS + 1],
    symbol: [u16; 288],
}

impl Huffman {
    const fn new() -> Self {
        Self { fast: [0; 1 << FAST_BITS], count: [0; MAX_BITS + 1], symbol: [0; 288] }
    }

    /// Builds the code from per-symbol lengths (0 = unused), refusing lengths no encoder can write. Like zlib, an
    /// incomplete code is allowed only for symbols and only when it is a single one-bit code, or empty.
    fn build(&mut self, lengths: &[u8], kind: Kind) -> Result<(), Error> {
        self.count = [0; MAX_BITS + 1];
        for &len in lengths {
            self.count[usize::from(len)] += 1;
        }
        self.count[0] = 0;
        self.fast = [0; 1 << FAST_BITS];
        let max = (1..=MAX_BITS).rev().find(|&len| self.count[len] != 0).unwrap_or(0);
        if max == 0 {
            return Ok(());
        }
        let mut left = 1i32;
        for &count in &self.count[1..] {
            left = (left << 1) - i32::from(count);
            if left < 0 {
                return Err(Error::CodeLengths);
            }
        }
        if left > 0 && (kind == Kind::CodeLengths || max != 1) {
            return Err(Error::CodeLengths);
        }
        let mut offset = [0u16; MAX_BITS + 2];
        let mut next = [0u32; MAX_BITS + 1];
        let mut code = 0u32;
        for len in 1..=MAX_BITS {
            offset[len + 1] = offset[len] + self.count[len];
            code = (code + u32::from(self.count[len - 1])) << 1;
            next[len] = code;
        }
        for (symbol, &len) in lengths.iter().enumerate() {
            let len = usize::from(len);
            if len == 0 {
                continue;
            }
            self.symbol[usize::from(offset[len])] = symbol as u16;
            offset[len] += 1;
            if len as u32 <= FAST_BITS {
                let reversed = (next[len].reverse_bits() >> (32 - len)) as usize;
                next[len] += 1;
                let entry = (symbol as u16) << 4 | len as u16;
                for slot in (reversed..1 << FAST_BITS).step_by(1 << len) {
                    self.fast[slot] = entry;
                }
            }
        }
        Ok(())
    }

    /// The next symbol and its code length from the low `avail` bits of `bits`; `None` when more bits are needed.
    #[inline(always)]
    fn decode(&self, bits: u64, avail: u32) -> Result<Option<(usize, u32)>, Error> {
        let entry = self.fast[(bits & ((1 << FAST_BITS) - 1)) as usize];
        if entry != 0 {
            let len = u32::from(entry & 15);
            return Ok((len <= avail).then_some((usize::from(entry >> 4), len)));
        }
        self.decode_slow(bits, avail)
    }

    /// Walks the canonical code one bit at a time (puff's method) for codes longer than the direct table.
    #[cold]
    fn decode_slow(&self, bits: u64, avail: u32) -> Result<Option<(usize, u32)>, Error> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            if len as u32 > avail {
                return Ok(None);
            }
            code |= ((bits >> (len - 1)) & 1) as i32;
            let count = i32::from(self.count[len]);
            if code - first < count {
                return Ok(Some((usize::from(self.symbol[(index + code - first) as usize]), len as u32)));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::Symbol)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The next block's 3-bit header.
    Header,
    /// A stored block's LEN and NLEN, byte aligned.
    StoredLen,
    /// Bytes of a stored block still to copy.
    Stored(u32),
    /// HLIT, HDIST and HCLEN.
    Counts,
    /// Code length code lengths read so far.
    CodeLengthLengths(usize),
    /// Literal/length and distance code lengths read so far.
    Lengths(usize),
    /// Compressed data.
    Data,
    /// A length is decoded, its distance is next.
    Distance(u32),
    /// The rest of a match that did not fit.
    Copy { len: u32, dist: u32 },
    /// The final block has ended.
    Done,
}

/// Why [`Inflater::run`] returned.
enum Stop {
    /// The decode buffer is full.
    Room,
    /// The input is used up in the middle of the stream.
    Input,
    /// The final block has ended.
    End,
}

/// A streaming raw Deflate64 (or Deflate) decoder that works on caller slices; see [`Inflater::step`].
pub struct Inflater {
    window: Box<[u8]>,
    /// Where the next decoded byte goes in `window`.
    pos: usize,
    /// Decoded bytes before this have been handed out.
    flushed: usize,
    /// Bytes decoded so far, for the distance check.
    total: u64,
    bits: u64,
    count: u32,
    state: State,
    last: bool,
    failed: Option<Error>,
    variant: Variant,
    len_base: [u16; 29],
    len_extra: [u8; 29],
    /// Distance codes this variant has.
    dist_codes: usize,
    hlit: usize,
    hdist: usize,
    hclen: usize,
    lengths: [u8; 320],
    #[cfg(test)]
    seen: tests::Seen,
    codes: Huffman,
    lit: Huffman,
    dist: Huffman,
}

impl Inflater {
    /// A decoder for one raw stream.
    pub fn new(variant: Variant) -> Box<Self> {
        let (mut len_base, mut len_extra) = (LEN_BASE, LEN_EXTRA);
        if variant == Variant::Deflate64 {
            (len_base[28], len_extra[28]) = (3, 16);
        }
        Box::new(Self {
            window: vec![0; WIN + SLACK].into_boxed_slice(),
            pos: 0,
            flushed: 0,
            total: 0,
            bits: 0,
            count: 0,
            state: State::Header,
            last: false,
            failed: None,
            variant,
            len_base,
            len_extra,
            dist_codes: if variant == Variant::Deflate64 { 32 } else { 30 },
            hlit: 0,
            hdist: 0,
            hclen: 0,
            lengths: [0; 320],
            #[cfg(test)]
            seen: tests::Seen::default(),
            codes: Huffman::new(),
            lit: Huffman::new(),
            dist: Huffman::new(),
        })
    }

    /// The variant this decoder reads.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// Decodes from `input` into `output`. Input the step does not report consumed must be offered again, followed
    /// by more. A step that consumes and produces nothing without being done needs more input than it was given: at
    /// the end of the input that means the stream is truncated. After an error every later step returns it again.
    pub fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let mut at = 0;
        let mut produced = 0;
        let mut starved = false;
        loop {
            let n = (self.pos - self.flushed).min(output.len() - produced);
            output[produced..produced + n].copy_from_slice(&self.window[self.flushed..self.flushed + n]);
            produced += n;
            self.flushed += n;
            if self.flushed < self.pos || self.state == State::Done || starved {
                break;
            }
            if self.pos == WIN {
                self.window.copy_within(WIN - HIST..WIN, 0);
                (self.pos, self.flushed) = (HIST, HIST);
            }
            match self.run(input, &mut at) {
                Ok(Stop::Room | Stop::End) => {}
                Ok(Stop::Input) => starved = true,
                Err(error) => {
                    self.failed = Some(error);
                    return Err(error);
                }
            }
        }
        // Whole bytes still in the bit buffer go back to the caller, so `consumed` is exact when the stream ends.
        // A starved step keeps them: the bits it holds are fewer than its next code needs, so the next step that
        // completes a code uses them all, and only bytes of the current input are ever left to give back.
        if !starved {
            let back = ((self.count / 8) as usize).min(at);
            at -= back;
            self.count -= back as u32 * 8;
            self.bits &= mask(self.count);
        }
        let done = self.state == State::Done && self.flushed == self.pos;
        Ok(Step { consumed: at, produced, done })
    }

    /// Tops the bit buffer up to at least 56 bits, or with whatever input is left.
    #[inline(always)]
    fn refill(&mut self, input: &[u8], at: &mut usize) {
        if let Some(word) = input.get(*at..*at + 8) {
            let word = u64::from_le_bytes(word.try_into().expect("eight bytes"));
            self.bits |= word << self.count;
            let bytes = (63 - self.count) >> 3;
            *at += bytes as usize;
            self.count += bytes * 8;
            self.bits &= mask(self.count);
        } else {
            while self.count < 56 && *at < input.len() {
                self.bits |= u64::from(input[*at]) << self.count;
                *at += 1;
                self.count += 8;
            }
        }
    }

    #[inline(always)]
    fn drop_bits(&mut self, n: u32) {
        self.bits >>= n;
        self.count -= n;
    }

    /// Decodes into the window until it is full, the input runs out or the stream ends.
    fn run(&mut self, input: &[u8], at: &mut usize) -> Result<Stop, Error> {
        loop {
            match self.state {
                State::Done => return Ok(Stop::End),
                State::Header => {
                    self.refill(input, at);
                    if self.count < 3 {
                        return Ok(Stop::Input);
                    }
                    self.last = self.bits & 1 != 0;
                    let kind = (self.bits >> 1) & 3;
                    #[cfg(test)]
                    if kind < 3 {
                        self.seen.blocks[kind as usize] += 1;
                    }
                    self.drop_bits(3);
                    self.state = match kind {
                        0 => {
                            self.drop_bits(self.count % 8);
                            State::StoredLen
                        }
                        1 => {
                            self.fixed();
                            State::Data
                        }
                        2 => State::Counts,
                        _ => return Err(Error::BlockType),
                    };
                }
                State::StoredLen => {
                    self.refill(input, at);
                    if self.count < 32 {
                        return Ok(Stop::Input);
                    }
                    let (len, nlen) = (self.bits & 0xFFFF, (self.bits >> 16) & 0xFFFF);
                    if len != !nlen & 0xFFFF {
                        return Err(Error::StoredLength);
                    }
                    self.drop_bits(32);
                    self.state = State::Stored(len as u32);
                }
                State::Stored(mut left) => {
                    while left != 0 {
                        if self.pos == WIN {
                            self.state = State::Stored(left);
                            return Ok(Stop::Room);
                        }
                        if self.count >= 8 {
                            self.window[self.pos] = self.bits as u8;
                            self.drop_bits(8);
                            self.pos += 1;
                            self.total += 1;
                            left -= 1;
                            continue;
                        }
                        let n = (left as usize).min(WIN - self.pos).min(input.len() - *at);
                        if n == 0 {
                            self.state = State::Stored(left);
                            return Ok(Stop::Input);
                        }
                        self.window[self.pos..self.pos + n].copy_from_slice(&input[*at..*at + n]);
                        *at += n;
                        self.pos += n;
                        self.total += n as u64;
                        left -= n as u32;
                    }
                    self.state = self.next_block();
                }
                State::Counts => {
                    self.refill(input, at);
                    if self.count < 14 {
                        return Ok(Stop::Input);
                    }
                    self.hlit = 257 + (self.bits & 31) as usize;
                    self.hdist = 1 + ((self.bits >> 5) & 31) as usize;
                    self.hclen = 4 + ((self.bits >> 10) & 15) as usize;
                    if self.hlit > 286 || self.hdist > self.dist_codes {
                        return Err(Error::CodeCount);
                    }
                    self.drop_bits(14);
                    self.lengths[..19].fill(0);
                    self.state = State::CodeLengthLengths(0);
                }
                State::CodeLengthLengths(mut i) => {
                    while i < self.hclen {
                        self.refill(input, at);
                        if self.count < 3 {
                            self.state = State::CodeLengthLengths(i);
                            return Ok(Stop::Input);
                        }
                        self.lengths[CL_ORDER[i]] = (self.bits & 7) as u8;
                        self.drop_bits(3);
                        i += 1;
                    }
                    self.codes.build(&self.lengths[..19], Kind::CodeLengths)?;
                    self.state = State::Lengths(0);
                }
                State::Lengths(mut i) => {
                    let end = self.hlit + self.hdist;
                    while i < end {
                        self.refill(input, at);
                        let Some((symbol, n)) = self.codes.decode(self.bits, self.count)? else {
                            self.state = State::Lengths(i);
                            return Ok(Stop::Input);
                        };
                        if symbol < 16 {
                            self.drop_bits(n);
                            self.lengths[i] = symbol as u8;
                            i += 1;
                            continue;
                        }
                        let (extra, base) = match symbol {
                            16 => (2, 3),
                            17 => (3, 3),
                            _ => (7, 11),
                        };
                        if self.count < n + extra {
                            self.state = State::Lengths(i);
                            return Ok(Stop::Input);
                        }
                        let repeat = base + ((self.bits >> n) & mask(extra)) as usize;
                        let value = if symbol == 16 {
                            if i == 0 {
                                return Err(Error::CodeLengths);
                            }
                            self.lengths[i - 1]
                        } else {
                            0
                        };
                        if i + repeat > end {
                            return Err(Error::CodeLengths);
                        }
                        self.drop_bits(n + extra);
                        self.lengths[i..i + repeat].fill(value);
                        i += repeat;
                    }
                    if self.lengths[256] == 0 {
                        return Err(Error::NoEndOfBlock);
                    }
                    let (hlit, hdist) = (self.hlit, self.hdist);
                    self.lit.build(&self.lengths[..hlit], Kind::Symbols)?;
                    self.dist.build(&self.lengths[hlit..hlit + hdist], Kind::Symbols)?;
                    self.state = State::Data;
                }
                State::Data => {
                    if let Some(stop) = self.data(input, at)? {
                        return Ok(stop);
                    }
                }
                State::Distance(len) => {
                    if let Some(stop) = self.distance(input, at, len)? {
                        return Ok(stop);
                    }
                }
                State::Copy { len, dist } => {
                    if let Some(stop) = self.copy(len, dist) {
                        return Ok(stop);
                    }
                    self.state = State::Data;
                }
            }
        }
    }

    fn next_block(&self) -> State {
        if self.last { State::Done } else { State::Header }
    }

    /// The fixed codes of block type 1.
    fn fixed(&mut self) {
        let mut lens = [8u8; 288];
        lens[144..256].fill(9);
        lens[256..280].fill(7);
        self.lit.build(&lens, Kind::Symbols).expect("the fixed literal code is complete");
        self.dist.build(&[5; 32], Kind::Symbols).expect("the fixed distance code is complete");
    }

    /// The literal/length loop. `None` when the block ended (state already moved on).
    #[inline(always)]
    fn data(&mut self, input: &[u8], at: &mut usize) -> Result<Option<Stop>, Error> {
        loop {
            self.data_fast(input, at);
            if self.pos >= WIN {
                return Ok(Some(Stop::Room));
            }
            self.refill(input, at);
            let Some((symbol, n)) = self.lit.decode(self.bits, self.count)? else {
                return Ok(Some(Stop::Input));
            };
            if symbol < 256 {
                self.drop_bits(n);
                self.window[self.pos] = symbol as u8;
                self.pos += 1;
                self.total += 1;
                // Literals come in runs; a second short one usually fits in the bits already buffered.
                let entry = self.lit.fast[(self.bits & ((1 << FAST_BITS) - 1)) as usize];
                let n = u32::from(entry & 15);
                if entry >> 4 < 256 && entry != 0 && n <= self.count && self.pos < WIN {
                    self.drop_bits(n);
                    self.window[self.pos] = (entry >> 4) as u8;
                    self.pos += 1;
                    self.total += 1;
                }
                continue;
            }
            if symbol == 256 {
                self.drop_bits(n);
                self.state = self.next_block();
                return Ok(None);
            }
            let index = symbol - 257;
            if index >= 29 {
                return Err(Error::Symbol);
            }
            let extra = u32::from(self.len_extra[index]);
            if self.count < n + extra {
                return Ok(Some(Stop::Input));
            }
            let len = u32::from(self.len_base[index]) + ((self.bits >> n) & mask(extra)) as u32;
            self.drop_bits(n + extra);
            #[cfg(test)]
            if index == 28 {
                self.seen.code285 += 1;
            }
            if let Some(stop) = self.distance(input, at, len)? {
                return Ok(Some(stop));
            }
        }
    }

    /// The common case without any suspend points: plenty of input, short codes, matches that fit. It stops, with
    /// nothing of the symbol consumed, at anything else (the end of the block, a long or invalid code, a match that
    /// does not fit or reaches too far back), which the general loop then handles.
    #[inline(always)]
    fn data_fast(&mut self, input: &[u8], at: &mut usize) {
        let (mut bits, mut count, mut pos, mut i) = (self.bits, self.count, self.pos, *at);
        let before = self.total - pos as u64;
        let fast = (1 << FAST_BITS) - 1;
        let (window, lit, dist_table) = (&mut self.window[..], &self.lit.fast, &self.dist.fast);
        let (len_base, len_extra, dist_codes) = (&self.len_base, &self.len_extra, self.dist_codes);
        #[cfg(test)]
        let seen = &mut self.seen;
        // Two 8-byte refills per symbol need 16 bytes of input.
        while input.len() - i >= 16 && pos < WIN {
            let refill = |bits: &mut u64, count: &mut u32, i: &mut usize| {
                let word = u64::from_le_bytes(input[*i..*i + 8].try_into().expect("eight bytes"));
                *bits |= word << *count;
                let bytes = (63 - *count) >> 3;
                *i += bytes as usize;
                *count += bytes * 8;
                *bits &= mask(*count);
            };
            refill(&mut bits, &mut count, &mut i);
            let entry = lit[(bits & fast) as usize];
            let (symbol, n) = (usize::from(entry >> 4), u32::from(entry & 15));
            if entry == 0 || symbol == 256 || symbol > 285 {
                break;
            }
            if symbol < 256 {
                window[pos] = symbol as u8;
                pos += 1;
                (bits, count) = (bits >> n, count - n);
                // Two more short literals fit in the 46+ bits left without a refill.
                for _ in 0..2 {
                    let entry = lit[(bits & fast) as usize];
                    if entry == 0 || entry >> 4 >= 256 || pos >= WIN {
                        break;
                    }
                    window[pos] = (entry >> 4) as u8;
                    pos += 1;
                    let n = u32::from(entry & 15);
                    (bits, count) = (bits >> n, count - n);
                }
                continue;
            }
            let index = symbol - 257;
            let extra = u32::from(len_extra[index]);
            let len = u32::from(len_base[index]) + ((bits >> n) & mask(extra)) as u32;
            let (mut bits2, mut count2, mut i2) = (bits >> (n + extra), count - n - extra, i);
            refill(&mut bits2, &mut count2, &mut i2);
            let entry = dist_table[(bits2 & fast) as usize];
            let (symbol, dn) = (usize::from(entry >> 4), u32::from(entry & 15));
            if entry == 0 || symbol >= dist_codes {
                break;
            }
            let dx = u32::from(DIST_EXTRA[symbol]);
            let dist = DIST_BASE[symbol] + ((bits2 >> dn) & mask(dx)) as u32;
            if u64::from(dist) > before + pos as u64 || len as usize > WIN - pos {
                break;
            }
            #[cfg(test)]
            {
                seen.matched(len, dist);
                seen.code285 += u32::from(index == 28);
            }
            (bits, count, i) = (bits2 >> (dn + dx), count2 - dn - dx, i2);
            copy_match(window, pos, dist as usize, len as usize);
            pos += len as usize;
        }
        (self.bits, self.count, self.pos, *at) = (bits, count, pos, i);
        self.total = before + pos as u64;
    }

    /// Decodes a distance for a match of `len` and copies it. `None` when the match is done (state is `Data`) or
    /// was cut short by a full window (state is `Copy`, and the caller sees `Room` next time round).
    #[inline(always)]
    fn distance(&mut self, input: &[u8], at: &mut usize, len: u32) -> Result<Option<Stop>, Error> {
        self.refill(input, at);
        let Some((symbol, n)) = self.dist.decode(self.bits, self.count)? else {
            self.state = State::Distance(len);
            return Ok(Some(Stop::Input));
        };
        if symbol >= self.dist_codes {
            return Err(Error::Symbol);
        }
        let extra = u32::from(DIST_EXTRA[symbol]);
        if self.count < n + extra {
            self.state = State::Distance(len);
            return Ok(Some(Stop::Input));
        }
        let dist = DIST_BASE[symbol] + ((self.bits >> n) & mask(extra)) as u32;
        self.drop_bits(n + extra);
        if u64::from(dist) > self.total {
            return Err(Error::Distance);
        }
        #[cfg(test)]
        self.seen.matched(len, dist);
        self.state = State::Data;
        Ok(self.copy(len, dist))
    }

    /// Copies a match into the window; what does not fit stays in `State::Copy`.
    #[inline(always)]
    fn copy(&mut self, len: u32, dist: u32) -> Option<Stop> {
        let room = WIN - self.pos;
        let n = (len as usize).min(room);
        copy_match(&mut self.window, self.pos, dist as usize, n);
        self.pos += n;
        self.total += n as u64;
        if n < len as usize {
            self.state = State::Copy { len: len - n as u32, dist };
            return Some(Stop::Room);
        }
        None
    }
}

#[inline(always)]
fn mask(bits: u32) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// LZ77 copy of `n` bytes from `dist` back to `dst`, byte-for-byte semantics. `buf` has `SLACK` bytes past where
/// the copy may end, so distances of 8 and up copy whole 8- or 16-byte chunks that may run past `dst + n`.
#[inline(always)]
fn copy_match(buf: &mut [u8], dst: usize, dist: usize, n: usize) {
    let src = dst - dist;
    if dist >= n {
        if n <= 32 && dist >= 16 {
            chunks(buf, src, dst, n);
        } else {
            buf.copy_within(src..src + n, dst);
        }
    } else if dist >= 16 {
        chunks(buf, src, dst, n);
    } else if dist >= 8 {
        let end = dst + n;
        let (mut src, mut dst) = (src, dst);
        while dst < end {
            let word: [u8; 8] = buf[src..src + 8].try_into().expect("eight bytes");
            buf[dst..dst + 8].copy_from_slice(&word);
            src += 8;
            dst += 8;
        }
    } else if dist == 1 {
        let byte = buf[src];
        buf[dst..dst + n].fill(byte);
    } else {
        for i in 0..n {
            buf[dst + i] = buf[src + i];
        }
    }
}

/// Copies 16 bytes at a time, possibly past `dst + n`; needs `dist >= 16` so no chunk reads bytes it writes.
#[inline(always)]
fn chunks(buf: &mut [u8], mut src: usize, mut dst: usize, n: usize) {
    let end = dst + n;
    while dst < end {
        let (head, tail) = buf.split_at_mut(dst);
        tail[..16].copy_from_slice(&head[src..src + 16]);
        src += 16;
        dst += 16;
    }
}

/// [`Inflater`] over a buffered reader. Decode errors are `io::ErrorKind::InvalidData` carrying an [`Error`]; input
/// that ends before the stream does is `UnexpectedEof`; errors from the reader pass through unchanged. Bytes after
/// the stream's end are left unread in the inner reader.
pub struct Inflate64Reader<R> {
    inner: R,
    inflater: Box<Inflater>,
}

impl<R: BufRead> Inflate64Reader<R> {
    /// A Deflate64 reader.
    pub fn new(inner: R) -> Self {
        Self::with_variant(inner, Variant::Deflate64)
    }

    /// A reader for either variant.
    pub fn with_variant(inner: R, variant: Variant) -> Self {
        Self { inner, inflater: Inflater::new(variant) }
    }

    /// The inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> Read for Inflate64Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let input = self.inner.fill_buf()?;
            let eof = input.is_empty();
            let step = self.inflater.step(input, buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            self.inner.consume(step.consumed);
            if step.produced != 0 || step.done {
                return Ok(step.produced);
            }
            if eof {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "deflate stream ends early"));
            }
        }
    }
}

#[cfg(test)]
mod tests;
