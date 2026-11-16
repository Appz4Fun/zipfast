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

//! RAR 1.5 (unpack version 15) and RAR 2.0 (20, and 26 for files past 2 GiB) compression, including 2.0's audio
//! blocks, as engines the RAR4 decoder steps one code at a time over buffered input. Ported from RustyGet's
//! `archive_native/{rar15,rar20,rarbits}.rs`.
#![allow(clippy::needless_range_loop, reason = "kept close to the original's indexed loops")]

use super::ppm::Bits;
use super::{DecodeResult, Rar4DecodeError};

/// Where an engine's output goes: the decoder's window and sink, at most to the member's end.
pub(super) trait Out {
    fn put(&mut self, byte: u8) -> DecodeResult<()>;
    /// Copies `len` bytes from `dist` back. `lenient`: a distance before the start writes zeros, as RAR 1.5 does.
    fn copy(&mut self, dist: u32, len: u32, lenient: bool) -> DecodeResult<()>;
}

pub(super) enum Engine {
    V15(Box<V15>),
    V20(Box<V20>),
}

impl Engine {
    pub(super) fn new(version: u8) -> Option<Self> {
        match version {
            15 => Some(Self::V15(Box::default())),
            20 | 26 => Some(Self::V20(Box::default())),
            _ => None,
        }
    }

    /// A member starts, new or going on from the one before.
    pub(super) fn start_member(&mut self, unpacked: u64) {
        match self {
            Self::V15(v) => {
                v.flags_cnt = 0;
                v.flag_buf = 0;
                v.st_mode = false;
                v.l_count = 0;
                v.need_flags = unpacked > 0;
            }
            Self::V20(v) => v.tables_left = 1024u64.saturating_add(unpacked / 4096),
        }
    }

    /// One code: a literal, a match or new tables.
    pub(super) fn step(&mut self, b: &mut Bits<'_>, out: &mut dyn Out) -> DecodeResult<()> {
        match self {
            Self::V15(v) => v.step(b, out),
            Self::V20(v) => v.step(b, out),
        }
    }

    /// Past a member's output in a solid stream: new tables written right after it belong to the next member.
    pub(super) fn member_end(&mut self, b: &mut Bits<'_>) {
        if let Self::V20(v) = self {
            v.member_end(b);
        }
    }
}

// ---- RAR 1.5

const DEC_L1: &[u32] = &[0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff];
const POS_L1: [u32; 13] = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const DEC_L2: &[u32] = &[0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff];
const POS_L2: [u32; 13] = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const DEC_HF0: &[u32] = &[0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff];
const POS_HF0: [u32; 13] = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const DEC_HF1: &[u32] = &[0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff];
const POS_HF1: [u32; 13] = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const DEC_HF2: &[u32] = &[0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff];
const POS_HF2: [u32; 13] = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const DEC_HF3: &[u32] = &[0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const DEC_HF4: &[u32] = &[0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

type Code = (u32, &'static [u32], &'static [u32; 13]);
const L1: Code = (2, DEC_L1, &POS_L1);
const L2: Code = (3, DEC_L2, &POS_L2);
const HF0: Code = (4, DEC_HF0, &POS_HF0);
const HF1: Code = (5, DEC_HF1, &POS_HF1);
const HF2: Code = (5, DEC_HF2, &POS_HF2);
const HF3: Code = (6, DEC_HF3, &POS_HF3);
const HF4: Code = (8, DEC_HF4, &POS_HF4);

const SHORT_LEN1: [u32; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u32; 15] = [0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];
const SHORT_LEN2: [u32; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u32; 15] = [0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];

pub(super) struct V15 {
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    num_huf: u32,
    buf60: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    flags_cnt: i32,
    flag_buf: u32,
    st_mode: bool,
    l_count: u32,
    need_flags: bool,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_len: u32,
}

impl Default for V15 {
    fn default() -> Self {
        let mut v = Self {
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            num_huf: 0,
            buf60: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            flags_cnt: 0,
            flag_buf: 0,
            st_mode: false,
            l_count: 0,
            need_flags: false,
            old_dist: [0; 4],
            old_dist_ptr: 0,
            last_dist: 0,
            last_len: 0,
        };
        for i in 0..256u16 {
            v.ch_set[usize::from(i)] = i << 8;
            v.ch_set_b[usize::from(i)] = i << 8;
            v.ch_set_a[usize::from(i)] = i;
            v.ch_set_c[usize::from(i)] = ((256 - i) & 0xff) << 8;
        }
        corr_huff(&mut v.ch_set_b, &mut v.n_to_pl_b);
        v
    }
}

impl V15 {
    fn step(&mut self, b: &mut Bits<'_>, out: &mut dyn Out) -> DecodeResult<()> {
        if self.need_flags {
            self.need_flags = false;
            self.get_flags(b);
            self.flags_cnt = 8;
            return Ok(());
        }
        if self.st_mode {
            return self.huff_decode(b, out);
        }
        self.flags_cnt -= 1;
        if self.flags_cnt < 0 {
            self.get_flags(b);
            self.flags_cnt = 7;
        }
        if self.flag_buf & 0x80 != 0 {
            self.flag_buf <<= 1;
            return if self.nlzb > self.nhfb { self.long_lz(b, out) } else { self.huff_decode(b, out) };
        }
        self.flag_buf <<= 1;
        self.flags_cnt -= 1;
        if self.flags_cnt < 0 {
            self.get_flags(b);
            self.flags_cnt = 7;
        }
        if self.flag_buf & 0x80 != 0 {
            self.flag_buf <<= 1;
            if self.nlzb > self.nhfb { self.huff_decode(b, out) } else { self.long_lz(b, out) }
        } else {
            self.flag_buf <<= 1;
            self.short_lz(b, out)
        }
    }
}

fn corr_huff(set: &mut [u16; 256], to_place: &mut [u8; 256]) {
    for (n, c) in set.iter_mut().enumerate() {
        *c = (*c & !0xff) | (7 - (n / 32) as u16);
    }
    to_place.fill(0);
    for (i, p) in to_place.iter_mut().take(7).enumerate() {
        *p = ((7 - i) * 32) as u8;
    }
}

impl V15 {
    fn decode_num(b: &mut Bits<'_>, num: u32, code: Code) -> u32 {
        let (mut start, dec, pos) = code;
        let num = num & 0xfff0;
        let mut i = 0;
        while i < dec.len() && dec[i] <= num {
            start += 1;
            i += 1;
        }
        b.skip(start);
        let base = if i > 0 { dec[i - 1] } else { 0 };
        ((num - base) >> (16 - start)) + pos.get(start as usize).copied().unwrap_or(0)
    }

    fn remember(&mut self, dist: u32, len: u32) {
        self.old_dist[self.old_dist_ptr] = dist;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_len = len;
        self.last_dist = dist;
    }

    fn short_lz(&mut self, b: &mut Bits<'_>, out: &mut dyn Out) -> DecodeResult<()> {
        self.num_huf = 0;
        let mut field = b.peek16();
        if self.l_count == 2 {
            b.skip(1);
            if field >= 0x8000 {
                return out.copy(self.last_dist, self.last_len, true);
            }
            field <<= 1;
            self.l_count = 0;
        }
        let field = (field >> 8) & 0xff;
        let (lens, xors) = if self.avr_ln1 < 37 { (SHORT_LEN1, SHORT_XOR1) } else { (SHORT_LEN2, SHORT_XOR2) };
        let special = if self.avr_ln1 < 37 { 1 } else { 3 };
        let len_of = |i: usize| {
            if i == special { self.buf60 + 3 } else { lens[i] }
        };
        let mut length = 0usize;
        while length < xors.len() && ((field ^ xors[length]) & !(0xff >> len_of(length)) & 0xff) != 0 {
            length += 1;
        }
        if length == xors.len() {
            // no code matches: only damaged data gets here
            return Err(Rar4DecodeError::Malformed("RAR 1.5 short match code"));
        }
        let n = len_of(length);
        b.skip(n);
        let mut length = length as u32;
        if length >= 9 {
            if length == 9 {
                self.l_count += 1;
                return out.copy(self.last_dist, self.last_len, true);
            }
            if length == 14 {
                self.l_count = 0;
                let field = b.peek16();
                let len = Self::decode_num(b, field, L2) + 5;
                let dist = (b.peek16() >> 1) | 0x8000;
                b.skip(15);
                self.last_len = len;
                self.last_dist = dist;
                return out.copy(dist, len, true);
            }
            self.l_count = 0;
            let saved = length;
            let dist = self.old_dist[self.old_dist_ptr.wrapping_sub((length - 9) as usize) & 3];
            let field = b.peek16();
            length = Self::decode_num(b, field, L1) + 2;
            if length == 0x101 && saved == 10 {
                self.buf60 ^= 1;
                return Ok(());
            }
            if dist > 256 {
                length += 1;
            }
            if dist >= self.max_dist3 {
                length += 1;
            }
            self.remember(dist, length);
            return out.copy(dist, length, true);
        }
        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;
        let field = b.peek16();
        let place = (Self::decode_num(b, field, HF2) & 0xff) as usize;
        let mut dist = u32::from(self.ch_set_a[place]);
        if place > 0 {
            let last = self.ch_set_a[place - 1];
            self.ch_set_a[place] = last;
            self.ch_set_a[place - 1] = dist as u16;
        }
        length += 2;
        dist += 1;
        self.remember(dist, length);
        out.copy(dist, length, true)
    }

    fn long_lz(&mut self, b: &mut Bits<'_>, out: &mut dyn Out) -> DecodeResult<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;
        let field = b.peek16();
        let mut length = if self.avr_ln2 >= 122 {
            Self::decode_num(b, field, L2)
        } else if self.avr_ln2 >= 64 {
            Self::decode_num(b, field, L1)
        } else if field < 0x100 {
            b.skip(16);
            field
        } else {
            let n = (field << 16).leading_zeros();
            b.skip(n + 1);
            n
        };
        self.avr_ln2 += length;
        self.avr_ln2 -= self.avr_ln2 >> 5;
        let field = b.peek16();
        let place = if self.avr_plc_b > 0x28ff {
            Self::decode_num(b, field, HF2)
        } else if self.avr_plc_b > 0x6ff {
            Self::decode_num(b, field, HF1)
        } else {
            Self::decode_num(b, field, HF0)
        };
        self.avr_plc_b += place;
        self.avr_plc_b -= self.avr_plc_b >> 8;
        let place = (place & 0xff) as usize;
        let (mut dist, mut new_place);
        loop {
            dist = u32::from(self.ch_set_b[place]);
            let slot = &mut self.n_to_pl_b[(dist & 0xff) as usize];
            new_place = usize::from(*slot);
            *slot = slot.wrapping_add(1);
            dist += 1;
            if dist & 0xff == 0 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }
        self.ch_set_b[place] = self.ch_set_b[new_place];
        self.ch_set_b[new_place] = dist as u16;
        let dist = ((dist & 0xff00) | (b.peek16() >> 8)) >> 1;
        b.skip(7);
        let old_avr3 = self.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && dist <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        length += 3;
        if dist >= self.max_dist3 {
            length += 1;
        }
        if dist <= 256 {
            length += 8;
        }
        self.max_dist3 = if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) { 0x7f00 } else { 0x2001 };
        self.remember(dist, length);
        out.copy(dist, length, true)
    }

    fn huff_decode(&mut self, b: &mut Bits<'_>, out: &mut dyn Out) -> DecodeResult<()> {
        let field = b.peek16();
        let code = match self.avr_plc {
            0x7600.. => HF4,
            0x5e00.. => HF3,
            0x3600.. => HF2,
            0x0e00.. => HF1,
            _ => HF0,
        };
        let mut place = (Self::decode_num(b, field, code) & 0xff) as i32;
        if self.st_mode {
            if place == 0 && field > 0xfff {
                place = 0x100;
            }
            place -= 1;
            if place == -1 {
                let field = b.peek16();
                b.skip(1);
                if field & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = false;
                    return Ok(());
                }
                let len = if field & 0x4000 != 0 { 4 } else { 3 };
                b.skip(1);
                let f = b.peek16();
                let dist = Self::decode_num(b, f, HF2);
                let dist = (dist << 5) | (b.peek16() >> 11);
                b.skip(5);
                return out.copy(dist, len, true);
            }
        } else {
            let n = self.num_huf;
            self.num_huf += 1;
            if n >= 16 && self.flags_cnt == 0 {
                self.st_mode = true;
            }
        }
        let place = place as usize & 0xff;
        self.avr_plc += place as u32;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }
        out.put((self.ch_set[place] >> 8) as u8)?;
        let (mut cur, mut new_place);
        loop {
            cur = u32::from(self.ch_set[place]);
            let slot = &mut self.n_to_pl[(cur & 0xff) as usize];
            new_place = usize::from(*slot);
            *slot = slot.wrapping_add(1);
            cur += 1;
            if cur & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }
        self.ch_set[place] = self.ch_set[new_place];
        self.ch_set[new_place] = cur as u16;
        Ok(())
    }

    fn get_flags(&mut self, b: &mut Bits<'_>) {
        let field = b.peek16();
        let place = Self::decode_num(b, field, HF2) as usize;
        if place >= 256 {
            return;
        }
        let (mut flags, mut new_place);
        loop {
            flags = u32::from(self.ch_set_c[place]);
            self.flag_buf = flags >> 8;
            let slot = &mut self.n_to_pl_c[(flags & 0xff) as usize];
            new_place = usize::from(*slot);
            *slot = slot.wrapping_add(1);
            flags += 1;
            if flags & 0xff != 0 {
                break;
            }
            corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
        }
        self.ch_set_c[place] = self.ch_set_c[new_place];
        self.ch_set_c[new_place] = flags as u16;
    }
}

// ---- RAR 2.0

const NC: usize = 298;
const DC: usize = 48;
const RC: usize = 28;
const BC: usize = 19;
const MC: usize = 257;

const LDECODE: [u8; 28] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LBITS: [u8; 28] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const DDECODE: [u32; DC] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144,
    8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680, 393216, 458752, 524288,
    589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const DBITS: [u8; DC] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
const SDDECODE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

#[derive(Default, Clone, Copy)]
struct Audio {
    k: [i32; 5],
    d: [i32; 4],
    last_delta: i32,
    dif: [u32; 11],
    count: u32,
    last: u32,
}

enum Blocks {
    Lz(Box<[Table; 3]>),
    Audio(Vec<Table>),
}

pub(super) struct V20 {
    old_table: [u8; MC * 4],
    reps: [u32; 4],
    rep_at: usize,
    last_dist: u32,
    last_len: u32,
    audio: [Audio; 4],
    channel: usize,
    channel_delta: i32,
    blocks: Option<Blocks>,
    /// new tables still allowed: each is work that makes no output
    tables_left: u64,
}

impl Default for V20 {
    fn default() -> Self {
        Self {
            old_table: [0; MC * 4],
            reps: [0; 4],
            rep_at: 0,
            last_dist: 0,
            last_len: 0,
            audio: [Audio::default(); 4],
            channel: 0,
            channel_delta: 0,
            blocks: None,
            tables_left: 1024,
        }
    }
}

impl V20 {
    fn step(&mut self, b: &mut Bits<'_>, out: &mut dyn Out) -> DecodeResult<()> {
        let Some(blocks) = &self.blocks else {
            self.blocks = Some(self.read_tables(b)?);
            return Ok(());
        };
        if let Blocks::Audio(tables) = blocks {
            let table = tables.get(self.channel).ok_or(Rar4DecodeError::Malformed("RAR 2.0 audio channel"))?;
            let n = table.decode(b);
            if n == 256 {
                self.blocks = Some(self.read_tables(b)?);
                return Ok(());
            }
            let channels = tables.len();
            let byte = self.decode_audio(n as u8);
            self.channel += 1;
            if self.channel == channels {
                self.channel = 0;
            }
            return out.put(byte);
        }
        let Blocks::Lz(lz) = blocks else { unreachable!() };
        let [ld, dd, rd] = &**lz;
        let number = usize::from(ld.decode(b));
        if number < 256 {
            return out.put(number as u8);
        }
        let (len, dist) = if number > 269 {
            let n = (number - 270).min(LDECODE.len() - 1);
            let mut len = u32::from(LDECODE[n]) + 3 + b.take(u32::from(LBITS[n]));
            let slot = usize::from(dd.decode(b)).min(DC - 1);
            let dist = DDECODE[slot] + 1 + b.take(u32::from(DBITS[slot]));
            if dist >= 0x2000 {
                len += 1;
                if dist >= 0x40000 {
                    len += 1;
                }
            }
            (len, dist)
        } else if number == 269 {
            self.blocks = Some(self.read_tables(b)?);
            return Ok(());
        } else if number == 256 {
            (self.last_len, self.last_dist)
        } else if number < 261 {
            let dist = self.reps[(self.rep_at.wrapping_sub(number - 256)) & 3];
            let slot = usize::from(rd.decode(b)).min(RC - 1);
            let mut len = u32::from(LDECODE[slot]) + 2 + b.take(u32::from(LBITS[slot]));
            if dist >= 0x101 {
                len += 1;
                if dist >= 0x2000 {
                    len += 1;
                    if dist >= 0x40000 {
                        len += 1;
                    }
                }
            }
            (len, dist)
        } else {
            let n = number - 261;
            (2, u32::from(SDDECODE[n]) + 1 + b.take(u32::from(SDBITS[n])))
        };
        self.last_dist = dist;
        self.reps[self.rep_at] = dist;
        self.rep_at = (self.rep_at + 1) & 3;
        self.last_len = len;
        if len == 0 {
            return Ok(());
        }
        out.copy(dist, len, false)
    }

    fn member_end(&mut self, b: &mut Bits<'_>) {
        let ends = match &self.blocks {
            Some(Blocks::Audio(tables)) => tables.get(self.channel).is_some_and(|t| t.decode(b) == 256),
            Some(Blocks::Lz(lz)) => lz[0].decode(b) == 269,
            None => false,
        };
        if ends && let Ok(blocks) = self.read_tables(b) {
            self.blocks = Some(blocks);
        }
    }

    fn read_tables(&mut self, b: &mut Bits<'_>) -> DecodeResult<Blocks> {
        self.tables_left =
            self.tables_left.checked_sub(1).ok_or(Rar4DecodeError::Malformed("RAR 2.0 tables without output"))?;
        let bad = || Rar4DecodeError::Malformed("RAR 2.0 tables");
        let field = b.peek16();
        let audio = field & 0x8000 != 0;
        if field & 0x4000 == 0 {
            self.old_table = [0; MC * 4];
        }
        b.skip(2);
        let size = if audio {
            let channels = ((field >> 12) & 3) as usize + 1;
            if self.channel >= channels {
                self.channel = 0;
            }
            b.skip(2);
            MC * channels
        } else {
            NC + DC + RC
        };
        let mut lengths = [0u8; BC];
        for l in &mut lengths {
            *l = b.take(4) as u8;
        }
        let bd = Table::new(&lengths).ok_or_else(bad)?;
        let mut table = [0u8; MC * 4];
        let mut i = 0;
        while i < size {
            if b.past_end() {
                return Err(bad());
            }
            let n = bd.decode(b);
            match n {
                0..=15 => {
                    table[i] = (n as u8 + self.old_table[i]) & 15;
                    i += 1;
                }
                16 => {
                    let times = b.take(2) as usize + 3;
                    let prev = table[i.checked_sub(1).ok_or_else(bad)?];
                    let end = (i + times).min(size);
                    table[i..end].fill(prev);
                    i = end;
                }
                _ => {
                    let times = if n == 17 { b.take(3) + 3 } else { b.take(7) + 11 } as usize;
                    let end = (i + times).min(size);
                    table[i..end].fill(0);
                    i = end;
                }
            }
        }
        if b.past_end() {
            return Err(bad());
        }
        self.old_table[..size].copy_from_slice(&table[..size]);
        Ok(if audio {
            Blocks::Audio(table[..size].chunks(MC).map(Table::new).collect::<Option<Vec<_>>>().ok_or_else(bad)?)
        } else {
            Blocks::Lz(Box::new([
                Table::new(&table[..NC]).ok_or_else(bad)?,
                Table::new(&table[NC..NC + DC]).ok_or_else(bad)?,
                Table::new(&table[NC + DC..NC + DC + RC]).ok_or_else(bad)?,
            ]))
        })
    }

    fn decode_audio(&mut self, delta: u8) -> u8 {
        let v = &mut self.audio[self.channel];
        v.count += 1;
        v.d[3] = v.d[2];
        v.d[2] = v.d[1];
        v.d[1] = v.last_delta - v.d[0];
        v.d[0] = v.last_delta;
        let p = (8 * v.last as i32)
            .wrapping_add(v.k[0].wrapping_mul(v.d[0]))
            .wrapping_add(v.k[1].wrapping_mul(v.d[1]))
            .wrapping_add(v.k[2].wrapping_mul(v.d[2]))
            .wrapping_add(v.k[3].wrapping_mul(v.d[3]))
            .wrapping_add(v.k[4].wrapping_mul(self.channel_delta));
        let p = ((p >> 3) & 0xff) as u32;
        let ch = p.wrapping_sub(u32::from(delta));
        let d = i32::from(delta as i8) << 3;
        let cd = self.channel_delta;
        let [d1, d2, d3, d4] = v.d;
        for (j, x) in [d1, d2, d3, d4, cd].into_iter().enumerate() {
            v.dif[1 + 2 * j] = v.dif[1 + 2 * j].wrapping_add(d.wrapping_sub(x).unsigned_abs());
            v.dif[2 + 2 * j] = v.dif[2 + 2 * j].wrapping_add(d.wrapping_add(x).unsigned_abs());
        }
        v.dif[0] = v.dif[0].wrapping_add(d.unsigned_abs());
        v.last_delta = i32::from((ch.wrapping_sub(v.last)) as u8 as i8);
        self.channel_delta = v.last_delta;
        v.last = ch & 0xff;
        if v.count & 0x1f == 0 {
            let [k1, k2, k3, k4, k5] = &mut v.k;
            adapt(&mut v.dif, &mut [k1, k2, k3, k4, k5]);
        }
        ch as u8
    }
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

/// A canonical Huffman table in RAR's form: thresholds per length, and the symbols in code order.
#[derive(Default, Clone)]
pub(super) struct Table {
    decode_len: [u32; 16],
    decode_pos: [u32; 16],
    decode_num: Vec<u16>,
}

impl Table {
    pub(super) fn new(lengths: &[u8]) -> Option<Table> {
        let mut count = [0u32; 16];
        for &l in lengths {
            count[usize::from(l & 15)] += 1;
        }
        count[0] = 0;
        let mut t = Table { decode_num: vec![0; lengths.len()], ..Table::default() };
        let mut upper = 0u32;
        for i in 1..16 {
            upper += count[i];
            t.decode_len[i] = upper << (16 - i);
            t.decode_pos[i] = t.decode_pos[i - 1] + count[i - 1];
            upper <<= 1;
        }
        if upper > 1 << 16 {
            return None;
        }
        let mut next = t.decode_pos;
        for (s, &l) in lengths.iter().enumerate() {
            let l = usize::from(l & 15);
            if l > 0 {
                t.decode_num[next[l] as usize] = s as u16;
                next[l] += 1;
            }
        }
        Some(t)
    }

    pub(super) fn decode(&self, bits: &mut Bits<'_>) -> u16 {
        let field = bits.peek16() & 0xfffe;
        let mut len = 15;
        for i in 1..15 {
            if field < self.decode_len[i] {
                len = i;
                break;
            }
        }
        bits.skip(len as u32);
        let dist = (field - self.decode_len[len - 1]) >> (16 - len);
        let pos = (self.decode_pos[len] + dist) as usize;
        self.decode_num.get(pos).copied().unwrap_or(0)
    }
}
