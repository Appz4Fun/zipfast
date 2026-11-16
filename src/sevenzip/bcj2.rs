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

//! BCJ2, the four-stream x86 converter (`0x0303011B`). The main stream carries the code with the 4-byte targets of
//! converted `CALL` (E8) and `JMP` (E9, and `0F 8x` Jcc) instructions taken out; those absolute targets sit big-endian
//! in the call and jump streams, and a range-coded bit stream says, per candidate opcode, whether it was converted.
//! The decoder puts each target back as an offset relative to the end of its instruction. Written from 7-Zip's
//! `7zFormat.txt` and the LZMA SDK's description of the format.
use std::io::{self, BufRead, Read};

use super::coders::data_error;

/// Probabilities: one per previous byte for E8, one for E9, one for Jcc.
const PROBS: usize = 258;
const TOP: u32 = 1 << 24;

pub(crate) struct Bcj2Reader<R> {
    main: R,
    call: R,
    jump: R,
    rc: R,
    range: u32,
    code: u32,
    started: bool,
    probs: [u16; PROBS],
    prev: u8,
    /// Output position: bytes handed out so far, counting the pending ones.
    pos: u32,
    /// A restored target waiting to be handed out.
    pending: [u8; 4],
    pending_at: usize,
    pending_len: usize,
    /// The last main byte was a candidate opcode whose bit has not been decoded yet.
    candidate: Option<u8>,
}

impl<R: BufRead> Bcj2Reader<R> {
    /// The inputs in the coder's stream order: main, call, jump, range coder.
    pub(crate) fn new(main: R, call: R, jump: R, rc: R) -> Self {
        Self {
            main,
            call,
            jump,
            rc,
            range: 0xFFFF_FFFF,
            code: 0,
            started: false,
            probs: [1024; PROBS],
            prev: 0,
            pos: 0,
            pending: [0; 4],
            pending_at: 0,
            pending_len: 0,
            candidate: None,
        }
    }

    fn rc_byte(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        match self.rc.read(&mut b)? {
            0 => Err(data_error("BCJ2 range coder stream ends early")),
            _ => Ok(b[0]),
        }
    }

    fn bit(&mut self, index: usize) -> io::Result<bool> {
        if !self.started {
            for _ in 0..5 {
                self.code = (self.code << 8) | u32::from(self.rc_byte()?);
            }
            self.started = true;
        }
        if self.range < TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.rc_byte()?);
        }
        let p = u32::from(self.probs[index]);
        let bound = (self.range >> 11) * p;
        if self.code < bound {
            self.range = bound;
            self.probs[index] = (p + ((2048 - p) >> 5)) as u16;
            Ok(false)
        } else {
            self.range -= bound;
            self.code -= bound;
            self.probs[index] = (p - (p >> 5)) as u16;
            Ok(true)
        }
    }

    /// Restores the target after candidate opcode `b`, if its bit says it was converted.
    fn settle(&mut self, b: u8) -> io::Result<()> {
        let index = match b {
            0xE8 => usize::from(self.prev),
            0xE9 => 256,
            _ => 257,
        };
        if !self.bit(index)? {
            self.prev = b;
            return Ok(());
        }
        let mut target = [0u8; 4];
        let source = if b == 0xE8 { &mut self.call } else { &mut self.jump };
        source.read_exact(&mut target).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof { data_error("BCJ2 call or jump stream ends early") } else { e }
        })?;
        let dest = u32::from_be_bytes(target).wrapping_sub(self.pos.wrapping_add(4));
        self.pending = dest.to_le_bytes();
        self.pending_at = 0;
        self.pending_len = 4;
        self.pos = self.pos.wrapping_add(4);
        self.prev = self.pending[3];
        Ok(())
    }
}

fn is_candidate(prev: u8, b: u8) -> bool {
    b & 0xFE == 0xE8 || (prev == 0x0F && b & 0xF0 == 0x80)
}

impl<R: BufRead> Read for Bcj2Reader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(b) = self.candidate.take() {
            self.settle(b)?;
        }
        if self.pending_at < self.pending_len {
            let n = (self.pending_len - self.pending_at).min(out.len());
            out[..n].copy_from_slice(&self.pending[self.pending_at..self.pending_at + n]);
            self.pending_at += n;
            return Ok(n);
        }
        let chunk = self.main.fill_buf()?;
        if chunk.is_empty() {
            return Ok(0);
        }
        // Copy plain bytes up to and including the next candidate opcode.
        let limit = chunk.len().min(out.len());
        let mut n = 0;
        let mut prev = self.prev;
        let mut found = None;
        while n < limit {
            let b = chunk[n];
            out[n] = b;
            n += 1;
            if is_candidate(prev, b) {
                found = Some(b);
                break;
            }
            prev = b;
        }
        self.main.consume(n);
        self.pos = self.pos.wrapping_add(n as u32);
        // `prev` is the byte before the candidate, which picks an E8's probability.
        self.prev = prev;
        // The bit is decoded on the next call, so a read that stops right after the opcode needs no target yet: the
        // stream may legitimately end there.
        self.candidate = found;
        Ok(n)
    }
}
