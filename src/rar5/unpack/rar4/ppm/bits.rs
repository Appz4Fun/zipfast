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

//! What RAR's decoders since 2.0 share: big-endian bits, and Huffman tables in RAR's form.

/// Big-endian bits from a byte slice, past whose end reads give zeros: the caller checks `past_end`.
pub(crate) struct Bits<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) addr: usize,
    pub(crate) bit: u32,
}

impl Bits<'_> {
    fn byte(&self, at: usize) -> u32 {
        u32::from(self.data.get(at).copied().unwrap_or(0))
    }

    /// The next 16 bits, not consumed.
    pub(crate) fn peek16(&self) -> u32 {
        let v = (self.byte(self.addr) << 16) | (self.byte(self.addr + 1) << 8) | self.byte(self.addr + 2);
        (v >> (8 - self.bit)) & 0xffff
    }

    pub(crate) fn skip(&mut self, n: u32) {
        let total = self.bit + n;
        self.addr += (total >> 3) as usize;
        self.bit = total & 7;
    }

    pub(crate) fn take(&mut self, n: u32) -> u32 {
        let v = self.peek16() >> (16 - n);
        self.skip(n);
        v
    }

    pub(crate) fn past_end(&self) -> bool {
        self.addr > self.data.len() || (self.addr == self.data.len() && self.bit > 0)
    }
}
