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

//! XPRESS with Huffman coding ("LZ77+Huffman"), as Microsoft's [MS-XCA] specifies it (section 2.2), for the
//! chunks of a WIM resource. A WIM chunk holds at most 64 KiB, so it is one block: a 256-byte table of 512 4-bit
//! code lengths, then a stream of 16-bit little-endian words read most significant bit first, with the bytes of
//! long match lengths between them.
//!
//! [MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/

/// The longest a code may be, and so the bits a table lookup takes.
const MAX_LEN: u32 = 15;
/// The most a chunk may hold: one block's worth.
pub(super) const MAX_CHUNK: usize = 1 << 16;

/// Decodes the chunk `input` into `out`, which ends up exactly `size` bytes long.
pub(super) fn decompress(input: &[u8], size: usize, out: &mut Vec<u8>) -> Result<(), &'static str> {
    const BAD: &str = "a WIM chunk's XPRESS data is damaged";
    if size > MAX_CHUNK {
        return Err(BAD);
    }
    out.clear();
    out.reserve(size);
    if input.len() < 256 {
        return Err(BAD);
    }
    let table = decoding_table(&input[..256]).ok_or(BAD)?;
    let mut bits = Bits { input, pos: 256, next: 0, extra: 16 };
    bits.next = (bits.word() << 16) | bits.word();
    while out.len() < size {
        let entry = table[(bits.next >> (32 - MAX_LEN)) as usize];
        let (symbol, len) = (u32::from(entry & 0x1ff), u32::from(entry >> 9));
        bits.consume(len);
        if symbol < 256 {
            out.push(symbol as u8);
            continue;
        }
        let symbol = symbol - 256;
        let mut length = (symbol & 15) as usize;
        let offset_bits = symbol >> 4;
        if length == 15 {
            length = usize::from(bits.byte().ok_or(BAD)?);
            if length == 255 {
                let lo = bits.byte().ok_or(BAD)?;
                let hi = bits.byte().ok_or(BAD)?;
                length = usize::from(u16::from_le_bytes([lo, hi]));
                if length < 15 {
                    return Err(BAD);
                }
                length -= 15;
            }
            length += 15;
        }
        length += 3;
        let offset = if offset_bits == 0 { 0 } else { (bits.next >> (32 - offset_bits)) as usize } + (1 << offset_bits);
        bits.consume(offset_bits);
        if offset > out.len() {
            return Err(BAD);
        }
        // a match may not run past the chunk: nothing after it would be read
        let length = length.min(size - out.len());
        let start = out.len() - offset;
        if offset >= length {
            out.extend_from_within(start..start + length);
        } else {
            for i in 0..length {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
    Ok(())
}

/// The 32-bit window on the input that MS-XCA reads codes through.
struct Bits<'a> {
    input: &'a [u8],
    pos: usize,
    next: u32,
    extra: i32,
}

impl Bits<'_> {
    /// The next 16-bit word; past the end of the input, zeros (the window is filled ahead of the codes, so the last
    /// words it holds may lie past the end).
    fn word(&mut self) -> u32 {
        let w = match self.input.get(self.pos..self.pos + 2) {
            Some(b) => u32::from(u16::from_le_bytes([b[0], b[1]])),
            None => 0,
        };
        self.pos += 2;
        w
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.input.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn consume(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        self.next <<= n;
        self.extra -= n as i32;
        if self.extra < 0 {
            self.next |= self.word() << (-self.extra) as u32;
            self.extra += 16;
        }
    }
}

/// The table MS-XCA builds: for every 15-bit prefix, the symbol (low 9 bits) and its code's length (above them).
/// Codes are canonical: shorter ones first, then by symbol. A table the codes don't fill exactly is refused.
fn decoding_table(lengths: &[u8]) -> Option<Box<[u16; 1 << MAX_LEN]>> {
    let len = |s: usize| (lengths[s / 2] >> (4 * (s % 2))) & 15;
    let mut table: Box<[u16; 1 << MAX_LEN]> = vec![0u16; 1 << MAX_LEN].into_boxed_slice().try_into().ok()?;
    let mut at = 0usize;
    for bits in 1..=MAX_LEN as u8 {
        for symbol in 0..512 {
            if len(symbol) == bits {
                let count = 1usize << (MAX_LEN as u8 - bits);
                let end = at.checked_add(count).filter(|&e| e <= table.len())?;
                table[at..end].fill(symbol as u16 | (u16::from(bits) << 9));
                at = end;
            }
        }
    }
    (at == table.len()).then_some(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Code lengths giving every literal and the 256 match symbols 9 bits each, which fills the table exactly.
    fn flat_table() -> [u8; 256] {
        [0x99; 256]
    }

    /// Writes 9-bit codes MSB first into 16-bit little-endian words, as the decoder reads them.
    fn encode(codes: &[(u32, u32)]) -> Vec<u8> {
        let mut out = flat_table().to_vec();
        let (mut acc, mut n) = (0u64, 0u32);
        for &(value, bits) in codes {
            acc = (acc << bits) | u64::from(value);
            n += bits;
        }
        // pad to whole words, and two more for the window filled ahead
        let pad = (16 - n % 16) % 16 + 32;
        acc <<= pad.min(63);
        let total = n + pad;
        assert!(total <= 64);
        let mut left = total;
        while left >= 16 {
            left -= 16;
            out.extend_from_slice(&(((acc >> left) & 0xffff) as u16).to_le_bytes());
        }
        out
    }

    #[test]
    fn literals_and_a_match_decode() {
        // 'a', then a match of length 3 + 2 at offset 1 (symbol 256 + 2, offset bits 0)
        let data = encode(&[(u32::from(b'a'), 9), (256 + 2, 9)]);
        let mut out = Vec::new();
        decompress(&data, 6, &mut out).unwrap();
        assert_eq!(out, b"aaaaaa");
    }

    #[test]
    fn a_match_before_the_start_is_refused() {
        let data = encode(&[(256 + (3 << 4), 9), (0, 3)]);
        let mut out = Vec::new();
        assert!(decompress(&data, 6, &mut out).is_err());
    }

    #[test]
    fn a_table_that_doesnt_fill_is_refused() {
        let mut data = vec![0u8; 300];
        data[0] = 1;
        assert!(decompress(&data, 1, &mut Vec::new()).is_err());
        assert!(decompress(&[0x99; 100], 1, &mut Vec::new()).is_err());
    }

    #[test]
    fn noise_never_panics() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut out = Vec::new();
        for round in 0..2000 {
            let mut data = flat_table().to_vec();
            if round % 3 == 0 {
                // uneven code lengths that still fill the table: one 1-bit code, then halving
                data = vec![0; 256];
                data[0] = 0x21;
                data[1] = 0x43;
                data[2] = 0x65;
                data[3] = 0x87;
                data[4] = 0xa9;
                data[5] = 0xcb;
                data[6] = 0xed;
                data[7] = 0xff;
            }
            for _ in 0..(round % 200) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                data.push(seed as u8);
            }
            let _ = decompress(&data, (seed % 70_000) as usize, &mut out);
        }
    }
}
