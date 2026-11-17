// Vendored from the lzxd crate 0.2.7 (https://github.com/Lonami/lzxd), MIT licensed:
//
// Copyright (c) 2020 Lonami <gh@lonami.dev>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
// The same notice is in LICENSE-MIT beside this file.
//
// Modified for zipfast's WIM reader:
// - WIM's LZX has no E8 header bit at the start of the stream: E8 translation is always on, with a translation size
//   of 12,000,000, and every chunk (32 KiB) is decoded on its own, from a fresh decoder, so its positions count
//   from the chunk's start. The header bit and the cross-chunk state are gone, and the translation lives here.
// - The translation took an absolute value of 0 as negative (`is_positive`); it is now taken as positive, as the
//   format says (0 <= value < translation size).
// - A match reaching back past the window, or past what the chunk has decoded, is an error rather than a panic or
//   a read of stale bytes; so is a match that would run past the chunk's end.
// - A block's size is one bit set for the default of 32 KiB, or clear and followed by 16 bits (block.rs), where
//   LZXD gives 24 bits.
// - The API is reduced to [`decompress_chunk`].

//! LZX as a WIM resource's chunks use it.

#![allow(dead_code, clippy::all, clippy::pedantic)]

use std::fmt;

use bitstream::Bitstream;
use block::{Block, Decoded, Kind as BlockKind};
use tree::{CanonicalTree, Tree};
use window::{Window, WindowSize};

mod bitstream;
mod block;
mod tree;
mod window;

/// The most a chunk may decode to: WIM's LZX chunks are 32 KiB.
pub(crate) const MAX_CHUNK_SIZE: usize = 32 * 1024;

/// WIM's fixed E8 translation size.
const E8_TRANSLATION_SIZE: i32 = 12_000_000;

/// Decoder state needed for new blocks.
pub(crate) struct DecoderState {
    window_size: WindowSize,
    /// path lengths of the previous main tree, which the next one's deltas apply to
    main_tree: CanonicalTree,
    /// path lengths of the previous length tree
    length_tree: CanonicalTree,
}

/// Specific cause for decompression failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeFailed {
    OverreadBlock,
    UnexpectedEof,
    InvalidBlock(u8),
    InvalidBlockSize(u32),
    InvalidPretreeElement(u16),
    InvalidPretreeRle,
    InvalidPathLengths,
    EmptyTree,
    WindowTooSmall,
    ChunkTooLong,
    /// a match reaches back before the chunk's start
    BadOffset,
}

impl fmt::Display for DecodeFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

struct Lzxd {
    window: Window,
    state: DecoderState,
    /// the three most recent real match offsets
    r: [u32; 3],
    current_block: Block,
}

impl Lzxd {
    fn new(window_size: WindowSize) -> Self {
        // > The main tree comprises 256 elements that correspond to all possible 8-bit
        // > characters, plus 8 * NUM_POSITION_SLOTS elements that correspond to matches.
        let main_tree = CanonicalTree::new(256 + 8 * window_size.position_slots());
        // > The length tree comprises 249 elements.
        let length_tree = CanonicalTree::new(249);
        Self {
            window: window_size.create_buffer(),
            state: DecoderState { window_size, main_tree, length_tree },
            // > The initial state of R0, R1, R2 is (1, 1, 1).
            r: [1, 1, 1],
            current_block: Block { remaining: 0, size: 0, kind: BlockKind::Uncompressed { r: [1, 1, 1] } },
        }
    }

    fn decompress(&mut self, chunk: &[u8], output_len: usize) -> Result<&mut [u8], DecodeFailed> {
        if output_len > MAX_CHUNK_SIZE {
            return Err(DecodeFailed::ChunkTooLong);
        }
        let mut bitstream = Bitstream::new(chunk);
        let mut decoded_len = 0;
        while decoded_len != output_len {
            if self.current_block.remaining == 0 {
                // an uncompressed block of odd size is padded to a whole word
                if matches!(self.current_block.kind, BlockKind::Uncompressed { .. }) && self.current_block.size % 2 != 0
                {
                    bitstream.read_byte();
                }
                self.current_block = Block::read(&mut bitstream, &mut self.state)?;
                if self.current_block.remaining == 0 {
                    return Err(DecodeFailed::InvalidBlockSize(0));
                }
            }

            let decoded = self.current_block.decode_element(&mut bitstream, &mut self.r)?;
            let left = output_len - decoded_len;
            let advance = match decoded {
                Decoded::Single(value) => {
                    self.window.push(value);
                    1
                }
                Decoded::Match { offset, length } => {
                    if offset == 0 || offset > decoded_len || length > left {
                        return Err(DecodeFailed::BadOffset);
                    }
                    self.window.copy_from_self(offset, length);
                    length
                }
                Decoded::Read(length) => {
                    let length = bitstream.remaining_bytes().min(length).min(left);
                    self.window.copy_from_bitstream(&mut bitstream, length)?;
                    length
                }
            };
            if advance == 0 {
                return Err(DecodeFailed::UnexpectedEof);
            }
            decoded_len += advance;
            self.current_block.remaining =
                self.current_block.remaining.checked_sub(advance as u32).ok_or(DecodeFailed::OverreadBlock)?;
        }
        self.window.past_view(decoded_len)
    }
}

/// Undoes the E8 translation in a chunk, whose positions count from its start: each `E8` byte (a call, on x86)
/// more than 10 bytes before the end is followed by a 32-bit value the compressor made absolute, which is made
/// relative again.
fn undo_e8(data: &mut [u8]) {
    if data.len() <= 10 {
        return;
    }
    let mut i = 0;
    while i < data.len() - 10 {
        if data[i] != 0xE8 {
            i += 1;
            continue;
        }
        let pos = i as i32;
        let abs = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
        if abs >= -pos && abs < E8_TRANSLATION_SIZE {
            let rel = if abs >= 0 { abs - pos } else { abs + E8_TRANSLATION_SIZE };
            data[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
        }
        i += 5;
    }
}

/// Decodes one WIM LZX chunk to exactly `size` bytes, appended to `out`.
pub(crate) fn decompress_chunk(chunk: &[u8], size: usize, out: &mut Vec<u8>) -> Result<(), DecodeFailed> {
    let mut lzxd = Lzxd::new(WindowSize::KB32);
    let data = lzxd.decompress(chunk, size)?;
    undo_e8(data);
    out.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e8_translation_takes_zero_as_positive() {
        let mut data = [0u8; 32];
        data[4] = 0xE8;
        // absolute 0 at position 4 is relative -4
        undo_e8(&mut data);
        assert_eq!(&data[5..9], &(-4i32).to_le_bytes());
        // a negative absolute value gains the translation size
        let mut data = [0u8; 32];
        data[8] = 0xE8;
        data[9..13].copy_from_slice(&(-3i32).to_le_bytes());
        undo_e8(&mut data);
        assert_eq!(&data[9..13], &(E8_TRANSLATION_SIZE - 3).to_le_bytes());
        // nothing in the last 10 bytes is touched
        let mut data = [0xE8u8; 12];
        undo_e8(&mut data);
        assert_eq!(&data[2..], &[0xE8; 10]);
    }

    #[test]
    fn noise_never_panics() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut out = Vec::new();
        for round in 0..3000 {
            let mut data = Vec::new();
            for _ in 0..(round % 600) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                data.push(seed as u8);
            }
            out.clear();
            let _ = decompress_chunk(&data, (seed % 33_000) as usize, &mut out);
        }
    }
}
