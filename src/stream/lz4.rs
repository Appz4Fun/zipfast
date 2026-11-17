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

//! The LZ4 frame format (lz4's `.lz4`), and the legacy frame format older lz4 tools and the Linux kernel write.
//! Frames, legacy frames and skippable frames may follow one another, as the `lz4` tool reads them. Blocks are
//! decoded by `lz4_flex`; this reads the framing and checks every checksum the frame carries.

use std::io::{self, BufRead, Read};

const FRAME_MAGIC: u32 = 0x184D_2204;
const LEGACY_MAGIC: u32 = 0x184C_2102;
/// A legacy frame's blocks decode to 8 MiB each, the last one less.
const LEGACY_BLOCK: usize = 8 << 20;
/// How far back a linked block may copy from.
const WINDOW: usize = 64 << 10;

fn bad(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

/// What the next bytes of the stream are.
enum State {
    /// between frames
    Boundary,
    Frame(Frame),
    Legacy,
    Done,
}

struct Frame {
    max_block: usize,
    linked: bool,
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
    hasher: Xxh32,
    decoded: u64,
}

pub(crate) struct Lz4Reader<R> {
    r: R,
    state: State,
    /// a block's stored bytes
    src: Vec<u8>,
    /// decoded bytes not yet handed out: `out[at..]`
    out: Vec<u8>,
    at: usize,
    /// the last [`WINDOW`] bytes decoded in this frame, for linked blocks
    window: Vec<u8>,
    frames: u64,
}

impl<R: BufRead> Lz4Reader<R> {
    pub(crate) fn new(r: R) -> Self {
        Lz4Reader { r, state: State::Boundary, src: Vec::new(), out: Vec::new(), at: 0, window: Vec::new(), frames: 0 }
    }

    /// Reads exactly `buf`, or returns false if the stream ends before its first byte.
    fn read_or_end(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        let mut n = 0;
        while n < buf.len() {
            match self.r.read(&mut buf[n..]) {
                Ok(0) if n == 0 => return Ok(false),
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "an LZ4 stream is cut short")),
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() || self.read_or_end(buf)? {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "an LZ4 stream is cut short"))
        }
    }

    fn u32(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Reads what starts at a frame boundary: a frame header, a skippable frame, or the end.
    fn boundary(&mut self) -> io::Result<()> {
        let mut magic = [0u8; 4];
        if !self.read_or_end(&mut magic)? {
            if self.frames == 0 {
                return Err(bad("an LZ4 stream holds no frame"));
            }
            self.state = State::Done;
            return Ok(());
        }
        self.start(u32::from_le_bytes(magic))
    }

    /// Starts the frame `magic` opens.
    fn start(&mut self, magic: u32) -> io::Result<()> {
        match magic {
            FRAME_MAGIC => {
                let mut desc = [0u8; 2];
                self.read_exact(&mut desc)?;
                let (flg, bd) = (desc[0], desc[1]);
                if flg >> 6 != 1 {
                    return Err(bad("an LZ4 frame has a version this reader doesn't know"));
                }
                if flg & 0x02 != 0 || bd & 0x8f != 0 {
                    return Err(bad("an LZ4 frame sets reserved bits"));
                }
                let max_block = match bd >> 4 {
                    4 => 64 << 10,
                    5 => 256 << 10,
                    6 => 1 << 20,
                    7 => 4 << 20,
                    _ => return Err(bad("an LZ4 frame's block size is invalid")),
                };
                let mut header = vec![flg, bd];
                let content_size = if flg & 0x08 != 0 {
                    let mut b = [0u8; 8];
                    self.read_exact(&mut b)?;
                    header.extend_from_slice(&b);
                    Some(u64::from_le_bytes(b))
                } else {
                    None
                };
                if flg & 0x01 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "an LZ4 frame needs a dictionary, which isn't supported",
                    ));
                }
                let mut hc = [0u8; 1];
                self.read_exact(&mut hc)?;
                if (xxh32(&header) >> 8) as u8 != hc[0] {
                    return Err(bad("an LZ4 frame header fails its checksum"));
                }
                self.window.clear();
                self.frames += 1;
                self.state = State::Frame(Frame {
                    max_block,
                    linked: flg & 0x20 == 0,
                    block_checksum: flg & 0x10 != 0,
                    content_checksum: flg & 0x04 != 0,
                    content_size,
                    hasher: Xxh32::new(),
                    decoded: 0,
                });
            }
            LEGACY_MAGIC => {
                self.frames += 1;
                self.state = State::Legacy;
            }
            m if m & 0xFFFF_FFF0 == 0x184D_2A50 => {
                let len = self.u32()?;
                let skipped = io::copy(&mut (&mut self.r).take(u64::from(len)), &mut io::sink())?;
                if skipped < u64::from(len) {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "an LZ4 skippable frame is cut short"));
                }
                // a stream of skippable frames alone holds no data, but isn't broken
                self.frames += 1;
                self.state = State::Boundary;
            }
            _ => return Err(bad("data after an LZ4 frame is not another frame")),
        }
        Ok(())
    }

    /// Decodes the next block into `out`, or moves on at the end of a frame.
    fn block(&mut self) -> io::Result<()> {
        match &mut self.state {
            State::Done => Ok(()),
            State::Boundary => self.boundary(),
            State::Legacy => {
                let mut size = [0u8; 4];
                if !self.read_or_end(&mut size)? {
                    self.state = State::Done;
                    return Ok(());
                }
                let size = u32::from_le_bytes(size);
                // a legacy frame has no end mark: the next frame's magic ends it
                if size == LEGACY_MAGIC || size == FRAME_MAGIC || size & 0xFFFF_FFF0 == 0x184D_2A50 {
                    return self.start(size);
                }
                // LZ4's bound for a block that decodes to 8 MiB
                if size as usize > LEGACY_BLOCK + LEGACY_BLOCK / 255 + 16 {
                    return Err(bad("an LZ4 legacy block is too big"));
                }
                self.src.resize(size as usize, 0);
                let mut src = std::mem::take(&mut self.src);
                self.read_exact(&mut src)?;
                self.out.resize(LEGACY_BLOCK, 0);
                let n = lz4_flex::block::decompress_into(&src, &mut self.out)
                    .map_err(|_| bad("an LZ4 block is corrupt"))?;
                self.src = src;
                self.out.truncate(n);
                self.at = 0;
                Ok(())
            }
            State::Frame(_) => {
                let word = self.u32()?;
                let State::Frame(f) = &mut self.state else { unreachable!() };
                if word == 0 {
                    // the end mark
                    let (sum, size, decoded, check) =
                        (f.content_checksum, f.content_size, f.decoded, std::mem::take(&mut f.hasher).finish());
                    if sum && self.u32()? != check {
                        return Err(bad("an LZ4 frame fails its content checksum"));
                    }
                    if size.is_some_and(|s| s != decoded) {
                        return Err(bad("an LZ4 frame's content size is wrong"));
                    }
                    self.state = State::Boundary;
                    return Ok(());
                }
                let stored = word & 0x8000_0000 != 0;
                let len = (word & 0x7FFF_FFFF) as usize;
                let (max, linked, checked) = (f.max_block, f.linked, f.block_checksum);
                if len > max {
                    return Err(bad("an LZ4 block is bigger than its frame allows"));
                }
                self.src.resize(len, 0);
                let mut src = std::mem::take(&mut self.src);
                self.read_exact(&mut src)?;
                if checked && self.u32()? != xxh32(&src) {
                    return Err(bad("an LZ4 block fails its checksum"));
                }
                if stored {
                    self.out.clear();
                    self.out.extend_from_slice(&src);
                } else {
                    self.out.resize(max, 0);
                    let n = if linked {
                        lz4_flex::block::decompress_into_with_dict(&src, &mut self.out, &self.window)
                    } else {
                        lz4_flex::block::decompress_into(&src, &mut self.out)
                    }
                    .map_err(|_| bad("an LZ4 block is corrupt"))?;
                    self.out.truncate(n);
                }
                self.src = src;
                self.at = 0;
                if linked {
                    let keep = WINDOW.saturating_sub(self.out.len()).min(self.window.len());
                    self.window.drain(..self.window.len() - keep);
                    let from = self.out.len().saturating_sub(WINDOW);
                    self.window.extend_from_slice(&self.out[from..]);
                }
                let State::Frame(f) = &mut self.state else { unreachable!() };
                f.decoded += self.out.len() as u64;
                if f.content_size.is_some_and(|s| f.decoded > s) {
                    return Err(bad("an LZ4 frame's content size is wrong"));
                }
                if f.content_checksum {
                    f.hasher.update(&self.out);
                }
                Ok(())
            }
        }
    }
}

impl<R: BufRead> Read for Lz4Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.at < self.out.len() {
                let n = buf.len().min(self.out.len() - self.at);
                buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if matches!(self.state, State::Done) {
                return Ok(0);
            }
            self.out.clear();
            self.at = 0;
            self.block()?;
        }
    }
}

const P1: u32 = 0x9E37_79B1;
const P2: u32 = 0x85EB_CA77;
const P3: u32 = 0xC2B2_AE3D;
const P4: u32 = 0x27D4_EB2F;
const P5: u32 = 0x1656_67B1;

fn round(acc: u32, lane: u32) -> u32 {
    acc.wrapping_add(lane.wrapping_mul(P2)).rotate_left(13).wrapping_mul(P1)
}

/// XXH32 with seed 0, fed in pieces of any size.
#[derive(Default)]
struct Xxh32 {
    acc: [u32; 4],
    buf: [u8; 16],
    buffered: usize,
    total: u64,
}

impl Xxh32 {
    fn new() -> Self {
        Xxh32 { acc: [P1.wrapping_add(P2), P2, 0, 0u32.wrapping_sub(P1)], ..Default::default() }
    }

    fn stripe(&mut self, s: &[u8]) {
        for (i, lane) in s.as_chunks::<4>().0.iter().enumerate() {
            self.acc[i] = round(self.acc[i], u32::from_le_bytes([lane[0], lane[1], lane[2], lane[3]]));
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buffered > 0 {
            let take = (16 - self.buffered).min(data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 16 {
                return;
            }
            let buf = self.buf;
            self.stripe(&buf);
            self.buffered = 0;
        }
        let whole = data.len() / 16 * 16;
        for s in data[..whole].as_chunks::<16>().0 {
            self.stripe(s);
        }
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    fn finish(self) -> u32 {
        let mut h = if self.total >= 16 {
            let [a, b, c, d] = self.acc;
            a.rotate_left(1)
                .wrapping_add(b.rotate_left(7))
                .wrapping_add(c.rotate_left(12))
                .wrapping_add(d.rotate_left(18))
        } else {
            P5
        };
        h = h.wrapping_add(self.total as u32);
        let mut tail = &self.buf[..self.buffered];
        while tail.len() >= 4 {
            let v = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
            h = h.wrapping_add(v.wrapping_mul(P3)).rotate_left(17).wrapping_mul(P4);
            tail = &tail[4..];
        }
        for &b in tail {
            h = h.wrapping_add(u32::from(b).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
        }
        h ^= h >> 15;
        h = h.wrapping_mul(P2);
        h ^= h >> 13;
        h = h.wrapping_mul(P3);
        h ^ (h >> 16)
    }
}

fn xxh32(data: &[u8]) -> u32 {
    let mut h = Xxh32::new();
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxh32_matches_the_reference_in_any_pieces() {
        // reference values from the xxHash test suite
        assert_eq!(xxh32(b""), 0x02CC_5D05);
        assert_eq!(xxh32(b"a"), 0x550D_7456);
        assert_eq!(xxh32(b"abc"), 0x32D1_53FF);
        let long: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let whole = xxh32(&long);
        for cut in [1, 5, 15, 16, 17, 333] {
            let mut h = Xxh32::new();
            for piece in long.chunks(cut) {
                h.update(piece);
            }
            assert_eq!(h.finish(), whole, "{cut}");
        }
    }
}
