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

//! The inflater against 7-Zip's Deflate64 streams (`tests/fixtures/deflate64`), flate2's Deflate streams, hand-built
//! streams for each Deflate64 extension, and damaged input.
use std::io::Read;

use super::*;

/// What a decoder met, for checking that a vector exercises what it is meant to.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Seen {
    /// Stored, fixed and dynamic blocks.
    pub(super) blocks: [u32; 3],
    pub(super) code285: u32,
    pub(super) max_len: u32,
    pub(super) max_dist: u32,
}

impl Seen {
    pub(super) fn matched(&mut self, len: u32, dist: u32) {
        self.max_len = self.max_len.max(len);
        self.max_dist = self.max_dist.max(dist);
    }
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/deflate64");

/// `(name, method, raw packed bytes)` of each member of a fixture ZIP, from its local headers.
fn zip_members(name: &str) -> Vec<(String, u16, Vec<u8>)> {
    let bytes = std::fs::read(format!("{FIXTURES}/{name}")).unwrap();
    let mut members = Vec::new();
    let mut at = 0;
    while bytes[at..at + 4] == *b"PK\x03\x04" {
        let le16 = |o: usize| u16::from_le_bytes([bytes[at + o], bytes[at + o + 1]]);
        let le32 = |o: usize| u32::from_le_bytes(bytes[at + o..at + o + 4].try_into().unwrap());
        let (method, packed) = (le16(8), le32(18) as usize);
        let (name_len, extra_len) = (usize::from(le16(26)), usize::from(le16(28)));
        let start = at + 30 + name_len + extra_len;
        let name = String::from_utf8(bytes[at + 30..at + 30 + name_len].to_vec()).unwrap();
        members.push((name, method, bytes[start..start + packed].to_vec()));
        at = start + packed;
    }
    members
}

/// The SHA-256 each input file should have.
fn expected(name: &str) -> (usize, String) {
    let text = std::fs::read_to_string(format!("{FIXTURES}/expected.txt")).unwrap();
    let line = text.lines().find(|l| l.split(' ').next() == Some(name)).unwrap();
    let mut parts = line.split(' ').skip(1);
    (parts.next().unwrap().parse().unwrap(), parts.next().unwrap().to_owned())
}

fn sha(data: &[u8]) -> String {
    crate::crypto::sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Done { output: Vec<u8>, consumed: usize },
    Truncated(Vec<u8>),
    Failed(Error),
}

/// Decodes `data` feeding at most `in_chunk` bytes and taking at most `out_chunk` bytes per step, offering unconsumed
/// input again as a caller must.
fn inflate_chunked(variant: Variant, data: &[u8], in_chunk: usize, out_chunk: usize) -> (Outcome, Seen) {
    let mut inflater = Inflater::new(variant);
    let mut output = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut at = 0;
    let mut idle = 0;
    loop {
        let end = (at + in_chunk).min(data.len());
        let step = match inflater.step(&data[at..end], &mut buf) {
            Ok(step) => step,
            Err(error) => return (Outcome::Failed(error), inflater.seen),
        };
        assert!(step.consumed <= end - at && step.produced <= buf.len());
        at += step.consumed;
        output.extend_from_slice(&buf[..step.produced]);
        if step.done {
            return (Outcome::Done { output, consumed: at }, inflater.seen);
        }
        if step.consumed == 0 && step.produced == 0 {
            if at == data.len() {
                return (Outcome::Truncated(output), inflater.seen);
            }
            // A caller that cannot add input to a step that made no progress would be stuck; ours always can, and
            // the decoder must never need it twice in a row with the same input.
            idle += 1;
            assert!(idle < 2, "no progress twice with input left");
        } else {
            idle = 0;
        }
    }
}

fn inflate(variant: Variant, data: &[u8]) -> (Outcome, Seen) {
    inflate_chunked(variant, data, 1 << 20, 1 << 20)
}

fn done(outcome: Outcome) -> Vec<u8> {
    match outcome {
        Outcome::Done { output, .. } => output,
        other => panic!("{other:?}"),
    }
}

#[test]
fn seven_zip_deflate64_members_decode_and_cover_every_extension() {
    let members = zip_members("d64.zip");
    assert_eq!(members.len(), 4);
    let mut total = Seen::default();
    for (name, method, raw) in &members {
        assert_eq!(*method, 9, "{name}");
        let (outcome, seen) = inflate(Variant::Deflate64, raw);
        let Outcome::Done { output, consumed } = outcome else { panic!("{name}: {outcome:?}") };
        assert_eq!(consumed, raw.len(), "{name}: the stream ends at the member's last byte");
        let (size, digest) = expected(name);
        assert_eq!((output.len(), sha(&output)), (size, digest), "{name}");
        for i in 0..3 {
            total.blocks[i] += seen.blocks[i];
        }
        total.code285 += seen.code285;
        total.matched(seen.max_len, seen.max_dist);
        match name.as_str() {
            "far.bin" => assert!(seen.max_dist > 32768 && seen.blocks[0] > 0, "{seen:?}"),
            // 7-Zip's Deflate64 encoder stops at length 257, so it never writes length code 285; the hand-built
            // streams below cover it.
            "runs.bin" => assert_eq!(seen.max_len, 257, "{seen:?}"),
            "small.txt" => assert!(seen.blocks[1] > 0, "{seen:?}"),
            "text.txt" => assert!(seen.blocks[2] > 0, "{seen:?}"),
            _ => unreachable!(),
        }
    }
    assert!(total.blocks.iter().all(|&n| n > 0), "{total:?}");
}

#[test]
fn any_input_and_output_chunking_gives_the_same_bytes() {
    for (name, _, raw) in zip_members("d64.zip") {
        let whole = done(inflate(Variant::Deflate64, &raw).0);
        let chunkings: &[(usize, usize)] = if raw.len() > 4096 {
            &[(1, 7), (3, 1 << 16), (4096, 1), (65536, 65539), (17, 300_000)]
        } else {
            &[(1, 1), (1, 7), (2, 3), (5, 64), (4096, 1), (17, 300_000)]
        };
        for &(i, o) in chunkings {
            let (outcome, _) = inflate_chunked(Variant::Deflate64, &raw, i, o);
            assert_eq!(outcome, Outcome::Done { output: whole.clone(), consumed: raw.len() }, "{name} {i}/{o}");
        }
        let mut reader = Inflate64Reader::new(std::io::BufReader::with_capacity(5, &raw[..]));
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, whole, "{name}: reader");
    }
}

#[test]
fn the_reader_leaves_trailing_bytes_and_reports_truncation() {
    let (_, _, raw) = zip_members("d64.zip").into_iter().find(|m| m.0 == "text.txt").unwrap();
    let mut data = raw.clone();
    data.extend_from_slice(b"TRAILER");
    let mut reader = Inflate64Reader::new(&data[..]);
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    assert_eq!(out.len(), expected("text.txt").0);
    assert_eq!(reader.into_inner(), b"TRAILER");
    let mut cut = Inflate64Reader::new(&raw[..raw.len() - 1]);
    let error = cut.read_to_end(&mut Vec::new()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}

fn deflate(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(level));
    std::io::Write::write_all(&mut e, data).unwrap();
    e.finish().unwrap()
}

/// Deterministic test bytes.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn words(seed: u64, n: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 8] = [b"zip ", b"fast ", b"deflate ", b"sixty-four ", b"window ", b"x", b"\n", b"block "];
    noise(seed, n).iter().flat_map(|b| WORDS[usize::from(b & 7)].iter().copied()).collect()
}

#[test]
fn plain_deflate_from_flate2_decodes_identically() {
    let mut runs = vec![b'r'; 70_000];
    runs.extend(noise(3, 5000));
    runs.extend(std::iter::repeat_n(b"abc".as_slice(), 4000).flatten());
    let inputs = [Vec::new(), b"a".to_vec(), words(1, 50_000), noise(2, 100_000), runs, words(4, 400_000)];
    for (i, input) in inputs.iter().enumerate() {
        for level in [0, 1, 6, 9] {
            let packed = deflate(input, level);
            let (outcome, seen) = inflate(Variant::Deflate, &packed);
            assert_eq!(outcome, Outcome::Done { output: input.clone(), consumed: packed.len() }, "{i} {level}");
            let (outcome, _) = inflate_chunked(Variant::Deflate, &packed, 3, 1000);
            assert_eq!(outcome, Outcome::Done { output: input.clone(), consumed: packed.len() }, "{i} {level}");
            // Without length code 285 (the only code Deflate64 changes that zlib writes) the stream means the same.
            if seen.code285 == 0 {
                let (outcome, _) = inflate(Variant::Deflate64, &packed);
                assert_eq!(outcome, Outcome::Done { output: input.clone(), consumed: packed.len() }, "{i} {level}");
            }
        }
    }
    // Text with no repeat of 258 bytes or more must have taken the Deflate64 branch above at least once.
    let packed = deflate(&words(1, 50_000), 6);
    assert_eq!(inflate(Variant::Deflate, &packed).1.code285, 0);
}

/// Writes a bit stream LSB first, Huffman codes MSB first, as Deflate does.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn put(&mut self, value: u32, n: u32) {
        self.acc |= u64::from(value) << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    fn code(&mut self, code: u32, len: u32) {
        self.put(code.reverse_bits() >> (32 - len), len);
    }

    /// A literal/length symbol of the fixed code.
    fn fixed(&mut self, symbol: u32) {
        match symbol {
            0..=143 => self.code(0x30 + symbol, 8),
            144..=255 => self.code(0x190 + symbol - 144, 9),
            256..=279 => self.code(symbol - 256, 7),
            _ => self.code(0xC0 + symbol - 280, 8),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// A fixed block holding `history` as literals, then each `(length symbol, length extra, distance code, distance
/// extra)` match, then the end of block.
fn fixed_block(variant: Variant, history: &[u8], matches: &[(u32, u32, u32, u32)]) -> Vec<u8> {
    let mut w = Bits::default();
    w.put(0b011, 3);
    for &b in history {
        w.fixed(u32::from(b));
    }
    for &(symbol, extra, dist, dist_extra) in matches {
        w.fixed(symbol);
        w.put(extra, extra_bits(variant, symbol));
        w.code(dist, 5);
        w.put(dist_extra, u32::from(DIST_EXTRA[dist as usize]));
    }
    w.fixed(256);
    w.finish()
}

/// Length extra bits as `variant` reads them.
fn extra_bits(variant: Variant, symbol: u32) -> u32 {
    if variant == Variant::Deflate64 && symbol == 285 { 16 } else { u32::from(LEN_EXTRA[symbol as usize - 257]) }
}

/// The reference LZ77 expansion.
fn expand(history: &[u8], matches: &[(usize, usize)]) -> Vec<u8> {
    let mut out = history.to_vec();
    for &(len, dist) in matches {
        for _ in 0..len {
            out.push(out[out.len() - dist]);
        }
    }
    out
}

#[test]
fn hand_built_deflate64_extensions() {
    let history = noise(9, 50_000);
    // Length 65538 (code 285, extra 65535) at distance 1; distance 40000 (code 30); distance 65536 (code 31, after
    // the output has grown past 64 KiB); length 3 via code 285 with extra 0.
    let matches = [(285, 65535, 0, 0), (257, 0, 30, 40000 - 32769), (285, 997, 31, 16383), (285, 0, 4, 0)];
    let stream = fixed_block(Variant::Deflate64, &history, &matches);
    let want = expand(&history, &[(65538, 1), (3, 40000), (1000, 65536), (3, 5)]);
    let (outcome, seen) = inflate(Variant::Deflate64, &stream);
    assert_eq!(outcome, Outcome::Done { output: want.clone(), consumed: stream.len() });
    assert_eq!((seen.code285, seen.max_len, seen.max_dist), (3, 65538, 65536));
    for (i, o) in [(1, 1), (2, 65537), (7, 3)] {
        assert_eq!(inflate_chunked(Variant::Deflate64, &stream, i, o).0, outcome, "{i}/{o}");
    }
    // In plain Deflate the same bits mean something else: 285 is 258 with no extra bits, and code 30 is invalid.
    assert!(matches!(inflate(Variant::Deflate, &stream).0, Outcome::Failed(_)));
    let plain = fixed_block(Variant::Deflate, b"ab", &[(285, 0, 1, 0)]);
    assert_eq!(done(inflate(Variant::Deflate, &plain).0), expand(b"ab", &[(258, 2)]));
}

fn failure(stream: &[u8]) -> Error {
    for variant in [Variant::Deflate, Variant::Deflate64] {
        match inflate(variant, stream).0 {
            Outcome::Failed(error) => {
                // And it stays failed.
                let mut inflater = Inflater::new(variant);
                let _ = inflater.step(stream, &mut [0u8; 1 << 20]);
                if inflater.failed.is_some() {
                    assert_eq!(inflater.step(b"", &mut [0u8; 4]), Err(inflater.failed.unwrap()));
                }
                if variant == Variant::Deflate64 {
                    return error;
                }
            }
            other => panic!("{variant:?}: {other:?}"),
        }
    }
    unreachable!()
}

/// A dynamic block header: all 19 code length code lengths (by symbol), then whatever `emit` writes.
fn dynamic(hlit: u32, hdist: u32, cl_lens: &[u8; 19], emit: impl FnOnce(&mut Bits)) -> Vec<u8> {
    let mut w = Bits::default();
    w.put(0b101, 3);
    w.put(hlit - 257, 5);
    w.put(hdist - 1, 5);
    w.put(19 - 4, 4);
    for &symbol in &CL_ORDER {
        w.put(u32::from(cl_lens[symbol]), 3);
    }
    emit(&mut w);
    // Padding, so each case fails on what it is about rather than running out of input.
    w.put(0, 32);
    w.put(0, 32);
    w.finish()
}

#[test]
fn damaged_streams_are_typed_errors() {
    // Reserved block type.
    assert_eq!(failure(&[0b111]), Error::BlockType);
    // Stored block whose NLEN is not the complement.
    assert_eq!(failure(&[0b001, 5, 0, 0xFA, 0xF0, 1, 2, 3, 4, 5]), Error::StoredLength);
    // HLIT of 287+.
    let mut w = Bits::default();
    w.put(0b101, 3);
    w.put(30, 5);
    w.put(0, 5);
    w.put(0, 4);
    w.put(0, 32);
    assert_eq!(failure(&w.finish()), Error::CodeCount);
    // Over-subscribed code length code: every one of the 19 symbols one bit long.
    assert_eq!(failure(&dynamic(257, 1, &[1; 19], |_| {})), Error::CodeLengths);
    // Incomplete code length code.
    let mut lens = [0u8; 19];
    lens[0] = 2;
    lens[1] = 2;
    assert_eq!(failure(&dynamic(257, 1, &lens, |w| w.put(0, 32))), Error::CodeLengths);
    // A complete code length code: 1 -> "0", 0 -> "10", 16 -> "11" (codes are assigned 1, then 0 and 16).
    let mut lens = [0u8; 19];
    (lens[1], lens[0], lens[16]) = (1, 2, 2);
    // Over-subscribed literal/length code: all 258 lengths 1.
    let all_ones = dynamic(257, 1, &lens, |w| {
        for _ in 0..258 {
            w.code(0, 1);
        }
    });
    assert_eq!(failure(&all_ones), Error::CodeLengths);
    // A repeat with nothing before it.
    assert_eq!(failure(&dynamic(257, 1, &lens, |w| w.code(0b11, 2))), Error::CodeLengths);
    // A repeat past the end: 257 ones, then "repeat 6" for the one distance length.
    let past_end = dynamic(257, 1, &lens, |w| {
        for _ in 0..257 {
            w.code(0, 1);
        }
        w.code(0b11, 2);
        w.put(3, 2);
    });
    assert_eq!(failure(&past_end), Error::CodeLengths);
    // No end-of-block code: 256 ones, then zeros for 256 and the distance.
    let no_eob = dynamic(257, 1, &lens, |w| {
        for _ in 0..256 {
            w.code(0, 1);
        }
        w.code(0b10, 2);
        w.code(0b10, 2);
    });
    assert_eq!(failure(&no_eob), Error::NoEndOfBlock);
    // Incomplete literal/length code of two 2-bit codes (zlib allows incompleteness only for one 1-bit code).
    // Code length code: 2 -> "0", 0 -> "10", 18 -> "11".
    let mut lens = [0u8; 19];
    (lens[2], lens[0], lens[18]) = (1, 2, 2);
    let two_codes = dynamic(257, 1, &lens, |w| {
        w.code(0b0, 1); // literal 0: length 2
        w.code(0b11, 2); // 138 zeros: 1..=138
        w.put(127, 7);
        w.code(0b11, 2); // 117 zeros: 139..=255
        w.put(106, 7);
        w.code(0b0, 1); // 256: length 2
        w.code(0b10, 2); // the distance: unused
    });
    assert_eq!(failure(&two_codes), Error::CodeLengths);
    // A distance past the start of the output, and one just inside it.
    assert_eq!(failure(&fixed_block(Variant::Deflate64, b"a", &[(257, 0, 1, 0)])), Error::Distance);
    assert!(matches!(
        inflate(Variant::Deflate64, &fixed_block(Variant::Deflate64, b"ab", &[(257, 0, 1, 0)])).0,
        Outcome::Done { .. }
    ));
    // Literal/length 286 and 287 exist in the fixed code but are invalid.
    let mut w = Bits::default();
    w.put(0b011, 3);
    w.fixed(286);
    w.put(0, 32);
    assert_eq!(failure(&w.finish()), Error::Symbol);
}

#[test]
fn deflate_rejects_distance_codes_30_and_31() {
    let history = noise(1, 40_000);
    let stream = fixed_block(Variant::Deflate64, &history, &[(257, 0, 30, 0)]);
    assert!(matches!(inflate(Variant::Deflate, &stream).0, Outcome::Failed(Error::Symbol)));
    assert!(matches!(inflate(Variant::Deflate64, &stream).0, Outcome::Done { .. }));
}

#[test]
fn every_truncation_is_reported_without_a_panic() {
    for (name, _, raw) in zip_members("d64.zip") {
        let whole = done(inflate(Variant::Deflate64, &raw).0);
        let stride = if raw.len() > 4096 { 97 } else { 1 };
        for cut in (0..raw.len()).step_by(stride) {
            match inflate_chunked(Variant::Deflate64, &raw[..cut], 1 << 20, 1 << 20).0 {
                Outcome::Truncated(output) => assert!(whole.starts_with(&output), "{name} at {cut}"),
                other => panic!("{name} cut at {cut}: {other:?}"),
            }
        }
    }
}

#[test]
fn damaged_7zip_streams_never_panic_or_hang() {
    let members = zip_members("d64.zip");
    let mut x = 0x1234_5678_9ABC_DEF1u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for round in 0..600 {
        let raw = &members[round % members.len()].2;
        let mut data = raw.clone();
        for _ in 0..1 + next() % 4 {
            let at = (next() as usize) % data.len();
            data[at] ^= 1 << (next() % 8);
        }
        let (in_chunk, out_chunk) = (1 + (next() % 5000) as usize, 1 + (next() % 70_000) as usize);
        let _ = inflate_chunked(Variant::Deflate64, &data, in_chunk, out_chunk);
        let random = noise(next(), (next() % 2000) as usize);
        let _ = inflate(Variant::Deflate64, &random);
        let _ = inflate(Variant::Deflate, &random);
    }
}

/// With block stops, every boundary a step stops at is a restart point: a decoder resumed there from the output
/// before it (its window) and the input from the boundary's bit decodes the rest exactly, in Deflate and Deflate64.
#[test]
fn block_boundaries_resume_from_the_window_and_a_bit_offset() {
    let mut data = words(3, 400_000);
    data.extend(noise(4, 70_000));
    data.extend(words(5, 300_000));
    let streams = [
        (Variant::Deflate, deflate(&data, 6)),
        (Variant::Deflate64, zip_members("d64.zip").into_iter().find(|m| m.0 == "runs.bin").unwrap().2),
    ];
    for (variant, stream) in streams {
        let mut inf = Inflater::new(variant);
        inf.set_block_stops(true);
        let (mut at, mut out, mut boundaries) = (0usize, Vec::new(), Vec::new());
        let mut buf = vec![0; 10_000];
        loop {
            let step = inf.step(&stream[at..(at + 3_000).min(stream.len())], &mut buf).unwrap();
            at += step.consumed;
            out.extend_from_slice(&buf[..step.produced]);
            if let Some(count) = inf.boundary() {
                boundaries.push((at as u64 * 8 - u64::from(count), out.len()));
            }
            if step.done {
                break;
            }
        }
        boundaries.dedup();
        assert!(boundaries.len() >= 3, "{variant:?}: {} boundaries", boundaries.len());
        assert_eq!(inf.blocks() as usize, boundaries.len() + 1);
        for &(bit, total) in &boundaries {
            let window = if variant == Variant::Deflate64 { 1 << 16 } else { 1 << 15 };
            let mut resumed = Inflater::resume(variant, &out[total.saturating_sub(window)..total], total as u64);
            let mut from = (bit / 8) as usize;
            if bit % 8 != 0 {
                resumed.preload(stream[from], (bit % 8) as u32);
                from += 1;
            }
            let mut rest = Vec::new();
            loop {
                let step = resumed.step(&stream[from..], &mut buf).unwrap();
                from += step.consumed;
                rest.extend_from_slice(&buf[..step.produced]);
                if step.done {
                    break;
                }
                assert!(step.consumed > 0 || step.produced > 0);
            }
            assert!(rest == out[total..], "{variant:?}: resumed at bit {bit}");
        }
    }
}
