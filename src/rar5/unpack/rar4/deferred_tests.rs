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

//! Production deferred lifecycle regressions; original vectors, no decoder substitutes.
use super::*;

#[test]
fn completed_output_keeps_actual_phase_for_deferred_boundary() {
    let packed = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/literal-a.packed"));
    let mut d = Rar4Decoder::new(65536, packed.len() as u64, 1, 65536, Cancellation::default()).unwrap();
    d.feed(packed, &mut |_: &[u8]| Ok(())).unwrap();
    assert!(matches!(d.saved_phase, Phase::Token), "logical completion must retain the actual next-token phase");
}

#[test]
fn cross_member_copy_uses_initialized_chain_history() {
    let mut d = Rar4Decoder::new(65536, 0, 2, 65536, Cancellation::default()).unwrap();
    d.dictionary[..8].copy_from_slice(b"ABCDEFGH");
    d.chain_base = 8;
    d.start_copy(2, 4).expect("a new member can use initialized predecessor history");
}

use lifecycle::{Boundary, BoundaryState};

// Byte-identical retained official fixture, duplicated only to keep all original tests unchanged.
const SOLID: &[u8] = &[
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0x3b, 0xd0, 0x73, 0x08, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xe5, 0x95, 0x74, 0x80, 0x80, 0x25, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x90, 0x4c, 0x00, 0x00, 0x03, 0x98, 0x5c,
    0xa5, 0x58, 0x84, 0x18, 0x22, 0x50, 0x1d, 0x35, 0x05, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x61, 0x2e, 0x74, 0x78, 0x74,
    0x09, 0x01, 0x41, 0x8c, 0xbd, 0x98, 0x0c, 0xef, 0x70, 0xa9, 0x81, 0x35, 0x38, 0x0b, 0x82, 0xcc, 0x0e, 0x31, 0x80,
    0xfc, 0x0f, 0xe4, 0x48, 0x20, 0xef, 0x69, 0xde, 0xc6, 0xfd, 0xd6, 0xf6, 0x93, 0xd5, 0xf5, 0x19, 0xf3, 0xcf, 0x96,
    0x5a, 0x7c, 0xd7, 0xb6, 0x3e, 0xed, 0x96, 0xbe, 0xbc, 0x7b, 0xd3, 0x7c, 0x74, 0xc7, 0x7c, 0x6f, 0xfb, 0x8f, 0x0b,
    0xeb, 0x02, 0x47, 0x7d, 0x60, 0x4f, 0xef, 0xac, 0x09, 0xfd, 0xf5, 0x81, 0x3f, 0xbe, 0xb0, 0x27, 0xf7, 0xd6, 0x04,
    0xfe, 0xfa, 0xc0, 0x9f, 0xdf, 0x58, 0x13, 0xfb, 0xeb, 0x02, 0x7f, 0x7d, 0x60, 0x4f, 0xff, 0x80, 0x22, 0xa5, 0x74,
    0x90, 0x80, 0x25, 0x00, 0x25, 0x00, 0x00, 0x00, 0x0b, 0x52, 0x00, 0x00, 0x03, 0x7c, 0xab, 0x5e, 0x6b, 0x84, 0x18,
    0x22, 0x50, 0x1d, 0x35, 0x05, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x62, 0x2e, 0x74, 0x78, 0x74, 0xbe, 0xb0, 0x10, 0xaf,
    0xac, 0x04, 0x2b, 0xeb, 0x01, 0x0a, 0xfa, 0xc0, 0x42, 0xbe, 0xb0, 0x10, 0xaf, 0xac, 0x04, 0x2b, 0xeb, 0x01, 0x0a,
    0xfa, 0xc0, 0x42, 0xbe, 0xb0, 0x10, 0xaf, 0xac, 0x04, 0x2d, 0xbc, 0xf5, 0xfe, 0x80, 0xc4, 0x3d, 0x7b, 0x00, 0x40,
    0x07, 0x00,
];
use crate::test_alloc::{ALLOC_REQUESTS, TRACK_ALLOC};

fn frame(packed: usize, unpacked: usize, ordinal: u64) -> CoreFrame {
    CoreFrame {
        ordinal,
        packed: packed as u64,
        unpacked: unpacked as u64,
        unpack_version: 29,
        method: 0x33,
        dictionary: 65536,
    }
}
fn create(packed: &[u8], unpacked: usize) -> Rar4Decoder {
    Rar4Decoder::new_frame(frame(packed.len(), unpacked, 7), 65536, Some(Cancellation::default())).unwrap()
}
fn sink(out: &mut Vec<u8>) -> impl Sink + '_ {
    move |bytes: &[u8]| {
        out.extend_from_slice(bytes);
        Ok(())
    }
}
fn defer(d: &mut Rar4Decoder, out: &mut Vec<u8>) -> CoreBinding {
    let c = d.finish_logical(&mut sink(out)).unwrap();
    let key = c.binding();
    d.validate_defer(c).unwrap().commit();
    key
}
fn boundary(d: &mut Rar4Decoder, bytes: &[u8], chunk: usize) -> Boundary {
    let mut state = d.resume_boundary(&[]).unwrap();
    loop {
        match state {
            BoundaryState::Ready(b) => return b,
            BoundaryState::NeedInput => {
                let at = d.fetched() as usize;
                state = d.resume_boundary(&bytes[at..bytes.len().min(at + chunk)]).unwrap();
            }
        }
    }
}

// First-party bit assembly: canonical codes from explicitly chosen lengths.
// No external encoder, packed-stream decoder, or convenient-boundary search.
#[derive(Default)]
struct Vector {
    bits: Vec<bool>,
}
impl Vector {
    fn number(&mut self, value: u32, width: u8) {
        for bit in (0..width).rev() {
            self.bits.push(value & (1 << bit) != 0);
        }
    }
    fn align(&mut self) {
        while !self.bits.len().is_multiple_of(8) {
            self.bits.push(false);
        }
    }
    fn symbol(&mut self, lengths: &[u8], symbol: usize) {
        let length = lengths[symbol];
        assert!(length > 0);
        let mut code = 0;
        for width in 1..=length {
            if width > 1 {
                code = (code + lengths.iter().filter(|&&l| l == width - 1).count() as u32) << 1;
            }
        }
        code += lengths[..symbol].iter().filter(|&&l| l == length).count() as u32;
        self.number(code, length);
    }
    fn tables(&mut self, lengths: &[u8; 404], old: Option<&[u8; 404]>) {
        self.align();
        self.number(0, 1); // LZ
        self.number(u32::from(old.is_some()), 1);
        for symbol in 0..20 {
            self.number(if symbol < 16 { 4 } else { 0 }, 4);
        }
        for (i, &length) in lengths.iter().enumerate() {
            self.number(u32::from(length.wrapping_sub(old.map_or(0, |o| o[i])) & 15), 4);
        }
    }
    fn end(&mut self, lengths: &[u8; 404], next_tables: bool) {
        self.symbol(&lengths[..299], 256);
        self.number(0, 1);
        self.number(u32::from(next_tables), 1);
    }
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.bits.len().div_ceil(8)];
        for (i, bit) in self.bits.iter().enumerate() {
            if *bit {
                bytes[i / 8] |= 1 << (7 - i % 8);
            }
        }
        bytes
    }
}
fn literal_lengths() -> [u8; 404] {
    let mut lengths = [0; 404];
    lengths[65] = 1;
    lengths[256] = 1;
    lengths
}
fn literals(count: usize, next_tables: bool) -> Vector {
    let lengths = literal_lengths();
    let mut v = Vector::default();
    v.tables(&lengths, None);
    for _ in 0..count {
        v.symbol(&lengths[..299], 65);
    }
    v.end(&lengths, next_tables);
    v
}

#[test]
fn official_two_member_gold_uses_production_lifecycle_one_dictionary() {
    // Original parser remains authoritative for both extents/metadata.
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(SOLID).unwrap();
    let mut volume = crate::rar5::reader::Volume::open(file.path()).unwrap();
    let mut headers = Vec::new();
    while let Some(block) = volume.next_block().unwrap() {
        if let crate::rar5::reader::Block::File(h) = block {
            headers.push(h);
        }
    }
    assert_eq!(SOLID.len(), 230);
    let first = &headers[0];
    let packed = &SOLID[first.data_at as usize..(first.data_at + first.packed_size) as usize];
    let gold = b"RAR4 archive compatibility.\n".repeat(700);
    assert_eq!((first.packed_size, first.unpacked_size, first.dictionary), (92, 19600, 1048576));
    assert_eq!(crate::crc32::hash(&gold), 0x58a55c98);
    let second = &headers[1];
    let next = &SOLID[second.data_at as usize..(second.data_at + second.packed_size) as usize];
    let mut next_gold = b"RAR4 archive compatibility.\n".repeat(750);
    next_gold.extend(b"end");
    for chunk in [1, 7, packed.len()] {
        let exact = |h: &crate::rar5::FileHeader, ordinal| CoreFrame {
            ordinal,
            packed: h.packed_size,
            unpacked: h.unpacked_size,
            unpack_version: h.rar4.unwrap().unpack_version,
            method: h.rar4.unwrap().method,
            dictionary: h.dictionary,
        };
        let mut d = Rar4Decoder::new_frame(exact(first, 0), first.dictionary, Some(Cancellation::default())).unwrap();
        let pointer = d.dictionary.as_ptr();
        d.trace = Some(tests::BoundaryTrace::default());
        let mut out = Vec::new();
        for piece in packed.chunks(chunk) {
            d.feed(&[], &mut sink(&mut out)).unwrap();
            d.feed(piece, &mut sink(&mut out)).unwrap();
        }
        assert_eq!(out, gold);
        assert_eq!((d.fed, d.fetched(), d.bits.count, d.consumed_bits().unwrap()), (92, 91, 6, 722));
        let binding = defer(&mut d, &mut out);
        let b = boundary(&mut d, packed, chunk);
        assert_eq!((d.fed, d.fetched(), d.bits.count, d.consumed_bits().unwrap()), (92, 92, 5, 731));
        assert!(matches!(d.saved_phase, Phase::Token)); // observed end256/00, cursor731
        let before = d.work.operations;
        d.begin_next(b, exact(second, 1)).unwrap();
        assert_eq!(d.binding.owner, binding.owner);
        assert_eq!((d.chain_base, d.produced, d.expected, d.fed, d.fetched()), (19600, 0, 21003, 0, 0));
        assert_eq!(d.work.operations, before);
        let mut out = Vec::new();
        for piece in next.chunks(chunk) {
            d.feed(piece, &mut sink(&mut out)).unwrap();
            d.feed(&[], &mut sink(&mut out)).unwrap();
        }
        d.finish(&mut sink(&mut out)).unwrap();
        assert_eq!(out, next_gold);
        assert_eq!(crate::crc32::hash(&out), 0x6b5eab7c);
        assert_eq!(
            crate::crypto::sha256(&out),
            [
                0x75, 0x50, 0xee, 0x05, 0xfc, 0x33, 0x75, 0x95, 0xe1, 0xb1, 0x8c, 0xc2, 0x9d, 0x94, 0xc0, 0x12, 0x56,
                0x66, 0x3e, 0xeb, 0x80, 0x1a, 0x7e, 0xe2, 0x84, 0xa9, 0x37, 0xfa, 0xf7, 0x7c, 0xff, 0x71
            ]
        );
        assert_eq!(d.first_cross, Some((0, 28, 257)));
        assert_eq!((d.produced, d.fed, d.fetched(), d.consumed_bits().unwrap()), (21003, 37, 35, 280));
        assert_eq!(d.dictionary.as_ptr(), pointer);
        assert_eq!(d.dictionary.capacity(), 1048576);
        assert!(!d.poisoned);
    }
}

#[test]
fn fed_tail_freezes_fetched_accumulator_phase_and_output() {
    let mut bytes = literals(1, false).bytes();
    bytes.extend([0xff; 32]);
    let mut d = create(&bytes, 1);
    let mut out = Vec::new();
    for (i, byte) in bytes.iter().enumerate() {
        let before = (d.fetched, d.bits.acc, d.bits.count, d.produced, d.table_builds);
        let done = matches!(d.phase, Phase::Complete);
        d.feed(&[*byte], &mut sink(&mut out)).unwrap();
        d.feed(&[], &mut sink(&mut out)).unwrap();
        if done {
            assert_eq!((d.fetched, d.bits.acc, d.bits.count, d.produced, d.table_builds), before);
        }
        assert_eq!(d.fed, i as u64 + 1);
    }
    assert_eq!(out, b"A");
    defer(&mut d, &mut out);
    let _b = boundary(&mut d, &bytes, 1);
    assert!(d.fetched < bytes.len() as u64);
    assert_eq!(out, b"A");
}

#[test]
fn grammar_00_01_same_file_tables_and_old_lengths() {
    let lengths = literal_lengths();
    for next_tables in [false, true] {
        for retain in [false, true] {
            let first = literals(1, next_tables).bytes();
            let mut next = Vector::default();
            if next_tables {
                next.tables(&lengths, if retain { Some(&lengths) } else { None });
            }
            next.symbol(&lengths[..299], 65);
            next.end(&lengths, false);
            let next = next.bytes();
            for chunk in [1, first.len()] {
                let mut d = create(&first, 1);
                let mut out = Vec::new();
                for part in first.chunks(chunk) {
                    d.feed(part, &mut sink(&mut out)).unwrap();
                }
                defer(&mut d, &mut out);
                let b = boundary(&mut d, &first, chunk);
                let builds = d.table_builds;
                d.begin_next(b, frame(next.len(), 1, 8)).unwrap();
                assert!(matches!((next_tables, d.phase), (false, Phase::Token) | (true, Phase::Align)));
                out.clear();
                for part in next.chunks(chunk) {
                    d.feed(part, &mut sink(&mut out)).unwrap();
                }
                d.finish(&mut sink(&mut out)).unwrap();
                assert_eq!(out, b"A");
                assert_eq!(d.old, lengths);
                assert_eq!(d.table_builds, builds + u64::from(next_tables));
            }
        }
    }
    // A real same-file /1 after last output rebuilds tables without output,
    // followed by an actual next-file /00; align at all eight bit positions.
    for count in 0..8 {
        for retain in [false, true] {
            let mut v = Vector::default();
            v.tables(&lengths, None);
            for _ in 0..count {
                v.symbol(&lengths[..299], 65);
            }
            v.symbol(&lengths[..299], 256);
            v.number(1, 1);
            v.tables(&lengths, if retain { Some(&lengths) } else { None });
            v.end(&lengths, false);
            let bytes = v.bytes();
            let mut d = create(&bytes, count);
            let mut out = Vec::new();
            d.feed(&bytes, &mut sink(&mut out)).unwrap();
            defer(&mut d, &mut out);
            let _b = boundary(&mut d, &bytes, 1);
            assert_eq!(d.table_builds, 2);
            assert_eq!(d.consumed_bits().unwrap(), v.bits.len() as u64);
            assert_eq!(out, vec![b'A'; count]);
            assert_eq!(d.old, lengths);
        }
    }
}

#[test]
fn empty_compressed_transition_and_independent_empty_slack() {
    let first = literals(0, false).bytes();
    let mut d = create(&first, 0);
    let mut out = Vec::new();
    d.feed(&first, &mut sink(&mut out)).unwrap();
    assert_eq!((d.fed, d.fetched, d.table_builds), (first.len() as u64, 0, 0));
    defer(&mut d, &mut out);
    let b = boundary(&mut d, &first, 1);
    assert_eq!(d.table_builds, 1);
    d.begin_next(b, frame(1, 1, 8)).unwrap();
    d.feed(&[0], &mut sink(&mut out)).unwrap();
    d.finish(&mut sink(&mut out)).unwrap();
    assert_eq!(out, b"A");
    let mut empty = create(&[], 0);
    let c = empty.finish_logical(&mut sink(&mut out)).unwrap();
    empty.validate_defer(c).unwrap().commit();
    assert!(matches!(empty.resume_boundary(&[]), Err(Rar4DecodeError::Malformed("RAR4 missing real boundary bits"))));
    assert!(empty.poisoned);
    let mut slack = create(&[0xff], 0);
    slack.feed(&[0xff], &mut sink(&mut out)).unwrap();
    slack.finish(&mut sink(&mut out)).unwrap();
    assert_eq!(slack.fetched, 0);
}

#[test]
fn every_real_boundary_bit_truncation_and_extra_output_refuse() {
    // Shift each boundary bit to a physical edge by choosing literal count.
    // Prefixes contain real bits only, never padded replacement end markers.
    let lengths = literal_lengths();
    let table_bits = 82 + 404 * 4;
    for missing in 0..3 {
        let literals = (8 - (table_bits + missing) % 8) % 8;
        let full = literals_control(literals, false);
        let cut_bits = table_bits + literals + missing;
        assert!(cut_bits.is_multiple_of(8));
        let bytes = &full[..cut_bits / 8];
        let mut d = create(bytes, literals);
        let mut out = Vec::new();
        d.feed(bytes, &mut sink(&mut out)).unwrap();
        defer(&mut d, &mut out);
        let result = d.resume_boundary(&[]);
        let error = match result {
            Err(e) => e,
            Ok(BoundaryState::NeedInput) => d.resume_boundary(&bytes[d.fetched as usize..]).unwrap_err(),
            Ok(BoundaryState::Ready(_)) => panic!("invented a boundary"),
        };
        assert!(matches!(error, Rar4DecodeError::Malformed(_)));
        assert!(d.poisoned);
        assert_eq!(d.consumed_bits().unwrap(), cut_bits as u64);
    }
    // Every whole-byte real prefix of a richer same-file boundary either fails
    // logical output or fails deferred boundary work, never emits a capability.
    let full = literals_control(1, false);
    for end in 0..full.len() {
        let mut d = create(&full[..end], 1);
        let mut out = Vec::new();
        if d.feed(&full[..end], &mut sink(&mut out)).is_err() {
            continue;
        }
        let Ok(c) = d.finish_logical(&mut sink(&mut out)) else {
            continue;
        };
        d.validate_defer(c).unwrap().commit();
        assert!(d.resume_boundary(&[]).is_err());
    }
    let mut v = Vector::default();
    v.tables(&lengths, None);
    v.symbol(&lengths[..299], 65);
    v.symbol(&lengths[..299], 65);
    v.end(&lengths, false);
    let bytes = v.bytes();
    let mut d = create(&bytes, 1);
    let mut out = Vec::new();
    d.feed(&bytes, &mut sink(&mut out)).unwrap();
    defer(&mut d, &mut out);
    assert!(matches!(d.resume_boundary(&[]), Err(Rar4DecodeError::DecodedSize { expected: 1, actual: 2 })));
    assert_eq!(out, b"A");
}
fn literals_control(count: usize, next_tables: bool) -> Vec<u8> {
    literals(count, next_tables).bytes()
}

#[test]
fn distinct_recent_slots_and_last_length_survive_member_transition() {
    let mut lengths = [0; 404];
    for symbol in (65..=72).chain([256, 258, 259, 260, 261, 262, 263, 264]) {
        lengths[symbol] = 4;
    }
    lengths[376] = 1; // recent length 0 => two bytes
    let mut first = Vector::default();
    first.tables(&lengths, None);
    let mut history = b"ABCDEFGH".to_vec();
    for symbol in 65..=72 {
        first.symbol(&lengths[..299], symbol);
    }
    for distance in 1..=4 {
        first.symbol(&lengths[..299], 263);
        first.number(distance - 1, 2);
        for _ in 0..2 {
            let byte = history[history.len() - distance as usize];
            history.push(byte);
        }
    }
    first.end(&lengths, false);
    let bytes = first.bytes();
    for token in 258..=262 {
        let mut d = create(&bytes, history.len());
        let mut out = Vec::new();
        d.feed(&bytes, &mut sink(&mut out)).unwrap();
        assert_eq!(out, history);
        assert_eq!((d.recent, d.last_length), ([4, 3, 2, 1], 2));
        defer(&mut d, &mut out);
        let b = boundary(&mut d, &bytes, 1);
        let mut next = Vector::default();
        next.symbol(&lengths[..299], token);
        if token != 258 {
            next.symbol(&lengths[376..], 0);
        }
        next.end(&lengths, false);
        let next = next.bytes();
        d.begin_next(b, frame(next.len(), 2, 8)).unwrap();
        out.clear();
        d.feed(&next, &mut sink(&mut out)).unwrap();
        d.finish(&mut sink(&mut out)).unwrap();
        let distance = if token == 258 { 4 } else { 4 - (token - 259) };
        let mut expected = history.clone();
        for _ in 0..2 {
            let byte = expected[expected.len() - distance];
            expected.push(byte);
        }
        assert_eq!(out, expected[history.len()..]);
        assert_eq!(d.recent[0], distance as u64);
    }
}

#[test]
fn low_repeat_and_table_reset_survive_real_deferred_protocol() {
    let mut lengths = [0; 404];
    for s in [65, 66, 256, 271] {
        lengths[s] = 2;
    }
    lengths[299 + 10] = 1;
    lengths[359] = 1;
    lengths[359 + 16] = 1;
    for next_tables in [false, true] {
        let mut first = Vector::default();
        first.tables(&lengths, None);
        first.symbol(&lengths[..299], 66);
        for _ in 0..32 {
            first.symbol(&lengths[..299], 65);
        }
        for low in [0, 16] {
            first.symbol(&lengths[..299], 271);
            first.symbol(&lengths[299..359], 10);
            first.symbol(&lengths[359..376], low);
        }
        first.end(&lengths, next_tables);
        let bytes = first.bytes();
        let mut d = create(&bytes, 39);
        let mut out = Vec::new();
        d.feed(&bytes, &mut sink(&mut out)).unwrap();
        assert_eq!((d.low, d.low_repeats), (0, 15));
        defer(&mut d, &mut out);
        let b = boundary(&mut d, &bytes, 1);
        let mut next = Vector::default();
        if next_tables {
            next.tables(&lengths, Some(&lengths));
        }
        next.symbol(&lengths[..299], 271);
        next.symbol(&lengths[299..359], 10);
        if next_tables {
            next.symbol(&lengths[359..376], 0);
        }
        next.end(&lengths, false);
        let next = next.bytes();
        d.begin_next(b, frame(next.len(), 3, 8)).unwrap();
        out.clear();
        d.feed(&next, &mut sink(&mut out)).unwrap();
        d.finish(&mut sink(&mut out)).unwrap();
        assert_eq!(d.low_repeats, if next_tables { 0 } else { 14 });
        assert_eq!(out.len(), 3);
        assert_eq!(d.first_cross, Some((0, 33, 3)));
    }
}

#[test]
fn actual_dictionary_wrap_and_active_geometry_bound_cross_member_copy() {
    let mut lengths = [0; 404];
    for s in [65, 66, 256, 271] {
        lengths[s] = 2;
    }
    lengths[299] = 1;
    let mut first = Vector::default();
    first.tables(&lengths, None);
    for i in 0..65538 {
        first.symbol(&lengths[..299], if i % 3 == 0 { 66 } else { 65 });
    }
    first.end(&lengths, false);
    let bytes = first.bytes();
    let mut d = create(&bytes, 65538);
    let mut out = Vec::new();
    for part in bytes.chunks(7) {
        d.feed(part, &mut sink(&mut out)).unwrap();
    }
    assert_eq!(out.len(), 65538);
    let last = *out.last().unwrap();
    defer(&mut d, &mut out);
    let b = boundary(&mut d, &bytes, 1);
    let mut next = Vector::default();
    next.symbol(&lengths[..299], 271);
    next.symbol(&lengths[299..359], 0);
    next.end(&lengths, false);
    let next = next.bytes();
    d.begin_next(b, frame(next.len(), 3, 8)).unwrap();
    out.clear();
    d.feed(&next, &mut sink(&mut out)).unwrap();
    d.finish(&mut sink(&mut out)).unwrap();
    assert_eq!(out, [last; 3]);
    assert_eq!(d.chain_base, 65538);
    assert_eq!(d.first_cross, Some((0, 1, 3)));
    let mut large = Rar4Decoder::new(131072, 0, 2, 131072, Cancellation::default()).unwrap();
    large.chain_base = 100000;
    large.binding.frame.dictionary = 65536;
    assert!(matches!(large.start_copy(2, 65537), Err(Rar4DecodeError::Malformed(_))));
    large.start_copy(2, 65536).unwrap();
}

fn logical_member() -> (Rar4Decoder, lifecycle::Completion) {
    let bytes = literals_control(1, false);
    let mut d = create(&bytes, 1);
    d.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    (d, c)
}
fn ready_member() -> (Rar4Decoder, Boundary) {
    let bytes = literals_control(1, false);
    let (mut d, c) = logical_member();
    d.validate_defer(c).unwrap().commit();
    let b = boundary(&mut d, &bytes, 1);
    (d, b)
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    binding: CoreBinding,
    phase: u8,
    fed: u64,
    fetched: u64,
    acc: u64,
    count: u8,
    produced: u64,
    base: u64,
    work: u64,
    history: u32,
    tables: u64,
    poison: bool,
    finished: bool,
}
fn snapshot(d: &Rar4Decoder) -> Snapshot {
    Snapshot {
        binding: d.binding,
        phase: d.lifecycle as u8,
        fed: d.fed,
        fetched: d.fetched,
        acc: d.bits.acc,
        count: d.bits.count,
        produced: d.produced,
        base: d.chain_base,
        work: d.work.operations,
        history: crate::crc32::hash(&d.dictionary),
        tables: d.table_builds,
        poison: d.poisoned,
        finished: d.finished,
    }
}

#[test]
fn foreign_completion_wrong_frame_and_stale_generation_reject_before_mutation() {
    let (mut a, a_token) = logical_member();
    let (mut b, b_token) = logical_member();
    let before = snapshot(&a);
    assert!(matches!(a.validate_defer(b_token), Err(Rar4DecodeError::Binding)));
    assert_eq!(snapshot(&a), before);
    b.abort(a_token).unwrap_err(); // foreign abort also cannot discard another decoder
    assert_eq!(b.lifecycle, Lifecycle::LogicalDone);
    for change in 0..9 {
        let (mut d, c) = logical_member();
        let key = d.binding;
        match change {
            0 => d.binding.member_seq += 1,
            1 => d.binding.frame.ordinal += 1,
            2 => d.binding.frame.packed += 1,
            3 => d.binding.frame.unpacked += 1,
            4 => d.binding.frame.unpack_version += 1,
            5 => d.binding.frame.method += 1,
            6 => d.binding.frame.dictionary *= 2,
            7 => d.binding.owner += 1,
            _ => d.binding.epoch += 1,
        }
        let before = snapshot(&d);
        assert!(matches!(d.validate_defer(c), Err(Rar4DecodeError::Binding)));
        assert_eq!(snapshot(&d), before);
        assert_ne!(d.binding, key);
    }
    let (mut d, c) = logical_member();
    let old = c.binding();
    d.reset_independent(old.frame).unwrap();
    let bytes = literals_control(1, false);
    d.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
    let fresh = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    let before = snapshot(&d);
    assert!(matches!(d.validate_defer(c), Err(Rar4DecodeError::Binding)));
    assert_eq!(snapshot(&d), before);
    d.validate_defer(fresh).unwrap().commit();
}

#[test]
fn forbidden_lifecycle_calls_drop_and_guard_drop_never_grant_history() {
    let (mut d, c) = logical_member();
    let (other, b) = ready_member();
    drop(other);
    let before = snapshot(&d);
    assert!(matches!(d.feed(&[], &mut |_: &[u8]| Ok(())), Err(Rar4DecodeError::State)));
    assert!(matches!(d.finish_logical(&mut |_: &[u8]| Ok(())), Err(Rar4DecodeError::State)));
    assert!(matches!(d.finish(&mut |_: &[u8]| Ok(())), Err(Rar4DecodeError::State)));
    assert!(matches!(d.resume_boundary(&[]), Err(Rar4DecodeError::State)));
    assert!(matches!(d.begin_next(b, frame(0, 0, 8)), Err(Rar4DecodeError::State)));
    assert_eq!(snapshot(&d), before);
    {
        let _guard = d.validate_defer(c).unwrap();
    }
    assert_eq!(snapshot(&d), before);
    assert!(matches!(d.resume_boundary(&[]), Err(Rar4DecodeError::State)));
    d.reset_independent(frame(0, 0, 7)).unwrap();
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    {
        let _discarded = c;
    }
    assert_eq!(d.lifecycle, Lifecycle::LogicalDone);
    assert!(d.feed(&[], &mut |_: &[u8]| Ok(())).is_err());
    d.reset_independent(frame(0, 0, 7)).unwrap();
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    d.abort(c).unwrap();
    assert_eq!(d.lifecycle, Lifecycle::Unavailable);
    assert!(d.resume_boundary(&[]).is_err());
    assert!(d.finish_logical(&mut |_: &[u8]| Ok(())).is_err());
    d.reset_independent(frame(0, 0, 7)).unwrap();
    d.finish(&mut |_: &[u8]| Ok(())).unwrap();
    let before = snapshot(&d);
    assert!(d.feed(&[], &mut |_: &[u8]| Ok(())).is_err());
    assert!(d.finish(&mut |_: &[u8]| Ok(())).is_err());
    assert!(d.resume_boundary(&[]).is_err());
    assert_eq!(snapshot(&d), before);
    // Active, Deferred and BoundaryReady all refuse finish/commit operations
    // requiring another state; token ownership prevents safe repeated use.
    let (mut a, c) = logical_member();
    a.validate_defer(c).unwrap().commit();
    let (_, foreign) = logical_member();
    let before = snapshot(&a);
    assert!(a.validate_defer(foreign).is_err());
    assert!(a.feed(&[], &mut |_: &[u8]| Ok(())).is_err());
    assert!(a.finish_logical(&mut |_: &[u8]| Ok(())).is_err());
    assert_eq!(snapshot(&a), before);
    let (mut a, b) = ready_member();
    let before = snapshot(&a);
    assert!(a.resume_boundary(&[]).is_err());
    assert!(a.feed(&[], &mut |_: &[u8]| Ok(())).is_err());
    assert!(a.finish_logical(&mut |_: &[u8]| Ok(())).is_err());
    assert_eq!(snapshot(&a), before);
    a.begin_next(b, frame(0, 0, 8)).unwrap();
    assert_eq!(a.binding.member_seq, 2);
}

#[test]
fn boundary_owner_generation_geometry_and_extent_rejection_is_atomic() {
    let (mut a, _a) = ready_member();
    let (_, b) = ready_member();
    let before = snapshot(&a);
    assert!(matches!(a.begin_next(b, frame(1, 1, 8)), Err(Rar4DecodeError::Binding)));
    assert_eq!(snapshot(&a), before);
    for (version, method, dictionary) in
        [(28, 0x33, 65536), (29, 0x30, 65536), (29, 0x36, 65536), (29, 0x33, 131072), (29, 0x33, 123)]
    {
        let (mut d, b) = ready_member();
        let mut f = frame(1, 1, 8);
        f.unpack_version = version;
        f.method = method;
        f.dictionary = dictionary;
        let before = snapshot(&d);
        assert!(d.begin_next(b, f).is_err());
        assert_eq!(snapshot(&d), before);
    }
    let (mut d, b) = ready_member();
    let old = d.binding;
    d.reset_independent(old.frame).unwrap();
    let bytes = literals_control(1, false);
    d.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    d.validate_defer(c).unwrap().commit();
    let _fresh = boundary(&mut d, &bytes, 1);
    let before = snapshot(&d);
    assert!(matches!(d.begin_next(b, frame(1, 1, 8)), Err(Rar4DecodeError::Binding)));
    assert_eq!(snapshot(&d), before);
    let (mut d, c) = logical_member();
    d.validate_defer(c).unwrap().commit();
    let before = snapshot(&d);
    assert!(matches!(d.resume_boundary(&[0; 1000]), Err(Rar4DecodeError::Binding)));
    assert_eq!(snapshot(&d), before);
}

#[test]
fn poisoned_instance_rejects_every_capability_and_reset_without_mutation() {
    for failure in 0..4 {
        let (mut d, c) = logical_member();
        let (_, b) = ready_member();
        match failure {
            0 => {
                d.work.cancel.as_ref().unwrap().cancel();
                assert!(d.validate_defer(c).is_err());
            }
            1 => {
                d.validate_defer(c).unwrap().commit();
                d.work.operations = u64::MAX;
                assert!(d.resume_boundary(&[]).is_err());
            }
            2 => {
                {
                    let _discarded = c;
                }
                let bytes = literals_control(2, false);
                d.reset_independent(frame(bytes.len(), 1, 8)).unwrap();
                d.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
                let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
                d.validate_defer(c).unwrap().commit();
                let err = d.resume_boundary(&[]);
                assert!(matches!(err, Err(Rar4DecodeError::DecodedSize { .. })));
            }
            _ => {
                d.reset_independent(frame(1, 1, 8)).unwrap();
                let err = d.finish_logical(&mut |_: &[u8]| Ok(()));
                assert!(err.is_err());
            }
        }
        assert!(d.poisoned);
        let (_, foreign) = logical_member();
        let before = snapshot(&d);
        assert!(d.validate_defer(foreign).is_err());
        let (_, foreign) = logical_member();
        assert!(d.abort(foreign).is_err());
        assert!(d.feed(&[], &mut |_: &[u8]| Ok(())).is_err());
        assert!(d.finish(&mut |_: &[u8]| Ok(())).is_err());
        assert!(d.finish_logical(&mut |_: &[u8]| Ok(())).is_err());
        assert!(d.resume_boundary(&[]).is_err());
        assert!(d.begin_next(b, frame(0, 0, 8)).is_err());
        assert!(d.reset_independent(frame(0, 0, 8)).is_err());
        assert_eq!(snapshot(&d), before);
    }
}

#[test]
fn reset_clears_semantics_in_place_and_stale_tokens_cannot_restore_history() {
    let bytes = literals_control(3, false);
    let mut d = create(&bytes, 3);
    let mut out = Vec::new();
    d.feed(&bytes, &mut sink(&mut out)).unwrap();
    let c = d.finish_logical(&mut sink(&mut out)).unwrap();
    let pointer = d.dictionary.as_ptr();
    let work = d.work.operations;
    let epoch = d.binding.epoch;
    d.recent = [4, 3, 2, 1];
    d.last_length = 100;
    d.low = 7;
    d.low_repeats = 15;
    d.reset_independent(frame(0, 0, 42)).unwrap();
    assert_eq!(d.dictionary.as_ptr(), pointer);
    assert_eq!(d.work.operations, work);
    assert_eq!(d.binding.epoch, epoch + 1);
    assert_eq!(
        (d.chain_base, d.produced, d.fed, d.fetched, d.recent, d.last_length, d.low, d.low_repeats),
        (0, 0, 0, 0, [0; 4], 0, 0, 0)
    );
    assert!(d.old.iter().all(|&n| n == 0));
    assert!(d.tables.iter().all(|h| h.used == 0));
    assert!(matches!(d.start_copy(1, 1), Err(Rar4DecodeError::Malformed(_))));
    let fresh = d.finish_logical(&mut sink(&mut out)).unwrap();
    let before = snapshot(&d);
    assert!(d.validate_defer(c).is_err());
    assert_eq!(snapshot(&d), before);
    d.abort(fresh).unwrap();
}

#[test]
fn counter_overflow_is_terminal_without_wrapped_identity_or_cursor() {
    let bytes = literals_control(1, false);
    let mut sequence = create(&bytes, 1);
    sequence.binding.member_seq = u64::MAX;
    sequence.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
    let c = sequence.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    sequence.validate_defer(c).unwrap().commit();
    let b = boundary(&mut sequence, &bytes, 1);
    let key = sequence.binding;
    assert!(matches!(sequence.begin_next(b, frame(0, 0, 8)), Err(Rar4DecodeError::CounterOverflow)));
    assert_eq!(sequence.binding, key);
    assert!(sequence.poisoned);
    let (mut d, _b) = ready_member();
    d.reset_independent(frame(0, 0, 0)).unwrap();
    d.binding.epoch = u64::MAX;
    let before = d.binding;
    assert!(matches!(d.reset_independent(frame(0, 0, 0)), Err(Rar4DecodeError::CounterOverflow)));
    assert_eq!(d.binding, before);
    assert!(d.poisoned);
    let (mut d, c) = logical_member();
    d.validate_defer(c).unwrap().commit();
    d.fetched = u64::MAX;
    assert!(matches!(d.resume_boundary(&[]), Err(Rar4DecodeError::CounterOverflow)));
    // The remaining-extent invariant is checked before parsing.
    assert_eq!(d.fetched, u64::MAX);
    assert!(d.poisoned);
    let bytes = literals_control(1, false);
    let mut d = create(&bytes, 1);
    d.chain_base = u64::MAX;
    assert!(matches!(d.feed(&bytes, &mut |_: &[u8]| Ok(())), Err(Rar4DecodeError::CounterOverflow)));
    assert_eq!((d.produced, d.chain_base), (0, u64::MAX));
    assert!(d.poisoned);
    let mut d = create(&[], 0);
    d.fetched = u64::MAX;
    assert!(matches!(d.feed(&[], &mut |_: &[u8]| Ok(())), Err(Rar4DecodeError::CounterOverflow)));
    assert!(d.poisoned);
}

#[test]
fn cancellation_in_boundary_tables_copy_and_next_transition_is_terminal() {
    let bytes = literals_control(0, false);
    let mut d = create(&bytes, 0);
    d.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    d.validate_defer(c).unwrap().commit();
    d.work.cancel_at = Some(d.work.operations + 100);
    assert!(matches!(d.resume_boundary(&bytes), Err(Rar4DecodeError::Canceled)));
    assert!(d.poisoned);
    assert_eq!(d.produced, 0);
    let (mut d, c) = logical_member();
    d.validate_defer(c).unwrap().commit();
    d.work.operations = 255;
    d.work.cancel_at = Some(256);
    assert!(matches!(d.resume_boundary(&[]), Err(Rar4DecodeError::Canceled)));
    assert!(d.poisoned);
    let (mut d, b) = ready_member();
    let before = d.binding;
    d.work.cancel.as_ref().unwrap().cancel();
    assert!(matches!(d.begin_next(b, frame(0, 0, 8)), Err(Rar4DecodeError::Canceled)));
    assert!(d.poisoned);
    assert_eq!(d.binding, before);
    let packed = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/official-lz-m3.packed"));
    let mut d = create(packed, 302400);
    d.work.cancel_at = Some(d.work.operations + 100000);
    assert!(matches!(d.feed(packed, &mut |_: &[u8]| Ok(())), Err(Rar4DecodeError::Canceled)));
    assert!(d.produced > 0 && d.produced < 302400);
    assert!(d.poisoned);
}

#[test]
fn production_lifecycle_allocates_one_window_and_zero_transition_storage() {
    let bytes = literals_control(1, false);
    let next = [0];
    let cancel = Cancellation::default();
    ALLOC_REQUESTS.with(|c| c.set(0));
    TRACK_ALLOC.with(|f| f.set(true));
    let created = Rar4Decoder::new_frame(frame(bytes.len(), 1, 7), 65536, Some(cancel));
    TRACK_ALLOC.with(|f| f.set(false));
    assert_eq!(ALLOC_REQUESTS.with(|c| c.get()), 1);
    let mut d = created.unwrap();
    let pointer = d.dictionary.as_ptr();
    let mut output = 0usize;
    let mut sink = |b: &[u8]| {
        output += b.len();
        Ok(())
    };
    ALLOC_REQUESTS.with(|c| c.set(0));
    TRACK_ALLOC.with(|f| f.set(true));
    let result = (|| -> DecodeResult<()> {
        d.feed(&bytes, &mut sink)?;
        let c = d.finish_logical(&mut sink)?;
        d.validate_defer(c)?.commit();
        let b = match d.resume_boundary(&[])? {
            BoundaryState::Ready(b) => b,
            BoundaryState::NeedInput => match d.resume_boundary(&bytes[d.fetched as usize..])? {
                BoundaryState::Ready(b) => b,
                BoundaryState::NeedInput => return Err(Rar4DecodeError::State),
            },
        };
        d.begin_next(b, frame(next.len(), 1, 8))?;
        d.feed(&next, &mut sink)?;
        d.finish(&mut sink)?;
        d.reset_independent(frame(bytes.len(), 1, 9))?;
        d.feed(&bytes, &mut sink)?;
        d.finish(&mut sink)?;
        Ok(())
    })();
    TRACK_ALLOC.with(|f| f.set(false));
    result.unwrap();
    assert_eq!(ALLOC_REQUESTS.with(|c| c.get()), 0);
    assert_eq!(output, 3);
    assert_eq!(d.dictionary.as_ptr(), pointer);
    println!(
        "native fixed decoder={} frame={} binding={} completion={} boundary={} guard={} window_len={} capacity={} transition_allocations=0",
        std::mem::size_of::<Rar4Decoder>(),
        std::mem::size_of::<CoreFrame>(),
        std::mem::size_of::<CoreBinding>(),
        std::mem::size_of::<lifecycle::Completion>(),
        std::mem::size_of::<Boundary>(),
        std::mem::size_of::<lifecycle::DeferGuard<'_>>(),
        d.dictionary.len(),
        d.dictionary.capacity()
    );
    println!(
        "explicit scratch: Huff={} reset_table_array={} Huff_build_offsets={} bytes; stack/RSS peak not measured",
        std::mem::size_of::<Huff>(),
        std::mem::size_of::<[Huff; 5]>(),
        std::mem::size_of::<[usize; 16]>()
    );
    assert!(std::mem::size_of::<Rar4Decoder>() <= 48 * 1024);
}

#[test]
fn wrong_retained_tables_history_and_reset_are_falsified_by_actual_protocol() {
    // A dependent match must have tables and bytes from its predecessor.
    let mut lengths = [0; 404];
    for s in [65, 66, 256, 271] {
        lengths[s] = 2;
    }
    lengths[299] = 1;
    let mut first = Vector::default();
    first.tables(&lengths, None);
    first.symbol(&lengths[..299], 66);
    first.end(&lengths, false);
    let bytes = first.bytes();
    let mut v = Vector::default();
    v.symbol(&lengths[..299], 271);
    v.symbol(&lengths[299..359], 0);
    v.end(&lengths, false);
    let next = v.bytes();
    for wrong in 0..4 {
        let mut d = create(&bytes, 1);
        d.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
        let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
        d.validate_defer(c).unwrap().commit();
        let b = boundary(&mut d, &bytes, 1);
        d.begin_next(b, frame(next.len(), 3, 8)).unwrap();
        match wrong {
            0 => d.chain_base = 0,
            1 => d.dictionary.fill(0),
            2 => d.chain_base += 1,
            _ => d.tables[1] = Huff::empty(),
        }
        let mut out = Vec::new();
        let result = d.feed(&next, &mut sink(&mut out));
        if wrong == 0 || wrong == 3 {
            assert!(result.is_err());
            assert!(d.poisoned);
        } else {
            result.unwrap();
            d.finish(&mut sink(&mut out)).unwrap();
            assert_ne!(out, b"BBB");
        }
    }
    // Reset removes old-length delta state; a table stream encoding only deltas
    // to the prior lengths must fail instead of using history after reset.
    let first = literals_control(1, true);
    let mut next = Vector::default();
    let lengths = literal_lengths();
    next.tables(&lengths, Some(&lengths));
    next.symbol(&lengths[..299], 65);
    let next = next.bytes();
    let mut d = create(&first, 1);
    d.feed(&first, &mut |_: &[u8]| Ok(())).unwrap();
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    d.validate_defer(c).unwrap().commit();
    let b = boundary(&mut d, &first, 1);
    d.begin_next(b, frame(next.len(), 1, 8)).unwrap();
    d.reset_independent(frame(next.len(), 1, 9)).unwrap();
    assert!(matches!(d.feed(&next, &mut |_: &[u8]| Ok(())), Err(Rar4DecodeError::Malformed("empty literal table"))));
}

#[test]
fn deferred_ppm_filter_and_same_file_truncation_keep_typed_failures() {
    let lengths = literal_lengths();
    for mode in 0..2 {
        let first = literals(1, true);
        let mut next = Vector::default();
        if mode == 0 {
            next.number(1, 1);
        } else {
            let mut l = [0; 404];
            l[65] = 1;
            l[257] = 1;
            next.tables(&l, None);
            next.symbol(&l[..299], 257);
        }
        let bytes = first.bytes();
        let next = next.bytes();
        let mut d = create(&bytes, 1);
        d.feed(&bytes, &mut |_: &[u8]| Ok(())).unwrap();
        let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
        d.validate_defer(c).unwrap().commit();
        let b = boundary(&mut d, &bytes, 1);
        d.begin_next(b, frame(next.len(), 0, 8)).unwrap();
        d.feed(&next, &mut |_: &[u8]| Ok(())).unwrap();
        let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
        d.validate_defer(c).unwrap().commit();
        // a PPM block or a filter record where the end-of-file marker belongs never grants a boundary
        assert!(d.resume_boundary(&next).is_err(), "mode {mode}");
        assert!(d.poisoned);
    }
    let mut v = Vector::default();
    v.tables(&lengths, None);
    v.symbol(&lengths[..299], 65);
    v.symbol(&lengths[..299], 256);
    v.number(1, 1);
    v.tables(&lengths, Some(&lengths));
    v.end(&lengths, false);
    let bytes = v.bytes();
    for end in (82 + 404 * 4 + 8) / 8..bytes.len() {
        let cut = &bytes[..end];
        let mut d = create(cut, 1);
        if d.feed(cut, &mut |_: &[u8]| Ok(())).is_err() {
            continue;
        }
        let Ok(c) = d.finish_logical(&mut |_: &[u8]| Ok(())) else {
            continue;
        };
        d.validate_defer(c).unwrap().commit();
        let result = d.resume_boundary(&[]);
        let result = match result {
            Ok(BoundaryState::NeedInput) => d.resume_boundary(&cut[d.fetched as usize..]),
            other => other,
        };
        assert!(result.is_err(), "real same-file table prefix {end} cannot grant continuation");
        assert!(d.poisoned);
    }
}

#[test]
fn dependent_empty_member_retains_exact_history_and_phase() {
    let first = literals_control(1, false);
    let mut d = create(&first, 1);
    let initial = d.active_binding().unwrap();
    d.feed(&first, &mut |_: &[u8]| Ok(())).unwrap();
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    assert_eq!(initial, c.binding());
    d.validate_defer(c).unwrap().commit();
    let b = boundary(&mut d, &first, 1);
    let empty = [0x80];
    d.begin_next(b, frame(1, 0, 8)).unwrap();
    d.feed(&empty, &mut |_: &[u8]| Ok(())).unwrap();
    assert_eq!((d.chain_base, d.produced, d.fed, d.fetched), (1, 0, 1, 0));
    let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
    d.validate_defer(c).unwrap().commit();
    let b = boundary(&mut d, &empty, 1);
    assert_eq!(d.consumed_bits().unwrap(), 3);
    d.begin_next(b, frame(1, 1, 9)).unwrap();
    let mut out = Vec::new();
    d.feed(&[0], &mut sink(&mut out)).unwrap();
    d.finish(&mut sink(&mut out)).unwrap();
    assert_eq!(out, b"A");
    assert_eq!((d.chain_base, d.binding.member_seq, d.table_builds), (1, 3, 1));
}

#[test]
fn every_real_bit_of_fifteen_bit_end_and_flags_is_required() {
    let mut lengths = [0; 404];
    lengths[65] = 1;
    lengths[256] = 15;
    let table_bits = 82 + 404 * 4;
    for retained_end_bits in 0..17 {
        let literal_count = (8 - (table_bits + retained_end_bits) % 8) % 8;
        let mut v = Vector::default();
        v.tables(&lengths, None);
        for _ in 0..literal_count {
            v.symbol(&lengths[..299], 65);
        }
        v.end(&lengths, false);
        let bytes = v.bytes();
        let cut = (table_bits + literal_count + retained_end_bits) / 8;
        let bytes = &bytes[..cut];
        let mut d = create(bytes, literal_count);
        d.feed(bytes, &mut |_: &[u8]| Ok(())).unwrap();
        let c = d.finish_logical(&mut |_: &[u8]| Ok(())).unwrap();
        d.validate_defer(c).unwrap().commit();
        let result = d.resume_boundary(&[]);
        let result = match result {
            Ok(BoundaryState::NeedInput) => d.resume_boundary(&bytes[d.fetched as usize..]),
            other => other,
        };
        assert!(matches!(result, Err(Rar4DecodeError::Malformed(_))), "end prefix {retained_end_bits}");
        assert!(d.poisoned);
        assert_eq!(d.consumed_bits().unwrap(), cut as u64 * 8);
    }
}

#[test]
fn private_state_binding_failures_project_internal_and_never_integrity() {
    for e in [Rar4DecodeError::State, Rar4DecodeError::Binding] {
        let fault = e.detailed(crate::error::RarScope::Member { index: Some(7) });
        let (failure, _) = fault.into_parts();
        assert!(matches!(
            *failure,
            crate::error::RarFailure::Internal(crate::error::RarInternal::Invariant("RAR4 completion/source binding"))
        ));
    }
}
