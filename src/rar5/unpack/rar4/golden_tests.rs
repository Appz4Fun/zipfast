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

//! Output and failure goldens recorded with the bit-by-bit Huffman decoder this file was written against: the
//! table-driven decoder must reproduce them exactly. Each fixture stream is decoded as is and under deterministic
//! mutations (bit flips, overwritten bytes, truncation), fed whole, a byte at a time and in 5-byte pieces, so the
//! table path, the end-of-input fallback and every malformed-table failure (incomplete and oversubscribed code
//! lengths, undefined codes) are each compared against what the old decoder did.

use super::*;

macro_rules! lz {
    ($name:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/", $name))
    };
}

/// (name, packed stream, expected unpacked size)
fn bases() -> Vec<(&'static str, Vec<u8>, usize)> {
    let mut bases = vec![
        ("all-recent-slots", lz!("all-recent-slots.packed").to_vec(), 56),
        ("code-length-nibble-zero-run", lz!("code-length-nibble-zero-run.packed").to_vec(), 1),
        ("dd10-low", lz!("dd10-low.packed").to_vec(), 36),
        ("dd59-reach4m", lz!("dd59-reach4m.packed").to_vec(), 4194309),
        ("low-repeat16", lz!("low-repeat16.packed").to_vec(), 90),
        ("low-reset-table", lz!("low-reset-table.packed").to_vec(), 45),
        ("new-match-repeat-last", lz!("new-match-repeat-last.packed").to_vec(), 7),
        ("official-lz-m1", lz!("official-lz-m1.packed").to_vec(), 302400),
        ("official-lz-m3", lz!("official-lz-m3.packed").to_vec(), 302400),
        ("previous-length-runs", lz!("previous-length-runs.packed").to_vec(), 2),
        ("table-reuse-delta", lz!("table-reuse-delta.packed").to_vec(), 2),
        ("threshold262144", lz!("threshold262144.packed").to_vec(), 262149),
        ("threshold8192", lz!("threshold8192.packed").to_vec(), 8196),
        ("vm-marker-after-prefix", lz!("vm-marker-after-prefix.packed").to_vec(), 4096),
    ];
    // rar 6.24 -ma4 -m3 of zipf.txt (Zipf-distributed words: codes up to 15 bits) and code.exe (x86-like bytes)
    let archive = lz!("zipf-m3.rar");
    for (name, (offset, packed, unpacked)) in ["zipf-text", "zipf-code"].into_iter().zip(members(archive)) {
        bases.push((name, archive[offset..offset + packed].to_vec(), unpacked));
    }
    bases.extend(constructed());
    bases
}

/// The (payload offset, packed size, unpacked size) of each file block of a plain RAR 4.x archive.
fn members(archive: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut found = Vec::new();
    let mut at = 7;
    while at + 7 <= archive.len() {
        let u16_at = |p: usize| usize::from(u16::from_le_bytes([archive[p], archive[p + 1]]));
        let u32_at = |p: usize| u32::from_le_bytes(archive[p..p + 4].try_into().unwrap()) as usize;
        let (kind, flags, size) = (archive[at + 2], u16_at(at + 3), u16_at(at + 5));
        let add = if kind == 0x74 || flags & 0x8000 != 0 { u32_at(at + 7) } else { 0 };
        if kind == 0x74 {
            found.push((at + size, add, u32_at(at + 11)));
        }
        at += size + add;
    }
    found
}

struct BitWriter {
    bytes: Vec<u8>,
    used: u32,
}
impl BitWriter {
    fn new() -> Self {
        Self { bytes: Vec::new(), used: 0 }
    }
    fn put(&mut self, value: u32, n: u32) {
        for k in (0..n).rev() {
            if self.used % 8 == 0 {
                self.bytes.push(0);
            }
            if (value >> k) & 1 != 0 {
                *self.bytes.last_mut().unwrap() |= 0x80 >> (self.used % 8);
            }
            self.used += 1;
        }
    }
}

/// Hand-built table failures.
fn constructed() -> Vec<(&'static str, Vec<u8>, usize)> {
    let mut cases = Vec::new();
    // three code-length codes of length 1: oversubscribed
    let mut w = BitWriter::new();
    w.put(0, 2);
    for _ in 0..20 {
        w.put(1, 4);
    }
    w.put(0, 16);
    cases.push(("bc-oversubscribed", w.bytes, 16));
    // one code-length code of length 1 ("0"): every code starting with 1 is undefined
    let mut w = BitWriter::new();
    w.put(0, 2);
    w.put(1, 4);
    w.put(15, 4);
    w.put(15, 4); // 17 zero lengths
    w.put(0, 4);
    w.put(0, 4);
    w.put(0x7fff, 15);
    w.put(0x7fff, 15);
    cases.push(("bc-incomplete-undefined", w.bytes, 16));
    // code-length codes of lengths 1..15 and one more 15: complete, with the longest codes the format allows
    let mut w = BitWriter::new();
    w.put(0, 2);
    for length in 1..15 {
        w.put(length, 4);
    }
    w.put(15, 4);
    w.put(0, 4); // one length 15 (symbol 14)
    w.put(15, 4);
    w.put(0, 4); // and another (symbol 15)
    w.put(0, 4);
    w.put(0, 4);
    w.put(0, 4);
    w.put(0, 4);
    for _ in 0..64 {
        w.put(0x7ffe, 15); // symbol 14
        w.put(0x7ffc >> 1, 14); // symbol 13
        w.put(0, 1); // symbol 0
    }
    cases.push(("bc-fifteen-bit-codes", w.bytes, 16));
    cases
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(base: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut bytes = base.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    // half the mutations land in the first 96 bytes, where the tables are
    let at = |rng: &mut Rng, len: usize| if rng.next() & 1 == 0 { rng.below(len.min(96)) } else { rng.below(len) };
    match rng.below(4) {
        0 => {
            let p = at(rng, bytes.len());
            bytes[p] ^= 1 << rng.below(8);
        }
        1 => {
            for _ in 0..3 {
                let p = at(rng, bytes.len());
                bytes[p] ^= 1 << rng.below(8);
            }
        }
        2 => {
            let p = at(rng, bytes.len());
            bytes[p] = rng.next() as u8;
        }
        _ => {
            let p = at(rng, bytes.len());
            bytes.truncate(p);
        }
    }
    bytes
}

fn fnv(hash: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *hash = (*hash ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
    }
}

/// Decodes `packed` fed in `chunk`-byte pieces, then finishes: the output's length and hash, and how it ended.
fn decode(packed: &[u8], unpacked: usize, chunk: usize) -> String {
    let mut d = Rar4Decoder::new(4 << 20, packed.len() as u64, unpacked as u64, 4 << 20, Cancellation::default())
        .expect("decoder");
    let mut out = Vec::new();
    let mut sink = |bytes: &[u8]| {
        out.extend_from_slice(bytes);
        Ok(())
    };
    let mut status = None;
    for piece in packed.chunks(chunk.max(1)) {
        if let Err(error) = d.feed(piece, &mut sink) {
            status = Some(format!("feed {error:?}"));
            break;
        }
    }
    let status = match status {
        Some(status) => status,
        None => match d.finish(&mut sink) {
            Ok(()) => "ok".to_string(),
            Err(error) => format!("finish {error:?}"),
        },
    };
    let mut hash = 0xcbf2_9ce4_8422_2325;
    fnv(&mut hash, &out);
    format!("{}:{hash:016x}:{status}", out.len())
}

fn digest(name: &str, packed: &[u8], unpacked: usize) -> u64 {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ name.len() as u64 ^ (packed.len() as u64) << 20);
    let mut hash = 0xcbf2_9ce4_8422_2325;
    // big outputs take long to decode a byte of input at a time: fewer mutations, fed in 5-byte pieces
    let big = unpacked > 1 << 16;
    let mutations = if unpacked > 1 << 20 { 8 } else if big { 40 } else { 150 };
    for case in 0..=mutations {
        let bytes = if case == 0 { packed.to_vec() } else { mutate(packed, &mut rng) };
        let chunks: &[usize] = if big && case != 0 { &[usize::MAX, 5] } else { &[usize::MAX, 1, 5] };
        for &chunk in chunks {
            let record = decode(&bytes, unpacked, chunk);
            fnv(&mut hash, record.as_bytes());
            fnv(&mut hash, b"\n");
        }
    }
    hash
}

/// Recorded with the bit-by-bit decoder (zipfast 56819cd7).
const GOLDEN: &[(&str, u64)] = &[
    ("all-recent-slots", 0xaa5163684f9a3d51),
    ("code-length-nibble-zero-run", 0x5a7ff6942c6f5c8d),
    ("dd10-low", 0xf106d182f37ab38f),
    ("dd59-reach4m", 0x89ad910d7be64d98),
    ("low-repeat16", 0xe65f1a1039fc445f),
    ("low-reset-table", 0x4df806ad368c8ac8),
    ("new-match-repeat-last", 0x918dc7d7e83e17a8),
    ("official-lz-m1", 0xa048d6848cbb3151),
    ("official-lz-m3", 0xb3b7a9e7ec9f559b),
    ("previous-length-runs", 0x33657ff6dbedd612),
    ("table-reuse-delta", 0xd2cdf70ea9e5907b),
    ("threshold262144", 0xbf4d7cc926d8712a),
    ("threshold8192", 0x1bd0655c1b395a60),
    ("vm-marker-after-prefix", 0xf2b40f96a00abbe7),
    ("zipf-text", 0x7ceec6facabe93b4),
    ("zipf-code", 0xc82644e4bc7a919b),
    ("bc-oversubscribed", 0x0680218dc1f87d44),
    ("bc-incomplete-undefined", 0xb28722b366072f86),
    ("bc-fifteen-bit-codes", 0x78f0aead1728c309),
];

#[test]
fn table_decoder_reproduces_bitwise_goldens() {
    let computed: Vec<(&str, u64)> =
        bases().iter().map(|(name, packed, unpacked)| (*name, digest(name, packed, unpacked.to_owned()))).collect();
    let table: String = computed.iter().map(|(name, hash)| format!("    (\"{name}\", 0x{hash:016x}),\n")).collect();
    assert_eq!(computed.as_slice(), GOLDEN, "computed goldens:\n{table}");
}

#[test]
fn unmutated_streams_report_as_before() {
    // the fixtures' own outcomes, readable: a regression here names the stream
    for (name, packed, unpacked) in bases() {
        let whole = decode(&packed, unpacked, usize::MAX);
        assert_eq!(decode(&packed, unpacked, 1), whole, "{name}");
        eprintln!("{name}: {whole}");
    }
}

/// The code at the start of `window` found as the old decoder did: a bit at a time, against each length's codes.
fn bitwise(h: &Huff, window: u32) -> Option<(u16, u8)> {
    let mut prefix = 0;
    for depth in 1..16 {
        prefix = (prefix << 1) | ((window >> (15 - depth)) & 1);
        if let Some(relative) = prefix.checked_sub(h.first[depth])
            && relative < u32::from(h.count[depth])
        {
            return Some((h.symbols[h.offset[depth] + relative as usize], depth as u8));
        }
    }
    None
}

#[test]
fn table_lookup_matches_the_bitwise_search_for_every_window() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut work = Work { operations: 0, cancel: None, cancel_at: None };
    let mut h = Huff::empty();
    let (mut complete, mut incomplete) = (0, 0);
    for round in 0..240 {
        let n = [20, 299, 60, 17, 28][round % 5];
        // lengths that fit the code space, in random symbol order: often incomplete, sometimes complete
        let mut lengths = vec![0u8; n];
        let mut space = 1u32 << 15;
        let longest = 1 + rng.below(15) as u32;
        for _ in 0..n * 2 {
            let symbol = rng.below(n);
            let length = 1 + rng.below(longest as usize) as u32;
            if lengths[symbol] == 0 && space >= 1 << (15 - length) {
                lengths[symbol] = length as u8;
                space -= 1 << (15 - length);
            }
        }
        // fill what is left with the longest codes when there are symbols for them
        for length in lengths.iter_mut().filter(|l| **l == 0) {
            if round % 2 == 0 && space != 0 {
                *length = 15;
                space -= 1;
            }
        }
        if space == 0 { complete += 1 } else { incomplete += 1 }
        h.build(&lengths, &mut work).unwrap();
        for window in 0..1u32 << 15 {
            let entry = h.quick[(window >> (15 - QUICK_BITS)) as usize];
            let table = if entry != 0 { Some((entry >> 4, (entry & 15) as u8)) } else { h.long(window) };
            assert_eq!(table, bitwise(&h, window), "round {round} window {window:#06x} lengths {lengths:?}");
        }
    }
    assert!(complete > 10 && incomplete > 10, "{complete} complete, {incomplete} incomplete");
    // oversubscribed lengths still fail the build as before
    assert!(matches!(h.build(&[1, 1, 1], &mut work), Err(Rar4DecodeError::Malformed("oversubscribed Huffman table"))));
    assert!(matches!(h.build(&[16], &mut work), Err(Rar4DecodeError::Malformed("code length"))));
}
