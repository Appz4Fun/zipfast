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

//! Restarts of the feed decoder at stored Deflate blocks after a hole (WP-A7): hand-built Deflate streams (stored and
//! fixed-Huffman blocks, so every block and output offset is known), ZIPs around them, holes before stored blocks.

use std::io::Cursor;
use zipfast::map::*;
use zipfast::zip::write::*;

// ---- a small Deflate writer: stored and fixed-Huffman blocks, with the output it makes ----

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u32; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

#[derive(Clone, Copy)]
enum Op {
    Lit(u8),
    /// length 3..=227, distance 1..=32768
    Match(u16, u32),
}

#[derive(Default)]
struct Deflater {
    bytes: Vec<u8>,
    acc: u64,
    n: u32,
    plain: Vec<u8>,
    /// (output offset, stream byte offset) at the start of each block's header
    marks: Vec<(u64, usize)>,
}

impl Deflater {
    fn bits(&mut self, v: u32, n: u32) {
        self.acc |= u64::from(v) << self.n;
        self.n += n;
        while self.n >= 8 {
            self.bytes.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// A Huffman code, most significant bit first.
    fn code(&mut self, v: u32, n: u32) {
        let mut r = 0;
        for i in 0..n {
            r |= ((v >> i) & 1) << (n - 1 - i);
        }
        self.bits(r, n);
    }

    fn align(&mut self) {
        if self.n > 0 {
            self.bits(0, 8 - self.n);
        }
    }

    fn mark(&mut self) {
        self.marks.push((self.plain.len() as u64, self.bytes.len()));
    }

    fn stored(&mut self, data: &[u8], last: bool) {
        for chunk in data.chunks(65_535).chain(data.is_empty().then_some(&[][..])) {
            self.mark();
            let end =
                last && std::ptr::eq(chunk.as_ptr_range().end, data.as_ptr_range().end) || data.is_empty() && last;
            self.bits(u32::from(end), 1);
            self.bits(0, 2);
            self.align();
            self.bits(chunk.len() as u32, 16);
            self.bits(!(chunk.len() as u32) & 0xFFFF, 16);
            self.bytes.extend_from_slice(chunk);
            self.plain.extend_from_slice(chunk);
        }
    }

    fn sym(&mut self, s: u32) {
        match s {
            0..=143 => self.code(0x30 + s, 8),
            144..=255 => self.code(0x190 + s - 144, 9),
            256..=279 => self.code(s - 256, 7),
            _ => self.code(0xC0 + s - 280, 8),
        }
    }

    fn fixed(&mut self, ops: &[Op], last: bool) {
        self.mark();
        self.bits(u32::from(last), 1);
        self.bits(1, 2);
        for &op in ops {
            match op {
                Op::Lit(b) => {
                    self.sym(u32::from(b));
                    self.plain.push(b);
                }
                Op::Match(len, dist) => {
                    let li = LEN_BASE.iter().rposition(|&b| b <= len && len != 258 || b == len).unwrap();
                    self.sym(257 + li as u32);
                    self.bits(u32::from(len - LEN_BASE[li]), u32::from(LEN_EXTRA[li]));
                    let di = DIST_BASE.iter().rposition(|&b| b <= dist).unwrap();
                    self.code(di as u32, 5);
                    self.bits(dist - DIST_BASE[di], u32::from(DIST_EXTRA[di]));
                    for _ in 0..len {
                        let b = self.plain[self.plain.len() - dist as usize];
                        self.plain.push(b);
                    }
                }
            }
        }
        self.sym(256);
    }

    fn finish(mut self) -> (Vec<u8>, Vec<u8>, Vec<(u64, usize)>) {
        self.align();
        (self.bytes, self.plain, self.marks)
    }
}

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }
}

/// Bytes that do not look like a stored block header anywhere (no LEN/NLEN pair), so the only candidates are the ones
/// a test puts there.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut next = rng(seed);
    let mut v: Vec<u8> = (0..len).map(|_| next() as u8).collect();
    for i in 0..v.len().saturating_sub(3) {
        if v[i] ^ v[i + 2] == 0xFF && v[i + 1] ^ v[i + 3] == 0xFF {
            v[i + 2] ^= 0x55;
        }
    }
    v
}

/// Literals of text-like bytes, with matches back into what is there.
fn ops(have: usize, len: usize, seed: u64, back: u32) -> Vec<Op> {
    let mut next = rng(seed);
    let mut out = Vec::new();
    let mut made = 0usize;
    while made < len {
        let r = next();
        if r.is_multiple_of(5) && have + made > 3 {
            let l = 3 + (r >> 8) as u16 % 40;
            out.push(Op::Match(l, 1 + ((r >> 20) as u32 % back.min((have + made) as u32))));
            made += l as usize;
        } else {
            out.push(Op::Lit(b'a' + (r >> 8) as u8 % 26));
            made += 1;
        }
    }
    out
}

// ---- a ZIP around raw Deflate bytes ----

fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

fn raw_zip(method: u16, packed: &[u8], plain: &[u8]) -> Vec<u8> {
    let name = b"m.bin";
    let crc = crc32(plain);
    let mut z = Vec::new();
    let le16 = |z: &mut Vec<u8>, v: u16| z.extend_from_slice(&v.to_le_bytes());
    let le32 = |z: &mut Vec<u8>, v: u32| z.extend_from_slice(&v.to_le_bytes());
    le32(&mut z, 0x0403_4b50);
    for v in [20, 0, method, 0, 0x21] {
        le16(&mut z, v);
    }
    for v in [crc, packed.len() as u32, plain.len() as u32] {
        le32(&mut z, v);
    }
    le16(&mut z, name.len() as u16);
    le16(&mut z, 0);
    z.extend_from_slice(name);
    z.extend_from_slice(packed);
    let cd = z.len();
    le32(&mut z, 0x0201_4b50);
    for v in [20, 20, 0, method, 0, 0x21] {
        le16(&mut z, v);
    }
    for v in [crc, packed.len() as u32, plain.len() as u32] {
        le32(&mut z, v);
    }
    for v in [name.len() as u16, 0, 0, 0, 0] {
        le16(&mut z, v);
    }
    le32(&mut z, 0);
    le32(&mut z, 0);
    z.extend_from_slice(name);
    let cd_len = z.len() - cd;
    le32(&mut z, 0x0605_4b50);
    for v in [0, 0, 1, 1] {
        le16(&mut z, v);
    }
    le32(&mut z, cd_len as u32);
    le32(&mut z, cd as u32);
    le16(&mut z, 0);
    z
}

/// The offset of the member's packed data in `raw_zip`'s file.
const DATA: usize = 30 + 5;

/// A sink that allows a byte to be written again only after the decoder reported it lost (a refuted restart), and
/// counts what it was given.
#[derive(Default)]
struct Sink {
    out: Vec<u8>,
    seen: Vec<bool>,
    writes: u64,
    twice: u64,
}

impl FeedSink for Sink {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        let end = offset as usize + bytes.len();
        if self.seen.len() < end {
            self.seen.resize(end, false);
            self.out.resize(end, 0);
        }
        self.twice += self.seen[offset as usize..end].iter().filter(|&&s| s).count() as u64;
        self.seen[offset as usize..end].iter_mut().for_each(|s| *s = true);
        self.out[offset as usize..end].copy_from_slice(bytes);
        self.writes += bytes.len() as u64;
        Ok(())
    }

    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let at = offset as usize;
        let n = self.seen.get(at..).map_or(0, |s| s.iter().take(buf.len()).take_while(|&&s| s).count());
        buf[..n].copy_from_slice(&self.out[at..at + n]);
        Ok(n)
    }
}

fn options() -> FeedOptions {
    FeedOptions { max_needs: usize::MAX, ..FeedOptions::new(None) }
}

struct Run {
    status: FeedStatus,
    stats: FeedStats,
    sink: Sink,
    /// the status with the hole open, after everything else is fed
    open: FeedStatus,
    /// which output bytes the sink held with the hole open
    open_seen: Vec<bool>,
    open_out: Vec<u8>,
}

/// Feeds the ZIP in articles with the packed range `hole` lost, then the hole's bytes.
fn run_hole(zip: &[u8], hole: std::ops::Range<usize>, plain: &[u8], article: usize) -> Run {
    let map = MemberMap::from_memory(&[zip], "r.zip", None).unwrap();
    let mut d = FeedDecoder::new(&map, 0, options()).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Sink::default();
    let (h0, h1) = (DATA + hole.start, DATA + hole.end);
    source.insert(0, 0, &zip[..h0]).unwrap();
    d.run(&mut source, &mut sink).unwrap();
    source.mark_lost(0, h0 as u64..h1 as u64);
    for (i, c) in zip[h1..].chunks(article).enumerate() {
        source.insert(0, (h1 + i * article) as u64, c).unwrap();
        d.run(&mut source, &mut sink).unwrap();
    }
    let open = d.status().clone();
    let open_seen = sink.seen.clone();
    let open_out = sink.out.clone();
    source.insert(0, h0 as u64, &zip[h0..h1]).unwrap();
    d.run(&mut source, &mut sink).unwrap();
    let status = d.status().clone();
    assert!(status.done && status.lost.is_empty(), "{status:?}");
    assert_eq!(sink.out.len(), plain.len());
    assert!(sink.out == plain, "output differs");
    Run { status, stats: d.stats(), sink, open, open_seen, open_out }
}

/// The unwritten bytes below `end` with the hole open, as ranges.
fn unwritten(seen: &[bool], end: usize) -> Vec<std::ops::Range<u64>> {
    let mut out: Vec<std::ops::Range<u64>> = Vec::new();
    for i in 0..end {
        if !seen.get(i).copied().unwrap_or(false) {
            match out.last_mut() {
                Some(r) if r.end == i as u64 => r.end += 1,
                _ => out.push(i as u64..i as u64 + 1),
            }
        }
    }
    out
}

/// text block, a stored block of `stored` bytes holding a fake LEN/NLEN that does not decode, text with matches back
/// across the stored block, noise, and a final text block.
fn stream(stored: usize) -> (Vec<u8>, Vec<u8>, Vec<(u64, usize)>) {
    let mut d = Deflater::default();
    d.fixed(&ops(d.plain.len(), 30_000, 1, 3_000), false);
    let mut payload = noise(stored, 2);
    // a pair that checks out after a zero byte, and decodes to nothing valid
    payload[100..105].copy_from_slice(&[0x00, 0x34, 0x12, 0xCB, 0xED]);
    d.stored(&payload, false);
    d.fixed(&ops(d.plain.len(), 20_000, 3, 32_000), false);
    d.stored(&noise(9_000, 4), false);
    d.fixed(&ops(d.plain.len(), 10_000, 5, 20_000), true);
    d.finish()
}

#[test]
fn a_hole_before_a_stored_block_restarts_there() {
    let (packed, plain, marks) = stream(40_000);
    for method in [8u16, 9] {
        let zip = raw_zip(method, &packed, &plain);
        // the hole: inside the first block
        let hole = 5_000..7_500;
        let r = run_hole(&zip, hole.clone(), &plain, 3_000);
        let restart = marks[1].0;
        let lost = &r.open.lost;
        assert_eq!(lost.len(), 1, "{lost:?}");
        assert_eq!(lost[0].end, restart, "the lost range ends where the stored block's output starts");
        // exactly the lost range is unwritten below the stored block, and the stored block is written
        assert_eq!(unwritten(&r.open_seen, restart as usize), vec![lost[0].clone()]);
        assert!(lost[0].start > 3_000 && lost[0].start < restart);
        assert!(!r.open.done && !r.open.stalled && r.open.unproven);
        assert!(r.open.frontier > restart + 40_000 - 1);
        assert!(r.open.needs.iter().any(|n| n.kind == NeedKind::Repair && n.range.start == (DATA + hole.start) as u64));
        // what was written is the plain output
        for i in 0..r.open_seen.len() {
            if r.open_seen[i] {
                assert_eq!(r.open_out[i], plain[i], "byte {i}");
            }
        }
        // 64 KiB windows (Deflate64) are not complete after 40000 bytes: the block after waits for the repair
        if method == 9 {
            assert_eq!(r.open.frontier, restart + 40_000);
        } else {
            assert!(r.open.frontier > restart + 40_000 + 15_000, "{}", r.open.frontier);
        }
        assert_eq!(r.status.crc_ok, Some(true));
        assert!(!r.status.unproven);
        assert_eq!(r.sink.twice, 0, "each byte written once");
        assert_eq!(r.stats.written, plain.len() as u64);
        assert!(r.stats.redecoded > 0);
    }
}

#[test]
fn a_short_stored_block_does_not_hold_the_window_of_a_later_block() {
    // 5000 bytes of stored data, then a block that matches 20000 bytes back: into the lost output
    let mut d = Deflater::default();
    d.fixed(&ops(d.plain.len(), 30_000, 11, 3_000), false);
    d.stored(&noise(5_000, 12), false);
    d.fixed(&ops(d.plain.len(), 8_000, 13, 20_000), false);
    d.stored(&noise(2_000, 14), true);
    let (packed, plain, marks) = d.finish();
    let zip = raw_zip(8, &packed, &plain);
    let r = run_hole(&zip, 5_000..7_000, &plain, 3_000);
    let restart = marks[1].0;
    assert_eq!(r.open.lost.len(), 1);
    assert_eq!(r.open.lost[0].end, restart);
    // the stored block is written; the block after it is not decoded (its window is partly lost)
    assert_eq!(r.open.frontier, restart + 5_000);
    assert_eq!(r.open_seen.len() as u64, restart + 5_000);
    assert_eq!(r.status.crc_ok, Some(true));
    assert_eq!(r.sink.twice, 0);
    assert_eq!(r.stats.written, plain.len() as u64);
}

#[test]
fn consecutive_stored_blocks_need_no_window() {
    // stored blocks after a short one decode though the window is partly lost; a stream of them restarts whole
    let mut d = Deflater::default();
    d.fixed(&ops(d.plain.len(), 30_000, 21, 3_000), false);
    for i in 0..6 {
        d.stored(&noise(3_000, 30 + i), false);
    }
    d.fixed(&ops(d.plain.len(), 8_000, 22, 100), true);
    let (packed, plain, marks) = d.finish();
    let zip = raw_zip(8, &packed, &plain);
    let r = run_hole(&zip, 4_000..6_000, &plain, 2_500);
    assert_eq!(r.open.lost[0].end, marks[1].0);
    // the six stored blocks (18000 bytes, short of a window) are written; the Huffman block after them is not
    assert_eq!(r.open.frontier, marks[1].0 + 18_000);
    assert_eq!(r.status.crc_ok, Some(true));
    assert_eq!(r.sink.twice, 0);
}

#[test]
fn a_false_match_that_decodes_is_refuted_and_the_decode_falls_back() {
    // the hole swallows the real stored block's header; inside its payload sits a LEN/NLEN pair after a zero byte
    // whose block runs to the data's end as a final stored block, so the whole rest "decodes" from there, with an
    // output offset five bytes off
    let mut d = Deflater::default();
    d.fixed(&ops(d.plain.len(), 30_000, 41, 3_000), false);
    let b1 = noise(20_000, 42);
    let b2 = noise(3_000, 43);
    d.stored(&b1, false);
    let b1_marks = d.marks.len() - 1;
    d.stored(&b2, true);
    let (mut packed, mut plain, marks) = d.finish();
    let b1_header = marks[b1_marks].1;
    let b1_data = b1_header + 5;
    // the fake: at payload offset 1000 (the byte before it zero), final, running to the data's end
    let fake = b1_data + 1_000;
    let end = packed.len();
    let len = (end - (fake + 4)) as u16;
    packed[fake - 1] = 0x00;
    packed[fake..fake + 2].copy_from_slice(&len.to_le_bytes());
    packed[fake + 2..fake + 4].copy_from_slice(&(!len).to_le_bytes());
    // the fake bytes overwrote payload bytes: the member's plain output follows
    let off = marks[b1_marks].0 as usize;
    plain[off + (fake - 1 - b1_data)] = 0x00;
    plain[off + (fake - b1_data)..off + (fake - b1_data) + 2].copy_from_slice(&len.to_le_bytes());
    plain[off + (fake - b1_data) + 2..off + (fake - b1_data) + 4].copy_from_slice(&(!len).to_le_bytes());
    let zip = raw_zip(8, &packed, &plain);
    let hole = (b1_header - 400)..(b1_header + 20);
    let r = run_hole(&zip, hole, &plain, 4_000);
    let restart = r.open.lost[0].end;
    // taken five output bytes off, then refuted: the bytes it wrote are lost again and written right
    assert_ne!(restart, marks[b1_marks].0, "the false restart was taken");
    assert!(r.open.unproven);
    assert_eq!(r.status.crc_ok, Some(true));
    assert!(!r.status.unproven);
    assert!(r.sink.twice > 0, "the refuted output was written again");
    assert_eq!(r.stats.written, plain.len() as u64 + r.sink.twice);
}

#[test]
fn no_stored_block_after_the_hole_waits_as_before() {
    let mut d = Deflater::default();
    d.fixed(&ops(d.plain.len(), 60_000, 51, 3_000), true);
    let (packed, plain, _) = d.finish();
    let zip = raw_zip(8, &packed, &plain);
    let r = run_hole(&zip, 5_000..6_000, &plain, 3_000);
    assert!(r.open.stalled && r.open.lost.is_empty() && !r.open.unproven);
    assert!(r.open.needs.iter().all(|n| n.kind != NeedKind::Repair));
    assert_eq!(r.sink.twice, 0);
}

#[test]
fn winzip_aes_restarts_and_checks_its_code() {
    // incompressible content: the writer stores its blocks
    let mut next = rng(77);
    let plain: Vec<u8> = (0..300_000).map(|_| next() as u8).collect();
    for ae2 in [false, true] {
        let mut w = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
        let options = EntryOptions {
            name: EntryName::Utf8("r.bin"),
            method: Method::Deflate(DeflateLevel::new(6).unwrap()),
            modified: DosDateTime::default(),
            extended_mtime: None,
            permissions: Permissions::new(0o644).unwrap(),
            comment: b"",
        };
        let variant = if ae2 { AesVariant::Ae2 } else { AesVariant::Ae1 };
        let request = WinZipAesRequest::new("pw", AesStrength::Aes256, variant).unwrap();
        w.add_winzip_aes_file(
            options,
            &mut Cursor::new(&plain),
            InputLength::Exact(plain.len() as u64),
            request,
            |s| {
                s.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8 + 3);
                Ok(())
            },
        )
        .unwrap();
        let zip = w.finish().unwrap().sink;
        let map = MemberMap::from_memory(&[zip.as_slice()], "a.zip", Some("pw")).unwrap();
        let member = &map.members[0];
        let packed = member.pieces[0].packed.clone();
        let mut d =
            FeedDecoder::new(&map, 0, FeedOptions { max_needs: usize::MAX, ..FeedOptions::new(Some("pw")) }).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        let mut sink = Sink::default();
        let (h0, h1) = (packed.start + 100_000, packed.start + 103_000);
        source.insert(0, 0, &zip[..h0 as usize]).unwrap();
        d.run(&mut source, &mut sink).unwrap();
        source.mark_lost(0, h0..h1);
        source.insert(0, h1, &zip[h1 as usize..]).unwrap();
        let open = d.run(&mut source, &mut sink).unwrap();
        assert!(!open.lost.is_empty() && open.unproven && !open.stalled, "ae2={ae2}: {open:?}");
        source.insert(0, h0, &zip[h0 as usize..h1 as usize]).unwrap();
        let status = d.run(&mut source, &mut sink).unwrap();
        assert!(status.done && status.lost.is_empty(), "{status:?}");
        assert!(sink.out == plain);
        assert_eq!(status.auth_ok, Some(true), "ae2={ae2}");
        assert_eq!(status.crc_ok, if ae2 { None } else { Some(true) });
        assert!(!status.unproven, "ae2={ae2}");
        assert_eq!(sink.twice, 0);
    }
}

#[test]
fn a_snapshot_taken_with_a_restart_open_restores_and_finishes() {
    let (packed, plain, _) = stream(40_000);
    let zip = raw_zip(8, &packed, &plain);
    let map = MemberMap::from_memory(&[zip.as_slice()], "r.zip", None).unwrap();
    let mut d = FeedDecoder::new(&map, 0, options()).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Sink::default();
    let (h0, h1) = (DATA + 5_000, DATA + 7_500);
    source.insert(0, 0, &zip[..h0]).unwrap();
    source.mark_lost(0, h0 as u64..h1 as u64);
    source.insert(0, h1 as u64, &zip[h1..]).unwrap();
    let open = d.run(&mut source, &mut sink).unwrap();
    assert!(!open.lost.is_empty());
    let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
    let mut d = FeedDecoder::restore(&map, 0, options(), &snap).unwrap();
    source.insert(0, h0 as u64, &zip[h0..h1]).unwrap();
    let status = d.run(&mut source, &mut sink).unwrap();
    assert!(status.done && status.lost.is_empty(), "{status:?}");
    assert_eq!(status.crc_ok, Some(true));
    assert!(sink.out == plain);
}
