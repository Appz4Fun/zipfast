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

//! The feed decoder over 7z LZMA2 folders (plain and 7zAES over LZMA2): articles fed shuffled, some missing and
//! supplied later.

use std::ops::Range;
use zipfast::map::*;

// ---- A minimal 7z writer: one folder of LZMA2 (or 7zAES over LZMA2) holding several files ----

/// A coder as stored: its id and properties.
type Coder = (&'static [u8], Vec<u8>);

const LZMA2: &[u8] = &[0x21];
const AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
const PASSWORD: &str = "pw";
const SALT: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
const IV: [u8; 16] = [0x5A; 16];

fn num(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    for k in 0..i {
        out.push((value >> (8 * k)) as u8);
    }
}

fn aes_key() -> [u8; 32] {
    zipfast::crypto::derive_7z_key(PASSWORD, &SALT, 6).unwrap()
}

fn aes_properties() -> Vec<u8> {
    let mut p = vec![6 | 0x80 | 0x40, ((SALT.len() as u8 - 1) << 4) | 15];
    p.extend_from_slice(&SALT);
    p.extend_from_slice(&IV);
    p
}

/// A raw LZMA2 stream of `plain` (1 MiB dictionary, 7z property 16), encoded in independent blocks of `block`
/// bytes as 7-Zip's multithreaded encoder writes them: each block starts with a dictionary reset.
fn lzma2(plain: &[u8], block: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in plain.chunks(block) {
        let mut opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
        opts.dict_size(1 << 20);
        let mut filters = liblzma::stream::Filters::new();
        filters.lzma2(&opts);
        let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
        let mut enc = Vec::with_capacity(piece.len() + 4096);
        let mut input = piece;
        loop {
            enc.reserve(1 << 16);
            let before = stream.total_in();
            let status = stream.process_vec(input, &mut enc, liblzma::stream::Action::Finish).unwrap();
            input = &input[(stream.total_in() - before) as usize..];
            if status == liblzma::stream::Status::StreamEnd {
                break;
            }
        }
        assert_eq!(enc.pop(), Some(0x00), "end marker");
        out.extend(enc);
    }
    out.push(0x00);
    out
}

/// A 7z archive of one folder holding `files`; `encrypted` puts 7zAES under the LZMA2 coder.
fn seven_zip(files: &[(&str, Vec<u8>)], encrypted: bool, block: usize) -> Vec<u8> {
    let plain: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    let lz = lzma2(&plain, block);
    let n = plain.len() as u64;
    let (packed, coders, sizes): (Vec<u8>, Vec<Coder>, Vec<u64>) = if encrypted {
        let mut padded = lz.clone();
        padded.resize(lz.len().next_multiple_of(16), 0);
        let cipher = zipfast::crypto::encrypt_cbc(&aes_key(), &IV, &padded).unwrap();
        (cipher, vec![(LZMA2, vec![16]), (AES, aes_properties())], vec![n, lz.len() as u64])
    } else {
        (lz, vec![(LZMA2, vec![16])], vec![n])
    };
    let mut h = vec![0x01, 0x04, 0x06];
    num(&mut h, 0);
    num(&mut h, 1);
    h.push(0x09);
    num(&mut h, packed.len() as u64);
    h.extend_from_slice(&[0x00, 0x07, 0x0B]);
    num(&mut h, 1);
    h.push(0x00);
    num(&mut h, coders.len() as u64);
    for (id, props) in &coders {
        h.push(id.len() as u8 | 0x20);
        h.extend_from_slice(id);
        num(&mut h, props.len() as u64);
        h.extend_from_slice(props);
    }
    for i in 0..coders.len() - 1 {
        num(&mut h, i as u64);
        num(&mut h, i as u64 + 1);
    }
    h.push(0x0C);
    for s in &sizes {
        num(&mut h, *s);
    }
    h.extend_from_slice(&[0x00, 0x08, 0x0D]);
    num(&mut h, files.len() as u64);
    h.push(0x09);
    for (_, b) in &files[..files.len() - 1] {
        num(&mut h, b.len() as u64);
    }
    h.extend_from_slice(&[0x0A, 0x01]);
    for (_, b) in files {
        h.extend_from_slice(&crc32fast::hash(b).to_le_bytes());
    }
    h.extend_from_slice(&[0x00, 0x00, 0x05]);
    num(&mut h, files.len() as u64);
    let mut names = vec![0u8];
    for (name, _) in files {
        for u in name.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    h.push(0x11);
    num(&mut h, names.len() as u64);
    h.extend_from_slice(&names);
    h.extend_from_slice(&[0x00, 0x00]);
    let mut sig = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4, 0, 0, 0, 0];
    sig.extend_from_slice(&(packed.len() as u64).to_le_bytes());
    sig.extend_from_slice(&(h.len() as u64).to_le_bytes());
    sig.extend_from_slice(&crc32fast::hash(&h).to_le_bytes());
    let start = crc32fast::hash(&sig[12..32]);
    sig[8..12].copy_from_slice(&start.to_le_bytes());
    sig.extend(packed);
    sig.extend(h);
    sig
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn text(len: usize, seed: usize) -> Vec<u8> {
    let words: [&[u8]; 8] =
        [b"lorem ", b"ipsum ", b"dolor ", b"sit ", b"amet, ", b"consectetur ", b"adipiscing ", b"elit. "];
    let mut out = Vec::with_capacity(len + 16);
    let mut i = seed;
    while out.len() < len {
        out.extend_from_slice(words[(i * 7 + i / 13) % 8]);
        i += 1;
    }
    out.truncate(len);
    out
}

/// Text and incompressible runs: LZMA chunks, stored chunks, and state resets after the stored ones.
fn mixed(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut k = 0;
    while out.len() < len {
        let n = [90_000usize, 200_000, 150_000, 130_000][k % 4];
        if k % 2 == 0 {
            out.extend(text(n, seed as usize + k));
        } else {
            out.extend(noise(n, seed + k as u64));
        }
        k += 1;
    }
    out.truncate(len);
    out
}

fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut x = seed | 1;
    for i in (1..v.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.swap(i, (x % (i as u64 + 1)) as usize);
    }
}

/// The output, which bytes were written, and optionally a donor (the payload as another copy holds it, read back
/// where nothing was written).
struct Out {
    bytes: Vec<u8>,
    seen: Vec<bool>,
    written: u64,
    donor: Option<Vec<u8>>,
    /// the folder's output before the member (what a `SolidStreamSink` gives back through `read_earlier`)
    earlier: Vec<u8>,
}

impl Out {
    fn new(size: usize, donor: Option<Vec<u8>>) -> Self {
        Self { bytes: vec![0; size], seen: vec![false; size], written: 0, donor, earlier: Vec::new() }
    }
}

impl FeedSink for Out {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        let (s, e) = (offset as usize, offset as usize + bytes.len());
        assert!(self.seen[s..e].iter().all(|w| !w), "output {s}..{e} written twice");
        self.seen[s..e].iter_mut().for_each(|w| *w = true);
        self.written += bytes.len() as u64;
        self.bytes[s..e].copy_from_slice(bytes);
        Ok(())
    }

    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let at = offset as usize;
        let Some(&written) = self.seen.get(at) else { return Ok(0) };
        let end = (at + buf.len()).min(self.seen.len());
        let run = self.seen[at..end].iter().take_while(|&&w| w == written).count();
        match (written, &self.donor) {
            (true, _) => buf[..run].copy_from_slice(&self.bytes[at..at + run]),
            (false, Some(d)) => buf[..run].copy_from_slice(&d[at..at + run]),
            (false, None) => return Ok(0),
        }
        Ok(run)
    }

    fn read_earlier(&mut self, at: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let at = at as usize;
        if at >= self.earlier.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.earlier.len() - at);
        buf[..n].copy_from_slice(&self.earlier[at..at + n]);
        Ok(n)
    }
}

type Article = (u32, u64, Vec<u8>);

fn articles(volumes: &[Vec<u8>], size: usize) -> Vec<Article> {
    let mut out = Vec::new();
    for (v, bytes) in volumes.iter().enumerate() {
        for (i, chunk) in bytes.chunks(size).enumerate() {
            out.push((v as u32, (i * size) as u64, chunk.to_vec()));
        }
    }
    out
}

fn inside(needs: &[NeedBytes], missing: &[Article]) -> bool {
    needs.iter().all(|n| {
        let mut at = n.range.start;
        while at < n.range.end {
            match missing.iter().find(|(v, off, b)| *v == n.volume && *off <= at && at < off + b.len() as u64) {
                Some((_, off, b)) => at = off + b.len() as u64,
                None => return false,
            }
        }
        true
    })
}

struct Report {
    /// decoded again from the first repair on (the main decode's own start is not counted)
    repair_redecoded: u64,
    stalled: bool,
    holes: u64,
    lost: u64,
    redecoded: u64,
}

/// Feeds member `member` of the set from shuffled articles of `article` bytes, every `every`th missing at first,
/// then the missing ones; checks the output and returns what happened.
fn feed(volumes: &[Vec<u8>], member: usize, plain: &[u8], article: usize, every: usize, donor: bool) -> Report {
    feed_with(volumes, member, plain, &[], article, every, donor)
}

thread_local! {
    /// [`FeedOptions::threads`] for [`feed_with`] in this test's thread
    static THREADS: std::cell::Cell<FeedThreads> = const { std::cell::Cell::new(FeedThreads::One) };
}

/// [`feed`] with the folder's output before the member given back by the sink (`earlier`).
fn feed_with(
    volumes: &[Vec<u8>],
    member: usize,
    plain: &[u8],
    earlier: &[u8],
    article: usize,
    every: usize,
    donor: bool,
) -> Report {
    let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, "set.7z.001", Some(PASSWORD)).unwrap();
    let threads = THREADS.with(std::cell::Cell::get);
    let options = FeedOptions { max_needs: usize::MAX, read_chunk: 4096, threads, ..FeedOptions::new(Some(PASSWORD)) };
    let mut d = FeedDecoder::new(&map, member, options).unwrap();
    let mut out = Out::new(plain.len(), donor.then(|| plain.to_vec()));
    out.earlier = earlier.to_vec();
    let mut all = articles(volumes, article);
    // fixed; FEED7Z_SEED varies it (to run many shuffles in a loop)
    let extra: u64 = std::env::var("FEED7Z_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    shuffle(&mut all, (0xFEED ^ article as u64 ^ every as u64).wrapping_add(extra.wrapping_mul(0x9E37_79B9)));
    let (missing, present): (Vec<_>, Vec<_>) = all.into_iter().enumerate().partition(|(i, _)| i % every == every / 2);
    let missing: Vec<Article> = missing.into_iter().map(|(_, a)| a).collect();
    let mut source = ArticleBuffer::new(usize::MAX);
    for (v, off, b) in &missing {
        source.mark_lost(*v, *off..*off + b.len() as u64);
    }
    for (_, (v, off, b)) in &present {
        source.insert(*v, *off, b).unwrap();
        d.run(&mut source, &mut out).unwrap();
    }
    let s = d.status().clone();
    // what is needed lies in the missing articles; past every hole it can, the decoder needs only repairs
    assert!(inside(&s.needs, &missing), "{:?}", s.needs);
    if !s.stalled {
        assert!(s.needs.iter().all(|n| n.kind == NeedKind::Repair), "{:?}", s.needs);
    } else {
        assert_eq!(s.needs[0].kind, NeedKind::Next);
    }
    let before_repairs = d.stats().redecoded;
    let report = Report {
        repair_redecoded: 0,
        stalled: s.stalled,
        holes: d.stats().holes,
        lost: s.lost.iter().map(|r| r.end - r.start).sum(),
        redecoded: 0,
    };
    // the missing articles, through a snapshot round trip half way
    let half = missing.len() / 2;
    for (k, (v, off, b)) in missing.iter().enumerate() {
        if k == half {
            let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
            let options =
                FeedOptions { max_needs: usize::MAX, read_chunk: 4096, threads, ..FeedOptions::new(Some(PASSWORD)) };
            d = FeedDecoder::restore(&map, member, options, &snap).unwrap();
        }
        source.insert(*v, *off, b).unwrap();
        d.run(&mut source, &mut out).unwrap();
    }
    let s = d.status();
    assert!(s.done, "{s:?}");
    assert_eq!(s.crc_ok, Some(true));
    assert!(out.bytes == plain, "output differs");
    assert_eq!(out.written, plain.len() as u64, "each output byte written once");
    // holes skipped over the decoder's whole life (a restored decoder skips again those it meets again)
    Report {
        redecoded: d.stats().redecoded,
        repair_redecoded: d.stats().redecoded - before_repairs,
        holes: d.stats().holes,
        ..report
    }
}

#[test]
fn lzma2_folders_feed_shuffled_with_holes_skipped_and_repaired() {
    let plain = mixed(1_500_000, 3);
    for encrypted in [false, true] {
        let archive = seven_zip(&[("m.bin", plain.clone())], encrypted, 400_000);
        let volumes: Vec<Vec<u8>> = archive.chunks(600_000).map(<[u8]>::to_vec).collect();
        for donor in [false, true] {
            for (article, every) in [(1_500, 11), (3_000, 7), (20_000, 9)] {
                let r = feed(&volumes, 0, &plain, article, every, donor);
                eprintln!(
                    "aes {encrypted} donor {donor} article {article}: stalled {}, {} holes skipped, {} lost, {} decoded \
                     again",
                    r.stalled, r.holes, r.lost, r.redecoded
                );
                // a repair decodes again at most from the restart point before its hole (a block of 400 KB), and the
                // restore half way decodes again from the main decode's restart point
                assert!(r.redecoded <= (r.holes + 1) * 400_000, "{}", r.redecoded);
            }
        }
    }
}

/// `FeedOptions::threads`: workers decode the independent blocks (dictionary resets) ahead of the main decode. In
/// order, shuffled, with holes repaired and a snapshot round trip half way, plain and under 7zAES, the output is
/// the same, every byte written once, and the CRC matches.
#[test]
fn workers_decode_independent_blocks_with_the_same_output() {
    THREADS.with(|t| t.set(FeedThreads::Count(3)));
    let plain = mixed(2_000_000, 5);
    for encrypted in [false, true] {
        let archive = seven_zip(&[("m.bin", plain.clone())], encrypted, 250_000);
        let volumes: Vec<Vec<u8>> = archive.chunks(600_000).map(<[u8]>::to_vec).collect();
        // all present (every = never missing), then with holes
        for (article, every) in [(4_096, usize::MAX), (1_500, 11), (20_000, 9)] {
            let r = feed(&volumes, 0, &plain, article, every, false);
            eprintln!("aes {encrypted} article {article} every {every}: {} holes, {} lost", r.holes, r.lost);
        }
    }
    THREADS.with(|t| t.set(FeedThreads::One));
}

#[test]
fn small_holes_inside_payloads_are_skipped_without_held_output() {
    // articles small enough that most holes lie inside a chunk's payload: the main decode restarts at the next
    // stored chunk or dictionary reset, and goes on
    let plain = mixed(1_500_000, 5);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, 400_000);
    let volumes = vec![archive];
    let r = feed(&volumes, 0, &plain, 1_000, 41, false);
    // with the fixed shuffle some hole lies inside a payload (another shuffle may put every one over a header)
    if std::env::var_os("FEED7Z_SEED").is_none() {
        assert!(r.holes > 0, "no hole skipped");
    }
}

#[test]
fn members_after_the_first_of_a_folder_start_at_its_last_reset() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.txt", text(300_000, 1)), ("b.bin", mixed(700_000, 2)), ("c.txt", text(500_000, 4))];
    for encrypted in [false, true] {
        let archive = seven_zip(&files, encrypted, 350_000);
        let volumes: Vec<Vec<u8>> = archive.chunks(400_000).map(<[u8]>::to_vec).collect();
        for (i, (_, plain)) in files.iter().enumerate() {
            let r = feed(&volumes, i, plain, 2_500, 9, false);
            eprintln!("member {i} aes {encrypted}: {} holes, {} decoded again", r.holes, r.redecoded);
        }
    }
}

#[test]
fn needs_name_headers_first_and_a_snapshot_restores_mid_member() {
    let plain = mixed(900_000, 9);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, 300_000);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let r = member_restart(&map, 0).unwrap();
    assert_eq!(r.layer, Layer::SevenZipLzma2);
    let mut d = FeedDecoder::new(&map, 0, FeedOptions { max_needs: usize::MAX, ..FeedOptions::default() }).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut out = Out::new(plain.len(), None);
    let s = d.run(&mut source, &mut out).unwrap();
    // nothing held: the first header is the next need, the rest of the folder ahead
    assert_eq!(s.needs[0].kind, NeedKind::Next);
    assert_eq!(s.needs[0].range.start, 32);
    assert!(s.needs.iter().skip(1).all(|n| n.kind == NeedKind::Ahead));
    // the first half, then a snapshot, then a restore that decodes again from the last restart point
    let half = archive.len() / 2;
    source.insert(0, 0, &archive[..half]).unwrap();
    d.run(&mut source, &mut out).unwrap();
    let frontier = d.status().frontier;
    assert!(frontier > 0);
    let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
    let mut d = FeedDecoder::restore(&map, 0, FeedOptions::default(), &snap).unwrap();
    assert_eq!(d.status().frontier, frontier);
    source.insert(0, half as u64, &archive[half..]).unwrap();
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert!(out.bytes == plain);
    // decoded again: at most from the block's reset to the frontier
    assert!(d.stats().redecoded <= 300_000, "{}", d.stats().redecoded);
}

#[test]
fn a_wrong_7zaes_password_is_typed() {
    let plain = text(50_000, 1);
    let archive = seven_zip(&[("m.txt", plain)], true, 1 << 20);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", Some(PASSWORD)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive).unwrap();
    let mut wrong = 0;
    for pw in ["nope", "wrong", "x", "hunter2"] {
        let mut d = FeedDecoder::new(&map, 0, FeedOptions::new(Some(pw))).unwrap();
        let mut out = Out::new(50_000, None);
        match d.run(&mut source, &mut out) {
            Err(FeedError::WrongPassword) => wrong += 1,
            Err(FeedError::Decode { .. }) => {}
            Ok(s) => assert_ne!(s.crc_ok, Some(true)),
            Err(e) => panic!("{e}"),
        }
    }
    assert!(wrong > 0);
    assert!(matches!(FeedDecoder::new(&map, 0, FeedOptions::new(None)), Err(FeedError::PasswordRequired)));
}

/// Needs never name packed bytes outside the hole a decoder waits at, and a header lost in a hole stalls the main
/// decode until it comes.
#[test]
fn a_header_in_a_hole_stalls_until_it_comes() {
    let plain = mixed(600_000, 11);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, 1 << 20);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let index = map.lzma2_chunks(0, &refs, Default::default()).unwrap();
    // a hole over a chunk header in the middle
    let c = index.chunks[index.chunks.len() / 2];
    let hole: Range<u64> = 32 + c.packed_offset - 10..32 + c.packed_offset + 10;
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive[..hole.start as usize]).unwrap();
    source.insert(0, hole.end, &archive[hole.end as usize..]).unwrap();
    source.mark_lost(0, hole.clone());
    let mut d = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
    let mut out = Out::new(plain.len(), None);
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.stalled, "{s:?}");
    assert_eq!(s.needs[0], NeedBytes { volume: 0, range: hole.clone(), kind: NeedKind::Next });
    source.insert(0, hole.start, &archive[hole.start as usize..hole.end as usize]).unwrap();
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true));
    assert_eq!(d.stats().redecoded, 0);
    assert!(out.bytes == plain);
}

/// An article-sized hole (far larger than a chunk) in a single-reset folder: everything after it arrives and nothing
/// is decoded or written past the hole (no header there can be trusted), and the repair resumes the stopped decoder
/// once: nothing is decoded twice, each output byte is written once, and the work after the repair is the tail only.
#[test]
fn an_article_sized_hole_waits_and_resumes_without_decoding_twice() {
    let plain = mixed(3_000_000, 21);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, usize::MAX >> 1);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let article = 750_000usize;
    // the second article of the archive: an interior boundary, with a nonempty prefix before it (the archive is
    // about 1.7 MB, so a boundary computed from a third of its length would be 0)
    assert!(archive.len() > 2 * article, "the archive has an interior article");
    let hole = article as u64..(2 * article).min(archive.len()) as u64;
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive[..hole.start as usize]).unwrap();
    source.insert(0, hole.end, &archive[hole.end as usize..]).unwrap();
    source.mark_lost(0, hole.clone());
    let mut d = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
    let mut out = Out::new(plain.len(), None);
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.stalled || !s.needs.is_empty(), "{s:?}");
    let before = out.written;
    assert!(before > 0, "the prefix before the hole was decoded and written: {s:?}");
    assert!(before < plain.len() as u64);
    source.insert(0, hole.start, &archive[hole.start as usize..hole.end as usize]).unwrap();
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert_eq!(d.stats().redecoded, 0);
    assert_eq!(out.written, plain.len() as u64, "each output byte written once");
    assert!(out.bytes == plain);
}

/// A sink that keeps nothing it is given (the default `read_held`).
struct WriteOnly {
    out: Out,
}

impl FeedSink for WriteOnly {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.out.write_at(offset, bytes)
    }
}

/// A hole in a stored chunk followed by a chunk that resets only the LZMA state, decoded into a sink that gives
/// nothing back: the repair must not pick a restart that needs the dictionary from the sink (written output is not
/// held there), and finishes with the decoder it kept.
#[test]
fn a_write_only_sink_repairs_a_stored_hole_before_a_state_reset() {
    let plain = mixed(900_000, 21);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, 1 << 20);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let index = map.lzma2_chunks(0, &refs, Default::default()).unwrap();
    let k = (0..index.chunks.len() - 1)
        .find(|&k| {
            index.chunks[k].kind == Lzma2ChunkKind::Stored
                && index.chunks[k + 1].kind == Lzma2ChunkKind::Lzma
                && matches!(index.chunks[k + 1].reset, Lzma2Reset::State | Lzma2Reset::StateProps)
        })
        .expect("a stored chunk before a state reset");
    let p = index.chunks[k].payload();
    let at = 32 + (p.start + p.end) / 2;
    let hole = at..at + 100;
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive[..hole.start as usize]).unwrap();
    source.insert(0, hole.end, &archive[hole.end as usize..]).unwrap();
    source.mark_lost(0, hole.clone());
    let mut d = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
    let mut sink = WriteOnly { out: Out::new(plain.len(), None) };
    let s = d.run(&mut source, &mut sink).unwrap();
    assert!(!s.lost.is_empty(), "{s:?}");
    source.insert(0, hole.start, &archive[hole.start as usize..hole.end as usize]).unwrap();
    let s = d.run(&mut source, &mut sink).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert!(sink.out.bytes == plain);
    assert_eq!(sink.out.written, plain.len() as u64);
}

/// Cancellation stops the header walk before a later member of a folder, even while bytes are missing.
#[test]
fn cancellation_interrupts_the_walk_to_a_later_member() {
    let files: Vec<(&str, Vec<u8>)> = vec![("a.txt", text(300_000, 1)), ("b.txt", text(200_000, 2))];
    let archive = seven_zip(&files, false, 1 << 20);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let options = FeedOptions::default();
    let control = options.control.clone();
    let mut d = FeedDecoder::new(&map, 1, options).unwrap();
    control.cancel();
    let mut out = Out::new(200_000, None);
    let mut source = ArticleBuffer::new(usize::MAX);
    assert!(matches!(d.run(&mut source, &mut out), Err(FeedError::Canceled)));
}

// ---- Several members of one folder in sequence: each hands its LZMA2 state to the next ----

/// The members' outputs of one folder, as one sink per member: each member's own output, and the earlier members'
/// at folder offsets (`FeedSink::read_earlier`).
struct FolderView<'a> {
    outs: &'a mut [Out],
    i: usize,
    starts: &'a [u64],
}

impl FeedSink for FolderView<'_> {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.outs[self.i].write_at(offset, bytes)
    }

    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.outs[self.i].read_held(offset, buf)
    }

    fn read_earlier(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let j = self.starts.partition_point(|&s| s <= offset) - 1;
        assert!(j < self.i);
        let room = (self.starts[j + 1] - offset) as usize;
        let n = buf.len().min(room);
        self.outs[j].read_held(offset - self.starts[j], &mut buf[..n])
    }
}

/// The LZMA2 chunks of a raw stream: (packed range of the payload, output range), from the stream's start.
fn chunks(lz: &[u8]) -> Vec<(Range<u64>, Range<u64>)> {
    let (mut p, mut o) = (0usize, 0u64);
    let mut out = Vec::new();
    while lz[p] != 0 {
        let c = lz[p];
        let (hdr, unpacked, packed) = if c < 0x80 {
            let u = (usize::from(lz[p + 1]) << 8 | usize::from(lz[p + 2])) + 1;
            (3, u, u)
        } else {
            let u = ((usize::from(c & 0x1F) << 16) | usize::from(lz[p + 1]) << 8 | usize::from(lz[p + 2])) + 1;
            let k = (usize::from(lz[p + 3]) << 8 | usize::from(lz[p + 4])) + 1;
            (if (c >> 5) & 3 >= 2 { 6 } else { 5 }, u, k)
        };
        out.push(((p + hdr) as u64..(p + hdr + packed) as u64, o..o + unpacked as u64));
        p += hdr + packed;
        o += unpacked as u64;
    }
    out
}

struct FolderRun {
    map: MemberMap,
    starts: Vec<u64>,
    outs: Vec<Out>,
    decoders: Vec<Option<FeedDecoder>>,
    /// a successor had output lost from its very start: a hole in the member before reached it
    saw_overflow: bool,
}

impl FolderRun {
    fn options() -> FeedOptions {
        FeedOptions { max_needs: usize::MAX, read_chunk: 4096, ..FeedOptions::new(Some(PASSWORD)) }
    }

    fn step(&mut self, source: &mut ArticleBuffer) {
        let n = self.decoders.len();
        for k in 0..n {
            let waiting_next = k + 1 < n && self.decoders[k + 1].is_none();
            let Some(d) = self.decoders[k].as_mut() else { continue };
            let mut view = FolderView { outs: &mut self.outs, i: k, starts: &self.starts };
            let s = d.run(source, &mut view).unwrap_or_else(|e| panic!("member {k}: {e}"));
            if k > 0 && s.lost.first().is_some_and(|r| r.start == 0) {
                self.saw_overflow = true;
            }
            if waiting_next && s.frontier == d.size() {
                let next = d.next_solid(&self.map, k + 1, Self::options()).unwrap();
                self.decoders[k + 1] = Some(next);
            }
        }
    }
}

/// Members of one folder decoded in sequence, each going on from the LZMA2 decoder the member before left (a
/// folder that resets its dictionary only at its start, and one in 7-Zip-like blocks), from shuffled articles with
/// small holes inside payloads: one late in the first member, inside a chunk the second member continues, so the
/// output it loses runs on into the second member, which repairs that part from the first member's restart point.
/// With and without held output, with a snapshot round trip of the second member: exact, CRCs verified, each byte
/// written once, and nothing before a member decoded again except for repairs.
#[test]
fn members_of_a_folder_hand_over_in_sequence() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.bin", mixed(300_000, 21)), ("b.bin", mixed(700_000, 22)), ("c.txt", text(500_000, 4))];
    let sizes: Vec<u64> = files.iter().map(|(_, b)| b.len() as u64).collect();
    let starts = vec![0, sizes[0], sizes[0] + sizes[1], sizes.iter().sum()];
    let plain: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    for block in [usize::MAX, 350_000] {
        let lz = lzma2(&plain, block.min(plain.len()));
        let walked = chunks(&lz);
        // the chunk holding output 5,000 bytes before the first member's end, and one in the middle of the
        // folder, each with 8 payload bytes lost (folder packed offsets: the archive's packed bytes start at 32)
        let mut holes: Vec<u64> = Vec::new();
        for target in [sizes[0] - 5_000, starts[2] + 100_000] {
            let (p, _) = walked.iter().find(|(_, o)| o.contains(&target)).unwrap();
            holes.push(32 + (p.start + p.end) / 2);
        }
        for encrypted in [false, true] {
            for (donor, with_holes) in [(false, false), (false, true), (true, true)] {
                let holes: &[u64] = if with_holes { &holes } else { &[] };
                let archive = seven_zip(&files, encrypted, block.min(plain.len()));
                let volumes: Vec<Vec<u8>> = archive.chunks(400_000).map(<[u8]>::to_vec).collect();
                let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
                let map = MemberMap::from_memory(&refs, "set.7z.001", Some(PASSWORD)).unwrap();
                let first = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
                let mut run = FolderRun {
                    map,
                    starts: starts.clone(),
                    outs: files.iter().map(|(_, b)| Out::new(b.len(), donor.then(|| b.clone()))).collect(),
                    decoders: vec![Some(first), None, None],
                    saw_overflow: false,
                };
                let mut all = articles(&volumes, 2_500);
                shuffle(&mut all, 0x7501 ^ block as u64);
                let mut source = ArticleBuffer::new(usize::MAX);
                let lost: Vec<(u32, Range<u64>)> =
                    holes.iter().map(|&h| ((h / 400_000) as u32, h % 400_000..h % 400_000 + 8)).collect();
                for (v, r) in &lost {
                    source.mark_lost(*v, r.clone());
                }
                for (v, off, b) in &all {
                    let end = off + b.len() as u64;
                    let mut at = *off;
                    for (_, r) in lost.iter().filter(|(lv, r)| lv == v && *off <= r.start && r.end <= end) {
                        source.insert(*v, at, &b[(at - off) as usize..(r.start - off) as usize]).unwrap();
                        at = r.end;
                    }
                    source.insert(*v, at, &b[(at - off) as usize..]).unwrap();
                    run.step(&mut source);
                }
                let started = run.decoders.iter().filter(|d| d.is_some()).count();
                let state: Vec<_> = run.decoders.iter().map(|d| d.as_ref().map(|d| d.status().clone())).collect();
                eprintln!(
                    "block {block} aes {encrypted} donor {donor}: {started} started, overflow {}, {state:?}",
                    run.saw_overflow
                );
                // a snapshot round trip of the second member, then the lost bytes
                if let Some(d) = run.decoders[1].as_ref().filter(|_| !holes.is_empty()) {
                    let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
                    run.decoders[1] = Some(FeedDecoder::restore(&run.map, 1, FolderRun::options(), &snap).unwrap());
                    for (v, off, b) in &all {
                        source.insert(*v, *off, b).unwrap();
                    }
                }
                for (v, r) in &lost {
                    let a = all.iter().find(|(av, off, b)| av == v && *off <= r.start && r.end <= off + b.len() as u64);
                    let (_, off, b) = a.unwrap();
                    source.insert(*v, r.start, &b[(r.start - off) as usize..(r.end - off) as usize]).unwrap();
                    run.step(&mut source);
                }
                for _ in 0..3 {
                    run.step(&mut source);
                }
                let mut redecoded = 0;
                for (k, d) in run.decoders.iter().enumerate() {
                    let d = d.as_ref().unwrap_or_else(|| panic!("member {k} never started"));
                    let s = d.status();
                    assert!(s.done && s.crc_ok == Some(true), "member {k}: {s:?}");
                    assert!(run.outs[k].bytes == files[k].1, "member {k} output");
                    assert_eq!(run.outs[k].written, sizes[k], "member {k}: each byte written once");
                    redecoded += d.stats().redecoded;
                }
                eprintln!("  decoded again {redecoded}");
                if holes.is_empty() {
                    // nothing before a member is decoded again (FeedDecoder::new for member 2 of the single-reset
                    // folder decodes the 1 MB before it)
                    assert_eq!(redecoded, 0);
                } else {
                    // repairs decode from the restart point before their hole, which in a folder that resets only
                    // at its start can lie in an earlier member
                    assert!(redecoded <= 2 * plain.len() as u64, "{redecoded}");
                }
            }
        }
    }
}

/// A member whose main decode has finished, snapshotted and restored before it hands over, still hands over: the
/// restart and the lost output past its end it was to hand on are in its snapshot. With a hole late in member 0
/// (its loss runs on into member 1) and without one, both folder layouts.
#[test]
fn a_finished_member_restored_before_its_hand_off_still_hands_over() {
    let files: Vec<(&str, Vec<u8>)> = vec![("a.bin", mixed(300_000, 31)), ("b.bin", mixed(400_000, 32))];
    let sizes: Vec<u64> = files.iter().map(|(_, b)| b.len() as u64).collect();
    let plain: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    for block in [usize::MAX, 350_000] {
        let lz = lzma2(&plain, block.min(plain.len()));
        let walked = chunks(&lz);
        let (p, _) = walked.iter().find(|(_, o)| o.contains(&(sizes[0] - 5_000))).unwrap();
        let hole = 32 + (p.start + p.end) / 2;
        for with_hole in [false, true] {
            let archive = seven_zip(&files, false, block.min(plain.len()));
            let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
            let mut source = ArticleBuffer::new(usize::MAX);
            if with_hole {
                source.insert(0, 0, &archive[..hole as usize]).unwrap();
                source.insert(0, hole + 8, &archive[hole as usize + 8..]).unwrap();
                source.mark_lost(0, hole..hole + 8);
            } else {
                source.insert(0, 0, &archive).unwrap();
            }
            let starts = vec![0, sizes[0], sizes[0] + sizes[1]];
            let mut outs: Vec<Out> = files.iter().map(|(_, b)| Out::new(b.len(), None)).collect();
            let mut d0 = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
            let s = d0.run(&mut source, &mut FolderView { outs: &mut outs, i: 0, starts: &starts }).unwrap();
            assert_eq!(s.frontier, sizes[0], "{s:?}");
            let snap = FeedSnapshot::from_bytes(&d0.snapshot().to_bytes()).unwrap();
            let mut d0 = FeedDecoder::restore(&map, 0, FolderRun::options(), &snap).unwrap();
            let mut d1 = d0.next_solid(&map, 1, FolderRun::options()).unwrap();
            source.insert(0, 0, &archive).unwrap();
            for _ in 0..2 {
                d0.run(&mut source, &mut FolderView { outs: &mut outs, i: 0, starts: &starts }).unwrap();
                d1.run(&mut source, &mut FolderView { outs: &mut outs, i: 1, starts: &starts }).unwrap();
            }
            for (k, d) in [d0, d1].iter().enumerate() {
                let s = d.status();
                assert!(s.done && s.crc_ok == Some(true), "block {block} hole {with_hole} member {k}: {s:?}");
                assert!(outs[k].bytes == files[k].1, "member {k} output");
                assert_eq!(outs[k].written, sizes[k], "member {k}: each byte written once");
            }
        }
    }
}

/// A zero-length member at the folder's end still follows the member before: the hand-off reaches it.
#[test]
fn a_trailing_empty_member_of_a_folder_is_handed_over_to() {
    let files: Vec<(&str, Vec<u8>)> = vec![("a.bin", mixed(200_000, 33)), ("e.txt", Vec::new())];
    let archive = seven_zip(&files, false, 350_000);
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    assert_eq!(map.members[1].unpacked_size, Some(0));
    if map.members[1].folder.is_none() {
        // a map that gives the empty member no place in the folder has nothing to hand over
        return;
    }
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive).unwrap();
    let mut d0 = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
    let mut out0 = Out::new(200_000, None);
    assert!(d0.run(&mut source, &mut out0).unwrap().done);
    let mut d1 = d0.next_solid(&map, 1, FolderRun::options()).unwrap();
    let s = d1.run(&mut source, &mut Out::new(0, None)).unwrap();
    assert!(s.done && s.crc_ok != Some(false), "{s:?}");
}

/// A zero-length member at the folder's start hands over to the member after it.
#[test]
fn a_leading_empty_member_of_a_folder_hands_over() {
    let files: Vec<(&str, Vec<u8>)> = vec![("e.txt", Vec::new()), ("a.bin", mixed(200_000, 34))];
    let archive = seven_zip(&files, false, 350_000);
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    assert_eq!(map.members[0].unpacked_size, Some(0));
    if map.members[0].folder.is_none() {
        // a map that gives the empty member no place in the folder has nothing to hand over
        return;
    }
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive).unwrap();
    let mut d0 = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
    assert!(d0.run(&mut source, &mut Out::new(0, None)).unwrap().done);
    let mut d1 = d0.next_solid(&map, 1, FolderRun::options()).unwrap();
    let mut out1 = Out::new(200_000, None);
    let s = d1.run(&mut source, &mut out1).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert!(out1.bytes == files[1].1);
    assert_eq!(d1.stats().redecoded, 0);
}

/// Under 7zAES, a zero-length member in the middle of a folder created on its own walks to its start through the
/// decrypted stream, and hands over to the member after it.
#[test]
fn an_empty_member_under_7zaes_seeks_and_hands_over() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.bin", mixed(150_000, 35)), ("e.txt", Vec::new()), ("b.bin", mixed(150_000, 36))];
    let archive = seven_zip(&files, true, 100_000);
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    if map.members[1].folder.is_none() {
        return;
    }
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive).unwrap();
    let mut d1 = FeedDecoder::new(&map, 1, FolderRun::options()).unwrap();
    let s = d1.run(&mut source, &mut Out::new(0, None)).unwrap();
    assert!(s.done, "{s:?}");
    let mut d2 = d1.next_solid(&map, 2, FolderRun::options()).unwrap();
    let mut out = Out::new(150_000, None);
    let s = d2.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert!(out.bytes == files[2].1);
}

/// A hand-off that fails on the next member's own setup (a window limit) keeps the state: the next attempt still
/// goes on from it, decoding nothing again.
#[test]
fn a_failed_lzma2_hand_off_keeps_the_state() {
    let files: Vec<(&str, Vec<u8>)> = vec![("a.bin", mixed(200_000, 37)), ("b.bin", mixed(200_000, 38))];
    let archive = seven_zip(&files, false, usize::MAX);
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive).unwrap();
    let mut d0 = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
    assert!(d0.run(&mut source, &mut Out::new(200_000, None)).unwrap().done);
    let small = FeedOptions { max_window: 1 << 10, ..FolderRun::options() };
    assert!(matches!(d0.next_solid(&map, 1, small), Err(FeedError::Unsupported(FeedUnsupported::Window { .. }))));
    let mut d1 = d0.next_solid(&map, 1, FolderRun::options()).unwrap();
    let mut out = Out::new(200_000, None);
    let s = d1.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert!(out.bytes == files[1].1);
    assert_eq!(d1.stats().redecoded, 0);
}

/// A hole whose loss runs past a whole short member to a restart in the member after it: the short member's main
/// decode is done as soon as it is handed over, and its snapshot (taken at once, before its own hand-off) restores
/// and hands over on.
#[test]
fn a_member_skipped_whole_by_a_hole_snapshots_and_hands_over() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.bin", mixed(300_000, 39)), ("b.txt", text(3_000, 7)), ("c.bin", mixed(300_000, 40))];
    let sizes: Vec<u64> = files.iter().map(|(_, b)| b.len() as u64).collect();
    let plain: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    let lz = lzma2(&plain, plain.len());
    let walked = chunks(&lz);
    // inside the chunk holding output 5,000 bytes before member 0's end, at about that output's place
    let target = sizes[0] - 5_000;
    let (p, o) = walked.iter().find(|(_, o)| o.contains(&target)).unwrap();
    let hole = 32 + p.start + (target - o.start) * (p.end - p.start) / (o.end - o.start);
    let archive = seven_zip(&files, false, plain.len());
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    let starts = vec![0, sizes[0], sizes[0] + sizes[1], sizes.iter().sum()];
    let mut outs: Vec<Out> = files.iter().map(|(_, b)| Out::new(b.len(), None)).collect();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive[..hole as usize]).unwrap();
    source.insert(0, hole + 8, &archive[hole as usize + 8..]).unwrap();
    source.mark_lost(0, hole..hole + 8);
    let mut d0 = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
    let s = d0.run(&mut source, &mut FolderView { outs: &mut outs, i: 0, starts: &starts }).unwrap();
    assert_eq!(s.frontier, sizes[0], "{s:?}");
    let d1 = d0.next_solid(&map, 1, FolderRun::options()).unwrap();
    // the loss covers member 1 whole (and runs on into member 2)
    assert_eq!(d1.status().lost, vec![0..sizes[1]], "{:?}", d1.status());
    let snap = FeedSnapshot::from_bytes(&d1.snapshot().to_bytes()).unwrap();
    let mut d1 = FeedDecoder::restore(&map, 1, FolderRun::options(), &snap).unwrap();
    let d2 = d1.next_solid(&map, 2, FolderRun::options()).unwrap();
    assert!(d2.status().lost.first().is_some_and(|r| r.start == 0), "{:?}", d2.status());
    source.insert(0, 0, &archive).unwrap();
    let mut ds = [d0, d1, d2];
    for _ in 0..2 {
        for (k, d) in ds.iter_mut().enumerate() {
            d.run(&mut source, &mut FolderView { outs: &mut outs, i: k, starts: &starts }).unwrap();
        }
    }
    for (k, d) in ds.iter().enumerate() {
        let s = d.status();
        assert!(s.done && s.crc_ok == Some(true), "member {k}: {s:?}");
        assert!(outs[k].bytes == files[k].1, "member {k} output");
        assert_eq!(outs[k].written, sizes[k], "member {k}: each byte written once");
    }
}

/// A member snapshotted after it was handed over and before its first run, in a block after the folder's first,
/// with the bytes the decoders passed released: restored, it goes on from the handed-over restart point, whose
/// packed bytes are still held, and needs nothing again.
#[test]
fn a_successor_snapshotted_before_its_first_run_restores_at_the_handed_over_point() {
    let files: Vec<(&str, Vec<u8>)> = vec![("a.bin", mixed(500_000, 41)), ("b.bin", mixed(300_000, 42))];
    let archive = seven_zip(&files, false, 350_000);
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    let starts = vec![0, 500_000, 800_000];
    let mut outs: Vec<Out> = files.iter().map(|(_, b)| Out::new(b.len(), None)).collect();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive).unwrap();
    let mut d0 = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
    let s = d0.run(&mut source, &mut FolderView { outs: &mut outs, i: 0, starts: &starts }).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    let held = source.held();
    assert!(held < archive.len(), "the bytes member 0 passed were released");
    let d1 = d0.next_solid(&map, 1, FolderRun::options()).unwrap();
    let snap = FeedSnapshot::from_bytes(&d1.snapshot().to_bytes()).unwrap();
    let mut d1 = FeedDecoder::restore(&map, 1, FolderRun::options(), &snap).unwrap();
    let s = d1.run(&mut source, &mut FolderView { outs: &mut outs, i: 1, starts: &starts }).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "restored at the handed-over point: {s:?}");
    assert!(outs[1].bytes == files[1].1);
    assert_eq!(outs[1].written, 300_000);
}

/// A member whose main decode restarted with a dictionary from held output hands its window on as unproven, even
/// once its hole is repaired and its own CRC matches: the member after it starts unproven.
#[test]
fn a_seeded_lzma2_dictionary_stays_unproven_past_the_members_own_crc() {
    let files: Vec<(&str, Vec<u8>)> = vec![("a.bin", mixed(700_000, 43)), ("b.bin", mixed(200_000, 44))];
    let sizes = [700_000u64, 200_000];
    let plain: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    let lz = lzma2(&plain, plain.len());
    let walked = chunks(&lz);
    // 8 bytes lost in the LZMA chunk holding output 180,000 (text, before a stored run and a state reset after it)
    let target = 180_000;
    let (p, o) = walked.iter().find(|(_, o)| o.contains(&target)).unwrap();
    let hole = 32 + p.start + (target - o.start) * (p.end - p.start) / (o.end - o.start);
    let archive = seven_zip(&files, false, plain.len());
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    let starts = vec![0, sizes[0], sizes[0] + sizes[1]];
    let mut outs: Vec<Out> = files.iter().map(|(_, b)| Out::new(b.len(), Some(b.clone()))).collect();
    let mut source = ArticleBuffer::new(usize::MAX);
    // all but the hole and member 0's last bytes
    let tail = archive.len() - 200_000;
    source.insert(0, 0, &archive[..hole as usize]).unwrap();
    source.insert(0, hole + 8, &archive[hole as usize + 8..tail]).unwrap();
    source.mark_lost(0, hole..hole + 8);
    let mut d0 = FeedDecoder::new(&map, 0, FolderRun::options()).unwrap();
    let s = d0.run(&mut source, &mut FolderView { outs: &mut outs, i: 0, starts: &starts }).unwrap();
    assert!(d0.stats().holes > 0 && !s.lost.is_empty(), "{s:?}");
    assert!(s.unproven, "a dictionary from held output: {s:?}");
    // the hole's bytes, then the rest: member 0 done, its CRC matched
    source.insert(0, hole, &archive[hole as usize..hole as usize + 8]).unwrap();
    d0.run(&mut source, &mut FolderView { outs: &mut outs, i: 0, starts: &starts }).unwrap();
    source.insert(0, 0, &archive).unwrap();
    let s = d0.run(&mut source, &mut FolderView { outs: &mut outs, i: 0, starts: &starts }).unwrap();
    assert!(s.done && s.crc_ok == Some(true) && !s.unproven, "{s:?}");
    let mut d1 = d0.next_solid(&map, 1, FolderRun::options()).unwrap();
    assert!(d1.status().unproven, "member 1 starts from a dictionary seeded from held output");
    let s = d1.run(&mut source, &mut FolderView { outs: &mut outs, i: 1, starts: &starts }).unwrap();
    assert!(s.done && s.crc_ok == Some(true) && !s.unproven, "{s:?}");
    assert!(outs[1].bytes == files[1].1);
}

/// A folder that resets its dictionary only at its start, with a state reset after every stored (noise) stretch: a
/// repair in a later member restarts at the nearest state reset before its hole (its dictionary read back from the
/// sink, the earlier members' part through `read_earlier`), not at the folder's start, and repairs blocked on the same
/// missing bytes do not each decode up to them. All the repairs of the member with state resets decode again about
/// one checkpoint interval (1 MiB) together, where each decoded from the folder's start (about 1 MB and more) before.
#[test]
fn repairs_in_a_single_reset_folder_restart_at_the_nearest_state_reset() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.txt", text(900_000, 1)), ("b.bin", mixed(2_000_000, 2)), ("c.txt", text(900_000, 4))];
    let folder: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    for encrypted in [false, true] {
        let archive = seven_zip(&files, encrypted, usize::MAX >> 1);
        let volumes: Vec<Vec<u8>> = archive.chunks(5_000_000).map(<[u8]>::to_vec).collect();
        let mut start = 0;
        for (i, (_, plain)) in files.iter().enumerate() {
            for (article, every) in [(3_000, 11), (20_000, 9)] {
                let r = feed_with(&volumes, i, plain, &folder[..start], article, every, false);
                eprintln!(
                    "member {i} aes {encrypted} article {article}: {} holes, {} decoded again by repairs",
                    r.holes, r.repair_redecoded
                );
                if i == 1 {
                    // state resets after every noise stretch: all the repairs together decode again about one
                    // checkpoint interval (1 MiB: the first repair's decoder, reached past the member's start), where
                    // every one decoded from the folder's start before (13 to 19 MB here)
                    assert!(r.repair_redecoded <= (1 << 20) + 400_000, "{}", r.repair_redecoded);
                } else if i == 2 {
                    // one long text stretch: no state reset after the folder's start to restart at, so a repair
                    // decodes from the start (up to the member's size) each
                    assert!(r.repair_redecoded <= (r.holes + 1) * 3_000_000, "{}", r.repair_redecoded);
                }
            }
            start += plain.len();
        }
    }
}

/// A snapshot taken when the main decode and every repair stand at restart points that reach into earlier members
/// keeps the dictionary-reset fallback: restored on a sink that holds the member's own output but cannot give the
/// earlier members' (no `read_earlier`), the repairs still complete (from the fallback) instead of `HeldOutput`.
#[test]
fn a_snapshot_keeps_the_dictionary_reset_fallback_past_seeded_restart_points() {
    let files: Vec<(&str, Vec<u8>)> = vec![("a.txt", text(900_000, 1)), ("b.bin", mixed(2_000_000, 2))];
    let plain = &files[1].1;
    let archive = seven_zip(&files, false, usize::MAX >> 1);
    let volumes = vec![archive];
    let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, "set.7z.001", Some(PASSWORD)).unwrap();
    let options = || FeedOptions { max_needs: usize::MAX, read_chunk: 4096, ..FeedOptions::new(Some(PASSWORD)) };
    // in order, holes only in the second half: the main decode passes the first megabyte's state resets first, so
    // its restart point (and every repair's) lies in the earlier member
    let all = articles(&volumes, 5_000);
    let half = all.len() / 2;
    let (missing, present): (Vec<_>, Vec<_>) = all.into_iter().enumerate().partition(|(i, _)| *i > half && i % 9 == 4);
    let missing: Vec<Article> = missing.into_iter().map(|(_, a)| a).collect();
    let mut d = FeedDecoder::new(&map, 1, options()).unwrap();
    let mut out = Out::new(plain.len(), None);
    out.earlier = files[0].1.clone();
    let mut source = ArticleBuffer::new(usize::MAX);
    for (v, off, b) in &missing {
        source.mark_lost(*v, *off..*off + b.len() as u64);
    }
    for (_, (v, off, b)) in &present {
        source.insert(*v, *off, b).unwrap();
        d.run(&mut source, &mut out).unwrap();
    }
    // the member's own output stays, the earlier members' is gone; the packed bytes are fetched again
    let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
    out.earlier = Vec::new();
    let mut d = FeedDecoder::restore(&map, 1, options(), &snap).unwrap();
    for (_, (v, off, b)) in &present {
        source.insert(*v, *off, b).unwrap();
    }
    for (v, off, b) in &missing {
        source.insert(*v, *off, b).unwrap();
        d.run(&mut source, &mut out).unwrap_or_else(|e| panic!("{e}"));
    }
    d.run(&mut source, &mut out).unwrap_or_else(|e| panic!("{e}"));
    let s = d.status();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert!(out.bytes == *plain);
}

/// Held mode for a layer that waits at holes: the caller holds another copy's output from the stalled frontier to
/// the member's end, retires it with `fill_lost`, and the member is done with its CRC checked, the hole never fetched.
#[test]
fn fill_lost_to_the_end_finishes_a_folder_waiting_at_a_hole() {
    let plain = mixed(3_000_000, 21);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, usize::MAX >> 1);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let article = 750_000usize;
    let hole = article as u64..(2 * article).min(archive.len()) as u64;
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive[..hole.start as usize]).unwrap();
    source.insert(0, hole.end, &archive[hole.end as usize..]).unwrap();
    source.mark_lost(0, hole.clone());
    let mut d = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
    let mut out = Out::new(plain.len(), None);
    let s = d.run(&mut source, &mut out).unwrap();
    let frontier = s.frontier;
    assert!(frontier > 0 && frontier < plain.len() as u64, "{s:?}");
    // Interior output is refused for this layer; the rest from the frontier is taken.
    assert!(matches!(d.fill_lost(0..1, &plain[..1]), Err(FeedError::FillLost(_))));
    out.write_at(frontier, &plain[frontier as usize..]).unwrap();
    d.fill_lost(frontier..plain.len() as u64, &plain[frontier as usize..]).unwrap();
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true) && s.needs.is_empty(), "{s:?}");
    assert!(out.bytes == plain);
    assert_eq!(out.written, plain.len() as u64, "each output byte once");
}

/// A 7z member the folder's next member goes on from keeps its hand-off: filling it to its end is refused (the last
/// member of the folder may be filled).
#[test]
fn fill_lost_to_the_end_is_refused_for_a_member_with_a_successor() {
    let a = mixed(400_000, 31);
    let b = mixed(300_000, 32);
    let archive = seven_zip(&[("a.bin", a.clone()), ("b.bin", b.clone())], false, 1 << 16);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive[..archive.len() / 3]).unwrap();
    let mut d = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
    let mut out = Out::new(a.len(), None);
    let s = d.run(&mut source, &mut out).unwrap();
    let f = s.frontier;
    assert!(f < a.len() as u64, "{s:?}");
    assert!(matches!(d.fill_lost(f..a.len() as u64, &a[f as usize..]), Err(FeedError::FillLost(_))));
}

/// Codex on #295: with workers, every region not yet arrived (anywhere: a block's payload, the header that ends a
/// block a worker owns) leaves the decoder either done or naming what it needs, never stuck with no need; and a
/// snapshot taken then (the main decode possibly finished, workers short of input) restores to a decoder that
/// finishes with the CRC checked once the region comes.
#[test]
fn workers_never_stall_without_a_need_and_snapshots_keep_their_blocks() {
    let plain = mixed(1_200_000, 21);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, 150_000);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let options = || FeedOptions {
        max_needs: usize::MAX,
        read_chunk: 4096,
        threads: FeedThreads::Count(3),
        ..FeedOptions::default()
    };
    let gap = 3000usize;
    let mut at = 64usize;
    while at + gap < archive.len() {
        let mut d = FeedDecoder::new(&map, 0, options()).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        source.insert(0, 0, &archive[..at]).unwrap();
        source.insert(0, (at + gap) as u64, &archive[at + gap..]).unwrap();
        let mut out = Out::new(plain.len(), None);
        let mut s = d.run(&mut source, &mut out).unwrap().clone();
        while s.more {
            s = d.run(&mut source, &mut out).unwrap().clone();
        }
        assert!(s.done || !s.needs.is_empty(), "gap at {at}: stuck with no need: {s:?}");
        let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
        let mut d = FeedDecoder::restore(&map, 0, options(), &snap).unwrap();
        source.insert(0, at as u64, &archive[at..at + gap]).unwrap();
        let mut s = d.run(&mut source, &mut out).unwrap().clone();
        while s.more {
            s = d.run(&mut source, &mut out).unwrap().clone();
        }
        assert!(s.done && s.crc_ok == Some(true), "gap at {at}: {s:?}");
        assert!(out.bytes == plain, "gap at {at}: output differs");
        at += 37_001;
    }
}

/// Codex on #295: [`FeedOptions::run_budget`] holds with workers: a run writes about the budget (plus the worker
/// output already in hand when it ran out) and says `more`, rather than writing the whole member.
#[test]
fn workers_keep_to_the_run_budget() {
    let plain = mixed(4_000_000, 23);
    let archive = seven_zip(&[("m.bin", plain.clone())], false, 150_000);
    let refs = [archive.as_slice()];
    let map = MemberMap::from_memory(&refs, "set.7z", None).unwrap();
    let budget = 400_000u64;
    let options = FeedOptions { run_budget: Some(budget), threads: FeedThreads::Count(3), ..FeedOptions::default() };
    let mut d = FeedDecoder::new(&map, 0, options).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &archive).unwrap();
    let mut out = Out::new(plain.len(), None);
    let mut runs = 0;
    loop {
        let before = out.written;
        let s = d.run(&mut source, &mut out).unwrap().clone();
        runs += 1;
        // the budget, plus at most a few blocks' output the workers had sent when it ran out
        assert!(out.written - before <= budget + 4 * 160_000, "run {runs} wrote {}", out.written - before);
        if !s.more {
            assert!(s.done && s.crc_ok == Some(true), "{s:?}");
            break;
        }
        assert!(runs < 1000, "no progress");
    }
    assert!(runs >= 5, "{runs} runs");
    assert!(out.bytes == plain);
}
