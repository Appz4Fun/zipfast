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

//! The feed-driven decoder over ZIP members (`zipfast::map::FeedDecoder`): Deflate, Deflate64 and stored members,
//! plain, ZipCrypto and WinZip AES, single files, Info-ZIP split sets and byte splits, fed as shuffled articles with
//! holes and late repairs, with a snapshot round trip part way.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::ops::Range;
use std::path::Path;
use zipfast::map::*;
use zipfast::zip::write::*;

fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
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

/// Text-like content that Deflate packs into many dynamic-Huffman blocks, with incompressible stretches (stored
/// blocks) now and then.
fn content(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&str; 16] = [
        "feed ", "decoder ", "article ", "volume ", "deflate ", "window ", "block ", "hole ", "repair ", "zip ",
        "member ", "output ", "packed ", "stream ", "the ", "of ",
    ];
    let mut next = rng(seed);
    let mut out = Vec::with_capacity(len + 64);
    while out.len() < len {
        let r = next();
        if r.is_multiple_of(97) {
            for _ in 0..(r >> 8) % 3_000 {
                out.push(next() as u8);
            }
        } else {
            out.extend_from_slice(WORDS[(r >> 16) as usize % WORDS.len()].as_bytes());
            if r.is_multiple_of(13) {
                out.extend_from_slice(format!("{}\n", r % 100_000).as_bytes());
            }
        }
    }
    out.truncate(len);
    out
}

/// A deterministic shuffle.
fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut next = rng(seed);
    for i in (1..v.len()).rev() {
        v.swap(i, (next() % (i as u64 + 1)) as usize);
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Deflate,
    ZipCrypto { deflate: bool },
    Aes { deflate: bool, ae2: bool },
}

fn method(deflate: bool) -> Method {
    if deflate { Method::Deflate(DeflateLevel::new(6).unwrap()) } else { Method::Stored }
}

/// A ZIP written forward (every nonempty entry has a data descriptor: sizes only in the central directory).
fn zip_streamed(entries: &[(&str, &[u8], Kind)]) -> Vec<u8> {
    let mut w = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    for &(name, plain, kind) in entries {
        let options = |deflate| EntryOptions {
            name: EntryName::Utf8(name),
            method: method(deflate),
            modified: DosDateTime::default(),
            extended_mtime: None,
            permissions: Permissions::new(0o644).unwrap(),
            comment: b"",
        };
        let len = InputLength::Exact(plain.len() as u64);
        let mut input = Cursor::new(plain);
        match kind {
            Kind::Deflate => drop(w.add_file(options(true), &mut input, len).unwrap()),
            Kind::ZipCrypto { deflate } => drop(
                w.add_zipcrypto_file(options(deflate), &mut input, len, "pw", |r| {
                    r.iter_mut().enumerate().for_each(|(i, b)| *b = 0x31 + i as u8);
                    Ok(())
                })
                .unwrap(),
            ),
            Kind::Aes { deflate, ae2 } => {
                let variant = if ae2 { AesVariant::Ae2 } else { AesVariant::Ae1 };
                let request = WinZipAesRequest::new("pw", AesStrength::Aes256, variant).unwrap();
                w.add_winzip_aes_file(options(deflate), &mut input, len, request, |salt| {
                    salt.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8 + 7);
                    Ok(())
                })
                .unwrap();
            }
        }
    }
    w.finish().unwrap().sink
}

/// A ZIP written to a seekable sink: sizes in the local headers, no data descriptors.
fn zip_seekable(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
    for &(name, plain) in entries {
        let options = EntryOptions {
            name: EntryName::Utf8(name),
            method: method(true),
            modified: DosDateTime::default(),
            extended_mtime: None,
            permissions: Permissions::new(0o644).unwrap(),
            comment: b"",
        };
        w.add_file(options, &mut Cursor::new(plain), InputLength::Exact(plain.len() as u64)).unwrap();
    }
    w.finish().unwrap().sink.into_inner()
}

/// Every volume cut into articles of `size` bytes: (volume, offset, bytes).
fn articles(volumes: &[Vec<u8>], size: usize) -> Vec<(u32, u64, Vec<u8>)> {
    let mut out = Vec::new();
    for (v, bytes) in volumes.iter().enumerate() {
        for (i, chunk) in bytes.chunks(size).enumerate() {
            out.push((v as u32, (i * size) as u64, chunk.to_vec()));
        }
    }
    out
}

/// The volume ranges of a member's packed stream range.
fn stream_ranges(member: &MapMember, stream: Range<u64>) -> Vec<(u32, Range<u64>)> {
    let mut out = Vec::new();
    for p in &member.pieces {
        let len = p.packed.end - p.packed.start;
        let (s, e) = (stream.start.max(p.stream_offset), stream.end.min(p.stream_offset + len));
        if s < e {
            out.push((p.volume, p.packed.start + (s - p.stream_offset)..p.packed.start + (e - p.stream_offset)));
        }
    }
    out
}

fn merge(mut v: Vec<(u32, Range<u64>)>) -> Vec<(u32, Range<u64>)> {
    v.sort_by_key(|(vol, r)| (*vol, r.start));
    let mut out: Vec<(u32, Range<u64>)> = Vec::new();
    for (vol, r) in v {
        match out.last_mut() {
            Some((pv, pr)) if *pv == vol && pr.end >= r.start => pr.end = pr.end.max(r.end),
            _ => out.push((vol, r)),
        }
    }
    out
}

fn intersect(a: &[(u32, Range<u64>)], b: &[(u32, Range<u64>)]) -> Vec<(u32, Range<u64>)> {
    let mut out = Vec::new();
    for (va, ra) in a {
        for (vb, rb) in b {
            let (s, e) = (ra.start.max(rb.start), ra.end.min(rb.end));
            if va == vb && s < e {
                out.push((*va, s..e));
            }
        }
    }
    merge(out)
}

/// A sink that refuses to write any output byte twice, and gives back what was written.
#[derive(Default)]
struct Once {
    out: Vec<u8>,
    seen: Vec<bool>,
}

impl FeedSink for Once {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        let end = offset as usize + bytes.len();
        if self.seen.len() < end {
            self.seen.resize(end, false);
        }
        assert!(self.seen[offset as usize..end].iter().all(|s| !s), "output {offset}..{end} written twice");
        self.seen[offset as usize..end].iter_mut().for_each(|s| *s = true);
        self.out.write_at(offset, bytes)
    }

    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let at = offset as usize;
        let n = self.seen.get(at..).map_or(0, |s| s.iter().take(buf.len()).take_while(|&&s| s).count());
        buf[..n].copy_from_slice(&self.out[at..at + n]);
        Ok(n)
    }
}

fn options(password: Option<&str>) -> FeedOptions {
    FeedOptions { max_needs: usize::MAX, ..FeedOptions::new(password) }
}

struct Feed<'a> {
    what: String,
    volumes: &'a [Vec<u8>],
    name: &'a str,
    password: Option<&'a str>,
    member: usize,
    /// the member's output, when known (else its CRC proves it)
    plain: Option<&'a [u8]>,
    article: usize,
    missing_every: usize,
    seed: u64,
}

/// What a feed came to.
#[derive(Debug)]
struct Outcome {
    status: FeedStatus,
    stats: FeedStats,
    /// redecoded by the restore, and the frontier it was taken at
    restore_redecoded: u64,
    restore_frontier: u64,
    /// articles fetched again after the restore (released bytes read again)
    refetched: usize,
    out: Vec<u8>,
}

/// Feeds every article but the missing ones (marked lost) shuffled, running the decoder after each; checks the
/// needs then name exactly the missing articles' bytes the member reads, from the hole the main decode waits at;
/// then supplies the missing ones in another order with a snapshot round trip half way, giving back again whatever
/// the restored decoder asks for, and checks the output.
fn feed(f: &Feed) -> Outcome {
    let map = MemberMap::from_memory(&refs(f.volumes), f.name, f.password).unwrap();
    let member = &map.members[f.member];
    let size = member.unpacked_size.unwrap();
    let mut all = articles(f.volumes, f.article);
    shuffle(&mut all, f.seed);
    let (missing, present): (Vec<_>, Vec<_>) = all
        .into_iter()
        .enumerate()
        .partition(|(i, _)| f.missing_every > 0 && i % f.missing_every == f.missing_every / 2);
    let mut decoder = FeedDecoder::new(&map, f.member, options(f.password)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let lost = |a: &(usize, (u32, u64, Vec<u8>))| (a.1.0, a.1.1..a.1.1 + a.1.2.len() as u64);
    for a in &missing {
        let (v, r) = lost(a);
        source.mark_lost(v, r);
    }
    let missing_ranges: Vec<(u32, Range<u64>)> = merge(missing.iter().map(lost).collect());
    let mut sink = Once::default();
    for (_, (v, off, bytes)) in &present {
        source.insert(*v, *off, bytes).unwrap();
        decoder.run(&mut source, &mut sink).unwrap();
    }
    let status = decoder.status().clone();
    let stalled_at = status.frontier;
    if !status.done && !status.lost.is_empty() {
        // a stored WinZip AES member skips holes: the needs are exactly the missing bytes of its lost output
        let spans: Vec<(u32, Range<u64>)> =
            member.packed_spans(0..size).unwrap().into_iter().map(|p| (p.volume, p.packed)).collect();
        let got = merge(status.needs.iter().map(|n| (n.volume, n.range.clone())).collect());
        assert_eq!(got, intersect(&missing_ranges, &spans), "{}: needs", f.what);
        assert!(status.needs.iter().all(|n| n.kind == NeedKind::Repair), "{}", f.what);
        assert!(!status.stalled && status.frontier == size, "{}", f.what);
    } else if !status.done {
        // the needs are exactly the missing bytes from the first one the decode waits at to the stream's end
        let first = &status.needs[0];
        assert_eq!(first.kind, NeedKind::Next, "{}", f.what);
        let whole = stream_ranges(member, 0..u64::MAX);
        let mut at_hole = 0;
        for p in &member.pieces {
            if p.volume == first.volume && p.packed.contains(&first.range.start) {
                at_hole = p.stream_offset + (first.range.start - p.packed.start);
            }
        }
        let want = intersect(&missing_ranges, &stream_ranges(member, at_hole..u64::MAX));
        let got = merge(status.needs.iter().map(|n| (n.volume, n.range.clone())).collect());
        assert_eq!(got, want, "{}: needs", f.what);
        assert!(!intersect(&missing_ranges, &whole).is_empty());
        assert!(status.stalled, "{}: waits at a hole", f.what);
        assert!(status.lost.is_empty(), "{}: nothing lost", f.what);
    }
    // the output so far is exact
    if let Some(plain) = f.plain {
        for (i, (&got, &want)) in sink.out.iter().zip(plain).take(stalled_at as usize).enumerate() {
            if !status.lost.iter().any(|r| r.contains(&(i as u64))) {
                assert_eq!(got, want, "{}: byte {i}", f.what);
            }
        }
    }
    let mut missing = missing;
    shuffle(&mut missing, f.seed ^ 0x55);
    let half = missing.len() / 2;
    let delivered: BTreeSet<usize> = present.iter().map(|(i, _)| *i).collect();
    let mut delivered = delivered;
    let (mut restore_redecoded, mut restore_frontier, mut refetched) = (0, 0, 0);
    let all = {
        let mut a = articles(f.volumes, f.article);
        shuffle(&mut a, f.seed);
        a
    };
    for (k, (i, (v, off, bytes))) in missing.iter().enumerate() {
        if k == half {
            let snap = FeedSnapshot::from_bytes(&decoder.snapshot().to_bytes()).unwrap();
            restore_frontier = decoder.status().frontier;
            let before = decoder.stats().redecoded;
            decoder = FeedDecoder::restore(&map, f.member, options(f.password), &snap).unwrap();
            assert_eq!(decoder.stats().redecoded, before);
            // the restored decoder asks again for released bytes it reads (ZipCrypto from the stream's start)
            loop {
                let status = decoder.run(&mut source, &mut sink).unwrap();
                let again: Vec<usize> = (0..all.len())
                    .filter(|j| delivered.contains(j))
                    .filter(|&j| {
                        let (av, ao, ab) = &all[j];
                        status
                            .needs
                            .iter()
                            .any(|n| n.volume == *av && n.range.start < ao + ab.len() as u64 && *ao < n.range.end)
                            && source.absent(*av, *ao..ao + ab.len() as u64).is_some_and(|r| !r.is_empty())
                    })
                    .collect();
                if again.is_empty() {
                    break;
                }
                for j in again {
                    let (av, ao, ab) = &all[j];
                    source.insert(*av, *ao, ab).unwrap();
                    refetched += 1;
                }
            }
            restore_redecoded = decoder.stats().redecoded - before;
        }
        source.insert(*v, *off, bytes).unwrap();
        delivered.insert(*i);
        decoder.run(&mut source, &mut sink).unwrap();
    }
    let status = decoder.status().clone();
    assert!(status.done && status.lost.is_empty() && status.needs.is_empty(), "{}: {status:?}", f.what);
    assert_eq!(sink.out.len() as u64, size, "{}", f.what);
    if let Some(plain) = f.plain {
        assert!(sink.out == plain, "{}: output differs", f.what);
    }
    let stats = decoder.stats();
    assert_eq!(stats.written, size, "{}: each byte written once", f.what);
    Outcome { status, stats, restore_redecoded, restore_frontier, refetched, out: sink.out }
}

fn check(o: &Outcome, what: &str, crc: bool) {
    if crc {
        assert_eq!(o.status.crc_ok, Some(true), "{what}");
    } else {
        assert_eq!(o.status.crc_ok, None, "{what}");
    }
}

/// The largest output a restore may decode again: one Deflate block of this content (the encoder ends blocks at
/// most every 64 Ki symbols, which this content keeps well under this).
const ONE_BLOCK: u64 = 256 << 10;

#[test]
fn deflate_members_wait_at_holes_and_restore_from_a_block_boundary() {
    let a = content(1_500_000, 1);
    let b = content(700_000, 2);
    let zips = [
        ("streamed (data descriptors)", zip_streamed(&[("a.txt", &a, Kind::Deflate), ("b.txt", &b, Kind::Deflate)])),
        ("seekable", zip_seekable(&[("a.txt", &a), ("b.txt", &b)])),
    ];
    for (what, zip) in &zips {
        let map = MemberMap::from_memory(&[zip.as_slice()], "d.zip", None).unwrap();
        assert_eq!(map.members[0].method, MapMethod::Compressed { id: 8 });
        for (member, plain) in [(0, &a), (1, &b)] {
            for (article, every, seed) in [(7_000, 5, 1), (25_000, 3, 2), (3_000, 0, 3), (750_000, 2, 4)] {
                let o = feed(&Feed {
                    what: format!("{what} member {member} {article}/{every}"),
                    volumes: std::slice::from_ref(zip),
                    name: "d.zip",
                    password: None,
                    member,
                    plain: Some(plain),
                    article,
                    missing_every: every,
                    seed,
                });
                check(&o, what, true);
                assert!(!o.status.unproven && o.status.auth_ok.is_none());
                assert_eq!(o.refetched, 0, "{what}: a plain restore reads only from its checkpoint");
                assert!(
                    o.restore_redecoded <= ONE_BLOCK && o.restore_redecoded <= o.restore_frontier,
                    "{what}: restore decoded {} again at {}",
                    o.restore_redecoded,
                    o.restore_frontier
                );
                // nothing decoded twice but what the restore decoded again
                assert_eq!(o.stats.redecoded, o.restore_redecoded, "{what}");
            }
        }
    }
}

#[test]
fn a_restore_mid_member_decodes_at_most_one_block_again() {
    let a = content(2_000_000, 9);
    let zip = zip_streamed(&[("a.txt", &a, Kind::Deflate)]);
    let map = MemberMap::from_memory(&[zip.as_slice()], "d.zip", None).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Once::default();
    let mut decoder = FeedDecoder::new(&map, 0, options(None)).unwrap();
    // the first 60% of the packed bytes, in order
    let cut = zip.len() * 6 / 10;
    for chunk in zip[..cut].chunks(9_000).enumerate() {
        source.insert(0, (chunk.0 * 9_000) as u64, chunk.1).unwrap();
        decoder.run(&mut source, &mut sink).unwrap();
    }
    let frontier = decoder.status().frontier;
    assert!(frontier > 1_000_000, "{frontier}");
    let snap = FeedSnapshot::from_bytes(&decoder.snapshot().to_bytes()).unwrap();
    // in this session, and in a new one whose source holds only the bytes from here on
    for fresh_source in [false, true] {
        let mut source2 = ArticleBuffer::new(usize::MAX);
        let src: &mut ArticleBuffer = if fresh_source { &mut source2 } else { &mut source };
        let mut d = FeedDecoder::restore(&map, 0, options(None), &snap).unwrap();
        let mut out = Once { out: sink.out.clone(), seen: sink.seen.clone() };
        let status = d.run(src, &mut out).unwrap();
        assert_eq!(status.frontier, frontier);
        if fresh_source {
            // it asks for the packed bytes from its checkpoint, within one block's packed bytes of the cut
            let first = &status.needs[0];
            assert_eq!(first.kind, NeedKind::Next);
            assert!(first.range.start < cut as u64 && cut as u64 - first.range.start < ONE_BLOCK);
            src.insert(0, first.range.start, &zip[first.range.start as usize..]).unwrap();
        } else {
            src.insert(0, cut as u64, &zip[cut..]).unwrap();
        }
        let status = d.run(src, &mut out).unwrap();
        assert!(status.done, "{status:?}");
        assert_eq!(status.crc_ok, Some(true));
        assert!(out.out == a);
        let redecoded = d.stats().redecoded;
        assert!(redecoded > 0 && redecoded <= ONE_BLOCK, "{redecoded}");
    }
    // without the window held, a restore says which output it needs
    let mut d = FeedDecoder::restore(&map, 0, options(None), &snap).unwrap();
    let mut empty = Vec::new();
    assert!(matches!(d.run(&mut source, &mut empty), Err(FeedError::HeldOutput { .. })));
}

#[test]
fn encrypted_members_zipcrypto_and_winzip_aes() {
    let a = content(900_000, 5);
    let s = content(300_000, 6);
    let kinds = [
        ("zipcrypto deflate", Kind::ZipCrypto { deflate: true }, &a, true),
        ("zipcrypto stored", Kind::ZipCrypto { deflate: false }, &s, true),
        ("aes ae-1 deflate", Kind::Aes { deflate: true, ae2: false }, &a, true),
        ("aes ae-2 deflate", Kind::Aes { deflate: true, ae2: true }, &a, false),
        ("aes ae-1 stored", Kind::Aes { deflate: false, ae2: false }, &s, true),
        ("aes ae-2 stored", Kind::Aes { deflate: false, ae2: true }, &s, false),
    ];
    for (what, kind, plain, crc) in kinds {
        let zip = zip_streamed(&[("x.bin", plain, kind)]);
        for (article, every, seed) in [(7_000, 5, 11), (40_000, 3, 12), (5_000, 0, 13)] {
            let o = feed(&Feed {
                what: format!("{what} {article}/{every}"),
                volumes: std::slice::from_ref(&zip),
                name: "e.zip",
                password: Some("pw"),
                member: 0,
                plain: Some(plain),
                article,
                missing_every: every,
                seed,
            });
            check(&o, what, crc);
            let aes = matches!(kind, Kind::Aes { .. });
            let stored_aes = matches!(kind, Kind::Aes { deflate: false, .. });
            if aes {
                // the code is checked in order; a compressed member restored past its start cannot check it, a
                // stored one catches it up from the held output
                let checked = stored_aes || every == 0 || o.restore_frontier == 0;
                assert_eq!(o.status.auth_ok, checked.then_some(true), "{what} {article}/{every}");
                assert_eq!(o.status.unproven, !crc && !checked, "{what} {article}/{every}");
            } else {
                assert_eq!(o.status.auth_ok, None);
                assert!(!o.status.unproven);
            }
            if matches!(kind, Kind::ZipCrypto { .. }) && o.restore_frontier > 0 {
                // a ZipCrypto restore reads the packed bytes before its checkpoint again (keystream only)
                assert!(o.refetched > 0, "{what}");
            }
            if !matches!(kind, Kind::ZipCrypto { .. }) {
                assert_eq!(o.refetched, 0, "{what}");
            }
            assert!(o.restore_redecoded <= ONE_BLOCK, "{what}: {}", o.restore_redecoded);
        }
    }
}

#[test]
fn a_damaged_authentication_code_fails_it() {
    let s = content(50_000, 8);
    for deflate in [true, false] {
        let mut zip = zip_streamed(&[("x.bin", &s, Kind::Aes { deflate, ae2: true })]);
        let map = MemberMap::from_memory(&[zip.as_slice()], "e.zip", Some("pw")).unwrap();
        let m = &map.members[0];
        let tag_at = (m.pieces[0].packed.end - 1) as usize;
        zip[tag_at] ^= 1;
        let mut d = FeedDecoder::new(&map, 0, options(Some("pw"))).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        source.insert(0, 0, &zip).unwrap();
        let status = d.run(&mut source, &mut Once::default()).unwrap();
        assert!(status.done);
        assert_eq!((status.auth_ok, status.crc_ok, status.unproven), (Some(false), None, true), "{deflate}");
    }
}

#[test]
fn wrong_passwords_are_typed() {
    let s = content(20_000, 3);
    let zc = zip_streamed(&[("x.bin", &s, Kind::ZipCrypto { deflate: true })]);
    let map = MemberMap::from_memory(&[zc.as_slice()], "e.zip", None).unwrap();
    assert!(matches!(FeedDecoder::new(&map, 0, options(None)), Err(FeedError::PasswordRequired)));
    // ZipCrypto checks its header's last byte once it is read (1 in 256 wrong passwords pass, then fail the CRC)
    let mut d = FeedDecoder::new(&map, 0, options(Some("nope"))).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &zc).unwrap();
    assert!(matches!(d.run(&mut source, &mut Once::default()), Err(FeedError::WrongPassword)));
    let aes = zip_streamed(&[("x.bin", &s, Kind::Aes { deflate: true, ae2: false })]);
    let map = MemberMap::from_memory(&[aes.as_slice()], "e.zip", None).unwrap();
    assert!(matches!(FeedDecoder::new(&map, 0, options(Some("nope"))), Err(FeedError::WrongPassword)));
}

#[test]
fn byte_split_volumes() {
    let a = content(600_000, 21);
    let b = content(200_000, 22);
    let zip = zip_streamed(&[
        ("a.txt", &a, Kind::Aes { deflate: true, ae2: false }),
        ("b.txt", &b, Kind::ZipCrypto { deflate: true }),
        ("c.txt", &b, Kind::Deflate),
    ]);
    // A byte split (`s.zip.001`, `s.zip.002`, ... of 40,000 bytes each) is one ZIP cut anywhere: the member map
    // keeps the pieces as volumes, so a member crossing a cut has a part per piece and its needs name the piece.
    let volumes: Vec<Vec<u8>> = zip.chunks(40_000).map(<[u8]>::to_vec).collect();
    assert!(volumes.len() > 5, "{}", volumes.len());
    let map = MemberMap::from_memory(&refs(&volumes), "s.zip.001", Some("pw")).unwrap();
    assert_eq!(map.volumes as usize, volumes.len());
    let crossing = map.members[0].pieces.iter().map(|p| p.volume).collect::<Vec<_>>();
    assert!(crossing.len() > 2 && crossing.windows(2).all(|w| w[1] == w[0] + 1), "{crossing:?}");
    for p in &map.members[0].pieces {
        assert!(p.packed.end <= volumes[p.volume as usize].len() as u64);
    }
    for (member, plain) in [(0, &a), (1, &b), (2, &b)] {
        let o = feed(&Feed {
            what: format!("byte split member {member}"),
            volumes: &volumes,
            name: "s.zip.001",
            password: Some("pw"),
            member,
            plain: Some(plain),
            article: 10_000,
            missing_every: 4,
            seed: 31 + member as u64,
        });
        check(&o, "byte split", true);
    }
}

fn fixture(dir: &str, names: &[&str]) -> Vec<Vec<u8>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(dir);
    names.iter().map(|n| std::fs::read(root.join(n)).unwrap()).collect()
}

#[test]
fn info_zip_split_sets() {
    // deflated: c.txt crosses the boundary; crypt: stored ZipCrypto (with a data descriptor) crossing it
    for (set, names, password) in
        [("deflated", ["deflated.z01", "deflated.zip"], None), ("crypt", ["crypt.z01", "crypt.zip"], Some("password"))]
    {
        let volumes = fixture("zip-split", &names);
        let map = MemberMap::from_memory(&refs(&volumes), names[0], password).unwrap();
        for (member, m) in map.members.iter().enumerate() {
            if m.is_dir || m.unpacked_size == Some(0) {
                continue;
            }
            for (article, every, seed) in [(5_000, 4, 41), (1_500, 3, 42)] {
                let o = feed(&Feed {
                    what: format!("{set} member {member}"),
                    volumes: &volumes,
                    name: names[0],
                    password,
                    member,
                    plain: None,
                    article,
                    missing_every: every,
                    seed,
                });
                check(&o, set, true);
            }
        }
    }
}

#[test]
fn deflate64_fixtures() {
    let expected =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/deflate64/expected.txt"))
            .unwrap();
    let sha = |name: &str| {
        expected.lines().find_map(|l| {
            let mut f = l.split(' ');
            (f.next() == Some(name)).then(|| (f.next().unwrap().parse::<u64>().unwrap(), f.next().unwrap().to_owned()))
        })
    };
    for (file, password) in
        [("d64.zip", None), ("d64_zipcrypto.zip", Some("password")), ("d64_aes.zip", Some("password"))]
    {
        let volumes = fixture("deflate64", &[file]);
        let map = MemberMap::from_memory(&refs(&volumes), file, password).unwrap();
        for (member, m) in map.members.iter().enumerate() {
            assert!(matches!(m.method, MapMethod::Compressed { id: 9 } | MapMethod::Stored), "{file}");
            for (article, every, seed) in [(2_000, 4, 51), (700, 3, 52), (10_000, 0, 53)] {
                let o = feed(&Feed {
                    what: format!("{file} {:?}", m.name),
                    volumes: &volumes,
                    name: file,
                    password,
                    member,
                    plain: None,
                    article,
                    missing_every: every,
                    seed,
                });
                let (size, digest) = sha(m.name.as_deref().unwrap()).unwrap();
                assert_eq!(o.out.len() as u64, size);
                let got: String = zipfast::crypto::sha256(&o.out).iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(got, digest, "{file} {:?}", m.name);
                if m.checks.and_then(|c| c.crc32).is_some() {
                    assert_eq!(o.status.crc_ok, Some(true));
                }
            }
        }
    }
}

#[test]
fn a_hole_stalls_the_main_decode_until_its_bytes_come() {
    let a = content(400_000, 61);
    let zip = zip_streamed(&[("a.txt", &a, Kind::Deflate)]);
    let map = MemberMap::from_memory(&[zip.as_slice()], "d.zip", None).unwrap();
    let mut d = FeedDecoder::new(&map, 0, options(None)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Once::default();
    let hole = 50_000u64..60_000;
    source.insert(0, 0, &zip[..hole.start as usize]).unwrap();
    source.mark_lost(0, hole.clone());
    source.insert(0, hole.end, &zip[hole.end as usize..]).unwrap();
    let status = d.run(&mut source, &mut sink).unwrap();
    assert!(status.stalled && !status.done && status.lost.is_empty());
    assert_eq!(status.needs, vec![NeedBytes { volume: 0, range: hole.clone(), kind: NeedKind::Next }]);
    let frontier = status.frontier;
    assert!(frontier > 0);
    // running again changes nothing and counts the hole once
    let again = d.run(&mut source, &mut sink).unwrap();
    assert_eq!(again.frontier, frontier);
    assert_eq!(d.stats().holes, 1);
    source.insert(0, hole.start, &zip[hole.start as usize..hole.end as usize]).unwrap();
    let status = d.run(&mut source, &mut sink).unwrap();
    assert!(status.done && !status.stalled);
    assert_eq!(status.crc_ok, Some(true));
    assert!(sink.out == a);
    assert_eq!(d.stats().redecoded, 0);
}

#[test]
fn bytes_the_decoder_passed_are_released() {
    let a = content(1_000_000, 71);
    let zip = zip_streamed(&[("a.txt", &a, Kind::Deflate)]);
    let map = MemberMap::from_memory(&[zip.as_slice()], "d.zip", None).unwrap();
    let mut d = FeedDecoder::new(&map, 0, options(None)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Once::default();
    let mut peak = 0;
    for (i, chunk) in zip.chunks(8_000).enumerate() {
        source.insert(0, (i * 8_000) as u64, chunk).unwrap();
        d.run(&mut source, &mut sink).unwrap();
        peak = peak.max(source.held());
    }
    assert!(d.status().done);
    // what the decoder holds back is the bytes from its last block boundary on
    assert!(peak < 200_000, "{peak}");
}

#[test]
fn empty_members_verify_their_header_and_code() {
    for kind in [
        Kind::Deflate,
        Kind::ZipCrypto { deflate: false },
        Kind::ZipCrypto { deflate: true },
        Kind::Aes { deflate: true, ae2: false },
    ] {
        let zip = zip_streamed(&[("e.bin", b"", kind), ("f.bin", b"x", kind)]);
        let map = MemberMap::from_memory(&[zip.as_slice()], "e.zip", Some("pw")).unwrap();
        let mut d = FeedDecoder::new(&map, 0, options(Some("pw"))).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        // one byte at a time
        let mut sink = Once::default();
        for (i, b) in zip.iter().enumerate() {
            source.insert(0, i as u64, std::slice::from_ref(b)).unwrap();
            d.run(&mut source, &mut sink).unwrap();
        }
        let status = d.status();
        assert!(status.done && sink.out.is_empty(), "{kind:?}: {status:?}");
        assert_eq!(status.crc_ok, Some(true), "{kind:?}");
        if matches!(kind, Kind::ZipCrypto { .. }) {
            let mut d = FeedDecoder::new(&map, 0, options(Some("nope"))).unwrap();
            let mut source = ArticleBuffer::new(usize::MAX);
            source.insert(0, 0, &zip).unwrap();
            assert!(matches!(d.run(&mut source, &mut Once::default()), Err(FeedError::WrongPassword)), "{kind:?}");
        }
    }
}
