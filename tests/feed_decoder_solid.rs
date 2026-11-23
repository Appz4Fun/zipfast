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

//! The feed-driven decoder over solid RAR 5.0 streams: members after the first go on from the decoder state the
//! member before left (handed over in-session, or carried across a restart), fed as shuffled articles with holes.
mod common;

use common::{FileSpec, archive_with};
use std::ops::Range;
use zipfast::map::*;

const SALT: [u8; 16] = [3; 16];

/// Literal-rich content (random runs and repeats of them), as video is.
fn video_like(len: usize, seed: u64) -> Vec<u8> {
    let mut plain = Vec::with_capacity(len + 512);
    let mut x = seed | 1;
    while plain.len() < len {
        for _ in 0..300 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            plain.push(x as u8);
        }
        let back = plain.len() - 1_000.min(plain.len());
        let repeat = plain[back..back + 200.min(plain.len() - back)].to_vec();
        plain.extend(repeat);
    }
    plain.truncate(len);
    plain
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

type Article = (u32, u64, Vec<u8>);

/// A solid RAR 5.0 archive of three compressed members, each starting with copies of the one before (its window
/// reaches back into the earlier member's output, and its first matches may repeat the earlier member's distances).
struct Solid {
    map: MemberMap,
    bytes: Vec<u8>,
    plains: Vec<Vec<u8>>,
    starts: Vec<u64>,
    password: Option<&'static str>,
}

struct Collect(Vec<u8>);
impl zipfast::rar5::unpack::Sink for Collect {
    fn put(&mut self, bytes: &[u8]) -> zipfast::Result<()> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn rar5_solid(seed: u64, encrypted: bool) -> Solid {
    rar5_solid_with(seed, encrypted, false)
}

/// With `filter`, member 1 declares an E8 filter over part of the output member 2 starts by copying: a window
/// rebuilt from held output must undo it relative to member 1's start.
fn rar5_solid_with(seed: u64, encrypted: bool, filter: bool) -> Solid {
    let a = video_like(220_000, seed);
    let mut b = a[a.len() - 90_000..a.len() - 20_000].to_vec();
    b.extend(video_like(160_000, seed + 1));
    if filter {
        // calls with small addresses, which an E8 filter rewrites
        for k in (0..b.len() - 5).step_by(64) {
            b[k] = 0xE8;
            b[k + 4] = 0;
        }
    }
    let mut c = b[b.len() - 100_000..b.len() - 40_000].to_vec();
    c.extend(video_like(140_000, seed + 2));
    solid_from(&[a, b, c], encrypted, filter.then_some(1), "")
}

fn op_len(op: &zipfast::rar5::testenc::Op) -> usize {
    use zipfast::rar5::testenc::Op;
    match op {
        Op::Lit(_) => 1,
        Op::Match(n, _) | Op::Rep(_, n) => *n as usize,
        _ => 0,
    }
}

/// One LZ pass over the members' concatenation, cut between ops at or just past each member's end (a member's ops
/// never run into the next): the ops of each member.
fn solid_ops(raw: &[Vec<u8>]) -> (Vec<u8>, Vec<Vec<zipfast::rar5::testenc::Op>>) {
    use zipfast::rar5::testenc;
    let all = raw.concat();
    let ops = testenc::lz(&all, 1 << 17, 16);
    let mut wanted = Vec::new();
    let mut sum = 0;
    for r in &raw[..raw.len() - 1] {
        sum += r.len();
        wanted.push(sum);
    }
    let mut at = 0usize;
    let mut groups: Vec<Vec<testenc::Op>> = vec![Vec::new()];
    for op in ops {
        if groups.len() <= wanted.len() && at >= wanted[groups.len() - 1] {
            groups.push(Vec::new());
        }
        at += op_len(&op);
        groups.last_mut().unwrap().push(op);
    }
    assert_eq!(groups.len(), raw.len());
    (all, groups)
}

/// A solid archive of the members `raw` (one LZ pass, blocks of 2,000 ops); with `filter`, that member declares an
/// E8 filter at the block 95,000 bytes before its end, over 40,000 bytes.
fn solid_from(raw: &[Vec<u8>], encrypted: bool, filter: Option<usize>, prefix: &str) -> Solid {
    use zipfast::rar5::testenc;
    let (_, groups) = solid_ops(raw);
    let mut streams: Vec<Vec<u8>> = groups.iter().map(|g| testenc::tuned_stream(g, 2_000)).collect();
    if let Some(m) = filter {
        let size: usize = groups[m].iter().map(op_len).sum();
        let chunks: Vec<&[testenc::Op]> = groups[m].chunks(2_000).collect();
        let mut out = Vec::new();
        let mut at = 0usize;
        let mut placed = false;
        for (i, c) in chunks.iter().enumerate() {
            let mut c = c.to_vec();
            if !placed && at + 95_000 >= size {
                c.insert(0, testenc::Op::Filter { start: 0, len: 40_000, kind: 1, channels: 0 });
                placed = true;
            }
            at += c.iter().map(op_len).sum::<usize>();
            out.extend(testenc::tuned_block(&c, i + 1 == chunks.len()));
        }
        assert!(placed);
        streams[m] = out;
    }
    let plains = reference(&streams, &groups.iter().map(|g| g.iter().map(op_len).sum()).collect::<Vec<_>>());
    if filter.is_none() {
        let (all, _) = (raw.concat(), ());
        assert_eq!(plains.concat(), all);
    }
    pack(&streams, plains, encrypted, prefix)
}

/// What the packed streams of a solid stream decode to (filters applied), member by member.
fn reference(streams: &[Vec<u8>], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut dec = zipfast::rar5::unpack::Unpacker::new(zipfast::rar5::unpack::Window::full(1 << 18)).unwrap();
    dec.set_threads(0, u64::MAX);
    let mut plains = Vec::new();
    for (i, st) in streams.iter().enumerate() {
        if i == 0 {
            dec.reset(Some(sizes[0] as u64));
        } else {
            dec.next_file(Some(sizes[i] as u64));
        }
        let mut out = Collect(Vec::new());
        dec.feed(st, &mut out).unwrap();
        dec.finish(&mut out).unwrap();
        assert_eq!(out.0.len(), sizes[i]);
        plains.push(out.0);
    }
    plains
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let mut inner: Vec<u8> = padded.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(message);
    let mut outer: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&zipfast::crypto::sha256(&inner));
    zipfast::crypto::sha256(&outer)
}

/// The RAR 5.0 password check value for `password` (KDF count 1).
fn password_check(password: &str) -> [u8; 8] {
    let mut block = SALT.to_vec();
    block.extend(1u32.to_be_bytes());
    let mut u = hmac(password.as_bytes(), &block);
    let mut sum = u;
    for _ in 1..(1u32 << 1) + 32 {
        u = hmac(password.as_bytes(), &u);
        sum.iter_mut().zip(u).for_each(|(s, b)| *s ^= b);
    }
    let mut folded = [0u8; 8];
    sum.iter().enumerate().for_each(|(i, b)| folded[i % 8] ^= b);
    folded
}

/// The archive: member `i` holds packed stream `streams[i]` decoding to `plains[i]`, every one after the first
/// solid; encrypted with password "pw" (with a password check), each member its own IV; names prefixed.
fn pack(streams: &[Vec<u8>], plains: Vec<Vec<u8>>, encrypted: bool, prefix: &str) -> Solid {
    let keys = encrypted.then(|| zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap());
    let check = password_check("pw");
    let mut packed = Vec::new();
    let mut crcs = Vec::new();
    let mut extras = Vec::new();
    for (i, st) in streams.iter().enumerate() {
        let mut data = st.clone();
        let mut crc = crc32fast::hash(&plains[i]);
        let mut extra = Vec::new();
        if let Some((key, hash_key)) = &keys {
            let iv = [i as u8 + 1; 16];
            data.resize(data.len().div_ceil(16) * 16, 0);
            data = zipfast::crypto::encrypt_cbc(key, &iv, &data).unwrap();
            extra = vec![48, 1, 0, 3, 1];
            extra.extend(SALT);
            extra.extend(iv);
            extra.extend(check);
            extra.extend(&zipfast::crypto::sha256(&check)[..4]);
            crc = zipfast::crypto::rar5_tweak_crc32(crc, hash_key);
        }
        packed.push(data);
        crcs.push(crc);
        extras.push(extra);
    }
    let names: Vec<String> = (0..streams.len()).map(|i| format!("{prefix}{}.bin", (b'a' + i as u8) as char)).collect();
    let specs: Vec<(FileSpec<'_>, u32)> = (0..streams.len())
        .map(|i| {
            let mut s = FileSpec::new(&names[i], &packed[i]);
            s.method = 3;
            s.size = Some(plains[i].len() as u64);
            s.solid = i > 0;
            s.extra = extras[i].clone();
            (s, crcs[i])
        })
        .collect();
    let bytes = archive_with(&specs, true);
    let password = encrypted.then_some("pw");
    let map = MemberMap::from_memory(&[&bytes], "s.rar", password).unwrap();
    assert!(map.members[1..].iter().all(|m| m.solid) && !map.members[0].solid);
    let mut starts = vec![0u64];
    for p in &plains {
        starts.push(starts.last().unwrap() + p.len() as u64);
    }
    starts.pop();
    Solid { map, bytes, plains, starts, password }
}

/// One member's output: each byte written once, read back where written, else from a donor (another copy's
/// output) when there is one.
#[derive(Default)]
struct Held {
    out: Vec<u8>,
    seen: Vec<bool>,
    donor: Vec<u8>,
}

impl Held {
    fn write(&mut self, offset: u64, bytes: &[u8]) {
        let end = offset as usize + bytes.len();
        if self.seen.len() < end {
            self.seen.resize(end, false);
            self.out.resize(end, 0);
        }
        assert!(self.seen[offset as usize..end].iter().all(|s| !s), "output {offset}..{end} written twice");
        self.seen[offset as usize..end].iter_mut().for_each(|s| *s = true);
        self.out[offset as usize..end].copy_from_slice(bytes);
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let mut n = 0;
        for (i, b) in buf.iter_mut().enumerate() {
            let at = offset as usize + i;
            if self.seen.get(at).copied().unwrap_or(false) {
                *b = self.out[at];
            } else if let Some(&d) = self.donor.get(at) {
                *b = d;
            } else {
                break;
            }
            n += 1;
        }
        n
    }
}

/// The sink of member `i` of a stream whose members' outputs are `outs`: its own output, and the earlier members'
/// at stream offsets.
struct View<'a> {
    outs: &'a mut [Held],
    i: usize,
    starts: &'a [u64],
    /// stream offsets read back from earlier members
    earlier: &'a mut u64,
}

impl FeedSink for View<'_> {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.outs[self.i].write(offset, bytes);
        Ok(())
    }

    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.outs[self.i].read(offset, buf))
    }

    fn read_earlier(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let j = self.starts.partition_point(|&s| s <= offset) - 1;
        assert!(j < self.i, "read_earlier at {offset} for member {}", self.i);
        let room = (self.starts[j + 1] - offset) as usize;
        let n = buf.len().min(room);
        let got = self.outs[j].read(offset - self.starts[j], &mut buf[..n]);
        *self.earlier += got as u64;
        Ok(got)
    }
}

/// A feed of a solid stream's members: a decoder per member, each started by a hand-off from the one before once
/// that one's main decode has finished.
struct Run<'s> {
    s: &'s Solid,
    source: ArticleBuffer,
    outs: Vec<Held>,
    decoders: Vec<Option<FeedDecoder>>,
    earlier: u64,
    /// whether a successor was ever unproven while the member before it was not done
    saw_unproven: bool,
    /// whether each successor was unproven when handed over
    started_unproven: Vec<bool>,
}

impl<'s> Run<'s> {
    fn new(s: &'s Solid, donor: bool) -> Self {
        let outs = s
            .plains
            .iter()
            .map(|p| Held { donor: if donor { p.clone() } else { Vec::new() }, ..Held::default() })
            .collect();
        let first = FeedDecoder::new(&s.map, 0, options(s)).unwrap();
        Run {
            s,
            source: ArticleBuffer::new(usize::MAX),
            outs,
            decoders: std::iter::once(Some(first))
                .chain(std::iter::repeat_with(|| None))
                .take(s.plains.len())
                .collect(),
            earlier: 0,
            saw_unproven: false,
            started_unproven: vec![false; s.plains.len()],
        }
    }

    fn view(&mut self, i: usize) -> (&mut FeedDecoder, &mut ArticleBuffer, View<'_>) {
        let d = self.decoders[i].as_mut().unwrap();
        (d, &mut self.source, View { outs: &mut self.outs, i, starts: &self.s.starts, earlier: &mut self.earlier })
    }

    fn step(&mut self) {
        let n = self.s.plains.len();
        let mut i = 0;
        while i < n {
            if self.decoders[i].is_some() {
                let (d, src, mut view) = self.view(i);
                loop {
                    let st = d.run(src, &mut view).unwrap_or_else(|e| panic!("member {i}: {e:?}"));
                    if !st.more {
                        break;
                    }
                }
                let st = self.decoders[i].as_ref().unwrap().status().clone();
                if i + 1 < n && self.decoders[i + 1].is_none() && st.frontier == self.s.plains[i].len() as u64 {
                    // an empty member's frontier is at its size from the start: it hands over once its blocks are in
                    match self.decoders[i].as_mut().unwrap().next_solid(&self.s.map, i + 1, options(self.s)) {
                        Ok(next) => {
                            if next.status().unproven {
                                self.saw_unproven = true;
                                self.started_unproven[i + 1] = true;
                            }
                            self.decoders[i + 1] = Some(next);
                        }
                        Err(FeedError::Handoff(_)) if self.s.plains[i].is_empty() => {}
                        Err(e) => panic!("member {i}: {e}"),
                    }
                }
            }
            i += 1;
        }
    }

    fn insert(&mut self, a: &Article) {
        self.source.insert(a.0, a.1, &a.2).unwrap();
        self.step();
    }

    fn check_done(&self) -> FeedStats {
        let mut total = FeedStats::default();
        for i in 0..self.s.plains.len() {
            let d = self.decoders[i].as_ref().unwrap_or_else(|| panic!("member {i} never started"));
            let st = d.status();
            assert!(st.done && st.crc_ok == Some(true) && !st.unproven, "member {i}: {st:?}");
            assert_eq!(self.outs[i].out, self.s.plains[i], "member {i} output");
            assert!(self.outs[i].seen.iter().all(|s| *s), "member {i} written whole");
            let s = d.stats();
            assert_eq!(s.written, self.s.plains[i].len() as u64, "member {i} written once");
            total.packed_read += s.packed_read;
            total.written += s.written;
            total.redecoded += s.redecoded;
            total.holes += s.holes;
        }
        total
    }
}

fn options(s: &Solid) -> FeedOptions {
    FeedOptions { max_needs: usize::MAX, ..FeedOptions::new(s.password) }
}

/// The archive cut into articles, shuffled; every `missing_every`-th one (from `skip`) held back. The articles of
/// member data only are held back, so the headers always arrive.
fn split(s: &Solid, size: usize, missing_every: usize, seed: u64) -> (Vec<Article>, Vec<Article>) {
    let mut all: Vec<Article> =
        s.bytes.chunks(size).enumerate().map(|(i, c)| (0u32, (i * size) as u64, c.to_vec())).collect();
    shuffle(&mut all, seed);
    let data: Vec<Range<u64>> = s.map.members.iter().flat_map(|m| m.pieces.iter().map(|p| p.packed.clone())).collect();
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for (i, a) in all.into_iter().enumerate() {
        let r = a.1..a.1 + a.2.len() as u64;
        let inside = data.iter().any(|d| d.start <= r.start && r.end <= d.end);
        if missing_every > 0 && i % missing_every == missing_every / 2 && inside {
            missing.push(a);
        } else {
            present.push(a);
        }
    }
    (present, missing)
}

/// The archive cut into articles, shuffled; the articles holding member `m`'s data at fraction `f` of it held back.
fn split_at(s: &Solid, size: usize, at: &[(usize, f64)], seed: u64) -> (Vec<Article>, Vec<Article>) {
    let mut all: Vec<Article> =
        s.bytes.chunks(size).enumerate().map(|(i, c)| (0u32, (i * size) as u64, c.to_vec())).collect();
    shuffle(&mut all, seed);
    let points: Vec<u64> = at
        .iter()
        .map(|&(m, f)| {
            let p = &s.map.members[m].pieces[0].packed;
            p.start + ((p.end - p.start) as f64 * f) as u64
        })
        .collect();
    all.into_iter().partition(|a| !points.iter().any(|&p| a.1 <= p && p < a.1 + a.2.len() as u64))
}

#[test]
fn a_solid_stream_hands_over_member_to_member_without_decoding_twice() {
    for encrypted in [false, true] {
        let s = rar5_solid(21, encrypted);
        // a successor cannot start on its own: its window and decoder state are the member before's
        assert!(matches!(
            FeedDecoder::new(&s.map, 1, options(&s)),
            Err(FeedError::Unsupported(FeedUnsupported::Solid))
        ));
        let (present, _) = split(&s, 6_000, 0, 5);
        let mut run = Run::new(&s, false);
        for a in &present {
            run.insert(a);
        }
        let stats = run.check_done();
        assert_eq!(stats.redecoded, 0, "{stats:?}");
        // the window lived on in the decoder: nothing was read back
        assert_eq!(run.earlier, 0);
        // the hand-off happened before the next member's bytes were all there: a member's needs are its own
        let d1 = run.decoders[1].as_ref().unwrap();
        assert_eq!(d1.stream_start(), s.starts[1]);
    }
}

#[test]
fn holes_without_held_output_wait_and_the_successor_starts_once_they_come() {
    for encrypted in [false, true] {
        let s = rar5_solid(22, encrypted);
        let (present, missing) = split(&s, 7_000, 7, 6);
        let mut run = Run::new(&s, false);
        for (v, off, b) in &missing {
            run.source.mark_lost(*v, *off..*off + b.len() as u64);
        }
        for a in &present {
            run.insert(a);
        }
        // the first member waits at its first hole, so nothing after it could start
        let d0 = run.decoders[0].as_ref().unwrap().status().clone();
        assert!(d0.stalled && !d0.done, "{d0:?}");
        assert!(run.decoders[2].is_none());
        for a in missing.iter().rev() {
            run.insert(a);
        }
        let stats = run.check_done();
        assert_eq!(stats.redecoded, 0, "{stats:?}");
    }
}

/// Holes skipped over held output: a member hands over once its main decode passes its end, with ranges still lost
/// and repaired later; the successor's window holds held output in those ranges (unproven), its own holes are
/// skipped too, and every repair, including those whose checkpoint window reaches into the member before, ends
/// exact.
#[test]
fn a_hole_in_one_member_reaches_the_next_through_the_window() {
    for encrypted in [false, true] {
        let s = rar5_solid(23, encrypted);
        // a hole late in member 0 (its lost output is what member 1 starts by copying), one early in member 1 (its
        // restart's window reaches into member 0) and one in the middle of member 2
        let (present, missing) = split_at(&s, 7_000, &[(0, 0.75), (1, 0.12), (2, 0.5)], 7);
        let mut run = Run::new(&s, true);
        for (v, off, b) in &missing {
            run.source.mark_lost(*v, *off..*off + b.len() as u64);
        }
        for a in &present {
            run.insert(a);
        }
        let lost: Vec<Vec<Range<u64>>> =
            run.decoders.iter().map(|d| d.as_ref().map(|d| d.status().lost.clone()).unwrap_or_default()).collect();
        let states: Vec<_> = run.decoders.iter().map(|d| d.as_ref().map(|d| d.status().clone())).collect();
        assert!(run.decoders.iter().all(Option::is_some), "every member started over held output: {states:#?}");
        // member 0's lost output lies in what member 1 starts by copying: member 1 decoded from it as held output
        let a_len = s.plains[0].len() as u64;
        assert!(lost[0].iter().any(|r| r.end > a_len - 90_000 && r.start < a_len - 20_000), "{lost:?}");
        // a successor started while the member before still had lost output is unproven until done
        assert!(run.saw_unproven);
        // everything written so far is right
        for (i, o) in run.outs.iter().enumerate() {
            for (k, w) in o.seen.iter().enumerate() {
                if *w {
                    assert_eq!(o.out[k], s.plains[i][k], "member {i} byte {k}");
                }
            }
        }
        // the missing articles come late, in another order, with a snapshot round trip of the middle member
        for (n, a) in missing.iter().enumerate() {
            run.insert(a);
            if n == missing.len() / 2 {
                let snap = run.decoders[1].as_ref().unwrap().snapshot();
                let snap = FeedSnapshot::from_bytes(&snap.to_bytes()).unwrap();
                let restored = FeedDecoder::restore(&s.map, 1, options(&s), &snap).unwrap();
                run.decoders[1] = Some(restored);
                run.step();
            }
        }
        let stats = run.check_done();
        eprintln!("encrypted {encrypted}: {stats:?}, earlier read back {}", run.earlier);
        let total: u64 = s.plains.iter().map(|p| p.len() as u64).sum();
        assert!(stats.redecoded < total / 4, "{stats:?}");
    }
}

/// A finished member's state survives a snapshot (and a restart): the successor starts from the carry, reading its
/// window back from the earlier member's output, and a successor's snapshot taken across the boundary restores.
#[test]
fn a_successor_starts_from_a_carry_and_restores_across_the_boundary() {
    for encrypted in [false, true] {
        let s = rar5_solid(24, encrypted);
        let (present, _) = split(&s, 5_000, 0, 8);
        // member 0 alone first
        let mut run = Run::new(&s, false);
        let m0_end = s.map.members[0].pieces.last().unwrap().packed.end;
        let (first, rest): (Vec<_>, Vec<_>) = present.into_iter().partition(|a| a.1 < m0_end);
        for a in &first {
            run.source.insert(a.0, a.1, &a.2).unwrap();
        }
        {
            let (d, src, mut view) = run.view(0);
            let st = d.run(src, &mut view).unwrap();
            assert!(st.done && st.crc_ok == Some(true), "{st:?}");
        }
        let carry = run.decoders[0].as_ref().unwrap().solid_carry().expect("a carry at the end");
        assert_eq!(carry.next_start(), s.starts[1]);
        assert!(!carry.unproven());
        // a snapshot of the finished member keeps it: restored, it hands over from there
        let snap0 = FeedSnapshot::from_bytes(&run.decoders[0].as_ref().unwrap().snapshot().to_bytes()).unwrap();
        let mut d0 = FeedDecoder::restore(&s.map, 0, options(&s), &snap0).unwrap();
        assert_eq!(d0.solid_carry(), Some(carry.clone()));
        let via_restore = d0.next_solid(&s.map, 1, options(&s)).unwrap();
        drop(via_restore);
        // the carry, serialized, starts member 1 in a "new process"
        let carry = SolidCarry::from_bytes(&carry.to_bytes()).unwrap();
        assert!(matches!(FeedDecoder::resume_solid(&s.map, 2, options(&s), &carry), Err(FeedError::Handoff(_))));
        let d1 = FeedDecoder::resume_solid(&s.map, 1, options(&s), &carry).unwrap();
        run.decoders[1] = Some(d1);
        // half of the rest, then a snapshot of member 1 mid-member, restored
        let half = rest.len() / 2;
        for a in &rest[..half] {
            run.source.insert(a.0, a.1, &a.2).unwrap();
        }
        run.step();
        assert!(run.earlier > 0, "the carry's window came from member 0's output");
        let snap = run.decoders[1].as_ref().unwrap().snapshot();
        let snap = FeedSnapshot::from_bytes(&snap.to_bytes()).unwrap();
        run.decoders[1] = Some(FeedDecoder::restore(&s.map, 1, options(&s), &snap).unwrap());
        for a in &rest[half..] {
            run.insert(a);
        }
        let stats = run.check_done();
        // the restore decoded again at most the output since the last block boundary
        assert!(stats.redecoded < 64 << 10, "{stats:?}");
    }
}

/// A filter member 1 ran is still in the window member 2 starts with: restored from a carry (its window read back
/// from member 1's filtered output), member 2 undoes it relative to member 1's start, as the decoder held it.
#[test]
fn a_carry_undoes_an_earlier_members_filter_relative_to_that_member() {
    for encrypted in [false, true] {
        let s = rar5_solid_with(25, encrypted, true);
        let (present, _) = split(&s, 6_000, 0, 9);
        let m1_end = s.map.members[1].pieces.last().unwrap().packed.end;
        let (first, rest): (Vec<_>, Vec<_>) = present.into_iter().partition(|a| a.1 < m1_end);
        let mut run = Run::new(&s, false);
        for a in &first {
            run.insert(a);
        }
        let carry = run.decoders[1].as_ref().unwrap().solid_carry().expect("member 1 finished");
        // drop the live hand-off: member 2 starts from the carry, as after a restart
        let carry = SolidCarry::from_bytes(&carry.to_bytes()).unwrap();
        run.decoders[2] = Some(FeedDecoder::resume_solid(&s.map, 2, options(&s), &carry).unwrap());
        for a in &rest {
            run.insert(a);
        }
        run.check_done();
        assert!(run.earlier > 0);
    }
}

/// A member shorter than the window does not prove the older bytes it leaves in the window: member 0 skips a hole
/// over held output (its repair still to come), member 1 (20 KB) decodes and passes its CRC, and member 2, which
/// starts by copying member 0's output from around the hole, is unproven until its own CRC matches.
#[test]
fn a_short_proven_member_does_not_prove_the_older_window() {
    for encrypted in [false, true] {
        let a = video_like(200_000, 41);
        let b = video_like(20_000, 42);
        let mut c = a[60_000..150_000].to_vec();
        c.extend(video_like(60_000, 43));
        let s = solid_from(&[a, b, c], encrypted, None, "");
        let (present, missing) = split_at(&s, 7_000, &[(0, 0.5)], 11);
        let mut run = Run::new(&s, true);
        for (v, off, b) in &missing {
            run.source.mark_lost(*v, *off..*off + b.len() as u64);
        }
        for a in &present {
            run.insert(a);
        }
        let st: Vec<FeedStatus> = run.decoders.iter().map(|d| d.as_ref().unwrap().status().clone()).collect();
        assert!(!st[0].done && st[0].unproven, "member 0 skipped its hole: {:?}", st[0]);
        assert!(st[1].done && st[1].crc_ok == Some(true) && !st[1].unproven, "{:?}", st[1]);
        // member 2 decoded from member 0's unproven output: unproven until its own CRC matched
        assert!(run.started_unproven[2], "member 2 started from a window holding member 0's unproven output");
        assert!(st[2].unproven || (st[2].done && st[2].crc_ok == Some(true)), "{:?}", st[2]);
        for a in &missing {
            run.insert(a);
        }
        run.check_done();
    }
}

/// An empty member's blocks set the tables the next member's first block (which has none) goes on with: they are
/// decoded before the hand-off and before the carry is taken, also when the empty member is the stream's first.
#[test]
fn an_empty_member_with_blocks_sets_the_next_members_tables() {
    use zipfast::rar5::testenc;
    for encrypted in [false, true] {
        for empty_first in [false, true] {
            let a = video_like(120_000, 51);
            let mut c = a[40_000..100_000].to_vec();
            c.extend(video_like(50_000, 52));
            let raw: Vec<Vec<u8>> = if empty_first { vec![c.clone()] } else { vec![a, c] };
            let (_, groups) = solid_ops(&raw);
            let sizes: Vec<usize> = groups.iter().map(|g| g.iter().map(op_len).sum()).collect();
            // an empty member: one block with fixed tables and no symbols; then a member whose block has no tables
            let empty = testenc::block(&[], true, true);
            let last = testenc::block(groups.last().unwrap(), false, true);
            let (streams, sizes) = if empty_first {
                (vec![empty, last], vec![0, sizes[0]])
            } else {
                (vec![testenc::tuned_stream(&groups[0], 2_000), empty, last], vec![sizes[0], 0, sizes[1]])
            };
            let plains = reference(&streams, &sizes);
            let s = pack(&streams, plains, encrypted, "");
            let (present, _) = split(&s, 4_000, 0, 12);
            let mut run = Run::new(&s, false);
            for a in &present {
                run.insert(a);
            }
            let stats = run.check_done();
            assert_eq!(stats.redecoded, 0);
            // the carry taken at the empty member's end holds its tables too
            let e = if empty_first { 0 } else { 1 };
            let carry = run.decoders[e].as_ref().unwrap().solid_carry().expect("a carry");
            let mut run2 = Run::new(&s, false);
            for a in &present {
                run2.source.insert(a.0, a.1, &a.2).unwrap();
            }
            run2.outs = run.outs.iter().map(|o| Held { donor: o.out.clone(), ..Held::default() }).collect();
            run2.outs[e + 1] = Held::default();
            run2.decoders = (0..s.plains.len()).map(|_| None).collect();
            run2.decoders[e + 1] = Some(FeedDecoder::resume_solid(&s.map, e + 1, options(&s), &carry).unwrap());
            let (d, src, mut view) = run2.view(e + 1);
            let st = d.run(src, &mut view).unwrap();
            assert!(st.done && st.crc_ok == Some(true), "from the carry: {st:?}");
        }
    }
}

/// A sink that only takes output: no read_held, no read_earlier.
struct WriteOnly(Vec<u8>);

impl FeedSink for WriteOnly {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_at(offset, bytes)
    }
}

/// A hand-off that fails on the successor's own setup (a wrong password, a window limit) keeps the live decoder:
/// the next attempt still goes on in-session, needing no output read back.
#[test]
fn a_failed_hand_off_keeps_the_live_decoder() {
    let s = rar5_solid(26, true);
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &s.bytes).unwrap();
    let mut d0 = FeedDecoder::new(&s.map, 0, options(&s)).unwrap();
    let mut out0 = WriteOnly(Vec::new());
    assert!(d0.run(&mut source, &mut out0).unwrap().done);
    assert!(matches!(d0.next_solid(&s.map, 1, FeedOptions::new(Some("wrong"))), Err(FeedError::WrongPassword)));
    let small = FeedOptions { max_window: 1 << 10, ..options(&s) };
    assert!(matches!(d0.next_solid(&s.map, 1, small), Err(FeedError::Unsupported(FeedUnsupported::Window { .. }))));
    let mut d1 = d0.next_solid(&s.map, 1, options(&s)).unwrap();
    let mut out1 = WriteOnly(Vec::new());
    let st = d1.run(&mut source, &mut out1).unwrap();
    assert!(st.done && st.crc_ok == Some(true), "{st:?}");
    assert_eq!(out1.0, s.plains[1]);
}

/// A carry binds to its stream: one from another archive whose members have the same sizes is refused.
#[test]
fn a_carry_from_another_stream_is_refused() {
    let raw = {
        let a = video_like(100_000, 61);
        let mut b = a[20_000..80_000].to_vec();
        b.extend(video_like(40_000, 62));
        vec![a, b]
    };
    let x = solid_from(&raw, false, None, "");
    let y = solid_from(&raw, false, None, "other/");
    assert_eq!(x.starts, y.starts);
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &x.bytes).unwrap();
    let mut d0 = FeedDecoder::new(&x.map, 0, options(&x)).unwrap();
    assert!(d0.run(&mut source, &mut WriteOnly(Vec::new())).unwrap().done);
    let carry = d0.solid_carry().unwrap();
    assert!(FeedDecoder::resume_solid(&x.map, 1, options(&x), &carry).is_ok());
    assert!(matches!(FeedDecoder::resume_solid(&y.map, 1, options(&y), &carry), Err(FeedError::Handoff(_))));
}
