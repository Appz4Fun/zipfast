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

//! `SolidStreamSink`: a solid RAR 5.0 stream's members kept in persistent direct partials, a later member started
//! after a restart from a serialized `SolidCarry` reading its window back from the earlier members' durable output.
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
#![allow(dead_code, reason = "helpers copied from feed_decoder_solid.rs")]
mod common;

#[allow(dead_code, reason = "the shared doc store also carries fault hooks these tests do not use")]
mod anchor_store {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/persistent-anchor-store.rs"));
}

use common::{FileSpec, archive_with};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use zipfast::map::*;
use zipfast::partial::*;
use zipfast::progressive::{
    ProgressiveLimits, ProtectedVolume, ProtectionDeclaration, ProtectionInventory, SessionControl, VolumeBacking,
};

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

// ---- the persistent side ----

fn protection() -> ProtectionDeclaration {
    ProtectionDeclaration::Complete {
        epoch: 1,
        inventory: ProtectionInventory {
            volumes: vec![ProtectedVolume { index: 0, name: "set.rar".into(), backing: VolumeBacking::NonFile }],
            auxiliary_paths: Vec::new(),
        },
    }
}

fn direct(work: &Path, password: Option<&str>) -> DirectPartials {
    let (output_root, state_dir, anchors) = (work.join("out"), work.join("state"), work.join("anchors"));
    for dir in [&output_root, &state_dir, &anchors] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::File::open(work).unwrap().sync_all().unwrap();
    DirectPartials::new(DirectOptions {
        binding: ArchiveBinding { job: [7; 16], archive: [9; 32] },
        output_root,
        state_dir,
        naming: PartialNaming::ArchivePath,
        limits: PartialLimits::for_members(8),
        progressive_limits: ProgressiveLimits::default(),
        anchors: Arc::new(anchor_store::DurableAnchors::open(&anchors).unwrap()),
        control: SessionControl::default(),
        protection: protection(),
        password: password.map(str::to_owned),
    })
    .unwrap()
}

fn verify(file: &mut PartialFile) -> Verdict {
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(verdict) = file.poll_verify(&mut cx) {
            return verdict.unwrap();
        }
    }
}

fn options(s: &Solid) -> FeedOptions {
    FeedOptions { max_needs: usize::MAX, ..FeedOptions::new(s.password) }
}

/// Counts what `read_earlier` returned.
struct Counting<'a> {
    sink: &'a mut SolidStreamSink,
    earlier: u64,
}

impl FeedSink for Counting<'_> {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.sink.write_at(offset, bytes)
    }
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.sink.read_held(offset, buf)
    }
    fn read_earlier(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.sink.read_earlier(offset, buf)?;
        self.earlier += n as u64;
        Ok(n)
    }
}

/// Runs `d` until it stops asking to run again; saves its snapshot as the member's cursor.
fn drive(d: &mut FeedDecoder, source: &mut ArticleBuffer, sink: &mut SolidStreamSink) -> (FeedStatus, u64) {
    let mut counting = Counting { sink, earlier: 0 };
    let st = loop {
        let st = d.run(source, &mut counting).unwrap();
        if !st.more {
            break st;
        }
    };
    counting.sink.set_cursor(&d.snapshot().to_bytes()).unwrap();
    let earlier = counting.earlier;
    (st, earlier)
}

fn member_bytes(file: &PartialFile) -> Vec<u8> {
    std::fs::read(file.output_path()).unwrap()
}

fn work_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zipfast-solid-sink-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_stream_layout_follows_the_members_sizes() {
    let s = rar5_solid(31, false);
    let slots = stream_slots(&s.map, 2).unwrap();
    assert_eq!(slots.len(), 3);
    for (i, slot) in slots.iter().enumerate() {
        assert_eq!((slot.member, slot.start, slot.size), (i, s.starts[i], s.plains[i].len() as u64));
    }
    assert_eq!(stream_slots(&s.map, 0).unwrap().len(), 1);
    assert!(stream_slots(&s.map, 9).is_err());
}

#[test]
fn read_earlier_spans_members_and_stops_at_the_first_unknown_byte() {
    let s = rar5_solid(32, false);
    let work = work_dir("span");
    let parts = direct(&work, None);
    let mut sink = SolidStreamSink::open(&parts, &s.map, 2).unwrap();
    assert_eq!(sink.stream_start(), s.starts[2]);
    // nothing known yet
    let mut buf = vec![0u8; 100];
    assert_eq!(sink.read_earlier(0, &mut buf).unwrap(), 0);
    let mut files: Vec<PartialFile> = sink.into_files();
    // member 0 whole, member 1 up to 15,000 bytes
    files[0].fill(0, &s.plains[0]).unwrap();
    files[1].fill(0, &s.plains[1][..15_000]).unwrap();
    let mut sink = SolidStreamSink::new(vec![
        (s.starts[0], s.plains[0].len() as u64, files.remove(0)),
        (s.starts[1], s.plains[1].len() as u64, files.remove(0)),
        (s.starts[2], s.plains[2].len() as u64, files.remove(0)),
    ])
    .unwrap();
    let all = s.plains.concat();
    // across the boundary of members 0 and 1
    let at = s.starts[1] - 50;
    let mut buf = vec![0u8; 400];
    assert_eq!(sink.read_earlier(at, &mut buf).unwrap(), 400);
    assert_eq!(buf, all[at as usize..at as usize + 400]);
    // up to member 1's first unknown byte
    let at = s.starts[1] + 14_900;
    let mut buf = vec![0u8; 400];
    assert_eq!(sink.read_earlier(at, &mut buf).unwrap(), 100);
    assert_eq!(buf[..100], all[at as usize..at as usize + 100]);
    assert_eq!(sink.read_earlier(at + 100, &mut buf).unwrap(), 0);
    // the current member's own range is not earlier output
    assert_eq!(sink.read_earlier(s.starts[2], &mut buf).unwrap(), 0);
    drop(sink);
    let _ = std::fs::remove_dir_all(&work);
}

/// Members 0 and 1 are decoded into their partials, every handle is dropped, and member 2 starts from the
/// serialized carry in a "new process": its window comes from the durable output of members 0 and 1.
#[test]
fn a_member_resumes_from_a_carry_over_durable_earlier_members() {
    for encrypted in [false, true] {
        let s = rar5_solid(33, encrypted);
        let work = work_dir(if encrypted { "aes" } else { "plain" });
        let mut source = ArticleBuffer::new(usize::MAX);
        source.insert(0, 0, &s.bytes).unwrap();
        let carry_bytes = {
            let parts = direct(&work, s.password);
            let mut sink = SolidStreamSink::open(&parts, &s.map, 0).unwrap();
            let mut d0 = FeedDecoder::new(&s.map, 0, options(&s)).unwrap();
            let (st, _) = drive(&mut d0, &mut source, &mut sink);
            assert!(st.done && st.crc_ok == Some(true), "{st:?}");
            sink.commit().unwrap();
            sink.next_member(&parts, &s.map, 1).unwrap();
            assert_eq!(sink.stream_start(), s.starts[1]);
            let mut d1 = d0.next_solid(&s.map, 1, options(&s)).unwrap();
            let (st, _) = drive(&mut d1, &mut source, &mut sink);
            assert!(st.done && st.crc_ok == Some(true), "{st:?}");
            sink.commit().unwrap();
            d1.solid_carry().expect("member 1 finished").to_bytes()
            // every handle dropped here
        };
        let parts = direct(&work, s.password);
        let mut sink2 = SolidStreamSink::open(&parts, &s.map, 2).unwrap();
        let carry = SolidCarry::from_bytes(&carry_bytes).unwrap();
        let mut d2 = FeedDecoder::resume_solid(&s.map, 2, options(&s), &carry).unwrap();
        let (st, earlier) = drive(&mut d2, &mut source, &mut sink2);
        assert!(st.done && st.crc_ok == Some(true) && !st.unproven, "{st:?}");
        assert!(earlier > 0, "the window came from the earlier members' output");
        assert_eq!(d2.stats().redecoded, 0, "{:?}", d2.stats());
        assert_eq!(d2.stats().written, s.plains[2].len() as u64);
        let mut files = sink2.into_files();
        for (i, f) in files.iter().enumerate() {
            assert_eq!(member_bytes(f), s.plains[i], "member {i}");
        }
        let mut last = files.pop().unwrap();
        assert!(matches!(verify(&mut last), Verdict::Ok { .. }));
        let _ = std::fs::remove_dir_all(&work);
    }
}

/// Inserts every article of `bytes` (one volume) except those overlapping `hole`, which are marked lost.
fn insert_except(source: &mut ArticleBuffer, bytes: &[u8], hole: std::ops::Range<u64>, size: usize) {
    for (i, c) in bytes.chunks(size).enumerate() {
        let at = (i * size) as u64;
        if at < hole.end && hole.start < at + c.len() as u64 {
            source.mark_lost(0, at..at + c.len() as u64);
        } else {
            source.insert(0, at, c).unwrap();
        }
    }
}

/// Member 1 skipped a hole (its output past it held from elsewhere: here already in its partial); member 2 starts
/// from member 1's carry after a restart and is unproven until its own CRC matches; member 1's repair, also after
/// the restart, completes it from its own saved cursor.
#[test]
fn a_hole_in_an_earlier_member_leaves_the_successor_unproven_until_proven() {
    for encrypted in [false, true] {
        let s = rar5_solid(34, encrypted);
        let work = work_dir(if encrypted { "hole-aes" } else { "hole-plain" });
        let p = &s.map.members[1].pieces[0].packed;
        let mid = p.start + (p.end - p.start) / 2;
        let hole = mid - 1_500..mid + 1_500;
        let mut source = ArticleBuffer::new(usize::MAX);
        insert_except(&mut source, &s.bytes, hole.clone(), 3_000);
        let carry_bytes = {
            let parts = direct(&work, s.password);
            let mut sink = SolidStreamSink::open(&parts, &s.map, 0).unwrap();
            let mut d0 = FeedDecoder::new(&s.map, 0, options(&s)).unwrap();
            let (st, _) = drive(&mut d0, &mut source, &mut sink);
            assert!(st.done && st.crc_ok == Some(true), "{st:?}");
            sink.commit().unwrap();
            sink.next_member(&parts, &s.map, 1).unwrap();
            // the plaintext of member 1 known from another copy
            sink.current_mut().file_mut().fill(0, &s.plains[1]).unwrap();
            let mut d1 = d0.next_solid(&s.map, 1, options(&s)).unwrap();
            let (st, _) = drive(&mut d1, &mut source, &mut sink);
            assert_eq!(st.frontier, s.plains[1].len() as u64, "{st:?}");
            assert!(!st.lost.is_empty() && st.unproven && !st.done, "member 1 skipped its hole: {st:?}");
            sink.commit().unwrap();
            d1.solid_carry().expect("member 1's main decode finished").to_bytes()
        };
        // after the restart
        let parts = direct(&work, s.password);
        let carry = SolidCarry::from_bytes(&carry_bytes).unwrap();
        assert!(carry.unproven());
        let mut sink2 = SolidStreamSink::open(&parts, &s.map, 2).unwrap();
        let mut d2 = FeedDecoder::resume_solid(&s.map, 2, options(&s), &carry).unwrap();
        assert!(d2.status().unproven, "member 2 starts from a window holding unproven output");
        let (st, earlier) = drive(&mut d2, &mut source, &mut sink2);
        assert!(earlier > 0);
        assert!(st.done && st.crc_ok == Some(true), "{st:?}");
        assert_eq!(d2.stats().redecoded, 0);
        // member 1's repair arrives: its own cursor restores it, the sink carries its earlier member too
        drop(sink2);
        let mut sink1 = SolidStreamSink::open(&parts, &s.map, 1).unwrap();
        let cursor = sink1.current().file().cursor().unwrap().expect("member 1's cursor");
        let mut d1 = FeedDecoder::restore(&s.map, 1, options(&s), &FeedSnapshot::from_bytes(&cursor).unwrap()).unwrap();
        // every article, lost ones included
        for (i, c) in s.bytes.chunks(3_000).enumerate() {
            let _ = source.insert(0, (i * 3_000) as u64, c);
        }
        let (st, _) = drive(&mut d1, &mut source, &mut sink1);
        assert!(st.done && st.crc_ok == Some(true) && st.lost.is_empty(), "{st:?}");
        let mut files = sink1.into_files();
        let mut f1 = files.pop().unwrap();
        assert_eq!(member_bytes(&f1), s.plains[1]);
        assert!(matches!(verify(&mut f1), Verdict::Ok { .. }));
        let _ = std::fs::remove_dir_all(&work);
    }
}
