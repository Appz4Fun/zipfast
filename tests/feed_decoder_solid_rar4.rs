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

//! The feed decoder over solid RAR 4.x streams (the solid fixtures under `tests/fixtures/rar4*`): each member after
//! the first goes on from the decoder the member before left (window, tables, PPMd model), fed as shuffled articles
//! with holes; a successor restored from a snapshot decodes the stream again from its start.

use std::path::{Path, PathBuf};
use zipfast::map::*;

const PASSWORDS: [Option<&str>; 4] = [None, Some("password"), Some("junrar"), Some("testpw123")];

fn sets(dir: &Path) -> Vec<Vec<PathBuf>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.to_ascii_lowercase().ends_with(".rar"))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let lower = name.to_ascii_lowercase();
        let stem = &name[..name.len() - 4];
        let mut vols = vec![dir.join(&name)];
        if let Some(i) = lower.rfind(".part") {
            let digits = &lower[i + 5..lower.len() - 4];
            if digits.trim_start_matches('0') != "1" {
                continue;
            }
            for k in 2.. {
                let next = format!("{}.part{:0width$}.rar", &name[..i], k, width = digits.len());
                if !dir.join(&next).exists() {
                    break;
                }
                vols.push(dir.join(next));
            }
        } else {
            for k in 0.. {
                let next = dir.join(format!("{stem}.r{k:02}"));
                if !next.exists() {
                    break;
                }
                vols.push(next);
            }
        }
        out.push(vols);
    }
    out
}

struct Out {
    bytes: Vec<u8>,
    seen: Vec<bool>,
    written: u64,
}

impl Out {
    fn new(n: usize) -> Self {
        Out { bytes: vec![0; n], seen: vec![false; n], written: 0 }
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

/// The solid streams of a map: runs of compressed members, a member without the solid flag and the solid ones
/// after it (directories and stored members pass by).
fn streams(map: &MemberMap) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = Vec::new();
    for (i, m) in map.members.iter().enumerate() {
        if m.is_dir || !matches!(m.method, MapMethod::Compressed { .. }) {
            continue;
        }
        match out.last_mut() {
            Some(s) if m.solid => s.push(i),
            _ => out.push(vec![i]),
        }
    }
    out.retain(|s| s.len() >= 2);
    out
}

/// A member decoded on its own (a successor decodes the stream again first), everything held.
fn reference(map: &MemberMap, i: usize, vols: &[Vec<u8>], password: Option<&str>) -> Option<Vec<u8>> {
    let mut d = FeedDecoder::new(map, i, FeedOptions::new(password)).ok()?;
    let mut out = Out::new(d.size() as usize);
    let mut source = ArticleBuffer::new(usize::MAX);
    for (v, b) in vols.iter().enumerate() {
        source.insert(v as u32, 0, b).unwrap();
    }
    let s = d.run(&mut source, &mut out).ok()?;
    (s.done && s.crc_ok == Some(true)).then_some(out.bytes)
}

struct Chain<'a> {
    map: &'a MemberMap,
    stream: &'a [usize],
    password: Option<&'a str>,
    decoders: Vec<Option<FeedDecoder>>,
    outs: Vec<Out>,
    /// a member waited at a hole while the next had not started
    held_back: bool,
}

impl Chain<'_> {
    fn options(&self) -> FeedOptions {
        FeedOptions { max_needs: usize::MAX, read_chunk: 64, ..FeedOptions::new(self.password) }
    }

    fn step(&mut self, source: &mut ArticleBuffer) {
        let options = self.options();
        let n = self.stream.len();
        for k in 0..n {
            let waiting_next = k + 1 < n && self.decoders[k + 1].is_none();
            let Some(d) = self.decoders[k].as_mut() else { continue };
            let s = d.run(source, &mut self.outs[k]).unwrap();
            if s.stalled && waiting_next {
                self.held_back = true;
            }
            if waiting_next && s.done {
                let next = d.next_solid(self.map, self.stream[k + 1], options.clone()).unwrap();
                assert!(!next.status().unproven);
                self.decoders[k + 1] = Some(next);
            }
        }
    }
}

#[test]
fn solid_rar4_streams_hand_over_member_to_member() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut fed = 0;
    let mut members = 0;
    let mut restores = 0;
    for dir in ["rar4", "rar4-legacy", "rar4-rar300", "rar4-archiver", "rar4-volumes"] {
        let Ok(_) = std::fs::read_dir(root.join(dir)) else { continue };
        for set in sets(&root.join(dir)) {
            let vols: Vec<Vec<u8>> = set.iter().map(|p| std::fs::read(p).unwrap()).collect();
            let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
            let first = set[0].file_name().unwrap();
            for password in PASSWORDS {
                let Ok(map) = MemberMap::from_memory(&refs, first, password) else { continue };
                if map.format != MapFormat::Rar4 {
                    break;
                }
                let mut any = false;
                for stream in streams(&map) {
                    let plains: Option<Vec<Vec<u8>>> =
                        stream.iter().map(|&i| reference(&map, i, &vols, password)).collect();
                    let Some(plains) = plains else { continue };
                    any = true;
                    let packed: u64 = stream.iter().map(|&i| map.members[i].packed_size).sum();
                    for (size, every) in [(97usize, 5usize), ((packed as usize).div_ceil(8).max(16), 3)] {
                        restores += usize::from(feed(&map, &stream, &vols, password, &plains, size, every));
                    }
                    eprintln!("{dir}/{}: stream of {} members fed", first.to_string_lossy(), stream.len());
                    fed += 1;
                    members += stream.len();
                }
                if any {
                    break;
                }
            }
        }
    }
    eprintln!("{fed} solid streams, {members} members, {restores} successors restored mid-stream");
    assert!(fed >= 4, "{fed} streams");
    assert!(restores >= 2, "{restores} restores");
}

/// Feeds a stream's members from shuffled articles, every `every`th missing until the rest are in, each member
/// handed the decoder of the one before; half way through the missing ones the last started successor is restored
/// from a snapshot (decoding the stream again from its start). Whether one was.
fn feed(
    map: &MemberMap,
    stream: &[usize],
    vols: &[Vec<u8>],
    password: Option<&str>,
    plains: &[Vec<u8>],
    size: usize,
    every: usize,
) -> bool {
    let mut all: Vec<Article> = Vec::new();
    for (v, bytes) in vols.iter().enumerate() {
        for (k, chunk) in bytes.chunks(size).enumerate() {
            all.push((v as u32, (k * size) as u64, chunk.to_vec()));
        }
    }
    shuffle(&mut all, 0x501D ^ size as u64);
    let (missing, present): (Vec<_>, Vec<_>) = all.into_iter().enumerate().partition(|(k, _)| k % every == 1);
    let mut source = ArticleBuffer::new(usize::MAX);
    for (_, (v, off, b)) in &missing {
        source.mark_lost(*v, *off..*off + b.len() as u64);
    }
    let first = FeedDecoder::new(map, stream[0], FeedOptions { read_chunk: 64, ..FeedOptions::new(password) }).unwrap();
    let mut chain = Chain {
        map,
        stream,
        password,
        decoders: std::iter::once(Some(first)).chain(std::iter::repeat_with(|| None)).take(stream.len()).collect(),
        outs: plains.iter().map(|p| Out::new(p.len())).collect(),
        held_back: false,
    };
    for (_, (v, off, b)) in &present {
        source.insert(*v, *off, b).unwrap();
        chain.step(&mut source);
    }
    let started = chain.decoders.iter().filter(|d| d.is_some()).count();
    // a member waiting at a hole holds back every member after it
    if started < stream.len() {
        assert!(chain.held_back);
    }
    let half = missing.len() / 2;
    let mut restore_cost = 0;
    for (k, (_, (v, off, b))) in missing.iter().enumerate() {
        if k == half
            && let Some(last) = (1..stream.len()).rev().find(|&j| chain.decoders[j].is_some())
        {
            let d = chain.decoders[last].as_ref().unwrap();
            let frontier = d.status().frontier;
            let before = d.stats().redecoded;
            let snap = FeedSnapshot::from_bytes(&d.snapshot().to_bytes()).unwrap();
            let restored = FeedDecoder::restore(map, stream[last], chain.options(), &snap).unwrap();
            // the stream's earlier members and the member up to the frontier are decoded again, nothing else
            restore_cost = restored.stream_start() + frontier;
            assert_eq!(restored.stats().redecoded, before);
            chain.decoders[last] = Some(restored);
            // the bytes passed were released: the caller gives them again when asked
            for (_, (v, off, b)) in present.iter().chain(&missing[..k]) {
                source.insert(*v, *off, b).unwrap();
            }
        }
        source.insert(*v, *off, b).unwrap();
        chain.step(&mut source);
    }
    for _ in 0..stream.len() {
        chain.step(&mut source);
    }
    let mut redecoded = 0;
    for (j, d) in chain.decoders.iter().enumerate() {
        let d = d.as_ref().unwrap_or_else(|| panic!("member {j} never started"));
        let s = d.status();
        assert!(s.done && s.crc_ok == Some(true), "member {j}: {s:?}");
        assert_eq!(chain.outs[j].bytes, plains[j], "member {j}");
        assert_eq!(chain.outs[j].written, plains[j].len() as u64, "each byte written once");
        redecoded += d.stats().redecoded;
    }
    assert!(redecoded <= restore_cost, "{redecoded} > {restore_cost}");
    restore_cost > 0
}

/// A hand-off that fails on the successor's own setup (a window limit) keeps the decoder: the next attempt still
/// goes on from it.
#[test]
fn a_failed_rar4_hand_off_keeps_the_decoder() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4");
    let bytes = std::fs::read(root.join("solid.rar")).unwrap();
    let map = MemberMap::from_memory(&[&bytes], "solid.rar", None).unwrap();
    let stream = streams(&map).into_iter().next().expect("a solid stream");
    let plain = reference(&map, stream[1], std::slice::from_ref(&bytes), None).expect("it decodes");
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &bytes).unwrap();
    let mut d0 = FeedDecoder::new(&map, stream[0], FeedOptions::default()).unwrap();
    let mut out0 = Out::new(d0.size() as usize);
    assert!(d0.run(&mut source, &mut out0).unwrap().done);
    let small = FeedOptions { max_window: 1 << 10, ..FeedOptions::default() };
    assert!(matches!(
        d0.next_solid(&map, stream[1], small),
        Err(FeedError::Unsupported(FeedUnsupported::Window { .. }))
    ));
    let mut d1 = d0.next_solid(&map, stream[1], FeedOptions::default()).unwrap();
    let mut out1 = Out::new(plain.len());
    let s = d1.run(&mut source, &mut out1).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert_eq!(out1.bytes, plain);
    // handed the decoder: nothing before the member decoded again
    assert_eq!(d1.stats().redecoded, 0);
}

/// Rewrites a RAR 3.x archive as `rar -p` would have written it: each file header gains a salt and the encryption
/// flag, and each member's packed data is padded to whole AES blocks and encrypted with the keys for `password` and
/// that salt.
fn encrypt_rar4(archive: &[u8], password: &str, salt: [u8; 8]) -> Vec<u8> {
    let (key, iv) = zipfast::crypto::derive_rar4_key_iv(password, &salt);
    let mut out = archive[..7].to_vec();
    let mut at = 7;
    while at + 7 <= archive.len() {
        let kind = archive[at + 2];
        let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
        let mut header = archive[at..at + size].to_vec();
        let data_len = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        let mut data = archive[at + size..at + size + data_len].to_vec();
        if kind == 0x74 {
            assert_eq!(flags & 0x100, 0, "no high sizes in these fixtures");
            let name_len = usize::from(u16::from_le_bytes([header[26], header[27]]));
            header.splice(32 + name_len..32 + name_len, salt);
            header[3..5].copy_from_slice(&(flags | 0x404).to_le_bytes());
            header[5..7].copy_from_slice(&((size + 8) as u16).to_le_bytes());
            data.resize(data.len().next_multiple_of(16), 0);
            data = zipfast::crypto::encrypt_cbc(&key, &iv, &data).unwrap();
            header[7..11].copy_from_slice(&(data.len() as u32).to_le_bytes());
            let crc = crc32fast::hash(&header[2..]) as u16;
            header[..2].copy_from_slice(&crc.to_le_bytes());
        }
        out.extend(header);
        out.extend(data);
        at += size + data_len;
    }
    out
}

/// One key-derivation budget covers every key a decoder derives: a successor decoding two encrypted earlier members
/// again derives three keys, which a session budget of two and a half refuses (each alone fits).
#[test]
fn a_successor_charges_every_key_it_derives_to_one_budget() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-rar300");
    let plain = std::fs::read(root.join("solid_rar300.rar")).unwrap();
    let bytes = encrypt_rar4(&plain, "secret", *b"saltsalt");
    let map = MemberMap::from_memory(&[&bytes], "solid_rar300.rar", Some("secret")).unwrap();
    let stream = streams(&map).into_iter().next().expect("a solid stream");
    assert_eq!(stream.len(), 3);
    assert!(stream.iter().all(|&i| map.members[i].encrypted));
    let last = *stream.last().unwrap();
    // decodes with the default budget
    assert!(reference(&map, last, std::slice::from_ref(&bytes), Some("secret")).is_some());
    // a RAR 3.x key ("secret", 8-byte salt) costs about 94,000 blocks
    let limited = || {
        let mut o = FeedOptions::new(Some("secret"));
        o.limits.kdf_session_blocks = 250_000;
        o
    };
    assert!(FeedDecoder::new(&map, stream[0], limited()).is_ok());
    assert!(matches!(FeedDecoder::new(&map, last, limited()), Err(FeedError::Key(_))));
}

/// A handed-over decoder answers to the new member's session control: canceling the earlier member's after the
/// hand-off leaves the new one running.
#[test]
fn a_handed_over_rar4_decoder_follows_the_new_members_control() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-rar300");
    let bytes = std::fs::read(root.join("solid_rar300.rar")).unwrap();
    let map = MemberMap::from_memory(&[&bytes], "solid_rar300.rar", None).unwrap();
    let stream = streams(&map).into_iter().next().expect("a solid stream");
    let last = *stream.last().unwrap();
    let plain = reference(&map, last, std::slice::from_ref(&bytes), None).expect("it decodes");
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &bytes).unwrap();
    let first = FeedOptions::default();
    let mut controls = vec![first.control.clone()];
    let mut d = FeedDecoder::new(&map, stream[0], first).unwrap();
    for &i in &stream[1..] {
        assert!(d.run(&mut source, &mut Out::new(d.size() as usize)).unwrap().done);
        let options = FeedOptions::default();
        controls.push(options.control.clone());
        d = d.next_solid(&map, i, options).unwrap();
    }
    // every earlier member's control: the decoder was started under the first one's
    for c in &controls[..controls.len() - 1] {
        c.cancel();
    }
    let mut out = Out::new(plain.len());
    let s = d.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert_eq!(out.bytes, plain);
}

/// A hand-off to another archive's member at the same place (here the same stream rewritten with a password) is
/// refused, and the decoder stays for the right one.
#[test]
fn a_rar4_hand_off_into_another_archive_is_refused() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-rar300");
    let bytes = std::fs::read(root.join("solid_rar300.rar")).unwrap();
    let other = encrypt_rar4(&bytes, "secret", *b"saltsalt");
    let map = MemberMap::from_memory(&[&bytes], "solid_rar300.rar", None).unwrap();
    let other_map = MemberMap::from_memory(&[&other], "solid_rar300.rar", Some("secret")).unwrap();
    let stream = streams(&map).into_iter().next().expect("a solid stream");
    assert_eq!(streams(&other_map).into_iter().next(), Some(stream.clone()));
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &bytes).unwrap();
    let mut d0 = FeedDecoder::new(&map, stream[0], FeedOptions::default()).unwrap();
    assert!(d0.run(&mut source, &mut Out::new(d0.size() as usize)).unwrap().done);
    assert!(matches!(
        d0.next_solid(&other_map, stream[1], FeedOptions::new(Some("secret"))),
        Err(FeedError::Handoff(_))
    ));
    let plain = reference(&map, stream[1], std::slice::from_ref(&bytes), None).expect("it decodes");
    let mut d1 = d0.next_solid(&map, stream[1], FeedOptions::default()).unwrap();
    let mut out = Out::new(plain.len());
    let s = d1.run(&mut source, &mut out).unwrap();
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert_eq!(out.bytes, plain);
    assert_eq!(d1.stats().redecoded, 0);
}

fn solid_fixture(name: &str) -> (Vec<u8>, MemberMap, Vec<usize>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-rar300");
    let bytes = std::fs::read(root.join(name)).unwrap();
    let map = MemberMap::from_memory(&[&bytes], name, None).unwrap();
    let stream = streams(&map).into_iter().next().expect("a solid stream");
    (bytes, map, stream)
}

fn ppmd_solid() -> (Vec<u8>, MemberMap, Vec<usize>) {
    let (bytes, map, stream) = solid_fixture("ppmd_solid_rar300.rar");
    assert_eq!(stream.len(), 2);
    (bytes, map, stream)
}

/// Runs member `i` on its own over the whole archive: its status and output.
fn run_alone(map: &MemberMap, i: usize, bytes: &[u8]) -> Option<(FeedStatus, Vec<u8>)> {
    let mut d = FeedDecoder::new(map, i, FeedOptions::default()).ok()?;
    let mut out = Out::new(d.size() as usize);
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, bytes).unwrap();
    let s = d.run(&mut source, &mut out).ok()?;
    Some((s, out.bytes))
}

/// A standalone successor decoding an earlier member again checks that member's CRC: when it fails, what the
/// successor decodes from that window is unproven, as after a hand-off from the damaged member.
#[test]
fn a_replayed_earlier_member_that_fails_its_crc_makes_the_successor_unproven() {
    let mut checked = 0;
    for name in ["solid_simple_rar300.rar", "solid_rar300.rar", "ppmd_solid_rar300.rar"] {
        let (bytes, map, stream) = solid_fixture(name);
        let last = *stream.last().unwrap();
        // the clean archive: proven
        let (clean, _) = run_alone(&map, last, &bytes).unwrap();
        assert!(clean.done && clean.crc_ok == Some(true) && !clean.unproven, "{clean:?}");
        let packed = map.members[stream[0]].pieces[0].packed.clone();
        for at in (packed.start..packed.end).step_by(1.max((packed.end - packed.start) as usize / 200)) {
            let mut damaged = bytes.clone();
            damaged[at as usize] ^= 0x55;
            let Ok(map) = MemberMap::from_memory(&[&damaged], name, None) else { continue };
            // the earlier member decodes to its size and fails its CRC
            let Some((first, _)) = run_alone(&map, stream[0], &damaged) else { continue };
            if !(first.done && first.crc_ok == Some(false)) {
                continue;
            }
            let Some((s, _)) = run_alone(&map, last, &damaged) else { continue };
            assert!(s.done, "{s:?}");
            if s.crc_ok == Some(true) {
                continue;
            }
            assert!(s.unproven, "{name}: damaged byte {at}: {s:?}");
            checked += 1;
        }
    }
    assert!(checked > 0, "no damaged byte made the earlier member fail only its CRC");
}

/// An earlier member larger than the article buffer's limit still replays: the packed bytes it has consumed are
/// released as the replay goes, so the buffer never fills.
#[test]
fn a_replayed_earlier_member_larger_than_the_buffer_limit_completes() {
    let (bytes, map, stream) = ppmd_solid();
    let (_, plain) = run_alone(&map, stream[1], &bytes).unwrap();
    let limit = 4096;
    assert!(map.members[stream[0]].packed_size > 2 * limit as u64);
    let mut d = FeedDecoder::new(&map, stream[1], FeedOptions { read_chunk: 64, ..FeedOptions::default() }).unwrap();
    let mut out = Out::new(plain.len());
    let mut source = ArticleBuffer::new(limit);
    let mut status = d.status().clone();
    for (k, chunk) in bytes.chunks(512).enumerate() {
        let at = (k * 512) as u64;
        if source.insert(0, at, chunk).is_err() {
            d.run(&mut source, &mut out).unwrap();
            source.insert(0, at, chunk).expect("the replay released what it consumed");
        }
        status = d.run(&mut source, &mut out).unwrap();
    }
    let s = status;
    assert!(s.done && s.crc_ok == Some(true), "{s:?}");
    assert_eq!(out.bytes, plain);
}
