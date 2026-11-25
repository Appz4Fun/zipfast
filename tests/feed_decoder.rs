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

//! The feed-driven decoder (`zipfast::map::FeedDecoder`): articles fed shuffled, some missing and supplied later.
mod common;

use common::{FileSpec, SIG, end_block, file_block, main_block};
use std::io::Cursor;
use std::ops::Range;
use zipfast::map::*;

fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
}

fn data(len: usize, seed: u64) -> Vec<u8> {
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

/// A deterministic shuffle.
fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut x = seed | 1;
    for i in (1..v.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.swap(i, (x % (i as u64 + 1)) as usize);
    }
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

/// The parts of a volume range that hold bytes the member's output needs.
fn data_part(member: &MapMember, volume: u32, range: Range<u64>) -> Vec<Range<u64>> {
    member
        .packed_spans(0..member.unpacked_size.unwrap())
        .unwrap()
        .into_iter()
        .filter(|p| p.volume == volume)
        .filter_map(|p| {
            let (s, e) = (range.start.max(p.packed.start), range.end.min(p.packed.end));
            (s < e).then_some(s..e)
        })
        .collect()
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

const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];

/// One encrypted stored RAR5 member holding `plain`, password "pw", its ciphertext cut at stream offsets `cuts`
/// into volumes.
fn rar5_encrypted(plain: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let size = plain.len();
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
    let mut padded = plain.to_vec();
    padded.resize(size.div_ceil(16) * 16, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &IV, &padded).unwrap();
    let mut extra = vec![36, 1, 0, 2, 1];
    extra.extend(SALT);
    extra.extend(IV);
    let mut spec = FileSpec::new("e.bin", &cipher);
    spec.size = Some(size as u64);
    spec.extra = extra;
    let bounds: Vec<usize> = std::iter::once(0).chain(cuts.iter().copied()).chain([cipher.len()]).collect();
    bounds
        .windows(2)
        .enumerate()
        .map(|(index, pair)| {
            let part = &cipher[pair[0]..pair[1]];
            let last = pair[1] == cipher.len();
            let crc = zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(if last { plain } else { part }), &hash_key);
            let mut bytes = SIG.to_vec();
            bytes.extend(main_block(true, Some(index as u64)));
            bytes.extend(file_block(&spec, part, crc, index > 0, !last));
            bytes.extend(end_block(!last));
            bytes
        })
        .collect()
}

fn winzip_aes(plain: &[u8]) -> Vec<u8> {
    use zipfast::zip::write::*;
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let options = EntryOptions {
        name: EntryName::Utf8("aes.bin"),
        method: Method::Stored,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"",
    };
    let request = WinZipAesRequest::new("pw", AesStrength::Aes256, AesVariant::Ae1).unwrap();
    writer
        .add_winzip_aes_file(
            options,
            &mut Cursor::new(plain),
            InputLength::Exact(plain.len() as u64),
            request,
            |salt| {
                salt.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8 + 1);
                Ok(())
            },
        )
        .unwrap();
    writer.finish().unwrap().sink
}

/// A sink that refuses to write any output byte twice.
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
}

struct Case {
    what: &'static str,
    volumes: Vec<Vec<u8>>,
    name: &'static str,
    password: Option<&'static str>,
    plain: Vec<u8>,
}

fn cases() -> Vec<Case> {
    let plain = data(40_000, 7);
    vec![
        Case {
            what: "rar5 stored, 6 volumes",
            volumes: common::volumes(&FileSpec::new("big.bin", &plain), 7_000),
            name: "x.part1.rar",
            password: None,
            plain: plain.clone(),
        },
        Case {
            what: "rar5 AES stored, 4 volumes",
            volumes: rar5_encrypted(&plain, &[9_001, 20_000, 31_337]),
            name: "e.part1.rar",
            password: Some("pw"),
            plain: plain.clone(),
        },
        Case {
            what: "rar5 AES stored, odd size",
            volumes: rar5_encrypted(&plain[..39_993], &[10_000]),
            name: "e.part1.rar",
            password: Some("pw"),
            plain: plain[..39_993].to_vec(),
        },
        Case {
            what: "WinZip AES stored",
            volumes: vec![winzip_aes(&plain)],
            name: "w.zip",
            password: Some("pw"),
            plain: plain.clone(),
        },
    ]
}

/// Feeds every article but the `missing` ones (marked lost) in shuffled order, running the decoder after each,
/// then checks what it needs; then supplies the missing ones and checks the output. Returns the stats.
fn all_needs(password: Option<&str>) -> FeedOptions {
    FeedOptions { max_needs: usize::MAX, ..FeedOptions::new(password) }
}

fn feed_case(case: &Case, article: usize, missing_every: usize, seed: u64) -> FeedStats {
    let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
    let member = &map.members[0];
    let mut all = articles(&case.volumes, article);
    shuffle(&mut all, seed);
    let (missing, present): (Vec<_>, Vec<_>) =
        all.into_iter().enumerate().partition(|(i, _)| missing_every > 0 && i % missing_every == missing_every / 2);
    let mut decoder = FeedDecoder::new(&map, 0, all_needs(case.password)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    for (_, (v, off, bytes)) in &missing {
        source.mark_lost(*v, *off..*off + bytes.len() as u64);
    }
    let mut sink = Once::default();
    for (_, (v, off, bytes)) in &present {
        source.insert(*v, *off, bytes).unwrap();
        let status = decoder.run(&mut source, &mut sink).unwrap();
        // the main decode never waits behind a hole
        assert!(status.needs.iter().all(|n| n.kind != NeedKind::Next
            || !missing.iter().any(|(_, (mv, mo, mb))| {
                *mv == n.volume && n.range.start < mo + mb.len() as u64 && *mo < n.range.end
            })));
    }
    let status = decoder.status().clone();
    // everything that arrived is decoded; only the missing articles' data is needed, exactly
    let want = merge(
        missing
            .iter()
            .flat_map(|(_, (v, off, b))| {
                data_part(member, *v, *off..*off + b.len() as u64).into_iter().map(|r| (*v, r))
            })
            .collect(),
    );
    let got = merge(status.needs.iter().map(|n| (n.volume, n.range.clone())).collect());
    assert_eq!(got, want, "{}: needs", case.what);
    assert!(status.needs.iter().all(|n| n.kind == NeedKind::Repair), "{}: {:?}", case.what, status.needs);
    assert_eq!(status.done, want.is_empty(), "{}", case.what);
    assert_eq!(status.frontier, case.plain.len() as u64);
    // output outside the lost ranges is there already
    for (i, (&got, &want)) in sink.out.iter().zip(&case.plain).enumerate() {
        if !status.lost.iter().any(|r| r.contains(&(i as u64))) {
            assert_eq!(got, want, "{}: byte {i}", case.what);
        }
    }
    // a snapshot round trip in the middle of the repairs
    let snap = FeedSnapshot::from_bytes(&decoder.snapshot().to_bytes()).unwrap();
    assert_eq!(snap.lost(), status.lost.as_slice());
    let mut decoder = FeedDecoder::restore(&map, 0, all_needs(case.password), &snap).unwrap();
    let mut missing = missing;
    shuffle(&mut missing, seed ^ 0x55);
    for (_, (v, off, bytes)) in &missing {
        source.insert(*v, *off, bytes).unwrap();
        decoder.run(&mut source, &mut sink).unwrap();
    }
    let status = decoder.status().clone();
    assert!(status.done && status.lost.is_empty() && status.needs.is_empty(), "{}: {status:?}", case.what);
    assert_eq!(status.crc_ok, Some(true), "{}", case.what);
    assert_eq!(sink.out, case.plain, "{}", case.what);
    let stats = decoder.stats();
    // nothing written twice (the sink checks), and repairs read only near their holes
    assert_eq!(stats.written, case.plain.len() as u64, "{}", case.what);
    let extra = stats.packed_read - member.packed_size.min(stats.packed_read);
    // under CBC a hole costs at most two blocks read twice on each side (the main decode's IV after it, the repair's
    // IV and partial block before it), again after each partial repair, and once more after the snapshot
    let bound = 64 * (stats.holes + missing.len() as u64) + 16;
    assert!(extra <= bound, "{}: read {extra} bytes more than once over {} holes", case.what, stats.holes);
    stats
}

#[test]
fn shuffled_articles_with_holes_repaired_later() {
    for case in cases() {
        for (article, every, seed) in [(1_000, 5, 1), (777, 4, 2), (4_096, 3, 3), (1_000, 0, 4), (64, 7, 5)] {
            let stats = feed_case(&case, article, every, seed);
            if every > 0 {
                assert!(stats.holes > 0, "{} {article} {every}", case.what);
            }
        }
    }
}

#[test]
fn needs_name_the_next_gap_then_what_is_ahead() {
    let case = &cases()[1];
    let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::new(case.password)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Vec::new();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    // nothing held: the first piece's data is next, the rest ahead
    let p = &map.members[0].pieces;
    assert_eq!(status.needs[0], NeedBytes { volume: 0, range: p[0].packed.clone(), kind: NeedKind::Next });
    assert_eq!(
        status.needs[1..].iter().map(|n| (n.volume, n.range.clone(), n.kind)).collect::<Vec<_>>(),
        p[1..].iter().map(|p| (p.volume, p.packed.clone(), NeedKind::Ahead)).collect::<Vec<_>>()
    );
    // the first volume arrives: the decoder waits at the start of the second piece
    source.insert(0, 0, &case.volumes[0]).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert_eq!(status.needs[0], NeedBytes { volume: 1, range: p[1].packed.clone(), kind: NeedKind::Next });
    // the bytes of a block cut by the volume end wait for the next volume
    assert_eq!(status.frontier, (p[0].packed.end - p[0].packed.start) & !15);
    assert_eq!(status.frontier, sink.len() as u64);
}

#[test]
fn a_hole_under_cbc_loses_its_blocks_and_one_more() {
    let plain = data(10_000, 3);
    let volumes = rar5_encrypted(&plain, &[]);
    let map = MemberMap::from_memory(&refs(&volumes), "e.rar", Some("pw")).unwrap();
    let base = map.members[0].pieces[0].packed.start;
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &volumes[0]).unwrap();
    let hole = 1_000..1_100u64;
    source.release(0, base + hole.start..base + hole.end);
    source.mark_lost(0, base + hole.start..base + hole.end);
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::new(Some("pw"))).unwrap();
    let mut sink = Vec::new();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert_eq!(status.lost, vec![992..1_120]);
    assert_eq!(
        status.needs,
        vec![NeedBytes { volume: 0, range: base + hole.start..base + hole.end, kind: NeedKind::Repair }]
    );
    assert_eq!(status.frontier, 10_000);
    source.insert(0, base + hole.start, &volumes[0][(base + hole.start) as usize..(base + hole.end) as usize]).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert!(status.done && status.crc_ok == Some(true));
    assert_eq!(sink, plain);
}

// Catches the main decode releasing the IV block it holds in memory while it waits inside a partial block: a hole
// met there starts its lost range at that block, and the repair reads the IV block from the source again.
#[test]
fn a_hole_after_a_partial_cbc_block_keeps_the_iv_block_for_its_repair() {
    let plain = data(10_000, 5);
    let volumes = rar5_encrypted(&plain, &[]);
    let map = MemberMap::from_memory(&refs(&volumes), "e.rar", Some("pw")).unwrap();
    let base = map.members[0].pieces[0].packed.start as usize;
    // the first article ends one byte into a block, the second is lost, the rest arrives
    let (cut, cut2) = (base + 4_001, base + 5_001);
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::new(Some("pw"))).unwrap();
    let mut sink = Vec::new();
    source.insert(0, 0, &volumes[0][..cut]).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert_eq!(status.frontier, 4_000);
    source.mark_lost(0, cut as u64..cut2 as u64);
    source.insert(0, cut2 as u64, &volumes[0][cut2..]).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert_eq!(status.lost, vec![4_000..5_024]);
    source.insert(0, cut as u64, &volumes[0][cut..cut2]).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert!(status.done && status.crc_ok == Some(true), "{status:?}");
    assert_eq!(sink, plain);
}

#[test]
fn a_run_budget_interleaves_and_a_snapshot_resumes_the_main_decode() {
    let case = &cases()[1];
    let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
    let mut options = FeedOptions::new(case.password);
    options.run_budget = Some(5_000);
    options.read_chunk = 1_000;
    let mut decoder = FeedDecoder::new(&map, 0, options.clone()).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    for (v, bytes) in case.volumes.iter().enumerate() {
        source.insert(v as u32, 0, bytes).unwrap();
    }
    let mut sink = Once::default();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert!(status.more && !status.done && status.frontier >= 5_000 && status.frontier < 7_000);
    let bytes = decoder.snapshot().to_bytes();
    drop(decoder);
    let mut decoder = FeedDecoder::restore(&map, 0, options, &FeedSnapshot::from_bytes(&bytes).unwrap()).unwrap();
    let mut runs = 1;
    while !decoder.run(&mut source, &mut sink).unwrap().done {
        runs += 1;
    }
    assert!(runs >= 6, "{runs}");
    assert_eq!(decoder.status().crc_ok, Some(true));
    assert_eq!(sink.out, case.plain);
    assert_eq!(decoder.stats().written, case.plain.len() as u64);
}

#[test]
fn bytes_the_decoder_passed_are_released() {
    let case = &cases()[0];
    let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Vec::new();
    let mut peak = 0;
    for a in articles(&case.volumes, 1_000) {
        source.insert(a.0, a.1, &a.2).unwrap();
        decoder.run(&mut source, &mut sink).unwrap();
        peak = peak.max(source.held());
    }
    assert!(decoder.status().done);
    assert_eq!(sink, case.plain);
    // in order, only header bytes and the article being read stay held
    assert!(peak < 2_000, "peak {peak}");
}

#[test]
fn refusals_and_failures_are_typed() {
    let plain = data(5_000, 1);
    let volumes = rar5_encrypted(&plain, &[]);
    let map = MemberMap::from_memory(&refs(&volumes), "e.rar", Some("pw")).unwrap();
    assert!(matches!(FeedDecoder::new(&map, 0, FeedOptions::default()), Err(FeedError::PasswordRequired)));
    assert!(matches!(FeedDecoder::new(&map, 3, FeedOptions::default()), Err(FeedError::NoSuchMember { index: 3 })));
    // RAR 5.0 without a check value: a wrong password shows in the CRC
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::new(Some("nope"))).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &volumes[0]).unwrap();
    let status = decoder.run(&mut source, &mut Vec::new()).unwrap();
    assert_eq!((status.done, status.crc_ok), (true, Some(false)));
    // WinZip AES checks its verifier
    let zip = vec![winzip_aes(&plain)];
    let map = MemberMap::from_memory(&refs(&zip), "w.zip", None).unwrap();
    assert!(matches!(FeedDecoder::new(&map, 0, FeedOptions::new(Some("nope"))), Err(FeedError::WrongPassword)));
    // cancellation
    let options = FeedOptions::new(Some("pw"));
    let mut decoder =
        FeedDecoder::restore(&map, 0, options.clone(), &FeedDecoder::new(&map, 0, options.clone()).unwrap().snapshot())
            .unwrap();
    options.control.cancel();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &zip[0]).unwrap();
    assert!(matches!(decoder.run(&mut source, &mut Vec::new()), Err(FeedError::Canceled)));
    assert!(matches!(decoder.run(&mut source, &mut Vec::new()), Err(FeedError::AlreadyFailed)));
    // a snapshot of another member is refused
    let other = vec![winzip_aes(&plain[..4_000])];
    let other_map = MemberMap::from_memory(&refs(&other), "w.zip", None).unwrap();
    let snap = FeedDecoder::new(&other_map, 0, FeedOptions::new(Some("pw"))).unwrap().snapshot();
    assert!(matches!(FeedDecoder::restore(&map, 0, FeedOptions::new(Some("pw")), &snap), Err(FeedError::Snapshot(_))));
    assert!(matches!(FeedSnapshot::from_bytes(b"ZFFD\x01"), Err(FeedError::Snapshot(_))));
}

#[test]
fn bytes_past_an_early_hole_are_released_too() {
    let case = &cases()[1];
    let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::new(case.password)).unwrap();
    // a buffer of three articles: the decode must let go of what it passed, also past the hole
    let mut source = ArticleBuffer::new(3_000);
    let mut sink = Once::default();
    let all = articles(&case.volumes, 1_000);
    let (lost_v, lost_off, lost_bytes) = all[3].clone();
    source.mark_lost(lost_v, lost_off..lost_off + 1_000);
    for (i, a) in all.iter().enumerate() {
        if i != 3 {
            source.insert(a.0, a.1, &a.2).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
    }
    let status = decoder.status().clone();
    assert_eq!(status.lost.len(), 1);
    source.insert(lost_v, lost_off, &lost_bytes).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert!(status.done && status.crc_ok == Some(true));
    assert_eq!(sink.out, case.plain);
}

#[test]
fn snapshots_bind_to_their_member_and_empty_keyed_members_verify() {
    let (a, b) = (data(3_000, 1), data(3_000, 2));
    let bytes = common::archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", &b)]);
    let map = MemberMap::from_memory(&[&bytes], "two.rar", None).unwrap();
    let snap = FeedDecoder::new(&map, 1, FeedOptions::default()).unwrap().snapshot();
    assert!(matches!(FeedDecoder::restore(&map, 0, FeedOptions::default(), &snap), Err(FeedError::Snapshot(_))));
    assert!(FeedDecoder::restore(&map, 1, FeedOptions::default(), &snap).is_ok());
    // an empty AES member whose CRC is keyed with the password
    let empty = rar5_encrypted(&[], &[]);
    let map = MemberMap::from_memory(&refs(&empty), "e.rar", Some("pw")).unwrap();
    let decoder = FeedDecoder::new(&map, 0, FeedOptions::new(Some("pw"))).unwrap();
    assert_eq!((decoder.status().done, decoder.status().crc_ok), (true, Some(true)));
}
// ---- Compressed RAR 5.0 ----

/// Literal-rich content (random runs and repeats of them), as video is: the restart search pins blocks by their
/// literals.
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

/// One compressed (method 3) RAR 5.0 member holding `plain`, AES-encrypted with password "pw" when `encrypted`,
/// cut into volumes of at most `chunk` packed bytes.
fn rar5_compressed(plain: &[u8], encrypted: bool, chunk: usize) -> Vec<Vec<u8>> {
    use zipfast::rar5::testenc;
    let mut data = testenc::tuned_stream(&testenc::lz(plain, 1 << 17, 16), 2_000);
    let mut crc = crc32fast::hash(plain);
    let mut extra = Vec::new();
    if encrypted {
        let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
        data.resize(data.len().div_ceil(16) * 16, 0);
        data = zipfast::crypto::encrypt_cbc(&key, &IV, &data).unwrap();
        extra = vec![36, 1, 0, 2, 1];
        extra.extend(SALT);
        extra.extend(IV);
        crc = zipfast::crypto::rar5_tweak_crc32(crc, &hash_key);
    }
    let mut spec = FileSpec::new("c.bin", &data);
    spec.method = 3;
    spec.size = Some(plain.len() as u64);
    spec.extra = extra;
    let parts: Vec<&[u8]> = data.chunks(chunk).collect();
    let n = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let last = i + 1 == n;
            let mut bytes = SIG.to_vec();
            bytes.extend(main_block(true, if i == 0 { None } else { Some(i as u64) }));
            let part_crc = if last {
                crc
            } else if encrypted {
                let (_, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
                zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(part), &hash_key)
            } else {
                crc32fast::hash(part)
            };
            bytes.extend(file_block(&spec, part, part_crc, i > 0, !last));
            bytes.extend(end_block(!last));
            bytes
        })
        .collect()
}

/// A sink that writes each byte once, reads back what it wrote, and holds a donor: plaintext known from another
/// copy, read back where nothing was written.
#[derive(Default)]
struct Held {
    out: Vec<u8>,
    seen: Vec<bool>,
    donor: Vec<u8>,
    /// bytes given back by `read_held`
    read_back: u64,
}

impl FeedSink for Held {
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
        self.read_back += n as u64;
        Ok(n)
    }
}

/// An article: volume, offset and bytes.
type Article = (u32, u64, Vec<u8>);

struct Feed {
    map: MemberMap,
    plain: Vec<u8>,
    password: Option<&'static str>,
    present: Vec<Article>,
    missing: Vec<Article>,
}

fn compressed_feed(encrypted: bool, missing_every: usize, seed: u64) -> (Feed, Vec<Vec<u8>>) {
    let plain = video_like(600_000, seed);
    let volumes = rar5_compressed(&plain, encrypted, 150_000);
    let password = encrypted.then_some("pw");
    let map = MemberMap::from_memory(&refs(&volumes), "c.part1.rar", password).unwrap();
    assert!(matches!(map.members[0].method, MapMethod::Compressed { .. }));
    let mut all = articles(&volumes, 7_000);
    shuffle(&mut all, seed);
    let (missing, present): (Vec<_>, Vec<_>) =
        all.into_iter().enumerate().partition(|(i, _)| missing_every > 0 && i % missing_every == missing_every / 2);
    let strip = |v: Vec<(usize, Article)>| v.into_iter().map(|(_, a)| a).collect();
    (Feed { map, plain, password, present: strip(present), missing: strip(missing) }, volumes)
}

fn missing_data(feed: &Feed) -> Vec<(u32, Range<u64>)> {
    let m = &feed.map.members[0];
    merge(
        feed.missing
            .iter()
            .flat_map(|(v, off, b)| {
                m.pieces.iter().filter(move |p| p.volume == *v).filter_map(move |p| {
                    let (s, e) = ((*off).max(p.packed.start), (off + b.len() as u64).min(p.packed.end));
                    (s < e).then_some((*v, s..e))
                })
            })
            .collect(),
    )
}

fn within(needs: &[NeedBytes], ranges: &[(u32, Range<u64>)]) -> bool {
    needs.iter().all(|n| ranges.iter().any(|(v, r)| *v == n.volume && r.start <= n.range.start && n.range.end <= r.end))
}

#[test]
fn compressed_without_held_output_waits_at_holes_and_never_decodes_twice() {
    for encrypted in [false, true] {
        let (feed, _) = compressed_feed(encrypted, 6, 11);
        let mut decoder = FeedDecoder::new(&feed.map, 0, all_needs(feed.password)).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        for (v, off, b) in &feed.missing {
            source.mark_lost(*v, *off..*off + b.len() as u64);
        }
        let mut sink = Held::default();
        for (v, off, b) in &feed.present {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        let status = decoder.status().clone();
        let holes = missing_data(&feed);
        assert!(status.stalled && !status.done, "{status:?}");
        assert_eq!(status.needs[0].kind, NeedKind::Next);
        // the hole it waits at is the first missing article after the frontier, exactly
        assert!(holes.iter().any(|(v, r)| *v == status.needs[0].volume && *r == status.needs[0].range), "{status:?}");
        assert!(within(&status.needs[..1], &holes));
        assert!(status.lost.is_empty());
        assert_eq!(sink.out, feed.plain[..status.frontier as usize]);
        for (v, off, b) in &feed.missing {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        let status = decoder.status().clone();
        assert!(status.done && status.crc_ok == Some(true), "{status:?}");
        assert_eq!(sink.out, feed.plain);
        let stats = decoder.stats();
        assert_eq!((stats.written, stats.redecoded), (feed.plain.len() as u64, 0));
    }
}

#[test]
fn compressed_holes_are_skipped_with_held_output_and_repaired_from_a_checkpoint() {
    for encrypted in [false, true] {
        let (feed, _) = compressed_feed(encrypted, 9, 12);
        let mut decoder = FeedDecoder::new(&feed.map, 0, all_needs(feed.password)).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        for (v, off, b) in &feed.missing {
            source.mark_lost(*v, *off..*off + b.len() as u64);
        }
        // another copy's output is held (a twin), but only where nothing is written: every byte written comes from
        // this copy's packed bytes
        let from = 0;
        let mut sink = Held { donor: vec![0; from], ..Held::default() };
        sink.donor.extend_from_slice(&feed.plain[from..]);
        for (v, off, b) in &feed.present {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        let status = decoder.status().clone();
        let holes = missing_data(&feed);
        // the main decode got past every hole it met after the held output starts
        assert!(decoder.stats().holes > 0, "{status:?}");
        assert!(!status.lost.is_empty());
        assert!(status.lost.iter().all(|r| r.start as usize >= from), "{:?}", status.lost);
        assert!(within(&status.needs, &holes), "{:?} vs {holes:?}", status.needs);
        for (i, w) in sink.seen.iter().enumerate() {
            if *w {
                assert_eq!(sink.out[i], feed.plain[i], "byte {i}");
            }
        }
        for (v, off, b) in &feed.missing {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        let status = decoder.status().clone();
        assert!(status.done && status.crc_ok == Some(true), "{status:?}");
        assert!(sink.seen.iter().all(|s| *s));
        assert_eq!(sink.out, feed.plain);
        let stats = decoder.stats();
        assert_eq!(stats.written, feed.plain.len() as u64);
        // repairs re-decode from the checkpoint before each hole, not from the start
        assert!(stats.redecoded < feed.plain.len() as u64 / 4, "{stats:?}");
        eprintln!("encrypted {encrypted}: {stats:?}");
    }
}

#[test]
fn a_compressed_snapshot_resumes_from_its_checkpoint() {
    for encrypted in [false, true] {
        let plain = video_like(600_000, 13);
        let volumes = rar5_compressed(&plain, encrypted, 1 << 20);
        let password = encrypted.then_some("pw");
        let map = MemberMap::from_memory(&refs(&volumes), "c.rar", password).unwrap();
        let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::new(password)).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        let mut sink = Held::default();
        let cut = volumes[0].len() * 3 / 5;
        source.insert(0, 0, &volumes[0][..cut]).unwrap();
        let status = decoder.run(&mut source, &mut sink).unwrap();
        assert!(status.frontier > 0 && !status.done);
        let bytes = decoder.snapshot().to_bytes();
        drop(decoder);
        let snap = FeedSnapshot::from_bytes(&bytes).unwrap();
        let mut decoder = FeedDecoder::restore(&map, 0, FeedOptions::new(password), &snap).unwrap();
        assert_eq!(decoder.status().frontier, status.frontier);
        source.insert(0, cut as u64, &volumes[0][cut..]).unwrap();
        let done = decoder.run(&mut source, &mut sink).unwrap();
        assert!(done.done && done.crc_ok == Some(true), "{done:?}");
        assert_eq!(sink.out, plain);
        let stats = decoder.stats();
        assert_eq!(stats.written, plain.len() as u64);
        // only the output since the last block boundary before the snapshot was decoded again
        assert!(stats.redecoded < 64 << 10, "{stats:?}");
        // without held output a compressed restore cannot rebuild its window
        let mut decoder = FeedDecoder::restore(&map, 0, FeedOptions::new(password), &snap).unwrap();
        assert!(matches!(decoder.run(&mut source, &mut Vec::new()), Err(FeedError::HeldOutput { .. })));
    }
}

#[test]
fn a_skipped_compressed_hole_does_not_pin_the_bytes_after_its_restart() {
    let plain = video_like(600_000, 14);
    let volumes = rar5_compressed(&plain, false, 1 << 20);
    let map = MemberMap::from_memory(&refs(&volumes), "c.rar", None).unwrap();
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
    // room for about fifteen articles: the decode has to let go of what it passed, past the skipped hole too
    let mut source = ArticleBuffer::new(100_000);
    let mut sink = Held { donor: plain.clone(), ..Held::default() };
    let all = articles(&volumes, 7_000);
    let hole = 10;
    source.mark_lost(all[hole].0, all[hole].1..all[hole].1 + all[hole].2.len() as u64);
    for (i, (v, off, b)) in all.iter().enumerate() {
        if i != hole {
            source.insert(*v, *off, b).unwrap_or_else(|e| panic!("article {i}: {e}"));
            decoder.run(&mut source, &mut sink).unwrap();
        }
    }
    let status = decoder.status().clone();
    assert!(status.frontier == plain.len() as u64 && status.lost.len() == 1, "{status:?}");
    let (v, off, b) = &all[hole];
    source.insert(*v, *off, b).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert!(status.done && status.crc_ok == Some(true), "{status:?}");
    assert_eq!(sink.out, plain);
}

#[test]
fn a_repair_that_waited_goes_on_under_a_run_budget() {
    let plain = video_like(600_000, 14);
    let volumes = rar5_compressed(&plain, false, 1 << 20);
    let map = MemberMap::from_memory(&refs(&volumes), "c.rar", None).unwrap();
    let options = FeedOptions { run_budget: Some(1_500), ..FeedOptions::default() };
    let mut decoder = FeedDecoder::new(&map, 0, options).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut sink = Held { donor: plain.clone(), ..Held::default() };
    let all = articles(&volumes, 7_000);
    let hole = 10;
    let (hv, hoff, hbytes) = all[hole].clone();
    source.mark_lost(hv, hoff..hoff + hbytes.len() as u64);
    let run = |decoder: &mut FeedDecoder, source: &mut ArticleBuffer, sink: &mut Held| {
        let mut status = decoder.run(source, sink).unwrap();
        for _ in 0..10_000 {
            if !status.more {
                break;
            }
            status = decoder.run(source, sink).unwrap();
        }
        status
    };
    for (i, (v, off, b)) in all.iter().enumerate() {
        if i != hole {
            source.insert(*v, *off, b).unwrap();
            run(&mut decoder, &mut source, &mut sink);
        }
    }
    // the repair waits at the hole
    let status = decoder.status().clone();
    assert!(status.lost.len() == 1 && status.needs.iter().any(|n| n.kind == NeedKind::Repair), "{status:?}");
    // its bytes come; the repair goes on a budget at a time, past them (and its source lets them go)
    source.insert(hv, hoff, &hbytes).unwrap();
    let status = run(&mut decoder, &mut source, &mut sink);
    assert!(status.done && status.crc_ok == Some(true), "{status:?}");
    assert_eq!(sink.out, plain);
}

/// The packed stream of `plain` with a delta filter declared at the start of block `k`, covering `len` bytes of
/// output from there (past the block's end).
fn stream_with_filter(plain: &[u8], k: usize, len: u64) -> (Vec<u8>, Vec<u64>) {
    use zipfast::rar5::testenc::{self, Op};
    let ops = testenc::lz(plain, 1 << 17, 16);
    let chunks: Vec<Vec<Op>> = ops.chunks(2_000).map(<[Op]>::to_vec).collect();
    let mut starts = Vec::new();
    let mut at = 0u64;
    let mut out = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        starts.push(at);
        at += c
            .iter()
            .map(|op| match op {
                Op::Lit(_) => 1,
                Op::Match(len, _) | Op::Rep(_, len) => u64::from(*len),
                _ => 0,
            })
            .sum::<u64>();
        let mut c = c.clone();
        if i == k {
            c.insert(0, Op::Filter { start: 0, len, kind: 0, channels: 1 });
        }
        out.extend(testenc::tuned_block(&c, i + 1 == chunks.len()));
    }
    (out, starts)
}

/// One plain compressed member over volumes of `chunk` packed bytes, without a CRC (its output is what it decodes to).
fn rar5_packed_volumes(data: &[u8], size: usize, chunk: usize) -> Vec<Vec<u8>> {
    let mut spec = FileSpec::new("c.bin", data);
    spec.method = 3;
    spec.size = Some(size as u64);
    spec.no_crc = true;
    let parts: Vec<&[u8]> = data.chunks(chunk).collect();
    let n = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let last = i + 1 == n;
            let mut bytes = SIG.to_vec();
            bytes.extend(main_block(true, if i == 0 { None } else { Some(i as u64) }));
            bytes.extend(file_block(&spec, part, 0, i > 0, !last));
            bytes.extend(end_block(!last));
            bytes
        })
        .collect()
}

#[test]
fn a_snapshot_after_a_skip_restores_at_the_restart_not_before_the_hole() {
    let plain0 = video_like(600_000, 15);
    let hole = 10;
    let present_after = 5;
    // where a skip of the hole restarts on this content: the block the lost range ends at
    let (packed, starts) = stream_with_filter(&plain0, usize::MAX, 0);
    let volumes = rar5_packed_volumes(&packed, plain0.len(), 1 << 20);
    let skip = |volumes: &[Vec<u8>], plain: &[u8]| {
        let map = MemberMap::from_memory(&refs(volumes), "c.rar", None).unwrap();
        let all = articles(volumes, 7_000);
        let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        let mut sink = Held { donor: plain.to_vec(), ..Held::default() };
        source.mark_lost(all[hole].0, all[hole].1..all[hole].1 + 7_000);
        for (v, off, b) in all.iter().take(hole + 1 + present_after).filter(|a| a.1 != all[hole].1) {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        (decoder, source, sink, map)
    };
    let (decoder, ..) = skip(&volumes, &plain0);
    let restart = decoder.status().lost.first().expect("the hole is skipped").end;
    let k = starts.iter().position(|&s| s == restart).expect("a restart at a block start");
    // the same content with a filter declared in the restart's block that runs past it: at the end of that block
    // no checkpoint can be taken
    let (packed, _) = stream_with_filter(&plain0, k, 60_000);
    let volumes = rar5_packed_volumes(&packed, plain0.len(), 1 << 20);
    let mut whole = Vec::new();
    let map = MemberMap::from_memory(&refs(&volumes), "c.rar", None).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &volumes[0]).unwrap();
    assert!(FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap().run(&mut source, &mut whole).unwrap().done);
    let all = articles(&volumes, 7_000);
    let (decoder, mut source, mut sink, map) = skip(&volumes, &whole);
    let status = decoder.status().clone();
    assert_eq!(status.lost.first().map(|r| r.end), Some(restart), "{status:?}");
    assert!(status.frontier < restart + 60_000, "the main decode stopped inside the filter: {status:?}");
    // a restore with the hole still missing must not skip it again
    let snap = FeedSnapshot::from_bytes(&decoder.snapshot().to_bytes()).unwrap();
    drop(decoder);
    let mut decoder = FeedDecoder::restore(&map, 0, FeedOptions::default(), &snap).unwrap();
    let holes = decoder.stats().holes;
    decoder.run(&mut source, &mut sink).unwrap();
    // it restored at the restart: the hole was not met (and skipped) again
    assert_eq!(decoder.stats().holes, holes, "{:?}", decoder.stats());
    for (v, off, b) in all.iter().skip(hole + 1 + present_after) {
        source.insert(*v, *off, b).unwrap();
        decoder.run(&mut source, &mut sink).unwrap();
    }
    source.insert(all[hole].0, all[hole].1, &volumes[0][all[hole].1 as usize..all[hole].1 as usize + 7_000]).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert!(status.done, "{status:?}");
    assert_eq!(sink.out, whole);
    assert!(sink.seen.iter().all(|s| *s));
}

/// Copy B continues copy A's extraction (a failover): `open_at` starts the main decode where A's output stops, so
/// none of B's packed bytes before that are ever needed, and with A's prefix CRC the member's CRC is still checked.
#[test]
fn open_at_continues_another_copys_output_without_reading_before_it() {
    for case in cases() {
        let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
        let member = &map.members[0];
        let size = case.plain.len() as u64;
        let cbc = member.mapping == OutputMapping::CbcBlocks;
        for at in [1, 15, 16, 17, 7_000, 20_001, size - 1, size] {
            let mut decoder = FeedDecoder::open_at(&map, 0, at, all_needs(case.password)).unwrap();
            let start = decoder.status().frontier;
            if cbc {
                assert_eq!(start, at & !15, "{} at {at}", case.what);
            } else {
                assert_eq!(start, at, "{} at {at}", case.what);
            }
            if start > 0 {
                decoder.set_prefix_crc32(crc32fast::hash(&case.plain[..start as usize])).unwrap();
            }
            assert!(decoder.set_prefix_crc32(0).is_err(), "a second (or needless) prefix CRC is refused");
            // The first byte of B each volume may be asked for: its span for `start..`, then to the volume's end.
            let first: Vec<(u32, u64)> =
                member.packed_spans(start..size).unwrap().iter().map(|span| (span.volume, span.packed.start)).collect();
            let mut source = ArticleBuffer::new(usize::MAX);
            let mut sink = Once { out: case.plain[..start as usize].to_vec(), ..Default::default() };
            let mut asked = 0u64;
            for _ in 0..10_000 {
                let status = decoder.run(&mut source, &mut sink).unwrap();
                if status.done {
                    break;
                }
                assert!(!status.needs.is_empty(), "{} at {at}: stuck without needs", case.what);
                for need in &status.needs {
                    let floor = first.iter().find(|(v, _)| *v == need.volume).map(|&(_, f)| f);
                    assert!(
                        floor.is_some_and(|f| need.range.start >= f),
                        "{} at {at}: needs {need:?} before {first:?}",
                        case.what
                    );
                    let bytes = &case.volumes[need.volume as usize][need.range.start as usize..need.range.end as usize];
                    source.insert(need.volume, need.range.start, bytes).unwrap();
                    asked += bytes.len() as u64;
                }
            }
            let status = decoder.status().clone();
            assert!(status.done, "{} at {at}: {status:?}", case.what);
            assert_eq!(status.crc_ok, Some(true), "{} at {at}", case.what);
            assert_eq!(sink.out, case.plain, "{} at {at}", case.what);
            assert_eq!(decoder.stats().written, size - start, "{} at {at}", case.what);
            // Only what the rest needs: B's bytes from the start's span on (plus a WinZip AES code).
            let rest: u64 =
                member.packed_spans(start..size).unwrap().iter().map(|s| s.packed.end - s.packed.start).sum();
            assert!(asked <= rest + 10, "{} at {at}: asked {asked} for {rest}", case.what);
        }
    }
}

#[test]
fn open_at_refuses_compressed_members_and_offsets_past_the_end() {
    let plain = data(20_000, 3);
    let volumes = rar5_compressed(&plain, false, 1 << 20);
    let map = MemberMap::from_memory(&refs(&volumes), "c.part1.rar", None).unwrap();
    assert!(matches!(
        FeedDecoder::open_at(&map, 0, 100, FeedOptions::new(None)),
        Err(FeedError::Unsupported(FeedUnsupported::Compressed { .. }))
    ));
    let case = &cases()[0];
    let map = MemberMap::from_memory(&refs(&case.volumes), case.name, None).unwrap();
    let past = case.plain.len() as u64 + 1;
    assert!(matches!(FeedDecoder::open_at(&map, 0, past, FeedOptions::new(None)), Err(FeedError::Malformed(_))));
    // At 0 it is a fresh decoder, and a prefix CRC has nothing to cover.
    let mut fresh = FeedDecoder::open_at(&map, 0, 0, FeedOptions::new(None)).unwrap();
    assert_eq!(fresh.status().frontier, 0);
    assert!(fresh.set_prefix_crc32(0).is_err());
}

/// RustyGet: extraction straight from the volume files as the downloader writes them. Articles land in shuffled
/// order (one lost, then written late); the decoder reads each from disk once, the moment it is written, and never
/// waits for a finished volume.
#[test]
fn volume_files_feed_the_decoder_as_articles_are_written() {
    use std::os::unix::fs::FileExt;
    for case in cases() {
        let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
        let member = &map.members[0];
        let dir = tempfile::tempdir().unwrap();
        let mut source = VolumeFiles::new();
        let mut writers = Vec::new();
        for (i, volume) in case.volumes.iter().enumerate() {
            let path = dir.path().join(format!("v{i}"));
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(volume.len() as u64).unwrap();
            source.set_file(i as u32, std::fs::File::open(&path).unwrap());
            writers.push(file);
        }
        let mut all = articles(&case.volumes, 1_000);
        shuffle(&mut all, 11);
        let late = all.remove(all.len() / 2);
        source.mark_lost(late.0, late.1..late.1 + late.2.len() as u64);
        let mut decoder = FeedDecoder::new(&map, 0, all_needs(case.password)).unwrap();
        let mut sink = Once::default();
        for (v, off, bytes) in &all {
            writers[*v as usize].write_all_at(bytes, *off).unwrap();
            source.mark_written(*v, *off..*off + bytes.len() as u64);
            let status = decoder.run(&mut source, &mut sink).unwrap();
            // Written bytes are never needed.
            for need in &status.needs {
                assert!(
                    source.written(need.volume).iter().all(|w| w.end <= need.range.start || need.range.end <= w.start),
                    "{}: {need:?} is written",
                    case.what
                );
            }
        }
        writers[late.0 as usize].write_all_at(&late.2, late.1).unwrap();
        source.mark_written(late.0, late.1..late.1 + late.2.len() as u64);
        let status = decoder.run(&mut source, &mut sink).unwrap();
        assert!(status.done && status.lost.is_empty(), "{}: {status:?}", case.what);
        assert_eq!(status.crc_ok, Some(true), "{}", case.what);
        assert_eq!(sink.out, case.plain, "{}", case.what);
        // Each packed byte read from disk once (under CBC a hole costs a few blocks read twice around it).
        let stats = decoder.stats();
        let extra = stats.packed_read.saturating_sub(member.packed_size);
        let bound = 64 * (stats.holes + 1) + 16;
        assert!(extra <= bound, "{}: read {extra} bytes twice over {} holes", case.what, stats.holes);
    }
}

#[test]
fn volume_files_answer_written_lost_and_late_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v0");
    std::fs::write(&path, vec![7u8; 100]).unwrap();
    let mut source = VolumeFiles::new();
    source.set_file(0, std::fs::File::open(&path).unwrap());
    source.mark_written(0, 10..20);
    source.mark_lost(0, 0..30); // only 0..10 and 20..30 become lost: 10..20 is written
    let mut buf = [0u8; 64];
    assert_eq!(source.read_packed(0, 12, &mut buf), PackedRead::Data(8));
    assert_eq!(source.read_packed(0, 0, &mut buf), PackedRead::Hole { len: 10 });
    assert_eq!(source.read_packed(0, 25, &mut buf), PackedRead::Hole { len: 5 });
    assert_eq!(source.read_packed(0, 40, &mut buf), PackedRead::NotYet { len: u64::MAX });
    assert_eq!(source.absent(0, 0..50), Some(vec![0..10, 20..50]));
    source.mark_written(0, 20..30);
    assert_eq!(source.read_packed(0, 25, &mut buf), PackedRead::Data(5));
    // Reported written past the file's end: the bytes are damaged, not late.
    source.mark_written(0, 150..160);
    assert_eq!(source.read_packed(0, 150, &mut buf), PackedRead::Hole { len: 10 });
    // A volume never given a file.
    assert_eq!(source.read_packed(9, 0, &mut buf), PackedRead::NotYet { len: u64::MAX });
}

/// prybar-fc's bench (RAR5 -m3, 20 holes, held mode): a seeded restart whose output disagrees with the held output
/// (here the other copy differs in scattered bytes; in the bench a filter the search did not see) must not fail the
/// decoder. The restart is abandoned at the mismatch, another is searched from there, and failing that the rest is
/// repaired from the checkpoint before the hole once its bytes come; every byte still lands once and exactly.
#[test]
fn a_seeded_restart_that_disagrees_with_held_output_does_not_fail_the_decoder() {
    for encrypted in [false, true] {
        let (feed, _) = compressed_feed(encrypted, 9, 12);
        let mut decoder = FeedDecoder::new(&feed.map, 0, all_needs(feed.password)).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        for (v, off, b) in &feed.missing {
            source.mark_lost(*v, *off..*off + b.len() as u64);
        }
        let mut donor = feed.plain.clone();
        for at in (20_000..donor.len()).step_by(40_000) {
            donor[at] ^= 0x5a;
        }
        let mut sink = Held { donor, ..Held::default() };
        for (v, off, b) in &feed.present {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        for (i, w) in sink.seen.iter().enumerate() {
            if *w {
                assert_eq!(sink.out[i], feed.plain[i], "{encrypted}: byte {i} written wrong");
            }
        }
        for (v, off, b) in &feed.missing {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        let status = decoder.status().clone();
        assert!(status.done && status.crc_ok == Some(true), "{encrypted}: {status:?}");
        assert_eq!(sink.out, feed.plain, "{encrypted}");
    }
}

/// prybar-fc's bench: every run at a hole re-read the held output, the packed bytes after it and the window before
/// asking whether anything had grown. A retry at the same hole now reads only what is new.
#[test]
fn skip_retries_at_a_hole_do_not_read_the_held_output_again() {
    let (feed, _) = compressed_feed(false, 9, 12);
    let mut decoder = FeedDecoder::new(&feed.map, 0, all_needs(None)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    for (v, off, b) in &feed.missing {
        source.mark_lost(*v, *off..*off + b.len() as u64);
    }
    let mut sink = Held { donor: feed.plain.clone(), ..Held::default() };
    // In volume order, one article per run: each hole is met with few packed bytes after it, and retried.
    let mut present = feed.present.clone();
    present.sort_by_key(|(v, off, _)| (*v, *off));
    let mut runs = 0u64;
    for (v, off, b) in &present {
        source.insert(*v, *off, b).unwrap();
        decoder.run(&mut source, &mut sink).unwrap();
        runs += 1;
    }
    let size = feed.plain.len() as u64;
    eprintln!("read back {} for {size} output over {runs} runs, {} holes", sink.read_back, decoder.stats().holes);
    // Before: 7.20 MB read back here (12x the output: held output and window again on every retry). After: 3.53 MB,
    // mostly the window before each hole, read once per hole and once per repair restore.
    assert!(sink.read_back < 6 * size, "read back {} for {size} output", sink.read_back);
}

/// The core of "never read an article twice" for dupe recovery: lost output another copy already gave us is retired
/// with `fill_lost`, so the member finishes (done, crc_ok) without fetching the missing articles or reading the
/// output back.
#[test]
fn fill_lost_retires_held_output_so_the_member_finishes_without_its_missing_articles() {
    // RAR 5.0 compressed, held mode (a twin's output past the frontier): holes are skipped, then filled from the twin.
    for encrypted in [false, true] {
        let (feed, _) = compressed_feed(encrypted, 9, 12);
        let mut decoder = FeedDecoder::new(&feed.map, 0, all_needs(feed.password)).unwrap();
        let mut source = ArticleBuffer::new(usize::MAX);
        for (v, off, b) in &feed.missing {
            source.mark_lost(*v, *off..*off + b.len() as u64);
        }
        let mut sink = Held { donor: feed.plain.clone(), ..Held::default() };
        for (v, off, b) in &feed.present {
            source.insert(*v, *off, b).unwrap();
            decoder.run(&mut source, &mut sink).unwrap();
        }
        let lost = decoder.status().lost.clone();
        assert!(!lost.is_empty(), "{encrypted}: holes were skipped");
        // A wrong length and a range that is not lost are refused.
        assert!(matches!(decoder.fill_lost(lost[0].clone(), &[]), Err(FeedError::FillLost(_))));
        let written = 0..lost[0].start.min(1);
        if !written.is_empty() {
            assert!(matches!(decoder.fill_lost(written, &[0]), Err(FeedError::FillLost(_))));
        }
        for range in &lost {
            let bytes = &feed.plain[range.start as usize..range.end as usize];
            sink.write_at(range.start, bytes).unwrap(); // the caller's output holds the twin's bytes
            decoder.fill_lost(range.clone(), bytes).unwrap();
        }
        // A main decode still waiting at a hole near the end (no packed bytes after it to restart from): the twin
        // holds the rest too.
        let frontier = decoder.status().frontier;
        let size = feed.plain.len() as u64;
        if frontier < size {
            let bytes = &feed.plain[frontier as usize..];
            sink.write_at(frontier, bytes).unwrap();
            decoder.fill_lost(frontier..size, bytes).unwrap();
        }
        let status = decoder.run(&mut source, &mut sink).unwrap();
        assert!(status.done && status.lost.is_empty() && status.needs.is_empty(), "{encrypted}: {status:?}");
        assert_eq!(status.crc_ok, Some(true), "{encrypted}");
        assert_eq!(sink.out, feed.plain, "{encrypted}");
    }
    // Stored AES (CBC): a hole's lost blocks filled from the twin.
    let case = &cases()[1];
    let map = MemberMap::from_memory(&refs(&case.volumes), case.name, case.password).unwrap();
    let mut decoder = FeedDecoder::new(&map, 0, all_needs(case.password)).unwrap();
    let mut source = ArticleBuffer::new(usize::MAX);
    let mut all = articles(&case.volumes, 1_000);
    let gone = all.remove(17);
    source.mark_lost(gone.0, gone.1..gone.1 + gone.2.len() as u64);
    let mut sink = Once::default();
    for (v, off, b) in &all {
        source.insert(*v, *off, b).unwrap();
        decoder.run(&mut source, &mut sink).unwrap();
    }
    let lost = decoder.status().lost.clone();
    assert_eq!(lost.len(), 1);
    let range = lost[0].clone();
    // A wrong byte is taken as given and caught by the CRC.
    let mut wrong = case.plain[range.start as usize..range.end as usize].to_vec();
    wrong[0] ^= 1;
    let mut probe = FeedDecoder::restore(&map, 0, all_needs(case.password), &decoder.snapshot()).unwrap();
    probe.fill_lost(range.clone(), &wrong).unwrap();
    assert_eq!(probe.run(&mut source, &mut Once::default()).unwrap().crc_ok, Some(false));
    decoder.fill_lost(range.clone(), &case.plain[range.start as usize..range.end as usize]).unwrap();
    let status = decoder.run(&mut source, &mut sink).unwrap();
    assert!(status.done && status.crc_ok == Some(true), "{status:?}");
}
