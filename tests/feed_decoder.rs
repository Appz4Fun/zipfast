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
