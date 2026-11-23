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

//! Persistent partials created from a member map (`zipfast::partial::DirectPartials`), fed by a `FeedDecoder`
//! through `DirectSink`: restarts in the middle (handles dropped, and a process aborted with a group open), holes
//! and late repairs, exact output, verification, each byte written once, durable sync counts, and limits that
//! scale with the member count.
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]

mod common;

#[allow(dead_code, reason = "the shared doc store also carries fault hooks these tests do not use")]
mod anchor_store {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/persistent-anchor-store.rs"));
}

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use zipfast::map::{ArticleBuffer, FeedDecoder, FeedOptions, FeedSink, FeedSnapshot, MemberMap};
use zipfast::partial::*;
use zipfast::progressive::{
    ProgressiveLimits, ProtectedVolume, ProtectionDeclaration, ProtectionInventory, SessionControl, VolumeBacking,
};

fn payload(size: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// A stored RAR 5.0 member `name` holding `data`, cut into volumes of `chunk` data bytes, with a BLAKE2sp record
/// when `blake`.
fn stored_set(name: &str, data: &[u8], chunk: usize, blake: bool) -> Vec<Vec<u8>> {
    let mut spec = common::FileSpec::new(name, data);
    spec.size = Some(data.len() as u64);
    if blake {
        spec.extra = common::blake_record(common::blake(data));
    }
    common::volumes(&spec, chunk)
}

fn protection(count: usize) -> ProtectionDeclaration {
    ProtectionDeclaration::Complete {
        epoch: 1,
        inventory: ProtectionInventory {
            volumes: (0..count as u32)
                .map(|index| ProtectedVolume {
                    index,
                    name: format!("set.part{}.rar", index + 1).into(),
                    backing: VolumeBacking::NonFile,
                })
                .collect(),
            auxiliary_paths: Vec::new(),
        },
    }
}

/// The work directory's roots, created and synced as the anchor store requires.
fn roots(work: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let (output, state, anchors) = (work.join("out"), work.join("state"), work.join("anchors"));
    for dir in [&output, &state, &anchors] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::File::open(work).unwrap().sync_all().unwrap();
    (output, state, anchors)
}

fn direct(work: &Path, volumes: usize, limits: PartialLimits) -> DirectPartials {
    let (output_root, state_dir, anchors) = roots(work);
    DirectPartials::new(DirectOptions {
        binding: ArchiveBinding { job: [7; 16], archive: [9; 32] },
        output_root,
        state_dir,
        naming: PartialNaming::ArchivePath,
        limits,
        progressive_limits: ProgressiveLimits::default(),
        anchors: Arc::new(anchor_store::DurableAnchors::open(&anchors).unwrap()),
        control: SessionControl::default(),
        protection: protection(volumes),
        password: None,
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

/// Articles of `article` bytes over every volume, in a fixed shuffled order, and which of them are lost on their
/// first delivery (every `every`-th of that order).
struct Articles {
    list: Vec<(u32, u64, u64)>,
    lost: Vec<bool>,
}

impl Articles {
    fn new(volumes: &[Vec<u8>], article: u64, every: usize, seed: u64) -> Self {
        let mut list = Vec::new();
        for (v, bytes) in volumes.iter().enumerate() {
            let mut at = 0;
            while at < bytes.len() as u64 {
                let len = article.min(bytes.len() as u64 - at);
                list.push((v as u32, at, len));
                at += len;
            }
        }
        // Each article arrives up to eight places late, as a download in flight delivers them.
        let mut x = seed | 1;
        for i in 0..list.len() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let j = (i + (x % 8) as usize).min(list.len() - 1);
            list.swap(i, j);
        }
        let lost = (0..list.len()).map(|i| i % every == every - 1).collect();
        Self { list, lost }
    }
    fn insert(&self, buffer: &mut ArticleBuffer, volumes: &[Vec<u8>], i: usize) {
        let (v, at, len) = self.list[i];
        buffer.insert(v, at, &volumes[v as usize][at as usize..(at + len) as usize]).unwrap();
    }
}

/// Phase one of a restart test: creates the member's partial, feeds the first `upto` articles of the order (lost
/// ones marked lost), commits and saves the decoder's snapshot next to the work directory, then feeds `extra` more
/// articles without committing. Returns the sink (open group included) and what was durable at the snapshot.
fn first_half(
    work: &Path,
    volumes: &[Vec<u8>],
    articles: &Articles,
    upto: usize,
    extra: usize,
) -> (DirectPartials, DirectSink, FeedDecoder, u64) {
    let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
    let map = MemberMap::from_memory(&refs, "set.part1.rar", None).unwrap();
    let parts = direct(work, volumes.len(), PartialLimits::default());
    let member = parts.open(&map, 0).unwrap();
    assert_eq!(member.origin, DirectOrigin::Created);
    // Born at full size with every byte unknown.
    let size = map.members[0].unpacked_size.unwrap();
    assert_eq!(member.file.remaining().unwrap(), vec![0..size]);
    assert_eq!(std::fs::metadata(member.file.output_path()).unwrap().len(), size);
    let mut sink = DirectSink::new(member.file);
    let mut decoder = FeedDecoder::new(&map, 0, FeedOptions::new(None)).unwrap();
    let mut buffer = ArticleBuffer::new(usize::MAX);
    for i in 0..upto {
        if articles.lost[i] {
            let (v, at, len) = articles.list[i];
            buffer.mark_lost(v, at..at + len);
        } else {
            articles.insert(&mut buffer, volumes, i);
        }
        decoder.run(&mut buffer, &mut sink).unwrap();
    }
    // A commit point: the partial's state now claims every byte written, and the snapshot is taken after it, so
    // it never claims more than is durable.
    sink.file().state().unwrap();
    let durable = size - sink.file().remaining().unwrap().iter().map(|r| r.end - r.start).sum::<u64>();
    let snapshot = decoder.snapshot().to_bytes();
    let path = work.join("decoder.snap");
    std::fs::write(work.join("decoder.tmp"), &snapshot).unwrap();
    std::fs::File::open(work.join("decoder.tmp")).unwrap().sync_all().unwrap();
    std::fs::rename(work.join("decoder.tmp"), &path).unwrap();
    std::fs::File::open(work).unwrap().sync_all().unwrap();
    for i in upto..(upto + extra).min(articles.list.len()) {
        if articles.lost[i] {
            let (v, at, len) = articles.list[i];
            buffer.mark_lost(v, at..at + len);
        } else {
            articles.insert(&mut buffer, volumes, i);
        }
        decoder.run(&mut buffer, &mut sink).unwrap();
    }
    (parts, sink, decoder, durable)
}

/// Phase two: a new process (or the same one after dropping everything) finds the member again, restores the
/// decoder from the saved snapshot and delivers every article, lost ones included (late repairs). Checks exact
/// output, `Verdict::Ok`, and that nothing the durable state knew was written again. Returns the bytes written.
fn second_half(work: &Path, volumes: &[Vec<u8>], data: &[u8], articles: &Articles) -> u64 {
    let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
    let map = MemberMap::from_memory(&refs, "set.part1.rar", None).unwrap();
    let parts = direct(work, volumes.len(), PartialLimits::default());
    let member = parts.open(&map, 0).unwrap();
    assert_eq!(member.origin, DirectOrigin::Adopted);
    let size = data.len() as u64;
    let gaps = member.file.remaining().unwrap();
    let unknown: u64 = gaps.iter().map(|r| r.end - r.start).sum();
    assert!(unknown > 0 && unknown < size, "{gaps:?}");
    // What the state knows is exactly the payload there.
    let mut sink = DirectSink::new(member.file);
    let mut at = 0;
    for gap in gaps.iter().chain(std::iter::once(&(size..size))) {
        let mut buf = vec![0; (gap.start - at) as usize];
        if !buf.is_empty() {
            assert_eq!(sink.read_held(at, &mut buf).unwrap(), buf.len());
            assert_eq!(buf, data[at as usize..gap.start as usize]);
        }
        at = gap.end;
    }
    let snapshot = FeedSnapshot::from_bytes(&std::fs::read(work.join("decoder.snap")).unwrap()).unwrap();
    let mut decoder = FeedDecoder::restore(&map, 0, FeedOptions::new(None), &snapshot).unwrap();
    let mut buffer = ArticleBuffer::new(usize::MAX);
    let mut status = decoder.run(&mut buffer, &mut sink).unwrap();
    for i in 0..articles.list.len() {
        if status.done {
            break;
        }
        articles.insert(&mut buffer, volumes, i);
        status = decoder.run(&mut buffer, &mut sink).unwrap();
    }
    assert!(status.done && status.lost.is_empty(), "{status:?}");
    assert_eq!(status.crc_ok, Some(true));
    // Each byte the durable state lacked was written once, and nothing it knew was written again.
    assert_eq!(sink.applied_bytes(), unknown);
    let mut file = sink.into_file();
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert!(file.remaining().unwrap().is_empty());
    assert_eq!(std::fs::read(file.output_path()).unwrap(), data);
    unknown
}

const CHILD: &str = "ZIPFAST_DIRECT_CHILD";

#[test]
fn a_member_survives_its_handles_dropped_mid_feed() {
    let tmp = tempfile::tempdir().unwrap();
    let data = payload(600_000, 3);
    let volumes = stored_set("dir/payload.bin", &data, 110_000, true);
    let articles = Articles::new(&volumes, 7_000, 5, 11);
    let half = articles.list.len() / 2;
    let (parts, sink, decoder, durable) = first_half(tmp.path(), &volumes, &articles, half, 0);
    assert!(durable > 0);
    // Dropped without finishing: no verification, no last commit asked for.
    drop((decoder, sink, parts));
    let written = second_half(tmp.path(), &volumes, &data, &articles);
    assert_eq!(written + durable, data.len() as u64);
}

/// Runs phase one in a child process that aborts with written output uncommitted (an open group): what the group
/// held is lost with it, and the restarted feed writes it again, from the snapshot taken at the last commit.
#[test]
fn a_member_survives_an_abort_with_a_group_open() {
    if let Some(work) = std::env::var_os(CHILD) {
        let work = PathBuf::from(work);
        let data = payload(600_000, 5);
        let volumes = stored_set("payload.bin", &data, 130_000, false);
        let articles = Articles::new(&volumes, 6_000, 4, 17);
        let before = durable_sync_count();
        let (_parts, mut sink, _decoder, durable) =
            first_half(&work, &volumes, &articles, articles.list.len() / 3, articles.list.len() / 3);
        let syncs = durable_sync_count() - before;
        // the group the extra articles wrote is open: written, not committed
        let held = (0..data.len() as u64).filter(|&o| sink.read_held(o, &mut [0]).unwrap() == 1).count() as u64;
        std::fs::write(work.join("child.txt"), format!("{durable} {held} {syncs}")).unwrap();
        std::process::abort();
    }
    let tmp = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["a_member_survives_an_abort_with_a_group_open", "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, tmp.path())
        .status()
        .unwrap();
    assert!(!status.success(), "the child aborts");
    let report = std::fs::read_to_string(tmp.path().join("child.txt")).unwrap();
    let numbers: Vec<u64> = report.split(' ').map(|n| n.parse().unwrap()).collect();
    let (durable, held, syncs) = (numbers[0], numbers[1], numbers[2]);
    assert!(held > durable, "the open group held more than the commit: {report}");
    // Genesis plus one commit: a handful of syncs, independent of the member's size.
    assert!(syncs <= 30, "{report}");
    let data = payload(600_000, 5);
    let volumes = stored_set("payload.bin", &data, 130_000, false);
    let articles = Articles::new(&volumes, 6_000, 4, 17);
    let written = second_half(tmp.path(), &volumes, &data, &articles);
    // The aborted group is gone: the restart wrote everything past the commit again, nothing before it.
    assert_eq!(written + durable, data.len() as u64);
}

/// The genesis of a direct partial records nothing per unknown byte: a 40 MB member's state bundle is as small as
/// a 100 KB member's, and both cost the same syncs.
#[test]
fn a_member_is_born_unwritten_at_any_size() {
    let tmp = tempfile::tempdir().unwrap();
    let mut sizes = Vec::new();
    for (i, size) in [100_000usize, 40_000_000].into_iter().enumerate() {
        let work = tmp.path().join(format!("w{i}"));
        let data = vec![i as u8; size];
        let volumes = stored_set("big.bin", &data, 8_000_000, false);
        let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
        let map = MemberMap::from_memory(&refs, "set.part1.rar", None).unwrap();
        let parts = direct(&work, volumes.len(), PartialLimits::default());
        let member = parts.open(&map, 0).unwrap();
        assert_eq!(member.file.remaining().unwrap(), vec![0..size as u64]);
        let bundle: u64 = std::fs::read_dir(work.join("state"))
            .unwrap()
            .flat_map(|e| std::fs::read_dir(e.unwrap().path()).unwrap())
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        sizes.push(bundle);
        // written in pieces out of order, the member verifies once every byte is there
        let mut sink = DirectSink::new(member.file);
        let piece = size / 3;
        for (start, end) in [(piece, 2 * piece), (0, piece), (2 * piece, size)] {
            sink.write_at(start as u64, &data[start..end]).unwrap();
        }
        // offered again: matches, writes nothing
        sink.write_at(0, &data[..10]).unwrap();
        assert_eq!(sink.applied_bytes(), size as u64);
        // a different byte over known output is refused
        assert!(sink.write_at(5, &[data[5] ^ 1]).is_err());
        let mut file = sink.into_file();
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    }
    assert!(sizes[1] <= sizes[0] + 64, "{sizes:?}");
}

/// Many members kept open at once: the defaults refuse the 17th, `PartialLimits::for_members` fits the set. A
/// wrong byte verifies `Bad`, and the same name under another archive's binding is not adopted.
#[test]
fn limits_scale_with_the_member_count() {
    let tmp = tempfile::tempdir().unwrap();
    let count = 40;
    let datas: Vec<Vec<u8>> = (0..count).map(|i| payload(2_000 + i * 31, i as u64 + 1)).collect();
    let names: Vec<String> = (0..count).map(|i| format!("m{i:02}.bin")).collect();
    let mut volume = common::SIG.to_vec();
    volume.extend(common::main_block(false, None));
    for (name, data) in names.iter().zip(&datas) {
        volume.extend(common::file_block(
            &common::FileSpec::new(name, data),
            data,
            crc32fast::hash(data),
            false,
            false,
        ));
    }
    volume.extend(common::end_block(false));
    let map = MemberMap::from_memory(&[&volume], "set.part1.rar", None).unwrap();
    let defaults = direct(&tmp.path().join("defaults"), 1, PartialLimits::default());
    let mut held = Vec::new();
    let error = loop {
        match defaults.open(&map, held.len()) {
            Ok(member) => held.push(member),
            Err(error) => break error,
        }
    };
    // Each live handle holds about six descriptors: the 64 files of the defaults run out first.
    assert!(held.len() < 16, "{}", held.len());
    assert!(
        matches!(
            error.kind,
            PartialErrorKind::Limit { resource: PartialResource::OpenFiles | PartialResource::OpenPartials, .. }
        ),
        "{error:?}"
    );
    drop((held, defaults));
    let limits = PartialLimits::for_members(count);
    assert!(limits.open_partials >= count as u32 && limits.open_files >= 8 * count as u32);
    let parts = direct(&tmp.path().join("scaled"), 1, limits);
    let mut sinks: Vec<DirectSink> = (0..count).map(|i| DirectSink::new(parts.open(&map, i).unwrap().file)).collect();
    for (i, sink) in sinks.iter_mut().enumerate() {
        let mut data = datas[i].clone();
        if i == 7 {
            data[100] ^= 0x40;
        }
        sink.write_at(0, &data).unwrap();
    }
    for (i, sink) in sinks.into_iter().enumerate() {
        let verdict = verify(&mut sink.into_file());
        if i == 7 {
            assert!(matches!(verdict, Verdict::Bad { .. }), "{verdict:?}");
        } else {
            assert!(matches!(verdict, Verdict::Ok { .. }), "{i}: {verdict:?}");
        }
    }
    // Reopened, every member is adopted with its output; another binding's key is another member.
    let member = parts.open(&map, 3).unwrap();
    assert_eq!(member.origin, DirectOrigin::Adopted);
    assert!(member.file.remaining().unwrap().is_empty());
    let other = DirectPartials::new(DirectOptions {
        binding: ArchiveBinding { job: [8; 16], archive: [9; 32] },
        output_root: tmp.path().join("scaled/out"),
        state_dir: tmp.path().join("scaled/state"),
        naming: PartialNaming::ArchivePath,
        limits: PartialLimits::default(),
        progressive_limits: ProgressiveLimits::default(),
        anchors: Arc::new(anchor_store::DurableAnchors::open(&tmp.path().join("defaults/anchors")).unwrap()),
        control: SessionControl::default(),
        protection: protection(1),
        password: None,
    })
    .unwrap();
    drop(member);
    let error = other.open(&map, 3).err().unwrap();
    assert!(matches!(error.kind, PartialErrorKind::AlreadyExists), "{error:?}");
}
