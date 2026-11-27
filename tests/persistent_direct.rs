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

// ---- Every container the feed decoder handles: the decoder's cursor kept with the output across a restart ----

fn read_volumes(dir: &str, names: &[&str]) -> Vec<Vec<u8>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(dir);
    names.iter().map(|n| std::fs::read(root.join(n)).unwrap()).collect()
}

/// Every file a straight extraction of `volumes` writes, as bytes.
fn straight(work: &Path, volumes: &[Vec<u8>], first: &str, password: Option<&str>) -> Vec<Vec<u8>> {
    let set = work.join("set");
    std::fs::create_dir_all(&set).unwrap();
    let names: Vec<PathBuf> = volumes_named(first, volumes.len()).into_iter().map(|n| set.join(n)).collect();
    for (path, bytes) in names.iter().zip(volumes) {
        std::fs::write(path, bytes).unwrap();
    }
    let dest = work.join("straight");
    let options = zipfast::extract::Options {
        mode: zipfast::extract::Mode::Extract,
        dest: dest.clone(),
        overwrite: zipfast::extract::Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: false,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        rar4_raw_names: false,
        folder_times: Default::default(),
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    };
    zipfast::extract::run_with_password(&names[0], &options, password, |_| {}).unwrap();
    let mut files = Vec::new();
    let mut dirs = vec![dest];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                dirs.push(entry.path());
            } else {
                files.push(std::fs::read(entry.path()).unwrap());
            }
        }
    }
    files
}

/// The names a set's volumes go by: `x.rar, x.r00, ..` for an old-style first name, `x.7z.001, ..` for a split 7z,
/// `x.part1.rar, ..` otherwise.
fn volumes_named(first: &str, count: usize) -> Vec<String> {
    if let Some(stem) = first.strip_suffix(".7z.001") {
        return (1..=count).map(|i| format!("{stem}.7z.{i:03}")).collect();
    }
    if let Some(stem) = first.strip_suffix(".part1.rar") {
        return (1..=count).map(|i| format!("{stem}.part{i}.rar")).collect();
    }
    let stem = first.strip_suffix(".rar").or_else(|| first.strip_suffix(".7z")).unwrap();
    let ext = if first.ends_with(".7z") { "7z" } else { "rar" };
    std::iter::once(format!("{stem}.{ext}")).chain((0..count - 1).map(|i| format!("{stem}.r{i:02}"))).collect()
}

struct Fed {
    index: usize,
    sink: DirectSink,
    decoder: FeedDecoder,
}

/// Feeds every member of the set the feed decoder handles into direct partials, setting each decoder's snapshot
/// as its partial's cursor after every run; drops everything (a restart) after `cut` of the articles; finds the
/// partials again, restores each decoder from its partial's cursor and delivers every article (the lost ones too:
/// late repairs). Checks: nothing verified before its bytes are all there, exact output against a straight
/// extraction, `crc_ok`, `Verdict::Ok`, and every byte the durable state lacked written exactly once, nothing it
/// held written again. Returns the members fed.
fn restart_set(work: &Path, volumes: &[Vec<u8>], first: &str, password: Option<&str>, article: u64, cut: f64) -> usize {
    let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
    let map = MemberMap::from_memory(&refs, first, password).unwrap();
    let fed: Vec<usize> = (0..map.members.len())
        .filter(|&i| {
            let m = &map.members[i];
            !m.is_dir
                && m.unpacked_size.is_some_and(|s| s > 0)
                && FeedDecoder::new(&map, i, FeedOptions::new(password)).is_ok()
        })
        .collect();
    assert!(!fed.is_empty());
    let open = |work: &Path| {
        let (output_root, state_dir, anchors) = roots(work);
        DirectPartials::new(DirectOptions {
            binding: ArchiveBinding { job: [3; 16], archive: [4; 32] },
            output_root,
            state_dir,
            naming: PartialNaming::ArchivePath,
            limits: PartialLimits::for_members(fed.len()),
            progressive_limits: ProgressiveLimits::default(),
            anchors: Arc::new(anchor_store::DurableAnchors::open(&anchors).unwrap()),
            control: SessionControl::default(),
            protection: protection(volumes.len()),
            password: password.map(str::to_owned),
        })
        .unwrap()
    };
    let articles = Articles::new(volumes, article, 4, 23);
    let upto = ((articles.list.len() as f64 * cut) as usize).max(1);
    {
        let parts = open(work);
        let mut members: Vec<Fed> = fed
            .iter()
            .map(|&index| {
                let member = parts.open(&map, index).unwrap();
                assert_eq!(member.origin, DirectOrigin::Created);
                let decoder = FeedDecoder::new(&map, index, FeedOptions::new(password)).unwrap();
                Fed { index, sink: DirectSink::new(member.file), decoder }
            })
            .collect();
        let mut buffer = ArticleBuffer::new(usize::MAX);
        let mut source = Shared(&mut buffer);
        for i in 0..upto {
            if articles.lost[i] {
                let (v, at, len) = articles.list[i];
                source.0.mark_lost(v, at..at + len);
            } else {
                articles.insert(source.0, volumes, i);
            }
            for m in &mut members {
                m.decoder.run(&mut source, &mut m.sink).unwrap();
                m.sink.set_cursor(&m.decoder.snapshot().to_bytes()).unwrap();
            }
        }
        // the restart: every handle dropped without finishing (an open group and the last cursor commit then)
    }
    let parts = open(work);
    let reference = straight(work, volumes, first, password);
    let mut buffer = ArticleBuffer::new(usize::MAX);
    let mut members = Vec::new();
    let mut unknown = Vec::new();
    for &index in &fed {
        let member = parts.open(&map, index).unwrap();
        assert_eq!(member.origin, DirectOrigin::Adopted);
        let mut file = member.file;
        let gaps: u64 = file.remaining().unwrap().iter().map(|r| r.end - r.start).sum();
        if gaps > 0 {
            assert!(matches!(verify(&mut file), Verdict::Incomplete { .. }), "verified before its bytes are there");
        }
        unknown.push(gaps);
        let decoder = match file.cursor().unwrap() {
            Some(bytes) => FeedDecoder::restore(
                &map,
                index,
                FeedOptions::new(password),
                &FeedSnapshot::from_bytes(&bytes).unwrap(),
            )
            .unwrap(),
            None => FeedDecoder::new(&map, index, FeedOptions::new(password)).unwrap(),
        };
        members.push(Fed { index, sink: DirectSink::new(file), decoder });
    }
    assert!(unknown.iter().sum::<u64>() > 0, "the restart came before the feed was done");
    let mut source = Shared(&mut buffer);
    for i in 0..articles.list.len() {
        articles.insert(source.0, volumes, i);
        for m in &mut members {
            if !m.decoder.status().done {
                m.decoder.run(&mut source, &mut m.sink).unwrap();
                m.sink.set_cursor(&m.decoder.snapshot().to_bytes()).unwrap();
            }
        }
    }
    let mut used = vec![false; reference.len()];
    for (m, unknown) in members.into_iter().zip(unknown) {
        let status = m.decoder.status().clone();
        assert!(status.done && status.lost.is_empty(), "member {}: {status:?}", m.index);
        assert_ne!(status.crc_ok, Some(false), "member {}", m.index);
        assert_eq!(m.sink.applied_bytes(), unknown, "member {}: each byte the durable state lacked, once", m.index);
        let mut file = m.sink.into_file();
        match verify(&mut file) {
            Verdict::Ok { .. } => {}
            Verdict::Incomplete { holes, missing_checks: true, .. } if holes.is_empty() => {}
            other => panic!("member {}: {other:?}", m.index),
        }
        let out = std::fs::read(file.output_path()).unwrap();
        let found = reference.iter().enumerate().position(|(i, r)| !used[i] && *r == out);
        used[found.unwrap_or_else(|| panic!("member {}: output differs from the extraction", m.index))] = true;
    }
    fed.len()
}

/// The article buffer shared by every member's decoder, with releases ignored: members of one 7z folder read the
/// same packed bytes.
struct Shared<'a>(&'a mut ArticleBuffer);

impl zipfast::map::PackedSource for Shared<'_> {
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> zipfast::map::PackedRead {
        self.0.read_packed(volume, offset, buf)
    }
}

const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];

/// One compressed (method 3) RAR 5.0 member holding `plain`, AES with keyed checks (password "pw") when
/// `encrypted`, cut into volumes of at most `chunk` packed bytes.
fn rar5_compressed(plain: &[u8], encrypted: bool, chunk: usize) -> Vec<Vec<u8>> {
    use zipfast::rar5::testenc;
    let mut data = testenc::tuned_stream(&testenc::lz(plain, 1 << 17, 16), 2_000);
    let mut crc = crc32fast::hash(plain);
    let mut extra = Vec::new();
    let keys = encrypted.then(|| zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap());
    if let Some((key, hash_key)) = &keys {
        data.resize(data.len().div_ceil(16) * 16, 0);
        data = zipfast::crypto::encrypt_cbc(key, &IV, &data).unwrap();
        extra = vec![36, 1, 0, 2, 1];
        extra.extend(SALT);
        extra.extend(IV);
        crc = zipfast::crypto::rar5_tweak_crc32(crc, hash_key);
    }
    let mut spec = common::FileSpec::new("c.bin", &data);
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
            let mut bytes = common::SIG.to_vec();
            bytes.extend(common::main_block(true, if i == 0 { None } else { Some(i as u64) }));
            let part_crc = match (&keys, last) {
                (_, true) => crc,
                (Some((_, hash_key)), false) => zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(part), hash_key),
                (None, false) => crc32fast::hash(part),
            };
            bytes.extend(common::file_block(&spec, part, part_crc, i > 0, !last));
            bytes.extend(common::end_block(!last));
            bytes
        })
        .collect()
}

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

#[test]
fn compressed_rar5_restarts_from_its_cursor() {
    let tmp = tempfile::tempdir().unwrap();
    for (i, encrypted) in [false, true].into_iter().enumerate() {
        let volumes = rar5_compressed(&video_like(500_000, 7 + i as u64), encrypted, 90_000);
        let password = encrypted.then_some("pw");
        for (j, cut) in [0.3, 0.7].into_iter().enumerate() {
            let work = tmp.path().join(format!("{i}-{j}"));
            assert_eq!(restart_set(&work, &volumes, "set.part1.rar", password, 6_000, cut), 1);
        }
    }
}

#[test]
fn compressed_and_header_encrypted_rar4_restart_from_their_cursors() {
    let tmp = tempfile::tempdir().unwrap();
    let sets: [(&str, &[&str], Option<&str>); 3] = [
        (
            "rar4-rar300",
            &[
                "compressed_multivol_prng_rar300.rar",
                "compressed_multivol_prng_rar300.r00",
                "compressed_multivol_prng_rar300.r01",
                "compressed_multivol_prng_rar300.r02",
                "compressed_multivol_prng_rar300.r03",
            ],
            None,
        ),
        (
            "rar4-rar300",
            &["header_encrypted_multivol_rar300.rar", "header_encrypted_multivol_rar300.r00"],
            Some("password"),
        ),
        ("rar4-archiver", &["win-encvol.rar", "win-encvol.r00", "win-encvol.r01", "win-encvol.r02"], Some("testpw123")),
    ];
    for (i, (dir, names, password)) in sets.into_iter().enumerate() {
        let volumes = read_volumes(dir, names);
        let article = (volumes.iter().map(|v| v.len()).sum::<usize>() / 24).max(64) as u64;
        let work = tmp.path().join(format!("{i}"));
        assert!(restart_set(&work, &volumes, names[0], password, article, 0.5) >= 1);
    }
}

#[test]
fn seven_zip_lzma2_and_header_encrypted_restart_from_their_cursors() {
    let tmp = tempfile::tempdir().unwrap();
    // three members of one LZMA2 folder, cut into volumes
    let whole = read_volumes("7z", &["lzma2_chunks.7z"]).remove(0);
    let volumes: Vec<Vec<u8>> = whole.chunks(whole.len().div_ceil(3)).map(<[u8]>::to_vec).collect();
    for (j, cut) in [0.4, 0.8].into_iter().enumerate() {
        let fed = restart_set(&tmp.path().join(format!("lz-{j}")), &volumes, "chunks.7z.001", None, 4_000, cut);
        assert_eq!(fed, 3);
    }
    // 7zAES over Copy behind encrypted headers (-mhe)
    let volumes = read_volumes("7z", &["encrypted_headers.7z"]);
    assert_eq!(restart_set(&tmp.path().join("mhe"), &volumes, "e.7z", Some("password"), 500, 0.5), 1);
}

/// The cursor is committed with the output it describes: set with no group open it commits on its own; it comes
/// back after a reopen; a session-made member has none to set.
#[test]
fn a_cursor_commits_with_the_output_and_comes_back() {
    let tmp = tempfile::tempdir().unwrap();
    let data = payload(150_000, 9);
    let volumes = stored_set("p.bin", &data, 60_000, false);
    let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
    let map = MemberMap::from_memory(&refs, "set.part1.rar", None).unwrap();
    {
        let parts = direct(tmp.path(), volumes.len(), PartialLimits::default());
        let mut sink = DirectSink::new(parts.open(&map, 0).unwrap().file);
        assert_eq!(sink.file().cursor().unwrap(), None);
        sink.write_at(0, &data[..70_000]).unwrap();
        sink.set_cursor(b"first").unwrap();
        sink.commit().unwrap();
        // a cursor alone, no group open: the next ordinary operation commits it
        sink.set_cursor(b"second").unwrap();
        sink.file().remaining().unwrap();
        // set but never committed by an operation: the last handle's drop commits it
        sink.write_at(70_000, &data[70_000..80_000]).unwrap();
        sink.set_cursor(b"third").unwrap();
    }
    let parts = direct(tmp.path(), volumes.len(), PartialLimits::default());
    let member = parts.open(&map, 0).unwrap();
    assert_eq!(member.origin, DirectOrigin::Adopted);
    assert_eq!(member.file.cursor().unwrap().as_deref(), Some(&b"third"[..]));
    assert_eq!(member.file.remaining().unwrap(), vec![80_000..150_000]);
    // held output for a handover: the durable known bytes, no checks claimed verified yet
    let held = member.file.held_output().unwrap();
    assert_eq!(held.good, vec![0..80_000]);
    assert!(!held.finished);
}

/// A process aborted mid-feed with cursors set but not committed: the restart restores each decoder from the
/// cursor of the last commit, which never describes more than that commit's output.
#[test]
fn a_compressed_member_survives_an_abort_from_its_last_committed_cursor() {
    const NAME: &str = "a_compressed_member_survives_an_abort_from_its_last_committed_cursor";
    let volumes = rar5_compressed(&video_like(600_000, 21), true, 120_000);
    let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
    let map = MemberMap::from_memory(&refs, "set.part1.rar", Some("pw")).unwrap();
    let articles = Articles::new(&volumes, 5_000, 1_000_000, 29);
    let options = || FeedOptions::new(Some("pw"));
    let parts = |work: &Path| {
        let (output_root, state_dir, anchors) = roots(work);
        DirectPartials::new(DirectOptions {
            binding: ArchiveBinding { job: [5; 16], archive: [6; 32] },
            output_root,
            state_dir,
            naming: PartialNaming::ArchivePath,
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors: Arc::new(anchor_store::DurableAnchors::open(&anchors).unwrap()),
            control: SessionControl::default(),
            protection: protection(volumes.len()),
            password: Some("pw".into()),
        })
        .unwrap()
    };
    if let Some(work) = std::env::var_os(CHILD) {
        let work = PathBuf::from(work);
        let parts = parts(&work);
        let mut sink = DirectSink::new(parts.open(&map, 0).unwrap().file);
        let mut decoder = FeedDecoder::new(&map, 0, options()).unwrap();
        let mut buffer = ArticleBuffer::new(usize::MAX);
        let third = articles.list.len() / 3;
        for i in 0..2 * third {
            articles.insert(&mut buffer, &volumes, i);
            decoder.run(&mut buffer, &mut sink).unwrap();
            sink.set_cursor(&decoder.snapshot().to_bytes()).unwrap();
            if i + 1 == third {
                sink.commit().unwrap();
            }
        }
        std::process::abort();
    }
    let tmp = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, tmp.path())
        .status()
        .unwrap();
    assert!(!status.success(), "the child aborts");
    let parts = parts(tmp.path());
    let member = parts.open(&map, 0).unwrap();
    assert_eq!(member.origin, DirectOrigin::Adopted);
    let mut sink = DirectSink::new(member.file);
    let unknown: u64 = sink.file().remaining().unwrap().iter().map(|r| r.end - r.start).sum();
    let size = map.members[0].unpacked_size.unwrap();
    assert!(unknown > 0 && unknown < size, "{unknown} of {size}");
    let cursor = FeedSnapshot::from_bytes(&sink.file().cursor().unwrap().unwrap()).unwrap();
    // the committed cursor's frontier is within the committed output
    let mut decoder = FeedDecoder::restore(&map, 0, options(), &cursor).unwrap();
    assert!(decoder.status().frontier <= size - unknown, "{:?}", decoder.status());
    let mut buffer = ArticleBuffer::new(usize::MAX);
    for i in 0..articles.list.len() {
        articles.insert(&mut buffer, &volumes, i);
        if !decoder.run(&mut buffer, &mut sink).unwrap().done {
            continue;
        }
        break;
    }
    assert_eq!(decoder.status().crc_ok, Some(true));
    assert_eq!(sink.applied_bytes(), unknown);
    let mut file = sink.into_file();
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
}

/// A group commit whose anchor CAS lands but reports an error, with a cursor pending: the next operation resolves
/// the uncertain commit from the store instead of opening a cursor-only group on top of it.
#[test]
fn an_uncertain_commit_with_a_cursor_pending_is_reconciled() {
    let tmp = tempfile::tempdir().unwrap();
    let data = payload(90_000, 13);
    let volumes = stored_set("u.bin", &data, 40_000, false);
    let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
    let map = MemberMap::from_memory(&refs, "set.part1.rar", None).unwrap();
    let (output_root, state_dir, anchor_dir) = roots(tmp.path());
    let anchors = Arc::new(anchor_store::DurableAnchors::open(&anchor_dir).unwrap());
    let parts = DirectPartials::new(DirectOptions {
        binding: ArchiveBinding { job: [2; 16], archive: [2; 32] },
        output_root,
        state_dir,
        naming: PartialNaming::ArchivePath,
        limits: PartialLimits::default(),
        progressive_limits: ProgressiveLimits::default(),
        anchors: anchors.clone(),
        control: SessionControl::default(),
        protection: protection(volumes.len()),
        password: None,
    })
    .unwrap();
    let mut sink = DirectSink::new(parts.open(&map, 0).unwrap().file);
    sink.write_at(0, &data[..50_000]).unwrap();
    sink.set_cursor(b"one").unwrap();
    anchors.fail_after_rename(1);
    let error = sink.commit().unwrap_err();
    assert!(error.committed.is_some(), "{error:?}");
    // the commit landed in the store; the next operation reconciles with it and goes on
    assert_eq!(sink.file().remaining().unwrap(), vec![50_000..90_000]);
    assert_eq!(sink.file().cursor().unwrap().as_deref(), Some(&b"one"[..]));
    sink.write_at(50_000, &data[50_000..]).unwrap();
    sink.set_cursor(b"two").unwrap();
    let mut file = sink.into_file();
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(file.cursor().unwrap().as_deref(), Some(&b"two"[..]));
}
