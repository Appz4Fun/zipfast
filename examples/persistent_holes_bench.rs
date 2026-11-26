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

//! Times a persistent session over one big RAR5 stored member whose volumes have missing articles: the session
//! records them as holes, then `refill_from_packed` fills them from the volume files, as after a par2 repair, and
//! `poll_verify` checks the member. Reports wall time and zipfast's durable syncs for each phase.
//!
//! `cargo run --release --features persistent-partials --example persistent_holes_bench -- <work dir> [MiB]
//! [volumes] [holes] [hole KiB] [runs]`. Holes are spread evenly over the member's data; `ZF_GROUP_HOLES=1` turns on
//! `PartialLimits::group_holes`, `ZF_GROUP_REFILLS=1` `PartialLimits::group_refills`.
//!
//! `ZF_SET=<dir>` runs an existing RAR set instead (its `*.rar` volumes in name order; the MiB and volume arguments
//! are then ignored), `ZF_PASSWORD` sets its password, and `ZF_HOLES=v:offset:len,...` lists the packed ranges
//! answered as holes (volume index, offset in that volume file, length) in place of the generated ones. Every hole
//! is refilled on every member's handle. The summary also gives the session's extra time per hole (against a run
//! without holes) and the time per refill.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Instant,
};
use zipfast::partial::*;
use zipfast::progressive::*;

#[path = "../tests/common/mod.rs"]
mod common;
#[allow(dead_code, reason = "the shared doc store also carries fault hooks the benchmark does not use")]
mod anchor_store {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/persistent-anchor-store.rs"));
}

fn volume_name(index: u32) -> OsString {
    format!("big.part{:03}.rar", index + 1).into()
}
/// The volume names of an existing set: its `*.rar` files in name order.
fn set_names(dir: &Path) -> Vec<OsString> {
    let mut names: Vec<OsString> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .filter(|n| n.to_string_lossy().to_ascii_lowercase().ends_with(".rar"))
        .collect();
    names.sort();
    names
}

/// Writes the set once: a stored member of `size` bytes cut into `volumes` parts.
fn generate(dir: &Path, size: u64, volumes: u32) -> u64 {
    let done = dir.join("complete");
    if done.exists() {
        return size;
    }
    fs::create_dir_all(dir).unwrap();
    let chunk = size.div_ceil(volumes as u64);
    let mut whole = crc32fast::Hasher::new();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut written = 0u64;
    for index in 0..volumes {
        let len = chunk.min(size - written) as usize;
        let mut part = vec![0u8; len];
        for word in part.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            word.copy_from_slice(&bytes[..word.len()]);
        }
        whole.update(&part);
        written += len as u64;
        let last = index + 1 == volumes;
        let crc = if last { whole.clone().finalize() } else { crc32fast::hash(&part) };
        // The header carries the whole member's size.
        let mut spec = common::FileSpec::new("big.bin", &[]);
        spec.size = Some(size);
        let mut out = common::SIG.to_vec();
        out.extend(common::main_block(true, if index == 0 { None } else { Some(index as u64) }));
        out.extend(common::file_block(&spec, &part, crc, index > 0, !last));
        out.extend(common::end_block(!last));
        let mut file = File::create(dir.join(volume_name(index))).unwrap();
        file.write_all(&out).unwrap();
    }
    File::create(done).unwrap();
    size
}
struct DiskSource {
    index: u32,
    file: File,
    len: u64,
    /// Packed ranges answered as holes, as articles still missing.
    holes: Vec<std::ops::Range<u64>>,
}
impl RangeSource for DiskSource {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.index as u128 + 1),
            generation: 0,
            extent: self.len,
            length: SourceLength::Final(self.len),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        use std::os::unix::fs::FileExt;
        if let Some(hole) = self.holes.iter().find(|h| h.contains(&at)) {
            return Ok(RangeRead::Hole { len: (hole.end - at).min(buf.len() as u64) });
        }
        let next = self.holes.iter().filter(|h| h.start > at).map(|h| h.start).min().unwrap_or(self.len);
        let n = (next.min(self.len) - at).min(buf.len() as u64) as usize;
        let count = self.file.read_at(&mut buf[..n], at).unwrap();
        Ok(RangeRead::Filled { count })
    }
}
struct Provider {
    dir: PathBuf,
    names: Vec<OsString>,
    holes: Vec<(u32, std::ops::Range<u64>)>,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..self.names.len() as u32)
                    .map(|index| ProtectedVolume {
                        index,
                        name: self.names[index as usize].clone(),
                        backing: VolumeBacking::NonFile,
                    })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        })
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        if request.index as usize >= self.names.len() {
            return Ok(VolumeAnswer::Missing);
        }
        let file = File::open(self.dir.join(&self.names[request.index as usize])).unwrap();
        let len = file.metadata().unwrap().len();
        let holes = self.holes.iter().filter(|(v, _)| *v == request.index).map(|(_, r)| r.clone()).collect();
        Ok(VolumeAnswer::Ready(Box::new(DiskSource { index: request.index, file, len, holes })))
    }
}

fn options(dest: &Path, first: &OsString) -> ProgressiveOptions {
    let mut options = ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: dest.into(),
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
            damaged_input: Default::default(),
            salvage_truncated_zip: false,
            unix_modes: Default::default(),
            backslashes: Default::default(),
        },
        first.clone(),
    );
    options.limits.volume_handles = 4096;
    if let Some(password) = std::env::var_os("ZF_PASSWORD") {
        options.set_password(Some(password.into_string().unwrap())).unwrap();
    }
    options
}

/// Counts calls into the durable anchor store of the docs.
struct Counting {
    inner: anchor_store::DurableAnchors,
    cas: AtomicU64,
    current: AtomicU64,
}
impl StateAnchorStore for Counting {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        self.current.fetch_add(1, Ordering::Relaxed);
        self.inner.current(member)
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        self.cas.fetch_add(1, Ordering::Relaxed);
        self.inner.compare_exchange(member, expected, next)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let work = PathBuf::from(args.get(1).expect("work directory"));
    let mib: u64 = args.get(2).map_or(36, |s| s.parse().unwrap());
    let volumes: u32 = args.get(3).map_or(8, |s| s.parse().unwrap());
    let holes: u64 = args.get(4).map_or(3, |s| s.parse().unwrap());
    let hole_kib: u64 = args.get(5).map_or(750, |s| s.parse().unwrap());
    let runs: usize = args.get(6).map_or(5, |s| s.parse().unwrap());
    let (set, names, label) = match std::env::var_os("ZF_SET") {
        Some(dir) => {
            let set = PathBuf::from(dir);
            let names = set_names(&set);
            let label = set.file_name().unwrap().to_string_lossy().into_owned();
            (set, names, label)
        }
        None => {
            let set = work.join(format!("set-{mib}-{volumes}"));
            generate(&set, mib << 20, volumes);
            (set, (0..volumes).map(volume_name).collect(), format!("{mib} MiB, {volumes} volumes"))
        }
    };
    let ranges: Vec<(u32, std::ops::Range<u64>)> = match std::env::var("ZF_HOLES") {
        Ok(list) => list
            .split(',')
            .filter(|h| !h.is_empty())
            .map(|h| {
                let f: Vec<u64> = h.split(':').map(|x| x.parse().unwrap()).collect();
                (f[0] as u32, f[1]..f[1] + f[2])
            })
            .collect(),
        Err(_) if std::env::var_os("ZF_SET").is_some() => Vec::new(),
        Err(_) => generated_holes(&set, mib << 20, volumes, holes, hole_kib),
    };
    let mut best = [f64::MAX; 3];
    let mut best_clean = f64::MAX;
    // refill calls per run (every packed span of every hole report, cipher-neighbour reports included)
    let mut refills = 0u64;
    for _ in 0..runs {
        let (t, n) = run(&set, &work, &names, &ranges);
        refills = n;
        for i in 0..3 {
            best[i] = best[i].min(t[i]);
        }
        if !ranges.is_empty() {
            best_clean = best_clean.min(run(&set, &work, &names, &[]).0[0]);
        }
    }
    let count = ranges.len().max(1) as f64;
    let per_refill = refills.max(1) as f64;
    let hole_mib = ranges.iter().map(|(_, r)| r.end - r.start).sum::<u64>() as f64 / (1 << 20) as f64;
    println!(
        "{label}, {} holes ({hole_mib:.2} MiB): session {:.1} ms (clean {:.1} ms, {:.2} ms per hole), refill {:.1} ms \
         ({:.2} ms per refill of {refills}, {:.0} MiB/s), verify {:.1} ms (best of {runs})",
        ranges.len(),
        best[0] * 1e3,
        if ranges.is_empty() { best[0] * 1e3 } else { best_clean * 1e3 },
        if ranges.is_empty() { 0.0 } else { (best[0] - best_clean) * 1e3 / count },
        best[1] * 1e3,
        best[1] * 1e3 / per_refill,
        hole_mib / best[1].max(1e-9),
        best[2] * 1e3
    );
}

/// `holes` packed ranges of `hole_kib` spread evenly over the generated member's data.
fn generated_holes(set: &Path, size: u64, volumes: u32, holes: u64, hole_kib: u64) -> Vec<(u32, std::ops::Range<u64>)> {
    // Data offsets of each volume: a volume holds a fixed header before its part.
    let lens: Vec<u64> = (0..volumes).map(|i| fs::metadata(set.join(volume_name(i))).unwrap().len()).collect();
    let chunk = size.div_ceil(volumes as u64);
    let mut ranges = Vec::new();
    for k in 0..holes {
        // an output offset spread over the member, then the volume and packed offset holding it
        let out = size / (holes + 1) * (k + 1);
        let v = (out / chunk) as u32;
        let part_len = chunk.min(size - v as u64 * chunk);
        let data_start = lens[v as usize] - part_len - end_len(v + 1 == volumes);
        let at = data_start + out % chunk;
        let end = (at + (hole_kib << 10)).min(data_start + part_len);
        ranges.push((v, at..end));
    }
    ranges
}

/// The length of the end-of-archive block the generator writes after a part.
fn end_len(last: bool) -> u64 {
    common::end_block(!last).len() as u64
}

/// One run: the session with holes, then the refills, then verification. Returns the three phase times and the
/// number of refill calls made.
fn run(set: &Path, work: &Path, names: &[OsString], holes: &[(u32, std::ops::Range<u64>)]) -> ([f64; 3], u64) {
    let root = work.join("holes-run");
    let _ = fs::remove_dir_all(&root);
    for sub in ["out", "state", "anchors"] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    File::open(&root).unwrap().sync_all().unwrap();
    let anchors = Arc::new(Counting {
        inner: anchor_store::DurableAnchors::open(&root.join("anchors")).unwrap(),
        cas: AtomicU64::new(0),
        current: AtomicU64::new(0),
    });
    let partial = PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: root.join("state"),
        // `ZF_GROUP_HOLES=1`: holes join the open group (`PartialLimits::group_holes`).
        limits: PartialLimits {
            group_holes: std::env::var_os("ZF_GROUP_HOLES").is_some(),
            group_refills: std::env::var_os("ZF_GROUP_REFILLS").is_some(),
            ..PartialLimits::for_members(16)
        },
        anchors: anchors.clone(),
        control: SessionControl::default(),
    };
    let s0 = durable_sync_count();
    let l0 = exclusion_lstat_count();
    let start = Instant::now();
    let mut session = ProgressiveSession::new_partial(
        Box::new(Provider { dir: set.into(), names: names.to_vec(), holes: holes.to_vec() }),
        options(&root.join("out"), &names[0]),
        partial,
    )
    .unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut key = None;
    let mut handles = Vec::new();
    let mut reports = Vec::new();
    loop {
        match session.poll_event(&mut cx) {
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => key = Some(member),
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => reports.push(report),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => {
                if let Some(key) = key.take() {
                    handles.push((session.partial_file(&key).unwrap(), key));
                }
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            Poll::Ready(Err(error)) => panic!("{error:?}"),
            _ => {}
        }
    }
    drop(session);
    let session_time = start.elapsed().as_secs_f64();
    let s1 = durable_sync_count();
    let c1 = anchors.cas.load(Ordering::Relaxed);
    assert!(!handles.is_empty(), "a partial handle");
    // As RustyGet does after a repair: one refill per packed span of each reported hole, on the hole's member.
    let mut readers: Vec<Option<File>> = names.iter().map(|_| None).collect();
    let start = Instant::now();
    let mut refills = 0u64;
    for report in &reports {
        let (file, _) = handles.iter_mut().find(|(_, key)| *key == report.member).expect("the hole's member");
        for span in &report.packed {
            let reader = readers[span.volume as usize]
                .get_or_insert_with(|| File::open(set.join(&names[span.volume as usize])).unwrap());
            file.refill_from_packed(span.volume, span.range.clone(), reader).unwrap();
            refills += 1;
        }
    }
    // Grouped refills are durable at the group's commit: count that commit as part of the refill.
    for (file, _) in &handles {
        file.remaining().unwrap();
    }
    let refill_time = start.elapsed().as_secs_f64();
    let s2 = durable_sync_count();
    let c2 = anchors.cas.load(Ordering::Relaxed);
    let start = Instant::now();
    for (file, _) in &mut handles {
        loop {
            match file.poll_verify(&mut cx) {
                Poll::Ready(Ok(Verdict::Ok { .. })) => break,
                Poll::Ready(other) => panic!("verify {other:?}"),
                Poll::Pending => {}
            }
        }
    }
    let verify_time = start.elapsed().as_secs_f64();
    if !holes.is_empty() {
        eprintln!(
            "syncs: session {}, refill {}, verify {}; anchor CAS session {} refill {}; hole events {}, refills {refills}; \
             exclusion lstats {}",
            s1 - s0,
            s2 - s1,
            durable_sync_count() - s2,
            c1,
            c2 - c1,
            reports.len(),
            exclusion_lstat_count() - l0
        );
    }
    drop(handles);
    fs::remove_dir_all(&root).unwrap();
    ([session_time, refill_time, verify_time], refills)
}
