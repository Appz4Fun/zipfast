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

//! Times one big RAR5 stored member over many local volumes: a persistent session (`new_partial`, with a durable
//! anchor store on the same disk) against a plain progressive extraction of the same set.
//!
//! `cargo run --release --features persistent-partials --example persistent_bench -- <work dir> [MiB] [volumes]
//! [plain|persistent|both]`; set `ZF_GROUP_MIB` to override `PartialLimits::group_commit_bytes`.
//!
//! `ZF_SET=<dir>` runs an existing set instead: every `*.rar` in it, in name order (for example a RustyGet
//! z-fixture), with `ZF_PASSWORD` for an encrypted one. `ZF_RUNS` repeats each run and reports the best.
//!
//! The volumes are generated once into `<work dir>/set-<MiB>-<volumes>` and reused. Each run extracts into a fresh
//! directory under `<work dir>` and removes it afterwards. The persistent run also reports durable syncs issued by
//! zipfast and the anchor store's CAS and `current` calls, each per GiB of output.

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
    match std::env::var_os("ZF_SET") {
        Some(dir) => existing_names(Path::new(&dir))[index as usize].clone(),
        None => format!("big.part{:03}.rar", index + 1).into(),
    }
}

/// The `*.rar` volumes of an existing set, in name order (`r.part1.rar` .. `r.part7.rar` sort correctly below ten).
fn existing_names(dir: &Path) -> Vec<OsString> {
    let mut names: Vec<OsString> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().ends_with(".rar"))
        .collect();
    names.sort_by_key(|n| {
        let s = n.to_string_lossy().into_owned();
        let digits: String = s.chars().filter(char::is_ascii_digit).collect();
        (digits.len(), s)
    });
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
        let n = (self.len - at).min(buf.len() as u64) as usize;
        let count = self.file.read_at(&mut buf[..n], at).unwrap();
        Ok(RangeRead::Filled { count })
    }
}
struct Provider {
    dir: PathBuf,
    volumes: u32,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..self.volumes)
                    .map(|index| ProtectedVolume { index, name: volume_name(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        })
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        if request.index >= self.volumes {
            return Ok(VolumeAnswer::Missing);
        }
        let file = File::open(self.dir.join(volume_name(request.index))).unwrap();
        let len = file.metadata().unwrap().len();
        Ok(VolumeAnswer::Ready(Box::new(DiskSource { index: request.index, file, len })))
    }
}

fn options(dest: &Path) -> ProgressiveOptions {
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
            unix_modes: Default::default(),
            backslashes: Default::default(),
        },
        volume_name(0),
    );
    options.limits.volume_handles = 4096;
    if let Ok(password) = std::env::var("ZF_PASSWORD") {
        options.set_password(Some(password)).unwrap();
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

fn drive(session: &mut ProgressiveSession) {
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        match session.poll_event(&mut cx) {
            Poll::Ready(Ok(None)) => return,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => match outcome {
                MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. } => {}
                MemberOutcome::PersistentComplete { verdict, .. } => panic!("verdict {verdict:?}"),
                MemberOutcome::PersistentPartial { .. } => panic!("member left partial"),
                _ => {}
            },
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            Poll::Ready(Err(error)) => panic!("{error:?}"),
            _ => {}
        }
    }
}

fn plain(set: &Path, work: &Path, volumes: u32) -> f64 {
    let dest = work.join("plain-out");
    let _ = fs::remove_dir_all(&dest);
    fs::create_dir_all(&dest).unwrap();
    let start = Instant::now();
    let mut session = ProgressiveSession::new(Box::new(Provider { dir: set.into(), volumes }), options(&dest)).unwrap();
    drive(&mut session);
    drop(session);
    let elapsed = start.elapsed().as_secs_f64();
    fs::remove_dir_all(&dest).unwrap();
    elapsed
}

fn persistent(set: &Path, work: &Path, volumes: u32, size: u64) -> f64 {
    let root = work.join("persistent-run");
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
        // `ZF_GROUP_MIB` overrides the group size (0: one transaction per write) and disables the interval.
        limits: match std::env::var("ZF_GROUP_MIB") {
            Ok(mib) => PartialLimits {
                group_commit_bytes: mib.parse::<u64>().unwrap() << 20,
                group_commit_interval: std::time::Duration::from_secs(3600),
                ..PartialLimits::default()
            },
            Err(_) => PartialLimits::default(),
        },
        anchors: anchors.clone(),
        control: SessionControl::default(),
    };
    let syncs = durable_sync_count();
    let lstats = exclusion_lstat_count();
    let start = Instant::now();
    let mut session = ProgressiveSession::new_partial(
        Box::new(Provider { dir: set.into(), volumes }),
        options(&root.join("out")),
        partial,
    )
    .unwrap();
    drive(&mut session);
    drop(session);
    let elapsed = start.elapsed().as_secs_f64();
    let gib = size as f64 / (1u64 << 30) as f64;
    let syncs = durable_sync_count() - syncs;
    let lstats = exclusion_lstat_count() - lstats;
    let cas = anchors.cas.load(Ordering::Relaxed);
    let current = anchors.current.load(Ordering::Relaxed);
    println!(
        "persistent counts: zipfast syncs {syncs} ({:.0}/GiB), anchor CAS {cas} ({:.0}/GiB), anchor current {current} \
         ({:.0}/GiB); anchor-store syncs (2 per CAS, 1 per current) {:.0}/GiB; exclusion lstats {lstats}",
        syncs as f64 / gib,
        cas as f64 / gib,
        current as f64 / gib,
        (2 * cas + current) as f64 / gib,
    );
    if std::env::var_os("ZF_SET").is_none() {
        assert_eq!(fs::metadata(root.join("out/big.bin")).unwrap().len(), size);
    }
    fs::remove_dir_all(&root).unwrap();
    elapsed
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let work = PathBuf::from(args.get(1).expect("work directory"));
    let mib: u64 = args.get(2).map_or(2048, |s| s.parse().unwrap());
    let volumes: u32 = args.get(3).map_or(40, |s| s.parse().unwrap());
    let which = args.get(4).map_or("both", String::as_str);
    let (set, size, volumes, mib) = match std::env::var_os("ZF_SET") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            let names = existing_names(&dir);
            let size: u64 = names.iter().map(|n| fs::metadata(dir.join(n)).unwrap().len()).sum();
            (dir, size, names.len() as u32, size >> 20)
        }
        None => {
            let set = work.join(format!("set-{mib}-{volumes}"));
            let size = generate(&set, mib << 20, volumes);
            (set, size, volumes, mib)
        }
    };
    let runs: usize = std::env::var("ZF_RUNS").map_or(1, |r| r.parse().unwrap());
    let gib = size as f64 / (1u64 << 30) as f64;
    let mut times = (None, None);
    if which != "persistent" {
        let t = (0..runs).map(|_| plain(&set, &work, volumes)).fold(f64::MAX, f64::min);
        println!("plain progressive: {t:.2} s ({:.0} MiB/s)", mib as f64 / t);
        times.0 = Some(t);
    }
    if which != "plain" {
        let t = (0..runs).map(|_| persistent(&set, &work, volumes, size)).fold(f64::MAX, f64::min);
        println!("persistent: {t:.2} s ({:.0} MiB/s, {:.1} s/GiB)", mib as f64 / t, t / gib);
        times.1 = Some(t);
    }
    if let (Some(plain), Some(persistent)) = times {
        println!("ratio persistent/plain: {:.2}", persistent / plain);
    }
}
