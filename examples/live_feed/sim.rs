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

//! The core of the `live_feed` example: a simulated Usenet download feeding [`FeedDecoder`]s, the way a downloader
//! such as RustyGet extracts while it downloads. `main.rs` is only the command line around [`run`];
//! `tests/live_feed.rs` runs the same code on small fixtures.
//!
//! The pieces, in the order data flows through them:
//!
//! 1. [`Articles`]: every volume cut into decoded articles (750,000 bytes by default), and the reverse lookup from
//!    a volume byte range to article indices that turns [`NeedBytes`] into download priority.
//! 2. [`Network`]: delivers the articles out of order (each up to `lateness` places late, or fully shuffled), with a
//!    choice among the next `window` arrivals; a `drop` fraction fails on the first try and comes back later as a
//!    repair.
//! 3. [`ArticleBuffer`]: holds what arrived ([`ArticleBuffer::insert`]) and what failed
//!    ([`ArticleBuffer::mark_lost`]); the decoders read from it and release what they passed.
//! 4. One [`FeedDecoder`] per member, run after every delivery; its [`FeedStatus::needs`] become the download
//!    priority ([`priority`]) the network picks its next delivery by.
//! 5. A [`FeedSink`] per member: a persistent partial (`PartialFile`, with the `persistent-partials` feature, for
//!    the stored RAR members it admits) or a plain preallocated file.
//!
//! The member map is built from the whole volumes up front: a downloader has the headers (the first article of
//! each volume, or a header map) before the data, and this example is about the data.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zipfast::map::{
    ArticleBuffer, FeedDecoder, FeedError, FeedOptions, FeedSink, FeedStatus, MemberMap, NeedKind, PackedRead,
    PackedSource,
};

/// The decoded size of a Usenet article as most posters cut them.
pub const ARTICLE: u64 = 750_000;

/// What one run simulates. [`Config::new`] gives the defaults the command line starts from.
#[derive(Clone, Debug)]
pub struct Config {
    /// The set's volumes, first first.
    pub volumes: Vec<PathBuf>,
    pub password: Option<String>,
    /// Decoded article size in bytes.
    pub article: u64,
    /// Seeds the arrival order and which articles fail.
    pub seed: u64,
    /// How many places late an article may arrive (0: in order); None shuffles the whole set.
    pub lateness: Option<usize>,
    /// How many of the next arrivals the network can choose between (1: no choice).
    pub window: usize,
    /// The fraction of articles that fail on their first try and are delivered later as repairs.
    pub drop: f64,
    /// A failed article can be fetched again this many deliveries after it failed; None: once the first pass is over
    /// (as when repairs come from a backup server or par2 at the end).
    pub repair_delay: Option<usize>,
    pub sink: SinkKind,
    /// `PartialLimits::group_holes`.
    pub group_holes: bool,
    /// `PartialLimits::group_refills`.
    pub group_refills: bool,
    /// `PartialLimits::group_commit_bytes` in MiB; None keeps the default (64 MiB).
    pub group_commit_mib: Option<u64>,
    /// `FeedOptions::max_needs`.
    pub max_needs: usize,
    /// The article buffer's byte limit.
    pub buffer_limit: usize,
    /// An empty or missing directory for the output, the partials' state and the straight extraction.
    pub work: PathBuf,
    /// Compare the output with a straight extraction of the set.
    pub verify: bool,
}

impl Config {
    pub fn new(volumes: Vec<PathBuf>, work: PathBuf) -> Self {
        Self {
            volumes,
            password: None,
            article: ARTICLE,
            seed: 1,
            lateness: Some(8),
            window: 4,
            drop: 0.05,
            repair_delay: None,
            sink: SinkKind::Auto,
            group_holes: false,
            group_refills: false,
            group_commit_mib: None,
            max_needs: 64,
            buffer_limit: usize::MAX,
            work,
            verify: true,
        }
    }
}

/// Where member output goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkKind {
    /// A persistent partial for each member the persistent path admits (stored RAR, no `-hp`), a plain file for the
    /// rest.
    Auto,
    /// Plain preallocated files only.
    File,
    /// Persistent partials only: fails when a fed member is not admitted (or without the feature).
    Partial,
}

/// What a run measured. [`Report::tsv`] prints it as one line.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub format: String,
    /// Members with data, and how many of them were fed (the rest have no feed decoder yet).
    pub members: usize,
    pub fed: usize,
    /// `partial`, `file` or `mixed`.
    pub sink: String,
    pub set_bytes: u64,
    /// The fed members' output size.
    pub output_bytes: u64,
    pub articles: usize,
    /// Articles that failed once.
    pub dropped: usize,
    /// Deliveries, failures included, before every member was done.
    pub deliveries: usize,
    /// Deliveries where the priority list picked another article than the next arrival.
    pub picks: usize,
    /// From the first byte of work (the partials' genesis) to every member written, committed and verified.
    pub wall: Duration,
    /// Creating the persistent partials (part of `wall`).
    pub genesis: Duration,
    /// Decoder runs after a repair arrived (part of `wall`).
    pub repair_time: Duration,
    /// Output bytes the decoders wrote, bytes decoded again without being written, packed bytes read.
    pub written: u64,
    pub redecoded: u64,
    pub packed_read: u64,
    /// Holes the main decodes met (`FeedStats::holes`).
    pub holes: u64,
    /// Sink writes into output reported lost before (repairs), and their bytes.
    pub refills: u64,
    pub refill_bytes: u64,
    /// Runs that ended with a compressed member waiting at a hole it cannot skip.
    pub stalls: u64,
    /// File and directory syncs: zipfast's (`durable_sync_count`) for partials, one per member for plain files.
    pub syncs: u64,
    pub peak_buffer: usize,
    /// Every fed member's `crc_ok` was true or None, and every partial verified `Verdict::Ok`.
    pub crc_ok: bool,
    /// The output equals a straight extraction (None when not checked).
    pub verified: Option<bool>,
}

impl Report {
    /// The column names of [`Self::tsv`].
    pub const HEADER: &'static str = "label\tformat\tmembers\tfed\tsink\tset_mb\tout_mb\tarticles\tdropped\tdeliveries\t\
         picks\twall_ms\tgenesis_ms\tmb_s\twritten\tredecoded\tpacked_read\tholes\trefills\trefill_bytes\trepair_ms\t\
         ms_per_hole\tstalls\tsyncs\tpeak_buf_mb\tcrc\tverify";

    /// One tab-separated line, columns as in [`Self::HEADER`]. `ms_per_hole` is the repair time per dropped article.
    pub fn tsv(&self, label: &str) -> String {
        let mb = |b: u64| b as f64 / 1e6;
        let ms = |d: Duration| d.as_secs_f64() * 1e3;
        let verify = match self.verified {
            Some(true) => "ok",
            Some(false) => "FAIL",
            None => "-",
        };
        format!(
            "{label}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.2}\t{}\t{}\t\
             {:.1}\t{}\t{verify}",
            self.format,
            self.members,
            self.fed,
            self.sink,
            mb(self.set_bytes),
            mb(self.output_bytes),
            self.articles,
            self.dropped,
            self.deliveries,
            self.picks,
            ms(self.wall),
            ms(self.genesis),
            mb(self.output_bytes) / self.wall.as_secs_f64().max(1e-9),
            self.written,
            self.redecoded,
            self.packed_read,
            self.holes,
            self.refills,
            self.refill_bytes,
            ms(self.repair_time),
            ms(self.repair_time) / self.dropped.max(1) as f64,
            self.stalls,
            self.syncs,
            mb(self.peak_buffer as u64),
            if self.crc_ok { "ok" } else { "FAIL" },
        )
    }
}

// ---- Articles: volume ranges <-> article indices ----

/// One decoded article: `len` bytes of volume `volume` from `offset`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Article {
    pub volume: u32,
    pub offset: u64,
    pub len: u64,
}

/// Every volume cut into articles of `size` bytes (the last of a volume shorter), numbered volume by volume.
pub struct Articles {
    pub list: Vec<Article>,
    /// Index of each volume's first article, and one past the last at the end.
    first: Vec<usize>,
    size: u64,
}

impl Articles {
    pub fn cut(volume_lens: &[u64], size: u64) -> Self {
        let mut list = Vec::new();
        let mut first = Vec::with_capacity(volume_lens.len() + 1);
        for (volume, &len) in volume_lens.iter().enumerate() {
            first.push(list.len());
            let mut offset = 0;
            while offset < len {
                list.push(Article { volume: volume as u32, offset, len: size.min(len - offset) });
                offset += size;
            }
        }
        first.push(list.len());
        Self { list, first, size }
    }

    /// The articles holding bytes `range` of volume `volume`: this is how a [`NeedBytes`] (a volume range) becomes
    /// articles to download. With equal-sized articles it is a division; a downloader with an NZB keeps each
    /// segment's offset instead and searches.
    pub fn covering(&self, volume: u32, range: Range<u64>) -> Range<usize> {
        let v = volume as usize;
        if v + 1 >= self.first.len() || range.start >= range.end {
            return 0..0;
        }
        let (base, next) = (self.first[v], self.first[v + 1]);
        let start = (base + (range.start / self.size) as usize).min(next);
        let end = (base + range.end.div_ceil(self.size) as usize).min(next);
        start..end
    }
}

/// The download priority the decoders' statuses ask for: article indices, most urgent first. Every
/// [`NeedKind::Next`] need of every member comes first (a main decode waits for it), then every
/// [`NeedKind::Repair`] (output reported lost), then every [`NeedKind::Ahead`] (read later, not held yet). Within a
/// kind, members keep archive order and each member its own need order. An article listed once keeps its first,
/// most urgent place.
pub fn priority<'a>(statuses: impl Iterator<Item = &'a FeedStatus> + Clone, articles: &Articles) -> Vec<usize> {
    let mut order = Vec::new();
    let mut listed = std::collections::HashSet::new();
    for kind in [NeedKind::Next, NeedKind::Repair, NeedKind::Ahead] {
        for status in statuses.clone() {
            for need in status.needs.iter().filter(|n| n.kind == kind) {
                for article in articles.covering(need.volume, need.range.clone()) {
                    if listed.insert(article) {
                        order.push(article);
                    }
                }
            }
        }
    }
    order
}

// ---- The simulated network ----

/// A small seeded generator (xorshift64*), so a seed gives the same run everywhere.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// Uniform in `0..n` (n > 0).
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, self.below(i as u64 + 1) as usize);
        }
    }
}

/// What the network does next.
enum Event {
    /// The article arrived (`repair`: on its second try).
    Deliver { article: usize, repair: bool },
    /// The article failed: the server does not have it (yet).
    Fail { article: usize },
}

/// Articles arrive in a jittered order; the downloader may pick among the next `window` (connections in flight),
/// and among failed articles that can be fetched again.
struct Network {
    /// First tries not made yet, in arrival order.
    queue: std::collections::VecDeque<usize>,
    /// Articles that fail on their first try.
    fails: Vec<bool>,
    /// Failed articles: (article, the delivery count from which it can be fetched again; usize::MAX: once the queue
    /// is empty).
    repairs: Vec<(usize, usize)>,
    window: usize,
    delay: Option<usize>,
    /// Deliveries and failures so far.
    tick: usize,
}

impl Network {
    fn new(count: usize, config: &Config) -> Self {
        let mut rng = Rng::new(config.seed);
        let mut order: Vec<usize> = (0..count).collect();
        match config.lateness {
            None => rng.shuffle(&mut order),
            // each article arrives up to `late` places after its turn
            Some(late) => {
                let due: Vec<usize> = (0..count).map(|i| i + rng.below(late as u64 + 1) as usize).collect();
                order.sort_by_key(|&i| (due[i], i));
            }
        }
        // exactly round(drop * count) articles fail once
        let mut pick: Vec<usize> = (0..count).collect();
        rng.shuffle(&mut pick);
        let mut fails = vec![false; count];
        let dropped = ((config.drop.clamp(0.0, 1.0) * count as f64).round() as usize).min(count);
        for &i in &pick[..dropped] {
            fails[i] = true;
        }
        Self {
            queue: order.into(),
            fails,
            repairs: Vec::new(),
            window: config.window.max(1),
            delay: config.repair_delay,
            tick: 0,
        }
    }

    /// The next event: the candidate the priority list ranks first (`rank`: article -> place), else the next
    /// arrival. Returns whether the priority changed the choice. None when nothing is left to deliver.
    fn next(&mut self, rank: &HashMap<usize, usize>) -> Option<(Event, bool)> {
        let queue_empty = self.queue.is_empty();
        let ready = |at: usize| if at == usize::MAX { queue_empty } else { at <= self.tick };
        if self.queue.is_empty() && !self.repairs.iter().any(|&(_, at)| ready(at)) {
            // only repairs with a delay left: let time pass
            let soonest = self.repairs.iter().map(|&(_, at)| at).min()?;
            self.tick = soonest;
        }
        let queue_empty = self.queue.is_empty();
        let ready = |at: usize| if at == usize::MAX { queue_empty } else { at <= self.tick };
        // candidates: (from the queue?, position there or in `repairs`, article)
        let mut candidates: Vec<(bool, usize, usize)> =
            self.queue.iter().take(self.window).enumerate().map(|(p, &a)| (true, p, a)).collect();
        candidates.extend(
            self.repairs.iter().enumerate().filter(|(_, (_, at))| ready(*at)).map(|(p, &(a, _))| (false, p, a)),
        );
        let default = *candidates.first()?;
        let chosen = candidates
            .iter()
            .copied()
            .min_by_key(|&(_, _, a)| rank.get(&a).copied().unwrap_or(usize::MAX))
            .filter(|&(_, _, a)| rank.contains_key(&a))
            .unwrap_or(default);
        let picked = chosen != default;
        self.tick += 1;
        let (from_queue, place, article) = chosen;
        let event = if from_queue {
            self.queue.remove(place);
            if self.fails[article] {
                let at = self.delay.map_or(usize::MAX, |d| self.tick + d);
                self.repairs.push((article, at));
                Event::Fail { article }
            } else {
                Event::Deliver { article, repair: false }
            }
        } else {
            self.repairs.remove(place);
            Event::Deliver { article, repair: true }
        };
        Some((event, picked))
    }
}

// ---- The packed source ----

/// The article buffer the decoders share. Releases are passed on only when no two fed members share packed bytes
/// (7z members of one folder do): a release by one decoder must not drop bytes another still reads.
struct Source {
    buffer: ArticleBuffer,
    release: bool,
}

impl PackedSource for Source {
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> PackedRead {
        self.buffer.read_packed(volume, offset, buf)
    }
    fn absent(&self, volume: u32, range: Range<u64>) -> Option<Vec<Range<u64>>> {
        self.buffer.absent(volume, range)
    }
    fn release(&mut self, volume: u32, range: Range<u64>) {
        if self.release {
            self.buffer.release(volume, range);
        }
    }
}

// ---- Sinks ----

/// Sorted, disjoint, merged ranges: the output a sink holds, for [`FeedSink::read_held`].
#[derive(Default)]
struct Ranges(Vec<Range<u64>>);

impl Ranges {
    fn insert(&mut self, r: Range<u64>) {
        let mut r = r;
        let at = self.0.partition_point(|x| x.end < r.start);
        let mut end = at;
        while end < self.0.len() && self.0[end].start <= r.end {
            r.start = r.start.min(self.0[end].start);
            r.end = r.end.max(self.0[end].end);
            end += 1;
        }
        self.0.splice(at..end, [r]);
    }
    /// How many bytes from `offset` are held, contiguously.
    fn held_from(&self, offset: u64) -> u64 {
        let at = self.0.partition_point(|x| x.end <= offset);
        self.0.get(at).filter(|x| x.start <= offset).map_or(0, |x| x.end - offset)
    }
}

/// Plain output: a preallocated file written in place, synced once at the end. It is not durable across a crash
/// (nothing records which bytes were written); it is the baseline the persistent partial is compared with.
struct FileSink {
    file: File,
    path: PathBuf,
    written: Ranges,
}

impl FileSink {
    fn create(path: PathBuf, size: u64) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::options().read(true).write(true).create_new(true).open(&path)?;
        file.set_len(size)?;
        Ok(Self { file, path, written: Ranges::default() })
    }
}

impl FeedSink for FileSink {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all_at(bytes, offset)?;
        self.written.insert(offset..offset + bytes.len() as u64);
        Ok(())
    }
    /// Gives back what this decoder wrote: compressed members rebuild their window from it after a restart.
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.written.held_from(offset).min(buf.len() as u64) as usize;
        self.file.read_exact_at(&mut buf[..n], offset)?;
        Ok(n)
    }
}

#[cfg(feature = "persistent-partials")]
mod persistent {
    //! The persistent-partial sink. A `PartialFile` exists only for a member a persistent session created, so the
    //! partials are made by a "genesis" session that reads the set's headers and is told every data byte is a hole
    //! (nothing has arrived yet): each admitted member gets its output file at full size, its state bundle and an
    //! anchor, with its whole output one hole per volume piece. From then on the feed decoder's output reaches the
    //! partial as plaintext fills of those holes, through a `FillWriter`, which joins the open group commit: one
    //! durable commit per `group_commit_bytes` of output, not per write.

    use super::*;
    use std::io::Write;
    use std::task::{Context, Poll, Waker};
    use zipfast::partial::*;
    use zipfast::progressive::*;

    #[allow(dead_code, reason = "the shared doc store also carries fault hooks the example does not use")]
    mod anchor_store {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/persistent-anchor-store.rs"));
    }

    pub(super) struct PartialSink {
        file: PartialFile,
        reader: File,
        written: Ranges,
    }

    fn io_err(e: PartialError) -> io::Error {
        io::Error::other(e.to_string())
    }

    impl PartialSink {
        pub(super) fn path(&self) -> PathBuf {
            self.file.output_path().to_path_buf()
        }
        /// Commits the open group and verifies the member's checks (`Verdict::Ok` once every byte is known).
        pub(super) fn finish(mut self) -> Result<bool, String> {
            self.file.remaining().map_err(|e| e.to_string())?;
            let mut cx = Context::from_waker(Waker::noop());
            loop {
                match self.file.poll_verify(&mut cx) {
                    Poll::Ready(Ok(Verdict::Ok { .. })) => return Ok(true),
                    Poll::Ready(Ok(other)) => {
                        eprintln!("partial {}: {other:?}", self.path().display());
                        return Ok(false);
                    }
                    Poll::Ready(Err(e)) => return Err(e.to_string()),
                    Poll::Pending => {}
                }
            }
        }
    }

    impl FeedSink for PartialSink {
        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
            // A writer per call: `flush` hands the bytes to the open group (no durable work of its own), and the
            // writer is dropped with nothing buffered. The group commits at its size or interval, or when the
            // handle's next ordinary operation runs.
            let mut writer = self.file.fill_writer(offset).map_err(io_err)?;
            writer.write_all(bytes)?;
            writer.flush()?;
            drop(writer);
            self.written.insert(offset..offset + bytes.len() as u64);
            Ok(())
        }
        fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            // Grouped writes are in the output file already, committed or not.
            let n = self.written.held_from(offset).min(buf.len() as u64) as usize;
            self.reader.read_exact_at(&mut buf[..n], offset)?;
            Ok(n)
        }
    }

    /// A volume in memory whose member data reads as holes.
    struct HeaderOnly {
        index: u32,
        bytes: Arc<Vec<u8>>,
        holes: Vec<Range<u64>>,
    }

    impl RangeSource for HeaderOnly {
        fn info(&self) -> SourceInfo {
            let len = self.bytes.len() as u64;
            SourceInfo {
                id: SourceId(self.index as u128 + 1),
                generation: 0,
                extent: len,
                length: SourceLength::Final(len),
            }
        }
        fn backing_files(&self) -> &[File] {
            &[]
        }
        fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            if let Some(hole) = self.holes.iter().find(|h| h.contains(&at)) {
                // one answer for the whole piece (the session accepts up to 256 MiB)
                return Ok(RangeRead::Hole { len: (hole.end - at).min(256 << 20) });
            }
            let next = self.holes.iter().filter(|h| h.start > at).map(|h| h.start).min().unwrap_or(u64::MAX);
            let end = (self.bytes.len() as u64).min(next).min(at + buf.len() as u64);
            let count = end.saturating_sub(at) as usize;
            buf[..count].copy_from_slice(&self.bytes[at as usize..at as usize + count]);
            Ok(RangeRead::Filled { count })
        }
    }

    struct Provider {
        names: Vec<std::ffi::OsString>,
        volumes: Vec<Arc<Vec<u8>>>,
        holes: Vec<Vec<Range<u64>>>,
    }

    impl VolumeSource for Provider {
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            let volumes = (0..self.names.len() as u32)
                .map(|index| ProtectedVolume {
                    index,
                    name: self.names[index as usize].clone(),
                    backing: VolumeBacking::NonFile,
                })
                .collect();
            Ok(ProtectionDeclaration::Complete {
                epoch: 1,
                inventory: ProtectionInventory { volumes, auxiliary_paths: Vec::new() },
            })
        }
        fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            let i = request.index as usize;
            if i >= self.volumes.len() {
                return Ok(VolumeAnswer::Missing);
            }
            Ok(VolumeAnswer::Ready(Box::new(HeaderOnly {
                index: request.index,
                bytes: self.volumes[i].clone(),
                holes: self.holes[i].clone(),
            })))
        }
    }

    /// Whether the persistent path admits the set at all: RAR without encrypted headers. Members it does not
    /// admit (compressed, encrypted RAR 4.x) are refused one by one by the session.
    pub(super) fn admits(map: &MemberMap) -> bool {
        matches!(map.format, zipfast::map::MapFormat::Rar5 | zipfast::map::MapFormat::Rar4) && !map.header_encrypted
    }

    /// Runs the genesis session over `volumes` and returns a sink per admitted member, keyed by its stored name.
    pub(super) fn genesis(
        config: &Config,
        map: &MemberMap,
        volumes: &[Arc<Vec<u8>>],
        dest: &Path,
    ) -> Result<HashMap<Vec<u8>, PartialSink>, String> {
        let root = config.work.join("partial");
        for sub in ["state", "anchors"] {
            fs::create_dir_all(root.join(sub)).map_err(|e| e.to_string())?;
        }
        fs::create_dir_all(dest).map_err(|e| e.to_string())?;
        for dir in [&root, &config.work] {
            File::open(dir).and_then(|d| d.sync_all()).map_err(|e| e.to_string())?;
        }
        let anchors = Arc::new(anchor_store::DurableAnchors::open(&root.join("anchors")).map_err(|e| e.to_string())?);
        let mut holes = vec![Vec::new(); volumes.len()];
        for member in &map.members {
            for piece in &member.pieces {
                holes[piece.volume as usize].push(piece.packed.clone());
            }
        }
        let names: Vec<std::ffi::OsString> =
            config.volumes.iter().map(|p| p.file_name().unwrap_or_default().to_owned()).collect();
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
            },
            names[0].clone(),
        );
        options.limits.volume_handles = 4096;
        options.set_password(config.password.clone()).map_err(|e| format!("{e:?}"))?;
        let mut limits = PartialLimits {
            group_holes: config.group_holes,
            group_refills: config.group_refills,
            ..PartialLimits::default()
        };
        if let Some(mib) = config.group_commit_mib {
            limits.group_commit_bytes = mib << 20;
        }
        let partial = PartialOptions {
            binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
            naming: PartialNaming::ArchivePath,
            state_dir: root.join("state"),
            limits,
            anchors,
            control: SessionControl::default(),
        };
        let provider = Provider { names, volumes: volumes.to_vec(), holes };
        let mut session =
            ProgressiveSession::new_partial(Box::new(provider), options, partial).map_err(|e| format!("{e:?}"))?;
        let mut cx = Context::from_waker(Waker::noop());
        let mut name = Vec::new();
        let mut key = None;
        let mut sinks = HashMap::new();
        loop {
            match session.poll_event(&mut cx) {
                Poll::Ready(Ok(None)) => break,
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { name: n, .. }))) => name = n.to_vec(),
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => key = Some(member),
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => {
                    if let Some(member) = key.take() {
                        let file = session.partial_file(&member).map_err(|e| e.to_string())?;
                        let reader = File::open(file.output_path()).map_err(|e| e.to_string())?;
                        sinks.insert(
                            std::mem::take(&mut name),
                            PartialSink { file, reader, written: Ranges::default() },
                        );
                    }
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                    return Err(format!("genesis session: {failure:?}"));
                }
                Poll::Ready(Err(e)) => return Err(format!("genesis session: {e:?}")),
                _ => {}
            }
        }
        Ok(sinks)
    }

    pub(super) fn syncs() -> u64 {
        durable_sync_count()
    }
}

/// A member's sink, counting repair writes.
struct Sink {
    out: Out,
    /// The end of the furthest write: a write before it fills output reported lost earlier.
    end: u64,
    refills: u64,
    refill_bytes: u64,
}

enum Out {
    File(FileSink),
    #[cfg(feature = "persistent-partials")]
    Partial(persistent::PartialSink),
}

impl FeedSink for Sink {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if offset < self.end {
            self.refills += 1;
            self.refill_bytes += bytes.len() as u64;
        }
        self.end = self.end.max(offset + bytes.len() as u64);
        match &mut self.out {
            Out::File(f) => f.write_at(offset, bytes),
            #[cfg(feature = "persistent-partials")]
            Out::Partial(p) => p.write_at(offset, bytes),
        }
    }
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.out {
            Out::File(f) => f.read_held(offset, buf),
            #[cfg(feature = "persistent-partials")]
            Out::Partial(p) => p.read_held(offset, buf),
        }
    }
}

impl Sink {
    fn path(&self) -> PathBuf {
        match &self.out {
            Out::File(f) => f.path.clone(),
            #[cfg(feature = "persistent-partials")]
            Out::Partial(p) => p.path(),
        }
    }
    /// Makes the output durable and checks it: returns (verified, syncs issued here).
    fn finish(self) -> Result<(bool, u64), String> {
        match self.out {
            Out::File(f) => {
                f.file.sync_all().map_err(|e| e.to_string())?;
                Ok((true, 1))
            }
            // counted through `durable_sync_count`
            #[cfg(feature = "persistent-partials")]
            Out::Partial(p) => Ok((p.finish()?, 0)),
        }
    }
}

/// One member being fed.
struct Member {
    index: usize,
    name: String,
    size: u64,
    decoder: FeedDecoder,
    sink: Sink,
    status: FeedStatus,
}

// ---- The run ----

/// Lists a set directory's volumes in order: `.partN.rar` and `.7z.NNN` by number, an old-style `.rar` before its
/// `.rNN`. Other files (par2, json, nfo) are left out.
pub fn volumes_in(dir: &Path) -> io::Result<Vec<PathBuf>> {
    fn is_volume(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        let ext = lower.rsplit('.').next().unwrap_or("");
        let numbered = ext.len() >= 2 && ext.chars().skip(1).all(|c| c.is_ascii_digit());
        lower.ends_with(".rar")
            || lower.ends_with(".7z")
            || lower.ends_with(".zip")
            || (numbered && (ext.starts_with('r') || ext.starts_with('z')))
            || (ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()))
    }
    /// Natural order: digit runs compare as numbers.
    fn key(name: &str) -> (bool, Vec<(String, u64)>) {
        let lower = name.to_ascii_lowercase();
        let old_first = lower.ends_with(".rar") && !lower.contains(".part");
        let mut parts = Vec::new();
        let mut text = String::new();
        let mut chars = lower.chars().peekable();
        while let Some(c) = chars.next() {
            if c.is_ascii_digit() {
                let mut n = c.to_digit(10).unwrap() as u64;
                while let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                    n = n.saturating_mul(10).saturating_add(d as u64);
                    chars.next();
                }
                parts.push((std::mem::take(&mut text), n));
            } else {
                text.push(c);
            }
        }
        parts.push((text, 0));
        (!old_first, parts)
    }
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.file_name().and_then(|n| n.to_str()).is_some_and(is_volume))
        .collect();
    files.sort_by_cached_key(|p| key(p.file_name().and_then(|n| n.to_str()).unwrap_or("")));
    Ok(files)
}

fn output_name(name: &str) -> String {
    name.chars().map(|c| if matches!(c, '/' | '\\' | ':') { '_' } else { c }).collect()
}

/// Simulates the download of `config.volumes` and feeds it through the decoders. See the module docs.
pub fn run(config: &Config) -> Result<Report, String> {
    let mut report = Report::default();
    // The "network": the volume files in memory, cut into articles.
    let volumes: Vec<Arc<Vec<u8>>> = config
        .volumes
        .iter()
        .map(|p| fs::read(p).map(Arc::new).map_err(|e| format!("{}: {e}", p.display())))
        .collect::<Result<_, _>>()?;
    let first = config.volumes.first().ok_or("no volumes")?;
    let refs: Vec<&[u8]> = volumes.iter().map(|v| v.as_slice()).collect();
    let map = MemberMap::from_memory(&refs, first.file_name().unwrap_or_default(), config.password.as_deref())
        .map_err(|e| format!("map: {e:?}"))?;
    report.format = format!("{:?}", map.format).to_lowercase();
    report.set_bytes = volumes.iter().map(|v| v.len() as u64).sum();
    let articles = Articles::cut(&volumes.iter().map(|v| v.len() as u64).collect::<Vec<_>>(), config.article.max(1));
    report.articles = articles.list.len();
    fs::create_dir_all(&config.work).map_err(|e| e.to_string())?;
    let dest = config.work.join("feed");

    let start = Instant::now();
    #[cfg(feature = "persistent-partials")]
    let syncs_before = persistent::syncs();

    // Sinks: the persistent partials first (their genesis reads only headers), then plain files.
    #[cfg(feature = "persistent-partials")]
    let mut partials = if config.sink != SinkKind::File && persistent::admits(&map) {
        persistent::genesis(config, &map, &volumes, &dest)?
    } else {
        HashMap::new()
    };
    #[cfg(not(feature = "persistent-partials"))]
    {
        if config.sink == SinkKind::Partial {
            return Err("--sink partial needs the persistent-partials feature".into());
        }
        if config.group_holes || config.group_refills || config.group_commit_mib.is_some() {
            eprintln!("note: the --group-* options only apply to persistent partials (build with persistent-partials)");
        }
    }
    report.genesis = start.elapsed();

    let mut members = Vec::new();
    let mut kinds = (0, 0); // (partial, file)
    for (index, m) in map.members.iter().enumerate() {
        let Some(size) = m.unpacked_size.filter(|&s| s > 0 && !m.is_dir) else { continue };
        report.members += 1;
        let options = FeedOptions { max_needs: config.max_needs, ..FeedOptions::new(config.password.as_deref()) };
        let decoder = match FeedDecoder::new(&map, index, options) {
            Ok(d) => d,
            Err(FeedError::Unsupported(why)) => {
                eprintln!("member {index} ({:?}): not fed: {why:?}", m.name);
                continue;
            }
            Err(e) => return Err(format!("member {index}: {e}")),
        };
        let name = m.name.clone().unwrap_or_else(|| format!("member{index}"));
        #[cfg(feature = "persistent-partials")]
        let partial = partials.remove(&m.raw_name);
        #[cfg(not(feature = "persistent-partials"))]
        let partial: Option<()> = None;
        let out = match partial {
            #[cfg(feature = "persistent-partials")]
            Some(p) => {
                kinds.0 += 1;
                Out::Partial(p)
            }
            #[cfg(not(feature = "persistent-partials"))]
            Some(()) => unreachable!(),
            None if config.sink == SinkKind::Partial => {
                return Err(format!("member {index} ({name}): no persistent partial (the persistent path refuses it)"));
            }
            None => {
                kinds.1 += 1;
                let path = dest.join(output_name(&name));
                Out::File(FileSink::create(path, size).map_err(|e| e.to_string())?)
            }
        };
        report.output_bytes += size;
        let sink = Sink { out, end: 0, refills: 0, refill_bytes: 0 };
        members.push(Member { index, name, size, decoder, sink, status: FeedStatus::default() });
    }
    report.fed = members.len();
    report.sink = match kinds {
        (0, _) => "file",
        (_, 0) => "partial",
        _ => "mixed",
    }
    .into();
    if members.is_empty() {
        return Err("no member can be fed".into());
    }

    // Releases are safe only when the fed members' packed bytes are disjoint.
    let mut spans: Vec<(u32, u64, u64)> = members
        .iter()
        .flat_map(|m| map.members[m.index].pieces.iter().map(|p| (p.volume, p.packed.start, p.packed.end)))
        .collect();
    spans.sort();
    let disjoint = spans.windows(2).all(|w| w[0].0 != w[1].0 || w[0].2 <= w[1].1);
    let mut source = Source { buffer: ArticleBuffer::new(config.buffer_limit), release: disjoint };
    let mut network = Network::new(articles.list.len(), config);
    report.dropped = network.fails.iter().filter(|&&f| f).count();

    // Run every member once before anything arrives: the first needs say where to start.
    let mut repair_run = false;
    loop {
        let run_start = Instant::now();
        for m in members.iter_mut().filter(|m| !m.status.done) {
            m.status = m.decoder.run(&mut source, &mut m.sink).map_err(|e| format!("member {}: {e}", m.index))?;
            report.stalls += m.status.stalled as u64;
        }
        if repair_run {
            report.repair_time += run_start.elapsed();
        }
        if members.iter().all(|m| m.status.done) {
            break;
        }
        // NeedBytes -> download priority -> the next delivery.
        let order = priority(members.iter().map(|m| &m.status), &articles);
        let rank: HashMap<usize, usize> = order.iter().enumerate().map(|(place, &a)| (a, place)).collect();
        let Some((event, picked)) = network.next(&rank) else {
            let stuck: Vec<_> = members.iter().filter(|m| !m.status.done).map(|m| (m.index, &m.status)).collect();
            return Err(format!("every article delivered, members not done: {stuck:?}"));
        };
        report.deliveries += 1;
        report.picks += picked as usize;
        repair_run = false;
        match event {
            Event::Deliver { article, repair } => {
                let a = articles.list[article];
                let bytes = &volumes[a.volume as usize][a.offset as usize..(a.offset + a.len) as usize];
                source.buffer.insert(a.volume, a.offset, bytes).map_err(|e| format!("{e}; raise --buffer-mib"))?;
                report.peak_buffer = report.peak_buffer.max(source.buffer.held());
                repair_run = repair;
            }
            Event::Fail { article } => {
                let a = articles.list[article];
                source.buffer.mark_lost(a.volume, a.offset..a.offset + a.len);
            }
        }
    }

    // Collect the counters, make the output durable and check it.
    report.crc_ok = true;
    let mut outputs = Vec::new();
    for m in members {
        let stats = m.decoder.stats();
        report.written += stats.written;
        report.redecoded += stats.redecoded;
        report.packed_read += stats.packed_read;
        report.holes += stats.holes;
        report.refills += m.sink.refills;
        report.refill_bytes += m.sink.refill_bytes;
        if m.status.crc_ok == Some(false) {
            eprintln!("member {} ({}): CRC mismatch", m.index, m.name);
            report.crc_ok = false;
        }
        let path = m.sink.path();
        let (ok, syncs) = m.sink.finish()?;
        report.crc_ok &= ok;
        report.syncs += syncs;
        outputs.push((m.index, m.size, path));
    }
    #[cfg(feature = "persistent-partials")]
    {
        report.syncs += persistent::syncs() - syncs_before;
    }
    report.wall = start.elapsed();

    if config.verify {
        report.verified = Some(verify(config, &map, &outputs)?);
    }
    Ok(report)
}

/// Extracts the set the ordinary way and compares every fed member's output with it, byte for byte.
fn verify(config: &Config, map: &MemberMap, outputs: &[(usize, u64, PathBuf)]) -> Result<bool, String> {
    let straight = config.work.join("straight");
    let options = zipfast::extract::Options {
        mode: zipfast::extract::Mode::Extract,
        dest: straight.clone(),
        overwrite: zipfast::extract::Overwrite::Always,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: false,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
    };
    zipfast::extract::run_with_password(&config.volumes[0], &options, config.password.as_deref(), |_| {})
        .map_err(|e| format!("straight extraction: {e}"))?;
    let mut all = true;
    for (index, size, path) in outputs {
        let name = map.members[*index].name.clone().unwrap_or_default().replace('\\', "/");
        let same = same_bytes(path, &straight.join(&name), *size).map_err(|e| format!("{name}: {e}"))?;
        if !same {
            eprintln!("member {index} ({name}): output differs from the straight extraction");
        }
        all &= same;
    }
    Ok(all)
}

fn same_bytes(a: &Path, b: &Path, size: u64) -> io::Result<bool> {
    let (fa, fb) = (File::open(a)?, File::open(b)?);
    if fa.metadata()?.len() != size || fb.metadata()?.len() != size {
        return Ok(false);
    }
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    let mut at = 0;
    while at < size {
        let n = (size - at).min(1 << 20) as usize;
        fa.read_exact_at(&mut ba[..n], at)?;
        fb.read_exact_at(&mut bb[..n], at)?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
        at += n as u64;
    }
    Ok(true)
}
