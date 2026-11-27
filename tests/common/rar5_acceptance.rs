// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//! Test-only wire construction and independent physical-to-inner expectations.
use crate::common;
use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::{blake2sp::Blake2sp, crypto::AesKey, progressive::*};

const BUFFER: usize = 700_000;
const PASSWORD: &str = "task7-original-fixture";
const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];

#[derive(Clone, Debug)]
struct Part {
    start: u64,
    len: u64,
    payload: u64,
    physical: u64,
    digest: [u8; 32],
}

pub struct Fixture {
    dir: PathBuf,
    pub size: u64,
    article: u64,
    encrypted: bool,
    crc: u32,
    digest: [u8; 32],
    parts: Vec<Part>,
    losses: Vec<(usize, Range<u64>)>,
    expected: Vec<OutputHole>,
}

pub fn large_root() -> PathBuf {
    let p = PathBuf::from(std::env::var_os("ZIPFAST_TASK7_FIXTURES").expect("explicit persistent fixture path"));
    assert!(p.is_absolute());
    assert_eq!(std::env::var("ZIPFAST_TASK7_LARGE_LEASE").as_deref(), Ok("granted"));
    p
}

pub fn persistent_fast_dir(label: &str) -> PathBuf {
    let parent = std::env::var_os("ZIPFAST_TASK7_FAST_EVIDENCE").map(PathBuf::from);
    if let Some(parent) = &parent {
        fs::create_dir_all(parent).unwrap();
    }
    let mut builder = tempfile::Builder::new();
    let prefix = format!("rar5-task7-{label}-");
    builder.prefix(&prefix);
    let dir = match parent {
        Some(p) => builder.tempdir_in(p),
        None => builder.tempdir(),
    }
    .unwrap()
    .keep();
    eprintln!("Task7 preserved fixture/evidence: {}", dir.display());
    dir
}

fn mix(mut n: u64) -> u64 {
    n = n.wrapping_add(0x9e3779b97f4a7c15);
    n = (n ^ (n >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    n = (n ^ (n >> 27)).wrapping_mul(0x94d049bb133111eb);
    n ^ (n >> 31)
}

fn pattern(at: u64, out: &mut [u8]) {
    let mut done = 0;
    while done < out.len() {
        let pos = at + done as u64;
        let word = mix((pos / 8) ^ 0x7461736b37726172).to_le_bytes();
        let skip = (pos % 8) as usize;
        let n = (8 - skip).min(out.len() - done);
        out[done..done + n].copy_from_slice(&word[skip..skip + n]);
        done += n;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

fn unhex(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

fn file_digest(path: &Path) -> [u8; 32] {
    let mut f = File::open(path).unwrap();
    let mut buf = vec![0; BUFFER];
    let mut h = Blake2sp::new();
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    h.finish()
}

fn header(packed: u64, size: u64, crc: u32, digest: [u8; 32], before: bool, after: bool, enc: bool) -> Vec<u8> {
    let mut fields = vec![4]; // file flags: CRC present
    common::vint(size, &mut fields);
    common::vint(0x20, &mut fields);
    fields.extend(crc.to_le_bytes());
    common::vint(0, &mut fields); // Stored, non-solid
    common::vint(0, &mut fields); // Windows host; no archive metadata effects
    common::vint(5, &mut fields);
    fields.extend(b"inner");
    let mut extra = Vec::new();
    if enc {
        extra.extend([36, 1, 0, 0, 1]); // size, crypt, version, flags, KDF exponent
        extra.extend(SALT);
        extra.extend(IV);
    }
    extra.extend(common::blake_record(digest));
    let mut body = Vec::new();
    common::vint(2, &mut body);
    common::vint(3 | if before { 8 } else { 0 } | if after { 16 } else { 0 }, &mut body);
    common::vint(extra.len() as u64, &mut body);
    common::vint(packed, &mut body);
    body.extend(fields);
    body.extend(extra);
    let mut sized = Vec::new();
    common::vint(body.len() as u64, &mut sized);
    sized.extend(body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend(sized);
    out
}

fn wire_header(mut h: Vec<u8>, key: Option<&[u8; 32]>, ordinal: usize) -> Vec<u8> {
    if let Some(key) = key {
        h.resize(h.len().next_multiple_of(16), 0);
        let iv = [ordinal as u8 + 30; 16];
        let mut out = iv.to_vec();
        out.extend(zipfast::crypto::encrypt_cbc(key, &iv, &h).unwrap());
        out
    } else {
        h
    }
}

fn prefix(index: usize, key: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = common::SIG.to_vec();
    if key.is_some() {
        let mut params = vec![0, 0, 1];
        params.extend(SALT);
        out.extend(common::block(4, 0, &params, &[], &[], false));
    }
    out.extend(wire_header(common::main_block(true, (index > 0).then_some(index as u64)), key, 0));
    out
}

fn payload_offset(index: usize, packed: u64, size: u64, key: Option<&[u8; 32]>, count: usize) -> u64 {
    (prefix(index, key).len()
        + wire_header(header(packed, size, 0, [0; 32], index > 0, index + 1 < count, key.is_some()), key, 1).len())
        as u64
}

struct CipherStream {
    key: AesKey,
    previous: [u8; 16],
    block: [u8; 16],
    used: usize,
    next: u64,
    size: u64,
}
impl CipherStream {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            if self.used == 16 {
                let mut block = [0; 16];
                let n = (self.size.saturating_sub(self.next)).min(16) as usize;
                pattern(self.next, &mut block[..n]);
                self.next += 16;
                for (b, p) in block.iter_mut().zip(self.previous) {
                    *b ^= p;
                }
                self.block = self.key.encrypt_block(&block);
                self.previous = self.block;
                self.used = 0;
            }
            *b = self.block[self.used];
            self.used += 1;
        }
    }
}

fn archive_path(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!("a.part{:02}.rar", index + 1))
}

fn build(dir: &Path, size: u64, article: u64, encrypted: bool, lengths: Vec<u64>) -> Fixture {
    fs::create_dir_all(dir).unwrap();
    assert!(!dir.join("manifest.txt").exists(), "never overwrite frozen evidence");
    let gold_path = dir.join("gold.bin");
    let mut existing = gold_path.exists().then(|| File::open(&gold_path).unwrap());
    if let Some(file) = &existing {
        assert_eq!(file.metadata().unwrap().len(), size);
    }
    let mut gold = if existing.is_none() {
        Some(OpenOptions::new().write(true).create_new(true).open(&gold_path).unwrap())
    } else {
        None
    };
    let mut buffer = vec![0; BUFFER];
    let mut check = vec![0; if existing.is_some() { BUFFER } else { 0 }];
    let mut crc = crc32fast::Hasher::new();
    let mut hash = Blake2sp::new();
    let mut at = 0;
    while at < size {
        let n = (size - at).min(BUFFER as u64) as usize;
        pattern(at, &mut buffer[..n]);
        if let Some(file) = &mut gold {
            file.write_all(&buffer[..n]).unwrap();
        }
        if let Some(file) = &mut existing {
            file.read_exact(&mut check[..n]).unwrap();
            assert_eq!(buffer[..n], check[..n], "shared gold must match offset recipe");
        }
        crc.update(&buffer[..n]);
        hash.update(&buffer[..n]);
        at += n as u64;
    }
    if let Some(file) = &gold {
        file.sync_all().unwrap();
    }
    let crc = crc.finalize();
    let digest = hash.finish();
    let key = encrypted.then(|| zipfast::crypto::derive_rar5_key_and_hash_key(PASSWORD, 1, &SALT, None).unwrap().0);
    let mut cipher = key.as_ref().map(|k| CipherStream {
        key: AesKey::new(k).unwrap(),
        previous: IV,
        block: [0; 16],
        used: 16,
        next: 0,
        size,
    });
    let mut parts = Vec::new();
    let mut start = 0;
    for (i, &len) in lengths.iter().enumerate() {
        let last = i + 1 == lengths.len();
        let mut file = OpenOptions::new().read(true).write(true).create_new(true).open(archive_path(dir, i)).unwrap();
        let pre = prefix(i, key.as_ref());
        let placeholder = wire_header(header(len, size, 0, [0; 32], i > 0, !last, encrypted), key.as_ref(), 1);
        file.write_all(&pre).unwrap();
        file.write_all(&placeholder).unwrap();
        let payload = file.stream_position().unwrap();
        assert_eq!(payload, payload_offset(i, len, size, key.as_ref(), lengths.len()));
        let mut part_crc = crc32fast::Hasher::new();
        let mut part_hash = Blake2sp::new();
        let mut done = 0;
        while done < len {
            let n = (len - done).min(BUFFER as u64) as usize;
            if let Some(cipher) = &mut cipher {
                cipher.fill(&mut buffer[..n]);
            } else {
                pattern(start + done, &mut buffer[..n]);
            }
            file.write_all(&buffer[..n]).unwrap();
            part_crc.update(&buffer[..n]);
            part_hash.update(&buffer[..n]);
            done += n as u64;
        }
        file.write_all(&wire_header(common::end_block(!last), key.as_ref(), 2)).unwrap();
        let physical = file.stream_position().unwrap();
        let checks = if last { (crc, digest) } else { (part_crc.finalize(), part_hash.finish()) };
        let actual = wire_header(header(len, size, checks.0, checks.1, i > 0, !last, encrypted), key.as_ref(), 1);
        assert_eq!(actual.len(), placeholder.len());
        file.seek(SeekFrom::Start(pre.len() as u64)).unwrap();
        file.write_all(&actual).unwrap();
        file.sync_all().unwrap();
        assert_eq!(file.metadata().unwrap().len(), physical);
        drop(file);
        parts.push(Part { start, len, payload, physical, digest: file_digest(&archive_path(dir, i)) });
        start += len;
    }
    assert_eq!(start, if encrypted { size.next_multiple_of(16) } else { size });
    Fixture { dir: dir.to_owned(), size, article, encrypted, crc, digest, parts, losses: vec![], expected: vec![] }
}

fn union(mut ranges: Vec<Range<u64>>) -> Vec<OutputHole> {
    ranges.sort_by_key(|r| r.start);
    let mut out: Vec<OutputHole> = Vec::new();
    for r in ranges {
        if r.is_empty() {
            continue;
        }
        if let Some(last) = out.last_mut().filter(|h| r.start <= h.offset + h.len) {
            last.len = (r.end - last.offset).max(last.len);
        } else {
            out.push(OutputHole { offset: r.start, len: r.end - r.start });
        }
    }
    out
}

fn expected(f: &Fixture) -> Vec<OutputHole> {
    union(
        f.losses
            .iter()
            .map(|(i, loss)| {
                let p = &f.parts[*i];
                let begin = loss.start.max(p.payload);
                let end = loss.end.min(p.payload + p.len);
                assert!(begin < end, "loss must intersect payload");
                let c = p.start + begin - p.payload..p.start + end - p.payload;
                if f.encrypted { (c.start / 16 * 16)..(c.end.div_ceil(16) * 16 + 16).min(f.size) } else { c }
            })
            .collect(),
    )
}

fn eligible(f: &Fixture, i: usize, a: u64) -> bool {
    let p = &f.parts[i];
    let r = a * f.article..((a + 1) * f.article).min(p.physical);
    // Exactly the recorded framing union [0,payload) U [payload+len,physical).
    r.start >= p.payload && r.end <= p.payload + p.len
}

fn manifest(f: &Fixture) {
    let mut s = format!(
        "task7-rar5-v1\nsize {}\narticle {}\nencrypted {}\ncrc {}\nblake {}\n",
        f.size,
        f.article,
        u8::from(f.encrypted),
        f.crc,
        hex(&f.digest)
    );
    let articles: u64 = f.parts.iter().map(|p| p.physical.div_ceil(f.article)).sum();
    writeln!(s, "articles-total {articles}").unwrap();
    writeln!(s, "articles-lost {}", f.losses.len()).unwrap();
    writeln!(s, "physical-missing-bytes {}", f.losses.iter().map(|(_, r)| r.end - r.start).sum::<u64>()).unwrap();
    writeln!(s, "inner-hole-bytes {}", f.expected.iter().map(|h| h.len).sum::<u64>()).unwrap();
    if f.encrypted && f.parts.len() == 10 {
        writeln!(s, "cipher-cut-k {}", (f.parts[0].payload + f.parts[0].len) % f.article).unwrap();
    }
    for (i, p) in f.parts.iter().enumerate() {
        writeln!(s, "part {i} {} {} {} {} {}", p.start, p.len, p.payload, p.physical, hex(&p.digest)).unwrap();
        writeln!(s, "framing {i} 0 {} {} {}", p.payload, p.payload + p.len, p.physical).unwrap();
        for a in 0..p.physical.div_ceil(f.article) {
            writeln!(s, "article-state {i} {a} {}", if eligible(f, i, a) { "eligible" } else { "protected" }).unwrap();
        }
    }
    for (i, r) in &f.losses {
        writeln!(s, "loss {i} {} {}", r.start, r.end).unwrap();
    }
    for h in &f.expected {
        writeln!(s, "hole {} {}", h.offset, h.len).unwrap();
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(f.dir.join("manifest.txt")).unwrap();
    file.write_all(s.as_bytes()).unwrap();
    file.sync_all().unwrap();
}

fn layout(size: u64, article: u64, enc: bool) -> (Vec<u64>, Option<u64>) {
    assert!(size == 500_000_000 || size <= 1_048_576);
    assert_eq!(size % 80, 0); // ten integral parts and a block-aligned whole member
    let base = size / 10;
    let mut lengths = vec![base; 10];
    let mut cross = None;
    if enc {
        let key = zipfast::crypto::derive_rar5_key_and_hash_key(PASSWORD, 1, &SALT, None).unwrap().0;
        let p = payload_offset(0, base, size, Some(&key), 10);
        let boundary = (base + p).div_ceil(article) * article;
        let crosses = |k: u64| {
            let c = boundary - p;
            c.div_ceil(16) * 16 + 16 > c + k && !(c + k).is_multiple_of(16)
        };
        let k = if crosses(7) { 7 } else { (1..16).find(|&k| crosses(k)).unwrap() };
        lengths[0] = boundary - p + k;
        lengths[1] = 2 * base - lengths[0];
        cross = Some(boundary / article - 1);
    }
    (lengths, cross)
}

pub fn large_geometry_preflight() {
    let size = 500_000_000;
    let article = 700_000;
    for enc in [false, true] {
        let (lengths, cross) = layout(size, article, enc);
        let key = enc.then(|| zipfast::crypto::derive_rar5_key_and_hash_key(PASSWORD, 1, &SALT, None).unwrap().0);
        let mut start = 0;
        let parts: Vec<_> = lengths
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                let payload = payload_offset(i, len, size, key.as_ref(), 10);
                let physical = payload + len + wire_header(common::end_block(i < 9), key.as_ref(), 2).len() as u64;
                let p = Part { start, len, payload, physical, digest: [0; 32] };
                start += len;
                p
            })
            .collect();
        let counts: Vec<_> = parts.iter().map(|p| p.physical.div_ceil(article)).collect();
        assert_eq!(start, size);
        assert_eq!(counts, if enc { vec![73, 71, 72, 72, 72, 72, 72, 72, 72, 72] } else { vec![72; 10] });
        let mut f = Fixture {
            dir: PathBuf::new(),
            size,
            article,
            encrypted: enc,
            crc: 0,
            digest: [0; 32],
            parts,
            losses: vec![],
            expected: vec![],
        };
        if let Some(a) = cross {
            assert_eq!(a, 71);
            assert!(eligible(&f, 0, a));
            f.losses.push((0, a * article..(a + 1) * article));
            let holes = expected(&f);
            assert!(holes[0].offset < f.parts[1].start && holes[0].offset + holes[0].len > f.parts[1].start);
        }
        eprintln!(
            "header-only large preflight encrypted={enc} articles={counts:?} payload_offset={} first_two_payloads={:?} mandatory_cross_article={cross:?}",
            f.parts[0].payload,
            &lengths[..2]
        );
    }
}

pub fn prepare(dir: &Path, size: u64, article: u64, enc: bool) -> Fixture {
    let (lengths, cross) = layout(size, article, enc);
    let mut f = build(dir, size, article, enc, lengths);
    let counts: Vec<_> = f.parts.iter().map(|p| p.physical.div_ceil(article)).collect();
    let count: u64 = counts.iter().sum();
    assert_eq!(count % 10, 0, "article geometry must give an exact integral ten percent: {counts:?}");
    if size == 500_000_000 {
        assert_eq!(count, 720);
        assert_eq!(counts, if enc { vec![73, 71, 72, 72, 72, 72, 72, 72, 72, 72] } else { vec![72; 10] });
    }
    let mut chosen = BTreeSet::new();
    let pair = (0..counts[0] - 1).find(|&a| eligible(&f, 0, a) && eligible(&f, 0, a + 1)).unwrap();
    chosen.extend([(0, pair), (0, pair + 1)]);
    if let Some(a) = cross {
        assert!(eligible(&f, 0, a));
        chosen.insert((0, a));
    }
    let mut candidates: Vec<_> = counts
        .iter()
        .enumerate()
        .flat_map(|(i, &count)| (0..count).map(move |a| (i, a)))
        .filter(|&(i, a)| eligible(&f, i, a))
        .collect();
    candidates.sort_by_key(|&(i, a)| (mix(((i as u64) << 32) | a), i, a));
    for x in candidates {
        if chosen.len() as u64 == count / 10 {
            break;
        }
        chosen.insert(x);
    }
    assert_eq!(chosen.len() as u64 * 10, count);
    f.losses =
        chosen.into_iter().map(|(i, a)| (i, a * article..((a + 1) * article).min(f.parts[i].physical))).collect();
    f.expected = expected(&f);
    if enc {
        let cut = f.parts[1].start;
        assert!(f.expected.iter().any(|h| h.offset < cut && h.offset + h.len > cut), "actual cross-volume taint");
    }
    manifest(&f);
    eprintln!(
        "fixture={} bytes={size} articles={count} lost={} holes={}",
        dir.display(),
        f.losses.len(),
        f.expected.len()
    );
    f
}

pub fn prepare_pair(root: &Path, size: u64, article: u64) -> (Fixture, Fixture) {
    let plain = prepare(&root.join("plain"), size, article, false);
    let encrypted = root.join("encrypted");
    fs::create_dir_all(&encrypted).unwrap();
    // One persistent gold inode for both containers, never another 500 MB copy.
    fs::hard_link(plain.dir.join("gold.bin"), encrypted.join("gold.bin")).unwrap();
    let encrypted = prepare(&encrypted, size, article, true);
    (plain, encrypted)
}

pub fn load(dir: &Path) -> Fixture {
    let text = fs::read_to_string(dir.join("manifest.txt")).unwrap();
    assert_eq!(text.lines().next(), Some("task7-rar5-v1"));
    let mut f = Fixture {
        dir: dir.to_owned(),
        size: 0,
        article: 0,
        encrypted: false,
        crc: 0,
        digest: [0; 32],
        parts: vec![],
        losses: vec![],
        expected: vec![],
    };
    for line in text.lines().skip(1) {
        let v: Vec<_> = line.split_whitespace().collect();
        let n = |i: usize| v[i].parse::<u64>().unwrap();
        match v[0] {
            "size" => f.size = n(1),
            "article" => f.article = n(1),
            "encrypted" => f.encrypted = n(1) == 1,
            "crc" => f.crc = n(1) as u32,
            "blake" => f.digest = unhex(v[1]),
            "part" => {
                assert_eq!(n(1) as usize, f.parts.len());
                f.parts.push(Part { start: n(2), len: n(3), payload: n(4), physical: n(5), digest: unhex(v[6]) });
            }
            "loss" => f.losses.push((n(1) as usize, n(2)..n(3))),
            "hole" => f.expected.push(OutputHole { offset: n(1), len: n(2) }),
            "framing"
            | "article-state"
            | "articles-total"
            | "articles-lost"
            | "physical-missing-bytes"
            | "inner-hole-bytes"
            | "cipher-cut-k" => {}
            _ => panic!("unknown manifest record"),
        }
    }
    assert_eq!(f.parts.len(), 10);
    assert_eq!(f.article, 700_000);
    let count: u64 = f.parts.iter().map(|p| p.physical.div_ceil(f.article)).sum();
    assert_eq!(count, 720);
    assert_eq!(f.losses.len(), 72);
    for (i, r) in &f.losses {
        assert_eq!(r.start % f.article, 0);
        assert_eq!(r.end, ((r.start / f.article + 1) * f.article).min(f.parts[*i].physical));
        assert!(eligible(&f, *i, r.start / f.article));
    }
    assert_eq!(f.expected, expected(&f));
    // Streaming checks are preparation/preflight, outside the timed correctness child.
    f
}

#[derive(Default)]
struct Stats {
    callbacks: u64,
    pending: Option<Waker>,
    volume_waits: usize,
    article_waits: usize,
    read_bytes: u64,
    reads: Vec<(usize, u64, usize, &'static str)>,
}
type Shared = Arc<Mutex<Stats>>;

struct Articles {
    native: ImmutableFileSource,
    original: SourceInfo,
    volume: usize,
    article: u64,
    losses: Vec<Range<u64>>,
    seen: BTreeSet<u64>,
    waits: bool,
    stats: Shared,
}
impl RangeSource for Articles {
    fn info(&self) -> SourceInfo {
        self.stats.lock().unwrap().callbacks += 1;
        let info = self.native.info();
        assert_eq!(info, self.original);
        info
    }
    fn backing_files(&self) -> &[File] {
        self.stats.lock().unwrap().callbacks += 1;
        self.native.backing_files()
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let a = at / self.article;
        let mut stats = self.stats.lock().unwrap();
        stats.callbacks += 1;
        if self.waits && self.seen.insert(a) {
            assert!(stats.pending.is_none());
            stats.pending = Some(cx.waker().clone());
            stats.article_waits += 1;
            stats.reads.push((self.volume, at, buf.len(), "NotYet"));
            return Ok(RangeRead::NotYet);
        }
        let end = ((a + 1) * self.article).min(self.original.length.value());
        if let Some(loss) = self.losses.iter().find(|r| r.contains(&at)) {
            let len = loss.end - at;
            stats.reads.push((self.volume, at, len as usize, "Hole"));
            return Ok(RangeRead::Hole { len });
        }
        let mut n = buf.len().min((end - at) as usize);
        if let Some(loss) = self.losses.iter().find(|r| r.start > at) {
            n = n.min((loss.start - at) as usize);
        }
        drop(stats);
        let result = self.native.read_at(at, &mut buf[..n], cx)?;
        if let RangeRead::Filled { count } = result {
            let mut s = self.stats.lock().unwrap();
            s.read_bytes += count as u64;
            s.reads.push((self.volume, at, count, "Filled"));
        }
        Ok(result)
    }
}

struct Provider {
    dir: PathBuf,
    article: u64,
    losses: Vec<(usize, Range<u64>)>,
    waited: BTreeSet<u32>,
    count: usize,
    stats: Shared,
}
impl VolumeSource for Provider {
    fn volume(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let mut s = self.stats.lock().unwrap();
        s.callbacks += 1;
        assert!((request.index as usize) < self.count);
        assert_eq!(request.expected, archive_path(&self.dir, request.index as usize).file_name().unwrap());
        if self.waited.insert(request.index) {
            assert!(s.pending.is_none());
            s.pending = Some(cx.waker().clone());
            s.volume_waits += 1;
            return Ok(VolumeAnswer::Wait);
        }
        drop(s);
        let native = ImmutableFileSource::open(&archive_path(&self.dir, request.index as usize))?;
        let original = native.info();
        Ok(VolumeAnswer::Ready(Box::new(Articles {
            native,
            original,
            volume: request.index as usize,
            article: self.article,
            losses: self.losses.iter().filter(|(i, _)| *i == request.index as usize).map(|(_, r)| r.clone()).collect(),
            seen: BTreeSet::new(),
            waits: true,
            stats: self.stats.clone(),
        })))
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        self.stats.lock().unwrap().callbacks += 1;
        Ok(ProtectionDeclaration::Opaque)
    }
}

fn session(f: &Fixture, fill: HoleFill) -> (ProgressiveSession, Shared) {
    let stats = Arc::new(Mutex::new(Stats::default()));
    let mut opts = ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: f.dir.join("destination"),
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
        },
        "a.part01.rar".into(),
    );
    opts.hole_policy = HolePolicy::PartialStored { fill };
    opts.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    opts.recovery_publication = RecoveryPublication::VerifiedInner;
    opts.limits.read_chunk = BUFFER as u64;
    opts.limits.packed_work_per_poll = BUFFER as u64;
    if f.encrypted {
        // Exponent 1, short password and absent verifier cost exactly
        // 2 setup + 2 first-HMAC + 2 continuation + 32 hash-key blocks.
        // One header derivation/volume and one member derivation, once in
        // extraction and once in strict replacement replay. Waits get none.
        opts.limits.kdf_session_blocks = 2 * (f.parts.len() as u64 + 1) * 38;
        opts.set_password(Some(PASSWORD.into())).unwrap();
    }
    let provider = Provider {
        dir: f.dir.clone(),
        article: f.article,
        losses: f.losses.clone(),
        waited: BTreeSet::new(),
        count: f.parts.len(),
        stats: stats.clone(),
    };
    (ProgressiveSession::new(Box::new(provider), opts).unwrap(), stats)
}

fn poll(s: &mut ProgressiveSession) -> Poll<ProgressiveResult<Option<ProgressiveEvent>>> {
    s.poll_event(&mut Context::from_waker(Waker::noop()))
}

fn resume(s: &mut ProgressiveSession, shared: &Shared) {
    if shared.lock().unwrap().pending.is_none() {
        return;
    }
    let calls = shared.lock().unwrap().callbacks;
    for _ in 0..3 {
        assert!(poll(s).is_pending());
    }
    assert_eq!(shared.lock().unwrap().callbacks, calls, "unwoken source callbacks");
    let w = shared.lock().unwrap().pending.take().unwrap();
    w.wake();
}

fn extract(s: &mut ProgressiveSession, stats: &Shared, f: &Fixture) -> Artifact {
    let mut output = None;
    let mut opened = Vec::new();
    let mut starts = 0;
    let mut valid = 0;
    let mut logical = 0;
    for _ in 0..20_000_000 {
        match poll(s) {
            Poll::Pending => resume(s, stats),
            Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index, .. }))) => opened.push(index),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { name, size, .. }))) => {
                starts += 1;
                assert_eq!(name.as_slice(), b"inner");
                assert_eq!(size, Some(f.size));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { valid_bytes, logical_end, .. }))) => {
                valid += valid_bytes;
                assert!(logical_end >= logical);
                logical = logical_end;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome: MemberOutcome::Partial(a), .. }))) => {
                assert!(output.is_none());
                output = Some(a);
            }
            Poll::Ready(Ok(None)) => {
                assert_eq!(starts, 1);
                assert_eq!(opened, (0..f.parts.len() as u32).collect::<Vec<_>>());
                assert_eq!(valid, f.size - f.expected.iter().map(|h| h.len).sum::<u64>());
                let a = output.expect("exactly one Partial artifact");
                assert_eq!(a.size(), Some(f.size));
                assert_eq!(a.produced_extent(), f.size);
                assert_eq!(a.holes(), f.expected);
                assert_eq!(a.publication(), ArtifactPublication::Unpublished);
                assert!(!f.dir.join("destination/inner").exists());
                return a;
            }
            Poll::Ready(Err(e)) => panic!("engine failure: {e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                panic!("engine terminated: {failure:?}")
            }
            _ => panic!("unexpected acceptance event"),
        }
    }
    panic!("bounded event loop exhausted");
}

fn verify(s: &mut ProgressiveSession, a: &mut Artifact) -> Verification {
    for _ in 0..20_000_000 {
        if let Poll::Ready(v) = s.poll_verify(a, &mut Context::from_waker(Waker::noop())) {
            return v.unwrap();
        }
    }
    panic!("bounded verification loop exhausted");
}

fn export(a: &mut Artifact, f: &Fixture, partial: bool) -> [u8; 32] {
    let name = if partial { "partial-sparse.bin" } else { "recovered-inner.bin" };
    let mut out = OpenOptions::new().write(true).create_new(true).open(f.dir.join(name)).unwrap();
    let mut gold = File::open(f.dir.join("gold.bin")).unwrap();
    let mut buf = vec![0; BUFFER];
    let mut check = vec![0; BUFFER];
    let mut at = 0;
    let mut hash = Blake2sp::new();
    let mut crc = crc32fast::Hasher::new();
    while at < f.size {
        let n = (f.size - at).min(BUFFER as u64) as usize;
        match a.read_at(at, &mut buf[..n]).unwrap() {
            ArtifactRead::Filled { count } => {
                assert!(count > 0);
                gold.seek(SeekFrom::Start(at)).unwrap();
                gold.read_exact(&mut check[..count]).unwrap();
                assert_eq!(buf[..count], check[..count], "byte exact gold at {at}");
                out.write_all(&buf[..count]).unwrap();
                if !partial {
                    hash.update(&buf[..count]);
                    crc.update(&buf[..count]);
                }
                at += count as u64;
            }
            ArtifactRead::Hole { len } => {
                assert!(partial && len > 0);
                assert!(f.expected.iter().any(|h| h.offset <= at && at + len <= h.offset + h.len));
                at += len;
                out.seek(SeekFrom::Start(at)).unwrap();
            }
            _ => panic!("unexpected public artifact read at {at}"),
        }
    }
    out.set_len(f.size).unwrap();
    out.sync_all().unwrap();
    assert_eq!(a.read_at(f.size, &mut buf).unwrap(), ArtifactRead::End);
    if partial {
        [0; 32]
    } else {
        assert_eq!(crc.finalize(), f.crc);
        hash.finish()
    }
}

pub fn exercise(f: &Fixture, fill: HoleFill) {
    assert_eq!(f.expected, expected(f), "independent expectation before engine entry");
    let (mut s, stats) = session(f, fill);
    let mut a = extract(&mut s, &stats, f);
    export(&mut a, f, true);
    assert!(
        matches!(s.poll_verify(&mut a, &mut Context::from_waker(Waker::noop())), Poll::Ready(Err(e)) if matches!(e.kind, FailureKind::IncompleteOutput))
    );
    s.set_expected_inner(&a, ExpectedInner::Blake2sp { digest: f.digest, label: "original deterministic gold".into() })
        .unwrap();
    let mut gold = File::open(f.dir.join("gold.bin")).unwrap();
    let mut buffer = vec![0; BUFFER];
    let mut patches = 0;
    for hole in &f.expected {
        let mut at = hole.offset;
        while at < hole.offset + hole.len {
            let n = (hole.offset + hole.len - at).min(BUFFER as u64) as usize;
            gold.seek(SeekFrom::Start(at)).unwrap();
            gold.read_exact(&mut buffer[..n]).unwrap();
            s.patch(&mut a, at, &buffer[..n]).unwrap();
            at += n as u64;
            patches += 1;
        }
    }
    assert!(a.holes().is_empty());
    let first = verify(&mut s, &mut a);
    let mut final_verification = first.clone();
    assert_eq!(first.crc32_verdict(), CheckVerdict::Passed);
    assert_eq!(first.blake2sp_verdict(), CheckVerdict::Passed);
    assert_eq!(first.size_verdict(), CheckVerdict::Passed);
    let mut replacement_revision = None;
    if f.encrypted {
        assert_eq!(first.level(), VerificationLevel::InnerOnly);
        assert_eq!(first.packed(), PackedEvidence::Missing);
        assert_eq!(first.authentication(), AuthenticationEvidence::CbcChecksOnly);
        assert_eq!(
            a.required_verification_volumes().collect::<Vec<_>>(),
            (0..f.parts.len() as u32).collect::<Vec<_>>()
        );
        assert!(matches!(s.publish_recovered(&mut a).unwrap_err().kind, FailureKind::PublicationAuthorityRequired));
        for i in 0..f.parts.len() {
            s.supply_verification_source(
                i as u32,
                Box::new(ImmutableFileSource::open(&archive_path(&f.dir, i)).unwrap()),
            )
            .unwrap();
            if i == 0 && f.parts.len() > 1 {
                let v = verify(&mut s, &mut a);
                assert_eq!(v.level(), VerificationLevel::InnerOnly);
                assert_eq!(v.packed(), PackedEvidence::Missing);
            }
        }
        let v = verify(&mut s, &mut a);
        assert_eq!(v.level(), VerificationLevel::Strict);
        assert_eq!(v.packed(), PackedEvidence::Passed);
        assert_eq!(v.authentication(), AuthenticationEvidence::CbcChecksOnly);
        assert_eq!(v.replacement_revision(), Some(f.parts.len() as u64));
        replacement_revision = v.replacement_revision();
        final_verification = v;
    } else {
        assert_eq!(first.level(), VerificationLevel::Strict);
        assert_eq!(first.packed(), PackedEvidence::Passed);
    }
    assert_eq!(a.publication(), ArtifactPublication::Unpublished);
    assert!(!f.dir.join("destination/inner").exists());
    assert!(matches!(a.evidence(), ArtifactEvidence::Verified(_)));
    assert_eq!(export(&mut a, f, false), f.digest);
    let st = stats.lock().unwrap();
    assert_eq!(st.volume_waits, f.parts.len());
    assert!(st.article_waits > 0);
    let mut consumed = vec![0; f.parts.len()];
    for &(i, at, count, status) in &st.reads {
        if status != "NotYet" {
            assert_eq!(at, consumed[i], "original source bytes must not replay across waits");
            consumed[i] += count as u64;
        }
    }
    assert_eq!(consumed, f.parts.iter().map(|p| p.physical).collect::<Vec<_>>());
    let mut evidence = format!(
        "PASS\nbytes={}\ncrc32={:08x}\nblake2sp={}\nvolumes={}\nvolume_waits={}\narticle_waits={}\ncallbacks={}\nfilled_source_bytes={}\npatch_calls={}\nreplacement_revision={replacement_revision:?}\npublication=Unpublished\nauthority=Opaque-original\n",
        f.size,
        f.crc,
        hex(&f.digest),
        f.parts.len(),
        st.volume_waits,
        st.article_waits,
        st.callbacks,
        st.read_bytes,
        patches
    );
    writeln!(evidence, "initial_level={:?}\ninitial_packed={:?}\nfinal_level={:?}\nfinal_packed={:?}\nauthentication={:?}\nno_original_byte_replay=true", first.level(), first.packed(), final_verification.level(), final_verification.packed(), final_verification.authentication()).unwrap();
    for h in &f.expected {
        writeln!(evidence, "expected-hole {} {}", h.offset, h.len).unwrap();
    }
    fs::write(f.dir.join("result.txt"), evidence).unwrap();
    let mut trace = File::create(f.dir.join("physical-reads.tsv")).unwrap();
    for (i, at, count, status) in &st.reads {
        writeln!(trace, "{i}\t{at}\t{count}\t{status}").unwrap();
    }
}

pub fn small_boundaries() {
    for lost in [17..18, 79..80] {
        let dir = persistent_fast_dir("cbc79");
        let mut f = build(&dir, 79, 700, true, vec![23, 57]);
        let (i, r) = if lost.start < 23 {
            (0, f.parts[0].payload + lost.start..f.parts[0].payload + lost.end)
        } else {
            (1, f.parts[1].payload + lost.start - 23..f.parts[1].payload + lost.end - 23)
        };
        f.losses = vec![(i, r)];
        f.expected = expected(&f);
        assert_eq!(
            f.expected,
            if lost.start == 17 {
                vec![OutputHole { offset: 16, len: 32 }]
            } else {
                vec![OutputHole { offset: 64, len: 15 }]
            }
        );
        manifest(&f);
        exercise(&f, HoleFill::Sparse);
    }
    let dir = persistent_fast_dir("header-negative");
    let mut f = build(&dir, 79, 700, false, vec![40, 39]);
    f.losses = vec![(0, 0..1)];
    let (mut s, st) = session(&f, HoleFill::Sparse);
    let mut failed = false;
    for _ in 0..1000 {
        match poll(&mut s) {
            Poll::Pending => resume(&mut s, &st),
            Poll::Ready(Err(e)) => {
                assert!(matches!(e.kind, FailureKind::HeaderHole));
                assert_eq!(e.context.volume_index, Some(0));
                failed = true;
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("header negative unexpectedly finished"),
        }
    }
    assert!(failed);
    assert!(!dir.join("destination/inner").exists());
    let (mut s, st) = session(&f, HoleFill::Sparse);
    assert!(poll(&mut s).is_pending());
    let calls = st.lock().unwrap().callbacks;
    s.control().cancel();
    assert!(matches!(poll(&mut s), Poll::Ready(Err(e)) if matches!(e.kind, FailureKind::Canceled)));
    assert_eq!(st.lock().unwrap().callbacks, calls);
    let (mut s, st) = session(&f, HoleFill::Sparse);
    let mut article_canceled = false;
    for _ in 0..1000 {
        match poll(&mut s) {
            Poll::Pending if st.lock().unwrap().article_waits > 0 => {
                let calls = st.lock().unwrap().callbacks;
                s.control().cancel();
                assert!(matches!(poll(&mut s), Poll::Ready(Err(e)) if matches!(e.kind, FailureKind::Canceled)));
                assert_eq!(st.lock().unwrap().callbacks, calls);
                article_canceled = true;
                break;
            }
            Poll::Pending => resume(&mut s, &st),
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("must reach article wait before header-hole read"),
        }
    }
    assert!(article_canceled);
}
