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

//! ISO 9660 images, read as tar members so they take tar's whole pipeline. The tree comes from the primary volume
//! descriptor with Rock Ridge when it has it (names, symbolic links, modes, owners, times, relocated deep folders),
//! else from a Joliet supplementary descriptor (UCS-2 names), else from the primary one's plain names. A file of
//! several extents (one past 4 GiB) reads as one.
//!
//! Every extent has to lie inside the image; the walk visits each folder once, bounded in depth, folder count,
//! entries and bytes read, and Rock Ridge continuation areas are bounded per record and in all.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Read};

use super::table::{self, Names};
use super::{Kind, Member, TarMagic, TarMetadata};
use crate::error::{Error, Result};

const SECTOR: u64 = 2048;
/// The first volume descriptor's offset, after the 32 KiB system area.
pub(super) const DESCRIPTORS: u64 = 16 * SECTOR;
const MAX_DESCRIPTORS: u64 = 64;
const MAX_DEPTH: usize = 128;
const MAX_ENTRIES: usize = 1 << 18;
/// The most bytes of folder data the walk reads, all folders together.
const MAX_DIR_BYTES: u64 = 256 << 20;
/// Rock Ridge continuation areas: how many one record may chain, and how many bytes they may add in all.
const MAX_CONTINUATIONS: usize = 16;
const MAX_SUSP_BYTES: u64 = 64 << 20;
const MAX_EXTENTS: usize = 1 << 16;
/// What the files may declare in all, against the image's length: files sharing extents (hard links, empty files)
/// count once each, so a few thousand files on one big extent can't turn a small image into terabytes.
const MAX_DECLARED_RATIO: u64 = 4;
const MAX_DECLARED_FREE: u64 = 64 << 20;

fn corrupt(why: &'static str) -> Error {
    Error::Corrupt(why)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Naming {
    Plain,
    Joliet,
    RockRidge { skip: usize },
}

#[derive(Debug)]
struct Entry {
    /// its name and folder, in the walk's [`Names`]: the full path is built only as it is handed out
    name: usize,
    kind: Kind,
    link: String,
    /// (first sector, length in bytes) of each extent, in order
    extents: Vec<(u64, u64)>,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<i64>,
}

pub(super) struct State {
    file: File,
    entries: VecDeque<Entry>,
    names: Names,
}

/// Whether `file` holds an ISO 9660 image: "CD001" in its first volume descriptor.
pub(super) fn sniff(file: &File) -> bool {
    let mut id = [0u8; 6];
    crate::batch::read_at_detailed(file, &mut id, DESCRIPTORS).is_ok() && &id[1..6] == b"CD001"
}

fn read_at(file: &File, at: u64, buf: &mut [u8]) -> Result<()> {
    crate::batch::read_at_detailed(file, buf, at).map_err(|e| match e {
        crate::batch::PositionReadError::Eof => Error::Truncated,
        crate::batch::PositionReadError::Io { source, .. } => Error::Io(source),
    })
}

fn both32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Seconds since 1970 from the 7-byte form: years since 1900, month, day, hour, minute, second, and the zone in
/// 15-minute steps east of UTC.
fn time7(b: &[u8]) -> Option<i64> {
    let (y, m, d) = (1900 + i64::from(b[0]), i64::from(b[1]), i64::from(b[2]));
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let local = civil(y, m, d)? + i64::from(b[3]) * 3600 + i64::from(b[4]) * 60 + i64::from(b[5]);
    Some(local - i64::from(b[6] as i8) * 15 * 60)
}

/// The 17-byte form: "YYYYMMDDHHMMSScc" in ASCII, then the zone.
fn time17(b: &[u8]) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| std::str::from_utf8(&b[r]).ok()?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(4..6)?, n(6..8)?);
    if y == 0 || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let local = civil(y, m, d)? + n(8..10)? * 3600 + n(10..12)? * 60 + n(12..14)?;
    Some(local - i64::from(b[16] as i8) * 15 * 60)
}

/// Seconds at midnight UTC of a day (Howard Hinnant's days from civil).
fn civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400)
}

/// What a directory record says, before the walk makes an entry of it.
struct Record {
    extent: u64,
    size: u64,
    flags: u8,
    name: Vec<u8>,
    mtime: Option<i64>,
    /// Rock Ridge: what its system use entries say
    rr: Rr,
}

#[derive(Default)]
struct Rr {
    name: Option<Vec<u8>>,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<i64>,
    symlink: Option<Vec<u8>>,
    /// a relocated folder's real place (CL): the record stands for that folder
    child: Option<u64>,
    /// a folder moved here by relocation (RE): passed over where it sits
    relocated: bool,
    /// zisofs-compressed data (ZF), which isn't read
    zisofs: bool,
    /// the last symbolic link component read goes on in the next one (its CONTINUE flag)
    sl_continues: bool,
    /// the root's SP entry: bytes to skip at the start of every record's system use area
    sp: Option<usize>,
}

struct Walk<'a> {
    file: &'a File,
    len: u64,
    names: Naming,
    susp_bytes: u64,
}

impl Walk<'_> {
    fn check_extent(&self, extent: u64, size: u64) -> Result<()> {
        let start = extent.checked_mul(SECTOR);
        if start.and_then(|s| s.checked_add(size)).is_none_or(|end| end > self.len) {
            return Err(corrupt("an ISO 9660 extent lies outside the image"));
        }
        Ok(())
    }

    /// The records of the folder at `extent`, `size` bytes, in order; `.` and `..` left out unless `dots`.
    fn records(&mut self, extent: u64, size: u64, budget: &mut u64, dots: bool) -> Result<Vec<Record>> {
        self.check_extent(extent, size)?;
        *budget = budget.checked_sub(size).ok_or(corrupt("an ISO 9660 image's folders are too big"))?;
        let mut data = vec![0u8; size as usize];
        read_at(self.file, extent * SECTOR, &mut data)?;
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < data.len() {
            let len = usize::from(data[at]);
            if len == 0 {
                // no record crosses a sector: the rest of this one is padding
                at = (at / SECTOR as usize + 1) * SECTOR as usize;
                continue;
            }
            let rec = data.get(at..at + len).ok_or(corrupt("an ISO 9660 directory record runs past its folder"))?;
            if len < 34 || (at % SECTOR as usize) + len > SECTOR as usize {
                return Err(corrupt("an ISO 9660 directory record is malformed"));
            }
            let name_len = usize::from(rec[32]);
            if 33 + name_len > len {
                return Err(corrupt("an ISO 9660 directory record's name runs past it"));
            }
            let name = rec[33..33 + name_len].to_vec();
            let dot = name_len == 1 && (name[0] == 0 || name[0] == 1);
            at += len;
            if dot && !dots {
                continue;
            }
            let su_start = 33 + name_len + (1 - name_len % 2);
            let mut rr = Rr::default();
            if let Naming::RockRidge { skip } = self.names
                && su_start + skip <= len
            {
                self.susp(&rec[su_start + skip..], &mut rr, 0)?;
            }
            out.push(Record {
                extent: u64::from(both32(&rec[2..6])),
                size: u64::from(both32(&rec[10..14])),
                flags: rec[25],
                name,
                mtime: time7(&rec[18..25]),
                rr,
            });
        }
        Ok(out)
    }

    /// Reads the system use entries in `area`, following continuation areas (CE) within the bounds.
    fn susp(&mut self, area: &[u8], rr: &mut Rr, hops: usize) -> Result<()> {
        let mut at = 0;
        let mut next: Option<(u64, u64, u64)> = None;
        while at + 4 <= area.len() {
            let (sig, len) = (&area[at..at + 2], usize::from(area[at + 2]));
            if len < 4 || at + len > area.len() {
                break;
            }
            let d = &area[at + 4..at + len];
            match sig {
                b"SP" if d.len() >= 3 && d[..2] == [0xbe, 0xef] => rr.sp = Some(usize::from(d[2])),
                b"NM" if !d.is_empty() => {
                    let flags = d[0];
                    let part: &[u8] = match flags {
                        f if f & 0x02 != 0 => b".",
                        f if f & 0x04 != 0 => b"..",
                        _ => &d[1..],
                    };
                    let name = rr.name.get_or_insert_with(Vec::new);
                    if name.len() + part.len() > 4096 {
                        return Err(corrupt("a Rock Ridge name is too long"));
                    }
                    name.extend_from_slice(part);
                }
                b"PX" if d.len() >= 32 => {
                    rr.mode = Some(both32(&d[0..4]));
                    rr.uid = Some(u64::from(both32(&d[16..20])));
                    rr.gid = Some(u64::from(both32(&d[24..28])));
                }
                b"TF" if !d.is_empty() => {
                    let flags = d[0];
                    let width = if flags & 0x80 != 0 { 17 } else { 7 };
                    // creation comes first when present, then modification
                    let skip = usize::from(flags & 0x01 != 0);
                    if flags & 0x02 != 0
                        && let Some(t) = d.get(1 + skip * width..1 + (skip + 1) * width)
                    {
                        rr.mtime = if width == 17 { time17(t) } else { time7(t) };
                    }
                }
                b"SL" if !d.is_empty() => {
                    let target = rr.symlink.get_or_insert_with(Vec::new);
                    let mut i = 1;
                    while i + 2 <= d.len() {
                        let (cflags, clen) = (d[i], usize::from(d[i + 1]));
                        let Some(c) = d.get(i + 2..i + 2 + clen) else { break };
                        let part: &[u8] = match cflags {
                            f if f & 0x02 != 0 => b".",
                            f if f & 0x04 != 0 => b"..",
                            f if f & 0x08 != 0 => b"/",
                            _ => c,
                        };
                        // a component goes after a slash, unless the one before it continues into it (its
                        // CONTINUE flag, 0x01, which may carry across SL entries) or it follows the root
                        if !target.is_empty() && !rr.sl_continues && !target.ends_with(b"/") && part != b"/" {
                            target.push(b'/');
                        }
                        if target.len() + part.len() > 4096 {
                            return Err(corrupt("a Rock Ridge symbolic link is too long"));
                        }
                        target.extend_from_slice(part);
                        rr.sl_continues = cflags & 0x01 != 0;
                        i += 2 + clen;
                    }
                }
                b"CL" if d.len() >= 8 => rr.child = Some(u64::from(both32(&d[0..4]))),
                b"RE" => rr.relocated = true,
                b"ZF" => rr.zisofs = true,
                b"CE" if d.len() >= 24 => {
                    next =
                        Some((u64::from(both32(&d[0..4])), u64::from(both32(&d[8..12])), u64::from(both32(&d[16..20]))))
                }
                b"ST" => break,
                _ => {}
            }
            at += len;
        }
        if let Some((block, offset, length)) = next {
            if hops >= MAX_CONTINUATIONS {
                return Err(corrupt("Rock Ridge continuation areas chain too far"));
            }
            self.susp_bytes =
                self.susp_bytes.checked_sub(length).ok_or(corrupt("Rock Ridge continuation areas are too big"))?;
            let start = block.checked_mul(SECTOR).and_then(|b| b.checked_add(offset));
            let start = start.filter(|s| s.checked_add(length).is_some_and(|e| e <= self.len));
            let start = start.ok_or(corrupt("a Rock Ridge continuation area lies outside the image"))?;
            let mut more = vec![0u8; length as usize];
            read_at(self.file, start, &mut more)?;
            self.susp(&more, rr, hops + 1)?;
        }
        Ok(())
    }
}

/// A plain ISO 9660 name: the version (";1") and a lone trailing dot go.
fn plain_name(raw: &[u8]) -> Vec<u8> {
    let mut n = raw.to_vec();
    if let Some(semi) = n.iter().rposition(|&c| c == b';') {
        n.truncate(semi);
    }
    if n.ends_with(b".") {
        n.pop();
    }
    n
}

fn joliet_name(raw: &[u8]) -> Vec<u8> {
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
    let mut s = String::from_utf16_lossy(&units);
    if let Some(semi) = s.rfind(';') {
        s.truncate(semi);
    }
    s.into_bytes()
}

/// Reads the volume descriptors and walks the tree of the ISO 9660 image at `file`, `len` bytes long.
pub(super) fn open(file: File, len: u64) -> Result<State> {
    let mut primary: Option<[u8; 34]> = None;
    let mut joliet: Option<[u8; 34]> = None;
    for i in 0..MAX_DESCRIPTORS {
        let mut d = [0u8; SECTOR as usize];
        // an image cut short before its terminator, or missing one, keeps the descriptors read so far
        let read = read_at(&file, DESCRIPTORS + i * SECTOR, &mut d);
        if primary.is_some() && (read.is_err() || &d[1..6] != b"CD001") {
            break;
        }
        read?;
        if &d[1..6] != b"CD001" {
            return Err(corrupt("an ISO 9660 volume descriptor is malformed"));
        }
        if u16::from_le_bytes([d[128], d[129]]) != SECTOR as u16 && matches!(d[0], 1 | 2) {
            return Err(Error::Unsupported("an ISO 9660 image with blocks other than 2048 bytes".into()));
        }
        let root: [u8; 34] = d[156..190].try_into().expect("34 bytes");
        match d[0] {
            1 if primary.is_none() => primary = Some(root),
            2 if joliet.is_none() && [b"%/@", b"%/C", b"%/E"].iter().any(|e| d[88..91] == **e) => joliet = Some(root),
            255 => break,
            _ => {}
        }
    }
    let primary = primary.ok_or(corrupt("an ISO 9660 image has no primary volume descriptor"))?;
    let mut walk = Walk { file: &file, len, names: Naming::Plain, susp_bytes: MAX_SUSP_BYTES };
    let root_of = |r: &[u8; 34]| (u64::from(both32(&r[2..6])), u64::from(both32(&r[10..14])));
    let (pext, psize) = root_of(&primary);
    // Rock Ridge shows in the root's "." record: an SP entry, or Rock Ridge entries straight away
    let mut budget = MAX_DIR_BYTES;
    walk.names = Naming::RockRidge { skip: 0 };
    let dot = walk.records(pext, psize, &mut budget, true)?.into_iter().next();
    let rock = dot.as_ref().is_some_and(|d| d.rr.sp.is_some() || d.rr.mode.is_some() || d.rr.name.is_some());
    let (root_extent, root_size) = if rock {
        walk.names = Naming::RockRidge { skip: dot.and_then(|d| d.rr.sp).unwrap_or(0) };
        (pext, psize)
    } else if let Some(j) = joliet {
        walk.names = Naming::Joliet;
        root_of(&j)
    } else {
        walk.names = Naming::Plain;
        (pext, psize)
    };
    let mut entries = Vec::new();
    let mut names = Names::default();
    let mut relocation = false;
    // where a root folder named "rr_moved" sits in `entries`, should relocation be in use
    let mut rr_moved: Option<usize> = None;
    // what the files declare in all: shared extents (hard links, empty files) count once per file
    let mut declared = 0u64;
    let most = len.saturating_mul(MAX_DECLARED_RATIO).saturating_add(MAX_DECLARED_FREE);
    let mut seen = HashSet::new();
    seen.insert(root_extent);
    // depth-first, each folder before what is in it: (extent, size, the folder's name, depth)
    let mut stack: Vec<(u64, u64, Option<usize>, usize)> = vec![(root_extent, root_size, None, 0)];
    while let Some((extent, size, parent, depth)) = stack.pop() {
        let records = walk.records(extent, size, &mut budget, false)?;
        let mut folders = Vec::new();
        let mut pending: Option<(Entry, Vec<u8>)> = None;
        for r in records {
            if r.rr.relocated || r.flags & 0x04 != 0 {
                // moved elsewhere by relocation, or an associated file
                continue;
            }
            let raw = match walk.names {
                Naming::RockRidge { .. } => r.rr.name.clone().unwrap_or_else(|| plain_name(&r.name)),
                Naming::Joliet => joliet_name(&r.name),
                Naming::Plain => plain_name(&r.name),
            };
            if raw.is_empty() || raw == b"." || raw == b".." {
                continue;
            }
            let name = String::from_utf8_lossy(&raw).into_owned();
            let raw_name = std::str::from_utf8(&raw).is_err().then(|| raw.clone());
            let dir = r.flags & 0x02 != 0 || r.rr.child.is_some();
            let kind = if r.rr.symlink.is_some() {
                Kind::Symlink
            } else if dir {
                Kind::Dir
            } else if r.rr.zisofs {
                // zisofs data would come out compressed
                Kind::Other(b'z')
            } else {
                match r.rr.mode.map(|m| m & 0o170000) {
                    Some(0o010000) => Kind::Other(b'6'),
                    Some(0o020000) => Kind::Other(b'3'),
                    Some(0o060000) => Kind::Other(b'4'),
                    Some(0o140000) => Kind::Other(b's'),
                    _ => Kind::File,
                }
            };
            if entries.len() >= MAX_ENTRIES {
                return Err(corrupt("an ISO 9660 image has too many entries"));
            }
            let mtime = r.rr.mtime.or(r.mtime);
            let mut entry = |extents: Vec<(u64, u64)>| Entry {
                name: names.push(name.clone(), raw_name.clone(), parent),
                kind,
                link: r.rr.symlink.as_ref().map(|t| String::from_utf8_lossy(t).into_owned()).unwrap_or_default(),
                extents,
                mode: r.rr.mode,
                uid: r.rr.uid,
                gid: r.rr.gid,
                mtime,
            };
            if kind == Kind::File {
                walk.check_extent(r.extent, r.size)?;
                // a file of several extents: every record but the last has the multi-extent flag
                declared = declared.saturating_add(r.size);
                if declared > most {
                    return Err(corrupt("an ISO 9660 image's files declare far more data than it holds"));
                }
                match &mut pending {
                    Some((p, raw_of)) if *raw_of == raw => {
                        if p.extents.len() >= MAX_EXTENTS {
                            return Err(corrupt("an ISO 9660 file has too many extents"));
                        }
                        p.extents.push((r.extent, r.size));
                    }
                    _ => {
                        if let Some((p, _)) = pending.take() {
                            entries.push(finished(p)?);
                        }
                        pending = Some((entry(vec![(r.extent, r.size)]), raw.clone()));
                    }
                }
                if r.flags & 0x80 == 0
                    && let Some((p, _)) = pending.take()
                {
                    entries.push(finished(p)?);
                }
                continue;
            }
            if let Some((p, _)) = pending.take() {
                entries.push(finished(p)?);
            }
            let e = entry(Vec::new());
            let me = e.name;
            if kind == Kind::Dir && parent.is_none() && name == "rr_moved" {
                rr_moved = Some(entries.len());
            }
            entries.push(e);
            if kind == Kind::Dir {
                // a relocated folder's record (CL) points at the folder itself, whose "." gives its size
                let (fext, fsize) = match r.rr.child {
                    Some(at) => {
                        relocation = true;
                        let mut first = [0u8; 34];
                        walk.check_extent(at, 34)?;
                        read_at(walk.file, at * SECTOR, &mut first)?;
                        (at, u64::from(both32(&first[10..14])))
                    }
                    None => (r.extent, r.size),
                };
                if depth + 1 > MAX_DEPTH {
                    return Err(corrupt("an ISO 9660 image's folders nest too deep"));
                }
                // each folder is read once: a folder reached again (a loop) is passed over
                if seen.insert(fext) {
                    folders.push((fext, fsize, Some(me), depth + 1));
                }
            }
        }
        if let Some((p, _)) = pending.take() {
            entries.push(finished(p)?);
        }
        // the stack takes them in reverse, so the folders come out in their listed order
        stack.extend(folders.into_iter().rev());
    }
    // the folder Rock Ridge writers move deep folders into ("rr_moved" in the root) is left out once their
    // relocation has been undone; anywhere else, or with no relocation, it is an ordinary folder
    if relocation && let Some(at) = rr_moved {
        entries.remove(at);
    }
    let entries = entries.into();
    Ok(State { file, entries, names })
}

/// A file whose extents are all read: refused when they overlap one another, which no writer does and which
/// would read the same bytes over and over.
fn finished(e: Entry) -> Result<Entry> {
    let mut ranges: Vec<(u64, u64)> = e.extents.iter().map(|&(lba, len)| (lba * SECTOR, len)).collect();
    table::disjoint(&mut ranges, "an ISO 9660 file's extents overlap")?;
    Ok(e)
}

/// A file's data: its extents one after another.
pub(super) struct Data {
    file: File,
    extents: VecDeque<(u64, u64)>,
    at: u64,
    pub(super) fault: Option<&'static str>,
}

impl Read for Data {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(&(extent, len)) = self.extents.front() else { return Ok(0) };
            if self.at == len {
                self.extents.pop_front();
                self.at = 0;
                continue;
            }
            let n = buf.len().min((len - self.at).min(1 << 20) as usize);
            if n == 0 {
                return Ok(0);
            }
            let offset = extent * SECTOR + self.at;
            crate::batch::read_at_detailed(&self.file, &mut buf[..n], offset).map_err(|e| match e {
                crate::batch::PositionReadError::Eof => io::Error::from(io::ErrorKind::UnexpectedEof),
                crate::batch::PositionReadError::Io { source, .. } => source,
            })?;
            self.at += n as u64;
            return Ok(n);
        }
    }
}

impl State {
    fn next_entry(&mut self) -> Result<Option<(Member, Option<Data>)>> {
        let Some(e) = self.entries.pop_front() else { return Ok(None) };
        let (path, raw_path) = self.names.path(e.name, "an ISO 9660 path is too long")?;
        let size: u64 = e.extents.iter().map(|&(_, l)| l).sum();
        let data = (e.kind == Kind::File).then(|| -> Result<Data> {
            Ok(Data { file: self.file.try_clone()?, extents: e.extents.into(), at: 0, fault: None })
        });
        let data = data.transpose()?;
        let typeflag = match e.kind {
            Kind::File => b'0',
            Kind::Dir => b'5',
            Kind::Symlink => b'2',
            Kind::HardLink => b'1',
            Kind::Other(t) => t,
        };
        let member = Member {
            name: path,
            raw_name: raw_path,
            link: e.link,
            size: if e.kind == Kind::File { size } else { 0 },
            kind: e.kind,
            mtime: e.mtime,
            nanos: 0,
            mode: e.mode.unwrap_or(if e.kind == Kind::Dir { 0o755 } else { 0o644 }) & 0o7777,
            atime: None,
            ctime: None,
            cpio: true,
            sparse: None,
            tar: Box::new(TarMetadata {
                magic: TarMagic::Other,
                typeflag,
                user: None,
                group: None,
                uid: e.uid,
                gid: e.gid,
                device_major: None,
                device_minor: None,
                pax_header_name: None,
                pax_records: Vec::new(),
                pax_records_truncated: false,
                header: None,
            }),
        };
        Ok(Some((member, data)))
    }
}

impl super::MemberData for Data {
    fn fault(&mut self) -> Option<&'static str> {
        self.fault.take()
    }
}

impl super::RandomAccess for State {
    fn next(&mut self) -> Result<Option<super::RandomMember>> {
        Ok(self.next_entry()?.map(|(m, d)| (m, d.map(|d| Box::new(d) as Box<dyn super::MemberData>))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_in_both_forms() {
        // 2026-01-02 03:04:05 UTC, written in UTC and at UTC+1
        assert_eq!(time7(&[126, 1, 2, 3, 4, 5, 0]), Some(1_767_323_045));
        assert_eq!(time7(&[126, 1, 2, 4, 4, 5, 4]), Some(1_767_323_045));
        assert_eq!(time17(b"20260102030405\x00\x00\x00"), Some(1_767_323_045));
        assert_eq!(time7(&[126, 13, 2, 3, 4, 5, 0]), None);
    }

    fn rec(name: &[u8], extent: u32, size: u32, flags: u8) -> Vec<u8> {
        let mut r = vec![0u8; 33];
        r[2..6].copy_from_slice(&extent.to_le_bytes());
        r[6..10].copy_from_slice(&extent.to_be_bytes());
        r[10..14].copy_from_slice(&size.to_le_bytes());
        r[14..18].copy_from_slice(&size.to_be_bytes());
        r[18..25].copy_from_slice(&[126, 1, 2, 3, 4, 5, 0]);
        r[25] = flags;
        r[32] = name.len() as u8;
        r.extend_from_slice(name);
        if r.len() % 2 == 1 {
            r.push(0);
        }
        r[0] = r.len() as u8;
        r
    }

    /// 100 folders, one in the next, each with a 200-byte name, and 2,000 files in the deepest: each name is kept
    /// once, and a 20 KB path is built only as its file is handed out.
    #[test]
    fn paths_are_built_one_at_a_time() {
        let (depth, files) = (100usize, 2000usize);
        let dir_name = |i: usize| format!("{i:03}{}", "d".repeat(197)).into_bytes();
        // folder i at sector 18 + i; the deepest one's records run over `list` sectors from there
        let list = (files * 50).div_ceil(SECTOR as usize) + 2;
        let size = |i: usize| if i + 1 == depth { (list * 2048) as u32 } else { 2048 };
        let mut img = vec![0u8; (18 + depth + list) * SECTOR as usize];
        let put = |img: &mut Vec<u8>, sector: usize, recs: &[Vec<u8>]| {
            let mut at = sector * SECTOR as usize;
            for r in recs {
                if at % SECTOR as usize + r.len() > SECTOR as usize {
                    at = (at / SECTOR as usize + 1) * SECTOR as usize;
                }
                img[at..at + r.len()].copy_from_slice(r);
                at += r.len();
            }
        };
        img[16 * 2048] = 1;
        img[16 * 2048 + 1..16 * 2048 + 6].copy_from_slice(b"CD001");
        img[16 * 2048 + 128..16 * 2048 + 130].copy_from_slice(&2048u16.to_le_bytes());
        let root = rec(&[0], 17, 2048, 2);
        img[16 * 2048 + 156..16 * 2048 + 156 + root.len()].copy_from_slice(&root);
        // sector 17 is the root, where a terminator would be: the scan stops at the first sector that isn't one
        put(&mut img, 17, &[rec(&[0], 17, 2048, 2), rec(&[1], 17, 2048, 2), rec(&dir_name(0), 18, size(0), 2)]);
        for i in 0..depth {
            let at = 18 + i;
            let mut recs = vec![rec(&[0], at as u32, size(i), 2), rec(&[1], at as u32 - 1, 2048, 2)];
            if i + 1 < depth {
                recs.push(rec(&dir_name(i + 1), at as u32 + 1, size(i + 1), 2));
            } else {
                recs.extend((0..files).map(|f| rec(format!("F{f:05}.TXT;1").as_bytes(), 0, 0, 0)));
            }
            put(&mut img, at, &recs);
        }
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, &img).unwrap();
        let mut state = open(file, img.len() as u64).unwrap();
        assert!(state.names.bytes() < depth * 210 + files * 20, "{} bytes of names kept", state.names.bytes());
        let mut longest = 0;
        let mut count = 0;
        while let Some((m, _)) = state.next_entry().unwrap() {
            longest = longest.max(m.name.len());
            count += 1;
        }
        assert_eq!(count, depth + files);
        assert!(longest > depth * 200, "{longest}");
    }

    /// A symbolic link component flagged CONTINUE goes on in the next one, even in the next SL entry.
    #[test]
    fn continued_symbolic_link_components_join() {
        let file = tempfile::tempfile().unwrap();
        let mut walk = Walk { file: &file, len: 0, names: Naming::RockRidge { skip: 0 }, susp_bytes: MAX_SUSP_BYTES };
        let sl = |components: &[(u8, &[u8])]| {
            let mut body = vec![0u8];
            for (flags, c) in components {
                body.push(*flags);
                body.push(c.len() as u8);
                body.extend_from_slice(c);
            }
            let mut e = vec![b'S', b'L', (body.len() + 4) as u8, 1];
            e.extend(body);
            e
        };
        // "foo" continues into "bar" (in the next SL entry), then "baz" after a slash; and "/" then "etc"
        let mut area = sl(&[(0x01, b"foo")]);
        area.extend(sl(&[(0, b"bar"), (0, b"baz")]));
        let mut rr = Rr::default();
        walk.susp(&area, &mut rr, 0).unwrap();
        assert_eq!(rr.symlink.as_deref(), Some(&b"foobar/baz"[..]));
        let mut rr = Rr::default();
        walk.susp(&sl(&[(0x08, b""), (0, b"etc"), (0x04, b""), (0, b"x")]), &mut rr, 0).unwrap();
        assert_eq!(rr.symlink.as_deref(), Some(&b"/etc/../x"[..]));
    }

    #[test]
    fn names_lose_their_version() {
        assert_eq!(plain_name(b"A.TXT;1"), b"A.TXT");
        assert_eq!(plain_name(b"README.;1"), b"README");
        assert_eq!(joliet_name(&[0, b'a', 0, b';', 0, b'1']), b"a");
    }
}
