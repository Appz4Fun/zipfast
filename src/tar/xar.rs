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

//! xar archives (`.xar`, and the outer layer of a macOS `.pkg`), read as tar members so they take tar's whole
//! pipeline. A xar file is a header, a zlib-compressed XML table of contents, and a heap: each file's data sits at
//! an offset in the heap, stored or compressed with gzip (zlib), bzip2, xz or LZMA, with a checksum of the data
//! as extracted that is checked as it is read (SHA-1, MD5, SHA-256, SHA-512). A file with no such checksum or another
//! kind, and a table of contents whose header names none (algorithm 0) or an unknown one, are read unchecked:
//! xar gives nothing else to check them by. Files may not share heap ranges, so no data is decoded twice.
//!
//! The table of contents is read by a small XML reader bounded in size and nesting, which expands no entity but
//! the five XML defines and character references, and refuses a document type declaration.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read};

use super::table::{self, Names};
use super::{Kind, Member, TarMagic, TarMetadata};
use crate::error::{Error, Result};

/// The most a table of contents may take, compressed or not.
const MAX_TOC: u64 = 64 << 20;
/// How deep the table of contents' elements may nest (files within folders count one level each, plus a few).
const MAX_DEPTH: usize = 256;
/// The most files a table of contents may list (each takes a few hundred bytes while the archive is read).
const MAX_FILES: usize = 1 << 18;
const MAX_TEXT: usize = 1 << 20;

pub(super) const MAGIC: &[u8; 4] = b"xar!";

fn corrupt(why: &'static str) -> Error {
    Error::Corrupt(why)
}

/// How a file's data is stored in the heap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Stored,
    Zlib,
    Bzip2,
    Xz,
    Lzma,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Digest {
    Sha1(Vec<u8>),
    Md5(Vec<u8>),
    Sha256(Vec<u8>),
    Sha512(Vec<u8>),
}

/// One file of the table of contents.
#[derive(Debug, Default)]
struct Entry {
    id: Option<String>,
    /// the <file> this one sits in, which comes before it
    parent: Option<usize>,
    /// its own name; the full path is built only as the file is handed out, from its folders' names
    path: String,
    raw_path: Option<Vec<u8>>,
    kind: Option<String>,
    /// the `link` attribute of `type`: "original" for a hard link's first name, else the id it links to
    hard: Option<String>,
    /// a symbolic link's target
    target: Option<String>,
    /// a hard link's file (chains followed to the file that holds the data), or Err when the chain leads nowhere
    link_to: Option<std::result::Result<usize, ()>>,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    user: Option<String>,
    group: Option<String>,
    mtime: Option<i64>,
    /// (heap offset, archived length, extracted size)
    data: Option<(u64, u64, u64)>,
    encoding: Option<Encoding>,
    digest: Option<Digest>,
}

/// What a xar archive's reader keeps: the files still to hand out, and where to read their data.
pub(super) struct State {
    file: File,
    heap: u64,
    len: u64,
    entries: Vec<Entry>,
    /// every file's own name and folder, its full path built only as it is handed out
    names: Names,
    /// the order to hand them out in: the table's, with hard links moved after the file they link to
    order: VecDeque<usize>,
}

/// Reads the header and table of contents of the xar archive at `file`, `len` bytes long.
pub(super) fn open(mut file: File, len: u64) -> Result<State> {
    let mut head = [0u8; 28];
    read_at(&mut file, 0, &mut head)?;
    if &head[..4] != MAGIC {
        return Err(Error::NotAnArchive);
    }
    let header_size = u64::from(u16::from_be_bytes([head[4], head[5]]));
    let toc_packed = u64::from_be_bytes(head[8..16].try_into().expect("8 bytes"));
    let toc_size = u64::from_be_bytes(head[16..24].try_into().expect("8 bytes"));
    let alg = u32::from_be_bytes(head[24..28].try_into().expect("4 bytes"));
    if header_size < 28 || toc_packed > MAX_TOC || toc_size > MAX_TOC {
        return Err(corrupt("a xar header is impossible"));
    }
    // a header longer than 28 bytes names its checksum ("sha256", ...) when the algorithm number is 3
    let mut alg_name = String::new();
    if alg == 3 && header_size > 28 {
        let mut name = vec![0u8; (header_size - 28).min(64) as usize];
        read_at(&mut file, 28, &mut name)?;
        alg_name = String::from_utf8_lossy(super::text(&name)).into_owned();
    }
    let heap = header_size.checked_add(toc_packed).filter(|&h| h <= len).ok_or(Error::Truncated)?;
    let mut packed = vec![0u8; toc_packed as usize];
    read_at(&mut file, header_size, &mut packed)?;
    let mut toc = Vec::new();
    flate2::read::ZlibDecoder::new(&packed[..])
        .take(MAX_TOC + 1)
        .read_to_end(&mut toc)
        .map_err(|_| corrupt("a xar table of contents doesn't decompress"))?;
    if toc.len() as u64 != toc_size {
        return Err(corrupt("a xar table of contents has the wrong size"));
    }
    let (mut entries, order, toc_sum, toc_style) = parse_toc(&toc)?;
    // algorithm 3 is "other": named after the header, or only in the TOC's own <checksum style="...">
    if alg == 3 && alg_name.is_empty() {
        alg_name = toc_style.unwrap_or_default();
    }
    // the table of contents' own checksum, kept in the heap
    let digest = match (alg, alg_name.as_str()) {
        (1, _) => Some(Digest::Sha1(Vec::new())),
        (2, _) => Some(Digest::Md5(Vec::new())),
        (3, "sha256") => Some(Digest::Sha256(Vec::new())),
        (3, "sha512") => Some(Digest::Sha512(Vec::new())),
        _ => None,
    };
    // a header that names a checksum the table doesn't say where to find has lost it: refused, not read unchecked
    if digest.is_some() && toc_sum.is_none() {
        return Err(corrupt("a xar table of contents' checksum is missing"));
    }
    if let (Some((offset, size)), Some(kind)) = (toc_sum, digest) {
        let start = heap.checked_add(offset).filter(|s| s.checked_add(size).is_some_and(|e| e <= len));
        let start = start.ok_or(corrupt("a xar table of contents' checksum lies outside the file"))?;
        if size > 64 {
            return Err(corrupt("a xar table of contents' checksum is too long"));
        }
        let mut stored = vec![0u8; size as usize];
        read_at(&mut file, start, &mut stored)?;
        let mut h = Hasher::of(&kind);
        h.update(&packed);
        if h.finish() != stored {
            return Err(corrupt("a xar table of contents fails its checksum"));
        }
    }
    let mut names = Names::default();
    for e in &mut entries {
        names.push(std::mem::take(&mut e.path), e.raw_path.take(), e.parent);
    }
    Ok(State { file, heap, len, entries, names, order: order.into() })
}

fn read_at(file: &mut File, at: u64, buf: &mut [u8]) -> Result<()> {
    crate::batch::read_at_detailed(file, buf, at).map_err(|e| match e {
        crate::batch::PositionReadError::Eof => Error::Truncated,
        crate::batch::PositionReadError::Io { source, .. } => Error::Io(source),
    })
}

enum Hasher {
    Sha1(crate::crypto::Sha1Digest),
    Md5(crate::crypto::Md5),
    Sha256(crate::crypto::Sha256),
    Sha512(crate::crypto::Sha512),
}

impl Hasher {
    fn of(d: &Digest) -> Self {
        match d {
            Digest::Sha1(_) => Hasher::Sha1(crate::crypto::Sha1Digest::new()),
            Digest::Md5(_) => Hasher::Md5(crate::crypto::Md5::new()),
            Digest::Sha256(_) => Hasher::Sha256(crate::crypto::Sha256::new()),
            Digest::Sha512(_) => Hasher::Sha512(crate::crypto::Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha1(h) => h.update(data),
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Md5(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// A range of the archive file, read with positional reads.
struct Range {
    file: File,
    at: u64,
    end: u64,
}

impl Read for Range {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min((self.end - self.at).min(1 << 20) as usize);
        if n == 0 {
            return Ok(0);
        }
        crate::batch::read_at_detailed(&self.file, &mut buf[..n], self.at).map_err(|e| match e {
            crate::batch::PositionReadError::Eof => io::Error::from(io::ErrorKind::UnexpectedEof),
            crate::batch::PositionReadError::Io { source, .. } => source,
        })?;
        self.at += n as u64;
        Ok(n)
    }
}

/// A file's data as extracted: exactly its size, checked against its checksum as the last byte comes out.
pub(super) struct Data {
    inner: Box<dyn Read>,
    left: u64,
    /// the data's length in the archive, as stored or compressed
    packed: u64,
    /// set once the end has been checked: no byte past the size, and the checksum
    ended: bool,
    hasher: Option<(Hasher, Vec<u8>)>,
    /// why the last read failed, when it was the data's own fault
    pub(super) fault: Option<&'static str>,
}

impl Read for Data {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            // an empty file is checked on its first read: nothing ever comes out of it to trigger the check below
            if !self.ended {
                self.end()?;
            }
            return Ok(0);
        }
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "a xar file's data is shorter than its size"));
        }
        if let Some((h, _)) = &mut self.hasher {
            h.update(&buf[..n]);
        }
        self.left -= n as u64;
        // checked as the last byte comes out: the reader may never ask past the size
        if self.left == 0 {
            self.end()?;
        }
        Ok(n)
    }
}

impl Data {
    /// Checks the end of the data, once all of its size is out: no byte past it, and its checksum.
    fn end(&mut self) -> io::Result<()> {
        self.ended = true;
        let bad = |why: &'static str| io::Error::new(io::ErrorKind::InvalidData, why);
        if self.inner.read(&mut [0u8; 1])? != 0 {
            self.fault = Some("a xar file's data is longer than its size");
            return Err(bad("a xar file's data is longer than its size"));
        }
        if let Some((h, want)) = self.hasher.take()
            && h.finish() != want
        {
            self.fault = Some("a xar file fails its checksum");
            return Err(bad("a xar file fails its checksum"));
        }
        Ok(())
    }
}

impl State {
    /// The next file as a member, and a reader of its data when it has any.
    fn path(&self, i: usize) -> Result<(String, Option<Vec<u8>>)> {
        self.names.path(i, "a xar file's path is too long")
    }

    fn next_entry(&mut self) -> Result<Option<(Member, Option<Data>)>> {
        let Some(i) = self.order.pop_front() else { return Ok(None) };
        let (path, raw_path) = self.path(i)?;
        let link_target = match self.entries[i].link_to.take() {
            Some(Ok(t)) => Some(self.path(t)?.0),
            // a link that leads nowhere has no target: an empty one, which no member can be named, fails it alone
            Some(Err(())) => Some(String::new()),
            None => None,
        };
        // what the file says beyond its name and folder is needed once, here
        let mut e = std::mem::take(&mut self.entries[i]);
        e.path = path;
        e.raw_path = raw_path;
        if link_target.is_some() {
            e.target = link_target;
        }
        let kind = match (e.kind.as_deref(), e.hard.as_deref()) {
            (Some("directory"), _) => Kind::Dir,
            (Some("symlink"), _) => Kind::Symlink,
            (Some("hardlink"), Some(h)) if h != "original" => Kind::HardLink,
            (Some("file") | Some("hardlink") | None, _) => Kind::File,
            (Some("fifo"), _) => Kind::Other(b'6'),
            (Some("character special"), _) => Kind::Other(b'3'),
            (Some("block special"), _) => Kind::Other(b'4'),
            _ => Kind::Other(b's'),
        };
        let mut data = None;
        let mut size = 0;
        if kind == Kind::File
            && let Some((offset, length, extracted)) = e.data
        {
            let start = self.heap.checked_add(offset);
            let end = start.and_then(|s| s.checked_add(length)).filter(|&end| end <= self.len);
            let (Some(start), Some(end)) = (start, end) else {
                return Err(corrupt("a xar file's data lies outside the archive"));
            };
            let range = Range { file: self.file.try_clone()?, at: start, end };
            let inner: Box<dyn Read> = match e.encoding.unwrap_or(Encoding::Stored) {
                Encoding::Stored => Box::new(range),
                Encoding::Zlib => Box::new(flate2::read::ZlibDecoder::new(range)),
                Encoding::Bzip2 => Box::new(bzip2::read::BzDecoder::new(range)),
                Encoding::Xz => {
                    let stream = liblzma::stream::Stream::new_stream_decoder(crate::stream::LZMA_MEMORY_LIMIT, 0)
                        .map_err(io::Error::other)?;
                    Box::new(liblzma::read::XzDecoder::new_stream(range, stream))
                }
                Encoding::Lzma => {
                    let stream = liblzma::stream::Stream::new_lzma_decoder(crate::stream::LZMA_MEMORY_LIMIT)
                        .map_err(io::Error::other)?;
                    Box::new(liblzma::read::XzDecoder::new_stream(range, stream))
                }
            };
            let hasher = e.digest.as_ref().map(|d| {
                let want = match d {
                    Digest::Sha1(w) | Digest::Md5(w) | Digest::Sha256(w) | Digest::Sha512(w) => w.clone(),
                };
                (Hasher::of(d), want)
            });
            size = extracted;
            data = Some(Data { inner, left: extracted, packed: length, ended: false, hasher, fault: None });
        }
        let typeflag = match kind {
            Kind::File => b'0',
            Kind::Dir => b'5',
            Kind::Symlink => b'2',
            Kind::HardLink => b'1',
            Kind::Other(t) => t,
        };
        let link = match kind {
            Kind::Symlink => e.target.clone().unwrap_or_default(),
            Kind::HardLink => e.target.clone().unwrap_or_default(),
            _ => String::new(),
        };
        let member = Member {
            name: e.path,
            raw_name: e.raw_path,
            link,
            raw_link: None,
            size,
            kind,
            mtime: e.mtime,
            nanos: 0,
            mode: e.mode.unwrap_or(if kind == Kind::Dir { 0o755 } else { 0o644 }) & 0o7777,
            atime: None,
            ctime: None,
            cpio: true,
            sparse: None,
            tar: Box::new(TarMetadata {
                magic: TarMagic::Other,
                typeflag,
                user: e.user,
                group: e.group,
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

/// Seconds since 1970 from an ISO 8601 time as xar writes it: `2026-01-02T03:04:05Z`, a fraction allowed.
fn parse_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in text.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn hex(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if !t.len().is_multiple_of(2) {
        return None;
    }
    (0..t.len()).step_by(2).map(|i| u8::from_str_radix(t.get(i..i + 2)?, 16).ok()).collect()
}

/// The files of a table of contents with their own names and folders, the order to hand them out in (each folder
/// before what is in it, each hard link after its file), where the table's own checksum is kept in the heap, and
/// the style it names.
#[allow(clippy::type_complexity)]
fn parse_toc(toc: &[u8]) -> Result<(Vec<Entry>, Vec<usize>, Option<(u64, u64)>, Option<String>)> {
    let mut xml = xml::Reader::new(toc);
    // the open elements' names; for each open <file>, its index in `entries`
    let mut stack: Vec<String> = Vec::new();
    let mut files: Vec<usize> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut toc_sum: (Option<u64>, Option<u64>) = (None, None);
    let mut toc_style: Option<String> = None;
    let mut text = String::new();
    // attributes of the open elements that matter once their text is in: name's enctype, type's link, ...
    let mut open_attrs: Vec<Vec<(String, String)>> = Vec::new();
    while let Some(event) = xml.next()? {
        match event {
            xml::Event::Start { name, attrs: a, empty } => {
                if stack.len() >= MAX_DEPTH {
                    return Err(corrupt("a xar table of contents nests too deep"));
                }
                text.clear();
                let attrs = a;
                let in_toc = stack.len() >= 2 && stack[0] == "xar" && stack[1] == "toc";
                if name == "file" && in_toc && stack.last().is_some_and(|p| p == "toc" || p == "file") {
                    if entries.len() >= MAX_FILES {
                        return Err(corrupt("a xar table of contents lists too many files"));
                    }
                    let id = attrs.iter().find(|(k, _)| k == "id").map(|(_, v)| v.clone());
                    entries.push(Entry { id, parent: files.last().copied(), ..Entry::default() });
                    files.push(entries.len() - 1);
                }
                // an <encoding style="..."/> carries its value in an attribute
                if name == "encoding"
                    && stack.last().is_some_and(|p| p == "data")
                    && stack.iter().rev().nth(1).is_some_and(|p| p == "file")
                    && let Some(&i) = files.last()
                {
                    let style = attrs.iter().find(|(k, _)| k == "style").map(|(_, v)| v.as_str()).unwrap_or("");
                    entries[i].encoding = Some(match style {
                        "application/octet-stream" | "" => Encoding::Stored,
                        "application/x-gzip" => Encoding::Zlib,
                        "application/x-bzip2" => Encoding::Bzip2,
                        "application/x-xz" => Encoding::Xz,
                        "application/x-lzma" => Encoding::Lzma,
                        _ => return Err(Error::Unsupported(format!("xar data encoded as {style}"))),
                    });
                }
                if name == "checksum" && stack.len() == 2 && stack[1] == "toc" {
                    toc_style = attrs.iter().find(|(k, _)| k == "style").map(|(_, v)| v.clone());
                }
                stack.push(name);
                open_attrs.push(attrs);
                if empty {
                    stack.pop();
                    open_attrs.pop();
                }
            }
            xml::Event::Text(t) => {
                if text.len() + t.len() > MAX_TEXT {
                    return Err(corrupt("a xar table of contents has an element too long"));
                }
                text.push_str(&t);
            }
            xml::Event::End => {
                let Some(name) = stack.pop() else { return Err(corrupt("a xar table of contents is malformed")) };
                let a = open_attrs.pop().unwrap_or_default();
                let attr = |k: &str| a.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
                let parent = stack.last().map(String::as_str);
                let value = std::mem::take(&mut text);
                let v = value.trim();
                // the table's own checksum: <toc><checksum><offset/><size/></checksum>
                if stack.len() == 3 && stack[1] == "toc" && stack[2] == "checksum" {
                    match name.as_str() {
                        "offset" => toc_sum.0 = v.parse().ok(),
                        "size" => toc_sum.1 = v.parse().ok(),
                        _ => {}
                    }
                    continue;
                }
                if name == "file" && parent.is_some_and(|p| p == "toc" || p == "file") {
                    files.pop();
                    continue;
                }
                let Some(&i) = files.last() else { continue };
                let e = &mut entries[i];
                let num =
                    |v: &str| v.parse::<u64>().map_err(|_| corrupt("a xar table of contents' number is unreadable"));
                match (parent, name.as_str()) {
                    (Some("file"), "name") => {
                        let raw = if attr("enctype") == Some("base64") {
                            base64(v).ok_or(corrupt("a xar file's base64 name is unreadable"))?
                        } else {
                            value.as_bytes().to_vec()
                        };
                        let name = String::from_utf8_lossy(&raw).into_owned();
                        let raw_path = std::str::from_utf8(&raw).is_err().then_some(raw);
                        e.path = name;
                        e.raw_path = raw_path;
                    }
                    (Some("file"), "type") => {
                        e.kind = Some(v.to_owned());
                        e.hard = attr("link").map(str::to_owned);
                    }
                    (Some("file"), "link") => e.target = Some(value.clone()),
                    (Some("file"), "mode") => {
                        e.mode =
                            Some(u32::from_str_radix(v, 8).map_err(|_| corrupt("a xar file's mode is unreadable"))?)
                    }
                    (Some("file"), "uid") => e.uid = v.parse().ok(),
                    (Some("file"), "gid") => e.gid = v.parse().ok(),
                    (Some("file"), "user") => e.user = Some(v.to_owned()),
                    (Some("file"), "group") => e.group = Some(v.to_owned()),
                    (Some("file"), "mtime") => e.mtime = parse_time(v),
                    (Some("data"), "offset") if stack.iter().rev().nth(1).is_some_and(|p| p == "file") => {
                        let d = e.data.get_or_insert((0, 0, 0));
                        d.0 = num(v)?;
                    }
                    (Some("data"), "length") if stack.iter().rev().nth(1).is_some_and(|p| p == "file") => {
                        let d = e.data.get_or_insert((0, 0, 0));
                        d.1 = num(v)?;
                    }
                    (Some("data"), "size") if stack.iter().rev().nth(1).is_some_and(|p| p == "file") => {
                        let d = e.data.get_or_insert((0, 0, 0));
                        d.2 = num(v)?;
                    }
                    (Some("data"), "extracted-checksum") if stack.iter().rev().nth(1).is_some_and(|p| p == "file") => {
                        let digest = hex(v).ok_or(corrupt("a xar file's checksum is unreadable"))?;
                        e.digest = match attr("style") {
                            Some("sha1") if digest.len() == 20 => Some(Digest::Sha1(digest)),
                            Some("md5") if digest.len() == 16 => Some(Digest::Md5(digest)),
                            Some("sha256") if digest.len() == 32 => Some(Digest::Sha256(digest)),
                            Some("sha512") if digest.len() == 64 => Some(Digest::Sha512(digest)),
                            Some("sha1" | "md5" | "sha256" | "sha512") => {
                                return Err(corrupt("a xar file's checksum has the wrong length"));
                            }
                            // other digests (sha224, sha384, ...) are not checked
                            _ => None,
                        };
                    }
                    _ => {}
                }
            }
        }
    }
    if !stack.is_empty() {
        return Err(corrupt("a xar table of contents is cut short"));
    }
    let by_id: HashMap<String, usize> =
        entries.iter().enumerate().filter_map(|(i, e)| Some((e.id.clone()?, i))).collect();
    let link_id = |e: &Entry| -> Option<String> {
        (e.kind.as_deref() == Some("hardlink")).then(|| e.hard.clone()).flatten().filter(|h| h != "original")
    };
    // a hard link names another file's id, which may be a link itself: the chain is followed to the file that
    // holds the data, and the link moves to just after it (macOS xar can list a link before its original)
    let mut after: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut deferred = vec![false; entries.len()];
    for i in 0..entries.len() {
        let Some(mut id) = link_id(&entries[i]) else { continue };
        let mut hops = 0;
        let resolved = loop {
            let Some(&t) = by_id.get(&id) else { break Err(()) };
            match link_id(&entries[t]) {
                Some(next) if hops < 64 && t != i => {
                    id = next;
                    hops += 1;
                }
                Some(_) => break Err(()),
                None => break Ok(t),
            }
        };
        if let Ok(t) = resolved
            && t > i
        {
            after.entry(t).or_default().push(i);
            deferred[i] = true;
        }
        entries[i].link_to = Some(resolved);
    }
    let mut order = Vec::with_capacity(entries.len());
    for (i, &moved) in deferred.iter().enumerate() {
        if moved {
            continue;
        }
        order.push(i);
        order.extend(after.get(&i).map(Vec::as_slice).unwrap_or(&[]));
    }
    // each file's data has a heap range of its own: files sharing one would decode the same bytes over and over
    let mut ranges: Vec<(u64, u64)> = entries
        .iter()
        .filter(|e| link_id(e).is_none() && matches!(e.kind.as_deref(), Some("file" | "hardlink") | None))
        .filter_map(|e| e.data)
        .filter(|&(_, length, _)| length > 0)
        .map(|(offset, length, _)| (offset, length))
        .collect();
    table::disjoint(&mut ranges, "xar files share heap data")?;
    let toc_sum = match toc_sum {
        (Some(o), Some(s)) => Some((o, s)),
        _ => None,
    };
    Ok((entries, order, toc_sum, toc_style))
}

/// A small XML reader for xar's table of contents: elements, attributes, text and CDATA, the five predefined
/// entities and character references. A document type declaration is refused, so no entity is ever defined.
mod xml {
    use crate::error::{Error, Result};

    pub(super) enum Event {
        Start { name: String, attrs: Vec<(String, String)>, empty: bool },
        End,
        Text(String),
    }

    pub(super) struct Reader<'a> {
        b: &'a [u8],
        at: usize,
    }

    fn bad() -> Error {
        Error::Corrupt("a xar table of contents is malformed XML")
    }

    fn unescape(raw: &[u8]) -> Result<String> {
        let s = std::str::from_utf8(raw).map_err(|_| bad())?;
        if !s.contains('&') {
            return Ok(s.to_owned());
        }
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find('&') {
            out.push_str(&rest[..i]);
            let end = rest[i..].find(';').ok_or_else(bad)? + i;
            let ent = &rest[i + 1..end];
            let c = match ent {
                "lt" => '<',
                "gt" => '>',
                "amp" => '&',
                "quot" => '"',
                "apos" => '\'',
                _ if ent.starts_with("#x") => {
                    char::from_u32(u32::from_str_radix(&ent[2..], 16).map_err(|_| bad())?).ok_or_else(bad)?
                }
                _ if ent.starts_with('#') => char::from_u32(ent[1..].parse().map_err(|_| bad())?).ok_or_else(bad)?,
                _ => return Err(bad()),
            };
            out.push(c);
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    impl<'a> Reader<'a> {
        pub(super) fn new(b: &'a [u8]) -> Self {
            Reader { b, at: 0 }
        }

        fn find(&self, pat: &[u8]) -> Result<usize> {
            self.b[self.at..].windows(pat.len()).position(|w| w == pat).map(|i| self.at + i).ok_or_else(bad)
        }

        pub(super) fn next(&mut self) -> Result<Option<Event>> {
            loop {
                if self.at >= self.b.len() {
                    return Ok(None);
                }
                if self.b[self.at] != b'<' {
                    let end = self.b[self.at..].iter().position(|&c| c == b'<').map_or(self.b.len(), |i| self.at + i);
                    let text = unescape(&self.b[self.at..end])?;
                    self.at = end;
                    return Ok(Some(Event::Text(text)));
                }
                let rest = &self.b[self.at..];
                if rest.starts_with(b"<?") {
                    self.at = self.find(b"?>")? + 2;
                    continue;
                }
                if rest.starts_with(b"<!--") {
                    self.at = self.find(b"-->")? + 3;
                    continue;
                }
                if rest.starts_with(b"<![CDATA[") {
                    let start = self.at + 9;
                    self.at = start;
                    let end = self.find(b"]]>")?;
                    let text = std::str::from_utf8(&self.b[start..end]).map_err(|_| bad())?.to_owned();
                    self.at = end + 3;
                    return Ok(Some(Event::Text(text)));
                }
                if rest.starts_with(b"<!") {
                    // a document type declaration could define entities: none is taken
                    return Err(Error::Corrupt("a xar table of contents has a document type declaration"));
                }
                if rest.starts_with(b"</") {
                    self.at = self.find(b">")? + 1;
                    return Ok(Some(Event::End));
                }
                // a start tag: name, attributes, then > or />
                let mut i = self.at + 1;
                let name_end = i + self.b[i..]
                    .iter()
                    .position(|&c| c.is_ascii_whitespace() || c == b'>' || c == b'/')
                    .ok_or_else(bad)?;
                let name = std::str::from_utf8(&self.b[i..name_end]).map_err(|_| bad())?.to_owned();
                if name.is_empty() {
                    return Err(bad());
                }
                i = name_end;
                let mut attrs = Vec::new();
                loop {
                    while i < self.b.len() && self.b[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    match self.b.get(i) {
                        Some(b'>') => {
                            self.at = i + 1;
                            return Ok(Some(Event::Start { name, attrs, empty: false }));
                        }
                        Some(b'/') if self.b.get(i + 1) == Some(&b'>') => {
                            self.at = i + 2;
                            return Ok(Some(Event::Start { name, attrs, empty: true }));
                        }
                        Some(_) => {
                            let eq = i + self.b[i..].iter().position(|&c| c == b'=').ok_or_else(bad)?;
                            let key = std::str::from_utf8(&self.b[i..eq]).map_err(|_| bad())?.trim().to_owned();
                            let mut j = eq + 1;
                            while j < self.b.len() && self.b[j].is_ascii_whitespace() {
                                j += 1;
                            }
                            let quote = *self.b.get(j).ok_or_else(bad)?;
                            if quote != b'"' && quote != b'\'' {
                                return Err(bad());
                            }
                            let end = j + 1 + self.b[j + 1..].iter().position(|&c| c == quote).ok_or_else(bad)?;
                            attrs.push((key, unescape(&self.b[j + 1..end])?));
                            i = end + 1;
                        }
                        None => return Err(bad()),
                    }
                }
            }
        }
    }
}

impl super::MemberData for Data {
    fn fault(&mut self) -> Option<&'static str> {
        self.fault.take()
    }

    fn packed(&self) -> Option<u64> {
        Some(self.packed)
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
    fn times_read_as_utc() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2026-01-02T03:04:05Z"), Some(1_767_323_045));
        assert_eq!(parse_time("2000-02-29T12:00:00.5Z"), Some(951_825_600));
        assert_eq!(parse_time("2026-13-02T03:04:05Z"), None);
    }

    #[test]
    fn the_xml_reader_takes_no_entity_it_doesnt_know() {
        let read = |s: &str| -> Result<Vec<String>> {
            let mut r = xml::Reader::new(s.as_bytes());
            let mut out = Vec::new();
            while let Some(e) = r.next()? {
                if let xml::Event::Text(t) = e {
                    out.push(t);
                }
            }
            Ok(out)
        };
        assert_eq!(read("<a>x &lt;&#65;&#x42;&amp; <![CDATA[<raw>]]></a>").unwrap(), ["x <AB& ", "<raw>"]);
        assert!(read("<!DOCTYPE a [<!ENTITY e \"boom\">]><a>&e;</a>").is_err());
        assert!(read("<a>&e;</a>").is_err());
        assert!(read("<a b=c></a>").is_err());
    }

    /// A folder with a 60,000-byte name and thousands of files in it: each name is kept once, and a full path is
    /// built only as its file is handed out, so the table costs what it holds, not names times files.
    #[test]
    fn paths_are_built_one_at_a_time() {
        let long = "n".repeat(60_000);
        let mut toc = format!("<xar><toc><file id=\"0\"><name>{long}</name><type>directory</type>");
        let n = 5_000;
        for i in 0..n {
            toc.push_str(&format!("<file id=\"{}\"><name>c{i}</name><type>file</type></file>", i + 1));
        }
        toc.push_str("</file></toc></xar>");
        let (mut entries, order, _, _) = parse_toc(toc.as_bytes()).unwrap();
        let mut names = Names::default();
        for e in &mut entries {
            names.push(std::mem::take(&mut e.path), e.raw_path.take(), e.parent);
        }
        assert!(names.bytes() < 60_000 + 10 * n, "{} bytes of names kept", names.bytes());
        let file = tempfile::tempfile().unwrap();
        let mut state = State { file, heap: 0, len: 0, entries, names, order: order.into() };
        let mut count = 0;
        while let Some((m, _)) = state.next_entry().unwrap() {
            if count > 0 {
                assert!(m.name.starts_with(&long) && m.name.len() < 60_010);
            }
            count += 1;
        }
        assert_eq!(count, n + 1);
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut toc = String::from("<xar><toc>");
        for _ in 0..MAX_DEPTH {
            toc.push_str("<file><name>d</name>");
        }
        assert!(parse_toc(toc.as_bytes()).is_err());
    }
}
