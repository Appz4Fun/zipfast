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

//! WIM (Windows Imaging) files, read as tar members so they take tar's whole pipeline. A WIM file is a 208-byte
//! header, resources (blobs of file data, one metadata resource per image, an XML description) and a lookup table
//! that names each resource by the SHA-1 of its contents. An image's metadata resource holds its security
//! descriptors and its tree of directory entries; a file's entry names its data by SHA-1, so data shared by several
//! files is stored once.
//!
//! Resources are stored as they are or compressed in chunks (32 KiB by default) with XPRESS (Huffman) or LZX,
//! each chunk on its own, after a table of where each chunk starts. LZMS, and the solid resources that pack several
//! blobs into one compressed stream (in practice always LZMS), are refused: LZMS has no public specification.
//! Split sets (`.swm`) are refused as well.
//!
//! Everything read is bounded: the lookup table's entries, the metadata resource's size, the entries of the tree
//! (each read once, so no cycle loops), its depth, every path and all paths together. Resources may not overlap,
//! and data that several files share may be written again only up to a small multiple of the archive's size.
//! Every blob's SHA-1 is checked as its last byte is read, so no file whose data fails it is published.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read};

mod lzx;
mod xpress;

use super::{Kind, Member, TarMagic, TarMetadata, table};
use crate::crypto::Sha1Digest;
use crate::error::{Error, Result};

pub(super) const MAGIC: &[u8; 8] = b"MSWIM\0\0\0";
const HEADER_LEN: usize = 208;

/// Lookup table entries taken (each 50 bytes on disk).
const MAX_ENTRIES: usize = 1 << 20;
/// The largest metadata resource taken, decompressed.
const MAX_METADATA: u64 = 256 << 20;
/// Directory entries taken in an image.
const MAX_DENTRIES: usize = 1 << 21;
/// How deep folders may nest.
const MAX_DEPTH: usize = 1024;
/// Bytes of all the paths an image hands out, hard link targets included.
const MAX_PATH_BYTES: u64 = 512 << 20;
/// The largest reparse point (symbolic link) data taken.
const MAX_REPARSE: u64 = 64 << 10;
/// Named stream records read across an image (each entry may claim 65,535, and entries may share them).
const MAX_STREAM_RECORDS: u64 = 1 << 22;
/// Images taken.
const MAX_IMAGES: u32 = 1 << 16;

// header flags
const HDR_COMPRESSION: u32 = 0x2;
const HDR_SPANNED: u32 = 0x8;
const HDR_XPRESS: u32 = 0x2_0000;
const HDR_LZX: u32 = 0x4_0000;
const HDR_LZMS: u32 = 0x8_0000;
const HDR_XPRESS2: u32 = 0x20_0000;

// resource flags
const RES_FREE: u8 = 0x1;
const RES_METADATA: u8 = 0x2;
const RES_COMPRESSED: u8 = 0x4;
const RES_SPANNED: u8 = 0x8;
const RES_SOLID: u8 = 0x10;

// file attributes
const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_REPARSE_POINT: u32 = 0x400;

const TAG_MOUNT_POINT: u32 = 0xA000_0003;
const TAG_SYMLINK: u32 = 0xA000_000C;

/// Seconds from 1601-01-01 (FILETIME's epoch) to 1970-01-01.
const FILETIME_UNIX_DIFF: i64 = 11_644_473_600;

fn corrupt(why: &'static str) -> Error {
    Error::Corrupt(why)
}

fn lzms() -> Error {
    Error::Unsupported("WIM LZMS compression is not supported".into())
}

fn solid() -> Error {
    Error::Unsupported("WIM LZMS solid resources are not supported".into())
}

/// Whether `head` starts a WIM file.
pub(super) fn sniff(head: &[u8]) -> bool {
    head.len() >= 12
        && head.starts_with(MAGIC)
        && u32::from_le_bytes(head[8..12].try_into().expect("4 bytes")) as usize >= HEADER_LEN
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().expect("2 bytes"))
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// How chunks are compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codec {
    Xpress,
    Lzx,
}

/// A resource header: where a resource lies, how it is stored, and its size once read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResHdr {
    stored: u64,
    flags: u8,
    offset: u64,
    size: u64,
}

impl ResHdr {
    fn parse(b: &[u8]) -> Self {
        let first = le64(b, 0);
        ResHdr { stored: first & ((1 << 56) - 1), flags: (first >> 56) as u8, offset: le64(b, 8), size: le64(b, 16) }
    }
}

/// What a WIM file's header says, as [`super::wim_info`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WimInfo {
    /// The GUID every part of a WIM set shares.
    pub guid: [u8; 16],
    /// How many images the file holds; image 1 is the one extracted.
    pub images: u32,
    /// "none", "XPRESS", "LZX" or "LZMS".
    pub compression: &'static str,
    /// The size of a compressed resource's chunks.
    pub chunk_size: u32,
}

/// The header, checked.
struct Header {
    info: WimInfo,
    codec: Option<Codec>,
    lzms: bool,
    chunk: u64,
    lookup: ResHdr,
}

fn read_header(file: &File, len: u64) -> Result<Header> {
    let mut h = [0u8; HEADER_LEN];
    read_at(file, 0, &mut h)?;
    if &h[..8] != MAGIC {
        return Err(Error::NotAnArchive);
    }
    if (le32(&h, 8) as u64) < HEADER_LEN as u64 || le32(&h, 8) as u64 > len {
        return Err(corrupt("a WIM header is impossible"));
    }
    let flags = le32(&h, 16);
    let mut chunk = u64::from(le32(&h, 20));
    let guid: [u8; 16] = h[24..40].try_into().expect("16 bytes");
    let (part, parts) = (le16(&h, 40), le16(&h, 42));
    let images = le32(&h, 44);
    if part != 1 || parts != 1 || flags & HDR_SPANNED != 0 {
        return Err(Error::Unsupported("split WIM sets (.swm) are not supported".into()));
    }
    if images > MAX_IMAGES {
        return Err(corrupt("a WIM header lists too many images"));
    }
    let (codec, lzms, name) = if flags & HDR_COMPRESSION == 0 {
        (None, false, "none")
    } else if flags & HDR_LZX != 0 {
        (Some(Codec::Lzx), false, "LZX")
    } else if flags & (HDR_XPRESS | HDR_XPRESS2) != 0 {
        (Some(Codec::Xpress), false, "XPRESS")
    } else if flags & HDR_LZMS != 0 {
        (None, true, "LZMS")
    } else {
        return Err(Error::Unsupported("a WIM file's compression is unknown".into()));
    };
    if codec.is_some() || lzms {
        // old files leave the chunk size out; it is then 32 KiB
        if chunk == 0 {
            chunk = 32 << 10;
        }
        let ok = chunk.is_power_of_two()
            && match codec {
                Some(Codec::Lzx) => chunk == lzx::MAX_CHUNK_SIZE as u64,
                Some(Codec::Xpress) => (4096..=xpress::MAX_CHUNK as u64).contains(&chunk),
                None => true,
            };
        if !ok && !lzms {
            return Err(Error::Unsupported(format!("WIM chunks of {chunk} bytes are not supported for {name}")));
        }
    }
    let lookup = ResHdr::parse(&h[48..72]);
    Ok(Header {
        info: WimInfo { guid, images, compression: name, chunk_size: chunk as u32 },
        codec,
        lzms,
        chunk,
        lookup,
    })
}

/// Reads what the header of the WIM file at `file` says.
pub(super) fn info(file: &File) -> Result<WimInfo> {
    Ok(read_header(file, file.metadata()?.len())?.info)
}

fn read_at(file: &File, at: u64, buf: &mut [u8]) -> Result<()> {
    crate::batch::read_at_detailed(file, buf, at).map_err(|e| match e {
        crate::batch::PositionReadError::Eof => Error::Truncated,
        crate::batch::PositionReadError::Io { source, .. } => Error::Io(source),
    })
}

/// What decoding resources needs: the file, and how its chunks are compressed.
#[derive(Clone)]
struct Store {
    file: std::sync::Arc<File>,
    len: u64,
    codec: Option<Codec>,
    lzms: bool,
    chunk: u64,
}

impl Store {
    /// A reader of the resource `res`'s contents, which checks them against `sha1` (when given) as the last byte
    /// comes out.
    fn open(&self, res: &ResHdr, sha1: Option<[u8; 20]>) -> Result<Blob> {
        if res.flags & RES_SOLID != 0 {
            return Err(solid());
        }
        if res.flags & RES_SPANNED != 0 {
            return Err(Error::Unsupported("split WIM sets (.swm) are not supported".into()));
        }
        let end = res.offset.checked_add(res.stored).filter(|&e| e <= self.len);
        if end.is_none() || res.offset < HEADER_LEN as u64 {
            return Err(corrupt("a WIM resource lies outside the file"));
        }
        let compressed = res.flags & RES_COMPRESSED != 0;
        let chunks = if !compressed {
            if res.stored != res.size {
                return Err(corrupt("a stored WIM resource's sizes differ"));
            }
            None
        } else {
            if self.lzms {
                return Err(lzms());
            }
            let codec = self.codec.ok_or(corrupt("a WIM resource is compressed in a file that isn't"))?;
            let count = res.size.div_ceil(self.chunk);
            let width = if res.size > u64::from(u32::MAX) { 8 } else { 4 };
            let table = count.saturating_sub(1).checked_mul(width).filter(|&t| t <= res.stored);
            let Some(table) = table else { return Err(corrupt("a WIM resource's chunk table is impossible")) };
            Some(Chunks { codec, count, width, table, index: 0, cache_start: 0, cache: Vec::new() })
        };
        Ok(Blob {
            store: self.clone(),
            res: *res,
            chunks,
            out: Vec::new(),
            out_pos: 0,
            done: 0,
            hasher: sha1.map(|want| (Sha1Digest::new(), want)),
            fault: None,
        })
    }

    /// The whole contents of `res`, at most `max` bytes, checked against `sha1`.
    fn read_all(&self, res: &ResHdr, sha1: [u8; 20], max: u64, too_big: &'static str) -> Result<Vec<u8>> {
        if res.size > max {
            return Err(corrupt(too_big));
        }
        let mut blob = self.open(res, Some(sha1))?;
        let mut out = Vec::new();
        match blob.read_to_end(&mut out) {
            Ok(_) => Ok(out),
            Err(e) => Err(blob.fault.take().map_or_else(|| super::read_error(e), Error::Corrupt)),
        }
    }
}

/// Where a compressed resource is in its chunks.
struct Chunks {
    codec: Codec,
    count: u64,
    /// bytes per chunk table entry
    width: u64,
    /// the chunk table's length
    table: u64,
    /// the next chunk to decode
    index: u64,
    /// the chunk table entries read ahead: entry `cache_start + i` is `cache[i]`
    cache_start: u64,
    cache: Vec<u64>,
}

/// Chunk table entries read at a time.
const TABLE_READ: u64 = 4096;

impl Chunks {
    /// Where chunk `i` starts, counted from the end of the chunk table.
    fn start(&mut self, store: &Store, res: &ResHdr, i: u64) -> Result<u64> {
        if i == 0 {
            return Ok(0);
        }
        // table entry i - 1 holds chunk i's start
        let e = i - 1;
        if e < self.cache_start || e >= self.cache_start + self.cache.len() as u64 {
            let n = TABLE_READ.min(self.count - 1 - e);
            let mut raw = vec![0u8; (n * self.width) as usize];
            read_at(&store.file, res.offset + e * self.width, &mut raw)?;
            self.cache = raw
                .chunks_exact(self.width as usize)
                .map(|c| if self.width == 8 { le64(c, 0) } else { u64::from(le32(c, 0)) })
                .collect();
            self.cache_start = e;
        }
        Ok(self.cache[(e - self.cache_start) as usize])
    }
}

/// A resource's contents as read: exactly its size, checked against its SHA-1 as the last byte comes out.
struct Blob {
    store: Store,
    res: ResHdr,
    chunks: Option<Chunks>,
    /// the last chunk decoded, and how much of it has been handed out
    out: Vec<u8>,
    out_pos: usize,
    /// bytes handed out so far
    done: u64,
    hasher: Option<(Sha1Digest, [u8; 20])>,
    fault: Option<&'static str>,
}

impl Blob {
    /// Decodes the next chunk into `out`.
    fn next_chunk(&mut self) -> Result<()> {
        let store = self.store.clone();
        let res = self.res;
        let chunk_size = store.chunk;
        let ch = self.chunks.as_mut().expect("compressed");
        let i = ch.index;
        let data_len = res.stored - ch.table;
        let start = ch.start(&store, &res, i)?;
        let end = if i + 1 == ch.count { data_len } else { ch.start(&store, &res, i + 1)? };
        let size = if i + 1 == ch.count { res.size - i * chunk_size } else { chunk_size };
        if start > end || end > data_len || end - start > size || end == start {
            return Err(corrupt("a WIM resource's chunk table is damaged"));
        }
        let mut packed = vec![0u8; (end - start) as usize];
        read_at(&store.file, res.offset + ch.table + start, &mut packed)?;
        self.out.clear();
        if packed.len() as u64 == size {
            // a chunk that didn't shrink is stored as it is
            self.out.extend_from_slice(&packed);
        } else {
            match ch.codec {
                Codec::Xpress => xpress::decompress(&packed, size as usize, &mut self.out).map_err(corrupt)?,
                Codec::Lzx => lzx::decompress_chunk(&packed, size as usize, &mut self.out)
                    .map_err(|_| corrupt("a WIM chunk's LZX data is damaged"))?,
            }
        }
        ch.index += 1;
        self.out_pos = 0;
        Ok(())
    }

    fn fill(&mut self, buf: &mut [u8]) -> Result<usize> {
        let left = self.res.size - self.done;
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(left.min(usize::MAX as u64) as usize);
        let n = if self.chunks.is_none() {
            let n = want.min(1 << 20);
            read_at(&self.store.file, self.res.offset + self.done, &mut buf[..n])?;
            n
        } else {
            if self.out_pos == self.out.len() {
                self.next_chunk()?;
            }
            let n = want.min(self.out.len() - self.out_pos);
            buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
            n
        };
        if let Some((h, _)) = &mut self.hasher {
            h.update(&buf[..n]);
        }
        self.done += n as u64;
        if self.done == self.res.size
            && let Some((h, want)) = self.hasher.take()
            && h.finalize() != want
        {
            return Err(corrupt("a WIM file fails its SHA-1"));
        }
        Ok(n)
    }
}

impl Read for Blob {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.fill(buf) {
            Ok(n) => Ok(n),
            Err(Error::Corrupt(why)) => {
                self.fault = Some(why);
                Err(io::Error::new(io::ErrorKind::InvalidData, why))
            }
            Err(Error::Truncated) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Err(Error::Io(e)) => Err(e),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

impl super::MemberData for Blob {
    fn fault(&mut self) -> Option<&'static str> {
        self.fault.take()
    }
}

/// A lookup table entry: a blob's resource.
#[derive(Clone, Copy)]
struct Blobs {
    res: ResHdr,
}

/// A folder being walked: the offset of its next entry, and its path.
struct Frame {
    next: u64,
    path: String,
}

/// One image of a WIM file, its entries handed out one at a time as the tree is walked.
pub(super) struct State {
    store: Store,
    blobs: HashMap<[u8; 20], Blobs>,
    meta: Vec<u8>,
    stack: Vec<Frame>,
    /// every entry offset read, so none is read twice
    seen: HashSet<u64>,
    /// path bytes still to hand out
    path_budget: u64,
    /// named stream records still to be read
    streams_left: u64,
    /// symbolic link targets already read, by their reparse data's SHA-1 and tag, so shared reparse data is decoded
    /// once
    targets: HashMap<([u8; 20], u32), String>,
    /// reparse data decoded, for tests
    reparse_reads: usize,
    /// the path of each hard link group's first file
    groups: HashMap<u64, String>,
    /// blobs handed out once already, and the bytes of shared data that may still be written again
    used: HashSet<[u8; 20]>,
    shared_left: u64,
}

/// Reads the header, lookup table and image `image`'s metadata from the WIM file `file`, `len` bytes long.
pub(super) fn open(file: File, len: u64, image: u32) -> Result<State> {
    let header = read_header(&file, len)?;
    let store =
        Store { file: std::sync::Arc::new(file), len, codec: header.codec, lzms: header.lzms, chunk: header.chunk };
    // the lookup table, stored as it is
    let lt = header.lookup;
    if lt.size / 50 > MAX_ENTRIES as u64 {
        return Err(corrupt("a WIM lookup table has too many entries"));
    }
    let table = {
        let mut blob = store.open(&lt, None)?;
        let mut out = Vec::new();
        blob.read_to_end(&mut out)
            .map_err(|e| blob.fault.take().map_or_else(|| super::read_error(e), Error::Corrupt))?;
        out
    };
    let mut blobs = HashMap::new();
    let mut metadata = Vec::new();
    let mut ranges = Vec::new();
    let mut solid_blobs = HashSet::new();
    for e in table.as_chunks::<50>().0 {
        let res = ResHdr::parse(&e[..24]);
        let part = le16(e, 24);
        let sha1: [u8; 20] = e[30..50].try_into().expect("20 bytes");
        if res.flags & RES_FREE != 0 {
            continue;
        }
        if part != 1 {
            return Err(Error::Unsupported("split WIM sets (.swm) are not supported".into()));
        }
        if res.flags & RES_SOLID != 0 {
            // a solid resource itself, or a blob inside one
            solid_blobs.insert(sha1);
            if res.flags & RES_METADATA != 0 {
                metadata.push((res, sha1));
            }
            continue;
        }
        ranges.push((res.offset, res.stored));
        if res.flags & RES_METADATA != 0 {
            metadata.push((res, sha1));
        } else {
            blobs.entry(sha1).or_insert(Blobs { res });
        }
    }
    table::disjoint(&mut ranges, "WIM resources overlap")?;
    if image == 0 || image > header.info.images || image as usize > metadata.len() {
        return Err(Error::Unsupported(format!("the WIM file has no image {image}")));
    }
    let (meta_res, meta_sha1) = metadata[image as usize - 1];
    let meta = store.read_all(&meta_res, meta_sha1, MAX_METADATA, "a WIM image's metadata is too large")?;
    // security data first, then the root entry at the next 8-byte boundary
    if meta.len() < 8 {
        return Err(corrupt("a WIM image's metadata is truncated"));
    }
    let security = u64::from(le32(&meta, 0)).max(8).next_multiple_of(8);
    if security > meta.len() as u64 {
        return Err(corrupt("a WIM image's security data runs past its metadata"));
    }
    let mut state = State {
        store,
        blobs,
        meta,
        stack: Vec::new(),
        seen: HashSet::new(),
        path_budget: MAX_PATH_BYTES,
        streams_left: MAX_STREAM_RECORDS,
        targets: HashMap::new(),
        reparse_reads: 0,
        groups: HashMap::new(),
        used: HashSet::new(),
        shared_left: len.saturating_mul(8).saturating_add(64 << 20),
    };
    for s in solid_blobs {
        state.blobs.entry(s).or_insert(Blobs { res: ResHdr { stored: 0, flags: RES_SOLID, offset: 0, size: 0 } });
    }
    let root = state.dentry(security)?.ok_or(corrupt("a WIM image has no root folder"))?;
    if root.attributes & ATTR_DIRECTORY == 0 {
        return Err(corrupt("a WIM image's root isn't a folder"));
    }
    if root.subdir != 0 {
        state.enter(root.subdir, String::new())?;
    }
    Ok(state)
}

/// A directory entry, as read.
struct Dentry {
    attributes: u32,
    subdir: u64,
    atime: u64,
    mtime: u64,
    hash: [u8; 20],
    reparse_tag: u32,
    link_group: u64,
    name: String,
    /// the hashes of the streams kept with the named ones but with no name, in order (at most two are kept)
    unnamed: Vec<[u8; 20]>,
    /// where the entry after this one (its next sibling) starts
    next: u64,
}

fn filetime(t: u64) -> Option<(i64, u32)> {
    if t == 0 {
        return None;
    }
    let secs = (t / 10_000_000) as i64 - FILETIME_UNIX_DIFF;
    Some((secs, (t % 10_000_000) as u32 * 100))
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect();
    String::from_utf16_lossy(&units)
}

impl State {
    /// Starts walking the folder whose first entry is at `at`.
    fn enter(&mut self, at: u64, path: String) -> Result<()> {
        if self.stack.len() >= MAX_DEPTH {
            return Err(corrupt("a WIM image's folders nest too deep"));
        }
        self.stack.push(Frame { next: at, path });
        Ok(())
    }

    /// The entry at `at`, or None for the end of a folder's entries.
    fn dentry(&mut self, at: u64) -> Result<Option<Dentry>> {
        let meta = &self.meta;
        let bad = || corrupt("a WIM directory entry is damaged");
        let at_us = usize::try_from(at).map_err(|_| bad())?;
        if at_us.checked_add(8).is_none_or(|e| e > meta.len()) {
            return Err(bad());
        }
        let length = le64(meta, at_us);
        if length == 0 {
            return Ok(None);
        }
        if !self.seen.insert(at) {
            return Err(corrupt("a WIM image's folders form a loop"));
        }
        if self.seen.len() > MAX_DENTRIES {
            return Err(corrupt("a WIM image has too many entries"));
        }
        let end = at.checked_add(length).filter(|&e| e <= meta.len() as u64).ok_or_else(bad)?;
        if length < 102 {
            return Err(bad());
        }
        let d = &meta[at_us..end as usize];
        let attributes = le32(d, 8);
        let subdir = le64(d, 16);
        let atime = le64(d, 48);
        let mtime = le64(d, 56);
        let hash: [u8; 20] = d[64..84].try_into().expect("20 bytes");
        let (reparse_tag, link_group) =
            if attributes & ATTR_REPARSE_POINT != 0 { (le32(d, 88), 0) } else { (0, le64(d, 88)) };
        let streams = le16(d, 96);
        let short_len = usize::from(le16(d, 98));
        let name_len = usize::from(le16(d, 100));
        if name_len % 2 != 0 || 102 + name_len + short_len > d.len() {
            return Err(bad());
        }
        // lone surrogates come out as U+FFFD
        let name = utf16(&d[102..102 + name_len]);
        // the named streams follow the entry, each at an 8-byte boundary
        let mut pos = end.next_multiple_of(8);
        let mut unnamed = Vec::new();
        // charged before they are walked: entries may point their streams at the same records
        self.streams_left = self
            .streams_left
            .checked_sub(u64::from(streams))
            .ok_or(corrupt("a WIM image has too many named streams"))?;
        let meta = &self.meta;
        for _ in 0..streams {
            let p = usize::try_from(pos).map_err(|_| bad())?;
            if p.checked_add(38).is_none_or(|e| e > meta.len()) {
                return Err(bad());
            }
            let slen = le64(meta, p);
            let send = pos.checked_add(slen).filter(|&e| e <= meta.len() as u64).ok_or_else(bad)?;
            if slen < 38 {
                return Err(bad());
            }
            let sname = usize::from(le16(meta, p + 36));
            if 38 + sname as u64 > slen {
                return Err(bad());
            }
            let shash: [u8; 20] = meta[p + 16..p + 36].try_into().expect("20 bytes");
            if sname == 0 && unnamed.len() < 2 {
                unnamed.push(shash);
            }
            pos = send.next_multiple_of(8);
        }
        Ok(Some(Dentry { attributes, subdir, atime, mtime, hash, reparse_tag, link_group, name, unnamed, next: pos }))
    }

    /// Charges a path against the image's budget.
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.path_budget =
            self.path_budget.checked_sub(bytes as u64).ok_or(corrupt("a WIM image's paths add up to too much"))?;
        Ok(())
    }

    /// The blob named `sha1`, as a reader and its size; none for the all-zero hash (no data).
    fn blob(&mut self, sha1: [u8; 20]) -> Result<Option<(Blob, u64)>> {
        if sha1 == [0; 20] {
            return Ok(None);
        }
        let Some(b) = self.blobs.get(&sha1).copied() else {
            return Err(corrupt("a WIM file's data is missing from the lookup table"));
        };
        if b.res.flags & RES_SOLID != 0 {
            return Err(solid());
        }
        if !self.used.insert(sha1) {
            self.shared_left = self
                .shared_left
                .checked_sub(b.res.size)
                .ok_or(corrupt("a WIM image repeats shared data past a multiple of the archive's size"))?;
        }
        Ok(Some((self.store.open(&b.res, Some(sha1))?, b.res.size)))
    }

    /// The target of a symbolic link or junction's reparse data (without its 8-byte header, as WIM keeps it), with
    /// `/` for `\`. An absolute target keeps its leading `\??\` (as `/??/`), so the pipeline refuses it.
    fn reparse_target(&mut self, tag: u32, sha1: [u8; 20]) -> Result<String> {
        if let Some(target) = self.targets.get(&(sha1, tag)) {
            return Ok(target.clone());
        }
        let bad = || corrupt("a WIM symbolic link's reparse data is damaged");
        let Some(b) = self.blobs.get(&sha1).copied() else {
            return Err(corrupt("a WIM file's data is missing from the lookup table"));
        };
        self.reparse_reads += 1;
        let data = self.store.read_all(&b.res, sha1, MAX_REPARSE, "a WIM symbolic link's reparse data is too large")?;
        let fixed = if tag == TAG_SYMLINK { 12 } else { 8 };
        if data.len() < fixed {
            return Err(bad());
        }
        let (sub_off, sub_len) = (usize::from(le16(&data, 0)), usize::from(le16(&data, 2)));
        let relative = tag == TAG_SYMLINK && le32(&data, 8) & 1 != 0;
        let names = &data[fixed..];
        let sub = names.get(sub_off..sub_off + sub_len).ok_or_else(bad)?;
        let target = utf16(sub);
        let target = target.replace('\\', "/");
        let target = if relative || target.starts_with('/') { target } else { format!("/{target}") };
        // the cached copy counts against the paths' budget
        self.charge(target.len())?;
        self.targets.insert((sha1, tag), target.clone());
        Ok(target)
    }

    fn next_entry(&mut self) -> Result<Option<super::RandomMember>> {
        loop {
            let Some(frame) = self.stack.last() else { return Ok(None) };
            let at = frame.next;
            let Some(d) = self.dentry(at)? else {
                self.stack.pop();
                continue;
            };
            let frame = self.stack.last_mut().expect("a frame");
            frame.next = d.next;
            if d.name.is_empty() || d.name == "." || d.name == ".." || d.name.contains(['/', '\0']) {
                return Err(corrupt("a WIM directory entry has an impossible name"));
            }
            let path = if frame.path.is_empty() { d.name.clone() } else { format!("{}/{}", frame.path, d.name) };
            if path.len() > table::MAX_PATH {
                return Err(corrupt("a WIM file's path is too long"));
            }
            self.charge(path.len())?;
            let dir = d.attributes & ATTR_DIRECTORY != 0;
            let mut kind = if dir { Kind::Dir } else { Kind::File };
            let mut link = String::new();
            let mut data = None;
            let mut size = 0;
            // Streams: the entry's own hash, then the unnamed ones kept with the named streams. A reparse point's
            // first stream is its reparse data and its second its file data; a file's only one is its data.
            let mut streams = Vec::with_capacity(3);
            if d.hash != [0; 20] {
                streams.push(d.hash);
            }
            streams.extend(d.unnamed.iter().copied());
            let reparse = d.attributes & ATTR_REPARSE_POINT != 0;
            if reparse && matches!(d.reparse_tag, TAG_SYMLINK | TAG_MOUNT_POINT) {
                kind = Kind::Symlink;
                let sha1 = streams.first().copied().unwrap_or([0; 20]);
                link = self.reparse_target(d.reparse_tag, sha1)?;
            } else if !dir {
                let sha1 = streams.get(usize::from(reparse)).copied().unwrap_or([0; 20]);
                let first = (d.link_group != 0).then(|| self.groups.get(&d.link_group).cloned());
                match first {
                    Some(Some(target)) => {
                        kind = Kind::HardLink;
                        self.charge(target.len())?;
                        link = target;
                    }
                    first => {
                        if first.is_some() {
                            self.charge(path.len())?;
                            self.groups.insert(d.link_group, path.clone());
                        }
                        if let Some((blob, n)) = self.blob(sha1)? {
                            data = Some(Box::new(blob) as Box<dyn super::MemberData>);
                            size = n;
                        }
                    }
                }
            }
            if dir && d.subdir != 0 && kind == Kind::Dir {
                self.enter(d.subdir, path.clone())?;
            }
            let (mtime, nanos) = filetime(d.mtime).map_or((None, 0), |(s, n)| (Some(s), n));
            let typeflag = match kind {
                Kind::File => b'0',
                Kind::Dir => b'5',
                Kind::Symlink => b'2',
                Kind::HardLink => b'1',
                Kind::Other(t) => t,
            };
            let member = Member {
                name: path,
                raw_name: None,
                link,
                size,
                kind,
                mtime,
                nanos,
                mode: if kind == Kind::Dir { 0o755 } else { 0o644 },
                atime: filetime(d.atime),
                ctime: None,
                cpio: true,
                sparse: None,
                tar: Box::new(TarMetadata {
                    magic: TarMagic::Other,
                    typeflag,
                    user: None,
                    group: None,
                    uid: None,
                    gid: None,
                    device_major: None,
                    device_minor: None,
                    pax_header_name: None,
                    pax_records: Vec::new(),
                    pax_records_truncated: false,
                    header: None,
                }),
            };
            return Ok(Some((member, data)));
        }
    }
}

impl super::RandomAccess for State {
    fn next(&mut self) -> Result<Option<super::RandomMember>> {
        self.next_entry()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1Digest::new();
        h.update(data);
        h.finalize()
    }

    /// A directory entry: `subdir` is where a folder's entries start (0 for none).
    fn dentry(name: &str, attributes: u32, subdir: u64, hash: [u8; 20], group: u64) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let len = (102 + name.len() + 2).next_multiple_of(8);
        let mut d = vec![0u8; len];
        d[..8].copy_from_slice(&(len as u64).to_le_bytes());
        d[8..12].copy_from_slice(&attributes.to_le_bytes());
        d[12..16].copy_from_slice(&(-1i32).to_le_bytes());
        d[16..24].copy_from_slice(&subdir.to_le_bytes());
        d[56..64].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        d[64..84].copy_from_slice(&hash);
        d[88..96].copy_from_slice(&group.to_le_bytes());
        d[100..102].copy_from_slice(&(name.len() as u16).to_le_bytes());
        d[102..102 + name.len()].copy_from_slice(&name);
        d
    }

    /// An uncompressed WIM file of one image: `blobs` stored after the header, then `meta` (the metadata
    /// resource), then the lookup table; `extra` adds raw lookup entries.
    fn wim(blobs: &[&[u8]], meta: &[u8], extra: &[[u8; 50]]) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_LEN];
        let mut table = Vec::new();
        let mut entry = |out: &mut Vec<u8>, data: &[u8], flags: u8| {
            let mut e = [0u8; 50];
            e[..8].copy_from_slice(&(data.len() as u64 | (u64::from(flags) << 56)).to_le_bytes());
            e[8..16].copy_from_slice(&(out.len() as u64).to_le_bytes());
            e[16..24].copy_from_slice(&(data.len() as u64).to_le_bytes());
            e[24..26].copy_from_slice(&1u16.to_le_bytes());
            e[26..30].copy_from_slice(&1u32.to_le_bytes());
            e[30..50].copy_from_slice(&sha1(data));
            out.extend_from_slice(data);
            table.extend_from_slice(&e);
        };
        for b in blobs {
            entry(&mut out, b, 0);
        }
        entry(&mut out, meta, RES_METADATA);
        for e in extra {
            table.extend_from_slice(e);
        }
        let at = out.len() as u64;
        out.extend_from_slice(&table);
        out[..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out[12..16].copy_from_slice(&0x10d00u32.to_le_bytes());
        out[40..42].copy_from_slice(&1u16.to_le_bytes());
        out[42..44].copy_from_slice(&1u16.to_le_bytes());
        out[44..48].copy_from_slice(&1u32.to_le_bytes());
        out[48..56].copy_from_slice(&(table.len() as u64).to_le_bytes());
        out[56..64].copy_from_slice(&at.to_le_bytes());
        out[64..72].copy_from_slice(&(table.len() as u64).to_le_bytes());
        out
    }

    /// Metadata whose root folder holds `children` (each built with offsets counted from the metadata's start;
    /// the root's entries start at [`FIRST`]).
    fn meta(children: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&8u32.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
        let root = dentry("", ATTR_DIRECTORY, FIRST, [0; 20], 0);
        assert_eq!(m.len() + root.len() + 8, FIRST as usize);
        m.extend_from_slice(&root);
        m.extend_from_slice(&[0; 8]);
        for c in children {
            m.extend_from_slice(c);
        }
        m.extend_from_slice(&[0; 8]);
        m.extend_from_slice(tail);
        m
    }

    /// Where the root folder's entries start: after the security data (8), the root (104) and its end marker.
    const FIRST: u64 = 8 + 104 + 8;

    /// A member's name, and its data read whole (or the error reading it gave).
    type Got = (String, std::result::Result<Vec<u8>, String>);

    /// Every member's name and data.
    fn read(bytes: &[u8]) -> Result<Vec<Got>> {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        let mut state = open(f, bytes.len() as u64, 1)?;
        let mut out = Vec::new();
        while let Some((m, data)) = super::super::RandomAccess::next(&mut state)? {
            let data = match data {
                Some(mut d) => {
                    let mut v = Vec::new();
                    d.read_to_end(&mut v).map(|_| v).map_err(|e| d.fault().map_or(e.to_string(), str::to_owned))
                }
                None => Ok(Vec::new()),
            };
            out.push((m.name, data));
        }
        Ok(out)
    }

    #[test]
    fn a_built_image_reads_back() {
        let data = b"hello".as_slice();
        let m = meta(&[dentry("a.txt", 0x80, 0, sha1(data), 0), dentry("b.txt", 0x80, 0, sha1(data), 0)], &[]);
        let got = read(&wim(&[data], &m, &[])).unwrap();
        assert_eq!(got, vec![("a.txt".into(), Ok(b"hello".to_vec())), ("b.txt".into(), Ok(b"hello".to_vec()))]);
    }

    #[test]
    fn data_that_fails_its_sha1_is_refused() {
        let data = b"hello".as_slice();
        let m = meta(&[dentry("a.txt", 0x80, 0, sha1(data), 0)], &[]);
        let mut w = wim(&[data], &m, &[]);
        w[HEADER_LEN] = b'j';
        let got = read(&w).unwrap();
        assert_eq!(got[0].1, Err("a WIM file fails its SHA-1".to_owned()));
        // a hash the lookup table doesn't hold
        let m = meta(&[dentry("a.txt", 0x80, 0, [7; 20], 0)], &[]);
        assert!(read(&wim(&[data], &m, &[])).is_err());
    }

    #[test]
    fn a_folder_that_contains_itself_is_refused() {
        // the folder's entries start where the root's do: itself
        let m = meta(&[dentry("loop", ATTR_DIRECTORY, FIRST, [0; 20], 0)], &[]);
        let e = read(&wim(&[], &m, &[])).unwrap_err();
        assert!(e.to_string().contains("loop"), "{e}");
    }

    #[test]
    fn deep_nesting_is_refused() {
        // folder i's single entry is folder i + 1, each laid out after the last
        let mut tail = Vec::new();
        let first_len = dentry("d", ATTR_DIRECTORY, 0, [0; 20], 0).len() as u64;
        let mut at = FIRST + first_len + 8;
        let mut first = None;
        for _ in 0..MAX_DEPTH + 10 {
            let d = dentry("d", ATTR_DIRECTORY, at + first_len + 8, [0; 20], 0);
            first.get_or_insert(at);
            tail.extend_from_slice(&d);
            tail.extend_from_slice(&[0; 8]);
            at += first_len + 8;
        }
        let m = meta(&[dentry("d", ATTR_DIRECTORY, first.unwrap(), [0; 20], 0)], &tail);
        let e = read(&wim(&[], &m, &[])).unwrap_err();
        assert!(e.to_string().contains("too deep"), "{e}");
    }

    #[test]
    fn overlapping_resources_are_refused() {
        let data = b"some data".as_slice();
        let m = meta(&[dentry("a", 0x80, 0, sha1(data), 0)], &[]);
        let mut e = [0u8; 50];
        e[..8].copy_from_slice(&4u64.to_le_bytes());
        e[8..16].copy_from_slice(&(HEADER_LEN as u64 + 2).to_le_bytes());
        e[16..24].copy_from_slice(&4u64.to_le_bytes());
        e[24..26].copy_from_slice(&1u16.to_le_bytes());
        e[30] = 9;
        let err = read(&wim(&[data], &m, &[e])).unwrap_err();
        assert!(err.to_string().contains("overlap"), "{err}");
    }

    #[test]
    fn shared_data_is_written_again_only_so_much() {
        let data = vec![0x5a; 1 << 20];
        let children: Vec<Vec<u8>> = (0..100).map(|i| dentry(&format!("f{i}"), 0x80, 0, sha1(&data), 0)).collect();
        let w = wim(&[&data], &meta(&children, &[]), &[]);
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&w).unwrap();
        let mut state = open(f, w.len() as u64, 1).unwrap();
        let mut n = 0;
        let err = loop {
            match super::super::RandomAccess::next(&mut state) {
                Ok(Some(_)) => n += 1,
                Ok(None) => panic!("all {n} copies were handed out"),
                Err(e) => break e,
            }
        };
        assert!(err.to_string().contains("shared data"), "{err}");
        // 8 times the archive and 64 MiB more: 72 copies after the first
        assert_eq!(n, 73);
    }

    #[test]
    fn hard_links_point_at_the_first_name() {
        let data = b"linked".as_slice();
        let m = meta(&[dentry("a", 0x80, 0, sha1(data), 9), dentry("b", 0x80, 0, sha1(data), 9)], &[]);
        let w = wim(&[data], &m, &[]);
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&w).unwrap();
        let mut state = open(f, w.len() as u64, 1).unwrap();
        let (a, _) = super::super::RandomAccess::next(&mut state).unwrap().unwrap();
        let (b, data) = super::super::RandomAccess::next(&mut state).unwrap().unwrap();
        assert_eq!((a.kind, b.kind, b.link.as_str()), (Kind::File, Kind::HardLink, "a"));
        assert!(data.is_none());
    }

    #[test]
    fn impossible_names_are_refused() {
        for name in ["..", ".", "a/b", "a\0b"] {
            let m = meta(&[dentry(name, ATTR_DIRECTORY, 0, [0; 20], 0)], &[]);
            assert!(read(&wim(&[], &m, &[])).is_err(), "{name:?}");
        }
    }

    #[test]
    fn named_streams_shared_by_many_entries_are_read_only_so_often() {
        // K folders, each holding one entry whose named streams are the same N records: the walk would read K * N
        const N: u16 = u16::MAX;
        let k = (MAX_STREAM_RECORDS / u64::from(N)) as usize + 2;
        let folder_len = dentry("d0000", ATTR_DIRECTORY, 0, [0; 20], 0).len() as u64;
        let child_len = dentry("f0000", 0x80, 0, [0; 20], 0).len() as u64;
        // after the root's entries: the K children, then the shared records and an end marker
        let children_at = FIRST + k as u64 * folder_len + 8;
        let shared_at = children_at + k as u64 * child_len;
        let mut folders = Vec::new();
        let mut tail = Vec::new();
        for i in 0..k {
            let at = children_at + i as u64 * child_len;
            folders.push(dentry(&format!("d{i:04}"), ATTR_DIRECTORY, at, [0; 20], 0));
            let mut c = dentry(&format!("f{i:04}"), 0x80, 0, [0; 20], 0);
            // the entry's length runs to the shared records, and it claims N of them
            c[..8].copy_from_slice(&(shared_at - at).to_le_bytes());
            c[96..98].copy_from_slice(&N.to_le_bytes());
            tail.extend_from_slice(&c);
        }
        let mut record = [0u8; 40];
        record[..8].copy_from_slice(&40u64.to_le_bytes());
        for _ in 0..N {
            tail.extend_from_slice(&record);
        }
        tail.extend_from_slice(&[0; 8]);
        let m = meta(&folders, &tail);
        let start = std::time::Instant::now();
        let e = read(&wim(&[], &m, &[])).unwrap_err();
        assert!(e.to_string().contains("too many named streams"), "{e}");
        assert!(start.elapsed() < std::time::Duration::from_secs(30));
    }

    #[test]
    fn shared_reparse_data_is_decoded_once() {
        // a relative symbolic link to "t": substitute name at 0, 2 bytes; print name after it; flags 1
        let mut blob = Vec::new();
        for v in [0u16, 2, 2, 2] {
            blob.extend_from_slice(&v.to_le_bytes());
        }
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&[b't', 0, b't', 0]);
        let links: Vec<Vec<u8>> = (0..2000)
            .map(|i| dentry(&format!("l{i}"), ATTR_REPARSE_POINT, 0, sha1(&blob), u64::from(TAG_SYMLINK)))
            .collect();
        let w = wim(&[&blob], &meta(&links, &[]), &[]);
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&w).unwrap();
        let mut state = open(f, w.len() as u64, 1).unwrap();
        let mut n = 0;
        while let Some((m, _)) = super::super::RandomAccess::next(&mut state).unwrap() {
            assert_eq!((m.kind, m.link.as_str()), (Kind::Symlink, "t"));
            n += 1;
        }
        assert_eq!((n, state.reparse_reads), (2000, 1));
    }

    #[test]
    fn mangled_images_never_panic() {
        let data = b"hello world, hello world".as_slice();
        let m = meta(&[dentry("a.txt", 0x80, 0, sha1(data), 0), dentry("d", ATTR_DIRECTORY, 0, [0; 20], 0)], &[]);
        let good = wim(&[data], &m, &[]);
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..3000 {
            let mut w = good.clone();
            for _ in 0..1 + seed % 4 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = (seed >> 8) as usize % w.len();
                w[at] = seed as u8;
            }
            let _ = read(&w);
        }
    }
}
