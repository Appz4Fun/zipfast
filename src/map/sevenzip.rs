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

//! The 7z walker: the signature header at offset 0, the volume lengths up to the end of the next header, the next
//! header itself and, for an encoded header, its packed stream, decoded (LZMA, LZMA2, 7zAES, Copy) into the real
//! header. A split set (`.7z.001`, `.7z.002`, ...) is a plain byte split: archive offsets run over the volumes in
//! order. Member data is never read.
use super::{
    CipherParams, CoderKind, FolderSlot, Got, MapChecks, MapCoder, MapEnd, MapError, MapFolder, MapFormat, MapInput,
    MapMember, MapMethod, MapOptions, MapPiece, MemberMap, Opened, OutputMapping, PackedSpan, read,
};
use crate::progressive::{FailureKind, ProgressiveFailure, Resource, Usage, VolumeRequest};
use std::{
    ffi::OsString,
    ops::Range,
    task::{Context, Poll},
};

/// The signature that starts a 7z archive.
pub(crate) const MAGIC: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];
/// Bytes of the signature header; the next header offset counts from its end.
const SIGNATURE_LEN: u64 = 32;
const CHUNK: usize = 64 << 10;
/// Encoded headers that decode to another encoded header, at most.
const MAX_NESTING: u32 = 4;
/// Coders, and coder streams, in one folder at most (7-Zip's own bound).
const MAX_FOLDER_STREAMS: u64 = 64;

const ID_END: u64 = 0x00;
const ID_HEADER: u64 = 0x01;
const ID_ARCHIVE_PROPERTIES: u64 = 0x02;
const ID_ADDITIONAL_STREAMS: u64 = 0x03;
const ID_MAIN_STREAMS: u64 = 0x04;
const ID_FILES: u64 = 0x05;
const ID_PACK_INFO: u64 = 0x06;
const ID_UNPACK_INFO: u64 = 0x07;
const ID_SUBSTREAMS: u64 = 0x08;
const ID_SIZE: u64 = 0x09;
const ID_CRC: u64 = 0x0A;
const ID_FOLDER: u64 = 0x0B;
const ID_CODERS_UNPACK_SIZE: u64 = 0x0C;
const ID_NUM_UNPACK_STREAM: u64 = 0x0D;
const ID_EMPTY_STREAM: u64 = 0x0E;
const ID_EMPTY_FILE: u64 = 0x0F;
const ID_ANTI: u64 = 0x10;
const ID_NAME: u64 = 0x11;
const ID_CTIME: u64 = 0x12;
const ID_ATIME: u64 = 0x13;
const ID_MTIME: u64 = 0x14;
const ID_WIN_ATTRIBUTES: u64 = 0x15;
const ID_ENCODED_HEADER: u64 = 0x17;

const ATTRIBUTE_UNIX_EXTENSION: u32 = 0x8000;

/// A header parse failure, before the volume it belongs to is attached.
enum Bad {
    Malformed(&'static str),
    Unsupported(&'static str),
    Failure(ProgressiveFailure),
}

impl From<ProgressiveFailure> for Bad {
    fn from(failure: ProgressiveFailure) -> Self {
        Self::Failure(failure)
    }
}

impl Bad {
    fn into_map(self, volume: u32) -> MapError {
        match self {
            Self::Malformed(what) => malformed(volume, what),
            Self::Unsupported(what) => unsupported(volume, what),
            Self::Failure(failure) => MapError::from_failure(volume, failure),
        }
    }
}

fn malformed(volume: u32, what: &'static str) -> MapError {
    MapError::Malformed { volume, failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(what))) }
}

fn unsupported(volume: u32, what: &'static str) -> MapError {
    MapError::Unsupported { volume, failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(what))) }
}

fn checksum(volume: u32, expected: u32, actual: u32) -> MapError {
    use crate::progressive::{ChecksumAlgorithm, ChecksumScope, ChecksumValue};
    MapError::Malformed {
        volume,
        failure: Box::new(ProgressiveFailure::new(FailureKind::ChecksumMismatch {
            algorithm: ChecksumAlgorithm::Crc32,
            scope: ChecksumScope::Header,
            expected: Box::new(ChecksumValue::Crc32(expected.to_be_bytes())),
            actual: Box::new(ChecksumValue::Crc32(actual.to_be_bytes())),
        })),
    }
}

type Parsed<T> = Result<T, Bad>;

// ---- The header model ----

struct Coder {
    id: u64,
    properties: Vec<u8>,
    in_streams: u64,
    out_streams: u64,
}

struct Folder {
    coders: Vec<Coder>,
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: Vec<u64>,
    unpack_sizes: Vec<u64>,
    crc: Option<u32>,
    /// The output stream not bound to any input.
    main_out: u64,
}

impl Folder {
    fn unpacked_size(&self) -> u64 {
        self.unpack_sizes[self.main_out as usize]
    }

    fn simple(&self) -> bool {
        self.coders.iter().all(|c| c.in_streams == 1 && c.out_streams == 1)
    }

    /// The coders in decoding order, from the one the packed stream feeds to the one producing the output, for a
    /// chain of one-in one-out coders over one packed stream.
    fn chain(&self) -> Option<Vec<usize>> {
        if !self.simple() || self.packed_streams.len() != 1 {
            return None;
        }
        // With one stream per coder, coder `c` owns input and output stream `c`.
        let mut order = Vec::with_capacity(self.coders.len());
        let mut coder = usize::try_from(self.packed_streams[0]).ok()?;
        loop {
            if coder >= self.coders.len() || order.contains(&coder) {
                return None;
            }
            order.push(coder);
            match self.bind_pairs.iter().find(|&&(_, out)| out == coder as u64) {
                Some(&(next, _)) => coder = usize::try_from(next).ok()?,
                None => break,
            }
        }
        (order.len() == self.coders.len()).then_some(order)
    }

    fn aes(&self) -> Option<&Coder> {
        self.coders.iter().find(|c| CoderKind::from_id(c.id) == CoderKind::Aes)
    }
}

/// How a data folder's output maps to its packed bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Shape {
    /// Copy coders only, over one packed stream.
    Copy,
    /// 7zAES and Copy coders only, over one packed stream, with readable 7zAES properties.
    AesCopy,
    Other,
}

#[derive(Default)]
struct Streams {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    pack_crcs: Vec<Option<u32>>,
    folders: Vec<Folder>,
    /// Members per folder.
    substreams: Vec<u64>,
    /// Size and CRC of every substream, folder by folder.
    sub_sizes: Vec<u64>,
    sub_crcs: Vec<Option<u32>>,
}

#[derive(Default)]
struct FileEntry {
    raw_name: Vec<u8>,
    name: Option<String>,
    has_stream: bool,
    is_dir: bool,
    /// An anti item (a deletion marker in an update archive): not listed.
    anti: bool,
    attributes: Option<u32>,
    ctime: Option<u64>,
    atime: Option<u64>,
    mtime: Option<u64>,
}

/// The 7zAES parameters in coder properties.
pub(crate) fn aes_params(properties: &[u8]) -> Option<CipherParams> {
    let (&first, rest) = properties.split_first()?;
    let num_cycles_power = first & 0x3F;
    if first & 0xC0 == 0 {
        return rest.is_empty().then(|| CipherParams::SevenZipAes { num_cycles_power, salt: Vec::new(), iv: [0; 16] });
    }
    let (&second, rest) = rest.split_first()?;
    let salt_len = usize::from((first >> 7) & 1) + usize::from(second >> 4);
    let iv_len = usize::from((first >> 6) & 1) + usize::from(second & 0x0F);
    if rest.len() != salt_len + iv_len {
        return None;
    }
    let mut iv = [0; 16];
    iv[..iv_len].copy_from_slice(&rest[salt_len..]);
    Some(CipherParams::SevenZipAes { num_cycles_power, salt: rest[..salt_len].to_vec(), iv })
}

// ---- The byte reader ----

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    usage: &'a Usage,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], usage: &'a Usage) -> Self {
        Self { buf, pos: 0, usage }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn byte(&mut self) -> Parsed<u8> {
        let b = *self.buf.get(self.pos).ok_or(Bad::Malformed("7z header ends early"))?;
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: u64) -> Parsed<&'a [u8]> {
        let n =
            usize::try_from(n).ok().filter(|&n| n <= self.remaining()).ok_or(Bad::Malformed("7z header ends early"))?;
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// A 7z NUMBER: the first byte's leading one bits count the extra little-endian bytes.
    fn number(&mut self) -> Parsed<u64> {
        let first = self.byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = u64::from(first & mask.wrapping_sub(1));
                return Ok(value | (high << (8 * i)));
            }
            value |= u64::from(self.byte()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    fn u32(&mut self) -> Parsed<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Parsed<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().expect("eight bytes")))
    }

    /// A count of items each taking at least `min_bytes` bytes of what is left, charged to `resource` if any.
    fn count(&mut self, min_bytes: usize, resource: Option<Resource>) -> Parsed<usize> {
        let n = self.number()?;
        self.bounded(n, min_bytes, resource)
    }

    fn bounded(&self, n: u64, min_bytes: usize, resource: Option<Resource>) -> Parsed<usize> {
        let fits = usize::try_from(n).ok().filter(|&n| n.saturating_mul(min_bytes) <= self.remaining());
        let n = fits.ok_or(Bad::Malformed("7z item count exceeds the header"))?;
        if let Some(resource) = resource {
            self.usage.charge(resource, n as u64)?;
        }
        Ok(n)
    }

    fn bits(&mut self, n: usize) -> Parsed<Vec<bool>> {
        let bytes = self.bytes(n.div_ceil(8) as u64)?;
        Ok((0..n).map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0).collect())
    }

    /// An "all defined" byte, then a bit vector unless it is set.
    fn defined(&mut self, n: usize) -> Parsed<Vec<bool>> {
        if self.byte()? != 0 { Ok(vec![true; n]) } else { self.bits(n) }
    }

    fn digests(&mut self, n: usize) -> Parsed<Vec<Option<u32>>> {
        let defined = self.defined(n)?;
        defined.into_iter().map(|d| if d { self.u32().map(Some) } else { Ok(None) }).collect()
    }

    fn expect(&mut self, id: u64, what: &'static str) -> Parsed<()> {
        if self.number()? == id { Ok(()) } else { Err(Bad::Malformed(what)) }
    }

    fn pack_info(&mut self, streams: &mut Streams) -> Parsed<()> {
        streams.pack_pos = self.number()?;
        let n = self.count(1, Some(Resource::Parts))?;
        loop {
            match self.number()? {
                ID_END => break,
                ID_SIZE => {
                    streams.pack_sizes = (0..n).map(|_| self.number()).collect::<Parsed<_>>()?;
                }
                ID_CRC => streams.pack_crcs = self.digests(n)?,
                _ => return Err(Bad::Malformed("7z pack info property")),
            }
        }
        if streams.pack_sizes.len() != n {
            return Err(Bad::Malformed("7z pack sizes missing"));
        }
        if streams.pack_crcs.is_empty() {
            streams.pack_crcs = vec![None; n];
        }
        Ok(())
    }

    fn folder(&mut self) -> Parsed<Folder> {
        let n = self.count(1, None)?;
        if n == 0 || n as u64 > MAX_FOLDER_STREAMS {
            return Err(Bad::Malformed("7z folder coder count"));
        }
        let mut coders = Vec::with_capacity(n);
        let (mut total_in, mut total_out) = (0u64, 0u64);
        for _ in 0..n {
            let flags = self.byte()?;
            if flags & 0x80 != 0 {
                return Err(Bad::Unsupported("7z alternative coder methods"));
            }
            let id_len = flags & 0x0F;
            if id_len > 8 {
                return Err(Bad::Malformed("7z coder id size"));
            }
            let id = self.bytes(u64::from(id_len))?.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b));
            let (in_streams, out_streams) = if flags & 0x10 != 0 { (self.number()?, self.number()?) } else { (1, 1) };
            if in_streams > MAX_FOLDER_STREAMS || out_streams > MAX_FOLDER_STREAMS {
                return Err(Bad::Malformed("7z coder stream count"));
            }
            let properties =
                if flags & 0x20 != 0 { (self.number().and_then(|n| self.bytes(n)))?.to_vec() } else { Vec::new() };
            self.usage.charge(Resource::MetadataBytes, (std::mem::size_of::<Coder>() + properties.len()) as u64)?;
            total_in += in_streams;
            total_out += out_streams;
            coders.push(Coder { id, properties, in_streams, out_streams });
        }
        if total_out == 0 || total_in > MAX_FOLDER_STREAMS || total_out > MAX_FOLDER_STREAMS {
            return Err(Bad::Malformed("7z folder stream count"));
        }
        let bind_count = total_out - 1;
        if total_in < bind_count + 1 {
            return Err(Bad::Malformed("7z folder bind pairs"));
        }
        let mut bind_pairs = Vec::with_capacity(bind_count as usize);
        for _ in 0..bind_count {
            let (input, output) = (self.number()?, self.number()?);
            if input >= total_in || output >= total_out || bind_pairs.iter().any(|&(i, o)| i == input || o == output) {
                return Err(Bad::Malformed("7z folder bind pair"));
            }
            bind_pairs.push((input, output));
        }
        let packed_count = total_in - bind_count;
        let packed_streams = if packed_count == 1 {
            let free = (0..total_in).find(|i| bind_pairs.iter().all(|&(input, _)| input != *i));
            vec![free.ok_or(Bad::Malformed("7z folder packed stream"))?]
        } else {
            let mut list = Vec::with_capacity(packed_count as usize);
            for _ in 0..packed_count {
                let index = self.number()?;
                if index >= total_in || list.contains(&index) || bind_pairs.iter().any(|&(i, _)| i == index) {
                    return Err(Bad::Malformed("7z folder packed stream"));
                }
                list.push(index);
            }
            list
        };
        let main_out = (0..total_out)
            .find(|o| bind_pairs.iter().all(|&(_, out)| out != *o))
            .ok_or(Bad::Malformed("7z folder output stream"))?;
        Ok(Folder { coders, bind_pairs, packed_streams, unpack_sizes: Vec::new(), crc: None, main_out })
    }

    fn unpack_info(&mut self, streams: &mut Streams) -> Parsed<()> {
        self.expect(ID_FOLDER, "7z unpack info without folders")?;
        let n = self.count(2, Some(Resource::Parts))?;
        if self.byte()? != 0 {
            return Err(Bad::Unsupported("7z folders stored outside the header"));
        }
        let mut folders = Vec::with_capacity(n);
        for _ in 0..n {
            folders.push(self.folder()?);
        }
        self.expect(ID_CODERS_UNPACK_SIZE, "7z folder unpack sizes missing")?;
        for folder in &mut folders {
            let outs: u64 = folder.coders.iter().map(|c| c.out_streams).sum();
            folder.unpack_sizes = (0..outs).map(|_| self.number()).collect::<Parsed<_>>()?;
        }
        loop {
            match self.number()? {
                ID_END => break,
                ID_CRC => {
                    for (folder, crc) in folders.iter_mut().zip(self.digests(n)?) {
                        folder.crc = crc;
                    }
                }
                _ => return Err(Bad::Malformed("7z unpack info property")),
            }
        }
        streams.folders = folders;
        Ok(())
    }

    fn substreams_info(&mut self, streams: &mut Streams) -> Parsed<()> {
        let folders = &streams.folders;
        let mut counts = vec![1u64; folders.len()];
        let mut id = self.number()?;
        if id == ID_NUM_UNPACK_STREAM {
            for count in &mut counts {
                *count = self.number()?;
            }
            id = self.number()?;
        }
        let mut sizes = Vec::new();
        let total = counts.iter().try_fold(0u64, |a, &c| a.checked_add(c)).ok_or(Bad::Malformed("7z substreams"))?;
        let have_sizes = id == ID_SIZE;
        if !have_sizes && counts.iter().any(|&c| c > 1) {
            return Err(Bad::Malformed("7z substream sizes missing"));
        }
        // Each size but a folder's last takes a byte at least; the rest are one per folder.
        let explicit = counts.iter().map(|&c| c.saturating_sub(1)).sum::<u64>();
        self.bounded(explicit, 1, Some(Resource::Parts))?;
        self.usage.charge(Resource::Parts, total - explicit)?;
        sizes.try_reserve_exact(total as usize).map_err(|_| Bad::Malformed("7z substreams"))?;
        for (folder, &count) in folders.iter().zip(&counts) {
            if count == 0 {
                continue;
            }
            let mut sum = 0u64;
            for _ in 1..count {
                let size = self.number()?;
                sum = sum.checked_add(size).ok_or(Bad::Malformed("7z substream sizes"))?;
                sizes.push(size);
            }
            let rest = folder.unpacked_size().checked_sub(sum).ok_or(Bad::Malformed("7z substream sizes"))?;
            sizes.push(rest);
        }
        if have_sizes {
            id = self.number()?;
        }
        let unknown: u64 =
            folders.iter().zip(&counts).map(|(f, &c)| if c == 1 && f.crc.is_some() { 0 } else { c }).sum();
        let mut digests = None;
        while id != ID_END {
            if id == ID_CRC {
                // At least a bit each.
                let n = usize::try_from(unknown)
                    .ok()
                    .filter(|&n| n <= 8 * self.remaining() + 8)
                    .ok_or(Bad::Malformed("7z item count exceeds the header"))?;
                digests = Some(self.digests(n)?);
            } else {
                let size = self.number()?;
                self.bytes(size)?;
            }
            id = self.number()?;
        }
        let mut digests = digests.map(Vec::into_iter);
        let mut crcs = Vec::with_capacity(sizes.len());
        for (folder, &count) in folders.iter().zip(&counts) {
            if count == 1 && folder.crc.is_some() {
                crcs.push(folder.crc);
            } else {
                for _ in 0..count {
                    crcs.push(digests.as_mut().and_then(Iterator::next).flatten());
                }
            }
        }
        streams.substreams = counts;
        streams.sub_sizes = sizes;
        streams.sub_crcs = crcs;
        Ok(())
    }

    fn streams_info(&mut self) -> Parsed<Streams> {
        let mut streams = Streams::default();
        let mut id = self.number()?;
        if id == ID_PACK_INFO {
            self.pack_info(&mut streams)?;
            id = self.number()?;
        }
        if id == ID_UNPACK_INFO {
            self.unpack_info(&mut streams)?;
            id = self.number()?;
        }
        if id == ID_SUBSTREAMS {
            if streams.folders.is_empty() {
                return Err(Bad::Malformed("7z substreams without folders"));
            }
            self.substreams_info(&mut streams)?;
            id = self.number()?;
        } else {
            streams.substreams = vec![1; streams.folders.len()];
            streams.sub_sizes = streams.folders.iter().map(Folder::unpacked_size).collect();
            streams.sub_crcs = streams.folders.iter().map(|f| f.crc).collect();
        }
        if id != ID_END {
            return Err(Bad::Malformed("7z streams info property"));
        }
        let packed: usize = streams.folders.iter().map(|f| f.packed_streams.len()).sum();
        if packed > streams.pack_sizes.len() {
            return Err(Bad::Malformed("7z folders need more packed streams than listed"));
        }
        Ok(streams)
    }

    fn files_info(&mut self) -> Parsed<Vec<FileEntry>> {
        let n = self.number()?;
        self.usage.check(Resource::Entries, n)?;
        let n = usize::try_from(n).map_err(|_| Bad::Malformed("7z file count"))?;
        self.usage.charge(Resource::Entries, n as u64)?;
        let per = std::mem::size_of::<FileEntry>() + std::mem::size_of::<MapMember>();
        self.usage.charge(Resource::MetadataBytes, (n as u64).saturating_mul(per as u64))?;
        let mut files = Vec::new();
        files.try_reserve_exact(n).map_err(|_| Bad::Malformed("7z file count"))?;
        files.resize_with(n, FileEntry::default);
        let mut empty_stream = vec![false; n];
        let mut empty_file: Vec<bool> = Vec::new();
        let mut anti: Vec<bool> = Vec::new();
        loop {
            let id = self.number()?;
            if id == ID_END {
                break;
            }
            let size = self.number()?;
            let mut sub = Reader::new(self.bytes(size)?, self.usage);
            match id {
                ID_EMPTY_STREAM => {
                    empty_stream = sub.bits(n)?;
                    empty_file = vec![false; empty_stream.iter().filter(|&&e| e).count()];
                }
                ID_EMPTY_FILE => empty_file = sub.bits(empty_file.len())?,
                ID_ANTI => anti = sub.bits(empty_file.len())?,
                ID_NAME => {
                    if sub.byte()? != 0 {
                        return Err(Bad::Unsupported("7z names stored outside the header"));
                    }
                    self.usage.charge(Resource::NameBytes, sub.remaining() as u64)?;
                    let units = sub.bytes(sub.remaining() as u64)?;
                    let mut names = units.as_chunks::<2>().0.split(|unit| *unit == [0, 0]);
                    for file in &mut files {
                        let name = names.next().ok_or(Bad::Malformed("7z names"))?;
                        file.raw_name = name.as_flattened().to_vec();
                        file.name =
                            String::from_utf16(&name.iter().map(|u| u16::from_le_bytes(*u)).collect::<Vec<_>>()).ok();
                    }
                    if !units.len().is_multiple_of(2)
                        || names.next().is_none_or(|rest| !rest.is_empty())
                        || names.next().is_some()
                    {
                        return Err(Bad::Malformed("7z names"));
                    }
                }
                ID_CTIME | ID_ATIME | ID_MTIME | ID_WIN_ATTRIBUTES => {
                    let defined = sub.defined(n)?;
                    if sub.byte()? != 0 {
                        return Err(Bad::Unsupported("7z file properties stored outside the header"));
                    }
                    for (file, defined) in files.iter_mut().zip(defined) {
                        if !defined {
                            continue;
                        }
                        match id {
                            ID_CTIME => file.ctime = Some(sub.u64()?),
                            ID_ATIME => file.atime = Some(sub.u64()?),
                            ID_MTIME => file.mtime = Some(sub.u64()?),
                            _ => file.attributes = Some(sub.u32()?),
                        }
                    }
                }
                // Start positions, padding and the like.
                _ => {}
            }
        }
        // As 7-Zip: an entry without a stream is a directory unless it is an empty file; an entry with a stream is
        // always a file. Attributes are not consulted. The empty-file and anti bits count over the empty streams.
        let mut empty_index = 0usize;
        for (file, empty) in files.iter_mut().zip(empty_stream) {
            file.has_stream = !empty;
            if empty {
                let empty_file = empty_file.get(empty_index).copied().unwrap_or(false);
                file.anti = anti.get(empty_index).copied().unwrap_or(false);
                file.is_dir = !empty_file;
                empty_index += 1;
            }
        }
        Ok(files)
    }

    /// A plain header after its id byte: the main streams and the files.
    fn header(&mut self) -> Parsed<(Streams, Vec<FileEntry>)> {
        let mut id = self.number()?;
        if id == ID_ARCHIVE_PROPERTIES {
            while self.number()? != ID_END {
                let size = self.number()?;
                self.bytes(size)?;
            }
            id = self.number()?;
        }
        if id == ID_ADDITIONAL_STREAMS {
            return Err(Bad::Unsupported("7z additional streams"));
        }
        let mut streams = Streams::default();
        if id == ID_MAIN_STREAMS {
            streams = self.streams_info()?;
            id = self.number()?;
        }
        let mut files = Vec::new();
        if id == ID_FILES {
            files = self.files_info()?;
            id = self.number()?;
        }
        if id != ID_END {
            return Err(Bad::Malformed("7z header property"));
        }
        Ok((streams, files))
    }
}

// ---- Decoding an encoded header ----

/// Decodes LZMA or LZMA2 data into exactly `size` bytes. Ok(None) means the data does not decode. The dictionary
/// is shrunk to what `size` bytes can use, so a stated dictionary never allocates more than the output.
fn lzma(kind: CoderKind, properties: &[u8], input: &[u8], size: usize, usage: &Usage) -> Parsed<Option<Vec<u8>>> {
    let shaped = match kind {
        CoderKind::Lzma => properties.len() == 5,
        _ => properties.len() == 1,
    };
    let what = if kind == CoderKind::Lzma { "7z LZMA properties" } else { "7z LZMA2 properties" };
    if !shaped {
        return Err(Bad::Malformed(what));
    }
    let (filters, window) = crate::codec::filters(properties, size as u64).map_err(|_| Bad::Malformed(what))?;
    usage.check(Resource::DecoderWindow, window)?;
    match crate::codec::decode(&filters, input, Some(size as u64), size as u64) {
        Ok(out) => Ok(Some(out)),
        Err(crate::codec::LzmaError::Allocation) => Err(Bad::Unsupported("7z LZMA decoder")),
        Err(_) => Ok(None),
    }
}

/// Decodes a header folder over its packed bytes. Ok(None) means the bytes do not decode (or decode to the wrong
/// CRC): a wrong password when the folder is encrypted.
fn decode_folder(folder: &Folder, packed: &[u8], key: Option<&[u8; 32]>, usage: &Usage) -> Parsed<Option<Vec<u8>>> {
    let order = folder.chain().ok_or(Bad::Unsupported("7z header coder graph"))?;
    let mut data = packed.to_vec();
    for coder_index in order {
        let coder = &folder.coders[coder_index];
        let size = folder.unpack_sizes[coder_index];
        usage.charge(Resource::HeaderBytes, size)?;
        let size = usize::try_from(size).map_err(|_| Bad::Malformed("7z header size"))?;
        data = match CoderKind::from_id(coder.id) {
            CoderKind::Copy => {
                if data.len() < size {
                    return Ok(None);
                }
                data.truncate(size);
                data
            }
            CoderKind::Aes => {
                let Some(CipherParams::SevenZipAes { iv, .. }) = aes_params(&coder.properties) else {
                    return Err(Bad::Malformed("7zAES properties"));
                };
                let key = key.ok_or(Bad::Malformed("7zAES without a key"))?;
                if !data.len().is_multiple_of(16) || data.len() < size {
                    return Ok(None);
                }
                let aes = crate::crypto::AesKey::new(key).expect("AES-256 key");
                aes.decrypt_cbc_in_place(&mut iv.clone(), &mut data);
                data.truncate(size);
                data
            }
            kind @ (CoderKind::Lzma | CoderKind::Lzma2) => match lzma(kind, &coder.properties, &data, size, usage)? {
                Some(out) => out,
                None => return Ok(None),
            },
            _ => return Err(Bad::Unsupported("7z header coder")),
        };
    }
    if let Some(crc) = folder.crc
        && crate::crc32::hash(&data) != crc
    {
        return Ok(None);
    }
    Ok(Some(data))
}

// ---- The walker ----

enum Phase {
    Signature,
    Volumes,
    NextHeader,
    /// The packed stream of an encoded header is being read.
    Packed(Box<Streams>),
}

/// Archive bytes being gathered.
struct Job {
    at: u64,
    len: u64,
    data: Vec<u8>,
}

enum Filled {
    Done(Vec<u8>),
    /// The volume is missing, or ends before the bytes do.
    Unavailable(u32),
}

pub(crate) struct SevenZipWalker {
    usage: Usage,
    names: Vec<OsString>,
    /// Lengths of the volumes opened so far, in order.
    lens: Vec<u64>,
    /// The volume open on the input.
    current: Option<u32>,
    phase: Phase,
    job: Option<Job>,
    parked: Option<usize>,
    buffer: Vec<u8>,
    header_at: u64,
    header_len: u64,
    header_crc: u32,
    header_encrypted: bool,
    header_cipher: Option<CipherParams>,
    depth: u32,
    /// Volumes kept open on the input, least recently used first, at most `handles` of them.
    kept: Vec<u32>,
    handles: u64,
}

impl SevenZipWalker {
    pub(crate) fn new(options: &MapOptions, usage: Usage) -> Self {
        Self {
            usage,
            names: vec![options.first_name.clone()],
            lens: Vec::new(),
            current: None,
            phase: Phase::Signature,
            job: None,
            parked: None,
            buffer: Vec::new(),
            header_at: 0,
            header_len: 0,
            header_crc: 0,
            header_encrypted: false,
            header_cipher: None,
            depth: 0,
            kept: Vec::new(),
            handles: options.limits.volume_handles,
        }
    }

    pub(crate) fn poll(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        options: &MapOptions,
    ) -> Poll<Result<MemberMap, MapError>> {
        match self.poll_inner(input, cx, options) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(map)) => Poll::Ready(Ok(map)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn map(&self, end: MapEnd, streams: Streams, files: Vec<FileEntry>) -> Result<MemberMap, MapError> {
        let complete = end == MapEnd::Complete;
        let (folders, members) = if complete { self.build(streams, files)? } else { (Vec::new(), Vec::new()) };
        Ok(MemberMap {
            format: MapFormat::SevenZip,
            header_encrypted: self.header_encrypted,
            header_cipher: self.header_cipher.clone(),
            complete,
            end,
            volumes: self.lens.len() as u32,
            members,
            folders,
        })
    }

    /// The first volume opened that is shorter than a later one, as a hint for [`MapEnd::HeaderUnavailable`]. A
    /// split cut at one size makes only the last volume short, so such a volume may have lost bytes; but 7-Zip
    /// also writes splits of several sizes (`-v1000b -v2000b`), where a short first volume is honest.
    fn suspect(&self) -> Option<u32> {
        let lens = &self.lens;
        (0..lens.len()).find(|&i| lens[i + 1..].iter().any(|&later| later > lens[i])).map(|i| i as u32)
    }

    fn unavailable(&self, volume: u32) -> Result<MemberMap, MapError> {
        let end = MapEnd::HeaderUnavailable { volume, offset: self.header_at, suspect: self.suspect() };
        self.map(end, Streams::default(), Vec::new())
    }

    /// The volume holding archive offset `at`, the offset in it and the bytes left in it from there.
    fn locate(&self, at: u64) -> Option<(u32, u64, u64)> {
        let mut start = 0u64;
        for (volume, &len) in self.lens.iter().enumerate() {
            let end = start.saturating_add(len);
            if at < end {
                return Some((volume as u32, at - start, end - at));
            }
            start = end;
        }
        None
    }

    /// The volumes holding archive range `range`, cut at volume boundaries.
    fn split(&self, range: Range<u64>) -> Vec<(u32, Range<u64>)> {
        let mut out = Vec::new();
        let mut at = range.start;
        while at < range.end {
            let Some((volume, offset, left)) = self.locate(at) else { break };
            let n = left.min(range.end - at);
            out.push((volume, offset..offset + n));
            at += n;
        }
        out
    }

    fn header_volume(&self) -> u32 {
        self.locate(self.header_at).map_or(0, |(v, _, _)| v)
    }

    fn volume_name(&mut self, index: u32) -> Result<OsString, MapError> {
        while self.names.len() <= index as usize {
            let next = super::next_volume_name(self.names.last().expect("first name"));
            self.usage.charge(Resource::MetadataBytes, next.len() as u64).map_err(|e| MapError::from_failure(0, e))?;
            self.names.push(next);
        }
        Ok(self.names[index as usize].clone())
    }

    /// Opens volume `index` on the input. Ok(None) means pending.
    fn open(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>, index: u32) -> Result<Option<Opened>, MapError> {
        let expected = self.volume_name(index)?;
        self.usage.charge(Resource::SourceRequests, 1).map_err(|e| MapError::from_failure(index, e))?;
        self.current = None;
        match input.open(&VolumeRequest { index, expected }, cx).map_err(|e| MapError::from_failure(index, e))? {
            Opened::Wait => {
                self.usage.charge(Resource::ProviderWakes, 1).map_err(|e| MapError::from_failure(index, e))?;
                Ok(None)
            }
            Opened::Ready => {
                self.current = Some(index);
                self.keep(input, index)?;
                Ok(Some(Opened::Ready))
            }
            Opened::Abort => Err(MapError::Aborted { volume: index }),
            Opened::Missing => Ok(Some(Opened::Missing)),
        }
    }

    /// Keeps the current volume open under its index. At most `volume_handles` volumes stay open: past that, the
    /// one used least recently is closed, and asked for again if it is needed later.
    fn keep(&mut self, input: &mut dyn MapInput, index: u32) -> Result<(), MapError> {
        if let Some(i) = self.kept.iter().position(|&k| k == index) {
            self.kept.remove(i);
        } else {
            if self.handles == 0 {
                return Err(MapError::Limit { resource: Resource::VolumeHandles, limit: 0, attempted: 1 });
            }
            while self.kept.len() as u64 >= self.handles {
                input.release(self.kept.remove(0));
            }
        }
        self.kept.push(index);
        input.keep(index);
        Ok(())
    }

    /// Makes volume `index`, whose length is known, current again: from the kept volumes, or by asking the source
    /// again, which must give the same length. Ok(None) means pending; Ok(Some(false)) that it is missing now.
    fn reselect(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        index: u32,
    ) -> Result<Option<bool>, MapError> {
        if let Some(i) = self.kept.iter().position(|&k| k == index) {
            if !input.select(index) {
                return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::SourceContract))));
            }
            self.kept.remove(i);
            self.kept.push(index);
            self.current = Some(index);
            return Ok(Some(true));
        }
        match self.open(input, cx, index)? {
            None => Ok(None),
            Some(Opened::Ready) if input.len() != self.lens[index as usize] => {
                Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::SourceChanged))))
            }
            Some(Opened::Ready) => Ok(Some(true)),
            Some(_) => Ok(Some(false)),
        }
    }

    /// Gathers the current job's bytes. Ok(Pending) means the source has to be polled again.
    fn fill(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Result<Poll<Filled>, MapError> {
        loop {
            let job = self.job.as_ref().expect("a job to fill");
            let have = job.data.len() as u64;
            if have == job.len {
                return Ok(Poll::Ready(Filled::Done(self.job.take().expect("a job").data)));
            }
            let (at, left) = (job.at + have, job.len - have);
            let Some((volume, offset, in_volume)) = self.locate(at) else {
                return Ok(Poll::Ready(Filled::Unavailable(self.lens.len() as u32)));
            };
            if self.current != Some(volume) {
                match self.reselect(input, cx, volume)? {
                    None => return Ok(Poll::Pending),
                    Some(true) => {}
                    Some(false) => return Ok(Poll::Ready(Filled::Unavailable(volume))),
                }
            }
            let want = left.min(in_volume).min(CHUNK as u64) as usize;
            let n = self.parked.take().unwrap_or(want);
            if self.buffer.len() < n {
                self.buffer.resize(n, 0);
            }
            match read(input, &self.usage, offset, &mut self.buffer[..n], cx)
                .map_err(|e| MapError::from_failure(volume, e))?
            {
                Got::NotYet => {
                    self.parked = Some(n);
                    return Ok(Poll::Pending);
                }
                Got::Hole => return Err(MapError::HeaderHole { volume, offset }),
                Got::Eof => return Ok(Poll::Ready(Filled::Unavailable(volume))),
                Got::Filled(count) => {
                    let count = count.min(n);
                    self.usage
                        .charge(Resource::HeaderBytes, count as u64)
                        .map_err(|e| MapError::from_failure(volume, e))?;
                    let job = self.job.as_mut().expect("a job");
                    job.data.extend_from_slice(&self.buffer[..count]);
                }
            }
        }
    }

    fn start_job(&mut self, at: u64, len: u64) -> Result<(), MapError> {
        self.usage.check(Resource::HeaderBytes, len).map_err(|e| MapError::from_failure(self.header_volume(), e))?;
        let mut data = Vec::new();
        data.try_reserve_exact(len.min(CHUNK as u64) as usize)
            .map_err(|_| malformed(self.header_volume(), "7z header allocation"))?;
        self.job = Some(Job { at, len, data });
        Ok(())
    }

    fn poll_inner(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        options: &MapOptions,
    ) -> Result<Poll<MemberMap>, MapError> {
        loop {
            if options.control.is_canceled() {
                return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled))));
            }
            match &mut self.phase {
                Phase::Signature => {
                    if self.lens.is_empty() {
                        // Format detection left volume 0 open.
                        self.lens.push(input.len());
                        self.current = Some(0);
                        self.keep(input, 0)?;
                        if self.lens[0] < SIGNATURE_LEN {
                            return Ok(Poll::Ready(MemberMap {
                                format: MapFormat::SevenZip,
                                header_encrypted: false,
                                header_cipher: None,
                                complete: false,
                                end: MapEnd::Truncated { volume: 0, offset: 0 },
                                volumes: 1,
                                members: Vec::new(),
                                folders: Vec::new(),
                            }));
                        }
                        self.start_job(0, SIGNATURE_LEN)?;
                    }
                    let bytes = match self.fill(input, cx)? {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(Filled::Done(bytes)) => bytes,
                        Poll::Ready(Filled::Unavailable(_)) => {
                            return Err(malformed(0, "7z signature header past the end of the volume"));
                        }
                    };
                    if bytes[..6] != MAGIC {
                        return Err(MapError::NotArchive);
                    }
                    if bytes[6] != 0 {
                        return Err(unsupported(0, "7z major version"));
                    }
                    let stored = u32::from_le_bytes(bytes[8..12].try_into().expect("four bytes"));
                    let actual = crate::crc32::hash(&bytes[12..32]);
                    if stored != actual {
                        return Err(checksum(0, stored, actual));
                    }
                    let offset = u64::from_le_bytes(bytes[12..20].try_into().expect("eight bytes"));
                    self.header_len = u64::from_le_bytes(bytes[20..28].try_into().expect("eight bytes"));
                    self.header_crc = u32::from_le_bytes(bytes[28..32].try_into().expect("four bytes"));
                    self.header_at = SIGNATURE_LEN
                        .checked_add(offset)
                        .filter(|at| at.checked_add(self.header_len).is_some())
                        .ok_or_else(|| malformed(0, "7z next header offset"))?;
                    if self.header_len == 0 {
                        // An empty archive.
                        return self.map(MapEnd::Complete, Streams::default(), Vec::new()).map(Poll::Ready);
                    }
                    self.usage
                        .check(Resource::HeaderBytes, self.header_len)
                        .map_err(|e| MapError::from_failure(0, e))?;
                    self.phase = Phase::Volumes;
                }
                Phase::Volumes => {
                    let end = self.header_at + self.header_len;
                    // Volume sizes are not checked here: 7-Zip writes splits of several sizes, and a volume that
                    // lost bytes shifts the header, which then fails its CRC.
                    if self.lens.iter().fold(0u64, |a, &l| a.saturating_add(l)) >= end {
                        self.start_job(self.header_at, self.header_len)?;
                        self.phase = Phase::NextHeader;
                        continue;
                    }
                    let index = self.lens.len() as u32;
                    match self.open(input, cx, index)? {
                        None => return Ok(Poll::Pending),
                        Some(Opened::Ready) => self.lens.push(input.len()),
                        Some(_) => return self.unavailable(index).map(Poll::Ready),
                    }
                }
                Phase::NextHeader => {
                    let bytes = match self.fill(input, cx)? {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(Filled::Done(bytes)) => bytes,
                        Poll::Ready(Filled::Unavailable(volume)) => return self.unavailable(volume).map(Poll::Ready),
                    };
                    let actual = crate::crc32::hash(&bytes);
                    if actual != self.header_crc {
                        return Err(checksum(self.header_volume(), self.header_crc, actual));
                    }
                    if let Some(map) = self.header(&bytes, false)? {
                        return Ok(Poll::Ready(map));
                    }
                }
                Phase::Packed(_) => {
                    let bytes = match self.fill(input, cx)? {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(Filled::Done(bytes)) => bytes,
                        Poll::Ready(Filled::Unavailable(volume)) => return self.unavailable(volume).map(Poll::Ready),
                    };
                    let Phase::Packed(streams) = std::mem::replace(&mut self.phase, Phase::NextHeader) else {
                        unreachable!()
                    };
                    let decoded = self.decode(&streams, &bytes, options)?;
                    if let Some(map) = self.header(&decoded, true)? {
                        return Ok(Poll::Ready(map));
                    }
                }
            }
        }
    }

    /// Reads a (possibly decoded) header: a plain header gives the map; an encoded one starts reading its packed
    /// stream and gives None.
    fn header(&mut self, bytes: &[u8], decoded: bool) -> Result<Option<MemberMap>, MapError> {
        let volume = self.header_volume();
        let usage = self.usage.clone();
        let mut reader = Reader::new(bytes, &usage);
        let id = reader.number().map_err(|e| e.into_map(volume))?;
        match id {
            ID_HEADER => {
                let (streams, files) = reader.header().map_err(|e| e.into_map(volume))?;
                self.map(MapEnd::Complete, streams, files).map(Some)
            }
            ID_ENCODED_HEADER => {
                self.depth += 1;
                if self.depth > MAX_NESTING {
                    return Err(malformed(volume, "7z encoded headers nest too deep"));
                }
                let streams = reader.streams_info().map_err(|e| e.into_map(volume))?;
                if streams.folders.len() != 1 || streams.folders[0].packed_streams.len() != 1 {
                    return Err(unsupported(volume, "7z encoded header layout"));
                }
                let start = SIGNATURE_LEN
                    .checked_add(streams.pack_pos)
                    .ok_or_else(|| malformed(volume, "7z encoded header position"))?;
                let len = streams.pack_sizes[0];
                if start.checked_add(len).is_none_or(|end| end > self.header_at) {
                    return Err(malformed(volume, "7z encoded header position"));
                }
                if let Some(aes) = streams.folders[0].aes() {
                    self.header_encrypted = true;
                    self.header_cipher = aes_params(&aes.properties);
                }
                self.start_job(start, len)?;
                self.phase = Phase::Packed(Box::new(streams));
                Ok(None)
            }
            _ if decoded && self.header_encrypted => Err(MapError::WrongPassword),
            _ => Err(malformed(volume, "7z header id")),
        }
    }

    /// Decodes an encoded header's packed stream.
    fn decode(&mut self, streams: &Streams, packed: &[u8], options: &MapOptions) -> Result<Vec<u8>, MapError> {
        let volume = self.header_volume();
        if let Some(crc) = streams.pack_crcs.first().copied().flatten() {
            let actual = crate::crc32::hash(packed);
            if actual != crc {
                return Err(checksum(volume, crc, actual));
            }
        }
        let folder = &streams.folders[0];
        let key = match folder.aes() {
            None => None,
            Some(aes) => {
                let Some(CipherParams::SevenZipAes { num_cycles_power, salt, .. }) = aes_params(&aes.properties) else {
                    return Err(malformed(volume, "7zAES properties"));
                };
                let password =
                    options.password.as_deref().filter(|p| !p.is_empty()).ok_or(MapError::PasswordRequired)?;
                Some(self.derive(password, &salt, num_cycles_power, options, volume)?)
            }
        };
        match decode_folder(folder, packed, key.as_ref(), &self.usage).map_err(|e| e.into_map(volume))? {
            Some(decoded) => Ok(decoded),
            None if key.is_some() => Err(MapError::WrongPassword),
            None => Err(malformed(volume, "7z encoded header does not decode")),
        }
    }

    fn derive(
        &self,
        password: &str,
        salt: &[u8],
        num_cycles_power: u8,
        options: &MapOptions,
        volume: u32,
    ) -> Result<[u8; 32], MapError> {
        let usage = &self.usage;
        let fail = |e| MapError::from_failure(volume, e);
        usage.check(Resource::PasswordUtf8Bytes, password.len() as u64).map_err(fail)?;
        usage.check(Resource::PasswordEncodedBytes, password.encode_utf16().count() as u64 * 2).map_err(fail)?;
        options.limits.check_seven_zip_kdf(num_cycles_power).map_err(fail)?;
        let mut meter = crate::rar5::member::KdfMeter::new(usage, &options.control);
        match crate::crypto::derive_7z_key_controlled(password, salt, num_cycles_power, &mut meter) {
            None => Err(unsupported(volume, "7zAES cycle count")),
            Some(Ok(key)) => Ok(key),
            Some(Err(crate::crypto::KdfControlError::Canceled)) => {
                Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled))))
            }
            Some(Err(crate::crypto::KdfControlError::Limit { resource, limit, attempted })) => {
                Err(MapError::Limit { resource, limit, attempted })
            }
        }
    }

    /// Lists folders and members from a parsed header.
    fn build(&self, streams: Streams, files: Vec<FileEntry>) -> Result<(Vec<MapFolder>, Vec<MapMember>), MapError> {
        let volume = self.header_volume();
        let fail = |e| MapError::from_failure(volume, e);
        // Where each packed stream starts in the archive; all of them lie before the header.
        let mut pack_starts = Vec::with_capacity(streams.pack_sizes.len());
        let mut at = SIGNATURE_LEN.checked_add(streams.pack_pos);
        for &size in &streams.pack_sizes {
            let start = at.ok_or_else(|| malformed(volume, "7z packed stream position"))?;
            pack_starts.push(start);
            at = start.checked_add(size);
        }
        if at.is_none_or(|end| end > self.header_at) {
            return Err(malformed(volume, "7z packed streams run past the header"));
        }
        let mut folders = Vec::with_capacity(streams.folders.len());
        let mut shapes = Vec::with_capacity(streams.folders.len());
        let mut first_pack = 0usize;
        for (index, (folder, &members)) in streams.folders.iter().zip(&streams.substreams).enumerate() {
            let packs = first_pack..first_pack + folder.packed_streams.len();
            first_pack = packs.end;
            let mut packed = Vec::new();
            let mut stream = 0u64;
            for k in packs.clone() {
                for (v, range) in self.split(pack_starts[k]..pack_starts[k] + streams.pack_sizes[k]) {
                    let n = range.end - range.start;
                    packed.push(PackedSpan { volume: v, packed: range, stream: stream..stream + n });
                    stream += n;
                }
            }
            self.usage
                .charge(Resource::MetadataBytes, (std::mem::size_of::<MapFolder>() + packed.len() * 48) as u64)
                .map_err(fail)?;
            let cipher = folder.aes().and_then(|c| aes_params(&c.properties));
            let shape = match folder.chain() {
                Some(_) if folder.coders.iter().all(|c| c.id == 0) => Shape::Copy,
                Some(_) if cipher.is_some() && folder.coders.iter().filter(|c| c.id != 0).count() == 1 => {
                    Shape::AesCopy
                }
                _ => Shape::Other,
            };
            shapes.push((shape, pack_starts.get(packs.start).copied(), packs.start));
            folders.push(MapFolder {
                index: index as u32,
                coders: folder
                    .coders
                    .iter()
                    .map(|c| MapCoder {
                        kind: CoderKind::from_id(c.id),
                        id: c.id,
                        properties: c.properties.clone(),
                        in_streams: c.in_streams as u32,
                        out_streams: c.out_streams as u32,
                    })
                    .collect(),
                bind_pairs: folder.bind_pairs.clone(),
                packed_streams: folder.packed_streams.clone(),
                pack_sizes: streams.pack_sizes[packs].to_vec(),
                packed,
                unpack_sizes: folder.unpack_sizes.clone(),
                unpacked_size: folder.unpacked_size(),
                crc32: folder.crc,
                members,
                cipher,
            });
        }
        let with_stream = files.iter().filter(|f| f.has_stream).count();
        if with_stream != streams.sub_sizes.len() {
            return Err(malformed(volume, "7z file count does not match the substreams"));
        }
        // The folder and offset of each substream, in order.
        let mut slots = streams
            .substreams
            .iter()
            .enumerate()
            .flat_map(|(folder, &count)| std::iter::repeat_n(folder, count as usize))
            .zip(streams.sub_sizes.iter().zip(&streams.sub_crcs));
        let mut folder_offset = (usize::MAX, 0u64);
        let mut members = Vec::with_capacity(files.len());
        for file in files {
            if file.anti {
                continue;
            }
            let base = MapMember {
                ordinal: members.len() as u64,
                raw_name: file.raw_name,
                name: file.name,
                is_dir: file.is_dir,
                unpacked_size: Some(0),
                packed_size: 0,
                method: MapMethod::Stored,
                mapping: OutputMapping::Direct,
                solid: false,
                encrypted: false,
                cipher: None,
                checks: Some(MapChecks::default()),
                mtime: file.mtime.map(filetime),
                ctime: file.ctime.map(filetime),
                atime: file.atime.map(filetime),
                dos_time: None,
                attributes: u64::from(file.attributes.unwrap_or(0)),
                unix_mode: file.attributes.filter(|a| a & ATTRIBUTE_UNIX_EXTENSION != 0).map(|a| a >> 16),
                complete: true,
                pieces: Vec::new(),
                folder: None,
            };
            if !file.has_stream {
                members.push(base);
                continue;
            }
            let (folder_index, (&size, &crc)) = slots.next().expect("as many substreams as files with data");
            if folder_offset.0 != folder_index {
                folder_offset = (folder_index, 0);
            }
            let offset = folder_offset.1;
            folder_offset.1 += size;
            let (shape, pack_start, pack_index) = shapes[folder_index];
            let folder = &folders[folder_index];
            let checks = MapChecks { crc32: crc, blake2sp: None, keyed: false };
            let mut member = MapMember {
                unpacked_size: Some(size),
                checks: Some(checks),
                encrypted: folder.cipher.is_some(),
                cipher: folder.cipher.clone(),
                folder: Some(FolderSlot { index: folder_index as u32, offset }),
                ..base
            };
            let direct = match (shape, pack_start) {
                (Shape::Copy, Some(start)) => {
                    if offset + size > streams.pack_sizes[pack_index] {
                        return Err(malformed(volume, "7z member data past its folder's packed stream"));
                    }
                    Some((OutputMapping::Direct, start + offset, size))
                }
                (Shape::AesCopy, Some(start)) if offset == 0 => {
                    let len = size.checked_next_multiple_of(16).ok_or_else(|| malformed(volume, "7z member size"))?;
                    if len > streams.pack_sizes[pack_index] {
                        return Err(malformed(volume, "7z member data past its folder's packed stream"));
                    }
                    Some((OutputMapping::CbcBlocks, start, len))
                }
                _ => None,
            };
            member.method = if shape == Shape::Other { MapMethod::Coders } else { MapMethod::Stored };
            member.solid = shape == Shape::Other && offset > 0;
            match direct {
                Some((mapping, start, len)) => {
                    member.mapping = mapping;
                    let mut stream = 0u64;
                    for (v, range) in self.split(start..start + len) {
                        let n = range.end - range.start;
                        member.pieces.push(MapPiece {
                            volume: v,
                            packed: range,
                            header: 0..0,
                            stream_offset: stream,
                            out: mapping.out_of(stream..stream + n, Some(size)),
                            checks: MapChecks::default(),
                            final_part: false,
                        });
                        stream += n;
                    }
                }
                // The folder's spans are listed once, in `MapFolder::packed`; the slot points there.
                None => member.mapping = OutputMapping::None,
            }
            if let Some(last) = member.pieces.last_mut() {
                last.final_part = true;
            }
            member.packed_size = member.pieces.iter().map(|p| p.packed.end - p.packed.start).sum();
            self.usage
                .charge(
                    Resource::MetadataBytes,
                    (member.raw_name.len() * 2 + member.pieces.len() * std::mem::size_of::<MapPiece>()) as u64,
                )
                .and_then(|_| self.usage.charge(Resource::Parts, member.pieces.len() as u64))
                .map_err(fail)?;
            members.push(member);
        }
        Ok((folders, members))
    }
}

/// A Windows FILETIME (100 ns units since 1601) as seconds and nanoseconds since 1970.
fn filetime(ticks: u64) -> (i64, u32) {
    const EPOCH_DIFF: i64 = 11_644_473_600;
    ((ticks / 10_000_000) as i64 - EPOCH_DIFF, (ticks % 10_000_000) as u32 * 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage() -> Usage {
        Usage::new(crate::progressive::ProgressiveLimits::default())
    }

    #[test]
    fn numbers_decode_every_length() {
        let usage = usage();
        for (bytes, want) in [
            (&[0x7Fu8][..], 0x7Fu64),
            (&[0x80, 0xFF], 0xFF),
            (&[0xBF, 0xFF], 0x3FFF),
            (&[0xDF, 0xFF, 0xFF], 0x1F_FFFF),
            (&[0xC1, 0x02, 0x03], 0x01_0302),
            (&[0xFF, 1, 2, 3, 4, 5, 6, 7, 8], 0x0807_0605_0403_0201),
        ] {
            assert_eq!(Reader::new(bytes, &usage).number().ok(), Some(want), "{bytes:?}");
        }
        assert!(Reader::new(&[0xC1, 0x02], &usage).number().is_err());
    }

    #[test]
    fn aes_properties() {
        assert_eq!(
            aes_params(&[0x13]),
            Some(CipherParams::SevenZipAes { num_cycles_power: 0x13, salt: vec![], iv: [0; 16] })
        );
        let mut props = vec![0xD3, 0x0F];
        props.extend([1; 17]);
        assert_eq!(
            aes_params(&props),
            Some(CipherParams::SevenZipAes { num_cycles_power: 0x13, salt: vec![1], iv: [1; 16] })
        );
        assert_eq!(aes_params(&props[..17]), None);
        assert_eq!(aes_params(&[]), None);
    }

    #[test]
    fn filetimes() {
        assert_eq!(filetime(116_444_736_000_000_000), (0, 0));
        assert_eq!(filetime(116_444_736_000_000_123), (0, 12_300));
    }
}
