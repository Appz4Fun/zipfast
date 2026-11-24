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

//! A streaming tar writer to any `Write` sink, byte-exact with GNU tar 1.35 for its `--format=gnu` (the default),
//! `--format=ustar` and `--format=pax` outputs, `-b 20` blocking by default. See `docs/tar-writer.md`.

use std::io::{Read, Write};

use crate::error::{Error, Result};

pub use super::compress::{CompressedWriter, Compression};

const BLOCK: usize = 512;
const MAX_OCTAL_7: u64 = 0o7777777;
const MAX_OCTAL_11: u64 = 0o77777777777;

/// The archive dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TarFormat {
    /// GNU tar's default: `ustar  \0` magic, `././@LongLink` for long names and link targets, base-256 numbers.
    #[default]
    Gnu,
    /// POSIX ustar: names split over the prefix field; what does not fit is an error.
    Ustar,
    /// POSIX pax: extended headers for long or non-ASCII names, big numbers and sub-second mtimes. The extended
    /// header is named `<dir>/PaxHeaders/<base>` (GNU tar's `--pax-option=exthdr.name=%d/PaxHeaders/%f`) so the
    /// output does not depend on a process id.
    Pax,
}

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TarEntryKind {
    File,
    Dir,
    Symlink,
    /// `link` names the earlier member it links to; no data follows.
    HardLink,
    CharDevice,
    BlockDevice,
    Fifo,
    /// A sparse file: `size` is the apparent size, `sparse` the data segments; only their bytes follow. GNU and
    /// pax formats only (pax writes version 1.0, which GNU tar 1.35 uses by default).
    Sparse,
}

/// A stat-like description of one member, as the caller read it from the file system.
#[derive(Clone, Debug)]
pub struct TarEntry {
    /// The member name as stored; a directory's trailing slash is added when missing.
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    /// Permission bits (`st_mode & 0o7777`; higher bits are dropped as GNU tar does).
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    /// The owner and group names; empty when unknown.
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    /// Seconds since the epoch and the nanoseconds past them.
    pub mtime: i64,
    pub mtime_nanos: u32,
    /// The data length of a [`TarEntryKind::File`]; ignored for every other kind.
    pub size: u64,
    /// The target of a symbolic or hard link.
    pub link: Vec<u8>,
    pub dev_major: u64,
    pub dev_minor: u64,
    /// For [`TarEntryKind::Sparse`]: the data segments as `(offset, length)`, ascending, non-empty, not
    /// overlapping, inside `size`. Everything between them is a hole. `size` is the apparent file size.
    pub sparse: Vec<(u64, u64)>,
}

impl TarEntry {
    /// An entry of `kind` named `path`, owned by root, mode 0644 (0755 for a directory), mtime 0.
    pub fn new(path: impl Into<Vec<u8>>, kind: TarEntryKind) -> TarEntry {
        TarEntry {
            path: path.into(),
            kind,
            mode: if kind == TarEntryKind::Dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            uname: Vec::new(),
            gname: Vec::new(),
            mtime: 0,
            mtime_nanos: 0,
            size: 0,
            link: Vec::new(),
            dev_major: 0,
            dev_minor: 0,
            sparse: Vec::new(),
        }
    }
}

/// An owner or group override (`--owner=NAME:ID`, `--group=NAME:ID`).
#[derive(Clone, Debug, Default)]
pub struct IdOverride {
    pub id: u64,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TarWriterOptions {
    pub format: TarFormat,
    /// `-b N`: blocks per record; the archive is padded to whole records (default 20, 10240 bytes).
    pub blocking_factor: usize,
    /// `--owner`
    pub owner: Option<IdOverride>,
    /// `--group`
    pub group: Option<IdOverride>,
    /// `--mtime`: seconds, replacing every member's mtime (sub-seconds dropped).
    pub mtime: Option<i64>,
    /// `--numeric-owner`: no owner or group names.
    pub numeric_owner: bool,
    /// The process id GNU tar puts in a pax sparse member's name (`<dir>/GNUSparseFile.<pid>/<name>`); the
    /// current process id when `None`. Set it for reproducible archives.
    pub sparse_pid: Option<u32>,
}

impl Default for TarWriterOptions {
    fn default() -> Self {
        TarWriterOptions {
            format: TarFormat::Gnu,
            blocking_factor: 20,
            owner: None,
            group: None,
            mtime: None,
            numeric_owner: false,
            sparse_pid: None,
        }
    }
}

/// Writes a tar archive to `W`, member by member.
pub struct TarWriter<W: Write> {
    w: W,
    opts: TarWriterOptions,
    written: u64,
    /// data bytes still owed to the current file
    owed: u64,
}

impl<W: Write> TarWriter<W> {
    pub fn new(w: W, opts: TarWriterOptions) -> TarWriter<W> {
        TarWriter {
            w,
            opts: TarWriterOptions { blocking_factor: opts.blocking_factor.max(1), ..opts },
            written: 0,
            owed: 0,
        }
    }

    /// Writes the header of `entry`. For a [`TarEntryKind::File`] its `size` bytes of data must follow through
    /// [`write_data`](Self::write_data) before the next entry.
    pub fn begin(&mut self, entry: &TarEntry) -> Result<()> {
        if self.owed != 0 {
            return Err(Error::Unsupported("a tar member's data is incomplete".into()));
        }
        if entry.path.is_empty() {
            return Err(Error::Unsupported("a tar member with an empty name".into()));
        }
        let sparse = entry.kind == TarEntryKind::Sparse;
        let data_len = if sparse { check_sparse(entry)? } else { 0 };
        let size = if entry.kind == TarEntryKind::File { entry.size } else { 0 };
        let mut name = entry.path.clone();
        if entry.kind == TarEntryKind::Dir && !name.ends_with(b"/") {
            name.push(b'/');
        }
        let (blocks, owed) = if sparse {
            let h = Header::resolve(entry, name, data_len, &self.opts);
            match self.opts.format {
                TarFormat::Gnu => (h.gnu_sparse()?, data_len),
                TarFormat::Pax => {
                    let map = pax_map(entry);
                    let pid = self.opts.sparse_pid.unwrap_or_else(std::process::id);
                    let h = Header { size: map.len() as u64 + data_len, ..h };
                    let mut blocks = h.pax_sparse(pid)?;
                    push_data(&mut blocks, &map, false);
                    (blocks, data_len)
                }
                TarFormat::Ustar => return Err(Error::Unsupported("sparse members need the gnu or pax format".into())),
            }
        } else {
            let h = Header::resolve(entry, name, size, &self.opts);
            let blocks = match self.opts.format {
                TarFormat::Gnu => h.gnu()?,
                TarFormat::Ustar => h.ustar()?,
                TarFormat::Pax => h.pax()?,
            };
            (blocks, size)
        };
        for b in &blocks {
            self.put(b)?;
        }
        self.owed = owed;
        Ok(())
    }

    /// Data of the current file; at most the bytes still owed.
    pub fn write_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() as u64 > self.owed {
            return Err(Error::Unsupported("more data than the tar member's size".into()));
        }
        self.put(data)?;
        self.owed -= data.len() as u64;
        if self.owed == 0 {
            self.pad()?;
        }
        Ok(())
    }

    /// A whole member: its header, then `entry.size` bytes read from `data` (an error when it ends early).
    pub fn append(&mut self, entry: &TarEntry, data: &mut dyn Read) -> Result<()> {
        self.begin(entry)?;
        let mut buf = vec![0u8; 64 << 10];
        while self.owed > 0 {
            let want = buf.len().min(self.owed as usize);
            let n = match data.read(&mut buf[..want]) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(Error::Truncated);
            }
            self.write_data(&buf[..n])?;
        }
        Ok(())
    }

    /// The end of the archive: two zero blocks, then zeros to the end of the record. Returns the sink.
    pub fn finish(mut self) -> Result<W> {
        if self.owed != 0 {
            return Err(Error::Unsupported("a tar member's data is incomplete".into()));
        }
        self.put(&[0u8; 2 * BLOCK])?;
        let record = (self.opts.blocking_factor * BLOCK) as u64;
        let n = (record - self.written % record) % record;
        self.put(&vec![0u8; n as usize])?;
        self.w.flush()?;
        Ok(self.w)
    }

    fn put(&mut self, data: &[u8]) -> Result<()> {
        self.w.write_all(data)?;
        self.written += data.len() as u64;
        Ok(())
    }

    fn pad(&mut self) -> Result<()> {
        let n = (BLOCK as u64 - self.written % BLOCK as u64) % BLOCK as u64;
        self.put(&[0u8; BLOCK][..n as usize])
    }
}

/// An entry with the overrides applied.
struct Header<'a> {
    e: &'a TarEntry,
    name: Vec<u8>,
    size: u64,
    uid: u64,
    gid: u64,
    uname: Vec<u8>,
    gname: Vec<u8>,
    mtime: i64,
    nanos: u32,
    numeric: bool,
}

impl<'a> Header<'a> {
    fn resolve(e: &'a TarEntry, name: Vec<u8>, size: u64, o: &TarWriterOptions) -> Header<'a> {
        let (uid, mut uname) = match &o.owner {
            Some(ov) => (ov.id, ov.name.clone()),
            None => (e.uid, e.uname.clone()),
        };
        let (gid, mut gname) = match &o.group {
            Some(ov) => (ov.id, ov.name.clone()),
            None => (e.gid, e.gname.clone()),
        };
        if o.numeric_owner {
            uname.clear();
            gname.clear();
        }
        let (mtime, nanos) = match o.mtime {
            Some(m) => (m, 0),
            None => (e.mtime, e.mtime_nanos),
        };
        Header { e, name, size, uid, gid, uname, gname, mtime, nanos, numeric: o.numeric_owner }
    }

    fn typeflag(&self) -> u8 {
        match self.e.kind {
            TarEntryKind::File | TarEntryKind::Sparse => b'0',
            TarEntryKind::HardLink => b'1',
            TarEntryKind::Symlink => b'2',
            TarEntryKind::CharDevice => b'3',
            TarEntryKind::BlockDevice => b'4',
            TarEntryKind::Dir => b'5',
            TarEntryKind::Fifo => b'6',
        }
    }

    fn is_device(&self) -> bool {
        matches!(self.e.kind, TarEntryKind::CharDevice | TarEntryKind::BlockDevice)
    }

    fn has_link(&self) -> bool {
        matches!(self.e.kind, TarEntryKind::Symlink | TarEntryKind::HardLink)
    }

    /// The 512-byte header. `numbers_extended` says which of uid, gid, size and mtime went to a pax header, so
    /// the field holds 0; the others that do not fit use base-256 when `base256` allows it.
    fn block(&self, f: &Fields) -> Result<[u8; BLOCK]> {
        let mut h = [0u8; BLOCK];
        let n = f.name.len().min(100);
        h[..n].copy_from_slice(&f.name[..n]);
        octal(&mut h[100..108], u64::from(f.mode & 0o7777));
        num(&mut h[108..116], f.uid, f.base256)?;
        num(&mut h[116..124], f.gid, f.base256)?;
        num(&mut h[124..136], f.size, f.base256)?;
        num_time(&mut h[136..148], f.mtime, f.base256)?;
        h[148..156].fill(b' ');
        h[156] = f.typeflag;
        let l = f.link.len().min(100);
        h[157..157 + l].copy_from_slice(&f.link[..l]);
        if f.gnu_magic {
            h[257..265].copy_from_slice(b"ustar  \0");
        } else {
            h[257..265].copy_from_slice(b"ustar\x0000");
        }
        let u = f.uname.len().min(32);
        h[265..265 + u].copy_from_slice(&f.uname[..u]);
        let g = f.gname.len().min(32);
        h[297..297 + g].copy_from_slice(&f.gname[..g]);
        if f.device {
            num(&mut h[329..337], f.dev_major, f.base256)?;
            num(&mut h[337..345], f.dev_minor, f.base256)?;
        }
        h[345..345 + f.prefix.len()].copy_from_slice(f.prefix);
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        Ok(h)
    }

    fn fields<'b>(&'b self, name: &'b [u8], prefix: &'b [u8], gnu: bool) -> Fields<'b> {
        Fields {
            name,
            prefix,
            link: &self.e.link,
            mode: self.e.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            mtime: self.mtime,
            typeflag: self.typeflag(),
            uname: &self.uname,
            gname: &self.gname,
            device: self.is_device(),
            dev_major: self.e.dev_major,
            dev_minor: self.e.dev_minor,
            base256: gnu,
            gnu_magic: gnu,
        }
    }

    fn gnu(&self) -> Result<Vec<[u8; BLOCK]>> {
        let mut out = Vec::new();
        if self.has_link() && self.e.link.len() > 100 {
            self.long_record(&mut out, b'K', &self.e.link)?;
        }
        if self.name.len() > 100 {
            self.long_record(&mut out, b'L', &self.name)?;
        }
        let f = self.fields(&self.name, b"", true);
        out.push(self.block(&f)?);
        Ok(out)
    }

    /// An old GNU sparse header (`S`): the first four segments in the header, the rest in extension blocks. The
    /// map ends with a zero-length segment at the apparent size, as GNU tar writes it.
    fn gnu_sparse(&self) -> Result<Vec<[u8; BLOCK]>> {
        let mut out = Vec::new();
        if self.name.len() > 100 {
            self.long_record(&mut out, b'L', &self.name)?;
        }
        let mut f = self.fields(&self.name, b"", true);
        f.typeflag = b'S';
        let mut h = self.block(&f)?;
        let mut segs = self.e.sparse.clone();
        segs.push((self.e.size, 0));
        let mut ext: Vec<[u8; BLOCK]> = Vec::new();
        for (i, &(off, len)) in segs.iter().enumerate() {
            let slot: &mut [u8] = if i < 4 {
                &mut h[386 + 24 * i..386 + 24 * (i + 1)]
            } else {
                let j = (i - 4) % 21;
                if j == 0 {
                    ext.push([0u8; BLOCK]);
                }
                let b = ext.last_mut().expect("pushed above");
                &mut b[24 * j..24 * (j + 1)]
            };
            num(&mut slot[..12], off, true)?;
            num(&mut slot[12..], len, true)?;
        }
        if segs.len() > 4 {
            h[482] = 1;
        }
        for k in 1..ext.len() {
            ext[k - 1][504] = 1;
        }
        num(&mut h[483..495], self.e.size, true)?;
        let sum: u64 =
            h.iter().enumerate().map(|(i, &b)| u64::from(if (148..156).contains(&i) { b' ' } else { b })).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.push(h);
        out.extend(ext);
        Ok(out)
    }

    /// A pax 1.0 sparse member: an `x` header with the `GNU.sparse.*` records, then the data header named
    /// `<dir>/GNUSparseFile.<pid>/<base>` (cut to 100 bytes, as GNU tar does). The caller adds the map blocks.
    fn pax_sparse(&self, pid: u32) -> Result<Vec<[u8; BLOCK]>> {
        let (dir, base) = dir_and_base(&self.name);
        let data_name = [dir.as_slice(), format!("/GNUSparseFile.{pid}/").as_bytes(), base].concat();
        self.pax_with(Some(&data_name))
    }

    /// A `././@LongLink` member (several blocks: header, then the text and a NUL padded to blocks).
    fn long_record(&self, out: &mut Vec<[u8; BLOCK]>, typeflag: u8, text: &[u8]) -> Result<()> {
        let root: &[u8] = if self.numeric { b"" } else { b"root" };
        let f = Fields {
            name: b"././@LongLink",
            prefix: b"",
            link: b"",
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: text.len() as u64 + 1,
            mtime: 0,
            typeflag,
            uname: root,
            gname: root,
            device: false,
            dev_major: 0,
            dev_minor: 0,
            base256: true,
            gnu_magic: true,
        };
        out.push(self.block(&f)?);
        push_data(out, text, true);
        Ok(())
    }

    fn ustar(&self) -> Result<Vec<[u8; BLOCK]>> {
        let (prefix, name) = match split_ustar(&self.name) {
            Some(s) => s,
            None => return Err(Error::Unsupported("a file name too long for the ustar format".into())),
        };
        if self.has_link() && self.e.link.len() > 100 {
            return Err(Error::Unsupported("a link target too long for the ustar format".into()));
        }
        if self.uname.len() > 32 || self.gname.len() > 32 {
            return Err(Error::Unsupported("an owner name too long for the ustar format".into()));
        }
        let f = self.fields(name, prefix, false);
        Ok(vec![self.block(&f)?])
    }

    fn pax(&self) -> Result<Vec<[u8; BLOCK]>> {
        self.pax_with(None)
    }

    /// `sparse_name`: the data header's name of a pax 1.0 sparse member (then the path travels in
    /// `GNU.sparse.name` instead of `path`, and the first records describe the sparse layout).
    fn pax_with(&self, sparse_name: Option<&[u8]>) -> Result<Vec<[u8; BLOCK]>> {
        let mut recs: Vec<u8> = Vec::new();
        let mut rec = |k: &str, v: &[u8]| recs.extend_from_slice(&pax_record(k, v));
        let link = &self.e.link;
        let wide = |s: &[u8], max: usize| s.len() > max || !s.is_ascii();
        if self.has_link() && wide(link, 100) {
            rec("linkpath", link);
        }
        if sparse_name.is_some() {
            rec("GNU.sparse.major", b"1");
            rec("GNU.sparse.minor", b"0");
            rec("GNU.sparse.name", &self.name);
            rec("GNU.sparse.realsize", self.e.size.to_string().as_bytes());
        } else if wide(&self.name, 100) {
            rec("path", &self.name);
        }
        let mut f = self.fields(sparse_name.unwrap_or(&self.name), b"", false);
        let field_zero = |v: &mut u64, key: &str, max: u64, rec: &mut dyn FnMut(&str, &[u8])| {
            if *v > max {
                rec(key, v.to_string().as_bytes());
                *v = 0;
            }
        };
        field_zero(&mut f.uid, "uid", MAX_OCTAL_7, &mut rec);
        field_zero(&mut f.gid, "gid", MAX_OCTAL_7, &mut rec);
        field_zero(&mut f.size, "size", MAX_OCTAL_11, &mut rec);
        let in_range = (0..=MAX_OCTAL_11 as i64).contains(&self.mtime);
        if !in_range || self.nanos != 0 {
            // the signed decimal of mtime + nanos/1e9: a negative time with a fraction is minus its magnitude
            let (whole, nanos) = if self.mtime < 0 && self.nanos != 0 {
                (self.mtime.unsigned_abs() - 1, 1_000_000_000 - self.nanos)
            } else {
                (self.mtime.unsigned_abs(), self.nanos)
            };
            let mut v = format!("{}{whole}", if self.mtime < 0 { "-" } else { "" });
            if nanos != 0 {
                let frac = format!("{nanos:09}");
                v.push('.');
                v.push_str(frac.trim_end_matches('0'));
            }
            rec("mtime", v.as_bytes());
        }
        if !in_range {
            f.mtime = 0;
        }
        if wide(&self.uname, 32) {
            rec("uname", &self.uname);
        }
        if wide(&self.gname, 32) {
            rec("gname", &self.gname);
        }
        if self.is_device() && (self.e.dev_major > MAX_OCTAL_7 || self.e.dev_minor > MAX_OCTAL_7) {
            return Err(Error::Unsupported("a device number too large for a pax header".into()));
        }
        let mut out = Vec::new();
        if !recs.is_empty() {
            let (dir, base) = dir_and_base(&self.name);
            let xname = [dir.as_slice(), b"/PaxHeaders/", base].concat();
            let x = Fields {
                name: &xname,
                prefix: b"",
                link: b"",
                mode: 0o644,
                uid: 0,
                gid: 0,
                size: recs.len() as u64,
                mtime: self.mtime.clamp(0, MAX_OCTAL_11 as i64),
                typeflag: b'x',
                uname: b"",
                gname: b"",
                device: false,
                dev_major: 0,
                dev_minor: 0,
                base256: false,
                gnu_magic: false,
            };
            out.push(self.block(&x)?);
            push_data(&mut out, &recs, false);
        }
        out.push(self.block(&f)?);
        Ok(out)
    }
}

struct Fields<'a> {
    name: &'a [u8],
    prefix: &'a [u8],
    link: &'a [u8],
    mode: u32,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: i64,
    typeflag: u8,
    uname: &'a [u8],
    gname: &'a [u8],
    device: bool,
    dev_major: u64,
    dev_minor: u64,
    base256: bool,
    gnu_magic: bool,
}

/// `data` (and a NUL when `nul`) in whole zero-padded blocks.
fn push_data(out: &mut Vec<[u8; BLOCK]>, data: &[u8], nul: bool) {
    let mut all = data.to_vec();
    if nul {
        all.push(0);
    }
    for chunk in all.chunks(BLOCK) {
        let mut b = [0u8; BLOCK];
        b[..chunk.len()].copy_from_slice(chunk);
        out.push(b);
    }
}

/// GNU tar's `%d` and `%f`: the directory part of a name (`.` when it has none) and its last component.
fn dir_and_base(name: &[u8]) -> (Vec<u8>, &[u8]) {
    let mut end = name.len();
    while end > 1 && name[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &name[..end];
    match trimmed.iter().rposition(|&b| b == b'/') {
        None => (b".".to_vec(), trimmed),
        Some(i) => {
            let mut d = i;
            while d > 1 && trimmed[d - 1] == b'/' {
                d -= 1;
            }
            let dir = if d == 0 { b"/".to_vec() } else { trimmed[..d].to_vec() };
            (dir, &trimmed[i + 1..])
        }
    }
}

/// A name split into a ustar prefix and name the way GNU tar does: at the last slash within the first 156 bytes.
fn split_ustar(name: &[u8]) -> Option<(&[u8], &[u8])> {
    if name.len() <= 100 {
        return Some((b"", name));
    }
    let mut length = name.len();
    if length > 156 {
        length = 156;
    } else if name[length - 1] == b'/' {
        length -= 1;
    }
    let mut i = length - 1;
    while i > 0 && name[i] != b'/' {
        i -= 1;
    }
    if i == 0 || name.len() - i - 1 > 100 {
        return None;
    }
    Some((&name[..i], &name[i + 1..]))
}

/// The segments a sparse entry carries, checked; returns the data bytes they hold.
fn check_sparse(e: &TarEntry) -> Result<u64> {
    let bad = |m: &str| Err(Error::Unsupported(format!("sparse tar member: {m}")));
    let mut end = 0u64;
    let mut total = 0u64;
    for &(off, len) in &e.sparse {
        if len == 0 {
            return bad("empty data segment");
        }
        if off < end {
            return bad("segments out of order or overlapping");
        }
        end = match off.checked_add(len) {
            Some(x) if x <= e.size => x,
            _ => return bad("segment beyond the apparent size"),
        };
        total += len;
    }
    // GNU tar pads every data segment to whole blocks but counts the stored size unpadded; only the last
    // segment may end mid-block, or the stored size and the layout disagree and GNU tar misreads the archive.
    if let Some((_, rest)) = e.sparse.split_last()
        && rest.iter().any(|&(_, len)| len % BLOCK as u64 != 0)
    {
        return bad("a data segment before the last must be a multiple of 512 bytes");
    }
    Ok(total)
}

/// The pax 1.0 map at the start of the member's data: the segment count, then offset and length of each (with
/// the final zero-length segment at the apparent size), one number per line, padded to whole blocks.
fn pax_map(e: &TarEntry) -> Vec<u8> {
    let mut t = format!("{}\n", e.sparse.len() + 1);
    for &(off, len) in &e.sparse {
        t.push_str(&format!("{off}\n{len}\n"));
    }
    t.push_str(&format!("{}\n0\n", e.size));
    let mut v = t.into_bytes();
    v.resize(v.len().div_ceil(BLOCK) * BLOCK, 0);
    v
}

/// One pax record, `"<len> <key>=<value>\n"`, its length counting its own digits.
fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body = key.len() + value.len() + 3;
    let mut len = body + 1;
    while len != body + len.to_string().len() {
        len = body + len.to_string().len();
    }
    let mut r = format!("{len} {key}=").into_bytes();
    r.extend_from_slice(value);
    r.push(b'\n');
    r
}

/// A zero-padded octal number filling all but the last byte of `field`, which is NUL.
fn octal(field: &mut [u8], v: u64) {
    let digits = field.len() - 1;
    field[..digits].copy_from_slice(format!("{v:0digits$o}").as_bytes());
    field[digits] = 0;
}

/// An unsigned number: octal when it fits, else base-256 (GNU) or an error.
fn num(field: &mut [u8], v: u64, base256: bool) -> Result<()> {
    let digits = field.len() - 1;
    if digits >= 22 || v < 1u64 << (3 * digits) {
        octal(field, v);
        return Ok(());
    }
    if !base256 {
        return Err(Error::Unsupported("a number too large for the tar format".into()));
    }
    field.fill(0);
    let n = field.len();
    // The marker takes the top bit and the next one is the sign, so 8n - 2 value bits remain.
    if n <= 8 && v >> (8 * n - 2) != 0 {
        return Err(Error::Unsupported("a number too large for the tar field".into()));
    }
    if n >= 8 {
        field[n - 8..].copy_from_slice(&v.to_be_bytes());
    } else {
        field.copy_from_slice(&v.to_be_bytes()[8 - n..]);
    }
    field[0] |= 0x80;
    Ok(())
}

/// A time: octal when 0 through the field's maximum, else base-256 two's complement (GNU) or an error.
fn num_time(field: &mut [u8], v: i64, base256: bool) -> Result<()> {
    if (0..=MAX_OCTAL_11 as i64).contains(&v) {
        octal(field, v as u64);
        return Ok(());
    }
    if !base256 {
        return Err(Error::Unsupported("a time out of range for the tar format".into()));
    }
    let fill = if v < 0 { 0xff } else { 0 };
    field.fill(fill);
    let n = field.len();
    field[n - 8..].copy_from_slice(&v.to_be_bytes());
    field[0] = if v < 0 { 0xff } else { 0x80 };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pax_record_lengths_count_themselves() {
        assert_eq!(pax_record("path", b"a"), b"9 path=a\n");
        let v = vec![b'x'; 91];
        assert!(pax_record("path", &v).starts_with(b"101 path="));
    }

    #[test]
    fn ustar_split_matches_gnu() {
        let name = [vec![b'd'; 60], b"/".to_vec(), vec![b'e'; 60], b"/r.txt".to_vec()].concat();
        let (p, n) = split_ustar(&name).unwrap();
        assert_eq!((p.len(), n), (121, b"r.txt".as_slice()));
        assert!(split_ustar(&[b'x'; 101]).is_none());
    }

    #[test]
    fn base256_numbers() {
        let mut f = [0u8; 8];
        num(&mut f, 3_000_000, true).unwrap();
        assert_eq!(f, [0x80, 0, 0, 0, 0, 0x2d, 0xc6, 0xc0]);
        assert!(num(&mut f, 3_000_000, false).is_err());
        let mut t = [0u8; 12];
        num_time(&mut t, -1, true).unwrap();
        assert_eq!(t, [0xff; 12]);
    }

    #[test]
    fn dir_and_base_follow_gnu() {
        assert_eq!(dir_and_base(b"a"), (b".".to_vec(), b"a".as_slice()));
        assert_eq!(dir_and_base(b"a/b/"), (b"a".to_vec(), b"b".as_slice()));
        assert_eq!(dir_and_base(b"a/b/c"), (b"a/b".to_vec(), b"c".as_slice()));
    }
}
