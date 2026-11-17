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

//! A tar archive read member by member, its file data spooled to an unnamed temporary file, then written sorted as
//! a gzipped POSIX tar.

use std::collections::HashMap;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use flate2::{Compression, GzBuilder};

use super::{
    Budget, RepackFormat, RepackOptions, RepackSummary, copy_exact, lossy, nested_name, open_input, repack_nested,
    unsafe_name,
};
use crate::error::{Error, Result};
use crate::tar::{RawKind, walk_members};

const BLOCK: usize = 512;
/// GNU tar and bsdtar pad an archive to whole records of 20 blocks.
const RECORD: u64 = 20 * BLOCK as u64;
const MAX_OCTAL_11: u64 = 0o77777777777;
const MAX_OCTAL_7: u64 = 0o7777777;
/// The OS byte `gzip -n` writes on Unix.
const GZIP_OS_UNIX: u8 = 3;

struct Member {
    name: Vec<u8>,
    link: Vec<u8>,
    kind: RawKind,
    device: (u64, u64),
    /// the linked set a file or hard link belongs to
    group: Option<usize>,
}

/// One file's data, shared by every hard link to it.
struct Group {
    offset: u64,
    len: u64,
    mode: u32,
}

pub(super) fn repack(input: &Path, out: &mut dyn Write, opts: &RepackOptions) -> Result<RepackSummary> {
    drop(open_input(input)?);
    let mut budget = Budget { left: opts.limit };
    let mut spool = BufWriter::with_capacity(1 << 20, tempfile::tempfile()?);
    let mut spooled = 0u64;
    let mut members = Vec::new();
    let mut groups: Vec<Group> = Vec::new();
    // a hard link names the member it links to by its stored name; the latest member of that name counts
    let mut by_name: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut nested = 0u64;
    walk_members(input, opts.limit, |raw, data| {
        if unsafe_name(&raw.name) {
            return Err(Error::UnsafePath(lossy(&raw.name)));
        }
        if raw.link.contains(&0) {
            return Err(Error::Corrupt("a tar link target holds a NUL"));
        }
        let mut name = raw.name;
        let mut group = None;
        match raw.kind {
            RawKind::Dir => {
                while name.len() > 1 && name.ends_with(b"/") {
                    name.pop();
                }
                name.push(b'/');
            }
            RawKind::File => {
                budget.take(raw.size)?;
                let offset = spooled;
                let len = if opts.nested && nested_name(&name) {
                    let mut whole = tempfile::tempfile()?;
                    {
                        let mut w = BufWriter::new(&mut whole);
                        data.read(&mut |d| w.write_all(d).map_err(Error::Io))?;
                        w.flush()?;
                    }
                    let (mut from, len) = match repack_nested(&mut whole, opts, &mut budget)? {
                        Some(repacked) => {
                            nested += 1;
                            repacked
                        }
                        None => {
                            whole.seek(SeekFrom::Start(0))?;
                            (whole, raw.size)
                        }
                    };
                    copy_exact(&mut from, &mut spool, len)?;
                    len
                } else {
                    let mut len = 0u64;
                    data.read(&mut |d| {
                        len += d.len() as u64;
                        spool.write_all(d).map_err(Error::Io)
                    })?;
                    if len != raw.size {
                        return Err(Error::Truncated);
                    }
                    len
                };
                spooled += len;
                groups.push(Group { offset, len, mode: raw.mode });
                group = Some(groups.len() - 1);
                by_name.insert(name.clone(), groups.len() - 1);
            }
            RawKind::HardLink => {
                let Some(&g) = by_name.get(&raw.link) else {
                    return Err(Error::Corrupt("a tar hard link names no earlier file"));
                };
                group = Some(g);
                by_name.insert(name.clone(), g);
            }
            RawKind::Symlink | RawKind::CharDevice | RawKind::BlockDevice | RawKind::Fifo => {}
        }
        members.push(Member { name, link: raw.link, kind: raw.kind, device: raw.device, group });
        Ok(())
    })?;
    let mut spool = spool.into_inner().map_err(|e| Error::Io(e.into_error()))?;

    // stable, so two members of the same name keep their order
    members.sort_by(|a, b| a.name.cmp(&b.name));

    let gz = GzBuilder::new().mtime(0).operating_system(GZIP_OS_UNIX).write(out, Compression::new(opts.level));
    let mut tar = TarWriter { w: gz, written: 0, mtime: opts.mtime };
    // the name each linked set's data was written under, once it has been
    let mut written_as: Vec<Option<Vec<u8>>> = vec![None; groups.len()];
    for m in &members {
        match m.kind {
            RawKind::Dir => tar.header(&m.name, b"", b'5', 0o755, 0, (0, 0))?,
            RawKind::Symlink => tar.header(&m.name, &m.link, b'2', 0o777, 0, (0, 0))?,
            RawKind::CharDevice => tar.header(&m.name, b"", b'3', 0o644, 0, m.device)?,
            RawKind::BlockDevice => tar.header(&m.name, b"", b'4', 0o644, 0, m.device)?,
            RawKind::Fifo => tar.header(&m.name, b"", b'6', 0o644, 0, (0, 0))?,
            RawKind::File | RawKind::HardLink => {
                let g = m.group.expect("files and hard links have a group");
                let group = &groups[g];
                let mode = if group.mode & 0o111 != 0 { 0o755 } else { 0o644 };
                match &written_as[g] {
                    Some(first) => tar.header(&m.name, first, b'1', mode, 0, (0, 0))?,
                    None => {
                        tar.header(&m.name, b"", b'0', mode, group.len, (0, 0))?;
                        spool.seek(SeekFrom::Start(group.offset))?;
                        copy_exact(&mut spool, &mut tar.w, group.len)?;
                        tar.written += group.len;
                        tar.pad()?;
                        written_as[g] = Some(m.name.clone());
                    }
                }
            }
        }
    }
    tar.finish()?;
    Ok(RepackSummary { format: RepackFormat::TarGz, members: members.len() as u64, nested })
}

struct TarWriter<W: Write> {
    w: W,
    written: u64,
    mtime: u64,
}

impl<W: Write> TarWriter<W> {
    /// A member's header, after a pax header when its name, link or size does not fit ustar.
    fn header(
        &mut self,
        name: &[u8],
        link: &[u8],
        typeflag: u8,
        mode: u32,
        size: u64,
        device: (u64, u64),
    ) -> Result<()> {
        if device.0 > MAX_OCTAL_7 || device.1 > MAX_OCTAL_7 {
            return Err(Error::Unsupported("a device number too large for a tar header".into()));
        }
        let split = split_ustar(name);
        let mut records: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut binary = false;
        if link.len() > 100 {
            binary |= std::str::from_utf8(link).is_err();
            records.push(("linkpath", link.to_vec()));
        }
        if split.is_none() {
            binary |= std::str::from_utf8(name).is_err();
            records.push(("path", name.to_vec()));
        }
        if size > MAX_OCTAL_11 {
            records.push(("size", size.to_string().into_bytes()));
        }
        if binary {
            records.insert(0, ("hdrcharset", b"BINARY".to_vec()));
        }
        if !records.is_empty() {
            let mut data = Vec::new();
            for (key, value) in &records {
                data.extend_from_slice(&pax_record(key, value));
            }
            let base = name.rsplit(|&b| b == b'/').find(|p| !p.is_empty()).unwrap_or(b"");
            let pax_name: Vec<u8> = [b"PaxHeaders/".as_slice(), base].concat();
            let h = block(
                &pax_name[..pax_name.len().min(100)],
                b"",
                b"",
                b'x',
                0o644,
                data.len() as u64,
                self.mtime,
                (0, 0),
            );
            self.w.write_all(&h)?;
            self.w.write_all(&data)?;
            self.written += (BLOCK + data.len()) as u64;
            self.pad()?;
        }
        let (prefix, short) = split.unwrap_or((b"", &name[..name.len().min(100)]));
        let link = &link[..link.len().min(100)];
        let h =
            block(short, prefix, link, typeflag, mode, if size > MAX_OCTAL_11 { 0 } else { size }, self.mtime, device);
        self.w.write_all(&h)?;
        self.written += BLOCK as u64;
        Ok(())
    }

    /// Zeros to the end of the block.
    fn pad(&mut self) -> Result<()> {
        let n = (BLOCK as u64 - self.written % BLOCK as u64) % BLOCK as u64;
        self.w.write_all(&[0u8; BLOCK][..n as usize])?;
        self.written += n;
        Ok(())
    }

    /// The two zero blocks that end the archive, zeros to the end of the record, and the gzip trailer.
    fn finish(mut self) -> Result<()>
    where
        W: Finish,
    {
        self.w.write_all(&[0u8; 2 * BLOCK])?;
        self.written += 2 * BLOCK as u64;
        let n = (RECORD - self.written % RECORD) % RECORD;
        self.w.write_all(&vec![0u8; n as usize])?;
        self.w.end()
    }
}

trait Finish {
    fn end(self) -> Result<()>;
}

impl<W: Write> Finish for flate2::write::GzEncoder<W> {
    fn end(self) -> Result<()> {
        let mut inner = self.finish()?;
        inner.flush()?;
        Ok(())
    }
}

/// A name split into a ustar prefix and name, or `None` when it fits neither way.
fn split_ustar(name: &[u8]) -> Option<(&[u8], &[u8])> {
    if name.len() <= 100 {
        return Some((b"", name));
    }
    // a trailing slash (a directory's) can't be the split
    let body = &name[..name.len() - 1];
    body.iter()
        .enumerate()
        .filter(|&(_, &b)| b == b'/')
        .map(|(i, _)| i)
        .find_map(|i| (i > 0 && i <= 155 && name.len() - i - 1 <= 100).then(|| (&name[..i], &name[i + 1..])))
}

/// One pax record, `"<len> <key>=<value>\n"`, its length counting its own digits.
fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body = key.len() + value.len() + 3; // space, '=', newline
    let mut len = body + 1;
    while len != body + len.to_string().len() {
        len = body + len.to_string().len();
    }
    let mut r = format!("{len} {key}=").into_bytes();
    r.extend_from_slice(value);
    r.push(b'\n');
    r
}

#[allow(clippy::too_many_arguments)]
fn block(
    name: &[u8],
    prefix: &[u8],
    link: &[u8],
    typeflag: u8,
    mode: u32,
    size: u64,
    mtime: u64,
    device: (u64, u64),
) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name);
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], mtime);
    h[148..156].fill(b' ');
    h[156] = typeflag;
    h[157..157 + link.len()].copy_from_slice(link);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    octal(&mut h[329..337], device.0);
    octal(&mut h[337..345], device.1);
    h[345..345 + prefix.len()].copy_from_slice(prefix);
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// A zero-padded octal number filling all but the last byte of `field`, which is NUL.
fn octal(field: &mut [u8], v: u64) {
    let digits = field.len() - 1;
    field[..digits].copy_from_slice(format!("{v:0digits$o}").as_bytes());
    field[digits] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pax_record_lengths_count_themselves() {
        assert_eq!(pax_record("path", b"a"), b"9 path=a\n");
        assert_eq!(pax_record("path", b"abc"), b"12 path=abc\n");
        // 98 bytes of body plus two digits would be 100, which has three
        let v = vec![b'x'; 91];
        let r = pax_record("path", &v);
        assert_eq!(r.len(), 101);
        assert!(r.starts_with(b"101 path="));
    }

    #[test]
    fn long_names_split_at_a_slash() {
        let name = [vec![b'd'; 120], b"/".to_vec(), vec![b'f'; 50]].concat();
        let (prefix, rest) = split_ustar(&name).unwrap();
        assert_eq!(prefix.len(), 120);
        assert_eq!(rest.len(), 50);
        assert!(split_ustar(&[b'x'; 101]).is_none());
        let dir = [vec![b'd'; 101], b"/".to_vec()].concat();
        assert!(split_ustar(&dir).is_none());
    }
}
