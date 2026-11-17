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

//! ar archives, read in the common, GNU and BSD layouts and written again as GNU `ar D` writes them.
//!
//! An archive is `!<arch>\n` and then members, each a 60-byte header (name 16, time 12, owner 6, group 6, octal
//! mode 8, decimal size 10, and the two bytes `` `\n ``) followed by its data padded to an even length with `\n`.
//! GNU ends a short name with `/`, keeps longer names in a `//` member and refers to them as `/<offset>`, and keeps
//! its symbol table in a `/` (or `/SYM64/`) member. BSD writes a long name as `#1/<length>` with the name at the
//! start of the data, and keeps its symbol table in `__.SYMDEF` (or `__.SYMDEF SORTED`, `__.SYMDEF_64`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::{
    Budget, RepackFormat, RepackOptions, RepackSummary, copy_exact, lossy, nested_name, open_input, repack_nested,
};
use crate::error::{Error, Result};
use crate::extract::ListingBudget;

pub(super) const MAGIC: &[u8; 8] = b"!<arch>\n";
pub(super) const THIN: &[u8; 8] = b"!<thin>\n";
const HEADER: u64 = 60;
/// The most bytes a symbol or long-name table may take: both are held in memory.
const MAX_TABLE: u64 = 64 << 20;
/// The longest BSD `#1/` name.
const MAX_BSD_NAME: u64 = 4096;
/// The largest size a header's 10 decimal digits hold.
const MAX_SIZE: u64 = 9_999_999_999;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    /// names of up to 16 bytes, no slash
    Plain,
    Gnu,
    Bsd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymKind {
    Gnu32,
    Gnu64,
    Bsd32,
    Bsd64,
}

struct Symtab {
    kind: SymKind,
    /// a BSD table's own name, written again as it was
    name: Vec<u8>,
    /// a BSD table's byte order
    big: bool,
    /// each distinct symbol name once
    names: Vec<Vec<u8>>,
    /// (index into `names`, member header offset in the input)
    entries: Vec<(usize, u64)>,
}

enum Data {
    /// in the input, at this offset
    Input(u64),
    /// a repacked nested tarball
    Temp(File),
}

struct Member {
    name: Vec<u8>,
    /// where its header was in the input, which a symbol table points at
    header_at: u64,
    size: u64,
    data: Data,
}

/// Repacks the ar archive at `input` into `out`, charging what it reads to `budget` and keeping its temporaries in
/// `scratch`.
pub(super) fn repack(
    input: &Path,
    out: &mut dyn Write,
    opts: &RepackOptions,
    budget: &mut Budget,
    scratch: &Path,
) -> Result<RepackSummary> {
    let mut file = open_input(input)?;
    let len = file.metadata()?.len();
    let mut magic = [0u8; 8];
    if crate::tar::read_full(&mut file, &mut magic)? < 8 || magic != *MAGIC {
        if magic == *THIN {
            return Err(Error::Unsupported("a thin ar archive names files outside itself".into()));
        }
        return Err(Error::NotAnArchive);
    }

    let mut members: Vec<Member> = Vec::new();
    let mut symtab: Option<Symtab> = None;
    let mut long_names: Option<Vec<u8>> = None;
    let (mut gnu, mut bsd) = (false, false);
    let mut listing = ListingBudget::default();
    let mut nested = 0u64;
    let mut pos = 8u64;
    while pos < len {
        file.seek(SeekFrom::Start(pos))?;
        if len - pos < HEADER {
            // some writers leave a stray newline at the end
            let mut rest = Vec::new();
            file.read_to_end(&mut rest)?;
            if rest.iter().all(|&b| b == b'\n') {
                break;
            }
            return Err(Error::Truncated);
        }
        let mut h = [0u8; HEADER as usize];
        file.read_exact(&mut h)?;
        if &h[58..60] != b"`\n" {
            return Err(Error::Corrupt("an ar member header is damaged"));
        }
        let stored_size = decimal(&h[48..58]).ok_or(Error::Corrupt("an ar member's size is unreadable"))?;
        let header_at = pos;
        let mut data_at = pos + HEADER;
        if stored_size > len - data_at {
            return Err(Error::Truncated);
        }
        pos = data_at + stored_size + (stored_size & 1);
        let mut size = stored_size;
        let field = trim_spaces(&h[..16]);
        let read_table = |file: &mut File, at: u64, size: u64| -> Result<Vec<u8>> {
            if size > MAX_TABLE {
                return Err(Error::Unsupported("an ar symbol or name table is too large".into()));
            }
            let mut data = vec![0u8; size as usize];
            file.seek(SeekFrom::Start(at))?;
            file.read_exact(&mut data)?;
            Ok(data)
        };
        let mut set_symtab = |kind, name: &[u8], data: Vec<u8>| {
            if symtab.is_some() {
                return Err(Error::Corrupt("an ar archive has two symbol tables"));
            }
            symtab = Some(parse_symtab(kind, name, &data)?);
            Ok(())
        };
        let name = if field == b"/" || field == b"/SYM64/" {
            gnu = true;
            budget.take(size)?;
            let kind = if field == b"/" { SymKind::Gnu32 } else { SymKind::Gnu64 };
            set_symtab(kind, b"", read_table(&mut file, data_at, size)?)?;
            continue;
        } else if field == b"//" {
            gnu = true;
            if long_names.is_some() {
                return Err(Error::Corrupt("an ar archive has two long-name tables"));
            }
            budget.take(size)?;
            long_names = Some(read_table(&mut file, data_at, size)?);
            continue;
        } else if let Some(offset) = field.strip_prefix(b"/").and_then(decimal) {
            gnu = true;
            let table = long_names.as_deref().ok_or(Error::Corrupt("an ar long name comes before its table"))?;
            let rest = usize::try_from(offset).ok().and_then(|o| table.get(o..));
            let rest = rest.ok_or(Error::Corrupt("an ar long name points past its table"))?;
            let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
            let name = &rest[..end];
            name.strip_suffix(b"/").unwrap_or(name).to_vec()
        } else if let Some(n) = field.strip_prefix(b"#1/").and_then(decimal) {
            bsd = true;
            if n > size || n > MAX_BSD_NAME {
                return Err(Error::Corrupt("an ar BSD name is longer than its member"));
            }
            let mut raw = vec![0u8; n as usize];
            file.read_exact(&mut raw)?;
            while raw.last() == Some(&0) {
                raw.pop();
            }
            data_at += n;
            size -= n;
            raw
        } else if let Some(name) = field.strip_suffix(b"/") {
            gnu = true;
            name.to_vec()
        } else {
            field.to_vec()
        };
        if name.starts_with(b"__.SYMDEF") {
            bsd = true;
            budget.take(size)?;
            let kind = if name.starts_with(b"__.SYMDEF_64") { SymKind::Bsd64 } else { SymKind::Bsd32 };
            set_symtab(kind, &name, read_table(&mut file, data_at, size)?)?;
            continue;
        }
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
            || name.contains(&b'\n')
        {
            return Err(Error::UnsafePath(lossy(&name)));
        }
        listing.record(&lossy(&name))?;
        budget.take(size)?;
        let mut member = Member { name, header_at, size, data: Data::Input(data_at) };
        if opts.nested && nested_name(&member.name) {
            let mut whole = tempfile::tempfile_in(scratch)?;
            file.seek(SeekFrom::Start(data_at))?;
            copy_exact(&mut file, &mut whole, size)?;
            if let Some((repacked, len)) = repack_nested(&mut whole, opts, budget, scratch)? {
                member.data = Data::Temp(repacked);
                member.size = len;
                nested += 1;
            }
        }
        members.push(member);
    }

    let mut flavor = if bsd {
        Flavor::Bsd
    } else if gnu {
        Flavor::Gnu
    } else {
        Flavor::Plain
    };
    if flavor == Flavor::Plain && members.iter().any(|m| m.name.len() > 16 || m.name.contains(&b' ')) {
        flavor = Flavor::Gnu;
    }

    // dpkg reads `debian-binary` first; everything else in name order
    let keep_first = members.first().is_some_and(|m| m.name == b"debian-binary");
    members[usize::from(keep_first)..].sort_by(|a, b| a.name.cmp(&b.name));

    // GNU long names, in member order
    let mut table = Vec::new();
    let mut gnu_fields: Vec<Vec<u8>> = Vec::with_capacity(members.len());
    if flavor != Flavor::Bsd {
        for m in &members {
            gnu_fields.push(match flavor {
                Flavor::Gnu if m.name.len() > 15 => {
                    let field = format!("/{}", table.len()).into_bytes();
                    table.extend_from_slice(&m.name);
                    table.extend_from_slice(b"/\n");
                    field
                }
                Flavor::Gnu => [m.name.as_slice(), b"/"].concat(),
                _ => m.name.clone(),
            });
        }
    }

    // Where each member's header lands, so the symbol table can point at it. BSD names every member `#1/<n>`
    // with its name NUL-padded so that its data starts 8-aligned, as Apple's linker requires and Apple's ar does.
    let padded = |n: u64| n + (n & 1);
    let mut at = 8u64;
    let symtab_name = symtab.as_ref().map(|s| match s.kind {
        SymKind::Gnu32 => (b"/".to_vec(), Vec::new()),
        SymKind::Gnu64 => (b"/SYM64/".to_vec(), Vec::new()),
        SymKind::Bsd32 | SymKind::Bsd64 => bsd_name(at, &s.name),
    });
    if let (Some(s), Some((_, extra))) = (&symtab, &symtab_name) {
        at += HEADER + padded(extra.len() as u64 + s.rebuilt_len());
    }
    if !table.is_empty() {
        at += HEADER + padded(table.len() as u64);
    }
    let mut moved = HashMap::with_capacity(members.len());
    let mut names: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(members.len());
    for (i, m) in members.iter().enumerate() {
        moved.insert(m.header_at, at);
        let name = match flavor {
            Flavor::Bsd => bsd_name(at, &m.name),
            _ => (std::mem::take(&mut gnu_fields[i]), Vec::new()),
        };
        at += HEADER + padded(name.1.len() as u64 + m.size);
        names.push(name);
    }

    out.write_all(MAGIC)?;
    if let (Some(s), Some((field, extra))) = (&symtab, &symtab_name) {
        let data = s.rebuild(&moved)?;
        let size = extra.len() as u64 + data.len() as u64;
        let mode: &[u8] = if matches!(s.kind, SymKind::Gnu32 | SymKind::Gnu64) { b"0" } else { b"644" };
        out.write_all(&header(field, Some(opts.mtime), mode, size)?)?;
        out.write_all(extra)?;
        out.write_all(&data)?;
        pad(out, size)?;
    }
    if !table.is_empty() {
        out.write_all(&header(b"//", None, b"", table.len() as u64)?)?;
        out.write_all(&table)?;
        pad(out, table.len() as u64)?;
    }
    for (m, (field, extra)) in members.iter_mut().zip(&names) {
        let size = extra.len() as u64 + m.size;
        out.write_all(&header(field, Some(opts.mtime), b"644", size)?)?;
        out.write_all(extra)?;
        match &mut m.data {
            Data::Input(offset) => {
                file.seek(SeekFrom::Start(*offset))?;
                copy_exact(&mut file, out, m.size)?;
            }
            Data::Temp(temp) => {
                temp.seek(SeekFrom::Start(0))?;
                copy_exact(temp, out, m.size)?;
            }
        }
        pad(out, size)?;
    }
    Ok(RepackSummary { format: RepackFormat::Ar, members: members.len() as u64, nested })
}

/// A BSD `#1/<n>` header name for a member whose header is at `at`, and the name bytes before its data, padded
/// with NULs so that the data starts 8-aligned.
fn bsd_name(at: u64, name: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut bytes = name.to_vec();
    while !(at + HEADER + bytes.len() as u64).is_multiple_of(8) {
        bytes.push(0);
    }
    (format!("#1/{}", bytes.len()).into_bytes(), bytes)
}

/// Reads a symbol table's (symbol, member header offset) pairs. Each distinct name is copied once, and the bytes
/// copied are held to [`MAX_TABLE`]: a BSD table may point every entry at the same long name, or at every byte of
/// one, and copying per entry would take the table's size squared.
fn parse_symtab(kind: SymKind, name: &[u8], data: &[u8]) -> Result<Symtab> {
    let bad = || Error::Corrupt("an ar symbol table is damaged");
    let width = kind.width();
    let get = |at: usize, big: bool| -> Option<u64> {
        let b = data.get(at..at.checked_add(width)?)?;
        Some(b.iter().enumerate().fold(0u64, |v, (i, &x)| {
            let shift = if big { 8 * (width - 1 - i) } else { 8 * i };
            v | (u64::from(x) << shift)
        }))
    };
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut interned: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut copied = 0u64;
    // the name starting at `at` in `strings`, as an index into `names`
    let mut symbol = |strings: &[u8], at: u64| -> Result<usize> {
        let rest = usize::try_from(at).ok().and_then(|at| strings.get(at..)).ok_or_else(bad)?;
        let end = rest.iter().position(|&b| b == 0).ok_or_else(bad)?;
        copied += end as u64 + 1;
        if copied > MAX_TABLE {
            return Err(Error::Unsupported("an ar symbol table's names are too large".into()));
        }
        let name = &rest[..end];
        if let Some(&i) = interned.get(name) {
            return Ok(i);
        }
        names.push(name.to_vec());
        interned.insert(name.to_vec(), names.len() - 1);
        Ok(names.len() - 1)
    };
    let mut entries = Vec::new();
    let big = match kind {
        // GNU: a big-endian count, then that many member offsets, then as many NUL-ended names, one after another
        SymKind::Gnu32 | SymKind::Gnu64 => {
            let n = get(0, true).ok_or_else(bad)?;
            if n > (data.len() / width) as u64 {
                return Err(bad());
            }
            let n = n as usize;
            let strings = data.get((n + 1) * width..).ok_or_else(bad)?;
            let mut at = 0u64;
            for i in 0..n {
                let offset = get((i + 1) * width, true).ok_or_else(bad)?;
                let index = symbol(strings, at)?;
                entries.push((index, offset));
                at += strings[at as usize..].iter().position(|&b| b == 0).ok_or_else(bad)? as u64 + 1;
            }
            true
        }
        // BSD: the byte length of an array of (name offset, member offset) pairs, the length of the names, then the
        // names, all in the writer's byte order
        SymKind::Bsd32 | SymKind::Bsd64 => {
            let pair = 2 * width as u64;
            let fits = |big: bool| {
                let bytes = get(0, big)?;
                let strsize = get(usize::try_from(bytes.checked_add(width as u64)?).ok()?, big)?;
                let end = (width as u64).checked_mul(2)?.checked_add(bytes)?.checked_add(strsize)?;
                (bytes % pair == 0 && end <= data.len() as u64).then_some((bytes / pair, strsize))
            };
            let (big, (n, strsize)) = match (fits(false), fits(true)) {
                (Some(f), _) => (false, f),
                (None, Some(f)) => (true, f),
                (None, None) => return Err(bad()),
            };
            let strings_at = width + (n as usize) * 2 * width + width;
            let strings = &data[strings_at..strings_at + strsize as usize];
            // entries sharing a name offset share its resolution
            let mut resolved: HashMap<u64, usize> = HashMap::new();
            for i in 0..n as usize {
                let at = width + i * 2 * width;
                let strx = get(at, big).ok_or_else(bad)?;
                let offset = get(at + width, big).ok_or_else(bad)?;
                let index = match resolved.get(&strx) {
                    Some(&index) => index,
                    None => {
                        let index = symbol(strings, strx)?;
                        resolved.insert(strx, index);
                        index
                    }
                };
                entries.push((index, offset));
            }
            big
        }
    };
    Ok(Symtab { kind, name: name.to_vec(), big, names, entries })
}

impl SymKind {
    fn width(self) -> usize {
        if matches!(self, SymKind::Gnu64 | SymKind::Bsd64) { 8 } else { 4 }
    }
}

impl Symtab {
    /// The names a rebuilt table holds: one per entry for GNU (at most the input's own names, which lie one after
    /// another), each distinct name once for BSD, NULs included.
    fn names_len(&self) -> u64 {
        match self.kind {
            SymKind::Gnu32 | SymKind::Gnu64 => self.entries.iter().map(|&(n, _)| self.names[n].len() as u64 + 1).sum(),
            SymKind::Bsd32 | SymKind::Bsd64 => self.names.iter().map(|n| n.len() as u64 + 1).sum(),
        }
    }

    /// The length of the table [`Symtab::rebuild`] writes, which does not depend on where members land.
    fn rebuilt_len(&self) -> u64 {
        let w = self.kind.width() as u64;
        let n = self.entries.len() as u64;
        match self.kind {
            SymKind::Gnu32 | SymKind::Gnu64 => w * (n + 1) + self.names_len(),
            SymKind::Bsd32 | SymKind::Bsd64 => w + 2 * w * n + w + self.names_len().next_multiple_of(8),
        }
    }

    /// The table written afresh with every member offset moved to where that member's header now is, its entries
    /// in a fixed order (GNU by member then name, BSD by name then member) whatever order the input had. A BSD
    /// table holds each distinct name once, in name order.
    fn rebuild(&self, moved: &HashMap<u64, u64>) -> Result<Vec<u8>> {
        let width = self.kind.width();
        let mut entries = Vec::with_capacity(self.entries.len());
        for &(name, old) in &self.entries {
            let new = moved.get(&old).copied().ok_or(Error::Corrupt("an ar symbol table points at no member"))?;
            if width == 4 && new > u64::from(u32::MAX) {
                return Err(Error::Unsupported("an ar archive too large for its 32-bit symbol table".into()));
            }
            entries.push((self.names[name].as_slice(), new, name));
        }
        let big = self.big;
        let mut out = Vec::with_capacity(self.rebuilt_len() as usize);
        let put = |out: &mut Vec<u8>, v: u64| {
            let bytes = v.to_be_bytes();
            let mut b = bytes[8 - width..].to_vec();
            if !big {
                b.reverse();
            }
            out.extend_from_slice(&b);
        };
        match self.kind {
            SymKind::Gnu32 | SymKind::Gnu64 => {
                entries.sort_by(|a, b| (a.1, a.0).cmp(&(b.1, b.0)));
                put(&mut out, entries.len() as u64);
                for &(_, offset, _) in &entries {
                    put(&mut out, offset);
                }
                for &(name, _, _) in &entries {
                    out.extend_from_slice(name);
                    out.push(0);
                }
            }
            SymKind::Bsd32 | SymKind::Bsd64 => {
                entries.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
                let mut order: Vec<usize> = (0..self.names.len()).collect();
                order.sort_by(|&a, &b| self.names[a].cmp(&self.names[b]));
                let mut strx = vec![0u64; self.names.len()];
                let mut at = 0u64;
                for &i in &order {
                    strx[i] = at;
                    at += self.names[i].len() as u64 + 1;
                }
                put(&mut out, (2 * width * entries.len()) as u64);
                for &(_, offset, name) in &entries {
                    put(&mut out, strx[name]);
                    put(&mut out, offset);
                }
                let strsize = self.names_len().next_multiple_of(8);
                put(&mut out, strsize);
                let start = out.len();
                for &i in &order {
                    out.extend_from_slice(&self.names[i]);
                    out.push(0);
                }
                out.resize(start + strsize as usize, 0);
            }
        }
        Ok(out)
    }
}

/// A 60-byte member header: `name` space-padded, the time (blank for `None`), owner and group 0 (blank with the
/// time), `mode`, and `size`.
fn header(name: &[u8], mtime: Option<u64>, mode: &[u8], size: u64) -> Result<[u8; HEADER as usize]> {
    if size > MAX_SIZE {
        return Err(Error::Unsupported("an ar member too large for its header".into()));
    }
    let mut h = [b' '; HEADER as usize];
    h[..name.len()].copy_from_slice(name);
    if let Some(mtime) = mtime {
        let t = mtime.to_string();
        h[16..16 + t.len()].copy_from_slice(t.as_bytes());
        h[28] = b'0';
        h[34] = b'0';
    }
    h[40..40 + mode.len()].copy_from_slice(mode);
    let s = size.to_string();
    h[48..48 + s.len()].copy_from_slice(s.as_bytes());
    h[58..60].copy_from_slice(b"`\n");
    Ok(h)
}

fn pad(out: &mut dyn Write, size: u64) -> Result<()> {
    if size & 1 == 1 {
        out.write_all(b"\n")?;
    }
    Ok(())
}

fn trim_spaces(field: &[u8]) -> &[u8] {
    let end = field.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    &field[..end]
}

/// A decimal field: digits, then spaces.
fn decimal(field: &[u8]) -> Option<u64> {
    let digits = trim_spaces(field);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}
