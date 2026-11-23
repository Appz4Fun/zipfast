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

//! Deterministic repacking of ar archives (`.a`, a `.deb`'s or `.ipk`'s outer layer) and tarballs, the way
//! reproducible-builds tools make them: the same members with the same contents always give the same bytes,
//! whatever times, owners and order the input carried.
//!
//! * **ar** is written as GNU `ar D` writes it: every member's time is [`RepackOptions::mtime`] (0 by default),
//!   its owner and group 0 and its mode `644`. Members are sorted by name, except that a `.deb`'s leading
//!   `debian-binary` stays first, as dpkg requires. A symbol table (GNU `/` or `/SYM64/`, BSD `__.SYMDEF`,
//!   `__.SYMDEF SORTED`, `__.SYMDEF_64` or `__.SYMDEF_64 SORTED`) stays first and its member offsets are rewritten
//!   for the new order. The input's naming style (plain, GNU, BSD) is kept.
//! * **tar** (plain, or compressed in any way the tar reader reads, cpio included) is written as
//!   `tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@N --format=posix` would, then gzipped: POSIX
//!   ustar headers with pax records only where a name, link or size does not fit, sorted by the name's bytes,
//!   owner and group 0 with no names, every time `N`, and modes normalised to `755` for directories and for files
//!   with any execute bit, `644` for other files and devices and `777` for symlinks. Hard links are kept, the
//!   first member of each linked set in the new order carrying the data. Times other than the modification time
//!   (pax `atime`, `ctime`) and every other pax record are dropped.
//! * **gzip** is written with MTIME 0, no stored name, OS 3 (Unix, as `gzip -n` on Unix writes) and a fixed
//!   deflate level ([`RepackOptions::level`], 9 by default).
//!
//! The output is the same for the same zipfast build; another build may compress differently.
//!
//! The input is hostile: names that are absolute or climb with `..` are refused, a hard link must name an earlier
//! member, the tar reader's limits apply (decoded bytes, entry count, name bytes, sparse bombs), and nothing is
//! read through or written to a link on disk. Symlink members are kept as data and never followed, and a tar member
//! whose path passes through a symlink member is refused, as is a tar file or link name given twice (a folder given
//! twice is written once). The output and every temporary are made beside the target, and the output is renamed
//! over it, refusing a symlink in its place.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::output::{replace, temporary};

mod ar;
mod tarball;

/// How a repack writes its output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepackOptions {
    /// Seconds since 1970 given to every member, as `SOURCE_DATE_EPOCH` or `--mtime=@N` gives it. At most
    /// 8589934591 (the largest an 11-digit octal tar field holds).
    pub mtime: u64,
    /// Deflate level for the gzip layer, 0 to 9.
    pub level: u32,
    /// Also repack the `.tar.gz` and `.tgz` files inside the archive (a `.deb`'s or `.ipk`'s `control.tar.gz` and
    /// `data.tar.gz`), one level deep. A member with such a name that is not a tarball is kept as it is.
    pub nested: bool,
    /// The most bytes read from the archive's members, holes and nested tarballs included, and the most decoded
    /// from a compressed tar stream.
    pub limit: u64,
}

impl Default for RepackOptions {
    fn default() -> Self {
        RepackOptions { mtime: 0, level: 9, nested: false, limit: 8 << 30 }
    }
}

/// The layout repacked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepackFormat {
    /// an ar archive, written as ar
    Ar,
    /// a tar or cpio archive, written as a gzipped POSIX tar
    TarGz,
}

/// What a repack wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepackSummary {
    pub format: RepackFormat,
    /// Members written, symbol and name tables not counted.
    pub members: u64,
    /// Members that were themselves tarballs and were repacked ([`RepackOptions::nested`]).
    pub nested: u64,
}

/// The largest time a tar header holds in octal.
const MAX_MTIME: u64 = 0o77777777777;

/// Repacks `input` to `output`: an ar archive as ar, anything the tar reader reads as a gzipped tar.
pub fn repack(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackSummary> {
    if is_ar(input)? { repack_ar(input, output, opts) } else { repack_tar_gz(input, output, opts) }
}

/// Repacks an ar archive.
pub fn repack_ar(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackSummary> {
    check(opts)?;
    staged(output, |out, scratch| ar::repack(input, out, opts, &mut Budget { left: opts.limit }, scratch))
}

/// Repacks a tar archive (plain, compressed, or cpio) as a gzipped tar.
pub fn repack_tar_gz(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackSummary> {
    check(opts)?;
    staged(output, |out, scratch| tarball::repack(input, out, opts, &mut Budget { left: opts.limit }, scratch))
}

fn check(opts: &RepackOptions) -> Result<()> {
    if opts.mtime > MAX_MTIME {
        return Err(Error::Unsupported(format!("repack time {} is past {MAX_MTIME}", opts.mtime)));
    }
    if opts.level > 9 {
        return Err(Error::Unsupported(format!("deflate level {} is not 0 to 9", opts.level)));
    }
    Ok(())
}

fn is_ar(path: &Path) -> Result<bool> {
    let mut head = [0u8; 8];
    let mut file = open_input(path)?;
    let n = crate::tar::read_full(&mut file, &mut head)?;
    Ok(n == 8 && (head == *ar::MAGIC || head == *ar::THIN))
}

/// Opens an input archive without following a symlink at its path, refusing anything but a regular file (a FIFO
/// would hang, a device would never end).
fn open_input(path: &Path) -> Result<File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::Unsupported(format!("{} is a symlink, which a repack does not follow", path.display())));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Unsupported(format!("{} is not a regular file", path.display())));
    }
    Ok(file)
}

/// Writes through a temporary beside `output`, then renames it over `output`, refusing a symlink there. `write`
/// also gets the output's folder, where every other temporary goes.
fn staged(
    output: &Path,
    write: impl FnOnce(&mut BufWriter<File>, &Path) -> Result<RepackSummary>,
) -> Result<RepackSummary> {
    let parent = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let temp = temporary(parent)?;
    let (file, path) = temp.into_parts();
    let mut out = BufWriter::with_capacity(1 << 20, file);
    let summary = write(&mut out, parent)?;
    let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    file.sync_all()?;
    drop(file);
    replace(path, output)?;
    Ok(summary)
}

/// Bytes counted against [`RepackOptions::limit`]: every member byte read (holes included), every byte a
/// compressed tar stream decodes to, symbol and name tables, and all of that again inside nested tarballs.
struct Budget {
    left: u64,
}

impl Budget {
    fn take(&mut self, n: u64) -> Result<()> {
        self.left = self
            .left
            .checked_sub(n)
            .ok_or_else(|| Error::Unsupported("archive exceeds the repack byte limit".into()))?;
        Ok(())
    }
}

/// Whether a member named so is a tarball to repack when [`RepackOptions::nested`] is set.
fn nested_name(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(b".tar.gz") || lower.ends_with(b".tgz")
}

/// Repacks the tarball in `data` (a file read from its start), returning the repacked bytes in a new temporary
/// file in `scratch`, or `None` when it is not a tarball. Nested tarballs are not opened again. Whatever the inner
/// repack reads and decodes is charged to `budget`, then the repacked bytes as well.
fn repack_nested(
    data: &mut File,
    opts: &RepackOptions,
    budget: &mut Budget,
    scratch: &Path,
) -> Result<Option<(File, u64)>> {
    let mut inner = temporary(scratch)?;
    data.seek(SeekFrom::Start(0))?;
    io::copy(data, inner.as_file_mut())?;
    inner.as_file_mut().flush()?;
    let inner_opts = RepackOptions { nested: false, ..opts.clone() };
    let mut out = BufWriter::new(tempfile::tempfile_in(scratch)?);
    match tarball::repack(inner.path(), &mut out, &inner_opts, budget, scratch) {
        Ok(_) => {}
        Err(Error::NotAnArchive) => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    let len = file.stream_position()?;
    budget.take(len)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(Some((file, len)))
}

/// Copies exactly `len` bytes from `from` to `to`; fewer is a truncated archive.
fn copy_exact(from: &mut (impl Read + ?Sized), to: &mut (impl Write + ?Sized), len: u64) -> Result<()> {
    let copied = io::copy(&mut (&mut *from).take(len), to)?;
    if copied != len {
        return Err(Error::Truncated);
    }
    Ok(())
}

/// A member name that climbs out of where it is extracted (absolute, or with a `..` part) or holds a NUL.
fn unsafe_name(name: &[u8]) -> bool {
    name.is_empty() || name[0] == b'/' || name.contains(&0) || name.split(|&b| b == b'/').any(|part| part == b"..")
}

fn lossy(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}
