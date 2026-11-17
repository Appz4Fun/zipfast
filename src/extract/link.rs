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

//! Unix symbolic links stored as RAR 4.x members: a Unix-host member whose mode is `S_IFLNK`, its data the link's
//! target. UnRAR creates them on Unix; so does every route here, within the destination only.
//!
//! A target is taken only when it is relative and, read from the link's own folder, stays inside the destination.
//! `..` may only lead the target: the folders it climbs out of are real ones (a member is never written through a
//! link), so where it lands is known before the link exists. Past them the target only descends, through folders or
//! through links that were each checked the same way, so no chain of links leads out either.

use std::io;
use std::path::Path;

/// The longest target taken, in bytes (`PATH_MAX` less its NUL).
pub(crate) const MAX_TARGET: u64 = 4095;

/// Whether a link at `rel`, relative to the destination, may point at `target`.
pub(crate) fn contained(rel: &Path, target: &[u8]) -> bool {
    if target.is_empty() || target.len() as u64 > MAX_TARGET || target.contains(&0) || target[0] == b'/' {
        return false;
    }
    // folders between the destination and the link
    let mut depth = rel.components().count().saturating_sub(1);
    let mut leading = true;
    for part in target.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." if leading => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return false,
            },
            b".." => return false,
            _ => leading = false,
        }
    }
    true
}

/// Creates the link at `path`. With `replace` the file there is replaced in one rename, which never follows a link;
/// without, the link is only created where nothing is.
#[cfg(unix)]
pub(crate) fn create(path: &Path, target: &[u8], replace: bool) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let target = std::ffi::OsStr::from_bytes(target);
    if !replace {
        return std::os::unix::fs::symlink(target, path);
    }
    let parent = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let name = path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..64 {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut stage = std::ffi::OsString::from(".");
        stage.push(name);
        stage.push(format!(".{}-{n}.zipfast-link", std::process::id()));
        let stage = parent.join(stage);
        match std::os::unix::fs::symlink(target, &stage) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        return std::fs::rename(&stage, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&stage);
        });
    }
    Err(io::ErrorKind::AlreadyExists.into())
}

/// Links are created on Unix only.
#[cfg(not(unix))]
pub(crate) fn create(_: &Path, _: &[u8], _: bool) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

/// The message for a link whose target is absolute or leads out of the destination.
pub(crate) const UNSAFE_TARGET: &str = "the link's target is absolute or leads out of the destination";
/// The message for a hard link whose target is not a file this run extracted.
pub(crate) const HARD_TARGET: &str = "the hard link's target is not a file extracted earlier in this run";

/// A link member, for the tar, ZIP and 7z runners.
pub(crate) enum LinkKind {
    /// A symbolic link to these target bytes.
    Symbolic(Vec<u8>),
    /// A hard link to this earlier member, relative to the destination.
    Hard(std::path::PathBuf),
}

/// Where an extracted file landed (a rename mode may have put it elsewhere than its name), and which file it was.
#[derive(Clone)]
struct Landed {
    rel: std::path::PathBuf,
    dev: u64,
    ino: u64,
}

/// The regular files a run has extracted, by member path: the only targets a hard link may take, so it never
/// reaches a file outside the destination or one that was there before the run. Each records where the file landed
/// and its device and inode; a hard link is made only to that same file, reached without following links. A test
/// run records the names only.
#[derive(Default)]
pub(crate) struct Extracted(std::collections::HashMap<std::path::PathBuf, Option<Landed>>);

impl Extracted {
    /// The member at `rel` was written to `landed` (an absolute path under `dest`).
    pub(crate) fn file(&mut self, dest: &Path, rel: &Path, landed: &Path) {
        let record = std::fs::symlink_metadata(landed).ok().filter(|m| m.file_type().is_file()).and_then(|m| {
            let landed = landed.strip_prefix(dest).ok()?.to_path_buf();
            let (dev, ino) = identity(&m);
            Some(Landed { rel: landed, dev, ino })
        });
        match record {
            Some(record) => {
                self.0.insert(rel.to_path_buf(), Some(record));
            }
            None => {
                self.0.remove(rel);
            }
        }
    }

    /// A test run found the member at `rel` whole.
    pub(crate) fn tested(&mut self, rel: &Path) {
        self.0.insert(rel.to_path_buf(), None);
    }

    /// Something other than a file this run wrote is now at `rel`: every record at or below it goes, by member
    /// path or by where it landed.
    pub(crate) fn replaced(&mut self, rel: &Path) {
        self.0.retain(|name, landed| {
            !name.starts_with(rel) && landed.as_ref().is_none_or(|landed| !landed.rel.starts_with(rel))
        });
    }

    pub(crate) fn contains(&self, rel: &Path) -> bool {
        self.0.contains_key(rel)
    }
}

#[cfg(unix)]
fn identity(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}

#[cfg(not(unix))]
fn identity(_: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// Why a link member is refused before anything is written, or None when it may be placed at `rel`.
pub(crate) fn refusal(rel: &Path, kind: &LinkKind, extracted: &Extracted) -> Option<&'static str> {
    match kind {
        LinkKind::Symbolic(target) if !contained(rel, target) => Some(UNSAFE_TARGET),
        LinkKind::Hard(target) if !extracted.contains(target) => Some(HARD_TARGET),
        _ => None,
    }
}

/// Places a checked link member: a symbolic link, or a hard link to the earlier member (a copy where the file
/// system takes no hard link). `place` comes from the run's target check, so the overwrite choice, a rename mode
/// and the refusal to write through a link in the way are already settled.
pub(crate) fn publish(
    dest: &Path,
    rel: &Path,
    place: super::Place,
    kind: &LinkKind,
    extracted: &mut Extracted,
) -> io::Result<()> {
    let (path, replace) = match place.reserved {
        Some(reserved) => (reserved.into_parts().1, true),
        None => (place.path, place.replace),
    };
    match kind {
        LinkKind::Symbolic(target) => {
            create(&path, target, replace)?;
            extracted.replaced(rel);
            if let Ok(landed) = path.strip_prefix(dest) {
                extracted.replaced(landed);
            }
        }
        LinkKind::Hard(target) => {
            let landed = extracted.0.get(target).cloned().flatten().ok_or_else(|| io::Error::other(HARD_TARGET))?;
            hard(dest, &landed, &path, replace)?;
            extracted.file(dest, rel, &path);
        }
    }
    Ok(())
}

static NEXT_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A free name beside `path` for staging.
fn stage_beside(path: &Path) -> io::Result<std::path::PathBuf> {
    let parent = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let name = path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let n = NEXT_STAGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut stage = std::ffi::OsString::from(".");
    stage.push(name);
    stage.push(format!(".{}-{n}.zipfast-hardlink", std::process::id()));
    Ok(parent.join(stage))
}

/// A hard link at `path` to the file the earlier member landed as: reached from `dest` one folder at a time without
/// following any link, and only when it is still that file (device and inode). A copy where linking fails, read
/// through the same checked handle. The stage is created only where nothing is, and so is `path` without `replace`.
fn hard(dest: &Path, landed: &Landed, path: &Path, replace: bool) -> io::Result<()> {
    let stage = stage_beside(path)?;
    stage_hard(dest, landed, &stage)?;
    let placed = if replace {
        std::fs::rename(&stage, path)
    } else {
        std::fs::hard_link(&stage, path).or_else(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Err(e),
            _ => copy_new(&mut std::fs::File::open(&stage)?, path),
        })
    };
    let _ = std::fs::remove_file(&stage);
    placed
}

/// Copies `from` into a new file at `to`, created only where nothing is.
fn copy_new(from: &mut std::fs::File, to: &Path) -> io::Result<()> {
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(to)?;
    if let Err(e) = io::copy(from, &mut out) {
        drop(out);
        let _ = std::fs::remove_file(to);
        return Err(e);
    }
    Ok(())
}

#[cfg(unix)]
fn stage_hard(dest: &Path, landed: &Landed, stage: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let gone = || io::Error::other("the hard link's target is no longer the file extracted earlier");
    let cstr = |b: &[u8]| CString::new(b).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput));
    let open_at = |dir: libc::c_int, name: &CString, flags: libc::c_int| -> io::Result<OwnedFd> {
        // SAFETY: a NUL-terminated name relative to an open directory (or the current directory).
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) }
    };
    let mut dir = open_at(libc::AT_FDCWD, &cstr(dest.as_os_str().as_bytes())?, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let parts: Vec<_> = landed.rel.components().collect();
    let (last, folders) = parts.split_last().ok_or_else(gone)?;
    for part in folders {
        let std::path::Component::Normal(name) = part else { return Err(gone()) };
        let name = cstr(name.as_bytes())?;
        dir = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .map_err(|_| gone())?;
    }
    let std::path::Component::Normal(name) = last else { return Err(gone()) };
    let name = cstr(name.as_bytes())?;
    // st_dev and st_ino differ in width between platforms
    #[allow(clippy::unnecessary_cast)]
    let same = |m: &libc::stat| {
        (m.st_mode & libc::S_IFMT) == libc::S_IFREG && m.st_dev as u64 == landed.dev && m.st_ino as u64 == landed.ino
    };
    // SAFETY: zeroed stat filled in by fstatat on an open directory and a NUL-terminated name.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 || !same(&st) {
        return Err(gone());
    }
    let to = cstr(stage.as_os_str().as_bytes())?;
    // SAFETY: flags 0 never follow a symbolic link at the source name, resolved within the checked directory.
    let linked = unsafe { libc::linkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_FDCWD, to.as_ptr(), 0) } == 0;
    if linked {
        // the name could have been swapped between the check and the link: the staged link must be that file
        match std::fs::symlink_metadata(stage) {
            Ok(m) if identity(&m) == (landed.dev, landed.ino) => return Ok(()),
            _ => {
                let _ = std::fs::remove_file(stage);
                return Err(gone());
            }
        }
    }
    // A copy, read through a handle opened without following a link and checked to be that file.
    let fd = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NOFOLLOW).map_err(|_| gone())?;
    // SAFETY: zeroed stat filled in by fstat on an open descriptor.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 || !same(&st) {
        return Err(gone());
    }
    copy_new(&mut std::fs::File::from(fd), stage)
}

#[cfg(not(unix))]
fn stage_hard(dest: &Path, landed: &Landed, stage: &Path) -> io::Result<()> {
    let source = dest.join(&landed.rel);
    if !std::fs::symlink_metadata(&source)?.file_type().is_file() {
        return Err(io::Error::other("the hard link's target is no longer a file"));
    }
    std::fs::hard_link(&source, stage).or_else(|_| copy_new(&mut std::fs::File::open(&source)?, stage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_targets_inside_the_destination_are_taken() {
        let ok = |rel: &str, target: &str| contained(Path::new(rel), target.as_bytes());
        assert!(ok("link", "emptydir"));
        assert!(ok("emptydir/link", "link"));
        assert!(ok("a/b/link", "../../c/./d/"));
        assert!(ok("a/link", ".."));
        assert!(!ok("link", ".."));
        assert!(!ok("a/link", "../.."));
        assert!(!ok("link", "/etc/passwd"));
        assert!(!ok("a/b/link", "c/../d"));
        assert!(!ok("a/link", "b/../../x"));
        assert!(!ok("link", ""));
        assert!(!ok("link", "a\0b"));
        assert!(!ok("link", &"a".repeat(4096)));
    }
}
