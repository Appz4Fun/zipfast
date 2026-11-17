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

/// The regular files a run has extracted, relative to the destination: the only targets a hard link may take, so
/// it never reaches a file outside the destination or one that was there before the run.
#[derive(Default)]
pub(crate) struct Extracted(std::collections::HashSet<std::path::PathBuf>);

impl Extracted {
    pub(crate) fn file(&mut self, rel: &Path) {
        self.0.insert(rel.to_path_buf());
    }

    /// Something other than a file this run wrote is now at `rel`.
    pub(crate) fn replaced(&mut self, rel: &Path) {
        self.0.remove(rel);
    }

    pub(crate) fn contains(&self, rel: &Path) -> bool {
        self.0.contains(rel)
    }
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
        }
        LinkKind::Hard(target) => {
            hard(&dest.join(target), &path, replace)?;
            extracted.file(rel);
        }
    }
    Ok(())
}

/// A hard link at `path` to the file `source`, never following a link at `source`; a copy where linking fails.
fn hard(source: &Path, path: &Path, replace: bool) -> io::Result<()> {
    if !std::fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(io::Error::other("the hard link's target is no longer a file"));
    }
    let parent = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let name = path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut stage = std::ffi::OsString::from(".");
    stage.push(name);
    stage.push(format!(".{}-{n}.zipfast-hardlink", std::process::id()));
    let stage = parent.join(stage);
    if link_no_follow(source, &stage).is_err() {
        // a copy, made without following a link at either end
        let mut from = std::fs::File::open(source)?;
        let mut to = std::fs::OpenOptions::new().write(true).create_new(true).open(&stage)?;
        if let Err(e) = io::copy(&mut from, &mut to) {
            let _ = std::fs::remove_file(&stage);
            return Err(e);
        }
    }
    let placed = if replace {
        std::fs::rename(&stage, path)
    } else {
        // only where nothing is: a hard link of the staged name, then the stage goes
        std::fs::hard_link(&stage, path).or_else(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Err(e),
            _ => std::fs::copy(&stage, path).map(|_| ()),
        })
    };
    let _ = std::fs::remove_file(&stage);
    placed
}

#[cfg(unix)]
fn link_no_follow(source: &Path, path: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: both are NUL-terminated paths; flags 0 never follow a symbolic link at `from`.
    let r = unsafe { libc::linkat(libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to.as_ptr(), 0) };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(not(unix))]
fn link_no_follow(source: &Path, path: &Path) -> io::Result<()> {
    std::fs::hard_link(source, path)
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
