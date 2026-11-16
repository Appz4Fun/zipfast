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
