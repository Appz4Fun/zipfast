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

//! Rename-on-conflict output names: 7-Zip's `-aou` and `-aot`, UnRAR's `-or`.
//!
//! A free name is never looked for and then taken: every candidate is claimed with a create-new or no-replace
//! primitive (`O_CREAT | O_EXCL`, `renameat2(RENAME_NOREPLACE)`, `renameatx_np(RENAME_EXCL)`, or a hard link), and
//! the next number is tried only when that primitive reports the name taken.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// How a renamed output name is spelled. See [`renamed_name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RenameStyle {
    /// `stem_N.ext`, as 7-Zip's `-aou` and `-aot` write it. A name whose only dot is its first character has no
    /// extension: `.bashrc` becomes `.bashrc_1`.
    Underscore,
    /// `stem(N).ext`, as UnRAR's `-or` writes it. UnRAR takes everything from the last dot of the name as its
    /// extension, a leading dot included: `.bashrc` becomes `(1).bashrc`.
    Parenthesized,
}

/// The highest number tried for a renamed name. When `N = 1 ..= RENAME_LIMIT` are all taken, the member fails with a
/// typed error: [`crate::error::RarPolicyReason::RenameExhausted`] for RAR, tar and the legacy ZIP runner, and
/// [`crate::zip::ReadFault::CheckedFormat`] for checked ZIP runs, which stop there as on any publication failure.
/// Each attempt in a checked ZIP run is charged to its I/O budget, which may end the search sooner.
pub const RENAME_LIMIT: u32 = 10_000;

/// A member written under another name, or whose existing target was moved aside, by [`super::Overwrite::RenameNew`]
/// or [`super::Overwrite::RenameExisting`].
///
/// A record is made only when a rename happened: a member written at its own name has none. Paths are the
/// destination joined with the member's relative output path, as the run spells them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RenamedOutput {
    /// Where the member would have been written without a conflict.
    pub requested: PathBuf,
    /// Where the member's data went: the renamed path for `RenameNew`, `requested` for `RenameExisting`.
    pub path: PathBuf,
    /// For `RenameExisting`, where the file that stood at `requested` was moved. It stays there even when writing
    /// the member then fails; the member's own outcome says whether its data arrived at `path`.
    pub existing: Option<PathBuf>,
}

/// What an [`super::Overwrite`] asks for when the target exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenameMode {
    New(RenameStyle),
    Existing(RenameStyle),
}

impl RenameMode {
    pub(crate) fn style(self) -> RenameStyle {
        match self {
            Self::New(style) | Self::Existing(style) => style,
        }
    }
}

/// The `n`th renamed spelling of the file name `name`, as `style` writes it.
///
/// The name is split at its last dot into a stem and an extension, which keeps its dot; the number goes between
/// them. A name without a dot is all stem. For [`RenameStyle::Underscore`] a dot that is the first character does not
/// start an extension, as in 7-Zip; for [`RenameStyle::Parenthesized`] it does, as in UnRAR. A trailing dot is an
/// empty extension, so `a.` becomes `a_1.` or `a(1).`.
///
/// ```
/// use std::ffi::OsStr;
/// use zipfast::extract::{RenameStyle, renamed_name};
///
/// assert_eq!(renamed_name(OsStr::new("a.txt"), 1, RenameStyle::Underscore), "a_1.txt");
/// assert_eq!(renamed_name(OsStr::new("b.tar.gz"), 2, RenameStyle::Underscore), "b.tar_2.gz");
/// assert_eq!(renamed_name(OsStr::new("noext"), 1, RenameStyle::Parenthesized), "noext(1)");
/// assert_eq!(renamed_name(OsStr::new(".bashrc"), 1, RenameStyle::Underscore), ".bashrc_1");
/// assert_eq!(renamed_name(OsStr::new(".bashrc"), 1, RenameStyle::Parenthesized), "(1).bashrc");
/// ```
pub fn renamed_name(name: &OsStr, n: u32, style: RenameStyle) -> OsString {
    let bytes = name.as_encoded_bytes();
    let split = match (bytes.iter().rposition(|&b| b == b'.'), style) {
        (Some(0), RenameStyle::Underscore) | (None, _) => bytes.len(),
        (Some(dot), _) => dot,
    };
    let (stem, extension) = bytes.split_at(split);
    let number = match style {
        RenameStyle::Underscore => format!("_{n}"),
        RenameStyle::Parenthesized => format!("({n})"),
    };
    let mut out = Vec::with_capacity(bytes.len() + number.len());
    out.extend_from_slice(stem);
    out.extend_from_slice(number.as_bytes());
    out.extend_from_slice(extension);
    // SAFETY: `stem` and `extension` split a valid encoded OsStr at an ASCII byte, and the inserted bytes are ASCII,
    // so the result is valid encoded OsStr bytes.
    unsafe { OsString::from_encoded_bytes_unchecked(out) }
}

/// Why no renamed name could be claimed.
#[derive(Debug)]
pub(crate) enum RenameError {
    /// Every candidate up to [`RENAME_LIMIT`] was taken.
    Exhausted,
    Io(PathBuf, io::Error),
}

/// Every candidate path for `target`, in order.
pub(crate) fn candidates(target: &Path, style: RenameStyle) -> impl Iterator<Item = PathBuf> + '_ {
    let name = target.file_name().unwrap_or_default();
    (1..=RENAME_LIMIT).map(move |n| target.with_file_name(renamed_name(name, n, style)))
}

/// Claims the first free renamed name for `target` with a no-replace primitive. `claim` tries one name and reports
/// `AlreadyExists` when it is taken; `skip` passes over a candidate that must never be used (a protected path).
pub(crate) fn claim_candidate<T>(
    target: &Path,
    style: RenameStyle,
    skip: impl Fn(&Path) -> bool,
    mut claim: impl FnMut(&Path) -> io::Result<T>,
) -> Result<(PathBuf, T), RenameError> {
    for candidate in candidates(target, style) {
        if skip(&candidate) {
            continue;
        }
        match claim(&candidate) {
            Ok(value) => return Ok((candidate, value)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(RenameError::Io(candidate, error)),
        }
    }
    Err(RenameError::Exhausted)
}

/// An empty output file this run created with `O_EXCL`, to be written in place. It is removed when dropped unless
/// [`Reserved::into_parts`] handed it on, and only while the name still holds the same file.
pub(crate) struct Reserved {
    file: Option<File>,
    path: PathBuf,
}

impl Reserved {
    /// Creates `path` exclusively. A name that is taken, even by a dangling symlink, reports `AlreadyExists`.
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        Ok(Self { file: Some(file), path: path.to_path_buf() })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The open file and its path. The caller takes over removing it on failure.
    pub(crate) fn into_parts(mut self) -> (File, PathBuf) {
        let file = self.file.take().expect("reserved file");
        (file, std::mem::take(&mut self.path))
    }
}

impl Drop for Reserved {
    fn drop(&mut self) {
        let Some(file) = self.file.take() else { return };
        if same_file(&file, &self.path) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn same_file(file: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), fs::symlink_metadata(path)) {
        (Ok(a), Ok(b)) => b.is_file() && (a.dev(), a.ino()) == (b.dev(), b.ino()),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file(file: &File, path: &Path) -> bool {
    matches!((file.metadata(), fs::symlink_metadata(path)), (Ok(a), Ok(b)) if b.is_file() && a.len() == b.len())
}

/// Moves `from` to `to` without replacing anything at `to`: `AlreadyExists` when `to` is taken. A symlink at `from`
/// is moved itself, never followed.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = |path: &Path| CString::new(path.as_os_str().as_bytes()).map_err(|_| io::ErrorKind::InvalidInput);
        let (old, new) = (c(from)?, c(to)?);
        #[cfg(target_os = "linux")]
        // SAFETY: both paths are NUL-terminated and live across the call.
        let status = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                old.as_ptr(),
                libc::AT_FDCWD,
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: both paths are NUL-terminated and live across the call.
        let status = unsafe {
            libc::renameatx_np(libc::AT_FDCWD, old.as_ptr(), libc::AT_FDCWD, new.as_ptr(), libc::RENAME_EXCL)
        } as libc::c_long;
        if status >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        // A file system without the no-replace rename still has an atomic no-clobber link.
        if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP)) {
            return Err(error);
        }
    }
    link_then_unlink(from, to)
}

/// The portable no-replace move: a hard link fails when `to` is taken, and the old name goes only once the new one
/// holds the file, so the file is never without a name.
fn link_then_unlink(from: &Path, to: &Path) -> io::Result<()> {
    if fs::symlink_metadata(from)?.file_type().is_symlink() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(name: &str, n: u32, style: RenameStyle) -> String {
        renamed_name(OsStr::new(name), n, style).into_string().unwrap()
    }

    #[test]
    fn names_split_at_the_last_dot() {
        use RenameStyle::*;
        assert_eq!(name("a.txt", 1, Underscore), "a_1.txt");
        assert_eq!(name("a.txt", 2, Underscore), "a_2.txt");
        assert_eq!(name("noext", 1, Underscore), "noext_1");
        assert_eq!(name("b.tar.gz", 1, Underscore), "b.tar_1.gz");
        assert_eq!(name(".bashrc", 1, Underscore), ".bashrc_1");
        assert_eq!(name(".config.json", 1, Underscore), ".config_1.json");
        assert_eq!(name("a.", 1, Underscore), "a_1.");
        assert_eq!(name("top.txt", 1, Parenthesized), "top(1).txt");
        assert_eq!(name("noext", 1, Parenthesized), "noext(1)");
        assert_eq!(name("b.tar.gz", 10000, Parenthesized), "b.tar(10000).gz");
        assert_eq!(name(".bashrc", 1, Parenthesized), "(1).bashrc");
        assert_eq!(name("a.", 3, Parenthesized), "a(3).");
    }

    #[test]
    fn claims_skip_taken_and_skipped_names() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.txt");
        fs::write(dir.path().join("a_1.txt"), b"x").unwrap();
        let skip = dir.path().join("a_2.txt");
        let (path, reserved) =
            claim_candidate(&target, RenameStyle::Underscore, |p| p == skip, Reserved::create).unwrap();
        assert_eq!(path, dir.path().join("a_3.txt"));
        assert_eq!(reserved.path(), path);
        drop(reserved);
        assert!(!path.exists(), "an unused reservation is removed");
    }

    #[test]
    fn no_replace_rename_refuses_a_taken_name() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        fs::write(&a, b"a").unwrap();
        fs::write(&b, b"b").unwrap();
        assert_eq!(rename_noreplace(&a, &b).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        fs::remove_file(&b).unwrap();
        rename_noreplace(&a, &b).unwrap();
        assert_eq!(fs::read(&b).unwrap(), b"a");
        assert!(!a.exists());
        assert!(link_then_unlink(&b, &a).is_ok());
        assert_eq!(fs::read(&a).unwrap(), b"a");
    }
}
