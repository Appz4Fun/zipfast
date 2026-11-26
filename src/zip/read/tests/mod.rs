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

#[cfg(unix)]
#[allow(dead_code)] // One shared first-party fixture also models metadata forms used by other suites.
#[path = "../../../../tests/common/zip_parity_fixture.rs"]
mod fixture;

/// A temporary directory only its owner can write, whatever the umask: the spool and staging rightly refuse a group-
/// or world-writable parent, and `tempfile::tempdir()` follows the umask (0775 under umask 002, as Ubuntu gives
/// ordinary users).
#[cfg(unix)]
pub(super) fn tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap()
}

/// `path` and its missing parents, made private (0700) whatever the umask, as [`tempdir`].
#[cfg(unix)]
pub(super) fn private_dirs(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path.as_ref())
}

/// One new private (0700) directory, as `std::fs::create_dir` but whatever the umask.
#[cfg(unix)]
pub(super) fn private_dir(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path.as_ref())
}

mod core;

#[cfg(unix)]
mod cipher;
#[cfg(unix)]
mod spool;

#[cfg(unix)]
mod codecs;

#[cfg(unix)]
mod projected;

#[cfg(unix)]
mod output;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod policy;

#[cfg(target_os = "macos")]
mod qualified;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod run;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod portable;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod diagnostic;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod review_r1;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) mod task6;
