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

//! Shared directory validation, retaining legacy accounting and failures.
use super::*;
pub(crate) fn open_directory(path: &Path) -> ProgressiveResult<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    o.open(path).map_err(|e| out(OutputOperation::Create, e, 0))
}
pub(crate) fn check_directory(path: &Path, file: &fs::File, identity: native::Identity) -> ProgressiveResult<()> {
    let meta = fs::symlink_metadata(path).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
    if !meta.is_dir()
        || native::Identity::metadata(&meta).map_err(|e| out(OutputOperation::Metadata, e, 0))? != identity
        || native::Identity::file(file).map_err(|e| out(OutputOperation::Metadata, e, 0))? != identity
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn check_parents(root: &Path, path: &Path, usage: &Usage) -> ProgressiveResult<()> {
    let relative = path.parent().ok_or_else(invalid)?.strip_prefix(root).map_err(|_| invalid())?;
    usage.charge(Resource::MetadataBytes, (path.as_os_str().len() as u64).saturating_mul(2))?;
    let mut at = root.to_path_buf();
    for component in relative.components() {
        usage.charge(Resource::SourceBookkeeping, 1 + at.as_os_str().len() as u64)?;
        at.push(component);
        let meta = match fs::symlink_metadata(&at) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
        }
    }
    Ok(())
}
