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

use zipfast::Error;
use zipfast::extract::Options;
use zipfast::zip::{EncryptedReadContext, EncryptedReadOptions};
#[test]
fn additive_context_keeps_legacy_options() {
    let _literal = Options {
        mode: zipfast::extract::Mode::Test,
        dest: Default::default(),
        overwrite: Default::default(),
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: false,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    };
    let _ = EncryptedReadContext::new(EncryptedReadOptions::default()).unwrap();
}
fn exhaustive_error(error: Error) {
    match error {
        Error::Io(_)
        | Error::NotAnArchive
        | Error::Corrupt(_)
        | Error::Truncated
        | Error::MissingVolume(_)
        | Error::UnnamedVolume(_)
        | Error::Unsupported(_)
        | Error::Encrypted
        | Error::BadChecksum(_)
        | Error::UnsafePath(_) => {}
    }
}
#[test]
fn legacy_error_exhaustiveness() {
    exhaustive_error(Error::Encrypted);
}

#[test]
fn checked_source_signature_stays_context_bound() {
    let _: fn(&mut zipfast::zip::ReadSession, &mut EncryptedReadContext) -> zipfast::zip::ZipReadResult<()> =
        zipfast::zip::ReadSession::check_source_checked;
}
