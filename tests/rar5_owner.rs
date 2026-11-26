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

//! RAR 5.0 Unix owner record (file header extra record 0x06), as UnRAR `vt` prints `Unix owner: user:group`.

mod common;

use zipfast::rar5::reader::{Block, Volume};

#[test]
fn rar5_unix_owner_record_is_exposed() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar5-owner/r5extra.rar");
    let mut volume = Volume::open(&path).unwrap();
    let mut owners = Vec::new();
    while let Ok(Some(block)) = volume.next_block() {
        match block {
            Block::File(h) if !h.service => owners.push((h.name.clone(), h.owner.clone())),
            Block::End { .. } => break,
            _ => {}
        }
    }
    let owned = owners.iter().find(|(name, _)| name.starts_with("owned.txt")).expect("owned.txt listed");
    let owner = owned.1.as_ref().expect("owned.txt has an owner record");
    assert_eq!(owner.user.as_deref(), Some(&b"user"[..]));
    assert_eq!(owner.group.as_deref(), Some(&b"group"[..]));
    let timed = owners.iter().find(|(name, _)| name.starts_with("timed.txt")).expect("timed.txt listed");
    assert!(timed.1.is_none(), "timed.txt has no owner record");
}

/// A file header with a Unix owner record of `user`/`group` names, in a one-file archive.
fn owned_archive(user: &[u8], group: &[u8]) -> Vec<u8> {
    let mut record = vec![0x06, 0x03, user.len() as u8];
    record.extend_from_slice(user);
    record.push(group.len() as u8);
    record.extend_from_slice(group);
    // RAR vint: 7 bits per byte, low first, high bit = more.
    let mut extra = Vec::new();
    let mut n = record.len();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        extra.push(if n > 0 { byte | 0x80 } else { byte });
        if n == 0 {
            break;
        }
    }
    extra.extend(record);
    let mut spec = common::FileSpec::new("f.txt", b"hello");
    spec.extra = extra;
    common::archive(&[spec])
}

/// The decoded owner names are charged to the catalogue's capacity for every header copy it keeps.
#[test]
fn owner_names_count_against_the_catalogue_capacity() {
    use zipfast::rar5::session::{RarSession, RarSessionOptions};
    let dir = tempfile::tempdir().unwrap();
    let capacity = |user: &[u8], group: &[u8]| {
        let path = dir.path().join("a.rar");
        std::fs::write(&path, owned_archive(user, group)).unwrap();
        let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let header = session.headers().find(|h| !h.is_service()).expect("file header");
        assert_eq!(header.owner().and_then(|o| o.user.as_deref()), Some(user));
        session.usage().capacity
    };
    let short = capacity(b"u", b"g");
    let long = capacity(&[b'u'; 100], &[b'g'; 100]);
    // Two retained copies (the listed member and the header record) of 198 more name bytes.
    assert!(long >= short + 2 * 198, "{short} -> {long}");
}
