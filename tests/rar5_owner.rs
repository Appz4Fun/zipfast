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
