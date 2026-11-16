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

//! `RarMember::unrar_name` reads a RAR5 name the way UnRAR does on Unix.

mod common;

use common::{SIG, block, end_block, main_block, vint};
use zipfast::rar5::session::{RarSession, RarSessionOptions};
use zipfast::rar5::{unrar_name, unrar_name_to_string};

/// A stored file header whose name is `name`, whatever its bytes.
fn file_with_raw_name(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut fields = Vec::new();
    vint(0x4, &mut fields); // CRC32 present
    vint(data.len() as u64, &mut fields);
    vint(0o644, &mut fields);
    fields.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    vint(0, &mut fields); // stored
    vint(1, &mut fields); // Unix host
    vint(name.len() as u64, &mut fields);
    fields.extend_from_slice(name);
    block(2, 0, &fields, &[], data, true)
}

fn units(s: &str) -> Vec<u32> {
    s.chars().map(u32::from).collect()
}

#[test]
fn members_with_names_that_are_not_utf8_get_unrar_names() {
    let names: [(&[u8], &str, Vec<u32>); 5] = [
        (b"plain.txt", "plain.txt", units("plain.txt")),
        (b"c\xffd", "c\u{fffd}d", units("c")),
        (b"s\xed\xa0\x80t", "s\u{fffd}\u{fffd}\u{fffd}t", vec![u32::from('s'), 0xd800, u32::from('t')]),
        (b"over\xc0\xaflong", "over\u{fffd}\u{fffd}long", units("over/long")),
        (b"tail\xe2\x82", "tail\u{fffd}", units("tail")),
    ];
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    for (raw, _, _) in &names {
        bytes.extend(file_with_raw_name(raw, b"data"));
    }
    bytes.extend(end_block(false));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("names.rar");
    std::fs::write(&path, bytes).unwrap();

    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let members = session.entries().collect::<Vec<_>>();
    assert_eq!(members.len(), names.len());
    for (member, (raw, name, unrar)) in members.iter().zip(&names) {
        assert_eq!(member.raw_name(), *raw);
        assert_eq!(member.name(), *name);
        assert_eq!(member.unrar_name().as_ref(), Some(unrar), "{raw:?}");
        assert_eq!(unrar_name(member.raw_name()), *unrar);
    }
    assert_eq!(unrar_name_to_string(&members[1].unrar_name().unwrap()).as_deref(), Some("c"));
    assert_eq!(unrar_name_to_string(&members[2].unrar_name().unwrap()), None);
    assert_eq!(unrar_name_to_string(&members[3].unrar_name().unwrap()).as_deref(), Some("over/long"));
}
