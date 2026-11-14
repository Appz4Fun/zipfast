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

//! Public adapter parity for the shared progressive framing and physical model.
mod common;
use common::{FileSpec, archive, volumes};
use zipfast::rar5::{
    reader::{Block, Volume},
    session::{RarSession, RarSessionOptions},
};

#[test]
fn file_volume_and_catalogue_keep_public_names_offsets_and_checks() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("a.rar");
    let payload = b"shared physical framing";
    let bytes = archive(&[FileSpec::new("unicode-Ω", payload)]);
    std::fs::write(&path, &bytes).unwrap();
    let mut volume = Volume::open(&path).unwrap();
    assert_eq!(volume.file().metadata().unwrap().len(), bytes.len() as u64);
    let Some(Block::File(header)) = volume.next_block().unwrap() else { panic!("file") };
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let member = session.entries().next().unwrap();
    let part = member.parts().next().unwrap();
    assert_eq!(member.raw_name(), "unicode-Ω".as_bytes());
    assert_eq!(member.name(), header.name);
    assert_eq!(part.data_offset(), header.data_at);
    assert_eq!(part.packed_size(), header.packed_size);
    assert_eq!(part.checks().crc32, header.crc32);
}

#[test]
fn physical_model_keeps_one_name_and_part_order_across_volumes() {
    let temp = tempfile::tempdir().unwrap();
    let data = b"a logical member across physical volumes";
    let pieces = volumes(&FileSpec::new("one", data), 9);
    for (i, bytes) in pieces.iter().enumerate() {
        std::fs::write(temp.path().join(format!("a.part{:02}.rar", i + 1)), bytes).unwrap();
    }
    let session = RarSession::open(&temp.path().join("a.part01.rar"), None, RarSessionOptions::default()).unwrap();
    let members = session.entries().collect::<Vec<_>>();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].raw_name(), b"one");
    assert!(members[0].is_complete());
    assert_eq!(members[0].parts().map(|p| p.volume()).collect::<Vec<_>>(), (0..pieces.len()).collect::<Vec<_>>());
    assert_eq!(members[0].packed_size(), data.len() as u64);
}
