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

//! Tar listing metadata: owner, ids, device numbers, magic and pax records, as 7-Zip's `l -slt` prints them.
use std::path::Path;

use zipfast::extract::{self, Entry};
use zipfast::tar::TarMagic;

fn list(name: &str) -> Vec<Entry> {
    extract::list(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tar-meta").join(name)).unwrap()
}

#[test]
fn pax_members_carry_owner_times_and_records() {
    for archive in ["pax.tar", "pax.tgz"] {
        let entries = list(archive);
        assert_eq!(entries.len(), 1, "{archive}");
        let e = &entries[0];
        assert_eq!((e.atime, e.ctime), (Some((1_614_834_367, 500_000_000)), Some((1_600_000_000, 250_000_000))));
        let t = e.tar.as_deref().unwrap();
        assert_eq!(t.magic, TarMagic::Ustar);
        assert_eq!(t.typeflag, b'0');
        assert_eq!(
            (t.user.as_deref(), t.group.as_deref(), t.uid, t.gid),
            (Some("builder"), Some("staff"), Some(1234), Some(56))
        );
        assert_eq!((t.device_major, t.device_minor), (None, None));
        assert_eq!(t.pax_header_name.as_deref(), Some("././@PaxHeader"));
        let keys: Vec<_> = t.pax_records.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"atime") && keys.contains(&"ctime"), "{keys:?}");
        assert!(t.pax_records.iter().any(|(k, v)| k == "comment" && v == b"hi"));
        assert_eq!(&t.header[257..263], b"ustar\0");
    }
}

#[test]
fn gnu_and_ustar_magic_and_devices() {
    let gnu = list("gnu.tar");
    let t = gnu[0].tar.as_deref().unwrap();
    assert_eq!((t.magic, t.user.as_deref(), t.uid), (TarMagic::Gnu, Some("builder"), Some(1234)));
    assert_eq!((t.pax_header_name.as_deref(), t.pax_records.len()), (None, 0));
    assert_eq!((gnu[0].atime, gnu[0].ctime), (None, None));
    let ustar = list("ustar.tar");
    let dev = ustar.iter().find(|e| e.name == "dev").unwrap().tar.as_deref().unwrap();
    assert_eq!(
        (dev.magic, dev.typeflag, dev.device_major, dev.device_minor),
        (TarMagic::Ustar, b'3', Some(4), Some(7))
    );
}
