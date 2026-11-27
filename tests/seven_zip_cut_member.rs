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

//! A member cut inside its data in 7z mode (`DamagedInput::SevenZip` with `keep_broken`, `salvage_truncated_zip` and
//! `UnverifiedOutput::Emit`): what 7-Zip 26.06 writes for `7z x`, `7z e` and `7z x -so` (observed; they write the
//! same bytes) is what zipfast keeps (`extract::run`), prints (`RarSession::print_selected`) and reads
//! (`SelectedEntry` with `SelectOptions::damaged_input`). Expected sizes and SHA-256s are 7-Zip's output; see
//! `tests/fixtures/seven-zip-cut-member/README.md` and `docs/compat-options.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{
    self, Cancellation, DamagedInput, Mode, Options, Overwrite, RarOutcome, SelectOptions, SelectedEntry,
    UnverifiedOutput,
};
use zipfast::rar5::session::{RarPrintOptions, RarSession, RarSessionOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn sha256(bytes: &[u8]) -> String {
    zipfast::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// An archive cut at `at` bytes, the member 7-Zip reports failed (none when only a later local header is cut), and
/// the files `7z x` writes: each name, size and SHA-256, in the archive's order.
struct Cut {
    label: &'static str,
    fixture: &'static str,
    at: usize,
    password: Option<&'static str>,
    failed: Option<&'static str>,
    files: &'static [(&'static str, usize, &'static str)],
}

/// A ZIP fixture is the archive 7-Zip made (`zs-<method>.zip`), cut at the largest point used; each case cuts it
/// shorter. Members: `a.txt` (55,581 bytes), `b.bin` (20,000), `c.txt`. Cut points: `a0` just past `a.txt`'s local
/// header, `a4k` 4,000 bytes into its data, `b100` 100 bytes into `b.bin`'s, `c3k` 3,000 into `c.txt`'s, `chdr` inside
/// `c.txt`'s local header.
const CUTS: &[Cut] = &[
    // 7z: ERROR: E_FAIL : Unspecified error
    Cut {
        label: "zs-aes-deflate-a0",
        fixture: "seven-zip-cut-member/zs-aes-deflate.cut.zip",
        at: 46,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: Data Error in encrypted file. Wrong password? : a.txt
    Cut {
        label: "zs-aes-deflate-a4k",
        fixture: "seven-zip-cut-member/zs-aes-deflate.cut.zip",
        at: 4046,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 11834, "443fcaf1165e236cf4c8203bd76f702e8467660c7dc9159c2dbc975ed820f0fd")],
    },
    // 7z: ERROR: Unexpected end of data : b.bin
    Cut {
        label: "zs-aes-deflate-b100",
        fixture: "seven-zip-cut-member/zs-aes-deflate.cut.zip",
        at: 17351,
        password: Some("pw"),
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 82, "f6428dbd4cc7c18523717e04ec5d635d1c98cedf21d2b1e196e426ea9aa7cd31"),
        ],
    },
    // 7z: ERROR: Data Error in encrypted file. Wrong password? : c.txt
    Cut {
        label: "zs-aes-deflate-c3k",
        fixture: "seven-zip-cut-member/zs-aes-deflate.cut.zip",
        at: 40325,
        password: Some("pw"),
        failed: Some("c.txt"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
            ("c.txt", 8908, "95169540bc2d22dfd02e3a46c23f0853577930962f0e27409198f46ebe2ca7ec"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-aes-deflate-chdr",
        fixture: "seven-zip-cut-member/zs-aes-deflate.cut.zip",
        at: 37299,
        password: Some("pw"),
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: E_FAIL : Unspecified error
    Cut {
        label: "zs-aes-store-a0",
        fixture: "seven-zip-cut-member/zs-aes-store.cut.zip",
        at: 46,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: Unexpected end of data : a.txt
    Cut {
        label: "zs-aes-store-a4k",
        fixture: "seven-zip-cut-member/zs-aes-store.cut.zip",
        at: 4046,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 3982, "c586b6fe5f81ffaccfc1cacbf05c6a3cb9413aa375ad12bdd66558954bef827c")],
    },
    // 7z: ERROR: Unexpected end of data : b.bin
    Cut {
        label: "zs-aes-store-b100",
        fixture: "seven-zip-cut-member/zs-aes-store.cut.zip",
        at: 55801,
        password: Some("pw"),
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 82, "f6428dbd4cc7c18523717e04ec5d635d1c98cedf21d2b1e196e426ea9aa7cd31"),
        ],
    },
    // 7z: ERROR: Unexpected end of data : c.txt
    Cut {
        label: "zs-aes-store-c3k",
        fixture: "seven-zip-cut-member/zs-aes-store.cut.zip",
        at: 78775,
        password: Some("pw"),
        failed: Some("c.txt"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
            ("c.txt", 2982, "1fb611c8366d063ce9e196d76eaaaffd1c49090b2489011971347474d47e5ff6"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-aes-store-chdr",
        fixture: "seven-zip-cut-member/zs-aes-store.cut.zip",
        at: 75749,
        password: Some("pw"),
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: Data Error : a.txt
    Cut {
        label: "zs-bzip2-a0",
        fixture: "seven-zip-cut-member/zs-bzip2.cut.zip",
        at: 35,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: Data Error : a.txt
    Cut {
        label: "zs-bzip2-a4k",
        fixture: "seven-zip-cut-member/zs-bzip2.cut.zip",
        at: 4035,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: CRC Failed : b.bin
    Cut {
        label: "zs-bzip2-b100",
        fixture: "seven-zip-cut-member/zs-bzip2.cut.zip",
        at: 13470,
        password: None,
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 100, "859cf3f8b7ab02d85284f675138010f0ee3aa851380587407b08dbb9440e41a5"),
        ],
    },
    // 7z: ERROR: Data Error : c.txt
    Cut {
        label: "zs-bzip2-c3k",
        fixture: "seven-zip-cut-member/zs-bzip2.cut.zip",
        at: 36405,
        password: None,
        failed: Some("c.txt"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
            ("c.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-bzip2-chdr",
        fixture: "seven-zip-cut-member/zs-bzip2.cut.zip",
        at: 33390,
        password: None,
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: Data Error : a.txt
    Cut {
        label: "zs-deflate-a0",
        fixture: "seven-zip-cut-member/zs-deflate.cut.zip",
        at: 35,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: Data Error : a.txt
    Cut {
        label: "zs-deflate-a4k",
        fixture: "seven-zip-cut-member/zs-deflate.cut.zip",
        at: 4035,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 11890, "4367e9ab0d639db7a06d6c784ef7bc81e534d2e01c82334d17d71547723f7267")],
    },
    // 7z: ERROR: CRC Failed : b.bin
    Cut {
        label: "zs-deflate-b100",
        fixture: "seven-zip-cut-member/zs-deflate.cut.zip",
        at: 17301,
        password: None,
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 100, "859cf3f8b7ab02d85284f675138010f0ee3aa851380587407b08dbb9440e41a5"),
        ],
    },
    // 7z: ERROR: Data Error : c.txt
    Cut {
        label: "zs-deflate-c3k",
        fixture: "seven-zip-cut-member/zs-deflate.cut.zip",
        at: 40236,
        password: None,
        failed: Some("c.txt"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
            ("c.txt", 8964, "9f5c5477d516b9bcb42a9abc29bf428cb44477754ab867a6160040bf32c0edaa"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-deflate-chdr",
        fixture: "seven-zip-cut-member/zs-deflate.cut.zip",
        at: 37221,
        password: None,
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: Data Error : a.txt
    Cut {
        label: "zs-lzma-a0",
        fixture: "seven-zip-cut-member/zs-lzma.cut.zip",
        at: 35,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: Data Error : a.txt
    Cut {
        label: "zs-lzma-a4k",
        fixture: "seven-zip-cut-member/zs-lzma.cut.zip",
        at: 4035,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 12759, "5c4ff3e1ab1e8c7d1ec8c6ea74e486b6eb5f9349cefc60e0fb6ecaa7ad83952e")],
    },
    // 7z: ERROR: CRC Failed : b.bin
    Cut {
        label: "zs-lzma-b100",
        fixture: "seven-zip-cut-member/zs-lzma.cut.zip",
        at: 16238,
        password: None,
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 100, "859cf3f8b7ab02d85284f675138010f0ee3aa851380587407b08dbb9440e41a5"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-lzma-chdr",
        fixture: "seven-zip-cut-member/zs-lzma.cut.zip",
        at: 36158,
        password: None,
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: CRC Failed : a.txt
    Cut {
        label: "zs-store-a0",
        fixture: "seven-zip-cut-member/zs-store.cut.zip",
        at: 35,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: CRC Failed : a.txt
    Cut {
        label: "zs-store-a4k",
        fixture: "seven-zip-cut-member/zs-store.cut.zip",
        at: 4035,
        password: None,
        failed: Some("a.txt"),
        files: &[("a.txt", 4000, "f6b34a82a133a256181c7cfab25282dd96dbe8871abeed30be7fb25647b49b11")],
    },
    // 7z: ERROR: CRC Failed : b.bin
    Cut {
        label: "zs-store-b100",
        fixture: "seven-zip-cut-member/zs-store.cut.zip",
        at: 55751,
        password: None,
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 100, "859cf3f8b7ab02d85284f675138010f0ee3aa851380587407b08dbb9440e41a5"),
        ],
    },
    // 7z: ERROR: CRC Failed : c.txt
    Cut {
        label: "zs-store-c3k",
        fixture: "seven-zip-cut-member/zs-store.cut.zip",
        at: 78686,
        password: None,
        failed: Some("c.txt"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
            ("c.txt", 3000, "bd97f35475efd0cbe809cbc0881b6fc31659ba33de3fa838c141f5d9dffea0f2"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-store-chdr",
        fixture: "seven-zip-cut-member/zs-store.cut.zip",
        at: 75671,
        password: None,
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: E_FAIL : Unspecified error
    Cut {
        label: "zs-zc-deflate-a0",
        fixture: "seven-zip-cut-member/zs-zc-deflate.cut.zip",
        at: 35,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: Data Error in encrypted file. Wrong password? : a.txt
    Cut {
        label: "zs-zc-deflate-a4k",
        fixture: "seven-zip-cut-member/zs-zc-deflate.cut.zip",
        at: 4035,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 11854, "1adb6969d64ce4e9c775a679d9c545d16d66e13367ae08c7a931391d6ba67fd3")],
    },
    // 7z: ERROR: CRC Failed in encrypted file. Wrong password? : b.bin
    Cut {
        label: "zs-zc-deflate-b100",
        fixture: "seven-zip-cut-member/zs-zc-deflate.cut.zip",
        at: 17313,
        password: Some("pw"),
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 88, "722218921d1375f0bee85db59fbca263811a5e6cc48161c594afc5dce256ae25"),
        ],
    },
    // 7z: ERROR: Data Error in encrypted file. Wrong password? : c.txt
    Cut {
        label: "zs-zc-deflate-c3k",
        fixture: "seven-zip-cut-member/zs-zc-deflate.cut.zip",
        at: 40260,
        password: Some("pw"),
        failed: Some("c.txt"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
            ("c.txt", 8925, "be8b3f61f65227a2e1d2961325dfc25ec6be1368857a3e5f8f7580be852c76d3"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-zc-deflate-chdr",
        fixture: "seven-zip-cut-member/zs-zc-deflate.cut.zip",
        at: 37245,
        password: Some("pw"),
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: E_FAIL : Unspecified error
    Cut {
        label: "zs-zc-store-a0",
        fixture: "seven-zip-cut-member/zs-zc-store.cut.zip",
        at: 35,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: CRC Failed in encrypted file. Wrong password? : a.txt
    Cut {
        label: "zs-zc-store-a4k",
        fixture: "seven-zip-cut-member/zs-zc-store.cut.zip",
        at: 4035,
        password: Some("pw"),
        failed: Some("a.txt"),
        files: &[("a.txt", 3988, "2e0468a1aa47a8ba89907a8d0da01b23c465c45205adbf7ac7597164ac5bae56")],
    },
    // 7z: ERROR: CRC Failed in encrypted file. Wrong password? : b.bin
    Cut {
        label: "zs-zc-store-b100",
        fixture: "seven-zip-cut-member/zs-zc-store.cut.zip",
        at: 55763,
        password: Some("pw"),
        failed: Some("b.bin"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 88, "722218921d1375f0bee85db59fbca263811a5e6cc48161c594afc5dce256ae25"),
        ],
    },
    // 7z: ERROR: CRC Failed in encrypted file. Wrong password? : c.txt
    Cut {
        label: "zs-zc-store-c3k",
        fixture: "seven-zip-cut-member/zs-zc-store.cut.zip",
        at: 78710,
        password: Some("pw"),
        failed: Some("c.txt"),
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
            ("c.txt", 2988, "54de82427bb78027f72289d0641aae5277d40de881c8aaa56cbecb4087d43aa3"),
        ],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "zs-zc-store-chdr",
        fixture: "seven-zip-cut-member/zs-zc-store.cut.zip",
        at: 75695,
        password: Some("pw"),
        failed: None,
        files: &[
            ("a.txt", 55581, "659d23fd263c2c224aabfcf2ae50c4c61d95f1dc5273111ea3f368ff5586e8e8"),
            ("b.bin", 20000, "f5d2817d5839c91e66cf80c225aa89677956115fb0b69f8e8011444a049feef5"),
        ],
    },
    // 7z: ERROR: Data Error : unrardll.txt
    Cut {
        label: "solid-1518",
        fixture: "rar4/solid.rar",
        at: 1518,
        password: None,
        failed: Some("unrardll.txt"),
        files: &[
            ("tese.txt", 787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
            ("unrardll.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
    },
    // 7z: ERROR: Data Error : unrardll.txt
    Cut {
        label: "solid-3036",
        fixture: "rar4/solid.rar",
        at: 3036,
        password: None,
        failed: Some("unrardll.txt"),
        files: &[
            ("tese.txt", 787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
            ("unrardll.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
    },
    // 7z: ERROR: Data Error : unrardll.txt
    Cut {
        label: "solid-4554",
        fixture: "rar4/solid.rar",
        at: 4554,
        password: None,
        failed: Some("unrardll.txt"),
        files: &[
            ("tese.txt", 787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
            ("unrardll.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
    },
    // 7z: ERROR: Data Error : solid_lorem_a.txt
    Cut {
        label: "ppmd_solid_rar300-5977",
        fixture: "rar4-rar300/ppmd_solid_rar300.rar",
        at: 5977,
        password: None,
        failed: Some("solid_lorem_a.txt"),
        files: &[("solid_lorem_a.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: Data Error : BIGLZ.BIN
    Cut {
        label: "BIGLZ-2675",
        fixture: "rar4-legacy/BIGLZ.RAR",
        at: 2675,
        password: None,
        failed: Some("BIGLZ.BIN"),
        files: &[("BIGLZ.BIN", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")],
    },
    // 7z: ERROR: CRC Failed : big.bin
    Cut {
        label: "r4-stored-18019",
        fixture: "emit-cut-archive/r4-stored.rar",
        at: 18019,
        password: None,
        failed: Some("big.bin"),
        files: &[("big.bin", 17960, "a30930b94adfe93811c4074f7ce2daf1f39743ebec98978ca77b7e59433293cc")],
    },
    // 7z: ERROR: Data Error : big.bin
    Cut {
        label: "r5-stored-18015",
        fixture: "emit-cut-archive/r5-stored.rar",
        at: 18015,
        password: None,
        failed: Some("big.bin"),
        files: &[("big.bin", 17970, "f3ed3905d782815302a69e76e31c66acebb084e37eb01bd17c33157c715b9511")],
    },
    // 7z: ERROR: Data Error : big.bin
    Cut {
        label: "r5-stored-36031",
        fixture: "emit-cut-archive/r5-stored.rar",
        at: 36031,
        password: None,
        failed: Some("big.bin"),
        files: &[("big.bin", 35986, "7847bd188f6a6ea20a3faf8743a3de3b9582a4f81db114c87574afb73318144e")],
    },
    // 7z: lists only the members before the cut, each whole
    Cut {
        label: "esppw-1200",
        fixture: "rar5-solid-enc/esppw.rar",
        at: 1200,
        password: Some("pw"),
        failed: None,
        files: &[("t/a", 1000, "1962185c163dc8b9d8457024e0ceffd1b8d59d5da38ee9f0cf3cda5ac4d98763")],
    },
];

/// A RAR volume set with a volume missing: the volumes present, the first, and what `7z x` writes (7-Zip: "ERROR =
/// Missing volume", then the member that needed it fails).
struct Missing {
    label: &'static str,
    dir: &'static str,
    volumes: &'static [&'static str],
    password: Option<&'static str>,
    failed: &'static str,
    files: &'static [(&'static str, usize, &'static str)],
}

const MISSING: &[Missing] = &[
    // 7z: ERROR = Missing volume : multi.part2.rar; ERROR: Data Error : file2.txt (RAR 2.9 LZ: nothing of it)
    Missing {
        label: "multi-miss2",
        dir: "rar4-volumes",
        volumes: &["multi.part1.rar", "multi.part3.rar"],
        password: None,
        failed: "file2.txt",
        files: &[
            ("file1.txt", 18, "a56c9d9d7c000206a6b29db5cdfd754645a10d5ad419c8298f7530a550dfbd87"),
            ("file2.txt", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
    },
    // 7z: ERROR = Missing volume : win-encvol.r01; ERROR: Data Error in encrypted file. Wrong password? : split.bin
    // (stored, encrypted: the whole AES blocks of the first volume)
    Missing {
        label: "encvol-miss1",
        dir: "rar4-archiver",
        volumes: &["win-encvol.rar", "win-encvol.r00", "win-encvol.r02"],
        password: Some("testpw123"),
        failed: "split.bin",
        files: &[("split.bin", 1808, "bc013adc4b458d13b233399b7e9dc8e18c30e7262d996ccbed628896885fd86b")],
    },
    // 7z: ERROR = Missing volume : win-encvol.r02; ERROR: Data Error in encrypted file. Wrong password? : split.bin
    Missing {
        label: "encvol-miss2",
        dir: "rar4-archiver",
        volumes: &["win-encvol.rar", "win-encvol.r00", "win-encvol.r01"],
        password: Some("testpw123"),
        failed: "split.bin",
        files: &[("split.bin", 2704, "b1f45e0cfea9efeb90292377618e4208fe7cd5eba99ff91dd02f0cc9552d7cc2")],
    },
];

const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// What `7z x -so` prints of each RAR case (length and SHA-256: the files `7z x` writes, in order), and the same
/// without the member that fails, which is what `Withhold` prints.
type Printed = (usize, &'static str);
const PRINTS: &[(&str, Printed, Printed)] = &[
    (
        "solid-1518",
        (787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
        (787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
    ),
    (
        "solid-3036",
        (787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
        (787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
    ),
    (
        "solid-4554",
        (787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
        (787, "7114676bda779d9a08f4f607bf149e40156baa5689f82e618fe04d5bca84bf34"),
    ),
    ("ppmd_solid_rar300-5977", (0, EMPTY), (0, EMPTY)),
    ("BIGLZ-2675", (0, EMPTY), (0, EMPTY)),
    ("r4-stored-18019", (17960, "a30930b94adfe93811c4074f7ce2daf1f39743ebec98978ca77b7e59433293cc"), (0, EMPTY)),
    ("r5-stored-18015", (17970, "f3ed3905d782815302a69e76e31c66acebb084e37eb01bd17c33157c715b9511"), (0, EMPTY)),
    ("r5-stored-36031", (35986, "7847bd188f6a6ea20a3faf8743a3de3b9582a4f81db114c87574afb73318144e"), (0, EMPTY)),
    (
        "esppw-1200",
        (1000, "1962185c163dc8b9d8457024e0ceffd1b8d59d5da38ee9f0cf3cda5ac4d98763"),
        (1000, "1962185c163dc8b9d8457024e0ceffd1b8d59d5da38ee9f0cf3cda5ac4d98763"),
    ),
    (
        "multi-miss2",
        (18, "a56c9d9d7c000206a6b29db5cdfd754645a10d5ad419c8298f7530a550dfbd87"),
        (18, "a56c9d9d7c000206a6b29db5cdfd754645a10d5ad419c8298f7530a550dfbd87"),
    ),
    ("encvol-miss1", (1808, "bc013adc4b458d13b233399b7e9dc8e18c30e7262d996ccbed628896885fd86b"), (0, EMPTY)),
    ("encvol-miss2", (2704, "b1f45e0cfea9efeb90292377618e4208fe7cd5eba99ff91dd02f0cc9552d7cc2"), (0, EMPTY)),
];

/// One archive to read: where it is, and what 7-Zip makes of it.
struct Case {
    label: &'static str,
    archive: PathBuf,
    password: Option<&'static str>,
    failed: Option<&'static str>,
    files: &'static [(&'static str, usize, &'static str)],
}

impl Case {
    fn rar(&self) -> bool {
        !self.label.starts_with("zs-")
    }

    /// A RAR cut inside a header, not a member's data: only the whole-archive runner reads the members before it
    /// (a `RarSession` and a RAR listing refuse a cut header unless `DamagedInput::Salvage`).
    fn rar_header_cut(&self) -> bool {
        self.rar() && self.failed.is_none()
    }
}

/// Every case, its archive written under `dir`: the first `at` bytes of a fixture, or the volumes present of a set.
fn cases(dir: &Path) -> Vec<Case> {
    let mut cases = Vec::new();
    for cut in CUTS {
        let bytes = fs::read(Path::new(FIXTURES).join(cut.fixture)).unwrap();
        let name = Path::new(cut.fixture).file_name().unwrap().to_string_lossy().replace(".cut", "");
        let own = dir.join(cut.label);
        fs::create_dir_all(&own).unwrap();
        let archive = own.join(name);
        fs::write(&archive, &bytes[..cut.at]).unwrap();
        cases.push(Case { label: cut.label, archive, password: cut.password, failed: cut.failed, files: cut.files });
    }
    for set in MISSING {
        let own = dir.join(set.label);
        fs::create_dir_all(&own).unwrap();
        for volume in set.volumes {
            fs::copy(Path::new(FIXTURES).join(set.dir).join(volume), own.join(volume)).unwrap();
        }
        let archive = own.join(set.volumes[0]);
        cases.push(Case {
            label: set.label,
            archive,
            password: set.password,
            failed: Some(set.failed),
            files: set.files,
        });
    }
    cases
}

/// Prybar's 7z mode, as `extract::run` takes it.
fn seven_zip_mode(dest: &Path, unverified: UnverifiedOutput) -> Options {
    Options {
        keep_broken: true,
        attempt_continued_members: true,
        damaged_input: DamagedInput::SevenZip,
        unverified_output: unverified,
        salvage_truncated_zip: true,
        seven_zip_strict: true,
        ..defaults(dest)
    }
}

/// Every opt-in off.
fn defaults(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
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
        damaged_input: DamagedInput::Refuse,
        unsupported_filters: Default::default(),
        unverified_output: UnverifiedOutput::Withhold,
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

/// Every file under `dir`: its path from `dir`, size and SHA-256.
fn written(dir: &Path) -> BTreeMap<String, (usize, String)> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, (usize, String)>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let bytes = fs::read(&path).unwrap();
                let name = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                out.insert(name, (bytes.len(), sha256(&bytes)));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn expected(case: &Case) -> BTreeMap<String, (usize, String)> {
    case.files.iter().map(|(name, size, sha)| (name.to_string(), (*size, sha.to_string()))).collect()
}

/// `7z x`: the members before the cut whole, and the member cut short as 7-Zip writes it (a 0-byte file where 7-Zip
/// decodes nothing of it); the run fails.
#[test]
fn extraction_keeps_what_7z_writes() {
    let dir = tempfile::tempdir().unwrap();
    for case in cases(dir.path()) {
        let dest = dir.path().join(format!("{}-out", case.label));
        let result = extract::run_with_password(
            &case.archive,
            &seven_zip_mode(&dest, UnverifiedOutput::Emit),
            case.password,
            |_| {},
        );
        let failed = match &result {
            Ok(summary) => !summary.errors.is_empty(),
            Err(_) => true,
        };
        assert!(failed, "{}: the run fails: {result:?}", case.label);
        assert_eq!(written(&dest), expected(&case), "{}", case.label);
    }
}

/// `7z x -so NAME` through `SelectedEntry` (both of its opens): each member as `7z x` writes it, and the member cut
/// short fails, its bytes reported unverified. With `Withhold` that member still fails.
#[test]
fn selected_entry_reads_what_7z_prints() {
    let dir = tempfile::tempdir().unwrap();
    for case in cases(dir.path()).into_iter().filter(|case| !case.rar_header_cut()) {
        // a set missing a volume doesn't list (the volume is missing); its members are read by index all the same
        if !case.label.contains("miss") {
            let listing = extract::list_detailed_with_options(
                &case.archive,
                case.password,
                &seven_zip_mode(&dir.path().join("unused"), UnverifiedOutput::Emit),
            )
            .unwrap_or_else(|error| panic!("{}: {error}", case.label));
            let names: Vec<_> = listing.entries.iter().map(|entry| entry.name.clone()).collect();
            let want: Vec<_> = case.files.iter().map(|(name, ..)| name.to_string()).collect();
            assert_eq!(names, want, "{}: 7z lists", case.label);
        }
        for (index, &(name, size, sha)) in case.files.iter().enumerate() {
            let what = format!("{} {name}", case.label);
            let fails = case.failed == Some(name);
            for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
                let select = SelectOptions::new().damaged_input(DamagedInput::SevenZip).unverified_output(unverified);
                for checked in [false, true] {
                    let mut out = Vec::new();
                    let read = if checked {
                        SelectedEntry::open_cancelable_with_zip_limit_and_options(
                            &case.archive,
                            index,
                            case.password,
                            u64::MAX,
                            None,
                            Cancellation::default(),
                            select,
                        )
                        .map_err(|error| error.to_string())
                    } else {
                        SelectedEntry::open_cancelable_with_options(
                            &case.archive,
                            index,
                            case.password,
                            u64::MAX,
                            Cancellation::default(),
                            select,
                        )
                        .map_err(|error| error.to_string())
                    }
                    .and_then(|entry| {
                        entry
                            .read(case.password, |chunk| {
                                out.extend_from_slice(chunk);
                                Ok(())
                            })
                            .map_err(|error| error.to_string())
                    });
                    let what = format!("{what} {unverified:?} checked={checked}");
                    assert_eq!(read.is_err(), fails, "{what}: {read:?}");
                    if unverified == UnverifiedOutput::Emit || !fails {
                        assert_eq!((out.len(), sha256(&out)), (size, sha.to_string()), "{what}");
                    }
                    if fails && unverified == UnverifiedOutput::Emit && size != 0 {
                        let error = read.unwrap_err();
                        assert!(error.contains(&format!("{size} bytes written unverified")), "{what}: {error}");
                    }
                }
            }
        }
    }
}

/// `7z x -so` of a RAR through `RarSession::print_selected` under `DamagedInput::SevenZip`: with `Emit` the members
/// as `7z x` writes them, the one cut short reported failed; with `Withhold` only the members before it.
#[test]
fn rar_session_prints_what_7z_prints() {
    let dir = tempfile::tempdir().unwrap();
    for case in cases(dir.path()).into_iter().filter(|case| case.rar() && !case.rar_header_cut()) {
        let options = RarSessionOptions { damaged_input: DamagedInput::SevenZip, ..RarSessionOptions::default() };
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{} {unverified:?}", case.label);
            let mut session = RarSession::open(&case.archive, case.password, options.clone())
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            let all = session.select(|member| !member.is_directory()).unwrap();
            let print = RarPrintOptions { unverified_output: unverified, ..RarPrintOptions::default() };
            let mut output = Vec::new();
            let mut failed = Vec::new();
            session
                .print_selected(&all, &mut output, &print, |event| {
                    if matches!(event.outcome, RarOutcome::Failed(_)) {
                        failed.push(event.entry.name.clone());
                    }
                })
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            assert_eq!(failed, case.failed.map(str::to_string).into_iter().collect::<Vec<_>>(), "{what}: failed");
            let (emit, withhold) =
                PRINTS.iter().find(|(label, ..)| *label == case.label).map(|(_, e, w)| (e, w)).unwrap();
            let want = if unverified == UnverifiedOutput::Emit { emit } else { withhold };
            assert_eq!((output.len(), sha256(&output)), (want.0, want.1.to_string()), "{what}: bytes");
        }
    }
}

/// By default (every opt-in off) nothing changes: the member cut short is never written, a ZIP cut before its end
/// record doesn't open, and a cut RAR doesn't open in a `RarSession`.
#[test]
fn defaults_are_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    for case in cases(dir.path()) {
        let dest = dir.path().join(format!("{}-default", case.label));
        let result = extract::run_with_password(&case.archive, &defaults(&dest), case.password, |_| {});
        if let Some(failed) = case.failed {
            assert!(!dest.join(failed).exists(), "{}: {result:?}", case.label);
        }
        if !case.rar() {
            assert!(result.is_err(), "{}: {result:?}", case.label);
            assert!(
                SelectedEntry::open_cancelable_with_options(
                    &case.archive,
                    0,
                    case.password,
                    u64::MAX,
                    Cancellation::default(),
                    SelectOptions::new().unverified_output(UnverifiedOutput::Emit),
                )
                .is_err(),
                "{}",
                case.label
            );
        } else if !case.label.contains("miss") && !case.rar_header_cut() {
            assert!(
                RarSession::open(&case.archive, case.password, RarSessionOptions::default()).is_err(),
                "{}",
                case.label
            );
        }
    }
}
