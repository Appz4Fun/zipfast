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

//! `extract::Options::keep_broken`: a file that fails once its output was created keeps what was written (or stays
//! empty), as 7-Zip 26.06 `x`/`e` and UnRAR 7.30 `-kb` do; by default it is removed.

mod common;

use common::FileSpec;
use std::fs;
use std::path::Path;
use zipfast::extract::{self, Mode, Options, Overwrite};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn options(dest: &Path, keep: bool, threads: usize) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(threads),
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
        keep_broken: keep,
    }
}

/// prybar P2 (`7z x multi_broken.part1.rar`): its second volume is missing, so `file2.txt` never gets its data. 7-Zip
/// leaves it empty and exits 2; zipfast keeps it only when asked.
#[test]
fn a_member_cut_off_by_a_missing_volume_stays_empty_when_asked() {
    let path = Path::new(FIXTURES).join("rar4/multi_broken.part1.rar");
    let dir = tempfile::tempdir().unwrap();
    for (keep, threads) in [(true, 1), (true, 4), (false, 1), (false, 4)] {
        let out = dir.path().join(format!("{keep}-{threads}"));
        let summary = extract::run(&path, &options(&out, keep, threads), |_| {}).unwrap();
        assert!(!summary.errors.is_empty(), "{keep} {threads}: file2.txt fails");
        assert_eq!(fs::read(out.join("file1.txt")).unwrap().len(), 18, "{keep} {threads}");
        let kept = fs::metadata(out.join("file2.txt"));
        assert_eq!(kept.is_ok(), keep, "{keep} {threads}: file2.txt kept only when asked");
    }
}

/// prybar P2 (`7z x r5misc.rar`: "CRC Failed : blake.bin", the file kept): a stored file whose data is damaged keeps
/// every byte written, with its time set, when asked; small (checked whole on a worker) and large alike.
#[test]
fn a_file_failing_its_checksum_keeps_what_was_written_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    for len in [3_000usize, 3 << 20] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + i / 251) as u8).collect();
        let mut rar = common::archive(&[FileSpec::new("bad.bin", &data)]);
        // flip a byte in the stored data
        let at = rar.windows(64).position(|w| w == &data[1000..1064]).unwrap();
        rar[at] ^= 0x55;
        let path = dir.path().join(format!("{len}.rar"));
        fs::write(&path, &rar).unwrap();
        for (keep, threads) in [(true, 1), (true, 4), (false, 1), (false, 4)] {
            let out = dir.path().join(format!("{len}-{keep}-{threads}"));
            let summary = extract::run(&path, &options(&out, keep, threads), |_| {}).unwrap();
            assert_eq!(summary.errors.len(), 1, "{len} {keep} {threads}: {:?}", summary.errors);
            match fs::read(out.join("bad.bin")) {
                Ok(kept) => {
                    assert!(keep, "{len} {threads}: removed by default");
                    assert_eq!(kept.len(), len, "{len} {threads}");
                    let mut want = data.clone();
                    want[1000] ^= 0x55;
                    assert!(kept == want, "{len} {threads}: what was decoded, damage included");
                }
                Err(_) => assert!(!keep, "{len} {threads}: kept when asked"),
            }
        }
    }
}

/// prybar P2 (`7z x s.zip.001` without `.002`: "Unexpected end of data : c.bin", kept): the entry cut off by the
/// missing volume keeps what was written when asked.
#[test]
fn a_zip_entry_cut_off_by_a_missing_volume_keeps_what_was_written_when_asked() {
    let path = Path::new(FIXTURES).join("zip-bytesplit-streamed/s.zip.001");
    let dir = tempfile::tempdir().unwrap();
    for keep in [true, false] {
        let out = dir.path().join(format!("{keep}"));
        let summary = extract::run(&path, &options(&out, keep, 1), |_| {}).unwrap();
        assert!(!summary.errors.is_empty(), "{keep}");
        assert_eq!(fs::read(out.join("a.txt")).unwrap().len(), 800, "{keep}");
        assert_eq!(fs::metadata(out.join("c.bin")).is_ok(), keep, "{keep}: c.bin kept only when asked");
        if keep {
            // c.bin is stored from byte 168 of the first piece to its end: those bytes, as 7-Zip keeps them
            let first = fs::read(&path).unwrap();
            assert!(fs::read(out.join("c.bin")).unwrap() == first[168..], "c.bin holds what the first piece has");
        }
    }
}

/// prybar P2 (`7z x -pwrong encrypted_files.7z`): `baz.txt` fails its CRC ("CRC Failed in encrypted file. Wrong
/// password?") and 7-Zip keeps it, garbage and all; `foo.txt` fails to decode ("Data Error") and is not kept. The
/// unencrypted files come out either way.
#[test]
fn a_7z_file_failing_its_crc_under_a_wrong_password_is_kept_when_asked() {
    let path = Path::new(FIXTURES).join("7z/encrypted_files.7z");
    let dir = tempfile::tempdir().unwrap();
    for keep in [true, false] {
        let out = dir.path().join(format!("{keep}"));
        let summary = extract::run_with_password(&path, &options(&out, keep, 1), Some("wrong"), |_| {}).unwrap();
        assert_eq!(summary.errors.len(), 2, "{keep}: {:?}", summary.errors);
        assert!(out.join("bar.txt").is_file() && out.join("7zFormat.txt").is_file(), "{keep}");
        assert_eq!(out.join("baz.txt").is_file(), keep, "{keep}: baz.txt kept only when asked");
        assert!(!out.join("foo.txt").exists(), "{keep}: a data error is not kept");
    }
}
