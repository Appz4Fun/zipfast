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

//! A regular file where a folder member goes fails only that member, as it does a file member, on every route:
//! RAR 4.x, RAR 5.0, tar (read in place and staged), cpio, xar, ISO 9660, WIM, ZIP and 7z. The file is never
//! replaced, and the members after it still extract.

mod common;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use common::FileSpec;
use zipfast::extract::{self, Mode, Options, Overwrite};

const IN_THE_WAY: &str = "a file is in the way";

fn options(dest: &Path) -> Options {
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
        salvage_truncated_zip: false,
    }
}

fn fixture(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(path)
}

fn tar(members: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, kind, body) in members {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let mut octal = |at: usize, width: usize, v: u64| {
            h[at..at + width].copy_from_slice(format!("{v:0w$o}\0", w = width - 1).as_bytes());
        };
        octal(100, 8, if kind == b'5' { 0o755 } else { 0o644 });
        octal(108, 8, 0);
        octal(116, 8, 0);
        octal(124, 12, body.len() as u64);
        octal(136, 12, 1_577_934_245);
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend(h);
        out.extend(body);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend([0u8; 1024]);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

/// A RAR 4.x archive of a folder `d` and then a file `z`.
fn rar4() -> Vec<u8> {
    let hash = zipfast::crc32::hash;
    let block = |kind: u8, flags: u16, body: &[u8]| {
        let mut bytes = vec![0, 0, kind];
        bytes.extend(flags.to_le_bytes());
        bytes.extend(((body.len() + 7) as u16).to_le_bytes());
        bytes.extend(body);
        let crc = hash(&bytes[2..]) as u16;
        bytes[..2].copy_from_slice(&crc.to_le_bytes());
        bytes
    };
    let member = |name: &[u8], data: &[u8], flags: u16, attributes: u32| {
        let mut body = Vec::new();
        body.extend((data.len() as u32).to_le_bytes());
        body.extend((data.len() as u32).to_le_bytes());
        body.push(3);
        body.extend(hash(data).to_le_bytes());
        body.extend(0x50221884u32.to_le_bytes());
        body.extend([20, 0x30]);
        body.extend((name.len() as u16).to_le_bytes());
        body.extend(attributes.to_le_bytes());
        body.extend(name);
        let mut bytes = block(0x74, flags | 0x8000, &body);
        bytes.extend(data);
        bytes
    };
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    bytes.extend(member(b"d", b"", 0xe0, 0o040755));
    bytes.extend(member(b"z", b"z\n", 0, 0o100644));
    bytes.extend(block(0x7b, 0x4000, &[]));
    bytes
}

/// One route's case: the archive, the folder member a file is put in the way of, and a member after it that must
/// still come out.
struct Case {
    name: &'static str,
    archive: PathBuf,
    folder: &'static str,
    later: &'static str,
}

#[test]
fn a_file_where_a_folder_member_goes_fails_only_that_member() {
    let tmp = tempfile::tempdir().unwrap();
    let write = |name: &str, bytes: Vec<u8>| {
        let path = tmp.path().join(name);
        fs::write(&path, bytes).unwrap();
        path
    };
    let folder_tar = tar(&[("d/", b'5', b""), ("d/sub/", b'5', b""), ("z", b'0', b"z\n")]);
    let mut iso = Vec::new();
    flate2::read::GzDecoder::new(fs::File::open(fixture("iso9660/rr-joliet.iso.gz")).unwrap())
        .read_to_end(&mut iso)
        .unwrap();
    let rar5 = common::archive(&[
        FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("d", b"") },
        FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("d/sub", b"") },
        FileSpec::new("z", b"z\n"),
    ]);
    let cases = [
        Case { name: "rar4", archive: write("a4.rar", rar4()), folder: "d", later: "z" },
        Case { name: "rar5", archive: write("a5.rar", rar5), folder: "d", later: "z" },
        Case { name: "tar", archive: write("a.tar", folder_tar.clone()), folder: "d", later: "z" },
        Case { name: "tgz", archive: write("a.tgz", gzip(&folder_tar)), folder: "d", later: "z" },
        Case { name: "cpio", archive: fixture("cpio/newc.cpio"), folder: "d", later: "a" },
        Case { name: "xar", archive: fixture("xar/bsd-stored.xar"), folder: "d", later: "big" },
        Case {
            name: "iso",
            archive: write("rr-joliet.iso", iso),
            folder: "dir",
            later: "LongFileName With Spaces.txt",
        },
        Case { name: "wim", archive: fixture("wim/lzx.wim"), folder: "empty-dir", later: "hello.txt" },
        Case { name: "zip", archive: fixture("links/under-link-folder.zip"), folder: "real", later: "z.txt" },
        Case { name: "7z", archive: fixture("links/under-link-folder.7z"), folder: "real", later: "z.txt" },
    ];
    for case in cases {
        let name = case.name;
        let dest = tmp.path().join(format!("out-{name}"));
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join(case.folder), b"mine").unwrap();
        let s = extract::run(&case.archive, &options(&dest), |_| {})
            .unwrap_or_else(|e| panic!("{name}: the run stopped: {e}"));
        let blocked: Vec<_> =
            s.errors.iter().filter(|e| e.starts_with(case.folder) && e.ends_with(IN_THE_WAY)).collect();
        assert!(!blocked.is_empty(), "{name}: {:?}", s.errors);
        assert!(
            s.errors.iter().all(|e| e.ends_with(IN_THE_WAY)
                || e.ends_with("a symlink is in the way")
                || !e.starts_with(case.folder)),
            "{name}: {:?}",
            s.errors
        );
        assert_eq!(fs::read(dest.join(case.folder)).unwrap(), b"mine", "{name}: the file in the way was replaced");
        assert!(fs::symlink_metadata(dest.join(case.later)).is_ok(), "{name}: {} missing: {:?}", case.later, s.errors);
    }
}

/// A file the archive itself placed earlier, where a later folder member goes: that folder and the folder below it
/// fail, and the run goes on (tar read in place and staged, ZIP and RAR 5.0).
#[test]
fn a_file_member_before_a_folder_of_its_name_fails_only_the_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = tar(&[("d", b'0', b"file"), ("d/", b'5', b""), ("d/sub/", b'5', b""), ("z", b'0', b"z\n")]);
    let rar5 = common::archive(&[
        FileSpec::new("d", b"file"),
        FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("d", b"") },
        FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("d/sub", b"") },
        FileSpec::new("z", b"z\n"),
    ]);
    for (name, bytes) in [("a.tar", tar_bytes.clone()), ("a.tgz", gzip(&tar_bytes)), ("a.rar", rar5)] {
        let archive = tmp.path().join(name);
        fs::write(&archive, bytes).unwrap();
        let dest = tmp.path().join(format!("out-{name}"));
        let s = extract::run(&archive, &options(&dest), |_| {}).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(s.errors.len(), 2, "{name}: {:?}", s.errors);
        assert!(s.errors.iter().all(|e| e.starts_with("d") && e.ends_with(IN_THE_WAY)), "{name}: {:?}", s.errors);
        assert_eq!(fs::read(dest.join("d")).unwrap(), b"file", "{name}");
        assert_eq!(fs::read(dest.join("z")).unwrap(), b"z\n", "{name}");
    }
}
