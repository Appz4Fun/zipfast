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

//! `rar5::frame`: RAR 5.0 and RAR 4.x header blocks read and written back byte for byte on rar-made archives, and
//! archives written from scratch with them extract.

use std::path::{Path, PathBuf};
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::frame::{self, MainHeader, rar4};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Every RAR file under the given directories.
fn rar_files(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in dirs.iter().filter(|d| d.is_dir()) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.extend(rar_files(&[path]));
            } else if path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                let e = e.to_ascii_lowercase();
                e.len() == 3 && e.starts_with('r') && (e == "rar" || e[1..].bytes().all(|c| c.is_ascii_digit()))
            }) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn corpus() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> =
        ["rar4", "rar4-volumes", "rar4-archiver", "rar4-legacy", "rar4-lz", "rar4-rar300", "rar4-unrar"]
            .iter()
            .map(|d| Path::new(FIXTURES).join(d))
            .collect();
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(Path::new(&home).join("prybar-refs/rar4-reference/in"));
        dirs.push(Path::new(&home).join("git.xbmc4lyfe/zipfast-test-fixtures/rar5-tail"));
    }
    if let Some(z) = std::env::var_os("ZIPFAST_Z_FIXTURES") {
        dirs.push(PathBuf::from(z));
    }
    rar_files(&dirs)
}

/// Each block of every RAR 4.x archive at hand, read and written back: the same bytes, and the stored checksum is
/// [`rar4::header_crc`]. A volume's end block carries the CRC32 of the bytes before it.
#[test]
fn rar4_blocks_round_trip_byte_for_byte() {
    let (mut files, mut blocks) = (0, 0);
    for path in corpus() {
        let bytes = std::fs::read(&path).unwrap();
        let Some(start) = bytes.windows(7).position(|w| w == rar4::MARKER) else { continue };
        files += 1;
        let mut at = start + 7;
        while let Ok(Some(b)) = rar4::read_block(&bytes, at) {
            let header = b.header(&bytes);
            assert_eq!(rar4::header_crc(header), Some(u16::from_le_bytes([header[0], header[1]])));
            let written = match b.head_type {
                rar4::HEAD_MAIN => {
                    let main = rar4::MainHeader::parse(header).unwrap();
                    Some(main.encode().unwrap())
                }
                rar4::HEAD_FILE | rar4::HEAD_SERVICE => {
                    Some(rar4::FileHeader::parse(header).unwrap().encode().unwrap())
                }
                rar4::HEAD_END => {
                    let end = rar4::EndOfArchive::parse(header).unwrap();
                    if let Some(crc) = end.data_crc {
                        assert_eq!(crc, zipfast::crc32::hash(&bytes[..at]), "{}", path.display());
                    }
                    Some(end.encode().unwrap())
                }
                _ => None,
            };
            if let Some(written) = written {
                assert_eq!(written, header, "{} block at {at}", path.display());
                blocks += 1;
            }
            if b.head_type == rar4::HEAD_END || b.head_type == rar4::HEAD_MAIN && b.flags & rar4::MHD_PASSWORD != 0 {
                break;
            }
            let Some(next) = b.data_end().and_then(|e| usize::try_from(e).ok()) else { break };
            at = next;
        }
    }
    assert!(files >= 10 && blocks >= 30, "{files} files, {blocks} blocks");
}

/// The main and end headers of every RAR 5.0 volume at hand, read and written back byte for byte.
#[test]
fn rar5_main_and_end_headers_round_trip_byte_for_byte() {
    let mut volumes = 0;
    for path in corpus() {
        let bytes = std::fs::read(&path).unwrap();
        if !bytes.starts_with(frame::SIGNATURE) {
            continue;
        }
        let Ok(Some(b)) = frame::read_block(&bytes, 8) else { continue };
        if b.kind != 1 {
            continue; // encrypted headers
        }
        let main = MainHeader::parse(&bytes[8..]).unwrap();
        assert_eq!(main.encode(), b.header(&bytes), "{}", path.display());
        // The end header: the last block before any zero padding.
        let end = (bytes.len().saturating_sub(4096)..bytes.len()).find_map(|at| {
            let b = frame::read_block(&bytes, at).ok()??;
            (b.kind == 5 && bytes[b.header_end..].iter().all(|&c| c == 0)).then_some(b)
        });
        if let Some(end) = end {
            let more = bytes[end.fields.clone()][0] & 1 != 0;
            assert_eq!(frame::end_of_archive(more), end.header(&bytes), "{}", path.display());
        }
        volumes += 1;
    }
    assert!(volumes > 0);
}

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
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
        seven_zip_strict: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

/// A stored file header for `name` and `data` (one part, or part of a split file when `split` is given).
fn stored(name: &str, part: &[u8], whole: &[u8], split: u16, crc: u32) -> Vec<u8> {
    let (field, unicode) = rar4::unicode_name_field(name);
    rar4::FileHeader {
        head_type: rar4::HEAD_FILE,
        flags: split | if unicode { rar4::LHD_UNICODE } else { 0 },
        packed_size: part.len() as u64,
        unpacked_size: whole.len() as u64,
        host_os: 2,
        crc,
        dos_time: 0x5a21_7c00,
        unpack_version: 29,
        method: 0x30,
        attributes: 0x20,
        name: field,
        salt: None,
        ext_time: None,
        rest: Vec::new(),
    }
    .encode()
    .unwrap()
}

/// A RAR 4.x archive written from scratch with these blocks lists and extracts, Unicode names included.
#[test]
fn a_written_rar4_archive_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("made.rar");
    let data = b"hello from a RAR 4.x archive written by zipfast";
    let name = "dir/na\u{ef}ve \u{6771}\u{4eac} \u{1f600}.txt";
    let mut archive = rar4::MARKER.to_vec();
    archive.extend(rar4::MainHeader::new(0).encode().unwrap());
    archive.extend(stored(name, data, data, 0, zipfast::crc32::hash(data)));
    archive.extend_from_slice(data);
    archive.extend(stored("plain.txt", b"x", b"x", 0, zipfast::crc32::hash(b"x")));
    archive.push(b'x');
    archive.extend(rar4::EndOfArchive::new(false).encode().unwrap());
    std::fs::write(&path, &archive).unwrap();
    let names: Vec<String> = extract::list(&path).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, [name, "plain.txt"]);
    let out = dir.path().join("out");
    extract::run(&path, &options(&out), |_| {}).unwrap();
    assert_eq!(std::fs::read(out.join(name)).unwrap(), data);
}

/// A file split over two RAR 4.x volumes written from scratch extracts: continuation flags, the part checksum, the
/// volume flags and the end blocks with their data CRC32 and volume number.
#[test]
fn a_written_rar4_volume_set_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 + i / 13) as u8).collect();
    let (one, two) = data.split_at(3000);
    let mut first = rar4::MARKER.to_vec();
    first.extend(
        rar4::MainHeader::new(rar4::MHD_VOLUME | rar4::MHD_NEWNUMBERING | rar4::MHD_FIRSTVOLUME).encode().unwrap(),
    );
    first.extend(stored("movie.bin", one, &data, rar4::LHD_SPLIT_AFTER, zipfast::crc32::hash(one)));
    first.extend_from_slice(one);
    let crc = zipfast::crc32::hash(&first);
    first.extend(rar4::EndOfArchive::volume(true, crc, 0).encode().unwrap());
    let mut second = rar4::MARKER.to_vec();
    second.extend(rar4::MainHeader::new(rar4::MHD_VOLUME | rar4::MHD_NEWNUMBERING).encode().unwrap());
    second.extend(stored("movie.bin", two, &data, rar4::LHD_SPLIT_BEFORE, zipfast::crc32::hash(&data)));
    second.extend_from_slice(two);
    let crc = zipfast::crc32::hash(&second);
    second.extend(rar4::EndOfArchive::volume(false, crc, 1).encode().unwrap());
    std::fs::write(dir.path().join("set.part1.rar"), &first).unwrap();
    std::fs::write(dir.path().join("set.part2.rar"), &second).unwrap();
    let out = dir.path().join("out");
    extract::run(&dir.path().join("set.part1.rar"), &options(&out), |_| {}).unwrap();
    assert_eq!(std::fs::read(out.join("movie.bin")).unwrap(), data);
}

/// A patched field and a resealed checksum: what rebuilding another volume's headers takes.
#[test]
fn patched_headers_reseal() {
    let mut header = rar4::FileHeader::parse(&stored("a.bin", b"abc", b"abcdef", rar4::LHD_SPLIT_AFTER, 1)).unwrap();
    header.crc = 0x1234_5678;
    let mut bytes = header.encode().unwrap();
    bytes[0] ^= 0xff;
    rar4::seal(&mut bytes).unwrap();
    assert_eq!(rar4::FileHeader::parse(&bytes).unwrap(), header);
    // RAR 5.0: patch a same-width field and reseal.
    let mut end = frame::end_of_archive(true);
    end[7] = 0;
    frame::reseal_header(&mut end).unwrap();
    assert_eq!(end, frame::end_of_archive(false));
    // An oversized name or an inconsistent flag is refused, not written wrong.
    header.name = vec![b'a'; 70_000];
    assert!(header.encode().is_err());
    header.name = b"a".to_vec();
    header.packed_size = 5 << 32;
    assert!(header.encode().is_err());
    header.flags |= rar4::LHD_LARGE;
    let large = header.encode().unwrap();
    assert_eq!(rar4::FileHeader::parse(&large).unwrap().packed_size, 5 << 32);
    assert_eq!(rar4::read_block(&large, 0).unwrap().unwrap().data_len, 5 << 32);
}

/// RAR 2.x headers with an embedded comment: the main header's checksum covers its first 13 bytes, a file header's
/// its fields before the comment. Written that way they read back, and zipfast's own map walk accepts them.
#[test]
fn rar2_commented_headers_are_checksummed_over_what_precedes_the_comment() {
    let comment = rar4::block(0x75, 0, b"\x05\x00\x0f\x30\x00\x00hello").unwrap();
    let mut main = rar4::MainHeader::new(rar4::MHD_COMMENT);
    main.rest = comment.clone();
    let main_bytes = main.encode().unwrap();
    assert_eq!(u16::from_le_bytes([main_bytes[0], main_bytes[1]]), zipfast::crc32::hash(&main_bytes[2..13]) as u16);
    assert_eq!(rar4::MainHeader::parse(&main_bytes).unwrap(), main);
    let data = b"commented member data";
    let mut file = rar4::FileHeader::parse(&stored("a.bin", data, data, 0, zipfast::crc32::hash(data))).unwrap();
    file.flags |= rar4::LHD_COMMENT;
    file.rest = b"\x05\x00\x0f\x30\x00\x00file comment".to_vec();
    let file_bytes = file.encode().unwrap();
    let fields_end = file_bytes.len() - file.rest.len();
    assert_eq!(
        u16::from_le_bytes([file_bytes[0], file_bytes[1]]),
        zipfast::crc32::hash(&file_bytes[2..fields_end]) as u16
    );
    assert_eq!(rar4::FileHeader::parse(&file_bytes).unwrap(), file);
    // The comment is not covered: changing it leaves the header readable.
    let mut other = file_bytes.clone();
    *other.last_mut().unwrap() ^= 0xff;
    assert!(rar4::read_block(&other, 0).unwrap().is_some());
    // A checksum over the whole header is not what RAR 2.x writes.
    let mut whole = main_bytes.clone();
    let crc = zipfast::crc32::hash(&whole[2..]) as u16;
    whole[..2].copy_from_slice(&crc.to_le_bytes());
    assert!(rar4::read_block(&whole, 0).is_err());
    // zipfast's map walk reads the archive.
    let mut bytes = rar4::MARKER.to_vec();
    bytes.extend(&main_bytes);
    bytes.extend(&file_bytes);
    bytes.extend_from_slice(data);
    bytes.extend(rar4::EndOfArchive::new(false).encode().unwrap());
    let map = zipfast::map::MemberMap::from_volume(&bytes, zipfast::map::MapOptions::new("old.rar")).unwrap();
    assert_eq!(map.end, zipfast::map::VolumeEnd::Complete);
    assert_eq!(map.members.len(), 1);
}
