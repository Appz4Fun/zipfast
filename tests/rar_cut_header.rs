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

//! What UnRAR 7.30 makes of a RAR archive cut short inside a header, under `DamagedInput::Salvage` (Prybar's UnRAR
//! mode): the fields of a RAR 4.x file header cut short, the file `unrar x -kb` keeps for one, a split member whose
//! next volume's header can't be read, a later volume cut inside its main header, and the zeros a RAR 2.9 match
//! before the history copies at the end of a member cut short. The expected values are UnRAR 7.30 beta 1 for Linux
//! x86-64 (`unrar lt`, `p -inul` and `x -kb` with `-y -p-`, in `docker --network none` with the cuts mounted read-only).

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, DamagedInput, Mode, Options, Overwrite};
use zipfast::rar5::HeaderCut;
use zipfast::rar5::session::{RarDecodeLimits, RarHeader, RarSession, RarSessionOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    fs::read(Path::new(FIXTURES).join(path)).unwrap()
}

fn options(dest: &Path, mode: Mode, damaged: DamagedInput, keep_broken: bool) -> Options {
    Options {
        mode,
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
        keep_broken,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: damaged,
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
        seven_zip_strict: false,
    }
}

/// A fresh folder holding `volumes` (name, bytes); the first is the archive.
struct Case {
    dir: tempfile::TempDir,
    archive: PathBuf,
}

fn case(volumes: &[(&str, &[u8])]) -> Case {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in volumes {
        fs::write(dir.path().join(name), bytes).unwrap();
    }
    let archive = dir.path().join(volumes[0].0);
    Case { dir, archive }
}

#[allow(clippy::result_large_err)]
fn session(case: &Case, damaged: DamagedInput) -> Result<RarSession, extract::RarRunError> {
    RarSession::open(&case.archive, None, RarSessionOptions { damaged_input: damaged, ..Default::default() })
}

fn sha256(bytes: &[u8]) -> String {
    zipfast::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The files under `dir` (relative path, length, SHA-256), sorted.
fn tree(dir: &Path) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        let Ok(entries) = fs::read_dir(&at) else { continue };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = fs::read(&path).unwrap();
                let name = path.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                out.push((name, bytes.len(), sha256(&bytes)));
            }
        }
    }
    out.sort();
    out
}

/// What a `RarSession` under `Salvage` writes of every member (with `keep_broken` or not), and how many failed.
fn session_tree(case: &Case, keep_broken: bool) -> (Vec<(String, usize, String)>, u64) {
    let mut session = session(case, DamagedInput::Salvage).unwrap();
    let selected = session.select(|_| true).unwrap();
    let out = case.dir.path().join(if keep_broken { "kb" } else { "x" });
    let opts = options(&out, Mode::Extract, DamagedInput::Salvage, keep_broken);
    let summary = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
    (tree(&out), summary.failed)
}

fn file(name: &str, len: usize, sha: &str) -> (String, usize, String) {
    (name.to_owned(), len, sha.to_owned())
}

const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn first_header(session: &RarSession) -> RarHeader<'_> {
    session.volume_headers(0).next().unwrap()
}

/// latest_winrar.rar's header for 1.txt (20 to 62: packed size at 27, unpacked size 31, host 35, CRC 36, time 40,
/// version 44, method 45, name size 46, attributes 48, name 52, extended time 57) cut short: a number not wholly
/// there reads as 0 and is not stepped over, so the next field is read from its bytes (cut at 33 the host is the
/// unpacked size's first byte, 5: "BeOS"); the name and the time's fraction bytes take what of them is there.
#[test]
fn a_cut_rar4_header_reads_its_fields_as_unrar_does() {
    let bytes = fixture("rar4/latest_winrar.rar");
    // (cut, packed, unpacked, host, CRC, version, method, name), as `unrar lt` lists them
    let cases: &[(usize, u64, u64, u8, u32, u8, u8, &str)] = &[
        (28, 0, 0, 17, 0, 0, 0, ""),
        (31, 17, 0, 0, 0, 0, 0, ""),
        (33, 17, 0, 5, 0, 0, 0, ""),
        (36, 17, 5, 2, 0, 0, 0, ""),
        (37, 17, 5, 2, 0, 192, 0, ""),
        (45, 17, 5, 2, 0xa0de_71c0, 29, 0, ""),
        (46, 17, 5, 2, 0xa0de_71c0, 29, 0x35, ""),
        (49, 17, 5, 2, 0xa0de_71c0, 29, 0x35, " "),
        (50, 17, 5, 2, 0xa0de_71c0, 29, 0x35, " "),
        (52, 17, 5, 2, 0xa0de_71c0, 29, 0x35, ""),
        (53, 17, 5, 2, 0xa0de_71c0, 29, 0x35, "1"),
        (58, 17, 5, 2, 0xa0de_71c0, 29, 0x35, "1.txt"),
    ];
    for &(cut, packed, unpacked, host, crc, version, method, name) in cases {
        let case = case(&[("t.rar", &bytes[..cut])]);
        let session = session(&case, DamagedInput::Salvage).unwrap();
        let header = first_header(&session);
        let raw = header.rar4_metadata().unwrap();
        assert_eq!(header.cut(), Some(HeaderCut::Header), "{cut}");
        assert_eq!(
            (header.packed_size(), header.unpacked_size(), raw.host, raw.stored_crc, raw.unpack_version, raw.method),
            (packed, Some(unpacked), host, crc, version, method),
            "{cut}"
        );
        assert_eq!(header.name(), name, "{cut}");
        // UnRAR's "1979-11-30 00:00:00": the DOS time not there reads as 0
        assert_eq!(raw.dos_time == 0, cut < 44, "{cut}");
        let member = session.entries().next().unwrap();
        assert_eq!((member.name(), member.packed_size()), (name, packed), "{cut}");
        let listing = extract::list_detailed_with_options(
            &case.archive,
            None,
            &options(case.dir.path(), Mode::Test, DamagedInput::Salvage, false),
        )
        .unwrap();
        assert_eq!((listing.entries[0].packed, listing.entries[0].size), (packed, unpacked), "{cut}");
    }
    // the extended time (flags 0xf000 at 57: mtime, one second on, three fraction bytes at 59): 10:07:18 at 58,
    // 10:07:19 at 59, then ,000018000 and ,002962000 as the fraction bytes come
    let mtime = |cut: usize| {
        let case = case(&[("t.rar", &bytes[..cut])]);
        let session = session(&case, DamagedInput::Salvage).unwrap();
        let time = first_header(&session).modified().unwrap();
        (time.seconds, time.nanos)
    };
    let (base, _) = mtime(58);
    assert_eq!(
        [mtime(58), mtime(59), mtime(60), mtime(61)],
        [(base, 0), (base + 1, 0), (base + 1, 18_000), (base + 1, 2_962_000)]
    );
    // a4-p-126.rar: f.txt's salt (57 to 65) cut short moves the reading to its end, and the extended time after it
    // (flags at 65, three fraction bytes at 67) comes as it is there: ,000017000 ,000452200 ,157738600
    let bytes = fixture("rar-long-password/a4-p-126.rar");
    let mtime = |cut: usize| {
        let case = case(&[("t.rar", &bytes[..cut])]);
        let session = session(&case, DamagedInput::Salvage).unwrap();
        let time = first_header(&session).modified().unwrap();
        (time.seconds, time.nanos)
    };
    let (base, _) = mtime(60);
    assert_eq!(
        [mtime(60), mtime(64), mtime(66), mtime(67), mtime(68), mtime(69), mtime(70)],
        [(base, 0), (base, 0), (base, 0), (base, 0), (base, 17_000), (base, 452_200), (base, 157_738_600)]
    );
}

/// `unrar x -kb` keeps a file for a RAR 4.x file header cut short, under what of its name is there, holding what
/// UnRAR decodes from no data (zeros): nothing from latest_winrar.rar's 1.txt (RAR 2.9), two bytes from
/// readme_154_normal.rar's README.md (RAR 1.5) cut a byte before its header's end. Nothing without a name, and
/// nothing without `keep_broken` (plain `unrar x`).
#[test]
fn keep_broken_keeps_what_unrar_decodes_of_a_cut_rar4_header() {
    let bytes = fixture("rar4/latest_winrar.rar");
    for (cut, name) in [(49, " "), (50, " "), (53, "1"), (58, "1.txt"), (61, "1.txt")] {
        let case = case(&[("t.rar", &bytes[..cut])]);
        assert_eq!(session_tree(&case, true), (vec![file(name, 0, EMPTY)], 1), "{cut}");
        assert_eq!(session_tree(&case, false), (vec![], 1), "{cut}");
    }
    for cut in [30, 40, 52] {
        let case = case(&[("t.rar", &bytes[..cut])]);
        assert_eq!(session_tree(&case, true), (vec![], 1), "{cut}");
    }
    let bytes = fixture("rar4-legacy/readme_154_normal.rar");
    let case = case(&[("t.rar", &bytes[..60])]);
    let readme = file("README.m", 2, "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7");
    assert_eq!(session_tree(&case, true), (vec![readme], 1));
    assert_eq!(session_tree(&case, false), (vec![], 1));
}

/// rar4-volumes/multi.part1.rar to part3 with part2 cut short at `len`.
fn multi(len: usize) -> Case {
    let part2 = fixture("rar4-volumes/multi.part2.rar");
    case(&[
        ("multi.part1.rar", &fixture("rar4-volumes/multi.part1.rar")),
        ("multi.part2.rar", &part2[..len]),
        ("multi.part3.rar", &fixture("rar4-volumes/multi.part3.rar")),
    ])
}

const FILE1: (&str, usize, &str) =
    ("file1.txt", 18, "a56c9d9d7c000206a6b29db5cdfd754645a10d5ad419c8298f7530a550dfbd87");
const FILE3: (&str, usize, &str) =
    ("file3.txt", 18, "e61bda8939997643d5c9eeb13d5758cf8a77cfb32e2ce4e8f83eb8e36066d772");

/// file2.txt is split from part1 into part2 (main header 7 to 20, continuation header 20 to 66, then its data);
/// file3.txt is in part3. Part2 cut anywhere before file2.txt's data, inside its main header (UnRAR: "Main archive
/// header is corrupt") or its continuation header, or after the main header: UnRAR ends file2.txt where part1's data
/// does, decoded as a member cut short (zeros read on: 6,238 bytes, kept with `-kb`), joins nothing of part3 to it,
/// and goes on to extract file3.txt. Cut inside the data (80) it decodes the 14 bytes there too.
#[test]
fn a_split_member_ends_where_its_next_volume_cannot_be_read() {
    let file1 = file(FILE1.0, FILE1.1, FILE1.2);
    let file3 = file(FILE3.0, FILE3.1, FILE3.2);
    let file2 = file("file2.txt", 6238, "82f18ab53f5420440009ec32b6eec0130b63a68d89ebca1487c5baea76778938");
    for len in [7, 12, 20, 25, 40, 60, 64] {
        let case = multi(len);
        assert_eq!(session_tree(&case, true), (vec![file1.clone(), file2.clone(), file3.clone()], 1), "{len}");
        assert_eq!(session_tree(&case, false), (vec![file1.clone(), file3.clone()], 1), "{len}");
    }
    let file2 = file("file2.txt", 6257, "d6360327b8b983541822b3a1d6b55521d9a07092e80de5ecff21add9488b1dd0");
    assert_eq!(session_tree(&multi(80), true), (vec![file1, file2, file3], 1));
    // the default reading is unchanged: the cut volume fails the catalogue
    for len in [12, 40] {
        assert!(session(&multi(len), DamagedInput::Refuse).is_err(), "{len}");
    }
}

/// rar5-threads/big.part02.rar cut inside its main header (12, 20) or a.txt's continuation header (30, 45): UnRAR
/// goes on to big.part03.rar and extracts s.txt, and joins nothing of part03 to a.txt, which fails (`x` writes only
/// s.txt).
#[test]
fn a_rar5_volume_cut_in_its_headers_is_read_past() {
    let s = file("s.txt", 6, "4c47b3e816fbe7d40cef9f665ba8f0be1ae68b5e8e7ed70f5b6bab7f70528e8f");
    let part2 = fixture("rar5-threads/big.part02.rar");
    for len in [12, 20, 30, 45] {
        let case = case(&[
            ("big.part01.rar", &fixture("rar5-threads/big.part01.rar")),
            ("big.part02.rar", &part2[..len]),
            ("big.part03.rar", &fixture("rar5-threads/big.part03.rar")),
        ]);
        assert_eq!(session_tree(&case, false), (vec![s.clone()], 1), "{len}");
        let (kept, failed) = session_tree(&case, true);
        assert_eq!(failed, 1, "{len}");
        assert_eq!(kept.len(), 2, "{len}: {kept:?}");
        assert_eq!(kept[1], s, "{len}");
        // UnRAR keeps 1,867,777 bytes of a.txt: part01's data decoded as a member cut short (zipfast's RAR 5.0 tail
        // can differ in its last bytes), far short of the 4,400,000 a join of part03 would give
        assert_eq!(kept[0].0, "a.txt", "{len}");
        assert!((1_867_445..=1_867_777).contains(&kept[0].1), "{len}: {}", kept[0].1);
    }
}

/// rar4-volumes/multi.part1.rar cut inside file2.txt's data (RAR 2.9): UnRAR's decoding over the zeros past the end
/// ends in a match reaching before the history, which copies the zeros its window holds there ("\0\0\0" at the end
/// of the 34 and 99 bytes `unrar p` prints and `x -kb` keeps). The runner and a `RarSession` keep the same bytes.
#[test]
fn a_cut_rar29_member_ends_with_the_zeros_a_match_before_the_history_copies() {
    let bytes = fixture("rar4-volumes/multi.part1.rar");
    for (cut, len, sha) in [
        (219, 34, "51ec9adbabbee9456ada7094d9427934175448cefcf4e81bcf9ddc16091ea045"),
        (272, 99, "85a36cc6e77852ec6b56b19d4fc7f4837a63f767128dd867268e0c3803509487"),
    ] {
        let case = case(&[("multi.part1.rar", &bytes[..cut])]);
        let want = vec![file(FILE1.0, FILE1.1, FILE1.2), file("file2.txt", len, sha)];
        assert_eq!(session_tree(&case, true), (want.clone(), 1), "{cut}");
        let out = case.dir.path().join("run");
        let summary =
            extract::run(&case.archive, &options(&out, Mode::Extract, DamagedInput::Salvage, true), |_| {}).unwrap();
        assert_eq!(summary.errors.len(), 1, "{cut}: {:?}", summary.errors);
        assert_eq!(tree(&out), want, "{cut}");
    }
}
