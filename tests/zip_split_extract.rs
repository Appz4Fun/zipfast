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

//! Listing, testing and extracting Info-ZIP spanned sets (`name.z01`, ..., `name.zip`) from their `.zip`, as 7-Zip
//! does. The expected listings and contents are 7-Zip 26.06's (`7z l -slt`, `7z x`) for the real Info-ZIP sets in
//! `tests/fixtures/zip-split`.

mod split_zip_builder;

use std::fs;
use std::path::{Path, PathBuf};

use split_zip_builder::{Entry, Layout, aes_entry, data, split_zip, zipcrypto};
use zipfast::extract::{self, Mode, Options, Overwrite};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip-split").join(name)
}

fn options(dest: &Path, mode: Mode) -> Options {
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
        keep_broken: false,
        attempt_continued_members: false,
        damaged_input: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// 7-Zip's listing of each real set: (path, size, packed size, CRC, directory).
fn reference(set: &str) -> Vec<(&'static str, u64, u64, Option<u32>, bool)> {
    match set {
        "stored" => vec![
            ("a.bin", 140_000, 140_000, Some(0x329A_E6F9), false),
            ("dir", 0, 0, None, true),
            ("dir/b.txt", 640, 640, Some(0x84A8_513C), false),
        ],
        "deflated" => {
            vec![("c.txt", 93_336, 70_626, Some(0x80C0_5F59), false), ("dir/b.txt", 640, 25, Some(0x84A8_513C), false)]
        }
        "crypt" => vec![("s.bin", 66_000, 66_012, Some(0x02E5_71C8), false)],
        _ => unreachable!(),
    }
}

fn listed(path: &Path) -> Vec<(String, u64, u64, Option<u32>, bool)> {
    extract::list(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .into_iter()
        .map(|e| (e.name.trim_end_matches('/').to_owned(), e.size, e.packed, e.crc32.filter(|_| !e.dir), e.dir))
        .collect()
}

fn reference_owned(set: &str) -> Vec<(String, u64, u64, Option<u32>, bool)> {
    reference(set).into_iter().map(|(n, s, p, c, d)| (n.to_owned(), s, p, c, d)).collect()
}

/// Copies a real set into `dir`, renaming its volumes with `stem` and upper-cased extensions when `upper`.
fn copy_set(set: &str, dir: &Path, stem: &str, upper: bool) -> PathBuf {
    let mut last = None;
    for entry in fs::read_dir(fixture("")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        let Some(ext) = name.strip_prefix(&format!("{set}.")) else { continue };
        let ext = if upper { ext.to_ascii_uppercase() } else { ext.to_owned() };
        let to = dir.join(format!("{stem}.{ext}"));
        fs::copy(&path, &to).unwrap();
        if ext.eq_ignore_ascii_case("zip") {
            last = Some(to);
        }
    }
    last.unwrap()
}

#[test]
fn real_sets_list_as_7zip_lists_them_from_the_zip_or_the_z01() {
    for set in ["stored", "deflated", "crypt"] {
        assert_eq!(listed(&fixture(&format!("{set}.zip"))), reference_owned(set), "{set}");
        assert_eq!(listed(&fixture(&format!("{set}.z01"))), reference_owned(set), "{set} from .z01");
        let detailed = extract::list_detailed(&fixture(&format!("{set}.zip")), None).unwrap();
        assert!(!detailed.unexpected_end(), "{set}");
    }
    // the volume names follow the `.zip`'s case
    let dir = tempfile::tempdir().unwrap();
    let upper = copy_set("stored", dir.path(), "UP", true);
    assert_eq!(listed(&upper), reference_owned("stored"));
}

#[test]
fn real_sets_test_and_extract_whole() {
    for set in ["stored", "deflated", "crypt"] {
        let password = (set == "crypt").then_some("password");
        let dir = tempfile::tempdir().unwrap();
        let tested = extract::run_with_password(
            &fixture(&format!("{set}.zip")),
            &options(dir.path(), Mode::Test),
            password,
            |_| {},
        )
        .unwrap();
        assert!(tested.errors.is_empty(), "{set}: {:?}", tested.errors);
        let out = dir.path().join("out");
        let s = extract::run_with_password(
            &fixture(&format!("{set}.zip")),
            &options(&out, Mode::Extract),
            password,
            |_| {},
        )
        .unwrap();
        assert!(s.errors.is_empty(), "{set}: {:?}", s.errors);
        for (name, size, _, crc, is_dir) in reference(set) {
            let path = out.join(name);
            if is_dir {
                assert!(path.is_dir(), "{set}: {name}");
                continue;
            }
            let bytes = fs::read(&path).unwrap();
            assert_eq!((bytes.len() as u64, Some(crc32fast::hash(&bytes))), (size, crc), "{set}: {name}");
        }
    }
}

#[test]
fn zipcrypto_needs_its_password_across_pieces() {
    let dir = tempfile::tempdir().unwrap();
    for password in [None, Some("wrong")] {
        let s = extract::run_with_password(&fixture("crypt.zip"), &options(dir.path(), Mode::Test), password, |_| {})
            .unwrap();
        assert_eq!(s.errors.len(), 1, "{password:?}: {:?}", s.errors);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn the_checked_route_and_inspection_read_the_set_too() {
    use zipfast::extract::Cancellation;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let report = extract::run_with_policy(
        &fixture("crypt.zip"),
        &options(&out, Mode::Extract),
        Some("password"),
        &Cancellation::default(),
        &Default::default(),
        |_: extract::RunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed()), (1, 0));
    assert_eq!(crc32fast::hash(&fs::read(out.join("s.bin")).unwrap()), 0x02E5_71C8);
    let inspection = extract::inspect_cancelable(&fixture("stored.zip"), None, &Cancellation::default());
    assert!(inspection.is_ok(), "{:?}", inspection.err());
}

#[test]
fn a_missing_middle_volume_lists_every_member_and_fails_only_those_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    let zip = copy_set("stored", dir.path(), "gap", false);
    fs::remove_file(dir.path().join("gap.z02")).unwrap();
    // The directory is in the `.zip`, so 7-Zip still lists every member and reports the missing volume.
    let detailed = extract::list_detailed(&zip, None).unwrap();
    assert!(detailed.unexpected_end());
    assert_eq!(detailed.missing_volume.as_deref(), Some(dir.path().join("gap.z02").as_path()));
    assert_eq!(detailed.entries.len(), 3);
    let out = dir.path().join("out");
    let s = extract::run(&zip, &options(&out, Mode::Extract), |_| {}).unwrap();
    // a.bin crosses the missing volume; dir/b.txt is whole in the `.zip`
    assert!(s.errors.iter().any(|e| e.contains("a.bin") && e.contains("gap.z02")), "{:?}", s.errors);
    assert!(s.errors.iter().all(|e| !e.contains("b.txt")), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("dir/b.txt")).unwrap(), b"hello split zip\n".repeat(40));
    assert!(!out.join("a.bin").exists());
}

#[test]
fn a_missing_volume_holding_the_directory_lists_the_members_before_the_gap() {
    // The directory starts on disk 1 and disk 1 is gone: only the local headers before the gap can be listed.
    let a = data(3000, 1);
    let b = data(500, 2);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", &b)];
    let total_data = 4 + 2 * 30 + 5 + 5 + a.len() + b.len();
    let set = split_zip(&entries, &[total_data - 10, total_data + 20], Layout { marker: true, zip64: false });
    assert_eq!(set.directory.0, 1);
    let dir = tempfile::tempdir().unwrap();
    for (i, v) in set.volumes.iter().enumerate() {
        let name = if i + 1 == set.volumes.len() { "cut.zip".to_owned() } else { format!("cut.z{:02}", i + 1) };
        if i != 1 {
            fs::write(dir.path().join(name), v).unwrap();
        }
    }
    let detailed = extract::list_detailed(&dir.path().join("cut.zip"), None).unwrap();
    assert!(detailed.unexpected_end());
    assert_eq!(detailed.missing_volume.as_deref(), Some(dir.path().join("cut.z02").as_path()));
    assert_eq!(detailed.entries.first().map(|e| e.name.as_str()), Some("a.bin"));
    let s =
        extract::run(&dir.path().join("cut.zip"), &options(&dir.path().join("out"), Mode::Extract), |_| {}).unwrap();
    assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), a);
    assert!(s.errors.iter().any(|e| e.contains("cut.z02")), "{:?}", s.errors);
}

/// Writes `volumes` as `stem.z01`, ..., `stem.zip` in `dir`; returns the `.zip`.
fn write_set(dir: &Path, stem: &str, volumes: &[Vec<u8>]) -> PathBuf {
    for (i, v) in volumes.iter().enumerate() {
        let name = if i + 1 == volumes.len() { format!("{stem}.zip") } else { format!("{stem}.z{:02}", i + 1) };
        fs::write(dir.join(name), v).unwrap();
    }
    dir.join(format!("{stem}.zip"))
}

#[test]
fn winzip_aes_and_zipcrypto_decrypt_across_pieces() {
    let plain = data(6000, 5);
    let crc = crc32fast::hash(&plain);
    let zc = Entry {
        name: "zc.bin",
        payload: zipcrypto("pw", (crc >> 24) as u8, &plain),
        method: 0,
        flags: 1,
        extra: Vec::new(),
        crc,
        size: plain.len() as u32,
    };
    let entries = [Entry::stored("first.bin", b"x"), aes_entry(&plain), zc];
    let start = split_zip_builder::data_abs(&entries, 1, true);
    // the AES salt and verifier straddle the first cut, its data the second, the ZipCrypto header the third
    let zc_start = split_zip_builder::data_abs(&entries, 2, true);
    let set = split_zip(&entries, &[start + 7, start + 4000, zc_start + 5], Layout { marker: true, zip64: false });
    let dir = tempfile::tempdir().unwrap();
    let zip = write_set(dir.path(), "enc", &set.volumes);
    let out = dir.path().join("out");
    let s = extract::run_with_password(&zip, &options(&out, Mode::Extract), Some("pw"), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("aes.bin")).unwrap(), plain);
    assert_eq!(fs::read(out.join("zc.bin")).unwrap(), plain);
}

#[test]
fn zip64_end_records_and_volume_names_past_z99() {
    let a = data(20_000, 3);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", b"tail")];
    let start = split_zip_builder::data_abs(&entries, 0, true);
    // 120 cuts through a.bin: `.z01` to `.z120`, then `.zip`
    let cuts: Vec<usize> = (1..=120).map(|i| start + i * 150).collect();
    for zip64 in [false, true] {
        let set = split_zip(&entries, &cuts, Layout { marker: true, zip64 });
        let dir = tempfile::tempdir().unwrap();
        let zip = write_set(dir.path(), "many", &set.volumes);
        assert!(dir.path().join("many.z100").is_file() && dir.path().join("many.z120").is_file());
        let names: Vec<_> = extract::list(&zip).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["a.bin", "b.bin"], "zip64={zip64}");
        let out = dir.path().join("out");
        let s = extract::run(&zip, &options(&out, Mode::Extract), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "zip64={zip64}: {:?}", s.errors);
        assert_eq!(fs::read(out.join("a.bin")).unwrap(), a);
        assert_eq!(fs::read(out.join("b.bin")).unwrap(), b"tail");
        assert_eq!(s.volumes, 121);
    }
}

#[test]
fn a_lone_zip_with_a_stray_z01_beside_it_stays_a_lone_archive() {
    let set = split_zip(&[Entry::stored("only.txt", b"only")], &[], Layout::default());
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("lone.zip");
    fs::write(&zip, &set.volumes[0]).unwrap();
    fs::write(dir.path().join("lone.z01"), b"not a volume").unwrap();
    let names: Vec<_> = extract::list(&zip).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["only.txt"]);
    let out = dir.path().join("out");
    let s = extract::run(&zip, &options(&out, Mode::Extract), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!((s.volumes, fs::read(out.join("only.txt")).unwrap()), (1, b"only".to_vec()));
}

#[test]
fn a_lone_zip_with_trailing_bytes_and_a_stray_z01_still_opens() {
    // No end record ends exactly at the end of the `.zip`: it is no set's last volume, and the single-file reader,
    // which allows trailing bytes, reads it as before.
    let set = split_zip(&[Entry::stored("only.txt", b"only")], &[], Layout::default());
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("lone.zip");
    let mut bytes = set.volumes[0].clone();
    bytes.extend(b"JUNKJUNK");
    fs::write(&zip, &bytes).unwrap();
    let alone: Vec<_> = extract::list(&zip).unwrap().into_iter().map(|e| e.name).collect();
    fs::write(dir.path().join("lone.z01"), b"not a volume").unwrap();
    let beside: Vec<_> = extract::list(&zip).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!((alone.as_slice(), beside.as_slice()), (&["only.txt".to_owned()][..], &["only.txt".to_owned()][..]));
    let out = dir.path().join("out");
    let s = extract::run(&zip, &options(&out, Mode::Extract), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
}

/// A FIFO with no writer where a volume should be is never opened: listing doesn't block on it.
#[cfg(unix)]
#[test]
fn a_fifo_in_place_of_a_volume_is_refused_without_blocking() {
    let a = data(3000, 1);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", b"tail")];
    let start = split_zip_builder::data_abs(&entries, 0, true);
    let cuts = [start + 1000, start + 2000];
    for zip64 in [false, true] {
        let set = split_zip(&entries, &cuts, Layout { marker: true, zip64 });
        let dir = tempfile::tempdir().unwrap();
        let zip = write_set(dir.path(), "fifo", &set.volumes);
        // the ZIP64 locator names disk 2 (the `.zip`); make the middle volume a FIFO, and for the ZIP64 case also
        // point the locator at it
        let z02 = dir.path().join("fifo.z02");
        fs::remove_file(&z02).unwrap();
        let name = std::ffi::CString::new(z02.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        if zip64 {
            let mut last = fs::read(&zip).unwrap();
            let locator = last.len() - 22 - 20;
            assert_eq!(&last[locator..locator + 4], b"PK\x06\x07");
            last[locator + 4..locator + 8].copy_from_slice(&1u32.to_le_bytes());
            fs::write(&zip, last).unwrap();
        }
        let (done, wait) = std::sync::mpsc::channel();
        let path = zip.clone();
        std::thread::spawn(move || {
            let _ = done.send(extract::list_detailed(&path, None).map(|l| (l.entries.len(), l.unexpected_end())));
        });
        let listed = wait.recv_timeout(std::time::Duration::from_secs(20)).expect("listing blocked on the FIFO");
        // the FIFO counts as a missing volume (or the ZIP64 record it was to hold can't be read): never a hang
        if let Ok((_, unexpected_end)) = listed {
            assert!(unexpected_end, "zip64={zip64}");
        }
    }
}

/// Copies a real set into `dir` as `stem.*`, leaving out the volumes with the extensions in `skip`.
fn copy_set_without(set: &str, dir: &Path, stem: &str, skip: &[&str]) {
    for ext in ["z01", "z02", "zip"] {
        let from = fixture(&format!("{set}.{ext}"));
        if from.is_file() && !skip.contains(&ext) {
            fs::copy(&from, dir.join(format!("{stem}.{ext}"))).unwrap();
        }
    }
}

/// Expected 7-Zip 26.06 results for the real sets with their `.zip` removed, opened from the `.z01`: only the first
/// member's local header is reachable (each one crosses into the `.zip`), it is listed, and it is never extracted.
#[test]
fn a_missing_zip_lists_the_local_headers_from_the_z01() {
    // (set, name, size, packed, CRC, size unknown)
    for (set, name, size, packed, crc, unknown) in [
        ("stored", "a.bin", 140_000, 140_000, 0x329A_E6F9, false),
        ("deflated", "c.txt", 93_336, 70_626, 0x80C0_5F59, false),
        // a data descriptor past the gap: 7-Zip lists no size and the bytes up to the gap as packed
        ("crypt", "s.bin", 0, 65_497, 0x02E5_71C8, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        copy_set_without(set, dir.path(), "nz", &["zip"]);
        let z01 = dir.path().join("nz.z01");
        let detailed = extract::list_detailed(&z01, Some("password")).unwrap();
        assert!(detailed.unexpected_end(), "{set}");
        assert_eq!(detailed.missing_volume.as_deref(), Some(dir.path().join("nz.zip").as_path()), "{set}");
        let got: Vec<_> =
            detailed.entries.iter().map(|e| (e.name.as_str(), e.size, e.packed, e.crc32, e.size_unknown)).collect();
        assert_eq!(got, [(name, size, packed, Some(crc), unknown)], "{set}");
        let out = dir.path().join("out");
        let s = extract::run_with_password(&z01, &options(&out, Mode::Extract), Some("password"), |_| {}).unwrap();
        assert!(s.errors.iter().any(|e| e.contains(name) && e.contains("nz.zip")), "{set}: {:?}", s.errors);
        assert_eq!(s.files, 0, "{set}");
        // nothing partial is published (7-Zip writes what it could read)
        assert!(!out.join(name).exists(), "{set}");
    }
}

#[test]
fn a_missing_zip_extracts_the_members_wholly_before_it() {
    let a = data(3000, 1);
    let b = data(500, 2);
    let c = data(4000, 3);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", &b), Entry::stored("c.bin", &c)];
    // a.bin crosses into `.z02`, b.bin is whole there, c.bin crosses into the `.zip`
    let cuts =
        [split_zip_builder::data_abs(&entries, 0, true) + 1000, split_zip_builder::data_abs(&entries, 2, true) + 10];
    for marker in [true, false] {
        let set = split_zip(&entries, &cuts.map(|c| c - usize::from(!marker) * 4), Layout { marker, zip64: false });
        let dir = tempfile::tempdir().unwrap();
        let zip = write_set(dir.path(), "part", &set.volumes);
        fs::remove_file(&zip).unwrap();
        let z01 = dir.path().join("part.z01");
        let detailed = extract::list_detailed(&z01, None).unwrap();
        assert_eq!(detailed.missing_volume.as_deref(), Some(zip.as_path()), "marker={marker}");
        let names: Vec<_> = detailed.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a.bin", "b.bin", "c.bin"], "marker={marker}");
        let out = dir.path().join("out");
        let s = extract::run(&z01, &options(&out, Mode::Extract), |_| {}).unwrap();
        assert_eq!(
            (fs::read(out.join("a.bin")).unwrap(), fs::read(out.join("b.bin")).unwrap()),
            (a.clone(), b.clone())
        );
        assert!(!out.join("c.bin").exists(), "marker={marker}");
        assert!(s.errors.iter().any(|e| e.contains("c.bin") && e.contains("part.zip")), "{:?}", s.errors);
        // the checked route refuses a set it could only walk (see a_lone_z01_is_refused_on_the_checked_route)
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let out = dir.path().join("checked");
            assert!(checked_rejects(&z01, &out), "marker={marker}");
            assert!(no_files(&out), "marker={marker}");
        }
    }
}

#[test]
fn a_missing_zip_keeps_winzip_aes_members_before_it_readable() {
    // The local walk reads the AES extra field, so an encrypted member wholly before the gap still decrypts.
    let plain = data(6000, 5);
    let entries = [Entry::stored("first.bin", b"x"), aes_entry(&plain), Entry::stored("last.bin", &data(900, 4))];
    let start = split_zip_builder::data_abs(&entries, 1, true);
    let last_start = split_zip_builder::data_abs(&entries, 2, true);
    let set = split_zip(&entries, &[start + 7, start + 4000, last_start + 5], Layout { marker: true, zip64: false });
    let dir = tempfile::tempdir().unwrap();
    let zip = write_set(dir.path(), "aes", &set.volumes);
    fs::remove_file(&zip).unwrap();
    let z01 = dir.path().join("aes.z01");
    let out = dir.path().join("out");
    let s = extract::run_with_password(&z01, &options(&out, Mode::Extract), Some("pw"), |_| {}).unwrap();
    assert_eq!(fs::read(out.join("aes.bin")).unwrap(), plain, "{:?}", s.errors);
    assert!(s.errors.iter().all(|e| !e.contains("aes.bin")), "{:?}", s.errors);
    assert!(s.errors.iter().any(|e| e.contains("last.bin") && e.contains("aes.zip")), "{:?}", s.errors);
}

#[test]
fn a_missing_zip_walks_past_members_with_zip64_local_sizes() {
    // A member whose local header defers its sizes to the ZIP64 extra field (as forced-ZIP64 writers do) is
    // listed and extracted, and the walk goes on to the members after it.
    let a = data(700, 1);
    let b = data(300, 2);
    let mut zip64 = Entry::stored("a.bin", &a);
    zip64.size = u32::MAX;
    zip64.extra = [&[1, 0, 16, 0][..], &(a.len() as u64).to_le_bytes(), &(a.len() as u64).to_le_bytes()].concat();
    let entries = [zip64, Entry::stored("b.bin", &b), Entry::stored("c.bin", &data(900, 3))];
    let cuts =
        [split_zip_builder::data_abs(&entries, 0, true) + 100, split_zip_builder::data_abs(&entries, 2, true) + 10];
    let set = split_zip(&entries, &cuts, Layout { marker: true, zip64: false });
    let dir = tempfile::tempdir().unwrap();
    let zip = write_set(dir.path(), "z64", &set.volumes);
    fs::remove_file(&zip).unwrap();
    let z01 = dir.path().join("z64.z01");
    let detailed = extract::list_detailed(&z01, None).unwrap();
    let got: Vec<_> = detailed.entries.iter().map(|e| (e.name.as_str(), e.size)).collect();
    assert_eq!(got, [("a.bin", 700), ("b.bin", 300), ("c.bin", 900)]);
    let out = dir.path().join("out");
    let s = extract::run(&z01, &options(&out, Mode::Extract), |_| {}).unwrap();
    assert_eq!((fs::read(out.join("a.bin")).unwrap(), fs::read(out.join("b.bin")).unwrap()), (a, b), "{:?}", s.errors);
    assert!(s.errors.iter().any(|e| e.contains("c.bin") && e.contains("z64.zip")), "{:?}", s.errors);
}

/// Marks `name`'s central directory record in `volume` as a Unix symbolic link.
#[cfg(unix)]
fn make_symlink(volume: &mut [u8], name: &str) {
    let at = (0..volume.len() - 46)
        .find(|&i| {
            volume[i..i + 4] == *b"PK\x01\x02" && volume.get(i + 46..i + 46 + name.len()) == Some(name.as_bytes())
        })
        .expect("central record");
    volume[at + 38..at + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
}

#[cfg(unix)]
#[test]
fn a_symlink_reaching_a_missing_middle_volume_fails_alone() {
    let target = b"some/where/far/away";
    let after = data(800, 6);
    let entries = [Entry::stored("link", target), Entry::stored("after.bin", &after)];
    // the link's target runs from `.z01` through `.z02` (removed) into the `.zip`, which holds after.bin whole
    let start = split_zip_builder::data_abs(&entries, 0, true);
    let mut set = split_zip(&entries, &[start + 3, start + 8], Layout { marker: true, zip64: false });
    make_symlink(set.volumes.last_mut().unwrap(), "link");
    let dir = tempfile::tempdir().unwrap();
    let zip = write_set(dir.path(), "sym", &set.volumes);
    fs::remove_file(dir.path().join("sym.z02")).unwrap();
    for mode in [Mode::Test, Mode::Extract] {
        let out = dir.path().join(format!("out-{mode:?}"));
        let s = extract::run(&zip, &options(&out, mode), |_| {}).unwrap();
        assert!(s.errors.iter().any(|e| e.contains("link") && e.contains("sym.z02")), "{mode:?}: {:?}", s.errors);
        assert!(s.errors.iter().all(|e| !e.contains("after.bin")), "{mode:?}: {:?}", s.errors);
        if mode == Mode::Extract {
            assert_eq!(fs::read(out.join("after.bin")).unwrap(), after);
        }
    }
}

#[test]
fn a_missing_numbered_volume_and_zip_end_the_walk_at_the_first_gap() {
    let a = data(3000, 1);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", b"tail")];
    let start = split_zip_builder::data_abs(&entries, 0, true);
    let set = split_zip(&entries, &[start + 1000, start + 2000, start + 2500], Layout { marker: true, zip64: false });
    let dir = tempfile::tempdir().unwrap();
    let zip = write_set(dir.path(), "gap", &set.volumes);
    fs::remove_file(&zip).unwrap();
    fs::remove_file(dir.path().join("gap.z02")).unwrap();
    // `.z03` is there, so `.z02` is the gap
    let detailed = extract::list_detailed(&dir.path().join("gap.z01"), None).unwrap();
    assert_eq!(detailed.missing_volume.as_deref(), Some(dir.path().join("gap.z02").as_path()));
    assert_eq!(detailed.entries.len(), 1);
    // with `.z03` gone too, nothing says the set had more numbered volumes: the `.zip` is what's missing
    fs::remove_file(dir.path().join("gap.z03")).unwrap();
    let detailed = extract::list_detailed(&dir.path().join("gap.z01"), None).unwrap();
    assert_eq!(detailed.missing_volume.as_deref(), Some(zip.as_path()));
}

#[test]
fn a_lone_archive_named_z01_stays_a_lone_archive() {
    let set = split_zip(&[Entry::stored("only.txt", b"only")], &[], Layout::default());
    let dir = tempfile::tempdir().unwrap();
    let z01 = dir.path().join("lone.z01");
    fs::write(&z01, &set.volumes[0]).unwrap();
    let detailed = extract::list_detailed(&z01, None).unwrap();
    assert!(!detailed.unexpected_end());
    assert_eq!(detailed.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["only.txt"]);
}

/// Whether the checked route (`run_with_policy`) rejects `zip`, extracting into `out`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn checked_rejects(zip: &Path, out: &Path) -> bool {
    extract::run_with_policy(
        zip,
        &options(out, Mode::Extract),
        None,
        &extract::Cancellation::default(),
        &Default::default(),
        |_: extract::RunEvent<'_>| Ok(()),
    )
    .is_err()
}

/// Whether `dir` holds no file at any depth.
fn no_files(dir: &Path) -> bool {
    !dir.exists()
        || fs::read_dir(dir).unwrap().all(|e| {
            let path = e.unwrap().path();
            path.is_dir() && no_files(&path)
        })
}

/// A real set with its `.z01` removed is not opened as a set, unlike 7-Zip (which lists every member and extracts
/// those not on disk 0): without the first volume, nothing but the `.zip`'s own end record says it belongs to a set,
/// and a hostile lone `.zip` could say the same. The checked route rejects it and writes nothing.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_set_missing_its_z01_is_rejected() {
    for set in ["stored", "deflated", "crypt"] {
        let dir = tempfile::tempdir().unwrap();
        copy_set_without(set, dir.path(), "n1", &["z01"]);
        let zip = dir.path().join("n1.zip");
        let out = dir.path().join("out");
        assert!(checked_rejects(&zip, &out), "{set}");
        assert!(no_files(&out), "{set}");
    }
}

/// A crafted directory offset on an absent middle disk is never trusted: the member starting there fails as missing
/// it, and the archive still opens and extracts the rest.
#[test]
fn a_member_on_an_absent_disk_with_a_wild_offset_still_fails_alone() {
    let a = data(3000, 1);
    let b = data(1500, 2);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", &b), Entry::stored("c.bin", b"tail")];
    let b_header = split_zip_builder::data_abs(&entries, 1, true) - 30 - 5;
    let c_header = split_zip_builder::data_abs(&entries, 2, true) - 30 - 5;
    // a.bin whole in `.z01`, b.bin starts on `.z02` and ends there, c.bin in the `.zip`
    let set = split_zip(&entries, &[b_header, c_header], Layout { marker: true, zip64: false });
    assert_eq!(set.locals.iter().map(|l| l.0).collect::<Vec<_>>(), [0, 1, 2]);
    for wild in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let zip = write_set(dir.path(), "w", &set.volumes);
        fs::remove_file(dir.path().join("w.z02")).unwrap();
        if wild {
            // point b.bin's directory record (the second) at a huge offset on disk 1
            let mut last = fs::read(&zip).unwrap();
            let records: Vec<_> =
                last.windows(4).enumerate().filter(|(_, w)| *w == b"PK\x01\x02").map(|(i, _)| i).collect();
            last[records[1] + 42..records[1] + 46].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
            fs::write(&zip, last).unwrap();
        }
        let detailed = extract::list_detailed(&zip, None).unwrap();
        assert_eq!(detailed.entries.len(), 3, "wild={wild}");
        assert_eq!(detailed.missing_volume.as_deref(), Some(dir.path().join("w.z02").as_path()));
        let out = dir.path().join("out");
        let s = extract::run(&zip, &options(&out, Mode::Extract), |_| {}).unwrap();
        assert!(s.errors.iter().any(|e| e.starts_with("b.bin") && e.contains("w.z02")), "{:?}", s.errors);
        assert!(!out.join("b.bin").exists());
        assert_eq!(fs::read(out.join("a.bin")).unwrap(), a, "wild={wild}");
        assert_eq!(fs::read(out.join("c.bin")).unwrap(), b"tail", "wild={wild}");
        // the library read fails the same way, without reading anything
        let mut archive = zipfast::zip::Archive::open(&zip).unwrap();
        let err = archive.read_at(1, None, u64::MAX, |_| Ok(())).unwrap_err();
        assert!(matches!(err, zipfast::Error::MissingVolume(ref p) if p.ends_with("w.z02")), "{err}");
    }
}

/// An end record whose comment puts it at the very start of the first window read: the ZIP64 locator before it is
/// still found, with every volume there and with a middle one missing.
#[test]
fn a_long_comment_keeps_the_zip64_locator_in_view() {
    let a = data(3000, 1);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", b"tail")];
    let start = split_zip_builder::data_abs(&entries, 0, true);
    for comment in [4070usize, 4090, 65_535] {
        let set = split_zip(&entries, &[start + 1000, start + 2000], Layout { marker: true, zip64: true });
        let dir = tempfile::tempdir().unwrap();
        let zip = write_set(dir.path(), "c", &set.volumes);
        let mut last = fs::read(&zip).unwrap();
        let n = last.len();
        last[n - 2..].copy_from_slice(&(comment as u16).to_le_bytes());
        last.extend(std::iter::repeat_n(b'#', comment));
        fs::write(&zip, last).unwrap();
        let names: Vec<_> = extract::list(&zip).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["a.bin", "b.bin"], "comment={comment}");
        fs::remove_file(dir.path().join("c.z02")).unwrap();
        let s = extract::run(&zip, &options(&dir.path().join("out"), Mode::Extract), |_| {}).unwrap();
        assert!(s.errors.iter().any(|e| e.starts_with("a.bin") && e.contains("c.z02")), "{:?}", s.errors);
        assert_eq!(fs::read(dir.path().join("out/b.bin")).unwrap(), b"tail", "comment={comment}");
    }
}

/// A single `.zip` whose end record says it is a later disk (directory and entries there) is not a set without its
/// `.z01`, whatever other numbered volume sits beside it: the checked route reads it and rejects the multi-disk end
/// record, and it never falls back to the legacy split reader.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_lone_multi_disk_zip_without_its_z01_takes_the_checked_route() {
    let entries = [Entry::stored("a.bin", b"payload"), Entry::stored("b.bin", b"tail")];
    // disk 1, and disk 5: the disks before hold only the spanning marker's bytes
    for cuts in [vec![4], vec![1, 2, 3, 4, 4]] {
        let disk = cuts.len() as u32;
        let set = split_zip(&entries, &cuts, Layout { marker: true, zip64: false });
        assert_eq!((set.locals[0].0, set.directory.0), (disk, disk));
        // any numbered volume but the `.z01`, including the one the `.zip` claims to follow
        let named = [format!("lone.z{disk:02}"), "lone.z02".to_owned()];
        let junks = named.into_iter().filter(|n| n != "lone.z01").map(Some);
        for junk in std::iter::once(None).chain(junks) {
            let dir = tempfile::tempdir().unwrap();
            let zip = dir.path().join("lone.zip");
            fs::write(&zip, set.volumes.last().unwrap()).unwrap();
            if let Some(junk) = &junk {
                fs::write(dir.path().join(junk), b"junk volume").unwrap();
            }
            let out = dir.path().join("out");
            assert!(checked_rejects(&zip, &out), "disk {disk}, junk {junk:?}: must be rejected");
            assert!(no_files(&out), "disk {disk}, junk {junk:?}");
        }
    }
    // with its real `.z01` beside it, the disk-1 `.zip` is the last volume of a set again
    let set = split_zip(&entries, &[4], Layout { marker: true, zip64: false });
    let dir = tempfile::tempdir().unwrap();
    let zip = write_set(dir.path(), "lone", &set.volumes);
    let names: Vec<_> = extract::list(&zip).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["a.bin", "b.bin"]);
}

/// A lone `.z01`, no `.zip` and nothing else beside it, can only be read by walking its local headers: the unchecked
/// routes list and extract it as 7-Zip does, but the checked route refuses it with a clear error and writes nothing,
/// as it did before sets could open without their `.zip`. It never falls back to the legacy reader.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_lone_z01_is_refused_on_the_checked_route() {
    let a = data(3000, 1);
    let entries = [Entry::stored("a.bin", &a), Entry::stored("b.bin", b"tail")];
    let end = split_zip_builder::data_abs(&entries, 1, true) + 4;
    for marker in [true, false] {
        // everything up to the end of b.bin in the `.z01`; the directory would be in the `.zip`
        let set = split_zip(&entries, &[end - usize::from(!marker) * 4], Layout { marker, zip64: false });
        let dir = tempfile::tempdir().unwrap();
        let z01 = dir.path().join("lone.z01");
        fs::write(&z01, &set.volumes[0]).unwrap();
        let out = dir.path().join("checked");
        let error = extract::run_with_policy(
            &z01,
            &options(&out, Mode::Extract),
            None,
            &extract::Cancellation::default(),
            &Default::default(),
            |_: extract::RunEvent<'_>| Ok(()),
        )
        .err()
        .unwrap_or_else(|| panic!("marker={marker}: the checked route must refuse a lone .z01"));
        assert!(format!("{error:?}").contains("without its .zip"), "marker={marker}: {error:?}");
        assert!(no_files(&out), "marker={marker}");
        // the unchecked routes walk it
        let names: Vec<_> = extract::list(&z01).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["a.bin", "b.bin"], "marker={marker}");
        let out = dir.path().join("out");
        let s = extract::run(&z01, &options(&out, Mode::Extract), |_| {}).unwrap();
        assert_eq!(fs::read(out.join("a.bin")).unwrap(), a, "marker={marker}");
        assert_eq!(fs::read(out.join("b.bin")).unwrap(), b"tail", "marker={marker}");
        assert!(s.errors.iter().any(|e| e.contains("lone.zip")), "{:?}", s.errors);
    }
}
