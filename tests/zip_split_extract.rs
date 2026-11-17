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
