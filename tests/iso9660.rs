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

//! ISO 9660 images from xorriso (Rock Ridge and Joliet), genisoimage (Joliet alone, plain names, Rock Ridge with
//! relocated deep folders) and bsdtar, see tests/fixtures/iso9660/gen.sh, through the same entry points as tar;
//! then images built here: several extents, loops, extents outside the image, deep nesting.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite, SelectedEntry};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iso9660")
}

fn opts(mode: Mode, dest: &Path) -> Options {
    Options {
        mode,
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
    }
}

fn sha(data: &[u8]) -> String {
    zipfast::crypto::sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn expected() -> BTreeMap<String, String> {
    fs::read_to_string(fixtures().join("expected.sha256"))
        .unwrap()
        .lines()
        .map(|l| {
            let (sum, name) = l.split_once("  ").unwrap();
            (name.to_owned(), sum.to_owned())
        })
        .collect()
}

/// The fixture, gunzipped into `dir`.
fn image(name: &str, dir: &Path) -> PathBuf {
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(fs::File::open(fixtures().join(format!("{name}.iso.gz"))).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    let path = dir.join(format!("{name}.iso"));
    fs::write(&path, data).unwrap();
    path
}

/// The images with Rock Ridge: the whole tree, symbolic links and all.
const ROCK_RIDGE: [&str; 3] = ["rr-joliet", "relocated", "bsdtar"];

#[test]
fn rock_ridge_images_extract_the_whole_tree() {
    let want = expected();
    for fixture in ROCK_RIDGE {
        let dir = tempfile::tempdir().unwrap();
        let path = image(fixture, dir.path());
        let out = dir.path().join("out");
        let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{fixture}: {:?}", s.errors);
        for (name, sum) in &want {
            assert_eq!(&sha(&fs::read(out.join(name)).unwrap()), sum, "{fixture}/{name}");
        }
        assert_eq!(fs::read(out.join("café.txt")).unwrap(), b"unicode\n", "{fixture}");
        assert!(!out.join("rr_moved").exists(), "{fixture}: the relocation folder is undone");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::read_link(out.join("link")).unwrap(), Path::new("a.txt"), "{fixture}");
            assert_eq!(fs::read_link(out.join("dir/sub/up")).unwrap(), Path::new("../../a.txt"), "{fixture}");
            // bsdtar's Rock Ridge keeps only the useful bits of a mode
            if fixture != "bsdtar" {
                assert_eq!(fs::metadata(out.join("dir/sub/f")).unwrap().mode() & 0o777, 0o600, "{fixture}");
                assert_eq!(fs::metadata(out.join("dir")).unwrap().mode() & 0o777, 0o751, "{fixture}");
            }
        }
        let mtime = fs::metadata(out.join("a.txt")).unwrap().modified().unwrap();
        let since = mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(since, 1_767_323_045, "{fixture}: 2026-01-02 03:04:05 UTC");
    }
}

#[test]
fn joliet_and_plain_names_are_read_without_rock_ridge() {
    let want = expected();
    let dir = tempfile::tempdir().unwrap();
    // Joliet: the names as written, in UCS-2; genisoimage dropped the symbolic links and the folders past 8 levels
    let out = dir.path().join("joliet");
    let s = extract::run(&image("joliet", dir.path()), &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    for name in ["a.txt", "dir/sub/f", "LongFileName With Spaces.txt", "big.bin"] {
        assert_eq!(&sha(&fs::read(out.join(name)).unwrap()), &want[name], "joliet/{name}");
    }
    assert_eq!(fs::read(out.join("café.txt")).unwrap(), b"unicode\n");
    // plain ISO 9660 level 1: upper-case 8.3 names, the version gone
    let out = dir.path().join("plain");
    let s = extract::run(&image("plain", dir.path()), &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(&sha(&fs::read(out.join("A.TXT")).unwrap()), &want["a.txt"]);
    assert_eq!(&sha(&fs::read(out.join("LONGFILE.TXT")).unwrap()), &want["LongFileName With Spaces.txt"]);
    assert_eq!(&sha(&fs::read(out.join("DIR/SUB/F")).unwrap()), &want["dir/sub/f"]);
}

#[test]
fn a_test_a_listing_and_a_read_by_index_agree() {
    let want = expected();
    for fixture in ROCK_RIDGE {
        let dir = tempfile::tempdir().unwrap();
        let path = image(fixture, dir.path());
        let s = extract::run(&path, &opts(Mode::Test, &dir.path().join("unused")), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{fixture}: {:?}", s.errors);
        assert!(!dir.path().join("unused").exists());
        let listing = extract::list(&path).unwrap();
        // every folder comes before what is in it
        for (i, e) in listing.iter().enumerate() {
            if let Some((parent, _)) = e.name.rsplit_once('/') {
                assert!(listing[..i].iter().any(|p| p.dir && p.name == parent), "{fixture}: {} first", e.name);
            }
        }
        let index = listing.iter().position(|e| e.name == "big.bin").unwrap();
        assert_eq!(listing[index].size, 300_000);
        let mut data = Vec::new();
        SelectedEntry::open(&path, index, None, 1 << 20)
            .unwrap()
            .read(None, |c| {
                data.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(sha(&data), want["big.bin"], "{fixture}");
    }
}

// --- built here -------------------------------------------------------------------------------------------------

const SECTOR: usize = 2048;

fn both32(v: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&v.to_le_bytes());
    b[4..].copy_from_slice(&v.to_be_bytes());
    b
}

/// A directory record.
fn record(name: &[u8], extent: u32, size: u32, flags: u8) -> Vec<u8> {
    let mut r = vec![0u8; 33];
    r[2..10].copy_from_slice(&both32(extent));
    r[10..18].copy_from_slice(&both32(size));
    r[18..25].copy_from_slice(&[126, 1, 2, 3, 4, 5, 0]);
    r[25] = flags;
    r[28..32].copy_from_slice(&[1, 0, 0, 1]);
    r[32] = name.len() as u8;
    r.extend_from_slice(name);
    if r.len() % 2 == 1 {
        r.push(0);
    }
    r[0] = r.len() as u8;
    r
}

/// An image of `sectors` sectors: a primary volume descriptor whose root folder is at sector 18 (`root`, one
/// sector), a terminator, and whatever `fill` writes.
fn iso(sectors: usize, root: &[Vec<u8>], fill: impl FnOnce(&mut [u8])) -> Vec<u8> {
    iso_with(sectors, 1, root, true, fill)
}

/// [`iso`] with a root folder of `root_sectors` sectors (records packed so none crosses a sector), and a
/// terminator only with `terminator`.
fn iso_with(
    sectors: usize,
    root_sectors: usize,
    root: &[Vec<u8>],
    terminator: bool,
    fill: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let mut img = vec![0u8; sectors * SECTOR];
    let root_size = (root_sectors * SECTOR) as u32;
    let pvd = &mut img[16 * SECTOR..17 * SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
    pvd[130..132].copy_from_slice(&2048u16.to_be_bytes());
    let root_at = if terminator { 18 } else { 17 };
    let root_rec = record(&[0], root_at, root_size, 2);
    pvd[156..156 + root_rec.len()].copy_from_slice(&root_rec);
    if terminator {
        let term = &mut img[17 * SECTOR..18 * SECTOR];
        term[0] = 255;
        term[1..6].copy_from_slice(b"CD001");
    }
    let mut records = vec![record(&[0], root_at, root_size, 2), record(&[1], root_at, root_size, 2)];
    records.extend_from_slice(root);
    let mut at = root_at as usize * SECTOR;
    for r in records {
        if at % SECTOR + r.len() > SECTOR {
            at = (at / SECTOR + 1) * SECTOR;
        }
        assert!(at + r.len() <= (root_at as usize + root_sectors) * SECTOR, "the root folder is too small");
        img[at..at + r.len()].copy_from_slice(&r);
        at += r.len();
    }
    fill(&mut img);
    img
}

fn run_image(bytes: &[u8]) -> (Result<extract::Summary, String>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.iso");
    fs::write(&path, bytes).unwrap();
    let r = extract::run(&path, &opts(Mode::Extract, &dir.path().join("out")), |_| {}).map_err(|e| e.to_string());
    (r, dir)
}

#[test]
fn a_file_of_several_extents_reads_as_one() {
    // three extents, the first two with the multi-extent flag
    let root =
        [record(b"BIG.BIN;1", 20, 4096, 0x80), record(b"BIG.BIN;1", 23, 2048, 0x80), record(b"BIG.BIN;1", 25, 100, 0)];
    let bytes = iso(26, &root, |img| {
        img[20 * SECTOR..22 * SECTOR].fill(b'a');
        img[23 * SECTOR..24 * SECTOR].fill(b'b');
        img[25 * SECTOR..25 * SECTOR + 100].fill(b'c');
    });
    let (s, dir) = run_image(&bytes);
    let s = s.unwrap();
    assert!(s.errors.is_empty() && s.files == 1, "{:?}", s.errors);
    let data = fs::read(dir.path().join("out/BIG.BIN")).unwrap();
    let mut want = vec![b'a'; 4096];
    want.extend(vec![b'b'; 2048]);
    want.extend(vec![b'c'; 100]);
    assert!(data == want);
}

#[test]
fn a_folder_that_loops_back_is_read_once() {
    // "LOOP" is the root again, and "SELF" (at 19) is itself
    let root =
        [record(b"LOOP", 18, SECTOR as u32, 2), record(b"SELF", 19, SECTOR as u32, 2), record(b"F.TXT;1", 20, 2, 0)];
    let bytes = iso(21, &root, |img| {
        let mut d = record(&[0], 19, SECTOR as u32, 2);
        d.extend(record(&[1], 18, SECTOR as u32, 2));
        d.extend(record(b"SELF", 19, SECTOR as u32, 2));
        img[19 * SECTOR..19 * SECTOR + d.len()].copy_from_slice(&d);
        img[20 * SECTOR..20 * SECTOR + 2].copy_from_slice(b"hi");
    });
    zipfast::work::take(zipfast::work::Work::IsoFolders);
    let (s, dir) = run_image(&bytes);
    let s = s.unwrap();
    // the root, and the folder at 19: each scheduled once however many entries point back at them
    let folders = zipfast::work::take(zipfast::work::Work::IsoFolders);
    assert!(folders <= 2, "{folders} folders read");
    assert_eq!(fs::read(dir.path().join("out/F.TXT")).unwrap(), b"hi", "{:?}", s.errors);
}

#[test]
fn extents_outside_the_image_are_refused() {
    let file = iso(21, &[record(b"F.TXT;1", 1 << 20, 10, 0)], |_| {});
    let folder = iso(21, &[record(b"DIR", 1 << 20, SECTOR as u32, 2)], |_| {});
    let past_end = iso(21, &[record(b"F.TXT;1", 20, 5 * SECTOR as u32, 0)], |_| {});
    for (what, bytes) in [("file", file), ("folder", folder), ("past the end", past_end)] {
        let (r, _dir) = run_image(&bytes);
        let message = match r {
            Ok(s) => s.errors.join("\n"),
            Err(e) => e,
        };
        assert!(message.contains("outside the image"), "{what}: {message}");
    }
}

#[test]
fn folders_nested_past_the_bound_are_refused() {
    // a chain of 200 folders, one sector each, from sector 19 on
    let n = 200;
    let root = [record(b"D", 19, SECTOR as u32, 2)];
    let bytes = iso(19 + n + 1, &root, |img| {
        for i in 0..n {
            let at = 19 + i;
            let mut d = record(&[0], at as u32, SECTOR as u32, 2);
            d.extend(record(&[1], at as u32 - 1, SECTOR as u32, 2));
            d.extend(record(b"D", at as u32 + 1, SECTOR as u32, 2));
            img[at * SECTOR..at * SECTOR + d.len()].copy_from_slice(&d);
        }
    });
    let (r, _dir) = run_image(&bytes);
    let message = match r {
        Ok(s) => s.errors.join("\n"),
        Err(e) => e,
    };
    assert!(message.contains("nest too deep"), "{message}");
}

#[test]
fn a_record_whose_name_runs_past_it_is_refused() {
    // a name longer than the record holding it
    let mut bad = record(b"F.TXT;1", 20, 2, 0);
    bad[32] = 200;
    let (r, _dir) = run_image(&iso(21, &[bad], |_| {}));
    let message = match r {
        Ok(s) => s.errors.join("\n"),
        Err(e) => e,
    };
    assert!(message.contains("record"), "{message}");
}

/// Bytes flipped across a real image's descriptors and folders: errors or a tree, never a panic or a hang.
#[test]
fn damaged_images_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let original = fs::read(image("rr-joliet", dir.path())).unwrap();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for round in 0..200 {
        let mut bytes = original.clone();
        for _ in 0..1 + round % 6 {
            // the descriptors and the folders after them, where the structure is
            let i = 16 * SECTOR + (next() % (24 * SECTOR as u64)) as usize;
            bytes[i] ^= (next() as u8) | 1;
        }
        let path = dir.path().join(format!("f{round}.iso"));
        fs::write(&path, &bytes).unwrap();
        let _ = extract::list(&path);
        let _ = extract::run(&path, &opts(Mode::Test, dir.path()), |_| {});
        fs::remove_file(&path).unwrap();
    }
}

fn message(r: Result<extract::Summary, String>) -> String {
    match r {
        Ok(s) => s.errors.join("\n"),
        Err(e) => e,
    }
}

/// One file of 3,000 records all pointing at the same sector: refused, rather than read 3,000 times.
#[test]
fn a_file_whose_extents_overlap_is_refused() {
    let records: Vec<Vec<u8>> =
        (0..3000).map(|i| record(b"F.BIN;1", 200, SECTOR as u32, if i < 2999 { 0x80 } else { 0 })).collect();
    let bytes = iso_with(201, 100, &records, true, |_| {});
    let (r, _dir) = run_image(&bytes);
    assert!(message(r).contains("extents overlap"));
}

/// Files sharing an extent (hard links, empty files) are fine, a few; a thousand on one 1 MiB extent declare
/// far more than a 1 MiB image could hold, and are refused before anything is written.
#[test]
fn many_files_sharing_an_extent_are_refused_but_a_few_are_fine() {
    let names: Vec<String> = (0..1000).map(|i| format!("F{i:04}.BIN;1")).collect();
    let few: Vec<Vec<u8>> = names[..3].iter().map(|n| record(n.as_bytes(), 60, 1 << 20, 0)).collect();
    let (r, dir) = run_image(&iso_with(60 + 512 + 1, 1, &few, true, |img| img[60 * SECTOR] = b'x'));
    let s = r.unwrap();
    assert!(s.errors.is_empty() && s.files == 3, "{:?}", s.errors);
    assert_eq!(fs::read(dir.path().join("out/F0002.BIN")).unwrap()[0], b'x');
    let many: Vec<Vec<u8>> = names.iter().map(|n| record(n.as_bytes(), 60, 1 << 20, 0)).collect();
    let (r, dir) = run_image(&iso_with(60 + 512 + 1, 40, &many, true, |_| {}));
    assert!(message(r).contains("declare far more data"));
    assert!(!dir.path().join("out").exists() || fs::read_dir(dir.path().join("out")).unwrap().next().is_none());
}

/// An image cut short, or missing its terminator, is read with the descriptors before the end.
#[test]
fn an_image_without_its_terminator_reads_with_the_descriptors_before() {
    let bytes = iso_with(19, 1, &[record(b"A.TXT;1", 18, 2, 0)], false, |img| {
        img[18 * SECTOR..18 * SECTOR + 2].copy_from_slice(b"ok")
    });
    let (r, dir) = run_image(&bytes);
    let s = r.unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(dir.path().join("out/A.TXT")).unwrap(), b"ok");
}

/// A folder named rr_moved is an ordinary folder unless Rock Ridge relocation is in use, at the root only.
#[test]
fn rr_moved_is_kept_without_relocation() {
    let root = [record(b"rr_moved", 19, SECTOR as u32, 2)];
    let bytes = iso(21, &root, |img| {
        let mut d = record(&[0], 19, SECTOR as u32, 2);
        d.extend(record(&[1], 18, SECTOR as u32, 2));
        d.extend(record(b"F.TXT;1", 20, 2, 0));
        img[19 * SECTOR..19 * SECTOR + d.len()].copy_from_slice(&d);
        img[20 * SECTOR..20 * SECTOR + 2].copy_from_slice(b"hi");
    });
    let (r, dir) = run_image(&bytes);
    let s = r.unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(dir.path().join("out/rr_moved/F.TXT")).unwrap(), b"hi");
}

/// A hybrid image (boot code in the system area, so its head looks like nothing known) takes the ISO reader on
/// every entry point, not only those that sniff past the head.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_hybrid_image_is_read_on_every_route() {
    use zipfast::extract::{Cancellation, Inspection, RunEvent};
    let bytes = iso(21, &[record(b"A.TXT;1", 20, 2, 0)], |img| {
        img[..4].copy_from_slice(&[0x33, 0xed, 0xfa, 0x8e]);
        img[20 * SECTOR..20 * SECTOR + 2].copy_from_slice(b"ok");
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hybrid.iso");
    fs::write(&path, bytes).unwrap();
    let Inspection::Other(entries) = extract::inspect(&path).unwrap() else { panic!("read as ZIP") };
    assert_eq!(entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["A.TXT"]);
    let out = dir.path().join("out");
    let report = extract::run_with_zip_policy(
        &path,
        &opts(Mode::Extract, &out),
        None,
        &Cancellation::default(),
        &Default::default(),
        |_: RunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.files(), 1);
    assert_eq!(fs::read(out.join("A.TXT")).unwrap(), b"ok");
}

/// A record with an extended attribute record: the attribute blocks come first, the data after them.
#[test]
fn file_data_follows_its_extended_attribute_record() {
    let mut rec = record(b"A.TXT;1", 19, 4, 0);
    rec[1] = 1;
    let bytes = iso(21, &[rec], |img| {
        img[19 * SECTOR..19 * SECTOR + 4].copy_from_slice(b"attr");
        img[20 * SECTOR..20 * SECTOR + 4].copy_from_slice(b"data");
    });
    let (r, dir) = run_image(&bytes);
    let s = r.unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(dir.path().join("out/A.TXT")).unwrap(), b"data");
}

/// A file whose last record still has the multi-extent flag is unfinished: at the folder's end, before another
/// name, or before a folder.
#[test]
fn a_file_missing_its_last_extent_is_refused() {
    let at_end = vec![record(b"BIG.BIN;1", 20, 2048, 0x80)];
    let other_name = vec![record(b"BIG.BIN;1", 20, 2048, 0x80), record(b"C.BIN;1", 21, 2, 0)];
    let folder = vec![record(b"BIG.BIN;1", 20, 2048, 0x80), record(b"D", 18, SECTOR as u32, 2)];
    for (what, root) in [("at the end", at_end), ("another name", other_name), ("a folder", folder)] {
        let (r, _dir) = run_image(&iso(22, &root, |_| {}));
        assert!(message(r).contains("last extent is missing"), "{what}");
    }
}

/// Interleaved data (file unit and gap sizes) isn't contiguous: refused rather than read as if it were.
#[test]
fn interleaved_files_are_refused() {
    let mut rec = record(b"A.BIN;1", 20, 4096, 0);
    rec[26] = 1;
    rec[27] = 1;
    let (r, _dir) = run_image(&iso(24, &[rec], |_| {}));
    assert!(message(r).contains("interleaved"));
}
