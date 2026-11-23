//! Printing 7z members to one writer, as `7z x -so` does, and reading one member or one member of a split ZIP set
//! through `extract::SelectedEntry` (the route `-so` takes in prybar). Every expected digest is the SHA-256 of
//! `7z x -so -ppassword <archive>` from 7-Zip 26.06 (Linux, `~/prybar-refs/compat/bin/7z`), which also exits 0 on
//! each of these archives.

use std::path::{Path, PathBuf};

use zipfast::extract::{self, Cancellation, SelectedEntry};
use zipfast::sevenzip::{self, SevenZipLimits};

fn fixture(path: &str) -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).join(path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const ARCHIVES: &[(&str, &str)] = &[
    ("7z-extract/aes.7z", "c8754cdc221213d4cb91427a41e69e6d2789f4e0bc627f2c9c93ed4c2b4af1b5"),
    ("7z-extract/aes_copy.7z", "30f3da1996156e32db947056998e23e48579e9062e0ce0ccf6fc4fe1263fd800"),
    ("7z-extract/aes_hdr.7z", "c8754cdc221213d4cb91427a41e69e6d2789f4e0bc627f2c9c93ed4c2b4af1b5"),
    ("7z-extract/bcj2.7z", "6ff786a1d62f1484dbd40e245f923b7e2507033cf0dad00bba3f1cbbf9af3b69"),
    ("7z-extract/bcj_arm.7z", "569ad1581fb3ca426c7d343a7e2593e4b8d9a031718267618f1cb27ed7d4bef3"),
    ("7z-extract/bcj_arm64.7z", "62e42ad83458f4716ed8ec2dad194306a0e39d15f2368b5c0aa78d08ec594784"),
    ("7z-extract/bcj_armt.7z", "fa7c37be8eaed491c05ad05e5d8e285e21067d8c28475b2af97d43b0c5dcdd4e"),
    ("7z-extract/bcj_ia64.7z", "24cfc67decb3febe57d44a06c3afe768c0428d05582126e4ed14e72f613ce7ee"),
    ("7z-extract/bcj_ppc.7z", "7ca9efc168715b12210aa488dafc317656c95b35b3b1a46420c1e3e12fb080a9"),
    ("7z-extract/bcj_sparc.7z", "e0cfdce35665d2fa88a5a94b9fe90cf3763c3d5e51aa151dbefa18c0aed7cf4a"),
    ("7z-extract/bcj_x86.7z", "6ff786a1d62f1484dbd40e245f923b7e2507033cf0dad00bba3f1cbbf9af3b69"),
    ("7z-extract/bzip2.7z", "c8754cdc221213d4cb91427a41e69e6d2789f4e0bc627f2c9c93ed4c2b4af1b5"),
    ("7z-extract/copy.7z", "7bbbab9951c5de0c4b23f55a26d68b1eb57bfd7e86ffcde6fd8681b23e6c1564"),
    ("7z-extract/deflate.7z", "c8754cdc221213d4cb91427a41e69e6d2789f4e0bc627f2c9c93ed4c2b4af1b5"),
    ("7z-extract/delta.7z", "b3768f199120a33f5c8981874e6e4b91e76357703364a4771d56e5664e83dd0e"),
    ("7z-extract/lzma.7z", "c8754cdc221213d4cb91427a41e69e6d2789f4e0bc627f2c9c93ed4c2b4af1b5"),
    ("7z-extract/lzma2.7z", "c8754cdc221213d4cb91427a41e69e6d2789f4e0bc627f2c9c93ed4c2b4af1b5"),
    ("7z-extract/ppmd.7z", "99079333dc0f73964b16aadcbfa55285b3f8f8d9a91b57c081114bd7a1d3cbd8"),
    ("7z-extract/ppmd_solid.7z", "c1b251a0618fac5ab134d0b15520c1a9bf27346289fdfcf914f64e629768868d"),
    ("7z-extract/solid.7z", "c1b251a0618fac5ab134d0b15520c1a9bf27346289fdfcf914f64e629768868d"),
    ("7z-extract/times.7z", "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"),
    ("7z-extract/tree.7z", "1c2283016f949e0d5b938969442c32f90a509a866dffa92e9b957613dbbf09d0"),
    ("7z-extract/split.7z.001", "47ffef6267dc7892c228653fa86702426c07185609d3642889ab49e03c4c3af3"),
    ("7z/empty_file.7z", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("7z/encrypted_files.7z", "84f376b545a5ce6aad65e2daf81b4e6f077845a63ae39ca453a2b308ea6c9fe7"),
    ("7z/encrypted_headers.7z", "395ad336c59c49757660ef145153b0f689b5e30e6f546a3dd2afc9f1da5e06e9"),
    ("7z/lzma2_chunks.7z", "963287c5ce3d5d9481776c8ebb2a9bd33eb0f1aea0273affe30ac141f74efee4"),
    ("7z/multi_substreams_encrypted.7z", "a4e4a6133e809ec898b8d1d4378657376dababa720b8ef83c4d5722584243cf8"),
    ("7z/solid_lzma_multi.7z", "2cba8366793c35badaec4917b065156fed8216fd2cbc0a2e78c522e1f39acfcf"),
    ("7z/solid_lzma_single.7z", "395ad336c59c49757660ef145153b0f689b5e30e6f546a3dd2afc9f1da5e06e9"),
    ("7z/store_method.7z", "304a9e289ebc010efdd36debd593eb33c2ab1744e480640bbaec4fcce1cb34b0"),
    ("7z/store_method_enc_headers.7z", "304a9e289ebc010efdd36debd593eb33c2ab1744e480640bbaec4fcce1cb34b0"),
    ("7z/store_with_directories.7z", "462381187f88ff032fc9d05b8c9c633bfbf75e0f537231f65d1ecdd3a236ede2"),
    ("7z/store_with_empty.7z", "304a9e289ebc010efdd36debd593eb33c2ab1744e480640bbaec4fcce1cb34b0"),
    ("7z/multi_volume.7z.001", "304a9e289ebc010efdd36debd593eb33c2ab1744e480640bbaec4fcce1cb34b0"),
];

fn print_all(path: &Path, password: Option<&str>) -> (zipfast::Result<extract::Summary>, Vec<u8>) {
    let mut out = Vec::new();
    let result = sevenzip::print_selected(
        path,
        password,
        |_, _| true,
        &mut out,
        &Cancellation::default(),
        &SevenZipLimits::default(),
    );
    (result, out)
}

#[test]
fn printing_every_member_matches_7z_x_so() {
    for (archive, want) in ARCHIVES {
        let (result, out) = print_all(&fixture(archive), Some("password"));
        let summary = result.unwrap_or_else(|e| panic!("{archive}: {e}"));
        assert!(summary.errors.is_empty(), "{archive}: {:?}", summary.errors);
        assert_eq!(hex(&zipfast::crypto::sha256(&out)), *want, "{archive}");
    }
}

/// The route prybar's `-so` takes: list the archive, then read each regular member with `SelectedEntry`.
#[test]
fn selected_entries_read_one_by_one_match_7z_x_so() {
    for (archive, want) in ARCHIVES {
        let path = fixture(archive);
        let entries = extract::list_with_password(&path, Some("password")).unwrap();
        // 7-Zip prints a symbolic link's target too; prybar leaves links out, so do the comparison without them
        if entries.iter().any(|e| e.link.is_some()) {
            continue;
        }
        let mut out = Vec::new();
        for (index, entry) in entries.iter().enumerate().filter(|(_, e)| !e.dir) {
            let selected = SelectedEntry::open(&path, index, Some("password"), 1 << 30)
                .unwrap_or_else(|e| panic!("{archive} #{index}: {e}"));
            assert_eq!(selected.name(), entry.name);
            selected
                .read(Some("password"), |bytes| {
                    out.extend_from_slice(bytes);
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(hex(&zipfast::crypto::sha256(&out)), *want, "{archive}");
    }
}

/// A selection inside a solid folder prints in archive order, whatever order it names the members in, as 7-Zip does
/// (`7z x -so solid.7z text/b.txt big/one.txt`).
#[test]
fn a_selection_in_a_solid_folder_prints_in_archive_order() {
    let mut out = Vec::new();
    let mut seen = Vec::new();
    let summary = sevenzip::print_selected_with(
        &fixture("7z-extract/solid.7z"),
        None,
        &mut |_, name| name == "text/b.txt" || name == "big/one.txt",
        &mut |ordinal, bytes| {
            if seen.last() != Some(&ordinal) {
                seen.push(ordinal);
            }
            out.extend_from_slice(bytes);
            Ok(())
        },
        &Cancellation::default(),
        &SevenZipLimits::default(),
    )
    .unwrap();
    assert_eq!((summary.files, summary.errors.len()), (2, 0));
    assert!(seen.windows(2).all(|w| w[0] < w[1]), "archive order: {seen:?}");
    assert_eq!(hex(&zipfast::crypto::sha256(&out)), "c2e65ab97c21ab972f17c5370477a63c2eb0916e97295e4aeafac86188c822b9");
}

/// With a wrong password no encrypted member prints anything (7-Zip reports each a data error and exits 2); members
/// that are not encrypted still print. `encrypted_files.7z` holds two plain members of 15 and 7,573 bytes.
#[test]
fn a_wrong_password_prints_only_the_unencrypted_members() {
    for (archive, plain) in [("7z-extract/aes.7z", 0), ("7z/encrypted_files.7z", 15 + 7573)] {
        let (result, out) = print_all(&fixture(archive), Some("wrong"));
        assert_eq!(out.len(), plain, "{archive}");
        // either the whole run refuses the password or each encrypted member fails on its own
        if let Ok(summary) = result {
            assert!(!summary.errors.is_empty(), "{archive}");
        }
        let path = fixture(archive);
        let index = extract::list_with_password(&path, Some("wrong"))
            .unwrap()
            .iter()
            .position(|e| !e.dir && e.encrypted)
            .unwrap();
        let selected = SelectedEntry::open(&path, index, Some("wrong"), 1 << 30).unwrap();
        let mut got = Vec::new();
        assert!(
            selected
                .read(Some("wrong"), |b| {
                    got.extend_from_slice(b);
                    Ok(())
                })
                .is_err(),
            "{archive}"
        );
    }
}

#[test]
fn a_directory_or_out_of_range_entry_is_refused() {
    let path = fixture("7z-extract/solid.7z");
    let entries = extract::list(&path).unwrap();
    let dir = entries.iter().position(|e| e.dir).unwrap();
    assert!(SelectedEntry::open(&path, dir, None, 1 << 30).is_err());
    assert!(SelectedEntry::open(&path, entries.len(), None, 1 << 30).is_err());
    let big = entries.iter().position(|e| e.name == "big/one.txt").unwrap();
    assert!(SelectedEntry::open(&path, big, None, 100).is_err(), "over the byte limit");
}

/// Split ZIP sets read one entry at a time, as `-so` does (7-Zip prints the same bytes).
#[test]
fn split_zip_entries_read_one_by_one_match_7z_x_so() {
    for (set, want) in [
        ("zip-bytesplit/bytesplit.zip.001", "a1f47857d021871c1a6f17a3a468b2561c0b735161916180a6cb3be5de11a433"),
        ("zip-split/stored.zip", "0f4ed9475dd874d276e6c3627a1cf89e805b1205d0b64c0f87ac76b0ffa69236"),
        ("zip-split/deflated.zip", "46129b3a9f2be688b9bc1108eb9eae0f7b36bbfa2b0d9ba43abf6b2e698f1d16"),
    ] {
        let path = fixture(set);
        let entries = extract::list(&path).unwrap();
        let mut out = Vec::new();
        for (index, _) in entries.iter().enumerate().filter(|(_, e)| !e.dir && e.link.is_none()) {
            let selected =
                SelectedEntry::open(&path, index, None, 1 << 30).unwrap_or_else(|e| panic!("{set} #{index}: {e}"));
            selected
                .read(None, |bytes| {
                    out.extend_from_slice(bytes);
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(hex(&zipfast::crypto::sha256(&out)), want, "{set}");
        // and through the checked dispatcher prybar uses for ZIP
        let index = entries.iter().position(|e| !e.dir).unwrap();
        let checked =
            SelectedEntry::open_cancelable_with_zip_limit(&path, index, None, 1 << 30, None, Cancellation::default());
        assert!(checked.is_ok(), "{set}: {:?}", checked.err().map(|e| e.to_string()));
    }
}

/// A small member late in a solid folder needs the members before it decoded: that work counts against the
/// selection's byte limit, packed and decoded, as RAR's solid history does.
#[test]
fn a_late_member_of_a_solid_folder_counts_the_members_before_it() {
    use zipfast::zip::{ReadFault, ReadResource};
    let path = fixture("7z-extract/solid.7z");
    let entries = extract::list(&path).unwrap();
    let tiny = entries.iter().position(|e| e.name == "text/tiny.txt").unwrap();
    assert!(entries[tiny].size < 1000);
    // the whole folder fits a large budget
    assert!(SelectedEntry::open(&path, tiny, None, 1 << 30).is_ok());
    let error = SelectedEntry::open(&path, tiny, None, 1000).err().expect("refused over the budget");
    assert!(error.to_string().contains("byte limit"), "{error}");
    let error = SelectedEntry::open_cancelable_with_zip_limit(&path, tiny, None, 1000, None, Cancellation::default())
        .err()
        .expect("refused over the budget");
    assert!(
        matches!(
            error.operation(),
            Some(ReadFault::Limit { resource: ReadResource::MemberPackedBytes | ReadResource::MemberDecodedBytes, .. })
        ),
        "{error:?}"
    );
}

/// Limits that spool every member to a temporary file in `dir`.
fn on_disk(dir: &Path) -> SevenZipLimits {
    let mut limits = SevenZipLimits::default();
    limits.spool_memory_bytes = 0;
    limits.spool_dir = Some(dir.to_path_buf());
    limits
}

fn names_in(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()
}

/// Spooled to disk, the output is still byte-identical to `7z x -so`, and the spool file never has a name: the
/// spool folder is empty while a member is being copied out (its file still open) and after the run.
#[test]
fn spooling_to_disk_leaves_no_named_file_and_prints_the_same_bytes() {
    for (archive, want) in ARCHIVES {
        let dir = tempfile::tempdir().unwrap();
        let limits = on_disk(dir.path());
        let mut out = Vec::new();
        let mut seen_names = Vec::new();
        let summary = sevenzip::print_selected_with(
            &fixture(archive),
            Some("password"),
            &mut |_, _| true,
            &mut |_, bytes| {
                seen_names.extend(names_in(dir.path()));
                out.extend_from_slice(bytes);
                Ok(())
            },
            &Cancellation::default(),
            &limits,
        )
        .unwrap_or_else(|e| panic!("{archive}: {e}"));
        assert!(summary.errors.is_empty(), "{archive}: {:?}", summary.errors);
        assert_eq!(hex(&zipfast::crypto::sha256(&out)), *want, "{archive}");
        assert!(seen_names.is_empty(), "{archive}: named spool files {seen_names:?}");
        assert!(names_in(dir.path()).is_empty(), "{archive}");
    }
}

/// A run that fails (wrong password) or is canceled mid-member leaves nothing in the spool folder either.
#[test]
fn a_failed_or_canceled_print_leaves_no_spool_file() {
    let dir = tempfile::tempdir().unwrap();
    let limits = on_disk(dir.path());
    for archive in ["7z-extract/aes.7z", "7z/encrypted_files.7z"] {
        let mut out = Vec::new();
        let _ = sevenzip::print_selected(
            &fixture(archive),
            Some("wrong"),
            |_, _| true,
            &mut out,
            &Cancellation::default(),
            &limits,
        );
        assert!(names_in(dir.path()).is_empty(), "{archive}");
    }
    // canceled while the first member is being copied out
    let cancel = Cancellation::default();
    let result = sevenzip::print_selected_with(
        &fixture("7z-extract/solid.7z"),
        None,
        &mut |_, _| true,
        &mut |_, _| {
            cancel.cancel();
            Ok(())
        },
        &cancel,
        &limits,
    );
    let error = result.expect_err("canceled");
    assert!(matches!(sevenzip::SevenZipError::of(&error), Some(sevenzip::SevenZipError::Canceled)), "{error}");
    assert!(names_in(dir.path()).is_empty());
}

/// A member that would hold back more than `spool_member_bytes` fails with the typed limit and prints nothing; the
/// others still print.
#[test]
fn a_member_over_the_spool_cap_fails_and_prints_nothing() {
    let path = fixture("7z-extract/solid.7z");
    let mut limits = SevenZipLimits::default();
    limits.spool_member_bytes = 10_000;
    let mut out = Vec::new();
    let summary =
        sevenzip::print_selected(&path, None, |_, _| true, &mut out, &Cancellation::default(), &limits).unwrap();
    // big/one.txt (49,999) and big/two.txt (50,000) are over; text/* (5,999 + 2,999 + 18 + 9) print
    assert_eq!(summary.errors.len(), 2, "{:?}", summary.errors);
    assert!(summary.errors.iter().all(|e| e.contains("SpoolBytes")), "{:?}", summary.errors);
    assert_eq!(out.len(), 5_999 + 2_999 + 18 + 9);
    assert_eq!(summary.files, 4);
}
