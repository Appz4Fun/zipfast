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

//! The portable staged backend behind the test-only "filesystem unsupported" control, and its no-replace ladder.
use crate::extract::{Cancellation, Mode, Options, Overwrite, RenameStyle};
use crate::zip::read::native_policy::PORTABLE_RENAME_RUNG;
use crate::zip::read::output::file::FORCE_UNSUPPORTED;
use crate::zip::write::{
    AesStrength, AesVariant, DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions,
    WinZipAesRequest, WriterOptions, ZipStreamWriter,
};
use crate::zip::*;
use std::path::Path;

fn entry(name: &str) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method: Method::Deflate(DeflateLevel::new(6).unwrap()),
        modified: DosDateTime::new(2024, 5, 6, 7, 8, 10).unwrap(),
        extended_mtime: None,
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"",
    }
}

fn archive(path: &Path) -> (Vec<u8>, Vec<u8>) {
    let plain: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
    let secret: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let mut writer = ZipStreamWriter::new(std::fs::File::create(path).unwrap(), WriterOptions::default()).unwrap();
    writer.add_file(entry("a.txt"), &mut plain.as_slice(), InputLength::Exact(plain.len() as u64)).unwrap();
    writer
        .add_winzip_aes_file(
            entry("s.bin"),
            &mut secret.as_slice(),
            InputLength::Exact(secret.len() as u64),
            WinZipAesRequest::new("pw", AesStrength::Aes128, AesVariant::Ae1).unwrap(),
            |salt| {
                salt.fill(7);
                Ok(())
            },
        )
        .unwrap();
    writer.finish().unwrap();
    (plain, secret)
}

#[allow(clippy::result_large_err)] // The public checked result.
fn run(archive: &Path, dest: &Path, overwrite: Overwrite, storage: StagedStorage) -> ZipReadResult<ZipRunReport> {
    let options = Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
    };
    let overrides = EncryptedReadOverrides { staged_storage: storage, ..Default::default() };
    crate::zip::run_with_policy(
        archive,
        &options,
        Some("pw"),
        &Cancellation::default(),
        &overrides,
        |_: ZipRunEvent<'_>| Ok(()),
    )
}

struct Forced;
impl Forced {
    fn new(rung: u8) -> Self {
        FORCE_UNSUPPORTED.with(|f| f.set(true));
        PORTABLE_RENAME_RUNG.with(|r| r.set(rung));
        Self
    }
}
impl Drop for Forced {
    fn drop(&mut self) {
        FORCE_UNSUPPORTED.with(|f| f.set(false));
        PORTABLE_RENAME_RUNG.with(|r| r.set(0));
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> =
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

#[test]
fn unsupported_filesystem_falls_back_to_portable() {
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (plain, secret) = archive(&zip);
    let _forced = Forced::new(0);
    let dest = tempfile::tempdir().unwrap();
    let report = run(&zip, dest.path(), Overwrite::Skip, StagedStorage::Auto).unwrap();
    assert_eq!((report.files(), report.failed(), report.portable_files(), report.native_files()), (2, 0, 2, 0));
    assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), plain);
    assert_eq!(std::fs::read(dest.path().join("s.bin")).unwrap(), secret);
    assert_eq!(report.usage().member_spool_bytes, 0);
    assert_eq!(report.usage().live_fds, 0);
    assert_eq!(names(dest.path()), ["a.txt", "s.bin"]);
    let meta = std::fs::metadata(dest.path().join("a.txt")).unwrap();
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777, 0o640);
    // The archived 2024 time was restored (best effort, but every local test filesystem keeps it).
    let modified = meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!((1_704_067_200..1_735_689_600).contains(&modified), "{modified}");
    // The native-only policy keeps the old refusal.
    let dest = tempfile::tempdir().unwrap();
    let error = run(&zip, dest.path(), Overwrite::Skip, StagedStorage::NativeOnly).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::UnsupportedStorage)), "{error:?}");
    assert!(names(dest.path()).is_empty());
}

#[test]
fn portable_no_replace_ladder_keeps_every_overwrite_mode() {
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (plain, _) = archive(&zip);
    for rung in 0..=2 {
        let _forced = Forced::new(rung);
        for overwrite in [
            Overwrite::Skip,
            Overwrite::Always,
            Overwrite::RenameNew(RenameStyle::Underscore),
            Overwrite::RenameExisting(RenameStyle::Parenthesized),
        ] {
            let dest = tempfile::tempdir().unwrap();
            std::fs::write(dest.path().join("a.txt"), b"old").unwrap();
            let report = run(&zip, dest.path(), overwrite, StagedStorage::Auto).unwrap();
            assert_eq!(report.failed(), 0, "rung {rung} {overwrite:?}");
            let at = |name: &str| std::fs::read(dest.path().join(name)).unwrap();
            let (expected, a): (&[&str], &[u8]) = match overwrite {
                Overwrite::Skip => (&["a.txt", "s.bin"], b"old"),
                Overwrite::Always => (&["a.txt", "s.bin"], &plain),
                Overwrite::RenameNew(_) => {
                    assert_eq!(at("a_1.txt"), plain);
                    (&["a.txt", "a_1.txt", "s.bin"], b"old")
                }
                _ => {
                    assert_eq!(at("a(1).txt"), b"old");
                    (&["a(1).txt", "a.txt", "s.bin"], &plain)
                }
            };
            assert_eq!(at("a.txt"), a, "rung {rung} {overwrite:?}");
            assert_eq!(names(dest.path()), expected, "rung {rung} {overwrite:?}");
            assert_eq!(report.usage().live_fds, 0);
        }
    }
}

#[test]
fn portable_rename_refuses_existing_name_on_every_rung() {
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let handle = std::fs::File::open(dir.path()).unwrap();
    for rung in 0..=2 {
        PORTABLE_RENAME_RUNG.with(|r| r.set(rung));
        std::fs::write(dir.path().join("stage"), b"new").unwrap();
        std::fs::write(dir.path().join("target"), b"old").unwrap();
        let error = crate::zip::read::native_policy::rename_portable(
            handle.as_raw_fd(),
            c"stage",
            handle.as_raw_fd(),
            c"target",
            false,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists, "rung {rung}");
        assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"old");
        std::fs::remove_file(dir.path().join("target")).unwrap();
        crate::zip::read::native_policy::rename_portable(
            handle.as_raw_fd(),
            c"stage",
            handle.as_raw_fd(),
            c"target",
            false,
        )
        .unwrap();
        assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"new");
        assert!(!dir.path().join("stage").exists(), "rung {rung}");
        std::fs::remove_file(dir.path().join("target")).unwrap();
    }
    PORTABLE_RENAME_RUNG.with(|r| r.set(0));
}

#[test]
fn portable_tampered_aes_leaves_nothing() {
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (plain, _) = archive(&zip);
    let mut bytes = std::fs::read(&zip).unwrap();
    let at = bytes.windows(5).position(|w| w == b"s.bin").unwrap();
    let extra = u16::from_le_bytes([bytes[at - 2], bytes[at - 1]]) as usize;
    bytes[at + 5 + extra + 8 + 2 + 2_000] ^= 1;
    std::fs::write(&zip, bytes).unwrap();
    let _forced = Forced::new(0);
    let dest = tempfile::tempdir().unwrap();
    let report = run(&zip, dest.path(), Overwrite::Skip, StagedStorage::Auto).unwrap();
    assert_eq!((report.files(), report.failed()), (1, 1));
    assert_eq!(names(dest.path()), ["a.txt"]);
    assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), plain);
}
