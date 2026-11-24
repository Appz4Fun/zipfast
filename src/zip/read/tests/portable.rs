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
    // Incompressible, so the AES ciphertext stays above the 64 KiB in-memory snapshot limit.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let secret: Vec<u8> = (0..300_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
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
        windows_safe_names: false,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
        preexisting_links: Default::default(),
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

fn identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).unwrap();
    Some((meta.dev(), meta.ino()))
}

#[test]
fn portable_rename_refuses_existing_name_on_every_rung() {
    use crate::zip::read::native_policy::{Published, rename_portable};
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let handle = std::fs::File::open(dir.path()).unwrap();
    let fd = handle.as_raw_fd();
    for rung in 0..=2 {
        PORTABLE_RENAME_RUNG.with(|r| r.set(rung));
        std::fs::write(dir.path().join("stage"), b"new").unwrap();
        let ours = identity(&dir.path().join("stage"));
        std::fs::write(dir.path().join("target"), b"old").unwrap();
        let error = rename_portable(fd, c"stage", fd, c"target", false, ours).unwrap_err();
        // A raw EEXIST, so publication reads as definitely not published.
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST), "rung {rung}");
        assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"old");
        std::fs::remove_file(dir.path().join("target")).unwrap();
        assert_eq!(rename_portable(fd, c"stage", fd, c"target", false, ours).unwrap(), Published::Clean);
        assert_eq!(std::fs::read(dir.path().join("target")).unwrap(), b"new");
        assert!(!dir.path().join("stage").exists(), "rung {rung}");
        std::fs::remove_file(dir.path().join("target")).unwrap();
    }
    PORTABLE_RENAME_RUNG.with(|r| r.set(0));
}

/// Another user swaps the stage name for their own file after our descriptor closed: refused on every rung and for
/// `Always`, and the swapped-in bytes are never published.
#[test]
fn portable_rename_refuses_a_substituted_stage() {
    use crate::zip::read::native_policy::rename_portable;
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let handle = std::fs::File::open(dir.path()).unwrap();
    let fd = handle.as_raw_fd();
    for (rung, replace) in [(0, false), (1, false), (2, false), (0, true)] {
        PORTABLE_RENAME_RUNG.with(|r| r.set(rung));
        std::fs::write(dir.path().join("stage"), b"verified").unwrap();
        let ours = identity(&dir.path().join("stage"));
        std::fs::write(dir.path().join("evil"), b"attacker").unwrap();
        std::fs::rename(dir.path().join("evil"), dir.path().join("stage")).unwrap();
        let error = rename_portable(fd, c"stage", fd, c"target", replace, ours).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESTALE), "rung {rung} replace {replace}");
        assert!(!dir.path().join("target").exists());
        std::fs::remove_file(dir.path().join("stage")).unwrap();
    }
    PORTABLE_RENAME_RUNG.with(|r| r.set(0));
}

/// A hard-link publication whose stage unlink fails still publishes, and the leftover plaintext name is retired.
#[test]
fn portable_link_publication_retires_a_stage_it_could_not_unlink() {
    use crate::zip::read::native_policy::PORTABLE_UNLINK_FAILS;
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (plain, secret) = archive(&zip);
    let _forced = Forced::new(1);
    PORTABLE_UNLINK_FAILS.with(|f| f.set(true));
    for overwrite in [Overwrite::Skip, Overwrite::RenameNew(RenameStyle::Underscore)] {
        let dest = tempfile::tempdir().unwrap();
        let report = run(&zip, dest.path(), overwrite, StagedStorage::Auto).unwrap();
        assert_eq!((report.files(), report.failed()), (2, 0), "{overwrite:?}");
        assert_eq!(names(dest.path()), ["a.txt", "s.bin"], "{overwrite:?}");
        assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), plain);
        assert_eq!(std::fs::read(dest.path().join("s.bin")).unwrap(), secret);
    }
    PORTABLE_UNLINK_FAILS.with(|f| f.set(false));
}

/// `run_with_context` plans streaming only for its own run; the caller's context gets its setting back.
#[test]
fn run_with_context_restores_the_stream_setting() {
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (_, secret) = archive(&zip);
    let dest = tempfile::tempdir().unwrap();
    let options = Options {
        mode: Mode::Extract,
        dest: dest.path().into(),
        overwrite: Overwrite::Skip,
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
    };
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    assert!(!context.options.stream_staged_aes);
    let report = crate::zip::run_with_context(
        &zip,
        &options,
        Some("pw"),
        &Cancellation::default(),
        &mut context,
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed(), report.usage().member_spool_bytes), (2, 0, 0));
    assert_eq!(std::fs::read(dest.path().join("s.bin")).unwrap(), secret);
    assert!(!context.options.stream_staged_aes);
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

#[allow(clippy::result_large_err)] // The public checked result.
fn callback_read(zip: &Path, storage: StagedStorage, temp: &Path) -> ZipReadResult<(Vec<u8>, EncryptedReadUsage)> {
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(zip, &cancel)?;
    let overrides =
        EncryptedReadOverrides { staged_storage: storage, temp_dir: Some(temp.to_path_buf()), ..Default::default() };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(1),
        None,
        ZipReadOutput::Callback,
        Some("pw"),
        &overrides,
        &cancel,
    )?;
    let mut out = Vec::new();
    session.read_at_with_context(1, Some("pw"), u64::MAX, &cancel, &mut context, |b| {
        out.extend_from_slice(b);
        Ok(())
    })?;
    Ok((out, context.usage()))
}

/// A caller-callback AES read still spools (its sink must only see authenticated bytes). With the temp directory
/// outside the native allow-list it falls back to a portable spool under `Auto` and stays refused under `NativeOnly`.
#[test]
fn spool_on_unsupported_temp_dir_falls_back_unless_native_only() {
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (_, secret) = archive(&zip);
    let temp = tempfile::tempdir().unwrap();
    let _forced = Forced::new(0);
    for storage in [StagedStorage::Auto, StagedStorage::PortableOnly] {
        let (out, usage) = callback_read(&zip, storage, temp.path()).unwrap();
        assert_eq!(out, secret, "{storage:?}");
        assert!(usage.member_spool_bytes > 0, "{storage:?}: {usage:?}");
        assert_eq!(usage.live_fds, 0);
        assert_eq!(names(temp.path()), Vec::<String>::new(), "{storage:?}");
    }
    let error = callback_read(&zip, StagedStorage::NativeOnly, temp.path()).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::UnsupportedStorage)), "{error:?}");
    assert_eq!(names(temp.path()), Vec::<String>::new());
}

/// Optional real-filesystem run: `ZIPFAST_ANYFS_DEST=/Volumes/exfat cargo test spool_on_real_portable_temp_dir`.
#[test]
fn spool_on_real_portable_temp_dir() {
    let Some(base) = std::env::var_os("ZIPFAST_ANYFS_DEST") else { return };
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (_, secret) = archive(&zip);
    let temp = tempfile::tempdir_in(base).unwrap();
    let (out, usage) = callback_read(&zip, StagedStorage::Auto, temp.path()).unwrap();
    assert_eq!(out, secret);
    assert!(usage.member_spool_bytes > 0);
}

/// Another user moves our portable spool away and puts their own file under its name just before we unlink it.
/// We remove their file, ours keeps a link: the read must fail instead of continuing with a named spool.
#[test]
fn portable_spool_swapped_before_unlink_fails_the_read() {
    use crate::zip::read::spool::hooks::HOOK;
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    archive(&zip);
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().to_path_buf();
    let _forced = Forced::new(0);
    let mut swapped = false;
    HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, _| {
            if op == ReadIoOperation::Unlink && !swapped {
                swapped = true;
                let spool = std::fs::read_dir(&dir)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| p.file_name().unwrap().to_string_lossy().starts_with(".zipfast"))
                    .expect("spool name");
                std::fs::rename(&spool, dir.join("moved")).unwrap();
                std::fs::write(&spool, b"someone else's file").unwrap();
            }
            None
        }))
    });
    let result = callback_read(&zip, StagedStorage::Auto, temp.path());
    HOOK.with(|h| *h.borrow_mut() = None);
    let error = result.unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::UnsupportedIdentity)), "{error:?}");
    // Their file under the spool name was the one removed; ours survives only under the name it was moved to.
    assert_eq!(names(temp.path()), ["moved"]);
}

/// The verified-stdout route stages through a private file in the temp directory, then copies it out.
#[allow(clippy::result_large_err)] // The public checked result.
fn stdout_read(zip: &Path, ordinal: usize, password: Option<&str>, temp: &Path, max: u64) -> ZipReadResult<Vec<u8>> {
    use std::io::{Read, Seek};
    use std::os::fd::AsFd;
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(zip, &cancel)?;
    let overrides = EncryptedReadOverrides { temp_dir: Some(temp.to_path_buf()), ..Default::default() };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(ordinal),
        None,
        ZipReadOutput::VerifiedStdout,
        password,
        &overrides,
        &cancel,
    )?;
    let mut out = tempfile::tempfile().unwrap();
    session.admit_output_fd(out.as_fd(), &mut context)?;
    let mut stage = ZipReadStage::prepare_stdout(session.stage_entry(ordinal).unwrap(), &cancel, &mut context)?;
    if let Err(error) =
        session.read_at_with_context(ordinal, password, max, &cancel, &mut context, |b| stage.write_all(b, &cancel))
    {
        return Err(stage.finish_error(error, &mut context));
    }
    stage.copy_verified(&mut out, &cancel, &mut context, |c| session.check_source(c))?;
    out.rewind().unwrap();
    let mut bytes = Vec::new();
    out.read_to_end(&mut bytes).unwrap();
    Ok(bytes)
}

/// Stdout of AES and plain members through a portable temp directory: forced through the test hook here, and on a
/// real filesystem (exFAT renumbers the unlinked stage's inode) with `ZIPFAST_ANYFS_DEST`.
#[test]
fn stdout_through_portable_temp_dir() {
    let work = tempfile::tempdir().unwrap();
    let zip = work.path().join("a.zip");
    let (plain, secret) = archive(&zip);
    let real = std::env::var_os("ZIPFAST_ANYFS_DEST");
    let temp = match &real {
        Some(base) => tempfile::tempdir_in(base).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let _forced = real.is_none().then(|| Forced::new(0));
    assert_eq!(stdout_read(&zip, 0, Some("pw"), temp.path(), u64::MAX).unwrap(), plain);
    assert_eq!(stdout_read(&zip, 1, Some("pw"), temp.path(), u64::MAX).unwrap(), secret);
    assert_eq!(names(temp.path()).iter().filter(|n| n.contains("zipfast")).count(), 0);
}
