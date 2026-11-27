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

//! Checked staged output on destinations outside the native allow-list, and streamed WinZip AES.
#![cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::{Path, PathBuf};
use zipfast::extract::{Cancellation, Mode, Options, Overwrite};
use zipfast::zip::write::{
    AesStrength, AesVariant, DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions,
    WinZipAesRequest, WriterOptions, ZipStreamWriter,
};
use zipfast::zip::*;

fn entry(name: &str, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"",
    }
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(seed as u32 % 31) as u8 ^ seed).collect()
}

/// Small plain files, a directory, and one AES entry far above the old 64 KiB spool threshold.
fn fixture(path: &Path, aes_len: usize) -> Vec<(String, Vec<u8>)> {
    let mut writer = ZipStreamWriter::new(std::fs::File::create(path).unwrap(), WriterOptions::default()).unwrap();
    let mut files = Vec::new();
    writer
        .add_directory(EntryOptions { permissions: Permissions::new(0o755).unwrap(), ..entry("dir/", Method::Stored) })
        .unwrap();
    for (i, name) in ["a.txt", "dir/b.bin", "dir/c.txt"].into_iter().enumerate() {
        let data = payload(i as u8 + 1, 1000 + i * 3000);
        let method = if i % 2 == 0 { Method::Deflate(DeflateLevel::new(6).unwrap()) } else { Method::Stored };
        writer.add_file(entry(name, method), &mut data.as_slice(), InputLength::Exact(data.len() as u64)).unwrap();
        files.push((name.to_string(), data));
    }
    let data = payload(9, aes_len);
    writer
        .add_winzip_aes_file(
            entry("dir/secret.bin", Method::Deflate(DeflateLevel::new(1).unwrap())),
            &mut data.as_slice(),
            InputLength::Exact(data.len() as u64),
            WinZipAesRequest::new("password", AesStrength::Aes256, AesVariant::Ae2).unwrap(),
            |salt| {
                salt.fill(0x5a);
                Ok(())
            },
        )
        .unwrap();
    files.push(("dir/secret.bin".to_string(), data));
    writer.finish().unwrap().sink.sync_all().unwrap();
    files
}

fn options(dest: &Path, overwrite: Overwrite) -> Options {
    Options {
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
    }
}

fn destination() -> (Option<tempfile::TempDir>, PathBuf) {
    match std::env::var_os("ZIPFAST_ANYFS_DEST") {
        Some(base) => {
            let dir = tempfile::tempdir_in(base).unwrap();
            let path = dir.path().to_path_buf();
            if std::env::var_os("ZIPFAST_ANYFS_KEEP").is_some() {
                return (None, dir.keep());
            }
            (Some(dir), path)
        }
        None => {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().to_path_buf();
            (Some(dir), path)
        }
    }
}

fn overrides(storage: StagedStorage) -> EncryptedReadOverrides {
    let mut overrides = EncryptedReadOverrides::default();
    overrides.staged_storage = storage;
    // A staged AES member streams; no private spool directory is resolved, so an unusable one is harmless.
    overrides.temp_dir = Some(PathBuf::from("/nonexistent/zipfast-spool"));
    overrides
}

#[allow(clippy::result_large_err)] // The public checked result.
fn run(
    archive: &Path,
    dest: &Path,
    overwrite: Overwrite,
    password: &str,
    storage: StagedStorage,
) -> ZipReadResult<ZipRunReport> {
    run_with_policy(
        archive,
        &options(dest, overwrite),
        Some(password),
        &Cancellation::default(),
        &overrides(storage),
        |_: ZipRunEvent<'_>| Ok(()),
    )
}

/// Every name under `dir`, recursively, relative and sorted.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(path.strip_prefix(base).unwrap().to_string_lossy().into_owned());
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Flips one ciphertext byte of the AES member, well inside its payload.
fn tamper(archive: &Path) {
    let mut bytes = std::fs::read(archive).unwrap();
    let name = b"dir/secret.bin";
    let at = bytes.windows(name.len()).position(|w| w == name).unwrap();
    let header = at - 30;
    assert_eq!(&bytes[header..header + 4], b"PK\x03\x04");
    let extra = u16::from_le_bytes([bytes[header + 28], bytes[header + 29]]) as usize;
    let ciphertext = at + name.len() + extra + 16 + 2;
    bytes[ciphertext + 70_000] ^= 0x40;
    std::fs::write(archive, bytes).unwrap();
}

fn check_tree(dest: &Path, files: &[(String, Vec<u8>)]) {
    for (name, data) in files {
        assert_eq!(&std::fs::read(dest.join(name)).unwrap(), data, "{name}");
    }
    assert!(tree(dest).iter().all(|n| !n.contains(".zipfast") && !n.contains("~zipfast")), "{:?}", tree(dest));
}

#[test]
fn extracts_on_any_destination() {
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let files = fixture(&archive, 3 << 20);
    let (_guard, dest) = destination();
    let report = run(&archive, &dest, Overwrite::Skip, "password", StagedStorage::Auto).unwrap();
    println!("native={} portable={}", report.native_files(), report.portable_files());
    assert_eq!((report.files(), report.failed()), (4, 0));
    assert_eq!(report.native_files() + report.portable_files(), 4);
    assert_eq!(report.usage().member_spool_bytes, 0);
    check_tree(&dest, &files);
}

/// The portable backend, forced on whatever the destination is: the stand-in for ZFS, NFS, SMB, FUSE, overlayfs...
#[test]
fn portable_backend_publishes_every_member() {
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let files = fixture(&archive, 3 << 20);
    let (_guard, dest) = destination();
    let report = run(&archive, &dest, Overwrite::Skip, "password", StagedStorage::PortableOnly).unwrap();
    assert_eq!((report.files(), report.failed(), report.portable_files(), report.native_files()), (4, 0, 4, 0));
    check_tree(&dest, &files);
    let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(dest.join("a.txt")).unwrap().permissions());
    if std::env::var_os("ZIPFAST_ANYFS_DEST").is_none() {
        assert_eq!(mode & 0o777, 0o644);
    }
}

/// A large WinZip AES member streams straight into its stage: no spool, no temp directory, published once the
/// HMAC matches. Tampered, it fails with a typed authentication error and leaves nothing behind.
#[test]
fn streamed_aes_publishes_only_authenticated_output() {
    for storage in [StagedStorage::Auto, StagedStorage::PortableOnly] {
        let work = tempfile::tempdir().unwrap();
        let archive = work.path().join("a.zip");
        let files = fixture(&archive, 8 << 20);
        let (_guard, dest) = destination();
        let report = run(&archive, &dest, Overwrite::Skip, "password", storage).unwrap();
        assert_eq!((report.files(), report.failed()), (4, 0), "{storage:?}");
        assert_eq!((report.usage().member_spool_bytes, report.usage().live_spool_bytes), (0, 0));
        check_tree(&dest, &files);

        tamper(&archive);
        let (_guard, dest) = destination();
        let mut failures = Vec::new();
        let report = run_with_policy(
            &archive,
            &options(&dest, Overwrite::Skip),
            Some("password"),
            &Cancellation::default(),
            &overrides(storage),
            |event: ZipRunEvent<'_>| {
                if let ZipRunEvent::MemberFailed { name, error, .. } = event {
                    failures.push((
                        name.to_string(),
                        matches!(error.operation(), Some(ReadFault::AuthenticationFailed)),
                        error.publication_state(),
                        error.cleanup_errors().len(),
                    ));
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((report.files(), report.failed()), (3, 1), "{storage:?}");
        assert_eq!(failures, [("dir/secret.bin".to_string(), true, PublicationState::NotPublished, 0)], "{storage:?}");
        assert!(!dest.join("dir/secret.bin").exists());
        check_tree(&dest, &files[..3]);
    }
}

#[test]
fn portable_overwrite_modes() {
    use zipfast::extract::RenameStyle;
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let files = fixture(&archive, 200_000);
    let (_guard, dest) = destination();
    let a = dest.join("a.txt");
    let fresh = &files[0].1;
    for (overwrite, kept, member_at) in [
        (Overwrite::Skip, true, None),
        (Overwrite::Always, false, Some("a.txt")),
        (Overwrite::RenameNew(RenameStyle::Underscore), true, Some("a_1.txt")),
        (Overwrite::RenameExisting(RenameStyle::Parenthesized), false, Some("a.txt")),
    ] {
        for name in tree(&dest).into_iter().rev() {
            let path = dest.join(name);
            // Some filesystems keep sidecar names (macOS AppleDouble `._x` on exFAT) that vanish with their file.
            let _ = if path.is_dir() { std::fs::remove_dir(path) } else { std::fs::remove_file(path) };
        }
        std::fs::write(&a, b"old").unwrap();
        let report = run(&archive, &dest, overwrite, "password", StagedStorage::PortableOnly).unwrap();
        assert_eq!(report.failed(), 0, "{overwrite:?}");
        assert_eq!(std::fs::read(&a).unwrap() == b"old", kept, "{overwrite:?}");
        if let Some(at) = member_at {
            assert_eq!(&std::fs::read(dest.join(at)).unwrap(), fresh, "{overwrite:?}");
        }
        if matches!(overwrite, Overwrite::RenameExisting(_)) {
            assert_eq!(std::fs::read(dest.join("a(1).txt")).unwrap(), b"old");
        }
        if overwrite == Overwrite::Skip {
            assert_eq!(report.skipped(), 1);
        }
        check_tree(&dest, &files[1..]);
    }
}

#[test]
fn native_only_refuses_or_runs_natively() {
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    fixture(&archive, 100_000);
    let (_guard, dest) = destination();
    match run(&archive, &dest, Overwrite::Skip, "password", StagedStorage::NativeOnly) {
        Ok(report) => assert_eq!((report.native_files(), report.portable_files()), (4, 0)),
        Err(error) => {
            assert!(matches!(error.operation(), Some(ReadFault::UnsupportedStorage)), "{error:?}");
            assert!(!dest.join("a.txt").exists());
        }
    }
}

/// `Publication::Bulk`: every member through the portable stage with no per-file flush, the same results, overwrite
/// policy and tamper refusal, and no leftover stage names.
#[test]
fn bulk_publication_matches_staged_results() {
    use zipfast::extract::RenameStyle;
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let files = fixture(&archive, 1 << 20);
    let (_guard, dest) = destination();
    let mut overrides = overrides(StagedStorage::Auto);
    overrides.publication = Publication::Bulk;
    let bulk = |dest: &Path, overwrite: Overwrite| {
        run_with_policy(
            &archive,
            &options(dest, overwrite),
            Some("password"),
            &Cancellation::default(),
            &overrides,
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap()
    };
    let report = bulk(&dest, Overwrite::Skip);
    assert_eq!((report.files(), report.failed(), report.portable_files()), (4, 0, 4));
    check_tree(&dest, &files);
    // Skip keeps what is there; Always replaces it; RenameNew writes beside it.
    std::fs::write(dest.join("a.txt"), b"old").unwrap();
    assert_eq!(bulk(&dest, Overwrite::Skip).skipped(), 4);
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"old");
    bulk(&dest, Overwrite::RenameNew(RenameStyle::Underscore));
    assert_eq!(std::fs::read(dest.join("a_1.txt")).unwrap(), files[0].1);
    bulk(&dest, Overwrite::Always);
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), files[0].1);
    assert!(tree(&dest).iter().all(|n| !n.contains("zipfast")), "{:?}", tree(&dest));
    // NativeOnly keeps native staging where the destination allows it.
    let (_guard, native) = destination();
    overrides.staged_storage = StagedStorage::NativeOnly;
    let report = run_with_policy(
        &archive,
        &options(&native, Overwrite::Skip),
        Some("password"),
        &Cancellation::default(),
        &overrides,
        |_: ZipRunEvent<'_>| Ok(()),
    );
    if let Ok(report) = report {
        assert_eq!(report.portable_files(), 0);
    }
}

/// A destination root reached through a symlink (macOS `/tmp` is one) is caller configuration: a Bulk run publishes
/// and flushes through it without a Flush fault.
#[test]
fn bulk_publication_through_a_symlinked_destination_root() {
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let files = fixture(&archive, 200_000);
    let real = work.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = work.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut overrides = overrides(StagedStorage::Auto);
    overrides.publication = Publication::Bulk;
    let report = run_with_policy(
        &archive,
        &options(&link, Overwrite::Skip),
        Some("password"),
        &Cancellation::default(),
        &overrides,
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed()), (4, 0));
    check_tree(&real, &files);
}

fn bulk_overrides() -> EncryptedReadOverrides {
    let mut overrides = overrides(StagedStorage::Auto);
    overrides.publication = Publication::Bulk;
    overrides
}

/// A flattened Bulk run flushes the directory its files really went to (the root), not their archive folders,
/// which a flattened run never creates.
#[test]
fn bulk_publication_with_flatten_flushes_the_root() {
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let files = fixture(&archive, 1000);
    let dest = work.path().join("out");
    let report = run_with_policy(
        &archive,
        &Options { flatten: true, ..options(&dest, Overwrite::Always) },
        Some("password"),
        &Cancellation::default(),
        &bulk_overrides(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed()), (4, 0));
    for (name, data) in &files {
        assert_eq!(std::fs::read(dest.join(Path::new(name).file_name().unwrap())).unwrap(), *data, "{name}");
    }
}

/// An archived directory mode that no longer lets the directory be opened (0300) is restored after the run's
/// directory flush, so it doesn't turn a successful Bulk extraction into a Flush fault.
#[test]
fn bulk_publication_flushes_before_restoring_restrictive_directory_modes() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let mut writer = ZipStreamWriter::new(std::fs::File::create(&archive).unwrap(), WriterOptions::default()).unwrap();
    writer
        .add_directory(EntryOptions {
            permissions: Permissions::new(0o300).unwrap(),
            ..entry("locked/", Method::Stored)
        })
        .unwrap();
    writer.add_file(entry("locked/f.txt", Method::Stored), &mut &b"data"[..], InputLength::Exact(4)).unwrap();
    writer.finish().unwrap().sink.sync_all().unwrap();
    let dest = work.path().join("out");
    let report = run_with_policy(
        &archive,
        &options(&dest, Overwrite::Always),
        None,
        &Cancellation::default(),
        &bulk_overrides(),
        |_: ZipRunEvent<'_>| Ok(()),
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dest.join("locked")).unwrap().permissions().mode() & 0o777;
    std::fs::set_permissions(dest.join("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let report = report.unwrap();
    assert_eq!((report.files(), report.failed()), (1, 0));
    assert_eq!(mode, 0o300);
    assert_eq!(std::fs::read(dest.join("locked/f.txt")).unwrap(), b"data");
}

/// The checked route's start hook sees the path a member is published at (flattened when flattening) and is not
/// asked about a member whose target is blocked (an existing directory under `Always`).
#[test]
fn start_hook_sees_published_paths_and_never_blocked_targets() {
    use std::sync::{Arc, Mutex};
    use zipfast::extract::{MemberFilter, StartDecision};
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    fixture(&archive, 1000);
    for flatten in [false, true] {
        let dest = work.path().join(format!("out{flatten}"));
        std::fs::create_dir_all(dest.join("a.txt")).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let filter = MemberFilter::all().on_start(move |start| {
            record.lock().unwrap().push(start.path.to_path_buf());
            StartDecision::Write
        });
        let report = run_with_policy(
            &archive,
            &Options { flatten, select: Some(filter), ..options(&dest, Overwrite::Always) },
            Some("password"),
            &Cancellation::default(),
            &overrides(StagedStorage::Auto),
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap();
        assert_eq!(report.failed(), 1, "a.txt is blocked by the directory");
        let mut seen = seen.lock().unwrap().clone();
        seen.sort();
        let mut want: Vec<PathBuf> = ["dir/b.bin", "dir/c.txt", "dir/secret.bin"]
            .iter()
            .map(|n| if flatten { dest.join(Path::new(n).file_name().unwrap()) } else { dest.join(n) })
            .collect();
        want.sort();
        assert_eq!(seen, want, "flatten {flatten}");
    }
}

/// The start hook is asked before the member's payload storage is admitted: a member larger than the live spool
/// limit that the hook skips never charges its decoded size, so the run goes on to the other members.
#[test]
#[allow(clippy::result_large_err)] // The public checked result.
fn a_start_hook_skip_comes_before_payload_storage_is_admitted() {
    use zipfast::extract::{MemberFilter, StartDecision};
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join("a.zip");
    let files = fixture(&archive, 200_000);
    let mut limited = overrides(StagedStorage::Auto);
    limited.live_spool_bytes = Some(100_000);
    let run = |dest: &Path, select: Option<MemberFilter>| {
        run_with_policy(
            &archive,
            &Options { select, ..options(dest, Overwrite::Always) },
            Some("password"),
            &Cancellation::default(),
            &limited,
            |_: ZipRunEvent<'_>| Ok(()),
        )
    };
    // without the hook the over-limit member is refused
    let refused = run(&work.path().join("all"), None);
    assert!(refused.as_ref().map_or(true, |report| report.failed() > 0), "{refused:?}");

    let dest = work.path().join("skip");
    let filter = MemberFilter::all().on_start(|start| {
        if start.path.ends_with("dir/secret.bin") { StartDecision::Skip } else { StartDecision::Write }
    });
    let report = run(&dest, Some(filter)).unwrap();
    assert_eq!((report.files(), report.failed()), (3, 0));
    for (name, data) in files.iter().filter(|(name, _)| name != "dir/secret.bin") {
        assert_eq!(std::fs::read(dest.join(name)).unwrap(), *data, "{name}");
    }
    assert!(!dest.join("dir/secret.bin").exists());
}
