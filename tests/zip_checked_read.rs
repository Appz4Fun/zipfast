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

#[allow(dead_code)] // Shared ZIP fixture covers metadata cases used by other targets.
#[path = "common/zip_parity_fixture.rs"]
mod fixture;
use std::io::Write;
use zipfast::extract::Cancellation;
use zipfast::zip::{
    EncryptedReadContext, EncryptedReadOverrides, ProjectedReadScope, ProjectedReadSession, ZipReadOutput,
};

#[test]
fn public_checked_clear_read_and_consumed_plan() {
    let bytes = fixture::build(&[fixture::Member::stored(b"one", b"payload")], &[0], b"", b"", false).bytes;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        Some(64),
        ZipReadOutput::Callback,
        None,
        &EncryptedReadOverrides::default(),
        &cancel,
    )
    .unwrap();
    let mut out = Vec::new();
    session
        .read_at_with_context(0, None, 64, &cancel, &mut context, |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(out, b"payload");
    assert_eq!(context.usage().members, 0);
    assert_eq!(context.run_usage().records, 1);
    assert!(session.read_at_with_context(0, None, 64, &cancel, &mut context, |_| Ok(())).is_err());
    session.check_source(&mut context).unwrap();
}

#[path = "common/mod.rs"]
mod common;
#[test]
fn checked_generic_recognized_rar_is_terminal_while_legacy_falls_through() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::ReadFault;
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.part1.rar");
    let next = dir.path().join("multi.part2.rar");
    let mut prefix = b"launcher".to_vec();
    prefix.extend(common::SIG);
    prefix.extend(common::main_block(true, None));
    prefix.extend(common::end_block(true));
    let zip = fixture::build(&[fixture::Member::stored(b"zip", b"one")], &[0], &prefix, b"", false).bytes;
    std::fs::write(&first, &zip).unwrap();
    std::fs::write(&next, b"not a rar volume").unwrap();
    let old = SelectedEntry::open(&first, 0, None, 64).unwrap();
    assert!(old.is_zip());
    assert_eq!(old.name(), "zip");
    let error = SelectedEntry::open_cancelable_with_zip_limit(&first, 0, None, 64, None, Cancellation::default())
        .err()
        .unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use zipfast::extract::{self, Mode, Options, Overwrite};
        use zipfast::zip::ZipRunEvent;
        let options = Options {
            mode: Mode::Test,
            dest: dir.path().join("out"),
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
            refused_link_placeholder: false,
            restart_from_first_volume: false,
            replace_placed_links: false,
            keep_broken: false,
            attempt_continued_members: false,
        };
        let error = extract::run_with_zip_policy(
            &first,
            &options,
            None,
            &Cancellation::default(),
            &Default::default(),
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))));
        let mut context = EncryptedReadContext::new(Default::default()).unwrap();
        let error = extract::run_with_zip_context(
            &first,
            &options,
            None,
            &Cancellation::default(),
            &mut context,
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))));
        for command in ["t", "l", "v"] {
            let result =
                std::process::Command::new(env!("CARGO_BIN_EXE_zipfast")).arg(command).arg(&first).output().unwrap();
            assert_eq!(result.status.code(), Some(2), "{command}: {result:?}");
            assert!(!String::from_utf8_lossy(&result.stdout).contains("zip"));
        }
        assert_eq!(std::fs::read(&first).unwrap(), zip);
    }
}
#[test]
fn checked_rar_selected_header_parity_and_old_nonzip_consuming_read() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::ReadFault;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("one.rar");
    std::fs::write(&path, common::archive(&[common::FileSpec::new("rar", b"bytes")])).unwrap();
    let mut selected =
        SelectedEntry::open_cancelable_with_zip_limit(&path, 0, None, 64, Some(u64::MAX), Cancellation::default())
            .unwrap();
    assert!(!selected.is_zip());
    assert_eq!(selected.name(), "rar");
    assert!(selected.zip_read_context(None, ZipReadOutput::Callback, &Default::default()).unwrap().is_none());
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    assert!(matches!(
        selected.read_with_zip_context(None, &mut context, |_| Ok(())).unwrap_err().operation(),
        Some(ReadFault::UnsupportedCheckedFormat)
    ));
    let mut out = Vec::new();
    selected
        .read(None, |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(out, b"bytes");
}
#[test]
fn original_zip64_selection_override_replaces_default_before_factory() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::{ReadFault, ReadResource, ReadSession};
    let mut member = fixture::Member::stored(b"entry", b"123456789012345");
    member.flags = 1;
    member.zip64 = true;
    let mut zip = fixture::build(&[member], &[0], b"", b"", false);
    let central = zip.central[0];
    let extra = central + 46 + b"entry".len();
    let huge = (8u64 << 30) + 1;
    // Deliberately synthetic declaration: this tests constructor admission,
    // not physical multi-GiB decode/throughput (qualified in Tasks6/7).
    zip.bytes[extra + 4..extra + 12].copy_from_slice(&huge.to_le_bytes());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&zip.bytes).unwrap();
    assert!(SelectedEntry::open(file.path(), 0, None, 8 << 30).is_err());
    let error = SelectedEntry::open_cancelable_with_zip_limit(file.path(), 0, None, 1, None, Cancellation::default())
        .err()
        .unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::MemberPackedBytes, .. })));
    let mut selected = SelectedEntry::open_cancelable_with_zip_limit(
        file.path(),
        0,
        None,
        8 << 30,
        Some(huge),
        Cancellation::default(),
    )
    .unwrap();
    let c = selected.zip_read_context(Some("pw"), ZipReadOutput::Callback, &Default::default()).unwrap().unwrap();
    assert_eq!(c.options().limits().member_decoded_bytes, huge);
    let mut retained = ReadSession::open(file.path()).unwrap();
    let id = retained.metadata().entry_id(0).unwrap();
    assert!(retained.select(&id, 8 << 30, Cancellation::default()).is_err());
    assert!(retained.select(&id, huge, Cancellation::default()).is_ok());
    zip.bytes[central + 8..central + 10].copy_from_slice(&0u16.to_le_bytes());
    std::fs::write(file.path(), &zip.bytes).unwrap();
    assert!(
        SelectedEntry::open_cancelable_with_zip_limit(
            file.path(),
            0,
            None,
            8 << 30,
            Some(huge),
            Cancellation::default()
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn raw_bootstrap_child() {
    use std::path::Path;
    use zipfast::zip::ReadFault;
    let Ok(case) = std::env::var("ZIPFAST_TASK4_BOOTSTRAP_CHILD") else { return };
    if case == "overlong" {
        let component = "d".repeat(100);
        let levels = libc::PATH_MAX as usize / 101 + 2;
        for _ in 0..levels {
            std::fs::create_dir(&component).unwrap();
            std::env::set_current_dir(&component).unwrap();
        }
        let result = ProjectedReadSession::open(Path::new("missing"), &Cancellation::default());
        for _ in 0..levels {
            std::env::set_current_dir("..").unwrap();
            std::fs::remove_dir(&component).unwrap();
        }
        let e = result.err().unwrap();
        assert!(!e.is_source_changed());
        assert_eq!(e.bootstrap_usage().unwrap().opens(), 0);
        assert_eq!(e.bootstrap_usage().unwrap().metadata(), 0);
        #[cfg(target_os = "macos")]
        assert_eq!(e.bootstrap_usage().unwrap().cwd_retirement(), Some(zipfast::zip::CloseDisposition::Closed));
        return;
    }
    if case == "removed" {
        let cwd = std::env::current_dir().unwrap();
        std::fs::remove_dir(cwd).unwrap();
        let e = ProjectedReadSession::open(Path::new("missing"), &Cancellation::default()).err().unwrap();
        assert!(e.bootstrap_usage().unwrap().opens() <= 1);
        assert_eq!(e.bootstrap_usage().unwrap().acquired_fds(), 0);
        return;
    }
    let mut s = ProjectedReadSession::open(Path::new("archive.zip"), &Cancellation::default()).unwrap();
    assert_eq!(s.entries().next().unwrap().name, "entry");
    assert_eq!(s.bootstrap_usage().opens(), 1);
    #[cfg(target_os = "macos")]
    assert_eq!(s.bootstrap_usage().cwd_retirement(), Some(zipfast::zip::CloseDisposition::Closed));
    #[cfg(target_os = "linux")]
    assert_eq!(s.bootstrap_usage().cwd_retirement(), None);
    assert!(s.bootstrap_usage().path_operations() >= 1);
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    s.read_at_with_context(0, None, 64, &Cancellation::default(), &mut c, |_| Ok(())).unwrap();
    let cancel = Cancellation::default();
    cancel.cancel();
    let e = ProjectedReadSession::open(Path::new("archive.zip"), &cancel).err().unwrap();
    assert!(matches!(e.operation(), Some(ReadFault::Cancelled)));
    assert_eq!(e.bootstrap_usage().unwrap().attempts(), 0);
}
#[cfg(unix)]
#[test]
fn raw_native_relative_unicode_removed_cwd_nul_and_long_paths() {
    use std::os::unix::ffi::OsStringExt;
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes;
    for name in [std::ffi::OsString::from("unicode-雪"), std::ffi::OsString::from_vec(b"raw-\xff".to_vec())] {
        let cwd = dir.path().join(name);
        if let Err(error) = std::fs::create_dir(&cwd) {
            assert!(cfg!(target_os = "macos") && error.raw_os_error() == Some(libc::EILSEQ));
            continue;
        }
        std::fs::write(cwd.join("archive.zip"), &bytes).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("raw_bootstrap_child")
            .arg("--nocapture")
            .current_dir(&cwd)
            .env("ZIPFAST_TASK4_BOOTSTRAP_CHILD", "normal")
            .status()
            .unwrap();
        assert!(status.success());
    }
    let deep = dir.path().join("overlong-cwd");
    std::fs::create_dir(&deep).unwrap();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("raw_bootstrap_child")
            .current_dir(&deep)
            .env("ZIPFAST_TASK4_BOOTSTRAP_CHILD", "overlong")
            .status()
            .unwrap()
            .success()
    );
    let cwd = dir.path().join("removed");
    std::fs::create_dir(&cwd).unwrap();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("raw_bootstrap_child")
            .current_dir(&cwd)
            .env("ZIPFAST_TASK4_BOOTSTRAP_CHILD", "removed")
            .status()
            .unwrap()
            .success()
    );
    for path in [std::path::PathBuf::from("x".repeat(5000)), std::ffi::OsString::from_vec(b"nul\0path".to_vec()).into()]
    {
        let e = ProjectedReadSession::open(&path, &Cancellation::default()).err().unwrap();
        assert_eq!(e.bootstrap_usage().unwrap().opens(), 0);
    }
}

#[test]
fn r1_public_selection_refusals_keep_completed_parser_usage() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::{CloseDisposition, ReadFault, ReadResource};
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    let decoded = [0u8; 256];
    encoder.write_all(&decoded).unwrap();
    let compressed = encoder.finish().unwrap();
    for case in 0..4 {
        let member = match case {
            1 => fixture::Member::stored(b"directory/", b""),
            3 => fixture::Member::deflated(b"entry", &compressed, &decoded),
            _ => fixture::Member::stored(b"entry", b"payload"),
        };
        let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes).unwrap();
        let expected = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap().parser_usage();
        let error = SelectedEntry::open_cancelable_with_zip_limit(
            file.path(),
            if case == 0 { 9 } else { 0 },
            None,
            match case {
                2 => 2,
                3 => 10,
                _ => 1024,
            },
            None,
            Cancellation::default(),
        )
        .err()
        .unwrap();
        match case {
            0 | 1 => assert!(matches!(error.operation(), Some(ReadFault::CheckedFormat { .. }))),
            2 => assert!(matches!(
                error.operation(),
                Some(ReadFault::Limit { resource: ReadResource::MemberPackedBytes, .. })
            )),
            3 => assert!(matches!(
                error.operation(),
                Some(ReadFault::Limit { resource: ReadResource::MemberDecodedBytes, .. })
            )),
            _ => unreachable!(),
        }
        assert_eq!(error.parser_usage(), Some(expected));
        assert!(expected.fetched_bytes > 0);
        let boot = error.bootstrap_usage().unwrap();
        assert_eq!(boot.metadata(), 6);
        assert_eq!(boot.source_retirement(), Some(CloseDisposition::Closed));
        assert_eq!(boot.acquired_fds(), 1);
        assert_eq!(error.cleanup_errors().len(), 0);
    }
}
#[test]
fn r1_public_unbound_missing_source_keeps_action_plan_origin() {
    use zipfast::zip::{BootstrapPhase, CheckedSourceFault, ReadIoOperation};
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&fixture::build(&[fixture::Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    std::fs::remove_file(file.path()).unwrap();
    let mut calls = 0;
    let error = session
        .read_at_with_context(0, None, 64, &cancel, &mut context, |_| {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(calls, 0);
    assert!(matches!(error.source_change(), Some(CheckedSourceFault::Unavailable { .. })));
    let boot = error.bootstrap_usage().expect("originating explicit binding snapshot");
    assert_eq!(boot, context.bootstrap_usage());
    assert_eq!(boot.phase(), BootstrapPhase::ActionPlan);
    assert_eq!((boot.metadata(), boot.attempts(), boot.bytes(), boot.acquisition_attempts()), (2, 2, 0, 1));
    assert_eq!(context.run_usage().records, 0);
    assert_eq!(context.run_usage().io_attempts, 0);
    assert!(error.parser_usage().is_none());
    assert!(error.cleanup_errors().all(|e| e.operation != ReadIoOperation::Close));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn r2_rar_precedence_survives_sfx_corrupt_initializer_and_zip_tail() {
    use zipfast::extract::{self, Mode, Options, Overwrite};
    use zipfast::zip::{ReadFault, ZipRunEvent};
    let dir = tempfile::tempdir().unwrap();
    let rar = common::archive(&[common::FileSpec::new("rar-entry", b"payload")]);
    for prefix in [b"".as_slice(), b"launcher".as_slice()] {
        for corrupt in [false, true] {
            let mut first = prefix.to_vec();
            first.extend_from_slice(&rar);
            if corrupt {
                first[prefix.len() + common::SIG.len()] ^= 1;
            }
            let combined =
                fixture::build(&[fixture::Member::stored(b"zip-tail", b"one")], &[0], &first, b"", false).bytes;
            let path = dir.path().join(format!("case-{}-{corrupt}.bin", prefix.len()));
            std::fs::write(&path, &combined).unwrap();
            let options = Options {
                mode: Mode::Test,
                dest: dir.path().join("unused"),
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
                refused_link_placeholder: false,
                restart_from_first_volume: false,
                replace_placed_links: false,
                keep_broken: false,
                attempt_continued_members: false,
            };
            let result = extract::run_with_zip_policy(
                &path,
                &options,
                None,
                &Cancellation::default(),
                &Default::default(),
                |_: ZipRunEvent<'_>| Ok(()),
            );
            let mut context = EncryptedReadContext::new(Default::default()).unwrap();
            let contextual = extract::run_with_zip_context(
                &path,
                &options,
                None,
                &Cancellation::default(),
                &mut context,
                |_: ZipRunEvent<'_>| Ok(()),
            );
            for result in [result, contextual] {
                if corrupt {
                    assert!(matches!(
                        result.unwrap_err().operation(),
                        Some(ReadFault::Legacy(zipfast::Error::Corrupt(_)))
                    ));
                } else {
                    let report = result.unwrap();
                    assert_eq!((report.files(), report.decoded_bytes(), report.failed()), (1, 7, 0));
                }
            }
            for command in ["t", "l", "v"] {
                let result =
                    std::process::Command::new(env!("CARGO_BIN_EXE_zipfast")).arg(command).arg(&path).output().unwrap();
                assert_eq!(result.status.code(), Some(if corrupt { 2 } else { 0 }), "{command}: {result:?}");
                assert!(!String::from_utf8_lossy(&result.stdout).contains("zip-tail"));
                if !corrupt && command != "t" {
                    assert!(String::from_utf8_lossy(&result.stdout).contains("rar-entry"));
                }
            }
            assert_eq!(std::fs::read(&path).unwrap(), combined);
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod projected_inspection {
    use super::{common, fixture};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsFd;
    use std::path::Path;
    use zipfast::extract::{self, Cancellation, ProjectedInspection};
    use zipfast::zip::{EncryptedReadContext, ProjectedReadScope, ReadFault, ZipReadOutput, ZipReadStage};

    fn zip_bytes(prefix: &[u8]) -> Vec<u8> {
        fixture::build(&[fixture::Member::stored(b"original", b"payload")], &[0], prefix, b"", false).bytes
    }
    #[allow(clippy::result_large_err)] // Preserve the public inline checked evidence in this test helper.
    fn inspect(path: &Path, password: Option<&str>) -> zipfast::zip::ZipReadResult<ProjectedInspection> {
        extract::inspect_projected_cancelable(path, password, &Cancellation::default())
    }
    fn other(path: &Path, password: Option<&str>) -> Vec<extract::Entry> {
        match inspect(path, password).unwrap() {
            ProjectedInspection::Other(entries) => entries,
            _ => panic!("incumbent non-ZIP listing required"),
        }
    }

    #[test]
    #[allow(clippy::result_large_err)] // The final source-check closure returns fixed inline checked evidence.
    fn original_projected_zip_supports_verified_stdout_after_generic_dispatch() {
        for prefix in [b"".as_slice(), b"launcher".as_slice()] {
            let file = tempfile::NamedTempFile::new().unwrap();
            let bytes = zip_bytes(prefix);
            std::fs::write(file.path(), &bytes).unwrap();
            let ProjectedInspection::Zip(mut session) = inspect(file.path(), None).unwrap() else {
                panic!("original projected ZIP required")
            };
            assert_eq!(session.entries().len(), 1);
            let id = session.entry_id(0).unwrap();
            assert_eq!(session.entry(&id).unwrap().name, "original");
            assert_eq!(session.dispatch_bytes(), bytes.len() as u64 * if prefix.is_empty() { 1 } else { 2 });
            assert_eq!(session.bootstrap_usage().opens(), 1);
            assert_eq!(
                session.bootstrap_usage().bytes(),
                session.dispatch_bytes() + session.parser_usage().fetched_bytes
            );
            assert!(session.bootstrap_usage().bytes() <= 129 << 20);
            let cancel = Cancellation::default();
            let mut context = EncryptedReadContext::for_projected(
                &mut session,
                ProjectedReadScope::Entry(0),
                Some(7),
                ZipReadOutput::VerifiedStdout,
                None,
                &Default::default(),
                &cancel,
            )
            .unwrap();
            assert!(ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context).is_err());
            let mut out = tempfile::tempfile().unwrap();
            session.admit_output_fd(out.as_fd(), &mut context).unwrap();
            let mut stage =
                ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context).unwrap();
            session.read_at_with_context(0, None, 7, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
            assert_eq!(stage.copy_verified(&mut out, &cancel, &mut context, |c| session.check_source(c)).unwrap(), 7);
            out.seek(SeekFrom::Start(0)).unwrap();
            let mut actual = Vec::new();
            out.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, b"payload");
        }
    }

    fn tar_bytes() -> Vec<u8> {
        let mut bytes = vec![0; 2048];
        bytes[..9].copy_from_slice(b"tar-entry");
        bytes[100..108].copy_from_slice(b"0000644\0");
        bytes[124..136].copy_from_slice(b"00000000003\0");
        bytes[148..156].fill(b' ');
        bytes[156] = b'0';
        bytes[257..263].copy_from_slice(b"ustar\0");
        bytes[512..515].copy_from_slice(b"tar");
        let sum: u64 = bytes[..512].iter().map(|&b| u64::from(b)).sum();
        bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        bytes
    }
    #[test]
    fn tar_and_compressed_tar_keep_head_priority_and_legacy_terminal_errors() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let tar = tar_bytes();
        for bytes in [tar.clone(), zip_bytes(&tar)] {
            std::fs::write(file.path(), bytes).unwrap();
            assert_eq!(other(file.path(), None)[0].name, "tar-entry");
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar).unwrap();
        let gzip = encoder.finish().unwrap();
        std::fs::write(file.path(), &gzip).unwrap();
        assert_eq!(other(file.path(), None)[0].name, "tar-entry");
        std::fs::write(file.path(), zip_bytes(&gzip)).unwrap();
        assert!(matches!(inspect(file.path(), None).err().unwrap().operation(), Some(ReadFault::Legacy(_))));
    }

    // Same published-layout first-party RAR4 fixture used by rar4_stored.rs.
    fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 0, kind];
        bytes.extend(flags.to_le_bytes());
        bytes.extend(((body.len() + 7) as u16).to_le_bytes());
        bytes.extend(body);
        let crc = zipfast::crc32::hash(&bytes[2..]) as u16;
        bytes[..2].copy_from_slice(&crc.to_le_bytes());
        bytes
    }
    fn rar4() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(3u32.to_le_bytes());
        body.extend(3u32.to_le_bytes());
        body.push(3);
        body.extend(zipfast::crc32::hash(b"rar").to_le_bytes());
        body.extend(0x50221884u32.to_le_bytes());
        body.extend([20, 0x30]);
        body.extend(9u16.to_le_bytes());
        body.extend(0o100644u32.to_le_bytes());
        body.extend(b"rar-entry");
        let mut bytes = b"Rar!\x1a\x07\0".to_vec();
        bytes.extend(rar4_block(0x73, 0, &[0; 6]));
        bytes.extend(rar4_block(0x74, 0x8000, &body));
        bytes.extend(b"rar");
        bytes.extend(rar4_block(0x7b, 0x4000, &[]));
        bytes
    }
    #[test]
    fn genuine_rar4_and_rar5_sfx_win_over_zip_tail_and_keep_header_failures_terminal() {
        let file = tempfile::NamedTempFile::new().unwrap();
        for rar in [rar4(), common::archive(&[common::FileSpec::new("rar-entry", b"rar")])] {
            for launcher in [b"".as_slice(), b"launcher".as_slice()] {
                let mut prefix = launcher.to_vec();
                prefix.extend(&rar);
                std::fs::write(file.path(), zip_bytes(&prefix)).unwrap();
                assert_eq!(other(file.path(), None)[0].name, "rar-entry");
                // Corrupt the initializer CRC after genuine recognition.
                prefix[launcher.len() + if rar[6] == 0 { 7 } else { 8 }] ^= 1;
                std::fs::write(file.path(), zip_bytes(&prefix)).unwrap();
                let error = inspect(file.path(), None).err().unwrap();
                if rar[6] == 0 {
                    assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::BadChecksum(_)))));
                } else {
                    assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::Corrupt(_)))));
                }
            }
        }
        let mut rar = common::archive(&[common::FileSpec::new("rar-entry", b"rar")]);
        rar[common::SIG.len() + common::main_block(false, None).len()] ^= 1;
        std::fs::write(file.path(), zip_bytes(&rar)).unwrap();
        assert!(matches!(
            inspect(file.path(), None).err().unwrap().operation(),
            Some(ReadFault::Legacy(zipfast::Error::Corrupt(_)))
        ));
    }
    #[test]
    fn recognized_rar_later_volume_not_an_archive_is_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("multi.part1.rar");
        let mut prefix = b"launcher".to_vec();
        prefix.extend(common::SIG);
        prefix.extend(common::main_block(true, None));
        prefix.extend(common::end_block(true));
        std::fs::write(&first, zip_bytes(&prefix)).unwrap();
        assert!(matches!(
            inspect(&first, None).err().unwrap().operation(),
            Some(ReadFault::Legacy(zipfast::Error::MissingVolume(_)))
        ));
        std::fs::write(dir.path().join("multi.part2.rar"), b"not a rar").unwrap();
        assert!(matches!(
            inspect(&first, None).err().unwrap().operation(),
            Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))
        ));
    }
    #[test]
    fn sfx_rar_password_errors_are_terminal_and_correct_password_lists() {
        use zipfast::crypto::{derive_rar5_key, encrypt_cbc};
        const PASSWORD: &str = "inspection test";
        let salt = [7; 16];
        let key = derive_rar5_key(PASSWORD, 3, &salt, None).unwrap();
        let mut fields = vec![0, 0, 3];
        fields.extend(salt);
        let mut prefix = b"launcher".to_vec();
        prefix.extend(common::SIG);
        prefix.extend(common::block(4, 0, &fields, &[], &[], false));
        for (i, mut header) in [common::main_block(false, None), common::end_block(false)].into_iter().enumerate() {
            let iv = [i as u8; 16];
            header.resize(header.len().next_multiple_of(16), 0);
            prefix.extend(iv);
            prefix.extend(encrypt_cbc(&key, &iv, &header).unwrap());
        }
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), zip_bytes(&prefix)).unwrap();
        for password in [None, Some("wrong")] {
            assert!(matches!(
                inspect(file.path(), password).err().unwrap().operation(),
                Some(ReadFault::Legacy(zipfast::Error::Encrypted))
            ));
        }
        assert!(other(file.path(), Some(PASSWORD)).is_empty());
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod direct_completion {
    use super::fixture;
    use std::io::{Read, Seek, SeekFrom};
    use zipfast::extract::{Cancellation, Mode, Options, Overwrite, SelectedEntry};
    use zipfast::zip::{
        EncryptedReadContext, ProjectedReadScope, ProjectedReadSession, ReadFault, ReadSession, ZipDiagnosticSink,
        ZipReadOutput,
    };
    fn options(dest: std::path::PathBuf) -> Options {
        Options {
            mode: Mode::Test,
            dest,
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
            refused_link_placeholder: false,
            restart_from_first_volume: false,
            replace_placed_links: false,
            keep_broken: false,
            attempt_continued_members: false,
        }
    }
    #[test]
    #[allow(clippy::result_large_err)] // Actual operations and renderer preserve fixed inline checked faults.
    fn all_original_owners_log_actual_success_skip_and_failure_to_safe_regular_file() {
        for owner in 0..3 {
            for outcome in 0..3 {
                let mut member = fixture::Member::stored(b"entry", b"payload");
                if outcome == 2 {
                    member.crc = Some(0);
                }
                let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
                let source = tempfile::NamedTempFile::new().unwrap();
                std::fs::write(source.path(), &bytes).unwrap();
                let mut log = tempfile::tempfile().unwrap();
                let cancel = Cancellation::default();
                let opts = options(source.path().parent().unwrap().join("out"));
                macro_rules! run_completion {
                    ($session:ident, $context:ident, $prepared:expr, $read:expr, $emit:ident) => {{
                        let token = $prepared;
                        let result = if outcome == 1 { Ok(false) } else { $read.map(|()| true) };
                        let completion =
                            $session.$emit(token, &mut $context, result, &mut log, |operation, _, writer| {
                                writer.write_fmt(format_args!(
                                    "{}\n",
                                    match operation {
                                        Ok(true) => "success",
                                        Ok(false) => "skip",
                                        Err(_) => "failure",
                                    }
                                ))
                            });
                        let (value, error, usage) = completion.into_parts();
                        if outcome == 2 {
                            assert!(value.is_none());
                            assert!(matches!(error.unwrap().operation(), Some(ReadFault::Integrity { .. })));
                        } else {
                            assert_eq!(value, Some(outcome == 0));
                            assert!(error.is_none());
                        }
                        assert!(usage.accepted_bytes > 0);
                    }};
                }
                match owner {
                    0 => {
                        let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
                        let mut context = EncryptedReadContext::for_projected(
                            &mut session,
                            ProjectedReadScope::Entry(0),
                            Some(64),
                            ZipReadOutput::Callback,
                            None,
                            &Default::default(),
                            &cancel,
                        )
                        .unwrap();
                        run_completion!(
                            session,
                            context,
                            session
                                .prepare_diagnostics(0, &opts, &cancel, &mut context, ZipDiagnosticSink::Stderr, &log)
                                .unwrap(),
                            session.read_at_with_context(0, None, 64, &cancel, &mut context, |_| Ok(())),
                            emit_diagnostic
                        );
                    }
                    1 => {
                        let mut session = ReadSession::open(source.path()).unwrap();
                        let id = session.metadata().entry_id(0).unwrap();
                        let mut context = EncryptedReadContext::for_session(
                            &mut session,
                            &id,
                            Some(64),
                            ZipReadOutput::Callback,
                            None,
                            &Default::default(),
                            &cancel,
                        )
                        .unwrap();
                        run_completion!(
                            session,
                            context,
                            session
                                .prepare_diagnostics(&id, &opts, &cancel, &mut context, ZipDiagnosticSink::Stderr, &log)
                                .unwrap(),
                            session.select(&id, 64, cancel.clone()).unwrap().read_with_context(
                                None,
                                &mut context,
                                |_| Ok(())
                            ),
                            emit_diagnostic
                        );
                    }
                    _ => {
                        let mut session = SelectedEntry::open_cancelable_with_zip_limit(
                            source.path(),
                            0,
                            None,
                            64,
                            None,
                            cancel.clone(),
                        )
                        .unwrap();
                        let mut context = session
                            .zip_read_context(None, ZipReadOutput::Callback, &Default::default())
                            .unwrap()
                            .unwrap();
                        run_completion!(
                            session,
                            context,
                            session
                                .prepare_zip_diagnostics(&opts, &mut context, ZipDiagnosticSink::Stderr, &log)
                                .unwrap()
                                .unwrap(),
                            session.read_with_zip_context(None, &mut context, |_| Ok(())),
                            emit_zip_diagnostic
                        );
                    }
                }
                log.seek(SeekFrom::Start(0)).unwrap();
                let mut actual = String::new();
                log.read_to_string(&mut actual).unwrap();
                assert_eq!(actual, ["success\n", "skip\n", "failure\n"][outcome]);
                assert_eq!(std::fs::read(source.path()).unwrap(), bytes);
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod direct_aliases {
    use super::fixture;
    use zipfast::extract::{Cancellation, Mode, Options, Overwrite, SelectedEntry};
    use zipfast::zip::{
        EncryptedReadContext, ProjectedReadScope, ProjectedReadSession, ReadSession, ZipDiagnosticSink, ZipReadOutput,
    };
    #[test]
    fn all_three_owners_refuse_source_hardlink_destination_and_protected_aliases_before_payload() {
        for owner in 0..3 {
            for alias in 0..4 {
                let root = tempfile::tempdir().unwrap();
                let source = root.path().join("source.zip");
                let bytes =
                    fixture::build(&[fixture::Member::stored(b"entry", b"payload")], &[0], b"", b"", false).bytes;
                std::fs::write(&source, &bytes).unwrap();
                let dest = root.path().join("dest");
                std::fs::create_dir(&dest).unwrap();
                let mut opts = Options {
                    mode: if alias == 2 { Mode::Extract } else { Mode::Test },
                    dest: dest.clone(),
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
                };
                let log_path = match alias {
                    0 => source.clone(),
                    1 => {
                        let path = root.path().join("hardlink");
                        std::fs::hard_link(&source, &path).unwrap();
                        path
                    }
                    2 => {
                        let path = dest.join("entry");
                        std::fs::write(&path, b"prior").unwrap();
                        path
                    }
                    _ => {
                        let path = root.path().join("protected");
                        std::fs::write(&path, b"protected").unwrap();
                        opts.protected_paths.insert(path.clone());
                        path
                    }
                };
                let log = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
                let cancel = Cancellation::default();
                let output = || {
                    if alias == 2 {
                        ZipReadOutput::StagedFiles { destination: &opts.dest }
                    } else {
                        ZipReadOutput::Callback
                    }
                };
                let error = match owner {
                    0 => {
                        let mut session = ProjectedReadSession::open(&source, &cancel).unwrap();
                        let mut context = EncryptedReadContext::for_projected(
                            &mut session,
                            ProjectedReadScope::Entry(0),
                            Some(64),
                            output(),
                            None,
                            &Default::default(),
                            &cancel,
                        )
                        .unwrap();
                        session
                            .prepare_diagnostics(0, &opts, &cancel, &mut context, ZipDiagnosticSink::Stderr, &log)
                            .err()
                            .unwrap()
                    }
                    1 => {
                        let mut session = ReadSession::open(&source).unwrap();
                        let id = session.metadata().entry_id(0).unwrap();
                        let mut context = EncryptedReadContext::for_session(
                            &mut session,
                            &id,
                            Some(64),
                            output(),
                            None,
                            &Default::default(),
                            &cancel,
                        )
                        .unwrap();
                        session
                            .prepare_diagnostics(&id, &opts, &cancel, &mut context, ZipDiagnosticSink::Stderr, &log)
                            .err()
                            .unwrap()
                    }
                    _ => {
                        let mut session =
                            SelectedEntry::open_cancelable_with_zip_limit(&source, 0, None, 64, None, cancel).unwrap();
                        let mut context =
                            session.zip_read_context(None, output(), &Default::default()).unwrap().unwrap();
                        session
                            .prepare_zip_diagnostics(&opts, &mut context, ZipDiagnosticSink::Stderr, &log)
                            .err()
                            .unwrap()
                    }
                };
                assert!(error.diagnostic_boundary_fault().is_some(), "owner={owner} alias={alias}: {error:?}");
                assert_eq!(std::fs::read(&source).unwrap(), bytes);
                if alias == 2 {
                    assert_eq!(std::fs::read(dest.join("entry")).unwrap(), b"prior");
                }
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn native_print_refuses_diagnostics_that_alias_actual_stdout() {
    use std::os::fd::AsFd;
    use zipfast::extract::{Mode, Options, Overwrite, SelectedEntry};
    use zipfast::zip::{ReadSession, ZipDiagnosticSink};
    for owner in 0..3 {
        let source = tempfile::NamedTempFile::new().unwrap();
        let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"payload")], &[0], b"", b"", false).bytes;
        std::fs::write(source.path(), &bytes).unwrap();
        let mut out = tempfile::tempfile().unwrap();
        let cancel = Cancellation::default();
        let options = Options {
            mode: Mode::Test,
            dest: source.path().parent().unwrap().join("out"),
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
            refused_link_placeholder: false,
            restart_from_first_volume: false,
            replace_placed_links: false,
            keep_broken: false,
            attempt_continued_members: false,
        };
        macro_rules! refuse_completion {
            ($session:ident,$context:ident,$token:expr,$admit:expr,$emit:ident) => {{
                let token = $token;
                let operation = $admit;
                assert!(operation.is_err(), "owner={owner} must refuse before staging");
                $session.$emit(token, &mut $context, operation, &mut out, |_, _, _| {
                    panic!("latched alias refusal must not render into payload output")
                })
            }};
        }
        let completion = match owner {
            0 => {
                let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
                let mut context = EncryptedReadContext::for_projected(
                    &mut session,
                    ProjectedReadScope::Entry(0),
                    Some(64),
                    ZipReadOutput::VerifiedStdout,
                    None,
                    &Default::default(),
                    &cancel,
                )
                .unwrap();
                refuse_completion!(
                    session,
                    context,
                    session
                        .prepare_diagnostics(0, &options, &cancel, &mut context, ZipDiagnosticSink::Stderr, &out)
                        .unwrap(),
                    session.admit_output_fd(out.as_fd(), &mut context).map(|()| true),
                    emit_diagnostic
                )
            }
            1 => {
                let mut session = ReadSession::open(source.path()).unwrap();
                let id = session.metadata().entry_id(0).unwrap();
                let mut context = EncryptedReadContext::for_session(
                    &mut session,
                    &id,
                    Some(64),
                    ZipReadOutput::VerifiedStdout,
                    None,
                    &Default::default(),
                    &cancel,
                )
                .unwrap();
                refuse_completion!(
                    session,
                    context,
                    session
                        .prepare_diagnostics(&id, &options, &cancel, &mut context, ZipDiagnosticSink::Stderr, &out)
                        .unwrap(),
                    session.admit_output_fd(out.as_fd(), &mut context).map(|()| true),
                    emit_diagnostic
                )
            }
            _ => {
                let mut session =
                    SelectedEntry::open_cancelable_with_zip_limit(source.path(), 0, None, 64, None, cancel).unwrap();
                let mut context = session
                    .zip_read_context(None, ZipReadOutput::VerifiedStdout, &Default::default())
                    .unwrap()
                    .unwrap();
                refuse_completion!(
                    session,
                    context,
                    session
                        .prepare_zip_diagnostics(&options, &mut context, ZipDiagnosticSink::Stderr, &out)
                        .unwrap()
                        .unwrap(),
                    session.admit_zip_output_fd(out.as_fd(), &mut context),
                    emit_zip_diagnostic
                )
            }
        };
        let (value, error, usage) = completion.into_parts();
        assert!(value.is_none());
        assert!(error.is_some());
        assert_eq!(usage.accepted_bytes, 0);
        assert_eq!(out.metadata().unwrap().len(), 0);
        assert_eq!(std::fs::read(source.path()).unwrap(), bytes);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod protected_name_completion {
    use super::fixture;
    use std::io::Read;
    use zipfast::extract::{Cancellation, Mode, Options, Overwrite, SelectedEntry};
    use zipfast::zip::{
        EncryptedReadContext, ProjectedReadScope, ProjectedReadSession, ReadSession, ZipDiagnosticSink, ZipReadOutput,
        ZipReadStage,
    };

    #[test]
    #[allow(clippy::result_large_err)]
    fn current_protected_name_substitution_is_checked_for_all_owners_before_and_after_completion() {
        for owner in 0..3 {
            for extract in [false, true] {
                for symlink in [false, true] {
                    for post in [false, true] {
                        let root = tempfile::tempdir().unwrap();
                        let source = root.path().join("source.zip");
                        let bytes =
                            fixture::build(&[fixture::Member::stored(b"entry", b"payload")], &[0], b"", b"", false)
                                .bytes;
                        std::fs::write(&source, &bytes).unwrap();
                        let dest = root.path().join("out");
                        std::fs::create_dir(&dest).unwrap();
                        std::fs::write(dest.join("entry"), b"prior target").unwrap();
                        let protected = root.path().join("protected");
                        let log_path = root.path().join("log");
                        std::fs::write(&protected, b"protected").unwrap();
                        std::fs::write(&log_path, b"prior").unwrap();
                        let mut log = std::fs::OpenOptions::new().read(true).append(true).open(&log_path).unwrap();
                        let cancel = Cancellation::default();
                        let options = Options {
                            mode: if extract { Mode::Extract } else { Mode::Test },
                            dest: dest.clone(),
                            overwrite: Overwrite::Skip,
                            flatten: false,
                            threads: Some(1),
                            protected_paths: [protected.clone()].into_iter().collect(),
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
                        };
                        let output = || {
                            if extract {
                                ZipReadOutput::StagedFiles { destination: &options.dest }
                            } else {
                                ZipReadOutput::Callback
                            }
                        };
                        let replace = || {
                            std::fs::remove_file(&protected).unwrap();
                            if symlink {
                                std::os::unix::fs::symlink(&log_path, &protected).unwrap();
                            } else {
                                std::fs::hard_link(&log_path, &protected).unwrap();
                            }
                        };
                        let mut rendered = false;
                        macro_rules! emit {
                            ($session:ident,$context:ident,$token:expr,$operation:expr,$method:ident) => {{
                                let token = $token;
                                let operation = $operation;
                                assert_eq!(operation.as_ref().ok(), Some(&!extract));
                                if !post {
                                    replace();
                                }
                                $session.$method(token, &mut $context, operation, &mut log, |_, _, writer| {
                                    rendered = true;
                                    writer.write_fmt(format_args!("completion\n"))?;
                                    if post {
                                        replace();
                                    }
                                    Ok(())
                                })
                            }};
                        }
                        let completion = match owner {
                            0 => {
                                let mut session = ProjectedReadSession::open(&source, &cancel).unwrap();
                                let mut context = EncryptedReadContext::for_projected(
                                    &mut session,
                                    ProjectedReadScope::Entry(0),
                                    Some(64),
                                    output(),
                                    None,
                                    &Default::default(),
                                    &cancel,
                                )
                                .unwrap();
                                emit!(
                                    session,
                                    context,
                                    session
                                        .prepare_diagnostics(
                                            0,
                                            &options,
                                            &cancel,
                                            &mut context,
                                            ZipDiagnosticSink::Stderr,
                                            &log
                                        )
                                        .unwrap(),
                                    if extract {
                                        ZipReadStage::prepare_file(
                                            session.stage_entry(0).unwrap(),
                                            std::path::Path::new("entry"),
                                            &options,
                                            &cancel,
                                            &mut context,
                                        )
                                        .map(|stage| {
                                            assert!(stage.is_none());
                                            false
                                        })
                                    } else {
                                        session
                                            .read_at_with_context(0, None, 64, &cancel, &mut context, |_| Ok(()))
                                            .map(|()| true)
                                    },
                                    emit_diagnostic
                                )
                            }
                            1 => {
                                let mut session = ReadSession::open(&source).unwrap();
                                let id = session.metadata().entry_id(0).unwrap();
                                let mut context = EncryptedReadContext::for_session(
                                    &mut session,
                                    &id,
                                    Some(64),
                                    output(),
                                    None,
                                    &Default::default(),
                                    &cancel,
                                )
                                .unwrap();
                                emit!(
                                    session,
                                    context,
                                    session
                                        .prepare_diagnostics(
                                            &id,
                                            &options,
                                            &cancel,
                                            &mut context,
                                            ZipDiagnosticSink::Stderr,
                                            &log
                                        )
                                        .unwrap(),
                                    if extract {
                                        let mut selected = session.select(&id, 64, cancel.clone()).unwrap();
                                        ZipReadStage::prepare_file(
                                            selected.stage_entry().unwrap(),
                                            std::path::Path::new("entry"),
                                            &options,
                                            &cancel,
                                            &mut context,
                                        )
                                        .map(|stage| {
                                            assert!(stage.is_none());
                                            false
                                        })
                                    } else {
                                        session
                                            .select(&id, 64, cancel.clone())
                                            .unwrap()
                                            .read_with_context(None, &mut context, |_| Ok(()))
                                            .map(|()| true)
                                    },
                                    emit_diagnostic
                                )
                            }
                            _ => {
                                let mut session = SelectedEntry::open_cancelable_with_zip_limit(
                                    &source,
                                    0,
                                    None,
                                    64,
                                    None,
                                    cancel.clone(),
                                )
                                .unwrap();
                                let mut context =
                                    session.zip_read_context(None, output(), &Default::default()).unwrap().unwrap();
                                emit!(
                                    session,
                                    context,
                                    session
                                        .prepare_zip_diagnostics(
                                            &options,
                                            &mut context,
                                            ZipDiagnosticSink::Stderr,
                                            &log
                                        )
                                        .unwrap()
                                        .unwrap(),
                                    if extract {
                                        ZipReadStage::prepare_file(
                                            session.zip_stage_entry().unwrap().unwrap(),
                                            std::path::Path::new("entry"),
                                            &options,
                                            &cancel,
                                            &mut context,
                                        )
                                        .map(|stage| {
                                            assert!(stage.is_none());
                                            false
                                        })
                                    } else {
                                        session.read_with_zip_context(None, &mut context, |_| Ok(())).map(|()| true)
                                    },
                                    emit_zip_diagnostic
                                )
                            }
                        };
                        let (value, error, usage) = completion.into_parts();
                        assert_eq!(value, Some(!extract));
                        assert!(
                            error.is_some(),
                            "owner={owner} extract={extract} symlink={symlink} post={post} rendered={rendered} accepted={}",
                            usage.accepted_bytes
                        );
                        assert!(
                            error.unwrap().diagnostic_boundary_fault().is_some(),
                            "owner={owner} extract={extract} symlink={symlink} post={post}"
                        );
                        assert_eq!(rendered, post);
                        assert_eq!(usage.accepted_bytes, if post { 11 } else { 0 });
                        let expected = if post { b"priorcompletion\n".as_slice() } else { b"prior".as_slice() };
                        assert_eq!(std::fs::read(&log_path).unwrap(), expected);
                        assert_eq!(std::fs::read(&protected).unwrap(), expected);
                        assert_eq!(std::fs::read(dest.join("entry")).unwrap(), b"prior target");
                        assert_eq!(std::fs::read(&source).unwrap(), bytes);
                        let mut held = Vec::new();
                        use std::io::{Seek, SeekFrom};
                        log.seek(SeekFrom::Start(0)).unwrap();
                        log.read_to_end(&mut held).unwrap();
                        assert_eq!(held, expected);
                    }
                }
            }
        }
    }
}
