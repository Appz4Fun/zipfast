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

//! `extract::run_with_policy`, the one entry point for every format: cancellation, live member events and every
//! overwrite mode for ZIP, tar, lone compressed streams, RAR and 7z, and tar's own `tar::run_with_policy`.
#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::result_large_err)]
mod common;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite, RenameStyle, RunEvent};
use zipfast::zip::{ReadFault, ZipReadError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Zip,
    Tar,
    TarGz,
    Gzip,
    Rar,
    /// RAR 4.x: a solid, compressed WinRAR fixture
    Rar4,
    SevenZip,
    /// 7z with one solid PPMd folder
    SevenZipPpmd,
}

const FAMILIES: [Family; 8] = [
    Family::Zip,
    Family::Tar,
    Family::TarGz,
    Family::Gzip,
    Family::Rar,
    Family::Rar4,
    Family::SevenZip,
    Family::SevenZipPpmd,
];

/// Families whose members are fixtures, not the bytes asked for.
fn fixed(family: Family) -> bool {
    matches!(family, Family::Rar4 | Family::SevenZip | Family::SevenZipPpmd)
}

/// The listing index of `name` in the archive at `path`.
fn ordinal_of(path: &Path, name: &str) -> u64 {
    extract::list(path).unwrap().iter().position(|e| e.name == name).unwrap_or_else(|| panic!("{name}")) as u64
}

const SEVEN_ZIP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/7z-extract");

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in members {
        let crc = zipfast::crc32::hash(data);
        let offset = out.len() as u32;
        let common = |out: &mut Vec<u8>| {
            out.extend(20u16.to_le_bytes());
            out.extend(0x0800u16.to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(0x21u16.to_le_bytes());
            out.extend(crc.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
        };
        out.extend(0x04034b50u32.to_le_bytes());
        common(&mut out);
        out.extend(name.as_bytes());
        out.extend(*data);
        central.extend(0x02014b50u32.to_le_bytes());
        central.extend(0x0314u16.to_le_bytes());
        common(&mut central);
        central.extend([0; 6]);
        central.extend((0o100644u32 << 16).to_le_bytes());
        central.extend(offset.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let start = out.len() as u32;
    out.extend(&central);
    out.extend(0x06054b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(start.to_le_bytes());
    out.extend([0; 2]);
    out
}

fn tar_header(name: &str, size: usize, kind: u8) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"14000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = kind;
    header[257..265].copy_from_slice(b"ustar\x0000");
    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header
}

/// A tar of regular files; a name ending in `@` becomes a symlink member (refused by the extractor).
fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in members {
        match name.strip_suffix('@') {
            Some(link) => out.extend(tar_header(link, 0, b'2')),
            None => {
                out.extend(tar_header(name, data.len(), b'0'));
                out.extend(*data);
            }
        }
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn rar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let specs: Vec<_> = members.iter().map(|(name, data)| common::FileSpec::new(name, data)).collect();
    common::archive(&specs)
}

/// Writes an archive of `family` holding `a.txt` = `first` and `b.txt` = `second` (7z: the fixture's
/// `text/a.txt` and `text/b.txt`; a lone gzip stream holds only `first`, as `a.txt`). Returns its path and the
/// member paths.
fn archive(dir: &Path, family: Family, first: &[u8], second: &[u8]) -> (PathBuf, Vec<&'static str>) {
    let members: [(&str, &[u8]); 2] = [("a.txt", first), ("b.txt", second)];
    let (name, bytes, names) = match family {
        Family::Zip => ("in.zip", zip(&members), vec!["a.txt", "b.txt"]),
        Family::Tar => ("in.tar", tar(&members), vec!["a.txt", "b.txt"]),
        Family::TarGz => ("in.tar.gz", gzip(&tar(&members)), vec!["a.txt", "b.txt"]),
        Family::Gzip => ("a.txt.gz", gzip(first), vec!["a.txt"]),
        Family::Rar => ("in.rar", rar(&members), vec!["a.txt", "b.txt"]),
        Family::Rar4 => (
            "in.rar",
            fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4/latest_winrar.rar")).unwrap(),
            vec!["1.txt", "2.txt"],
        ),
        Family::SevenZip => {
            ("in.7z", fs::read(Path::new(SEVEN_ZIP).join("lzma2.7z")).unwrap(), vec!["text/a.txt", "text/b.txt"])
        }
        Family::SevenZipPpmd => {
            ("in.7z", fs::read(Path::new(SEVEN_ZIP).join("ppmd_solid.7z")).unwrap(), vec!["big/one.txt", "big/two.txt"])
        }
    };
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    (path, names)
}

fn options(dest: &Path, overwrite: Overwrite) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
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
    }
}

/// What a run delivered to its observer, in order.
#[derive(Debug, Default)]
struct Events {
    /// `(kind, ordinal, name)` of member events
    members: Vec<(&'static str, u64, String)>,
    renamed: Vec<Option<u64>>,
    lines: Vec<String>,
    ended: bool,
}

fn run(
    archive: &Path,
    opts: &Options,
    cancel: &Cancellation,
    mut on: impl FnMut(&RunEvent<'_>),
) -> (Result<extract::RunReport, ZipReadError>, Events) {
    let mut events = Events::default();
    let result = extract::run_with_policy(archive, opts, None, cancel, &Default::default(), |event: RunEvent<'_>| {
        on(&event);
        match event {
            RunEvent::MemberSucceeded { ordinal, name, .. } => events.members.push(("ok", ordinal, name.to_owned())),
            RunEvent::MemberSkipped { ordinal, name } => events.members.push(("skipped", ordinal, name.to_owned())),
            RunEvent::MemberFailed { ordinal, name, .. } => events.members.push(("failed", ordinal, name.to_owned())),
            RunEvent::MemberRenamed { ordinal, .. } => events.renamed.push(ordinal),
            RunEvent::LegacyDiagnostic { message } => events.lines.push(message.to_owned()),
            RunEvent::RunEnded { .. } => events.ended = true,
            _ => {}
        }
        Ok(())
    });
    (result, events)
}

fn cancelled(result: &Result<extract::RunReport, ZipReadError>) -> bool {
    matches!(result.as_ref().map_err(ZipReadError::operation), Err(Some(ReadFault::Cancelled)))
}

#[test]
fn a_canceled_token_stops_every_format_before_anything_is_written() {
    for family in FAMILIES {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = archive(dir.path(), family, b"one", b"two");
        let out = dir.path().join("out");
        let cancel = Cancellation::default();
        cancel.cancel();
        let (result, _) = run(&path, &options(&out, Overwrite::Skip), &cancel, |_| {});
        assert!(cancelled(&result), "{family:?}: {result:?}");
        assert!(!out.exists() || fs::read_dir(&out).unwrap().next().is_none(), "{family:?}");
    }
}

#[test]
fn cancellation_between_members_stops_every_format_with_a_typed_error() {
    for family in FAMILIES.into_iter().filter(|&f| f != Family::Gzip) {
        let dir = tempfile::tempdir().unwrap();
        let (path, names) = archive(dir.path(), family, b"one", b"two");
        let out = dir.path().join("out");
        // The first member already exists, so Skip passes it with an event (ZIP, tar) or a report line (RAR, 7z);
        // canceling there stops the run before the second.
        fs::create_dir_all(out.join(names[0]).parent().unwrap()).unwrap();
        fs::write(out.join(names[0]), b"old").unwrap();
        let cancel = Cancellation::default();
        let (result, _) = run(&path, &options(&out, Overwrite::Skip), &cancel.clone(), |event| {
            if matches!(event, RunEvent::MemberSkipped { .. } | RunEvent::LegacyDiagnostic { .. }) {
                cancel.cancel();
            }
        });
        assert!(cancelled(&result), "{family:?}: {result:?}");
        assert_eq!(fs::read(out.join(names[0])).unwrap(), b"old", "{family:?}");
        assert!(!out.join(names[1]).exists(), "{family:?}: the member after the cancellation was written");
    }
}

/// A file of `n` MiB that compresses to almost nothing: the same compressed piece over and over, which every multi-
/// stream decoder reads back to back.
fn big_stream(codec: &str, mib: usize) -> Vec<u8> {
    let piece = vec![0u8; 1 << 20];
    let one = match codec {
        "gz" => gzip(&piece),
        "xz" => {
            let mut e = liblzma::write::XzEncoder::new(Vec::new(), 1);
            e.write_all(&piece).unwrap();
            e.finish().unwrap()
        }
        "bz2" => {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
            e.write_all(&piece).unwrap();
            e.finish().unwrap()
        }
        "zst" => zstd::encode_all(&piece[..], 1).unwrap(),
        _ => unreachable!(),
    };
    one.repeat(mib)
}

/// Runs `path` and cancels from another thread as soon as anything appears in the destination, that is once the
/// (only) member's output has been created and its data is being decoded into it.
fn cancel_once_output_appears(path: &Path, out: &Path) -> Result<extract::RunReport, ZipReadError> {
    cancel_once_output_appears_with(path, &options(out, Overwrite::Skip))
}

fn cancel_once_output_appears_with(path: &Path, opts: &Options) -> Result<extract::RunReport, ZipReadError> {
    let out = &opts.dest;
    let cancel = Cancellation::default();
    let watcher = {
        let (cancel, out) = (cancel.clone(), out.to_path_buf());
        std::thread::spawn(move || {
            for _ in 0..20_000 {
                if fs::read_dir(&out).is_ok_and(|mut d| d.next().is_some()) {
                    cancel.cancel();
                    return true;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            false
        })
    };
    let (result, _) = run(path, opts, &cancel, |_| {});
    assert!(watcher.join().unwrap(), "the output never appeared");
    result
}

#[test]
fn every_stream_codec_is_canceled_mid_member() {
    for codec in ["gz", "xz", "bz2", "zst"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("big.bin.{codec}"));
        fs::write(&path, big_stream(codec, 512)).unwrap();
        let out = dir.path().join("out");
        let result = cancel_once_output_appears(&path, &out);
        assert!(cancelled(&result), "{codec}: {result:?}");
        assert!(!out.join("big.bin").exists(), "{codec}: a canceled member was published");
    }
}

#[test]
fn a_compressed_tar_is_canceled_mid_member() {
    // One 512 MiB member of zeros: gzip members back to back decode as one stream.
    let mib = 512;
    let mut bytes = gzip(&tar_header("big.bin", mib << 20, b'0'));
    bytes.extend(gzip(&vec![0u8; 1 << 20]).repeat(mib));
    bytes.extend(gzip(&[0u8; 1024]));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.tar.gz");
    fs::write(&path, bytes).unwrap();
    let out = dir.path().join("out");
    let result = cancel_once_output_appears(&path, &out);
    assert!(cancelled(&result), "{result:?}");
    assert!(!out.join("big.bin").exists(), "a canceled member was published");
}

#[test]
fn tar_reports_members_live_with_their_ordinals() {
    let dir = tempfile::tempdir().unwrap();
    for gz in [false, true] {
        let plain = tar(&[("a.txt", b"one"), ("link@", b""), ("b.txt", b"two"), ("c.txt", b"three")]);
        let path = dir.path().join(if gz { "in.tar.gz" } else { "in.tar" });
        fs::write(&path, if gz { gzip(&plain) } else { plain }).unwrap();
        let out = dir.path().join(format!("out{gz}"));
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("b.txt"), b"old").unwrap();
        let (result, events) = run(&path, &options(&out, Overwrite::Skip), &Cancellation::default(), |event| {
            // A member is on disk when its success arrives.
            if let RunEvent::MemberSucceeded { name, .. } = event {
                assert!(out.join(name).exists(), "{name} reported before it was written");
            }
        });
        let report = result.unwrap();
        assert_eq!((report.files(), report.skipped(), report.failed()), (2, 1, 1));
        let want = [("ok", 0, "a.txt"), ("failed", 1, "link"), ("skipped", 2, "b.txt"), ("ok", 3, "c.txt")];
        let got: Vec<_> = events.members.iter().map(|(k, o, n)| (*k, *o, n.as_str())).collect();
        if gz {
            // A compressed tar publishes once the stream checks out: failures come as they are found, the rest after.
            let mut sorted = got.clone();
            sorted.sort_by_key(|e| e.1);
            assert_eq!(sorted, want, "gz");
        } else {
            assert_eq!(got, want);
        }
        assert!(events.ended);
    }
    // A lone stream is member 0.
    let (path, _) = archive(dir.path(), Family::Gzip, b"one", b"");
    let (result, events) = run(&path, &options(&dir.path().join("lone"), Overwrite::Skip), &Default::default(), |_| {});
    result.unwrap();
    assert_eq!(events.members, [("ok", 0, "a.txt".to_owned())]);
}

#[test]
fn tar_has_its_own_policy_entry_point() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = archive(dir.path(), Family::Tar, b"one", b"two");
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("a.txt"), b"old").unwrap();
    let mut seen = Vec::new();
    let report = zipfast::tar::run_with_policy(
        &path,
        &options(&out, Overwrite::RenameNew(RenameStyle::Underscore)),
        &Cancellation::default(),
        |event: RunEvent<'_>| {
            match event {
                RunEvent::MemberRenamed { ordinal, .. } => seen.push(format!("renamed {ordinal:?}")),
                RunEvent::MemberSucceeded { ordinal, name, .. } => seen.push(format!("ok {ordinal} {name}")),
                _ => {}
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.files(), 2);
    assert_eq!(seen, ["renamed Some(0)", "ok 0 a.txt", "ok 1 b.txt"]);
    assert_eq!(fs::read(out.join("a_1.txt")).unwrap(), b"one");
    let canceled = Cancellation::default();
    canceled.cancel();
    let error =
        zipfast::tar::run_with_policy(&path, &options(&out, Overwrite::Skip), &canceled, |_: RunEvent<'_>| Ok(()))
            .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Cancelled)), "{error:?}");
    // Anything else is not tar's.
    let (zip_path, _) = archive(dir.path(), Family::Zip, b"one", b"two");
    let error = zipfast::tar::run_with_policy(
        &zip_path,
        &options(&out, Overwrite::Skip),
        &Default::default(),
        |_: RunEvent<'_>| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))), "{error:?}");
}

#[test]
fn every_overwrite_mode_in_every_format() {
    let modes = [
        Overwrite::Skip,
        Overwrite::Always,
        Overwrite::RenameNew(RenameStyle::Underscore),
        Overwrite::RenameExisting(RenameStyle::Parenthesized),
    ];
    for family in FAMILIES {
        for mode in modes {
            let dir = tempfile::tempdir().unwrap();
            let (path, names) = archive(dir.path(), family, b"one", b"two");
            let out = dir.path().join("out");
            let target = out.join(names[0]);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(&target, b"old").unwrap();
            // The fixtures' own text; the rest hold "one".
            let new = (!fixed(family)).then(|| b"one".to_vec());
            let (result, events) = run(&path, &options(&out, mode), &Cancellation::default(), |_| {});
            let report = result.unwrap_or_else(|e| panic!("{family:?} {mode:?}: {e:?}"));
            let what = format!("{family:?} {mode:?}");
            let stem = target.file_stem().unwrap().to_str().unwrap().to_owned();
            let renamed_new = target.with_file_name(format!("{stem}_1.txt"));
            let renamed_old = target.with_file_name(format!("{stem}(1).txt"));
            let content = |p: &Path| fs::read(p).unwrap();
            match mode {
                Overwrite::Skip => {
                    assert_eq!((report.skipped(), content(&target)), (1, b"old".to_vec()), "{what}");
                }
                Overwrite::Always => {
                    assert_eq!(report.skipped(), 0, "{what}");
                    assert_ne!(content(&target), b"old", "{what}");
                    if let Some(new) = &new {
                        assert_eq!(&content(&target), new, "{what}");
                    }
                }
                Overwrite::RenameNew(_) => {
                    assert_eq!(content(&target), b"old", "{what}");
                    assert_ne!(content(&renamed_new), b"old", "{what}");
                    assert_eq!(events.renamed.len(), 1, "{what}");
                }
                _ => {
                    assert_eq!(content(&renamed_old), b"old", "{what}");
                    assert_ne!(content(&target), b"old", "{what}");
                    assert_eq!(events.renamed.len(), 1, "{what}");
                }
            }
            assert_eq!(report.failed(), 0, "{what}");
            if !fixed(family) {
                assert_eq!(report.files() + report.skipped(), names.len() as u64, "{what}");
            }
            // Every format names the member a rename was for.
            let first = ordinal_of(&path, names[0]);
            assert!(events.renamed.iter().all(|o| *o == Some(first)), "{what}: {:?}", events.renamed);
            // and reports each member it took, live, with its listing index
            let want: Vec<u64> = names.iter().map(|n| ordinal_of(&path, n)).collect();
            let mut got: Vec<u64> =
                events.members.iter().filter(|(_, _, n)| names.contains(&n.as_str())).map(|(_, o, _)| *o).collect();
            got.sort_unstable();
            assert_eq!(got, want, "{what}: {:?}", events.members);
        }
    }
}

#[test]
fn rar_and_7z_report_members_live_with_their_ordinals() {
    for family in [Family::Rar, Family::Rar4, Family::SevenZip, Family::SevenZipPpmd] {
        let dir = tempfile::tempdir().unwrap();
        let (path, names) = archive(dir.path(), family, b"one", b"two");
        let out = dir.path().join("out");
        fs::create_dir_all(out.join(names[0]).parent().unwrap()).unwrap();
        fs::write(out.join(names[0]), b"old").unwrap();
        let (result, events) = run(&path, &options(&out, Overwrite::Skip), &Default::default(), |event| {
            // A member is on disk when its success arrives.
            if let RunEvent::MemberSucceeded { name, .. } = event {
                assert!(out.join(name).exists(), "{family:?}: {name} reported before it was written");
            }
        });
        let report = result.unwrap();
        assert_eq!(report.skipped(), 1, "{family:?}");
        assert!(events.lines.iter().any(|l| l.contains("exists, skipped")), "{family:?}: {:?}", events.lines);
        let listing = extract::list(&path).unwrap();
        // One event per member, in listing order, each with its listing index and name.
        let got: Vec<(u64, String)> = events.members.iter().map(|(_, o, n)| (*o, n.clone())).collect();
        let want: Vec<(u64, String)> = listing
            .iter()
            .enumerate()
            .filter(|(_, e)| got.iter().any(|(_, n)| *n == e.name))
            .map(|(i, e)| (i as u64, e.name.clone()))
            .collect();
        assert_eq!(got, want, "{family:?}");
        assert_eq!(got.len() as u64, report.files() + report.skipped() + report.dirs(), "{family:?}: {got:?}");
        let skipped = ordinal_of(&path, names[0]);
        assert!(events.members.contains(&("skipped", skipped, names[0].to_owned())), "{family:?}");
        assert!(events.members.contains(&("ok", ordinal_of(&path, names[1]), names[1].to_owned())), "{family:?}");
        assert!(events.ended);
    }
}

/// A 7z archive holding one member, `big.bin` = `len` copies of `byte`, stored with the Copy coder.
fn seven_zip_copy(len: u64, byte: u8) -> Vec<u8> {
    fn number(out: &mut Vec<u8>, value: u64) {
        let extra = (0..8).find(|&i| value < 1u64 << (7 * (i + 1))).unwrap_or(8);
        let first = if extra == 8 { 0xFF } else { ((0xFFu16 << (8 - extra)) as u8) | (value >> (8 * extra)) as u8 };
        out.push(first);
        out.extend_from_slice(&value.to_le_bytes()[..extra]);
    }
    let data = vec![byte; len as usize];
    let crc = crc32fast::hash(&data);
    let mut header = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09];
    number(&mut header, len);
    header.extend_from_slice(&[0x00, 0x07, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C]);
    number(&mut header, len);
    header.extend_from_slice(&[0x0A, 0x01]);
    header.extend_from_slice(&crc.to_le_bytes());
    header.extend_from_slice(&[0x00, 0x00, 0x05, 0x01, 0x11]);
    let name: Vec<u8> = "big.bin\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    number(&mut header, name.len() as u64 + 1);
    header.push(0x00);
    header.extend_from_slice(&name);
    header.extend_from_slice(&[0x00, 0x00]);
    let mut start = Vec::new();
    start.extend_from_slice(&len.to_le_bytes());
    start.extend_from_slice(&(header.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32fast::hash(&header).to_le_bytes());
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4];
    out.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(&data);
    out.extend_from_slice(&header);
    out
}

#[test]
fn a_7z_member_is_canceled_mid_member() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.7z");
    fs::write(&path, seven_zip_copy(5, b'x')).unwrap();
    // The hand-made archive is one a run reads.
    let small = dir.path().join("small");
    let (result, events) = run(&path, &options(&small, Overwrite::Skip), &Default::default(), |_| {});
    assert_eq!(result.unwrap().files(), 1);
    assert_eq!(events.members, [("ok", 0, "big.bin".to_owned())]);
    assert_eq!(fs::read(small.join("big.bin")).unwrap(), b"xxxxx");
    fs::write(&path, seven_zip_copy(512 << 20, 7)).unwrap();
    let out = dir.path().join("out");
    let result = cancel_once_output_appears(&path, &out);
    assert!(cancelled(&result), "{result:?}");
    assert!(!out.join("big.bin").exists(), "a canceled member was published");
}

#[test]
fn a_rar_member_is_canceled_mid_member() {
    let big = vec![5u8; 128 << 20];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.rar");
    fs::write(&path, rar(&[("big.bin", &big)])).unwrap();
    drop(big);
    // One thread decodes through the member's sink; several copy a big stored part in parallel.
    for threads in [Some(1), None] {
        let out = dir.path().join(format!("out{threads:?}"));
        let result = cancel_once_output_appears_with(&path, &Options { threads, ..options(&out, Overwrite::Skip) });
        assert!(cancelled(&result), "{threads:?}: {result:?}");
        assert!(!out.join("big.bin").exists(), "{threads:?}: a canceled member was published");
    }
}

#[test]
fn a_threaded_rar_run_publishes_nothing_once_canceled() {
    // Many small members go to the file workers in groups; canceling at the first success must stop them.
    let datas: Vec<(String, Vec<u8>)> =
        (0..3000).map(|i| (format!("f{i:04}.txt"), format!("member {i} ").repeat(50).into_bytes())).collect();
    let members: Vec<(&str, &[u8])> = datas.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("many.rar");
    fs::write(&path, rar(&members)).unwrap();
    let threads = 4;
    let out = dir.path().join("out");
    let cancel = Cancellation::default();
    let opts = Options { threads: Some(threads), ..options(&out, Overwrite::Skip) };
    // The workers run ahead of the reports, so some files are already out when the first success arrives.
    let mut at_cancel = None;
    let (result, events) = run(&path, &opts, &cancel.clone(), |event| {
        if matches!(event, RunEvent::MemberSucceeded { .. }) && at_cancel.is_none() {
            cancel.cancel();
            at_cancel = Some(fs::read_dir(&out).unwrap().count());
        }
    });
    let at_cancel = at_cancel.expect("a member succeeded");
    assert!(cancelled(&result), "{result:?}");
    let succeeded = events.members.iter().filter(|(k, _, _)| *k == "ok").count();
    assert_eq!(succeeded, 1, "members were reported after the cancellation: {:?}", events.members.len());
    // No member still queued is reported as failed.
    assert!(events.members.iter().all(|(k, _, _)| *k != "failed"), "{:?}", events.members);
    let on_disk = || fs::read_dir(&out).unwrap().count();
    let published = on_disk();
    // Past those, at most the file each worker was publishing as the token was set.
    assert!(published <= at_cancel + threads, "{at_cancel} files out at the cancellation, {published} after it");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(on_disk(), published, "files kept appearing after the run returned");
}

#[test]
fn the_start_hook_reaches_every_format() {
    for family in FAMILIES {
        let dir = tempfile::tempdir().unwrap();
        let (path, names) = archive(dir.path(), family, b"one", b"two");
        let out = dir.path().join("out");
        let declined = out.join(names[0]);
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let filter = {
            let (asked, declined) = (asked.clone(), declined.clone());
            extract::MemberFilter::all().on_start(move |start| {
                asked.lock().unwrap().push(start.path.to_path_buf());
                if start.path == declined { extract::StartDecision::Skip } else { extract::StartDecision::Write }
            })
        };
        let opts = Options { select: Some(filter), ..options(&out, Overwrite::Skip) };
        let (result, events) = run(&path, &opts, &Cancellation::default(), |_| {});
        let report = result.unwrap_or_else(|e| panic!("{family:?}: {e:?}"));
        assert!(report.skipped() >= 1, "{family:?}");
        assert!(!declined.exists(), "{family:?}: a declined member was written");
        assert!(asked.lock().unwrap().contains(&declined), "{family:?}: the hook was not asked");
        let ordinal = ordinal_of(&path, names[0]);
        assert!(
            events.members.contains(&("skipped", ordinal, names[0].to_owned())),
            "{family:?}: {:?}",
            events.members
        );
        if names.len() > 1 {
            assert!(out.join(names[1]).exists(), "{family:?}");
        }
    }
}

/// Runs like a CLI that renders member events through the observer's checked diagnostic scope (as Prybar does), and
/// returns the report and the member events.
fn run_rendering(
    archive: &Path,
    opts: &Options,
) -> (Result<extract::RunReport, ZipReadError>, Vec<(&'static str, u64)>) {
    use zipfast::zip::{ZipDiagnosticScope, ZipDiagnosticSink, ZipObserverResult, ZipRunObserver};
    struct Render<'a> {
        sink: fs::File,
        members: &'a mut Vec<(&'static str, u64)>,
    }
    impl ZipRunObserver for Render<'_> {
        fn prepare(&mut self, scope: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            scope.admit_sinks(None, Some(&self.sink))?;
            Ok(())
        }
        fn observe(&mut self, event: RunEvent<'_>, scope: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            let (kind, ordinal, name) = match event {
                RunEvent::MemberSucceeded { ordinal, name, .. } => ("ok", ordinal, name),
                RunEvent::MemberSkipped { ordinal, name } => ("skipped", ordinal, name),
                RunEvent::MemberFailed { ordinal, name, .. } => ("failed", ordinal, name),
                _ => return Ok(()),
            };
            self.members.push((kind, ordinal));
            scope.emit(ZipDiagnosticSink::Stderr, &mut self.sink, |_, writer| {
                writer.write_fmt(format_args!("{kind} {name}\n"))
            })?;
            Ok(())
        }
    }
    let mut members = Vec::new();
    let render = Render { sink: tempfile::tempfile().unwrap(), members: &mut members };
    let result = extract::run_with_policy(archive, opts, None, &Cancellation::default(), &Default::default(), render);
    (result, members)
}

#[test]
fn a_second_run_over_the_same_folder_finishes_in_every_format_and_mode() {
    for family in FAMILIES {
        for mode in [Overwrite::Skip, Overwrite::RenameNew(RenameStyle::Underscore), Overwrite::Always] {
            let dir = tempfile::tempdir().unwrap();
            let (path, names) = archive(dir.path(), family, b"one", b"two");
            let out = dir.path().join("out");
            let what = format!("{family:?} {mode:?}");
            let (first, _) = run_rendering(&path, &options(&out, mode));
            let first = first.unwrap_or_else(|e| panic!("{what}, first run: {e:?}"));
            let (second, members) = run_rendering(&path, &options(&out, mode));
            let second = second.unwrap_or_else(|e| panic!("{what}, second run: {e:?}"));
            assert_eq!(second.failed(), 0, "{what}");
            if mode == Overwrite::Skip {
                // Everything is there already: every file is skipped, and each skip comes as an event.
                assert_eq!((second.files(), second.skipped()), (0, first.files()), "{what}");
                assert_eq!(members.iter().filter(|(k, _)| *k == "skipped").count() as u64, first.files(), "{what}");
            } else {
                assert_eq!((second.files(), second.skipped()), (first.files(), 0), "{what}");
            }
            for name in &names {
                assert!(out.join(name).exists(), "{what}: {name}");
            }
            // Testing over it reports and renders as well.
            let (tested, _) = run_rendering(&path, &Options { mode: Mode::Test, ..options(&out, mode) });
            tested.unwrap_or_else(|e| panic!("{what}, test run: {e:?}"));
        }
        // A member the start hook declines is rendered as a skip too.
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = archive(dir.path(), family, b"one", b"two");
        let filter = extract::MemberFilter::all().on_start(|_| extract::StartDecision::Skip);
        let opts = Options { select: Some(filter), ..options(&dir.path().join("out"), Overwrite::Skip) };
        let (result, members) = run_rendering(&path, &opts);
        let report = result.unwrap_or_else(|e| panic!("{family:?} declined: {e:?}"));
        assert_eq!(report.files(), 0, "{family:?}");
        // (folders still succeed: the hook is not asked about them)
        assert!(members.iter().all(|(k, _)| *k != "failed"), "{family:?}: {members:?}");
        assert!(members.iter().any(|(k, _)| *k == "skipped"), "{family:?}: {members:?}");
    }
}

#[test]
fn the_prybar_rar4_reference_extracts_twice_with_skip() {
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4/latest_winrar.rar"));
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    run_rendering(path, &options(&out, Overwrite::Skip)).0.unwrap();
    let report = run_rendering(path, &options(&out, Overwrite::Skip)).0.unwrap();
    assert_eq!((report.files(), report.skipped()), (0, 2));
}
