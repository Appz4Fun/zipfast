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

//! `RewritePlan::rename`: payloads stay byte-identical, headers are rebuilt.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, path::Path, process::Command};

use zipfast::zip::ReadSession;
use zipfast::zip::rewrite::{
    Placement, Replacement, RewriteError, RewriteOptions, RewriteOutcome, RewritePlan, Verification,
};
use zipfast::zip::write::{DosDateTime, EntryName, EntryOptions, Method, Permissions};

fn le16(b: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
}
fn le32(b: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(b[at..at + 4].try_into().unwrap()))
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[derive(Clone, Default)]
struct M {
    name: Vec<u8>,
    flags: u16,
    local_extra: Vec<u8>,
    central_extra: Vec<u8>,
    data: Vec<u8>,
    descriptor: bool,
    wide: bool,
    comment: Vec<u8>,
}

fn m(name: &str, data: &[u8]) -> M {
    M { name: name.as_bytes().to_vec(), data: data.to_vec(), ..M::default() }
}

fn unicode_path(name: &str, old_raw: &[u8]) -> Vec<u8> {
    let mut body = vec![1];
    body.extend(crc32fast::hash(old_raw).to_le_bytes());
    body.extend(name.as_bytes());
    let mut field = vec![0x75, 0x70];
    field.extend((body.len() as u16).to_le_bytes());
    field.extend(body);
    field
}

fn ut_field() -> Vec<u8> {
    // Extended timestamp (0x5455), mtime only.
    vec![0x55, 0x54, 5, 0, 1, 0x80, 0x51, 0x01, 0x4a]
}

/// Build a Stored archive. `wide` members use ZIP64 sizes and offsets, and
/// any wide member adds ZIP64 end records.
fn build(members: &[M]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let zip64_end = members.iter().any(|m| m.wide);
    for m in members {
        let offset = out.len() as u64;
        let crc = crc32fast::hash(&m.data);
        let size = m.data.len() as u64;
        let flags = m.flags | if m.descriptor { 8 } else { 0 };
        let mut local_extra = m.local_extra.clone();
        let (lcrc, lsize) = if m.descriptor { (0, 0) } else { (crc, size) };
        if m.wide {
            local_extra.extend([1, 0, 16, 0]);
            local_extra.extend(lsize.to_le_bytes());
            local_extra.extend(lsize.to_le_bytes());
        }
        out.extend(0x0403_4b50_u32.to_le_bytes());
        out.extend((if m.wide { 45_u16 } else { 20 }).to_le_bytes());
        out.extend(flags.to_le_bytes());
        out.extend([0, 0, 0x21, 0, 0x21, 0x5a]);
        out.extend(lcrc.to_le_bytes());
        let small = if m.wide { u32::MAX } else { lsize as u32 };
        out.extend(small.to_le_bytes());
        out.extend(small.to_le_bytes());
        out.extend((m.name.len() as u16).to_le_bytes());
        out.extend((local_extra.len() as u16).to_le_bytes());
        out.extend(&m.name);
        out.extend(&local_extra);
        out.extend(&m.data);
        if m.descriptor {
            out.extend(0x0807_4b50_u32.to_le_bytes());
            out.extend(crc.to_le_bytes());
            if m.wide {
                out.extend(size.to_le_bytes());
                out.extend(size.to_le_bytes());
            } else {
                out.extend((size as u32).to_le_bytes());
                out.extend((size as u32).to_le_bytes());
            }
        }
        let mut extra = m.central_extra.clone();
        if m.wide {
            extra.extend([1, 0, 24, 0]);
            extra.extend(size.to_le_bytes());
            extra.extend(size.to_le_bytes());
            extra.extend(offset.to_le_bytes());
        }
        central.extend(0x0201_4b50_u32.to_le_bytes());
        central.extend([0x3f, 3]);
        central.extend((if m.wide { 45_u16 } else { 20 }).to_le_bytes());
        central.extend(flags.to_le_bytes());
        central.extend([0, 0, 0x21, 0, 0x21, 0x5a]);
        central.extend(crc.to_le_bytes());
        let small = if m.wide { u32::MAX } else { size as u32 };
        central.extend(small.to_le_bytes());
        central.extend(small.to_le_bytes());
        central.extend((m.name.len() as u16).to_le_bytes());
        central.extend((extra.len() as u16).to_le_bytes());
        central.extend((m.comment.len() as u16).to_le_bytes());
        central.extend([0; 4]);
        central.extend(0x81a4_0000_u32.to_le_bytes());
        central.extend((if m.wide { u32::MAX } else { offset as u32 }).to_le_bytes());
        central.extend(&m.name);
        central.extend(&extra);
        central.extend(&m.comment);
    }
    let directory_at = out.len() as u64;
    let count = members.len() as u64;
    out.extend(&central);
    if zip64_end {
        let end64 = out.len() as u64;
        out.extend(0x0606_4b50_u32.to_le_bytes());
        out.extend(44_u64.to_le_bytes());
        out.extend([45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        for value in [count, count, central.len() as u64, directory_at] {
            out.extend(value.to_le_bytes());
        }
        out.extend(0x0706_4b50_u32.to_le_bytes());
        out.extend(0_u32.to_le_bytes());
        out.extend(end64.to_le_bytes());
        out.extend(1_u32.to_le_bytes());
    }
    out.extend(0x0605_4b50_u32.to_le_bytes());
    out.extend([0; 4]);
    let (c16, c32) = if zip64_end { (u16::MAX, u32::MAX) } else { (count as u16, 0) };
    out.extend(c16.to_le_bytes());
    out.extend(c16.to_le_bytes());
    out.extend((if zip64_end { c32 } else { central.len() as u32 }).to_le_bytes());
    out.extend((if zip64_end { c32 } else { directory_at as u32 }).to_le_bytes());
    out.extend([0, 0]);
    out
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Rec {
    name: Vec<u8>,
    flags: usize,
    local_offset: u64,
    local_extra: Vec<u8>,
    central_extra: Vec<u8>,
    comment: Vec<u8>,
    crc: u64,
    packed: u64,
    version_needed: usize,
    /// Payload and descriptor bytes.
    body: Vec<u8>,
    /// Whole local record.
    local: Vec<u8>,
}

/// Parse a classic or ZIP64 archive through its central directory.
fn parse(bytes: &[u8]) -> Vec<Rec> {
    let eocd = bytes.len() - 22;
    assert_eq!(le32(bytes, eocd), 0x0605_4b50);
    let (mut count, mut at) = (le16(bytes, eocd + 10) as u64, le32(bytes, eocd + 16));
    if count == 0xffff {
        let locator = eocd - 20;
        let end64 = le64(bytes, locator + 8) as usize;
        assert_eq!(le32(bytes, end64), 0x0606_4b50);
        count = le64(bytes, end64 + 32);
        at = le64(bytes, end64 + 48);
    }
    let directory_start = at as usize;
    let mut records = Vec::new();
    let mut at = directory_start;
    for _ in 0..count {
        assert_eq!(le32(bytes, at), 0x0201_4b50);
        let (nl, el, cl) = (le16(bytes, at + 28), le16(bytes, at + 30), le16(bytes, at + 32));
        let extra = bytes[at + 46 + nl..at + 46 + nl + el].to_vec();
        let mut packed = le32(bytes, at + 20);
        let mut offset = le32(bytes, at + 42);
        let mut i = 0;
        while i + 4 <= extra.len() {
            let (id, len) = (le16(&extra, i), le16(&extra, i + 2));
            if id == 1 {
                let mut cursor = i + 4;
                if le32(bytes, at + 24) == u64::from(u32::MAX) {
                    cursor += 8;
                }
                if packed == u64::from(u32::MAX) {
                    packed = le64(&extra, cursor);
                    cursor += 8;
                }
                if offset == u64::from(u32::MAX) {
                    offset = le64(&extra, cursor);
                }
            }
            i += 4 + len;
        }
        records.push(Rec {
            name: bytes[at + 46..at + 46 + nl].to_vec(),
            flags: le16(bytes, at + 8),
            local_offset: offset,
            local_extra: Vec::new(),
            central_extra: extra,
            comment: bytes[at + 46 + nl + el..at + 46 + nl + el + cl].to_vec(),
            crc: le32(bytes, at + 16),
            packed,
            version_needed: le16(bytes, at + 6),
            body: Vec::new(),
            local: Vec::new(),
        });
        at += 46 + nl + el + cl;
    }
    let mut starts: Vec<u64> = records.iter().map(|r| r.local_offset).collect();
    starts.sort_unstable();
    starts.push(directory_start as u64);
    for record in &mut records {
        let at = record.local_offset as usize;
        assert_eq!(le32(bytes, at), 0x0403_4b50, "local signature at {at}");
        let next = starts[starts.partition_point(|&s| s <= record.local_offset)] as usize;
        let (nl, el) = (le16(bytes, at + 26), le16(bytes, at + 28));
        assert_eq!(&bytes[at + 30..at + 30 + nl], &record.name[..], "local name matches central");
        record.local_extra = bytes[at + 30 + nl..at + 30 + nl + el].to_vec();
        record.body = bytes[at + 30 + nl + el..next].to_vec();
        record.local = bytes[at..next].to_vec();
    }
    records
}

fn options() -> RewriteOptions {
    RewriteOptions::new(Replacement::LastWriterWins)
}

fn entry(name: &str) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method: Method::Stored,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"",
    }
}

struct Rig {
    _root: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl Rig {
    fn new(bytes: &[u8]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("archive.zip");
        fs::write(&path, bytes).unwrap();
        Self { _root: root, path }
    }

    fn plan(&self) -> RewritePlan {
        RewritePlan::open(&self.path, options()).unwrap()
    }

    fn id(&self, plan: &RewritePlan, ordinal: usize) -> zipfast::zip::EntryId {
        plan.metadata().entry_id(ordinal).unwrap()
    }

    /// Rename one member and publish. Returns the new archive bytes.
    fn rename(&self, ordinal: usize, new_name: EntryName<'_>) -> Result<Vec<u8>, RewriteError> {
        let mut plan = self.plan();
        let id = self.id(&plan, ordinal);
        plan.rename(&id, new_name)?;
        match plan.publish().map_err(|failure| failure.cause)? {
            RewriteOutcome::Replaced(_) => Ok(fs::read(&self.path).unwrap()),
            RewriteOutcome::Unchanged { .. } => panic!("a rename must change the archive"),
        }
    }
}

fn tool(name: &[&str]) -> Option<String> {
    name.iter()
        .find(|candidate| {
            Command::new(candidate)
                .arg("--help")
                .output()
                .is_ok_and(|out| !out.stdout.is_empty() || !out.stderr.is_empty())
        })
        .map(|candidate| candidate.to_string())
}

/// `unzip -t` and `7z t` accept the archive, when the binaries exist.
fn external_tests(bytes: &[u8]) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("check.zip");
    fs::write(&path, bytes).unwrap();
    if tool(&["unzip"]).is_some() {
        let out = Command::new("unzip").arg("-t").arg(&path).output().unwrap();
        assert!(out.status.success(), "unzip -t: {}", String::from_utf8_lossy(&out.stdout));
    }
    if let Some(seven) = tool(&["7zz", "7z"]) {
        let out = Command::new(seven).arg("t").arg(&path).output().unwrap();
        assert!(out.status.success(), "7z t: {}", String::from_utf8_lossy(&out.stdout));
    }
}

/// Central extras with the ZIP64 local-offset value (the last 8 bytes of a
/// three-value ZIP64 extra) zeroed, since offsets legitimately move.
fn norm(extra: &[u8]) -> Vec<u8> {
    let (mut out, mut i) = (extra.to_vec(), 0);
    while i + 4 <= extra.len() {
        let len = le16(extra, i + 2);
        if le16(extra, i) == 1 && len == 24 {
            out[i + 4 + 16..i + 4 + 24].fill(0);
        }
        i += 4 + len;
    }
    out
}

/// Everything except the renamed member is byte-identical (local records
/// whole, central fields equal) and the renamed member keeps its payload.
fn check_only_name_changed(old: &[u8], new: &[u8], index: usize, name: &[u8]) -> (Rec, Rec) {
    let (before, after) = (parse(old), parse(new));
    assert_eq!(before.len(), after.len());
    for (i, (b, a)) in before.iter().zip(&after).enumerate() {
        if i != index {
            assert_eq!(b.local, a.local, "member {i} local record");
            assert_eq!(
                (&b.name, b.flags, norm(&b.central_extra), &b.comment),
                (&a.name, a.flags, norm(&a.central_extra), &a.comment)
            );
        }
        assert_eq!((b.crc, b.packed, &b.body), (a.crc, a.packed, &a.body), "member {i} payload, descriptor and sizes");
        assert_eq!(b.comment, a.comment);
    }
    assert_eq!(after[index].name, name);
    external_tests(new);
    (before[index].clone(), after[index].clone())
}

fn display_names(bytes: &[u8]) -> Vec<String> {
    let rig = Rig::new(bytes);
    ReadSession::open(&rig.path).unwrap().metadata().entries().map(|e| e.name().to_string()).collect()
}

#[test]
fn plain_archive_longer_shorter_and_same_length_names() {
    let members = [m("a.txt", b"alpha"), m("dir/b.txt", &[7; 3000]), m("c.txt", b"gamma")];
    let bytes = build(&members);
    for (index, name) in [(0, "x"), (0, "a-much-longer-name.txt"), (1, "dir/c.bin"), (2, "d/e/f/g.txt")] {
        let rig = Rig::new(&bytes);
        let new = rig.rename(index, EntryName::Utf8(name)).unwrap();
        let (_, after) = check_only_name_changed(&bytes, &new, index, name.as_bytes());
        assert_eq!(after.flags, 0, "ASCII names leave the UTF-8 flag clear");
        // The data is found where the new central record says and extracts alike.
        let data = new_data(&new, name);
        assert_eq!(data, members[index].data);
        assert!(display_names(&new).contains(&name.to_string()));
        assert_eq!(new.len() as i64 - bytes.len() as i64, 2 * (name.len() as i64 - members[index].name.len() as i64));
    }
}

fn new_data(archive: &[u8], name: &str) -> Vec<u8> {
    let records = parse(archive);
    let record = records.iter().find(|r| r.name == name.as_bytes()).unwrap();
    record.body[..record.packed as usize].to_vec()
}

#[test]
fn zip64_members_keep_wide_sizes_and_offsets_follow_the_new_name_lengths() {
    let mut members = [m("one", &[1; 700]), m("two", &[2; 900]), m("three", b"3")];
    for member in &mut members {
        member.wide = true;
    }
    members[1].central_extra = ut_field();
    members[1].local_extra = ut_field();
    let bytes = build(&members);
    for (index, name) in [(0, "a-much-longer-first-name"), (1, "t"), (2, "tres")] {
        let rig = Rig::new(&bytes);
        let new = rig.rename(index, EntryName::Utf8(name)).unwrap();
        let (before, after) = check_only_name_changed(&bytes, &new, index, name.as_bytes());
        assert_eq!(norm(&before.central_extra), norm(&after.central_extra), "ZIP64 and timestamp extras survive");
        assert_eq!(after.central_extra[after.central_extra.len() - 8..], after.local_offset.to_le_bytes());
        assert_eq!(before.local_extra, after.local_extra);
        assert_eq!(new_data(&new, name), members[index].data);
        // Offsets point at local records bearing the matching names.
        for record in parse(&new) {
            assert!(record.local.starts_with(b"PK\x03\x04"));
        }
    }
}

#[test]
fn data_descriptor_members_keep_their_descriptors() {
    for wide in [false, true] {
        let mut members = [m("first.bin", &[9; 400]), m("second.bin", &[8; 5000]), m("third", b"z")];
        for member in &mut members {
            member.descriptor = true;
            member.wide = wide;
        }
        members[1].comment = b"kept".to_vec();
        let bytes = build(&members);
        for (index, name) in [(0, "renamed-first-with-a-long-name.bin"), (1, "s"), (2, "third2")] {
            let rig = Rig::new(&bytes);
            let new = rig.rename(index, EntryName::Utf8(name)).unwrap();
            let (before, after) = check_only_name_changed(&bytes, &new, index, name.as_bytes());
            assert_eq!(after.flags & 8, 8, "bit 3 stays set");
            assert_eq!(before.local[6..8], after.local[6..8], "descriptor flag in the local header");
            assert_eq!(before.local[14..26], after.local[14..26], "local CRC and sizes stay zero");
            assert_eq!(new_data(&new, name), members[index].data);
        }
    }
}

#[test]
fn unicode_path_extra_is_dropped_and_other_extras_survive() {
    let uber = "\u{fc}ber.txt";
    let mut first = m("old.txt", b"data data data");
    let extra = [ut_field(), unicode_path(uber, b"old.txt")].concat();
    first.local_extra = extra.clone();
    first.central_extra = extra;
    let members = [first, m("keep.txt", b"k")];
    let bytes = build(&members);
    let mut expect_extra = ut_field();
    for (name, flag) in [
        (EntryName::Utf8("plain.txt"), 0),
        (EntryName::Utf8("caf\u{e9}.txt"), 0x800),
        (EntryName::Raw(b"raw\xe9.txt"), 0),
    ] {
        let rig = Rig::new(&bytes);
        let raw = match name {
            EntryName::Utf8(n) => n.as_bytes().to_vec(),
            EntryName::Raw(n) => n.to_vec(),
        };
        let new = rig.rename(0, name).unwrap();
        let (_, after) = check_only_name_changed(&bytes, &new, 0, &raw);
        assert_eq!(after.flags, flag);
        assert_eq!(after.central_extra, expect_extra, "0x7075 removed, 0x5455 kept");
        assert_eq!(after.local_extra, expect_extra);
        expect_extra = ut_field();
    }
    // The old Unicode name stops resolving, the new one resolves.
    let rig = Rig::new(&bytes);
    assert_eq!(display_names(&bytes)[0], uber);
    let new = rig.rename(0, EntryName::Utf8("plain.txt")).unwrap();
    assert_eq!(display_names(&new), ["plain.txt", "keep.txt"]);
}

#[test]
fn utf8_flag_follows_the_new_name_and_the_comment_encoding() {
    // Flag set, ASCII new name: flag cleared (as 7-Zip does).
    let mut first = m("\u{fc}ber.txt", b"abc");
    first.flags = 0x800;
    let bytes = build(&[first.clone(), m("z", b"")]);
    let rig = Rig::new(&bytes);
    let new = rig.rename(0, EntryName::Utf8("plain.txt")).unwrap();
    assert_eq!(parse(&new)[0].flags, 0);
    assert_eq!(le16(&new, 6), 0, "local flags agree");
    let new = Rig::new(&bytes).rename(0, EntryName::Utf8("\u{fc}ber2.txt")).unwrap();
    assert_eq!(parse(&new)[0].flags, 0x800);
    external_tests(&new);

    // A UTF-8 comment keeps the flag: clearing it would change the comment's
    // encoding, so a name that can live with the flag still renames.
    first.comment = "n\u{fc}te".as_bytes().to_vec();
    let bytes = build(&[first.clone()]);
    let new = Rig::new(&bytes).rename(0, EntryName::Utf8("plain.txt")).unwrap();
    assert_eq!(parse(&new)[0].flags, 0x800);
    assert_eq!(parse(&new)[0].comment, first.comment);
    let error = Rig::new(&bytes).rename(0, EntryName::Raw(b"bad\xff.txt")).unwrap_err();
    assert!(matches!(error, RewriteError::RenameEncoding(_)), "{error}");

    // An OEM comment with the flag clear forbids a non-ASCII UTF-8 name.
    let mut oem = m("a", b"x");
    oem.comment = vec![0x82];
    let bytes = build(&[oem]);
    let error = Rig::new(&bytes).rename(0, EntryName::Utf8("caf\u{e9}")).unwrap_err();
    assert!(matches!(error, RewriteError::RenameEncoding(_)), "{error}");
    Rig::new(&bytes).rename(0, EntryName::Utf8("cafe")).unwrap();
}

#[test]
fn directories_rename_as_directories() {
    let bytes = build(&[m("d/", b""), m("d/f", b"x")]);
    let rig = Rig::new(&bytes);
    let new = rig.rename(0, EntryName::Utf8("e/")).unwrap();
    check_only_name_changed(&bytes, &new, 0, b"e/");
    assert!(matches!(Rig::new(&bytes).rename(0, EntryName::Utf8("e")).unwrap_err(), RewriteError::Infrastructure(_)));
    assert!(matches!(Rig::new(&bytes).rename(1, EntryName::Utf8("g/")).unwrap_err(), RewriteError::Infrastructure(_)));
}

#[test]
fn unsafe_and_malformed_names_are_refused() {
    let bytes = build(&[m("a", b"1"), m("b", b"2")]);
    for name in ["", "/abs", "../up", "a/../b", "x//y", "./z", "back\\slash", "c:evil", "ctl\u{1}", "trail/"] {
        let rig = Rig::new(&bytes);
        let error = rig.rename(0, EntryName::Utf8(name)).unwrap_err();
        assert!(matches!(error, RewriteError::Infrastructure(_)), "{name:?}: {error}");
        assert_eq!(fs::read(&rig.path).unwrap(), bytes);
    }
    let long = "n".repeat(70_000);
    assert!(matches!(Rig::new(&bytes).rename(0, EntryName::Utf8(&long)).unwrap_err(), RewriteError::Infrastructure(_)));
}

#[test]
fn duplicate_names_are_refused_but_freed_names_are_reusable() {
    let bytes = build(&[m("a", b"1"), m("b", b"2"), m("a", b"3")]);
    let rig = Rig::new(&bytes);
    // Same name, another live member's name, and a no-op rename all conflict.
    assert!(matches!(rig.rename(1, EntryName::Utf8("a")).unwrap_err(), RewriteError::NameConflict));
    assert!(matches!(rig.rename(1, EntryName::Utf8("b")).unwrap_err(), RewriteError::NameConflict));
    // Renaming one of two duplicates leaves the other alone.
    let new = rig.rename(0, EntryName::Utf8("c")).unwrap();
    check_only_name_changed(&bytes, &new, 0, b"c");

    // A removed member's name is free; a renamed-away name is free.
    let mut plan = rig.plan();
    let (first, second) = (rig.id(&plan, 0), rig.id(&plan, 1));
    plan.remove(&first).unwrap();
    plan.rename(&second, EntryName::Utf8("a")).unwrap_err(); // the third entry still holds "a"
    let third = rig.id(&plan, 2);
    plan.remove(&third).unwrap();
    plan.rename(&second, EntryName::Utf8("a")).unwrap();
    plan.publish().unwrap();
    let after = parse(&fs::read(&rig.path).unwrap());
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].name, b"a");
    assert_eq!(after[0].body, b"2");
}

#[test]
fn renames_conflict_with_each_other_with_appends_and_with_repeat_edits() {
    let bytes = build(&[m("a", b"1"), m("b", b"2"), m("c", b"3")]);
    let rig = Rig::new(&bytes);
    let mut plan = rig.plan();
    let (a, b, c) = (rig.id(&plan, 0), rig.id(&plan, 1), rig.id(&plan, 2));
    plan.rename(&a, EntryName::Utf8("x")).unwrap();
    assert!(matches!(plan.rename(&b, EntryName::Utf8("x")), Err(RewriteError::NameConflict)));
    assert!(matches!(plan.rename(&a, EntryName::Utf8("y")), Err(RewriteError::DuplicateEdit)));
    assert!(matches!(plan.remove(&a), Err(RewriteError::DuplicateEdit)));
    // The new name of a renamed member is taken, the old one is free.
    let mut appended = entry("q");
    appended.comment = b"";
    let source = rig._root.path().join("input");
    fs::write(&source, b"new").unwrap();
    plan.add_file(Placement::Append, &source, appended, None).unwrap();
    assert!(matches!(plan.rename(&c, EntryName::Utf8("q")), Err(RewriteError::NameConflict)));
    plan.add_file(Placement::Append, &source, entry("a"), None).unwrap();
    let mut late = entry("x");
    late.comment = b"";
    assert!(matches!(plan.add_file(Placement::Append, &source, late, None), Err(RewriteError::NameConflict)));
    plan.publish().unwrap();
    let names: Vec<_> = parse(&fs::read(&rig.path).unwrap()).into_iter().map(|r| r.name).collect();
    assert_eq!(names, [b"x".to_vec(), b"b".to_vec(), b"c".to_vec(), b"q".to_vec(), b"a".to_vec()]);
}

#[test]
fn hierarchy_conflicts_fail_the_plan_before_staging() {
    let bytes = build(&[m("a", b"1"), m("b", b"2")]);
    let rig = Rig::new(&bytes);
    let mut plan = rig.plan();
    let a = rig.id(&plan, 0);
    plan.rename(&a, EntryName::Utf8("b/c")).unwrap();
    let failure = plan.publish().unwrap_err();
    assert!(matches!(failure.cause, RewriteError::NameConflict), "{failure}");
    assert_eq!(fs::read(&rig.path).unwrap(), bytes);
    assert_eq!(fs::read_dir(rig.path.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn full_verification_and_receipts_see_renamed_members_as_retained() {
    let mut members = [m("a", &[5; 100]), m("b", &[6; 100])];
    members[0].descriptor = true;
    let bytes = build(&members);
    let rig = Rig::new(&bytes);
    let mut opts = options();
    opts.verification = Verification::Full;
    let mut plan = RewritePlan::open(&rig.path, opts).unwrap();
    let id = rig.id(&plan, 0);
    plan.rename(&id, EntryName::Utf8("renamed-a")).unwrap();
    let report = plan.publish_with_receipts();
    assert!(report.written.is_empty(), "retained members have no write receipt");
    let RewriteOutcome::Replaced(done) = report.outcome.unwrap() else { panic!("replaced") };
    assert_eq!(done.verification.retained_payload_verified, 2);
    assert_eq!(done.verification.new_verified, 0);
    external_tests(&fs::read(&rig.path).unwrap());
}

#[test]
fn rename_needs_the_exact_collision_policy() {
    let bytes = build(&[m("a", b"1")]);
    let rig = Rig::new(&bytes);
    let mut opts = options();
    opts.collisions = zipfast::zip::create::CollisionPolicy::CallerKeys;
    let mut plan = RewritePlan::open(&rig.path, opts).unwrap();
    let id = rig.id(&plan, 0);
    assert!(matches!(plan.rename(&id, EntryName::Utf8("b")), Err(RewriteError::RenameUnsupported(_))));
}

// ---- 7-Zip `rn` parity ------------------------------------------------------

fn fixture(name: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip-rename").join(name)).unwrap()
}

/// Strip the NTFS timestamp extra (0x000a) 7-Zip adds to a renamed central record.
fn without_ntfs(extra: &[u8]) -> Vec<u8> {
    let (mut out, mut i) = (Vec::new(), 0);
    while i + 4 <= extra.len() {
        let len = le16(extra, i + 2);
        if le16(extra, i) != 0x000a {
            out.extend(&extra[i..i + 4 + len]);
        }
        i += 4 + len;
    }
    out
}

/// Our rename of `ordinal` matches 7-Zip's `rn` output: identical bytes for
/// every local record, and identical central records apart from 7-Zip's NTFS
/// timestamp extra.
fn matches_seven_zip(source: &str, ordinal: usize, new_name: &str, seven: &str) {
    let old = fixture(source);
    let reference = fixture(seven);
    let ours = Rig::new(&old).rename(ordinal, EntryName::Utf8(new_name)).unwrap();
    let (a, b) = (parse(&ours), parse(&reference));
    assert_eq!(a.len(), b.len());
    for (ours, theirs) in a.iter().zip(&b) {
        assert_eq!(ours.local, theirs.local, "{seven}: local record of {:?}", String::from_utf8_lossy(&ours.name));
        assert_eq!(
            (&ours.name, ours.flags, ours.local_offset, ours.crc, ours.packed, &ours.comment, ours.version_needed),
            (
                &theirs.name,
                theirs.flags,
                theirs.local_offset,
                theirs.crc,
                theirs.packed,
                &theirs.comment,
                theirs.version_needed
            ),
            "{seven}"
        );
        assert_eq!(ours.central_extra, without_ntfs(&theirs.central_extra), "{seven}");
    }
    let local_end = |bytes: &[u8]| {
        let records = parse(bytes);
        let last = records.iter().max_by_key(|r| r.local_offset).unwrap();
        last.local_offset as usize + last.local.len()
    };
    assert_eq!(ours[..local_end(&ours)], reference[..local_end(&reference)], "{seven}: bytes before the directory");
    external_tests(&ours);
}

#[test]
fn matches_seven_zip_rn_for_plain_archives() {
    matches_seven_zip("plain.zip", 0, "z.txt", "plain.same.7z.zip");
    matches_seven_zip("plain.zip", 0, "much-longer-name.txt", "plain.longer.7z.zip");
    matches_seven_zip("plain.zip", 1, "b", "plain.shorter.7z.zip");
}

#[test]
fn matches_seven_zip_rn_for_unicode_extra_and_utf8_flag() {
    let longer = "caf\u{e9}-longer.txt";
    matches_seven_zip("uextra.zip", 0, "new.txt", "uextra.ascii.7z.zip");
    matches_seven_zip("uextra.zip", 0, longer, "uextra.utf8.7z.zip");
    matches_seven_zip("utf8.zip", 0, "plain.txt", "utf8.ascii.7z.zip");
    matches_seven_zip("utf8.zip", 0, longer, "utf8.utf8.7z.zip");
}

/// Rebuilding the records of a member with a large extra and comment is charged to `plan_capacity` before it is
/// allocated, and the usage reports what the prepared plan retains.
#[test]
fn rename_charges_the_rebuilt_records_to_plan_capacity() {
    use zipfast::zip::create::{CreateError, CreateLimit};

    let mut big = m("a", b"payload");
    big.central_extra = {
        let mut field = vec![0xfe, 0xca];
        field.extend(30_000u16.to_le_bytes());
        field.extend(vec![7; 30_000]);
        field
    };
    big.local_extra = big.central_extra.clone();
    big.comment = vec![b'c'; 30_000];
    let rig = Rig::new(&build(&[big, m("b", b"other")]));

    let publish = |plan_capacity: Option<u64>| {
        let mut opts = options();
        if let Some(bytes) = plan_capacity {
            opts.limits.common.plan_capacity = bytes;
        }
        let mut plan = RewritePlan::open(&rig.path, opts).unwrap();
        let id = rig.id(&plan, 0);
        plan.rename(&id, EntryName::Utf8("renamed")).unwrap();
        plan.publish()
    };
    // a limit above the small members' bookkeeping and below the ~90 KB of rebuilt records
    let failure = publish(Some(40_000)).expect_err("the rebuilt records exceed the plan capacity");
    assert!(matches!(failure.cause, RewriteError::Infrastructure(CreateError::Limit(CreateLimit::PlanCapacity))));
    let Ok(RewriteOutcome::Replaced(done)) = publish(None) else { panic!("replaced") };
    assert!(done.usage.common.plan.capacity >= 90_000, "{}", done.usage.common.plan.capacity);
}
