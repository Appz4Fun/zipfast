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

//! Deterministic ar and tar.gz repacking: same members in, same bytes out, whatever the times, owners, modes and
//! order; the output lists and extracts as the input does.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::{Compression, GzBuilder};
use zipfast::Error;
use zipfast::repack::{RepackFormat, RepackOptions, repack, repack_ar, repack_tar_gz};

// ---------------------------------------------------------------- tar fixtures

struct Owner {
    uid: u64,
    gid: u64,
    user: &'static str,
    group: &'static str,
    mtime: u64,
}

const ALICE: Owner = Owner { uid: 1000, gid: 1000, user: "alice", group: "staff", mtime: 1_600_000_000 };
const BOB: Owner = Owner { uid: 501, gid: 20, user: "bob", group: "wheel", mtime: 1_700_000_123 };

fn octal(field: &mut [u8], v: u64) {
    let digits = field.len() - 1;
    field[..digits].copy_from_slice(format!("{v:0digits$o}").as_bytes());
}

fn tar_header(name: &[u8], typeflag: u8, mode: u32, size: u64, link: &[u8], o: &Owner) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name);
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], o.uid);
    octal(&mut h[116..124], o.gid);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], o.mtime);
    h[148..156].fill(b' ');
    h[156] = typeflag;
    h[157..157 + link.len()].copy_from_slice(link);
    h[257..265].copy_from_slice(b"ustar  \0");
    h[265..265 + o.user.len()].copy_from_slice(o.user.as_bytes());
    h[297..297 + o.group.len()].copy_from_slice(o.group.as_bytes());
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

enum T<'a> {
    File(&'a str, u32, &'a [u8]),
    Dir(&'a str, u32),
    Sym(&'a str, &'a str),
    Hard(&'a str, &'a str),
}

fn tar(members: &[T<'_>], o: &Owner) -> Vec<u8> {
    let mut out = Vec::new();
    for m in members {
        match *m {
            T::File(name, mode, data) => {
                let name = name.as_bytes();
                if name.len() > 100 {
                    let long = [name, b"\0"].concat();
                    out.extend_from_slice(&tar_header(b"././@LongLink", b'L', 0o644, long.len() as u64, b"", o));
                    out.extend_from_slice(&long);
                    out.resize(out.len().next_multiple_of(512), 0);
                }
                out.extend_from_slice(&tar_header(&name[..name.len().min(100)], b'0', mode, data.len() as u64, b"", o));
                out.extend_from_slice(data);
                out.resize(out.len().next_multiple_of(512), 0);
            }
            T::Dir(name, mode) => out.extend_from_slice(&tar_header(name.as_bytes(), b'5', mode, 0, b"", o)),
            T::Sym(name, to) => out.extend_from_slice(&tar_header(name.as_bytes(), b'2', 0o777, 0, to.as_bytes(), o)),
            T::Hard(name, to) => out.extend_from_slice(&tar_header(name.as_bytes(), b'1', 0o644, 0, to.as_bytes(), o)),
        }
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn gzip(data: &[u8], mtime: u32, name: &str, level: u32) -> Vec<u8> {
    let mut gz = GzBuilder::new().mtime(mtime).filename(name).write(Vec::new(), Compression::new(level));
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

fn long_name() -> String {
    format!("deep/{}/{}", "d".repeat(120), "f".repeat(110))
}

/// The same tree twice, in a different order, with different owners, times, modes and gzip headers, and the hard
/// link pointing the other way.
fn tree_a() -> Vec<u8> {
    let long = long_name();
    let t = tar(
        &[
            T::Dir("a", 0o700),
            T::File("a/x", 0o700, b"executable\n"),
            T::Hard("a/h", "a/x"),
            T::File("b.txt", 0o600, b"bee\n"),
            T::Sym("a/l", "x"),
            T::Dir("deep/", 0o750),
            T::File(&long, 0o640, b"long\n"),
        ],
        &ALICE,
    );
    gzip(&t, 12345, "tree.tar", 1)
}

fn tree_b() -> Vec<u8> {
    let long = long_name();
    let t = tar(
        &[
            T::File("b.txt", 0o664, b"bee\n"),
            T::Sym("a/l", "x"),
            T::File(&long, 0o664, b"long\n"),
            T::Dir("deep", 0o755),
            T::Dir("a/", 0o775),
            T::File("a/h", 0o755, b"executable\n"),
            T::Hard("a/x", "a/h"),
        ],
        &BOB,
    );
    gzip(&t, 99, "other.tar", 9)
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn repacked(dir: &Path, name: &str, input: &[u8], opts: &RepackOptions) -> Vec<u8> {
    let i = write(dir, &format!("{name}.in"), input);
    let o = dir.join(format!("{name}.out"));
    repack(&i, &o, opts).unwrap();
    std::fs::read(o).unwrap()
}

#[test]
fn tar_gz_repacks_to_the_same_bytes_twice() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions::default();
    let one = repacked(dir.path(), "one", &tree_a(), &opts);
    let two = repacked(dir.path(), "two", &tree_a(), &opts);
    assert_eq!(one, two);
    // gzip: no FNAME flag, MTIME 0, XFL 2 (level 9), OS 3
    assert_eq!(&one[..10], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3]);
}

#[test]
fn tar_gz_ignores_times_owners_modes_order_and_gzip_header() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions::default();
    let a = repacked(dir.path(), "a", &tree_a(), &opts);
    let b = repacked(dir.path(), "b", &tree_b(), &opts);
    assert_eq!(a, b);
    // an uncompressed tar of the same tree gives the same bytes too
    let plain = flate2_decode(&tree_b());
    assert_eq!(repacked(dir.path(), "plain", &plain, &opts), a);
}

fn flate2_decode(gz: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut out).unwrap();
    out
}

#[test]
fn tar_gz_output_is_normalised() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions { mtime: 1_234_567_890, ..RepackOptions::default() };
    let out = repacked(dir.path(), "a", &tree_a(), &opts);
    let path = write(dir.path(), "check.tar.gz", &out);
    let entries = zipfast::tar::list(&path).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let long = long_name();
    assert_eq!(names, ["a/", "a/h", "a/l", "a/x", "b.txt", "deep/", long.as_str()]);
    for e in &entries {
        assert_eq!(e.mtime, Some(1_234_567_890), "{}", e.name);
        let tar = e.tar.as_ref().unwrap();
        assert_eq!((tar.uid, tar.gid), (Some(0), Some(0)), "{}", e.name);
        assert_eq!((tar.user.as_deref(), tar.group.as_deref()), (Some(""), Some("")), "{}", e.name);
    }
    let mode = |n: &str| entries.iter().find(|e| e.name == n).unwrap().mode.unwrap();
    assert_eq!(mode("a/"), 0o755);
    assert_eq!(mode("a/h"), 0o755);
    assert_eq!(mode("a/l"), 0o777);
    assert_eq!(mode("b.txt"), 0o644);
    assert_eq!(mode(&long), 0o644);
    // the first of the linked pair in name order carries the data
    assert_eq!(entries[1].size, 11);
    assert_eq!(entries[3].link, Some(zipfast::rar5::Redirection::HardLink("a/h".into())));
}

#[test]
fn tar_gz_refuses_names_that_climb_out_and_dangling_hard_links() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions::default();
    for (name, members) in [
        ("climb", vec![T::File("../evil", 0o644, b"x")]),
        ("deep-climb", vec![T::File("a/../../evil", 0o644, b"x")]),
        ("absolute", vec![T::File("/etc/evil", 0o644, b"x")]),
    ] {
        let i = write(dir.path(), name, &tar(&members, &ALICE));
        let o = dir.path().join(format!("{name}.out"));
        assert!(matches!(repack(&i, &o, &opts), Err(Error::UnsafePath(_))), "{name}");
        assert!(!o.exists());
    }
    let i = write(dir.path(), "dangling", &tar(&[T::Hard("a", "nowhere")], &ALICE));
    assert!(matches!(repack(&i, &dir.path().join("d.out"), &opts), Err(Error::Corrupt(_))));
}

#[test]
fn byte_limit_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions { limit: 8, ..RepackOptions::default() };
    let i = write(dir.path(), "big", &tar(&[T::File("f", 0o644, &[7; 100])], &ALICE));
    assert!(matches!(repack(&i, &dir.path().join("o"), &opts), Err(Error::Unsupported(_))));
}

#[cfg(unix)]
#[test]
fn links_on_disk_are_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions::default();
    let real = write(dir.path(), "real.tar.gz", &tree_a());
    let link = dir.path().join("link.tar.gz");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(repack(&link, &dir.path().join("o"), &opts).is_err());
    // an output path that is a symlink is not written through
    let victim = write(dir.path(), "victim", b"keep me");
    let out = dir.path().join("out.tar.gz");
    std::os::unix::fs::symlink(&victim, &out).unwrap();
    assert!(repack(&real, &out, &opts).is_err());
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
}

#[test]
fn nested_tarballs_are_repacked_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let outer = |inner: Vec<u8>, o: &Owner| gzip(&tar(&[T::File("data.tar.gz", 0o644, &inner)], o), 1, "x", 6);
    let a = outer(tree_a(), &ALICE);
    let b = outer(tree_b(), &BOB);
    let flat = RepackOptions::default();
    assert_ne!(repacked(dir.path(), "fa", &a, &flat), repacked(dir.path(), "fb", &b, &flat));
    let nested = RepackOptions { nested: true, ..RepackOptions::default() };
    let i = write(dir.path(), "na.in", &a);
    let summary = repack(&i, &dir.path().join("na.out"), &nested).unwrap();
    assert_eq!((summary.format, summary.members, summary.nested), (RepackFormat::TarGz, 1, 1));
    assert_eq!(std::fs::read(dir.path().join("na.out")).unwrap(), repacked(dir.path(), "nb", &b, &nested));
}

// ---------------------------------------------------------------- ar fixtures

fn ar_header(name: &[u8], mtime: u64, uid: u64, mode: u32, size: usize) -> Vec<u8> {
    let mut h = format!("{:<16}{mtime:<12}{uid:<6}{uid:<6}{mode:<8o}{size:<10}`\n", "").into_bytes();
    h[..name.len()].copy_from_slice(name);
    h
}

fn pad(out: &mut Vec<u8>) {
    if out.len() % 2 == 1 {
        out.push(b'\n');
    }
}

/// A GNU archive with a `/` symbol table pointing at its members (symbol `sym_<name>` in each) and a `//` table.
fn gnu_ar(members: &[(&str, &[u8])], mtime: u64, uid: u64) -> Vec<u8> {
    let mut table = Vec::new();
    let mut fields = Vec::new();
    for (name, _) in members {
        if name.len() > 15 {
            fields.push(format!("/{}", table.len()));
            table.extend_from_slice(format!("{name}/\n").as_bytes());
        } else {
            fields.push(format!("{name}/"));
        }
    }
    let names: Vec<String> = members.iter().map(|(n, _)| format!("sym_{n}")).collect();
    let symtab_len = 4 + 4 * members.len() + names.iter().map(|n| n.len() + 1).sum::<usize>();
    let mut at = 8 + 60 + symtab_len.next_multiple_of(2);
    if !table.is_empty() {
        at += 60 + table.len().next_multiple_of(2);
    }
    let mut offsets = Vec::new();
    for (_, data) in members {
        offsets.push(at as u32);
        at += 60 + data.len().next_multiple_of(2);
    }
    let mut out = b"!<arch>\n".to_vec();
    out.extend(ar_header(b"/", mtime, 0, 0, symtab_len));
    out.extend((members.len() as u32).to_be_bytes());
    for o in offsets {
        out.extend(o.to_be_bytes());
    }
    for n in &names {
        out.extend(n.as_bytes());
        out.push(0);
    }
    pad(&mut out);
    if !table.is_empty() {
        out.extend(format!("{:<48}{:<10}`\n", "//", table.len()).into_bytes());
        out.extend(&table);
        pad(&mut out);
    }
    for ((_, data), field) in members.iter().zip(&fields) {
        out.extend(ar_header(field.as_bytes(), mtime, uid, 0o100664, data.len()));
        out.extend(*data);
        pad(&mut out);
    }
    out
}

/// A BSD archive, every name as `#1/<n>`.
fn bsd_ar(members: &[(&str, &[u8])], mtime: u64, uid: u64) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        out.extend(ar_header(format!("#1/{}", name.len()).as_bytes(), mtime, uid, 0o100644, name.len() + data.len()));
        out.extend(name.as_bytes());
        out.extend(*data);
        pad(&mut out);
    }
    out
}

/// A plain archive as dpkg writes a `.deb`.
fn plain_ar(members: &[(&str, &[u8])], mtime: u64, uid: u64) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        out.extend(ar_header(name.as_bytes(), mtime, uid, 0o100644, data.len()));
        out.extend(*data);
        pad(&mut out);
    }
    out
}

const OBJ_A: &[u8] = b"object a\n";
const OBJ_B: &[u8] = b"object bb\n";
const OBJ_LONG: &[u8] = b"a long-named object\n";

#[test]
fn gnu_ar_repacks_deterministically_and_moves_its_symbol_table() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions::default();
    let one = gnu_ar(&[("b.o", OBJ_B), ("a_rather_long_object.o", OBJ_LONG), ("a.o", OBJ_A)], 1_600_000_000, 1000);
    let two = gnu_ar(&[("a.o", OBJ_A), ("b.o", OBJ_B), ("a_rather_long_object.o", OBJ_LONG)], 1_700_000_000, 501);
    let out = repacked(dir.path(), "one", &one, &opts);
    assert_eq!(out, repacked(dir.path(), "one-again", &one, &opts));
    assert_eq!(out, repacked(dir.path(), "two", &two, &opts));
    // every symbol still points at the header of the member it came from
    let header = |at: usize| &out[at..at + 60];
    let count = u32::from_be_bytes(out[68..72].try_into().unwrap()) as usize;
    assert_eq!(count, 3);
    let symbols_at = 72 + 4 * count;
    let symbols: Vec<&[u8]> = out[symbols_at..].split(|&b| b == 0).take(count).collect();
    let table_at = 8 + 60 + (4 + 4 * count + symbols.iter().map(|s| s.len() + 1).sum::<usize>()).next_multiple_of(2);
    assert_eq!(&header(table_at)[..2], b"//");
    let table = &out[table_at + 60..];
    for (i, symbol) in symbols.iter().enumerate() {
        let at = u32::from_be_bytes(out[72 + 4 * i..76 + 4 * i].try_into().unwrap()) as usize;
        let field = std::str::from_utf8(&header(at)[..16]).unwrap().trim_end();
        let name = match field.strip_prefix('/') {
            Some(offset) => {
                let rest = &table[offset.parse::<usize>().unwrap()..];
                std::str::from_utf8(&rest[..rest.iter().position(|&b| b == b'/').unwrap()]).unwrap().to_string()
            }
            None => field.trim_end_matches('/').to_string(),
        };
        assert_eq!(*symbol, format!("sym_{name}").as_bytes());
        // GNU `ar D`: time 0, owner 0, group 0, mode 644
        assert_eq!(&header(at)[16..48], b"0           0     0     644     ");
    }
}

#[test]
fn bsd_and_plain_ar_repack_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions::default();
    let members = [("zeta.o", OBJ_A), ("a name with spaces.o", OBJ_B), ("alpha.o", OBJ_LONG)];
    let mut reversed = members;
    reversed.reverse();
    let out = repacked(dir.path(), "bsd1", &bsd_ar(&members, 1, 2), &opts);
    assert_eq!(out, repacked(dir.path(), "bsd2", &bsd_ar(&reversed, 999_999, 501), &opts));
    // data 8-aligned, as Apple's linker wants
    let mut at = 8;
    while at < out.len() {
        let field = std::str::from_utf8(&out[at..at + 16]).unwrap().trim_end();
        let n: usize = field.strip_prefix("#1/").unwrap().parse().unwrap();
        assert_eq!((at + 60 + n) % 8, 0);
        let size: usize = std::str::from_utf8(&out[at + 48..at + 58]).unwrap().trim_end().parse().unwrap();
        at += 60 + size.next_multiple_of(2);
    }

    let deb = [("debian-binary", b"2.0\n".as_slice()), ("control.tar.gz", b"ctl"), ("data.tar.gz", b"data")];
    let out = repacked(dir.path(), "deb", &plain_ar(&deb, 1_600_000_000, 1000), &opts);
    assert_eq!(&out[8..24], b"debian-binary   ");
    assert_eq!(out, repacked(dir.path(), "deb2", &plain_ar(&deb, 5, 0), &opts));
}

#[test]
fn deb_nested_tarballs_are_repacked() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions { nested: true, ..RepackOptions::default() };
    let one = plain_ar(&[("debian-binary", b"2.0\n"), ("data.tar.gz", &tree_a())], 1, 1000);
    let two = plain_ar(&[("debian-binary", b"2.0\n"), ("data.tar.gz", &tree_b())], 2, 0);
    let i = write(dir.path(), "one.deb", &one);
    let summary = repack_ar(&i, &dir.path().join("one.out"), &opts).unwrap();
    assert_eq!((summary.format, summary.members, summary.nested), (RepackFormat::Ar, 2, 1));
    assert_eq!(std::fs::read(dir.path().join("one.out")).unwrap(), repacked(dir.path(), "two", &two, &opts));
}

#[test]
fn ar_refuses_unsafe_names_thin_archives_and_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let opts = RepackOptions::default();
    let i = write(dir.path(), "climb.a", &bsd_ar(&[("../evil", b"x")], 0, 0));
    assert!(matches!(repack(&i, &dir.path().join("o"), &opts), Err(Error::UnsafePath(_))));
    let i = write(dir.path(), "thin.a", b"!<thin>\n");
    assert!(matches!(repack(&i, &dir.path().join("o"), &opts), Err(Error::Unsupported(_))));
    let mut cut = plain_ar(&[("a.o", OBJ_A)], 0, 0);
    cut.truncate(cut.len() - 4);
    let i = write(dir.path(), "cut.a", &cut);
    assert!(matches!(repack(&i, &dir.path().join("o"), &opts), Err(Error::Truncated)));
    // a symbol table pointing nowhere
    let mut bad = gnu_ar(&[("a.o", OBJ_A)], 0, 0);
    bad[72..76].copy_from_slice(&3u32.to_be_bytes());
    let i = write(dir.path(), "bad.a", &bad);
    assert!(matches!(repack(&i, &dir.path().join("o"), &opts), Err(Error::Corrupt(_))));
    // not an ar is not repacked as one
    let i = write(dir.path(), "tar.a", &tree_a());
    assert!(matches!(repack_ar(&i, &dir.path().join("o"), &opts), Err(Error::NotAnArchive)));
}

// ---------------------------------------------------------------- reference tools

fn tool(name: &str) -> bool {
    Command::new(name).arg("--version").output().is_ok()
}

fn run(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{cmd:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// Every file's bytes and every symlink's target under `root`, by relative path.
fn tree(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let e = e.unwrap();
            let rel = e.path().strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let kind = e.file_type().unwrap();
            if kind.is_symlink() {
                out.insert(rel, format!("-> {}", std::fs::read_link(e.path()).unwrap().display()));
            } else if kind.is_dir() {
                out.insert(rel, "dir".into());
                stack.push(e.path());
            } else {
                out.insert(rel, String::from_utf8_lossy(&std::fs::read(e.path()).unwrap()).into_owned());
            }
        }
    }
    out
}

#[test]
fn bsdtar_lists_and_extracts_the_output_as_the_input() {
    if !tool("bsdtar") {
        eprintln!("bsdtar not found: skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let input = write(dir.path(), "in.tar.gz", &tree_b());
    let output = dir.path().join("out.tar.gz");
    repack_tar_gz(&input, &output, &RepackOptions::default()).unwrap();
    let list = |p: &Path| {
        let mut names: Vec<String> = String::from_utf8(run(Command::new("bsdtar").arg("-tf").arg(p)))
            .unwrap()
            .lines()
            .map(|l| l.trim_end_matches('/').to_string())
            .collect();
        names.sort();
        names
    };
    assert_eq!(list(&input), list(&output));
    let extract = |p: &Path, to: &str| {
        let d = dir.path().join(to);
        std::fs::create_dir(&d).unwrap();
        run(Command::new("bsdtar").arg("-xf").arg(p).arg("-C").arg(&d));
        tree(&d)
    };
    let (a, b) = (extract(&input, "x-in"), extract(&output, "x-out"));
    assert_eq!(a, b);
    assert!(b.contains_key(&long_name()));
}

#[test]
fn ar_lists_and_prints_the_output_as_the_input() {
    if Command::new("ar").output().is_err() {
        eprintln!("ar not found: skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let members = [("zeta.o", OBJ_A), ("a_rather_long_object.o", OBJ_LONG), ("b.o", OBJ_B)];
    let mut fixtures = vec![("deb", plain_ar(&[("debian-binary", b"2.0\n"), ("data.tar.gz", b"data")], 7, 3))];
    // Apple's ar reads BSD names, GNU ar both
    fixtures.push(("bsd", bsd_ar(&members, 7, 3)));
    if !cfg!(target_os = "macos") {
        fixtures.push(("gnu", gnu_ar(&members, 7, 3)));
    }
    for (name, bytes) in fixtures {
        let input = write(dir.path(), &format!("{name}.a"), &bytes);
        let output = dir.path().join(format!("{name}.out.a"));
        repack_ar(&input, &output, &RepackOptions::default()).unwrap();
        let list = |p: &Path| {
            let mut names: Vec<String> = String::from_utf8(run(Command::new("ar").arg("t").arg(p)))
                .unwrap()
                .lines()
                .filter(|l| !l.starts_with("__.SYMDEF"))
                .map(str::to_string)
                .collect();
            names.sort();
            names
        };
        let names = list(&input);
        assert_eq!(names, list(&output), "{name}");
        for member in &names {
            let p = |a: &Path| run(Command::new("ar").arg("p").arg(a).arg(member));
            assert_eq!(p(&input), p(&output), "{name}: {member}");
        }
    }
}
