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

//! MS-DOS date and time fields carry no time zone. As Info-ZIP unzip, 7-Zip, libarchive and UnRAR do, zipfast reads
//! them as local wall-clock time: listing and extraction give the UTC instant of that wall-clock time in the local
//! zone. Each test re-runs itself in a child process under a fixed `TZ`, since the C library reads the zone once.

#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::Command;

use zipfast::extract::{self, Mode, MtimeOrigin, Options, Overwrite};

const CHILD: &str = "ZIPFAST_DOS_TZ_CHILD";

/// Runs `test` (this file's test of that name) in a child process with `TZ=tz`; returns true in the child.
fn in_zone(test: &str, tz: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env("TZ", tz)
        .env(CHILD, "1")
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("1 passed"), "{test} under TZ={tz}:\n{text}");
    false
}

/// Seconds since 1970 of a civil date and time, as if it were UTC.
fn wall(year: i64, month: i64, day: i64, hour: i64, minute: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    days * 86_400 + hour * 3600 + minute * 60
}

/// A stored ZIP of `(name, data, DOS time, DOS date)` members, with no time extra.
fn zip(members: &[(&str, &[u8], u16, u16)]) -> Vec<u8> {
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for &(name, data, time, date) in members {
        let crc = zipfast::crc32::hash(data);
        let offset = out.len() as u32;
        let common = |out: &mut Vec<u8>| {
            out.extend(20u16.to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(time.to_le_bytes());
            out.extend(date.to_le_bytes());
            out.extend(crc.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
        };
        out.extend(0x0403_4b50u32.to_le_bytes());
        common(&mut out);
        out.extend(name.as_bytes());
        out.extend(data);
        central.extend(0x0201_4b50u32.to_le_bytes());
        central.extend(20u16.to_le_bytes());
        common(&mut central);
        central.extend([0u8; 6]); // comment length, disk, internal attributes
        central.extend(0u32.to_le_bytes()); // external attributes
        central.extend(offset.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let at = out.len() as u32;
    out.extend(&central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(at.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

fn dos(year: u16, month: u16, day: u16, hour: u16, minute: u16) -> (u16, u16) {
    ((hour << 11) | (minute << 5), ((year - 1980) << 9) | (month << 5) | day)
}

/// Lists and extracts `archive`, returning each member's listed mtime and the extracted file's mtime.
fn times(archive: &Path) -> Vec<(String, i64, i64)> {
    let listed = extract::list(archive).unwrap();
    let dest = archive.with_extension("out");
    let options = Options {
        mode: Mode::Extract,
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
    };
    let summary = extract::run(archive, &options, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    listed
        .into_iter()
        .filter(|e| !e.dir)
        .map(|e| {
            assert_eq!(e.mtime_origin, Some(MtimeOrigin::LocalWallClock), "{}", e.name);
            let modified = fs::metadata(dest.join(&e.name)).unwrap().modified().unwrap();
            let on_disk = modified.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            (e.name, e.mtime.unwrap(), on_disk)
        })
        .collect()
}

fn zip_members() -> Vec<u8> {
    let (wt, wd) = dos(2024, 1, 15, 12, 0);
    let (st, sd) = dos(2024, 7, 15, 12, 0);
    // 2024-03-10 02:30 does not exist in Chicago (clocks go 02:00 -> 03:00); 2024-11-03 01:30 happens twice
    let (gt, gd) = dos(2024, 3, 10, 2, 30);
    let (ot, od) = dos(2024, 11, 3, 1, 30);
    zip(&[("winter", b"w", wt, wd), ("summer", b"s", st, sd), ("gap", b"g", gt, gd), ("overlap", b"o", ot, od)])
}

#[test]
fn zip_dos_times_are_chicago_wall_clock() {
    if !in_zone("zip_dos_times_are_chicago_wall_clock", "America/Chicago") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("t.zip");
    fs::write(&archive, zip_members()).unwrap();
    let hour = 3600;
    for (name, listed, on_disk) in times(&archive) {
        assert_eq!(listed, on_disk, "{name}: listing and extraction agree");
        let (base, offsets): (i64, &[i64]) = match name.as_str() {
            "winter" => (wall(2024, 1, 15, 12, 0), &[6 * hour]),
            "summer" => (wall(2024, 7, 15, 12, 0), &[5 * hour]),
            // mktime resolves a gap or an overlap one way or the other: either offset is the platform's choice
            "gap" => (wall(2024, 3, 10, 2, 30), &[5 * hour, 6 * hour]),
            "overlap" => (wall(2024, 11, 3, 1, 30), &[5 * hour, 6 * hour]),
            other => panic!("{other}"),
        };
        assert!(offsets.iter().any(|o| listed == base + o), "{name}: {listed} vs wall {base}");
    }
}

#[test]
fn zip_dos_times_are_unchanged_in_utc() {
    if !in_zone("zip_dos_times_are_unchanged_in_utc", "UTC") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("t.zip");
    fs::write(&archive, zip_members()).unwrap();
    for (name, listed, on_disk) in times(&archive) {
        let base = match name.as_str() {
            "winter" => wall(2024, 1, 15, 12, 0),
            "summer" => wall(2024, 7, 15, 12, 0),
            "gap" => wall(2024, 3, 10, 2, 30),
            "overlap" => wall(2024, 11, 3, 1, 30),
            other => panic!("{other}"),
        };
        assert_eq!((listed, on_disk), (base, base), "{name}");
    }
}

/// Members every two minutes from 00:00 to 05:00 on both 2024 Chicago change days. zipfast remembers the zone's
/// offset per hour, so this checks that no hour borrows its neighbour's offset across a change.
fn change_day_members() -> Vec<(String, (u16, u16))> {
    let mut members = Vec::new();
    for (month, day) in [(3, 10), (11, 3)] {
        for minute in (0..5 * 60).step_by(2) {
            let (hour, minute) = (minute / 60, minute % 60);
            members.push((format!("{month:02}-{day:02}-{hour:02}{minute:02}"), dos(2024, month, day, hour, minute)));
        }
    }
    members
}

#[test]
fn zip_dos_times_take_the_right_offset_on_each_side_of_a_change() {
    if !in_zone("zip_dos_times_take_the_right_offset_on_each_side_of_a_change", "America/Chicago") {
        return;
    }
    let named = change_day_members();
    let members: Vec<(&str, &[u8], u16, u16)> =
        named.iter().map(|(n, (t, d))| (n.as_str(), &b"x"[..], *t, *d)).collect();
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("t.zip");
    fs::write(&archive, zip(&members)).unwrap();
    let hour = 3600;
    let listed = times(&archive);
    assert_eq!(listed.len(), named.len());
    for (name, listed, on_disk) in listed {
        assert_eq!(listed, on_disk, "{name}: listing and extraction agree");
        let (month, rest) = name.split_at(2);
        let day: i64 = rest[1..3].parse().unwrap();
        let (h, m): (i64, i64) = (rest[4..6].parse().unwrap(), rest[6..8].parse().unwrap());
        let offset = listed - wall(2024, month.parse().unwrap(), day, h, m);
        // Standard time is UTC-6, daylight time UTC-5. In the hour that is skipped (March 02:xx) or repeated
        // (November 01:xx), mktime may resolve either way.
        let expected: &[i64] = match (month, h) {
            ("03", 0..=1) => &[6 * hour],
            ("03", 2) => &[5 * hour, 6 * hour],
            ("03", _) => &[5 * hour],
            ("11", 0) => &[5 * hour],
            ("11", 1) => &[5 * hour, 6 * hour],
            ("11", _) => &[6 * hour],
            _ => unreachable!(),
        };
        assert!(expected.contains(&offset), "{name}: offset {offset} s, expected one of {expected:?}");
    }
}

/// RAR 4.x DOS times are local wall clock too: the same archive lists one zone offset later in Chicago than in UTC.
#[test]
fn rar4_dos_times_follow_the_local_zone() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-rar300/solid_simple_rar300.rar");
    let mtimes = |tz: &str| -> Vec<i64> {
        if std::env::var_os(CHILD).is_some() {
            return Vec::new();
        }
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["rar4_print_mtimes", "--exact", "--nocapture", "--test-threads=1", "--ignored"])
            .env("TZ", tz)
            .env("ZIPFAST_DOS_TZ_PRINT", &fixture)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix("MTIME "))
            .map(|v| v.parse().unwrap())
            .collect()
    };
    let (utc, chicago) = (mtimes("UTC"), mtimes("America/Chicago"));
    assert!(!utc.is_empty() && utc.len() == chicago.len(), "{utc:?} {chicago:?}");
    for (u, c) in utc.iter().zip(&chicago) {
        assert!([5 * 3600, 6 * 3600].contains(&(c - u)), "{u} {c}");
    }
}

/// Prints the listed mtimes of the archive in `ZIPFAST_DOS_TZ_PRINT`; run by `rar4_dos_times_follow_the_local_zone`.
#[test]
#[ignore]
fn rar4_print_mtimes() {
    let Some(path) = std::env::var_os("ZIPFAST_DOS_TZ_PRINT") else { return };
    for entry in extract::list(Path::new(&path)).unwrap() {
        assert_eq!(entry.mtime_origin, Some(MtimeOrigin::LocalWallClock));
        println!("MTIME {}", entry.mtime.unwrap());
    }
}
