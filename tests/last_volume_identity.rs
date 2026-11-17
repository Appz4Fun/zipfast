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

//! A set's identity read from its last volume alone: only the last volume is opened.
mod common;

use common::FileSpec;
use std::path::Path;
use zipfast::map::*;

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(path)).unwrap()
}

fn identity(bytes: &[u8], name: &str) -> LastVolumeIdentity {
    last_volume_identity(HeldVolume::whole(bytes), MapOptions::new(name)).unwrap()
}

fn held<'a>(bytes: &'a [u8], head: usize, tail: usize) -> HeldVolume<'a> {
    let head = head.min(bytes.len());
    let tail = tail.min(bytes.len());
    HeldVolume::new(&bytes[..head], &bytes[bytes.len() - tail..], bytes.len() as u64).unwrap()
}

/// (name, size, CRC32) of each member of a whole-set map, in order.
fn keys(members: impl IntoIterator<Item = (Option<String>, Option<u64>, Option<u32>)>) -> Vec<(String, u64, u32)> {
    members.into_iter().map(|(n, s, c)| (n.unwrap(), s.unwrap(), c.unwrap_or(0))).collect()
}

fn map_keys(map: &MemberMap) -> Vec<(String, u64, u32)> {
    keys(map.members.iter().map(|m| (m.name.clone(), m.unpacked_size, m.checks.and_then(|c| c.crc32))))
}

fn identity_keys(id: &LastVolumeIdentity) -> Vec<(String, u64, u32)> {
    keys(id.members.iter().map(|m| (m.name.clone(), m.unpacked_size, m.checks.and_then(|c| c.crc32))))
}

// ---- RAR 4.x ----

#[test]
fn rar4_last_volume_names_its_set_position_and_ending_members() {
    let parts: Vec<Vec<u8>> = (1..=3).map(|i| fixture(&format!("rar4-volumes/multi.part{i}.rar"))).collect();
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let full = MemberMap::from_memory(&refs, "multi.part1.rar", None).unwrap();
    let last = &parts[2];

    let id = identity(last, "multi.part3.rar");
    assert_eq!(id.format, MapFormat::Rar4);
    assert_eq!(id.scope, IdentityScope::EndingHere);
    assert_eq!(id.is_last, Some(true));
    let SetFacts::Rar { volume, end_record } = &id.set else { panic!("{:?}", id.set) };
    assert!(volume.multi_volume && volume.new_naming && !volume.first_volume);
    let end = end_record.expect("the end header");
    assert_eq!(end.flags & 1, 0, "no volume follows");
    if let Some(number) = end.volume_number {
        assert_eq!(number, 2);
        assert_eq!((id.volume_number, id.volumes), (Some(2), Some(3)));
    }
    // Every member ending in the last volume carries the whole member's size and CRC, as the full map does.
    assert!(!id.members.is_empty());
    let full_keys = map_keys(&full);
    for key in identity_keys(&id) {
        assert!(full_keys.contains(&key), "{key:?} not in {full_keys:?}");
    }

    // Its first bytes (through its headers) and last bytes give the same identity.
    let headers_end = volume.members.iter().map(|m| m.header.end).max().unwrap() as usize;
    let cut = last_volume_identity(held(last, headers_end, 32), MapOptions::new("multi.part3.rar")).unwrap();
    assert_eq!(identity_keys(&cut), identity_keys(&id));
    assert_eq!((cut.is_last, cut.volume_number), (id.is_last, id.volume_number));
    let SetFacts::Rar { end_record: cut_end, .. } = &cut.set else { panic!() };
    assert_eq!(*cut_end, Some(end));

    // Without the last bytes the end header is not known.
    let head_only = last_volume_identity(held(last, headers_end, 0), MapOptions::new("multi.part3.rar")).unwrap();
    assert_eq!(head_only.is_last, None);
    assert_eq!(identity_keys(&head_only), identity_keys(&id));
}

// ---- RAR 5.0 ----

#[test]
fn rar5_first_article_of_the_last_volume_gives_the_final_size_and_crc() {
    let gold: Vec<u8> = (0..10_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let spec = FileSpec::new("big.bin", &gold);
    let volumes = common::volumes(&spec, 2600);
    let last = volumes.last().unwrap();

    for (head, tail) in [(last.len(), last.len()), (120, 16), (120, 0)] {
        let id = last_volume_identity(held(last, head, tail), MapOptions::new("big.part4.rar")).unwrap();
        assert_eq!(id.format, MapFormat::Rar5);
        assert_eq!(id.volume_number, Some(3));
        let [member] = id.members.as_slice() else { panic!("{:?}", id.members) };
        assert_eq!(member.name.as_deref(), Some("big.bin"));
        assert_eq!(member.unpacked_size, Some(gold.len() as u64));
        assert_eq!(member.checks.unwrap().crc32, Some(crc32fast::hash(&gold)));
        assert_eq!(member.split_before, Some(true));
        if tail == 0 {
            assert_eq!((id.is_last, id.volumes), (None, None));
        } else {
            assert_eq!((id.is_last, id.volumes), (Some(true), Some(4)));
            let SetFacts::Rar { end_record, .. } = &id.set else { panic!() };
            let end = end_record.unwrap();
            assert_eq!((end.flags, end.offset as usize), (0, last.len() - common::end_block(false).len()));
        }
    }

    // A middle volume: the member goes on, so nothing ends there, and the end header says so.
    let id = identity(&volumes[1], "big.part2.rar");
    assert!(id.members.is_empty());
    assert_eq!((id.volume_number, id.is_last, id.volumes), (Some(1), Some(false), None));
}

#[test]
fn rar5_tail_end_header_must_lie_after_the_headers_read() {
    let gold = vec![7u8; 3000];
    let spec = FileSpec::new("a.bin", &gold);
    let volumes = common::volumes(&spec, 1000);
    let last = volumes.last().unwrap();
    // A tail whose last bytes hold an end header claiming more volumes is still read: it is the volume's own.
    let id = last_volume_identity(held(last, 100, 20), MapOptions::new("a.part3.rar")).unwrap();
    assert_eq!(id.is_last, Some(true));
    // A corrupt end header is not taken.
    let mut bad = last.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    let id = last_volume_identity(held(&bad, 100, 20), MapOptions::new("a.part3.rar")).unwrap();
    assert_eq!(id.is_last, None);
}

// ---- ZIP ----

#[test]
fn split_zip_last_volume_lists_the_whole_set() {
    for name in ["stored", "deflated", "crypt"] {
        let mut volumes = Vec::new();
        for ext in ["z01", "z02", "z03"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/zip-split/{name}.{ext}"));
            if let Ok(bytes) = std::fs::read(path) {
                volumes.push(bytes);
            }
        }
        let last = fixture(&format!("zip-split/{name}.zip"));
        volumes.push(last.clone());
        let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
        let full = MemberMap::from_memory(&refs, format!("{name}.z01"), None).unwrap();

        let id = identity(&last, &format!("{name}.zip"));
        assert_eq!(id.format, MapFormat::Zip, "{name}");
        assert_eq!(id.scope, IdentityScope::WholeSet);
        let count = volumes.len() as u32;
        assert_eq!((id.volume_number, id.is_last, id.volumes), (Some(count - 1), Some(true), Some(count)), "{name}");
        assert_eq!(identity_keys(&id), map_keys(&full), "{name}");
        let SetFacts::Zip { end_at, directory, zip64, .. } = &id.set else { panic!() };
        assert!(!zip64);
        assert!(directory.end <= *end_at);

        // A tail too short for the directory says how much is needed, and that much is enough.
        let short = last_volume_identity(held(&last, 0, 22), MapOptions::new(format!("{name}.zip")));
        let Err(MapError::TailTooShort { from_end }) = short else { panic!("{name}: {short:?}") };
        // At least the directory, and at most the end records' window (64 KiB and a bit) or the volume.
        assert!(from_end >= last.len() as u64 - directory.start, "{name}");
        assert!(from_end <= (last.len() as u64).max(65_633), "{name}");
        let id =
            last_volume_identity(held(&last, 0, from_end as usize), MapOptions::new(format!("{name}.zip"))).unwrap();
        assert_eq!(identity_keys(&id), map_keys(&full), "{name}");
    }
}

/// A single-disk ZIP of stored members.
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let at = out.len() as u32;
        let crc = crc32fast::hash(data);
        let common = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes()); // version needed
            v.extend_from_slice(&0u16.to_le_bytes()); // flags
            v.extend_from_slice(&0u16.to_le_bytes()); // stored
            v.extend_from_slice(&0u32.to_le_bytes()); // DOS time and date
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        out.extend_from_slice(b"PK\x03\x04");
        common(&mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // made by
        common(&mut central);
        central.extend_from_slice(&[0; 6]); // comment length, disk, internal attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        central.extend_from_slice(&at.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let directory_at = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&directory_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn single_disk_zip_is_volume_zero_of_one() {
    let zip = stored_zip(&[("a.txt", b"hello"), ("b.txt", b"world!")]);
    let id = identity(&zip, "x.zip");
    assert_eq!((id.volume_number, id.volumes), (Some(0), Some(1)));
    let k = identity_keys(&id);
    assert_eq!(k[0], ("a.txt".into(), 5, crc32fast::hash(b"hello")));
    assert_eq!(k[1], ("b.txt".into(), 6, crc32fast::hash(b"world!")));
}

#[test]
fn split_zip_directory_on_an_earlier_volume_is_missing() {
    let mut last = fixture("zip-split/stored.zip");
    let n = last.len();
    // The end record's "disk where the directory starts" field: point it at disk 0.
    let at = n - 22 - usize::from(u16::from_le_bytes([last[n - 2], last[n - 1]]));
    last[at + 6..at + 8].copy_from_slice(&0u16.to_le_bytes());
    let result = last_volume_identity(HeldVolume::whole(&last), MapOptions::new("stored.zip"));
    assert!(matches!(result, Err(MapError::MissingDirectory { volume: 0 })), "{result:?}");
}

// ---- 7z ----

#[test]
fn seven_zip_last_split_volume_alone_lists_the_archive() {
    let first = fixture("7z/multi_volume.7z.001");
    let last = fixture("7z/multi_volume.7z.002");
    let full = MemberMap::from_memory(&[&first, &last], "multi_volume.7z.001", None).unwrap();

    let id = identity(&last, "multi_volume.7z.002");
    assert_eq!(id.format, MapFormat::SevenZip);
    assert_eq!(id.scope, IdentityScope::WholeSet);
    assert_eq!((id.volume_number, id.is_last), (None, Some(true)));
    assert_eq!(identity_keys(&id), map_keys(&full));
    let SetFacts::SevenZip { archive_offset, header, .. } = &id.set else { panic!() };
    assert_eq!(*archive_offset, first.len() as u64, "the volume starts where the first ends");
    assert_eq!(header.end, last.len() as u64);

    // The last bytes alone are enough when they hold the header (and an encoded header's packed stream).
    let from_end = (last.len() as u64 - header.start) as usize;
    let SetFacts::SevenZip { encoded, .. } = &id.set else { panic!() };
    let needed = if *encoded {
        let short = last_volume_identity(held(&last, 0, from_end), MapOptions::new("multi_volume.7z.002"));
        let Err(MapError::TailTooShort { from_end: n }) = short else { panic!("{short:?}") };
        n as usize
    } else {
        from_end
    };
    let id = last_volume_identity(held(&last, 0, needed), MapOptions::new("multi_volume.7z.002")).unwrap();
    assert_eq!(identity_keys(&id), map_keys(&full));
}

#[test]
fn seven_zip_archives_read_from_their_tail() {
    for name in [
        "store_method.7z",
        "store_method_enc_headers.7z",
        "store_with_directories.7z",
        "store_with_empty.7z",
        "solid_lzma_single.7z",
        "solid_lzma_multi.7z",
        "encrypted_files.7z",
        "multi_substreams_encrypted.7z",
        "lzma2_chunks.7z",
    ] {
        let bytes = fixture(&format!("7z/{name}"));
        let full = MemberMap::from_memory(&[&bytes], name, None).unwrap();
        // Only the tail: the signature header is not used.
        let tail = held(&bytes, 0, bytes.len() - 32);
        let id = last_volume_identity(tail, MapOptions::new(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let SetFacts::SevenZip { archive_offset, .. } = &id.set else { panic!() };
        assert_eq!(*archive_offset, 0, "{name}");
        let expect: Vec<_> = full
            .members
            .iter()
            .map(|m| (m.raw_name.clone(), m.is_dir, m.unpacked_size, m.checks.and_then(|c| c.crc32)))
            .collect();
        let got: Vec<_> = id
            .members
            .iter()
            .map(|m| (m.raw_name.clone(), m.is_dir, m.unpacked_size, m.checks.and_then(|c| c.crc32)))
            .collect();
        assert_eq!(got, expect, "{name}");
    }
}

#[test]
fn seven_zip_encrypted_header_needs_the_password() {
    let bytes = fixture("7z/encrypted_headers.7z");
    let tail = held(&bytes, 0, bytes.len() - 32);
    let result = last_volume_identity(tail, MapOptions::new("e.7z"));
    assert!(matches!(result, Err(MapError::PasswordRequired)), "{result:?}");
    let result = last_volume_identity(tail, MapOptions::new("e.7z").password(Some("wrong")));
    assert!(matches!(result, Err(MapError::WrongPassword)), "{result:?}");
    let id = last_volume_identity(tail, MapOptions::new("e.7z").password(Some("password"))).unwrap();
    let SetFacts::SevenZip { header_encrypted, encoded, .. } = &id.set else { panic!() };
    assert!(*header_encrypted && *encoded);
    assert_eq!(id.members[0].name.as_deref(), Some("7zFormat.txt"));
}

// ---- Hostile bytes ----

#[test]
fn noise_and_damaged_tails_are_refused_without_panicking() {
    let noise: Vec<u8> = (0..70_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    let result = last_volume_identity(HeldVolume::whole(&noise), MapOptions::new("x.bin"));
    assert!(matches!(result, Err(MapError::NotArchive)), "{result:?}");
    assert!(matches!(last_volume_identity(HeldVolume::whole(&[]), MapOptions::new("x")), Err(MapError::NotArchive)));

    // Every single-byte change in a 7z tail header, and every cut of a ZIP tail, ends in a result or a typed error.
    let last = fixture("7z/multi_volume.7z.002");
    let full = identity(&last, "m.7z.002");
    let SetFacts::SevenZip { header, .. } = &full.set else { panic!() };
    for i in header.start as usize..last.len() {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut bad = last.clone();
            bad[i] ^= flip;
            if let Ok(id) = last_volume_identity(HeldVolume::whole(&bad), MapOptions::new("m.7z.002")) {
                assert_eq!(id.format, MapFormat::SevenZip);
            }
        }
    }
    let zip = fixture("zip-split/deflated.zip");
    for cut in 0..zip.len() {
        let _ = last_volume_identity(held(&zip, 0, cut), MapOptions::new("d.zip"));
        let _ = last_volume_identity(HeldVolume::new(&[], &zip[..cut], cut as u64).unwrap(), MapOptions::new("d.zip"));
    }
}

#[test]
fn a_canceled_walk_stops() {
    let options = MapOptions::new("x.zip");
    options.control.cancel();
    let result = last_volume_identity(HeldVolume::whole(&fixture("zip-split/stored.zip")), options);
    assert!(matches!(result, Err(MapError::Source(_))), "{result:?}");
}

// ---- Review follow-ups ----

/// A 7z NUMBER.
fn num(v: u64, out: &mut Vec<u8>) {
    let mut n = 0;
    while n < 8 && v >= 1u64 << (7 * (n + 1)) {
        n += 1;
    }
    if n == 8 {
        out.push(0xff);
        out.extend_from_slice(&v.to_le_bytes());
        return;
    }
    out.push(((0xff00u16 >> n) as u8) | (v >> (8 * n)) as u8);
    out.extend_from_slice(&v.to_le_bytes()[..n]);
}

/// The unpack info of one Copy folder of `size` bytes, with its CRC when given.
fn copy_folder(size: u64, crc: Option<u32>, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C]);
    num(size, out);
    if let Some(crc) = crc {
        out.extend_from_slice(&[0x0A, 0x01]);
        out.extend_from_slice(&crc.to_le_bytes());
    }
    out.push(0x00);
}

/// A plain 7z header: one stored member `name` of `data`, its packed stream at pack position `pack_pos`.
fn plain_header(name: &str, data: &[u8], pack_pos: u64) -> Vec<u8> {
    let mut h = vec![0x01, 0x04, 0x06];
    num(pack_pos, &mut h);
    h.extend_from_slice(&[0x01, 0x09]);
    num(data.len() as u64, &mut h);
    h.push(0x00);
    copy_folder(data.len() as u64, Some(crc32fast::hash(data)), &mut h);
    h.push(0x00);
    let mut names = vec![0x00];
    for unit in name.encode_utf16() {
        names.extend_from_slice(&unit.to_le_bytes());
    }
    names.extend_from_slice(&[0, 0]);
    h.extend_from_slice(&[0x05, 0x01, 0x11]);
    num(names.len() as u64, &mut h);
    h.extend_from_slice(&names);
    h.extend_from_slice(&[0x00, 0x00]);
    h
}

/// A 7z archive: signature header, `data` as one Copy stream, then the header; encoded (a Copy folder over the plain
/// header, with or without its CRC) when `encoded` is Some.
fn seven(name: &str, data: &[u8], encoded: Option<bool>) -> Vec<u8> {
    let plain = plain_header(name, data, 0);
    let mut body = data.to_vec();
    let header = match encoded {
        None => plain,
        Some(with_crc) => {
            body.extend_from_slice(&plain);
            let mut h = vec![0x17, 0x06];
            num(data.len() as u64, &mut h);
            h.extend_from_slice(&[0x01, 0x09]);
            num(plain.len() as u64, &mut h);
            h.push(0x00);
            copy_folder(plain.len() as u64, with_crc.then(|| crc32fast::hash(&plain)), &mut h);
            h.push(0x00);
            h
        }
    };
    let mut start = Vec::new();
    start.extend_from_slice(&(body.len() as u64).to_le_bytes());
    start.extend_from_slice(&(header.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32fast::hash(&header).to_le_bytes());
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4];
    out.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(&body);
    out.extend_from_slice(&header);
    out
}

fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn a_plain_header_after_megabytes_of_random_data_is_found() {
    let data = noise(3 << 20, 0x5eed);
    let archive = seven("big.bin", &data, None);
    let full = MemberMap::from_memory(&[&archive], "big.7z", None).unwrap();
    assert_eq!(map_keys(&full), vec![("big.bin".into(), data.len() as u64, crc32fast::hash(&data))]);
    // The tail starts right after the signature header: every bogus candidate in the data is tried first.
    let id = last_volume_identity(held(&archive, 0, archive.len() - 32), MapOptions::new("big.7z")).unwrap();
    assert_eq!(identity_keys(&id), map_keys(&full));
    let SetFacts::SevenZip { archive_offset, encoded, .. } = &id.set else { panic!() };
    assert_eq!((*archive_offset, *encoded), (0, false));
}

#[test]
fn random_tails_are_not_archives() {
    for seed in 1..4 {
        let bytes = noise(2 << 20, seed);
        let result = last_volume_identity(HeldVolume::whole(&bytes), MapOptions::new("x.bin"));
        assert!(matches!(result, Err(MapError::NotArchive)), "seed {seed}: {result:?}");
    }
}

#[test]
fn an_encoded_header_without_a_folder_crc_is_not_taken() {
    let data = noise(5000, 9);
    let with_crc = seven("a.bin", &data, Some(true));
    assert_eq!(identity_keys(&identity(&with_crc[32..], "a.7z")).len(), 1);
    let without = seven("a.bin", &data, Some(false));
    // A whole-archive walk has the signature header's CRC; the tail does not.
    assert!(MemberMap::from_memory(&[&without], "a.7z", None).unwrap().complete);
    let result = last_volume_identity(HeldVolume::whole(&without[32..]), MapOptions::new("a.7z"));
    assert!(matches!(result, Err(MapError::NotArchive)), "{result:?}");
}

#[test]
fn a_rar_part_running_past_the_volume_is_dropped() {
    let gold = noise(5000, 3);
    let spec = FileSpec::new("a.bin", &gold);
    let mut bytes = common::SIG.to_vec();
    bytes.extend(common::main_block(true, Some(2)));
    bytes.extend(common::file_block(&spec, &gold, crc32fast::hash(&gold), true, false));
    // The volume is said to be 1000 bytes long, but the part's data runs to 5000 and more.
    let head = &bytes[..200];
    let id = last_volume_identity(HeldVolume::new(head, &[], 1000).unwrap(), MapOptions::new("a.part3.rar")).unwrap();
    assert!(id.members.is_empty(), "{:?}", id.members);
    let SetFacts::Rar { volume, .. } = &id.set else { panic!() };
    assert!(volume.members.is_empty());
    // With the true length it is listed.
    let id =
        last_volume_identity(HeldVolume::new(head, &[], bytes.len() as u64).unwrap(), MapOptions::new("a.part3.rar"))
            .unwrap();
    assert_eq!(identity_keys(&id), vec![("a.bin".into(), gold.len() as u64, crc32fast::hash(&gold))]);
}

#[test]
fn a_rar5_locator_past_the_volume_is_dropped() {
    let main_with_locator = |quick_open: u64| {
        let mut record = vec![0x01, 0x01];
        common::vint(quick_open, &mut record);
        let mut extra = Vec::new();
        common::vint(record.len() as u64, &mut extra);
        extra.extend_from_slice(&record);
        let mut fields = Vec::new();
        common::vint(1 | 2, &mut fields);
        common::vint(1, &mut fields);
        common::block(1, 0, &fields, &extra, &[], false)
    };
    for (quick_open, kept) in [(10, true), (1 << 40, false)] {
        let mut bytes = common::SIG.to_vec();
        bytes.extend(main_with_locator(quick_open));
        bytes.extend(common::end_block(false));
        let id = identity(&bytes, "x.part2.rar");
        let SetFacts::Rar { volume, .. } = &id.set else { panic!() };
        assert_eq!(volume.locator.is_some(), kept, "{quick_open}: {:?}", volume.locator);
        if kept {
            assert_eq!(volume.locator.unwrap().quick_open, Some(10));
        }
    }
}
