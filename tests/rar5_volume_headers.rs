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

//! `rar5::rebuild_volume_headers`: every volume of rar 7.30 volume sets rebuilt from its siblings' headers and
//! compared byte for byte with the real volume.
//!
//! The committed sets (`tests/fixtures/rar5-volume-headers/*.frames`) keep each volume's bytes before and after its
//! packed data, its length and its part's hashes: the rebuild never reads packed data. The full sets they come from
//! (and RustyGet's z-fixture sets, with `ZIPFAST_Z_FIXTURES`) are checked when present.

use std::path::{Path, PathBuf};

use zipfast::rar5::frame::{read_block, read_vint};
use zipfast::rar5::{
    HashKind, PartHashes, TargetVolume, VolumeFrame, VolumeHeadersError, rebuild_volume_headers,
    rebuild_volume_headers_from,
};

const FRAMES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar5-volume-headers");

/// A file header as the test reads it.
#[derive(Clone, Debug)]
struct File {
    name: String,
    split_before: bool,
    split_after: bool,
    crc32: Option<u32>,
    blake2sp: Option<[u8; 32]>,
    encrypted: bool,
    stored: bool,
    data_len: u64,
}

/// One volume of a set.
#[derive(Clone, Debug)]
struct Volume {
    name: String,
    len: u64,
    /// The files in it, in order, with their packed data length in this volume.
    files: Vec<File>,
    /// For a volume holding one file: the bytes before and after its packed data, and that data's hashes.
    head: Vec<u8>,
    tail: Vec<u8>,
    part: PartHashes,
    /// Whether the set has encrypted headers (nothing is parsed then).
    encrypted_headers: bool,
}

impl Volume {
    fn single(&self) -> Option<&File> {
        (self.files.len() == 1).then(|| &self.files[0])
    }
}

/// The file header block `block` of `bytes`.
fn file(bytes: &[u8], block: &zipfast::rar5::frame::Block) -> File {
    let f = &bytes[block.fields.clone()];
    let mut p = 0;
    let mut next = || {
        let (v, n) = read_vint(f, p).unwrap();
        p += n;
        v
    };
    let file_flags = next();
    next(); // unpacked size
    next(); // attributes
    if file_flags & 0x2 != 0 {
        p += 4;
    }
    let crc32 = (file_flags & 0x4 != 0).then(|| {
        let v = u32::from_le_bytes(f[p..p + 4].try_into().unwrap());
        p += 4;
        v
    });
    let (compression, n) = read_vint(f, p).unwrap();
    p += n;
    let (_, n) = read_vint(f, p).unwrap(); // host OS
    p += n;
    let (name_len, n) = read_vint(f, p).unwrap();
    p += n;
    let name = String::from_utf8_lossy(&f[p..p + name_len as usize]).into_owned();
    let extra = &bytes[block.extra.clone()];
    let (mut blake2sp, mut encrypted) = (None, false);
    let mut q = 0;
    while q < extra.len() {
        let (size, n) = read_vint(extra, q).unwrap();
        let record = &extra[q + n..q + n + size as usize];
        let (kind, k) = read_vint(record, 0).unwrap();
        match kind {
            1 => encrypted = true,
            2 => blake2sp = Some(record[k + 1..k + 33].try_into().unwrap()),
            _ => {}
        }
        q += n + size as usize;
    }
    File {
        name,
        split_before: block.flags & 0x8 != 0,
        split_after: block.flags & 0x10 != 0,
        crc32,
        blake2sp,
        encrypted,
        stored: (compression >> 7) & 7 == 0,
        data_len: block.data_len,
    }
}

/// A whole volume read from disk.
fn read_volume(path: &Path) -> Volume {
    let bytes = std::fs::read(path).unwrap();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let mut volume = Volume {
        name,
        len: bytes.len() as u64,
        files: Vec::new(),
        head: Vec::new(),
        tail: Vec::new(),
        part: PartHashes::default(),
        encrypted_headers: false,
    };
    let mut at = 8;
    let mut first_data = None;
    while let Ok(Some(block)) = read_block(&bytes, at) {
        match block.kind {
            2 => {
                volume.files.push(file(&bytes, &block));
                first_data.get_or_insert(block.header_end..block.header_end + block.data_len as usize);
            }
            4 => {
                volume.encrypted_headers = true;
                break;
            }
            5 => break,
            _ => {}
        }
        at = block.header_end + block.data_len as usize;
    }
    match first_data {
        Some(data) if !volume.encrypted_headers => {
            // Cut around the first file's data: for a volume holding more than one file, its tail starts with the
            // next file header, which the rebuild must refuse in a sibling.
            if volume.files.len() == 1 {
                volume.part = PartHashes::of_bytes(&bytes[data.clone()]);
            }
            volume.head = bytes[..data.start].to_vec();
            volume.tail = bytes[data.end..].to_vec();
        }
        _ => volume.head = bytes[..bytes.len().min(256)].to_vec(),
    }
    volume
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The `.frames` lines of a set: per single-file volume `name len crc32 blake2sp head tail`; per other volume
/// `name len - files`, its files as `name:data_len`.
fn frames_text(volumes: &[Volume]) -> String {
    let mut out = String::new();
    for v in volumes {
        match v.single() {
            Some(_) if !v.encrypted_headers => out.push_str(&format!(
                "{} {} {:08x} {} {} {}\n",
                v.name,
                v.len,
                v.part.crc32.unwrap(),
                hex(&v.part.blake2sp.unwrap()),
                hex(&v.head),
                hex(&v.tail)
            )),
            _ => {
                let files: Vec<String> = v.files.iter().map(|f| format!("{}:{}", f.name, f.data_len)).collect();
                let files = if files.is_empty() { "none".to_string() } else { files.join(",") };
                let tail = &v.tail[..v.tail.len().min(512)];
                out.push_str(&format!("{} {} - {} {} {}\n", v.name, v.len, files, hex(&v.head), hex(tail)));
            }
        }
    }
    out
}

/// A committed set.
fn read_frames(path: &Path) -> Vec<Volume> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .map(|line| {
            let w: Vec<&str> = line.split(' ').collect();
            let len = w[1].parse().unwrap();
            if w[2] == "-" {
                let files: Vec<File> = w[3]
                    .split(',')
                    .filter(|e| *e != "none")
                    .map(|e| {
                        let (name, data) = e.rsplit_once(':').unwrap();
                        File {
                            name: name.into(),
                            split_before: true,
                            split_after: true,
                            crc32: None,
                            blake2sp: None,
                            encrypted: false,
                            stored: false,
                            data_len: data.parse().unwrap(),
                        }
                    })
                    .collect();
                return Volume {
                    name: w[0].into(),
                    len,
                    encrypted_headers: w[3] == "none",
                    files,
                    head: unhex(w[4]),
                    tail: unhex(w[5]),
                    part: PartHashes::default(),
                };
            }
            let head = unhex(w[4]);
            let mut block = read_block(&head, 8).unwrap().unwrap();
            while block.kind != 2 {
                block = read_block(&head, block.data_end().unwrap() as usize).unwrap().unwrap();
            }
            let file = file(&head, &block);
            Volume {
                name: w[0].into(),
                len,
                files: vec![file],
                part: PartHashes {
                    crc32: Some(u32::from_str_radix(w[2], 16).unwrap()),
                    blake2sp: Some(unhex(w[3]).try_into().unwrap()),
                },
                head,
                tail: unhex(w[5]),
                encrypted_headers: false,
            }
        })
        .collect()
}

/// What checking a set found.
#[derive(Debug, Default)]
struct Tally {
    exact: usize,
    refused: Vec<String>,
}

/// The target description of volume `t` of `set`, as a downloader holding its borrowed data knows it.
fn target(set: &[Volume], t: usize, data_len: bool) -> TargetVolume {
    let v = &set[t];
    let f = v.single().unwrap();
    // The part's packed offset in its member: the member's parts in the volumes before.
    let mut offset = 0u64;
    for earlier in set[..t].iter().rev() {
        let Some(g) = earlier.files.last().filter(|g| g.name == f.name) else { break };
        offset += g.data_len;
        if earlier.files.len() > 1 || !g.split_before {
            break;
        }
    }
    let hashes = if f.split_after {
        v.part
    } else {
        // The last part records the whole file's hashes: the caller has them from another copy of the file.
        PartHashes { crc32: f.crc32, blake2sp: f.blake2sp }
    };
    TargetVolume {
        index: t as u64,
        volume_len: v.len,
        last: t + 1 == set.len(),
        hashes,
        data_len: data_len.then_some(f.data_len),
        packed_offset: f.stored.then_some(offset),
    }
}

/// Rebuilds volume `t` of `set` from sibling `s` and checks the outcome: exact bytes, or a refusal of the kind the
/// pair calls for.
fn check(set_name: &str, set: &[Volume], t: usize, s: usize, tally: &mut Tally) {
    let (tv, sv) = (&set[t], &set[s]);
    let label = format!("{set_name}: {} from {}", tv.name, sv.name);
    if sv.encrypted_headers {
        let target =
            TargetVolume { index: t as u64, volume_len: tv.len, last: t + 1 == set.len(), ..Default::default() };
        let got = rebuild_volume_headers(&sv.head, &sv.tail, &target);
        assert!(matches!(got, Err(VolumeHeadersError::EncryptedHeaders)), "{label}: {got:?}");
        tally.refused.push(format!("{label}: encrypted headers"));
        return;
    }
    let sibling_ok = sv.single().is_some();
    let Some(tf) = tv.single() else {
        // A volume holding the end of one member and the start of the next: with the stored member's packed offset
        // the layout check refuses it; otherwise the caller must not ask.
        if let (Some(sf), Some(first)) = (sv.single(), tv.files.first())
            && sibling_ok
            && sf.stored
            && first.name == sf.name
            && !tv.encrypted_headers
        {
            let mut offset = 0;
            for earlier in set[..t].iter().rev() {
                let Some(g) = earlier.files.last().filter(|g| g.name == first.name) else { break };
                offset += g.data_len;
                if earlier.files.len() > 1 || !g.split_before {
                    break;
                }
            }
            let target = TargetVolume {
                index: t as u64,
                volume_len: tv.len,
                last: t + 1 == set.len(),
                hashes: sv.part,
                data_len: None,
                packed_offset: Some(offset),
            };
            match rebuild_volume_headers(&sv.head, &sv.tail, &target) {
                Err(VolumeHeadersError::LayoutDiffers(_) | VolumeHeadersError::FirstVolumeUnproven) => {
                    tally.refused.push(format!("{label}: layout"))
                }
                other => panic!("{label}: a volume holding two members gave {other:?}"),
            }
        }
        return;
    };
    if sibling_ok && sv.single().unwrap().name != tf.name {
        return; // another member: the caller must not ask
    }
    for data_len in [true, false] {
        let target = target(set, t, data_len);
        let got = rebuild_volume_headers(&sv.head, &sv.tail, &target);
        let expected_refusal: Option<fn(&VolumeHeadersError) -> bool> = if sv.encrypted_headers {
            Some(|e| matches!(e, VolumeHeadersError::EncryptedHeaders))
        } else if is_rr(sv) {
            Some(|e| matches!(e, VolumeHeadersError::RecoveryRecord))
        } else if sv.single().is_none() {
            Some(|e| matches!(e, VolumeHeadersError::LayoutDiffers(_) | VolumeHeadersError::PerVolumeRecord(_)))
        } else if has_comment(sv) {
            Some(|e| matches!(e, VolumeHeadersError::PerVolumeRecord(_)))
        } else if t == 0 && t + 1 != set.len() && (!data_len || s + 1 == set.len()) {
            Some(|e| matches!(e, VolumeHeadersError::FirstVolumeUnproven))
        } else if t == 0 && has_comment(tv) {
            // The comment in the first volume shows as packed data shorter than the room the volume leaves.
            Some(|e| matches!(e, VolumeHeadersError::SizeMismatch { .. }))
        } else if !tf.split_after && tf.encrypted {
            Some(|e| matches!(e, VolumeHeadersError::EncryptedFinalPart))
        } else if !data_len && tf.data_len <= 4096 && sv.single().unwrap().data_len > 4096 && quick_open(sv) {
            // A small part's quick open data depends on the set's mode, which a large sibling part does not show.
            Some(|e| matches!(e, VolumeHeadersError::QuickOpenMode | VolumeHeadersError::ReserveUnknown))
        } else if s + 1 == set.len() && t + 1 != set.len() && !data_len {
            Some(|e| matches!(e, VolumeHeadersError::ReserveUnknown))
        } else {
            None
        };
        match (got, expected_refusal) {
            (Ok(frame), None) => {
                assert_frame(&label, &frame, tv);
                tally.exact += 1;
            }
            (Ok(frame), Some(_)) => {
                // Not expected to be provable: if it is claimed anyway it must still be right.
                assert_frame(&label, &frame, tv);
                panic!("{label}: expected a refusal, rebuilt exactly");
            }
            (Err(e), Some(expected)) => {
                assert!(expected(&e), "{label} (data_len {data_len}): refused with {e:?}");
                tally.refused.push(format!("{label}: {e}"));
            }
            (Err(e), None) => panic!("{label} (data_len {data_len}): {e:?}"),
        }
    }
}

fn is_rr(v: &Volume) -> bool {
    zipfast::rar5::frame::MainHeader::parse(&v.head[8..]).is_ok_and(|m| m.archive_flags & 0x8 != 0)
}

fn quick_open(v: &Volume) -> bool {
    zipfast::rar5::frame::MainHeader::parse(&v.head[8..])
        .is_ok_and(|m| m.locator.is_some_and(|l| l.quick_open.is_some()))
}

fn has_comment(v: &Volume) -> bool {
    // A service header between the main and file headers.
    let main = read_block(&v.head, 8).unwrap().unwrap();
    read_block(&v.head, main.header_end).ok().flatten().is_some_and(|b| b.kind == 3)
}

fn assert_frame(label: &str, frame: &VolumeFrame, real: &Volume) {
    assert_eq!(hex(&frame.head), hex(&real.head), "{label}: head");
    assert_eq!(frame.data_offset, real.head.len() as u64, "{label}");
    assert_eq!(frame.data_len, real.single().unwrap().data_len, "{label}");
    assert_eq!(hex(&frame.tail), hex(&real.tail), "{label}: tail");
    assert_eq!(frame.data_offset + frame.data_len + frame.tail.len() as u64, real.len, "{label}");
    assert!(frame.tail[frame.tail.len() - frame.padding as usize..].iter().all(|&b| b == 0), "{label}");
}

/// Checks every volume of `set` against siblings: all of them, or (`neighbours`) the volumes next to it and the
/// first and last.
fn check_set(set_name: &str, set: &[Volume], neighbours: bool) -> Tally {
    let mut tally = Tally::default();
    let n = set.len();
    for t in 0..n {
        let siblings: Vec<usize> = if neighbours {
            let mut s = vec![t.wrapping_sub(1), t + 1, 0, 1, n - 1, n - 2];
            s.retain(|&s| s < n && s != t);
            s.sort();
            s.dedup();
            s
        } else {
            (0..n).filter(|&s| s != t).collect()
        };
        for s in siblings {
            check(set_name, set, t, s, &mut tally);
        }
    }
    tally
}

fn committed_sets() -> Vec<(String, Vec<Volume>)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(FRAMES)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "frames"))
        .collect();
    paths.sort();
    paths.into_iter().map(|p| (p.file_stem().unwrap().to_string_lossy().into_owned(), read_frames(&p))).collect()
}

/// Every volume of every committed rar-made set, rebuilt from every sibling (neighbours in the 175-volume set):
/// byte for byte, or refused for the reason the pair calls for.
#[test]
fn every_volume_of_the_committed_sets_rebuilds_from_its_siblings() {
    let sets = committed_sets();
    assert!(sets.len() >= 12, "{}", sets.len());
    let mut total = 0;
    for (name, set) in &sets {
        let tally = check_set(name, set, set.len() > 40);
        eprintln!("{name}: {} exact, {} refused", tally.exact, tally.refused.len());
        let floor = match name.as_str() {
            "hp" | "rr" => 0,
            _ => set.len(),
        };
        assert!(tally.exact >= floor, "{name}: only {} exact: {:#?}", tally.exact, tally.refused);
        total += tally.exact;
    }
    assert!(total > 1500, "{total}");
}

/// The set's member hash records: CRC32 sets record the part CRC32 of a continuing part, `-htb` sets its BLAKE2sp.
#[test]
fn a_continuing_part_records_the_hashes_of_its_packed_bytes() {
    let sets = committed_sets();
    let (_, stored) = sets.iter().find(|(n, _)| n == "stored").unwrap();
    let f = stored[1].single().unwrap();
    assert_eq!(f.crc32, stored[1].part.crc32);
    let (_, blake) = sets.iter().find(|(n, _)| n == "storedb").unwrap();
    let f = blake[1].single().unwrap();
    assert_eq!((f.crc32, f.blake2sp), (None, blake[1].part.blake2sp));
}

/// Missing hashes, sizes that do not add up, a layout contradicted by the packed offset, a target that is the
/// sibling: typed refusals.
#[test]
fn what_cannot_be_proven_is_refused() {
    let sets = committed_sets();
    let (_, set) = sets.iter().find(|(n, _)| n == "stored").unwrap();
    let (_, blake) = sets.iter().find(|(n, _)| n == "storedb").unwrap();
    let sib = &set[3];
    let base = target(set, 4, true);
    let refuse = |sib: &Volume, t: TargetVolume| rebuild_volume_headers(&sib.head, &sib.tail, &t).unwrap_err();
    assert!(matches!(
        refuse(sib, TargetVolume { hashes: PartHashes::default(), ..base }),
        VolumeHeadersError::MissingHash(HashKind::Crc32)
    ));
    let bbase = target(blake, 4, true);
    assert!(matches!(
        refuse(&blake[3], TargetVolume { hashes: PartHashes { crc32: Some(1), blake2sp: None }, ..bbase }),
        VolumeHeadersError::MissingHash(HashKind::Blake2sp)
    ));
    assert!(matches!(
        refuse(sib, TargetVolume { data_len: Some(base.data_len.unwrap() - 1), ..base }),
        VolumeHeadersError::SizeMismatch { .. }
    ));
    assert!(matches!(refuse(sib, TargetVolume { volume_len: 10, ..base }), VolumeHeadersError::SizeMismatch { .. }));
    assert!(matches!(
        refuse(sib, TargetVolume { volume_len: u64::MAX, data_len: None, ..base }),
        VolumeHeadersError::SizeMismatch { .. }
    ));
    // A stored member's packed offset saying the member would end (or overrun) in a middle volume.
    let unpacked = 150_000;
    assert!(matches!(
        refuse(sib, TargetVolume { packed_offset: Some(unpacked - 100), ..base }),
        VolumeHeadersError::LayoutDiffers(_)
    ));
    // ... or start in it, after the sibling's part.
    assert!(matches!(
        refuse(&set[2], TargetVolume { packed_offset: Some(0), ..base }),
        VolumeHeadersError::LayoutDiffers(_)
    ));
    assert!(matches!(refuse(sib, TargetVolume { index: 3, ..base }), VolumeHeadersError::LayoutDiffers(_)));
    // The last volume as the target before its sibling, and a target past the set's last volume.
    let last = target(set, set.len() - 1, true);
    assert!(matches!(refuse(sib, TargetVolume { index: 2, ..last }), VolumeHeadersError::LayoutDiffers(_)));
    assert!(matches!(
        refuse(&set[set.len() - 1], TargetVolume { index: set.len() as u64, ..last }),
        VolumeHeadersError::LayoutDiffers(_)
    ));
    // Not RAR 5.0, truncated, damaged.
    assert!(matches!(
        refuse(&Volume { head: b"Rar!\x1a\x07\x00".to_vec(), ..sib.clone() }, base),
        VolumeHeadersError::NotRar5
    ));
    assert!(matches!(
        refuse(&Volume { head: sib.head[..sib.head.len() - 3].to_vec(), ..sib.clone() }, base),
        VolumeHeadersError::Truncated
    ));
    let mut bad = sib.clone();
    let at = bad.head.len() - 5;
    bad.head[at] ^= 1;
    assert!(matches!(refuse(&bad, base), VolumeHeadersError::Corrupt(_)));
    // Tail holding more than the quick open data and end header.
    let mut extra = sib.clone();
    extra.tail.extend_from_slice(&[0, 0, 0, 1]);
    assert!(matches!(refuse(&extra, base), VolumeHeadersError::PerVolumeRecord(_) | VolumeHeadersError::Corrupt(_)));
}

/// The reader form reads the sibling's headers and tail and skips its data.
#[test]
fn a_sibling_read_from_a_reader_gives_the_same_frame() {
    let sets = committed_sets();
    let (_, set) = sets.iter().find(|(n, _)| n == "compb").unwrap();
    let sib = &set[2];
    let data_len = sib.single().unwrap().data_len as usize;
    let mut whole = sib.head.clone();
    whole.resize(whole.len() + data_len, 0xa5);
    whole.extend_from_slice(&sib.tail);
    let t = target(set, 3, true);
    let from_reader = rebuild_volume_headers_from(&mut std::io::Cursor::new(&whole), &t).unwrap();
    assert_eq!(from_reader, rebuild_volume_headers(&sib.head, &sib.tail, &t).unwrap());
    assert_frame("compb reader", &from_reader, &set[3]);
    // Cut anywhere, the reader form refuses without panicking.
    for cut in (0..whole.len()).step_by(997).chain(whole.len() - 9..whole.len()) {
        assert!(rebuild_volume_headers_from(&mut std::io::Cursor::new(&whole[..cut]), &t).is_err(), "{cut}");
    }
}

/// Hostile siblings never panic: every single-byte change and every truncation of a sibling's head and tail.
#[test]
fn hostile_siblings_never_panic() {
    let sets = committed_sets();
    for name in ["stored", "storedb", "passb", "many"] {
        let (_, set) = sets.iter().find(|(n, _)| n == name).unwrap();
        let sib = &set[1];
        let t = target(set, 2, true);
        for i in 0..sib.head.len() + sib.tail.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let (mut head, mut tail) = (sib.head.clone(), sib.tail.clone());
                if i < head.len() {
                    head[i] ^= flip;
                } else {
                    tail[i - head.len()] ^= flip;
                }
                if let Ok(frame) = rebuild_volume_headers(&head, &tail, &t) {
                    // A change the rebuild cannot see (padding in the sibling's tail is checked, so only bytes it
                    // copies verbatim, resealed): the frame is still self-consistent.
                    assert_eq!(frame.data_offset + frame.data_len + frame.tail.len() as u64, t.volume_len);
                }
            }
        }
        for cut in 0..sib.head.len() {
            let _ = rebuild_volume_headers(&sib.head[..cut], &sib.tail, &t);
        }
        for cut in 0..sib.tail.len() {
            let _ = rebuild_volume_headers(&sib.head, &sib.tail[..cut], &t);
        }
        for volume_len in [0, 1, 100, t.volume_len - 1, t.volume_len + 1, u64::MAX / 2, u64::MAX] {
            for data_len in [None, Some(0), Some(u64::MAX)] {
                let _ = rebuild_volume_headers(&sib.head, &sib.tail, &TargetVolume { volume_len, data_len, ..t });
            }
        }
        for index in [0, 1, u64::MAX] {
            let _ = rebuild_volume_headers(&sib.head, &sib.tail, &TargetVolume { index, ..t });
        }
    }
}

/// The full rar-made sets, outside the repository: `ZIPFAST_RAR5_VOLUME_HEADER_SETS`, or the default fixtures path.
fn full_sets() -> Option<PathBuf> {
    let dir = std::env::var_os("ZIPFAST_RAR5_VOLUME_HEADER_SETS").map(PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|h| Path::new(&h).join("git.xbmc4lyfe/zipfast-test-fixtures/rar5-volume-headers"))
    })?;
    dir.is_dir().then_some(dir)
}

fn read_set(dir: &Path) -> Vec<Volume> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "rar"))
        .collect();
    paths.sort();
    paths.iter().map(|p| read_volume(p)).collect()
}

/// Every volume of the full sets (the committed ones' sources, two larger ones, and with `ZIPFAST_Z_FIXTURES`
/// RustyGet's z-fixture RAR 5.0 sets), hashes computed from the real packed data. With
/// `ZIPFAST_WRITE_VOLUME_FRAMES=1` it writes the committed `.frames` files from the full sets.
#[test]
fn every_volume_of_the_full_sets_rebuilds_from_its_neighbours() {
    let Some(dir) = full_sets() else {
        eprintln!("skipped: no full sets (set ZIPFAST_RAR5_VOLUME_HEADER_SETS)");
        return;
    };
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    // The volume tail sets (100 KB volumes: quick open modes, small pieces, several files per volume).
    let tail_sets =
        std::env::var_os("ZIPFAST_RAR5_TAIL_SETS").map(PathBuf::from).unwrap_or_else(|| dir.join("../rar5-tail"));
    if tail_sets.is_dir() {
        dirs.extend(std::fs::read_dir(tail_sets).unwrap().map(|e| e.unwrap().path()));
    }
    if let Some(z) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(PathBuf::from) {
        dirs.extend(
            std::fs::read_dir(z)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.file_name().unwrap().to_string_lossy().contains("_rar5_")),
        );
    }
    dirs.sort();
    let write = std::env::var_os("ZIPFAST_WRITE_VOLUME_FRAMES").is_some();
    for set_dir in dirs.iter().filter(|d| d.is_dir()) {
        let name = set_dir.file_name().unwrap().to_string_lossy().into_owned();
        let set = read_set(set_dir);
        if set.is_empty() {
            continue;
        }
        let tally = check_set(&name, &set, true);
        eprintln!("{name}: {} volumes, {} exact, {} refused", set.len(), tally.exact, tally.refused.len());
        if write && set_dir.parent() == Some(dir.as_path()) && !name.starts_with("big") {
            std::fs::write(Path::new(FRAMES).join(format!("{name}.frames")), frames_text(&set)).unwrap();
        }
    }
}
