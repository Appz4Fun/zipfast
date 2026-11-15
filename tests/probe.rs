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

//! Probing a first article: bare media, RAR and ZIP packing, and the borrowable verdict.
mod common;

use common::{FileSpec, SIG, archive, block, end_block, file_block, main_block};
use zipfast::map::{CipherParams, MapMethod, OutputMapping, VolumeEnd};
use zipfast::probe::*;

// ---- Synthetic media headers ----

fn pad(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    bytes.extend((bytes.len()..len).map(|i| (i * 7 % 251) as u8));
    bytes
}

fn ebml(doctype: &[u8]) -> Vec<u8> {
    let mut body = vec![0x42, 0x86, 0x81, 1, 0x42, 0xf7, 0x81, 1, 0x42, 0xf2, 0x81, 4, 0x42, 0xf3, 0x81, 8];
    body.extend([0x42, 0x82, 0x80 | doctype.len() as u8]);
    body.extend(doctype);
    body.extend([0x42, 0x87, 0x81, 4, 0x42, 0x85, 0x81, 2]);
    let mut out = vec![0x1a, 0x45, 0xdf, 0xa3, 0x80 | body.len() as u8];
    out.extend(body);
    out.extend([0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pad(out, 4096)
}

fn mkv() -> Vec<u8> {
    ebml(b"matroska")
}

fn iso(brand: &[u8; 4]) -> Vec<u8> {
    let mut out = 24u32.to_be_bytes().to_vec();
    out.extend(b"ftyp");
    out.extend(brand);
    out.extend(0x200u32.to_be_bytes());
    out.extend(brand);
    out.extend(b"iso2");
    out.extend(16u32.to_be_bytes());
    out.extend(b"free");
    out.extend([0; 8]);
    out.extend(1000u32.to_be_bytes());
    out.extend(b"mdat");
    pad(out, 4096)
}

fn quicktime_classic() -> Vec<u8> {
    let mut out = 8u32.to_be_bytes().to_vec();
    out.extend(b"wide");
    out.extend(5000u32.to_be_bytes());
    out.extend(b"mdat");
    pad(out, 4096)
}

fn avi() -> Vec<u8> {
    let mut out = b"RIFF".to_vec();
    out.extend(100_000u32.to_le_bytes());
    out.extend(b"AVI LIST");
    out.extend(1000u32.to_le_bytes());
    out.extend(b"hdrlavih");
    pad(out, 4096)
}

fn packets(stride: usize, offset: usize, count: usize) -> Vec<u8> {
    let mut out = vec![0x11; stride * count];
    for i in 0..count {
        out[i * stride + offset] = 0x47;
    }
    out
}

const ASF_GUID: [u8; 16] =
    [0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c];

fn asf() -> Vec<u8> {
    let mut out = ASF_GUID.to_vec();
    out.extend(5000u64.to_le_bytes());
    out.extend(6u32.to_le_bytes());
    out.extend([1, 2]);
    pad(out, 4096)
}

fn mpg() -> Vec<u8> {
    pad(vec![0, 0, 1, 0xba, 0x44, 0, 4, 0, 4, 1], 4096)
}

fn found(kind: MediaKind, confidence: Confidence) -> Option<MediaMatch> {
    Some(MediaMatch { kind, confidence })
}

#[test]
fn bare_media_kinds_are_recognised_from_their_first_bytes() {
    use Confidence::*;
    let cases: Vec<(Vec<u8>, MediaKind)> = vec![
        (mkv(), MediaKind::Mkv),
        (ebml(b"webm"), MediaKind::Webm),
        (iso(b"isom"), MediaKind::Mp4),
        (iso(b"M4V "), MediaKind::Mp4),
        (iso(b"qt  "), MediaKind::Mov),
        (quicktime_classic(), MediaKind::Mov),
        (avi(), MediaKind::Avi),
        (packets(188, 0, 20), MediaKind::MpegTs),
        (packets(192, 4, 20), MediaKind::M2ts),
        (asf(), MediaKind::Asf),
        (mpg(), MediaKind::MpegPs),
    ];
    for (bytes, kind) in cases {
        assert_eq!(sniff(&bytes), found(kind, Validated), "{kind:?}");
        let packing = probe(&bytes, None, None).unwrap();
        assert_eq!(packing, Packing::BareMedia(MediaMatch { kind, confidence: Validated }), "{kind:?}");
        assert_eq!(packing.borrowable(), Borrowable::Yes);
    }
    // A few packets are the magic, not validated; the EBML header without the Segment after it likewise.
    assert_eq!(sniff(&packets(188, 0, 4)), found(MediaKind::MpegTs, Magic));
    assert_eq!(sniff(&mkv()[..40]), found(MediaKind::Mkv, Magic));
    assert_eq!(sniff(&mkv()[..10]), found(MediaKind::Mkv, Magic));
}

#[test]
fn near_misses_are_not_media() {
    let mut not_ts = packets(188, 0, 20);
    not_ts[188 * 5] = 0x48;
    let mut wave = avi();
    wave[8..12].copy_from_slice(b"WAVE");
    let mut short_ftyp = iso(b"isom");
    short_ftyp[..4].copy_from_slice(&3u32.to_be_bytes());
    let mut binary_brand = iso(b"isom");
    binary_brand[8] = 0x01;
    let mut odd_ftyp = iso(b"isom");
    odd_ftyp[..4].copy_from_slice(&26u32.to_be_bytes());
    let mut bad_asf = asf();
    bad_asf[16..24].copy_from_slice(&10u64.to_le_bytes());
    let mut bad_ps = mpg();
    bad_ps[4] = 0xff;
    let mut not_atom = quicktime_classic();
    not_atom[12..16].copy_from_slice(b"\x01\x02\x03\x04");
    let misses: Vec<(&str, Vec<u8>)> = vec![
        ("a lone sync byte", vec![0x47]),
        ("a sync byte then noise", pad(vec![0x47], 4096)),
        ("two packets", packets(188, 0, 2)),
        ("a broken sync", not_ts),
        ("a lone m2ts sync", pad(vec![0, 0, 0, 0, 0x47], 4096)),
        ("RIFF WAVE", wave),
        ("EBML of another DocType", ebml(b"other")),
        ("an ftyp of 3 bytes", short_ftyp),
        ("a binary brand", binary_brand),
        ("an ftyp of odd length", odd_ftyp),
        ("an ASF header object too small", bad_asf),
        ("a pack header without marker bits", bad_ps),
        ("a wide atom followed by noise", not_atom),
        ("noise", pad(Vec::new(), 4096)),
        ("nothing", Vec::new()),
    ];
    for (what, bytes) in misses {
        assert_eq!(sniff(&bytes), None, "{what}");
        assert_eq!(probe(&bytes, None, None).unwrap(), Packing::Unknown, "{what}");
    }
    assert_eq!(Packing::Unknown.borrowable(), Borrowable::Unknown(Undecided::NotRecognised));
}

#[test]
fn media_kinds_by_name() {
    for (name, kind) in [
        ("a.mkv", MediaKind::Mkv),
        ("A.WEBM", MediaKind::Webm),
        ("x/b.m4v", MediaKind::Mp4),
        ("c.mov", MediaKind::Mov),
        ("d.avi", MediaKind::Avi),
        ("e.ts", MediaKind::MpegTs),
        ("f.mts", MediaKind::M2ts),
        ("g.wmv", MediaKind::Asf),
        ("h.vob", MediaKind::MpegPs),
    ] {
        assert_eq!(media_kind_for_name(name), Some(kind), "{name}");
    }
    assert_eq!(media_kind_for_name("release.nfo"), None);
}

fn rar_of(packing: &Packing) -> &RarPacking {
    match packing {
        Packing::Rar(rar) => rar,
        other => panic!("not RAR: {other:?}"),
    }
}

fn zip_of(packing: &Packing) -> &ZipPacking {
    match packing {
        Packing::Zip(zip) => zip,
        other => panic!("not ZIP: {other:?}"),
    }
}

// ---- RAR 5.0 ----

#[test]
fn rar5_stored_plain_is_borrowable_and_its_media_sniffed() {
    let movie = mkv();
    let bytes = archive(&[FileSpec::new("movie.mkv", &movie)]);
    let packing = probe(&bytes, None, None).unwrap();
    let rar = rar_of(&packing);
    assert_eq!(rar.version, RarVersion::Rar5);
    assert!(rar.volume.known && rar.volume.first_volume && !rar.volume.multi_volume);
    assert_eq!(rar.volume.volume_number, Some(0));
    assert!(!rar.header_encrypted && !rar.locked);
    assert_eq!(rar.borrowable, Borrowable::Yes);
    let member = rar.first_media.as_ref().unwrap();
    assert_eq!(member.name.as_deref(), Some("movie.mkv"));
    assert_eq!(member.size, Some(movie.len() as u64));
    assert_eq!(member.packing, MemberPacking::Stored);
    assert_eq!(member.mapping, OutputMapping::Direct);
    assert_eq!(member.selected, Selection::Extension);
    assert_eq!(member.name_kind, Some(MediaKind::Mkv));
    assert_eq!(member.sniffed, found(MediaKind::Mkv, Confidence::Validated));
    let data = member.data.clone().unwrap();
    assert_eq!(&bytes[data.start as usize..data.end as usize], &movie[..]);
    assert!(!member.continued);

    // The first 2 KiB of the same archive: the member's data runs past the head and still sniffs.
    let packing = probe(&bytes[..2048], None, None).unwrap();
    let rar = rar_of(&packing);
    assert!(matches!(rar.map.end, VolumeEnd::Truncated { .. }));
    assert_eq!(rar.borrowable, Borrowable::Yes);
    assert_eq!(rar.first_media.as_ref().unwrap().media(), Some(MediaKind::Mkv));

    // Behind a self-extracting stub: found by the RAR scanner, offsets in the head's coordinates.
    let mut stubbed = b"MZ".to_vec();
    stubbed.resize(3000, 0x90);
    stubbed.extend(&bytes);
    let packing = probe(&stubbed, None, None).unwrap();
    let member = packing.first_media().unwrap();
    assert_eq!(member.data.as_ref().unwrap().start, data.start + 3000);
    assert_eq!(member.sniffed, found(MediaKind::Mkv, Confidence::Validated));

    // An obfuscated name: chosen by its magic.
    let bytes = archive(&[FileSpec::new("a8f3e0c1", &movie)]);
    let packing = probe(&bytes, None, None).unwrap();
    let member = packing.first_media().unwrap();
    assert_eq!(member.selected, Selection::Magic);
    assert_eq!(member.name_kind, None);
    assert_eq!(member.media(), Some(MediaKind::Mkv));
}

#[test]
fn an_nfo_before_the_mkv_does_not_win() {
    let movie = mkv();
    let nfo = b"release notes".to_vec();
    let bytes = archive(&[FileSpec::new("release.nfo", &nfo), FileSpec::new("movie.mkv", &movie)]);
    let packing = probe(&bytes, None, None).unwrap();
    let member = packing.first_media().unwrap();
    assert_eq!((member.index, member.name.as_deref()), (1, Some("movie.mkv")));
    assert_eq!(member.selected, Selection::Extension);
    assert_eq!(packing.borrowable(), Borrowable::Yes);

    // Nothing media by name or magic: the largest non-side member, first of equals.
    let big = vec![0u8; 5000];
    let bytes = archive(&[
        FileSpec::new("release.nfo", &big),
        FileSpec::new("disc.iso", &big[..4000]),
        FileSpec::new("extra.bin", &big[..4000]),
    ]);
    let member = probe(&bytes, None, None).unwrap().first_media().cloned().unwrap();
    assert_eq!((member.index, member.selected), (1, Selection::Largest));

    // Only side files in a complete listing: the largest of them.
    let bytes = archive(&[FileSpec::new("a.nfo", &big[..10]), FileSpec::new("b.sfv", &big[..20])]);
    let member = probe(&bytes, None, None).unwrap().first_media().cloned().unwrap();
    assert_eq!(member.name.as_deref(), Some("b.sfv"));

    // Only side files so far in a cut listing: undecided.
    let bytes = archive(&[FileSpec::new("a.nfo", &big[..10]), FileSpec::new("movie.mkv", &movie)]);
    let first_header = bytes.windows(9).position(|w| w == b"movie.mkv").unwrap() - 20;
    let packing = probe(&bytes[..first_header], None, None).unwrap();
    assert_eq!(packing.first_media(), None);
    assert_eq!(packing.borrowable(), Borrowable::Unknown(Undecided::Truncated));
}

const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let mut inner: Vec<u8> = padded.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(message);
    let mut outer: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&zipfast::crypto::sha256(&inner));
    zipfast::crypto::sha256(&outer)
}

fn password_check(password: &str, kdf_count: u8) -> [u8; 8] {
    let mut block = SALT.to_vec();
    block.extend(1u32.to_be_bytes());
    let mut u = hmac(password.as_bytes(), &block);
    let mut sum = u;
    for _ in 1..(1u32 << kdf_count) + 32 {
        u = hmac(password.as_bytes(), &u);
        sum.iter_mut().zip(u).for_each(|(s, b)| *s ^= b);
    }
    let mut folded = [0u8; 8];
    sum.iter().enumerate().for_each(|(i, b)| folded[i % 8] ^= b);
    folded
}

/// A RAR 5.0 archive with one stored member encrypted with "pw", with or without a password check value.
fn rar5_encrypted(name: &str, plain: &[u8], with_check: bool) -> Vec<u8> {
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
    let mut padded = plain.to_vec();
    padded.resize(plain.len().next_multiple_of(16), 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &IV, &padded).unwrap();
    let mut extra = vec![if with_check { 48 } else { 36 }, 1, 0, if with_check { 3 } else { 2 }, 1];
    extra.extend(SALT);
    extra.extend(IV);
    if with_check {
        let check = password_check("pw", 1);
        extra.extend(check);
        extra.extend(&zipfast::crypto::sha256(&check)[..4]);
    }
    let mut spec = FileSpec::new(name, &cipher);
    spec.size = Some(plain.len() as u64);
    spec.extra = extra;
    let crc = zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(plain), &hash_key);
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    bytes.extend(file_block(&spec, &cipher, crc, false, false));
    bytes.extend(end_block(false));
    bytes
}

#[test]
fn rar5_data_encrypted_with_and_without_the_password() {
    let movie = mkv();
    let bytes = rar5_encrypted("movie.mkv", &movie, true);

    let packing = probe(&bytes, None, None).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::NeedsPassword(PasswordNeed::DataEncrypted));
    let member = packing.first_media().unwrap();
    assert_eq!(member.packing, MemberPacking::DataEncrypted { cipher: CipherKind::Rar5Aes256, stored: true });
    assert_eq!(member.mapping, OutputMapping::CbcBlocks);
    assert!(matches!(member.cipher, Some(CipherParams::Rar5 { kdf_count: 1, iv: Some(IV), check: Some(_), .. })));
    assert_eq!(member.sniffed, None);

    let packing = probe(&bytes, None, Some("pw")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::YesWithPassword(PasswordProof::Verifier));
    assert_eq!(packing.first_media().unwrap().sniffed, found(MediaKind::Mkv, Confidence::Validated));

    let packing = probe(&bytes, None, Some("wrong")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::NeedsPassword(PasswordNeed::WrongPassword));

    // Without a check value the decrypted magic proves the password; noise proves nothing.
    let bytes = rar5_encrypted("movie.mkv", &movie, false);
    let packing = probe(&bytes, None, Some("pw")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::YesWithPassword(PasswordProof::Plaintext));
    let packing = probe(&bytes, None, Some("wrong")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::YesWithPassword(PasswordProof::Unverified));
    assert_eq!(packing.first_media().unwrap().sniffed, None);
}

const HP_PASSWORD: &str = "zipfast-test-only";
const HP_SALT: [u8; 16] = [0x53; 16];
const HP_CHECK: [u8; 12] = [0x17, 0x41, 0x9a, 0xfa, 0xa6, 0x98, 0xfd, 0x50, 0xa8, 0x4b, 0x9b, 0x32];

fn hp_archive(name: &str, payload: &[u8]) -> Vec<u8> {
    let iv = [0x49; 16];
    let key = zipfast::crypto::derive_rar5_key_and_hash_key(HP_PASSWORD, 4, &HP_SALT, None).unwrap().0;
    let params = [&[0, 1, 4], HP_SALT.as_slice(), HP_CHECK.as_slice()].concat();
    let mut bytes = SIG.to_vec();
    bytes.extend(block(4, 0, &params, &[], &[], false));
    let spec = FileSpec::new(name, payload);
    for (mut header, data) in [
        (main_block(false, None), b"".as_slice()),
        (file_block(&spec, payload, crc32fast::hash(payload), false, false), payload),
        (end_block(false), b"".as_slice()),
    ] {
        header.truncate(header.len() - data.len());
        header.resize(header.len().next_multiple_of(16), 0);
        bytes.extend(iv);
        bytes.extend(zipfast::crypto::encrypt_cbc(&key, &iv, &header).unwrap());
        bytes.extend(data);
    }
    bytes
}

#[test]
fn rar5_encrypted_headers_lock_without_the_password() {
    let movie = mkv();
    let bytes = hp_archive("movie.mkv", &movie);

    let packing = probe(&bytes, None, None).unwrap();
    let rar = rar_of(&packing);
    assert!(rar.header_encrypted && rar.locked && !rar.volume.known);
    assert_eq!(rar.first_media, None);
    assert_eq!(rar.borrowable, Borrowable::NeedsPassword(PasswordNeed::HeaderEncrypted));
    assert_eq!(probe(&bytes, None, Some("")).unwrap(), packing, "an empty password is none");

    let packing = probe(&bytes, None, Some(HP_PASSWORD)).unwrap();
    let rar = rar_of(&packing);
    assert!(rar.header_encrypted && !rar.locked && rar.volume.known);
    let member = rar.first_media.as_ref().unwrap();
    assert_eq!(member.name.as_deref(), Some("movie.mkv"));
    assert_eq!(member.sniffed, found(MediaKind::Mkv, Confidence::Validated));
    assert_eq!(rar.borrowable, Borrowable::YesWithPassword(PasswordProof::Headers));

    let packing = probe(&bytes, None, Some("wrong")).unwrap();
    let rar = rar_of(&packing);
    assert!(rar.locked && rar.first_media.is_none());
    assert_eq!(rar.borrowable, Borrowable::NeedsPassword(PasswordNeed::WrongPassword));
}

#[test]
fn a_head_cut_before_the_first_file_header_is_unknown() {
    let movie = mkv();
    let bytes = archive(&[FileSpec::new("movie.mkv", &movie)]);
    let cut = SIG.len() + main_block(false, None).len() + 5;
    let packing = probe(&bytes[..cut], None, None).unwrap();
    let rar = rar_of(&packing);
    assert!(rar.volume.known && rar.map.members.is_empty());
    assert_eq!(rar.first_media, None);
    assert_eq!(rar.borrowable, Borrowable::Unknown(Undecided::Truncated));
    // Cut inside the signature's main header: the format and nothing else.
    let packing = probe(&bytes[..SIG.len() + 2], None, None).unwrap();
    assert!(!rar_of(&packing).volume.known);
    assert_eq!(packing.borrowable(), Borrowable::Unknown(Undecided::Truncated));
}

#[test]
fn a_middle_volume_reports_its_place_and_the_continued_member() {
    let movie = pad(mkv(), 10_000);
    let volumes = common::volumes(&FileSpec::new("movie.mkv", &movie), 2600);
    assert_eq!(volumes.len(), 4);
    let head = &volumes[2][..2048];
    let packing = probe(head, None, None).unwrap();
    let rar = rar_of(&packing);
    assert_eq!(rar.volume.volume_number, Some(2));
    assert!(rar.volume.known && rar.volume.multi_volume && rar.volume.new_naming && !rar.volume.first_volume);
    let member = rar.first_media.as_ref().unwrap();
    assert!(member.continued);
    assert_eq!(member.name.as_deref(), Some("movie.mkv"));
    assert_eq!(member.size, Some(10_000));
    assert_eq!(member.packed_size, Some(2600));
    assert_eq!(member.sniffed, None, "a continuation does not start the file");
    assert_eq!(member.media(), Some(MediaKind::Mkv));
    assert_eq!(rar.borrowable, Borrowable::Yes);
}

#[test]
fn rar5_compressed_and_solid_are_not_borrowable() {
    let mut spec = FileSpec::new("movie.mkv", b"compressed stand-in");
    spec.method = 3;
    spec.size = Some(100_000);
    let bytes = archive(&[spec]);
    let packing = probe(&bytes, None, None).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::No(NotBorrowable::Compressed));
    assert_eq!(packing.first_media().unwrap().packing, MemberPacking::Compressed { method: 3, solid: false });

    let mut spec = FileSpec::new("movie.mkv", b"compressed stand-in");
    spec.method = 3;
    spec.size = Some(100_000);
    spec.solid = true;
    let bytes = archive(&[spec]);
    assert_eq!(probe(&bytes, None, None).unwrap().borrowable(), Borrowable::No(NotBorrowable::Solid));
}

// ---- RAR 4.x ----

fn r4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = crc32fast::hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn r4_member(name: &[u8], data: &[u8], flags: u16, method: u8, size: usize, salt: Option<[u8; 8]>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((size as u32).to_le_bytes());
    body.push(3);
    body.extend(0u32.to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([29, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut flags = flags | 0x8000;
    if let Some(salt) = salt {
        body.extend(salt);
        flags |= 0x404;
    }
    let mut bytes = r4_block(0x74, flags, &body);
    bytes.extend(data);
    bytes
}

fn r4_archive(files: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(r4_block(0x73, 0, &[0; 6]));
    for file in files {
        bytes.extend(file);
    }
    bytes.extend(r4_block(0x7b, 0x4000, &[]));
    bytes
}

#[test]
fn rar4_stored_compressed_and_encrypted() {
    let movie = mkv();
    let bytes = r4_archive(&[
        r4_member(b"release.nfo", b"notes", 0, 0x30, 5, None),
        r4_member(b"movie.mkv", &movie, 0, 0x30, movie.len(), None),
    ]);
    let packing = probe(&bytes, None, None).unwrap();
    let rar = rar_of(&packing);
    assert_eq!(rar.version, RarVersion::Rar4);
    assert_eq!(rar.borrowable, Borrowable::Yes);
    let member = rar.first_media.as_ref().unwrap();
    assert_eq!((member.index, member.name.as_deref()), (1, Some("movie.mkv")));
    assert_eq!(member.sniffed, found(MediaKind::Mkv, Confidence::Validated));

    let bytes = r4_archive(&[r4_member(b"movie.mkv", b"lz stand-in", 0, 0x33, 50_000, None)]);
    let packing = probe(&bytes, None, None).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::No(NotBorrowable::Compressed));
    assert_eq!(packing.first_media().unwrap().method, MapMethod::Compressed { id: 0x33 });

    let salt = [1, 2, 3, 4, 5, 6, 7, 8];
    let (key, iv) = zipfast::crypto::derive_rar4_key_iv("pw", &salt);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &movie).unwrap();
    let bytes = r4_archive(&[r4_member(b"movie.mkv", &cipher, 0, 0x30, movie.len(), Some(salt))]);
    let packing = probe(&bytes, None, None).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::NeedsPassword(PasswordNeed::DataEncrypted));
    assert_eq!(
        packing.first_media().unwrap().packing,
        MemberPacking::DataEncrypted { cipher: CipherKind::Rar4Aes128, stored: true }
    );
    let packing = probe(&bytes, None, Some("pw")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::YesWithPassword(PasswordProof::Plaintext));
    assert_eq!(packing.first_media().unwrap().sniffed, found(MediaKind::Mkv, Confidence::Validated));
    // RAR 4.x has no check value: a wrong password goes unproven.
    let packing = probe(&bytes, None, Some("wrong")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::YesWithPassword(PasswordProof::Unverified));
}

// ---- ZIP ----

struct ZipSpec<'a> {
    name: &'a str,
    payload: Vec<u8>,
    method: u16,
    flags: u16,
    extra: Vec<u8>,
    crc: u32,
    size: u32,
}

fn zip(entries: &[ZipSpec<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let local_at = out.len() as u32;
        let common = |sig: u32, out: &mut Vec<u8>| {
            out.extend(sig.to_le_bytes());
            if sig == 0x0201_4b50 {
                out.extend(((3u16 << 8) | 20).to_le_bytes());
            }
            out.extend(20u16.to_le_bytes());
            out.extend(e.flags.to_le_bytes());
            out.extend(e.method.to_le_bytes());
            out.extend(0x6000u16.to_le_bytes());
            out.extend(0x5a21u16.to_le_bytes());
            out.extend(e.crc.to_le_bytes());
            out.extend((e.payload.len() as u32).to_le_bytes());
            out.extend(e.size.to_le_bytes());
            out.extend((e.name.len() as u16).to_le_bytes());
            out.extend((e.extra.len() as u16).to_le_bytes());
        };
        common(0x0403_4b50, &mut out);
        out.extend(e.name.as_bytes());
        out.extend(&e.extra);
        out.extend(&e.payload);
        common(0x0201_4b50, &mut central);
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend((0o100644u32 << 16).to_le_bytes());
        central.extend(local_at.to_le_bytes());
        central.extend(e.name.as_bytes());
        central.extend(&e.extra);
    }
    let cd_at = out.len() as u32;
    out.extend(&central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(cd_at.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

fn stored<'a>(name: &'a str, payload: &[u8]) -> ZipSpec<'a> {
    ZipSpec {
        name,
        payload: payload.to_vec(),
        method: 0,
        flags: 0,
        extra: vec![],
        crc: crc32fast::hash(payload),
        size: payload.len() as u32,
    }
}

/// A WinZip AES-256 stored entry encrypted with `password`.
fn aes<'a>(name: &'a str, plain: &[u8], password: &str) -> ZipSpec<'a> {
    let salt = [0x77; 16];
    let derived = zipfast::crypto::aes_derive(password.as_bytes(), &salt, 32).unwrap();
    let mut payload = salt.to_vec();
    payload.extend(&derived[64..66]);
    payload.extend(zipfast::crypto::decrypt_winzip_ctr(&derived[..32], plain).unwrap());
    payload.extend([0xee; 10]);
    let extra = [&[0x01, 0x99, 7, 0][..], &2u16.to_le_bytes(), b"AE", &[3], &0u16.to_le_bytes()].concat();
    ZipSpec { name, payload, method: 99, flags: 1, extra, crc: 0, size: plain.len() as u32 }
}

#[test]
fn zip_stored_deflated_and_aes() {
    let movie = mkv();
    let bytes = zip(&[stored("release.nfo", b"notes"), stored("movie.mkv", &movie)]);
    for tail in [None, Some(&bytes[bytes.len() - 200..])] {
        let packing = probe(&bytes, tail, None).unwrap();
        let zip = zip_of(&packing);
        assert_eq!(zip.directory, tail.is_some());
        assert!(zip.complete);
        assert_eq!(zip.members, 2);
        assert_eq!(zip.borrowable, Borrowable::Yes);
        let member = zip.first_media.as_ref().unwrap();
        assert_eq!((member.index, member.name.as_deref()), (1, Some("movie.mkv")));
        assert_eq!(member.packing, MemberPacking::Stored);
        assert_eq!(member.sniffed, found(MediaKind::Mkv, Confidence::Validated));
        let data = member.data.clone().unwrap();
        assert_eq!(&bytes[data.start as usize..data.end as usize], &movie[..]);
    }

    let deflated = ZipSpec { method: 8, size: 90_000, ..stored("movie.mkv", b"deflate stand-in") };
    let bytes = zip(&[deflated]);
    let packing = probe(&bytes, None, None).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::No(NotBorrowable::Compressed));
    assert_eq!(packing.first_media().unwrap().packing, MemberPacking::Compressed { method: 8, solid: false });

    let bytes = zip(&[aes("movie.mkv", &movie, "pw")]);
    let packing = probe(&bytes, None, None).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::NeedsPassword(PasswordNeed::DataEncrypted));
    let member = packing.first_media().unwrap();
    assert_eq!(
        member.packing,
        MemberPacking::DataEncrypted { cipher: CipherKind::WinZipAes { strength: 3 }, stored: true }
    );
    assert_eq!(member.mapping, OutputMapping::Counter { skip: 18 });
    assert!(matches!(member.cipher, Some(CipherParams::WinZipAes { strength: 3, .. })));
    let packing = probe(&bytes, None, Some("pw")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::YesWithPassword(PasswordProof::Verifier));
    assert_eq!(packing.first_media().unwrap().sniffed, found(MediaKind::Mkv, Confidence::Validated));
    let packing = probe(&bytes, None, Some("not it")).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::NeedsPassword(PasswordNeed::WrongPassword));

    let zipcrypto = ZipSpec { flags: 1, ..stored("movie.mkv", &[0; 112]) };
    let packing = probe(&zip(&[zipcrypto]), None, None).unwrap();
    assert_eq!(packing.borrowable(), Borrowable::No(NotBorrowable::SequentialCipher));
}

#[test]
fn zip_head_alone_lists_what_it_holds_and_the_tail_adds_the_rest() {
    let movie = pad(mkv(), 50_000);
    let bytes = zip(&[stored("sample.nfo", b"notes"), stored("movie.mkv", &movie), stored("extra.mkv", b"x")]);
    let head = &bytes[..8192];
    let tail = &bytes[bytes.len() - 4096..];

    let packing = probe(head, None, None).unwrap();
    let zip = zip_of(&packing);
    assert!(!zip.directory && !zip.complete);
    assert_eq!(zip.members, 2, "the third local header is past the head");
    assert_eq!(zip.first_media.as_ref().unwrap().name.as_deref(), Some("movie.mkv"));
    assert_eq!(zip.borrowable, Borrowable::Yes);

    let packing = probe(head, Some(tail), None).unwrap();
    let zip = zip_of(&packing);
    assert!(zip.directory && zip.complete);
    assert_eq!(zip.members, 3);
    let member = zip.first_media.as_ref().unwrap();
    assert_eq!(member.name.as_deref(), Some("movie.mkv"));
    assert_eq!(member.size, Some(50_000));
    assert_eq!(member.sniffed, found(MediaKind::Mkv, Confidence::Validated));

    // A known file length gives the same answer; a tail missing the directory falls back to the head.
    let with_len = probe_with(head, Some(tail), None, &ProbeOptions::new().file_len(Some(bytes.len() as u64))).unwrap();
    assert_eq!(with_len, packing);
    let packing = probe(head, Some(&bytes[bytes.len() - 30..]), None).unwrap();
    assert!(!zip_of(&packing).directory);
}

#[test]
fn zip_head_cut_inside_its_first_local_header_is_truncated() {
    let movie = mkv();
    let bytes = zip(&[stored("movie.mkv", &movie)]);
    let packing = probe(&bytes[..20], None, None).unwrap();
    let zip = zip_of(&packing);
    assert_eq!(zip.members, 0);
    assert_eq!(zip.borrowable, Borrowable::Unknown(Undecided::Truncated));
}
