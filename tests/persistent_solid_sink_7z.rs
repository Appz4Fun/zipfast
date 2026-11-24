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

//! `SolidStreamSink` over a 7z folder: the members of one LZMA2 folder (plain and 7zAES) kept in persistent direct
//! partials; a later member of the folder started after a restart reads the earlier members' durable output at
//! folder offsets.
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
#![allow(dead_code, reason = "helpers copied from feed_decoder_7z.rs")]
mod common;

#[allow(dead_code, reason = "the shared doc store also carries fault hooks these tests do not use")]
mod anchor_store {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/persistent-anchor-store.rs"));
}

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use zipfast::map::*;
use zipfast::partial::*;
use zipfast::progressive::{
    ProgressiveLimits, ProtectedVolume, ProtectionDeclaration, ProtectionInventory, SessionControl, VolumeBacking,
};

// ---- A minimal 7z writer: one folder of LZMA2 (or 7zAES over LZMA2) holding several files ----

/// A coder as stored: its id and properties.
type Coder = (&'static [u8], Vec<u8>);

const LZMA2: &[u8] = &[0x21];
const AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
const PASSWORD: &str = "pw";
const SALT: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
const IV: [u8; 16] = [0x5A; 16];

fn num(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    for k in 0..i {
        out.push((value >> (8 * k)) as u8);
    }
}

fn aes_key() -> [u8; 32] {
    zipfast::crypto::derive_7z_key(PASSWORD, &SALT, 6).unwrap()
}

fn aes_properties() -> Vec<u8> {
    let mut p = vec![6 | 0x80 | 0x40, ((SALT.len() as u8 - 1) << 4) | 15];
    p.extend_from_slice(&SALT);
    p.extend_from_slice(&IV);
    p
}

/// A raw LZMA2 stream of `plain` (1 MiB dictionary, 7z property 16), encoded in independent blocks of `block`
/// bytes as 7-Zip's multithreaded encoder writes them: each block starts with a dictionary reset.
fn lzma2(plain: &[u8], block: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in plain.chunks(block) {
        let mut opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
        opts.dict_size(1 << 20);
        let mut filters = liblzma::stream::Filters::new();
        filters.lzma2(&opts);
        let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
        let mut enc = Vec::with_capacity(piece.len() + 4096);
        let mut input = piece;
        loop {
            enc.reserve(1 << 16);
            let before = stream.total_in();
            let status = stream.process_vec(input, &mut enc, liblzma::stream::Action::Finish).unwrap();
            input = &input[(stream.total_in() - before) as usize..];
            if status == liblzma::stream::Status::StreamEnd {
                break;
            }
        }
        assert_eq!(enc.pop(), Some(0x00), "end marker");
        out.extend(enc);
    }
    out.push(0x00);
    out
}

/// A 7z archive of one folder holding `files`; `encrypted` puts 7zAES under the LZMA2 coder.
fn seven_zip(files: &[(&str, Vec<u8>)], encrypted: bool, block: usize) -> Vec<u8> {
    let plain: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    let lz = lzma2(&plain, block);
    let n = plain.len() as u64;
    let (packed, coders, sizes): (Vec<u8>, Vec<Coder>, Vec<u64>) = if encrypted {
        let mut padded = lz.clone();
        padded.resize(lz.len().next_multiple_of(16), 0);
        let cipher = zipfast::crypto::encrypt_cbc(&aes_key(), &IV, &padded).unwrap();
        (cipher, vec![(LZMA2, vec![16]), (AES, aes_properties())], vec![n, lz.len() as u64])
    } else {
        (lz, vec![(LZMA2, vec![16])], vec![n])
    };
    let mut h = vec![0x01, 0x04, 0x06];
    num(&mut h, 0);
    num(&mut h, 1);
    h.push(0x09);
    num(&mut h, packed.len() as u64);
    h.extend_from_slice(&[0x00, 0x07, 0x0B]);
    num(&mut h, 1);
    h.push(0x00);
    num(&mut h, coders.len() as u64);
    for (id, props) in &coders {
        h.push(id.len() as u8 | 0x20);
        h.extend_from_slice(id);
        num(&mut h, props.len() as u64);
        h.extend_from_slice(props);
    }
    for i in 0..coders.len() - 1 {
        num(&mut h, i as u64);
        num(&mut h, i as u64 + 1);
    }
    h.push(0x0C);
    for s in &sizes {
        num(&mut h, *s);
    }
    h.extend_from_slice(&[0x00, 0x08, 0x0D]);
    num(&mut h, files.len() as u64);
    h.push(0x09);
    for (_, b) in &files[..files.len() - 1] {
        num(&mut h, b.len() as u64);
    }
    h.extend_from_slice(&[0x0A, 0x01]);
    for (_, b) in files {
        h.extend_from_slice(&crc32fast::hash(b).to_le_bytes());
    }
    h.extend_from_slice(&[0x00, 0x00, 0x05]);
    num(&mut h, files.len() as u64);
    let mut names = vec![0u8];
    for (name, _) in files {
        for u in name.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    h.push(0x11);
    num(&mut h, names.len() as u64);
    h.extend_from_slice(&names);
    h.extend_from_slice(&[0x00, 0x00]);
    let mut sig = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4, 0, 0, 0, 0];
    sig.extend_from_slice(&(packed.len() as u64).to_le_bytes());
    sig.extend_from_slice(&(h.len() as u64).to_le_bytes());
    sig.extend_from_slice(&crc32fast::hash(&h).to_le_bytes());
    let start = crc32fast::hash(&sig[12..32]);
    sig[8..12].copy_from_slice(&start.to_le_bytes());
    sig.extend(packed);
    sig.extend(h);
    sig
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn text(len: usize, seed: usize) -> Vec<u8> {
    let words: [&[u8]; 8] =
        [b"lorem ", b"ipsum ", b"dolor ", b"sit ", b"amet, ", b"consectetur ", b"adipiscing ", b"elit. "];
    let mut out = Vec::with_capacity(len + 16);
    let mut i = seed;
    while out.len() < len {
        out.extend_from_slice(words[(i * 7 + i / 13) % 8]);
        i += 1;
    }
    out.truncate(len);
    out
}

/// Text and incompressible runs: LZMA chunks, stored chunks, and state resets after the stored ones.
fn mixed(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut k = 0;
    while out.len() < len {
        let n = [90_000usize, 200_000, 150_000, 130_000][k % 4];
        if k % 2 == 0 {
            out.extend(text(n, seed as usize + k));
        } else {
            out.extend(noise(n, seed + k as u64));
        }
        k += 1;
    }
    out.truncate(len);
    out
}

fn direct(work: &Path) -> DirectPartials {
    let (output_root, state_dir, anchors) = (work.join("out"), work.join("state"), work.join("anchors"));
    for dir in [&output_root, &state_dir, &anchors] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::File::open(work).unwrap().sync_all().unwrap();
    DirectPartials::new(DirectOptions {
        binding: ArchiveBinding { job: [7; 16], archive: [9; 32] },
        output_root,
        state_dir,
        naming: PartialNaming::ArchivePath,
        limits: PartialLimits::for_members(8),
        progressive_limits: ProgressiveLimits::default(),
        anchors: Arc::new(anchor_store::DurableAnchors::open(&anchors).unwrap()),
        control: SessionControl::default(),
        protection: ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: vec![ProtectedVolume { index: 0, name: "set.7z".into(), backing: VolumeBacking::NonFile }],
                auxiliary_paths: Vec::new(),
            },
        },
        password: Some(PASSWORD.to_owned()),
    })
    .unwrap()
}

fn verify(file: &mut PartialFile) -> Verdict {
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(verdict) = file.poll_verify(&mut cx) {
            return verdict.unwrap();
        }
    }
}

fn options() -> FeedOptions {
    FeedOptions { max_needs: usize::MAX, read_chunk: 4096, ..FeedOptions::new(Some(PASSWORD)) }
}

struct Counting<'a> {
    sink: &'a mut SolidStreamSink,
    earlier: u64,
}

impl FeedSink for Counting<'_> {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.sink.write_at(offset, bytes)
    }
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.sink.read_held(offset, buf)
    }
    fn read_earlier(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.sink.read_earlier(offset, buf)?;
        self.earlier += n as u64;
        Ok(n)
    }
}

fn drive(d: &mut FeedDecoder, source: &mut ArticleBuffer, sink: &mut SolidStreamSink) -> (FeedStatus, u64) {
    let mut counting = Counting { sink, earlier: 0 };
    let st = loop {
        let st = d.run(source, &mut counting).unwrap();
        if !st.more {
            break st;
        }
    };
    (st, counting.earlier)
}

fn work_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zipfast-solid-sink-7z-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_folder_layout_follows_the_members_offsets() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.bin", mixed(100_000, 1)), ("b.bin", mixed(50_000, 2)), ("c.txt", text(7_000, 3))];
    let archive = seven_zip(&files, false, usize::MAX);
    let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
    let slots = stream_slots(&map, 2).unwrap();
    let want = [(0usize, 0u64, 100_000u64), (1, 100_000, 50_000), (2, 150_000, 7_000)];
    assert_eq!(slots.iter().map(|s| (s.member, s.start, s.size)).collect::<Vec<_>>(), want);
    assert_eq!(stream_slots(&map, 1).unwrap().len(), 2);
}

/// Members 0 and 1 of a three-member folder are decoded into their partials, every handle is dropped, and member 2
/// is decoded after the restart through a sink over all three partials: exact output and CRC. (A fresh 7z member
/// decodes the folder from its last state reset, so `read_earlier` is not asked here; see the unit test of the
/// RAR 5.0 file for the read path.)
#[test]
fn a_later_folder_member_decodes_after_a_restart_over_durable_earlier_members() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.bin", mixed(300_000, 21)), ("b.bin", mixed(700_000, 22)), ("c.txt", text(500_000, 4))];
    let plain_len: usize = files.iter().map(|(_, b)| b.len()).sum();
    for block in [usize::MAX, 350_000] {
        for encrypted in [false, true] {
            let archive = seven_zip(&files, encrypted, block.min(plain_len));
            let volumes: Vec<Vec<u8>> = archive.chunks(400_000).map(<[u8]>::to_vec).collect();
            let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
            let map = MemberMap::from_memory(&refs, "set.7z.001", Some(PASSWORD)).unwrap();
            let mut source = ArticleBuffer::new(usize::MAX);
            for (v, bytes) in volumes.iter().enumerate() {
                source.insert(v as u32, 0, bytes).unwrap();
            }
            let work = work_dir(&format!("{block}-{encrypted}"));
            {
                let parts = direct(&work);
                let mut sink = SolidStreamSink::open(&parts, &map, 0).unwrap();
                let mut d0 = FeedDecoder::new(&map, 0, options()).unwrap();
                let (st, _) = drive(&mut d0, &mut source, &mut sink);
                assert!(st.done && st.crc_ok == Some(true), "{st:?}");
                sink.commit().unwrap();
                sink.next_member(&parts, &map, 1).unwrap();
                let mut d1 = d0.next_solid(&map, 1, options()).unwrap();
                let (st, _) = drive(&mut d1, &mut source, &mut sink);
                assert!(st.done && st.crc_ok == Some(true), "{st:?}");
                sink.commit().unwrap();
            }
            // a new process: the packed bytes come again
            let mut source = ArticleBuffer::new(usize::MAX);
            for (v, bytes) in volumes.iter().enumerate() {
                source.insert(v as u32, 0, bytes).unwrap();
            }
            let parts = direct(&work);
            let mut sink = SolidStreamSink::open(&parts, &map, 2).unwrap();
            assert_eq!(sink.stream_start(), (files[0].1.len() + files[1].1.len()) as u64);
            let mut d2 = FeedDecoder::new(&map, 2, options()).unwrap();
            let (st, earlier) = drive(&mut d2, &mut source, &mut sink);
            assert!(st.done && st.crc_ok == Some(true), "{st:?}");
            eprintln!("block {block} aes {encrypted}: earlier read {earlier}, {:?}", d2.stats());
            assert_eq!(d2.stats().written, files[2].1.len() as u64);
            let mut all = sink.into_files();
            for (i, f) in all.iter().enumerate() {
                assert!(std::fs::read(f.output_path()).unwrap() == files[i].1, "member {i}");
            }
            assert!(matches!(verify(&mut all.pop().unwrap()), Verdict::Ok { .. }));
            let _ = std::fs::remove_dir_all(&work);
        }
    }
}

/// The LZMA2 chunks of a raw stream: (packed range of the payload, output range), from the stream's start.
fn chunks(lz: &[u8]) -> Vec<(std::ops::Range<u64>, std::ops::Range<u64>)> {
    let (mut p, mut o) = (0usize, 0u64);
    let mut out = Vec::new();
    while lz[p] != 0 {
        let c = lz[p];
        let (hdr, unpacked, packed) = if c < 0x80 {
            let u = (usize::from(lz[p + 1]) << 8 | usize::from(lz[p + 2])) + 1;
            (3, u, u)
        } else {
            let u = ((usize::from(c & 0x1F) << 16) | usize::from(lz[p + 1]) << 8 | usize::from(lz[p + 2])) + 1;
            let k = (usize::from(lz[p + 3]) << 8 | usize::from(lz[p + 4])) + 1;
            (if (c >> 5) & 3 >= 2 { 6 } else { 5 }, u, k)
        };
        out.push(((p + hdr) as u64..(p + hdr + packed) as u64, o..o + unpacked as u64));
        p += hdr + packed;
        o += unpacked as u64;
    }
    out
}

/// After the restart, member 2 meets 8 lost payload bytes inside its own output and the repair arrives later, all
/// through the sink over the three partials: exact output. (The decoder currently restarts such a repair at the
/// folder's last state reset inside the member, so it does not read the earlier members back here.)
#[test]
fn a_repair_after_a_restart_goes_through_the_folder_sink() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("a.bin", mixed(300_000, 21)), ("b.bin", mixed(700_000, 22)), ("c.txt", text(500_000, 4))];
    let plain: Vec<u8> = files.iter().flat_map(|(_, b)| b.clone()).collect();
    let block = 350_000;
    let lz = lzma2(&plain, block);
    let walked = chunks(&lz);
    let target = 1_000_000 + 60_000;
    let (p, _) = walked.iter().find(|(_, o)| o.contains(&target)).unwrap();
    let hole = 32 + (p.start + p.end) / 2;
    for encrypted in [false, true] {
        let archive = seven_zip(&files, encrypted, block);
        let map = MemberMap::from_memory(&[&archive], "set.7z", Some(PASSWORD)).unwrap();
        let work = work_dir(&format!("repair-{encrypted}"));
        let fresh = || {
            let mut source = ArticleBuffer::new(usize::MAX);
            source.insert(0, 0, &archive).unwrap();
            source
        };
        {
            let mut source = fresh();
            let parts = direct(&work);
            let mut sink = SolidStreamSink::open(&parts, &map, 0).unwrap();
            let mut d0 = FeedDecoder::new(&map, 0, options()).unwrap();
            drive(&mut d0, &mut source, &mut sink);
            sink.next_member(&parts, &map, 1).unwrap();
            let mut d1 = d0.next_solid(&map, 1, options()).unwrap();
            let (st, _) = drive(&mut d1, &mut source, &mut sink);
            assert!(st.done && st.crc_ok == Some(true), "{st:?}");
            sink.commit().unwrap();
        }
        let mut source = ArticleBuffer::new(usize::MAX);
        source.mark_lost(0, hole..hole + 8);
        source.insert(0, 0, &archive[..hole as usize]).unwrap();
        source.insert(0, hole + 8, &archive[hole as usize + 8..]).unwrap();
        let parts = direct(&work);
        let mut sink = SolidStreamSink::open(&parts, &map, 2).unwrap();
        let mut d2 = FeedDecoder::new(&map, 2, options()).unwrap();
        let (st, _) = drive(&mut d2, &mut source, &mut sink);
        assert!(!st.lost.is_empty() || !st.done, "the hole is met: {st:?}");
        source.insert(0, hole, &archive[hole as usize..hole as usize + 8]).unwrap();
        let (st, earlier) = drive(&mut d2, &mut source, &mut sink);
        assert!(st.done && st.crc_ok == Some(true) && st.lost.is_empty(), "{st:?}");
        eprintln!("aes {encrypted}: earlier read {earlier}, {:?}", d2.stats());
        let files_out = sink.into_files();
        assert!(std::fs::read(files_out[2].output_path()).unwrap() == files[2].1);
        let _ = std::fs::remove_dir_all(&work);
    }
}
