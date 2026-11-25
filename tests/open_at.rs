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

//! Restart points and handover plans (`zipfast::map::{member_restart, open_at, complete_rar5, complete_lzma2}`).

mod common;

use common::{FileSpec, archive, archive_with};
use zipfast::map::{
    Layer, Lzma2DecodeOptions, Lzma2Framing, MapMember, MemberMap, OpenAt, OpenAtError, OpenAtOptions, RestartGrain,
    Seed, Start, complete_lzma2, complete_rar5, member_restart, open_at,
};
use zipfast::rar5::unpack::{NearOptions, Sink};

/// A Usenet article's size, for counting the pieces a header walk touches.
const ARTICLE: u64 = 768_000;

struct Collect(Vec<u8>);
impl Sink for Collect {
    fn put(&mut self, bytes: &[u8]) -> zipfast::Result<()> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn sample(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(format!("word{} of line {} again ", x % 300, x % 50).as_bytes());
    }
    out.truncate(len);
    out
}

/// The member's packed stream bytes from stream offset `from` to its end, read through `spans`.
fn fetch(vols: &[&[u8]], spans: &[zipfast::map::PackedSpan]) -> Vec<u8> {
    spans
        .iter()
        .flat_map(|s| vols[s.volume as usize][s.packed.start as usize..s.packed.end as usize].to_vec())
        .collect()
}

/// Every stored member of `map` opens at several offsets exactly where its mapping allows, with the spans
/// `packed_spans` gives from there to the end.
fn stored_members_open_exactly(map: &MemberMap) -> usize {
    let mut checked = 0;
    for (i, m) in map.members.iter().enumerate() {
        let Ok(r) = member_restart(map, i) else { continue };
        let Some(size) = m.unpacked_size.filter(|&s| s > 0) else { continue };
        if !matches!(r.grain, RestartGrain::AnyByte | RestartGrain::Block16) {
            continue;
        }
        for t in [0, 1, size / 3, size / 2 + 7, size - 1].into_iter().filter(|&t| t < size) {
            let plan = open_at(map, i, t, &OpenAtOptions::default()).unwrap();
            let Start::At { output } = plan.start else { panic!("{:?}", plan.start) };
            match r.grain {
                RestartGrain::AnyByte => assert_eq!(output, t),
                _ => assert_eq!(output, t & !15),
            }
            assert_eq!(Some(plan.spans.clone()), m.packed_spans(output..size), "member {i} at {t}");
            checked += 1;
        }
        assert!(matches!(open_at(map, i, size, &OpenAtOptions::default()), Err(OpenAtError::PastEnd { .. })));
    }
    checked
}

#[test]
fn stored_rar_members_open_at_any_byte() {
    let a = sample(5_000);
    let b = sample(70_000);
    let bytes = archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", &b)]);
    let map = MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap();
    let r = member_restart(&map, 1).unwrap();
    assert_eq!((r.layer, r.grain, r.stream_start), (Layer::Stored, RestartGrain::AnyByte, 0));
    assert!(stored_members_open_exactly(&map) >= 10);
    // The spans from the restart carry exactly the rest of the member.
    let plan = open_at(&map, 1, 12_345, &OpenAtOptions::default()).unwrap();
    assert_eq!(fetch(&[&bytes], &plan.spans), b[12_345..]);
}

#[test]
fn seven_zip_copy_zip_and_aes_members_open_from_the_map() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let read = |p: &str| std::fs::read(format!("{dir}/{p}")).unwrap();
    let copy = read("7z-extract/copy.7z");
    let map = MemberMap::from_memory(&[&copy], "copy.7z", None).unwrap();
    assert!(stored_members_open_exactly(&map) > 0);
    let aes = read("7z-extract/aes_copy.7z");
    let map = MemberMap::from_memory(&[&aes], "aes_copy.7z", None).unwrap();
    assert!(
        map.members.iter().enumerate().any(|(i, _)| member_restart(&map, i).unwrap().grain == RestartGrain::Block16)
    );
    assert!(stored_members_open_exactly(&map) > 0);
    for set in ["stored", "crypt"] {
        let names: Vec<String> = std::fs::read_dir(format!("{dir}/zip-split"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with(set) && !n.ends_with(".md"))
            .collect();
        let mut names = names;
        names.sort_by_key(|n| if n.ends_with(".zip") { "~".to_owned() } else { n.clone() });
        let vols: Vec<Vec<u8>> = names.iter().map(|n| read(&format!("zip-split/{n}"))).collect();
        let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
        let map = MemberMap::from_memory(&refs, &names[0], None).unwrap();
        if set == "crypt" {
            // ZipCrypto decrypts only from the entry's start
            let i = map.members.iter().position(|m| m.encrypted).unwrap();
            assert_eq!(member_restart(&map, i).unwrap().layer, Layer::StoredSequential);
            let r = open_at(&map, i, 10, &OpenAtOptions::default());
            assert!(matches!(r, Err(OpenAtError::StartOnly(Layer::StoredSequential))));
        } else {
            assert!(stored_members_open_exactly(&map) > 0, "{set}");
        }
    }
}

/// A compressed RAR 5.0 member: the plan names a search region and the donor; completing it with the held packed
/// bytes and the plaintext gives a decoder that produces the rest exactly.
#[test]
fn a_compressed_rar5_member_hands_over_through_a_plan() {
    use zipfast::rar5::testenc;
    let plain = sample(600_000);
    let data = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let mut spec = FileSpec::new("c.bin", &data);
    spec.method = 3;
    spec.size = Some(plain.len() as u64);
    let bytes = archive_with(&[(spec, crc32fast::hash(&plain))], false);
    let map = MemberMap::from_memory(&[&bytes], "c.rar", None).unwrap();
    let r = member_restart(&map, 0).unwrap();
    assert_eq!((r.layer, r.grain, r.dictionary), (Layer::Rar5Compressed, RestartGrain::Rar5Blocks, Some(128 << 10)));
    for target in [100_000u64, 350_000, 599_000] {
        let plan = open_at(&map, 0, target, &OpenAtOptions::default()).unwrap();
        let Start::Rar5 { stream_target, ref donor, .. } = plan.start else { panic!("{:?}", plan.start) };
        assert_eq!((stream_target, donor.end), (target, target));
        let held = fetch(&[&bytes], &plan.spans);
        assert_eq!(plan.spans.first().unwrap().stream.start, plan.fetch_from);
        let resume = handover(&map, &plan, &held, &plain);
        assert!(resume <= target && target - resume < 100_000, "restart {resume} for {target}");
    }
}

/// A seeded plan fetches only near the target and resumes from the held plaintext; its output is flagged
/// unverified, and on filter-free content it is exact.
#[test]
fn a_seeded_rar5_plan_fetches_near_the_target() {
    use zipfast::rar5::testenc;
    // literal-rich content, as the restart search pins blocks by their literals: random runs and repeats of them
    let mut plain = Vec::with_capacity(600_000);
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    while plain.len() < 600_000 {
        for _ in 0..300 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            plain.push(x as u8);
        }
        let back = plain.len() - 1_000.min(plain.len());
        let repeat = plain[back..back + 200.min(plain.len() - back)].to_vec();
        plain.extend(repeat);
    }
    plain.truncate(600_000);
    let data = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let mut spec = FileSpec::new("c.bin", &data);
    spec.method = 3;
    spec.size = Some(plain.len() as u64);
    let bytes = archive_with(&[(spec, crc32fast::hash(&plain))], false);
    let map = MemberMap::from_memory(&[&bytes], "c.rar", None).unwrap();
    let target = 450_000u64;
    let checked = open_at(&map, 0, target, &OpenAtOptions::default()).unwrap();
    let packed_len = map.members[0].packed_size;
    let options = OpenAtOptions {
        seed: Seed::HeldPlaintext { strict: false },
        search: Some(packed_len / 3),
        ..Default::default()
    };
    let plan = open_at(&map, 0, target, &options).unwrap();
    assert_eq!(plan.seed, Seed::HeldPlaintext { strict: false });
    assert!(plan.fetch_from > checked.fetch_from, "fetches less: {} vs {}", plan.fetch_from, checked.fetch_from);
    let Start::Rar5 { ref donor, .. } = plan.start else { panic!() };
    assert_eq!(donor.end, target);
    let held = fetch(&[&bytes], &plan.spans);
    let known = &plain[..target as usize];
    let mut r = complete_rar5(&map, &plan, plan.fetch_from, &held, 0, known, &NearOptions::default()).unwrap();
    assert!(!r.checked, "a seeded window is unverified");
    let mut out = Collect(Vec::new());
    r.decoder.feed(&held[(r.feed_from - plan.fetch_from) as usize..], &mut out).unwrap();
    r.decoder.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[r.output as usize..]);
    // the checked plan is still checked
    let held = fetch(&[&bytes], &checked.spans);
    let r = complete_rar5(&map, &checked, checked.fetch_from, &held, 0, known, &NearOptions::default()).unwrap();
    assert!(r.checked);
}

/// prybar-fc's compressed failover bench: with known plaintext that does not reach a guarded restart's check (here
/// only 256 KiB before the target), a seeded plan takes the nearest unguarded restart instead of failing; its output
/// is unverified and, on filter-free content, exact.
#[test]
fn a_seeded_rar5_plan_falls_back_to_an_unguarded_restart() {
    use zipfast::rar5::testenc;
    let mut plain = Vec::with_capacity(900_000);
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    while plain.len() < 900_000 {
        for _ in 0..300 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            plain.push(x as u8);
        }
        let back = plain.len() - 1_000.min(plain.len());
        let repeat = plain[back..back + 200.min(plain.len() - back)].to_vec();
        plain.extend(repeat);
    }
    plain.truncate(900_000);
    let data = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let mut spec = FileSpec::new("c.bin", &data);
    spec.method = 3;
    spec.size = Some(plain.len() as u64);
    let bytes = archive_with(&[(spec, crc32fast::hash(&plain))], false);
    let map = MemberMap::from_memory(&[&bytes], "c.rar", None).unwrap();
    let target = 700_000u64;
    let packed_len = map.members[0].packed_size;
    let options = OpenAtOptions {
        seed: Seed::HeldPlaintext { strict: false },
        search: Some(packed_len / 3),
        ..Default::default()
    };
    let plan = open_at(&map, 0, target, &options).unwrap();
    let held = fetch(&[&bytes], &plan.spans);
    let known_base = target - (256 << 10);
    let known = &plain[known_base as usize..target as usize];
    let mut r = complete_rar5(&map, &plan, plan.fetch_from, &held, known_base, known, &NearOptions::default())
        .expect("an unguarded restart when no guarded one can be checked");
    assert!(!r.checked);
    assert!(r.output <= target);
    let mut out = Collect(Vec::new());
    r.decoder.feed(&held[(r.feed_from - plan.fetch_from) as usize..], &mut out).unwrap();
    r.decoder.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[r.output as usize..]);
    // strict refuses what is not guarded
    let strict = OpenAtOptions { seed: Seed::HeldPlaintext { strict: true }, ..options };
    let plan = open_at(&map, 0, target, &strict).unwrap();
    assert!(complete_rar5(&map, &plan, plan.fetch_from, &held, known_base, known, &NearOptions::default()).is_err());
}

/// Completes a RAR 5.0 plan with the whole plaintext known, decodes to the end and checks the output; returns the
/// restart's member output offset.
fn handover(map: &MemberMap, plan: &OpenAt, held: &[u8], stream_plain: &[u8]) -> u64 {
    let mut r = complete_rar5(map, plan, plan.fetch_from, held, 0, stream_plain, &NearOptions::default()).unwrap();
    let mut out = Collect(Vec::new());
    r.decoder.feed(&held[(r.feed_from - plan.fetch_from) as usize..], &mut out).unwrap();
    r.decoder.finish(&mut out).unwrap();
    let start = plan.restart.stream_start as usize;
    let size = map.members[plan.member].unpacked_size.unwrap() as usize;
    assert_eq!(out.0, stream_plain[start + r.output as usize..start + size], "member {} output", plan.member);
    assert_eq!(r.redecode, plan.target - r.output);
    r.output
}

/// The second member of a solid stream: its stream start is the first member's size, and the handover resumes it.
#[test]
fn a_solid_second_rar5_member_hands_over_at_its_stream_offset() {
    use zipfast::rar5::testenc;
    // the first member differs from the second's start, or literals would pin to both
    let a: Vec<u8> = sample(150_000).iter().map(u8::to_ascii_uppercase).collect();
    let b = sample(400_000);
    let first = testenc::tuned_stream(&testenc::lz(&a, 1 << 17, 16), 2_000);
    let second = testenc::tuned_stream(&testenc::lz(&b, 1 << 17, 16), 2_000);
    let mut sa = FileSpec::new("a.bin", &first);
    sa.method = 3;
    sa.size = Some(a.len() as u64);
    let mut sb = FileSpec::new("b.bin", &second);
    sb.method = 3;
    sb.size = Some(b.len() as u64);
    sb.solid = true;
    let bytes = archive_with(&[(sa, crc32fast::hash(&a)), (sb, crc32fast::hash(&b))], true);
    let map = MemberMap::from_memory(&[&bytes], "s.rar", None).unwrap();
    let r = member_restart(&map, 1).unwrap();
    assert_eq!(r.stream_start, a.len() as u64);
    let stream = [a.clone(), b.clone()].concat();
    let plan = open_at(&map, 1, 300_000, &OpenAtOptions::default()).unwrap();
    let Start::Rar5 { stream_target, .. } = plan.start else { panic!() };
    assert_eq!(stream_target, a.len() as u64 + 300_000);
    let held = fetch(&[&bytes], &plan.spans);
    handover(&map, &plan, &held, &stream);
}

/// A restart at the member's start needs no search: a target of 0 (and a target so close to the start that no block
/// before it pins) starts a fresh decoder at packed offset 0.
#[test]
fn a_compressed_rar5_member_opens_at_its_start() {
    use zipfast::rar5::testenc;
    let plain = sample(300_000);
    let data = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let mut spec = FileSpec::new("c.bin", &data);
    spec.method = 3;
    spec.size = Some(plain.len() as u64);
    let bytes = archive_with(&[(spec, crc32fast::hash(&plain))], false);
    let map = MemberMap::from_memory(&[&bytes], "c.rar", None).unwrap();
    for target in [0u64, 40] {
        let plan = open_at(&map, 0, target, &OpenAtOptions::default()).unwrap();
        assert_eq!(plan.fetch_from, 0);
        let held = fetch(&[&bytes], &plan.spans);
        let mut r = complete_rar5(&map, &plan, 0, &held, 0, &plain[..target as usize], &NearOptions::default())
            .unwrap_or_else(|e| panic!("target {target}: {e}"));
        assert_eq!((r.output, r.feed_from, r.redecode, r.near.is_none()), (0, 0, target, true), "target {target}");
        let mut out = Collect(Vec::new());
        r.decoder.feed(&held, &mut out).unwrap();
        r.decoder.finish(&mut out).unwrap();
        assert_eq!(out.0, plain, "target {target}");
    }
}

/// Directories and stored members take no part in a solid stream's decoding: a solid member's stream starts after
/// the last compressed member without the solid flag, and only compressed members' sizes count.
#[test]
fn a_solid_streams_start_skips_directories_and_stored_members() {
    use zipfast::rar5::testenc;
    let a = sample(50_000);
    let b = sample(30_000);
    let stored = sample(7_000);
    let pa = testenc::tuned_stream(&testenc::lz(&a, 1 << 17, 16), 2_000);
    let pb = testenc::tuned_stream(&testenc::lz(&b, 1 << 17, 16), 2_000);
    let mut sa = FileSpec::new("a.bin", &pa);
    sa.method = 3;
    sa.size = Some(a.len() as u64);
    let mut dir = FileSpec::new("d", &[]);
    dir.dir = true;
    let ss = FileSpec::new("s.bin", &stored);
    let mut sb = FileSpec::new("b.bin", &pb);
    sb.method = 3;
    sb.size = Some(b.len() as u64);
    sb.solid = true;
    let bytes = archive_with(
        &[(sa, crc32fast::hash(&a)), (dir, 0), (ss, crc32fast::hash(&stored)), (sb, crc32fast::hash(&b))],
        true,
    );
    let map = MemberMap::from_memory(&[&bytes], "s.rar", None).unwrap();
    assert_eq!(map.members.len(), 4);
    assert_eq!(member_restart(&map, 3).unwrap().stream_start, a.len() as u64);
    assert_eq!(member_restart(&map, 0).unwrap().stream_start, 0);
}

#[test]
fn plans_refuse_what_they_cannot_do() {
    use zipfast::rar5::testenc;
    let plain = sample(100_000);
    let data = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let mut spec = FileSpec::new("c.bin", &data);
    spec.method = 3;
    spec.size = Some(plain.len() as u64);
    let bytes = archive_with(&[(spec, crc32fast::hash(&plain))], false);
    let map = MemberMap::from_memory(&[&bytes], "c.rar", None).unwrap();
    assert!(matches!(member_restart(&map, 5), Err(OpenAtError::NoMember(5))));
    let plan = open_at(&map, 0, 50_000, &OpenAtOptions::default()).unwrap();
    let held = fetch(&[&bytes], &plan.spans);
    // known plaintext ending before the target
    let r = complete_rar5(&map, &plan, plan.fetch_from, &held, 0, &plain[..10_000], &NearOptions::default());
    assert!(matches!(r, Err(OpenAtError::NeedMore { .. })));
    // a RAR plan is not an LZMA2 plan
    let r = complete_lzma2(&map, &plan, plan.fetch_from, &held, 0, &plain, None, &Lzma2DecodeOptions::default());
    assert!(matches!(r, Err(OpenAtError::WrongPlan)));
}

// ---- RustyGet's fixtures (ZIPFAST_Z_FIXTURES) ----

struct Fixture {
    vols: Vec<Vec<u8>>,
    map: MemberMap,
    password: String,
}

fn fixture(dir: &std::path::Path, set: &str, password: &str) -> Fixture {
    let set_dir = dir.join(set);
    let mut names: Vec<String> = std::fs::read_dir(&set_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.contains(".rar") || n.contains(".7z"))
        .collect();
    names.sort();
    let vols: Vec<Vec<u8>> = names.iter().map(|n| std::fs::read(set_dir.join(n)).unwrap()).collect();
    let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, &names[0], Some(password)).unwrap();
    Fixture { vols, map, password: password.to_owned() }
}

fn payload(dir: &std::path::Path, m: &MapMember) -> Vec<u8> {
    let name = m.name.as_deref().unwrap();
    let base = name.rsplit(['/', '\\']).next().unwrap();
    std::fs::read(dir.join(base)).unwrap()
}

/// Decrypts held packed bytes from stream offset `from` as the plan fetched them: from 0 with the member's IV, or
/// with the first 16 bytes as the IV.
fn decrypt_held(key: &[u8], iv: &[u8; 16], from: u64, held: &[u8]) -> (u64, Vec<u8>) {
    if from == 0 {
        (0, zipfast::crypto::decrypt_cbc(key, iv, &held[..held.len() / 16 * 16]).unwrap())
    } else {
        let prev: [u8; 16] = held[..16].try_into().unwrap();
        let body = &held[16..];
        (from + 16, zipfast::crypto::decrypt_cbc(key, &prev, &body[..body.len() / 16 * 16]).unwrap())
    }
}

#[test]
fn handovers_on_the_z_fixtures() {
    use zipfast::map::CipherParams;
    let Some(dir) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(std::path::PathBuf::from) else {
        eprintln!("skipped: set ZIPFAST_Z_FIXTURES to the z-fixtures sets directory");
        return;
    };
    let manifest = String::from_utf8(std::fs::read(dir.join("MANIFEST.json")).unwrap()).unwrap();
    let at = manifest.find("\"password\"").unwrap();
    let password = manifest[at..].split('"').nth(3).unwrap().to_owned();
    for set in
        ["F03_rar5_m3_video", "F04_rar5_m3_aes", "F05_rar5_m5_mixed", "F06_rar5_m3_mixed_hp", "F12_rar5_m3_aes_2files"]
    {
        let f = fixture(&dir, set, &password);
        let refs: Vec<&[u8]> = f.vols.iter().map(Vec::as_slice).collect();
        let mut stream = Vec::new();
        for (i, m) in f.map.members.iter().enumerate() {
            if m.is_dir || m.unpacked_size.unwrap_or(0) == 0 {
                continue;
            }
            let plain = payload(&dir, m);
            let r = member_restart(&f.map, i).unwrap();
            if r.stream_start == 0 {
                stream.clear();
            }
            assert_eq!(r.stream_start, stream.len() as u64, "{set} member {i}");
            stream.extend_from_slice(&plain);
            for target in [0, plain.len() as u64 / 3, plain.len() as u64 * 4 / 5] {
                let plan = open_at(&f.map, i, target, &OpenAtOptions::default()).unwrap();
                let held = fetch(&refs, &plan.spans);
                let (from, held) = match m.cipher.clone() {
                    Some(CipherParams::Rar5 { kdf_count, salt, iv: Some(iv), check, .. }) => {
                        let key = zipfast::crypto::derive_rar5_key(&f.password, kdf_count, &salt, check).unwrap();
                        decrypt_held(&key, &iv, plan.fetch_from, &held)
                    }
                    _ => (plan.fetch_from, held),
                };
                let started = std::time::Instant::now();
                // the donor is what a handover holds: the stream's output up to the target
                let known = &stream[..(r.stream_start + target) as usize];
                let mut res = complete_rar5(&f.map, &plan, from, &held, 0, known, &NearOptions::default())
                    .unwrap_or_else(|e| panic!("{set} member {i} target {target}: {e}"));
                let mut out = Collect(Vec::new());
                res.decoder.feed(&held[(res.feed_from - from) as usize..], &mut out).unwrap();
                res.decoder.finish(&mut out).unwrap();
                eprintln!(
                    "{set} member {i} target {target}: restart {} ({} back), {} ms",
                    res.output,
                    res.redecode,
                    started.elapsed().as_millis()
                );
                assert_eq!(out.0, plain[res.output as usize..], "{set} member {i} target {target}");
                assert!(
                    res.near.as_ref().is_none_or(|n| n.window_checked),
                    "{set} member {i} target {target}: the default plan checks the window"
                );
                // A narrow fetch: the restart either decodes exactly or is refused, never wrong.
                let narrow = OpenAtOptions { search: Some(4 << 20), ..Default::default() };
                let plan = open_at(&f.map, i, target, &narrow).unwrap();
                let held = fetch(&refs, &plan.spans);
                let (from, held) = match m.cipher.clone() {
                    Some(CipherParams::Rar5 { kdf_count, salt, iv: Some(iv), check, .. }) => {
                        let key = zipfast::crypto::derive_rar5_key(&f.password, kdf_count, &salt, check).unwrap();
                        decrypt_held(&key, &iv, plan.fetch_from, &held)
                    }
                    _ => (plan.fetch_from, held),
                };
                let verdict = match complete_rar5(&f.map, &plan, from, &held, 0, known, &NearOptions::default()) {
                    Err(e) => format!("refused: {e}"),
                    Ok(mut res) => {
                        let mut out = Collect(Vec::new());
                        let fed = res.decoder.feed(&held[(res.feed_from - from) as usize..], &mut out);
                        match fed.and_then(|()| res.decoder.finish(&mut out)) {
                            Ok(()) => {
                                assert_eq!(out.0, plain[res.output as usize..], "{set} narrow {target}");
                                format!("exact from {}", res.output)
                            }
                            Err(e) => {
                                let got = &out.0;
                                assert_eq!(got[..], plain[res.output as usize..res.output as usize + got.len()]);
                                format!("refused while decoding: {e}")
                            }
                        }
                    }
                };
                eprintln!("{set} member {i} target {target} narrow (4 MiB): {verdict}");
                // Seeded from the held plaintext: fetch from near the target only; the output is unverified and
                // checked here against the payload.
                if target > 0 {
                    let default_fetch =
                        m.packed_size - open_at(&f.map, i, target, &OpenAtOptions::default()).unwrap().fetch_from;
                    let seeded = OpenAtOptions { seed: Seed::HeldPlaintext { strict: false }, ..Default::default() };
                    let plan = open_at(&f.map, i, target, &seeded).unwrap();
                    let held = fetch(&refs, &plan.spans);
                    let (from, held) = match m.cipher.clone() {
                        Some(CipherParams::Rar5 { kdf_count, salt, iv: Some(iv), check, .. }) => {
                            let key = zipfast::crypto::derive_rar5_key(&f.password, kdf_count, &salt, check).unwrap();
                            decrypt_held(&key, &iv, plan.fetch_from, &held)
                        }
                        _ => (plan.fetch_from, held),
                    };
                    let started = std::time::Instant::now();
                    let verdict = match complete_rar5(&f.map, &plan, from, &held, 0, known, &NearOptions::default()) {
                        Err(e) => format!("refused: {e}"),
                        Ok(mut res) => {
                            let mut out = Collect(Vec::new());
                            let fed = res.decoder.feed(&held[(res.feed_from - from) as usize..], &mut out);
                            let fin = fed.and_then(|()| res.decoder.finish(&mut out));
                            let exact = fin.is_ok() && out.0 == plain[res.output as usize..];
                            format!(
                                "{} from {} ({} back), checked {}, suspects {:?}, {} ms",
                                if exact { "exact" } else { "WRONG" },
                                res.output,
                                res.redecode,
                                res.checked,
                                res.decoder.seed_suspects().iter().map(|s| (s.at, s.reason)).collect::<Vec<_>>(),
                                started.elapsed().as_millis()
                            )
                        }
                    };
                    eprintln!(
                        "{set} member {i} target {target} seeded: fetched {} of {} packed (checked plan {}): {verdict}",
                        m.packed_size - plan.fetch_from,
                        m.packed_size,
                        default_fetch
                    );
                }
            }
        }
    }
    for set in ["F07_7z_lzma2_video", "F08_7z_lzma2_mixed_mt", "F10_7z_lzma2_aes_mixed"] {
        let f = fixture(&dir, set, &password);
        let refs: Vec<&[u8]> = f.vols.iter().map(Vec::as_slice).collect();
        for (i, m) in f.map.members.iter().enumerate() {
            let Some(slot) = m.folder else { continue };
            let folder = &f.map.folders[slot.index as usize];
            if folder.members != 1 {
                continue;
            }
            let plain = payload(&dir, m);
            let r = member_restart(&f.map, i).unwrap();
            assert_eq!((r.layer, r.grain), (Layer::SevenZipLzma2, RestartGrain::Lzma2Chunks), "{set}");
            for target in [plain.len() as u64 / 3, plain.len() as u64 * 4 / 5] {
                let plan = open_at(&f.map, i, target, &OpenAtOptions::default()).unwrap();
                let Start::Lzma2 { framing: how, .. } = plan.start else { panic!("{:?}", plan.start) };
                let held = fetch(&refs, &plan.spans);
                // The framing: a header walk from the stream's start (the map walks the in-memory volumes, reading
                // headers only), or under 7zAES the decrypted bytes from 0 that the plan fetches.
                let framing = match how {
                    Lzma2Framing::HeaderWalk => {
                        Some(f.map.lzma2_chunks(slot.index as usize, &refs, Default::default()).unwrap())
                    }
                    _ => None,
                };
                let (from, held) = match folder.cipher.clone() {
                    Some(CipherParams::SevenZipAes { num_cycles_power, salt, iv }) => {
                        assert_eq!((how, plan.fetch_from), (Lzma2Framing::FromStart, 0), "{set}");
                        let key = zipfast::crypto::derive_7z_key(&f.password, &salt, num_cycles_power).unwrap();
                        decrypt_held(&key, &iv, plan.fetch_from, &held)
                    }
                    _ => (plan.fetch_from, held),
                };
                let known = &plain[..target as usize];
                let options = Lzma2DecodeOptions { max_output: 1 << 34, max_dictionary: 1 << 31, ..Default::default() };
                let started = std::time::Instant::now();
                let res = complete_lzma2(&f.map, &plan, from, &held, 0, known, framing.as_ref(), &options)
                    .unwrap_or_else(|e| panic!("{set} member {i} target {target}: {e}"));
                // What the handover fetched: the bulk from `fetch_from`, plus the header walk before it.
                let folder_len: u64 = folder.pack_sizes.iter().sum();
                let walk = framing.as_ref().map(|ix| {
                    let before: Vec<_> = ix.chunks.iter().filter(|c| c.packed_offset < plan.fetch_from).collect();
                    let articles: std::collections::BTreeSet<u64> =
                        before.iter().map(|c| c.packed_offset / ARTICLE).collect();
                    (before.len(), before.iter().map(|c| c.header_len()).sum::<u64>(), articles.len())
                });
                eprintln!(
                    "{set} member {i} target {target}: restart {} ({} back), {} ms; bulk {} of {} packed bytes from {}; \
                     header walk before it (chunks, header bytes, {}-byte pieces touched): {:?}",
                    res.output,
                    res.redecode,
                    started.elapsed().as_millis(),
                    folder_len - plan.fetch_from,
                    folder_len,
                    plan.fetch_from,
                    ARTICLE,
                    walk
                );
                assert_eq!(res.bytes, plain[res.output as usize..], "{set} member {i} target {target}");
            }
        }
    }
}

/// prybar-fc's 7z failover fixture (7-Zip -mx5 -mmt, 310 MB): a run of stored chunks that the next LZMA chunk continues
/// the state over is no restart; complete_lzma2 names the nearest real one (`FetchFrom`), and from there the output is
/// exact. Set ZIPFAST_FEED_FIXTURES to the directory holding payload.bin and 7z_lzma2/.
#[test]
fn lzma2_failover_never_restarts_in_a_stored_run_the_state_continues_over() {
    let Some(dir) = std::env::var_os("ZIPFAST_FEED_FIXTURES").map(std::path::PathBuf::from) else {
        eprintln!("skipped: set ZIPFAST_FEED_FIXTURES to prybar-fc's feed fixtures directory");
        return;
    };
    let plain = std::fs::read(dir.join("payload.bin")).unwrap();
    let mut names: Vec<_> = std::fs::read_dir(dir.join("7z_lzma2")).unwrap().map(|e| e.unwrap().path()).collect();
    names.sort();
    let vols: Vec<Vec<u8>> = names.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, "set.7z.001", None).unwrap();
    let mut stream = Vec::new();
    for s in &map.folders[0].packed {
        stream.extend_from_slice(&vols[s.volume as usize][s.packed.start as usize..s.packed.end as usize]);
    }
    let index = map.lzma2_chunks(0, &refs, Default::default()).unwrap();
    let opts = Lzma2DecodeOptions { max_output: 1 << 34, ..Lzma2DecodeOptions::default() };
    for frac in [0.25f64, 0.5, 0.9] {
        let target = (plain.len() as f64 * frac) as u64;
        let plan = open_at(&map, 0, target, &OpenAtOptions::default()).unwrap();
        let Start::Lzma2 { ref donor, .. } = plan.start else { panic!("{:?}", plan.start) };
        let mut from = plan.fetch_from;
        let mut known_base = donor.start;
        let r = loop {
            match complete_lzma2(
                &map,
                &plan,
                from,
                &stream[from as usize..],
                known_base,
                &plain[known_base as usize..donor.end as usize],
                Some(&index),
                &opts,
            ) {
                Err(OpenAtError::FetchFrom { packed, output }) if packed < from => {
                    from = packed;
                    known_base = output.saturating_sub(1 << 26).min(known_base);
                }
                other => break other.unwrap(),
            }
        };
        let s = r.output as usize;
        assert!(r.bytes == plain[s..s + r.bytes.len()] && s + r.bytes.len() == plain.len(), "{frac}");
    }
}
