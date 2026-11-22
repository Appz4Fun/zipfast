//! RustyGet's Z1-Z3 fixture matrix: every set of a z-fixtures directory (F01-F12) against each of its holes.
//!
//! Skipped unless `ZIPFAST_Z_FIXTURES` names the sets directory (the one holding `MANIFEST.json`, the payloads and a
//! directory per set). Run it in release:
//!
//! ```text
//! ZIPFAST_Z_FIXTURES=~/rustyget-requests/z-fixtures/sets cargo test --release --test z_fixture_matrix -- --nocapture
//! ```
//!
//! `Z_MATRIX_SETS=F01,F05` runs only the sets whose names start with those prefixes; `Z_MATRIX_OUT=<file>` writes the
//! table as Markdown. A hole is taken from the set's intact volumes as the bytes a recipient lost:
//!
//! - **Z1** (RAR 5.0 and 7z AES stored): the lost member data is rebuilt from the payload with `rebuild_cbc`, the
//!   final block from the article CRC32 when its padding is random, and must equal the volume's bytes. Header bytes in
//!   an article are not Z1's to rebuild (they come from the volume-tail rebuild or another copy) and are reported.
//! - **Z2** (RAR 5.0 compressed, decrypted when encrypted): `resync` on the packed bytes after the hole, then
//!   `Unpacker::resume_at`; the donor's plaintext before the restart plus the resumed output must equal the payload.
//!   A solid set's later member is decoded after it, from its own packed bytes.
//! - **Z3** (7z LZMA2, decrypted when encrypted): the first chunk header chain after the hole that runs to the end
//!   marker fixes its output offset (from the folder size); decoding restarts at the first stored chunk or LZMA state
//!   reset with `decode_with_dictionary`; the output must equal the payload.
//!
//! The number of output bytes the donor supplied past the hole's estimated start is reported for Z2 and Z3.

use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Instant;

use zipfast::crypto::{
    CbcRebuildError, cbc_rebuild_span, decrypt_cbc, derive_7z_key, derive_rar5_key, rebuild_cbc,
    rebuild_cbc_zero_padded, rebuild_final_block,
};
use zipfast::map::{
    CipherParams, CoderKind, Lzma2ChunkKind, Lzma2DecodeOptions, Lzma2End, Lzma2Index, Lzma2IndexOptions,
    Lzma2Position, Lzma2Reset, Lzma2Start, MapMember, MapMethod, MemberMap,
};
use zipfast::rar5::unpack::{ResyncError, Sink, Unpacker, Window, resync, window_for};

// ---------------------------------------------------------------------------------------------------------------
// A minimal JSON reader for MANIFEST.json (the crate has no JSON dependency).

#[derive(Debug, Clone)]
enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, key: &str) -> &J {
        match self {
            J::Obj(fields) => fields.iter().find(|(k, _)| k == key).map_or(&J::Null, |(_, v)| v),
            _ => &J::Null,
        }
    }
    fn str(&self) -> &str {
        if let J::Str(s) = self { s } else { "" }
    }
    fn num(&self) -> u64 {
        if let J::Num(n) = self { *n as u64 } else { 0 }
    }
    fn arr(&self) -> &[J] {
        if let J::Arr(v) = self { v } else { &[] }
    }
    fn bool(&self) -> bool {
        matches!(self, J::Bool(true))
    }
}

fn json(b: &[u8], i: &mut usize) -> J {
    let ws = |i: &mut usize| {
        while b.get(*i).is_some_and(|c| c.is_ascii_whitespace()) {
            *i += 1;
        }
    };
    ws(i);
    let v = match b[*i] {
        b'{' => {
            *i += 1;
            let mut fields = Vec::new();
            loop {
                ws(i);
                if b[*i] == b'}' {
                    *i += 1;
                    break;
                }
                let J::Str(k) = json(b, i) else { panic!("object key") };
                ws(i);
                assert_eq!(b[*i], b':');
                *i += 1;
                fields.push((k, json(b, i)));
                ws(i);
                if b[*i] == b',' {
                    *i += 1;
                }
            }
            J::Obj(fields)
        }
        b'[' => {
            *i += 1;
            let mut items = Vec::new();
            loop {
                ws(i);
                if b[*i] == b']' {
                    *i += 1;
                    break;
                }
                items.push(json(b, i));
                ws(i);
                if b[*i] == b',' {
                    *i += 1;
                }
            }
            J::Arr(items)
        }
        b'"' => {
            *i += 1;
            let mut s = String::new();
            while b[*i] != b'"' {
                if b[*i] == b'\\' {
                    *i += 1;
                    match b[*i] {
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(&b[*i + 1..*i + 5]).unwrap();
                            s.push(char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap_or('?'));
                            *i += 4;
                        }
                        c => s.push(c as char),
                    }
                    *i += 1;
                } else {
                    let start = *i;
                    while b[*i] != b'"' && b[*i] != b'\\' {
                        *i += 1;
                    }
                    s.push_str(std::str::from_utf8(&b[start..*i]).unwrap());
                }
            }
            *i += 1;
            J::Str(s)
        }
        b't' => {
            *i += 4;
            J::Bool(true)
        }
        b'f' => {
            *i += 5;
            J::Bool(false)
        }
        b'n' => {
            *i += 4;
            J::Null
        }
        _ => {
            let start = *i;
            while b.get(*i).is_some_and(|c| matches!(c, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
                *i += 1;
            }
            J::Num(std::str::from_utf8(&b[start..*i]).unwrap().parse().unwrap())
        }
    };
    ws(i);
    v
}

// ---------------------------------------------------------------------------------------------------------------
// Outcomes.

enum Outcome {
    Pass(String),
    Fail(String),
    Na(String),
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Outcome::Pass(_) => "PASS",
            Outcome::Fail(_) => "FAIL",
            Outcome::Na(_) => "n/a",
        }
    }
    fn note(&self) -> &str {
        match self {
            Outcome::Pass(n) | Outcome::Fail(n) | Outcome::Na(n) => n,
        }
    }
}

macro_rules! fail {
    ($($t:tt)*) => { return Outcome::Fail(format!($($t)*)) };
}

struct Hole {
    id: String,
    volume: usize,
    range: Range<u64>,
    crc32: u32,
}

struct Set<'a> {
    vols: Vec<Vec<u8>>,
    map: MemberMap,
    password: &'a str,
    payloads: &'a HashMap<String, Vec<u8>>,
}

/// A packed stream (a RAR member's pieces, or a 7z folder's packed spans) and where its bytes lie in the volumes.
struct Stream {
    bytes: Vec<u8>,
    /// `(volume, volume range, stream offset)` per piece, in stream order.
    spans: Vec<(usize, Range<u64>, u64)>,
}

impl Stream {
    fn new(vols: &[Vec<u8>], mut spans: Vec<(usize, Range<u64>, u64)>) -> Self {
        spans.sort_by_key(|s| s.2);
        let mut bytes = Vec::new();
        for (v, r, at) in &spans {
            assert_eq!(*at, bytes.len() as u64, "spans are back to back");
            bytes.extend_from_slice(&vols[*v][r.start as usize..r.end as usize]);
        }
        Stream { bytes, spans }
    }
    fn of_member(vols: &[Vec<u8>], m: &MapMember) -> Self {
        Self::new(vols, m.pieces.iter().map(|p| (p.volume as usize, p.packed.clone(), p.stream_offset)).collect())
    }
    /// The part of `hole` (in volume `volume`) that lies in this stream, as stream offsets.
    fn hole(&self, volume: usize, hole: &Range<u64>) -> Option<Range<u64>> {
        self.spans.iter().filter(|s| s.0 == volume).find_map(|(_, r, at)| {
            let (lo, hi) = (hole.start.max(r.start), hole.end.min(r.end));
            (lo < hi).then(|| at + (lo - r.start)..at + (hi - r.start))
        })
    }
    /// Where stream byte `s` lies: `(volume, volume offset)`.
    fn locate(&self, s: u64) -> Option<(usize, u64)> {
        self.spans
            .iter()
            .find(|(_, r, at)| s >= *at && s < at + (r.end - r.start))
            .map(|(v, r, at)| (*v, r.start + (s - at)))
    }
}

fn payload_of<'a>(set: &Set<'a>, m: &MapMember) -> Option<&'a [u8]> {
    let name = m.name.as_deref()?;
    let base = name.rsplit(['/', '\\']).next()?;
    // A renamed member (F03b) is matched by size.
    set.payloads
        .get(base)
        .or_else(|| set.payloads.values().find(|p| Some(p.len() as u64) == m.unpacked_size))
        .map(Vec::as_slice)
}

/// The members of `set`'s archive with data, in archive order.
fn data_members<'s>(set: &'s Set<'_>) -> Vec<&'s MapMember> {
    set.map.members.iter().filter(|m| !m.is_dir && m.unpacked_size.unwrap_or(0) > 0).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Z1: AES-CBC stored data rebuilt from its plaintext.

/// Rebuilds stream range `hole` of a CBC stream of plaintext `plain`, writing the rebuilt bytes into `article` (the
/// hole's bytes in volume `hole_vol`) and marking them in `covered`. `zero_pad`: 7z pads the last block with zeros.
#[allow(clippy::too_many_arguments)]
fn rebuild_into(
    key: &[u8],
    iv: [u8; 16],
    stream: &Stream,
    plain: &[u8],
    zero_pad: bool,
    hole: Range<u64>,
    article_hole: &Hole,
    article: &mut [u8],
    covered: &mut [bool],
    notes: &mut Vec<String>,
) -> Result<(), Z1Error> {
    let n = plain.len() as u64;
    let span = cbc_rebuild_span(hole.clone(), n);
    let previous: [u8; 16] = match span.previous_at {
        Some(at) => stream.bytes[at as usize..at as usize + 16].try_into().unwrap(),
        None => iv,
    };
    let check = span
        .check
        .clone()
        .map(|c| ((c.start - span.range.start) as usize, &stream.bytes[c.start as usize..c.end as usize]));
    let text = &plain[span.range.start as usize..span.range.end as usize];
    let place = |bytes: &[u8], from: u64, article: &mut [u8], covered: &mut [bool]| {
        for (i, &b) in bytes.iter().enumerate() {
            let s = from + i as u64;
            if let Some((v, off)) = stream.locate(s)
                && v == article_hole.volume
                && article_hole.range.contains(&off)
            {
                let k = (off - article_hole.range.start) as usize;
                article[k] = b;
                covered[k] = true;
            }
        }
    };
    let rebuilt = if zero_pad {
        rebuild_cbc_zero_padded(key, &previous, text, span.stream_end, check)
    } else {
        rebuild_cbc(key, &previous, text, span.stream_end, check)
    };
    match rebuilt {
        Ok(bytes) => {
            place(&bytes, span.range.start, article, covered);
            Ok(())
        }
        Err(CbcRebuildError::FinalPadding { pad }) => {
            let whole = text.len() / 16 * 16;
            let mut prev = previous;
            if whole > 0 {
                let bytes = rebuild_cbc(key, &previous, &text[..whole], false, None)
                    .map_err(|e| Z1Error::Failed(format!("{e:?}")))?;
                prev = bytes[whole - 16..].try_into().unwrap();
                place(&bytes, span.range.start, article, covered);
            }
            let block_at = span.range.start + whole as u64;
            // The final block's 16 bytes: those in the article vary with the padding; the CRC32 of the article
            // (as rebuilt so far, the rest being header bytes from another source) must match the manifest.
            let positions: Vec<Option<usize>> = (0..16u64)
                .map(|i| {
                    stream.locate(block_at + i).and_then(|(v, off)| {
                        (v == article_hole.volume && article_hole.range.contains(&off))
                            .then(|| (off - article_hole.range.start) as usize)
                    })
                })
                .collect();
            if pad > 3 {
                // The final block's article bytes stay unrebuilt: the member's data is not recovered.
                return Err(Z1Error::Unsupported(format!(
                    "final block: {pad} random padding bytes, too many to search for"
                )));
            }
            // CRC32 is affine: crc(base ^ x) = crc(base) ^ crc(x) ^ crc(0). Precompute each bit's effect.
            let mut base = article.to_vec();
            for p in positions.iter().flatten() {
                base[*p] = 0;
            }
            let c0 = zipfast::crc32::hash(&base);
            let zero = zipfast::crc32::hash(&vec![0u8; base.len()]);
            let mut basis = [[0u32; 8]; 16];
            for (i, p) in positions.iter().enumerate() {
                if let Some(p) = *p {
                    for (bit, slot) in basis[i].iter_mut().enumerate() {
                        let mut e = vec![0u8; base.len()];
                        e[p] = 1 << bit;
                        *slot = zipfast::crc32::hash(&e) ^ zero;
                    }
                }
            }
            let intact: Vec<(usize, u8)> = (0..16)
                .filter(|&i| positions[i].is_none())
                .filter_map(|i| stream.bytes.get((block_at + i as u64) as usize).map(|&b| (i, b)))
                .collect();
            let found = rebuild_final_block(key, &prev, &text[whole..], |blk| {
                if intact.iter().any(|&(i, b)| blk[i] != b) {
                    return false;
                }
                let mut c = c0;
                for (i, &byte) in blk.iter().enumerate() {
                    let mut x = byte;
                    while x != 0 {
                        let bit = x.trailing_zeros() as usize;
                        c ^= basis[i][bit];
                        x &= x - 1;
                    }
                }
                c == article_hole.crc32
            });
            match found {
                Some(blk) => {
                    notes.push(format!("final block: {pad} random padding bytes found from the article CRC32"));
                    place(&blk, block_at, article, covered);
                    Ok(())
                }
                None => Err(Z1Error::Failed(format!("no {pad}-byte padding gives the article CRC32"))),
            }
        }
        Err(e) => Err(Z1Error::Failed(format!("{e:?}"))),
    }
}

/// Why [`rebuild_into`] could not rebuild a hole's member data.
enum Z1Error {
    /// Z1 does not cover this case (reported as n/a, never as a pass).
    Unsupported(String),
    Failed(String),
}

impl Z1Error {
    fn outcome(self, what: &str) -> Outcome {
        match self {
            Z1Error::Unsupported(e) => Outcome::Na(format!("{what}: {e}")),
            Z1Error::Failed(e) => Outcome::Fail(format!("{what}: {e}")),
        }
    }
}

fn finish_z1(article: &[u8], original: &[u8], covered: &[bool], notes: Vec<String>) -> Outcome {
    let data = covered.iter().filter(|&&c| c).count();
    if data == 0 {
        return Outcome::Na(format!("hole holds no member data ({} header bytes){}", original.len(), join(&notes)));
    }
    let wrong = covered.iter().zip(article.iter().zip(original)).filter(|(c, (a, o))| **c && a != o).count();
    let header = original.len() - data;
    if wrong > 0 {
        fail!("{wrong} of {data} rebuilt data bytes differ{}", join(&notes));
    }
    let tail = if header > 0 { format!("; {header} header bytes not Z1's") } else { String::new() };
    Outcome::Pass(format!("{data} data bytes rebuilt exactly{tail}{}", join(&notes)))
}

fn join(notes: &[String]) -> String {
    if notes.is_empty() { String::new() } else { format!("; {}", notes.join("; ")) }
}

fn z1_rar(set: &Set<'_>, hole: &Hole) -> Outcome {
    let original = &set.vols[hole.volume][hole.range.start as usize..hole.range.end as usize];
    let mut article = original.to_vec();
    let mut covered = vec![false; article.len()];
    let mut notes = Vec::new();
    for m in data_members(set) {
        let stream = Stream::of_member(&set.vols, m);
        let Some(h) = stream.hole(hole.volume, &hole.range) else { continue };
        let Some(plain) = payload_of(set, m) else { fail!("no payload for {:?}", m.name) };
        let Some(CipherParams::Rar5 { kdf_count, salt, iv: Some(iv), check, .. }) = m.cipher.clone() else {
            fail!("member {:?} is not RAR 5.0 encrypted", m.name)
        };
        if m.method != MapMethod::Stored {
            fail!("member {:?} is not stored", m.name);
        }
        let key = derive_rar5_key(set.password, kdf_count, &salt, check).expect("key");
        let name = m.name.clone().unwrap_or_default();
        if let Err(e) =
            rebuild_into(&key, iv, &stream, plain, false, h.clone(), hole, &mut article, &mut covered, &mut notes)
        {
            return e.outcome(&name);
        }
        if data_members(set).len() > 1 {
            notes.push(format!("{name} stream {}..{}", h.start, h.end));
        }
    }
    finish_z1(&article, original, &covered, notes)
}

fn z1_7z(set: &Set<'_>, hole: &Hole) -> Outcome {
    let original = &set.vols[hole.volume][hole.range.start as usize..hole.range.end as usize];
    let mut article = original.to_vec();
    let mut covered = vec![false; article.len()];
    let mut notes = Vec::new();
    for folder in &set.map.folders {
        let stream = Stream::new(
            &set.vols,
            folder.packed.iter().map(|s| (s.volume as usize, s.packed.clone(), s.stream.start)).collect(),
        );
        let Some(h) = stream.hole(hole.volume, &hole.range) else { continue };
        let Some(CipherParams::SevenZipAes { num_cycles_power, salt, iv }) = folder.cipher.clone() else {
            fail!("folder {} is not 7zAES", folder.index)
        };
        let plain = folder_plain(set, folder.index);
        let key = derive_7z_key(set.password, &salt, num_cycles_power).expect("key");
        if let Err(e) = rebuild_into(&key, iv, &stream, &plain, true, h, hole, &mut article, &mut covered, &mut notes) {
            return e.outcome(&format!("folder {}", folder.index));
        }
    }
    finish_z1(&article, original, &covered, notes)
}

/// A 7z folder's output: its members' payloads in folder order.
fn folder_plain(set: &Set<'_>, index: u32) -> Vec<u8> {
    let mut members: Vec<&MapMember> =
        set.map.members.iter().filter(|m| m.folder.is_some_and(|f| f.index == index)).collect();
    members.sort_by_key(|m| m.folder.unwrap().offset);
    members.iter().flat_map(|m| payload_of(set, m).expect("payload").iter().copied()).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Decrypting the packed bytes after a hole (CBC: a block decrypts from the ciphertext block before it).

/// The packed bytes after stream hole `h`, decrypted when `key` is given, and their offset in the stream. None when
/// nothing decodable is left after the hole.
fn after_hole(stream: &[u8], h: &Range<u64>, cipher: Option<(&[u8], [u8; 16])>) -> Option<(Vec<u8>, usize)> {
    match cipher {
        None => {
            let base = h.end as usize;
            (base < stream.len()).then(|| (stream[base..].to_vec(), base))
        }
        Some((key, _iv)) => {
            // The first block whose previous ciphertext block lies wholly after the hole.
            let b = (h.end as usize).div_ceil(16) + 1;
            if b * 16 >= stream.len() {
                return None;
            }
            let iv: [u8; 16] = stream[(b - 1) * 16..b * 16].try_into().unwrap();
            let end = stream.len() / 16 * 16;
            Some((decrypt_cbc(key, &iv, &stream[b * 16..end]).expect("decrypt"), b * 16))
        }
    }
}

struct Collect(Vec<u8>);
impl Sink for Collect {
    fn put(&mut self, bytes: &[u8]) -> zipfast::Result<()> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Z2: RAR 5.0 compressed, restarted after the hole.

fn rar5_key(set: &Set<'_>, m: &MapMember) -> Option<([u8; 32], [u8; 16])> {
    match m.cipher.clone()? {
        CipherParams::Rar5 { kdf_count, salt, iv: Some(iv), check, .. } => {
            Some((derive_rar5_key(set.password, kdf_count, &salt, check).expect("key"), iv))
        }
        _ => None,
    }
}

/// A member's whole packed stream, decrypted when encrypted (the AES padding past the last block left on).
fn whole_packed(set: &Set<'_>, m: &MapMember) -> Vec<u8> {
    let stream = Stream::of_member(&set.vols, m);
    match rar5_key(set, m) {
        Some((key, iv)) => decrypt_cbc(&key, &iv, &stream.bytes[..stream.bytes.len() / 16 * 16]).expect("decrypt"),
        None => stream.bytes,
    }
}

fn z2(set: &Set<'_>, hole: &Hole) -> Outcome {
    let members = data_members(set);
    let solid = members.iter().skip(1).any(|m| m.solid);
    let payloads: Vec<&[u8]> = members.iter().map(|m| payload_of(set, m).expect("payload")).collect();
    // The member the restart happens in: the last one the hole touches.
    let Some((j, h)) = members
        .iter()
        .enumerate()
        .filter_map(|(i, m)| Stream::of_member(&set.vols, m).hole(hole.volume, &hole.range).map(|h| (i, h)))
        .next_back()
    else {
        return Outcome::Na("hole holds no member data".into());
    };
    let m = members[j];
    let stream = Stream::of_member(&set.vols, m);
    let keys = rar5_key(set, m);
    let Some((after, base)) = after_hole(&stream.bytes, &h, keys.as_ref().map(|(k, iv)| (&k[..], *iv))) else {
        return Outcome::Na(format!("hole reaches the end of {}", m.name.as_deref().unwrap_or("?")));
    };
    // Output offsets count over the solid stream: the member's output starts after the earlier members'.
    let off: u64 = if solid { payloads[..j].iter().map(|p| p.len() as u64).sum() } else { 0 };
    let known: Vec<u8> = if solid { payloads[..=j].concat() } else { payloads[j].to_vec() };
    let size = off + payloads[j].len() as u64;
    let total: u64 = if solid { payloads.iter().map(|p| p.len() as u64).sum() } else { size };
    let dict = total.next_power_of_two().max(128 << 10);
    let window = window_for(dict, Some(if solid { total } else { size }), solid).expect("window");
    let ratio = payloads[j].len() as f64 / stream.bytes.len() as f64;
    // The output where the hole starts, from below: a restart found in the intact bytes just before the hole is a
    // block start at or before it. The donor supplies at most the output from there to the restart after the hole.
    let hole_out =
        before_hole(&stream.bytes, &h, keys.as_ref().map(|(k, iv)| (&k[..], *iv)), &known, off, size, window);

    let started = Instant::now();
    let mut log = Vec::new();
    let Some((resumed, r_out, tries)) = restart_rar5(&after, base, &known, off, size, window, ratio, &mut log) else {
        fail!("no restart ({} ms): {}", started.elapsed().as_millis(), log.join(", "));
    };
    let ms = started.elapsed().as_millis();
    let (mut u, out) = resumed;
    if out.0[..] != known[r_out as usize..size as usize] {
        fail!("resumed output differs from the payload (restart at {r_out})");
    }
    // Later members of a solid stream, from their own packed bytes.
    let mut later = String::new();
    if solid {
        for (k, mk) in members.iter().enumerate().skip(j + 1) {
            let mut out = Collect(Vec::new());
            u.next_file(Some(payloads[k].len() as u64));
            let packed = whole_packed(set, mk);
            if let Err(e) = u.feed(&packed, &mut out).and_then(|()| u.finish(&mut out)) {
                fail!("member {k} after the restart: {e}");
            }
            if out.0 != payloads[k] {
                fail!("member {k} after the restart decodes wrong");
            }
            later = format!("; member {} after it decodes", k + 1);
        }
    }
    let which = if members.len() > 1 {
        format!("member {}{}, ", j + 1, if solid { " (solid)" } else { " (not solid)" })
    } else {
        String::new()
    };
    let donor = match hole_out {
        Some(at) => format!("donor <= {} B", r_out - at),
        None => "donor from the member start".to_owned(),
    };
    Outcome::Pass(format!(
        "{which}restart at output {r_out}, {donor} (hole {} B packed), {tries} tries, {ms} ms{}{later}",
        h.end - h.start,
        join(&log)
    ))
}

/// A block start at or before the hole's first output byte, found by resync in up to 256 KiB of intact packed bytes
/// before the hole. None when the hole starts within that much of the member's start (then the member start bounds
/// it) or nothing restarts there.
#[allow(clippy::too_many_arguments)]
fn before_hole(
    stream: &[u8],
    h: &Range<u64>,
    cipher: Option<(&[u8], [u8; 16])>,
    known: &[u8],
    off: u64,
    size: u64,
    window: Window,
) -> Option<u64> {
    let from = h.start.checked_sub(256 << 10)?;
    let (bytes, base) = after_hole(stream, &(0..from), cipher)?;
    let end = (h.start as usize).saturating_sub(base);
    let r = resync(&bytes[..end.min(bytes.len())], 0, known, window, off..size).ok()?;
    Some(r.output_offset)
}

type Resumed = (Unpacker, Collect);

/// Resync and resume, moving on past filters, budget exhaustion and restarts the check against the plaintext
/// rejects. Returns the resumed decoder (finished), its output, the restart's output offset and the tries made.
#[allow(clippy::too_many_arguments)]
fn restart_rar5(
    after: &[u8],
    base: usize,
    known: &[u8],
    off: u64,
    size: u64,
    window: Window,
    ratio: f64,
    log: &mut Vec<String>,
) -> Option<(Resumed, u64, usize)> {
    let mut skip = 0usize;
    let mut est = off + ((base as f64) * ratio) as u64;
    let mut floor = off;
    // The whole rest of the member first: on these sets it is as fast as a narrow range and needs no estimate (the
    // packing ratio of mixed content is far from uniform). Narrow ranges around the estimate follow when the wide
    // one is ambiguous (repeated content) or finds nothing. Z_MATRIX_NARROW=1 skips the wide range.
    let widths: &[u64] = if std::env::var_os("Z_MATRIX_NARROW").is_some() {
        &[64 << 10, 512 << 10, 4 << 20, 32 << 20]
    } else {
        &[1 << 40, 64 << 10, 512 << 10, 4 << 20, 32 << 20]
    };
    let mut tries = 0;
    while tries < 60 && skip < after.len() {
        let mut moved = false;
        for &w in widths {
            tries += 1;
            let expected = est.saturating_sub(w).max(floor)..(est + w).min(size);
            match resync(&after[skip..], 0, known, window, expected) {
                Ok(r) => {
                    let mut u = match Unpacker::resume_at(window, &r, 0, known, Some(size)) {
                        Ok(u) => u,
                        Err(e) => {
                            log.push(format!("resume_at: {e}"));
                            return None;
                        }
                    };
                    let mut out = Collect(Vec::new());
                    match u.feed(&after[skip + r.packed_offset..], &mut out).and_then(|()| u.finish(&mut out)) {
                        Ok(()) => return Some(((u, out), r.output_offset, tries)),
                        Err(zipfast::Error::BadChecksum(msg)) => {
                            log.push(format!("check refused restart at {}: {msg}", r.output_offset));
                            skip += r.packed_offset + 1;
                            floor = r.output_offset + 1;
                            est = r.output_offset;
                            moved = true;
                            break;
                        }
                        Err(e) => {
                            log.push(format!("decode after restart at {}: {e}", r.output_offset));
                            return None;
                        }
                    }
                }
                Err(ResyncError::Filter { packed_offset, output_offset, output_end }) => {
                    log.push(format!("filter at output {output_offset} to {output_end}"));
                    skip += packed_offset + 1;
                    floor = output_end;
                    est = output_end;
                    moved = true;
                    break;
                }
                Err(ResyncError::Exhausted) => {
                    log.push("exhausted".into());
                    skip += 16 << 10;
                    est += ((16u64 << 10) as f64 * ratio) as u64;
                    moved = true;
                    break;
                }
                Err(ResyncError::Ambiguous) => continue,
                Err(ResyncError::NotFound) => continue,
            }
        }
        if !moved {
            log.push("not found".into());
            skip += 64 << 10;
            est += ((64u64 << 10) as f64 * ratio) as u64;
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------
// Z3: 7z LZMA2, restarted at a stored chunk or a state reset after the hole.

fn z3(set: &Set<'_>, hole: &Hole) -> Outcome {
    let mut result = Outcome::Na("hole holds no folder data".into());
    for folder in &set.map.folders {
        let stream = Stream::new(
            &set.vols,
            folder.packed.iter().map(|s| (s.volume as usize, s.packed.clone(), s.stream.start)).collect(),
        );
        let Some(h) = stream.hole(hole.volume, &hole.range) else { continue };
        let Some(lzma2) = folder.coders.iter().find(|c| c.kind == CoderKind::Lzma2) else {
            fail!("folder {} has no LZMA2 coder", folder.index)
        };
        let dict_prop = lzma2.properties[0];
        let key = match folder.cipher.clone() {
            Some(CipherParams::SevenZipAes { num_cycles_power, salt, iv }) => {
                Some((derive_7z_key(set.password, &salt, num_cycles_power).expect("key"), iv))
            }
            _ => None,
        };
        let target = folder_plain(set, folder.index);
        let total = target.len() as u64;
        // Where the chunk the hole starts in begins, from the walk before the hole.
        let pre = match &key {
            Some((k, iv)) => decrypt_cbc(k, iv, &stream.bytes[..(h.start as usize) / 16 * 16]).expect("decrypt"),
            None => stream.bytes[..h.start as usize].to_vec(),
        };
        let hole_out = Lzma2Index::from_bytes(&pre, Lzma2IndexOptions::default()).end_position().unpacked;
        let Some((after, _base)) = after_hole(&stream.bytes, &h, key.as_ref().map(|(k, iv)| (&k[..], *iv))) else {
            return Outcome::Na("hole reaches the folder's end".into());
        };
        let started = Instant::now();
        // The first chunk header chain after the hole that runs to the end marker at the stream's end.
        let mut found = None;
        for p in 0..after.len().min(1 << 20) {
            let c = after[p];
            if !(c == 1 || c == 2 || c >= 0x80) {
                continue;
            }
            let opts = Lzma2IndexOptions {
                start: Lzma2Start::Resume(Lzma2Position { packed: 0, unpacked: 0 }),
                ..Lzma2IndexOptions::default()
            };
            let idx = Lzma2Index::from_bytes(&after[p..], opts);
            let Lzma2End::EndMarker { offset } = idx.end else { continue };
            // The end marker ends the stream (an encrypted stream has up to 15 padding bytes after it).
            if idx.chunks.len() < 2 || (after.len() - p) as u64 - (offset + 1) >= 16 {
                continue;
            }
            let rest = idx.end_position().unpacked;
            if rest > total {
                continue;
            }
            found = Some((p, idx, total - rest));
            break;
        }
        let Some((p, idx, x)) = found else { fail!("no chunk chain after the hole") };
        let packed = &after[p..];
        let chunks = &idx.chunks;
        let restartable = |c: &zipfast::map::Lzma2Chunk| {
            c.kind == Lzma2ChunkKind::Stored
                || matches!(c.reset, Lzma2Reset::State | Lzma2Reset::StateProps | Lzma2Reset::DictStateProps)
        };
        let opts = Lzma2DecodeOptions { max_output: 1 << 34, max_dictionary: 1 << 31, ..Lzma2DecodeOptions::default() };
        // A false header before the true chain can lead into it: chunk offsets counted back from the end are right
        // for the true chunks whatever the head, so the restart is the first restartable chunk that checks out
        // against the payload (a stored chunk's bytes, or one LZMA chunk decoded from the payload before it).
        let checks_out = |k: usize| -> bool {
            let c = chunks[k];
            let at = (x + c.unpacked_offset) as usize;
            let Some(want) = target.get(at..at + c.unpacked_len as usize) else { return false };
            if c.kind == Lzma2ChunkKind::Stored {
                let pl = c.payload();
                packed.get(pl.start as usize..pl.end as usize) == Some(want)
            } else {
                idx.decode_with_dictionary(k..k + 1, packed, 0, dict_prop, &target[..at], &opts)
                    .is_ok_and(|b| b == want)
            }
        };
        let Some(s) = (0..chunks.len()).find(|&k| restartable(&chunks[k]) && checks_out(k)) else {
            fail!("no restart chunk after the hole checks out")
        };
        let restart_out = x + chunks[s].unpacked_offset;
        let mut out = target[..restart_out as usize].to_vec();
        let mut i = s;
        let mut donor_extra = 0u64;
        while i < chunks.len() {
            let c = chunks[i];
            if c.kind == Lzma2ChunkKind::Stored {
                let pl = c.payload();
                out.extend_from_slice(&packed[pl.start as usize..pl.end as usize]);
                i += 1;
            } else if restartable(&c) {
                match idx.decode_with_dictionary(i..chunks.len(), packed, 0, dict_prop, &out, &opts) {
                    Ok(bytes) => out.extend_from_slice(&bytes),
                    Err(e) => fail!("decode_with_dictionary at chunk {i}: {e:?}"),
                }
                break;
            } else {
                // An LZMA chunk that continues the state (after a stored chunk): the donor covers it.
                let next = (i + 1..chunks.len()).find(|&k| restartable(&chunks[k])).unwrap_or(chunks.len());
                let to = chunks.get(next).map_or(total, |c| x + c.unpacked_offset);
                donor_extra += to - out.len() as u64;
                out.extend_from_slice(&target[out.len()..to as usize]);
                i = next;
            }
        }
        let ms = started.elapsed().as_millis();
        if out != target {
            fail!("output differs from the payload (restart at {restart_out})");
        }
        let donor = restart_out.saturating_sub(hole_out) + donor_extra;
        result = Outcome::Pass(format!(
            "restart at output {restart_out} ({:?} chunk), donor {donor} B from the hole's chunk, {ms} ms",
            chunks[s].reset
        ));
    }
    result
}

// ---------------------------------------------------------------------------------------------------------------

/// Holes the manifest does not have, for a set with two members: one article straddling the members' boundary, and
/// one in the middle of the second member's data. CRC32s are of the intact bytes.
fn synthetic_holes(set: &Set<'_>) -> Vec<Hole> {
    let members = data_members(set);
    let Some(second) = members.get(1) else { return Vec::new() };
    let article = |id: &str, volume: usize, center: u64| {
        let len = set.vols[volume].len() as u64;
        let start = center.saturating_sub(375_000).min(len.saturating_sub(750_000));
        let range = start..(start + 750_000).min(len);
        let crc32 = zipfast::crc32::hash(&set.vols[volume][range.start as usize..range.end as usize]);
        Hole { id: id.to_owned(), volume, range, crc32 }
    };
    let mut holes = Vec::new();
    if let Some(first) = second.pieces.iter().min_by_key(|p| p.stream_offset) {
        holes.push(article("synthetic:member_boundary", first.volume as usize, first.packed.start));
    }
    let mid = second.pieces.iter().map(|p| p.packed.end - p.packed.start).sum::<u64>() / 2;
    if let Some(p) = second
        .pieces
        .iter()
        .find(|p| (p.stream_offset..p.stream_offset + (p.packed.end - p.packed.start)).contains(&mid))
    {
        holes.push(article("synthetic:member2_middle", p.volume as usize, p.packed.start + (mid - p.stream_offset)));
    }
    holes
}

#[test]
fn z_fixture_matrix() {
    let Some(dir) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(PathBuf::from) else {
        eprintln!("skipped: set ZIPFAST_Z_FIXTURES to the z-fixtures sets directory");
        return;
    };
    let only: Vec<String> =
        std::env::var("Z_MATRIX_SETS").map(|s| s.split(',').map(str::to_owned).collect()).unwrap_or_default();
    let manifest = std::fs::read(dir.join("MANIFEST.json")).expect("MANIFEST.json");
    let manifest = json(&manifest, &mut 0);
    let password = manifest.get("password").str().to_owned();
    let mut payloads = HashMap::new();
    if let J::Obj(fields) = manifest.get("payloads") {
        for (name, _) in fields {
            payloads.insert(name.clone(), std::fs::read(dir.join(name)).expect("payload"));
        }
    }
    let mut rows = Vec::new();
    let mut failures = 0;
    for fixture in manifest.get("fixtures").arr() {
        let name = fixture.get("name").str();
        if !only.is_empty() && !only.iter().any(|p| name.starts_with(p.as_str())) {
            continue;
        }
        let set_dir: &Path = &dir.join(name);
        let vol_names: Vec<String> =
            fixture.get("volumes").arr().iter().map(|v| v.get("name").str().to_owned()).collect();
        let vols: Vec<Vec<u8>> = vol_names.iter().map(|v| std::fs::read(set_dir.join(v)).expect("volume")).collect();
        let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
        let map = match MemberMap::from_memory(&refs, &vol_names[0], Some(&password)) {
            Ok(map) => map,
            Err(e) => {
                rows.push((name.to_owned(), "(all)".to_owned(), Outcome::Fail(format!("map: {e:?}"))));
                failures += 1;
                continue;
            }
        };
        let set = Set { vols, map, password: &password, payloads: &payloads };
        let is_7z = vol_names[0].contains(".7z");
        let compressed = set.map.members.iter().any(|m| matches!(m.method, MapMethod::Compressed { .. }));
        let lzma2 = set.map.folders.iter().any(|f| f.coders.iter().any(|c| c.kind == CoderKind::Lzma2));
        let mut holes: Vec<(Hole, bool)> = fixture
            .get("holes")
            .arr()
            .iter()
            .map(|h| {
                let hole = Hole {
                    id: h.get("id").str().to_owned(),
                    volume: vol_names.iter().position(|v| v == h.get("volume").str()).expect("hole volume"),
                    range: h.get("offset").num()..h.get("offset").num() + h.get("length").num(),
                    crc32: u32::from_str_radix(h.get("original").get("crc32").str(), 16).expect("crc32"),
                };
                (hole, h.get("stretch").bool())
            })
            .collect();
        holes.extend(synthetic_holes(&set).into_iter().map(|h| (h, false)));
        for (hole, stretch) in holes {
            let t = Instant::now();
            let outcome = match (is_7z, compressed || lzma2) {
                (false, false) => z1_rar(&set, &hole),
                (false, true) => z2(&set, &hole),
                (true, false) => z1_7z(&set, &hole),
                (true, true) => z3(&set, &hole),
            };
            if matches!(outcome, Outcome::Fail(_)) {
                failures += 1;
            }
            let id = if stretch { format!("{} (stretch)", hole.id) } else { hole.id.clone() };
            eprintln!("{name} {id}: {} {} [{} ms]", outcome.label(), outcome.note(), t.elapsed().as_millis());
            rows.push((name.to_owned(), id, outcome));
        }
    }
    let mut table = String::from("| Set | Hole | Result | Notes |\n|---|---|---|---|\n");
    for (set, hole, o) in &rows {
        table.push_str(&format!("| {set} | {hole} | {} | {} |\n", o.label(), o.note().replace('|', "/")));
    }
    eprintln!("\n{table}");
    if let Some(out) = std::env::var_os("Z_MATRIX_OUT") {
        std::fs::write(out, &table).expect("write table");
    }
    assert_eq!(failures, 0, "{failures} set x hole checks failed");
}
