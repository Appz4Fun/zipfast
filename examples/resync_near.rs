//! Times [`resync_near`] at target output offsets of a real RAR 5.0 member, the way a handover asks: the known
//! plaintext ends at the target, the packed position is estimated from the member's packing ratio, and the decoder
//! is resumed at the restart with that plaintext only, then checked against the whole plaintext.
//!
//! `cargo run --release --example resync_near -- <set dir> <password> <plaintext file> <target>...`

use std::time::Instant;
use zipfast::crypto::{decrypt_cbc, derive_rar5_key};
use zipfast::map::{CipherParams, MemberMap};
use zipfast::rar5::unpack::{NearOptions, Sink, Unpacker, resync_near, window_for};

struct Collect(Vec<u8>);
impl Sink for Collect {
    fn put(&mut self, bytes: &[u8]) -> zipfast::Result<()> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::Path::new(&args[1]);
    let password = &args[2];
    let plain = std::fs::read(&args[3]).unwrap();
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".rar"))
        .collect();
    names.sort();
    let vols: Vec<Vec<u8>> = names.iter().map(|n| std::fs::read(dir.join(n)).unwrap()).collect();
    let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, &names[0], Some(password)).unwrap();
    let m = map.members.iter().find(|m| m.unpacked_size == Some(plain.len() as u64)).expect("member");
    let mut packed: Vec<u8> = Vec::new();
    for p in &m.pieces {
        packed.extend_from_slice(&vols[p.volume as usize][p.packed.start as usize..p.packed.end as usize]);
    }
    if let Some(CipherParams::Rar5 { kdf_count, salt, iv: Some(iv), check, .. }) = m.cipher.clone() {
        let key = derive_rar5_key(password, kdf_count, &salt, check).unwrap();
        packed = decrypt_cbc(&key, &iv, &packed[..packed.len() / 16 * 16]).unwrap();
    }
    let size = plain.len() as u64;
    let window = window_for(m.dictionary.unwrap_or(32 << 20), Some(size), false).unwrap();
    let ratio = size as f64 / packed.len() as f64;
    eprintln!("member {:?}: {} packed, {} out, ratio {ratio:.3}", m.name, packed.len(), size);
    for t in &args[4..] {
        let target: u64 = t.parse().unwrap();
        let known = &plain[..target as usize];
        let estimate = Some((target as f64 / ratio) as usize);
        let started = Instant::now();
        match resync_near(&packed, 0, known, window, target, &NearOptions { estimate, ..Default::default() }) {
            Ok(n) => {
                let ms = started.elapsed().as_millis();
                let check = Unpacker::resume_in_stream(window, &n.resync, 0, 0, known, Some(size)).and_then(|mut u| {
                    let mut out = Collect(Vec::new());
                    u.feed(&packed[n.resync.packed_offset..], &mut out)
                        .and_then(|()| u.finish(&mut out))
                        .map(|()| out.0)
                });
                let verdict = match check {
                    Ok(out) if out == plain[n.resync.output_offset as usize..] => "resumed output exact".to_owned(),
                    Ok(_) => "RESUMED OUTPUT DIFFERS".to_owned(),
                    Err(e) => format!("resume: {e}"),
                };
                eprintln!(
                    "target {target}: restart {} ({} back), anchor {}, work {}, {ms} ms, guarded {}; {verdict}",
                    n.resync.output_offset,
                    n.back,
                    n.anchor,
                    n.work,
                    n.resync.guarded()
                );
            }
            Err(e) => eprintln!("target {target}: {e} ({} ms)", started.elapsed().as_millis()),
        }
    }
}
