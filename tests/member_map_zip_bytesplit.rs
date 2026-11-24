//! Member maps of byte-split ZIP sets: `name.zip.001`, `name.zip.002`, ... (one ZIP cut anywhere, no disk numbers).

use std::{
    fs::File,
    path::Path,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::map::*;
use zipfast::progressive::{
    ProgressiveResult, RangeRead, RangeSource, SourceId, SourceInfo, SourceLength, VolumeAnswer, VolumeRequest,
    VolumeSource,
};

fn fixture() -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip-bytesplit");
    (1..=4).map(|i| std::fs::read(dir.join(format!("bytesplit.zip.{i:03}"))).unwrap()).collect()
}

fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
}

fn extract(volumes: &[Vec<u8>], map: &MemberMap, member: usize) -> Vec<u8> {
    let mut out = Vec::new();
    extract_member_from(&refs(volumes), map, member, 0, None, &mut out).unwrap();
    out
}

/// The members of `map` over `volumes` must give the bytes the single-volume map of the concatenation gives, and
/// each member's parts must cover its data piece by piece.
fn check(volumes: &[Vec<u8>]) {
    let whole = vec![volumes.concat()];
    let single = MemberMap::from_memory(&refs(&whole), "x.zip", None).unwrap();
    let map = MemberMap::from_memory(&refs(volumes), "x.zip.001", None).unwrap();
    assert_eq!(map.volumes as usize, volumes.len());
    assert!(map.complete);
    assert_eq!(map.members.len(), single.members.len());
    for (i, (m, s)) in map.members.iter().zip(&single.members).enumerate() {
        assert_eq!(m.name, s.name);
        assert_eq!(m.unpacked_size, s.unpacked_size);
        assert_eq!(m.checks, s.checks);
        assert_eq!(m.packed_size, s.packed_size);
        let total: u64 = m.pieces.iter().map(|p| p.packed.end - p.packed.start).sum();
        assert_eq!(total, s.pieces[0].packed.end - s.pieces[0].packed.start);
        for p in &m.pieces {
            assert!(p.packed.end <= volumes[p.volume as usize].len() as u64);
        }
        assert_eq!(m.pieces.iter().filter(|p| p.final_part).count(), 1);
        assert_eq!(extract(volumes, &map, i), extract(&whole, &single, i), "member {i}");
    }
}

#[test]
fn the_7zip_fixture_maps_per_piece() {
    let volumes = fixture();
    check(&volumes);
    let map = MemberMap::from_memory(&refs(&volumes), "bytesplit.zip.001", None).unwrap();
    let noise = map.members.iter().find(|m| m.name.as_deref() == Some("noise.bin")).unwrap();
    // 3000 stored bytes cross the 1 KiB cuts: one part per piece, in order.
    let vols: Vec<u32> = noise.pieces.iter().map(|p| p.volume).collect();
    assert!(vols.len() >= 3 && vols.windows(2).all(|w| w[1] == w[0] + 1), "{vols:?}");
    assert_eq!(noise.pieces[0].header.start, 0);
    assert!(noise.pieces[1..].iter().all(|p| p.header == (0..0) && p.packed.start == 0));
    assert_eq!(noise.pieces.iter().map(|p| p.stream_offset).collect::<Vec<_>>()[0], 0);
}

#[test]
fn any_cut_including_inside_headers_and_the_directory() {
    let whole = fixture().concat();
    for size in [4usize, 7, 13, 29, 64, 100, 511, 1500] {
        let volumes: Vec<Vec<u8>> = whole.chunks(size).map(<[u8]>::to_vec).collect();
        check(&volumes);
    }
}

#[derive(Default)]
struct Gate {
    ready: bool,
    wake: Option<Waker>,
}

struct Piece {
    data: Vec<u8>,
    gate: Arc<Mutex<Gate>>,
}

fn wait(gate: &Mutex<Gate>, cx: &Context<'_>) -> bool {
    let mut g = gate.lock().unwrap();
    if !g.ready {
        g.wake = Some(cx.waker().clone());
        return true;
    }
    g.ready = false;
    false
}

impl RangeSource for Piece {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(1),
            generation: 0,
            extent: self.data.len() as u64,
            length: SourceLength::Final(self.data.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        if wait(&self.gate, cx) {
            return Ok(RangeRead::NotYet);
        }
        let end = (at + buf.len().min(5) as u64).min(self.data.len() as u64);
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}

/// Gives volume `i` (asked for any number of times) while it is present, waiting before each answer.
struct Provider {
    volumes: Vec<Option<Vec<u8>>>,
    gate: Arc<Mutex<Gate>>,
    asked: Arc<Mutex<Vec<(u32, String)>>>,
}

impl VolumeSource for Provider {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        if wait(&self.gate, cx) {
            return Ok(VolumeAnswer::Wait);
        }
        self.asked.lock().unwrap().push((r.index, r.expected.to_string_lossy().into_owned()));
        Ok(match self.volumes.get(r.index as usize).cloned().flatten() {
            Some(data) => VolumeAnswer::Ready(Box::new(Piece { data, gate: self.gate.clone() })),
            None => VolumeAnswer::Missing,
        })
    }
}

fn drive(volumes: Vec<Option<Vec<u8>>>, handles: Option<u64>) -> (Result<MemberMap, MapError>, Vec<(u32, String)>) {
    let gate = Arc::new(Mutex::new(Gate::default()));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let provider = Provider { volumes, gate: gate.clone(), asked: asked.clone() };
    let mut options = MapOptions::new("s.zip.001");
    if let Some(h) = handles {
        options.limits.volume_handles = h;
    }
    let mut builder = MapBuilder::new(Box::new(provider), options);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10_000_000 {
        match builder.poll_map(&mut cx) {
            Poll::Ready(result) => return (result, asked.lock().unwrap().clone()),
            Poll::Pending => {
                let waker = {
                    let mut g = gate.lock().unwrap();
                    g.ready = true;
                    g.wake.take().expect("pending after a waker was kept")
                };
                waker.wake();
            }
        }
    }
    panic!("map did not finish");
}

#[test]
fn volume_sources_with_waits_and_few_handles_match_memory() {
    let whole = fixture().concat();
    let volumes: Vec<Vec<u8>> = whole.chunks(300).map(<[u8]>::to_vec).collect();
    let expected = MemberMap::from_memory(&refs(&volumes), "s.zip.001", None).unwrap();
    for handles in [None, Some(1), Some(2)] {
        let (map, asked) = drive(volumes.iter().cloned().map(Some).collect(), handles);
        assert_eq!(map.unwrap(), expected, "handles {handles:?}");
        // Pieces are asked for in order under names counting up, the one past the end last (and found missing).
        assert_eq!(asked[0], (0, "s.zip.001".to_owned()));
        assert_eq!(asked[1], (1, "s.zip.002".to_owned()));
        let end = (volumes.len() as u32, format!("s.zip.{:03}", volumes.len() + 1));
        assert!(asked.contains(&end), "{asked:?}");
    }
}

#[test]
fn a_missing_last_piece_is_not_a_complete_map() {
    let whole = fixture().concat();
    let volumes: Vec<Vec<u8>> = whole.chunks(300).map(<[u8]>::to_vec).collect();
    let mut cut: Vec<_> = volumes.into_iter().map(Some).collect();
    cut.pop();
    let (result, _) = drive(cut, None);
    assert!(!matches!(result, Ok(ref m) if m.complete), "{result:?}");
}
