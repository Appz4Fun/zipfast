//! The quick open check reads the block header at the locator's target in fixed pieces and within the catalogue's
//! read budget. A locator pointing at a large header-size field costs no large allocation, and a target that would
//! overrun the read budget is reported as not checked rather than failing the open.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

use zipfast::rar5::session::{RarCatalogueLimits, RarQuickOpen, RarSession, RarSessionOptions};

/// Records the largest single allocation made while `WATCH` is set.
struct Largest;
static WATCH: AtomicBool = AtomicBool::new(false);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every request is passed to System with its original layout.
unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if WATCH.load(Relaxed) {
            LARGEST.fetch_max(layout.size(), Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Largest = Largest;

/// r5extra.rar with its quick open offset set to 20, which lands on a header-size field of about 1.05 MB, plus
/// enough trailing bytes after the archive for that header to fit in the volume.
fn big_header_target() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar5-compat/r5extra.rar");
    let mut b = std::fs::read(path).unwrap();
    b[0x27] = 1; // quick open offset only
    b[0x28] = 20;
    let crc = crc32fast::hash(&b[12..47]);
    b[8..12].copy_from_slice(&crc.to_le_bytes());
    b.resize(b.len() + 1_200_000, 0);
    b
}

fn open(bytes: &[u8], limits: RarCatalogueLimits) -> RarQuickOpen {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.rar");
    std::fs::write(&path, bytes).unwrap();
    let options = RarSessionOptions { limits, follow_volumes: false, ..RarSessionOptions::default() };
    LARGEST.store(0, Relaxed);
    WATCH.store(true, Relaxed);
    let session = RarSession::open(&path, None, options);
    WATCH.store(false, Relaxed);
    let session = session.unwrap();
    assert_eq!(session.headers().filter(|h| !h.is_service()).count(), 2, "the files are still listed");
    session.volumes().next().unwrap().quick_open()
}

#[test]
fn a_large_header_at_the_quick_open_target_costs_no_large_allocation_and_respects_the_read_budget() {
    let bytes = big_header_target();
    // The size field fits the volume now, so the header is read and its CRC fails: UnRAR's corrupt main header.
    assert_eq!(open(&bytes, RarCatalogueLimits::default()), RarQuickOpen::Corrupt);
    let largest = LARGEST.load(Relaxed);
    assert!(largest < 256 << 10, "largest allocation during the open: {largest} bytes");
    // A target that would overrun the read budget is not checked, and the open still succeeds.
    // enough for the archive's own headers, not for the 1 MB block at the quick open target
    let limits = RarCatalogueLimits { read_bytes: 64 << 10, ..RarCatalogueLimits::default() };
    assert_eq!(open(&bytes, limits), RarQuickOpen::Unchecked);
}

/// The check is optional and never fails the open: at every read budget, an archive whose locator points at a
/// corrupt header opens exactly when the same archive without a locator does, and a budget that leaves too little
/// for the probe gives `Unchecked`.
#[test]
fn the_quick_open_check_never_fails_an_open_at_any_read_budget() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar5-compat/r5extra.rar");
    let with = std::fs::read(path).unwrap();
    let mut without = with.clone();
    without[0x27] = 0; // locator flags: no offsets
    let crc = crc32fast::hash(&without[12..47]);
    without[8..12].copy_from_slice(&crc.to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let open = |bytes: &[u8], read_bytes: u64| {
        let path = dir.path().join("a.rar");
        std::fs::write(&path, bytes).unwrap();
        let limits = RarCatalogueLimits { read_bytes, ..RarCatalogueLimits::default() };
        let options = RarSessionOptions { limits, follow_volumes: false, ..RarSessionOptions::default() };
        RarSession::open(&path, None, options).ok().map(|s| s.volumes().next().unwrap().quick_open())
    };
    let mut unchecked = 0;
    for read_bytes in 0..=with.len() as u64 + 64 {
        let plain = open(&without, read_bytes);
        let located = open(&with, read_bytes);
        assert_eq!(plain.is_some(), located.is_some(), "read budget {read_bytes}: the check changed whether it opens");
        match located {
            Some(RarQuickOpen::Unchecked) => unchecked += 1,
            Some(status) => assert_eq!(status, RarQuickOpen::Corrupt, "read budget {read_bytes}"),
            None => {}
        }
    }
    assert!(unchecked > 0, "some budget fits the headers but not the probe");
}

/// A multi-volume RAR 5.0 set whose main headers carry a locator pointing at the file header after them (a valid
/// target), or, with `located` false, the same record under an unknown type, so every byte read is the same but no
/// quick open check runs.
fn locator_set(located: bool) -> Vec<Vec<u8>> {
    use common::{FileSpec, SIG, block, end_block, file_block, vint};
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let spec = FileSpec::new("big.bin", &data);
    let parts: Vec<&[u8]> = data.chunks(1000).collect();
    let main = |i: usize, quick_open: u8| {
        let mut fields = Vec::new();
        vint(if i == 0 { 1 } else { 3 }, &mut fields); // volume, and a volume number after the first
        if i > 0 {
            vint(i as u64, &mut fields);
        }
        // locator record: size 3, type 1 (or an unknown 0x7e), flags 1 (quick open), offset
        let extra = [3, if located { 1 } else { 0x7e }, 1, quick_open];
        block(1, 0, &fields, &extra, &[], false)
    };
    (0..parts.len())
        .map(|i| {
            let target = main(i, 0).len() as u8; // the file header right after the main header
            let mut out = SIG.to_vec();
            out.extend(main(i, target));
            let last = i + 1 == parts.len();
            let crc = if last { crc32fast::hash(&data) } else { crc32fast::hash(parts[i]) };
            out.extend(file_block(&spec, parts[i], crc, i > 0, !last));
            out.extend(end_block(!last));
            out
        })
        .collect()
}

/// With several volumes the checks run after every volume's required headers are read: at every read budget the set
/// with locators opens exactly when the same set without them does, and a budget that leaves too little for the
/// checks still opens, with `Unchecked` volumes.
#[test]
fn quick_open_checks_never_take_budget_a_later_volume_needs() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, set: &[Vec<u8>]| {
        for (i, v) in set.iter().enumerate() {
            std::fs::write(dir.path().join(format!("{name}.part{}.rar", i + 1)), v).unwrap();
        }
        dir.path().join(format!("{name}.part1.rar"))
    };
    let with = write("with", &locator_set(true));
    let without = write("without", &locator_set(false));
    let total: u64 = locator_set(true).iter().map(|v| v.len() as u64).sum();
    let open = |path: &Path, read_bytes: u64| {
        let limits = RarCatalogueLimits { read_bytes, ..RarCatalogueLimits::default() };
        let options = RarSessionOptions { limits, ..RarSessionOptions::default() };
        RarSession::open(path, None, options).ok().map(|s| s.volumes().map(|v| v.quick_open()).collect::<Vec<_>>())
    };
    assert_eq!(open(&with, 1 << 20).unwrap(), vec![RarQuickOpen::Valid; 3], "every locator is checked with room");
    let mut partly_unchecked = 0;
    for read_bytes in 0..=total + 64 {
        let plain = open(&without, read_bytes);
        let located = open(&with, read_bytes);
        assert_eq!(plain.is_some(), located.is_some(), "read budget {read_bytes}: the checks changed whether it opens");
        if let Some(statuses) = located {
            assert_eq!(statuses.len(), 3);
            assert!(
                statuses.iter().all(|s| matches!(s, RarQuickOpen::Valid | RarQuickOpen::Unchecked)),
                "{statuses:?}"
            );
            if statuses.contains(&RarQuickOpen::Unchecked) {
                partly_unchecked += 1;
            }
        }
    }
    assert!(partly_unchecked > 0, "some budget fits every volume's headers but not every check");
}
