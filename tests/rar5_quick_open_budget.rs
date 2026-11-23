//! The quick open check reads the block header at the locator's target in fixed pieces and within the catalogue's
//! read budget. A locator pointing at a large header-size field costs no large allocation, and a target that would
//! overrun the read budget is reported as not checked rather than failing the open.

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
