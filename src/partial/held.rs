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

//! Held output: the plaintext a persistent member already holds, read from a live handle or, read-only and without
//! the archive or its binding, from a closed state directory. See "Held output" in `docs/persistent-partials.md`.

use super::native::{bundle_name, hex};
use super::state::{self, KnownLeaf, Snapshot};
use super::types::{err, io_error, malformed};
use super::*;
use crate::progressive::OutputOperation;
use crate::progressive::native::Identity;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// What a persistent member's output already holds: the file, the member it belongs to, and the output ranges
/// known good.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct HeldOutput {
    /// The output file: the output root joined with `relative_output`.
    pub output_path: PathBuf,
    /// The output path relative to the output root, as the state records it (only normal components).
    pub relative_output: PathBuf,
    /// The member the state belongs to (its archive binding, ordinal and identity).
    pub member: MemberKey,
    /// The member's name as the archive stores it.
    pub name: Arc<[u8]>,
    /// The member's unpacked size.
    pub size: u64,
    /// The member's plaintext checks where they are known: the archive's own, or those a caller supplied to
    /// [`PartialFile::abandon_tail`]. `None` while the extraction has not read them, and for an encrypted RAR 5.0
    /// member whose checks are keyed with the password (they say nothing about plaintext without it).
    pub checks: Option<MemberChecks>,
    /// Whether the member counts as finished: its extraction reached the end, or its tail was abandoned.
    pub finished: bool,
    /// Output ranges known good, sorted, disjoint and not touching: bytes written and committed (by the extraction
    /// or by fills of plaintext from another copy) and not inside any hole. Bytes written after the last commit,
    /// and bytes declared bad, are not included.
    pub good: Vec<Range<u64>>,
}

/// Options for [`load_held`].
#[derive(Clone, Debug, Default)]
pub struct HeldOptions {
    /// Bounds on reading each bundle: record and page sizes and counts, the bundle's total record count and bytes
    /// (`journal_records`, `journal_bytes`, counting every record file, torn ones included), leaves and metadata.
    /// A bundle over a bound is skipped with `PartialErrorKind::Limit`. The defaults read any state a session with
    /// default limits wrote.
    pub limits: PartialLimits,
    /// Re-read every good range of every output file and keep only ranges whose CRC-32 still matches the one the
    /// state recorded. Costs a read of all held output. Without it, ranges are rehashed only for an output file
    /// that is not the one the state was written for (another inode, or another length), such as a copy made
    /// across file systems.
    pub rehash: bool,
}

/// A bundle [`load_held`] could not read.
#[derive(Debug)]
#[non_exhaustive]
pub struct HeldSkip {
    /// The bundle directory.
    pub bundle: PathBuf,
    /// Why: `Busy` when a session holds the bundle, `StateUnavailable` when it has no readable record,
    /// `StateMalformed`/`JournalCorrupt`/`StateVersion` for damage, an `Io` error (for example `NotFound` for the
    /// output file), or `UnsafePath` when the output file or a state file (`lock`, a record, a page) is not a
    /// regular file.
    pub error: PartialError,
}

/// What [`load_held`] found under a state directory.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct HeldScan {
    /// One entry per readable member bundle, in directory-name order.
    pub held: Vec<HeldOutput>,
    /// Bundles that could not be read, with the reason.
    pub skipped: Vec<HeldSkip>,
}

/// Reads the held output of every member bundle under `state_root`, read-only and binding-agnostic: no archive,
/// no password, no anchor store, and no check that the output root or archive are the ones the state was written
/// for. Output paths are `output_root` joined with each state's recorded relative path.
///
/// Nothing is written, created, renamed, compacted or deleted. A bundle a session holds is skipped as `Busy`:
/// each bundle's `lock` file is probed with a shared, non-blocking advisory lock for the duration of its read (a
/// session opening that bundle at that very moment gets `Busy` and can retry). Call it while no session owns the
/// state.
///
/// Which state counts: without the anchor store the newest record is taken (the highest sequence). Every record
/// is conservative for the output it describes (an intent marks the output it may change unknown, and a commit
/// is written only after its output was synced), so the newest record never claims bytes the output does not
/// hold. Records that fail their checksum (or are too short to carry one) are ignored: such a record was torn by
/// a crash during its write and never anchored, so the output never depended on it. A record whose checksum
/// holds but which is otherwise unreadable (an unknown version, a malformed field) skips the bundle; an older
/// record is never used in its place. When two records share the newest sequence (an intent whose anchor update
/// failed, retried), only output both call good is returned, and leaves they share are charged once.
///
/// Every file is opened read-only, without following a symbolic link and without blocking, so state on read-only
/// media or owned by another user is read, and a FIFO or other non-regular file in place of a state file skips
/// the bundle (`UnsafePath`) instead of stalling.
///
/// Errors are for `state_root` itself (it cannot be listed); every problem with one bundle lands in
/// [`HeldScan::skipped`]. Directory entries whose names are not bundle names are ignored.
pub fn load_held(state_root: &Path, output_root: &Path, options: &HeldOptions) -> PartialResult<HeldScan> {
    native::platform()?;
    options.limits.validate()?;
    let state_root = std::path::absolute(state_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    let output_root = std::path::absolute(output_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&state_root).map_err(|e| io_error(OutputOperation::Read, e))? {
        let entry = entry.map_err(|e| io_error(OutputOperation::Read, e))?;
        let Ok(name) = entry.file_name().into_string() else { continue };
        if name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            names.push(name);
        }
    }
    names.sort();
    let mut scan = HeldScan::default();
    for name in names {
        let bundle = state_root.join(&name);
        match held_bundle(&bundle, &name, &output_root, options) {
            Ok(held) => scan.held.push(held),
            Err(error) => scan.skipped.push(HeldSkip { bundle, error }),
        }
    }
    Ok(scan)
}

/// Opens `path` read-only, as the session's own state-file opener does: without following a symbolic link at its
/// last component and without blocking (a FIFO in its place never stalls the read). `None` when nothing is there;
/// `UnsafePath` when it is not a regular file.
fn open_regular(path: &Path) -> PartialResult<Option<std::fs::File>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(err(PartialErrorKind::UnsafePath)),
        Err(e) => return Err(io_error(OutputOperation::Read, e)),
    };
    if !file.metadata().map_err(|e| io_error(OutputOperation::Metadata, e))?.is_file() {
        return Err(err(PartialErrorKind::UnsafePath));
    }
    Ok(Some(file))
}

/// A shared, non-blocking advisory lock on an open file, released when the file is dropped. `Busy` when a session
/// holds the exclusive one.
fn probe_lock(file: &std::fs::File) -> PartialResult<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;
        // A shared lock never displaces an exclusive holder; the descriptor's drop releases it.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            let cause = std::io::Error::last_os_error();
            if cause.kind() == std::io::ErrorKind::WouldBlock {
                return Err(err(PartialErrorKind::Busy));
            }
            return Err(io_error(OutputOperation::Read, cause));
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = file;
    Ok(())
}

/// The snapshot `state` names, its pages read from `bundle` read-only (a saved state may be on read-only media or
/// owned by another user). Leaves equal to ones in `reusable` share their charge.
fn read_snapshot(
    bundle: &Path,
    state: &PartialState,
    budget: &PartialBudget,
    reusable: &[KnownLeaf],
) -> PartialResult<Snapshot> {
    let (_, _, _, head) = state::decode_record(&state.wire, &budget.limits)?;
    let mut pages = budget.vector(head.pages.len())?;
    for reference in &head.pages {
        let file = open_regular(&bundle.join(format!("p-{}", hex(&reference.digest))))?
            .ok_or_else(|| err(PartialErrorKind::StateUnavailable))?;
        let bytes = state::read_bounded(&file, reference.len as usize, budget)?;
        if bytes.len() != reference.len as usize || crate::crypto::sha256(&bytes) != reference.digest {
            return Err(err(PartialErrorKind::JournalCorrupt));
        }
        pages.push((reference.kind, bytes));
    }
    state::decode_pages(head, pages, budget, reusable)
}

fn held_bundle(bundle_path: &Path, name: &str, output_root: &Path, options: &HeldOptions) -> PartialResult<HeldOutput> {
    let meta = std::fs::symlink_metadata(bundle_path).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    if !meta.is_dir() {
        return Err(malformed());
    }
    let lock = open_regular(&bundle_path.join("lock"))?;
    if let Some(lock) = &lock {
        probe_lock(lock)?;
    }
    let usage = crate::progressive::Usage::new(crate::progressive::ProgressiveLimits::default());
    let budget = PartialBudget::new(options.limits.clone(), usage.clone(), Arc::new(PartialExclusions::new(usage)))?;
    // Every record that decodes, with its sequence.
    let mut records = Vec::new();
    // The bundle's records count against `journal_records` and `journal_bytes` as a session's own read of the
    // bundle charges them (torn ones included); the charges last for the whole read.
    let mut charges = Vec::new();
    for entry in std::fs::read_dir(bundle_path).map_err(|e| io_error(OutputOperation::Read, e))? {
        let entry = entry.map_err(|e| io_error(OutputOperation::Read, e))?;
        let file_name = entry.file_name();
        let Some(record) = file_name.to_str().filter(|n| n.starts_with("r-")) else { continue };
        // Gone since the listing (a session retired it): nothing to read.
        let Some(file) = open_regular(&bundle_path.join(record))? else { continue };
        let len = file.metadata().map_err(|e| io_error(OutputOperation::Metadata, e))?.len();
        charges.push(budget.reserve(PartialResource::JournalRecords, 1)?);
        charges.push(budget.reserve(PartialResource::JournalBytes, len)?);
        let wire = state::read_bounded(&file, options.limits.state_wire_bytes as usize, &budget)?;
        // A record torn by a crash during its write (too short for its checksum, or failing it) was never
        // anchored: ignore it. Anything else wrong with a record whose checksum holds (an unknown version, a
        // malformed field) is damage: the bundle is skipped, never read from an older record.
        if wire.len() < 4 {
            continue;
        }
        let head = match state::decode_record(&wire, &options.limits) {
            Ok((_, _, _, head)) => head,
            Err(e) if matches!(e.kind, PartialErrorKind::JournalCorrupt) => continue,
            Err(e) => return Err(e),
        };
        if bundle_name(&head.member) != name {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        records.push((head.sequence, wire));
    }
    let newest =
        records.iter().map(|(sequence, _)| *sequence).max().ok_or_else(|| err(PartialErrorKind::StateUnavailable))?;
    // The first newest record's leaves (for a rehash) and the output identity it was written for.
    let mut first: Option<(HeldOutput, Vec<KnownLeaf>, Identity)> = None;
    for (_, wire) in records.into_iter().filter(|(sequence, _)| *sequence == newest) {
        let state = PartialState::parse(wire, &options.limits)?;
        // A tied record naming the same leaves shares their charge with the first one.
        let reusable = first.as_ref().map_or(&[][..], |(_, known, _)| known.as_slice());
        let snapshot = read_snapshot(bundle_path, &state, &budget, reusable)?;
        let candidate = held_from_snapshot(&snapshot, output_root.join(&snapshot.head.relative_output));
        match &mut first {
            None => first = Some((candidate, snapshot.known, snapshot.head.binding.output)),
            Some((held, _, _)) => {
                if held.relative_output != candidate.relative_output || held.size != candidate.size {
                    return Err(malformed());
                }
                held.good = intersect(&held.good, &candidate.good);
            }
        }
    }
    let (mut held, known, identity) = first.ok_or_else(|| err(PartialErrorKind::StateUnavailable))?;
    check_output(&mut held, &known, identity, options.rehash)?;
    Ok(held)
}

/// The held output of `snapshot`, written at `output_path`.
pub(super) fn held_from_snapshot(snapshot: &Snapshot, output_path: PathBuf) -> HeldOutput {
    let head = &snapshot.head;
    let keyed = (snapshot.crypt.is_some_and(|crypt| crypt.tweaked_crc)
        || snapshot.evidence.direct.as_ref().is_some_and(|d| d.keyed.is_some()))
        && head.tail != Some(TailChecks::Supplied);
    let checks =
        (!keyed && (head.checks.crc32.is_some() || head.checks.blake2sp.is_some())).then(|| head.checks.clone());
    let mut good: Vec<Range<u64>> = snapshot.known.iter().map(|leaf| leaf.range.clone()).collect();
    good.sort_by_key(|r| r.start);
    let good = merge(good);
    let mut holes: Vec<Range<u64>> = snapshot.holes.iter().map(|hole| hole.out.clone()).collect();
    holes.sort_by_key(|r| r.start);
    let good = subtract(&good, &merge(holes));
    // A direct member has no extraction: it is finished once every byte is written.
    let finished = head.member_finished
        || (snapshot.evidence.direct.is_some() && good.first().is_some_and(|r| *r == (0..head.size)))
        || (snapshot.evidence.direct.is_some() && head.size == 0);
    HeldOutput {
        output_path,
        relative_output: head.relative_output.clone(),
        member: head.member.clone(),
        name: snapshot.name.clone(),
        size: head.size,
        checks,
        finished,
        good,
    }
}

/// Sorted ranges merged where they overlap or touch; empty ranges dropped.
fn merge(sorted: Vec<Range<u64>>) -> Vec<Range<u64>> {
    let mut out: Vec<Range<u64>> = Vec::with_capacity(sorted.len());
    for r in sorted.into_iter().filter(|r| r.start < r.end) {
        match out.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

/// `a` minus `b`, both sorted and merged.
fn subtract(a: &[Range<u64>], b: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut out = Vec::new();
    let mut j = 0;
    for r in a {
        let mut start = r.start;
        while j < b.len() && b[j].end <= start {
            j += 1;
        }
        let mut k = j;
        while k < b.len() && b[k].start < r.end {
            if b[k].start > start {
                out.push(start..b[k].start);
            }
            start = start.max(b[k].end);
            k += 1;
        }
        if start < r.end {
            out.push(start..r.end);
        }
    }
    out
}

/// `a` and `b` both cover, both sorted and merged.
fn intersect(a: &[Range<u64>], b: &[Range<u64>]) -> Vec<Range<u64>> {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < a.len() && j < b.len() {
        let start = a[i].start.max(b[j].start);
        let end = a[i].end.min(b[j].end);
        if start < end {
            out.push(start..end);
        }
        if a[i].end < b[j].end { i += 1 } else { j += 1 }
    }
    out
}

/// Checks that `held.output_path` is a regular file and, when it is not the file the state was written for (or
/// `rehash` asks), keeps only good ranges whose recorded leaf CRC-32 still matches the bytes there.
fn check_output(held: &mut HeldOutput, known: &[KnownLeaf], recorded: Identity, rehash: bool) -> PartialResult<()> {
    let meta = std::fs::symlink_metadata(&held.output_path).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    if !meta.is_file() {
        return Err(err(PartialErrorKind::UnsafePath));
    }
    let same = Identity::metadata(&meta).ok() == Some(recorded) && meta.len() == held.size;
    if same && !rehash {
        return Ok(());
    }
    let file = open_regular(&held.output_path)?
        .ok_or_else(|| io_error(OutputOperation::Read, std::io::ErrorKind::NotFound.into()))?;
    let len = file.metadata().map_err(|e| io_error(OutputOperation::Metadata, e))?.len();
    let mut buffer = vec![0u8; 1 << 20];
    let mut matching = Vec::new();
    for leaf in known {
        if leaf.range.end > len {
            continue;
        }
        let mut hasher = crate::crc32::Hasher::new();
        let mut at = leaf.range.start;
        let mut ok = true;
        while at < leaf.range.end {
            let n = ((leaf.range.end - at) as usize).min(buffer.len());
            match crate::output::range::read_at(&file, at, &mut buffer[..n]) {
                Ok(0) => {
                    ok = false;
                    break;
                }
                Ok(read) => {
                    hasher.update(&buffer[..read]);
                    at += read as u64;
                }
                Err(e) => return Err(io_error(OutputOperation::Read, e)),
            }
        }
        if ok && hasher.finalize() == leaf.crc {
            matching.push(leaf.range.clone());
        }
    }
    matching.sort_by_key(|r| r.start);
    held.good = intersect(&held.good, &merge(matching));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::single_range_in_vec_init, reason = "one-range lists are the inputs under test")]
    fn ranges_merge_subtract_and_intersect() {
        assert_eq!(merge(vec![0..5, 5..7, 9..9, 8..12, 10..11]), vec![0..7, 8..12]);
        assert_eq!(subtract(&[0..10, 20..30], &[2..4, 8..22, 29..40]), vec![0..2, 4..8, 22..29]);
        assert_eq!(subtract(&[0..10], &[]), vec![0..10]);
        assert_eq!(subtract(&[5..10], &[0..20]), Vec::<Range<u64>>::new());
        assert_eq!(intersect(&[0..10, 20..30], &[5..25]), vec![5..10, 20..25]);
        assert_eq!(intersect(&[0..10], &[10..20]), Vec::<Range<u64>>::new());
    }
}
