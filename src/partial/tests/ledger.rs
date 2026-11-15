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

use crate::partial::*;
use crate::progressive::*;
use std::{
    fs,
    ops::Range,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
#[derive(Default)]
pub(super) struct Store {
    pub value: Mutex<Option<StateAnchor>>,
    pub calls: AtomicUsize,
    pub fail: Mutex<Option<(usize, bool)>>,
}
impl StateAnchorStore for Store {
    fn current(&self, _: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        Ok(self.value.lock().unwrap().clone())
    }
    fn compare_exchange(&self, _: &MemberKey, expected: Option<&StateAnchor>, next: &StateAnchor) -> PartialResult<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let failure = *self.fail.lock().unwrap();
        if failure == Some((call, false)) {
            return Err(PartialError::new(PartialErrorKind::AnchorConflict));
        }
        let mut value = self.value.lock().unwrap();
        if value.as_ref() != expected {
            return Err(PartialError::new(PartialErrorKind::AnchorConflict));
        }
        *value = Some(next.clone());
        if failure == Some((call, true)) {
            return Err(PartialError::new(PartialErrorKind::AnchorConflict));
        }
        Ok(())
    }
}
pub(super) struct Fixture {
    pub dir: tempfile::TempDir,
    pub data: Vec<u8>,
    pub member: MemberKey,
    pub store: Arc<Store>,
    pub evidence: InitialEvidence,
    pub checks: MemberChecks,
}
impl Fixture {
    pub fn new(size: usize, split: bool, crc: bool, blake: bool) -> Self {
        Self::with_hashes(size, split, crc, blake, false)
    }
    pub fn with_hashes(size: usize, split: bool, crc: bool, blake: bool, nonfinal_only: bool) -> Self {
        use crate::rar5::{
            framing::{HeaderParser, ParserStep},
            reader::Block,
        };
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("out")).unwrap();
        fs::create_dir(dir.path().join("state")).unwrap();
        let data = (0..size).map(|i| ((i * 31 + 7) % 251) as u8).collect::<Vec<_>>();
        let ranges: Vec<Range<usize>> = if split {
            assert!(size > 17);
            vec![0..17, 17..size]
        } else {
            std::iter::once(0..size).collect::<Vec<_>>()
        };
        let mut parts = Vec::new();
        let mut admissions = Vec::new();
        let mut headers = Vec::new();
        let mut metadata = None;
        for (index, range) in ranges.iter().enumerate() {
            let final_part = index + 1 == ranges.len();
            let scope = if final_part { data.as_slice() } else { &data[range.clone()] };
            let mut spec = super::rar_fixture::FileSpec::new("member.bin", &data);
            spec.no_crc = !crc;
            if blake && (!nonfinal_only || !final_part) {
                spec.extra.extend(super::rar_fixture::blake_record(super::rar_fixture::blake(scope)));
            }
            let bytes = super::rar_fixture::file_block(
                &spec,
                &data[range.clone()],
                crate::crc32::hash(scope),
                index != 0,
                !final_part,
            );
            let expected = std::ffi::OsString::from(format!("part{index}.rar"));
            let mut parser =
                HeaderParser::progressive(expected.clone().into(), 0, Usage::new(ProgressiveLimits::default()));
            let mut step = parser.advance(&[]).unwrap().1;
            let frame = loop {
                match step {
                    ParserStep::Need { offset, len } => {
                        step = parser.advance(&bytes[offset as usize..offset as usize + len]).unwrap().1
                    }
                    ParserStep::Frame(frame) => break frame,
                    _ => panic!("real Stored fixture header"),
                }
            };
            let Block::File(header) = frame.block else { panic!("real file header") };
            if index == 0 {
                metadata = Some((&header).into());
            }
            parts.push(PlainPart {
                ordinal: index as u64,
                packed: PackedSpan {
                    volume: index as u32,
                    range: header.data_at..header.data_at + (range.end - range.start) as u64,
                },
                out: range.start as u64..range.end as u64,
                final_part,
                crc32: header.crc32,
                blake2sp: header.blake2sp,
            });
            admissions.push(SourceAdmission {
                volume: index as u32,
                info: SourceInfo {
                    id: SourceId(index as u128 + 1),
                    generation: 1,
                    extent: bytes.len() as u64,
                    length: SourceLength::Final(bytes.len() as u64),
                },
                expected,
            });
            headers.push(HeaderWitness {
                volume: index as u32,
                packed: frame.extent.clone(),
                bytes: bytes[frame.extent.start as usize..frame.extent.end as usize].to_vec(),
            });
        }
        let checks = MemberChecks {
            size: size as u64,
            crc32: crc.then(|| crate::crc32::hash(&data)),
            blake2sp: (blake && !nonfinal_only).then(|| super::rar_fixture::blake(&data)),
        };
        Self {
            dir,
            data,
            member: MemberKey::new(ArchiveBinding { job: [5; 16], archive: [6; 32] }, 0, [7; 32]),
            store: Arc::new(Store::default()),
            evidence: InitialEvidence {
                format: crate::rar5::RarFormat::Rar5,
                metadata: metadata.unwrap(),
                parts,
                admissions,
                headers,
            },
            checks,
        }
    }
    pub fn protection(&self) -> ProtectionDeclaration {
        ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: self
                    .evidence
                    .admissions
                    .iter()
                    .map(|a| ProtectedVolume {
                        index: a.volume,
                        name: a.expected.clone(),
                        backing: VolumeBacking::NonFile,
                    })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        }
    }
    pub fn create(&self) -> PartialFile {
        self.create_with(PartialLimits::default(), ProgressiveLimits::default()).unwrap()
    }
    pub fn create_with(&self, limits: PartialLimits, progressive: ProgressiveLimits) -> PartialResult<PartialFile> {
        let spec = CreateSpec {
            member: self.member.clone(),
            name: Arc::from(b"member.bin".as_slice()),
            output_root: self.dir.path().join("out"),
            state_root: self.dir.path().join("state"),
            relative_output: "member.bin".into(),
            size: self.data.len() as u64,
            protection: self.protection(),
            evidence: self.evidence.clone(),
        };
        let read_chunk = progressive.read_chunk;
        let usage = Usage::new(progressive);
        let options = CoreOptions {
            limits,
            usage: usage.clone(),
            read_chunk,
            anchors: self.store.clone(),
            control: SessionControl::default(),
            exclusions: Arc::new(PartialExclusions::new(usage)),
        };
        Ok(PartialFile::from_core(PartialCore::create(spec, self.checks.clone(), options)?))
    }
    // Model an extraction whose real parsed parts were all reported missing.
    // Run the canonical machine to completion before committing that fact.
    pub fn finish_missing_member(&self, file: &PartialFile) {
        use crate::rar5::{
            framing::{HeaderParser, ParserStep},
            member::{MemberMachine, RecoverySink},
            physical::{PhysicalMember, PhysicalPart},
            reader::Block,
            unpack::Sink,
        };
        struct Missing;
        impl Sink for Missing {
            fn put(&mut self, bytes: &[u8]) -> crate::error::Result<()> {
                assert!(bytes.is_empty());
                Ok(())
            }
        }
        impl RecoverySink for Missing {
            fn hole(&mut self, _: u64) -> crate::error::Result<()> {
                Ok(())
            }
        }
        let usage = Usage::new(ProgressiveLimits::default());
        let mut machine: Option<MemberMachine> = None;
        let mut member: Option<PhysicalMember> = None;
        for (index, witness) in self.evidence.headers.iter().enumerate() {
            let mut parser = HeaderParser::progressive(
                self.evidence.admissions[index].expected.clone().into(),
                witness.packed.start,
                usage.clone(),
            );
            let mut step = parser.advance(&[]).unwrap().1;
            let frame = loop {
                match step {
                    ParserStep::Need { offset, len } => {
                        let at = (offset - witness.packed.start) as usize;
                        step = parser.advance(&witness.bytes[at..at + len]).unwrap().1;
                    }
                    ParserStep::Frame(frame) => break frame,
                    _ => panic!("canonical file frame"),
                }
            };
            let Block::File(header) = frame.block else { panic!("canonical file") };
            let wire = frame.wire.unwrap();
            let part = PhysicalPart::new(index, &header, frame.crypt, &wire);
            if machine.is_none() {
                let context = crate::extract::EntryContext {
                    entry: crate::extract::RarEntryIdentity { index: Some(0), order: 0, name: header.name.clone() },
                    method: header.method,
                    password: crate::error::RarPasswordEvidence::NotEncrypted,
                };
                machine = Some(MemberMachine::new(&header, context, None, &usage, &SessionControl::default()).unwrap());
                member = Some(PhysicalMember::new(header, wire, 0, &part).unwrap());
            } else {
                member.as_mut().unwrap().append(&header, &part).unwrap();
            }
            let machine = machine.as_mut().unwrap();
            machine.begin_part(&part);
            machine.feed_stored(None, part.packed_size as usize, &mut Missing).unwrap();
            machine.finish_part(&part).unwrap();
        }
        let mut machine = machine.unwrap();
        machine.finish_decode(&mut Missing).unwrap();
        machine.finish_member(&member.unwrap()).unwrap();
        file.core.finish_member().unwrap();
    }
    pub fn context(&self) -> PartialOpenContext {
        PartialOpenContext {
            output_root: self.dir.path().join("out"),
            state_root: self.dir.path().join("state"),
            expected_member: self.member.clone(),
            expected_anchor: self.store.current(&self.member).unwrap().unwrap(),
            protection: self.protection(),
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors: self.store.clone(),
            control: SessionControl::default(),
            password: None,
        }
    }
    pub fn output(&self) -> std::path::PathBuf {
        self.dir.path().join("out/member.bin")
    }
    pub fn report(&self, file: &PartialFile, out: Range<u64>) -> HoleReport {
        let op = file.core.operation().unwrap();
        let revision = op.snapshot.head.revision + 1;
        drop(op);
        let packed = self
            .evidence
            .parts
            .iter()
            .filter_map(|p| {
                let a = out.start.max(p.out.start);
                let b = out.end.min(p.out.end);
                (a < b).then(|| PackedSpan {
                    volume: p.packed.volume,
                    range: p.packed.range.start + a - p.out.start..p.packed.range.start + b - p.out.start,
                })
            })
            .collect();
        HoleReport {
            id: revision,
            revision,
            member: self.member.clone(),
            name: Arc::from(b"member.bin".as_slice()),
            out,
            packed,
            cause: HoleCause::Missing,
        }
    }
    pub fn hole(&self, file: &PartialFile, out: Range<u64>) {
        file.core.record_hole(self.report(file, out)).unwrap();
    }
}
// A later mismatch must prevent the earlier unknown gap from being written.
#[test]
fn fill_compares_every_overlap_before_mutation() {
    let f = Fixture::new(65_537, true, true, false);
    let file = f.create();
    f.hole(&file, 0..8);
    file.core.write_original(8, &f.data[8..17]).unwrap();
    f.hole(&file, 17..24);
    file.core.write_original(24, &f.data[24..33]).unwrap();
    let before = fs::read(f.output()).unwrap();
    let calls = f.store.calls.load(Ordering::SeqCst);
    let mut wrong = f.data[..33].to_vec();
    wrong[26] ^= 1;
    assert!(matches!(file.core.fill_plain(0, &wrong).unwrap_err().kind, PartialErrorKind::OverlapMismatch { .. }));
    assert_eq!(fs::read(f.output()).unwrap(), before);
    assert_eq!(f.store.calls.load(Ordering::SeqCst), calls);
    let result = file.core.fill_plain(0, &f.data[..33]).unwrap();
    assert_eq!(result.applied, vec![0..8, 17..24]);
    assert_eq!(&fs::read(f.output()).unwrap()[..33], &f.data[..33]);
}
// Part/leaf boundaries and a subhole must retain valid fragments with real hashers.
#[test]
fn crc_leaf_split_rehashes_fragments() {
    let f = Fixture::new(65_537, true, true, false);
    let file = f.create();
    file.core.write_original(0, &f.data).unwrap();
    {
        let op = file.core.operation().unwrap();
        assert_eq!(
            op.snapshot.known.iter().map(|l| l.range.clone()).collect::<Vec<_>>(),
            vec![0..17, 17..65_536, 65_536..65_537]
        );
    }
    f.hole(&file, 8..24);
    assert_eq!(file.remaining().unwrap(), vec![8..24]);
    {
        let op = file.core.operation().unwrap();
        for leaf in &op.snapshot.known {
            assert_eq!(
                leaf.hasher.clone().finalize(),
                crate::crc32::hash(&f.data[leaf.range.start as usize..leaf.range.end as usize])
            );
        }
    }
    file.core.fill_plain(8, &f.data[8..24]).unwrap();
    assert!(file.remaining().unwrap().is_empty());
    assert_eq!(fs::read(f.output()).unwrap(), f.data);
}
#[test]
fn empty_fill_validates_offset_and_unproduced_geometry() {
    let f = Fixture::new(33, true, true, false);
    let file = f.create();
    let before = file.state().unwrap();
    assert!(file.core.fill_plain(34, &[]).is_err());
    assert!(file.core.fill_plain(32, &[1, 2]).is_err());
    let empty = file.core.fill_plain(33, &[]).unwrap();
    assert!(empty.applied.is_empty());
    assert_eq!(empty.state.anchor(), before.anchor());
}

#[test]
fn fill_requires_observed_holes_not_preallocated_geometry() {
    let f = Fixture::new(33, true, true, false);
    let file = f.create();
    let before = file.state().unwrap();
    let calls = f.store.calls.load(Ordering::SeqCst);
    let output = fs::read(f.output()).unwrap();
    assert!(file.core.fill_plain(0, &f.data[..17]).is_err());
    assert_eq!(file.state().unwrap().anchor(), before.anchor());
    assert_eq!(f.store.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fs::read(f.output()).unwrap(), output);
    f.hole(&file, 0..17);
    file.core.fill_plain(0, &f.data[..17]).unwrap();
    assert!(file.core.fill_plain(17, &f.data[17..]).is_err());
    let before = file.state().unwrap();
    assert!(file.core.fill_plain(0, &f.data[..17]).unwrap().applied.is_empty());
    assert_eq!(file.state().unwrap().anchor(), before.anchor());
    f.hole(&file, 17..33);
    file.core.fill_plain(17, &f.data[17..]).unwrap();
    assert!(file.remaining().unwrap().is_empty());
}

#[test]
fn part_checks_use_nonfinal_packed_scope() {
    let f = Fixture::new(65_537, true, true, false);
    let file = f.create();
    f.hole(&file, 0..65_537);
    let filled = file.core.fill_plain(0, &f.data[..17]).unwrap();
    assert_eq!(filled.part_checks.len(), 2);
    assert_eq!(filled.part_checks[0].range, 0..17);
    assert_eq!(filled.part_checks[0].crc32, CheckResult::Passed);
    assert_eq!(filled.part_checks[1].crc32, CheckResult::Pending);
    assert_eq!(filled.part_checks[0].blake2sp, CheckResult::Missing);
    let filled = file.core.fill_plain(17, &f.data[17..]).unwrap();
    assert_eq!(filled.part_checks[1].crc32, CheckResult::Passed);
}
#[test]
fn complete_blake_parts_are_pending_in_fill_result() {
    let f = Fixture::new(33, true, false, true);
    let file = f.create();
    f.hole(&file, 0..33);
    let filled = file.core.fill_plain(0, &f.data[..17]).unwrap();
    assert_eq!(filled.part_checks.len(), 2);
    assert_eq!(filled.part_checks[0].crc32, CheckResult::Missing);
    assert_eq!(filled.part_checks[0].blake2sp, CheckResult::Pending);
    assert!(filled.needs_verification);
}

#[test]
fn split_fragment_leases_survive_uncertain_cas_at_exact_cap() {
    for at in [1, 2] {
        for persisted in [false, true] {
            let f = Fixture::new(33, false, true, false);
            let limits = PartialLimits { crc_leaves: 2, ..PartialLimits::default() };
            let file = f.create_with(limits, ProgressiveLimits::default()).unwrap();
            file.core.write_original(0, &f.data).unwrap();
            let call = f.store.calls.load(Ordering::SeqCst) + at;
            *f.store.fail.lock().unwrap() = Some((call, persisted));
            let error = file.core.record_hole(f.report(&file, 10..20)).unwrap_err();
            assert!(error.committed.is_some());
            *f.store.fail.lock().unwrap() = None;
            file.core.compact().expect("explicit recovery must reuse prepared fragment leases");
            assert_eq!(
                file.remaining().unwrap(),
                if at == 1 && !persisted { vec![] } else { std::iter::once(10..20).collect::<Vec<_>>() }
            );
        }
    }
}
#[test]
fn fill_faults_keep_entire_intent_unknown() {
    for sync in [false, true] {
        let f = Fixture::new(33, true, true, false);
        let mut file = f.create();
        f.hole(&file, 0..33);
        file.fill(8, &f.data[8..17]).unwrap();
        if sync {
            super::state::SYNC_FAULT.set(true);
        } else {
            super::state::WRITE_FAULT.set(Some(2));
        }
        let result = file.fill(0, &f.data);
        super::state::SYNC_FAULT.set(false);
        super::state::WRITE_FAULT.set(None);
        let error = result.unwrap_err();
        assert!(matches!(error.kind, PartialErrorKind::Io { .. }));
        assert!(error.committed.is_some());
        if !sync {
            assert_eq!(error.output.unwrap().completed, 2);
        }
        assert_eq!(file.remaining().unwrap(), vec![0..8, 17..33]);
        let state = file.close().unwrap();
        let mut file = PartialFile::open(state, f.context()).unwrap();
        assert_eq!(file.remaining().unwrap(), vec![0..8, 17..33]);
        file.fill(0, &f.data).unwrap();
        assert!(file.remaining().unwrap().is_empty());
    }
}
#[test]
fn fill_leaf_and_work_caps_precede_effects() {
    for resource in [0, 1, 2] {
        for exact in [false, true] {
            let f = Fixture::new(33, true, true, false);
            let mut limits = PartialLimits::default();
            let mut progressive = ProgressiveLimits::default();
            match resource {
                0 => limits.fill_bytes = if exact { 33 } else { 32 },
                1 => limits.crc_leaves = if exact { 2 } else { 1 },
                _ => progressive.verify_work_bytes = if exact { 83 } else { 82 },
            }
            let mut file = f.create_with(limits, progressive).unwrap();
            f.hole(&file, 0..33);
            let calls = f.store.calls.load(Ordering::SeqCst);
            let before = fs::read(f.output()).unwrap();
            let result = file.fill(0, &f.data);
            if exact {
                result.unwrap();
                assert!(file.remaining().unwrap().is_empty());
            } else {
                let error = result.unwrap_err();
                assert!(matches!(error.kind, PartialErrorKind::Limit { .. } | PartialErrorKind::Progressive(_)));
                assert_eq!(f.store.calls.load(Ordering::SeqCst), calls);
                assert_eq!(fs::read(f.output()).unwrap(), before);
            }
        }
    }
}
#[test]
fn resulting_hole_intervals_are_admitted_before_fill() {
    for exact in [false, true] {
        let f = Fixture::new(33, true, true, false);
        let progressive =
            ProgressiveLimits { hole_intervals: if exact { 2 } else { 1 }, ..ProgressiveLimits::default() };
        let mut file = f.create_with(PartialLimits::default(), progressive).unwrap();
        f.hole(&file, 0..33);
        let calls = f.store.calls.load(Ordering::SeqCst);
        let result = file.fill(8, &f.data[8..17]);
        if exact {
            result.unwrap();
            assert_eq!(file.remaining().unwrap(), vec![0..8, 17..33]);
        } else {
            assert!(result.is_err());
            assert_eq!(f.store.calls.load(Ordering::SeqCst), calls);
            assert_eq!(fs::read(f.output()).unwrap(), vec![0; 33]);
        }
    }
}
#[test]
fn two_cores_fill_out_of_order_without_shared_authority() {
    let a = Fixture::new(33, true, true, false);
    let mut b = Fixture::new(33, true, true, false);
    b.member = MemberKey::new(b.member.binding().clone(), 1, [8; 32]);
    let mut fa = a.create();
    let mut fb = b.create();
    a.hole(&fa, 0..33);
    b.hole(&fb, 0..33);
    fa.fill(17, &a.data[17..]).unwrap();
    fb.fill(0, &b.data[..8]).unwrap();
    fa.fill(0, &a.data[..17]).unwrap();
    assert!(fa.remaining().unwrap().is_empty());
    assert_eq!(fb.remaining().unwrap(), vec![8..33]);
    fb.fill(8, &b.data[8..]).unwrap();
    assert!(fb.remaining().unwrap().is_empty());
}

#[test]
fn producer_cannot_skip_unobserved_output() {
    let f = Fixture::new(33, true, true, false);
    let file = f.create();
    let calls = f.store.calls.load(Ordering::SeqCst);
    assert!(file.core.write_original(8, &f.data[8..17]).is_err());
    assert!(file.core.record_hole(f.report(&file, 8..17)).is_err());
    assert_eq!(f.store.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 33]);
}

#[test]
fn filled_hole_reports_release_interval_capacity() {
    let f = Fixture::new(33, true, true, false);
    let limits = ProgressiveLimits { hole_intervals: 1, ..ProgressiveLimits::default() };
    let mut file = f.create_with(PartialLimits::default(), limits).unwrap();
    f.hole(&file, 0..17);
    file.fill(0, &f.data[..17]).unwrap();
    f.hole(&file, 17..33);
    file.fill(17, &f.data[17..]).unwrap();
    assert!(file.remaining().unwrap().is_empty());
}

// Empty operations need no read capacity, even after a legitimate zero-chunk reopen.
#[test]
fn reopened_unknown_empty_fills_allow_zero_read_chunk() {
    let f = Fixture::new(33, true, true, false);
    let file = f.create();
    f.hole(&file, 0..33);
    let state = file.close().unwrap();
    let anchor = state.anchor().clone();
    let calls = f.store.calls.load(Ordering::SeqCst);
    let output = fs::read(f.output()).unwrap();
    let mut context = f.context();
    context.progressive_limits.read_chunk = 0;
    let mut file = PartialFile::open(state, context).unwrap();
    for offset in [0, 33] {
        let result = file.fill(offset, &[]).expect("valid empty fill needs no read chunk");
        assert!(result.applied.is_empty());
        assert_eq!(result.state.anchor(), &anchor);
    }
    assert!(matches!(file.fill(34, &[]).unwrap_err().kind, PartialErrorKind::InvalidOptions));
    assert!(matches!(file.fill(0, &f.data[..17]).unwrap_err().kind, PartialErrorKind::InvalidOptions));
    assert_eq!(file.state().unwrap().anchor(), &anchor);
    assert_eq!(f.store.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fs::read(f.output()).unwrap(), output);
}
// Declared damage is recorded with its cause, and pages written before causes were stored decode as Missing.
#[test]
fn declared_damage_persists_cause_and_legacy_pages_decode_as_missing() {
    use crate::partial::state::{self, PageKind};
    let f = Fixture::new(65_537, true, true, false);
    let file = f.create();
    file.core.write_original(0, &f.data).unwrap();
    let part = f.evidence.parts[1].clone();
    let damaged = part.packed.range.start + 2..part.packed.range.start + 5;
    let (reports, mapped) = file.core.declare_damage(part.packed.volume, &damaged).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].out, part.out.start + 2..part.out.start + 5);
    assert!(matches!(reports[0].cause, HoleCause::DeclaredBad));
    assert_eq!(mapped, vec![damaged.clone()]);
    assert_eq!(file.remaining().unwrap(), vec![part.out.start + 2..part.out.start + 5]);
    let op = file.core.operation().unwrap();
    let (pages, _pages) = state::encode_pages(&op.snapshot, &file.core.budget).unwrap();
    let decoded = state::decode_pages(op.snapshot.head.clone(), pages.clone(), &file.core.budget, &[]).unwrap();
    assert!(matches!(decoded.holes[..], [HoleReport { cause: HoleCause::DeclaredBad, .. }]));
    let legacy = pages
        .into_iter()
        .map(|(kind, bytes)| {
            if kind != PageKind::Validity {
                return (kind, bytes);
            }
            let payload = state::page_payload(kind, &bytes).unwrap();
            (kind, state::page_bytes(kind, &payload[..payload.len() - op.snapshot.holes.len()]).unwrap())
        })
        .collect();
    let decoded = state::decode_pages(op.snapshot.head.clone(), legacy, &file.core.budget, &[]).unwrap();
    assert!(matches!(decoded.holes[..], [HoleReport { cause: HoleCause::Missing, .. }]));
    // States whose holes are all Missing carry no cause section, so older builds can still read them.
    let (mut missing_only, _copy) = file.core.clone_snapshot(&op.snapshot).unwrap();
    missing_only.holes[0].cause = HoleCause::Missing;
    let validity = |pages: Vec<(PageKind, Vec<u8>)>| {
        let (kind, bytes) = pages.into_iter().find(|(kind, _)| *kind == PageKind::Validity).unwrap();
        state::page_payload(kind, &bytes).unwrap().len()
    };
    let with_causes = validity(state::encode_pages(&op.snapshot, &file.core.budget).unwrap().0);
    let without = validity(state::encode_pages(&missing_only, &file.core.budget).unwrap().0);
    assert_eq!(with_causes - without, op.snapshot.holes.len());
}
