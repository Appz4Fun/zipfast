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
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Store {
    value: Mutex<Option<StateAnchor>>,
    calls: std::sync::atomic::AtomicUsize,
    currents: std::sync::atomic::AtomicUsize,
    fail: Mutex<Option<(usize, bool)>>,
    observe: Mutex<Option<(usize, std::path::PathBuf, Vec<u8>)>>,
    hook: Mutex<Option<Arc<dyn Fn(usize) + Send + Sync>>>,
}
impl StateAnchorStore for Store {
    fn current(&self, _: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        self.currents.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.value.lock().unwrap().clone())
    }
    fn compare_exchange(&self, _: &MemberKey, expected: Option<&StateAnchor>, next: &StateAnchor) -> PartialResult<()> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if let Some((at, path, expected)) = &*self.observe.lock().unwrap() {
            if *at == call {
                assert_eq!(&fs::read(path).unwrap(), expected, "output changed before intent acknowledgement");
            }
        }
        let callback = self.hook.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(call);
        }
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
    pub(super) dir: tempfile::TempDir,
    store: Arc<Store>,
    pub(super) member: MemberKey,
    evidence: InitialEvidence,
    checks: MemberChecks,
}
impl Fixture {
    pub(super) fn new() -> Self {
        Self::new_in(None)
    }
    fn new_in(parent: Option<&std::path::Path>) -> Self {
        use crate::rar5::{
            framing::{HeaderParser, ParserStep},
            reader::Block,
        };
        let dir = match parent {
            Some(parent) => tempfile::tempdir_in(parent).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::create_dir(dir.path().join("out")).unwrap();
        fs::create_dir(dir.path().join("state")).unwrap();
        let data = b"abcdefghijklmnop";
        let bytes = super::rar_fixture::file_block(
            &super::rar_fixture::FileSpec::new("member.bin", data),
            data,
            crc32fast::hash(data),
            false,
            false,
        );
        let usage = Usage::new(ProgressiveLimits::default());
        let mut parser = HeaderParser::progressive("fixture.rar".into(), 0, usage);
        let mut step = parser.advance(&[]).unwrap().1;
        let frame = loop {
            match step {
                ParserStep::Need { offset, len } => {
                    step = parser.advance(&bytes[offset as usize..offset as usize + len]).unwrap().1;
                }
                ParserStep::Frame(frame) => break frame,
                _ => panic!("Stored fixture must parse"),
            }
        };
        let Block::File(header) = frame.block else { panic!("file header required") };
        let evidence = InitialEvidence {
            metadata: (&header).into(),
            parts: vec![PlainPart {
                ordinal: 0,
                packed: PackedSpan { volume: 0, range: header.data_at..header.data_at + 16 },
                out: 0..16,
                final_part: true,
                crc32: header.crc32,
                blake2sp: header.blake2sp,
            }],
            admissions: vec![SourceAdmission {
                volume: 0,
                info: SourceInfo {
                    id: SourceId(123),
                    generation: 1,
                    extent: bytes.len() as u64,
                    length: SourceLength::Final(bytes.len() as u64),
                },
                expected: "fixture.rar".into(),
            }],
            headers: vec![HeaderWitness {
                volume: 0,
                packed: frame.extent.clone(),
                bytes: bytes[frame.extent.start as usize..frame.extent.end as usize].to_vec(),
            }],
        };
        Self {
            dir,
            store: Arc::new(Store::default()),
            member: MemberKey::new(ArchiveBinding { job: [1; 16], archive: [2; 32] }, 0, [3; 32]),
            evidence,
            checks: MemberChecks { size: 16, crc32: header.crc32, blake2sp: None },
        }
    }
    pub(super) fn protection(&self) -> ProtectionDeclaration {
        ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: vec![ProtectedVolume {
                    index: 0,
                    name: "fixture.rar".into(),
                    backing: VolumeBacking::NonFile,
                }],
                auxiliary_paths: vec![],
            },
        }
    }
    pub(super) fn create(&self) -> PartialResult<PartialFile> {
        self.create_with(PartialLimits::default(), ProgressiveLimits::default(), SessionControl::default())
    }
    pub(super) fn spec(&self) -> CreateSpec {
        CreateSpec {
            member: self.member.clone(),
            name: Arc::from(b"member.bin".as_slice()),
            output_root: self.dir.path().join("out"),
            state_root: self.dir.path().join("state"),
            relative_output: "member.bin".into(),
            size: 16,
            protection: self.protection(),
            evidence: self.evidence.clone(),
        }
    }
    pub(super) fn options(
        &self,
        limits: PartialLimits,
        progressive: ProgressiveLimits,
        control: SessionControl,
    ) -> CoreOptions {
        let read_chunk = progressive.read_chunk;
        let usage = Usage::new(progressive);
        CoreOptions {
            limits,
            usage: usage.clone(),
            read_chunk,
            anchors: self.store.clone(),
            control,
            exclusions: Arc::new(PartialExclusions::new(usage)),
        }
    }
    pub(super) fn create_with(
        &self,
        limits: PartialLimits,
        progressive: ProgressiveLimits,
        control: SessionControl,
    ) -> PartialResult<PartialFile> {
        let core = PartialCore::create(self.spec(), self.checks.clone(), self.options(limits, progressive, control))?;
        Ok(PartialFile::from_core(core))
    }
    pub(super) fn context(&self) -> PartialOpenContext {
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
        }
    }
    pub(super) fn open(&self, state: PartialState) -> PartialResult<PartialFile> {
        let anchor = self.store.current(&self.member)?.unwrap();
        PartialFile::open(
            state,
            PartialOpenContext {
                output_root: self.dir.path().join("out"),
                state_root: self.dir.path().join("state"),
                expected_member: self.member.clone(),
                expected_anchor: anchor,
                protection: self.protection(),
                limits: PartialLimits::default(),
                progressive_limits: ProgressiveLimits::default(),
                anchors: self.store.clone(),
                control: SessionControl::default(),
            },
        )
    }
    pub(super) fn fail_first_anchor(&self) {
        *self.store.fail.lock().unwrap() = Some((1, false));
    }
    pub(super) fn output(&self) -> std::path::PathBuf {
        self.dir.path().join("out/member.bin")
    }
}

// Catches create-with-truncate, delayed sizing, or TempPath drop ownership.
#[test]
fn create_is_exclusive_full_size_and_drop_preserves() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    assert_eq!(fs::metadata(f.output()).unwrap().len(), 16);
    assert_eq!(file.remaining().unwrap(), vec![0..16]);
    assert!(matches!(f.create().err().unwrap().kind, PartialErrorKind::AlreadyExists));
    let state = file.close().unwrap();
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
    let reopened = f.open(state).unwrap();
    assert_eq!(reopened.remaining().unwrap(), vec![0..16]);
}

// Catches output or bundle locking that blocks or permits a second writer.
#[test]
fn bundle_and_output_locks_are_nonblocking() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    let state = file.state().unwrap();
    assert!(matches!(f.open(state).err().unwrap().kind, PartialErrorKind::Busy));
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
}

// Catches writing before a failed intent CAS, including falsely blessing a prefix.
#[test]
fn anchored_intent_precedes_every_write() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    *f.store.fail.lock().unwrap() = Some((3, false));
    *f.store.observe.lock().unwrap() = Some((3, f.output(), vec![0; 16]));
    let error = file.core.write_original(0, b"abcd").unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::AnchorCommitUncertain));
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
    assert_eq!(file.remaining().unwrap(), vec![0..16]);
}
// Catches automatic CAS retries and guessed acknowledgement after an ambiguous return.
#[test]
fn ambiguous_cas_requires_explicit_current_retry() {
    use std::sync::atomic::Ordering::SeqCst;
    let f = Fixture::new();
    let file = f.create().unwrap();
    *f.store.fail.lock().unwrap() = Some((4, true));
    let current_calls = f.store.currents.load(SeqCst);
    let error = file.core.write_original(0, b"abcd").unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::AnchorCommitUncertain));
    assert_eq!(f.store.currents.load(SeqCst), current_calls + 1);
    assert_eq!(f.store.calls.load(SeqCst), 4);
    assert_eq!(fs::read(f.output()).unwrap(), b"abcd\0\0\0\0\0\0\0\0\0\0\0\0");
    file.core.write_original(0, b"abcd").unwrap();
    assert_eq!(f.store.currents.load(SeqCst), current_calls + 2);
    assert_eq!(f.store.calls.load(SeqCst), 4, "acknowledged retry must not rewrite output");
    assert_eq!(file.remaining().unwrap(), vec![4..16]);
}
// Catches accepting an old queue head or trusting a cached CRC after output edits.
#[test]
fn stale_or_forged_state_cannot_write() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    let old = file.state().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let latest = file.close().unwrap();
    assert!(matches!(f.open(old).err().unwrap().kind, PartialErrorKind::StateStale { .. }));
    let loaded = PartialState::load(&f.dir.path().join("state"), latest.anchor(), &PartialLimits::default()).unwrap();
    assert_eq!(loaded.anchor(), latest.anchor());
    use std::os::unix::fs::FileExt;
    fs::OpenOptions::new().write(true).open(f.output()).unwrap().write_at(b"X", 0).unwrap();
    assert!(matches!(f.open(loaded).err().unwrap().kind, PartialErrorKind::OutputChanged));
    assert_eq!(&fs::read(f.output()).unwrap()[..4], b"Xbcd");
}
// Catches compaction retiring the previous trusted head before the CAS acknowledgement.
#[test]
fn compaction_keeps_last_acknowledged_bundle() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let acknowledged = file.state().unwrap();
    *f.store.fail.lock().unwrap() = Some((5, false));
    assert!(matches!(file.core.compact().unwrap_err().kind, PartialErrorKind::AnchorCommitUncertain));
    let loaded =
        PartialState::load(&f.dir.path().join("state"), acknowledged.anchor(), &PartialLimits::default()).unwrap();
    assert_eq!(loaded.anchor(), acknowledged.anchor());
    drop(file);
    assert_eq!(f.open(loaded).unwrap().remaining().unwrap(), vec![4..16]);
}

struct DurableStore {
    path: std::path::PathBuf,
    member: MemberKey,
}
impl StateAnchorStore for DurableStore {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        assert_eq!(member, &self.member);
        match fs::read(&self.path) {
            Ok(bytes) => {
                assert_eq!(bytes.len(), 40);
                Ok(Some(StateAnchor::new(
                    member.clone(),
                    u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                    bytes[8..].try_into().unwrap(),
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(OutputOperation::Read, e)),
        }
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        use std::io::Write;
        if self.current(member)?.as_ref() != expected {
            return Err(err(PartialErrorKind::AnchorConflict));
        }
        let temp = self.path.with_extension(format!("next-{}", next.sequence()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| io_error(OutputOperation::Create, e))?;
        file.write_all(&next.sequence().to_le_bytes()).map_err(|e| io_error(OutputOperation::Write, e))?;
        file.write_all(next.digest()).map_err(|e| io_error(OutputOperation::Write, e))?;
        file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))?;
        fs::rename(&temp, &self.path).map_err(|e| io_error(OutputOperation::Write, e))?;
        fs::File::open(self.path.parent().unwrap()).unwrap().sync_all().map_err(|e| io_error(OutputOperation::Flush, e))
    }
}
#[test]
fn process_kill_child() {
    let Some(parent) = std::env::var_os("ZIPFAST_PARTIAL_KILL_ROOT") else {
        return;
    };
    let parent = std::path::PathBuf::from(parent);
    let f = Fixture::new_in(Some(&parent));
    fs::write(parent.join("fixture-path"), f.dir.path().to_str().unwrap()).unwrap();
    let store = Arc::new(DurableStore { path: parent.join("trusted-anchor"), member: f.member.clone() });
    let mut options = f.options(
        PartialLimits::default(),
        ProgressiveLimits { read_chunk: 4, ..Default::default() },
        SessionControl::default(),
    );
    options.anchors = store;
    let core = PartialCore::create(f.spec(), f.checks.clone(), options).unwrap();
    core.write_original(0, b"abcdefghijklmnop").unwrap();
}
// Catches certification of an unanchored tail and incorrect crash ordering at real fsync/CAS boundaries.
#[test]
fn crash_recovers_last_acknowledged_state() {
    use std::time::{Duration, Instant};
    for (phase, sequence, written) in [
        ("intent-sync", 1, 0),
        ("intent-cas", 2, 0),
        ("write", 2, 4),
        ("output-sync", 2, 16),
        ("commit-sync", 2, 16),
        ("commit-cas", 3, 16),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "partial::tests::state::process_kill_child", "--test-threads=1"])
            .env("ZIPFAST_PARTIAL_KILL_ROOT", root.path())
            .env("ZIPFAST_PARTIAL_KILL_AT", phase)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if root.path().join("checkpoint").exists() {
                break;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("child exited before {phase} checkpoint: {status}");
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("watchdog at {phase}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
        let path = std::path::PathBuf::from(fs::read_to_string(root.path().join("fixture-path")).unwrap());
        let template = Fixture::new();
        let anchors =
            Arc::new(DurableStore { path: root.path().join("trusted-anchor"), member: template.member.clone() });
        let anchor = anchors.current(&template.member).unwrap().unwrap();
        assert_eq!(anchor.sequence(), sequence, "{phase}");
        let state = PartialState::load(&path.join("state"), &anchor, &PartialLimits::default()).unwrap();
        let file = PartialFile::open(
            state,
            PartialOpenContext {
                output_root: path.join("out"),
                state_root: path.join("state"),
                expected_member: template.member.clone(),
                expected_anchor: anchor,
                protection: template.protection(),
                limits: PartialLimits::default(),
                progressive_limits: ProgressiveLimits { read_chunk: 4, ..Default::default() },
                anchors,
                control: SessionControl::default(),
            },
        )
        .unwrap();
        assert_eq!(file.remaining().unwrap(), if sequence == 3 { vec![] } else { vec![0..16] }, "{phase}");
        let mut expected = vec![0; 16];
        expected[..written].copy_from_slice(&b"abcdefghijklmnop"[..written]);
        assert_eq!(fs::read(path.join("out/member.bin")).unwrap(), expected, "{phase}");
    }
}

pub(crate) fn checkpoint(phase: &str) {
    if std::env::var("ZIPFAST_PARTIAL_KILL_AT").ok().as_deref() != Some(phase) {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var_os("ZIPFAST_PARTIAL_KILL_ROOT").unwrap());
    fs::write(root.join("checkpoint"), phase).unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
// Catches losing the durable intent receipt when a user CAS callback cancels.
#[test]
fn cancellation_after_acknowledged_intent_returns_its_anchor() {
    let f = Fixture::new();
    let control = SessionControl::default();
    let file = f.create_with(PartialLimits::default(), ProgressiveLimits::default(), control.clone()).unwrap();
    *f.store.hook.lock().unwrap() = Some(Arc::new(move |call| {
        if call == 3 {
            control.cancel();
        }
    }));
    let error = file.core.write_original(0, b"abcd").unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::Canceled));
    assert_eq!(error.committed.as_ref().map(StateAnchor::sequence), Some(2));
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
}
#[test]
fn reentrant_callback_child() {
    if std::env::var_os("ZIPFAST_PARTIAL_REENTRANT_CHILD").is_none() {
        return;
    }
    let f = Fixture::new();
    let file = f.create().unwrap();
    let weak = Arc::downgrade(&file.core);
    *f.store.hook.lock().unwrap() = Some(Arc::new(move |call| {
        if call == 3 {
            let core = weak.upgrade().unwrap();
            assert!(matches!(core.write_original(0, b"abcd").unwrap_err().kind, PartialErrorKind::Busy));
        }
    }));
    file.core.write_original(0, b"abcd").unwrap();
    assert_eq!(&fs::read(f.output()).unwrap()[..4], b"abcd");
}
// Catches retaining an internal mutex across a user callback, with a subprocess watchdog.
#[test]
fn reentrant_anchor_callback_is_busy_without_deadlock() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "partial::tests::state::reentrant_callback_child", "--test-threads=1"])
        .env("ZIPFAST_PARTIAL_REENTRANT_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("reentrant callback deadlocked");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

// Catches a hole update bypassing the two-CAS invalidation engine or erasing output.
#[test]
fn record_hole_invalidates_without_writing_output() {
    use std::sync::atomic::Ordering::SeqCst;
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let start = f.evidence.parts[0].packed.range.start;
    file.core
        .record_hole(HoleReport {
            id: 7,
            revision: 2,
            member: f.member.clone(),
            name: Arc::from(b"member.bin".as_slice()),
            out: 0..4,
            packed: vec![PackedSpan { volume: 0, range: start..start + 4 }],
            cause: HoleCause::Missing,
        })
        .unwrap();
    assert_eq!(f.store.calls.load(SeqCst), 6);
    assert_eq!(file.remaining().unwrap(), vec![0..16]);
    assert_eq!(&fs::read(f.output()).unwrap()[..4], b"abcd");
    let state = file.close().unwrap();
    assert_eq!(f.open(state).unwrap().remaining().unwrap(), vec![0..16]);
}
fn split_fixture() -> (Fixture, EvidenceUpdate) {
    use crate::rar5::{
        framing::{HeaderParser, ParserStep},
        reader::Block,
    };
    let mut f = Fixture::new();
    let data = b"abcdefghijklmnop";
    let part = |volume: u32, start: usize| {
        let mut spec = super::rar_fixture::FileSpec::new("member.bin", data);
        spec.size = Some(16);
        let payload = &data[start..start + 8];
        let bytes = super::rar_fixture::file_block(&spec, payload, crc32fast::hash(payload), volume != 0, volume == 0);
        let mut parser =
            HeaderParser::progressive(format!("part-{volume}.rar").into(), 0, Usage::new(ProgressiveLimits::default()));
        let mut step = parser.advance(&[]).unwrap().1;
        let frame = loop {
            match step {
                ParserStep::Need { offset, len } => {
                    step = parser.advance(&bytes[offset as usize..offset as usize + len]).unwrap().1
                }
                ParserStep::Frame(frame) => break frame,
                _ => panic!("file frame"),
            }
        };
        let Block::File(header) = frame.block else { panic!("file header") };
        InitialEvidence {
            metadata: (&header).into(),
            parts: vec![PlainPart {
                ordinal: volume as u64,
                packed: PackedSpan { volume, range: header.data_at..header.data_at + 8 },
                out: start as u64..(start + 8) as u64,
                final_part: volume == 1,
                crc32: header.crc32,
                blake2sp: None,
            }],
            admissions: vec![SourceAdmission {
                volume,
                info: SourceInfo {
                    id: SourceId(123 + volume as u128),
                    generation: 1,
                    extent: bytes.len() as u64,
                    length: SourceLength::Final(bytes.len() as u64),
                },
                expected: format!("part-{volume}.rar").into(),
            }],
            headers: vec![HeaderWitness {
                volume,
                packed: frame.extent.clone(),
                bytes: bytes[..frame.extent.end as usize].to_vec(),
            }],
        }
    };
    f.evidence = part(0, 0);
    f.checks.crc32 = None;
    let second = part(1, 8);
    (f, EvidenceUpdate { parts: second.parts, admissions: second.admissions, headers: second.headers, checks: None })
}
// Catches writing unproven ranges and losing additive canonical evidence at reopen.
#[test]
fn evidence_extension_is_anchored_and_survives_reopen() {
    let (f, update) = split_fixture();
    let mut spec = f.spec();
    spec.protection = ProtectionDeclaration::Complete {
        epoch: 1,
        inventory: ProtectionInventory {
            volumes: vec![
                ProtectedVolume { index: 0, name: "part-0.rar".into(), backing: VolumeBacking::NonFile },
                ProtectedVolume { index: 1, name: "part-1.rar".into(), backing: VolumeBacking::NonFile },
            ],
            auxiliary_paths: vec![],
        },
    };
    let core = PartialCore::create(
        spec,
        f.checks.clone(),
        f.options(PartialLimits::default(), ProgressiveLimits::default(), SessionControl::default()),
    )
    .unwrap();
    assert!(core.write_original(8, b"ijklmnop").is_err());
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
    core.extend_evidence(update).unwrap();
    let state = core.state().unwrap();
    drop(core);
    let mut context = f.context();
    context.protection = ProtectionDeclaration::Complete {
        epoch: 1,
        inventory: ProtectionInventory {
            volumes: vec![
                ProtectedVolume { index: 0, name: "part-0.rar".into(), backing: VolumeBacking::NonFile },
                ProtectedVolume { index: 1, name: "part-1.rar".into(), backing: VolumeBacking::NonFile },
            ],
            auxiliary_paths: vec![],
        },
    };
    let opened = PartialFile::open(state, context).unwrap();
    opened.core.write_original(8, b"ijklmnop").unwrap();
    assert_eq!(opened.remaining().unwrap(), vec![0..8]);
}
// Catches replacing an already witnessed part instead of rejecting contradiction.
#[test]
fn contradictory_evidence_is_rejected_before_cas() {
    use std::sync::atomic::Ordering::SeqCst;
    let f = Fixture::new();
    let file = f.create().unwrap();
    let mut changed = f.evidence.parts[0].clone();
    changed.packed.range.start += 1;
    let error = file
        .core
        .extend_evidence(EvidenceUpdate { parts: vec![changed], admissions: vec![], headers: vec![], checks: None })
        .unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::BindingMismatch(_) | PartialErrorKind::StateMalformed));
    assert_eq!(f.store.calls.load(SeqCst), 2);
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
}

// Catches a standalone fill bypassing anchored invalidation or returning another revision.
#[test]
fn plain_fill_uses_the_same_transaction_and_returns_its_state() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    let start = f.evidence.parts[0].packed.range.start;
    file.core
        .record_hole(HoleReport {
            id: 1,
            revision: 1,
            member: f.member.clone(),
            name: Arc::from(b"member.bin".as_slice()),
            out: 0..4,
            packed: vec![PackedSpan { volume: 0, range: start..start + 4 }],
            cause: HoleCause::Missing,
        })
        .unwrap();
    let result = file.core.fill_plain(0, b"abcd").unwrap();
    assert_eq!(result.revision, 2);
    assert_eq!(result.applied, vec![0..4]);
    assert!(result.needs_verification);
    assert!(result.part_checks.is_empty());
    assert_eq!(result.state.anchor(), file.state().unwrap().anchor());
    drop(file);
    assert_eq!(f.open(result.state).unwrap().remaining().unwrap(), vec![4..16]);
}

// Catches restoring cached CRC numbers as if they were actual incremental hashers.
#[test]
fn reopened_extents_rebuild_actual_hashers() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let state = file.close().unwrap();
    let file = f.open(state).unwrap();
    let operation = file.core.operation().unwrap();
    assert_eq!(operation.snapshot.known[0].hasher.clone().finalize(), crc32fast::hash(b"abcd"));
}

thread_local! {
    static WRITE_FAULT:std::cell::Cell<Option<usize>>=const {std::cell::Cell::new(None)};
    static SYNC_FAULT:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static STAMP_FAULT:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
}
pub(crate) fn fault_write(file: &fs::File, offset: u64, bytes: &[u8]) -> std::io::Result<usize> {
    WRITE_FAULT.with(|fault| match fault.get() {
        Some(0) => Err(std::io::Error::other("injected persistent short-write failure")),
        Some(remaining) => {
            let count = crate::output::range::write_at(file, offset, &bytes[..bytes.len().min(remaining)])?;
            fault.set(Some(remaining - count));
            Ok(count)
        }
        None => crate::output::range::write_at(file, offset, bytes),
    })
}
pub(crate) fn fault_sync() -> std::io::Result<()> {
    if SYNC_FAULT.with(std::cell::Cell::get) {
        Err(std::io::Error::other("injected persistent output-sync failure"))
    } else {
        Ok(())
    }
}
// Catches blessing a short prefix or dropping the acknowledged conservative anchor on IO failure.
#[test]
fn partial_write_and_sync_failures_keep_the_entire_intent_unknown() {
    for sync_failure in [false, true] {
        let f = Fixture::new();
        let file = f.create().unwrap();
        if sync_failure {
            SYNC_FAULT.set(true)
        } else {
            WRITE_FAULT.set(Some(2))
        }
        let result = file.core.write_original(0, b"abcd");
        WRITE_FAULT.set(None);
        SYNC_FAULT.set(false);
        let error = result.unwrap_err();
        assert!(matches!(error.kind, PartialErrorKind::Io { .. }));
        assert_eq!(error.committed.as_ref().map(StateAnchor::sequence), Some(2));
        if !sync_failure {
            assert_eq!(error.output.unwrap().completed, 2);
        }
        assert_eq!(file.remaining().unwrap(), vec![0..16]);
        let state = file.close().unwrap();
        let opened = f.open(state).unwrap();
        assert_eq!(opened.remaining().unwrap(), vec![0..16]);
        let mut expected = vec![0; 16];
        let n = if sync_failure { 4 } else { 2 };
        expected[..n].copy_from_slice(&b"abcd"[..n]);
        assert_eq!(fs::read(f.output()).unwrap(), expected);
    }
}

#[test]
fn alternative_provenance_survives_canonical_reopen() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    let result = file.core.fill_plain(0, b"abcd").unwrap();
    drop(file);
    let reopened = f.open(result.state).unwrap();
    let op = reopened.core.operation().unwrap();
    assert!(matches!(op.snapshot.known[0].provenance, crate::partial::state::Provenance::Alt));
}

// Catches treating the shared live-leaf budget as a per-member limit.
#[test]
fn shared_crc_leaf_capacity_is_released_only_with_its_owner() {
    let first = Fixture::new();
    let second = Fixture::new();
    let usage = Usage::new(ProgressiveLimits::default());
    let exclusions = Arc::new(PartialExclusions::new(usage.clone()));
    let mut limits = PartialLimits::default();
    limits.crc_leaves = 1;
    let options = |f: &Fixture| CoreOptions {
        limits: limits.clone(),
        usage: usage.clone(),
        read_chunk: 1024,
        anchors: f.store.clone(),
        control: SessionControl::default(),
        exclusions: exclusions.clone(),
    };
    let a = PartialCore::create(first.spec(), first.checks.clone(), options(&first)).unwrap();
    let b = PartialCore::create(second.spec(), second.checks.clone(), options(&second)).unwrap();
    a.write_original(0, b"abcd").unwrap();
    let error = b.write_original(0, b"abcd").unwrap_err();
    assert!(matches!(
        error.kind,
        PartialErrorKind::Limit { resource: PartialResource::CrcLeaves, limit: 1, attempted: 2 }
    ));
    assert_eq!(second.store.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(fs::read(second.output()).unwrap(), vec![0; 16]);
    drop(a);
    b.write_original(0, b"abcd").unwrap();
    assert_eq!(&fs::read(second.output()).unwrap()[..4], b"abcd");
}

// State-file identity protection must survive aliases outside the reserved subtree.
#[test]
fn state_file_aliases_are_excluded_until_acknowledged_retirement() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    let state = file.state().unwrap();
    let bundle = f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member));
    let record = bundle.join(format!("r-{}", crate::partial::native::hex(state.anchor().digest())));
    let held = fs::File::open(&record).unwrap();
    assert!(file.core.budget.exclusions.check_input(&[], &[held.try_clone().unwrap()]).is_err());
    let page = fs::read_dir(&bundle)
        .unwrap()
        .map(|e| e.unwrap())
        .find(|e| e.file_name().to_string_lossy().starts_with("p-"))
        .unwrap()
        .path();
    let alias = f.dir.path().join("page-alias");
    fs::hard_link(page, &alias).unwrap();
    assert!(
        file.core
            .budget
            .exclusions
            .check_input(std::slice::from_ref(&alias), &[fs::File::open(&alias).unwrap()])
            .is_err()
    );
    fs::remove_file(alias).unwrap();
    let alias = f.dir.path().join("record-alias");
    fs::hard_link(&record, &alias).unwrap();
    let error = file.core.compact().unwrap_err();
    assert!(error.committed.is_some());
    assert!(record.exists());
    assert!(file.core.budget.exclusions.check_input(&[], &[held.try_clone().unwrap()]).is_err());
    fs::remove_file(alias).unwrap();
    file.core.compact().unwrap();
    assert!(!record.exists());
    assert!(file.core.budget.exclusions.check_input(&[], &[held]).is_ok());
}

// Exhausting path capacity must precede creating mutation pages or acknowledging an intent.
#[test]
fn state_exclusion_capacity_precedes_mutation_effects() {
    let f = Fixture::new();
    let mut progressive = ProgressiveLimits::default();
    progressive.protection_paths = 8;
    let file = f.create_with(PartialLimits::default(), progressive, SessionControl::default()).unwrap();
    let bundle = f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member));
    let names = || {
        let mut names = fs::read_dir(&bundle).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
        names.sort();
        names
    };
    let before = names();
    let error = file.core.write_original(0, b"abcd").unwrap_err();
    assert!(
        matches!(error.kind,PartialErrorKind::Progressive(cause) if matches!(cause.kind,FailureKind::Limit {resource:Resource::ProtectionPaths,..}))
    );
    assert_eq!(names(), before);
    assert_eq!(f.store.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
}

// Recovery must reuse the single logical leaf, including rollback from a read failure.
#[test]
fn ambiguous_compaction_recovers_at_exact_shared_leaf_cap() {
    for persisted in [false, true] {
        let f = Fixture::new();
        let mut limits = PartialLimits::default();
        limits.crc_leaves = 1;
        let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
        file.core.write_original(0, b"abcd").unwrap();
        let prior = file.state().unwrap();
        let bundle = f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member));
        let prior_record = bundle.join(format!("r-{}", crate::partial::native::hex(prior.anchor().digest())));
        let before = fs::read(f.output()).unwrap();
        *f.store.fail.lock().unwrap() = Some((5, persisted));
        assert!(matches!(file.core.compact().unwrap_err().kind, PartialErrorKind::AnchorCommitUncertain));
        let confirmed = f.store.current(&f.member).unwrap().unwrap();
        // Any attempted output write during recovery must fail this assertion.
        WRITE_FAULT.set(Some(0));
        let recovery = file.core.write_original(0, b"abcd");
        WRITE_FAULT.set(None);
        recovery.unwrap();
        assert_eq!(file.state().unwrap().anchor(), &confirmed);
        assert_eq!(fs::read(f.output()).unwrap(), before);
        assert_eq!(f.store.calls.load(std::sync::atomic::Ordering::SeqCst), 5);
        assert_eq!(prior_record.exists(), !persisted);
        assert_eq!(file.core.budget.exclusions.counters.lock().unwrap()[PartialResource::CrcLeaves as usize], 1);
    }
}
#[test]
fn confirmed_uncertainty_anchor_survives_reconstruction_failure() {
    let f = Fixture::new();
    let mut limits = PartialLimits::default();
    limits.crc_leaves = 1;
    let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    *f.store.fail.lock().unwrap() = Some((5, true));
    file.core.compact().unwrap_err();
    let confirmed = f.store.current(&f.member).unwrap().unwrap();
    let bundle = f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member));
    let (_, _, _, head) =
        crate::partial::state::decode_record(&file.state().unwrap().wire, &PartialLimits::default()).unwrap();
    let page = bundle.join(format!("p-{}", crate::partial::native::hex(&head.pages[0].digest)));
    let hidden = f.dir.path().join("held-page");
    fs::rename(&page, &hidden).unwrap();
    let error = file.core.write_original(0, b"abcd").unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::StateUnavailable));
    assert_eq!(error.committed.as_ref(), Some(&confirmed));
    assert_eq!(file.core.budget.exclusions.counters.lock().unwrap()[PartialResource::CrcLeaves as usize], 1);
    fs::rename(hidden, page).unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    assert_eq!(file.core.budget.exclusions.counters.lock().unwrap()[PartialResource::CrcLeaves as usize], 1);
}

pub(crate) fn fault_post_write_stamp() -> std::io::Result<()> {
    if STAMP_FAULT.replace(false) { Err(std::io::Error::other("injected post-write metadata failure")) } else { Ok(()) }
}
#[test]
fn post_write_stamp_failure_preserves_intent_and_primary_error() {
    for short in [false, true] {
        let f = Fixture::new();
        let file = f.create().unwrap();
        STAMP_FAULT.set(true);
        if short {
            WRITE_FAULT.set(Some(2));
        }
        let error = file.core.write_original(0, b"abcd").unwrap_err();
        WRITE_FAULT.set(None);
        STAMP_FAULT.set(false);
        let intent = f.store.current(&f.member).unwrap().unwrap();
        assert_eq!(intent.sequence(), 2);
        assert_eq!(error.committed.as_ref(), Some(&intent));
        let output = error.output.as_ref().expect("acknowledged write progress");
        assert_eq!((output.offset, output.attempted, output.completed), (0, 4, if short { 2 } else { 4 }));
        match error.kind {
            PartialErrorKind::Io { operation, cause } => {
                assert_eq!(operation, if short { OutputOperation::Write } else { OutputOperation::Metadata });
                assert_eq!(
                    cause.to_string(),
                    if short {
                        "injected persistent short-write failure"
                    } else {
                        "injected post-write metadata failure"
                    }
                );
            }
            other => panic!("{other:?}"),
        }
        let state = PartialState::load(&f.dir.path().join("state"), &intent, &PartialLimits::default()).unwrap();
        drop(file);
        assert_eq!(f.open(state).unwrap().remaining().unwrap(), vec![0..16]);
        let mut bytes = vec![0; 16];
        let n = if short { 2 } else { 4 };
        bytes[..n].copy_from_slice(&b"abcd"[..n]);
        assert_eq!(fs::read(f.output()).unwrap(), bytes);
    }
}

fn genesis_cap(resource: Resource, cap: u64) -> (Fixture, PartialResult<PartialFile>) {
    let f = Fixture::new();
    let mut progressive = ProgressiveLimits::default();
    match resource {
        Resource::ProtectionPaths => progressive.protection_paths = cap,
        Resource::ProtectionPathBytes => progressive.protection_path_bytes = cap,
        Resource::MetadataBytes => progressive.metadata_bytes = cap,
        _ => unreachable!(),
    }
    let result = f.create_with(PartialLimits::default(), progressive, SessionControl::default());
    (f, result)
}
fn assert_genesis_rejection(resource: Resource, cap: u64) {
    let (f, result) = genesis_cap(resource, cap);
    let error = result.err().expect("one-under admission must reject");
    assert!(
        matches!(error.kind,PartialErrorKind::Progressive(ref cause) if matches!(cause.kind,FailureKind::Limit {resource:r,..} if r==resource)),
        "{error:?}"
    );
    assert!(!f.output().exists(), "known cap failure created output");
    assert_eq!(fs::read_dir(f.dir.path().join("state")).unwrap().count(), 0, "known cap failure created a bundle");
    assert_eq!(f.store.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}
fn measured_genesis_boundary(resource: Resource, high: u64) {
    let mut low = 0;
    let mut high = high;
    assert!(genesis_cap(resource, high).1.is_ok());
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        if genesis_cap(resource, mid).1.is_ok() { high = mid } else { low = mid }
    }
    assert!(genesis_cap(resource, high).1.is_ok());
    assert_genesis_rejection(resource, high - 1);
    println!("genesis {resource:?}: exact={high}, one-under={}", high - 1);
}
#[test]
fn genesis_exclusion_count_admits_exact_and_rejects_before_effects() {
    assert!(genesis_cap(Resource::ProtectionPaths, 8).1.is_ok());
    for cap in [2, 3, 7] {
        assert_genesis_rejection(Resource::ProtectionPaths, cap);
    }
}
#[test]
fn genesis_path_bytes_admits_exact_and_rejects_before_effects() {
    measured_genesis_boundary(Resource::ProtectionPathBytes, 1_048_576);
}
#[test]
fn genesis_metadata_admits_exact_and_rejects_before_effects() {
    measured_genesis_boundary(Resource::MetadataBytes, 1_048_576);
}
