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

type StoreHook = Arc<dyn Fn(usize) + Send + Sync>;

#[derive(Default)]
struct Store {
    value: Mutex<Option<StateAnchor>>,
    calls: std::sync::atomic::AtomicUsize,
    currents: std::sync::atomic::AtomicUsize,
    fail: Mutex<Option<(usize, bool)>>,
    observe: Mutex<Option<(usize, std::path::PathBuf, Vec<u8>)>>,
    hook: Mutex<Option<StoreHook>>,
}
impl StateAnchorStore for Store {
    fn current(&self, _: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        self.currents.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.value.lock().unwrap().clone())
    }
    fn compare_exchange(&self, _: &MemberKey, expected: Option<&StateAnchor>, next: &StateAnchor) -> PartialResult<()> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if let Some((at, path, expected)) = &*self.observe.lock().unwrap()
            && *at == call
        {
            assert_eq!(&fs::read(path).unwrap(), expected, "output changed before intent acknowledgement");
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
    size: u64,
}
/// The file block header of a stored member of `size` bytes, without its data.
fn sized_header(name: &str, size: u64, crc: u32) -> Vec<u8> {
    use super::rar_fixture::vint;
    let mut fields = Vec::new();
    vint(0x4 | 0x2, &mut fields);
    vint(size, &mut fields);
    vint(0o644, &mut fields);
    fields.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    fields.extend_from_slice(&crc.to_le_bytes());
    vint(0, &mut fields);
    vint(1, &mut fields);
    vint(name.len() as u64, &mut fields);
    fields.extend_from_slice(name.as_bytes());
    let mut body = Vec::new();
    vint(2, &mut body);
    vint(2, &mut body);
    vint(size, &mut body);
    body.extend(fields);
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend(body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend(sized);
    out
}
impl Fixture {
    pub(super) fn new() -> Self {
        Self::new_in(None)
    }
    fn new_in(parent: Option<&std::path::Path>) -> Self {
        Self::sized_in(parent, 16)
    }
    /// A stored member of `size` bytes; above 16 bytes only its header exists (the archive data is never read).
    fn sized(size: u64) -> Self {
        Self::sized_in(None, size)
    }
    fn sized_in(parent: Option<&std::path::Path>, size: u64) -> Self {
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
        let bytes = if size == 16 {
            super::rar_fixture::file_block(
                &super::rar_fixture::FileSpec::new("member.bin", data),
                data,
                crc32fast::hash(data),
                false,
                false,
            )
        } else {
            sized_header("member.bin", size, 0x1234_5678)
        };
        let total = if size == 16 { bytes.len() as u64 } else { bytes.len() as u64 + size };
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
            format: crate::rar5::RarFormat::Rar5,
            metadata: (&header).into(),
            parts: vec![PlainPart {
                ordinal: 0,
                packed: PackedSpan { volume: 0, range: header.data_at..header.data_at + size },
                out: 0..size,
                final_part: true,
                crc32: header.crc32,
                blake2sp: header.blake2sp,
            }],
            admissions: vec![SourceAdmission {
                volume: 0,
                info: SourceInfo {
                    id: SourceId(123),
                    generation: 1,
                    extent: total,
                    length: SourceLength::Final(total),
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
            checks: MemberChecks { size, crc32: header.crc32, blake2sp: None },
            size,
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
            size: self.size,
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
            password: None,
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
                password: None,
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
    // One transaction per write; grouped_commit_cas_uncertainty_recovers_from_the_store covers groups.
    let file = f.create_with(ungrouped(), ProgressiveLimits::default(), SessionControl::default()).unwrap();
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
    let grouped = std::env::var_os("ZIPFAST_PARTIAL_GROUPED").is_some();
    // Grouped: commit every 8 bytes, so four 4-byte writes make two groups.
    let limits = if grouped { PartialLimits { group_commit_bytes: 8, ..Default::default() } } else { ungrouped() };
    let mut options =
        f.options(limits, ProgressiveLimits { read_chunk: 4, ..Default::default() }, SessionControl::default());
    options.anchors = store;
    let core = PartialCore::create(f.spec(), f.checks.clone(), options).unwrap();
    if std::env::var("ZIPFAST_PARTIAL_KILL_AT").ok().as_deref() == Some("journal-prefix") {
        JOURNAL_FAULT.set(Some(JournalFault::Write { page: true, remaining: 2 }));
    }
    if grouped {
        for at in (0..16).step_by(4) {
            core.write_original(at, &b"abcdefghijklmnop"[at as usize..at as usize + 4]).unwrap();
        }
    } else {
        core.write_original(0, b"abcdefghijklmnop").unwrap();
    }
}
/// One transaction per write, as before group commits.
pub(super) fn ungrouped() -> PartialLimits {
    PartialLimits { group_commit_bytes: 0, ..Default::default() }
}
// Catches certification of an unanchored tail and incorrect crash ordering at real fsync/CAS boundaries.
#[test]
fn crash_recovers_last_acknowledged_state() {
    for (phase, sequence, written) in [
        ("journal-prefix", 1, 0),
        ("intent-sync", 1, 0),
        ("intent-cas", 2, 0),
        ("write", 2, 4),
        ("output-sync", 2, 16),
        ("commit-sync", 2, 16),
        ("commit-cas", 3, 16),
    ] {
        let committed = if sequence == 3 { 16 } else { 0 };
        let (file, _root, path) = crash_and_reopen(phase, false, sequence, committed, written);
        if phase == "journal-prefix" {
            file.core
                .write_original(0, b"abcdefghijklmnop")
                .expect("restart must complete torn unanchored journal prefix");
            assert!(file.remaining().unwrap().is_empty());
            assert_eq!(fs::read(path.join("out/member.bin")).unwrap(), b"abcdefghijklmnop");
        }
    }
}
// Catches a group commit that claims output before its sync, or a crash inside a group that loses the committed
// part: four 4-byte writes in groups of 8 bytes. After a crash the uncommitted tail is unknown, the committed part
// verifies by rehash, and extraction can resume from the committed `produced`.
#[test]
fn crash_inside_a_group_reopens_with_only_committed_output_known() {
    for (phase, sequence, committed, written) in [
        ("intent-sync:1", 1, 0, 0),
        ("intent-cas:1", 2, 0, 0),
        ("write:1", 2, 0, 4),
        ("write:2", 2, 0, 8),
        ("output-sync:1", 2, 0, 8),
        ("commit-sync:1", 2, 0, 8),
        ("commit-cas:1", 3, 8, 8),
        ("intent-sync:2", 3, 8, 8),
        ("intent-cas:2", 4, 8, 8),
        ("write:3", 4, 8, 12),
        ("output-sync:2", 4, 8, 16),
        ("commit-sync:2", 4, 8, 16),
        ("commit-cas:2", 5, 16, 16),
    ] {
        let (file, _root, path) = crash_and_reopen(phase, true, sequence, committed, written);
        // Extraction resumes at the committed `produced`; uncommitted bytes are simply written again.
        for at in (committed..16).step_by(4) {
            file.core.write_original(at, &b"abcdefghijklmnop"[at as usize..at as usize + 4]).unwrap();
        }
        assert!(file.remaining().unwrap().is_empty(), "{phase}");
        assert_eq!(fs::read(path.join("out/member.bin")).unwrap(), b"abcdefghijklmnop", "{phase}");
    }
}
/// Kills `process_kill_child` at `phase` (`name` or `name:n` for its n-th occurrence) and reopens from the trusted
/// anchor: the anchor has `sequence`, output below `committed` is known and everything after it unknown, and the
/// first `written` bytes reached the output file.
fn crash_and_reopen(
    phase: &str,
    grouped: bool,
    sequence: u64,
    committed: u64,
    written: usize,
) -> (PartialFile, tempfile::TempDir, std::path::PathBuf) {
    use std::time::{Duration, Instant};
    let root = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "partial::tests::state::process_kill_child", "--test-threads=1"])
        .env("ZIPFAST_PARTIAL_KILL_ROOT", root.path())
        .env("ZIPFAST_PARTIAL_KILL_AT", phase)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if grouped {
        command.env("ZIPFAST_PARTIAL_GROUPED", "1");
    }
    let mut child = command.spawn().unwrap();
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
    let anchors = Arc::new(DurableStore { path: root.path().join("trusted-anchor"), member: template.member.clone() });
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
            password: None,
        },
    )
    .unwrap();
    let remaining = if committed == 16 { vec![] } else { std::iter::once(committed..16).collect::<Vec<_>>() };
    assert_eq!(file.remaining().unwrap(), remaining, "{phase}");
    let mut expected = vec![0; 16];
    expected[..written].copy_from_slice(&b"abcdefghijklmnop"[..written]);
    assert_eq!(fs::read(path.join("out/member.bin")).unwrap(), expected, "{phase}");
    (file, root, path)
}

pub(crate) fn checkpoint(phase: &str) {
    static HITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let Some(wanted) = std::env::var("ZIPFAST_PARTIAL_KILL_AT").ok() else { return };
    // `name:n` stops at the n-th occurrence of `name`, `name` at the first.
    let (name, nth) = match wanted.split_once(':') {
        Some((name, nth)) => (name.to_owned(), nth.parse::<usize>().unwrap()),
        None => (wanted.clone(), 1),
    };
    if name != phase || HITS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 != nth {
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
            format: crate::rar5::RarFormat::Rar5,
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
    let start = f.evidence.parts[0].packed.range.start;
    core.record_hole(HoleReport {
        id: 1,
        revision: 1,
        member: f.member.clone(),
        name: Arc::from(b"member.bin".as_slice()),
        out: 0..8,
        packed: vec![PackedSpan { volume: 0, range: start..start + 8 }],
        cause: HoleCause::Missing,
    })
    .unwrap();
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
    assert_eq!(result.part_checks.len(), 1);
    assert_eq!(result.part_checks[0].crc32, CheckResult::Pending);
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
    pub(super) static WRITE_FAULT:std::cell::Cell<Option<usize>>=const {std::cell::Cell::new(None)};
    pub(super) static SYNC_FAULT:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
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
        // One transaction per write; grouped_write_and_sync_failures_keep_the_group_unknown covers groups.
        let file = f.create_with(ungrouped(), ProgressiveLimits::default(), SessionControl::default()).unwrap();
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
    let limits = PartialLimits { crc_leaves: 1, ..PartialLimits::default() };
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
    let progressive = ProgressiveLimits { protection_paths: 8, ..ProgressiveLimits::default() };
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
        let limits = PartialLimits { crc_leaves: 1, ..PartialLimits::default() };
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
    let limits = PartialLimits { crc_leaves: 1, ..PartialLimits::default() };
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

#[derive(Clone, Copy)]
enum JournalFault {
    Write { page: bool, remaining: usize },
    Sync { page: bool, directory: bool, remaining: usize },
}
thread_local! {
    static JOURNAL_FAULT: std::cell::Cell<Option<JournalFault>> = const { std::cell::Cell::new(None) };
}
pub(crate) fn journal_write(file: &fs::File, name: &str, at: u64, bytes: &[u8]) -> std::io::Result<usize> {
    if let Some(JournalFault::Write { page, remaining }) = JOURNAL_FAULT.get()
        && name.starts_with(if page { "p-" } else { "r-" })
    {
        if remaining == 0 {
            JOURNAL_FAULT.set(None);
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
        }
        let n = crate::output::range::write_at(file, at, &bytes[..bytes.len().min(remaining)])?;
        JOURNAL_FAULT.set(Some(JournalFault::Write { page, remaining: remaining - n }));
        checkpoint("journal-prefix");
        return Ok(n);
    }
    crate::output::range::write_at(file, at, bytes)
}
pub(crate) fn journal_sync(file: &fs::File, names: &[&str], directory: bool) -> std::io::Result<()> {
    if let Some(JournalFault::Sync { page, directory: wanted, remaining }) = JOURNAL_FAULT.get()
        && directory == wanted
        && names.iter().any(|name| name.starts_with(if page { "p-" } else { "r-" }))
    {
        if remaining > 0 {
            JOURNAL_FAULT.set(Some(JournalFault::Sync { page, directory, remaining: remaining - 1 }));
            return Err(std::io::Error::other("injected journal sync failure"));
        }
        JOURNAL_FAULT.set(None);
    }
    file.sync_all()
}
fn prepared_public_fill(f: &Fixture) -> PartialFile {
    let file = f.create().unwrap();
    let packed = f.evidence.parts[0].packed.clone();
    file.core
        .record_hole(HoleReport {
            id: 1,
            revision: 1,
            member: f.member.clone(),
            name: Arc::from(b"member.bin".as_slice()),
            out: 0..16,
            packed: vec![packed],
            cause: HoleCause::Missing,
        })
        .unwrap();
    file
}
#[test]
fn journal_torn_unanchored_file_retries_live_and_after_reopen() {
    for page in [false, true] {
        for reopen in [false, true] {
            let f = Fixture::new();
            let mut file = prepared_public_fill(&f);
            let before = file.state().unwrap();
            let calls = f.store.calls.load(std::sync::atomic::Ordering::SeqCst);
            JOURNAL_FAULT.set(Some(JournalFault::Write { page, remaining: 2 }));
            let error = file.fill(0, b"abcdefghijklmnop").unwrap_err();
            assert!(
                matches!(error.kind, PartialErrorKind::Io {operation: OutputOperation::Write, ref cause} if cause.raw_os_error() == Some(libc::ENOSPC))
            );
            assert_eq!(f.store.calls.load(std::sync::atomic::Ordering::SeqCst), calls);
            assert_eq!(file.state().unwrap().anchor(), before.anchor());
            assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
            if reopen {
                drop(file);
                file = f.open(before).unwrap();
            }
            file.fill(0, b"abcdefghijklmnop").expect("unanchored torn journal must be retryable");
            let state = file.close().unwrap();
            assert!(f.open(state).unwrap().remaining().unwrap().is_empty());
            assert_eq!(fs::read(f.output()).unwrap(), b"abcdefghijklmnop");
        }
    }
}
#[test]
fn journal_equal_retry_reestablishes_file_and_directory_durability_before_cas() {
    for page in [false, true] {
        for directory in [false, true] {
            for reopen in [false, true] {
                let f = Fixture::new();
                let mut file = prepared_public_fill(&f);
                let before = file.state().unwrap();
                let calls = f.store.calls.load(std::sync::atomic::Ordering::SeqCst);
                JOURNAL_FAULT.set(Some(JournalFault::Sync { page, directory, remaining: 2 }));
                for attempt in 0..2 {
                    if attempt == 1 && reopen {
                        drop(file);
                        file = f.open(before.clone()).unwrap();
                    }
                    let result = file.fill(0, b"abcdefghijklmnop");
                    assert_eq!(
                        f.store.calls.load(std::sync::atomic::Ordering::SeqCst),
                        calls,
                        "unsynced journal escaped into anchor CAS"
                    );
                    let error = result.unwrap_err();
                    assert!(
                        matches!(error.kind, PartialErrorKind::Io { operation: OutputOperation::Flush, ref cause } if cause.to_string() == "injected journal sync failure")
                    );
                    assert_eq!(file.state().unwrap().anchor(), before.anchor());
                    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
                }
                file.fill(0, b"abcdefghijklmnop").unwrap();
                let state = file.close().unwrap();
                assert!(f.open(state).unwrap().remaining().unwrap().is_empty());
                assert_eq!(fs::read(f.output()).unwrap(), b"abcdefghijklmnop");
            }
        }
    }
}

#[test]
fn journal_recovery_never_repairs_conflicting_or_current_anchored_bytes() {
    use std::io::{Seek, SeekFrom, Write};
    for anchored in [false, true] {
        let f = Fixture::new();
        let mut file = prepared_public_fill(&f);
        let before = file.state().unwrap();
        let bundle = f.dir.path().join("state").join(super::super::native::bundle_name(&f.member));
        let target = if anchored {
            let op = file.core.operation().unwrap();
            bundle.join(format!("p-{}", super::super::native::hex(&op.snapshot.head.pages[0].digest)))
        } else {
            let names = fs::read_dir(&bundle).unwrap().map(|e| e.unwrap().path()).collect::<Vec<_>>();
            JOURNAL_FAULT.set(Some(JournalFault::Write { page: false, remaining: 2 }));
            assert!(file.fill(0, b"abcdefghijklmnop").is_err());
            fs::read_dir(&bundle)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| !names.contains(p) && p.file_name().unwrap().to_str().unwrap().starts_with("r-"))
                .unwrap()
        };
        let mut damaged = fs::OpenOptions::new().write(true).open(&target).unwrap();
        damaged.set_len(2).unwrap();
        if !anchored {
            damaged.seek(SeekFrom::Start(0)).unwrap();
            damaged.write_all(b"XX").unwrap();
        }
        damaged.sync_all().unwrap();
        let saved = fs::read(&target).unwrap();
        let calls = f.store.calls.load(std::sync::atomic::Ordering::SeqCst);
        let error = file.fill(0, b"abcdefghijklmnop").unwrap_err();
        assert!(matches!(error.kind, PartialErrorKind::JournalCorrupt));
        assert_eq!(f.store.calls.load(std::sync::atomic::Ordering::SeqCst), calls);
        assert_eq!(file.state().unwrap().anchor(), before.anchor());
        assert_eq!(fs::read(&target).unwrap(), saved);
        assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
        drop(file);
        if anchored {
            assert!(f.open(before).is_err());
        }
        assert_eq!(fs::read(target).unwrap(), saved);
    }
}

// Catches a failed archive-authority rewrite leaving wrong alt bytes known, or leaving the range unfillable.
#[test]
fn failed_packed_rewrite_of_alt_bytes_leaves_a_fillable_declared_hole() {
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
    file.core.fill_plain(0, b"wxyz").unwrap();
    WRITE_FAULT.set(Some(2));
    let result = file.core.fill_packed(0, start, b"abcd");
    WRITE_FAULT.set(None);
    let error = result.unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::Io { .. }), "{error:?}");
    assert_eq!(error.packed_progress.as_ref().expect("wrong alt reported").corrected, vec![0..4]);
    assert_eq!(file.remaining().unwrap(), vec![0..16]);
    let state = file.close().unwrap();
    let mut opened = f.open(state).unwrap();
    assert_eq!(opened.remaining().unwrap(), vec![0..16]);
    let op = opened.core.operation().unwrap();
    assert!(op.snapshot.holes.iter().any(|h| h.out == (0..4) && h.cause == HoleCause::DeclaredBad));
    drop(op);
    opened.fill(0, b"abcd").unwrap();
    assert_eq!(&fs::read(f.output()).unwrap()[..4], b"abcd");
}

fn hole(f: &Fixture, file: &PartialFile, revision: u64, out: Range<u64>) {
    let start = f.evidence.parts[0].packed.range.start;
    file.core
        .record_hole(HoleReport {
            id: revision,
            revision,
            member: f.member.clone(),
            name: Arc::from(b"member.bin".as_slice()),
            packed: vec![PackedSpan { volume: 0, range: start + out.start..start + out.end }],
            out,
            cause: HoleCause::Missing,
        })
        .unwrap();
}

// Catches an intent snapshot whose rewrite holes exceed the reopen limit, which would strand the member.
#[test]
fn packed_rewrite_holes_respect_the_reopen_limit() {
    let f = Fixture::new();
    let progressive = ProgressiveLimits { hole_intervals: 1, ..ProgressiveLimits::default() };
    let file = f.create_with(PartialLimits::default(), progressive, SessionControl::default()).unwrap();
    let start = f.evidence.parts[0].packed.range.start;
    hole(&f, &file, 1, 0..4);
    file.core.fill_plain(0, b"wxyz").unwrap();
    hole(&f, &file, 3, 4..8);
    let error = file.core.fill_packed(0, start, b"abcd").unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::Progressive(_)), "{error:?}");
    assert_eq!(&fs::read(f.output()).unwrap()[..4], b"wxyz");
    let state = file.close().unwrap();
    f.open(state).unwrap();
}

struct FailAfter {
    bytes: Vec<u8>,
    at: u64,
    reads: usize,
}
impl std::io::Read for FailAfter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        if self.reads > 1 {
            return Err(std::io::Error::other("volume went away"));
        }
        let n = buf.len().min(self.bytes.len() - self.at as usize);
        buf[..n].copy_from_slice(&self.bytes[self.at as usize..self.at as usize + n]);
        self.at += n as u64;
        Ok(n)
    }
}
impl std::io::Seek for FailAfter {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let std::io::SeekFrom::Start(at) = pos else { unreachable!() };
        self.at = at;
        Ok(at)
    }
}

// Catches losing which alt bytes were corrected when a later refill chunk fails.
#[test]
fn refill_failure_reports_corrections_already_committed() {
    let f = Fixture::new();
    let limits = PartialLimits { fill_bytes: 4, ..PartialLimits::default() };
    let mut file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
    let start = f.evidence.parts[0].packed.range.start;
    hole(&f, &file, 1, 0..8);
    file.core.fill_plain(0, b"wxyz").unwrap();
    file.core.fill_plain(4, b"wxyz").unwrap();
    let mut volume = vec![0u8; start as usize + 16];
    volume[start as usize..start as usize + 8].copy_from_slice(b"abcdefgh");
    let mut reader = FailAfter { bytes: volume, at: 0, reads: 0 };
    let error = file.refill_from_packed(0, start..start + 8, &mut reader).unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::PackedRead(_)), "{error:?}");
    assert_eq!((error.volume, error.packed_offset), (Some(0), Some(start + 4)));
    let progress = error.packed_progress.expect("committed progress");
    assert_eq!(progress.corrected, vec![0..4]);
    assert_eq!(&fs::read(f.output()).unwrap()[..8], b"abcdwxyz");
}

// Catches confirmed alt bytes staying Alt, which makes every later refill re-read them.
#[test]
fn alt_bytes_confirmed_by_archive_bytes_are_not_refilled_again() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    let start = f.evidence.parts[0].packed.range.start;
    hole(&f, &file, 1, 0..4);
    file.core.fill_plain(0, b"abcd").unwrap();
    assert_eq!(file.core.refill_targets(0, &(start..start + 4)).unwrap(), vec![start..start + 4]);
    let result = file.core.fill_packed(0, start, b"abcd").unwrap();
    assert!(result.applied.is_empty() && result.corrected.is_empty());
    assert!(file.core.refill_targets(0, &(start..start + 4)).unwrap().is_empty());
    let state = file.close().unwrap();
    let reopened = f.open(state).unwrap();
    assert!(reopened.core.refill_targets(0, &(start..start + 4)).unwrap().is_empty());
}

// Catches a grouped write failure that drops or certifies output: the group stays open, the bytes of the failed
// write stay unknown, and the next operation commits what the group wrote before.
#[test]
fn grouped_write_and_sync_failures_keep_the_group_unknown() {
    for sync_failure in [false, true] {
        let f = Fixture::new();
        let file = f.create().unwrap();
        file.core.write_original(0, b"abcd").unwrap();
        let result = if sync_failure {
            SYNC_FAULT.set(true);
            file.state().map(|_| ())
        } else {
            WRITE_FAULT.set(Some(2));
            file.core.write_original(4, b"efgh")
        };
        WRITE_FAULT.set(None);
        SYNC_FAULT.set(false);
        let error = result.unwrap_err();
        assert!(matches!(error.kind, PartialErrorKind::Io { .. }));
        // The group's intent is the anchored state.
        assert_eq!(error.committed.as_ref().map(StateAnchor::sequence), Some(2));
        assert_eq!(f.store.current(&f.member).unwrap().unwrap().sequence(), 2);
        if !sync_failure {
            assert_eq!(error.output.unwrap().completed, 2);
        }
        // The next operation commits the group: the first write is known, the failed one is not.
        assert_eq!(file.remaining().unwrap(), vec![4..16]);
        let state = file.close().unwrap();
        assert_eq!(state.anchor().sequence(), 3);
        let opened = f.open(state).unwrap();
        assert_eq!(opened.remaining().unwrap(), vec![4..16]);
    }
}
// Catches a group commit whose ambiguous CAS is trusted or replayed: recovery rebuilds from whichever state the
// store holds, and extraction resumes at that state's `produced`.
#[test]
fn grouped_commit_cas_uncertainty_recovers_from_the_store() {
    use std::sync::atomic::Ordering::SeqCst;
    for persisted in [false, true] {
        let f = Fixture::new();
        let limits = PartialLimits { group_commit_bytes: 8, ..Default::default() };
        let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
        file.core.write_original(0, b"abcd").unwrap();
        // Genesis made two CAS calls and the group intent the third; the fourth is the group commit.
        assert_eq!(f.store.calls.load(SeqCst), 3);
        *f.store.fail.lock().unwrap() = Some((4, persisted));
        let error = file.core.write_original(4, b"efgh").unwrap_err();
        *f.store.fail.lock().unwrap() = None;
        assert!(matches!(error.kind, PartialErrorKind::AnchorCommitUncertain));
        assert_eq!(fs::read(f.output()).unwrap()[..8], *b"abcdefgh");
        let committed = if persisted { 8 } else { 0 };
        assert_eq!(file.remaining().unwrap(), vec![committed..16]);
        for at in (committed..16).step_by(4) {
            file.core.write_original(at, &b"abcdefghijklmnop"[at as usize..at as usize + 4]).unwrap();
        }
        assert!(file.remaining().unwrap().is_empty());
        assert_eq!(fs::read(f.output()).unwrap(), b"abcdefghijklmnop");
    }
}
// Catches losing the written tail of an open group when the last owner drops without committing.
#[test]
fn dropping_the_last_owner_commits_an_open_group() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    assert_eq!(f.store.current(&f.member).unwrap().unwrap().sequence(), 2);
    drop(file);
    let anchor = f.store.current(&f.member).unwrap().unwrap();
    assert_eq!(anchor.sequence(), 3);
    let state = PartialState::load(&f.dir.path().join("state"), &anchor, &PartialLimits::default()).unwrap();
    assert_eq!(f.open(state).unwrap().remaining().unwrap(), vec![4..16]);
}
// Catches a FillWriter that commits each buffer on its own: with grouping it commits once per group.
#[test]
fn fill_writer_commits_per_group_not_per_buffer() {
    use std::io::Write;
    use std::sync::atomic::Ordering::SeqCst;
    for (group, commits) in [(8, 2), (0, 4)] {
        let f = Fixture::new();
        let limits = PartialLimits { fill_bytes: 4, group_commit_bytes: group, ..Default::default() };
        let mut file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
        hole(&f, &file, 1, 0..16);
        let before = f.store.calls.load(SeqCst);
        let mut writer = file.fill_writer(0).unwrap();
        writer.write_all(b"abcdefghijklmnop").unwrap();
        let result = writer.finish().unwrap();
        assert_eq!(result.applied, vec![0..16]);
        // Two CAS calls (intent and commit) per durable transaction.
        assert_eq!(f.store.calls.load(SeqCst) - before, 2 * commits, "group {group}");
        assert_eq!(result.state.anchor(), &f.store.current(&f.member).unwrap().unwrap());
        assert!(file.remaining().unwrap().is_empty());
        assert_eq!(fs::read(f.output()).unwrap(), b"abcdefghijklmnop");
    }
}
// Catches a FillWriter error that loses what earlier buffers of the group wrote: they are committed and the
// writer's position is their end.
#[test]
fn fill_writer_error_commits_earlier_buffers() {
    use std::io::Write;
    let f = Fixture::new();
    let limits = PartialLimits { fill_bytes: 4, ..Default::default() };
    let mut file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
    hole(&f, &file, 1, 0..12);
    let mut writer = file.fill_writer(0).unwrap();
    // 12..16 is not a hole: the fourth buffer is refused before writing.
    assert!(writer.write_all(b"abcdefghijklmnop").is_err());
    assert_eq!(writer.position(), 12);
    assert!(matches!(writer.finish().unwrap_err().kind, PartialErrorKind::IncompleteOutput));
    // The three buffers before it were committed when the fourth failed.
    let anchor = f.store.current(&f.member).unwrap().unwrap();
    assert_eq!(file.close().unwrap().anchor(), &anchor);
    let state = PartialState::load(&f.dir.path().join("state"), &anchor, &PartialLimits::default()).unwrap();
    assert_eq!(f.open(state).unwrap().remaining().unwrap(), vec![12..16]);
}
// Catches group commits that strand a member when the bundle runs out of room: compaction runs at group begin and
// inside a group's commit, and the result reopens.
#[test]
fn grouped_commits_compact_under_journal_pressure() {
    let f = Fixture::new();
    let limits = PartialLimits { group_commit_bytes: 2, journal_records: 6, state_pages: 9, ..Default::default() };
    let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
    for at in 0..16 {
        file.core.write_original(at, &b"abcdefghijklmnop"[at as usize..at as usize + 1]).unwrap();
    }
    assert!(file.remaining().unwrap().is_empty());
    let state = file.close().unwrap();
    assert!(f.open(state).unwrap().remaining().unwrap().is_empty());
}
// Catches a commit that rewrites the whole ledger of a big member: the validity ledger is paged by output window,
// so a commit writes only the pages whose windows changed, and the paged state reopens.
#[test]
fn big_member_commit_writes_only_changed_ledger_pages() {
    let size = 1u64 << 30;
    let f = Fixture::sized(size);
    let file = f.create().unwrap();
    let pages = |file: &PartialFile| {
        file.state().unwrap();
        file.core.operation().unwrap().snapshot.head.pages.iter().map(|p| p.digest).collect::<Vec<_>>()
    };
    let bundle = f.dir.path().join("state").join(super::super::native::bundle_name(&f.member));
    let page_files = || {
        fs::read_dir(&bundle)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_str().unwrap().starts_with("p-"))
            .count()
    };
    file.core.write_original(0, &[7; 65_536]).unwrap();
    let first = pages(&file);
    // Geometry, extent count, at least four windows, holes, header witnesses.
    assert!(first.len() >= 8, "{}", first.len());
    hole(&f, &file, 2, 65_536..600 << 20);
    let second = pages(&file);
    let files = page_files();
    file.core.write_original(600 << 20, &[9; 65_536]).unwrap();
    let third = pages(&file);
    let changed = third.iter().filter(|d| !second.contains(d)).count();
    assert_eq!(changed, 1, "only the window holding the write changes");
    assert_eq!(page_files(), files + changed);
    let state = file.close().unwrap();
    let opened = f.open(state).unwrap();
    assert_eq!(opened.remaining().unwrap(), vec![65_536..600 << 20, (600 << 20) + 65_536..size]);
}
// Catches a compaction inside a group commit that anchors the group's run-ahead head (its `produced` past output
// that is neither synced nor known): after a failed CAS anywhere in the run, both the live handle and a reopen
// must show a state extraction can resume from, with every unknown byte at or after `produced`.
#[test]
fn compaction_inside_a_group_never_anchors_the_run_ahead_head() {
    let data = b"abcdefghijklmnop";
    let resume = |file: &PartialFile, phase: &str| {
        let remaining = file.remaining().unwrap();
        assert!(remaining.len() <= 1 && remaining.iter().all(|r| r.end == 16), "{phase}: {remaining:?}");
        if let Some(r) = remaining.first() {
            for at in r.start..16 {
                file.core
                    .write_original(at, &data[at as usize..at as usize + 1])
                    .unwrap_or_else(|e| panic!("{phase}: resume at {at}: {e:?}"));
            }
        }
        assert!(file.remaining().unwrap().is_empty(), "{phase}");
    };
    for persisted in [false, true] {
        for call in 3..20 {
            for reopen in [false, true] {
                let phase = format!("call {call} persisted {persisted} reopen {reopen}");
                let f = Fixture::new();
                let limits =
                    PartialLimits { group_commit_bytes: 2, journal_records: 6, state_pages: 9, ..Default::default() };
                let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
                *f.store.fail.lock().unwrap() = Some((call, persisted));
                let failed =
                    (0..16u64).any(|at| file.core.write_original(at, &data[at as usize..at as usize + 1]).is_err());
                *f.store.fail.lock().unwrap() = None;
                if !failed {
                    continue;
                }
                if reopen {
                    drop(file);
                    let anchor = f.store.current(&f.member).unwrap().unwrap();
                    let state =
                        PartialState::load(&f.dir.path().join("state"), &anchor, &PartialLimits::default()).unwrap();
                    resume(&f.open(state).unwrap(), &phase);
                } else {
                    resume(&file, &phase);
                }
            }
        }
    }
}
// Catches a FillWriter that counts bytes as committed when the group commit's CAS was ambiguous and did not land:
// its position and the error's progress must follow the durable state.
#[test]
fn fill_writer_position_follows_an_uncertain_group_commit() {
    use std::io::Write;
    for persisted in [false, true] {
        let f = Fixture::new();
        let limits = PartialLimits { fill_bytes: 4, group_commit_bytes: 8, ..Default::default() };
        let mut file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
        hole(&f, &file, 1, 0..16);
        // Genesis and the hole took four CAS calls; the group intent is the fifth, its commit the sixth.
        *f.store.fail.lock().unwrap() = Some((6, persisted));
        let mut writer = file.fill_writer(0).unwrap();
        assert!(writer.write_all(b"abcdefghijklmnop").is_err());
        *f.store.fail.lock().unwrap() = None;
        let committed = if persisted { 8 } else { 0 };
        assert_eq!(writer.position(), committed, "persisted {persisted}");
        drop(writer);
        assert_eq!(file.remaining().unwrap(), vec![committed..16]);
        let f2 = Fixture::new();
        let mut file2 = f2.create_with(limits_8(), ProgressiveLimits::default(), SessionControl::default()).unwrap();
        hole(&f2, &file2, 1, 0..16);
        *f2.store.fail.lock().unwrap() = Some((6, persisted));
        let error = file2.fill_from(0, 16, &mut &b"abcdefghijklmnop"[..]).unwrap_err();
        *f2.store.fail.lock().unwrap() = None;
        assert_eq!(error.output.unwrap().completed, committed, "persisted {persisted}");
        assert_eq!(file2.remaining().unwrap(), vec![committed..16]);
    }
}
fn limits_8() -> PartialLimits {
    PartialLimits { fill_bytes: 4, group_commit_bytes: 8, ..Default::default() }
}
// Catches windowed ledger pages that outgrow a caller's smaller `state_pages`: a big member then keeps the
// single-stream layout and still commits and reopens.
#[test]
fn big_member_fits_a_small_state_page_budget() {
    let size = 1u64 << 30;
    let f = Fixture::sized(size);
    let limits = PartialLimits { state_pages: 9, ..Default::default() };
    let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
    file.core.write_original(0, &[7; 65_536]).unwrap();
    hole(&f, &file, 2, 65_536..600 << 20);
    file.core.write_original(600 << 20, &[9; 65_536]).unwrap();
    let state = file.close().unwrap();
    let opened = f.open(state).unwrap();
    assert_eq!(opened.remaining().unwrap(), vec![65_536..600 << 20, (600 << 20) + 65_536..size]);
}
// Catches a drop commit during unwinding, which syncs files and calls the caller's store: a second panic there
// would abort the process. The group is left uncommitted, as after a crash.
#[test]
fn dropping_while_panicking_leaves_the_group_uncommitted() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owner = file;
        panic!("unwind with an open group");
    }));
    assert!(unwound.is_err());
    let anchor = f.store.current(&f.member).unwrap().unwrap();
    assert_eq!(anchor.sequence(), 2, "the group intent stays anchored");
    let state = PartialState::load(&f.dir.path().join("state"), &anchor, &PartialLimits::default()).unwrap();
    assert_eq!(f.open(state).unwrap().remaining().unwrap(), vec![0..16]);
}

// Catches a grouped hole (`PartialLimits::group_holes`) paying a transaction of its own, sharing an id with
// another hole, or being lost once its group commits.
#[test]
fn grouped_holes_join_the_open_group_and_commit_with_it() {
    let f = Fixture::new();
    let limits = PartialLimits { group_holes: true, ..PartialLimits::default() };
    let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
    let data = b"abcdefghijklmnop";
    file.core.write_original(0, &data[..4]).unwrap();
    let sequence = || f.store.current(&f.member).unwrap().unwrap().sequence();
    let opened = sequence();
    let first = file.core.hole_report(4..6, HoleCause::Missing).unwrap();
    file.core.record_hole_with(first.clone(), &[]).unwrap();
    file.core.write_original(6, &data[6..10]).unwrap();
    let second = file.core.hole_report(10..12, HoleCause::Missing).unwrap();
    file.core.record_hole_with(second.clone(), &[]).unwrap();
    // No anchor moved: the holes are in the open group, and the anchored state (what a crash would reopen) is
    // still the group's intent, which knows neither hole nor the output after them.
    assert_eq!(sequence(), opened, "grouped holes add no transaction");
    assert_ne!(first.id, second.id);
    assert_eq!(first.revision, second.revision, "a group's holes share its revision");
    // Committing the group makes both durable.
    assert_eq!(file.remaining().unwrap(), vec![4..6, 10..16]);
    assert!(sequence() > opened);
    let state = file.close().unwrap();
    let reopened = f.open(state).unwrap();
    assert_eq!(reopened.remaining().unwrap(), vec![4..6, 10..16]);
}
// Catches the opt-in changing anything when it is off, or grouping a hole that is not at the end of the produced
// output: those still commit in a transaction of their own.
#[test]
fn ungrouped_holes_still_commit_on_their_own() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let sequence = || f.store.current(&f.member).unwrap().unwrap().sequence();
    let before = sequence();
    let report = file.core.hole_report(4..6, HoleCause::Missing).unwrap();
    file.core.record_hole_with(report.clone(), &[]).unwrap();
    assert!(sequence() > before, "without group_holes a hole is its own transaction");
    assert_eq!(report.id, report.revision);
}
