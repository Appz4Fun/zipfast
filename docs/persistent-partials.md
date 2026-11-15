# Persistent plain RAR5 stored output

Enable `persistent-partials`. On Linux and macOS, `ProgressiveSession::new_partial` exclusively creates ordinary named files at full logical size. Existing output is never truncated or replaced, even with `Overwrite::Always`. Treat those files as read-only until the handle is closed; fill through `PartialFile`, and keep the output and state bundle together. Dropping the session or handle preserves both.

This H2 path accepts plain RAR5 Stored members with known sizes and a Complete source catalogue. RAR4, encryption, compression, redirections and unknown sizes are refused when known. Complete describes all source names and native handles; it grants no legacy publication receipt. `PersistentComplete` carries its own `Verdict`, and only `Verdict::Ok` permits archive metadata to be applied. Modified time and permissions report separate results.

`PartialReady` follows durable genesis and precedes payload reads. Retain its `MemberKey` and obtain a handle with `partial_file`. Each `Hole` describes an observed output range and exact packed spans; waiting for a provider is never damage. A fill cannot target unproduced preallocation. Known overlaps must match before any write. The handle can fill and poll verification while another member progresses, and survives session cancellation/drop. Deferred part checks appear in `Verdict::Incomplete.parts` as well as `Ok.parts`; a live `PartVerified` event is a mirror.

Persist serialized `PartialState` only as an untrusted cache. Keep `StateAnchorStore` in independently trusted durable storage: each mutation first durably CASes an intent, writes/syncs output, then durably CASes its commit. On `AnchorCommitUncertain`, retain all files and the reported committed anchor. The caller may explicitly retry the same operation on the live handle. After closing every owner, load the latest trusted anchor and `PartialState::load`, then reopen with matching expected member/anchor. A cached older state returns `StateStale`; it never rolls the trusted store back. Reopen synchronously rehashes known output with bounded reads, costing O(known output), and does not call a source provider.

The following Linux/macOS example uses a process-locked, atomically replaced anchor file with file and directory sync. Its directory must be trusted and exclusively managed by this store. The in-memory Complete provider illustrates source ownership; network providers implement the same wake/Wait/Hole contract. Choose stable job/archive bindings for your application. The example's byte-only serde adapter uses the public serde contract without another serialization dependency.

```no_run
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use zipfast::partial::*;
use zipfast::progressive::*;

// This directory is caller-owned trusted storage, separate from output/state.
// One process holds its OS lock; threads serialize each durable CAS.
struct DurableAnchors { root: PathBuf, directory: File, _lock: File, serial: Mutex<u64> }
impl DurableAnchors {
    fn open(root: &Path) -> PartialResult<Self> {
        fs::create_dir_all(root).map_err(store_io)?;
        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(root.join("store.lock")).map_err(store_io)?;
        lock.lock().map_err(store_io)?;
        Ok(Self { root: root.into(), directory: File::open(root).map_err(store_io)?, _lock: lock, serial: Mutex::new(0) })
    }
    fn path(&self, member: &MemberKey) -> PathBuf {
        fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
        self.root.join(format!("{}-{}-{:016x}-{}", hex(&member.binding().job),
            hex(&member.binding().archive), member.ordinal(), hex(member.identity())))
    }
    fn read(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        let file = match File::open(self.path(member)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(store_io(e)),
        };
        let mut bytes = Vec::new();
        file.take(41).read_to_end(&mut bytes).map_err(store_io)?;
        if bytes.len() != 40 { return Err(PartialError::new(PartialErrorKind::StateUnavailable)); }
        Ok(Some(StateAnchor::new(member.clone(), u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            bytes[8..].try_into().unwrap())))
    }
}
fn store_io(cause: std::io::Error) -> PartialError {
    PartialError::new(PartialErrorKind::Io { operation: OutputOperation::Flush, cause })
}
impl StateAnchorStore for DurableAnchors {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        let _guard = self.serial.lock().unwrap();
        self.read(member)
    }
    fn compare_exchange(&self, member: &MemberKey, expected: Option<&StateAnchor>, next: &StateAnchor) -> PartialResult<()> {
        let mut serial = self.serial.lock().unwrap();
        if next.member() != member || self.read(member)?.as_ref() != expected {
            return Err(PartialError::new(PartialErrorKind::AnchorConflict));
        }
        *serial = serial.checked_add(1).ok_or_else(|| PartialError::new(PartialErrorKind::StateUnavailable))?;
        let temporary = self.root.join(format!("new-{}-{}", std::process::id(), serial));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(store_io)?;
        file.write_all(&next.sequence().to_le_bytes()).map_err(store_io)?;
        file.write_all(next.digest()).map_err(store_io)?;
        file.sync_all().map_err(store_io)?;
        fs::rename(&temporary, self.path(member)).map_err(store_io)?;
        // A late error is uncertain: rename may have durably installed next.
        self.directory.sync_all().map_err(store_io)
    }
}
struct MemorySource { bytes: Vec<u8> }
impl RangeSource for MemorySource {
    fn info(&self) -> SourceInfo { SourceInfo { id: SourceId(1), generation: 0,
        extent: self.bytes.len() as u64, length: SourceLength::Final(self.bytes.len() as u64) } }
    fn backing_files(&self) -> &[File] { &[] }
    fn read_at(&mut self, offset: u64, out: &mut [u8], _: &mut std::task::Context<'_>) -> ProgressiveResult<RangeRead> {
        let start = usize::try_from(offset).map_err(|_| ProgressiveFailure::new(FailureKind::SourceContract))?;
        let input = self.bytes.get(start..).ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?;
        let count = input.len().min(out.len()); out[..count].copy_from_slice(&input[..count]);
        Ok(RangeRead::Filled { count })
    }
}
struct CompleteProvider { source: Option<MemorySource> }
fn catalogue() -> ProtectionDeclaration {
    ProtectionDeclaration::Complete { epoch: 1, inventory: ProtectionInventory {
        volumes: vec![ProtectedVolume { index: 0, name: "example.rar".into(), backing: VolumeBacking::NonFile }],
        auxiliary_paths: vec![],
    } }
}
impl VolumeSource for CompleteProvider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> { Ok(catalogue()) }
    fn volume(&mut self, request: &VolumeRequest, _: &mut std::task::Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        if request.index != 0 { return Ok(VolumeAnswer::Missing); }
        self.source.take().map(|source| VolumeAnswer::Ready(Box::new(source)))
            .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))
    }
}

# use serde::{Serializer, ser::Impossible};
# use serde::de::value::Error;
# struct Bytes;
# macro_rules! scalar {($($name:ident($t:ty)),* $(,)?)=>{$(fn $name(self,_:$t)->Result<Vec<u8>,Error> {Err(::serde::ser::Error::custom("only bytes accepted"))})*};}
# impl Serializer for Bytes {
#     type Ok = Vec<u8>;
#     type Error = Error;
#     type SerializeSeq = Impossible<Vec<u8>, Error>;
#     type SerializeTuple = Impossible<Vec<u8>, Error>;
#     type SerializeTupleStruct = Impossible<Vec<u8>, Error>;
#     type SerializeTupleVariant = Impossible<Vec<u8>, Error>;
#     type SerializeMap = Impossible<Vec<u8>, Error>;
#     type SerializeStruct = Impossible<Vec<u8>, Error>;
#     type SerializeStructVariant = Impossible<Vec<u8>, Error>;
#     scalar!(
#         serialize_bool(bool),
#         serialize_i8(i8),
#         serialize_i16(i16),
#         serialize_i32(i32),
#         serialize_i64(i64),
#         serialize_u8(u8),
#         serialize_u16(u16),
#         serialize_u32(u32),
#         serialize_u64(u64),
#         serialize_f32(f32),
#         serialize_f64(f64),
#         serialize_char(char),
#         serialize_str(&str)
#     );
#     fn serialize_bytes(self, v: &[u8]) -> Result<Vec<u8>, Error> {
#         Ok(v.to_vec())
#     }
#     fn serialize_none(self) -> Result<Vec<u8>, Error> {
#         Err(::serde::ser::Error::custom("only bytes accepted"))
#     }
#     fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<Vec<u8>, Error> {
#         self.serialize_none()
#     }
#     fn serialize_unit(self) -> Result<Vec<u8>, Error> {
#         self.serialize_none()
#     }
#     fn serialize_unit_struct(self, _: &'static str) -> Result<Vec<u8>, Error> {
#         self.serialize_none()
#     }
#     fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<Vec<u8>, Error> {
#         self.serialize_none()
#     }
#     fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, _: &T) -> Result<Vec<u8>, Error> {
#         self.serialize_none()
#     }
#     fn serialize_newtype_variant<T: ?Sized + Serialize>(
#         self,
#         _: &'static str,
#         _: u32,
#         _: &'static str,
#         _: &T,
#     ) -> Result<Vec<u8>, Error> {
#         self.serialize_none()
#     }
#     fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
#         Err(::serde::ser::Error::custom("only bytes accepted"))
#     }
#     fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
#         self.serialize_seq(None)
#     }
#     fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeTupleStruct, Error> {
#         self.serialize_seq(None)
#     }
#     fn serialize_tuple_variant(
#         self,
#         _: &'static str,
#         _: u32,
#         _: &'static str,
#         _: usize,
#     ) -> Result<Self::SerializeTupleVariant, Error> {
#         self.serialize_seq(None)
#     }
#     fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
#         self.serialize_seq(None)
#     }
#     fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
#         self.serialize_seq(None)
#     }
#     fn serialize_struct_variant(
#         self,
#         _: &'static str,
#         _: u32,
#         _: &'static str,
#         _: usize,
#     ) -> Result<Self::SerializeStructVariant, Error> {
#         self.serialize_seq(None)
#     }
# }
#
use serde::{Serialize, Deserialize};
use std::task::{Context, Poll};

fn start(archive: Vec<u8>, workspace: &Path) -> PartialResult<(ProgressiveSession, Arc<DurableAnchors>)> {
    let anchors = Arc::new(DurableAnchors::open(&workspace.join("trusted-anchors"))?);
    let extract = zipfast::extract::Options { mode: zipfast::extract::Mode::Extract,
        dest: workspace.join("output"), overwrite: zipfast::extract::Overwrite::Always,
        flatten: false, threads: Some(1), protected_paths: Default::default(), parallel_min: None };
    let session = ProgressiveSession::new_partial(
        Box::new(CompleteProvider { source: Some(MemorySource { bytes: archive }) }),
        ProgressiveOptions::new(extract, "example.rar".into()),
        PartialOptions { binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
            naming: PartialNaming::ArchivePath, state_dir: workspace.join("state"),
            limits: PartialLimits::default(), anchors: anchors.clone(),
            control: SessionControl::default() }, // independent from session.control()
    ).map_err(PartialError::from)?;
    Ok((session, anchors))
}

// Called by an executor. Pending means wait for its waker, never declare a hole.
fn early_handle(session: &mut ProgressiveSession, cx: &mut Context<'_>) -> PartialResult<Option<PartialFile>> {
    if let Poll::Ready(event) = session.poll_event(cx) {
        if let Some(ProgressiveEvent::PartialReady { member, state }) = event.map_err(PartialError::from)? {
            let bytes = state.serialize(Bytes).map_err(|_| PartialError::new(PartialErrorKind::StateMalformed))?;
            let decoded = PartialState::deserialize(serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(&bytes))
                .map_err(|_| PartialError::new(PartialErrorKind::StateMalformed))?;
            assert_eq!(decoded.anchor(), state.anchor());
            return session.partial_file(&member).map(Some);
        }
    }
    Ok(None)
}

// The caller explicitly chooses a retry; the library does not retry CAS errors.
fn repair(file: &mut PartialFile, report: &HoleReport, bytes: &[u8], retry_uncertain: bool) -> PartialResult<FillResult> {
    match file.fill(report.out.start, bytes) {
        Err(error) if retry_uncertain && matches!(error.kind, PartialErrorKind::AnchorCommitUncertain) =>
            file.fill(report.out.start, bytes),
        result => result,
    }
}

fn reopen_latest(workspace: &Path, member: MemberKey, anchors: Arc<DurableAnchors>) -> PartialResult<PartialFile> {
    let latest = anchors.current(&member)?.ok_or_else(|| PartialError::new(PartialErrorKind::StateUnavailable))?;
    let state = PartialState::load(&workspace.join("state"), &latest, &PartialLimits::default())?;
    PartialFile::open(state, PartialOpenContext { output_root: workspace.join("output"),
        state_root: workspace.join("state"), expected_member: member, expected_anchor: latest,
        protection: catalogue(), limits: PartialLimits::default(), progressive_limits: ProgressiveLimits::default(),
        anchors, control: SessionControl::default() })
}
# fn main() {}
```

Drive `poll_event` and `PartialFile::poll_verify` with your executor's context. Do not spin on provider waits. The source session and partial controls are independent; cancel the partial control only when you intend to stop its file operations. Ordinary filesystem reads are fine, but external writes, truncation, renaming, hardlink changes or replacing the roots invalidate ownership checks. Size, metadata, state, descriptor and event limits are enforced before their corresponding work; synchronous durable CAS and sync costs are intentional.

Lost headers/volumes, compressed/AES/RAR4 recovery, the full 500 MB acceptance workload, and resume cursor restoration remain later stages. This API does not silently emulate them.
