# Persistent plain RAR5 stored output

Enable `persistent-partials`. On Linux and macOS, `ProgressiveSession::new_partial` exclusively creates ordinary named files at full logical size. Existing output is never truncated or replaced, even with `Overwrite::Always`. Treat those files as read-only until the handle is closed; fill through `PartialFile`, and keep the output and state bundle together. Dropping the session or handle preserves both.

This H2 path accepts plain RAR5 Stored members with known sizes and a Complete source catalogue. RAR4, encryption, compression, redirections and unknown sizes are refused when known. Complete describes all source names and native handles; it grants no legacy publication receipt. `PersistentComplete` carries its own `Verdict`, and only `Verdict::Ok` permits archive metadata to be applied. Modified time and permissions report separate results.

`PartialReady` follows durable genesis and precedes payload reads. Retain its `MemberKey` and obtain a handle with `partial_file`. Each `Hole` describes an observed output range and exact packed spans; waiting for a provider is never damage. A fill cannot target unproduced preallocation. Known overlaps must match before any write. The handle can fill and poll verification while another member progresses, and survives session cancellation/drop. Whole-member `Ok` and archive metadata require the canonical member finish to be durably committed, even when every output byte is already known. A handle paused or closed before that finish returns `Incomplete` (possibly with no holes); reopen preserves this distinction. Deferred part checks appear in `Verdict::Incomplete.parts` as well as `Ok.parts`; a live `PartVerified` event is a mirror.

Damage can also be declared late, for example when an article's yEnc CRC turns out wrong after zipfast consumed it. `ProgressiveSession::declare_hole(volume, range)` takes zero-based volume and archive byte offsets at any time. Output already written from those bytes becomes `DeclaredBad` holes in each affected member; the returned `DamageReceipt` lists them, plus `unmapped` spans (header or padding bytes with no output) and `pending` spans not read yet. Pending bytes are skipped without asking the provider and reported as `Hole` events with cause `DeclaredBad` when reached. A finished member's handle sees the new holes, verifies `Incomplete` until they are filled, and then verifies `Ok` again. After the session ends, `PartialFile::declare_hole` does the same for one member. Declaring damage on a header that has not been read yet is not supported yet: the session stops with `HeaderHole` when it reaches it. Each member's holes are committed one durable run at a time, so if `declare_hole` returns an error part way, earlier runs may already be holes; `PartialFile::remaining` shows the current state and repeating the call reports only what is left. Pending ranges past the end of a volume are never reached and so never reported. Hole causes are kept in the durable state; states written before causes were recorded reopen with every hole as `Missing`, and a build from before causes were recorded cannot open a state that holds declared damage.

Persist serialized `PartialState` only as an untrusted cache. Keep `StateAnchorStore` in independently trusted durable storage: each mutation first durably CASes an intent, writes/syncs output, then durably CASes its commit. On `AnchorCommitUncertain`, retain all files and the reported committed anchor. The caller may explicitly retry the same operation on the live handle. After closing every owner, load the latest trusted anchor and `PartialState::load`, then reopen with matching expected member/anchor. A cached older state returns `StateStale`; it never rolls the trusted store back. Reopen synchronously rehashes known output with bounded reads, costing O(known output), and does not call a source provider.

The following Linux/macOS example uses a process-locked, atomically replaced anchor file with file and directory sync. The exact [DurableAnchors implementation](persistent-anchor-store.rs) is compiled into this example and exercised by the public fault regression; copy it into your `anchor_store` module. Its directory must already exist, be trusted and be exclusively managed by this store. Before `open`, the caller must durably provision the root and every newly created ancestor link by syncing their parents; `open` deliberately does not create missing roots. Under the serialization lock, `current` syncs the anchor directory before acknowledging a visible anchor, so a failed rename-sync remains uncertain until that durability recovery succeeds. The in-memory Complete provider illustrates source ownership; network providers implement the same wake/Wait/Hole contract. Choose stable job/archive bindings for your application. The example's byte-only serde adapter uses the public serde contract without another serialization dependency.

```no_run
use std::{fs::File, path::Path, sync::Arc};
use zipfast::partial::*;
use zipfast::progressive::*;

# mod anchor_store { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/persistent-anchor-store.rs")); }
use anchor_store::DurableAnchors;

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

// Precondition: workspace/trusted-anchors and its ancestor links were durably provisioned.
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

A persistent session keeps every opened original volume source open so later refills can revisit it, and each one counts against `ProgressiveLimits::volume_handles` (default 64, ceiling 4096). Raise that limit for sets with more volumes; past it, opening the next volume fails with `Limit { resource: VolumeHandles, .. }` rather than closing earlier sources.

Lost headers and volumes, compressed/AES/RAR4 recovery, the full 500 MB acceptance workload, and resume cursor restoration remain later stages. This API does not silently emulate them.
