# Persistent RAR5 stored output

Enable `persistent-partials`. On Linux and macOS, `ProgressiveSession::new_partial` exclusively creates ordinary named files at full logical size. Existing output is never truncated or replaced, even with `Overwrite::Always`. Treat those files as read-only until the handle is closed; fill through `PartialFile`, and keep the output and state bundle together. Dropping the session or handle preserves both.

This H2 path accepts RAR5 Stored members with known sizes and a Complete source catalogue, plain or encrypted (AES-256-CBC, with the password set through `ProgressiveOptions::set_password`). RAR4, encrypted headers (`-hp`), compression, redirections and unknown sizes are refused when known. Complete describes all source names and native handles; it grants no legacy publication receipt. `PersistentComplete` carries its own `Verdict`, and only `Verdict::Ok` permits archive metadata to be applied. Modified time and permissions report separate results.

`PartialReady` follows durable genesis and precedes payload reads. Retain its `MemberKey` and obtain a handle with `partial_file`. Each `Hole` describes an observed output range and exact packed spans; waiting for a provider is never damage. `Hole` and `BytesWritten` events arrive in output order: every hole below a `BytesWritten`'s `logical_end` has been delivered before it. A fill cannot target unproduced preallocation. Known overlaps must match before any write. The handle can fill and poll verification while another member progresses, and survives session cancellation/drop. Whole-member `Ok` and archive metadata require the canonical member finish to be durably committed, even when every output byte is already known. A handle paused or closed before that finish returns `Incomplete` (possibly with no holes); reopen preserves this distinction. Deferred part checks appear in `Verdict::Incomplete.parts` as well as `Ok.parts`; a live `PartVerified` event is a mirror.

Damage can also be declared late, for example when an article's yEnc CRC turns out wrong after zipfast consumed it. `ProgressiveSession::declare_hole(volume, range)` takes zero-based volume and archive byte offsets at any time. Output already written from those bytes becomes `DeclaredBad` holes in each affected member; the returned `DamageReceipt` lists them, plus `unmapped` spans (header or padding bytes with no output) and `pending` spans not read yet. Pending bytes are skipped without asking the provider and reported as `Hole` events with cause `DeclaredBad` when reached. A finished member's handle sees the new holes, verifies `Incomplete` until they are filled, and then verifies `Ok` again. After the session ends, `PartialFile::declare_hole` does the same for one member. Declaring damage on a header that has not been read yet is not supported yet: the session stops with `HeaderHole` when it reaches it. Each member's holes are committed one durable run at a time, so if `declare_hole` returns an error part way, earlier runs may already be holes; `PartialFile::remaining` shows the current state and repeating the call reports only what is left. Pending ranges past the end of a volume are never reached and so never reported. Hole causes are kept in the durable state; states written before causes were recorded reopen with every hole as `Missing`, and a build from before causes were recorded cannot open a state that holds declared damage.

Large plaintext ranges can be streamed instead of passed as one slice. `PartialFile::fill_writer(offset)` returns a `FillWriter` (`std::io::Write`) that buffers at most `PartialLimits::fill_bytes` and commits each full buffer as one `fill` transaction; `finish()` commits the rest and returns the combined `applied` ranges. This suits RustyGet's alt switch, where `[offset_reached, end)` of the member comes from another copy and known bytes in that range must simply match. A failed transaction poisons the writer: `write` returns an `io::Error` with the message, and `finish` returns the typed `PartialError`. Ranges committed before stay filled. `PartialFile::fill_from(offset, len, reader)` does the same from an `io::Read` and fails with `FillRead` (with `output.completed`) if the input errors or ends early. `fill_bytes` also bounds each write of the extraction itself, so keep it at least `ProgressiveLimits::read_chunk`.

Holes can also be filled from archive bytes instead of plaintext. `PartialFile::fill_packed(volume, offset, bytes)` takes raw bytes of a volume file, for example from a byte-identical twin post or a par2-repaired slice, and maps them to this member's output. A fill may be larger than the holes it covers and may include headers, good bytes or other members: bytes that map to no produced output of this member come back in `unmapped`, and bytes over output the original extraction wrote must match or the call fails with `OverlapMismatch` before writing anything. Archive bytes win over alt bytes: output previously filled with `fill` whose bytes differ is rewritten and listed in `corrected`, so the caller can stop trusting that alt. If such a rewrite fails part way, the corrected range stays a `DeclaredBad` hole that any later fill can complete. `PartialFile::refill_from_packed(volume, range, reader)` is the same after a volume was repaired in place: it reads from `reader` only the packed bytes whose output is still a hole or came from an alt, so the cost follows the damaged ranges rather than the volume size. Alt bytes that archive bytes confirm count as archive output from then on, so later refills skip them. Each call commits at most `PartialLimits::fill_bytes` bytes per transaction; if a later step fails (for example `PackedRead` when the caller's volume cannot be read, with `volume` and `packed_offset` set), the error's `packed_progress` lists what earlier steps already applied and corrected. Both work for plain and encrypted stored members.

Encrypted stored members are one AES-256-CBC ciphertext stream across all their parts; a volume boundary never resets CBC. Ciphertext stream offset `c` is output offset `c`, clipped at the unpacked size, and the final padding maps to no output. Plaintext block `k` needs ciphertext blocks `k` and `k - 1` (the header IV for block 0), so a hole is reported on 16-byte block boundaries: blocks whose ciphertext overlapped unavailable or declared bytes are `Missing` or `DeclaredBad`, and the one block after them, whose own ciphertext arrived, is a separate report with cause `CipherNeighbour`. A hole in the final padding loses the last block, and its report ends at the unpacked size. The packed spans of a report are its whole ciphertext blocks, padding included, one span per volume piece. One feed can produce several reports, and the `CipherNeighbour` report of a hole can arrive with the following data feed. `declare_hole` widens the same way.

`fill` takes plaintext and works exactly as for plain members; this is the alt path. `fill_packed` and `refill_from_packed` take ciphertext and decrypt it with the previous ciphertext block, taken from the supplied bytes or from a small durable record of ciphertext blocks next to holes: the extraction keeps the block before each hole and each `CipherNeighbour` block, and `fill_packed` keeps the edge blocks (or the part of a block a volume boundary or a fill boundary cut) that a remaining hole still needs, so filling volume by volume decrypts the blocks cut by volume boundaries. A block whose previous block is in neither is left unfilled and listed in `PackedFillResult::undecryptable`. `refill_from_packed` reads each damaged range from one block before it. Declared damage drops every kept block it overlaps, since that ciphertext is no longer trusted, and keeps none of its own; filling a declared hole from archive bytes needs an intact block before it, from the same fill, from a block kept for an earlier hole, or from an earlier fill that kept it. The record never holds keys or passwords; it is written only when it is not empty, so states without it decode unchanged. Plaintext output still has to match wherever the original extraction wrote it.

RAR5 keys an encrypted member's part and member CRC32/BLAKE2sp with the password when the encryption record says so (`rar5_tweak_crc32`, `rar5_tweak_blake2sp`), and part checks always cover ciphertext. So encrypted parts never check plaintext output: their `PartCheck`s report `Missing` and no `PartVerified` event is emitted. Member checks are verified on the plaintext with the hash key applied. A session-created handle holds the keys in memory only. `PartialFile::open` derives them from the header witness and `PartialOpenContext::password` (KDF work counts against the progressive limits); a password that fails the archive's check value is `WrongPassword`. Without a password, `fill`, `remaining` and `declare_hole` work, `fill_packed` fails with `PasswordRequired`, and `poll_verify` returns `Incomplete` while holes remain and then fails with `PasswordRequired` instead of `Ok` when the member checks are keyed. Without a check value a wrong password cannot be detected at open. `fill_packed` then writes nothing until the password has decrypted one whole block of output the original extraction wrote, and that block matches: a fill that includes such a block proves the password for the handle (a mismatch is `WrongPassword`), and a fill without one that would write unresolved output fails with `PasswordUnverified`. While the password is unproven, `refill_from_packed` reads two blocks before each damaged range instead of one, so the second decrypts output the extraction wrote and proves it (unless that output is itself a hole or alt output, or the range starts at the beginning of the member's piece in that volume, where no earlier block of the volume exists); exact report spans alone do not. In those cases `fill_packed` with bytes that also cover output the extraction wrote, such as the whole volume, proves the password. One block per original leaf is tried, so an original block that is itself wrong does not refute a correct password. Plaintext `fill` is not checked; with a wrong password keyed member checks then verify `Bad`.

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
        anchors, control: SessionControl::default(), password: None })
}
# fn main() {}
```

Drive `poll_event` and `PartialFile::poll_verify` with your executor's context. Do not spin on provider waits. The source session and partial controls are independent; cancel the partial control only when you intend to stop its file operations. Ordinary filesystem reads are fine, but external writes, truncation, renaming, hardlink changes or replacing the roots invalidate ownership checks. Size, metadata, state, descriptor and event limits are enforced before their corresponding work; synchronous durable CAS and sync costs are intentional.

A persistent session keeps every opened original volume source open so later refills can revisit it, and each one counts against `ProgressiveLimits::volume_handles` (default 64, ceiling 4096). Raise that limit for sets with more volumes; past it, opening the next volume fails with `Limit { resource: VolumeHandles, .. }` rather than closing earlier sources.

Lost headers and volumes, compressed, RAR4 and encrypted-header recovery, the full 500 MB acceptance workload, and resume cursor restoration remain later stages. This API does not silently emulate them.
