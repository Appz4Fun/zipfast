# Persistent RAR stored output

Enable `persistent-partials`. On Linux and macOS, `ProgressiveSession::new_partial` exclusively creates ordinary named files at full logical size. Existing output is never truncated or replaced, even with `Overwrite::Always`; the rename modes are refused with `FailureKind::InvalidCapability`. Treat those files as read-only until the handle is closed; fill through `PartialFile`, and keep the output and state bundle together. Dropping the session or handle preserves both.

This H2 path accepts RAR5 Stored members with known sizes and a Complete source catalogue, plain or encrypted (AES-256-CBC, with the password set through `ProgressiveOptions::set_password`), and plain RAR4 Stored members (see below). Encrypted headers (`-hp`, RAR4 or RAR5) end the session. Compressed members, encrypted RAR4 members, redirections and members of unknown size are refused one by one: the session skips them and goes on (see "Refused members and directory entries" below), and directory entries create their directory. Complete describes all source names and native handles; it grants no legacy publication receipt. `PersistentComplete` carries its own `Verdict`, and only `Verdict::Ok` permits archive metadata to be applied. Modified time and permissions report separate results.

`PartialReady` follows durable genesis and precedes payload reads. Retain its `MemberKey` and obtain a handle with `partial_file`. Once a member has finished and its handle has been taken with `partial_file`, the session drops its own reference: the member's state pages, descriptors and `open_partials` lease are freed when the caller drops its last handle, so a set's member count is not bounded by `state_pages` or `open_files`. Drop each handle when done with it. The session never verifies or extracts a released member again; `partial_file` returns another handle while one lives, and `BindingMismatch(Member)` after the last is dropped (reopen it with `PartialFile::open`). Damage that `declare_hole` maps to a released member whose handles were all dropped is listed in `DamageReceipt::released` as `(MemberKey, PackedSpan)`, never in `unmapped`: reopen that member with `PartialFile::open` and declare the span there with `PartialFile::declare_hole`. While a handle lives, the damage is applied to it as before. `PartialFile::relative_output_path` returns the sanitized output path relative to the output root (normal components only) and `PartialFile::output_path` the absolute path (the root made absolute joined with it), so a caller need not walk the output tree to find it. Each `Hole` describes an observed output range and exact packed spans; waiting for a provider is never damage. `Hole` and `BytesWritten` events arrive in output order: every hole below a `BytesWritten`'s `logical_end` has been delivered before it. A fill cannot target unproduced preallocation, except a tail abandoned with `abandon_tail` (see "Taking over an unfinished member" below). Known overlaps must match before any write. The handle can fill and poll verification while another member progresses, and survives session cancellation/drop. Whole-member `Ok` and archive metadata require the canonical member finish to be durably committed, even when every output byte is already known. A handle paused or closed before that finish returns `Incomplete` (possibly with no holes); reopen preserves this distinction. Deferred part checks appear in `Verdict::Incomplete.parts` as well as `Ok.parts`; a live `PartVerified` event is a mirror.

Damage can also be declared late, for example when an article's yEnc CRC turns out wrong after zipfast consumed it. `ProgressiveSession::declare_hole(volume, range)` takes zero-based volume and archive byte offsets at any time. Output already written from those bytes becomes `DeclaredBad` holes in each affected member; the returned `DamageReceipt` lists them, plus `unmapped` spans (header or padding bytes with no output) and `pending` spans not read yet. Pending bytes are skipped without asking the provider and reported as `Hole` events with cause `DeclaredBad` when reached. A finished member's handle sees the new holes, verifies `Incomplete` until they are filled, and then verifies `Ok` again. After the session ends, `PartialFile::declare_hole` does the same for one member. Declaring damage on a header that has not been read yet is not supported yet: the session stops with `HeaderHole` when it reaches it. Each member's holes are committed one durable run at a time, so if `declare_hole` returns an error part way, earlier runs may already be holes; `PartialFile::remaining` shows the current state and repeating the call reports only what is left. Pending ranges past the end of a volume are never reached and so never reported. Hole causes are kept in the durable state; states written before causes were recorded reopen with every hole as `Missing`, and a build from before causes were recorded cannot open a state that holds declared damage.

Large plaintext ranges can be streamed instead of passed as one slice. `PartialFile::fill_writer(offset)` returns a `FillWriter` (`std::io::Write`) that buffers at most `PartialLimits::fill_bytes` and writes each full buffer into a group commit (see below), so it commits once per `group_commit_bytes` rather than once per buffer; `finish()` writes the rest, commits, and returns the combined `applied` ranges. This suits RustyGet's alt switch, where `[offset_reached, end)` of the member comes from another copy and known bytes in that range must simply match. A failed write poisons the writer: `write` returns an `io::Error` with the message, and `finish` returns the typed `PartialError`. The writer then commits what earlier buffers wrote, if it can, and `position()` is the end of the committed bytes; ranges committed before stay filled. `PartialFile::fill_from(offset, len, reader)` does the same from an `io::Read` and fails with `FillRead` (with `output.completed`, the committed bytes) if the input errors or ends early. `fill_bytes` (default 1 MiB, at most 64 MiB) also bounds one `fill` or `fill_packed` call, one `refill_from_packed` step and each write of the extraction itself, so keep it at least `ProgressiveLimits::read_chunk`; a `FillWriter` buffer above 1 MiB is charged to the metadata budget while the writer lives.

Writes are committed in groups. Extraction writes and `FillWriter` / `fill_from` buffers join a group commit: before the first write of a group one intent is anchored (the committed head with the next sequence and revision; its ledger is unchanged, because the group only adds output the committed state calls unknown), output is then written with no further durable work, and the group commits once it holds `PartialLimits::group_commit_bytes` (default 64 MiB, at most 16 GiB) or has been open for `group_commit_interval` (default 2 s, at most an hour), checked at each write. The commit writes the ledger pages that changed, syncs the output, then appends and anchors the commit record. A session about to wait for a provider first commits a group older than the interval, so a stalled download does not keep written output uncommitted. Every other operation commits an open group before it runs: `fill`, `fill_packed`, `refill_from_packed`, `declare_hole` (on the session or a handle), `remaining`, `state`, `close`, `poll_verify`, the member finish, and recording a hole. A hole therefore forces a commit: the group before it is committed, then the hole is committed as its own transaction, so a `Hole` event and the reports `declare_hole` returns are durable when delivered, as before. Volume boundaries do not commit: the new part, admission and header witness join the open group and commit with it. When the last owner of a handle drops (session and every `PartialFile`), an open group is committed if that still succeeds, except while the thread is panicking: that commit syncs files and calls your anchor store, and a second panic during unwinding would abort the process, so the group is then left uncommitted, exactly as after a crash. `group_commit_bytes` 0 restores one durable transaction per write; `fill` and `fill_packed` stay one transaction per call either way.

Grouping keeps the durability rules: an intent is anchored before any write to output the committed state does not already claim, the output is synced before the commit that claims it, and every anchor change is a CAS. After a crash, reopen sees the last anchored state: output committed by earlier groups is known (and verified by the reopen rehash), and everything a group wrote after its intent is unknown, like a hole that extraction or a refill can produce again. So the durable `produced` is the committed one, and it can lag the written output by up to one group: after a restart (see below), a member mid-extraction resumes from the committed `produced` in its `PartialState`, never from the last `BytesWritten`, and the uncommitted tail is extracted again. `BytesWritten` and `PartVerified` events report output written, which may not be committed yet; `PartialFile::state` commits any open group and returns a state covering everything written so far. An ambiguous CAS of a group commit is reported as `AnchorCommitUncertain` like any other, and the next operation rebuilds from whichever state the store holds; a `FillWriter` that fails that way sets `position()` (and `fill_from` its `output.completed`) from the rebuilt state. A compaction needed while a group commits re-anchors the group's intent, never the output the group wrote ahead of it.

Commits write only the ledger pages that changed. Pages are content addressed: a page equal to one this handle already wrote durably is not written or synced again, and the last encoding is kept in memory so an unchanged page is not hashed again either. A member whose extent ledger exceeds 128 KiB (about 390 MiB of output) splits its validity ledger by output window into at most 24 pages (and at most `state_pages / 2 - 4`, so a smaller `state_pages` gets fewer, larger windows, or the single-stream layout below two), with the extent count and the hole list on small pages of their own and unknown gaps cut on absolute 64 KiB boundaries, so a group commit writes the count page, the one or two windows it touched, and the hole list only if it changed. The state format is unchanged (pages of one kind are concatenated on decode), so earlier builds read these states, and smaller members encode exactly as before. Each commit still re-encodes the ledger in memory and compares it with the last encoding, a linear pass of 21 bytes per 64 KiB of member (about 0.3 MiB per GiB).

With these defaults one durable commit covers 64 MiB instead of 1 MiB: on a 2 GiB stored member over 40 local volumes (macOS, `F_FULLFSYNC`), file and directory syncs went from about 18,000 to about 240 per GiB and anchor CAS calls from about 2,100 to about 35 per GiB. `examples/persistent_bench.rs` measures this against a plain progressive extraction of the same set.

Holes can also be filled from archive bytes instead of plaintext. `PartialFile::fill_packed(volume, offset, bytes)` takes raw bytes of a volume file, for example from a byte-identical twin post or a par2-repaired slice, and maps them to this member's output. A fill may be larger than the holes it covers and may include headers, good bytes or other members: bytes that map to no produced output of this member come back in `unmapped`, and bytes over output the original extraction wrote must match or the call fails with `OverlapMismatch` before writing anything. Archive bytes win over alt bytes: output previously filled with `fill` whose bytes differ is rewritten and listed in `corrected`, so the caller can stop trusting that alt. If such a rewrite fails part way, the corrected range stays a `DeclaredBad` hole that any later fill can complete. `PartialFile::refill_from_packed(volume, range, reader)` is the same after a volume was repaired in place: it reads from `reader` only the packed bytes whose output is still a hole or came from an alt, so the cost follows the damaged ranges rather than the volume size. Alt bytes that archive bytes confirm count as archive output from then on, so later refills skip them. Each call commits at most `PartialLimits::fill_bytes` bytes per transaction; if a later step fails (for example `PackedRead` when the caller's volume cannot be read, with `volume` and `packed_offset` set), the error's `packed_progress` lists what earlier steps already applied and corrected. Both work for plain and encrypted stored members.

Encrypted stored members are one AES-256-CBC ciphertext stream across all their parts; a volume boundary never resets CBC. Ciphertext stream offset `c` is output offset `c`, clipped at the unpacked size, and the final padding maps to no output. Plaintext block `k` needs ciphertext blocks `k` and `k - 1` (the header IV for block 0), so a hole is reported on 16-byte block boundaries: blocks whose ciphertext overlapped unavailable or declared bytes are `Missing` or `DeclaredBad`, and the one block after them, whose own ciphertext arrived, is a separate report with cause `CipherNeighbour`. A hole in the final padding loses the last block, and its report ends at the unpacked size. The packed spans of a report are its whole ciphertext blocks, padding included, one span per volume piece. One feed can produce several reports, and the `CipherNeighbour` report of a hole can arrive with the following data feed. `declare_hole` widens the same way.

`fill` takes plaintext and works exactly as for plain members; this is the alt path. `fill_packed` and `refill_from_packed` take ciphertext and decrypt it with the previous ciphertext block, taken from the supplied bytes or from a small durable record of ciphertext blocks next to holes: the extraction keeps the block before each hole and each `CipherNeighbour` block, and `fill_packed` keeps the edge blocks (or the part of a block a volume boundary or a fill boundary cut) that a remaining hole still needs, so filling volume by volume decrypts the blocks cut by volume boundaries. A block whose previous block is in neither is left unfilled and listed in `PackedFillResult::undecryptable`. `refill_from_packed` reads each damaged range from one block before it. Declared damage drops every kept block it overlaps, since that ciphertext is no longer trusted, and keeps none of its own; filling a declared hole from archive bytes needs an intact block before it, from the same fill, from a block kept for an earlier hole, or from an earlier fill that kept it. The record never holds keys or passwords; it is written only when it is not empty, so states without it decode unchanged. Plaintext output still has to match wherever the original extraction wrote it.

RAR5 keys an encrypted member's part and member CRC32/BLAKE2sp with the password when the encryption record says so (`rar5_tweak_crc32`, `rar5_tweak_blake2sp`), and part checks always cover ciphertext. So encrypted parts never check plaintext output: their `PartCheck`s report `Missing` and no `PartVerified` event is emitted. Member checks are verified on the plaintext with the hash key applied. A session-created handle holds the keys in memory only. `PartialFile::open` derives them from the header witness and `PartialOpenContext::password` (KDF work counts against the progressive limits); a password that fails the archive's check value is `WrongPassword`. Without a password, `fill`, `remaining` and `declare_hole` work, `fill_packed` fails with `PasswordRequired`, and `poll_verify` returns `Incomplete` while holes remain and then fails with `PasswordRequired` instead of `Ok` when the member checks are keyed. Without a check value a wrong password cannot be detected at open. `fill_packed` then writes nothing until the password has decrypted one whole block of output the original extraction wrote, and that block matches: a fill that includes such a block proves the password for the handle (a mismatch is `WrongPassword`), and a fill without one that would write unresolved output fails with `PasswordUnverified`. While the password is unproven, `refill_from_packed` reads two blocks before each damaged range instead of one, so the second decrypts output the extraction wrote and proves it (unless that output is itself a hole or alt output, or the range starts at the beginning of the member's piece in that volume, where no earlier block of the volume exists); exact report spans alone do not. In those cases `fill_packed` with bytes that also cover output the extraction wrote, such as the whole volume, proves the password. One block per original leaf is tried, so an original block that is itself wrong does not refute a correct password. Plaintext `fill` is not checked; with a wrong password keyed member checks then verify `Bad`.

RAR4 Stored members (method 0x30, unpack version 20 or 29) are admitted plain, unsplit or split across `.rar`/`.r00` or `.partNN.rar` volumes, wherever the progressive RAR4 path reads them. Packed bytes map one to one onto output, so `Hole` reports, `declare_hole`, `fill`, `fill_packed`, `refill_from_packed`, reopen and verification behave exactly as for plain RAR5 members, and a hole across a volume boundary is reported once per volume. RAR4 has no BLAKE2sp: every check is a CRC32 combined from the known extents, so verification never reads output back (`VerifyPath::ExtentCombine`, or `ReopenRehash` after reopen). The member check is the file CRC in the final part's header. The CRC field of each non-final part's header holds the CRC32 of that part's packed data: unrar checks it as the packed-data hash for every unpack version from 20 on, which covers all the progressive path admits, and the RAR4 parser and member machine already verify it per part. For stored data that is the CRC of the part's output range, so a clean non-final part emits `PartVerified` during extraction and a wrong fill there verifies `PartBad` naming its volume. A wrong byte in the final part verifies `Bad`, because the final header carries only the member CRC. A non-final CRC field of `0xFFFFFFFF`, which unrar skips as "no hash", is treated as a CRC like any other, as everywhere else on the progressive RAR4 path. A caller that rebuilds a volume before it has every packed byte, reporting the missing ranges as `RangeRead::Hole` and patching them later with `refill_from_packed`, can't know that part's CRC. Set `ProgressiveOptions::rar4_unknown_part_crc` and store 0 in that part's CRC field: a non-final RAR4 part whose CRC field is 0 is then read as having no part check, as a RAR 5.0 part without a data CRC is. Its `PartCheck` reports `Missing` and no `PartVerified` event is emitted. The member CRC in the final part is never affected: a final part's 0 is still the member check, and that check and `poll_verify` after the refill still judge the whole file. A state written this way reopens through `PartialFile::open` with the part still unchecked, with no option needed. A restarted persistent session must set the option as the original did: without it, the session reads the 0 as a CRC again, so it fails that part's check, or ends with `BindingMismatch(Source)` once the part is already recorded in the state. With the option off, the default, a 0 that does not match the part is a part CRC mismatch as before. A real part CRC of 0 also loses its part check while the option is on. RAR4 members have their own identity domain, so a RAR4 and a RAR5 member never share a `MemberKey` or a state bundle. A RAR4 state records its format so reopen parses its header witnesses as RAR4; RAR5 states are unchanged, and builds without RAR4 support refuse RAR4 states. RAR4 header encryption ends the session with `UnsupportedMethod` before any output or state is created. Encrypted RAR4 members, compressed RAR4 members and members with an all-ones RAR4 size are refused per member (`RefusalReason::Encrypted`, `Compressed`, `UnknownSize`), with no output or state for them.

Volumes can be declared as they become known, for example when obfuscated posts get their final names from par2 later. This is opt-in: the provider returns true from `VolumeSource::extends_protection`, which a persistent session reads once when it starts. Without it a persistent session keeps the frozen contract exactly. A persistent session whose provider opts in may start with a Complete declaration naming only the volumes known so far. Later `VolumeSource::protection` answers may declare more volumes and auxiliary paths with a higher epoch, provided every earlier entry (index, name and backing, including its native paths and handles) is unchanged; an absent handle may later be supplied. Anything else is refused with `SourceChanged`: an altered or removed entry, a lower epoch, or a different inventory at the same epoch. When the session requests an index the current declaration does not name, it does not fail: it still asks the provider, so the provider learns which volume is needed. Answer `Wait` and wake the request's waker once a declaration names the volume; the session reads the declaration again on every attempt and then admits the volume with the usual name, alias and identity checks. If the provider answers `Ready` before declaring the volume, the session reads the declaration once more, and if the volume is still undeclared it holds the source unread and waits for the same waker. Each appended path is checked when it is declared against every output, state bundle and lock the session created under an earlier epoch, canonicalised as member creation canonicalises, so a symlinked-directory alias is caught too (a match fails with `UnsafePath`). Members created later are guarded against the whole current declaration: once every parent directory is checked, and before any name is created, the output and bundle are checked against the declaration as it stands then, and creation is prepared again if it grew meanwhile. An extension that fails after its new paths were bound leaves the session failed. Ordinary sessions (except with the library-owned `GrowingFileVolumes`, see `docs/growing-volumes.md`), and persistent sessions whose provider does not opt in, keep frozen declarations: an extension there is still `SourceChanged`, and an undeclared volume is still `SourceContract`. Persistent state does not record the declaration, and `PartialFile::open` only checks that `PartialOpenContext::protection` is Complete and names neither the output nor the bundle. So reopen accepts the newest declaration, or any other Complete one that meets that check, and a member created before an extension reopens under the extended declaration. The state does not record the highest epoch seen either, so reopen cannot refuse an older declaration that omits later volumes: the caller must pass the newest one it holds, or the reopened member is not guarded against the omitted paths. Recording the epoch would mean a journaled state commit on every live member whenever the declaration grows.

We chose append-only epochs over a NonFile inventory whose names are confirmed at admission. With append-only epochs the current declaration is always a complete, validated statement of everything admitted so far: name coverage, native identity binding, alias checks and the output exclusions apply exactly as they did, and each extension is checked once, when it is declared. Placeholder names would mean admitting volumes the declaration never named, and native paths that appear only at admission would bypass the up-front alias checks.

Persist serialized `PartialState` only as an untrusted cache. Keep `StateAnchorStore` in independently trusted durable storage: each mutation (or group of writes) first durably CASes an intent, writes/syncs output, then durably CASes its commit. On `AnchorCommitUncertain`, retain all files and the reported committed anchor. The caller may explicitly retry the same operation on the live handle. After closing every owner, load the latest trusted anchor and `PartialState::load`, then reopen with matching expected member/anchor. A cached older state returns `StateStale`; it never rolls the trusted store back. Reopen synchronously rehashes known output with bounded reads, costing O(known output), and does not call a source provider.

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
        flatten: false, threads: Some(1), protected_paths: Default::default(), parallel_min: None, select: None,
        windows_safe_names: false };
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

A persistent session resumes a set after a restart. Start `new_partial` again with the same output root, `state_dir`, `ArchiveBinding` and anchor store (and the password of an encrypted set). The session walks the archive from the first volume as before; at each member header it derives the member's `MemberKey` (binding, member ordinal, digest of the first header) and asks the anchor store for it. A member with an anchor is adopted instead of created, and the session delivers `PartialAdopted { member, state, produced, finished }` where it would deliver `PartialReady`; obtain its handle with `partial_file` as usual. Adoption creates and rewrites nothing: it loads the anchored state, rebinds the output and bundle (the native identities recorded at genesis must match), checks the paths against the current declaration as a creation does and registers them as exclusions, and rehashes the known output, so it costs a local read of the member's known output, like `PartialFile::open`. The output path, name and size, the first part and its header witness, and later every part the state already records (with its header witness) must match the archive being read.

- A member whose canonical finish is committed (`finished`), with or without holes left, is not extracted again. Its parts are walked header by header: the session reads each volume's headers but seeks over the member's data, so no data byte of it is read from the source. Its `MemberFinished` follows with its current outcome (`PersistentComplete` with its verdict, or `PersistentPartial` while holes remain), and nothing is committed for it.
- Any other member continues from its committed `produced`. The session seeks to the packed offset that maps there and feeds the member machine from it; nothing before it is read again, except, for an encrypted member, the previous 16-byte ciphertext block, which is the CBC state at that point (it may lie partly in the previous volume; if the source answers it as a hole, the first block after the resume point is a `CipherNeighbour` hole). The machine's hash state at the resume point is rebuilt from the known output: the member CRC32 by combining the leaves the reopen rehash verified, its BLAKE2sp (when the member has one) and the current part's CRC32/BLAKE2sp by reading that output back. If the output before the resume point has holes, or holds alt output (from `fill`), the member check (or the part check) is not judged while streaming, as after a hole; `poll_verify` returns `Incomplete` until holes are filled, and then judges the output. A resumed member's streaming checks never end the session: archive bytes a `fill_packed` wrote cannot be told apart from extracted output, so a mismatch marks the check missing and `poll_verify` reports it as `Bad` or `PartBad`, while the session goes on with the next member, as it does without a restart. The machine starts the part it resumes in, so that part is checked as its own header declares. An encrypted part's checks cover ciphertext the resume skipped, so the part the member resumes in is not checked (encrypted parts never report plaintext part results anyway); member checks are unaffected. A member resumed exactly at a part boundary resumes at the end of the earlier part, whose check is then judged on the rebuilt hash. A member whose every output byte was committed but whose canonical finish was not only performs the finish.
- Holes recorded before the crash stay holes and stay fillable; output an uncommitted group wrote is unknown to the anchored state, so it is extracted again. Damage declared with `declare_hole` on bytes the earlier session had not reached yet is not remembered: declare it again. Damage declared on the resumed session on bytes its walk then skips (output already produced, of a finished or the resumed member) is applied to that output when the walk passes it: it becomes `DeclaredBad` holes, delivered as `Hole` events, and leaves the pending set. Damage on an encrypted member's previous ciphertext block, declared before or while the session reads it, makes the output decrypted from that block `DeclaredBad` holes and the first block after the resume point a `CipherNeighbour` hole.
- A crash during the resumed session leaves the same kind of state, and the next session resumes again.
- Members the earlier session never reached are created as usual. The reserved cursor field of the state stays unused: the resume point is derived from the committed `produced` and the recorded part map, so the state format is unchanged.
- With `VolumeSource::extends_protection`, the restarted provider may again declare only the volumes known so far: adopted paths are checked against the declaration current at adoption, and later extensions are checked against them like any created member's paths.

Adoption is refused, with the session failing on the typed error and every file left as it is, when the member does not match: `BindingMismatch(Member)` for another output path, name or size; `BindingMismatch(Source)` for a recorded part or header witness that differs; `BindingMismatch(Output)` for a replaced output, parent or bundle (other native identities); `OutputChanged` for known output whose bytes changed; `StateUnavailable` when the anchored state is gone; `UnsafePath` for a path the current declaration names. Another archive whose members have the same names has other first headers and so other member keys, so its members are not adopted: creating them finds the existing outputs and fails with `AlreadyExists`, exactly as before, and the existing output is never overwritten. We chose failing the session over skipping the member so that a mismatch is never mistaken for a member that needs no work; per-member refusal (below) deliberately does not cover adoption mismatches. A member whose genesis was cut short before the output reached its full size cannot be adopted (`OutputChanged`); nothing was produced for it, so remove its anchor, bundle and output and restart.

## Refused members and directory entries

A persistent session refuses, one member at a time, what it cannot keep as a persistent partial: a compressed member (`RefusalReason::Compressed { method }`), an encrypted RAR4 member (`Encrypted`), a member of unknown size (`UnknownSize`, the RAR5 flag or an all-ones RAR4 size) and a link or file copy (`Redirection`: a RAR 5.0 redirection record or a RAR4 Unix symbolic link). The member gets its `MemberStarted` as usual, and then, with no event in between, `MemberFinished` with `MemberOutcome::Refused { reason }`. Nothing is created for it: no output, no state bundle, no anchor, no parent directory, no `PartialReady`. Its data is skipped without being read: the session seeks past each of its parts, opening later volumes only to read their headers, so a refused member costs no download of its data. The session then goes on with the next member, so RustyGet can extract a refused member afterwards with an ordinary session (for example with `Overwrite::Skip` over the same root, which skips the persistent outputs that exist). Refused members still count in the member ordinals, so `MemberKey`s of later members do not depend on whether earlier ones were refused.

Only what walking past the member needs is checked: header CRCs, framing, that each later part continues the same member, as for any member, and that its data lies within its volume (data running past the volume end is `Truncated`, as reading it would be). The checks that only matter for decoding or writing (RAR4 decoder features, solid RAR4 history, an encrypted member's salt or password, the safety of its name) are not applied to a refused member, since nothing is ever created for it. Damage declared with `declare_hole` on a refused member's data is dropped when the session skips it: it was reported as `pending` and is never reported as a hole, because no output exists for it. A later part of an admitted member that would be refused (which continuation checks already exclude) still fails the session, as before. Problems that make the set unwalkable still end the session: malformed or truncated headers, header holes, and encrypted headers (`-hp`), which this path does not open.

In a solid archive every compressed member is refused, and that does not make any stored member a refusal: stored data never reads or feeds the solid history, so the stored members before, between and after them are extracted as usual. An ordinary session extracting one of the refused solid members must decode every compressed member before it in the solid group; an ordinary session walking the set from the start does that by itself, also when it skips the stored members whose outputs exist.

A directory entry creates its directory under the output root with the checks a member creation applies to its parents: each missing ancestor and the directory itself are checked against the current declaration (a path it names is `UnsafePath`) before any name is created, then created exclusively beneath its held parent (mode 0700 until its metadata is applied), its parent synced, and registered so a later extension of the declaration cannot name it. Below the output root every component, existing or created, is opened relative to its held parent without following symbolic links, for directory entries and for a file member's parents alike: a file or a symbolic link where the directory or any of its parents goes ends the session with `UnsafePath`, and nothing is created or changed through the link. (The output root itself, as the caller gives it, may be reached through links.) An existing directory is kept. The entry finishes with `MemberOutcome::Directory { created }`, where `created` means this session created the directory: for this entry, or earlier as the parent of a member stored before its entry, as RAR usually stores directory records after their files. It is not a persistent partial and has no anchor, bundle or handle.

Only a directory the session created (in either way) gets the entry's modified time and permissions; a directory that existed before the session is left exactly as it was. They are applied when the session reaches the end of the set, deepest directories first and the last entry for a directory winning, as an ordinary session does, with two exceptions so that metadata never breaks the session's own files: a directory that is, or holds, the state root or a path the declaration names (a native volume path or an auxiliary path) gets no metadata at all, and a directory that holds an output of this session keeps its owner's read, write and search permission (the entry's mode with 0700 added). A directory replaced meanwhile (including by a symbolic link) ends the session with `OutputChanged` and is left alone. A session that ends early does not apply them; a restart finds the directories existing (`created: false`) and leaves them as they are, so it does not fix up directories an earlier session created.

After a restart (see above) the walk meets the same members: refused members are refused again with the same reasons, directories are found (`created: false`), and members before and after them are adopted with the same keys.

Lost headers and volumes, compressed members as persistent partials, encrypted RAR4 members as persistent partials, encrypted-header recovery and the full 500 MB acceptance workload remain later stages. This API does not silently emulate them.

## Taking over an unfinished member

When the primary download dies mid-member, its session never reaches the member's end: a missing volume ends it, and a volume that never arrives parks it. To finish the member from another copy packed differently, keep its `PartialFile` and call `abandon_tail(supplied: Option<MemberChecks>)`. It ends the member at its committed `produced` and reads nothing more. `[produced, size)` becomes one hole with cause `HoleCause::TailAbandoned`, and the method returns that hole's report; its start is the offset to resume from. The member then counts as finished. Fill the hole with plaintext (`fill`, `fill_writer`, `fill_from`; for example `MemberReader` from that offset into `fill_writer`), and `poll_verify` reaches `Verdict::Ok` once every byte is known and the checks pass. The handle, output file and inode stay the same.

The checks:

- If the extraction already read the member's final checks, the archive's checks are kept (`TailChecks::Archive`). `supplied` may be `None`; if given, it must agree where both are plain values, or the call fails with `BindingMismatch(Member)`.
- Otherwise `supplied` is required (`InvalidOptions` without it): `size` must equal the member's, and it must carry a CRC-32 or BLAKE2sp. Take them from the alt's `MapMember::checks` when `keyed` is false, from the release's known size and CRC, or from the primary's final volume once its header is available (map it with `MemberMap`). They are compared as plaintext values, never keyed with the password, even for an encrypted RAR5 member whose own checks are keyed (`TailChecks::Supplied`).
- `PartialFile::tail_checks()` says which applies.

What `Verdict::Ok` claims: with `Archive` checks, what it claims for any member. With `Supplied` checks, only that the whole output matches the checks the caller gave. The prefix came from the archive; the tail came from wherever the caller filled it. Treat the result as verified only to the extent you trust those checks: a CRC-32 from the release's own listing or the alt's archive is as strong as the alt; a value from an untrusted source proves nothing. A wrong supplied CRC gives `Verdict::Bad { which: Crc32 }`. Part checks of the parts the primary recorded still run on their own ranges.

Durability: the abandon is one transaction. A crash leaves the state before it (the tail is still unproduced) or the abandoned one. Fills of the tail are ordinary fills (grouped, then committed). After a restart, reopen the handle with `PartialFile::open` and go on filling from `remaining()`. A restarted session (see the resume after a restart above) adopts the member as finished (`PartialAdopted { finished: true }`), writes nothing, and walks past any later parts of it. A session still extracting the member when it is abandoned fails with `PartialErrorKind::TailAbandoned` on its next write; the handle stays usable. Abandoning again with the same checks returns the same report; other checks are `TailAbandoned`. A member whose extraction finished has no tail (`InvalidOptions`).

Encrypted members (RAR5 AES-256-CBC): the produced prefix ends on a block boundary, and the tail is filled with plaintext, so no ciphertext, IV or key is needed for it. The abandoned hole's packed spans list only the archive bytes the recorded parts hold. `fill_packed` and `refill_from_packed` still work on holes in the produced prefix.

