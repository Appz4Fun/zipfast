# Persistent Plain Stored Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an opt-in plain RAR5 Stored session whose named sparse output can be filled, checked and reopened independently after extraction ends or the process crashes.

**Architecture:** Share the canonical session/parser/physical model and minimal native range/path guards, with an independently owned PartialCore and bounded validity ledger. Every mutation first durably anchors conservative invalidation, then writes/syncs output, then durably anchors the commit. Legacy Artifact/default publication and failure behavior remain unchanged.

**Tech Stack:** Rust 1.100.0; existing libc/native I/O, CRC32/BLAKE2sp/SHA256; optional bounded manual serde support. No parser, crypto, payload spool or general storage framework is added.

**Spec:** [Persistent Stored holes design](../specs/2026-11-14-persistent-stored-holes-design.md). This H2 plan makes its plain-Store increment concrete; all later requirements remain required.

## Execution status — 2026-11-15T04:51:14.508174+00:00

Task 1 (H2-A) is privately reviewed and closed at `8106d3ff065dfcdc8298fd5588904c1cac6998dd`: original review's three Important findings fixed in round 1 and SAME scoped review three addressed/zero open. Final focused feature tests42/42, default output45/45 and integration2/2, fmt pass. Exact reviewed core was cleanly integrated with qualified public PR104 main `042aea4f8643419193f59a05b14cadd3d8650454` at merge `5ef870948c10a0d9b2dd60c6654132667e7eefb9`; joint feature42/42 passes without warnings. Source/receipt paths are in the SDD Task1 report and root final receipt. No full H2/public/platform claim follows.

Task 2 is next; its finite lease records the final implementation BASE (including this documentation-only status update). Initial H2 Task1 BASE was725471a, while later task BASEs contain the reviewed preceding implementation. Public algorithm baseline0030 below remains historical; API additions are now qualified at042. The frozen contracts and future all-nine/R1/full-compatibility scope remain unchanged.

Deferred Minor for final whole-branch review: whether predictable `SourceBookkeeping` work in exclusion reservation also needs genesis pre-admission. This is visible followup, not an unresolved blocker in the reviewed three-resource fix. Do not silently discard it or broaden the closed Task1 fix round. Tasks2/3 and final feature/default/platform gates remain required.

## Global Constraints

- Rust 1.100.0; private offline Cargo/target directories; jobs 3; no global cache mutation.
- No original reacquisition, duplicate-ID waiver, payload spool, second parser, source-generation rewrite or unsafe stage-path extraction.
- Preserve default one-pass source drops, callback counts, resource limits, publication and failure contracts.
- Existing metadata budget 128 MiB, read chunk 1 MiB, and 64 GiB byte-work budgets remain; these are not process RSS limits.
- No internal locks across provider/source callbacks, RawWaker clone/drop/wake hooks, or user source destructors.
- New persistent placement requires Complete source/protection catalogue, create-new names, known size and plain RAR5 Stored; incompatible known facts reject before output effects. Complete is not native publication authority.
- No normal PartialFile rename/delete/truncate; output shorter or longer on reopen is a typed mismatch. Session Drop/cancellation must not implicitly cancel/discard independent handles.
- Uniform two durable anchor CAS acknowledgements per bounded mutation; no payload redo store, self-hash authority or unanchored-tail validity.
- No 500 MB/native/oracle/benchmark campaign until a separate named root resource window. Existing ignored large tests remain ignored.

**Source gate:** Public algorithm baseline remains `0030c75a86f5ab7c1cf89a8dea91d55bdc435e86`. The privately qualified H1 source foundation is `301c89a60f1026928f61e192f09e242ea5b6d9e7`, tree `e3987aa47713c153a0b445daf6152afc640e606f`: task and whole-branch source reviews are clear, and exact-source private Rust 1.100 Mac fmt, strict Clippy, workspace/all-target (1,642 top-level passes plus 12 child summaries; 36 ignored) and doc (16 passes) gates passed. No new Linux/hosted/public-release or full-hole-acceptance claim follows. Required seams were first inspected at `7801082`; the final delta changes only two info-callback cancellation boundaries in source.rs, leaving constructor/control/protection interfaces intact. Root rechecked those affected methods and line locations at qualified301. The H2 implementation BASE will be the docs-only descendant recorded in its source lease. Private optional-serde qualification and a finite source lease remain required. The same H2 builder closed the standalone-part-result correction. Do not inspect or edit concurrent working source; this document alone authorizes no implementation.

## Review Focus

1. Anchor CAS returns an error after actually persisting: no guessed rollback or retry writes; query trusted current only on caller retry. Task 1 (H2-A).
2. Compaction, queue lag or forged tail hides newer validity/damage: retain the last acknowledged bundle, reject stale input and never certify unanchored records. Task 1 (H2-A).
3. A state/output path aliases a later source, or an independently opened writer races the first: reject before input reads/output mutation, preserve all descriptors/bytes. Tasks 1/3 (H2-A/H2-C).
4. CRC leaf splitting, part boundaries and absent/BLAKE checks differ: do not split aggregate CRC algebraically or report size-only Ok. Task 2 (H2-B).
5. Session Drop, same-core reentrant callbacks or different task wakers affect a surviving handle: independent control/lifetime, Busy for reentrancy, no lost cancellation or stale verdict. Tasks 1/3 (H2-A/H2-C).

---

## Source files and responsibilities

| Task | Create | Modify, narrowly |
|---|---|---|
| 1 (H2-A) | `src/partial/mod.rs`, `types.rs`, `limits.rs`, `native.rs`, `state.rs`, `journal.rs`, `anchor.rs`, `tests/state.rs`, `tests/native.rs`, `tests/serde.rs`; `src/output/range.rs`; `src/progressive/output/guard.rs` | `src/lib.rs`, `Cargo.toml`, `Cargo.lock`; `src/progressive/mod.rs` feature-gated crate-private helper re-exports; `src/output.rs` positional-I/O wrappers; `src/progressive/output.rs` and `output/policy.rs` common root/parent checks only |
| 2 (H2-B) | `src/partial/ledger.rs`, `verify.rs`, `tests/ledger.rs`, `tests/verify.rs` | `partial/mod.rs`, `types.rs`; no CRC/crypto algorithm change |
| 3 (H2-C) | `src/progressive/session/partial.rs`, `tests/persistent_partials.rs`, `tests/common/partial_state.rs`, `docs/persistent-partials.md` | `progressive/session.rs`, `error.rs`, `mod.rs`, `source.rs`, `source/retained.rs`, `output/native.rs`; `rar5/physical.rs` proven plain ranges; `extract.rs` fallible metadata helper/legacy wrapper; `partial/{mod,types,verify}.rs`; `.github/workflows/ci.yml` |

Test module roots may be wired through mod.rs. No ZIP/CLI, original codec, old publisher or unrelated refactor. `SourceDriver` protection hook changes wait until root-qualified final H1 BASE. The candidate seam check identifies two narrow file-scope corrections: Task 1 (H2-A) adds crate-private helper re-exports in progressive/mod.rs, and Task 3 (H2-C) touches source/retained.rs for the actual constructor allowance and shared read-path plumbing; root must include both in the source lease. Any additional production file/API/dependency or a need to duplicate parsing/crypto must be reported to root before editing. Tasks remain coherent: A supplies a working durable owner/reopen/write-fault harness, B fills/verifies it, C connects a real archive consumer; no empty scaffolding task.

## Frozen public API for this increment

All new exports below are under `zipfast::partial`, gated by `persistent-partials`. Data types are Clone/Debug where practical; errors retain typed IO errors rather than requiring Clone. Enums are non-exhaustive. Member/anchor/state fields remain private data, not capability constructors.

```rust
pub type PartialResult<T> = Result<T, PartialError>;
pub struct ArchiveBinding { pub job: [u8; 16], pub archive: [u8; 32] }
pub struct MemberKey { binding: ArchiveBinding, ordinal: u64, identity: [u8; 32] }
pub struct StateAnchor { member: MemberKey, sequence: u64, digest: [u8; 32] }
pub struct PartialState { wire: Vec<u8>, member: MemberKey, anchor: StateAnchor } // validated/cached
pub enum PartialNaming { ArchivePath, Suffix(OsString) }
pub struct PartialOptions {
    pub binding: ArchiveBinding, pub naming: PartialNaming, pub state_dir: PathBuf,
    pub limits: PartialLimits, pub anchors: Arc<dyn StateAnchorStore>,
    pub control: SessionControl,
}
pub struct PartialOpenContext {
    pub output_root: PathBuf, pub state_root: PathBuf,
    pub expected_member: MemberKey, pub expected_anchor: StateAnchor,
    pub protection: ProtectionDeclaration, pub limits: PartialLimits,
    pub progressive_limits: ProgressiveLimits,
    pub anchors: Arc<dyn StateAnchorStore>, pub control: SessionControl,
}
pub trait StateAnchorStore: Send + Sync + 'static {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>>;
    fn compare_exchange(&self, member: &MemberKey, expected: Option<&StateAnchor>,
        next: &StateAnchor) -> PartialResult<()>;
}
pub struct PackedSpan { pub volume: u32, pub range: Range<u64> }
pub enum HoleCause { Missing, DeclaredBad, CipherNeighbour, HeaderLost }
pub struct HoleReport {
    pub id: u64, pub revision: u64, pub member: MemberKey, pub name: Arc<[u8]>,
    pub out: Range<u64>, pub packed: Vec<PackedSpan>, pub cause: HoleCause,
}
pub struct MemberChecks { pub size: u64, pub crc32: Option<u32>, pub blake2sp: Option<[u8;32]> }
pub enum CheckResult { Passed, Missing, Pending, Failed }
pub struct PartCheck { pub volume: u32, pub part: u64, pub range: Range<u64>,
    pub crc32: CheckResult, pub blake2sp: CheckResult }
pub enum VerifyPath { ExtentCombine, TargetedReadback, WholeReadback, ReopenRehash }
pub enum AttributeResult { Applied, NotRequested, Failed(std::io::Error) }
pub struct MetadataResult { pub modified: AttributeResult, pub permissions: AttributeResult }
pub enum Verdict {
    Ok { revision: u64, parts: Vec<PartCheck>, path: VerifyPath, metadata: MetadataResult },
    PartBad { revision: u64, volume: u32, part: u64, which: ChecksumAlgorithm },
    Bad { revision: u64, which: ChecksumAlgorithm },
    Incomplete { revision: u64, holes: Vec<Range<u64>>, parts: Vec<PartCheck>, missing_checks: bool },
}
pub struct FillResult { pub revision: u64, pub applied: Vec<Range<u64>>,
    pub state: PartialState, pub part_checks: Vec<PartCheck>, pub needs_verification: bool }
impl MemberKey {
    pub fn new(binding: ArchiveBinding, ordinal: u64, identity: [u8;32]) -> Self;
    pub fn binding(&self) -> &ArchiveBinding;
    pub fn ordinal(&self) -> u64;
    pub fn identity(&self) -> &[u8;32];
}
impl StateAnchor {
    pub fn new(member: MemberKey, sequence: u64, digest: [u8;32]) -> Self;
    pub fn member(&self) -> &MemberKey;
    pub fn sequence(&self) -> u64;
    pub fn digest(&self) -> &[u8;32];
}
impl PartialState {
    pub fn load(state_root: &Path, anchor: &StateAnchor, limits: &PartialLimits)
        -> PartialResult<Self>;
    pub fn member(&self) -> &MemberKey;
    pub fn anchor(&self) -> &StateAnchor;
}
impl ProgressiveSession {
    pub fn new_partial(provider: Box<dyn VolumeSource>, options: ProgressiveOptions,
        partial: PartialOptions) -> ProgressiveResult<Self>;
    pub fn partial_file(&mut self, member: &MemberKey) -> PartialResult<PartialFile>;
}
impl PartialFile {
    pub fn open(state: PartialState, context: PartialOpenContext) -> PartialResult<Self>;
    pub fn fill(&mut self, out_offset: u64, bytes: &[u8]) -> PartialResult<FillResult>;
    pub fn remaining(&self) -> PartialResult<Vec<Range<u64>>>;
    pub fn state(&self) -> PartialResult<PartialState>;
    pub fn poll_verify(&mut self, cx: &mut Context<'_>) -> Poll<PartialResult<Verdict>>;
    pub fn close(self) -> PartialResult<PartialState>;
}
```

PartialState stores validated decoded member/anchor fields alongside its bounded canonical wire so getters return stable references; decoding validates they match the wire. Only PartialState gets manual serde Serialize/Deserialize. MemberKey and StateAnchor constructors create data for trusted-store lookup, not verification authority. Version one requires archive/member identity and canonical header/checksum witnesses; no runtime MemberId nonce, fd, key/password, Verdict, native guard or publication receipt is serialized. H2 emits only HoleCause::Missing; other vocabulary is reserved for approved later increments.

`Verdict::Incomplete.parts` and `Ok.parts` are current-revision snapshots, with one entry per proven part in canonical volume/part order. Missing means the archive supplied no expected checksum; Pending means a declared check is incomplete or not yet evaluated. Passed/Failed require actual checks against the returned revision. A revision change invalidates cached results: declared checks become Pending until revalidated; no previous-revision Passed may escape in an Incomplete snapshot. FillResult.part_checks contains only immediate checks from that fill; needs_verification flags deferred work. poll_verify services eligible complete-part work before returning Incomplete with the latest parts, even if another part still has holes; PartBad remains the explicit failure result. A standalone or reopened handle observes deferred BLAKE success through this return without a session or separate event drain.

Feature-gated ProgressiveEvent additions: `PartialReady { member: MemberKey, state: PartialState }`, `Hole(HoleReport)`, `PartVerified { member: MemberKey, check: PartCheck }`. Feature-gated MemberOutcome additions: `PersistentPartial { member: MemberKey, state: PartialState, expected: MemberChecks }` and `PersistentComplete { member: MemberKey, state: PartialState, verdict: Verdict }`. Existing runtime member ids remain in enclosing legacy events; persistent identity is separate. A clean persistent file never produces a fake legacy Verified/published receipt. PartVerified only mirrors completed current-revision results while the session is alive; the core verification return owns independent result delivery. No new handle queue or event API is added.

`PartialError` fields: `member: Option<MemberKey>`, `volume: Option<u32>`, `packed_offset: Option<u64>`, `output: Option<OutputRange>`, `committed: Option<StateAnchor>`, `location: Option<PartialLocation>`, `kind: PartialErrorKind`. `PartialLocation { output: PathBuf, state_bundle: PathBuf }` reports retained explicitly named files after a failed creation; it exposes no private Stage path. Non-exhaustive kinds: Progressive(Box<ProgressiveFailure>), UnsupportedPlatform, UnsupportedFormat, UnsupportedMethod, InvalidOptions, UnknownMemberSize, AlreadyExists, UnsafePath, BindingMismatch(BindingField), StateVersion, StateMalformed, StateStale { latest: StateAnchor }, StateUnavailable, JournalCorrupt, AnchorConflict, AnchorCommitUncertain, Busy, Canceled, OverlapMismatch { range: Range<u64> }, IncompleteOutput, OutputChanged, Limit { resource: PartialResource, limit: u64, attempted: u64 }, Io { operation: OutputOperation, cause: io::Error }. BindingField is Job/Archive/Member/Root/Output/Source/Anchor. Session errors use `FailureKind::Partial(Box<PartialError>)` under the feature, preserving existing progressive context. A late failure after acknowledged commit returns that anchor in committed and never rolls back valid durable state.

## Exact bounds and supported native policy

PartialLimits uses the following fields/defaults/hard ceilings; validate configuration and checked conversions before effects. Values above a hard ceiling reject with typed Limit (no silent clamp). Zero capacity is permitted but cannot admit a nonempty operation; new session requires at least one event slot. Effective work limits also obey ProgressiveLimits.

| Field/type | Default | Hard ceiling |
|---|---:|---:|
| state_wire_bytes: u32 | 65,536 | 65,536 |
| state_pages: u32 | 128 | 128 |
| ledger_bytes: u64 | 67,108,864 | 67,108,864 |
| journal_bytes: u64 | 67,108,864 | 67,108,864 |
| journal_records: u32 | 65,536 | 65,536 |
| crc_leaves: u32 | 1,048,576 | 1,048,576 |
| open_files: u32 | 64 | 4,096 |
| open_partials: u32 | 16 | 4,096 |
| events: u32 | 64 | 64 |
| fill_bytes: u32 | 1,048,576 | 1,048,576 |

PartialResource has StateWire/StatePages/LedgerBytes/JournalBytes/JournalRecords/CrcLeaves/OpenFiles/OpenPartials/Events/FillBytes corresponding to that table. A state page and journal record are each at most 1 MiB; per-poll verification/local reopen chunk is min(configured read_chunk, 1 MiB), nonzero when work remains. Retain existing hole_intervals/name/path/metadata budgets. Every output/root/parent/lock/journal/page/transient descriptor counts before opening/cloning; same shared descriptor is not counted once per Arc. Source guard descriptors retain H1's separate source ceilings. Bounded event backpressure stops further source reading; it never drops a report. Sizes and revisions use checked arithmetic; revision wrap is StateMalformed/Limit before mutation.

Ok/Incomplete part snapshots use the same bounds: count cannot exceed the proven part catalogue; checked vector allocation and copied bytes are charged to existing cumulative metadata Usage before allocation, while retained check storage counts toward LedgerBytes. FillResult part copies obey the same allocation accounting. Verification readback is charged to existing byte-work limits and the per-poll chunk cap. Exact/one-over tests cover both result variants and repeated polls; snapshots cannot evade budgets by cloning. Session mirrors remain bounded by Events and do not make standalone progress depend on a session queue.

New native operations support Linux/macOS only; other platforms return UnsupportedPlatform before effects, while legacy routes remain unchanged. Existing libc 0.2.191 exposes `flock`, `LOCK_EX`, `LOCK_NB`, and `openat` for these targets (read-only source inspection confirmed declarations; no runtime qualification was run). Use a tiny native wrapper around `flock(fd, LOCK_EX|LOCK_NB)`, not a guessed newer std API or new dependency. EWOULDBLOCK/EAGAIN becomes Busy; EINTR checks cancellation then returns typed IO for caller retry, never a blocking/spinning lock loop. Unsupported locking/filesystem semantics return typed IO/UnsupportedPlatform, not success. Close the held descriptor to release the lock.

Lock a stable, never-replaced bundle lock file and the output fd nonblockingly; compaction may replace journal/state names, never the lock inode. Acquire/revalidate both before any output mutation. Fresh create uses checked exclusive/no-follow 0600 output/state names under held roots/parents; existing target is AlreadyExists, never silently overwritten. Competing reopen changes neither output nor bundle. Same-core handles share existing descriptors/lock ownership. Advisory locks coordinate cooperative writers only.

## Durable state, callback and ownership contract

One PartialCore owns persistent fd/root/parent guards, bundle, expected checks/proven plain runs, ledger, independent control, anchor store and revision. Same-core operations reserve an operation token under a short mutex, then release it before callbacks/I/O/hook-bearing drops. Reentrant same-core mutation returns Busy. No Arc cycle or borrowed original-session nonce. Session drop/cancel releases only its ownership/control; the PartialOptions control independently governs surviving handles, unless caller deliberately shares cancellation.

Uniform mutation order is mandatory, including extraction validity/hole changes:

1. Rebind native names/fds, check current trusted anchor, precompare all known overlaps, validate bounds/geometry and reserve all work/event/ledger capacity. Persist+sync a conservative intent marking all to-be-modified ranges unknown. CAS the independent store from expected anchor to intent; no output byte write before acknowledgement.
2. Write approved ranges, reporting short-write progress; check cancellation/identity/revision, sync output. Any failed write leaves the entire intended mutation unknown, never only a blessed short prefix.
3. Persist+sync the commit and CAS intent→commit. Only acknowledged commit permits new valid state, FillResult or completion/event advertisement. Report acknowledged commits even if a later cancellation/metadata error occurs.

A newly created output has no trustworthy content. Its genesis intent precedes set_len/initialization; PartialReady follows durable full-size genesis commit and parent directory sync. A crash before Ready can leave an explicitly reported orphan/short output; ordinary open still rejects length mismatch and never repairs it by truncation. No automatic orphan deletion/adoption.

`StateAnchorStore::compare_exchange` promises durable atomic compare-and-swap in trusted caller storage. It receives exact member/previous/next anchor values computed from actual canonical bytes, not native authority. An error may mean the CAS succeeded: mark AnchorCommitUncertain and do not mutate again until an explicit caller retry calls current once. If current is expected, intent or exact commit, recover the corresponding known state; unrelated anchor is AnchorConflict/StateStale. Do not busy-spin or infer success from elapsed time. Every user callback runs outside locks; revalidate state and cancellation afterward. The documentation must tell RustyGet to retain the bundle with its queue state and to supply an independently trusted anchor, not another field from the same untrusted blob.

Binary WAL v1 uses eight-byte magic `ZFPART1\0`, u16 version 1, little-endian fixed-width integers, u32 bounded byte/collection lengths, option tags 0/1 only, and rejects trailing/unknown fields. Record kind tags are 1 GenesisIntent, 2 MutationIntent, 3 MutationCommit, 4 SnapshotTransition; page kind tags are 1 Geometry, 2 Validity, 3 HeaderWitnesses. Hash exact canonical record/page bytes including type/version/length. The envelope includes bundle/member identity, monotone sequence/transaction, previous digest, kind, bounded length, payload and CRC for torn-tail detection; SHA256 anchors exact canonical bytes. Kinds are GenesisIntent/MutationIntent/MutationCommit/SnapshotTransition. Records/deltas reference bounded immutable pages; never rewrite/spool output payload into WAL. PartialState carries manifest/head/page references and reserved optional cursor-reference version field, not extraction decoder state. Validate all lengths/counts/order/arithmetic before allocation, reject unsupported versions and duplicate/overlapping contradictory ledger records. Page filenames derive from validated digests; serialized paths cannot select arbitrary files.

Reopen compares independently supplied member/anchor with current before mutation. Older queue blob returns StateStale/latest, zero writes; `PartialState::load(state_root, latest, limits)` reads the exact anchored head for retry. Self-consistent unanchored tail never certifies bytes. Compaction creates/syncs pages and a snapshot transition, anchors it, then retires obsolete state names only after acknowledgement; keep all data necessary for the last acknowledged anchor until then. A failed/ambiguous transition retains both. Missing referenced bundle data is StateUnavailable; forged state/tail with recomputed CRC/self-hash fails the independent anchor binding.

`open` is synchronous local rebind+known-extent rehash in ≤1 MiB chunks, with cancellation between chunks and no usable handle before success. It never reads a source provider or prior archive volume. Check stamps/identity before and after work; persisted CRCs are hints, rehash actual output to rebuild known-leaf Hashers. Shorter or longer file is BindingMismatch/OutputChanged before writes. Document O(known-output) I/O. No polling-open framework, trusted hasher deserialization or resume truncation.

## Validated H1 candidate seams

All locations below are in committed qualified H1 `301c89a60f1026928f61e192f09e242ea5b6d9e7`, not a concurrent working source:

- `source/retained.rs:104`: `SourceDriver::new_retained(Box<dyn VolumeSource>, OsString, ProgressiveLimits, SessionControl) -> ProgressiveResult<Self>` is pub(crate); it enables bounded cancellation fanout and retains originals. Task 3 (H2-C) consumes it from session/partial.rs, which can access parent session validation/assembly without widening their private visibility. The constructor's allowance is in retained.rs, not source.rs; discovery/refill remain H3/H4 consumers.
- `source.rs:129–143,195–258` and `source/retained.rs:258–285`: public cancel/is_canceled plus crate-private cancellation_token exist; retained selected/read gates register internally and retire on completion. Fanout registration/owner types are private and stay so. H2 synchronous open/fill checks cancellation between bounded local chunks. poll_verify has no provider wait: when bounded local work remains, self-wake outside locks and return Pending; holes yield Ready(Incomplete), not a parked wait for fill. Thus independent handles need no legacy single-slot register call or new fanout visibility.
- `source.rs:536,557,982`: validate_current/shared_usage/refresh_protection provide revalidation and accounting; refresh_protection validates/canonicalizes Complete inventories, checks epoch consistency and admitted names, then refreshes native guards. The three planned partial hooks are new, not already present. require_partial_catalogue uses this path and accepts explicit NonFile entries; check_partial_target uses native.check_target without treating publication_check's native-only authority boolean as persistent-placement permission.
- `source.rs:682–810,825–878` and shared `poll_available` at 380: volume callbacks feed admit_source; replacement lanes also call admit_source. Install the same opt-in exclusions before replacement admission. Check current exclusions after info/backing_files callbacks and before native admission, and recheck around each source read/info callback before SourceBytes charge/cursor advance/output acceptance. RangeOperation carries the optional shared exclusion context; update both selected and retained read call sites (`source/retained.rs:471`) without changing feature-off callbacks/allocation. Existing native refresh is not itself reciprocal output/state exclusion.
- `output/native.rs:29,67,208,303` exposes crate-private Identity/NativeProtection/admit/check_target, but progressive/mod.rs declares output private. Task 1 (H2-A) adds feature-gated `pub(crate) use output::{guard, native};` there, with the new guard module crate-private, so sibling partial code uses progressive::guard/native. Usage is already crate-private and glob-re-exported from limits; no public API or broad module visibility is added. Task 3 (H2-C)'s existing source.rs/output/native.rs allowance covers the new protection hooks; retained.rs is the sole additional production-file entry for its read plumbing/allowance.

These are checked implementation placement facts at the privately qualified H1 source. They do not grant H2 source edits or imply new Linux/hosted/public qualification.

## Private task interfaces

These are the narrow seams; bodies belong to implementers. Native guard sharing must preserve legacy wrappers and charges.

- `output::range::{read_at(&File, u64, &mut [u8]) -> io::Result<usize>, write_at(&File, u64, &[u8]) -> io::Result<usize>}`: factor only existing Unix FileExt operations; OwnedStage keeps its fault hook, TempPath, discard and publication logic.
- `progressive::output::guard::{open_directory(&Path) -> ProgressiveResult<File>, check_directory(&Path, &File, Identity) -> ProgressiveResult<()>, check_parents(&Path, &Path, &Usage) -> ProgressiveResult<()>}`: shared existing validation; legacy Root/Policy delegate without policy change. New persistent owner holds its own guards.
- `partial::native::PersistentNative::{create(&CreateSpec, &PartialBudget) -> PartialResult<Self>, reopen(&ReopenSpec, &PartialBudget) -> PartialResult<Self>, check(&self, expected_len: u64) -> PartialResult<()>, sync(&self) -> PartialResult<()>}`. CreateSpec/ReopenSpec are validated root-relative member/output/bundle identities, expected length and protection facts; no unchecked paths from wire. Native owner uses common range I/O; Drop closes fds only.
- `partial::journal::Bundle::{create(&CreateSpec, &PartialBudget) -> PartialResult<Self>, open(&ReopenSpec, &StateAnchor, &PartialBudget) -> PartialResult<Self>, append_intent(&MutationIntent) -> PartialResult<StateAnchor>, append_commit(&MutationCommit) -> PartialResult<StateAnchor>, prepare_compaction(&mut self, &CommittedState) -> PartialResult<PreparedCompaction>, complete_compaction(&mut self, PreparedCompaction, &AnchorAck) -> PartialResult<()>}`. append methods sync their record before returning candidate anchor; they do not CAS or advertise it.
- `partial::anchor::AnchorBinding::{current(&self) -> PartialResult<Option<StateAnchor>>, advance(&self, expected: Option<&StateAnchor>, next: &StateAnchor) -> PartialResult<AnchorAck>, confirm_current(&self, expected: &StateAnchor) -> PartialResult<AnchorAck>}` wraps caller store with member binding; operation-token/revision/uncertainty checks are owned by PartialCore outside callback locks.
- `partial::ledger::Ledger::{plan_fill(&self, out: Range<u64>) -> PartialResult<FillPlan>, commit_fill(&mut self, &FillPlan, &[KnownLeaf]) -> PartialResult<()>, remaining(&self) -> PartialResult<Vec<Range<u64>>>}`. FillPlan splits hole/known overlap and provenance; precomparison and write bytes stay in core. KnownLeaf owns exact range/actual Hasher and provenance Original/Alt; durable records store digest/length hints only.
- `PartialCore::{create(spec: CreateSpec, checks: MemberChecks, options: CoreOptions) -> PartialResult<Arc<Self>>, write_original(&self, offset: u64, bytes: &[u8]) -> PartialResult<()>, record_hole(&self, report: HoleReport) -> PartialResult<()>, fill_plain(&self, offset: u64, bytes: &[u8]) -> PartialResult<FillResult>, extend_evidence(&self, update: EvidenceUpdate) -> PartialResult<()>}`. CreateSpec and CoreOptions carry stable key/native spec, limits/shared Usage, anchors/independent control and event capacity. write_original/record_hole use the same anchored mutation engine as fill; no alternate direct-write route.
- `PartialFile::from_core(Arc<PartialCore>) -> Self` is crate-private and consumes the existing durable owner for Task 3 handle construction; it creates no new authority, descriptor or allocation. The core field stays private.
- Task 3 (H2-C) SourceDriver hooks: `require_partial_catalogue(&mut self) -> ProgressiveResult<()>`, `check_partial_target(&mut self, path: &Path, identity: Option<Identity>) -> ProgressiveResult<()>`, `install_partial_exclusions(&mut self, exclusions: Arc<PartialExclusions>) -> ProgressiveResult<()>`. PartialExclusions is one concrete shared bounded exclusion list for this persistent session, not a source registry or callback trait. Its entries are `PartialProtectedPath { path: PathBuf, identity: Option<Identity>, root: PathBuf, root_identity: Identity, parent: PathBuf, parent_identity: Identity, directory: bool }`; directory entries exclude the state-bundle subtree. Cores reserve output/bundle/page names before creation and bind actual identities before data writes. Validate/recheck using existing NativeProtection; check later original/replacement admissions and recheck after source callbacks against a current exclusion revision before accepting source bytes. Snapshot/update its small list under a mutex, then release it before path I/O/source callbacks; do not hold a source-driver borrow during independent fills. CoreOptions shares the same Arc so a fill on A can protect new state pages while the session extracts B. Bound paths/identities by existing protection-path/metadata limits and prune obsolete state entries only after acknowledged compaction has removed the corresponding state files; persistent output exclusions last for the session. Feature-off/legacy mode allocates/calls nothing extra. Candidate placement is pinned below; revalidate affected seams only if the final qualified BASE differs.
- `extract::finish_file_checked(&File, &Meta) -> FileMetadataResult`; `FileMetadataResult { modified: Option<io::Result<()>>, permissions: Option<io::Result<()>> }`. Existing finish_file delegates and discards results as before. Preserve archive_time conversion, Unix mode mask 0o777 and zero mode semantics. Partial code converts each attribute independently to public MetadataResult, applies only on verified current revision, and updates its own post-metadata stamp without claiming a publication receipt.

Task 3 prepares missing output roots, state roots and archive-path parent directories before Core::create, using rooted/no-follow/held-parent checks, bounded charging, Complete-catalogue exclusions before mkdir, and revalidation after callbacks. Complete is not legacy publication authority: do not blindly call Policy::prepare_parents, whose publication_check has different authority. Task 1 requires existing validated roots/parents and exclusively creates only the bundle, lock and output.

InitialEvidence contains only actual metadata, proven current parts, admitted original snapshots and canonical header witnesses. Task 1 fixtures use the existing canonical parser; empty or synthetic witnesses are not a substitute. EvidenceUpdate adds these bounded facts and optional member-check enrichment through the same two-CAS engine, rejecting contradictory changes. Future expected catalogue facts remain separate from admitted snapshots. CoreOptions.read_chunk is supplied from validated ProgressiveLimits and local byte work uses min(read_chunk, 1 MiB); zero rejects required work with InvalidOptions.

Compaction preparation persists the next snapshot while retaining the prior acknowledged bundle. Core performs caller-store CAS outside locks, obtains an unforgeable private AnchorAck bound to the exact anchor, and only then completes retirement. An ambiguous CAS retains both versions until explicit trusted-current confirmation; retirement failures retain the acknowledged state in the error receipt. The public StateAnchorStore signature is unchanged.

PartialErrorKind::Progressive preserves existing work-budget failures, their original Resource, limit, attempted value and context; Error::source exposes the nested failure. PartialErrorKind::Limit remains specific to the ten partial resources, with no misleading mappings of MetadataBytes, VerifyBytes or OutputWriteBytes. Tests assert these typed failures and unchanged output when admission fails.

Private record layouts are fixed to these inputs; all variable collections use the listed caps and canonical codec, never unconstrained serde derive:

```rust
struct CreateSpec {
    member: MemberKey, name: Arc<[u8]>, output_root: PathBuf, state_root: PathBuf,
    relative_output: PathBuf, size: u64, protection: ProtectionDeclaration, evidence: InitialEvidence,
}
struct InitialEvidence {
    metadata: crate::extract::Meta, parts: Vec<PlainPart>,
    admissions: Vec<SourceAdmission>, headers: Vec<HeaderWitness>,
}
struct SourceAdmission { volume: u32, info: SourceInfo, expected: OsString }
struct HeaderWitness { volume: u32, packed: Range<u64>, bytes: Vec<u8> }
struct ReopenSpec { state: PartialState, context: PartialOpenContext }
struct CoreOptions {
    limits: PartialLimits, usage: Usage, read_chunk: u64, anchors: Arc<dyn StateAnchorStore>,
    control: SessionControl, exclusions: Arc<PartialExclusions>,
}
struct PartialBudget { limits: PartialLimits, usage: Usage /* private bounded counters */ }
struct PageRef { kind: PageKind, digest: [u8;32], len: u32 }
enum PageKind { Geometry, Validity, HeaderWitnesses }
struct NativeBinding {
    root: Identity, parent: Identity, output: Identity, bundle: Identity,
}
struct CommittedState {
    member: MemberKey, sequence: u64, revision: u64, relative_output: PathBuf,
    size: u64, produced: u64, member_finished: bool, checks: MemberChecks,
    binding: NativeBinding, pages: Vec<PageRef>, metadata: crate::extract::Meta,
    cursor: Option<CursorRef>,
}
struct CursorRef { version: u16, digest: [u8;32] } // H2 requires None; reserved for R1
struct MutationIntent {
    transaction: u64, parent: Option<StateAnchor>, conservative: CommittedState,
    affected: Vec<Range<u64>>,
}
struct MutationCommit {
    transaction: u64, parent: StateAnchor, valid: CommittedState,
}
```

Geometry pages contain bounded `PlainPart { ordinal: u64, packed: PackedSpan, out: Range<u64>, final_part: bool, crc32: Option<u32>, blake2sp: Option<[u8;32]> }` plus source admission facts `(volume, SourceInfo, expected name)`; HeaderWitnesses pages hold bounded canonical header byte spans `(volume, packed range, bytes)`, split across page boundaries if needed. Validity pages contain bounded sorted ranges with Original/Alt/Unknown provenance and optional `(crc,len)` hint plus HoleReports. Raw source bytes are never payload-spooled. Manifest/page transitions rewrite only changed bounded metadata pages, not unchanged pages or output payload. Native identities serialize as fixed dev/inode integers checked on reopen, not native capability objects. Member digest uses a version-tagged canonical first-header identity/name/checksum descriptor under the caller archive binding; do not hash mutable availability or a process nonce.

PartialBudget tracks live OpenFiles/OpenPartials/Events/StatePages/LedgerBytes/JournalBytes/JournalRecords/CrcLeaves and per-object StateWire/per-call FillBytes; existing Usage retains cumulative metadata/read/write work. Reserve live capacity before effect and release it only when the owned resource actually closes/retires, including transient fds and error exits. Do not create an extensible quota/storage adapter framework. PartialExclusions provides `reserve(&self, path: &PartialProtectedPath) -> PartialResult<()>`, `bind(&self, path: &Path, file: &File) -> PartialResult<()>`, and `check_input(&self, paths: &[PathBuf], files: &[File]) -> ProgressiveResult<()>`; allocation and revision checks use the shared Usage/protection limits. It owns binding facts, not additional source/provider/decoder owners. Checked paths/counters and per-member Busy reservation are the only runtime authorities; never accept a caller-created private test record on a public path.

## Task 1: H2-A — Persistent owner, anchored state and synchronous reopen

**Files:** Task 1 (H2-A) row above. **Consumes:** qualified native/path/source semantics, accepted public types/caps and anchor protocol. **Produces:** functioning internal PartialCore creation/anchored original-write/hole/reopen, native exclusion, manual state serde and fault harness. Task 1 (H2-A) encodes append-only 64 KiB known/unknown extent records and rehashes them on reopen; Task 2 (H2-B) extends that same codec/state with arbitrary splitting/combination, not a second ledger format. The archive consumer is Task 3 (H2-C), but A tests actual files/anchors, not empty stubs.

- [ ] Validate final reviewed H1 BASE and required interface signatures with root before source; record exact SHA in task evidence. Confirm private Rust 1.100.0/cache/target/disk lease. No full baseline rebuild.
- [ ] Under a separate dependency grant, inspect owned cached serde manifest/index/license and exact transitive closure. Proposed dependency is optional `serde = { version = "=1.0.229", default-features = false, features = ["std"], optional = true }`, feature `persistent-partials = ["dep:serde"]`, no default feature change. If offline qualification fails, report the exact missing/incompatible item; do not fetch/downgrade silently. First offline manifest resolution (`cargo metadata --offline --format-version 1 --features persistent-partials`) may update the lock only for the required closure; reject unrelated locked-package changes. Rust 1.100 build qualification occurs in the task RED/GREEN cycle, not an extra full baseline build; a dependency/compiler failure is not a valid RED. All subsequent commands use --locked.
- [ ] Add RED tests `create_is_exclusive_full_size_and_drop_preserves`, `bundle_and_output_locks_are_nonblocking`, `anchored_intent_precedes_every_write`, `ambiguous_cas_requires_explicit_current_retry`, `crash_recovers_last_acknowledged_state`, `stale_or_forged_state_cannot_write`, `compaction_keeps_last_acknowledged_bundle`, `open_rehash_is_bounded_and_cancelable`, `state_serde_bytes_and_sequence_are_bounded`. Assertions: existing bytes/names unchanged; two independent opens get Busy; intent CAS failure gives zero writes; partial write leaves entire intent range unknown; wrong/old anchor rejects; shorter/longer output rejects without resizing; output mutation defeats cached CRC; no provider called during open. Actual subprocess kill at intent-sync/CAS/write/output-sync/commit-sync/CAS boundaries must reopen exact expected holes/bytes.
- [ ] Run `cargo test --offline --locked --jobs 3 --features persistent-partials --lib partial::tests::` and record expected RED from missing behavior/API, not environment errors. Tests call real public serde traits: first-party bytes serializer plus serde value bytes/sequence deserializers, then load/open the roundtripped state. Oversized sequence with misleading/absent size_hint rejects by the cap before unbounded allocation; no serde_json/bincode runtime dependency.
- [ ] Implement only Task 1 (H2-A) interfaces/modules and narrow common native helpers. Include exact/one-over metadata/FD/journal/page/record caps, no-follow/parent swap/hardlink alias cases, genesis-before-Ready state, nonblocking native locks and two-CAS engine. User callback cancellation/reentrancy must run outside locks; reserve capacity before intent/CAS. No mutation retry loop after ambiguous CAS; committed error receipts preserve acknowledged state.
- [ ] Run Task 1 (H2-A) tests plus `cargo test --offline --locked --jobs 3 --lib progressive::output::tests::` and the existing progressive output integration test. Expected all pass. Existing default OwnedStage cleanup/publication/fault behavior is unchanged. Use bounded subprocess watchdogs for reentrant callback/lock deadlock cases.
- [ ] Run fmt check, inspect only Task 1 (H2-A) allowlisted changes, then commit under root's source/integration grant with message `feat: add anchored persistent partial storage`. Deliver focused evidence/review; no push/PR/release or large native campaign.

## Task 2: H2-B — Plain fills, CRC ledger and actual part/member verification

**Files:** Task 2 (H2-B) row. **Consumes:** Task 1 (H2-A) owner/state/anchor engine. **Produces:** public plain fill/remaining/state/poll_verify semantics and persistent leaf/part checks; no source/parser change.

- [ ] Add RED tests `fill_compares_every_overlap_before_mutation`, `crc_leaf_split_rehashes_fragments`, `part_checks_use_nonfinal_packed_scope`, `missing_hash_is_not_ok`, `blake_verification_uses_readback`, `reopen_never_trusts_serialized_crc`, `changed_revision_invalidates_verify`, `fill_faults_keep_entire_intent_unknown`, `standalone_incomplete_exposes_deferred_part_success`, `reopened_incomplete_exposes_deferred_part_success`, `part_snapshots_are_revision_bound_and_bounded`. Use 65,537-byte data to cross a 65,536-byte leaf and a part boundary at byte 17; nonfinal part CRC and final member CRC have different expected scopes. One wrong filled byte in the nonfinal part yields correct volume+part PartBad; wrong final-region byte yields member Bad. Matching overlap is accepted; mismatch in a later overlap yields zero output writes despite an earlier hole in the same input.
- [ ] In the standalone/reopen RED cases, use a split member with one complete BLAKE-checked part and another hole; release the creating owner, and repeat after closing/reopening from anchored state. Drive poll_verify to Ready(Incomplete), assert correct volume/part/range and BLAKE Passed for the complete part, and Pending for a declared check on the holed part versus Missing for an absent check. Fill the remainder and reach Ok. Change revision during deferred work and assert no old Passed is returned without current-revision revalidation. Assert exact/one-over snapshot allocations, repeat-poll accounting and readback work charges. Task 3 (H2-C) repeats this contract after dropping an actual ProgressiveSession.
- [ ] Run the feature partial test filter and confirm RED. Add exact/one-over fill/leaf/interval/work budgets, out-of-order/subhole fills, empty valid-offset no-op, unproduced/beyond-size rejection and two independent member cores.
- [ ] Implement Ledger/verification using actual in-memory Hasher objects on 64 KiB leaves split at part boundaries. Rehash affected fragments when editing/splitting; combine complete known leaves only. Plain nonfinal part checks hash their real packed/output span; final checks cover whole member. Persist provenance Original/Alt independently from pass/fail. Reopen rehashes known extents; BLAKE2sp requires real bounded readback. Size-only/unknown final checks returns Incomplete, never Ok.
- [ ] Complete cheap CRC part checks at fill commit and return them in FillResult; schedule BLAKE part readback with needs_verification=true. poll_verify processes pending complete parts even while the whole member is incomplete, then returns current-revision parts in Incomplete (or explicit PartBad on failure). A live session may mirror completion as PartVerified; standalone/reopened handles need no event queue. A stable revision/stamp guards every poll and invalidates old cached part results before snapshot delivery. Metadata remains NotRequested until Task 3 (H2-C) supplies the fallible helper; no early attribute changes. Ordinary fill cannot overwrite original or Alt mismatches and never clears a legacy sticky failure.
- [ ] Run Tasks 1+2 (H2-A/H2-B) tests and `cargo test --offline --locked --jobs 3 --lib progressive::session::recovery::tests::`. Assert combine/readback work counters match the advertised path and bad borrowed revision remains diagnosable. Do not add duplicate CRC implementation or unchecked hasher-deserialization constructor.
- [ ] Run fmt check, inspect Task 2 (H2-B) scope, commit `feat: fill and verify persistent stored extents` under root grant and obtain focused review before C.

## Task 3: H2-C — Real plain RAR5 session, independent handles, metadata and CI

**Files:** Task 3 (H2-C) row. **Consumes:** reviewed H1 retained driver/cancellation and Tasks 1/2 (H2-A/H2-B) durable core. **Produces:** actual feature-gated new_partial/session event consumer, reciprocal source protection, per-attribute metadata and public adoption example.

- [ ] Add RED public tests `plain_stored_reports_holes_before_finish`, `waits_are_not_damage`, `fill_survives_session_drop_and_other_member_progress`, `complete_catalogue_and_future_source_aliases`, `persistent_clean_member_has_no_publication_receipt`, `metadata_is_per_attribute_and_after_verification`, `deferred_part_success_survives_session_drop_and_reopen`. Small first-party split archive: two members, 700-byte simulated articles, 10% deterministic holes, ten small volumes; compare exact output+packed ranges, full bytes/checks after fill, and Wait/NotYet wake counts. Cross-volume holes split exactly; no geometry is guessed for missing headers/volumes. Default path retains original event/API behavior. The deferred-part test repeats Task 2 (H2-B) through the actual session: drop it before BLAKE readback while another part has holes, observe Passed in the surviving handle's Incomplete.parts, then repeat after reopen and finish to Ok; a live PartVerified event is only a mirror.
- [ ] Run `cargo test --offline --locked --jobs 3 --features persistent-partials --test persistent_partials` and record RED. Include typed refusal for RAR4/AES/compression/unknown size/redirections/invalid options on this API before effects when known. These are H2 scope boundaries, not waivers of H3/H4 requirements.
- [ ] Wire feature-gated persistent sink through existing session start/Stage/Part/finish phases and canonical PhysicalModel/MemberMachine. Bind exact plain part runs; map source hole before advancing output. Emit PartialReady only after genesis durability, Hole before later reads/finish and completion with persistent Verdict. Never fall back to a temporary Artifact or a second parser. Root a shared core per member; caller handles outlive session. Extracting B and filling/verifying A are independent; same-core operations Busy. H1 cancellation fanout remains intact and SourceBytes keeps accepted-byte semantics.
- [ ] Implement Complete catalogue validation/provisional target checks and reciprocal output/state exclusions before later original/replacement source admissions. Existing Complete does not grant legacy publication authority; source NativeProtection/default behavior remains unchanged. Check names/actual identities and recheck path binding after caller callbacks, before data reads/writes. Output/state files cannot be archive inputs, including future-volume aliases and callback-time swaps. Exact cap/one-over transient fd tests are required.
- [ ] Factor finish_file_checked and preserve finish_file's old swallowing wrapper. Report modified/permissions independently; only actually parsed mtime/nanos and Unix mode are applied. Apply on current verified revision under the operation token and record/recheck the resulting stamp. A permission failure cannot imply mtime failed or corrupt checksum verdict, and cannot create a legacy publication receipt. Already-acknowledged state survives any late error.
- [ ] Add adoption docs and compile example: Complete provider, independent PartialOptions control, durable trusted anchor store, named output/state bundle retention, early handle/fill, explicit caller retry for uncertainty, stale anchor→load latest→open, O(known-output) rehash, supported scope and ordinary no-truncate contract. It must run against the real public API/serde roundtrip, not pseudo-code calling nonexistent fields.
- [ ] Extend `.github/workflows/ci.yml` with feature-enabled Linux/macOS clippy/all-targets/doc commands alongside unchanged default jobs; same Rust 1.100.0. New commands: `cargo clippy --workspace --all-targets --locked --features persistent-partials -- -D warnings`, `cargo test --workspace --all-targets --locked --features persistent-partials`, `cargo test --workspace --doc --locked --features persistent-partials`. No runtime serde_json/bincode or install step. Local equivalents use --offline --jobs 3. Remove new_retained dead_code allowance only on this real consumer; explicitly reassign unused discovery/refill allowances to H3/H4, never fake-call them.
- [ ] Run all feature partial/public tests and existing `progressive_holes`, `progressive_output`, `progressive_rar`, `progressive_rar4`, `progressive_rar4_compressed` integration tests. Check feature-off API compilation and unchanged Artifact recovery/publication. Then fmt/scope review and commit `feat: expose persistent plain RAR5 stored extraction` under root grant. No publication claim until final review/CI gates.

## Final verification, future scope and self-review

Root provides private CARGO_HOME/CARGO_TARGET_DIR, exact Rust 1.100.0 bin PATH and a bounded target-disk lease. Initial dependency resolution is the one explicit exception to --locked after a grant; no network/global-cache fallback. Missing dependencies/native support are reported to root. No duplicate full baseline build. After task reviews, final private Mac checks once (repeat only for relevant failures/fixes):

```sh
cargo fmt --all -- --check
cargo clippy --offline --workspace --all-targets --locked --jobs 3 -- -D warnings
cargo clippy --offline --workspace --all-targets --locked --jobs 3 --features persistent-partials -- -D warnings
cargo test --offline --workspace --all-targets --locked --jobs 3
cargo test --offline --workspace --all-targets --locked --jobs 3 --features persistent-partials
cargo test --offline --workspace --doc --locked --jobs 3
cargo test --offline --workspace --doc --locked --jobs 3 --features persistent-partials
```

Never add --ignored/--include-ignored. Root grants any focused Linux native window and later exact-head hosted review/CI/release checks. Preserve old proof/worktrees. No speed claim: two durable CAS writes per mutation and synchronous reopen rehash are accepted initial costs.

| Full request | H2 coverage / next owner |
|---|---|
| Hole §§1–4/9, acceptance 1/4/6/8 | Real plain wait/hole events, named output, fills/part checks/crash reopen; exact 500 MB/ten volumes/700 KB/10% remains a later granted acceptance window. Small real tests do not waive it. |
| Late declaration, lost header/whole volume, damaged compressed+clean successor; acceptance 2/3/5/7 | H3/H4; H2 refuses unknown geometry without guessing. |
| AES/RAR4, raw packed refill, 1 MiB PAR overlap and wrong-Alt correction; acceptance 9 | H4; H2 retains Alt provenance and durable handle only. |
| Entry.mode and SelectedEntry volume notices | H5, not this metadata-helper change. |
| Resume | Versioned cursor reference/anchor durability reserved; R1 still implements exact cursor restore, acknowledged barrier and no-earlier-payload proof. |
| Original eight / 7z | All remain required; actual 7z reader precedes Copy/AES hole/resume adapters. |

- [x] Coverage: A/B/C provide a real useful H2 consumer; all deferred acceptance/extras/resume cases are explicitly retained.
- [x] Step precision: each task has named RED assertions, exact interfaces/scope, bounded GREEN commands and a reviewable commit; no setup-only task or implementation method bodies.
- [x] Type consistency: stable member/anchor data is separate from runtime ids/authority; PartialState caches validated fields for getters; per-attribute metadata does not require cloneable IO errors; late errors carry committed anchors.
- [x] Review Focus: ambiguity/compaction/alias/CRC/callback-lifetime conditions each map to task tests.
- [x] Proportion: limited native helpers and session sink route; no new publisher/decoder/framework. Current source leases remain untouched.

H1 final private source/review/Mac qualification and affected-seam validation are complete at301. Outstanding gates are the docs-only implementation BASE recorded by root, private serde closure qualification and a finite source lease including the two recorded file-scope corrections. The same H2 builder has closed the standalone-result correction. Root has already settled the architecture decisions; none requires a user permission menu. Do not start source/dependency/native work until root grants the corresponding finite task.
