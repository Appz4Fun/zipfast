# Persistent Stored holes and durable partial output

Status: accepted architecture; implementation is staged. Baseline: `0030c75a86f5ab7c1cf89a8dea91d55bdc435e86` (qualified C1), tree `50ae252749b3ebae8cdd7cef963cc6d1f54e7617`. This document specifies intended behavior, not features already available.

Requirements: `zipfast-hole-skip-request.md` (SHA256 `a9a431336a8e0b089fe321a15878f97ec423244854c40e54a7acf83bbaafb0f6`), `zipfast-resume-request.md` (SHA256 `ff3e0bf934f921a4afe3a4ca57bf36ea59e08b73d0b9ef2a8559bb25505f33ae`), and the original eight-part RustyGet extraction/mapping request. The summaries and acceptance table below are self-contained; consumers need no private filesystem paths.

RustyGet needs Stored extraction to pass caller-declared damaged archive ranges, preserve correctly positioned sparse output, report exact gaps immediately when geometry is known, and accept borrowed plaintext or repaired archive bytes later—even after process restart. Subsequent cursor resume must append from a safe checkpoint without replaying prior volume payloads. Persistent hole filling is delivered first, with a compatible durable-state boundary for that later feature.

Anti-goals: no invented headers/offsets/IVs/checksums or compression restart points; no source mutation concealed within an immutable generation; no fabricated verification/publication authority; no silent loss of accepted durable fills; no alternate decoder/parser; no change to legacy defaults.

## 1. Decision and scope

Use an **opt-in `partial::PartialFile` ownership policy with a shared private output/source/physical-model core**, rather than teaching the existing `Artifact` capability to survive arbitrary restart. Existing `ProgressiveSession` remains the parser/decoder driver. Its ordinary options, `Artifact` lifecycle, source immutability and strict publication behavior stay intact.

| Viable approach | Reuse | Cost and limitation |
|---|---|---|
| Extend `Artifact`, with a persistent facade | Existing `Stage`, recovery record, guards and publisher; smallest apparent public surface | Today mutation needs session nonce, weak authority, original `SourceDriver`, and no publication receipt; verification prohibits active extraction. Making persistence a flag on this capability introduces a second meaning for almost every invariant. Feasible only after the same ownership split described below, with more risk of changing old defaults. |
| Opt-in `PartialFile`, shared internals (chosen) | Same canonical `HeaderParser`, `PhysicalModel`, `MemberMachine`, checksum rules, native identity/alias checks, quotas and checked publisher for legacy paths | Adds explicit durable named-output policy and durable identities. Requires deliberate core refactoring, not copying decoder/parser or exporting private stage paths. Clear lifetime and crash contract; independent filling is a member operation, not a session-global verification job. |

Hole-skip includes reopening and filling completed partial output after restart. It does **not** restore an extraction cursor. The subsequent resume branch adds that cursor to the same durable envelope. Do not announce resume implemented merely because `PartialFile::open` works.

RAR5 Stored first, then RAR5 encrypted headers/data, then RAR4 Stored; required source foundations and independent compressed failure continuation belong in this request. 7z Copy/AES integration remains required when the actual reader exists. Do not introduce a placeholder 7z success path. Original requests 1–8, old RAR 1.5/2, PPM/VM, C2/C3/C4, maps/probe/seek, and full compatibility remain queued, not replaced or waived.

## 2. Existing implementation at the qualified baseline

Line references refer to qualified commit `0030c75a86f5ab7c1cf89a8dea91d55bdc435e86`, tree `50ae252749b3ebae8cdd7cef963cc6d1f54e7617`. The tree is unchanged from the source inspected during architecture preparation.

| Existing seam | Verified contract and required change |
|---|---|
| `progressive/source.rs:37–94` | `SourceInfo { id: SourceId(u128), generation, extent, length: Advertised/Final(u64) }`. `VolumeSource::volume(&mut self, &VolumeRequest, &mut Context) -> ProgressiveResult<VolumeAnswer>`; `Ready(Box<dyn RangeSource>)/Wait/Missing/Abort`. `RangeSource: Send + Any + 'static` has `info`, `read_at(..., cx) -> ProgressiveResult<RangeRead>`, `backing_files`. `Filled { count }`, `NotYet`, `Hole { len }` differ from illustrative request signatures. Keep zero-based volume indices and wake-controlled retry. |
| `SourceDriver` at `source.rs:231`; `select_volume:376`, `supply_replacement:563`, `poll_replacement:635` | Owns only current original source; prior admission records retain identity but `select_volume` drops the object. Replacement lanes are separate explicit generations, not retained originals. Duplicate source IDs are rejected. Extend ownership into retained lanes without calling `VolumeSource` twice for an admitted original and without disabling duplicate-ID checks. |
| `progressive/session.rs:45–193` | `ProgressiveEvent` already has volume/start/bytes/finish/termination; no immediate hole event. `MemberOutcome::Partial(Artifact)` and `Stopped { inner_offset, restart, failure, artifact }` exist; no requested `Unrecoverable`. `MemberId` is opaque session `NonZeroU64` + ordinal (`error.rs:22`), not a durable cross-process ID. |
| `ProgressiveSession::new`, `control`, `poll_event` (`session.rs:210,299,302`) | Serialized caller-driven session. `Phase::Header` treats `SourceStep::Hole` as terminal `HeaderHole`; `Missing` is terminal in the driver. `Phase::Part` and `StageSink` feed the canonical member engine. Add opt-in damage, geometry/discovery and persistent-output routes here, not a second extraction loop. |
| `rar5/framing.rs:64–193` | `PhysicalFrame { block, crypt, wire, extent, data_end, header_crypt }`; `HeaderParser::advance`, `set_format`, encryption setters; `ParserStep::Need/LegacyKeyRequired/Frame/End`. Exact offset framing exists, but safe export/restore and lost-header anchors do not. No payload scanning for plausible reset headers. |
| `rar5/physical.rs:23–143` | `PhysicalPart { volume, data_offset, packed_size, checks, crypt, legacy, final_part, wire_extent, raw_flags, raw_compression, plain_extent }`; `plain_extent` currently starts `None`. `PhysicalMember` owns part range/size/final checks/continuation identity. Extend this canonical model with proven mapping and unknown gaps. `continuation_issue` is shared with catalogue. |
| `rar5/member.rs:25–213,331–448,496–566` | `PendingCipher` owns CBC IV/remainder, padding and availability; physical part boundary does not reset CBC. `MemberMachine::feed_stored(data: Option<&[u8]>, len, &mut dyn RecoverySink)` handles holes. `RecoverySink::hole(len)` lacks cause/packed coordinates. Extend internal delivery with positioned damage metadata, preserving one cipher implementation. |
| `MemberMachine::finish_part_core`, `verify_packed`, `InnerChecks::verify` | Nonfinal parts verify **packed** bytes if present; final part carries whole-inner checks. RAR5 keyed checks are tweaked after computing raw digest. No assumption that every volume has a CRC, nor that an encrypted part CRC hashes plaintext. |
| `progressive/output.rs:393–485,729–780` | `Stage` owns `OwnedStage`, `Arc<Root>`, weak authority, generation, holes, extent/validity and `Assessment`. `write_at` is append-only at `produced`; `set_len` grows only. `Artifact` owns stage+recovery record, can outlive session for reading/discard; no independent restartable mutation authority. |
| `progressive/recovery.rs:50–115,141–331` | Recovery record retains physical model, target, key, header witnesses and part evidence. `patch(&mut self, &mut Artifact, offset, &[u8])` requires original session, one wholly invalid interval, nonempty ≤1 MiB and valid size. `poll_verify(&mut self, &mut Artifact, cx)` scans stage and rejects active extraction. Sticky failed assessment and `supply_verification_source` are intentional old contracts; neither is a general PAR repair API. |
| `src/output.rs:512–596`, progressive native/policy modules | `OwnedStage` encapsulates temp-name deletion/publication. Extract shared descriptor/identity/range-I/O primitives, never recover its private path and reopen it as a persistent output. Legacy publisher keeps its checked target and protection authority. |
| `extract.rs:282,854,867,1473,1885` | `Entry` lacks `mode`; `SelectedEntry::unix_mode()` uses `Meta.mode`. `SelectedEntry::read(self, password, sink)` consumes self, has no notice/current-volume API; RAR uses `RarSelection` and `rar_read_at`/`walk_until`. PR95 controlled selected extraction does not supply this requested read notice. |
| `Cargo.toml`, `Cargo.lock`, `crc32.rs` | Rust 1.100. Root has no serde dependency and lock contains no serde/derive/json/bincode/postcard package. CRC has `Hasher::combine`; there is no durable extent-CRC ledger. Existing crypto has SHA256 and AES block encryption, so no new crypto dependency is needed merely for state digest or CBC reconstruction. |

## 3. Proposed public surface (new, not existing API)

Use additive non-exhaustive enums/new methods. Do not rename existing `Partial(Artifact)` or reinterpret its receipt. The signatures below define the intended consumer surface; H2 must pin complete public data definitions and limits before its source lease. H1 introduces none of this public surface.

```rust
// Durable identity is data, never a restored MemberId capability.
pub struct MemberKey { /* private archive_set_id, stable ordinal, identity digest */ }
pub struct PackedSpan { pub volume: u32, pub range: Range<u64> }
pub enum HoleCause { Missing, DeclaredBad, CipherNeighbour, HeaderLost }
pub struct HoleReport {
    pub id: HoleId, pub revision: u64, pub member: MemberKey,
    pub name: Arc<[u8]>, pub out: Range<u64>,
    pub packed: Vec<PackedSpan>, pub cause: HoleCause,
}
pub enum GeometryReason { LostHeader, MissingPartSizes, MissingCipherParameters, AmbiguousMembers }
pub struct UnmappedDamage { /* damage id, known packed spans, optional member, GeometryReason */ }

impl ProgressiveSession {
    pub fn new_partial(provider: Box<dyn VolumeSource>, options: ProgressiveOptions,
                       persistent: PartialOptions) -> ProgressiveResult<Self>;
    pub fn declare_hole(&mut self, volume: u32, range: Range<u64>)
        -> ProgressiveResult<DamageReceipt>;
    pub fn partial_file(&mut self, member: &MemberKey) -> ProgressiveResult<PartialFile>;
}
// New ProgressiveEvent variants: PartialReady, Hole(HoleReport),
// GeometryPending(UnmappedDamage), HoleResolved, PartVerified, VerificationInvalidated.
// New outcome: PersistentPartial { member, state, expected, holes },
// and Unrecoverable { stopped_at_out, restart: RestartAvailability, failure }.

impl PartialFile {
    pub fn open(state: PartialState, context: PartialOpenContext) -> PartialResult<Self>;
    pub fn fill(&mut self, out_offset: u64, plain: &[u8]) -> PartialResult<FillResult>;
    pub fn fill_packed(&mut self, volume: u32, offset: u64, bytes: &[u8])
        -> PartialResult<FillResult>; // twin provenance, match-or-error
    pub fn fill_packed_repair(&mut self, volume: u32, offset: u64,
                              bytes: &[u8], repair: &CheckedRepair) -> PartialResult<FillResult>;
    pub fn attach_source(&mut self, volume: u32, source: Box<dyn RangeSource>,
                         binding: RefillBinding) -> PartialResult<()>;
    pub fn poll_refill_from_packed(&mut self, volume: u32, range: Range<u64>,
                                  cx: &mut Context<'_>) -> Poll<PartialResult<FillResult>>;
    pub fn remaining(&self) -> Vec<Range<u64>>;
    pub fn poll_verify(&mut self, cx: &mut Context<'_>) -> Poll<PartialResult<Verdict>>;
    pub fn state(&self) -> PartialState; // latest committed durable state, not an in-flight snapshot
    pub fn close(self) -> PartialResult<PartialState>; // sync; leaves named output intact
}
```

`PartialOpenContext` carries explicit output root, expected job/archive binding, optional password, caller-admitted sources, quotas, cancellation and state-store location. A bare `open(state)` is insufficient to establish filesystem authority, secrets and sources safely; the request examples are illustrative. Bytes-only fills are synchronous bounded operations; provider reads and large verification are pollable to preserve `NotYet`, cancellation and bounded work. Optional convenience `verify` can only be a documented executor wrapper, never a busy-poll loop.

`Verdict` needs `Ok { checks, path }`, `PartBad { volume, part, which }`, `Bad { which }`, **and** `Incomplete { holes, missing_evidence }`; absent hash is not a pass. `path` identifies `ExtentCombine`, `TargetedReadback`, `WholeReadback`, `PackedReconstruction` and restart prefix rehash where used. `FillResult` reports actual committed ranges, still-needed ciphertext, corrected donor mismatch ranges and immediate part verdicts; attach donor labels only as bounded caller provenance. A whole 1 MiB PAR block can include headers, padding, other members and good bytes: route by the canonical map, validate nonpayload spans against known evidence, report unmapped spans, never copy archive header bytes into output. Same member ranges map independently; a session-level packed dispatcher can distribute a block across existing handles.

`PartialOptions` explicitly chooses named persistent paths (member-relative policy or caller suffix mapping), state directory and expected volume catalogue. Validate paths under the requested root before create-new/open; reject aliases with all admitted/protected source paths. For known member size, reserve quota then `set_len(final_size)` immediately. Unknown size cannot satisfy size-up-front: typed `UnknownMemberSize` for this policy until geometry is proven. No ordinary PartialFile operation renames, deletes or truncates output. Drop releases ownership and leaves file/state; close is the fallible durability operation. Metadata applies only after a current verified revision, through the existing checked metadata primitives. Persistent placement is explicitly provisional even when its name is final; it is not a legacy publication receipt.

Add `Entry.mode: Option<u32>` from each adapter's existing Unix metadata, absent for formats/hosts without it. This changes downstream struct literals in this unpublished 0.1 API and needs release notes. Add `SelectedEntry::read_observed(self, password, sink, notice: impl FnMut(SelectedReadNotice) -> Result<()>)`; `read` delegates with a no-op. Notice includes volume index/name and `Header/Prerequisite/Selected` role and fires before reads on each volume transition, including solid prerequisite work. Thread it through existing walking/reading seams, with callback error/cancel propagation; no log parsing. ZIP/TAR use their actual source geometry, not fictitious RAR volume numbers.

## 4. Shared private ownership and bounded foundation

H1 retains original lanes in a small optional collection owned by the existing `SourceDriver`, factoring only source-owned range state and checked available-source reads. Keep provider acquisition, admission/protection and replacement orchestration in place. The collection associates admitted `(volume, SourceId, generation)` with its original `Box<dyn RangeSource>`, permanent-hole ledger, source facts and independent operation wake gates; native guards stay with the existing driver. Discovery/refill use the same original owner and separate serialized cursors. H2 can move that owning collection into the longer-lived shared PartialCore, with no second parser or provider reacquisition. Moving past a volume transfers its original object into the registry. No provider reopen, duplicate-ID exception, or unbounded descriptor cache. All retained descriptors, inventory descriptors and replacement lanes count toward existing handle ceilings; default 64/hard 4096 remain real. Exhaustion returns typed capacity/limit before dropping required evidence. New generation admission is explicit and never mutates a live lane's identity promise.

Retained operations may park under distinct task wakers. H1 supplies bounded opt-in cancellation registration/fanout shared by every SessionControl clone, including clones created before retention starts. Cancel wakes all live selected provider/range waits and original leases; retired/dropped registrations are removed or weak/reclaimable. Register metadata and scan/fanout work are metered under existing Usage/source-operation caps; no locks cross Waker hooks or source callbacks/destructors. Cancellation notification does not grant provider retry readiness. The legacy default control path retains its allocation/callback/counter pattern. See the H1 plan for the exact private seam, race/retirement rules and two-lease-plus-selected-wait tests.

SourceBytes retains accepted-byte meaning in **all** modes: validated Filled.count or Hole.len only. NotYet, callback errors and post-callback cancellation/source-change rejection before byte commit add none. SourceRequests retains existing callback-attempt/info-check debit sites and failure ordering; no-wake polls do not call the source or add a debit. Refill additionally precharges requested VerifyBytes as existing replacement verification does; Discovery and ordinary selected reads do not. An eight-byte NotYet followed by a woken two-byte Filled costs SourceBytes=2 everywhere and VerifyBytes=16 for Refill (zero for Discovery/selected), regardless of intervening un-woken polls. The shared read helper must preserve this distinction and existing charge/commit order.

Private `GeometryLedger` extends `PhysicalModel` with proven Stored inner↔packed runs, header spans, part digest scope, member crypto stream offset and anchor identities. Use `plain_extent` only when proven. Model unknown gaps as unknown, not fake `PhysicalPart` headers. Header-only discovery uses the same `HeaderParser`, skipping known payload lengths through `RangeSource`; validates continuation, format, sizes, encryption and volume numbering through existing rules. This is the minimal map foundation required here; publish only `PackedSpan`/hole mappings now. Full original `MemberMap`/seek/probe APIs remain separate work using this foundation.

Private `PartialCore` owns persistent output descriptor/root guards, member key, geometry, validity/provenance ledger, revision, expected checks, durable journal and access to retained sources. Session and handle share `Arc` ownership of this core; durable registry ownership survives session end while any handle exists. Avoid a session/core cycle. Allow one writer operation per member, serialize extraction/fill/verify commits, and release internal locks before provider callbacks. Use operation tokens and revision validation, returning `Busy` or retrying a bounded poll if the same member changes. Filling completed member A while extracting B must work; unlike legacy `poll_verify`, it is not a global conflict. Same-member fills operate only on observed holes, never not-yet-produced output reserved by preallocation.

Storage is O(parts + header witnesses + damage/extent records), not O(payload). Record capped 64 KiB CRC leaves split at part boundaries; 500 MB uses approximately 8,000 leaves plus hole fragments, not a byte bitmap. Bound retained ciphertext edge blocks and unresolved raw fill fragments separately; large packed fills are processed in ≤1 MiB chunks. Add limits for serialized state bytes, journal bytes/records, extent count, discovery distance/header bytes and pending ciphertext, in addition to all existing cumulative read/write/verify/KDF budgets. All offsets use checked arithmetic. Oversized state/interval counts reject before allocation or mutation; no “small checkpoint” claim without configured caps.

## 5. Damage and hole geometry

`declare_hole` adds **damage evidence** against a previously admitted source generation. It does not tell `RangeSource` to change old `Filled` to `Hole`, undo an immutable-source promise, or permit old available bytes to mutate. Registry reads overlay damage while preserving original observed evidence. Bump damage/geometry revisions and invalidate output validity, CRC leaves, part results and cached verification for every affected member. Already finished persistent handles remain discoverable; emit invalidation events for prior revision verdicts. Historical verified receipts are revision-specific, not permanent claims. Legacy published `Artifact` output is not retroactively made writable by this API.

Plain payload damage maps by exact intersections. CBC mapping is relative to the member cipher stream, not volume offset: expand touched ciphertext to complete 16-byte blocks, invalidate corresponding plaintext and the following plaintext block, clip to known inner size, and split `Missing/DeclaredBad` from `CipherNeighbour`. Track all contributing physical spans even across volumes. A missing preceding ciphertext makes a raw fill incomplete, not wrongly decrypted. Header damage invalidates geometry/checks/IV facts derived from that header until canonically re-established; do not merely punch a payload-sized output hole. Repeated/overlapping declarations union dependency damage and are idempotent except new evidence revisions.

Report exact `HoleReport` immediately once geometry is known, before member completion. If geometry is not known, emit `GeometryPending` immediately with exact **known packed** spans and typed reason; emit resolved per-member reports later. This is an explicit representation of the spec's “when sizes allow it”, not a guessed `out` range. Preserve packed cause ranges independently of their expanded output effect. Merge remaining output holes for filling while retaining cause IDs/packed provenance for diagnostics.

Lost headers: if the preceding canonical frame gives the next header offset, continue there; a known volume start is another valid anchor. A header's own length being lost generally prevents locating its same-volume successor. Do not scan payload bytes for apparently valid headers. Advance/discover at the next admitted volume start, whose intact split header can identify the member. Encrypted header IV independence helps only at a **known header boundary with available IV/KDF context**. It is not permission to invent an IV or search for one.

Whole missing volumes: caller expected lengths bound the packed extent and volume identity, but include headers/padding/possibly other members. They do not equal missing inner bytes. For one identifiable Stored split member with known final inner size and all other proven part contributions, forward discovery can determine the aggregate missing inner interval by subtraction. More missing volumes may leave the distribution among packed spans unknown even when aggregate output gap is known. Multiple unseen members, unknown padding, lost data-encryption parameters or incomplete tail geometry require `UnknownGeometry` for affected members. Resume independent later members only from proven parser boundaries. Do not fabricate checksums for lost parts.

Forward discovery must retain original admitted sources, obey Wait/NotYet and budgets, and not emit false extraction completion. If future headers are not yet available, park for those bytes; do not reinterpret their wait as a hole. Once future geometry is available, write suffix at its proven position and keep the gap sparse. If irreducibly ambiguous, return a typed member outcome and continue a proven independent successor. This finite discovery subset is a prerequisite, even though broader C2 compressed-source work was deferred.

## 6. Fills, integrity and repair precedence

Maintain per-range provenance: `OriginalGood`, `Hole(causes)`, `Alt(donor, revision)`, `CheckedRepair(certificate, generation)`, plus `UnknownAfterInterruptedWrite`. CRC/verification status is separate from provenance. `fill` may split holes, arrive out of order and overlap any known extent; compare all nonhole overlap before writing. Ordinary mismatches return typed `OverlapMismatch` with exact ranges and no semantic commit. A larger fill must not overwrite any original-good byte. Compare-before-write also prevents a later bad overlap from leaving a partially accepted operation.

`fill_packed` is twin data by default and follows the same match-or-error rule. A separately validated `CheckedRepair` allows replacement of conflicting **Alt-origin** bytes and reports those exact donor mismatches, even if that alt produced an earlier failed check. It never authorizes silently changing `OriginalGood`, unrelated repairs or archive geometry. When previously original-good data is now damaged, require explicit damage declaration first. Preserve the historical archive failure fact for its old source/output revision; a new repair revision can be checked afresh. Do not clear the legacy sticky `Assessment.failed` globally or let `ExpectedInner` override old archive failures.

Repair certificate design: caller `RepairVerifier` validates archive-set/file identity, generation, covered packed range and digest of supplied bytes against its **already verified** PAR block result, returning a bounded certificate. The library opaque `CheckedRepair` is constructed only through that verifier and actual byte binding. This is a cooperative trust boundary, not native archive authenticity or magic `trusted: true`; persist the certificate as provenance and revalidate on reopen if used for precedence. The chosen callback boundary adds no par-rs dependency. The callback receives the actual bytes and bounded claim, so its own PAR verifier can use its existing IFSC digest (including MD5) without adding that algorithm here. No lock is held during the callback; revision/cancellation checks follow it, and reentrant mutation returns Busy. Final archive checks remain necessary; forged cooperative assertions never mint publication authority.

`refill_from_packed` reads a retained original only if its generation is unchanged and the bytes were already available under its contract. If PAR rewrites the archive, old leases must be retired and a new explicitly bound generation supplied; validate set/length/header witnesses/protection and invalidate dependent checks. Do not keep reading a supposedly immutable old descriptor that was modified in place. Existing strict full replacement witness replay remains useful for legacy recovery and complete-source comparisons, but a one-block fill is not automatically such a witness.

For AES, map raw archive spans into the canonical cipher stream; use retained neighbouring ciphertext or known initial IV. Cross-volume neighbours are ordinary stream dependencies. Merge bounded partial cipher blocks until complete; report exactly which previous block is still needed. Repaired ciphertext may require updating both its own output and the following plaintext block. Compare good plaintext and raw known bytes, preserve actual padding evidence and correct keyed checksum parameters. Never reset member CBC merely because a new part header has an IV-looking field; follow existing MemberMachine semantics.

CRC path: hash actual successfully written bytes into leaves, combine ordered `(crc,len)` only for completely known extents. A leaf CRC cannot be split to arbitrary subranges from its aggregate alone. Split-time edits/late damage reread at most affected leaf fragments (and any cipher dependencies), recompute them, then combine unchanged leaves. Plain nonfinal part checks use exactly that part's packed/output interval. BLAKE2sp needs one bounded full readback at final verification; do not pretend CRC-combine handles it. State-restored leaves are untrusted hints: output descriptor/path identity plus mtime alone does not bind bytes. Rehash valid extents on reopen unless an independently trusted storage-integrity mechanism establishes identical content; report that cost honestly. External writes while open invalidate verification; the named-output lease is cooperative, backed by identity/stamp checks and readback where required, not protection against a malicious concurrent writer.

Encrypted plaintext fills cannot be checked by applying ciphertext part CRC directly to plaintext. Reconstruct needed ciphertext with existing AES encryption from a proven prior ciphertext anchor (or initial IV), across complete known plaintext blocks until the part scope is complete; compare available ciphertext at boundaries and check actual packed digest. Retain or reread genuine padding where a scope includes it; never generate guessed padding and call it evidence. This may require targeted prefix/suffix work or waiting for another hole. If packed evidence cannot be reconstructed, report `Incomplete`/whole-inner result with missing packed scope, not `PartBad` guessed from an inner mismatch. The required wrong-byte test uses a real part check and must prove attribution for supported plain and encrypted cases; unsupported geometry is tested separately and cannot silently replace acceptance.

## 7. Durable state and restart composition

Use optional Cargo feature `persistent-partials` with `serde = { version = "1", features = ["derive"], optional = true }`; own data-only types use bounded validated deserialization. No serde_json/bincode runtime dependency: caller chooses serde format. The internal journal uses one documented versioned, length-bounded record encoding with checksums/torn-tail detection; it is not a second copy of archive parsing. Dependency additions require the future lease/offline availability check; none was acquired now.

Data layout:

```text
DurableEnvelopeV1
  schema/format versions, job/archive binding, state id, commit sequence
  root-relative output name + native identity hints; expected output size
  member key/name, canonical geometry/header witnesses, checksum scopes/values
  source ids/generations/lengths/identity commitments, KDF parameters (no key/password)
  output, damage, geometry, repair and verification revisions
  produced frontier (not file length), validity/provenance/CRC leaves, open HoleReports
  journal anchor and digest, metadata-to-apply, optional ResumeCursorV1
ResumeCursorV1 (implemented later)
  current volume/packed offset, stable member ordinal, safe produced frontier
  parser-safe phase/format/main context, part remaining, cipher stream position
  CBC previous block/IV + previous-known flag, padding counters, KDF references
  completed-member references and state revisions; current member durable state reference
```

No serde of `MemberMachine`, `HeaderParser`, `AesKey`, `Artifact`, `Verification`, `Target`, `SourceStamp` capability, native descriptor or process nonce. New process creates fresh runtime IDs and reconnects stable keys only after validation. Password/key re-entry is required by default; wrong password never triggers output mutation. Hash state is not tied to Rust struct memory layout: initial implementation rehashes output prefix/part evidence as needed, later stable hasher serialization would need its own versioned proof.

Checkpoint size is bounded O(current cursor + references + bounded current holes), with immutable versioned member-ledger pages referenced by digest; finished-member manifests can be paged rather than copying every member into each checkpoint. Caller persists checkpoint **with referenced durable state**, not just an orphan serde blob. `PartialState` is still portable serializable data sufficient to locate/rebind its journal and pages within explicit root/context; moved files require explicit rebind, not guessing identity.

Serialized state is untrusted. Verify schema/lengths/interval order, arithmetic, names/root containment, output fd/path binding and source commitments before any write. Caller supplies expected archive/job and committed-state digest from its trusted queue context; self-declared digests inside the same untrusted blob prove nothing. A checkpoint altered along with all its self-hashes must fail the independent expected binding. That cooperative binding establishes provenance, not native publication authority. Reparse retained canonical header witnesses and verify header integrity; after reopen rehash output as above. If expected archive/source/committed-state binding cannot be re-established, return typed mismatch, never guess and never auto-delete/restart.

Mutation durability order, under exclusive member operation lease:

1. Validate identity, source revisions, overlap, bounds/quota; prepare invalidation and bounded intent for every actually modified range. Append intent to owned journal and fsync it **before** output mutation. Keep old externally committed state valid for replay, not as authority for touched bytes.
2. Perform positional writes, accounting each short write/cancellation/ENOSPC. No validity bit/CRC leaf becomes durable yet. On failure, leave all intended changed ranges unknown/holes, with exact attempted/completed bytes; original-good compare-only spans remain good.
3. Recheck identities/revisions, sync output, then append commit with new ledger/revision and sync journal. Publish `state()`'s new committed sequence only now. Atomic sidecar replace/parent-directory sync is permitted for state files; it does not rename/delete partial output.
4. Compact journal only after a fully durable snapshot and directory sync. Crash after output write but before commit replays intent as unknown, never stale valid CRC. Crash after durable commit but before caller queue update replays journal to latest safe state. Torn tails cannot invent a commit. Refill retries are idempotent match-or-error.

Create output/state with create-new and checked root/parent descriptors; persist parent directory entry before advertising `PartialReady`. State directory aliases/protected source paths are checked too. Reject symlink/hardlink/path swaps, foreign outputs and shorter output on reopen. Ordinary `PartialFile::open` also rejects unexpected length and never truncates. Metadata application is a separate revision-checked post-verification operation; a later damage/repair revision invalidates its verdict without pretending the output disappeared.

Resume branch API proposal: `ProgressiveSession::resume(checkpoint, provider, options, ResumeContext { root, password, expected_binding })`, plus `request_checkpoint` and `CheckpointReady` event. Only snapshot a parser-safe boundary or a Stored feed boundary with complete AES block, no buffered unaccounted ciphertext, and known next parser action. Mid-block request rounds down to last retained safe state; never serialize half a decryption as “safe”. A volume boundary inside a CBC block may require the prior safe point, including its volume/offset and chain block. This satisfies “at boundaries and/or N MiB”, not a promise that every physical boundary is safe.

Resume validates everything before mutation, reopens current volume at its recorded offset, and reconstructs parser/machine via narrow safe-state constructors using the canonical engine. It reads no earlier-volume data; volume 1 headers may be read for KDF only, and persisted header/KDF witnesses avoid that where possible. Output prefix rehash is allowed and separately metered; nonfinal packed prefix checks can require ciphertext reconstruction from output plus persisted anchors, not rereading earlier volume payload. A state lacking necessary exact cipher/padding facts is typed not-resumable. No scan from volume 1 disguised as resume.

Resume-only truncation: explicit validated ownership of the **current** member and exact safe frontier permits truncating its output down to `bytes_written`; it then re-establishes requested final sparse length before extraction appends. File length from preallocation must never be mistaken for produced bytes. Finished member files are never truncated or rewritten. Shorter current output, schema/set mismatch and stale incompatible state return typed errors before truncation.

**Chosen checkpoint/fill barrier:** a fill beyond the last durable extraction cursor frontier requires a newly acknowledged safe checkpoint before commit, otherwise `CheckpointRequired`/`Busy` with **zero output writes**. An old incompatible checkpoint returns `CheckpointSuperseded` before truncation and preserves every durable fill. Prefix fills and declared damage reconcile from the journal. No payload redo store is introduced. Hole-skip reserves the versioned cursor/journal references but does not implement cursor resume; R1 pins the acknowledgement protocol after hole-skip delivery. Ordinary post-extraction PartialFile filling remains independent of cursor resume.

## 8. Requirement → implementation → regression coverage

All checks below are required implementation evidence, not tests run during design preparation. Small first-party fixtures/fault tests precede production changes. Existing read-only golden inputs/proof may be reused when matching exact conditions; new large/native runs require root's named resource window.

| Spec requirement | Existing/new ownership | Concrete regression retained |
|---|---|---|
| Hole §1 caller ranges, late declarations, distinct waits | Existing source protocol + new DamageLedger/declare method | Filled then late CRC rejection; duplicate/overlap declarations; original generation remains immutable; Wait/NotYet never creates HoleReport. |
| §2 immediate exact output+packed events | Canonical run ledger and richer RecoverySink damage | Observe hole before member finish; cross-member/volume split; CBC main/neighbor cause separation; unknown coordinates use typed event then resolution. |
| §3 preallocated named output/no rename-delete-truncate | New persistent native policy sharing guard primitives | Size visible at member start; sparse unwritten regions; drop/cancel preserves output; no partial metadata application; alias/symlink/hardlink/parent swap rejection. |
| §4 all fill forms, durable handle, CRC paths/part checks | PartialCore/ledger/retained sources | Out-of-order subhole fill, matching good overlap, wrong overlap no commit, fill while another member extracts and after session drop/reopen, exact checksum path and per-part event. |
| §4b twin/alt/PAR ordering | CheckedRepair/provenance revisions | Twin mismatch errors; verified PAR corrects Alt only with mismatch report; original-good mismatch errors; stale generation/certificate rejected; late repaired source explicit rebind. |
| §5 RAR4/RAR5 AES and hp | Existing cipher plus positioned gaps/refill/check reconstruction | Every byte position around AES boundary, parts split within block, last-block padding, missing prev block, hole+next taint, header IV loss vs intact next header, keyed checksum. |
| §6 header/whole missing volume | Header discovery + expected volume catalogue | Known-boundary lost header and recoverable split header; whole middle volume with exact inferred gap; sizes include overhead; ambiguous multi-member volume returns typed unknown, no guessed output. |
| §7 independent members | Shared registry/per-member ledgers | Damage affects only overlapping members; clean member verifies; cross-member PAR block dispatches safely. |
| §8 compressed failure | Existing stop machinery with opt-in proven-boundary drain | Damaged independent compressed member reports Unrecoverable at real output offset; drain known remaining parts through canonical framing and then decode clean independent successor. Solid history remains invalid until proven reset; unknown framing is not recoverable. |
| §9 typed events/errors | Extend ProgressiveEvent/FailureKind and context | Password/checksum/truncation/hole/unsupported/unsafe-path carry member, volume, packed offset where known; no string parsing. |
| §10 Entry.mode | All listing adapter conversions | Unix RAR/ZIP/TAR permission bits, absent host metadata, listing-vs-SelectedEntry agreement. |
| §10 selected read notices | read_observed → existing RarSelection/walking/read seam | Split volume transitions including prerequisite reads; notice before reads, sink error/cancel propagation, unchanged old read output. |
| Acceptance 1 | New entrypoint end-to-end | **500 MB, ten RAR5 volumes, 700 KB articles, 10% holes**; finish to end, exact hole union, fill original bytes, verify Ok and byte comparison. Keep units/rounding and deterministic loss seed in proof. |
| Acceptance 2 | Same entrypoint variants | Same RAR4 Stored, RAR5 Stored encrypted headers with password; whole missing middle volume with expected sizes. |
| Acceptance 3 | Discovery + mapping | Hole across volume boundary and hole covering member header, exact reports and continued extraction. |
| Acceptance 4 | Real part and final checks | One wrong fill byte returns correct PartBad volume when scope exists; otherwise Bad. Encrypted packed-domain attribution proof, missing-check case honest. |
| Acceptance 5 | Damage revisions | Declare already extracted bytes, invalidate earlier verdict, fill correct bytes, final Ok. |
| Acceptance 6 | Durable reopen | Actual subprocess kill mid-fill at intent/write/sync/commit boundaries, reload PartialState, retry/finish, Ok; short-write/ENOSPC/cancel independently injected. |
| Acceptance 7 | Independent continuation | Two-member non-solid fixture: supported compressed member 1 with data hole → Unrecoverable; intact member 2 extracts/verifies. |
| Acceptance 8 | Existing wake protocol + persistent policy | Supply volumes one-by-one, Wait between, article NotYet and holes; equal result to acceptance 1 and no extra un-woken callbacks. |
| Acceptance 9 | Packed repair path | Post-extraction **1 MiB volume-aligned PAR blocks** over holes+good bytes → Ok; repeat with wrong alt first, observe correction mismatch and Ok. Test fill_packed_repair and new-generation refill path. |
| Resume §1 checkpoints | Later CursorV1/safe-state constructors | Volume/N-MiB/request checkpoints; bounded serialized size; round-down at mid-CBC block/header; secrets absent. |
| Resume §2 reopen/append | Later resume-only authority | Longer output truncated to frontier then continued; shorter/schema/set/source/output binding mismatch typed and byte-for-byte unchanged; finished files untouched. |
| Resume §3 holes/streaming | Shared envelope/journal | Current open reports persist; waiting state restarts without converting wait to damage; completed partial handles remain fillable; old-cursor vs later-fill tests above. |
| Resume §4/acceptances | Later RAR branch, then 7z integration | Seeded subprocess kills between volumes/mid-volume/mid-AES-block for RAR4/RAR5 Stored and RAR5 encrypted headers+data; final bytes/hash equal uninterrupted control; recorded provider reads prove no earlier payload and only permitted volume-1 headers. Solid typed not-resumable; compressed current-member restart remains nice-to-have. |
| Original all-eight continuity | Retained foundation, not full feature claim | Preserve original streaming encrypted fixtures, map byte reproduction, offset-N boundary/mid/last-block extraction, 7z Copy/AES and LZMA2 scan/find/decode, probe and typed errors in master queue. No fake completed status for APIs not delivered here. |

## 9. Implementation boundaries and accepted decisions

These are accepted architecture decisions. Implementation still requires a finite task lease and review; no user permission menu is needed.

| Decision | Required implementation contract |
|---|---|
| Opt-in PartialFile | Share canonical machinery; preserve Artifact defaults and strict publication authority. |
| Retained originals first | Minimal SourceDriver factor, exactly one owner per source, no reopen/ID waiver/spool; legacy mode remains one-pass. |
| Geometry | Canonical bounded discovery or exact caller facts, else typed unknown. Whole-volume length never substitutes for payload length. |
| Checksums | Rehash on reopen; combine actual known CRC leaves; AES packed checks require real anchor/geometry/padding. Missing evidence is explicit. |
| State authority | Open/ResumeContext supplies independent trusted job/archive/member/committed-state anchor. Serialized self-hashes and capability-looking data grant no authority. |
| Repair | Caller-owned RepairVerifier receives actual bytes/claim without internal locks; fresh bound CheckedRepair authorizes only Alt-origin correction. |
| Persistence | Bounded versioned intent/write/sync/commit journal, no default redo payload store; optional serde feature with bounded deserialization. |
| Resume composition | Acknowledged safe-checkpoint barrier and typed supersession; no lost accepted fills, no ordinary PartialFile truncation. |

| Increment | Deliverable and source boundary |
|---|---|
| H1 | Retained-original source ownership, exact admission/high-water behavior, independent serialized read leases, bounded descriptors/source objects, independent-task cancellation fanout, accepted-byte accounting and stale-wake protection. Small first-party fixtures and regressions belong in its tasks. No Cargo, public API, publisher, ZIP, CLI or default changes. See the H1 implementation plan. |
| H2 | Persistent named-output policy, shared native range-I/O/guards, versioned journal/state, PartialFile open/plain fill/CRC ledger and immediate RAR5 Stored reports. Pin full PartialLimits, public data types, state-anchor API, exact serde availability/lock changes and feature-enabled CI before editing. |
| H3 | Late damage, bounded canonical header/missing-volume geometry and independent compressed Unrecoverable/clean-successor continuation. No new compressed codec algorithm. |
| H4 | AES raw fill/refill and packed-domain evidence, verifier-bound repair precedence, RAR5 header/data encryption and RAR4 Stored integration. Preserve legacy sticky recovery. |
| H5 | Entry.mode/read notices, complete consumer documentation and all exact nine acceptance checks. Large/native acceptance work only in a named future resource window. |
| R1, after H public qualification | Separate checkpoint/resume branch and finite plan using the delivered durable schema; safe-state restore, exact kill/read-trace tests and acknowledgement protocol. |
| Subsequent required work | Actual 7z reader followed by Copy/AES hole/resume adapters; original maps/probe/seek, 7z codecs/chunk tools and remaining RAR compatibility work. |

H1 foundations are independently testable but stay unreleased until a meaningful public consumer exists; foundation completion is not completion of this request. Each later increment gets its own finite plan and evidence, rather than an implicit open-ended grant. Preserve existing fixture provenance and private proof; do not copy external decoder implementations. Required small RED/GREEN tests precede changes, followed by focused regression, independent review and exact-head hosted checks. Root coordinates source grants, final resource windows, release qualification and consumer handoff.

## 10. H1 constraints inherited by its implementation plan

- Rust 1.100.0; private offline Cargo/target directories; jobs 3; no global cache mutation.
- No H1 Cargo/dependency/feature changes, public PartialFile API, publisher, ZIP or CLI changes.
- Preserve default one-pass source drops, callback counts, resource limits, publication and failure contracts.
- Existing metadata budget 128 MiB, read chunk 1 MiB, and 64 GiB byte-work budgets remain; these are not process RSS limits.
- Count retained non-file source objects as well as actual backing/protection/replacement descriptors; each independently obeys the existing volume_handles configured limit, capped at 4096 (default 64) in opt-in retention mode.
- No internal locks across provider/source callbacks, RawWaker clone/drop/wake hooks, or user source destructors.
- No original reacquisition, duplicate-ID waiver, payload spool, second parser, source-generation rewrite or unsafe stage-path extraction.
- No 500 MB/native/oracle campaign in H1; final private Mac checks once, focused Linux checks only under a root resource lease.
