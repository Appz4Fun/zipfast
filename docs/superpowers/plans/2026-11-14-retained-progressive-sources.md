# Retained Progressive Sources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an internal opt-in retained-original-source foundation that supports revisiting admitted volumes and serialized positioned reads without reopening sources or changing legacy extraction.

**Architecture:** Keep provider acquisition, immutable admission records, protection/native guards and replacement orchestration in `SourceDriver`. Factor only source-owned range facts into `OriginalSource` and the reusable available-source read operation; retain original objects in a small optional driver-owned collection. No shared mutex registry or persistent-output implementation is needed for H1.

**Tech Stack:** Rust 1.100.0, std ownership/atomics/wakers, existing progressive quotas and native guards; existing first-party test facilities. No new dependency.

**Spec:** [Persistent Stored holes design](../specs/2026-11-14-persistent-stored-holes-design.md), especially §§2, 4, 9–10. Read both documents before implementation.

## Global Constraints

- Rust 1.100.0; private offline Cargo/target directories; jobs 3; no global cache mutation.
- No H1 Cargo/dependency/feature changes, public PartialFile API, publisher, ZIP or CLI changes.
- Preserve default one-pass source drops, callback counts, resource limits, publication and failure contracts.
- Existing metadata budget 128 MiB, read chunk 1 MiB, and 64 GiB byte-work budgets remain; these are not process RSS limits.
- Count retained non-file source objects as well as actual backing/protection/replacement descriptors; each independently obeys the existing volume_handles configured limit, capped at 4096 (default 64) in opt-in retention mode.
- No internal locks across provider/source callbacks, RawWaker clone/drop/wake hooks, or user source destructors.
- No original reacquisition, duplicate-ID waiver, payload spool, second parser, source-generation rewrite or unsafe stage-path extraction.
- No 500 MB/native/oracle campaign in H1; final private Mac checks once, focused Linux checks only under a root resource lease.

Source begins only after root's fresh builder check and a named source lease. Root selected fresh implementation owner per actual task, with scoped review; this document's author owns documentation only. Base is qualified `0030c75a86f5ab7c1cf89a8dea91d55bdc435e86`, tree `50ae252749b3ebae8cdd7cef963cc6d1f54e7617`, branch `codex/persistent-stored-holes`. Do not create another worktree or rebuild the full baseline. Root supplies private environment/disk budget; preserve every old worktree and proof directory.

## Review Focus

1. A provider returns a source that is rejected during admission: destroy it exactly once outside locks, preserve the old owner or poison explicitly, and never admit it on retry. Task 1 tests this.
2. Selection returns to an earlier volume while newer volumes were admitted: the next new volume follows admission high-water, not selected cursor, and no provider reacquisition occurs. Task 1 tests this.
3. A custom non-file source has no descriptors: it still consumes retained-object capacity, including replacement objects. Task 1 tests this.
4. A stale provider waker or lease destructor arrives after retirement: it cannot authorize a new range, extraction or replacement retry. Task 2 tests this.
5. Independently parked leases and selected waits use different task wakers, including reentrant RawWaker hooks: external cancellation must wake every live operation without granting provider retry readiness, waking a previously retired registration, deadlocking or advancing a canceled read. Task 2 tests fanout and bounded subprocess reentrancy.

---

## File map and limits of the factor

| File | Responsibility |
|---|---|
| Modify `src/progressive/source.rs` | Keep SourceDriver orchestration. Add private opt-in constructor, retention selection/admission/accounting and bounded shared cancellation fanout; factor per-source facts and one shared checked range-read helper. Existing default constructors remain one-pass. |
| Create `src/progressive/source/retained.rs` | Retention-only records, positioned-read token and SourceDriver methods for original leases. No parser, publisher or independent provider loop. Parent module private visibility is sufficient. |
| Modify `src/progressive/source/tests.rs` | Preserve assertions and add only default-mode characterization/helper visibility needed by focused tests; adapt direct private field access after the narrow factor without weakening expected values. |
| Create `src/progressive/source/retained_tests.rs` | Small in-memory/drop-counter/native-temp-source tests and bounded reentrancy children for the new internal mode. |

No production changes outside these files in H1. Existing recovery/session/output tests run unchanged. If implementation requires another production file, a new resource/public error variant, a mutex source registry, or changing native publication policy, report the concrete exception to root before editing it.

### Exact private interfaces and state

All names below are internal, not RustyGet APIs. `ProgressiveResult` and `SourceStep` remain existing types.

```rust
impl SourceDriver {
    pub(crate) fn new_retained(provider: Box<dyn VolumeSource>, first: OsString,
        limits: ProgressiveLimits, control: SessionControl) -> ProgressiveResult<Self>;
    // Existing signatures retained:
    pub(crate) fn select_volume(&mut self, request: VolumeRequest) -> ProgressiveResult<()>;
    pub(crate) fn poll_step(&mut self, cx: &mut Context<'_>, buf: &mut [u8])
        -> Poll<ProgressiveResult<SourceStep>>;
    // Added by task 2:
    pub(crate) fn begin_original_read(&mut self, volume: u32, offset: u64,
        purpose: OriginalReadPurpose) -> ProgressiveResult<OriginalRead>;
    pub(crate) fn poll_original_read(&mut self, read: &mut OriginalRead,
        cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<ProgressiveResult<SourceStep>>;
    pub(crate) fn retire_original_read(&mut self, read: &mut OriginalRead)
        -> ProgressiveResult<()>;
}
pub(crate) enum OriginalReadPurpose { Discovery, Refill }
pub(crate) struct OriginalRead { /* private owner identity, source identity,
    lease epoch, cursor, gate, state, purpose */ }
```

`OriginalSource` holds exactly one `Box<dyn RangeSource>`, volume index, current validated `SourceInfo`, permanent-hole intervals, backing descriptor count and (task 2) optional lease record. Move current `source/info/holes/backing_count` into this value; do not duplicate the object or heap-box this wrapper in default mode. Keep initial `(index,id,name,SourceInfo)` admission snapshots immutable in existing `admitted`; `observed_info` continues returning that snapshot. Live extent/Advertised→Final transitions update only `OriginalSource.live` after checking the existing identity/length/monotonicity rules.

`RetainedOriginals` is an optional field: `None` for `new`, `with_usage`, replacement child drivers and `sealed_memory`; `Some` only for `new_retained`. It owns the unselected originals, highest **successfully admitted** original index, an operation identity and checked nonwrapping lease counter. No eager vector allocation in default mode and no replacement of `admitted` with a new registry. Sorted retained slots use volume index; charge lookup/comparison/movement/allocation via existing Usage helpers. Admission high-water and selected request/cursor are separate. Wait before admission changes neither source ownership nor high-water.

For new mode, `select_volume` may select an already admitted exact `(index,name)` or the next index after high-water. It moves current source state into retained storage and moves a retained target into current ownership; a next-new selection leaves current empty pending acquisition. Reject wrong names, skipped new indices, duplicate IDs and out-of-bounds requests. Charge all needed slot capacity, request-name work and fresh-gate allocation before ownership movement; use infallible moves after preparation. If later native admission changes guards before failing, poison driver before return; it must not retry partially admitted state. Returning to an admitted source emits one `VolumeOpened` on the next nonempty `poll_step` with its original id, without provider callback or re-admission. Empty reads remain callback/event-free. Revisited-source identity is checked before notice/read; no new native guard clone.

Default `select_volume` keeps its current monotonic behavior/drop timing/counters. Original source destructor may run only after internal locks are absent. Retained mode never evicts an original silently; capacity rejection preserves the current owner (or explicit terminal poison after a partial native failure). Dropping the driver drops each original exactly once; a read token does not own a source or keep the driver alive. H2 may later move the same collection into a longer-lived owner under its own lease—H1 does not claim session-independent lifetime.

Task 2's exact reusable seam is a stack-borrowed operation view, avoiding a new default heap owner:

```rust
struct RangeOperation<'a> {
    cursor: &'a mut CheckedCursor, gate: &'a Arc<WakeGate>,
    parked: &'a mut bool, retry_admitted: &'a mut bool,
    control: &'a SessionControl, usage: &'a mut Usage, verify: bool,
}
fn poll_available(original: &mut OriginalSource, op: RangeOperation<'_>,
    buf: &mut [u8]) -> ProgressiveResult<Poll<SourceStep>>;
impl OriginalSource {
    fn check_info(&mut self, usage: &mut Usage) -> ProgressiveResult<()>;
    fn hole_bound(&self, offset: u64, touching: bool, usage: &mut Usage)
        -> ProgressiveResult<usize>;
    fn remember_hole(&mut self, offset: u64, end: u64, usage: &mut Usage)
        -> ProgressiveResult<()>;
}
```

The caller registers its task waker and, in retained mode, its cancellation registration described below; it refreshes native guards and supplies the right operation gate/epoch; the helper creates the provider Context from that gate. Existing SourceDriver wrappers can delegate rather than changing recovery callers. The operation view holds no locks. Its fields borrow existing selected/replacement state or the OriginalRead token; it owns no source and adds no allocation.

Task 2 introduces a shared range-read helper, used by selected reads, replacement child-driver reads and original lease reads. Keep provider acquisition and `VolumeOpened` handling outside it. The helper takes the selected `OriginalSource`, checked cursor/request state, control, Usage, buffer, and read purpose; it preserves exact existing order: pre-read info check, bounded work charge, source callback, post-read info/cancel check, validate Filled/Hole answer, commit permanent-hole/byte accounting, then cursor advance. It must not bypass the native guard refresh for a retained read. Default operations retain their existing wake/counter behavior; fresh per-request epochs are an opt-in retained-mode rule.

### Lease, wake and error contract

- A lease binds one existing `(owner, volume, SourceId, generation, epoch)` and a cursor independent of extraction. It never calls `VolumeSource`; unadmitted volume, wrong owner, retired token or missing opt-in mode returns `InvalidCapability` before source callbacks. Offset past logical EOF returns `SourceContract`; exact EOF returns `EndOfVolume` without read callback. Empty read returns Filled/count 0 without provider callbacks or advancing state.
- At most one active read lease per original; selected extraction cannot read/select away the same leased current lane. Reject this scheduling conflict with `InvalidCapability` before mutation/poisoning; other already admitted lanes may be leased/read serially while a different lane waits. No public Busy error is added. H2 schedules around this internal condition.
- States are `Active`, `Parked { offset, requested_len }`, `Retired`, `Failed` and `Canceled`. NotYet parks the same request; repeat poll with no wake performs no source callback or attempted-read charge. Change of parked offset/length is invalid. A filled/hole result advances the lease cursor only on success, then the next request gets a fresh gate/epoch. A successful callback is not permission to reuse its waker on another request.
- The opt-in selected acquisition/range cursor also gets a fresh gate when changing request, preventing old volume/range wakers from waking a later request. Preserve pre-return wake races: a wake before NotYet/Wait is retained for exactly that request. Account ProviderWakes before retry callbacks. Do not add this new allocation/counter pattern to legacy default/replacement operations.
- `OriginalRead` owns a small charged Arc epoch with an atomic retired flag; its Drop retires the cancellation registration, sets the epoch flag and disarms the gate without source access or a registry lock. The driver's lane lease record observes retirement lazily before reuse. Explicit retirement is allocation-free, sets terminal token state even if cancellation is already latched, and invalidates stale provider wakers. A new lease allocates a fresh gate; an allocation/budget failure cannot reactivate the prior epoch. Token Drop after driver Drop is harmless.
- Cancellation is checked before callbacks and after each callback/RawWaker boundary. A canceled read never advances cursor or commits the callback answer, even if Filled was returned. `Canceled` has priority over stale-token/closed errors; every later poll remains closed. Structural conflicts rejected before starting an operation do not poison the owner. Source contract/change/I/O/budget errors during a read poison the driver and the affected token, disarm gates and retain ownership for eventual orderly drop; do not silently resume extraction against uncertain source facts.
- No source object is inside a new mutex. Existing WakeGate/Usage locks protect only internal data, never user code. Clone/take task Wakers outside/inside existing small lock regions as appropriate, but drop/wake them outside locks. Call `info`, `backing_files`, `read_at`, `volume`, `protection` and source destructors outside every internal lock. Callback-triggered cancellation of this or another driver is supported; safe Rust does not permit a second simultaneous mutable borrow of this same driver.

### Opt-in cancellation fanout (Task 2)

Distinct task wakers are supported for independently parked operations. Checking the canceled bit only on a later poll is insufficient. Every retained selected provider/range wait and original lease has its own cancellation registration; selected opt-in polls do **not** replace the legacy single task registration. Default/replacement callers keep their current single-task path. The public SessionControl API and cancellation token remain unchanged.

Pin the private control seam in `source.rs`:

```rust
struct ControlWake { legacy: WakeGate, retained: OnceLock<Arc<CancelFanout>> }
struct CancelFanout { /* terminal canceled flag + mutex of bounded Weak<CancelSlot> records */ }
struct CancelOwner { /* existing retained-driver operation identity + configured max operations */ }
struct CancelRegistration { /* owns Arc<CancelSlot>; Drop retires, no source access */ }
struct CancelSlot { /* owner identity, Weak<WakeGate>, atomic retired flag */ }
impl SessionControl {
    fn enable_retained_cancel(&self, usage: &mut Usage) -> ProgressiveResult<()>;
    fn register_retained_cancel(&self, owner: &CancelOwner, gate: &Arc<WakeGate>,
        usage: &mut Usage) -> ProgressiveResult<CancelRegistration>;
}
impl CancelRegistration { fn retire(&mut self); }
impl WakeGate { fn notify_canceled(&self); }
```

Use one shared `Arc<ControlWake>` **in place of** the existing control `Arc<WakeGate>`, not an additional default Arc/allocation; its OnceLock is empty by default and allocates no fanout or registration until retained mode is enabled. Existing provider/request WakeGate layout remains unchanged, so its existing size-based retirement charges do not drift. Public SessionControl clones made **before** `new_retained` see the same installed hub; attaching an option only to the constructor's local control clone is incorrect. No new default callbacks, quota debits, vector or allocation count; the extra empty control attachment is inline in the existing shared control allocation.

`new_retained` creates a CancelOwner using its existing operation identity and `limits.volume_handles.min(4096)`, and enables the shared fanout after precharging its allocation. A hub may serve multiple retained drivers sharing one SessionControl: count each owner's live registrations against that owner's cap and total live hub registrations against 4096. Each operation has at most one live registration; selected and leased use of the same source cannot overlap, so this fits the existing source/lease ceiling. Reclaim expired/retired weak rows before capacity rejection and before charging capacity growth; charge the bounded scan/comparison/movement work under SourceBookkeeping. Limit failures use existing VolumeHandles with the actual per-owner or hard cap, before a provider callback or owner-state mutation.

Registration charges its Arc/slot/weak-record capacity under MetadataBytes and scan work plus one future fanout visit under SourceBookkeeping **before** admission. That prepayment makes the infallible SessionControl::cancel path allocation-free and bounded: set the sticky cancellation token first, set the hub terminal flag and move its existing vector out under its small mutex, then upgrade/check/notify live slots outside the mutex. Only the first cancellation drains the list; repeated cancel cannot rescan registrations. Enabling the hub observes the already-sticky cancellation token, so a hub installed after cancellation starts terminal. A registration racing cancellation checks both the token and terminal flag under the same mutex, cannot be inserted after drain, and wakes its already-registered task outside locks before returning Canceled. It never calls the provider. Missing precharged capacity/work fails before a registration is installed. No Usage or registry lock is held while calling gate notification, any Waker hook or source code.

The operation first registers its task Waker in its own gate (clone/drop hooks outside locks), then installs/reuses its cancellation registration and rechecks cancellation before any provider call. Refreshing a parked task Waker reuses the same slot. Completing a request, retiring/dropping a token, poisoning or canceling an operation retires the registration; new request epochs install a new slot. Drop/retire sets the slot retired flag and releases ownership without locking the hub; only a bounded weak row remains until next admission/drain. A provider's old Waker keeps only the old request gate alive, not its cancellation slot. Fanout skips retired/dead slots and never reactivates an epoch. Retirement completed before cancellation is not notified; an already-started notification racing retirement may finish, as ordinary wake races permit.

`notify_canceled` only takes the registered task Waker under the gate mutex and wakes/drops it outside the mutex. It **does not set ready, increment ProviderWakes or authorize a provider retry**; existing readiness, if any, still cannot bypass the canceled-token check. Keep legacy `notify(false)` behavior on the legacy control gate. RawWaker wake/drop may reenter cancel: the fanout vector is already detached, its terminal bit prevents another drain, and no lock is held. Cancel-registration Drop never drops a user task Waker while holding the hub lock. This is a bounded control registry, not a mutex around source objects.

### Accounting, protection and preserved recovery

Two independent opt-in ceilings use existing `Resource::VolumeHandles`: (A) original+replacement `RangeSource` objects, including non-file objects, ≤ configured `volume_handles` capped at 4096; (B) actual retained original/current backing descriptors + every existing native-protection descriptor + replacement lane backing/guard descriptors, under the same limit. Default is 64. Enforce A before acquiring the next original when known; enforce B after inspecting candidate backing and before native cloning. Count the live old replacement during replacement admission, as existing code does. Recompute aggregate counts on parent admission, protection upgrade and replacement admission; do not use a stale child external-handle snapshot as aggregate truth. Keep immutable backing/native stamps and protection Complete epoch/inventory freeze rules intact.

Metadata/name/interval allocations and comparison/movement work remain charged; new owner/lease Arc/gates/retained slots and cancellation registrations are charged only in new mode. **SourceBytes always means validated accepted Filled.count or Hole.len**, for default selected, retained selected, Discovery, Refill and replacement reads. It never charges requested length, NotYet, callback error or a post-callback cancellation/source change rejected before byte commit. Keep the existing accepted-byte charge/ledger/cursor ordering, including existing failure behavior if later bookkeeping fails; do not change default quota semantics. SourceRequests retains existing callback-attempt/info-check debit sites and failure ordering; an un-woken poll adds no new debit. Refill additionally charges requested VerifyBytes **before** invoking read_at, exactly like replacement verification; Discovery and ordinary selected reads do not. A VerifyBytes limit failure prevents that callback. A SourceBytes limit failure can occur after a valid callback but before cursor advance; it cannot be replaced by attempted-length precharging. Repeated accepted reads count again as cumulative source work. No extra accounting mode is needed in RangeOperation: its existing verify boolean distinguishes attempted verification reads.

| Requested 8-byte read sequence | SourceBytes | VerifyBytes | read_at calls |
|---|---:|---:|---:|
| Discovery or retained/default selected: NotYet, ten un-woken polls, woken Filled { count: 2 } | 2 | 0 | 2 |
| Refill: same sequence | 2 | 16 | 2 |
| Discovery or selected: callback error, or Filled rejected by post-callback cancellation/change | 0 | 0 | 1 |
| Refill: callback error, or Filled rejected by post-callback cancellation/change | 0 | 8 | 1 |
| Discovery/selected: validated Hole { len: 3 } | 3 | 0 | 1 |
| Refill: validated Hole { len: 3 } | 3 | 8 | 1 |

Counters above exclude admission/setup and unrelated operations. NotYet contributes zero SourceBytes; each actual Refill attempt contributes eight VerifyBytes. Ten un-woken polls add zero SourceBytes, VerifyBytes and source callbacks/info checks. H1 does not change final PublicationAuthority checks, supply_verification_source scope, recovery_closed priority, abort_replacement_reads failure behavior, original admission history or Artifact sticky failures.

## Execution environment and commands

Root supplies **private** `CARGO_HOME`, **private new** `CARGO_TARGET_DIR`, and `ZIPFAST_RUST100_BIN` pointing to the exact Rust 1.100.0 toolchain bin directory. Set `PATH="$ZIPFAST_RUST100_BIN:$PATH"`; verify `rustc --version` is 1.100.0 before the first test. Do not use or seed from global Cargo caches. Root prepares a private clone of its owned cache seed only after source grant; this plan does not authorize copying/preparing it. The new target directory has a root-assigned disk budget and is not an old evidence target.

For every command below, retain this environment and run from repository root. Cargo test commands use `--offline --locked --jobs 3`; do not retry by enabling network or increasing jobs. Missing cache/toolchain or exceeded disk budget is a root escalation, not authorization to mutate global state. Do not run all-target baseline tests before RED: qualified base evidence already exists.

## Task 1: Retain and revisit admitted originals without changing legacy mode

**Files:** Modify `src/progressive/source.rs` and `src/progressive/source/tests.rs`; create `src/progressive/source/retained.rs` and `src/progressive/source/retained_tests.rs`.

**Interfaces:** Consumes existing SourceDriver new/select/poll, SourceInfo, SourceStep, Usage and NativeProtection contracts. Produces `new_retained`, `OriginalSource`, optional `RetainedOriginals`, retained-mode selection/high-water behavior and correct aggregate counts described above. No read lease methods yet.

- [ ] Write first-party RED tests `retained_revisit_keeps_owner_and_high_water`, `retained_live_info_does_not_rewrite_admission`, `retained_nonfile_and_replacement_object_limit`, `retained_native_counts_before_clone`, `retained_rejected_candidate_drops_once` and `legacy_selection_still_drops_and_matches_counters`. Use exact source IDs 10/11/12 and three 8-byte sources, not archive fixtures. Required assertions:

  ```text
  admit 0, admit 1, revisit 0, select 2 => provider requests [0,1,2], never [0,1,0]
  revisited read_at offsets start at 0; original hole ledger and source object survive
  initial extent 2 -> live extent 8/Final(8): observed_info remains original Advertised(8), extent 2
  source-object limit 2: two non-file originals accepted; third rejected attempted=3 before volume callback
  one original + one replacement uses both object slots; third original/replacement rejected
  two distinct immutable-file originals: four total backing+guard descriptors accepted at limit 4
  next native candidate rejected before clone; existing guard counts unchanged
  failed candidate Drop count=1; retained owners Drop count=0 until final driver drop, then each=1
  default path: old source Drop occurs at select_volume; legacy callback/Usage values unchanged
  duplicate SourceId and wrong retained name are rejected; no provider reacquisition after either
  ```

- [ ] Run `cargo test --offline --locked --jobs 3 --lib progressive::source::retained_tests::`. Expected RED specifically missing `new_retained`/retention behavior; record the compiler/assertion cause, not unrelated environment failure. Do not add stubs solely to get a different failure.
- [ ] Implement the per-source value and optional retention branch in the specified files. Precharge selection moves and fresh selected request gates; preserve old constructors exactly. Keep existing native logic; only pass correct aggregate counts, retaining all admission/protection poison behavior. Implement no parser/public feature.
- [ ] Run the new filter above and `cargo test --offline --locked --jobs 3 --lib progressive::source::tests::`. Expected all pass, including exact existing quota assertions. Check revisit notices precede reads and empty reads do not deliver pending notices. No unbounded allocation or source drop under locks.
- [ ] Inspect diff for only the four granted source/test files, run `cargo fmt --all -- --check`, and commit the working increment with `git add src/progressive/source.rs src/progressive/source/tests.rs src/progressive/source/retained.rs src/progressive/source/retained_tests.rs` then `git commit -m "refactor: retain original progressive sources on opt-in"`. Commit only under root's source/integration grant; no push/PR/release. Deliver test evidence and focused review before Task 2.

## Task 2: Add bounded original read leases with isolated request epochs

**Files:** Modify the same four files; no others.

**Interfaces:** Consumes Task 1 ownership/selection/accounting and existing checked RangeSource semantics. Produces `OriginalReadPurpose`, `OriginalRead`, begin/poll/retire_original_read, the single shared checked range-read helper, and the private cancellation fanout interfaces above. Default source and replacement caller signatures remain unchanged.

- [ ] Add RED tests `retained_read_has_independent_cursor_and_no_reacquisition`, `retained_lease_same_lane_conflicts_without_poison`, `retained_parked_read_needs_its_own_wake`, `retained_stale_wake_cannot_authorize_new_request`, `retained_drop_and_retire_leave_owner_valid`, `retained_read_mutation_and_cancel_poison_before_advance`, `retained_epoch_limit_failure_never_reactivates`, `retained_replacement_guard_regressions`, `retained_callbacks_and_drops_are_lock_free`, `retained_cancel_wakes_all_live_operations`, `retained_cancel_registration_race_and_capacity`, and `retained_accepted_and_attempted_byte_accounting`. Required assertions:

  ```text
  selected volume 1 cursor=3; lease volume 0 at offset=2 reads bytes [2..4]; selected cursor still=3
  second lease of same source and selected read of leased current source => InvalidCapability, no callbacks
  NotYet then 10 polls without wake => exactly one source read; its own wake permits exactly one retry
  old request/retired lease waker cannot retry replacement, selection or new lease's NotYet
  immediate pre-return wake still works; short fill/hole advances exact count; EOF/empty no read callback
  previous Hole then Filled on revisit => SourceChanged; info change during callback rejects before advance
  callback cancellation returns Canceled, cursor unchanged; all later reads closed
  retirement/drop preserves source; new lease uses fresh epoch; failed allocation leaves old token terminal
  non-file cap and native aggregate cap still include leases without double-counting source objects
  two leases A/B parked on distinct task counters + selected provider Wait C, retire fourth lease D
  cancel through a SessionControl clone made before new_retained => A/B/C wake, D does not
  repeat with selected range NotYet instead of provider Wait; all later polls Canceled, no callbacks/advance
  cancel fanout leaves provider ready/wake counters unchanged; preexisting readiness cannot bypass cancellation
  expired/retired slots reclaimed before capacity check; exact owner/hub cap passes, one-over fails pre-callback
  race cancellation during task-Waker clone/registration: task still notified, no lost wake/lock or provider call
  request 8 -> NotYet -> 10 no-wake polls -> woken Filled(2): SourceBytes=2 in every mode
  same sequence: VerifyBytes=16 for Refill/replacement, 0 for Discovery/ordinary selected, read_at calls=2
  callback error or post-callback cancel/change: SourceBytes=0; Refill VerifyBytes=8, others=0
  validated Hole(3): SourceBytes=3; Refill VerifyBytes=8, others=0
  SourceBytes limit=2 accepts the short result despite request 8; limit=1 fails after callback before advance
  Refill VerifyBytes limit=7 fails before first callback; limit=15 permits NotYet but rejects retry before callback
  ```

- [ ] Run `cargo test --offline --locked --jobs 3 --lib progressive::source::retained_tests::`. Expected RED from absent lease interfaces/behavior. Use existing test patterns for failure injection and exact accounting, not sleeping waits.
- [ ] Implement the private opt-in cancellation hub/registrations and lease state, then the minimal shared checked range-read helper. Keep provider acquisition outside the helper; invoke original native guard refresh before retained reads and validate again after callbacks as required. Gate retirement is allocation-free; fresh epoch admission is fully charged before callback. `OriginalRead` Drop touches only its epoch/atomic/gate and cancellation registration; it never accesses a source. Add focused `#[allow(dead_code, reason = "H1 private retained-source entrypoint consumed by H2 persistent output")]` only to otherwise-unused entrypoints/types; H2 must remove each allowance when it adds the consumer.
- [ ] Implement bounded subprocess reentrancy tests using the existing 3-second child watchdog pattern. Exercise custom RawWaker clone/wake/drop hooks, source info/backing/read callbacks and source Drop invoking SessionControl::cancel and a different driver's control/read path. Include fanout wake/drop reentering cancel, registration clone-hook cancellation and retire-before-cancel cases. Assert child exits normally, pending callbacks stay uncalled and every source drops once. No unsafe aliasing of a live mutable driver to fake reentrancy; RawWaker test hooks may use safe owned counters/control handles.
- [ ] Run both source test filters. Run `cargo test --offline --locked --jobs 3 --lib progressive::session::recovery::tests::` to preserve replacement retry retirement, closed recovery, active-extraction conflict and publication checks. Expected all pass. If the source error is genuine, fail closed; do not “fix” old tests by dropping guards or reducing assertions.
- [ ] Run focused existing integration: `cargo test --offline --locked --jobs 3 --test progressive_holes --test progressive_output --test progressive_rar --test progressive_rar4 --test progressive_rar4_compressed`. This is protocol/regression work on existing small fixtures, not permission for the 500 MB acceptance binary or a native/oracle campaign.
- [ ] Inspect production diff for H1 scope and absence of default new allocations/callbacks; run fmt check and commit with `git add` of the four explicit files then `git commit -m "feat: add bounded retained-source read leases"`. No push/PR/release; provide evidence for scoped review.

## Final H1 verification and handoff

After both task reviews/fixes, run these final private Mac checks **once**, with the granted environment (repeat only on relevant fixes/failures):

```sh
cargo fmt --all -- --check
cargo clippy --offline --workspace --all-targets --locked --jobs 3 -- -D warnings
cargo test --offline --workspace --all-targets --locked --jobs 3
cargo test --offline --workspace --doc --locked --jobs 3
```

Keep existing ignored 500 MB acceptance preparation/runs ignored; never add `--ignored` or `--include-ignored` to these commands. Only root may grant focused Linux native-source/regression execution. Do not add local audit/fuzz downloads or new broad campaign work. Root later handles exact-head hosted CI/review and release gates when the public consumer exists. Record current SHA, environment, commands/results and unchanged Cargo/default API in task evidence; report retained objects/descriptor peaks from exact small tests as accounting evidence, not process RSS promises. Preserve all prior proof.

## Self-review and deferred coverage

- [x] Spec coverage: H1 owns only design §§4/9/10 retained-source foundation; H2–H5/R1 explicitly own persistent files, hole events, discovery/parser geometry, repair, extras and resume. All nine acceptance cases remain in the full design; H1 claims none completed.
- [x] Step scan: two useful testable tasks, each RED→minimal implementation→GREEN→reviewable commit; no setup-only task or implementation method bodies.
- [x] Type consistency: SourceDriver remains owner; OriginalRead borrows it only during polls and owns no source; source lease state is distinct from immutable admission/live info and selected high-water.
- [x] Review Focus: every listed condition maps to named assertions above, including candidate Drop, non-file counts, revisit high-water, stale wake, independent-task cancellation fanout and callback lock boundaries; exact accepted/attempted byte matrix is pinned in Task 2.
- [x] Proportion: only per-source state and range-read factor; no wholesale registry/parser rewrite. All public API and dependency decisions remain deferred to their finite named consumer plans.

No architecture question remains for the H1 owner beyond ordinary implementation details. Any necessary exception to the exact production file/scope boundary goes to root before code. Root's fresh builder check may revise this plan before source grant; no implementation is authorized by documentation preparation alone.
