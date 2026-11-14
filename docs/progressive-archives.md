# Progressive RAR5 sessions

`zipfast::progressive::ProgressiveSession` owns a `VolumeSource` and
`ProgressiveOptions`. Call `poll_event` with your current task context until it
returns `Ready(Ok(None))`. Events are delivered once, one per poll. The session
is `Send`; polling is serialized by its mutable borrow. No runtime is required.

`VolumeSource::volume` runs for every volume, including zero. `Wait` and
`RangeSource::read_at`'s `NotYet` must arrange a wake using the supplied context.
An unchanged parked session does not retry providers. A wake during the provider
call is retained. The engine separately self-wakes when its packed-work budget
requires a scheduling yield. The context is never retained; only its owned
waker is registered. `SessionControl::cancel()` wakes a parked session.

`SourceInfo::extent` is an addressable span, not a downloaded prefix. Availability
belongs to each range answer. The driver checks identity, generation, length,
and immutable native-file bindings. The session retains partial header, CBC,
decoder, packed-check, and inner-check state across waits and volume boundaries.
RAR5 CBC continuation does not restart at a new volume.

`MemberStarted::name` shares the physical model's raw-name allocation through
`Arc<Vec<u8>>`. It is not a lossy decoded pathname. Member identities include a
checked process-session nonce and an ordinal; exhaustion fails without wrapping.

## Output and evidence

Output is staged under a pinned destination directory. `MemberFinished` with
`Verified` means publication actually succeeded. Whole-source-set authority is
required in addition to successful size and checksum checks. Arbitrary providers
with opaque or non-file declarations receive `Provisional(Artifact)`, even when
its evidence is `Verified` at `VerificationLevel::Strict`.

`from_sealed_memory` takes ownership of the complete bounded set of named byte
buffers. Its private backend can establish memory publication authority. A
custom provider cannot claim that authority through a protection declaration.
Native inventories reserve future volume names and aliases before output can
replace any target. Retained original immutable stamps remain checked after
volume switches and before publication.

`Verification` exposes the exact-size verdict, CRC32 and BLAKE2sp verdicts,
provenance, packed evidence, authentication evidence, and level. A declared
checksum failure never becomes missing evidence. A member without a whole-inner
checksum remains provisional. RAR CBC checks are reported as `CbcChecksOnly`,
not authenticated-encryption evidence.

Artifacts own their private descriptors and cleanup/quota leases. Use
`Artifact::read_at` to read valid produced bytes, including a stopped or canceled
prefix. Artifacts remain readable and discardable after their session is dropped.
`discard` confirms cleanup and releases a slot; drop attempts guarded cleanup.
At the retained-artifact limit the session emits one `CapacityNeeded`, then
parks without further reads until a slot is released or cancellation occurs.

A fatal failure after any stage was created is delivered exactly once as
`SessionTerminated`; pre-stage failures use `Err`. `RetainProvisional` transfers
the active artifact. `Remove` removes it, except that a cleanup failure returns
both the artifact and the separate cleanup error. Delivered artifacts are never
reclaimed by cancellation or session drop. A stopped member carries its retained
prefix under the same aftermath policy. Cleanup failure makes that stop terminal.

## Test, Skip, metadata and solid policy

`extract::Mode::Test` uses the same framing, cipher, decoder and declared
integrity checks without constructing an output context or touching the
destination. `Tested(TestEvidence)` reports actual bytes and individual size,
CRC32, BLAKE2sp, packed and authentication verdicts; absent optional checks remain
`Missing`, and the checksum accessor returns `None` when no checksum was
provided. Tested is never a publication result. Discarded/tested bytes produce
no `BytesWritten` event.

`Overwrite::Skip` reports `Skipped(ExistingTarget)` after checking the bound
safe target and source identities; existing bytes, timestamps and permissions
are preserved. Independent skipped payloads are traversed without decoding or
checksum claims. Compressed skipped predecessors in a solid archive are decoded
and checked to retain required history. Older archive versions follow the
complete extractor's skip policy. Skip avoids temporary files and artifact
capacity parking; Extract construction still requires nonzero output/artifact
capacity. A changed target, protected input alias or symlink fails closed.

Basic zero-payload, nonsplit directories produce `Directory { created }`.
`created: false` includes existing directories and Test/flatten entries; it
claims neither checksum verification nor successful metadata restoration.
Directory mutation requires whole-source-set authority. An otherwise valid
opaque-provider directory reports a member-local `Stopped` with
`PublicationAuthorityRequired`; independent successors can continue. Existing
regular files and symlinks are never removed to make directories.

Regular-file metadata is applied best effort through the original staging
descriptor **after** atomic publication and before that descriptor closes.
The brief final-name-at-0600 interval is intentional: provisional artifacts and
failed publication stages remain 0600. The existing complete-path metadata
helper restores ordinary timestamps and modes masked to 0777, including zero
mode; it does not restore ownership, set-id or sticky bits. There is no atomic
metadata/durability guarantee. A published file whose staging-name cleanup fails
reports `PublishedWithFailure`, explicitly carrying its verification and the
primary failure. An optional artifact owns only the leftover staging name;
discarding it cannot remove the final target. That event is terminal and emitted
once. Pending directory metadata is skipped after this published failure.

Directory metadata is queued with bounded paths and native identities, then
restored deepest-first through newly opened nofollow descriptors checked against
those identities. The last repeated directory header wins. Normal EOF and
noncancel termination attempt this once; unsafe replacement is never mutated.
OS metadata errors are best effort, while binding/protection failures remain
errors. Cancellation skips pending directory metadata; already-created
directories keep their current metadata. Drop never performs another pass.

RAR5 solid streams reuse the complete extractor's serial decoder preparation
primitives and the canonical `MemberMachine`/`Unpacker`. Clean decoded history
survives stored/directory interleaving and test/skip predecessors. All declared
checks must pass; missing optional checks do not poison history, and successors
retain their own independent evidence. Actual decode/check/hole failure invalidates
history. A final-part compressed failure in a solid archive can stop that member,
refuse dependent members and resume a proven independent reset. Split failures
without a safe boundary and existing independent-member integrity failures remain
terminal. No byte scanning invents a reset point.

All redirection kinds remain typed `RarUnsupported::Redirection { kind }`, as in
the complete extractor; this entrypoint creates no links. RAR4 codecs, repair,
hole filling, patching, recovered publication and other formats remain outside
this entrypoint's supported scope. Full original compatibility remains open.

## Limits

Limits retain the documented finite defaults in `ProgressiveLimits`, including
1 MiB read/packed-work chunks, 16 retained artifacts, 128 MiB metadata, 256 MiB
decoder windows and 64 GiB source/output/verification budgets. Test and passive
solid decoding charge decoded bytes to cumulative `LogicalOutputBytes`, but do
not charge nonexistent temporary extent, output writes or physical verification
reads. Extracted stages continue to charge logical extent and temporary bytes
together. Test permits zero output/artifact/temp/write capacities. Optional
physical artifact reads still charge `VerifyBytes`; hashing bytes already flowing
through the decoder is not a second physical read.

Directory queue capacity/path storage and sorting work use existing finite
metadata/name/bookkeeping budgets; no descriptor is retained per directory.
Sealed memory charges retained bytes and inventory before acceptance. Source
bookkeeping and provider requests remain separate cumulative budgets. KDF work
uses the shared controlled meter and cumulative session budget. Limits bound
engine work and retained allocation, not operating-system RSS or free disk space.
