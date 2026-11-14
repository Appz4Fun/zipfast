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

## Current scope and limits

This entrypoint supports RAR5 complete-byte extraction and real availability
waits, including encrypted headers/data and split members. It consumes the same
framing, physical model, crypto, and decoder producers as complete extraction.
It rejects unsupported codecs, solid-member lifecycle, RAR4, and other formats;
it does not implement directory/redirection creation, archive timestamp/mode
restoration, repair, hole filling, patching, or recovered publication. Published
regular files retain the staging file metadata.
A data hole ends the active member or session; it never produces valid missing
bytes. Later independent members can follow a stopped final part.

`extract::Mode::Test` is currently rejected at construction as
`UnsupportedMethod`, before providers or output are touched. Use the existing
complete-file test API. With `Overwrite::Skip`, an existing target remains
untouched but this new entrypoint currently reports a typed `AlreadyExists`
output failure instead of a legacy skip outcome. These policy-integration gaps
remain open; legacy complete-file behavior is unchanged.

Limits retain the documented finite defaults in `ProgressiveLimits`, including
1 MiB read/packed-work chunks, 16 retained artifacts, 128 MiB metadata, and 64 GiB
source/output/verification budgets. Sealed memory charges its retained bytes and
inventory against metadata before acceptance. Source bookkeeping and provider
requests are separate cumulative budgets. Zero artifact/output capacity fails
as a typed limit instead of creating an unwakeable park. KDF work uses the shared
controlled meter and configurable cumulative session budget. Limits bound engine
work and retained allocation, not operating-system RSS or free disk space.
