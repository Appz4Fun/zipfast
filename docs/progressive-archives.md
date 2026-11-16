# Progressive RAR sessions

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

For sets that are still being downloaded, the library-owned `GrowingFileVolumes`
provider waits for absent volumes, answers `NotYet` past each file's current end,
and grows a Complete native inventory as volumes appear, so verified members
still publish Strict. See `docs/growing-volumes.md`.

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

The rename modes (`Overwrite::RenameNew`, `Overwrite::RenameExisting`) are
refused at construction with `FailureKind::InvalidCapability`, before any
source or output is touched; a session binds its publication names ahead of time.

`Overwrite::Skip` reports `Skipped(ExistingTarget)` after checking the bound
safe target and source identities; existing bytes, timestamps and permissions
are preserved. Independent skipped payloads are traversed without decoding or
checksum claims. Compressed skipped predecessors in a solid archive are decoded
and checked to retain required history. Older archive versions follow the
complete extractor's skip policy. Skip avoids temporary files and artifact
capacity parking; Extract construction still requires nonzero output/artifact
capacity. A changed target, protected input alias or symlink fails closed.

Basic zero-payload, nonsplit directories produce `Directory { created, deferred }`.
`created: false` includes existing directories and Test/flatten entries; it
claims neither checksum verification nor successful metadata restoration.
Directory mutation requires whole-source-set authority. An otherwise valid
opaque-provider directory creates nothing and reports
`Directory { created: false, deferred: Some(path) }`, where `path` is the
sanitized target relative to (and contained in) the destination root, for the
caller to create itself; the session goes on with the next member. Existing
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
those identities. Root, parent and leaf bindings are rechecked after the provider
authorization callback. The last repeated directory header wins. Normal EOF and
noncancel termination attempt this once; unsafe replacement is never mutated.
OS metadata errors are best effort, while binding/protection failures remain
errors. On termination, active-stage cleanup runs first. If removal fails, the
primary failure, removal error and owned leftover artifact are returned; pending
directory metadata is drained and skipped without callbacks or mutations. If
stage cleanup succeeds (or the stage is retained without a cleanup error), the
directory pass may run and its failure is returned as the cleanup error.
Cancellation also skips pending directory metadata; already-created directories
keep their current metadata. Drop never performs another pass.

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
the complete extractor; this entrypoint creates no links. Stored recovery is
available for the admitted RAR4 and RAR5 subsets below. Full original
compatibility remains open.

## RAR4 capability boundary

| Progressive RAR4 case | Current admission |
| --- | --- |
| Plain Stored, unpack version 20 or 29 | Supported with declared size and CRC32 checks. |
| Plain split Stored | Supported with exact raw-name/method/version/dictionary continuity, nonfinal packed-part CRC32 and final whole-inner CRC32. |
| Plain Stored holes and patching | Shared sparse/zero holes, bounded patching and whole-inner read-back verification; wrong patches and failed declared checks stay failed. |
| Directory records carrying the payload-encryption flag | Typed unsupported, including salt-present records; checked before every disposition. |
| Modern version-29 AES Stored payload, including split parts | Admitted with explicit salt, known size, and unchanged data salt across parts; continuous CBC. |
| Salt-prefixed AES encrypted headers | Admitted incrementally; each header derives its own IV. Explicit alternate header encryption versions remain unsupported. |
| Plain version-29 independent LZ, raw methods 0x31..0x35 | Supported with known size, one physical part, and a 64 KiB–4 MiB dictionary. Independent members may occur in a forward volume set. |
| Split or solid compressed payload, compressed AES, compressed payload under encrypted headers | Typed unsupported before dispositions/output; separately qualified geometry and continuation remain required. |
| RAR1.5/2 compressed payload, PPM and VM | Typed unsupported; original engines and independent positive fixtures remain required work. |
| Ambiguous/unknown RAR4 unpacked size, old revisions, special file types | Typed unsupported. |

RAR4 framing uses the same incremental producer for `Volume`, catalogue
and progressive reads. Header waits retain exact parser state and raw encoded
names; a header hole stops with `HeaderHole`. A set cannot switch archive format
between volumes. The complete-file API retains its existing payload admission
policy, including its split/encryption refusals; this table describes progressive
admission only. No codec state is exposed as a verified restart point.

Stored and independent LZ support are increments, not completion of RAR4 or the full archive
request. Independent LZ owns an exact canonical frame and checks all packed bytes,
output size, declared CRC and source state before success. Its logical codec finish
proves no solid boundary and grants no reusable history or restart capability.
Compressed holes stop with the actual decoded prefix and no restart; they never
enter Stored sparse recovery. The core observes the session cancellation token
within decoding; dictionary and output limits remain finite.

The 500,000,000-byte, ten-volume article-loss acceptance remains required
separate correctness qualification.

## Stored holes and repair

Opt in with `HolePolicy::PartialStored { fill: HoleFill::Sparse }` or `Zero`.
The default remains `Fail`. A permanent source hole in a stored member advances
its logical output position, keeps the range invalid, and continues. `Partial`
owns the private artifact; no final target is published. `holes()` returns the
sorted, disjoint, adjacent-coalesced inner-file intervals, and `produced_extent()`
is the logical extent, including holes. `BytesWritten.valid_bytes` counts only
actual valid output. Sparse and zero filling have identical validity and exact
final size; zero writes proceed in bounded, cancelable poll steps.

Plain store maps packed holes directly to inner offsets. CBC loss rounds to
cipher blocks and also invalidates the following plaintext block in that same
chain. Losing ciphertext `[17,18)` or `[16,32)` invalidates inner `[16,48)`.
The first available block after a loss supplies only the next block's IV.
RAR5 volume boundaries never reset the chain. Taint is clipped to declared inner
size and genuine new-member IV boundaries. Losing a ciphertext byte corresponding
to padding still taints the last affected plaintext block. After plaintext repair,
missing ciphertext evidence remains missing. RAR5 stored padding is less than one
block; a whole extra padding block is malformed, not a recoverable padding-only
extent. A nonaligned final ciphertext extent fails its framing check.

If encrypted stored plaintext size is unknown when a hole arrives, recovery
stops with `DataHole` at the committed prefix. It does not guess padding geometry.
Plain store may reconcile an initially unknown size with a real final declaration.
Header holes are `HeaderHole`. Compressed holes remain stopped prefixes with
invalidated dependent solid history; they are not patchable stored artifacts.

`session.patch(&mut artifact, offset, bytes)` accepts one nonempty range wholly
inside a current coalesced hole, within the declared inner size and read-chunk
limit (at most 1 MiB). It rejects valid-byte overwrite, foreign/closed/published
artifacts, overflow, changed staging identity, and canceled/dropped sessions.
It reserves interval-split capacity before writing. The entire call is one
validity commit: short writes may be retried, but a final error leaves the whole
attempted range invalid, even if some bytes physically changed. Error context
reports the attempted range and completed physical byte count. Retry only the
still-invalid range. A successful wrong patch is validly written data whose
checksum can fail; this API does not grant arbitrary overwrite afterward.

```rust,ignore
for hole in artifact.holes().to_vec() {
    // Fetch the corresponding trusted donor bytes, then use bounded chunks.
    for (offset, bytes) in donor_chunks(hole.offset, hole.len) {
        session.patch(&mut artifact, offset, &bytes)?;
    }
}
// Poll with the caller's current Context until Ready, respecting Pending/wakes.
let verdict = poll_until_ready(|cx| session.poll_verify(&mut artifact, cx))?;
```

## Full verification and publication policy

`poll_verify` scans the whole private stage in bounded chunks, including exact
size, every declared CRC32/BLAKE2sp check and private keyed RAR checks. Nonempty
holes return `IncompleteOutput`. Plain stored packed checks are recomputed for
every corresponding part during that same stage scan. Encrypted plaintext repair
cannot reconstruct original ciphertext or padding evidence: it yields `InnerOnly`
and `PackedEvidence::Missing`, with `CbcChecksOnly` authentication evidence.
A declared failed check is never downgraded to Missing and cannot be overridden
by a caller digest. A member with no whole-inner digest yields `Unverified`,
`checksum() == None` and provisional artifact evidence; absence of a checksum
never proves a password.

An actual declared checksum mismatch permanently marks this artifact Failed,
including a mistaken caller expectation. Correcting expectation metadata cannot
rehabilitate that artifact; the caller must restart recovery with a new artifact.
Separating caller-metadata correction from sticky archive failures is a future
compatibility extension, not supported by this initial policy.

A caller can provide `ExpectedInner::Crc32 { digest, label }` or `Blake2sp` using
`set_expected_inner(&artifact, expected)`. Labels are limited to 1024 UTF-8 bytes.
Caller digests compare raw plaintext; archive keyed checks remain separate.
`caller_expected()` retains every successfully checked caller digest and label,
including when archive evidence remains the primary verdict origin. When caller
evidence supplies the missing whole-inner digest, the verdict records
`EvidenceOrigin::Caller` with its label, never Archive. Updating expectations
invalidates previous evidence. `Artifact::evidence()` returns an owned snapshot;
old snapshots are observations and cannot authorize publication.

Output changes, expectations and supplied-source generations invalidate current
verification jobs/permits. Each new attempt rescans the stage. Jobs are bound to
the originating session/member/output, exact descriptor stamp/extent, output and
expectation generation, and replacement revision. Only one verification job runs
per session. While it runs or is parked, conflicting event polling or verification
of another artifact returns `InvalidCapability` without consuming the original
job. Verification and explicit recovered publication also reject an active or
parked extraction operation until its current member reaches a terminal event;
that conflict preserves both the extraction state and the retained artifact.
A parked verification poll invokes no provider callbacks or source-request debits
without readiness, while updating the task waker and checking cancellation.
Cancellation wakes the registered caller. Patching or changing expectations
for that artifact, or supplying a new replacement generation, abandons its job;
retained sources keep their identities and permanent-hole history, and old request
wakers cannot authorize a later request.

With `RecoveryPublication::VerifiedInner`, call `publish_recovered(&mut artifact)`
explicitly after a current InnerOnly success. It still requires original
whole-source-set publication authority and safe source/target bindings. Missing
packed evidence is permitted; Failed evidence is not. The published receipt keeps
InnerOnly, its provenance, Missing packed evidence and CbcChecksOnly. Without
publication authority the method returns `PublicationAuthorityRequired` and keeps
the owned artifact. The default Strict policy does not permit this transition.

A successful Strict `poll_verify` may publish through the same checked publisher.
Successful content verification can still leave an authority-less artifact
unpublished. Check `artifact.publication()` for the actual `Unpublished`, `Strict`
or `RecoveredInner` receipt. Successful publication retires the staging descriptor
and releases capacity; the receipt/evidence remain readable, while `read_at`,
patch and reverify return `InvalidCapability`. They never reopen the final path.
A post-publication staging-name cleanup error returns typed `Output(Remove)` with
an already-published receipt. The artifact then owns only leftover-stage cleanup;
`discard`/drop cannot remove the final target. That error closes further session
mutation. Metadata is applied through the original descriptor only after actual
publication, preserving provisional mode 0600.

## Promoting an Opaque set to Complete

A provider that cannot name its files up front (obfuscated posts, names learned
from par2 later) may start `Opaque` and promote the set once it is final: its
next `protection()` answer is simply `Complete`. There is no separate call. The
session asks for the declaration at every volume admission, member boundary and
publication check, and adopts the promotion at the first of these. Every source
admitted while Opaque must then be one of the files the declaration names for
its volume (same device and inode as a declared handle), and every admitted
name must be declared; members finished after the promotion can publish Strict.

A volume the session already read may have been replaced on disk by then with a
new inode: a par2 repair renamed over it, or the provider fell back to a backup
copy. Its bytes came from a file the declaration no longer names, so the
promotion is declined rather than failing the session: the session stays Opaque,
keeps extracting, and finishes members as `Provisional` (no Strict publication
authority). The same epoch is not retried; a declaration with a higher epoch is.
A promotion whose inventory leaves out an admitted name is still a
`SourceContract` failure. Sources served as `ImmutableFileSource` treat any
replacement of their path as `SourceChanged` regardless, so serve volumes that
may be repaired in place through a caller-provided `RangeSource`.

## Strict encrypted replacement evidence

For strict verification of repaired encrypted store, supply explicit new sources
with `supply_verification_source(volume_index, source)`. The indices returned by
`artifact.required_verification_volumes()` are all member-part volumes whose
original framing must be proved, including otherwise undamaged parts. The engine
does not retain/reacquire all original download providers or mutate their hole
generations. Replacement identity/generation/declared length are frozen within
this separate verification generation; available bytes remain immutable under the
provider contract. Missing replacements leave InnerOnly evidence.

The same checked source machinery handles NotYet, wakes, identity, ranges,
cancellation and finite budgets in independent verification lanes. Replacement
framing is checked against retained bounded wire witnesses, including signatures,
encrypted header IV/ciphertext and unknown fields, then reparsed with the canonical
header parser. The canonical member machine rechecks all packed parts, complete
cipher/padding geometry, final checks, and compares all replacement plaintext with
the repaired stage. It does not extract a second output or decode unrelated earlier
members. `Verification::replacement_revision()` identifies the explicit generation
that established Passed packed evidence; the missing original ciphertext has not
silently become available.

Publication still requires the original whole-set authority and protection of
**every** supplied replacement input. **Use `ImmutableFileSource` for every
replacement lane that should be able to publish:** it is the only source type
that authorizes publication, and the session recognises it by its concrete type,
so a wrapper around it does not. A single lane from any other source keeps the
artifact `Unpublished` even when verification reaches `Strict`. Initial replacement publication supports
actual `ImmutableFileSource` native adapters, with retained path/descriptor/stamp
checks and alias protection. Custom opaque or claimed native/non-file replacement
providers can establish cooperative content evidence but remain unpublished,
including if recovered publication is later requested. No replacement can remove
original immutable bindings or reserved future-volume paths. Library-owned sealed
replacement memory is not provided by this initial API.

This RAR recovery path does not enable WinZip AES holes. Future ZIP integration
must require complete global authentication before plaintext access; CBC format
checks are not authenticated encryption.

## Limits

Limits retain the documented finite defaults in `ProgressiveLimits`, including
1 MiB read/packed-work chunks, 16 retained artifacts, 128 MiB metadata, 256 MiB
decoder windows and 64 GiB source/output/verification budgets. Test and passive
solid decoding charge decoded bytes to cumulative `LogicalOutputBytes`, but do
not charge nonexistent temporary extent, output writes or physical verification
reads. Extracted stages continue to charge logical extent and temporary bytes
together. Test permits zero output/artifact/temp/write capacities. Optional
artifact reads still charge `VerifyBytes`; reporting a Hole does not. Verification
charges attempted stage/replacement read spans, including failed attempts and
provider retries. In-memory hashing is not a physical read. `VerifyWorkBytes`
(default 64 GiB) separately bounds byte-span processing passes, not exact CPU
instructions or time. Combined fixed hash/decrypt/compare work may charge a span
once; distinct rescans/replays charge again. SourceBytes counts source spans
(including reported holes), SourceRequests counts callbacks, and these counters
are not a sum claiming measured disk traffic.

Directory queue capacity/path storage and sorting work use existing finite
metadata/name/bookkeeping budgets; no descriptor is retained per directory.
Sealed memory charges retained bytes and inventory before acceptance. Source
bookkeeping and provider requests remain separate cumulative budgets. KDF work
uses the shared controlled meter and cumulative session budget. Limits bound
engine work and retained allocation, not operating-system RSS or free disk space.


Modern RAR4 Stored AES uses the same progressive session for visible and encrypted
headers. The admitted encrypted payload family has unpack version 29, an explicit
eight-byte salt, a known whole-member size, and the same data salt on all split
parts. Cipher blocks and availability taint continue across physical part and
volume boundaries, including boundaries inside a block. Each encrypted header
instead starts its own salt-derived IV. Different split data salts and older
crypto schemes are refused; they are not interpreted as IV reset instructions.
Trailing AES padding is clipped by the declared size (at most 15 bytes), without
requiring zero padding. Compressed AES/solid RAR4 and other legacy codec families
remain outside this encrypted increment.

RAR4 has no explicit password verifier. A missing password is reported separately;
plaintext-dependent checksum or framing failure after decryption remains ambiguous
between a wrong password and damaged ciphertext. Successful CBC checks are
`CbcChecksOnly`, not authentication. Legacy data does not use RAR5 keyed checksum
tweaks. Strict replacement replay binds the original salt and complete physical
header extent, including encrypted header padding.

Progressive RAR4 key derivation checks password bounds before allocating its UTF-16LE
buffer (4096 UTF-8 bytes and 8192 encoded bytes, or configured stricter limits).
It charges actual SHA-1 compressions, including all IV snapshot finalizations and
final key padding, before the primitive. The independent ceilings are 2^22 blocks
per derivation and a default 2^26 per session; a permitted long password can still
reach a work limit. Such exhaustion is a resource failure, not a password verdict.
The existing public unrestricted crypto helper retains its previous behavior.
