# Checked encrypted ZIP reads

The additive checked reader streams Stored, Deflate, Bzip2, ZIP LZMA, XZ and Zstandard members. It supports ZipCrypto and WinZip AES-128/192/256, AE-1 and AE-2. AES verifies the complete ciphertext authentication tag in an owned snapshot before constructing the decoder, decrypting or invoking a plaintext callback. ZipCrypto's password header is weak evidence; it does not authenticate the payload. AE-1 requires the ZIP CRC; AE-2 uses its authentication tag and ignores the wire CRC. Every supported codec must finish exactly at the declared packed and decoded boundaries under its format's permitted termination rules.

Existing `Archive::read_at`, consuming selected reads, `run` and `run_with_password` preserve the 128 MiB packed encrypted-member ceiling. Their signatures and `extract::Options` literals remain compatible. The ordinary command uses the checked policy path. Applications opt into checked reads with `EncryptedReadContext` and the methods below.

## Required output and temporary storage

The default checked CLI intentionally restricts ZIP extraction storage, including **clear, unencrypted members**. Destination storage must be ownership-enforced **local APFS on macOS**, or an admitted **ext-family, XFS, Btrfs or tmpfs filesystem on Linux**. Linux also requires the implemented trusted procfs descriptor view and native ACL facilities. The ownership, privacy and other native-capability checks still apply on these filesystems.

Extraction fails closed on unlisted destinations: common examples are Linux overlayfs/container root filesystems, network mounts, exFAT and macOS HFS+. Use a supported mounted destination. Large encrypted snapshots also need supported temporary storage; set `ZIPFAST_ZIP_TEMP_DIR` to an appropriate mounted location when needed. A supported temporary directory does not make an unsupported destination usable. Permission changes do not add a filesystem to the allowlist. There is no silent fallback to legacy extraction or weaker staging.

Physical qualification currently covers macOS APFS and Linux ext4, Btrfs and tmpfs. XFS is admitted by the code but has **not** been physically qualified in this campaign; other ext variants are not claimed tested. This milestone sacrifices extraction compatibility on previously usable unlisted storage. The full filesystem compatibility goal remains open. Carry this restriction into release and consumer adoption; see [release/adoption notes](zip-checked-release-notes.md).

## Read one original catalogue entry

```rust
use zipfast::extract::Cancellation;
use zipfast::zip::{EncryptedReadContext, EncryptedReadOverrides,
    ProjectedReadScope, ProjectedReadSession, ZipReadOutput};

let cancel = Cancellation::default();
let mut session = ProjectedReadSession::open(path, &cancel)?;
let mut context = EncryptedReadContext::for_projected(
    &mut session, ProjectedReadScope::Entry(ordinal), None,
    ZipReadOutput::Callback, password, &EncryptedReadOverrides::default(), &cancel,
)?;
session.read_at_with_context(ordinal, password, u64::MAX, &cancel,
    &mut context, |bytes| { /* consume provisional bytes */ Ok(()) })?;
session.check_source(&mut context)?;
```

`ProjectedReadSession` retains one original projection, file and source binding. `ReadSession` retains canonical metadata and stable `EntryId`s; use `EncryptedReadContext::for_session` before selecting its original ID and calling `SelectedZipEntry::read_with_context`. The generic `SelectedEntry::open_cancelable_with_zip_limit`, `zip_read_context` and `read_with_zip_context` use the same checked engine for ZIP. The original source stays held through final checks. A foreign ID, different owner, consumed action or altered source invalidates the attempt. Create a fresh action context for every retry; failed attempts spend cumulative work and I/O allowances.

For generic archive discovery on macOS and Linux, use
`extract::inspect_projected_cancelable(path, password, &cancel)`. Match the
non-exhaustive `extract::ProjectedInspection`: `Zip(session)` supplies the same
projected session used above, while `Other(entries)` supplies the incumbent
non-ZIP listing. Handle future variants when matching outside the crate. The
ZIP case moves one original source/catalogue and includes actual dispatch bytes
in the cumulative 129 MiB dispatch/parser allowance; it does not reopen ZIP or
create retained metadata first. ZIP/TAR head signatures win, then bounded RAR
recognition precedes a ZIP attempt. A recognized format's errors are terminal,
including RAR initializer, password, member and later-volume failures.

The inspection password decrypts RAR headers; ZIP reads receive their payload
password separately. TAR listing keeps its pathname reopen after checked source
retirement, and later non-ZIP selection keeps its existing reopen/legacy scope.
The successful returned ZIP session keeps its ordinary file-drop lifecycle;
inspection adds no explicit successful-close receipt or close-error API.
Constructor failures and TAR retirement retain existing checked cleanup
evidence. This entry point is not exposed on other platforms.

Callbacks are provisional until the full read returns success. AES authentication alone does not prove codec completion, decoded length, CRC where required, source stability or publication. A caller that publishes callback bytes directly accepts those later failure outcomes. Raw callback writes, caller allocations, arbitrary external operations and native codec allocations are outside Rust reader capacity accounting. Use controlled output for publication requirements.

## One final selected-operation diagnostic

On macOS/Linux, prepare one checked completion sink immediately after the
original action-context factory, before payload FD admission, source checks,
staging or decoding. Use `ProjectedReadSession::prepare_diagnostics(ordinal, ...)`,
`ReadSession::prepare_diagnostics(&original_id, ...)`, or
`SelectedEntry::prepare_zip_diagnostics(...)`. The generic selection returns
`None` for its incumbent non-ZIP scope. Keep the same owner, context, immutable
options and actual output handle through its matching `emit_diagnostic` or
`emit_zip_diagnostic` call. `Mode::Test` options accompany callback/discard/stdout
actions; staged-file actions require their original `Mode::Extract` options and
destination. A prepared token cannot be cloned or emitted twice.

For example, with the original projected session and a fresh callback context:

```rust
let token = session.prepare_diagnostics(
    ordinal, &options, &cancel, &mut context,
    zipfast::zip::ZipDiagnosticSink::Stderr, &stderr,
)?;
let operation = session.read_at_with_context(
    ordinal, password, u64::MAX, &cancel, &mut context,
    |bytes| { /* consume provisional bytes */ Ok(()) },
).and_then(|()| session.check_source(&mut context)).map(|()| true);
let (value, error, diagnostic_usage) = session.emit_diagnostic(
    token, &mut context, operation, &mut stderr,
    |operation, status, writer| writer.write_fmt(format_args!(
        "ZIP completion: {}\n",
        if status.is_fatal() { "source unavailable" }
        else { match operation { Ok(true) => "complete", Ok(false) => "skipped", Err(_) => "failed" } },
    )),
).into_parts();
// Inspect BOTH value and error before choosing the application's final status.
```

`Some(value)` is the actual successful operation/publication or legitimate skip
receipt, even if `error` is also `Some` because final diagnostics failed. Record
that completed operation before reporting the diagnostic failure; it cannot be
rolled back. `None` plus an error retains the original failed operation with
new checked evidence merged. The carrier never returns `None, None`. Successful
operation values move without cloning; there is only one inline error slot.
A diagnostic-only error after success has `Unknown` publication disposition;
the preserved operation value holds its actual publication/accepted-byte result.

Admission checks regular log files against the held source, selected output and
protected targets. Actual payload stdout FD admission also refuses a prepared
regular diagnostic alias and latches that refusal before staging or copying;
the completion renderer cannot then write into that same payload file. Pipes,
sockets, TTYs and the exact native null device may be shared. The classifier
recognizes only macOS character device 3:2 and Linux 1:3 as null, using its
existing descriptor observation; other non-TTY character devices remain refused.
Descriptor/source/target observations are repeated at final rendering. Regular
sinks also recheck every current protected name before and after emission,
following symlinks and using the original frozen CWD for relative names in both
Test and Extract modes. Stable substitutions before emission refuse rendering;
a substitution observed after writing retains the actual accepted-byte receipt.
These bounded observations do not make namespace changes inside an unobservable
syscall or write interval atomic. The checked diagnostic allowance includes two
additional path operations per protected name per possible emission, together
with their metadata and retry attempts. No
unchecked fallback is permitted after an admission, formatting or write refusal.

Bootstrap/factory failures before a prepared context keep the terminal-only
diagnostic boundary: safe streams/exact null are supported, unbound regular logs
are refused. This API does not add a source reopen, metadata copy or regular-log
proof for those earlier failures. Its compact state shares phase-exclusive action
storage with the existing run directory index. Actual control inventories retain
the 16 KiB phase and 256 KiB reader-component bounds; they are capacity inventories,
not process RSS limits or measurements of the operating system stack.

## Policy and limits

`EncryptedReadContext::new(EncryptedReadOptions::default())` is deliberately conservative. Its encrypted limits are:

| Resource | Default |
|---|---:|
| Packed bytes/member, decoded bytes/member, ciphertext spool/member | 8 GiB each |
| Combined live ciphertext and plaintext staging | 16 GiB |
| Cumulative source bytes | 1 TiB + 64 MiB |
| Cumulative packed/decoded bytes | 1 TiB each |
| Cumulative logical I/O | 6 TiB + 64 MiB |
| Cumulative work | 8 TiB |
| Members and KDF calls | 100,000 each |
| Password UTF-8 bytes | 65,535 |
| I/O attempts and codec steps | 16,777,216 each |
| Interrupted retries and create attempts | 16 each |
| Reader acquisitions/member | 32 |
| Live owned FDs | 5 |
| Ciphertext memory threshold | 64 KiB |
| Rust reader capacity | 256 KiB |
| Native LZMA memory / Zstandard maximum window log | 256 MiB / 27 |

These are library admission defaults, not process RSS limits or command policy. The `for_projected` and `for_session` factories derive finite checked allowances from the one retained original catalogue, selected scope, actual password length, caller ceiling and output mode. `run_with_policy` and `extract::run_with_zip_policy` do the same. They introduce no fixed 8 GiB, 100,000-member, 1 TiB or 65,535-password ceiling. The parser's existing 1,000,000-entry policy remains. Explicit `EncryptedReadOverrides` lower the corresponding allowances. `run_with_context` and `extract::run_with_zip_context` honor the supplied finite options.

An output policy includes every record, including clear members, directories, skipped entries and diagnostics. Encrypted limits of zero do not disable this separate all-record ledger or reject clear payloads solely for being clear. Per-member/password/count limits use `u64`; cumulative bytes/work/attempts and combined live staging use `u128`, with checked arithmetic and no unlimited sentinel.

Ciphertext payload requests never exceed 64 KiB. AES ciphertext at or below the threshold uses memory; larger ciphertext uses a private spool and synchronous readback. The threshold accepts 0 through 1 MiB. Raising it above 64 KiB requires a correspondingly larger explicit finite reader-capacity allowance: at least threshold + 3 × 64 KiB. An empty ciphertext acquires no payload buffer or ciphertext spool. Disk failure returns typed I/O; it does not grow an emergency Vec or use mmap. Native codec state, stack/control reservations and caller storage must be considered separately when estimating total RSS.

## Verified output and terminal evidence

`ZipReadStage::prepare_stdout` consumes original entry provenance from a projected session, retained selection or generic selected ZIP. First admit the actual output FD through that same owner. Write callbacks into the private stage, then call `copy_verified` with a final source-check closure bound to that owner. The owner admits the external output descriptor, and `copy_verified` revalidates that actual descriptor before copying. It observes the original source before and after the copy, then explicitly retires its owned stage. Retain the same locked external output handle throughout; there is no extra post-copy external-descriptor validation. The run APIs use checked synchronous file staging and publication for extraction.

Explicit finish and close run on success and error. A close is attempted once: an interrupted or failed close retains unresolved FD usage and poisons further acquisition. Drop is a bounded fallback, not evidence of successful cleanup. `ZipReadError` retains typed operation, source, sink, diagnostic and cleanup evidence inline, plus partial run totals, publication state (`NotPublished`, `Published` or `Unknown`) and accepted output-byte counts. An error after accepted stdout bytes or successful publication cannot promise rollback. Preserve the complete error and report when adapting it to a UI.

The temporary directory/file checks require trusted functioning storage and process credentials, appropriate type/ownership/mode/ACL, identity and link count. The threat model excludes privileged or same-process compromise and hostile same-UID acquisition of private handles. Already-open same-UID handles can outlive namespace changes. Source and namespace checks detect observed changes optimistically; they do not eliminate check-to-unlink/rename races or malicious restoration of all observed state between checks.

See [qualification evidence](validation/encrypted-streaming-2026-11-13.md) and the [Prybar integration handoff](prybar-resource-integration.md) for measured coverage and caller work.

## Generic non-ZIP legacy events

`extract::run_with_zip_policy` and `run_with_zip_context` retain the incumbent non-ZIP engine. Their legacy observer skips `prepare`; its scope is unbound and cannot admit checked sinks or use checked `emit`. Use the consumer's existing legacy output path. Legacy allocation, parsing and callback behavior are not checked ZIP resource guarantees.

`LegacyDiagnostic { message }` forwards the original mixed callback stream, which includes skips/progress as well as failures. After a successful legacy `Summary`, `LegacyError { message, .. }` borrows each original `Summary.errors` string in order, before `RunEnded`. These are legacy strings, not new typed archive-error classifications. Normal renderers that already print `LegacyDiagnostic` ignore `LegacyError` to avoid duplicates. Quiet renderers ignore mixed diagnostics and print only `LegacyError`; silent renderers ignore both. Counts remain the summary's counts. Plain closure observers receive both event kinds and must choose the channel they render; the adapter does not print either implicitly. The first observer failure stops later callbacks, error replay and `RunEnded`, while retaining the available summary counts; the incumbent legacy operation itself keeps its existing completion behavior.
