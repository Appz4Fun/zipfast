# One entry point for every format

`extract::run_with_policy` is the one function to call to test or extract any archive zipfast reads:

```rust
pub fn run_with_policy(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    overrides: &zip::EncryptedReadOverrides,
    observe: impl RunObserver,
) -> zip::ZipReadResult<RunReport>
```

`extract::run_with_context` is the same with a caller-owned `zip::EncryptedReadContext` in place of the overrides,
so encrypted-ZIP budgets carry across runs. `run_with_zip_policy` and `run_with_zip_context` are the same
functions under their older names. `RunEvent`, `RunObserver` and `RunReport` are `ZipRunEvent`, `ZipRunObserver`
and `ZipRunReport` under format-neutral names. Unix (macOS, Linux) only, like the checked ZIP reader.

## Formats

The format comes from the file's content, never its name:

| content | runner |
|---|---|
| ZIP (also with a self-extracting stub) | the checked ZIP reader ([checked ZIP reads](zip-checked-reads.md)) |
| tar, plain or gzip/xz/zstd/bzip2-compressed | the tar runner, also callable as `tar::run_with_policy` |
| a lone `.gz`, `.xz`, `.zst` or `.bz2` that holds no tar | the tar runner, as one member (ordinal 0) |
| RAR 5.0 and RAR 4.x, single or multi-volume | the RAR runner |
| 7z, single or `.7z.001` split | the 7z runner ([7z extraction](7z-extract.md)) |

## Options

One `Options` for all of them: `mode` (Test or Extract), `dest`, `overwrite`, `flatten`, `threads`,
`protected_paths` and `select` apply to every format.

`Overwrite::Skip`, `Always`, `RenameNew` and `RenameExisting` behave the same way in every format; see the README's
"renaming on conflict".

## Cancellation

The `Cancellation` reaches every format's inner loop:

- ZIP: between members, in every decode step, in staging and publication.
- tar and lone streams: every read of the archive (each header and every 1 MiB of member data), and, for a
  compressed stream, every read of packed bytes and of decoded bytes, so a decoder that loops on its input without
  producing output still stops.
- RAR: before each member and with every chunk of a member's decoded data. A big stored RAR 5.0 part copied on
  several threads is checked once its copy finishes, and dropped unpublished.
- 7z: between members, before every packed read and every 1 MiB between coders.

A canceled run returns an error whose `operation()` is `ReadFault::Cancelled`. Members published before it stay;
the member in progress is not published.

## Events

Every run ends with `RunEnded { report, error }`.

| | ZIP | tar, lone stream | RAR, 7z |
|---|---|---|---|
| `MemberSucceeded` / `MemberSkipped` / `MemberFailed` | live, with the listing index | live, with the listing index | live, with the listing index |
| `MemberRenamed` | `ordinal: Some(..)`, just before the member's own event | `ordinal: Some(..)`, just before the member's own event | `ordinal: Some(..)`, just before the member's own event |
| `LegacyDiagnostic` (report lines: skips, failures) | not sent | as they happen | as they happen |
| `LegacyError` (`Summary::errors` text) | not sent | at the end | at the end |

A compressed tar is staged and published once the whole stream has decoded and checked out, so its members'
success events arrive at the end; failures found while decoding come as they are found. A tar member that fails
carries `ReadFault::Legacy` with the reason.

RAR and 7z send a member's event as soon as it is published (or tested). A 7z member in a solid folder that stores
its own CRC is held until the folder's end, so those members' events come together when the folder checks out, in
listing order. A RAR or 7z member that fails carries `ReadFault::Legacy` with the reason. The listing index is the
member's position in `extract::list`, counting folders and members a filter left out.

## Errors

ZIP's typed faults are unchanged. For 7z, a missing password is `ReadFault::PasswordRequired` and a wrong one
`PasswordCheckFailed`. Any other tar, stream, RAR or 7z failure that stops the run is `ReadFault::Legacy` carrying
the format's own `Error` (`sevenzip::SevenZipError::of` finds the 7z detail).
