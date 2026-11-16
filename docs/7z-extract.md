# 7z extraction

zipfast tests and extracts 7z archives, single files and plain byte splits (`name.7z.001`, `name.7z.002`, ...),
through the same entry points as the other formats. The headers come from the member map
([member maps](member-map.md#7z)); `zipfast::sevenzip` decodes the folders.

## Entry points

- `extract::run`, `extract::run_with_password` and the CLI (`zipfast t|x|e|l`): a file starting with the 7z
  signature (`7z\xBC\xAF\x27\x1C`) is 7z, before any other format test.
- `extract::run_with_zip_policy` and `extract::run_with_zip_context`: the checked dispatcher routes 7z like tar, as
  a legacy route, so its report lines reach the observer as `ZipRunEvent::LegacyDiagnostic` and
  `ZipRunEvent::LegacyError`, the `Cancellation` passed in is honoured, and the run ends with `RunEnded`.
- `extract::list`, `extract::list_with_password`, `extract::inspect*`: the entries in archive order.
- `sevenzip::run(first, &Options, password, &Cancellation, &SevenZipLimits, report)` and
  `sevenzip::list(first, password)`: the same, with explicit limits. The dispatchers use
  `SevenZipLimits::default()`.

`Options` work as for ZIP and tar: `mode` (`Test` decodes and checks everything and writes nothing), `dest`,
`overwrite`, `flatten`, `protected_paths` (the archive and every volume of a split set are protected too) and
`select` (a `MemberFilter`, asked once per member in archive order with the ordinal `list` gives). `threads` and
`parallel_min` are ignored: a folder decodes on one thread.

Overwrite choices are made by `extract::check_target`, the function every whole-archive run uses:

- `Skip` reports `name: exists, skipped`; `Always` replaces the file once the new one has checked out.
- `RenameNew(style)` and `RenameExisting(style)` claim the name when the member starts, before it is decoded: the
  member's own name (or, for `RenameNew`, the first free `stem_N.ext` / `stem(N).ext`) is created empty with
  `O_EXCL`, and for `RenameExisting` the file in the way is first moved to the first free renamed name without
  replacing anything. The data still goes to a temporary file and replaces the claimed empty file only after its
  CRC matches, and only if the name still holds the file the run created (same device and inode); if something
  else was put there meanwhile, the member fails and that file is left alone. A member that fails removes its
  claimed file, but a file `RenameExisting` moved aside stays moved.
  Each rename is reported to the callback as it is made (`<requested>: exists, written as <path>` or
  `<requested>: existing file moved to <path>`), recorded in `Summary::renames`, sent to the observer as
  `ZipRunEvent::MemberRenamed` on the checked dispatcher, and kept in `RunError::renames` when
  `extract::run_with_renames` stops early (a wrong password, cancellation).

Selected single-entry reads (`SelectedEntry::open*`) refuse 7z with `Unsupported`. Progressive and persistent-partial
sessions read RAR only and refuse a 7z archive as before.

## What decodes

| coder | id | notes |
|---|---|---|
| Copy | `00` | |
| LZMA | `030101` | liblzma raw decoder; the dictionary is shrunk to the coder's output size |
| LZMA2 | `21` | the same |
| Deflate | `040108` | flate2 |
| Deflate64 | `040109` | zipfast's own streaming inflater (`zipfast::inflate64`), 64 KiB window |
| BZip2 | `040202` | the bzip2 crate (pure Rust backend), multi-stream |
| Zstandard | `04F71101` | as the 7-Zip ZS fork writes it; zstd crate |
| 7zAES | `06F10701` | AES-256-CBC, key from SHA-256 over `2^NumCyclesPower` rounds of salt, UTF-16LE password and counter |
| BCJ (x86) | `03030103` | optional 4-byte start offset property |
| BCJ2 | `0303011B` | four inputs: main, call, jump, range coder |
| PPC, IA64, ARM, ARMT, SPARC | `03030205`, `03030401`, `03030501`, `03030701`, `03030805` | |
| ARM64 | `0A` | |
| Delta | `03` | one property byte, distance minus one |
| Swap2, Swap4 | `020302`, `020304` | |
| PPMd | `030401` | variant H with 7-Zip's range coder, the model shared with RAR 2.9's PPM blocks; its memory (up to 256 MiB) counts against `dictionary_bytes` |

Not decoded, refused before anything is written with `SevenZipError::UnsupportedCoder { id }`: RISC-V (`0B`) and any
other id. Only folders holding a selected member are checked, so a filter
can still take the rest of an archive.

No new dependencies: liblzma, flate2, bzip2 and zstd were already used for ZIP, xz and tar, and Deflate64 is zipfast's own decoder.

## Folders

A folder's coders are wired up from its bind pairs: starting from the one output no bind pair consumes, each coder
input is either another coder's output (a bind pair) or a packed stream (the folder's packed-stream list, in
order). Any arrangement decodes, not only a chain; BCJ2's four inputs come out of three LZMA coders and a raw packed
stream that way. A cycle, a coder nothing reads, an input bound to nothing or a coder with several outputs is
refused.

Each folder is decoded once, from the front, as a chain of readers: nothing is buffered beyond a few 64 KiB
buffers per coder, whatever the folder's size. Members are cut from the folder's output by their sizes, in order.
A member that is not written (unselected, an existing file under `Skip`, an unsafe name) but sits before a member
that is, is decoded through and dropped; decoding of a folder stops after the last member anyone needs, and a
folder nothing is selected from is not opened at all. Every coder's output is held to the size the header gives
it: data that ends early, or does not decode, fails the member.

## Checks and publication

Every file member's CRC is checked before the file appears. Data is written to a temporary file in the target's
folder; once its CRC (where stored) matches, its time and permissions are set and it takes the target's name:
without replacing anything (`persist_noclobber`) unless the target existed and `Always` was asked, in which case it
replaces the file after checking again that no symbolic link has appeared there. A mismatch or a decoding failure
reports `name: ...` in `Summary::errors` and removes the temporary file; the run goes on. After a decoding failure
the rest of that folder cannot be decoded, and its selected members are reported as failed too.

A folder of several members that stores its own CRC (7-Zip stores per-file CRCs instead, but the format allows
it) holds its verified files back until the whole folder has been read and its CRC matches; then they are
published together, or all reported as failed. `Mode::Test` does the same: the members count as tested only once
the folder's CRC matches.

A member with no CRC of its own and no folder CRC behind it cannot be checked:

- **Unencrypted, it is published unverified**, as 7-Zip extracts it: only a decoding error can catch damage.
- Encrypted, it is refused (`encrypted without a CRC, and no password proven yet: cannot be verified`) unless the
  password was already proven in this run, since a wrong key would turn it into garbage nothing could detect.

Destination safety is the shared code's: names are made relative and refused when they would leave the destination
(`..`, absolute paths; a backslash counts as a separator, so `..\x` is refused too), folders are made without
following links, a link at a target or in the way is refused, and protected paths are never replaced.

## Entries

- Directories and empty files (entries without a stream) are created; directory times and permissions are set once
  everything inside them is written.
- Anti items (deletion markers of update archives) are skipped: the member map does not list them, and nothing is
  ever deleted.
- `mtime` is restored. Attributes with the Unix extension bit (`0x8000`) give the permission bits of the high 16
  bits (`mode & 0o777`; set-id and sticky bits are dropped). An entry whose Unix file type is a symbolic link is
  reported (`links are not supported yet`) and not written; devices and pipes likewise. Windows attribute bits
  without the Unix extension are listed (`Entry::attributes`) but not applied.

## Passwords

Data encryption and encrypted headers (`-mhe`) are both read. 7z stores no password check value, so as 7-Zip
does, a wrong password is recognised by its effect: for encrypted headers, a header that does not decode; for
encrypted data, the first encrypted member failing to decode or failing its CRC before the password is proven.
Either stops the run with `SevenZipError::WrongPassword`; nothing is published.

The password is proven by encrypted headers that decode and pass their CRC, or by an encrypted member that passes
its CRC. After that, a failing encrypted member is a data error for that member. Before it, a correct password
with a damaged first encrypted member is indistinguishable from a wrong one and is reported as
`WrongPassword`, as 7-Zip reports "Wrong password?" in the same case.

Key derivation accepts `NumCyclesPower` up to 24 (7-Zip's own limit) for headers and data alike; 7-Zip writes 19.

| failure | `extract::run*` | `extract::run_with_zip_policy` |
|---|---|---|
| no password | `Error::Encrypted` ("encrypted: a password is required, or the one given is wrong") | `ReadFault::PasswordRequired` |
| wrong password | `Error::Io` (kind `PermissionDenied`) carrying `SevenZipError::WrongPassword` | `ReadFault::PasswordCheckFailed { cipher: CipherKind::Aes }` |
| canceled | `Error::Io` (kind `ConnectionAborted`) carrying `SevenZipError::Canceled` | `ReadFault::Cancelled` |
| anything else | as below | `ReadFault::Legacy(..)` with the same `Error` |

The crate's legacy `Error` keeps its variants (a test pins them), so the typed `SevenZipError` travels inside it:
`SevenZipError::of(&error)` returns it. A missing volume is `Error::MissingVolume(path)` and an I/O failure
`Error::Io`; the rest is an `Error::Io` whose kind is `Unsupported` (an unsupported coder or feature),
`InvalidInput` (a limit) or `InvalidData` (corrupt headers), carrying the `SevenZipError`.

## Limits

`SevenZipLimits` (defaults in brackets; `#[non_exhaustive]`, start from `Default` and set fields):

- `folder_bytes` (no limit): the decoded size of a folder, and of every coder's output inside it, not only the last
  (`FolderBytes`). The outputs of all a folder's coders together may total at most four times this
  (`FolderCoderBytes`). It bounds work and output, not memory, since every coder streams and stops at its declared
  size: a solid folder of a 4K remux is far past any fixed cap, so there is none by default. Lower it to keep a
  chain like Deflate over LZMA2 from expanding a little packed data into a huge inner stream. Decoding checks for
  cancellation at least once per MiB either way.
- `dictionary_bytes` (4 GiB): the memory one folder's decoders allocate up front, LZMA and LZMA2 dictionaries,
  summed over the folder's coders (a BCJ2 folder has three), each dictionary first shrunk to its
  coder's output size (`DictionaryBytes`). This is the memory-bomb guard: a tiny archive declaring a huge
  dictionary and output allocates at most this. 4 GiB is the largest LZMA dictionary and opens 7-Zip's largest
  setting, `-md=1536m`; an allocation the system refuses up front is an `OutOfMemory` I/O error, though with the
  usual overcommit memory may only run short as a dictionary fills, where the OOM killer can end the process. The
  Zstandard coder's window isn't counted. Lower it where memory is
  short.
- `folders` (4096), `pack_streams` (4096), `coders` per folder (32), `coder_properties` bytes per coder (64) and
  `entries` (65536, counting anti items, checked while the header is read).

An archive past one fails with `SevenZipError::Limit { limit, max, attempted }` before anything is written. Listing
(`sevenzip::list`, or `list_with_limits` with the caller's limits) reads only headers, so only the header limits
(folders, pack streams, coders, coder properties, entries) apply to it. The
member map's own header budgets (`ProgressiveLimits`) apply as well.

## Split sets

Volumes concatenate: the first volume is the path given, later ones are named by the member map's rule
(`name.7z.001` → `name.7z.002`). A missing volume holding the headers or member data is
`SevenZipError::MissingVolume(path)`. At most 16 volumes are open at once while data is read.

## Cancellation

The `Cancellation` is checked between members, before every packed read, in every stream between two coders and
at every coder's output at least once per MiB passed (so a decoder that loops over its input without producing
output, such as Deflate over empty blocks, still stops), between 256 KiB output chunks, and during key derivation. A canceled run returns `SevenZipError::Canceled`; the member being written is not
published and its temporary file is removed.

## Probe

`probe::probe` recognises a 7z head as `Packing::SevenZip(SevenZipPacking)`: the format version, where the end
header is and how long it is, and so `archive_len`, the archive's whole length (for a split set, the volumes'
sum). The headers sit at the end, so members are listed (`complete`, `first_media`, `borrowable`, `map`) only when
the head holds the whole archive. Encrypted headers make it `locked` with `Borrowable::NeedsPassword`; a stored
7zAES member with a password is `PasswordUnverified` unless its decrypted start sniffs as media.

## Tests

`tests/sevenzip_extract.rs` extracts archives 7-Zip 26.06 wrote (`tests/fixtures/7z-extract`, commands in its
README) for every coder above but Swap and Zstandard, solid, split, encrypted and header-encrypted archives, and
checks each file against the inputs' SHA-256. Hand-built archives cover unsafe names, the default bounds and a
folder CRC. The branch converters also have unit tests against hand-computed vectors and a chunking test.
