# 7z extraction

zipfast tests and extracts 7z archives, single files and plain byte splits (`name.7z.001`, `name.7z.002`, ...),
through the same entry points as the other formats. The headers come from the member map
([member maps](member-map.md#7z)); `zipfast::sevenzip` decodes the folders.

## Entry points

- `extract::run`, `extract::run_with_password` and the CLI (`zipfast t|x|e|l`): a file starting with the 7z
  signature (`7z\xBC\xAF\x27\x1C`) is 7z, before any other format test.
- `extract::run_with_policy` and `extract::run_with_context` (also named `run_with_zip_policy`/`run_with_zip_context`;
  see [one entry point](extract-entry.md)): the checked dispatcher routes 7z, as
  a legacy route: each member reaches the observer live as `MemberSucceeded`/`MemberSkipped`/`MemberFailed` with
  its listing index (renames as `MemberRenamed { ordinal: Some(..) }`), its report lines as `LegacyDiagnostic` and
  `LegacyError`, the `Cancellation` passed in is honoured, and the run ends with `RunEnded`.
- `extract::list`, `extract::list_with_password`, `extract::inspect*`: the entries in archive order.
- `sevenzip::run(first, &Options, password, &Cancellation, &SevenZipLimits, report)` and
  `sevenzip::list(first, password)`: the same, with explicit limits. The dispatchers use
  `SevenZipLimits::default()`.

`Options` work as for ZIP and tar: `mode` (`Test` decodes and checks everything and writes nothing), `dest`,
`overwrite`, `flatten`, `protected_paths` (the archive and every volume of a split set are protected too) and
`select` (a `MemberFilter`, asked once per member in archive order with the ordinal `list` gives). `threads` (None:
one per core) is how many threads an LZMA2 folder written in independent blocks decodes on; `Some(1)` keeps every
folder on the calling thread ([LZMA2 on several threads](#lzma2-on-several-threads)). `parallel_min` is ignored.

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
  `extract::run_with_renames` stops early (a wrong password for encrypted headers, cancellation).

Selected single-entry reads (`SelectedEntry::open*`) refuse 7z with `Unsupported`. Progressive and persistent-partial
sessions read RAR only and refuse a 7z archive as before.

## Printing members (`7z x -so`)

`sevenzip::print_selected(first, password, select, output, cancel, limits)` writes the data of the members `select`
takes (it gets each member's listing index and name; directories are never offered) to one writer, in archive order,
as `7z x -so` does. Each folder is decoded once, front to back, even when several of its members are taken: the
members before and between them are decoded and dropped. Each member is held back until its
CRC checks out (for a folder of several members that stores its own CRC, until the folder's does, so those print
together at the folder's end), so a member that fails prints nothing; it is a line in `Summary::errors` and the run
goes on. `print_selected_with` hands each chunk to a callback with the member's listing index instead.
`extract::SelectedEntry::open` (and `open_cancelable_with_zip_limit`) read one 7z member through the same code, so
callers that read members one by one get the same bytes. Their byte limit counts the solid history the member
needs, as for RAR: its folder's packed bytes and the decoded bytes through the member (the whole folder when the
folder's own CRC must vouch for it), refused at open with `ReadResource::MemberPackedBytes` /
`MemberDecodedBytes` on the checked dispatcher. The caller's cancellation reaches the header walk and an encrypted
header's key derivation. Reading one by one decodes the member's folder up to it each time, so
for several members of one solid folder `print_selected` is the cheaper route. A split ZIP set (`.z01`... `.zip`, or
`.zip.001`...) also opens with `SelectedEntry`, read across its volumes as `extract::run` reads it.

7-Zip prints an encrypted member's data before its CRC fails (a wrong password on a Copy folder); zipfast withholds
a member until it checks out.

Held-back plaintext stays in memory while all held members together keep at most
`SevenZipLimits::spool_memory_bytes` (1 MiB); past that a member moves to the run's one temporary file in `spool_dir`
(the system's temporary folder by default), as a range of it. The file is unlinked as it is made: it has no name, is
written and read back at each member's offsets through its one descriptor, and vanishes with the descriptor, so
neither a crash nor `SIGKILL` leaves decrypted data on disk, and a folder that holds back many members (for its own
CRC) uses one descriptor and bounded memory. A member that would hold back more than `spool_member_bytes` (8 GiB) fails with
`SevenZipLimit::SpoolBytes` as soon as it goes past it, prints nothing, and the run goes on. Holding back and
copying out check for cancellation every chunk.

## What decodes

| coder | id | notes |
|---|---|---|
| Copy | `00` | |
| LZMA | `030101` | liblzma raw decoder; the dictionary is shrunk to the coder's output size |
| LZMA2 | `21` | the same; a stream of independent blocks (`7z -mmt`) decodes on several threads, see below |
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
buffers per coder, whatever the folder's size (an LZMA2 coder decoding blocks on several threads holds a bounded
budget more, see below). Members are cut from the folder's output by their sizes, in order.
A member that is not written (unselected, an existing file under `Skip`, an unsafe name) but sits before a member
that is, is decoded through and dropped; decoding of a folder stops after the last member anyone needs, and a
folder nothing is selected from is not opened at all. Every coder's output is held to the size the header gives
it: data that ends early, or does not decode, fails the member.

## LZMA2 on several threads

7-Zip with `-mmt` (the default on a machine with several cores) writes LZMA2 as a run of independent blocks: each
starts with a chunk that resets the dictionary (control byte `0x01`, a stored chunk, or `0xE0` and up, an LZMA chunk
with new properties), and since a dictionary reset forces new properties on the next LZMA chunk, a block decodes on
its own exactly as it does inside the stream. With more than one thread (`Options::threads` for `sevenzip::run`
and the dispatchers, `SevenZipLimits::decode_threads` for `print_selected` and `SelectedEntry`, None for one per
core), an LZMA2 coder whose output is at least 2 MiB decodes such blocks side by side:

- Every stream starts on the one-thread decoder, with a walker that follows the chunk headers (as
  [`map::Lzma2Index`](member-map.md) reads them) in each 64 KiB block it reads: a few operations per chunk, no
  copies. It switches to the pipeline below at a chunk boundary only once that can pay: at a second piece (a
  dictionary reset at least 1 MiB of output after the start), or once more than 1 MiB of output has gone by and less
  than nine tenths of it came from stored chunks. A stream of stored chunks with no second piece (incompressible data
  from one-thread 7-Zip, F07 below) never switches and runs at the one-thread speed. Nor does a stream whose output
  so far is more than 64 times its packed bytes: highly repetitive data (1 GiB of a repeated paragraph packs to
  158 KB) decodes at close to memory speed on one thread, and handing its blocks between threads costs more than it
  gains (0.9 times one thread on a loaded i7-8700K before this rule). The ratio is checked at each chunk boundary
  until the switch, over the whole stream so far.
- In the pipeline, the run's thread reads the packed stream and walks its chunk headers; a dictionary reset at least
  1 MiB of output after the last cut starts a new piece. Packed bytes are read in 64 KiB blocks that are moved, not
  copied, to whichever thread decodes them.
- The run's thread decodes the piece at the head of the stream itself, straight into the reader's buffer, as the
  one-thread decoder does. Each later piece goes to one of `threads` worker threads, which decodes it as its packed
  bytes arrive and hands back its output in 1 MiB segments (the run's thread mostly reads, checks and writes once
  the workers have the pieces). When the head piece is done, the next one is
  handed out from its worker, or decoded on the run's thread if no worker has taken it yet. The output goes out in
  stream order, so it is byte for byte the one-thread output, and the member and folder CRCs check the same bytes.
- Worker threads start only with a second piece: an LZMA-coded stream of one block (one-thread 7-Zip, `-mmt1`,
  liblzma) is decoded on the run's thread alone, with a short lookahead.

Memory is bounded by `SevenZipLimits::lzma2_parallel_bytes` (256 MiB, at least 4 MiB), so several extractions at
once stay modest. Each worker costs its dictionary (the coder's, shrunk to the folder's output) and its one 1 MiB
output buffer, which it makes only when it has output to make (a short last segment goes out in a buffer of its own
size, and every queued buffer counts by what it allocates); the workers take at most a third of the budget, and
fewer start when they would take more (none: one thread). Their dictionaries also come out of what
`dictionary_bytes` leaves once the folder's coders are built, shared by all its LZMA2 coders and taken when a coder
starts its workers. At most two pieces per thread are in the pipeline, and the packed bytes waiting for decoders and
the decoded bytes waiting for the run together stay within the rest of the budget: a worker waits while it is
spent, and reading ahead stops (except the head piece's next bytes, up to 256 KiB waiting for its decoder, which
the run cannot move without; anything further ahead must fit the budget). The
head's worker is let past the budget only while the run has fewer than two of its 1 MiB segments waiting, since the
run is waiting for those: the run always moves, and a run that stops reading (writing a member, a slow `-so`
consumer) stops the head too, so a block of zeros cannot pile up decoded output. Reading ahead also stops once the
packed bytes waiting in the piece being read pass the larger of 8 MiB and the output handed out so far, capped by
the budget (256 KiB in a piece that is nine tenths stored chunks, which cost only a copy to decode), so a one-block stream holds little more
than the one-thread decoder does. All told, the threads hold at most the budget and two segments at any moment.
Peak resident memory can read higher: each piece's decoder allocates its dictionary afresh (liblzma offers no way to
reuse one), and on Linux glibc keeps freed blocks of that size in its per-thread arenas instead of returning them.
So on glibc a worker asks it to trim its arenas (`malloc_trim`) after finishing pieces, at most once per 4 MiB of
dictionaries freed. With 12 threads on the 16 MiB-block archive below that brought peak RSS from 343-367 MiB to
289-315 MiB, with no measurable cost in time; `MALLOC_MMAP_THRESHOLD_=131072` (which makes glibc hand such blocks
back by itself) gave 287 MiB, and 8 threads 296 MiB without either.

7-Zip's blocks are four times its dictionary: 4 MiB at `-md=1m`, 64 MiB at `-mx5`'s 16 MiB, 256 MiB at `-mx9`'s
64 MiB (7-Zip 26 at `-mx5 -mmt8` wrote 134 MiB blocks with a 32 MiB dictionary for the measured archive). With the
256 MiB default such a stream gets two workers (a 32 MiB dictionary and a 1 MiB buffer each) and 190 MiB for bytes
in flight, about one and a half blocks, so it decodes only partly side by side: about 1.6 times one thread on that
archive, whatever the thread count. Streams of smaller blocks (16 MiB at `-md=4m`) get every thread. A caller that
wants the most speed on large blocks and has the memory raises `lzma2_parallel_bytes` (1 GiB lets the six 134 MiB
blocks overlap: about 3.4 times one thread at 8 threads, with peak memory near 1 GiB).

Failures keep their place. A piece that does not decode, ends early, or whose packed bytes cannot be read gives the
output it decoded before the failure and then the failure, in stream order, so the failure lands on the member it
lands on with one thread. (The one-thread decoder drops what liblzma made in the call that failed, up to one 256 KiB
read; the threaded one hands it out, so a member that ends within that much before a failure can check out on
several threads where it fails on one.) Workers check the `Cancellation` every 1 MiB of output and every 20 ms while
they wait, the run's thread does the same, and a folder that is closed early (a failure, the last needed member)
stops and joins its workers.

Measured on a solid 768 MiB folder (`7z a -mx5 -mmt8`) and the RustyGet fixtures; see the pull request that added it
for the table. LZMA2 written by one thread, xz and LZMA (not LZMA2) folders are unchanged.

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
- `mtime` is restored. A member without an `MTime` property lists `mtime: None` and is written with
  `Options::fallback_mtime` when one is given (7-Zip uses the archive file's mtime), else left with the time it was
  written at. Attributes with the Unix extension bit (`0x8000`) give the permission bits of the high 16
  bits (`mode & 0o777`; set-id and sticky bits are dropped). An entry whose Unix file type is a symbolic link is
  reported (`links are not supported yet`) and not written; devices and pipes likewise. Windows attribute bits
  without the Unix extension are listed (`Entry::attributes`) but not applied.

## Passwords

Data encryption and encrypted headers (`-mhe`) are both read. 7z stores no password check value, so as 7-Zip
does, a wrong password is recognised by its effect: for encrypted headers, a header that does not decode; for
encrypted data, an encrypted folder failing to decode or failing its CRC before the password is proven.
Encrypted headers that do not decode stop the run with `SevenZipError::WrongPassword`: nothing can be listed.
With data-only encryption, as 7-Zip does ("Data Error in encrypted file. Wrong password? : <name>" when the folder's
data does not decode, "CRC Failed in encrypted file. Wrong password? : <name>" when it decodes, as a Copy folder
does, but fails a CRC), each member of such a folder fails on its own (every member of a solid folder, in archive
order): a `<name>: data error in encrypted file: wrong password?` or `<name>: CRC failed in encrypted file: wrong
password?` line in `Summary::errors`, `SevenZipError::WrongPassword { failure: Some(..) }` as the member's error,
with `EncryptedFailure::DataError` or `EncryptedFailure::CrcFailed` (`ReadFault::PasswordCheckFailed { seven_zip:
Some(..), .. }` on the checked dispatcher), and nothing published for it. The first sign in a folder decides for all
of its members. See [compatibility options](compat-options.md#7z-wrong-passwords-how-the-member-failed).
The run goes on with the other folders, so plain folders still extract. The run ends `Ok` with these failures in
its summary (the `zipfast` command then exits 1, as for any failed member; 7-Zip exits 2).

The password is proven by encrypted headers that decode and pass their CRC, or by an encrypted member that passes
its CRC. After that, a failing encrypted member is a data error for that member. Before it, a correct password
with a damaged encrypted member is indistinguishable from a wrong one and is reported as a wrong password, as
7-Zip reports "Wrong password?" in the same case.

Key derivation accepts `NumCyclesPower` up to 24 (7-Zip's own limit) for headers and data alike; 7-Zip writes 19.

| failure | `extract::run*` | `extract::run_with_zip_policy` |
|---|---|---|
| no password | `Error::Encrypted` ("encrypted: a password is required, or the one given is wrong") | `ReadFault::PasswordRequired` |
| wrong password | `Error::Io` (kind `PermissionDenied`) carrying `SevenZipError::WrongPassword { failure }` (`None` for encrypted headers) | `ReadFault::PasswordCheckFailed { cipher: CipherKind::Aes, seven_zip: failure }` |
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
