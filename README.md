# zipfast

A fast, universal archive extractor written in Rust. Work in progress.

## Workspace

The workspace requires Rust 1.100.0 or newer. `rust-toolchain.toml` pins development
and CI to Rust 1.100.0 with rustfmt and Clippy. Use rustup's Cargo and rustc
from `PATH` so the pin also applies to nested commands.

The root package builds the `zipfast` library and command.
[`zipview`](crates/zipview/README.md) is a read-only ZIP library for in-memory and range-based access.
See [workspace integration](docs/zipview-workspace.md) for Git dependencies, build commands, and import provenance.

## What works

- RAR4 archives: bounded header listing and verification, extraction, and selected
  printing of Stored and compressed regular files of every unpack version (RAR 1.5's 15, RAR 2.0's 20/26
  with audio blocks, RAR 2.9's 29 with PPMd variant H and the VM standard filters), including files split
  across `name.partN.rar` or `name.rar`/`name.r00` volumes, solid archives, AES-encrypted (`-p`) files and
  encrypted headers (`-hp`), through every entry point including progressive sessions. Unix symbolic links are
  created on Unix when their target stays inside the destination. The catalogue retains unsupported member
  metadata and reports typed payload exclusions, keeps names that aren't UTF-8 as UnRAR lists them, and ends at a
  missing later volume, failing only the member split into it.
- RAR 5.0 archives: listing, testing and extracting stored and compressed files (every method, solid archives,
  filters), including files split across `name.partNN.rar` or `name.rar`/`name.r00` volume sets, self-extracting
  stubs, CRC32 and BLAKE2sp checks, modification times and Unix permissions. Big files decode on several cores.
- ZIP archives: stored, deflated, Deflate64, bzip2, LZMA, xz and zstd entries, ZIP64, self-extracting stubs, UTF-8 and code page 437 names,
  Unix permissions, and extended or NTFS timestamps. Checked streaming reads support ZipCrypto and WinZip AES
  (all strengths, AE-1/AE-2); see [checked ZIP reads](docs/zip-checked-reads.md) for policy, staging and legacy caps, and [staged output](docs/zip-staged-output.md) for the native and portable backends.
  Split sets list, test and extract from their first file: raw byte splits (`name.zip.001`, ...) and Info-ZIP
  spanned sets (`name.z01`, `name.z02`, ..., `name.zip`, from the `.zip` or the `.z01`), read as 7-Zip reads them;
  a missing volume fails only the members whose bytes it holds. As in 7-Zip, a spanned set opens from whatever
  volumes are there: without its `.zip` the members are found by walking the local headers from the `.z01`, and
  without its `.z01` (with a later numbered volume there) the members starting on it fail while the rest extract. Unlike 7-Zip, a member cut short by a
  missing volume is never written in part: zipfast only publishes data whose size and CRC it has checked.
- tar archives, plain or compressed with gzip, xz, zstd, bzip2, LZ4 (frames and legacy frames), Unix compress or
  LZMA-alone (`.tar.gz`, `.tgz`, `.tar.xz`, `.tar.zst`, `.tar.bz2`, `.tar.lz4`, `.tar.Z`, `.tar.lzma` and so on),
  each found by its first bytes whatever the name: POSIX ustar and pax (long names, big sizes, fractional times), GNU long names and base-256
  sizes, and pre-POSIX headers. A compressed file that holds no tar archive comes out as the one file it
  compresses. xz files written in blocks (`xz -T0`) decode on several cores.
- xar archives (`.xar`, and the outer layer of a macOS `.pkg`): file data stored or compressed with gzip, bzip2,
  xz or LZMA, each file's extracted checksum (SHA-1, MD5, SHA-256 or SHA-512) and the table of contents' own
  checksum checked. A file with no extracted checksum or another kind (sha224, sha384, crc), and a table of contents
  whose header names no checksum (algorithm 0) or an unknown one, are read unchecked: xar has nothing else to check
  them by. Files may not share heap data.
  The XML table of contents is read with bounds on its size, nesting, file count and path length, and no entity is
  expanded but XML's own five. Members take tar's pipeline, links included.
- WIM (Windows Imaging) files, found by their magic: stored, XPRESS (Huffman) and LZX resources in chunks, each
  blob checked against its SHA-1 before the file it fills is published. Image 1 is extracted;
  `tar::list_wim_image` lists another and `tar::wim_info` reads the header (GUID, image count, compression).
  Folders, names, timestamps, hard links, and symbolic links and junctions (as symbolic links, only when they stay
  inside the destination) take tar's pipeline. LZMS and solid resources are refused: LZMS has no public
  specification. Split sets (`.swm`) are refused too. Lookup table entries, metadata, entries, nesting and path
  bytes are bounded, resources may not overlap, and data shared by several files is written again only up to a
  multiple of the archive's size. The LZX decoder is the MIT-licensed `lzxd` crate, vendored and patched for WIM.
- cpio archives, plain or compressed as tar can be: the binary format in either byte order, odc (`070707`), newc
  (`070701`) and newc with checksums (`070702`, checked). They take tar's whole pipeline: containment, symbolic and
  hard links, overwrite choices, listing and reads by index. A file's hard links come out as links to the name that
  carried its data (the last one in newc, the first in the older formats); `TRAILER!!!` ends the archive.
- 7z archives (`.7z`, split `.7z.001`, ...): testing and extracting through the same entry points, options and
  checks as the other formats. Copy, LZMA, LZMA2, Deflate, Deflate64, BZip2, Zstandard, PPMd, 7zAES (also with
  encrypted headers), BCJ, BCJ2, ARM, ARM64, ARMT, PPC, SPARC, IA64, Delta and Swap; solid folders stream without
  buffering and every CRC is checked before a file appears; see [7z extraction](docs/7z-extract.md).
- Member maps (`zipfast::map`): a typed header listing of RAR4, RAR 5.0 (including `-hp` with a password) and
  ZIP archives from memory or a range source, mapping each stored member's output offsets to per-volume packed
  spans; see [member maps](docs/member-map.md).
- Reading a stored member from any output offset (`zipfast::map::extract_member_from`, `MemberReader`): plain,
  RAR 5.0 and RAR 4.x AES and WinZip AES members stream their plaintext suffix from the packed bytes that offset
  needs, checking the parts they cover, for example to finish a partial output from another copy; see
  [extract-member-from](docs/extract-member-from.md).
- Probing (`zipfast::probe`): from a file's first bytes (one Usenet article) and optionally its last, tells bare
  media (mkv, webm, mp4, mov, avi, MPEG-TS, M2TS, ASF, MPEG-PS) from RAR4, RAR 5.0, ZIP and 7z, picks the first media
  member, says whether it is stored, compressed, data-encrypted or behind encrypted headers, and whether its bytes
  can be borrowed; see [probing](docs/probe.md).
- Extraction never writes outside the destination: `..`, absolute paths, drive letters and links in the way are
  refused.

Remaining RAR4 capabilities, RAR 5.0 links and ZIP PPMd are next.

## Usage

```
zipfast l archive.rar             # list
zipfast t archive.rar             # test every checksum, write nothing
zipfast x archive.part01.rar out  # extract with folders
zipfast e archive.rar out         # extract without folders
```

**ZIP extraction storage:** the default checked command requires ownership-enforced local APFS on macOS, or ext-family/XFS/Btrfs/tmpfs on Linux with the implemented procfs descriptor and ACL facilities. This applies to clear ZIP members too. Unlisted destinations—including Linux overlayfs/container root, network mounts, exFAT and macOS HFS+—fail closed. Choose supported mounted output and, for encrypted disk snapshots, temporary locations (`ZIPFAST_ZIP_TEMP_DIR`); changing temp storage cannot fix an unsupported destination. Physical qualification covers APFS/ext4/Btrfs/tmpfs; XFS is admitted but unqualified, and other ext variants are not claimed tested. Full filesystem compatibility remains open. See [checked storage and release notes](docs/zip-checked-release-notes.md).

Switches: `-o+`/`-y` overwrite existing files, `-o-` skip them (default), `-q` quiet, `-mt<n>` use up to n
threads (default: one per core).

Exit status: 0 all good, 1 some files failed, 2 the archive couldn't be read.

Extraction protects the input archive and existing consecutive RAR volume names. It refuses destination symlinks.
A successful overwrite atomically replaces the destination name. Replacing a separate hard-link name leaves the
original archive inode and its bytes intact.

For compressed TAR, extraction stages member payloads and archive-supplied directory metadata until the outer
stream passes verification. Pending payloads use temporary disk space. Members publish in archive order, so a
publication failure can leave earlier verified members in place.

### Deterministic repack

```
zipfast repack lib.a out.a                       # ar as GNU `ar D` writes it
SOURCE_DATE_EPOCH=1700000000 zipfast repack --nested pkg.deb out.deb
zipfast repack --mtime=0 --level=9 src.tar.xz out.tar.gz
```

`zipfast repack` (library: `zipfast::repack::repack`) rewrites an ar archive (`.a`, a `.deb`'s or `.ipk`'s outer
layer) as ar, or any tarball the tar reader reads as a `.tar.gz`, so that the same members always give the same
bytes: members sorted by name (a `.deb`'s `debian-binary` stays first), owner and group 0 with no names, every
time `--mtime` (default `$SOURCE_DATE_EPOCH`, else 0), modes normalised (ar `644`; tar `755`/`644`/`777`), symbol
tables rebuilt for the new order, and gzip with MTIME 0, no name, OS 3 and level 9. `--nested` also repacks
`.tar.gz` members one level deep, charging their work to the same byte limit. Unsafe names, tar names given twice,
paths through a symlink member, dangling hard links and thin archives are refused, the reader's limits apply,
temporaries stay beside the output, and links on disk are never followed. Output is reproducible for a given zipfast build.

### Library: one entry point for every format

`extract::run_with_policy` (or `extract::run_with_context`, with a caller-owned `EncryptedReadContext`) tests or
extracts ZIP, tar, lone `.gz`/`.xz`/`.bz2`/`.zst`/`.lz4`/`.Z`/`.lzma` streams, RAR4/RAR5 and 7z with one `Options`, one
`Cancellation` and one observer of `extract::RunEvent`s. The format comes from the content. Cancellation reaches
every format's inner loop and ends the run with `ReadFault::Cancelled`; `Overwrite` (Skip, Always, RenameNew,
RenameExisting) and `Options::select` apply everywhere. Every format reports each member live with its listing index.
`tar::run_with_policy` is the same API for tar and streams alone. See [one entry point](docs/extract-entry.md).

```rust
use zipfast::extract::{self, Cancellation, RunEvent};
let cancel = Cancellation::default();
let report = extract::run_with_policy(&path, &opts, password, &cancel, &Default::default(), |event: RunEvent<'_>| {
    if let RunEvent::MemberSucceeded { ordinal, name, .. } = event {
        println!("{ordinal} {name}");
    }
    Ok(())
})?;
```

### Library: choosing members

`extract::Options::select` takes an optional `MemberFilter`, a shared predicate over a `MemberRef` (decoded name,
stored name bytes when kept, `is_dir`, and the zero-based ordinal that `extract::list` gives the member). `None`
keeps the old behaviour. `run`, `run_with_password`, `run_with_zip_policy`, `run_with_zip_context` and
`run_rar_with_outcomes` apply the filter to ZIP, tar (plain or compressed), lone compressed files, and RAR4/RAR5,
in both `Mode::Test` and `Mode::Extract`:

```rust
use zipfast::extract::{MemberFilter, Options};
let opts = Options { select: Some(MemberFilter::new(|m| m.is_dir || m.name.ends_with(".mkv"))), ..opts };
```

The filter runs as members are listed. `MemberFilter::on_start` adds a hook asked, in archive order, about each
selected member as it starts to be written, once its output path is final (after any rename mode chose its name):
`StartDecision::Skip` writes nothing for it and reports it skipped (`RarSkipReason::Declined`), so a caller can count
and limit what is really written. It runs on extraction by tar, lone compressed files, legacy ZIP, 7z and RAR
whole-archive runs; the checked ZIP route, test mode and folders don't call it. `MemberFilter::all()` takes every
member, for the hook alone. Staged output files are created under `zipfast::STAGED_PREFIX` (`.zipfast-`), so a
temporary a crash leaves can be told from a finished file.

An unselected member is not written, tested, counted or reported. Folder entries are offered with `is_dir` set. An
unselected folder entry is not created, but the folders above a selected file still are. Path safety and overwrite
checks apply to selected members as before. ZIP doesn't read unselected entries. In a solid RAR archive, unselected
compressed members are still decoded for the dictionary history but not checked. `Summary::matched`,
`ZipRunReport::matched()` and `RarRunSummary::matched` count the members the filter took. A run that matches
nothing succeeds with zero matched, so the caller can choose its own exit status. Only these whole-archive runners
apply the filter. `RarSession::extract_selected`/`extract_selected_controlled`, progressive and persistent-partial
sessions, and `ZipReadStage::prepare_file` have their own member selection and refuse `select: Some(..)` with a typed
error before doing anything.

### Library: renaming on conflict

`extract::Overwrite` has `Skip` (default), `Always`, and two rename modes for an existing target. Neither ever
replaces a file:

| Mode | Matches | Existing `a.txt` | New member |
|---|---|---|---|
| `RenameNew(RenameStyle::Underscore)` | 7-Zip `-aou` | kept | `a_1.txt`, then `a_2.txt`, ... |
| `RenameNew(RenameStyle::Parenthesized)` | UnRAR `-or` | kept | `a(1).txt`, then `a(2).txt`, ... |
| `RenameExisting(RenameStyle::Underscore)` | 7-Zip `-aot` | moved to `a_1.txt` | `a.txt` |

The name is split at its last dot (`d/b.tar.gz` becomes `d/b.tar_1.gz`, `noext` becomes `noext_1`). `Underscore`
follows 7-Zip for a leading dot (`.bashrc_1`); `Parenthesized` follows UnRAR, which counts a leading dot as the
extension (`(1).bashrc`). `extract::renamed_name` spells a candidate. N starts at 1 and takes the first free value up
to `extract::RENAME_LIMIT` (10,000); beyond that the member fails with a typed error and the run goes on. A run makes
at most 2^20 rename attempts in all. A name too long to take a number is shortened from the end of its stem, at a
UTF-8 character boundary, to fit `NAME_MAX` (255 bytes). Each name is claimed with
`O_EXCL`, `renameat2(RENAME_NOREPLACE)` (Linux) or `renameatx_np(RENAME_EXCL)` (macOS), never looked up first, so
duplicate members in one run number sequentially and nothing is clobbered.

A symlink at the target is refused. A folder at a file member's target is handled as 7-Zip 26.06 does: `RenameNew`
leaves it alone and writes the member at the first free renamed name, and `RenameExisting` moves the folder, contents
and all, to that name with a no-replace rename and writes the member in its place; the move is reported as
`RenamedOutput::existing`. A protected path or alias of one (the archive, its volumes and `Options::protected_paths`)
at the target is only a name in use for `RenameNew`, which replaces nothing (`self.zip` extracted beside itself is
written as `self_1.zip`, like `-aou`), but `RenameExisting` refuses it, and refuses a folder holding one, since it
would move it. A candidate name that is a protected path is passed over. Folder members are reused, never renamed. The whole-archive runners (`run`, `run_with_password`,
`run_with_zip_policy`, `run_with_zip_context`, `run_rar_with_outcomes`, ZIP, tar, lone compressed files, RAR4/RAR5)
and `RarSession::extract_selected`/`extract_selected_controlled` support them. In controlled extraction the options'
rename mode settles every conflict: the control's `RarOverwriteMode` and the observer's `overwrite` are not asked.
Progressive and persistent-partial sessions refuse them with `FailureKind::InvalidCapability`, and
`ZipReadStage::prepare_file` refuses them with `ReadFault::InvalidPlan`, before doing anything.

Each rename is reported as an `extract::RenamedOutput { requested, path, existing }` in `Summary::renames`,
`RarRunSummary::renames` (kept in a terminal error's `partial` too, and delivered with each member's outcome as
`RarEntryOutcome::renamed`, so a live listing can print UnRAR's `Extracting  (1).bashrc  OK`), or as a
`ZipRunEvent::MemberRenamed` event from
`run_with_zip_policy`/`run_with_zip_context`, sent as each rename is made. `extract::run_with_renames` is
`run_with_password` with a terminal `RunError { error, renames }`; `run` and `run_with_password` keep returning
`Error`, and their report callback gets a line per rename as it happens (`<requested>: exists, written as <path>` or
`<requested>: existing file moved to <path>`). A member written at its own name gets no record. `RenameExisting`
records the move as soon as it happens, so an existing file moved aside for a member that then fails is still
reported (and stays at the renamed name). Staged runners (checked ZIP, `RarSession` selected extraction) move it
only once the new member is verified; the other runners claim names when the member starts, as 7-Zip does.
`RenameExisting` needs a no-replace rename or hard links: on FAT or exFAT the member fails with
`RarPolicyReason::RenameUnsupported`. The hard-link fallback removes the old name only after checking that both names
hold the linked file, and reports a link it had to leave behind.

`Overwrite` is now `#[non_exhaustive]`. Code that matched `Skip` and `Always` exhaustively needs a wildcard arm.

### Library: listing metadata

`extract::list` and `list_with_password` return one `extract::Entry` per member: `name`, `size`, `packed`, `mtime`,
`mtime_origin`, `crc32`, `method`, `dir`, `encrypted`, `solid`, `link`, `mode` and `attributes`.

- `mtime` counts seconds since 1970. `mtime_origin` (`Some` exactly when `mtime` is) says which clock it came from.
  `MtimeOrigin::Utc` is a true Unix time: a ZIP extended-timestamp (0x5455) or NTFS (0x000a) extra (the later of the
  two in the central extra field wins over the DOS fields), RAR 5.0, tar and the gzip `MTIME` field (0 means none).
  `MtimeOrigin::LocalWallClock` is MS-DOS date and time fields counted as if they were UTC: a ZIP without a time
  extra, and every RAR 4.x time. RAR 4.x's extended-time record only adds a second and a fraction to the local DOS
  time, as UnRAR reads it. 7-Zip prints a local wall-clock time as stored and converts a UTC time to local time.
- A lone compressed file (`.gz`, `.xz`, `.bz2`, `.zst`, `.lz4`, `.Z`, `.lzma`) is extracted with the gzip `MTIME` when it holds one, and
  otherwise with the compressed file's own modification time, as 7-Zip, `gunzip -N`, `xz` and `bzip2` do. The listing
  shows only the gzip `MTIME`.
- `mode` holds Unix mode bits: ZIP host 3, RAR 4.x host Unix, RAR 5.0 host Unix and tar.
- `attributes` holds raw Windows attribute bits (`FILE_ATTRIBUTE_*`, the source of 7-Zip's `D R H S A` column):
  the low 16 bits of a ZIP entry's external attributes for hosts 0 (FAT), 6 (HPFS), 10 and 11 (NTFS) and 14 (VFAT),
  and the file attributes of a RAR 4.x MS-DOS, OS/2 or Win32 member or a RAR 5.0 Windows member. It is `None`
  for Unix and other hosts, and for tar and gzip.

`RarSession::volumes()` yields a `RarVolumeMetadata` per volume. `flags()` is normalized to the RAR 5.0 `MHFL_*`
bits, keeping only the volume and solid bits for RAR 4.x. `rar4_flags()` returns the RAR 4.x main header's raw
`MHD_*` flags, and `new_numbering()` says whether the set is named `NAME.partN.rar` (always for RAR 5.0, and
`MHD_NEWNUMBERING`, 0x0010, for RAR 4.x) rather than `NAME.rar`, `NAME.r00`, ..., as UnRAR's `VolNameToFirstName`
needs to know.

## Builds tuned for a processor

A plain `cargo build --release` runs on any x86-64 or Apple silicon processor, and picks AVX2 at run time where
that pays. `scripts/build-tuned.sh` builds variants tuned for newer processors into `dist/`:

| Build | For |
|---|---|
| `zipfast-x86_64-v3` | x86-64-v3: AVX2, BMI2, FMA (Intel Haswell, AMD Zen 1 and later) |
| `zipfast-x86_64-v4` | x86-64-v4: AVX-512 (Intel Skylake-X and Ice Lake, AMD Zen 4 and later) |
| `zipfast-apple-m4` | Apple M4 and later |
| `zipfast-apple-m5` | Apple M5 and later |

The x86 builds are made on an x86-64 machine and the Apple ones on an Apple silicon Mac; `scripts/build-tuned.sh v3`
makes just one. A tuned build uses its processor's instructions everywhere, the Rust runtime included, so on a
processor that lacks them it stops on an illegal instruction.

## Compatibility sweep

`scripts/compat-sweep.sh [PARENT]` builds archives with the real tools on the machine (bsdtar in every format and
filter, Info-ZIP `zip` with each option, `ditto`, and bare gzip, bzip2, xz, lzma, zstd, lz4 and compress files),
extracts each with a reference tool and with zipfast, and diffs the trees: bytes, names, file, folder or link type,
link targets, mtimes within 2 s and modes. It works only in a fresh `mktemp -d` directory under PARENT (default `$TMPDIR`) and prints its path.
Results go to `WORKDIR/results.tsv`, details to `WORKDIR/log/`.
`REF7Z=<dir with a Linux amd64 7z>` adds archives written and extracted by 7-Zip in Docker; `RAR4REF=<dir>` compares
against UnRAR's checksums for a RAR4 corpus; `BIG=1` adds one member over 4 GiB per family. Delete WORKDIR after.

## Sources

ZIP follows PKWARE's published APPNOTE. tar follows the POSIX ustar and pax interchange formats and GNU tar's
manual for its extensions. The RAR 5.0 block layout follows RARLAB's published "RAR 5.0 archive format" technical note.

## License

zipfast by xbmc4lyfe.

zipview by xbmc4lyfe.

The project source uses the [Reciprocal Public License 1.5](LICENSE).
Zipview's [license and Exhibit B](crates/zipview/LICENSE) accompany its source.
See section 6 for source availability, notices, and attribution for
deployed extensions. Dependencies retain their own licenses.
See [Contributing](CONTRIBUTING.md) for sending changes upstream.

### RAR4 metadata, Stored and version-29 LZ reads

RAR sessions identify the archive, volume, and member format. RAR4 metadata
retains the raw name, host, method, unpack version, flags, and DOS time bits.
The normalized member fields map Unix host attributes to the existing Unix
category. Names use strict UTF-8 or the bounded RAR4 Unicode representation.
Legacy codepage names that cannot be decoded as UTF-8 stop with an unsupported
encoding error. Control-character escaping remains the display caller's
responsibility.

DOS timestamps have no time zone. RAR4 uses the existing ZIP UTC projection
for valid civil dates and preserves the original bits for callers choosing
another policy. Extended times retain the odd second and subsecond fields.

Stored and version-29 LZ reads verify exact size and CRC before
publication or verified selected printing. LZ methods 0x31 through 0x35 use
64 KiB through 4 MiB dictionaries. An independent member resets the decoder; a
member flagged solid goes on from the window, tables and recent distances the
member before it left, starting where that member's end-of-file marker says
(at a token, or at new tables). Members a run skips or doesn't select are still
decoded through, unwritten, when a later member needs their history. A member
split over volumes feeds one decoder across its parts, checking each non-final
part's CRC of its packed bytes. RAR 3.x AES-128 (`-p`) decrypts ahead of the
decoder; it has no password check value, so a wrong password shows as a
checksum or decoder error.
Decoding is serial and retains bounded incremental input state. Real decoded
bits are required. Once the declared output is complete, remaining declared
packed bytes are charged and drained without claiming canonical tail encoding.
Empty compressed members use the same logical-completion policy and verify the
empty CRC. PPM blocks decode with PPMd variant H (the model asks for its memory,
up to 256 MiB, which is committed in 64 KiB pages as the model writes it; a
progressive session's `decoder_window` and a selected session's window limit
bound it, and a held filter block, with a typed limit failure) and
are buffered 4 KiB ahead until the member's data is all in; LZ matches, filter
records and the end-of-file escape inside them are honoured, and a solid member
goes on from the model. Filter records are parsed and the six standard filters
(E8, E8E9, ITANIUM, DELTA, RGB and AUDIO), recognised by their program's length
and CRC as UnRAR does, run natively on output held back until each block is
complete (at most the VM's 256 KiB); any other VM program reports a typed
unsupported outcome, and no unsupported command can be skipped into CRC
success. Unpack versions 15 and 20/26 decode with RAR 1.5's and 2.0's own
engines, solid streams included. Before version 20 a non-final part's CRC field
holds no packed-data hash, so only the member CRC is checked. A progressive
session over complete volumes ends an archive that has no end-of-archive block
at a block boundary, as UnRAR does, when every member so far predates RAR 2.9
(unpack version below 29, no extended-time record); a later archive cut there
is still truncated, and a session following growing files waits for more. A
filter block reaching into the next solid member, which UnRAR would keep
waiting, is refused as corrupt: its bytes are the first member's output.
RAR 1.5 and 2.0 encryption, symbolic
links and special files retain explicit exclusions. Members from hosts above
Unix (MacOS, BeOS) are plain files with no mode, and old file revisions are
written under their stored name, `;n` suffix included (UnRAR `-ver`). Encrypted headers,
old embedded comments and legacy service layouts stop catalogue construction.
The existing catalogue, selected decode and spool limits apply to RAR4.
Catalogue opening reserves a conservative temporary capacity allowance of
12 times each header length before allocating header and name scratch.

With the `persistent-partials` feature, plain RAR4 Stored members, unsplit or
split across volumes, can be extracted to persistent partial files. Holes are
skipped and reported exactly, filled later from plaintext or archive bytes, and
verified with each non-final part's header CRC, which pins a bad fill to its
volume, and with the member CRC. Encrypted RAR4 members, RAR4 header
encryption and compressed RAR4 members are refused with typed errors before any
output. See [docs/persistent-partials.md](docs/persistent-partials.md).
