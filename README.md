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
  printing of unencrypted, unsplit Stored regular files and non-solid version-29
  LZ compressed regular files. PPM and VM/filter commands remain excluded. The catalogue retains
  unsupported member metadata and reports typed payload exclusions.
- RAR 5.0 archives: listing, testing and extracting stored and compressed files (every method, solid archives,
  filters), including files split across `name.partNN.rar` or `name.rar`/`name.r00` volume sets, self-extracting
  stubs, CRC32 and BLAKE2sp checks, modification times and Unix permissions. Big files decode on several cores.
- ZIP archives: stored, deflated, bzip2, LZMA, xz and zstd entries, ZIP64, self-extracting stubs, UTF-8 and code page 437 names,
  Unix permissions, and extended or NTFS timestamps. Checked streaming reads support ZipCrypto and WinZip AES
  (all strengths, AE-1/AE-2); see [checked ZIP reads](docs/zip-checked-reads.md) for policy, staging and legacy caps.
- tar archives, plain or compressed with gzip, xz, zstd or bzip2 (`.tar.gz`, `.tgz`, `.tar.xz`, `.tar.zst`,
  `.tar.bz2` and so on): POSIX ustar and pax (long names, big sizes, fractional times), GNU long names and base-256
  sizes, and pre-POSIX headers. A compressed file that holds no tar archive comes out as the one file it
  compresses. xz files written in blocks (`xz -T0`) decode on several cores.
- Member maps (`zipfast::map`): a typed header listing of RAR4, RAR 5.0 (including `-hp` with a password) and
  ZIP archives from memory or a range source, mapping each stored member's output offsets to per-volume packed
  spans; see [member maps](docs/member-map.md).
- Reading a stored member from any output offset (`zipfast::map::extract_member_from`, `MemberReader`): plain,
  RAR 5.0 and RAR 4.x AES and WinZip AES members stream their plaintext suffix from the packed bytes that offset
  needs, checking the parts they cover, for example to finish a partial output from another copy; see
  [extract-member-from](docs/extract-member-from.md).
- Probing (`zipfast::probe`): from a file's first bytes (one Usenet article) and optionally its last, tells bare
  media (mkv, webm, mp4, mov, avi, MPEG-TS, M2TS, ASF, MPEG-PS) from RAR4, RAR 5.0 and ZIP, picks the first media
  member, says whether it is stored, compressed, data-encrypted or behind encrypted headers, and whether its bytes
  can be borrowed; see [probing](docs/probe.md).
- Extraction never writes outside the destination: `..`, absolute paths, drive letters and links in the way are
  refused.

Remaining RAR4 capabilities, links, 7z and the rarer ZIP methods (Deflate64, PPMd) are next.

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

An unselected member is not written, tested, counted or reported. Folder entries are offered with `is_dir` set. An
unselected folder entry is not created, but the folders above a selected file still are. Path safety and overwrite
checks apply to selected members as before. ZIP doesn't read unselected entries. In a solid RAR archive, unselected
compressed members are still decoded for the dictionary history but not checked. `Summary::matched`,
`ZipRunReport::matched()` and `RarRunSummary::matched` count the members the filter took. A run that matches
nothing succeeds with zero matched, so the caller can choose its own exit status. Only these whole-archive runners
apply the filter. `RarSession::extract_selected`/`extract_selected_controlled`, progressive and persistent-partial
sessions, and `ZipReadStage::prepare_file` have their own member selection and refuse `select: Some(..)` with a typed
error before doing anything.

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

Stored and version-29 non-solid LZ reads verify exact size and CRC before
publication or verified selected printing. LZ methods 0x31 through 0x35 use
64 KiB through 4 MiB dictionaries and reset state for each independent member.
Decoding is serial and retains bounded incremental input state. Real decoded
bits are required. Once the declared output is complete, remaining declared
packed bytes are charged and drained without claiming canonical tail encoding.
Empty compressed members use the same logical-completion policy and verify the
empty CRC. PPM and VM/filter commands encountered before completion report typed
unsupported outcomes. No unsupported command can be skipped into CRC success.
Compressed versions 15, 20 and 26, solid, encrypted and split payloads, symbolic
links, special files, old file revisions, and unsupported host attributes retain
explicit exclusions. Encrypted headers,
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
