# 7-Zip and UnRAR compatibility options

Fields of `extract::Options`, and one typed error detail, let a caller that imitates 7-Zip or UnRAR (Prybar's
`7z` and `unrar` modes) get their behaviour where zipfast's own default differs. Every default keeps zipfast's
behaviour, so a caller that sets them to `Default::default()` (or `None`) sees no change.

Adding these fields breaks `Options { .. }` struct literals that list every field: add

```rust
special_entries: Default::default(),
fallback_mtime: None,
compressed_tar: Default::default(),
version_naming: Default::default(),
preexisting_links: Default::default(),
refused_link_placeholder: false,
restart_from_first_volume: false,
replace_placed_links: false,
keep_broken: false,
attempt_continued_members: false,
encrypted_links: Default::default(),
damaged_input: Default::default(),
unsupported_filters: Default::default(),
unverified_output: Default::default(),
salvage_truncated_zip: false,
seven_zip_strict: false,
unix_modes: Default::default(),
backslashes: Default::default(),
```

The reference behaviour below is 7-Zip 26.06 and UnRAR 7.30 beta 1 for Linux x86-64, run in Docker with
`--network none` and `TZ=UTC`. `tests/compat_options.rs` checks each point.

## `special_entries`: tar devices and FIFOs

`SpecialEntries::Refuse` (the default) fails a character device, block device or FIFO member of a tar, cpio, xar or
ISO 9660 image (`dev: devices and pipes are not extracted`), and a `SelectedEntry` for one is refused as not a regular
file. `SpecialEntries::EmptyFile` makes it an empty regular file with the member's mode bits and modification time,
and a `SelectedEntry` for it reads as zero bytes. That is what 7-Zip does:

| `ustar.tar` (`f.txt`, character device `dev` 4,7) | 7-Zip 26.06 | zipfast, `EmptyFile` |
|---|---|---|
| `7z x` / `7z e` | `dev` empty, `-rw-r--r--`, 2020-01-02 03:04:05, exit 0 | the same |
| `7z t` | exit 0 | `Summary::errors` empty, 2 files |
| `7z x -so ustar.tar dev` | 0 bytes | `SelectedEntry` reads 0 bytes |

No device node or pipe is ever made. Sockets and other unknown cpio, xar or ISO 9660 entry types, old GNU sparse
members in a ustar header and GNU multi-volume continuations are refused under both choices. A compressed tar
follows the same choice (its members are staged until the stream checks out, as before).

`SelectedEntry` takes the choice through `SelectOptions` (`SelectOptions::from(&options)`, or
`SelectOptions::new().special_entries(..)`) with `SelectedEntry::open_cancelable_with_options` or
`open_cancelable_with_zip_limit_and_options`; the older `open*` functions keep the defaults.

## `fallback_mtime`: entries without a time

`fallback_mtime: Option<SystemTime>` is the time given to an output whose entry records none. The entries keep saying
they have none: `Entry::mtime` and `SelectedEntry::modified()` stay `None`, so a caller can tell and choose.

| entry without a time | how it shows | 7-Zip 26.06 | UnRAR 7.30 |
|---|---|---|---|
| 7z member without `MTime` (`7z a -mtm=off`) | `Entry::mtime == None` | archive file's mtime (files, folders and links) | n/a |
| RAR 4.x member with DOS date and time 0 | `Entry::mtime == None` | archive file's mtime | 1979-11-30 00:00:00 local time, what the zero DOS date reads as |
| RAR 5.0 member without a time field | `Entry::mtime == None` | archive file's mtime | the extraction time |

So a 7-Zip imitation passes the archive file's mtime, and an UnRAR imitation passes 1979-11-30 00:00:00 for RAR 4.x
and `None` for RAR 5.0. A time the entry does record is never replaced.

It is applied to files, folders and symbolic links by the whole-archive runners for RAR (`extract::run`,
`run_with_password`, `run_rar_with_outcomes`), 7z (`sevenzip::run` and the dispatchers), legacy ZIP and tar, by
`RarSession::extract_selected` and `extract_selected_controlled`, and by progressive sessions (files, links and
folders). A persistent-partial file keeps its member's recorded metadata, which its journal binds, so a member
without a time there is left with the time it was written at. `SelectedEntry` writes nothing itself: its caller
dates what it writes.

## `compressed_tar`: one file for `.tgz` and friends

`CompressedTar::Members` (the default) reads the tar inside a gzip, bzip2, xz, zstd, lz4, lzma or `.Z` layer member
by member. `CompressedTar::Whole` reads the decompressed stream as one file, as 7-Zip does for `x`, `e` and `x -so`:

| archive | 7-Zip 26.06 `x` writes | zipfast, `Whole` |
|---|---|---|
| `pax.tgz` (gzip header without a name or MTIME) | `pax.tar`, archive's mtime | the same |
| `a.tbz`, `a.tbz2`, `a.txz`, `a.tzst` | `a.tar`, archive's mtime | the same |
| `b.tar.gz`, `b.tar.bz2`, `b.tar.xz`, `b.tar.zst` | `b.tar`, archive's mtime | the same |
| `named.tgz` (`gzip -N` of `inner.tar`) | `inner.tar`, the gzip header's MTIME | the same |

The name and time come from the code that names a lone compressed file: the gzip header's stored name (its last
component, cleaned like a member name) when there is one, else the archive name with its compression ending
replaced; the gzip MTIME when set, else the archive file's own mtime. The stream is the only entry: ordinal 0 for a
`MemberFilter`, index 0 for `SelectedEntry` (with `SelectOptions::compressed_tar`), and the one entry
`tar::list_with_options` lists. A plain tar, cpio, xar, WIM or ISO 9660 image is read as members under both choices.

## `version_naming`: RAR 5.0 file revisions

Older file revisions (`rar -ver`) are written only when the run takes them (`MemberFilter::with_versions`, or
`RarSelection::with_versions` for `RarSession`). `version_naming` says what they are called:

| `nested.rar`: `dir/sub/a.txt` (revision 2, then current), `b.txt` (revision 1) | written as |
|---|---|
| `VersionNaming::Semicolon` (default), UnRAR `x -ver` | `dir/sub/a.txt;2`, `dir/sub/a.txt`, `b.txt;1` |
| `VersionNaming::SevenZipDir`, 7-Zip 26.06 `x` | `[VER]/2/dir/sub/a.txt`, `dir/sub/a.txt`, `[VER]/1/b.txt` |
| `SevenZipDir` with `flatten`, 7-Zip `e -y` | `a.txt` (the current file, written last, wins), `b.txt` |

7-Zip extracts revisions without being asked, so a 7-Zip imitation passes `MemberFilter::with_versions` together
with `SevenZipDir`. `r5extra.rar` (both members revision 3) comes out as `[VER]/3/owned.txt` and
`[VER]/3/timed.txt` under 7-Zip and under zipfast with these choices. `VersionNaming::name(name, version)` gives the
name for a caller's own listing.

## `preexisting_links`: archive links through links already in the destination

Before an archive's symbolic link is made, its target is followed through the links on its way as they exist then.
The link is refused when that leads out of the destination, whichever choice is made. With `d -> sub` and
`x -> ../outside` already in the destination:

| archive link | `PreexistingLinks::FollowInside` (default), UnRAR 7.30 | `PreexistingLinks::Refuse`, 7-Zip 26.06 |
|---|---|---|
| `f -> d/file.txt` | made | refused |
| `l -> d`, then `m -> l/file.txt` | both made | `l` refused, `m` made (nothing at `l`) |
| `e -> x/file.txt` | refused | refused |

UnRAR also makes `e`; zipfast never makes a link that leads out of the destination.

With `Options::replace_placed_links` (UnRAR 7.30 `e -y`), a symbolic link this run placed itself (same device and
inode as the link it made) is not a pre-existing link: a later member of the same name replaces it by rename, never
following it, as a file replaces a file (tar, ZIP, 7z and RAR runs, and `RarSession::extract_selected`, which takes
the same `Options`, for a link or a file over it; `Overwrite::Skip` keeps it). `extract_selected_controlled` does it
too, through its own overwrite decision (`RarOverwriteMode::Always` replaces, `Skip` keeps, `Ask` asks the observer): its
binding accepts a symbolic link at the target only when it is one this run placed (device and inode). Off (the default) it
is refused, as 7-Zip 26.06 does (`7z e dirlink_unix.rar`: "Dangerous link via another link was ignored", exit 2). A link from before the run is still refused (`a symlink is in the way`). The
checked ZIP route (`run_with_policy`) does this for a link over a link, but still refuses a file over a link it placed.

## `refused_link_placeholder`: an empty file where a link was refused

When 7-Zip refuses a dangerous link ("Dangerous link via another link was ignored") it writes an empty regular file
at the link's path. A later member under that path then fails, its parent being a file, and 7-Zip exits 2. zipfast
leaves nothing by default, so the later member's folder is created as a real one. With `d/` already in the
destination and an archive holding `s -> d/inner`, then `s/new.txt`, under `PreexistingLinks::Refuse`:

| | `refused_link_placeholder: false` (default) | `true`, 7-Zip 26.06 |
|---|---|---|
| `s -> d/inner` | refused, nothing at `s` | refused, `s` an empty file |
| `s/new.txt` | written in a new folder `s/` | fails: `s` is not a folder |

It applies to every symbolic link refused for its target: one that leads out of the destination, lexically
(`../x`, an absolute target) or through another link, or one `PreexistingLinks::Refuse` refuses. A refused hard
link or file copy leaves nothing. The placeholder is checked and written as any output file is: never through a
link, under the `Overwrite` mode (a rename mode gives it the renamed name, `Skip` leaves what is there), and
recorded as a file this run wrote. The member is reported refused, or failed, as it is without the option. A test
run writes nothing. The whole-archive runners for RAR, 7z, ZIP and tar, `RarSession` extraction and progressive
sessions honour it (a progressive session still stops at the refused link, as without the option).
`tests/links.rs` and `tests/rar5_links.rs` check these points.

## `encrypted_links`: encrypted RAR 5.0 links and a wrong password

`rar a -p` encrypts file data but leaves headers in the clear, so a link member's target (its redirection record)
is readable whatever the password. UnRAR 7.30 reports the wrong password for the member and creates nothing;
7-Zip 26.06 doesn't check the password for a link at all. `Options::encrypted_links` picks one:
`EncryptedLinks::Verify` (the default), `EncryptedLinks::VerifyFirst` (UnRAR's reporting order, for Prybar's unrar
mode) or `EncryptedLinks::PlaceUnverified` (7-Zip's, for Prybar's 7z mode).
It applies on every route: `extract::run*`, `RarSession::extract_selected` and `extract_selected_controlled` (from
the `Options` they take), `RarSession::test_selected` (from `RarSessionOptions::encrypted_links`, as it takes no
`Options`), and progressive sessions (from `ProgressiveOptions`' extract options).

With `Verify`, a redirection member whose header carries an encryption record (Unix or Windows symbolic link,
junction, hard link, file copy) is placed, or passes a test, only when its password check value verifies the
password. No password fails it as `RarFailure::PasswordRequired`, a wrong one as `RarFailure::WrongPassword`, as an
encrypted data member fails; nothing is created. A record without a check value, or with a check value whose
checksum doesn't match, can't verify any password, and a link has no data to check one against: the member is
refused as `RarFailure::EncryptedIntegrity` with `RarIntegrityReason::UnverifiableLinkPassword`, even with the right
password. A progressive session stops at such a member, as it does at a wrong password.

`Verify` checks the password once the member is known to be placed or tested: a member skipped for an existing
target under `Overwrite::Skip` is reported `Skipped(ExistingTarget)`, and a hard link or copy whose target the run
didn't extract fails on its target (`RarPolicyReason::HardLinkTarget`; a progressive session stops with
`UnsafePath`), whatever the password. `VerifyFirst` checks it first, as UnRAR 7.30 does: `unrar x -o- -pwrong` over
links that already exist prints "Incorrect password" and exits 11, and a hard link with a missing target is reported
as the wrong password. Under `VerifyFirst` a password that doesn't verify fails such a member as above
(`WrongPassword`, `PasswordRequired`, `EncryptedIntegrity`/`UnverifiableLinkPassword`) before the overwrite decision
and the target checks; one that verifies goes on to them as usual. Nothing is placed or replaced either way, so this
changes only what is reported. An older file revision is still skipped before anything, on every route. A
`RarSession` test run checks the password first under every mode.

The order on every route (`extract::run*`, `RarSession::extract_selected` and `extract_selected_controlled`, a
progressive session) is: (1) under `VerifyFirst` only, the password; (2) the overwrite decision: under
`Overwrite::Skip` (and `RarOverwriteMode::Skip` on the controlled route) a link member whose target already exists,
whatever is there (a file, a folder, a symbolic link an earlier run placed), is reported `Skipped(ExistingTarget)`
and nothing else about it is checked, as UnRAR 7.30's `unrar x -o- -ppw` over an earlier run's output is "All OK";
(3) for a link that will be placed, every link check (a target that leaves the destination, a hard link or copy of a
file the run didn't extract, the path checks, protected paths, `replace_placed_links`), then under `Verify` the
password, then the placing. A skipped member places and touches nothing, so it needs none of the checks in (3).
Under `Overwrite::Skip` a symbolic link at a member's target (any member's, not just a link's) is skipped as an
existing target the same way, rather than refused as `RarPolicyReason::Symlink`: nothing is written through it or
over it. A symbolic link in a folder above the target is still refused.

With `PlaceUnverified`, the password isn't checked for such a member (no key is derived): with a wrong password,
with none, or with no check value, the link is placed (or passes a test) and reported as any placed link is,
`RarOutcome::Verified`, with the password evidence `RarPasswordEvidence::Unverified` in its checks, so a caller can
tell it from a verified link (a progressive session reports `MemberOutcome::Verified`/`Tested`, which carries no
password evidence; a caller that set the option knows an encrypted link there went unchecked). Every other link check
still applies: a target that leaves the destination, a hard link or copy of a file the run didn't extract,
protected paths, `replace_placed_links` and the overwrite decision. RAR 4.x symbolic links (whose target is their
encrypted data) and members with data still need their password.

What 7-Zip 26.06 (`7zz`, macOS arm64) does with such archives:

| archive | `x -p<wrong>` | `x` (no `-p`) | `t -p<wrong>` |
|---|---|---|---|
| symlinks and a junction with a check value | links created, exit 0, "Everything is Ok" | same | "ERROR: Wrong password" per link, exit 2 |
| the same without a check value | links created, exit 0 | same | exit 0 |
| hard link and file copy | hard link created; copy "Unsupported Method", exit 2 | same | exit 0 |

So `x` reports no error for an encrypted link under a wrong password or none, and `PlaceUnverified` matches it. `t`
does check a check value it has (a wrong password is an error there, and with no `-p` it asks for one), which
`PlaceUnverified` doesn't mirror: a test passes those links too, with `RarPasswordEvidence::Unverified`.

## 7z wrong passwords: how the member failed

7z keeps no password check value, so a wrong password shows by its effect, and 7-Zip words the two effects
differently. A member's `SevenZipError::WrongPassword { failure }` now says which (`failure: None` is the run-level
failure for encrypted headers):

| folder | 7-Zip 26.06 `t -pwrong` | `failure` | `Summary::errors` line |
|---|---|---|---|
| compressed (LZMA, LZMA2, ...) under 7zAES: `aes.7z`, `*_wrongpw.7z` | `Data Error in encrypted file. Wrong password?` | `Some(EncryptedFailure::DataError)` | `<name>: data error in encrypted file: wrong password?` |
| Copy (or filters only) under 7zAES: `aes_copy.7z` | `CRC Failed in encrypted file. Wrong password?` | `Some(EncryptedFailure::CrcFailed)` | `<name>: CRC failed in encrypted file: wrong password?` |

The first sign in a folder decides for every later member of it. On the checked dispatcher the member's error is
`ReadFault::PasswordCheckFailed { cipher: CipherKind::Aes, seven_zip: Some(failure) }`; ZIP's own password failures
have `seven_zip: None`. `EncryptedFailure::seven_zip_message()` returns 7-Zip's text.

## Starting from a later RAR volume

UnRAR 7.30 `x`/`t` given a later volume (`multi.part2.rar`, `name.r00`) whose first member continues from an earlier
one starts over at the set's first volume when every volume back to it exists and opens, and extracts everything;
with a volume missing in between it extracts what starts in the given and later volumes and reports the continued
member as needing a previous volume (`RarSkipReason::MissingStart`). The whole-archive runners (`extract::run`,
`run_rar_with_outcomes` and the dispatchers) do it with `Options::restart_from_first_volume`, and a `RarSession` when
opened with `RarSessionOptions::restart_from_first_volume`. Both are off by default: the run starts at the volume given
and walks forward only, as 7-Zip 26.06 does (`7z x multi.part2.rar` reports file2 as a data error, extracts file3 and
never opens part1). With the session option, `RarSession::restarted_from()` then names the volume it started at
(None when it started at the one given). A selection by listing position (`MemberRef::ordinal`) counts from the
volume given, as UnRAR's listing of that volume does; a session restarted at the first volume lists from there.

## `keep_broken`: a failed file keeps what was written

By default a file whose extraction fails is removed, so a later run never takes it for finished. With
`Options::keep_broken`, as 7-Zip 26.06 `x`/`e` and UnRAR 7.30 `-kb` do, it stays with what was written (cut to that
length) and its times set, and the member is still reported failed:

| Runner | Kept | Checked against 7-Zip 26.06 |
| --- | --- | --- |
| RAR | a CRC or BLAKE2sp mismatch, a missing volume, a decoder or size failure, once the file was placed (empty when nothing was written yet) | `r5misc.rar` `blake.bin` (CRC Failed), `multi_broken.part1.rar` `file2.txt` (missing volume: empty), `r5solid.rar` (Data Error: both empty) |
| ZIP | a missing or truncated volume, a CRC or data failure; the bytes before the cut are written first, and a streamed member cut off before its descriptor is read to the cut | `s.zip.001` / `streamed.zip.001` `c.bin` (Unexpected end of data: the 11,832 bytes of the first piece); `-pwrong aes.zip` / `crypto.zip` (every file empty) |
| ZIP (checked route: a single-file `.zip` through `run_with_policy`) | a member failing on its own data (a wrong password, a CRC, a cut), published under every check a verified file passes except the read's completion, at the length written | `-pwrong aes.zip` / `crypto.zip` (every file empty) |
| RAR (`RarSession::extract_selected` and `extract_selected_controlled`) | a member failing on its own data, published as a verified one would be (every recheck, hook and overwrite decision alike) | UnRAR `-kb` |
| 7z | a member CRC failure, including a wrong password shown by the CRC; a decode failure ("Data Error") is not kept, as 7-Zip keeps none | `-pwrong encrypted_files.7z`: `baz.txt` kept, `foo.txt` not |
| RAR (persistent-partial sessions, `ProgressiveSession::new_partial`) | a stored member failing its final CRC32 or BLAKE2sp that the session doesn't turn into a `DeclaredBad` hole (a member in one part, say; an encrypted part failing its own check still ends the session): its finish is committed with every byte written, `MemberFinished` reports `PersistentComplete` with `Verdict::Bad` (no archive metadata applied), and the session goes on with the next member instead of ending | (no reference tool has persistent output; `docs/persistent-partials.md`, "Damaged members") |

Not kept: links, and a failure writing the output (that stops the run). Whatever the option, a 7z member that fails
before anything of it is kept no longer leaves the folders its placing created (`-pwrong aes.7z` leaves no empty
`text/`, as 7-Zip leaves none). A RAR member whose filter is unsupported is
kept empty; 7-Zip writes its data unfiltered (`generic_delta_padding_mutation.rar`), which zipfast does with
`unsupported_filters` (below).

## `attempt_continued_members`: a member continued from an earlier volume

A RAR run started at a later volume meets a member whose start is in an earlier one. By default it is passed over as
lacking its start (`RarSkipReason::MissingStart`). With `Options::attempt_continued_members`, as 7-Zip 26.06 `x` does,
it is extracted from what this volume holds and fails: a stored member writes the bytes it has and fails its checksum
("CRC Failed": `win-oldvol.r00` `split.bin`), a compressed one fails without decoding ("Data Error":
`multi.part2.rar` `file2.txt`). With `keep_broken` the file stays, matching 7-Zip's tree; the run's later members come
out as usual. (`restart_from_first_volume`, UnRAR's behaviour, goes back for the start instead.)

## `salvage_truncated_zip`: a ZIP cut short, read from its local headers

A single ZIP file cut short (`head -c 30000` of an archive holding one 50,000-byte deflated member) has lost its
central directory and end record. By default zipfast refuses it as not a ZIP archive (`ReadFault::CheckedFormat`,
`Error::NotAnArchive` from `extract::run`), because the checked route needs the central directory. 7-Zip 26.06 walks
the local headers from the start instead: it extracts what it can, says "Unexpected end of archive" and exits 2, and
`7zz x` keeps 29,955 bytes of the cut member.

With `Options::salvage_truncated_zip`, when the checked route finds no end record (and nothing else went wrong) in one
file that starts with a local header (or the spanning marker before one), and is not a split or spanned set, the file
is read by walking its local headers (`LegacyRoute::TruncatedZip`, the walk byte-split sets cut short already use):

- the members whose local headers lie before the cut are tested or extracted;
- the one the cut reaches fails as `archive is truncated` (not "missing volume"), and keeps what decoded with
  `keep_broken`; without it the partial file is removed;
- the run then reports `archive is truncated` as a `LegacyError`, as a byte-split set cut short reports its missing
  piece.

Events come as for other legacy runs (`LegacyDiagnostic`, `LegacyError`). An archive whose end record is found is read
on the checked route as ever, option or not. `extract::run` honours the option too, and
`zip::list_detailed_with_options` lists such a file (`Listing::truncated`, `Listing::unexpected_end`). The other
listings (`inspect_projected_cancelable`, `zipfast l`) and `SelectedEntry` take no `Options` and still refuse it.
`tests/zip_salvage_truncated.rs` checks each point.

## `damaged_input`: RAR archives with damaged headers

`DamagedInput::Refuse` (the default) fails a RAR 4.x or RAR 5.0 run, listing or catalogue at the first header that
fails its checksum or doesn't parse, as before. `DamagedInput::Salvage` reads on the way UnRAR 7.30 does, and
`DamagedInput::Resync` also looks past an unreadable header. Whatever was read past comes back as `HeaderDamage`
records (volume, offset, `HeaderDamageKind`, the member name when the header parsed, where reading resumed), so a
caller can warn and exit as the tools do: UnRAR prints "Corrupt header is found" / "NAME - the file header is
corrupt" and exits 3, 7-Zip prints "Headers Error" (or "Unexpected end of archive") and exits 2.

What UnRAR 7.30 (`x`, `t`, `l`) does, from archives with one byte changed, cut short or with bytes inserted, and what
`Salvage` does:

| damage | UnRAR 7.30 | 7-Zip 26.06 | `Salvage` |
|---|---|---|---|
| a file header fails its checksum but parses (a CRC byte, or its name, changed) | "the file header is corrupt"; the member is listed and extracted as the header reads (a changed name is the name written), its data checksum deciding; the rest follows; exit 3 | "Headers Error", stops there, exit 2 | the same as UnRAR: `ChecksumMismatch` with the name, the member listed and extracted as read |
| the main header fails its checksum | "Main archive header is corrupt", reads on | "Headers Error" | `ChecksumMismatch`, reads on |
| a RAR 4.x block's type byte changed (checksum fails, type unknown) | the block is passed over by its size, the rest extracted | "Headers Error" | `ChecksumMismatch`, passed over by its size |
| a header that can't be read (size field changed, garbage inserted before it) | "Corrupt header is found" or "Unexpected end of archive", nothing after it is read, exit 3 | "Headers Error", stops | `Unreadable` (or `UnexpectedEnd`), the rest of the volume passed over, what came before stands |
| the volume ends inside a header or its data | "Unexpected end of archive" | "Unexpected end of archive" | `UnexpectedEnd`, the volume ends there |
| a RAR 5.0 volume without its end header | no message | "Unexpected end of archive", exit 2 | `UnexpectedEnd` at the volume's length |
| only a member's data damaged | "checksum error", the rest extracted | "CRC Failed" | as before, with any `damaged_input`: the member fails, nothing is recorded as header damage |
| a RAR 4.x archive cut inside its main header | "Main archive header is corrupt", lists "0 files" (`Details: RAR 1.5`) | | opens with no members, `UnexpectedEnd` |

Neither tool looks past an unreadable header for the next one. `Resync` does, for callers (RustyGet) that would rather
recover the members after a damaged stretch, such as a hole still waiting for repair, garbage between blocks, or the
rest of a member's compressed data after its header was hit: from the byte after the unreadable header it searches the
rest of the volume for a file, service or end header (never a main header) whose fixed fields are plausible (RAR 5.0:
a one-byte flags field, a file or service header of at most 8 KiB, an end header of at most 32 bytes; RAR 4.x: a
known host, unpack version and method, and a name that fits) and whose checksum passes, and reads on from there
(`HeaderDamage::resumed_at`). Under `Resync` a damaged header of an unknown type is unreadable too, rather than passed
over by the size it claims, so the search starts from it. Each search is one forward pass, read in chunks from 64 bytes
doubling to 1 MiB; all the searches in a volume together may read and checksum at most 16 times the volume's length
plus 1 MiB, so a volume stays linear whatever its bytes are, and megabytes of random (compressed-looking) data are
crossed well within that. Past the bound, or when a `RarSession` catalogue's read budget (`RarCatalogueLimits::
read_bytes`) has no room left, the search gives up and passes over the rest of the volume rather than fail. A RAR 4.x
header checksum is 16 bits, so in a long damaged stretch a resync can land on a false header: what it reads from it
fails its own checks (a member's data checksum, the next header's framing) and the search goes on. A whole-archive
run checks its `Cancellation` while it searches. Bytes passed over (an unreadable stretch, a resync) break a solid
archive's history: a solid member after them fails as lacking it (`RarFailure::SolidHistoryUnavailable`) until a
non-solid member starts a new history, in the whole-archive runners and in `RarSession` alike.

Encrypted headers (`-hp`) are never salvaged, by either choice: there a failed checksum is how a wrong password shows.
A RAR 5.0 encryption header that fails its checksum is never read as it stands either (its salt and KDF parameters
would make every later header look like a wrong password): it is an unreadable header. A damage record keeps at most
1 KiB of a member's name.
A member whose data fails its checksum fails as before (`keep_broken` keeps what was written).

Where it applies:

- the whole-archive RAR runners (`extract::run`, `run_with_password`, `run_rar_with_outcomes`, and `run_with_policy`
  / `run_with_zip_policy` through the legacy route): `Summary::damaged_headers`, `RarRunSummary::damaged_headers`, and
  `ZipRunReport::damaged_headers()` (a count; each record is also sent as a `LegacyDiagnostic` line);
- listing: `extract::list_detailed_with_options` (`Listing::damaged_headers`, `Listing::headers_damaged()`, and
  `Listing::unexpected_end()` for `UnexpectedEnd`);
- `RarSession`, through `RarSessionOptions::damaged_input`: the catalogue reads past the damage, its members list and
  extract (`extract_selected`, `extract_selected_controlled`, printing) as any other, and
  `RarArchiveMetadata::damaged_headers()` says what was read past;
- `Volume::open_damaged` and `Volume::take_damage` for callers walking blocks themselves;
- progressive sessions (`ProgressiveSession::new`, `from_sealed_memory`), through `ProgressiveOptions::extract`: each
  damaged header is a `ProgressiveEvent::HeaderDamaged { volume, damage }`, delivered before anything read from that
  header (so just before the `MemberStarted` of a member whose header failed its checksum). See "Damaged headers in a
  progressive session" below.

Persistent-partial sessions (`ProgressiveSession::new_partial`) honour it too, with the same events and hole rules; a
member read from a damaged header, or after one, is bound to its header's position so that a restart over the same
bytes, or over a header repaired since, finds it again (`docs/persistent-partials.md`, "Damaged headers"). Listings
that take no `Options` (`extract::list`, `list_detailed`, `inspect*`) refuse it too. The CLI takes `--salvage` and
`--resync` (for `l`, `t`, `x`, `e`; a listing of anything but RAR stays as it is), prints each damaged header and a warning, and exits 1.
`tests/rar_salvage.rs` checks each point.

### Damaged headers in a progressive session

A progressive session reads bytes as its source delivers them, and a range that is missing now may be filled later
(an article fetched again, PAR2 repair, another copy). So only bytes the source has delivered are ever judged damaged:

- A header the source has not delivered yet (`RangeRead::NotYet`, or a volume not there yet) is waited on, as under
  `Refuse`; it is never damage. When it arrives it is read as any other header.
- A header inside a range the source answers as a `Hole` is not damage either: the session stops with `HeaderHole`, as
  under `Refuse`, since the bytes may yet be repaired. Run the session again once they are.
- A resync never searches across a `Hole`: the next header may be inside it, so the search stops with `HeaderHole`.
  On a source whose end isn't known yet (`GrowingFileVolumes`) a search that has not found a header waits for more
  bytes, as reading a header does.
- Only a header whose bytes were delivered and are wrong (a checksum that fails, fields that don't parse, a header or
  data running past the volume's known end) is salvaged, exactly as the whole-archive runners do: the same members,
  the same bytes and the same `HeaderDamage` records (`volume` is the volume's name as the session asked for it).

Under salvage the session takes the volume's length from the source (`SourceInfo::length`, unless it is
`Advertised(u64::MAX)`), so a header or data running past it is a volume cut short (`UnexpectedEnd`). The rest of a
damaged volume is passed over as in the whole-archive runners: a volume set goes on with its next volume (a sealed set,
or a declared last volume, may end there), anything else ends. A folder whose damaged header claims data is created and
its data passed over. A resync's work is bounded as the whole-archive one's, by 16 times the furthest offset read in
the volume plus 1 MiB, and it charges its window (at most a chunk and one candidate header) to `MetadataBytes`. Bytes
passed over break a solid archive's history: the next solid member stops with `SolidHistoryUnavailable`.
`tests/progressive_salvage.rs` checks each point.
## `unsupported_filters`: a RAR 3.x/4.x member using a VM filter zipfast doesn't run

RAR 3.x/4.x carries filters as programs for its virtual machine. zipfast runs the standard ones (E8, E8E9, ITANIUM,
DELTA, RGB, AUDIO), recognised by their program's length and CRC-32; any other program is unsupported. By default
(`UnsupportedFilters::Fail`) such a member fails as `RarFailure::Unsupported(RarUnsupported::Rar4Feature("VM/filter
payload"))` and nothing of it is written (`keep_broken` keeps it empty).

7-Zip 26.06 decodes the member anyway and writes each block such a program filters as decoded, unfiltered; the
standard filters in the same member still apply. With `UnsupportedFilters::WriteUnfiltered` zipfast does the same:

| `generic_delta_padding_mutation.rar` | 7-Zip 26.06 | zipfast, `WriteUnfiltered` |
| --- | --- | --- |
| `7z x` / `7z e` | "ERROR: Unsupported Method : itanium_synthetic_bundles.bin", exit 2, the 1 MiB file written (SHA-256 `aff2543c…76c5`) with its time | the same file, with its time; the member reported failed with `RarFailure::Unsupported(RarUnsupported::FilterWrittenUnfiltered)` |
| `7z t` | the same error, exit 2 | the same failure, nothing written |
| `7z x -so` | the same error, exit 2, the same bytes streamed | `SelectedEntry` with `SelectOptions::unverified_output(UnverifiedOutput::Emit)`: the same bytes to the sink, then an `UnverifiedWritten` error (see `unverified_output` below) |

The member's checksum is not checked (the unfiltered data can't match it), so the failure says the file is written
but unverified: a caller imitating 7-Zip prints "Unsupported Method" and exits 2. It reaches every report a RAR run
makes: a line in `Summary::errors` ("unsupported method: VM filter, written unfiltered"), `RarOutcome::Failed` in
`run_rar_with_outcomes` and `RarSession` extraction events. Only a member a block of which was actually written
unfiltered gets it.

In a solid stream the following members decode as usual, since RAR 3.x filters act on the output and never on the
history the stream goes on from. 7-Zip agrees: with one of `tiny_e8e9.exe`'s two filter programs in
`solid_e8_filter_member_offset.rar` changed (its check byte still holding) and a third member continuing the stream,
it reports only `tiny_e8e9.exe` and writes the third member whole. A program whose check byte (the XOR of its other
bytes) doesn't hold is damaged data: 7-Zip reports "Data Error", and with `WriteUnfiltered` zipfast fails the member as
corrupt data, writing nothing (by default it fails as unsupported, as before).

Honoured by the whole-archive runners (`extract::run`, `run_with_password`, `run_rar_with_outcomes` and the
dispatchers) and by `RarSession::extract_selected` and `extract_selected_controlled`, where the file is published as
a verified one would be (every recheck and hook alike). `RarSession` test and print runs, progressive and
persistent-partial sessions and `FeedDecoder` take no such choice (progressive sessions have no outcome for a member
written but unverified) and fail the member as unsupported; `SelectedEntry` writes it unfiltered under
`SelectOptions::unverified_output` (below). `tests/rar_unsupported_filters.rs`
checks each point.

## `unverified_output`: the bytes of a member that fails

UnRAR and 7-Zip hand over what they decoded of a member before it failed; zipfast by default doesn't (a printed or
streamed member shows only once verified, and `keep_broken` keeps a RAR member cut off by a missing volume empty, as
7-Zip `x` does). `UnverifiedOutput::Emit` does as the tools do. The member is still reported failed with the failure
it had (a missing volume, a checksum, a data error), and a sign says its bytes went out unverified, so a caller prints
the tool's error and exits as it would (UnRAR: exit 3 or 6; 7-Zip: exit 2). `UnverifiedOutput::Withhold`, the
default, changes nothing.

| field | route | under `Emit` | sign |
| --- | --- | --- | --- |
| `Options::unverified_output` | `extract::run`, `run_with_password`, `run_rar_with_outcomes`, the dispatchers | with `keep_broken`, a RAR member cut off by a missing volume keeps every byte UnRAR 7.30 `x -kb` keeps (without `keep_broken` it is removed, as `unrar x` removes it) | the member's usual failure ("missing volume") |
| `Options::unverified_output` | `RarSession::extract_selected`, `extract_selected_controlled` | with `keep_broken`, the same member is written and kept (by default a session doesn't write it at all) | `RarOutcome::Failed` with `RarFailure::MissingVolume` or `MissingSplitContinuation` |
| `Options::unverified_output` | persistent-partial sessions (`ProgressiveSession::new_partial`) | with `keep_broken`, a stored member cut off by a missing volume or a set truncated inside it keeps the bytes already written (as ever) and is reported before the session's failure | `MemberFinished` with `MemberOutcome::PersistentUnverified { missing, .. }`, then the session's `MissingVolume` or `Truncated` |
| `RarPrintOptions::unverified_output` | `RarSession::print_selected` (`unrar p`) | a member failing on its own data (checksum, decoder error, missing volume, a wrong RAR 3.x password shown by its checksum) has what was decoded of it printed; one cut off by a missing volume is decoded from the volumes there | `RarOutcome::Failed`, and `RarEntryOutcome::unverified_bytes = Some(n)` |
| `SevenZipPrintOptions::unverified_output` | `sevenzip::print_selected_with_options` (`7z x -so`) | a 7z member failing on its data has what 7-Zip 26.06 streams of it printed | its line in `Summary::errors`, and an `UnverifiedMember { index, name, bytes }` in `Summary::unverified` |
| `SelectOptions::unverified_output` | `SelectedEntry` (`open_cancelable_with_options`, `open_cancelable_with_zip_limit_and_options`), 7z and RAR | 7z: as `print_selected_with_options`; RAR 3.x/4.x: a VM filter zipfast doesn't run leaves its block unfiltered (as `UnsupportedFilters::WriteUnfiltered`); other formats already stream as they decode | `read` fails with an `Error::Io` carrying `UnverifiedWritten { bytes, cause }` (`UnverifiedWritten::of`); `cause` is the failure without `Emit`, `Error::Unsupported(UNFILTERED_SELECTED)` for a RAR member written unfiltered |

`SelectOptions::from(&options)` copies `Options::unverified_output`.

### A RAR member cut off by a missing volume

UnRAR 7.30 decodes what the volumes there hold, but not to the last bit. From `multi_broken.part1.rar`, two RAR 3.00
sets and `text.rar` made into a cut-off first volume at 47 places (`tests/fixtures/unverified-output/README.md`):

- RAR 3.x/4.x (LZ): an LZ token whose first bit lies in the last 30 bytes of the data there is not decoded, nor
  anything after it. In a PPMd block or a RAR 1.5/2.0 stream every byte decoded is handed over (not checked against
  UnRAR).
- RAR 5.0: a symbol starting in the last 128 bits of the data there is not decoded; a block of which fewer than 1,024
  bytes (header included) are there is not decoded at all, and then the last symbols of the block before, within
  128 bits of the data's end, are left out too. `RarSession` decodes a member it knows is cut off on the calling
  thread whatever its thread settings, so this always holds there. The whole-archive run finds the cut only at the
  missing volume: blocks of a big member it decoded on worker threads can't give back their last symbols, so a cut
  within 16 bytes past one of them may write up to a few bytes more than UnRAR.

| first volume alone | `unrar p` / `x -kb` | `Withhold` + `keep_broken` | `Emit` + `keep_broken`, `RarPrintOptions` `Emit` |
| --- | --- | --- | --- |
| `multi_broken.part1.rar` `file2.txt` | 6,198 bytes | empty (7-Zip `x`) | the same 6,198 bytes |
| `multivol_newnaming_rar300.part01.rar` | 53,664 bytes | the 32 KiB flushed before the volume was missed | the same 53,664 bytes |
| `r5-partial.part1.rar` (RAR 5.0) | 55,043 bytes | the whole blocks written | the same 55,043 bytes |

`7z x -so` on such a member is not imitated: 7-Zip 26.06 streams nothing of a RAR 3.x/4.x one and decodes a RAR 5.0
one to the end of the data (55,084 bytes for `r5-partial`), and a `SelectedEntry` keeps streaming what it did before.

### 7z members under `7z x -so`

| case | 7-Zip 26.06 `x -so` (exit 2) | `Emit` |
| --- | --- | --- |
| a member failing its CRC (`copy_crc.7z`) | every byte decoded, "CRC Failed" | the same bytes |
| a data error in an LZMA stream (`lzma_bad.7z`, solid `solid_bad.7z`) | the bytes before the error, "Data Error" | the same bytes |
| a later member of a solid block an earlier one broke | nothing | nothing |
| a folder whose packed stream is cut short (`lzma_trunc.7z`) | the bytes decoded, "Data Error" | the same bytes |
| a wrong password, LZMA folder (`-pwrong enc.7z`) | nothing, "Data Error in encrypted file. Wrong password?" | nothing |
| a wrong password, Copy folder (`-pwrong enc_copy.7z`) | the decrypted garbage, "CRC Failed in encrypted file. Wrong password?" | the same bytes |

### A member carrying more than its declared size

A member whose data gives more bytes than its header declares fails its size check, and every reference mode stops
at the declared size: UnRAR 7.30 `x -kb` and `p` (exit 3, checksum error) and 7-Zip 26.06 `x` and `x -so` (exit 2,
"CRC Failed" or "Data Error") write exactly the declared bytes, for RAR 5.0 and RAR 4.x (stored, LZ, PPMd), 7z (Copy,
LZMA, LZMA2) and ZIP (stored, Deflate). zipfast does the same in every route: a file kept with `keep_broken` (RAR,
ZIP on both routes, 7z), `RarSession` extraction and printing under `Emit`, `sevenzip::print_selected_with_options`
and `SelectedEntry` under `Emit` (whose `UnverifiedWritten::bytes` is then the declared size). Without `keep_broken`
the file is removed as before; a `SelectedEntry` under `Withhold` streams as before.

| `tests/fixtures/declared-size` | member | declared | carried | every mode writes |
| --- | --- | --- | --- | --- |
| `r5-stored.rar`, `r4-stored.rar`, `zip-stored.zip` | stored | 1 | 60,000 | 1 byte |
| `r5-lz.rar` (`-m3`), `zip-deflate.zip` | compressed | 1,000 | 211,990 | 1,000 bytes |
| `r4-lz.rar` (RAR 2.9 LZ), `r4-ppmd.rar` (PPMd) | compressed | 100, 1,000 | 787, 98,304 | 100, 1,000 bytes |
| `7z-copy.7z`, `7z-lzma.7z`, `7z-lzma2.7z` | folder unpack size | 1,000 | 12,000 | 1,000 bytes |

`tests/declared_size.rs` checks each point, on the calling thread and on decode workers, and a stored RAR 5.0 member
declaring 1 byte and carrying 5,000,000.

Not covered: a Copy folder whose header gives fewer packed than unpacked bytes is refused as malformed headers
(7-Zip streams the packed bytes and reports "Data Error"); an LZMA2 folder big enough to be decoded on several threads
hands over only what its threads finished before the error. `tests/unverified_output.rs` checks each point against the
reference tools' output.


## `seven_zip_strict`: 7-Zip's end checks on a 7z folder and a ZIP local header

7-Zip checks more than each member's CRC. Once it has decoded a 7z folder to its end, it also checks that every coder
in the folder ended where its stream ends. Separately, it compares each ZIP member's local header with the member's
central directory record. zipfast by default checks the CRC only. `seven_zip_strict: true` makes these checks too. It
defaults to `false`, and with `false` nothing changes.

### 7z folders

These checks run only when a folder is decoded to its end. Selecting only a solid block's earlier members skips them,
as `7z t archive.7z a.txt` does. Whatever the checks find, every member that passes its CRC is still written or
printed. A folder that fails gets one line in `Summary::errors` and a `FolderDamage { folder, kind, detail }` in
`Summary::folder_damage`. The line looks like 7-Zip's (`#N: data error: ...` or `#N: there are some data after the end
of the payload data: ...`). 7-Zip 26.06 reports such a folder as `Data Error : #N` or `There are some data after the
end of the payload data : #N` and exits 2, even though every member's CRC passes.

| coder | 7-Zip 26.06 reports it (zipfast does too) | 7-Zip 26.06 passes it |
| --- | --- | --- |
| LZMA | the range coder's final code is not 0; bytes after the data (`Data Error : #N`) | an end marker after the data |
| LZMA2 | bytes after the end marker; a chunk starting after the folder's size (`Data Error`) | **a missing end marker** |
| PPMd | the range coder's final code is not 0; bytes left over (`Data Error`); a first byte that isn't 0 fails every member (`Data Error : name`) | |
| BCJ2 | main, call or jump stream bytes, or range coder bytes, left unused; the range coder's final code is not 0 (`Data Error`); a first range coder byte that isn't 0 fails every member (`Data Error : name`) | |
| Deflate, Deflate64 | more output past the folder's size (`Data Error`); input after the end block (`data after the end`) | |
| BZip2 | a second stream after the first (`data after the end`); 7-Zip's coder decodes one stream, so members held in a second one fail (`Data Error : name`) | |
| Copy | packed bytes beyond the unpacked size (`data after the end`) | |

A coder feeding another one is stopped at the folder's end. A Deflate or Deflate64 coder behind a Copy coder must already be at its last block's end by then; otherwise it is a `Data Error`, although the same stream on its own may have empty blocks after the output. zipfast checks each coder before the coders feeding it, so every coder can first read what it still needs.

The LZMA2 missing end marker is not an error in 7-Zip 26.06, so zipfast doesn't flag it either. In strict mode an LZMA2
folder is decoded on one thread, because the end checks need the whole stream in order. A folder whose input fails to
decode before its end gets the usual member failures, and a `FolderDamage` when every member had already passed.

7-Zip sometimes reports a damaged last range coder byte as `Data Error : name` for the last member. zipfast then reports
that member's CRC failure and the folder. Both tools exit 2 and write the same bytes.

### ZIP local headers

7-Zip 26.06 compares each local header with its central directory record: the CRC-32, the compressed size, the size,
the method and the data descriptor flag. When the local header sets the data descriptor flag, 7-Zip doesn't compare
its CRC-32 or sizes. It also skips a size of `0xFFFFFFFF` (ZIP64), and it never compares the time, the version or the
name. If any compared field differs, 7-Zip reports `Headers Error : name`, fails the member and exits 2. `7z x` leaves
that member's file empty.

With `seven_zip_strict`, zipfast fails such a member without decoding it. The failure is a `LocalHeaderMismatch {
ordinal, name, crc32, packed_size, size, method, descriptor_flag }`, where each flag names a field that differs:

- The legacy route (`extract::run` and friends) puts it in `Summary::local_header_mismatches` and gives it a line in
  `Summary::errors`.
- The checked route (`run_with_zip_policy`) fails the member with `ReadFault::LocalHeaderMismatch` and counts it in
  `ZipRunReport::local_header_mismatches()`.

With `keep_broken`, the member's file is left empty, as 7-Zip `x` leaves it.

Differences from 7-Zip:

- A mismatch on the first member makes 7-Zip report a headers error for the whole archive and walk the local headers
  instead. zipfast reports just that member.
- When only the data descriptor flag differs, 7-Zip still writes the member's data. zipfast fails the member before
  writing it.
- A link is compared too and fails unread. 7-Zip `x` leaves an empty regular file in its place; zipfast places nothing, even with `keep_broken`.

### Routes

The whole-archive runners and the dispatchers honour the option for 7z, both on the checked ZIP route and on the legacy
ZIP route. `sevenzip::print_selected_with_options` honours it too, through `SevenZipPrintOptions::seven_zip_strict`.
`ZipReadSession`, `SelectedEntry`, and progressive and persistent sessions ignore it. The progressive and persistent
sessions decode neither 7z nor ZIP.

`tests/seven_zip_strict.rs` checks each point against the fixtures in `tests/fixtures/seven-zip-strict`, whose
README gives 7-Zip 26.06's verdict on each.
