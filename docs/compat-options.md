# 7-Zip and UnRAR compatibility options

Five fields of `extract::Options`, and one typed error detail, let a caller that imitates 7-Zip or UnRAR (Prybar's
`7z` and `unrar` modes) get their behaviour where zipfast's own default differs. Every default keeps zipfast's
behaviour, so a caller that sets them to `Default::default()` (or `None`) sees no change.

Adding these fields breaks `Options { .. }` struct literals that list every field: add

```rust
special_entries: Default::default(),
fallback_mtime: None,
compressed_tar: Default::default(),
version_naming: Default::default(),
preexisting_links: Default::default(),
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
