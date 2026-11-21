# Rebuilding the end of a RAR 5.0 volume

When the end of a RAR 5.0 volume is lost (its last Usenet articles, say) after the archived data ends, the missing bytes are derivable from the volume's surviving start and its length. `zipfast::rar5::rebuild_volume_tail` produces them as rar writes them, so a rebuilt volume matches the original byte for byte and passes par2. It also says when it cannot be sure.

```rust
let tail = zipfast::rar5::rebuild_volume_tail(&surviving_start, volume_len, Some(more_volumes))?;
if tail.exact {
    // write tail.bytes at tail.offset, then tail.padding zero bytes: the volume is now the one rar wrote
}
```

## Input

- **`head`:** the surviving start of the volume, at least through its last file header. The packed data under the headers need not be present (or correct): only the headers are read.
  - Bytes past the end of the last file's data are compared with the rebuilt ones. If they differ, `doubt` is `DiffersFromSupplied`.
  - A damaged header there marks where the rebuilt tail starts.
- **`volume_len`:** the volume's exact length in bytes, taken from the par2 file description or the yEnc `=ybegin size=`. Don't take it from the NZB: its segment sizes count encoded articles.
- **`more_volumes`:** whether volumes follow this one.
  - With `None`, a last file that continues in the next volume implies more volumes.
  - Otherwise the flag is inferred as clear, and the result is not claimed exact (`MoreVolumesInferred`).

## Output

`RebuiltTail { offset, bytes, padding, exact, doubt }`:

- **`offset`:** where the last file's packed data ends.
- **`bytes`:** the volume's headers from `offset`:
  - **Quick open service header (`QO`):** present when the main header's locator names one. Its data caches exact copies of file headers in the volume, each with its distance back from the service header. rar writes some of its fields padded with continuation bytes, and the rebuild does the same. Which headers are cached depends on the set's quick open mode (see below).
  - **End of archive header:** its "more volumes" flag comes from `more_volumes`.
- **`padding`:** how many zero bytes follow `bytes` up to `volume_len`. It is a count rather than bytes, so an untrusted length never allocates. rar reserves room for the quick open data before it knows its size, so a middle volume usually ends with a few zeros. If the default mode skipped the volume's last header, its reserved room is added, so up to about 85 zeros in rar's output. With `-qo+` and many small files, rar reserves about 6 more bytes per cached header, so such middle volumes are doubted (`UnexpectedPadding`) rather than claimed exact.

## Quick open mode

- **`-qo+`:** rar caches every file header in the volume's quick open data.
- **Default `-qo`:** rar caches only the files with more than 4096 bytes of packed data in that volume. It skips smaller pieces, empty files and directories, and writes no service header at all when nothing is left to cache. The main header's locator offset is then 0.
- **Why it matters:** a volume holding such a small piece, for example an `.nfo` before the movie or the first few KiB of the next episode, has two possible tails. Its start does not show which.

To handle it:

- **Learn the mode:** call `zipfast::rar5::quick_open_mode(&intact_volume)` on any intact volume of the same set. It returns `Some(QuickOpenMode::All)` or `Some(QuickOpenMode::LargeFiles)` when that volume holds a small piece, and `None` when it shows nothing either way.
- **Pass it on:** give the result to `rebuild_volume_tail_with(head, volume_len, more_volumes, mode)`. A supplied mode is trusted, because the volume's length cannot always reveal a wrong one, so take it from the set and never guess it.
- **Without it:** a volume with a small piece is rebuilt in whichever mode fits its length. If both fit, it is rebuilt in the default mode and doubted with `QuickOpenMode`.

`exact` is true only when the bytes are certain to be rar's. Otherwise `doubt` says why:

- **`QuickOpenElsewhere`:** the locator puts the quick open header somewhere other than right after the last file's data. Something the surviving bytes do not show lies in between, for example a further file header that was lost too.
- **`UnexpectedPadding`:** the padding is not what rar usually leaves. That means any padding after the last volume's end header, or after a middle volume's, more than 64 bytes plus the room reserved for a skipped last header. Either `volume_len` is wrong, the volume holds headers the surviving bytes don't show, or rar reserved unusually much. A middle volume's length that is off by only a few bytes can't be detected, which is why it must be exact.
- **`QuickOpenMode`:** see "Quick open mode" above.
- **`MoreVolumesInferred`:** see `more_volumes` above.
- **`MoreVolumesContradicted`:** `more_volumes` is `Some(false)`, but the last file continues in the next volume.
- **`LastFileEnds`:** more volumes follow, but the last file the surviving bytes show ends in this volume. A further file header may have been lost with the tail, because rar normally fills a middle volume with a file that continues. Supplying the bytes past that file's data settles it.
- **`DiffersFromSupplied`:** see `head` above.
- **`LargeQuickOpen`:** quick open data of 16 KiB or more, beyond the field widths seen in rar's output.

## Refused

- **Encrypted headers (`-hp`):** `Error::Unsupported`. Every header starts with a random IV, so no rebuild can match.
- **An archive comment (`-z`) or any other service header before the files:** `Error::Unsupported`.
- **A recovery record (`-rr`):** `Error::Unsupported`. Its data covers the whole volume.
- **Not RAR 5.0:** `Error::NotAnArchive` for anything but a RAR 5.0 volume at offset 0.
- **Too short:** `Error::Truncated` when `head` ends before a file header does.

Data-encrypted archives (`-p`) rebuild normally: their file headers are plain.

## Tested against

The rebuild was written from the RAR 5.0 format description. It was checked against sets made by rar 7.30 with `-ma5 -m0 -v`, covering middle and last volumes:

- quick open off, on and default;
- `-p`;
- three files sharing volumes;
- small pieces under both quick open modes: a volume ending with a 3516-byte first piece, an `.nfo` before the movie, and a last volume holding 2020 bytes;
- a member name long enough for a 197-byte file header;
- a 3 GB member in 200 MB volumes, where the default quick open mode still caches the member's header.

- **Committed tests:** `tests/rar5_volume_tail.rs` rebuilds header-only copies of four such volumes. The packed data is replaced by zeros, since only headers are read. It also covers each doubt and refusal.
- **Full sets:** `every_volume_of_the_rar_made_sets_rebuilds_byte_for_byte` cuts and rebuilds every volume of the full sets, with the mode taken from the set by `quick_open_mode`, plus the first and last 4 KiB of the 3 GB member's volumes. That is 85 volumes, all byte for byte. It also checks that, without the mode, no volume is ever claimed exact with the wrong bytes. It skips unless `ZIPFAST_RAR5_TAIL_SETS` (or the default fixtures path) holds them.
- **par2:** byte equality implies equal par2 block hashes, so par2 is not run.
