# Rebuilding a lost RAR 5.0 volume's headers from a sibling

When a RAR 5.0 volume is dead in every copy of a release, a downloader can borrow its packed data from another
release of the same file and write the volume back exactly as rar wrote it, so the set's par2 files verify it.
Everything around the packed data follows from an intact sibling volume of the same set.
`zipfast::rar5::rebuild_volume_headers` produces those bytes and says where the data goes:

```rust
use zipfast::rar5::{PartHashes, TargetVolume, rebuild_volume_headers_from};

let target = TargetVolume {
    index: 12,                                   // 0-based: name.part13.rar
    volume_len,                                  // exact, from par2 or yEnc
    last: false,
    hashes: PartHashes::of_reader(&mut borrowed)?, // a continuing part records its packed bytes' hashes
    data_len: Some(borrowed_len),
    packed_offset: Some(member_offset),          // optional: checks a stored member's layout
};
let frame = rebuild_volume_headers_from(&mut sibling_file, &target)?;
// write frame.head, then frame.data_len borrowed bytes (at frame.data_offset), then frame.tail
```

## API

- `rebuild_volume_headers(sibling_head, sibling_tail, &TargetVolume) -> Result<VolumeFrame, VolumeHeadersError>`.
  `sibling_head` is the sibling from offset 0 up to its packed data, and `sibling_tail` is everything after that
  data. The packed data is never read.
- `rebuild_volume_headers_from(&mut impl Read + Seek, &TargetVolume)` reads those two pieces from the sibling
  volume and seeks past its data. A tail over 1 MiB (`MAX_SIBLING_TAIL`) is refused.
- `PartHashes::of_reader` / `of_bytes`: the CRC32 and BLAKE2sp of a continuing part's packed bytes.

`TargetVolume`:

| field | meaning |
|---|---|
| `index` | the volume's number, 0-based |
| `volume_len` | its exact length |
| `last` | whether it is the set's last volume. The member's last part is in it, and its end header says no more volumes follow |
| `hashes` | what the file header records. For a part that continues, the CRC32 (and with `-htb` the BLAKE2sp) of the part's packed bytes. For the member's last part, the whole file's unpacked CRC32 or BLAKE2sp, taken from another copy of the file (the alt release's last volume, an SFV). Only the hash the sibling carries is needed |
| `data_len` | the borrowed data's length, checked against the room the volume leaves. Required for a first volume that is not the last, and for a middle volume rebuilt from the set's last volume |
| `packed_offset` | where this part starts in the member's packed data. For a stored member it proves the layout: the part continues from a previous volume exactly when this is not 0, and the member ends in the set's last volume |

`VolumeFrame { head, data_offset, data_len, tail, padding, split_before, split_after }`. `head` is the volume up to
the packed data and `tail` is everything after it, zero padding included (`padding` counts those zeros). Together
they are `volume_len` bytes.

## What is rebuilt

- **Signature and main header:** the sibling's, with the target's volume number (none for the first volume) and its
  quick open locator offset, written at the sibling's field width.
- **File header:** the sibling's, byte for byte, apart from:
  - the split flags;
  - the data size (at the sibling's width: rar pads it);
  - the CRC32 field and BLAKE2sp record;
  - for an encrypted member, the crypt record's "checksums are keyed" flag. rar sets it only on the last part.
- **Tail:** the quick open service header caching that file header, the end of archive header and the padding, from
  [`rebuild_volume_tail_with`](rar5-volume-tail.md). The set's quick open mode comes from the sibling when its part
  is 4096 bytes or less.
- **Data length:**
  - *Middle volume:* rar fills it to the same reserve after the data as the sibling. That reserve is the sibling's
    tail length, and it pins the data length.
  - *Last volume:* nothing follows its end header, so its length pins the data length.

The target is taken to hold one part of the sibling's member, filling the volume the way the sibling's part fills
it. That is how rar lays out a member spanning many volumes.

## Refused (`VolumeHeadersError`)

| error | when |
|---|---|
| `NotRar5`, `Truncated`, `Corrupt` | the sibling is not a sound RAR 5.0 volume |
| `EncryptedHeaders` | `-hp`: every header starts with a random IV |
| `RecoveryRecord` | `-rr`: its data covers each volume's own bytes |
| `PerVolumeRecord` | the sibling holds an archive comment or other service header before its file, or anything but the quick open data, the end header and zeros after its data |
| `LayoutDiffers` | the sibling holds more than one file, or a file not split across volumes, or its member cannot have a part in the target (it starts in the sibling after the target, or ends before it), or `packed_offset` contradicts the layout |
| `MissingHash(Crc32 \| Blake2sp)` | the sibling's header records that hash and `hashes` lacks it |
| `EncryptedFinalPart` | `-p` and the target holds the member's last part: rar keys its checksums with the password |
| `SizeMismatch` | no data length makes the volume's size add up, or the one that does is not `data_len` |
| `FirstVolumeUnproven` | a first volume that is not the last, without `data_len` or with the last volume as the sibling. rar writes an archive comment only into the first volume, and only packed data shorter than the room the reserve leaves shows one |
| `ReserveUnknown` | a middle volume from the set's last volume without `data_len` |
| `QuickOpenMode` | a small (4096 bytes or less) target part whose quick open data depends on a mode the sibling does not show, without `data_len` to decide |
| `Doubt(TailDoubt)` | the rebuilt tail is not certain |

Hostile siblings and target values never panic. Arithmetic is checked, and allocation is bounded by the sibling's
bytes plus at most 1 MiB of padding.

## Not detectable

Without `packed_offset` (and for a compressed member, which has no checkable layout), a target that holds the end
of the member and the start of another cannot be told from one holding a single part. Ask only for volumes that
hold one part of the sibling's member. With RAR's normal layout that is every volume between a member's first and
last.

## Checked against

`tests/rar5_volume_headers.rs`:

- **Committed sets:** every volume of 16 rar 7.30 sets in `tests/fixtures/rar5-volume-headers/*.frames` (each
  volume's bytes around its data, its length and its part's hashes), rebuilt from every sibling, or from neighbours
  in the 175-volume set. The variants are:
  - stored, `-m3`, solid, `-htb` stored and compressed;
  - `-qo+` and `-qo-`;
  - `-p` and `-p -htb`;
  - `-k`, extended times, an archive comment;
  - three files, 175 volumes (2-byte volume numbers);
  - `-hp` and `-rr`, which are refused.

  About 4,800 rebuilds are byte for byte. Each refusal is checked to be the one the pair calls for, and nothing
  refused is ever rebuilt with wrong bytes.
- **Full sets:** when present (`ZIPFAST_RAR5_VOLUME_HEADER_SETS`, by default
  `zipfast-test-fixtures/rar5-volume-headers`), the hashes are computed from the real packed data. The run also
  covers:
  - two larger sets (700 KB stored, 500 KB `-m1 -htb -qo+`);
  - the [volume tail](rar5-volume-tail.md) sets: quick open modes, small pieces, several files per volume;
  - with `ZIPFAST_Z_FIXTURES`, RustyGet's RAR 5.0 z-fixture sets (F01-F06, F11, F12: 750 KB volumes; stored, `-m3`,
    `-m5`, AES, `-hp`, two files).

  Every volume holding one part rebuilds from its neighbours byte for byte. The rest are refused for their reason.
- **Hostile siblings:** every single-byte change and truncation of sibling heads and tails, and extreme target
  values.
