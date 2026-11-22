# RAR header frames: rebuilding and writing volume headers

`zipfast::rar5::frame` reads and writes RAR header blocks byte for byte, and `zipfast::rar5::rebuild_volume_head` rebuilds a RAR 5.0 volume's lost start from its own last bytes. With [`rebuild_volume_tail`](rar5-volume-tail.md) for the other end, a downloader can rebuild a volume's headers on both sides of its data without a copy of the format of its own.

## RAR 5.0 blocks (`rar5::frame`)

| API | does |
|---|---|
| `put_vint(out, v)`, `put_vint_min(out, v, min_len)`, `vint_len(v)`, `read_vint(bytes, at) -> Option<(value, len)>` | variable length integers; `put_vint_min` pads with continuation bytes the way rar writes fields it fills in later (the locator, the quick open data size) |
| `seal_header(fields) -> Vec<u8>` | a header block from its fields (type, flags and on): CRC32, size, fields |
| `reseal_header(&mut block)` | recomputes a block's CRC32 after a same-width field was patched |
| `read_block(bytes, at) -> Result<Option<Block>>` | one block: `kind`, `flags`, `fields`/`extra` ranges, `data_len`, `header_end`; CRC32 checked, data area not read |
| `MainHeader::{parse, encode, for_volume}` | the main header field by field: archive flags, volume number, locator (offsets with their padded widths), other extra records kept whole; `for_volume(i)` sets volume `i`'s number as rar does (none for the first) |
| `end_of_archive(more_volumes) -> Vec<u8>` | the end header exactly as rar writes it; `false` turns a middle volume's end into a last volume's |

Every written block reads back with zipfast's own reader, and the main and end headers of every rar-made RAR 5.0 volume in the test corpus are written back byte for byte (`tests/rar_frames.rs`).

## RAR 1.5-4.x blocks (`rar5::frame::rar4`)

| API | does |
|---|---|
| `MARKER` | the 7-byte marker block |
| `header_crc(block) -> Option<u16>`, `seal(&mut block)` | the 16-bit header checksum: the low 16 bits of the CRC32 of the header from `HEAD_TYPE` to `HEAD_SIZE`; for RAR 2.x headers holding a comment, only what precedes it (a main header with `MHD_COMMENT`: its first 13 bytes; a file header with `LHD_COMMENT`: its fields through name, salt and extended time), as RAR 2.x writes and UnRAR checks |
| `block(head_type, flags, fields)` | any header from its fields, `HEAD_SIZE` and `HEAD_CRC` filled in |
| `read_block(bytes, at)` | one block: type, flags, `head_size`, `header_end`, `data_len` (a file header's packed size with its high 32 bits, or `ADD_SIZE`); checksum checked |
| `MainHeader::{new, parse, encode}` | the main header (volume, solid, new numbering, first volume, ...; the reserved fields and an encryption version byte kept) |
| `FileHeader::{parse, encode}` | file and service headers: sizes (64-bit under `LHD_LARGE`), host, CRC, time, version, method, attributes, the raw name field, salt, extended time, and any SubData kept whole; continuation flags `LHD_SPLIT_BEFORE`/`LHD_SPLIT_AFTER` are plain flags |
| `EndOfArchive::{new, volume, parse, encode}` | the end block: `new(next)` is rar 2.x/3.x's 7-byte form; `volume(next, data_crc, number)` is WinRAR's 20-byte form with the CRC32 of the volume's bytes before the block, the volume number and 7 reserved bytes |
| `unicode_name_field(name) -> (field, needs_unicode_flag)` | a name field: ASCII as it is, otherwise legacy name, NUL and RAR's compact Unicode encoding |

Every main, file, service and end block of every RAR 4.x archive in the corpus (zipfast's fixtures, and UnRAR's reference corpus when present) is written back byte for byte, and each volume end block's data CRC32 is checked against the volume's bytes. Archives and a two-volume set written from scratch with these blocks list and extract with zipfast, Unicode names included.

`unicode_name_field` writes a valid encoding that RAR 3.x and later decode; WinRAR's encoder may choose other codes for the same name, so its bytes are not claimed to match WinRAR's. To rebuild an existing header exactly, keep its `name` field from `FileHeader::parse`.

## Rebuilding a RAR 5.0 volume's start (`rar5::rebuild_volume_head`)

rar 5 and later end every volume made with quick open data (the default) with a `QO` service header whose records copy file headers in the volume, each with its distance back from that header. The main header holds only the volume flags and number and a locator naming where the `QO` header is. So a volume whose first bytes were lost in every copy, typically its first Usenet article, can have them back from its last ones:

```rust
let head = zipfast::rar5::rebuild_volume_head(
    &last_bytes,          // the volume's last bytes: through its QO header, end header and padding
    volume_len,           // exact, from par2 or yEnc, not from the NZB
    &zipfast::rar5::HeadOptions { volume: Some(index), sibling: Some(&intact_volume_start) },
)?;
if head.exact {
    // write head.bytes at offset 0: the signature, main header and first file header; its data follows
}
```

`RebuiltHead`:

- **`bytes`**: the volume from offset 0: the signature, the main header, and the first file header when it follows the main header directly (always, unless something uncached comes first).
- **`main`**: the main header as a `MainHeader`.
- **`headers`**: every header the quick open data copies, placed at its offset with its data length, also those later in the volume, so headers lost elsewhere in it can be written back too.
- **`quick_open_offset`**, **`more_volumes`**.
- **`exact`** and **`doubt`**.

`HeadOptions`:

- **`volume`**: the volume's number, 0-based, from its name. Nothing else in the volume's start says it. Without it, a volume starting with a whole file is taken for the first (`VolumeNumberInferred`), and one starting inside a file is refused.
- **`sibling`**: the start of any intact volume of the same set, through its main header. The set's archive flags (solid, locked), the main header's other extra records and the locator field's width come from it, so the main header is certain. Without it, the archive flags are inferred from the cached file headers (a file continuing the solid stream shows a solid archive; a file other than the first without that bit shows a non-solid one) and the locator width from where the first cached header starts, and the result is never claimed exact: a locked archive (`-k`) does not show that way.

When the result is not certain, `doubt` says why:

- **`VolumeNumberInferred`**, **`VolumeNumberContradicted`** (volume 0, but its first file continues from a previous volume).
- **`ArchiveFlagsInferred`**: no sibling was given. The lock flag (`-k`) shows only in the main header, so without a sibling the archive flags are never certain, even when the cached headers show whether the archive is solid. The bytes assume an unlocked archive (and a non-solid one unless a cached file continues the solid stream).
- **`UncachedHeaders`**: something the quick open data does not copy lies between headers it does. rar's default quick open mode skips files with 4096 bytes of packed data or less in the volume; an archive comment or another service header also does. The listed headers are still exact.
- **`MainHeaderSize`**: the rebuilt main header does not end where the first cached header starts, and nothing fits between: the main header holds records neither the sibling nor the default layout has.

Refused: a tail not ending in a RAR 5.0 end header (`NotAnArchive`); no quick open header right before the end header, as in `-qo-` sets, `-hp` sets (every header is encrypted), a recovery record (`-rr`) or a default-mode volume with nothing cached (`Unsupported`); quick open records failing their CRC32 or placing headers impossibly (`Corrupt`). Hostile input never panics, and the work is linear in the tail's length: the backward scans checksum only headers claiming at most 64 bytes (end header) or 256 bytes (quick open header), so overlapping fake headers cannot make them re-hash the tail.

Compared with RustyGet's `head_from_tail`, this also rebuilds sets whose locator field has another width (rar pads it to two bytes more than the volume size takes, so 5 bytes in 100 KB volumes and 6 in 5 MB ones), keeps the sibling's archive flags and extra records instead of refusing solid archives, lists every cached header, and reports why a result is uncertain instead of returning nothing.

Tested (`tests/rar5_volume_head.rs`) on rar 7.30 volumes kept as vectors (one file, two files, `-p` last volume, small pieces in both quick open modes, no quick open data), and, when present, on every volume of the rar-made sets of `ZIPFAST_RAR5_TAIL_SETS` and RustyGet's `ZIPFAST_Z_FIXTURES` sets: 113 of 157 volumes rebuild exactly; the rest are `-hp`, `-qo-`, `-rr` or default-mode volumes that are refused or doubted, and no result claimed exact differs from the volume.
