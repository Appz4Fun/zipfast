# Rebuilding a copy's volumes from held output

A downloader switching from copy A of a file to copy B (the same file in another container) holds the output A
produced. For a stored or AES-stored copy B, every volume byte of B that carries output already held can be
computed locally, so those articles never need downloading, and a par2 verifier can count them as present
blocks. `zipfast::map::ContainerRebuilder` computes them from B's [member map](member-map.md), built from header
bytes alone:

```rust
let map = MemberMap::from_memory(&volume_heads, "b.part01.rar", Some(password))?; // or MapBuilder
let mut rebuilder = ContainerRebuilder::new(&map, Some(password));
let mut held = HeldMembers::new().with(member, &video, Some(good_ranges)); // or your own HeldOutput
let got = rebuilder.rebuild(volume, article_range, &mut held, &mut RebuildOptions::default())?;
for region in &got.regions {
    match &region.state {
        ByteState::Rebuilt(_) => { /* got.bytes for region.range are the volume's: write them, mark them present */ }
        ByteState::Unneeded { .. } => { /* compressed data before a handover restart: never needed */ }
        ByteState::Missing(why) => { /* download these */ }
    }
}
```

## API

- `ContainerRebuilder::new(&map, password)`. It keeps derived keys (one derivation per salt) and CBC checkpoints
  between calls, so rebuilding a set's articles in order encrypts each byte once.
- `rebuild(volume, range, &mut dyn HeldOutput, &mut RebuildOptions) -> Result<RebuiltRange, RebuildError>`. It
  rebuilds bytes `range` of volume `volume` (zero-based, as in the map) and reports every byte.
- `members_on(volume)` lists the members with data in a volume.
- `skipped_spans(&map, &plan)` lists the packed spans an `open_at` plan never needs.

`HeldOutput::read_held(member, offset, buf) -> Vec<Range<u64>>` copies a member's output from `offset` into `buf`
and returns the ranges it holds. Bytes outside them are holes. Offsets are the member's own output offsets, for a
7z member too. Implementations:

- `HeldMembers` (slices in memory, each with optional good ranges);
- any `FnMut(usize, u64, &mut [u8]) -> Vec<Range<u64>>`;
- a downloader's held file plus its coverage.

`RebuildOptions`:

| field | use |
|---|---|
| `member` | rebuild only this member; other members' bytes are `Missing::OtherMember`, also inside a shared 7z folder, whose other members' output still chains the CBC stream internally |
| `known` | `KnownBytes { volume, offset, bytes }`: volume bytes the caller holds (downloaded articles). Never reported as rebuilt. They give the CBC block before a range when the held output has a hole, take part in CRC checks, and are compared with what is rebuilt (`RebuiltRange::conflicts`) |
| `checks` | `Crc32Check { volume, range, crc32 }`: an article's CRC32 (from its yEnc trailer), used to find a RAR final block's random padding. Every usable check applies together; give both articles' CRCs when an article boundary cuts through the block |
| `accept` | the caller's own test of a final block candidate (`FinalBlock { member, block, places, pad }`), for example a par2 slice hash. It applies together with the CRC checks, to the candidates they pass, up to 2^24 times |
| `headers` | `VolumeHeaders`: rebuild RAR 5.0 headers from the bytes held of the volume (see below) |
| `plans` | `open_at` plans of compressed members (see below); with several plans on one stream (members of one 7z folder), the earliest restart decides |
| `max_chain` | the most stream bytes encrypted forward to reach a CBC range's previous block (default: no limit) |
| `max_range` | the largest range accepted (default 1 GiB) |

`RebuiltRange { volume, range, bytes, regions, conflicts }`:

- **`regions`:** the range back to back. Each `Region { range, member, output, state }` gives the member output
  offsets it carries, where the mapping is exact.
- **`bytes`:** exact where a region is `Rebuilt`, a guess where it is `Missing::Header(HeaderGap::Doubtful(_))`,
  and zero elsewhere.
- **Helpers:** `rebuilt_len()`, `unneeded_len()`, `len_where(pred)`, `complete()` and `missing()`.

## What is rebuilt, per layer

| layer | rebuilt (`Rebuilt::`) | from |
|---|---|---|
| plain stored: RAR 5.0, RAR 4.x, ZIP, a 7z Copy folder | `Plain`: data = output | the held output (`OutputMapping::Direct`) |
| RAR 5.0 / RAR 4.x AES stored, 7zAES over Copy | `Cbc`: AES-CBC ciphertext of whole blocks | the held output and the key, derived from the password and `CipherParams`. The previous ciphertext block comes from the member's IV (RAR 5.0: the file header's; RAR 4.x: derived; 7z: the folder's), from the held output by encrypting forward from the nearest checkpoint, or from `known` bytes |
| the last CBC block | `CbcFinal { pad, searched }` | 7z pads with zeros: always rebuilt. RAR pads with random bytes: found with `crypto::rebuild_final_block` when a `Crc32Check` or `accept` decides (up to 3 padding bytes) |
| WinZip AES stored | `CounterPrefix`: salt and verifier | the map's `CipherParams::WinZipAes` |
| | `Counter`: the output XOR the keystream (counter = block + 1, little-endian) | the key from the password |
| | `CounterAuth`: the 10-byte HMAC-SHA1 code | only when the whole output is held |
| RAR 5.0 headers | `Header(Tail \| Head \| Cached)` | `VolumeHeaders`, below |

A 7z AES-over-Copy folder is one CBC stream over all its members, so its later members are rebuilt too, even
though the map gives them no pieces. Each RAR member is its own stream; a volume boundary never resets CBC.

## Not rebuilt (`Missing::`)

| reason | meaning |
|---|---|
| `Header(gap)` | Archive structure. `NotRar5` (only RAR 5.0 headers are rebuilt: 7z signature and end headers, ZIP local and central headers), `Encrypted` (`-hp`: every header has a random IV), `NoSource`, `Refused(text)`, `NotCovered`, or `Doubtful(doubt)` (rebuilt but not certain; the guess is in `bytes`) |
| `NotHeld` | The output these bytes carry (`region.output`) is not held. For CBC that is the whole block |
| `Chain` | AES-CBC: the ciphertext block before is unknown, because the held output has a hole since the last checkpoint (or `max_chain` was hit). Pass the 16 volume bytes before the range as `known` (for example the end of the previous article) to restart the chain |
| `FinalPadding { pad, searched }` | A RAR final block with `pad` random padding bytes. Either no check could decide (`searched: false`; a `Crc32Check` needs every other byte of its range rebuilt in the call or `known`), or no padding passed. More than 3 padding bytes are never searched (2^32 tries and more) |
| `FinalPaddingAmbiguous { pad, candidates }` | Several paddings pass every check (a check that sees only a byte or two of the block). Bytes all passing candidates agree on are rebuilt; the others are this. Give the other article's CRC too |
| `Padding` | CBC blocks wholly past the output (extra padding) |
| `Key(problem)` | `NoPassword`, `WrongPassword` (a RAR 5.0 or WinZip check value refused it) or `Derivation`. Without a check value (7z, RAR 4.x, RAR 5.0 without one), a wrong password rebuilds wrong bytes: compare with `known` bytes (`conflicts`), and prove the result with the article CRC or par2 |
| `AuthCode` | The WinZip AES code covers the whole output, which is not all held |
| `Compressed(layer)` | Compressed data cannot be computed from output |
| `Sequential` | ZipCrypto: every byte depends on the random encryption header and all earlier output |
| `Unmapped(what)` | No output mapping: legacy RAR 4.x encryption, an unknown size, odd cipher parameters |
| `OtherMember` | With `RebuildOptions::member` set |

## Headers (RAR 5.0)

`VolumeHeaders { volume_len, head, tail, more_volumes, quick_open, sibling }`:

- **`head`:** the volume's surviving start, through its last file header (its first article, usually). Member data
  in it may be zeros. It rebuilds the volume's tail with `rar5::rebuild_volume_tail_with`: the quick open service
  header, the end of archive header and the zero padding up to `volume_len`.
- **`tail`:** the volume's bytes after its last data (its last article's header part). It rebuilds the volume's
  start (signature, main header, first file header) with `rar5::rebuild_volume_head`, and every file header the
  quick open data caches, wherever it lies in the volume (`Cached`).
- **`more_volumes`, `quick_open` (`rar5::quick_open_mode` of an intact volume), `sibling`:** these make the results
  certain. See [volume tails](rar5-volume-tail.md) and `rebuild_volume_head`.

Header bytes are written only where no member data lies. A rebuild that is not certain marks its bytes
`Doubtful(HeaderDoubt::Tail | Head)`.

## Compressed members

Compressed data is not rebuildable. With a handover plan from [`open_at`](open-at.md) in `RebuildOptions::plans`,
packed bytes before the plan's restart (`OpenAt::fetch_from`) are `Unneeded`, and only the rest is
`Missing::Compressed`. `skipped_spans(&map, &plan)` gives the same spans without a rebuild. For a 7z LZMA2 plan
with `Lzma2Framing::HeaderWalk`, `Unneeded { chunk_headers: true }`: the few header bytes of each LZMA2 chunk in
them are still read for the walk.

## Final block checks

A RAR final block's padding is random. `Crc32Check` treats the article CRC32 as an affine function of the block's
bytes. The CRC of the rest of the range is computed once, and each candidate costs one AES block and at most 128
XORs, not a CRC over 750 KB. The check needs every other byte of its range, rebuilt in the same call or `known`:

- With the volume's headers rebuilt (`VolumeHeaders`), the last article of a plain-header set is checked from the
  call alone.
- With encrypted headers, the header bytes must be `known`, which means downloaded. The article is then downloaded
  anyway.

`known` bytes inside the final block also act as a filter.

Every padding is tried against all usable checks, the `known` filter and `accept` together. A byte of the block is
rebuilt only when every passing candidate agrees on it: a check that covers one byte of the block (the article
boundary falls just inside it) passes about 256 paddings out of 65,536 for 2 padding bytes, which agree on that
byte only.

## Checked against

`tests/container_rebuild.rs` covers:

- RAR 5.0 plain and AES stored sets written by the test, with volume parts that are not multiples of 16;
- ranges cutting through blocks, holes, chains restarted from known bytes, and checkpoints carried between calls;
- wrong and missing passwords, and the member filter;
- a compressed member with a handover plan;
- WinZip AES-128 and AES-256 stored entries;
- 7-Zip's 7zAES-over-Copy (`-mhe`) and Copy split fixtures;
- WinRAR's RAR 4.x AES stored set over four volumes.

Rebuilt bytes are compared with the volumes byte for byte.

`tests/container_rebuild_z.rs` (with `ZIPFAST_Z_FIXTURES`) rebuilds every volume of RustyGet's stored z-fixture
sets from the payloads. Header sources are only the bytes before and after each volume's data, with the data
zeroed:

| set | volumes | bytes rebuilt | not rebuilt |
|---|---|---|---|
| F01 RAR 5.0 store + AES | 7 | 35,994,150 / 35,994,150 (100%) | none: data, final block from the article CRC, head, tail and cached headers |
| F02 the same with `-hp` | 7 | 35,992,128 / 35,995,694 | 3,566 encrypted header bytes (512 per volume, 494 in the last) |
| F09 7z Copy + 7zAES, `-mhe` | 7 | 35,992,128 / 35,992,338 | the 32-byte signature header and the 178-byte encrypted header |
| F11 RAR 5.0 store + AES, 2 files | 12 | 61,995,834 / 61,995,834 (100%) | none, across the member boundary |

It also checks:

- ranges cutting through AES blocks (`3*750000+5..4*750000+5`, `12345..54321`, `7..23`, and one ending 3 bytes
  before the volume's end), each from a fresh rebuilder;
- a 100-byte hole in the held output: its blocks are `NotHeld`; the next article is all `Chain` until the 64
  volume bytes before it are known, and is then rebuilt whole.

On the compressed sets, a seeded handover at 60% of the output leaves unneeded:

- F03 (RAR 5.0 `-m3`): 11.1 MB of 36.1 MB;
- F07 (7z LZMA2): 17.4 MB of 36.0 MB, except its chunk headers.

A whole stored set rebuilds in 0.2 to 3.2 s (release, M4, one thread), key derivation and the full final block search included.
