# Feed-driven decoding

`zipfast::map::FeedDecoder` decodes one member of a [member map](member-map.md) from packed bytes that arrive in any
order, as a Usenet download delivers them. It never waits: each `run` writes the output as far as the bytes held
allow and returns. When bytes are missing it says which ones it needs (`NeedBytes { volume, range, kind }`), so the
downloader can move those articles up its queue. A hole (an article that will not come) is skipped where the layer
allows, its output reported lost, and repaired when its bytes turn up, without decoding anything else again. The
decoder's state can be saved and restored, also across a process restart.

```rust,ignore
use zipfast::map::{ArticleBuffer, FeedDecoder, FeedOptions, MemberMap};

let map = MemberMap::from_memory(&header_bytes, "r.part1.rar", Some(pw))?; // or MapBuilder over a VolumeSource
let mut decoder = FeedDecoder::new(&map, member, FeedOptions::new(Some(pw)))?;
let mut articles = ArticleBuffer::new(256 << 20);
let mut out = std::fs::File::create("video.mkv")?; // anything implementing FeedSink
loop {
    let (volume, offset, bytes) = next_article();      // any order
    articles.insert(volume, offset, &bytes)?;          // or articles.mark_lost(volume, range) for a dead one
    let status = decoder.run(&mut articles, &mut out)?;
    prioritise(&status.needs);                         // Next first, then Repair, then Ahead
    if status.done { break; }
}
```

## Input: a packed source

The decoder pulls packed bytes from a `PackedSource`, so the caller decides where they live and memory stays
bounded:

- `read_packed(volume, offset, buf) -> PackedRead`: `Data(n)` (the first `n` bytes of `buf`), `NotYet { len }`
  (not arrived; `len` bytes from `offset` are absent as far as the source knows) or `Hole { len }` (lost until the
  source holds them again). Offsets are a volume's own byte offsets, as `MapPiece::packed` gives them.
- `absent(volume, range)` (optional): the parts of a range not held, listed as `NeedKind::Ahead`.
- `release(volume, range)` (optional hint): bytes the decoder will not read again, so the source may drop them.
  Everything the main decode passed is released, also past holes, except the bytes a lost range's repair still reads.

`ArticleBuffer::new(limit)` is an in-memory source: `insert(volume, offset, bytes)` in any order (overlaps keep
the bytes already held; `BufferFull` when the limit would be passed, storing nothing, so the caller holds them
itself and inserts them when they are needed), `mark_lost(volume, range)` (answered `Hole` until inserted) and
`held()`. It drops what the decoder releases: fed in order, it holds only the article being read.

## Output: a sink

`FeedSink::write_at(offset, bytes)` gets member output at member offsets. The main decode writes in order; a repair
writes a range reported lost before. No output byte is written twice. `Vec<u8>` is a sink (it grows as needed).

## Running

`run(&mut source, &mut sink) -> FeedStatus` first advances the main decode from its frontier as far as the source
has contiguous bytes (holes skipped where the layer allows), then retries each lost range whose bytes may be back.
`FeedStatus`:

| field | meaning |
|---|---|
| `frontier` | the main decode's output offset: every byte before it is written or in `lost` |
| `lost` | output ranges lost to holes and not yet repaired, in order |
| `needs` | the packed bytes needed, in priority order, at most `FeedOptions::max_needs` (default 64): `Next` (the main decode waits for them), `Repair` (they repair `lost`, in output order), `Ahead` (the main decode will read them later and the source does not hold them) |
| `more` | the run stopped at `FeedOptions::run_budget` output bytes with more to do |
| `done` | every output byte is written |
| `crc_ok` | once done: whether the output matches the member's CRC32 (keyed with the password where the map says so, as RAR 5.0 AES members' are); None without one |

`NeedBytes` ranges are exact: a `Next` need is the run of bytes from the frontier the source reported absent, a
`Repair` need the missing bytes a repair stopped at. Both are cut at piece (volume) boundaries.

The CRC is kept per run of contiguous output and joined (`crc32::combine`) as holes are repaired, so the verdict
needs no second pass. Members with only a BLAKE2sp hash, and WinZip AE-2 entries (no CRC), report `crc_ok: None`;
the WinZip authentication code and RAR part checks are not checked here (use `MemberReader` or a persistent
partial's verify for those).

`FeedOptions`: `password`, `limits` (KDF budgets and password sizes, as for maps), `control` (a `SessionControl`:
cancels a run between reads and a key derivation in progress), `read_chunk` (the largest read, default 256 KiB),
`max_needs`, `run_budget`. Keys are derived in `new`, so a wrong password shows there where the member records a
check value (RAR 5.0 with a check, WinZip AES); otherwise as `crc_ok: Some(false)`.

`stats()` counts packed bytes read, output bytes written and holes met, over the decoder's life.

## Layers

| member | holes |
|---|---|
| plain stored (RAR 5.0, RAR 4.x, ZIP method 0, 7z Copy): `OutputMapping::Direct` | output byte = stream byte: the hole's own output is lost; the main decode goes on right after it |
| AES-CBC stored (RAR 5.0, RAR 4.x AES-128, the first member of a 7zAES-over-Copy folder): `CbcBlocks` | each block needs the ciphertext block before it: the lost output runs from the start of the block the hole begins in to the end of the block after the one it ends in (`[floor16(start), ceil16(end) + 16)`); the main decode restarts there with the block before as IV |
| WinZip AES stored: `Counter { skip }` | each byte decrypts on its own: exactly the hole's output is lost |
| ZipCrypto | refused (`FeedUnsupported::SequentialCipher`): its keystream needs every earlier byte |
| compressed members, 7z coded folders | refused (`Compressed`, `Coders`); see [next](#next) |

A repair reads only the lost range's bytes (under CBC, also the block before it as IV) and writes only the lost
output. A repair that stops at bytes still missing keeps what it decoded, needs only the rest, and next time asks
the source for one byte at the point it stopped before reading anything again.

## Saving and restoring

`snapshot()` captures the decoder between runs: the main decode's position (under CBC its block and that block's
IV), the lost ranges, the CRC runs and the stats. It never holds keys or plaintext. `FeedSnapshot::to_bytes()` and
`from_bytes()` give a compact versioned encoding (`ZFFD`, version 1) to keep next to the output file. It records a
fingerprint of the member (name, sizes, method, cipher parameters, piece positions), so it restores only onto that
member.
`FeedDecoder::restore(&map, member, options, &snapshot)` derives the key again and continues from there: bytes read
past the frontier short of a block are read again, and lost ranges are repaired as before. A snapshot of another
member or layer is `FeedError::Snapshot`. Persistent partials (`docs/persistent-partials.md`) remain the durable,
journaled store for output; a snapshot is the decoder's position over it.

## Errors

Missing bytes are never an error. `FeedError`: `NoSuchMember`, `Unsupported(FeedUnsupported)`, `IncompleteMember`
(the map lists only some pieces), `PasswordRequired`, `WrongPassword`, `Key` (other key-derivation failures:
limits), `Malformed` (an inconsistent map, checked as `MemberReader` checks it), `SourceContract`, `Write { out,
error }`, `Canceled`, `Snapshot`, and `AlreadyFailed` after a failed run (restore a snapshot instead).

## Next

Compressed RAR 5.0 members (restart after a hole from held plaintext, checkpoints at block starts so a repair
re-decodes only from the nearest one) and 7z LZMA2 folders (restart at the next chunk that resets the dictionary or
stores its bytes, from a chunk index).

## Tests

`tests/feed_decoder.rs`: RAR 5.0 stored over six volumes, RAR 5.0 AES stored over four volumes (one with a size
that is not a block multiple) and WinZip AES, cut into articles of 64 to 4,096 bytes, fed shuffled with every third
to seventh article missing, then the missing ones supplied in another order after a snapshot round trip: the output
equals the payload with no byte written twice, the CRC matches, the needs are exactly the missing articles' data
bytes, and bytes read again stay within two blocks per hole. Also: `Next` and `Ahead` needs before anything
arrives, the CBC hole geometry, run budgets with a restore in between, release keeping an in-order feed's buffer to
one article, and typed refusals (passwords, cancellation, foreign snapshots).

`tests/feed_decoder_z.rs` (with `ZIPFAST_Z_FIXTURES`): F01 (RAR 5.0 AES stored, 36 MB), F02 (the same with `-hp`)
and F11 (two AES stored members, 36 + 26 MB) cut into 750,000-byte articles, shuffled, every seventh missing and
supplied later: exact, CRC verified, each output byte written once, needs only inside the missing articles, packed
bytes read again under 500 per member. Release build on an M-series Mac: 11 to 20 ms to feed a set, 2 to 4 ms to
repair.
