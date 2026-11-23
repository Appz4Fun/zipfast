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

`FeedSink::read_held(offset, buf) -> usize` (default: nothing held) gives back output already held from `offset`:
what the decoder wrote, or plaintext of the member known from elsewhere, such as another copy's output kept over a
handover (a persistent partial's held output). Compressed members use it to rebuild their window when they restart
at a checkpoint (after a snapshot, for a repair) and to skip holes (below). `Vec<u8>` gives back its bytes up to its
length, so a `Vec` the caller filled beforehand acts as held output.

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
| `stalled` | a compressed main decode waits at a hole it cannot skip; the hole's bytes are the first `Next` need |
| `crc_ok` | once done: whether the output matches the member's CRC32 (keyed with the password where the map says so, as RAR 5.0 AES members' are); None without one |

`NeedBytes` ranges are exact: a `Next` need is the run of bytes from the frontier the source reported absent, a
`Repair` need the missing bytes a repair stopped at. Both are cut at piece (volume) boundaries.

The CRC is kept per run of contiguous output and joined (`crc32::combine`) as holes are repaired, so the verdict
needs no second pass. Members with only a BLAKE2sp hash, and WinZip AE-2 entries (no CRC), report `crc_ok: None`;
the WinZip authentication code and RAR part checks are not checked here (use `MemberReader` or a persistent
partial's verify for those).

`FeedOptions`: `password`, `limits` (KDF budgets and password sizes, as for maps), `control` (a `SessionControl`:
cancels a run between reads and a key derivation in progress), `read_chunk` (the largest read, default 256 KiB),
`max_needs`, `run_budget`, `max_window` (the largest RAR 5.0 dictionary, or LZMA2 decoder dictionary, a member may allocate, default 1 GiB). Keys are derived in `new`, so a wrong password shows there where the member records a
check value (RAR 5.0 with a check, WinZip AES); otherwise as `crc_ok: Some(false)`.

`stats()` counts packed bytes read, output bytes written, holes met and output `redecoded` (decoded again without
being written: a compressed repair from its checkpoint up to the lost range, a restore from its checkpoint up to the
old frontier, and for a 7z member after its folder's first the folder output before it), over the decoder's life.

## Layers

| member | holes |
|---|---|
| plain stored (RAR 5.0, RAR 4.x, ZIP method 0, 7z Copy): `OutputMapping::Direct` | output byte = stream byte: the hole's own output is lost; the main decode goes on right after it |
| AES-CBC stored (RAR 5.0, RAR 4.x AES-128, the first member of a 7zAES-over-Copy folder): `CbcBlocks` | each block needs the ciphertext block before it: the lost output runs from the start of the block the hole begins in to the end of the block after the one it ends in (`[floor16(start), ceil16(end) + 16)`); the main decode restarts there with the block before as IV |
| WinZip AES stored: `Counter { skip }` | each byte decrypts on its own: exactly the hole's output is lost |
| ZipCrypto | refused (`FeedUnsupported::SequentialCipher`): its keystream needs every earlier byte |
| compressed RAR 5.0 (methods 1-5, AES-256 under them too), not solid | see [compressed RAR 5.0](#compressed-rar-50) |
| 7z folders of one LZMA2 coder, alone or over 7zAES, any member of the folder | see [7z LZMA2](#7z-lzma2) |
| solid RAR 5.0 members after a stream's first, RAR 4.x and ZIP compressed members, other 7z coder chains | refused (`Solid`, `Compressed`, `Coders`); see [next](#next) |

A repair reads only the lost range's bytes (under CBC, also the block before it as IV) and writes only the lost
output. A repair that stops at bytes still missing keeps what it decoded, needs only the rest, and next time asks
the source for one byte at the point it stopped before reading anything again.

## Compressed RAR 5.0

The main decode feeds the packed bytes (decrypted first under AES) to an `rar5::unpack::Unpacker` on the calling
thread and writes its output in order. After every read it keeps a checkpoint at the last block boundary it passed:
the decoder's state between two blocks (the four last match distances, the last length, the code lengths a block
without tables would use, and the filters whose output the window still holds), with the stream offset of the next
block. A checkpoint holds no window: restoring one reads the window back from the sink (`read_held`, the dictionary's
worth of output before it) and undoes those filters there, as the decoder held its window. Checkpoints are about
500 bytes; one is kept for the main decode and one per skipped hole.

At a hole, output past it cannot be placed without plaintext past it: the blocks after it decode, but their output
offset and the window they copy from are unknown. So:

- **No held output past the frontier** (`read_held` gives nothing there): the main decode waits at the hole
  (`stalled`), and the hole's bytes are the first `Next` need. When they come it goes on from where it stands; nothing
  is decoded twice.
- **Held output past the frontier** (another copy's): it reads up to 8 MiB of packed bytes after the hole and up to
  32 MiB of held output, and looks for the restart (a fixed work budget per search, about a second at most) with [`resync_near`](rar5-resync.md#restarting-near-a-target-handover)
  toward targets just past where the hole's output should end (nearest first). It starts a decoder there, seeded from
  the held output (`Unpacker::resume_seeded`, not strict), reports `frontier..restart` as `lost`, keeps the
  checkpoint before the hole for its repair, and goes on. The output after a seeded restart is unverified until
  `crc_ok` (a filter the search did not see may have changed what a later copy reads); the lost range is held output,
  never written by the skip. A skip that finds no restart (too few packed bytes after the hole yet, content the search
  cannot pin) waits as above and is tried again once clearly more is held (twice the packed bytes, or more held output).
- **Repair**: once the hole's bytes are back, a second decoder restarts at the checkpoint before the hole, decodes to
  the restart's block and writes exactly the lost range; it must meet the restart's output offset, else
  `FeedError::Decode`. The checkpoint is taken where the main decode stood when it met the hole, so on the fixtures a
  repair decodes nothing it does not write (`redecoded` 0). A repair that stops at missing bytes keeps what it wrote
  and its latest checkpoint. While it runs, the repair has its own window (`max_window` bounds each).

The member's size and CRC are checked at its end (`crc_ok`); the CRC runs join across repairs as for stored members.

## 7z LZMA2

A 7z folder's output spans its members: the decoder is per member, but it decodes the folder's LZMA2 stream, and
its positions (restart points, lost ranges inside it) are folder output offsets; the sink still gets member offsets
(`MemberRestart::stream_start` is the member's place in the folder). Output before the member is decoded and
counted in `redecoded`, never written.

**Framing.** Chunk starts are known only from a walk of chunk headers from the folder's first packed byte, each
header giving the next one's place; nothing is ever taken from plaintext or header-like bytes in a payload. The main
decode reads the chunks in order. Headers walked ahead (to find a restart) are cached. Under 7zAES each read decrypts
whole blocks with the ciphertext block before as IV, so a header needs its blocks and the one before, and a hole of
ciphertext `[a, b)` leaves plaintext `[floor16(a), ceil16(b) + 16)` unusable. A first header that cannot be one under
7zAES (7zAES records no password check) is `WrongPassword`.

**Start.** The folder's first member starts at the folder's start. A later member walks the headers before it
(those bytes are `Next` needs, nothing else) and starts at the last chunk at or before its first byte that resets
the dictionary; the output before the member is decoded again (7-Zip resets per block with `-mmt`; a single-threaded
folder resets only at its start).

**Decoding.** liblzma's raw LZMA2 decoder is fed the chunks from a restart point: a chunk that resets the
dictionary, or one that resets the LZMA state with the dictionary-sized output before it given back by the sink
(`read_held`), fed to the decoder as stored chunks. The main decode keeps its restart point at the last such chunk it
passed (a state reset counts only when the output before it was written).

**Holes.** At a hole in a chunk's payload the main decode restarts after it where it can decode without the lost
bytes:

- in a stored chunk, right after the hole: exactly the hole's output (under 7zAES widened to blocks) is lost, and
  copying goes on; its repair copies the payload bytes when they come;
- otherwise at the next chunk, found by walking the headers after the hole, that is stored (copied as it is), resets
  the dictionary, or resets the state with the output before it held. Everything from the hole to there is lost.

A chunk met later that needs the lost bytes (an LZMA chunk continuing the state across them) is lost too, up to the
next restart. The restart is never searched for in plaintext: when a header after the hole is itself in a hole, or no
restart exists before the member's end (a single-threaded folder), the main decode waits at the hole (`stalled`, the
hole's bytes the first `Next` need) and goes on with its decoder when they come, decoding nothing twice. When a header
after the hole has not arrived yet, its bytes are the first `Next` need and the hole the next. Usenet articles (750 KB)
are far larger than a chunk (at most 64 KiB packed), so an article-sized hole always hides headers and waits; holes
inside payloads (damaged or partly fetched articles) are skipped.

**Repairs.** A decoded repair starts from the restart point before its hole, decodes without writing up to the lost
range and writes exactly it. When the main decode skips a hole in an LZMA chunk, its decoder, stopped at the hole,
becomes the repair's: the repair goes on from the hole once its bytes come (`redecoded` 0). A repair whose lost range
starts at a state reset starts there once the output before it is held (after the stored repair before it, say).
A repair that stops at missing bytes keeps its decoder and what it wrote. At most 8 repairs keep a decoder; the others,
and every repair after a restore, start from their restart point, so a repair decodes again at most from the restart
point before its hole (a 7-Zip block, about 4 dictionaries) to the lost range.

**Memory.** Packed bytes from the main decode's restart point on are kept for a repair or a restore (at most 64 MiB
behind its read position; older ones are released and asked for again as needs when a repair reads them).


`snapshot()` captures the decoder between runs: the main decode's position (under CBC its block and that block's
IV; for a compressed member its checkpoint, frontier and the skipped holes' checkpoints and restarts), the lost
ranges, the CRC runs and the stats. It never holds keys or plaintext. `FeedSnapshot::to_bytes()` and `from_bytes()`
give a compact versioned encoding (`ZFFD`, version 2; version 1 stored snapshots still load) to keep next to the
output file. It records a fingerprint of the member (name, sizes, method, cipher parameters, piece positions), so it
restores only onto that member.
`FeedDecoder::restore(&map, member, options, &snapshot)` derives the key again and continues from there: bytes read
past the frontier short of a block are read again, and lost ranges are repaired as before. A snapshot of another
member or layer is `FeedError::Snapshot`. An LZMA2 member restores at its restart point (its dictionary read back when it is a state reset), decodes up to the
old frontier without writing and goes on; repairs restart from their restart points. A compressed RAR 5.0 member restores at its checkpoint, reading its window back
with `read_held` (`FeedError::HeldOutput` when the sink does not give it), decodes up to the old frontier without
writing (counted in `redecoded`: at most the output since the last block boundary before the snapshot) and goes
on; it never decodes from the member's start unless the snapshot was taken there. Persistent partials (`docs/persistent-partials.md`) remain the durable,
journaled store for output; a snapshot is the decoder's position over it.

## Errors

Missing bytes are never an error. `FeedError`: `NoSuchMember`, `Unsupported(FeedUnsupported)`, `IncompleteMember`
(the map lists only some pieces), `PasswordRequired`, `WrongPassword`, `Key` (other key-derivation failures:
limits), `Malformed` (an inconsistent map, checked as `MemberReader` checks it), `SourceContract`, `Write { out,
error }`, `Canceled`, `Snapshot`, `Decode { out, error }` (compressed data that does not decode, a repair that does
not meet its restart), `HeldOutput { range }` (a checkpoint's window the sink does not give back), and
`AlreadyFailed` after a failed run (restore a snapshot instead).

## Next

- 7z LZMA2 under BCJ or Delta (a chain of coders), LZMA (not LZMA2) folders.
- Solid RAR 5.0 members after the first: the same checkpoints over the solid stream (the window holds earlier
  members' output).
- A skip without held output past the hole is impossible for compressed data (see above); RAR 4.x compressed
  members have no restart search yet.

## Tests

`tests/feed_decoder.rs`: RAR 5.0 stored over six volumes, RAR 5.0 AES stored over four volumes (one with a size
that is not a block multiple) and WinZip AES, cut into articles of 64 to 4,096 bytes, fed shuffled with every third
to seventh article missing, then the missing ones supplied in another order after a snapshot round trip: the output
equals the payload with no byte written twice, the CRC matches, the needs are exactly the missing articles' data
bytes, and bytes read again stay within two blocks per hole. Also: `Next` and `Ahead` needs before anything
arrives, the CBC hole geometry, run budgets with a restore in between, release keeping an in-order feed's buffer to
one article, and typed refusals (passwords, cancellation, foreign snapshots).

Compressed RAR 5.0 (`tests/feed_decoder.rs`, plain and AES, 600 KB of video-like content over four volumes, 7,000-byte
articles shuffled, every sixth or ninth missing): without held output the decoder waits at the first hole, names it
exactly as `Next`, and once the missing articles come finishes exact with nothing decoded twice; with held output it
skips every hole it can, writes nothing outside the payload, needs only bytes inside the missing articles, and the
repairs finish exact with each byte written once and `redecoded` 0 (bound checked: under a quarter of the member). A
snapshot taken mid-member, serialized and restored resumes from its checkpoint, decoding under 64 KiB again; restored
without held output it is `HeldOutput`.

`tests/feed_decoder_z.rs` (with `ZIPFAST_Z_FIXTURES`): F01 (RAR 5.0 AES stored, 36 MB), F02 (the same with `-hp`)
and F11 (two AES stored members, 36 + 26 MB) cut into 750,000-byte articles, shuffled, every seventh missing and
supplied later: exact, CRC verified, each output byte written once, needs only inside the missing articles, packed
bytes read again under 500 per member. Release build on an M-series Mac: 11 to 20 ms to feed a set, 2 to 4 ms to
repair.

The same test feeds the compressed sets F03 (video, `-m3`, 36 MB), F05 (mixed, `-m5`, 26 MB) and F12 (two AES
`-m3` members) the same way, each twice:

| set | without held output | with held output (the payload as another copy) |
|---|---|---|
| F03 | waits at the first hole (3.0 MB); exact once the missing articles come, `redecoded` 0 | all 6 holes skipped (5.9 MB lost, then repaired); exact, `redecoded` 0 |
| F05 | waits at 1.5 MB; exact, `redecoded` 0 | its hole skipped (4.3 MB lost); exact, `redecoded` 0 |
| F12 | both members wait (4.5 MB, 1.4 MB); exact, `redecoded` 0 | member 1: all 6 holes skipped; member 2: one skipped, then waits at a hole the search cannot place; both exact, `redecoded` 0 |

Every output byte is written once, and `crc_ok` is true. Skips cost packed reads: each attempt reads up to 8 MiB
after the hole again, so F12 with held output read 60 and 72 MB of packed bytes for 36 and 14 MB members. Timings
(release, M-series, but on a machine running other builds at a load of about 25): a set's feed takes 0.1 to 1 s and
its repairs 0.01 to 2 s, mostly in the restart searches.

7z LZMA2 (`tests/feed_decoder_7z.rs`): folders built with liblzma's raw encoder in 7-Zip-like independent blocks
(text and incompressible runs: LZMA chunks, stored chunks, state resets), plain and 7zAES, split into volumes, cut
into articles of 1,500 to 20,000 bytes, shuffled, every 7th to 11th missing, with and without held output, a
snapshot round trip half way through the repairs: exact, CRC verified, each byte written once, needs only inside the
missing articles, `redecoded` under a block per skipped hole (0 with held output, a few hundred KB of a 1.5 MB member
without: repairs of LZMA chunks that continue across a lost stored run). Also: members after a folder's first (seek
from the last reset), a header in a hole stalling until it comes (`redecoded` 0), headers as the first `Next` need, a
snapshot mid-member restored from its restart point, and a wrong 7zAES password.

`tests/feed_decoder_z.rs` feeds F07 (video, all stored chunks), F08 (mixed, `-mmt4 -md1m`) and F10 (F08 under
7zAES, `-mhe`) as above, each with and without held output: every set waits at its first hole (each article-sized
hole hides chunk headers) and finishes exact once the missing articles come, `redecoded` 0. Then again with only
16 KiB in the middle of each missing article lost: F07 and F08 skip two holes (32 KB lost; F08 without held output
445 KB, up to the next reset) and wait at a hole over a header; F10 skips all three; all exact, `redecoded` 0.
