# Opening a member at an output offset

A downloader switching from one copy of a release to another (the same file in another container) wants to start
the new copy where the old one's extraction stopped, fetching only what the rest needs. `zipfast::map` plans that
from the new copy's [member map](member-map.md), built from header bytes alone:

- `member_restart(&map, member) -> MemberRestart` says how a member restarts: its `layer`, the `grain` of its
  restart points, whether the packed bytes are `encrypted` under the layer, its `dictionary`, its `stream_start`
  (where its output starts in its decoder's stream) and `size`.
- `open_at(&map, member, offset, &OpenAtOptions) -> OpenAt` plans opening the member at member output offset
  `offset`. It reads nothing: plain data in, plain data out.
- `complete_rar5` and `complete_lzma2` finish a compressed plan once the packed bytes it named are held.

## Layers and restart points

| `layer` | `grain` | restart points | what `open_at` gives |
|---|---|---|---|
| `Stored` (RAR, ZIP, 7z Copy) | `AnyByte` | any byte, from the map | `Start::At { output: offset }` and exact spans |
| `StoredCbc` (RAR 5.0 / 4.x AES, 7zAES over Copy) | `Block16` | any 16-byte block; the ciphertext block before it is the IV (the member's IV for block 0) | `Start::At { output: offset & !15 }`; the spans start with the IV block |
| `StoredCounter` (WinZip AES) | `AnyByte` | any byte | `Start::At { output: offset }` |
| `StoredSequential` (ZipCrypto) | `StartOnly` | the start only | `OpenAtError::StartOnly` |
| `Rar5Compressed` (methods 1-5, AES under them too) | `Rar5Blocks` | block starts, found by `resync_near` over held packed bytes and known plaintext | `Start::Rar5 { stream_target, estimate, first, donor }` |
| `SevenZipLzma2` (LZMA2, 7zAES under it too) | `Lzma2Chunks` | chunks that reset the LZMA state or store their bytes, found by walking the folder's chunk headers back from its end marker | `Start::Lzma2 { folder, folder_target, dict_prop, donor }` |
| `Other` (RAR 4.x compressed, ZIP compressed, other 7z coders) | `StartOnly` | the start only | `OpenAtError::StartOnly` |

For stored layers `spans` are exactly `MapMember::packed_spans(output..size)`: the packed bytes from the restart to
the member's end, per volume. Nothing before them is needed.

## Compressed members

The map cannot show where a compressed member's restart points lie; its packed bytes do. So `open_at` estimates
where the target's packed bytes lie (the member's average packing ratio, or `OpenAtOptions::estimate` when the
caller knows better), and fetches from `OpenAtOptions::search` bytes (default 4 MiB) before that estimate:

- `fetch_from` and `spans`: the packed bytes to fetch, from `fetch_from` to the end of the member's packed stream
  (RAR) or the folder's (7z). A handover needs everything after the restart anyway; the search region before the
  estimate is the only extra.
- `donor`: the known plaintext to supply, in the decoder stream's output offsets, ending at the target. It is the
  minimum: about twice the dictionary plus a filter's reach (RAR) or twice the dictionary (LZMA2) before the
  target. A handover usually holds everything the old copy extracted; supply all of it.
- Encrypted packed bytes are decrypted by the caller before completing. The fetch then starts one block early: when
  `fetch_from` is not 0 its first 16 bytes are the IV of the rest; at 0 the member's (folder's) IV applies.

### RAR 5.0

`complete_rar5(&map, &plan, packed_from, packed, known_base, known, &NearOptions) -> Rar5Resume` runs
[`resync_near`](rar5-resync.md) over the held packed bytes (`packed` starts at packed stream offset `packed_from`)
toward `stream_target`, and starts an `Unpacker` there with `resume_in_stream`, based at the member's
`stream_start`, so a solid stream's later member restarts with its filters addressed from its own start:

- `decoder`: feed it the packed bytes from `feed_from` to the member's end; it writes the member's output from
  `output` on.
- `redecode`: `target - output`, the output decoded again before the target.
- `near`: the search's report (how far back it landed, work, time, whether the restart is guarded).

The restart lands at the last block start at or before the target; one block of rar's can cover several MiB of
highly compressible output, so `redecode` can be that large. `OpenAtError::Resync` and `NeedMore` say when the
held bytes or the known plaintext do not reach far enough back: fetch from earlier, or supply more plaintext.

#### Seeding the window from held plaintext

`OpenAtOptions { seed: Seed::HeldPlaintext { strict }, .. }` is for a handover that holds the output before the
target (from an earlier copy) and wants to download as little of the new copy as it can. The plan fetches packed
bytes from shortly before the target's estimated packed position: by default a filter's reach (4 MiB of output) at
twice the member's average packing ratio plus `SEED_SEARCH` (2 MiB), enough for a guarded restart; `search` sets it.
Its `donor` is, as for a checked plan, the dictionary and a filter's reach before the target, twice: the window of a
guarded restart's check lies that far back. `complete_rar5` starts the decoder with `Unpacker::resume_seeded`: the
window is filled from the held plaintext instead of being followed from far back. When the plaintext given does not
reach a guarded restart's check, the nearest unguarded restart is taken instead (noted as `SeedSuspect::Unguarded`;
`strict` refuses it). A failover should pass `OpenAtOptions::estimate` (copy A's packed position of the target): the
average packing ratio can be several MB off on mixed content, leaving the target outside the bytes fetched first.
A smaller `search` fetches less but can give an unguarded restart (below).

The output is then **unverified**: `Rar5Resume::checked` is false unless the follow happened to cover the window.
RAR's window holds output as it was before its filters (E8, E8E9, ARM, delta) ran, while held plaintext is filtered
output, so a filter declared before the restart, which nothing fetched shows, may have changed bytes a later match
copies. Prove the member with its CRC32 or BLAKE2sp at the end and fall back to a checked plan
(`Seed::Checked`, the default) when it fails. On the way, `decoder.seed_suspect()` / `seed_suspects()` give early
signs, the first of each kind, most telling first:

- `BeforeSeed { source }`: a match copied from before the held plaintext (window bytes never seeded): wrong unless
  what it wrote is overwritten. Supply more plaintext.
- `Unguarded`: noted at the restart, before decoding: it is not guarded, so a filter declared before it may cover
  output after it, and the held plaintext does not reach past such a filter's longest reach. A plain `resync` result
  is never guarded and never proves its window (its floor of 0 is no proof).
- `Filter`: the decoder met a filter record. That filter decodes right, but filters come where content suits them
  (x86 code, tables), so earlier ones may have changed seeded bytes.
- `UncheckedCopy { source }`: a match copied from seeded output a filter it never saw may have changed. On video
  this fires on nearly every handover (long matches reach back past the restart), so it says little on its own.

With `strict`, a copy that a checked decoder would refuse is refused (`Error::BadChecksum`) instead of decoded, and
an unguarded restart is refused at the start (`Error::Unsupported`).
No scan cheaper than the follow itself can prove there was no filter before the restart: filter records sit inside
the Huffman-coded blocks, which only decoding them reads.

Measured on z-fixtures (release, M4, one thread; plaintext only up to the target; checked against the payload):

| set | target | fetched (checked plan) | result | suspects |
|---|---|---|---|---|
| F03, F04, F12 video | 12.0 MB | 34.5 MB (36.1 MB) | exact, 6.4 KB back, unverified, 0.3 s | `UncheckedCopy` |
| F03, F04, F12 video | 28.8 MB | 17.7 MB (36.1 MB) | exact, 5.5 KB back, unverified, 0.3 s | `UncheckedCopy` |
| F05, F06, F12 mixed | 8.7 MB | 14.0 MB (14.0 MB) | exact, 678 KB back, checked (the reach covers the member's start), 25 ms | `Filter` |
| F05, F06, F12 mixed | 20.8 MB | 9.4 MB (14.0 MB) | exact, 6.6 MB back (block start), unverified, 0.2 s | `UncheckedCopy` |

An earlier run with a 2 MiB `search` and no guard fetched 26.1 / 9.3 MB on the video sets (exact) and was refused at
20.8 MB on the mixed ones (search exhausted); such unguarded restarts are now noted as `Unguarded`. A refused seeded plan is retried with a larger `search`, or as
a checked plan.

### 7z LZMA2

An LZMA2 restart must sit at a chunk start, and only a walk of chunk headers from the stream's first byte proves
where those are. Header-like bytes inside a stored payload form chains that end at the true end marker, and since
repeated plaintext can make such a chain match any amount of the known output, no plaintext match can prove
the framing. So the plan's `framing` says how the chunk starts become known:

- `Lzma2Framing::HeaderWalk` (unencrypted folders): walk the headers from the folder's packed stream start up to
  past the target, reading only each header (at most 6 bytes; the next header lies a header and a payload further
  on). `Lzma2IndexBuilder::for_folder` does this over a `VolumeSource`, and `MemberMap::lzma2_chunks` does it over
  volumes in memory. Pass the index to `complete_lzma2`. The bulk fetch starts at `fetch_from`. LZMA2 chunks carry at
  most 64 KiB of packed bytes, so the headers are that close: a download in larger pieces (Usenet articles, about
  750 KB) touches every piece before the target for the walk, even though it reads only a few bytes of each.
- `Lzma2Framing::FromStart` (7zAES under LZMA2): headers are ciphertext, so the plan fetches the folder from its
  start (`fetch_from` is 0) and `complete_lzma2` walks the decrypted bytes itself. A caller that decrypts header
  blocks on its own can pass an index instead.

`complete_lzma2(&map, &plan, packed_from, packed, known_base, known, framing, &Lzma2DecodeOptions) -> Lzma2Resume`
restarts at the last chunk at or before the target that resets the LZMA state or stores its bytes, among the chunk
starts in `framing` (an index walked from the stream's start; `None` walks `packed`, which must then start at 0)
whose header is in `packed`. From there the chunks must run to the end marker at exactly the LZMA2 stream's end (the
folder's packed size, or under 7zAES the AES coder's output size, which leaves out the block padding). It decodes to
the folder's end with the known output before the restart as the dictionary (only its last dictionary-sized bytes are
used): `bytes` is the folder's output from `output` on, bounded by `Lzma2DecodeOptions::max_output` (stored and
decoded output together; `OpenAtError::OutputLimit` past it), and `redecode` is `folder_target - output`. Without a
usable chunk start the result is `NeedMore`. A stored chunk is a restart only when the framing shows that the next LZMA chunk after
it resets the state (7-Zip `-mmt` goes on after a run of stored chunks with an LZMA chunk that continues the state from
before them): when the nearest such restart lies before the packed bytes held, the result is
`FetchFrom { packed, output }`: fetch from `packed`, supply output from `output` less the dictionary, and complete again.
A framing index that ends before the folder's end (one walked only up to past the target) is walked on over the packed
bytes held when they go on from where it ends; a stored candidate the index still cannot rule out is tried, and once one
meets an LZMA chunk that continues the state, the rest of that last stored run is given up with it (they would all
meet it). The stream's first chunk is always a restart. When decoding reaches an LZMA chunk whose dictionary the known
output does not cover (from the restart less the dictionary, unless a chunk since resets it), the result is
`NeedMore` for that range, not a decode error. The search is one pass back over the index. A member's output is the folder's from its `stream_start`. A folder
counts as LZMA2 only with exactly one LZMA2 coder, alone or under 7zAES.

Which volume bytes a plan never needs, per article, is what `ContainerRebuilder` reports as `Unneeded` with the plan
in `RebuildOptions::plans`; `skipped_spans(&map, &plan)` lists them (see [container rebuild](container-rebuild.md)).

## Limits

- RAR 4.x compressed members, ZIP compressed entries and 7z folders with coders other than LZMA2 (and 7zAES under
  it) restart only at their start.
- `complete_lzma2` returns the decoded rest of the folder in one buffer (`Lzma2DecodeOptions::max_output`).
- A 7z LZMA2 restart needs the folder's packed bytes to its end marker, since chunk offsets are fixed from there.
