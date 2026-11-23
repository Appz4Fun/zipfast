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

### 7z LZMA2

`complete_lzma2(&map, &plan, packed_from, packed, known_base, known, &Lzma2DecodeOptions) -> Lzma2Resume` needs the
folder's packed bytes from `fetch_from` to the folder's end. It finds the first chunk header chain in them that runs
to the end marker at exactly the LZMA2 stream's end (the folder's packed size, or under 7zAES the AES coder's output
size, which leaves out the block padding); counting back from the folder's size gives every chunk's output offset.
A single chunk and its end marker count as a chain. It restarts
at the last chunk at or before the target that resets the LZMA state or stores its bytes and checks out against the
known output, and decodes from there to the folder's end with the known output before it as the dictionary:
`bytes` is the folder's output from `output` on, bounded by `Lzma2DecodeOptions::max_output` (stored and decoded
output together; `OpenAtError::OutputLimit` past it), and `redecode` is `folder_target - output`. A member's output is
the folder's from its `stream_start`.

## Limits

- RAR 4.x compressed members, ZIP compressed entries and 7z folders with coders other than LZMA2 (and 7zAES under
  it) restart only at their start.
- `complete_lzma2` returns the decoded rest of the folder in one buffer (`Lzma2DecodeOptions::max_output`).
- A 7z LZMA2 restart needs the folder's packed bytes to its end marker, since chunk offsets are fixed from there.
