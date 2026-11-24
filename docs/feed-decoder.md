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
  The hint is per decoder: when several decoders share a source and their members share packed bytes (the members of
  one 7z folder all read the folder's packed stream, `MapFolder::packed`, and list no `pieces` of their own), the
  source must keep bytes until no decoder reads them. Count releases per decoder, or ignore them; `ArticleBuffer`
  drops whatever it is told. The [live feed example](#live-feed-example) ignores releases when the fed members'
  bytes overlap.

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

`FeedSink::read_earlier(stream_offset, buf) -> usize` (default: nothing held) gives back output of the earlier
members of the member's solid stream (RAR) or folder (7z), at offsets in that stream's output before the member's
start (`FeedDecoder::stream_start()`). A window that reaches back into earlier members reads it: a solid successor
started from a carry or restored from a snapshot, and restarts, repairs and skips close after a member's start. See
[solid streams and folders](#solid-streams-and-folders).

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
| `unproven` | output written so far was decoded from a window not proven yet: seeded from held output past a hole, or handed over from an earlier solid member that was not done with its CRC matched; WinZip AES output until its authentication code matches; cleared once done with `crc_ok` or `auth_ok` true and neither false |
| `auth_ok` | WinZip AES, once done: whether the authentication code matched; None for other members and when it could not be checked (see [ZIP](#zip)) |

`NeedBytes` ranges are exact: a `Next` need is the run of bytes from the frontier the source reported absent, a
`Repair` need the missing bytes a repair stopped at. Both are cut at piece (volume) boundaries.

The CRC is kept per run of contiguous output and joined (`crc32::combine`) as holes are repaired, so the verdict
needs no second pass. Members with only a BLAKE2sp hash, and WinZip AE-2 entries (no CRC), report `crc_ok: None`.
The WinZip AES authentication code is checked (`auth_ok`, see [ZIP](#zip)); RAR part checks are not checked here (use
`MemberReader` or a persistent partial's verify for those).

`FeedOptions`: `password`, `limits` (KDF budgets and password sizes, as for maps), `control` (a `SessionControl`:
cancels a run between reads and a key derivation in progress), `read_chunk` (the largest read, default 256 KiB),
`max_needs`, `run_budget`, `max_window` (the largest RAR 5.0 dictionary, or LZMA2 decoder dictionary, a member may allocate, default 1 GiB). Keys are derived in `new`, so a wrong password shows there where the member records a
check value (RAR 5.0 with a check, WinZip AES); otherwise as `crc_ok: Some(false)`.

`stats()` counts packed bytes read, output bytes written, holes met and output `redecoded` (decoded again without
being written: a compressed repair from its checkpoint up to the lost range, a restore from its checkpoint up to the
old frontier, for a 7z member after its folder's first started on its own the folder output before it, and for a RAR
4.x solid successor started on its own the stream's earlier members), over the decoder's life.

## Layers

| member | holes |
|---|---|
| plain stored (RAR 5.0, RAR 4.x, ZIP method 0, 7z Copy): `OutputMapping::Direct` | output byte = stream byte: the hole's own output is lost; the main decode goes on right after it |
| AES-CBC stored (RAR 5.0, RAR 4.x AES-128, the first member of a 7zAES-over-Copy folder): `CbcBlocks` | each block needs the ciphertext block before it: the lost output runs from the start of the block the hole begins in to the end of the block after the one it ends in (`[floor16(start), ceil16(end) + 16)`); the main decode restarts there with the block before as IV |
| WinZip AES stored: `Counter { skip }` | each byte decrypts on its own: exactly the hole's output is lost; the authentication code is caught up after repairs (see [ZIP](#zip)) |
| ZIP Deflate and Deflate64 (methods 8 and 9; plain, ZipCrypto, WinZip AES), ZipCrypto stored | waits at every hole; see [ZIP](#zip) |
| compressed RAR 5.0 (methods 1-5, AES-256 under them too) | see [compressed RAR 5.0](#compressed-rar-50); solid successors [below](#solid-streams-and-folders) |
| 7z folders of one LZMA2 coder, alone or over 7zAES, any member of the folder | see [7z LZMA2](#7z-lzma2); members in sequence [below](#solid-streams-and-folders) |
| compressed RAR 4.x (unpack versions 1.5, 2.0, 2.6, 2.9: LZ, audio, PPMd, filters; AES-128 under them too) | waits at every hole; see [compressed RAR 4.x](#compressed-rar-4x); solid successors [below](#solid-streams-and-folders) |
| other ZIP methods (bzip2, LZMA, PPMd, ...), other 7z coder chains | refused (`Compressed`, `Coders`); see [next](#next) |

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

**Cost of a hole.** Profiled with `live_feed` on F07, F08 and F10 (drop 2% and 5%): a hole costs what decoding the
output held behind it costs (about 36 to 78 ms per hole on F08 and F10, where 20 MB of output waits behind the
hole; 1 to 5 ms on F07, mostly stored chunks). 95% of it is liblzma's decode loop (the decode rate with no hole is
the same, 250 to 300 MB/s), `redecoded` is 0 and every packed byte is read once, so resuming costs nothing beyond
the decode itself. It could only fall with chunk-level parallelism after the repair (an independent block per
thread), or by decoding before the repair, which the framing rule forbids.

**Memory.** Packed bytes from the main decode's restart point on are kept for a repair or a restore (at most 64 MiB
behind its read position; older ones are released and asked for again as needs when a repair reads them).


## Compressed RAR 4.x

The main decode feeds the packed bytes (decrypted first under AES-128) to the RAR 2.9/3.x decoder (and its RAR 1.5
and 2.0 engines, picked by the header's unpack version, `MapMember::unpack_version`) in order, and writes its output
in order. RAR 4.x has **no restart point inside a member**: there is no block resync for its LZ or PPMd streams, so a
hole cannot be skipped, with or without held output. At a hole the main decode waits (`stalled`, the hole's bytes the
first `Next` need) and goes on from where it stands when they come; nothing is lost, repaired or decoded twice.

The decoder's state cannot be checkpointed cheaply (a window of up to 4 MiB, a PPMd model of up to 256 MiB, Huffman
tables, pending filters), so a snapshot records only the frontier: a restore **decodes again from the member's start**
up to it, writing nothing before it, and that cost is counted in `stats().redecoded` (at most the frontier). The bytes
the decoder passed are released as it goes (memory stays bounded), so a restored decoder asks for the member's packed
bytes from its start again (`Next` needs). The 1.5/2.0 engines and PPMd hold up to 4 KiB of input back as lookahead,
so their output can trail the bytes fed by that much.

## ZIP

ZIP members, single files and split sets alike (Info-ZIP `.z01` ... `.zip` sets, mapped as `MemberMap` maps them;
see [member maps](member-map.md)), are decoded member by member: ZIP has no solid streams. Sizes come from the central
directory, so members written with data descriptors (flag bit 3, zeros in the local header) feed as any other. A
byte-split set (`name.zip.001`, `.002`, ...) is one ZIP cut anywhere: map the pieces concatenated as one volume, and
place each piece's articles at its start (the sum of the earlier pieces' sizes) plus their own offset.

- **Stored, plain or WinZip AES**: the stored lanes above; holes are skipped and repaired.
- **Deflate and Deflate64, plain or WinZip AES**: the main decode decrypts (WinZip AES counter mode decrypts each
  byte on its own) and feeds the packed bytes to zipfast's inflater (`inflate64`, which reads both) in order, and
  writes the output in order. Deflate has no restart point a decoder can find after a hole: a block starts at a bit
  offset known only by decoding up to it, and the block after a hole copies from output the hole hid. So at a hole
  the main decode waits (`stalled`, the hole's bytes the first `Next` need, the bytes after it `Ahead`) and goes on
  with its decoder when they come; nothing is lost, repaired or decoded twice. No resync over the data after a hole is
  attempted (a stored block's LEN/NLEN after a hole could be found, but its output offset and the window before it
  cannot be proven before the member's CRC, and the blocks after it copy from the hole's output anyway).
- **ZipCrypto, stored or under Deflate**: its keystream depends on every byte before, so it waits at holes too. A wrong
  password shows once the 12-byte header is read (its last byte is the check byte, `WrongPassword`; one wrong password
  in 256 passes it and fails the CRC).

**Checkpoints.** After every Deflate block the main decode notes the block boundary it passed with its output written:
the boundary's bit offset in the packed stream and the output offset there, 16 bytes, no window. A restore reads the
window back from the sink (`read_held`, the 32 KiB of output before the boundary for Deflate, 64 KiB for Deflate64;
`HeldOutput` when not held), starts the inflater at the boundary's bit and decodes up to the old frontier without
writing: `redecoded` is at most one block (the encoders end blocks every 16 to 64 Ki symbols; under 20 KB on the test
content). The packed bytes from the checkpoint on are kept (not released), so a restore in the same session reads
nothing again; one after a restart asks for them from the checkpoint (`Next` needs). A ZipCrypto member's keystream
cannot be rebuilt at a checkpoint without the bytes before it (keeping its keys in a snapshot would leak them), so a
restore reads the member's packed bytes from its start again (decrypting only: nothing is inflated or written before
the checkpoint); those are `Next` needs after a restart.

**WinZip AES authentication.** The authentication code (HMAC-SHA1 over the ciphertext, the 10 bytes after it) is
hashed in order as the main decode reads, and compared once its bytes are read: `auth_ok`, and `done` waits for them
(they are a `Next` need once the output is written). Until then the output is `unproven` (AE-2 members record no CRC,
so the code is all there is). A stored member skips holes, so its code is caught up after the repairs from the output
held (`read_held`, encrypted again); with a sink that holds nothing it cannot be (`auth_ok: None`, then the CRC alone
proves an AE-1 member). A restore of a stored member catches it up the same way. A restored Deflate member whose
checkpoint is past the data's start does not read the ciphertext before it again, so its code is not checked
(`auth_ok: None`): an AE-1 member is proven by its CRC, an AE-2 member stays `unproven`.

## Solid streams and folders

A solid RAR stream decodes its members one after another with one decoder: a member's window (and tables, match
history, PPMd model) is what the members before it left. A 7z folder is one LZMA2 stream holding its members end to
end. `FeedDecoder::next_solid(&mut self, &map, index, options)` starts the decoder of the next member from this
one's state, once this one's main decode has finished (its frontier at its size), however its repairs stand:

```rust,ignore
let mut decoders = vec![FeedDecoder::new(&map, first, options.clone())?];
loop {
    for (k, d) in decoders.iter_mut().enumerate() {
        d.run(&mut articles, &mut sinks.member(k))?;     // a sink per member, see read_earlier
    }
    let last = decoders.last_mut().unwrap();
    if last.status().frontier == last.size() && more_members {
        let next = last.next_solid(&map, next_index, options.clone())?;
        decoders.push(next);
    }
    // ... feed articles, stop once every decoder is done
}
```

The earlier decoder keeps its lost ranges and repairs them as before; the new one reads on from where the earlier
one stopped, so nothing before the new member is decoded again (`redecoded` 0 on a clean feed). A hand-off of
anything else (not the next member of the stream or folder, a main decode still running, a second hand-off) is
`FeedError::Handoff`. A member's sink gives the earlier members' output through `read_earlier` (stream offsets),
the caller's view over the earlier members' files.

**RAR 5.0.** Every member of a solid stream decodes with one window, sized for the stream's largest dictionary
(`FeedOptions::max_window` bounds it). Checkpoints count stream offsets, and a filter they record addresses from its
own member's start, so a checkpoint in member N+1 rebuilds its window from member N's output (`read_earlier`) and
undoes member N's filters there as the decoder held them. At its end a member keeps its decoder for the hand-off
and its state there as a checkpoint at the next member's start: the **carry**. `solid_carry()` gives it
(`SolidCarry`, about 500 bytes, `to_bytes`/`from_bytes`, no plaintext or keys), and the member's snapshots keep it
from then on. `FeedDecoder::resume_solid(&map, index, options, &carry)` starts the next member from it, in this
process or a later one: its first run reads the window (the dictionary's worth of output before the member) back
through `read_earlier` (`FeedError::EarlierOutput` when not held), and the decoder state is exact. A finished member
restored from its snapshot hands over the same way (`next_solid` falls back to its carry). A carry records the
member it was taken from, so `resume_solid` refuses one of another stream (`Handoff`), even with the same sizes. The
successor is set up (keys, limits) before the live decoder leaves the member before it, so a hand-off that fails
there (`WrongPassword`, `Unsupported(Window)`) can be tried again in-session. An empty member's blocks are decoded too
(they may set the tables the next member goes on with) before it hands over; an empty member without packed bytes
passes the stream on as it got it. `FeedDecoder::new` on a solid successor is `Unsupported(Solid)`: without the carry
its window and match history are unknown.

Holes work as in a single member, at stream offsets: a skip over held output reads the window from the earlier
members' output too, and a repair or restore whose checkpoint window reaches before the member reads it there. A
member that skipped a hole hands over once its main decode passes its end, with ranges still lost: the next member's
window holds the held output in those ranges, so it is `unproven` until its own CRC matches (and so is the carry,
`SolidCarry::unproven`). A member's CRC proves only its own output: the end of the output not proven is handed on
from member to member while it lies within a window's reach of the next member's start, so a member after a short
one that passed its CRC is still `unproven` when its window holds the older unproven bytes. A member that restarted
from held output hands on its window as unproven while that restart is within reach, even once its own CRC matches:
the window holds the held output as plaintext where the decoder held a filter's input, which a repair does not
rebuild. A member waiting at a hole without held output holds back every member after it
(the next one starts once its bytes come). A RAR 5.0 restart found at a member's very end (only the cipher's padding
after it) is not taken; the last block before it is.

**RAR 4.x.** The decoder (window, tables, distances, PPMd model, filters) goes on into the next member: each member's
end-of-file marker is read past its output and says where the next starts. The successor is set up (keys, limits)
before the decoder leaves the member before it, so a hand-off that fails there can be tried again; the handed decoder
is canceled through the new member's `FeedOptions::control` from then on. A map whose member before `index` is not
this decoder's member (another archive's) is refused (`Handoff`), keeping the decoder. A successor that was not handed the
decoder (`FeedDecoder::new`, or `restore` from a snapshot) **decodes the stream again from its first member**,
writing nothing before its own member: those members' packed bytes are asked for again (`Next` needs, members
released one by one as they are passed), their keys derived again (one RAR 3.x key derivation per encrypted member,
all charged to the one session budget, `ProgressiveLimits::kdf_session_blocks`), and their output counted in `redecoded`, so a restore costs the stream's output up to the snapshot's frontier
(`stream_start() + frontier`). While it decodes them again its frontier (and a snapshot's) stays where its own
output stands. There is no restart point inside a RAR 4.x member, so nothing cheaper exists without
the decoder's state; keep the session (and the hand-off) alive across a set where you can.

**7z.** The LZMA2 decoder goes on at the member's end: the output it decoded past the member's end in its last step
(at most a chunk's worth) goes to the next member, which writes it first. A member that a successor follows walks
past its end for a restart after a hole: lost output that runs on into the next member is handed over as lost, with
its repair (from the restart point before the hole, which then lies in the earlier member; that output is decoded
again, not written). Lost output can run on through several members; a member a hole skips whole is done once it is handed over, and
hands the restart on to the next. The packed bytes the members share are released
in turn: a member never releases what the members after it start from, a successor never what the members before it
may still read. A dictionary taken from output the decoder did not write (held output, an earlier member's) leaves
the member `unproven` until its CRC matches, and its successors while that output is within the dictionary's reach
(as for RAR 5.0). `FeedDecoder::new` on a later member still starts at the last dictionary
reset before it (decoding the folder output in between again). A member's snapshot taken after its main decode
finished and before the hand-off keeps what it is to hand over: the restart point to go on from (the output past its
end is decoded again from there) and the lost output past its end with its repairs; a successor snapshotted before
its first run restores at that restart point too. The next member is the folder's
next member in the map, also a zero-length one at the folder's end; a zero-length member with a member after it
(at the folder's start, say) runs its main decode to its own start and hands over from there (under 7zAES with
its key). The next member is set up (keys, limits) before the state leaves the member before it, so a hand-off that
fails there can be tried again.

A solid member started in a later process ([`FeedDecoder::resume_solid`], or a restored successor whose window
reaches back past its start) reads the earlier members' output through [`FeedSink::read_earlier`]. With persistent
partials, `zipfast::partial::SolidStreamSink` provides it over the members' direct partials (stream offsets mapped
to member and offset by `stream_start`); see `docs/persistent-partials.md` ("Solid streams").

## Saving and restoring

`snapshot()` captures the decoder between runs: the main decode's position (under CBC its block and that block's
IV; for a compressed member its checkpoint, frontier and the skipped holes' checkpoints and restarts), the lost
ranges, the CRC runs and the stats. It never holds keys or plaintext. `FeedSnapshot::to_bytes()` and `from_bytes()`
give a compact versioned encoding (`ZFFD`, version 3, which adds `unproven` and the window's unproven end; versions
1 and 2 still load) to keep next to the
output file. It records a fingerprint of the member (name, sizes, method, cipher parameters, piece positions), so it
restores only onto that member.
`FeedDecoder::restore(&map, member, options, &snapshot)` derives the key again and continues from there: bytes read
past the frontier short of a block are read again, and lost ranges are repaired as before. A snapshot of another
member or layer is `FeedError::Snapshot`. An LZMA2 member restores at its restart point (its dictionary read back when it is a state reset), decodes up to the
old frontier without writing and goes on; repairs restart from their restart points. A compressed RAR 4.x member restores at its start (above). A compressed RAR 5.0 member restores at its checkpoint, reading its window back
with `read_held` (`FeedError::HeldOutput` when the sink does not give it), decodes up to the old frontier without
writing (counted in `redecoded`: at most the output since the last block boundary before the snapshot) and goes
on; it never decodes from the member's start unless the snapshot was taken there. A ZIP Deflate member restores at its
last block boundary (above), a ZipCrypto one reads its packed bytes from the start again. Persistent partials (`docs/persistent-partials.md`) remain the durable,
journaled store for output; a snapshot is the decoder's position over it. Kept as a direct partial's cursor
(`PartialFile::set_cursor`), it commits atomically with the output it describes.

## Live feed example

`examples/live_feed/` is a reference integration for a downloader: it takes a multi-volume RAR 5.0, RAR 4.x, 7z or
ZIP set (a single `.zip`, an Info-ZIP `.z01` ... `.zip` set, or a byte split `.zip.001`, which it maps as the pieces
concatenated), plays it as a Usenet download and extracts while the articles arrive. `sim.rs` holds everything (it is also what
`tests/live_feed.rs` runs on small fixtures); `main.rs` is its command line.

```text
cargo run --release --features persistent-partials --example live_feed -- \
    [--password PW] [--article 750000] [--seed 1] [--lateness 8|all] [--window 4] [--drop 0.05] [--drop-articles I,J,..] \
    [--repair-delay N] [--sink auto|file|partial] [--group-holes] [--group-refills] [--group-commit-mib N] \
    [--max-needs 64] [--buffer-mib N] [--work DIR] [--keep] [--no-verify] [--runs N] [--label NAME] [--header] \
    <set dir | volume...>
```

The simulation:

- **Articles.** Each volume is cut into decoded articles of `--article` bytes. The map is built from the whole
  volumes first, since a downloader has the headers before the data.
- **Network.** Articles arrive in volume order, each up to `--lateness` places late (`all` shuffles the whole set,
  seeded by `--seed`). The downloader can choose among the next `--window` arrivals (its connections in flight). A
  `--drop` fraction fails on the first try: the article is `mark_lost` in the `ArticleBuffer`, and it can be
  fetched again `--repair-delay` deliveries later (by default once the first pass is over), as a repair.
  `--drop-articles` names exactly which articles fail (indices over the whole set, volume by volume).
- **Decoding.** After every delivery or failure, each member's `FeedDecoder` runs over the shared `ArticleBuffer`.
  Its `FeedStatus::needs` choose the next delivery (see below).
- **Output.** With `persistent-partials`, every fed member, whatever its container and method (stored or compressed
  RAR 5.0 and RAR 4.x, `-hp` sets, 7z Copy and LZMA2, encrypted or not), writes into a `PartialFile` that
  `DirectPartials` creates straight from the member map (see `docs/persistent-partials.md`, "Partials from a member
  map"): born at full size with nothing written, no session and no header read again. The decoder's `write_at`
  reaches it through a `DirectSink`, whose writes join the open group commit; `read_held` gives back what the partial
  holds. After every run that wrote something, the decoder's snapshot is set as the partial's cursor, which commits
  with the output it describes. Every member's handle stays open until its feed is done; each holds about six
  descriptors, so the example sizes the limits with `PartialLimits::for_members` (the defaults, 16 open partials and
  64 files, run out at about ten members). RustyGet must do the same, or close and reopen handles beyond the 4096
  ceiling. Without the feature, or with `--sink file`, members write a preallocated plain file instead
  (`plain/member-NNNNN.out`, named by member index alone, synced once, not durable). `--group-holes` and
  `--group-refills` set `PartialLimits::group_holes` and `group_refills`; the feed path records no hole and calls no
  `refill_from_packed`, so neither changes anything here (lost output is just unknown output, and repairs are
  plaintext writes, which join the group anyway). `genesis_ms` is the time to create the partials.
- **Restart.** `--restart-at N` restarts the downloader after `N` deliveries: every decoder, sink and the article
  buffer are dropped (each partial's open group and last cursor commit as its handle drops), the partials are found
  again (`DirectOrigin::Adopted`), each decoder is restored from its partial's cursor, and the articles the decoders
  need again (their `NeedBytes` over articles already delivered) are fetched again as repairs due now. Plain-file
  members start over. `restart_ms` and `refetched` report the cost.
- **Report.** stdout gets one tab-separated line per run (`--header` prints the column names first): wall time,
  MB/s, bytes written, `redecoded`, packed bytes read, holes met, repair writes (`refills`: writes into a range a
  status listed as lost) and their bytes, the
  repair time and that time per dropped article, stalls, syncs (`durable_sync_count` for partials, one per plain
  file), peak buffer, the CRC verdict (`crc_ok`, plus `poll_verify` for partials), and whether the output equals a
  straight extraction of the set (each output must equal one file the extraction wrote, each file used once). The
  exit status is non-zero when a check fails.

### From `NeedBytes` to download priority

Each `NeedBytes` names a byte range of one volume. A downloader knows where each of its segments (articles) lies
in its volume, so a need becomes the articles covering that range. With equal articles that is
`first_article[volume] + range.start / article ..= (range.end - 1) / article` (`Articles::covering`); with an NZB,
search the segment offsets instead. `priority` builds one list over all members:

1. every `Next` need of every member: a main decode is waiting for it;
2. then every `Repair` need: it repairs output reported lost;
3. then every `Ahead` need: read later, not held yet.

Members keep archive order within each kind, and an article listed once keeps its first (most urgent) place. The
network then delivers the candidate ranked highest among those it can deliver now (the next `--window` arrivals and
the repairs that are due), or the next arrival when none is ranked. The `picks` column counts the times this changed
the order. This matters most for a compressed member that waits at a hole: its `Next` need is the dropped article,
and it moves ahead of every `Ahead` article as soon as the article can be fetched again.

## Errors

Missing bytes are never an error. `FeedError`: `NoSuchMember`, `Unsupported(FeedUnsupported)`, `IncompleteMember`
(the map lists only some pieces), `PasswordRequired`, `WrongPassword`, `Key` (other key-derivation failures:
limits), `Malformed` (an inconsistent map, checked as `MemberReader` checks it), `SourceContract`, `Write { out,
error }`, `Canceled`, `Snapshot`, `Decode { out, error }` (compressed data that does not decode, a repair that does
not meet its restart), `HeldOutput { range }` (a checkpoint's window the sink does not give back),
`EarlierOutput { range }` (earlier solid members' output, stream offsets, that `read_earlier` does not give),
`Handoff` (a solid hand-off that does not fit), and `AlreadyFailed` after a failed run (restore a snapshot instead).

## Next

- 7z LZMA2 under BCJ or Delta (a chain of coders), LZMA (not LZMA2) folders.
- ZIP: a Deflate skip past a hole with held output past it (as RAR 5.0 does: find the block boundary after the hole
  whose decode matches the held output), and checking a restored WinZip AES Deflate member's code by reading its
  ciphertext again.
- A skip without held output past the hole is impossible for compressed RAR data (see above). RAR 4.x members have no
  restart search at all: a resync over RAR 2.9 LZ blocks (tables at block starts) and cheap decoder checkpoints would
  let holes be skipped and restores (also of solid successors) start near their frontier.
- A 7z repair in a later member whose lost output began in an earlier one decodes from that member's restart point;
  in a folder that resets only at its start, several such repairs decode the same stretch again each.

## Tests

`tests/feed_decoder.rs`: RAR 5.0 stored over six volumes, RAR 5.0 AES stored over four volumes (one with a size
that is not a block multiple) and WinZip AES, cut into articles of 64 to 4,096 bytes, fed shuffled with every third
to seventh article missing, then the missing ones supplied in another order after a snapshot round trip: the output
equals the payload with no byte written twice, the CRC matches, the needs are exactly the missing articles' data
bytes, and bytes read again stay within two blocks per hole. Also: `Next` and `Ahead` needs before anything
arrives, the CBC hole geometry, a hole met while the main decode waits inside a partial CBC block (the IV block
before it stays held for the repair), run budgets with a restore in between, release keeping an in-order feed's buffer to
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

Compressed RAR 4.x (`tests/feed_decoder_rar4.rs`): every compressed, non-solid member the fixtures under
`tests/fixtures/rar4*` hold that decodes (35 members: unpack versions 1.5, 2.0 and 2.9; LZ, audio, PPMd, RarVM
filters (x86 E8/E9, delta, RGB, audio, Itanium), AES-128, old- and new-style multi-volume sets), cut into 97-byte
articles and into six articles, shuffled, every fifth or third missing: the decoder waits at the first hole (its bytes
the first `Next` need, nothing lost), and once the missing articles come (with a snapshot round trip half way, after
which the released bytes are asked for from the member's start and given again) the output is exact, CRC verified,
each byte written once, and `redecoded` is at most the frontier at the snapshot (0 to 164 KB on the fixtures). A solid
successor on its own decodes its stream again (below), an encrypted member without a password is `PasswordRequired`.

ZIP (`tests/feed_decoder_zip.rs`): Deflate members written forward (data descriptors) and to a seekable sink (sizes
in the local headers), 0.7 to 2 MB of text with incompressible stretches; ZipCrypto Deflate and stored; WinZip AES
AE-1 and AE-2, Deflate and stored; a byte split; the Info-ZIP split fixtures (`deflated`, `crypt`: stored ZipCrypto
across the boundary, with a data descriptor); and the Deflate64 fixtures (plain, ZipCrypto, WinZip AES, checked against
their SHA-256). Each is cut into articles of 700 to 750,000 bytes, shuffled, every second to fifth missing: the main
decode waits at the first hole (stored AES skips it), the needs are exactly the missing articles' bytes the member reads
from the hole on (the first `Next`), and once the missing ones come, with a snapshot round trip half way (the restored
decoder given back whatever it asks for again), the output is exact, CRC (and authentication code) verified, each byte
written once, and `redecoded` is what the restore decoded again, at most one block (0 to 20 KB). Plain and AES restores
read nothing again; ZipCrypto restores read the packed bytes before their checkpoint again. Also: a restore 1.2 MB into
a 2 MB member, in the session and in a new one that holds only the bytes from the checkpoint on (`HeldOutput` without
the window), a hole stalling with nothing lost and counted once, a damaged authentication code (`auth_ok: Some(false)`),
wrong passwords, and the buffer holding only the bytes from the last block boundary on. `src/inflate64/tests.rs`
resumes Deflate and Deflate64 streams at every block boundary from the window and the bit offset. `tests/live_feed.rs`
runs a mixed ZIP (Deflate, AES, ZipCrypto Deflate and stored), its byte split and the Info-ZIP split fixtures through
the live feed example, also with a restart part way.

Restarts (`tests/persistent_direct.rs`, see `docs/persistent-partials.md`): every container is fed into persistent
partials, restarted part way and restored from each partial's cursor, and on the z-fixtures `live_feed --restart-at 15`
and `30` finish exact on every set (F01-F12: RAR 5.0 stored, AES, `-hp`, `-m3`/`-m5`, 7z LZMA2, 7zAES, `-mhe`), with
1 to 30 articles fetched again and 40-140 ms to reopen and restore. LZMA2 members restore at their restart point
and decode up to the old frontier again (F07: 9-22 MB `redecoded`).

`tests/live_feed.rs` runs the [live feed example](#live-feed-example)'s core on a generated stored RAR 5.0 set (a
persistent partial with `persistent-partials`, a plain file without), the RAR 4.x volume fixture and the 7z volume
fixture. Each is delivered out of order with a fifth of the articles dropped and repaired later, and checked
against a straight extraction. Also covered:

- a set of 20 stored members over two volumes, beyond the default partial limits, two of whose names flatten
  alike;
- a dropped trailing article counting as a refill when repaired;
- old-style volume discovery past `.r99` (`.s00`, `.s01`);
- the three members of one solid 7z LZMA2 folder (`lzma2_chunks.7z` cut into volumes) fed from one buffer;
- a 250-byte member name, and stored and compressed members whose names match the plain-file fallback's;
- backslash names checked against the file the extraction wrote, whether it made `d/x` (Windows-made) or kept the
  backslash (Unix-made);
- the need-to-article mapping and the priority order;
- a restart part way (`restart_at`) on the stored RAR 5.0, RAR 4.x and 7z volume sets, with partials and plain files.

Solid streams (`tests/feed_decoder_solid.rs`, `tests/feed_decoder_solid_rar4.rs`, `tests/feed_decoder_7z.rs`):

- RAR 5.0: three members of 220 to 230 KB, each starting with copies of the one before (its window and first match
  distances reach into the earlier member), plain and AES, in 5,000 to 7,000-byte articles shuffled: handed over
  member to member, exact, CRCs verified, each byte written once, `redecoded` 0, nothing read back. Holes without held
  output: the first member waits, nothing after it starts, and once the bytes come all finish exact with `redecoded`
  0. Holes with held output, one late in member 0 (its lost output is what member 1 copies), one early in member 1
  (the restart's window reaches into member 0) and one in member 2: every member starts before any repair, the
  successors are `unproven` until done, a snapshot of member 1 is restored half way through the late articles, and
  all end exact with `redecoded` 0. A carry taken at member 0's end, serialized, starts member 1 (its window read back
  from member 0's output), and member 1's snapshot restores across the boundary (under 64 KiB decoded again). An E8
  filter in member 1 over output member 2 copies is undone relative to member 1's start when member 2 starts from a
  carry (with the filter undone at the stream's offset instead, member 2's CRC fails). Also: a 20 KB member that
  passes its CRC between a member with a skipped hole and one that copies from around it leaves the third
  `unproven`; an empty member whose block sets the tables the next member's first block (without tables) uses, as the
  stream's first member and after another, handed over and from its carry; a hand-off that fails on a wrong password
  or a window limit, then succeeds in-session with a write-only sink; and a carry refused by an archive whose members
  have the same sizes but other names; and a member that skipped a hole after an E8-filtered region, repaired and
  proven by its CRC, whose successor copying that region still starts `unproven`.
- RAR 4.x: every solid stream the fixtures hold that decodes (10 streams, 21 members: LZ, PPMd, an E8 filter at a
  member offset, AES), in 97-byte articles and in eight, shuffled, every fifth or third missing: each successor starts
  once the member before is done, a member waiting at a hole holds back those after it, a successor restored half way
  through the missing articles decodes the stream again (`redecoded` at most `stream_start() + frontier`), and every
  member ends exact, CRC verified, each byte written once.
- 7z: three members (300 KB, 700 KB, 500 KB) in one folder that resets only at its start and in 350 KB blocks, plain
  and 7zAES, in 2,500-byte articles shuffled: handed over in sequence, `redecoded` 0. With 8 bytes lost in the
  chunk holding output 5,000 bytes before member 0's end and in the middle of member 2, with and without held output:
  the loss runs on into member 1 (lost from its start, repaired by member 1 from member 0's restart point), member 1
  is restored from a snapshot, and all end exact, CRCs verified, each byte written once (repairs decode up to 1.1 MB
  again in the single-reset folder, 38 KB in the blocked one). Also: a finished member snapshotted and restored
  before it hands over, with and without a loss running on into the next member, and a zero-length member at the
  folder's end handed over to, one at its start handing over, one in the middle of a 7zAES folder created on its own
handing over, and a hand-off failing on a window limit, then going on with nothing decoded again.
