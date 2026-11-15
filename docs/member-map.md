# Member maps

`zipfast::map` lists an archive's headers as typed data and says where each member's bytes are: which volume, which
packed range in it, and for stored members which output range those bytes carry. Only header bytes are read; member
data is skipped, never fetched. A caller that has lost part of one copy of a release can use the map of another copy
(the same file in a different container) to fetch only the articles covering the missing output range.

Mapped: RAR 5.0 and RAR 4.x (stored and compressed members, split across volumes, data encryption, and encrypted
headers `-hp` when a password is given) and single-disk ZIP (every method is listed; stored, ZipCrypto and WinZip AES
entries get output mappings). 7z is not mapped yet; the types are format-neutral so it can be added (`MapFormat`,
`CipherParams` and `OutputMapping` are `#[non_exhaustive]`).

## Building a map

Format detection: a first volume starting with a ZIP local or end header is ZIP, one starting with `Rar!` is RAR.
Anything else (a self-extracting stub) is ZIP when its last 1,046 bytes hold a ZIP end-of-central-directory record,
so a stored `.rar` inside a ZIP is not mistaken for the archive; otherwise the RAR scanner looks for a signature in
the first MiB, reading 4 KiB at a time. Over a `VolumeSource` this tail check waits for the volume's last bytes.
The ZIP central directory is parsed within the caller's `ProgressiveLimits` (header bytes, entries, names, metadata).

- `MemberMap::from_memory(&[&vol0, &vol1, ...], "name.part1.rar", password)` reads volumes held in memory, in order.
  Later volumes may be absent and the last one may be cut short; the map then has `complete: false`.
- `MapBuilder::new(volume_source, MapOptions::new("name.part1.rar"))` reads through a `progressive::VolumeSource`.
  `poll_map(cx)` returns `Pending` on `RangeRead::NotYet` or `VolumeAnswer::Wait`, and retries the parked read with
  the same length after the provider wakes the task. Volume 0 is asked for with the first name; later volumes with
  the names `volume::next_volume_os` derives, though providers usually key on `VolumeRequest::index`.
- `MapOptions` carries the password, the `ProgressiveLimits` (header bytes, per-volume header bytes, header
  allocation, header blocks, names, metadata, entries, parts, source requests, provider wakes and KDF work all count),
  and a `SessionControl` that cancels a walk, including a key derivation in progress.

How a walk ends is `MemberMap::end`:

| `end` | meaning |
|---|---|
| `Complete` | the archive's last end header was read (`complete: true`) |
| `MissingVolume { volume }` | the volume source answered `Missing`, or the memory slice ended, after volume 0 |
| `Truncated { volume, offset }` | the volume ended before its headers did; `offset` is the start of the header being read; pieces already announced are listed even when their data lies past the end |

Failures are `MapError`: `NotArchive`, `MissingFirstVolume`, `PasswordRequired`, `WrongPassword`,
`HeaderHole { volume, offset }` (a `RangeRead::Hole` inside header bytes; holes in member data are never reached),
`Malformed`, `Unsupported` (both with the volume and the underlying typed `ProgressiveFailure`), `Limit { resource,
limit, attempted }`, `Source` (provider failure, contract breach, cancellation) and `Aborted { volume }`.

Encrypted headers: RAR 5.0 headers with a password check value report a wrong password as soon as the key is
derived. Without a check value (and for RAR 4.x, which has none), a wrong password shows up on the first header it
decrypts, as a header checksum or framing failure, or as a header size that runs past the end of the
volume; all are `WrongPassword`. A volume genuinely cut inside its first encrypted header cannot be told apart and
is also reported as `WrongPassword`. Once any header has decrypted under the password, on any volume, later failures
are damage (`Malformed`) and a later volume cut short is `Truncated`. Derived header keys are cached per salt, so a RAR4 archive repeating the same
salt in every header costs one derivation.

## The map

`MemberMap { format, header_encrypted, header_cipher, complete, end, volumes, members }`.

`MapMember` carries the ordinal, `raw_name` (bytes as stored; for ZIP, the UTF-8 bytes of the decoded name) and
`name` (decoded, when it decodes), `is_dir`,
`unpacked_size`, `packed_size` (over the pieces seen), `method` (`Stored` or `Compressed { id }` with the format's
method number), `mapping`, `solid`, `encrypted`, `cipher`, final `checks` (once the final piece is seen), `mtime`,
`attributes`, `unix_mode` and `complete`, and its `pieces`.

`MapPiece` is one part header: `volume`, `packed` (data bytes in that volume), `header` (the header's wire extent,
including the IV and padding of an encrypted header, or a ZIP local header with its name and extra field),
`stream_offset` (where `packed.start` falls in the member's packed stream, the concatenation of all its pieces),
`out`, the part's own `checks` and `final_part`. RAR intermediate parts declare checks of their packed bytes; RAR 5.0
encrypted members' checks are keyed with the password (`MapChecks::keyed`).

`CipherParams` never holds keys or passwords:

- `Rar5 { kdf_count, salt, iv, check, keyed_checks }`: AES-256-CBC. `iv` is the data IV (None for header encryption,
  where each header carries its own). `check` is the 8-byte password check value and its 4-byte checksum.
- `Rar4 { salt }`: AES-128-CBC with key and IV derived from the password and salt (unpack version 29 with a salt,
  as the extractor admits it).
- `Rar4Legacy { unpack_version, salt }`: older RAR 4.x data encryption, or version 29 without a salt. Not mapped:
  `mapping` is `None` and `packed_spans` returns None.
- `ZipCrypto { check }`: the byte the 12-byte encryption header decrypts to last.
- `WinZipAes { strength, vendor_version, salt, verifier }`: read from the first bytes of the entry's data. An entry
  is WinZip AES when its method is 99 or it has an AES extra field, as the extractor decides; one without a valid
  extra field gets `cipher: None` and `mapping: None`.

## Output offsets and restart points

`OutputMapping` says how output offsets relate to the packed stream, and `MapPiece::out` is filled where that is
exact:

| mapping | used for | output byte `o` | `out` |
|---|---|---|---|
| `Direct` | plain stored RAR and ZIP | stream byte `o` | exact |
| `CbcBlocks` | encrypted stored RAR (5.0 and 4.x) | stream byte `o`; block `k` needs block `k - 1` (the IV for block 0); padding maps to no output | exact when the size is known |
| `Counter { skip }` | WinZip AES stored | stream byte `o + skip` (after salt and verifier); the 10-byte authentication code maps to no output | exact |
| `Sequential { skip }` | ZipCrypto stored | stream byte `o + skip`, but decrypting needs every earlier byte | None |
| `None` | compressed | no mapping | None |

Encrypted RAR stored members are one CBC stream across all their parts (a continuation part whose RAR 5.0
encryption record names a different KDF count or salt is `Malformed`; only the first part's IV is used, so a later
part restating a different IV is accepted): a volume boundary never resets CBC, so a
stream offset `c` is output offset `c`, clipped at the unpacked size. This is the same geometry persistent partials
use (`docs/persistent-partials.md`).

`MapMember::packed_spans(out)` turns an output range into the per-volume `PackedSpan { volume, packed, stream }`
list to fetch, in stream order and cut at piece boundaries. `out` is clipped to the unpacked size.

- `Direct`: exactly the bytes of `out`.
- `CbcBlocks`: widened to whole 16-byte blocks plus the block before the first one, whose ciphertext is the IV of
  the first block. When the first block is block 0, its IV is `CipherParams::Rar5::iv` (RAR 5.0) or derived from the
  password (RAR 4.x) and no earlier block is included. The end may reach into the padding. Decrypt the spans' bytes
  with the first 16 as the IV (or the member IV when the first span starts at stream offset 0).
- `Counter`: exactly the bytes of `out`, shifted past the salt and verifier.
- `Sequential`: everything from stream offset 0 to the end of `out`.
- `None`: `packed_spans` returns None. Encrypted members of unknown size also return None.

For stored members these spans are the restart points: decryption can begin at any block boundary, plain data at
any byte. Restart points inside compressed data (decoder checkpoints) are future work.

Only pieces present in the map are covered. For a map with `complete: false`, compare the returned `stream` ranges
with the request to see what the missing volumes still have to supply.
