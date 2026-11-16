# Member maps

`zipfast::map` lists an archive's headers as typed data and says where each member's bytes are: which volume, which
packed range in it, and for stored members which output range those bytes carry. Only header bytes are read; member
data is skipped, never fetched. A caller that has lost part of one copy of a release can use the map of another copy
(the same file in a different container) to fetch only the articles covering the missing output range.

Mapped: RAR 5.0 and RAR 4.x (stored and compressed members, split across volumes, data encryption, and encrypted
headers `-hp` when a password is given), single-disk ZIP and split ZIP sets (`.z01`, ..., `.zip`; every method is
listed; stored, ZipCrypto and WinZip AES entries get output mappings, see [Split ZIP sets](#split-zip-sets)), and 7z
(single files and plain byte splits `.7z.001`, `.7z.002`, ...; see [7z](#7z)).

## Building a map

Format detection: a first volume starting with the 7z signature (`7z\xBC\xAF`) is 7z. One starting with the
spanning signature `PK\x07\x08`, or with a ZIP local header when the first name ends in `.z01`, is a split ZIP set.
Otherwise a first volume starting with a ZIP local or end header is ZIP, one starting with `Rar!` is RAR.
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
| `Truncated { volume, offset }` | the volume ended before its headers did; `offset` is the start of the header being read (the end of the signature when the bytes end inside the main header); pieces already announced are listed even when their data lies past the end |
| `Damaged { volume, offset, reason }` | the header at `offset` in volume `volume` is damaged or unsupported (see below); members and pieces whose headers came before it are listed, a member split across it is `complete: false` |
| `HeaderUnavailable { volume, offset }` | 7z: the archive's header at archive offset `offset` is not in the bytes available, because volume `volume` is missing or ends early (a cut set); no members are listed |

Failures are `MapError`: `NotArchive`, `MissingFirstVolume`, `PasswordRequired`, `WrongPassword`,
`HeaderHole { volume, offset }` (a `RangeRead::Hole` inside header bytes; holes in member data are never reached),
`Malformed`, `Unsupported` (both with the volume and the underlying typed `ProgressiveFailure`), `Limit { resource,
limit, attempted }`, `Source` (provider failure, contract breach, cancellation), `Aborted { volume }` and, for split
ZIP sets, `MissingDirectory { volume }`.

Damage: once volume 0's main header has been read, a damaged header ends the walk with `MapEnd::Damaged` instead
of failing it. Damage is a header checksum, framing or field failure, a header out of order or inconsistent with an
earlier one (a continuation that does not match its member, a later volume without a signature), or a RAR 4.x
header feature not mapped. `reason` is a `HeaderDamage`: `Checksum`, `Malformed(what)` or `Unsupported(what)`;
`offset` is the start of the damaged header. Everything else still fails the walk: damage in the signature or
volume 0's main header, a wrong password, limits and allocation failures, internal errors, holes and source
failures.

`MapEnd`, `VolumeEnd` and `HeaderDamage` are `#[non_exhaustive]`: match them with a wildcard arm.

Encrypted headers: RAR 5.0 headers with a password check value report a wrong password as soon as the key is
derived. Without a check value (and for RAR 4.x, which has none), a wrong password shows up on the first header it
decrypts, as a header checksum or framing failure, or as a header size that runs past the end of the
volume; all are `WrongPassword`. A volume genuinely cut inside its first encrypted header cannot be told apart and
is also reported as `WrongPassword`. Once any header has decrypted under the password, on any volume, later failures
are damage (`Damaged`) and a later volume cut short is `Truncated`. Derived header keys are cached per salt, so a RAR4 archive repeating the same
salt in every header costs one derivation.

## The map

`MemberMap { format, header_encrypted, header_cipher, complete, end, volumes, members, folders }` (`folders` is
empty except for 7z).

`MapMember` carries the ordinal, `raw_name` (bytes as stored; for ZIP, the UTF-8 bytes of the decoded name) and
`name` (decoded, when it decodes), `is_dir`,
`unpacked_size`, `packed_size` (RAR: over the pieces seen; ZIP: the size the directory declares, also when only some
pieces are present; 7z: see [7z](#7z)), `method` (`Stored`, `Compressed { id }` with the format's method number, or
`Coders` for a 7z coded folder), `mapping`, `solid`, `encrypted`, `cipher`, final `checks` (once the final piece is
seen), `mtime`, `dos_time` (RAR 4.x: the header's DOS date and time as stored, also when it is not a valid date and
`mtime` is None; None for other formats), `attributes`, `unix_mode` and `complete`, its `pieces`, and `folder` (7z
only: the folder and substream offset).

`MapPiece` is one part header: `volume`, `packed` (data bytes in that volume), `header` (the header's wire extent,
including the IV and padding of an encrypted header, or a ZIP local header with its name and extra field; empty for
7z),
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
- `SevenZipAes { num_cycles_power, salt, iv }`: 7zAES (see [7z](#7z)).
- `WinZipAes { strength, vendor_version, salt, verifier }`: read from the first bytes of the entry's data. An entry
  is WinZip AES when its method is 99 or it has an AES extra field, as the extractor decides; one without a valid
  extra field gets `cipher: None` and `mapping: None`.

## Split ZIP sets

An Info-ZIP split set is `name.z01`, `name.z02`, ..., `name.zNN` and the final `name.zip`, which holds the end of
central directory record. Its disks are numbered from 0 in that order: `.z01` is disk 0 and `.zip` the last disk.
Every disk number (end records, ZIP64 end record and locator, central directory entries, including ZIP64 start
disks) and every offset is relative to that numbering; an offset is relative to the start of its disk. Disk 0 may
start with the 4-byte spanning signature `PK\x07\x08`; offsets in disk 0 count it, so nothing is adjusted. Real Info-ZIP
sets (`tests/fixtures/zip-split`) are checked: Info-ZIP writes the signature, cuts volumes at the byte (mid-member)
and keeps the central directory in the `.zip`.

Volumes are passed in disk order, `.z01` first and `.zip` last, and `MapPiece::volume` is the disk number.

- `from_memory(&[&z01, &z02, ..., &zip], "name.z01", None)`. The last slice must be the `.zip`: its end record's
  disk number must equal the slice count minus one, or the map fails `Malformed` ("volume count does not match its
  end record"). Pass a missing middle volume as an empty slice (no volume of a set is empty, so an empty volume
  counts as missing). Middle volumes are opened as needed; the last slice is searched for the end record, and when it
  holds none (no `.zip` was passed, or it is cut) the map fails `MissingDirectory { volume }` with `volume` the last
  slice's index.
- `MapBuilder` with `MapOptions::new("name.z01")`. The last volume's index is unknown until its end record is read,
  so volumes are asked for in order with names derived from the first name: the extension becomes `z02`, `z03`, ...
  (`z100` after `z99`), or `zip` for the last volume (upper case when the first name's extension is). Volume `i` is
  asked for as `name.z{i+1}`; when the source answers `Missing`, it is asked for again, at the same index, as
  `name.zip`. A source that keys on names thus answers `name.zip` the second time; one that keys on the index
  answers the last volume the first time (under its numbered name) and `Missing` twice for the next index, and the
  volume before is then searched for the end record. That volume is taken as the last only when its end record
  states its own index as the disk and its directory (or ZIP64 end record) ends where the end records start, so
  member data shaped like an end record does not stop the search; otherwise, and across indexes missing in a row
  (missing middle volumes), the search goes on, until 64 indexes in a row lack a volume, which is
  `MissingDirectory { volume }` with the first of them. A source that keys on names and lacks a middle volume
  answers `name.zip` at that index: the volume is then bound to the disk number its end record states, and the
  volumes in between are asked for later by name. The first name is never asked for again at another index, so a
  one-volume set starting with the spanning signature and named `name.zip` maps as one volume.
  `MemberReader` asks for a split set's volumes with the same names.
- Volumes stay open for the walk, at most `ProgressiveLimits::volume_handles` of them (64 by default; 0 is a
  `Limit` failure). Past that the volume used least recently is closed and asked for again when it is needed, which
  must give the same length (`Source` failure otherwise). Volume 0 is always asked for under the first name.

The walk reads the last volume's tail for the end record (its last 42 bytes, then up to a 64 KiB comment), the
ZIP64 end record when the directory's disk is only stated there, then the central directory over the volumes that
hold it (it may span several), with the same parser, checks and `ProgressiveLimits` as a single-disk ZIP. Then each
entry's local header is read on its disk, and the member's data is placed on the volumes it crosses: one `MapPiece`
per volume, cut at volume boundaries, with `stream_offset` and `out` running on across them. A local header, the
WinZip AES salt and verifier, or the ZipCrypto header may cross a boundary too. The first piece's `header` is the
part of the local header in its volume; a piece the data continues into has the empty `header` `0..0`. Only the last
piece carries the member's `checks` and is `final_part`. Budgets are charged as for single-disk ZIP: header bytes
read, entries, one part per piece, metadata per member and the derived volume names.

Missing and cut volumes:

| situation | result |
|---|---|
| a middle volume is missing (`Missing`, or an empty slice) | the walk goes on; `end` is `MissingVolume { volume }` for the first one met. A member whose local header is on it (or runs into it) is listed without pieces, `cipher: None`, `checks: None`, `complete: false`; one whose data runs into it lists its pieces before it and is `complete: false` |
| a volume before the last ends before a local header on it | `Truncated { volume, offset }` at that header, and the walk stops; members before it are listed |
| a volume before the last is cut inside the data of a member that crosses its end | `Truncated { volume, offset }` with the cut volume and its length, and the walk stops before that member (see below). The volumes before the last all have one length, so the cut one is the first volume the data runs to the end of that is shorter than the longest; when none is, the first volume the data crosses is named |
| the last volume is missing, or cut so that its end record is gone | `MapError::MissingDirectory { volume }` |
| a volume holding part of the central directory or the ZIP64 end record is missing | `MapError::MissingDirectory { volume }` |

Pieces are placed using each volume's length, so a volume before the last that is cut inside member data would shift
the data of a member crossing its end. The placement is checked against the directory: a member's data, plus 12
bytes when it has a data descriptor, must end at or before the next local header or the central directory in disk
and offset order. For data that crosses a boundary and has a data descriptor, the descriptor is read: its CRC must be
the member's, and a descriptor signature in the 4 bytes before it means the data was placed 4 bytes late. A failed
check on data that crosses a boundary is the cut above (a member is never listed `complete` with shifted spans);
on data within one volume it is a wrong directory, `Malformed`. (Data that genuinely ends with the bytes
`PK\x07\x08`, crosses a boundary and has a descriptor without signature is reported as cut.) `volumes` is the set's volume count
from the end record. Hostile disk numbers (past the last volume) and offsets (past the end of the last volume, or a
directory offset that disagrees with the directory's position, a ZIP64 end record other than the one the locator
points at) are `Malformed`; a local header offset past the end
of an earlier volume reads as that volume being cut. A split set's `.zip` mapped on its own is `Unsupported`.

## 7z

A 7z set is one archive, possibly cut into plain byte pieces (`name.7z.001`, `name.7z.002`, ...) that concatenate
back into it. Archive offsets run over the volumes in order; `MapPiece::volume`, `MapPiece::packed` and the
`PackedSpan`s are per-volume, cut at volume boundaries. The walk reads only:

1. the 32-byte signature header at offset 0 (its CRC is checked), which says where the next header is;
2. the volumes' lengths, opening volumes in order until they reach the end of the next header (over a
   `VolumeSource` later volumes are asked for by index, with names counting up the numeric extension:
   `set.7z.001`, `set.7z.002`, ...);
3. the next header (CRC checked), at the end of the set;
4. for an encoded header (the usual case), its packed stream, decoded into the real header. LZMA and LZMA2 are
   decoded with liblzma raw decoders from the coder properties, 7zAES with the key derived from
   `MapOptions::password`, and Copy as is; the decoded size is the folder's recorded unpack size, charged to the
   header byte budget before allocation, and the dictionary is shrunk to that size, so a stated 4 GiB dictionary
   never allocates more than the header. The folder CRC is checked. Encoded headers may nest up to 4 deep.

A plain byte split has no per-volume headers, so `MemberMap::from_volume` refuses 7z (`NotArchive`), and
`probe` reports `Packing::Unknown`.

Members: one `MapMember` per file entry, in header order. `raw_name` is the name's UTF-16LE bytes as stored and
`name` its decoding; `is_dir` is an empty stream that is not an empty file (or the directory attribute); `mtime`
and `attributes` are the header's, and `unix_mode` is set when the attribute's Unix extension bit (0x8000) is.
`checks.crc32` is the substream CRC. `folder` is `Some(FolderSlot { index, offset })`: the folder in
`MemberMap::folders` and the member's offset in that folder's output (its substream position). Directories and
empty files have no folder and no pieces.

Folders: `MemberMap::folders` lists every folder as a `MapFolder` with its coders as stored (`MapCoder { kind, id,
properties, in_streams, out_streams }`, where `kind` is a `CoderKind` such as `Copy`, `Lzma`, `Lzma2`, `Aes`,
`Bcj`, `Delta`, or `Other(id)` for an id it does not name), its bind pairs and packed stream indexes, the size of
each packed stream, `packed` (all its packed streams back to back as per-volume `PackedSpan`s), every coder output
size, `unpacked_size` (the unbound output), its CRC, how many members it holds and, when a coder is 7zAES, the
`cipher`. 7-Zip lists the coder producing the folder's output first: LZMA2 over 7zAES is `[Lzma2, Aes]`.

The mapping depends on the folder:

| folder | `method` | `mapping` | pieces |
|---|---|---|---|
| Copy coders only, one packed stream | `Stored` | `Direct` | the member's own bytes: packed stream start + `offset`, `unpacked_size` long, stream offsets from 0 |
| 7zAES and Copy coders only, one packed stream; the member at `offset` 0 | `Stored` | `CbcBlocks` | the folder's ciphertext from its start, `unpacked_size` rounded up to 16 bytes; block 0 decrypts with `CipherParams::SevenZipAes::iv` |
| 7zAES and Copy, a later member | `Stored` | `None` | the folder's packed bytes |
| anything else (LZMA, LZMA2, BCJ, PPMd, 7zAES over LZMA, ...) | `Coders` | `None` | the folder's packed bytes, stream offsets over the folder's packed streams; `solid` when `offset` is not 0 |

So an LZMA2 member gives its folder's packed range (`MapFolder::packed`, also the member's pieces) and the folder's
`unpacked_size`; the caller finds LZMA2 chunks in that range itself. A later member of a 7zAES folder can still be
read from its `FolderSlot::offset` with the folder's spans: CBC decryption starts at any block given the block
before it.

`CipherParams::SevenZipAes { num_cycles_power, salt, iv }`: AES-256-CBC, key from SHA-256 over
`2^num_cycles_power` rounds of the salt, the UTF-16LE password and an 8-byte little-endian round counter (0x3F: no
hashing, the key is the salt and password zero-padded). `salt` is 0 to 16 bytes, `iv` the stored IV zero-padded to
16. No password check value is recorded, so a wrong data password shows only in the member CRC.

Encrypted headers (`-mhe`): the encoded header's folder has a 7zAES coder. Without a password (`None` or empty)
the walk fails with `PasswordRequired`. A wrong password is `WrongPassword`: the decrypted bytes do not decode, fail
the folder CRC, or do not start with a header id. `header_encrypted` and `header_cipher` describe it. The key
derivation counts against `kdf_exponent` (the cycle power), `kdf_derivation_blocks` and `kdf_session_blocks` (one
block per SHA-256 compression), and password sizes, and cancels with the `SessionControl`. Powers above 24 (other
than 0x3F) are `Unsupported`, as in 7-Zip.

Cut sets: the header is at the end, so a set with only its first pieces cannot be listed. When a volume the header
needs is missing (or ends before its advertised length), the map ends `HeaderUnavailable { volume, offset }` with
`complete: false`, `volumes` the volumes opened and no members or folders. Bytes that end inside the signature header
are `Truncated { volume: 0, offset: 0 }`. An empty archive (next header size 0) is `Complete` with no members.

Failures and budgets: every count in the header is an untrusted number and is checked against the bytes left in the
header (each item takes at least a byte) before anything is allocated; files count against `entries` and
`metadata_bytes`, folders, packed streams, substreams and pieces against `parts`, names against `name_bytes`, bytes
read and decoded against `header_bytes`, and each open or read against `source_requests` (waits against
`provider_wakes`). A bad signature or next header CRC, an inconsistent field, or packed streams running into the
header are `Malformed` (CRC failures as a header `ChecksumMismatch`); external (out-of-header) folders or file
properties, additional streams, alternative coder methods, a major version other than 0, and header coders other
than Copy, LZMA, LZMA2 and 7zAES in a single chain are `Unsupported`. 7z damage is never `MapEnd::Damaged`: the
header is one unit.

## Single-volume maps

`MemberMap::from_volume(bytes, MapOptions::new(name))` reads the headers of one RAR volume on its own: any volume of
a set (a `.part07.rar`, or an obfuscated file that is really volume 12), or only its first bytes (a single Usenet
article). `VolumeMapBuilder::new(range_source, options)` is the pollable form over one `progressive::RangeSource`:
`poll_map(cx)` returns `Pending` on `RangeRead::NotYet` and retries the parked read with the same length; a hole in
header bytes is `HeaderHole { volume: 0, .. }`; the source's current length is where the volume ends.

Volume 0 is not needed. The volume's position is reported, never checked: the main header's volume number is not
compared with anything, and a member that continues from an earlier volume is listed as it is instead of being
matched against that volume's part. RAR 4.x and RAR 5.0 volumes are read, behind a self-extracting stub too; ZIP is
`NotArchive`. `MapOptions` limits, budgets and cancellation apply as for whole-archive maps, and the volume in
`MapError` variants is 0.

`VolumeMap`:

| field | meaning |
|---|---|
| `format` | `Rar4` or `Rar5`, from the signature when the main header was not read |
| `main_read` | the main header was read; false for a `Locked` RAR 5.0 volume and bytes that end inside the main header, where the facts below are defaults |
| `volume_number` | zero-based. RAR 5.0: the main header's volume number, 0 when it records none (only the first volume omits it). RAR 4.x: the end header's number (`EARC_VOLNUMBER`) when the end header is read and records one, else 0 for a first volume and None otherwise. A non-volume archive is volume 0 |
| `first_volume` | the first volume, or a single-volume archive. RAR 4.x: `MHD_FIRSTVOLUME` (written since RAR 3.0) or an end-header number of 0. RAR 2.x first volumes lack `MHD_FIRSTVOLUME`, so a prefix of one that stops before the end header reports `first_volume: false` and `volume_number: None`. A main header claiming the first volume with an end header numbering it otherwise is `Damaged` at the end header, and the facts are the main header's |
| `multi_volume` | the main header's volume flag |
| `new_naming` | `.partNN.rar` naming: always true for RAR 5.0, RAR 4.x `MHD_NEWNUMBERING` (false means `.rar`, `.r00`, `.r01`, ...) |
| `has_next_volume` | the end header's "not last volume" flag; false when the end header was not reached |
| `solid`, `header_encrypted`, `header_cipher` | as the main header and encryption header state them |
| `end` | `Complete` (the end header was read), `Truncated { offset }`, `Locked { offset }` or `Damaged { offset, reason }` |
| `members` | one `VolumeMember` per file header, in volume order; service headers are not listed |

Truncation is normal. Bytes that end inside member data or inside a header give `Truncated { offset }`, where
`offset` is the start of the header being read; it lies past the end of the bytes when the last listed member's data
does. A member whose header was read is listed with its declared packed size and data offsets even when its data
runs past the end.

Damage is reported, not raised, once the main header has been read: a damaged or unsupported header ends the map
with `Damaged { offset, reason }` (as for whole-archive maps), listing the members whose headers came before it,
with the main header's volume facts (`has_next_volume` is false, since the end header was not reached). Damage in
the signature or the main header itself fails the walk.

Encrypted headers (`-hp`): with a password, headers decrypt as for `from_memory`, and a wrong password is
`WrongPassword` where it can be told. A single-volume map treats bytes that end inside the first encrypted header as
a cut, not a wrong password, since prefixes are its normal input: it reports `Truncated` unless the header's first
decrypted block is not a header that can stand there (RAR 4.x: a file, service or end header; RAR 5.0: a main,
file, service or end header), which is `WrongPassword`. RAR 5.0 headers with a password check value are proven
before any header is read. **Without a check value (always for RAR 4.x), a wrong password is missed** when the bytes
end within the first 16 bytes of ciphertext of that header, or, about once in a hundred, when the noise passes for a
header type; the map is then `Truncated` with no members. Any complete header that fails its checksum is
`WrongPassword`. Without a password (`None` or empty) the walk stops at the first encrypted header
with `Locked { offset }`, `header_encrypted: true`, the header cipher parameters and no members, instead of
`PasswordRequired`. RAR 5.0 encrypts the main header too, so a locked RAR 5.0 volume has `main_read: false` and no
volume facts; RAR 4.x keeps its main header in the clear, so its facts are known. Members whose data is encrypted
but whose headers are not are listed with their `cipher`.

`VolumeMember` carries `raw_name` and `name`, `is_dir`, `unpacked_size` (every part header records the whole
member's), `packed_size` and `packed` (this part's data bytes in this volume), `header` (the header's wire extent),
`split_before` (continues from the previous volume), `split_after` (continues in the next), `method`, `mapping`,
`solid`, `encrypted`, `cipher`, `part_checks` (as stored in this header: of this part's packed bytes when it has
`split_after`, of the member's output otherwise), `checks` (the member's final checks: `Some(part_checks)` exactly
on its last part), `mtime`, `dos_time` (as for `MapMember`), `attributes` and `unix_mode`. Where a continuation part falls in the member's packed
stream depends on earlier volumes; a whole-archive map gives that as `MapPiece::stream_offset`.

## RAR 4.x leniency

Map walks (`MemberMap::from_memory`, `MapBuilder` and single-volume `from_volume` / `VolumeMapBuilder`) accept these
in old RAR 2.x/3.x/4.x archives, which `RarSession`, `extract::list` and extraction still refuse:

- A legacy name that is not UTF-8 (no Unicode flag, OEM/CP437 bytes such as `caf\x82.mkv`): the member is listed
  with `raw_name` holding the stored bytes and `name: None`. A whole-archive map matches split parts by those bytes.
  An empty name or one holding a NUL byte is still damage.
- Legacy service blocks 0x75..=0x79 (old comment, AV, old subblock, old recovery record, sign): skipped. Which have
  data after the header follows unrar's `ReadHeader15`: the old comment (0x75) never has any, even with LONG_BLOCK
  set; the old subblock (0x77) and old recovery record (0x78) always start with its size, LONG_BLOCK or not; the AV
  (0x76) and sign (0x79) blocks have it exactly when LONG_BLOCK is set. Their header bytes count against the header
  budgets like any other header. A header size below 7, or a 0x77/0x78 header too short for its data size, is
  damage; a header or data size running past the volume ends the walk `Truncated` there.
- Embedded comments: `MHD_COMMENT` (0x02) with the RAR 2.x comment inside the main header, and `LHD_COMMENT` (0x08)
  with the comment after a file header's name. Both lie inside the declared header size and are skipped with it.
  As in unrar, the CRC of such a header covers only what precedes the comment: the main header's 13 fixed bytes,
  and the file header's fields up to the name, salt and extended times.
- Header CRCs unrar does not check: the AV (0x76) and sign (0x79) blocks and the Unix-owner old subblock (0x77 with
  subtype `UO_HEAD`, 0x0101), which old versions wrote without a proper CRC, are not checked either. In an archive
  with encrypted headers every header is checked whole, since the CRC is what reveals a wrong password.
- Sizes: a main header longer than its fixed fields, bytes left over inside a file or service header after the
  fields its flags call for, and an end header of any size (bytes past its fields are ignored; a volume number the
  header is too short to hold is absent). As in unrar, the main and end headers never have data after them.
- `MHD_ENCRYPTVER` (0x200) on a `-hp` archive: the main header's extra byte gives the header encryption version.
  RAR 3.x headers are always encrypted the RAR 2.9 way, so versions up to 36 (what unrar 3.x accepts) are read
  like any `-hp` archive; a later version is `Unsupported` (the main header cannot be read).

## Output offsets and restart points

`OutputMapping` says how output offsets relate to the packed stream, and `MapPiece::out` is filled where that is
exact:

| mapping | used for | output byte `o` | `out` |
|---|---|---|---|
| `Direct` | plain stored RAR and ZIP, 7z Copy folders | stream byte `o` | exact |
| `CbcBlocks` | encrypted stored RAR (5.0 and 4.x), the first member of a 7z 7zAES-over-Copy folder | stream byte `o`; block `k` needs block `k - 1` (the IV for block 0); padding maps to no output | exact when the size is known |
| `Counter { skip }` | WinZip AES stored | stream byte `o + skip` (after salt and verifier); the 10-byte authentication code maps to no output | exact |
| `Sequential { skip }` | ZipCrypto stored | stream byte `o + skip`, but decrypting needs every earlier byte | None |
| `None` | compressed | no mapping | None |

Encrypted RAR stored members are one CBC stream across all their parts (a continuation part whose RAR 5.0
encryption record names a different KDF count or salt is damage; only the first part's IV is used, so a later
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
