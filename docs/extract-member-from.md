# Reading a member from an output offset

`zipfast::map::MemberReader` and `zipfast::map::extract_member_from` stream a stored member's plaintext from any
output offset to its end. They read only the packed bytes that range needs, as
[`MapMember::packed_spans`](member-map.md#output-offsets-and-restart-points) lists them.

The use case: a download of one copy of a release dies part way. The caller holds a persistent `PartialFile` whose
output is valid up to `offset_reached`. Another copy has the same file packed differently: RAR 5.0 or RAR 4.x
store, possibly encrypted, or ZIP. The caller maps that copy with `MemberMap`, fetches only the articles covering
`[offset_reached, end)`, and streams the plaintext from `offset_reached` into the partial:

```rust,ignore
let map = MemberMap::from_memory(&alt_volumes, "alt.part1.rar", None)?;
let mut writer = partial.fill_writer(offset_reached)?;
let done = extract_member_from(&alt_volumes, &map, member, offset_reached, Some(password), &mut writer)?;
writer.finish()?;
// partial.poll_verify(..) checks the whole member, which a suffix read cannot. Until it passes,
// done.password_verified == false means the alt's password was never proven.
```

## API

- `MemberReader::new(source: Box<dyn VolumeSource>, map: &MemberMap, member: usize, out_offset: u64, options:
  MapOptions)` builds a pollable reader. `MapOptions` is the same type that builds maps. It holds the first
  volume's name (later volumes are asked for with names that `volume::next_volume_os` derives; providers usually
  key on `VolumeRequest::index`), the password, the `ProgressiveLimits` (source requests, source bytes, provider
  wakes, KDF work for RAR 5.0, RAR 4.x and WinZip AES, password sizes), a `SessionControl` for cancellation, and
  `part_hold_bytes` (see [checks while streaming](#checks-while-streaming)). `new` refuses at once, before any read,
  when the member cannot be read from that offset.
  - `poll_read(cx, buf) -> Poll<Result<usize, ExtractFromError>>` returns plaintext. `Ok(0)` for a nonempty `buf`
    means the member's end, once every check that could run has passed.
  - `poll_write_to(cx, sink: &mut dyn Write) -> Poll<Result<u64, _>>` writes to the end and returns the byte
    count. It can be polled again after `Pending`. For example, the sink can be a `PartialFile::fill_writer`.
  - `position()` is the output offset of the next byte; `end()` is the member's size.
  - `password_verified()` says whether the password is proven (see [passwords](#passwords)).
  - `RangeRead::NotYet` and `VolumeAnswer::Wait` give `Pending`. The provider wakes the task, and the parked read
    is retried with the same length.
  - Only the volumes holding needed bytes are opened, in order. A volume before the first needed piece is never
    asked for.
- `extract_member_from(volumes: &[&[u8]], map, member, out_offset, password, sink: &mut impl Write) ->
  Result<ExtractedFrom, _>` does the same over volumes in memory. `ExtractedFrom { written, password_verified }`
  gives the bytes written and the password verdict. A volume the read does not need may be an empty slice.
  `extract_member_from_with` takes `MapOptions` instead of a password.

`MemberMap` is a public type, so a caller may build or edit one. The reader validates the member before reading:
- pieces must be contiguous from stream offset 0, with ordered packed ranges and no offset overflow;
- `encrypted` must agree with `mapping`, and `cipher` with `mapping` (a CBC member needs RAR 5.0 parameters with
  an IV, or RAR 4.x parameters);
- each `piece.out` must be the output range its stream range carries.

Anything else is `Malformed`.

## Supported members

| member | mapping | how the read starts |
|---|---|---|
| plain stored RAR 5.0, RAR 4.x, ZIP method 0 | `Direct` | at stream byte `out_offset` |
| RAR 5.0 stored, AES-256-CBC | `CbcBlocks` | at the block holding `out_offset`. The ciphertext block before it is read as the IV, or the member IV is used for block 0. Leading bytes of the first block and the final padding are trimmed |
| RAR 4.x stored, AES-128-CBC (unpack version 29 with a salt) | `CbcBlocks` | as RAR 5.0. Key and block-0 IV come from the password and salt |
| WinZip AES stored (AE-1, AE-2, all strengths) | `Counter { skip }` | at ciphertext byte `out_offset`, with the counter set to that block (`out_offset / 16 + 1`, little-endian) |
| ZipCrypto stored | `Sequential { skip }` | only at offset 0 (or at the end) |

A CBC stream does not reset at volume boundaries, so an output offset is a stream offset, and pieces may be cut
anywhere.

`out_offset == size` is an empty read that succeeds without reading anything or needing a password.

Typed refusals (`ExtractFromError::Unsupported(UnsupportedRead::..)`):

- `Compressed { id }`: compressed members. Restart points inside compressed data are future work.
- `SequentialCipher`: ZipCrypto from an offset other than 0. Its keystream depends on all earlier plaintext.
- `LegacyRar4Cipher`: RAR 4.x encryption other than AES-128 (an older unpack version, or version 29 without a
  salt).
- `UnmappedCipher`: other encryption the map does not map (ZIP strong encryption, AES without a valid extra
  field).
- `UnknownSize`: no recorded unpacked size.

Other refusals made at construction: `NoSuchMember`, `OffsetPastEnd`, `PasswordRequired`, and `IncompleteMember {
out }`. The last one means the map (one with `complete: false`) lists the member's pieces only up to output `out`.

## Passwords

- RAR 5.0 with a password check value: a wrong password is `WrongPassword` as soon as the key is derived.
- RAR 5.0 without one: the member's checks are keyed with the password. A wrong password fails the first keyed
  check the read covers: a whole non-final part's check (reported as `PartBad`), or the member check from offset
  0 (`MemberBad`). If the read covers neither, the output is wrong.
- RAR 4.x records no check value. A wrong password gives wrong plaintext. From offset 0 the member CRC catches it
  (`MemberBad`); otherwise the caller's own verify (for example `PartialFile::poll_verify`) does.
- WinZip AES: the 2-byte password verifier gives `WrongPassword` (with a 1 in 65,536 chance of passing a wrong
  password).
- ZipCrypto: the check byte gives `WrongPassword` (1 in 256).

`MemberReader::password_verified()` (and `ExtractedFrom::password_verified`) is true when:
- the member is not encrypted;
- the RAR 5.0 check value or the WinZip AES verifier matched;
- a RAR 5.0 keyed part check passed;
- the member check or WinZip authentication code passed, from offset 0.

A successful read with `password_verified() == false` produced unverified plaintext. This happens with RAR 4.x
AES from an offset other than 0, or with RAR 5.0 without a check value when the read covered no whole part. A wrong
password there gives garbage with no error, which only the caller's verify of the finished output catches.

## Checks while streaming

- **Part checks.** A RAR part whose packed bytes the read covers from the first byte is checked when its last byte
  is read. Its plaintext is held back in memory until the check passes, so a bad part's bytes never reach the
  caller. The hold is capped by `MapOptions::part_hold_bytes` (default 256 MiB; a part's output is at most its
  packed size). A larger part is streamed unchecked and still checked at its end. RAR 5.0 non-final part checks are CRC32 or BLAKE2sp of
  the packed bytes (ciphertext for encrypted members), keyed with the password when the member's checks are keyed.
  RAR 4.x non-final part CRCs cover the packed bytes. A failure is `PartBad { out, volume, part, which, bad }`:
  - `volume` names the volume holding the bad bytes, so the bad article is pinned.
  - `part` indexes `MapMember::pieces`.
  - `bad` is the output range that part carries, clipped to the read. For CBC it includes one more block, which
    decrypts with the part's last ciphertext block.
  - `released: false` means the part was held back: nothing of `bad` was returned, and `out` is the offset reached.
  - `released: true` means the part was larger than the cap: its bytes were returned unchecked. `out` is
    `bad.start`, and the caller must rewind there and discard what it wrote from that offset on.
  - A part that the read enters in its middle cannot be checked.
- **Member checks.** A final part's checks cover the whole output. From offset 0 the read covers the whole member,
  so it checks them at the end (`MemberBad { which }`); for WinZip AES it also checks the HMAC-SHA1 authentication
  code (`AuthenticationFailed`). Every byte has been returned by then. From any other offset neither can be
  checked: the member CRC and the WinZip HMAC need every byte. The caller's verify of the finished output (the
  `PartialFile` verify) covers that.

## Errors while streaming

Each carries `out`, the offset to resume from: every byte from the starting offset up to `out` was returned or
written and is good as far as the reader could check. A caller switching copies again resumes there. The one
exception is `PartBad { released: true }`, where bytes past `out` were also returned and must be discarded.

- `Hole { out, volume, packed }`: the source answered `RangeRead::Hole` at `packed` in `volume`. For CBC, a hole in
  the IV block before the start gives `out == out_offset`. A hole inside a held-back part gives the part's output
  start, because its earlier bytes were never checked.
- `MissingVolume { out, volume }`: `VolumeAnswer::Missing`.
- `Truncated { out, volume, packed }`: a volume ended inside the member's data.
- `PartBad`, `MemberBad`, `AuthenticationFailed`: see above.
- `Write { out, error }`: the sink failed.
- `Limit`, `Source` (provider failure, contract breach, cancellation), `Aborted { volume }`, `Malformed` (an
  inconsistent map).

After an error, the reader answers `AlreadyFailed`.

## Limitations

- Persistent partials accept alt plaintext only inside holes that the session has already produced
  (`PartialFile::fill`; see [persistent partials](persistent-partials.md)). A takeover therefore needs the original
  session to have run the member to its end, with `[offset_reached, end)` reported as holes. A member that was
  mid-extraction when its session stopped (for example after a restart) cannot be filled past `produced` yet.
  Resume after a restart is a separate item.
- Compressed members and 7z are not supported.
