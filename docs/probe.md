# Probing

`zipfast::probe` says how a release is packed from the first bytes of its first file, typically one Usenet article
of about 700 KB, held in memory. It answers three questions:

1. Is the file bare media, a RAR volume, a ZIP archive, or something else?
2. For an archive: which member is the media file, and is it stored, compressed, data-encrypted, or behind
   encrypted headers?
3. Can that member's bytes be borrowed? That is, do its output offsets map to packed bytes, so another copy of the
   same content (an "alt") can fill a missing output range, and this copy's packed bytes can be turned into output
   at any offset?

```rust
use zipfast::probe::{probe, Borrowable, Packing};

let packing = probe(&first_article, None, Some("password"))?;
match packing.borrowable() {
    Borrowable::Yes | Borrowable::YesWithPassword(_) => { /* map offsets, borrow */ }
    Borrowable::NeedsPassword(_) | Borrowable::No(_) | Borrowable::Unknown(_) => { /* fetch it all */ }
}
```

## API

- `probe(head, tail, password) -> Result<Packing, MapError>`
- `probe_with(head, tail, password, &ProbeOptions)`: `ProbeOptions { limits, file_len }`. `limits` are the
  member map's `ProgressiveLimits` (header bytes, names, entries, metadata, KDF). `file_len` is the whole file's
  length when known (a yEnc `size=`); without it the ZIP directory's position is inferred from `tail`.
- `sniff(bytes) -> Option<MediaMatch>` and `media_kind_for_name(name) -> Option<MediaKind>`, the two media tests
  the probe uses.

`head` is the file's first bytes. `tail`, when given, is its last bytes and is used only for ZIP (the central
directory is at the end). An empty password is no password.

Detection order: a `Rar!` signature at offset 0 is RAR; a ZIP local header, an empty archive's end record, or the
spanned-archive marker followed by a local header is ZIP; then the media magic at offset 0; then the RAR scanner,
which finds a RAR signature behind a self-extracting stub in the first MiB. Anything else is `Packing::Unknown`.
A ZIP behind a stub is not detected.

Errors are `MapError`s from the member map: damaged or unsupported RAR headers, a budget in `limits`, or a ZIP
whose first local header is damaged. A wrong password for encrypted headers is not an error (see below).

## `Packing`

| variant | contents |
|---|---|
| `BareMedia(MediaMatch)` | `MediaMatch { kind, confidence }`; always `Borrowable::Yes` |
| `Rar(RarPacking)` | `version` (`Rar4`/`Rar5`), `volume: VolumeFacts`, `header_encrypted`, `locked`, `first_media`, `borrowable`, and the full `map: VolumeMap` |
| `Zip(ZipPacking)` | `directory` (central directory read from `tail`), `complete` (every member listed), `spanned`, `members` (count), `first_media`, `borrowable` |
| `Unknown` | `Borrowable::Unknown(NotRecognised)` |

`Packing::borrowable()` and `Packing::first_media()` read across variants.

`VolumeFacts { known, volume_number, first_volume, multi_volume, new_naming, has_next_volume, solid }` come from
`MemberMap::from_volume` (see the "Single-volume maps" section of [member maps](member-map.md) for each rule).
`known` is false when the main header was not read: a locked RAR 5.0 volume, or a head that ends inside it.
A first article of a middle volume (`.part03.rar`) gives its volume number and the member continuing into it.

`locked` is true when the headers are encrypted and could not be read, either without a password or with the wrong
one. A locked RAR 5.0 volume has no volume facts (its main header is encrypted); RAR 4.x keeps its main header in
the clear.

### `MemberFacts`

`index` (among the members listed), `raw_name`, `name`, `size` (unpacked), `packed_size` (RAR: this volume's part),
`method` (`MapMethod`), `packing`, `mapping` (`OutputMapping`, as in member maps), `cipher` (`CipherParams`, never a
key), `continued` (the member continues from an earlier volume), `header` and `data` (offsets in the head's
coordinates; `data` may run past the end of the head), `name_kind` (from the extension), `sniffed` (from the
member's first bytes), and `selected`. `media()` is `sniffed`, else `name_kind`.

`packing: MemberPacking`:

- `Stored`: stored in the clear.
- `Compressed { method, solid }`: the format's method number (RAR 5.0 1 to 5, RAR 4.x 0x31 to 0x35, ZIP method).
- `DataEncrypted { cipher, stored }`: `cipher` is `Rar5Aes256`, `Rar4Aes128`, `Rar4Legacy`, `ZipCrypto`,
  `WinZipAes { strength }` or `Unknown` (ZIP strong encryption, AES without a valid extra field).

Encrypted headers are not a member packing: without the password there are no members to describe, which is
`RarPacking::locked`.

`sniffed` is filled when the member's data starts inside the head and is not a continuation: for plain stored data
always, for encrypted stored data when the password is given (up to 64 KiB is decrypted).

## Choosing the first media member

1. Directories are skipped.
2. The first member (in header order) whose name has a media extension: `mkv`, `mk3d`, `webm`, `mp4`, `m4v`, `mov`,
   `qt`, `avi`, `ts`, `trp`, `m2ts`, `mts`, `wmv`, `asf`, `mpg`, `mpeg`, `vob`, `m2p` (`Selection::Extension`), or
   whose plain stored data in the head starts with a media magic (`Selection::Magic`, for obfuscated names).
3. Otherwise the largest listed member that is not a side file (`nfo`, `sfv`, `txt`, `jpg`, `jpeg`, `png`, `gif`,
   `bmp`, `srr`, `srs`, `nzb`, `par2`, `md5`, `sha1`, `sha256`, `url`, `diz`, `log`, `cue`, `srt`, `sub`, `idx`,
   `ass`, `ssa`, `htm`, `html`), the first of equal sizes (`Selection::Largest`).
4. Otherwise, when every member is listed (the RAR volume's end header was read, or the ZIP central directory was
   reached), the largest member of all.
5. Otherwise none: the head ends before a member worth choosing, `Borrowable::Unknown(Truncated)`.

So an `nfo` before the `mkv` never wins, and a head holding only an `nfo` header so far stays undecided.

## `Borrowable`

| verdict | when |
|---|---|
| `Yes` | bare media, or the member is stored in the clear |
| `YesWithPassword(proof)` | the member is stored and encrypted with a mapped cipher (RAR AES-CBC, WinZip AES), and a password was given that no check rejects; or it is stored in the clear behind encrypted headers that the password opened |
| `NeedsPassword(HeaderEncrypted)` | encrypted headers (`-hp`), no password |
| `NeedsPassword(DataEncrypted)` | encrypted stored data, no password |
| `NeedsPassword(WrongPassword)` | the password fails the encrypted headers, a RAR 5.0 check value, or a WinZip AES verifier |
| `No(Solid)` | compressed in a solid stream |
| `No(Compressed)` | compressed (whether or not also encrypted) |
| `No(UnsupportedCipher)` | older RAR encryption, ZIP strong encryption, AES without its parameters |
| `No(SequentialCipher)` | ZipCrypto: output byte `o` needs the whole stream before it decrypted |
| `Unknown(Truncated)` | the head ends before a member header that could be chosen |
| `Unknown(NoMembers)` | a complete listing with no files |
| `Unknown(NotRecognised)` | `Packing::Unknown` |

`PasswordProof`, strongest first:

- `Verifier`: the format's own check matched. RAR 5.0: the 8-byte password check value (needs a KDF of at most
  2^20 rounds; above that nothing is checked). WinZip AES: the 2-byte verifier, which a wrong password passes about
  once in 65,536.
- `Plaintext`: the decrypted first bytes of the member are a recognised media magic.
- `Headers`: the password decrypted the encrypted headers.
- `Unverified`: nothing checked it. RAR 4.x has no check value, so a wrong password for a RAR 4.x member whose
  first bytes are not in the head (or not media) is `Unverified`.

A continued member (`continued: true`) is judged the same way: stored data maps, but where this part falls in the
member's output depends on earlier volumes.

## Media recognition

`sniff` looks at offset 0 only:

| kind | magic | `Validated` when |
|---|---|---|
| `Mkv`, `Webm` | EBML `1A 45 DF A3`, DocType `matroska` or `webm` | the Segment element follows the EBML header. Another DocType is rejected; a header cut before its DocType is `Mkv` by magic |
| `Mp4`, `Mov` | an `ftyp` box of 16 to 4,096 bytes with a printable major brand (`qt  ` is `Mov`) | the next box is a known type or past the bytes |
| `Mov` | a QuickTime file without `ftyp`: a first `moov`, `mdat`, `wide`, `free`, `skip` or `pnot` atom | the next atom is a known type; a next atom that is not one rejects it |
| `Avi` | `RIFF` size `AVI ` | a `LIST` chunk follows |
| `MpegTs` | `0x47` every 188 bytes from offset 0, at least 3 present and all present matching (16 checked) | 8 or more |
| `M2ts` | `0x47` every 192 bytes from offset 4, same counts | 8 or more |
| `Asf` | the ASF header object GUID | the header size is at least 30 and the reserved bytes are `01 02`; a smaller size is rejected |
| `MpegPs` | pack header `00 00 01 BA` | MPEG-2 or MPEG-1 marker bits; other bits are rejected |

A lone `0x47` byte, two packets' worth, RIFF WAVE, and an `ftyp` of an impossible size are not media.
