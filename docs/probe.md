# Probing

`zipfast::probe` says how a release is packed from the first bytes of its first file, typically one Usenet article
of about 700 KB, held in memory. It answers three questions:

1. Is the file bare media, a RAR volume, a ZIP archive, a 7z archive, or something else?
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
    // PasswordUnverified: prove the password some other way before borrowing.
    _ => { /* fetch it all */ }
}
```

Only `Yes` and `YesWithPassword(_)` are safe to borrow on. `PasswordUnverified` is deliberately a separate verdict:
the password may be wrong, and borrowed bytes decrypted with a wrong key are noise.

## API

- `probe(head, tail, password) -> Result<Packing, MapError>`
- `probe_with(head, tail, password, &ProbeOptions)`: `ProbeOptions { limits, file_len }`. `limits` are the
  member map's `ProgressiveLimits` (header bytes, names, entries, metadata, KDF). `file_len` is the whole file's
  length when known (a yEnc `size=`); without it the ZIP directory's position is inferred from `tail`.
- `sniff(bytes) -> Option<MediaMatch>` and `media_kind_for_name(name) -> Option<MediaKind>`, the two media tests
  the probe uses.

`head` is the file's first bytes. `tail`, when given, is its last bytes and is used only for ZIP (the central
directory is at the end). An empty password is no password.

The ZIP local-header walk moves strictly forward with checked arithmetic and lists at most `limits.entries` entries.

Detection order: the 7z signature (`7z\xBC\xAF\x27\x1C`) at offset 0 is 7z; a `Rar!` signature at offset 0 is RAR; a ZIP local header, an empty archive's end record, or the
spanned-archive marker followed by a local header is ZIP; then the media magic at offset 0; then the RAR scanner,
which finds a RAR signature behind a self-extracting stub in the first MiB. Anything else is `Packing::Unknown`.
A ZIP behind a stub is not detected.

Errors are `MapError`s from the member map: unsupported or damaged RAR headers the map does not tolerate, a budget
in `limits` (including `Limit { resource: Entries }` when the ZIP local-header walk passes `limits.entries`, and the
KDF budgets below), or a ZIP whose first local header is damaged. A wrong password for encrypted headers is not an
error (see below). A RAR volume whose map stops at a damaged header (`VolumeEnd::Damaged`) is probed from the members
listed before it, as an incomplete listing, like `Truncated`.

## `Packing`

| variant | contents |
|---|---|
| `BareMedia(MediaMatch)` | `MediaMatch { kind, confidence }`; always `Borrowable::Yes` |
| `Rar(RarPacking)` | `version` (`Rar4`/`Rar5`), `volume: VolumeFacts`, `header_encrypted`, `locked`, `first_media`, `borrowable`, and the full `map: VolumeMap` |
| `Zip(ZipPacking)` | `directory` (central directory read from `tail`), `complete` (every member listed), `spanned`, `members` (count), `first_media`, `borrowable` |
| `SevenZip(SevenZipPacking)` | `version`, `header_offset` and `header_len` (the end header, as archive offsets), `archive_len` (the whole archive; a split set's total), `complete`, `header_encrypted`, `locked`, `members`, `first_media`, `borrowable`, `map` |
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

A `Largest` pick from an incomplete listing (step 3 before the end header or central directory) is tentative: a
media member may follow. The member is reported in `first_media`, but the verdict is `Unknown(NoMediaYet)`.

So an `nfo` before the `mkv` never wins, and a head holding only an `nfo` header so far stays undecided.

## `Borrowable`

| verdict | when |
|---|---|
| `Yes` | bare media, or the member is stored in the clear |
| `YesWithPassword(proof)` | the member is stored and encrypted with a mapped cipher (RAR AES-CBC, WinZip AES), and something proved the password given (see `PasswordProof`); or it is stored in the clear behind encrypted headers that the password opened |
| `PasswordUnverified` | as above, but nothing could check or refute the password. **Not safe to borrow on** |
| `NeedsPassword(HeaderEncrypted)` | encrypted headers (`-hp`), no password |
| `NeedsPassword(DataEncrypted)` | encrypted stored data, no password |
| `NeedsPassword(WrongPassword)` | the password fails the encrypted headers, a RAR 5.0 check value, or a WinZip AES verifier; or a plaintext contradiction (below) |
| `No(Solid)` | compressed in a solid stream |
| `No(Compressed)` | compressed (whether or not also encrypted) |
| `No(UnsupportedCipher)` | older RAR encryption, ZIP strong encryption, ZIP method 99 without its AES extra field, a RAR 5.0 KDF count above 20 (the most the probe derives) |
| `No(SequentialCipher)` | ZipCrypto: output byte `o` needs the whole stream before it decrypted |
| `Unknown(Truncated)` | the head ends (or a damaged header stops the listing) before a member that could be chosen |
| `Unknown(NoMediaYet)` | no media member yet, and the largest member so far comes from an incomplete listing |
| `Unknown(NoMembers)` | a complete listing with no files |
| `Unknown(NotRecognised)` | `Packing::Unknown` |

`PasswordProof`, strongest first:

- `Verifier`: the format's own check matched. RAR 5.0: the 8-byte password check value, which stands on its own.
  WinZip AES: the 2-byte verifier, which a wrong password passes about once in 65,536, so a plaintext contradiction
  (below) still overrules it.
- `Plaintext`: the decrypted first bytes of the member are a recognised media magic. When the name has a media
  extension, the sniffed kind must be of the same family (Matroska/WebM, MP4/QuickTime, TS/M2TS, or the kind
  itself); a `.avi` that decrypts to Matroska is no proof.
- `Headers`: the password decrypted the encrypted headers. A plaintext contradiction does not overrule it.

A **plaintext contradiction** proves a password wrong: the member's name names a kind whose start is mandatory, at
least 4 KiB of plaintext (or the whole member, if smaller) was decrypted, nothing sniffs, and the plaintext does
not start the way that kind must:

| named kind | must start with |
|---|---|
| Matroska, WebM | the EBML magic `1A 45 DF A3` |
| AVI | `RIFF` |
| ASF | the ASF header GUID |
| MP4, QuickTime | a box header: a size of 0, 1 or at least 8, then four printable ASCII bytes (fragments start with `styp`, `moof`, `sidx` and others, and an `ftyp` over 4 KiB is not sniffed) |
| MPEG-TS, M2TS, MPEG-PS | never a contradiction: a stream may start mid-packet, use 204-byte packets, or be an elementary stream |

Without a proof or a contradiction the verdict is `PasswordUnverified`: no check value (always for RAR 4.x), and the
member's first bytes are not in the head, its name names no media, or the plaintext is of an unsniffed but
plausible form.

Data key derivations are charged to `ProbeOptions::limits`. RAR 5.0 KDF counts above 20 are past what the probe
derives and give `No(UnsupportedCipher)`; counts up to 20 but above `kdf_exponent` are
`MapError::Limit { resource: KdfExponent }`. `kdf_derivation_blocks` (per derivation) and `kdf_session_blocks` (over
the whole probe) are `MapError::Limit` when they run out. Header decryption is charged by the member map as usual.

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
| `MpegPs` | pack header `00 00 01 BA` | the whole pack header (MPEG-2: 14 bytes plus stuffing, MPEG-1: 12 bytes) has its marker bits and is followed by a start code `00 00 01`. Bad marker bits, or no start code after the header, are rejected; bytes ending inside the header are the magic only |

A lone `0x47` byte, two packets' worth, RIFF WAVE, and an `ftyp` of an impossible size are not media.

## 7z

A 7z archive keeps its headers at its end, so a first article normally holds only the 32-byte signature header. The
probe reports what it says: the format version and where the end header lies, which gives the archive's whole
length (`archive_len`; for a split set, the sum of its volumes). Members are listed only when the head holds the
whole archive; until then `complete` is false and `borrowable` is `Unknown(Truncated)`. With the headers read, a
Copy member is `Yes`, anything coded is `No(Compressed)`, and a member stored under 7zAES (`CipherKind::SevenZipAes`)
is judged as other encrypted stored members are: 7z has no check value, so with a password it is
`PasswordUnverified` unless its decrypted start sniffs as media. Encrypted headers (`-mhe`) that do not open give
`locked` and `NeedsPassword(HeaderEncrypted)` or `NeedsPassword(WrongPassword)`.
