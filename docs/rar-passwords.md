# RAR password length and character handling

Measured by running `rar` 7.20 and 6.24 (macOS arm64) and `unrar` 7.30 (macOS, and the Linux build in docker),
never from source. Fixtures and how they were made: `tests/fixtures/rar-long-password/README.md`.
Tests: `tests/rar_long_password.rs`, and unit tests in `src/crypto.rs`.

## Findings

Archive made with an ASCII password of N characters, then opened by `unrar t -p<candidate>`. "ok" means the
archive tests clean (exit 0); "no" is a refusal (exit 11 for RAR5, 3 for RAR4). Same result for RAR5 and RAR4
(`-ma5`, `-ma4`), for data encryption (`-p`) and header encryption (`-hp`).

| password length | candidate: first 125 | first 126 | first 127 | first 128 | first 129 | first 130 | whole |
|---|---|---|---|---|---|---|---|
| 126 | no | ok | n/a | n/a | n/a | n/a | ok |
| 127 | no | no | ok | n/a | n/a | n/a | ok |
| 128 | no | no | ok | ok | n/a | n/a | ok |
| 129 | no | no | ok | ok | ok | n/a | ok |
| 200 | no | no | ok | ok | ok | ok | ok |

Both `rar` (when creating) and `unrar` (when opening) use only the first 127 characters. A candidate opens an
archive exactly when its first 127 characters equal the password's first 127. `rar` 7.20 prints "Password
exceeds the maximum allowed length of 127 characters and will be truncated." and goes on (it does not refuse);
`rar` 6.24 truncates silently. `unrar` is silent when it opens an over-long candidate.

Characters, not bytes or UTF-16 units:

| password | candidate | result |
|---|---|---|
| 120 ASCII + 10 x U+00E9 (130 characters, 140 bytes) | first 127 characters | ok |
| same | first 126 characters | no |
| same | first 127 bytes (fewer than 127 characters) | no |
| 124 ASCII + 6 x U+1F600 (130 characters, 136 UTF-16 units) | first 127 characters | ok |
| same | first 126 characters | no |

RAR5 hashes the UTF-8 bytes of the first 127 characters.

## RAR 3.x/4.x: two more facts found on the way

* Each character is hashed as two bytes. A character above U+FFFF is its code point's low 16 bits, not a UTF-16
  surrogate pair (an archive made by `rar` with six U+1F600 opens in `unrar` only with that mapping; Linux
  `unrar` agrees with macOS). Archives written on Windows, where characters are UTF-16, may differ for such
  passwords; zipfast follows the binaries it was checked against.
* The RAR 3.x key derivation uses a SHA-1 that rewrites the message it hashes (the password in UTF-16 plus the
  salt), so every later one of its 2^18 rounds sees changed bytes. A block hashed straight from the message, which
  is every block after the first 64 bytes, is overwritten with the last 16 expanded message words (little
  endian). It shows once the message exceeds 64 bytes (29 characters with the 8-byte salt). zipfast used a plain
  SHA-1 and could not open RAR 4 archives with passwords of 29 or more characters; this is fixed together with
  the truncation (found because the long-password fixtures would not open).

## zipfast

`crypto::RAR_MAX_PASSWORD_CHARS` (127) is applied where keys are derived: RAR5 (`rar5_pbkdf2`,
`Rar5PasswordCheck::accepts_bytes`; UTF-8, characters are counted, invalid UTF-8 is cut at 127 bytes) and RAR4
(`derive_rar4_key_iv_impl`; UTF-16 units, a pair counts as one character). Every public and controlled derive
function passes through them, so data and header encryption, listing, extraction, mapping and the progressive
and partial sessions all agree.

## Derived keys are cached per run and session

`rar` gives every encrypted header and file record of an archive (and of every volume of a set) the same salt, so
deriving per member or per volume repeats the same PBKDF2 run: ~3 ms each at the usual count of 15, which made a
1000-member `-hp` archive take seconds. UnRAR and 7-Zip keep the keys of recent inputs, and so does zipfast:

* `crypto::KdfCache` keeps key material by (password, salt, count), at most `KdfCache::KEPT` (16) inputs, least
  recently used dropped first, in memory only, for the life of one run or session. An archive with a new salt in
  every header derives as it would without a cache. Nothing is kept across runs or process-wide.
* RAR 5.0 keeps the key, the `HashKey` and the derived password check value (`crypto::Rar5Derived`), not a verdict:
  every member's own check value is still compared, so a wrong password fails each member as before. Material
  derived for a record without a usable check value is derived again for a later record that has one.
* The whole-archive runner shares one `crypto::SharedRar5Keys` with every volume it opens (header keys) and its
  members (data keys, link password checks); listing shares it between volumes; `RarSession` shares it between the
  catalogue and every selection. Progressive and partial sessions, member maps and feed decoders cache through
  their `progressive::Usage`, for RAR 5.0, RAR 3.x and 7zAES: a repeated input charges no KDF work to the session
  budget, a new one is charged in full.
