# RAR long-password fixtures

Each archive holds one file, `f.txt` (`hello long password test data`). The name is
`<kind>-<enc>-<id>.rar`; `pw<id>.txt` (no trailing newline) is the password it was made with.

- `a5-*` / `u5-*`: RAR 5.0, made with `rar` 7.20 (`rar a -ma5 ...`).
- `a4-*` / `u4-*`: RAR 3.x/4.x, made with `rar` 6.24 (`rar a -ma4 ...`); `rar` 7 cannot write RAR 4.
- `-p-`: data encryption (`-p<password>`); `-hp-`: header encryption (`-hp<password>`).
- `a*-<n>`: ASCII password of n characters (126, 127, 128, 129, 200): `A0B1C2...` (letter, digit, repeating).
- `u*-e`: 120 ASCII characters then ten `é` (130 characters, 140 UTF-8 bytes) (`pwe.txt`).
- `u*-j`: 124 ASCII characters then six U+1F600 (130 characters; 136 UTF-16 units) (`pwj.txt`).

Made with a UTF-8 locale. The expectations (`tests/rar_long_password.rs`) come from running UnRAR 7.30 on
these archives; see `docs/rar-passwords.md` for the table.
- `mid4-p-40`, `mid4-hp-40`: RAR 4, 40-character password (`pw40.txt`, the first 40 characters of `pw200.txt`).
- `short4-p-abc`: RAR 4, password `abc`.
