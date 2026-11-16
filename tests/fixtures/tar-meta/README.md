# Tar listing metadata fixtures

Written by `gen.py` (Python's `tarfile`): `python3 gen.py .`

| file | contents |
|---|---|
| `pax.tar`, `pax.tgz` | `f.txt` as pax, owner `builder`/`staff` (1234/56), with `atime`, `ctime` and `comment` records |
| `gnu.tar` | `f.txt` with GNU magic, the same owner |
| `ustar.tar` | `f.txt` and the character device `dev` (4, 7), POSIX ustar |
