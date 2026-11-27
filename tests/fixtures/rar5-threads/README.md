# RAR 5.0 fixtures big enough for worker threads

Used by `tests/rar5_session_threads.rs`. Made with rar 7.00 (Linux x86-64) from text written by `make_text.py` (a
48 KiB passage of words repeated, with `CHANGES` five-byte words changed before each repetition), and tested whole
with `unrar t`. The RAR 5.0 blocks are about 24 KB packed each, so every big member has several.

```sh
python3 make_text.py a.txt 4400000 1 1200
python3 make_text.py b.txt 4200000 2 600
python3 make_text.py c.txt 600000 3 600
python3 make_text.py d.txt 4300000 4 600
printf 'small\n' > s.txt
rar a -ma5 -m3 -md1m -s- -v128k big.rar a.txt s.txt       # big.part01.rar .. big.part03.rar
rar a -ma5 -m3 -md4m -s solid.rar b.txt c.txt d.txt s.txt
```

| file | size | SHA-256 | packed |
| --- | --- | --- | --- |
| `a.txt` (`big`, over 3 volumes) | 4,400,000 | `f19b51f7…48dab4` | 295,109 over 3 volumes |
| `b.txt` (`solid`) | 4,200,000 | `f6539c68…443cb1` | 152,166 |
| `c.txt` (`solid`) | 600,000 | `024dcef7…089b8e` | 30,575 |
| `d.txt` (`solid`) | 4,300,000 | `55f5bb3c…be0774` | 155,976 |
| `s.txt` (both) | 6 | `4c47b3e8…528e8f` | |

`a.txt`, `b.txt` and `d.txt` are past the 4 MiB from which the decoder goes to its workers by default.
