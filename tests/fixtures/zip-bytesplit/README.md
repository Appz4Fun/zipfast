# Byte-split ZIP fixture

`bytesplit.zip.001` to `.004`: one ZIP cut at 1 KiB boundaries with no disk numbers, written by 7-Zip (7zz) 26.06:

```sh
7zz a -tzip -v1k bytesplit.zip noise.bin tiny.txt
```

`noise.bin` is 3000 pseudo-random bytes (stored, as Deflate does not shrink it) and `tiny.txt` is `tiny\n`.
