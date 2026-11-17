#!/bin/sh
# Regenerates the LZ4, compress (.Z) and LZMA-alone fixtures with the host's tools (macOS: lz4 1.11, compress,
# xz 5.x, bsdtar 3.7):   sh gen.sh   (from this directory)
set -eu
w=$(mktemp -d)
# 64 KiB that compresses unevenly: words, then 8 KiB of noise (which fills a 9- or 12-bit LZW table and makes
# compress clear it), then words again; and 512 KiB of four letters at random, which fills a 16-bit table
python3 -c '
import random, sys
r = random.Random(1)
words = [b"tar", b"lz4", b"frame", b"block", b"code", b"table", b"clear", b"window", b"zipfast", b"\n"]
out = bytearray()
while len(out) < 24 << 10: out += r.choice(words) + b" "
out += bytes(r.getrandbits(8) for _ in range(8 << 10))
while len(out) < 64 << 10: out += r.choice(words) + b" "
open(sys.argv[1], "wb").write(out)
open(sys.argv[2], "wb").write(bytes(r.choice(b"acgt") for _ in range(512 << 10)))' "$w/data.bin" "$w/dna.bin"
printf 'a small second member\n' > "$w/small.txt"
for v in plain legacy linked; do cp "$w/data.bin" "$w/data-$v.bin"; done
lz4 -q -9 -f "$w/data-plain.bin" data-plain.bin.lz4
lz4 -q -l -f "$w/data-legacy.bin" data-legacy.bin.lz4
lz4 -q -B4 -BD -BX --content-size -f "$w/data-linked.bin" data-linked.bin.lz4
# a frame, a skippable frame, a legacy frame: one stream, as lz4 -d reads it
python3 -c '
import sys, struct
a = open(sys.argv[1], "rb").read(); b = open(sys.argv[2], "rb").read()
open(sys.argv[3], "wb").write(a + struct.pack("<II", 0x184D2A53, 5) + b"skip!" + b)' \
  data-plain.bin.lz4 data-legacy.bin.lz4 data-frames.bin.lz4
for b in 9 12; do cp "$w/data.bin" "$w/data-b$b.bin"; compress -c -b $b "$w/data-b$b.bin" > data-b$b.bin.Z; done
compress -c -b 16 "$w/dna.bin" > dna.bin.Z
xz --format=lzma -6 -c "$w/data.bin" > data.bin.lzma
(cd "$w" && shasum -a 256 data.bin dna.bin small.txt) > expected.sha256
for z in --lz4 --lzma -Z; do
  ext=$(echo "$z" | sed 's/--//; s/-Z/Z/')
  COPYFILE_DISABLE=1 bsdtar -c --format ustar $z --uid 0 --gid 0 --uname root --gname root -f "t.tar.$ext" -C "$w" data.bin small.txt
done
rm -rf "$w"
