#!/bin/sh
# Regenerates the xar fixtures: bsdtar 3.7 with each compression and file checksum, and macOS xar 1.8 with
# SHA-256 checksums (the TOC checksum named in the header).   sh gen.sh   (from this directory)
set -eu
w=$(mktemp -d)
mkdir -p "$w/src/d"
cd "$w/src"
printf 'hello xar\n' > a
ln a b
ln -s a s
: > e
printf 'nested\n' > d/f
python3 -c 'import random; r = random.Random(7); open("big", "wb").write(bytes(r.choice(b"abcdefgh \n") for _ in range(100000)))'
touch -t 202601020304.05 a e d/f big d
touch -h -t 202601020304.05 s
cd - > /dev/null
bx() { COPYFILE_DISABLE=1 bsdtar -c --format xar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root \
  --gname root --options "$2" -f "$1" -C "$w/src" a b s e d big; }
bx bsd-gzip-sha1.xar xar:compression=gzip,xar:checksum=sha1
bx bsd-bzip2-md5.xar xar:compression=bzip2,xar:checksum=md5,xar:toc-checksum=md5
bx bsd-xz.xar xar:compression=xz
bx bsd-lzma.xar xar:compression=lzma
bx bsd-stored.xar xar:compression=none,xar:checksum=none,xar:toc-checksum=none
(cd "$w/src" && COPYFILE_DISABLE=1 xar -c --toc-cksum=sha256 --file-cksum=sha256 --no-compress '^big$' \
  -f "$OLDPWD/apple-sha256.xar" a b s e d big)
# xar records the owner's names and ids: they become root's, and the TOC and its checksum are rewritten
python3 - apple-sha256.xar <<'PY'
import hashlib, re, struct, sys, zlib
path = sys.argv[1]
d = open(path, "rb").read()
magic, hs, ver, tc, tu, alg = struct.unpack(">4sHHQQI", d[:28])
toc = zlib.decompress(d[hs:hs + tc]).decode()
toc = re.sub(r"<(user|group)>[^<]*<", r"<\1>root<", toc)
toc = re.sub(r"<(uid|gid)>[^<]*<", r"<\1>0<", toc)
packed = zlib.compress(toc.encode(), 9)
heap = bytearray(d[hs + tc:])
heap[0:32] = hashlib.sha256(packed).digest()
head = struct.pack(">4sHHQQI", magic, hs, ver, len(packed), len(toc.encode()), alg) + d[28:hs]
open(path, "wb").write(head + packed + bytes(heap))
PY
(cd "$w/src" && shasum -a 256 a d/f big) > expected.sha256
rm -rf "$w"
