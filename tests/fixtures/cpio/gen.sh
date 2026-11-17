#!/bin/sh
# Regenerates the cpio fixtures with macOS bsdtar 3.7 (newc, odc and the binary format in the host's byte
# order); the newc-with-checksums and big-endian binary ones are converted from those here, since bsdtar writes
# neither.   sh gen.sh   (from this directory)
set -eu
w=$(mktemp -d)
mkdir "$w/src" "$w/src/d"
cd "$w/src"
printf 'linked data\n' > a
ln a b
ln a c
: > e
ln e e2
ln -s a s
printf 'in a folder\n' > d/f
mkfifo p
touch -t 202601020304.05 a e d/f d . p
touch -h -t 202601020304.05 s
cd - > /dev/null
for f in newc odc bin; do
  # the binary format has no way to store a fifo
  p=p; [ $f = bin ] && p=
  COPYFILE_DISABLE=1 bsdtar -c --format $f --uid 0 --gid 0 -f "$f.cpio" -C "$w/src" d a b c e e2 s $p
done
gzip -n -9 -c newc.cpio > newc.cpio.gz
xz -c odc.cpio > odc.cpio.xz
python3 - <<'PY'
import struct
# newc to newc with checksums: magic 070702, and the check field the sum of each file's data bytes
d = bytearray(open("newc.cpio", "rb").read()); i = 0
while True:
    assert d[i:i+6] == b"070701"
    f = lambda k: int(d[i+6+8*k:i+14+8*k], 16)
    size, namesize = f(6), f(11)
    name_end = i + 110 + namesize; data = (name_end + 3) // 4 * 4
    name = bytes(d[i+110:name_end-1])
    d[i:i+6] = b"070702"
    if f(1) & 0o170000 == 0o100000:
        d[i+102:i+110] = b"%08X" % (sum(d[data:data+size]) & 0xffffffff)
    if name == b"TRAILER!!!": break
    i = (data + size + 3) // 4 * 4
open("crc.cpio", "wb").write(d)
# little-endian binary to big-endian: every 16-bit field swapped
d = bytearray(open("bin.cpio", "rb").read()); i = 0
while True:
    w = struct.unpack_from("<13H", d, i)
    assert w[0] == 0o070707
    struct.pack_into(">13H", d, i, *w)
    namesize, size = w[10], (w[11] << 16) | w[12]
    name = bytes(d[i+26:i+26+namesize-1])
    if name == b"TRAILER!!!": break
    i += 26 + namesize + namesize % 2
    i += size + size % 2
open("bin-be.cpio", "wb").write(d)
PY
rm -rf "$w"
