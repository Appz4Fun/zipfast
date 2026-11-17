#!/bin/sh
# Regenerates the sparse tar fixtures: GNU tar 1.35 in Docker (debian:trixie-slim) and macOS bsdtar (libarchive).
#   sh gen.sh        (from this directory)
set -eu
cat > /tmp/zf-sparse-make.sh <<'EOS'
set -eu
mk() { # name: islands of data at 1 MiB steps after a leading hole, then a trailing hole
  f=$1; n=$2; rm -f "$f"; truncate -s $(( (n + 1) * 1048576 + 12345 )) "$f"
  i=1; while [ $i -le $n ]; do
    printf "island %d " $i | dd of="$f" bs=1 seek=$(( i * 1048576 )) conv=notrunc 2>/dev/null
    head -c 8188 /dev/zero | tr '\0' "$(printf "\\$(printf %o $((64 + i % 26)))")" | dd of="$f" bs=1 seek=$(( i * 1048576 + 4 )) conv=notrunc 2>/dev/null
    i=$((i + 1)); done
}
EOS
docker run --rm --network none -v "$PWD:/o" -v /tmp/zf-sparse-make.sh:/m.sh:ro debian:trixie-slim sh -c '
  set -eu; . /m.sh; mkdir /w; cd /w; mk few 3; mk many 30
  tar --version | head -1
  tar -c --sparse --format=gnu -f /o/gnu-old.tar few many
  for v in 0.0 0.1 1.0; do tar -c --sparse --format=posix --sparse-version=$v --pax-option=delete=atime,delete=ctime -f /o/pax-$v.tar few many; done
  gzip -n -9 -c /o/pax-1.0.tar > /o/pax-1.0.tgz
  sha256sum few many > /o/expected.sha256; ls -l few many | awk "{print \$5, \$9}" > /o/expected.size'
rm -f /tmp/zf-sparse-make.sh
# bsdtar finds holes with SEEK_HOLE, and APFS keeps holes only in bigger files: 24 MiB apart, three islands
rm -rf /tmp/zf-sparse-src; mkdir /tmp/zf-sparse-src
python3 -c '
import sys
f = open(sys.argv[1], "wb")
for i in range(1, 4):
    f.seek(i * (24 << 20)); f.write(b"island %d " % i + bytes([64 + i]) * 8188)
f.truncate(4 * (24 << 20) + 12345)' /tmp/zf-sparse-src/holes
bsdtar --version
COPYFILE_DISABLE=1 bsdtar -c --format pax --read-sparse --no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root --gname root -f bsdtar-pax.tar -C /tmp/zf-sparse-src holes
gzip -n -9 -c bsdtar-pax.tar > bsdtar-pax.tgz
(cd /tmp/zf-sparse-src && shasum -a 256 holes) > expected-bsdtar.sha256
rm -rf /tmp/zf-sparse-src
