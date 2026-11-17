#!/bin/sh
# Regenerates the ISO 9660 fixtures: xorriso 1.5.6 and genisoimage 1.1.11 in Docker (debian:trixie-slim), and
# macOS bsdtar 3.7. Images are mostly zeros, so they are kept gzipped.   sh gen.sh   (from this directory)
set -eu
cat > /tmp/zf-iso-make.sh <<'EOS'
set -eu
mk() { # the tree every image holds
  rm -rf "$1"; mkdir -p "$1/dir/sub" "$1/a/b/c/d/e/f/g/h/i/j"
  printf 'hello iso\n' > "$1/a.txt"
  ln -s a.txt "$1/link"
  ln -s ../../a.txt "$1/dir/sub/up"
  printf 'deep\n' > "$1/dir/sub/f"
  printf 'ten levels down\n' > "$1/a/b/c/d/e/f/g/h/i/j/k.txt"
  printf 'long name\n' > "$1/LongFileName With Spaces.txt"
  printf 'unicode\n' > "$1/$(printf 'caf\303\251.txt')"
  yes 'a line of iso data, again and again' | head -c 300000 > "$1/big.bin"
  chmod 0751 "$1/dir"; chmod 0600 "$1/dir/sub/f"
  find "$1" -exec touch -h -d 2026-01-02T03:04:05Z {} +
}
EOS
docker run --rm -v "$PWD:/o" -v /tmp/zf-iso-make.sh:/m.sh:ro debian:trixie-slim sh -c '
  set -eu; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq xorriso genisoimage >/dev/null 2>&1
  . /m.sh; mk /src; cd /src
  xorriso -as mkisofs -quiet -R -J -V RRJOLIET -o /o/rr-joliet.iso /src
  # xorriso always writes Rock Ridge: Joliet alone, and plain ISO 9660 names, come from genisoimage
  genisoimage -quiet -input-charset utf-8 -J -V JOLIET -o /o/joliet.iso /src
  genisoimage -quiet -input-charset utf-8 -iso-level 1 -V PLAIN -o /o/plain.iso /src
  genisoimage -quiet -input-charset utf-8 -R -V RELOCATED -o /o/relocated.iso /src
  sha256sum a.txt dir/sub/f a/b/c/d/e/f/g/h/i/j/k.txt "LongFileName With Spaces.txt" big.bin > /o/expected.sha256'
. /tmp/zf-iso-make.sh
w=$(mktemp -d); mk "$w/src"
# the same tree, from bsdtar
COPYFILE_DISABLE=1 bsdtar -c --format iso9660 --options iso9660:joliet,iso9660:rockridge,iso9660:volume-id=BSDTAR \
  --uid 0 --gid 0 -f bsdtar.iso -C "$w/src" .
rm -rf "$w" /tmp/zf-iso-make.sh
for f in *.iso; do gzip -n -9 -f "$f"; done
