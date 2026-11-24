#!/bin/sh
# Regenerates the reference archives with GNU tar 1.35 (debian:trixie). Run from this directory:
#   docker run --rm -v "$PWD":/w debian:trixie sh /w/make-reference.sh
# The tree contents here must match tests/tar_writer.rs.
set -e
tar --version | head -1
rm -rf /t && mkdir /t && cd /t
A=$(printf 'a%.0s' $(seq 1 100))      # 100 chars
A1="${A}b"                            # 101 chars
C100=$(printf 'c%.0s' $(seq 1 100))
C60=$(printf 'e%.0s' $(seq 1 60))
T150=$(printf 't%.0s' $(seq 1 150))
mkdir d && printf 'hello\n' > d/short.txt
chown 1:1 d/short.txt; chmod 644 d/short.txt
printf 'x' > "$A"; printf 'y' > "$A1"
mkdir -p "$C100/$C100/$C60" && printf 'deep\n' > "$C100/$C100/$C60/file.bin"
U="uni/$(printf '\303\274n\303\257')-$(printf '\346\227\245\346\234\254').txt"
mkdir uni && printf 'u\n' > "$U"
ln -s d/short.txt link
ln -s "$T150" longlink
ln d/short.txt hl
ln "$A" "hl-$(printf 'h%.0s' $(seq 1 110))"
: > empty
mkfifo pipe
mknod null c 1 3
mknod blk b 7 0
printf 'big\n' > bigtime; printf 'bigid\n' > bigid; chown 3000000:2 bigid
P60=$(printf 'p%.0s' $(seq 1 60)); Q60=$(printf 'q%.0s' $(seq 1 60))
mkdir -p "$P60/$Q60" && printf 'split\n' > "$P60/$Q60/r.txt"
printf 'frac\n' > frac
H110=$(printf 'h%.0s' $(seq 1 110))
ln -s "$T150" "both-$H110"
chown 0:0 d; chmod 755 d; chmod 4755 empty
for f in d d/short.txt "$A" "$A1" "$C100" "$C100/$C100" "$C100/$C100/$C60" "$C100/$C100/$C60/file.bin" uni "$U" link longlink empty pipe null blk bigtime bigid "$P60" "$P60/$Q60" "$P60/$Q60/r.txt" "both-$H110"; do
  touch -h -d @1700000000 "$f"
done
touch -h -d @9000000000 bigtime
touch -d @1700000000.123456789 frac
touch -d @1700000123 hl-*
# the hard link target is the first-listed name, so list it first
LIST="d d/short.txt hl $A hl-$(printf 'h%.0s' $(seq 1 110)) $A1 $C100 $C100/$C100 $C100/$C100/$C60 $C100/$C100/$C60/file.bin uni "$U" link longlink empty pipe null blk bigtime bigid frac $P60 $P60/$Q60 $P60/$Q60/r.txt both-$H110"
printf "%s\n" "$LIST" | sed "s/ /\n/g" | tr ' ' '\n' > /list.txt
touch -h -d @1700000000 hl
chown 3000000:2 "$A1"; touch -d @1700000000.5 "$A1"
C="tar -c --no-recursion --sort=none -b 20"
$C --format=gnu -f /w/gnu.tar -T /list.txt
$C --format=gnu --numeric-owner -f /w/gnu-numeric.tar -T /list.txt
$C --format=gnu --owner=alice:1001 --group=staff:50 --mtime=@1600000000 -f /w/gnu-override.tar -T /list.txt
$C --format=pax --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime -f /w/pax.tar -T /list.txt
printf 'd\nd/short.txt\nhl\nlink\nempty\npipe\nnull\nblk\nfrac\n%s\n%s\n' "$P60" "$P60/$Q60/r.txt" > /list2.txt
$C --format=ustar -f /w/ustar.tar -T /list2.txt
ls -l /w
