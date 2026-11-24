#!/bin/sh
# Regenerates the sparse reference archives with GNU tar 1.35 (debian:trixie). Run from this directory:
#   docker run --rm --privileged -v "$PWD":/w debian:trixie sh /w/make-sparse.sh
# (--privileged only for `unshare -fp`: tar runs as pid 1, so pax names its data member GNUSparseFile.1/<name>).
# The files must match tests/tar_writer_sparse.rs. Data lives in 4096-byte file system blocks (tmpfs).
set -e
tar --version | head -1
M=/dev/shm/t; rm -rf $M && mkdir $M && cd $M
blk() { head -c 4096 /dev/zero | tr '\0' "$1"; }        # one block of letter $1
put() { blk "$1" | dd of="$2" bs=4096 seek="$3" conv=notrunc 2>/dev/null; }   # block $3 of file $2
# one data block at each end, a long hole between (data runs to EOF)
truncate -s 1M one-hole; put A one-hole 0; put Z one-hole 255
# 6 and 30 segments (the old GNU header holds 4; each extension block holds 21 more), hole at the end
truncate -s 1M many6; for i in 0 1 2 3 4 5; do put $(echo ABCDEF | cut -c$((i+1))) many6 $((i*40)); done
truncate -s 1M many30; for i in $(seq 0 29); do put $(echo abcdefghijklmnopqrstuvwxyzABCD | cut -c$((i+1))) many30 $((i*8)); done
# data then a hole to the end; hole then data; a partial last block; nothing but hole
truncate -s 1M hole-end; put H hole-end 0
truncate -s 1M hole-start; put S hole-start 255
truncate -s 36840 partial; put P partial 0; printf 'tail-data' | dd of=partial bs=1 seek=36000 conv=notrunc 2>/dev/null
truncate -s 1M all-hole
# a long name in a directory, an uid too big for octal and a fractional mtime
L=sd/$(printf 'l%.0s' $(seq 1 110)); mkdir sd; truncate -s 20480 "$L"; put L "$L" 0; put M "$L" 3
ls -ls
LIST="one-hole many6 many30 hole-end hole-start partial all-hole $L"
for f in $LIST; do chmod 644 $f; chown 0:0 $f; touch -d @1700000000 $f; done
chown 3000000:2 "$L"; touch -d @1700000000.25 "$L"
printf '%s\n' $LIST > /list.txt
C="tar -c --no-recursion --sort=none -b 20 --sparse -T /list.txt"
P=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime
$C --format=gnu -f /w/sparse-gnu.tar
unshare -fp $C --format=pax --pax-option=$P -f /w/sparse-pax10.tar
unshare -fp $C --format=pax --sparse-version=1.0 --pax-option=$P -f /w/sparse-pax10-explicit.tar
cmp /w/sparse-pax10.tar /w/sparse-pax10-explicit.tar && echo "pax default sparse version == 1.0"
rm /w/sparse-pax10-explicit.tar
ls -l /w/sparse-*
