#!/bin/sh
# Builds the WIM fixtures with wimlib-imagex (Debian's wimtools) in a container with no network:
#   docker run --name wimtools-build debian:stable-slim sh -c 'apt-get update && apt-get install -y wimtools'
#   docker commit wimtools-build zf-wimtools && docker rm wimtools-build
#   docker run --rm --network none -v "$PWD":/out zf-wimtools sh /out/gen.sh
# The tree is made of fixed bytes so the fixtures are the same each run but for their GUIDs and timestamps.
set -eu
cd /tmp
rm -rf tree tree2
mkdir -p tree/dir/sub tree/empty-dir
printf 'hello, wim\n' > tree/hello.txt
: > tree/empty.txt
# text that compresses, several chunks long
i=0; while [ $i -lt 3000 ]; do echo "line $i of a text file that spans several 32 KiB chunks"; i=$((i+1)); done > tree/dir/big.txt
# bytes that don't compress, so some chunks are stored as they are (mawk's generator, as Debian has it)
awk 'BEGIN{srand(7); for(i=0;i<100000;i++) printf "%c", int(rand()*256)}' > tree/dir/random.bin
# a copy: the same blob, stored once
cp tree/dir/big.txt tree/dir/sub/copy.txt
printf 'unicode\n' > "tree/dir/sub/caf$(printf '\303\251').txt"
ln tree/hello.txt tree/dir/hard.txt
ln -s ../hello.txt tree/dir/rel-link
ln -s /etc/passwd tree/dir/abs-link
# x86 code-like bytes for LZX's E8 translation
awk 'BEGIN{for(i=0;i<20000;i++) printf "\350%c%c%c%c\220", i%256, int(i/256)%256, 0, 0}' > tree/dir/e8.bin
mkdir -p tree2
printf 'second image\n' > tree2/two.txt

for c in none xpress lzx; do
  wimlib-imagex capture tree /out/$c.wim "one" --compress=$c --unix-data >/dev/null
done
wimlib-imagex capture tree /out/lzms.wim "one" --compress=lzms >/dev/null
wimlib-imagex capture tree /out/solid.wim "one" --solid >/dev/null
cp /out/xpress.wim /out/multi.wim
wimlib-imagex append tree2 /out/multi.wim "two" >/dev/null
# expected contents: sha256 of each file as wimlib extracts it (LZMS and solid files are only checked to be refused)
rm -rf x && mkdir x && wimlib-imagex apply /out/lzx.wim 1 x >/dev/null
(cd x && find . -type f | LC_ALL=C sort | xargs sha256sum) > /out/expected.sha256
