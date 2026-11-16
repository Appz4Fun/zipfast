#!/bin/sh
# Regenerates the Deflate64 fixtures. Usage: gen.sh /path/to/7zz OUTDIR
# Made with 7-Zip (7zz) 26.06 on macOS arm64. The tests check what the archives extract to, not their bytes.
set -eu
SZ=$1
OUT=$(cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 -I "$HERE/gen_inputs.py" "$WORK/in"
cd "$WORK/in"
find . -exec touch -t 202001020304.05 {} +
a() { name=$1; shift; rm -f "$OUT/$name"; "$SZ" a </dev/null -bd -bso0 -bsp0 -mtc=off -mta=off "$OUT/$name" "$@"; }
a d64.zip -tzip -mm=Deflate64 -mx=9 far.bin runs.bin small.txt text.txt
a d64_zipcrypto.zip -tzip -mm=Deflate64 -mem=ZipCrypto -ppassword small.txt text.txt
a d64_aes.zip -tzip -mm=Deflate64 -mem=AES256 -ppassword small.txt text.txt
a d64.7z -t7z -m0=Deflate64 -mx=9 far.bin runs.bin small.txt text.txt
# The expected contents: size and SHA-256 of every input file.
for f in far.bin runs.bin small.txt text.txt; do
  printf '%s %s %s\n' "$f" "$(wc -c < "$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
done > "$OUT/expected.txt"
