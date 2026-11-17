#!/bin/sh
# Regenerates the ZIP PPMd fixtures with 7-Zip 26.06 (Linux amd64) in Docker:
#   tests/fixtures/zip-ppmd/gen.sh /dir/holding/7z
set -eu
BIN=$1
OUT=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 -I "$OUT/gen_inputs.py" "$WORK"
docker run --rm --platform linux/amd64 --network none -e TZ=UTC -v "$BIN:/b:ro" -v "$WORK:/w" -v "$OUT:/o" \
  rust:1-bookworm sh -c '
    cd /w &&
    /b/7z a -bso0 -bsp0 -tzip -mm=PPMd -mo=6 -mmem=1m /o/ppmd-o6-restart.zip w150.txt small.txt &&
    /b/7z a -bso0 -bsp0 -tzip -mx=9 -mm=PPMd -mo=8 -mmem=1m /o/ppmd-o8-cutoff.zip w150.txt small.txt &&
    /b/7z a -bso0 -bsp0 -tzip -mx=9 -mm=PPMd -mo=16 -mmem=1m /o/ppmd-o16-cutoff.zip w150.txt small.txt &&
    /b/7z a -bso0 -bsp0 -tzip -mx=9 -mm=PPMd -mem=AES256 -ppassword /o/ppmd-aes.zip small.txt'
