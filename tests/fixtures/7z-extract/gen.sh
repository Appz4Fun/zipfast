#!/bin/sh
# Regenerates the 7z extraction fixtures. Usage: gen.sh /path/to/7zz OUTDIR
# Made with 7-Zip (7zz) 26.06 on macOS arm64. Output differs between 7-Zip versions; the tests only check that the
# archives extract to the inputs gen_inputs.py writes, not their bytes.
set -eu
SZ=$1
OUT=$(cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 -I "$HERE/gen_inputs.py" "$WORK/in"
cd "$WORK/in"
# Fixed times so the archives carry known mtimes (2020-01-02 03:04:05 local).
find . -exec touch -t 202001020304.05 {} +
a() { name=$1; shift; rm -f "$OUT/$name"; "$SZ" a -bd -bso0 -bsp0 -mtc=off -mta=off "$OUT/$name" "$@"; }
a copy.7z -m0=Copy text/a.txt text/b.txt text/tiny.txt
a lzma.7z -m0=LZMA:d=64k -ms=off text/a.txt text/b.txt
a lzma2.7z -m0=LZMA2:d=64k -ms=off text/a.txt text/b.txt
a solid.7z -m0=LZMA2:d=1m -ms=on text big
a tree.7z -m0=LZMA2:d=64k tree text/run.sh
for f in x86:BCJ arm:ARM armt:ARMT arm64:ARM64 ppc:PPC sparc:SPARC ia64:IA64; do
  arch=${f%%:*}; filter=${f#*:}
  a "bcj_$arch.7z" -mf="$filter" -m0=LZMA:d=64k "code/$arch.bin"
done
a bcj2.7z -mf=BCJ2 -m0=LZMA:d=64k code/x86.bin
a delta.7z -mf=Delta:4 -m0=LZMA2:d=64k delta/samples.raw
a deflate.7z -m0=Deflate text/a.txt text/b.txt
a bzip2.7z -m0=BZip2 text/a.txt text/b.txt
a ppmd.7z -m0=PPMd text/a.txt
a ppmd_solid.7z -m0=PPMd:mem=2m:o=32 -ms=on text big
a aes.7z -m0=LZMA2:d=64k -ppassword text/a.txt text/b.txt
a aes_hdr.7z -m0=LZMA2:d=64k -ppassword -mhe=on text/a.txt text/b.txt
a aes_copy.7z -m0=Copy -ppassword text/tiny.txt
rm -f "$OUT"/split.7z.*
"$SZ" a -bd -bso0 -bsp0 -mtc=off -mta=off -m0=LZMA2:d=64k "$OUT/split.7z" -v4k noise/noise.bin text/tiny.txt
# The expected contents: size and SHA-256 of every input file, by path.
find . -type f | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do
  printf '%s %s %s\n' "$f" "$(wc -c < "$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
done > "$OUT/expected.txt"
