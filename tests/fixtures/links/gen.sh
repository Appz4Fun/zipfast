#!/bin/sh
# Regenerates the link fixtures: tests/fixtures/links/gen.sh /path/to/7zz
# Real archivers (bsdtar, Info-ZIP zip -y, ditto, 7zz -snl) over one tree; crafted cases come from crafted.py.
set -eu
SZ=$1
OUT=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
mkdir -p tree/dir
printf 'hello\n' > tree/dir/file.txt
ln -s dir/file.txt tree/ln_file
ln -s dir tree/ln_dir
ln -s ln_file tree/chain
ln tree/dir/file.txt tree/hard.txt
find tree -exec touch -h -t 202001020304.05 {} +
cd tree
export COPYFILE_DISABLE=1
bsdtar --uid 1000 --gid 1000 --uname builder --gname builder -cf "$OUT/bsdtar.tar" dir ln_file ln_dir chain hard.txt
gzip -9nc "$OUT/bsdtar.tar" > "$OUT/bsdtar.tgz"
rm -f "$OUT/infozip.zip" "$OUT/7z.7z"
zip -qry -X "$OUT/infozip.zip" dir ln_file ln_dir chain
ditto -c -k --norsrc --noextattr --noacl . "$OUT/ditto.zip"
"$SZ" a -bso0 -bsp0 -snl -mx=1 "$OUT/7z.7z" dir ln_file ln_dir chain
python3 -I "$OUT/crafted.py" "$OUT"
