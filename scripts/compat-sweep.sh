#!/usr/bin/env bash
# Compatibility sweep: build archives with the system's real tools (bsdtar, Info-ZIP zip, ditto, gzip, bzip2, xz,
# zstd, lz4, compress), extract each with a reference tool and with zipfast, and diff the two trees.
#
#   scripts/compat-sweep.sh [WORKDIR]        # default WORKDIR: ${TMPDIR:-/tmp}/zf-compat
#
# Env: ZIPFAST=path/to/zipfast (default: cargo build --release and use target/release/zipfast)
#      BIG=1 also builds the one >4 GiB sparse-member case per family (slow, ~5 GiB of scratch while it runs)
#      REF7Z=dir holding a Linux amd64 `7z` (7-Zip 26.06): builds 7z/zip/tar/xz/wim archives with 7-Zip in Docker
#             (linux/amd64, no network) and uses 7-Zip's own extraction as the reference. Needs docker.
#      RAR4REF=dir with in/ and out/*.xstatus, out/*.sha256 written by UnRAR: compares zipfast's file bytes with them.
# Output: WORKDIR/results.tsv (case, reference tool, status, symptom). Mismatch detail in WORKDIR/log/<case>.txt.
set -u
W=${1:-${TMPDIR:-/tmp}/zf-compat}
W=$(mkdir -p "$W" && cd "$W" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${ZIPFAST:-}" ]; then
  (cd "$HERE" && cargo build --release -q) || exit 1
  ZIPFAST=${CARGO_TARGET_DIR:-$HERE/target}/release/zipfast
fi
SRC=$W/src A=$W/arc X=$W/x LOG=$W/log
chmod -R u+w "$W" 2>/dev/null; rm -rf "$SRC" "$A" "$X" "$LOG" "$W/ref7z"; mkdir -p "$SRC" "$A" "$X" "$LOG"
have() { command -v "$1" >/dev/null 2>&1; }

# ---- source tree with tricky contents ----
mk_tree() {
  local d=$1; mkdir -p "$d/dir/sub" "$d/emptydir"
  printf 'hello\n' > "$d/a.txt"
  : > "$d/empty"
  head -c 300000 /dev/urandom > "$d/dir/random.bin"
  yes 'compressible line of text' | head -c 2000000 > "$d/dir/sub/text.txt"
  chmod 755 "$d/dir/sub/text.txt"; chmod 600 "$d/a.txt"
  ln -s a.txt "$d/link"; ln -s ../a.txt "$d/dir/uplink"; ln -s missing "$d/dangling"
  ln "$d/a.txt" "$d/hard"
  local l100; l100=$(printf 'n%.0s' $(seq 120))
  local l255; l255=$(printf 'm%.0s' $(seq 200))
  printf 'long\n' > "$d/$l100"
  mkdir -p "$d/deep/$l255"; printf 'deeper\n' > "$d/deep/$l255/$l255"
  printf 'utf8\n' > "$d/caf$(printf '\xc3\xa9')-ünï.txt"
  printf 'sparse-ish' > "$d/sparse"; truncate -s 8000000 "$d/sparse"; printf 'end' >> "$d/sparse"
  printf 'x\n' > "$d/xattr.txt"; xattr -w user.test value "$d/xattr.txt" 2>/dev/null || true
  touch -t 200001020304.05 "$d/a.txt" "$d/dir"
}
mk_tree "$SRC/t"
# a separate tree with a non-UTF-8 name (not every tool takes it)
mkdir -p "$SRC/raw"; printf 'latin1\n' > "$SRC/raw/$(printf 'caf\xe9').txt" 2>/dev/null || true
# many entries
mkdir -p "$SRC/many/d"; (cd "$SRC/many/d" && seq 1 70000 | xargs touch)

CASES=$W/cases.tsv; : > "$CASES"
add() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$CASES"; }   # name archive reftool srcdir

# ---- tar family: every format x every filter ----
FILTERS="none gzip bzip2 xz lzma zstd lz4 compress"
for fmt in ustar pax gnutar v7 cpio newc odc xar 7zip zip iso9660 shar; do
  for f in $FILTERS; do
    case $fmt in 7zip|zip|xar|iso9660) [ "$f" = none ] || continue ;; esac
    out="$A/bsdtar-$fmt-$f"
    fl=""; [ "$f" = none ] || fl="--$f"
    case $fmt in newc|odc) opt="--format $fmt" ;; *) opt="--format $fmt" ;; esac
    if (cd "$SRC/t" && bsdtar -c $opt $fl -f "$out" . 2>"$LOG/gen-${fmt}-$f.err"); then
      add "bsdtar-$fmt-$f" "$out" bsdtar t
    fi
  done
done
for fmt in pax gnutar; do
  (cd "$SRC/t" && bsdtar -c --format $fmt -S -f "$A/bsdtar-$fmt-sparse" sparse) && add "bsdtar-$fmt-sparse" "$A/bsdtar-$fmt-sparse" bsdtar t
done
(cd "$SRC/raw" && bsdtar -c --format ustar -f "$A/bsdtar-ustar-rawname" .) && add bsdtar-ustar-rawname "$A/bsdtar-ustar-rawname" bsdtar raw
(cd "$SRC/many" && bsdtar -czf "$A/bsdtar-many.tgz" .) && add bsdtar-many-tgz "$A/bsdtar-many.tgz" bsdtar many

# ---- zip (Info-ZIP) ----
if have zip; then
  (cd "$SRC/t" && zip -qr -y "$A/zip-deflate.zip" .) && add zip-deflate "$A/zip-deflate.zip" unzip t
  (cd "$SRC/t" && zip -qr -y -0 "$A/zip-store.zip" .) && add zip-store "$A/zip-store.zip" unzip t
  (cd "$SRC/t" && zip -qr -y -Z bzip2 "$A/zip-bzip2.zip" .) && add zip-bzip2 "$A/zip-bzip2.zip" unzip t
  (cd "$SRC/t" && zip -qr -y -fz "$A/zip-zip64.zip" .) && add zip-zip64 "$A/zip-zip64.zip" unzip t
  (cd "$SRC/t" && zip -qr -y -P secret "$A/zip-zipcrypto.zip" .) && add zip-zipcrypto "$A/zip-zipcrypto.zip" unzip:secret t
  (cd "$SRC/t" && zip -qr "$A/zip-noy.zip" a.txt link dir) && add zip-follow-links "$A/zip-noy.zip" unzip t
  (cd "$SRC/t" && zip -qr -y -z "$A/zip-comment.zip" a.txt <<<"archive comment") && add zip-comment "$A/zip-comment.zip" unzip t
  (cd "$SRC/t" && zip -q -c "$A/zip-entrycomment.zip" a.txt <<<"entry comment") && add zip-entrycomment "$A/zip-entrycomment.zip" unzip t
  (cd "$SRC/t" && cat dir/sub/text.txt | zip -q - - > "$A/zip-stdin.zip") && add zip-stdin "$A/zip-stdin.zip" unzip t
  (cd "$SRC/t" && cat dir/random.bin | zip -q -fz - - > "$A/zip-stdin64.zip") && add zip-stdin-zip64 "$A/zip-stdin64.zip" unzip t
  (cd "$SRC/t" && zip -qr -y -s 1m "$A/zip-split.zip" .) && add zip-split-s "$A/zip-split.zip" unzip-join t
  (cd "$SRC/raw" && zip -qr "$A/zip-rawname.zip" .) && add zip-rawname "$A/zip-rawname.zip" unzip raw
  (cd "$SRC/many" && zip -qr "$A/zip-many.zip" .) && add zip-many "$A/zip-many.zip" unzip many
  (cd "$SRC/t" && zip -qr -D "$A/zip-nodirs.zip" dir) && add zip-nodirentries "$A/zip-nodirs.zip" unzip t
fi
bsdtar -c --format zip --options zip:compression=store -f "$A/bsdtar-zip-store" -C "$SRC/t" . && add bsdtar-zip-store "$A/bsdtar-zip-store" bsdtar t
cat "$SRC/t/a.txt" | bsdtar -c --format zip -f - -C "$SRC/t" a.txt > "$A/bsdtar-zip-stream" && add bsdtar-zip-stream "$A/bsdtar-zip-stream" bsdtar t
if have ditto; then
  ditto -c -k --sequesterRsrc "$SRC/t" "$A/ditto-rsrc.zip" && add ditto-sequester "$A/ditto-rsrc.zip" ditto t
  ditto -c -k "$SRC/t" "$A/ditto-plain.zip" && add ditto-plain "$A/ditto-plain.zip" ditto t
  ditto -c -k --keepParent "$SRC/t" "$A/ditto-parent.zip" && add ditto-keepparent "$A/ditto-parent.zip" ditto t
fi

# ---- bare compressed files ----
B=$SRC/bare; mkdir -p "$B"; cp "$SRC/t/dir/sub/text.txt" "$B/payload"
for c in gzip bzip2 xz lzma zstd lz4 compress; do
  have $c || continue
  case $c in gzip) e=gz ;; bzip2) e=bz2 ;; xz) e=xz ;; lzma) e=lzma ;; zstd) e=zst ;; lz4) e=lz4 ;; compress) e=Z ;; esac
  mkdir -p "$A/bare-$c"; $c -c < "$B/payload" > "$A/bare-$c/payload.$e" 2>/dev/null && add "bare-$c" "$A/bare-$c/payload.$e" "cat:$c" bare
  if [ "$c" != compress ]; then
    mkdir -p "$A/concat-$c"
    { head -c 1000000 "$B/payload" | $c -c; tail -c +1000001 "$B/payload" | $c -c; } > "$A/concat-$c/payload.$e" && add "concat-$c" "$A/concat-$c/payload.$e" "cat:$c" bare
  fi
done
mkdir -p "$A/gzip-named"; gzip -c -N "$B/payload" > "$A/gzip-named/other.gz" && add gzip-N-name "$A/gzip-named/other.gz" "cat:gzip" bare
mkdir -p "$A/xz-mt"; xz -T4 --block-size=500000 -c "$B/payload" > "$A/xz-mt/payload.xz" && add xz-multiblock "$A/xz-mt/payload.xz" "cat:xz" bare
mkdir -p "$A/zstd-long"; zstd -q --long=27 -c "$B/payload" > "$A/zstd-long/payload.zst" && add zstd-long "$A/zstd-long/payload.zst" "cat:zstd" bare

if [ "${BIG:-0}" = 1 ]; then
  mkdir -p "$SRC/big"; truncate -s 4400000000 "$SRC/big/huge"; printf tail >> "$SRC/big/huge"
  (cd "$SRC/big" && bsdtar -c --format pax --zstd -f "$A/big-pax-zstd" huge) && add big-pax-zstd "$A/big-pax-zstd" bsdtar big
  (cd "$SRC/big" && zip -q -1 "$A/big.zip" huge) && add big-zip "$A/big.zip" unzip big
fi

# ---- 7-Zip in Docker: archive and reference-extract inside the container ----
if [ -n "${REF7Z:-}" ] && have docker; then
  mkdir -p "$A/7z" "$W/ref7z"
  cat > "$W/gen7z.sh" <<'EOS'
set -u; cd /w/src/t; Z=/r/7z
mk() { n=$1; shift; out=/w/arc/7z/$n; $Z a -bd -y -snl "$@" "$out" . >/dev/null 2>&1 || { echo "gen fail $n"; return; }
  mkdir -p /w/ref7z/$n; (cd /w/ref7z/$n && x=$out; [ -f "$out.001" ] && x=$out.001; $Z x -bd -y -snl $PWARG "$x" >/dev/null 2>/w/ref7z/$n.err; echo $? > /w/ref7z/$n.rc); }
PWARG=
mk lzma2.7z -t7z; mk lzma.7z -t7z -m0=lzma; mk ppmd.7z -t7z -m0=ppmd; mk bzip2.7z -t7z -m0=bzip2
mk deflate.7z -t7z -m0=deflate; mk copy.7z -t7z -m0=copy; mk nonsolid.7z -t7z -ms=off; mk solid-e.7z -t7z -ms=e
mk bcj2.7z -t7z -mf=BCJ2; mk delta.7z -t7z -mf=Delta:4; mk arm64.7z -t7z -mf=ARM64; mk mt.7z -t7z -mmt=4 -mx=9
mk zstdless-header-off.7z -t7z -mhc=off
PWARG=-psecret; mk aes.7z -t7z -psecret; mk aes-mhe.7z -t7z -psecret -mhe=on; mk aes-zip.zip -tzip -psecret -mem=AES256
mk zipcrypto.zip -tzip -psecret -mem=ZipCrypto; PWARG=
mk deflate.zip -tzip; mk deflate64.zip -tzip -mm=Deflate64; mk bzip2.zip -tzip -mm=BZip2; mk lzma.zip -tzip -mm=LZMA
mk ppmd.zip -tzip -mm=PPMd; mk store.zip -tzip -mm=Copy; mk zip-utf8.zip -tzip -mcu=on
mk tar.tar -ttar; mk wim.wim -twim
mk split.7z -t7z -v1m
$Z a -bd -y -txz /w/arc/7z/payload.xz /w/src/bare/payload >/dev/null && mkdir -p /w/ref7z/payload.xz && (cd /w/ref7z/payload.xz && $Z x -y /w/arc/7z/payload.xz >/dev/null; echo $? > /w/ref7z/payload.xz.rc)
$Z a -bd -y -tgzip /w/arc/7z/payload.gz /w/src/bare/payload >/dev/null && mkdir -p /w/ref7z/payload.gz && (cd /w/ref7z/payload.gz && $Z x -y /w/arc/7z/payload.gz >/dev/null; echo $? > /w/ref7z/payload.gz.rc)
$Z a -bd -y -tbzip2 /w/arc/7z/payload.bz2 /w/src/bare/payload >/dev/null && mkdir -p /w/ref7z/payload.bz2 && (cd /w/ref7z/payload.bz2 && $Z x -y /w/arc/7z/payload.bz2 >/dev/null; echo $? > /w/ref7z/payload.bz2.rc)
EOS
  docker run --rm --platform linux/amd64 --network none -e TZ=UTC -v "$REF7Z:/r:ro" -v "$W:/w" rust:1-bookworm bash /w/gen7z.sh
  for f in "$A"/7z/*; do
    n=$(basename "$f"); case $n in *.7z.0[0-9][2-9]) continue ;; esac
    rn=${n%.001}; [ -d "$W/ref7z/$rn" ] || continue
    add "7z-$rn" "$f" "dir:$W/ref7z/$rn" t
  done
fi
if [ -n "${RAR4REF:-}" ]; then
  for xs in "$RAR4REF"/out/*.xstatus; do
    grep -q 'status=0' "$xs" || continue
    n=$(basename "$xs" .xstatus); rel=${n#in_}; rel=in/${rel/_//}
    [ -f "$RAR4REF/$rel" ] && add "rar4-$n" "$RAR4REF/$rel" "sha:${xs%.xstatus}.sha256" -
  done
fi

# ---- run ----
python3 -I - "$CASES" "$X" "$LOG" "$ZIPFAST" "$W/results.tsv" "$SRC" <<'PY'
import os, sys, stat, subprocess, hashlib, shutil
cases, X, LOG, ZF, OUT, SRC = sys.argv[1:]
def rm(p):
    subprocess.run(['chmod', '-R', 'u+w', p], capture_output=True); shutil.rmtree(p, ignore_errors=True)
def sh(cmd, **kw): return subprocess.run(cmd, capture_output=True, **kw)
def manifest(root):
    m = {}
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(d, n); rel = os.path.relpath(p, root).encode('utf-8', 'surrogateescape')
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode): v = ('link', os.readlink(p))
            elif stat.S_ISDIR(st.st_mode): v = ('dir',)
            else:
                h = hashlib.sha1()
                with open(p, 'rb') as f:
                    for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
                v = ('file', st.st_size, h.hexdigest()[:12])
            m[rel] = (v, int(st.st_mtime), stat.S_IMODE(st.st_mode))
    return m
def ref(tool, arc, dst):
    if tool == 'bsdtar': return sh(['bsdtar', '-xpf', arc, '-C', dst])
    if tool == 'unzip': return sh(['unzip', '-qo', arc, '-d', dst])
    if tool == 'unzip:secret': return sh(['unzip', '-qo', '-P', 'secret', arc, '-d', dst])
    if tool == 'unzip-join':
        j = dst + '.joined.zip'; r = sh(['zip', '-q', '-s', '0', arc, '--out', j])
        r = sh(['unzip', '-qo', j, '-d', dst]); os.remove(j); return r
    if tool == 'ditto': return sh(['ditto', '-x', '-k', arc, dst])
    if tool.startswith('dir:'):
        d = tool[4:]; rm(dst); shutil.copytree(d, dst, symlinks=True)
        rc = int(open(d + '.rc').read().strip() or 1)
        return subprocess.CompletedProcess([], rc, b'', open(d + '.err', 'rb').read() if os.path.exists(d + '.err') else b'')
    if tool.startswith('sha:'):
        return subprocess.CompletedProcess([], 0, b'', b'')
    if tool.startswith('cat:'):
        c = tool[4:]; name = os.path.basename(arc).rsplit('.', 1)[0]
        with open(os.path.join(dst, name), 'wb') as o: return subprocess.run([c, '-dc', arc], stdout=o, stderr=subprocess.PIPE)
res = open(OUT, 'w')
for line in open(cases):
    name, arc, tool, _ = line.rstrip('\n').split('\t')
    r, z = os.path.join(X, name + '.ref'), os.path.join(X, name + '.zf')
    os.makedirs(r); os.makedirs(z)
    rr = ref(tool, arc, r)
    pw = ['-psecret'] if ('secret' in tool or 'aes' in name or 'zipcrypto' in name) else []
    if 'win-enc' in arc: pw = ['-ptestpw123']
    zr = sh([ZF, 'x', '-y', '-q'] + pw + [arc, z + '/'])
    log = open(os.path.join(LOG, name + '.txt'), 'w')
    log.write(f'ref rc={rr.returncode} {rr.stderr.decode(errors="replace")[:2000]}\nzf rc={zr.returncode} {zr.stderr.decode(errors="replace")[:2000]}{zr.stdout.decode(errors="replace")[:1000]}\n')
    if zr.returncode != 0 and rr.returncode == 0:
        sym = 'zipfast fails: ' + (zr.stderr or zr.stdout).decode(errors='replace').strip().splitlines()[-1][:120] if (zr.stderr or zr.stdout) else 'zipfast fails'
        res.write(f'{name}\t{tool}\tFAIL\t{sym}\n'); res.flush()
    else:
        if tool.startswith('sha:'):
            want = {l.split(None, 1)[1].strip()[2:]: l.split()[0] for l in open(tool[4:]) if l.strip()}
            got = {}
            for d, _, fs in os.walk(z):
                for f in fs:
                    p = os.path.join(d, f)
                    if os.path.islink(p): continue
                    got[os.path.relpath(p, z)] = hashlib.sha256(open(p, 'rb').read()).hexdigest()
            diffs = [f'content {k!r}' for k in want if got.get(k) != want[k]] + [f'extra {k!r}' for k in got if k not in want]
            log.write('\n'.join(diffs) + '\n')
            res.write(f'{name}\t{tool[:3]}\t{"OK" if not diffs else "DIFF"}\t{len(diffs)} diffs; first: {diffs[0][:140] if diffs else ""}\n'); res.flush()
            rm(r); rm(z); continue
        a, b = manifest(r), manifest(z)
        diffs = []
        for k in sorted(set(a) | set(b)):
            if k not in b: diffs.append(f'missing {k!r}'); continue
            if k not in a: diffs.append(f'extra {k!r}'); continue
            (va, ta, ma), (vb, tb, mb) = a[k], b[k]
            if va != vb: diffs.append(f'content {k!r} ref={va} zf={vb}')
            elif va[0] != 'link':
                if abs(ta - tb) > 2: diffs.append(f'mtime {k!r} ref={ta} zf={tb}')
                if ma != mb: diffs.append(f'mode {k!r} ref={ma:o} zf={mb:o}')
        log.write('\n'.join(diffs) + '\n')
        st = 'OK' if not diffs else 'DIFF'
        if rr.returncode != 0: st += f'(ref rc={rr.returncode})'
        kinds = sorted({d.split()[0] for d in diffs})
        res.write(f'{name}\t{tool}\t{st}\t{len(diffs)} diffs: {",".join(kinds)}; first: {diffs[0][:140] if diffs else ""}\n'); res.flush()
    rm(r); rm(z)
PY
column -t -s $'\t' "$W/results.tsv"
