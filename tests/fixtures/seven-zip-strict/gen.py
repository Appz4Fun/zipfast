# Copyright (C) 2026 xbmc4lyfe
# SPDX-License-Identifier: RPL-1.5
#
# Unless explicitly acquired and licensed from Licensor under another license,
# the contents of this file are subject to the Reciprocal Public License
# ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
# may not copy or use this file in either source code or executable form,
# except in compliance with the terms and conditions of the RPL.
#
# All software distributed under the RPL is provided strictly on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
# HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
# ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
# rights and limitations under the RPL.

"""Writes the `seven_zip_strict` fixtures: archives 7-Zip 26.06 writes, then altered where 7-Zip's extra end checks
look (a range coder's last bytes, bytes after a stream's end, a ZIP local header field).

    python3 -I gen.py /path/to/7z OUT_DIR

Each fixture's 7-Zip 26.06 `t` verdict is in README.md; tests/seven_zip_strict.rs checks zipfast against it.
"""
import io, os, random, shutil, struct, subprocess, sys, tempfile, zipfile, zlib, bz2

SEVEN, OUT = os.path.abspath(sys.argv[1]), sys.argv[2]
rng = random.Random(20261126)


def text(n):
    return bytes(rng.choice(b"abcdefgh \n") for _ in range(n))


def code(n):
    """x86-like bytes with many E8/E9/Jcc candidates, for BCJ2."""
    b = bytearray()
    while len(b) < n:
        r = rng.random()
        if r < 0.1:
            b += b"\xe8" + bytes(rng.randrange(256) for _ in range(2)) + b"\x00\x00"
        elif r < 0.15:
            b += b"\xe9" + bytes(rng.randrange(256) for _ in range(2)) + b"\x00\x00"
        else:
            b += rng.choice([b"\x89\xc3", b"\x48\x8b", b"\x90", b"\xc3"])
    return bytes(b[:n])


def number(b, i):
    """A 7z header number at b[i]: (value, next index)."""
    first, i, mask, value = b[i], i + 1, 0x80, 0
    for n in range(8):
        if first & mask == 0:
            return value | (first & (mask - 1)) << (8 * n), i
        value |= b[i] << (8 * n)
        i += 1
        mask >>= 1
    return value, i


def encode(v):
    for n in range(8):
        if v < 1 << (7 * (n + 1)):
            return bytes([(0xFF << (8 - n)) & 0xFF | v >> (8 * n)]) + (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
    return b"\xff" + v.to_bytes(8, "little")


def packs(data):
    """The packed streams of a 7z archive written with an uncompressed header (-mhc=off)."""
    offset, size = struct.unpack_from("<QQ", data, 12)
    h = data[32 + offset : 32 + offset + size]
    assert h[:3] == b"\x01\x04\x06", "needs -mhc=off"
    pos, i = number(h, 3)
    count, i = number(h, i)
    assert h[i] == 9
    i += 1
    sizes = []
    for _ in range(count):
        s, i = number(h, i)
        sizes.append(s)
    out, at = [], 32 + pos
    for s in sizes:
        out.append(data[at : at + s])
        at += s
    return out


def repack(data, streams):
    """`data` with its packed streams replaced (sizes in the header and both header CRCs fixed)."""
    offset, size = struct.unpack_from("<QQ", data, 12)
    h = data[32 + offset : 32 + offset + size]
    pos, i = number(h, 3)
    count, i = number(h, i)
    i += 1
    old = 0
    for _ in range(count):
        s, i = number(h, i)
        old += s
    header = h[:3] + encode(pos) + encode(count) + b"\x09" + b"".join(encode(len(s)) for s in streams) + h[i:]
    body = data[32 : 32 + pos] + b"".join(streams) + data[32 + pos + old : 32 + offset]
    start = struct.pack("<QQI", len(body), len(header), zlib.crc32(header))
    return data[:8] + struct.pack("<I", zlib.crc32(start)) + start + body + header


def seven(files, *args):
    d = tempfile.mkdtemp()
    try:
        for name, content in files.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(content)
        out = os.path.join(d, "out.7z")
        cmd = [SEVEN, "a", "-t7z", "-mhc=off", "-mtm=off", "-mtc=off", "-mta=off", out, *args, *files]
        subprocess.run(cmd, cwd=d, check=True, stdout=subprocess.DEVNULL)
        with open(out, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(d)


def verdict(data):
    """7-Zip's `t` error lines for an archive."""
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, "t.7z")
        with open(path, "wb") as f:
            f.write(data)
        run = subprocess.run([SEVEN, "t", "-y", "-p-", path], capture_output=True, text=True)
        return sorted({line for line in run.stdout.splitlines() + run.stderr.splitlines() if line.startswith("ERROR")})
    finally:
        shutil.rmtree(d)


def first_with(want, variants):
    """The first variant 7-Zip reports exactly `want` for (the members' own CRCs pass)."""
    for data in variants:
        if verdict(data) == want:
            return data
    raise SystemExit(f"no variant gives {want}")


def patched(stream, at, value):
    b = bytearray(stream)
    b[at] = value
    return bytes(b)


fixtures = {}
two = {"a.txt": text(1500), "b.txt": text(1500)}
both = two["a.txt"] + two["b.txt"]

lzma = seven(two, "-m0=LZMA", "-ms=on")
(p,) = packs(lzma)
fixtures["lzma.7z"] = lzma
fixtures["lzma-code.7z"] = first_with(
    ["ERROR: Data Error : #0"], (repack(lzma, [patched(p, -1, v)]) for v in range(256) if v != p[-1])
)
fixtures["lzma-tail.7z"] = repack(lzma, [p + b"\x00"])
fixtures["lzma-eos.7z"] = seven(two, "-m0=LZMA:eos", "-ms=on")

lzma2 = seven(two, "-m0=LZMA2", "-ms=on")
(p,) = packs(lzma2)
assert p[-1] == 0
fixtures["lzma2-no-end-marker.7z"] = repack(lzma2, [p[:-1]])
fixtures["lzma2-tail.7z"] = repack(lzma2, [p + b"\x00"])
fixtures["lzma2-chunk-start.7z"] = repack(lzma2, [patched(p, -1, 0xB3)])

ppmd = seven(two, "-m0=PPMd", "-ms=on")
(p,) = packs(ppmd)
fixtures["ppmd.7z"] = ppmd
fixtures["ppmd-code.7z"] = first_with(
    ["ERROR: Data Error : #0"], (repack(ppmd, [patched(p, -1, v)]) for v in range(255, -1, -1) if v != p[-1])
)
fixtures["ppmd-tail.7z"] = repack(ppmd, [p + b"\x00\x01\x02"])
fixtures["ppmd-first-byte.7z"] = repack(ppmd, [patched(p, 0, 1)])

deflate = seven(two, "-m0=Deflate", "-ms=on")
(p,) = packs(deflate)
fixtures["deflate-tail.7z"] = repack(deflate, [p + b"\x00\x01\x02"])
c = zlib.compressobj(9, zlib.DEFLATED, -15)
fixtures["deflate-past-size.7z"] = repack(
    deflate, [c.compress(both) + c.flush(zlib.Z_FULL_FLUSH) + c.compress(b"extra") + c.flush()]
)

deflate64 = seven(two, "-m0=Deflate64", "-ms=on")
(p,) = packs(deflate64)
fixtures["deflate64-tail.7z"] = repack(deflate64, [p + b"\x00\x01\x02"])
# Copy feeding Deflate64, whose stream holds the output in a block that isn't the last, then an empty last block:
# fine on its own, but 7-Zip stops a coder that feeds another at the output's end ("Data Error"), and zipfast checks
# Deflate64 before the Copy coder feeding it, as a check of Copy first would find bytes left ("data after the end")
chain = seven({"a.txt": b"x"}, "-m0=Deflate64", "-m1=Copy")
stored = lambda last, data: bytes([last]) + struct.pack("<HH", len(data), len(data) ^ 0xFFFF) + data
fixtures["deflate64-copy-last-block-empty.7z"] = repack(chain, [stored(0, b"x") + stored(1, b"")])

bzip2 = seven(two, "-m0=BZip2", "-ms=on")
(p,) = packs(bzip2)
fixtures["bzip2-second-stream.7z"] = repack(bzip2, [p + bz2.compress(b"more")])
fixtures["bzip2-two-streams.7z"] = repack(bzip2, [bz2.compress(two["a.txt"]) + bz2.compress(two["b.txt"])])

copy = seven({"a.txt": text(1500)}, "-m0=Copy")
(p,) = packs(copy)
fixtures["copy-tail.7z"] = repack(copy, [p + b"zz"])

bcj2 = seven({"a.bin": code(6000), "b.bin": code(6000) + b"\x90\xe8"}, "-m0=BCJ2", "-m1=LZMA", "-mb0s0:1", "-ms=on")
main, call, jump, rc = packs(bcj2)
fixtures["bcj2.7z"] = bcj2
fixtures["bcj2-call-tail.7z"] = repack(bcj2, [main, call + b"\x00", jump, rc])
fixtures["bcj2-rc-code.7z"] = first_with(
    ["ERROR: Data Error : #0"], (repack(bcj2, [main, call, jump, patched(rc, -1, v)]) for v in range(256) if v != rc[-1])
)
fixtures["bcj2-rc-first-byte.7z"] = repack(bcj2, [main, call, jump, patched(rc, 0, 1)])

folders = seven({"a.txt": text(1500), "b.txt": text(1500), "c.txt": text(1500)}, "-m0=LZMA", "-ms=2f")
s = packs(folders)
fixtures["two-folders-last-tail.7z"] = repack(folders, s[:-1] + [s[-1] + b"\x00"])


def local_header(data, k):
    at = 0
    for _ in range(k):
        name, extra = struct.unpack_from("<HH", data, at + 26)
        at += 30 + name + extra + struct.unpack_from("<I", data, at + 18)[0]
    return at


buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for name in ("f0.txt", "f1.txt", "f2.txt"):
        info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, text(1200))
plain = buf.getvalue()
fixtures["local.zip"] = plain


def zip_patched(field, size, value):
    b = bytearray(plain)
    at = local_header(b, 1) + field
    old = int.from_bytes(b[at : at + size], "little")
    b[at : at + size] = (value(old)).to_bytes(size, "little")
    return bytes(b)


fixtures["local-crc.zip"] = zip_patched(14, 4, lambda v: v ^ 1)
fixtures["local-size.zip"] = zip_patched(22, 4, lambda v: v + 1)
fixtures["local-method.zip"] = zip_patched(8, 2, lambda v: 0)
fixtures["local-descriptor-flag.zip"] = zip_patched(6, 2, lambda v: v | 8)
# with the data descriptor flag set in both, 7-Zip doesn't compare the local CRC and sizes
streamed = bytearray(zip_patched(6, 2, lambda v: v | 8))
cd = streamed.find(b"PK\x01\x02", 0)
while cd != -1:
    if struct.unpack_from("<I", streamed, cd + 42)[0] == local_header(plain, 1):
        streamed[cd + 8 : cd + 10] = (struct.unpack_from("<H", streamed, cd + 8)[0] | 8).to_bytes(2, "little")
    cd = streamed.find(b"PK\x01\x02", cd + 4)
at = local_header(streamed, 1)
streamed[at + 14 : at + 18] = (0x12345678).to_bytes(4, "little")
fixtures["local-streamed-crc.zip"] = bytes(streamed)

os.makedirs(OUT, exist_ok=True)
for name, data in sorted(fixtures.items()):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print(name, len(data))
