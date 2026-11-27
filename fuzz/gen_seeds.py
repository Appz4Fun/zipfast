#!/usr/bin/env python3
"""Seed the zipfast fuzz corpora from tests/fixtures (and the zipview seeds). Run from the repo root:
python3 fuzz/gen_seeds.py. Each seed is two option bytes (options, flags) then the archive; flags bit 0 supplies a
password, so every fixture is added both ways."""
import os, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent
FIX = ROOT.parent / "tests" / "fixtures"
MAX = 64 * 1024
MAGIC = {
    "extract_rar4": b"Rar!\x1a\x07\x00",
    "extract_rar5": b"Rar!\x1a\x07\x01\x00",
    "extract_zip": b"PK\x03\x04",
    "extract_7z": b"7z\xbc\xaf\x27\x1c",
}
files = [p for p in FIX.rglob("*") if p.is_file() and p.stat().st_size <= MAX]
files += [p for p in (ROOT.parent / "crates/zipview/fuzz/seeds").glob("*.zip")]
n = 0
for target, magic in MAGIC.items():
    out = ROOT / "seeds" / target
    out.mkdir(parents=True, exist_ok=True)
    for p in files:
        data = p.read_bytes()
        if not data.startswith(magic):
            continue
        for flags in (0, 1, 2):
            (out / f"{p.name}.{flags}").write_bytes(bytes([0x80 if flags == 0 else 0x08, flags]) + data)
            n += 1
# progressive and probe take any RAR seed
for target, pre in (("progressive_rar", None), ("probe", None)):
    out = ROOT / "seeds" / target
    out.mkdir(parents=True, exist_ok=True)
    for p in files:
        data = p.read_bytes()
        for magic in (MAGIC["extract_rar4"], MAGIC["extract_rar5"], MAGIC["extract_7z"], MAGIC["extract_zip"]):
            if data.startswith(magic) and (target == "probe" or magic.startswith(b"Rar!")):
                flags = 4 if magic == MAGIC["extract_rar4"] else 0
                if target == "probe":
                    (out / f"{p.name}.p").write_bytes(b"\x01" + data + data[-512:])
                else:
                    (out / f"{p.name}.p").write_bytes(bytes([0x80, flags | 1]) + data)
                    (out / f"{p.name}.s").write_bytes(bytes([0x80, flags | 2]) + data)
                n += 1

# fuzz_map_feed / fuzz_feed_holes: byte 0 picks the format (head % 3: rar, 7z, zip) and the volume count
# ((head >> 6) + 1), then the archive.
FEED_MAGIC = [
    (0, (MAGIC["extract_rar4"], MAGIC["extract_rar5"])),
    (1, (MAGIC["extract_7z"],)),
    (2, (MAGIC["extract_zip"],)),
]


def feed_head(fmt, nvol):
    for low in range(64):
        h = ((nvol - 1) << 6) | low
        if h % 3 == fmt:
            return h


for target in ("fuzz_map_feed", "fuzz_feed_holes"):
    out = ROOT / "seeds" / target
    out.mkdir(parents=True, exist_ok=True)
    for p in files:
        data = p.read_bytes()
        for fmt, magics in FEED_MAGIC:
            if any(data.startswith(m) for m in magics):
                for nvol in (1, 2):
                    (out / f"{p.name}.{nvol}").write_bytes(bytes([feed_head(fmt, nvol)]) + data)
                    n += 1

# rar5_crypt_record: a RAR5 encryption record body (version vint 0, flags vint, KDF count byte, 16-byte salt, then an
# optional 16-byte IV and a 12-byte password check). The target wraps the first 64 bytes in a HEAD_CRYPT block; the
# rest follows as the archive body. Counts stay at lg2 <= 15 so each derivation is fast.
out = ROOT / "seeds" / "rar5_crypt_record"
out.mkdir(parents=True, exist_ok=True)
salt = bytes(range(16))
iv = bytes(range(0x40, 0x50))
check = bytes(range(0x80, 0x8C))
end_block = bytes.fromhex("0b0000000001050000")  # not a valid CRC; only a plausible trailing block
for count in (0, 4, 10, 15):
    for flags in (0, 1, 3):
        rec = bytes([0, flags, count]) + salt
        for name, body in (("bare", rec), ("iv", rec + iv), ("check", rec + check), ("iv_check", rec + iv + check)):
            (out / f"{name}.c{count}.f{flags}").write_bytes(body)
            (out / f"{name}.c{count}.f{flags}.tail").write_bytes(body.ljust(64, b"\0") + end_block)
            n += 2
print(n, "seeds")
