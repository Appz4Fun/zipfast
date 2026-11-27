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
print(n, "seeds")
