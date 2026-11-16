#!/usr/bin/env python3
"""Writes the deterministic input files the 7z extraction fixtures are made from (see README.md)."""
import os
import random
import struct
import sys

out = sys.argv[1]
rng = random.Random(7)


def put(name, data, mode=0o644):
    path = os.path.join(out, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def text(n, seed):
    r = random.Random(seed)
    words = b"alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho".split()
    parts = []
    size = 0
    while size < n:
        w = r.choice(words)
        parts.append(w)
        size += len(w) + 1
    return b" ".join(parts)[:n]


def code(arch, n, seed):
    """Bytes with plenty of branch instructions for `arch`, so the branch filter has work to do."""
    r = random.Random(seed)
    b = bytearray()
    while len(b) < n:
        pick = r.random()
        if arch == "x86":
            if pick < 0.3:
                b += bytes([0xE8]) + struct.pack("<i", r.randint(-4000, 4000))
            elif pick < 0.4:
                b += bytes([0xE9]) + struct.pack("<i", r.randint(-4000, 4000))
            elif pick < 0.45:
                b += bytes([0x0F, 0x84]) + struct.pack("<i", r.randint(-4000, 4000))
            else:
                b += bytes(r.choice([0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0xC3, 0x90]) for _ in range(3))
        elif arch == "arm":
            word = (r.randint(0, 0x3FF) & 0xFFFFFF) | (0xEB << 24) if pick < 0.4 else r.choice([0xE1A00000, 0xE3A00001, 0xE12FFF1E])
            b += struct.pack("<I", word)
        elif arch == "armt":
            if pick < 0.4:
                off = r.randint(0, 0x3FFFFF)
                b += struct.pack("<HH", 0xF000 | ((off >> 11) & 0x7FF), 0xF800 | (off & 0x7FF))
            else:
                b += struct.pack("<HH", 0x4770, 0x2001)
        elif arch == "arm64":
            if pick < 0.3:
                b += struct.pack("<I", 0x94000000 | r.randint(0, 0x3FFF))
            elif pick < 0.45:
                rd = r.randint(0, 30)
                imm = r.randint(0, 0xFFF)
                b += struct.pack("<I", 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd)
            else:
                b += struct.pack("<I", r.choice([0xD503201F, 0xD65F03C0, 0xAA0103E0]))
        elif arch == "ppc":
            word = 0x48000001 | (r.randint(0, 0xFFFF) << 2) if pick < 0.4 else r.choice([0x60000000, 0x4E800020, 0x7C0802A6])
            b += struct.pack(">I", word)
        elif arch == "sparc":
            word = 0x40000000 | r.randint(0, 0x3FFF) if pick < 0.4 else r.choice([0x01000000, 0x81C3E008, 0x9DE3BF98])
            b += struct.pack(">I", word)
        elif arch == "ia64":
            bundle = bytearray(r.getrandbits(8) for _ in range(16))
            if pick < 0.5:
                bundle[0] = (bundle[0] & 0xE0) | 0x16  # template with a branch slot
                # opcode 5 in bits 37..40 of slot 2, btype 0
                slot_bits = 5 + 41 * 2
                bits = int.from_bytes(bundle, "little")
                slot = (bits >> slot_bits) & ((1 << 41) - 1)
                slot &= ~(0xF << 37)
                slot |= 5 << 37
                slot &= ~(7 << 6)
                bits &= ~(((1 << 41) - 1) << slot_bits)
                bits |= slot << slot_bits
                bundle = bytearray(bits.to_bytes(16, "little"))
            b += bundle
    return bytes(b[:n])


put("text/a.txt", text(6000, 1))
put("text/b.txt", text(3000, 2))
put("text/tiny.txt", b"hello 7z\n")
put("text/run.sh", b"#!/bin/sh\necho hi\n", 0o755)
for arch in ["x86", "arm", "armt", "arm64", "ppc", "sparc", "ia64"]:
    put(f"code/{arch}.bin", code(arch, 8192, arch))
# 16-bit samples for Delta.
put("delta/samples.raw", b"".join(struct.pack("<hh", int(1000 * ((i % 50) - 25)), i % 300) for i in range(2048)))
put("noise/noise.bin", bytes(rng.getrandbits(8) for _ in range(10000)))
# A larger compressible file for the solid / cancellation tests.
put("big/one.txt", text(50_000, 3))
put("big/two.txt", text(50_000, 4))
os.makedirs(os.path.join(out, "tree/emptydir"), exist_ok=True)
put("tree/sub/file.txt", text(500, 5))
put("tree/empty.txt", b"")
