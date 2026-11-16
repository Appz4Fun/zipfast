# Writes the inputs the Deflate64 fixtures are made from. Usage: python3 -I gen_inputs.py OUTDIR
import os
import random
import sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
rng = random.Random(64)


def write(name, data):
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)


# A 40000-byte random block twice: the first copy does not compress (stored blocks), the second is one match
# 40000 bytes back (distance codes 30/31).
block = bytes(rng.getrandbits(8) for _ in range(40000))
write("far.bin", block + block)
# Long runs. 7-Zip caps Deflate64 matches at 257 bytes, so length code 285 is covered by hand-built unit tests.
write("runs.bin", b"A" * 100000 + b"xyz" * 7 + bytes(70000) + b"B" * 300 + b"0123456789" * 3000)
# Too short for a dynamic block's header to pay off: a fixed block.
write("small.txt", b"hello hello hello\n")
# Text: dynamic blocks.
words = [b"archive", b"deflate", b"window", b"member", b"stream", b"block", b"length", b"distance", b"code"]
write("text.txt", b" ".join(rng.choice(words) for _ in range(1500)) + b"\n")
