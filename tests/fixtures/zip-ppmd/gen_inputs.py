# The PPMd fixture inputs: 150000 bytes of word salad (enough to fill a 1 MiB model and make it restart or cut
# off) and a small repetitive text.
import random, sys
d = sys.argv[1]
r = random.Random(98)
words = ["".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(r.randint(2, 9))) for _ in range(3000)]
out, size = [], 0
while size < 700_000:
    w = r.choice(words) + r.choice(["", " ", " ", " ", ", ", ". ", "\n"])
    out.append(w)
    size += len(w)
open(f"{d}/w150.txt", "wb").write("".join(out)[:700_000].encode()[:150_000])
open(f"{d}/small.txt", "wb").write(b"hello ppmd\n" * 50)
