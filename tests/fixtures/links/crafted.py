# Crafted link archives: escapes, a member under a linked folder, and a hard link to a missing member.
import io, sys, tarfile, zipfile
out = sys.argv[1]

def tar(name, members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for kind, path, extra in members:
            t = tarfile.TarInfo(path)
            t.mtime = 1577934245
            if kind == "file":
                t.size = len(extra)
                tf.addfile(t, io.BytesIO(extra))
                continue
            if kind == "dir":
                t.type = tarfile.DIRTYPE
            elif kind == "sym":
                t.type, t.linkname = tarfile.SYMTYPE, extra
            elif kind == "hard":
                t.type, t.linkname = tarfile.LNKTYPE, extra
            tf.addfile(t)
    open(f"{out}/{name}", "wb").write(buf.getvalue())

tar("escape.tar", [
    ("sym", "up", "../outside"),
    ("sym", "abs", "/etc/passwd"),
    ("dir", "d/", None),
    ("sym", "d/sneak", "x/../../.."),
    ("file", "ok.txt", b"ok\n"),
])
tar("under-link.tar", [
    ("dir", "real/", None),
    ("sym", "ln", "real"),
    ("file", "ln/evil.txt", b"evil\n"),
])
tar("hard-missing.tar", [
    ("hard", "orphan", "nowhere.txt"),
    ("file", "later.txt", b"later\n"),
    ("hard", "early", "later.txt"),
])

def zsym(z, path, target):
    info = zipfile.ZipInfo(path, (2020, 1, 2, 3, 4, 6))
    info.create_system = 3
    info.external_attr = (0o120777 << 16)
    z.writestr(info, target)

with zipfile.ZipFile(f"{out}/escape.zip", "w") as z:
    zsym(z, "up", "../outside")
    zsym(z, "abs", "/etc/passwd")
    z.writestr("ok.txt", b"ok\n")
with zipfile.ZipFile(f"{out}/under-link.zip", "w") as z:
    z.writestr("real/", b"")
    zsym(z, "ln", "real")
    z.writestr("ln/evil.txt", b"evil\n")

# A member under a linked folder in the middle: it alone fails, the ones around it still extract.
tar("under-link-middle.tar", [
    ("file", "a.txt", b"a\n"),
    ("dir", "real/", None),
    ("sym", "ln", "real"),
    ("file", "ln/evil.txt", b"evil\n"),
    ("file", "z.txt", b"z\n"),
])
with zipfile.ZipFile(f"{out}/under-link-middle.zip", "w") as z:
    for path, data in [("a.txt", b"a\n"), ("real/", b"")]:
        z.writestr(zipfile.ZipInfo(path, (2020, 1, 2, 3, 4, 6)), data)
    zsym(z, "ln", "real")
    for path, data in [("ln/evil.txt", b"evil\n"), ("z.txt", b"z\n")]:
        z.writestr(zipfile.ZipInfo(path, (2020, 1, 2, 3, 4, 6)), data)
with zipfile.ZipFile(f"{out}/under-link-folder.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("real/", (2020, 1, 2, 3, 4, 6)), b"")
    zsym(z, "ln", "real")
    for path, data in [("ln/sub/", b""), ("z.txt", b"z\n")]:
        z.writestr(zipfile.ZipInfo(path, (2020, 1, 2, 3, 4, 6)), data)
