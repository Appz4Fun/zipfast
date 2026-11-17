import io, sys, tarfile, gzip
out = sys.argv[1]
def info(fmt):
    t = tarfile.TarInfo("f.txt"); t.size = 2; t.mtime = 1577934245; t.mode = 0o644
    t.uname, t.gname, t.uid, t.gid = "builder", "staff", 1234, 56
    if fmt == tarfile.PAX_FORMAT:
        t.pax_headers = {"atime": "1614834367.5", "ctime": "1600000000.25", "comment": "hi"}
    return t
for name, fmt in [("pax.tar", tarfile.PAX_FORMAT), ("gnu.tar", tarfile.GNU_FORMAT), ("ustar.tar", tarfile.USTAR_FORMAT)]:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        tf.addfile(info(fmt), io.BytesIO(b"x\n"))
        if fmt == tarfile.USTAR_FORMAT:
            d = tarfile.TarInfo("dev"); d.type = tarfile.CHRTYPE; d.devmajor, d.devminor = 4, 7; d.mtime = 1577934245
            tf.addfile(d)
    open(f"{out}/{name}", "wb").write(buf.getvalue())
    if name == "pax.tar":
        open(f"{out}/pax.tgz", "wb").write(gzip.compress(buf.getvalue(), mtime=0))
