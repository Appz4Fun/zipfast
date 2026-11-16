// 7z listings carry 7-Zip-style method strings (as `7z l -slt` prints them), Windows attributes and UTC mtimes.

use std::path::Path;

use zipfast::extract::{self, Entry, MtimeOrigin};

fn list(name: &str) -> Vec<Entry> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/7z-extract").join(name);
    let pw = name.starts_with("aes").then_some("password");
    extract::list_with_password(&path, pw).unwrap()
}

fn method(name: &str) -> String {
    list(name).into_iter().find_map(|e| e.method_name).unwrap()
}

#[test]
fn method_strings_match_7zip() {
    for (file, want) in [
        ("copy.7z", "Copy"),
        ("lzma.7z", "LZMA:6k"),
        ("lzma2.7z", "LZMA2:6k"),
        ("solid.7z", "LZMA2:17"),
        ("bcj_x86.7z", "BCJ LZMA:13"),
        ("bcj_arm64.7z", "ARM64 LZMA:13"),
        ("bcj2.7z", "BCJ2 LZMA:13 LZMA:13:lc0:lp2 LZMA:13:lc0:lp2"),
        ("delta.7z", "Delta:4 LZMA2:13"),
        ("deflate.7z", "Deflate"),
        ("bzip2.7z", "BZip2"),
        ("ppmd.7z", "PPMD:o6:mem17"),
        ("ppmd_solid.7z", "PPMD:o32:mem21"),
        ("aes.7z", "LZMA2:12k 7zAES:19"),
        ("aes_copy.7z", "Copy 7zAES:19"),
    ] {
        assert_eq!(method(file), want, "{file}");
    }
}

#[test]
fn empty_members_and_directories_have_no_method() {
    for e in list("tree.7z") {
        assert_eq!(e.method_name.is_none(), e.dir || e.size == 0, "{}", e.name);
        assert_eq!(e.mtime_origin.is_some(), e.mtime.is_some());
        if e.mtime.is_some() {
            assert_eq!(e.mtime_origin, Some(MtimeOrigin::Utc));
        }
    }
}

#[test]
fn creation_and_access_times_when_stored() {
    // times.7z: 7zz -mtc=on -mta=on; a.txt modified 2020-01-02 03:04:05, accessed 2021-03-04 05:06:07 (both local
    // time, same UTC offset), created whenever the fixture was made (`7z l -slt`: `.5437579` past the second).
    let e = &list("times.7z")[0];
    let mtime = e.mtime.unwrap();
    let (atime, atime_ns) = e.atime.unwrap();
    assert_eq!((atime - mtime, atime_ns), (1_614_834_367 - 1_577_934_245, 0));
    let (ctime, ctime_ns) = e.ctime.unwrap();
    assert!(ctime > atime);
    assert_eq!(ctime_ns, 543_757_900);
    // Archives made without them (gen.sh passes -mtc=off -mta=off) carry neither.
    let e = &list("lzma2.7z")[0];
    assert_eq!((e.ctime, e.atime), (None, None));
}
