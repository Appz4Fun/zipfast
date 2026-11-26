//! RAR passwords are cut to their first 127 characters, as `rar` and UnRAR do: a candidate opens an archive
//! exactly when its first 127 characters equal the password's first 127. Expectations recorded by running UnRAR
//! 7.30 on these fixtures (`tests/fixtures/rar-long-password/README.md`, `docs/rar-passwords.md`).

use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar-long-password")
}

fn opts(dest: &Path) -> Options {
    Options {
        mode: Mode::Test,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: false,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        salvage_truncated_zip: false,
    }
}

fn opens(archive: &str, password: &str) -> bool {
    let tmp = tempfile::tempdir().unwrap();
    match extract::run_with_password(&dir().join(archive), &opts(tmp.path()), Some(password), |_| {}) {
        Ok(summary) => {
            if !summary.errors.is_empty() {
                eprintln!("{archive}: {:?}", summary.errors);
            }
            summary.errors.is_empty() && summary.files == 1
        }
        Err(e) => {
            eprintln!("{archive}: {e}");
            false
        }
    }
}

fn prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Every archive of one password: candidates of 125 to 128 characters (and the whole password) open it exactly
/// when their first 127 characters match.
fn check(id: &str) {
    let pw = std::fs::read_to_string(dir().join(format!("pw{id}.txt"))).unwrap();
    let len = pw.chars().count();
    for kind in ["5-p", "5-hp", "4-p", "4-hp"] {
        let archive = if id.chars().all(|c| c.is_ascii_digit()) {
            format!("a{kind}-{id}.rar")
        } else {
            format!("u{kind}-{id}.rar")
        };
        let mut tries: Vec<usize> = [125, 126, 127, 128, len].into_iter().filter(|&k| k <= len).collect();
        tries.dedup();
        for k in tries {
            let cand = prefix(&pw, k);
            let want = prefix(&cand, 127) == prefix(&pw, 127);
            assert_eq!(opens(&archive, &cand), want, "{archive}: first {k} of {len} characters");
        }
    }
}

#[test]
fn ascii_126() {
    check("126");
}
#[test]
fn ascii_127() {
    check("127");
}
#[test]
fn ascii_128() {
    check("128");
}
#[test]
fn ascii_129() {
    check("129");
}
#[test]
fn ascii_200() {
    check("200");
}
#[test]
fn two_byte_characters_count_as_one() {
    check("e");
    // 127 bytes of the 140-byte password is fewer than 127 characters: refused, as UnRAR does.
    let pw = std::fs::read_to_string(dir().join("pwe.txt")).unwrap();
    let bytes = &pw.as_bytes()[..127];
    let cut = String::from_utf8_lossy(bytes).into_owned();
    assert!(!opens("u5-p-e.rar", &cut));
    assert!(!opens("u4-hp-e.rar", &cut));
}
#[test]
fn astral_characters_count_as_one() {
    check("j");
}
/// RAR 3.x derives its key from a SHA-1 that rewrites the message it hashes, which shows from 29 characters up
/// (a UTF-16 message of 64 bytes with the salt): 40 characters, below the 127 limit.
#[test]
fn rar4_passwords_over_28_characters_below_the_limit() {
    let pw = std::fs::read_to_string(dir().join("pw40.txt")).unwrap();
    assert!(opens("mid4-p-40.rar", &pw));
    assert!(opens("mid4-hp-40.rar", &pw));
    assert!(!opens("mid4-p-40.rar", &pw[..39]));
    assert!(opens("short4-p-abc.rar", "abc"));
}
