# WP-B3: long RAR passwords

Status: merged. Branch rar-long-password. Worktree /Users/allen/git.xbmc4lyfe/zipfast-b3. PR: 264.

Done: experiments (rar 7.20 for RAR5, rar 6.24 for RAR4 (7.x cannot write RAR4), unrar 7.30 mac + Linux docker);
findings in docs/rar-passwords.md (truncate to 127 characters, rar truncates too, characters not bytes/units);
truncation in src/crypto.rs for RAR5 and RAR4 (data + header); fixtures + tests/rar_long_password.rs.

Extra fixes found by the fixtures: (1) RAR 3.x key derivation SHA-1 rewrites its message (zipfast could not open
RAR4 passwords of 29+ chars at all); (2) RAR4 hashes a non-BMP character as its low 16 bits, not a surrogate pair.
Decision: followed the binaries for (2); WinRAR (Windows) archives with astral RAR4 passwords may not open.

Tests: cargo test --release --test rar_long_password; cargo test --lib crypto; cargo test --test kdf_raw_passwords.
Two lib tests that used 4096-char passwords were rewritten (truncation makes the old ceiling case unreachable).
Left: nothing.
