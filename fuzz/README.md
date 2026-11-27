<!--
Copyright (C) 2026 xbmc4lyfe
SPDX-License-Identifier: RPL-1.5

Unless explicitly acquired and licensed from Licensor under another license,
the contents of this file are subject to the Reciprocal Public License
("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
may not copy or use this file in either source code or executable form,
except in compliance with the terms and conditions of the RPL.

All software distributed under the RPL is provided strictly on an "AS IS"
basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
rights and limitations under the RPL.
-->

# zipfast fuzz harness

cargo-fuzz targets for the whole-archive entry points (`extract_rar4`, `extract_rar5`, `extract_zip`, `extract_7z`,
`probe`, `progressive_rar`, `rar5_crypt_record`, `fuzz_map_feed`, `fuzz_feed_holes`). This crate is outside the
workspace and needs nightly.

## Seeds

The corpus and seeds are gitignored. From the repo root:

    python3 fuzz/gen_seeds.py

It writes `fuzz/seeds/<target>/` for every target from `tests/fixtures`: archives with option bytes for the extract
targets, format/volume head bytes for the two feed targets, and small RAR5 encryption records (KDF count lg2 <= 15, so
a derivation is fast) for `rar5_crypt_record`. `cargo fuzz run` exits when a target's seed directory is missing.

    cd fuzz
    cargo +nightly fuzz run <target> corpus/<target> seeds/<target> -- -max_total_time=60

## Build farm (GCE hosts)

cargo-fuzz there defaults to `x86_64-unknown-linux-musl`, where ASan fails. Always pass the host triple:

    cargo +nightly fuzz run --target "$(rustc -vV | sed -n 's/host: //p')" <target> corpus/<target> seeds/<target>

The same flag goes on `cargo fuzz build`.

## Scratch files

Targets extract under `/dev/shm/zf-fuzz-<pid>/`. Extraction can leave read-only entries; the harness cleanup
(`drive::remove_tree`) restores the owner's write bit (and rwx on directories) before removing. A leftover empty
`zf-fuzz-<pid>` directory per process is harmless.
