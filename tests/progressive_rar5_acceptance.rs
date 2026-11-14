// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//! Original, bounded first-party RAR5 article-loss acceptance. Large runs are explicit.
#[path = "common/rar5_acceptance.rs"]
mod acceptance;
mod common;

#[test]
fn large_geometry_without_payload_creation() {
    acceptance::large_geometry_preflight();
}

#[test]
fn scaled_plain_articles_sparse_and_zero() {
    for fill in [zipfast::progressive::HoleFill::Sparse, zipfast::progressive::HoleFill::Zero] {
        let dir = acceptance::persistent_fast_dir("plain");
        let fixture = acceptance::prepare(&dir, 490_000, 700, false);
        acceptance::exercise(&fixture, fill);
    }
}

#[test]
fn scaled_encrypted_headers_and_strict_replacements() {
    let dir = acceptance::persistent_fast_dir("encrypted");
    let (_, fixture) = acceptance::prepare_pair(&dir, 490_000, 700);
    acceptance::exercise(&fixture, zipfast::progressive::HoleFill::Sparse);
}

#[test]
fn small_cbc_cross_part_padding_header_hole_and_cancel() {
    acceptance::small_boundaries();
}

#[test]
#[ignore = "500 MB preparation requires a separate root correctness-window lease"]
fn prepare_large_fixtures() {
    let root = acceptance::large_root();
    acceptance::prepare_pair(&root, 500_000_000, 700_000);
}

#[test]
#[ignore = "requires prepared immutable 500 MB fixture and root correctness-window lease"]
fn plain_large_acceptance() {
    let fixture = acceptance::load(&acceptance::large_root().join("plain"));
    assert_eq!(fixture.size, 500_000_000);
    acceptance::exercise(&fixture, zipfast::progressive::HoleFill::Sparse);
}

#[test]
#[ignore = "requires prepared immutable 500 MB fixture and root correctness-window lease"]
fn encrypted_large_acceptance() {
    let fixture = acceptance::load(&acceptance::large_root().join("encrypted"));
    assert_eq!(fixture.size, 500_000_000);
    acceptance::exercise(&fixture, zipfast::progressive::HoleFill::Sparse);
}
