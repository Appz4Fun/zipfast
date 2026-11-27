// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

//! prybar's compat fuzzing: a valid solid, encrypted RAR 5.0 archive holding an empty member
//! (`rar a -mt1 -ma5 -s -ppw esppw.rar t/a t/b t/c`, `t/b` 0 bytes; `eshppw.rar` adds `-hp`). RAR writes no
//! block for the empty member (packed size 0), and the cipher layer took the missing final block for a cut: `t/b`
//! failed as truncated and every member after it lost the solid history. UnRAR 7.30 and 7-Zip 26.06 extract all three.

use std::fs;
use std::path::{Path, PathBuf};
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::session::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar5-solid-enc");

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
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
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        rar4_raw_names: false,
        folder_times: Default::default(),
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

fn sizes(out: &Path) -> Vec<(String, u64)> {
    ["t/a", "t/b", "t/c"]
        .iter()
        .map(|n| (n.to_string(), fs::metadata(out.join(n)).map(|m| m.len()).unwrap_or(u64::MAX)))
        .collect()
}

fn want() -> Vec<(String, u64)> {
    vec![("t/a".into(), 1000), ("t/b".into(), 0), ("t/c".into(), 1000)]
}

#[test]
fn a_solid_encrypted_archive_with_an_empty_member_extracts_on_every_route() {
    for name in ["esppw.rar", "eshppw.rar"] {
        let path = PathBuf::from(FIXTURES).join(name);
        let dir = tempfile::tempdir().unwrap();

        // the whole-archive runner (each member's CRC is checked, keyed)
        let out = dir.path().join("run");
        let summary = extract::run_with_password(&path, &options(&out), Some("pw"), |_| {}).unwrap();
        assert!(summary.errors.is_empty(), "{name}: {:?}", summary.errors);
        assert_eq!(sizes(&out), want(), "{name}");

        // RarSession
        let out = dir.path().join("selected");
        let mut session = RarSession::open(&path, Some("pw"), RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!((summary.files, summary.failed), (3, 0), "{name}: {summary:?}");
        assert_eq!(sizes(&out), want(), "{name}");

        // the progressive session
        let out = dir.path().join("progressive");
        let verified = progressive(&path, &out);
        assert_eq!(verified, 3, "{name}");
        assert_eq!(sizes(&out), want(), "{name}");
    }
}

fn progressive(path: &Path, dest: &Path) -> usize {
    use std::task::{Context, Poll};
    use zipfast::progressive::*;
    let volume = (path.file_name().unwrap().to_owned(), fs::read(path).unwrap().into_boxed_slice());
    let mut opts = ProgressiveOptions::new(options(dest), path.file_name().unwrap().to_owned());
    opts.set_password(Some("pw".into())).unwrap();
    let mut session = ProgressiveSession::from_sealed_memory(vec![volume], opts).unwrap();
    let waker = std::task::Waker::noop();
    let mut verified = 0;
    loop {
        match session.poll_event(&mut Context::from_waker(waker)) {
            Poll::Pending => std::thread::yield_now(),
            Poll::Ready(Ok(None)) => return verified,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => {
                assert!(matches!(outcome, MemberOutcome::Verified(_)), "a member did not verify");
                verified += 1;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(failure)) => panic!("{failure:?}"),
        }
    }
}

/// FeedDecoder, member by member through the solid stream (`next_solid`): the empty member is done and checked, and
/// the member after it decodes on from the history.
#[test]
fn feed_decoder_carries_the_solid_stream_over_an_empty_encrypted_member() {
    use zipfast::map::{ArticleBuffer, FeedDecoder, FeedOptions, MemberMap};
    let bytes = fs::read(PathBuf::from(FIXTURES).join("esppw.rar")).unwrap();
    let map = MemberMap::from_memory(&[&bytes], "esppw.rar", Some("pw")).unwrap();
    assert_eq!(map.members.len(), 3);
    let mut source = ArticleBuffer::new(usize::MAX);
    source.insert(0, 0, &bytes).unwrap();
    let mut d = FeedDecoder::new(&map, 0, FeedOptions::new(Some("pw"))).unwrap();
    for index in 0..3 {
        if index > 0 {
            d = d.next_solid(&map, index, FeedOptions::new(Some("pw"))).unwrap();
        }
        let mut out: Vec<u8> = Vec::new();
        let status = d.run(&mut source, &mut out).unwrap().clone();
        assert!(status.done && status.crc_ok == Some(true), "member {index}: {status:?}");
        assert_eq!(out.len(), [1000, 0, 1000][index], "member {index}");
    }
}
