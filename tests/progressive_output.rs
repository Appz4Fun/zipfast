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

use std::{
    fs,
    io::Write,
    task::{Context, Waker},
};
use zipfast::progressive::{FailureKind, ImmutableFileSource, RangeRead, RangeSource};

#[test]
fn source_growth_is_change_for_immutable_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    fs::write(&path, b"abc").unwrap();
    let mut source = ImmutableFileSource::open(&path).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = [0; 8];
    assert_eq!(source.read_at(1, &mut buf, &mut cx).unwrap(), RangeRead::Filled { count: 2 });
    assert_eq!(&buf[..2], b"bc");
    fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"d").unwrap();
    assert!(matches!(source.read_at(0, &mut buf, &mut cx).unwrap_err().kind, FailureKind::SourceChanged));
}

#[test]
fn source_path_rebound_during_wait() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    fs::write(&path, b"original").unwrap();
    let mut source = ImmutableFileSource::open(&path).unwrap();
    fs::rename(&path, dir.path().join("old")).unwrap();
    fs::write(&path, b"rebound!").unwrap();
    let mut buf = [0; 8];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(source.read_at(0, &mut buf, &mut cx).unwrap_err().kind, FailureKind::SourceChanged));
    assert_eq!(fs::read(&path).unwrap(), b"rebound!");
}
