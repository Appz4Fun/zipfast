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

//! Every reader in the workspace agrees on directories far larger than the
//! parity fixtures: a real ZIP64 member count, long names, private extras,
//! comments, Unicode Path extras and a self-extractor prefix, each spanning
//! many parser reads. The archives come from the generator behind
//! `examples/zip_directory_bench`, at sizes a test can afford.

#[path = "../examples/zip_directory_bench/shapes.rs"]
mod shapes;

use std::io::Write;

use shapes::{BENCH_SHAPES, COMMENT, LONG_NAME_BYTES, Shape, Written};
use zip_container::{DirectoryParser, Limits, Profile};
use zipfast::zip::Archive;
use zipview::{ZipIndexOpener, ZipReader};

fn build(shape: &Shape) -> (Vec<u8>, Written) {
    let mut bytes = Vec::new();
    let written = shapes::write(shape, &mut bytes).unwrap();
    assert_eq!(written.len, bytes.len() as u64);
    (bytes, written)
}

fn shape(label: &'static str, count: usize) -> Shape {
    Shape { label, count, rich: false, unicode: false, prefix: 0, force_zip64: false }
}

fn slice<'a>(bytes: &'a [u8], range: &std::ops::Range<u64>) -> &'a [u8] {
    &bytes[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()]
}

/// Opens the archive with all four readers and checks each member against the generator.
fn check_readers(shape: &Shape) {
    let (bytes, written) = build(shape);
    let members = &written.members;

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let mut fast = Archive::open(file.path()).unwrap();
    assert_eq!(fast.entries.len(), shape.count, "{}: fast count", shape.label);
    for (index, (entry, member)) in fast.entries.iter().zip(members).enumerate() {
        assert_eq!(entry.name, member.name, "{}: fast name {index}", shape.label);
        assert_eq!(entry.local_at, member.local_at + shape.prefix, "{}: fast offset {index}", shape.label);
        assert_eq!(
            (entry.crc32, entry.size, entry.packed, entry.method),
            (member.crc32, member.payload.len() as u64, member.payload.len() as u64, 0)
        );
    }
    for index in [0, 1, shape.count / 2, shape.count - 1] {
        let mut payload: Vec<u8> = Vec::new();
        fast.read_at(index, None, 1_000, |chunk| {
            payload.extend(chunk);
            Ok(())
        })
        .unwrap();
        assert_eq!(payload, members[index].payload, "{}: fast payload {index}", shape.label);
    }

    let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, Limits::default()).unwrap();
    let mut reads = 0;
    while let Some(range) = parser.next_read().unwrap() {
        reads += 1;
        parser.supply(range.start, slice(&bytes, &range)).unwrap();
    }
    let directory = parser.finish().unwrap();
    assert!(reads >= 1);
    let central = written.directory_at + shape.prefix..written.directory_at + shape.prefix + written.directory_len;
    assert_eq!(directory.directory_range, central, "{}: container directory range", shape.label);
    assert_eq!(directory.entries.len(), shape.count, "{}: container count", shape.label);
    assert_eq!(directory.raw_comment, COMMENT, "{}: container comment", shape.label);
    assert_eq!(directory.zip64_end.is_some(), shape.zip64(), "{}: container ZIP64", shape.label);
    assert_eq!(directory.prefix_shift, shape.prefix, "{}: container prefix", shape.label);
    for (index, (record, member)) in directory.entries.iter().zip(members).enumerate() {
        assert_eq!(record.raw_name.as_ref(), member.raw_name.as_slice(), "{}: container name {index}", shape.label);
        assert_eq!(record.raw_comment.len(), member.comment_len, "{}: container comment {index}", shape.label);
        assert_eq!(
            directory.physical_local_header_offset(index),
            Some(member.local_at + shape.prefix),
            "{}: container offset {index}",
            shape.label
        );
        assert_eq!(record.known.unicode_path.is_some(), shape.unicode, "{}: container unicode {index}", shape.label);
    }

    let view = ZipReader::new(&bytes).unwrap();
    assert_eq!(view.len(), shape.count, "{}: view count", shape.label);
    for (index, (entry, member)) in view.entries().iter().zip(members).enumerate() {
        // zipview ignores Unicode Path extras for names (docs/zip-parser-parity.md), so it reports the raw name.
        assert_eq!(entry.name().as_bytes(), member.raw_name.as_slice(), "{}: view name {index}", shape.label);
        assert_eq!(entry.crc32(), member.crc32, "{}: view crc {index}", shape.label);
        assert_eq!(entry.local_header_offset(), member.local_at, "{}: view offset {index}", shape.label);
    }
    // Duplicate names resolve to the first in central order, as every reader agrees.
    let duplicate = std::str::from_utf8(&members[0].raw_name).unwrap();
    assert_eq!(view.by_name(duplicate).map(|e| e.local_header_offset()), Some(members[0].local_at));
    for index in [1, shape.count - 1] {
        assert_eq!(
            view.read_entry(&view.entries()[index]).unwrap(),
            members[index].payload,
            "{}: view payload {index}",
            shape.label
        );
    }

    let mut opener = ZipIndexOpener::new(bytes.len() as u64);
    while let Some(range) = opener.next_read().unwrap() {
        opener.supply(range.start, slice(&bytes, &range)).unwrap();
    }
    let index = opener.finish().unwrap();
    assert_eq!(index.len(), shape.count, "{}: index count", shape.label);
    for (ordinal, (entry, member)) in index.entries().iter().zip(members).enumerate() {
        assert_eq!(entry.name().as_bytes(), member.raw_name.as_slice(), "{}: index name {ordinal}", shape.label);
        assert_eq!(entry.local_header_offset(), member.local_at, "{}: index offset {ordinal}", shape.label);
    }
}

#[test]
fn short_names_past_the_classic_member_limit_need_zip64() {
    // 70,000 members: past 65,535, so the classic end record holds the sentinel and only ZIP64 gives the count.
    check_readers(&shape("short-zip64-70k", 70_000));
}

#[test]
fn rich_metadata_with_a_self_extractor_prefix() {
    check_readers(&Shape { rich: true, prefix: 8192, ..shape("rich-prefix-3k", 3_000) });
}

#[test]
fn rich_metadata_with_zip64_end_records_below_the_limit() {
    check_readers(&Shape { rich: true, force_zip64: true, ..shape("rich-zip64-3k", 3_000) });
}

#[test]
fn unicode_path_extras_name_members_under_their_unicode_names() {
    check_readers(&Shape { unicode: true, force_zip64: true, ..shape("unicode-zip64-3k", 3_000) });
}

#[test]
fn generator_shapes_match_their_description() {
    let (_, short) = build(&shape("short", 4));
    let names: Vec<&str> = short.members.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["duplicate.bin", "duplicate.bin", "e00000002", "e00000003"]);
    assert_eq!(short.members[0].payload, b"first");
    assert_eq!(short.members[3].payload, 3u32.to_le_bytes());

    let (_, rich) = build(&Shape { rich: true, ..shape("rich", 3) });
    assert_eq!((rich.members[0].extra_len, rich.members[0].comment_len), (0, 0));
    assert_eq!((rich.members[2].extra_len, rich.members[2].comment_len), (196, 148));
    assert_eq!(rich.members[2].raw_name.len(), LONG_NAME_BYTES);

    let (_, unicode) = build(&Shape { unicode: true, ..shape("unicode", 3) });
    assert_eq!(unicode.members[0].raw_name, unicode.members[1].raw_name);
    assert!(unicode.members[2].name.starts_with("üv/00000002-"));
    assert_eq!(unicode.members[2].extra_len, 4 + 5 + unicode.members[2].name.len());

    let prefixed = Shape { prefix: 100, ..shape("prefixed", 2) };
    let (bytes, written) = build(&prefixed);
    assert!(bytes.starts_with(&[b'S'; 100]));
    assert_eq!(written.members[0].local_at, 0, "stored offsets stay relative to the archive");
    assert!(bytes.ends_with(COMMENT));
}

#[test]
fn bench_shapes_are_the_documented_ones() {
    let labels: Vec<(&str, usize, bool)> = BENCH_SHAPES.iter().map(|s| (s.label, s.count, s.zip64())).collect();
    assert_eq!(
        labels,
        [
            ("short-20k", 20_000, false),
            ("rich-prefix-20k", 20_000, false),
            ("short-zip64-200k", 200_000, true),
            ("rich-zip64-200k", 200_000, true),
            ("unicode-zip64-200k", 200_000, true),
        ]
    );
}

#[test]
#[should_panic(expected = "a prefix is not combined with ZIP64")]
fn a_prefixed_zip64_shape_is_refused() {
    build(&Shape { prefix: 1, force_zip64: true, ..shape("bad", 2) });
}
