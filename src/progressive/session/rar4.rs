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

//! Independent exact-frame admission; no deferred history or archive restart authority.
use super::*;
use crate::rar5::{
    FileHeader, FileWire,
    unpack::rar4::{CoreBinding, CoreFrame},
};
fn invalid() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::InvalidCapability)
}
pub(super) fn core_frame(
    member: MemberId,
    h: &FileHeader,
    legacy: Option<crate::rar5::LegacyCrypt>,
) -> ProgressiveResult<CoreFrame> {
    let raw = h.rar4.ok_or_else(invalid)?;
    if h.rar4_progressive_unsupported(legacy).is_some() || h.method == 0 || h.size_unknown() {
        return Err(invalid());
    }
    h.data_at.checked_add(h.packed_size).ok_or_else(invalid)?;
    Ok(CoreFrame {
        ordinal: member.ordinal,
        packed: h.packed_size,
        unpacked: h.unpacked_size,
        unpack_version: raw.unpack_version,
        method: raw.method,
        dictionary: h.dictionary,
    })
}
pub(super) struct Independent {
    member: MemberId,
    volume: u32,
    source: SourceInfo,
    core: CoreBinding,
    extent: std::ops::Range<u64>,
    data_at: u64,
    crc: Option<u32>,
    witness: recovery::WireSnapshot,
}
impl Independent {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        member: MemberId,
        volume: u32,
        source: SourceInfo,
        core: CoreBinding,
        h: &FileHeader,
        wire: &FileWire,
        witness: recovery::WireSnapshot,
    ) -> Self {
        Self { member, volume, source, core, extent: wire.extent.clone(), data_at: h.data_at, crc: h.crc32, witness }
    }
    pub(super) fn binding(&self) -> CoreBinding {
        self.core
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate(
        &self,
        member: Option<MemberId>,
        volume: u32,
        source: Option<SourceInfo>,
        model: &PhysicalModel,
        witnesses: &[recovery::WireVolume],
        usage: &Usage,
    ) -> ProgressiveResult<()> {
        let current = source.ok_or_else(invalid)?;
        if current.id != self.source.id
            || current.generation != self.source.generation
            || current.length != self.source.length
            || current.extent < self.source.extent
        {
            return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
        }
        let h = model.members.first().ok_or_else(invalid)?;
        let p = model.parts.first().ok_or_else(invalid)?;
        if member != Some(self.member)
            || volume != self.volume
            || model.members.len() != 1
            || model.parts.len() != 1
            || !h.complete
            || h.packed_size != self.core.frame.packed
            || !p.final_part
            || p.volume != volume as usize
            || core_frame(self.member, &h.header, h.wire.legacy.and_then(|w| w.crypt))? != self.core.frame
            || h.wire.extent != self.extent
            || p.wire_extent != self.extent
            || p.data_offset != self.data_at
            || p.packed_size != self.core.frame.packed
            || h.header.crc32 != self.crc
            || p.checks.crc32 != self.crc
            || h.final_checks != Some(p.checks)
            || p.checks.keyed
            || p.checks.blake2sp.is_some()
            || !self.witness.matches_current(witnesses, volume, usage)?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 0, kind];
        bytes.extend(flags.to_le_bytes());
        bytes.extend(((body.len() + 7) as u16).to_le_bytes());
        bytes.extend(body);
        let crc = crate::crc32::hash(&bytes[2..]) as u16;
        bytes[..2].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    fn member(name: &[u8], packed: &[u8], expected: &[u8], version: u8, method: u8, flags: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend((packed.len() as u32).to_le_bytes());
        body.extend((expected.len() as u32).to_le_bytes());
        body.push(3);
        body.extend(crate::crc32::hash(expected).to_le_bytes());
        body.extend(0x50221884u32.to_le_bytes());
        body.extend([version, method]);
        body.extend((name.len() as u16).to_le_bytes());
        body.extend(0o100644u32.to_le_bytes());
        body.extend(name);
        let mut bytes = block(0x74, flags | 0x8000, &body);
        bytes.extend(packed);
        bytes
    }
    fn archive(files: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = b"Rar!\x1a\x07\0".to_vec();
        bytes.extend(block(0x73, 0, &[0; 6]));
        for file in files {
            bytes.extend(file);
        }
        bytes.extend(block(0x7b, 0x4000, &[]));
        bytes
    }
    fn options(dir: &std::path::Path) -> ProgressiveOptions {
        ProgressiveOptions::new(
            crate::extract::Options {
                mode: crate::extract::Mode::Extract,
                dest: dir.to_owned(),
                overwrite: crate::extract::Overwrite::Always,
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
                unix_modes: Default::default(),
                backslashes: Default::default(),
            },
            OsString::from("a.rar"),
        )
    }

    #[test]
    fn c1_existing_witness_snapshot_is_bounded_and_owner_specific() {
        let producer = Usage::new(ProgressiveLimits::default());
        let mut volumes = Vec::new();
        recovery::record_header(&mut volumes, 0, 7, b"header", &producer).unwrap();
        let bytes = std::mem::size_of::<recovery::WireSnapshot>() as u64;
        for (metadata_bytes, source_bookkeeping, resource) in
            [(bytes - 1, 1, Resource::MetadataBytes), (bytes, 0, Resource::SourceBookkeeping)]
        {
            let usage = Usage::new(ProgressiveLimits { metadata_bytes, source_bookkeeping, ..Default::default() });
            let error = recovery::WireSnapshot::capture_current(&volumes, 0, &usage).err().unwrap();
            assert!(matches!(error.kind, FailureKind::Limit { resource: got, .. } if got == resource));
        }
        let usage =
            Usage::new(ProgressiveLimits { metadata_bytes: bytes, source_bookkeeping: 2, ..Default::default() });
        let snapshot = recovery::WireSnapshot::capture_current(&volumes, 0, &usage).unwrap();
        assert!(snapshot.matches_current(&volumes, 0, &usage).unwrap());
        assert!(matches!(
            snapshot.matches_current(&volumes, 0, &usage).unwrap_err().kind,
            FailureKind::Limit { resource: Resource::SourceBookkeeping, .. }
        ));
        assert!(matches!(
            usage.charge(Resource::MetadataBytes, 1).unwrap_err().kind,
            FailureKind::Limit { resource: Resource::MetadataBytes, .. }
        ));
        let mut foreign = Vec::new();
        recovery::record_header(&mut foreign, 0, 7, b"header", &producer).unwrap();
        assert!(!snapshot.matches_current(&foreign, 0, &producer).unwrap());
        assert!(!snapshot.matches_current(&volumes, 1, &producer).unwrap());
        recovery::record_header(&mut volumes, 0, 13, b"later", &producer).unwrap();
        assert!(!snapshot.matches_current(&volumes, 0, &producer).unwrap());
    }
    #[test]
    fn c1_native_short_write_and_failed_write_keep_output_authority() {
        for fail in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let bytes = archive(&[member(
                b"one",
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/rar4-lz/new-match-repeat-last.packed"
                )),
                b"AAAAAAA",
                29,
                0x33,
                0,
            )]);
            let mut s = ProgressiveSession::from_sealed_memory(
                vec![("a.rar".into(), bytes.into_boxed_slice())],
                options(dir.path()),
            )
            .unwrap();
            crate::output::OWNED_STAGE_FAULT.with(|slot| {
                *slot.borrow_mut() =
                    Some((crate::output::OwnedOperation::Write, if fail { Err(libc::ENOSPC) } else { Ok(Some(1)) }))
            });
            let mut done = false;
            for _ in 0..10000 {
                match s.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
                    Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                        assert!(fail);
                        assert!(
                            matches!(failure.kind,FailureKind::Output{operation:OutputOperation::Write,ref cause} if cause.raw_os_error()==Some(libc::ENOSPC))
                        );
                        assert_eq!(failure.context.output_range.as_ref().unwrap().completed, 0);
                        done = true;
                        break;
                    }
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                        outcome: MemberOutcome::Verified(v),
                        ..
                    }))) => {
                        assert!(!fail);
                        assert_eq!(v.inner_size(), 7);
                        done = true;
                        break;
                    }
                    Poll::Ready(Err(e)) => panic!("{e:?}"),
                    _ => {}
                }
            }
            assert!(done);
            if fail {
                assert!(!dir.path().join("one").exists());
            } else {
                assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), b"AAAAAAA");
            }
            crate::output::OWNED_STAGE_FAULT.with(|slot| assert!(slot.borrow().is_none()));
        }
    }
    #[test]
    fn c1_witness_and_foreign_codec_binding_cannot_publish() {
        for mutation in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let bytes = archive(&[member(
                b"one",
                include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/literal-a.packed")),
                b"A",
                29,
                0x33,
                0,
            )]);
            let mut s = ProgressiveSession::from_sealed_memory(
                vec![("a.rar".into(), bytes.into_boxed_slice())],
                options(dir.path()),
            )
            .unwrap();
            let mut started = false;
            for _ in 0..1000 {
                match s.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => {
                        started = true;
                        break;
                    }
                    Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                        panic!("terminated before MemberStarted: {failure:?}")
                    }
                    Poll::Ready(Err(e)) => panic!("failed before MemberStarted: {e:?}"),
                    Poll::Ready(Ok(None)) => panic!("EOF before MemberStarted"),
                    _ => {}
                }
            }
            assert!(started, "MemberStarted not observed within 1000 setup polls");
            match mutation {
                0 => s.rar4_independent.as_mut().unwrap().core.member_seq += 1,
                1 => recovery::record_header(&mut s.witnesses, s.volume, 999, b"new header", &s.usage).unwrap(),
                _ => {
                    let mut foreign = Vec::new();
                    recovery::record_header(&mut foreign, s.volume, 0, b"foreign header", &s.usage).unwrap();
                    s.rar4_independent.as_mut().unwrap().witness =
                        recovery::WireSnapshot::capture_current(&foreign, s.volume, &s.usage).unwrap();
                }
            }
            let mut refused = false;
            for _ in 0..1000 {
                match s.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
                    Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. })))
                    | Poll::Ready(Err(failure)) => {
                        assert!(matches!(failure.kind, FailureKind::InvalidCapability));
                        refused = true;
                        break;
                    }
                    _ => {}
                }
            }
            assert!(refused);
            assert!(!dir.path().join("one").exists());
        }
    }
    #[test]
    fn c1_short_native_prefix_survives_later_write_limit() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = archive(&[member(
            b"one",
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/new-match-repeat-last.packed")),
            b"AAAAAAA",
            29,
            0x33,
            0,
        )]);
        let mut opts = options(dir.path());
        opts.artifact_aftermath = ArtifactAftermath::RetainProvisional;
        opts.limits.output_write_bytes = 7;
        let mut s =
            ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), bytes.into_boxed_slice())], opts).unwrap();
        crate::output::OWNED_STAGE_FAULT
            .with(|slot| *slot.borrow_mut() = Some((crate::output::OwnedOperation::Write, Ok(Some(1)))));
        for _ in 0..10000 {
            if let Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, artifact, .. }))) =
                s.poll_event(&mut Context::from_waker(std::task::Waker::noop()))
            {
                assert!(matches!(failure.kind, FailureKind::Limit { resource: Resource::OutputWriteBytes, .. }));
                assert_eq!(failure.context.inner_offset, Some(1));
                let mut artifact = artifact.unwrap();
                let mut byte = [0];
                assert!(matches!(artifact.read_at(0, &mut byte).unwrap(), ArtifactRead::Filled { count: 1 }));
                assert_eq!(byte, [b'A']);
                assert!(!dir.path().join("one").exists());
                return;
            }
        }
        panic!("no terminal failure")
    }
}
