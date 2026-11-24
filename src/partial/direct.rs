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

//! Persistent partials created straight from a member map, without a progressive session: the output of a
//! [`crate::map::FeedDecoder`] (or any other writer of member plaintext) kept durably with holes, group commits and
//! a restart.
use super::*;
use crate::map::{CipherParams, FeedSink, MapFormat, MemberMap};
use crate::progressive::{ProgressiveLimits, ProtectionDeclaration, Usage, native::NativeProtection};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// How [`DirectPartials`] creates and finds its members' partials.
pub struct DirectOptions {
    /// Binds every member key to the caller's job and archive, as [`PartialOptions::binding`] does.
    pub binding: ArchiveBinding,
    /// Outputs are created under this root, at the member's sanitized archive path (see [`DirectPartials::open`]).
    pub output_root: PathBuf,
    /// One state bundle per member is created in this directory.
    pub state_dir: PathBuf,
    pub naming: PartialNaming,
    /// Limits shared by every member of the set: `open_partials` and `open_files` count all its live handles
    /// together. [`PartialLimits::for_members`] sizes them for a set.
    pub limits: PartialLimits,
    /// Memory, verification and KDF budgets shared by the set; `read_chunk` bounds the reads of a reopen rehash.
    pub progressive_limits: ProgressiveLimits,
    pub anchors: Arc<dyn StateAnchorStore>,
    pub control: SessionControl,
    /// The set's volumes and other inputs, `Complete`: no output or state bundle may be one of them.
    pub protection: ProtectionDeclaration,
    /// The password of an encrypted set. Needed only to verify RAR 5.0 members whose checks are keyed with it; it
    /// is never stored.
    pub password: Option<String>,
}

/// Whether [`DirectPartials::open`] created the member's partial or found it from an earlier run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectOrigin {
    /// Created now, at full size, with nothing written.
    Created,
    /// Created by an earlier run (its anchor was in the store): reopened, its known output rehashed.
    Adopted,
}

/// A member's partial from [`DirectPartials::open`].
pub struct DirectMember {
    pub file: PartialFile,
    pub key: MemberKey,
    pub origin: DirectOrigin,
}

/// Creates persistent partials for the members of a [`MemberMap`] directly, without a progressive session or
/// reading any header again, and finds them again after a restart.
///
/// A member's partial is born at full size with its whole output unknown: nothing is recorded for that, so a
/// member of any size costs the same small genesis transaction. Output is then written at output offsets
/// (through [`DirectSink`], [`PartialFile::fill`], [`PartialFile::fill_writer`] or [`PartialFile::fill_from`]),
/// grouped into durable commits as extraction writes are, and [`PartialFile::poll_verify`] judges the member's
/// own checks (the map's CRC32 and BLAKE2sp) once every byte is known. See `docs/persistent-partials.md`
/// ("Partials from a member map").
pub struct DirectPartials {
    options: DirectOptions,
    usage: Usage,
    exclusions: Arc<PartialExclusions>,
    /// Hash keys derived for keyed RAR 5.0 checks, by KDF count and salt: members of a set usually share them.
    hash_keys: Mutex<Vec<(u8, [u8; 16], MemberKeys)>>,
}

const IDENTITY_DOMAIN: &[u8] = b"zipfast/direct/member/v1\0";

fn container(format: MapFormat) -> u8 {
    match format {
        MapFormat::Zip => 1,
        MapFormat::Rar4 => 4,
        MapFormat::Rar5 => 5,
        MapFormat::SevenZip => 7,
    }
}

impl DirectPartials {
    pub fn new(options: DirectOptions) -> PartialResult<Self> {
        native::platform()?;
        options.limits.validate()?;
        if options.state_dir.as_os_str().is_empty()
            || options.output_root.as_os_str().is_empty()
            || options.progressive_limits.read_chunk == 0
            || !matches!(options.protection, ProtectionDeclaration::Complete { .. })
        {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let usage = Usage::new(options.progressive_limits.clone());
        let exclusions = Arc::new(PartialExclusions::new(usage.clone()));
        Ok(Self { options, usage, exclusions, hash_keys: Mutex::new(Vec::new()) })
    }

    /// The key a member's partial has in the anchor store: the binding, the member's ordinal, and a digest of
    /// what the map says about it (container, name, size, checks, method and where its data lies). The same map of
    /// the same set gives the same key, so a restart finds the member again; another archive's member of the same
    /// name does not.
    pub fn member_key(&self, map: &MemberMap, index: usize) -> PartialResult<MemberKey> {
        let member = map.members.get(index).ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
        let mut identity = IDENTITY_DOMAIN.to_vec();
        identity.push(container(map.format));
        identity.extend_from_slice(&(member.raw_name.len() as u64).to_le_bytes());
        identity.extend_from_slice(&member.raw_name);
        identity.extend_from_slice(&member.unpacked_size.unwrap_or(u64::MAX).to_le_bytes());
        identity.extend_from_slice(&member.packed_size.to_le_bytes());
        let checks = member.checks.unwrap_or_default();
        identity.extend_from_slice(&checks.crc32.map_or([0xFF; 5], |c| {
            let mut b = [1; 5];
            b[1..].copy_from_slice(&c.to_le_bytes());
            b
        }));
        identity.extend_from_slice(&checks.blake2sp.unwrap_or([0; 32]));
        identity.push(checks.blake2sp.is_some() as u8 | (checks.keyed as u8) << 1 | (member.encrypted as u8) << 2);
        let method: [u8; 3] = match member.method {
            crate::map::MapMethod::Stored => [0, 0, 0],
            crate::map::MapMethod::Compressed { id } => [1, id as u8, (id >> 8) as u8],
            crate::map::MapMethod::Coders => [2, 0, 0],
        };
        identity.extend_from_slice(&method);
        for piece in &member.pieces {
            identity.extend_from_slice(&piece.volume.to_le_bytes());
            identity.extend_from_slice(&piece.packed.start.to_le_bytes());
            identity.extend_from_slice(&piece.packed.end.to_le_bytes());
        }
        if let Some(slot) = &member.folder {
            identity.extend_from_slice(&slot.index.to_le_bytes());
            identity.extend_from_slice(&slot.offset.to_le_bytes());
        }
        Ok(MemberKey::new(self.options.binding.clone(), member.ordinal, crate::crypto::sha256(&identity)))
    }

    /// The output path of member `index` relative to the output root: its name as the map decodes it, sanitized
    /// (`/` separates directories; `..`, roots and empty components are dropped), with
    /// [`PartialNaming::Suffix`] appended.
    pub fn relative_output(&self, map: &MemberMap, index: usize) -> PartialResult<PathBuf> {
        let member = map.members.get(index).ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
        let name = member.name.as_deref().ok_or_else(|| err(PartialErrorKind::UnsafePath))?;
        let mut relative =
            crate::path::sanitize_fallible(name, false).map_err(|_| err(PartialErrorKind::UnsafePath))?;
        if let PartialNaming::Suffix(suffix) = &self.options.naming {
            let mut file = relative.file_name().ok_or_else(|| err(PartialErrorKind::UnsafePath))?.to_os_string();
            file.push(suffix);
            relative.set_file_name(file);
        }
        native::validate_relative(&relative)?;
        Ok(relative)
    }

    /// The partial of member `index` at [`Self::relative_output`]; see [`Self::open_at`].
    pub fn open(&self, map: &MemberMap, index: usize) -> PartialResult<DirectMember> {
        let relative = self.relative_output(map, index)?;
        self.open_at(map, index, relative)
    }

    /// The partial of member `index`, its output at `relative` under the output root. When the anchor store
    /// holds the member's key it is adopted: reopened as [`PartialFile::open`] reopens (the native identities
    /// recorded at its creation must match, and its known output is rehashed), after checking that it records
    /// this output path, name, size and checks ([`DirectOrigin::Adopted`]). Otherwise it is created: the output
    /// file exclusively at its full size, never over an existing file (`AlreadyExists`), its parents without
    /// following symbolic links, and the state bundle and anchor in one durable genesis ([`DirectOrigin::Created`]).
    /// Directories and members of unknown size are refused (`InvalidOptions`, `UnknownMemberSize`).
    pub fn open_at(&self, map: &MemberMap, index: usize, relative: PathBuf) -> PartialResult<DirectMember> {
        let member = map.members.get(index).ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
        if member.is_dir {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let size = member.unpacked_size.ok_or_else(|| err(PartialErrorKind::UnknownMemberSize))?;
        native::validate_relative(&relative)?;
        let key = self.member_key(map, index)?;
        let tag = |mut error: PartialError| {
            error.member.get_or_insert_with(|| key.clone());
            error
        };
        let checks = member.checks.unwrap_or_default();
        let keyed = match (&member.cipher, checks.keyed) {
            (Some(CipherParams::Rar5 { kdf_count, salt, check, .. }), true) => {
                Some(KeyedChecks { kdf_count: *kdf_count, salt: *salt, check: *check })
            }
            (_, true) => return Err(tag(err(PartialErrorKind::UnsupportedMethod))),
            _ => None,
        };
        let facts = DirectFacts { container: container(map.format), keyed };
        let member_checks = MemberChecks { size, crc32: checks.crc32, blake2sp: checks.blake2sp };
        let keys = match (&facts.keyed, &self.options.password) {
            (Some(keyed), Some(password)) => Some(self.hash_keys(password, keyed).map_err(tag)?),
            _ => None,
        };
        let core_options = || CoreOptions {
            limits: self.options.limits.clone(),
            usage: self.usage.clone(),
            read_chunk: self.options.progressive_limits.read_chunk,
            anchors: self.options.anchors.clone(),
            control: self.options.control.clone(),
            exclusions: self.exclusions.clone(),
        };
        if let Some(anchor) = self.options.anchors.current(&key).map_err(tag)? {
            let (core, _, _) = PartialCore::adopt(
                AdoptSpec {
                    member: key.clone(),
                    anchor,
                    output_root: self.options.output_root.clone(),
                    state_root: self.options.state_dir.clone(),
                    protection: self.options.protection.clone(),
                    keys,
                },
                core_options(),
            )
            .map_err(tag)?;
            core.check_direct(&relative, &member.raw_name, &member_checks, &facts).map_err(tag)?;
            return Ok(DirectMember { file: PartialFile::from_core(core), key, origin: DirectOrigin::Adopted });
        }
        let metadata = crate::extract::Meta {
            mtime: member.mtime.map(|(seconds, _)| seconds),
            nanos: member.mtime.map_or(0, |(_, nanos)| nanos.min(999_999_999)),
            mode: member.unix_mode.map(|mode| mode & 0o7777),
        };
        let spec = CreateSpec {
            member: key.clone(),
            name: Arc::from(member.raw_name.as_slice()),
            output_root: self.options.output_root.clone(),
            state_root: self.options.state_dir.clone(),
            relative_output: relative,
            size,
            protection: self.options.protection.clone(),
            evidence: InitialEvidence {
                format: crate::rar5::RarFormat::Rar5,
                metadata,
                parts: vec![PlainPart {
                    ordinal: 0,
                    packed: PackedSpan { volume: 0, range: 0..0 },
                    out: 0..size,
                    final_part: true,
                    crc32: None,
                    blake2sp: None,
                }],
                admissions: Vec::new(),
                headers: Vec::new(),
                direct: Some(facts),
            },
        };
        let mut prepared = PartialCore::prepare_create(spec, member_checks, core_options()).map_err(tag)?;
        if let Some(keys) = keys {
            prepared.set_keys(keys);
        }
        prepared.reserve_ready_state().map_err(tag)?;
        // Every directory on the way, the output and the bundle are checked against the declaration before any
        // name is created, as a session's genesis checks them.
        let mut usage = self.usage.clone();
        let mut protection = NativeProtection::new(&usage).map_err(PartialError::from)?;
        protection.refresh(&self.options.protection, &mut usage, 0).map_err(PartialError::from)?;
        let parents = prepared
            .prepare_parents(|path| {
                match path {
                    native::GenesisPath::Parent(path) | native::GenesisPath::Output(path) => {
                        protection.check_partial_target(path, &mut usage)?
                    }
                    native::GenesisPath::Bundle(path) => protection.check_partial_subtree(path, &mut usage)?,
                }
                Ok(())
            })
            .map_err(tag)?;
        parents.check().map_err(tag)?;
        let (core, _, _) = prepared.complete_ready().map_err(tag)?;
        drop(parents);
        Ok(DirectMember { file: PartialFile::from_core(core), key, origin: DirectOrigin::Created })
    }

    fn hash_keys(&self, password: &str, keyed: &KeyedChecks) -> PartialResult<MemberKeys> {
        if let Some((_, _, keys)) = self
            .hash_keys
            .lock()
            .unwrap()
            .iter()
            .find(|(count, salt, _)| *count == keyed.kdf_count && *salt == keyed.salt)
        {
            return Ok(keys.clone());
        }
        let budget = PartialBudget::new(self.options.limits.clone(), self.usage.scoped(), self.exclusions.clone())?;
        let keys = derive_hash_keys(password, keyed, &budget, &self.options.control)?;
        let mut cache = self.hash_keys.lock().unwrap();
        if cache.len() < 64 {
            cache.push((keyed.kdf_count, keyed.salt, keys.clone()));
        }
        Ok(keys)
    }
}

/// Derives the keys of keyed RAR 5.0 checks (only their hash key is used) from the recorded KDF parameters. A
/// password that fails a recorded check value is `WrongPassword`.
pub(super) fn derive_hash_keys(
    password: &str,
    keyed: &KeyedChecks,
    budget: &PartialBudget,
    control: &SessionControl,
) -> PartialResult<MemberKeys> {
    let params = crate::crypto::Rar5CryptParams {
        kdf_count: keyed.kdf_count,
        salt: keyed.salt,
        iv: [0; 16],
        check: keyed.check,
        tweaked_crc: true,
    };
    MemberKeys::derive(password, &params, budget, control)
}

impl PartialCore {
    /// Refuses adopting a direct partial that records another output path, name, size, checks or facts.
    pub(crate) fn check_direct(
        &self,
        relative: &std::path::Path,
        name: &[u8],
        checks: &MemberChecks,
        facts: &DirectFacts,
    ) -> PartialResult<()> {
        let op = self.operation()?;
        let snapshot = &op.snapshot;
        if snapshot.head.relative_output != relative
            || &*snapshot.name != name
            || snapshot.head.checks != *checks
            || snapshot.evidence.direct.as_ref() != Some(facts)
        {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        Ok(())
    }
}

impl PartialLimits {
    /// Limits for `members` partials kept open together (a session's persistent members, or a
    /// [`DirectPartials`] set): `open_partials` at least `members` and `open_files` at least `8 * members + 16`,
    /// each at most its ceiling of 4096, the other limits at their defaults. A live handle holds five descriptors
    /// (output, lock, bundle, output root and state root) plus one per directory between the output root and the
    /// output; creating or reopening one briefly holds a few more, and a commit one journal file at a time. Past
    /// about 500 members the ceiling is reached: close the handles of members that are done and reopen them
    /// ([`PartialFile::open`], or [`DirectPartials::open`] again) when needed. The process's own descriptor limit
    /// must allow as many.
    pub fn for_members(members: usize) -> Self {
        let defaults = Self::default();
        let members = u32::try_from(members).unwrap_or(u32::MAX);
        Self {
            open_partials: defaults.open_partials.max(members).min(4096),
            open_files: defaults.open_files.max(members.saturating_mul(8).saturating_add(16)).min(4096),
            ..defaults
        }
    }
}

/// A [`FeedSink`] over a direct partial: [`FeedSink::write_at`] writes the decoder's output into the open group
/// commit (no durable work of its own; the group commits at its size or interval, or at the handle's next
/// ordinary operation), and [`FeedSink::read_held`] reads back output the partial holds: what this handle wrote,
/// and after a restart the output the durable state knows.
///
/// A write over output already known must match it and writes nothing (`OverlapMismatch` otherwise), so a decoder
/// restored from an older snapshot that offers committed output again rewrites nothing.
pub struct DirectSink {
    file: PartialFile,
    applied: u64,
}

impl DirectSink {
    pub fn new(file: PartialFile) -> Self {
        Self { file, applied: 0 }
    }
    pub fn file(&self) -> &PartialFile {
        &self.file
    }
    pub fn file_mut(&mut self) -> &mut PartialFile {
        &mut self.file
    }
    pub fn into_file(self) -> PartialFile {
        self.file
    }
    /// Output bytes this sink wrote to the file: those that were unknown when written. Bytes offered again over
    /// known output are not counted.
    pub fn applied_bytes(&self) -> u64 {
        self.applied
    }
}

impl FeedSink for DirectSink {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        let chunk = self.file.core.budget.limits.value(PartialResource::FillBytes).max(1) as usize;
        let mut at = 0;
        while at < bytes.len() {
            let n = (bytes.len() - at).min(chunk);
            let (applied, _) = self
                .file
                .core
                .fill_grouped(offset + at as u64, &bytes[at..at + n])
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            self.applied += applied.iter().map(|r| r.end - r.start).sum::<u64>();
            at += n;
        }
        Ok(())
    }
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.core.read_known(offset, buf).map_err(|e| std::io::Error::other(e.to_string()))
    }
}
