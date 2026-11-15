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

//! Immutable bounded journal records and content-addressed metadata pages.
use super::*;
use super::{
    anchor::AnchorAck,
    limits::{PartialBudget, Reservation},
    native::{Directory, bundle_name, hex, open_at},
    state::{self, CommittedState, MutationCommit, MutationIntent, PageKind, PageRef, Snapshot},
};
use crate::progressive::OutputOperation;
use std::{ffi::OsStr, path::Path};
type PreparedFiles = Vec<(String, Vec<u8>, bool)>;
struct Stored {
    name: String,
    written: bool,
    size: u64,
    _bytes: Reservation,
    _count: Reservation,
}
pub(crate) struct Bundle {
    directory: Directory,
    budget: PartialBudget,
    files: Vec<Stored>,
    acknowledged: Option<StateAnchor>,
}
pub(crate) struct PreparedCompaction {
    pub(super) state: PartialState,
    retire: Vec<String>,
}
impl Bundle {
    pub(crate) fn create(spec: &CreateSpec, budget: &PartialBudget) -> PartialResult<Self> {
        Self::at(&spec.state_root, &spec.member, budget)
    }
    pub(crate) fn open(spec: &ReopenSpec, anchor: &StateAnchor, budget: &PartialBudget) -> PartialResult<Self> {
        if spec.state.anchor() != anchor {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Anchor)));
        }
        Self::at(&spec.context.state_root, anchor.member(), budget)
    }
    pub(super) fn at(root: &Path, member: &MemberKey, budget: &PartialBudget) -> PartialResult<Self> {
        let directory = Directory::open(
            std::path::absolute(root).map_err(|e| io_error(OutputOperation::Metadata, e))?.join(bundle_name(member)),
            budget,
        )?;
        let _transient = budget.reserve(PartialResource::OpenFiles, 1)?;
        let entries = std::fs::read_dir(&directory.path).map_err(|e| io_error(OutputOperation::Read, e))?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io_error(OutputOperation::Read, e))?;
            let name = entry.file_name();
            if name == "lock" {
                continue;
            }
            let name = name.into_string().map_err(|_| malformed())?;
            if name.len() != 66
                || !(name.starts_with("p-") || name.starts_with("r-"))
                || !name.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(malformed());
            }
            let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| io_error(OutputOperation::Metadata, e))?;
            if !meta.is_file() {
                return Err(malformed());
            }
            let identity = crate::progressive::native::Identity::metadata(&meta)
                .map_err(|e| io_error(OutputOperation::Metadata, e))?;
            Self::exclude(&directory, budget, &name, Some(identity))?;
            let is_page = name.starts_with("p-");
            let count = budget
                .reserve(if is_page { PartialResource::StatePages } else { PartialResource::JournalRecords }, 1)?;
            let bytes = budget.reserve(
                if is_page { PartialResource::LedgerBytes } else { PartialResource::JournalBytes },
                meta.len(),
            )?;
            budget.metadata(std::mem::size_of::<Stored>() as u64 + name.len() as u64)?;
            files.try_reserve_exact(1).map_err(|_| malformed())?;
            files.push(Stored { name, written: true, size: meta.len(), _bytes: bytes, _count: count });
        }
        directory.check()?;
        Ok(Self { directory, budget: budget.clone(), files, acknowledged: None })
    }
    fn exclude(
        directory: &Directory,
        budget: &PartialBudget,
        name: &str,
        identity: Option<crate::progressive::native::Identity>,
    ) -> PartialResult<()> {
        budget.exclude(&PartialProtectedPath {
            path: directory.path.join(name),
            identity,
            root: directory.path.clone(),
            root_identity: directory.identity,
            parent: directory.path.clone(),
            parent_identity: directory.identity,
            directory: false,
        })
    }
    // Each immutable file reserves one staging Stored and one retained Stored plus its 66-byte name.
    pub(super) fn genesis_metadata(pages: usize) -> PartialResult<u64> {
        let refs = pages.checked_mul(std::mem::size_of::<PageRef>()).ok_or_else(malformed)?;
        let files = pages
            .checked_add(2)
            .and_then(|n| n.checked_mul(2 * std::mem::size_of::<Stored>() + 66))
            .ok_or_else(malformed)?;
        Ok(refs.checked_add(files).ok_or_else(malformed)? as u64)
    }
    pub(super) fn persist_pages(
        &mut self,
        snapshot: &mut Snapshot,
        pages: Vec<(PageKind, Vec<u8>)>,
    ) -> PartialResult<()> {
        let mut refs = self.budget.vector(pages.len())?;
        for (kind, bytes) in pages {
            let digest = crate::crypto::sha256(&bytes);
            self.put(&format!("p-{}", hex(&digest)), &bytes, true)?;
            refs.push(PageRef { kind, digest, len: bytes.len() as u32 });
        }
        snapshot.head.pages = refs;
        Ok(())
    }
    fn put(&mut self, name: &str, bytes: &[u8], page: bool) -> PartialResult<()> {
        self.directory.check()?;
        if self.files.iter().any(|f| f.name == name && f.written) {
            let f = open_at(&self.directory.held.file, OsStr::new(name), false, &self.budget)?;
            if state::read_bounded(&f.file, bytes.len(), &self.budget)? != bytes {
                return Err(err(PartialErrorKind::JournalCorrupt));
            }
            return Ok(());
        }
        if !self.files.iter().any(|f| f.name == name) {
            self.reserve_files(&[(name.to_owned(), bytes.to_vec(), page)])?;
        }
        let file = open_at(&self.directory.held.file, OsStr::new(name), true, &self.budget)?;
        self.files.iter_mut().find(|f| f.name == name).unwrap().written = true;
        self.budget.exclusions.bind(&self.directory.path.join(name), &file.file)?;
        let mut at = 0;
        while at < bytes.len() {
            let n = crate::output::range::write_at(&file.file, at as u64, &bytes[at..])
                .map_err(|e| io_error(OutputOperation::Write, e))?;
            if n == 0 {
                return Err(io_error(OutputOperation::Write, std::io::ErrorKind::WriteZero.into()));
            }
            at += n;
        }
        file.file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))?;
        self.directory.held.file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))?;
        self.directory.check()?;
        Ok(())
    }
    pub(crate) fn append_intent(&mut self, intent: &MutationIntent) -> PartialResult<StateAnchor> {
        for range in &intent.affected {
            if range.start > range.end || range.end > intent.conservative.size {
                return Err(malformed());
            }
        }
        let kind = if intent.parent.is_none() { 1 } else { 2 };
        let state = state::encode_record(
            kind,
            intent.transaction,
            intent.parent.as_ref(),
            &intent.conservative,
            &self.budget.limits,
        )?;
        self.put(&format!("r-{}", hex(state.anchor().digest())), &state.wire, false)?;
        Ok(state.anchor)
    }
    pub(crate) fn append_commit(&mut self, commit: &MutationCommit) -> PartialResult<StateAnchor> {
        let state =
            state::encode_record(3, commit.transaction, Some(&commit.parent), &commit.valid, &self.budget.limits)?;
        self.put(&format!("r-{}", hex(state.anchor().digest())), &state.wire, false)?;
        Ok(state.anchor)
    }
    pub(super) fn snapshot(&self, state: &PartialState) -> PartialResult<Snapshot> {
        self.snapshot_reusing(state, &[])
    }
    pub(super) fn snapshot_reusing(
        &self,
        state: &PartialState,
        reusable: &[state::KnownLeaf],
    ) -> PartialResult<Snapshot> {
        let (_, _, _, head) = state::decode_record(&state.wire, &self.budget.limits)?;
        let mut pages = self.budget.vector(head.pages.len())?;
        for reference in &head.pages {
            let name = format!("p-{}", hex(&reference.digest));
            let file =
                open_at(&self.directory.held.file, OsStr::new(&name), false, &self.budget).map_err(|e| {
                    match e.kind {
                        PartialErrorKind::Io { ref cause, .. } if cause.kind() == std::io::ErrorKind::NotFound => {
                            err(PartialErrorKind::StateUnavailable)
                        }
                        _ => e,
                    }
                })?;
            let bytes = state::read_bounded(&file.file, reference.len as usize, &self.budget)?;
            if bytes.len() != reference.len as usize || crate::crypto::sha256(&bytes) != reference.digest {
                return Err(err(PartialErrorKind::JournalCorrupt));
            }
            pages.push((reference.kind, bytes));
        }
        self.directory.check()?;
        state::decode_pages(head, pages, &self.budget, reusable)
    }
    pub(super) fn reserve_files(&mut self, files: &[(String, Vec<u8>, bool)]) -> PartialResult<()> {
        let mut added = self.budget.vector(files.len())?;
        for (name, bytes, page) in files {
            if self.files.iter().any(|f| &f.name == name) || added.iter().any(|f: &Stored| &f.name == name) {
                continue;
            }
            let count = self
                .budget
                .reserve(if *page { PartialResource::StatePages } else { PartialResource::JournalRecords }, 1)?;
            let space = self.budget.reserve(
                if *page { PartialResource::LedgerBytes } else { PartialResource::JournalBytes },
                bytes.len() as u64,
            )?;
            Self::exclude(&self.directory, &self.budget, name, None)?;
            self.budget.metadata(name.len() as u64)?;
            added.push(Stored {
                name: name.clone(),
                written: false,
                size: bytes.len() as u64,
                _bytes: space,
                _count: count,
            });
        }
        self.budget.metadata((added.len() * std::mem::size_of::<Stored>()) as u64)?;
        self.files.try_reserve_exact(added.len()).map_err(|_| malformed())?;
        self.files.extend(added);
        Ok(())
    }
    pub(super) fn prepare_mutation(
        &mut self,
        parent: &StateAnchor,
        intent: &mut Snapshot,
        commit: &mut Snapshot,
    ) -> PartialResult<(PartialState, PartialState, PreparedFiles)> {
        let mut files = Vec::new();
        for snapshot in [&mut *intent, &mut *commit] {
            let pages = state::encode_pages(snapshot, &self.budget)?;
            let mut refs = self.budget.vector(pages.len())?;
            for (kind, bytes) in pages {
                let digest = crate::crypto::sha256(&bytes);
                refs.push(PageRef { kind, digest, len: bytes.len() as u32 });
                files.push((format!("p-{}", hex(&digest)), bytes, true));
            }
            snapshot.head.pages = refs;
        }
        let intent_state =
            state::encode_record(2, intent.head.revision, Some(parent), &intent.head, &self.budget.limits)?;
        let commit_state = state::encode_record(
            3,
            intent.head.revision,
            Some(intent_state.anchor()),
            &commit.head,
            &self.budget.limits,
        )?;
        files.push((format!("r-{}", hex(intent_state.anchor().digest())), intent_state.wire.clone(), false));
        files.push((format!("r-{}", hex(commit_state.anchor().digest())), commit_state.wire.clone(), false));
        Ok((intent_state, commit_state, files))
    }
    /// Maintenance is useful only when it can reclaim the pressured storage
    /// and leave room for this already-validated transaction. Include one
    /// compaction record of headroom so a small journal does not become stuck.
    pub(super) fn needs_compaction(
        &self,
        head: &CommittedState,
        files: &[(String, Vec<u8>, bool)],
    ) -> PartialResult<bool> {
        let visits = self
            .files
            .len()
            .checked_mul(files.len().checked_add(head.pages.len()).ok_or_else(malformed)?)
            .ok_or_else(malformed)?;
        self.budget.usage.charge(Resource::SourceBookkeeping, visits as u64)?;
        self.budget.metadata(
            (std::mem::size_of::<CommittedState>()
                + head.relative_output.as_os_str().len()
                + head.pages.len() * (std::mem::size_of::<PageRef>() + 66)) as u64,
        )?;
        let live = head.pages.iter().map(|p| format!("p-{}", hex(&p.digest))).collect::<Vec<_>>();
        let mut compact_head = head.clone();
        compact_head.sequence = compact_head.sequence.checked_add(1).ok_or_else(malformed)?;
        let compact = self.compaction_state(&compact_head)?;
        let compact_name = format!("r-{}", hex(compact.anchor().digest()));
        let retained_compact = self.files.iter().any(|f| f.name == compact_name);
        let maintenance =
            [0, 0, u64::from(!retained_compact), if retained_compact { 0 } else { compact.wire.len() as u64 }];
        let mut needed = [0u64; 4];
        let mut after_needed = [0u64; 4];
        let mut reclaim = [0u64; 4];
        let add = |totals: &mut [u64; 4], page: bool, size: u64| -> PartialResult<()> {
            let i = if page { 0 } else { 2 };
            totals[i] = totals[i].checked_add(1).ok_or_else(malformed)?;
            totals[i + 1] = totals[i + 1].checked_add(size).ok_or_else(malformed)?;
            Ok(())
        };
        for (i, (name, bytes, page)) in files.iter().enumerate() {
            if files[..i].iter().any(|(prior, _, _)| prior == name) {
                continue;
            }
            let existing = self.files.iter().find(|f| &f.name == name);
            if existing.is_none() {
                add(&mut needed, *page, bytes.len() as u64)?;
            }
            if !live.contains(name) && existing.is_none_or(|f| f.written) {
                add(&mut after_needed, *page, bytes.len() as u64)?;
            }
        }
        for file in &self.files {
            if file.written && file.name != compact_name && !live.contains(&file.name) {
                add(&mut reclaim, file.name.starts_with("p-"), file.size)?;
            }
        }
        let counts = *self.budget.exclusions.counters.lock().unwrap();
        let resources = [
            PartialResource::StatePages,
            PartialResource::LedgerBytes,
            PartialResource::JournalRecords,
            PartialResource::JournalBytes,
        ];
        let mut pressure = false;
        for (i, resource) in resources.into_iter().enumerate() {
            let used = counts[resource as usize];
            let cap = self.budget.limits.value(resource);
            let projected =
                used.checked_add(needed[i]).and_then(|n| n.checked_add(maintenance[i])).ok_or_else(malformed)?;
            pressure |= projected > cap;
            // Do not acknowledge maintenance which cannot make this transaction fit.
            if used.checked_add(maintenance[i]).ok_or_else(malformed)? > cap
                || used
                    .checked_sub(reclaim[i])
                    .and_then(|n| n.checked_add(maintenance[i]))
                    .and_then(|n| n.checked_add(after_needed[i]))
                    .ok_or_else(malformed)?
                    > cap
            {
                return Ok(false);
            }
        }
        Ok(pressure && reclaim.iter().any(|n| *n > 0))
    }
    pub(super) fn write_pages(&mut self, files: &[(String, Vec<u8>, bool)]) -> PartialResult<()> {
        for (name, bytes, page) in files {
            if *page {
                self.put(name, bytes, true)?;
            }
        }
        Ok(())
    }
    pub(super) fn acknowledge(&mut self, state: &StateAnchor, ack: &AnchorAck) -> PartialResult<()> {
        if !ack.matches(state) {
            return Err(err(PartialErrorKind::AnchorConflict));
        }
        self.acknowledged = Some(state.clone());
        Ok(())
    }
    fn compaction_state(&self, head: &CommittedState) -> PartialResult<PartialState> {
        let parent = self.acknowledged.as_ref().ok_or_else(|| err(PartialErrorKind::AnchorConflict))?;
        if head.sequence != parent.sequence().checked_add(1).ok_or_else(malformed)? {
            return Err(malformed());
        }
        state::encode_record(4, head.revision, Some(parent), head, &self.budget.limits)
    }
    pub(crate) fn prepare_compaction(&mut self, head: &CommittedState) -> PartialResult<PreparedCompaction> {
        let state = self.compaction_state(head)?;
        let name = format!("r-{}", hex(state.anchor().digest()));
        let mut retire = self.budget.vector(self.files.len())?;
        for f in &self.files {
            if f.written && f.name != name && !head.pages.iter().any(|p| f.name == format!("p-{}", hex(&p.digest))) {
                self.budget.metadata(f.name.len() as u64)?;
                retire.push(f.name.clone());
            }
        }
        self.put(&name, &state.wire, false)?;
        Ok(PreparedCompaction { state, retire })
    }
    pub(crate) fn complete_compaction(&mut self, prepared: PreparedCompaction, ack: &AnchorAck) -> PartialResult<()> {
        if !ack.matches(prepared.state.anchor()) {
            return Err(err(PartialErrorKind::AnchorConflict));
        }
        self.acknowledge(prepared.state.anchor(), ack)?;
        for name in prepared.retire {
            self.directory.check()?;
            let path = self.directory.path.join(&name);
            let file = open_at(&self.directory.held.file, OsStr::new(&name), false, &self.budget)?;
            let held = crate::progressive::native::Identity::file(&file.file)
                .map_err(|e| io_error(OutputOperation::Metadata, e))?;
            let meta = std::fs::symlink_metadata(&path).map_err(|e| io_error(OutputOperation::Metadata, e))?;
            if crate::progressive::native::Identity::metadata(&meta)
                .map_err(|e| io_error(OutputOperation::Metadata, e))?
                != held
            {
                return Err(err(PartialErrorKind::JournalCorrupt));
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                use std::os::fd::AsRawFd;
                let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| malformed())?;
                // Only obsolete validated names in the held bundle are retired.
                if unsafe { libc::unlinkat(self.directory.held.file.as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
                    return Err(io_error(OutputOperation::Remove, std::io::Error::last_os_error()));
                }
            }
            self.budget.exclusions.retire(&path);
            self.files.retain(|f| f.name != name);
        }
        self.directory.held.file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))
    }
}
