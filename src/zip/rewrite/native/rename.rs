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

//! Member rename: rebuilt local and central headers around untouched payloads.

use std::sync::Arc;

use zip_container::{CentralHeader, ExtraIter};

use crate::zip::write::raw::Renamed;

use super::*;

const UNICODE_PATH: u16 = 0x7075;

/// A validated rename, resolved against the member's comment encoding.
pub(super) struct Spec {
    pub(super) name: Box<[u8]>,
    pub(super) utf8: bool,
}

impl RewritePlan {
    /// Rename exactly this occurrence, keeping its payload, CRC, sizes, data
    /// descriptor, timestamps, attributes, comment and other extras.
    ///
    /// Like 7-Zip's `rn`, the local and central names are replaced, any
    /// Info-ZIP Unicode Path extra (0x7075) is dropped, and the UTF-8 flag
    /// (bit 11) is set exactly when the new name is `EntryName::Utf8` with a
    /// non-ASCII name. A member whose comment has non-ASCII bytes keeps its
    /// flag, because the flag also selects the comment's encoding. If that
    /// would misencode the name, the call fails with
    /// [`RewriteError::RenameEncoding`].
    ///
    /// The name follows the rules of new entries (no absolute paths, controls,
    /// backslashes or empty, `.` and `..` components) and must keep the old
    /// name's trailing slash. It may not equal a live name: a name still held
    /// by an unedited member, an append or an earlier rename conflicts, while
    /// the name of a removed or already renamed member is free. Only the
    /// exact entry is renamed, not members under a renamed directory.
    /// Renames need [`CollisionPolicy::Exact`].
    pub fn rename(&mut self, old: &EntryId, new_name: EntryName<'_>) -> Result<()> {
        if self.options.collisions != CollisionPolicy::Exact {
            return Err(RewriteError::RenameUnsupported("rename needs the exact collision policy"));
        }
        let ordinal = self.unedited(old)?;
        let raw = name_bytes(new_name);
        work(&self.options, &mut self.usage, (raw.len() as u64).saturating_mul(4).saturating_add(1))?;
        let entry = self.metadata.view(ordinal);
        let old_raw = entry.raw_name();
        let directory = raw.ends_with(b"/");
        if directory != old_raw.ends_with(b"/") {
            return Err(CreateError::InvalidName("a rename must keep the trailing slash").into());
        }
        create::native::validate_rename_name(new_name, directory)?;
        let utf8 = resolve_flag(new_name, entry.header().flags & FLAG_UTF8 != 0, entry.raw_comment())?;
        // Reject a name another live member holds, then claim it.
        self.names.check_append(raw, &self.metadata, &self.inputs, &self.options, &mut self.usage)?;
        for spec in &self.renames {
            work(&self.options, &mut self.usage, raw.len().min(spec.name.len()) as u64 + 1)?;
            if *spec.name == *raw {
                return Err(RewriteError::NameConflict);
            }
        }
        let common = self.options.limits.common;
        let variable = add(self.variable_capacity, raw.len() as u64)?;
        let fixed = add(self.fixed_capacity()?, raw.len() as u64)?;
        reserve_push(&mut self.renames, &self.options, fixed)?;
        let fixed = add(self.fixed_capacity()?, raw.len() as u64)?;
        limit(fixed, common.plan_capacity, CreateLimit::PlanCapacity)?;
        self.usage.common.plan.capacity = self.usage.common.plan.capacity.max(fixed);
        self.variable_capacity = variable;
        self.names.remove(ordinal);
        self.actions[ordinal] = Action::Rename(self.renames.len());
        self.renames.push(Spec { name: raw.into(), utf8 });
        Ok(())
    }
}

fn resolve_flag(new_name: EntryName<'_>, old_flag: bool, comment: &[u8]) -> Result<bool> {
    let wanted = matches!(new_name, EntryName::Utf8(name) if !name.is_ascii());
    let flag = if comment.is_ascii() { wanted } else { old_flag };
    if wanted && !flag {
        return Err(RewriteError::RenameEncoding(
            "a non-ASCII UTF-8 name needs the flag, but the comment uses another encoding",
        ));
    }
    if flag && std::str::from_utf8(name_bytes(new_name)).is_err() {
        return Err(RewriteError::RenameEncoding("the member's UTF-8 flag needs a UTF-8 name"));
    }
    Ok(flag)
}

fn le16(bytes: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}

fn keep_extras(extra: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let items = ExtraIter::new(extra, 0).map_err(|_| RewriteError::UnsupportedLayout("invalid extra range"))?;
    for item in items {
        let item = item.map_err(|_| RewriteError::UnsupportedLayout("malformed extra field"))?;
        if item.id != UNICODE_PATH {
            out.extend_from_slice(&extra[item.range.start as usize..item.range.end as usize]);
        }
    }
    Ok(())
}

fn set_flag(flags: &mut [u8], utf8: bool) {
    let value = u16::from_le_bytes([flags[0], flags[1]]);
    let value = if utf8 { value | FLAG_UTF8 } else { value & !FLAG_UTF8 };
    flags.copy_from_slice(&value.to_le_bytes());
}

/// Build replacement headers from the validated source records.
fn rebuild(local: &[u8], central: &[u8], spec: &Spec, header_end: u64) -> Result<Renamed> {
    let name_len = u16::try_from(spec.name.len()).map_err(|_| CreateError::InvalidName("name too long"))?;
    let (local_name, local_extra) = (le16(local, 26), le16(local, 28));
    let extra = &local[30 + local_name..30 + local_name + local_extra];
    let mut head = Vec::new();
    head.try_reserve_exact(30 + spec.name.len() + extra.len())?;
    head.extend_from_slice(&local[..30]);
    head.extend_from_slice(&spec.name);
    keep_extras(extra, &mut head)?;
    let extra_len = u16::try_from(head.len() - 30 - spec.name.len()).expect("filtering shrinks the extra");
    set_flag(&mut head[6..8], spec.utf8);
    head[26..28].copy_from_slice(&name_len.to_le_bytes());
    head[28..30].copy_from_slice(&extra_len.to_le_bytes());

    let (central_name, central_extra, comment) = (le16(central, 28), le16(central, 30), le16(central, 32));
    let extra = &central[46 + central_name..46 + central_name + central_extra];
    let comment = &central[46 + central_name + central_extra..46 + central_name + central_extra + comment];
    let mut record = Vec::new();
    record.try_reserve_exact(46 + spec.name.len() + extra.len() + comment.len())?;
    record.extend_from_slice(&central[..46]);
    record.extend_from_slice(&spec.name);
    keep_extras(extra, &mut record)?;
    let extra_len = u16::try_from(record.len() - 46 - spec.name.len()).expect("filtering shrinks the extra");
    record.extend_from_slice(comment);
    set_flag(&mut record[8..10], spec.utf8);
    record[28..30].copy_from_slice(&name_len.to_le_bytes());
    record[30..32].copy_from_slice(&extra_len.to_le_bytes());
    Ok(Renamed { header_end, local_header: head, central: record })
}

/// Rebuilt central facts that depend on the new record.
pub(super) type CentralFacts = (CentralHeader, u64, Option<(u16, u16)>);

pub(super) fn central_facts(renamed: &Renamed) -> Result<CentralFacts> {
    let record = &renamed.central;
    let header = CentralHeader::parse(record).map_err(|_| RewriteError::UnsupportedLayout("renamed central record"))?;
    let extra_at = 46 + u64::from(header.name_len);
    let extra = &record[extra_at as usize..extra_at as usize + usize::from(header.extra_len)];
    let mut zip64 = None;
    for item in ExtraIter::new(extra, 0).map_err(|_| RewriteError::UnsupportedLayout("invalid extra range"))? {
        let item = item.map_err(|_| RewriteError::UnsupportedLayout("malformed extra field"))?;
        if item.id == 1 {
            zip64 = Some((item.range.start as u16, item.body.len() as u16));
        }
    }
    Ok((header, extra_at, zip64))
}

/// The plan fields rename preparation touches.
pub(super) struct Plan<'a> {
    pub(super) file: &'a File,
    pub(super) metadata: &'a Metadata,
    pub(super) actions: &'a [Action],
    pub(super) renames: &'a [Spec],
    pub(super) options: &'a RewriteOptions,
    pub(super) usage: &'a mut RewriteUsage,
}

/// Read each renamed member's local header and central record from the held
/// source and rebuild them. Indexed by source ordinal.
pub(super) fn build(plan: Plan<'_>, members: &[Member], attempts: &Attempts<'_>) -> Result<Vec<Option<Arc<Renamed>>>> {
    let Plan { file, metadata, actions, renames, options, usage } = plan;
    let mut result = Vec::new();
    if renames.is_empty() {
        return Ok(result);
    }
    result.try_reserve_exact(members.len())?;
    result.resize(members.len(), None);
    let limits = options.limits;
    for ordinal in 0..members.len() {
        let Action::Rename(index) = actions[ordinal] else { continue };
        let member = members[ordinal];
        let entry = metadata.view(ordinal);
        let central_range = entry.source().raw_range();
        let local_len = member.payload_at - member.local_at;
        let central_len = central_range.end - central_range.start;
        work(options, usage, add(local_len, central_len)? / 64 + 1)?;
        let mut local = Vec::new();
        let mut central = Vec::new();
        local.try_reserve_exact(local_len as usize)?;
        central.try_reserve_exact(central_len as usize)?;
        local.resize(local_len as usize, 0);
        central.resize(central_len as usize, 0);
        let mut reader = Reader {
            file,
            attempts,
            bytes: &mut usage.layout_read_bytes,
            max: limits.layout_read_bytes,
            exhausted: ReadLimit::Rewrite(RewriteLimit::LayoutReadBytes),
        };
        reader.read(member.local_at, &mut local)?;
        reader.read(central_range.start, &mut central)?;
        let renamed = rebuild(&local, &central, &renames[index], member.payload_at)?;
        result[ordinal] = Some(Arc::new(renamed));
    }
    Ok(result)
}
