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

//! The whole-archive run: members in archive order, each folder decoded once, front to back.
use std::borrow::Cow;
use std::cell::RefCell;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::coders::{self, Fault, Keys};
use super::source::VolumeSet;
use super::{SevenZipError, SevenZipLimits, check_bounds, member_name, open_map};
use crate::extract::{
    Cancellation, Checked, Dirs, LegacyMember, LegacyReport, Meta, Mode, Options, Overwrite, Place, RenameLog,
    RenamedOutput, Summary,
};
use crate::map::{MapFolder, MapMember, MemberMap};
use crate::output::Output;

type Outcome<T> = std::result::Result<T, SevenZipError>;

const CHUNK: usize = 256 << 10;

/// Unix file type bits, from the high half of the attributes.
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// A verified file waiting for its folder's own CRC before it is published.
struct Staged {
    temporary: tempfile::TempPath,
    place: Place,
    name: String,
    size: u64,
    /// its listing index, for the observer
    ordinal: u64,
}

/// The folder being decoded.
struct Active {
    index: usize,
    reader: Box<dyn Read>,
    /// Bytes of the folder's output read so far.
    pos: u64,
    crc: crc32fast::Hasher,
    /// Why the rest of the folder cannot be decoded, once something failed.
    failed: Option<String>,
    /// Files held back for the folder's CRC: only for a folder of several members that stores one.
    staged: Vec<Staged>,
    /// Tested members held back for the folder's CRC in the same case: name and size.
    tested: Vec<(String, u64, u64)>,
    defer: bool,
}

struct Run<'a> {
    opts: &'a Options,
    map: &'a MemberMap,
    set: Rc<RefCell<VolumeSet>>,
    keys: Keys,
    limits: &'a SevenZipLimits,
    cancel: &'a Cancellation,
    report: &'a mut dyn LegacyReport,
    summary: Summary,
    dirs: Dirs,
    active: Option<Active>,
    /// The password is known to be right: the encrypted headers decoded and passed their CRC, or some encrypted
    /// data has decoded and checked out.
    password_proven: bool,
    buf: Vec<u8>,
    /// the listing index of the member being handled
    current: u64,
}

pub(super) fn run(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
    report: &mut dyn LegacyReport,
) -> std::result::Result<Summary, (SevenZipError, Vec<RenamedOutput>)> {
    let early = |e| (e, Vec::new());
    let map = open_map(first, password, cancel, limits).map_err(early)?;
    check_bounds(&map, limits).map_err(early)?;
    let selected: Vec<bool> = map
        .members
        .iter()
        .enumerate()
        .map(|(ordinal, m)| options.selects(&member_name(m), None, m.is_dir, ordinal as u64))
        .collect();
    // The last selected member of each folder: decoding stops there.
    let mut needed = vec![None::<usize>; map.folders.len()];
    for (ordinal, m) in map.members.iter().enumerate() {
        if let Some(slot) = m.folder
            && selected[ordinal]
        {
            let folder =
                needed.get_mut(slot.index as usize).ok_or((SevenZipError::Corrupt("7z folder index"), Vec::new()))?;
            *folder = Some(ordinal);
        }
    }
    // Refuse an unsupported coder before anything is written.
    for (folder, _) in map.folders.iter().zip(&needed).filter(|(_, n)| n.is_some()) {
        if let Some(coder) = folder.coders.iter().find(|c| !coders::supported(c.kind)) {
            return Err(early(SevenZipError::UnsupportedCoder { id: coder.id }));
        }
    }
    let set = Rc::new(RefCell::new(VolumeSet::new(first, map.volumes)));
    let opts = protect(options, set.borrow().paths()).map_err(early)?;
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest).map_err(|e| early(SevenZipError::Io(e)))?;
    }
    let mut run = Run {
        opts: &opts,
        map: &map,
        set,
        keys: Keys::new(password),
        limits,
        cancel,
        report,
        summary: Summary { volumes: u64::from(map.volumes), ..Summary::default() },
        dirs: Dirs::default(),
        active: None,
        password_proven: map.header_encrypted,
        buf: vec![0; CHUNK],
        current: 0,
    };
    let result = run.members(&selected, &needed);
    crate::extract::finish_dirs(&mut run.summary);
    match result {
        Ok(()) => Ok(run.summary),
        Err(error) => Err((error, std::mem::take(&mut run.summary.renames))),
    }
}

/// The options with every volume of the set protected as well as the first.
fn protect<'o>(options: &'o Options, volumes: &[PathBuf]) -> Outcome<Cow<'o, Options>> {
    let legacy = |e: crate::Error| match e {
        crate::Error::Io(e) => SevenZipError::Io(e),
        other => SevenZipError::Io(io::Error::other(other.to_string())),
    };
    let mut opts = options.protecting(&volumes[0]).map_err(legacy)?;
    if opts.mode == Mode::Extract {
        for volume in &volumes[1..] {
            if let Ok(canonical) = volume.canonicalize() {
                opts.to_mut().protected_paths.insert(canonical);
            }
        }
    }
    Ok(opts)
}

fn meta(m: &MapMember) -> Meta {
    let (mtime, nanos) = m.mtime.map_or((None, 0), |(s, n)| (Some(s), n));
    Meta { mtime, nanos, mode: m.unix_mode.map(|mode| mode & 0o7777) }
}

fn legacy_error(e: crate::Error) -> SevenZipError {
    match e {
        crate::Error::Io(e) => SevenZipError::Io(e),
        other => SevenZipError::Io(io::Error::other(other.to_string())),
    }
}

impl Run<'_> {
    fn fail(&mut self, name: &str, why: &str) {
        self.fail_at(self.current, name, why);
    }

    /// A member failed: reported as a line and, live, as its outcome.
    fn fail_at(&mut self, ordinal: u64, name: &str, why: &str) {
        let line = format!("{name}: {why}");
        self.report.line(&line);
        self.report.member(LegacyMember::Failed {
            ordinal,
            name,
            error: crate::Error::Io(io::Error::other(why.to_owned())),
        });
        self.summary.errors.push(line);
    }

    fn skipped(&mut self, ordinal: u64, name: &str) {
        self.report.line(&format!("{name}: exists, skipped"));
        self.summary.skipped += 1;
        self.report.member(LegacyMember::Skipped { ordinal, name });
    }

    fn succeeded(&mut self, ordinal: u64, name: &str, bytes: u64) {
        self.summary.files += 1;
        self.summary.bytes += bytes;
        self.report.member(LegacyMember::Succeeded { ordinal, name, bytes });
    }

    fn members(&mut self, selected: &[bool], needed: &[Option<usize>]) -> Outcome<()> {
        let map = self.map;
        for (ordinal, member) in map.members.iter().enumerate() {
            if self.cancel.is_canceled() {
                return Err(SevenZipError::Canceled);
            }
            let take = selected[ordinal];
            self.current = ordinal as u64;
            if take {
                self.summary.matched += 1;
            }
            match member.folder {
                None if take => self.loose(member)?,
                None => {}
                Some(slot) => {
                    let index = slot.index as usize;
                    // Past the last member anyone needs, the folder is not decoded.
                    if needed[index].is_none_or(|last| ordinal > last) {
                        continue;
                    }
                    self.member(member, index, slot.offset, take)?;
                }
            }
        }
        self.close_folder()
    }

    /// Where a member is to go, or None when it is not written (already reported). Folders above it are made.
    fn place(&mut self, member: &MapMember, name: &str) -> Outcome<Option<(PathBuf, Option<Place>)>> {
        let rel = match crate::path::sanitize(&name.replace('\\', "/"), false) {
            Ok(rel) => rel,
            Err(e) => {
                self.fail(name, &e.to_string());
                return Ok(None);
            }
        };
        let rel =
            if self.opts.flatten && !member.is_dir { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        if let Some(kind) = member.unix_mode.map(|mode| mode & S_IFMT).filter(|&k| k != 0) {
            let why = match kind {
                S_IFREG | S_IFDIR => None,
                S_IFLNK => Some("links are not supported yet"),
                _ => Some("devices and pipes are not extracted"),
            };
            if let Some(why) = why {
                self.fail(name, why);
                return Ok(None);
            }
        }
        if self.opts.mode != Mode::Extract || member.is_dir {
            return Ok(Some((rel, None)));
        }
        let report = &mut *self.report;
        let renames = &mut self.summary.renames;
        let ordinal = self.current;
        let mut log = RenameLog {
            budget: &mut self.summary.rename_budget,
            record: &mut |renamed| {
                report.renamed_member(ordinal, &renamed);
                renames.push(renamed);
            },
        };
        let checked = crate::extract::check_target(self.opts, &rel, Some(&mut self.dirs), &mut log);
        match checked.map_err(legacy_error)? {
            Checked::Write(place) => Ok(Some((rel, Some(place)))),
            Checked::Exists => {
                self.skipped(self.current, name);
                Ok(None)
            }
            Checked::Declined => {
                self.report.line(&format!("{name}: declined, skipped"));
                self.summary.skipped += 1;
                self.report.member(LegacyMember::Skipped { ordinal: self.current, name });
                Ok(None)
            }
            Checked::Blocked(why) => {
                self.fail(name, why);
                Ok(None)
            }
        }
    }

    /// A directory or an empty file: no data.
    fn loose(&mut self, member: &MapMember) -> Outcome<()> {
        let name = member_name(member);
        let Some((rel, place)) = self.place(member, &name)? else { return Ok(()) };
        if member.is_dir {
            if self.opts.mode == Mode::Extract && !self.opts.flatten {
                crate::extract::make_dirs(&self.opts.dest, &rel).map_err(legacy_error)?;
                self.summary.dir_meta.push((self.opts.dest.join(&rel), meta(member)));
            }
            self.summary.dirs += 1;
            self.report.member(LegacyMember::Succeeded { ordinal: self.current, name: &name, bytes: 0 });
            return Ok(());
        }
        if let Some(place) = place {
            let (temporary, output) = self.stage(&place, 0)?;
            output.finish(|file| crate::extract::finish_file(file, &meta(member))).map_err(SevenZipError::Io)?;
            if !self.publish(Staged { temporary, place, name, size: 0, ordinal: self.current })? {
                return Ok(());
            }
        } else {
            self.succeeded(self.current, &name, 0);
        }
        Ok(())
    }

    /// A temporary file beside the target.
    fn stage(&self, place: &Place, size: u64) -> Outcome<(tempfile::TempPath, Output)> {
        let parent = place.path.parent().ok_or(SevenZipError::Corrupt("7z output path"))?;
        let (file, temporary) = crate::output::temporary(parent).map_err(SevenZipError::Io)?.into_parts();
        Ok((temporary, Output::new(file, Some(size))))
    }

    /// Gives a verified file its name: replacing what is there only when that was asked for, never through a link.
    /// False when it was not published (already reported).
    fn publish(&mut self, staged: Staged) -> Outcome<bool> {
        let Staged { temporary, place, name, size, ordinal } = staged;
        if let Some(reserved) = place.reserved {
            // The rename mode's own empty file, created with O_EXCL when the member started, takes the data, as long
            // as the name still holds that file.
            if cfg!(unix) && !reserved.still_ours() {
                self.fail_at(ordinal, &name, "the claimed name was replaced while the member was extracted");
                return Ok(false);
            }
            crate::output::replace(temporary, reserved.path()).map_err(SevenZipError::Io)?;
            drop(reserved.into_parts());
        } else if place.replace {
            crate::output::replace(temporary, &place.path).map_err(SevenZipError::Io)?;
        } else if let Err(error) = temporary.persist_noclobber(&place.path) {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                if self.opts.overwrite == Overwrite::Skip {
                    self.skipped(ordinal, &name);
                } else {
                    self.fail_at(ordinal, &name, "another file appeared at the target while it was extracted");
                }
                return Ok(false);
            }
            return Err(SevenZipError::Io(error.error));
        }
        self.succeeded(ordinal, &name, size);
        Ok(true)
    }

    /// Finishes the folder being decoded: its own CRC, when it was read to the end, and the files held for it.
    fn close_folder(&mut self) -> Outcome<()> {
        let Some(mut active) = self.active.take() else { return Ok(()) };
        let folder = &self.map.folders[active.index];
        if active.defer && active.failed.is_none() && (!active.staged.is_empty() || !active.tested.is_empty()) {
            // Read to the end, so the folder's CRC can vouch for what is held.
            let left = folder.unpacked_size - active.pos;
            self.pump(&mut active, left, None, None)?;
        }
        let complete = active.failed.is_none() && active.pos == folder.unpacked_size;
        let good = complete && folder.crc32.is_none_or(|crc| crc == active.crc.clone().finalize());
        let staged = std::mem::take(&mut active.staged);
        let tested = std::mem::take(&mut active.tested);
        if !good {
            let why = active.failed.clone().unwrap_or_else(|| "checksum error in its solid block".to_owned());
            let mut failed: Vec<(u64, &str)> = staged
                .iter()
                .map(|s| (s.ordinal, s.name.as_str()))
                .chain(tested.iter().map(|(n, _, o)| (*o, n.as_str())))
                .collect();
            failed.sort_by_key(|(o, _)| *o);
            for (ordinal, name) in failed {
                self.fail_at(ordinal, name, &why);
            }
            return Ok(());
        }
        for (name, size, ordinal) in tested {
            self.succeeded(ordinal, &name, size);
        }
        for staged in staged {
            self.publish(staged)?;
        }
        Ok(())
    }

    fn open_folder(&mut self, index: usize) -> Outcome<()> {
        self.close_folder()?;
        let folder: &MapFolder = &self.map.folders[index];
        let mut cx = coders::Context {
            set: &self.set,
            keys: &mut self.keys,
            limits: self.limits,
            cancel: self.cancel,
            dictionaries: 0,
        };
        let reader = coders::folder_reader(folder, &mut cx)?;
        self.active = Some(Active {
            index,
            reader,
            pos: 0,
            crc: crc32fast::Hasher::new(),
            failed: None,
            staged: Vec::new(),
            tested: Vec::new(),
            defer: folder.crc32.is_some() && folder.members > 1,
        });
        Ok(())
    }

    /// Reads `len` bytes of the active folder into `out` (or nowhere), hashing them into `member_crc` as well.
    /// A data failure marks the folder failed and is returned as Ok(Some(why)); the run's own failures are errors.
    fn pump(
        &mut self,
        active: &mut Active,
        mut len: u64,
        mut out: Option<&mut Output>,
        mut member_crc: Option<&mut crc32fast::Hasher>,
    ) -> Outcome<Option<String>> {
        while len > 0 {
            if self.cancel.is_canceled() {
                return Err(SevenZipError::Canceled);
            }
            let n = len.min(self.buf.len() as u64) as usize;
            let got = match active.reader.read(&mut self.buf[..n]) {
                Ok(0) => Err(Fault::Truncated),
                Ok(got) => Ok(got),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => Err(Fault::of(e)),
            };
            let got = match got {
                Ok(got) => got,
                Err(Fault::Canceled) => return Err(SevenZipError::Canceled),
                Err(Fault::Input(e)) => return Err(SevenZipError::Io(e)),
                Err(Fault::Missing(path)) => return Err(SevenZipError::MissingVolume(path)),
                Err(fault @ (Fault::Data(_) | Fault::Truncated)) => {
                    let why = format!("data error: {fault}");
                    active.failed =
                        Some(format!("cannot be decoded: an earlier member of its solid block failed ({fault})"));
                    return Ok(Some(why));
                }
            };
            let bytes = &self.buf[..got];
            active.crc.update(bytes);
            if let Some(crc) = member_crc.as_deref_mut() {
                crc.update(bytes);
            }
            if let Some(out) = out.as_deref_mut() {
                out.write(bytes).map_err(SevenZipError::Io)?;
            }
            active.pos += got as u64;
            len -= got as u64;
        }
        Ok(None)
    }

    /// A member with data, at `offset` in folder `index`.
    fn member(&mut self, member: &MapMember, index: usize, offset: u64, take: bool) -> Outcome<()> {
        if self.active.as_ref().is_none_or(|a| a.index != index) {
            self.open_folder(index)?;
        }
        let name = member_name(member);
        let size = member.unpacked_size.unwrap_or(0);
        let mut active = self.active.take().expect("an active folder");
        let result = self.member_in(&mut active, member, &name, offset, size, take);
        self.active = Some(active);
        result
    }

    fn member_in(
        &mut self,
        active: &mut Active,
        member: &MapMember,
        name: &str,
        offset: u64,
        size: u64,
        take: bool,
    ) -> Outcome<()> {
        let encrypted = member.encrypted;
        if let Some(why) = active.failed.clone() {
            if take {
                self.fail(name, &why);
            }
            return Ok(());
        }
        // Members nobody needs before this one are decoded through.
        if active.pos > offset {
            active.failed = Some("cannot be decoded: its solid block is inconsistent".to_owned());
            return Err(SevenZipError::Corrupt("7z members overlap in their folder"));
        }
        if active.pos < offset {
            let gap = offset - active.pos;
            if let Some(why) = self.pump(active, gap, None, None)? {
                return self.data_failure(active, name, &why, encrypted, take);
            }
        }
        let target = if take { self.place(member, name)? } else { None };
        let mut staged = match &target {
            Some((_, Some(place))) => Some(self.stage(place, size)?),
            _ => None,
        };
        let mut crc = crc32fast::Hasher::new();
        let outcome = self.pump(active, size, staged.as_mut().map(|(_, out)| out), Some(&mut crc))?;
        if let Some(why) = outcome {
            return self.data_failure(active, name, &why, encrypted, take);
        }
        if encrypted && member.checks.and_then(|c| c.crc32).is_none() && !active.defer && !self.password_proven {
            // Nothing could tell decrypted garbage from the data: with a wrong password it would be published.
            if take {
                self.fail(name, "encrypted without a CRC, and no password proven yet: cannot be verified");
            }
            return Ok(());
        }
        let crc_ok = member.checks.and_then(|c| c.crc32).is_none_or(|want| want == crc.finalize());
        if !crc_ok {
            if encrypted && !self.password_proven {
                return Err(SevenZipError::WrongPassword);
            }
            if take {
                self.fail(name, &crate::Error::BadChecksum(name.to_owned()).to_string());
            }
            return Ok(());
        }
        if encrypted && member.checks.and_then(|c| c.crc32).is_some() {
            self.password_proven = true;
        }
        let Some((_, place)) = target else { return Ok(()) };
        let Some(place) = place else {
            // Testing: checked, nothing to write; a folder with its own CRC vouches for it at its end.
            if active.defer {
                active.tested.push((name.to_owned(), size, self.current));
            } else {
                self.succeeded(self.current, name, size);
            }
            return Ok(());
        };
        let (temporary, output) = staged.take().expect("a staged output");
        output.finish(|file| crate::extract::finish_file(file, &meta(member))).map_err(SevenZipError::Io)?;
        let staged = Staged { temporary, place, name: name.to_owned(), size, ordinal: self.current };
        if active.defer {
            active.staged.push(staged);
        } else {
            self.publish(staged)?;
        }
        Ok(())
    }

    fn data_failure(&mut self, active: &mut Active, name: &str, why: &str, encrypted: bool, take: bool) -> Outcome<()> {
        if encrypted && !self.password_proven {
            return Err(SevenZipError::WrongPassword);
        }
        if active.failed.is_none() {
            active.failed = Some("cannot be decoded: an earlier member of its solid block failed".to_owned());
        }
        if take {
            self.fail(name, why);
        }
        Ok(())
    }
}
