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
use super::{EncryptedFailure, SevenZipError, SevenZipLimits, check_bounds, member_name, open_map_keyed};
use crate::extract::{
    Cancellation, Checked, Dirs, FolderDamage, FolderDamageKind, LegacyMember, LegacyReport, Meta, Mode, Options,
    Overwrite, Place, RenameLog, RenamedOutput, Summary,
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
    /// A symbolic link at this destination-relative path: the staged data is its target.
    link: Option<PathBuf>,
    /// the archived modification time, for a symbolic link
    modified: Option<std::time::SystemTime>,
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
    /// The failure is an encrypted folder that did not decrypt under the password, and how that showed: every member
    /// of it that is taken fails as a wrong password the same way, as 7-Zip reports each one ("Data Error in
    /// encrypted file. Wrong password?" or "CRC Failed in encrypted file. Wrong password?").
    wrong_password: Option<EncryptedFailure>,
    /// Files held back for the folder's CRC: only for a folder of several members that stores one.
    staged: Vec<Staged>,
    /// Tested members held back for the folder's CRC in the same case: name and size.
    tested: Vec<(String, u64, u64)>,
    /// Printed members held back for the folder's CRC in the same case: listing index and spooled data.
    held: Vec<(u64, Spool)>,
    /// [`crate::extract::UnverifiedOutput::Emit`]: those of `held` that failed and print unverified (queued behind
    /// the ones before them, so the output stays in archive order)
    unverified_held: Vec<u64>,
    defer: bool,
    /// [`crate::extract::Options::seven_zip_strict`]: the coders' end checks, made once the folder is read to its end
    checks: Vec<coders::EndCheck>,
}

/// Plaintext one member holds back until it checks out: in memory, or a range of the run's [`SpoolStore`] file.
/// Past `spool_member_bytes` it drops what it holds and takes no more.
#[derive(Default)]
struct Spool {
    data: Held,
    len: u64,
    /// went past `spool_member_bytes`: emptied, takes nothing more
    over: bool,
}

#[derive(Default)]
enum Held {
    #[default]
    Nothing,
    Memory(Vec<u8>),
    /// `len` bytes at `start` of the store's file
    File {
        start: u64,
    },
}

/// Where every held-back member of a run keeps its plaintext: in memory while all of them together hold at most
/// `spool_memory_bytes`, past that in one temporary file shared by the run, which has no name (unlinked as it is
/// made, written and read back through its one descriptor at each member's own offsets), so neither a crash nor a
/// kill leaves decrypted data on disk, and however many members a folder holds back the run uses one descriptor.
#[derive(Default)]
struct SpoolStore {
    file: Option<fs::File>,
    /// bytes in use at the start of `file`; a member's range is always the last one while it is written
    len: u64,
    /// bytes all held members keep in memory
    memory: u64,
}

impl SpoolStore {
    fn file(&mut self, limits: &SevenZipLimits) -> io::Result<&mut fs::File> {
        if self.file.is_none() {
            self.file = Some(match &limits.spool_dir {
                Some(dir) => tempfile::tempfile_in(dir)?,
                None => tempfile::tempfile()?,
            });
        }
        Ok(self.file.as_mut().expect("a spool file"))
    }

    /// Appends `bytes` at the end of the file.
    fn append(&mut self, bytes: &[u8], limits: &SevenZipLimits) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let at = self.len;
        let file = self.file(limits)?;
        file.seek(SeekFrom::Start(at))?;
        file.write_all(bytes)?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    fn write(&mut self, spool: &mut Spool, bytes: &[u8], limits: &SevenZipLimits) -> io::Result<()> {
        if spool.over {
            return Ok(());
        }
        let n = bytes.len() as u64;
        let len = spool.len.saturating_add(n);
        if len > limits.spool_member_bytes {
            self.release(spool)?;
            spool.over = true;
            return Ok(());
        }
        match std::mem::take(&mut spool.data) {
            Held::Nothing if self.memory.saturating_add(n) <= limits.spool_memory_bytes => {
                self.memory += n;
                spool.data = Held::Memory(bytes.to_vec());
            }
            Held::Memory(mut held) if self.memory.saturating_add(n) <= limits.spool_memory_bytes => {
                self.memory += n;
                held.extend_from_slice(bytes);
                spool.data = Held::Memory(held);
            }
            // over the memory budget: the member moves to the file, behind every range there
            Held::Nothing => {
                let start = self.len;
                self.append(bytes, limits)?;
                spool.data = Held::File { start };
            }
            Held::Memory(held) => {
                let start = self.len;
                self.memory -= held.len() as u64;
                self.append(&held, limits)?;
                self.append(bytes, limits)?;
                spool.data = Held::File { start };
            }
            Held::File { start } => {
                debug_assert_eq!(start + spool.len, self.len, "the member written is the last range");
                self.append(bytes, limits)?;
                spool.data = Held::File { start };
            }
        }
        spool.len = len;
        Ok(())
    }

    /// Lets `spool`'s plaintext go: its memory, or its range when it is the file's last one.
    fn release(&mut self, spool: &mut Spool) -> io::Result<()> {
        match std::mem::take(&mut spool.data) {
            Held::Nothing => {}
            Held::Memory(held) => self.memory -= held.len() as u64,
            Held::File { start } => {
                if start + spool.len == self.len {
                    self.len = start;
                    if let Some(file) = &self.file {
                        file.set_len(start)?;
                    }
                }
            }
        }
        spool.len = 0;
        Ok(())
    }

    /// Forgets every range and all memory accounting: the folder they belonged to is done.
    fn reset(&mut self) -> io::Result<()> {
        self.memory = 0;
        self.len = 0;
        if let Some(file) = &self.file {
            file.set_len(0)?;
        }
        Ok(())
    }

    /// Hands what `spool` holds to `sink`, in order, checking for cancellation before each chunk and at the end.
    fn replay(
        &mut self,
        spool: &Spool,
        cancel: &Cancellation,
        mut sink: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> Outcome<()> {
        use std::io::{Seek, SeekFrom};
        let canceled = || if cancel.is_canceled() { Err(SevenZipError::Canceled) } else { Ok(()) };
        match &spool.data {
            Held::Nothing => {}
            Held::Memory(held) => {
                for chunk in held.chunks(CHUNK) {
                    canceled()?;
                    sink(chunk).map_err(SevenZipError::Io)?;
                }
            }
            Held::File { start } => {
                let file = self.file.as_mut().ok_or(SevenZipError::Corrupt("7z spool file missing"))?;
                file.seek(SeekFrom::Start(*start)).map_err(SevenZipError::Io)?;
                let mut left = spool.len;
                let mut chunk = vec![0; chunk_len(left)];
                while left > 0 {
                    canceled()?;
                    let want = chunk_len(left).min(chunk.len());
                    match file.read(&mut chunk[..want]) {
                        Ok(0) => return Err(SevenZipError::Io(io::ErrorKind::UnexpectedEof.into())),
                        Ok(n) => {
                            sink(&chunk[..n]).map_err(SevenZipError::Io)?;
                            left -= n as u64;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(SevenZipError::Io(e)),
                    }
                }
            }
        }
        canceled()
    }
}

/// The next read's length for `left` bytes still to go: at most [`CHUNK`], the minimum taken in `u64`, so a member of
/// 4 GiB or more is not truncated on a 32-bit target.
fn chunk_len(left: u64) -> usize {
    left.min(CHUNK as u64) as usize
}

/// Where a member's bytes go while it is decoded.
enum Dest<'o> {
    File(&'o mut Output),
    Spool(&'o mut Spool),
}

/// Where printed members go: their listing index and a chunk of their data, in archive order.
pub(super) type PrintSink<'a> = &'a mut dyn FnMut(u64, &[u8]) -> io::Result<()>;

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
    /// Destination-relative paths of links staged for their folder's CRC and not published yet: a later member under
    /// one must not create its parents before the link takes the path, so it fails as under a published link.
    pending_links: Vec<PathBuf>,
    /// the folders placing the current member created, deepest first, and its target: removed again (when empty)
    /// if the member leaves nothing there, as 7-Zip creates a file's folders only as its data comes
    fresh_dirs: Option<(PathBuf, Vec<PathBuf>)>,
    active: Option<Active>,
    /// The password is known to be right: the encrypted headers decoded and passed their CRC, or some encrypted
    /// data has decoded and checked out.
    password_proven: bool,
    buf: Vec<u8>,
    /// the listing index of the member being handled
    current: u64,
    /// files written so far (symbolic links only are placed; 7z hard links are stored as files)
    extracted: crate::extract::link::Extracted,
    /// Printing (`7z x -so`) instead of extracting or testing: each selected member is spooled until it checks
    /// out, then copied here.
    print: Option<PrintSink<'a>>,
    /// Where held-back members keep their plaintext (see [`SpoolStore`]).
    store: SpoolStore,
    /// threads an LZMA2 coder may decode its blocks on
    threads: usize,
    /// [`crate::extract::UnverifiedOutput::Emit`] when printing: a member that fails on its data prints what was
    /// decoded of it, as 7-Zip 26.06 `x -so` does
    unverified: bool,
    /// [`crate::extract::Options::seven_zip_strict`]
    strict: bool,
}

/// `threads` as asked for, None for one per core.
fn thread_count(threads: Option<usize>) -> usize {
    threads.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get())).max(1)
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
    let (map, header_key) = open_map_keyed(first, password, cancel, limits).map_err(early)?;
    let mut keys = Keys::new(password);
    if let Some((cycles, salt, key)) = header_key {
        keys.seed(cycles, salt, key);
    }
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
        keys,
        limits,
        cancel,
        report,
        summary: Summary { volumes: u64::from(map.volumes), ..Summary::default() },
        dirs: Dirs::default(),
        pending_links: Vec::new(),
        fresh_dirs: None,
        extracted: crate::extract::link::Extracted::new(&opts),
        active: None,
        password_proven: map.header_encrypted,
        buf: vec![0; CHUNK],
        current: 0,
        print: None,
        store: SpoolStore::default(),
        threads: thread_count(options.threads),
        unverified: false,
        strict: options.seven_zip_strict,
    };
    let result = run.members(&selected, &needed);
    crate::extract::finish_dirs(&mut run.summary);
    match result {
        Ok(()) => Ok(run.summary),
        Err(error) => Err((error, std::mem::take(&mut run.summary.renames))),
    }
}

/// Prints the members `select` takes (by listing index and name; directories are never offered) to `sink` in
/// archive order: each folder is decoded once, front to back, and each member is spooled until its CRC (and, for a
/// folder of several members that stores one, the folder's CRC) checks out, then copied to `sink`. A member that
/// fails is a line in the returned [`Summary::errors`] and prints nothing; the run goes on. The run itself fails as
/// [`run`] does (a missing or wrong password, a limit, an unsupported coder, cancellation, unreadable volumes), and
/// on an error from `sink`.
pub(super) fn print(
    first: &Path,
    password: Option<&str>,
    select: &mut dyn FnMut(u64, &str) -> bool,
    sink: PrintSink<'_>,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
    print_options: &super::SevenZipPrintOptions,
) -> Outcome<Summary> {
    let unverified = print_options.unverified_output == crate::extract::UnverifiedOutput::Emit;
    let (map, header_key) = open_map_keyed(first, password, cancel, limits)?;
    let mut keys = Keys::new(password);
    if let Some((cycles, salt, key)) = header_key {
        keys.seed(cycles, salt, key);
    }
    check_bounds(&map, limits)?;
    let selected: Vec<bool> = map
        .members
        .iter()
        .enumerate()
        .map(|(ordinal, m)| !m.is_dir && select(ordinal as u64, &member_name(m)))
        .collect();
    let mut needed = vec![None::<usize>; map.folders.len()];
    for (ordinal, m) in map.members.iter().enumerate() {
        if let Some(slot) = m.folder
            && selected[ordinal]
        {
            *needed.get_mut(slot.index as usize).ok_or(SevenZipError::Corrupt("7z folder index"))? = Some(ordinal);
        }
    }
    for (folder, _) in map.folders.iter().zip(&needed).filter(|(_, n)| n.is_some()) {
        if let Some(coder) = folder.coders.iter().find(|c| !coders::supported(c.kind)) {
            return Err(SevenZipError::UnsupportedCoder { id: coder.id });
        }
    }
    let options = Options {
        mode: Mode::Test,
        dest: PathBuf::new(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
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
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    };
    let set = Rc::new(RefCell::new(VolumeSet::new(first, map.volumes)));
    let mut report = |_: &str| {};
    let mut run = Run {
        opts: &options,
        map: &map,
        set,
        keys,
        limits,
        cancel,
        report: &mut report,
        summary: Summary { volumes: u64::from(map.volumes), ..Summary::default() },
        dirs: Dirs::default(),
        pending_links: Vec::new(),
        fresh_dirs: None,
        extracted: crate::extract::link::Extracted::new(&options),
        active: None,
        password_proven: map.header_encrypted,
        buf: vec![0; CHUNK],
        current: 0,
        print: Some(sink),
        store: SpoolStore::default(),
        threads: thread_count(limits.decode_threads),
        unverified,
        strict: print_options.seven_zip_strict,
    };
    run.members(&selected, &needed)?;
    Ok(run.summary)
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

    /// A member of an encrypted folder that did not decrypt under the given password: a line, and as its outcome
    /// the typed [`SevenZipError::WrongPassword`] with how it failed (`SevenZipError::of` finds it in the member's
    /// error).
    fn fail_wrong_password(&mut self, ordinal: u64, name: &str, failure: EncryptedFailure) {
        let line = format!("{name}: {}", failure.line());
        self.report.line(&line);
        self.report.member(LegacyMember::Failed {
            ordinal,
            name,
            error: crate::Error::from(SevenZipError::WrongPassword { failure: Some(failure) }),
        });
        self.summary.errors.push(line);
    }

    /// Marks the active folder as not decrypting under the password (shown by `failure`), and fails this member if it
    /// is taken.
    fn wrong_password(
        &mut self,
        active: &mut Active,
        name: &str,
        take: bool,
        failure: EncryptedFailure,
    ) -> Outcome<()> {
        // the first sign decides: the rest of the folder fails the same way
        let failure = *active.wrong_password.get_or_insert(failure);
        if active.failed.is_none() {
            active.failed = Some(failure.line().to_owned());
        }
        // Earlier members held back for the folder's CRC (ones without a CRC of their own) failed too: report them
        // first, so the failures come in archive order. Their staged files are dropped, which removes them.
        let mut held: Vec<(u64, String)> = std::mem::take(&mut active.staged)
            .into_iter()
            .map(|s| (s.ordinal, s.name))
            .chain(std::mem::take(&mut active.tested).into_iter().map(|(n, _, o)| (o, n)))
            .collect();
        held.sort_by_key(|(o, _)| *o);
        // printed members held for the same CRC print nothing (UnverifiedOutput::Emit: what they hold): let their
        // plaintext go now
        active.unverified_held.clear();
        let mut spools = std::mem::take(&mut active.held).into_iter();
        while let Some((ordinal, mut spool)) = spools.next() {
            if self.unverified {
                let name = member_name(&self.map.members[ordinal as usize]);
                if let Err(error) = self.print_unverified(ordinal, &name, spool) {
                    // a failure writing the output ends the run: what is still held goes
                    for (_, mut spool) in spools {
                        let _ = self.store.release(&mut spool);
                    }
                    return Err(error);
                }
            } else {
                let _ = self.store.release(&mut spool);
            }
        }
        for (ordinal, held) in held {
            self.fail_wrong_password(ordinal, &held, failure);
        }
        if take {
            self.fail_wrong_password(self.current, name, failure);
        }
        Ok(())
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
        self.close_folder()?;
        // canceled from the last folder's deferred outcomes
        if self.cancel.is_canceled() {
            return Err(SevenZipError::Canceled);
        }
        Ok(())
    }

    /// Where a member is to go, or None when it is not written (already reported). Folders above it are made.
    fn place(&mut self, member: &MapMember, name: &str) -> Outcome<Option<(PathBuf, Option<Place>)>> {
        if member.is_dir && crate::path::names_root_with(name, !self.opts.literal_backslashes()) {
            return Ok(None);
        }
        // as 7-Zip writes 7z names: a `\` separates folders too, unless `Options::backslashes` keeps it in the name
        let written: std::borrow::Cow<'_, str> =
            if self.opts.literal_backslashes() { name.into() } else { name.replace('\\', "/").into() };
        let rel = match crate::path::sanitize_with(&written, false, self.opts.windows_safe_names) {
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
                S_IFLNK if member.unpacked_size.unwrap_or(0) > crate::extract::link::MAX_TARGET => {
                    Some("the link's target is too long")
                }
                S_IFLNK => None,
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
        if self.pending_links.iter().any(|link| rel.starts_with(link) && rel != *link) {
            self.fail(name, "a parent is a link in the same archive that is not placed yet");
            return Ok(None);
        }
        let report = &mut *self.report;
        let renames = &mut self.summary.renames;
        let ordinal = self.current;
        let mut log = RenameLog {
            budget: &mut self.summary.rename_budget,
            placed: self.opts.replace_placed_links.then_some(&self.extracted),
            record: &mut |renamed| {
                report.renamed_member(ordinal, &renamed);
                renames.push(renamed);
            },
        };
        // the folders checking the target creates
        let target = self.opts.dest.join(&rel);
        let fresh: Vec<PathBuf> = target
            .ancestors()
            .skip(1)
            .take_while(|dir| *dir != self.opts.dest && std::fs::symlink_metadata(dir).is_err())
            .map(Path::to_path_buf)
            .collect();
        if !fresh.is_empty() {
            self.fresh_dirs = Some((target, fresh));
        }
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
        if self.print.is_some() {
            // an empty file prints nothing; directories are never selected for printing
            if !member.is_dir {
                self.succeeded(self.current, &name, 0);
            }
            return Ok(());
        }
        let Some((rel, place)) = self.place(member, &name)? else { return Ok(()) };
        if member.is_dir {
            if self.opts.mode == Mode::Extract && !self.opts.flatten {
                if let Some(why) = crate::extract::make_member_dirs(&self.opts.dest, &rel).map_err(legacy_error)? {
                    self.fail(&name, why);
                    return Ok(());
                }
                self.summary.dir_meta.push((self.opts.dest.join(&rel), self.opts.dir_meta(meta(member))));
            }
            self.summary.dirs += 1;
            self.report.member(LegacyMember::Succeeded { ordinal: self.current, name: &name, bytes: 0 });
            return Ok(());
        }
        if let Some(place) = place {
            let (temporary, output) = self.stage(&place, 0)?;
            output
                .finish(|file| crate::extract::finish_file(file, &self.opts.meta(meta(member))))
                .map_err(SevenZipError::Io)?;
            let link = is_link(member).then(|| rel.clone());
            if !self.publish(Staged {
                temporary,
                place,
                name,
                size: 0,
                ordinal: self.current,
                link,
                modified: self.opts.meta(meta(member)).modified(),
            })? {
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

    /// [`crate::extract::Options::keep_broken`]: a file that failed its CRC (already reported) takes its name with what
    /// was decoded, as a verified one would. Best effort: when that fails, it is removed as without the option.
    fn keep_broken(&mut self, (temporary, output): (tempfile::TempPath, Output), place: Place, member: &MapMember) {
        let meta = self.opts.meta(meta(member));
        if output.finish(|file| crate::extract::keep_written(file, &meta, None)).is_err() {
            return;
        }
        Self::put_kept(temporary, place);
    }

    /// A kept broken file takes its name: as a verified one would, never through a link; best effort.
    fn put_kept(temporary: tempfile::TempPath, place: Place) {
        let _ = match place.reserved {
            Some(reserved) if cfg!(unix) && !reserved.still_ours() => return,
            Some(reserved) => crate::output::replace(temporary, reserved.path()).map(|()| drop(reserved.into_parts())),
            None if place.replace => crate::output::replace_link(temporary, &place.path, place.link),
            None => temporary.persist_noclobber(&place.path).map_err(|error| error.error),
        };
    }

    /// Gives a verified file its name: replacing what is there only when that was asked for, never through a link.
    /// False when it was not published (already reported).
    fn publish(&mut self, staged: Staged) -> Outcome<bool> {
        let Staged { temporary, place, name, size, ordinal, link, modified } = staged;
        if let Some(rel) = link {
            // A symbolic link: its verified data is the target.
            let text = std::fs::read(&temporary).map_err(SevenZipError::Io)?;
            let kind = crate::extract::link::LinkKind::Symbolic(text);
            if let Some(why) = crate::extract::link::refusal_before_place(&rel, &kind, &self.extracted) {
                self.fail_at(ordinal, &name, why);
                return Ok(false);
            }
            drop(temporary);
            // the folders known so far are looked at again past a link
            self.dirs.forget();
            if let Err(e) =
                crate::extract::link::publish(&self.opts.dest, &rel, place, &kind, modified, &mut self.extracted)
            {
                if let Some(why) = crate::extract::link::member_failure(&e) {
                    self.fail_at(ordinal, &name, why);
                    return Ok(false);
                }
                return Err(SevenZipError::Io(e));
            }
            self.succeeded(ordinal, &name, 0);
            return Ok(true);
        }
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
            crate::output::replace_link(temporary, &place.path, place.link).map_err(SevenZipError::Io)?;
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
        // Options::seven_zip_strict: a folder decoded to its end has its coders' ends checked, as 7-Zip checks them;
        // what fails is the folder's damage, whatever its members' own checks said
        if complete {
            self.check_end(&mut active)?;
        }
        let good = complete && folder.crc32.is_none_or(|crc| crc == active.crc.clone().finalize());
        // An encrypted folder whose own CRC fails before any data proved the password did not decrypt.
        // a folder that decoded to its end and fails only its own CRC shows it as a CRC failure
        let wrong_password = active.wrong_password.or_else(|| {
            (!good && folder.cipher.is_some() && !self.password_proven).then(|| {
                if active.failed.is_some() { EncryptedFailure::DataError } else { EncryptedFailure::CrcFailed }
            })
        });
        let staged = std::mem::take(&mut active.staged);
        self.pending_links.clear();
        let tested = std::mem::take(&mut active.tested);
        let held = std::mem::take(&mut active.held);
        if !good {
            let why = active.failed.clone().unwrap_or_else(|| "checksum error in its solid block".to_owned());
            // Options::keep_broken: every member held for the folder decoded whole and only the folder's CRC failed:
            // they stay, as 7-Zip keeps them (not after a decode failure, and never a link)
            let staged = if self.opts.keep_broken && complete {
                let (kept, rest): (Vec<_>, Vec<_>) = staged.into_iter().partition(|s| s.link.is_none());
                let names: Vec<(u64, String)> = kept.iter().map(|s| (s.ordinal, s.name.clone())).collect();
                for s in kept {
                    Self::put_kept(s.temporary, s.place);
                }
                (rest, names)
            } else {
                (staged, Vec::new())
            };
            let (staged, kept_names) = staged;
            // kept or not, every member held for the folder failed with it
            let mut failed: Vec<(u64, &str)> = staged
                .iter()
                .map(|s| (s.ordinal, s.name.as_str()))
                .chain(kept_names.iter().map(|(o, n)| (*o, n.as_str())))
                .chain(tested.iter().map(|(n, _, o)| (*o, n.as_str())))
                .collect();
            failed.sort_by_key(|(o, _)| *o);
            // UnverifiedOutput::Emit: the printed members held for the folder's CRC print what they hold
            if self.unverified {
                for (ordinal, spool) in held {
                    let name = member_name(&self.map.members[ordinal as usize]);
                    self.print_unverified(ordinal, &name, spool)?;
                }
            } else {
                drop(held);
            }
            for (ordinal, name) in failed {
                if let Some(failure) = wrong_password {
                    self.fail_wrong_password(ordinal, name, failure);
                } else {
                    self.fail_at(ordinal, name, &why);
                }
            }
            return self.store.reset().map_err(SevenZipError::Io);
        }
        // A cancellation from an earlier member's outcome stops the deferred members still to come.
        let canceled = |run: &Self| if run.cancel.is_canceled() { Err(SevenZipError::Canceled) } else { Ok(()) };
        let unverified_held = std::mem::take(&mut active.unverified_held);
        for (ordinal, spool) in held {
            canceled(self)?;
            if unverified_held.contains(&ordinal) {
                let name = member_name(&self.map.members[ordinal as usize]);
                self.print_unverified(ordinal, &name, spool)?;
            } else {
                self.print_spooled(ordinal, spool)?;
            }
        }
        self.store.reset().map_err(SevenZipError::Io)?;
        for (name, size, ordinal) in tested {
            canceled(self)?;
            self.succeeded(ordinal, &name, size);
        }
        for staged in staged {
            canceled(self)?;
            self.publish(staged)?;
        }
        Ok(())
    }

    /// [`crate::extract::Options::seven_zip_strict`]: runs the folder's end checks (each coder's, inner ones first);
    /// the first that finds damage is the folder's [`FolderDamage`], reported as a line.
    fn check_end(&mut self, active: &mut Active) -> Outcome<()> {
        let mut found = None;
        // A coder's check may still read its input (an end block, a trailer), so checks run downstream first: a
        // coder's inputs were built, and their checks registered, before it.
        for check in active.checks.iter_mut().rev() {
            if self.cancel.is_canceled() {
                return Err(SevenZipError::Canceled);
            }
            match check() {
                Ok(None) => continue,
                Ok(Some(damage)) => found = Some(damage),
                // a decoder that ran out of memory says nothing about the data
                Err(e) if e.kind() == std::io::ErrorKind::OutOfMemory => return Err(SevenZipError::Io(e)),
                Err(e) => match Fault::of(e) {
                    Fault::Canceled => return Err(SevenZipError::Canceled),
                    Fault::Missing(path) => return Err(SevenZipError::MissingVolume(path)),
                    Fault::Input(e) => return Err(SevenZipError::Io(e)),
                    Fault::Data(_) | Fault::Truncated => {
                        found = Some((FolderDamageKind::DataError, "the folder's input does not decode to its end"))
                    }
                },
            }
            break;
        }
        active.checks.clear();
        if let Some((kind, detail)) = found {
            let damage = FolderDamage::new(active.index as u64, kind, detail);
            let line = damage.to_string();
            self.report.line(&line);
            self.summary.errors.push(line);
            self.summary.folder_damage.push(damage);
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
            threads: self.threads,
            spare: Default::default(),
            strict: self.strict,
            checks: Vec::new(),
        };
        let reader = coders::folder_reader(folder, &mut cx)?;
        let checks = std::mem::take(&mut cx.checks);
        self.active = Some(Active {
            index,
            reader,
            pos: 0,
            crc: crc32fast::Hasher::new(),
            failed: None,
            wrong_password: None,
            staged: Vec::new(),
            tested: Vec::new(),
            held: Vec::new(),
            unverified_held: Vec::new(),
            defer: folder.crc32.is_some() && folder.members > 1,
            checks,
        });
        Ok(())
    }

    /// Reads `len` bytes of the active folder into `out` (or nowhere), hashing them into `member_crc` as well.
    /// A data failure marks the folder failed and is returned as Ok(Some(why)); the run's own failures are errors.
    fn pump(
        &mut self,
        active: &mut Active,
        mut len: u64,
        mut out: Option<Dest<'_>>,
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
            match out.as_mut() {
                Some(Dest::File(out)) => out.write(bytes).map_err(SevenZipError::Io)?,
                Some(Dest::Spool(spool)) => self.store.write(spool, bytes, self.limits).map_err(SevenZipError::Io)?,
                None => {}
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
        self.drop_fresh_dirs();
        result
    }

    /// The folders the member's placing created, when it left nothing at its target (it failed before any file was
    /// kept): removed while empty, so a wrong password leaves no empty folders (7-Zip 26.06). A member held for its
    /// folder's CRC has its staged file in there, so its folders stay.
    fn drop_fresh_dirs(&mut self) {
        let Some((target, fresh)) = self.fresh_dirs.take() else { return };
        if std::fs::symlink_metadata(&target).is_ok() {
            return;
        }
        for dir in fresh {
            if std::fs::remove_dir(&dir).is_err() {
                break;
            }
        }
        // the folders known to exist are looked at again
        self.dirs.forget();
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
                if let Some(failure) = active.wrong_password {
                    self.fail_wrong_password(self.current, name, failure);
                } else {
                    self.fail(name, &why);
                }
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
        let mut target = match take {
            // printing writes no file, so the name needs no checking: it is only reported
            true if self.print.is_some() => Some((PathBuf::new(), None)),
            true => self.place(member, name)?,
            false => None,
        };
        let mut staged = match &target {
            Some((_, Some(place))) => Some(self.stage(place, size)?),
            _ => None,
        };
        // testing a link, or printing: the data is held back (see `Spool`) until it is checked
        let mut spool = match &target {
            Some((_, None)) if is_link(member) || self.print.is_some() => Some(Spool::default()),
            _ => None,
        };
        let mut crc = crc32fast::Hasher::new();
        let dest = match (staged.as_mut(), spool.as_mut()) {
            (Some((_, out)), _) => Some(Dest::File(out)),
            (None, Some(spool)) => Some(Dest::Spool(spool)),
            (None, None) => None,
        };
        let outcome = self.pump(active, size, dest, Some(&mut crc))?;
        if let Some(why) = outcome {
            if let Some(mut spool) = spool.take() {
                if self.unverified && !spool.over {
                    // UnverifiedOutput::Emit: what decoded before the failure, as 7-Zip streams it
                    self.emit_failed(active, name, spool)?;
                } else {
                    self.store.release(&mut spool).map_err(SevenZipError::Io)?;
                }
            }
            return self.data_failure(active, name, &why, encrypted, take);
        }
        if encrypted && member.checks.and_then(|c| c.crc32).is_none() && !active.defer && !self.password_proven {
            // Nothing could tell decrypted garbage from the data: with a wrong password it would be published.
            if let Some(spool) = spool.as_mut() {
                self.store.release(spool).map_err(SevenZipError::Io)?;
            }
            if take {
                self.fail(name, "encrypted without a CRC, and no password proven yet: cannot be verified");
            }
            return Ok(());
        }
        let crc_ok = member.checks.and_then(|c| c.crc32).is_none_or(|want| want == crc.finalize());
        if !crc_ok {
            if let Some(mut spool) = spool.take() {
                if self.unverified && !spool.over {
                    // UnverifiedOutput::Emit: everything decoded, as 7-Zip streams a member failing its CRC
                    self.emit_failed(active, name, spool)?;
                } else {
                    self.store.release(&mut spool).map_err(SevenZipError::Io)?;
                }
            }
            // Options::keep_broken: what was decoded stays, as 7-Zip keeps a file that fails its CRC (a wrong
            // password's garbage included); reported failed all the same
            if let (Some(staged), Some((_, Some(place)))) = (staged.take(), target.take())
                && self.opts.keep_broken
                && !is_link(member)
            {
                self.keep_broken(staged, place, member);
            }
            if encrypted && !self.password_proven {
                // Decrypted garbage: the password does not open this folder. The rest of the folder fails the same
                // way; the run goes on with the other folders.
                return self.wrong_password(active, name, take, EncryptedFailure::CrcFailed);
            }
            if take {
                self.fail(name, &crate::Error::BadChecksum(name.to_owned()).to_string());
            }
            return Ok(());
        }
        if encrypted && member.checks.and_then(|c| c.crc32).is_some() {
            self.password_proven = true;
        }
        let Some((rel, place)) = target else {
            if let Some(spool) = spool.as_mut() {
                self.store.release(spool).map_err(SevenZipError::Io)?;
            }
            return Ok(());
        };
        if spool.as_ref().is_some_and(|s| s.over) {
            // held back too much to be checked: it fails, and nothing of it is printed or tested
            let max = self.limits.spool_member_bytes;
            self.fail(name, &super::limit(super::SevenZipLimit::SpoolBytes, max, size).to_string());
            return Ok(());
        }
        if self.print.is_some() {
            let spool = spool.take().expect("a spooled member");
            // A folder with its own CRC vouches for its members at its end: printed then, in order.
            if active.defer {
                active.held.push((self.current, spool));
                active.tested.push((name.to_owned(), size, self.current));
            } else {
                self.print_spooled(self.current, spool)?;
                self.succeeded(self.current, name, size);
            }
            return Ok(());
        }
        let Some(place) = place else {
            // Testing a link checks its target as extracting would.
            if let Some(mut spool) = spool.take() {
                let mut text = Vec::new();
                let replayed = self.store.replay(&spool, self.cancel, |bytes| {
                    text.extend_from_slice(bytes);
                    Ok(())
                });
                self.store.release(&mut spool).map_err(SevenZipError::Io)?;
                replayed?;
                let kind = crate::extract::link::LinkKind::Symbolic(text);
                if let Some(why) = crate::extract::link::refusal(&rel, &kind, &self.extracted) {
                    self.fail(name, why);
                    return Ok(());
                }
            }
            // Testing: checked, nothing to write; a folder with its own CRC vouches for it at its end.
            if active.defer {
                active.tested.push((name.to_owned(), size, self.current));
            } else {
                self.succeeded(self.current, name, size);
            }
            return Ok(());
        };
        let (temporary, output) = staged.take().expect("a staged output");
        output
            .finish(|file| crate::extract::finish_file(file, &self.opts.meta(meta(member))))
            .map_err(SevenZipError::Io)?;
        let link = is_link(member).then_some(rel);
        let staged = Staged {
            temporary,
            place,
            name: name.to_owned(),
            size,
            ordinal: self.current,
            link,
            modified: self.opts.meta(meta(member)).modified(),
        };
        if active.defer {
            if let Some(link) = &staged.link {
                // Only a link that will occupy its path holds it: one refused without a placeholder leaves nothing.
                // Held by the output path chosen for it (a rename mode may have moved it), not by its archive name.
                let text = std::fs::read(&staged.temporary).map_err(SevenZipError::Io)?;
                let kind = crate::extract::link::LinkKind::Symbolic(text);
                if crate::extract::link::refusal_before_place(link, &kind, &self.extracted).is_none() {
                    let out = staged.place.path.strip_prefix(&self.opts.dest).unwrap_or(link).to_path_buf();
                    self.pending_links.push(out);
                }
            }
            active.staged.push(staged);
        } else {
            self.publish(staged)?;
        }
        Ok(())
    }

    /// [`crate::extract::UnverifiedOutput::Emit`]: a failing member's data, printed now, or behind the members of its
    /// folder still held for the folder's CRC, so that the output stays in archive order.
    fn emit_failed(&mut self, active: &mut Active, name: &str, spool: Spool) -> Outcome<()> {
        if active.held.is_empty() {
            return self.print_unverified(self.current, name, spool);
        }
        active.held.push((self.current, spool));
        active.unverified_held.push(self.current);
        Ok(())
    }

    /// [`crate::extract::UnverifiedOutput::Emit`]: copies a failing member's held-back data to the print sink and
    /// notes it in [`Summary::unverified`] (the member's failure is reported as without it).
    fn print_unverified(&mut self, ordinal: u64, name: &str, spool: Spool) -> Outcome<()> {
        let bytes = spool.len;
        self.print_spooled(ordinal, spool)?;
        if bytes != 0 {
            self.summary.unverified.push(crate::extract::UnverifiedMember::new(ordinal, name, bytes));
        }
        Ok(())
    }

    /// Copies a checked member's held-back data to the print sink.
    fn print_spooled(&mut self, ordinal: u64, mut spool: Spool) -> Outcome<()> {
        let Run { print, store, cancel, .. } = self;
        let result = match print.as_mut() {
            Some(sink) => store.replay(&spool, cancel, |bytes| sink(ordinal, bytes)),
            None => Ok(()),
        };
        store.release(&mut spool).map_err(SevenZipError::Io)?;
        result
    }

    fn data_failure(&mut self, active: &mut Active, name: &str, why: &str, encrypted: bool, take: bool) -> Outcome<()> {
        if encrypted && !self.password_proven {
            return self.wrong_password(active, name, take, EncryptedFailure::DataError);
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

/// Whether a member is a Unix symbolic link (`S_IFLNK` in the attributes' high bits).
fn is_link(member: &MapMember) -> bool {
    member.unix_mode.is_some_and(|mode| mode & S_IFMT == S_IFLNK)
}

#[cfg(test)]
mod spool_tests {
    use super::*;

    fn limits(memory: u64) -> SevenZipLimits {
        SevenZipLimits { spool_memory_bytes: memory, ..SevenZipLimits::default() }
    }

    fn data(member: usize) -> Vec<u8> {
        (0..100).map(|i| (member * 7 + i) as u8).collect()
    }

    fn replayed(store: &mut SpoolStore, spool: &Spool) -> Vec<u8> {
        let mut out = Vec::new();
        store
            .replay(spool, &Cancellation::default(), |b| {
                out.extend_from_slice(b);
                Ok(())
            })
            .unwrap();
        out
    }

    /// Members held back together share one memory budget: past it they go to the run's one file, and each still
    /// reads back exactly.
    #[test]
    fn held_members_share_one_memory_budget_and_spill_to_the_file() {
        let limits = limits(4096);
        let mut store = SpoolStore::default();
        let mut held = Vec::new();
        for member in 0..1000 {
            let mut spool = Spool::default();
            store.write(&mut spool, &data(member)[..60], &limits).unwrap();
            store.write(&mut spool, &data(member)[60..], &limits).unwrap();
            assert!(store.memory <= 4096, "memory {} after member {member}", store.memory);
            held.push(spool);
        }
        // about 40 members fit in memory; the rest are in the file
        assert!(store.len >= (1000 - 41) * 100, "file holds {}", store.len);
        for (member, spool) in held.iter_mut().enumerate() {
            assert_eq!(replayed(&mut store, spool), data(member), "member {member}");
            store.release(spool).unwrap();
        }
        assert_eq!(store.memory, 0);
        store.reset().unwrap();
        assert_eq!(store.len, 0);
    }

    /// However many members are held on disk, the run keeps one descriptor open for them.
    #[cfg(unix)]
    #[test]
    fn many_members_on_disk_use_one_descriptor() {
        let open_fds =
            || std::fs::read_dir(if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" }).unwrap().count();
        let limits = limits(0);
        let mut store = SpoolStore::default();
        let mut first = Spool::default();
        store.write(&mut first, &data(0), &limits).unwrap();
        let before = open_fds();
        let mut held = vec![first];
        for member in 1..5000 {
            let mut spool = Spool::default();
            store.write(&mut spool, &data(member), &limits).unwrap();
            held.push(spool);
        }
        // other tests open files concurrently: allow a little slack, far below 5000
        assert!(open_fds() <= before + 16, "{} descriptors before, {} after", before, open_fds());
        for member in [0, 1, 2500, 4999] {
            assert_eq!(replayed(&mut store, &held[member]), data(member), "member {member}");
        }
    }

    /// Lengths of 4 GiB and more give a full chunk, as smaller ones do (a 32-bit `usize` cast first would truncate
    /// them to nothing or to a sliver).
    #[test]
    fn chunk_lengths_take_the_minimum_before_narrowing() {
        for left in [0u64, 1, CHUNK as u64 - 1, CHUNK as u64, 1 << 32, (1 << 32) + 5, u64::MAX] {
            assert_eq!(chunk_len(left) as u64, left.min(CHUNK as u64), "{left}");
        }
        assert_eq!(chunk_len(1 << 32), CHUNK);
    }

    /// A cancel that arrives during the last chunk of a member held in memory is reported, as it is from the file.
    #[test]
    fn a_cancel_on_the_last_chunk_is_reported() {
        let limits = limits(1 << 20);
        let mut store = SpoolStore::default();
        let mut spool = Spool::default();
        store.write(&mut spool, b"short member", &limits).unwrap();
        let cancel = Cancellation::default();
        let result = store.replay(&spool, &cancel, |_| {
            cancel.cancel();
            Ok(())
        });
        assert!(matches!(result, Err(SevenZipError::Canceled)));
    }
}
