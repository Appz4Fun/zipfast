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

//! Lists, tests and extracts an archive. RAR 5.0 lives here: its volumes are followed in order and compressed files
//! decoded. Other formats have modules of their own.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::batch::{self, Batch, Done, Job, JobData, Outcome};
use crate::blake2sp::Blake2sp;
use crate::error::{Error, RarPasswordEvidence, RarScope, Result};
use crate::output::{Output, temporary};
use crate::path::sanitize;
use crate::rar5::member::{CipherBlocks, MemberMachine, PendingCipher};
use crate::rar5::reader::{Block, ReadDataError, SIGNATURE_PROBE_BYTES, Volume, signature_end};
use crate::rar5::unpack::rar4::{Rar4DecodeError, Rar4Decoder};
use crate::rar5::unpack::{Sink, Unpacker, window_for_detailed};
use crate::rar5::{FileHeader, MemberCrypt, RarFormat, Redirection};
use crate::volume::next_volume;
use crate::zip::{InspectionSource, ReadSession, SessionResult};

pub(crate) mod link;
mod rar_outcome;
mod rename;
use crate::error::{
    IoOperation, RarFailure, RarFault, RarIntegrityReason, RarInternal, RarPolicyReason, RarResource, RarUnsupported,
};
pub(crate) use rar_outcome::{EntryContext, RunResult};
pub use rar_outcome::{
    RarEntryIdentity, RarEntryOutcome, RarMatchState, RarOutcome, RarOutput, RarRunError, RarRunSummary, RarSkipReason,
    RarVerification,
};
use rar_outcome::{Reports, RunFault};
pub use rename::{RENAME_LIMIT, RENAME_NAME_MAX, RenameStyle, RenamedOutput, RunError, renamed_name};
pub(crate) use rename::{
    RUN_RENAME_ATTEMPTS, RenameBudget, RenameError, RenameMode, Reserved, claim_candidate, rename_noreplace,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// read every file and check it, write nothing
    Test,
    /// write every file under the destination
    Extract,
}

/// What extraction does when a member's target already exists.
///
/// The enum is `#[non_exhaustive]`: matches on it need a wildcard arm. The two rename modes were added after `Skip`
/// and `Always`, so an exhaustive match written before them no longer compiles.
///
/// Every mode refuses a symlink at the target (never followed or replaced). `Skip` leaves anything else alone;
/// `Always` also refuses a directory and a protected path or an alias of one ([`Options::protected_paths`], the
/// archive and its volumes). The rename modes follow 7-Zip 26.06: `RenameNew` leaves a directory or protected input at
/// the target alone and writes the member at a renamed name (`self.zip` extracted beside itself becomes
/// `self_1.zip`), while `RenameExisting` moves a directory aside with its contents, as it moves a file, but refuses a
/// protected path, and a directory holding one (the archive, say), rather than move it. A rename mode never
/// replaces anything: the renamed name is claimed with a create-new or no-replace primitive, never chosen by looking
/// first, so two members (or another process) can't be handed the same name. A renamed name is in the same folder as
/// the requested one and follows the same containment rules. Folder members are never renamed: an existing folder is
/// reused as with the other modes.
///
/// Runs report each rename as a [`RenamedOutput`]: [`Summary::renames`], [`RarRunSummary::renames`] (kept in a
/// terminal error's `partial`, and each also delivered with its member's outcome as [`RarEntryOutcome::renamed`]),
/// [`RunError::renames`] from [`run_with_renames`], and
/// [`crate::zip::ZipRunEvent::MemberRenamed`] for [`run_with_zip_policy`] and [`run_with_zip_context`], sent as each
/// rename is made. The legacy report callback of [`run`] and [`run_with_password`] gets a line for each rename as
/// it is made, so a run that stops with an error still says where moved files went.
///
/// Running out of names, and `RenameExisting` on a file system with neither a no-replace rename nor hard links
/// (FAT, exFAT: [`crate::error::RarPolicyReason::RenameUnsupported`]), fail only that member. A name too long to
/// number has its stem shortened to fit `NAME_MAX` (see [`renamed_name`]). Progressive
/// and persistent-partial sessions refuse the rename modes with `FailureKind::InvalidCapability` before doing
/// anything, and so does `ZipReadStage::prepare_file` (with `ReadFault::InvalidPlan`), which has no report to name
/// the file in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Overwrite {
    /// leave a file that is already there alone
    #[default]
    Skip,
    /// replace a file that is already there, once the new one is verified
    Always,
    /// Write the member under the first free renamed name (`a_1.txt`, `a_2.txt`, ... or `a(1).txt`, ...), leaving
    /// the existing file, folder or protected input alone: 7-Zip's `-aou` with [`RenameStyle::Underscore`], UnRAR's `-or` with
    /// [`RenameStyle::Parenthesized`]. Members with the same name in one run take the next free number each.
    RenameNew(RenameStyle),
    /// Move the existing file or folder to the first free renamed name, then write the member at its own name:
    /// 7-Zip's `-aot`.
    /// The existing file is moved with a no-replace rename, so it always has a name; if writing the member fails
    /// afterwards, it stays at the renamed name and [`RenamedOutput::existing`] says where.
    RenameExisting(RenameStyle),
}

impl Overwrite {
    pub(crate) fn rename(self) -> Option<RenameMode> {
        match self {
            Self::RenameNew(style) => Some(RenameMode::New(style)),
            Self::RenameExisting(style) => Some(RenameMode::Existing(style)),
            Self::Skip | Self::Always => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub mode: Mode,
    pub dest: PathBuf,
    pub overwrite: Overwrite,
    /// drop the stored folders and write every file straight into the destination
    pub flatten: bool,
    /// threads to decode with, counting the one that writes the output; None for one per core
    pub threads: Option<usize>,
    /// Additional existing paths to preserve. Extraction also protects its archive and RAR volumes.
    pub protected_paths: HashSet<PathBuf>,
    /// the smallest file decoded on several threads; None for the decoder's default
    #[doc(hidden)]
    pub parallel_min: Option<u64>,
    /// Which members to test or extract. `None` takes every member.
    ///
    /// Only the whole-archive runners apply it: [`run`], [`run_with_password`], [`run_with_zip_policy`],
    /// [`run_with_zip_context`], [`run_rar_with_outcomes`] and the format runners they dispatch to (`zip::run*`,
    /// `tar::run`). There the filter is asked once per member, in archive order, before anything about that member is
    /// checked, written or counted; see [`MemberFilter`] for what an unselected member means for each format.
    ///
    /// Runs that choose members their own way refuse `Some` before doing anything:
    /// `RarSession::extract_selected` and `extract_selected_controlled` fail with
    /// `RarFailure::Unsupported(RarUnsupported::MemberFilter)`, progressive and persistent-partial sessions with
    /// `FailureKind::InvalidCapability`, and `ZipReadStage::prepare_file` with `ReadFault::InvalidPlan`.
    pub select: Option<MemberFilter>,
}

/// One member as a [`MemberFilter`] sees it.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct MemberRef<'a> {
    /// The member's name as [`list`] reports it: decoded to text, before any output path policy.
    pub name: &'a str,
    /// The name's bytes exactly as stored, when they differ from `name` and the reader kept them. `None` means `name`
    /// is all the reader keeps. Today only tar sets it, for a ustar or GNU long name that isn't UTF-8.
    pub raw_name: Option<&'a [u8]>,
    /// The member is a folder.
    pub is_dir: bool,
    /// Zero-based position of the member in what [`list`] returns for the same archive.
    pub ordinal: u64,
}

impl MemberRef<'_> {
    /// The stored name's bytes: `raw_name` when kept, else the decoded name's UTF-8.
    pub fn name_bytes(&self) -> &[u8] {
        self.raw_name.unwrap_or(self.name.as_bytes())
    }
}

/// A predicate choosing which members a whole-archive run tests or extracts. Runs with their own member selection
/// refuse it; see [`Options::select`].
///
/// Every format a whole-archive run reads applies it the same way:
///
/// - An unselected member is neither written nor tested, and it is left out of every count, message and outcome.
///   [`Summary::matched`], [`RarRunSummary::matched`] and [`crate::zip::ZipRunReport::matched`] count the members the
///   filter took, so a caller can tell a run that matched nothing from one that failed. A run that matches nothing
///   succeeds with zero files.
/// - Folder entries are offered too, with `is_dir` set. An unselected folder entry is not created and its times and
///   permissions are not restored, but the folders above a selected file are still made so the file can be written.
/// - Path safety, overwrite and protected-path checks apply to selected members exactly as without a filter. An
///   unselected member is never written, not even as an empty file.
/// - ZIP does not read or decompress an unselected member. Plain tar seeks past it. Compressed tar decodes through
///   it, since the stream can only be read in order.
/// - In a solid RAR archive an unselected compressed member that a later member may depend on is still decoded, to
///   keep the dictionary history, but it is not checked against its checksums, counted or reported. Its failure to
///   decode is reported on the next selected member that needed it, as with a member skipped because its target
///   exists.
/// - A RAR continuation part whose first part isn't in the set has no listing position, so the filter is not asked
///   about it. It is handled as before (reported as [`RarSkipReason::MissingStart`], or taken as a member of its own
///   after a different member that was missing its next part) only when there is no filter; with one, it is passed
///   over.
///
/// ```
/// use zipfast::extract::{MemberFilter, Mode, Options, Overwrite};
///
/// let opts = Options {
///     mode: Mode::Test,
///     dest: "out".into(),
///     overwrite: Overwrite::Skip,
///     flatten: false,
///     threads: None,
///     protected_paths: Default::default(),
///     parallel_min: None,
///     select: Some(MemberFilter::new(|m| m.is_dir || m.name.ends_with(".txt"))),
/// };
/// assert!(format!("{opts:?}").contains("MemberFilter(..)"));
/// ```
#[derive(Clone)]
pub struct MemberFilter {
    filter: Arc<dyn Fn(&MemberRef<'_>) -> bool + Send + Sync>,
    start: Option<StartHook>,
}

/// The hook [`MemberFilter::on_start`] keeps.
type StartHook = Arc<dyn Fn(&MemberStart<'_>) -> StartDecision + Send + Sync>;

/// A selected member about to be written, as [`MemberFilter::on_start`] sees it.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct MemberStart<'a> {
    /// Where the member is written: the final output path, after a rename mode chose its name.
    pub path: &'a Path,
}

/// What [`MemberFilter::on_start`] decides for a member about to be written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StartDecision {
    /// Write it.
    Write,
    /// Don't: nothing is written for it, a renamed name it claimed is let go, and it is reported as skipped
    /// ([`RarSkipReason::Declined`] on typed RAR runs, "declined, skipped" on report lines).
    Skip,
}

impl MemberFilter {
    pub fn new(filter: impl Fn(&MemberRef<'_>) -> bool + Send + Sync + 'static) -> Self {
        Self { filter: Arc::new(filter), start: None }
    }

    /// A filter that takes every member, for use with [`MemberFilter::on_start`] alone.
    pub fn all() -> Self {
        Self::new(|_| true)
    }

    /// Adds a hook asked about each selected member, in archive order, as it starts to be written: once its output
    /// path is final (after the overwrite choice and any rename mode's renaming) and before anything is written for
    /// it. Unlike the filter, which runs as members are listed, this sees only members that will really be written,
    /// so a caller can count them or limit them in order.
    ///
    /// It runs on extraction (not [`Mode::Test`]) of tar, lone compressed files, the legacy ZIP route, 7z and RAR
    /// whole-archive runs, and the checked ZIP route of [`run_with_policy`](crate::extract::run_with_policy). On
    /// the checked ZIP route a rename mode picks its name only when the member is published, so there the hook sees
    /// the requested path. Folders and members whose target is skipped or blocked don't call it.
    pub fn on_start(mut self, hook: impl Fn(&MemberStart<'_>) -> StartDecision + Send + Sync + 'static) -> Self {
        self.start = Some(Arc::new(hook));
        self
    }

    /// Whether the filter takes `member`.
    pub fn selects(&self, member: &MemberRef<'_>) -> bool {
        (self.filter)(member)
    }

    /// What the start hook decides for a member about to be written; [`StartDecision::Write`] without one.
    pub fn starts(&self, member: &MemberStart<'_>) -> StartDecision {
        self.start.as_ref().map_or(StartDecision::Write, |hook| hook(member))
    }
}

impl From<Arc<dyn Fn(&MemberRef<'_>) -> bool + Send + Sync>> for MemberFilter {
    fn from(filter: Arc<dyn Fn(&MemberRef<'_>) -> bool + Send + Sync>) -> Self {
        Self { filter, start: None }
    }
}

impl std::fmt::Debug for MemberFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemberFilter(..)")
    }
}

impl Options {
    /// Whether a run takes this member: always without a filter.
    pub(crate) fn selects(&self, name: &str, raw_name: Option<&[u8]>, is_dir: bool, ordinal: u64) -> bool {
        self.select.as_ref().is_none_or(|filter| filter.selects(&MemberRef { name, raw_name, is_dir, ordinal }))
    }

    pub(crate) fn protecting(&self, input: &Path) -> Result<Cow<'_, Self>> {
        self.protecting_detailed(input).map_err(RarFault::into_legacy)
    }

    fn protecting_detailed(&self, input: &Path) -> crate::error::RarResult<Cow<'_, Self>> {
        if self.mode != Mode::Extract {
            return Ok(Cow::Borrowed(self));
        }
        let mut opts = self.clone();
        for path in &self.protected_paths {
            if let Ok(canonical) = path.canonicalize() {
                opts.protected_paths.insert(canonical);
            }
        }
        let canonical = input
            .canonicalize()
            .map_err(|e| RarFault::input(IoOperation::Metadata, Some(input.to_path_buf()), None, e))?;
        opts.protected_paths.insert(canonical);
        Ok(Cow::Owned(opts))
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub skipped: u64,
    /// Members (files and folders) taken by [`Options::select`], whatever became of them: every member when there is
    /// no filter. Zero means nothing matched.
    pub matched: u64,
    /// one line per file that failed
    pub errors: Vec<String>,
    pub volumes: u64,
    /// Members renamed by [`Overwrite::RenameNew`] or [`Overwrite::RenameExisting`], in the order the names were
    /// claimed. Empty for the other modes.
    pub renames: Vec<RenamedOutput>,
    /// the rename attempts this run has left
    pub(crate) rename_budget: RenameBudget,
    /// folders whose times and permissions are set once everything inside them is written
    pub(crate) dir_meta: Vec<(PathBuf, Meta)>,
}

/// What is restored on an extracted file or folder besides its data.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Meta {
    /// seconds since 1970
    pub mtime: Option<i64>,
    pub nanos: u32,
    /// Unix permission bits, when the archive was made on a Unix system
    pub mode: Option<u32>,
}

impl From<&FileHeader> for Meta {
    fn from(h: &FileHeader) -> Self {
        Meta { mtime: h.mtime, nanos: h.mtime_nanos, mode: h.is_unix().then_some(h.attributes as u32) }
    }
}

/// Where a file's data is to go, once the destination has been checked.
pub(crate) enum Target {
    Write(Output),
    /// already there and not to be overwritten
    Exists,
    /// the start hook declined the member
    Declined,
    /// something else stands in the way
    Blocked(&'static str),
}

/// A checked output path. A replacement is staged until verification.
pub(crate) struct Place {
    pub path: PathBuf,
    pub replace: bool,
    /// The file already created at `path` by a rename mode, to be written in place.
    pub reserved: Option<Reserved>,
}

impl Place {
    fn new(path: PathBuf, replace: bool) -> Self {
        Self { path, replace, reserved: None }
    }

    fn reserved(reserved: Reserved) -> Self {
        Self { path: reserved.path().to_path_buf(), replace: false, reserved: Some(reserved) }
    }
}

/// What [`check_target`] found.
pub(crate) enum Checked {
    Write(Place),
    Exists,
    /// the start hook declined the member
    Declined,
    Blocked(&'static str),
}

/// Prepares the output file for `rel`: makes its folders, honours the overwrite choice, and never writes through a
/// link left at the target. `size` is preallocated when known.
pub(crate) fn open_target(opts: &Options, rel: &Path, size: Option<u64>, log: &mut RenameLog<'_>) -> Result<Target> {
    Ok(match check_target(opts, rel, None, log)? {
        Checked::Write(place) => Target::Write(create_target(place, size)?),
        Checked::Exists => Target::Exists,
        Checked::Declined => Target::Declined,
        Checked::Blocked(why) => Target::Blocked(why),
    })
}

/// The folders one run has made or checked, so each is looked at once.
#[derive(Default)]
pub(crate) struct Dirs {
    /// each folder, and whether this run made it
    known: HashMap<PathBuf, bool>,
    /// every path this run has written or made, in lower case
    taken: HashSet<String>,
    /// a name was seen that a file system may take as another spelling of a different one, so from then on every
    /// target is looked for
    unsure: bool,
}

/// The first half of [`open_target`]: makes the folders and checks the target, without creating it. With `dirs`,
/// folders are made only once, and a file in a folder this run made is not looked for, since nothing can be there
/// that the run did not put there.
pub(crate) fn check_target(
    opts: &Options,
    rel: &Path,
    dirs: Option<&mut Dirs>,
    log: &mut RenameLog<'_>,
) -> Result<Checked> {
    check_target_detailed(opts, rel, dirs, log)
        .map(|result| match result {
            DetailedChecked::Write(place) => Checked::Write(place),
            DetailedChecked::Exists => Checked::Exists,
            DetailedChecked::Declined => Checked::Declined,
            DetailedChecked::Blocked(reason) => Checked::Blocked(blocked_message(&reason)),
        })
        .map_err(RarFault::into_legacy)
}

enum DetailedChecked {
    Write(Place),
    Exists,
    Declined,
    Blocked(RarPolicyReason),
}

fn blocked_message(reason: &RarPolicyReason) -> &'static str {
    match reason {
        RarPolicyReason::Symlink => "a symlink is in the way",
        RarPolicyReason::Directory => "a folder is in the way",
        RarPolicyReason::ProtectedInput => "the output path would replace a protected input",
        RarPolicyReason::RenameExhausted => "no free name to rename to",
        RarPolicyReason::RenameUnsupported => "the file system can't rename without replacing",
        RarPolicyReason::LinkTarget => "the link's target is absolute or leads out of the destination",
        _ => unreachable!("unexpected target policy"),
    }
}

/// Where a run's rename mode records its renames, and the attempts it may still make.
pub(crate) struct RenameLog<'a> {
    pub(crate) budget: &'a mut RenameBudget,
    /// called once per rename, as soon as it is made
    pub(crate) record: &'a mut dyn FnMut(RenamedOutput),
}

/// The runners whose callers read plain report lines; a rename mode's renames reach the caller as they happen too.
pub(crate) trait LegacyReport {
    fn line(&mut self, line: &str);
    fn renamed(&mut self, _renamed: &RenamedOutput) {}
    /// A rename made for the member at `ordinal` (its listing index), when the runner knows it.
    fn renamed_member(&mut self, _ordinal: u64, renamed: &RenamedOutput) {
        self.renamed(renamed)
    }
    /// A member finished, as soon as it did: from the runners that report members one by one (tar and lone
    /// compressed streams).
    fn member(&mut self, _member: LegacyMember<'_>) {}
}

/// How a member ended, for [`LegacyReport::member`]. `ordinal` is the member's listing index.
pub(crate) enum LegacyMember<'a> {
    Succeeded { ordinal: u64, name: &'a str, bytes: u64 },
    Skipped { ordinal: u64, name: &'a str },
    Failed { ordinal: u64, name: &'a str, error: Error },
}

/// The error a run stopped with when its [`Cancellation`] was triggered.
pub(crate) fn canceled_error() -> Error {
    Error::Io(canceled_io())
}

/// The marker a [`Cancellation`] puts in the I/O errors it causes, so they are told from any other aborted I/O.
#[derive(Debug)]
struct Canceled;

impl std::fmt::Display for Canceled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation canceled")
    }
}

impl std::error::Error for Canceled {}

/// The I/O error of a run stopping for its [`Cancellation`].
pub(crate) fn canceled_io() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, Canceled)
}

/// Whether `error` is a run stopping for its [`Cancellation`] (see [`Cancellation::check_io`]).
fn is_cancellation(error: &Error) -> bool {
    matches!(error, Error::Io(e) if e.get_ref().is_some_and(|inner| inner.is::<Canceled>()))
}

impl<F: FnMut(&str)> LegacyReport for F {
    fn line(&mut self, line: &str) {
        self(line)
    }
    fn renamed(&mut self, renamed: &RenamedOutput) {
        self(&renamed.line())
    }
}

/// With a rename mode, the returned place already holds the file, created with `O_EXCL` (see [`place_renamed`]), and
/// any rename goes to `log`. A place to write is offered to the filter's start hook last.
fn check_target_detailed(
    opts: &Options,
    rel: &Path,
    dirs: Option<&mut Dirs>,
    log: &mut RenameLog<'_>,
) -> crate::error::RarResult<DetailedChecked> {
    let Some(filter) = opts.select.as_ref().filter(|f| f.start.is_some()) else {
        return place_target(opts, rel, dirs, log);
    };
    // Hold this member's renames until the hook decides: a declined one must leave no trace of a new name.
    let budget = log.budget.left();
    let mut held = Vec::new();
    let checked = place_target(opts, rel, dirs, &mut RenameLog { budget: log.budget, record: &mut |r| held.push(r) })?;
    if let DetailedChecked::Write(place) = &checked
        && filter.starts(&MemberStart { path: &place.path }) == StartDecision::Skip
    {
        if matches!(opts.overwrite.rename(), Some(rename::RenameMode::Existing(_))) {
            // what was at the name was really moved aside: that rename stands
            held.into_iter().for_each(|r| (log.record)(r));
        } else {
            // the new name a rename claimed is let go with the place, and its attempts are given back
            log.budget.restore(budget);
        }
        return Ok(DetailedChecked::Declined);
    }
    held.into_iter().for_each(|r| (log.record)(r));
    Ok(checked)
}

fn place_target(
    opts: &Options,
    rel: &Path,
    mut dirs: Option<&mut Dirs>,
    log: &mut RenameLog<'_>,
) -> crate::error::RarResult<DetailedChecked> {
    let target = opts.dest.join(rel);
    let rename = opts.overwrite.rename();
    if let Some(parent) = rel.parent() {
        match dirs.as_deref_mut() {
            Some(dirs) => {
                make_dirs_known_detailed(&opts.dest, parent, dirs)?;
                let first = dirs.note(rel);
                if rename.is_none() && first && dirs.known.get(parent) == Some(&true) {
                    return Ok(DetailedChecked::Write(Place::new(target, false)));
                }
            }
            None => make_dirs_detailed(&opts.dest, parent)?,
        }
    }
    if let Some(mode) = rename {
        return place_renamed(opts, target, rel, mode, dirs, log);
    }
    let metadata = |e| RarFault::output(IoOperation::Metadata, Some(target.clone()), None, e, false);
    Ok(match fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_symlink() => DetailedChecked::Blocked(RarPolicyReason::Symlink),
        Ok(_) if opts.overwrite == Overwrite::Skip => DetailedChecked::Exists,
        Ok(meta) if meta.is_dir() => DetailedChecked::Blocked(RarPolicyReason::Directory),
        Ok(_)
            if !opts.protected_paths.is_empty()
                && opts.protected_paths.contains(&target.canonicalize().map_err(metadata)?) =>
        {
            DetailedChecked::Blocked(RarPolicyReason::ProtectedInput)
        }
        Ok(_) => DetailedChecked::Write(Place::new(target, true)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DetailedChecked::Write(Place::new(target, false)),
        Err(e) => return Err(metadata(e)),
    })
}

/// Claims the output file for a rename mode, whose parent folders are already made and checked.
///
/// The requested name is created with `O_EXCL` first. When it is taken, a symlink there is refused. Otherwise
/// `RenameNew` creates the first free renamed name with `O_EXCL`, leaving what is at the requested name alone, even a
/// folder or a protected input (7-Zip's `-aou` writes `self.zip` beside the archive as `self_1.zip`). `RenameExisting`
/// moves what is there, a file or a folder with its contents, to the first free renamed name with a no-replace rename
/// and then creates the requested name with `O_EXCL` (7-Zip's `-aot`); it refuses a protected input, and a folder that
/// holds one (the archive, say), since that would move it. A candidate that is a protected path is passed over.
/// Nothing is ever replaced, and the file this returns is new and empty. A folder moved aside is forgotten by `dirs`,
/// so a later member under its old name makes the folder again.
///
/// Running out of names (or of the run's rename attempts) and a file system that can't move without replacing are
/// this member's failure ([`DetailedChecked::Blocked`]), not the run's.
fn place_renamed(
    opts: &Options,
    target: PathBuf,
    rel: &Path,
    mode: RenameMode,
    dirs: Option<&mut Dirs>,
    log: &mut RenameLog<'_>,
) -> crate::error::RarResult<DetailedChecked> {
    let create = |path: &Path, e| RarFault::output(IoOperation::CreateFile, Some(path.to_path_buf()), None, e, false);
    let metadata = |path: &Path, e| RarFault::output(IoOperation::Metadata, Some(path.to_path_buf()), None, e, false);
    match Reserved::create(&target) {
        Ok(reserved) => return Ok(DetailedChecked::Write(Place::reserved(reserved))),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(create(&target, e)),
    }
    let meta = fs::symlink_metadata(&target).map_err(|e| metadata(&target, e))?;
    if meta.file_type().is_symlink() {
        return Ok(DetailedChecked::Blocked(RarPolicyReason::Symlink));
    }
    if let RenameMode::Existing(_) = mode {
        let canonical = target.canonicalize().map_err(|e| metadata(&target, e))?;
        if is_protected(opts, &canonical) || meta.is_dir() && holds_protected(opts, &canonical) {
            return Ok(DetailedChecked::Blocked(RarPolicyReason::ProtectedInput));
        }
    }
    let parent = target.parent().and_then(|p| p.canonicalize().ok());
    let skip = |candidate: &Path| {
        is_protected(opts, candidate)
            || parent.as_ref().is_some_and(|p| candidate.file_name().is_some_and(|n| is_protected(opts, &p.join(n))))
    };
    let failed = |error| match error {
        RenameError::Exhausted => Ok(DetailedChecked::Blocked(RarPolicyReason::RenameExhausted)),
        RenameError::Unsupported => Ok(DetailedChecked::Blocked(RarPolicyReason::RenameUnsupported)),
        RenameError::Io(path, e) => Err(RarFault::output(IoOperation::Publish, Some(path), None, e, false)),
    };
    match mode {
        RenameMode::New(style) => {
            let (path, reserved) = match claim_candidate(&target, style, log.budget, skip, Reserved::create) {
                Ok(claimed) => claimed,
                Err(error) => return failed(error),
            };
            (log.record)(RenamedOutput { requested: target, path, existing: None });
            Ok(DetailedChecked::Write(Place::reserved(reserved)))
        }
        RenameMode::Existing(style) => {
            let (moved, ()) =
                match claim_candidate(&target, style, log.budget, skip, |to| rename_noreplace(&target, to)) {
                    Ok(claimed) => claimed,
                    Err(error) => return failed(error),
                };
            if meta.is_dir()
                && let Some(dirs) = dirs
            {
                dirs.forget(rel);
            }
            (log.record)(RenamedOutput {
                requested: target.clone(),
                path: target.clone(),
                existing: Some(moved.clone()),
            });
            match Reserved::create(&target) {
                Ok(reserved) => Ok(DetailedChecked::Write(Place::reserved(reserved))),
                Err(e) => {
                    // the existing file keeps its new name, and both the error and `renames` say where it went
                    let why = format!("{} was moved to {}, but {e}", target.display(), moved.display());
                    Err(create(&target, io::Error::new(e.kind(), why)))
                }
            }
        }
    }
}

fn is_protected(opts: &Options, path: &Path) -> bool {
    !opts.protected_paths.is_empty() && opts.protected_paths.contains(path)
}

/// Whether the folder `dir` (canonical) holds a protected path at any depth.
fn holds_protected(opts: &Options, dir: &Path) -> bool {
    opts.protected_paths.iter().any(|path| path.starts_with(dir))
}

/// Files from this size up are given their full length when created. A small file gains nothing from it, and the
/// call costs as much as closing the file.
const PREALLOCATE_MIN: u64 = 1 << 20;

/// The second half of [`open_target`].
pub(crate) fn create_target(place: Place, size: Option<u64>) -> Result<Output> {
    create_target_detailed(place, size).map_err(crate::error::RarFault::into_legacy)
}

pub(crate) fn create_target_detailed(place: Place, size: Option<u64>) -> crate::error::RarResult<Output> {
    use crate::error::{IoOperation, RarFailure, RarFault, RarPolicyReason};
    let create_fault = |e| RarFault::output(IoOperation::CreateFile, Some(place.path.clone()), None, e, false);
    if let Some(reserved) = place.reserved {
        let (file, path) = reserved.into_parts();
        if let Some(size) = size.filter(|&s| s >= PREALLOCATE_MIN) {
            let _ = file.set_len(size);
        }
        return Ok(Output::created(file, size, path));
    }
    let (file, staged) = if place.replace {
        let parent = place.path.parent().ok_or_else(|| {
            RarFault::new(
                RarFailure::Policy { reason: RarPolicyReason::UnsafePath, path: place.path.clone() },
                Error::UnsafePath(place.path.display().to_string()),
            )
        })?;
        let (file, path) = temporary(parent).map_err(create_fault)?.into_parts();
        (file, Some(path))
    } else {
        let file = OpenOptions::new().write(true).create_new(true).open(&place.path).map_err(create_fault)?;
        (file, None)
    };
    if let Some(size) = size.filter(|&s| s >= PREALLOCATE_MIN) {
        // one allocation up front keeps a big file in few extents; failure here is harmless
        let _ = file.set_len(size);
    }
    Ok(match staged {
        Some(path) => Output::staged(file, size, path, place.path),
        None => Output::created(file, size, place.path),
    })
}

/// Which clock an [`Entry::mtime`] was read from.
///
/// Every `mtime` is a count of seconds since 1970-01-01 00:00:00, but only a
/// `Utc` one is a true Unix timestamp. A `LocalWallClock` one is the stored
/// date and time fields, which carry no time zone, counted as if they were UTC:
/// formatting it as UTC gives back the wall-clock time the archiver recorded.
/// 7-Zip and UnRAR print such a time as stored and convert a UTC time to local
/// time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MtimeOrigin {
    /// A Unix timestamp: ZIP extended-timestamp (0x5455) and NTFS (0x000a)
    /// extras, RAR 5.0, tar and the gzip `MTIME` field.
    Utc,
    /// MS-DOS date and time fields read as UTC: ZIP without a time extra and
    /// RAR 4.x, including its extended-time precision record.
    LocalWallClock,
}

/// One entry for a listing.
///
/// `mode`, `mtime_origin`, `ctime`, `atime`, `tar` and `attributes` are additive in this unpublished
/// 0.1 API; downstream struct literals must supply them (`None` when the
/// archive holds no such metadata).
#[derive(Clone, Debug)]
pub struct Entry {
    /// Unix mode bits as stored by the archive, when available.
    pub mode: Option<u32>,
    pub name: String,
    pub size: u64,
    pub packed: u64,
    /// Seconds since 1970; see `mtime_origin` for the clock it was read from.
    pub mtime: Option<i64>,
    /// Which clock `mtime` was read from: `Some` exactly when `mtime` is.
    pub mtime_origin: Option<MtimeOrigin>,
    /// Creation time as UTC seconds since 1970 and nanoseconds: 7z kCTime (`7z a -mtc=on`), or a tar pax `ctime`
    /// record (strictly the status change time, which 7-Zip lists as Created); `None` otherwise.
    pub ctime: Option<(i64, u32)>,
    /// Last access time as UTC seconds since 1970 and nanoseconds: 7z kATime (`7z a -mta=on`) or a tar pax
    /// `atime` record; `None` otherwise.
    pub atime: Option<(i64, u32)>,
    /// Tar members: owner and group, ids, device numbers, magic, pax records and the raw header. None for other
    /// formats and for a lone compressed file.
    pub tar: Option<Box<crate::tar::TarMetadata>>,
    /// Raw Windows (MS-DOS) attribute bits (`FILE_ATTRIBUTE_*`: read-only 0x1,
    /// hidden 0x2, system 0x4, directory 0x10, archive 0x20, ...), when the
    /// archive was made on a host that stores them: ZIP hosts 0 (FAT), 6
    /// (HPFS), 10 and 11 (NTFS), 14 (VFAT), from the low 16 bits of the
    /// external attributes; RAR 4.x hosts MS-DOS, OS/2 and Win32 and RAR 5.0
    /// host Windows, from the file attributes. `None` for Unix and other
    /// hosts, whose permission bits are in `mode`, and for tar and gzip.
    pub attributes: Option<u32>,
    pub crc32: Option<u32>,
    pub method: u8,
    /// The method as 7-Zip's `7z l -slt` prints it (`LZMA2:24 BCJ`, `LZMA:16`, `PPMD:o6:mem24`,
    /// `LZMA2:24 7zAES:19`), for 7z members that have data; `None` for other formats and for empty
    /// members and directories, which 7-Zip leaves blank.
    pub method_name: Option<String>,
    pub dir: bool,
    pub encrypted: bool,
    pub solid: bool,
    pub link: Option<Redirection>,
}

#[derive(Default)]
pub(crate) struct ListingBudget {
    entries: usize,
    name_bytes: usize,
}

impl ListingBudget {
    pub(crate) fn record(&mut self, name: &str) -> Result<()> {
        self.entries += 1;
        self.name_bytes += name.len();
        if self.entries > 1_000_000 || self.name_bytes > 64 << 20 {
            return Err(Error::Unsupported("archive listing exceeds the entry or name byte limit".into()));
        }
        Ok(())
    }
}

/// Every volume of the set in turn, starting from `first`, calling `on_block` for each block.
fn walk(
    vol: Volume,
    password: Option<&str>,
    mut on_block: impl FnMut(&mut Volume, Block) -> Result<()>,
) -> Result<u64> {
    walk_until(vol, password, None, |vol, block| {
        on_block(vol, block)?;
        Ok(false)
    })
}

fn walk_until(
    vol: Volume,
    password: Option<&str>,
    cancel: Option<&Cancellation>,
    mut on_block: impl FnMut(&mut Volume, Block) -> Result<bool>,
) -> Result<u64> {
    let mut observer = SelectedReadObserver::default();
    walk_until_observed(vol, password, cancel, &mut observer, |vol, block, _, _| on_block(vol, block))
}

fn walk_until_observed(
    mut vol: Volume,
    password: Option<&str>,
    cancel: Option<&Cancellation>,
    observer: &mut SelectedReadObserver<'_>,
    mut on_block: impl FnMut(&mut Volume, Block, u32, &mut SelectedReadObserver<'_>) -> Result<bool>,
) -> Result<u64> {
    let format = vol.format();
    let mut volumes = 0;
    loop {
        let index = observer.volume_index(volumes)?;
        volumes += 1;
        let mut more = vol.main.is_volume();
        let mut saw_end = false;
        loop {
            if let Some(cancel) = cancel {
                cancel.check_io()?;
            }
            observer.notify(index, &vol.path, SelectedReadRole::Header, cancel)?;
            let Some(block) = vol.next_block()? else { break };
            match block {
                Block::End { more_volumes, .. } => {
                    more = more_volumes;
                    saw_end = true;
                    break;
                }
                Block::Crypt => return Err(Error::Encrypted),
                b => {
                    if on_block(&mut vol, b, index, observer)? {
                        return Ok(volumes);
                    }
                }
            }
        }
        if !saw_end && !vol.main.is_volume() {
            more = false;
        }
        if !more {
            return Ok(volumes);
        }
        let Some(next) = next_volume(&vol.path) else {
            // the set says it goes on, but this name has no volume number to step
            if saw_end {
                return Err(Error::UnnamedVolume(vol.path));
            }
            return Ok(volumes);
        };
        if !next.exists() {
            // without an end header a volume flag alone doesn't prove another volume was made
            if saw_end {
                return Err(Error::MissingVolume(next));
            }
            return Ok(volumes);
        }
        observer.notify(observer.volume_index(volumes)?, &next, SelectedReadRole::Header, cancel)?;
        vol = Volume::open_with_password(&next, password)?;
        if vol.format() != format {
            return Err(Error::Corrupt("RAR volume format changed"));
        }
    }
}

fn walk_rar(mut vol: Volume, run: &mut Run<'_, '_, '_>) -> RunResult<()> {
    let format = vol.format();
    loop {
        run.reports.volume()?;
        let mut more = vol.main.is_volume();
        let mut saw_end = false;
        while let Some((block, crypt)) = vol.next_block_detailed()? {
            match block {
                Block::End { more_volumes, .. } => {
                    more = more_volumes;
                    saw_end = true;
                    break;
                }
                Block::File(h) => {
                    if run.cancel.as_ref().is_some_and(Cancellation::is_canceled) {
                        return Err(RarFault::new(RarFailure::Canceled, canceled_error()).into());
                    }
                    run.file_block(&mut vol, h, crypt)?
                }
                _ => {}
            }
        }
        if !more {
            return Ok(());
        }
        let Some(next) = next_volume(&vol.path) else {
            return if saw_end {
                let path = vol.path;
                Err(RarFault::new(RarFailure::UnnamedVolume { path: path.clone() }, Error::UnnamedVolume(path)).into())
            } else {
                Ok(())
            };
        };
        if !next.exists() {
            if !saw_end {
                return Ok(());
            }
            // A file split into the missing volume fails on its own, as UnRAR reports it; what came before stands.
            if run.pending.is_some() {
                run.drain()?;
                let mut p = run.pending.take().expect("pending member");
                let failure = Arc::new(RarFailure::MissingVolume { path: next.clone() });
                if !p.hidden && (!run.reports.typed() || (!p.failed && !p.passive)) {
                    run.reports.failed(
                        &p.context,
                        Arc::clone(&failure),
                        format_args!("missing volume {}", next.display()),
                    )?;
                }
                p.discard();
                run.stream = None;
                run.rar4 = None;
                return Ok(());
            }
            return Err(
                RarFault::new(RarFailure::MissingVolume { path: next.clone() }, Error::MissingVolume(next)).into()
            );
        }
        vol = Volume::open_detailed(&next, run.password)?;
        if vol.format() != format {
            return Err(RarFault::new(
                RarFailure::integrity(
                    RarScope::Header { volume: next },
                    RarIntegrityReason::HeaderFraming("RAR volume format changed"),
                    RarPasswordEvidence::NotEncrypted,
                    false,
                ),
                Error::Corrupt("RAR volume format changed"),
            )
            .into());
        }
    }
}

/// The formats found by their first bytes. Anything else is tried as RAR, since a self-extracting RAR starts with
/// a program; a file that turns out not to be RAR gets one more try as a ZIP, which is found from its end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Zip,
    /// tar, plain or compressed, or a lone compressed file
    Tar,
    /// 7z, found by its signature
    SevenZip,
    Other,
}

const HEAD_PROBE_BYTES: usize = 1024;

fn sniff(path: &Path) -> Result<Format> {
    let mut head = [0u8; HEAD_PROBE_BYTES];
    let n = crate::tar::read_full(&mut File::open(path)?, &mut head)?;
    Ok(classify_head(&head[..n]))
}

fn classify_head(head: &[u8]) -> Format {
    if crate::sevenzip::sniff(head) {
        Format::SevenZip
    } else if crate::zip::sniff(head) {
        Format::Zip
    } else if crate::stream::Codec::sniff(head).is_some() || crate::tar::sniff_tar(head) {
        Format::Tar
    } else {
        Format::Other
    }
}

// Keep the original file and bootstrap ledger through format discovery. These
// fallible pre-action probes (1024 + at most 1 MiB + 8 bytes) are dropped before
// central parsing; they are not part of the encrypted payload scratch bound.
#[allow(clippy::large_enum_variant)] // Keep the checked owner inline, without a new fallible allocation.
pub(crate) enum CheckedRoute {
    Zip(crate::zip::read::CheckedOpen),
    Legacy(LegacyRoute),
}
pub(crate) enum LegacyRoute {
    Tar,
    SevenZip,
    /// A raw byte-split ZIP (`name.zip.001`, `name.zip.002`, ...), read as the pieces concatenated.
    SplitZip,
    Rar {
        signature: crate::rar5::reader::HeldSignature,
        path: PathBuf,
    },
}
#[allow(clippy::result_large_err)]
pub(crate) fn checked_route(path: &Path, cancel: &Cancellation) -> crate::zip::ZipReadResult<CheckedRoute> {
    let (opened, head) = crate::zip::read::CheckedOpen::open(path, cancel)?.probe(HEAD_PROBE_BYTES, cancel)?;
    match classify_head(&head) {
        Format::Zip if crate::zip::is_byte_split(path) => {
            // The checked reader holds one source file; a byte-split set reopens its pieces by path.
            opened.retire()?;
            Ok(CheckedRoute::Legacy(LegacyRoute::SplitZip))
        }
        Format::Zip => Ok(CheckedRoute::Zip(opened)),
        Format::Tar => {
            // TAR deliberately retains its incumbent path-based ownership scope.
            opened.retire()?;
            Ok(CheckedRoute::Legacy(LegacyRoute::Tar))
        }
        Format::SevenZip => {
            // 7z reopens its volumes by path, as TAR does.
            opened.retire()?;
            Ok(CheckedRoute::Legacy(LegacyRoute::SevenZip))
        }
        Format::Other => {
            let (opened, probe) = opened.probe(SIGNATURE_PROBE_BYTES as usize, cancel)?;
            match opened.recognize_rar(&probe) {
                Ok((signature, path)) => Ok(CheckedRoute::Legacy(LegacyRoute::Rar { signature, path })),
                Err(opened) => Ok(CheckedRoute::Zip(opened)),
            }
        }
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl LegacyRoute {
    pub(crate) fn run(
        self,
        first: &Path,
        options: &Options,
        password: Option<&str>,
        report: &mut impl LegacyReport,
    ) -> std::result::Result<Summary, RunError> {
        self.run_cancelable(first, options, password, &Cancellation::default(), report)
    }
    pub(crate) fn run_cancelable(
        self,
        first: &Path,
        options: &Options,
        password: Option<&str>,
        cancel: &Cancellation,
        report: &mut impl LegacyReport,
    ) -> std::result::Result<Summary, RunError> {
        match self {
            Self::Tar => crate::tar::run_reporting_cancelable(first, options, Some(cancel), report),
            Self::SevenZip => {
                let limits = crate::sevenzip::SevenZipLimits::default();
                crate::sevenzip::run_reporting(first, options, password, cancel, &limits, report)
            }
            Self::SplitZip => {
                cancel.check_io().map_err(Error::from)?;
                crate::zip::run_renaming(first, options, password, |line: &str| report.line(line))
            }
            Self::Rar { signature, .. } => {
                let mut reports = Reports::legacy(report);
                let result = rar_run_shared_open(first, options, password, Some(cancel), &mut reports, || {
                    Volume::from_held_signature_detailed(first, signature, password)
                });
                let Reports::Legacy { summary, .. } = reports else { unreachable!() };
                legacy_result(result, summary)
            }
        }
    }
    pub(crate) fn list(self, first: &Path, password: Option<&str>) -> Result<Vec<Entry>> {
        match self {
            Self::Tar => crate::tar::list(first),
            Self::SevenZip => crate::sevenzip::list(first, password),
            Self::SplitZip => crate::zip::list(first),
            Self::Rar { signature, .. } => {
                rar_list_from_volume(Volume::from_held_signature(first, signature, password)?, password)
            }
        }
    }
}

#[allow(clippy::large_enum_variant)] // Own the immutable ZIP catalogue and raw initial proof inline, without another allocation.
enum SelectedSource {
    Zip(crate::zip::read::ProjectedOwner),
    Tar(Box<crate::tar::Selected>),
    Rar { path: PathBuf, chain_start: usize, name: String, rar4: bool },
}

const RAR_SELECTED_WINDOW_LIMIT: u64 = 256 << 20;

/// A shared cancellation signal for selected reads.
#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    /// Requests that the decoder stop at its next cancellation check.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Reports whether the caller requested cancellation.
    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn check_io(&self) -> std::io::Result<()> {
        if self.is_canceled() {
            return Err(canceled_io());
        }
        Ok(())
    }
}

/// Why a selected read is about to use an archive source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SelectedReadRole {
    /// Archive signature, main headers, or member headers are being scanned.
    Header,
    /// A solid predecessor is being decoded to establish the selected history.
    Prerequisite,
    /// The selected member's payload is about to be read or decoded.
    Selected,
}

/// A source-purpose transition during [`SelectedEntry::read_observed`].
///
/// The path labels the source opened by this operation (ZIP may retain a
/// resolved path), not its current filesystem identity or location after a rename. Copy it inside the callback
/// if it must be retained. A notice does not certify any payload bytes.
#[derive(Clone, Copy, Debug)]
pub struct SelectedReadNotice<'a> {
    /// Zero-based read order, starting at the supplied first volume.
    pub volume_index: u32,
    pub path: &'a Path,
    pub role: SelectedReadRole,
}

type SelectedReadCallback<'a> = &'a mut dyn FnMut(SelectedReadNotice<'_>) -> Result<()>;

#[derive(Default)]
struct SelectedReadObserver<'a> {
    callback: Option<SelectedReadCallback<'a>>,
    last: Option<(u32, SelectedReadRole)>,
}

impl SelectedReadObserver<'_> {
    fn volume_index(&self, index: u64) -> Result<u32> {
        if self.callback.is_none() {
            return Ok(0);
        }
        u32::try_from(index).map_err(|_| Error::Unsupported("selected read volume index exceeds u32".into()))
    }

    fn notify(
        &mut self,
        volume_index: u32,
        path: &Path,
        role: SelectedReadRole,
        cancel: Option<&Cancellation>,
    ) -> Result<()> {
        let Some(callback) = &mut self.callback else { return Ok(()) };
        if self.last == Some((volume_index, role)) {
            return Ok(());
        }
        if let Some(cancel) = cancel {
            cancel.check_io()?;
        }
        let result = callback(SelectedReadNotice { volume_index, path, role });
        let after = cancel.map(Cancellation::check_io).transpose();
        result?;
        after?;
        self.last = Some((volume_index, role));
        Ok(())
    }
}

/// A regular file selected by its index in the archive listing.
pub struct SelectedEntry {
    source: SelectedSource,
    index: usize,
    limit: u64,
    windows_names: bool,
    meta: Meta,
    cancel: Cancellation,
}

impl SelectedEntry {
    /// Admits the actual ZIP output descriptor; other formats return false.
    #[cfg(unix)]
    #[allow(clippy::result_large_err)]
    pub fn admit_zip_output_fd(
        &mut self,
        fd: std::os::fd::BorrowedFd<'_>,
        context: &mut crate::zip::EncryptedReadContext,
    ) -> crate::zip::ZipReadResult<bool> {
        match &mut self.source {
            SelectedSource::Zip(owner) => {
                owner.admit_output_fd(fd, context)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Prepares one final ZIP diagnostic before payload work; non-ZIP keeps its incumbent scope.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[allow(clippy::result_large_err)]
    pub fn prepare_zip_diagnostics<'o>(
        &mut self,
        options: &'o Options,
        context: &mut crate::zip::EncryptedReadContext,
        which: crate::zip::ZipDiagnosticSink,
        sink: &dyn std::os::fd::AsFd,
    ) -> crate::zip::ZipReadResult<Option<crate::zip::ZipDirectDiagnostics<'o>>> {
        match &mut self.source {
            SelectedSource::Zip(owner) => {
                owner.prepare_diagnostics(self.index, options, &self.cancel, context, which, sink).map(Some)
            }
            _ => Ok(None),
        }
    }
    /// Consumes the original prepared capability and preserves the operation receipt.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn emit_zip_diagnostic<T, W: std::io::Write + std::os::fd::AsFd, F>(
        &mut self,
        token: crate::zip::ZipDirectDiagnostics<'_>,
        context: &mut crate::zip::EncryptedReadContext,
        operation: crate::zip::ZipReadResult<T>,
        out: &mut W,
        render: F,
    ) -> crate::zip::ZipDiagnosticCompletion<T>
    where
        F: FnOnce(
            &crate::zip::ZipReadResult<T>,
            crate::zip::ZipDiagnosticStatus<'_>,
            &mut crate::zip::ZipDiagnosticWriter<'_, W>,
        ) -> crate::zip::ZipDiagnosticResult<()>,
    {
        match &mut self.source {
            SelectedSource::Zip(owner) => {
                owner.emit_diagnostic(Some(self.index), token, context, operation, out, render)
            }
            _ => crate::zip::ZipDiagnosticCompletion::refused(
                token,
                context,
                operation,
                crate::zip::ReadFault::UnsupportedCheckedFormat.into(),
            ),
        }
    }
    /// Borrows the original ZIP record; other formats have no ZIP stage proof.
    #[allow(clippy::result_large_err)]
    pub fn zip_stage_entry(&mut self) -> crate::zip::ZipReadResult<Option<crate::zip::ZipStageEntry<'_>>> {
        match &mut self.source {
            SelectedSource::Zip(owner) => owner.stage_entry(self.index).map(Some),
            _ => Ok(None),
        }
    }
    /// Opens a zero-based listing entry. The limit applies independently to
    /// packed and decoded bytes. It includes the entire compressed TAR stream
    /// or any solid RAR members required to decode the selection.
    pub fn open(path: &Path, index: usize, password: Option<&str>, limit: u64) -> Result<Self> {
        Self::open_cancelable(path, index, password, limit, Cancellation::default())
    }

    /// Opens an entry and checks the signal while scanning and decoding it.
    pub fn open_cancelable(
        path: &Path,
        index: usize,
        password: Option<&str>,
        limit: u64,
        cancel: Cancellation,
    ) -> Result<Self> {
        cancel.check_io()?;
        match sniff(path)? {
            Format::Tar => {
                let selected = crate::tar::Selected::open(path, index, limit, cancel.clone())?;
                return Ok(Self {
                    meta: selected.meta,
                    windows_names: false,
                    index,
                    limit,
                    source: SelectedSource::Tar(Box::new(selected)),
                    cancel,
                });
            }
            Format::Other => match rar_selected_header(path, index, password, &cancel) {
                Ok((header, chain_start)) => {
                    if header.is_dir() || header.redirection.is_some() {
                        return Err(Error::Unsupported("the selected RAR5 entry is not a regular file".into()));
                    }
                    if header.packed_size > limit || (!header.size_unknown() && header.unpacked_size > limit) {
                        return Err(Error::Unsupported("the selected RAR5 entry exceeds the byte limit".into()));
                    }
                    return Ok(Self {
                        meta: Meta::from(&header),
                        windows_names: !header.is_unix(),
                        index,
                        limit,
                        source: SelectedSource::Rar {
                            path: path.to_path_buf(),
                            chain_start,
                            rar4: header.format == RarFormat::Rar4,
                            name: header.name,
                        },
                        cancel,
                    });
                }
                Err(Error::NotAnArchive) => {}
                Err(error) => return Err(error),
            },
            Format::SevenZip => return Err(Error::Unsupported("reading one 7z entry on its own".into())),
            Format::Zip => {}
        }
        let archive = crate::zip::read::ProjectedOwner::open_legacy(path, &cancel)?;
        let entry =
            archive.entries().get(index).ok_or_else(|| Error::Unsupported("entry index is out of range".into()))?;
        crate::zip::check_selected_legacy(entry, limit)?;
        Ok(Self {
            windows_names: entry.host != 3,
            meta: Meta { mtime: entry.mtime, nanos: entry.nanos, mode: entry.unix_mode() },
            index,
            limit,
            source: SelectedSource::Zip(archive),
            cancel,
        })
    }

    /// Opens a selection with an encrypted-ZIP-specific replacement ceiling.
    /// Recognized RAR errors are terminal on this additive checked dispatcher.
    #[allow(clippy::result_large_err)]
    pub fn open_cancelable_with_zip_limit(
        path: &Path,
        index: usize,
        password: Option<&str>,
        max_bytes: u64,
        encrypted_zip_max_bytes: Option<u64>,
        cancel: Cancellation,
    ) -> crate::zip::ZipReadResult<Self> {
        use crate::zip::{ReadFault, ReadResource};
        let opened = match checked_route(path, &cancel)? {
            CheckedRoute::Zip(opened) => opened,
            CheckedRoute::Legacy(LegacyRoute::Tar) => {
                let selected =
                    crate::tar::Selected::open(path, index, max_bytes, cancel.clone()).map_err(ReadFault::Legacy)?;
                return Ok(Self {
                    meta: selected.meta,
                    windows_names: false,
                    index,
                    limit: max_bytes,
                    source: SelectedSource::Tar(Box::new(selected)),
                    cancel,
                });
            }
            CheckedRoute::Legacy(LegacyRoute::SevenZip) => {
                return Err(ReadFault::Legacy(Error::Unsupported("reading one 7z entry on its own".into())).into());
            }
            CheckedRoute::Legacy(LegacyRoute::SplitZip) => {
                return Err(ReadFault::Legacy(Error::Unsupported(
                    "reading one entry of a byte-split ZIP on its own".into(),
                ))
                .into());
            }
            CheckedRoute::Legacy(LegacyRoute::Rar { signature, path: held_path }) => {
                let volume = Volume::from_held_signature(&held_path, signature, password).map_err(ReadFault::Legacy)?;
                let (header, chain_start) =
                    rar_selected_header_from_volume(volume, index, password, &cancel).map_err(ReadFault::Legacy)?;
                if header.is_dir() || header.redirection.is_some() {
                    return Err(ReadFault::Legacy(Error::Unsupported(
                        "the selected RAR5 entry is not a regular file".into(),
                    ))
                    .into());
                }
                if header.packed_size > max_bytes || (!header.size_unknown() && header.unpacked_size > max_bytes) {
                    return Err(ReadFault::Legacy(Error::Unsupported(
                        "the selected RAR5 entry exceeds the byte limit".into(),
                    ))
                    .into());
                }
                return Ok(Self {
                    meta: Meta::from(&header),
                    windows_names: !header.is_unix(),
                    index,
                    limit: max_bytes,
                    source: SelectedSource::Rar {
                        path: held_path,
                        chain_start,
                        rar4: header.format == RarFormat::Rar4,
                        name: header.name,
                    },
                    cancel,
                });
            }
        };
        let owner = opened.into_zip(&cancel)?;
        let selection = (|| -> crate::zip::ZipReadResult<_> {
            let entry =
                owner.entries().get(index).ok_or(ReadFault::CheckedFormat { reason: "entry index is out of range" })?;
            if entry.is_dir() || entry.is_link() {
                return Err(ReadFault::CheckedFormat { reason: "selected ZIP entry is not a regular file" }.into());
            }
            let limit = if entry.encrypted() { encrypted_zip_max_bytes.unwrap_or(max_bytes) } else { max_bytes };
            if entry.packed > limit {
                return Err(ReadFault::Limit {
                    resource: ReadResource::MemberPackedBytes,
                    limit: limit.into(),
                    attempted: entry.packed.into(),
                }
                .into());
            }
            if entry.size > limit {
                return Err(ReadFault::Limit {
                    resource: ReadResource::MemberDecodedBytes,
                    limit: limit.into(),
                    attempted: entry.size.into(),
                }
                .into());
            }
            Ok((limit, entry.host != 3, Meta { mtime: entry.mtime, nanos: entry.nanos, mode: entry.unix_mode() }))
        })();
        let (limit, windows_names, meta) = match selection {
            Ok(selection) => selection,
            Err(error) => return Err(owner.reject(error)),
        };
        Ok(Self { windows_names, meta, index, limit, source: SelectedSource::Zip(owner), cancel })
    }
    pub fn is_zip(&self) -> bool {
        matches!(self.source, SelectedSource::Zip(_))
    }
    #[allow(clippy::result_large_err)]
    pub fn check_zip_source(
        &mut self,
        context: &mut crate::zip::EncryptedReadContext,
    ) -> crate::zip::ZipReadResult<()> {
        match &mut self.source {
            SelectedSource::Zip(owner) => owner.check_source(context),
            _ => Err(crate::zip::ReadFault::UnsupportedCheckedFormat.into()),
        }
    }
    #[allow(clippy::result_large_err)]
    pub fn zip_read_context(
        &mut self,
        password: Option<&str>,
        output: crate::zip::ZipReadOutput<'_>,
        overrides: &crate::zip::EncryptedReadOverrides,
    ) -> crate::zip::ZipReadResult<Option<crate::zip::EncryptedReadContext>> {
        match &mut self.source {
            SelectedSource::Zip(owner) => crate::zip::EncryptedReadContext::for_owner(
                owner,
                crate::zip::ProjectedReadScope::Entry(self.index),
                Some(self.limit),
                output,
                password,
                overrides,
                &self.cancel,
            )
            .map(Some),
            _ => Ok(None),
        }
    }
    #[allow(clippy::result_large_err)]
    pub fn read_with_zip_context(
        &mut self,
        password: Option<&str>,
        context: &mut crate::zip::EncryptedReadContext,
        sink: impl FnMut(&[u8]) -> crate::zip::ZipSinkResult<()>,
    ) -> crate::zip::ZipReadResult<()> {
        match &mut self.source {
            SelectedSource::Zip(owner) => {
                owner.read_checked(self.index, password, self.limit, &self.cancel, context, sink)
            }
            _ => Err(crate::zip::ReadFault::UnsupportedCheckedFormat.into()),
        }
    }

    /// Returns the name stored in the archive.
    pub fn name(&self) -> &str {
        match &self.source {
            SelectedSource::Zip(owner) => &owner.entries()[self.index].name,
            SelectedSource::Tar(selected) => &selected.name,
            SelectedSource::Rar { name, .. } => name,
        }
    }

    /// Returns a path checked for traversal and absolute components.
    pub fn relative_path(&self) -> Result<PathBuf> {
        if let SelectedSource::Rar { name, rar4, .. } = &self.source {
            let output = crate::path::rar_output_name(name, *rar4)
                .ok_or_else(|| Error::Unsupported("the selected name can't be written one to one".into()))?;
            return sanitize(&output, self.windows_names);
        }
        sanitize(self.name(), self.windows_names)
    }

    /// Returns Unix permission bits if the archive stores them.
    pub fn unix_mode(&self) -> Option<u32> {
        self.meta.mode
    }

    /// Returns the modification time as Unix seconds and nanoseconds.
    pub fn modified(&self) -> Option<(i64, u32)> {
        self.meta.mtime.map(|seconds| (seconds, self.meta.nanos))
    }

    /// Decodes the selected file into the sink. Data is provisional until
    /// all available integrity checks pass and this function returns success.
    pub fn read(self, password: Option<&str>, sink: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.read_inner(password, sink, &mut SelectedReadObserver::default())
    }

    /// Decodes the selection with borrowed source-purpose notices during this read.
    ///
    /// RAR reports header scans and required solid payload work in the existing
    /// traversal. ZIP and TAR report their single source as `Selected`, at index
    /// zero, before the existing read. Consecutive identical volume/role notices
    /// are suppressed; notices are not emitted for individual chunks. Readers
    /// may buffer or read ahead; roles describe logical work, not byte ranges.
    /// Source inspection already performed by `open` is not replayed. A callback
    /// error stops the read unchanged, and cancellation is checked immediately
    /// before and after each callback. Bytes remain provisional until all
    /// integrity checks pass and this method returns success, just as for `read`.
    pub fn read_observed(
        self,
        password: Option<&str>,
        sink: impl FnMut(&[u8]) -> Result<()>,
        mut notice: impl FnMut(SelectedReadNotice<'_>) -> Result<()>,
    ) -> Result<()> {
        self.read_inner(password, sink, &mut SelectedReadObserver { callback: Some(&mut notice), last: None })
    }

    fn read_inner(
        self,
        password: Option<&str>,
        mut sink: impl FnMut(&[u8]) -> Result<()>,
        observer: &mut SelectedReadObserver<'_>,
    ) -> Result<()> {
        self.cancel.check_io()?;
        let mut checked_sink = |chunk: &[u8]| {
            self.cancel.check_io()?;
            sink(chunk)
        };
        match self.source {
            SelectedSource::Zip(mut archive) => {
                if observer.callback.is_some() {
                    let path = archive.source_path().map_err(|error| Error::Io(std::io::Error::other(error)))?;
                    observer.notify(0, path, SelectedReadRole::Selected, Some(&self.cancel))?;
                }
                archive.legacy_read(self.index, password, self.limit, &self.cancel, &mut checked_sink)
            }
            SelectedSource::Tar(selected) => {
                observer.notify(0, selected.source_path(), SelectedReadRole::Selected, Some(&self.cancel))?;
                selected.read(&mut checked_sink)
            }
            SelectedSource::Rar { path, chain_start, name, .. } => {
                let selection = RarSelection {
                    sink: &mut checked_sink,
                    emit: false,
                    packed_left: self.limit,
                    decoded_left: self.limit,
                    cancel: &self.cancel,
                };
                rar_read_at(&path, chain_start, self.index, &name, password, selection, observer)
            }
        }?;
        self.cancel.check_io()?;
        Ok(())
    }
}

fn rar_selected_header(
    path: &Path,
    index: usize,
    password: Option<&str>,
    cancel: &Cancellation,
) -> Result<(FileHeader, usize)> {
    let volume = Volume::open_with_password(path, password)?;
    rar_selected_header_from_volume(volume, index, password, cancel)
}
fn rar_selected_header_from_volume(
    volume: Volume,
    index: usize,
    password: Option<&str>,
    cancel: &Cancellation,
) -> Result<(FileHeader, usize)> {
    let mut current = 0;
    let mut chain_start = None;
    let mut header = None;
    walk_until(volume, password, Some(cancel), |_, block| {
        if let Block::File(file) = block
            && !file.split_before()
        {
            if file.method != 0 && !file.solid && !file.is_dir() && file.redirection.is_none() {
                chain_start = Some(current);
            }
            if current == index {
                let first = if file.solid && file.method != 0 { chain_start.unwrap_or(current) } else { current };
                header = Some((file, first));
                return Ok(true);
            }
            current += 1;
        }
        Ok(false)
    })?;
    header.ok_or_else(|| Error::Unsupported("entry index is out of range".into()))
}

/// Format-specific metadata returned by checked projected inspection.
///
/// Available on macOS and Linux. ZIP retains its original projected catalogue
/// and source; non-ZIP listings keep their incumbent ownership/reopen scope.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)] // Move the original ZIP owner inline without another allocation.
pub enum ProjectedInspection {
    /// The original checked ZIP source and its single projected catalogue.
    Zip(crate::zip::ProjectedReadSession),
    /// The existing listing for TAR, compressed streams, 7z, RAR, or a byte-split ZIP (`.zip.001`).
    Other(Vec<Entry>),
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
thread_local! {
    pub(crate) static PROJECTED_INSPECTION_LEGACY_COMPLETED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Inspects an archive with one checked dispatch and cooperative cancellation.
///
/// Available on macOS and Linux. ZIP and TAR/codec head signatures take
/// precedence; an unknown head searches the bounded RAR signature window before
/// trying ZIP. Recognized format errors are terminal, including RAR initializer,
/// password, member and later-volume errors. `password` decrypts RAR headers;
/// supply ZIP payload passwords separately to checked reads.
///
/// ZIP moves the held source, original projected catalogue and cumulative
/// dispatch/parser budget into the returned session. Successful sessions retain
/// the existing ordinary file-drop lifecycle. TAR retires the checked source
/// before its incumbent pathname listing; other non-ZIP listings retain their
/// existing ownership scope. Cancellation is checked before acquisition and
/// after successful legacy listing; a legacy failure keeps its original error.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)] // Preserve inline checked operation/source/cleanup evidence.
pub fn inspect_projected_cancelable(
    first: &Path,
    password: Option<&str>,
    cancel: &Cancellation,
) -> crate::zip::ZipReadResult<ProjectedInspection> {
    use crate::zip::ReadFault;
    match checked_route(first, cancel)? {
        CheckedRoute::Zip(opened) => opened.into_zip_projected(cancel).map(ProjectedInspection::Zip),
        CheckedRoute::Legacy(route) => {
            let entries = route.list(first, password).map_err(ReadFault::Legacy)?;
            #[cfg(test)]
            {
                let completed = PROJECTED_INSPECTION_LEGACY_COMPLETED.with(|s| s.borrow_mut().take());
                if let Some(completed) = completed {
                    completed();
                }
            }
            if cancel.is_canceled() {
                return Err(ReadFault::Cancelled.into());
            }
            Ok(ProjectedInspection::Other(entries))
        }
    }
}

/// Format-specific metadata returned by archive inspection.
pub enum Inspection {
    /// Immutable ZIP directory and the retained source for selected reads.
    Zip(ReadSession),
    /// The existing listing for TAR, compressed streams, or RAR.
    Other(Vec<Entry>),
}

/// Inspects an archive and retains the ZIP source for selected reads.
pub fn inspect(first: &Path) -> SessionResult<Inspection> {
    inspect_with_password(first, None)
}

/// Inspects an archive, using `password` for encrypted RAR headers.
pub fn inspect_with_password(first: &Path, password: Option<&str>) -> SessionResult<Inspection> {
    inspect_cancelable(first, password, &Cancellation::default())
}

/// Inspects an archive with cooperative cancellation.
///
/// ZIP and TAR/codec head signatures take precedence. With an unknown head,
/// inspection searches the bounded RAR signature window before trying ZIP.
/// After recognition, errors from that format are terminal, including RAR
/// errors from later volumes. ZIP sessions require supported Unix identity.
///
/// The ZIP fetch budget includes both format probes and directory parsing.
/// The existing non-ZIP listing calls observe cancellation on successful
/// return. For ZIP payloads, supply a password to the selected read.
pub fn inspect_cancelable(first: &Path, password: Option<&str>, cancel: &Cancellation) -> SessionResult<Inspection> {
    let mut source = InspectionSource::open(first, cancel)?;
    let mut head = [0; HEAD_PROBE_BYTES];
    let n = source.read_probe(&mut head, cancel)?;
    let format = classify_head(&head[..n]);
    cancel.check_io().map_err(Error::from)?;
    let entries = match format {
        // A byte-split set (`.zip.001`) has no single source for a ZIP read session: list it as a whole.
        Format::Zip if crate::zip::is_byte_split(first) => {
            drop(source);
            crate::zip::list(first)?
        }
        Format::Zip => return source.into_zip(cancel).map(Inspection::Zip),
        Format::Tar => {
            drop(source);
            crate::tar::list(first)?
        }
        Format::SevenZip => {
            drop(source);
            crate::sevenzip::list(first, password)?
        }
        Format::Other => {
            let signature = signature_end(&source.probe_prefix(SIGNATURE_PROBE_BYTES, cancel)?);
            cancel.check_io().map_err(Error::from)?;
            match signature {
                Ok(_) => {
                    drop(source);
                    rar_list(first, password)?
                }
                Err(Error::NotAnArchive) => return source.into_zip(cancel).map(Inspection::Zip),
                Err(error) => return Err(error.into()),
            }
        }
    };
    cancel.check_io().map_err(Error::from)?;
    Ok(Inspection::Other(entries))
}

/// The entries of an archive, whatever its format.
pub fn list(first: &Path) -> Result<Vec<Entry>> {
    list_with_password(first, None)
}

/// The entries of an archive, decrypting encrypted headers when `password` is given.
pub fn list_with_password(first: &Path, password: Option<&str>) -> Result<Vec<Entry>> {
    match sniff(first)? {
        Format::Zip => return crate::zip::list(first),
        Format::Tar => return crate::tar::list(first),
        Format::SevenZip => return crate::sevenzip::list(first, password),
        Format::Other => {}
    }
    match rar_list(first, password) {
        Err(Error::NotAnArchive) => crate::zip::list(first),
        other => other,
    }
}

/// The events of a [`run_with_policy`] or [`run_with_context`] run, whatever the format.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use crate::zip::{ZipRunEvent as RunEvent, ZipRunObserver as RunObserver, ZipRunReport as RunReport};

/// **The one entry point for every format**: tests or extracts a ZIP, tar (plain or compressed), lone compressed
/// stream (`.gz`, `.xz`, `.bz2`, `.zst`), RAR4/RAR5 or 7z archive with one [`Options`], one [`Cancellation`] and
/// one observer.
///
/// - The format comes from the file's content, never its name.
/// - `cancel` reaches every format's inner loop: ZIP decoding and staging, tar headers and data, every stream
///   codec, RAR members and their decoded data, 7z folders. A canceled run returns an error whose
///   [`crate::zip::ZipReadError::operation`] is [`crate::zip::ReadFault::Cancelled`]; members finished before it
///   stay published, the one in progress is not.
/// - [`Options::overwrite`] (Skip, Always, RenameNew, RenameExisting) and [`Options::select`] apply to every format.
/// - Observer events ([`RunEvent`]): every format (a lone compressed stream is ordinal 0) sends `MemberSucceeded`,
///   `MemberSkipped` and `MemberFailed` live, with the member's listing index, and `MemberRenamed` with
///   `Some(ordinal)` just before. Tar, RAR and 7z also send their report lines as `LegacyDiagnostic` as they happen
///   and their failures as `LegacyError` at the end. Every run ends with `RunEnded`.
/// - A wrong or missing password is [`crate::zip::ReadFault::PasswordRequired`] or `PasswordCheckFailed` for ZIP and
///   7z; other non-ZIP failures are [`crate::zip::ReadFault::Legacy`] carrying the format's own [`Error`].
///
/// This is [`run_with_zip_policy`] under a format-neutral name; [`run_with_context`] is the same with a caller-owned
/// [`crate::zip::EncryptedReadContext`] (its encrypted-ZIP budgets carry across runs).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)]
pub fn run_with_policy(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    overrides: &crate::zip::EncryptedReadOverrides,
    observe: impl RunObserver,
) -> crate::zip::ZipReadResult<RunReport> {
    run_with_zip_policy(first, options, password, cancel, overrides, observe)
}

/// [`run_with_policy`] with a caller-owned encrypted-read context; see there. Same as [`run_with_zip_context`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)]
pub fn run_with_context(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    context: &mut crate::zip::EncryptedReadContext,
    observe: impl RunObserver,
) -> crate::zip::ZipReadResult<RunReport> {
    run_with_zip_context(first, options, password, cancel, context, observe)
}

/// Tests or extracts an archive, whatever its format. Same as [`run_with_policy`], its format-neutral name.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)]
pub fn run_with_zip_policy(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    overrides: &crate::zip::EncryptedReadOverrides,
    observe: impl crate::zip::ZipRunObserver,
) -> crate::zip::ZipReadResult<crate::zip::ZipRunReport> {
    match checked_route(first, cancel)? {
        CheckedRoute::Zip(opened) => crate::zip::read::with_opened_policy(
            opened.into_zip_projected(cancel)?,
            options,
            password,
            cancel,
            overrides,
            observe,
        ),
        CheckedRoute::Legacy(route) => legacy_zip_report(route, first, options, password, cancel, observe),
    }
}
/// [`run_with_zip_policy`] with a caller-owned encrypted-read context. Same as [`run_with_context`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)]
pub fn run_with_zip_context(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    context: &mut crate::zip::EncryptedReadContext,
    observe: impl crate::zip::ZipRunObserver,
) -> crate::zip::ZipReadResult<crate::zip::ZipRunReport> {
    match checked_route(first, cancel)? {
        CheckedRoute::Zip(opened) => crate::zip::read::with_opened_context(
            opened.into_zip_projected(cancel)?,
            options,
            password,
            cancel,
            context,
            observe,
        ),
        CheckedRoute::Legacy(route) => legacy_zip_report(route, first, options, password, cancel, observe),
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)]
pub(crate) fn legacy_zip_report(
    route: LegacyRoute,
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    mut observe: impl crate::zip::ZipRunObserver,
) -> crate::zip::ZipReadResult<crate::zip::ZipRunReport> {
    use crate::zip::{ReadFault, ZipReadError, ZipRunEvent, ZipRunReport};
    let seven_zip = matches!(route, LegacyRoute::SevenZip);
    /// Hands the legacy runner's lines and renames to the observer as they happen; the first observer failure stops
    /// further events and fails the run.
    struct Forward<'o, O> {
        observe: &'o mut O,
        fault: Option<ZipReadError>,
    }
    impl<O: crate::zip::ZipRunObserver> Forward<'_, O> {
        fn send(&mut self, event: ZipRunEvent<'_>) {
            if self.fault.is_none() {
                let mut scope = crate::zip::ZipDiagnosticScope::legacy();
                if matches!(
                    event,
                    ZipRunEvent::MemberSucceeded { .. }
                        | ZipRunEvent::MemberSkipped { .. }
                        | ZipRunEvent::MemberFailed { .. }
                        | ZipRunEvent::MemberRenamed { .. }
                ) {
                    scope = crate::zip::ZipDiagnosticScope::legacy_member();
                }
                let result = self.observe.observe(event, &mut scope);
                let e = scope.finish(result);
                if e.failed() {
                    self.fault = Some(e.merge(ReadFault::InvalidPlan.into()));
                }
            }
        }
    }
    impl<O: crate::zip::ZipRunObserver> LegacyReport for Forward<'_, O> {
        fn line(&mut self, message: &str) {
            self.send(ZipRunEvent::LegacyDiagnostic { message });
        }
        fn renamed(&mut self, renamed: &RenamedOutput) {
            self.send(ZipRunEvent::MemberRenamed { ordinal: None, renamed });
        }
        fn renamed_member(&mut self, ordinal: u64, renamed: &RenamedOutput) {
            self.send(ZipRunEvent::MemberRenamed { ordinal: Some(ordinal), renamed });
        }
        fn member(&mut self, member: LegacyMember<'_>) {
            match member {
                LegacyMember::Succeeded { ordinal, name, bytes } => {
                    self.send(ZipRunEvent::MemberSucceeded { ordinal, name, decoded_bytes: bytes })
                }
                LegacyMember::Skipped { ordinal, name } => self.send(ZipRunEvent::MemberSkipped { ordinal, name }),
                LegacyMember::Failed { ordinal, name, error } => {
                    let error = ZipReadError::from(ReadFault::Legacy(error));
                    self.send(ZipRunEvent::MemberFailed { ordinal, name, error: &error });
                }
            }
        }
    }
    let mut forward = Forward { observe: &mut observe, fault: None };
    // The renames have reached the observer as they were made, so a terminal error needn't carry them.
    let result = route.run_cancelable(first, options, password, cancel, &mut forward).map_err(|e| e.error);
    let fault = forward.fault;
    let (report, summary, mut terminal) = match result {
        Ok(summary) => (ZipRunReport::from_legacy(&summary), Some(summary), None),
        Err(error) => {
            let fault = if seven_zip {
                seven_zip_fault(error)
            } else if cancel.is_canceled() && is_cancellation(&error) {
                ReadFault::Cancelled
            } else {
                ReadFault::Legacy(error)
            };
            (ZipRunReport::default(), None, Some(ZipReadError::from(fault)))
        }
    };
    if let Some(fault) = fault {
        return Err(fault.with_partial(report));
    }
    // Borrow the original legacy strings while the successful Summary is live.
    // This error-only channel lets quiet consumers omit mixed skip/progress text.
    if let Some(summary) = &summary {
        for message in &summary.errors {
            let mut scope = crate::zip::ZipDiagnosticScope::legacy();
            let result = observe.observe(ZipRunEvent::LegacyError { message }, &mut scope);
            let evidence = scope.finish(result);
            if evidence.failed() {
                return Err(evidence.merge(ReadFault::InvalidPlan.into()).with_partial(report));
            }
        }
    }
    let mut scope = crate::zip::ZipDiagnosticScope::legacy();
    let result = observe.observe(ZipRunEvent::RunEnded { report: &report, error: terminal.as_ref() }, &mut scope);
    let evidence = scope.finish(result);
    if evidence.failed() {
        terminal = Some(evidence.merge(terminal.take().unwrap_or_else(|| ReadFault::InvalidPlan.into())));
    }
    terminal.map_or(Ok(report), |e| Err(e.with_partial(report)))
}
/// The checked-path fault for a failed 7z run: the password and cancellation failures ZIP reports, typed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn seven_zip_fault(error: Error) -> crate::zip::ReadFault {
    use crate::sevenzip::SevenZipError;
    use crate::zip::{CipherKind, ReadFault};
    match (&error, SevenZipError::of(&error)) {
        (Error::Encrypted, _) => ReadFault::PasswordRequired,
        (_, Some(SevenZipError::WrongPassword)) => ReadFault::PasswordCheckFailed { cipher: CipherKind::Aes },
        (_, Some(SevenZipError::Canceled)) => ReadFault::Cancelled,
        _ => ReadFault::Legacy(error),
    }
}
pub fn run(first: &Path, opts: &Options, report: impl FnMut(&str)) -> Result<Summary> {
    run_with_password(first, opts, None, report)
}

/// Tests or extracts an archive, decrypting with `password` when encrypted.
pub fn run_with_password(
    first: &Path,
    opts: &Options,
    password: Option<&str>,
    report: impl FnMut(&str),
) -> Result<Summary> {
    run_with_renames(first, opts, password, report).map_err(|e| e.error)
}

/// [`run_with_password`], whose terminal error keeps the renames a rename mode made before it ([`RunError`]).
///
/// With [`Overwrite::RenameNew`] or [`Overwrite::RenameExisting`], a run that stops early may already have moved
/// existing files aside; `RunError::renames` says where, as [`Summary::renames`] does for a run that finishes. The
/// report callback also gets a line for each rename as it is made (`<requested>: exists, written as <path>` or
/// `<requested>: existing file moved to <path>`), with [`run`] and [`run_with_password`] too.
pub fn run_with_renames(
    first: &Path,
    opts: &Options,
    password: Option<&str>,
    mut report: impl FnMut(&str),
) -> std::result::Result<Summary, RunError> {
    match sniff(first)? {
        Format::Zip => return zip_run(first, opts, password, &mut report),
        Format::Tar => return crate::tar::run_reporting(first, opts, &mut report),
        Format::SevenZip => {
            let limits = crate::sevenzip::SevenZipLimits::default();
            return crate::sevenzip::run_reporting(
                first,
                opts,
                password,
                &Cancellation::default(),
                &limits,
                &mut report,
            );
        }
        Format::Other => {}
    }
    match rar_run(first, opts, password, &mut report) {
        Err(RunError { error: Error::NotAnArchive, .. }) => zip_run(first, opts, password, &mut report),
        other => other,
    }
}

fn zip_run(
    path: &Path,
    opts: &Options,
    password: Option<&str>,
    report: &mut impl FnMut(&str),
) -> std::result::Result<Summary, RunError> {
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest).map_err(Error::from)?;
    }
    crate::zip::run_renaming(path, opts, password, report)
}

fn rar_list(first: &Path, password: Option<&str>) -> Result<Vec<Entry>> {
    rar_list_from_volume(Volume::open_with_password(first, password)?, password)
}

fn rar_list_from_volume(volume: Volume, password: Option<&str>) -> Result<Vec<Entry>> {
    let mut out: Vec<Entry> = Vec::new();
    let mut budget = ListingBudget::default();
    walk(volume, password, |_, block| {
        let Block::File(h) = block else { return Ok(()) };
        if h.split_before() {
            if let Some(last) = out.last_mut().filter(|e| e.name == h.name) {
                last.packed = last.packed.checked_add(h.packed_size).ok_or(Error::Corrupt("split packed size"))?;
                if !h.split_after() {
                    last.crc32 = h.crc32;
                }
            }
            return Ok(());
        }
        budget.record(&h.name)?;
        let crc32 = if h.split_after() { None } else { h.crc32 };
        let dir = h.is_dir();
        let mode = Meta::from(&h).mode;
        out.push(Entry {
            mode,
            mtime_origin: h.mtime_origin(),
            ctime: None,
            atime: None,
            tar: None,
            attributes: h.windows_attributes(),
            name: h.name,
            size: h.unpacked_size,
            packed: h.packed_size,
            mtime: h.mtime,
            crc32,
            method: h.method,
            method_name: None,
            dir,
            encrypted: h.encrypted,
            solid: h.solid,
            link: h.redirection,
        });
        Ok(())
    })?;
    Ok(out)
}

/// A file being read, whose data may run on into later volumes.
pub(crate) struct Pending {
    context: EntryContext,
    out: Option<Output>,
    checks: crate::rar5::member::InnerChecks,
    /// something already went wrong: read past the rest of it
    failed: bool,
    /// decoded only to keep a solid stream going: not counted, not written
    passive: bool,
    /// not taken by the run's member filter: never reported, even when its parts go missing
    hidden: bool,
    compressed: bool,
    encrypted: bool,
    /// AES-256-CBC state for an encrypted RAR5 file
    cipher: Option<PendingCipher>,
    /// where it is written, folded as `batch_paths` is
    key: Option<String>,
    /// where it is to be written, until the file is created there
    place: Option<Place>,
    /// its bytes, gathered to be checked and written whole on a worker
    mem: Option<Vec<u8>>,
    /// what each later RAR4 part must repeat: dictionary, unpack version, method and salt
    rar4_identity: Option<(u64, u8, u8, Option<[u8; 8]>)>,
    /// stops the member as its data comes in
    cancel: Option<Cancellation>,
    /// a RAR4 symbolic link: where it goes and its target, gathered as it is decoded
    link: Option<LinkOut>,
}

/// A symbolic link being extracted: created once its target is decoded and checked.
struct LinkOut {
    place: Place,
    /// where it goes, relative to the destination
    rel: PathBuf,
    target: Vec<u8>,
}

impl std::ops::Deref for Pending {
    type Target = crate::rar5::member::InnerChecks;
    fn deref(&self) -> &Self::Target {
        &self.checks
    }
}
impl std::ops::DerefMut for Pending {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.checks
    }
}

impl Pending {
    pub(crate) fn new(h: &FileHeader, context: EntryContext) -> Self {
        Pending {
            context,
            out: None,
            checks: crate::rar5::member::InnerChecks::new(h),
            failed: false,
            passive: false,
            hidden: false,
            compressed: h.method != 0,
            encrypted: h.encrypted,
            cipher: None,
            key: None,
            place: None,
            mem: None,
            rar4_identity: h.rar4.map(|raw| (h.dictionary, raw.unpack_version, raw.method, raw.salt)),
            cancel: None,
            link: None,
        }
    }

    /// Creates the file at its place, if it has one and isn't created yet.
    fn open(&mut self, size: Option<u64>) -> crate::error::RarResult<()> {
        if let Some(place) = self.place.take() {
            self.out = Some(create_target_detailed(place, size)?);
        }
        Ok(())
    }

    /// Gives up on this file: what was written of it is removed, so a later run doesn't take it for finished.
    fn discard(&mut self) {
        self.failed = true;
        self.place = None;
        self.mem = None;
        self.link = None;
        drop(self.out.take());
    }

    pub(crate) fn hash_key(&self, keyed: bool) -> Option<&[u8; 32]> {
        self.cipher.as_ref().filter(|_| keyed).and_then(crate::rar5::member::PendingCipher::checksum_key)
    }

    /// Decoded bytes, to the checksums and the output file.
    fn take(&mut self, chunk: &[u8]) -> Result<()> {
        self.take_detailed(chunk).map_err(RarFault::into_legacy)
    }

    fn take_detailed(&mut self, chunk: &[u8]) -> crate::error::RarResult<()> {
        self.take_with(chunk, |_| Ok(()))
    }

    pub(crate) fn take_with(
        &mut self,
        mut chunk: &[u8],
        admit: impl FnOnce(&[u8]) -> crate::error::RarResult<()>,
    ) -> crate::error::RarResult<()> {
        if self.cancel.as_ref().is_some_and(Cancellation::is_canceled) {
            return Err(RarFault::new(RarFailure::Canceled, canceled_error()));
        }
        if let Some(cipher) = self.cipher.as_mut().filter(|cipher| cipher.stored_padding.is_some()) {
            chunk = cipher
                .trim_stored(chunk, self.checks.bytes)
                .map_err(|error| batch::decoder_failure(error, self.context.scope(), self.context.password))?;
            if chunk.is_empty() {
                return Ok(());
            }
        }
        let new_size = self.bytes.checked_add(chunk.len() as u64).ok_or_else(RarFault::counter_limit)?;
        admit(chunk)?;
        if let Some(mem) = self.mem.as_mut() {
            mem.extend_from_slice(chunk);
            self.bytes = new_size;
            return Ok(());
        }
        if !self.decoder_crc {
            self.hasher.update(chunk);
        }
        if let Some(b) = self.blake.as_mut() {
            b.update(chunk);
        }
        if let Some(out) = self.out.as_mut() {
            out.write_detailed(chunk).map_err(|e| e.detailed(false))?;
        }
        if let Some(link) = self.link.as_mut() {
            // more than a target may hold fails the size check or the target check
            let room = (link::MAX_TARGET as usize + 1).saturating_sub(link.target.len()).min(chunk.len());
            link.target.extend_from_slice(&chunk[..room]);
        }
        self.bytes = new_size;
        Ok(())
    }
}

impl Sink for Pending {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.take(bytes)
    }

    fn wants_crc(&self) -> bool {
        self.decoder_crc
    }

    fn crc(&mut self, crc: u32) {
        self.crc = Some(crc);
    }
}

impl Pending {
    pub(crate) fn verified_size(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn context(&self) -> &EntryContext {
        &self.context
    }

    fn start_cipher(
        context: &mut EntryContext,
        compressed: bool,
        params: crate::crypto::Rar5CryptParams,
        password: &str,
        size: Option<u64>,
    ) -> std::result::Result<PendingCipher, RarFailure> {
        let keys = crate::crypto::derive_rar5_keys(password, params.kdf_count, &params.salt, params.check)
            .map_err(|error| RarFailure::crypt(error, context.scope()))?;
        context.password = keys.evidence;
        Ok(PendingCipher::from_keys(params, keys, compressed, size))
    }

    pub(crate) fn start_selected_cipher(
        &mut self,
        params: crate::crypto::Rar5CryptParams,
        password: &str,
        size: Option<u64>,
    ) -> std::result::Result<(), RarFailure> {
        self.cipher = Some(Self::start_cipher(&mut self.context, self.compressed, params, password, size)?);
        Ok(())
    }

    /// RAR 3.x AES-128 for a selected RAR4 member, from keys derived for its salt.
    pub(crate) fn start_selected_legacy_cipher(&mut self, (key, iv): ([u8; 16], [u8; 16]), size: u64) {
        self.context.password = RarPasswordEvidence::VerifierUnavailable(crate::error::RarVerifierUnavailable::Absent);
        self.cipher = Some(PendingCipher::from_legacy(key, iv, size, self.compressed));
    }

    pub(crate) fn selected_cipher(&mut self) -> Option<&mut PendingCipher> {
        self.cipher.as_mut()
    }

    pub(crate) fn verify_selected(
        &mut self,
        size: Option<u64>,
        crc32: Option<u32>,
        blake2sp: Option<[u8; 32]>,
        keyed: bool,
    ) -> std::result::Result<RarVerification, RarFailure> {
        self.verify_checks(size, crc32, blake2sp, keyed)?;
        Ok(self.context.checks(size.is_some(), crc32.is_some(), blake2sp.is_some()))
    }

    fn verify_checks(
        &mut self,
        size: Option<u64>,
        crc32: Option<u32>,
        blake2sp: Option<[u8; 32]>,
        keyed: bool,
    ) -> std::result::Result<(), RarFailure> {
        let key = self.cipher.as_ref().filter(|_| keyed).and_then(crate::rar5::member::PendingCipher::checksum_key);
        self.checks.verify(&self.context, size, crc32, blake2sp, key)
    }
}

enum MemberDecodeError {
    Decoder(Error),
    Rar4(Rar4DecodeError),
    Sink(RarFault),
}

struct PendingSink<'a> {
    pending: &'a mut Pending,
    fault: Option<RarFault>,
}

impl Sink for PendingSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        if self.fault.is_none() {
            self.fault = self.pending.take_detailed(bytes).err();
        }
        if self.fault.is_some() { Err(Error::Corrupt("RAR output stopped")) } else { Ok(()) }
    }

    fn wants_crc(&self) -> bool {
        self.pending.wants_crc()
    }

    fn crc(&mut self, crc: u32) {
        self.pending.crc(crc);
    }
}

/// Whether a RAR4 file goes on from the history of the one before it.
fn rar4_continues(h: &FileHeader) -> bool {
    h.rar4.is_some_and(|raw| raw.flags & 0x10 != 0)
}

/// The decoder for this part of a compressed RAR4 file: a new one, the solid stream's next file, or the same file
/// going on from the volume before.
pub(crate) fn rar4_part_decoder(
    kept: &mut Option<Rar4Decoder>,
    h: &FileHeader,
    solid_archive: bool,
    window_limit: u64,
    cancel: Option<Cancellation>,
) -> std::result::Result<Rar4Decoder, Rar4DecodeError> {
    if h.split_before() {
        let mut decoder = kept.take().ok_or(Rar4DecodeError::State)?;
        decoder.extend_packed(h.packed_size)?;
        return Ok(decoder);
    }
    let raw = h.rar4.ok_or(Rar4DecodeError::Binding)?;
    if rar4_continues(h) {
        let mut decoder = kept.take().ok_or(Rar4DecodeError::State)?;
        let frame = crate::rar5::unpack::rar4::CoreFrame {
            ordinal: 0,
            packed: h.packed_size,
            unpacked: h.unpacked_size,
            unpack_version: raw.unpack_version,
            method: raw.method,
            dictionary: h.dictionary,
        };
        decoder.next_solid_member(frame)?;
        return Ok(decoder);
    }
    *kept = None;
    let mut decoder = Rar4Decoder::new_with_cancel(h.dictionary, h.packed_size, h.unpacked_size, window_limit, cancel)?;
    decoder.set_version(raw.unpack_version)?;
    if solid_archive {
        decoder.track_boundary();
    }
    Ok(decoder)
}

fn with_rar4_member_sink(
    pending: &mut Pending,
    selection: Option<&mut RarSelection<'_>>,
    decode: impl FnOnce(&mut dyn Sink) -> std::result::Result<(), Rar4DecodeError>,
) -> std::result::Result<(), MemberDecodeError> {
    if let Some(selection) = selection {
        let result = decode(&mut SelectedSink { pending, selection });
        if selection.cancel.is_canceled() {
            return Err(MemberDecodeError::Sink(RarFault::new(RarFailure::Canceled, Error::Corrupt("RAR4 canceled"))));
        }
        return result.map_err(MemberDecodeError::Rar4);
    }
    let mut sink = PendingSink { pending, fault: None };
    let result = decode(&mut sink);
    match sink.fault {
        Some(fault) => Err(MemberDecodeError::Sink(fault)),
        None => result.map_err(MemberDecodeError::Rar4),
    }
}

fn with_member_sink(
    pending: &mut Pending,
    selection: Option<&mut RarSelection<'_>>,
    decode: impl FnOnce(&mut dyn Sink) -> Result<()>,
) -> std::result::Result<(), MemberDecodeError> {
    if let Some(selection) = selection {
        return decode(&mut SelectedSink { pending, selection }).map_err(MemberDecodeError::Decoder);
    }
    let mut sink = PendingSink { pending, fault: None };
    let result = decode(&mut sink);
    match sink.fault {
        Some(fault) => Err(MemberDecodeError::Sink(fault)),
        None => result.map_err(MemberDecodeError::Decoder),
    }
}

struct RarSelection<'a> {
    sink: &'a mut dyn FnMut(&[u8]) -> Result<()>,
    emit: bool,
    packed_left: u64,
    decoded_left: u64,
    cancel: &'a Cancellation,
}

struct SelectedSink<'p, 's> {
    pending: &'p mut Pending,
    selection: &'p mut RarSelection<'s>,
}

impl Sink for SelectedSink<'_, '_> {
    fn put(&mut self, chunk: &[u8]) -> Result<()> {
        self.selection.cancel.check_io()?;
        let before = self.pending.bytes;
        self.pending.take(chunk)?;
        let count = self.pending.bytes - before;
        self.selection.decoded_left = self
            .selection
            .decoded_left
            .checked_sub(count)
            .ok_or_else(|| Error::Unsupported("RAR5 decoding exceeds the decoded byte limit".into()))?;
        if self.selection.emit && count > 0 {
            (self.selection.sink)(&chunk[..count as usize])?;
        }
        Ok(())
    }

    fn wants_crc(&self) -> bool {
        self.pending.wants_crc()
    }

    fn crc(&mut self, crc: u32) {
        self.pending.crc(crc);
    }
}

/// What a file is checked against once all of it is in.
struct Checks {
    crc32: Option<u32>,
    blake2sp: Option<[u8; 32]>,
    keyed: bool,
    size: Option<u64>,
    meta: Meta,
}

impl From<&FileHeader> for Checks {
    fn from(h: &FileHeader) -> Self {
        Checks {
            crc32: h.crc32,
            blake2sp: h.blake2sp,
            keyed: h.crypt.as_ref().is_some_and(|crypt| crypt.tweaked_crc),
            size: (!h.size_unknown()).then_some(h.unpacked_size),
            meta: Meta::from(h),
        }
    }
}

/// A file of a solid stream whose blocks went to the decoder behind the ones before it.
type Queued = (Pending, Checks);

/// Queued files of a solid stream held open at most, when extracting and when testing: past this, the decoder
/// catches up to half as many.
const MAX_OPEN_QUEUED: usize = 64;
const MAX_TESTED_QUEUED: usize = 1024;

/// Queued files up to this size are gathered in memory and created, written and finished on a worker.
const GATHER_MAX: u64 = 1 << 20;

const NEEDS_EARLIER: &str = "needs the files before it in this solid archive, which weren't decoded";

struct Books<'a, 'r> {
    reports: &'a mut Reports<'r>,
    batch: &'a mut Option<Batch>,
    mode: Mode,
}

impl Books<'_, '_> {
    /// Takes in every file the workers hold.
    fn catch_up(&mut self) -> RunResult<()> {
        let Some(batch) = self.batch.as_mut() else { return Ok(()) };
        let mode = self.mode;
        batch.drain(&mut |done| apply_done(self.reports, mode, done))
    }

    fn catch_up_for_completion(&mut self) -> RunResult<()> {
        let first = self.catch_up();
        if self.reports.typed() && matches!(first, Err(RunFault::Reported { .. })) {
            while matches!(self.catch_up(), Err(RunFault::Reported { .. })) {}
        }
        first
    }

    fn fail(&mut self, ctx: &EntryContext, failure: RarFailure, legacy: impl std::fmt::Display) -> RunResult<()> {
        let drained = self.catch_up_for_completion();
        if drained.is_err() && !matches!(drained, Err(RunFault::Reported { .. })) {
            return drained;
        }
        let reported = self.reports.failed(ctx, Arc::new(failure), legacy);
        drained.and(reported)
    }

    fn terminal(&mut self, ctx: &EntryContext, fault: RarFault) -> RunFault {
        // Typed events keep their order even when a worker reports a secondary fatal error.
        if self.reports.typed() {
            while matches!(self.catch_up(), Err(RunFault::Reported { .. })) {}
        }
        self.reports.terminal(ctx, fault)
    }
}

/// A file's last part is in: checks it whole and finishes it, or hands it to a worker for that when its bytes were
/// gathered.
fn check_and_finish(books: &mut Books<'_, '_>, c: &Checks, mut p: Pending) -> RunResult<()> {
    if let Some(packed) = p.mem.take() {
        let job = Job {
            context: p.context,
            data: JobData {
                packed,
                method: 0,
                dictionary: 0,
                size: c.size.unwrap_or(p.checks.bytes),
                size_checked: c.size.is_some(),
                crc32: c.crc32,
                blake2sp: c.blake2sp,
                out: p.place.take(),
                meta: c.meta,
            },
        };
        let Some(batch) = books.batch.as_mut() else {
            return Err(invariant("no file workers", Error::Io(std::io::Error::other("no file workers"))).into());
        };
        return batch.submit(job, &mut |done| apply_done(books.reports, books.mode, done));
    }
    if p.passive {
        return Ok(());
    }
    if let Err(failure) = p.verify_checks(c.size, c.crc32, c.blake2sp, c.keyed) {
        let reason = match &failure {
            RarFailure::Integrity { reason, .. } | RarFailure::EncryptedIntegrity { reason, .. } => reason,
            _ => unreachable!("member checks return integrity failures"),
        };
        match reason {
            RarIntegrityReason::DeclaredHashUnavailable => {
                p.discard();
                return books.fail(
                    &p.context,
                    failure,
                    "its BLAKE2sp hash starts only in a later part, so it can't be checked",
                );
            }
            RarIntegrityReason::FinalChecks { .. } => {
                p.discard();
                return books.fail(&p.context, failure, "checksum error");
            }
            RarIntegrityReason::DecodedSize { expected, actual } => {
                let (expected, actual) = (*expected, *actual);
                p.discard();
                return books.fail(
                    &p.context,
                    failure,
                    format_args!("{actual} bytes where the header says {expected}"),
                );
            }
            _ => unreachable!("unexpected member check failure"),
        }
    }
    if let Some(out) = p.out.take()
        && let Err(e) = out.finish_detailed(|file| finish_file(file, &c.meta))
    {
        return Err(books.terminal(&p.context, e.detailed(false)));
    }
    if let Some(LinkOut { place, rel, target }) = p.link.take() {
        if !link::contained(&rel, &target) {
            let failure = RarFailure::Policy { reason: RarPolicyReason::LinkTarget, path: place.path };
            return books.fail(&p.context, failure, blocked_message(&RarPolicyReason::LinkTarget));
        }
        // a rename mode's reserved file is replaced by the link
        let (path, replace) = match place.reserved {
            Some(reserved) => (reserved.into_parts().1, true),
            None => (place.path, place.replace),
        };
        if let Err(e) = link::create(&path, &target, replace) {
            return Err(
                books.terminal(&p.context, RarFault::output(IoOperation::CreateFile, Some(path), None, e, false))
            );
        }
    }
    let drained = if books.reports.typed() { books.catch_up_for_completion() } else { Ok(()) };
    if drained.is_err() && !matches!(drained, Err(RunFault::Reported { .. })) {
        return drained;
    }
    let reported = books.reports.verified(
        &p.context,
        p.bytes,
        p.context.checks(c.size.is_some(), c.crc32.is_some(), c.blake2sp.is_some()),
        books.mode,
    );
    drained.and(reported)
}

/// Where a solid stream's queued files' bytes go: to the oldest file not yet finished, which an empty slice from the
/// decoder finishes.
fn with_route(
    queued: &mut VecDeque<Queued>,
    books: &mut Books<'_, '_>,
    decode: impl FnOnce(&mut dyn Sink) -> Result<()>,
) -> std::result::Result<(), RouteError> {
    let mut route = Route { queued, books, fault: None };
    let result = decode(&mut route);
    match route.fault {
        Some(fault) => Err(RouteError::Fatal(fault)),
        None => result.map_err(RouteError::Decoder),
    }
}

enum RouteError {
    Decoder(Error),
    Fatal(RunFault),
}

struct Route<'a, 'b, 'r> {
    queued: &'a mut VecDeque<Queued>,
    books: &'a mut Books<'b, 'r>,
    fault: Option<RunFault>,
}

impl Sink for Route<'_, '_, '_> {
    fn put(&mut self, chunk: &[u8]) -> Result<()> {
        if self.fault.is_some() {
            return Err(Error::Corrupt("RAR output stopped"));
        }
        let result = if self.queued.is_empty() {
            let reason = "more files than were queued";
            Err(invariant(reason, Error::Corrupt(reason)).into())
        } else if chunk.is_empty() {
            let (p, c) = self.queued.pop_front().unwrap();
            check_and_finish(self.books, &c, p)
        } else {
            let (p, _) = self.queued.front_mut().unwrap();
            p.take_detailed(chunk).map_err(|fault| {
                p.discard();
                if p.passive { fault.into() } else { self.books.terminal(&p.context, fault) }
            })
        };
        if let Err(fault) = result {
            self.fault = Some(fault);
            return Err(Error::Corrupt("RAR output stopped"));
        }
        Ok(())
    }

    fn wants_crc(&self) -> bool {
        self.queued.front().is_some_and(|(p, _)| p.wants_crc())
    }

    fn crc(&mut self, crc: u32) {
        if let Some((p, _)) = self.queued.front_mut() {
            p.crc = Some(crc);
        }
    }
}

/// Whether a decoder's error is the file's own trouble rather than the run's.
fn decoding_error(e: &Error) -> bool {
    matches!(e, Error::Corrupt(_) | Error::Unsupported(_) | Error::Truncated)
}

type HistoryFailure = (Option<u64>, Option<Arc<RarFailure>>);

fn history_failure(cause: Option<&HistoryFailure>) -> RarFailure {
    let (predecessor, cause) = cause.cloned().unwrap_or_default();
    RarFailure::SolidHistoryUnavailable { predecessor, cause }
}

struct Run<'a, 'r, 'c> {
    opts: &'a Options,
    password: Option<&'a str>,
    reports: &'r mut Reports<'c>,
    order: u64,
    /// the rename attempts this run has left
    rename_budget: RenameBudget,
    dir_meta: Vec<(PathBuf, Meta)>,
    unavailable: Option<HistoryFailure>,
    pending: Option<Pending>,
    /// the decoder, kept between files of a solid stream
    stream: Option<Unpacker>,
    /// the RAR4 decoder, kept between the parts of a split file and the files of a solid stream
    rar4: Option<Rar4Decoder>,
    /// RAR 3.x keys already derived for the run's password, by salt
    rar4_keys: crate::crypto::Rar4KeyCache,
    /// threads for work spread over files; 1 for none
    threads: usize,
    /// small files being decoded and written on other threads
    batch: Option<Batch>,
    /// where the files handed to the workers since they last finished everything are written, folded to lower case
    /// as a case-insensitive file system would; a later file going to one of these waits for them first
    batch_paths: HashSet<String>,
    /// files of a solid stream fed to the decoder and not yet finished, oldest first: their blocks may still be with
    /// its workers
    queued: VecDeque<Queued>,
    /// where the queued files are written, as `batch_paths`
    queued_paths: HashSet<String>,
    /// folders under the destination made (or found) so far
    dirs: Dirs,
    selection: Option<RarSelection<'a>>,
    /// members with a first header seen so far: the next one's listing position
    members: u64,
    /// checked before each member and as each member's data is decoded
    cancel: Option<Cancellation>,
}

/// A file finished on another thread, counted and reported as if done here.
fn apply_done(reports: &mut Reports<'_>, mode: Mode, done: Done) -> RunResult<()> {
    let ctx = &done.context;
    match done.outcome {
        Outcome::Done { bytes, size_checked, crc32_checked, blake2sp_checked } => {
            reports.verified(ctx, bytes, ctx.checks(size_checked, crc32_checked, blake2sp_checked), mode)
        }
        Outcome::Failed { reason, legacy } => reports.failed(ctx, Arc::from(reason), legacy),
        Outcome::Fatal(fault) => Err(reports.terminal(ctx, fault)),
        Outcome::Canceled => Err(RarFault::new(RarFailure::Canceled, canceled_error()).into()),
    }
}

fn invariant(reason: &'static str, legacy: Error) -> RarFault {
    RarFault::new(RarFailure::Internal(RarInternal::Invariant(reason)), legacy)
}

fn rar_run(
    first: &Path,
    opts: &Options,
    password: Option<&str>,
    mut report: impl FnMut(&str),
) -> std::result::Result<Summary, RunError> {
    let mut reports = Reports::legacy(&mut report);
    let result = rar_run_shared(first, opts, password, &mut reports);
    let Reports::Legacy { summary, .. } = reports else { unreachable!() };
    legacy_result(result, summary)
}

/// A legacy RAR run's result: a terminal error keeps the renames made before it.
fn legacy_result(result: RunResult<()>, mut summary: Summary) -> std::result::Result<Summary, RunError> {
    match result {
        Ok(()) => Ok(summary),
        Err(fault) => Err(RunError::new(fault.into_legacy(), std::mem::take(&mut summary.renames))),
    }
}

/// Test or extract all logical members of a RAR archive, including RAR with an SFX prefix.
///
/// The synchronous callback runs on the calling thread, in archive reporting order. Workers may
/// publish files independently. A callback panic unwinds without rolling back completed outputs.
///
/// A successful traversal can include failed or skipped members. Every normal member that
/// [`Options::select`] takes (every one without a filter) counts as a match, including directories
/// and existing-target skips. Unselected members produce no outcome and keep their listing index.
/// An empty archive, a volume containing only orphan continuations, or a filter that takes nothing
/// can complete with no matches. A terminal error contains partial
/// counts for the completions reported before return.
#[allow(clippy::result_large_err, reason = "the public error carries partial counts and an optional entry identity")]
pub fn run_rar_with_outcomes(
    first: &Path,
    opts: &Options,
    password: Option<&str>,
    mut on_entry: impl FnMut(&RarEntryOutcome),
) -> std::result::Result<RarRunSummary, RarRunError> {
    let mut reports = Reports::Typed { summary: RarRunSummary::default(), callback: &mut on_entry };
    let result = rar_run_shared(first, opts, password, &mut reports);
    let Reports::Typed { summary, .. } = reports else { unreachable!() };
    match result {
        Ok(()) => Ok(summary),
        Err(fault) => Err(fault.into_public(summary)),
    }
}

fn rar_run_shared<'a>(
    first: &Path,
    opts: &Options,
    password: Option<&str>,
    reports: &mut Reports<'a>,
) -> RunResult<()> {
    rar_run_shared_open(first, opts, password, None, reports, || Volume::open_detailed(first, password))
}

fn rar_run_shared_open<'a>(
    first: &Path,
    opts: &Options,
    password: Option<&str>,
    cancel: Option<&Cancellation>,
    reports: &mut Reports<'a>,
    open: impl FnOnce() -> crate::error::RarResult<Volume>,
) -> RunResult<()> {
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest)
            .map_err(|e| RarFault::output(IoOperation::CreateDirectory, Some(opts.dest.clone()), None, e, false))?;
    }
    let first_volume = open()?;
    let mut opts = match opts.protecting_detailed(first) {
        Ok(opts) => opts,
        Err(fault) => {
            reports.volume()?;
            return Err(fault.into());
        }
    };
    if let Cow::Owned(opts) = &mut opts {
        // An end header can request the next volume even if the main header omits the volume flag.
        // Reserve existing consecutive names before any member can replace one.
        let mut next = next_volume(first);
        while let Some(path) = next {
            match path.canonicalize() {
                Ok(canonical) => {
                    opts.protected_paths.insert(canonical);
                    next = next_volume(&path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => {
                    reports.volume()?;
                    return Err(RarFault::input(IoOperation::Metadata, Some(path), None, e).into());
                }
            }
        }
    }
    let threads = opts.threads.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    // The hidden size knob tests decoding blocks on workers, which batching would bypass.
    let threads = if opts.parallel_min.is_some() { 1 } else { threads };
    let mut run = Run::new(&opts, password, reports, threads);
    run.cancel = cancel.cloned();
    let walked = walk_rar(first_volume, &mut run).and_then(|()| run.drain());
    let canceled = cancel.is_some_and(Cancellation::is_canceled);
    if canceled {
        // Nothing more is published or reported: the workers drop what is still queued unwritten.
        run.batch = None;
    }
    if walked.is_err() && !canceled {
        // Retain the primary failure. Typed runs report each available genuine completion during cleanup.
        loop {
            match run.drain() {
                Err(RunFault::Reported { .. }) if run.reports.typed() => continue,
                _ => break,
            }
        }
    }
    let result = if let Some(mut p) = run.pending.take() {
        let already_reported = p.failed || p.passive;
        p.discard();
        if walked.is_ok() && !p.hidden && (!run.reports.typed() || !already_reported) {
            let failure = p.context.integrity(RarIntegrityReason::MissingSplitContinuation, false);
            run.reports.failed(&p.context, Arc::new(failure), "archive ends before this file does")
        } else {
            walked
        }
    } else {
        walked
    };
    finish_dir_meta(&mut run.dir_meta);
    result
}

fn rar_read_at(
    first: &Path,
    chain_start: usize,
    index: usize,
    name: &str,
    password: Option<&str>,
    selection: RarSelection<'_>,
    observer: &mut SelectedReadObserver<'_>,
) -> Result<()> {
    let opts = Options {
        mode: Mode::Test,
        dest: PathBuf::new(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
    };
    let cancel = selection.cancel;
    let mut callback = |_: &str| {};
    let mut reports = Reports::legacy(&mut callback);
    let mut run = Run::new(&opts, password, &mut reports, 1);
    run.selection = Some(RarSelection { sink: &mut *selection.sink, ..selection });
    let mut next = 0;
    let mut selected = false;
    let mut prerequisite = false;
    let mut complete = false;
    observer.notify(0, first, SelectedReadRole::Header, Some(cancel))?;
    let volume = Volume::open_with_password(first, run.password)?;
    walk_until_observed(volume, run.password, Some(cancel), observer, |volume, block, volume_index, observer| {
        let Block::File(header) = block else { return Ok(false) };
        if !header.split_before() {
            if run.pending.is_some() {
                return Err(Error::Truncated);
            }
            selected = next == index;
            prerequisite = (chain_start..index).contains(&next)
                && header.method != 0
                && !header.is_dir()
                && header.redirection.is_none();
            next += 1;
            if selected && (header.name != name || header.is_dir() || header.redirection.is_some()) {
                return Err(Error::Corrupt("RAR5 entry changed since it was selected"));
            }
        }
        if !selected && !prerequisite {
            return Ok(false);
        }
        if header.split_before() && run.pending.is_none() {
            return Err(Error::Truncated);
        }
        if let Some(selection) = &mut run.selection {
            selection.emit = selected;
        }
        observer.notify(
            volume_index,
            &volume.path,
            if selected { SelectedReadRole::Selected } else { SelectedReadRole::Prerequisite },
            Some(cancel),
        )?;
        let Reports::Legacy { summary, .. } = &run.reports else { unreachable!() };
        let before = summary.files;
        let crypt = header.crypt.map(Ok);
        let split_after = header.split_after();
        run.file_block(volume, header, crypt).map_err(RunFault::into_legacy)?;
        let Reports::Legacy { summary, .. } = &run.reports else { unreachable!() };
        if let Some(error) = summary.errors.first() {
            return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error.clone())));
        }
        complete = selected && !split_after && summary.files > before && run.pending.is_none();
        Ok(complete)
    })?;
    if !complete {
        return Err(Error::Truncated);
    }
    Ok(())
}

impl<'a, 'r, 'c> Run<'a, 'r, 'c> {
    fn new(opts: &'a Options, password: Option<&'a str>, reports: &'r mut Reports<'c>, threads: usize) -> Self {
        Self {
            opts,
            password: password.filter(|s| !s.is_empty()),
            reports,
            order: 0,
            rename_budget: RenameBudget::default(),
            dir_meta: Vec::new(),
            unavailable: None,
            pending: None,
            stream: None,
            rar4: None,
            rar4_keys: Default::default(),
            threads,
            batch: None,
            batch_paths: HashSet::new(),
            queued: VecDeque::new(),
            queued_paths: HashSet::new(),
            dirs: Dirs::default(),
            selection: None,
            members: 0,
            cancel: None,
        }
    }
}

impl Run<'_, '_, '_> {
    /// Finishes everything still on other threads.
    fn drain(&mut self) -> RunResult<()> {
        self.drain_solid()?;
        self.drain_batch()
    }

    fn drain_batch(&mut self) -> RunResult<()> {
        let Some(mut batch) = self.batch.take() else { return Ok(()) };
        let result = batch.drain(&mut |done| apply_done(self.reports, self.opts.mode, done));
        self.batch = Some(batch);
        self.batch_paths.clear();
        result
    }

    /// Whether `h` goes to the workers: it can, and at least one of them started.
    fn goes_to_batch(&mut self, vol: &Volume, h: &FileHeader) -> bool {
        self.batchable(vol, h)
            && self.batch.get_or_insert_with(|| Batch::new(self.threads, self.cancel.clone())).usable()
    }

    /// Reports a failure after every file before it, so reports keep archive order.
    fn fail_in_order(
        &mut self,
        ctx: &EntryContext,
        failure: RarFailure,
        why: impl std::fmt::Display,
    ) -> RunResult<Arc<RarFailure>> {
        self.drain()?;
        let failure = Arc::new(failure);
        self.reports.failed(ctx, Arc::clone(&failure), why)?;
        Ok(failure)
    }

    fn terminal(&mut self, ctx: &EntryContext, mut fault: RarFault) -> RunFault {
        if let RarFailure::Integrity { scope, reason: RarIntegrityReason::TruncatedData, password } =
            fault.failure.as_mut()
        {
            *scope = ctx.scope();
            *password = ctx.password;
        }
        if self.reports.typed() {
            let _ = self.drain_solid();
        }
        Books { reports: self.reports, batch: &mut self.batch, mode: self.opts.mode }.terminal(ctx, fault)
    }

    fn pending_terminal(&mut self, pending: &Pending, fault: RarFault) -> RunFault {
        if pending.passive { fault.into() } else { self.terminal(&pending.context, fault) }
    }

    fn lost_history(&mut self, ctx: &EntryContext, cause: Option<Arc<RarFailure>>) {
        self.stream = None;
        self.rar4 = None;
        self.unavailable = Some((ctx.entry.index, cause));
    }

    fn dependency_failure(&self) -> RarFailure {
        history_failure(self.unavailable.as_ref())
    }

    /// Whether `h` can go to the workers whole: a small file standing alone in one volume.
    fn batchable(&self, vol: &Volume, h: &FileHeader) -> bool {
        h.format == RarFormat::Rar5
            && self.threads > 1
            && !vol.main.is_solid()
            && !h.solid
            && !h.encrypted
            && !h.split_before()
            && !h.split_after()
            && !h.size_unknown()
            && h.unpacked_size <= batch::JOB_MAX
            && h.packed_size <= batch::JOB_MAX
            && (h.method == 0 || h.packed_size > 0)
    }

    /// Reads `h`'s data and hands it to the workers.
    fn send_to_batch(
        &mut self,
        vol: &mut Volume,
        h: &FileHeader,
        ctx: EntryContext,
        out: Option<Place>,
    ) -> RunResult<()> {
        let mut packed = Vec::with_capacity(h.packed_size as usize);
        vol.read_fast(h.method == 0);
        if let Err(ReadDataError::Input(fault)) = vol.read_data_detailed(h.data_at, h.packed_size, |piece, range| {
            packed.extend_from_slice(&piece.bytes()[range]);
            Ok::<_, std::convert::Infallible>(())
        }) {
            return Err(self.terminal(&ctx, fault));
        }
        let job = Job {
            context: ctx,
            data: JobData {
                packed,
                method: h.method,
                dictionary: h.dictionary,
                size: h.unpacked_size,
                size_checked: true,
                crc32: h.crc32,
                blake2sp: h.blake2sp,
                out,
                meta: Meta::from(h),
            },
        };
        let batch = self.batch.get_or_insert_with(|| Batch::new(self.threads, self.cancel.clone()));
        batch.submit(job, &mut |done| apply_done(self.reports, self.opts.mode, done))
    }

    fn file_block(&mut self, vol: &mut Volume, mut h: FileHeader, crypt: MemberCrypt) -> RunResult<()> {
        let continuation = h.split_before();
        if continuation && self.pending.as_ref().is_some_and(|p| p.context.entry.name == h.name) {
            let p = self.pending.take().unwrap();
            return self.continue_file(vol, &h, p, crypt);
        }
        let name = std::mem::take(&mut h.name);
        let selected = if continuation {
            // an orphan continuation has no listing position to filter on
            self.opts.select.is_none()
        } else {
            let ordinal = self.members;
            self.members = ordinal.checked_add(1).ok_or_else(RarFault::counter_limit)?;
            self.opts.selects(&name, None, h.is_dir(), ordinal)
        };
        if !selected {
            return self.unselected_block(vol, h, name, continuation);
        }
        let ctx = self.reports.encounter(!continuation, &mut self.order, name, h.method)?;
        if let Some(reason) = h.rar4_unsupported() {
            let cause =
                self.fail_in_order(&ctx, RarFailure::Unsupported(reason), "unsupported RAR4 payload feature")?;
            if vol.main.is_solid() && h.method != 0 && !h.is_dir() {
                self.lost_history(&ctx, Some(cause));
            }
            return Ok(());
        }
        if !self.goes_to_batch(vol, &h) && !self.queueable(vol, &h) && !self.beside_batch(vol, &h) {
            self.drain_batch()?;
        }
        // a continuation of some other member, after one that wants its next part, is taken as a member of its own
        if !self.end_pending()? && continuation {
            if self.reports.typed() {
                self.drain()?;
            }
            return self.reports.skipped(&ctx, RarSkipReason::MissingStart);
        }
        self.start_file(vol, &h, ctx, crypt)
    }

    /// A new member starts while the one before still waits for a part: that part is missing. Whether one waited.
    fn end_pending(&mut self) -> RunResult<bool> {
        let Some(mut p) = self.pending.take() else { return Ok(false) };
        if !p.hidden && (!self.reports.typed() || (!p.failed && !p.passive)) {
            let failure = Arc::new(p.context.integrity(RarIntegrityReason::MissingSplitContinuation, false));
            self.reports.failed(&p.context, Arc::clone(&failure), "next part is missing")?;
            if p.compressed {
                self.lost_history(&p.context, Some(failure));
            }
        } else if p.compressed && self.stream.is_some() {
            self.lost_history(&p.context, None);
        }
        p.discard();
        self.stream = None;
        if p.compressed {
            self.rar4 = None;
        }
        Ok(true)
    }

    /// A member the run's filter didn't take. It is not reported or counted, but in a solid archive a compressed one
    /// is still decoded when a later member may need its history.
    fn unselected_block(&mut self, vol: &mut Volume, h: FileHeader, name: String, continuation: bool) -> RunResult<()> {
        if self.pending.is_some() {
            // the member before is reported missing a part, after everything ahead of it
            self.drain_batch()?;
        }
        self.end_pending()?;
        if continuation {
            return Ok(());
        }
        // every member with a first header takes its listing index, even one this reader can't decode
        let mut ctx = self.reports.unselected(self.order, name, h.method)?;
        if let Some(reason) = h.rar4_unsupported() {
            if vol.main.is_solid() && h.method != 0 && !h.is_dir() {
                self.drain()?;
                self.lost_history(&ctx, Some(Arc::new(RarFailure::Unsupported(reason))));
            }
            return Ok(());
        }
        if !(vol.main.is_solid() && h.method != 0 && !h.is_dir()) {
            if h.split_after() {
                // its later parts are passed over too
                let mut p = Pending::new(&h, ctx);
                p.failed = true;
                p.hidden = true;
                self.pending = Some(p);
            }
            return Ok(());
        }
        let (cipher, failure) = match (h.crypt, self.password) {
            _ if h.format == RarFormat::Rar4 => match self.legacy_cipher(&mut ctx, &h) {
                Some(Ok(cipher)) => (Some(cipher), None),
                Some(Err(fault)) => return Err(fault.into()),
                None => (None, None),
            },
            (Some(params), Some(password)) => {
                let size = (!h.size_unknown()).then_some(h.unpacked_size);
                match Pending::start_cipher(&mut ctx, true, params, password, size) {
                    Ok(cipher) => (Some(cipher), None),
                    // a wrong password is why the members after it lose their history
                    Err(failure) => (None, Some(Arc::new(failure))),
                }
            }
            _ => (None, None),
        };
        self.pass_over(vol, &h, ctx, cipher, failure)?;
        // a member split over volumes waits here for its next part: it is this unselected one
        if let Some(p) = self.pending.as_mut() {
            p.hidden = true;
        }
        Ok(())
    }

    /// Decodes usable passive history in a solid archive.
    fn pass_over(
        &mut self,
        vol: &mut Volume,
        h: &FileHeader,
        ctx: EntryContext,
        cipher: Option<PendingCipher>,
        failure: Option<Arc<RarFailure>>,
    ) -> RunResult<()> {
        if h.method != 0
            && (!vol.main.is_solid()
                || h.algorithm != 0
                || h.redirection.is_some()
                || (h.encrypted && cipher.is_none()))
        {
            self.drain()?;
            self.lost_history(&ctx, failure);
        } else if vol.main.is_solid() && h.method != 0 {
            let mut p = Pending::new(h, ctx);
            p.passive = true;
            p.cipher = cipher;
            p.cancel = self.cancel.clone();
            return self.begin_decoding(vol, h, p);
        }
        if h.split_after() {
            let mut p = Pending::new(h, ctx);
            p.failed = true;
            self.pending = Some(p);
        }
        Ok(())
    }

    fn start_file(
        &mut self,
        vol: &mut Volume,
        h: &FileHeader,
        mut ctx: EntryContext,
        crypt: MemberCrypt,
    ) -> RunResult<()> {
        if let Some(v) = h.version
            && self.opts.mode == Mode::Extract
        {
            self.drain()?;
            self.reports.skipped(&ctx, RarSkipReason::OlderVersion(v))?;
            return self.pass_over(vol, h, ctx, None, None);
        }
        // A name mapped from bytes that aren't UTF-8 is written under its private-use characters; one that can't
        // be written one to one is refused (`crate::path::rar_output_name`).
        // (`h.name` was moved into `ctx`)
        let output = crate::path::rar_output_name(&ctx.entry.name, h.format == RarFormat::Rar4);
        if self.opts.mode == Mode::Extract && output.is_none() {
            let cause = self.fail_in_order(
                &ctx,
                RarFailure::Unsupported(RarUnsupported::NameEncoding),
                "the name can't be written one to one",
            )?;
            return self.pass_over(vol, h, ctx, None, Some(cause));
        }
        let rel = if self.selection.is_some() {
            PathBuf::new()
        } else {
            match sanitize(output.as_deref().unwrap_or(&ctx.entry.name), !h.is_unix()) {
                Ok(rel) => rel,
                Err(e) => {
                    let failure = RarFailure::Policy {
                        reason: RarPolicyReason::UnsafePath,
                        path: PathBuf::from(&ctx.entry.name),
                    };
                    let cause = self.fail_in_order(&ctx, failure, e)?;
                    return self.pass_over(vol, h, ctx, None, Some(cause));
                }
            }
        };
        let rel = if self.opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        let key = rel.to_string_lossy().to_lowercase();
        if self.opts.mode == Mode::Extract
            && rel.ancestors().any(|a| {
                let a = a.to_string_lossy().to_lowercase();
                self.batch_paths.contains(&a) || self.queued_paths.contains(&a)
            })
        {
            self.drain()?;
        }
        if h.is_dir() {
            if self.reports.typed() {
                self.drain()?;
            }
            if self.opts.mode == Mode::Extract && !self.opts.flatten {
                make_dirs_known_detailed(&self.opts.dest, &rel, &mut self.dirs).map_err(|e| self.terminal(&ctx, e))?;
                self.dir_meta.push((self.opts.dest.join(&rel), Meta::from(h)));
            }
            return self.reports.directory(&ctx);
        }
        let refuse = if let Some(reason) = h.rar4_unsupported() {
            Some((RarFailure::Unsupported(reason), "unsupported RAR4 payload feature"))
        } else if let Some(Err(e)) = crypt {
            Some((RarFailure::crypt(e, ctx.scope()), "encrypted (password required)"))
        } else if h.encrypted && (self.password.is_none() || (h.format == RarFormat::Rar5 && h.crypt.is_none())) {
            Some((RarFailure::PasswordRequired { scope: ctx.scope() }, "encrypted (password required)"))
        } else if h.method != 0 && h.algorithm != 0 {
            let reason = RarUnsupported::CompressionAlgorithm { algorithm: h.algorithm, method: h.method };
            Some((RarFailure::Unsupported(reason), "RAR 7 compression is not supported yet"))
        } else {
            None
        };
        if let Some((failure, why)) = refuse {
            let cause = self.fail_in_order(&ctx, failure, why)?;
            return self.pass_over(vol, h, ctx, None, Some(cause));
        }
        if let Some(link) = &h.redirection {
            let kind = match link {
                Redirection::UnixSymlink(_) => 1,
                Redirection::WindowsSymlink(_) => 2,
                Redirection::Junction(_) => 3,
                Redirection::HardLink(_) => 4,
                Redirection::FileCopy(_) => 5,
                Redirection::Unknown(kind) => *kind,
            };
            let reason = RarFailure::Unsupported(RarUnsupported::Redirection { kind });
            let cause = self.fail_in_order(&ctx, reason, format_args!("links are not supported yet ({link:?})"))?;
            return self.pass_over(vol, h, ctx, None, Some(cause));
        }
        let cipher = if h.format == RarFormat::Rar4 {
            match self.legacy_cipher(&mut ctx, h) {
                Some(Ok(cipher)) => Some(cipher),
                Some(Err(fault)) => return Err(self.terminal(&ctx, fault)),
                None => None,
            }
        } else if let (Some(cp), Some(pw)) = (h.crypt, self.password) {
            match Pending::start_cipher(&mut ctx, h.method != 0, cp, pw, (!h.size_unknown()).then_some(h.unpacked_size))
            {
                Ok(cipher) => Some(cipher),
                Err(failure) => {
                    let why = if matches!(failure, RarFailure::Internal(_)) {
                        "invalid encryption key"
                    } else {
                        "wrong password"
                    };
                    let cause = self.fail_in_order(&ctx, failure, why)?;
                    return self.pass_over(vol, h, ctx, None, Some(cause));
                }
            }
        } else {
            None
        };

        let link = h.is_rar4_symlink() && self.opts.mode == Mode::Extract;
        if link && (h.unpacked_size > link::MAX_TARGET || !cfg!(unix)) {
            let reason = RarFailure::Unsupported(RarUnsupported::Rar4Feature("symbolic link"));
            let cause = self.fail_in_order(&ctx, reason, "unsupported symbolic link")?;
            return self.pass_over(vol, h, ctx, cipher, Some(cause));
        }
        let place = if self.opts.mode == Mode::Extract {
            let mut renamed = None;
            let order = ctx.entry.order;
            let mut log = RenameLog {
                budget: &mut self.rename_budget,
                record: &mut |r| {
                    renamed = Some(r.clone());
                    self.reports.renamed_at(order, r)
                },
            };
            let checked = check_target_detailed(self.opts, &rel, Some(&mut self.dirs), &mut log);
            ctx.renamed = renamed;
            match checked.map_err(|e| self.terminal(&ctx, e))? {
                DetailedChecked::Write(place) => Some(place),
                DetailedChecked::Exists => {
                    self.drain()?;
                    self.reports.skipped(&ctx, RarSkipReason::ExistingTarget)?;
                    return self.pass_over(vol, h, ctx, cipher, None);
                }
                DetailedChecked::Declined => {
                    self.drain()?;
                    self.reports.skipped(&ctx, RarSkipReason::Declined)?;
                    return self.pass_over(vol, h, ctx, cipher, None);
                }
                DetailedChecked::Blocked(reason) => {
                    let message = blocked_message(&reason);
                    let cause = self.fail_in_order(
                        &ctx,
                        RarFailure::Policy { reason, path: self.opts.dest.join(&rel) },
                        message,
                    )?;
                    return self.pass_over(vol, h, ctx, cipher, Some(cause));
                }
            }
        } else {
            None
        };
        if self.goes_to_batch(vol, h) {
            if self.opts.mode == Mode::Extract {
                self.batch_paths.insert(key);
            }
            return self.send_to_batch(vol, h, ctx, place);
        }
        let mut p = Pending::new(h, ctx);
        p.cipher = cipher;
        p.cancel = self.cancel.clone();
        p.key = (self.opts.mode == Mode::Extract).then_some(key);
        p.place = place;
        if link && let Some(place) = p.place.take() {
            p.link = Some(LinkOut { place, rel, target: Vec::new() });
        }
        self.begin_decoding(vol, h, p)
    }

    /// RAR 3.x AES-128 for an encrypted RAR4 member, when the run has a password: derived once per salt. It has no
    /// password check value, so a wrong password shows as a checksum or decoder error.
    fn legacy_cipher(
        &mut self,
        ctx: &mut EntryContext,
        h: &FileHeader,
    ) -> Option<crate::error::RarResult<PendingCipher>> {
        let salt = h.rar4.and_then(|raw| raw.salt).filter(|_| h.encrypted)?;
        let password = self.password?;
        let cancel = self.selection.as_ref().map(|selection| selection.cancel.clone());
        Some(match self.rar4_keys.keys(password, &salt, cancel.as_ref()) {
            Ok((key, iv)) => {
                ctx.password = RarPasswordEvidence::VerifierUnavailable(crate::error::RarVerifierUnavailable::Absent);
                Ok(PendingCipher::from_legacy(key, iv, h.unpacked_size, h.method != 0))
            }
            Err(_) => Err(RarFault::new(RarFailure::Canceled, Error::Io(io::Error::from(io::ErrorKind::Interrupted)))),
        })
    }

    /// Sets the decoder up for a compressed file, then reads its first part.
    fn begin_decoding(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> RunResult<()> {
        let size = (!h.size_unknown()).then_some(h.unpacked_size);
        let queues = self.queueable(vol, h);
        if queues
            && h.solid
            && !self.queued.is_empty()
            && let Some(u) = self.stream.as_mut()
            && h.dictionary <= u.reach()
        {
            // every queued file holds its output open
            let most = if self.opts.mode == Mode::Extract { MAX_OPEN_QUEUED } else { MAX_TESTED_QUEUED };
            if self.queued.len() >= most {
                let mut books = Books { reports: self.reports, batch: &mut self.batch, mode: self.opts.mode };
                let caught_up = with_route(&mut self.queued, &mut books, |sink| u.catch_up(most as u64 / 2, sink));
                match caught_up {
                    Ok(()) => {}
                    Err(RouteError::Decoder(e)) => {
                        if !decoding_error(&e) {
                            p.discard();
                            self.discard_queued();
                            return Err(invariant("catching up RAR decoder", e).into());
                        }
                        let size_failure = u.take_size_failure();
                        self.fail_queued(Some(e), size_failure)?;
                        // The earlier decoder failure invalidated this member's history.
                        return self.begin_decoding(vol, h, p);
                    }
                    Err(RouteError::Fatal(fault)) => {
                        p.discard();
                        self.discard_queued();
                        return Err(fault);
                    }
                }
            }
            u.queue_file(size);
            return self.decode_queued(vol, h, p);
        }
        // anything else is done in order, after the queued files and what the workers hold; a whole file too big
        // for the workers is decoded here while they finish the ones before it, and reports in order when it fails
        let drained = if self.beside_batch(vol, h) { self.drain_solid() } else { self.drain() };
        if let Err(e) = drained {
            p.discard();
            return Err(e);
        }
        if h.format == RarFormat::Rar4 {
            self.stream = None;
            if h.method != 0 && !h.split_before() {
                if rar4_continues(h) {
                    if !self.rar4.as_ref().is_some_and(Rar4Decoder::has_boundary) {
                        let failure = self.dependency_failure();
                        p.discard();
                        self.rar4 = None;
                        if !p.passive {
                            self.fail_in_order(&p.context, failure, NEEDS_EARLIER)?;
                        }
                        return self.continue_file(vol, h, p, None);
                    }
                } else {
                    self.rar4 = None;
                    self.unavailable = None;
                }
            }
        }
        if h.format == RarFormat::Rar5 && h.method != 0 {
            let solid_archive = vol.main.is_solid();
            let ready = if h.solid {
                if crate::rar5::member::continue_decoder(&mut self.stream, h.dictionary, size) {
                    Ok(())
                } else {
                    let failure = self.dependency_failure();
                    p.discard();
                    self.stream = None;
                    if !p.passive {
                        self.fail_in_order(&p.context, failure, NEEDS_EARLIER)?;
                    }
                    return self.continue_file(vol, h, p, None);
                }
            } else {
                self.unavailable = None;
                match window_for_detailed(h.dictionary, size, solid_archive) {
                    Ok(window) if self.selection.is_some() && window.size > RAR_SELECTED_WINDOW_LIMIT => {
                        return Err(invariant(
                            "selected RAR window limit",
                            Error::Unsupported("RAR5 window exceeds the 256 MiB limit".into()),
                        )
                        .into());
                    }
                    Ok(window) => crate::rar5::member::reset_decoder(
                        &mut self.stream,
                        window,
                        size,
                        self.opts.threads,
                        self.opts.parallel_min,
                    ),
                    Err(e) => Err(e),
                }
            };
            if let Err(e) = ready {
                p.discard();
                let (failure, legacy) = e.detailed(p.context.scope()).into_parts();
                let cause = if !p.passive {
                    Some(self.fail_in_order(&p.context, *failure, legacy)?)
                } else {
                    Some(Arc::from(failure))
                };
                self.lost_history(&p.context, cause);
            } else if queues
                && let Some(u) = self.stream.as_mut()
                && u.threads() > 0
            {
                u.force_parallel();
                return self.decode_queued(vol, h, p);
            }
        }
        if let Err(e) = p.open(size) {
            p.discard();
            return Err(self.pending_terminal(&p, e));
        }
        self.continue_file(vol, h, p, None)
    }

    /// Whether `h` is a whole compressed file, standing alone, that is decoded on this thread while the workers
    /// finish the files handed to them before it: one too big to hand them. Its reports wait for theirs.
    fn beside_batch(&self, vol: &Volume, h: &FileHeader) -> bool {
        h.format == RarFormat::Rar5
            && self.threads > 1
            && !vol.main.is_solid()
            && !h.solid
            && h.method != 0
            && h.algorithm == 0
            && !h.encrypted
            && !h.split_before()
            && !h.split_after()
            && h.version.is_none()
            && h.redirection.is_none()
    }

    /// Whether `h` can be decoded behind the files before it in a solid stream: compressed, whole in this volume, of
    /// known size, with threads to spare.
    fn queueable(&self, vol: &Volume, h: &FileHeader) -> bool {
        h.format == RarFormat::Rar5
            && self.threads > 1
            && vol.main.is_solid()
            && h.method != 0
            && h.algorithm == 0
            && !h.encrypted
            && !h.split_before()
            && !h.split_after()
            && !h.size_unknown()
    }

    /// Feeds a whole file to the decoder behind the queued ones. Its bytes go to it once the ones before are done.
    fn decode_queued(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> RunResult<()> {
        // a small file is gathered and written whole on a worker; a bigger one is written as it comes
        let size = h.unpacked_size;
        if p.place.is_some()
            && size <= GATHER_MAX
            && self.batch.get_or_insert_with(|| Batch::new(self.threads, self.cancel.clone())).usable()
        {
            p.mem = Some(Vec::with_capacity(size as usize));
            // checked on the worker
            p.decoder_crc = false;
        } else if let Err(e) = p.open(Some(size)) {
            p.discard();
            return Err(self.pending_terminal(&p, e));
        }
        // registered only now, after any stream before was drained, so a later file at the same place waits for it
        if let Some(key) = p.key.clone() {
            self.queued_paths.insert(key);
        }
        self.queued.push_back((p, Checks::from(h)));
        let mut stream = self.stream.take();
        let mut books = Books { reports: self.reports, batch: &mut self.batch, mode: self.opts.mode };
        let queued = &mut self.queued;
        vol.read_fast(false);
        let read = vol.read_data_detailed(h.data_at, h.packed_size, |piece, range| {
            let Some(u) = stream.as_mut() else {
                return Err(RouteError::Fatal(
                    invariant("no decoder for a queued file", Error::Corrupt("no decoder for a queued file")).into(),
                ));
            };
            with_route(queued, &mut books, |sink| u.feed_shared(piece, range, sink))
        });
        match read {
            Ok(()) => {
                self.stream = stream;
                Ok(())
            }
            // The oldest file still queued is the one the decoder was on.
            Err(ReadDataError::Sink(RouteError::Decoder(e))) if decoding_error(&e) => {
                self.fail_queued(Some(e), stream.as_mut().and_then(Unpacker::take_size_failure))
            }
            Err(ReadDataError::Sink(RouteError::Decoder(e))) => {
                self.discard_queued();
                Err(invariant("feeding queued RAR decoder", e).into())
            }
            Err(ReadDataError::Sink(RouteError::Fatal(fault))) => {
                self.discard_queued();
                Err(fault)
            }
            Err(ReadDataError::Input(fault)) => {
                let context = self.queued.back().and_then(|(p, _)| (!p.passive).then(|| p.context.clone()));
                if let Some(u) = stream.as_mut() {
                    let mut books = Books { reports: self.reports, batch: &mut self.batch, mode: self.opts.mode };
                    let waited = with_route(&mut self.queued, &mut books, |sink| u.wait(sink));
                    if let Err(RouteError::Decoder(e)) = waited
                        && decoding_error(&e)
                    {
                        if self.reports.typed()
                            && let Some((mut p, _)) = self.queued.pop_back()
                        {
                            p.discard();
                            let _ = self.fail_queued(Some(e), u.take_size_failure());
                            return Err(self.pending_terminal(&p, fault));
                        }
                        let _ = self.fail_queued(Some(e), u.take_size_failure());
                        return Err(fault.into());
                    }
                }
                self.discard_queued();
                Err(match context {
                    Some(ctx) => self.terminal(&ctx, fault),
                    None => fault.into(),
                })
            }
        }
    }

    /// Decodes the queued files to their end and finishes them.
    fn drain_solid(&mut self) -> RunResult<()> {
        if self.queued.is_empty() {
            return Ok(());
        }
        let Some(mut u) = self.stream.take() else { return self.fail_queued(None, None) };
        let mut books = Books { reports: self.reports, batch: &mut self.batch, mode: self.opts.mode };
        let finished = with_route(&mut self.queued, &mut books, |sink| u.finish(sink));
        match finished {
            Ok(()) => {
                self.stream = Some(u);
                self.batch_paths.extend(self.queued_paths.drain());
                let Some((p, c)) = self.queued.pop_front() else { return Ok(()) };
                debug_assert!(self.queued.is_empty());
                check_and_finish(&mut books, &c, p)
            }
            Err(RouteError::Decoder(e)) if decoding_error(&e) => self.fail_queued(Some(e), u.take_size_failure()),
            Err(e) => {
                self.discard_queued();
                Err(match e {
                    RouteError::Decoder(e) => invariant("draining queued RAR decoder", e).into(),
                    RouteError::Fatal(fault) => fault,
                })
            }
        }
    }

    /// The oldest queued file failed. Later dependents refer directly to that cause.
    fn fail_queued(&mut self, decoder: Option<Error>, size: Option<(u64, u64)>) -> RunResult<()> {
        if let Err(e) = self.drain_batch() {
            self.discard_queued();
            return Err(e);
        }
        if let Some(e) = decoder
            && let Some((mut p, _)) = self.queued.pop_front()
        {
            let (failure, legacy) =
                batch::decoder_failure_with_size(e, p.context.scope(), p.context.password, size).into_parts();
            let cause: Arc<RarFailure> = Arc::from(failure);
            if !p.passive {
                self.reports.failed(&p.context, Arc::clone(&cause), legacy)?;
            }
            p.discard();
            self.lost_history(&p.context, Some(cause));
        }
        while let Some((mut p, _)) = self.queued.pop_front() {
            if !p.passive {
                self.reports.failed(&p.context, Arc::new(self.dependency_failure()), NEEDS_EARLIER)?;
            }
            p.discard();
        }
        self.stream = None;
        self.queued_paths.clear();
        Ok(())
    }

    /// Drops the queued files and what was written of them, unreported: the run itself is failing.
    fn discard_queued(&mut self) {
        for (mut p, _) in self.queued.drain(..) {
            p.discard();
        }
        self.stream = None;
        self.queued_paths.clear();
    }

    /// Reads this volume's part of a file and, at its last part, checks and finishes it.
    fn continue_file(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending, crypt: MemberCrypt) -> RunResult<()> {
        let split_after = h.split_after();
        if p.failed {
            if split_after {
                self.pending = Some(p);
            }
            return Ok(());
        }
        let changed = (h.method != 0) != p.compressed
            || h.encrypted != p.encrypted
            || (h.split_before()
                && p.rar4_identity != h.rar4.map(|raw| (h.dictionary, raw.unpack_version, raw.method, raw.salt)));
        if changed || matches!(crypt, Some(Err(_))) {
            let (failure, legacy) = match crypt {
                Some(Err(e)) if !changed => (RarFailure::crypt(e, p.context.scope()), "encrypted (password required)"),
                _ => (
                    p.context.integrity(RarIntegrityReason::ChangedContinuationEncoding, false),
                    "a later part is packed differently",
                ),
            };
            let failure = Arc::new(failure);
            if !p.passive {
                self.reports.failed(&p.context, Arc::clone(&failure), legacy)?;
            }
            p.discard();
            if p.compressed {
                self.lost_history(&p.context, Some(failure));
            } else {
                self.stream = None;
            }
            if split_after {
                self.pending = Some(p);
            }
            return Ok(());
        }
        if let Some(selection) = &mut self.selection {
            selection.cancel.check_io().map_err(|e| invariant("selected RAR cancellation", e.into()))?;
            selection.packed_left = selection.packed_left.checked_sub(h.packed_size).ok_or_else(|| {
                invariant(
                    "selected RAR packed budget",
                    Error::Unsupported("RAR5 decoding exceeds the packed byte limit".into()),
                )
            })?;
        }
        // a part's checksums cover only its own packed bytes
        let mut part = crate::crc32::Hasher::new();
        let mut part_blake = h.blake2sp.filter(|_| split_after).map(|_| Blake2sp::new());
        if h.format == RarFormat::Rar5
            && !p.compressed
            && !p.encrypted
            && self.threads > 1
            && h.packed_size >= batch::STORED_PARALLEL_MIN
            && p.blake.is_none()
            && part_blake.is_none()
        {
            return self.stored_parallel(vol, h, p);
        }
        let mut stream = if h.format == RarFormat::Rar5 && p.compressed { self.stream.take() } else { None };
        let mut rar4_error = None;
        let mut rar4 = if h.format == RarFormat::Rar4 && p.compressed {
            let cancel = self.selection.as_ref().map(|selection| selection.cancel.clone());
            let limit = if self.selection.is_some() { RAR_SELECTED_WINDOW_LIMIT } else { 4 << 20 };
            match rar4_part_decoder(&mut self.rar4, h, vol.main.is_solid(), limit, cancel) {
                Ok(decoder) => Some(decoder),
                Err(error) => {
                    rar4_error = Some(error);
                    None
                }
            }
        } else {
            None
        };
        // stored data is only checked (and copied) as it comes; compressed data goes to the decoder
        vol.read_fast(self.threads > 1 && !p.compressed && p.cipher.is_none());
        // a compressed RAR4 file is decrypted here, ahead of its decoder
        let mut rar4_cipher = if rar4.is_some() || rar4_error.is_some() { p.cipher.take() } else { None };
        let mut plain = Vec::new();
        let mut machine = MemberMachine::from_state(h, p.context.clone(), p.cipher.take(), stream.take(), p.bytes);
        let read = if let Some(error) = rar4_error {
            Err(ReadDataError::Sink(MemberDecodeError::Rar4(error)))
        } else {
            vol.read_data_detailed(h.data_at, h.packed_size, |piece, range| {
                if let Some(selection) = &self.selection {
                    selection.cancel.check_io().map_err(|e| MemberDecodeError::Decoder(e.into()))?;
                }
                if h.format == RarFormat::Rar4 && split_after {
                    // a RAR4 part's checksum covers its packed (and, if encrypted, encrypted) bytes
                    part.update(&piece.bytes()[range.clone()]);
                }
                if let Some(decoder) = rar4.as_mut() {
                    let mut chunk = &piece.bytes()[range];
                    if let Some(cipher) = rar4_cipher.as_mut() {
                        cipher.decrypt_selected(chunk, &mut plain);
                        chunk = &plain;
                    }
                    with_rar4_member_sink(&mut p, self.selection.as_mut(), |sink| decoder.feed(chunk, sink).map(|_| ()))
                } else {
                    with_member_sink(&mut p, self.selection.as_mut(), |sink| {
                        machine.feed_shared_core(piece, range, sink)
                    })
                }
            })
        };
        p.cipher = rar4_cipher.take().or(machine.cipher.take());
        stream = machine.take_rar5_decoder()?;
        if h.format == RarFormat::Rar5 {
            (part, part_blake) = machine.into_part_hashes();
        }
        let decoder_fault = |e: Error, p: &Pending, size| {
            batch::decoder_failure_with_size(e, p.context.scope(), p.context.password, size)
        };
        let sink_fault = |e, p: &Pending, size| match e {
            MemberDecodeError::Decoder(e) => decoder_fault(e, p, size),
            MemberDecodeError::Rar4(e) => e.detailed(p.context.scope()),
            MemberDecodeError::Sink(e) => e,
        };
        let decoded = match read {
            Ok(()) if !split_after => {
                let padding = match p.cipher.as_ref() {
                    Some(cipher) if !cipher.rem.is_empty() => Err(RarFault::new(
                        p.context.integrity(RarIntegrityReason::IncompleteCipherBlock, false),
                        Error::Truncated,
                    )),
                    Some(cipher) => cipher
                        .blocks
                        .as_ref()
                        .map_or(Ok(()), CipherBlocks::finish)
                        .map_err(|e| decoder_fault(e, &p, None)),
                    None => Ok(()),
                };
                padding.and_then(|()| {
                    if let Some(decoder) = rar4.as_mut() {
                        with_rar4_member_sink(&mut p, self.selection.as_mut(), |sink| {
                            decoder.finish_logical(sink).map(|_| ())
                        })
                        .map_err(|error| sink_fault(error, &p, None))
                    } else {
                        match stream.as_mut() {
                            Some(u) => with_member_sink(&mut p, self.selection.as_mut(), |sink| u.finish(sink))
                                .map_err(|e| sink_fault(e, &p, u.take_size_failure())),
                            None => Ok(()),
                        }
                    }
                })
            }
            Ok(()) => Ok(()),
            Err(ReadDataError::Sink(MemberDecodeError::Rar4(error))) => Err(error.detailed(p.context.scope())),
            Err(ReadDataError::Sink(MemberDecodeError::Decoder(e @ (Error::Corrupt(_) | Error::Unsupported(_)))))
                if self.selection.is_none() && (p.compressed || p.encrypted) =>
            {
                Err(decoder_fault(e, &p, stream.as_mut().and_then(Unpacker::take_size_failure)))
            }
            Err(ReadDataError::Sink(MemberDecodeError::Sink(fault)))
                if matches!(
                    fault.failure.as_ref(),
                    RarFailure::Integrity { .. } | RarFailure::EncryptedIntegrity { .. }
                ) =>
            {
                Err(fault)
            }
            Err(ReadDataError::Input(fault) | ReadDataError::Sink(MemberDecodeError::Sink(fault))) => {
                p.discard();
                return Err(self.pending_terminal(&p, fault));
            }
            Err(ReadDataError::Sink(MemberDecodeError::Decoder(e))) => {
                p.discard();
                let fault = decoder_fault(e, &p, stream.as_mut().and_then(Unpacker::take_size_failure));
                return Err(self.pending_terminal(&p, fault));
            }
        };
        if let Err(fault) = decoded {
            p.discard();
            if matches!(
                fault.failure.as_ref(),
                RarFailure::Output { .. }
                    | RarFailure::Canceled
                    | RarFailure::Internal(_)
                    | RarFailure::Limit { resource: RarResource::Counter, .. }
            ) {
                return Err(self.pending_terminal(&p, fault));
            }
            if self.selection.is_some() {
                return Err(fault.into());
            }
            let (failure, legacy) = fault.into_parts();
            let cause = if !p.passive {
                Some(self.fail_in_order(&p.context, *failure, legacy)?)
            } else {
                Some(Arc::from(failure))
            };
            if p.compressed {
                self.lost_history(&p.context, cause);
            }
            if split_after {
                self.pending = Some(p);
            }
            return Ok(());
        }
        self.stream = stream.or(self.stream.take());
        if let Some(decoder) = rar4
            && (split_after || (vol.main.is_solid() && decoder.has_boundary()))
        {
            // the rest of the file, or the next file of the solid stream, goes on from here
            self.rar4 = Some(decoder);
        }
        if split_after {
            // The hash mode belongs to this part, even though CBC and its derived key span the member.
            let hash_key = p.hash_key(h.crypt.as_ref().is_some_and(|crypt| crypt.tweaked_crc));
            let checks =
                crate::rar5::session::RarChecks { crc32: h.crc32, blake2sp: h.blake2sp, keyed: hash_key.is_some() };
            if let Err(failure) = crate::rar5::member::verify_packed(&p.context, checks, part, part_blake, hash_key) {
                let failure = Arc::new(failure);
                if !p.passive {
                    self.reports.failed(&p.context, Arc::clone(&failure), "checksum error in a volume's part")?;
                }
                p.discard();
                if p.compressed {
                    self.lost_history(&p.context, Some(failure));
                }
            }
            self.pending = Some(p);
            return Ok(());
        }
        self.finish_file_checks(h, p)
    }

    /// A file's last part is in: checks it whole and finishes it.
    fn finish_file_checks(&mut self, h: &FileHeader, p: Pending) -> RunResult<()> {
        check_and_finish(
            &mut Books { reports: self.reports, batch: &mut self.batch, mode: self.opts.mode },
            &Checks::from(h),
            p,
        )
    }
}

impl Run<'_, '_, '_> {
    /// A big part of a stored file, checked (and copied) on several threads. Ends as [`Self::continue_file`] does.
    fn stored_parallel(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> RunResult<()> {
        let split_after = h.split_after();
        if h.data_at.checked_add(h.packed_size).is_none_or(|end| end > vol.len()) {
            p.discard();
            let failure = p.context.integrity(RarIntegrityReason::TruncatedData, false);
            return Err(self.pending_terminal(&p, RarFault::new(failure, Error::Truncated)));
        }
        // the pieces are written by position, so the writer thread hands the file over first
        let file = match p.out.take().map(Output::handoff_detailed).transpose() {
            Ok(f) => f,
            Err(e) => {
                p.discard();
                return Err(self.terminal(&p.context, e.detailed(false)));
            }
        };
        let volume_path = vol.path.clone();
        let part = batch::stored_detailed(
            (vol.file(), Some(&volume_path)),
            h.data_at,
            h.packed_size,
            file.as_ref().map(|f| (&f.file, f.target())),
            p.bytes,
            self.threads,
            self.cancel.as_ref(),
        );
        let part = match part {
            Ok(part) => part,
            Err(e) => {
                drop(file);
                p.discard();
                return Err(self.pending_terminal(&p, e));
            }
        };
        // The copy threads don't poll the cancellation; a canceled member is dropped once its part is copied.
        if self.cancel.as_ref().is_some_and(Cancellation::is_canceled) {
            drop(file);
            p.discard();
            return Err(self.pending_terminal(&p, RarFault::new(RarFailure::Canceled, canceled_error())));
        }
        p.hasher.combine(&part);
        p.bytes =
            p.bytes.checked_add(h.packed_size).ok_or_else(|| self.pending_terminal(&p, RarFault::counter_limit()))?;
        if let Some(mut file) = file {
            if let Err(fault) = seek_output(&mut file, p.bytes) {
                drop(file);
                p.discard();
                return Err(self.pending_terminal(&p, fault));
            }
            let left = (!h.size_unknown()).then(|| h.unpacked_size.saturating_sub(p.bytes));
            p.out = Some(Output::resume(file, left));
        }
        if split_after {
            if h.crc32.is_some_and(|want| part.finalize() != want) {
                if !p.passive {
                    let reason = RarIntegrityReason::PackedPiece { crc32: true, blake2sp: false, keyed: false };
                    self.reports.failed(
                        &p.context,
                        Arc::new(p.context.integrity(reason, false)),
                        "checksum error in a volume's part",
                    )?;
                }
                p.discard();
            }
            self.pending = Some(p);
            return Ok(());
        }
        self.finish_file_checks(h, p)
    }
}

fn seek_output(file: &mut crate::output::WriteFile, offset: u64) -> crate::error::RarResult<()> {
    use std::io::{Seek, SeekFrom};
    file.file
        .seek(SeekFrom::Start(offset))
        .map(|_| ())
        .map_err(|e| RarFault::output(IoOperation::Seek, file.target().map(Path::to_path_buf), Some(offset), e, false))
}

/// Restores folders' permissions and times, deepest first, after their contents are written: a read-only folder
/// set first would stop its own files from being created.
pub(crate) fn finish_dirs(summary: &mut Summary) {
    finish_dir_meta(&mut summary.dir_meta);
}

fn finish_dir_meta(dir_meta: &mut Vec<(PathBuf, Meta)>) {
    let mut dirs = std::mem::take(dir_meta);
    dirs.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    #[cfg(unix)]
    for (path, h) in &dirs {
        use std::os::unix::fs::PermissionsExt;
        // only a real folder: never follow something that replaced it since
        if !fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        if let Ok(dir) = File::open(path) {
            set_time(&dir, h);
        }
        if let Some(mode) = h.mode {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777));
        }
    }
    #[cfg(not(unix))]
    let _ = dirs;
}

pub(crate) struct FileMetadataResult {
    pub modified: Option<io::Result<()>>,
    pub permissions: Option<io::Result<()>>,
}
/// Each requested attribute reports its own native result.
pub(crate) fn finish_file_checked(out: &File, h: &Meta) -> FileMetadataResult {
    finish_file_attributes(
        h,
        |at| out.set_modified(at),
        |mode| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                out.set_permissions(fs::Permissions::from_mode(mode))
            }
            #[cfg(not(unix))]
            {
                let _ = (out, mode);
                Ok(())
            }
        },
    )
}
fn finish_file_attributes(
    h: &Meta,
    modified: impl FnOnce(SystemTime) -> io::Result<()>,
    permissions: impl FnOnce(u32) -> io::Result<()>,
) -> FileMetadataResult {
    let modified = h.mtime.map(|seconds| {
        archive_time(seconds, h.nanos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "archive timestamp out of range"))
            .and_then(modified)
    });
    #[cfg(unix)]
    let permissions = h.mode.map(|mode| permissions(mode & 0o777));
    #[cfg(not(unix))]
    let permissions = {
        let _ = permissions;
        None
    };
    FileMetadataResult { modified, permissions }
}
/// Times and permissions, best effort: preserve the legacy swallowing policy.
pub(crate) fn finish_file(out: &File, h: &Meta) {
    let FileMetadataResult { modified, permissions } = finish_file_checked(out, h);
    drop((modified, permissions));
}

fn set_time(out: &File, h: &Meta) {
    if let Some(at) = h.mtime.and_then(|seconds| archive_time(seconds, h.nanos)) {
        let _ = out.set_modified(at);
    }
}

/// Converts an archive timestamp with a nonnegative fraction of a second.
pub fn archive_time(seconds: i64, nanos: u32) -> Option<SystemTime> {
    let elapsed = Duration::from_secs(seconds.unsigned_abs());
    let base = if seconds < 0 { UNIX_EPOCH.checked_sub(elapsed) } else { UNIX_EPOCH.checked_add(elapsed) }?;
    base.checked_add(Duration::from_nanos(u64::from(nanos)))
}

impl Dirs {
    /// Forgets the folder `rel` and everything under it, which a rename mode has moved away.
    fn forget(&mut self, rel: &Path) {
        self.known.retain(|path, _| !path.starts_with(rel));
    }

    /// Records the path `rel` as used by this run. True when nothing this run wrote can be at `rel` under any
    /// spelling: every part of it is a plain name, it was not used before in any letter case, and no name seen so
    /// far could be another spelling of it. A plain name has only ASCII letters, digits and common punctuation, and
    /// doesn't end in a dot or space. Anything else may be folded by some file system into a different name
    /// (Unicode normalization, `~` short names, `\` or `:` on Windows, trailing dots and spaces), so it makes every
    /// later answer false. (Opening the file still refuses to replace anything, should a name slip by.)
    fn note(&mut self, rel: &Path) -> bool {
        let mut key = String::new();
        for part in rel.components() {
            let plain = match part {
                Component::Normal(name) => name.to_str().filter(|n| plain_name(n)),
                _ => None,
            };
            let Some(name) = plain else {
                self.unsure = true;
                return false;
            };
            if !key.is_empty() {
                key.push('/');
            }
            key.extend(name.chars().map(|c| c.to_ascii_lowercase()));
        }
        self.taken.insert(key) && !self.unsure
    }
}

/// A name every file system keeps as it is, apart from letter case.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && !name.ends_with(['.', ' '])
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b" -_.,+=()[]{}@#&!'$%^;".contains(&b))
}

/// [`make_dirs`] for a run that remembers the folders it has made or checked, in `dirs`. It starts below the
/// deepest one already known, and tries to make each folder before looking at what is there, so a new folder costs
/// one call.
fn directory_policy(reason: RarPolicyReason, path: &Path, legacy: String) -> RarFault {
    RarFault::new(RarFailure::Policy { reason, path: path.to_path_buf() }, Error::UnsafePath(legacy))
}

fn make_dirs_known_detailed(root: &Path, rel: &Path, dirs: &mut Dirs) -> crate::error::RarResult<()> {
    let known =
        rel.ancestors().find(|a| a.as_os_str().is_empty() || dirs.known.contains_key(*a)).unwrap_or(Path::new(""));
    let Ok(rest) = rel.strip_prefix(known) else { return make_dirs_detailed(root, rel) };
    let mut at = root.join(known);
    let mut sub = known.to_path_buf();
    for part in rest.components() {
        at.push(part);
        sub.push(part);
        let made = match fs::create_dir(&at) {
            Ok(()) => true,
            // something is there already: only a real folder will do, never a link to one
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match fs::symlink_metadata(&at) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(directory_policy(RarPolicyReason::Symlink, &at, rel.display().to_string()));
                }
                Ok(meta) if meta.is_dir() => false,
                Ok(_) => {
                    return Err(directory_policy(
                        RarPolicyReason::ParentIsFile,
                        &at,
                        format!("{}: a file is in the way", rel.display()),
                    ));
                }
                Err(e) => return Err(RarFault::output(IoOperation::Metadata, Some(at.clone()), None, e, false)),
            },
            Err(e) => return Err(RarFault::output(IoOperation::CreateDirectory, Some(at.clone()), None, e, false)),
        };
        // a folder takes its name, so no file is later created over it
        dirs.note(&sub);
        dirs.known.insert(sub.clone(), made);
    }
    Ok(())
}

/// Creates `rel` under `root` one folder at a time, refusing to pass through a link.
pub(crate) fn make_dirs(root: &Path, rel: &Path) -> Result<()> {
    make_dirs_detailed(root, rel).map_err(RarFault::into_legacy)
}

pub(crate) fn make_dirs_detailed(root: &Path, rel: &Path) -> crate::error::RarResult<()> {
    let mut at = root.to_path_buf();
    for part in rel.components() {
        at.push(part);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(directory_policy(RarPolicyReason::Symlink, &at, rel.display().to_string()));
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(directory_policy(
                    RarPolicyReason::ParentIsFile,
                    &at,
                    format!("{}: a file is in the way", rel.display()),
                ));
            }
            Err(_) => match fs::create_dir(&at) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(RarFault::output(IoOperation::CreateDirectory, Some(at.clone()), None, e, false)),
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_cancellation_reads_as_one() {
        assert!(super::is_cancellation(&super::canceled_error()));
        let mut cancel = super::Cancellation::default();
        cancel.cancel();
        assert!(super::is_cancellation(&cancel.check_io().unwrap_err().into()));
        cancel = super::Cancellation::default();
        assert!(cancel.check_io().is_ok());
        // Some other aborted I/O, such as a peer dropping a connection, is not a cancellation.
        let aborted = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "operation canceled");
        assert!(!super::is_cancellation(&crate::Error::Io(aborted)));
    }

    use super::*;
    #[cfg(unix)]
    #[test]
    fn persistent_metadata_attributes_are_independent() {
        use std::os::unix::fs::PermissionsExt;
        let file = tempfile::tempfile().unwrap();
        let meta = Meta { mtime: Some(1_700_000_000), nanos: 123_000_000, mode: Some(0o7777) };
        let result = finish_file_attributes(
            &meta,
            |at| file.set_modified(at),
            |mode| {
                assert_eq!(mode, 0o777);
                Err(io::Error::from_raw_os_error(libc::EPERM))
            },
        );
        assert!(result.modified.unwrap().is_ok());
        assert_eq!(result.permissions.unwrap().unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert_eq!(
            file.metadata().unwrap().modified().unwrap(),
            archive_time(meta.mtime.unwrap(), meta.nanos).unwrap()
        );
        let absent = finish_file_attributes(&Meta::default(), |_| panic!("absent time"), |_| panic!("absent mode"));
        assert!(absent.modified.is_none() && absent.permissions.is_none());
        let zero = finish_file_checked(&file, &Meta { mode: Some(0), ..Meta::default() });
        assert!(zero.permissions.unwrap().is_ok());
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0);
        let result = finish_file_attributes(
            &meta,
            |_| Err(io::Error::from_raw_os_error(libc::EIO)),
            |mode| file.set_permissions(fs::Permissions::from_mode(mode)),
        );
        assert_eq!(result.modified.unwrap().unwrap_err().raw_os_error(), Some(libc::EIO));
        assert!(result.permissions.unwrap().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn create_and_seek_report_the_actual_output_operations() {
        use std::os::fd::OwnedFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        fs::write(&path, b"original").unwrap();
        let fault = create_target_detailed(Place::new(path.clone(), false), Some(0)).err().unwrap();
        assert!(matches!(fault.failure.as_ref(), RarFailure::Output {
            operation: IoOperation::CreateFile, path: Some(actual), source, ..
        } if actual == &path && source.raw_os_error() == Some(libc::EEXIST)));
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd: OwnedFd = socket.into();
        let mut output = Output::new(File::from(fd), Some(1)).handoff_detailed().unwrap();
        let fault = seek_output(&mut output, 1).unwrap_err();
        assert!(matches!(fault.failure.as_ref(), RarFailure::Output {
            operation: IoOperation::Seek, offset: Some(1), source, ..
        } if source.raw_os_error() == Some(libc::ESPIPE)));
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn pending_sink_retains_first_write_error_when_decoder_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readonly");
        fs::write(&path, b"keep").unwrap();
        let mut pending = Pending::new(&FileHeader::default(), empty_context());
        pending.out = Some(Output::new(File::open(&path).unwrap(), Some(1)));
        let result = with_member_sink(&mut pending, None, |sink| {
            let _ = sink.put(b"x");
            let _ = sink.put(b"y");
            Ok(())
        });
        let Err(MemberDecodeError::Sink(fault)) = result else { panic!("decoder swallowed the sink error") };
        assert!(matches!(fault.failure.as_ref(), RarFailure::Output {
            operation: IoOperation::Write, source, ..
        } if source.raw_os_error() == Some(libc::EBADF)));
        assert_eq!(pending.bytes, 0);
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }

    fn empty_context() -> EntryContext {
        EntryContext {
            entry: RarEntryIdentity { index: None, order: 0, name: String::new() },
            method: 0,
            password: crate::error::RarPasswordEvidence::NotEncrypted,
            renamed: None,
        }
    }

    #[test]
    fn encrypted_compressed_framing_bounds_padding_across_chunks() {
        use crate::rar5::testenc::{Op, block};

        let expected = b"cipher padding example";
        let ops: Vec<_> = expected.iter().copied().map(Op::Lit).collect();
        let packed = block(&ops, true, true);
        for piece in [1, 7, packed.len()] {
            let mut decoder =
                Unpacker::new(crate::rar5::unpack::window_for(1 << 20, Some(expected.len() as u64), false).unwrap())
                    .unwrap();
            decoder.set_threads(0, u64::MAX);
            decoder.reset(Some(expected.len() as u64));
            let mut sink = Pending::new(&FileHeader::default(), empty_context());
            sink.mem = Some(Vec::new());
            let mut blocks = CipherBlocks::default();

            blocks.feed(&packed[..2], &mut decoder, &mut sink).unwrap();
            assert!(matches!(blocks.finish(), Err(Error::Truncated)));
            for part in packed[2..packed.len() - 1].chunks(piece) {
                blocks.feed(part, &mut decoder, &mut sink).unwrap();
            }
            assert!(matches!(blocks.finish(), Err(Error::Truncated)));
            blocks.feed(&packed[packed.len() - 1..], &mut decoder, &mut sink).unwrap();
            blocks.feed(&[0; 7], &mut decoder, &mut sink).unwrap();
            blocks.feed(&[0; 8], &mut decoder, &mut sink).unwrap();
            blocks.finish().unwrap();
            decoder.finish(&mut sink).unwrap();
            assert_eq!(sink.mem.unwrap(), expected);

            let mut sink = Pending::new(&FileHeader::default(), empty_context());
            assert!(matches!(blocks.feed(&[0], &mut decoder, &mut sink), Err(Error::Corrupt(_))));
        }
    }

    #[test]
    fn a_path_used_under_other_letter_case_is_not_new() {
        let mut dirs = Dirs::default();
        assert!(dirs.note(Path::new("d")));
        assert!(dirs.note(Path::new("d/one")));
        // `D` may be `d` itself, and what goes in it lands in `d`
        assert!(!dirs.note(Path::new("D")));
        assert!(dirs.note(Path::new("D/two")));
        assert!(!dirs.note(Path::new("d/two")));
        assert!(!dirs.note(Path::new("d/ONE")));
        assert!(dirs.note(Path::new("d/three")));
    }

    #[test]
    fn after_a_name_that_may_fold_into_another_nothing_is_new() {
        for odd in ["d/\u{212A}", "d/e\u{301}", "d/LONGNA~1.TXT", "d/f.", "d/f ", "d./f", "d\\\\f", "d/f:s", "d/f*"] {
            let mut dirs = Dirs::default();
            assert!(dirs.note(Path::new("d/a")));
            assert!(!dirs.note(Path::new(odd)), "{odd:?}");
            // the Kelvin sign is `K` to a file system that normalizes names
            assert!(!dirs.note(Path::new("d/K")), "after {odd:?}");
            assert!(!dirs.note(Path::new("x/y")), "after {odd:?}");
        }
    }

    #[test]
    fn listing_budget_accepts_exactly_one_million_names() {
        let mut budget = ListingBudget::default();
        for _ in 0..1_000_000 {
            budget.record("name").unwrap();
        }
        assert!(matches!(budget.record("name"), Err(Error::Unsupported(_))));
    }

    #[test]
    fn listing_budget_accepts_exactly_sixty_four_mib_of_names() {
        let mut budget = ListingBudget::default();
        let name = "a".repeat(1 << 20);
        for _ in 0..64 {
            budget.record(&name).unwrap();
        }
        assert!(matches!(budget.record("a"), Err(Error::Unsupported(_))));
    }
}
