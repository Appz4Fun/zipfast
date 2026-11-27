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

//! Links from archives: symbolic links (RAR 4.x `S_IFLNK` members, RAR 5.0 Unix and Windows symbolic links and
//! junctions, tar, ZIP and 7z) and hard links and file copies (tar, RAR 5.0). UnRAR creates them on Unix; so does
//! every route here, within the destination only. A hard link or copy takes only a file the same run extracted,
//! where it landed, reached without following a link and only while it is still that file.
//!
//! A target is taken only when it is relative and, read from the link's own folder, stays inside the destination.
//! `..` may only lead the target: the folders it climbs out of are real ones (a member is never written through a
//! link), so where it lands is known before the link exists. Past them the target only descends, through folders or
//! through links that were each checked the same way, so no chain of links leads out either.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::extract::PreexistingLinks;

/// The longest target taken, in bytes (`PATH_MAX` less its NUL).
pub(crate) const MAX_TARGET: u64 = 4095;

/// Whether a link at `rel`, relative to the destination, may point at `target`.
pub(crate) fn contained(rel: &Path, target: &[u8]) -> bool {
    if target.is_empty() || target.len() as u64 > MAX_TARGET || target.contains(&0) || target[0] == b'/' {
        return false;
    }
    // folders between the destination and the link
    let mut depth = rel.components().count().saturating_sub(1);
    let mut leading = true;
    for part in target.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." if leading => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return false,
            },
            b".." => return false,
            _ => leading = false,
        }
    }
    true
}

/// A RAR 4.x symbolic link's target as it is written, mapped like the member names it may point at (see
/// `crate::rar5::framing::rar4_link_target`); None when it can't keep its meaning, which refuses the link.
pub(crate) fn rar4_target(target: &[u8]) -> Option<Vec<u8>> {
    crate::rar5::framing::rar4_link_target(target)
}

/// Creates the link at `path`, with the archived `modified` time when there is one (set on the link itself, best
/// effort, as `lutimes` does). With `replace` the file there is replaced in one rename, which never follows a link;
/// without, the link is only created where nothing is.
#[cfg(unix)]
pub(crate) fn create(path: &Path, target: &[u8], replace: bool, modified: Option<SystemTime>) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let target = std::ffi::OsStr::from_bytes(target);
    if !replace {
        std::os::unix::fs::symlink(target, path)?;
        if let Some(at) = modified {
            set_link_time(path, at);
        }
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..64 {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // a short stage name of its own: one built from the destination name could pass the name length limit
        let stage = parent.join(format!(".zipfast-link-{}-{n}", std::process::id()));
        match std::os::unix::fs::symlink(target, &stage) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        if let Some(at) = modified {
            set_link_time(&stage, at);
        }
        return std::fs::rename(&stage, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&stage);
        });
    }
    Err(io::ErrorKind::AlreadyExists.into())
}

/// Links are created on Unix only.
#[cfg(not(unix))]
pub(crate) fn create(_: &Path, _: &[u8], _: bool, _: Option<SystemTime>) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

/// Sets the modification time of the symbolic link at `path` itself, never what it points to (`utimensat` with
/// `AT_SYMLINK_NOFOLLOW`, as `lutimes`), leaving its access time. Best effort, as a file's times are.
#[cfg(unix)]
fn set_link_time(path: &Path, at: SystemTime) {
    use std::os::unix::ffi::OsStrExt;
    let Some(modified) = timespec(at) else { return };
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return };
    let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT as libc::c_long }, modified];
    // SAFETY: a NUL-terminated path and two timespecs; the flag never follows a link at the last component.
    let _ = unsafe { libc::utimensat(libc::AT_FDCWD, name.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
}

/// `at` as a timespec, before 1970 too; None when it doesn't fit.
#[cfg(unix)]
#[allow(clippy::useless_conversion, reason = "time_t is 32 bits on some Unix targets")]
fn timespec(at: SystemTime) -> Option<libc::timespec> {
    let (seconds, nanos) = match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(after) => (i64::try_from(after.as_secs()).ok()?, after.subsec_nanos()),
        Err(before) => {
            let before = before.duration();
            let seconds = i64::try_from(before.as_secs()).ok()?;
            match before.subsec_nanos() {
                0 => (seconds.checked_neg()?, 0),
                n => (seconds.checked_neg()?.checked_sub(1)?, 1_000_000_000 - n),
            }
        }
    };
    Some(libc::timespec { tv_sec: seconds.try_into().ok()?, tv_nsec: nanos as libc::c_long })
}

/// The message for a link whose target is absolute or leads out of the destination.
pub(crate) const UNSAFE_TARGET: &str = "the link's target is absolute or leads out of the destination";
/// The message for a hard link whose target is not a file this run extracted.
pub(crate) const HARD_TARGET: &str = "the hard link's target is not a file extracted earlier in this run";

/// The message for a hard link, under [`crate::extract::HardLinkTargets::StoredName`], whose target's name holds no
/// regular file reached without following a link.
pub(crate) const STORED_TARGET: &str = "the hard link's target is not a regular file in the destination";

/// The message for a hard link or file copy whose earlier file was changed or replaced since it was extracted.
pub(crate) const TARGET_CHANGED: &str = "the hard link's target is no longer the file extracted earlier";
/// The message for a link on a platform where links aren't created.
pub(crate) const UNSUPPORTED: &str = "links can't be created here";

/// A link member, for the tar, ZIP, 7z and RAR 5.0 runners.
#[derive(Clone, Debug)]
pub(crate) enum LinkKind {
    /// A symbolic link to these target bytes.
    Symbolic(Vec<u8>),
    /// A hard link to this earlier member, relative to the destination.
    Hard(std::path::PathBuf),
    /// A copy of this earlier member (a RAR 5.0 file copy), relative to the destination.
    Copy(std::path::PathBuf),
}

/// A RAR 5.0 redirection as a link member, or None for a kind this does not know. A Windows symbolic link or a
/// junction becomes a symbolic link with its backslashes made slashes (an absolute one, `\??\C:\...`, then fails
/// the target check). A hard link's or file copy's target is an earlier member's name, mapped and sanitized as
/// member names are (`windows` for a Windows-host archive: a `\` is `_`, see `FileHeader::output_name`) and, with
/// `flatten`, only its last component.
pub(crate) fn from_rar5(
    redirection: &crate::rar5::Redirection,
    windows: bool,
    windows_safe_names: bool,
    flatten: bool,
) -> Option<Result<LinkKind, crate::error::Error>> {
    use crate::rar5::Redirection;
    let member = |name: &str| {
        // the target is an earlier member's RAR 5.0 name, written as member names are: a Windows-made `\\` is `_`
        let name =
            if windows && name.contains('\\') { std::borrow::Cow::Owned(name.replace('\\', "_")) } else { name.into() };
        crate::path::sanitize_with(&name, windows, windows_safe_names)
            .map(|rel| if flatten { std::path::PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel })
    };
    Some(match redirection {
        Redirection::UnixSymlink(target) => Ok(LinkKind::Symbolic(target.as_bytes().to_vec())),
        Redirection::WindowsSymlink(target) | Redirection::Junction(target) => {
            Ok(LinkKind::Symbolic(target.replace('\\', "/").into_bytes()))
        }
        Redirection::HardLink(target) => member(target).map(LinkKind::Hard),
        Redirection::FileCopy(target) => member(target).map(LinkKind::Copy),
        Redirection::Unknown(_) => return None,
    })
}

/// Whether an encrypted RAR 5.0 redirection member may be placed: only when `password` is verified for it by the
/// check value in its encryption record. Its target is in the header, which `rar a -p` leaves in the clear, so a
/// link would otherwise be placed whatever the password, where UnRAR reports a wrong password and creates nothing.
///
/// No password (or an empty one) fails as password required, a missing or malformed encryption record as a
/// malformed one, a password the check value rejects as a wrong password, each as an encrypted data member fails.
/// A record with no check value, or one whose checksum doesn't match, can't verify any password: a link has no data
/// to check it against, so it is refused ([`RarIntegrityReason::UnverifiableLinkPassword`]) rather than placed.
/// On success, the evidence the member reports. A member that isn't encrypted passes as it is.
///
/// [`RarIntegrityReason::UnverifiableLinkPassword`]: crate::error::RarIntegrityReason::UnverifiableLinkPassword
pub(crate) fn rar5_password(
    keys: &mut crate::crypto::Rar5KeyCache,
    header: &crate::rar5::FileHeader,
    password: Option<&str>,
    scope: crate::error::RarScope,
) -> Result<crate::error::RarPasswordEvidence, crate::error::RarFailure> {
    use crate::error::{RarFailure, RarIntegrityReason, RarPasswordEvidence};
    if !header.encrypted {
        return Ok(RarPasswordEvidence::NotEncrypted);
    }
    let Some(password) = password.filter(|p| !p.is_empty()) else {
        return Err(RarFailure::PasswordRequired { scope });
    };
    let Some(params) = header.crypt else {
        return Err(RarFailure::Integrity {
            scope,
            reason: RarIntegrityReason::MalformedEncryptionRecord,
            password: RarPasswordEvidence::NotEncrypted,
        });
    };
    if let Some(verifier) = rar5_unverifiable(&params) {
        return Err(RarFailure::EncryptedIntegrity {
            scope,
            reason: RarIntegrityReason::UnverifiableLinkPassword,
            verifier,
        });
    }
    super::rar5_keys(keys, password, &params, scope).map(|keys| keys.evidence)
}

/// [`rar5_password`] under [`crate::extract::Options::encrypted_links`]: with
/// [`crate::extract::EncryptedLinks::PlaceUnverified`] the password isn't checked at all (no key is derived), as
/// 7-Zip 26.06 doesn't check it, and an encrypted link passes with the evidence
/// [`crate::error::RarPasswordEvidence::Unverified`]. Only the password is let go: every other link check applies.
pub(crate) fn rar5_link_password(
    keys: &mut crate::crypto::Rar5KeyCache,
    header: &crate::rar5::FileHeader,
    password: Option<&str>,
    scope: crate::error::RarScope,
    links: crate::extract::EncryptedLinks,
) -> Result<crate::error::RarPasswordEvidence, crate::error::RarFailure> {
    match links {
        crate::extract::EncryptedLinks::PlaceUnverified if header.encrypted => {
            Ok(crate::error::RarPasswordEvidence::Unverified)
        }
        _ => rar5_password(keys, header, password, scope),
    }
}

/// Why these encryption parameters can't verify a password, or None when their check value can: there is one,
/// and its checksum matches. Checked before any key is derived.
pub(crate) fn rar5_unverifiable(
    params: &crate::crypto::Rar5CryptParams,
) -> Option<crate::error::RarVerifierUnavailable> {
    use crate::error::RarVerifierUnavailable;
    match params.check {
        None => Some(RarVerifierUnavailable::Absent),
        Some((check, sum)) if crate::crypto::sha256(&check)[..4] != sum => {
            Some(RarVerifierUnavailable::CheckChecksumMismatch)
        }
        Some(_) => None,
    }
}

/// A failure that stops only its own member: a hard link's or copy's earlier file is gone or changed, or links
/// can't be created here. Any other error placing a link is the run's.
pub(crate) fn member_failure(error: &io::Error) -> Option<&'static str> {
    if error.kind() == io::ErrorKind::Unsupported {
        return Some(UNSUPPORTED);
    }
    error.get_ref().and_then(|inner| inner.downcast_ref::<Refused>()).map(|refused| refused.0)
}

/// Why a link was refused while being placed, carried inside an `io::Error`.
#[derive(Debug)]
struct Refused(&'static str);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refused {}

fn refused(why: &'static str) -> io::Error {
    io::Error::other(Refused(why))
}

/// Where an extracted file landed (a rename mode may have put it elsewhere than its name), and which file it was.
#[derive(Clone)]
struct Landed {
    rel: std::path::PathBuf,
    dev: u64,
    ino: u64,
}

/// The regular files a run has extracted, by member path: the only targets a hard link may take, so it never
/// reaches a file outside the destination or one that was there before the run. Each records where the file landed
/// and its device and inode; a hard link is made only to that same file, reached without following links. A test
/// run records the names only.
///
/// The records are bounded: past [`MAX_RECORDED`] bytes of paths a file is no longer recorded, so a hard link to
/// it fails as one to a file this run didn't extract. An archive of a million files whose paths repeat long folder
/// names can't make this run hold gigabytes of paths.
///
/// Both the records and an index of where each file landed are ordered by path, component by component, so the
/// records at or below a path are one range of each: [`Extracted::replaced`] visits only what it removes, however
/// many records there are and however many links are placed.
#[derive(Default)]
pub(crate) struct Extracted {
    records: BTreeMap<PathBuf, Option<Landed>>,
    /// device and inode of each symbolic link this run placed: the only links another link's target may pass
    /// through (see [`foreign_link`])
    links: std::collections::BTreeSet<(u64, u64)>,
    /// what a link's target may do with links the destination held before the run
    preexisting: PreexistingLinks,
    /// a refused symbolic link leaves an empty regular file at its path
    /// ([`crate::extract::Options::refused_link_placeholder`])
    placeholder: bool,
    /// where each extracted file landed, and the members that landed there
    landed: BTreeMap<PathBuf, Vec<PathBuf>>,
    bytes: usize,
    /// a hard link takes the regular file at its target's stored name, whoever wrote it
    /// ([`crate::extract::HardLinkTargets::StoredName`])
    stored_name_targets: bool,
}

/// The most bytes of paths [`Extracted`] holds, as much as a listing may.
pub(crate) const MAX_RECORDED: usize = 64 << 20;

/// What one record takes against [`MAX_RECORDED`]: its paths (the member's twice when the index of where it
/// landed holds it too) and a little for the tables.
fn cost(rel: &Path, landed: &Option<Landed>) -> usize {
    rel.as_os_str().len() + landed.as_ref().map_or(0, |l| l.rel.as_os_str().len() + rel.as_os_str().len()) + 96
}

/// The keys of `map` at or below `prefix`: one range, as paths order component by component.
fn at_or_below<'a, V>(map: &'a BTreeMap<PathBuf, V>, prefix: &'a Path) -> impl Iterator<Item = (&'a PathBuf, &'a V)> {
    map.range::<Path, _>((std::ops::Bound::Included(prefix), std::ops::Bound::Unbounded))
        .take_while(move |(k, _)| k.starts_with(prefix))
}

/// Whether `rel` is a normalised member path, as [`crate::path::sanitize`] makes them: plain components only, no
/// `.`, `..`, empty component, root or trailing separator. Paths compare component by component, so `a/`, `a//b`
/// or `a/./b` would find the record of `a` or `a/b` while their bytes differ.
fn normalised(rel: &Path) -> bool {
    use std::path::Component;
    rel.components().all(|c| matches!(c, Component::Normal(_)))
        && (cfg!(not(unix)) || rel.components().collect::<PathBuf>().as_os_str() == rel.as_os_str())
}

impl Extracted {
    /// No records yet, with the link settings of `options`. A test run never writes a placeholder.
    pub(crate) fn new(options: &crate::extract::Options) -> Self {
        let extracting = options.mode == crate::extract::Mode::Extract;
        Self {
            preexisting: options.preexisting_links,
            placeholder: options.refused_link_placeholder && extracting,
            stored_name_targets: options.hard_link_targets == crate::extract::HardLinkTargets::StoredName && extracting,
            ..Self::default()
        }
    }

    /// As [`Extracted::new`], for a writer that always extracts whatever `options.mode` says
    /// ([`crate::rar5::session::RarSession`]), which links only to files it extracted itself.
    pub(crate) fn for_output(options: &crate::extract::Options) -> Self {
        Self { placeholder: options.refused_link_placeholder, stored_name_targets: false, ..Self::new(options) }
    }

    /// Whether a refused symbolic link leaves an empty regular file at its path: its lexical target check then
    /// waits until its path is checked ([`refusal_before_place`]).
    pub(crate) fn placeholder(&self) -> bool {
        self.placeholder
    }
    fn forget(&mut self, rel: &Path) {
        // the record's own key, which is what was charged: never another spelling of it
        let Some((key, old)) = self.records.remove_entry(rel) else { return };
        let rel = key.as_path();
        self.bytes = self.bytes.saturating_sub(cost(rel, &old));
        if let Some(l) = old
            && let Some(members) = self.landed.get_mut(&l.rel)
        {
            members.retain(|m| m != rel);
            if members.is_empty() {
                self.landed.remove(&l.rel);
            }
        }
    }

    fn record(&mut self, rel: &Path, landed: Option<Landed>) {
        debug_assert!(normalised(rel), "record of an unnormalised path {rel:?}");
        debug_assert!(landed.as_ref().is_none_or(|l| normalised(&l.rel)), "unnormalised landing {rel:?}");
        self.forget(rel);
        let c = cost(rel, &landed);
        if let Some(bytes) = self.bytes.checked_add(c).filter(|&b| b <= MAX_RECORDED) {
            self.bytes = bytes;
            if let Some(l) = &landed {
                self.landed.entry(l.rel.clone()).or_default().push(rel.to_path_buf());
            }
            self.records.insert(rel.to_path_buf(), landed);
        }
    }

    /// The member at `rel` was written to `landed` (an absolute path under `dest`).
    pub(crate) fn file(&mut self, dest: &Path, rel: &Path, landed: &Path) {
        debug_assert!(normalised(rel), "record of an unnormalised path {rel:?}");
        let record = std::fs::symlink_metadata(landed).ok().filter(|m| m.file_type().is_file()).and_then(|m| {
            let landed = landed.strip_prefix(dest).ok()?.to_path_buf();
            let (dev, ino) = identity(&m);
            Some(Landed { rel: landed, dev, ino })
        });
        match record {
            Some(record) => self.record(rel, Some(record)),
            None => self.forget(rel),
        }
    }

    /// Whether `meta` (from `symlink_metadata`) is a symbolic link this run placed, by device and inode.
    pub(crate) fn owns_link(&self, meta: &std::fs::Metadata) -> bool {
        meta.file_type().is_symlink() && self.links.contains(&identity(meta))
    }

    /// A test run found the member at `rel` whole.
    pub(crate) fn tested(&mut self, rel: &Path) {
        self.record(rel, None);
    }

    /// Something other than a file this run wrote is now at `rel`: every record at or below it goes, by member
    /// path or by where it landed.
    pub(crate) fn replaced(&mut self, rel: &Path) {
        let mut gone: Vec<PathBuf> = at_or_below(&self.records, rel).map(|(k, _)| k.clone()).collect();
        gone.extend(at_or_below(&self.landed, rel).flat_map(|(_, members)| members.iter().cloned()));
        for member in gone {
            self.forget(&member);
        }
    }

    pub(crate) fn contains(&self, rel: &Path) -> bool {
        self.records.contains_key(rel)
    }

    /// The device and inode of the file the member at `rel` landed as, when it was extracted (not only tested).
    pub(crate) fn landed_identity(&self, rel: &Path) -> Option<(u64, u64)> {
        self.records.get(rel).and_then(|landed| landed.as_ref()).map(|landed| (landed.dev, landed.ino))
    }
}

#[cfg(unix)]
pub(crate) fn identity(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}

#[cfg(not(unix))]
pub(crate) fn identity(_: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// What one recorded symbolic link takes against [`MAX_RECORDED`].
const LINK_COST: usize = 64;

/// The message for a link whose target passes through a symbolic link that was in the destination before the run,
/// under [`PreexistingLinks::Refuse`].
pub(crate) const FOREIGN_LINK: &str = "the link's target passes through a link that was not extracted by this run";

/// The message for a link whose target, followed through the links on its way, leads out of the destination.
pub(crate) const LINK_LEAVES: &str = "the link's target leads out of the destination through another link";

/// How many links resolving one target may follow before it is refused (a loop, or a chain too long to check).
const MAX_HOPS: usize = 40;

/// Why the symbolic link to be placed at `path` (under `dest`) is refused for where its `target` really goes, or
/// None. Lexical containment ([`contained`]) treats every folder on the way as a real one; this follows the links
/// that are there now, as the system will: those the destination held before the run (`alias -> ../outside`) and
/// those this run placed (checked when they were made, and followed again as they are now). The target is refused
/// if any step leaves the destination, and under [`PreexistingLinks::Refuse`] as soon as it meets a link this run
/// did not place. The walk stops at the first part that doesn't exist: whatever is created there later is checked then.
#[cfg(unix)]
pub(crate) fn foreign_link(dest: &Path, path: &Path, target: &[u8], extracted: &Extracted) -> Option<&'static str> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let parts = |bytes: &[u8]| -> Vec<Vec<u8>> { bytes.split(|&b| b == b'/').map(<[u8]>::to_vec).collect() };
    let Some(mut at) = path.parent().map(Path::to_path_buf) else { return Some(LINK_LEAVES) };
    let mut pending: std::collections::VecDeque<Vec<u8>> = parts(target).into();
    let mut real_dest = None;
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        match part.as_slice() {
            b"" | b"." => continue,
            b".." => {
                if !at.pop() || !at.starts_with(dest) {
                    return Some(LINK_LEAVES);
                }
                continue;
            }
            name => at.push(std::ffi::OsStr::from_bytes(name)),
        }
        let m = match std::fs::symlink_metadata(&at) {
            Ok(m) => m,
            Err(_) => return None,
        };
        if !m.file_type().is_symlink() {
            continue;
        }
        if extracted.preexisting == PreexistingLinks::Refuse && !extracted.links.contains(&identity(&m)) {
            return Some(FOREIGN_LINK);
        }
        hops += 1;
        let Ok(next) = std::fs::read_link(&at) else { return Some(LINK_LEAVES) };
        if hops > MAX_HOPS {
            return Some(LINK_LEAVES);
        }
        at.pop();
        let next = next.into_os_string().into_vec();
        let rest = if next.first() == Some(&b'/') {
            // an absolute target stays inside only if it names the destination, as given or as it really is
            let next = Path::new(std::ffi::OsStr::from_bytes(&next));
            let real = real_dest.get_or_insert_with(|| std::fs::canonicalize(dest).ok());
            let Some(rest) =
                next.strip_prefix(dest).ok().or_else(|| real.as_ref().and_then(|r| next.strip_prefix(r).ok()))
            else {
                return Some(LINK_LEAVES);
            };
            at = dest.to_path_buf();
            parts(rest.as_os_str().as_bytes())
        } else {
            parts(&next)
        };
        for part in rest.into_iter().rev() {
            pending.push_front(part);
        }
    }
    None
}

/// Why a link member is refused before anything is written, or None when it may be placed at `rel`.
pub(crate) fn refusal(rel: &Path, kind: &LinkKind, extracted: &Extracted) -> Option<&'static str> {
    match kind {
        LinkKind::Symbolic(target) if !contained(rel, target) => Some(UNSAFE_TARGET),
        // under HardLinkTargets::StoredName what is at the target's name is found when the link is made
        LinkKind::Hard(_) if extracted.stored_name_targets => None,
        LinkKind::Hard(target) | LinkKind::Copy(target) if !extracted.contains(target) => Some(HARD_TARGET),
        _ => None,
    }
}

/// Whether something is already at `rel` under `dest` (a file, a folder or a link, a dangling one too), reached
/// through real folders only. Under `Overwrite::Skip` a link member found there is skipped before its target is
/// checked: a skipped member places and touches nothing, so it needs none of the checks a placed link does.
pub(crate) fn existing_target(dest: &Path, rel: &Path) -> bool {
    let mut at = dest.to_path_buf();
    let mut parts = rel.components().peekable();
    while let Some(part) = parts.next() {
        at.push(part);
        let Ok(meta) = std::fs::symlink_metadata(&at) else {
            return false;
        };
        if parts.peek().is_none() {
            return true;
        }
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return false;
        }
    }
    false
}

/// [`refusal`] for a writer that goes on to place the link with [`publish`] (or [`make_or_stand_in`]): with
/// placeholders on, a symbolic link whose target leaves the destination is not refused yet, so its path is checked
/// as any output's and the placeholder takes it; the placing refuses it then.
pub(crate) fn refusal_before_place(rel: &Path, kind: &LinkKind, extracted: &Extracted) -> Option<&'static str> {
    match kind {
        LinkKind::Symbolic(_) if extracted.placeholder => None,
        _ => refusal(rel, kind, extracted),
    }
}

/// Whether `error` from placing `kind` is a refused symbolic link, which a placeholder stands in for.
fn refused_symbolic(kind: &LinkKind, error: &io::Error) -> Option<&'static str> {
    match kind {
        LinkKind::Symbolic(_) if error.kind() != io::ErrorKind::Unsupported => member_failure(error),
        _ => None,
    }
}

/// Makes the link `kind` for the member at `rel` at `path`, as [`make_charging`] does after checking a symbolic
/// link's target lexically too ([`contained`]). With placeholders on, a symbolic link refused for its target leaves an
/// empty regular file at `path` instead, made as the link would be (only where nothing is, or replacing what is
/// there in one rename with `replace`, never through a link), and `Ok(Some(why))` says why the link was refused;
/// the caller records the file with [`stood_in`] and reports the member refused. Without, the refusal is the error.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_or_stand_in(
    dest: &Path,
    rel: &Path,
    kind: &LinkKind,
    extracted: &Extracted,
    path: &Path,
    replace: bool,
    modified: Option<SystemTime>,
    charge: &mut dyn FnMut(u64) -> io::Result<()>,
) -> io::Result<Option<&'static str>> {
    let made = match kind {
        LinkKind::Symbolic(target) if !contained(rel, target) => Err(refused(UNSAFE_TARGET)),
        _ => make_charging(dest, kind, extracted, path, replace, modified, charge),
    };
    match made {
        Ok(()) => Ok(None),
        Err(e)
            if extracted.placeholder
                && let Some(why) = refused_symbolic(kind, &e) =>
        {
            stand_in(path, replace)?;
            Ok(Some(why))
        }
        Err(e) => Err(e),
    }
}

/// Records the placeholder [`make_or_stand_in`] left at `path` (an absolute path under `dest`) for the member at
/// `rel`: a regular file this run wrote, as any other.
pub(crate) fn stood_in(dest: &Path, rel: &Path, path: &Path, extracted: &mut Extracted) {
    extracted.replaced(rel);
    if let Ok(landed) = path.strip_prefix(dest) {
        extracted.replaced(landed);
    }
    extracted.file(dest, rel, path);
}

/// An empty regular file at `path`: created only where nothing is (`O_EXCL`, which never follows a link), or with
/// `replace` staged beside it the same way and renamed over what is there, which never follows a link either.
fn stand_in(path: &Path, replace: bool) -> io::Result<()> {
    let new = |at: &Path| std::fs::OpenOptions::new().write(true).create_new(true).open(at).map(drop);
    if !replace {
        return new(path);
    }
    let parent = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    for _ in 0..64 {
        let n = NEXT_STAGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stage = parent.join(format!(".zipfast-placeholder-{}-{n}", std::process::id()));
        match new(&stage) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        return std::fs::rename(&stage, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&stage);
        });
    }
    Err(io::ErrorKind::AlreadyExists.into())
}

/// Places a checked link member: a symbolic link, or a hard link to the earlier member (a copy where the file
/// system takes no hard link), or a copy of it. `place` comes from the run's target check, so the overwrite choice,
/// a rename mode and the refusal to write through a link in the way are already settled. A rename mode's reserved
/// file is replaced by the link, or removed when the link can't be made.
pub(crate) fn publish(
    dest: &Path,
    rel: &Path,
    place: super::Place,
    kind: &LinkKind,
    modified: Option<SystemTime>,
    extracted: &mut Extracted,
) -> io::Result<()> {
    publish_charging(dest, rel, place, kind, modified, extracted, &mut |_| Ok(()))
}

/// [`publish`], asking `charge` first, with the copy's length, whenever the link has to be made as a copy, which
/// writes every byte of the target, holes included: an error from it fails the link instead.
pub(crate) fn publish_charging(
    dest: &Path,
    rel: &Path,
    place: super::Place,
    kind: &LinkKind,
    modified: Option<SystemTime>,
    extracted: &mut Extracted,
    charge: &mut dyn FnMut(u64) -> io::Result<()>,
) -> io::Result<()> {
    let (path, replace) = match &place.reserved {
        Some(reserved) => (reserved.path().to_path_buf(), true),
        None => (place.path.clone(), place.replace),
    };
    // on failure the reservation is dropped, which removes the empty file while it is still the one created
    let refused_with = make_or_stand_in(dest, rel, kind, extracted, &path, replace, modified, charge)?;
    if let Some(reserved) = place.reserved {
        let _ = reserved.into_parts();
    }
    match refused_with {
        None => placed(dest, rel, kind, &path, extracted),
        Some(why) => {
            // the placeholder is the run's own file, and the member is refused as without it
            stood_in(dest, rel, &path, extracted);
            return Err(refused(why));
        }
    }
    Ok(())
}

/// Makes the link `kind` at `path`, replacing what is there only with `replace`. A symbolic link takes the archived
/// `modified` time; a hard link is the earlier file, with its own time. Nothing is recorded: see [`placed`].
fn make_charging(
    dest: &Path,
    kind: &LinkKind,
    extracted: &Extracted,
    path: &Path,
    replace: bool,
    modified: Option<SystemTime>,
    charge: &mut dyn FnMut(u64) -> io::Result<()>,
) -> io::Result<()> {
    match kind {
        #[cfg(unix)]
        LinkKind::Symbolic(target) if let Some(why) = foreign_link(dest, path, target, extracted) => Err(refused(why)),
        LinkKind::Symbolic(target) => create(path, target, replace, modified),
        LinkKind::Hard(source) if extracted.stored_name_targets => {
            let found = stored_file(dest, source).ok_or_else(|| refused(STORED_TARGET))?;
            hard(dest, &found, path, replace, false, charge)
        }
        LinkKind::Hard(source) | LinkKind::Copy(source) => {
            let landed = extracted.records.get(source).cloned().flatten().ok_or_else(|| refused(HARD_TARGET))?;
            hard(dest, &landed, path, replace, matches!(kind, LinkKind::Copy(_)), charge)
        }
    }
}

/// The regular file at `rel` under `dest`, reached through real folders only (no symbolic link on the way or at
/// `rel`), as a hard link under [`crate::extract::HardLinkTargets::StoredName`] takes it. [`hard`] reaches it again
/// the same way and links it only while it is still this file (device and inode).
fn stored_file(dest: &Path, rel: &Path) -> Option<Landed> {
    if !normalised(rel) {
        return None;
    }
    let mut at = dest.to_path_buf();
    let mut parts = rel.components().peekable();
    while let Some(part) = parts.next() {
        at.push(part);
        let meta = std::fs::symlink_metadata(&at).ok()?;
        if parts.peek().is_none() {
            let (dev, ino) = identity(&meta);
            return meta.file_type().is_file().then(|| Landed { rel: rel.to_path_buf(), dev, ino });
        }
        if !meta.file_type().is_dir() {
            return None;
        }
    }
    None
}

/// Records a link member placed at `path` (an absolute path under `dest`) for the member at `rel`: a symbolic link
/// ends the records at and below both names (and later links may pass through it), and a hard link or copy is a
/// file later hard links may take.
pub(crate) fn placed(dest: &Path, rel: &Path, kind: &LinkKind, path: &Path, extracted: &mut Extracted) {
    match kind {
        LinkKind::Symbolic(_) => {
            extracted.replaced(rel);
            if let Ok(landed) = path.strip_prefix(dest) {
                extracted.replaced(landed);
            }
            // bounded like the file records: past the bound a link is not recorded, and a later link through it
            // is refused
            if let Ok(m) = std::fs::symlink_metadata(path)
                && m.file_type().is_symlink()
                && let Some(bytes) = extracted.bytes.checked_add(LINK_COST).filter(|&b| b <= MAX_RECORDED)
                && extracted.links.insert(identity(&m))
            {
                extracted.bytes = bytes;
            }
        }
        LinkKind::Hard(_) | LinkKind::Copy(_) => extracted.file(dest, rel, path),
    }
}

/// Records a link member a test run found sound.
pub(crate) fn tested(rel: &Path, kind: &LinkKind, extracted: &mut Extracted) {
    match kind {
        LinkKind::Symbolic(_) => extracted.replaced(rel),
        LinkKind::Hard(_) | LinkKind::Copy(_) => extracted.tested(rel),
    }
}

static NEXT_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A free name beside `path` for staging.
fn stage_beside(path: &Path) -> io::Result<std::path::PathBuf> {
    let parent = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let n = NEXT_STAGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // a short name of its own, as for symbolic links: one built from the destination name could pass the limit
    Ok(parent.join(format!(".zipfast-hardlink-{}-{n}", std::process::id())))
}

/// A hard link at `path` to the file the earlier member landed as (or with `copy` a copy of it): reached from
/// `dest` one folder at a time without following any link, and only when it is still that file (device and inode).
/// A copy where linking fails, read through the same checked handle. The stage is created only where nothing is,
/// and so is `path` without `replace`.
fn hard(
    dest: &Path,
    landed: &Landed,
    path: &Path,
    replace: bool,
    copy: bool,
    charge: &mut dyn FnMut(u64) -> io::Result<()>,
) -> io::Result<()> {
    let stage = stage_beside(path)?;
    let copied = stage_hard(dest, landed, &stage, copy, charge)?;
    let placed = if replace {
        std::fs::rename(&stage, path)
    } else {
        linked(&stage, path).or_else(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => Err(e),
            _ => {
                let mut from = open_no_follow(&stage)?;
                // a stage that is already a copy was charged for
                if !copied {
                    charge(from.metadata()?.len())?;
                }
                copy_new(&mut from, path)
            }
        })
    };
    let _ = std::fs::remove_file(&stage);
    placed
}

#[cfg(test)]
thread_local! {
    /// Makes every hard link on this thread fail, as on FAT or exFAT, so the copy is taken instead.
    pub(crate) static NO_HARD_LINKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn no_hard_links() -> bool {
    #[cfg(test)]
    return NO_HARD_LINKS.with(|n| n.get());
    #[cfg(not(test))]
    false
}

fn linked(from: &Path, to: &Path) -> io::Result<()> {
    if no_hard_links() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    std::fs::hard_link(from, to)
}

/// Opens `path` for reading, never through a symbolic link at its last component.
fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Copies `from` into a new file at `to`, created only where nothing is, with `from`'s permissions (the
/// archived ones it was extracted with), as a hard link would share them.
fn copy_new(from: &mut std::fs::File, to: &Path) -> io::Result<()> {
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(to)?;
    // set before any byte is written, so a restricted file's data is never readable under a wider mode
    if let Err(e) = from
        .metadata()
        .and_then(|m| out.set_permissions(m.permissions()))
        .and_then(|()| io::copy(from, &mut out).map(drop))
    {
        drop(out);
        let _ = std::fs::remove_file(to);
        return Err(e);
    }
    Ok(())
}

/// Links (with `copy`, or where linking fails, copies) the landed file to `stage`; true when it copied.
#[cfg(unix)]
fn stage_hard(
    dest: &Path,
    landed: &Landed,
    stage: &Path,
    copy: bool,
    charge: &mut dyn FnMut(u64) -> io::Result<()>,
) -> io::Result<bool> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let gone = || refused(TARGET_CHANGED);
    let cstr = |b: &[u8]| CString::new(b).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput));
    let open_at = |dir: libc::c_int, name: &CString, flags: libc::c_int| -> io::Result<OwnedFd> {
        // SAFETY: a NUL-terminated name relative to an open directory (or the current directory).
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) }
    };
    let mut dir = open_at(libc::AT_FDCWD, &cstr(dest.as_os_str().as_bytes())?, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let parts: Vec<_> = landed.rel.components().collect();
    let (last, folders) = parts.split_last().ok_or_else(gone)?;
    for part in folders {
        let std::path::Component::Normal(name) = part else { return Err(gone()) };
        let name = cstr(name.as_bytes())?;
        dir = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .map_err(|_| gone())?;
    }
    let std::path::Component::Normal(name) = last else { return Err(gone()) };
    let name = cstr(name.as_bytes())?;
    // st_dev and st_ino differ in width between platforms
    #[allow(clippy::unnecessary_cast)]
    let same = |m: &libc::stat| {
        (m.st_mode & libc::S_IFMT) == libc::S_IFREG && m.st_dev as u64 == landed.dev && m.st_ino as u64 == landed.ino
    };
    // SAFETY: zeroed stat filled in by fstatat on an open directory and a NUL-terminated name.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 || !same(&st) {
        return Err(gone());
    }
    let to = cstr(stage.as_os_str().as_bytes())?;
    // SAFETY: flags 0 never follow a symbolic link at the source name, resolved within the checked directory.
    let linked = !copy
        && !no_hard_links()
        && unsafe { libc::linkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_FDCWD, to.as_ptr(), 0) } == 0;
    if linked {
        // the name could have been swapped between the check and the link: the staged link must be that file
        match std::fs::symlink_metadata(stage) {
            Ok(m) if identity(&m) == (landed.dev, landed.ino) => return Ok(false),
            _ => {
                let _ = std::fs::remove_file(stage);
                return Err(gone());
            }
        }
    }
    // A copy, read through a handle opened without following a link and checked to be that file.
    let fd = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NOFOLLOW).map_err(|_| gone())?;
    // SAFETY: zeroed stat filled in by fstat on an open descriptor.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 || !same(&st) {
        return Err(gone());
    }
    charge(u64::try_from(st.st_size).unwrap_or(0))?;
    copy_new(&mut std::fs::File::from(fd), stage).map(|()| true)
}

#[cfg(not(unix))]
fn stage_hard(
    dest: &Path,
    landed: &Landed,
    stage: &Path,
    copy: bool,
    charge: &mut dyn FnMut(u64) -> io::Result<()>,
) -> io::Result<bool> {
    let source = dest.join(&landed.rel);
    if !std::fs::symlink_metadata(&source).is_ok_and(|m| m.file_type().is_file()) {
        return Err(refused(TARGET_CHANGED));
    }
    if !copy && linked(&source, stage).is_ok() {
        return Ok(false);
    }
    let mut from = std::fs::File::open(&source)?;
    charge(from.metadata()?.len())?;
    copy_new(&mut from, stage).map(|()| true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_targets_inside_the_destination_are_taken() {
        let ok = |rel: &str, target: &str| contained(Path::new(rel), target.as_bytes());
        assert!(ok("link", "emptydir"));
        assert!(ok("emptydir/link", "link"));
        assert!(ok("a/b/link", "../../c/./d/"));
        assert!(ok("a/link", ".."));
        assert!(!ok("link", ".."));
        assert!(!ok("a/link", "../.."));
        assert!(!ok("link", "/etc/passwd"));
        assert!(!ok("a/b/link", "c/../d"));
        assert!(!ok("a/link", "b/../../x"));
        assert!(!ok("link", ""));
        assert!(!ok("link", "a\0b"));
        assert!(!ok("link", &"a".repeat(4096)));
    }

    /// Past its byte bound a file is no longer recorded, and the bound is freed as records go.
    #[test]
    fn the_records_are_bounded() {
        let mut e = Extracted::default();
        let long = "d".repeat(60_000);
        let mut n = 0;
        while e.bytes + 60_100 <= MAX_RECORDED {
            e.tested(Path::new(&format!("{long}/{n}")));
            n += 1;
        }
        let late = format!("{long}/late");
        e.tested(Path::new(&late));
        assert!(!e.contains(Path::new(&late)), "past the bound");
        assert!(e.bytes <= MAX_RECORDED);
        e.replaced(Path::new(&long));
        assert_eq!(e.bytes, 0);
        e.tested(Path::new(&late));
        assert!(e.contains(Path::new(&late)));
    }

    fn landed_at(rel: &str) -> Option<Landed> {
        Some(Landed { rel: PathBuf::from(rel), dev: 1, ino: 2 })
    }

    /// A replacement takes every record at or below its path, by member path or by where the file landed, and
    /// nothing beside it ("a b" and "ab" are not below "a").
    #[test]
    fn a_replacement_takes_what_is_below_it_and_nothing_beside() {
        let mut e = Extracted::default();
        for name in ["a", "a/b", "a/b/c", "a b", "ab", "b"] {
            e.tested(Path::new(name));
        }
        // "x" landed (a rename mode) at "a/renamed"
        e.record(Path::new("x"), landed_at("a/renamed"));
        e.record(Path::new("y"), landed_at("ab/y"));
        e.replaced(Path::new("a"));
        let left: Vec<&str> = e.records.keys().map(|k| k.to_str().unwrap()).collect();
        assert_eq!(left, ["a b", "ab", "b", "y"]);
        assert_eq!(e.landed.len(), 1);
        e.replaced(Path::new(""));
        assert!(e.records.is_empty() && e.landed.is_empty() && e.bytes == 0);
    }

    /// The plain reference for [`Extracted`]: every record in a list, each replacement a scan of all of them, and
    /// "at or below" spelled out component by component.
    #[derive(Default)]
    struct Linear {
        records: Vec<(PathBuf, Option<PathBuf>)>,
    }

    fn below(path: &Path, prefix: &Path) -> bool {
        let (path, prefix): (Vec<_>, Vec<_>) = (path.components().collect(), prefix.components().collect());
        path.len() >= prefix.len() && path[..prefix.len()] == prefix[..]
    }

    impl Linear {
        fn forget(&mut self, rel: &Path) {
            self.records.retain(|(m, _)| m != rel);
        }

        fn record(&mut self, rel: &Path, landed: Option<PathBuf>) {
            self.forget(rel);
            self.records.push((rel.to_path_buf(), landed));
        }

        fn replaced(&mut self, rel: &Path) {
            self.records.retain(|(m, l)| !below(m, rel) && !l.as_deref().is_some_and(|l| below(l, rel)));
        }

        fn bytes(&self) -> usize {
            self.records
                .iter()
                .map(|(m, l)| cost(m, &l.as_ref().map(|l| Landed { rel: l.clone(), dev: 1, ino: 2 })))
                .sum()
        }
    }

    /// Random records, forgets and replacements, over names that sort between a folder and what is below it (`a b`,
    /// `a.b` and `ab` beside `a` and `a/b`), agree with the linear reference after every step: the same records,
    /// the same index of where each landed, and the same byte count.
    #[test]
    fn replacement_matches_a_linear_scan() {
        const PARTS: [&str; 8] = ["a", "a b", "a.b", "ab", "a/b", "b", "a-", "a0"];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let path = |next: &mut dyn FnMut(usize) -> usize| {
            let parts: Vec<&str> = (0..1 + next(3)).map(|_| PARTS[next(PARTS.len())]).collect();
            PathBuf::from(parts.join("/"))
        };
        for _ in 0..200 {
            let (mut e, mut reference) = (Extracted::default(), Linear::default());
            for _ in 0..60 {
                let rel = path(&mut next);
                match next(5) {
                    0 => {
                        e.tested(&rel);
                        reference.record(&rel, None);
                    }
                    1 | 2 => {
                        let landed = if next(2) == 0 { rel.clone() } else { path(&mut next) };
                        e.record(&rel, Some(Landed { rel: landed.clone(), dev: 1, ino: 2 }));
                        reference.record(&rel, Some(landed));
                    }
                    3 => {
                        e.forget(&rel);
                        reference.forget(&rel);
                    }
                    _ => {
                        e.replaced(&rel);
                        reference.replaced(&rel);
                    }
                }
                let mut want: Vec<_> = reference.records.iter().map(|(m, _)| m.clone()).collect();
                want.sort();
                assert_eq!(e.records.keys().cloned().collect::<Vec<_>>(), want);
                for (m, l) in &reference.records {
                    assert_eq!(e.records[m].as_ref().map(|l| &l.rel), l.as_ref(), "{m:?}");
                }
                let mut index: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
                for (m, l) in &reference.records {
                    if let Some(l) = l {
                        index.entry(l.clone()).or_default().push(m.clone());
                    }
                }
                let mut landed = e.landed.clone();
                landed.values_mut().for_each(|members| members.sort());
                index.values_mut().for_each(|members| members.sort());
                assert_eq!(landed, index);
                assert_eq!(e.bytes, reference.bytes());
            }
        }
    }

    /// A key spelled with a trailing separator or a `.` is refused in a debug build: such a path finds another
    /// spelling's record, and its byte count would drift.
    #[cfg(all(unix, debug_assertions))]
    #[test]
    fn unnormalised_keys_are_refused() {
        assert!(normalised(Path::new("a/b c/d.e")));
        for bad in ["a/", "a//b", "a/./b", "./a", "a/..", "/a"] {
            assert!(!normalised(Path::new(bad)), "{bad}");
            let caught = std::panic::catch_unwind(|| Extracted::default().tested(Path::new(bad)));
            assert!(caught.is_err(), "{bad}");
        }
    }

    /// 100,000 files and as many links placed beside them: each replacement visits only what it removes, so the
    /// run stays linear (a scan of every record per link was quadratic). A bound far above linear time.
    #[test]
    fn many_links_among_many_files_stay_linear() {
        let mut e = Extracted::default();
        let n = 100_000;
        for i in 0..n {
            e.record(Path::new(&format!("d{}/f{i}", i % 100)), landed_at(&format!("d{}/f{i}", i % 100)));
        }
        let start = std::time::Instant::now();
        for i in 0..n {
            e.replaced(Path::new(&format!("d{}/link{i}", i % 100)));
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(20), "{:?}", start.elapsed());
        assert_eq!(e.records.len(), n);
        e.replaced(Path::new("d7"));
        assert_eq!(e.records.len(), n - n / 100);
    }

    /// Replacing a file whose name is near the 255-byte component limit with a link works: the stage name is not
    /// built from the destination name.
    #[cfg(unix)]
    #[test]
    fn replacing_a_long_name_with_a_link_fits_the_name_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("n".repeat(240));
        std::fs::write(&path, b"old").unwrap();
        create(&path, b"target", true, None).unwrap();
        assert_eq!(std::fs::read_link(&path).unwrap(), Path::new("target"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
