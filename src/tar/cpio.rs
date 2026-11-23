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

//! cpio archives, read as tar members so they take tar's whole pipeline (containment, links, overwrite choices,
//! compressed streams): the old binary format in either byte order, the portable ASCII format (odc, `070707`), and
//! the new ASCII format (newc, `070701`) with or without its checksum (`070702`). The `TRAILER!!!` member ends the
//! archive.
//!
//! Hard links: newc stores a file's data with the last of its links, and the ones before it with none; odc and the
//! binary format store it with every link. Either way the first link to carry data comes out as the file and every
//! other name as a hard link to it, after it. Links that never carry data (an empty file) come out as an empty file
//! and links to it.

use std::collections::{HashMap, VecDeque};

use super::{Kind, Member, Reader, TarMagic, TarMetadata, name_of};
use crate::error::{Error, Result};

/// The longest member name taken, the NUL included.
const MAX_NAME: u64 = 64 << 10;
/// The longest symbolic link target taken.
const MAX_TARGET: u64 = 64 << 10;
/// What the bookkeeping for hard links may hold: names waiting for their data, and the names that carried it.
const MAX_LINK_BYTES: usize = 64 << 20;
const MAX_LINK_ENTRIES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Format {
    /// the old binary format, little- or big-endian
    Bin {
        big: bool,
    },
    Odc,
    Newc {
        crc: bool,
    },
}

impl Format {
    fn header_len(self) -> usize {
        match self {
            Format::Bin { .. } => 26,
            Format::Odc => 76,
            Format::Newc { .. } => 110,
        }
    }

    /// Padding after the name (whose length counts its NUL), so the data starts aligned.
    fn name_pad(self, namesize: u64) -> u64 {
        let end = self.header_len() as u64 + namesize;
        match self {
            Format::Bin { .. } => end % 2,
            Format::Odc => 0,
            Format::Newc { .. } => (4 - end % 4) % 4,
        }
    }

    fn data_pad(self, size: u64) -> u64 {
        match self {
            Format::Bin { .. } => size % 2,
            Format::Odc => 0,
            Format::Newc { .. } => (4 - size % 4) % 4,
        }
    }
}

/// The format a cpio archive starting with `head` uses: its magic, and a header whose fields read as numbers.
pub(super) fn sniff(head: &[u8]) -> Option<Format> {
    let format = match head.get(..6)? {
        b"070701" => Format::Newc { crc: false },
        b"070702" => Format::Newc { crc: true },
        b"070707" => Format::Odc,
        _ => match head[..2] {
            [0xc7, 0x71] => Format::Bin { big: false },
            [0x71, 0xc7] => Format::Bin { big: true },
            _ => return None,
        },
    };
    let header = parse(format, head.get(..format.header_len())?).ok()?;
    // the name has to be there and end in its NUL: two bytes of binary magic alone say little
    let start = format.header_len();
    let name = head.get(start..start + usize::try_from(header.namesize).ok()?)?;
    (name.last() == Some(&0)).then_some(format)
}

struct Header {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u64,
    gid: u64,
    nlink: u64,
    mtime: i64,
    namesize: u64,
    filesize: u64,
    check: u32,
}

fn digits(field: &[u8], radix: u32) -> Result<u64> {
    let text = std::str::from_utf8(field).map_err(|_| Error::Corrupt("a cpio header's numbers are unreadable"))?;
    u64::from_str_radix(text, radix).map_err(|_| Error::Corrupt("a cpio header's numbers are unreadable"))
}

fn parse(format: Format, h: &[u8]) -> Result<Header> {
    let header = match format {
        Format::Bin { big } => {
            let word = |i: usize| {
                let b = [h[2 * i], h[2 * i + 1]];
                u64::from(if big { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
            };
            Header {
                dev: word(1),
                ino: word(2),
                mode: word(3) as u32,
                uid: word(4),
                gid: word(5),
                nlink: word(6),
                mtime: ((word(8) << 16) | word(9)) as i64,
                namesize: word(10),
                filesize: (word(11) << 16) | word(12),
                check: 0,
            }
        }
        Format::Odc => {
            let f = |at: usize, len: usize| digits(&h[at..at + len], 8);
            Header {
                dev: f(6, 6)?,
                ino: f(12, 6)?,
                mode: f(18, 6)? as u32,
                uid: f(24, 6)?,
                gid: f(30, 6)?,
                nlink: f(36, 6)?,
                mtime: f(48, 11)? as i64,
                namesize: f(59, 6)?,
                filesize: f(65, 11)?,
                check: 0,
            }
        }
        Format::Newc { .. } => {
            let f = |i: usize| digits(&h[6 + 8 * i..14 + 8 * i], 16);
            Header {
                ino: f(0)?,
                mode: f(1)? as u32,
                uid: f(2)?,
                gid: f(3)?,
                nlink: f(4)?,
                mtime: f(5)? as i64,
                filesize: f(6)?,
                dev: (f(7)? << 32) | f(8)?,
                namesize: f(11)?,
                check: f(12)? as u32,
            }
        }
    };
    if header.namesize == 0 || header.namesize > MAX_NAME {
        return Err(Error::Corrupt("a cpio member's name length is impossible"));
    }
    Ok(header)
}

/// What a cpio archive's reader keeps between members.
pub(super) struct State {
    format: Format,
    ended: bool,
    /// members already read, to hand out before reading on: hard links resolved by a later member
    queue: VecDeque<Member>,
    /// for each file with more than one link (by device and inode): the name that carried its data
    owners: HashMap<(u64, u64), String>,
    /// links read before any carried data, by device and inode, each list in archive order
    waiting: HashMap<(u64, u64), Vec<Waiting>>,
    waiting_count: usize,
    /// the next waiting link's place in the archive, so the ones never resolved come out in order
    seq: u64,
    link_bytes: usize,
}

/// A link read before any carried its file's data: only what it takes to hand it out later, as a link or (at the
/// end, for the first of a file that never carried data) as an empty file.
struct Waiting {
    seq: u64,
    name: String,
    raw_name: Option<Vec<u8>>,
    mode: u32,
    mtime: i64,
    uid: u64,
    gid: u64,
}

impl Waiting {
    /// What one takes in the bookkeeping, its name included, against [`MAX_LINK_BYTES`].
    fn cost(&self) -> usize {
        std::mem::size_of::<Self>() + self.name.len() + self.raw_name.as_ref().map_or(0, Vec::len)
    }

    fn into_member(self, kind: Kind, link: String) -> Member {
        let mut m = cpio_member(self.name, self.raw_name, kind, link, 0, (self.mtime, self.mode), (self.uid, self.gid));
        m.size = 0;
        m
    }
}

/// A member as the cpio reader hands it out.
fn cpio_member(
    name: String,
    raw_name: Option<Vec<u8>>,
    kind: Kind,
    link: String,
    size: u64,
    (mtime, mode): (i64, u32),
    (uid, gid): (u64, u64),
) -> Member {
    let typeflag = match kind {
        Kind::File => b'0',
        Kind::Dir => b'5',
        Kind::Symlink => b'2',
        Kind::HardLink => b'1',
        Kind::Other(t) => t,
    };
    Member {
        name,
        raw_name,
        link,
        raw_link: None,
        size: if matches!(kind, Kind::File) { size } else { 0 },
        kind,
        mtime: Some(mtime),
        nanos: 0,
        mode: mode & 0o7777,
        atime: None,
        ctime: None,
        cpio: true,
        sparse: None,
        tar: Box::new(TarMetadata {
            magic: TarMagic::Other,
            typeflag,
            user: None,
            group: None,
            uid: Some(uid),
            gid: Some(gid),
            device_major: None,
            device_minor: None,
            pax_header_name: None,
            pax_records: Vec::new(),
            pax_records_truncated: false,
            header: None,
        }),
    }
}

impl State {
    pub(super) fn new(format: Format) -> Self {
        State {
            format,
            ended: false,
            queue: VecDeque::new(),
            owners: HashMap::new(),
            waiting: HashMap::new(),
            waiting_count: 0,
            seq: 0,
            link_bytes: 0,
        }
    }

    /// Counts `bytes` more of bookkeeping (a hash table entry's overhead included) against the caps.
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.link_bytes += bytes + 32;
        if self.link_bytes > MAX_LINK_BYTES || self.owners.len() + self.waiting_count >= MAX_LINK_ENTRIES {
            return Err(Error::Corrupt("a cpio archive has too many hard links"));
        }
        Ok(())
    }

    /// Hands out the links still waiting for data at the end: the first as an empty file, the rest as links to it.
    fn flush(&mut self) {
        let mut out: Vec<(u64, Member)> = Vec::with_capacity(self.waiting_count);
        for (_, links) in std::mem::take(&mut self.waiting) {
            let mut links = links.into_iter();
            let Some(first) = links.next() else { continue };
            let target = first.name.clone();
            out.push((first.seq, first.into_member(Kind::File, String::new())));
            out.extend(links.map(|l| (l.seq, l.into_member(Kind::HardLink, target.clone()))));
        }
        self.waiting_count = 0;
        // each file's first link comes before its others, so archive order keeps every link after its target
        out.sort_unstable_by_key(|(seq, _)| *seq);
        self.queue.extend(out.into_iter().map(|(_, m)| m));
    }
}

impl Reader {
    fn read_exact_cpio(&mut self, buf: &mut [u8]) -> Result<()> {
        if self.src.read(buf)? < buf.len() {
            return Err(Error::Truncated);
        }
        Ok(())
    }

    /// The next cpio member, after passing over whatever is left of the one before.
    pub(super) fn next_cpio(&mut self) -> Result<Option<Member>> {
        if self.unread > 0 {
            let n = std::mem::take(&mut self.unread);
            self.src.skip(n, &mut self.scratch)?;
        }
        self.crc = None;
        loop {
            let state = self.cpio.as_mut().expect("a cpio reader");
            if let Some(m) = state.queue.pop_front() {
                return Ok(Some(m));
            }
            if state.ended {
                return Ok(None);
            }
            let format = state.format;
            let mut head = [0u8; 110];
            let head = &mut head[..format.header_len()];
            let got = self.src.read(head)?;
            if got == 0 {
                // the trailer is missing, as an end marker can be in tar: what was read stands
                let state = self.cpio.as_mut().expect("a cpio reader");
                state.ended = true;
                state.flush();
                continue;
            }
            if got < head.len() {
                return Err(Error::Truncated);
            }
            // newc and newc with checksums mix, as some writers end either with a plain trailer
            let format = match (sniff_magic(head), format) {
                (Some(Format::Newc { crc }), Format::Newc { .. }) => Format::Newc { crc },
                (Some(found), _) if found == format => format,
                _ => return Err(Error::Corrupt("a cpio header's magic is wrong")),
            };
            let h = parse(format, head)?;
            let mut name = vec![0u8; h.namesize as usize];
            self.read_exact_cpio(&mut name)?;
            if name.pop() != Some(0) {
                return Err(Error::Corrupt("a cpio member's name doesn't end in NUL"));
            }
            // a name may hold padding NULs of its own
            if let Some(end) = name.iter().position(|&b| b == 0) {
                name.truncate(end);
            }
            self.src.skip(format.name_pad(h.namesize), &mut self.scratch)?;
            let data_pad = format.data_pad(h.filesize);
            if name == b"TRAILER!!!" {
                // what comes after the trailer is padding to the writer's block size
                self.src.skip(h.filesize, &mut self.scratch)?;
                let state = self.cpio.as_mut().expect("a cpio reader");
                state.ended = true;
                state.flush();
                continue;
            }
            let decoded = name_of(&name);
            let raw_name = std::str::from_utf8(&name).is_err().then_some(name);
            let kind = match h.mode & 0o170000 {
                0o100000 => Kind::File,
                0o040000 => Kind::Dir,
                0o120000 => Kind::Symlink,
                0o020000 => Kind::Other(b'3'),
                0o060000 => Kind::Other(b'4'),
                0o010000 => Kind::Other(b'6'),
                // a socket, or a type no writer uses
                _ => Kind::Other(b's'),
            };
            let mut link = String::new();
            let mut raw_link = None;
            let mut size = h.filesize;
            if kind == Kind::Symlink {
                if h.filesize > MAX_TARGET {
                    return Err(Error::Corrupt("a cpio symbolic link's target is too long"));
                }
                let mut target = vec![0u8; h.filesize as usize];
                self.read_exact_cpio(&mut target)?;
                self.src.skip(data_pad, &mut self.scratch)?;
                link = name_of(&target);
                raw_link = std::str::from_utf8(&target).is_err().then_some(target);
                size = 0;
            } else {
                self.unread = h.filesize + data_pad;
            }
            if kind == Kind::File && h.nlink > 1 && h.ino != 0 {
                let key = (h.dev, h.ino);
                let state = self.cpio.as_mut().expect("a cpio reader");
                if let Some(owner) = state.owners.get(&key) {
                    // the data is already out under another name: this one links to it, and its copy is passed over
                    let owner = owner.clone();
                    let m = cpio_member(decoded, raw_name, Kind::HardLink, owner, 0, (h.mtime, h.mode), (h.uid, h.gid));
                    return Ok(Some(m));
                }
                if h.filesize == 0 {
                    let seq = state.seq;
                    state.seq += 1;
                    let waiting =
                        Waiting { seq, name: decoded, raw_name, mode: h.mode, mtime: h.mtime, uid: h.uid, gid: h.gid };
                    state.charge(waiting.cost())?;
                    state.waiting.entry(key).or_default().push(waiting);
                    state.waiting_count += 1;
                    continue;
                }
                state.charge(std::mem::size_of::<((u64, u64), String)>() + decoded.len())?;
                state.owners.insert(key, decoded.clone());
                // the names that came before without data link to this one, after it: only this file's
                if let Some(before) = state.waiting.remove(&key) {
                    state.waiting_count -= before.len();
                    // their bookkeeping is freed: only the owner's name stays
                    state.link_bytes -= before.iter().map(|w| w.cost() + 32).sum::<usize>();
                    for earlier in before {
                        state.queue.push_back(earlier.into_member(Kind::HardLink, decoded.clone()));
                    }
                }
            }
            let mut m = cpio_member(decoded, raw_name, kind, link, size, (h.mtime, h.mode), (h.uid, h.gid));
            m.raw_link = raw_link;
            if matches!(format, Format::Newc { crc: true }) && kind == Kind::File {
                self.crc = Some(super::CpioCrc { want: h.check, sum: 0, left: h.filesize });
            }
            return Ok(Some(m));
        }
    }
}

fn sniff_magic(head: &[u8]) -> Option<Format> {
    match &head[..6] {
        b"070701" => Some(Format::Newc { crc: false }),
        b"070702" => Some(Format::Newc { crc: true }),
        b"070707" => Some(Format::Odc),
        _ => match head[..2] {
            [0xc7, 0x71] => Some(Format::Bin { big: false }),
            [0x71, 0xc7] => Some(Format::Bin { big: true }),
            _ => None,
        },
    }
}
