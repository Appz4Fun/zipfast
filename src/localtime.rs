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

//! MS-DOS date and time fields (ZIP without a time extra, RAR 4.x) carry no time zone: they are the archiving
//! machine's local wall clock. Info-ZIP unzip, 7-Zip, libarchive and UnRAR read them in the local time zone of the
//! machine extracting, and so does zipfast.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;

/// The UTC instant of `wall`, a local wall-clock time written as if it were Unix seconds in UTC, in this machine's
/// local time zone. A time in a daylight-saving gap or overlap resolves as the platform's `mktime` (Unix) or
/// `TzSpecificLocalTimeToSystemTime` (Windows) resolves it. Where the zone can't be applied, `wall` is returned.
///
/// The platform call is slow (on macOS about 2 microseconds, most of an archive open with many members), so the
/// zone's offset is remembered per hour of wall-clock time; see [`HourOffsets`].
pub(crate) fn local_to_utc(wall: i64) -> i64 {
    thread_local! {
        static OFFSETS: RefCell<HourOffsets> = RefCell::new(HourOffsets::default());
    }
    OFFSETS
        .with_borrow_mut(|offsets| offsets.convert(wall, || std::env::var_os("TZ"), imp::local_to_utc))
        .unwrap_or(wall)
}

/// How many hours [`HourOffsets`] remembers before it starts over.
const REMEMBERED_HOURS: usize = 4096;

/// How many conversions answered from memory may pass before `TZ` is read again. Reading it scans the environment,
/// which costs more than the conversion itself.
const TZ_CHECK_EVERY: u32 = 256;

/// The local zone's offset for each wall-clock hour already converted.
///
/// An hour whose first and last second convert with the same offset has that offset throughout: a zone changes its
/// offset at most once in an hour, and a change inside the hour would give its two ends different offsets. Such an
/// hour is converted by adding the offset. An hour whose ends differ holds a daylight-saving change, and every time
/// in it goes to the platform. So does every time in an hour whose ends the platform can't convert.
///
/// The offsets are kept for one value of `TZ` and dropped when it changes, since the platform reads `TZ` too. `TZ` is
/// read again before converting a new hour and after every [`TZ_CHECK_EVERY`] conversions from memory, so a change
/// to it takes effect within that many conversions.
#[derive(Default)]
struct HourOffsets {
    zone: Option<OsString>,
    /// Conversions answered from memory since `TZ` was last read.
    since_check: u32,
    /// The hour converted last and its entry in `hours`: archive members often share an hour with the one before.
    last: Option<(i64, Option<i64>)>,
    /// Hour number (`wall` divided by 3600, rounded down) to its offset, or `None` to ask the platform each time.
    hours: HashMap<i64, Option<i64>>,
}

impl HourOffsets {
    fn convert(
        &mut self,
        wall: i64,
        zone: impl FnOnce() -> Option<OsString>,
        platform: impl Fn(i64) -> Option<i64>,
    ) -> Option<i64> {
        let hour = wall.div_euclid(3600);
        if self.since_check < TZ_CHECK_EVERY
            && let Some((last_hour, offset)) = self.last
            && last_hour == hour
        {
            self.since_check += 1;
            return Self::apply(wall, offset, platform);
        }
        if self.since_check >= TZ_CHECK_EVERY || !self.hours.contains_key(&hour) {
            self.since_check = 0;
            let zone = zone();
            if zone != self.zone || self.hours.len() >= REMEMBERED_HOURS {
                self.hours.clear();
                self.last = None;
                self.zone = zone;
            }
        } else {
            self.since_check += 1;
        }
        let offset = *self.hours.entry(hour).or_insert_with(|| {
            let (first, last) = (hour.checked_mul(3600)?, hour.checked_mul(3600)?.checked_add(3599)?);
            let start = platform(first)?.checked_sub(first)?;
            let end = platform(last)?.checked_sub(last)?;
            (start == end).then_some(start)
        });
        self.last = Some((hour, offset));
        Self::apply(wall, offset, platform)
    }

    fn apply(wall: i64, offset: Option<i64>, platform: impl Fn(i64) -> Option<i64>) -> Option<i64> {
        match offset {
            Some(offset) => wall.checked_add(offset),
            None => platform(wall),
        }
    }
}

#[cfg(unix)]
mod imp {
    pub(super) fn local_to_utc(wall: i64) -> Option<i64> {
        let time = libc::time_t::try_from(wall).ok()?;
        // SAFETY: both are plain C structs written by the calls below; a null return is checked.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::gmtime_r(&time, &mut tm) }.is_null() {
            return None;
        }
        // Let mktime decide whether daylight saving applies, as unzip does.
        tm.tm_isdst = -1;
        let utc = unsafe { libc::mktime(&mut tm) };
        // -1 is also 1969-12-31 23:59:59 UTC, which no DOS time (1980 on) can map to.
        #[allow(clippy::useless_conversion)] // time_t is narrower on some targets
        (utc != -1).then_some(i64::from(utc))
    }
}

#[cfg(windows)]
mod imp {
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn TzSpecificLocalTimeToSystemTime(
            zone: *const std::ffi::c_void,
            local: *const SystemTime,
            universal: *mut SystemTime,
        ) -> i32;
    }

    pub(super) fn local_to_utc(wall: i64) -> Option<i64> {
        let (days, secs) = (wall.div_euclid(86_400), wall.rem_euclid(86_400));
        let (year, month, day) = civil(days);
        let local = SystemTime {
            year: u16::try_from(year).ok()?,
            month: month as u16,
            day: day as u16,
            hour: (secs / 3600) as u16,
            minute: (secs / 60 % 60) as u16,
            second: (secs % 60) as u16,
            ..SystemTime::default()
        };
        let mut utc = SystemTime::default();
        // SAFETY: a null zone means the current one; both structs are valid for the call.
        if unsafe { TzSpecificLocalTimeToSystemTime(std::ptr::null(), &local, &mut utc) } == 0 {
            return None;
        }
        let days = days_from_civil(i64::from(utc.year), i64::from(utc.month), i64::from(utc.day));
        Some(days * 86_400 + i64::from(utc.hour) * 3600 + i64::from(utc.minute) * 60 + i64::from(utc.second))
    }

    /// Year, month and day of a day count since 1970 (proleptic Gregorian).
    fn civil(days: i64) -> (i64, i64, i64) {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        (yoe + era * 400 + i64::from(month <= 2), month, day)
    }

    fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
        era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn local_to_utc(_wall: i64) -> Option<i64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zone at +2 hours that moves to +1 hour at `change`, which need not fall on the hour.
    fn zone_with_change(change: i64) -> impl Fn(i64) -> Option<i64> {
        move |wall: i64| Some(if wall < change { wall - 7200 } else { wall - 3600 })
    }

    #[test]
    fn offsets_match_the_platform_on_both_sides_of_a_change_inside_an_hour() {
        // The change at 10:30 sits inside an hour: that hour must go to the platform, the others use the offset.
        let change = 10 * 3600 + 1800;
        let platform = zone_with_change(change);
        let mut offsets = HourOffsets::default();
        for wall in (8 * 3600..13 * 3600).step_by(2) {
            assert_eq!(offsets.convert(wall, || None, &platform), platform(wall), "wall {wall}");
        }
        assert_eq!(offsets.hours.get(&10), Some(&None), "the hour holding the change is not cached");
        assert_eq!(offsets.hours.get(&9), Some(&Some(-7200)));
        assert_eq!(offsets.hours.get(&11), Some(&Some(-3600)));
    }

    #[test]
    fn a_change_on_the_hour_leaves_every_hour_uniform() {
        let change = 10 * 3600;
        let platform = zone_with_change(change);
        let mut offsets = HourOffsets::default();
        for wall in (8 * 3600..12 * 3600).step_by(2) {
            assert_eq!(offsets.convert(wall, || None, &platform), platform(wall), "wall {wall}");
        }
        assert_eq!(offsets.hours.get(&9), Some(&Some(-7200)));
        assert_eq!(offsets.hours.get(&10), Some(&Some(-3600)));
    }

    #[test]
    fn each_hour_asks_the_platform_twice_and_then_never() {
        let calls = std::cell::Cell::new(0);
        let platform = |wall: i64| {
            calls.set(calls.get() + 1);
            Some(wall + 18_000)
        };
        let mut offsets = HourOffsets::default();
        for wall in (0..3600).step_by(2) {
            assert_eq!(offsets.convert(wall, || None, platform), Some(wall + 18_000));
        }
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn a_new_tz_is_noticed_on_a_new_hour_or_within_the_check_interval() {
        let mut offsets = HourOffsets::default();
        assert_eq!(offsets.convert(100, || Some("A".into()), |w| Some(w + 1)), Some(101));
        // A new hour reads TZ: a change drops every remembered offset.
        assert_eq!(offsets.convert(4000, || Some("B".into()), |w| Some(w + 2)), Some(4002));
        assert_eq!(offsets.convert(100, || Some("B".into()), |w| Some(w + 2)), Some(102));
        // Within a remembered hour, TZ is read again after TZ_CHECK_EVERY conversions from memory.
        let reads = std::cell::Cell::new(0);
        for _ in 0..TZ_CHECK_EVERY {
            let zone = || {
                reads.set(reads.get() + 1);
                Some("B".into())
            };
            assert_eq!(offsets.convert(100, zone, |_| unreachable!("remembered")), Some(102));
        }
        assert_eq!(reads.get(), 0, "remembered conversions do not read TZ");
        assert_eq!(offsets.convert(100, || Some("C".into()), |w| Some(w + 3)), Some(103));
    }

    #[test]
    fn an_hour_the_platform_cannot_convert_goes_to_the_platform_each_time() {
        let mut offsets = HourOffsets::default();
        assert_eq!(offsets.convert(100, || None, |_| None), None);
        assert_eq!(offsets.convert(200, || None, |w| (w == 200).then_some(w)), Some(200));
    }

    #[test]
    fn the_cache_starts_over_when_full() {
        let mut offsets = HourOffsets::default();
        for hour in 0..REMEMBERED_HOURS as i64 + 10 {
            offsets.convert(hour * 3600, || None, Some);
        }
        assert!(offsets.hours.len() <= REMEMBERED_HOURS);
    }

    #[test]
    fn extreme_walls_do_not_overflow() {
        let mut offsets = HourOffsets::default();
        assert_eq!(offsets.convert(i64::MAX, || None, Some), Some(i64::MAX));
        assert_eq!(offsets.convert(i64::MIN, || None, Some), Some(i64::MIN));
    }
}
