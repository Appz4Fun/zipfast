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

/// The UTC instant of `wall`, a local wall-clock time written as if it were Unix seconds in UTC, in this machine's
/// local time zone. A time in a daylight-saving gap or overlap resolves as the platform's `mktime` (Unix) or
/// `TzSpecificLocalTimeToSystemTime` (Windows) resolves it. Where the zone can't be applied, `wall` is returned.
pub(crate) fn local_to_utc(wall: i64) -> i64 {
    imp::local_to_utc(wall).unwrap_or(wall)
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
