//! Time zones by IANA name ("America/Denver"), usable as `chrono` time zones.
//!
//! A zone's rules come from the system's time zone database (`/usr/share/zoneinfo`, or `$TZDIR`)
//! if it has that zone, as they did for the Python server, and otherwise from the copy built into
//! the binary (a system may have no database, or one without the older names such as
//! "US/Mountain"). Governments change these rules with little notice (British Columbia stopped
//! changing its clocks in 2026), and a server that switches a charger by the clock is an hour out
//! the moment its rules are stale: the system's copy is updated with the operating system, the
//! built-in one with the `jiff-tzdb` crate.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use chrono::{Datelike, FixedOffset, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, Offset, TimeZone, Timelike};
use jiff::tz::{AmbiguousOffset, TimeZone as Rules, TimeZoneDatabase};

/// A time zone. Small and `Copy`, so a `DateTime<Tz>` is too.
#[derive(Clone, Copy)]
pub struct Tz(Option<&'static Rules>);

impl Tz {
    pub const UTC: Tz = Tz(None);

    /// The zone's name, as it was asked for.
    pub fn name(&self) -> &'static str {
        self.0.and_then(Rules::iana_name).unwrap_or("UTC")
    }

    fn seconds_at(&self, utc: &NaiveDateTime) -> i32 {
        let Some(rules) = self.0 else { return 0 };
        let utc = utc.and_utc();
        // Outside the years jiff counts (-9999..=9999) there is nothing sensible to say.
        jiff::Timestamp::new(utc.timestamp(), utc.timestamp_subsec_nanos().min(999_999_999) as i32)
            .map_or(0, |instant| rules.to_offset(instant).seconds())
    }

    fn offset(&self, seconds: i32) -> TzOffset {
        TzOffset { tz: *self, fixed: FixedOffset::east_opt(seconds).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap()) }
    }
}

/// Every zone asked for so far. A zone is kept for as long as the process runs, which is what
/// lets `Tz` be `Copy`; only names the database knows get in, so there are a few hundred at most.
static KNOWN: Mutex<Option<HashMap<String, &'static Rules>>> = Mutex::new(None);

impl FromStr for Tz {
    type Err = String;

    fn from_str(name: &str) -> Result<Tz, String> {
        let mut known = KNOWN.lock().unwrap_or_else(|e| e.into_inner());
        let known = known.get_or_insert_with(HashMap::new);
        if let Some(rules) = known.get(name) {
            return Ok(Tz(Some(rules)));
        }
        let unknown = || format!("unknown time zone {name:?}");
        static BUILT_IN: OnceLock<TimeZoneDatabase> = OnceLock::new();
        let built_in = BUILT_IN.get_or_init(TimeZoneDatabase::bundled);
        // A database looks names up without regard to case; the name is stored as it was given,
        // and "america/denver" is not something another reader of the file would know.
        let rules = [jiff::tz::db(), built_in]
            .into_iter()
            .filter_map(|database| database.get(name).ok())
            .find(|rules| rules.iana_name() == Some(name))
            .ok_or_else(unknown)?;
        let rules: &'static Rules = Box::leak(Box::new(rules));
        known.insert(name.to_string(), rules);
        Ok(Tz(Some(rules)))
    }
}

impl fmt::Debug for Tz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl PartialEq for Tz {
    fn eq(&self, other: &Tz) -> bool {
        self.name() == other.name()
    }
}

/// A zone's offset from UTC at some moment.
#[derive(Clone, Copy, PartialEq)]
pub struct TzOffset {
    tz: Tz,
    fixed: FixedOffset,
}

impl Offset for TzOffset {
    fn fix(&self) -> FixedOffset {
        self.fixed
    }
}

impl fmt::Debug for TzOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.fixed, f)
    }
}

impl fmt::Display for TzOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.fixed, f)
    }
}

impl TimeZone for Tz {
    type Offset = TzOffset;

    fn from_offset(offset: &TzOffset) -> Tz {
        offset.tz
    }

    fn offset_from_local_date(&self, local: &NaiveDate) -> LocalResult<TzOffset> {
        self.offset_from_local_datetime(&local.and_time(NaiveTime::MIN))
    }

    /// `Single` for a wall-clock reading that happens once, `Ambiguous(first, second)` for one
    /// that happens twice (the clocks went back over it), `None` for one they skipped.
    fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> LocalResult<TzOffset> {
        let Some(rules) = self.0 else { return LocalResult::Single(self.offset(0)) };
        let wall = i16::try_from(local.year()).ok().and_then(|year| {
            let (date, time) = (local.date(), local.time());
            jiff::civil::DateTime::new(
                year,
                date.month() as i8,
                date.day() as i8,
                time.hour() as i8,
                time.minute() as i8,
                time.second() as i8,
                time.nanosecond().min(999_999_999) as i32,
            )
            .ok()
        });
        let Some(wall) = wall else { return LocalResult::Single(self.offset(0)) };
        match rules.to_ambiguous_timestamp(wall).offset() {
            AmbiguousOffset::Unambiguous { offset } => LocalResult::Single(self.offset(offset.seconds())),
            AmbiguousOffset::Fold { before, after } => {
                LocalResult::Ambiguous(self.offset(before.seconds()), self.offset(after.seconds()))
            }
            AmbiguousOffset::Gap { .. } => LocalResult::None,
        }
    }

    fn offset_from_utc_date(&self, utc: &NaiveDate) -> TzOffset {
        self.offset_from_utc_datetime(&utc.and_time(NaiveTime::MIN))
    }

    fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> TzOffset {
        self.offset(self.seconds_at(utc))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;

    fn zone(name: &str) -> Tz {
        name.parse().unwrap()
    }

    fn offset_hours(tz: Tz, y: i32, m: u32, d: u32, h: u32) -> f64 {
        let instant = Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap();
        f64::from(instant.with_timezone(&tz).offset().fix().local_minus_utc()) / 3600.0
    }

    #[test]
    fn zones_are_found_by_their_exact_name() {
        assert_eq!(zone("America/Denver").name(), "America/Denver");
        assert_eq!(zone("UTC").name(), "UTC");
        assert_eq!(zone("Etc/UTC").name(), "Etc/UTC");
        assert_eq!(zone("US/Mountain").name(), "US/Mountain"); // an old name not every system keeps
        for name in ["", "america/denver", "Mars/Olympus", "America/Denver ", "../etc/passwd", "/etc/localtime"] {
            assert!(name.parse::<Tz>().is_err(), "{name:?}");
        }
        // Asked for twice, it is the same zone and nothing more is kept.
        assert_eq!(zone("Europe/Berlin"), zone("Europe/Berlin"));
        assert_eq!(Tz::UTC.name(), "UTC");
    }

    #[test]
    fn offsets_follow_the_clock_changes() {
        let denver = zone("America/Denver");
        assert_eq!(offset_hours(denver, 2026, 1, 15, 12), -7.0);
        assert_eq!(offset_hours(denver, 2026, 7, 15, 12), -6.0);
        assert_eq!(offset_hours(zone("Asia/Kolkata"), 2026, 7, 15, 12), 5.5);
        assert_eq!(offset_hours(Tz::UTC, 2026, 7, 15, 12), 0.0);
        // Rules that only exist as "from now on" in the database still apply decades out.
        assert_eq!(offset_hours(zone("Europe/Berlin"), 2090, 7, 15, 12), 2.0);
        assert_eq!(offset_hours(zone("Europe/Berlin"), 2090, 1, 15, 12), 1.0);
    }

    #[test]
    fn a_wall_clock_reading_can_happen_once_twice_or_never() {
        let denver = zone("America/Denver");
        let wall = |m: u32, d: u32, h: u32, min: u32| NaiveDate::from_ymd_opt(2026, m, d).unwrap().and_hms_opt(h, min, 0).unwrap();
        let hours = |offset: TzOffset| offset.fix().local_minus_utc() / 3600;
        match denver.offset_from_local_datetime(&wall(6, 1, 12, 0)) {
            LocalResult::Single(offset) => assert_eq!(hours(offset), -6),
            other => panic!("{other:?}"),
        }
        // 8 March 2026: 02:00 becomes 03:00.
        assert!(matches!(denver.offset_from_local_datetime(&wall(3, 8, 2, 30)), LocalResult::None));
        // 1 November 2026: 02:00 becomes 01:00 again; the first pass is still summer time.
        match denver.offset_from_local_datetime(&wall(11, 1, 1, 30)) {
            LocalResult::Ambiguous(first, second) => assert_eq!((hours(first), hours(second)), (-6, -7)),
            other => panic!("{other:?}"),
        }
        // Converting back and forth agrees with itself across the change.
        let before = Utc.with_ymd_and_hms(2026, 11, 1, 7, 30, 0).unwrap().with_timezone(&denver);
        let after = before + Duration::hours(1);
        assert_eq!((before.naive_local(), after.naive_local()), (wall(11, 1, 1, 30), wall(11, 1, 1, 30)));
        assert_eq!(after.with_timezone(&Utc) - before.with_timezone(&Utc), Duration::hours(1));
    }

    /// The rules must not be older than what the Python server used (tzdata 2026): since
    /// November 2026 British Columbia, Alberta and Manitoba no longer set their clocks back.
    #[test]
    fn the_rules_are_recent() {
        for (name, hours) in [("America/Vancouver", -7.0), ("America/Edmonton", -6.0), ("America/Winnipeg", -5.0)] {
            assert_eq!(offset_hours(zone(name), 2026, 12, 1, 12), hours, "{name}");
        }
        // The copy built into the binary, which is what a system without a database gets.
        let built_in = TimeZoneDatabase::bundled().get("America/Vancouver").unwrap();
        let december = jiff::Timestamp::new(Utc.with_ymd_and_hms(2026, 12, 1, 12, 0, 0).unwrap().timestamp(), 0).unwrap();
        assert_eq!(built_in.to_offset(december).seconds(), -7 * 3600);
    }

    #[test]
    fn dates_out_of_range_do_not_panic() {
        let denver = zone("America/Denver");
        for moment in [NaiveDateTime::MIN, NaiveDateTime::MAX] {
            let _ = denver.offset_from_utc_datetime(&moment);
            let _ = denver.offset_from_local_datetime(&moment);
        }
    }
}
