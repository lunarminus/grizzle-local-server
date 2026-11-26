//! Charging windows and rate zones, in the cloud's `pricesByZone` format.
//!
//! Each zone is an object with `startHours`/`startMinutes`/`endHours`/`endMinutes` (optionally a
//! second range `startHours2`…), `allDay`, `days` (0=Sunday … 6=Saturday) and `connectorId`
//! (0 = every connector). A zone with `isSchedule` is a plain charging window; one with `priceKW`
//! is a rate zone. Either acts as a charging window when `scheduleEnabled` is true. Times are in
//! the station's local timezone.
//!
//! `days` are calendar days. A range that wraps past midnight (20:00-06:00) covers the small hours
//! and the late evening of each of those days; it does not run from a listed day into the next.
//!
//! Our own extension, `holidays`, says how a zone treats statutory holidays: `"same"` (default: a
//! holiday is just its weekday), `"skip"` (never on a holiday), `"also"` (its days plus every
//! holiday) or `"only"` (holidays only; `days` is ignored).

use std::collections::BTreeSet;

use chrono::{
    DateTime, Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, Offset, TimeZone, Timelike, Utc,
};
use serde_json::Value;

use crate::value::{char_len, get, parse_float, truthy, whole_number, Object};
use crate::zone::Tz;

pub type Zone = Object;
/// Is this calendar day a statutory holiday?
pub type HolidayCheck<'a> = &'a dyn Fn(NaiveDate) -> bool;

pub const MINUTES_PER_DAY: i64 = 24 * 60;
pub const HOLIDAY_MODES: [&str; 4] = ["same", "skip", "also", "only"];
pub const MAX_NAME_LENGTH: usize = 100;
/// Fields of the cloud's format we don't interpret but hand back unchanged.
pub const MAX_EXTRA_KEYS: usize = 32;

// --- validation -----------------------------------------------------------------------------
//
// Zones arrive from the REST API and are evaluated on every controller tick, forever. Anything
// stored here must therefore be something the functions below can evaluate.

const TIME_KEYS: [&str; 8] = [
    "startHours",
    "startMinutes",
    "endHours",
    "endMinutes",
    "startHours2",
    "startMinutes2",
    "endHours2",
    "endMinutes2",
];
const FLAG_KEYS: [&str; 4] = ["allDay", "isSchedule", "scheduleEnabled", "useSeason"];
const PRICE_KEYS: [&str; 2] = ["priceKW", "priceKWSummer"];

/// A zone's `_id` as text: 1-64 letters, digits or `_ . : -`. A number is taken as its digits.
pub fn zone_id(value: &Value) -> Result<String, String> {
    let text = match value {
        Value::Number(number) if number.is_i64() || number.is_u64() => number.to_string(),
        Value::String(text) => text.clone(),
        _ => String::new(),
    };
    let valid = (1..=64).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'));
    if valid {
        Ok(text)
    } else {
        Err("_id must be 1-64 letters, digits or _ . : -".to_string())
    }
}

/// An integer in `lo..=hi`; null means 0. Integral floats and digit strings are accepted.
fn whole(key: &str, value: &Value, lo: i64, hi: i64) -> Result<i64, String> {
    let number = match value {
        Value::Null => return Ok(0),
        Value::Number(_) => whole_number(value),
        Value::String(text) => {
            let text = text.trim();
            (!text.is_empty() && text.len() <= 4 && text.bytes().all(|b| b.is_ascii_digit()))
                .then(|| text.parse().ok())
                .flatten()
        }
        _ => None,
    };
    number.filter(|n| (lo..=hi).contains(n)).ok_or_else(|| format!("{key} must be a whole number from {lo} to {hi}"))
}

/// A finite number (numeric text is accepted), or `None` for null and "".
fn amount(key: &str, value: &Value) -> Result<Option<f64>, String> {
    let number = match value {
        Value::Null => return Ok(None),
        Value::String(text) if text.is_empty() => return Ok(None),
        Value::String(text) if text.len() <= 32 => parse_float(text),
        Value::Number(number) => number.as_f64(),
        _ => None,
    };
    match number {
        None => Err(format!("{key} must be a number")),
        Some(number) if !number.is_finite() => Err(format!("{key} must be a finite number")),
        Some(number) => Ok(Some(number)),
    }
}

/// Is this small enough, and plain enough, to store as a field we don't interpret?
fn passthrough(value: &Value) -> bool {
    match value {
        Value::String(text) => char_len(text) <= 200,
        other => other.to_string().len() <= 256,
    }
}

fn flag(key: &str, value: &Value) -> Result<bool, String> {
    match value {
        Value::Null => Ok(false),
        Value::Bool(flag) => Ok(*flag),
        Value::Number(number) if number.as_f64() == Some(0.0) => Ok(false),
        Value::Number(number) if number.as_f64() == Some(1.0) => Ok(true),
        _ => Err(format!("{key} must be true or false")),
    }
}

/// Validate a zone from the API (or from an old state file). The error is a readable message.
///
/// Only the keys present are returned, typed the way the evaluation below expects; `_id` is left
/// to the caller. Fields of the cloud's format that we don't interpret survive if they are small.
pub fn normalize_zone(raw: &Value, max_connector: i64, max_current: i64) -> Result<Zone, String> {
    let raw = raw.as_object().ok_or_else(|| "price object required".to_string())?;
    let mut zone = Zone::new();
    let mut extras = 0;
    for (key, value) in raw {
        let key = key.as_str();
        let clean = if key == "_id" {
            continue;
        } else if key == "name" {
            let name = match value {
                Value::Null => "",
                Value::String(name) => name.trim(),
                _ => return Err("name must be text".to_string()),
            };
            if char_len(name) > MAX_NAME_LENGTH {
                return Err(format!("name can't be longer than {MAX_NAME_LENGTH} characters"));
            }
            Value::from(name)
        } else if FLAG_KEYS.contains(&key) {
            Value::Bool(flag(key, value)?)
        } else if TIME_KEYS.contains(&key) {
            Value::from(whole(key, value, 0, if key.contains("Hours") { 24 } else { 59 })?)
        } else if key == "days" {
            let days = match value {
                Value::Null => &Vec::new(),
                Value::Array(days) if days.len() <= 64 && !days.iter().any(Value::is_null) => days,
                _ => return Err("days must be a list of numbers, 0 (Sunday) to 6 (Saturday)".to_string()),
            };
            let days: BTreeSet<i64> = days.iter().map(|day| whole("days", day, 0, 6)).collect::<Result<_, _>>()?;
            Value::from(days.into_iter().collect::<Vec<_>>())
        } else if key == "connectorId" {
            Value::from(whole(key, value, 0, max_connector)?)
        } else if key == "currentLimit" {
            match amount(key, value)?.filter(|limit| *limit != 0.0) {
                None => Value::Null, // "no limit of its own"
                Some(limit) if (1.0..=max_current as f64).contains(&limit) => crate::value::number(limit),
                Some(_) => return Err(format!("currentLimit must be between 1 and {max_current} A")),
            }
        } else if PRICE_KEYS.contains(&key) {
            match amount(key, value)? {
                Some(price) if price < 0.0 => return Err(format!("{key} can't be negative")),
                price => crate::value::opt_number(price),
            }
        } else if key == "holidays" {
            match value {
                Value::Null => Value::Null,
                Value::String(mode) if HOLIDAY_MODES.contains(&mode.as_str()) => value.clone(),
                _ => return Err("holidays must be one of ('same', 'skip', 'also', 'only')".to_string()),
            }
        } else {
            if char_len(key) > 40 || extras >= MAX_EXTRA_KEYS || !passthrough(value) {
                continue;
            }
            extras += 1;
            value.clone()
        };
        zone.insert(key.to_string(), clean);
    }
    for suffix in ["", "2"] {
        for edge in ["start", "end"] {
            let hours = get(&zone, &format!("{edge}Hours{suffix}")).as_i64();
            if hours == Some(24) && truthy(get(&zone, &format!("{edge}Minutes{suffix}"))) {
                return Err("a time can't be later than 24:00".to_string());
            }
        }
    }
    Ok(zone)
}

// --- evaluation -----------------------------------------------------------------------------

fn int(zone: &Zone, key: &str) -> i64 {
    whole_number(get(zone, key)).unwrap_or(0)
}

fn holiday_mode(zone: &Zone) -> &str {
    get(zone, "holidays").as_str().filter(|mode| !mode.is_empty()).unwrap_or("same")
}

/// Minute-of-day ranges. `start == end` (and allDay) mean the whole day.
fn ranges(zone: &Zone) -> Vec<(i64, i64)> {
    if truthy(get(zone, "allDay")) {
        return vec![(0, MINUTES_PER_DAY)];
    }
    let mut ranges = Vec::with_capacity(2);
    for suffix in ["", "2"] {
        let keys = ["startHours", "startMinutes", "endHours", "endMinutes"].map(|key| format!("{key}{suffix}"));
        if !suffix.is_empty() && !keys.iter().any(|key| truthy(get(zone, key))) {
            continue;
        }
        let [sh, sm, eh, em] = keys.map(|key| int(zone, &key));
        let (mut start, mut end) = (sh * 60 + sm, eh * 60 + em);
        if start == end {
            (start, end) = (0, MINUTES_PER_DAY);
        }
        ranges.push((start, end));
    }
    ranges
}

/// 0=Sunday … 6=Saturday, matching the app.
fn weekday(day: NaiveDate) -> i64 {
    i64::from(day.weekday().num_days_from_sunday())
}

/// Does the zone apply on this calendar day (before looking at the time of day)?
fn eligible(zone: &Zone, day: NaiveDate, is_holiday: Option<HolidayCheck<'_>>) -> bool {
    let mode = holiday_mode(zone);
    let holiday = mode != "same" && is_holiday.is_some_and(|check| check(day));
    if mode == "only" {
        return holiday;
    }
    let regular = match get(zone, "days").as_array().filter(|days| !days.is_empty()) {
        Some(days) => days.iter().any(|d| whole_number(d) == Some(weekday(day))),
        None => true,
    };
    match mode {
        "skip" => regular && !holiday,
        "also" => regular || holiday,
        _ => regular,
    }
}

pub fn applies_to(zone: &Zone, connector_id: i64) -> bool {
    let zone_connector = int(zone, "connectorId");
    zone_connector == 0 || connector_id == 0 || zone_connector == connector_id
}

/// The offset a wall-clock reading has in `tz`. A reading that occurs twice has two; `later` picks
/// the second. One that never occurs (the clocks skipped it) is read with the offset in force
/// before the change, or after it for `later`.
fn wall_offset(tz: Tz, wall: NaiveDateTime, later: bool) -> i32 {
    match tz.offset_from_local_datetime(&wall) {
        LocalResult::Single(offset) => offset.fix().local_minus_utc(),
        LocalResult::Ambiguous(first, second) => if later { second } else { first }.fix().local_minus_utc(),
        LocalResult::None => {
            // Far enough to either side to be clear of the change, whatever the zone's offset.
            let reference = if later { wall + Duration::hours(26) } else { wall - Duration::hours(26) };
            tz.offset_from_utc_datetime(&reference).fix().local_minus_utc()
        }
    }
}

/// The instant a wall-clock reading stands for: the first, if it happens twice (`later`: the
/// second); the moment the clocks changed, if they skipped it.
pub fn wall_instant(tz: Tz, wall: NaiveDateTime, later: bool) -> DateTime<Utc> {
    Utc.from_utc_datetime(&(wall - Duration::seconds(i64::from(wall_offset(tz, wall, later)))))
}

/// The moment whose wall-clock reading decides what applies at `now`: normally `now` itself.
///
/// On the night the clocks go back, an hour of wall-clock time happens twice. Read naively, a
/// window that starts at 01:30 would switch on, off again for the second 01:00-01:30, and back
/// on: a charger told to stop and to start again half an hour later. So the second time round is
/// read as the moment the repeat ends, and whatever the first pass ended with carries through.
fn wall_clock(now: DateTime<Tz>) -> NaiveDateTime {
    let tz = now.timezone();
    let wall = now.naive_local();
    let second_pass = match tz.offset_from_local_datetime(&wall) {
        LocalResult::Ambiguous(first, _) => first.fix().local_minus_utc() != now.offset().fix().local_minus_utc(),
        _ => false,
    };
    if !second_pass {
        return wall;
    }
    let mut instant = now.with_timezone(&Utc).with_second(0).and_then(|t| t.with_nanosecond(0)).unwrap_or_default();
    for _ in 0..3 * 60 {
        instant += Duration::minutes(1);
        let local = instant.with_timezone(&tz).naive_local();
        if matches!(tz.offset_from_local_datetime(&local), LocalResult::Single(_)) {
            return local;
        }
    }
    wall
}

/// Is `now` (in the station's zone) inside this zone?
///
/// Days are calendar days: a range that wraps past midnight, say 20:00-06:00, covers 00:00-06:00
/// and 20:00-24:00 of every day the zone applies to. It does not start on a listed day and spill
/// into the next one, so "weekdays 20:00-06:00" includes Monday's small hours and stops at
/// midnight on Friday. That is how utility rate plans (and the Grizzl-E app) read it.
pub fn zone_active(zone: &Zone, now: DateTime<Tz>, is_holiday: Option<HolidayCheck<'_>>) -> bool {
    let wall = wall_clock(now);
    if !eligible(zone, wall.date(), is_holiday) {
        return false;
    }
    let minute = f64::from(wall.hour() * 60 + wall.minute()) + f64::from(wall.second()) / 60.0;
    ranges(zone).into_iter().any(|(start, end)| {
        let (start, end) = (start as f64, end as f64);
        if start < end {
            start <= minute && minute < end
        } else {
            minute >= start || minute < end // wraps past midnight
        }
    })
}

/// The enabled charging window the connector is inside right now, if any.
pub fn charging_allowed<'z>(
    zones: impl IntoIterator<Item = &'z Zone>,
    now: DateTime<Tz>,
    connector_id: i64,
    is_holiday: Option<HolidayCheck<'_>>,
) -> Option<&'z Zone> {
    zones.into_iter().find(|zone| {
        truthy(get(zone, "scheduleEnabled")) && applies_to(zone, connector_id) && zone_active(zone, now, is_holiday)
    })
}

/// Electricity price per kWh: the flat holiday price, else the matching rate zone, else the base rate.
pub fn price_now(
    zones: &[Zone],
    now: DateTime<Tz>,
    base_price: Option<f64>,
    is_holiday: Option<HolidayCheck<'_>>,
    holiday_price: Option<f64>,
) -> Option<f64> {
    if let (Some(price), Some(check)) = (holiday_price, is_holiday) {
        if check(now.date_naive()) {
            return Some(price);
        }
    }
    for zone in zones {
        let Some(price) = get(zone, "priceKW").as_f64() else { continue };
        if !truthy(get(zone, "isSchedule")) && zone_active(zone, now, is_holiday) {
            return Some(price);
        }
    }
    base_price
}

/// When the connector's "allowed by schedule" state next flips, or `None` if it never does.
pub fn next_change(
    zones: &[Zone],
    now: DateTime<Tz>,
    connector_id: i64,
    is_holiday: Option<HolidayCheck<'_>>,
) -> Option<DateTime<Tz>> {
    let enabled: Vec<&Zone> =
        zones.iter().filter(|z| truthy(get(z, "scheduleEnabled")) && applies_to(z, connector_id)).collect();
    if enabled.is_empty() {
        return None;
    }
    let mut horizon_days = 8;
    if is_holiday.is_some() && enabled.iter().any(|zone| holiday_mode(zone) != "same") {
        // The next day a holiday rule lets a window apply (or stops it applying) can be most of a
        // year away: a holidays-only window in a country with one holiday left this year, a weekly
        // window whose next few days all fall on holidays.
        horizon_days = 370;
    }
    let tz = now.timezone();
    let allowed =
        |moment: DateTime<Tz>| charging_allowed(enabled.iter().copied(), moment, connector_id, is_holiday).is_some();
    let current = allowed(now);
    let midnight = now.date_naive().and_time(NaiveTime::MIN);
    let zone_ranges: Vec<Vec<(i64, i64)>> = enabled.iter().map(|zone| ranges(zone)).collect();
    let mut walls: BTreeSet<NaiveDateTime> = BTreeSet::new();
    for offset in -1..=horizon_days {
        let day = midnight + Duration::days(offset);
        walls.insert(day); // a new calendar day can change whether a zone applies at all
        for (start, end) in zone_ranges.iter().flatten() {
            walls.insert(day + Duration::minutes(*start));
            walls.insert(day + Duration::minutes(*end));
        }
        if wall_offset(tz, day, false) != wall_offset(tz, day + Duration::days(1), false) {
            // The clocks change today, so the wall clock skips or repeats part of an hour and the
            // state can flip at the change itself, not only at a boundary someone typed in.
            walls.extend((0..49).map(|step| day + Duration::minutes(30 * step)));
        }
    }
    // Compare as instants. A wall-clock time that occurs twice is two instants (both are
    // candidates), and one that never occurs still stands for a real instant.
    let now_utc = now.with_timezone(&Utc);
    let instants: BTreeSet<DateTime<Utc>> = walls
        .iter()
        .flat_map(|wall| [wall_instant(tz, *wall, false), wall_instant(tz, *wall, true)])
        .filter(|instant| *instant > now_utc)
        .collect();
    instants.into_iter().map(|instant| instant.with_timezone(&tz)).find(|moment| allowed(*moment) != current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn zone(value: Value) -> Zone {
        value.as_object().unwrap().clone()
    }

    fn at(tz: Tz, y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Tz> {
        tz.with_ymd_and_hms(y, mo, d, h, mi, 0).earliest().unwrap()
    }

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Tz> {
        at(Tz::UTC, y, mo, d, h, mi)
    }

    fn night() -> Zone {
        zone(json!({"_id": "night", "isSchedule": true, "scheduleEnabled": true,
            "startHours": 22, "startMinutes": 0, "endHours": 6, "endMinutes": 0, "days": [1, 2, 3, 4, 5]}))
    }

    #[test]
    fn window_crossing_midnight() {
        let zone = night();
        // 2026-11-09 is a Monday.
        assert!(zone_active(&zone, utc(2026, 11, 9, 23, 0), None));
        assert!(zone_active(&zone, utc(2026, 11, 10, 5, 59), None));
        assert!(!zone_active(&zone, utc(2026, 11, 10, 6, 0), None));
        assert!(!zone_active(&zone, utc(2026, 11, 10, 12, 0), None));
    }

    #[test]
    fn overnight_range_is_judged_per_calendar_day() {
        let zone = night();
        // Monday's small hours belong to Monday; Saturday's do not belong to Friday.
        assert!(zone_active(&zone, utc(2026, 11, 9, 3, 0), None));
        assert!(zone_active(&zone, utc(2026, 11, 13, 23, 30), None)); // Friday evening
        assert!(!zone_active(&zone, utc(2026, 11, 14, 3, 0), None)); // Saturday small hours
        assert!(!zone_active(&zone, utc(2026, 11, 8, 23, 0), None)); // Sunday evening
    }

    #[test]
    fn days_and_connector() {
        let mut zone = night();
        zone.insert("connectorId".into(), json!(2));
        let zones = vec![zone];
        let monday_night = utc(2026, 11, 9, 23, 0);
        assert!(charging_allowed(&zones, monday_night, 2, None).is_some());
        assert!(charging_allowed(&zones, monday_night, 1, None).is_none());
        assert!(charging_allowed(&zones, monday_night, 0, None).is_some());
        assert!(charging_allowed(&zones, utc(2026, 11, 8, 23, 0), 2, None).is_none()); // Sunday
        let mut disabled = zones.clone();
        disabled[0].insert("scheduleEnabled".into(), json!(false));
        assert!(charging_allowed(&disabled, monday_night, 2, None).is_none());
    }

    #[test]
    fn all_day_and_second_range() {
        let all_day = zone(json!({"allDay": true, "days": [0]}));
        assert!(zone_active(&all_day, utc(2026, 11, 8, 0, 0), None));
        assert!(zone_active(&all_day, utc(2026, 11, 8, 23, 59), None));
        assert!(!zone_active(&all_day, utc(2026, 11, 9, 0, 0), None));
        let two = zone(json!({"startHours": 6, "endHours": 8, "startHours2": 18, "endHours2": 20, "endMinutes2": 30}));
        assert!(zone_active(&two, utc(2026, 11, 9, 7, 0), None));
        assert!(!zone_active(&two, utc(2026, 11, 9, 12, 0), None));
        assert!(zone_active(&two, utc(2026, 11, 9, 20, 29), None));
        assert!(!zone_active(&two, utc(2026, 11, 9, 20, 30), None));
        // start == end means the whole day
        let same = zone(json!({"startHours": 8, "endHours": 8}));
        assert!(zone_active(&same, utc(2026, 11, 9, 3, 0), None));
    }

    #[test]
    fn next_change_finds_the_next_boundary() {
        let zones = vec![night()];
        // Monday noon: the window opens at 22:00.
        assert_eq!(next_change(&zones, utc(2026, 11, 9, 12, 0), 1, None), Some(utc(2026, 11, 9, 22, 0)));
        // Monday 23:00: inside; the calendar day ends at midnight but Tuesday's small hours continue.
        assert_eq!(next_change(&zones, utc(2026, 11, 9, 23, 0), 1, None), Some(utc(2026, 11, 10, 6, 0)));
        // Friday 23:00: Saturday is not a listed day, so it stops at midnight.
        assert_eq!(next_change(&zones, utc(2026, 11, 13, 23, 0), 1, None), Some(utc(2026, 11, 14, 0, 0)));
        // Saturday noon: next is Monday 00:00 (Monday's small hours).
        assert_eq!(next_change(&zones, utc(2026, 11, 14, 12, 0), 1, None), Some(utc(2026, 11, 16, 0, 0)));
        assert_eq!(next_change(&[], utc(2026, 11, 9, 12, 0), 1, None), None);
        let always = vec![zone(json!({"scheduleEnabled": true, "allDay": true}))];
        assert_eq!(next_change(&always, utc(2026, 11, 9, 12, 0), 1, None), None);
    }

    #[test]
    fn price_now_prefers_rate_zones_over_the_base_price() {
        let zones = vec![
            zone(json!({"isSchedule": true, "scheduleEnabled": true, "allDay": true, "priceKW": 9})),
            zone(json!({"priceKW": 0.30, "startHours": 16, "endHours": 21, "days": [1, 2, 3, 4, 5]})),
            zone(json!({"priceKW": "soon", "allDay": true})),
        ];
        assert_eq!(price_now(&zones, utc(2026, 11, 9, 17, 0), Some(0.10), None, None), Some(0.30));
        assert_eq!(price_now(&zones, utc(2026, 11, 9, 12, 0), Some(0.10), None, None), Some(0.10));
        assert_eq!(price_now(&zones, utc(2026, 11, 8, 17, 0), None, None, None), None);
    }

    #[test]
    fn holiday_modes() {
        let holiday: HolidayCheck<'_> = &|day| day == NaiveDate::from_ymd_opt(2026, 11, 11).unwrap();
        let on = utc(2026, 11, 11, 12, 0); // a Wednesday, and the holiday
        let off = utc(2026, 11, 12, 12, 0);
        let weekdays = |mode: &str| zone(json!({"allDay": true, "days": [1, 2, 3, 4, 5], "holidays": mode}));
        let weekend = |mode: &str| zone(json!({"allDay": true, "days": [0, 6], "holidays": mode}));
        assert!(zone_active(&weekdays("same"), on, Some(holiday)));
        assert!(!zone_active(&weekdays("skip"), on, Some(holiday)));
        assert!(zone_active(&weekdays("skip"), off, Some(holiday)));
        assert!(zone_active(&weekend("also"), on, Some(holiday)));
        assert!(!zone_active(&weekend("also"), off, Some(holiday)));
        assert!(zone_active(&weekend("only"), on, Some(holiday)));
        assert!(!zone_active(&weekdays("only"), off, Some(holiday)));
        // Without a calendar every mode but "only" falls back to the weekdays.
        assert!(zone_active(&weekdays("skip"), on, None));
        assert!(!zone_active(&weekdays("only"), on, None));
    }

    #[test]
    fn overnight_window_skips_the_holiday_as_a_calendar_day() {
        let holiday: HolidayCheck<'_> = &|day| day == NaiveDate::from_ymd_opt(2026, 11, 11).unwrap();
        let mut zone = night();
        zone.insert("holidays".into(), json!("skip"));
        assert!(zone_active(&zone, utc(2026, 11, 10, 23, 0), Some(holiday)));
        assert!(!zone_active(&zone, utc(2026, 11, 11, 3, 0), Some(holiday)));
        assert!(!zone_active(&zone, utc(2026, 11, 11, 23, 0), Some(holiday)));
        assert!(zone_active(&zone, utc(2026, 11, 12, 3, 0), Some(holiday)));
    }

    #[test]
    fn next_change_looks_far_enough_ahead_for_holiday_rules() {
        let christmas = NaiveDate::from_ymd_opt(2027, 12, 25).unwrap();
        let holiday: HolidayCheck<'_> = &|day| day == christmas;
        let only = vec![zone(json!({"scheduleEnabled": true, "allDay": true, "holidays": "only"}))];
        // From 2027-01-05 the only holiday is most of a year away.
        assert_eq!(next_change(&only, utc(2027, 1, 5, 12, 0), 1, Some(holiday)), Some(utc(2027, 12, 25, 0, 0)));
        assert_eq!(next_change(&only, utc(2027, 12, 25, 12, 0), 1, Some(holiday)), Some(utc(2027, 12, 26, 0, 0)));
        // Without holiday rules the look-ahead stays a week.
        let never = vec![zone(json!({"scheduleEnabled": true, "allDay": true, "holidays": "only"}))];
        assert_eq!(next_change(&never, utc(2027, 1, 5, 12, 0), 1, None), None);
    }

    #[test]
    fn next_change_in_the_hour_that_does_not_exist() {
        // America/Denver, 2026-03-08: 02:00 -> 03:00. A window "02:30-04:00" starts at an instant
        // the wall clock never shows.
        let tz: Tz = "America/Denver".parse().unwrap();
        let zones = vec![zone(json!({"scheduleEnabled": true, "startHours": 2, "startMinutes": 30, "endHours": 4}))];
        let before = at(tz, 2026, 3, 8, 1, 0);
        let change = next_change(&zones, before, 1, None).unwrap();
        // The state flips at the change itself: 03:00 MDT is already past 02:30.
        assert_eq!(change, at(tz, 2026, 3, 8, 3, 0));
        assert!(charging_allowed(&zones, change, 1, None).is_some());
        assert_eq!(next_change(&zones, change, 1, None), Some(at(tz, 2026, 3, 8, 4, 0)));
    }

    #[test]
    fn a_window_does_not_pause_when_the_clocks_go_back() {
        // America/Denver, 2026-11-01: 02:00 MDT -> 01:00 MST. 01:30-05:00 must not switch off for
        // the second 01:00-01:30.
        let tz: Tz = "America/Denver".parse().unwrap();
        let zone = zone(json!({"scheduleEnabled": true, "startHours": 1, "startMinutes": 30, "endHours": 5}));
        let first_0115 = tz.with_ymd_and_hms(2026, 11, 1, 1, 15, 0).earliest().unwrap();
        let first_0145 = tz.with_ymd_and_hms(2026, 11, 1, 1, 45, 0).earliest().unwrap();
        let second_0115 = tz.with_ymd_and_hms(2026, 11, 1, 1, 15, 0).latest().unwrap();
        let second_0145 = tz.with_ymd_and_hms(2026, 11, 1, 1, 45, 0).latest().unwrap();
        assert!(!zone_active(&zone, first_0115, None));
        assert!(zone_active(&zone, first_0145, None));
        assert!(zone_active(&zone, second_0115, None), "the repeat carries on what the first pass ended with");
        assert!(zone_active(&zone, second_0145, None));
        let zones = vec![zone];
        assert_eq!(next_change(&zones, first_0115, 1, None), Some(first_0145 - Duration::minutes(15)));
        assert_eq!(next_change(&zones, first_0145, 1, None), Some(at(tz, 2026, 11, 1, 5, 0)));
    }

    /// Some zones change their clocks at midnight, so the day starts at 01:00: "since midnight"
    /// is then "since the clocks changed", not a time that cannot be worked out.
    #[test]
    fn a_wall_clock_reading_is_an_instant_even_when_the_clocks_skipped_or_repeated_it() {
        let wall = |y: i32, mo: u32, d: u32, h: u32, mi: u32| {
            NaiveDate::from_ymd_opt(y, mo, d).unwrap().and_hms_opt(h, mi, 0).unwrap()
        };
        let instant = |y: i32, mo: u32, d: u32, h: u32, mi: u32| Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap();
        let santiago: Tz = "America/Santiago".parse().unwrap();
        assert_eq!(wall_instant(santiago, wall(2026, 9, 6, 0, 0), false), instant(2026, 9, 6, 4, 0));
        assert_eq!(wall_instant(santiago, wall(2026, 9, 5, 0, 0), false), instant(2026, 9, 5, 4, 0));
        assert_eq!(wall_instant(santiago, wall(2026, 9, 7, 0, 0), false), instant(2026, 9, 7, 3, 0));
        let cairo: Tz = "Africa/Cairo".parse().unwrap();
        assert_eq!(wall_instant(cairo, wall(2026, 4, 24, 0, 0), false), instant(2026, 4, 23, 22, 0));
        let denver: Tz = "America/Denver".parse().unwrap();
        assert_eq!(wall_instant(denver, wall(2026, 3, 8, 2, 30), false), instant(2026, 3, 8, 9, 30));
        assert_eq!(wall_instant(denver, wall(2026, 11, 1, 1, 30), false), instant(2026, 11, 1, 7, 30));
        assert_eq!(wall_instant(denver, wall(2026, 11, 1, 1, 30), true), instant(2026, 11, 1, 8, 30));
    }

    /// Step through four days minute by minute and compare every answer with a plain scan.
    fn check_against_scan(tz: Tz, start: DateTime<Tz>, zones: &[Zone]) {
        let minutes = 4 * 24 * 60;
        let state: Vec<bool> = (0..=minutes + 9 * 24 * 60)
            .map(|m| {
                charging_allowed(zones, (start.with_timezone(&Utc) + Duration::minutes(m)).with_timezone(&tz), 1, None)
                    .is_some()
            })
            .collect();
        for m in (0..minutes).step_by(7) {
            let now = (start.with_timezone(&Utc) + Duration::minutes(m)).with_timezone(&tz);
            let expected = (m as usize + 1..state.len()).find(|i| state[*i] != state[m as usize]);
            let got = next_change(zones, now, 1, None)
                .map(|t| (t.with_timezone(&Utc) - start.with_timezone(&Utc)).num_minutes());
            assert_eq!(got, expected.map(|i| i as i64), "at {now}");
        }
    }

    #[test]
    fn next_change_agrees_with_a_minute_by_minute_scan() {
        let tz: Tz = "America/Denver".parse().unwrap();
        let zones = vec![
            zone(
                json!({"scheduleEnabled": true, "startHours": 1, "startMinutes": 30, "endHours": 2, "endMinutes": 30}),
            ),
            zone(json!({"scheduleEnabled": true, "startHours": 22, "endHours": 1, "endMinutes": 15, "days": [0, 6]})),
        ];
        check_against_scan(tz, at(tz, 2026, 3, 6, 12, 0), &zones); // spring forward
        check_against_scan(tz, at(tz, 2026, 10, 30, 12, 0), &zones); // fall back
        check_against_scan(tz, at(tz, 2026, 6, 10, 12, 0), &zones); // ordinary days
        let sydney: Tz = "Australia/Lord_Howe".parse().unwrap(); // a half-hour change
        check_against_scan(sydney, at(sydney, 2026, 4, 3, 12, 0), &zones);
        check_against_scan(sydney, at(sydney, 2026, 10, 2, 12, 0), &zones);
    }

    #[test]
    fn normalize_zone_keeps_only_what_can_be_evaluated() {
        let clean = normalize_zone(
            &json!({"_id": "x", "name": "  Night  ", "startHours": "22", "startMinutes": 0.0, "endHours": 6,
                "days": [5, "1", 1, 3.0], "allDay": 0, "isSchedule": 1, "connectorId": null, "currentLimit": "16",
                "priceKW": "0.12", "holidays": "skip", "color": "#fff", "nested": {"a": [1, 2]}}),
            8,
            100,
        )
        .unwrap();
        assert_eq!(
            Value::Object(clean),
            json!({"name": "Night", "startHours": 22, "startMinutes": 0, "endHours": 6, "days": [1, 3, 5],
                "allDay": false, "isSchedule": true, "connectorId": 0, "currentLimit": 16, "priceKW": 0.12,
                "holidays": "skip", "color": "#fff", "nested": {"a": [1, 2]}})
        );
        let bad = [
            json!("zone"),
            json!({"startHours": "soon"}),
            json!({"startHours": 25}),
            json!({"startMinutes": 60}),
            json!({"endHours": 24, "endMinutes": 1}),
            json!({"startHours": true}),
            json!({"startHours": 1.5}),
            json!({"startHours": "12345"}),
            json!({"days": [7]}),
            json!({"days": "weekdays"}),
            json!({"days": [null]}),
            json!({"days": [-1]}),
            json!({"allDay": "yes"}),
            json!({"allDay": 2}),
            json!({"connectorId": 9}),
            json!({"currentLimit": 101}),
            json!({"currentLimit": -5}),
            json!({"currentLimit": "lots"}),
            json!({"currentLimit": [16]}),
            json!({"priceKW": -0.1}),
            json!({"priceKW": "NaN"}),
            json!({"priceKW": "inf"}),
            json!({"priceKW": true}),
            json!({"holidays": "never"}),
            json!({"holidays": 1}),
            json!({"name": 5}),
            json!({"name": "x".repeat(101)}),
        ];
        for zone in bad {
            assert!(normalize_zone(&zone, 8, 100).is_err(), "{zone}");
        }
        // 24:00 is a time; a limit of 0 means none; unknown fields survive only if small.
        let edge = normalize_zone(
            &json!({"endHours": 24, "endMinutes": 0, "currentLimit": 0, "priceKW": "", "big": "x".repeat(201),
                "deep": {"k": "y".repeat(300)}, "holidays": null, "name": null}),
            8,
            100,
        )
        .unwrap();
        assert_eq!(
            Value::Object(edge),
            json!({"endHours": 24, "endMinutes": 0, "currentLimit": null, "priceKW": null, "holidays": null, "name": ""})
        );
        let many: Zone = (0..50).map(|i| (format!("extra{i}"), json!(i))).collect();
        assert_eq!(normalize_zone(&Value::Object(many), 8, 100).unwrap().len(), MAX_EXTRA_KEYS);
    }

    #[test]
    fn zone_ids() {
        assert_eq!(zone_id(&json!("abc-1.2:3_4")).unwrap(), "abc-1.2:3_4");
        assert_eq!(zone_id(&json!(42)).unwrap(), "42");
        for bad in [json!(""), json!("a b"), json!("a/b"), json!(true), json!(null), json!(1.5), json!("x".repeat(65))]
        {
            assert!(zone_id(&bad).is_err(), "{bad}");
        }
    }
}
