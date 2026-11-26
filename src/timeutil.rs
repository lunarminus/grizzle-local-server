//! Timestamps: the one spelling we store, and a tolerant reader for what chargers send.

use chrono::{DateTime, Duration, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, SecondsFormat, TimeZone, Utc};
use serde_json::Value;

/// The one spelling of a time we store: UTC, milliseconds, trailing Z (so text order is time order).
pub fn iso(moment: DateTime<Utc>) -> String {
    moment.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// OCPP timestamps: ISO 8601, UTC, millisecond precision, trailing Z.
pub fn now_iso() -> String {
    iso(Utc::now())
}

/// A time to the second with `.000Z`, as the schedule times in the API are written.
pub fn iso_seconds(moment: DateTime<Utc>) -> String {
    moment.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.at += 1;
            return true;
        }
        false
    }

    /// Exactly `count` digits as a number.
    fn digits(&mut self, count: usize) -> Option<u32> {
        let slice = self.bytes.get(self.at..self.at + count)?;
        if !slice.iter().all(u8::is_ascii_digit) {
            return None;
        }
        self.at += count;
        Some(slice.iter().fold(0, |sum, digit| sum * 10 + u32::from(digit - b'0')))
    }

    /// `.123456` or `,123`: a fraction of a second in nanoseconds. Digits past the microsecond are dropped.
    fn fraction(&mut self) -> Option<u32> {
        if !(self.eat(b'.') || self.eat(b',')) {
            return Some(0);
        }
        let start = self.at;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.at += 1;
        }
        let digits = &self.bytes[start..self.at];
        if digits.is_empty() {
            return None;
        }
        let mut micros = 0u32;
        for index in 0..6 {
            micros = micros * 10 + digits.get(index).map_or(0, |d| u32::from(d - b'0'));
        }
        Some(micros * 1000)
    }
}

fn parse_date(cursor: &mut Cursor<'_>) -> Option<NaiveDate> {
    let year = cursor.digits(4)?;
    let dashed = cursor.eat(b'-');
    let month = cursor.digits(2)?;
    if dashed && !cursor.eat(b'-') {
        return None;
    }
    let day = cursor.digits(2)?;
    NaiveDate::from_ymd_opt(year as i32, month, day)
}

/// `HH`, `HH:MM`, `HH:MM:SS[.ffffff]` or the same without colons, then an optional offset.
fn parse_time(cursor: &mut Cursor<'_>) -> Option<(NaiveTime, Option<FixedOffset>)> {
    let hour = cursor.digits(2)?;
    let mut minute = 0;
    let mut second = 0;
    let mut nanos = 0;
    let colons = cursor.peek() == Some(b':');
    let more = |cursor: &mut Cursor<'_>| {
        if colons {
            cursor.eat(b':')
        } else {
            cursor.peek().is_some_and(|b| b.is_ascii_digit())
        }
    };
    if more(cursor) {
        minute = cursor.digits(2)?;
        if more(cursor) {
            second = cursor.digits(2)?;
            nanos = cursor.fraction()?;
        }
    }
    let time = NaiveTime::from_hms_nano_opt(hour, minute, second, nanos)?;
    if cursor.done() {
        return Some((time, None));
    }
    if cursor.eat(b'Z') || cursor.eat(b'z') {
        return cursor.done().then_some((time, FixedOffset::east_opt(0)));
    }
    let sign = match cursor.peek()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    cursor.at += 1;
    let hours = cursor.digits(2)?;
    let mut minutes = 0;
    let mut seconds = 0;
    if !cursor.done() {
        let colons = cursor.eat(b':');
        minutes = cursor.digits(2)?;
        if !cursor.done() {
            if colons && !cursor.eat(b':') {
                return None;
            }
            seconds = cursor.digits(2)?;
            cursor.fraction()?;
        }
    }
    if !cursor.done() || hours > 23 || minutes > 59 || seconds > 59 {
        return None;
    }
    let offset = FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60 + seconds) as i32)?;
    Some((time, Some(offset)))
}

/// A UTC time from an ISO 8601 string, or `None`. No offset means UTC.
///
/// Accepts what chargers have been seen to send and what a person types into a URL: a date alone,
/// a `T` or a space before the time, seconds and fractions optional, `Z` or a numeric offset.
pub fn parse_iso(text: &str) -> Option<DateTime<Utc>> {
    if text.is_empty() || text.chars().count() > 40 || !text.is_ascii() {
        return None;
    }
    let mut cursor = Cursor { bytes: text.as_bytes(), at: 0 };
    let date = parse_date(&mut cursor)?;
    if cursor.done() {
        return Some(Utc.from_utc_datetime(&date.and_time(NaiveTime::MIN)));
    }
    cursor.at += 1; // the separator: "T", a space, anything
    let (time, offset) = parse_time(&mut cursor)?;
    let naive = NaiveDateTime::new(date, time);
    let offset = offset.unwrap_or_else(|| FixedOffset::east_opt(0).expect("zero is a valid offset"));
    let utc = naive.checked_sub_offset(offset)?;
    // Years the calendar arithmetic elsewhere can't use are not times anyone means.
    (1..=9999).contains(&chrono::Datelike::year(&utc)).then(|| Utc.from_utc_datetime(&utc))
}

pub fn parse_iso_value(value: &Value) -> Option<DateTime<Utc>> {
    parse_iso(value.as_str()?)
}

/// A charger's timestamp in our spelling; the time now if it is missing, unreadable or implausible.
///
/// A clock that was never set (1970) or a date far in the future would otherwise order sessions
/// wrongly and keep samples from ever being pruned.
pub fn timestamp(value: &Value) -> String {
    let now = Utc::now();
    match parse_iso_value(value) {
        Some(moment) if chrono::Datelike::year(&moment) >= 2000 && moment <= now + Duration::days(1) => iso(moment),
        _ => iso(now),
    }
}

/// Whole seconds from `start` to `stop`, cut towards zero.
pub fn seconds_between(start: DateTime<Utc>, stop: DateTime<Utc>) -> i64 {
    (stop - start).num_seconds()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parsed(text: &str) -> Option<String> {
        parse_iso(text).map(iso)
    }

    #[test]
    fn parse_iso_reads_the_usual_spellings() {
        let expected = Some("2026-11-08T12:30:45.000Z".to_string());
        assert_eq!(parsed("2026-11-08T12:30:45Z"), expected);
        assert_eq!(parsed("2026-11-08T12:30:45.000Z"), expected);
        assert_eq!(parsed("2026-11-08T12:30:45+00:00"), expected);
        assert_eq!(parsed("2026-11-08 12:30:45"), expected);
        assert_eq!(parsed("2026-11-08T05:30:45-07:00"), expected);
        assert_eq!(parsed("2026-11-08T05:30:45-0700"), expected);
        assert_eq!(parsed("20261108T123045Z"), expected);
        assert_eq!(parsed("2026-11-08T12:30:45.123456789Z"), Some("2026-11-08T12:30:45.123Z".to_string()));
        assert_eq!(parsed("2026-11-08"), Some("2026-11-08T00:00:00.000Z".to_string()));
        assert_eq!(parsed("2026-11-08T12:30"), Some("2026-11-08T12:30:00.000Z".to_string()));
    }

    #[test]
    fn parse_iso_is_total() {
        let long = "2026-11-08T12:30:45".repeat(3);
        for bad in [
            "",
            "soon",
            "2026-13-01T00:00:00Z",
            "2026-11-08T25:00:00Z",
            "2026-11-08T12:30:45+99:00",
            "2026-11-08T12:30:45Zjunk",
            "2026-11-08T",
            "0001-01-01T00:00:00+23:59",
            "9999-12-31T23:59:59-23:59",
            "２０２６-11-08",
            long.as_str(),
        ] {
            assert_eq!(parse_iso(bad), None, "{bad:?}");
        }
        for value in [json!(null), json!(5), json!(["2026-11-08"]), json!({"a": 1}), json!(true)] {
            assert_eq!(parse_iso_value(&value), None);
        }
    }

    #[test]
    fn charger_timestamps_are_normalised_and_sanity_checked() {
        assert_eq!(timestamp(&json!("2026-11-08T05:30:45-07:00")), "2026-11-08T12:30:45.000Z");
        let now = Utc::now();
        for implausible in [json!("1970-01-01T00:00:05Z"), json!("2999-01-01T00:00:00Z"), json!(null), json!("x")] {
            let stamp = parse_iso(&timestamp(&implausible)).unwrap();
            assert!((stamp - now).num_seconds().abs() < 5, "{implausible}");
        }
    }
}
