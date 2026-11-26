//! Statutory holidays for schedules and rates.
//!
//! The dates are not computed here. `tools/gen_holidays.py` works them out with the Python
//! `holidays` package, for every country and subdivision (state, province, …) it supports, and
//! writes them into `holidays.bin`, which is built into this binary: 250 countries, with and
//! without observed days, for the years in [`first_year`]..=[`last_year`]. The file's layout is
//! described at the top of that script. Nothing is read from disk or the network at run time, and
//! a country's table is only unpacked when a station uses it.
//!
//! A station keeps its own settings:
//!
//! ```json
//! {"enabled": true, "country": "US", "subdivision": "ID", "observed": true,
//!  "priceKW": null, "excludedNames": [], "extraDates": [{"date": "2026-07-03", "name": "Shutdown"}]}
//! ```
//!
//! `excludedNames` drops holidays by name (so it holds across years, and also drops the observed
//! day of that holiday); `extraDates` adds one-off dates. `priceKW` is an optional flat price that
//! replaces every rate zone on a holiday.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{Datelike, Duration, NaiveDate};
use serde_json::{json, Value};

use crate::value::{clip, get, parse_float, to_text, truthy, Object};

static DATA: &[u8] = include_bytes!("holidays.bin");

pub const MAX_EXCLUDED_NAMES: usize = 500;
pub const MAX_EXTRA_DATES: usize = 500;
/// Unpacked calendars kept in memory: (country, subdivision, observed, year) each.
const CACHE_SIZE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subdivision {
    pub code: String,
    pub name: String,
}

#[derive(Debug)]
pub struct Country {
    pub code: String,
    pub subdivisions: Vec<Subdivision>,
    /// This country's compressed table within the data.
    blob: &'static [u8],
}

struct Index {
    first_year: i32,
    last_year: i32,
    version: String,
    countries: Vec<Country>,
}

/// One day of a calendar. `key` is the holiday's own name, which an observed day shares with the
/// holiday it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub day: NaiveDate,
    pub name: Arc<str>,
    pub key: Arc<str>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Option<usize> {
        let mut value = 0usize;
        for shift in (0..64).step_by(7) {
            let byte = *self.bytes.get(self.at)?;
            self.at += 1;
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let slice = self.bytes.get(self.at..self.at.checked_add(count)?)?;
        self.at += count;
        Some(slice)
    }

    fn string(&mut self) -> Option<&'a str> {
        let length = self.varint()?;
        std::str::from_utf8(self.take(length)?).ok()
    }
}

fn read_index(data: &'static [u8]) -> Option<Index> {
    let mut reader = Reader { bytes: data, at: 0 };
    if reader.take(4)? != b"GZH1" {
        return None;
    }
    let years = reader.take(4)?;
    let first_year = i32::from(u16::from_le_bytes([years[0], years[1]]));
    let last_year = i32::from(u16::from_le_bytes([years[2], years[3]]));
    let version = reader.string()?.to_string();
    let mut listed = Vec::new();
    for _ in 0..reader.varint()? {
        let code = reader.string()?.to_string();
        let mut subdivisions = Vec::new();
        for _ in 0..reader.varint()? {
            let code = reader.string()?.to_string();
            let name = reader.string()?.to_string();
            subdivisions.push(Subdivision { code, name });
        }
        listed.push((code, subdivisions, reader.varint()?));
    }
    let mut countries = Vec::with_capacity(listed.len());
    for (code, subdivisions, length) in listed {
        countries.push(Country { code, subdivisions, blob: reader.take(length)? });
    }
    (reader.at == data.len()).then_some(Index { first_year, last_year, version, countries })
}

fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| read_index(DATA).expect("holidays.bin is built in and was written by tools/gen_holidays.py"))
}

/// Every supported country with its subdivisions, for the settings form. Sorted by code.
pub fn countries() -> &'static [Country] {
    &index().countries
}

/// The first year the built-in table covers.
pub fn first_year() -> i32 {
    index().first_year
}

/// The last year the built-in table covers. Past it no day is a statutory holiday; regenerate the
/// table (tools/gen_holidays.py) well before then.
pub fn last_year() -> i32 {
    index().last_year
}

/// The version of the Python `holidays` package the table was computed with.
pub fn data_version() -> &'static str {
    &index().version
}

fn country(code: &str) -> Option<&'static Country> {
    let countries = countries();
    countries.binary_search_by(|c| c.code.as_str().cmp(code)).ok().map(|at| &countries[at])
}

/// Unpack one year of one calendar from a country's table.
fn decode(country: &Country, calendar: usize, year: i32) -> Option<Vec<Entry>> {
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib(country.blob).ok()?;
    let mut reader = Reader { bytes: &raw, at: 0 };
    let mut names = Vec::new();
    for _ in 0..reader.varint()? {
        names.push(reader.string()?);
    }
    let set_bytes = ((1 + country.subdivisions.len()) * 2).div_ceil(8);
    let mut sets = Vec::new();
    for _ in 0..reader.varint()? {
        sets.push(reader.take(set_bytes)?);
    }
    let index = index();
    let mut entries = Vec::new();
    for current in index.first_year..=index.last_year {
        let count = reader.varint()?;
        let mut day_of_year = 0;
        for _ in 0..count {
            day_of_year += reader.varint()?;
            let name = *names.get(reader.varint()?)?;
            let key = match reader.varint()? {
                0 => name,
                other => *names.get(other - 1)?,
            };
            let set = sets.get(reader.varint()?)?;
            if current == year && set[calendar / 8] & (1 << (calendar % 8)) != 0 {
                let day = NaiveDate::from_yo_opt(year, u32::try_from(day_of_year).ok()? + 1)?;
                entries.push(Entry { day, name: Arc::from(name), key: Arc::from(key) });
            }
        }
        if current == year {
            break;
        }
    }
    Some(entries)
}

type CacheKey = (String, Option<String>, bool, i32);

struct Cache {
    entries: HashMap<CacheKey, (u64, Arc<Vec<Entry>>)>,
    clock: u64,
}

/// One year of a country's (or one of its subdivisions') calendar, sorted by day.
///
/// `None` for a country or subdivision the table doesn't have; an empty list for a year outside it.
pub fn year(code: &str, subdivision: Option<&str>, observed: bool, year: i32) -> Option<Arc<Vec<Entry>>> {
    let country = country(code)?;
    let position = match subdivision {
        None => 0,
        Some(sub) => 1 + country.subdivisions.iter().position(|s| s.code == sub)?,
    };
    if !(first_year()..=last_year()).contains(&year) {
        return Some(Arc::new(Vec::new()));
    }
    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
    let key: CacheKey = (code.to_string(), subdivision.map(str::to_string), observed, year);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(|| Cache { entries: HashMap::new(), clock: 0 });
    cache.clock += 1;
    let now = cache.clock;
    if let Some((used, entries)) = cache.entries.get_mut(&key) {
        *used = now;
        return Some(entries.clone());
    }
    let entries = Arc::new(decode(country, position * 2 + usize::from(observed), year)?);
    if cache.entries.len() >= CACHE_SIZE {
        if let Some(oldest) = cache.entries.iter().min_by_key(|(_, (used, _))| *used).map(|(key, _)| key.clone()) {
            cache.entries.remove(&oldest);
        }
    }
    cache.entries.insert(key, (now, entries.clone()));
    Some(entries)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExtraDate {
    pub date: NaiveDate,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    pub country: Option<String>,
    pub subdivision: Option<String>,
    pub observed: bool,
    /// A flat price per kWh that replaces every rate zone on a holiday.
    pub price_kw: Option<f64>,
    /// Sorted, without duplicates.
    pub excluded_names: Vec<String>,
    /// Sorted by date, one per date.
    pub extra_dates: Vec<ExtraDate>,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            enabled: false,
            country: None,
            subdivision: None,
            observed: true,
            price_kw: None,
            excluded_names: Vec::new(),
            extra_dates: Vec::new(),
        }
    }
}

fn switch(raw: &Object, key: &str, default: bool) -> Result<bool, String> {
    match get(raw, key) {
        Value::Null => Ok(default),
        Value::Bool(flag) => Ok(*flag),
        Value::Number(number) if number.as_f64() == Some(0.0) => Ok(false),
        Value::Number(number) if number.as_f64() == Some(1.0) => Ok(true),
        // "false" is a non-empty string: taken for a truth value it would mean true
        _ => Err(format!("{key} must be true or false")),
    }
}

fn name_of(raw: &Object, key: &str) -> Result<String, String> {
    match get(raw, key) {
        Value::Null => Ok(String::new()),
        Value::String(text) => Ok(text.trim().to_string()),
        _ => Err(format!("{key} must be text")),
    }
}

/// `YYYY-MM-DD` (or `YYYYMMDD`) as a date.
fn parse_date(text: &str) -> Option<NaiveDate> {
    let digits = |part: &str, length: usize| -> Option<u32> {
        (part.len() == length && part.bytes().all(|b| b.is_ascii_digit())).then(|| part.parse().ok()).flatten()
    };
    let (year, month, day) = match text.len() {
        10 if text.is_ascii() && &text[4..5] == "-" && &text[7..8] == "-" => (&text[..4], &text[5..7], &text[8..]),
        8 if text.is_ascii() => (&text[..4], &text[4..6], &text[6..]),
        _ => return None,
    };
    // No year 0: there is none in the calendar the earlier (Python) versions read these dates
    // with, and they dropped a station's whole holiday settings over a date they could not read.
    let year = digits(year, 4).filter(|year| *year >= 1)?;
    NaiveDate::from_ymd_opt(year as i32, digits(month, 2)?, digits(day, 2)?)
}

impl Settings {
    /// Validate settings coming from the API. The error is a readable message.
    pub fn normalize(raw: &Value) -> Result<Settings, String> {
        let empty = Object::new();
        let raw = match raw {
            Value::Object(object) => object,
            other if !truthy(other) => &empty,
            _ => return Err("holiday settings must be an object".to_string()),
        };
        let enabled = switch(raw, "enabled", false)?;
        let observed = switch(raw, "observed", true)?;
        let country = Some(name_of(raw, "country")?.to_uppercase()).filter(|c| !c.is_empty());
        let mut subdivision = Some(name_of(raw, "subdivision")?).filter(|s| !s.is_empty());
        match &country {
            None => subdivision = None,
            Some(code) => {
                let known = self::country(code).ok_or_else(|| format!("unsupported country '{code}'"))?;
                if let Some(wanted) = &subdivision {
                    let found = known
                        .subdivisions
                        .iter()
                        .find(|s| s.code == *wanted)
                        .or_else(|| known.subdivisions.iter().find(|s| s.code.to_uppercase() == wanted.to_uppercase()))
                        .ok_or_else(|| format!("unknown region '{wanted}' for {code}"))?;
                    subdivision = Some(found.code.clone());
                }
            }
        }
        let price_kw = match get(raw, "priceKW") {
            Value::Null => None,
            Value::String(text) if text.is_empty() => None,
            price => {
                let number = match price {
                    Value::Number(number) => number.as_f64(),
                    Value::String(text) => parse_float(text),
                    _ => None,
                };
                // NaN would pass "< 0" and then poison every price and total
                let number = number.filter(|n| n.is_finite()).ok_or("holiday price must be a number")?;
                if number < 0.0 {
                    return Err("holiday price can't be negative".to_string());
                }
                Some(number)
            }
        };
        let list = |key: &str| -> Result<&[Value], String> {
            match get(raw, key) {
                Value::Array(items) => Ok(items),
                other if !truthy(other) => Ok(&[]),
                _ => Err("excludedNames and extraDates must be lists".to_string()),
            }
        };
        let (excluded, extras) = (list("excludedNames")?, list("extraDates")?);
        if excluded.len() > MAX_EXCLUDED_NAMES || extras.len() > MAX_EXTRA_DATES {
            return Err("too many holidays in the list".to_string());
        }
        let mut excluded_names = BTreeSet::new();
        for name in excluded {
            let name = name.as_str().filter(|n| n.chars().count() <= 200).ok_or("excludedNames must be holiday names")?;
            if !name.trim().is_empty() {
                excluded_names.insert(name.trim().to_string());
            }
        }
        let mut extra: BTreeMap<NaiveDate, String> = BTreeMap::new();
        for item in extras {
            let (date, name) = match item {
                Value::String(date) => (Some(date.clone()), None),
                Value::Object(object) => (Some(to_text(get(object, "date"))), Some(get(object, "name"))),
                _ => (None, None),
            };
            let day = date
                .and_then(|text| parse_date(&text))
                .ok_or_else(|| format!("invalid date {}; use YYYY-MM-DD", clip(&item.to_string(), 80)))?;
            let name = name.filter(|n| truthy(n)).map(to_text).unwrap_or_default();
            let name = clip(name.trim(), 60);
            extra.insert(day, if name.is_empty() { "Holiday".to_string() } else { name.to_string() });
        }
        Ok(Settings {
            enabled,
            country,
            subdivision,
            observed,
            price_kw,
            excluded_names: excluded_names.into_iter().collect(),
            extra_dates: extra.into_iter().map(|(date, name)| ExtraDate { date, name }).collect(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "country": self.country,
            "subdivision": self.subdivision,
            "observed": self.observed,
            "priceKW": self.price_kw,
            "excludedNames": self.excluded_names,
            "extraDates": self.extra_dates.iter()
                .map(|extra| json!({"date": extra.date.to_string(), "name": extra.name}))
                .collect::<Vec<_>>(),
        })
    }

    fn calendar(&self, year_wanted: i32) -> Option<Arc<Vec<Entry>>> {
        year(self.country.as_deref()?, self.subdivision.as_deref(), self.observed, year_wanted)
    }

    /// The holiday on `day` under these settings, or `None`. Ignores `enabled`; callers check it.
    pub fn holiday_name(&self, day: NaiveDate) -> Option<String> {
        if let Ok(at) = self.extra_dates.binary_search_by(|extra| extra.date.cmp(&day)) {
            return Some(self.extra_dates[at].name.clone());
        }
        let calendar = self.calendar(day.year())?;
        let at = calendar.binary_search_by(|entry| entry.day.cmp(&day)).ok()?;
        let entry = &calendar[at];
        (!self.is_excluded(&entry.key)).then(|| entry.name.to_string())
    }

    pub fn is_holiday(&self, day: NaiveDate) -> bool {
        self.holiday_name(day).is_some()
    }

    fn is_excluded(&self, key: &str) -> bool {
        self.excluded_names.binary_search_by(|name| name.as_str().cmp(key)).is_ok()
    }

    /// Holidays from `start` on, including excluded ones (`included: false`) so the form can list them.
    pub fn upcoming(&self, start: NaiveDate, days: i64) -> Vec<Upcoming> {
        let end = start + Duration::days(days);
        let mut rows: BTreeMap<NaiveDate, Upcoming> = BTreeMap::new();
        for year in start.year()..=end.year() {
            let Some(calendar) = self.calendar(year) else { break };
            for entry in calendar.iter().filter(|entry| start <= entry.day && entry.day <= end) {
                let row = Upcoming {
                    date: entry.day,
                    name: entry.name.to_string(),
                    key: Some(entry.key.to_string()),
                    included: !self.is_excluded(&entry.key),
                    custom: false,
                };
                rows.insert(entry.day, row);
            }
        }
        for extra in self.extra_dates.iter().filter(|extra| start <= extra.date && extra.date <= end) {
            let row = Upcoming { date: extra.date, name: extra.name.clone(), key: None, included: true, custom: true };
            rows.insert(extra.date, row);
        }
        rows.into_values().collect()
    }
}

/// A row of the list the settings form shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upcoming {
    pub date: NaiveDate,
    pub name: String,
    pub key: Option<String>,
    pub included: bool,
    pub custom: bool,
}

impl Upcoming {
    pub fn to_json(&self) -> Value {
        json!({
            "date": self.date.to_string(),
            "name": self.name,
            "key": self.key,
            "included": self.included,
            "custom": self.custom,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    fn settings(raw: Value) -> Settings {
        Settings::normalize(&raw).unwrap()
    }

    fn names(code: &str, sub: Option<&str>, observed: bool, y: i32) -> Vec<(NaiveDate, String)> {
        year(code, sub, observed, y).unwrap().iter().map(|e| (e.day, e.name.to_string())).collect()
    }

    #[test]
    fn the_table_lists_every_country_and_region() {
        assert_eq!(countries().len(), 250);
        assert_eq!(countries().iter().map(|c| c.subdivisions.len()).sum::<usize>(), 629);
        assert!(countries().windows(2).all(|pair| pair[0].code < pair[1].code));
        assert!((first_year(), last_year()) == (2000, 2100));
        assert!(!data_version().is_empty());
        let us = country("US").unwrap();
        assert!(us.subdivisions.iter().any(|s| s.code == "ID"));
        let ca = country("CA").unwrap();
        assert!(ca.subdivisions.iter().any(|s| s.code == "BC" && s.name == "British Columbia"), "{ca:?}");
    }

    #[test]
    fn calendar_and_observed_days() {
        let us = names("US", None, true, 2026);
        assert!(us.contains(&(day(2026, 7, 4), "Independence Day".to_string())));
        // 4 July 2026 is a Saturday: the observed day is the Friday.
        assert!(us.contains(&(day(2026, 7, 3), "Independence Day (observed)".to_string())));
        assert!(us.contains(&(day(2026, 11, 26), "Thanksgiving Day".to_string())));
        let plain = names("US", None, false, 2026);
        assert!(!plain.iter().any(|(d, _)| *d == day(2026, 7, 3)));
        assert!(plain.contains(&(day(2026, 7, 4), "Independence Day".to_string())));
        assert!(us.windows(2).all(|pair| pair[0].0 < pair[1].0), "sorted, one entry a day");
    }

    #[test]
    fn subdivisions_add_their_own_days() {
        let idaho = names("US", Some("ID"), true, 2026);
        let national = names("US", None, true, 2026);
        assert!(idaho.len() >= national.len());
        let bc = names("CA", Some("BC"), true, 2026);
        assert!(bc.iter().any(|(_, name)| name == "British Columbia Day"), "{bc:?}");
        assert!(!names("CA", Some("ON"), true, 2026).iter().any(|(_, name)| name == "British Columbia Day"));
        assert!(year("US", Some("XX"), true, 2026).is_none());
        assert!(year("XX", None, true, 2026).is_none());
    }

    #[test]
    fn years_outside_the_table_have_no_holidays() {
        assert!(year("US", None, true, 1999).unwrap().is_empty());
        assert!(year("US", None, true, 2101).unwrap().is_empty());
        assert!(!year("US", None, true, 2000).unwrap().is_empty());
        assert!(!year("US", None, true, 2100).unwrap().is_empty());
    }

    #[test]
    fn a_moved_holiday_is_not_also_kept_on_its_original_date() {
        // Colombia moves Epiphany (6 January) to the following Monday: in 2026, the 12th.
        let observed = settings(json!({"country": "CO", "observed": true}));
        assert!(observed.holiday_name(day(2026, 1, 12)).is_some());
        assert_eq!(observed.holiday_name(day(2026, 1, 6)), None);
        let plain = settings(json!({"country": "CO", "observed": false}));
        assert!(plain.holiday_name(day(2026, 1, 6)).is_some());
        assert_eq!(plain.holiday_name(day(2026, 1, 12)), None);
    }

    #[test]
    fn observed_days_that_are_additions_still_work() {
        let us = settings(json!({"country": "US"}));
        assert_eq!(us.holiday_name(day(2026, 7, 4)).as_deref(), Some("Independence Day"));
        assert_eq!(us.holiday_name(day(2026, 7, 3)).as_deref(), Some("Independence Day (observed)"));
        assert_eq!(us.holiday_name(day(2026, 7, 2)), None);
    }

    #[test]
    fn excluding_a_holiday_also_drops_its_observed_day_and_extra_dates_add() {
        let custom = settings(json!({
            "country": "us", "subdivision": "id",
            "excludedNames": ["Independence Day", " Independence Day ", ""],
            "extraDates": ["2026-07-10", {"date": "2026-08-01", "name": "  Company day  "}, {"date": "2026-07-10"}],
        }));
        assert_eq!(custom.country.as_deref(), Some("US"));
        assert_eq!(custom.subdivision.as_deref(), Some("ID"));
        assert_eq!(custom.excluded_names, ["Independence Day"]);
        assert_eq!(custom.holiday_name(day(2026, 7, 4)), None);
        assert_eq!(custom.holiday_name(day(2026, 7, 3)), None);
        assert_eq!(custom.holiday_name(day(2026, 7, 10)).as_deref(), Some("Holiday"));
        assert_eq!(custom.holiday_name(day(2026, 8, 1)).as_deref(), Some("Company day"));
        assert_eq!(custom.holiday_name(day(2026, 12, 25)).as_deref(), Some("Christmas Day"));

        let rows = custom.upcoming(day(2026, 7, 1), 40);
        let listed: Vec<(String, bool, bool)> = rows.iter().map(|r| (r.date.to_string(), r.included, r.custom)).collect();
        assert_eq!(
            listed,
            [
                ("2026-07-03".to_string(), false, false),
                ("2026-07-04".to_string(), false, false),
                ("2026-07-10".to_string(), true, true),
                ("2026-08-01".to_string(), true, true),
            ]
        );
        assert_eq!(rows[0].key.as_deref(), Some("Independence Day"));
        assert_eq!(rows[2].key, None);
    }

    #[test]
    fn upcoming_spans_the_new_year() {
        let us = settings(json!({"country": "US"}));
        let rows = us.upcoming(day(2026, 12, 20), 370);
        assert_eq!(rows.first().unwrap().name, "Christmas Day");
        assert!(rows.iter().any(|r| r.date == day(2027, 1, 1)));
        assert!(rows.iter().any(|r| r.date == day(2027, 12, 24) || r.date == day(2027, 12, 25)));
        assert!(rows.windows(2).all(|pair| pair[0].date < pair[1].date));
        assert!(Settings::default().upcoming(day(2026, 1, 1), 370).is_empty());
    }

    #[test]
    fn normalize_rejects_bad_input() {
        for (bad, message) in [
            (json!("US"), "holiday settings must be an object"),
            (json!({"country": "XX"}), "unsupported country 'XX'"),
            (json!({"country": 5}), "country must be text"),
            (json!({"country": "US", "subdivision": "Atlantis"}), "unknown region 'Atlantis' for US"),
            (json!({"priceKW": "cheap"}), "holiday price must be a number"),
            (json!({"priceKW": true}), "holiday price must be a number"),
            (json!({"priceKW": "NaN"}), "holiday price must be a number"),
            (json!({"priceKW": [1]}), "holiday price must be a number"),
            (json!({"priceKW": -1}), "holiday price can't be negative"),
            (json!({"excludedNames": "Christmas Day"}), "excludedNames and extraDates must be lists"),
            (json!({"excludedNames": [5]}), "excludedNames must be holiday names"),
            (json!({"excludedNames": ["x".repeat(201)]}), "excludedNames must be holiday names"),
            (json!({"excludedNames": vec!["x"; 501]}), "too many holidays in the list"),
            (json!({"extraDates": vec!["2026-01-01"; 501]}), "too many holidays in the list"),
        ] {
            assert_eq!(Settings::normalize(&bad).unwrap_err(), message, "{bad}");
        }
        let year_zero = [json!({"extraDates": ["0000-01-01"]}), json!({"extraDates": [{"date": "00000229"}]})];
        for bad in [json!({"extraDates": ["tomorrow"]}), json!({"extraDates": [5]}), json!({"extraDates": ["2026-02-30"]})]
            .into_iter()
            .chain(year_zero)
        {
            let message = Settings::normalize(&bad).unwrap_err();
            assert!(message.starts_with("invalid date") && message.ends_with("use YYYY-MM-DD"), "{message}");
        }
    }

    #[test]
    fn holiday_switches_must_be_booleans() {
        for key in ["enabled", "observed"] {
            for bad in [json!("false"), json!("true"), json!(2), json!([]), json!({})] {
                let message = Settings::normalize(&json!({key: bad})).unwrap_err();
                assert_eq!(message, format!("{key} must be true or false"));
            }
        }
    }

    #[test]
    fn holiday_switches_accept_booleans_and_defaults() {
        assert_eq!(Settings::normalize(&json!(null)).unwrap(), Settings::default());
        assert_eq!(Settings::normalize(&json!({})).unwrap(), Settings::default());
        let on = settings(json!({"enabled": 1, "observed": 0}));
        assert!(on.enabled && !on.observed);
        let nulls = settings(json!({"enabled": null, "observed": null, "country": null, "subdivision": "ID"}));
        assert!(!nulls.enabled && nulls.observed);
        assert_eq!(nulls.subdivision, None, "a region means nothing without a country");
        assert_eq!(settings(json!({"priceKW": ""})).price_kw, None);
        assert_eq!(settings(json!({"priceKW": "0.05"})).price_kw, Some(0.05));
    }

    #[test]
    fn settings_survive_a_round_trip() {
        let original = settings(json!({
            "enabled": true, "country": "CA", "subdivision": "BC", "observed": false, "priceKW": 0.07,
            "excludedNames": ["Boxing Day"], "extraDates": [{"date": "2026-03-01", "name": "x"}],
        }));
        assert_eq!(Settings::normalize(&original.to_json()).unwrap(), original);
        assert_eq!(
            original.to_json(),
            json!({"enabled": true, "country": "CA", "subdivision": "BC", "observed": false, "priceKW": 0.07,
                "excludedNames": ["Boxing Day"], "extraDates": [{"date": "2026-03-01", "name": "x"}]})
        );
    }

    /// Compare every calendar with what the Python package gave, row for row:
    /// `python tools/gen_holidays.py --dump holidays.jsonl --output /dev/null`, then
    /// `HOLIDAYS_DUMP=holidays.jsonl cargo test --release every_calendar -- --ignored`.
    #[test]
    #[ignore = "needs the dump written by tools/gen_holidays.py --dump"]
    fn every_calendar_matches_the_python_package() {
        use std::io::BufRead;
        let path = std::env::var("HOLIDAYS_DUMP").expect("HOLIDAYS_DUMP names the dump file");
        let file = std::io::BufReader::new(std::fs::File::open(path).unwrap());
        let mut checked = 0;
        // Group by country so that each table is unpacked once per calendar, not once per year.
        for line in file.lines() {
            let record: Value = serde_json::from_str(&line.unwrap()).unwrap();
            let code = record["country"].as_str().unwrap();
            let sub = record["subdivision"].as_str();
            let observed = record["observed"].as_bool().unwrap();
            let wanted_year = record["year"].as_i64().unwrap() as i32;
            let country = country(code).unwrap();
            let position = sub.map_or(0, |s| 1 + country.subdivisions.iter().position(|x| x.code == s).unwrap());
            let got: Vec<Value> = decode(country, position * 2 + usize::from(observed), wanted_year)
                .unwrap()
                .iter()
                .map(|e| json!([e.day.to_string(), &*e.name, &*e.key]))
                .collect();
            assert_eq!(Value::Array(got), record["rows"], "{code} {sub:?} observed={observed} {wanted_year}");
            checked += 1;
        }
        assert!(checked > 100_000, "only {checked} calendars in the dump");
    }
}
