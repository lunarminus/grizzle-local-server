//! Schedules, holidays and prices: results that were wrong for particular days, places or
//! sessions, and how they come out through the controller and the API. Also the charger's OCPP
//! identity (recorded, never shown) and the firmware's "unlock" check.
//!
//! The plain rules of windows, rate zones and the holiday calendar are tested where they are
//! written, in src/schedules.rs and src/holidays.rs. What is here is what those leave out: real
//! calendars instead of a made-up holiday, the nights the clocks change in 2027, and the cases
//! that were reported from real setups.

mod support;

use std::sync::Arc;

use chrono::{DateTime, Duration as Span, NaiveDate, TimeZone, Utc};
use grizzle_local::config::Settings;
use grizzle_local::controller::{effective_limit, Controller};
use grizzle_local::holidays;
use grizzle_local::ocpp::Connection;
use grizzle_local::schedules::{charging_allowed, next_change, price_now, zone_active, HolidayCheck, Zone};
use grizzle_local::state::Station;
use grizzle_local::zone::Tz;
use serde_json::{json, Value};

use support::{settings, FakeCharger, FakeOptions, TestServer};

fn denver_zone() -> Tz {
    "America/Denver".parse().unwrap()
}

/// What the fake charger presents over HTTP Basic.
const AUTH_KEY: &str = "s3cr3t-auth-key";

fn zone(value: Value) -> Zone {
    value.as_object().unwrap().clone()
}

/// The zone with these fields set as well.
fn with(mut zone: Zone, extra: Value) -> Zone {
    zone.extend(self::zone(extra));
    zone
}

/// A charging window from `start` to `end` ("HH:MM"), on every day.
fn window(start: &str, end: &str) -> Zone {
    let time = |text: &str| -> (i64, i64) {
        let (hours, minutes) = text.split_once(':').unwrap();
        (hours.parse().unwrap(), minutes.parse().unwrap())
    };
    let ((sh, sm), (eh, em)) = (time(start), time(end));
    zone(json!({
        "name": format!("{start}-{end}"), "startHours": sh, "startMinutes": sm, "endHours": eh, "endMinutes": em,
        "days": [], "allDay": false, "isSchedule": true, "scheduleEnabled": true,
    }))
}

fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, 0).unwrap()
}

fn to_utc(moment: DateTime<Tz>) -> DateTime<Utc> {
    moment.with_timezone(&Utc)
}

fn at(tz: Tz, year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Tz> {
    tz.with_ymd_and_hms(year, month, day, hour, minute, 0).earliest().unwrap()
}

fn denver(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Tz> {
    at(denver_zone(), year, month, day, hour, minute)
}

fn day(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).unwrap()
}

fn calendar(raw: Value) -> holidays::Settings {
    holidays::Settings::normalize(&raw).unwrap()
}

/// Idaho's holidays. Christmas Day 2026 is a Friday.
fn idaho() -> holidays::Settings {
    calendar(json!({"enabled": true, "country": "us", "subdivision": "id"}))
}

/// Equal the way pytest.approx has it: to within a millionth.
fn close(actual: &Value, expected: f64) -> bool {
    actual.as_f64().is_some_and(|actual| (actual - expected).abs() <= 1e-6 * expected.abs())
}

/// A controller on its own, with nothing listening, that knows one station: for tests that call
/// its handlers directly.
fn controller(dir: &tempfile::TempDir, serial: &str) -> Arc<Controller> {
    let controller = Controller::open(Arc::new(settings(dir.path(), &[]))).unwrap();
    add_station(&controller, serial);
    controller
}

fn add_station(controller: &Controller, serial: &str) {
    let station = Station::new(serial, &controller.settings);
    controller.lock().stations.insert(serial.to_string(), station);
}

fn handle(controller: &Arc<Controller>, serial: &str, action: &str, payload: Value) -> Value {
    controller.handle(serial, action, payload.as_object().unwrap()).unwrap()
}

/// A MeterValues message for transaction 1 with one energy reading.
fn reading(wh: i64) -> Value {
    let sampled = json!([{"value": wh.to_string(), "measurand": "Energy.Active.Import.Register", "unit": "Wh"}]);
    json!({"connectorId": 1, "transactionId": 1, "meterValue": [{"sampledValue": sampled}]})
}

/// A session as the history has it.
fn session(controller: &Controller, serial: &str, id: i64) -> Value {
    let sessions = controller.lock().store.sessions(serial, 50).unwrap();
    sessions.into_iter().find(|row| row["id"] == id).map(Value::Object).expect("the session is recorded")
}

async fn charger_with_key(server: &TestServer, serial: &str) -> FakeCharger {
    let options = FakeOptions { auth_key: AUTH_KEY.to_string(), ..FakeOptions::default() };
    FakeCharger::connect_with(server, serial, options).await.expect("the charger is admitted")
}

// The nights the clocks change. In America/Denver: 02:00 -> 03:00 on 2027-03-14, 02:00 -> 01:00 on
// 2027-11-07.

/// 02:30 never happens on the spring-forward night; the window really opens at the jump (03:00).
/// Wall-clock arithmetic put it at "02:30" in the old offset: half an hour late.
#[test]
fn next_change_in_the_hour_that_does_not_exist() {
    let now = utc(2027, 3, 14, 8, 0).with_timezone(&denver_zone()); // 01:00 MST
    let opens = |start: &str| next_change(&[window(start, "06:00")], now, 1, None).map(to_utc);
    assert_eq!(opens("02:30"), Some(utc(2027, 3, 14, 9, 0))); // 03:00 MDT, the instant of the jump
    assert_eq!(opens("02:00"), Some(utc(2027, 3, 14, 9, 0)));
    assert_eq!(opens("03:30"), Some(utc(2027, 3, 14, 9, 30)));
}

/// 01:00-02:00 happens twice. A window from 01:30 switched on, then off for the second
/// 01:00-01:30, then on again: a RemoteStop and, half an hour later, a RemoteStart.
#[test]
fn a_window_does_not_pause_when_the_clocks_go_back() {
    let zone = window("01:30", "05:00");
    let start = utc(2027, 11, 7, 6, 0); // 00:00 MDT; seven hours on it is 06:00 MST
    let states: Vec<bool> = (0..7 * 60)
        .map(|minute| zone_active(&zone, (start + Span::minutes(minute)).with_timezone(&denver_zone()), None))
        .collect();
    let flips: Vec<(usize, bool)> =
        (1..states.len()).filter(|i| states[*i] != states[i - 1]).map(|i| (i, states[i])).collect();
    assert_eq!(flips, [(90, true), (360, false)]); // on at the first 01:30 (07:30Z), off at 05:00 MST (12:00Z)

    let second_pass = utc(2027, 11, 7, 8, 10).with_timezone(&denver_zone());
    assert_eq!(second_pass.format("%H:%M %:z").to_string(), "01:10 -07:00"); // 01:10 for the second time
    assert!(zone_active(&zone, second_pass, None));
    assert_eq!(next_change(&[zone], second_pass, 1, None).map(to_utc), Some(utc(2027, 11, 7, 12, 0)));
    // A window that ended during the first pass stays ended.
    assert!(!zone_active(&window("20:00", "01:30"), second_pass, None));
    // Prices follow the same reading of the clock.
    let rate = with(window("01:30", "05:00"), json!({"isSchedule": false, "priceKW": 0.30}));
    assert_eq!(price_now(&[rate], second_pass, Some(0.10), None, None), Some(0.30));
}

/// The ground truth for next_change() is to walk real time a minute at a time and watch the state.
#[test]
fn next_change_agrees_with_a_minute_by_minute_scan() {
    let cases = [
        vec![window("02:30", "06:00")],
        vec![window("01:30", "05:00")],
        vec![window("01:15", "01:45")],
        vec![window("23:00", "02:30")],
        vec![window("00:00", "01:30"), window("03:00", "04:15")],
        vec![window("02:00", "03:00")],
        vec![with(window("22:00", "07:00"), json!({"days": [0, 6]}))],
    ];
    const ASKED: usize = 36 * 60; // a day and a half around the change
    const AHEAD: usize = 3 * 24 * 60; // how far the scan looks
    for night in [utc(2027, 3, 14, 0, 0), utc(2027, 11, 7, 0, 0)] {
        let start = night - Span::hours(6);
        let moment = |minute: usize| start + Span::minutes(minute as i64);
        for zones in &cases {
            let names: Vec<&str> = zones.iter().filter_map(|zone| zone["name"].as_str()).collect();
            let states: Vec<bool> = (0..ASKED + AHEAD)
                .map(|minute| charging_allowed(zones, moment(minute).with_timezone(&denver_zone()), 1, None).is_some())
                .collect();
            for asked in (0..ASKED).step_by(17) {
                // at awkward minutes
                let expected = (asked + 1..=asked + AHEAD).find(|minute| states[*minute] != states[asked]).map(moment);
                let found = next_change(zones, moment(asked).with_timezone(&denver_zone()), 1, None).map(to_utc);
                assert_eq!(found, expected, "{} at {}", names.join("+"), moment(asked));
            }
        }
    }
}

// Windows and rate zones on ordinary days.

/// src/schedules.rs has the all-day zone and a second range within one day. This second range
/// wraps past midnight.
#[test]
fn all_day_and_second_range() {
    let winter = zone(json!({
        "startHours": 9, "startMinutes": 0, "endHours": 17, "endMinutes": 0,
        "startHours2": 20, "startMinutes2": 0, "endHours2": 6, "endMinutes2": 0,
        "priceKW": 0.0923, "days": [1, 2, 3, 4, 5, 6], "allDay": false,
    }));
    assert!(zone_active(&winter, denver(2026, 11, 9, 10, 0), None));
    assert!(zone_active(&winter, denver(2026, 11, 9, 22, 0), None));
    assert!(zone_active(&winter, denver(2026, 11, 10, 3, 0), None));
    assert!(!zone_active(&winter, denver(2026, 11, 9, 18, 0), None));
}

/// Reported on a real setup: weekdays 09-17, weekdays 20-06 and Sunday all day.
///
/// "Weekdays 20:00-06:00" means that on a weekday the hours 00:00-06:00 and 20:00-24:00 are in the
/// zone, not "starts Monday 20:00 and runs into Tuesday". So Sunday (all day) runs straight on into
/// Monday's 00:00-06:00, and Saturday morning is outside every window.
#[test]
fn overnight_range_is_judged_per_calendar_day() {
    let weekdays = json!({"days": [1, 2, 3, 4, 5], "isSchedule": false, "priceKW": 0.0923});
    let zones = [
        with(window("09:00", "17:00"), weekdays.clone()),
        with(window("20:00", "06:00"), weekdays),
        with(window("00:00", "00:00"), json!({"days": [0], "allDay": true, "isSchedule": false, "priceKW": 0.0923})),
    ];
    let inside = |now: DateTime<Tz>| charging_allowed(&zones, now, 1, None).map(|zone| zone["name"].as_str().unwrap());
    let next = |now: DateTime<Tz>| next_change(&zones, now, 1, None);
    // 2026-11-08 is a Sunday
    assert_eq!(next(denver(2026, 11, 8, 19, 53)), Some(denver(2026, 11, 9, 6, 0)));
    assert_eq!(inside(denver(2026, 11, 9, 3, 0)), Some("20:00-06:00")); // Monday 03:00
    assert_eq!(inside(denver(2026, 11, 9, 7, 0)), None); // Monday 07:00, between windows
    assert_eq!(inside(denver(2026, 11, 13, 21, 0)), Some("20:00-06:00")); // Friday 21:00
    assert_eq!(inside(denver(2026, 11, 14, 3, 0)), None); // Saturday 03:00: Saturday isn't listed
    assert_eq!(next(denver(2026, 11, 13, 21, 0)), Some(denver(2026, 11, 14, 0, 0))); // Friday evening ends at midnight
    assert_eq!(next(denver(2026, 11, 14, 12, 0)), Some(denver(2026, 11, 15, 0, 0)));
    // Saturday -> Sunday 00:00
}

// Holidays.

/// Colombia moves Epiphany to the following Monday. With "observed days" on, both the Monday and
/// the 6th counted as holidays: nine ordinary working days a year were holidays there.
#[test]
fn a_moved_holiday_is_not_also_kept_on_its_original_date() {
    // Which of the two days is the holiday is tested in src/holidays.rs; this is what it is called.
    let observed = calendar(json!({"enabled": true, "country": "CO", "observed": true}));
    assert_eq!(observed.holiday_name(day(2026, 1, 12)).as_deref(), Some("Epiphany (observed)"));
    let plain = calendar(json!({"enabled": true, "country": "CO", "observed": false}));
    assert_eq!(plain.holiday_name(day(2026, 1, 6)).as_deref(), Some("Epiphany"));
    // Every holiday is on one day or the other: the year has as many of them either way.
    let in_2026 = |settings: &holidays::Settings| settings.upcoming(day(2026, 1, 1), 364).len();
    assert_eq!(in_2026(&observed), in_2026(&plain));
    // Excluding the holiday by its name still drops the day it is observed on.
    let without = calendar(json!({"enabled": true, "country": "CO", "observed": true, "excludedNames": ["Epiphany"]}));
    assert_eq!(without.holiday_name(day(2026, 1, 12)), None);
}

/// bool("false") is True: the string switched the option on. src/holidays.rs tries the strings,
/// lists and whole numbers; a fraction must not be rounded to a switch either.
#[test]
fn holiday_switches_must_be_booleans() {
    for key in ["enabled", "observed"] {
        for value in [json!("no"), json!(0.5)] {
            let refused = holidays::Settings::normalize(&json!({"country": "US", key: value}));
            assert_eq!(refused.unwrap_err(), format!("{key} must be true or false"), "{value}");
        }
    }
}

/// The search stopped after 8 days (120 for holidays-only windows): with the next holiday further
/// off than that, the page said no window was coming at all.
#[test]
fn next_change_looks_far_enough_ahead_for_holiday_rules() {
    let nl = calendar(json!({"enabled": true, "country": "NL"}));
    assert_eq!(nl.upcoming(day(2026, 5, 26), 300)[0].date, day(2026, 12, 25)); // seven months without a holiday
    let is_holiday: HolidayCheck<'_> = &|day| nl.is_holiday(day);
    let all_day = with(window("00:00", "00:00"), json!({"allDay": true}));
    let only = [with(all_day.clone(), json!({"holidays": "only"}))];
    let amsterdam: Tz = "Europe/Amsterdam".parse().unwrap();
    let found = next_change(&only, at(amsterdam, 2026, 5, 26, 12, 0), 1, Some(is_holiday));
    assert_eq!(found, Some(at(amsterdam, 2026, 12, 25, 0, 0)));

    // A Friday-only window that skips holidays, asked on a Good Friday (a public holiday in Great
    // Britain): the window next applies a week later. That was already within reach; it must stay right.
    let gb = calendar(json!({"enabled": true, "country": "GB", "subdivision": "ENG"}));
    assert!(gb.is_holiday(day(2026, 4, 3)));
    let is_holiday: HolidayCheck<'_> = &|day| gb.is_holiday(day);
    let fridays = [with(all_day, json!({"days": [5], "holidays": "skip"}))];
    let london: Tz = "Europe/London".parse().unwrap();
    let found = next_change(&fridays, at(london, 2026, 4, 3, 12, 0), 1, Some(is_holiday));
    assert_eq!(found, Some(at(london, 2026, 4, 10, 0, 0)));
}

/// src/holidays.rs has the days that are dropped and added. The form lists the holidays that
/// still count next to them.
#[test]
fn excluding_a_holiday_also_drops_its_observed_day_and_extra_dates_add() {
    let settings = calendar(json!({
        "country": "US", "subdivision": "ID",
        "excludedNames": ["Independence Day"], "extraDates": [{"date": "2026-12-24", "name": "Eve"}],
    }));
    assert_eq!(settings.holiday_name(day(2026, 12, 24)).as_deref(), Some("Eve"));
    let rows = settings.upcoming(day(2026, 6, 1), 250);
    let row = |date: NaiveDate| rows.iter().find(|row| row.date == date).expect("the day is listed");
    assert!(row(day(2026, 12, 24)).custom && row(day(2026, 12, 25)).included);
    assert!(!row(day(2026, 12, 25)).custom && !row(day(2026, 7, 3)).included);
}

/// The rest of the bad input is tried in src/holidays.rs.
#[test]
fn normalize_rejects_bad_input() {
    assert!(holidays::Settings::normalize(&json!({"extraDates": [{"date": "25/12/2026"}]})).is_err());
    let countries = holidays::countries();
    for code in ["US", "CA", "GB", "DE"] {
        assert!(countries.iter().any(|country| country.code == code), "{code}");
    }
    let us = countries.iter().find(|country| country.code == "US").unwrap();
    assert!(us.subdivisions.iter().any(|region| region.code == "ID" && region.name == "Idaho"));
}

/// A night window that skips the holiday is in src/schedules.rs. One for holidays only is its
/// mirror image: the holiday's small hours and late evening, and nothing of the morning after.
#[test]
fn overnight_window_skips_the_holiday_as_a_calendar_day() {
    let us = idaho();
    let is_holiday: HolidayCheck<'_> = &|day| us.is_holiday(day);
    let only = with(window("22:00", "06:00"), json!({"holidays": "only"}));
    assert!(zone_active(&only, denver(2026, 12, 25, 2, 0), Some(is_holiday)));
    assert!(zone_active(&only, denver(2026, 12, 25, 23, 0), Some(is_holiday)));
    assert!(!zone_active(&only, denver(2026, 12, 26, 2, 0), Some(is_holiday)));
}

#[test]
fn next_change_and_window_lookup_with_holidays() {
    let us = idaho();
    let is_holiday: HolidayCheck<'_> = &|day| us.is_holiday(day);
    let weekday = with(window("09:00", "17:00"), json!({"days": [1, 2, 3, 4, 5], "holidays": "skip"}));
    let only = with(window("09:00", "17:00"), json!({"allDay": true, "holidays": "only"}));
    let zones = [weekday, only];
    // Thursday 18:00: tomorrow is Christmas, so the next window opens Monday 09:00
    let thursday = denver(2026, 12, 24, 18, 0);
    assert_eq!(next_change(&zones[..1], thursday, 1, Some(is_holiday)), Some(denver(2026, 12, 28, 9, 0)));
    assert_eq!(next_change(&zones[..1], thursday, 1, None), Some(denver(2026, 12, 25, 9, 0)));
    let found = charging_allowed(&zones, denver(2026, 12, 25, 12, 0), 1, Some(is_holiday));
    assert!(found.is_some_and(|zone| std::ptr::eq(zone, &zones[1])));
    // holidays-only windows are found even when the next holiday is weeks away (Thanksgiving, 26 Nov)
    let found = next_change(&zones[1..], denver(2026, 11, 12, 12, 0), 1, Some(is_holiday));
    assert_eq!(found, Some(denver(2026, 11, 26, 0, 0)));
}

#[test]
fn holiday_price_and_rate_zone_modes() {
    let us = idaho();
    let is_holiday: HolidayCheck<'_> = &|day| us.is_holiday(day);
    let peak = with(
        window("09:00", "17:00"),
        json!({"priceKW": 0.30, "days": [1, 2, 3, 4, 5], "holidays": "skip", "isSchedule": false, "scheduleEnabled": false}),
    );
    let (eve, christmas) = (denver(2026, 12, 24, 12, 0), denver(2026, 12, 25, 12, 0));
    let price = |zone: &Zone, now: DateTime<Tz>, flat: Option<f64>| {
        price_now(std::slice::from_ref(zone), now, Some(0.10), Some(is_holiday), flat)
    };
    assert_eq!(price(&peak, eve, None), Some(0.30));
    assert_eq!(price(&peak, christmas, None), Some(0.10)); // peak skipped on the holiday
    let same = with(peak.clone(), json!({"holidays": "same"}));
    assert_eq!(price(&same, christmas, Some(0.07)), Some(0.07)); // flat price wins
    assert_eq!(price(&peak, eve, Some(0.07)), Some(0.30));
}

#[tokio::test]
async fn holiday_api() {
    const SERIAL: &str = "GRD-HOLIDAYS";
    let server = TestServer::with(&[("TZ", "America/Denver")]).await;
    add_station(server.controller(), SERIAL);
    let token = server.login().await;
    let (holidays, station) = (format!("/local/stations/{SERIAL}/holidays"), format!("/client/stations/{SERIAL}"));
    let names = |rows: &Value| -> Vec<String> {
        rows.as_array().unwrap().iter().filter_map(|row| row["name"].as_str()).map(str::to_string).collect()
    };

    assert_eq!(server.get("/local/holidays/countries", None).await.status, 401);
    let countries = server.json(&token, "/local/holidays/countries").await;
    assert!(countries["countries"].as_array().unwrap().iter().any(|country| country["code"] == "CA"));

    let data = server.json(&token, &holidays).await;
    assert_eq!((&data["settings"]["enabled"], &data["upcoming"]), (&json!(false), &json!([])));

    let body = json!({
        "enabled": true, "country": "US", "subdivision": "ID", "excludedNames": ["Columbus Day"], "priceKW": 0.07,
    });
    let preview = server.post(&format!("{holidays}/preview"), Some(&token), &body).await.json();
    assert!(names(&preview["upcoming"]).contains(&"Christmas Day".to_string()));
    let shown = server.json(&token, &station).await;
    // preview saves nothing
    assert_eq!((&shown["holidaysSettings"]["enabled"], &shown["holidays"]), (&json!(false), &json!([])));

    let saved = server.put(&holidays, Some(&token), &body).await.json();
    assert_eq!(saved["settings"]["priceKW"], 0.07);
    let columbus = saved["upcoming"].as_array().unwrap().iter().filter(|row| row["key"] == "Columbus Day");
    assert!(columbus.clone().all(|row| row["included"] == false));
    let shown = server.json(&token, &station).await;
    let listed = names(&shown["holidays"]);
    assert!(listed.contains(&"Christmas Day".to_string()) && !listed.contains(&"Columbus Day".to_string()));
    assert_eq!(shown["holidaysSettings"]["country"], "US");
    assert!(shown.get("holidayToday").is_some());

    assert_eq!(server.put(&holidays, Some(&token), &json!({"country": "ZZ"})).await.status, 400);
    let update = format!("{station}/scheduleUpdate");
    let bad = json!({"price": {"name": "x", "days": [1], "holidays": "sometimes"}});
    assert_eq!(server.post(&update, Some(&token), &bad).await.status, 400);
    let good = json!({"price": {"name": "Holiday", "allDay": true, "days": [], "holidays": "only"}});
    assert_eq!(server.post(&update, Some(&token), &good).await.status, 200);
    assert_eq!(server.json(&token, &station).await["pricesByZone"][0]["holidays"], "only");
}

// Current limits across connectors.

/// One profile goes to the whole station. With connector 1 in a 16 A window and connector 2 in a
/// 32 A one, whichever connector came last won: 32 A for both.
#[test]
fn the_lowest_window_limit_in_force_is_the_one_applied() {
    let settings = Settings::defaults();
    let mut station = Station::new("GRD-L0000HARD4", &settings);
    station.connector_count = 2;
    let all_day = |id: &str, connector: i64, limit: i64| {
        let window = json!({"allDay": true, "days": [], "isSchedule": true, "scheduleEnabled": true});
        with(zone(window), json!({"_id": id, "connectorId": connector, "currentLimit": limit}))
    };
    station.zones = vec![all_day("a", 1, 16), all_day("b", 2, 32)];
    assert_eq!(effective_limit(&station, &settings), Some(16));
    station.zones.reverse();
    assert_eq!(effective_limit(&station, &settings), Some(16));
    // A window's limit still overrides the station's own, in either direction...
    station.current_limit = Some(8);
    assert_eq!(effective_limit(&station, &settings), Some(16));
    // ...and without a window in force the station's limit applies.
    station.zones.clear();
    assert_eq!(effective_limit(&station, &settings), Some(8));
}

// What a session costs.

/// Cost only built up with each MeterValues reading. The last stretch of every session, and the
/// whole of a session without readings, was recorded with its energy and without its cost; pressing
/// "Recalculate" then changed totals although no price had changed.
#[tokio::test]
async fn energy_after_the_last_reading_is_paid_for() {
    const SERIAL: &str = "GRD-L0000HARD5";
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(&dir, SERIAL);
    controller.set_base_rate(SERIAL, &json!(0.10)).unwrap();

    handle(&controller, SERIAL, "StartTransaction", json!({"connectorId": 1, "idTag": "t", "meterStart": 100_000}));
    for wh in [100_000, 102_000, 105_000] {
        handle(&controller, SERIAL, "MeterValues", reading(wh));
    }
    handle(&controller, SERIAL, "StopTransaction", json!({"transactionId": 1, "meterStop": 106_000}));
    let recorded = session(&controller, SERIAL, 1);
    assert_eq!(recorded["energy_wh"], 6000.0);
    assert!(close(&recorded["cost"], 0.60), "{recorded}");
    assert!(close(&recorded["price_kwh"], 0.10), "{recorded}"); // the average the session was charged at
    let last = controller.lock().stations[SERIAL].connectors[&1].last_session.clone().unwrap();
    assert!(close(&last["priceTotal"], 0.60), "{last}");

    // No readings at all: the whole session is priced when it ends.
    handle(&controller, SERIAL, "StartTransaction", json!({"connectorId": 1, "idTag": "t", "meterStart": 106_000}));
    handle(&controller, SERIAL, "StopTransaction", json!({"transactionId": 2, "meterStop": 116_000}));
    let recorded = session(&controller, SERIAL, 2);
    assert!(close(&recorded["cost"], 1.00), "{recorded}");

    // ...so recalculating with unchanged prices changes nothing.
    let result = controller.recalculate_costs(SERIAL).unwrap();
    assert!(close(&result["cost_before"], 1.60) && close(&result["cost_after"], 1.60), "{result}");
}

/// transactionData was stored without the session's id, so repricing never saw it. It is still
/// kept out of the live total: its begin/end readings may be lifetime values even where the
/// session's own readings count from zero.
#[tokio::test]
async fn final_readings_in_stop_transaction_belong_to_the_session() {
    const SERIAL: &str = "GRD-L0000HARD6";
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(&dir, SERIAL);
    controller.set_base_rate(SERIAL, &json!(0.10)).unwrap();
    handle(&controller, SERIAL, "StartTransaction", json!({"connectorId": 1, "idTag": "t", "meterStart": 819_392}));
    handle(&controller, SERIAL, "MeterValues", reading(0));
    handle(&controller, SERIAL, "MeterValues", reading(1500)); // session-relative, like the Duo
    let lifetime_end = json!({"sampledValue": [{"value": "821392", "measurand": "Energy.Active.Import.Register"}]});
    let stop = json!({"transactionId": 1, "meterStop": 2000, "transactionData": [lifetime_end]});
    handle(&controller, SERIAL, "StopTransaction", stop);
    let recorded = session(&controller, SERIAL, 1);
    assert_eq!(recorded["energy_wh"], 2000.0); // not 821 kWh
    assert!(close(&recorded["cost"], 0.20), "{recorded}");
    let samples = controller.lock().store.samples(SERIAL, "", None, 100).unwrap();
    let sessions: Vec<Option<i64>> = samples.iter().map(|row| row["transaction_id"].as_i64()).collect();
    assert_eq!(sessions, [Some(1); 3]);
    let result = controller.recalculate_costs(SERIAL).unwrap();
    assert!(close(&result["cost_after"], 0.20), "{result}");
}

// The server records the charger's OCPP identity (serial + Auth key) for firmware_capture, and
// never leaks it through the HTTP API.

#[tokio::test]
async fn handshake_and_auth_key_recorded() {
    const SERIAL: &str = "GRD-L0000TEST1";
    let server = TestServer::start().await;
    let _charger = charger_with_key(&server, SERIAL).await;
    let station = server.state()["stations"][SERIAL].clone();
    assert_eq!(station["ocppAuthKey"], AUTH_KEY);
    let handshake = &station["ocppHandshake"];
    assert_eq!(handshake["authUser"], SERIAL);
    assert!(handshake["path"].as_str().unwrap().ends_with(SERIAL));
    assert!(handshake["protocols"].as_array().unwrap().contains(&json!("ocpp1.6")));
    assert!(handshake["recordedAt"].as_str().is_some_and(|at| !at.is_empty()));
}

#[tokio::test]
async fn empty_or_missing_auth_key_does_not_wipe_captured_key() {
    const SERIAL: &str = "GRD-L0000TEST2";
    let dir = tempfile::tempdir().unwrap();
    let controller = Controller::open(Arc::new(settings(dir.path(), &[]))).unwrap();
    let limits = &controller.settings;
    let conn = Arc::new(Connection::new(SERIAL, limits.rate_burst, limits.rate_per_second, limits.call_timeout));
    let key = || controller.lock().stations[SERIAL].ocpp_auth_key.clone();

    controller.on_connect(conn.clone(), Some(json!({"authUser": SERIAL})), Some(AUTH_KEY));
    assert_eq!(key().as_deref(), Some(AUTH_KEY));

    // A later connection with an empty password (colon, no value) must NOT overwrite it.
    controller.on_connect(conn.clone(), Some(json!({"authUser": SERIAL})), Some(""));
    assert_eq!(key().as_deref(), Some(AUTH_KEY));

    // Nor a connection with no Basic auth at all.
    controller.on_connect(conn, Some(json!({"authUser": null})), None);
    assert_eq!(key().as_deref(), Some(AUTH_KEY));
}

#[tokio::test]
async fn auth_key_never_exposed_by_api() {
    const SERIAL: &str = "GRD-L0000TEST3";
    let server = TestServer::start().await;
    let _charger = charger_with_key(&server, SERIAL).await;
    assert_eq!(server.state()["stations"][SERIAL]["ocppAuthKey"], AUTH_KEY);
    let token = server.login().await;

    let mut blob = String::new();
    for path in ["/client/stations", "/client/stations/{}", "/local/stations/{}/log", "/local/stations/{}/sessions"] {
        let path = path.replace("{}", SERIAL);
        let response = server.get(&path, Some(&token)).await;
        assert!(response.status < 400, "GET {path} -> {}", response.status);
        blob.push_str(&response.body);
    }
    for secret in [AUTH_KEY, "ocppAuthKey", "ocppHandshake"] {
        assert!(!blob.contains(secret), "{secret} is in a response");
    }
}

// The /commercial/ext-ocpp-check endpoint that keeps third-party OCPP unlocked.
//
// The real firmware (reverse engineered) GETs this path and compares the body to lowercase-hex
// MD5("<serial>;isUnlocked=true"); on a match it sets its isUnlocked flag. The digests here are
// what Python's hashlib gives for the two serials.

#[tokio::test]
async fn unlock_returns_firmware_expected_md5() {
    let server = TestServer::start().await;
    let response = server.get("/commercial/ext-ocpp-check/GRD-L0000430161", None).await;
    assert_eq!(response.status, 200); // public: the charger sends no Authorization header, so this must not be a 401
                                      // exactly the 32-char lowercase hex, no trailing newline (firmware does a strcmp)
    assert_eq!(response.body, "bf9e764a49121d4006c699d7b991314d");
}

#[tokio::test]
async fn unlock_per_serial() {
    let server = TestServer::start().await;
    let response = server.get("/commercial/ext-ocpp-check/GRD-L0000999999", None).await;
    assert_eq!(response.body, "4797c58c041f89d37f469dd8d5b5a62e");
}

#[tokio::test]
async fn unlock_can_be_disabled() {
    let server = TestServer::with(&[("GRIZZLE_OCPP_UNLOCK", "false")]).await;
    assert_eq!(server.get("/commercial/ext-ocpp-check/GRD-L0000430162", None).await.status, 404);
}
