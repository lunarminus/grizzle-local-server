//! What a hostile or broken charger can no longer do (the first half of pytests/test_hardening_ocpp.py).
//!
//! Unless GRIZZLE_OCPP_PASSWORD is set, anyone who can reach the port may connect as a charger the
//! server has never seen. So everything here is, in effect, unauthenticated input: none of it may
//! exhaust memory, stop the controller for other stations, corrupt what the API returns, or be kept
//! without bound.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use grizzle_local::ocpp::{Connection, MAX_FRAME_BYTES};
use grizzle_local::state::{Station, MAX_CONFIG_KEYS, MAX_CONNECTORS};
use grizzle_local::timeutil::parse_iso;
use serde_json::{json, Value};

use support::{capture_logs, logged, settings, wait_for, wait_until, RawCharger, TestServer};

/// A charger connected as `serial`, presenting no credentials at all.
async fn charger(server: &TestServer, serial: &str) -> RawCharger {
    RawCharger::connect(server, serial, None).await.expect("the charger is admitted")
}

/// A StatusNotification for connector 1, Available, with these fields changed.
fn status(changes: Value) -> Value {
    let mut payload = json!({"connectorId": 1, "status": "Available", "errorCode": "NoError"});
    payload.as_object_mut().unwrap().extend(changes.as_object().unwrap().clone());
    payload
}

/// The station as it would be written to state.json right now.
fn stored(server: &TestServer, serial: &str) -> Value {
    server.state()["stations"][serial].clone()
}

fn keys(object: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = object.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    keys
}

/// Nothing about this charger was logged as an error.
fn no_failures(serial: &str) {
    let bad: Vec<String> = logged(serial).into_iter().filter(|line| line.contains(" ERROR ")).collect();
    assert!(bad.is_empty(), "{bad:?}");
}

/// Let the controller's loop (once a second) go round a couple of times.
async fn a_couple_of_ticks() {
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
}

// Connector ids and counts are bounded.

#[tokio::test]
async fn out_of_range_connector_is_refused_and_changes_nothing() {
    // One frame with a huge connectorId used to set the station's connector count, and every
    // later frame and tick then looped (and allocated) that many times.
    const SERIAL: &str = "GRD-L0000HARD1";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    let cases = [
        ("StatusNotification", status(json!({"connectorId": 2_000_000_000}))),
        ("StatusNotification", status(json!({"connectorId": "9".repeat(40)}))),
        ("StatusNotification", status(json!({"connectorId": MAX_CONNECTORS + 1}))),
        ("StatusNotification", status(json!({"connectorId": -1}))),
        ("StatusNotification", status(json!({"connectorId": [1]}))),
        ("MeterValues", json!({"connectorId": 2_000_000_000, "meterValue": []})),
        ("StartTransaction", json!({"connectorId": 1e30, "idTag": "x", "meterStart": 0})),
    ];
    for (action, payload) in cases {
        let reply = cp.call(action, payload.clone()).await;
        assert!(reply[0] == 4 && reply[2] == "PropertyConstraintViolation", "{action} {payload}: {reply}");
        let station = stored(&server, SERIAL);
        assert_eq!(station["connectorCount"], 1);
        assert_eq!(keys(&station["connectors"]), ["1"]);
        assert_eq!(cp.call("Heartbeat", json!({})).await[0], 3); // and the server is still answering
    }
}

#[tokio::test]
async fn connector_ids_up_to_the_limit_still_work() {
    const SERIAL: &str = "GRD-L0000HARD2";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    assert_eq!(cp.call("StatusNotification", status(json!({"connectorId": MAX_CONNECTORS}))).await[0], 3);
    assert_eq!(stored(&server, SERIAL)["connectorCount"], MAX_CONNECTORS);
    assert_eq!(cp.call("StatusNotification", status(json!({"connectorId": 0}))).await[0], 3); // the station itself
}

/// Boot `cp` as a charger whose configuration claims these two values, and wait until the server
/// has read it.
async fn boot_claiming(cp: &RawCharger, connectors: &Value, dip_switch: &Value) {
    let claims = [("NumberOfConnectors", connectors), ("DipSwitchCurrentLimit", dip_switch)];
    let claims: Vec<Value> = claims.iter().map(|(key, value)| json!({"key": key, "value": value})).collect();
    cp.reply_with("GetConfiguration", json!({"configurationKey": claims}));
    let asked = cp.calls("TriggerMessage").len();
    assert_eq!(cp.call("BootNotification", json!({})).await[0], 3);
    // Once it has taken the configuration in, the server asks for each connector's status.
    wait_for("the configuration to be read", || cp.calls("TriggerMessage").len() > asked).await;
}

#[tokio::test]
async fn number_of_connectors_from_configuration_is_bounded() {
    const SERIAL: &str = "GRD-L0000HARD3";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    let claims = json!(["999999999", "9".repeat(5000), "0", "-3", "two", 1e12, null, ["2"]]);
    for claimed in claims.as_array().unwrap() {
        boot_claiming(&cp, claimed, claimed).await;
        let station = stored(&server, SERIAL);
        assert!(station["connectorCount"] == 1 && keys(&station["connectors"]) == ["1"], "{claimed}");
        assert!(station["dipSwitchCurrentLimit"].is_null(), "{claimed}");
    }
    boot_claiming(&cp, &json!("2"), &json!("32")).await;
    let station = stored(&server, SERIAL);
    assert!(station["connectorCount"] == 2 && station["dipSwitchCurrentLimit"] == 32, "{station}");
}

// A state file written by an older version (possibly under attack).

#[tokio::test]
async fn poisoned_state_file_is_repaired_at_startup() {
    // The pre-fix server saved what it was sent. Loading such a file must not bring back the hang.
    const SERIAL: &str = "GRD-L0000HARD4";
    capture_logs();
    let connectors = json!({
        "1": {
            "id": 1,
            "status": ["Charging"],
            "mode": "Whenever",
            "lastRemoteStart": 9e12,
            "lastRemoteStop": 9e12,
            "transaction": {"id": 3, "startAt": 12345, "energy": 0},
        },
        "2": {"id": 2, "status": "Available", "mode": "Schedule", "transaction": "none"},
        "2000000000": {"id": 2_000_000_000, "status": "Available"},
        "x": {},
        "03": {"id": 3},
    });
    let zones = json!([
        {"_id": "abc123", "name": "Night", "isSchedule": true, "scheduleEnabled": true, "allDay": true},
        {"_id": "bad", "startHours": "soon"},
        "junk",
        {"name": "no id"},
        // Values the old code accepted and coped with are mended, not thrown away:
        {"_id": "mend1", "name": "n".repeat(300), "isSchedule": true, "currentLimit": 120, "days": [1, 7, 9]},
    ]);
    let station = json!({
        "id": SERIAL,
        "displayName": ["not", "text"],
        "timezone": 5,
        "currency": null,
        "priceKW": "free",
        "connectorCount": 2_000_000_000,
        "maxCurrent": null,
        "minCurrent": "lots",
        "currentLimit": 1_000_000_000,
        "boot": {"chargePointModel": "GRD 40A 2025", "junk": "x".repeat(100_000)},
        "config": {"NumberOfConnectors": "2", "Huge": "y".repeat(100_000), "Nested": {"a": [1, 2]}},
        "dataTransfers": [{"at": "2026-01-01T00:00:00Z", "vendorId": "v", "data": "z".repeat(100_000)}],
        "connectors": connectors,
        "pricesByZone": zones,
        "holidaysSettings": {"enabled": true, "country": 12},
    });
    let state = json!({
        "next_transaction_id": 7,
        "tokens": {"t": "not a session", "u": {"refresh": "r", "expires": "soon"}},
        "stations": {SERIAL: station, "GRD-BROKEN": "not a station"},
    });
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let settings = settings(dir.path(), &[]);
    std::fs::create_dir_all(&settings.data_dir).unwrap();
    let state_path = settings.data_dir.join("state.json");
    std::fs::write(&state_path, state.to_string()).unwrap();

    let server = TestServer::with_settings(dir, settings).await;
    let state = server.state();
    assert!(state["stations"].get("GRD-BROKEN").is_none());
    let station = &state["stations"][SERIAL];
    assert!(station["connectorCount"] == 2 && keys(&station["connectors"]) == ["1", "2"], "{station}");
    let one = &station["connectors"]["1"];
    assert!(one["status"].is_null() && one["mode"] == "Active", "{one}");
    {
        let inner = server.controller().lock();
        let one = &inner.stations[SERIAL].connectors[&1];
        assert!(one.last_remote_start.is_none() && one.last_remote_stop.is_none());
    }
    assert_eq!(one["transaction"]["id"], 3);
    assert!(station["connectors"]["2"]["transaction"].is_null());
    assert!(station["displayName"] == SERIAL && station["priceKW"] == 0.0, "{station}");
    assert!(station["timezone"] == "UTC" && station["currency"] == "USD", "{station}");
    assert!(station["maxCurrent"] == 40 && station["minCurrent"] == 6, "{station}");
    assert!(station["currentLimit"].is_null());
    assert_eq!(station["boot"], json!({"chargePointModel": "GRD 40A 2025", "timestamp": null}));
    assert_eq!(station["config"]["NumberOfConnectors"], "2");
    assert_eq!(station["config"]["Huge"].as_str().unwrap().len(), 500);
    assert!(station["config"]["Nested"].is_null());
    assert_eq!(station["dataTransfers"][0]["data"].as_str().unwrap().len(), 1000);
    let zones = station["pricesByZone"].as_array().unwrap();
    assert_eq!(zones.iter().map(|zone| &zone["_id"]).collect::<Vec<_>>(), ["abc123", "mend1"]);
    let mended = &zones[1];
    assert_eq!(mended["name"].as_str().unwrap().len(), 100);
    assert!(mended["currentLimit"] == 100.0 && mended["days"] == json!([1]), "{mended}");
    assert!(station.get("holidaysSettings").is_none());
    assert_eq!(state["tokens"], json!({}));

    // The controller runs on it: a couple of ticks, the API answers, nothing blows up.
    let token = server.login().await;
    a_couple_of_ticks().await;
    let listed = server.station(&token, SERIAL).await;
    let listed: Vec<&Value> = listed["connectors"].as_array().unwrap().iter().map(|c| &c["connectorId"]).collect();
    assert_eq!(listed, [1, 2]);
    assert_eq!(server.get(&format!("/local/stations/{SERIAL}/sessions"), Some(&token)).await.status, 200);
    let _dir = server.stop().await; // which saves
    no_failures(SERIAL);
    assert!(std::fs::read_to_string(&state_path).unwrap().len() < 20_000); // and what is written back is small again
}

// A bounded number of stations.

#[tokio::test]
async fn unknown_serials_cannot_create_stations_without_limit() {
    const KEYED: Option<(&str, &str)> = Some(("GRD-TWO00001", "key"));
    let server = TestServer::with(&[("GRIZZLE_MAX_STATIONS", "2")]).await;
    let first = charger(&server, "GRD-ONE00001").await;
    let second = RawCharger::connect(&server, "GRD-TWO00001", KEYED).await.expect("the second station is admitted");
    assert_eq!(RawCharger::connect(&server, "GRD-THREE001", None).await.err(), Some(503));
    assert_eq!(keys(&server.state()["stations"]), ["GRD-ONE00001", "GRD-TWO00001"]);

    // Stations that exist are not affected, online or after a reconnect.
    second.close().await;
    wait_for("the second station to go offline", || !server.controller().is_online("GRD-TWO00001")).await;
    let second = RawCharger::connect(&server, "GRD-TWO00001", KEYED).await.expect("a known station may reconnect");
    assert_eq!(second.call("Heartbeat", json!({})).await[0], 3);

    // Deleting one makes room again.
    first.close().await;
    wait_for("the first station to go offline", || !server.controller().is_online("GRD-ONE00001")).await;
    let token = server.login().await;
    assert_eq!(server.delete("/local/stations/GRD-ONE00001", Some(&token)).await.status, 200);
    let _third = charger(&server, "GRD-THREE001").await;
    assert_eq!(keys(&server.state()["stations"]), ["GRD-THREE001", "GRD-TWO00001"]);
}

#[tokio::test]
async fn station_limit_also_holds_with_a_shared_ocpp_password() {
    let (one, two) = ("GRD-ONE00002", "GRD-TWO00002");
    let server = TestServer::with(&[("GRIZZLE_MAX_STATIONS", "1"), ("GRIZZLE_OCPP_PASSWORD", "shared")]).await;
    let _cp = RawCharger::connect(&server, one, Some((one, "shared"))).await.expect("the first station is admitted");
    assert_eq!(RawCharger::connect(&server, two, Some((two, "shared"))).await.err(), Some(503));
    // the password is still checked first
    assert_eq!(RawCharger::connect(&server, two, Some((two, "wrong"))).await.err(), Some(401));
}

// Numbers that are not numbers.

#[tokio::test]
async fn non_finite_meter_values_never_reach_the_api() {
    // One NaN in a response used to make /client/stations unparseable for the web page and Home
    // Assistant. A bare NaN or Infinity in a frame is not JSON here, so that frame is dropped
    // whole; what a charger can still send is the text spelling, and numbers no meter reads.
    const SERIAL: &str = "GRD-L0000HARD5";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    let start = cp.call("StartTransaction", json!({"connectorId": 1, "idTag": "t", "meterStart": 1e300})).await;
    assert_eq!(start[0], 3);
    let values = json!(["NaN", "nan", "Infinity", "-inf", "1e999", 1e300, "1".repeat(400), true]);
    for value in values.as_array().unwrap() {
        let sampled = json!([
            {"value": value, "measurand": "Power.Active.Import", "unit": "W"},
            {"value": value, "measurand": "Energy.Active.Import.Register", "unit": "kWh"},
            {"value": value, "measurand": "Voltage"},
            {"value": "7", "measurand": "Current.Import"},
        ]);
        let reply = cp.call("MeterValues", json!({"connectorId": 1, "meterValue": [{"sampledValue": sampled}]})).await;
        assert_eq!(reply[0], 3, "{value}: {reply}");
    }
    for bare in ["NaN", "Infinity", "-Infinity"] {
        let meter_value = format!(r#"[{{"sampledValue":[{{"value":{bare},"measurand":"Voltage"}}]}}]"#);
        cp.send_text(&format!(r#"[2,"bare","MeterValues",{{"connectorId":1,"meterValue":{meter_value}}}]"#));
    }
    let stop = json!({"transactionId": start[2]["transactionId"], "meterStop": 1e300});
    assert_eq!(cp.call("StopTransaction", stop).await[0], 3);
    assert!(!cp.frames().iter().any(|frame| frame.contains("bare")), "a frame that is not JSON gets no answer");

    let token = server.login().await;
    for history in ["sessions", "samples"] {
        server.json(&token, &format!("/local/stations/{SERIAL}/{history}")).await; // JSON a browser can parse
    }
    let station = server.station(&token, SERIAL).await; // and so is /client/stations
    let meter = &station["connectors"][0]["lastMeter"];
    assert!(meter["currentImport"] == 7.0 && meter["voltage"].is_null(), "{meter}");
    assert_eq!(station["connectors"][0]["power"], 0.0);
}

#[tokio::test]
async fn api_output_is_strict_json_even_if_state_holds_nan() {
    // Belt and braces: whatever gets into memory, a response is always parseable.
    const SERIAL: &str = "GRD-L0000HARD6";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    assert_eq!(cp.call("StatusNotification", status(json!({}))).await[0], 3);
    {
        let mut inner = server.controller().lock();
        let station = &mut inner.stations[SERIAL];
        station.price_kw = f64::NAN;
        station.connectors.get_mut(&1).unwrap().power = f64::INFINITY;
    }
    let token = server.login().await;
    let data = server.station(&token, SERIAL).await;
    assert!(data["connectors"][0]["power"].is_null());
}

// Values of the wrong type.

#[tokio::test]
async fn wrong_typed_messages_do_not_break_the_controller() {
    // Each of these used to leave something in the station that made every later tick raise,
    // for every station, which also skipped the periodic save.
    const SERIAL: &str = "GRD-L0000HARD7";
    capture_logs();
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    for status in [json!([]), json!({}), json!(5), json!(null), json!("")] {
        let reply = cp.call("StatusNotification", json!({"connectorId": 1, "status": status})).await;
        assert!(reply[0] == 4 && reply[2] == "TypeConstraintViolation", "{status}: {reply}");
    }
    assert_eq!(cp.call("StatusNotification", status(json!({"status": "Charging", "timestamp": [1]}))).await[0], 3);

    let stamps = [
        json!(5),
        json!("2026-01-01T00:00:00"),
        json!("9999-12-31T23:59:59-23:59"), // these two overflow when taken to UTC
        json!("0001-01-01T00:00:00+23:59"),
        json!(""),
        json!([]),
        json!("x".repeat(500)),
    ];
    for stamp in stamps {
        let payload = json!({"connectorId": 1, "idTag": ["a"], "meterStart": "lots", "timestamp": stamp});
        let reply = cp.call("StartTransaction", payload).await;
        assert_eq!(reply[0], 3, "{stamp}: {reply}");
        let tx = stored(&server, SERIAL)["connectors"]["1"]["transaction"].clone();
        assert!(parse_iso(tx["startAt"].as_str().unwrap()).is_some(), "{stamp}: {tx}");
        assert!(tx["idTag"].is_null() && tx["meterStart"].is_null(), "{stamp}: {tx}");
    }

    let odd_meter_values = [
        json!({"connectorId": 1, "meterValue": {"sampledValue": []}}),
        json!({"connectorId": 1, "meterValue": ["x", 5, null]}),
        json!({"connectorId": 1, "meterValue": [{"sampledValue": "nope"}]}),
        json!({"connectorId": 1, "meterValue": [{"sampledValue": [5, "x", {"value": "1", "measurand": ["list"]}]}]}),
        json!({"connectorId": 1, "transactionId": {"a": 1}, "meterValue": [{"timestamp": {}, "sampledValue": [
            {"value": "230", "measurand": "Voltage", "unit": ["V"], "phase": {}}]}]}),
        json!({"connectorId": 1, "transactionId": 1e30, "meterValue": [{"sampledValue": [{"value": "5"}]}]}),
    ];
    for payload in odd_meter_values {
        assert_eq!(cp.call("MeterValues", payload.clone()).await[0], 3, "{payload}");
    }
    assert_eq!(cp.call("StopTransaction", json!({"transactionId": "seven", "transactionData": "x"})).await[0], 3);

    // Lone surrogates are legal in a JSON string for Python, and SQLite and UTF-8 logs take
    // neither. Here they are not text at all: the frame is dropped and the connection lives on.
    cp.send_text(r#"[2,"lone","StartTransaction",{"connectorId":1,"idTag":"\udcff\ud800","meterStart":1}]"#);
    // Text that is valid, and that nothing downstream likes any better, goes the whole way.
    let odd = "\u{0}\u{ffff}";
    let start = cp.call("StartTransaction", json!({"connectorId": 1, "idTag": odd, "meterStart": 1})).await;
    assert_eq!(start[0], 3);
    assert!(!cp.frames().iter().any(|frame| frame.contains("lone")));
    let stop = json!({"transactionId": start[2]["transactionId"], "reason": odd, "meterStop": 2});
    assert_eq!(cp.call("StopTransaction", stop).await[0], 3);
    assert_eq!(cp.call("StatusNotification", status(json!({"status": odd, "info": odd}))).await[0], 3);
    assert_eq!(cp.call(odd, json!({odd: odd})).await[0], 4);
    assert_eq!(cp.call("DataTransfer", json!({"vendorId": ["v"], "data": {"deep": [1, 2]}})).await[0], 3);
    assert_eq!(cp.call("FirmwareStatusNotification", json!({"status": {"a": 1}})).await[0], 3);
    let boot = json!({"chargePointModel": ["GRD"], "firmwareVersion": {"v": 1}});
    assert_eq!(cp.call("BootNotification", boot).await[0], 3);

    a_couple_of_ticks().await; // over all of that
    let token = server.login().await;
    server.json(&token, "/client/stations").await;
    assert_eq!(server.get(&format!("/local/stations/{SERIAL}/sessions"), Some(&token)).await.status, 200);
    no_failures(SERIAL);
}

// One station can't hold up the others.

#[tokio::test]
async fn an_unresponsive_charger_does_not_stall_the_controller() {
    // The tick awaited every charger in turn (30 s per unanswered call). One silent peer with a car
    // "plugged in" therefore froze enforcement and saving for everybody.
    const SILENT: &str = "GRD-SILENT01";
    const OTHER: &str = "GRD-OTHER001";
    let server = TestServer::start().await;
    let silent = charger(&server, SILENT).await;
    silent.set_answer(false);
    silent.call("StatusNotification", status(json!({"status": "Preparing"}))).await;
    wait_for("RemoteStartTransaction", || !silent.calls("RemoteStartTransaction").is_empty()).await;
    // Forget that it was asked a moment ago, so that the next tick asks the silent one again.
    server.controller().lock().stations[SILENT].connectors.get_mut(&1).unwrap().last_remote_start = None;
    wait_for("a tick to be waiting on it", || silent.calls("RemoteStartTransaction").len() >= 2).await;

    // Meanwhile the controller still saves...
    {
        let mut other = Station::new(OTHER, &server.app.settings);
        other.ensure_connectors();
        other.display_name = "still being looked after".to_string();
        let mut inner = server.controller().lock();
        inner.stations.insert(OTHER.to_string(), other);
        inner.dirty = true;
    }
    let state_path = server.data_dir().join("state.json");
    let saved = || std::fs::read_to_string(&state_path).is_ok_and(|state| state.contains("still being looked after"));
    wait_until("the state to be saved", Duration::from_secs(4), saved).await;
    // ...and still enforces schedules for other stations.
    server.controller().lock().stations[OTHER].connectors.get_mut(&1).unwrap().is_active_by_schedule = None;
    let enforced = || server.controller().lock().stations[OTHER].connectors[&1].is_active_by_schedule == Some(false);
    wait_until("the other station to be enforced", Duration::from_secs(4), enforced).await;
}

#[tokio::test]
async fn boot_notification_spam_keeps_one_after_boot_task() {
    const SERIAL: &str = "GRD-L0000HARD8";
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let mut settings = settings(dir.path(), &[]);
    settings.boot_delay = Duration::from_secs(1); // longer than the spam takes
    let server = TestServer::with_settings(dir, settings).await;
    let cp = charger(&server, SERIAL).await;
    for _ in 0..40 {
        assert_eq!(cp.call("BootNotification", json!({"chargePointModel": "GRD 40A"})).await[0], 3);
    }
    // Of the forty conversations that were started, one is left, and that one still does its job.
    wait_until("GetConfiguration", Duration::from_secs(6), || !cp.calls("GetConfiguration").is_empty()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(cp.calls("GetConfiguration").len(), 1);
    assert_eq!(cp.calls("ChangeConfiguration").len(), 4);
}

#[tokio::test]
async fn call_gives_up_when_the_peer_stops_reading() {
    // The send used to be outside the deadline: a peer with a full receive window held the caller forever.
    // Nobody reads this connection's frames, so they fill its send queue and sending itself waits.
    let conn = Arc::new(Connection::new("GRD-STUCK001", 120.0, 10.0, Duration::from_secs(3600)));
    for _ in 0..100 {
        let conn = conn.clone();
        tokio::spawn(async move { conn.call("Heartbeat", json!({}), None).await });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let failure = conn.call("Reset", json!({"type": "Soft"}), Some(Duration::from_millis(200))).await.unwrap_err();
    assert!(failure.code == "Timeout" && started.elapsed() < Duration::from_secs(2), "{failure}");
}

#[tokio::test]
async fn call_reports_a_dead_socket_as_disconnected() {
    const SERIAL: &str = "GRD-DEAD0001";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    let conn = server.controller().lock().connections[SERIAL].clone();
    cp.vanish();
    let failure = conn.call("Reset", json!({}), Some(Duration::from_secs(5))).await.unwrap_err();
    assert_eq!(failure.code, "Disconnected");
}

// Bounded memory per connection.

#[tokio::test]
async fn oversized_frame_is_refused() {
    let server = TestServer::start().await;
    let cp = charger(&server, "GRD-L0000HARD9").await;
    cp.send_text(&json!([2, "big", "DataTransfer", {"data": "x".repeat(MAX_FRAME_BYTES + 1)}]).to_string());
    wait_until("the server to close the connection", Duration::from_secs(5), || cp.close_code().is_some()).await;
    assert_eq!(cp.close_code(), Some(1009)); // message too big
}

#[tokio::test]
async fn large_frames_are_not_kept_in_the_frame_log() {
    const SERIAL: &str = "GRD-L000HARD10";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    for _ in 0..5 {
        assert_eq!(cp.call("DataTransfer", json!({"vendorId": "v", "data": "x".repeat(100_000)})).await[0], 3);
    }
    let conn = server.controller().lock().connections[SERIAL].clone();
    assert!(conn.log_size().1 < 5_000); // what is actually held in memory
    let frames = conn.frames();
    assert!(frames.iter().any(|entry| entry["data"]["bytes"].as_u64().is_some_and(|bytes| bytes > 100_000)));
    assert!(frames.iter().any(|entry| entry["label"] == "-> result DataTransfer" && entry["data"][0] == 3));
    let station = stored(&server, SERIAL);
    let transfers = station["dataTransfers"].as_array().unwrap();
    assert_eq!(transfers.len(), 5);
    assert!(transfers.iter().all(|item| item["data"].as_str().unwrap().len() == 1000));
}

#[tokio::test]
async fn boot_and_configuration_payloads_are_stored_bounded() {
    const SERIAL: &str = "GRD-L000HARD11";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    // About 150 KiB: under the frame limit, far more than we keep.
    let long = json!({"key": "Long", "value": "v".repeat(5000)});
    let mut entries = vec![json!({"key": ["bad"], "value": "x"}), json!("junk"), long];
    entries.extend((0..2000).map(|i| json!({"key": format!("K{i}"), "value": "v".repeat(40)})));
    cp.reply_with("GetConfiguration", json!({"configurationKey": entries}));
    let boot = json!({
        "chargePointModel": format!("GRD {}", "M".repeat(5000)),
        "firmwareVersion": "1.0",
        "junk": "j".repeat(100_000),
        "deep": {"a": 1},
    });
    assert_eq!(cp.call("BootNotification", boot).await[0], 3);
    let station = stored(&server, SERIAL);
    assert_eq!(keys(&station["boot"]), ["chargePointModel", "firmwareVersion", "timestamp"]);
    assert_eq!(station["boot"]["chargePointModel"].as_str().unwrap().len(), 100);
    assert_eq!(station["model"]["code"].as_str().unwrap().len(), 100);
    let read = || stored(&server, SERIAL)["config"].as_object().is_some_and(|config| !config.is_empty());
    wait_until("the configuration to be read", Duration::from_secs(6), read).await;
    let station = stored(&server, SERIAL);
    let config = station["config"].as_object().unwrap();
    assert!(config.len() < MAX_CONFIG_KEYS);
    assert_eq!(config["Long"].as_str().unwrap().len(), 500);
    assert!(config.values().all(|value| value.as_str().is_some_and(|value| value.len() <= 500)));
}

#[tokio::test]
async fn many_meter_values_in_one_message_are_capped() {
    const SERIAL: &str = "GRD-L000HARD12";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    let one = json!({"sampledValue": [{"value": "230", "measurand": "Voltage"}]});
    assert_eq!(cp.call("MeterValues", json!({"connectorId": 1, "meterValue": vec![one; 500]})).await[0], 3);
    let rows = server.controller().lock().store.samples(SERIAL, "", None, 2000).unwrap().len();
    assert_eq!(rows, 16); // the controller's MAX_METER_VALUES
}

// Frames that aren't quite OCPP.

#[tokio::test]
async fn pending_calls_fail_when_the_read_loop_ends_abnormally() {
    const SERIAL: &str = "GRD-BOOM0001";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    cp.set_answer(false);
    let conn = server.controller().lock().connections[SERIAL].clone();
    let waiter = tokio::spawn(async move { conn.call("Reset", json!({}), None).await });
    wait_for("the call to reach the charger", || !cp.calls("Reset").is_empty()).await;
    cp.vanish(); // no close frame: the transport is simply gone
    let outcome = tokio::time::timeout(Duration::from_secs(5), waiter).await.expect("the call ends with the socket");
    assert_eq!(outcome.unwrap().unwrap_err().code, "Disconnected");
}
