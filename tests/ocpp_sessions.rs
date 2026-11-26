//! What a hostile or broken charger can no longer do to sessions, current limits, the history and
//! the logs (the second half of pytests/test_hardening_ocpp.py): transaction ids are never reused,
//! a session's energy is right under either register convention, a limit that was applied is
//! lifted again, the history stays bounded, and saving and logging survive whatever is reported.

mod support;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use grizzle_local::controller::Controller;
use grizzle_local::ocpp::MAX_FRAME_DEPTH;
use grizzle_local::state::Transaction;
use grizzle_local::store::{Sample, Store};
use grizzle_local::timeutil::parse_iso;
use serde_json::{json, Value};

use support::{capture_logs, logged, settings, wait_for, wait_until, Connect, RawCharger, TestServer};

/// The station of the tests that call a controller directly. A test that starts a server uses a
/// serial of its own, because all of them share one log.
const SERIAL: &str = "GRD-L0000SESS0";

/// A charger connected as `serial`, presenting no credentials at all.
async fn charger(server: &TestServer, serial: &str) -> RawCharger {
    RawCharger::connect(server, serial, None).await.expect("the charger is admitted")
}

fn status(status: &str) -> Value {
    json!({"connectorId": 1, "status": status, "errorCode": "NoError"})
}

/// Put a state.json where a server or controller started on `dir` will find it.
fn save_state(dir: &Path, state: &str) {
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(dir.join("data/state.json"), state).unwrap();
}

/// A server that starts on this state.json: what an earlier run, or an older version, left behind.
async fn server_on(state: Value, pairs: &[(&str, &str)]) -> TestServer {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    save_state(dir.path(), &state.to_string());
    let settings = settings(dir.path(), pairs);
    TestServer::with_settings(dir, settings).await
}

/// Wait for the controller's loop (once a second) to come round, and for what it starts for each
/// station to be done.
async fn next_tick(server: &TestServer) {
    server.controller().mark_dirty();
    wait_for("the next tick", || !server.controller().lock().dirty).await; // every tick ends by saving
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// The limits of the charging profiles the server has sent, in amps.
fn limits_sent(cp: &RawCharger) -> Vec<f64> {
    let limit = |call: &Value| call["csChargingProfiles"]["chargingSchedule"]["chargingSchedulePeriod"][0]["limit"].as_f64();
    cp.calls("SetChargingProfile").iter().map(|call| limit(call).expect("a limit")).collect()
}

/// A controller on its own, with nothing listening: for tests that call its handlers directly.
fn controller(dir: &Path) -> Arc<Controller> {
    Controller::open(Arc::new(settings(dir, &[]))).unwrap()
}

/// What the controller answers when SERIAL's charger sends this.
fn handle(controller: &Arc<Controller>, action: &str, payload: Value) -> Value {
    controller.handle(SERIAL, action, payload.as_object().unwrap()).unwrap()
}

/// A StartTransaction for connector 1 with this meterStart and no timestamp.
fn start(meter_start: i64) -> Value {
    json!({"connectorId": 1, "idTag": "t", "meterStart": meter_start})
}

/// Send SERIAL's StartTransaction; the transaction id it is given.
fn begin(controller: &Arc<Controller>, payload: Value) -> i64 {
    handle(controller, "StartTransaction", payload)["transactionId"].as_i64().unwrap()
}

/// A MeterValues message for connector 1 with one reading of the energy register.
fn register(value: impl ToString, unit: &str) -> Value {
    let sampled = json!([{"value": value.to_string(), "measurand": "Energy.Active.Import.Register", "unit": unit}]);
    json!({"connectorId": 1, "meterValue": [{"sampledValue": sampled}]})
}

/// The session open on SERIAL's connector 1.
fn transaction(controller: &Controller) -> Transaction {
    controller.lock().stations[SERIAL].connectors[&1].transaction.clone().expect("a session is open")
}

/// A station's recorded sessions, newest first.
fn sessions(controller: &Controller, serial: &str) -> Vec<Value> {
    controller.lock().store.sessions(serial, 1000).unwrap().into_iter().map(Value::Object).collect()
}

/// SERIAL's recorded session with this id.
fn session(controller: &Controller, tid: i64) -> Value {
    sessions(controller, SERIAL).into_iter().find(|session| session["id"] == tid).expect("the session is recorded")
}

/// Record a session for SERIAL in the history itself, as an earlier run would have; false if refused.
fn record(store: &mut Store, tid: i64, start_at: &str) -> bool {
    store.start_session(tid, SERIAL, 1, Some("t"), start_at, Some(0), Some(0.1)).is_ok()
}

fn close_to(actual: f64, expected: f64) -> bool {
    (actual - expected).abs() <= 1e-6 * expected.abs()
}

#[tokio::test]
async fn remote_start_works_after_a_host_reboot() {
    // lastRemoteStart was a monotonic-clock reading. Saved, then read back after the host rebooted
    // (clock near zero again), it looked like "tried a moment ago" for days: no car could start.
    const SERIAL: &str = "GRD-L0000SESS1";
    let connector = json!({"id": 1, "status": "Available", "mode": "Active", "transaction": null, "lastRemoteStart": 9e9});
    let station = json!({"id": SERIAL, "connectorCount": 1, "connectors": {"1": connector}, "pricesByZone": []});
    let server = server_on(json!({"stations": {SERIAL: station}}), &[]).await;
    // The charger reconnects; one that kept running sends no BootNotification (which would reset the limiter).
    let cp = charger(&server, SERIAL).await;
    assert_eq!(cp.call("StatusNotification", status("Preparing")).await[0], 3);
    wait_until("RemoteStartTransaction", Duration::from_secs(4), || !cp.calls("RemoteStartTransaction").is_empty()).await;
}

// History survives a lost state file.

#[test]
fn transaction_ids_never_reuse_recorded_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(dir.path());
    for _ in 0..3 {
        let tid = begin(&controller, start(1000));
        handle(&controller, "StopTransaction", json!({"transactionId": tid, "meterStop": 2000}));
    }
    controller.save();
    drop(controller);
    fs::remove_file(dir.path().join("data/state.json")).unwrap(); // state lost (or reset as corrupt); history.sqlite is still there

    let controller = self::controller(dir.path());
    assert_eq!(begin(&controller, start(2000)), 4);
    let sessions = sessions(&controller, SERIAL);
    let closed = sessions.iter().filter(|session| !session["stop_at"].is_null()).count();
    assert_eq!((sessions.len(), closed), (4, 3)); // nothing was overwritten
}

#[test]
fn state_file_that_is_not_an_object_is_set_aside() {
    // The unit test of the same name in src/store.rs has an array, a string and a cut-off object.
    // These are the others: JSON that is no container at all, and nesting no parser should follow.
    for content in ["12".to_string(), "null".to_string(), "[".repeat(50_000)] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("state.json"), &content).unwrap();
        let (_store, state) = Store::open(dir.path()).unwrap();
        assert!(state.is_empty(), "{content:.20}");
        assert!(fs::read_to_string(dir.path().join("state.corrupt.json")).unwrap() == content, "{content:.20}");
    }
}

// Logs.

#[tokio::test]
async fn charger_controlled_text_is_logged_on_one_line() {
    const SERIAL: &str = "GRD-L0000SESS2";
    capture_logs();
    let server = TestServer::start().await;
    let evil = "X\n2026-11-13 00:00:00,000 INFO grizzle_local: GRD-FORGED001 connected";
    let cp = charger(&server, SERIAL).await;
    cp.reply_with("ChangeConfiguration", json!({"status": evil}));
    assert_eq!(cp.call(evil, json!({"k": evil})).await[0], 4); // an action nobody implements
    assert_eq!(cp.call("StatusNotification", json!({"connectorId": 1, "status": evil, "errorCode": evil})).await[0], 3);
    assert_eq!(cp.call("BootNotification", json!({"chargePointModel": evil, "firmwareVersion": evil})).await[0], 3);
    assert_eq!(cp.call("DataTransfer", json!({"vendorId": evil, "data": evil})).await[0], 3);
    assert_eq!(cp.call("StopTransaction", json!({"transactionId": evil, "reason": evil})).await[0], 3);
    cp.send_text("not json at all\nINFO forged");
    cp.send_text(&json!([2, 5.5, evil, {}]).to_string());
    wait_until("ChangeConfiguration", Duration::from_secs(6), || !cp.calls("ChangeConfiguration").is_empty()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    cp.close().await;

    let ours = logged(SERIAL);
    assert!(ours.len() > 5, "{ours:?}");
    // The text did reach the log, and every time inside a line about this charger.
    assert!(ours.iter().any(|line| line.contains("X\\n2026-11-13")), "{ours:?}");
    for line in logged("GRD-FORGED001") {
        assert!(line.contains(SERIAL) && !line.contains(['\n', '\r']), "{line:?}");
    }
}

// Sessions: retransmissions, and a register that outgrows its starting point.

#[tokio::test]
async fn retransmitted_start_transaction_gets_the_same_transaction() {
    // OCPP tells a charger to repeat a request whose answer it never saw. Each repeat used to open
    // another session and leave the previous one open in the history for ever.
    const SERIAL: &str = "GRD-L0000SESS3";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    let start = json!({"connectorId": 1, "idTag": "tag", "meterStart": 1000, "timestamp": "2026-11-08T16:12:17Z"});
    let first = cp.call("StartTransaction", start.clone()).await[2]["transactionId"].clone();
    let again = cp.call("StartTransaction", start.clone()).await[2]["transactionId"].clone();
    assert_eq!(again, first);
    assert_eq!(sessions(server.controller(), SERIAL).len(), 1);

    // A different session on the same connector: the open one is closed, not orphaned.
    let mut other = start;
    other["meterStart"] = json!(1500);
    other["timestamp"] = json!("2026-11-08T17:00:00Z");
    let second = cp.call("StartTransaction", other).await[2]["transactionId"].clone();
    assert_ne!(second, first);
    let recorded = sessions(server.controller(), SERIAL);
    let of = |tid: &Value| recorded.iter().find(|session| session["id"] == *tid).expect("the session is recorded");
    assert!(of(&first)["stop_at"] == "2026-11-08T17:00:00.000Z" && of(&first)["reason"] == "Superseded");
    assert!(of(&second)["stop_at"].is_null());
    let open = server.controller().lock().stations[SERIAL].connectors[&1].transaction.as_ref().map(|tx| tx.id);
    assert_eq!(json!(open), second);
}

#[test]
fn session_relative_register_may_outgrow_meter_start() {
    // A nearly new charger: 5 kWh on the lifetime register, then a 20 kWh session. The firmware's
    // MeterValues count from 0; once they passed 5000 they were suddenly taken for lifetime readings
    // and the session's energy fell back to almost nothing (and its cost with it).
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(dir.path());
    handle(&controller, "Heartbeat", json!({})); // the station exists from its first message on
    controller.set_base_rate(SERIAL, &json!(0.10)).unwrap();
    begin(&controller, start(5000));

    let energies = [0, 2500, 4999, 5000, 5001, 12000, 19950].map(|wh| {
        handle(&controller, "MeterValues", register(wh, "Wh"));
        transaction(&controller).energy
    });
    assert_eq!(energies, [0.0, 2500.0, 4999.0, 5000.0, 5001.0, 12000.0, 19950.0]);
    let tx = transaction(&controller);
    assert!(tx.session_relative_register == Some(true) && close_to(tx.price_total, 1.995), "{tx:?}");
    let total = || controller.lock().stations[SERIAL].connectors[&1].total_energy_wh;
    assert_eq!(total(), Some(24950.0));

    handle(&controller, "StopTransaction", json!({"transactionId": 1, "meterStop": 20000})); // session-relative too
    assert_eq!(session(&controller, 1)["energy_wh"], 20000.0);
    assert_eq!(total(), Some(25000.0));
}

#[test]
fn meter_stop_is_read_in_whichever_convention_fits() {
    let cases: [(i64, &[i64], i64, f64); 5] = [
        (819_392, &[0, 1500], 2000, 2000.0),       // the Duo: lifetime start, session-relative everything else
        (819_392, &[0, 1500], 821_392, 2000.0),    // session-relative MeterValues, lifetime meterStop
        (500_000, &[500_000, 501_500], 502_000, 2000.0), // a charger that reports the lifetime register throughout
        (500_000, &[], 502_000, 2000.0),           // no MeterValues at all
        (5000, &[], 3000, 3000.0),                 // ...and a meterStop that can only be session-relative
    ];
    for (meter_start, readings, meter_stop, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let controller = controller(dir.path());
        begin(&controller, start(meter_start));
        for wh in readings {
            handle(&controller, "MeterValues", register(wh, "Wh"));
        }
        handle(&controller, "StopTransaction", json!({"transactionId": 1, "meterStop": meter_stop}));
        assert_eq!(session(&controller, 1)["energy_wh"], expected, "{meter_start} {readings:?} {meter_stop}");
    }
}

// Current limits.

#[tokio::test]
async fn a_windows_current_limit_is_lifted_when_the_window_ends() {
    // A window with its own limit throttled the charger, and when the window ended (or was switched
    // off, or deleted) nothing ever gave the current back: the charger stayed at 16 A for good.
    const SERIAL: &str = "GRD-L0000SESS4";
    let server = TestServer::start().await;
    let controller = server.controller();
    let cp = charger(&server, SERIAL).await;
    assert_eq!(cp.call("StatusNotification", status("Available")).await[0], 3);
    next_tick(&server).await; // so that the loop's own round does not fall in the middle of what follows
    let night = json!({"name": "Night", "isSchedule": true, "allDay": true, "days": [], "currentLimit": 16});
    let zone = controller.upsert_zone(SERIAL, &night).await.unwrap();
    let zone = zone["_id"].as_str().unwrap();
    let in_force = || {
        let inner = controller.lock();
        (inner.stations[SERIAL].applied_limit, inner.stations[SERIAL].limit_in_force)
    };
    assert_eq!(limits_sent(&cp), [16.0]);
    assert_eq!(in_force(), (Some(16), true));

    controller.set_zone_enabled(SERIAL, zone, false).await.unwrap(); // the window is over
    assert_eq!(limits_sent(&cp), [16.0, 40.0]); // back to the station's full current
    assert_eq!(in_force(), (Some(40), false));
    for _ in 0..3 {
        next_tick(&server).await;
    }
    assert_eq!(limits_sent(&cp), [16.0, 40.0]); // once; and a charger we never limited is left alone

    // With a station-wide limit, the end of the window falls back to that instead.
    controller.set_current_limit(SERIAL, 24).await.unwrap();
    controller.set_zone_enabled(SERIAL, zone, true).await.unwrap();
    controller.set_zone_enabled(SERIAL, zone, false).await.unwrap();
    assert_eq!(limits_sent(&cp), [16.0, 40.0, 24.0, 16.0, 24.0]);
}

#[tokio::test]
async fn a_limit_outside_the_chargers_range_is_sent_once() {
    const SERIAL: &str = "GRD-L0000SESS5";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    assert_eq!(cp.call("StatusNotification", status("Available")).await[0], 3);
    next_tick(&server).await;
    let trickle = json!({"name": "Trickle", "isSchedule": true, "allDay": true, "days": [], "currentLimit": 3});
    server.controller().upsert_zone(SERIAL, &trickle).await.unwrap();
    for _ in 0..4 {
        next_tick(&server).await;
    }
    assert_eq!(limits_sent(&cp), [6.0]); // clamped to the minimum, and not repeated on every tick
}

#[tokio::test]
async fn a_limit_left_in_force_by_an_older_version_is_lifted() {
    const SERIAL: &str = "GRD-L0000SESS6";
    let connector = json!({"id": 1, "status": "Available", "mode": "Active", "transaction": null});
    let mut station = json!({"id": SERIAL, "connectorCount": 1, "connectors": {"1": connector}, "pricesByZone": []});
    station["appliedLimit"] = json!(16); // applied for a window that has since ended; never lifted
    let server = server_on(json!({"stations": {SERIAL: station}}), &[]).await;
    let cp = charger(&server, SERIAL).await;
    wait_until("the limit to be lifted", Duration::from_secs(4), || limits_sent(&cp) == [40.0]).await;
}

// Saving must survive whatever a charger reports.

#[tokio::test]
async fn non_string_configuration_keys_do_not_break_saving() {
    // An integer key next to string keys made saving fail from then on: nothing was persisted any
    // more, while the server looked perfectly healthy.
    const SERIAL: &str = "GRD-L0000SESS7";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    let keys = json!([
        {"key": 1, "value": "x"},
        {"key": 2.5, "value": "x"},
        {"key": true, "value": "x"},
        {"key": null, "value": "x"},
        {"key": "HeartbeatInterval", "value": 300},
    ]);
    cp.reply_with("GetConfiguration", json!({"configurationKey": keys}));
    assert_eq!(cp.call("BootNotification", json!({"chargePointModel": "GRD 40A"})).await[0], 3);
    let config = || Value::Object(server.controller().lock().stations[SERIAL].config.clone());
    wait_until("the configuration to be read", Duration::from_secs(6), || config() != json!({})).await;
    assert_eq!(config(), json!({"HeartbeatInterval": "300"}));
    server.controller().mark_dirty();
    server.controller().save();
    assert!(server.saved_state()["stations"][SERIAL].is_object());
}

// Repricing a deep history.

/// How many write transactions history.sqlite has seen: SQLite counts them in the file's header.
fn commits(dir: &Path) -> u32 {
    let file = fs::read(dir.join("data/history.sqlite")).unwrap();
    u32::from_be_bytes(file[24..28].try_into().unwrap())
}

#[test]
fn recalculating_costs_uses_one_transaction_and_the_index() {
    // Each session cost one full scan of the station's samples and one commit, all with every
    // charger waiting: with a real history, a button press took seconds. (That the query uses its
    // index is checked next to it, by the_history_queries_use_their_indexes in src/store.rs.)
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(dir.path());
    handle(&controller, "Heartbeat", json!({}));
    controller.set_base_rate(SERIAL, &json!(0.20)).unwrap();
    {
        let mut inner = controller.lock();
        for tid in 1..=200 {
            let day = format!("2026-10-{:02}", 1 + tid % 28);
            inner.store.start_session(tid, SERIAL, 1, Some("t"), &format!("{day}T10:00:00.000Z"), Some(0), Some(0.0)).unwrap();
            let samples: Vec<Sample> = (0..30)
                .map(|minute| Sample {
                    station: SERIAL.to_string(),
                    connector: 1,
                    transaction_id: Some(tid),
                    at: format!("{day}T10:{minute:02}:00.000Z"),
                    energy_wh: Some(f64::from(minute) * 100.0),
                    ..Sample::default()
                })
                .collect();
            inner.store.add_samples(&samples).unwrap();
            let stop_at = format!("{day}T11:00:00.000Z");
            inner.store.finish_session(tid, &stop_at, Some(3000), Some(3000.0), Some(3600), Some(0.0), Some("Local"), None).unwrap();
        }
    }
    let before = commits(dir.path());
    let result = controller.recalculate_costs(SERIAL).unwrap();
    assert_eq!(commits(dir.path()), before + 1);
    assert!(result["sessions"] == 200 && close_to(result["cost_after"].as_f64().unwrap(), 200.0 * 3.0 * 0.20), "{result}");
    assert!(sessions(&controller, SERIAL).iter().all(|session| close_to(session["cost"].as_f64().unwrap(), 0.6)));
}

// Further cases for the areas above.

#[test]
fn a_lifetime_reading_rounded_just_below_meter_start_is_still_lifetime() {
    // Deciding the register convention once must not hinge on rounding: a charger that reports the
    // lifetime register in kWh with one decimal starts a hair below the exact meterStart.
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(dir.path());
    begin(&controller, start(819_392));
    handle(&controller, "MeterValues", register("819.3", "kWh")); // 92 Wh "below" the start
    let tx = transaction(&controller);
    assert_eq!((tx.session_relative_register, tx.energy), (Some(false), 0.0));
    handle(&controller, "MeterValues", register("821.4", "kWh"));
    assert!(close_to(transaction(&controller).energy, 2008.0)); // not 821 400

    // A register that really counts from zero is still recognised, next to a small lifetime total too.
    for (meter_start, first) in [(819_392, "0"), (5000, "0.01"), (300, "0")] {
        let dir = tempfile::tempdir().unwrap();
        let controller = self::controller(dir.path());
        begin(&controller, start(meter_start));
        handle(&controller, "MeterValues", register(first, "kWh"));
        assert_eq!(transaction(&controller).session_relative_register, Some(true), "{meter_start}");
    }
}

#[test]
fn a_session_reported_by_an_unset_clock_keeps_its_length() {
    // A charger whose clock was never set (1970) reports a session after the fact. Both ends are
    // stamped with the time we heard of them, milliseconds apart; the charger's clock, wrong date
    // and all, still measured how long the session was.
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(dir.path());
    let started = |meter_start: i64, timestamp: &str| {
        let mut payload = start(meter_start);
        payload["timestamp"] = json!(timestamp);
        begin(&controller, payload);
    };
    started(1000, "1970-01-01T00:10:00Z");
    handle(&controller, "StopTransaction", json!({"transactionId": 1, "meterStop": 8000, "timestamp": "1970-01-01T01:40:00Z"}));
    let recorded = session(&controller, 1);
    assert_eq!(recorded["duration_s"], 90 * 60);
    let start_at = parse_iso(recorded["start_at"].as_str().unwrap()).unwrap();
    assert!((Utc::now() - start_at).num_seconds().abs() < 60); // the dates are ours

    // With a sane clock nothing changes; and a clock that runs backwards is not believed.
    started(8000, "2026-11-08T16:12:17Z");
    handle(&controller, "StopTransaction", json!({"transactionId": 2, "timestamp": "2026-11-08T17:00:00Z"}));
    assert_eq!(session(&controller, 2)["duration_s"], 2863);
    started(8000, "1970-01-02T00:00:00Z");
    handle(&controller, "StopTransaction", json!({"transactionId": 3, "timestamp": "1970-01-01T00:00:00Z"}));
    assert!(session(&controller, 3)["duration_s"].as_i64().unwrap() < 5);
}

#[tokio::test]
async fn forgetting_a_station_removes_its_history() {
    const SERIAL: &str = "GRD-L0000SESS8";
    const KEPT: &str = "GRD-KEEP0001";
    let server = TestServer::start().await;
    for serial in [SERIAL, KEPT] {
        let cp = charger(&server, serial).await;
        let tid = cp.call("StartTransaction", start(0)).await[2]["transactionId"].clone();
        let sampled = json!([{"value": "230", "measurand": "Voltage"}]);
        cp.call("MeterValues", json!({"connectorId": 1, "meterValue": [{"sampledValue": sampled}]})).await;
        cp.call("StopTransaction", json!({"transactionId": tid, "meterStop": 10})).await;
        cp.close().await;
    }
    wait_for("the charger to be offline", || !server.controller().is_online(SERIAL)).await;
    let token = server.login().await;
    assert_eq!(server.delete(&format!("/local/stations/{SERIAL}"), Some(&token)).await.status, 200);
    let inner = server.controller().lock();
    for table in ["sessions", "samples"] {
        let mut query = inner.store.database().prepare(&format!("SELECT DISTINCT station FROM {table}")).unwrap();
        let left: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(left, [KEPT], "{table}");
    }
}

#[test]
fn an_impossible_transaction_counter_does_not_stop_sessions() {
    // A counter in state.json beyond what the history database can store (a damaged or hand-edited
    // file) was handed out as it was, and from then on no session could be recorded at all.
    let counters =
        ["1000000000000000000000000000000", "9223372036854775808", "9223372036854775807", "0", "-5", "\"7\"", "2.5", "true", "null", "[9]"];
    for counter in counters {
        let dir = tempfile::tempdir().unwrap();
        save_state(dir.path(), &format!("{{\"next_transaction_id\": {counter}}}"));
        let controller = controller(dir.path());
        assert!(record(&mut controller.lock().store, i64::MAX, "2026-10-31T10:00:00.000Z")); // recorded under such an id
        for expected in [1, 2] {
            let payload = json!({"connectorId": expected, "idTag": "t", "meterStart": 0});
            assert_eq!(begin(&controller, payload), expected, "{counter}");
        }
        assert_eq!(controller.lock().to_json()["next_transaction_id"], 3, "{counter}");
    }
}

#[test]
fn large_transaction_ids_that_can_be_stored_keep_counting() {
    // The limit is what the database can hold. Numbering that is merely far along carries on as it
    // always did; cutting it off lower would leave a counter that hands out the same id for ever.
    const FAR: i64 = 1 << 62;
    let cases: [(Option<i64>, &[i64], i64); 7] = [
        (Some(FAR), &[], 5),
        (Some(FAR - 1), &[], 5),
        (None, &[FAR - 1], 5),
        (None, &[FAR], 5),
        (Some(5), &[FAR, FAR + 1], 5),
        (Some(i64::MAX - 8), &[3], 5),
        (Some(i64::MAX - 1), &[], 2), // the last counter that can be continued from, and the last id there is
    ];
    for (counter, recorded, rounds) in cases {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = Store::open(&dir.path().join("data")).unwrap();
            for tid in recorded {
                assert!(record(&mut store, *tid, "2026-10-31T10:00:00.000Z"));
            }
        }
        save_state(dir.path(), &json!({"next_transaction_id": counter}).to_string());
        let controller = controller(dir.path());
        let first = counter.unwrap_or(1).max(recorded.iter().max().map_or(0, |newest| newest + 1));
        for round in 0..rounds {
            assert_eq!(begin(&controller, start(0)), first + round, "{counter:?} {recorded:?}");
        }
    }
}

#[test]
fn transaction_ids_follow_the_history_at_every_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(dir.path());
    assert_eq!(begin(&controller, start(0)), 1);
    assert!(record(&mut controller.lock().store, 50, "2026-11-01T10:00:00.000Z")); // the history is ahead of the counter
    assert_eq!(begin(&controller, start(0)), 51);
    // And an id can no longer silently replace a session.
    assert!(!record(&mut controller.lock().store, 50, "2026-11-02T10:00:00.000Z"));
    assert_eq!(session(&controller, 50)["start_at"], "2026-11-01T10:00:00.000Z");
}

#[tokio::test]
async fn saving_survives_odd_keys_and_a_failed_save_does_not_refuse_a_charger() {
    // The first half of the Python test (keys in a station that are not text) has nothing to
    // test here: a station is typed, and what is saved cannot have such keys.
    const SERIAL: &str = "GRD-NEWPIN01";
    capture_logs();
    let server = TestServer::start().await;
    // No save can succeed from here on: its temporary file cannot be created.
    fs::create_dir(server.data_dir().join("state.tmp")).unwrap();
    let cp = RawCharger::connect(&server, SERIAL, Some((SERIAL, "its-key"))).await.expect("the charger is admitted");
    assert_eq!(cp.call("Heartbeat", json!({})).await[0], 3); // connected, although the pin could not be saved yet
    assert_eq!(server.controller().lock().stations[SERIAL].ocpp_auth_key.as_deref(), Some("its-key"));
    assert!(!logged("saving state failed").is_empty());
}

#[tokio::test]
async fn frames_nested_absurdly_deep_are_dropped() {
    // What parse_frame makes of such frames is tested next to it, in src/ocpp.rs.
    const SERIAL: &str = "GRD-L0000SESS9";
    capture_logs();
    let mut nested = json!("x");
    for _ in 0..MAX_FRAME_DEPTH + 5 {
        nested = json!([nested]);
    }
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    cp.send_text(&json!([3, "u", {"a": nested}]).to_string());
    cp.send_text(&json!([2, "v", "DataTransfer", {"vendorId": "x", "data": nested}]).to_string());
    assert_eq!(cp.call("Heartbeat", json!({})).await[0], 3);
    assert!(server.controller().lock().stations[SERIAL].data_transfers.is_empty());
    let token = server.login().await;
    let log = server.get(&format!("/local/stations/{SERIAL}/log"), Some(&token)).await;
    assert_eq!(log.status, 200);
    log.json();
    let failures: Vec<String> = logged(SERIAL).into_iter().filter(|line| line.contains(" ERROR ")).collect();
    assert!(failures.is_empty(), "{failures:?}");
}

#[tokio::test]
async fn status_text_is_cleaned_like_every_other_field() {
    // The Python server took a lone surrogate in a status and cleaned it out of what it stored.
    // Here such a frame is not JSON and is dropped whole, so what there is to check is that it
    // leaves nothing behind, not even in the frame log (which keeps unreadable frames as text).
    const SERIAL: &str = "GRD-L0000SESSA";
    let server = TestServer::start().await;
    let cp = charger(&server, SERIAL).await;
    cp.send_text(r#"[2,"s1","StatusNotification",{"connectorId":1,"status":"Odd\udcff","errorCode":"NoError"}]"#);
    cp.send_text(r#"[2,"s2","StatusNotification",{"connectorId":0,"status":"Odd\ud800"}]"#);
    assert_eq!(cp.call("BootNotification", json!({"chargePointModel": "GRD 40A"})).await[0], 3);
    {
        let inner = server.controller().lock();
        let station = &inner.stations[SERIAL];
        assert!(station.status.is_none() && station.connectors[&1].status.is_none());
    }
    let token = server.login().await;
    let log = server.get(&format!("/local/stations/{SERIAL}/log"), Some(&token)).await;
    let unreadable = log.json()["frames"].as_array().unwrap().iter().filter(|frame| frame["label"] == "unparseable").count();
    assert_eq!((log.status, unreadable), (200, 2));
}

#[tokio::test]
async fn a_charger_without_an_id_keeps_the_station_it_had() {
    // A charger that sends no id is named after its address. An older version knew it by the
    // address of whatever stood in front of the server; now that the real address is known it
    // would have become a new station, without its mode, schedules or history. (In Python that
    // was the built-in TLS front end. There is none here, so a trusted proxy plays the part.)
    for (known, expected) in [
        (vec![], "unknown-192.168.1.50"),
        (vec!["unknown-127.0.0.1"], "unknown-127.0.0.1"),
        (vec!["unknown-127.0.0.1", "unknown-192.168.1.50"], "unknown-192.168.1.50"),
    ] {
        let stations: serde_json::Map<String, Value> = known.iter().map(|id| (id.to_string(), json!({"id": id}))).collect();
        let server = server_on(json!({"stations": stations}), &[("GRIZZLE_TRUSTED_PROXIES", "127.0.0.1")]).await;
        let how = Connect::path("/ocpp1.6").header("X-Forwarded-For", "192.168.1.50");
        let cp = RawCharger::connect_with(&server, &how).await.expect("the charger is admitted");
        assert_eq!(cp.call("Heartbeat", json!({})).await[0], 3);
        assert!(server.controller().is_online(expected), "{known:?}");
    }
}

#[tokio::test]
async fn the_read_loop_applies_the_rate_limit() {
    // The read loop has to call the limiter: the unit test of the limiter itself passes without that.
    const SERIAL: &str = "GRD-FLOOD002";
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let mut settings = settings(dir.path(), &[]);
    settings.rate_burst = 10.0;
    settings.rate_per_second = 1000.0;
    let server = TestServer::with_settings(dir, settings).await;
    let cp = charger(&server, SERIAL).await;
    let started = Instant::now();
    for _ in 0..60 {
        cp.send_text(r#"[3,"nobody-asked",{}]"#);
    }
    assert_eq!(cp.call("Heartbeat", json!({})).await[0], 3);
    assert!(started.elapsed() >= Duration::from_millis(45)); // 50 frames beyond the burst, at 1000 a second
    let frames = server.controller().lock().connections[SERIAL].frames();
    assert_eq!(frames.iter().filter(|frame| frame["label"] == "<- result").count(), 60);
}

#[test]
fn pruning_removes_what_is_older_than_the_limit_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, _) = Store::open(dir.path()).unwrap();
    let days_ago = [120.0, 91.0, 90.01, 89.99, 89.0, 1.0, 0.0];
    let rows: Vec<Sample> = (0..)
        .zip(days_ago)
        .map(|(n, days)| {
            let at = Utc::now() - chrono::Duration::seconds((days * 86_400.0) as i64);
            let at = at.format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
            Sample { station: SERIAL.to_string(), connector: 1, at, voltage_v: Some(f64::from(n)), ..Sample::default() }
        })
        .collect();
    store.add_samples(&rows).unwrap();
    store.prune_samples(90).unwrap();
    let left = store.samples(SERIAL, "2000-01-01", None, 100).unwrap();
    let left: Vec<f64> = left.iter().map(|row| row["voltage_v"].as_f64().unwrap()).collect();
    assert_eq!(left, [3.0, 4.0, 5.0, 6.0]); // to the minute, not "the whole day of the cutoff"
}

#[tokio::test]
async fn long_fields_and_many_sampled_values_are_cut_to_size() {
    const SERIAL: &str = "GRD-L0000SESSB";
    let server = TestServer::start().await;
    let long = "L".repeat(5000);
    let how = Connect::path(&format!("/ocpp1.6/{SERIAL}?{}", "q".repeat(3000)));
    let cp = RawCharger::connect_with(&server, &how).await.expect("the charger is admitted");
    let status = json!({"connectorId": 1, "status": long, "errorCode": long, "vendorErrorCode": long, "info": long});
    assert_eq!(cp.call("StatusNotification", status).await[0], 3);
    assert_eq!(cp.call("StartTransaction", json!({"connectorId": 1, "idTag": long, "meterStart": 0})).await[0], 3);
    let many: Vec<Value> = (0..500).map(|n| json!({"value": n.to_string(), "measurand": "Voltage", "phase": "L1"})).collect();
    assert_eq!(cp.call("MeterValues", json!({"connectorId": 1, "meterValue": [{"sampledValue": many}]})).await[0], 3);

    let inner = server.controller().lock();
    let station = &inner.stations[SERIAL];
    let connector = &station.connectors[&1];
    let len = |text: &Option<String>| text.as_deref().map_or(0, str::len);
    assert_eq!((len(&connector.status), len(&connector.error_code)), (32, 50));
    assert_eq!((len(&connector.vendor_error_code), len(&connector.info)), (50, 255));
    assert_eq!(len(&connector.transaction.as_ref().unwrap().id_tag), 64);
    // Only the first 64 readings of a meter value are looked at.
    assert_eq!(connector.last_meter.voltage_v, Some(63.0));
    let handshake = station.ocpp_handshake.as_ref().unwrap();
    assert!(handshake["query"].as_str().unwrap().len() == 200 && handshake.to_string().len() < 1000, "{handshake}");
}

#[test]
fn a_charger_with_an_unset_clock_repeating_itself_is_still_recognised() {
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(dir.path());
    let mut start = start(1000);
    start["timestamp"] = json!("1970-01-01T00:10:00Z");
    let first = begin(&controller, start.clone());
    let again = begin(&controller, start.clone());
    assert!(again == first && sessions(&controller, SERIAL).len() == 1);
    start["timestamp"] = json!("1970-01-01T05:00:00Z"); // a different session by the charger's own clock
    assert_ne!(begin(&controller, start), first);
}
