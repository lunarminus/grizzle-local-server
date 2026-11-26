//! Fake charger + server + the same REST calls the Home Assistant integration makes.

mod support;

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as Span, Timelike, Utc};
use grizzle_local::controller::{CommandError, Controller};
use serde_json::{json, Value};

use support::{settings, wait_for, FakeCharger, FakeOptions, TestServer, EMAIL, PASSWORD};

const SERIAL: &str = "GRD-L0000TEST1";

async fn server() -> TestServer {
    TestServer::with(&[("TZ", "America/Denver"), ("GRIZZLE_METER_INTERVAL", "1")]).await
}

fn station_path(tail: &str) -> String {
    format!("/client/stations/{SERIAL}{tail}")
}

/// A request as a signed-in client that must succeed; its JSON.
async fn api(server: &TestServer, token: &str, method: &str, path: &str, body: Value) -> Value {
    let response = server.send(method, path, Some(token), Some(&body)).await;
    assert!(response.status < 400, "{method} {path} -> {} {}", response.status, response.body);
    response.json()
}

fn close_to(actual: f64, expected: f64, relative: f64, absolute: f64) -> bool {
    (actual - expected).abs() <= (relative * expected.abs()).max(absolute)
}

/// A controller on its own, with nothing listening: for tests that call its handlers directly.
fn controller(dir: &tempfile::TempDir, pairs: &[(&str, &str)]) -> Arc<Controller> {
    Controller::open(Arc::new(settings(dir.path(), pairs))).unwrap()
}

fn handle(controller: &Arc<Controller>, action: &str, payload: Value) -> Value {
    controller.handle(SERIAL, action, payload.as_object().unwrap()).unwrap()
}

#[tokio::test]
async fn login_and_station_shape() {
    let server = server().await;
    let _charger = FakeCharger::connect(&server, SERIAL).await;
    assert_eq!(server.login_with(EMAIL, "nope").await.status, 401);
    assert_eq!(server.get("/client/stations", None).await.status, 401);
    let token = server.login().await;

    let station = server.station(&token, SERIAL).await;
    assert_eq!(station["id"], SERIAL);
    assert_eq!(station["online"], true);
    assert_eq!(station["bootNotification"]["chargePointModel"], "GRD 40A 2025");
    assert_eq!(station["model"]["displayName"], "Grizzl-E Duo");
    assert_eq!(station["connectors"].as_array().unwrap().len(), 2);
    assert_eq!((&station["connectors"][0]["connectorId"], &station["connectors"][1]["connectorId"]), (&json!(1), &json!(2)));
    assert_eq!(station["connectors"][0]["status"], "Available");
    assert_eq!(station["connectors"][0]["mode"], "Active");
    assert_eq!(station["model"]["maxCurrent"], 40);
    assert_eq!(station["model"]["minCurrent"], 16);
    let single = server.json(&token, &station_path("")).await;
    assert_eq!(single["serialNumber"], SERIAL);
    assert_eq!(server.get("/client/stations/GRD-NOBODY", Some(&token)).await.status, 404);
    assert_eq!(server.json(&token, "/client/auth/profile").await["email"], EMAIL);
}

#[tokio::test]
async fn malformed_get_configuration_is_survived() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    // The after-boot conversation sends GetConfiguration; the fake replies with the firmware's broken JSON.
    wait_for("GetConfiguration", || !charger.calls("GetConfiguration").is_empty()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!charger.is_closed());
    let token = server.login().await;
    assert_eq!(server.station(&token, SERIAL).await["online"], true);
    // Boot config was still pushed.
    let state = charger.state();
    assert_eq!(state.config["MeterValueSampleInterval"], "1");
    assert!(state.config["MeterValuesSampledData"].contains("Energy.Active.Import.Register"));
}

#[tokio::test]
async fn plug_in_starts_transaction_and_meter_values_flow() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    let token = server.login().await;
    charger.plug_in(1).await;
    wait_for("a transaction on connector 1", || charger.state().transactions.contains_key(&1)).await;
    assert!(charger.calls("RemoteStartTransaction").iter().any(|payload| payload["connectorId"] == 1));

    wait_for("connector 1 to charge", || charger.status(1) == "Charging").await;
    tokio::time::sleep(Duration::from_millis(1500)).await; // a couple of MeterValues
    let station = server.station(&token, SERIAL).await;
    let connector = &station["connectors"][0];
    assert_eq!(connector["status"], "Charging");
    let charge = &connector["charge"];
    assert!(charge.is_object());
    assert_eq!(charge["meterStart"], 501000);
    assert!(charge["energy"].as_f64().unwrap() > 0.0);
    assert!(charge["meterValues"]["voltage"][0].as_f64().unwrap() >= 237.0);
    assert_eq!(charge["meterValues"]["currentImport"][0], 32.0);
    assert_eq!(connector["power"], 32 * 240);
    assert!(station["connectors"][1]["charge"].is_null(), "connector 2 untouched");

    charger.unplug(1).await;
    wait_for("connector 1 to be available", || charger.status(1) == "Available").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let station = server.station(&token, SERIAL).await;
    assert!(station["connectors"][0]["charge"].is_null());
    let events = server.json(&token, &station_path("/events")).await;
    assert_eq!(events["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(events["sessions"][0]["reason"], "EVDisconnected");
    assert!(events["sessions"][0]["energy_wh"].as_f64().unwrap() > 0.0);
}

#[tokio::test]
async fn inactive_mode_stops_and_blocks_charging() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    let token = server.login().await;
    charger.plug_in(2).await;
    wait_for("a transaction on connector 2", || charger.state().transactions.contains_key(&2)).await;

    api(&server, &token, "POST", &station_path("/mode"), json!({"mode": "Inactive", "connectorId": 2})).await;
    wait_for("the transaction to stop", || !charger.state().transactions.contains_key(&2)).await;
    assert!(!charger.calls("RemoteStopTransaction").is_empty());
    wait_for("connector 2 back at Preparing", || charger.status(2) == "Preparing").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!charger.state().transactions.contains_key(&2), "Inactive connector must not be restarted");
    assert_eq!(server.station(&token, SERIAL).await["connectors"][1]["mode"], "Inactive");

    api(&server, &token, "POST", &station_path("/mode"), json!({"mode": "Active", "connectorId": 2})).await;
    wait_for("charging to resume", || charger.state().transactions.contains_key(&2)).await;
}

#[tokio::test]
async fn current_limit_sets_stack_level_zero_profile() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    let token = server.login().await;
    api(&server, &token, "PUT", &station_path("/currentLimit"), json!({"value": 24})).await;
    wait_for("the limit to arrive", || charger.state().limit_a == Some(24)).await;
    let payload = charger.calls("SetChargingProfile").pop().unwrap();
    let profile = &payload["csChargingProfiles"];
    assert_eq!((&payload["connectorId"], &profile["stackLevel"]), (&json!(0), &json!(0)));
    assert_eq!(profile["chargingProfilePurpose"], "TxDefaultProfile");
    assert_eq!(profile["chargingSchedule"]["chargingRateUnit"], "A");
    assert_eq!(profile["chargingSchedule"]["chargingSchedulePeriod"][0]["limit"], 24);
    let station = server.station(&token, SERIAL).await;
    assert_eq!(station["smartCharging"]["currentLimit"], 24);
    assert_eq!(station["smartCharging"]["appliedLimit"], 24);

    let refused = server.put(&station_path("/currentLimit"), Some(&token), &json!({"value": 99})).await;
    assert_eq!(refused.status, 400);
    assert_eq!(refused.json()["message"], "current limit must be between 16 and 40 A");
}

#[tokio::test]
async fn schedule_mode_follows_windows() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    let token = server.login().await;
    // A window that is not active right now: it starts in two hours and is half an hour long.
    let denver: chrono_tz::Tz = "America/Denver".parse().unwrap();
    let later = Utc::now().with_timezone(&denver) + Span::hours(2);
    let end = later + Span::minutes(30);
    let closed = json!({
        "name": "Later",
        "startHours": later.hour(), "startMinutes": later.minute(),
        "endHours": end.hour(), "endMinutes": end.minute(),
        "allDay": false, "days": [0, 1, 2, 3, 4, 5, 6], "isSchedule": true, "currentLimit": null, "connectorId": 0,
    });
    let created = api(&server, &token, "POST", &station_path("/scheduleUpdate"), json!({"price": closed})).await;
    let zone = created["_id"].as_str().unwrap().to_string();
    assert_eq!(zone.len(), 24);
    let station = server.station(&token, SERIAL).await;
    assert_eq!(station["pricesByZone"].as_array().unwrap().len(), 1);
    assert_eq!(station["pricesByZone"][0]["_id"], zone.as_str());
    assert_eq!(station["pricesByZone"][0]["scheduleEnabled"], true);
    assert_eq!(station["schedule"]["enabled"], true);

    api(&server, &token, "POST", &station_path("/mode"), json!({"mode": "Schedule", "connectorId": 0})).await;
    charger.plug_in(1).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!charger.state().transactions.contains_key(&1), "outside the window nothing should start");
    let station = server.station(&token, SERIAL).await;
    assert_eq!(station["mode"], "Schedule");
    assert_eq!(station["connectors"][0]["isActiveBySchedule"], false);
    assert!(station["connectors"][0]["nextScheduleTime"].is_string());

    // Widen the window so it covers now, with its own current limit.
    let mut open = closed.clone();
    open["_id"] = json!(zone);
    open["allDay"] = json!(true);
    open["currentLimit"] = json!(16);
    api(&server, &token, "POST", &station_path("/scheduleUpdate"), json!({"price": open})).await;
    wait_for("charging to start inside the window", || charger.state().transactions.contains_key(&1)).await;
    wait_for("the window's limit", || charger.state().limit_a == Some(16)).await;
    assert_eq!(server.station(&token, SERIAL).await["connectors"][0]["isActiveBySchedule"], true);

    // Disable the window: charging must stop.
    let disable = json!({"_id": zone, "scheduleEnabled": false});
    api(&server, &token, "POST", &station_path("/scheduleEnable"), disable).await;
    wait_for("charging to stop", || !charger.state().transactions.contains_key(&1)).await;

    let deleted = server.delete(&station_path(&format!("/scheduleDelete/{zone}")), Some(&token)).await;
    assert_eq!(deleted.status, 200);
    assert_eq!(server.station(&token, SERIAL).await["pricesByZone"], json!([]));
    assert_eq!(server.delete(&station_path(&format!("/scheduleDelete/{zone}")), Some(&token)).await.status, 404);
}

#[tokio::test]
async fn rate_and_cost() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    let token = server.login().await;
    api(&server, &token, "PUT", &station_path("/rate"), json!({"priceKW": 0.25})).await;
    assert_eq!(server.station(&token, SERIAL).await["priceKW"], 0.25);
    let start = charger.state().energy[&1];
    charger.plug_in(1).await;
    wait_for("connector 1 to charge", || charger.status(1) == "Charging").await;
    // Wait for readings rather than for a time: how many fit into two seconds depends on the machine.
    wait_for("some energy", || charger.state().energy[&1] >= start + 4).await;
    let charge = server.station(&token, SERIAL).await["connectors"][0]["charge"].clone();
    assert_eq!(charge["priceKW"], 0.25);
    let energy = charge["energy"].as_f64().unwrap();
    assert!(energy >= 1.0, "{charge}");
    // The API gives the total to 4 decimal places and the fake charger counts whole Wh, so the
    // rounding alone can be worth more than 5 %: 3 Wh cost 0.00075 and are reported as 0.0008.
    let total = charge["priceTotal"].as_f64().unwrap();
    assert!(close_to(total, energy / 1000.0 * 0.25, 0.05, 0.00005 + 1e-9), "{charge}");
}

#[tokio::test]
async fn reboot_and_raw_call() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    let token = server.login().await;
    let result = api(&server, &token, "POST", &station_path("/reboot"), json!({})).await;
    assert_eq!(result, json!({"status": "Accepted"}));
    assert!(charger.state().reset_requested);
    let call = json!({"action": "GetConfiguration", "payload": {"key": ["HeartbeatInterval"]}});
    let raw = api(&server, &token, "POST", &format!("/local/stations/{SERIAL}/ocpp"), call).await;
    assert_eq!(raw["result"]["configurationKey"][0]["key"], "HeartbeatInterval");
    let log = server.json(&token, &format!("/local/stations/{SERIAL}/log")).await;
    assert_eq!(log["online"], true);
    assert!(log["frames"].as_array().unwrap().iter().any(|frame| frame["label"] == "<- BootNotification"));
    // What the charger refuses comes back as it said it, not as a server error.
    let unknown = json!({"action": "ClearCache", "payload": {}});
    let refused = server.post(&format!("/local/stations/{SERIAL}/ocpp"), Some(&token), &unknown).await;
    assert_eq!(refused.status, 502);
    assert_eq!(refused.json()["error"], "NotImplemented");
}

#[tokio::test]
async fn token_refresh() {
    let server = server().await;
    let tokens = server.login_with(EMAIL, PASSWORD).await.json();
    let refreshed = server.post("/client/auth/refresh-token", None, &json!({"refreshToken": tokens["refreshToken"]})).await;
    assert_eq!(refreshed.status, 200);
    let new = refreshed.json();
    assert_ne!(new["token"], tokens["token"]);
    assert_eq!(server.get("/client/stations", tokens["token"].as_str()).await.status, 401);
    assert_eq!(server.get("/client/stations", new["token"].as_str()).await.status, 200);
    // A refresh token works once.
    let again = server.post("/client/auth/refresh-token", None, &json!({"refreshToken": tokens["refreshToken"]})).await;
    assert_eq!(again.status, 401);
}

#[tokio::test]
async fn state_survives_restart() {
    let server = TestServer::with(&[("GRIZZLE_API_EMAIL", "a@b"), ("GRIZZLE_API_PASSWORD", "x")]).await;
    let options = FakeOptions { path: format!("/{SERIAL}"), meter_interval: Duration::from_secs(5), ..FakeOptions::default() };
    let charger = FakeCharger::connect_with(&server, SERIAL, options).await.unwrap();
    let login = server.login_with("a@b", "x").await;
    assert_eq!(login.status, 200);
    let token = login.json()["token"].as_str().unwrap().to_string();
    api(&server, &token, "POST", &station_path("/mode"), json!({"mode": "Inactive", "connectorId": 1})).await;
    api(&server, &token, "PUT", &station_path("/currentLimit"), json!({"value": 20})).await;
    charger.close().await;
    let settings = (*server.app.settings).clone();
    let dir = server.stop().await;

    let saved: Value = serde_json::from_str(&std::fs::read_to_string(dir.path().join("data/state.json")).unwrap()).unwrap();
    let station = &saved["stations"][SERIAL];
    assert_eq!(station["connectors"]["1"]["mode"], "Inactive");
    assert_eq!(station["currentLimit"], 20);
    assert_eq!(station["boot"]["chargePointModel"], "GRD 40A 2025");

    // And a server started on the same directory knows all of it, and the session too.
    let again = TestServer::with_settings(dir, settings).await;
    let station = again.station(&token, SERIAL).await;
    assert_eq!(station["online"], false);
    assert_eq!(station["connectors"][0]["mode"], "Inactive");
    assert_eq!(station["smartCharging"]["currentLimit"], 20);
    assert_eq!(station["model"]["displayName"], "Grizzl-E Duo");
}

/// Real Duo firmware: StartTransaction.meterStart is lifetime Wh, MeterValues restart at 0.
#[tokio::test]
async fn session_relative_energy_register() {
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(&dir, &[]);
    let start = json!({"connectorId": 2, "idTag": "uc_default_auth", "meterStart": 819392, "timestamp": "2026-11-08T16:12:17Z"});
    assert_eq!(handle(&controller, "StartTransaction", start)["transactionId"], 1);
    controller.set_base_rate(SERIAL, &json!(0.10)).unwrap();
    let sample = |wh: f64, watts: f64| {
        json!({"connectorId": 2, "transactionId": 1, "meterValue": [{
            "timestamp": "2026-11-08T16:14:51Z",
            "sampledValue": [
                {"value": wh.to_string(), "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
                {"value": watts.to_string(), "measurand": "Power.Active.Import", "unit": "W"},
            ],
        }]})
    };
    handle(&controller, "MeterValues", sample(0.0, 0.0));
    handle(&controller, "MeterValues", sample(1500.0, 7200.0));
    {
        let inner = controller.lock();
        let connector = &inner.stations[SERIAL].connectors[&2];
        let tx = connector.transaction.as_ref().unwrap();
        assert_eq!(tx.energy, 1500.0);
        assert_eq!(tx.session_relative_register, Some(true));
        assert_eq!(connector.total_energy_wh, Some(819392.0 + 1500.0));
        assert!(close_to(tx.price_total, 0.15, 1e-9, 1e-12));
    }
    let stop = json!({"transactionId": 1, "meterStop": 2000, "timestamp": "2026-11-08T17:00:00Z", "reason": "Remote"});
    handle(&controller, "StopTransaction", stop);
    let inner = controller.lock();
    let connector = &inner.stations[SERIAL].connectors[&2];
    assert!(connector.transaction.is_none());
    assert_eq!(connector.last_session.as_ref().unwrap()["energy"], 2000.0);
    assert_eq!(connector.total_energy_wh, Some(819392.0 + 2000.0));
    let session = &inner.store.sessions(SERIAL, 50).unwrap()[0];
    assert_eq!(session["energy_wh"], 2000.0);
    assert_eq!(session["duration_s"], 2863);
    assert_eq!(session["reason"], "Remote");
}

#[tokio::test]
async fn config_keys_teach_dip_switch_and_connectors() {
    // What the charger says about itself in GetConfiguration is picked up after it boots.
    let server = TestServer::start().await;
    let options = FakeOptions { malformed_config: false, ..FakeOptions::default() };
    let charger = FakeCharger::connect_to(server.address, SERIAL, options).await.unwrap();
    {
        let mut state = charger.state();
        state.config.insert("DipSwitchCurrentLimit".into(), "32".into());
        state.config.insert("NumberOfConnectors".into(), "2".into());
        state.config.insert("AuthTag".into(), "house_tag".into());
    }
    let learned = || server.controller().lock().stations.get(SERIAL).is_some_and(|s| s.dip_switch_current_limit == Some(32));
    wait_for("the configuration to be read", learned).await;
    {
        let inner = server.controller().lock();
        let station = &inner.stations[SERIAL];
        assert_eq!(station.connector_count, 2);
        assert!(station.connectors.contains_key(&2));
        assert_eq!(station.id_tag.as_deref(), Some("house_tag"));
        assert_eq!(station.config["DipSwitchCurrentLimit"], "32");
    }
    // above the DIP switch
    let refused = server.controller().set_current_limit(SERIAL, 36).await;
    assert_eq!(refused, Err(CommandError::Invalid("current limit must be between 16 and 32 A".into())));
    assert_eq!(server.controller().set_current_limit(SERIAL, 32).await, Ok(()));
    // The charger's own tag is the one used to start a session.
    charger.plug_in(1).await;
    wait_for("a remote start", || !charger.calls("RemoteStartTransaction").is_empty()).await;
    assert_eq!(charger.calls("RemoteStartTransaction")[0]["idTag"], "house_tag");
}

#[tokio::test]
async fn web_page_is_served_without_login() {
    let server = server().await;
    let page = server.get("/", None).await;
    assert_eq!(page.status, 200);
    assert_eq!(page.header("content-type"), Some("text/html; charset=utf-8"));
    assert!(page.body.contains("<title>Grizzl-E local</title>"));
    let without_namespaces = page.body.replace("http://www.w3.org", "");
    assert!(!without_namespaces.contains("http://") && !page.body.contains("https://"), "nothing external");
    assert!(page.header("content-security-policy").unwrap().contains("frame-ancestors 'self'"));
    assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(server.get("/index.html", None).await.body, page.body);
    assert_eq!(server.get("/nope", None).await.status, 404);
    let head = server.request("HEAD", "/", &[], None).await;
    assert_eq!((head.status, head.body.as_str()), (200, ""));
    let post = server.request("POST", "/", &[], None).await;
    assert_eq!(post.status, 405);
    assert_eq!(post.header("allow"), Some("GET,HEAD"));
}

#[tokio::test]
async fn session_history_with_live_and_finished_sessions() {
    let server = server().await;
    let charger = FakeCharger::connect(&server, SERIAL).await;
    let token = server.login().await;
    api(&server, &token, "PUT", &station_path("/rate"), json!({"priceKW": 0.5})).await;
    charger.plug_in(1).await;
    wait_for("connector 1 to charge", || charger.status(1) == "Charging").await;
    tokio::time::sleep(Duration::from_millis(1600)).await;

    let sessions_path = format!("/local/stations/{SERIAL}/sessions");
    let data = server.json(&token, &sessions_path).await;
    let live = &data["sessions"][0];
    assert_eq!((&live["active"], &live["incomplete"], &live["stop_at"]), (&json!(true), &json!(false), &json!(null)));
    let energy = live["energy_wh"].as_f64().unwrap();
    assert!(energy > 0.0 && live["duration_s"].as_i64().unwrap() >= 1, "{live}");
    assert!(close_to(live["cost"].as_f64().unwrap(), energy / 1000.0 * 0.5, 0.05, 0.00005 + 1e-9), "{live}");
    assert_eq!(data["summary"]["today"]["count"], 1);
    assert_eq!(data["summary"]["all"]["energy_wh"].as_f64(), Some(energy));
    assert_eq!((&data["timezone"], &data["currency"]), (&json!("America/Denver"), &json!("USD")));

    charger.unplug(1).await;
    wait_for("connector 1 to be available", || charger.status(1) == "Available").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let data = server.json(&token, &format!("{sessions_path}?limit=5")).await;
    let done = &data["sessions"][0];
    assert_eq!((&done["active"], &done["reason"]), (&json!(false), &json!("EVDisconnected")));
    assert!(done["stop_at"].is_string());
    let (cost, energy) = (done["cost"].as_f64().unwrap(), done["energy_wh"].as_f64().unwrap());
    assert!(close_to(cost, energy / 1000.0 * 0.5, 0.05, 0.0), "{done}");
    assert!(close_to(data["summary"]["week"]["cost"].as_f64().unwrap(), cost, 0.0, 1e-4));
    assert_eq!(server.get(&sessions_path, None).await.status, 401);
}

/// Sessions recorded before any price existed get repriced from their stored meter samples.
#[tokio::test]
async fn recalculate_reprices_past_and_running_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(&dir, &[("TZ", "America/Denver")]);
    let sample = |connector: i64, tid: i64, stamp: &str, wh: f64| {
        let value = json!({"value": wh.to_string(), "measurand": "Energy.Active.Import.Register", "unit": "Wh"});
        json!({"connectorId": connector, "transactionId": tid, "meterValue": [{"timestamp": stamp, "sampledValue": [value]}]})
    };
    // Monday 2026-11-09, Denver is UTC-7: 08:00 -> 10:00 local, straddling the start of a 09:00 peak zone.
    let start = json!({"connectorId": 1, "idTag": "t", "meterStart": 500000, "timestamp": "2026-11-09T15:00:00Z"});
    handle(&controller, "StartTransaction", start);
    handle(&controller, "MeterValues", sample(1, 1, "2026-11-09T15:30:00Z", 2000.0)); // 08:30, 2 kWh so far
    handle(&controller, "MeterValues", sample(1, 1, "2026-11-09T16:30:00Z", 5000.0)); // 09:30, 5 kWh so far
    let stop = json!({"transactionId": 1, "meterStop": 506000, "timestamp": "2026-11-09T17:00:00Z", "reason": "Remote"});
    handle(&controller, "StopTransaction", stop);
    let session = |id: i64| -> Value {
        let sessions = controller.lock().store.sessions(SERIAL, 50).unwrap();
        Value::Object(sessions.into_iter().find(|session| session["id"] == id).unwrap())
    };
    assert_eq!(session(1)["cost"], 0.0, "no price was set while it ran");
    assert_eq!(session(1)["energy_wh"], 6000.0);

    controller.set_base_rate(SERIAL, &json!(0.10)).unwrap();
    let peak = json!({"name": "Peak", "priceKW": 0.30, "startHours": 9, "startMinutes": 0, "endHours": 17,
        "endMinutes": 0, "days": [1, 2, 3, 4, 5], "allDay": false});
    controller.upsert_zone(SERIAL, &peak).await.unwrap();
    // a session still running, with one sample before the peak
    let start = json!({"connectorId": 2, "idTag": "t", "meterStart": 800000, "timestamp": "2026-11-09T14:00:00Z"});
    handle(&controller, "StartTransaction", start);
    handle(&controller, "MeterValues", sample(2, 2, "2026-11-09T14:30:00Z", 4000.0));
    {
        // as if it had been recorded at price 0
        let mut inner = controller.lock();
        let station = inner.stations.get_mut(SERIAL).unwrap();
        station.connectors.get_mut(&2).unwrap().transaction.as_mut().unwrap().price_total = 0.0;
    }

    let result = controller.recalculate_costs(SERIAL).unwrap();
    assert_eq!((&result["sessions"], &result["cost_before"]), (&json!(2), &json!(0.0)));
    // 2 kWh at 0.10 + 3 kWh at 0.30 + the last 1 kWh (after the final sample) at the stop-time price 0.30
    assert!(close_to(session(1)["cost"].as_f64().unwrap(), 0.2 + 0.9 + 0.3, 1e-9, 0.0), "{}", session(1));
    assert!(close_to(session(1)["price_kwh"].as_f64().unwrap(), 1.4 / 6.0, 1e-9, 0.0));
    {
        let inner = controller.lock();
        let live = inner.stations[SERIAL].connectors[&2].transaction.as_ref().unwrap();
        assert!(close_to(live.price_total, 0.4, 1e-9, 0.0), "4 kWh at 07:30, base price: {}", live.price_total);
    }
    assert!(close_to(result["cost_after"].as_f64().unwrap(), 1.8, 1e-9, 0.0));

    // no samples at all (pruned after 90 days): the whole session is priced at its start time
    controller.lock().store.database().execute("DELETE FROM samples", []).unwrap();
    controller.recalculate_costs(SERIAL).unwrap();
    assert!(close_to(session(1)["cost"].as_f64().unwrap(), 6.0 * 0.10, 1e-9, 0.0));
    assert_eq!(controller.recalculate_costs("GRD-NOBODY"), Err(CommandError::NotFound));
}
