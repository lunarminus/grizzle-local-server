//! The REST API and the web page: sign-in, sessions, input validation, what is disclosed to whom.

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use grizzle_local::api::{origin_allowed, App, LOGIN_MAX_FAILURES, LOGIN_WINDOW_SECONDS, MAX_TOKENS, REFRESH_TTL, TOKEN_TTL};
use grizzle_local::config::{frame_ancestors, Settings};
use grizzle_local::controller::{station_tz, Token};
use grizzle_local::schedules::{normalize_zone, zone_id};
use grizzle_local::state::{Station, MAX_CONNECTORS, MAX_CURRENT, MAX_ZONES};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{capture_logs, logged, settings, wait_until, HttpResponse, RawCharger, TestServer, EMAIL, PASSWORD};

const LOGIN: &str = "/client/auth/login";
const REFRESH: &str = "/client/auth/refresh-token";
const LOGOUT: &str = "/client/auth/logout";

/// A server with a station that exists (and is offline), and the token of a signed-in client.
async fn station(serial: &str) -> (TestServer, String) {
    let server = TestServer::start().await;
    let mut station = Station::new(serial, &server.app.settings);
    station.ensure_connectors();
    server.controller().lock().stations.insert(serial.to_string(), station);
    let token = server.login().await;
    (server, token)
}

fn client(serial: &str, tail: &str) -> String {
    format!("/client/stations/{serial}/{tail}")
}

fn local(serial: &str, tail: &str) -> String {
    format!("/local/stations/{serial}/{tail}")
}

/// The station as it would be saved.
fn saved(server: &TestServer, serial: &str) -> Value {
    server.state()["stations"][serial].clone()
}

fn tokens(server: &TestServer) -> BTreeMap<String, Token> {
    server.controller().lock().tokens.clone()
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

/// `base` with the fields of `over` on top.
fn merged(base: &Value, over: &Value) -> Value {
    let mut all = base.clone();
    all.as_object_mut().unwrap().extend(over.as_object().unwrap().clone());
    all
}

/// A request whose body is sent exactly as given (it need not be JSON), signed in if there is a token.
async fn raw(server: &TestServer, method: &str, path: &str, token: &str, body: impl AsRef<[u8]>) -> HttpResponse {
    let bearer = format!("Bearer {token}");
    let headers = [("Content-Type", "application/json"), ("Authorization", bearer.as_str())];
    server.request(method, path, &headers[..if token.is_empty() { 1 } else { 2 }], Some(body.as_ref())).await
}

/// Sign in with the right email and this password, sending these headers too.
async fn sign_in(server: &TestServer, password: &str, headers: &[(&str, &str)]) -> HttpResponse {
    let body = json!({"emailOrPhone": EMAIL, "password": password}).to_string();
    let headers = [&[("Content-Type", "application/json")], headers].concat();
    server.request("POST", LOGIN, &headers, Some(body.as_bytes())).await
}

/// Sign in; the token and the refresh token.
async fn session(server: &TestServer) -> (String, String) {
    let tokens = server.login_with(EMAIL, PASSWORD).await.json();
    (tokens["token"].as_str().unwrap().to_string(), tokens["refreshToken"].as_str().unwrap().to_string())
}

/// The status of asking for a new session with this refresh token.
async fn refresh(server: &TestServer, refresh_token: &Value) -> u16 {
    server.post(REFRESH, None, &json!({"refreshToken": refresh_token})).await.status
}

/// The status of listing the stations with this token.
async fn listing(server: &TestServer, token: &str) -> u16 {
    server.get("/client/stations", Some(token)).await.status
}

/// Put a state.json where a server started on `dir` finds it; the data directory.
fn write_state(dir: &Path, state: &str) -> PathBuf {
    let data = dir.join("data");
    fs::create_dir(&data).unwrap();
    fs::write(data.join("state.json"), state).unwrap();
    data
}

/// A server over `dir`, as after a restart, configured by these environment variables.
async fn start_in(dir: &Arc<TempDir>, pairs: &[(&str, &str)]) -> TestServer {
    TestServer::with_settings(dir.clone(), settings(dir.path(), pairs)).await
}

// Signing in.

#[tokio::test]
async fn login_with_any_wrong_password_is_a_plain_401() {
    // The right email with a password that is not ASCII, or not text, was once a 500, which also
    // told the caller the email was right.
    let passwords = json!(["pöö", "密码", "x".repeat(100_000), "", null, 12345, ["a"], {"a": 1}]);
    for (n, password) in passwords.as_array().unwrap().iter().enumerate() {
        let server = TestServer::start().await;
        let response = server.post(LOGIN, None, &json!({"emailOrPhone": EMAIL, "password": password})).await;
        assert_eq!(response.status, 401, "password {n}");
        assert_eq!(response.json()["message"], "Invalid email or password");
        let response = server.post(LOGIN, None, &json!({"emailOrPhone": "who@else", "password": password})).await;
        assert_eq!(response.status, 401, "password {n}");
        server.stop().await;
    }
    // A lone surrogate is not JSON to this server: refused as such, whichever email it comes with.
    let server = TestServer::start().await;
    for email in [EMAIL, "who@else"] {
        let body = format!(r#"{{"emailOrPhone": "{email}", "password": "\udcff"}}"#);
        assert_eq!(raw(&server, "POST", LOGIN, "", body).await.status, 400);
    }
}

#[tokio::test]
async fn non_ascii_password_can_be_the_right_one() {
    let server = TestServer::with(&[("GRIZZLE_API_PASSWORD", "pässwörd-密码")]).await;
    assert_eq!(server.login_with(EMAIL, "passwoerd").await.status, 401);
    assert_eq!(server.login_with(EMAIL, "pässwörd-密码").await.status, 200);
}

#[tokio::test]
async fn refresh_with_a_bogus_token_is_a_plain_401() {
    let server = TestServer::start().await;
    server.login().await; // so there is a session to compare against
    for (n, token) in json!(["é", "x".repeat(100_000), "", null, 5, ["a"]]).as_array().unwrap().iter().enumerate() {
        assert_eq!(refresh(&server, token).await, 401, "token {n}");
    }
    // A lone surrogate is not JSON to this server.
    assert_eq!(raw(&server, "POST", REFRESH, "", r#"{"refreshToken": "\udcff"}"#).await.status, 400);
}

#[tokio::test]
async fn malformed_login_bodies_are_client_errors() {
    let server = TestServer::start().await;
    let deep = "[".repeat(100_000);
    let bodies: [&[u8]; 6] = [deep.as_bytes(), b"{\"emailOrPhone\": ", b"\xff\xfe", b"[]", b"\"text\"", b"12"];
    for body in bodies {
        let status = raw(&server, "POST", LOGIN, "", body).await.status;
        assert!([400, 401].contains(&status), "{status} for {:?}", String::from_utf8_lossy(&body[..body.len().min(20)]));
    }
}

#[tokio::test]
async fn an_empty_configured_password_lets_nobody_in() {
    let server = TestServer::with(&[("GRIZZLE_API_PASSWORD", "")]).await;
    assert!(server.app.settings.security_warnings().iter().any(|warning| warning.contains("empty")));
    for password in [json!(""), json!(null), json!(" ")] {
        let response = server.post(LOGIN, None, &json!({"emailOrPhone": EMAIL, "password": password})).await;
        assert_eq!(response.status, 401, "{password}");
    }
}

#[tokio::test]
async fn password_guessing_is_throttled() {
    let server = TestServer::start().await;
    for _ in 0..LOGIN_MAX_FAILURES {
        assert_eq!(server.login_with(EMAIL, "guess").await.status, 401);
    }
    let refused = server.login_with(EMAIL, "guess").await;
    assert_eq!(refused.status, 429);
    let wait: u32 = refused.header("retry-after").unwrap().parse().unwrap();
    assert!(wait > 0 && f64::from(wait) <= LOGIN_WINDOW_SECONDS);
    // Even the right password has to wait now: otherwise the limit would only slow down wrong guesses.
    assert_eq!(server.login_with(EMAIL, PASSWORD).await.status, 429);
    // Sessions that already exist are not affected.
    assert_eq!(refresh(&server, &json!("nope")).await, 401);
}

#[tokio::test]
async fn a_successful_login_clears_the_failures() {
    let server = TestServer::start().await;
    for _ in 0..LOGIN_MAX_FAILURES - 1 {
        server.login_with(EMAIL, "guess").await;
    }
    server.login().await;
    for _ in 0..LOGIN_MAX_FAILURES - 1 {
        assert_eq!(server.login_with(EMAIL, "guess").await.status, 401);
    }
}

// Sessions.

#[tokio::test]
async fn profile_does_not_mint_tokens() {
    let server = TestServer::start().await;
    let token = server.login().await;
    let before = tokens(&server);
    for _ in 0..10 {
        assert_eq!(server.json(&token, "/client/auth/profile").await["email"], EMAIL);
    }
    assert_eq!(tokens(&server), before);
}

#[tokio::test]
async fn logout_ends_the_session_on_the_server() {
    let server = TestServer::start().await;
    let (token, refresh_token) = session(&server).await;
    assert_eq!(listing(&server, &token).await, 200);
    assert_eq!(server.send("POST", LOGOUT, Some(&token), None).await.status, 200);
    assert_eq!(listing(&server, &token).await, 401);
    assert_eq!(refresh(&server, &json!(refresh_token)).await, 401);
    assert_eq!(server.send("POST", LOGOUT, None, None).await.status, 200); // nothing to end: still not an error
}

#[tokio::test]
async fn a_session_can_be_ended_after_its_token_has_expired() {
    // After seven days the token is refused, so the page signs out. That request used to be refused
    // too (it carried the expired token), and the refresh token stayed good for three more weeks.
    let server = TestServer::start().await;
    let (token, refresh_token) = session(&server).await;
    server.controller().lock().tokens.get_mut(&token).unwrap().expires = now() - 10.0;
    assert_eq!(listing(&server, &token).await, 401);
    assert_eq!(server.send("POST", LOGOUT, Some(&token), None).await.status, 200);
    assert!(tokens(&server).is_empty());
    assert_eq!(refresh(&server, &json!(refresh_token)).await, 401);

    // A session can also be ended by its refresh token alone.
    let (_, refresh_token) = session(&server).await;
    assert_eq!(server.post(LOGOUT, None, &json!({"refreshToken": refresh_token})).await.status, 200);
    assert!(tokens(&server).is_empty());
    assert_eq!(server.post(LOGOUT, None, &json!({"refreshToken": ["x"]})).await.status, 200);
}

#[tokio::test]
async fn the_web_page_signs_out_on_the_server_too() {
    let server = TestServer::start().await;
    assert!(server.get("/", None).await.body.contains("\"/client/auth/logout\""));
}

#[tokio::test]
async fn token_in_the_query_string_is_not_accepted() {
    let server = TestServer::start().await;
    let token = server.login().await;
    assert_eq!(server.get(&format!("/client/stations?token={token}"), None).await.status, 401);
    assert_eq!(listing(&server, &token).await, 200);
    let odd = format!("bearer  {token} ");
    assert_eq!(server.request("GET", "/client/stations", &[("Authorization", &odd)], None).await.status, 200);
}

#[tokio::test]
async fn the_number_of_sessions_is_bounded() {
    // The limit is a constant here, so this signs in more often than that.
    let server = TestServer::start().await;
    let mut issued = Vec::new();
    for _ in 0..MAX_TOKENS + 3 {
        issued.push(server.login().await);
    }
    let mut newest = issued.split_off(3); // the oldest made room
    newest.sort();
    assert_eq!(tokens(&server).into_keys().collect::<Vec<_>>(), newest);
}

#[tokio::test]
async fn refresh_tokens_expire() {
    let server = TestServer::start().await;
    let (token, refresh_token) = session(&server).await;
    let info = tokens(&server)[&token].clone();
    assert!((info.refresh_expires.unwrap() - info.expires - (REFRESH_TTL - TOKEN_TTL)).abs() < 1.0);

    // The access token has run out; the refresh token has not.
    server.controller().lock().tokens.get_mut(&token).unwrap().expires = now() - 10.0;
    assert_eq!(listing(&server, &token).await, 401);
    let renewed = server.post(REFRESH, None, &json!({"refreshToken": refresh_token})).await;
    assert_eq!(renewed.status, 200);
    let renewed = renewed.json();

    // Once the refresh token itself has expired it is worthless, and it used to work forever
    // (until someone else happened to sign in and garbage-collect it).
    let token = renewed["token"].as_str().unwrap();
    server.controller().lock().tokens.get_mut(token).unwrap().refresh_expires = Some(now() - 10.0);
    assert_eq!(refresh(&server, &renewed["refreshToken"]).await, 401);
    assert!(tokens(&server).is_empty());
}

#[tokio::test]
async fn sessions_saved_by_an_older_version_are_signed_out_once() {
    // An older version kept no record of which password a session was signed in with. If the
    // password is changed in the same restart as the upgrade, keeping those sessions would bless
    // exactly the ones the change was meant to end; and their tokens may have travelled in URLs.
    capture_logs();
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let old = json!({"token-from-before": {"refresh": "refresh-from-before", "expires": now() + 3600.0}});
    write_state(dir.path(), &json!({"tokens": old, "stations": {}}).to_string());
    let server = start_in(&dir, &[]).await;
    assert_eq!(listing(&server, "token-from-before").await, 401);
    assert_eq!(refresh(&server, &json!("refresh-from-before")).await, 401);
    let token = server.login().await; // signing in again is all it takes
    assert!(logged("earlier version").iter().any(|line| line.contains(" WARNING ")));
    server.stop().await;
    let server = start_in(&dir, &[]).await; // and from then on sessions are kept
    assert_eq!(listing(&server, &token).await, 200);
}

#[test]
fn a_damaged_credentials_mark_does_not_stop_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let state = json!({
        "tokens": {
            "t": {"refresh": "r", "expires": now() + 60.0, "refreshExpires": "soon"},
            "u": {"refresh": "r2", "expires": now() + 60.0},
        },
        "credentials": {"salt": "00", "mark": "märk"},
    });
    write_state(dir.path(), &state.to_string());
    let app = App::new(settings(dir.path(), &[])).unwrap();
    assert!(app.controller.lock().tokens.is_empty()); // "t" was malformed, "u" belonged to other credentials
}

// What the public endpoints say.

#[tokio::test]
async fn health_does_not_list_serials_to_strangers() {
    const SERIAL: &str = "GRD-API-HEALTH";
    let server = TestServer::start().await;
    let _charger = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    let response = server.get("/health", None).await;
    assert_eq!(response.status, 200);
    let data = response.json();
    assert!(!response.body.contains(SERIAL) && data.get("stations").is_none());
    assert_eq!((&data["status"], &data["stationCount"], &data["stationsOnline"]), (&json!("ok"), &json!(1), &json!(1)));
    let token = server.login().await;
    assert_eq!(server.json(&token, "/health").await["stations"], json!({SERIAL: true}));
}

#[tokio::test]
async fn unlock_check_ignores_things_that_are_not_serials() {
    capture_logs();
    let server = TestServer::start().await;
    let long = "x".repeat(65);
    for serial in ["GRD%0AINFO%20forged", "a%20b", "-dash", long.as_str(), "%00", "..", "%C3%A9"] {
        assert_eq!(server.get(&format!("/commercial/ext-ocpp-check/{serial}"), None).await.status, 404, "{serial}");
    }
    assert_eq!(logged("ext-ocpp-check"), Vec::<String>::new());
}

#[test]
fn frame_ancestors_setting() {
    let with = |value: &str| Settings::from_pairs(&[("GRIZZLE_FRAME_ANCESTORS", value)]);
    assert_eq!(Settings::defaults().frame_ancestors, "'self'");
    let two = with("http://homeassistant.local:8123, https://ha.example.com").unwrap();
    assert_eq!(two.frame_ancestors, "http://homeassistant.local:8123 https://ha.example.com");
    for value in ["x; script-src *", "\"self\"", "'unsafe-inline'", "a\tb;c", "http://a;b/"] {
        assert!(frame_ancestors(value).is_err(), "{value:?}");
        assert!(with(value).is_err(), "{value:?}");
    }
    assert_eq!(frame_ancestors("*").unwrap(), "*");
    assert_eq!(frame_ancestors(" 'none' ").unwrap(), "'none'");
}

#[tokio::test]
async fn page_is_not_frameable_by_other_sites_unless_configured() {
    let server = TestServer::start().await;
    let page = server.get("/", None).await;
    let policy = page.header("content-security-policy").unwrap();
    assert!(policy.ends_with("frame-ancestors 'self'") && !policy.contains("frame-ancestors *"));
    assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    let server = TestServer::with(&[("GRIZZLE_FRAME_ANCESTORS", "http://homeassistant.local:8123")]).await;
    let page = server.get("/", None).await;
    let policy = page.header("content-security-policy").unwrap();
    assert!(policy.ends_with("frame-ancestors http://homeassistant.local:8123"));
}

// Parameters.

#[tokio::test]
async fn bad_query_parameters_are_400_not_500() {
    const SERIAL: &str = "GRD-API-BADQUERY";
    let (server, token) = station(SERIAL).await;
    for path in [
        client(SERIAL, "events?limit=abc"), client(SERIAL, "events?limit=--5"),
        client(SERIAL, "events?limit=99999999999999999999"), local(SERIAL, "sessions?limit=1e3"),
        local(SERIAL, "samples?connector=abc"), local(SERIAL, "samples?connector=999999"),
        local(SERIAL, "samples?since=yesterday"), local(SERIAL, "samples?since=9999-12-31T23:59:59-23:59"),
    ] {
        let response = server.get(&path, Some(&token)).await;
        assert_eq!(response.status, 400, "{path}: {}", response.body);
        assert!(response.json().get("message").is_some(), "{path}");
    }
}

#[tokio::test]
async fn good_query_parameters_still_work() {
    const SERIAL: &str = "GRD-API-QUERY";
    let (server, token) = station(SERIAL).await;
    {
        let mut inner = server.controller().lock();
        for n in 1..=1010 {
            let start = format!("2026-10-01T00:{:02}:{:02}.000Z", n / 60, n % 60);
            inner.store.start_session(n, SERIAL, 1, Some("t"), &start, Some(0), Some(0.1)).unwrap();
        }
    }
    // A whole number outside 1..1000 is brought into range, as it always was; it is not an error.
    let rows = [("", 50), ("?limit=5", 5), ("?limit=1000", 1000), ("?limit=5000", 1000), ("?limit=0", 1), ("?limit=-7", 1)];
    for (query, rows) in rows {
        let data = server.json(&token, &client(SERIAL, &format!("events{query}"))).await;
        assert_eq!(data["sessions"].as_array().unwrap().len(), rows, "{query}");
    }
    let data = server.json(&token, &local(SERIAL, "sessions?limit=5000")).await;
    assert_eq!(data["sessions"].as_array().unwrap().len(), 1000);
    for tail in [
        "sessions?limit=5", "samples", "samples?connector=1", "samples?since=2026-11-08T00:00:00Z",
        "samples?since=2026-11-08T02:00:00%2B02:00&connector=2",
    ] {
        assert_eq!(server.get(&local(SERIAL, tail), Some(&token)).await.status, 200, "{tail}");
    }
}

#[tokio::test]
async fn bad_bodies_are_400_and_change_nothing() {
    const SERIAL: &str = "GRD-API-BODIES";
    let (server, token) = station(SERIAL).await;
    let before = saved(&server, SERIAL);
    let long_action = json!({"action": "x".repeat(100)}).to_string();
    let too_many_dates = json!({"extraDates": vec![json!({"date": "2026-12-24"}); 501]}).to_string();
    // The bodies are text because a client can send NaN and Infinity, which are not JSON.
    let cases: [(&str, String, &[&str]); 6] = [
        ("PUT", client(SERIAL, "currentLimit"), &[
            r#"{"value": "lots"}"#, r#"{"value": Infinity}"#, r#"{"value": null}"#, r#"{"value": [16]}"#, "{}",
        ]),
        ("PUT", client(SERIAL, "rate"), &[
            r#"{"priceKW": NaN}"#, r#"{"priceKW": Infinity}"#, r#"{"priceKW": "NaN"}"#, r#"{"priceKW": -0.1}"#,
            r#"{"priceKW": true}"#, r#"{"priceKW": {"a": 1}}"#,
        ]),
        ("POST", client(SERIAL, "mode"), &[
            r#"{"mode": "Active", "connectorId": 99}"#,
            r#"{"mode": "Active", "connectorId": 2}"#, // the station has one
            r#"{"mode": "Active", "connectorId": "one"}"#, r#"{"mode": ["Active"], "connectorId": 1}"#,
        ]),
        ("POST", local(SERIAL, "ocpp"), &[
            r#"{"action": "Reset", "timeout": "soon"}"#, r#"{"action": "Reset", "timeout": NaN}"#,
            r#"{"action": "Reset", "timeout": 1000000000.0}"#, r#"{"action": "Reset", "timeout": -1}"#,
            r#"{"action": "Reset", "payload": [1]}"#, r#"{"action": "Reset", "payload": {"x": NaN}}"#,
            &long_action, r#"{"action": 5}"#,
        ]),
        ("PUT", local(SERIAL, "holidays"), &[
            r#"{"enabled": true, "country": 12}"#, r#"{"priceKW": NaN}"#, r#"{"priceKW": [1]}"#,
            r#"{"excludedNames": "Christmas Day"}"#, r#"{"excludedNames": [5]}"#, &too_many_dates,
        ]),
        ("POST", local(SERIAL, "holidays/preview"), &[r#"{"extraDates": {"date": "2026-12-24"}}"#]),
    ];
    for (method, path, bodies) in cases {
        for body in bodies {
            let response = raw(&server, method, &path, &token, body).await;
            assert_eq!(response.status, 400, "{method} {path} {body:.80} -> {}", response.body);
            assert!(response.json().get("message").is_some(), "{method} {path} {body:.80}");
            assert_eq!(saved(&server, SERIAL), before, "{method} {path} {body:.80}");
        }
    }
}

#[tokio::test]
async fn raw_ocpp_call_validates_but_still_reaches_an_offline_error() {
    const SERIAL: &str = "GRD-API-OFFLINE";
    let (server, token) = station(SERIAL).await;
    let response = server.post(&local(SERIAL, "ocpp"), Some(&token), &json!({"action": "Reset", "timeout": 2})).await;
    assert_eq!((response.status, &response.json()["error"]), (502, &json!("Offline")));
}

// Station settings.

#[tokio::test]
async fn settings_are_validated_before_anything_is_applied() {
    // A refused request used to leave its other fields (and sometimes the bad one) applied;
    // connectorCount took any number (the same loop bomb as the charger-side one) and null made
    // every later BootNotification fail.
    const SERIAL: &str = "GRD-API-SETTINGS";
    let (server, token) = station(SERIAL).await;
    let before = saved(&server, SERIAL);
    let patches = json!([
        {"connectorCount": 1_000_000}, {"connectorCount": MAX_CONNECTORS + 1}, {"connectorCount": 0},
        {"connectorCount": null}, {"connectorCount": "many"}, {"connectorCount": 2.5},
        {"maxCurrent": null}, {"maxCurrent": 1_000_000_000}, {"minCurrent": -5}, {"minCurrent": 32, "maxCurrent": 16},
        {"dipSwitchCurrentLimit": "big"}, {"timezone": "Mars/Olympus_Mons"}, {"timezone": "../../etc/passwd"},
        {"currency": "DOLLARS"}, {"currency": "$$$"}, {"displayName": "n".repeat(500)},
    ]);
    for patch in patches.as_array().unwrap() {
        let body = merged(&json!({"displayName": "Renamed", "currency": "EUR"}), patch);
        let response = server.put(&local(SERIAL, "settings"), Some(&token), &body).await;
        assert_eq!(response.status, 400, "{patch}: {}", response.body);
        assert_eq!(saved(&server, SERIAL), before, "{patch}"); // not even the valid fields of a refused request
    }
}

#[tokio::test]
async fn valid_settings_apply_together() {
    const SERIAL: &str = "GRD-API-APPLIED";
    let (server, token) = station(SERIAL).await;
    let path = local(SERIAL, "settings");
    let body = json!({
        "displayName": "  Garage  ", "timezone": "America/Denver", "currency": "cad", "connectorCount": 2,
        "maxCurrent": 48, "minCurrent": 6, "dipSwitchCurrentLimit": 40,
    });
    let response = server.put(&path, Some(&token), &body).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let state = saved(&server, SERIAL);
    let expected = json!({
        "displayName": "Garage", "timezone": "America/Denver", "currency": "CAD", "connectorCount": 2,
        "modelLocked": true, "maxCurrent": 48, "minCurrent": 6, "dipSwitchCurrentLimit": 40,
    });
    for (key, value) in expected.as_object().unwrap() {
        assert_eq!(state.get(key), Some(value), "{key}");
    }
    assert_eq!(state["connectors"].as_object().unwrap().keys().collect::<Vec<_>>(), ["1", "2"]);
    assert_eq!(server.put(&path, Some(&token), &json!({"dipSwitchCurrentLimit": null})).await.status, 200);
    assert_eq!(saved(&server, SERIAL).get("dipSwitchCurrentLimit"), Some(&Value::Null));
    // Unknown or wrongly typed optional text is ignored, as before.
    assert_eq!(server.put(&path, Some(&token), &json!({"displayName": 5, "x": 1})).await.status, 200);
    assert_eq!(saved(&server, SERIAL)["displayName"], "Garage");
}

// Schedules and rate zones.

fn good_zone() -> Value {
    json!({
        "name": "Night", "startHours": 23, "startMinutes": 0, "endHours": 7, "endMinutes": 0,
        "allDay": false, "days": [1, 2, 3, 4, 5], "connectorId": 0, "currentLimit": null,
    })
}

#[tokio::test]
async fn an_invalid_zone_is_refused_and_not_stored() {
    // An invalid zone used to be appended first and refused second: the reply said 400, the zone
    // stayed, and every tick from then on failed while evaluating it.
    const SERIAL: &str = "GRD-API-BADZONE";
    capture_logs();
    let (server, token) = station(SERIAL).await;
    let bad = json!([
        {"startHours": "soon"}, {"startHours": 25}, {"endMinutes": 60}, {"endHours": 24, "endMinutes": 1},
        {"startMinutes": -1}, {"startHours": 1.5}, {"startHours": true}, {"startHours": [23]},
        {"days": 5}, {"days": "weekdays"}, {"days": [7]}, {"days": [null]}, {"days": [[1]]},
        {"connectorId": "left"}, {"connectorId": 99},
        {"currentLimit": 1_000_000}, {"currentLimit": -8}, {"currentLimit": "fast"},
        {"priceKW": -1}, {"priceKW": true}, {"priceKW": "cheap"},
        {"allDay": "false"}, {"scheduleEnabled": "yes"}, {"holidays": "sometimes"}, {"holidays": ["skip"]},
        {"name": 5}, {"name": "n".repeat(500)},
        {"_id": "has spaces"}, {"_id": {"$ne": null}}, {"_id": "x".repeat(65)},
    ]);
    let zone_with = |bad: &Value| json!({"price": merged(&good_zone(), bad)}).to_string();
    let mut bodies: Vec<String> = bad.as_array().unwrap().iter().map(zone_with).collect();
    // NaN and Infinity are not JSON, so they are written into the text, as a client could.
    for (key, value) in [("currentLimit", "NaN"), ("priceKW", "NaN"), ("priceKW", "Infinity")] {
        bodies.push(zone_with(&json!({key: "@"})).replace("\"@\"", value));
    }
    for body in &bodies {
        for path in ["scheduleUpdate", "pricesByZoneUpdate"] {
            let response = raw(&server, "POST", &client(SERIAL, path), &token, body).await;
            assert_eq!(response.status, 400, "{body:.300} -> {}", response.body);
            assert_eq!(saved(&server, SERIAL)["pricesByZone"], json!([]));
        }
    }
    // A tick evaluates the station's zones: wait for one, and it must have found nothing to complain about.
    server.controller().lock().stations[SERIAL].connectors.get_mut(&1).unwrap().is_active_by_schedule = None;
    let ticked = || server.controller().lock().stations[SERIAL].connectors[&1].is_active_by_schedule.is_some();
    wait_until("a tick", Duration::from_secs(4), ticked).await;
    let errors: Vec<String> = logged(SERIAL).into_iter().filter(|line| line.contains(" ERROR ")).collect();
    assert_eq!(errors, Vec::<String>::new());
}

#[tokio::test]
async fn zones_are_stored_normalised() {
    const SERIAL: &str = "GRD-API-ZONES";
    let (server, token) = station(SERIAL).await;
    let path = client(SERIAL, "pricesByZoneUpdate");
    // (Python also sent a NaN here; that cannot be part of a body this server reads at all.)
    let changes = json!({
        "name": "  Peak  ", "days": [5, 1, 1, 3.0, "2"], "startHours": "9", "endHours": 17.0, "priceKW": "0.30",
        "currentLimit": 0, "allDay": 0, "priceKWSummer": 0, "useSeason": false, "note": "kept",
        "nested": {"a": [1, 2]}, "huge": "h".repeat(5000), "deep": vec![json!(vec![json!([[1]]); 50]); 50],
    });
    let sent = merged(&good_zone(), &changes);
    let response = server.post(&path, Some(&token), &json!({"price": sent})).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let data = response.json();
    let zone = saved(&server, SERIAL)["pricesByZone"][0].clone();
    assert_eq!(zone, data["price"]);
    assert_eq!(data["_id"], zone["_id"]);
    assert_eq!(json!(zone_id(&zone["_id"]).unwrap()), zone["_id"]);
    let expected = json!({
        "name": "Peak", "days": [1, 2, 3, 5], "startHours": 9, "endHours": 17, "priceKW": 0.3,
        "currentLimit": null, "allDay": false, "scheduleEnabled": false,
        "note": "kept", "nested": {"a": [1, 2]}, // small unknown fields are handed back
    });
    for (key, value) in expected.as_object().unwrap() {
        assert_eq!(zone.get(key), Some(value), "{key}");
    }
    assert!(zone.get("huge").is_none() && zone.get("deep").is_none()); // large ones are not kept

    // An update merges into the zone and is validated as a whole; a refused update changes nothing.
    let update = json!({"price": {"_id": zone["_id"], "scheduleEnabled": true, "endHours": 20}});
    assert_eq!(server.post(&path, Some(&token), &update).await.status, 200);
    let zones = saved(&server, SERIAL)["pricesByZone"].clone();
    assert_eq!(zones.as_array().unwrap().len(), 1);
    let changed = &zones[0];
    assert_eq!((&changed["endHours"], &changed["scheduleEnabled"], &changed["name"]), (&json!(20), &json!(true), &json!("Peak")));
    let update = json!({"price": {"_id": zone["_id"], "name": "Renamed", "endHours": 99}});
    assert_eq!(server.post(&path, Some(&token), &update).await.status, 400);
    assert_eq!(saved(&server, SERIAL)["pricesByZone"], zones);
}

#[tokio::test]
async fn the_number_of_zones_is_bounded() {
    const SERIAL: &str = "GRD-API-MANYZONES";
    let (server, token) = station(SERIAL).await;
    let path = client(SERIAL, "scheduleUpdate");
    for n in 0..MAX_ZONES {
        let zone = merged(&good_zone(), &json!({"name": format!("z{n}")}));
        assert_eq!(server.post(&path, Some(&token), &json!({"price": zone})).await.status, 200);
    }
    assert_eq!(server.post(&path, Some(&token), &json!({"price": good_zone()})).await.status, 400);
    let zones = saved(&server, SERIAL)["pricesByZone"].clone();
    assert_eq!(zones.as_array().unwrap().len(), MAX_ZONES);
    // ...but the existing ones can still be changed.
    let update = json!({"price": {"_id": zones[0]["_id"], "name": "still editable"}});
    assert_eq!(server.post(&path, Some(&token), &update).await.status, 200);
    assert_eq!(saved(&server, SERIAL)["pricesByZone"][0]["name"], "still editable");
}

#[test]
fn normalize_zone_keeps_only_what_can_be_evaluated() {
    // What the unit test of the same name in src/schedules.rs does not have.
    let normal = |zone: Value, connectors: i64| normalize_zone(&zone, connectors, MAX_CURRENT).map(Value::Object);
    assert_eq!(normal(json!({}), 8).unwrap(), json!({}));
    let nulls = normal(json!({"days": null, "connectorId": null, "startHours": null}), 8).unwrap();
    assert_eq!(nulls, json!({"days": [], "connectorId": 0, "startHours": 0}));
    assert_eq!(normal(json!({"currentLimit": 16.0, "priceKW": 0}), 8).unwrap()["currentLimit"], 16);
    assert_eq!(normal(json!({"connectorId": 3}), 4).unwrap()["connectorId"], 3);
    assert!(normal(json!({"connectorId": 3}), 2).is_err());
}

// Files on disk.

#[tokio::test]
async fn state_and_history_files_are_private() {
    const SERIAL: &str = "GRD-API-FILES";
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let data = write_state(dir.path(), "{}");
    fs::write(data.join("state.tmp"), "leftover from a crash").unwrap();
    for name in ["state.json", "state.tmp"] {
        fs::set_permissions(data.join(name), fs::Permissions::from_mode(0o644)).unwrap(); // as an older version left it
    }
    let server = start_in(&dir, &[]).await;
    let charger = RawCharger::connect(&server, SERIAL, Some((SERIAL, "the-charger's-cloud-key"))).await.unwrap();
    server.login().await;
    server.controller().save();
    charger.close().await;
    // The charger's key is in there, which is exactly why the file must not be world-readable.
    assert!(fs::read_to_string(data.join("state.json")).unwrap().contains("the-charger's-cloud-key"));
    for name in ["state.json", "history.sqlite"] {
        assert_eq!(fs::metadata(data.join(name)).unwrap().permissions().mode() & 0o777, 0o600, "{name}");
    }
    assert!(!data.join("state.tmp").exists());
}

#[tokio::test]
async fn request_bodies_that_are_too_deep_are_refused() {
    const SERIAL: &str = "GRD-API-DEEP";
    let (server, token) = station(SERIAL).await;
    assert_eq!(raw(&server, "PUT", &local(SERIAL, "settings"), &token, "[".repeat(200_000)).await.status, 400);
}

#[tokio::test]
async fn unknown_station_and_wrong_session_are_unchanged() {
    let server = TestServer::start().await;
    let token = server.login().await;
    assert_eq!(server.get("/client/stations/GRD-NOPE", Some(&token)).await.status, 404);
    assert_eq!(listing(&server, "nope").await, 401);
    assert_eq!(server.request("GET", "/client/stations", &[("Authorization", "Basic abc")], None).await.status, 401);
}

// A changed password signs everybody out.

#[tokio::test]
async fn changing_the_password_signs_out_existing_sessions() {
    // Changing the password is what an owner does about a session that got into the wrong hands.
    // The old sessions used to keep working, and could be refreshed for ever.
    let server = TestServer::start().await;
    let (token, refresh_token) = session(&server).await;
    let dir = server.stop().await;
    // Same credentials after a restart: still signed in.
    let server = start_in(&dir, &[]).await;
    assert_eq!(listing(&server, &token).await, 200);
    server.stop().await;
    // A new password: the old session is gone, token and refresh token alike.
    let changed = ("GRIZZLE_API_PASSWORD", "a different password");
    let server = start_in(&dir, &[changed]).await;
    assert_eq!(listing(&server, &token).await, 401);
    assert_eq!(refresh(&server, &json!(refresh_token)).await, 401);
    let renewed = server.login_with(EMAIL, "a different password").await;
    assert_eq!(renewed.status, 200);
    server.stop().await;
    // A new email does the same.
    let server = start_in(&dir, &[changed, ("GRIZZLE_API_EMAIL", "someone@else")]).await;
    assert_eq!(listing(&server, renewed.json()["token"].as_str().unwrap()).await, 401);
    server.stop().await;
    let text = fs::read_to_string(dir.path().join("data/state.json")).unwrap();
    assert!(!text.contains(PASSWORD) && !text.contains("a different password"));
    let state: Value = serde_json::from_str(&text).unwrap();
    let mut kept: Vec<&String> = state["credentials"].as_object().unwrap().keys().collect();
    kept.sort();
    assert_eq!(kept, ["mark", "salt"]);
}

// Requests from web pages.

#[test]
fn which_web_origins_may_use_the_api() {
    // The cases the unit test of the same name in src/api.rs does not have.
    for (origin, host, allowed) in [
        ("http://attacker.example:9000", "attacker.example:9000", false), // DNS rebinding: same origin, public name
        // The names the charger uses: the certificate is for them, and only the owner's DNS override leads here.
        ("https://connect-api.unitedchargers.com", "connect-api.unitedchargers.com", true),
        ("https://evil.unitedchargers.com.example", "x", false),
        ("http://ocpp.unitedchargers.com.evil.example", "192.168.1.5:9000", false),
        ("http://local", "x", true),
        ("http://notlocal.com", "notlocal.com", false),
        ("http://[bad", "192.168.1.5:9000", false),
    ] {
        assert_eq!(origin_allowed(origin, host, &[]), allowed, "{origin} at {host}");
    }
}

#[test]
fn allowed_hosts_setting() {
    let hosts = |value: &str| Settings::from_pairs(&[("GRIZZLE_ALLOWED_HOSTS", value)]).unwrap().allowed_hosts;
    assert!(Settings::defaults().allowed_hosts.is_empty());
    let listed = hosts("Grizzle.Example.com, .ts.net");
    assert_eq!(listed, ["grizzle.example.com", ".ts.net"]);
    assert!(origin_allowed("https://grizzle.example.com", "127.0.0.1:9000", &listed));
    assert!(origin_allowed("https://nas.tail1234.ts.net", "x", &listed));
    assert!(!origin_allowed("https://other.example.com", "x", &listed));
    assert!(!origin_allowed("https://evilts.net", "x", &listed));
    assert!(origin_allowed("https://anything.example", "x", &hosts("*")));
}

#[tokio::test]
async fn a_page_from_a_public_name_cannot_use_the_api() {
    // DNS rebinding: a web site re-points its own name at this server, and the owner's browser then
    // treats the site's script as the API's own origin. Such a page must not even get to try a
    // password (nor may another site's page burn the owner's sign-in attempts).
    capture_logs();
    let server = TestServer::start().await;
    for origin in ["http://attacker.example:9000", "https://evil.example", "null"] {
        let response = sign_in(&server, PASSWORD, &[("Origin", origin)]).await;
        assert_eq!(response.status, 403, "{origin}");
        assert!(response.json()["message"].as_str().unwrap().contains("GRIZZLE_ALLOWED_HOSTS"), "{origin}");
    }
    for _ in 0..LOGIN_MAX_FAILURES + 5 {
        // refused before it counts as a failed sign-in
        assert_eq!(sign_in(&server, "guess", &[("Origin", "https://evil.example")]).await.status, 403);
    }
    let bearer = format!("Bearer {}", server.login().await); // the owner is not locked out by any of that
    let foreign = [("Authorization", bearer.as_str()), ("Origin", "http://attacker.example:9000")];
    assert_eq!(server.request("POST", LOGOUT, &foreign, None).await.status, 403);
    assert!(logged("attacker.example").iter().any(|line| line.contains(" WARNING ")));

    // The server's own page (a LAN address or name) and non-browser clients are unaffected.
    let own = format!("http://{}", server.address);
    let from_own_page = [("Authorization", bearer.as_str()), ("Origin", own.as_str())];
    assert_eq!(server.request("GET", "/client/stations", &from_own_page, None).await.status, 200);
    assert_eq!(sign_in(&server, PASSWORD, &[("Origin", "http://nas.local:9000")]).await.status, 200);
    assert_eq!(sign_in(&server, PASSWORD, &[]).await.status, 200);
    // Pages (which need no token) are still served to anyone; only the API is guarded.
    assert_eq!(server.request("GET", "/", &[("Origin", "https://evil.example")], None).await.status, 200);
}

#[tokio::test]
async fn a_listed_public_name_may_use_the_api() {
    let server = TestServer::with(&[("GRIZZLE_ALLOWED_HOSTS", "grizzle.example.com")]).await;
    assert_eq!(sign_in(&server, PASSWORD, &[("Origin", "https://grizzle.example.com")]).await.status, 200);
    assert_eq!(sign_in(&server, PASSWORD, &[("Origin", "https://other.example.com")]).await.status, 403);
}

#[tokio::test]
async fn odd_content_types_are_not_server_errors() {
    let server = TestServer::start().await;
    let body = json!({"emailOrPhone": EMAIL, "password": "wrong"}).to_string();
    for content_type in ["application/json; charset=no-such-codec", "application/json; charset=", "text/plain"] {
        let response = server.request("POST", LOGIN, &[("Content-Type", content_type)], Some(body.as_bytes())).await;
        assert!([400, 401].contains(&response.status), "{content_type}: {}", response.status);
    }
}

// A timezone the system doesn't know.

#[test]
fn an_unknown_timezone_is_reported_not_silently_utc() {
    // TZ=US/Mountain on an image without the legacy zone names, or a typo: schedules were quietly
    // evaluated in UTC, hours away from the owner's clock. (That the old alias and a good name
    // give no warning is in the unit tests of src/config.rs.)
    const SERIAL: &str = "GRD-API-MARS";
    capture_logs();
    let pairs = [("TZ", "Mars/Olympus_Mons"), ("GRIZZLE_API_PASSWORD", "a long passphrase")];
    let settings = Settings::from_pairs(&pairs).unwrap();
    let warnings = settings.security_warnings();
    assert!(warnings.iter().any(|warning| warning.contains("Mars/Olympus_Mons") && warning.contains("UTC")));
    let station = Station::new(SERIAL, &settings);
    for _ in 0..5 {
        assert_eq!(station_tz(&station, &settings).name(), "UTC");
    }
    assert_eq!(logged("Mars/Olympus_Mons").len(), 1); // said once, not on every tick
}

// The sign-in limit, again: in parallel, behind a proxy.

#[tokio::test]
async fn parallel_guesses_do_not_slip_past_the_limit() {
    // The limit was asked before the body was read and the failure noted after: requests whose
    // bodies arrive together had all been let in by the time any of them counted as a failure.
    let server = TestServer::start().await;
    let address = server.address;
    let guess = |n: usize| async move {
        let body = json!({"emailOrPhone": EMAIL, "password": format!("guess-{n}")}).to_string();
        let head = format!(
            "POST {LOGIN} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        // The server has the headers, and is waiting, for every one of them.
        tokio::time::sleep(Duration::from_millis(300)).await;
        stream.write_all(body.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response["HTTP/1.1 ".len()..][..3].to_string()
    };
    let statuses = join_all((0..40).map(guess)).await;
    assert_eq!(statuses.iter().filter(|status| *status == "401").count(), LOGIN_MAX_FAILURES, "{statuses:?}");
    assert_eq!(statuses.iter().filter(|status| *status == "429").count(), 40 - LOGIN_MAX_FAILURES, "{statuses:?}");
}

#[tokio::test]
async fn behind_a_trusted_proxy_one_client_cannot_lock_the_others_out() {
    let server = TestServer::with(&[("GRIZZLE_TRUSTED_PROXIES", "127.0.0.1")]).await;
    let mut last = 0;
    for _ in 0..LOGIN_MAX_FAILURES + 2 {
        last = sign_in(&server, "guess", &[("X-Forwarded-For", "203.0.113.50")]).await.status;
    }
    assert_eq!(last, 429);
    assert_eq!(sign_in(&server, PASSWORD, &[("X-Forwarded-For", "198.51.100.7")]).await.status, 200);
}

// Host names, once more.

#[tokio::test]
async fn the_refusal_says_exactly_what_to_set() {
    let server = TestServer::start().await;
    let response = sign_in(&server, PASSWORD, &[("Origin", "http://nas.fritz.box:9000")]).await;
    assert_eq!(response.status, 403);
    assert!(response.json()["message"].as_str().unwrap().contains("GRIZZLE_ALLOWED_HOSTS=nas.fritz.box"));
}

#[tokio::test]
async fn a_body_that_does_not_match_its_content_encoding_is_not_an_error_of_ours() {
    // The Python server's HTTP library used to decompress request bodies itself: a body that only
    // claimed to be gzip dropped the connection and logged a traceback, on the public sign-in
    // path, for anyone who asked. Bodies are read as they come, whatever they claim to be.
    capture_logs();
    let server = TestServer::start().await;
    for encoding in ["deflate", "gzip", "br", "nonsense"] {
        let headers = [("Content-Type", "application/json"), ("Content-Encoding", encoding)];
        for path in [LOGIN, REFRESH] {
            let response = server.request("POST", path, &headers, Some(b"\x1f\x8b not really compressed")).await;
            assert_eq!(response.status, 400, "{encoding} {path}");
            let response = server.request("POST", path, &headers, Some(br#"{"emailOrPhone": "x"}"#)).await;
            assert_eq!(response.status, 401, "{encoding} {path}"); // plain JSON is read as plain JSON
        }
    }
    // The log is shared by every test in this file; none of them gives the server a reason for an error.
    assert_eq!(logged(" ERROR "), Vec::<String>::new());
}
