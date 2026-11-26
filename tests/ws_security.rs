//! Security regressions: REST auth can't be skipped with an Upgrade header, and a charger's
//! identity can't be taken over by another WebSocket client (browser page, LAN device).

mod support;

use std::sync::Arc;
use std::time::Duration;

use grizzle_local::api::{PUBLIC_PATHS, ROUTES};
use grizzle_local::config::Settings;
use grizzle_local::ocpp::Connection;

use support::{capture_logs, logged, settings, wait_for, Connect, FakeCharger, FakeOptions, RawCharger, TestServer};

const SERIAL: &str = "GRD-L0000TEST1";
const OTHER: &str = "GRD-L0000TEST2";
const AUTH_KEY: &str = "s3cr3t-auth-key";

/// A real charger as SERIAL, booted. An empty key is a charger that has none.
async fn start_charger(server: &TestServer, auth_key: &str) -> FakeCharger {
    let options = FakeOptions { auth_key: auth_key.to_string(), ..FakeOptions::default() };
    FakeCharger::connect_with(server, SERIAL, options).await.expect("the charger is admitted")
}

/// Open a raw WebSocket; 101 on success (then close it) or the HTTP status of the refusal.
async fn ws_status(server: &TestServer, how: Connect) -> u16 {
    match RawCharger::connect_with(server, &how).await {
        Ok(charger) => {
            charger.close().await;
            101
        }
        Err(status) => status,
    }
}

/// [`ws_status`] for `/ocpp1.6/<serial>`, with the serial and this key as credentials if given.
async fn status(server: &TestServer, serial: &str, key: Option<&str>) -> u16 {
    let how = Connect::serial(serial);
    ws_status(server, key.map_or(how.clone(), |key| how.auth(serial, key))).await
}

/// [`ws_status`] for a charger whose only id is its HTTP Basic user.
async fn status_by_user(server: &TestServer, user: &str, key: &str) -> u16 {
    ws_status(server, Connect::path("/ocpp1.6").auth(user, key)).await
}

/// The key "é" the way a client that encodes credentials as Latin-1 sends it: not even UTF-8.
fn non_ascii_key(serial: &str) -> Connect {
    let credentials = [serial.as_bytes(), b":\xe9"].concat();
    Connect::serial(serial).header("Authorization", &format!("Basic {}", openssl::base64::encode_block(&credentials)))
}

/// Stop the server and start another over the same data, configured by `pairs`.
async fn restart(server: TestServer, pairs: &[(&str, &str)]) -> TestServer {
    let dir = server.stop().await;
    let settings = settings(dir.path(), pairs);
    TestServer::with_settings(dir, settings).await
}

/// A server that gives a connection this long to prove it is alive.
async fn server_with_liveness(timeout: Duration) -> TestServer {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let mut settings = settings(dir.path(), &[]);
    settings.liveness_timeout = timeout;
    TestServer::with_settings(dir, settings).await
}

fn pinned_key(server: &TestServer, serial: &str) -> Option<String> {
    server.controller().lock().stations.get(serial).and_then(|station| station.ocpp_auth_key.clone())
}

fn connection(server: &TestServer, serial: &str) -> Option<Arc<Connection>> {
    server.controller().lock().connections.get(serial).cloned()
}

fn is_current(server: &TestServer, serial: &str, conn: &Arc<Connection>) -> bool {
    connection(server, serial).is_some_and(|current| Arc::ptr_eq(&current, conn))
}

fn station_ids(server: &TestServer) -> Vec<String> {
    let mut ids: Vec<String> = server.controller().lock().stations.keys().cloned().collect();
    ids.sort();
    ids
}

async fn wait_offline(server: &TestServer, serial: &str) {
    wait_for("the charger to be offline", || !server.controller().is_online(serial)).await;
}

// #1: the Upgrade header must not skip REST authentication

#[tokio::test]
async fn upgrade_header_does_not_bypass_rest_auth() {
    let server = TestServer::start().await;
    let charger = start_charger(&server, AUTH_KEY).await; // so station routes would otherwise succeed
    let body = br#"{"mode": "Inactive", "action": "Reset"}"#;
    let json = ("Content-Type", "application/json");
    let variants: [&[(&str, &str)]; 2] =
        [&[("Upgrade", "websocket"), json], &[("Upgrade", "WebSocket"), ("Connection", "Upgrade"), json]];
    for headers in variants {
        let mut protected = 0;
        // Every /client and /local route the server has, except the ones meant to be public.
        let api = |pattern: &str| pattern.starts_with("/client/") || pattern.starts_with("/local/");
        for (method, pattern, _) in
            ROUTES.iter().filter(|(_, pattern, _)| api(pattern) && !PUBLIC_PATHS.contains(pattern))
        {
            let path = pattern.replace("{}", SERIAL);
            let response = server.request(method, &path, headers, Some(body)).await;
            assert_eq!(response.status, 401, "{method} {path} with {headers:?}");
            protected += 1;
        }
        assert_eq!(protected, 25, "a new route? then this test covers it too, and the count goes up");
    }
    assert!(server.controller().is_online(SERIAL));
    charger.close().await;
}

#[tokio::test]
async fn upgrade_header_does_not_mint_tokens() {
    let server = TestServer::start().await;
    let before = server.controller().lock().tokens.len();
    for _ in 0..5 {
        server.request("GET", "/client/auth/profile", &[("Upgrade", "websocket")], None).await;
    }
    assert_eq!(server.controller().lock().tokens.len(), before);
}

// #2: charger identity takeover

#[tokio::test]
async fn browser_origin_is_refused() {
    let server = TestServer::start().await;
    for origin in ["http://evil.example", "null"] {
        let how = Connect::serial("GRD-BROWSER1").header("Origin", origin).auth("x", "y");
        assert_eq!(ws_status(&server, how).await, 403, "{origin}");
        assert!(!server.controller().lock().stations.contains_key("GRD-BROWSER1"));
    }
}

#[tokio::test]
async fn invalid_charge_point_id_is_refused() {
    let server = TestServer::start().await;
    let too_long = format!("/ocpp1.6/{}", "A".repeat(65));
    let cases = [
        ("/ocpp1.6/bad%0Did", None), // CR in the path tail
        (too_long.as_str(), None),
        ("/ocpp1.6/a%20b", None),                   // space
        ("/ocpp1.6", Some("Z\n2026-11-11 FORGED")), // newline in the Basic-auth user
        ("/ocpp1.6", Some(".")),                    // not addressable through the REST API
        ("/ocpp1.6", Some("..")),
        ("/ocpp1.6", Some("-leading-dash")),
    ];
    for (path, user) in cases {
        let how = Connect::path(path);
        let how = user.map_or(how.clone(), |user| how.auth(user, "key"));
        assert_eq!(ws_status(&server, how).await, 400, "{path} as {user:?}");
        assert!(server.controller().lock().stations.is_empty());
    }
}

#[tokio::test]
async fn pinned_key_rejects_impostor_and_keeps_real_charger() {
    let server = TestServer::start().await;
    let charger = start_charger(&server, AUTH_KEY).await;
    let real = connection(&server, SERIAL).unwrap();
    assert_eq!(pinned_key(&server, SERIAL).as_deref(), Some(AUTH_KEY));

    assert_eq!(status(&server, SERIAL, Some("attacker-key")).await, 401);
    assert_eq!(status(&server, SERIAL, None).await, 401); // no credentials at all
    assert_eq!(status_by_user(&server, SERIAL, "attacker-key").await, 401); // id via user
    assert_eq!(ws_status(&server, non_ascii_key(SERIAL)).await, 401);
    assert_eq!(status(&server, SERIAL, Some("é")).await, 401); // the same key as UTF-8

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(is_current(&server, SERIAL, &real), "the real charger was displaced");
    assert!(!charger.is_closed());
    assert_eq!(pinned_key(&server, SERIAL).as_deref(), Some(AUTH_KEY));
    charger.close().await;
}

#[tokio::test]
async fn pinned_key_rejected_even_when_charger_offline() {
    let server = TestServer::start().await;
    start_charger(&server, AUTH_KEY).await.close().await;
    wait_offline(&server, SERIAL).await;

    assert_eq!(status(&server, SERIAL, Some("attacker-key")).await, 401);
    assert_eq!(status(&server, SERIAL, None).await, 401);
    assert_eq!(pinned_key(&server, SERIAL).as_deref(), Some(AUTH_KEY));
}

/// A real charger reconnecting without closing its old socket must still get in.
#[tokio::test]
async fn reconnect_with_same_key_replaces_stale_socket() {
    let server = TestServer::start().await;
    let first = start_charger(&server, AUTH_KEY).await;
    let old = connection(&server, SERIAL).unwrap();
    let second = start_charger(&server, AUTH_KEY).await;
    assert!(connection(&server, SERIAL).is_some() && !is_current(&server, SERIAL, &old));
    wait_for("the old socket to be closed", || first.is_closed()).await;
    second.close().await;
}

/// A charger that never presented a key can't be pinned, but it still can't be displaced.
#[tokio::test]
async fn unauthenticated_connection_cannot_displace_live_charger() {
    let server = TestServer::start().await;
    let charger = start_charger(&server, "").await;
    assert_eq!(pinned_key(&server, SERIAL), None);
    let real = connection(&server, SERIAL).unwrap();
    assert_eq!(status(&server, SERIAL, None).await, 409);
    assert_eq!(status(&server, SERIAL, Some("")).await, 409);
    assert_eq!(status(&server, SERIAL, Some("some-key")).await, 409);
    assert!(is_current(&server, SERIAL, &real));
    assert_eq!(pinned_key(&server, SERIAL), None);
    charger.close().await;
}

#[tokio::test]
async fn new_station_without_key_can_still_onboard() {
    let server = TestServer::start().await;
    assert_eq!(status(&server, "GRD-NEW00001", None).await, 101);
    assert!(server.controller().lock().stations.contains_key("GRD-NEW00001"));
}

#[tokio::test]
async fn global_ocpp_password() {
    let server = TestServer::with(&[("GRIZZLE_OCPP_PASSWORD", "shared-pw")]).await;
    assert_eq!(status(&server, "GRD-A0000001", None).await, 401);
    assert_eq!(status(&server, "GRD-A0000001", Some("nope")).await, 401);
    assert_eq!(ws_status(&server, non_ascii_key("GRD-A0000001")).await, 401);
    assert_eq!(status(&server, "GRD-A0000001", Some("é")).await, 401);
    assert_eq!(status(&server, "GRD-A0000001", Some("shared-pw")).await, 101);
}

#[tokio::test]
async fn changing_global_password_does_not_lock_chargers_out() {
    let server = TestServer::with(&[("GRIZZLE_OCPP_PASSWORD", "old-pw")]).await;
    assert_eq!(status(&server, "GRD-ROT00001", Some("old-pw")).await, 101);
    let server = restart(server, &[("GRIZZLE_OCPP_PASSWORD", "new-pw")]).await;
    assert_eq!(status(&server, "GRD-ROT00001", Some("old-pw")).await, 401);
    assert_eq!(status(&server, "GRD-ROT00001", Some("new-pw")).await, 101);
    // The recorded key follows the password (firmware_capture reads it).
    assert_eq!(pinned_key(&server, "GRD-ROT00001").as_deref(), Some("new-pw"));
}

#[tokio::test]
async fn pin_is_saved_immediately_and_survives_restart() {
    let server = TestServer::start().await;
    assert_eq!(status(&server, SERIAL, Some(AUTH_KEY)).await, 101);
    // On disk before any tick or shutdown save: a crash right now must not lose the pin.
    assert_eq!(server.saved_state()["stations"][SERIAL]["ocppAuthKey"], AUTH_KEY);
    let server = restart(server, &[]).await;
    assert_eq!(status(&server, SERIAL, Some("attacker-key")).await, 401);
    assert_eq!(status(&server, SERIAL, Some(AUTH_KEY)).await, 101);
}

/// A keyless charger reconnecting while its dead old socket is still open must get back in.
#[tokio::test]
async fn stale_socket_without_key_is_replaced() {
    let server = server_with_liveness(Duration::from_millis(300)).await;
    let stale = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    stale.set_answer(false); // never answers
    wait_for("the stale socket to be registered", || server.controller().is_online(SERIAL)).await;
    let old = connection(&server, SERIAL).unwrap();
    assert_eq!(status(&server, SERIAL, None).await, 101);
    assert!(!is_current(&server, SERIAL, &old));
    stale.close().await;
}

/// Someone presenting a key while a keyless charger is offline must not lock it out.
#[tokio::test]
async fn keyless_station_is_not_pinned_by_a_later_key() {
    let server = TestServer::start().await;
    assert_eq!(status(&server, SERIAL, None).await, 101); // the real, keyless charger
    wait_offline(&server, SERIAL).await;
    assert_eq!(status(&server, SERIAL, Some("squatter")).await, 101);
    assert_eq!(pinned_key(&server, SERIAL), None);
    wait_offline(&server, SERIAL).await;
    assert_eq!(status(&server, SERIAL, None).await, 101); // still gets in
}

/// Trust on first use: whoever connects first under an unseen serial with a key owns it.
#[tokio::test]
async fn first_key_on_new_serial_is_pinned() {
    let server = TestServer::start().await;
    assert_eq!(status(&server, "GRD-NEW00002", Some("first")).await, 101);
    wait_offline(&server, "GRD-NEW00002").await;
    assert_eq!(status(&server, "GRD-NEW00002", Some("second")).await, 401);
}

#[tokio::test]
async fn clear_pinned_key_requires_auth_and_allows_new_key() {
    let server = TestServer::start().await;
    start_charger(&server, AUTH_KEY).await.close().await;
    wait_offline(&server, SERIAL).await;

    let path = format!("/local/stations/{SERIAL}/auth-key");
    assert_eq!(server.delete(&path, None).await.status, 401);
    assert_eq!(server.request("DELETE", &path, &[("Upgrade", "websocket")], None).await.status, 401);
    assert_eq!(pinned_key(&server, SERIAL).as_deref(), Some(AUTH_KEY));

    let token = server.login().await;
    assert_eq!(server.delete(&path, Some(&token)).await.status, 200);
    assert_eq!(pinned_key(&server, SERIAL), None);

    let charger = start_charger(&server, "new-key").await;
    assert_eq!(pinned_key(&server, SERIAL).as_deref(), Some("new-key"));
    charger.close().await;
}

#[tokio::test]
async fn clear_pinned_key_drops_live_connection_so_charger_repins() {
    let server = TestServer::start().await;
    let charger = start_charger(&server, AUTH_KEY).await;
    let token = server.login().await;
    assert_eq!(server.delete(&format!("/local/stations/{SERIAL}/auth-key"), Some(&token)).await.status, 200);
    wait_for("the charger to be dropped", || charger.is_closed()).await;
    assert!(server.saved_state()["stations"][SERIAL].get("ocppAuthKey").is_none());

    let charger = start_charger(&server, "rotated-key").await;
    assert_eq!(pinned_key(&server, SERIAL).as_deref(), Some("rotated-key"));
    charger.close().await;
}

/// Two first connections for an unpinned serial race between the check and the install:
/// only one may get in, and the installed connection must be the one whose key is pinned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_connections_cannot_both_get_in() {
    let server = &TestServer::start().await;
    // The Python test slows the check down to hold the window open. Here the check for a new
    // serial never waits, so the handshakes are only run side by side, several times over.
    for round in 0..10 {
        let serial = &format!("GRD-RACE{round:04}");
        let attempt = |key: &'static str| async move {
            (key, RawCharger::connect(server, serial, Some((serial.as_str(), key))).await)
        };
        let results = <[_; 2]>::from(tokio::join!(attempt("key-a"), attempt("key-b")));
        let winners: Vec<&str> = results.iter().filter(|(_, result)| result.is_ok()).map(|(key, _)| *key).collect();
        let refused: Vec<u16> = results.iter().filter_map(|(_, result)| result.as_ref().err().copied()).collect();
        assert_eq!((winners.len(), refused), (1, vec![401]), "{serial}");
        assert_eq!(pinned_key(server, serial).as_deref(), Some(winners[0]));
        assert!(server.controller().is_online(serial));
    }
    assert_eq!(server.controller().admissions_in_progress(), 0, "nothing is kept per serial once a handshake is over");

    // The one wait the check does have is the liveness probe, so with a dead socket holding the
    // serial two handshakes overlap for certain. Checked one after the other, the second finds
    // the first answering; checked at the same time, both would see the dead socket and get in.
    let server = server_with_liveness(Duration::from_secs(1)).await;
    let stale = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    stale.set_answer(false);
    wait_for("the stale socket to be registered", || server.controller().is_online(SERIAL)).await;
    let (first, second) =
        tokio::join!(RawCharger::connect(&server, SERIAL, None), RawCharger::connect(&server, SERIAL, None));
    let mut statuses = [first.as_ref().err().copied(), second.as_ref().err().copied()];
    statuses.sort();
    assert_eq!(statuses, [None, Some(409)]);
    assert!(server.controller().is_online(SERIAL));
}

// #3: GRIZZLE_ALLOWED_CHARGERS, the serials that may connect at all

/// What config.rs's own test of this name leaves out (it has the separators, the blank list and
/// the quoted entry).
#[test]
fn allowed_chargers_setting() {
    let listing = |value: &str| {
        Settings::from_pairs(&[("GRIZZLE_ALLOWED_CHARGERS", value), ("GRIZZLE_API_PASSWORD", "a long passphrase")])
    };
    assert!(Settings::defaults().allowed_chargers.is_empty());
    let listed = listing(&format!(" {SERIAL},{OTHER}  unknown-192.168.1.50 ")).unwrap().allowed_chargers;
    assert_eq!(listed, [SERIAL, OTHER, "unknown-192.168.1.50"]);
    // An entry no charger could ever present is an error at startup rather than a charger that
    // is silently never let in.
    for impossible in [format!("{SERIAL};"), "*".to_string(), "-GRD".to_string(), "x".repeat(65)] {
        let err = listing(&impossible).unwrap_err();
        let said = err.split_once("GRIZZLE_ALLOWED_CHARGERS").is_some_and(|(_, rest)| rest.contains("leave it unset"));
        assert!(said, "{impossible}: {err}");
    }
    // The name a charger without an id is given can be listed, but it is not a serial: say so.
    let warnings = listing(&format!("{SERIAL} unknown-192.168.1.50")).unwrap().security_warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("unknown-192.168.1.50") && !warnings[0].contains(SERIAL), "{warnings:?}");
    assert!(listing(SERIAL).unwrap().security_warnings().is_empty());
}

#[tokio::test]
async fn a_blank_list_lets_any_serial_connect() {
    for blank in ["", " , "] {
        // in compose: GRIZZLE_ALLOWED_CHARGERS: ""
        let server = TestServer::with(&[("GRIZZLE_ALLOWED_CHARGERS", blank)]).await;
        assert_eq!(status(&server, OTHER, None).await, 101, "{blank:?}");
    }
}

#[tokio::test]
async fn only_listed_serials_may_connect() {
    capture_logs();
    let server = TestServer::with(&[("GRIZZLE_ALLOWED_CHARGERS", &format!("{SERIAL}, {OTHER}"))]).await;
    assert_eq!(status(&server, SERIAL, Some(AUTH_KEY)).await, 101);
    assert_eq!(status(&server, OTHER, None).await, 101);
    // Not listed: near misses, another spelling, and the name given to a charger that sends no serial.
    let near_misses = [SERIAL.to_lowercase(), SERIAL[..SERIAL.len() - 1].to_string(), format!("{SERIAL}1")];
    for stranger in ["GRD-L0000TEST3", "unknown-127.0.0.1"].into_iter().chain(near_misses.iter().map(String::as_str)) {
        assert_eq!(status(&server, stranger, None).await, 401, "{stranger}");
    }
    // However the serial is given: as the HTTP Basic user, or not at all. And the serial in the
    // path is the one that counts: a listed Basic user does not let another serial in.
    assert_eq!(status_by_user(&server, "GRD-L0000TEST3", "key").await, 401);
    assert_eq!(ws_status(&server, Connect::path("/ocpp1.6")).await, 401);
    assert_eq!(ws_status(&server, Connect::serial("GRD-L0000TEST3").auth(SERIAL, AUTH_KEY)).await, 401);
    wait_offline(&server, OTHER).await;
    assert_eq!(status_by_user(&server, OTHER, "").await, 101);
    assert_eq!(station_ids(&server), [SERIAL, OTHER]); // nothing was kept for the others
    let rejections = logged("GRD-L0000TEST3: rejected connection");
    assert!(rejections.iter().any(|line| line.contains("GRIZZLE_ALLOWED_CHARGERS")), "{rejections:?}");
}

/// The list keeps other serials out. A serial is printed on the charger and anyone can present
/// it: what keeps someone else from being taken for a listed charger is still its key.
#[tokio::test]
async fn a_listed_serial_still_needs_its_key() {
    let server = TestServer::with(&[("GRIZZLE_ALLOWED_CHARGERS", SERIAL)]).await;
    let charger = start_charger(&server, AUTH_KEY).await; // the real one; its key is pinned
    assert_eq!(status(&server, SERIAL, None).await, 401);
    assert_eq!(status(&server, SERIAL, Some("a guess")).await, 401);
    assert!(server.controller().is_online(SERIAL));
    charger.close().await;
    wait_offline(&server, SERIAL).await;
    assert_eq!(status(&server, SERIAL, Some("a guess")).await, 401);
    assert_eq!(status(&server, SERIAL, Some(AUTH_KEY)).await, 101);
}

/// A charger that sends no key has only its serial. Listed or not, whoever else presents that
/// serial is refused for as long as the charger is connected and answering.
#[tokio::test]
async fn a_listed_charger_without_a_key_cannot_be_displaced_while_it_answers() {
    let server = TestServer::with(&[("GRIZZLE_ALLOWED_CHARGERS", OTHER)]).await;
    let _charger = RawCharger::connect(&server, OTHER, None).await.unwrap();
    wait_for("the charger to be registered", || server.controller().is_online(OTHER)).await;
    let real = connection(&server, OTHER).unwrap();
    assert_eq!(status(&server, OTHER, None).await, 409);
    assert_eq!(status(&server, OTHER, Some("a guess")).await, 409);
    assert!(is_current(&server, OTHER, &real));
}

#[tokio::test]
async fn the_station_limit_still_applies_to_listed_serials() {
    let listed = format!("{SERIAL},{OTHER}");
    let server = TestServer::with(&[("GRIZZLE_ALLOWED_CHARGERS", &listed), ("GRIZZLE_MAX_STATIONS", "1")]).await;
    assert_eq!(status(&server, SERIAL, None).await, 101);
    assert_eq!(status(&server, OTHER, None).await, 503);
}

#[tokio::test]
async fn a_charger_that_sends_no_id_can_be_listed_by_the_name_it_is_given() {
    let server = TestServer::with(&[("GRIZZLE_ALLOWED_CHARGERS", "unknown-127.0.0.1")]).await;
    assert_eq!(ws_status(&server, Connect::path("/ocpp1.6")).await, 101);
    assert_eq!(status(&server, SERIAL, None).await, 401);
}

#[tokio::test]
async fn the_list_applies_with_a_shared_ocpp_password_too() {
    let server =
        TestServer::with(&[("GRIZZLE_ALLOWED_CHARGERS", SERIAL), ("GRIZZLE_OCPP_PASSWORD", "shared-pw")]).await;
    assert_eq!(status(&server, OTHER, Some("shared-pw")).await, 401);
    assert_eq!(status(&server, SERIAL, Some("wrong")).await, 401);
    assert_eq!(status(&server, SERIAL, Some("shared-pw")).await, 101);
    assert_eq!(station_ids(&server), [SERIAL]);
}

#[tokio::test]
async fn a_station_left_off_the_list_is_kept_but_cannot_connect() {
    let server = TestServer::start().await; // no list yet
    assert_eq!(status(&server, OTHER, None).await, 101);
    let server = restart(server, &[("GRIZZLE_ALLOWED_CHARGERS", SERIAL)]).await;
    assert_eq!(status(&server, OTHER, None).await, 401);
    assert_eq!(station_ids(&server), [OTHER]);
}

/// A charger that registered before the list existed presents the right key: the list still decides.
#[tokio::test]
async fn a_pinned_station_left_off_the_list_cannot_connect_with_its_own_key() {
    let server = TestServer::start().await; // no list yet
    assert_eq!(status(&server, OTHER, Some(AUTH_KEY)).await, 101);
    let server = restart(server, &[("GRIZZLE_ALLOWED_CHARGERS", SERIAL)]).await;
    assert_eq!(status(&server, OTHER, Some(AUTH_KEY)).await, 401);
    assert_eq!(pinned_key(&server, OTHER).as_deref(), Some(AUTH_KEY)); // kept, pin and all
    assert!(!server.controller().is_online(OTHER));
}
