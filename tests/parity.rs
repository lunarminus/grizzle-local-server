//! Things the Python server did that the first Rust version of it did not, found by comparing
//! the two side by side. None of them is in the Python test suite: nobody had thought to test
//! what the framework underneath did by itself.

mod support;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{http, wait_for, RawCharger, TestServer};

const BINARY: &str = env!("CARGO_BIN_EXE_grizzle-local");
const SERIAL: &str = "GRD-PARITY01";

/// The WebSocket handshake a charger sends, as bytes.
fn upgrade_request(serial: &str) -> Vec<u8> {
    format!(
        "GET /ocpp1.6/{serial} HTTP/1.1\r\nHost: grizzle\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: ocpp1.6\r\n\r\n"
    )
    .into_bytes()
}

/// Read from `stream` until `done` says the bytes so far are enough (or five seconds pass).
async fn read_until(stream: &mut TcpStream, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    let reading = async {
        let mut chunk = [0u8; 1024];
        while !done(&bytes) {
            match stream.read(&mut chunk).await {
                Ok(count) if count > 0 => bytes.extend_from_slice(&chunk[..count]),
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), reading).await;
    bytes
}

/// A client is supposed to mask its frames, small embedded ones are known not to, and the Python
/// server answered either kind.
#[tokio::test]
async fn frames_that_are_not_masked_are_answered() {
    let server = TestServer::start().await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&upgrade_request(SERIAL)).await.unwrap();
    let head = read_until(&mut stream, |bytes| bytes.ends_with(b"\r\n\r\n")).await;
    assert!(head.starts_with(b"HTTP/1.1 101 "), "{}", String::from_utf8_lossy(&head));

    let call = br#"[2,"1","Heartbeat",{}]"#;
    let mut frame = vec![0x81, call.len() as u8]; // a final text frame, mask bit not set
    frame.extend_from_slice(call);
    stream.write_all(&frame).await.unwrap();
    let reply = read_until(&mut stream, |bytes| bytes.len() >= 2 && bytes.len() >= 2 + usize::from(bytes[1])).await;
    assert_eq!(reply.first(), Some(&0x81), "{reply:?}");
    let text = String::from_utf8_lossy(&reply[2..]);
    assert!(text.starts_with(r#"[3,"1",{"currentTime":"#), "{text}");
    assert!(server.controller().is_online(SERIAL));
}

/// Every ping is owed an answer. From a peer that never reads its answers, the server stops
/// taking pings (its reading is rate-limited like any other frame, and what waits to be written
/// is bounded) instead of queueing an answer to each for as long as the peer cares to go on.
#[tokio::test]
async fn a_peer_that_pings_without_reading_is_not_served_without_limit() {
    let server = TestServer::start().await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&upgrade_request(SERIAL)).await.unwrap();
    let head = read_until(&mut stream, |bytes| bytes.ends_with(b"\r\n\r\n")).await;
    assert!(head.starts_with(b"HTTP/1.1 101 "), "{}", String::from_utf8_lossy(&head));

    let mut ping = vec![0x89, 125]; // a ping with as much in it as a ping may hold, not masked
    ping.extend_from_slice(&[b'p'; 125]);
    let block = ping.repeat(512);
    let mut taken = 0usize;
    let flood = async {
        loop {
            stream.write_all(&block).await.unwrap();
            taken += block.len();
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), flood).await;
    // What fits in the socket's buffers on the way is taken, and a burst of frames; not more.
    assert!(taken < 16 << 20, "the server took {} MB of pings in three seconds", taken >> 20);
    assert_eq!(server.get("/health", None).await.status, 200, "and it still answers everybody else");
}

/// A charger that ends the connection properly is answered with a close, not cut off.
#[tokio::test]
async fn a_charger_that_closes_gets_a_close_back() {
    let server = TestServer::start().await;
    let charger = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    assert_eq!(charger.call("Heartbeat", json!({})).await[0], 3);
    charger.close().await;
    assert!(charger.is_closed());
    assert_eq!(charger.close_code(), Some(1000));
    wait_for("the server to notice", || !server.controller().is_online(SERIAL)).await;
}

/// `%2F` is a slash inside a name, never one between names: a path spelled with it is not the
/// endpoint the same path with a real slash would be.
#[tokio::test]
async fn an_encoded_slash_does_not_separate_path_segments() {
    let server = TestServer::start().await;
    let token = server.login().await;
    let charger = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    assert_eq!(charger.call("Heartbeat", json!({})).await[0], 3);
    let send = |method: &'static str, path: String| {
        let (server, token) = (&server, token.as_str());
        async move { server.send(method, &path, Some(token), None).await }
    };

    assert_eq!(send("GET", "/client/stations".into()).await.status, 200);
    assert_eq!(send("GET", "/cl%69ent/stations".into()).await.status, 200, "any other escape is just a letter");
    for path in
        ["/client%2Fstations", "/client%2fstations", "/local%2Fholidays/countries", "/local/holidays%2Fcountries"]
    {
        for method in ["GET", "HEAD"] {
            assert_eq!(send(method, path.into()).await.status, 404, "{method} {path}");
        }
    }
    for (method, path) in
        [("POST", "/client%2Fauth/login".to_string()), ("DELETE", format!("/local%2Fstations/{SERIAL}"))]
    {
        let response = send(method, path.clone()).await;
        assert_eq!((response.status, response.header("allow")), (405, Some("GET,HEAD")), "{method} {path}");
    }
    assert_eq!(send("GET", format!("/client/stations/{SERIAL}/events")).await.status, 200);
    let response = send("GET", format!("/client/stations/{SERIAL}%2Fevents")).await;
    assert_eq!((response.status, response.body.as_str()), (404, "unknown station"), "a station called \"…/events\"");
    assert!(server.controller().lock().stations.contains_key(SERIAL), "and nothing was deleted");
    // Without a session it is refused before it is looked at, as its plain spelling would be.
    assert_eq!(server.get("/client%2Fstations", None).await.status, 401);
}

/// The calls the server has sent that `charger` has not been made to answer yet, answered now.
fn accept_calls(charger: &RawCharger, answered: &mut usize) {
    let frames = charger.frames();
    for frame in &frames[*answered..] {
        let frame: Value = serde_json::from_str(frame).unwrap();
        if frame[0] == 2 {
            charger.send_text(&json!([3, frame[1], {"status": "Accepted"}]).to_string());
        }
    }
    *answered = frames.len();
}

/// A command whose client hangs up while the charger is still thinking is carried through: the
/// charger's answer is waited for and recorded, as if the client were still there.
#[tokio::test]
async fn a_command_is_finished_even_if_its_client_hangs_up() {
    // No background round during the test: it would send the limit again and hide the difference.
    let server = TestServer::with(&[("GRIZZLE_TICK_SECONDS", "3600")]).await;
    let token = server.login().await;
    let charger = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    let status = json!({"connectorId": 1, "status": "Available", "errorCode": "NoError"});
    assert_eq!(charger.call("StatusNotification", status).await[0], 3);
    tokio::time::sleep(Duration::from_millis(300)).await; // let anything the server wants to say first be said
    charger.set_answer(false);
    let mut answered = charger.frames().len();

    let body = r#"{"value":16}"#;
    let request = format!(
        "PUT /client/stations/{SERIAL}/currentLimit HTTP/1.1\r\nHost: grizzle\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut client = TcpStream::connect(server.address).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    wait_for("the limit to be sent to the charger", || !charger.calls("SetChargingProfile").is_empty()).await;
    drop(client); // the app was closed, the phone lost its Wi-Fi
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.station(&token, SERIAL).await["smartCharging"]["appliedLimit"], Value::Null);

    let applied = || async { server.station(&token, SERIAL).await["smartCharging"]["appliedLimit"].clone() };
    for _ in 0..50 {
        accept_calls(&charger, &mut answered);
        tokio::time::sleep(Duration::from_millis(50)).await;
        if applied().await == json!(16) {
            break;
        }
    }
    assert_eq!(applied().await, json!(16), "the charger's answer was recorded");
}

/// Someone who opens connections under a charger's serial and drops them at once gets one
/// "are you still there?" sent to that charger at a time, not one per attempt.
#[tokio::test]
async fn abandoned_handshakes_do_not_each_probe_the_charger() {
    let server = TestServer::start().await;
    let charger = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    assert_eq!(charger.call("Heartbeat", json!({})).await[0], 3);
    tokio::time::sleep(Duration::from_millis(300)).await;
    charger.set_answer(false); // it is there, but slow to say so
    for _ in 0..20 {
        let mut stream = TcpStream::connect(server.address).await.unwrap();
        stream.write_all(&upgrade_request(SERIAL)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(stream);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let probes = charger.calls("TriggerMessage").len();
    assert_eq!(probes, 1, "one probe is outstanding, and the other attempts wait their turn behind it");
    assert!(server.controller().is_online(SERIAL));
}

/// A setting that cannot be read is an error. Taken for "not set", the password would silently
/// be the well-known default, with the server otherwise starting up as usual.
#[test]
fn a_setting_that_is_not_utf8_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let latin1 = |text: &[u8]| OsString::from_vec(text.to_vec());
    for name in ["GRIZZLE_API_PASSWORD", "GRIZZLE_OCPP_PASSWORD", "GRIZZLE_ALLOWED_CHARGERS", "GRIZZLE_DATA_DIR"] {
        for arguments in [&[][..], &["healthcheck"][..]] {
            let run = Command::new(BINARY)
                .args(arguments)
                .env_clear()
                .env("GRIZZLE_DATA_DIR", dir.path().join("data"))
                .env("GRIZZLE_PORT", "0")
                .env(name, latin1(b"p\xe4ssword-long"))
                .output()
                .unwrap();
            let said = String::from_utf8_lossy(&run.stderr);
            assert!(!run.status.success(), "{name} {arguments:?}: {said}");
            assert!(said.contains(name) && said.contains("not valid UTF-8"), "{name} {arguments:?}: {said}");
        }
    }
    assert!(!dir.path().join("data").exists(), "nothing was started");
}

/// An empty GRIZZLE_HOST is every address the machine has.
#[tokio::test]
async fn an_empty_host_listens_on_every_address() {
    let server = TestServer::with(&[("GRIZZLE_HOST", "")]).await;
    let port = server.address.port();
    let health = http(([127, 0, 0, 1], port).into(), "GET", "/health", &[], None).await;
    assert_eq!(health.status, 200);
}

/// "::" is IPv6, and only IPv6: it does not also open the port to every IPv4 interface.
#[tokio::test]
async fn an_ipv6_host_does_not_listen_on_ipv4_as_well() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return; // this machine has no IPv6 to try it on
    }
    let server = TestServer::with(&[("GRIZZLE_HOST", "::")]).await;
    let port = server.address.port();
    assert!(server.address.is_ipv6());
    let health = http((std::net::Ipv6Addr::LOCALHOST, port).into(), "GET", "/health", &[], None).await;
    assert_eq!(health.status, 200);
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err(), "IPv4 is not served on an IPv6 address");
}
