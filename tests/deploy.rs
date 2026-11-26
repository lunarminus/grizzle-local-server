//! Deployment-side behaviour of the server: shutting down, the TLS port and who the client really
//! is, the health check, and what the process says on stderr.
//!
//! What needs the real process (SIGTERM, the exit code, stderr) runs the built binary; the rest
//! runs a server in this process.

mod support;

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use grizzle_local::config::Settings;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_openssl::SslStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use support::{
    capture_logs, http, logged, settings, wait_for, wait_until, Connect, FakeCharger, FakeOptions, RawCharger,
    TestServer, EMAIL, PASSWORD,
};

const BINARY: &str = env!("CARGO_BIN_EXE_grizzle-local");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A self-signed certificate and key from scripts/make-cert.sh, one pair for the whole file.
fn certs() -> (&'static str, &'static str) {
    static CERTS: OnceLock<(String, String)> = OnceLock::new();
    let (cert, key) = CERTS.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("deploy-certs");
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/make-cert.sh");
        let made = Command::new("sh").arg(script).arg(&dir).output().unwrap();
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
        (dir.join("fullchain.pem").display().to_string(), dir.join("privkey.pem").display().to_string())
    });
    (cert, key)
}

/// A server in this process that also listens for TLS.
async fn tls_server(pairs: &[(&str, &str)]) -> TestServer {
    let (cert, key) = certs();
    let port = free_port().to_string();
    let mut all = vec![("GRIZZLE_TLS_CERT", cert), ("GRIZZLE_TLS_KEY", key), ("GRIZZLE_TLS_PORT", port.as_str())];
    all.extend_from_slice(pairs);
    TestServer::with(&all).await
}

/// A TLS connection to `address` made from the address `local`. Unless `verify`, any certificate
/// is accepted. `Err` is why the handshake failed.
async fn tls_from(local: &str, address: SocketAddr, verify: bool) -> Result<SslStream<TcpStream>, String> {
    let local: IpAddr = local.parse().unwrap();
    let socket = if local.is_ipv4() { TcpSocket::new_v4() } else { TcpSocket::new_v6() }.unwrap();
    socket.bind(SocketAddr::new(local, 0)).unwrap();
    let tcp = socket.connect(address).await.unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    if !verify {
        connector.set_verify(SslVerifyMode::NONE);
    }
    let ssl = connector.build().configure().unwrap().into_ssl("ocpp.unitedchargers.com").unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    Pin::new(&mut stream).connect().await.map_err(|err| err.to_string())?;
    Ok(stream)
}

/// One HTTPS request from the address `local`: the status and the body.
async fn https(local: &str, address: SocketAddr, method: &str, path: &str, body: Option<Value>) -> (u16, String) {
    let mut stream = tls_from(local, address, false).await.unwrap();
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all((head + &body).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await; // an abrupt end still leaves what was read
    let response = String::from_utf8_lossy(&response);
    let (head, body) = response.split_once("\r\n\r\n").expect("an HTTP response");
    (head.split(' ').nth(1).unwrap().parse().unwrap(), body.to_string())
}

/// A charger's WebSocket on a connection that is already open. Nothing reads it unless the test does.
async fn websocket<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    address: SocketAddr,
    path: &str,
) -> WebSocketStream<S> {
    let mut request = format!("ws://{address}{path}").into_client_request().unwrap();
    request.headers_mut().insert("Sec-WebSocket-Protocol", "ocpp1.6".parse().unwrap());
    tokio_tungstenite::client_async(request, stream).await.expect("the charger is admitted").0
}

/// The built server as a process of its own, on a free port, with its stderr collected.
struct Process {
    child: Child,
    address: SocketAddr,
    dir: tempfile::TempDir,
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl Process {
    /// Start it with these environment variables (on top of a sign-in of EMAIL / PASSWORD,
    /// loopback only, no TLS) and wait until it answers.
    async fn start(env: &[(&str, &str)]) -> Process {
        let dir = tempfile::tempdir().unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], free_port()));
        let mut child = Command::new(BINARY)
            .env_clear()
            .env("GRIZZLE_DATA_DIR", dir.path().join("data"))
            .env("GRIZZLE_HOST", "127.0.0.1")
            .env("GRIZZLE_PORT", address.port().to_string())
            .env("GRIZZLE_TLS_PORT", "0")
            .env("GRIZZLE_API_EMAIL", EMAIL)
            .env("GRIZZLE_API_PASSWORD", PASSWORD)
            .envs(env.iter().copied())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut pipe = child.stderr.take().unwrap();
        let stderr = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            text
        });
        let process = Process { child, address, dir, stderr: Some(stderr) };
        wait_for("the server to listen", || std::net::TcpStream::connect(address).is_ok()).await;
        // Once it answers it is serving, so its own handler takes a signal and not the default one.
        assert_eq!(http(address, "GET", "/health", &[], None).await.status, 200);
        process
    }

    /// SIGTERM, as `docker stop` sends it. The exit status and everything the server wrote to stderr.
    async fn terminate(&mut self) -> (ExitStatus, String) {
        assert!(Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status().unwrap().success());
        let mut status = None;
        // Docker waits ten seconds, then kills.
        wait_until("the server to exit", Duration::from_secs(8), || {
            status = self.child.try_wait().unwrap();
            status.is_some()
        })
        .await;
        (status.unwrap(), self.stderr.take().unwrap().join().unwrap())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill(); // only a test that failed leaves it running
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn sigterm_with_chargers_connected_saves_and_exits_promptly() {
    // `docker stop` with a charger connected (that is: always). A server that waits for its open
    // connections before it saves sits out the timeout, Docker kills it, and the save never runs.
    let (cert, key) = certs();
    let tls_port = free_port().to_string();
    let mut server = Process::start(&[
        ("GRIZZLE_TLS_PORT", &tls_port),
        ("GRIZZLE_TLS_CERT", cert),
        ("GRIZZLE_TLS_KEY", key),
        ("GRIZZLE_TICK_SECONDS", "3600"),
    ])
    .await;
    let tls_address = SocketAddr::new(server.address.ip(), tls_port.parse().unwrap());
    let plain = FakeCharger::connect_to(server.address, "GRD-PLAIN001", FakeOptions::default()).await.unwrap();
    let over_tls = FakeOptions { tls: true, ..FakeOptions::default() };
    let secure = FakeCharger::connect_to(tls_address, "GRD-TLS00001", over_tls).await.unwrap();
    wait_for("both chargers to boot", || plain.state().booted && secure.state().booted).await;

    // Something only the shutdown save can have written: the tick is an hour away.
    let sign_in = json!({"emailOrPhone": EMAIL, "password": PASSWORD}).to_string();
    let headers = [("Content-Type", "application/json")];
    let response = http(server.address, "POST", "/client/auth/login", &headers, Some(sign_in.as_bytes())).await;
    let token = response.json()["token"].as_str().unwrap().to_string();

    let started = Instant::now();
    let (status, stderr) = server.terminate().await;
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(status.success(), "{status}\n{stderr}");

    let state = std::fs::read_to_string(server.dir.path().join("data/state.json")).unwrap();
    let state: Value = serde_json::from_str(&state).unwrap();
    assert!(state["tokens"].get(&token).is_some());
    assert!(state["stations"].get("GRD-PLAIN001").is_some() && state["stations"].get("GRD-TLS00001").is_some());
    assert_eq!(state["stations"]["GRD-PLAIN001"]["boot"]["chargePointModel"], "GRD 40A 2025");
}

#[tokio::test]
async fn stop_saves_before_it_waits_for_sockets_to_close() {
    // A peer that never acknowledges the close must not stand between us and the save.
    const SERIAL: &str = "GRD-SLOW0001";
    let dir = std::sync::Arc::new(tempfile::tempdir().unwrap());
    let mut settings = settings(dir.path(), &[("GRIZZLE_TICK_SECONDS", "3600")]);
    settings.close_timeout = Duration::from_millis(300);
    let server = TestServer::with_settings(dir, settings).await;
    let saved =
        || std::fs::read_to_string(server.data_dir().join("state.json")).is_ok_and(|state| state.contains(SERIAL));

    let tcp = TcpStream::connect(server.address).await.unwrap();
    let mut peer = websocket(tcp, server.address, &format!("/ocpp1.6/{SERIAL}")).await;
    peer.send(Message::text(r#"[2,"1","Heartbeat",{}]"#)).await.unwrap();
    assert!(peer.next().await.unwrap().unwrap().to_text().unwrap().contains("currentTime"));
    // From here on nobody reads `peer`: the server's close frame is never answered.
    assert!(!saved());

    let started = Instant::now();
    let stop = server.controller().stop();
    tokio::pin!(stop);
    let still_closing = tokio::time::timeout(Duration::from_millis(100), &mut stop).await.is_err();
    let saved_while_closing = saved();
    if still_closing {
        stop.await;
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(still_closing && saved_while_closing, "closing: {still_closing}, saved: {saved_while_closing}");
}

#[tokio::test]
async fn no_charger_is_admitted_once_shutdown_has_begun() {
    // A handshake that is waiting on the liveness probe when shutdown starts used to be connected
    // after "every connection" had been closed: nothing closed that one, and exit waited ten seconds.
    const SERIAL: &str = "GRD-L0000HARD4";
    let server = TestServer::start().await;
    let present = RawCharger::connect(&server, SERIAL, None).await.unwrap();
    present.set_answer(false); // an unresponsive charger: the probe of it takes its time
    let address = server.address;
    let connecting =
        tokio::spawn(async move { RawCharger::connect_to(address, &Connect::serial(SERIAL)).await.map(|_| ()) });
    // The handshake is inside the admission check...
    wait_for("the liveness probe", || !present.calls("TriggerMessage").is_empty()).await;
    server.controller().stop().await; // ...when the server begins to stop
    assert_eq!(connecting.await.unwrap(), Err(503));
    assert!(server.controller().lock().connections.is_empty());
}

#[tokio::test]
async fn charger_over_wss_reaches_the_server() {
    const SERIAL: &str = "GRD-L0000TLS01";
    capture_logs();
    let server = tls_server(&[]).await;
    let options = FakeOptions { tls: true, connectors: 1, ..FakeOptions::default() };
    let charger = FakeCharger::connect_with(&server, SERIAL, options).await.unwrap();
    let token = server.login().await;
    let station = server.station(&token, SERIAL).await;
    assert_eq!(station["online"], true);
    charger.close().await;
    // No other test in this file connects from 127.0.0.1 to the TLS port of a server in this process.
    assert!(logged("handshake with 127.0.0.1:").iter().any(|line| line.contains(" OK")));
}

#[tokio::test]
async fn rejected_certificate_is_logged() {
    capture_logs();
    let server = tls_server(&[]).await;
    // A client that verifies, like a careful device would.
    let Err(refused) = tls_from("127.0.0.5", server.tls_address.unwrap(), true).await else {
        panic!("a self-signed certificate was accepted by a client that verifies");
    };
    assert!(refused.contains("certificate verify failed"), "{refused}");
    let said = || logged("REJECTED OUR CERTIFICATE").iter().any(|line| line.contains("TLS: 127.0.0.5:"));
    wait_for("the rejection to be logged", said).await;
}

#[tokio::test]
async fn tls_frontend_reports_the_real_peer() {
    const SERIAL: &str = "GRD-L0000HARD3";
    let server = tls_server(&[]).await;
    let (tls, controller) = (server.tls_address.unwrap(), server.controller());
    // The client connects from 127.0.0.3; the server itself is at 127.0.0.1.
    let stream = tls_from("127.0.0.3", tls, false).await.unwrap();
    let mut charger = websocket(stream, tls, &format!("/ocpp1.6/{SERIAL}")).await;
    wait_for("the charger to be online", || controller.is_online(SERIAL)).await;
    assert_eq!(controller.lock().stations[SERIAL].ocpp_handshake.as_ref().unwrap()["remote"], "127.0.0.3");
    charger.close(None).await.unwrap();
    // A charger that sends no id at all is named after its own address, not the server's.
    let stream = tls_from("127.0.0.3", tls, false).await.unwrap();
    let mut charger = websocket(stream, tls, "/ocpp1.6").await;
    wait_for("the placeholder station", || controller.lock().stations.contains_key("unknown-127.0.0.3")).await;
    assert!(!controller.lock().stations.contains_key("unknown-127.0.0.1"));
    charger.close(None).await.unwrap();
}

#[tokio::test]
async fn sign_in_throttle_counts_the_real_client_not_the_frontend() {
    // If every TLS client counted as one address (the server's own, as when a front end stood
    // before the plain port), one client could lock everyone else out.
    let server = tls_server(&[]).await;
    let tls = server.tls_address.unwrap();
    let sign_in = |password: &str| {
        let body = json!({"emailOrPhone": EMAIL, "password": password});
        async move { https("127.0.0.4", tls, "POST", "/client/auth/login", Some(body)).await.0 }
    };
    assert_eq!(sign_in("wrong").await, 401);
    let mut status = 0;
    for _ in 0..20 {
        status = sign_in("wrong").await;
    }
    assert_eq!(status, 429);
    assert_eq!(sign_in(PASSWORD).await, 429, "that address has to wait now, whatever it sends");
    assert_eq!(server.app.auth.throttle().tracked_clients(), 1);
    // Another address (here the plain port, from 127.0.0.1) is unaffected.
    assert_eq!(server.login_with(EMAIL, PASSWORD).await.status, 200);
}

#[tokio::test]
async fn placeholder_charger_id_uses_the_real_address() {
    let server = TestServer::start().await;
    let _charger = RawCharger::connect_with(&server, &Connect::path("/ocpp1.6")).await.unwrap(); // no serial anywhere
    wait_for("a station", || !server.controller().lock().stations.is_empty()).await;
    assert_eq!(server.controller().lock().stations.keys().collect::<Vec<_>>(), ["unknown-127.0.0.1"]);
}

#[tokio::test]
async fn tls_reaches_a_plain_listener_that_is_not_on_ipv4_loopback() {
    // With GRIZZLE_HOST=:: or one specific address nothing listens on 127.0.0.1. (The Python server
    // put a TLS front end before its plain port and always dialled 127.0.0.1: every TLS client
    // finished the handshake and was dropped.)
    let mut hosts = vec![("127.0.0.2", "127.0.0.2")]; // one specific address (any 127.x.x.x is local on Linux)
    if std::net::TcpListener::bind("[::1]:0").is_ok() {
        hosts.push(("::", "::1"));
    }
    for (host, reached_at) in hosts {
        let server = tls_server(&[("GRIZZLE_HOST", host)]).await;
        let address = SocketAddr::new(reached_at.parse().unwrap(), server.tls_address.unwrap().port());
        let (status, body) = https(reached_at, address, "GET", "/health", None).await;
        assert_eq!(status, 200, "{host}");
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["status"], "ok", "{host}");
    }
}

#[test]
fn generated_certificate_is_a_server_certificate_not_a_ca() {
    // `openssl req -x509` makes a CA by default: whoever copied privkey.pem could have signed
    // certificates for any site, valid wherever this certificate had been trusted.
    let (cert, key) = certs();
    let shown = Command::new("openssl").args(["x509", "-in", cert, "-noout", "-text"]).output().unwrap();
    assert!(shown.status.success());
    let text = String::from_utf8_lossy(&shown.stdout);
    assert!(text.contains("CA:FALSE") && !text.contains("CA:TRUE"));
    assert!(text.contains("TLS Web Server Authentication"));
    assert!(text.contains("DNS:ocpp.unitedchargers.com") && text.contains("DNS:connect-api.unitedchargers.com"));
    assert_eq!(std::fs::metadata(key).unwrap().permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn health_check_asks_where_the_server_listens() {
    // Which URL follows from which listen address is a unit test in src/healthcheck.rs.
    let server = TestServer::start().await;
    let check = |port: u16| async move {
        let mut command = Command::new(BINARY);
        command.arg("healthcheck").env_clear().env("GRIZZLE_HOST", "127.0.0.1").env("GRIZZLE_PORT", port.to_string());
        // A proxy setting must not come between us and ourselves (and no NO_PROXY keeps us from it).
        command.env("http_proxy", "http://127.0.0.1:9");
        tokio::task::spawn_blocking(move || command.output().unwrap().status.code()).await.unwrap()
    };
    assert_eq!(check(server.address.port()).await, Some(0));
    assert_eq!(check(free_port()).await, Some(1));
    let dockerfile = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Dockerfile")).unwrap();
    assert!(dockerfile.contains(r#"CMD ["grizzle-local", "healthcheck"]"#));
}

#[tokio::test]
async fn main_installs_the_formatter_that_keeps_log_lines_single() {
    let mut server = Process::start(&[("LOG_LEVEL", "WARNING"), ("GRIZZLE_API_PASSWORD", "change-me")]).await;
    // A charge point id with a line break in it, which the server refuses and says so.
    let refused = http(server.address, "GET", "/ocpp1.6/x%0Ay", &[("Upgrade", "websocket")], None).await;
    assert_eq!(refused.status, 400);
    let (_, stderr) = server.terminate().await;
    assert!(stderr.lines().any(|line| line.ends_with(r"invalid charge point id x\ny")), "{stderr}");
    // The level is the one asked for, and every line is a whole log line: date, time, level, where from.
    assert!(stderr.lines().count() >= 2, "{stderr}");
    for line in stderr.lines() {
        let words: Vec<&str> = line.splitn(4, ' ').collect();
        let whole =
            words.len() == 4 && words[0].len() == 10 && words[2] == "WARNING" && words[3].starts_with("grizzle_local");
        assert!(whole, "{line}");
    }
}

#[tokio::test]
async fn startup_says_what_an_operator_should_know() {
    type Pairs<'a> = &'a [(&'a str, &'a str)];
    // (the environment, the (level, text) of lines the log must then have)
    let cases: [(Pairs, Pairs); 2] = [
        (
            &[("GRIZZLE_API_PASSWORD", "change-me")],
            &[
                ("WARNING", "SECURITY: GRIZZLE_API_PASSWORD is a well-known default"),
                // A misspelt variable name leaves the list off; the log has to say that it is off.
                ("INFO", "any charger may connect (GRIZZLE_ALLOWED_CHARGERS is not set)"),
            ],
        ),
        (
            &[("GRIZZLE_ALLOWED_CHARGERS", "GRD-A1 GRD-B2")],
            &[("INFO", "only these chargers may connect"), ("INFO", "(GRIZZLE_ALLOWED_CHARGERS): GRD-A1, GRD-B2")],
        ),
    ];
    for (configured, expected) in cases {
        let (_, stderr) = Process::start(configured).await.terminate().await;
        for (level, said) in expected {
            let found = stderr.lines().any(|line| line.contains(&format!(" {level} ")) && line.contains(said));
            assert!(found, "{level} {said}\n{stderr}");
        }
    }
}

#[test]
fn frame_ancestors_may_be_pasted_from_the_address_bar() {
    // One pasted address is a unit test in src/config.rs. This is the rest: one in a list, and
    // what is refused all the same.
    let setting =
        |value| Settings::from_pairs(&[("GRIZZLE_FRAME_ANCESTORS", value)]).map(|settings| settings.frame_ancestors);
    assert_eq!(setting("https://ha.example.com/lovelace/0?x=1, 'self'").unwrap(), "https://ha.example.com 'self'");
    assert!(setting("http://a b;/").is_err());
}
