//! What the integration tests share: a server in this process on a free port, talked to over
//! real sockets by a small HTTP client and by pretend chargers.
//!
//! `FakeCharger` behaves like a real Grizzl-E. The hardening tests need the opposite: `RawCharger`
//! is a peer that sends exactly what a test tells it to, however wrong, and reports what came back.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use grizzle_local::api::App;
use grizzle_local::config::Settings;
use grizzle_local::controller::Controller;
use grizzle_local::server::Server;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

pub const EMAIL: &str = "ha@local";
pub const PASSWORD: &str = "correct horse battery";

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Wait until `predicate` holds (checked every 20 ms); panics after `timeout`.
pub async fn wait_until(what: &str, timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !predicate() {
        assert!(tokio::time::Instant::now() < deadline, "condition not met in time: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// [`wait_until`] with the usual ten seconds.
pub async fn wait_for(what: &str, predicate: impl FnMut() -> bool) {
    wait_until(what, Duration::from_secs(10), predicate).await;
}

/// Start keeping a copy of every log line (see [`logged`]). Safe to call from every test.
pub fn capture_logs() {
    grizzle_local::logging::configure("debug");
    grizzle_local::logging::start_capture();
}

/// The log lines captured so far that contain `needle`. Tests in one file share the log, so look
/// for something only your test produces (its own serial, say).
pub fn logged(needle: &str) -> Vec<String> {
    grizzle_local::logging::captured(needle)
}

/// The settings the tests run a server with: the environment given by `pairs` on top of a
/// sign-in of [`EMAIL`] / [`PASSWORD`], a tick every second, loopback only, a port of its own,
/// no TLS, and the waits that only exist for real hardware cut short.
pub fn settings(dir: &std::path::Path, pairs: &[(&str, &str)]) -> Settings {
    let mut all = vec![
        ("GRIZZLE_API_EMAIL", EMAIL),
        ("GRIZZLE_API_PASSWORD", PASSWORD),
        ("GRIZZLE_TICK_SECONDS", "1"),
        ("GRIZZLE_HOST", "127.0.0.1"),
        ("GRIZZLE_PORT", "0"),
        ("GRIZZLE_TLS_PORT", "0"),
    ];
    all.extend_from_slice(pairs);
    all.reverse(); // the first match wins: what the test asked for comes before the defaults
    let mut settings = Settings::from_pairs(&all).unwrap();
    settings.data_dir = dir.join("data");
    settings.credential_rounds = 1000; // deliberately slow in production; not what is being tested
    settings.boot_delay = Duration::from_millis(100);
    settings
}

/// What came back from an HTTP request.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// The body as JSON, parsed the way a browser does: NaN and Infinity are syntax errors.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|err| panic!("not JSON ({err}): {}", self.body))
    }
}

/// Send raw bytes to `address` and read until the server closes the connection.
pub async fn raw_http(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await;
    response
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));
    let mut lines = head.split("\r\n");
    let status = lines.next().and_then(|line| line.split(' ').nth(1)).and_then(|code| code.parse().ok());
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_string()))
        .collect();
    let status = status.unwrap_or_else(|| panic!("not an HTTP response: {text:?}"));
    HttpResponse { status, headers, body: body.to_string() }
}

/// One HTTP request on a connection of its own. `headers` are sent as given, after Host.
pub async fn http(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> HttpResponse {
    let mut request = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        request.push_str(&format!("Host: {address}\r\n"));
    }
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body.unwrap_or_default());
    parse_response(&raw_http(address, &bytes).await)
}

/// A server in this process, with a data directory of its own that goes when the last holder of
/// it does.
pub struct TestServer {
    pub app: Arc<App>,
    pub address: SocketAddr,
    pub tls_address: Option<SocketAddr>,
    pub dir: Arc<TempDir>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl TestServer {
    /// A server with the settings of [`settings`].
    pub async fn start() -> TestServer {
        TestServer::with(&[]).await
    }

    /// A server configured by these environment variables (on top of the tests' defaults).
    pub async fn with(pairs: &[(&str, &str)]) -> TestServer {
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let settings = settings(dir.path(), pairs);
        TestServer::with_settings(dir, settings).await
    }

    /// A server over an existing directory (a restart), or with settings a test has adjusted.
    pub async fn with_settings(dir: Arc<TempDir>, settings: Settings) -> TestServer {
        TestServer::try_with_settings(dir, settings).await.unwrap()
    }

    /// [`TestServer::with`] for a test that names a port itself, and so may find it taken.
    pub async fn try_with(pairs: &[(&str, &str)]) -> Result<TestServer, String> {
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let settings = settings(dir.path(), pairs);
        TestServer::try_with_settings(dir, settings).await
    }

    async fn try_with_settings(dir: Arc<TempDir>, settings: Settings) -> Result<TestServer, String> {
        let app = App::new(settings)?;
        let server = Server::bind(app.clone()).await?;
        let (address, tls_address) = (server.address(), server.tls_address());
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(server.run(async move {
            let _ = stopped.await;
        }));
        Ok(TestServer { app, address, tls_address, dir, stop: Some(stop), task: Some(task) })
    }

    pub fn controller(&self) -> &Arc<Controller> {
        &self.app.controller
    }

    pub fn data_dir(&self) -> PathBuf {
        self.app.settings.data_dir.clone()
    }

    /// The state as it would be written to state.json right now.
    pub fn state(&self) -> Value {
        self.controller().lock().to_json()
    }

    /// state.json as it is on disk.
    pub fn saved_state(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.data_dir().join("state.json")).unwrap()).unwrap()
    }

    /// Shut the server down the way SIGTERM does, and wait until it has. Returns the directory,
    /// to start another server on.
    pub async fn stop(mut self) -> Arc<TempDir> {
        drop(self.stop.take());
        if let Some(task) = self.task.take() {
            tokio::time::timeout(Duration::from_secs(15), task).await.expect("the server stops").unwrap();
        }
        self.dir.clone()
    }

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> HttpResponse {
        http(self.address, method, path, headers, body).await
    }

    /// A request with an optional bearer token and an optional JSON body.
    pub async fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> HttpResponse {
        let bearer = token.map(|token| format!("Bearer {token}"));
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(bearer) = &bearer {
            headers.push(("Authorization", bearer));
        }
        let body = body.map(|body| body.to_string());
        if body.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        self.request(method, path, &headers, body.as_ref().map(|body| body.as_bytes())).await
    }

    pub async fn get(&self, path: &str, token: Option<&str>) -> HttpResponse {
        self.send("GET", path, token, None).await
    }

    pub async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> HttpResponse {
        self.send("POST", path, token, Some(body)).await
    }

    pub async fn put(&self, path: &str, token: Option<&str>, body: &Value) -> HttpResponse {
        self.send("PUT", path, token, Some(body)).await
    }

    pub async fn delete(&self, path: &str, token: Option<&str>) -> HttpResponse {
        self.send("DELETE", path, token, None).await
    }

    /// Sign in with a password; the whole response.
    pub async fn login_with(&self, email: &str, password: &str) -> HttpResponse {
        self.post("/client/auth/login", None, &json!({"emailOrPhone": email, "password": password})).await
    }

    /// Sign in with the tests' credentials; the bearer token.
    pub async fn login(&self) -> String {
        let response = self.login_with(EMAIL, PASSWORD).await;
        assert_eq!(response.status, 200, "{}", response.body);
        response.json()["token"].as_str().unwrap().to_string()
    }

    /// GET a path as a signed-in client and return the JSON, asserting success.
    pub async fn json(&self, token: &str, path: &str) -> Value {
        let response = self.get(path, Some(token)).await;
        assert!(response.status < 400, "GET {path} -> {} {}", response.status, response.body);
        response.json()
    }

    /// One station as `GET /client/stations` lists it.
    pub async fn station(&self, token: &str, serial: &str) -> Value {
        let data = self.json(token, "/client/stations").await;
        let stations = data["stations"].as_array().unwrap();
        stations.iter().find(|station| station["serialNumber"] == serial).cloned().expect("the station is listed")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        drop(self.stop.take());
    }
}

trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}

type WebSocket = tokio_tungstenite::WebSocketStream<Box<dyn Socket>>;

/// How a charger connects.
#[derive(Debug, Clone, Default)]
pub struct Connect {
    /// The request path; `/ocpp1.6/<serial>` is the usual one.
    pub path: String,
    /// HTTP Basic user and password (the charger's serial and Auth key).
    pub auth: Option<(String, String)>,
    /// Extra request headers.
    pub headers: Vec<(String, String)>,
    /// Speak TLS (to the server's TLS port), accepting any certificate.
    pub tls: bool,
    /// Don't offer the ocpp1.6 subprotocol.
    pub no_subprotocol: bool,
}

impl Connect {
    pub fn serial(serial: &str) -> Connect {
        Connect { path: format!("/ocpp1.6/{serial}"), ..Connect::default() }
    }

    pub fn path(path: &str) -> Connect {
        Connect { path: path.to_string(), ..Connect::default() }
    }

    pub fn auth(mut self, user: &str, password: &str) -> Connect {
        self.auth = Some((user.to_string(), password.to_string()));
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Connect {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn tls(mut self) -> Connect {
        self.tls = true;
        self
    }
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", openssl::base64::encode_block(format!("{user}:{password}").as_bytes()))
}

/// Open a charger's WebSocket. `Err` is the HTTP status the server refused the handshake with
/// (0 if the connection failed some other way). `Ok` also gives the subprotocol the server chose.
async fn open(address: SocketAddr, how: &Connect) -> Result<(WebSocket, Option<String>), u16> {
    let scheme = if how.tls { "wss" } else { "ws" };
    let mut request = format!("{scheme}://{address}{}", how.path).into_client_request().unwrap();
    let headers = request.headers_mut();
    if !how.no_subprotocol {
        headers.insert("Sec-WebSocket-Protocol", "ocpp1.6".parse().unwrap());
    }
    if let Some((user, password)) = &how.auth {
        headers.insert("Authorization", basic(user, password).parse().unwrap());
    }
    for (name, value) in &how.headers {
        let name: hyper::header::HeaderName = name.parse().unwrap();
        headers.insert(name, value.parse().unwrap());
    }
    let tcp = TcpStream::connect(address).await.map_err(|_| 0u16)?;
    let socket: Box<dyn Socket> = if how.tls {
        let mut connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
        connector.set_verify(openssl::ssl::SslVerifyMode::NONE);
        let ssl = connector.build().configure().unwrap().into_ssl("ocpp.unitedchargers.com").unwrap();
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        Pin::new(&mut stream).connect().await.map_err(|_| 0u16)?;
        Box::new(stream)
    } else {
        Box::new(tcp)
    };
    match tokio_tungstenite::client_async(request, socket).await {
        Ok((socket, response)) => {
            let protocol = response.headers().get("sec-websocket-protocol").and_then(|value| value.to_str().ok());
            Ok((socket, protocol.map(str::to_string)))
        }
        Err(WsError::Http(response)) => Err(response.status().as_u16()),
        Err(_) => Err(0),
    }
}

struct RawShared {
    /// Every Call the server sent us: (action, payload).
    received: Mutex<Vec<(String, Value)>>,
    /// Every text frame the server sent us, as it came.
    frames: Mutex<Vec<String>>,
    /// false: read the server's Calls and never reply (an unresponsive charger).
    answer: AtomicBool,
    /// action -> payload to answer with (the default is `{"status": "Accepted"}`).
    replies: Mutex<HashMap<String, Value>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    closed: AtomicBool,
    close_code: Mutex<Option<u16>>,
}

/// A bare OCPP-J client. By default it answers the server's Calls with `{"status": "Accepted"}`.
pub struct RawCharger {
    shared: Arc<RawShared>,
    out: mpsc::UnboundedSender<Message>,
    count: AtomicU64,
    /// The subprotocol the server chose in the handshake.
    pub protocol: Option<String>,
    task: JoinHandle<()>,
}

impl RawCharger {
    /// Connect to `/ocpp1.6/<serial>`, with HTTP Basic credentials if given. `Err` is the HTTP
    /// status of the refusal.
    pub async fn connect(server: &TestServer, serial: &str, auth: Option<(&str, &str)>) -> Result<RawCharger, u16> {
        let mut how = Connect::serial(serial);
        if let Some((user, password)) = auth {
            how = how.auth(user, password);
        }
        RawCharger::connect_with(server, &how).await
    }

    pub async fn connect_with(server: &TestServer, how: &Connect) -> Result<RawCharger, u16> {
        let address = if how.tls { server.tls_address.expect("the server has a TLS port") } else { server.address };
        RawCharger::connect_to(address, how).await
    }

    pub async fn connect_to(address: SocketAddr, how: &Connect) -> Result<RawCharger, u16> {
        let (socket, protocol) = open(address, how).await?;
        let shared = Arc::new(RawShared {
            received: Mutex::new(Vec::new()),
            frames: Mutex::new(Vec::new()),
            answer: AtomicBool::new(true),
            replies: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            close_code: Mutex::new(None),
        });
        let (out, mut queue) = mpsc::unbounded_channel::<Message>();
        let task = tokio::spawn({
            let shared = shared.clone();
            let out = out.clone();
            async move {
                let (mut sink, mut stream) = socket.split();
                loop {
                    tokio::select! {
                        outgoing = queue.recv() => match outgoing {
                            Some(message) => {
                                if sink.send(message).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        },
                        incoming = stream.next() => match incoming {
                            Some(Ok(Message::Text(text))) => RawCharger::took(&shared, &out, text.as_str()),
                            Some(Ok(Message::Close(frame))) => {
                                *lock(&shared.close_code) = Some(frame.map_or(1005, |frame| u16::from(frame.code)));
                            }
                            Some(Ok(_)) => {}
                            Some(Err(_)) | None => break,
                        },
                    }
                }
                shared.closed.store(true, Ordering::SeqCst);
                lock(&shared.pending).clear();
            }
        });
        Ok(RawCharger { shared, out, count: AtomicU64::new(0), protocol, task })
    }

    fn took(shared: &RawShared, out: &mpsc::UnboundedSender<Message>, text: &str) {
        lock(&shared.frames).push(text.to_string());
        let Ok(frame) = serde_json::from_str::<Value>(text) else { return };
        if frame[0] == 2 {
            let action = frame[2].as_str().unwrap_or_default().to_string();
            lock(&shared.received).push((action.clone(), frame[3].clone()));
            if shared.answer.load(Ordering::SeqCst) {
                let reply =
                    lock(&shared.replies).get(&action).cloned().unwrap_or_else(|| json!({"status": "Accepted"}));
                let _ = out.send(Message::text(json!([3, frame[1], reply]).to_string()));
            }
        } else if let Some(waiter) = lock(&shared.pending).remove(&frame[1].to_string()) {
            let _ = waiter.send(frame);
        }
    }

    /// Send a Call; the whole reply frame, `[3, uid, payload]` or `[4, uid, code, description, {}]`.
    /// Panics if no reply comes within five seconds.
    pub async fn call(&self, action: &str, payload: Value) -> Value {
        let uid = json!(format!("t{}", self.count.fetch_add(1, Ordering::SeqCst) + 1));
        self.call_frame(uid, json!(action), payload).await.expect("the server replies")
    }

    /// Send a Call whose unique id and action can be anything at all; the reply frame, or `None`
    /// if there is none within five seconds.
    pub async fn call_frame(&self, uid: Value, action: Value, payload: Value) -> Option<Value> {
        let (waiter, reply) = oneshot::channel();
        lock(&self.shared.pending).insert(uid.to_string(), waiter);
        self.send_text(&json!([2, uid, action, payload]).to_string());
        tokio::time::timeout(Duration::from_secs(5), reply).await.ok().and_then(Result::ok)
    }

    /// Send a text frame exactly as given.
    pub fn send_text(&self, text: &str) {
        let _ = self.out.send(Message::text(text.to_string()));
    }

    pub fn send_message(&self, message: Message) {
        let _ = self.out.send(message);
    }

    /// Stop (or resume) answering the server's Calls.
    pub fn set_answer(&self, answer: bool) {
        self.shared.answer.store(answer, Ordering::SeqCst);
    }

    /// Answer the server's Calls for `action` with this payload from now on.
    pub fn reply_with(&self, action: &str, payload: Value) {
        lock(&self.shared.replies).insert(action.to_string(), payload);
    }

    /// Every Call the server has sent: (action, payload).
    pub fn received(&self) -> Vec<(String, Value)> {
        lock(&self.shared.received).clone()
    }

    /// The payloads of the Calls the server has sent for `action`.
    pub fn calls(&self, action: &str) -> Vec<Value> {
        self.received().into_iter().filter(|(name, _)| name == action).map(|(_, payload)| payload).collect()
    }

    /// Every text frame the server has sent, as it came.
    pub fn frames(&self) -> Vec<String> {
        lock(&self.shared.frames).clone()
    }

    /// Has the connection ended (by either side)?
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// The code of the close frame the server sent, if it sent one.
    pub fn close_code(&self) -> Option<u16> {
        *lock(&self.shared.close_code)
    }

    pub async fn wait_closed(&self) {
        wait_for("the connection to close", || self.is_closed()).await;
    }

    /// Close the WebSocket properly and wait for the connection to end.
    pub async fn close(&self) {
        let _ = self.out.send(Message::Close(Some(CloseFrame { code: 1000.into(), reason: "".into() })));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !self.is_closed() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Drop the TCP connection without a word, the way a charger that loses power does.
    pub fn vanish(&self) {
        self.task.abort();
        self.shared.closed.store(true, Ordering::SeqCst);
    }
}

impl Drop for RawCharger {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string()
}

/// What a [`FakeCharger`] is and has done. Tests read it, and may change it, through
/// [`FakeCharger::state`].
#[derive(Debug, Default)]
pub struct FakeState {
    /// connector -> status
    pub status: BTreeMap<i64, String>,
    /// connector -> (transaction id, idTag)
    pub transactions: BTreeMap<i64, (i64, String)>,
    /// connector -> the lifetime energy register, in Wh
    pub energy: BTreeMap<i64, i64>,
    /// connector -> the register when its session started
    pub session_starts: BTreeMap<i64, i64>,
    /// The limit of the last charging profile the server set, in amps.
    pub limit_a: Option<i64>,
    pub config: BTreeMap<String, String>,
    /// Server -> charger calls, for assertions.
    pub received: Vec<(String, Value)>,
    pub booted: bool,
    pub reset_requested: bool,
}

/// How a [`FakeCharger`] is built.
#[derive(Debug, Clone)]
pub struct FakeOptions {
    pub connectors: i64,
    pub meter_interval: Duration,
    /// Answer GetConfiguration with the firmware's broken JSON.
    pub malformed_config: bool,
    pub auth_key: String,
    /// The request path; `/ocpp1.6/<serial>` if empty.
    pub path: String,
    pub tls: bool,
    /// Report energy in MeterValues from the start of the session, as the Duo's firmware does,
    /// instead of the lifetime register.
    pub session_relative: bool,
}

impl Default for FakeOptions {
    fn default() -> FakeOptions {
        FakeOptions {
            connectors: 2,
            meter_interval: Duration::from_millis(500),
            malformed_config: true,
            auth_key: "secret".to_string(),
            path: String::new(),
            tls: false,
            session_relative: false,
        }
    }
}

struct FakeShared {
    serial: String,
    options: FakeOptions,
    state: Mutex<FakeState>,
    out: mpsc::UnboundedSender<Message>,
    pending: Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>,
    closed: AtomicBool,
}

/// A pretend Grizzl-E that speaks OCPP 1.6-J the way the real one does (the same behaviour as
/// tools/fake_charger.py): it boots, reports its connectors, and when a car is plugged in waits
/// for RemoteStartTransaction like the real thing. It also reproduces the firmware's malformed
/// GetConfiguration reply.
pub struct FakeCharger {
    shared: Arc<FakeShared>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeCharger {
    /// Connect with the default options and wait until the charger has booted.
    pub async fn connect(server: &TestServer, serial: &str) -> FakeCharger {
        FakeCharger::connect_with(server, serial, FakeOptions::default()).await.expect("the charger is admitted")
    }

    /// Connect and boot. `Err` is the HTTP status the server refused the handshake with.
    pub async fn connect_with(server: &TestServer, serial: &str, options: FakeOptions) -> Result<FakeCharger, u16> {
        let address = if options.tls { server.tls_address.expect("the server has a TLS port") } else { server.address };
        let charger = FakeCharger::connect_to(address, serial, options).await?;
        wait_for("the charger to boot", || charger.state().booted).await;
        Ok(charger)
    }

    /// Connect to any address, without waiting for the boot sequence.
    pub async fn connect_to(address: SocketAddr, serial: &str, options: FakeOptions) -> Result<FakeCharger, u16> {
        let path = if options.path.is_empty() { format!("/ocpp1.6/{serial}") } else { options.path.clone() };
        let mut how = Connect::path(&path).auth(serial, &options.auth_key);
        how.tls = options.tls;
        let (socket, _) = open(address, &how).await?;
        let (out, mut queue) = mpsc::unbounded_channel::<Message>();
        let mut state = FakeState::default();
        for cid in 1..=options.connectors {
            state.status.insert(cid, "Available".to_string());
            state.energy.insert(cid, 500_000 + cid * 1000);
        }
        state.config.insert("HeartbeatInterval".to_string(), "3600".to_string());
        state.config.insert("MeterValueSampleInterval".to_string(), "60".to_string());
        let shared = Arc::new(FakeShared {
            serial: serial.to_string(),
            options,
            state: Mutex::new(state),
            out,
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        let transport = tokio::spawn({
            let shared = shared.clone();
            async move {
                let (mut sink, mut stream) = socket.split();
                loop {
                    tokio::select! {
                        outgoing = queue.recv() => match outgoing {
                            Some(message) => {
                                if sink.send(message).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        },
                        incoming = stream.next() => match incoming {
                            Some(Ok(Message::Text(text))) => FakeShared::took(&shared, text.as_str()),
                            Some(Ok(_)) => {}
                            Some(Err(_)) | None => break,
                        },
                    }
                }
                shared.closed.store(true, Ordering::SeqCst);
                lock(&shared.pending).clear();
            }
        });
        let boot = tokio::spawn({
            let shared = shared.clone();
            async move {
                let boot = json!({
                    "chargePointVendor": "UnitedChargers",
                    "chargePointModel": "GRD 40A 2025",
                    "chargePointSerialNumber": shared.serial,
                    "firmwareVersion": "UDGRW070L-04.03.2",
                    "meterType": "0",
                });
                let Ok(result) = shared.call("BootNotification", boot).await else { return };
                let connectors: Vec<(i64, String)> =
                    lock(&shared.state).status.iter().map(|(cid, status)| (*cid, status.clone())).collect();
                for (cid, status) in connectors {
                    let _ = shared.send_status(cid, &status).await;
                }
                lock(&shared.state).booted = true;
                let interval = result["interval"].as_u64().filter(|interval| *interval > 0).unwrap_or(300);
                loop {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    if shared.call("Heartbeat", json!({})).await.is_err() {
                        return;
                    }
                }
            }
        });
        let meter = tokio::spawn({
            let shared = shared.clone();
            async move {
                loop {
                    tokio::time::sleep(shared.options.meter_interval).await;
                    shared.meter_values().await;
                }
            }
        });
        Ok(FakeCharger { shared, tasks: vec![transport, boot, meter] })
    }

    /// The charger's state, to look at or to change. Not to be held across an `.await`.
    pub fn state(&self) -> MutexGuard<'_, FakeState> {
        lock(&self.shared.state)
    }

    pub fn status(&self, cid: i64) -> String {
        self.state().status.get(&cid).cloned().unwrap_or_default()
    }

    /// The payloads of the Calls the server has sent for `action`.
    pub fn calls(&self, action: &str) -> Vec<Value> {
        self.state().received.iter().filter(|(name, _)| name == action).map(|(_, payload)| payload.clone()).collect()
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Send a Call; the result payload, or the CallError as `"code: description"`.
    pub async fn call(&self, action: &str, payload: Value) -> Result<Value, String> {
        self.shared.call(action, payload).await
    }

    pub async fn send_status(&self, cid: i64, status: &str) {
        self.shared.send_status(cid, status).await.expect("StatusNotification is accepted");
    }

    pub async fn plug_in(&self, cid: i64) {
        self.send_status(cid, "Preparing").await;
    }

    pub async fn unplug(&self, cid: i64) {
        if self.state().transactions.contains_key(&cid) {
            self.shared.stop_transaction(cid, "EVDisconnected").await;
        }
        self.send_status(cid, "Available").await;
    }

    /// Close the WebSocket and wait for the connection to end.
    pub async fn close(&self) {
        let _ = self.shared.out.send(Message::Close(None));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !self.is_closed() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for FakeCharger {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl FakeShared {
    async fn call(&self, action: &str, payload: Value) -> Result<Value, String> {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let uid = format!("f{}", COUNT.fetch_add(1, Ordering::SeqCst));
        let (waiter, reply) = oneshot::channel();
        lock(&self.pending).insert(uid.clone(), waiter);
        let frame = json!([2, uid, action, payload]).to_string();
        self.out.send(Message::text(frame)).map_err(|_| "disconnected".to_string())?;
        match tokio::time::timeout(Duration::from_secs(30), reply).await {
            Ok(Ok(result)) => result,
            _ => Err(format!("{action} was not answered")),
        }
    }

    async fn send_status(&self, cid: i64, status: &str) -> Result<Value, String> {
        lock(&self.state).status.insert(cid, status.to_string());
        let payload = json!({"connectorId": cid, "status": status, "errorCode": "NoError", "timestamp": now_iso()});
        self.call("StatusNotification", payload).await
    }

    async fn start_transaction(&self, cid: i64, id_tag: String) {
        let meter_start = lock(&self.state).energy.get(&cid).copied().unwrap_or(0);
        let payload = json!({"connectorId": cid, "idTag": id_tag, "meterStart": meter_start, "timestamp": now_iso()});
        let Ok(result) = self.call("StartTransaction", payload).await else { return };
        if let Some(tid) = result["transactionId"].as_i64() {
            {
                let mut state = lock(&self.state);
                state.transactions.insert(cid, (tid, id_tag));
                state.session_starts.insert(cid, meter_start);
            }
            let _ = self.send_status(cid, "Charging").await;
        }
    }

    async fn stop_transaction(&self, cid: i64, reason: &str) {
        let Some((tid, id_tag)) = lock(&self.state).transactions.remove(&cid) else { return };
        let _ = self.send_status(cid, "Finishing").await;
        let meter_stop = lock(&self.state).energy.get(&cid).copied().unwrap_or(0);
        let payload = json!({
            "transactionId": tid, "idTag": id_tag, "meterStop": meter_stop, "timestamp": now_iso(), "reason": reason,
        });
        let _ = self.call("StopTransaction", payload).await;
    }

    async fn meter_values(&self) {
        let charging: Vec<(i64, i64)> = {
            let state = lock(&self.state);
            let charging = |cid: &i64| state.status.get(cid).is_some_and(|status| status == "Charging");
            state.transactions.iter().filter(|(cid, _)| charging(cid)).map(|(cid, (tid, _))| (*cid, *tid)).collect()
        };
        for (cid, tid) in charging {
            let (register, watts, amps) = {
                let mut state = lock(&self.state);
                let amps = state.limit_a.unwrap_or(32).min(32);
                let watts = amps * 240;
                let added = (watts as f64 * self.options.meter_interval.as_secs_f64() / 3600.0) as i64;
                let energy = state.energy.entry(cid).or_default();
                *energy += added;
                let lifetime = *energy;
                let started = state.session_starts.get(&cid).copied().unwrap_or(lifetime);
                (if self.options.session_relative { lifetime - started } else { lifetime }, watts, amps)
            };
            let payload = json!({
                "connectorId": cid,
                "transactionId": tid,
                "meterValue": [{
                    "timestamp": now_iso(),
                    "sampledValue": [
                        {"value": register.to_string(), "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
                        {"value": watts.to_string(), "measurand": "Power.Active.Import", "unit": "W"},
                        {"value": amps.to_string(), "measurand": "Current.Import", "unit": "A"},
                        {"value": "240", "measurand": "Voltage", "unit": "V"},
                        {"value": "21", "measurand": "Temperature", "unit": "Celsius"},
                    ],
                }],
            });
            let _ = self.call("MeterValues", payload).await;
        }
    }

    /// One text frame from the server.
    fn took(shared: &Arc<FakeShared>, text: &str) {
        let Ok(frame) = serde_json::from_str::<Value>(text) else { return };
        let uid = frame[1].as_str().unwrap_or_default().to_string();
        match frame[0].as_u64() {
            Some(3) => {
                if let Some(waiter) = lock(&shared.pending).remove(&uid) {
                    let _ = waiter.send(Ok(frame[2].clone()));
                }
            }
            Some(4) => {
                if let Some(waiter) = lock(&shared.pending).remove(&uid) {
                    let error = format!("{}: {}", frame[2].as_str().unwrap_or("?"), frame[3].as_str().unwrap_or(""));
                    let _ = waiter.send(Err(error));
                }
            }
            Some(2) => FakeShared::handle_call(shared, &uid, frame[2].as_str().unwrap_or_default(), &frame[3]),
            _ => {}
        }
    }

    fn handle_call(shared: &Arc<FakeShared>, uid: &str, action: &str, payload: &Value) {
        let mut state = lock(&shared.state);
        state.received.push((action.to_string(), payload.clone()));
        let send = |text: String| {
            let _ = shared.out.send(Message::text(text));
        };
        let key_asked = payload["key"].as_array().is_some_and(|keys| !keys.is_empty()) || payload["key"].is_string();
        if action == "GetConfiguration" && shared.options.malformed_config && !key_asked {
            // The real firmware's bug, verbatim: a missing '[' and the socket stays open.
            return send(format!(r#"[3,"{uid}",{{"configurationKey":],"unknownKey":["MeterValuesSampledData"]}}]"#));
        }
        let cid_of = |payload: &Value| payload["connectorId"].as_i64().filter(|cid| *cid != 0).unwrap_or(1);
        let reply = match action {
            "RemoteStartTransaction" => {
                let cid = cid_of(payload);
                let ready = matches!(state.status.get(&cid).map(String::as_str), Some("Preparing" | "SuspendedEVSE"));
                if ready && !state.transactions.contains_key(&cid) {
                    let id_tag = payload["idTag"].as_str().unwrap_or_default().to_string();
                    let shared = shared.clone();
                    tokio::spawn(async move { shared.start_transaction(cid, id_tag).await });
                    json!({"status": "Accepted"})
                } else {
                    json!({"status": "Rejected"})
                }
            }
            "RemoteStopTransaction" => {
                let wanted = payload["transactionId"].as_i64();
                match state.transactions.iter().find(|(_, (tid, _))| Some(*tid) == wanted).map(|(cid, _)| *cid) {
                    Some(cid) => {
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            shared.stop_transaction(cid, "Remote").await;
                            // The car is still plugged in: back to Preparing, as the Duo does.
                            let _ = shared.send_status(cid, "Preparing").await;
                        });
                        json!({"status": "Accepted"})
                    }
                    None => json!({"status": "Rejected"}),
                }
            }
            "SetChargingProfile" => {
                let period = &payload["csChargingProfiles"]["chargingSchedule"]["chargingSchedulePeriod"][0];
                state.limit_a = period["limit"].as_f64().map(|limit| limit as i64);
                json!({"status": "Accepted"})
            }
            "ChangeConfiguration" => {
                let key = payload["key"].as_str().unwrap_or_default().to_string();
                state.config.insert(key, payload["value"].as_str().unwrap_or_default().to_string());
                json!({"status": "Accepted"})
            }
            "GetConfiguration" => {
                let keys: Vec<Value> = state
                    .config
                    .iter()
                    .map(|(key, value)| json!({"key": key, "readonly": false, "value": value}))
                    .collect();
                json!({"configurationKey": keys, "unknownKey": []})
            }
            "TriggerMessage" => {
                if payload["requestedMessage"] == "StatusNotification" {
                    let cid = cid_of(payload);
                    match state.status.get(&cid).cloned() {
                        Some(status) => {
                            let shared = shared.clone();
                            tokio::spawn(async move {
                                let _ = shared.send_status(cid, &status).await;
                            });
                            json!({"status": "Accepted"})
                        }
                        // a connector this charger doesn't have (the server may assume a Duo's two)
                        None => json!({"status": "Rejected"}),
                    }
                } else {
                    json!({"status": "Accepted"})
                }
            }
            "Reset" => {
                state.reset_requested = true;
                json!({"status": "Accepted"})
            }
            _ => return send(json!([4, uid, "NotImplemented", format!("{action} not supported"), {}]).to_string()),
        };
        send(json!([3, uid, reply]).to_string());
    }
}
