//! The listeners: one HTTP server for OCPP WebSockets, the REST API and the web page, on a plain
//! port and (when a certificate is there) on a TLS port.
//!
//! The TLS port is for pointing the charger at this server with a DNS override of
//! ocpp.unitedchargers.com. Every handshake on it is logged with its outcome, including the TLS
//! alert the peer sent, because that is what tells whether a charger verifies certificates: one
//! that rejects our self-signed certificate would otherwise simply never show up.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request as HttpRequest, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use log::Level;
use openssl::ssl::{Ssl, SslContext, SslFiletype, SslMethod, SslOptions, SslVersion};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

use crate::api::{client_ip, gate, percent_decode, App, Reply, Request, Route};
use crate::config::{is_charge_point_id, Settings};
use crate::crypto::base64_decode;
use crate::logging::printable;
use crate::net::upstream_host;
use crate::ocpp::{websocket_config, Connection};
use crate::timeutil::now_iso;
use crate::value::clip;

/// The web page: a single self-contained file (inline CSS and JS, no external requests).
const WEB_PAGE: &str = include_str!("web/index.html");
/// The largest request body read.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// How long a client may take to send a request's headers, or sit idle between requests.
const HEADER_TIMEOUT: Duration = Duration::from_secs(75);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// Words in a TLS alert that mean the peer did not like our certificate.
const CERT_ALERTS: [&str; 4] = ["CERTIFICATE", "UNKNOWN_CA", "CERTIFICATE_UNKNOWN", "BAD_CERTIFICATE"];
/// What OpenSSL offers when Python's `ssl` module sets a server up, which is what the charger has
/// been seen to connect to: forward secrecy only, AES-GCM and ChaCha20 first, no SHA-1 MACs.
const TLS_CIPHERS: &str =
    "@SECLEVEL=2:ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES:DHE+AES:!aNULL:!eNULL:!aDSS:!SHA1:!AESCCM";

/// Headers for the web page.
pub fn page_headers(settings: &Settings) -> Vec<(&'static str, String)> {
    vec![
        (
            "content-security-policy",
            format!(
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; \
                 object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors {}",
                settings.frame_ancestors
            ),
        ),
        ("cache-control", "no-cache".to_string()),
        ("x-content-type-options", "nosniff".to_string()),
        ("referrer-policy", "no-referrer".to_string()),
    ]
}

fn respond(reply: Reply) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(reply.status);
    if !reply.content_type.is_empty() {
        builder = builder.header("content-type", reply.content_type);
    }
    for (name, value) in &reply.headers {
        builder = builder.header(*name, value);
    }
    builder.body(Full::new(Bytes::from(reply.body))).unwrap_or_else(|err| {
        log::error!("could not build a response: {err}");
        let mut response = Response::new(Full::new(Bytes::from_static(b"500: Internal Server Error")));
        *response.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
        response
    })
}

/// The (user, password) from an HTTP Basic Authorization header, or (None, None).
fn basic_credentials(request: &Request) -> (Option<String>, Option<String>) {
    let header = request.header("authorization").unwrap_or_default();
    let encoded = match header.get(..6) {
        Some(scheme) if scheme.eq_ignore_ascii_case("basic ") => &header[6..],
        _ => return (None, None),
    };
    let Some(decoded) = base64_decode(encoded) else { return (None, None) };
    let decoded = String::from_utf8_lossy(&decoded);
    match decoded.split_once(':') {
        Some((user, password)) => (Some(user.to_string()), Some(password.to_string())),
        None => (Some(decoded.into_owned()), None),
    }
}

/// The charger's identity: last path segment, else the Basic auth user, else a placeholder.
///
/// The placeholder names the charger by its address. Earlier versions put the TLS port in front
/// of the plain one inside the same process, and a charger connecting over TLS was then named
/// after that front door's own (loopback) address; a station known under that name is kept in
/// use, so a charger that sends no id is still the station it was, with its mode, schedules and
/// history.
fn charge_point_id(app: &App, request: &Request, tls: bool) -> String {
    let tail = request.path.trim_end_matches('/').rsplit('/').next().unwrap_or_default();
    if !tail.is_empty() && !["ocpp1.6", "ocpp", "ocpp16"].contains(&tail) {
        return tail.to_string();
    }
    if let (Some(user), _) = basic_credentials(request) {
        if !user.is_empty() {
            return user;
        }
    }
    let placeholder = format!("unknown-{}", client_ip(request, &app.settings));
    let peer = request.peer.map_or("?".to_string(), |peer| peer.to_canonical().to_string());
    let earlier = format!("unknown-{}", if tls { upstream_host(&app.settings.host) } else { peer });
    let inner = app.controller.lock();
    if !inner.stations.contains_key(&placeholder) && inner.stations.contains_key(&earlier) {
        return earlier;
    }
    placeholder
}

/// Does the Connection header name this token (`upgrade`, among `keep-alive, Upgrade`)?
fn connection_has(request: &Request, token: &str) -> bool {
    request.header("connection").unwrap_or_default().split(',').any(|part| part.trim().eq_ignore_ascii_case(token))
}

/// A GET that no REST endpoint answers: a charger's WebSocket, the web page, or nothing.
async fn websocket_or_page(app: &Arc<App>, http: &mut HttpRequest<Incoming>, request: &Request, tls: bool) -> Reply {
    let settings = &app.settings;
    if !request.header("upgrade").is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket")) {
        if matches!(request.path.as_str(), "/" | "/index.html") {
            let mut page = Reply::text(200, WEB_PAGE);
            page.content_type = "text/html; charset=utf-8";
            page.headers = page_headers(settings);
            return page;
        }
        return Reply::not_found();
    }
    let remote = client_ip(request, settings);
    // Browsers always send Origin on a WebSocket handshake; the charger's firmware never does
    // (its handshake is GET/Upgrade/Sec-WebSocket-*/Authorization only). Refusing it stops any
    // web page the owner visits from connecting to the LAN server as a charger.
    if let Some(origin) = request.header("origin") {
        log::warn!(
            "rejected websocket from {remote}: browser Origin {} (chargers don't send one)",
            printable(origin, 200)
        );
        return Reply::text(403, "403: Forbidden");
    }
    let cp_id = charge_point_id(app, request, tls);
    if !is_charge_point_id(&cp_id) {
        log::warn!("rejected websocket from {remote}: invalid charge point id {}", printable(&cp_id, 100));
        return Reply::text(400, "400: Bad Request");
    }
    let (auth_user, auth_key) = basic_credentials(request);
    let controller = &app.controller;
    // Check and install under one lock, so a concurrent handshake can't slip in between.
    let admission = controller.admission(&cp_id).await;
    if let Some((status, reason)) = controller.connection_refusal(&cp_id, auth_key.as_deref()).await {
        log::warn!("{cp_id}: rejected connection from {remote}: {reason}");
        return match status {
            401 => Reply::text(401, "401: Unauthorized"),
            409 => Reply::text(409, "409: Conflict"),
            503 => Reply::text(503, "503: Service Unavailable"),
            _ => Reply::text(403, "403: Forbidden"),
        };
    }
    let key = request.header("sec-websocket-key").unwrap_or_default();
    let version = request.header("sec-websocket-version").unwrap_or_default();
    if request.method != "GET" || key.is_empty() || version.trim() != "13" || !connection_has(request, "upgrade") {
        return Reply::text(400, "400: Bad Request");
    }
    let offered: Vec<&str> = request
        .header("sec-websocket-protocol")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|protocol| !protocol.is_empty())
        .collect();
    let protocol = offered.contains(&"ocpp1.6").then_some("ocpp1.6");
    log::info!(
        "{cp_id}: websocket from {remote} path={} subprotocol={}",
        printable(&request.path, 200),
        protocol.unwrap_or("None")
    );
    // Record how the charger connected, so its cloud identity (serial + Auth key) can be
    // reused by tools/firmware_capture.py. This is never exposed through the HTTP API.
    let handshake = json!({
        "path": clip(&request.path, 200),
        "query": Some(clip(&request.query, 200)).filter(|query| !query.is_empty()),
        "authUser": auth_user.as_deref().map(|user| clip(user, 100)),
        "protocols": offered.iter().take(8).map(|protocol| clip(protocol, 50)).collect::<Vec<_>>(),
        "userAgent": request.header("user-agent").map(|agent| clip(agent, 200)),
        "remote": remote,
        "recordedAt": now_iso(),
    });
    let conn = Arc::new(Connection::new(&cp_id, settings.rate_burst, settings.rate_per_second, settings.call_timeout));
    controller.on_connect(conn.clone(), Some(handshake), auth_key.as_deref());
    drop(admission);

    let upgrade = hyper::upgrade::on(http);
    let controller = controller.clone();
    tokio::spawn(async move {
        match upgrade.await {
            Ok(upgraded) => {
                let socket = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(websocket_config())).await;
                let handler = |action: &str, payload| controller.handle(&conn.id, action, &payload);
                conn.run(socket, &handler).await;
            }
            Err(err) => {
                log::debug!("{}: the connection ended before it became a websocket: {err}", conn.id);
                conn.abandon();
            }
        }
        controller.on_disconnect(&conn);
    });

    let mut reply = Reply::text(101, "")
        .with_header("upgrade", "websocket")
        .with_header("connection", "Upgrade")
        .with_header("sec-websocket-accept", derive_accept_key(key.as_bytes()));
    reply.content_type = "";
    if let Some(protocol) = protocol {
        reply = reply.with_header("sec-websocket-protocol", protocol);
    }
    reply
}

/// The methods some endpoint answers at this path, for a 405.
fn allowed_methods(path: &str) -> String {
    let mut methods = vec!["GET", "HEAD"];
    methods.extend(["POST", "PUT", "DELETE"].into_iter().filter(|method| Route::find(method, path).is_some()));
    methods.join(",")
}

async fn handle(app: Arc<App>, mut http: HttpRequest<Incoming>, peer: SocketAddr, tls: bool) -> Response<Full<Bytes>> {
    let mut headers: Vec<(String, String)> = Vec::with_capacity(http.headers().keys_len());
    for (name, value) in http.headers() {
        if !headers.iter().any(|(seen, _)| seen == name.as_str()) {
            headers.push((name.as_str().to_string(), String::from_utf8_lossy(value.as_bytes()).into_owned()));
        }
    }
    let mut request = Request {
        method: http.method().as_str().to_string(),
        path: percent_decode(http.uri().path()),
        query: http.uri().query().unwrap_or_default().to_string(),
        headers,
        body: Vec::new(),
        peer: Some(peer.ip()),
    };
    if let Some(refusal) = gate(&app, &request) {
        return respond(refusal);
    }
    let reply = match Route::find(&request.method, &request.path) {
        Some(route) => match Limited::new(http.into_body(), MAX_BODY_BYTES).collect().await {
            Ok(body) => {
                request.body = body.to_bytes().to_vec();
                app.dispatch(route, &request).await
            }
            Err(err) if err.is::<http_body_util::LengthLimitError>() => {
                Reply::text(413, &format!("Maximum request body size {MAX_BODY_BYTES} exceeded"))
            }
            Err(_) => Reply::error(400, "invalid request body"),
        },
        None if matches!(request.method.as_str(), "GET" | "HEAD") => {
            websocket_or_page(&app, &mut http, &request, tls).await
        }
        None => Reply::text(405, "405: Method Not Allowed").with_header("allow", allowed_methods(&request.path)),
    };
    respond(reply)
}

/// Serve HTTP on one connection until it ends (or becomes a WebSocket, which then lives on by itself).
async fn serve_connection<I>(app: Arc<App>, io: I, peer: SocketAddr, tls: bool)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let app = app.clone();
        async move { Ok::<_, Infallible>(handle(app, request, peer, tls).await) }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades();
    if let Err(err) = connection.await {
        log::debug!("connection from {peer} ended: {err}");
    }
}

/// A TLS stream that says so in the log when it is finally closed.
struct Announced<S> {
    inner: S,
    peer: SocketAddr,
}

impl<S> Drop for Announced<S> {
    fn drop(&mut self) {
        log::info!("TLS: {} disconnected", self.peer);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Announced<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Announced<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The TLS settings for a certificate chain and its key (PEM files).
pub fn tls_context(cert: &str, key: &str) -> Result<SslContext, String> {
    let build = || -> Result<SslContext, openssl::error::ErrorStack> {
        let mut builder = SslContext::builder(SslMethod::tls_server())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_cipher_list(TLS_CIPHERS)?;
        builder.set_options(
            SslOptions::NO_COMPRESSION
                | SslOptions::CIPHER_SERVER_PREFERENCE
                | SslOptions::SINGLE_DH_USE
                | SslOptions::SINGLE_ECDH_USE,
        );
        builder.set_certificate_chain_file(cert)?;
        builder.set_private_key_file(key, SslFiletype::PEM)?;
        builder.check_private_key()?;
        Ok(builder.build())
    };
    build().map_err(|err| format!("cannot use the TLS certificate {cert} with the key {key}: {err}"))
}

/// Why a TLS handshake failed, in OpenSSL's words (`TLSV1_ALERT_UNKNOWN_CA`).
fn handshake_failure(err: &openssl::ssl::Error) -> String {
    let reason = err.ssl_error().and_then(|stack| stack.errors().first()).and_then(|first| first.reason());
    match reason {
        Some(reason) => reason.to_uppercase().replace(' ', "_"),
        None => err.to_string(),
    }
}

/// Run the TLS handshake on a new connection, log how it went, and serve HTTP over it.
async fn serve_tls(app: Arc<App>, context: SslContext, tcp: TcpStream, peer: SocketAddr) {
    log::info!("TLS: connection from {peer}");
    let stream = Ssl::new(&context).and_then(|ssl| tokio_openssl::SslStream::new(ssl, tcp));
    let mut stream = match stream {
        Ok(stream) => stream,
        Err(err) => return log::error!("TLS: cannot start a handshake with {peer}: {err}"),
    };
    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, Pin::new(&mut stream).accept()).await {
        Err(_) => {
            return log::warn!("TLS: {peer} never completed the handshake (not speaking TLS, or waiting on us?)");
        }
        Ok(Err(err)) => {
            let reason = handshake_failure(&err);
            if CERT_ALERTS.iter().any(|word| reason.contains(word)) {
                log::warn!(
                    "TLS: {peer} REJECTED OUR CERTIFICATE ({reason}). The device verifies certificates, so the DNS \
                     override cannot work with a self-signed cert."
                );
            } else {
                log::warn!("TLS: handshake with {peer} failed: {reason}");
            }
            return;
        }
        Ok(Ok(())) => {}
    }
    let ssl = stream.ssl();
    log::info!(
        "TLS: handshake with {peer} OK ({}, {})",
        ssl.version_str(),
        ssl.current_cipher().map_or("?", |cipher| cipher.name())
    );
    serve_connection(app, Announced { inner: stream, peer }, peer, true).await;
}

async fn bind(host: &str, port: u16) -> Result<TcpListener, String> {
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    TcpListener::bind((host, port)).await.map_err(|err| format!("cannot listen on {host} port {port}: {err}"))
}

/// The listeners, bound and ready to serve.
pub struct Server {
    pub app: Arc<App>,
    plain: TcpListener,
    tls: Option<(TcpListener, SslContext)>,
}

impl Server {
    /// Bind the plain port, and the TLS port if both certificate files exist.
    pub async fn bind(app: Arc<App>) -> Result<Server, String> {
        let settings = &app.settings;
        let plain = bind(&settings.host, settings.port).await?;
        let tls = if settings.tls_enabled() {
            let context = tls_context(&settings.tls_cert, &settings.tls_key)?;
            Some((bind(&settings.host, settings.tls_port).await?, context))
        } else {
            None
        };
        Ok(Server { app, plain, tls })
    }

    /// Where the plain listener really is (the port, if the settings asked for port 0).
    pub fn address(&self) -> SocketAddr {
        self.plain.local_addr().expect("a bound listener has an address")
    }

    pub fn tls_address(&self) -> Option<SocketAddr> {
        self.tls.as_ref().and_then(|(listener, _)| listener.local_addr().ok())
    }

    /// What an operator should know at startup, as log lines.
    pub fn startup_messages(&self) -> Vec<(Level, String)> {
        let settings = &self.app.settings;
        let listening = match self.tls_address() {
            Some(address) => format!(" and wss:// on {}", address.port()),
            None => " (no TLS: certificate not found)".to_string(),
        };
        let mut messages = vec![(
            Level::Info,
            format!(
                "grizzle-local {} listening on {}:{}{}",
                crate::VERSION,
                settings.host,
                self.address().port(),
                listening
            ),
        )];
        messages.extend(settings.security_warnings().into_iter().map(|warning| (Level::Warn, format!("SECURITY: {warning}"))));
        messages.push((
            Level::Info,
            if settings.allowed_chargers.is_empty() {
                "any charger may connect (GRIZZLE_ALLOWED_CHARGERS is not set)".to_string()
            } else {
                format!(
                    "only these chargers may connect (GRIZZLE_ALLOWED_CHARGERS): {}",
                    settings.allowed_chargers.join(", ")
                )
            },
        ));
        messages
    }

    /// Serve until `shutdown` completes; then stop listening, save, and close every connection.
    ///
    /// The save comes before anything that can wait on a peer: `docker stop` allows ten seconds
    /// in all, and a charger's socket never closes by itself.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let Server { app, plain, tls } = self;
        let ticker = tokio::spawn(app.controller.clone().run());
        let mut connections: JoinSet<()> = JoinSet::new();
        let accept_tls = || async {
            match &tls {
                Some((listener, context)) => listener.accept().await.map(|accepted| (accepted, context.clone())),
                None => std::future::pending().await,
            }
        };
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = plain.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nodelay(true);
                        connections.spawn(serve_connection(app.clone(), stream, peer, false));
                    }
                    Err(err) => accept_failed(&err).await,
                },
                accepted = accept_tls() => match accepted {
                    Ok(((stream, peer), context)) => {
                        let _ = stream.set_nodelay(true);
                        connections.spawn(serve_tls(app.clone(), context, stream, peer));
                    }
                    Err(err) => accept_failed(&err).await,
                },
                Some(_) = connections.join_next() => {} // forget the ones that have ended
            }
        }
        drop(plain); // no new connections
        drop(tls);
        app.controller.stop().await;
        connections.shutdown().await;
        ticker.abort();
        app.controller.save(); // whatever the last requests changed after the connections were closed
    }
}

async fn accept_failed(err: &std::io::Error) {
    // Out of file descriptors, most likely: give the ones in use a moment to be closed.
    log::warn!("could not accept a connection: {err}");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Completes when the process is asked to stop (SIGTERM from `docker stop`, or Ctrl-C).
async fn stop_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut terminate), Ok(mut interrupt)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
        log::error!("cannot listen for SIGTERM and SIGINT; only killing the process will stop it");
        return std::future::pending().await;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

/// Run the server with these settings until the process is told to stop.
pub async fn serve(settings: Settings) -> Result<(), String> {
    let app = App::new(settings)?;
    let server = Server::bind(app).await?;
    for (level, message) in server.startup_messages() {
        log::log!(level, "{message}");
    }
    server.run(stop_signal()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str, authorization: Option<&str>) -> Request {
        Request {
            method: "GET".into(),
            path: path.into(),
            headers: authorization.map(|value| ("authorization".to_string(), value.to_string())).into_iter().collect(),
            peer: Some("192.168.1.77".parse().unwrap()),
            ..Request::default()
        }
    }

    #[test]
    fn basic_credentials_are_read_tolerantly() {
        let of = |value: &str| basic_credentials(&request("/", Some(value)));
        assert_eq!(of("Basic R1JELTE6c2VjcmV0"), (Some("GRD-1".into()), Some("secret".into())));
        assert_eq!(of("basic R1JELTE6"), (Some("GRD-1".into()), Some("".into())));
        assert_eq!(of("Basic R1JELTE="), (Some("GRD-1".into()), None));
        assert_eq!(of("Basic YTpiOmM="), (Some("a".into()), Some("b:c".into())));
        assert_eq!(of("Basic !!!"), (Some("".into()), None));
        assert_eq!(of("Basic R1JELTE"), (None, None), "wrong padding");
        assert_eq!(of("Bearer R1JELTE6c2VjcmV0"), (None, None));
        assert_eq!(basic_credentials(&request("/", None)), (None, None));
    }

    #[test]
    fn page_is_not_frameable_by_other_sites_unless_configured() {
        let csp = |settings: &Settings| page_headers(settings)[0].1.clone();
        assert!(csp(&Settings::defaults()).ends_with("frame-ancestors 'self'"));
        let embedded = Settings::from_pairs(&[("GRIZZLE_FRAME_ANCESTORS", "http://homeassistant.local:8123")]).unwrap();
        assert!(csp(&embedded).ends_with("frame-ancestors http://homeassistant.local:8123"));
        assert!(csp(&embedded).contains("object-src 'none'"));
    }

    #[test]
    fn the_web_page_is_built_in_and_self_contained() {
        assert!(WEB_PAGE.contains("<html") && WEB_PAGE.contains("/client/auth/login"));
        for external in ["src=\"http", "href=\"http", "url(http", "@import"] {
            assert!(!WEB_PAGE.contains(external), "{external}");
        }
    }

    #[test]
    fn a_405_names_what_the_path_does_answer() {
        assert_eq!(allowed_methods("/client/auth/login"), "GET,HEAD,POST");
        assert_eq!(allowed_methods("/local/stations/GRD-1/holidays"), "GET,HEAD,PUT");
        assert_eq!(allowed_methods("/local/stations/GRD-1"), "GET,HEAD,DELETE");
        assert_eq!(allowed_methods("/nothing/here"), "GET,HEAD");
    }
}
