//! OCPP-J 1.6 framing over a WebSocket, written to be tolerant.
//!
//! Grizzl-E firmware is known to send a few malformed frames (for example a GetConfiguration
//! reply containing `"configurationKey":]`). Strict OCPP libraries reject those and the charger
//! then drops the connection, so this module parses frames itself, repairs what it can and drops
//! the rest without closing the socket.
//!
//! Tolerant of a sloppy charger is not the same as trusting it: anyone on the network can connect
//! as a charger the server has never seen, so every frame is also bounded in size, rate and what
//! it may leave behind in memory.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use crate::crypto::random_hex;
use crate::logging::{printable, printable_value};
use crate::timeutil::now_iso;
use crate::value::{char_len, clip, to_text, Object};

pub const CALL: u64 = 2;
pub const CALLRESULT: u64 = 3;
pub const CALLERROR: u64 = 4;

/// OCPP frames are a few hundred bytes; the largest, a GetConfiguration reply, a few KiB.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
/// A frame bigger than this is noted in the debug log but not kept, and what is kept is kept as
/// text: parsed, a few kilobytes of tiny JSON containers take many times their size in memory,
/// and 200 logged frames per connection would pin megabytes.
pub const LOG_FRAME_BYTES: usize = 8 * 1024;
/// Frames kept per connection for the debug log.
pub const LOG_FRAMES: usize = 200;
/// OCPP messages nest five or six levels. Anything much deeper is not OCPP.
pub const MAX_FRAME_DEPTH: usize = 32;
/// A ping goes out after this long without a frame from the charger; with no answer within half
/// of it again the socket is dead.
const HEARTBEAT: Duration = Duration::from_secs(120);
/// Frames waiting to be written. A peer that stops reading fills this, and then senders wait.
const SEND_QUEUE: usize = 32;
/// How much may wait in the socket to be written before the peer counts as gone. Well above the
/// largest frame the server sends (a raw call from the API: a request body, 1 MiB at most).
const MAX_UNSENT_BYTES: usize = 8 * 1024 * 1024;
/// How long a peer gets to acknowledge our close before the socket is dropped anyway.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// The settings of the WebSocket itself: no message or frame larger than [`MAX_FRAME_BYTES`].
///
/// A client is supposed to mask what it sends. Small embedded WebSocket clients are known to skip
/// it, the Python server never insisted, and masking protects proxies, not us: take either.
///
/// What waits to be written is bounded as well. A peer that sends pings and never reads would
/// otherwise have an answer to each one queued for it, for as long as it cares to go on.
pub fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
        .max_write_buffer_size(MAX_UNSENT_BYTES)
        .accept_unmasked_frames(true)
}

/// A frame could not be written: the connection is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyNotSent;

/// A CallError received from the charger, or a call that timed out or could not be sent.
#[derive(Debug, Clone, PartialEq)]
pub struct OcppError {
    pub code: String,
    pub description: String,
    pub details: Value,
}

impl OcppError {
    pub fn new(code: &str, description: &str) -> OcppError {
        OcppError::with_details(code, description, Value::Null)
    }

    pub fn with_details(code: &str, description: &str, details: Value) -> OcppError {
        // Both come from the charger when it answers with a CallError, and end up in logs.
        OcppError { code: printable(code, 64), description: printable(description, 300), details }
    }
}

impl fmt::Display for OcppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.description.is_empty() {
            write!(f, "{}", self.code)
        } else {
            write!(f, "{}: {}", self.code, self.description)
        }
    }
}

impl std::error::Error for OcppError {}

/// Why a handler did not answer a charger's Call with a result.
#[derive(Debug, Clone, PartialEq)]
pub enum HandlerError {
    /// No handler for this action.
    NotImplemented,
    /// Refused with a specific CallError code.
    Rejected { code: String, description: String },
    /// The handler failed; the charger is told only that.
    Internal(String),
}

impl HandlerError {
    pub fn rejected(code: &str, description: impl Into<String>) -> HandlerError {
        HandlerError::Rejected { code: code.to_string(), description: description.into() }
    }
}

pub type HandlerResult = Result<Value, HandlerError>;

/// Fix the malformed shapes Grizzl-E firmware is known to emit.
pub fn repair_json(text: &str) -> String {
    // '"configurationKey":]'  ->  '"configurationKey":[]'
    let chars: Vec<char> = text.chars().collect();
    let mut first = String::with_capacity(text.len() + 8);
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == ':' {
            let mut next = at + 1;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if chars.get(next) == Some(&']') {
                first.push_str(":[]");
                at = next + 1;
                continue;
            }
        }
        first.push(chars[at]);
        at += 1;
    }
    // trailing commas before a closing bracket/brace
    let chars: Vec<char> = first.chars().collect();
    let mut second = String::with_capacity(first.len());
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == ',' {
            let mut next = at + 1;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if matches!(chars.get(next), Some(']' | '}')) {
                at = next;
                continue;
            }
        }
        second.push(chars[at]);
        at += 1;
    }
    second
}

/// Is this JSON value nested more than `limit` levels?
fn too_deep(value: &Value, limit: usize) -> bool {
    let children: Box<dyn Iterator<Item = &Value> + '_> = match value {
        Value::Array(items) => Box::new(items.iter()),
        Value::Object(object) => Box::new(object.values()),
        _ => return false,
    };
    limit == 0 || children.into_iter().any(|child| too_deep(child, limit - 1))
}

fn frame_kind(frame: &[Value]) -> Option<u64> {
    let kind = frame.first()?.as_f64()?;
    [CALL, CALLRESULT, CALLERROR].into_iter().find(|k| *k as f64 == kind)
}

/// Parse an OCPP-J frame, repairing it if needed. `None` if hopeless.
pub fn parse_frame(text: &str) -> Option<Vec<Value>> {
    let repaired;
    for candidate in [text, {
        repaired = repair_json(text);
        repaired.as_str()
    }] {
        // The parser itself refuses anything nested more than 128 levels deep.
        let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(candidate) else { continue };
        if frame.len() >= 3 && frame_kind(&frame).is_some() {
            let deep = frame.iter().any(|item| too_deep(item, MAX_FRAME_DEPTH - 1));
            return (!deep).then_some(frame);
        }
    }
    None
}

/// Message type and unique id of a frame that didn't parse, if they are legible: `[3,"id"…`.
pub fn peek_frame(text: &str) -> Option<(u64, String)> {
    let rest = text.trim_start().strip_prefix('[')?.trim_start();
    let kind = match rest.chars().next()? {
        '2' => CALL,
        '3' => CALLRESULT,
        '4' => CALLERROR,
        _ => return None,
    };
    let rest = rest[1..].trim_start().strip_prefix(',')?.trim_start().strip_prefix('"')?;
    let uid = &rest[..rest.find('"')?];
    (!uid.is_empty()).then(|| (kind, uid.to_string()))
}

/// Can this unique id be sent back in a reply? (The spec says string; a number does no harm.)
fn echoable(uid: &Value) -> bool {
    uid.is_string() || uid.is_i64() || uid.is_u64()
}

struct LogEntry {
    at: String,
    direction: &'static str,
    label: String,
    text: String,
    /// It is JSON, to be decoded when the log is read.
    json: bool,
}

struct Bucket {
    allowance: f64,
    at: Instant,
}

type Reply = Result<Object, OcppError>;

/// One WebSocket from one charge point.
///
/// It exists from the moment the charger is admitted. The socket is attached a little later, by
/// [`Connection::run`]; calls made in between wait in the send queue.
pub struct Connection {
    pub id: String,
    out: mpsc::Sender<Message>,
    out_rx: Mutex<Option<mpsc::Receiver<Message>>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Reply>>>,
    log: Mutex<VecDeque<LogEntry>>,
    closed: AtomicBool,
    closing: Notify,
    done: watch::Sender<bool>,
    bucket: Mutex<Bucket>,
    rate_burst: f64,
    rate: f64,
    call_timeout: Duration,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Takes a call out of the pending map when the call is over, however it ends.
struct Forget<'a> {
    pending: &'a Mutex<HashMap<String, oneshot::Sender<Reply>>>,
    uid: &'a str,
}

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        lock(self.pending).remove(self.uid);
    }
}

impl Connection {
    pub fn new(id: &str, rate_burst: f64, rate_per_second: f64, call_timeout: Duration) -> Connection {
        let (out, out_rx) = mpsc::channel(SEND_QUEUE);
        Connection {
            id: id.to_string(),
            out,
            out_rx: Mutex::new(Some(out_rx)),
            pending: Mutex::new(HashMap::new()),
            log: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            closing: Notify::new(),
            done: watch::Sender::new(false),
            bucket: Mutex::new(Bucket { allowance: rate_burst, at: Instant::now() }),
            rate_burst,
            rate: rate_per_second.max(0.001),
            call_timeout,
        }
    }

    /// Has the socket gone, or been told to go?
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    // --- outbound -----------------------------------------------------------

    /// Send a Call and wait for its CallResult.
    pub async fn call(&self, action: &str, payload: Value, timeout: Option<Duration>) -> Reply {
        if self.is_closed() {
            return Err(OcppError::new("Disconnected", &format!("{action} could not be sent to {}: closed", self.id)));
        }
        let uid = random_hex(6);
        let (reply_to, reply) = oneshot::channel();
        lock(&self.pending).insert(uid.clone(), reply_to);
        // Whatever ends this call (an answer, the deadline, or the caller's task being aborted
        // while it waits), nobody is waiting for the answer afterwards.
        let _forget = Forget { pending: &self.pending, uid: &uid };
        let payload = if payload.is_null() { json!({}) } else { payload };
        let frame = json!([CALL, uid, action, payload]);
        // The send is inside the deadline too: a peer that stops reading must not be able to
        // hold a caller for as long as it likes.
        let outcome = tokio::time::timeout(timeout.unwrap_or(self.call_timeout), async {
            if self.send(&frame, &format!("-> {action}")).await.is_err() {
                let why = format!("{action} could not be sent to {}: the connection is gone", self.id);
                return Err(OcppError::new("Disconnected", &why));
            }
            reply.await.unwrap_or_else(|_| Err(OcppError::new("Disconnected", "Disconnected")))
        })
        .await;
        outcome.unwrap_or_else(|_| Err(OcppError::new("Timeout", &format!("{action} not answered by {}", self.id))))
    }

    async fn send(&self, frame: &Value, label: &str) -> Result<(), ReplyNotSent> {
        let text = frame.to_string();
        self.record("out", label, &text, true);
        self.out.send(Message::text(text)).await.map_err(|_| ReplyNotSent)
    }

    // --- inbound ------------------------------------------------------------

    /// Pump messages until the socket closes. `handler` answers the charger's Calls.
    pub async fn run<S>(&self, socket: WebSocketStream<S>, handler: &(dyn Fn(&str, Object) -> HandlerResult + Sync))
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut sink, mut stream) = socket.split();
        let Some(mut queue) = lock(&self.out_rx).take() else { return };
        // What to tell the peer if we are the one ending it for a reason (a frame too large).
        let mut parting: Option<CloseFrame> = None;
        let mut we_closed = false;
        {
            let writer = async {
                while let Some(message) = queue.recv().await {
                    let last = matches!(message, Message::Close(_));
                    if sink.send(message).await.is_err() {
                        return false;
                    }
                    if last {
                        return true;
                    }
                }
                false
            };
            let reader = self.read(&mut stream, handler);
            let told_to_close = async {
                self.closing.notified().await;
                tokio::time::sleep(CLOSE_GRACE).await; // the close frame is on its way; don't wait for ever
            };
            tokio::select! {
                sent_close = writer => we_closed = sent_close,
                farewell = reader => parting = farewell,
                () = told_to_close => {}
            }
        }
        self.closed.store(true, Ordering::SeqCst);
        if let Some(frame) = parting {
            let _ = tokio::time::timeout(CLOSE_GRACE, sink.send(Message::Close(Some(frame)))).await;
        } else if we_closed {
            // Let the peer acknowledge, so it sees a close and not a reset.
            let acknowledged = async {
                while let Some(Ok(message)) = stream.next().await {
                    if message.is_close() {
                        break;
                    }
                }
            };
            let _ = tokio::time::timeout(CLOSE_GRACE, acknowledged).await;
        } else {
            // If the peer closed, the answer to its close is waiting to be written: a peer that
            // closes properly should see a close and not a reset. (Nothing to write, or nobody
            // to write to, and this returns at once.)
            let _ = tokio::time::timeout(CLOSE_GRACE, sink.flush()).await;
        }
        self.fail_pending("Disconnected");
        self.done.send_replace(true);
    }

    /// The read loop. Returns a close frame to send if the connection ends on our initiative.
    async fn read<R>(
        &self,
        stream: &mut R,
        handler: &(dyn Fn(&str, Object) -> HandlerResult + Sync),
    ) -> Option<CloseFrame>
    where
        R: StreamExt<Item = Result<Message, WsError>> + Unpin,
    {
        let mut ping_at = Instant::now() + HEARTBEAT;
        let mut pong_by: Option<Instant> = None;
        loop {
            let message = tokio::select! {
                message = stream.next() => message,
                () = tokio::time::sleep_until(pong_by.unwrap_or(ping_at)) => {
                    if pong_by.is_some() {
                        log::warn!("{}: no answer to a ping; dropping the connection", self.id);
                        return None;
                    }
                    let _ = self.out.try_send(Message::Ping(Default::default()));
                    pong_by = Some(Instant::now() + HEARTBEAT / 2);
                    continue;
                }
            };
            ping_at = Instant::now() + HEARTBEAT;
            pong_by = None;
            match message {
                None | Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => return None,
                Some(Ok(Message::Close(_))) => return None,
                Some(Ok(message)) => {
                    // Whatever kind of frame it is: a ping costs an answer too.
                    self.throttle().await;
                    match message {
                        Message::Text(text) => {
                            if self.handle_text(text.as_str(), handler).await.is_err() {
                                return None; // the reply couldn't be sent: the socket is gone
                            }
                        }
                        Message::Binary(_) => log::debug!("{}: ignoring binary frame", self.id),
                        _ => {} // ping and pong: answered by the socket itself
                    }
                }
                Some(Err(WsError::Capacity(err))) => {
                    log::warn!("{}: closing the connection: {}", self.id, printable(&err.to_string(), 200));
                    return Some(CloseFrame { code: CloseCode::Size, reason: "frame too large".into() });
                }
                Some(Err(err)) => {
                    log::warn!("{}: websocket error {}", self.id, printable(&err.to_string(), 200));
                    return None;
                }
            }
        }
    }

    /// Token bucket: free up to the burst, then at most `rate` frames a second.
    async fn throttle(&self) {
        let wait = {
            let mut bucket = lock(&self.bucket);
            let now = Instant::now();
            bucket.allowance =
                self.rate_burst.min(bucket.allowance + (now - bucket.at).as_secs_f64() * self.rate) - 1.0;
            bucket.at = now;
            (bucket.allowance < 0.0).then(|| Duration::from_secs_f64(-bucket.allowance / self.rate))
        };
        if let Some(wait) = wait {
            tokio::time::sleep(wait).await;
        }
    }

    fn fail_pending(&self, reason: &str) {
        for (_, waiter) in lock(&self.pending).drain() {
            let _ = waiter.send(Err(OcppError::new("Disconnected", reason)));
        }
    }

    fn resolve(&self, uid: &str, reply: Reply) -> bool {
        match lock(&self.pending).remove(uid) {
            Some(waiter) => waiter.send(reply).is_ok(),
            None => false,
        }
    }

    /// Take one text frame. `Err` means a reply could not be sent.
    pub async fn handle_text(
        &self,
        text: &str,
        handler: &(dyn Fn(&str, Object) -> HandlerResult + Sync),
    ) -> Result<(), ReplyNotSent> {
        let Some(mut frame) = parse_frame(text) else {
            self.record("in", "unparseable", clip(text, 500), false);
            log::warn!("{}: dropping unparseable frame: {}", self.id, printable(text, 200));
            if let Some((kind, uid)) = peek_frame(text) {
                if kind != CALL {
                    // Resolve the waiting call with nothing rather than letting it time out.
                    self.resolve(&uid, Ok(Object::new()));
                }
            }
            return Ok(());
        };
        let kind = frame_kind(&frame).unwrap_or(CALL);
        let uid = frame[1].take();
        if kind == CALL {
            let action = frame[2].as_str().map(str::to_string);
            let (Some(action), true, true) = (action, frame.len() >= 4, echoable(&uid)) else {
                log::warn!("{}: malformed Call {}", self.id, printable(text, 200));
                return Ok(());
            };
            let payload = match frame[3].take() {
                Value::Object(payload) => payload,
                _ => Object::new(),
            };
            self.record("in", &format!("<- {}", clip(&action, 64)), text, true);
            return self.dispatch(uid, &action, payload, handler).await;
        }
        // Replies carry an id we made up ourselves, always a string; anything else matches nothing.
        let uid = uid.as_str().unwrap_or_default();
        if kind == CALLRESULT {
            self.record("in", "<- result", text, true);
            let payload = match frame[2].take() {
                Value::Object(payload) => payload,
                _ => Object::new(),
            };
            if !self.resolve(uid, Ok(payload)) {
                log::debug!("{}: result for unknown call {}", self.id, printable(uid, 64));
            }
        } else {
            self.record("in", "<- error", text, true);
            let code = to_text(&frame[2]);
            let description = frame.get(3).map(to_text).unwrap_or_default();
            let details = frame.get(4).cloned().unwrap_or(Value::Null);
            self.resolve(uid, Err(OcppError::with_details(&code, &description, details)));
        }
        Ok(())
    }

    async fn dispatch(
        &self,
        uid: Value,
        action: &str,
        payload: Object,
        handler: &(dyn Fn(&str, Object) -> HandlerResult + Sync),
    ) -> Result<(), ReplyNotSent> {
        let name = printable(action, 64);
        // Never let a handler bug kill the socket.
        let outcome = catch_unwind(AssertUnwindSafe(|| handler(action, payload)))
            .unwrap_or_else(|_| Err(HandlerError::Internal("the handler panicked".to_string())));
        let (reply, label) = match outcome {
            Ok(result) => {
                let result = if result.is_null() { json!({}) } else { result };
                (json!([CALLRESULT, uid, result]), format!("-> result {name}"))
            }
            Err(HandlerError::NotImplemented) => (
                json!([CALLERROR, uid, "NotImplemented", format!("{name} is not supported"), {}]),
                format!("-> error {name}"),
            ),
            Err(HandlerError::Rejected { code, description }) => {
                log::warn!("{}: refused {}: {}: {}", self.id, name, code, description);
                (json!([CALLERROR, uid, code, description, {}]), format!("-> error {name}"))
            }
            Err(HandlerError::Internal(why)) => {
                log::error!("{}: handler for {} failed: {}", self.id, name, printable(&why, 300));
                (json!([CALLERROR, uid, "InternalError", "handler failed", {}]), format!("-> error {name}"))
            }
        };
        self.send(&reply, &label).await
    }

    /// Note a frame in the debug log, as text.
    fn record(&self, direction: &'static str, label: &str, text: &str, json: bool) {
        let (text, json) = if text.len() > LOG_FRAME_BYTES {
            (json!({"omitted": "frame too large to keep in the log", "bytes": char_len(text)}).to_string(), true)
        } else {
            (text.to_string(), json)
        };
        log::debug!("{}: {} {}", self.id, label, printable(&text, 2000));
        let mut log = lock(&self.log);
        if log.len() >= LOG_FRAMES {
            log.pop_front();
        }
        log.push_back(LogEntry { at: now_iso(), direction, label: label.to_string(), text, json });
    }

    /// The debug log for the API: each entry with its frame decoded (or as text, if it never was JSON).
    pub fn frames(&self) -> Vec<Value> {
        lock(&self.log)
            .iter()
            .map(|entry| {
                let data = if entry.json {
                    parse_frame(&entry.text)
                        .map(Value::Array)
                        .or_else(|| serde_json::from_str(&entry.text).ok())
                        .unwrap_or_else(|| Value::from(entry.text.as_str()))
                } else {
                    Value::from(entry.text.as_str())
                };
                json!({"at": entry.at, "dir": entry.direction, "label": entry.label, "data": data})
            })
            .collect()
    }

    /// How many frames the debug log holds, and the bytes they take.
    pub fn log_size(&self) -> (usize, usize) {
        let log = lock(&self.log);
        (log.len(), log.iter().map(|entry| entry.text.len()).sum())
    }

    /// Close the socket and fail whatever was waiting on it. Returns once it is gone (or, for a
    /// connection whose socket was never attached, at once).
    pub async fn close(&self) {
        let was_closed = self.closed.swap(true, Ordering::SeqCst);
        self.fail_pending("Closed by server");
        if !was_closed {
            let frame = CloseFrame { code: CloseCode::Normal, reason: "".into() };
            let _ = self.out.try_send(Message::Close(Some(frame)));
            self.closing.notify_one();
        }
        if lock(&self.out_rx).is_some() {
            return; // never attached to a socket: there is nothing to wait for
        }
        let mut done = self.done.subscribe();
        let _ = tokio::time::timeout(CLOSE_GRACE * 2, done.wait_for(|done| *done)).await;
    }

    /// The connection ended without its socket ever being attached.
    pub fn abandon(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.fail_pending("Disconnected");
        self.done.send_replace(true);
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").field("id", &self.id).field("closed", &self.is_closed()).finish()
    }
}

/// A value from a charger as one bounded log line.
pub fn loggable(value: &Value, limit: usize) -> String {
    printable_value(value, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_get_configuration_is_repaired() {
        let frame = parse_frame(r#"[3,"abc",{"configurationKey":]}]"#).unwrap();
        assert_eq!(Value::Array(frame), json!([3, "abc", {"configurationKey": []}]));
        let frame = parse_frame(r#"[3,"abc",{"configurationKey": [{"key":"a","value":"1",},],}]"#).unwrap();
        assert_eq!(Value::Array(frame), json!([3, "abc", {"configurationKey": [{"key": "a", "value": "1"}]}]));
        assert_eq!(repair_json(r#"{"a":  ]}"#), r#"{"a":[]}"#);
        assert_eq!(repair_json(r#"[1, 2 , ]"#), r#"[1, 2 ]"#);
    }

    #[test]
    fn frames_that_are_not_ocpp_are_dropped() {
        for bad in [
            "",
            "{}",
            "[]",
            "[2]",
            "[2,\"a\"]",
            "[5,\"a\",{}]",
            "[\"2\",\"a\",{}]",
            "[true,\"a\",{}]",
            "nonsense",
            "[2,\"a\",NaN]",
        ] {
            assert!(parse_frame(bad).is_none(), "{bad}");
        }
        assert!(parse_frame("[2,\"a\",\"Heartbeat\",{}]").is_some());
        assert!(parse_frame("[2.0,\"a\",\"Heartbeat\",{}]").is_some());
    }

    #[test]
    fn frames_nested_absurdly_deep_are_dropped() {
        let nested = |depth: usize| format!("[2,\"a\",\"DataTransfer\",{}{}]", "[".repeat(depth), "]".repeat(depth));
        assert!(parse_frame(&nested(5)).is_some());
        assert!(parse_frame(&nested(MAX_FRAME_DEPTH - 1)).is_some());
        assert!(parse_frame(&nested(MAX_FRAME_DEPTH + 1)).is_none());
        assert!(parse_frame(&nested(5000)).is_none());
        assert!(parse_frame(&format!("[2,\"a\",\"X\",{}", "{\"a\":".repeat(100_000))).is_none());
    }

    #[test]
    fn peek_reads_what_is_legible() {
        assert_eq!(peek_frame(r#"[3,"abc",{"broken"#), Some((3, "abc".to_string())));
        assert_eq!(peek_frame(r#"  [ 4 , "x y" , oops"#), Some((4, "x y".to_string())));
        assert_eq!(peek_frame(r#"[2,"abc","Boot"#), Some((2, "abc".to_string())));
        for bad in [r#"[3,abc]"#, r#"[5,"abc"]"#, r#"[3,""]"#, "", "[", r#"{"3":"abc"}"#] {
            assert_eq!(peek_frame(bad), None, "{bad}");
        }
    }

    #[test]
    fn call_errors_are_sanitised() {
        let err = OcppError::with_details("Bad\nCode", &"x".repeat(400), json!({"a": 1}));
        assert_eq!(err.code, "Bad\\nCode");
        assert!(err.description.ends_with("...(+100 more)"));
        assert!(!err.to_string().contains('\n'));
        assert_eq!(OcppError::new("Timeout", "").to_string(), "Timeout");
        assert_eq!(OcppError::new("Offline", "GRD-1 is not connected").to_string(), "Offline: GRD-1 is not connected");
    }

    fn connection() -> Connection {
        Connection::new("GRD-TEST", 120.0, 10.0, Duration::from_secs(30))
    }

    async fn feed(
        conn: &Connection,
        text: &str,
        handler: &(dyn Fn(&str, Object) -> HandlerResult + Sync),
    ) -> Vec<Value> {
        conn.handle_text(text, handler).await.unwrap();
        let mut sent = Vec::new();
        let mut queue = lock(&conn.out_rx);
        while let Ok(Message::Text(text)) = queue.as_mut().unwrap().try_recv() {
            sent.push(serde_json::from_str(text.as_str()).unwrap());
        }
        sent
    }

    #[tokio::test]
    async fn calls_are_answered_with_results_and_errors() {
        let conn = connection();
        let handler = |action: &str, payload: Object| -> HandlerResult {
            match action {
                "Heartbeat" => Ok(json!({"currentTime": "now"})),
                "Echo" => Ok(Value::Object(payload)),
                "Nothing" => Ok(Value::Null),
                "Refuse" => Err(HandlerError::rejected("PropertyConstraintViolation", "no")),
                "Boom" => panic!("handler bug"),
                "Fail" => Err(HandlerError::Internal("disk full".into())),
                _ => Err(HandlerError::NotImplemented),
            }
        };
        assert_eq!(feed(&conn, r#"[2,"1","Heartbeat",{}]"#, &handler).await, [json!([3, "1", {"currentTime": "now"}])]);
        assert_eq!(feed(&conn, r#"[2,7,"Echo",{"a":1}]"#, &handler).await, [json!([3, 7, {"a": 1}])]);
        assert_eq!(feed(&conn, r#"[2,"2","Echo","not an object"]"#, &handler).await, [json!([3, "2", {}])]);
        assert_eq!(feed(&conn, r#"[2,"3","Nothing",{}]"#, &handler).await, [json!([3, "3", {}])]);
        assert_eq!(
            feed(&conn, r#"[2,"4","Refuse",{}]"#, &handler).await,
            [json!([4, "4", "PropertyConstraintViolation", "no", {}])]
        );
        assert_eq!(
            feed(&conn, r#"[2,"5","Boom",{}]"#, &handler).await,
            [json!([4, "5", "InternalError", "handler failed", {}])]
        );
        assert_eq!(
            feed(&conn, r#"[2,"6","Fail",{}]"#, &handler).await,
            [json!([4, "6", "InternalError", "handler failed", {}])]
        );
        assert_eq!(
            feed(&conn, "[2,\"7\",\"Odd\\nAction\",{}]", &handler).await,
            [json!([4, "7", "NotImplemented", "Odd\\nAction is not supported", {}])]
        );
    }

    #[tokio::test]
    async fn unhashable_unique_ids_do_not_kill_the_connection() {
        let conn = connection();
        let handler = |_: &str, _: Object| -> HandlerResult { Ok(json!({})) };
        for odd in [
            r#"[2,["a"],"Heartbeat",{}]"#,
            r#"[2,{"a":1},"Heartbeat",{}]"#,
            r#"[2,null,"Heartbeat",{}]"#,
            r#"[2,true,"Heartbeat",{}]"#,
            r#"[2,"a",5,{}]"#,
            r#"[2,"a","Heartbeat"]"#,
        ] {
            assert!(feed(&conn, odd, &handler).await.is_empty(), "{odd}");
        }
        for odd in [r#"[3,["a"],{}]"#, r#"[3,{"a":1},{}]"#, r#"[4,null,"x","y",{}]"#, r#"[3,5,{}]"#] {
            assert!(feed(&conn, odd, &handler).await.is_empty(), "{odd}");
        }
        assert_eq!(feed(&conn, r#"[2,"ok","Heartbeat",{}]"#, &handler).await.len(), 1);
    }

    #[tokio::test]
    async fn replies_reach_the_call_that_waits_for_them() {
        let conn = std::sync::Arc::new(connection());
        let handler = |_: &str, _: Object| -> HandlerResult { Ok(json!({})) };
        let uid_of = |conn: &Connection| -> String {
            let mut queue = lock(&conn.out_rx);
            match queue.as_mut().unwrap().try_recv().unwrap() {
                Message::Text(text) => {
                    serde_json::from_str::<Value>(text.as_str()).unwrap()[1].as_str().unwrap().to_string()
                }
                other => panic!("{other:?}"),
            }
        };

        let caller = tokio::spawn({
            let conn = conn.clone();
            async move { conn.call("GetConfiguration", json!({}), None).await }
        });
        tokio::task::yield_now().await;
        let uid = uid_of(&conn);
        conn.handle_text(&format!(r#"[3,"{uid}",{{"configurationKey":]}}]"#), &handler).await.unwrap();
        assert_eq!(Value::Object(caller.await.unwrap().unwrap()), json!({"configurationKey": []}));

        let caller = tokio::spawn({
            let conn = conn.clone();
            async move { conn.call("Reset", json!({"type": "Soft"}), None).await }
        });
        tokio::task::yield_now().await;
        let uid = uid_of(&conn);
        conn.handle_text(&format!(r#"[4,"{uid}","NotSupported","no\nway",{{"x":1}}]"#), &handler).await.unwrap();
        let err = caller.await.unwrap().unwrap_err();
        assert_eq!(
            (err.code.as_str(), err.description.as_str(), &err.details),
            ("NotSupported", "no\\nway", &json!({"x": 1}))
        );

        // A reply too broken to parse still ends the wait.
        let caller = tokio::spawn({
            let conn = conn.clone();
            async move { conn.call("GetConfiguration", json!({}), None).await }
        });
        tokio::task::yield_now().await;
        let uid = uid_of(&conn);
        conn.handle_text(&format!(r#"[3,"{uid}",{{"configurationKey": [{{"key"#), &handler).await.unwrap();
        assert!(caller.await.unwrap().unwrap().is_empty());

        // And one that is never answered times out.
        let err = conn.call("Reset", json!({}), Some(Duration::from_millis(50))).await.unwrap_err();
        assert_eq!(err.code, "Timeout");
        assert_eq!(err.description, "Reset not answered by GRD-TEST");
        assert!(lock(&conn.pending).is_empty());

        // Nor does a caller that is stopped while it waits (a repeated BootNotification aborts
        // the conversation that followed the one before) leave its call behind.
        let caller = tokio::spawn({
            let conn = conn.clone();
            async move { conn.call("Reset", json!({}), None).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(lock(&conn.pending).len(), 1);
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(lock(&conn.pending).is_empty());
    }

    #[tokio::test]
    async fn large_frames_are_not_kept_in_the_frame_log() {
        let conn = connection();
        let handler = |_: &str, _: Object| -> HandlerResult { Ok(json!({})) };
        let big = format!(r#"[2,"1","DataTransfer",{{"data":"{}"}}]"#, "x".repeat(LOG_FRAME_BYTES));
        feed(&conn, &big, &handler).await;
        feed(&conn, "not json at all", &handler).await;
        let frames = conn.frames();
        assert_eq!(frames[0]["label"], "<- DataTransfer");
        assert_eq!(frames[0]["data"]["omitted"], "frame too large to keep in the log");
        assert_eq!(
            frames[1],
            json!({"at": frames[1]["at"], "dir": "out", "label": "-> result DataTransfer", "data": [3, "1", {}]})
        );
        assert_eq!(frames[2]["label"], "unparseable");
        assert_eq!(frames[2]["data"], "not json at all");
        for n in 0..500 {
            feed(&conn, &format!(r#"[2,"{n}","Heartbeat",{{}}]"#), &handler).await;
        }
        let (count, bytes) = conn.log_size();
        assert_eq!(count, LOG_FRAMES);
        assert!(bytes < LOG_FRAMES * LOG_FRAME_BYTES);
    }

    #[tokio::test(start_paused = true)]
    async fn read_rate_is_limited_after_the_burst() {
        let conn = Connection::new("GRD-TEST", 5.0, 10.0, Duration::from_secs(30));
        let start = Instant::now();
        for _ in 0..5 {
            conn.throttle().await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO, "the burst is free");
        for _ in 0..20 {
            conn.throttle().await;
        }
        let elapsed = start.elapsed().as_secs_f64();
        assert!((1.9..=2.1).contains(&elapsed), "20 frames at 10 a second took {elapsed}s");
        // Idle time refills the bucket, but only up to the burst.
        tokio::time::sleep(Duration::from_secs(60)).await;
        let start = Instant::now();
        for _ in 0..5 {
            conn.throttle().await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
        conn.throttle().await;
        assert!(start.elapsed() > Duration::ZERO);
    }

    #[tokio::test]
    async fn a_closed_connection_fails_its_calls() {
        let conn = std::sync::Arc::new(connection());
        let caller = tokio::spawn({
            let conn = conn.clone();
            async move { conn.call("Reset", json!({}), None).await }
        });
        tokio::task::yield_now().await;
        conn.close().await;
        let err = caller.await.unwrap().unwrap_err();
        assert_eq!((err.code.as_str(), err.description.as_str()), ("Disconnected", "Closed by server"));
        assert!(conn.is_closed());
        assert_eq!(conn.call("Reset", json!({}), None).await.unwrap_err().code, "Disconnected");
    }
}
