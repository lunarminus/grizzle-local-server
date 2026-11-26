//! REST API shaped like connect-api.unitedchargers.com, plus a few local extras.
//!
//! Only the subset the Grizzl-E Connect app and the Home Assistant integration use is
//! implemented. Station ids are the charger serial (the cloud uses Mongo ids).

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::{Duration as Days, TimeZone, Utc};
use indexmap::IndexMap;
use serde_json::{json, Value};

use crate::config::{is_charge_point_id, Settings};
use crate::controller::{station_tz, CommandError, Controller, Token};
use crate::crypto::{hex, md5_hex, random_bytes, random_token, same_secret, slow_hash, unhex};
use crate::holidays;
use crate::logging::printable;
use crate::net::{address, is_global, split_url};
use crate::state::{connector_count, Connector, Station, MAX_CONNECTORS, MODES};
use crate::timeutil::{iso, parse_iso, seconds_between};
use crate::value::{get, number, opt_int, opt_number, round_to, to_text, truthy, whole_number, Object};

/// How long a bearer token works, in seconds.
pub const TOKEN_TTL: f64 = 7.0 * 24.0 * 3600.0;
/// How long its refresh token can still get a new one.
pub const REFRESH_TTL: f64 = 30.0 * 24.0 * 3600.0;
/// Sessions kept; the oldest make room.
pub const MAX_TOKENS: usize = 100;
/// Logout is public on purpose: a session whose token has just expired must still be endable (its
/// refresh token lives on for weeks). Tokens are unguessable, so there is nothing to protect here.
pub const PUBLIC_PATHS: [&str; 5] =
    ["/client/auth/login", "/client/auth/refresh-token", "/client/auth/logout", "/health", "/"];
/// Failed sign-ins allowed per client within the window before it has to wait, and from all clients
/// together before sign-in closes for clients that have never signed in successfully.
pub const LOGIN_MAX_FAILURES: usize = 10;
pub const LOGIN_MAX_TOTAL_FAILURES: usize = 200;
pub const LOGIN_WINDOW_SECONDS: f64 = 300.0;
/// Most sessions one request returns.
pub const MAX_SESSION_ROWS: i64 = 1000;
pub const MAX_OCPP_CALL_TIMEOUT: f64 = 120.0;
/// Host names nobody can register in public DNS, so no web site can point one of them at this server.
pub const PRIVATE_NAME_SUFFIXES: [&str; 10] = [
    ".local",
    ".lan",
    ".home",
    ".home.arpa",
    ".internal",
    ".intranet",
    ".corp",
    ".localdomain",
    ".localhost",
    ".test",
];
/// The names the charger calls us by (and the certificate from scripts/make-cert.sh is for). Only a
/// DNS override on the owner's own network makes them lead here.
pub const VENDOR_HOSTS: [&str; 2] = ["ocpp.unitedchargers.com", "connect-api.unitedchargers.com"];

// --- responses --------------------------------------------------------------------

/// What a handler answers with.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(data: &Value) -> Reply {
        Reply::json_status(200, data)
    }

    pub fn json_status(status: u16, data: &Value) -> Reply {
        // Strict JSON by construction: a number that is not finite has no JSON value and is null.
        Reply { status, content_type: "application/json; charset=utf-8", headers: Vec::new(), body: data.to_string().into_bytes() }
    }

    /// An error in the API's usual shape: `{"message": ..., "statusCode": ...}`.
    pub fn error(status: u16, message: &str) -> Reply {
        Reply::json_status(status, &json!({"message": message, "statusCode": status}))
    }

    pub fn text(status: u16, body: &str) -> Reply {
        Reply { status, content_type: "text/plain; charset=utf-8", headers: Vec::new(), body: body.as_bytes().to_vec() }
    }

    pub fn not_found() -> Reply {
        Reply::text(404, "404: Not Found")
    }

    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Reply {
        self.headers.push((name, value.into()));
        self
    }
}

impl From<CommandError> for Reply {
    fn from(err: CommandError) -> Reply {
        match err {
            CommandError::Invalid(message) => Reply::error(400, &message),
            CommandError::NotFound => Reply::text(404, "unknown station"),
            CommandError::Failed(message) => {
                log::error!("a request failed: {}", printable(&message, 300));
                Reply::error(500, "Internal Server Error")
            }
        }
    }
}

type Handled = Result<Reply, Reply>;

// --- requests ---------------------------------------------------------------------

/// What the handlers need of an HTTP request.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    /// The path, percent-decoded.
    pub path: String,
    /// The query string as it was sent.
    pub query: String,
    /// Header names in lower case; the first value of each.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The address the connection came from.
    pub peer: Option<IpAddr>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// The first value of a query parameter.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(&key.replace('+', " ")) == name).then(|| percent_decode(&value.replace('+', " ")))
        })
    }

    /// The JSON object in the body; `{}` for no body, or for JSON that is not an object.
    fn json_body(&self) -> Result<Object, Reply> {
        if self.body.is_empty() {
            return Ok(Object::new());
        }
        // Not JSON, not UTF-8, thousands of nested brackets: however a body fails to read, it is
        // the sender's mistake, not a server error.
        match serde_json::from_slice::<Value>(&self.body) {
            Ok(Value::Object(body)) => Ok(body),
            Ok(_) => Ok(Object::new()),
            Err(_) => Err(Reply::error(400, "invalid JSON")),
        }
    }

    /// The bearer token from the Authorization header ("" if there is none).
    ///
    /// Only the header: a token in the query string ends up in browser history, proxy logs and
    /// Referer headers.
    pub fn bearer(&self) -> &str {
        let header = self.header("authorization").unwrap_or_default();
        match header.get(..7) {
            Some(scheme) if scheme.eq_ignore_ascii_case("bearer ") => header[7..].trim(),
            _ => "",
        }
    }
}

/// `%41` -> `A`. Whatever doesn't decode stays as it is; bytes that aren't UTF-8 become U+FFFD.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let decoded = (bytes[at] == b'%')
            .then(|| text.get(at + 1..at + 3).and_then(|hex| u8::from_str_radix(hex, 16).ok()))
            .flatten();
        match decoded {
            Some(byte) => {
                out.push(byte);
                at += 3;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The address of whoever sent this request.
///
/// Seen through a reverse proxy named in GRIZZLE_TRUSTED_PROXIES: only then is X-Forwarded-For
/// believed, read from the right, and only as far as the first address that is not itself one of
/// those proxies.
pub fn client_ip(request: &Request, settings: &Settings) -> String {
    let Some(peer) = request.peer else { return "?".to_string() };
    let mut remote = peer.to_canonical();
    if settings.trusted_proxies.iter().any(|network| network.contains(remote)) {
        for hop in request.header("x-forwarded-for").unwrap_or_default().rsplit(',') {
            let Some(hop) = address(hop) else { break }; // not an address: stop believing the header
            remote = hop;
            if !settings.trusted_proxies.iter().any(|network| network.contains(hop)) {
                break;
            }
        }
    }
    remote.to_string()
}

// --- station JSON in the cloud's shape ------------------------------------------------

fn last_list(value: Value) -> Value {
    if value.is_null() {
        Value::Null
    } else {
        json!([value])
    }
}

fn build_charge(station: &Station, connector: &Connector) -> Value {
    let Some(tx) = &connector.transaction else { return Value::Null };
    let meter = &tx.meter;
    json!({
        "_id": tx.id.to_string(),
        "transactionId": tx.id,
        "station": station.id,
        "stationSerialNumber": station.id,
        "idTag": tx.id_tag,
        "connectorId": connector.id,
        "startAt": tx.start_at,
        "duration": tx.duration.unwrap_or(0),
        "energy": round_to(tx.energy, 1),
        "status": 0,
        "power": number(tx.power),
        "meterValues": {
            "currentImport": last_list(json!(meter.current_a)),
            "currentOffered": last_list(json!(meter.current_offered_a)),
            "energyActiveImportRegister": last_list(json!(meter.energy_wh)),
            "powerActiveImport": last_list(json!(meter.power_w)),
            "SoC": last_list(json!(meter.soc)),
            "temperature": last_list(json!(meter.temperature_c)),
            "voltage": last_list(json!(meter.voltage_v)),
            "priceKW": last_list(json!(tx.price_kw)),
            "date": last_list(json!(meter.at)),
        },
        "hasMeterValues": !meter.is_empty(),
        "currency": station.currency,
        "priceKW": tx.price_kw,
        "priceTotal": round_to(tx.price_total, 4),
        "meterStart": opt_number(tx.meter_start),
        "temperatureUnit": "Celsius",
        "isCommercial": false,
        "costByZones": [],
    })
}

fn build_connector(station: &Station, connector: &Connector) -> Value {
    let meter = &connector.last_meter;
    json!({
        "_id": format!("{}-{}", station.id, connector.id),
        "connectorId": connector.id,
        "type": "J1772",
        "maxPower": station.max_current * 240,
        "status": connector.status.as_deref().filter(|s| !s.is_empty()).unwrap_or("Unavailable"),
        "power": number(connector.power),
        "errorCode": connector.error_code.as_deref().filter(|c| !c.is_empty()).unwrap_or("NoError"),
        "mode": connector.mode.as_str(),
        "charge": build_charge(station, connector),
        "statusChangedAt": connector.status_changed_at,
        "isActiveBySchedule": connector.is_active_by_schedule,
        "nextScheduleTime": connector.next_schedule_time,
        // Extras the cloud doesn't have, handy for dashboards: latest readings even when idle.
        "lastMeter": {
            "currentImport": meter.current_a,
            "voltage": meter.voltage_v,
            "temperature": meter.temperature_c,
            "energyActiveImportRegister": meter.energy_wh,
            "date": meter.at,
        },
        "totalEnergyWh": connector.total_energy_wh,
    })
}

/// A station the way the cloud describes one, plus what only this server has.
pub fn build_station(station: &Station, online: bool, settings: &Settings) -> Value {
    let live: Vec<&Connector> =
        (1..=connector_count(station)).filter_map(|cid| station.connectors.get(&cid)).collect();
    let connectors: Vec<Value> = live.iter().map(|connector| build_connector(station, connector)).collect();
    let statuses: Vec<&str> = connectors.iter().filter_map(|c| c["status"].as_str()).collect();
    let status = if statuses.contains(&"Charging") { "Charging" } else { statuses.first().copied().unwrap_or("Unavailable") };
    let mode = match live.first() {
        Some(first) if live.iter().all(|connector| connector.mode == first.mode) => first.mode.as_str(),
        _ => "Active",
    };
    let limit = opt_int(station.current_limit);
    let firmware = get(&station.boot, "firmwareVersion");
    let holiday_settings = station.holidays.clone().unwrap_or_default();
    let today = Utc::now().with_timezone(&station_tz(station, settings)).date_naive();
    let upcoming: Vec<Value> = if holiday_settings.enabled {
        let rows = holiday_settings.upcoming(today, 370);
        rows.iter().filter(|row| row.included).map(|row| json!({"date": row.date.to_string(), "name": row.name})).collect()
    } else {
        Vec::new()
    };
    let holiday_today = if holiday_settings.enabled { holiday_settings.holiday_name(today) } else { None };
    json!({
        "id": station.id,
        "_id": station.id,
        "identity": station.id,
        "serialNumber": station.id,
        "displayName": if station.display_name.is_empty() { &station.id } else { &station.display_name },
        "online": online,
        "mode": mode,
        "status": if online { status } else { "Unavailable" },
        "errorCode": station.error_code.as_deref().filter(|code| !code.is_empty()).unwrap_or("NoError"),
        "schedule": {
            "enabled": station.zones.iter().any(|zone| truthy(get(zone, "scheduleEnabled"))),
            "weekdaysEnabled": false,
            "weekendsEnabled": false,
        },
        "connectors": connectors,
        "currency": station.currency,
        "priceKW": number(station.price_kw),
        "locationData": {"timezone": station.timezone, "autoselectTimezone": false},
        "bootNotification": {
            "chargePointModel": get(&station.boot, "chargePointModel"),
            "chargePointSerialNumber": get(&station.boot, "chargePointSerialNumber"),
            "chargePointVendor": get(&station.boot, "chargePointVendor"),
            "firmwareVersion": firmware,
            "meterType": get(&station.boot, "meterType"),
            "timestamp": get(&station.boot, "timestamp"),
        },
        "firmwareStatuses": [],
        "vendorData": {"formattedSerialNumber": station.id, "chargerType": station.model_code},
        "strategy": "Default",
        "model": {
            "_id": if station.model_code.is_empty() { "local" } else { &station.model_code },
            "name": station.model_name,
            "displayName": station.model_name,
            "maxCurrent": station.max_current,
            "minCurrent": station.min_current,
            "numberOfPhases": "OnePhase",
            "connectors": live.iter()
                .map(|_| json!({"maxPower": (station.max_current * 240) as f64 / 1000.0, "type": "type1"}))
                .collect::<Vec<_>>(),
            "strategy": "Default",
        },
        "smartCharging": {
            "applied": station.current_limit.is_some(),
            "currentLimit": limit,
            "weekdaysCurrentLimit": limit,
            "weekendsCurrentLimit": limit,
            "appliedLimit": station.applied_limit,
        },
        "supportedOcppProfiles": {"profiles": ["Core", "SmartCharging", "RemoteTrigger"], "firmwareVersion": firmware},
        "pricesByZone": station.zones,
        "holidaysSettings": holiday_settings.to_json(),
        "holidays": upcoming,
        "holidayToday": holiday_today,
        "sharedWith": [],
        "isSharedAccess": false,
        "dipSwitchCurrentLimit": station.dip_switch_current_limit,
        "isActiveBySchedule": live.iter().any(|connector| connector.is_active_by_schedule == Some(true)),
        "nextScheduleTime": live.iter().filter_map(|c| c.next_schedule_time.as_deref()).filter(|t| !t.is_empty()).min(),
        "powerSharingMode": 0,
        "lastSeen": station.last_seen,
        "firstSeen": station.first_seen,
        "config": station.config,
        "user": user(settings),
    })
}

fn user(settings: &Settings) -> Value {
    json!({"_id": "local", "firstName": "Local", "lastName": "Server", "email": settings.api_email})
}

// --- auth ------------------------------------------------------------------------

/// Slows password guessing.
///
/// - Per client: a few failures per window, then that client waits. IPv6 clients are counted by
///   their /64, since one machine can use any address in its own.
/// - Overall: when failures pour in from many clients at once, sign-in closes for every client
///   that has not signed in successfully before. The owner's usual address keeps working, and
///   sessions that already exist are not affected at all.
///
/// Times are seconds on any clock that only moves forward.
pub struct LoginThrottle {
    pub max_failures: usize,
    pub window: f64,
    pub max_total: usize,
    failures: IndexMap<String, VecDeque<f64>>,
    all: VecDeque<f64>,
    /// Clients that have signed in, least recently first.
    known: IndexMap<String, ()>,
}

impl Default for LoginThrottle {
    fn default() -> LoginThrottle {
        LoginThrottle::new(LOGIN_MAX_FAILURES, LOGIN_WINDOW_SECONDS, LOGIN_MAX_TOTAL_FAILURES)
    }
}

impl LoginThrottle {
    pub const MAX_CLIENTS: usize = 4096;
    pub const MAX_KNOWN: usize = 256;

    pub fn new(max_failures: usize, window: f64, max_total: usize) -> LoginThrottle {
        LoginThrottle {
            max_failures,
            window,
            max_total,
            failures: IndexMap::new(),
            all: VecDeque::new(),
            known: IndexMap::new(),
        }
    }

    /// What counts as one client: an IPv4 address, or an IPv6 /64.
    pub fn key(client: &str) -> String {
        match client.split('%').next().unwrap_or_default().parse::<IpAddr>().map(|ip| ip.to_canonical()) {
            Ok(IpAddr::V4(four)) => four.to_string(), // ::ffff:192.0.2.1 is the IPv4 client 192.0.2.1
            Ok(IpAddr::V6(six)) => {
                let network = u128::from(six) & !u128::from(u64::MAX);
                format!("{}/64", std::net::Ipv6Addr::from(network))
            }
            Err(_) => client.to_string(),
        }
    }

    fn wait(failures: &mut VecDeque<f64>, limit: usize, window: f64, now: f64) -> u64 {
        while failures.front().is_some_and(|first| now - first >= window) {
            failures.pop_front();
        }
        match failures.front() {
            Some(first) if failures.len() >= limit => ((window - (now - first)).ceil() as u64).max(1),
            _ => 0,
        }
    }

    /// Seconds this client must wait before trying again; 0 if it may try now.
    pub fn retry_after(&mut self, client: &str, now: f64) -> u64 {
        let key = LoginThrottle::key(client);
        let mut wait = 0;
        if let Some(failures) = self.failures.get_mut(&key) {
            wait = LoginThrottle::wait(failures, self.max_failures, self.window, now);
            if failures.is_empty() {
                self.failures.shift_remove(&key);
            }
        }
        if wait == 0 && !self.known.contains_key(&key) {
            wait = LoginThrottle::wait(&mut self.all, self.max_total, self.window, now);
        }
        wait
    }

    pub fn failed(&mut self, client: &str, now: f64) {
        let key = LoginThrottle::key(client);
        if !self.failures.contains_key(&key) && self.failures.len() >= LoginThrottle::MAX_CLIENTS {
            // Make room, but not by forgetting a client that is locked out right now if there is
            // any other: otherwise a crowd of addresses would be a way to reset one's own count.
            let (limit, window) = (self.max_failures, self.window);
            let idle = self.failures.iter_mut().position(|(_, f)| LoginThrottle::wait(f, limit, window, now) == 0);
            self.failures.shift_remove_index(idle.unwrap_or(0));
        }
        let failures = self.failures.entry(key).or_default();
        if failures.len() >= self.max_failures {
            failures.pop_front();
        }
        failures.push_back(now);
        if self.all.len() >= self.max_total {
            self.all.pop_front();
        }
        self.all.push_back(now);
    }

    pub fn succeeded(&mut self, client: &str) {
        let key = LoginThrottle::key(client);
        self.failures.shift_remove(&key);
        self.known.shift_remove(&key);
        self.known.insert(key, ());
        while self.known.len() > LoginThrottle::MAX_KNOWN {
            self.known.shift_remove_index(0);
        }
    }

    pub fn tracked_clients(&self) -> usize {
        self.failures.len()
    }
}

/// May a browser page from `origin` use the API?
///
/// Only browsers send Origin, and they send it with every request that changes something
/// (signing in included). The page we serve is reached by an address on the local network or a
/// name only the local network knows, and those are let through. What is refused is a page from a
/// public DNS name: either another web site posting to us (it can't read the answer, but it could
/// burn the owner's sign-in attempts), or a site that re-pointed its own name at this server (DNS
/// rebinding), which the browser would otherwise treat as the API's own origin. A deliberate
/// public name (a reverse proxy, say) is allowed with GRIZZLE_ALLOWED_HOSTS.
pub fn origin_allowed(origin: &str, host_header: &str, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.iter().any(|host| host == "*") {
        return true;
    }
    let Some(parts) = split_url(origin) else { return false };
    let host = parts.hostname.unwrap_or_default();
    let host = host.trim_end_matches('.');
    if !matches!(parts.scheme.as_str(), "http" | "https") || host.is_empty() {
        return false; // "null" (a sandboxed frame, a local file), browser extensions, anything else
    }
    if allowed_hosts.iter().any(|allowed| allowed == host) || VENDOR_HOSTS.contains(&host) {
        return true;
    }
    if allowed_hosts.iter().any(|suffix| suffix.starts_with('.') && host.ends_with(suffix.as_str())) {
        return true;
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        return host == "localhost" || !host.contains('.') || PRIVATE_NAME_SUFFIXES.iter().any(|s| host.ends_with(s));
    };
    if !is_global(ip) {
        return true; // a machine on the local network: nothing it couldn't send us directly
    }
    // a public address is fine only as our own page's
    split_url(&format!("//{host_header}")).and_then(|parts| parts.hostname).is_some_and(|served_as| served_as == host)
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

/// Sessions: who is signed in, and the limit on trying to be.
pub struct Auth {
    controller: Arc<Controller>,
    throttle: Mutex<LoginThrottle>,
    credentials_checked: AtomicBool,
    started: Instant,
}

impl Auth {
    pub fn new(controller: Arc<Controller>) -> Auth {
        let auth = Auth {
            controller,
            throttle: Mutex::new(LoginThrottle::default()),
            credentials_checked: AtomicBool::new(false),
            started: Instant::now(),
        };
        if !auth.controller.lock().tokens.is_empty() {
            // Sessions from before this start: are they for the credentials we have now?
            auth.check_credentials();
        }
        auth
    }

    pub fn throttle(&self) -> std::sync::MutexGuard<'_, LoginThrottle> {
        self.throttle.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Seconds on the clock the throttle counts by.
    fn clock(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    fn credentials_mark(&self, salt: &[u8]) -> String {
        let settings = &self.controller.settings;
        let material = format!("{}\0{}", settings.api_email.trim().to_lowercase(), settings.api_password);
        slow_hash(material.as_bytes(), salt, settings.credential_rounds)
    }

    /// Sign every session out if the email or password is no longer what it was when they signed in.
    ///
    /// Changing the password is how an owner locks out someone who got hold of a session; it has
    /// to actually do that. state.json keeps a salted, slow hash of the credentials to compare with
    /// (not the password, and not something that makes guessing it cheap).
    fn check_credentials(&self) {
        self.credentials_checked.store(true, Ordering::SeqCst);
        let saved = self.controller.lock().credentials.clone();
        let saved = match (saved["salt"].as_str(), saved["mark"].as_str()) {
            (Some(salt), Some(mark)) => Some((salt.to_string(), mark.to_string())),
            _ => None,
        };
        // The slow hash is worked out without holding the state.
        let same = saved.as_ref().map(|(salt, mark)| {
            unhex(salt).is_some_and(|salt| same_secret(Some(&self.credentials_mark(&salt)), mark))
        });
        if same == Some(true) {
            return;
        }
        let salt = random_bytes(16);
        let mark = self.credentials_mark(&salt);
        let mut inner = self.controller.lock();
        let sessions = inner.tokens.len();
        if sessions > 0 {
            if same.is_some() {
                log::warn!("the API email or password has changed: signing out {sessions} existing session(s)");
            } else {
                // Sessions from a version that kept no mark. Nothing says which password they were
                // signed in with (it may be the one that was just changed, in this very restart),
                // and their tokens may have travelled in URLs. Everyone signs in once more.
                log::warn!(
                    "signing out {sessions} session(s) saved by an earlier version: sign in again \
                     (Home Assistant does so itself)"
                );
            }
            inner.tokens.clear();
        }
        inner.credentials = json!({"salt": hex(&salt), "mark": mark});
        inner.dirty = true;
    }

    /// Sessions saved by an older version have no refresh expiry of their own.
    fn refresh_expiry(info: &Token) -> f64 {
        info.refresh_expires.filter(|expires| *expires != 0.0).unwrap_or(info.expires + (REFRESH_TTL - TOKEN_TTL))
    }

    /// A new session.
    pub fn issue(&self) -> Value {
        if !self.credentials_checked.load(Ordering::SeqCst) {
            self.check_credentials();
        }
        let now = unix_now();
        let (token, refresh) = (random_token(32), random_token(32));
        let mut inner = self.controller.lock();
        inner.tokens.retain(|_, info| Auth::refresh_expiry(info) >= now);
        let info = Token { refresh: refresh.clone(), expires: now + TOKEN_TTL, refresh_expires: Some(now + REFRESH_TTL) };
        inner.tokens.insert(token.clone(), info);
        while inner.tokens.len() > MAX_TOKENS {
            let oldest = inner.tokens.iter().min_by(|a, b| a.1.expires.total_cmp(&b.1.expires)).map(|(t, _)| t.clone());
            match oldest {
                Some(oldest) => inner.tokens.remove(&oldest),
                None => break,
            };
        }
        inner.dirty = true;
        drop(inner);
        json!({"token": token, "refreshToken": refresh, "isVerified": true, "user": self.user()})
    }

    /// A new session for a refresh token, which is used up by this. `None` if it is not one of ours.
    pub fn refresh(&self, refresh_token: &str) -> Option<Value> {
        let now = unix_now();
        let found = {
            let mut inner = self.controller.lock();
            let found = inner
                .tokens
                .iter()
                .find(|(_, info)| same_secret(Some(refresh_token), &info.refresh))
                .map(|(token, info)| (token.clone(), Auth::refresh_expiry(info)));
            if let Some((token, _)) = &found {
                inner.tokens.remove(token);
                inner.dirty = true;
            }
            found
        };
        found.filter(|(_, expires)| *expires > now).map(|_| self.issue())
    }

    pub fn valid(&self, token: &str) -> bool {
        !token.is_empty() && self.controller.lock().tokens.get(token).is_some_and(|info| info.expires > unix_now())
    }

    /// Forget a session, named by its token or its refresh token: neither works afterwards.
    pub fn revoke(&self, token: &str, refresh_token: &str) {
        let mut inner = self.controller.lock();
        let mut doomed: Vec<String> = Vec::new();
        if inner.tokens.contains_key(token) {
            doomed.push(token.to_string());
        }
        if !refresh_token.is_empty() {
            let matching = inner.tokens.iter().filter(|(_, info)| same_secret(Some(refresh_token), &info.refresh));
            doomed.extend(matching.map(|(token, _)| token.clone()));
        }
        for token in &doomed {
            inner.tokens.remove(token);
        }
        if !doomed.is_empty() {
            inner.dirty = true;
        }
    }

    pub fn user(&self) -> Value {
        json!({"_id": "local", "email": self.controller.settings.api_email, "firstName": "Local", "lastName": "Server"})
    }
}

// --- the application -----------------------------------------------------------------

/// The settings, the controller and the sessions: everything a request handler needs.
pub struct App {
    pub settings: Arc<Settings>,
    pub controller: Arc<Controller>,
    pub auth: Auth,
}

impl App {
    /// Open the data directory the settings name and build the application over it.
    pub fn new(settings: Settings) -> Result<Arc<App>, String> {
        let settings = Arc::new(settings);
        let controller = Controller::open(settings.clone())?;
        let auth = Auth::new(controller.clone());
        Ok(Arc::new(App { settings, controller, auth }))
    }
}

/// A REST endpoint. `Route::find` matches a method and path to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Health,
    UnlockCheck(String),
    Login,
    RefreshToken,
    Logout,
    Profile,
    Stations,
    Station(String),
    Mode(String),
    CurrentLimit(String),
    ZoneUpdate { station: String, schedule: bool },
    ZoneEnable(String),
    ZoneDelete { station: String, zone: String },
    Rate(String),
    Reboot(String),
    Events(String),
    Samples(String),
    Sessions(String),
    Recalculate(String),
    Countries,
    HolidaysGet(String),
    HolidaysPut(String),
    HolidaysPreview(String),
    Log(String),
    OcppCall(String),
    Settings(String),
    DeleteStation(String),
    ClearAuthKey(String),
}

impl Route {
    /// The endpoint for a method and a (percent-decoded) path, if there is one. HEAD is GET.
    pub fn find(method: &str, path: &str) -> Option<Route> {
        let method = if method == "HEAD" { "GET" } else { method };
        let segments: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
        if segments.iter().any(|segment| segment.is_empty()) {
            return None;
        }
        let id = |segment: &str| segment.to_string();
        Some(match (method, segments.as_slice()) {
            ("GET", ["health"]) => Route::Health,
            ("GET", ["commercial", "ext-ocpp-check", serial]) => Route::UnlockCheck(id(serial)),
            ("POST", ["client", "auth", "login"]) => Route::Login,
            ("POST", ["client", "auth", "refresh-token"]) => Route::RefreshToken,
            ("POST", ["client", "auth", "logout"]) => Route::Logout,
            ("GET", ["client", "auth", "profile"]) => Route::Profile,
            ("GET", ["client", "stations"]) => Route::Stations,
            ("GET", ["client", "stations", station]) => Route::Station(id(station)),
            ("POST", ["client", "stations", station, "mode"]) => Route::Mode(id(station)),
            ("PUT", ["client", "stations", station, "currentLimit"]) => Route::CurrentLimit(id(station)),
            ("POST", ["client", "stations", station, "scheduleUpdate"]) => {
                Route::ZoneUpdate { station: id(station), schedule: true }
            }
            ("POST", ["client", "stations", station, "pricesByZoneUpdate"]) => {
                Route::ZoneUpdate { station: id(station), schedule: false }
            }
            ("POST", ["client", "stations", station, "scheduleEnable"]) => Route::ZoneEnable(id(station)),
            ("DELETE", ["client", "stations", station, "scheduleDelete" | "pricesByZoneDelete", zone]) => {
                Route::ZoneDelete { station: id(station), zone: id(zone) }
            }
            ("PUT", ["client", "stations", station, "rate"]) => Route::Rate(id(station)),
            ("POST", ["client", "stations", station, "reboot"]) => Route::Reboot(id(station)),
            ("GET", ["client", "stations", station, "events"]) => Route::Events(id(station)),
            ("GET", ["local", "stations", station, "samples"]) => Route::Samples(id(station)),
            ("GET", ["local", "stations", station, "sessions"]) => Route::Sessions(id(station)),
            ("POST", ["local", "stations", station, "sessions", "recalculate"]) => Route::Recalculate(id(station)),
            ("GET", ["local", "holidays", "countries"]) => Route::Countries,
            ("GET", ["local", "stations", station, "holidays"]) => Route::HolidaysGet(id(station)),
            ("PUT", ["local", "stations", station, "holidays"]) => Route::HolidaysPut(id(station)),
            ("POST", ["local", "stations", station, "holidays", "preview"]) => Route::HolidaysPreview(id(station)),
            ("GET", ["local", "stations", station, "log"]) => Route::Log(id(station)),
            ("POST", ["local", "stations", station, "ocpp"]) => Route::OcppCall(id(station)),
            ("PUT", ["local", "stations", station, "settings"]) => Route::Settings(id(station)),
            ("DELETE", ["local", "stations", station]) => Route::DeleteStation(id(station)),
            ("DELETE", ["local", "stations", station, "auth-key"]) => Route::ClearAuthKey(id(station)),
            _ => return None,
        })
    }
}

/// What stands between a request and its handler: the origin check for the API, then the session.
/// `Some` is the refusal to send.
///
/// Chargers connect outside /client and /local, so they never need a token. Requests are NOT
/// exempted by their Upgrade header: a request to an API path is an API request whatever it says
/// it would like to be upgraded to.
pub fn gate(app: &App, request: &Request) -> Option<Reply> {
    let path = request.path.as_str();
    let api = path.starts_with("/client/") || path.starts_with("/local/");
    if api {
        // before the public sign-in paths: they are what it protects most
        if let Some(refusal) = refuse_origin(app, request) {
            return Some(refusal);
        }
    }
    if PUBLIC_PATHS.contains(&path) || !api || app.auth.valid(request.bearer()) {
        return None;
    }
    Some(Reply::error(401, "Unauthorized"))
}

/// A 403 for an API request made by a web page we don't accept requests from, else `None`.
fn refuse_origin(app: &App, request: &Request) -> Option<Reply> {
    // No Origin: not a browser (Home Assistant, curl), or a same-origin read.
    let origin = request.header("origin")?;
    if origin_allowed(origin, request.header("host").unwrap_or_default(), &app.settings.allowed_hosts) {
        return None;
    }
    let host = split_url(origin).and_then(|parts| parts.hostname).unwrap_or_else(|| origin.to_string());
    let name = printable(&host, 100);
    log::warn!(
        "refused {} {} from a web page at {}. If that is how you open this server, set GRIZZLE_ALLOWED_HOSTS={} \
         (names with a dot that are not LAN-only by their ending have to be listed; it guards against DNS rebinding)",
        request.method,
        printable(&request.path, 100),
        printable(origin, 100),
        name
    );
    Some(Reply::error(
        403,
        &format!(
            "This server does not accept requests from a page opened as {name}. If that is how you open it, set \
             GRIZZLE_ALLOWED_HOSTS={name} in the server's configuration and restart it; opening the page by its IP \
             address works without that."
        ),
    ))
}

// --- handlers -------------------------------------------------------------------

/// An integer parameter in `lo..=hi` (from JSON or a query string), or a 400.
fn whole(value: &Value, name: &str, lo: i64, hi: i64, default: Option<i64>) -> Result<i64, Reply> {
    let number = match value {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => {
            let text = text.trim();
            let digits = text.strip_prefix('-').unwrap_or(text);
            let valid = (1..=10).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit());
            Some(valid.then(|| text.parse::<i64>().ok()).flatten())
        }
        other => Some(whole_number(other).filter(|_| other.is_number())),
    };
    match number {
        None => default.ok_or_else(|| Reply::error(400, &format!("{name} is required"))),
        Some(number) => number
            .filter(|n| (lo..=hi).contains(n))
            .ok_or_else(|| Reply::error(400, &format!("{name} must be a whole number from {lo} to {hi}"))),
    }
}

/// `?limit=`: any whole number, brought into 1..=MAX_SESSION_ROWS; anything else is a 400.
fn row_limit(request: &Request, default: i64) -> Result<i64, Reply> {
    let asked = request.query_param("limit").map_or(Value::Null, Value::from);
    Ok(whole(&asked, "limit", -1_000_000_000, 1_000_000_000, Some(default))?.clamp(1, MAX_SESSION_ROWS))
}

fn unknown_station() -> Reply {
    Reply::text(404, "unknown station")
}

impl App {
    fn require_station(&self, station_id: &str) -> Result<(), Reply> {
        if self.controller.lock().stations.contains_key(station_id) {
            Ok(())
        } else {
            Err(unknown_station())
        }
    }

    fn station_json(&self, station_id: &str) -> Handled {
        let inner = self.controller.lock();
        let station = inner.stations.get(station_id).ok_or_else(unknown_station)?;
        Ok(Reply::json(&build_station(station, inner.is_online(station_id), &self.settings)))
    }

    /// Answer a REST request that has passed the [`gate`].
    pub async fn dispatch(&self, route: Route, request: &Request) -> Reply {
        self.route(route, request).await.unwrap_or_else(|refusal| refusal)
    }

    async fn route(&self, route: Route, request: &Request) -> Handled {
        match route {
            Route::Health => Ok(self.health(request)),
            Route::UnlockCheck(serial) => self.unlock_check(&serial),
            Route::Login => self.login(request),
            Route::RefreshToken => {
                let body = request.json_body()?;
                let token = get(&body, "refreshToken");
                let token = if truthy(token) { to_text(token) } else { String::new() };
                Ok(self.auth.refresh(&token).map_or_else(|| Reply::error(401, "Invalid refresh token"), |s| Reply::json(&s)))
            }
            Route::Logout => {
                // Always 200: an expired or unknown token simply has no session left to end.
                let body = request.json_body()?;
                self.auth.revoke(request.bearer(), get(&body, "refreshToken").as_str().unwrap_or_default());
                Ok(Reply::json(&json!({})))
            }
            Route::Profile => Ok(Reply::json(&self.auth.user())),
            Route::Stations => {
                let inner = self.controller.lock();
                let stations: Vec<Value> = inner
                    .stations
                    .values()
                    .map(|station| build_station(station, inner.is_online(&station.id), &self.settings))
                    .collect();
                Ok(Reply::json(&json!({"stations": stations, "groups": []})))
            }
            Route::Station(station) => self.station_json(&station),
            Route::Mode(station) => self.set_mode(&station, request).await,
            Route::CurrentLimit(station) => {
                self.require_station(&station)?;
                let body = request.json_body()?;
                let amps = whole(get(&body, "value"), "value", 0, 1000, None)?;
                self.controller.set_current_limit(&station, amps).await?;
                self.station_json(&station)
            }
            Route::ZoneUpdate { station, schedule } => self.zone_update(&station, schedule, request).await,
            Route::ZoneEnable(station) => {
                self.require_station(&station)?;
                let body = request.json_body()?;
                let zone = to_text(get(&body, "_id"));
                let enabled = truthy(get(&body, "scheduleEnabled"));
                match self.controller.set_zone_enabled(&station, &zone, enabled).await {
                    Err(CommandError::NotFound) => Err(Reply::error(404, "unknown schedule")),
                    other => other.map_err(Reply::from),
                }?;
                self.station_json(&station)
            }
            Route::ZoneDelete { station, zone } => {
                self.require_station(&station)?;
                match self.controller.delete_zone(&station, &zone).await {
                    Err(CommandError::NotFound) => Err(Reply::error(404, "unknown schedule")),
                    other => other.map_err(Reply::from),
                }?;
                self.station_json(&station)
            }
            Route::Rate(station) => {
                self.require_station(&station)?;
                let body = request.json_body()?;
                self.controller.set_base_rate(&station, get(&body, "priceKW"))?;
                self.station_json(&station)
            }
            Route::Reboot(station) => {
                self.require_station(&station)?;
                match self.controller.reboot(&station).await {
                    Ok(result) => Ok(Reply::json(&Value::Object(result))),
                    Err(err) => Err(Reply::error(503, &err.to_string())),
                }
            }
            Route::Events(station) => {
                self.require_station(&station)?;
                let limit = row_limit(request, 50)?;
                let sessions = self.controller.lock().store.sessions(&station, limit).map_err(CommandError::from)?;
                Ok(Reply::json(&json!({"sessions": sessions})))
            }
            Route::Samples(station) => self.samples(&station, request),
            Route::Sessions(station) => self.sessions(&station, request),
            Route::Recalculate(station) => Ok(Reply::json(&self.controller.recalculate_costs(&station)?)),
            Route::Countries => {
                let countries: Vec<Value> = holidays::countries()
                    .iter()
                    .map(|country| {
                        let subdivisions: Vec<Value> =
                            country.subdivisions.iter().map(|s| json!({"code": s.code, "name": s.name})).collect();
                        json!({"code": country.code, "subdivisions": subdivisions})
                    })
                    .collect();
                Ok(Reply::json(&json!({"countries": countries})))
            }
            Route::HolidaysGet(station) => {
                let saved = {
                    let inner = self.controller.lock();
                    inner.stations.get(&station).ok_or_else(unknown_station)?.holidays.clone().unwrap_or_default()
                };
                self.holiday_payload(&station, &saved)
            }
            Route::HolidaysPut(station) => {
                self.require_station(&station)?;
                let body = Value::Object(request.json_body()?);
                let saved = self.controller.set_holidays(&station, &body).await?;
                self.holiday_payload(&station, &saved)
            }
            Route::HolidaysPreview(station) => {
                // What the calendar would look like with these settings, without saving them.
                self.require_station(&station)?;
                let body = Value::Object(request.json_body()?);
                let settings = holidays::Settings::normalize(&body).map_err(|err| Reply::error(400, &err))?;
                self.holiday_payload(&station, &settings)
            }
            Route::Log(station) => {
                self.require_station(&station)?;
                let conn = self.controller.lock().connections.get(&station).cloned();
                let frames = conn.as_ref().map(|conn| conn.frames()).unwrap_or_default();
                Ok(Reply::json(&json!({"online": conn.is_some(), "frames": frames})))
            }
            Route::OcppCall(station) => self.ocpp_call(&station, request).await,
            Route::Settings(station) => {
                self.require_station(&station)?;
                self.controller.update_settings(&station, &request.json_body()?)?;
                self.station_json(&station)
            }
            Route::DeleteStation(station) => {
                self.require_station(&station)?;
                if self.controller.is_online(&station) {
                    return Err(Reply::error(409, "station is connected; disconnect it first"));
                }
                self.controller.delete_station(&station)?;
                Ok(Reply::json(&json!({})))
            }
            Route::ClearAuthKey(station) => {
                // Needed after changing the charger's Auth key, or replacing the charger under the
                // same serial: the next connection pins its key anew.
                self.require_station(&station)?;
                self.controller.clear_auth_key(&station).await;
                Ok(Reply::json(&json!({})))
            }
        }
    }

    fn login(&self, request: &Request) -> Handled {
        let client = client_ip(request, &self.settings);
        // The body first. From here to the end nothing waits, so checking the limit, comparing and
        // recording the outcome are one step: asked before the body was read, a hundred requests
        // held open together would all have been let through before any of them had failed.
        let body = request.json_body()?;
        let mut throttle = self.auth.throttle();
        let wait = throttle.retry_after(&client, self.auth.clock());
        if wait > 0 {
            let refusal = Reply::error(429, "Too many failed sign-in attempts. Try again later.");
            return Err(refusal.with_header("retry-after", wait.to_string()));
        }
        let first = |keys: &[&str]| keys.iter().map(|key| get(&body, key)).find(|v| truthy(v)).map(to_text);
        let email = first(&["emailOrPhone", "email"]).unwrap_or_default().trim().to_lowercase();
        let password = first(&["password"]).unwrap_or_default();
        // Both comparisons always run, in constant time: nothing about the timing or the outcome
        // tells a right email from a wrong one. An empty configured password matches nothing.
        let email_ok = same_secret(Some(&email), &self.settings.api_email.trim().to_lowercase());
        let password_ok = same_secret(Some(&password), &self.settings.api_password);
        if !(email_ok && password_ok) {
            throttle.failed(&client, self.auth.clock());
            log::warn!("failed sign-in from {}", printable(&client, 64));
            return Err(Reply::error(401, "Invalid email or password"));
        }
        throttle.succeeded(&client);
        drop(throttle);
        Ok(Reply::json(&self.auth.issue()))
    }

    async fn set_mode(&self, station: &str, request: &Request) -> Handled {
        self.require_station(station)?;
        let body = request.json_body()?;
        let Some(mode) = get(&body, "mode").as_str().filter(|mode| MODES.contains(mode)) else {
            return Err(Reply::error(400, "mode must be one of ('Active', 'Inactive', 'Schedule')"));
        };
        let connector = whole(get(&body, "connectorId"), "connectorId", 0, MAX_CONNECTORS, Some(0))?;
        self.controller.set_mode(station, mode, connector).await?;
        self.station_json(station)
    }

    async fn zone_update(&self, station: &str, schedule: bool, request: &Request) -> Handled {
        self.require_station(station)?;
        let mut body = request.json_body()?;
        let Some(Value::Object(mut price)) = body.remove("price") else {
            return Err(Reply::error(400, "price object required"));
        };
        if schedule {
            price.insert("isSchedule".to_string(), Value::Bool(true));
        }
        let zone = self.controller.upsert_zone(station, &Value::Object(price)).await?;
        let inner = self.controller.lock();
        let saved = inner.stations.get(station).ok_or_else(unknown_station)?;
        let mut data = build_station(saved, inner.is_online(station), &self.settings);
        data["_id"] = get(&zone, "_id").clone(); // the HA integration reads the new schedule id from here
        data["price"] = Value::Object(zone);
        Ok(Reply::json(&data))
    }

    fn holiday_payload(&self, station_id: &str, settings: &holidays::Settings) -> Handled {
        let inner = self.controller.lock();
        let station = inner.stations.get(station_id).ok_or_else(unknown_station)?;
        let today = Utc::now().with_timezone(&station_tz(station, &self.settings)).date_naive();
        let upcoming: Vec<Value> = settings.upcoming(today, 370).iter().map(holidays::Upcoming::to_json).collect();
        Ok(Reply::json(&json!({
            "settings": settings.to_json(),
            "upcoming": upcoming,
            "today": if settings.enabled { settings.holiday_name(today) } else { None },
        })))
    }

    fn samples(&self, station: &str, request: &Request) -> Handled {
        self.require_station(station)?;
        let since = match request.query_param("since").filter(|since| !since.is_empty()) {
            Some(since) => iso(parse_iso(&since).ok_or_else(|| {
                Reply::error(400, "since must be an ISO 8601 time such as 2026-11-08T00:00:00Z")
            })?),
            None => Utc::now().format("%Y-%m-%dT00:00:00Z").to_string(),
        };
        let connector = match request.query_param("connector").filter(|connector| !connector.is_empty()) {
            Some(connector) => Some(whole(&Value::from(connector), "connector", 1, MAX_CONNECTORS, None)?),
            None => None,
        };
        let rows = self.controller.lock().store.samples(station, &since, connector, 2000).map_err(CommandError::from)?;
        Ok(Reply::json(&json!({"samples": rows})))
    }

    /// Session history for the web page: finished sessions plus the ones in progress, with totals.
    fn sessions(&self, station_id: &str, request: &Request) -> Handled {
        self.require_station(station_id)?;
        let limit = row_limit(request, 100)? as usize;
        let inner = self.controller.lock();
        let station = inner.stations.get(station_id).ok_or_else(unknown_station)?;
        let now = Utc::now();
        let mut rows = inner.store.sessions(station_id, 5000).map_err(CommandError::from)?;
        for row in &mut rows {
            let open = get(row, "stop_at").is_null();
            let id = get(row, "id").as_i64();
            let running = station
                .connectors
                .values()
                .filter_map(|connector| connector.transaction.as_ref())
                .find(|tx| open && Some(tx.id) == id);
            row.insert("active".to_string(), Value::Bool(running.is_some()));
            // never closed, e.g. lost in a restart
            row.insert("incomplete".to_string(), Value::Bool(open && running.is_none()));
            if let Some(tx) = running {
                let start = get(row, "start_at").as_str().and_then(parse_iso);
                row.insert("energy_wh".to_string(), number(tx.energy));
                row.insert("duration_s".to_string(), json!(start.map(|start| seconds_between(start, now).max(0))));
                row.insert("cost".to_string(), json!(round_to(tx.price_total, 4)));
                row.insert("price_kwh".to_string(), json!(tx.price_kw));
            }
        }
        let tz = station_tz(station, &self.settings);
        let local = now.with_timezone(&tz);
        let midnight = local.date_naive().and_time(chrono::NaiveTime::MIN);
        let today = tz.from_local_datetime(&midnight).earliest().map_or(now, |t| t.with_timezone(&Utc));
        let periods = [("today", Some(today)), ("week", Some(now - Days::days(7))), ("month", Some(now - Days::days(30))), ("all", None)];
        let mut summary = Object::new();
        for (name, since) in periods {
            let (mut energy, mut cost, mut count) = (0.0, 0.0, 0);
            for row in &rows {
                let start = get(row, "start_at").as_str().and_then(parse_iso);
                if since.is_none_or(|since| start.is_some_and(|start| start >= since)) {
                    energy += get(row, "energy_wh").as_f64().unwrap_or(0.0);
                    cost += get(row, "cost").as_f64().unwrap_or(0.0);
                    count += 1;
                }
            }
            summary.insert(name.to_string(), json!({"energy_wh": energy, "cost": round_to(cost, 4), "count": count}));
        }
        rows.truncate(limit);
        Ok(Reply::json(&json!({
            "sessions": rows,
            "summary": summary,
            "currency": station.currency,
            "timezone": station.timezone,
        })))
    }

    /// Send any OCPP call to the charger: `{"action": "GetConfiguration", "payload": {}}`.
    async fn ocpp_call(&self, station: &str, request: &Request) -> Handled {
        self.require_station(station)?;
        let body = request.json_body()?;
        let Some(action) = get(&body, "action").as_str().filter(|a| !a.is_empty() && a.chars().count() <= 64) else {
            return Err(Reply::error(400, "action required"));
        };
        let payload = match get(&body, "payload") {
            Value::Null => json!({}),
            Value::Object(payload) => Value::Object(payload.clone()),
            _ => return Err(Reply::error(400, "payload must be an object")),
        };
        let timeout = match get(&body, "timeout") {
            Value::Null => 30.0,
            Value::String(text) if text.is_empty() => 30.0,
            Value::Number(seconds) if seconds.as_f64().is_some_and(|s| s > 0.0 && s <= MAX_OCPP_CALL_TIMEOUT) => {
                seconds.as_f64().unwrap_or(30.0)
            }
            _ => return Err(Reply::error(400, "timeout must be a number of seconds, at most 120")),
        };
        match self.controller.call(station, action, payload, Some(Duration::from_secs_f64(timeout))).await {
            Ok(result) => Ok(Reply::json(&json!({"result": result}))),
            Err(err) => Err(Reply::json_status(
                502,
                &json!({"error": err.code, "description": err.description, "details": err.details}),
            )),
        }
    }

    /// Liveness for the container health check: public, so it says nothing that identifies a charger.
    ///
    /// Serials are half of a charger's identity (all of it, for one that connects without an Auth
    /// key), so the per-station list is only added for a caller who is signed in.
    fn health(&self, request: &Request) -> Reply {
        let online: Object = {
            let inner = self.controller.lock();
            inner.stations.keys().map(|id| (id.clone(), Value::Bool(inner.is_online(id)))).collect()
        };
        let mut data = json!({
            "status": "ok",
            "version": crate::VERSION,
            "time": Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string(),
            "stationCount": online.len(),
            "stationsOnline": online.values().filter(|up| up.as_bool() == Some(true)).count(),
        });
        if self.auth.valid(request.bearer()) {
            data["stations"] = Value::Object(online);
        }
        Reply::json(&data)
    }

    /// Answer the Grizzl-E firmware's third-party-OCPP "unlock" check locally.
    ///
    /// The firmware GETs `connect-api.unitedchargers.com/commercial/ext-ocpp-check/<serial>` and
    /// expects the response body to equal the lowercase-hex MD5 of `"<serial>;isUnlocked=true"`; on
    /// a match it sets its internal `isUnlocked` flag, keeping a custom OCPP backend enabled. The
    /// expected value contains no server-side secret (just the public serial + a constant), so we
    /// can return it ourselves. Reached only if `connect-api.unitedchargers.com` is DNS-overridden
    /// to this server as well (served over TLS; the charger does not verify the certificate). This
    /// endpoint is public and unauthenticated, exactly as the charger calls it.
    fn unlock_check(&self, serial: &str) -> Handled {
        // Not a serial: nothing to answer, and nothing fit to log.
        if !self.settings.ocpp_unlock || !is_charge_point_id(serial) {
            return Err(Reply::not_found());
        }
        let digest = md5_hex(format!("{serial};isUnlocked=true").as_bytes());
        log::info!("ext-ocpp-check for {serial} -> isUnlocked (served {digest})");
        Ok(Reply::text(200, &digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(Route::find("GET", "/health"), Some(Route::Health));
        assert_eq!(Route::find("HEAD", "/health"), Some(Route::Health));
        assert_eq!(Route::find("POST", "/health"), None);
        assert_eq!(Route::find("GET", "/health/"), None);
        assert_eq!(Route::find("GET", "/client/stations/GRD-1"), Some(Route::Station("GRD-1".into())));
        assert_eq!(Route::find("GET", "/client/stations//"), None);
        assert_eq!(
            Route::find("DELETE", "/client/stations/GRD-1/pricesByZoneDelete/z1"),
            Some(Route::ZoneDelete { station: "GRD-1".into(), zone: "z1".into() })
        );
        assert_eq!(
            Route::find("POST", "/client/stations/GRD-1/scheduleUpdate"),
            Some(Route::ZoneUpdate { station: "GRD-1".into(), schedule: true })
        );
        assert_eq!(Route::find("DELETE", "/local/stations/GRD-1"), Some(Route::DeleteStation("GRD-1".into())));
        assert_eq!(Route::find("GET", "/local/stations/GRD-1"), None);
        assert_eq!(Route::find("GET", "/"), None);
        assert_eq!(Route::find("GET", ""), None);
    }

    #[test]
    fn query_parameters_and_percent_decoding() {
        let request = Request { query: "limit=5&since=2026-11-08T00%3A00%3A00Z&a+b=c+d&flag".into(), ..Request::default() };
        assert_eq!(request.query_param("limit").as_deref(), Some("5"));
        assert_eq!(request.query_param("since").as_deref(), Some("2026-11-08T00:00:00Z"));
        assert_eq!(request.query_param("a b").as_deref(), Some("c d"));
        assert_eq!(request.query_param("flag").as_deref(), Some(""));
        assert_eq!(request.query_param("missing"), None);
        assert_eq!(percent_decode("GRD%2D1%zz%"), "GRD-1%zz%");
        assert_eq!(percent_decode("%ff"), "\u{fffd}");
    }

    #[test]
    fn bearer_tokens_come_from_the_header_only() {
        let with = |value: &str| Request { headers: vec![("authorization".into(), value.into())], ..Request::default() };
        assert_eq!(with("Bearer abc").bearer(), "abc");
        assert_eq!(with("bearer  abc ").bearer(), "abc");
        assert_eq!(with("Basic abc").bearer(), "");
        assert_eq!(with("Bearer").bearer(), "");
        assert_eq!(with("Bearér x").bearer(), "");
        assert_eq!(Request { query: "token=abc".into(), ..Request::default() }.bearer(), "");
    }

    #[test]
    fn whole_number_parameters() {
        let ok = |value: Value| whole(&value, "n", 0, 10, Some(7)).unwrap();
        assert_eq!(ok(json!(5)), 5);
        assert_eq!(ok(json!(5.0)), 5);
        assert_eq!(ok(json!(" 5 ")), 5);
        assert_eq!(ok(json!(null)), 7);
        assert_eq!(ok(json!("")), 7);
        for bad in [json!(11), json!(-1), json!(5.5), json!("five"), json!(true), json!([5]), json!("5.0"), json!("12345678901")] {
            let refusal = whole(&bad, "n", 0, 10, Some(7)).unwrap_err();
            assert_eq!(refusal.status, 400, "{bad}");
            assert!(String::from_utf8_lossy(&refusal.body).contains("n must be a whole number from 0 to 10"));
        }
        let missing = whole(&json!(null), "value", 0, 10, None).unwrap_err();
        assert!(String::from_utf8_lossy(&missing.body).contains("value is required"));
    }

    #[test]
    fn which_web_origins_may_use_the_api() {
        let allowed = |origin: &str, host: &str, hosts: &[&str]| {
            origin_allowed(origin, host, &hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>())
        };
        for local in [
            "http://192.168.1.5:9000",
            "http://10.0.0.2",
            "http://[fd00::1]:9000",
            "http://127.0.0.1:9000",
            "http://localhost:9000",
            "http://nas:9000",
            "http://nas.local:9000",
            "https://grizzle.home.arpa",
            "http://NAS.LAN.",
            "https://ocpp.unitedchargers.com",
            "http://100.64.1.2:9000",
        ] {
            assert!(allowed(local, "whatever:9000", &[]), "{local}");
        }
        for foreign in [
            "http://evil.example.com",
            "https://grizzle.example.com:8443",
            "http://nas.fritz.box",
            "null",
            "file://",
            "chrome-extension://abcdef",
            "",
            "http://",
            "http://8.8.8.8:9000",
            "http://[2606:4700::1111]",
            "http://local.evil.com",
            "ftp://192.168.1.5",
        ] {
            assert!(!allowed(foreign, "192.168.1.5:9000", &[]), "{foreign}");
        }
        // A public address is fine only as our own page's.
        assert!(allowed("http://8.8.8.8:9000", "8.8.8.8:9000", &[]));
        assert!(!allowed("http://8.8.8.8:9000", "8.8.4.4:9000", &[]));
        // Listed names, suffixes and the wildcard.
        assert!(allowed("https://grizzle.example.com:8443", "x", &["grizzle.example.com"]));
        assert!(!allowed("https://other.example.com", "x", &["grizzle.example.com"]));
        assert!(allowed("https://a.b.example.com", "x", &[".example.com"]));
        assert!(!allowed("https://example.com.evil.net", "x", &[".example.com"]));
        assert!(allowed("https://anything.at.all", "x", &["*"]));
        assert!(allowed("null", "x", &["*"]));
    }

    #[test]
    fn login_throttle_window_and_bounds() {
        let mut throttle = LoginThrottle::new(3, 60.0, 1000);
        assert_eq!(throttle.retry_after("10.0.0.1", 0.0), 0);
        for at in [0.0, 1.0, 2.0] {
            throttle.failed("10.0.0.1", at);
        }
        assert_eq!(throttle.retry_after("10.0.0.1", 2.0), 58);
        assert_eq!(throttle.retry_after("10.0.0.2", 2.0), 0, "another client is not affected");
        assert_eq!(throttle.retry_after("10.0.0.1", 59.5), 1);
        assert_eq!(throttle.retry_after("10.0.0.1", 60.0), 0, "the oldest failure has left the window");
        throttle.failed("10.0.0.1", 60.0);
        assert_eq!(throttle.retry_after("10.0.0.1", 60.0), 1);
        assert_eq!(throttle.retry_after("10.0.0.1", 200.0), 0);
        assert_eq!(throttle.tracked_clients(), 0, "a client whose failures have all expired is forgotten");
    }

    #[test]
    fn a_successful_login_clears_the_failures() {
        let mut throttle = LoginThrottle::new(3, 60.0, 1000);
        for at in [0.0, 1.0] {
            throttle.failed("10.0.0.1", at);
        }
        throttle.succeeded("10.0.0.1");
        throttle.failed("10.0.0.1", 2.0);
        throttle.failed("10.0.0.1", 3.0);
        assert_eq!(throttle.retry_after("10.0.0.1", 3.0), 0);
        throttle.failed("10.0.0.1", 4.0);
        assert!(throttle.retry_after("10.0.0.1", 4.0) > 0);
    }

    #[test]
    fn ipv6_clients_are_counted_by_their_prefix() {
        assert_eq!(LoginThrottle::key("192.0.2.1"), "192.0.2.1");
        assert_eq!(LoginThrottle::key("::ffff:192.0.2.1"), "192.0.2.1");
        assert_eq!(LoginThrottle::key("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        assert_eq!(LoginThrottle::key("fe80::1%eth0"), "fe80::/64");
        assert_eq!(LoginThrottle::key("?"), "?");
        let mut throttle = LoginThrottle::new(3, 60.0, 1000);
        for (n, at) in [0.0, 1.0, 2.0].into_iter().enumerate() {
            throttle.failed(&format!("2001:db8:1:2::{n}"), at);
        }
        assert!(throttle.retry_after("2001:db8:1:2:ffff::9", 2.0) > 0, "any address in the same /64 waits");
        assert_eq!(throttle.retry_after("2001:db8:1:3::1", 2.0), 0);
    }

    #[test]
    fn a_flood_from_many_addresses_closes_sign_in_except_for_known_clients() {
        let mut throttle = LoginThrottle::new(10, 300.0, 50);
        throttle.succeeded("192.168.1.10"); // the owner's usual address
        for n in 0..50 {
            throttle.failed(&format!("10.0.{}.{}", n / 250, n % 250), n as f64 * 0.1);
        }
        assert!(throttle.retry_after("10.9.9.9", 5.0) > 0, "a client never seen before has to wait");
        assert_eq!(throttle.retry_after("192.168.1.10", 5.0), 0, "the owner's address still gets in");
        assert_eq!(throttle.retry_after("10.9.9.9", 400.0), 0, "and the flood passes");
    }

    #[test]
    fn a_crowd_of_addresses_does_not_reset_a_locked_out_client() {
        let mut throttle = LoginThrottle::new(3, 300.0, 1_000_000);
        for at in [0.0, 1.0, 2.0] {
            throttle.failed("10.0.0.1", at);
        }
        assert!(throttle.retry_after("10.0.0.1", 3.0) > 0);
        for n in 0..(LoginThrottle::MAX_CLIENTS + 100) {
            throttle.failed(&format!("172.{}.{}.{}", 16 + n / 65536, (n / 256) % 256, n % 256), 3.0);
        }
        assert_eq!(throttle.tracked_clients(), LoginThrottle::MAX_CLIENTS);
        assert!(throttle.retry_after("10.0.0.1", 4.0) > 0, "the locked-out client is still locked out");
    }

    #[test]
    fn known_clients_are_bounded() {
        let mut throttle = LoginThrottle::default();
        for n in 0..(LoginThrottle::MAX_KNOWN + 10) {
            throttle.succeeded(&format!("10.1.{}.{}", n / 256, n % 256));
        }
        assert_eq!(throttle.known.len(), LoginThrottle::MAX_KNOWN);
        assert!(!throttle.known.contains_key("10.1.0.0"), "the least recently seen made room");
        assert!(throttle.known.contains_key("10.1.1.9"));
    }

    #[test]
    fn forwarded_addresses_are_believed_only_from_trusted_proxies() {
        let request = |peer: &str, forwarded: &str| Request {
            peer: Some(peer.parse().unwrap()),
            headers: vec![("x-forwarded-for".into(), forwarded.into())],
            ..Request::default()
        };
        let plain = Settings::defaults();
        assert_eq!(client_ip(&request("172.18.0.2", "203.0.113.7"), &plain), "172.18.0.2", "anyone can send the header");
        let proxied = Settings::from_pairs(&[("GRIZZLE_TRUSTED_PROXIES", "172.18.0.0/16, 10.0.0.1")]).unwrap();
        assert_eq!(client_ip(&request("172.18.0.2", "203.0.113.7"), &proxied), "203.0.113.7");
        assert_eq!(client_ip(&request("192.168.1.9", "203.0.113.7"), &proxied), "192.168.1.9", "not from the proxy");
        // Read from the right, as far as the first address that isn't one of ours.
        assert_eq!(client_ip(&request("172.18.0.2", "6.6.6.6, 203.0.113.7, 10.0.0.1"), &proxied), "203.0.113.7");
        assert_eq!(client_ip(&request("172.18.0.2", "6.6.6.6, 203.0.113.7:4711"), &proxied), "203.0.113.7");
        assert_eq!(client_ip(&request("172.18.0.2", "203.0.113.7, unknown"), &proxied), "172.18.0.2");
        assert_eq!(client_ip(&request("172.18.0.2", ""), &proxied), "172.18.0.2");
        assert_eq!(client_ip(&request("172.18.0.2", "10.0.0.1"), &proxied), "10.0.0.1", "only proxies: the last one");
        assert_eq!(client_ip(&request("::ffff:172.18.0.2", "203.0.113.7"), &proxied), "203.0.113.7");
        assert_eq!(client_ip(&Request::default(), &proxied), "?");
    }
}
