//! The brain: charger state, OCPP message handling, and local mode/schedule enforcement.
//!
//! How the Grizzl-E Connect family behaves (from evcc's and others' experience):
//! - It never starts a transaction on its own. When a car is plugged in it reports `Preparing`
//!   and waits for the server's `RemoteStartTransaction`. That is how the cloud implements the
//!   Active / Inactive / Schedule modes, and so do we.
//! - It only honours charging profiles at `stackLevel` 0 and ignores limits below ~6-7 A.
//! - Some firmware replies to `GetConfiguration` with invalid JSON; see `ocpp.rs`.
//!
//! Everything a charger sends is untrusted. Unless GRIZZLE_OCPP_PASSWORD is set, anyone who can
//! reach the port may connect as a charger the server has never seen, so each handler below takes
//! only what it understands from a message (typed, bounded) and refuses or ignores the rest.
//!
//! All state lives behind one lock, which is never held while waiting for a charger: every
//! conversation with one looks at the state, lets go, waits, and looks again.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use chrono_tz::Tz;
use indexmap::IndexMap;
use serde_json::{json, Value};
use tokio::sync::OwnedMutexGuard;
use tokio::task::{AbortHandle, JoinHandle};

use crate::config::Settings;
use crate::crypto::{random_hex, same_secret};
use crate::holidays;
use crate::logging::{printable, printable_value};
use crate::ocpp::{Connection, HandlerError, HandlerResult, OcppError};
use crate::schedules::{charging_allowed, next_change, normalize_zone, price_now, zone_id, HolidayCheck, Zone, MAX_NAME_LENGTH};
use crate::state::{
    boot_fields, clean_config, connector_count, data_transfer, Meter, Mode, Station, Transaction, MAX_CONNECTORS,
    MAX_CURRENT, MAX_TRANSACTION_ID, MAX_ZONES, MODES,
};
use crate::store::{Sample, Store};
use crate::timeutil::{iso, iso_seconds, now_iso, parse_iso, parse_iso_value, seconds_between, timestamp};
use crate::value::{clip, get, objects, reading, round_to, small_int, text, to_float, truthy, Object};

const PLUGGED_IN: [&str; 5] = ["Preparing", "Charging", "SuspendedEV", "SuspendedEVSE", "Finishing"];
const WANTS_START: [&str; 2] = ["Preparing", "SuspendedEVSE"];
const REMOTE_RETRY: Duration = Duration::from_secs(60);

/// meterValue entries handled per message (a charger sends one).
const MAX_METER_VALUES: usize = 16;
const MAX_SAMPLED_VALUES: usize = 64;
/// How long samples are kept.
const SAMPLE_DAYS: i64 = 90;

struct ModelHint {
    prefix: &'static str,
    name: &'static str,
    connectors: i64,
    max_current: i64,
    min_current: i64,
}

/// Model hints keyed by a prefix of the OCPP chargePointModel string.
const MODEL_HINTS: [ModelHint; 4] = [
    ModelHint { prefix: "GRD", name: "Grizzl-E Duo", connectors: 2, max_current: 40, min_current: 16 },
    ModelHint { prefix: "GRM", name: "Grizzl-E Mini Connect", connectors: 1, max_current: 40, min_current: 6 },
    ModelHint { prefix: "GRU", name: "Grizzl-E Ultimate", connectors: 1, max_current: 48, min_current: 6 },
    ModelHint { prefix: "GRS", name: "Grizzl-E Smart", connectors: 1, max_current: 40, min_current: 6 },
];

fn measurand_key(measurand: &str) -> Option<&'static str> {
    Some(match measurand {
        "Energy.Active.Import.Register" => "energy_wh",
        "Power.Active.Import" => "power_w",
        "Current.Import" => "current_a",
        "Current.Offered" => "current_offered_a",
        "Voltage" => "voltage_v",
        "Temperature" => "temperature_c",
        "SoC" => "soc",
        _ => return None,
    })
}

/// Why a command from the REST API was not carried out.
#[derive(Debug, Clone, PartialEq)]
pub enum CommandError {
    /// What was asked makes no sense; the message says why. Nothing was changed.
    Invalid(String),
    /// No such station, schedule or rate zone.
    NotFound,
    /// The history database refused.
    Failed(String),
}

impl From<rusqlite::Error> for CommandError {
    fn from(err: rusqlite::Error) -> CommandError {
        CommandError::Failed(err.to_string())
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, CommandError> {
    Err(CommandError::Invalid(message.into()))
}

/// A signed-in session: its refresh token and when each of the two stops working (Unix seconds).
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub refresh: String,
    pub expires: f64,
    pub refresh_expires: Option<f64>,
}

/// What a handler wants done once the state is no longer locked.
enum Effect {
    AfterBoot(String),
    Enforce(String, i64),
}

/// Everything the server knows, behind [`Controller::lock`].
pub struct Inner {
    pub stations: IndexMap<String, Station>,
    pub tokens: BTreeMap<String, Token>,
    /// The mark that tells whether saved sessions belong to today's sign-in credentials.
    pub credentials: Value,
    pub next_transaction_id: i64,
    pub store: Store,
    pub connections: HashMap<String, Arc<Connection>>,
    pub dirty: bool,
    last_pin_save: Option<Instant>,
    /// station id -> its after-boot conversation
    boot_tasks: HashMap<String, JoinHandle<()>>,
    /// station id -> its tick in flight
    station_ticks: HashMap<String, JoinHandle<()>>,
    tasks: Vec<AbortHandle>,
}

pub struct Controller {
    pub settings: Arc<Settings>,
    inner: Mutex<Inner>,
    /// charge point id -> (the lock that serialises its admissions, how many hold or await it)
    admissions: Mutex<HashMap<String, (Arc<tokio::sync::Mutex<()>>, usize)>>,
    stopping: AtomicBool,
}

/// The station's timezone; UTC (with a warning, once per name) if its name is not a zone.
pub fn station_tz(station: &Station, settings: &Settings) -> Tz {
    static UNKNOWN: Mutex<Option<HashSet<String>>> = Mutex::new(None);
    let name = if station.timezone.is_empty() { &settings.timezone } else { &station.timezone };
    name.parse().unwrap_or_else(|_| {
        let mut unknown = UNKNOWN.lock().unwrap_or_else(|e| e.into_inner());
        // Once per name: this is asked on every tick, but silently charging on UTC's clock
        // instead of the owner's is exactly the kind of thing a log should mention.
        if unknown.get_or_insert_with(HashSet::new).insert(name.clone()) {
            log::warn!(
                "{}: timezone {} is not known here; evaluating schedules and rates in UTC",
                printable(&station.id, 80),
                printable(name, 64)
            );
        }
        Tz::UTC
    })
}

fn local_now(station: &Station, settings: &Settings) -> DateTime<Tz> {
    Utc::now().with_timezone(&station_tz(station, settings))
}

/// A `date -> bool` for this station's holidays, or `None` when holidays are switched off.
fn holiday_fn(station: &Station) -> Option<impl Fn(NaiveDate) -> bool + '_> {
    let settings = station.holidays.as_ref().filter(|settings| settings.enabled)?;
    Some(move |day| settings.is_holiday(day))
}

/// The enabled charging window the connector is inside at `now`, if any.
pub fn window_now(station: &Station, now: DateTime<Tz>, cid: i64) -> Option<&Zone> {
    let holidays = holiday_fn(station);
    charging_allowed(&station.zones, now, cid, holidays.as_ref().map(|f| f as HolidayCheck<'_>))
}

/// The price per kWh at `now`: the holiday price, a rate zone's, or the base price.
pub fn price_at(station: &Station, now: DateTime<Tz>) -> Option<f64> {
    let holidays = holiday_fn(station);
    let holiday_price = station.holidays.as_ref().and_then(|settings| settings.price_kw);
    let check = holidays.as_ref().map(|f| f as HolidayCheck<'_>);
    price_now(&station.zones, now, Some(station.price_kw), check, holiday_price)
}

/// Station current limit, overridden by an active window's own limit.
///
/// The limit goes to the charger as one profile for the whole station, so when the connectors
/// are in windows with different limits it has to be the lowest of them.
pub fn effective_limit(station: &Station, settings: &Settings) -> Option<i64> {
    let now = local_now(station, settings);
    let in_force = (1..=connector_count(station))
        .filter_map(|cid| window_now(station, now, cid))
        .filter_map(|zone| reading(get(zone, "currentLimit"), false))
        .map(|limit| limit as i64)
        .min();
    in_force.or(station.current_limit)
}

/// The message's connectorId (`default` when absent or 0), refused unless it is 0..=MAX_CONNECTORS.
fn connector_id(payload: &Object, default: i64) -> Result<i64, HandlerError> {
    let raw = get(payload, "connectorId");
    let cid = if truthy(raw) { small_int(raw, 0, MAX_CONNECTORS) } else { Some(default) };
    cid.ok_or_else(|| {
        HandlerError::rejected("PropertyConstraintViolation", format!("connectorId must be 0..{MAX_CONNECTORS}"))
    })
}

fn internal(err: impl ToString) -> HandlerError {
    HandlerError::Internal(err.to_string())
}

/// Close the connector's session, if it has one: work out energy, length and cost, and record them.
fn finish_transaction(
    station: &mut Station,
    cid: i64,
    store: &mut Store,
    settings: &Settings,
    meter_stop: Option<f64>,
    reason: Option<String>,
    stopped_at: &str,
    clock_stop: Option<DateTime<Utc>>,
) -> Result<(), rusqlite::Error> {
    let tz = station_tz(station, settings);
    let Some(connector) = station.connectors.get_mut(&cid) else { return Ok(()) };
    connector.power = 0.0;
    let Some(tx) = connector.transaction.take() else { return Ok(()) };
    let mut energy = tx.energy;
    if let (Some(meter_stop), Some(meter_start)) = (meter_stop, tx.meter_start) {
        let metered = tx.energy; // what the MeterValues added up to
        let lifetime = meter_stop - meter_start; // if meterStop is the lifetime register
        energy = if meter_stop < meter_start {
            meter_stop // can only be session-relative, like this firmware's MeterValues
        } else if metered > 0.0 && (meter_stop - metered).abs() < (lifetime - metered).abs() {
            // Not smaller than meterStart, yet it continues the session-relative readings we
            // have been following: a session that delivered more than the register started at.
            meter_stop
        } else {
            lifetime
        };
        connector.total_energy_wh = Some(meter_start + energy);
    }
    let start = tx.start_at.as_deref().and_then(parse_iso);
    let stop = parse_iso(stopped_at);
    let mut duration = match (start, stop) {
        (Some(start), Some(stop)) => Some(seconds_between(start, stop).max(0)),
        _ => None,
    };
    if let (Some(clock_start), Some(clock_stop)) = (tx.clock_start.as_deref().and_then(parse_iso), clock_stop) {
        if clock_stop >= clock_start {
            // Both ends as the charger's clock read them. For a charger whose clock was never set
            // (1970) and which reports a session after the fact, our own timestamps for the two
            // messages are milliseconds apart; its clock still measured the session correctly.
            duration = Some(seconds_between(clock_start, clock_stop));
        }
    }
    let mut cost = tx.price_total;
    // Cost builds up with each MeterValues reading. What was delivered after the last one (all
    // of it, if none arrived) is in the final energy but was never priced: do that now, the
    // way recalculating does, at the price in force at the end of the session (at its start
    // when there were no readings at all).
    let unpriced = energy - tx.last_session_energy;
    let mut last_session = tx.to_json();
    let tid = tx.id;
    if unpriced > 0.0 {
        let metered = tx.session_relative_register.is_some();
        let moment = if metered { stop.or(start) } else { start.or(stop) };
        let price = moment.and_then(|moment| price_at(station, moment.with_timezone(&tz)));
        cost += unpriced / 1000.0 * price.unwrap_or(0.0);
    }
    store.finish_session(
        tid,
        stopped_at,
        meter_stop.map(|stop| stop as i64),
        Some(energy),
        duration,
        Some(cost),
        reason.as_deref(),
        (energy > 0.0).then(|| cost / (energy / 1000.0)), // the average price, as recalculating records it
    )?;
    last_session["energy"] = json!(energy);
    last_session["priceTotal"] = json!(cost);
    last_session["stopAt"] = json!(stopped_at);
    last_session["duration"] = json!(duration);
    last_session["reason"] = json!(reason);
    if let Some(connector) = station.connectors.get_mut(&cid) {
        connector.last_session = Some(last_session);
    }
    log::info!(
        "{} connector {}: transaction {} stopped ({} Wh, {})",
        station.id,
        cid,
        tid,
        energy,
        reason.as_deref().map_or("None".to_string(), |reason| printable(reason, 50))
    );
    Ok(())
}

/// Take one meterValue into the connector's state; returns the history row to store, if any.
fn apply_meter_values(
    station: &mut Station,
    cid: i64,
    settings: &Settings,
    mv: &Object,
    tid: Option<i64>,
) -> Option<Sample> {
    let at = timestamp(get(mv, "timestamp"));
    let mut values = Meter::default();
    for sv in objects(get(mv, "sampledValue"), MAX_SAMPLED_VALUES) {
        let key = match get(sv, "measurand") {
            Value::String(measurand) if !measurand.is_empty() => measurand_key(measurand),
            other if !truthy(other) => Some("energy_wh"),
            _ => None,
        };
        let (Some(key), Some(mut value)) = (key, reading(get(sv, "value"), true)) else { continue };
        let unit = get(sv, "unit").as_str();
        if matches!((key, unit), ("energy_wh", Some("kWh")) | ("power_w", Some("kW"))) {
            value *= 1000.0;
        }
        let field = values.field_mut(key).expect("a key from measurand_key");
        *field = match *field {
            // keep the hottest phase; Grizzl-E is single phase anyway
            Some(earlier) if truthy(get(sv, "phase")) => Some(earlier.max(value)),
            _ => Some(value),
        };
    }
    if values.is_empty() {
        return None;
    }
    values.at = Some(at.clone());
    let in_session = station.connectors.get(&cid).is_some_and(|c| c.transaction.is_some());
    let price = (in_session && values.energy_wh.is_some())
        .then(|| price_at(station, local_now(station, settings)).unwrap_or(0.0));
    let connector = station.connectors.get_mut(&cid)?;
    connector.last_meter.update(&values);
    if let Some(power) = values.power_w {
        connector.power = power;
    }
    // What goes into the history is the lifetime register, whichever way the charger counts.
    let mut history_energy = values.energy_wh;
    let mut session_id = None;
    if let Some(tx) = connector.transaction.as_mut() {
        session_id = Some(tx.id);
        tx.meter.update(&values);
        if let Some(power) = values.power_w {
            tx.power = power;
        }
        if let (Some(register), Some(price)) = (values.energy_wh, price) {
            let meter_start = *tx.meter_start.get_or_insert(register);
            // Grizzl-E firmware reports Energy.Active.Import.Register relative to the start of
            // the session in MeterValues (it restarts at 0), while StartTransaction.meterStart is
            // the lifetime register. Detect which one we got, once: decided again on every
            // frame, a session-relative register that grows past meterStart (a long session on
            // a nearly new charger) would suddenly be read as the lifetime one, and the
            // session's energy would drop back to nearly nothing.
            let session_relative = tx.session_relative_register.unwrap_or_else(|| {
                // A reading just under meterStart is the lifetime register reported more
                // coarsely than meterStart was (kWh with a decimal or two), not a session
                // that happens to have delivered almost exactly the charger's lifetime total.
                let shortfall = meter_start - register;
                shortfall > 1000f64.min(meter_start.abs() * 0.01)
            });
            let session_energy = if session_relative { register } else { register - meter_start };
            let previous = tx.last_session_energy;
            tx.session_relative_register = Some(session_relative);
            tx.energy = session_energy.max(0.0);
            let total = meter_start + tx.energy;
            connector.total_energy_wh = Some(total);
            history_energy = Some(total);
            let delta_kwh = (tx.energy - previous).max(0.0) / 1000.0;
            tx.price_kw = Some(price);
            tx.price_total += delta_kwh * price;
            tx.last_session_energy = tx.energy;
        }
    } else if let Some(register) = values.energy_wh {
        if connector.total_energy_wh.unwrap_or(0.0) <= register {
            connector.total_energy_wh = Some(register);
        }
    }
    Some(Sample {
        station: station.id.clone(),
        connector: cid,
        transaction_id: tid.or(session_id),
        at,
        energy_wh: history_energy,
        power_w: values.power_w,
        current_a: values.current_a,
        voltage_v: values.voltage_v,
        temperature_c: values.temperature_c,
        soc: values.soc,
    })
}

/// Apply a message's meterValue list (bounded) and store its samples in one transaction.
fn take_meter_values(
    station: &mut Station,
    cid: i64,
    store: &mut Store,
    settings: &Settings,
    items: &Value,
    tid: Option<i64>,
) -> Result<(), rusqlite::Error> {
    let rows: Vec<Sample> = objects(items, MAX_METER_VALUES)
        .into_iter()
        .filter_map(|mv| apply_meter_values(station, cid, settings, mv, tid))
        .collect();
    store.add_samples(&rows)
}

/// Pick up what the charger tells us about itself (seen on a Duo, firmware UDGRW070L-04.03.2).
fn learn_from_config(station: &mut Station) {
    let dip = small_int(get(&station.config, "DipSwitchCurrentLimit"), 1, MAX_CURRENT);
    if dip.is_some() {
        station.dip_switch_current_limit = dip;
    }
    let reported = get(&station.config, "NumberOfConnectors").clone();
    let connectors = small_int(&reported, 1, MAX_CONNECTORS);
    if connectors.is_none() && truthy(&reported) {
        log::warn!(
            "{}: ignoring NumberOfConnectors={} (expected 1..{})",
            station.id,
            printable_value(&reported, 40),
            MAX_CONNECTORS
        );
    }
    if let Some(connectors) = connectors.filter(|_| !station.model_locked) {
        station.connector_count = connectors;
        station.ensure_connectors();
    }
    if let Some(tag) = get(&station.config, "AuthTag").as_str().filter(|t| !t.is_empty() && t.chars().count() <= 64) {
        station.id_tag = Some(tag.to_string());
    }
}

/// Cost of a session under today's rates: each slice of energy at the price in force when it was metered.
///
/// Samples hold either the lifetime register or energy since the session started (the Duo's
/// firmware does the latter); both are reduced to "Wh so far". Energy the samples don't account
/// for, such as the tail before StopTransaction or a session whose samples have been pruned, is
/// priced at the end (or, with no samples at all, the start) of the session.
fn reprice(
    station: &Station,
    tz: Tz,
    meter_start: Option<f64>,
    total_wh: f64,
    samples: &[(String, f64)],
    start_at: Option<&str>,
    end_at: Option<&str>,
) -> f64 {
    let price_of = |stamp: Option<&str>| -> f64 {
        stamp.and_then(parse_iso).and_then(|moment| price_at(station, moment.with_timezone(&tz))).unwrap_or(0.0)
    };
    let (mut cost, mut counted) = (0.0, 0.0);
    for (at, reading) in samples {
        let so_far = match meter_start {
            Some(base) if *reading >= base => reading - base,
            _ => *reading,
        }
        .min(total_wh);
        if so_far > counted {
            cost += (so_far - counted) / 1000.0 * price_of(Some(at));
            counted = so_far;
        }
    }
    if total_wh > counted {
        let stamp = if samples.is_empty() { start_at } else { end_at.or(start_at) };
        cost += (total_wh - counted) / 1000.0 * price_of(stamp);
    }
    cost
}

impl Inner {
    fn ensure_station(&mut self, settings: &Settings, station_id: &str) -> &mut Station {
        if !self.stations.contains_key(station_id) {
            self.stations.insert(station_id.to_string(), Station::new(station_id, settings));
            self.dirty = true;
        }
        let station = &mut self.stations[station_id];
        station.ensure_connectors();
        station
    }

    pub fn is_online(&self, station_id: &str) -> bool {
        self.connections.get(station_id).is_some_and(|conn| !conn.is_closed())
    }

    /// The next transaction id; counts on from the history as well as from the saved counter.
    fn allocate_transaction_id(&mut self) -> i64 {
        let tid = self.store.unused_id(self.next_transaction_id);
        self.next_transaction_id = tid + 1;
        tid
    }

    /// The state as it is written to state.json.
    pub fn to_json(&self) -> Value {
        let stations: Object = self.stations.iter().map(|(id, station)| (id.clone(), station.to_json())).collect();
        let tokens: Object = self
            .tokens
            .iter()
            .map(|(token, info)| {
                let info = json!({"refresh": info.refresh, "expires": info.expires, "refreshExpires": info.refresh_expires});
                (token.clone(), info)
            })
            .collect();
        let mut state = json!({
            "stations": stations,
            "tokens": tokens,
            "next_transaction_id": self.next_transaction_id,
        });
        if !self.credentials.is_null() {
            state["credentials"] = self.credentials.clone();
        }
        state
    }

    /// Write the state if it changed. Never fails: a failed save is logged and retried later.
    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        if let Err(err) = self.store.write_state(&self.to_json()) {
            self.dirty = true; // keep running; try again on the next tick
            log::error!("saving state failed: {err}");
        }
    }

    // --- inbound OCPP --------------------------------------------------------

    fn handle(&mut self, settings: &Settings, station_id: &str, action: &str, payload: &Object) -> (HandlerResult, Vec<Effect>) {
        self.ensure_station(settings, station_id).last_seen = Some(now_iso());
        let mut effects = Vec::new();
        let result = match action {
            "BootNotification" => self.on_boot_notification(settings, station_id, payload, &mut effects),
            "Heartbeat" => Ok(json!({"currentTime": now_iso()})),
            "StatusNotification" => self.on_status_notification(settings, station_id, payload, &mut effects),
            "Authorize" => Ok(json!({"idTagInfo": {"status": "Accepted"}})),
            "StartTransaction" => self.on_start_transaction(settings, station_id, payload),
            "StopTransaction" => self.on_stop_transaction(settings, station_id, payload),
            "MeterValues" => self.on_meter_values(settings, station_id, payload),
            "DataTransfer" => self.on_data_transfer(station_id, payload),
            "DiagnosticsStatusNotification" => {
                self.stations[station_id].diagnostics_status = text(get(payload, "status"), 32);
                Ok(json!({}))
            }
            "FirmwareStatusNotification" => {
                self.stations[station_id].firmware_status = text(get(payload, "status"), 32);
                Ok(json!({}))
            }
            _ => {
                log::info!(
                    "{}: unhandled {} {}",
                    station_id,
                    printable(action, 64),
                    printable_value(&Value::Object(payload.clone()), 300)
                );
                return (Err(HandlerError::NotImplemented), effects);
            }
        };
        if result.is_ok() {
            self.dirty = true;
        }
        (result, effects)
    }

    fn on_boot_notification(
        &mut self,
        settings: &Settings,
        station_id: &str,
        payload: &Object,
        effects: &mut Vec<Effect>,
    ) -> HandlerResult {
        let station = &mut self.stations[station_id];
        station.boot = boot_fields(payload, Some(now_iso()));
        let model = get(&station.boot, "chargePointModel").as_str().unwrap_or_default().to_string();
        let hint = MODEL_HINTS.iter().find(|hint| model.to_uppercase().starts_with(hint.prefix));
        station.model_code = model.clone();
        match hint {
            Some(hint) => {
                station.model_name = hint.name.to_string();
                if !station.model_locked {
                    station.connector_count = connector_count(station).max(hint.connectors);
                    station.max_current = hint.max_current;
                    station.min_current = hint.min_current;
                }
            }
            None => station.model_name = if model.is_empty() { "Grizzl-E".to_string() } else { model.clone() },
        }
        station.ensure_connectors();
        for connector in station.connectors.values_mut() {
            connector.last_remote_start = None;
        }
        station.applied_limit = None; // profiles may not survive a reboot
        log::info!(
            "{} booted: {} fw {}",
            station_id,
            printable(&model, 100),
            printable_value(get(&station.boot, "firmwareVersion"), 100)
        );
        effects.push(Effect::AfterBoot(station_id.to_string()));
        Ok(json!({"status": "Accepted", "currentTime": now_iso(), "interval": settings.heartbeat_interval}))
    }

    fn on_status_notification(
        &mut self,
        settings: &Settings,
        station_id: &str,
        payload: &Object,
        effects: &mut Vec<Effect>,
    ) -> HandlerResult {
        let cid = connector_id(payload, 0)?;
        let status = match get(payload, "status") {
            Value::String(status) if !status.is_empty() => clip(status, 32).to_string(),
            _ => return Err(HandlerError::rejected("TypeConstraintViolation", "status must be a string")),
        };
        let error_code = text(get(payload, "errorCode"), 50).filter(|c| !c.is_empty()).unwrap_or_else(|| "NoError".into());
        let station = &mut self.stations[station_id];
        if cid == 0 {
            station.status = Some(status);
            station.error_code = Some(error_code);
            return Ok(json!({}));
        }
        let connector = station.ensure_connector(cid).map_err(internal)?;
        if connector.status.as_deref() != Some(status.as_str()) {
            connector.status_changed_at = Some(timestamp(get(payload, "timestamp")));
            log::info!(
                "{} connector {}: {} -> {}",
                station_id,
                cid,
                connector.status.as_deref().map_or("None".to_string(), |s| printable(s, 32)),
                printable(&status, 32)
            );
        }
        connector.status = Some(status.clone());
        connector.error_code = Some(error_code);
        connector.vendor_error_code = text(get(payload, "vendorErrorCode"), 50);
        connector.info = text(get(payload, "info"), 255);
        if status == "Available" {
            connector.power = 0.0;
            if !connector.last_meter.is_empty() {
                // no MeterValues arrive while idle, so don't show the last session's draw
                connector.last_meter.current_a = Some(0.0);
                connector.last_meter.power_w = Some(0.0);
            }
            if connector.transaction.is_some() {
                // Missed the StopTransaction; close the session so state doesn't stick.
                let reason = Some("Available".to_string());
                finish_transaction(station, cid, &mut self.store, settings, None, reason, &now_iso(), None)
                    .map_err(internal)?;
            }
        }
        effects.push(Effect::Enforce(station_id.to_string(), cid));
        Ok(json!({}))
    }

    fn on_start_transaction(&mut self, settings: &Settings, station_id: &str, payload: &Object) -> HandlerResult {
        let cid = connector_id(payload, 1)?.max(1);
        let id_tag = text(get(payload, "idTag"), 64);
        let started = timestamp(get(payload, "timestamp"));
        let meter_start = reading(get(payload, "meterStart"), false);
        let clock_start = parse_iso_value(get(payload, "timestamp")).filter(|clock| clock.year() >= 1970).map(iso);
        let station = &mut self.stations[station_id];
        let open = station.ensure_connector(cid).map_err(internal)?.transaction.as_ref();
        if let Some(open) = open {
            // Compared by what the charger's clock said, not by the time we recorded: a charger
            // whose clock was never set gets "now" as the start each time it repeats itself.
            let same = open.clock_start == clock_start && open.meter_start == meter_start && open.id_tag == id_tag;
            if same && clock_start.is_some() {
                // The same StartTransaction again: the charger never saw our answer and, as OCPP
                // asks, repeats the request. Give it the same transaction, not a second session.
                return Ok(json!({"transactionId": open.id, "idTagInfo": {"status": "Accepted"}}));
            }
            // A different session on a connector that still has one open: the old one is over,
            // whether or not we were told. Close it, or it stays "not closed" in the history forever.
            let reason = Some("Superseded".to_string());
            finish_transaction(station, cid, &mut self.store, settings, None, reason, &started, None).map_err(internal)?;
        }
        let tid = self.allocate_transaction_id();
        let station = &mut self.stations[station_id];
        let price = price_at(station, local_now(station, settings));
        let connector = station.ensure_connector(cid).map_err(internal)?;
        connector.transaction = Some(Transaction {
            id: tid,
            id_tag: id_tag.clone(),
            start_at: Some(started.clone()),
            clock_start,
            meter_start,
            energy: 0.0,
            power: 0.0,
            meter: Meter::default(),
            price_kw: price,
            price_total: 0.0,
            last_session_energy: 0.0,
            session_relative_register: None,
            duration: None,
        });
        connector.power = 0.0;
        self.store
            .start_session(tid, station_id, cid, id_tag.as_deref(), &started, meter_start.map(|m| m as i64), price)
            .map_err(internal)?;
        log::info!(
            "{} connector {}: transaction {} started (meter {} Wh)",
            station_id,
            cid,
            tid,
            meter_start.map_or("None".to_string(), |m| m.to_string())
        );
        Ok(json!({"transactionId": tid, "idTagInfo": {"status": "Accepted"}}))
    }

    fn on_stop_transaction(&mut self, settings: &Settings, station_id: &str, payload: &Object) -> HandlerResult {
        let tid = small_int(get(payload, "transactionId"), 1, MAX_TRANSACTION_ID);
        let station = &mut self.stations[station_id];
        let cid = tid.and_then(|tid| {
            station.connectors.values().find(|c| c.transaction.as_ref().is_some_and(|tx| tx.id == tid)).map(|c| c.id)
        });
        let Some(cid) = cid else {
            log::warn!(
                "{}: StopTransaction for unknown transaction {}",
                station_id,
                printable_value(get(payload, "transactionId"), 40)
            );
            return Ok(json!({"idTagInfo": {"status": "Accepted"}}));
        };
        finish_transaction(
            station,
            cid,
            &mut self.store,
            settings,
            reading(get(payload, "meterStop"), false),
            text(get(payload, "reason"), 50),
            &timestamp(get(payload, "timestamp")),
            parse_iso_value(get(payload, "timestamp")),
        )
        .map_err(internal)?;
        // transactionData may carry final meter values. They are taken after the session is closed
        // on purpose: its begin/end readings can be the lifetime register even where MeterValues
        // count from zero, and must not be mistaken for the session's energy. Filed under the
        // session's id they are still there for repricing, which copes with either convention.
        take_meter_values(station, cid, &mut self.store, settings, get(payload, "transactionData"), tid)
            .map_err(internal)?;
        Ok(json!({"idTagInfo": {"status": "Accepted"}}))
    }

    fn on_meter_values(&mut self, settings: &Settings, station_id: &str, payload: &Object) -> HandlerResult {
        let cid = connector_id(payload, 1)?.max(1);
        let station = &mut self.stations[station_id];
        station.ensure_connector(cid).map_err(internal)?;
        let tid = small_int(get(payload, "transactionId"), 1, MAX_TRANSACTION_ID);
        take_meter_values(station, cid, &mut self.store, settings, get(payload, "meterValue"), tid).map_err(internal)?;
        Ok(json!({}))
    }

    fn on_data_transfer(&mut self, station_id: &str, payload: &Object) -> HandlerResult {
        log::info!("{}: DataTransfer {}", station_id, printable_value(&Value::Object(payload.clone()), 300));
        let station = &mut self.stations[station_id];
        station.data_transfers.push(data_transfer(payload, Some(now_iso())));
        let excess = station.data_transfers.len().saturating_sub(20);
        station.data_transfers.drain(..excess);
        Ok(json!({"status": "Accepted"}))
    }

    // --- who may connect ------------------------------------------------------

    /// The refusal for a never-seen serial when no more stations may be added, else `None`.
    fn full(&self, settings: &Settings, cp_id: &str) -> Option<(u16, String)> {
        if self.stations.contains_key(cp_id) || self.stations.len() < settings.max_stations {
            return None;
        }
        Some((
            503,
            format!(
                "this would be station number {} and GRIZZLE_MAX_STATIONS is {}; delete stations you don't use \
                 (DELETE /local/stations/<serial>) or raise the limit",
                self.stations.len() + 1,
                settings.max_stations
            ),
        ))
    }

    /// Store the Auth key the charger presented (for pinning and firmware_capture); true if changed.
    ///
    /// The admission check has already accepted this key, so an existing pin is never replaced
    /// by a different one. An empty or missing key never wipes a stored one.
    fn record_auth_key(station: &mut Station, settings: &Settings, auth_key: Option<&str>) -> bool {
        let Some(auth_key) = auth_key.filter(|key| !key.is_empty()) else {
            if station.ocpp_auth_key.is_none() {
                // Remember this station connects without a key, so a key presented later (by
                // anyone, while it's offline) isn't pinned and doesn't lock the charger out.
                station.ocpp_keyless = true;
            }
            return false;
        };
        if settings.ocpp_password.is_some() {
            // Authenticated by the shared password; keep the recorded key current.
            let changed = station.ocpp_auth_key.as_deref() != Some(auth_key);
            station.ocpp_auth_key = Some(auth_key.to_string());
            return changed;
        }
        if station.ocpp_auth_key.is_some() {
            return false;
        }
        if station.ocpp_keyless {
            log::warn!(
                "{} presented an Auth key but has connected without one before; not pinning it \
                 (DELETE /local/stations/{}/auth-key to let the next key be pinned)",
                station.id,
                station.id
            );
            return false;
        }
        station.ocpp_auth_key = Some(auth_key.to_string());
        log::info!("{}: pinned to the Auth key it presented", station.id);
        true
    }
}

/// Holds a charge point id's admission lock; see [`Controller::admission`].
pub struct Admission<'a> {
    controller: &'a Controller,
    id: String,
    guard: Option<OwnedMutexGuard<()>>,
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.guard.take();
        let mut admissions = self.controller.admissions.lock().unwrap_or_else(|e| e.into_inner());
        // Drop the entry only when nobody holds or awaits it.
        if let Some((_, users)) = admissions.get_mut(&self.id) {
            *users -= 1;
            if *users == 0 {
                admissions.remove(&self.id);
            }
        }
    }
}

impl Controller {
    /// A controller over what `store` holds. `saved` is the content of state.json.
    pub fn new(settings: Arc<Settings>, store: Store, saved: Object) -> Arc<Controller> {
        let mut stations = IndexMap::new();
        for (station_id, station) in get(&saved, "stations").as_object().into_iter().flatten() {
            match station.as_object().filter(|_| !station_id.is_empty()) {
                Some(station) => {
                    stations.insert(station_id.clone(), Station::from_saved(station_id, station, &settings));
                }
                None => log::warn!("dropping unreadable station entry {} from the saved state", printable(station_id, 80)),
            }
        }
        let mut tokens = BTreeMap::new();
        for (token, info) in get(&saved, "tokens").as_object().into_iter().flatten() {
            let Some(info) = info.as_object() else { continue };
            let refresh_expires = get(info, "refreshExpires");
            if let (Some(refresh), Some(expires), true) = (
                get(info, "refresh").as_str(),
                get(info, "expires").as_f64(),
                refresh_expires.is_null() || refresh_expires.is_number(),
            ) {
                let info = Token { refresh: refresh.to_string(), expires, refresh_expires: refresh_expires.as_f64() };
                tokens.insert(token.clone(), info);
            }
        }
        let counter = get(&saved, "next_transaction_id").as_i64().unwrap_or(1);
        let next_transaction_id = store.unused_id(counter);
        Arc::new(Controller {
            settings,
            inner: Mutex::new(Inner {
                stations,
                tokens,
                credentials: get(&saved, "credentials").clone(),
                next_transaction_id,
                store,
                connections: HashMap::new(),
                dirty: false,
                last_pin_save: None,
                boot_tasks: HashMap::new(),
                station_ticks: HashMap::new(),
                tasks: Vec::new(),
            }),
            admissions: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
        })
    }

    /// Open the data directory the settings name and start from what it holds.
    pub fn open(settings: Arc<Settings>) -> Result<Arc<Controller>, String> {
        let (store, saved) = Store::open(&settings.data_dir)?;
        Ok(Controller::new(settings, store, saved))
    }

    /// The state. Never held across an `.await`.
    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        // A handler that panicked did so in the middle of one message; the state is still usable.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn is_online(&self, station_id: &str) -> bool {
        self.lock().is_online(station_id)
    }

    pub fn mark_dirty(&self) {
        self.lock().dirty = true;
    }

    /// Write the state if it changed. Never fails: a failed save is logged and retried later.
    pub fn save(&self) {
        self.lock().save();
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Start a background task, kept track of so that stopping can cancel whatever is still
    /// talking to a charger. Not to be called with the state locked.
    fn spawn(self: &Arc<Self>, task: impl Future<Output = ()> + Send + 'static) -> JoinHandle<()> {
        let handle = tokio::spawn(task);
        let mut inner = self.lock();
        inner.tasks.retain(|task| !task.is_finished());
        inner.tasks.push(handle.abort_handle());
        handle
    }

    // --- connection lifecycle ------------------------------------------------

    /// Serialise the admission check and the registration per charge point id.
    ///
    /// Both the liveness probe and the WebSocket handshake wait, so without this two handshakes
    /// for the same id could both pass the check (say, two first connections with different keys)
    /// and the later one would replace the earlier one despite the pin the earlier one set.
    pub async fn admission(&self, cp_id: &str) -> Admission<'_> {
        let lock = {
            let mut admissions = self.admissions.lock().unwrap_or_else(|e| e.into_inner());
            let entry = admissions.entry(cp_id.to_string()).or_insert_with(|| (Arc::default(), 0));
            entry.1 += 1;
            entry.0.clone()
        };
        // Counted from here on, so that a handshake abandoned while it waits is uncounted again.
        let mut admission = Admission { controller: self, id: cp_id.to_string(), guard: None };
        admission.guard = Some(lock.lock_owned().await);
        admission
    }

    /// Decide whether a charger may connect as `cp_id`; (HTTP status, reason) if not.
    ///
    /// - With GRIZZLE_ALLOWED_CHARGERS set, only the serials listed there are considered at all.
    ///   That keeps other serials out; it is the checks below that keep someone else from being
    ///   taken for a listed one, since a serial is no secret.
    /// - With GRIZZLE_OCPP_PASSWORD set, the Basic password must match it and no per-station pin
    ///   is consulted (so changing the password never collides with one). The key presented is
    ///   still recorded, and is the station's pin if the password is later unset.
    /// - Otherwise a station is pinned to the first Auth key it presents (trust on first use):
    ///   any other key, or none, is refused. Clear the pin with DELETE /local/stations/{id}/auth-key.
    /// - A connection that proves nothing (no password, nothing pinned) may create a new station,
    ///   and may replace a station's existing connection only if that one no longer answers.
    /// - A serial nobody has seen is a new station, and there may only be GRIZZLE_MAX_STATIONS of
    ///   those: whoever can reach the port can invent serials, and each one is kept.
    /// - Nobody is admitted while the server is shutting down. The check can wait seconds for a
    ///   liveness probe; a handshake let in after stop() has closed "every" connection would be
    ///   the one nobody closes.
    pub async fn connection_refusal(&self, cp_id: &str, auth_key: Option<&str>) -> Option<(u16, String)> {
        let refusal = self.refusal(cp_id, auth_key).await;
        if refusal.is_none() && self.is_stopping() {
            return Some((503, "the server is shutting down".to_string()));
        }
        refusal
    }

    async fn refusal(&self, cp_id: &str, auth_key: Option<&str>) -> Option<(u16, String)> {
        let settings = &self.settings;
        if let Some(password) = &settings.ocpp_password {
            if !same_secret(auth_key, password) {
                return Some((401, "wrong OCPP password (GRIZZLE_OCPP_PASSWORD)".to_string()));
            }
        }
        if !settings.allowed_chargers.is_empty() && !settings.allowed_chargers.iter().any(|serial| serial == cp_id) {
            // Answered like a wrong key or password (401). That hides the list only from someone
            // who could not get in anyway: with GRIZZLE_OCPP_PASSWORD set, or for a serial whose key
            // is pinned, listed and unlisted serials get the same reply. Without either, a listed
            // serial is let in (or gets 409 or 503), which tells them apart.
            let why = "its serial is not in GRIZZLE_ALLOWED_CHARGERS; add it there to let this charger connect";
            return Some((401, why.to_string()));
        }
        {
            let inner = self.lock();
            if settings.ocpp_password.is_some() {
                return inner.full(settings, cp_id);
            }
            if let Some(pinned) = inner.stations.get(cp_id).and_then(|station| station.ocpp_auth_key.as_deref()) {
                if !same_secret(auth_key, pinned) {
                    return Some((
                        401,
                        format!(
                            "Auth key does not match the one this charger registered with; if you changed it, \
                             clear the old one with DELETE /local/stations/{cp_id}/auth-key"
                        ),
                    ));
                }
                return None;
            }
            if let Some(full) = inner.full(settings, cp_id) {
                return Some(full);
            }
        }
        if self.answers(cp_id).await {
            let why = "already connected and still answering; an unauthenticated connection may not replace it";
            return Some((409, why.to_string()));
        }
        None
    }

    /// True if the station's current connection replies to a harmless call in time.
    ///
    /// A charger that reconnects doesn't close its old socket first, so a dead socket can look
    /// online for minutes; probing tells a stale socket (replace it) from a live one (keep it).
    async fn answers(&self, cp_id: &str) -> bool {
        let Some(conn) = self.lock().connections.get(cp_id).cloned().filter(|conn| !conn.is_closed()) else {
            return false;
        };
        match conn.call("TriggerMessage", json!({"requestedMessage": "Heartbeat"}), Some(self.settings.liveness_timeout)).await {
            Ok(_) => true,
            // A CallError reply still proves someone is answering; a timeout or a drop doesn't.
            Err(err) => !matches!(err.code.as_str(), "Timeout" | "Disconnected") && !conn.is_closed(),
        }
    }

    /// Register an admitted connection as the station's (replacing, and closing, an earlier one).
    pub fn on_connect(self: &Arc<Self>, conn: Arc<Connection>, handshake: Option<Value>, auth_key: Option<&str>) {
        let old = {
            let mut inner = self.lock();
            let old = inner.connections.insert(conn.id.clone(), conn.clone());
            let station = inner.ensure_station(&self.settings, &conn.id);
            station.last_seen = Some(now_iso());
            if handshake.is_some() {
                station.ocpp_handshake = handshake;
            }
            let pinned = Inner::record_auth_key(station, &self.settings, auth_key);
            inner.dirty = true;
            if pinned && inner.last_pin_save.is_none_or(|at| at.elapsed() > Duration::from_secs(1)) {
                // Don't leave a fresh pin waiting for the next tick (a crash would lose it). At most
                // once a second, so a flood of new serials can't force a full save per handshake.
                inner.last_pin_save = Some(Instant::now());
                inner.save(); // logs a failure instead of failing: a full disk must not refuse the charger
            }
            old
        };
        log::info!("{} connected", conn.id);
        if let Some(old) = old.filter(|old| !Arc::ptr_eq(old, &conn)) {
            // A reconnecting charger doesn't close its old socket first.
            self.spawn(async move { old.close().await });
        }
    }

    /// Forget the pinned key and drop the live connection, so the charger's reconnect pins anew.
    pub async fn clear_auth_key(&self, station_id: &str) {
        let conn = {
            let mut inner = self.lock();
            let Some(station) = inner.stations.get_mut(station_id) else { return };
            station.ocpp_auth_key = None;
            station.ocpp_keyless = false;
            inner.dirty = true;
            inner.save();
            inner.connections.get(station_id).cloned()
        };
        log::warn!("{station_id}: pinned OCPP Auth key cleared; the next connection will pin a new one");
        if let Some(conn) = conn {
            conn.close().await;
        }
    }

    pub fn on_disconnect(&self, conn: &Arc<Connection>) {
        let mut inner = self.lock();
        if inner.connections.get(&conn.id).is_some_and(|current| Arc::ptr_eq(current, conn)) {
            inner.connections.remove(&conn.id);
            log::info!("{} disconnected", conn.id);
            if let Some(station) = inner.stations.get_mut(&conn.id) {
                station.last_seen = Some(now_iso());
                inner.dirty = true;
            }
        }
    }

    /// Answer a charger's Call. Whatever follows from it (configuring the charger after a boot,
    /// starting a session for a car that was just plugged in) happens afterwards, on its own.
    pub fn handle(self: &Arc<Self>, station_id: &str, action: &str, payload: &Object) -> HandlerResult {
        let (result, effects) = self.lock().handle(&self.settings, station_id, action, payload);
        for effect in effects {
            match effect {
                Effect::Enforce(station_id, cid) => {
                    let controller = self.clone();
                    self.spawn(async move { controller.enforce(&station_id, cid).await });
                }
                Effect::AfterBoot(station_id) => {
                    // One after-boot conversation per station: a charger that repeats BootNotification
                    // must not be able to pile up tasks (each of which sends it half a dozen calls).
                    let controller = self.clone();
                    let id = station_id.clone();
                    let task = self.spawn(async move { controller.after_boot(&id).await });
                    if let Some(previous) = self.lock().boot_tasks.insert(station_id, task) {
                        previous.abort();
                    }
                }
            }
        }
        result
    }

    // --- outbound OCPP -------------------------------------------------------

    /// Send a Call to a station's charger and wait for the answer.
    pub async fn call(
        &self,
        station_id: &str,
        action: &str,
        payload: Value,
        timeout: Option<Duration>,
    ) -> Result<Object, OcppError> {
        let conn = self.lock().connections.get(station_id).cloned().filter(|conn| !conn.is_closed());
        match conn {
            Some(conn) => conn.call(action, payload, timeout).await,
            None => Err(OcppError::new("Offline", &format!("{station_id} is not connected"))),
        }
    }

    /// Configure the charger the way the cloud does, then apply our settings.
    async fn after_boot(&self, station_id: &str) {
        tokio::time::sleep(self.settings.boot_delay).await;
        if !self.lock().stations.contains_key(station_id) {
            return;
        }
        let settings = &self.settings;
        let sampled = "Energy.Active.Import.Register,Power.Active.Import,Current.Import,Voltage,Temperature";
        for (key, value) in [
            ("HeartbeatInterval", settings.heartbeat_interval.to_string()),
            ("MeterValueSampleInterval", settings.meter_interval.to_string()),
            ("MeterValuesSampledData", sampled.to_string()),
            ("ClockAlignedDataInterval", "0".to_string()),
        ] {
            match self.call(station_id, "ChangeConfiguration", json!({"key": key, "value": value}), None).await {
                Ok(result) => log::info!(
                    "{}: ChangeConfiguration {}={} -> {}",
                    station_id,
                    key,
                    value,
                    printable_value(get(&result, "status"), 32)
                ),
                Err(err) => log::warn!("{station_id}: ChangeConfiguration {key} failed: {err}"),
            }
        }
        match self.call(station_id, "GetConfiguration", json!({}), None).await {
            Ok(result) => {
                let config = clean_config(get(&result, "configurationKey"));
                let count = config.len();
                let mut inner = self.lock();
                if let Some(station) = inner.stations.get_mut(station_id).filter(|_| count > 0) {
                    station.config = config;
                    learn_from_config(station);
                    inner.dirty = true;
                }
                log::info!("{station_id}: {count} configuration keys read");
            }
            Err(err) => log::warn!("{station_id}: GetConfiguration failed: {err}"),
        }
        let connectors = |controller: &Controller| controller.lock().stations.get(station_id).map_or(0, connector_count);
        for cid in 1..=connectors(self) {
            let payload = json!({"requestedMessage": "StatusNotification", "connectorId": cid});
            if let Err(err) = self.call(station_id, "TriggerMessage", payload, None).await {
                log::debug!("{station_id}: TriggerMessage failed: {err}");
            }
        }
        self.apply_limit(station_id, true).await;
        for cid in 1..=connectors(self) {
            self.enforce(station_id, cid).await;
        }
    }

    /// Send the charger the current limit that should be in force, if it isn't already.
    async fn apply_limit(&self, station_id: &str, force: bool) {
        let (limit, wanted) = {
            let inner = self.lock();
            let Some(station) = inner.stations.get(station_id).filter(|_| inner.is_online(station_id)) else { return };
            let (lo, hi) = (station.min_current, station.max_current);
            let wanted = effective_limit(station, &self.settings);
            let limit = match wanted {
                Some(wanted) => lo.max(wanted.min(hi)),
                // we never restricted this charger: leave its profile alone
                None if !station.limit_in_force => return,
                // A limit of ours is still in force (a window's own limit, and the window has ended,
                // been switched off or deleted). Nothing asks for one any more, so give the charger
                // its full current back; it would otherwise stay throttled for good.
                None => station.dip_switch_current_limit.map_or(hi, |dip| hi.min(dip)),
            };
            // Compare what would be sent, not what was asked for: a limit outside the charger's range
            // is clamped, and the unclamped number would never match, so every tick would send it again.
            if !force && station.applied_limit == Some(limit) {
                return;
            }
            (limit, wanted)
        };
        let profile = json!({
            "connectorId": 0,
            "csChargingProfiles": {
                "chargingProfileId": 1,
                "stackLevel": 0,
                "chargingProfilePurpose": "TxDefaultProfile",
                "chargingProfileKind": "Absolute",
                "chargingSchedule": {
                    "chargingRateUnit": "A",
                    "chargingSchedulePeriod": [{"startPeriod": 0, "limit": limit, "numberPhases": 1}],
                },
            },
        });
        match self.call(station_id, "SetChargingProfile", profile, None).await {
            Ok(result) => {
                let status = get(&result, "status");
                log::info!("{station_id}: SetChargingProfile {limit} A -> {}", printable_value(status, 32));
                if status == "Accepted" {
                    let mut inner = self.lock();
                    if let Some(station) = inner.stations.get_mut(station_id) {
                        station.applied_limit = Some(limit);
                        station.limit_in_force = wanted.is_some();
                        inner.dirty = true;
                    }
                }
            }
            Err(err) => log::warn!("{station_id}: SetChargingProfile failed: {err}"),
        }
    }

    /// Make the connector's real state match its mode and schedule.
    pub async fn enforce(&self, station_id: &str, cid: i64) {
        let (action, payload) = {
            let mut inner = self.lock();
            let online = inner.is_online(station_id);
            let Some(station) = inner.stations.get_mut(station_id) else { return };
            if station.ensure_connector(cid).is_err() {
                return;
            }
            let now = local_now(station, &self.settings);
            let active = window_now(station, now, cid).is_some();
            let holidays = holiday_fn(station);
            let next = next_change(&station.zones, now, cid, holidays.as_ref().map(|f| f as HolidayCheck<'_>));
            drop(holidays);
            let next_time = next.map(|next| iso_seconds(next.with_timezone(&Utc)));
            let id_tag = station.id_tag.clone().filter(|tag| !tag.is_empty());
            let connector = station.connectors.get_mut(&cid).expect("just ensured");
            let changed = connector.is_active_by_schedule != Some(active) || connector.next_schedule_time != next_time;
            connector.is_active_by_schedule = Some(active);
            connector.next_schedule_time = next_time;
            let allowed = connector.mode == Mode::Active || (connector.mode == Mode::Schedule && active);
            let status = connector.status.as_deref().unwrap_or_default();
            let (action, payload, stamp) = match &connector.transaction {
                None if allowed && WANTS_START.contains(&status) => {
                    let id_tag = id_tag.unwrap_or_else(|| self.settings.id_tag.clone());
                    let payload = json!({"connectorId": cid, "idTag": id_tag});
                    (Some("RemoteStartTransaction"), payload, &mut connector.last_remote_start)
                }
                Some(tx) if !allowed => {
                    let payload = json!({"transactionId": tx.id});
                    (Some("RemoteStopTransaction"), payload, &mut connector.last_remote_stop)
                }
                _ => (None, Value::Null, &mut connector.last_remote_start),
            };
            // Asked less than a minute ago: give the charger time to act on it.
            let recent = stamp.is_some_and(|last| last.elapsed() < REMOTE_RETRY);
            let action = action.filter(|_| online && !recent);
            if action.is_some() {
                *stamp = Some(Instant::now());
            }
            if changed {
                inner.dirty = true;
            }
            match action {
                Some(action) => (action, payload),
                None => return,
            }
        };
        match self.call(station_id, action, payload, None).await {
            Ok(result) => log::info!(
                "{station_id} connector {cid}: {action} -> {}",
                printable_value(get(&result, "status"), 32)
            ),
            Err(err) => log::warn!("{station_id} connector {cid}: {action} failed: {err}"),
        }
    }

    // --- commands (from the REST API) -----------------------------------------

    pub async fn set_mode(&self, station_id: &str, mode: &str, connector: i64) -> Result<(), CommandError> {
        let Some(mode) = Mode::parse(mode) else {
            return invalid(format!("mode must be one of {}", mode_list()));
        };
        let targets: Vec<i64> = {
            let mut inner = self.lock();
            let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
            let count = connector_count(station);
            if !(0..=count).contains(&connector) {
                return invalid(format!("connectorId must be 0 (all) or 1..{count}"));
            }
            let targets: Vec<i64> = if connector == 0 { (1..=count).collect() } else { vec![connector] };
            for cid in &targets {
                let connector = station.ensure_connector(*cid).map_err(CommandError::Invalid)?;
                connector.mode = mode;
                connector.last_remote_start = None;
                connector.last_remote_stop = None;
            }
            inner.dirty = true;
            targets
        };
        for cid in targets {
            self.enforce(station_id, cid).await;
        }
        Ok(())
    }

    pub async fn set_current_limit(&self, station_id: &str, amps: i64) -> Result<(), CommandError> {
        {
            let mut inner = self.lock();
            let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
            let lo = station.min_current;
            let hi = station.dip_switch_current_limit.map_or(station.max_current, |dip| dip.min(station.max_current));
            if !(lo..=hi).contains(&amps) {
                return invalid(format!("current limit must be between {lo} and {hi} A"));
            }
            station.current_limit = Some(amps);
            inner.dirty = true;
        }
        self.apply_limit(station_id, true).await;
        Ok(())
    }

    pub fn set_base_rate(&self, station_id: &str, price_kwh: &Value) -> Result<(), CommandError> {
        let mut inner = self.lock();
        let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
        match to_float(price_kwh).filter(|price| *price >= 0.0) {
            Some(price) => station.price_kw = price,
            None => return invalid("priceKW must be a number, zero or more"),
        }
        inner.dirty = true;
        Ok(())
    }

    /// Add a schedule or rate zone, or change the one with the same `_id`.
    ///
    /// The zone is validated before anything is stored: a zone the tick can't evaluate must never
    /// reach the list, least of all together with an error reply that says nothing was saved.
    pub async fn upsert_zone(&self, station_id: &str, price: &Value) -> Result<Zone, CommandError> {
        let zone = {
            let mut inner = self.lock();
            let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
            let Some(given) = price.as_object() else { return invalid("price object required") };
            let given_id = match get(given, "_id") {
                Value::Null => None,
                Value::String(id) if id.is_empty() => None,
                id => Some(zone_id(id).map_err(CommandError::Invalid)?),
            };
            let existing = given_id
                .as_ref()
                .and_then(|id| station.zones.iter().position(|zone| get(zone, "_id").as_str() == Some(id.as_str())));
            let zone = match existing {
                None => {
                    if station.zones.len() >= MAX_ZONES {
                        return invalid(format!("a station can have at most {MAX_ZONES} schedules and rate zones"));
                    }
                    let mut zone = normalize_zone(price, MAX_CONNECTORS, MAX_CURRENT).map_err(CommandError::Invalid)?;
                    zone.insert("_id".to_string(), Value::from(given_id.unwrap_or_else(|| random_hex(12))));
                    if !zone.contains_key("scheduleEnabled") {
                        let enabled = truthy(get(&zone, "isSchedule"));
                        zone.insert("scheduleEnabled".to_string(), Value::Bool(enabled));
                    }
                    station.zones.push(zone.clone());
                    zone
                }
                Some(at) => {
                    let mut merged = station.zones[at].clone();
                    for (key, value) in given {
                        merged.insert(key.clone(), value.clone());
                    }
                    let id = get(&station.zones[at], "_id").clone();
                    let mut zone = normalize_zone(&Value::Object(merged), MAX_CONNECTORS, MAX_CURRENT)
                        .map_err(CommandError::Invalid)?;
                    zone.insert("_id".to_string(), id);
                    station.zones[at] = zone.clone();
                    zone
                }
            };
            inner.dirty = true;
            zone
        };
        self.refresh_all(station_id).await;
        Ok(zone)
    }

    pub async fn set_zone_enabled(&self, station_id: &str, zone: &str, enabled: bool) -> Result<(), CommandError> {
        {
            let mut inner = self.lock();
            let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
            let found = station.zones.iter_mut().find(|z| get(z, "_id").as_str() == Some(zone));
            found.ok_or(CommandError::NotFound)?.insert("scheduleEnabled".to_string(), Value::Bool(enabled));
            inner.dirty = true;
        }
        self.refresh_all(station_id).await;
        Ok(())
    }

    pub async fn delete_zone(&self, station_id: &str, zone: &str) -> Result<(), CommandError> {
        {
            let mut inner = self.lock();
            let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
            let before = station.zones.len();
            station.zones.retain(|z| get(z, "_id").as_str() != Some(zone));
            if station.zones.len() == before {
                return Err(CommandError::NotFound);
            }
            inner.dirty = true;
        }
        self.refresh_all(station_id).await;
        Ok(())
    }

    /// Enforce every connector and the current limit, after something they depend on changed.
    async fn refresh_all(&self, station_id: &str) {
        let count = self.lock().stations.get(station_id).map_or(0, connector_count);
        for cid in 1..=count {
            self.enforce(station_id, cid).await;
        }
        self.apply_limit(station_id, false).await;
    }

    pub async fn set_holidays(&self, station_id: &str, raw: &Value) -> Result<holidays::Settings, CommandError> {
        let settings = holidays::Settings::normalize(raw).map_err(CommandError::Invalid)?;
        {
            let mut inner = self.lock();
            let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
            station.holidays = Some(settings.clone());
            inner.dirty = true;
        }
        self.refresh_all(station_id).await;
        Ok(settings)
    }

    /// Reprice every recorded session, and the ones in progress, with the current rates and holidays.
    pub fn recalculate_costs(&self, station_id: &str) -> Result<Value, CommandError> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
        let tz = station_tz(station, &self.settings);
        let (mut before, mut after, mut count) = (0.0, 0.0, 0);
        let mut repriced: Vec<(i64, f64, Option<f64>)> = Vec::new();
        let mut live: Vec<(i64, i64, f64, f64)> = Vec::new(); // (transaction, connector, cost, energy)
        for row in inner.store.sessions(station_id, 100_000)? {
            let Some(id) = get(&row, "id").as_i64() else { continue };
            let open = get(&row, "stop_at").is_null();
            let running = station
                .connectors
                .values()
                .find(|c| open && c.transaction.as_ref().is_some_and(|tx| tx.id == id))
                .map(|c| (c.id, c.transaction.as_ref().expect("just matched")));
            let (energy, old) = match (running, get(&row, "energy_wh").as_f64()) {
                (Some((_, tx)), _) => (tx.energy, tx.price_total),
                (None, Some(energy)) => (energy, get(&row, "cost").as_f64().unwrap_or(0.0)),
                (None, None) => continue, // never closed and not running: nothing to price
            };
            let samples = inner.store.energy_samples(station_id, id)?;
            let cost = reprice(
                station,
                tz,
                get(&row, "meter_start").as_f64(),
                energy,
                &samples,
                get(&row, "start_at").as_str(),
                get(&row, "stop_at").as_str(),
            );
            match running {
                Some((cid, _)) => live.push((id, cid, cost, energy)),
                None => repriced.push((id, round_to(cost, 6), (energy > 0.0).then(|| cost / (energy / 1000.0)))),
            }
            before += old;
            after += cost;
            count += 1;
        }
        for (_, cid, cost, energy) in live {
            if let Some(tx) = station.connectors.get_mut(&cid).and_then(|c| c.transaction.as_mut()) {
                tx.price_total = cost;
                tx.last_session_energy = energy;
            }
        }
        // One transaction for all of them: a commit per session would keep every charger waiting
        // on the disk for as long as the history is deep.
        inner.store.set_session_costs(&repriced)?;
        inner.dirty = true;
        log::info!("{station_id}: repriced {count} sessions, {before:.2} -> {after:.2}");
        Ok(json!({"sessions": count, "cost_before": round_to(before, 4), "cost_after": round_to(after, 4)}))
    }

    pub async fn reboot(&self, station_id: &str) -> Result<Object, OcppError> {
        self.call(station_id, "Reset", json!({"type": "Soft"}), None).await
    }

    /// Local-only tweaks: display name, timezone, currency, connector count, current bounds.
    ///
    /// Everything is checked first and applied only if all of it is acceptable, so a request that
    /// is refused changes nothing.
    pub fn update_settings(&self, station_id: &str, patch: &Object) -> Result<(), CommandError> {
        let mut inner = self.lock();
        let station = inner.stations.get_mut(station_id).ok_or(CommandError::NotFound)?;
        let text_of = |key: &str| get(patch, key).as_str().filter(|value| !value.is_empty());
        let mut display_name = None;
        if let Some(name) = text_of("displayName").map(str::trim).filter(|name| !name.is_empty()) {
            if name.chars().count() > MAX_NAME_LENGTH {
                return invalid(format!("displayName can't be longer than {MAX_NAME_LENGTH} characters"));
            }
            display_name = Some(name.to_string());
        }
        let timezone = text_of("timezone");
        if let Some(zone) = timezone {
            if zone.parse::<Tz>().is_err() {
                return invalid(format!("unknown timezone '{}'", clip(zone, 64)));
            }
        }
        let currency = text_of("currency");
        if let Some(code) = currency {
            if !(code.len() == 3 && code.bytes().all(|b| b.is_ascii_alphabetic())) {
                return invalid("currency must be a three-letter code such as USD");
            }
        }
        let mut numbers: HashMap<&str, Option<i64>> = HashMap::new();
        for (key, lo, hi) in [
            ("connectorCount", 1, MAX_CONNECTORS),
            ("maxCurrent", 1, MAX_CURRENT),
            ("minCurrent", 1, MAX_CURRENT),
            ("dipSwitchCurrentLimit", 1, MAX_CURRENT),
        ] {
            let Some(value) = patch.get(key) else { continue };
            if value.is_null() && key == "dipSwitchCurrentLimit" {
                numbers.insert(key, None); // "not known"
                continue;
            }
            match small_int(value, lo, hi) {
                Some(number) => numbers.insert(key, Some(number)),
                None => return invalid(format!("{key} must be a whole number from {lo} to {hi}")),
            };
        }
        let chosen = |key: &str, current: i64| numbers.get(key).copied().flatten().unwrap_or(current);
        if chosen("minCurrent", station.min_current) > chosen("maxCurrent", station.max_current) {
            return invalid("minCurrent can't be greater than maxCurrent");
        }

        if let Some(name) = display_name {
            station.display_name = name;
        }
        if let Some(zone) = timezone {
            station.timezone = zone.to_string();
        }
        if let Some(code) = currency {
            station.currency = code.to_uppercase();
        }
        station.max_current = chosen("maxCurrent", station.max_current);
        station.min_current = chosen("minCurrent", station.min_current);
        if let Some(dip) = numbers.get("dipSwitchCurrentLimit") {
            station.dip_switch_current_limit = *dip;
        }
        if ["connectorCount", "maxCurrent", "minCurrent"].iter().any(|key| numbers.contains_key(key)) {
            station.model_locked = true;
        }
        if let Some(Some(count)) = numbers.get("connectorCount") {
            station.connector_count = *count;
            station.ensure_connectors();
        }
        inner.dirty = true;
        Ok(())
    }

    /// Forget a station: its settings, and its recorded sessions and samples with it.
    pub fn delete_station(&self, station_id: &str) -> Result<(), CommandError> {
        let mut inner = self.lock();
        inner.stations.shift_remove(station_id);
        inner.dirty = true;
        for task in [inner.boot_tasks.remove(station_id), inner.station_ticks.remove(station_id)].into_iter().flatten() {
            task.abort();
        }
        inner.store.delete_history(station_id)?;
        Ok(())
    }

    // --- background loop ------------------------------------------------------

    /// One round of enforcement for one station.
    ///
    /// Each station gets its own task: these calls wait on the charger (up to the call timeout,
    /// per connector), and a charger that doesn't answer must only ever hold up itself.
    async fn tick_station(&self, station_id: &str) {
        self.refresh_all(station_id).await;
        let mut inner = self.lock();
        let Some(station) = inner.stations.get_mut(station_id) else { return };
        let now = Utc::now();
        for connector in station.connectors.values_mut() {
            let plugged_in = connector.status.as_deref().is_some_and(|status| PLUGGED_IN.contains(&status));
            if let Some(tx) = connector.transaction.as_mut().filter(|_| plugged_in) {
                let start = tx.start_at.as_deref().and_then(parse_iso);
                tx.duration = start.map(|start| seconds_between(start, now).max(0));
            }
        }
    }

    /// One pass of the background loop: start a tick for every station that isn't still busy with
    /// its last one, prune the history once an hour, and save.
    fn tick(self: &Arc<Self>, last_prune: &mut Option<Instant>) {
        let idle: Vec<String> = {
            let mut inner = self.lock();
            let inner = &mut *inner;
            inner.station_ticks.retain(|id, task| !task.is_finished() || inner.stations.contains_key(id));
            inner.boot_tasks.retain(|_, task| !task.is_finished());
            inner
                .stations
                .keys()
                // still busy with a slow charger: let it finish
                .filter(|id| inner.station_ticks.get(*id).is_none_or(|task| task.is_finished()))
                .cloned()
                .collect()
        };
        for station_id in idle {
            let controller = self.clone();
            let id = station_id.clone();
            let task = self.spawn(async move { controller.tick_station(&id).await });
            self.lock().station_ticks.insert(station_id, task);
        }
        let mut inner = self.lock();
        if last_prune.is_none_or(|at| at.elapsed() > Duration::from_secs(3600)) {
            *last_prune = Some(Instant::now());
            if let Err(err) = inner.store.prune_samples(SAMPLE_DAYS) {
                log::error!("pruning the history failed: {err}");
            }
        }
        // Whatever went wrong above, what is in memory still gets written.
        inner.save();
    }

    /// The background loop: runs until [`Controller::stop`].
    pub async fn run(self: Arc<Self>) {
        let mut last_prune = None;
        while !self.is_stopping() {
            self.tick(&mut last_prune);
            tokio::time::sleep(self.settings.tick).await;
        }
    }

    /// Stop talking to chargers: save, then close every connection (within the close timeout).
    pub async fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let connections: Vec<Arc<Connection>> = {
            let mut inner = self.lock();
            for task in inner.tasks.drain(..) {
                task.abort();
            }
            // Save first. Closing a socket waits for the peer to acknowledge, a dead peer never
            // does, and whoever asked us to stop (Docker: ten seconds) may not wait for all of them.
            inner.dirty = true;
            inner.save();
            inner.connections.values().cloned().collect()
        };
        let closing = async {
            let closes: Vec<_> = connections.iter().map(|conn| conn.close()).collect();
            futures_util::future::join_all(closes).await;
        };
        let _ = tokio::time::timeout(self.settings.close_timeout, closing).await;
        self.save();
    }
}

fn mode_list() -> String {
    format!("({})", MODES.map(|mode| format!("'{mode}'")).join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn controller(dir: &std::path::Path, pairs: &[(&str, &str)]) -> Arc<Controller> {
        let mut settings = Settings::from_pairs(pairs).unwrap();
        settings.data_dir = dir.to_path_buf();
        Controller::open(Arc::new(settings)).unwrap()
    }

    fn object(value: Value) -> Object {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn mode_list_reads_like_the_api_always_said_it() {
        assert_eq!(mode_list(), "('Active', 'Inactive', 'Schedule')");
    }

    #[tokio::test]
    async fn out_of_range_connector_is_refused_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let controller = controller(dir.path(), &[]);
        for bad in [json!(9), json!(4_000_000_000_i64), json!(-1), json!("lots"), json!([1]), json!(1.5)] {
            for action in ["StatusNotification", "MeterValues", "StartTransaction"] {
                let payload = object(json!({"connectorId": bad, "status": "Available", "errorCode": "NoError"}));
                let result = controller.handle("GRD-1", action, &payload);
                assert!(
                    matches!(&result, Err(HandlerError::Rejected { code, .. }) if code == "PropertyConstraintViolation"),
                    "{action} {bad}: {result:?}"
                );
            }
        }
        let inner = controller.lock();
        assert_eq!(inner.stations["GRD-1"].connectors.len(), 1);
        assert_eq!(inner.stations["GRD-1"].connector_count, 1);
    }

    #[tokio::test]
    async fn connector_ids_up_to_the_limit_still_work() {
        let dir = tempfile::tempdir().unwrap();
        let controller = controller(dir.path(), &[]);
        for cid in [json!(8), json!("3"), json!(2.0)] {
            let payload = object(json!({"connectorId": cid, "status": "Available"}));
            assert_eq!(controller.handle("GRD-1", "StatusNotification", &payload), Ok(json!({})));
        }
        let inner = controller.lock();
        assert_eq!(inner.stations["GRD-1"].connector_count, 8);
        assert_eq!(inner.stations["GRD-1"].connectors.len(), 8, "every connector up to the highest one exists");
    }
}
