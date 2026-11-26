//! What the server knows about each station, and how that is read from and written to state.json.
//!
//! Reading is where saved state is made safe to run on. An older version stored what chargers and
//! API clients sent as it came, so a file written then (possibly while someone was abusing that)
//! may hold a connector count in the billions, a status that isn't text, a schedule with a word
//! where an hour belongs. Everything is therefore read field by field, typed and bounded, and what
//! can't be used is repaired or dropped with a warning.

use std::collections::BTreeMap;
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::config::Settings;
use crate::holidays;
use crate::logging::{printable, printable_value};
use crate::schedules::{normalize_zone, zone_id, Zone, MAX_NAME_LENGTH};
use crate::value::{
    clip, get, number, objects, opt_int, opt_number, opt_text, reading, small_int, text, to_float, truthy, Object,
};

/// A Duo has 2 connectors; nothing in the family has more than a few.
pub const MAX_CONNECTORS: i64 = 8;
/// Amps; the largest Grizzl-E is 80 A.
pub const MAX_CURRENT: i64 = 100;
/// Schedules + rate zones per station.
pub const MAX_ZONES: usize = 100;
/// GetConfiguration entries kept (a Duo reports 34).
pub const MAX_CONFIG_KEYS: usize = 256;
/// The largest transaction id we accept from saved state or a charger.
pub const MAX_TRANSACTION_ID: i64 = 1 << 62;

pub const BOOT_FIELDS: [&str; 9] = [
    "chargePointVendor",
    "chargePointModel",
    "chargePointSerialNumber",
    "chargeBoxSerialNumber",
    "firmwareVersion",
    "iccid",
    "imsi",
    "meterType",
    "meterSerialNumber",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Active,
    Inactive,
    Schedule,
}

pub const MODES: [&str; 3] = ["Active", "Inactive", "Schedule"];

impl Mode {
    pub fn parse(text: &str) -> Option<Mode> {
        match text {
            "Active" => Some(Mode::Active),
            "Inactive" => Some(Mode::Inactive),
            "Schedule" => Some(Mode::Schedule),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Active => "Active",
            Mode::Inactive => "Inactive",
            Mode::Schedule => "Schedule",
        }
    }
}

/// The latest value of each thing a charger measures, and when it was measured.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Meter {
    pub energy_wh: Option<f64>,
    pub power_w: Option<f64>,
    pub current_a: Option<f64>,
    pub current_offered_a: Option<f64>,
    pub voltage_v: Option<f64>,
    pub temperature_c: Option<f64>,
    pub soc: Option<f64>,
    pub at: Option<String>,
}

impl Meter {
    pub fn is_empty(&self) -> bool {
        *self == Meter::default()
    }

    /// Take every value `newer` has.
    pub fn update(&mut self, newer: &Meter) {
        let fields = [
            (&mut self.energy_wh, newer.energy_wh),
            (&mut self.power_w, newer.power_w),
            (&mut self.current_a, newer.current_a),
            (&mut self.current_offered_a, newer.current_offered_a),
            (&mut self.voltage_v, newer.voltage_v),
            (&mut self.temperature_c, newer.temperature_c),
            (&mut self.soc, newer.soc),
        ];
        for (mine, theirs) in fields {
            if theirs.is_some() {
                *mine = theirs;
            }
        }
        if newer.at.is_some() {
            self.at.clone_from(&newer.at);
        }
    }

    /// The field for an OCPP measurand's key (`energy_wh`, …).
    pub fn field_mut(&mut self, key: &str) -> Option<&mut Option<f64>> {
        Some(match key {
            "energy_wh" => &mut self.energy_wh,
            "power_w" => &mut self.power_w,
            "current_a" => &mut self.current_a,
            "current_offered_a" => &mut self.current_offered_a,
            "voltage_v" => &mut self.voltage_v,
            "temperature_c" => &mut self.temperature_c,
            "soc" => &mut self.soc,
            _ => return None,
        })
    }

    fn from_saved(value: &Value) -> Meter {
        let Some(saved) = value.as_object() else { return Meter::default() };
        let field = |key: &str| reading(get(saved, key), false);
        Meter {
            energy_wh: field("energy_wh"),
            power_w: field("power_w"),
            current_a: field("current_a"),
            current_offered_a: field("current_offered_a"),
            voltage_v: field("voltage_v"),
            temperature_c: field("temperature_c"),
            soc: field("soc"),
            at: get(saved, "at").as_str().map(|at| clip(at, 40).to_string()),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        let fields = [
            ("energy_wh", self.energy_wh),
            ("power_w", self.power_w),
            ("current_a", self.current_a),
            ("current_offered_a", self.current_offered_a),
            ("voltage_v", self.voltage_v),
            ("temperature_c", self.temperature_c),
            ("soc", self.soc),
        ];
        for (key, value) in fields {
            if let Some(value) = value {
                object.insert(key.to_string(), json!(value));
            }
        }
        if let Some(at) = &self.at {
            object.insert("at".to_string(), json!(at));
        }
        Value::Object(object)
    }
}

/// A charging session in progress.
#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    pub id: i64,
    pub id_tag: Option<String>,
    /// When it started, by our reckoning (the charger's time if that is plausible).
    pub start_at: Option<String>,
    /// What the charger's own clock said, however wrong the date: the length of a session is the
    /// difference between two readings of that clock.
    pub clock_start: Option<String>,
    /// The lifetime register when the session began, in Wh.
    pub meter_start: Option<f64>,
    /// Wh delivered so far.
    pub energy: f64,
    pub power: f64,
    pub meter: Meter,
    pub price_kw: Option<f64>,
    pub price_total: f64,
    /// The session energy the cost so far accounts for.
    pub last_session_energy: f64,
    /// Whether this charger's MeterValues count from the start of the session. Decided once.
    pub session_relative_register: Option<bool>,
    pub duration: Option<i64>,
}

impl Transaction {
    fn from_saved(value: &Value) -> Option<Transaction> {
        let saved = value.as_object()?;
        let id = small_int(get(saved, "id"), 1, MAX_TRANSACTION_ID)?;
        let amount = |key: &str| reading(get(saved, key), false).unwrap_or(0.0);
        Some(Transaction {
            id,
            id_tag: text(get(saved, "idTag"), 64),
            start_at: get(saved, "startAt").as_str().map(|at| clip(at, 40).to_string()),
            clock_start: get(saved, "clockStart").as_str().map(|at| clip(at, 40).to_string()),
            meter_start: reading(get(saved, "meterStart"), false),
            energy: amount("energy"),
            power: amount("power"),
            meter: Meter::from_saved(get(saved, "meter")),
            price_kw: to_float(get(saved, "priceKW")),
            price_total: amount("priceTotal"),
            last_session_energy: amount("lastSessionEnergy"),
            session_relative_register: get(saved, "sessionRelativeRegister").as_bool(),
            duration: small_int(get(saved, "duration"), 0, i64::MAX),
        })
    }

    pub fn to_json(&self) -> Value {
        let mut object = json!({
            "id": self.id,
            "idTag": self.id_tag,
            "startAt": self.start_at,
            "clockStart": self.clock_start,
            "meterStart": opt_number(self.meter_start),
            "energy": number(self.energy),
            "power": number(self.power),
            "meter": self.meter.to_json(),
            "priceKW": self.price_kw,
            "priceTotal": self.price_total,
            "lastSessionEnergy": self.last_session_energy,
        });
        if let Some(relative) = self.session_relative_register {
            object["sessionRelativeRegister"] = json!(relative);
        }
        if let Some(duration) = self.duration {
            object["duration"] = json!(duration);
        }
        object
    }
}

#[derive(Debug, Clone)]
pub struct Connector {
    pub id: i64,
    pub status: Option<String>,
    pub error_code: Option<String>,
    pub status_changed_at: Option<String>,
    pub mode: Mode,
    pub power: f64,
    pub transaction: Option<Transaction>,
    pub last_meter: Meter,
    pub total_energy_wh: Option<f64>,
    pub is_active_by_schedule: Option<bool>,
    pub next_schedule_time: Option<String>,
    /// When RemoteStartTransaction was last tried. Never saved: it means nothing after a restart,
    /// and carried over it could look like "tried a moment ago" for days.
    pub last_remote_start: Option<Instant>,
    pub last_remote_stop: Option<Instant>,
    pub vendor_error_code: Option<String>,
    pub info: Option<String>,
    /// The last finished session as it stood when it ended.
    pub last_session: Option<Value>,
}

impl Connector {
    pub fn new(id: i64) -> Connector {
        Connector {
            id,
            status: None,
            error_code: Some("NoError".to_string()),
            status_changed_at: None,
            mode: Mode::Active,
            power: 0.0,
            transaction: None,
            last_meter: Meter::default(),
            total_energy_wh: None,
            is_active_by_schedule: None,
            next_schedule_time: None,
            last_remote_start: None,
            last_remote_stop: None,
            vendor_error_code: None,
            info: None,
            last_session: None,
        }
    }

    fn from_saved(id: i64, saved: &Object) -> Connector {
        let string = |key: &str, limit: usize| get(saved, key).as_str().map(|s| clip(s, limit).to_string());
        Connector {
            id,
            status: string("status", 32),
            error_code: string("errorCode", 50),
            status_changed_at: string("statusChangedAt", 40),
            mode: get(saved, "mode").as_str().and_then(Mode::parse).unwrap_or(Mode::Active),
            power: reading(get(saved, "power"), false).unwrap_or(0.0),
            transaction: Transaction::from_saved(get(saved, "transaction")),
            last_meter: Meter::from_saved(get(saved, "lastMeter")),
            total_energy_wh: reading(get(saved, "totalEnergyWh"), false),
            is_active_by_schedule: get(saved, "isActiveBySchedule").as_bool(),
            next_schedule_time: string("nextScheduleTime", 40),
            last_remote_start: None,
            last_remote_stop: None,
            vendor_error_code: string("vendorErrorCode", 50),
            info: string("info", 255),
            last_session: Some(get(saved, "lastSession")).filter(|v| v.is_object()).cloned(),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut object = json!({
            "id": self.id,
            "status": self.status,
            "errorCode": self.error_code,
            "statusChangedAt": self.status_changed_at,
            "mode": self.mode.as_str(),
            "power": number(self.power),
            "transaction": self.transaction.as_ref().map(Transaction::to_json),
            "lastMeter": self.last_meter.to_json(),
            "totalEnergyWh": self.total_energy_wh,
            "isActiveBySchedule": self.is_active_by_schedule,
            "nextScheduleTime": self.next_schedule_time,
            "lastRemoteStart": null,
            "lastRemoteStop": null,
            "vendorErrorCode": self.vendor_error_code,
            "info": self.info,
        });
        if let Some(session) = &self.last_session {
            object["lastSession"] = session.clone();
        }
        object
    }
}

#[derive(Debug, Clone)]
pub struct Station {
    pub id: String,
    pub display_name: String,
    pub timezone: String,
    pub currency: String,
    /// The base price per kWh.
    pub price_kw: f64,
    /// What the charger said about itself in its last BootNotification.
    pub boot: Object,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub connector_count: i64,
    pub connectors: BTreeMap<i64, Connector>,
    /// The owner's current limit in amps, if one is set.
    pub current_limit: Option<i64>,
    /// The limit the charger last accepted from us.
    pub applied_limit: Option<i64>,
    pub dip_switch_current_limit: Option<i64>,
    pub max_current: i64,
    pub min_current: i64,
    pub model_name: String,
    pub model_code: String,
    pub zones: Vec<Zone>,
    /// The charger's configuration keys as it reported them: text, or null.
    pub config: Object,
    /// Whether a limit of ours is in force on the charger (and so has to be lifted when nothing
    /// asks for one any more).
    pub limit_in_force: bool,
    /// The idTag the charger's own configuration names for remote starts.
    pub id_tag: Option<String>,
    /// The Auth key this station is pinned to. Never shown by the API.
    pub ocpp_auth_key: Option<String>,
    /// The station has connected without a key, so a key presented later is not pinned.
    pub ocpp_keyless: bool,
    /// How the charger last connected, for tools/firmware_capture.py. Never shown by the API.
    pub ocpp_handshake: Option<Value>,
    /// The owner set the connector count or current bounds: don't take them from the model again.
    pub model_locked: bool,
    pub status: Option<String>,
    pub error_code: Option<String>,
    pub data_transfers: Vec<Value>,
    pub diagnostics_status: Option<String>,
    pub firmware_status: Option<String>,
    pub holidays: Option<holidays::Settings>,
}

/// How many connectors a station has: always 1..=MAX_CONNECTORS, whatever is stored.
pub fn connector_count(station: &Station) -> i64 {
    station.connector_count.clamp(1, MAX_CONNECTORS)
}

/// The BootNotification fields we keep, each cut to size, with the time it arrived.
pub fn boot_fields(payload: &Object, timestamp: Option<String>) -> Object {
    let mut boot = Object::new();
    for key in BOOT_FIELDS {
        if let Some(value) = payload.get(key).and_then(|value| text(value, 100)) {
            boot.insert(key.to_string(), Value::from(value));
        }
    }
    if !boot.is_empty() || timestamp.is_some() {
        boot.insert("timestamp".to_string(), opt_text(&timestamp));
    }
    boot
}

/// A GetConfiguration reply as `{key: value}`: text keys and values only, a bounded number of them.
pub fn clean_config(items: &Value) -> Object {
    let mut config = Object::new();
    for item in objects(items, MAX_CONFIG_KEYS) {
        if let Some(key) = get(item, "key").as_str().filter(|k| !k.is_empty() && k.chars().count() <= 100) {
            let value = text(get(item, "value"), 500).map_or(Value::Null, Value::from);
            config.insert(key.to_string(), value);
        }
    }
    config
}

/// A DataTransfer message as we keep it: its fields cut to size.
pub fn data_transfer(payload: &Object, at: Option<String>) -> Value {
    let data = match get(payload, "data") {
        Value::Null => Value::Null,
        Value::String(data) => Value::from(clip(data, 1000)),
        other => Value::from(clip(&printable_value(other, 1000), 1000)), // not text: a bounded description of it
    };
    json!({
        "at": at,
        "vendorId": text(get(payload, "vendorId"), 255),
        "messageId": text(get(payload, "messageId"), 50),
        "data": data,
    })
}

/// A saved zone with the values an older version accepted, and coped with, brought into range.
///
/// Only what leaves the zone meaning the same: an over-long name is cut, a current limit beyond
/// the bounds is clamped (the old code clamped it when applying it), day numbers that never
/// matched any day are removed. A zone that is still refused after this (a word where an hour
/// belongs) is dropped by the caller: guessing its times could turn it into an all-day window.
fn mended_zone(zone: &Value) -> Value {
    let Some(zone) = zone.as_object() else { return zone.clone() };
    let mut mended = zone.clone();
    if let Some(name) = get(zone, "name").as_str() {
        mended.insert("name".to_string(), Value::from(clip(name.trim(), MAX_NAME_LENGTH)));
    }
    if let Some(limit) = zone.get("currentLimit") {
        let limit =
            reading(limit, false).filter(|limit| *limit > 0.0).map(|limit| limit.clamp(1.0, MAX_CURRENT as f64));
        mended.insert("currentLimit".to_string(), opt_number(limit));
    }
    if let Some(days) = get(zone, "days").as_array() {
        let days: Vec<Value> = days.iter().filter(|day| small_int(day, 0, 6).is_some()).cloned().collect();
        mended.insert("days".to_string(), Value::from(days));
    }
    Value::Object(mended)
}

impl Station {
    /// A station nobody has seen before.
    pub fn new(id: &str, settings: &Settings) -> Station {
        Station {
            id: id.to_string(),
            display_name: id.to_string(),
            timezone: settings.timezone.clone(),
            currency: settings.currency.clone(),
            price_kw: 0.0,
            boot: Object::new(),
            first_seen: Some(crate::timeutil::now_iso()),
            last_seen: None,
            connector_count: 1,
            connectors: BTreeMap::new(),
            current_limit: None,
            applied_limit: None,
            dip_switch_current_limit: None,
            max_current: settings.default_max_current,
            min_current: settings.default_min_current,
            model_name: "Grizzl-E".to_string(),
            model_code: String::new(),
            zones: Vec::new(),
            config: Object::new(),
            limit_in_force: false,
            id_tag: None,
            ocpp_auth_key: None,
            ocpp_keyless: false,
            ocpp_handshake: None,
            model_locked: false,
            status: None,
            error_code: None,
            data_transfers: Vec::new(),
            diagnostics_status: None,
            firmware_status: None,
            holidays: None,
        }
    }

    /// A station from state.json, made safe to run on. See the module's description.
    pub fn from_saved(id: &str, saved: &Object, settings: &Settings) -> Station {
        let string = |key: &str, limit: usize| get(saved, key).as_str().map(|s| clip(s, limit).to_string());
        let named = |key: &str, default: &str| match get(saved, key).as_str() {
            Some(value) if !value.is_empty() && value.chars().count() <= 64 => value.to_string(),
            _ => default.to_string(),
        };
        let amps = |key: &str| small_int(get(saved, key), 1, MAX_CURRENT);
        let applied_limit = amps("appliedLimit");
        let empty = Object::new();
        let boot = get(saved, "boot").as_object().unwrap_or(&empty);
        let model = get(saved, "model").as_object().unwrap_or(&empty);

        let mut connectors = BTreeMap::new();
        for (key, connector) in get(saved, "connectors").as_object().unwrap_or(&empty) {
            let cid = small_int(&Value::from(key.as_str()), 1, MAX_CONNECTORS);
            if let (Some(cid), Some(connector)) = (cid.filter(|cid| cid.to_string() == *key), connector.as_object()) {
                connectors.insert(cid, Connector::from_saved(cid, connector));
            }
        }
        let stored = get(saved, "connectorCount");
        let connector_count = match stored.as_i64().filter(|count| (1..=MAX_CONNECTORS).contains(count)) {
            Some(count) => count,
            None => {
                // Out of range: fall back to the connectors that really exist.
                let count = connectors.keys().next_back().copied().unwrap_or(1);
                if !stored.is_null() {
                    log::warn!(
                        "{}: saved connector count {} is not possible; using {}",
                        printable(id, 80),
                        printable_value(stored, 40),
                        count
                    );
                }
                count
            }
        };

        let mut zones = Vec::new();
        for zone in get(saved, "pricesByZone").as_array().map(Vec::as_slice).unwrap_or_default() {
            let clean = normalize_zone(zone, MAX_CONNECTORS, MAX_CURRENT)
                // Refused as it stands; mend what the old code merely tolerated before giving up.
                .or_else(|_| normalize_zone(&mended_zone(zone), MAX_CONNECTORS, MAX_CURRENT))
                .and_then(|mut clean| {
                    let id = zone_id(zone.get("_id").unwrap_or(&Value::Null))?;
                    clean.insert("_id".to_string(), Value::from(id));
                    Ok(clean)
                });
            match clean {
                Ok(clean) => zones.push(clean),
                Err(err) => log::warn!(
                    "{}: dropping an unusable schedule/rate zone from the saved state: {}",
                    printable(id, 80),
                    err
                ),
            }
        }
        zones.truncate(MAX_ZONES);

        let holidays = saved.get("holidaysSettings").and_then(|raw| match holidays::Settings::normalize(raw) {
            Ok(settings) => Some(settings),
            Err(err) => {
                log::warn!("{}: dropping unusable holiday settings from the saved state: {}", printable(id, 80), err);
                None
            }
        });
        let config_items: Vec<Value> = get(saved, "config")
            .as_object()
            .map(|config| config.iter().map(|(key, value)| json!({"key": key, "value": value})).collect())
            .unwrap_or_default();
        let transfers = get(saved, "dataTransfers");

        Station {
            id: id.to_string(),
            display_name: match get(saved, "displayName").as_str() {
                Some(name) if !name.is_empty() => clip(name, MAX_NAME_LENGTH).to_string(),
                _ => id.to_string(),
            },
            timezone: named("timezone", &settings.timezone),
            currency: named("currency", &settings.currency),
            price_kw: to_float(get(saved, "priceKW")).filter(|price| *price >= 0.0).unwrap_or(0.0),
            boot: boot_fields(boot, text(get(boot, "timestamp"), 40)),
            first_seen: string("firstSeen", 40),
            last_seen: string("lastSeen", 40),
            connector_count,
            connectors,
            current_limit: amps("currentLimit"),
            applied_limit,
            dip_switch_current_limit: amps("dipSwitchCurrentLimit"),
            max_current: amps("maxCurrent").unwrap_or(settings.default_max_current),
            min_current: amps("minCurrent").unwrap_or(settings.default_min_current),
            model_name: text(get(model, "name"), 100).filter(|n| !n.is_empty()).unwrap_or_else(|| "Grizzl-E".into()),
            model_code: text(get(model, "code"), 100).unwrap_or_default(),
            zones,
            config: clean_config(&Value::from(config_items)),
            limit_in_force: match saved.get("limitInForce") {
                Some(value) => truthy(value),
                // Saved by a version that never lifted a charging window's limit once the window was
                // over: if a limit was applied, treat it as still in force so that it is lifted now.
                None => applied_limit.is_some(),
            },
            id_tag: get(saved, "idTag").as_str().filter(|tag| tag.chars().count() <= 64).map(str::to_string),
            // An empty key is not one anyone could present: better unpinned than unusable.
            ocpp_auth_key: get(saved, "ocppAuthKey").as_str().filter(|key| !key.is_empty()).map(str::to_string),
            ocpp_keyless: truthy(get(saved, "ocppKeyless")),
            ocpp_handshake: Some(get(saved, "ocppHandshake")).filter(|v| v.is_object()).cloned(),
            model_locked: truthy(get(saved, "modelLocked")),
            status: string("status", 32),
            error_code: string("errorCode", 50),
            data_transfers: objects(transfers, 20)
                .into_iter()
                .map(|item| data_transfer(item, text(get(item, "at"), 40)))
                .collect(),
            diagnostics_status: string("diagnosticsStatus", 32),
            firmware_status: string("firmwareStatus", 32),
            holidays,
        }
    }

    pub fn to_json(&self) -> Value {
        let connectors: Object = self.connectors.iter().map(|(id, c)| (id.to_string(), c.to_json())).collect();
        let mut object = json!({
            "id": self.id,
            "displayName": self.display_name,
            "timezone": self.timezone,
            "currency": self.currency,
            "priceKW": number(self.price_kw),
            "boot": self.boot,
            "firstSeen": self.first_seen,
            "connectorCount": self.connector_count,
            "connectors": connectors,
            "currentLimit": opt_int(self.current_limit),
            "appliedLimit": opt_int(self.applied_limit),
            "dipSwitchCurrentLimit": opt_int(self.dip_switch_current_limit),
            "maxCurrent": self.max_current,
            "minCurrent": self.min_current,
            "model": {"name": self.model_name, "code": self.model_code},
            "pricesByZone": self.zones,
            "config": self.config,
            "limitInForce": self.limit_in_force,
        });
        let map = object.as_object_mut().expect("an object");
        let mut optional = |key: &str, value: Option<Value>| {
            if let Some(value) = value {
                map.insert(key.to_string(), value);
            }
        };
        optional("lastSeen", self.last_seen.clone().map(Value::from));
        optional("ocppHandshake", self.ocpp_handshake.clone());
        optional("idTag", self.id_tag.clone().map(Value::from));
        optional("ocppAuthKey", self.ocpp_auth_key.clone().map(Value::from));
        optional("ocppKeyless", self.ocpp_keyless.then_some(Value::Bool(true)));
        optional("modelLocked", self.model_locked.then_some(Value::Bool(true)));
        optional("status", self.status.clone().map(Value::from));
        optional("errorCode", self.error_code.clone().map(Value::from));
        optional("dataTransfers", (!self.data_transfers.is_empty()).then(|| Value::from(self.data_transfers.clone())));
        optional("diagnosticsStatus", self.diagnostics_status.clone().map(Value::from));
        optional("firmwareStatus", self.firmware_status.clone().map(Value::from));
        optional("holidaysSettings", self.holidays.as_ref().map(holidays::Settings::to_json));
        object
    }

    /// The connector, created if it doesn't exist yet. `Err` unless `cid` is 1..=MAX_CONNECTORS:
    /// every caller checks first, and this is the backstop that keeps a number from the network
    /// from ever becoming the length of a loop.
    pub fn ensure_connector(&mut self, cid: i64) -> Result<&mut Connector, String> {
        if !(1..=MAX_CONNECTORS).contains(&cid) {
            return Err(format!("connector must be 1..{MAX_CONNECTORS}"));
        }
        if !self.connectors.contains_key(&cid) && cid > connector_count(self) {
            self.connector_count = cid;
        }
        Ok(self.connectors.entry(cid).or_insert_with(|| Connector::new(cid)))
    }

    /// Make sure every connector the station is said to have exists.
    pub fn ensure_connectors(&mut self) {
        for cid in 1..=connector_count(self) {
            self.connectors.entry(cid).or_insert_with(|| Connector::new(cid));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(saved: Value) -> Station {
        Station::from_saved("GRD-1", saved.as_object().unwrap(), &Settings::defaults())
    }

    #[test]
    fn a_new_station_survives_a_round_trip() {
        let settings = Settings::defaults();
        let mut station = Station::new("GRD-1", &settings);
        station.ensure_connectors();
        station.ocpp_auth_key = Some("secret".into());
        station.holidays = Some(holidays::Settings::normalize(&json!({"enabled": true, "country": "US"})).unwrap());
        station.zones.push(normalize_zone(&json!({"allDay": true, "priceKW": 0.2}), 8, 100).unwrap());
        station.zones[0].insert("_id".into(), json!("z1"));
        let saved = station.to_json();
        let again = Station::from_saved("GRD-1", saved.as_object().unwrap(), &settings);
        assert_eq!(again.to_json(), saved);
        assert_eq!(saved["connectors"]["1"]["mode"], "Active");
        assert_eq!(saved["priceKW"], 0);
        assert_eq!(saved["limitInForce"], false);
    }

    #[test]
    fn poisoned_state_is_repaired_on_load() {
        let station = load(json!({
            "displayName": 5, "timezone": ["x"], "currency": "", "priceKW": -3, "maxCurrent": 100000, "minCurrent": "six",
            "currentLimit": 1e9, "appliedLimit": 24, "dipSwitchCurrentLimit": true,
            "connectorCount": 4_000_000_000_i64,
            "idTag": {"a": 1}, "ocppAuthKey": "", "boot": "booted", "model": 7, "config": [1, 2],
            "connectors": {
                "1": {"mode": "Turbo", "status": 9, "power": "lots", "totalEnergyWh": 1e300,
                      "lastRemoteStart": 12345.6, "lastRemoteStop": 1.0,
                      "transaction": {"id": 7, "energy": "x", "meterStart": true, "startAt": 5, "meter": 3,
                                      "sessionRelativeRegister": "yes", "priceKW": "0.2"}},
                "2": {"transaction": {"id": "seven"}},
                "02": {}, "0": {}, "9": {}, "x": {}, "3": "connector",
            },
            "pricesByZone": [
                {"_id": "ok", "startHours": 1, "endHours": 2},
                {"_id": "word", "startHours": "soon"},
                {"_id": "mend", "name": "x".repeat(300), "currentLimit": 500, "days": [1, 7, 9], "allDay": true},
                {"startHours": 1},
                "zone",
            ],
            "holidaysSettings": {"country": "Atlantis"},
            "dataTransfers": [{"vendorId": "v", "data": {"a": 1}, "at": "t"}, "x"],
        }));
        assert_eq!(station.display_name, "GRD-1");
        assert_eq!((station.timezone.as_str(), station.currency.as_str()), ("UTC", "USD"));
        assert_eq!(station.price_kw, 0.0);
        assert_eq!((station.max_current, station.min_current), (40, 6));
        assert_eq!(
            (station.current_limit, station.applied_limit, station.dip_switch_current_limit),
            (None, Some(24), None)
        );
        assert!(station.limit_in_force, "a limit applied by a version that never lifted it is still in force");
        assert_eq!(station.connector_count, 2);
        assert_eq!(station.connectors.keys().copied().collect::<Vec<_>>(), [1, 2]);
        assert_eq!((station.id_tag.clone(), station.ocpp_auth_key.clone()), (None, None));
        assert!(station.boot.is_empty() && station.config.is_empty());
        assert_eq!((station.model_name.as_str(), station.model_code.as_str()), ("Grizzl-E", ""));

        let one = &station.connectors[&1];
        assert_eq!((one.mode, one.status.clone(), one.power, one.total_energy_wh), (Mode::Active, None, 0.0, None));
        assert!(one.last_remote_start.is_none() && one.last_remote_stop.is_none());
        let tx = one.transaction.as_ref().unwrap();
        assert_eq!((tx.id, tx.energy, tx.meter_start, tx.start_at.clone()), (7, 0.0, None, None));
        assert_eq!((tx.session_relative_register, tx.price_kw), (None, Some(0.2)));
        assert!(tx.meter.is_empty());
        assert!(station.connectors[&2].transaction.is_none());

        let ids: Vec<&str> = station.zones.iter().map(|z| z["_id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["ok", "mend"]);
        let mended = &station.zones[1];
        assert_eq!(mended["name"].as_str().unwrap().len(), MAX_NAME_LENGTH);
        assert_eq!((&mended["currentLimit"], &mended["days"]), (&json!(100), &json!([1])));
        assert!(station.holidays.is_none());
        assert_eq!(
            station.data_transfers,
            [json!({"at": "t", "vendorId": "v", "messageId": null, "data": "{\"a\":1}"})]
        );
    }

    #[test]
    fn connector_count_never_exceeds_the_limit() {
        let mut station = load(json!({"connectorCount": 8}));
        assert_eq!(connector_count(&station), 8);
        station.connector_count = 5_000;
        assert_eq!(connector_count(&station), MAX_CONNECTORS);
        station.connector_count = -3;
        assert_eq!(connector_count(&station), 1);
        for (stored, expected) in
            [(json!(0), 1), (json!(9), 1), (json!(true), 1), (json!("2"), 1), (json!(2.0), 1), (json!(3), 3)]
        {
            assert_eq!(load(json!({"connectorCount": stored})).connector_count, expected);
        }
    }

    #[test]
    fn ensure_connector_is_a_backstop() {
        let mut station = Station::new("GRD-1", &Settings::defaults());
        for impossible in [0, -1, 9, 4_000_000_000] {
            assert!(station.ensure_connector(impossible).is_err());
        }
        assert!(station.connectors.is_empty());
        station.ensure_connector(3).unwrap().mode = Mode::Inactive;
        assert_eq!(station.connector_count, 3);
        assert_eq!(station.ensure_connector(3).unwrap().mode, Mode::Inactive);
        station.ensure_connectors();
        assert_eq!(station.connectors.len(), 3);
    }

    #[test]
    fn boot_and_configuration_payloads_are_stored_bounded() {
        let payload = json!({
            "chargePointModel": "M".repeat(5000), "chargePointVendor": 12, "firmwareVersion": ["x"],
            "meterType": null, "somethingElse": "ignored",
        });
        let boot = boot_fields(payload.as_object().unwrap(), Some("now".into()));
        assert_eq!(boot["chargePointModel"].as_str().unwrap().len(), 100);
        assert_eq!(boot["chargePointVendor"], "12");
        assert_eq!(boot.keys().collect::<Vec<_>>(), ["chargePointVendor", "chargePointModel", "timestamp"]);
        assert!(boot_fields(&Object::new(), None).is_empty());

        let mut items: Vec<Value> =
            (0..1000).map(|i| json!({"key": format!("k{i}"), "value": "v".repeat(2000)})).collect();
        items.insert(0, json!({"key": 5, "value": "x"}));
        items.insert(1, json!({"key": "", "value": "x"}));
        items.insert(2, json!({"key": "k".repeat(101), "value": "x"}));
        items.insert(3, json!({"key": "Number", "value": 34}));
        items.insert(4, json!({"key": "List", "value": [1]}));
        items.insert(5, json!("not an object"));
        let config = clean_config(&Value::from(items));
        assert_eq!(config.len(), MAX_CONFIG_KEYS - 4);
        assert_eq!((&config["Number"], &config["List"]), (&json!("34"), &json!(null)));
        assert_eq!(config["k0"].as_str().unwrap().len(), 500);
        assert!(clean_config(&json!("x")).is_empty());
    }
}
