//! Persistence: a JSON document for live state, SQLite for history.
//!
//! Both files are in the format the Python versions of this server wrote, so an existing data
//! directory carries on as it is.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{Duration, Utc};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection as Database};
use serde_json::{Map, Number, Value};

use crate::value::Object;

/// state.json holds the API's bearer tokens and the charger's cloud Auth key: owner-only.
const PRIVATE_FILE: u32 = 0o600;
/// History kept per station, whatever its age. A charger reporting every 30 s fills about a
/// quarter of this in the 90 days samples are kept for; what a station sends beyond it replaces
/// its own oldest rows instead of growing the database without end.
pub const MAX_SAMPLES_PER_STATION: i64 = 1_000_000;
pub const MAX_SESSIONS_PER_STATION: i64 = 100_000;
/// The largest integer SQLite stores. A transaction counter at or beyond it in state.json (a damaged
/// or hand-edited file) can never be recorded, so numbering does not continue from it.
pub const LAST_ID: i64 = i64::MAX;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY,
        station TEXT NOT NULL,
        connector INTEGER NOT NULL,
        id_tag TEXT,
        start_at TEXT NOT NULL,
        stop_at TEXT,
        meter_start INTEGER,
        meter_stop INTEGER,
        energy_wh REAL,
        duration_s INTEGER,
        price_kwh REAL,
        cost REAL,
        reason TEXT
    );
    CREATE TABLE IF NOT EXISTS samples (
        station TEXT NOT NULL,
        connector INTEGER NOT NULL,
        transaction_id INTEGER,
        at TEXT NOT NULL,
        energy_wh REAL,
        power_w REAL,
        current_a REAL,
        voltage_v REAL,
        temperature_c REAL,
        soc REAL
    );
    CREATE INDEX IF NOT EXISTS samples_station_at ON samples(station, at);
    CREATE INDEX IF NOT EXISTS samples_station_tx ON samples(station, transaction_id, at);
    CREATE INDEX IF NOT EXISTS sessions_station_start ON sessions(station, start_at);
";

fn restrict(path: &Path) {
    // Ignored on a filesystem without Unix permissions (SMB, some NAS datasets), and for a file
    // that isn't there yet.
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE));
}

/// state.json as a strict parser accepts it, where the Python versions of this server read and
/// wrote something it does not:
///
/// - `NaN`, `Infinity` and `-Infinity` (outside strings) become `null`: JSON proper has no
///   spelling for them;
/// - so does a number too large to be one (`1e400`, an integer of four hundred digits);
/// - so does a value nested deeper than [`MAX_STATE_NESTING`];
/// - half of a surrogate pair written as an escape (`"\ud83d"` with nothing to pair with: Python
///   kept such text as it came from a charger) becomes U+FFFD, the "not a character" character.
///
/// Any of them would otherwise have the whole file called corrupt, and every station forgotten,
/// over one value that nothing uses.
fn repaired(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut copied = 0;
    let mut depth = 0usize;
    // Is there an escape at `at` that spells half of a surrogate pair, and is it the first half?
    let surrogate = |at: usize| -> Option<bool> {
        let digits = bytes.get(at..at + 6).filter(|escape| escape.starts_with(b"\\u"))?;
        let code = u32::from_str_radix(std::str::from_utf8(&digits[2..]).ok()?, 16).ok()?;
        (0xD800..0xE000).contains(&code).then_some(code < 0xDC00)
    };
    // Where the string that opens at `at` ends (just past its closing quote).
    let string_end = |mut at: usize| -> usize {
        at += 1;
        while at < bytes.len() && bytes[at] != b'"' {
            at += if bytes[at] == b'\\' { 2 } else { 1 };
        }
        (at + 1).min(bytes.len())
    };
    while at < bytes.len() {
        // `text[copied..at]` is as it was; `with` goes in place of `text[at..end]`.
        let mut replace = |at: usize, end: usize, with: &str| {
            out.push_str(&text[copied..at]);
            out.push_str(with);
            copied = end;
        };
        match bytes[at] {
            b'"' => {
                let end = string_end(at);
                at += 1;
                while at < end {
                    match surrogate(at) {
                        Some(true) if surrogate(at + 6) == Some(false) => at += 12, // a proper pair
                        Some(_) => {
                            replace(at, at + 6, "\\ufffd");
                            at += 6;
                        }
                        None => at += if bytes[at] == b'\\' { 2 } else { 1 },
                    }
                }
                at = end;
            }
            b'[' | b'{' if depth == MAX_STATE_NESTING => {
                // Too deep to keep: skip to the bracket that closes it.
                let start = at;
                let mut inside = 0usize;
                while at < bytes.len() {
                    match bytes[at] {
                        b'"' => at = string_end(at) - 1,
                        b'[' | b'{' => inside += 1,
                        b']' | b'}' => inside -= 1,
                        _ => {}
                    }
                    at += 1;
                    if inside == 0 {
                        break;
                    }
                }
                replace(start, at, "null");
            }
            b'[' | b'{' => {
                depth += 1;
                at += 1;
            }
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                at += 1;
            }
            _ => {
                let rest = &text[at..];
                let word = ["-Infinity", "Infinity", "NaN"].into_iter().find(|word| rest.starts_with(word));
                let number =
                    rest.find(|c: char| !matches!(c, '0'..='9' | '.' | 'e' | 'E' | '+' | '-')).unwrap_or(rest.len());
                if let Some(word) = word {
                    replace(at, at + word.len(), "null");
                    at += word.len();
                } else if number > 0 {
                    let token = &rest[..number];
                    if is_json_number(token) && serde_json::from_str::<f64>(token).is_err() {
                        // Usually because it is too large. (Right at the largest number there is,
                        // the parser also refuses some long spellings of numbers that do fit:
                        // those are written the short way.)
                        let fits = token.parse::<f64>().ok().and_then(Number::from_f64);
                        replace(at, at + number, &fits.map_or("null".to_string(), |number| number.to_string()));
                    }
                    at += number;
                } else {
                    at += rest.chars().next().map_or(1, char::len_utf8);
                }
            }
        }
    }
    out.push_str(&text[copied.min(text.len())..]);
    out
}

/// Is this how JSON writes a number (whatever its size)?
fn is_json_number(token: &str) -> bool {
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let token = token.strip_prefix('-').unwrap_or(token);
    let (mantissa, exponent) = match token.find(['e', 'E']) {
        Some(at) => (&token[..at], Some(&token[at + 1..])),
        None => (token, None),
    };
    let (whole, fraction) = match mantissa.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (mantissa, None),
    };
    digits(whole)
        && (whole == "0" || !whole.starts_with('0'))
        && fraction.is_none_or(digits)
        && exponent.is_none_or(|exponent| digits(exponent.strip_prefix(['+', '-']).unwrap_or(exponent)))
}

/// A JSON text in ASCII: every other character as a `\uXXXX` escape (they only occur in strings).
///
/// This is how the Python versions wrote state.json, and it makes the file mean the same to
/// every reader, whatever encoding that reader assumes (tools/firmware_capture.py under a locale
/// that is not UTF-8, a 0.8 server gone back to).
fn ascii_json(text: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii() {
            out.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

/// How deep the brackets of a JSON text nest.
fn nesting(text: &str) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// state.json nests a handful of levels, plus whatever a zone's uninterpreted fields hold (a
/// request can nest 128 deep). The parser's own limit of 128 is too tight for that sum; this
/// one still stops a damaged file from exhausting the stack. What is nested deeper is dropped.
const MAX_STATE_NESTING: usize = 256;

fn parse_state(text: &str) -> Option<Value> {
    let mut reader = serde_json::Deserializer::from_str(text);
    reader.disable_recursion_limit();
    let value = serde::Deserialize::deserialize(&mut reader).ok()?;
    reader.end().ok()?;
    Some(value)
}

/// One meter reading for the history.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sample {
    pub station: String,
    pub connector: i64,
    pub transaction_id: Option<i64>,
    pub at: String,
    pub energy_wh: Option<f64>,
    pub power_w: Option<f64>,
    pub current_a: Option<f64>,
    pub voltage_v: Option<f64>,
    pub temperature_c: Option<f64>,
    pub soc: Option<f64>,
}

type DbResult<T> = Result<T, rusqlite::Error>;

pub struct Store {
    state_path: PathBuf,
    db: Database,
    /// Rows per station, counted once and kept up to date.
    sample_counts: HashMap<String, i64>,
    pub max_samples: i64,
    pub max_sessions: i64,
}

fn row_object(row: &rusqlite::Row<'_>, columns: &[String]) -> DbResult<Object> {
    let mut object = Map::with_capacity(columns.len());
    for (index, name) in columns.iter().enumerate() {
        let value = match row.get_ref(index)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(int) => Value::from(int),
            ValueRef::Real(real) => Number::from_f64(real).map_or(Value::Null, Value::Number),
            ValueRef::Text(text) => Value::from(String::from_utf8_lossy(text).into_owned()),
            ValueRef::Blob(_) => Value::Null,
        };
        object.insert(name.clone(), value);
    }
    Ok(object)
}

impl Store {
    /// Open (creating what is missing) the data directory. Returns the store and whatever
    /// state.json held: an empty object if there was none, or if what it holds is not a state (it
    /// is then set aside as `state.corrupt.json`).
    ///
    /// A state.json that is there but cannot be read (it belongs to another user, the disk gives
    /// an error) is an error and is left alone: starting empty over it would forget every station
    /// for a problem that `chown` fixes.
    pub fn open(data_dir: &Path) -> Result<(Store, Object), String> {
        fs::create_dir_all(data_dir).map_err(|err| format!("cannot create {}: {err}", data_dir.display()))?;
        let state_path = data_dir.join("state.json");
        let db_path = data_dir.join("history.sqlite");
        let db = Database::open(&db_path).map_err(|err| format!("cannot open {}: {err}", db_path.display()))?;
        db.execute_batch(SCHEMA).map_err(|err| format!("cannot use {}: {err}", db_path.display()))?;
        // After the history: a state.json that has to be set aside is not set aside by a start
        // that then fails anyway.
        let state = Store::load(&state_path)?;
        for path in [&state_path, &db_path] {
            restrict(path);
        }
        let store = Store {
            state_path,
            db,
            sample_counts: HashMap::new(),
            max_samples: MAX_SAMPLES_PER_STATION,
            max_sessions: MAX_SESSIONS_PER_STATION,
        };
        Ok((store, state))
    }

    // --- JSON state ---------------------------------------------------------

    fn load(path: &Path) -> Result<Object, String> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Object::new()),
            Err(err) => return Err(format!("cannot read {}: {err}", path.display())),
        };
        let parsed = String::from_utf8(bytes).ok().and_then(|text| {
            // As it is, if it can be; else with what a strict parser cannot take mended or cut out.
            let as_it_is = if nesting(&text) <= MAX_STATE_NESTING { parse_state(&text) } else { None };
            as_it_is.or_else(|| parse_state(&repaired(&text)))
        });
        match parsed {
            Some(Value::Object(state)) => Ok(state),
            _ => {
                let backup = path.with_extension("corrupt.json");
                log::error!("state.json is corrupt, moving it to {}", backup.display());
                fs::rename(path, &backup)
                    .map_err(|err| format!("{} is corrupt and cannot be moved aside: {err}", path.display()))?;
                restrict(&backup); // it may still hold sessions and the charger's Auth key
                Ok(Object::new())
            }
        }
    }

    /// Replace state.json with `state`, written to a temporary file first and flushed to disk.
    pub fn write_state(&self, state: &Value) -> std::io::Result<()> {
        let tmp = self.state_path.with_extension("tmp");
        let mut payload = Vec::with_capacity(4096);
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut payload, formatter);
        serde::Serialize::serialize(state, &mut serializer).map_err(std::io::Error::other)?;
        let payload = ascii_json(&String::from_utf8_lossy(&payload));
        let mut file: File =
            OpenOptions::new().write(true).create(true).truncate(true).mode(PRIVATE_FILE).open(&tmp)?;
        restrict(&tmp); // the mode above only applies when the file is new
        file.write_all(payload.as_bytes())?;
        // Without this a power cut can leave the renamed file empty, and an empty state means
        // every station (and every pinned Auth key) is forgotten.
        let _ = file.sync_all();
        drop(file);
        fs::rename(&tmp, &self.state_path)
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// A transaction id no recorded session has, whatever state.json remembers.
    ///
    /// The counter is saved with the rest of the state, a few seconds after the session row is
    /// committed: after a crash in between (or a lost state file) it is behind the history.
    pub fn unused_id(&self, counter: i64) -> i64 {
        let counter = if (1..LAST_ID).contains(&counter) { counter } else { 1 };
        let newest: Option<i64> = self
            .db
            .query_row("SELECT MAX(id) FROM sessions WHERE id < ?", params![LAST_ID], |row| row.get(0))
            .unwrap_or(None);
        counter.max(newest.unwrap_or(0) + 1)
    }

    // --- SQLite history -----------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn start_session(
        &mut self,
        tid: i64,
        station: &str,
        connector: i64,
        id_tag: Option<&str>,
        start_at: &str,
        meter_start: Option<i64>,
        price_kwh: Option<f64>,
    ) -> DbResult<()> {
        // A plain INSERT: ids are never reused, and if one ever were, failing here is better
        // than quietly replacing a recorded session.
        self.db.execute(
            "INSERT INTO sessions(id, station, connector, id_tag, start_at, meter_start, price_kwh)
             VALUES (?,?,?,?,?,?,?)",
            params![tid, station, connector, id_tag, start_at, meter_start, price_kwh],
        )?;
        Ok(())
    }

    /// Close a session. `price_kwh` (the average it was charged at) replaces the starting price if given.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_session(
        &mut self,
        tid: i64,
        stop_at: &str,
        meter_stop: Option<i64>,
        energy_wh: Option<f64>,
        duration_s: Option<i64>,
        cost: Option<f64>,
        reason: Option<&str>,
        price_kwh: Option<f64>,
    ) -> DbResult<()> {
        self.db.execute(
            "UPDATE sessions SET stop_at=?, meter_stop=?, energy_wh=?, duration_s=?, cost=?, reason=?,
             price_kwh=COALESCE(?, price_kwh) WHERE id=?",
            params![stop_at, meter_stop, energy_wh, duration_s, cost, reason, price_kwh, tid],
        )?;
        Ok(())
    }

    /// Insert several samples in one transaction (one commit, however many readings a message carries).
    pub fn add_samples(&mut self, rows: &[Sample]) -> DbResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let transaction = self.db.transaction()?;
        {
            let mut insert = transaction.prepare_cached(
                "INSERT INTO samples(station, connector, transaction_id, at, energy_wh, power_w, current_a,
                 voltage_v, temperature_c, soc) VALUES (?,?,?,?,?,?,?,?,?,?)",
            )?;
            for row in rows {
                insert.execute(params![
                    row.station,
                    row.connector,
                    row.transaction_id,
                    row.at,
                    row.energy_wh,
                    row.power_w,
                    row.current_a,
                    row.voltage_v,
                    row.temperature_c,
                    row.soc
                ])?;
            }
        }
        transaction.commit()?;
        let mut added: HashMap<&str, i64> = HashMap::new();
        for row in rows {
            *added.entry(row.station.as_str()).or_default() += 1;
        }
        for (station, count) in added {
            self.trim_samples(station, count)?;
        }
        Ok(())
    }

    /// Keep a station within `max_samples` (plus a tenth of slack, so trimming is rare).
    fn trim_samples(&mut self, station: &str, added: i64) -> DbResult<()> {
        let mut count = match self.sample_counts.get(station) {
            Some(count) => count + added,
            None => {
                self.db.query_row("SELECT COUNT(*) FROM samples WHERE station=?", params![station], |r| r.get(0))?
            }
        };
        let excess = count - self.max_samples;
        if excess > self.max_samples / 10 {
            self.db.execute(
                "DELETE FROM samples WHERE rowid IN
                 (SELECT rowid FROM samples WHERE station=? ORDER BY at LIMIT ?)",
                params![station, excess],
            )?;
            count -= excess;
        }
        self.sample_counts.insert(station.to_string(), count);
        Ok(())
    }

    fn rows(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> DbResult<Vec<Object>> {
        let mut statement = self.db.prepare_cached(sql)?;
        let columns: Vec<String> = statement.column_names().map(str::to_string).collect();
        let rows = statement.query_map(params, |row| row_object(row, &columns))?;
        rows.collect()
    }

    /// A station's sessions, newest first.
    pub fn sessions(&self, station: &str, limit: i64) -> DbResult<Vec<Object>> {
        self.rows("SELECT * FROM sessions WHERE station=? ORDER BY start_at DESC LIMIT ?", &[&station, &limit])
    }

    pub fn samples(&self, station: &str, since: &str, connector: Option<i64>, limit: i64) -> DbResult<Vec<Object>> {
        match connector {
            None => self.rows(
                "SELECT * FROM samples WHERE station=? AND at>=? ORDER BY at LIMIT ?",
                &[&station, &since, &limit],
            ),
            Some(connector) => self.rows(
                "SELECT * FROM samples WHERE station=? AND connector=? AND at>=? ORDER BY at LIMIT ?",
                &[&station, &connector, &since, &limit],
            ),
        }
    }

    /// A transaction's energy readings in time order, for repricing: `(at, energy_wh)`.
    pub fn energy_samples(&self, station: &str, tid: i64) -> DbResult<Vec<(String, f64)>> {
        let mut statement = self.db.prepare_cached(
            "SELECT at, energy_wh FROM samples WHERE station=? AND transaction_id=? AND energy_wh IS NOT NULL
             ORDER BY at",
        )?;
        let rows = statement.query_map(params![station, tid], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// Update many sessions' costs in one transaction: `(id, cost, price per kWh)` each.
    pub fn set_session_costs(&mut self, rows: &[(i64, f64, Option<f64>)]) -> DbResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let transaction = self.db.transaction()?;
        {
            let mut update = transaction.prepare_cached("UPDATE sessions SET cost=?, price_kwh=? WHERE id=?")?;
            for (tid, cost, price_kwh) in rows {
                update.execute(params![cost, price_kwh, tid])?;
            }
        }
        transaction.commit()
    }

    /// Drop samples older than `keep_days`, and the oldest finished sessions of a station that
    /// has more than `max_sessions` (a number no real charger reaches in decades).
    pub fn prune_samples(&mut self, keep_days: i64) -> DbResult<()> {
        // Sample times are ISO 8601 with a "T"; compare against the same spelling.
        let cutoff = (Utc::now() - Duration::days(keep_days)).format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
        let max_sessions = self.max_sessions;
        let transaction = self.db.transaction()?;
        transaction.execute("DELETE FROM samples WHERE at < ?", params![cutoff])?;
        let crowded: Vec<(String, i64)> = {
            let mut statement =
                transaction.prepare("SELECT station, COUNT(*) FROM sessions GROUP BY station HAVING COUNT(*) > ?")?;
            let rows = statement.query_map(params![max_sessions], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<DbResult<_>>()?
        };
        for (station, count) in crowded {
            transaction.execute(
                "DELETE FROM sessions WHERE id IN
                 (SELECT id FROM sessions WHERE station=? AND stop_at IS NOT NULL ORDER BY start_at LIMIT ?)",
                params![station, count - max_sessions],
            )?;
        }
        transaction.commit()?;
        self.sample_counts.clear(); // recount after pruning
        Ok(())
    }

    /// Remove everything recorded for a station (it is being forgotten).
    pub fn delete_history(&mut self, station: &str) -> DbResult<()> {
        let transaction = self.db.transaction()?;
        transaction.execute("DELETE FROM samples WHERE station=?", params![station])?;
        transaction.execute("DELETE FROM sessions WHERE station=?", params![station])?;
        transaction.commit()?;
        self.sample_counts.remove(station);
        Ok(())
    }

    /// The database itself, for tests that look at how it is used.
    pub fn database(&self) -> &Database {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn open(dir: &Path) -> (Store, Object) {
        Store::open(dir).unwrap()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn sample(station: &str, at: &str, energy: f64) -> Sample {
        Sample { station: station.into(), connector: 1, at: at.into(), energy_wh: Some(energy), ..Sample::default() }
    }

    #[test]
    fn state_and_history_files_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let (store, state) = open(dir.path());
        assert!(state.is_empty());
        store.write_state(&json!({"stations": {}})).unwrap();
        assert_eq!(mode(&dir.path().join("state.json")), 0o600);
        assert_eq!(mode(&dir.path().join("history.sqlite")), 0o600);
        assert!(!dir.path().join("state.tmp").exists());
        // A file an older version left world-readable is tightened when the store opens.
        fs::set_permissions(dir.path().join("state.json"), fs::Permissions::from_mode(0o644)).unwrap();
        drop(store);
        let (_store, state) = open(dir.path());
        assert_eq!(mode(&dir.path().join("state.json")), 0o600);
        assert_eq!(Value::Object(state), json!({"stations": {}}));
    }

    #[test]
    fn the_first_save_after_a_crash_is_private_too() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open(dir.path());
        // A temporary file left behind by a crash, readable by everyone.
        fs::write(dir.path().join("state.tmp"), "{").unwrap();
        fs::set_permissions(dir.path().join("state.tmp"), fs::Permissions::from_mode(0o644)).unwrap();
        store.write_state(&json!({"a": 1})).unwrap();
        assert_eq!(mode(&dir.path().join("state.json")), 0o600);
        assert_eq!(fs::read_to_string(dir.path().join("state.json")).unwrap(), "{\n \"a\": 1\n}");
    }

    #[test]
    fn state_file_that_is_not_an_object_is_set_aside() {
        for corrupt in ["[1, 2, 3]", "\"text\"", "{\"stations\": ", "", "\u{0}\u{1}"] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("state.json"), corrupt).unwrap();
            let (_store, state) = open(dir.path());
            assert!(state.is_empty(), "{corrupt:?}");
            assert!(!dir.path().join("state.json").exists());
            let backup = dir.path().join("state.corrupt.json");
            assert_eq!(fs::read_to_string(&backup).unwrap(), corrupt);
            assert_eq!(mode(&backup), 0o600);
        }
    }

    #[test]
    fn state_file_non_finite_numbers_are_dropped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("state.json"),
            r#"{"stations": {"GRD-1": {"priceKW": NaN, "displayName": "NaN and \"Infinity\"", "a": [Infinity, -Infinity, 1]}}}"#,
        )
        .unwrap();
        let (_store, state) = open(dir.path());
        assert_eq!(
            Value::Object(state),
            json!({"stations": {"GRD-1": {"priceKW": null, "displayName": "NaN and \"Infinity\"", "a": [null, null, 1]}}})
        );
        assert!(dir.path().join("state.json").exists());
    }

    /// Python read and wrote half a surrogate pair as an escape (a charger's DataTransfer text was
    /// stored as it came). Such a file is still the owner's stations, keys and schedules.
    #[test]
    fn state_file_with_half_a_surrogate_pair_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("state.json"),
            r#"{"stations": {"GRD-1": {"displayName": "half \ud83d", "b": "\ude00 other half", "c": "pair \ud83d\ude00",
                "d": "two firsts \ud83d\ud83d\ude00", "e": "a backslash \\ud83d", "f": "\ud83d", "\udfff": NaN}}}"#,
        )
        .unwrap();
        let (_store, state) = open(dir.path());
        assert_eq!(
            Value::Object(state),
            json!({"stations": {"GRD-1": {"displayName": "half \u{fffd}", "b": "\u{fffd} other half", "c": "pair \u{1f600}",
                "d": "two firsts \u{fffd}\u{1f600}", "e": "a backslash \\ud83d", "f": "\u{fffd}", "\u{fffd}": null}}})
        );
        assert!(dir.path().join("state.json").exists());
        assert!(!dir.path().join("state.corrupt.json").exists());
    }

    /// A zone keeps fields it does not interpret, and such a field may nest as deep as a request
    /// may (128): with the levels above it, deeper than a JSON parser takes by default.
    #[test]
    fn state_file_may_nest_deeper_than_a_request() {
        let nested = |depth: usize| {
            format!(r#"{{"stations": {{"GRD-1": {{"x": {}1{}}}}}}}"#, "[".repeat(depth), "]".repeat(depth))
        };
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("state.json"), nested(200)).unwrap();
        let (_store, state) = open(dir.path());
        let mut inner = &state["stations"]["GRD-1"]["x"];
        let mut depth = 0;
        while let Some(next) = inner.get(0) {
            inner = next;
            depth += 1;
        }
        assert_eq!((depth, inner), (200, &json!(1)));
        assert!(!dir.path().join("state.corrupt.json").exists());
        // Deeper than that, a value is dropped by itself and everything around it is kept.
        for depth in [MAX_STATE_NESTING, 100_000] {
            let dir = tempfile::tempdir().unwrap();
            let text =
                nested(depth).replace(r#"{"x":"#, r#"{"id": "GRD-1", "x":"#).replace("}}}", r#", "after": 7}}}"#);
            fs::write(dir.path().join("state.json"), text).unwrap();
            let (_store, state) = open(dir.path());
            let station = &state["stations"]["GRD-1"];
            assert_eq!((&station["id"], &station["after"]), (&json!("GRD-1"), &json!(7)), "{depth}");
            let mut inner = &station["x"];
            let mut kept = 3; // the levels above "x"
            while let Some(next) = inner.get(0) {
                inner = next;
                kept += 1;
            }
            assert_eq!((kept, inner), (MAX_STATE_NESTING, &Value::Null), "{depth}");
            assert!(!dir.path().join("state.corrupt.json").exists());
        }
        // Brackets that are never closed are no state at all, however many there are.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("state.json"), format!(r#"{{"stations": {}"#, "[".repeat(100_000))).unwrap();
        assert!(open(dir.path()).1.is_empty());
        assert!(dir.path().join("state.corrupt.json").exists());
        assert_eq!(nesting(r#"{"a": "[[[ \" [[", "b": [{"c": []}, []]}"#), 4);
    }

    /// state.json is written the way Python's json module wrote it: one space of indent, ASCII
    /// only. Byte for byte, so that whatever read the old file reads the new one.
    #[test]
    fn state_file_is_written_as_the_python_versions_wrote_it() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open(dir.path());
        let state = json!({"stations": {"GRD-1": {"displayName": "Garage é 😀 \u{2028}", "n": [1, 2.5, null], "e": {}}}, "tokens": {}});
        store.write_state(&state).unwrap();
        let written = fs::read_to_string(dir.path().join("state.json")).unwrap();
        // json.dumps(state, indent=1) gives exactly this.
        let expected = "{\n \"stations\": {\n  \"GRD-1\": {\n   \"displayName\": \"Garage \\u00e9 \\ud83d\\ude00 \\u2028\",\n   \"n\": [\n    1,\n    2.5,\n    null\n   ],\n   \"e\": {}\n  }\n },\n \"tokens\": {}\n}";
        assert_eq!(written, expected);
        assert!(written.is_ascii());
        let (_store, read_back) = open(dir.path());
        assert_eq!(Value::Object(read_back), state);
    }

    /// Python read `1e400` as infinity and an integer of any length as that integer, and kept
    /// the station either way. Such a number is nothing we can use; the rest of the file is.
    #[test]
    fn state_file_numbers_too_large_to_be_numbers_are_dropped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let huge = "9".repeat(400);
        let text = format!(
            r#"{{"stations": {{"GRD-1": {{"ocppAuthKey": "kept", "connectorCount": {huge}, "a": [1e400, -1E+999, 2e308, -{huge}],
                "fine": [1e308, 1e-400, 18446744073709551616, -0, 1.5e3], "text": "1e400 and {huge}"}}}}}}"#
        );
        fs::write(dir.path().join("state.json"), text).unwrap();
        let (_store, state) = open(dir.path());
        let station = &state["stations"]["GRD-1"];
        assert_eq!(station["ocppAuthKey"], "kept");
        assert_eq!(station["connectorCount"], Value::Null);
        assert_eq!(station["a"], json!([null, null, null, null]));
        // The largest number there is, in spellings the parser trips over: still that number.
        let dir = tempfile::tempdir().unwrap();
        let largest = r#"{"a": [1.7976931348623158e308, 1797693134862315700e290, 1.797693134862315700000e308, 1e400]}"#;
        fs::write(dir.path().join("state.json"), largest).unwrap();
        assert_eq!(Value::Object(open(dir.path()).1), json!({"a": [f64::MAX, f64::MAX, f64::MAX, null]}));
        assert_eq!(station["fine"], json!([1e308, 0.0, 18446744073709551616.0, -0.0, 1500.0]));
        assert_eq!(station["text"], format!("1e400 and {huge}"));
        assert!(!dir.path().join("state.corrupt.json").exists());
        // What is not a number at all is still not a state.
        for garbage in [r#"{"a": 1.2.3}"#, r#"{"a": 01}"#, r#"{"a": 1e}"#, r#"{"a": -}"#, r#"{"a": 1e400x}"#] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("state.json"), garbage).unwrap();
            assert!(open(dir.path()).1.is_empty(), "{garbage}");
            assert!(dir.path().join("state.corrupt.json").exists(), "{garbage}");
        }
        for (token, number) in
            [("0", true), ("-0.5e+10", true), ("12E3", true), ("01", false), ("1.", false), (".5", false)]
        {
            assert_eq!(is_json_number(token), number, "{token}");
        }
        for token in ["", "-", "1e", "1e+", "--1", "1.2.3", "+1", "e5", "1e5.0"] {
            assert!(!is_json_number(token), "{token}");
        }
    }

    /// Unreadable is not corrupt: the file is somebody's stations and keys, and the fix is on
    /// the outside (`chown`, a disk that answers). Starting empty over it would be the damage.
    #[test]
    fn state_file_that_cannot_be_read_stops_the_start_and_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::create_dir(&path).unwrap(); // reading it fails, whoever runs the test
        let err = Store::open(dir.path()).err().unwrap();
        assert!(err.starts_with("cannot read ") && err.contains("state.json"), "{err}");
        assert!(path.is_dir());
        assert!(!dir.path().join("state.corrupt.json").exists());
    }

    #[test]
    fn transaction_ids_never_reuse_recorded_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = open(dir.path());
        assert_eq!(store.unused_id(1), 1);
        store.start_session(41, "GRD-1", 1, Some("tag"), "2026-11-08T00:00:00.000Z", Some(100), Some(0.1)).unwrap();
        assert_eq!(store.unused_id(1), 42, "the history is ahead of a lost counter");
        assert_eq!(store.unused_id(100), 100);
        for impossible in [0, -5, LAST_ID] {
            assert_eq!(store.unused_id(impossible), 42);
        }
        assert_eq!(store.unused_id(LAST_ID - 1), LAST_ID - 1);
        assert!(store.start_session(41, "GRD-1", 1, None, "2026-11-08T00:00:00.000Z", None, None).is_err());
    }

    #[test]
    fn large_transaction_ids_that_can_be_stored_keep_counting() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = open(dir.path());
        store.start_session(LAST_ID - 10, "GRD-1", 1, None, "2026-11-08T00:00:00.000Z", None, None).unwrap();
        assert_eq!(store.unused_id(5), LAST_ID - 9);
        // A session recorded under the very last id is not counted on from.
        store.start_session(LAST_ID, "GRD-1", 1, None, "2026-11-08T00:00:00.000Z", None, None).unwrap();
        assert_eq!(store.unused_id(5), LAST_ID - 9);
    }

    #[test]
    fn sessions_and_samples_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = open(dir.path());
        store.start_session(1, "GRD-1", 2, Some("tag"), "2026-11-08T10:00:00.000Z", Some(1000), Some(0.1)).unwrap();
        store
            .finish_session(
                1,
                "2026-11-08T11:00:00.000Z",
                Some(6000),
                Some(5000.0),
                Some(3600),
                Some(0.75),
                Some("Local"),
                Some(0.15),
            )
            .unwrap();
        store.start_session(2, "GRD-1", 1, None, "2026-11-08T12:00:00.000Z", None, None).unwrap();
        store.finish_session(2, "2026-11-08T12:30:00.000Z", None, None, None, None, None, None).unwrap();
        let sessions = store.sessions("GRD-1", 50).unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0]["id"], 2, "newest first");
        assert_eq!(
            Value::Object(sessions[1].clone()),
            json!({"id": 1, "station": "GRD-1", "connector": 2, "id_tag": "tag", "start_at": "2026-11-08T10:00:00.000Z",
                "stop_at": "2026-11-08T11:00:00.000Z", "meter_start": 1000, "meter_stop": 6000, "energy_wh": 5000.0,
                "duration_s": 3600, "price_kwh": 0.15, "cost": 0.75, "reason": "Local"})
        );
        assert_eq!(store.sessions("GRD-1", 1).unwrap().len(), 1);
        assert!(store.sessions("GRD-2", 50).unwrap().is_empty());

        let mut second = sample("GRD-1", "2026-11-08T10:01:00.000Z", 1100.0);
        second.connector = 2;
        second.transaction_id = Some(1);
        store.add_samples(&[sample("GRD-1", "2026-11-08T10:00:30.000Z", 1050.0), second]).unwrap();
        assert_eq!(store.samples("GRD-1", "2026-11-08T00:00:00.000Z", None, 2000).unwrap().len(), 2);
        assert_eq!(store.samples("GRD-1", "2026-11-08T10:00:45.000Z", None, 2000).unwrap().len(), 1);
        assert_eq!(store.samples("GRD-1", "2026-11-08T00:00:00.000Z", Some(2), 2000).unwrap().len(), 1);
        assert_eq!(store.energy_samples("GRD-1", 1).unwrap(), [("2026-11-08T10:01:00.000Z".to_string(), 1100.0)]);

        store.set_session_costs(&[(1, 1.25, Some(0.25)), (2, 0.0, None)]).unwrap();
        let sessions = store.sessions("GRD-1", 50).unwrap();
        assert_eq!((&sessions[1]["cost"], &sessions[1]["price_kwh"]), (&json!(1.25), &json!(0.25)));
        assert_eq!((&sessions[0]["cost"], &sessions[0]["price_kwh"]), (&json!(0.0), &json!(null)));

        store.delete_history("GRD-1").unwrap();
        assert!(store.sessions("GRD-1", 50).unwrap().is_empty());
        assert!(store.samples("GRD-1", "", None, 2000).unwrap().is_empty());
    }

    #[test]
    fn history_per_station_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = open(dir.path());
        store.max_samples = 100;
        let count = |store: &Store, station: &str| store.samples(station, "", None, 100_000).unwrap().len();
        store.add_samples(&[sample("GRD-OTHER", "2026-11-08T00:00:00.000Z", 1.0)]).unwrap();
        for batch in 0..30 {
            let rows: Vec<Sample> =
                (0..10).map(|i| sample("GRD-1", &format!("2026-11-08T{:02}:{:02}:00.000Z", batch, i), 1.0)).collect();
            store.add_samples(&rows).unwrap();
            assert!(count(&store, "GRD-1") <= 110, "never more than the limit plus a tenth");
        }
        assert!(count(&store, "GRD-1") >= 100);
        // The oldest went first, and nobody else's rows were touched.
        let kept = store.samples("GRD-1", "", None, 1).unwrap();
        assert!(kept[0]["at"].as_str().unwrap() > "2026-11-08T10:00:00.000Z");
        assert_eq!(count(&store, "GRD-OTHER"), 1);
    }

    #[test]
    fn pruning_removes_what_is_older_than_the_limit_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = open(dir.path());
        let ago = |days: i64| (Utc::now() - Duration::days(days)).format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
        store
            .add_samples(&[
                sample("GRD-1", &ago(91), 1.0),
                sample("GRD-1", &ago(89), 2.0),
                sample("GRD-1", &ago(0), 3.0),
            ])
            .unwrap();
        store.prune_samples(90).unwrap();
        let left: Vec<f64> =
            store.samples("GRD-1", "", None, 100).unwrap().iter().map(|r| r["energy_wh"].as_f64().unwrap()).collect();
        assert_eq!(left, [2.0, 3.0]);

        // Sessions are kept whatever their age, up to the limit; only finished ones make room.
        store.max_sessions = 3;
        for id in 1..=5 {
            store.start_session(id, "GRD-1", 1, None, &format!("2020-01-0{id}T00:00:00.000Z"), None, None).unwrap();
            if id != 1 {
                store.finish_session(id, "2020-01-09T00:00:00.000Z", None, None, None, None, None, None).unwrap();
            }
        }
        store.start_session(9, "GRD-2", 1, None, "2020-01-01T00:00:00.000Z", None, None).unwrap();
        store.prune_samples(90).unwrap();
        let ids: Vec<i64> = store.sessions("GRD-1", 50).unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, [5, 4, 1], "the two oldest finished sessions went; the open one stayed");
        assert_eq!(store.sessions("GRD-2", 50).unwrap().len(), 1);
    }

    #[test]
    fn the_history_queries_use_their_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open(dir.path());
        let plan = |sql: &str| -> String {
            let mut statement = store.database().prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let rows = statement.query_map([], |row| row.get::<_, String>(3)).unwrap();
            rows.map(Result::unwrap).collect::<Vec<_>>().join("; ")
        };
        let energy = plan(
            "SELECT at, energy_wh FROM samples WHERE station='x' AND transaction_id=1 AND energy_wh IS NOT NULL ORDER BY at",
        );
        assert!(energy.contains("samples_station_tx") && !energy.contains("TEMP B-TREE"), "{energy}");
        let sessions = plan("SELECT * FROM sessions WHERE station='x' ORDER BY start_at DESC LIMIT 5");
        assert!(sessions.contains("sessions_station_start") && !sessions.contains("TEMP B-TREE"), "{sessions}");
        let samples = plan("SELECT * FROM samples WHERE station='x' AND at>='y' ORDER BY at LIMIT 5");
        assert!(samples.contains("samples_station_at") && !samples.contains("TEMP B-TREE"), "{samples}");
    }
}
