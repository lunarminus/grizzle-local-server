//! Logging to stderr, one line per message whatever the message holds.
//!
//! Much of what is logged comes off the network (serials, OCPP actions, statuses). Every message
//! has its control characters escaped and its length bounded here, so a newline in such a value
//! cannot start what looks like a new, genuine log line.

use std::io::Write;
use std::sync::Mutex;

use chrono::Utc;
use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::zone::Tz;

pub const MAX_LOG_MESSAGE: usize = 4000;

/// Control characters, and the Unicode line separators.
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}')
}

fn escape_into(out: &mut String, c: char) {
    match c {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
        c => out.push_str(&format!("\\u{:04x}", c as u32)),
    }
}

/// Untrusted text as one bounded line: safe to log, and unable to forge a second log line.
pub fn printable(text: &str, limit: usize) -> String {
    let mut out = String::with_capacity(text.len().min(limit) + 16);
    let mut chars = text.chars();
    for c in chars.by_ref().take(limit) {
        if is_control(c) {
            escape_into(&mut out, c);
        } else {
            out.push(c);
        }
    }
    let rest = chars.count();
    if rest > 0 {
        out.push_str(&format!("...(+{rest} more)"));
    }
    out
}

/// Any JSON value as one bounded line (text as it is, everything else as its JSON spelling).
pub fn printable_value(value: &serde_json::Value, limit: usize) -> String {
    match value {
        serde_json::Value::String(text) => printable(text, limit),
        serde_json::Value::Null => "None".to_string(),
        other => printable(&other.to_string(), limit),
    }
}

/// One log line: time, level, where from, and the message made safe.
pub fn format_line(time: &str, level: Level, target: &str, message: &str) -> String {
    let level = match level {
        Level::Warn => "WARNING",
        Level::Error => "ERROR",
        Level::Info => "INFO",
        Level::Debug | Level::Trace => "DEBUG",
    };
    format!("{time} {level} {target}: {}", printable(message, MAX_LOG_MESSAGE))
}

struct StderrLogger {
    zone: Tz,
}

static CAPTURE: Mutex<Option<Vec<String>>> = Mutex::new(None);

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // LOG_LEVEL=debug is for our own messages (every OCPP frame); the libraries underneath
        // only get a word in when something is wrong.
        let ours = metadata.target().starts_with("grizzle_local");
        metadata.level() <= if ours { log::max_level() } else { LevelFilter::Warn.min(log::max_level()) }
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let time = Utc::now().with_timezone(&self.zone).format("%Y-%m-%d %H:%M:%S,%3f").to_string();
        let line = format_line(&time, record.level(), record.target(), &record.args().to_string());
        if let Some(lines) = CAPTURE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            lines.push(line.clone());
        }
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }

    fn flush(&self) {}
}

pub fn level_from_name(name: &str) -> LevelFilter {
    match name.trim().to_ascii_uppercase().as_str() {
        "DEBUG" | "TRACE" => LevelFilter::Debug,
        "WARNING" | "WARN" => LevelFilter::Warn,
        "ERROR" | "CRITICAL" | "FATAL" => LevelFilter::Error,
        _ => LevelFilter::Info,
    }
}

/// Send everything to stderr through the formatter that keeps network-supplied text on one line.
///
/// Times are written in the zone `TZ` names, else in the machine's own local time. Calling it
/// again only changes the level.
pub fn configure(level: &str) {
    let zone = std::env::var("TZ").ok().and_then(|name| name.parse().ok()).unwrap_or_else(Tz::local);
    let _ = log::set_boxed_logger(Box::new(StderrLogger { zone }));
    log::set_max_level(level_from_name(level));
}

/// Keep a copy of every line logged from now on (tests look for what the server said).
pub fn start_capture() {
    let mut capture = CAPTURE.lock().unwrap_or_else(|e| e.into_inner());
    if capture.is_none() {
        *capture = Some(Vec::new());
    }
}

/// The lines logged since [`start_capture`] that contain `needle`.
pub fn captured(needle: &str) -> Vec<String> {
    let capture = CAPTURE.lock().unwrap_or_else(|e| e.into_inner());
    capture.iter().flatten().filter(|line| line.contains(needle)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_cannot_span_lines() {
        let hostile = "GRD-1\n2026-01-01 00:00:00,000 INFO grizzle_local: all is well\r\x1b[2J\u{2028}\u{85}\x7f";
        let safe = printable(hostile, 200);
        assert!(!safe.chars().any(is_control), "{safe:?}");
        assert!(safe.starts_with("GRD-1\\n2026"));
        assert!(safe.contains("\\r\\x1b[2J\\u2028\\x85\\x7f"));
    }

    #[test]
    fn printable_is_bounded() {
        let long = "x".repeat(1000);
        assert_eq!(printable(&long, 10), "xxxxxxxxxx...(+990 more)");
        assert_eq!(printable("short", 10), "short");
        assert_eq!(printable_value(&serde_json::json!({"a": "b\nc"}), 100), "{\"a\":\"b\\nc\"}");
    }

    #[test]
    fn the_formatter_escapes_whatever_reaches_it() {
        let line = format_line("2026-01-01 00:00:00,000", Level::Warn, "grizzle_local::x", "one\ntwo");
        assert_eq!(line, "2026-01-01 00:00:00,000 WARNING grizzle_local::x: one\\ntwo");
        let long = format_line("t", Level::Info, "x", &"y".repeat(MAX_LOG_MESSAGE + 50));
        assert!(long.ends_with("...(+50 more)"));
    }
}
