//! Reading untrusted JSON: what a charger or an API client sent, or what an old state file holds.
//!
//! Every helper here is total. It takes whatever value is there and returns something typed and
//! bounded, or `None`.

use serde_json::{Map, Number, Value};

pub type Object = Map<String, Value>;

static NULL: Value = Value::Null;

/// `object[key]`, or null when the key is missing.
pub fn get<'a>(object: &'a Object, key: &str) -> &'a Value {
    object.get(key).unwrap_or(&NULL)
}

/// The first `limit` characters of `text`.
pub fn clip(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

pub fn char_len(text: &str) -> usize {
    text.chars().count()
}

/// Would a script call this value "true"? Null, false, zero, and empty text, lists and objects are not.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => !object.is_empty(),
    }
}

/// A value as text: strings as they are, everything else as its JSON spelling.
pub fn to_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        other => other.to_string(),
    }
}

/// The number, if the value is a JSON number that is a whole one (5, or 5.0).
pub fn whole_number(value: &Value) -> Option<i64> {
    let number = value.as_number()?;
    if let Some(int) = number.as_i64() {
        return Some(int);
    }
    if number.is_u64() {
        return None; // beyond i64: no bound we check against reaches that far
    }
    let float = number.as_f64()?;
    (float.fract() == 0.0 && float.abs() < 9.0e18).then_some(float as i64)
}

/// Text that is nothing but ASCII digits, at most `max_len` of them.
fn digits(text: &str, max_len: usize) -> Option<i64> {
    if text.is_empty() || text.len() > max_len || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// An integer in `lo..=hi` from an integer, an integral float or a short digit string.
pub fn small_int(value: &Value, lo: i64, hi: i64) -> Option<i64> {
    let number = match value {
        Value::Number(_) => whole_number(value)?,
        Value::String(text) => digits(text, 6)?,
        _ => return None,
    };
    (lo..=hi).contains(&number).then_some(number)
}

/// Text as a float the way chargers and forms spell numbers: surrounding spaces are allowed.
pub fn parse_float(text: &str) -> Option<f64> {
    let text = text.trim();
    // Rust would also take "infinity" and "nan"; both are caught by the callers' finiteness checks.
    if text.is_empty() || text.contains(|c: char| c.is_whitespace()) {
        return None;
    }
    text.parse::<f64>().ok()
}

/// A finite float from a number or numeric text, else `None`. Booleans are not numbers.
pub fn to_float(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => parse_float(text)?,
        _ => return None,
    };
    number.is_finite().then_some(number)
}

/// No meter reads beyond this, whatever the unit.
pub const MAX_READING: f64 = 1e12;

/// A meter reading: a finite number of plausible size, else `None`.
///
/// `text` also accepts numeric strings, which is how OCPP spells sampled values.
pub fn reading(value: &Value, text: bool) -> Option<f64> {
    let number = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(string) if text && string.len() <= 32 => parse_float(string)?,
        _ => return None,
    };
    (number.is_finite() && number.abs() <= MAX_READING).then_some(number)
}

/// A string field from a charger: text or a number, cut to `limit` characters; anything else is dropped.
pub fn text(value: &Value, limit: usize) -> Option<String> {
    match value {
        Value::String(string) => Some(clip(string, limit).to_string()),
        Value::Number(number) => Some(clip(&number.to_string(), limit).to_string()),
        _ => None,
    }
}

/// The objects in a JSON list, looking at no more than its first `limit` items.
pub fn objects(value: &Value, limit: usize) -> Vec<&Object> {
    match value {
        Value::Array(items) => items.iter().take(limit).filter_map(Value::as_object).collect(),
        _ => Vec::new(),
    }
}

/// A float as JSON: whole numbers without a fraction (`1000`, not `1000.0`), as chargers send them.
pub fn number(value: f64) -> Value {
    if !value.is_finite() {
        return Value::Null;
    }
    if value.fract() == 0.0 && value.abs() < 1e15 {
        return Value::Number(Number::from(value as i64));
    }
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

pub fn opt_number(value: Option<f64>) -> Value {
    value.map_or(Value::Null, number)
}

pub fn opt_text(value: &Option<String>) -> Value {
    value.as_ref().map_or(Value::Null, |text| Value::String(text.clone()))
}

pub fn opt_int(value: Option<i64>) -> Value {
    value.map_or(Value::Null, Value::from)
}

/// Round to `digits` decimals, the way the decimal expansion of the number rounds.
pub fn round_to(value: f64, digits: usize) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    format!("{value:.digits$}").parse().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn small_int_takes_what_can_only_be_a_number() {
        assert_eq!(small_int(&json!(3), 1, 8), Some(3));
        assert_eq!(small_int(&json!(3.0), 1, 8), Some(3));
        assert_eq!(small_int(&json!("3"), 1, 8), Some(3));
        for bad in
            [json!(true), json!(3.5), json!("3 "), json!("1234567"), json!(9), json!(null), json!([3]), json!("٣")]
        {
            assert_eq!(small_int(&bad, 1, 8), None, "{bad}");
        }
    }

    #[test]
    fn readings_are_finite_and_plausible() {
        assert_eq!(reading(&json!(12.5), false), Some(12.5));
        assert_eq!(reading(&json!("12.5"), true), Some(12.5));
        assert_eq!(reading(&json!("12.5"), false), None);
        for bad in [json!("NaN"), json!("Infinity"), json!("-inf"), json!("1e13"), json!(true), json!("x"), json!(1e13)]
        {
            assert_eq!(reading(&bad, true), None, "{bad}");
        }
    }

    #[test]
    fn whole_floats_are_written_as_integers() {
        assert_eq!(number(1000.0).to_string(), "1000");
        assert_eq!(number(0.5).to_string(), "0.5");
        assert_eq!(number(f64::NAN), Value::Null);
        assert_eq!(round_to(0.125, 2), 0.12);
        assert_eq!(round_to(2.675, 2), 2.67);
    }
}
