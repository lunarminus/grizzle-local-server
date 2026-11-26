//! Settings, all from environment variables so the container is configured in compose.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono_tz::Tz;

use crate::net::{split_url, IpNet};
use crate::value::clip;

/// Passwords this project has shipped in its documentation or compose file, plus the obvious ones.
pub const WELL_KNOWN_PASSWORDS: [&str; 6] = ["grizzle", "change-me", "changeme", "password", "admin", "admin@local"];

/// Charge point ids become station keys, appear in logs and in the web page: serials such as
/// GRD-L0000XXXX, plus the unknown-<ip> fallback (dots/colons).
///
/// A letter or digit, then up to 63 more of letters, digits and `. _ : -`.
pub fn is_charge_point_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// One CSP source expression: 'self', 'none', *, a scheme (https:), a scheme://host[:port], or a host[:port].
fn is_csp_source(source: &str) -> bool {
    if matches!(source, "'self'" | "'none'" | "*") {
        return true;
    }
    if let Some(scheme) = source.strip_suffix(':') {
        if is_scheme(scheme) {
            return true;
        }
    }
    if let Some((scheme, host)) = source.split_once("://") {
        return is_scheme(scheme)
            && !host.is_empty()
            && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '*' | '[' | ']' | ':' | '-'));
    }
    let (host, port) = match source.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (source, None),
    };
    let mut chars = host.chars();
    let host_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '*')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '*' | '-'));
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit() || c == '*'));
    host_ok && port_ok
}

/// The entries of a setting that takes several values, separated by commas or spaces.
fn words(value: &str) -> Vec<String> {
    value.replace(',', " ").split_whitespace().map(str::to_string).collect()
}

/// One GRIZZLE_ALLOWED_HOSTS entry as a bare lower-case host name (or `*`, or a `.suffix`).
///
/// People paste what is in the address bar. `https://grizzle.example.com:8443/` means the host.
pub fn host_name(entry: &str) -> String {
    let entry = entry.trim().to_lowercase();
    if entry == "*" || entry.starts_with('.') {
        return entry.trim_end_matches('.').to_string();
    }
    let url = if entry.contains("://") { entry.clone() } else { format!("//{entry}") };
    let host = split_url(&url).and_then(|parts| parts.hostname);
    host.unwrap_or(entry).trim_end_matches('.').to_string()
}

/// Validate a list of CSP sources (spaces or commas between them); empty means `'self'`.
///
/// The result goes into a response header, so anything that isn't a plain source expression is
/// refused rather than passed through.
pub fn frame_ancestors(value: &str) -> Result<String, String> {
    let mut sources = Vec::new();
    for source in words(value) {
        let mut source = source;
        if source.contains("://") {
            // pasted from the address bar: http://homeassistant.local:8123/lovelace -> its origin
            if let Some(parts) = split_url(&source) {
                source = format!("{}://{}", parts.scheme, parts.netloc);
            }
        }
        if !is_csp_source(&source) {
            return Err(format!(
                "GRIZZLE_FRAME_ANCESTORS: {source:?} is not a CSP source \
                 (use 'self', *, or an origin such as http://homeassistant.local:8123)"
            ));
        }
        sources.push(source);
    }
    Ok(if sources.is_empty() { "'self'".to_string() } else { sources.join(" ") })
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub data_dir: PathBuf,
    pub host: String,
    pub port: u16,
    /// Optional TLS listener, for pointing the charger at this server via a DNS override of
    /// ocpp.unitedchargers.com (the charger then speaks wss:// to us on 443). TLS is enabled
    /// automatically when both files exist (scripts/make-cert.sh writes them).
    pub tls_port: u16,
    pub tls_cert: String,
    pub tls_key: String,
    /// Credentials the Home Assistant integration (or anything else) logs in with.
    pub api_email: String,
    pub api_password: String,
    /// If set, the charger's HTTP Basic auth password must match (its "Auth key").
    pub ocpp_password: Option<String>,
    /// Answer the firmware's "third-party OCPP unlock" check locally so a custom OCPP backend stays
    /// enabled without the vendor's paid unlock. Only reached if connect-api.unitedchargers.com is
    /// also DNS-overridden to this server. Set GRIZZLE_OCPP_UNLOCK=0 to disable.
    pub ocpp_unlock: bool,
    /// The serial numbers of the only chargers that may connect. Empty: any serial may. It keeps
    /// every other serial out. It does not prove that whoever presents a listed serial is that
    /// charger: a serial is no secret. That takes GRIZZLE_OCPP_PASSWORD, or the charger's Auth key,
    /// which the server pins the first time one is presented under that serial (unless something
    /// connected under it without a key before).
    pub allowed_chargers: Vec<String>,
    /// How many stations may exist. A charger nobody has seen before is added on its first
    /// connection, by anyone who can reach the port, so the number has to be bounded.
    pub max_stations: usize,
    /// Who may show the web page in a frame (CSP frame-ancestors). 'self' stops other sites from
    /// framing it and tricking a signed-in user into clicking; to embed the page in Home Assistant
    /// name its origin, e.g. http://homeassistant.local:8123.
    pub frame_ancestors: String,
    /// Extra host names under which browsers may use the web page and API. Addresses and names that
    /// only exist on a local network (nas, nas.local, 192.168.1.5) always work; a public DNS name
    /// (a reverse proxy's, say) has to be listed, because that is also what a DNS-rebinding attack
    /// looks like. ".example.com" allows every name under it; "*" allows all.
    pub allowed_hosts: Vec<String>,
    /// Reverse proxies in front of this server (addresses or networks, e.g. 172.18.0.2 or 10.0.0.0/8).
    /// Only from these is X-Forwarded-For believed, so that the sign-in limit counts the real client
    /// and not the proxy. Unset: the header is ignored, as anyone can send it.
    pub trusted_proxies: Vec<IpNet>,
    pub timezone: String,
    pub currency: String,
    pub heartbeat_interval: i64,
    pub meter_interval: i64,
    pub id_tag: String,
    pub default_min_current: i64,
    pub default_max_current: i64,
    pub tick: Duration,
    pub log_level: String,

    // Not configurable from the environment; tests shorten them.
    /// PBKDF2-HMAC-SHA256 rounds for the mark that tells us the sign-in credentials have changed.
    pub credential_rounds: u32,
    /// How long a live connection gets to answer before an unauthenticated newcomer may replace it.
    pub liveness_timeout: Duration,
    /// How long closing the chargers' sockets may take at shutdown, all of them together.
    pub close_timeout: Duration,
    /// How long a call to a charger waits for its answer unless the caller says otherwise.
    pub call_timeout: Duration,
    /// A charger sends a frame every few seconds. Past the burst, reading slows to this rate, which
    /// pushes back on a peer that floods us (every frame may cost a database write).
    pub rate_burst: f64,
    pub rate_per_second: f64,
    /// How long after BootNotification the server starts configuring the charger.
    pub boot_delay: Duration,
}

impl Settings {
    /// Settings from the process environment.
    pub fn from_env() -> Result<Settings, String> {
        Settings::from_lookup(|name| std::env::var(name).ok())
    }

    /// The settings an environment with nothing set gives.
    pub fn defaults() -> Settings {
        Settings::from_lookup(|_| None).expect("the defaults are valid")
    }

    /// Settings from name/value pairs, as the environment would give them (for tests and tools).
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Result<Settings, String> {
        Settings::from_lookup(|name| pairs.iter().find(|(key, _)| *key == name).map(|(_, value)| value.to_string()))
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Settings, String> {
        let text = |name: &str, default: &str| lookup(name).unwrap_or_else(|| default.to_string());
        let optional = |name: &str| lookup(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let int = |name: &str, default: i64| -> Result<i64, String> {
            match lookup(name).filter(|v| !v.is_empty()) {
                None => Ok(default),
                Some(value) => value.trim().parse().map_err(|_| format!("{name}: {value:?} is not a whole number")),
            }
        };
        let port = |name: &str, default: i64| -> Result<u16, String> {
            let value = int(name, default)?;
            u16::try_from(value).map_err(|_| format!("{name}: {value} is not a port number (0-65535)"))
        };
        let flag = |name: &str, default: bool| {
            let value = lookup(name).unwrap_or_default().trim().to_lowercase();
            if value.is_empty() {
                default
            } else {
                matches!(value.as_str(), "1" | "true" | "yes" | "on")
            }
        };

        let frame_ancestors = frame_ancestors(&text("GRIZZLE_FRAME_ANCESTORS", ""))?;
        let allowed_hosts: Vec<String> =
            words(&text("GRIZZLE_ALLOWED_HOSTS", "")).iter().map(|e| host_name(e)).filter(|n| !n.is_empty()).collect();
        let trusted_proxies = words(&text("GRIZZLE_TRUSTED_PROXIES", ""))
            .iter()
            .map(|proxy| IpNet::parse(proxy))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                format!("GRIZZLE_TRUSTED_PROXIES: {err} (use addresses or networks such as 10.0.0.0/8)")
            })?;
        let allowed_chargers = words(&text("GRIZZLE_ALLOWED_CHARGERS", ""));
        for serial in &allowed_chargers {
            // An entry that can never be a charger's id would lock every charger out without saying
            // why: `- GRIZZLE_ALLOWED_CHARGERS="GRD-..."` in a compose list keeps its quotes, for one.
            if !is_charge_point_id(serial) {
                return Err(format!(
                    "GRIZZLE_ALLOWED_CHARGERS: {serial:?} cannot be a charger's serial number \
                     (letters, digits and . _ : - only, at most 64 characters, no quotes); \
                     to let any charger connect, leave it unset"
                ));
            }
        }
        let timezone = lookup("GRIZZLE_TIMEZONE")
            .filter(|v| !v.is_empty())
            .or_else(|| lookup("TZ").filter(|v| !v.is_empty()))
            .unwrap_or_else(|| "UTC".to_string());

        Ok(Settings {
            data_dir: PathBuf::from(text("GRIZZLE_DATA_DIR", "/data")),
            host: text("GRIZZLE_HOST", "0.0.0.0"),
            port: port("GRIZZLE_PORT", 9000)?,
            tls_port: port("GRIZZLE_TLS_PORT", 8443)?,
            tls_cert: text("GRIZZLE_TLS_CERT", "/certs/fullchain.pem"),
            tls_key: text("GRIZZLE_TLS_KEY", "/certs/privkey.pem"),
            api_email: text("GRIZZLE_API_EMAIL", "admin@local"),
            api_password: text("GRIZZLE_API_PASSWORD", "grizzle"),
            ocpp_password: optional("GRIZZLE_OCPP_PASSWORD"),
            ocpp_unlock: flag("GRIZZLE_OCPP_UNLOCK", true),
            allowed_chargers,
            max_stations: int("GRIZZLE_MAX_STATIONS", 16)?.clamp(1, 1_000_000) as usize,
            frame_ancestors,
            allowed_hosts,
            trusted_proxies,
            timezone,
            currency: text("GRIZZLE_CURRENCY", "USD"),
            heartbeat_interval: int("GRIZZLE_HEARTBEAT_INTERVAL", 300)?,
            meter_interval: int("GRIZZLE_METER_INTERVAL", 30)?,
            id_tag: text("GRIZZLE_ID_TAG", "uc_default_auth"),
            default_min_current: int("GRIZZLE_MIN_CURRENT", 6)?,
            default_max_current: int("GRIZZLE_MAX_CURRENT", 40)?,
            tick: Duration::from_secs(int("GRIZZLE_TICK_SECONDS", 15)?.clamp(1, 86_400) as u64),
            log_level: text("LOG_LEVEL", "info").to_uppercase(),
            credential_rounds: 600_000,
            liveness_timeout: Duration::from_secs(5),
            close_timeout: Duration::from_secs(3),
            call_timeout: Duration::from_secs(30),
            rate_burst: 120.0,
            rate_per_second: 10.0,
            boot_delay: Duration::from_secs(2),
        })
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_port != 0 && Path::new(&self.tls_cert).is_file() && Path::new(&self.tls_key).is_file()
    }

    /// What an operator should know at startup about how this instance is configured.
    pub fn security_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.api_password.is_empty() {
            warnings.push(
                "GRIZZLE_API_PASSWORD is empty: nobody can sign in to the web page or the REST API until it is set"
                    .to_string(),
            );
        } else if WELL_KNOWN_PASSWORDS.contains(&self.api_password.to_lowercase().as_str()) {
            warnings.push(
                "GRIZZLE_API_PASSWORD is a well-known default: anyone who can reach this server can sign in and \
                 control the charger. Set a password of your own"
                    .to_string(),
            );
        } else if self.api_password.chars().count() < 8 {
            warnings.push("GRIZZLE_API_PASSWORD is shorter than 8 characters and easy to guess".to_string());
        }
        if self.frame_ancestors == "*" {
            warnings.push(
                "GRIZZLE_FRAME_ANCESTORS=* lets any web site show the page in a frame (clickjacking); \
                 name the origin that embeds it instead"
                    .to_string(),
            );
        }
        let placeholders: Vec<&str> =
            self.allowed_chargers.iter().filter(|s| s.starts_with("unknown-")).map(String::as_str).collect();
        if !placeholders.is_empty() {
            warnings.push(format!(
                "GRIZZLE_ALLOWED_CHARGERS lists {}: that is the name given to whatever connects without an id, \
                 not a serial, and anyone can also write it in the URL. Set a charge point id or an Auth key on \
                 the charger if it has one, or set GRIZZLE_OCPP_PASSWORD",
                placeholders.join(", ")
            ));
        }
        if self.timezone.parse::<Tz>().is_err() {
            warnings.push(format!(
                "timezone {:?} (TZ / GRIZZLE_TIMEZONE) is not a zone this system knows: schedules and rates for \
                 new stations will be evaluated in UTC. Use a name such as America/Denver",
                clip(&self.timezone, 64)
            ));
        }
        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_point_ids() {
        for good in ["GRD-L0000XXXX", "unknown-192.168.1.5", "unknown-::1", "a", &"a".repeat(64)] {
            assert!(is_charge_point_id(good), "{good}");
        }
        for bad in ["", "-x", ".x", "a b", "a/b", "a\n", &"a".repeat(65), "\"GRD-1\"", "é"] {
            assert!(!is_charge_point_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn frame_ancestors_setting() {
        assert_eq!(frame_ancestors("").unwrap(), "'self'");
        assert_eq!(frame_ancestors("  ").unwrap(), "'self'");
        assert_eq!(frame_ancestors("*").unwrap(), "*");
        assert_eq!(
            frame_ancestors("'self', http://homeassistant.local:8123").unwrap(),
            "'self' http://homeassistant.local:8123"
        );
        assert_eq!(frame_ancestors("https: ha.example.com:*").unwrap(), "https: ha.example.com:*");
        for bad in ["'self'; script-src *", "http://x/\r\nSet-Cookie:a", "'unsafe-inline'", "a;b", "\"x\""] {
            assert!(frame_ancestors(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn frame_ancestors_may_be_pasted_from_the_address_bar() {
        assert_eq!(
            frame_ancestors("http://homeassistant.local:8123/lovelace/0?edit=1").unwrap(),
            "http://homeassistant.local:8123"
        );
        assert_eq!(frame_ancestors("https://ha.example.com/").unwrap(), "https://ha.example.com");
    }

    #[test]
    fn allowed_host_entries_may_be_pasted_from_the_address_bar() {
        let settings = Settings::from_pairs(&[(
            "GRIZZLE_ALLOWED_HOSTS",
            "https://Grizzle.Example.com:8443/, nas.fritz.box:9000 .Example.org. * [fd00::1]:9000",
        )])
        .unwrap();
        assert_eq!(settings.allowed_hosts, ["grizzle.example.com", "nas.fritz.box", ".example.org", "*", "fd00::1"]);
    }

    #[test]
    fn allowed_chargers_setting() {
        let settings = Settings::from_pairs(&[("GRIZZLE_ALLOWED_CHARGERS", "GRD-1, GRD-2  GRD-3,")]).unwrap();
        assert_eq!(settings.allowed_chargers, ["GRD-1", "GRD-2", "GRD-3"]);
        assert!(Settings::from_pairs(&[("GRIZZLE_ALLOWED_CHARGERS", " , ")]).unwrap().allowed_chargers.is_empty());
        let err = Settings::from_pairs(&[("GRIZZLE_ALLOWED_CHARGERS", "\"GRD-1\"")]).unwrap_err();
        assert!(err.contains("cannot be a charger's serial number"), "{err}");
    }

    #[test]
    fn max_stations_setting() {
        assert_eq!(Settings::defaults().max_stations, 16);
        assert_eq!(Settings::from_pairs(&[("GRIZZLE_MAX_STATIONS", "3")]).unwrap().max_stations, 3);
        assert_eq!(Settings::from_pairs(&[("GRIZZLE_MAX_STATIONS", "0")]).unwrap().max_stations, 1);
        assert_eq!(Settings::from_pairs(&[("GRIZZLE_MAX_STATIONS", "-5")]).unwrap().max_stations, 1);
        assert!(Settings::from_pairs(&[("GRIZZLE_MAX_STATIONS", "many")]).is_err());
    }

    #[test]
    fn trusted_proxies_setting() {
        let settings = Settings::from_pairs(&[("GRIZZLE_TRUSTED_PROXIES", "172.18.0.2, 10.0.0.0/8")]).unwrap();
        assert_eq!(settings.trusted_proxies.len(), 2);
        let err = Settings::from_pairs(&[("GRIZZLE_TRUSTED_PROXIES", "the-proxy")]).unwrap_err();
        assert!(err.starts_with("GRIZZLE_TRUSTED_PROXIES:"), "{err}");
    }

    #[test]
    fn startup_warnings_name_weak_passwords() {
        let warnings = |password: &str| {
            Settings::from_pairs(&[("GRIZZLE_API_PASSWORD", password)]).unwrap().security_warnings().join("\n")
        };
        assert!(Settings::defaults().security_warnings().join("\n").contains("well-known default"));
        assert!(warnings("Change-Me").contains("well-known default"));
        assert!(warnings("").contains("is empty"));
        assert!(warnings("short").contains("shorter than 8"));
        assert_eq!(warnings("correct horse battery"), "");
    }

    #[test]
    fn other_startup_warnings() {
        let of = |name: &str, value: &str| {
            Settings::from_pairs(&[(name, value), ("GRIZZLE_API_PASSWORD", "correct horse battery")])
                .unwrap()
                .security_warnings()
                .join("\n")
        };
        assert!(of("GRIZZLE_FRAME_ANCESTORS", "*").contains("clickjacking"));
        assert!(of("GRIZZLE_ALLOWED_CHARGERS", "GRD-1 unknown-192.168.1.9").contains("lists unknown-192.168.1.9"));
        assert!(of("TZ", "Mars/Olympus").contains("is not a zone this system knows"));
        assert_eq!(of("TZ", "America/Denver"), "");
        assert_eq!(of("GRIZZLE_TIMEZONE", "US/Mountain"), "");
    }

    #[test]
    fn timezone_prefers_the_grizzle_setting() {
        let settings = Settings::from_pairs(&[("TZ", "Europe/Berlin"), ("GRIZZLE_TIMEZONE", "America/Denver")]);
        assert_eq!(settings.unwrap().timezone, "America/Denver");
        assert_eq!(Settings::from_pairs(&[("TZ", "Europe/Berlin")]).unwrap().timezone, "Europe/Berlin");
        assert_eq!(Settings::defaults().timezone, "UTC");
    }
}
