"""Settings, all from environment variables so the container is configured in compose."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

# Passwords this project has shipped in its documentation or compose file, plus the obvious ones.
WELL_KNOWN_PASSWORDS = frozenset({"grizzle", "change-me", "changeme", "password", "admin", "admin@local"})

# One CSP source expression: 'self', 'none', *, a scheme (https:), a scheme://host[:port], or a host[:port].
_CSP_SOURCE_RE = re.compile(
    r"'self'|'none'|\*|[A-Za-z][A-Za-z0-9+.-]*:|[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9.*\[\]:-]+"
    r"|[A-Za-z0-9*][A-Za-z0-9.*-]*(:[0-9*]+)?"
)


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


def _opt(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


def _host_name(entry: str) -> str:
    """One GRIZZLE_ALLOWED_HOSTS entry as a bare lower-case host name (or ``*``, or a ``.suffix``).

    People paste what is in the address bar. ``https://grizzle.example.com:8443/`` means the host.
    """
    entry = entry.strip().lower()
    if entry == "*" or entry.startswith("."):
        return entry.rstrip(".") if entry != "." else ""
    try:
        host = urlsplit(entry if "://" in entry else f"//{entry}").hostname
    except ValueError:
        host = None
    return (host or entry).rstrip(".")


def frame_ancestors(value: str | None) -> str:
    """Validate a list of CSP sources (spaces or commas between them); empty means ``'self'``.

    The result goes into a response header, so anything that isn't a plain source expression is
    refused rather than passed through.
    """
    sources = (value or "").replace(",", " ").split()
    for source in sources:
        if not _CSP_SOURCE_RE.fullmatch(source):
            raise ValueError(
                f"GRIZZLE_FRAME_ANCESTORS: {source!r} is not a CSP source "
                "(use 'self', *, or an origin such as http://homeassistant.local:8123)"
            )
    return " ".join(sources) or "'self'"


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("GRIZZLE_DATA_DIR", "/data")))
    host: str = field(default_factory=lambda: os.environ.get("GRIZZLE_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _int("GRIZZLE_PORT", 9000))
    # Optional TLS listener, for pointing the charger at this server via a DNS override
    # of ocpp.unitedchargers.com (the charger then speaks wss:// to us on 443).
    # TLS is enabled automatically when both files exist (scripts/make-cert.sh writes them).
    tls_port: int = field(default_factory=lambda: _int("GRIZZLE_TLS_PORT", 8443))
    tls_cert: str = field(default_factory=lambda: os.environ.get("GRIZZLE_TLS_CERT", "/certs/fullchain.pem"))
    tls_key: str = field(default_factory=lambda: os.environ.get("GRIZZLE_TLS_KEY", "/certs/privkey.pem"))

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_port) and Path(self.tls_cert).is_file() and Path(self.tls_key).is_file()

    # Credentials the Home Assistant integration (or anything else) logs in with.
    api_email: str = field(default_factory=lambda: os.environ.get("GRIZZLE_API_EMAIL", "admin@local"))
    api_password: str = field(default_factory=lambda: os.environ.get("GRIZZLE_API_PASSWORD", "grizzle"))
    # If set, the charger's HTTP Basic auth password must match (its "Auth key").
    ocpp_password: str | None = field(default_factory=lambda: _opt("GRIZZLE_OCPP_PASSWORD"))
    # Answer the firmware's "third-party OCPP unlock" check locally so a custom OCPP backend stays
    # enabled without the vendor's paid unlock. Only reached if connect-api.unitedchargers.com is
    # also DNS-overridden to this server. Set GRIZZLE_OCPP_UNLOCK=0 to disable.
    ocpp_unlock: bool = field(default_factory=lambda: _bool("GRIZZLE_OCPP_UNLOCK", True))
    # How many stations may exist. A charger nobody has seen before is added on its first
    # connection, by anyone who can reach the port, so the number has to be bounded.
    max_stations: int = field(default_factory=lambda: _int("GRIZZLE_MAX_STATIONS", 16))
    # Who may show the web page in a frame (CSP frame-ancestors). 'self' stops other sites from
    # framing it and tricking a signed-in user into clicking; to embed the page in Home Assistant
    # name its origin, e.g. http://homeassistant.local:8123.
    frame_ancestors: str = field(default_factory=lambda: os.environ.get("GRIZZLE_FRAME_ANCESTORS", ""))
    # Extra host names under which browsers may use the web page and API. Addresses and names that
    # only exist on a local network (nas, nas.local, 192.168.1.5) always work; a public DNS name
    # (a reverse proxy's, say) has to be listed, because that is also what a DNS-rebinding attack
    # looks like. Comma or space separated; ".example.com" allows every name under it; "*" allows all.
    allowed_hosts: tuple[str, ...] = field(default_factory=lambda: os.environ.get("GRIZZLE_ALLOWED_HOSTS", ""))
    # Reverse proxies in front of this server (addresses or networks, e.g. 172.18.0.2 or 10.0.0.0/8).
    # Only from these is X-Forwarded-For believed, so that the sign-in limit counts the real client
    # and not the proxy. Unset: the header is ignored, as anyone can send it.
    trusted_proxies: tuple = field(default_factory=lambda: os.environ.get("GRIZZLE_TRUSTED_PROXIES", ""))
    timezone: str = field(default_factory=lambda: os.environ.get("GRIZZLE_TIMEZONE") or os.environ.get("TZ") or "UTC")
    currency: str = field(default_factory=lambda: os.environ.get("GRIZZLE_CURRENCY", "USD"))
    heartbeat_interval: int = field(default_factory=lambda: _int("GRIZZLE_HEARTBEAT_INTERVAL", 300))
    meter_interval: int = field(default_factory=lambda: _int("GRIZZLE_METER_INTERVAL", 30))
    id_tag: str = field(default_factory=lambda: os.environ.get("GRIZZLE_ID_TAG", "uc_default_auth"))
    default_min_current: int = field(default_factory=lambda: _int("GRIZZLE_MIN_CURRENT", 6))
    default_max_current: int = field(default_factory=lambda: _int("GRIZZLE_MAX_CURRENT", 40))
    tick_seconds: int = field(default_factory=lambda: _int("GRIZZLE_TICK_SECONDS", 15))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "info").upper())

    def __post_init__(self) -> None:
        self.frame_ancestors = frame_ancestors(self.frame_ancestors)
        hosts = self.allowed_hosts
        if isinstance(hosts, str):
            hosts = hosts.replace(",", " ").split()
        self.allowed_hosts = tuple(name for name in map(_host_name, hosts) if name)
        proxies = self.trusted_proxies
        if isinstance(proxies, str):
            proxies = proxies.replace(",", " ").split()
        try:
            self.trusted_proxies = tuple(ipaddress.ip_network(str(proxy), strict=False) for proxy in proxies)
        except ValueError as err:
            raise ValueError(f"GRIZZLE_TRUSTED_PROXIES: {err} (use addresses or networks such as 10.0.0.0/8)") from None
        self.max_stations = max(1, int(self.max_stations))

    def security_warnings(self) -> list[str]:
        """What an operator should know at startup about how this instance is configured."""
        warnings = []
        if not self.api_password:
            warnings.append(
                "GRIZZLE_API_PASSWORD is empty: nobody can sign in to the web page or the REST API until it is set"
            )
        elif self.api_password.lower() in WELL_KNOWN_PASSWORDS:
            warnings.append(
                "GRIZZLE_API_PASSWORD is a well-known default: anyone who can reach this server can sign in and "
                "control the charger. Set a password of your own"
            )
        elif len(self.api_password) < 8:
            warnings.append("GRIZZLE_API_PASSWORD is shorter than 8 characters and easy to guess")
        if self.frame_ancestors == "*":
            warnings.append(
                "GRIZZLE_FRAME_ANCESTORS=* lets any web site show the page in a frame (clickjacking); "
                "name the origin that embeds it instead"
            )
        try:
            ZoneInfo(self.timezone)
        except Exception:  # noqa: BLE001 - unknown name, or not a zone name at all
            warnings.append(
                f"timezone {self.timezone[:64]!r} (TZ / GRIZZLE_TIMEZONE) is not a zone this system knows: schedules "
                "and rates for new stations will be evaluated in UTC. Use a name such as America/Denver"
            )
        return warnings
