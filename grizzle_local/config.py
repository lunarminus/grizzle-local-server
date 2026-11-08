"""Settings, all from environment variables so the container is configured in compose."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


def _opt(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


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
    timezone: str = field(default_factory=lambda: os.environ.get("GRIZZLE_TIMEZONE") or os.environ.get("TZ") or "UTC")
    currency: str = field(default_factory=lambda: os.environ.get("GRIZZLE_CURRENCY", "USD"))
    heartbeat_interval: int = field(default_factory=lambda: _int("GRIZZLE_HEARTBEAT_INTERVAL", 300))
    meter_interval: int = field(default_factory=lambda: _int("GRIZZLE_METER_INTERVAL", 30))
    id_tag: str = field(default_factory=lambda: os.environ.get("GRIZZLE_ID_TAG", "uc_default_auth"))
    default_min_current: int = field(default_factory=lambda: _int("GRIZZLE_MIN_CURRENT", 6))
    default_max_current: int = field(default_factory=lambda: _int("GRIZZLE_MAX_CURRENT", 40))
    tick_seconds: int = field(default_factory=lambda: _int("GRIZZLE_TICK_SECONDS", 15))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "info").upper())
