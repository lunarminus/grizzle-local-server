"""The brain: charger state, OCPP message handling, and local mode/schedule enforcement.

How the Grizzl-E Connect family behaves (from evcc's and others' experience):
- It never starts a transaction on its own. When a car is plugged in it reports
  ``Preparing`` and waits for the server's ``RemoteStartTransaction``. That is how
  the cloud implements the Active / Inactive / Schedule modes, and so do we.
- It only honours charging profiles at ``stackLevel`` 0 and ignores limits below ~6-7 A.
- Some firmware replies to ``GetConfiguration`` with invalid JSON; see ``ocpp.py``.

Everything a charger sends is untrusted. Unless GRIZZLE_OCPP_PASSWORD is set, anyone who can
reach the port may connect as a charger the server has never seen, so each handler below takes
only what it understands from a message (typed, bounded) and refuses or ignores the rest.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import secrets
import time as _time
from datetime import UTC, datetime, timedelta
from collections.abc import AsyncIterator, Coroutine
from typing import Any
from zoneinfo import ZoneInfo

from . import holiday_calendar
from .config import Settings
from .ocpp import CallRejected, ChargePointConnection, OcppError, now_iso, printable
from .schedules import MAX_NAME_LENGTH, charging_allowed, next_change, normalize_zone, price_now
from .schedules import zone_id as parse_zone_id
from .store import Store

_LOGGER = logging.getLogger(__name__)

MODES = ("Active", "Inactive", "Schedule")
PLUGGED_IN = {"Preparing", "Charging", "SuspendedEV", "SuspendedEVSE", "Finishing"}
WANTS_START = {"Preparing", "SuspendedEVSE"}
REMOTE_RETRY_SECONDS = 60

# Bounds on what a charger or an API client can make us keep or loop over.
MAX_CONNECTORS = 8  # a Duo has 2; nothing in the family has more
MAX_CURRENT = 100  # amps; the largest Grizzl-E is 80 A
MAX_ZONES = 100  # schedules + rate zones per station
ZONE_LIMITS = {"max_connector": MAX_CONNECTORS, "max_current": MAX_CURRENT}  # for normalize_zone
MAX_CONFIG_KEYS = 256  # GetConfiguration entries kept (a Duo reports 34)
MAX_METER_VALUES = 16  # meterValue entries handled per message (a charger sends one)
MAX_SAMPLED_VALUES = 64
MAX_READING = 1e12  # no meter reads beyond this, whatever the unit
BOOT_FIELDS = (
    "chargePointVendor",
    "chargePointModel",
    "chargePointSerialNumber",
    "chargeBoxSerialNumber",
    "firmwareVersion",
    "iccid",
    "imsi",
    "meterType",
    "meterSerialNumber",
)

# Model hints keyed by a prefix of the OCPP chargePointModel string.
MODEL_HINTS = [
    ("GRD", {"name": "Grizzl-E Duo", "connectors": 2, "maxCurrent": 40, "minCurrent": 16}),
    ("GRM", {"name": "Grizzl-E Mini Connect", "connectors": 1, "maxCurrent": 40, "minCurrent": 6}),
    ("GRU", {"name": "Grizzl-E Ultimate", "connectors": 1, "maxCurrent": 48, "minCurrent": 6}),
    ("GRS", {"name": "Grizzl-E Smart", "connectors": 1, "maxCurrent": 40, "minCurrent": 6}),
]

MEASURANDS = {
    "Energy.Active.Import.Register": "energy_wh",
    "Power.Active.Import": "power_w",
    "Current.Import": "current_a",
    "Current.Offered": "current_offered_a",
    "Voltage": "voltage_v",
    "Temperature": "temperature_c",
    "SoC": "soc",
}


def _same_secret(given: str | None, expected: str) -> bool:
    """Constant-time comparison that also copes with non-ASCII input (compare_digest on str doesn't)."""
    if not given or not isinstance(given, str):
        return False
    # surrogatepass: JSON can carry a lone surrogate, which plain UTF-8 refuses to encode.
    return secrets.compare_digest(given.encode("utf-8", "surrogatepass"), expected.encode("utf-8", "surrogatepass"))


def _parse_iso(value: Any) -> datetime | None:
    """A timezone-aware (UTC) datetime from an ISO 8601 string, or None. No offset means UTC."""
    if not isinstance(value, str) or not value or len(value) > 40:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return moment.astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def _iso(moment: datetime) -> str:
    """The one spelling of a time we store: UTC, milliseconds, trailing Z (so text order is time order)."""
    moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _timestamp(value: Any) -> str:
    """A charger's timestamp in our spelling; the time now if it is missing, unreadable or implausible.

    A clock that was never set (1970) or a date far in the future would otherwise order sessions
    wrongly and keep samples from ever being pruned.
    """
    moment = _parse_iso(value)
    now = datetime.now(UTC)
    if moment is None or moment.year < 2000 or moment > now + timedelta(days=1):
        return _iso(now)
    return _iso(moment)


def _recent(last: float | None, now: float) -> bool:
    """Was the last attempt less than REMOTE_RETRY_SECONDS ago? (None = never attempted)

    Times are from the monotonic clock, which restarts with the host: a "last attempt" later than
    now is from an earlier boot and counts as never.
    """
    return isinstance(last, (int, float)) and 0 <= now - last < REMOTE_RETRY_SECONDS


def _to_float(value: Any) -> float | None:
    """A finite float, or None."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _reading(value: Any, *, text: bool = False) -> float | int | None:
    """A meter reading: a finite number of plausible size, else None.

    ``text`` also accepts numeric strings, which is how OCPP spells sampled values. "NaN" and
    "Infinity" are numbers to float() but not to JSON: letting them in would make every later API
    response unparseable for browsers and Home Assistant.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if not text or len(value) > 32:
            return None
        try:
            value = float(value)
        except ValueError:
            return None
    if not isinstance(value, (int, float)):
        return None
    try:
        usable = math.isfinite(value) and abs(value) <= MAX_READING
    except OverflowError:
        usable = False
    return value if usable else None


def _text(value: Any, limit: int = 255) -> str | None:
    """A string field from a charger: text or a number, cut to ``limit``; anything else is dropped.

    Lone surrogates (JSON allows them) are replaced: neither SQLite nor a UTF-8 log can take them.
    """
    if isinstance(value, str):
        return value[:limit].encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)[:limit]
    return None


def _dicts(value: Any, limit: int) -> list[dict[str, Any]]:
    """The objects in a JSON list, at most ``limit`` of them; [] for anything that isn't a list."""
    if not isinstance(value, list):
        return []
    return [item for item in value[:limit] if isinstance(item, dict)]


def _small_int(value: Any, lo: int, hi: int) -> int | None:
    """An int in ``lo..hi`` from an int, an integral float or a short digit string; else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    elif isinstance(value, str) and len(value) <= 6 and value.isascii() and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or not lo <= value <= hi:
        return None
    return value


def connector_count(station: dict[str, Any]) -> int:
    """How many connectors the station has: always 1..MAX_CONNECTORS, whatever is stored."""
    count = station.get("connectorCount")
    if isinstance(count, bool) or not isinstance(count, int):
        return 1
    return max(1, min(count, MAX_CONNECTORS))


class Controller:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        self.connections: dict[str, ChargePointConnection] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._boot_tasks: dict[str, asyncio.Task[Any]] = {}  # station id -> its after-boot task
        self._station_ticks: dict[str, asyncio.Task[Any]] = {}  # station id -> its tick in flight
        self._dirty = False
        self._last_pin_save = float("-inf")
        self._admission_locks: dict[str, tuple[asyncio.Lock, int]] = {}  # id -> (lock, users)
        self._stopping = False
        self._unknown_zones: set[Any] = set()  # timezone names already reported as unusable
        self._sanitize_state()

    # --- station state helpers ---------------------------------------------

    @property
    def stations(self) -> dict[str, dict[str, Any]]:
        return self.store.state["stations"]

    def station(self, station_id: str) -> dict[str, Any] | None:
        return self.stations.get(station_id)

    def _ensure_station(self, station_id: str) -> dict[str, Any]:
        station = self.stations.get(station_id)
        if station is None:
            station = {
                "id": station_id,
                "displayName": station_id,
                "timezone": self.settings.timezone,
                "currency": self.settings.currency,
                "priceKW": 0,
                "boot": {},
                "firstSeen": now_iso(),
                "connectorCount": 1,
                "connectors": {},
                "currentLimit": None,
                "appliedLimit": None,
                "dipSwitchCurrentLimit": None,
                "maxCurrent": self.settings.default_max_current,
                "minCurrent": self.settings.default_min_current,
                "model": {"name": "Grizzl-E", "code": ""},
                "pricesByZone": [],
                "config": {},
            }
            self.stations[station_id] = station
            self._dirty = True
        for cid in range(1, connector_count(station) + 1):
            self._ensure_connector(station, cid)
        return station

    def _ensure_connector(self, station: dict[str, Any], cid: int) -> dict[str, Any]:
        if isinstance(cid, bool) or not isinstance(cid, int) or not 1 <= cid <= MAX_CONNECTORS:
            # Every caller checks first; this is the backstop that keeps a number from the network
            # from ever becoming the length of a loop.
            raise ValueError(f"connector must be 1..{MAX_CONNECTORS}")
        connectors = station["connectors"]
        key = str(cid)
        if key not in connectors:
            connectors[key] = {
                "id": cid,
                "status": None,
                "errorCode": "NoError",
                "statusChangedAt": None,
                "mode": "Active",
                "power": 0,
                "transaction": None,
                "lastMeter": {},
                "totalEnergyWh": None,
                "isActiveBySchedule": None,
                "nextScheduleTime": None,
                "lastRemoteStart": None,  # monotonic time of the last attempt; None = never
                "lastRemoteStop": None,
            }
            if cid > connector_count(station):
                station["connectorCount"] = cid
            self._dirty = True
        return connectors[key]

    def tz(self, station: dict[str, Any]) -> ZoneInfo:
        name = station.get("timezone") or self.settings.timezone
        try:
            return ZoneInfo(name)
        except Exception:  # noqa: BLE001 - bad tz name in state
            if name not in self._unknown_zones:
                # Once per name: this is asked on every tick, but silently charging on UTC's clock
                # instead of the owner's is exactly the kind of thing a log should mention.
                self._unknown_zones.add(name)
                _LOGGER.warning(
                    "%s: timezone %s is not known here; evaluating schedules and rates in UTC",
                    printable(station.get("id"), 80),
                    printable(name, 64),
                )
            return ZoneInfo("UTC")

    # --- state from disk ------------------------------------------------------

    def _sanitize_state(self) -> None:
        """Make whatever state.json held safe to run on.

        An older version stored what chargers and API clients sent as it came. A file written
        then (possibly while someone was abusing that) may hold a connector count in the billions,
        a status that isn't text, a schedule with a word where an hour belongs. The loops below
        assume none of that, so it is repaired or dropped here, once, at startup.
        """
        stations = self.store.state["stations"]
        for station_id in list(stations):
            station = stations[station_id]
            if not isinstance(station, dict) or not isinstance(station_id, str) or not station_id:
                _LOGGER.warning("dropping unreadable station entry %s from the saved state", printable(station_id, 80))
                del stations[station_id]
                continue
            self._sanitize_station(station_id, station)

    def _sanitize_station(self, station_id: str, station: dict[str, Any]) -> None:
        station["id"] = station_id
        name = station.get("displayName")
        station["displayName"] = name[:MAX_NAME_LENGTH] if isinstance(name, str) and name else station_id
        for key, default in (("timezone", self.settings.timezone), ("currency", self.settings.currency)):
            if not isinstance(station.get(key), str) or not station[key] or len(station[key]) > 64:
                station[key] = default
        price = _to_float(station.get("priceKW"))
        station["priceKW"] = price if price is not None and price >= 0 else 0
        for key, default in (
            ("maxCurrent", self.settings.default_max_current),
            ("minCurrent", self.settings.default_min_current),
        ):
            station[key] = _small_int(station.get(key), 1, MAX_CURRENT) or default
        for key in ("currentLimit", "appliedLimit", "dipSwitchCurrentLimit"):
            station[key] = _small_int(station.get(key), 1, MAX_CURRENT)
        if "limitInForce" not in station:
            # Saved by a version that never lifted a charging window's limit once the window was
            # over: if a limit was applied, treat it as still in force so that it is lifted now.
            station["limitInForce"] = station["appliedLimit"] is not None
        if not isinstance(station.get("idTag"), str) or len(station["idTag"]) > 64:
            station.pop("idTag", None)
        if "ocppAuthKey" in station and not (isinstance(station["ocppAuthKey"], str) and station["ocppAuthKey"]):
            del station["ocppAuthKey"]  # not a key anyone could present: better unpinned than unusable
        boot = station.get("boot") if isinstance(station.get("boot"), dict) else {}
        station["boot"] = self._boot_fields(boot, _text(boot.get("timestamp"), 40))
        model = station.get("model") if isinstance(station.get("model"), dict) else {}
        station["model"] = {
            "name": _text(model.get("name"), 100) or "Grizzl-E",
            "code": _text(model.get("code"), 100) or "",
        }
        station["config"] = self._clean_config(
            [{"key": key, "value": value} for key, value in station["config"].items()]
            if isinstance(station.get("config"), dict)
            else []
        )
        if "dataTransfers" in station:
            station["dataTransfers"] = [
                self._data_transfer(item, _text(item.get("at"), 40)) for item in _dicts(station["dataTransfers"], 20)
            ]

        connectors = station.get("connectors") if isinstance(station.get("connectors"), dict) else {}
        kept: dict[str, dict[str, Any]] = {}
        for key, connector in connectors.items():
            cid = _small_int(key, 1, MAX_CONNECTORS)
            if cid is None or str(cid) != key or not isinstance(connector, dict):
                continue
            connector["id"] = cid
            # These are monotonic-clock readings, which mean nothing after a restart: carried over,
            # they could look like "tried a moment ago" for days and suppress every RemoteStart.
            connector["lastRemoteStart"] = connector["lastRemoteStop"] = None
            if connector.get("mode") not in MODES:
                connector["mode"] = "Active"
            status = connector.get("status")
            connector["status"] = _text(status, 32) if isinstance(status, str) else None
            tx = connector.get("transaction")
            if not isinstance(tx, dict) or _small_int(tx.get("id"), 1, 2**62) is None:
                connector["transaction"] = None
            else:
                tx["id"] = _small_int(tx["id"], 1, 2**62)
                for field in ("energy", "power", "priceTotal", "lastSessionEnergy"):
                    tx[field] = _reading(tx.get(field)) or 0
                tx["meterStart"] = _reading(tx.get("meterStart"))
                tx["priceKW"] = _to_float(tx.get("priceKW"))
                tx["startAt"] = _text(tx.get("startAt"), 40) if isinstance(tx.get("startAt"), str) else None
                tx["idTag"] = _text(tx.get("idTag"), 64)
                if not isinstance(tx.get("meter"), dict):
                    tx["meter"] = {}
                if not isinstance(tx.get("sessionRelativeRegister"), bool):
                    tx.pop("sessionRelativeRegister", None)
            if not isinstance(connector.get("lastMeter"), dict):
                connector["lastMeter"] = {}
            connector["totalEnergyWh"] = _reading(connector.get("totalEnergyWh"))
            connector["power"] = _reading(connector.get("power")) or 0
            kept[key] = connector
        stored = station.get("connectorCount")
        station["connectors"] = kept
        if isinstance(stored, bool) or not isinstance(stored, int) or not 1 <= stored <= MAX_CONNECTORS:
            # Out of range: fall back to the connectors that really exist.
            station["connectorCount"] = max((int(key) for key in kept), default=1)
            if stored is not None:
                _LOGGER.warning(
                    "%s: saved connector count %s is not possible; using %s",
                    printable(station_id, 80),
                    printable(stored, 40),
                    station["connectorCount"],
                )

        zones = []
        for zone in station.get("pricesByZone") if isinstance(station.get("pricesByZone"), list) else []:
            try:
                try:
                    clean = normalize_zone(zone, **ZONE_LIMITS)
                except ValueError:
                    # Refused as it stands; mend what the old code merely tolerated before giving up.
                    clean = normalize_zone(self._mended_zone(zone), **ZONE_LIMITS)
                clean["_id"] = parse_zone_id(zone.get("_id"))
            except ValueError as err:
                _LOGGER.warning("%s: dropping an unusable schedule/rate zone from the saved state: %s", station_id, err)
                continue
            zones.append(clean)
        station["pricesByZone"] = zones[:MAX_ZONES]
        if "holidaysSettings" in station:
            try:
                station["holidaysSettings"] = holiday_calendar.normalize(station["holidaysSettings"])
            except (TypeError, ValueError, AttributeError) as err:
                _LOGGER.warning("%s: dropping unusable holiday settings from the saved state: %s", station_id, err)
                del station["holidaysSettings"]

    @staticmethod
    def _mended_zone(zone: Any) -> Any:
        """A saved zone with the values an older version accepted, and coped with, brought into range.

        Only what leaves the zone meaning the same: an over-long name is cut, a current limit beyond
        the bounds is clamped (the old code clamped it when applying it), day numbers that never
        matched any day are removed. A zone that is still refused after this (a word where an hour
        belongs) is dropped by the caller: guessing its times could turn it into an all-day window.
        """
        if not isinstance(zone, dict):
            return zone
        mended = dict(zone)
        if isinstance(mended.get("name"), str):
            mended["name"] = mended["name"].strip()[:MAX_NAME_LENGTH]
        if "currentLimit" in mended:
            limit = _reading(mended["currentLimit"])
            mended["currentLimit"] = None if limit is None or limit <= 0 else min(max(limit, 1), MAX_CURRENT)
        if isinstance(mended.get("days"), list):
            mended["days"] = [d for d in mended["days"] if _small_int(d, 0, 6) is not None]
        return mended

    # --- holidays, windows and prices -------------------------------------------

    def holiday_check(self, station: dict[str, Any]) -> Any:
        """A ``date -> bool`` for this station's holidays, or None when holidays are switched off."""
        settings = station.get("holidaysSettings") or {}
        if not settings.get("enabled"):
            return None
        return lambda day: holiday_calendar.holiday_name(settings, day) is not None

    def window_now(self, station: dict[str, Any], now: datetime, cid: int) -> dict[str, Any] | None:
        return charging_allowed(station["pricesByZone"], now, cid, self.holiday_check(station))

    def price_at(self, station: dict[str, Any], now: datetime) -> float | None:
        settings = station.get("holidaysSettings") or {}
        return price_now(
            station["pricesByZone"],
            now,
            _to_float(station.get("priceKW")),
            self.holiday_check(station),
            settings.get("priceKW"),
        )

    def is_online(self, station_id: str) -> bool:
        conn = self.connections.get(station_id)
        return conn is not None and not conn.ws.closed

    def mark_dirty(self) -> None:
        self._dirty = True

    # --- connection lifecycle ------------------------------------------------

    # How long a live connection gets to answer before an unauthenticated newcomer may replace it.
    LIVENESS_TIMEOUT = 5.0

    @contextlib.asynccontextmanager
    async def admission(self, cp_id: str) -> AsyncIterator[None]:
        """Serialise connection_refusal() .. on_connect() per charge point id.

        Both the liveness probe and the WebSocket handshake await, so without this two handshakes
        for the same id could both pass the check (say, two first connections with different keys)
        and the later one would replace the earlier one despite the pin the earlier one set.
        """
        lock, users = self._admission_locks.get(cp_id) or (asyncio.Lock(), 0)
        self._admission_locks[cp_id] = (lock, users + 1)
        try:
            async with lock:
                yield
        finally:
            # Drop the entry only when nobody holds or awaits it (a released Lock looks unlocked
            # before its next waiter runs, so locked() can't tell).
            lock, users = self._admission_locks[cp_id]
            if users == 1:
                del self._admission_locks[cp_id]
            else:
                self._admission_locks[cp_id] = (lock, users - 1)

    async def connection_refusal(self, cp_id: str, auth_key: str | None) -> tuple[int, str] | None:
        """Decide whether a charger may connect as ``cp_id``; (HTTP status, reason) if not.

        - With GRIZZLE_ALLOWED_CHARGERS set, only the serials listed there are considered at all.
          That keeps other serials out; it is the checks below that keep someone else from being
          taken for a listed one, since a serial is no secret.
        - With GRIZZLE_OCPP_PASSWORD set, the Basic password must match it, and no key is pinned
          (so changing the password never collides with a per-station pin).
        - Otherwise a station is pinned to the first Auth key it presents (trust on first use):
          any other key, or none, is refused. Clear the pin with DELETE /local/stations/{id}/auth-key.
        - A connection that proves nothing (no password, nothing pinned) may create a new station,
          and may replace a station's existing connection only if that one no longer answers.
        - A serial nobody has seen is a new station, and there may only be GRIZZLE_MAX_STATIONS of
          those: whoever can reach the port can invent serials, and each one is kept.
        - Nobody is admitted while the server is shutting down. The check below can wait seconds
          for a liveness probe; a handshake let in after stop() has closed "every" connection would
          be the one nobody closes, and exit would wait out its timeout (past Docker's patience).
        """
        refusal = await self._refusal(cp_id, auth_key)
        if refusal is None and self._stopping:
            return 503, "the server is shutting down"
        return refusal

    async def _refusal(self, cp_id: str, auth_key: str | None) -> tuple[int, str] | None:
        password = self.settings.ocpp_password
        if password is not None and not _same_secret(auth_key, password):
            return 401, "wrong OCPP password (GRIZZLE_OCPP_PASSWORD)"
        if self.settings.allowed_chargers and cp_id not in self.settings.allowed_chargers:
            # The same answer as for a wrong key or password, and after the password check: the
            # reply must not tell a stranger which serials are on the list.
            return 401, "its serial is not in GRIZZLE_ALLOWED_CHARGERS; add it there to let this charger connect"
        if password is not None:
            return self._full(cp_id)
        pinned = (self.station(cp_id) or {}).get("ocppAuthKey")
        if pinned:
            if not _same_secret(auth_key, pinned):
                return 401, (
                    "Auth key does not match the one this charger registered with; if you changed it, "
                    f"clear the old one with DELETE /local/stations/{cp_id}/auth-key"
                )
            return None
        full = self._full(cp_id)
        if full is not None:
            return full
        if await self._answers(cp_id):
            return 409, "already connected and still answering; an unauthenticated connection may not replace it"
        return None

    def _full(self, cp_id: str) -> tuple[int, str] | None:
        """The refusal for a never-seen serial when no more stations may be added, else None."""
        if cp_id in self.stations or len(self.stations) < self.settings.max_stations:
            return None
        return 503, (
            f"this would be station number {len(self.stations) + 1} and GRIZZLE_MAX_STATIONS is "
            f"{self.settings.max_stations}; delete stations you don't use (DELETE /local/stations/<serial>) "
            "or raise the limit"
        )

    async def _answers(self, cp_id: str) -> bool:
        """True if the station's current connection replies to a harmless call in time.

        A charger that reconnects doesn't close its old socket first, so a dead socket can look
        online for minutes; probing tells a stale socket (replace it) from a live one (keep it).
        """
        conn = self.connections.get(cp_id)
        if conn is None or conn.ws.closed:
            return False
        try:
            await conn.call("TriggerMessage", {"requestedMessage": "Heartbeat"}, self.LIVENESS_TIMEOUT)
        except OcppError as err:
            # A CallError reply still proves someone is answering; a timeout or a drop doesn't.
            return err.code not in ("Timeout", "Disconnected") and not conn.ws.closed
        except Exception:  # noqa: BLE001 - the socket failed while sending: it's dead
            return False
        return True

    async def on_connect(
        self,
        conn: ChargePointConnection,
        handshake: dict[str, Any] | None = None,
        auth_key: str | None = None,
    ) -> None:
        old = self.connections.get(conn.id)
        self.connections[conn.id] = conn
        station = self._ensure_station(conn.id)
        station["lastSeen"] = now_iso()
        if handshake is not None:
            station["ocppHandshake"] = handshake
        self._dirty = True
        if self._record_auth_key(station, auth_key) and _time.monotonic() - self._last_pin_save > 1.0:
            # Don't leave a fresh pin waiting for the next tick (a crash would lose it). At most
            # once a second, so a flood of new serials can't force a full save per handshake.
            self._last_pin_save = _time.monotonic()
            self.save()  # logs a failure instead of raising: a full disk must not refuse the charger
        _LOGGER.info("%s connected", conn.id)
        if old is not None and old is not conn:
            # A reconnecting charger doesn't close its old socket first.
            self._spawn(old.close())

    def _record_auth_key(self, station: dict[str, Any], auth_key: str | None) -> bool:
        """Store the Auth key the charger presented (for pinning and firmware_capture); True if changed.

        connection_refusal() has already accepted this key, so an existing pin is never replaced
        by a different one. An empty or missing key never wipes a stored one.
        """
        current = station.get("ocppAuthKey")
        if not auth_key:
            if not current:
                # Remember this station connects without a key, so a key presented later (by
                # anyone, while it's offline) isn't pinned and doesn't lock the charger out.
                station["ocppKeyless"] = True
            return False
        if self.settings.ocpp_password is not None:
            # Authenticated by the shared password; keep the recorded key current.
            station["ocppAuthKey"] = auth_key
            return current != auth_key
        if current:
            return False
        if station.get("ocppKeyless"):
            _LOGGER.warning(
                "%s presented an Auth key but has connected without one before; not pinning it "
                "(DELETE /local/stations/%s/auth-key to let the next key be pinned)",
                station["id"],
                station["id"],
            )
            return False
        station["ocppAuthKey"] = auth_key
        _LOGGER.info("%s: pinned to the Auth key it presented", station["id"])
        return True

    async def clear_auth_key(self, station_id: str) -> None:
        """Forget the pinned key and drop the live connection, so the charger's reconnect pins anew."""
        station = self.station(station_id)
        if station is None:
            return
        station.pop("ocppAuthKey", None)
        station.pop("ocppKeyless", None)
        self._dirty = True
        self.save()
        _LOGGER.warning("%s: pinned OCPP Auth key cleared; the next connection will pin a new one", station_id)
        conn = self.connections.get(station_id)
        if conn is not None:
            await conn.close()

    async def on_disconnect(self, conn: ChargePointConnection) -> None:
        if self.connections.get(conn.id) is conn:
            del self.connections[conn.id]
            _LOGGER.info("%s disconnected", conn.id)
            station = self.station(conn.id)
            if station:
                station["lastSeen"] = now_iso()
                self._dirty = True

    def _spawn(self, coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task[Any]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            _LOGGER.error("background task failed", exc_info=task.exception())

    # --- inbound OCPP --------------------------------------------------------

    async def handle(self, conn: ChargePointConnection, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        station = self._ensure_station(conn.id)
        station["lastSeen"] = now_iso()
        handler = getattr(self, f"_on_{action}", None)
        if handler is None:
            _LOGGER.info("%s: unhandled %s %s", conn.id, printable(action, 64), printable(payload, 300))
            raise NotImplementedError(action)
        result = await handler(station, payload)
        self._dirty = True
        return result

    @staticmethod
    def _connector_id(payload: dict[str, Any], default: int) -> int:
        """The message's connectorId (``default`` when absent or 0), refused unless it is 0..MAX_CONNECTORS."""
        raw = payload.get("connectorId") or default
        cid = _small_int(raw, 0, MAX_CONNECTORS)
        if cid is None:
            raise CallRejected("PropertyConstraintViolation", f"connectorId must be 0..{MAX_CONNECTORS}")
        return cid

    @staticmethod
    def _boot_fields(payload: dict[str, Any], timestamp: str | None) -> dict[str, Any]:
        boot: dict[str, Any] = {key: _text(payload[key], 100) for key in BOOT_FIELDS if key in payload}
        boot = {key: value for key, value in boot.items() if value is not None}
        if boot or timestamp:
            boot["timestamp"] = timestamp
        return boot

    async def _on_BootNotification(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        station["boot"] = self._boot_fields(payload, now_iso())
        model = station["boot"].get("chargePointModel") or ""
        hint = next((h for prefix, h in MODEL_HINTS if model.upper().startswith(prefix)), None)
        if hint:
            station["model"] = {"name": hint["name"], "code": model}
            if not station.get("modelLocked"):
                station["connectorCount"] = max(connector_count(station), hint["connectors"])
                station["maxCurrent"] = hint["maxCurrent"]
                station["minCurrent"] = hint["minCurrent"]
        else:
            station["model"] = {"name": model or "Grizzl-E", "code": model}
        for cid in range(1, connector_count(station) + 1):
            connector = self._ensure_connector(station, cid)
            connector["lastRemoteStart"] = None
        station["appliedLimit"] = None  # profiles may not survive a reboot
        _LOGGER.info(
            "%s booted: %s fw %s",
            station["id"],
            printable(model, 100),
            printable(station["boot"].get("firmwareVersion"), 100),
        )
        # One after-boot conversation per station: a charger that repeats BootNotification must
        # not be able to pile up tasks (each of which sends it half a dozen calls).
        previous = self._boot_tasks.get(station["id"])
        if previous is not None and not previous.done():
            previous.cancel()
        self._boot_tasks[station["id"]] = self._spawn(self._after_boot(station["id"]))
        return {"status": "Accepted", "currentTime": now_iso(), "interval": self.settings.heartbeat_interval}

    async def _on_Heartbeat(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        return {"currentTime": now_iso()}

    async def _on_StatusNotification(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        cid = self._connector_id(payload, 0)
        status = payload.get("status")
        if not isinstance(status, str) or not status:
            raise CallRejected("TypeConstraintViolation", "status must be a string")
        status = _text(status, 32)
        error_code = _text(payload.get("errorCode"), 50) or "NoError"
        if cid == 0:
            station["status"] = status
            station["errorCode"] = error_code
            return {}
        connector = self._ensure_connector(station, cid)
        if connector.get("status") != status:
            connector["statusChangedAt"] = _timestamp(payload.get("timestamp"))
            _LOGGER.info(
                "%s connector %s: %s -> %s",
                station["id"],
                cid,
                printable(connector.get("status"), 32),
                printable(status, 32),
            )
        connector["status"] = status
        connector["errorCode"] = error_code
        connector["vendorErrorCode"] = _text(payload.get("vendorErrorCode"), 50)
        connector["info"] = _text(payload.get("info"), 255)
        if status == "Available":
            connector["power"] = 0
            if connector.get("lastMeter"):  # no MeterValues arrive while idle, so don't show the last session's draw
                connector["lastMeter"] = {**connector["lastMeter"], "current_a": 0.0, "power_w": 0.0}
            if connector.get("transaction"):
                # Missed the StopTransaction; close the session so state doesn't stick.
                self._finish_transaction(station, connector, None, "Available", now_iso())
        self._spawn(self._enforce(station["id"], cid))
        return {}

    async def _on_Authorize(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        return {"idTagInfo": {"status": "Accepted"}}

    async def _on_StartTransaction(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        cid = self._connector_id(payload, 1) or 1
        connector = self._ensure_connector(station, cid)
        id_tag = _text(payload.get("idTag"), 64)
        started = _timestamp(payload.get("timestamp"))
        meter_start = _reading(payload.get("meterStart"))
        charger_clock = _parse_iso(payload.get("timestamp"))
        clock_start = _iso(charger_clock) if charger_clock and charger_clock.year >= 1970 else None
        open_tx = connector.get("transaction")
        if open_tx:
            # Compared by what the charger's clock said, not by the time we recorded: a charger
            # whose clock was never set gets "now" as the start each time it repeats itself.
            same = (open_tx.get("clockStart"), open_tx.get("meterStart"), open_tx.get("idTag")) == (
                clock_start,
                meter_start,
                id_tag,
            )
            if same and clock_start is not None:
                # The same StartTransaction again: the charger never saw our answer and, as OCPP
                # asks, repeats the request. Give it the same transaction, not a second session.
                return {"transactionId": open_tx["id"], "idTagInfo": {"status": "Accepted"}}
            # A different session on a connector that still has one open: the old one is over,
            # whether or not we were told. Close it, or it stays "not closed" in the history forever.
            self._finish_transaction(station, connector, None, "Superseded", started)
        tid = self.store.next_transaction_id()
        local_now = datetime.now(self.tz(station))
        price = self.price_at(station, local_now)
        connector["transaction"] = {
            "id": tid,
            "idTag": id_tag,
            "startAt": started,
            # What the charger's own clock said, however wrong the date: the length of a session
            # is the difference between two readings of that clock.
            "clockStart": clock_start,
            "meterStart": meter_start,
            "energy": 0,
            "power": 0,
            "meter": {},
            "priceKW": price,
            "priceTotal": 0.0,
            "lastSessionEnergy": 0.0,
        }
        connector["power"] = 0
        self.store.start_session(
            tid, station["id"], cid, id_tag, started, int(meter_start) if meter_start is not None else None, price
        )
        _LOGGER.info("%s connector %s: transaction %s started (meter %s Wh)", station["id"], cid, tid, meter_start)
        return {"transactionId": tid, "idTagInfo": {"status": "Accepted"}}

    async def _on_StopTransaction(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        tid = _small_int(payload.get("transactionId"), 1, 2**62)
        connectors = station["connectors"].values() if tid is not None else ()
        connector = next((c for c in connectors if (c.get("transaction") or {}).get("id") == tid), None)
        if connector is None:
            _LOGGER.warning(
                "%s: StopTransaction for unknown transaction %s",
                station["id"],
                printable(payload.get("transactionId"), 40),
            )
            return {"idTagInfo": {"status": "Accepted"}}
        self._finish_transaction(
            station,
            connector,
            _reading(payload.get("meterStop")),
            _text(payload.get("reason"), 50),
            _timestamp(payload.get("timestamp")),
            clock_stop=_parse_iso(payload.get("timestamp")),
        )
        # transactionData may carry final meter values. They are taken after the session is closed
        # on purpose: its begin/end readings can be the lifetime register even where MeterValues
        # count from zero, and must not be mistaken for the session's energy. Filed under the
        # session's id they are still there for repricing, which copes with either convention.
        self._take_meter_values(station, connector, payload.get("transactionData"), tid)
        return {"idTagInfo": {"status": "Accepted"}}

    def _finish_transaction(
        self,
        station: dict[str, Any],
        connector: dict[str, Any],
        meter_stop: Any,
        reason: str | None,
        stopped_at: str,
        clock_stop: datetime | None = None,
    ) -> None:
        tx = connector.get("transaction") or {}
        connector["transaction"] = None
        connector["power"] = 0
        if not tx:
            return
        energy = tx.get("energy")
        meter_start = _reading(tx.get("meterStart"))
        if meter_stop is not None and meter_start is not None:
            metered = _reading(energy) or 0.0  # what the MeterValues added up to
            lifetime = float(meter_stop) - float(meter_start)  # if meterStop is the lifetime register
            if meter_stop < meter_start:  # can only be session-relative, like this firmware's MeterValues
                energy = float(meter_stop)
            elif metered > 0 and abs(float(meter_stop) - metered) < abs(lifetime - metered):
                # Not smaller than meterStart, yet it continues the session-relative readings we
                # have been following: a session that delivered more than the register started at.
                energy = float(meter_stop)
            else:
                energy = lifetime
            connector["totalEnergyWh"] = float(meter_start) + energy
        start, stop = _parse_iso(tx.get("startAt")), _parse_iso(stopped_at)
        duration = max(0, int((stop - start).total_seconds())) if start and stop else None
        clock_start = _parse_iso(tx.get("clockStart"))
        if clock_start and clock_stop and clock_stop >= clock_start:
            # Both ends as the charger's clock read them. For a charger whose clock was never set
            # (1970) and which reports a session after the fact, our own timestamps for the two
            # messages are milliseconds apart; its clock still measured the session correctly.
            duration = int((clock_stop - clock_start).total_seconds())
        cost = float(_reading(tx.get("priceTotal")) or 0)
        # Cost builds up with each MeterValues reading. What was delivered after the last one (all
        # of it, if none arrived) is in the final energy but was never priced: do that now, the
        # way recalculating does, at the price in force at the end of the session (at its start
        # when there were no readings at all).
        unpriced = float(_reading(energy) or 0) - float(_reading(tx.get("lastSessionEnergy")) or 0)
        if unpriced > 0:
            metered = isinstance(tx.get("sessionRelativeRegister"), bool)
            moment = (stop if metered else start) or stop or start
            price = self.price_at(station, moment.astimezone(self.tz(station))) if moment else None
            cost += unpriced / 1000 * (price or 0)
        delivered = float(_reading(energy) or 0)
        self.store.finish_session(
            int(tx["id"]),
            stopped_at,
            int(meter_stop) if meter_stop is not None else None,
            energy,
            duration,
            cost,
            reason,
            cost / (delivered / 1000) if delivered > 0 else None,  # the average price, as recalculating records it
        )
        connector["lastSession"] = {
            **tx,
            "energy": energy,
            "priceTotal": cost,
            "stopAt": stopped_at,
            "duration": duration,
            "reason": reason,
        }
        _LOGGER.info(
            "%s connector %s: transaction %s stopped (%s Wh, %s)",
            station["id"],
            connector["id"],
            tx["id"],
            energy,
            printable(reason, 50),
        )

    async def _on_MeterValues(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        cid = self._connector_id(payload, 1) or 1
        connector = self._ensure_connector(station, cid)
        tid = _small_int(payload.get("transactionId"), 1, 2**62)
        self._take_meter_values(station, connector, payload.get("meterValue"), tid)
        return {}

    def _take_meter_values(
        self, station: dict[str, Any], connector: dict[str, Any], items: Any, tid: int | None
    ) -> None:
        """Apply a message's meterValue list (bounded) and store its samples in one transaction."""
        rows = [self._apply_meter_values(station, connector, mv, tid) for mv in _dicts(items, MAX_METER_VALUES)]
        self.store.add_samples([row for row in rows if row is not None])

    def _apply_meter_values(
        self, station: dict[str, Any], connector: dict[str, Any], mv: dict[str, Any], tid: int | None
    ) -> tuple[str, int, int | None, str, dict[str, Any]] | None:
        """Take one meterValue into the connector's state; returns the history row to store, if any."""
        at = _timestamp(mv.get("timestamp"))
        values: dict[str, Any] = {}
        for sv in _dicts(mv.get("sampledValue"), MAX_SAMPLED_VALUES):
            measurand = sv.get("measurand") or "Energy.Active.Import.Register"
            key = MEASURANDS.get(measurand) if isinstance(measurand, str) else None
            value = _reading(sv.get("value"), text=True)
            if key is None or value is None:
                continue
            value = float(value)
            if (key, sv.get("unit")) in (("energy_wh", "kWh"), ("power_w", "kW")):
                value *= 1000
            if sv.get("phase") and key in values:
                values[key] = max(values[key], value)  # keep the hottest phase; Grizzl-E is single phase anyway
            else:
                values[key] = value
        if not values:
            return None
        values["at"] = at
        connector["lastMeter"] = {**connector.get("lastMeter", {}), **values}
        if "power_w" in values:
            connector["power"] = values["power_w"]
        tx = connector.get("transaction")
        if tx:
            tx["meter"] = {**tx.get("meter", {}), **values}
            if "power_w" in values:
                tx["power"] = values["power_w"]
            if "energy_wh" in values:
                register = values["energy_wh"]
                meter_start = _reading(tx.get("meterStart"))
                if meter_start is None:
                    tx["meterStart"] = meter_start = register
                # Grizzl-E firmware reports Energy.Active.Import.Register relative to the start of
                # the session in MeterValues (it restarts at 0), while StartTransaction.meterStart is
                # the lifetime register. Detect which one we got, once: decided again on every
                # frame, a session-relative register that grows past meterStart (a long session on
                # a nearly new charger) would suddenly be read as the lifetime one, and the
                # session's energy would drop back to nearly nothing.
                session_relative = tx.get("sessionRelativeRegister")
                if not isinstance(session_relative, bool):
                    # A reading just under meterStart is the lifetime register reported more
                    # coarsely than meterStart was (kWh with a decimal or two), not a session
                    # that happens to have delivered almost exactly the charger's lifetime total.
                    shortfall = meter_start - register
                    session_relative = shortfall > min(1000.0, abs(meter_start) * 0.01)
                session_energy = register if session_relative else register - meter_start
                previous = tx.get("lastSessionEnergy")
                tx["sessionRelativeRegister"] = session_relative
                tx["energy"] = max(0.0, session_energy)
                connector["totalEnergyWh"] = float(meter_start) + tx["energy"]
                values["energy_wh"] = connector["totalEnergyWh"]  # store lifetime Wh in history
                if isinstance(previous, (int, float)):
                    delta_kwh = max(0.0, tx["energy"] - previous) / 1000
                    local_now = datetime.now(self.tz(station))
                    price = self.price_at(station, local_now) or 0
                    tx["priceKW"] = price
                    tx["priceTotal"] = float(tx.get("priceTotal") or 0) + delta_kwh * price
                tx["lastSessionEnergy"] = tx["energy"]
        elif "energy_wh" in values and (connector.get("totalEnergyWh") or 0) <= values["energy_wh"]:
            connector["totalEnergyWh"] = values["energy_wh"]
        return station["id"], connector["id"], tid or (tx or {}).get("id"), at, values

    @staticmethod
    def _data_transfer(payload: dict[str, Any], at: str | None) -> dict[str, Any]:
        data = payload.get("data")
        if data is not None and not isinstance(data, str):
            data = printable(data, 1000)  # not text: keep a bounded description of it
        return {
            "at": at,
            "vendorId": _text(payload.get("vendorId"), 255),
            "messageId": _text(payload.get("messageId"), 50),
            "data": data[:1000] if data is not None else None,
        }

    async def _on_DataTransfer(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        _LOGGER.info("%s: DataTransfer %s", station["id"], printable(payload, 300))
        kept = station.get("dataTransfers") if isinstance(station.get("dataTransfers"), list) else []
        station["dataTransfers"] = [*kept, self._data_transfer(payload, now_iso())][-20:]
        return {"status": "Accepted"}

    async def _on_DiagnosticsStatusNotification(
        self, station: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        station["diagnosticsStatus"] = _text(payload.get("status"), 32)
        return {}

    async def _on_FirmwareStatusNotification(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        station["firmwareStatus"] = _text(payload.get("status"), 32)
        return {}

    # --- outbound OCPP -------------------------------------------------------

    async def call(
        self, station_id: str, action: str, payload: dict[str, Any] | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        conn = self.connections.get(station_id)
        if conn is None or conn.ws.closed:
            raise OcppError("Offline", f"{station_id} is not connected")
        return await conn.call(action, payload, timeout)

    async def _after_boot(self, station_id: str) -> None:
        """Configure the charger the way the cloud does, then apply our settings."""
        await asyncio.sleep(2)
        station = self.station(station_id)
        if station is None:
            return
        s = self.settings
        for key, value in (
            ("HeartbeatInterval", str(s.heartbeat_interval)),
            ("MeterValueSampleInterval", str(s.meter_interval)),
            (
                "MeterValuesSampledData",
                "Energy.Active.Import.Register,Power.Active.Import,Current.Import,Voltage,Temperature",
            ),
            ("ClockAlignedDataInterval", "0"),
        ):
            try:
                result = await self.call(station_id, "ChangeConfiguration", {"key": key, "value": value})
                _LOGGER.info(
                    "%s: ChangeConfiguration %s=%s -> %s", station_id, key, value, printable(result.get("status"), 32)
                )
            except OcppError as err:
                _LOGGER.warning("%s: ChangeConfiguration %s failed: %s", station_id, key, err)
        try:
            result = await self.call(station_id, "GetConfiguration", {})
            config = self._clean_config(result.get("configurationKey"))
            if config:
                station["config"] = config
                self._learn_from_config(station, config)
                self._dirty = True
            _LOGGER.info("%s: %d configuration keys read", station_id, len(config))
        except OcppError as err:
            _LOGGER.warning("%s: GetConfiguration failed: %s", station_id, err)
        for cid in range(1, connector_count(station) + 1):
            try:
                await self.call(
                    station_id, "TriggerMessage", {"requestedMessage": "StatusNotification", "connectorId": cid}
                )
            except OcppError as err:
                _LOGGER.debug("%s: TriggerMessage failed: %s", station_id, err)
        await self._apply_limit(station_id, force=True)
        for cid in range(1, connector_count(station) + 1):
            await self._enforce(station_id, cid)

    @staticmethod
    def _clean_config(items: Any) -> dict[str, str | None]:
        """A GetConfiguration reply as ``{key: value}``: text keys and values only, a bounded number of them."""
        config: dict[str, str | None] = {}
        for item in _dicts(items, MAX_CONFIG_KEYS):
            key = item.get("key")
            if isinstance(key, str) and key and len(key) <= 100:
                config[_text(key, 100)] = _text(item.get("value"), 500)
        return config

    def _learn_from_config(self, station: dict[str, Any], config: dict[str, Any]) -> None:
        """Pick up what the charger tells us about itself (seen on a Duo, firmware UDGRW070L-04.03.2)."""
        dip = _small_int(config.get("DipSwitchCurrentLimit"), 1, MAX_CURRENT)
        if dip is not None:
            station["dipSwitchCurrentLimit"] = dip
        connectors = _small_int(config.get("NumberOfConnectors"), 1, MAX_CONNECTORS)
        if connectors is None and config.get("NumberOfConnectors") not in (None, ""):
            _LOGGER.warning(
                "%s: ignoring NumberOfConnectors=%s (expected 1..%d)",
                station["id"],
                printable(config.get("NumberOfConnectors"), 40),
                MAX_CONNECTORS,
            )
        if connectors is not None and not station.get("modelLocked"):
            station["connectorCount"] = connectors
            for cid in range(1, connectors + 1):
                self._ensure_connector(station, cid)
        auth_tag = config.get("AuthTag")
        if isinstance(auth_tag, str) and auth_tag and len(auth_tag) <= 64:
            station["idTag"] = auth_tag

    def effective_limit(self, station: dict[str, Any]) -> int | None:
        """Station current limit, overridden by an active window's own limit.

        The limit goes to the charger as one profile for the whole station, so when the connectors
        are in windows with different limits it has to be the lowest of them.
        """
        limit = station.get("currentLimit")
        local_now = datetime.now(self.tz(station))
        in_force = []
        for cid in range(1, connector_count(station) + 1):
            zone = self.window_now(station, local_now, cid)
            if zone and _reading(zone.get("currentLimit")) is not None:
                in_force.append(int(zone["currentLimit"]))
        if in_force:
            limit = min(in_force)
        return int(limit) if limit is not None else None

    async def _apply_limit(self, station_id: str, force: bool = False) -> None:
        station = self.station(station_id)
        if station is None or not self.is_online(station_id):
            return
        lo, hi = int(station.get("minCurrent") or 6), int(station.get("maxCurrent") or 80)
        wanted = self.effective_limit(station)
        if wanted is None:
            if not station.get("limitInForce"):
                return  # we never restricted this charger: leave its profile alone
            # A limit of ours is still in force (a window's own limit, and the window has ended, been
            # switched off or deleted). Nothing asks for one any more, so give the charger its full
            # current back; it would otherwise stay throttled for good.
            dip = station.get("dipSwitchCurrentLimit")
            limit = min(hi, dip) if isinstance(dip, int) and not isinstance(dip, bool) else hi
        else:
            limit = max(lo, min(wanted, hi))
        # Compare what would be sent, not what was asked for: a limit outside the charger's range
        # is clamped, and the unclamped number would never match, so every tick would send it again.
        if not force and station.get("appliedLimit") == limit:
            return
        profile = {
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
        }
        try:
            result = await self.call(station_id, "SetChargingProfile", profile)
            _LOGGER.info("%s: SetChargingProfile %s A -> %s", station_id, limit, printable(result.get("status"), 32))
            if result.get("status") == "Accepted":
                station["appliedLimit"] = limit
                station["limitInForce"] = wanted is not None
                self._dirty = True
        except OcppError as err:
            _LOGGER.warning("%s: SetChargingProfile failed: %s", station_id, err)

    async def _enforce(self, station_id: str, cid: int) -> None:
        """Make the connector's real state match its mode and schedule."""
        station = self.station(station_id)
        if station is None:
            return
        connector = self._ensure_connector(station, cid)
        local_now = datetime.now(self.tz(station))
        window = self.window_now(station, local_now, cid)
        nxt = next_change(station["pricesByZone"], local_now, cid, self.holiday_check(station))
        next_time = nxt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z") if nxt else None
        active = window is not None
        if connector.get("isActiveBySchedule") != active or connector.get("nextScheduleTime") != next_time:
            connector["isActiveBySchedule"] = active
            connector["nextScheduleTime"] = next_time
            self._dirty = True
        mode = connector.get("mode") or "Active"
        allowed = mode == "Active" or (mode == "Schedule" and window is not None)
        if not self.is_online(station_id):
            return
        status = connector.get("status")
        tx = connector.get("transaction")
        now = _time.monotonic()
        if allowed and tx is None and status in WANTS_START:
            action, stamp = "RemoteStartTransaction", "lastRemoteStart"
            payload = {"connectorId": cid, "idTag": station.get("idTag") or self.settings.id_tag}
        elif not allowed and tx is not None:
            action, stamp, payload = "RemoteStopTransaction", "lastRemoteStop", {"transactionId": tx["id"]}
        else:
            return
        if _recent(connector.get(stamp), now):
            return
        connector[stamp] = now
        try:
            result = await self.call(station_id, action, payload)
            _LOGGER.info("%s connector %s: %s -> %s", station_id, cid, action, printable(result.get("status"), 32))
        except OcppError as err:
            _LOGGER.warning("%s connector %s: %s failed: %s", station_id, cid, action, err)

    # --- commands (from the REST API) -----------------------------------------

    def _require(self, station_id: str) -> dict[str, Any]:
        station = self.station(station_id)
        if station is None:
            raise KeyError(station_id)
        return station

    async def set_mode(self, station_id: str, mode: str, connector_id: int = 0) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        station = self._require(station_id)
        count = connector_count(station)
        if isinstance(connector_id, bool) or not isinstance(connector_id, int) or not 0 <= connector_id <= count:
            raise ValueError(f"connectorId must be 0 (all) or 1..{count}")
        targets = [connector_id] if connector_id else range(1, count + 1)
        for cid in targets:
            connector = self._ensure_connector(station, int(cid))
            connector["mode"] = mode
            connector["lastRemoteStart"] = None
            connector["lastRemoteStop"] = None
        self._dirty = True
        for cid in targets:
            await self._enforce(station_id, int(cid))

    async def set_current_limit(self, station_id: str, amps: int) -> None:
        station = self._require(station_id)
        lo, hi = int(station.get("minCurrent") or 6), int(station.get("maxCurrent") or 80)
        dip = station.get("dipSwitchCurrentLimit")
        if isinstance(dip, int):
            hi = min(hi, dip)
        if not lo <= int(amps) <= hi:
            raise ValueError(f"current limit must be between {lo} and {hi} A")
        station["currentLimit"] = int(amps)
        self._dirty = True
        await self._apply_limit(station_id, force=True)

    async def set_base_rate(self, station_id: str, price_kwh: float) -> None:
        station = self._require(station_id)
        price = _to_float(price_kwh)
        if price is None or price < 0:
            raise ValueError("priceKW must be a number, zero or more")
        station["priceKW"] = price
        self._dirty = True

    async def upsert_zone(self, station_id: str, price: dict[str, Any]) -> dict[str, Any]:
        """Add a schedule or rate zone, or change the one with the same ``_id``.

        The zone is validated before anything is stored: a zone the tick can't evaluate must never
        reach the list, least of all together with an error reply that says nothing was saved.
        """
        station = self._require(station_id)
        zones = station["pricesByZone"]
        if not isinstance(price, dict):
            raise ValueError("price object required")
        given_id = parse_zone_id(price["_id"]) if price.get("_id") not in (None, "") else None
        existing = next((z for z in zones if z.get("_id") == given_id), None) if given_id else None
        if existing is None:
            if len(zones) >= MAX_ZONES:
                raise ValueError(f"a station can have at most {MAX_ZONES} schedules and rate zones")
            zone = normalize_zone(price, **ZONE_LIMITS)
            zone["_id"] = given_id or secrets.token_hex(12)
            zone.setdefault("scheduleEnabled", bool(zone.get("isSchedule")))
            zones.append(zone)
        else:
            zone = normalize_zone({**existing, **price}, **ZONE_LIMITS)
            zone["_id"] = existing["_id"]
            existing.clear()
            existing.update(zone)
            zone = existing
        self._dirty = True
        await self._refresh_all(station_id)
        return zone

    async def set_zone_enabled(self, station_id: str, zone_id: str, enabled: bool) -> None:
        station = self._require(station_id)
        zone = next((z for z in station["pricesByZone"] if z.get("_id") == zone_id), None)
        if zone is None:
            raise KeyError(zone_id)
        zone["scheduleEnabled"] = bool(enabled)
        self._dirty = True
        await self._refresh_all(station_id)

    async def delete_zone(self, station_id: str, zone_id: str) -> None:
        station = self._require(station_id)
        before = len(station["pricesByZone"])
        station["pricesByZone"] = [z for z in station["pricesByZone"] if z.get("_id") != zone_id]
        if len(station["pricesByZone"]) == before:
            raise KeyError(zone_id)
        self._dirty = True
        await self._refresh_all(station_id)

    async def _refresh_all(self, station_id: str) -> None:
        station = self._require(station_id)
        for cid in range(1, connector_count(station) + 1):
            await self._enforce(station_id, cid)
        await self._apply_limit(station_id)

    async def set_holidays(self, station_id: str, raw: dict[str, Any]) -> dict[str, Any]:
        station = self._require(station_id)
        station["holidaysSettings"] = holiday_calendar.normalize(raw)
        self._dirty = True
        await self._refresh_all(station_id)
        return station["holidaysSettings"]

    def _reprice(
        self,
        station: dict[str, Any],
        meter_start: Any,
        total_wh: float,
        samples: list[dict[str, Any]],
        start_at: str | None,
        end_at: str | None,
    ) -> float:
        """Cost of a session under today's rates: each slice of energy at the price in force when it was metered.

        Samples hold either the lifetime register or energy since the session started (the Duo's
        firmware does the latter); both are reduced to "Wh so far". Energy the samples don't
        account for, such as the tail before StopTransaction or a session whose samples have been
        pruned, is priced at the end (or, with no samples at all, the start) of the session.
        """
        tz = self.tz(station)

        def price_at(stamp: str | None) -> float:
            moment = _parse_iso(stamp)
            return (self.price_at(station, moment.astimezone(tz)) or 0.0) if moment else 0.0

        base = float(meter_start) if isinstance(meter_start, (int, float)) else None
        cost, counted = 0.0, 0.0
        for row in samples:
            reading = float(row["energy_wh"])
            so_far = min(reading - base if base is not None and reading >= base else reading, total_wh)
            if so_far > counted:
                cost += (so_far - counted) / 1000 * price_at(row["at"])
                counted = so_far
        if total_wh > counted:
            cost += (total_wh - counted) / 1000 * price_at((end_at or start_at) if samples else start_at)
        return cost

    async def recalculate_costs(self, station_id: str) -> dict[str, Any]:
        """Reprice every recorded session, and the ones in progress, with the current rates and holidays."""
        station = self._require(station_id)
        live = {
            int(c["transaction"]["id"]): c["transaction"]
            for c in station["connectors"].values()
            if c.get("transaction")
        }
        before = after = 0.0
        count = 0
        repriced: list[tuple[int, float, float | None]] = []
        for row in self.store.sessions(station_id, 100000):
            tx = live.get(row["id"]) if row["stop_at"] is None else None
            if tx is not None:
                energy = float(tx.get("energy") or 0)
                old = float(tx.get("priceTotal") or 0)
            elif row["energy_wh"] is not None:
                energy = float(row["energy_wh"])
                old = float(row["cost"] or 0)
            else:
                continue  # never closed and not running: nothing to price
            samples = self.store.energy_samples(station_id, row["id"])
            cost = self._reprice(station, row["meter_start"], energy, samples, row["start_at"], row["stop_at"])
            if tx is not None:
                tx["priceTotal"] = cost
                tx["lastSessionEnergy"] = energy
            else:
                repriced.append((row["id"], round(cost, 6), cost / (energy / 1000) if energy > 0 else None))
            before += old
            after += cost
            count += 1
        # One transaction for all of them: a commit per session would keep the event loop (and with
        # it every charger) waiting on the disk for as long as the history is deep.
        self.store.set_session_costs(repriced)
        self._dirty = True
        _LOGGER.info("%s: repriced %d sessions, %.2f -> %.2f", station_id, count, before, after)
        return {"sessions": count, "cost_before": round(before, 4), "cost_after": round(after, 4)}

    async def reboot(self, station_id: str) -> dict[str, Any]:
        self._require(station_id)
        return await self.call(station_id, "Reset", {"type": "Soft"})

    async def update_settings(self, station_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        """Local-only tweaks: display name, timezone, currency, connector count, current bounds.

        Everything is checked first and applied only if all of it is acceptable, so a request that
        is refused changes nothing.
        """
        station = self._require(station_id)
        changes: dict[str, Any] = {}
        name = patch.get("displayName")
        if isinstance(name, str) and name.strip():
            if len(name.strip()) > MAX_NAME_LENGTH:
                raise ValueError(f"displayName can't be longer than {MAX_NAME_LENGTH} characters")
            changes["displayName"] = name.strip()
        timezone = patch.get("timezone")
        if isinstance(timezone, str) and timezone:
            try:
                ZoneInfo(timezone)
            except Exception:  # noqa: BLE001 - unknown key, or not a valid key at all
                raise ValueError(f"unknown timezone {timezone[:64]!r}") from None
            changes["timezone"] = timezone
        currency = patch.get("currency")
        if isinstance(currency, str) and currency:
            if not (len(currency) == 3 and currency.isascii() and currency.isalpha()):
                raise ValueError("currency must be a three-letter code such as USD")
            changes["currency"] = currency.upper()
        for key, lo, hi in (
            ("connectorCount", 1, MAX_CONNECTORS),
            ("maxCurrent", 1, MAX_CURRENT),
            ("minCurrent", 1, MAX_CURRENT),
            ("dipSwitchCurrentLimit", 1, MAX_CURRENT),
        ):
            if key not in patch:
                continue
            if patch[key] is None and key == "dipSwitchCurrentLimit":
                changes[key] = None  # "not known"
                continue
            value = _small_int(patch[key], lo, hi)
            if value is None:
                raise ValueError(f"{key} must be a whole number from {lo} to {hi}")
            changes[key] = value
        low = changes.get("minCurrent", station.get("minCurrent"))
        high = changes.get("maxCurrent", station.get("maxCurrent"))
        if isinstance(low, int) and isinstance(high, int) and low > high:
            raise ValueError("minCurrent can't be greater than maxCurrent")

        station.update(changes)
        if any(key in changes for key in ("connectorCount", "maxCurrent", "minCurrent")):
            station["modelLocked"] = True
        if "connectorCount" in changes:
            for cid in range(1, changes["connectorCount"] + 1):
                self._ensure_connector(station, cid)
        self._dirty = True
        return station

    def delete_station(self, station_id: str) -> None:
        """Forget a station: its settings, and its recorded sessions and samples with it."""
        self.stations.pop(station_id, None)
        self.store.delete_history(station_id)
        for tasks in (self._boot_tasks, self._station_ticks):
            task = tasks.pop(station_id, None)
            if task is not None and not task.done():
                task.cancel()
        self._dirty = True

    # --- background loop ------------------------------------------------------

    async def _tick_station(self, station_id: str) -> None:
        """One round of enforcement for one station.

        Each station gets its own task: these calls wait on the charger (up to the call timeout,
        per connector), and a charger that doesn't answer must only ever hold up itself.
        """
        station = self.station(station_id)
        if station is None:
            return
        await self._refresh_all(station_id)
        for connector in station["connectors"].values():
            tx = connector.get("transaction")
            if tx and connector.get("status") in PLUGGED_IN:
                start = _parse_iso(tx.get("startAt"))
                tx["duration"] = max(0, int((datetime.now(UTC) - start).total_seconds())) if start else None

    def save(self) -> None:
        """Write the state if it changed. Never raises: a failed save is logged and retried later."""
        if not self._dirty:
            return
        self._dirty = False
        try:
            self.store.save()
        except Exception:  # noqa: BLE001 - keep running; try again on the next tick
            self._dirty = True
            _LOGGER.exception("saving state failed")

    async def run(self) -> None:
        last_prune = float("-inf")
        while not self._stopping:
            try:
                for station_id in list(self.stations):
                    running = self._station_ticks.get(station_id)
                    if running is None or running.done():  # still busy with a slow charger: let it finish
                        self._station_ticks[station_id] = self._spawn(self._tick_station(station_id))
                for station_id in [sid for sid, task in self._station_ticks.items() if task.done()]:
                    if station_id not in self.stations:
                        del self._station_ticks[station_id]
                for station_id in [sid for sid, task in self._boot_tasks.items() if task.done()]:
                    del self._boot_tasks[station_id]
                if _time.monotonic() - last_prune > 3600:
                    last_prune = _time.monotonic()
                    self.store.prune_samples()
            except Exception:  # noqa: BLE001
                _LOGGER.exception("controller tick failed")
            # Whatever went wrong above, what is in memory still gets written.
            self.save()
            await asyncio.sleep(self.settings.tick_seconds)

    # How long closing the chargers' sockets may take at shutdown, all of them together.
    CLOSE_TIMEOUT = 3.0

    async def stop(self) -> None:
        self._stopping = True
        for task in list(self._tasks):
            task.cancel()
        # Save first. Closing a socket waits for the peer to acknowledge, a dead peer never does,
        # and whoever asked us to stop (Docker: ten seconds) may not wait for all of them.
        self._dirty = True
        self.save()
        closing = [conn.close() for conn in list(self.connections.values())]
        if closing:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(asyncio.gather(*closing, return_exceptions=True), self.CLOSE_TIMEOUT)
        self.save()
