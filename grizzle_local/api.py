"""REST API shaped like connect-api.unitedchargers.com, plus a few local extras.

Only the subset the Grizzl-E Connect app and the Home Assistant integration use is
implemented. Station ids are the charger serial (the cloud uses Mongo ids).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import re
import secrets
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from aiohttp import web

from . import __version__, holiday_calendar
from .controller import MAX_CONNECTORS, MODES, Controller, _iso, _parse_iso, _same_secret, connector_count
from .ocpp import CP_ID_RE, OcppError, printable
from .tls import client_ip

_LOGGER = logging.getLogger(__name__)

TOKEN_TTL = 7 * 24 * 3600  # how long a bearer token works
REFRESH_TTL = 30 * 24 * 3600  # how long its refresh token can still get a new one
MAX_TOKENS = 100  # sessions kept; the oldest make room
# Logout is public on purpose: a session whose token has just expired must still be endable (its
# refresh token lives on for weeks). Tokens are unguessable, so there is nothing to protect here.
PUBLIC_PATHS = ("/client/auth/login", "/client/auth/refresh-token", "/client/auth/logout", "/health", "/")
# Failed sign-ins allowed per client within the window before it has to wait, and from all clients
# together before sign-in closes for clients that have never signed in successfully.
LOGIN_MAX_FAILURES = 10
LOGIN_MAX_TOTAL_FAILURES = 200
LOGIN_WINDOW_SECONDS = 300
MAX_SESSION_ROWS = 1000  # most sessions one request returns
MAX_OCPP_CALL_TIMEOUT = 120.0
# PBKDF2-HMAC-SHA256 rounds for the mark that tells us the sign-in credentials have changed.
CREDENTIAL_ROUNDS = 600_000
# Host names nobody can register in public DNS, so no web site can point one of them at this server.
PRIVATE_NAME_SUFFIXES = (
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
)
# The names the charger calls us by (and the certificate from scripts/make-cert.sh is for). Only a
# DNS override on the owner's own network makes them lead here.
VENDOR_HOSTS = ("ocpp.unitedchargers.com", "connect-api.unitedchargers.com")
_INTEGER_RE = re.compile(r"-?[0-9]{1,10}")


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _last_list(value: Any) -> list[Any] | None:
    return None if value is None else [value]


def build_charge(station: dict[str, Any], connector: dict[str, Any]) -> dict[str, Any] | None:
    tx = connector.get("transaction")
    if not tx:
        return None
    meter = tx.get("meter") or {}
    return {
        "_id": str(tx["id"]),
        "transactionId": tx["id"],
        "station": station["id"],
        "stationSerialNumber": station["id"],
        "idTag": tx.get("idTag"),
        "connectorId": connector["id"],
        "startAt": tx.get("startAt"),
        "duration": tx.get("duration") or 0,
        "energy": round(float(tx.get("energy") or 0), 1),
        "status": 0,
        "power": tx.get("power") or 0,
        "meterValues": {
            "currentImport": _last_list(meter.get("current_a")),
            "currentOffered": _last_list(meter.get("current_offered_a")),
            "energyActiveImportRegister": _last_list(meter.get("energy_wh")),
            "powerActiveImport": _last_list(meter.get("power_w")),
            "SoC": _last_list(meter.get("soc")),
            "temperature": _last_list(meter.get("temperature_c")),
            "voltage": _last_list(meter.get("voltage_v")),
            "priceKW": _last_list(tx.get("priceKW")),
            "date": _last_list(meter.get("at")),
        },
        "hasMeterValues": bool(meter),
        "currency": station.get("currency"),
        "priceKW": tx.get("priceKW"),
        "priceTotal": round(float(tx.get("priceTotal") or 0), 4),
        "meterStart": tx.get("meterStart"),
        "temperatureUnit": "Celsius",
        "isCommercial": False,
        "costByZones": [],
    }


def build_connector(station: dict[str, Any], connector: dict[str, Any]) -> dict[str, Any]:
    max_current = int(station.get("maxCurrent") or 40)
    meter = connector.get("lastMeter") or {}
    return {
        "_id": f"{station['id']}-{connector['id']}",
        "connectorId": connector["id"],
        "type": "J1772",
        "maxPower": max_current * 240,
        "status": connector.get("status") or "Unavailable",
        "power": connector.get("power") or 0,
        "errorCode": connector.get("errorCode") or "NoError",
        "mode": connector.get("mode") or "Active",
        "charge": build_charge(station, connector),
        "statusChangedAt": connector.get("statusChangedAt"),
        "isActiveBySchedule": connector.get("isActiveBySchedule"),
        "nextScheduleTime": connector.get("nextScheduleTime"),
        # Extras the cloud doesn't have, handy for dashboards: latest readings even when idle.
        "lastMeter": {
            "currentImport": meter.get("current_a"),
            "voltage": meter.get("voltage_v"),
            "temperature": meter.get("temperature_c"),
            "energyActiveImportRegister": meter.get("energy_wh"),
            "date": meter.get("at"),
        },
        "totalEnergyWh": connector.get("totalEnergyWh"),
    }


def build_station(controller: Controller, station: dict[str, Any]) -> dict[str, Any]:
    connectors = [
        build_connector(station, station["connectors"][str(cid)])
        for cid in range(1, connector_count(station) + 1)
        if str(cid) in station["connectors"]
    ]
    online = controller.is_online(station["id"])
    statuses = [c["status"] for c in connectors]
    status = "Charging" if "Charging" in statuses else (statuses[0] if statuses else "Unavailable")
    modes = {c["mode"] for c in connectors}
    boot = station.get("boot") or {}
    model = station.get("model") or {}
    max_current = int(station.get("maxCurrent") or 40)
    limit = station.get("currentLimit")
    holiday_settings = {**holiday_calendar.DEFAULTS, **(station.get("holidaysSettings") or {})}
    today = datetime.now(controller.tz(station)).date()
    return {
        "id": station["id"],
        "_id": station["id"],
        "identity": station["id"],
        "serialNumber": station["id"],
        "displayName": station.get("displayName") or station["id"],
        "online": online,
        "mode": modes.pop() if len(modes) == 1 else "Active",
        "status": status if online else "Unavailable",
        "errorCode": station.get("errorCode") or "NoError",
        "schedule": {
            "enabled": any(z.get("scheduleEnabled") for z in station["pricesByZone"]),
            "weekdaysEnabled": False,
            "weekendsEnabled": False,
        },
        "connectors": connectors,
        "currency": station.get("currency"),
        "priceKW": station.get("priceKW") or 0,
        "locationData": {"timezone": station.get("timezone"), "autoselectTimezone": False},
        "bootNotification": {
            "chargePointModel": boot.get("chargePointModel"),
            "chargePointSerialNumber": boot.get("chargePointSerialNumber"),
            "chargePointVendor": boot.get("chargePointVendor"),
            "firmwareVersion": boot.get("firmwareVersion"),
            "meterType": boot.get("meterType"),
            "timestamp": boot.get("timestamp"),
        },
        "firmwareStatuses": [],
        "vendorData": {"formattedSerialNumber": station["id"], "chargerType": model.get("code")},
        "strategy": "Default",
        "model": {
            "_id": model.get("code") or "local",
            "name": model.get("name"),
            "displayName": model.get("name"),
            "maxCurrent": max_current,
            "minCurrent": int(station.get("minCurrent") or 6),
            "numberOfPhases": "OnePhase",
            "connectors": [{"maxPower": max_current * 240 / 1000, "type": "type1"} for _ in connectors],
            "strategy": "Default",
        },
        "smartCharging": {
            "applied": limit is not None,
            "currentLimit": limit,
            "weekdaysCurrentLimit": limit,
            "weekendsCurrentLimit": limit,
            "appliedLimit": station.get("appliedLimit"),
        },
        "supportedOcppProfiles": {
            "profiles": ["Core", "SmartCharging", "RemoteTrigger"],
            "firmwareVersion": boot.get("firmwareVersion"),
        },
        "pricesByZone": station["pricesByZone"],
        "holidaysSettings": holiday_settings,
        "holidays": [
            {"date": row["date"], "name": row["name"]}
            for row in (holiday_calendar.upcoming(holiday_settings, today, 370) if holiday_settings["enabled"] else [])
            if row["included"]
        ],
        "holidayToday": holiday_calendar.holiday_name(holiday_settings, today) if holiday_settings["enabled"] else None,
        "sharedWith": [],
        "isSharedAccess": False,
        "dipSwitchCurrentLimit": station.get("dipSwitchCurrentLimit"),
        "isActiveBySchedule": any(c.get("isActiveBySchedule") for c in connectors),
        "nextScheduleTime": min((c["nextScheduleTime"] for c in connectors if c.get("nextScheduleTime")), default=None),
        "powerSharingMode": 0,
        "lastSeen": station.get("lastSeen"),
        "firstSeen": station.get("firstSeen"),
        "config": station.get("config") or {},
        "user": {"_id": "local", "firstName": "Local", "lastName": "Server", "email": controller.settings.api_email},
    }


# --- auth ------------------------------------------------------------------------


class LoginThrottle:
    """Slows password guessing.

    - Per client: a few failures per window, then that client waits. IPv6 clients are counted by
      their /64, since one machine can use any address in its own.
    - Overall: when failures pour in from many clients at once, sign-in closes for every client
      that has not signed in successfully before. The owner's usual address keeps working, and
      sessions that already exist are not affected at all.
    """

    MAX_CLIENTS = 4096
    MAX_KNOWN = 256

    def __init__(
        self,
        max_failures: int = LOGIN_MAX_FAILURES,
        window: float = LOGIN_WINDOW_SECONDS,
        max_total: int = LOGIN_MAX_TOTAL_FAILURES,
    ) -> None:
        self.max_failures = max_failures
        self.window = window
        self.max_total = max_total
        self._failures: dict[str, deque[float]] = {}
        self._all: deque[float] = deque(maxlen=max_total)
        self._known: dict[str, None] = {}  # clients that have signed in (a dict for its insertion order)

    @staticmethod
    def key(client: str) -> str:
        """What counts as one client: an IPv4 address, or an IPv6 /64."""
        try:
            address = ipaddress.ip_address(client.split("%", 1)[0])
        except ValueError:
            return client
        if address.version == 4:
            return str(address)
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)  # ::ffff:192.0.2.1 is the IPv4 client 192.0.2.1
        return f"{ipaddress.ip_network((address, 64), strict=False).network_address}/64"

    def _wait(self, failures: deque[float] | None, limit: int, now: float) -> int:
        if not failures:
            return 0
        while failures and now - failures[0] >= self.window:
            failures.popleft()
        if len(failures) < limit:
            return 0
        return max(1, math.ceil(self.window - (now - failures[0])))

    def retry_after(self, client: str, now: float | None = None) -> int:
        """Seconds this client must wait before trying again; 0 if it may try now."""
        now = time.monotonic() if now is None else now
        key = self.key(client)
        wait = self._wait(self._failures.get(key), self.max_failures, now)
        if key in self._failures and not self._failures[key]:
            del self._failures[key]
        if not wait and key not in self._known:
            wait = self._wait(self._all, self.max_total, now)
        return wait

    def failed(self, client: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        key = self.key(client)
        if key not in self._failures and len(self._failures) >= self.MAX_CLIENTS:
            # Make room, but not by forgetting a client that is locked out right now if there is
            # any other: otherwise a crowd of addresses would be a way to reset one's own count.
            idle = (k for k, f in self._failures.items() if not self._wait(f, self.max_failures, now))
            del self._failures[next(idle, next(iter(self._failures)))]
        self._failures.setdefault(key, deque(maxlen=self.max_failures)).append(now)
        self._all.append(now)

    def succeeded(self, client: str) -> None:
        key = self.key(client)
        self._failures.pop(key, None)
        self._known.pop(key, None)
        self._known[key] = None
        while len(self._known) > self.MAX_KNOWN:
            del self._known[next(iter(self._known))]


def origin_allowed(origin: str, host_header: str, allowed_hosts: tuple[str, ...]) -> bool:
    """May a browser page from ``origin`` use the API?

    Only browsers send Origin, and they send it with every request that changes something
    (signing in included). The page we serve is reached by an address on the local network or a
    name only the local network knows, and those are let through. What is refused is a page from a
    public DNS name: either another web site posting to us (it can't read the answer, but it could
    burn the owner's sign-in attempts), or a site that re-pointed its own name at this server (DNS
    rebinding), which the browser would otherwise treat as the API's own origin. A deliberate
    public name (a reverse proxy, say) is allowed with GRIZZLE_ALLOWED_HOSTS.
    """
    if "*" in allowed_hosts:
        return True
    try:
        parts = urlsplit(origin)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not host:
        return False  # "null" (a sandboxed frame, a local file), browser extensions, anything else
    if host in allowed_hosts or host in VENDOR_HOSTS:
        return True
    if any(host.endswith(suffix) for suffix in allowed_hosts if suffix.startswith(".")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host == "localhost" or "." not in host or host.endswith(PRIVATE_NAME_SUFFIXES)
    if not address.is_global:
        return True  # a machine on the local network: nothing it couldn't send us directly
    try:
        served_as = (urlsplit(f"//{host_header}").hostname or "").lower()
    except ValueError:
        return False
    return served_as == host  # a public address is fine only as our own page's


class Auth:
    def __init__(self, controller: Controller) -> None:
        self.controller = controller
        self.throttle = LoginThrottle()
        self._credentials_checked = False
        if self._tokens:
            # Sessions from before this start: are they for the credentials we have now?
            self._check_credentials()

    def _credentials_mark(self, salt: bytes) -> str:
        settings = self.controller.settings
        material = f"{settings.api_email.strip().lower()}\0{settings.api_password}".encode("utf-8", "surrogatepass")
        return hashlib.pbkdf2_hmac("sha256", material, salt, CREDENTIAL_ROUNDS).hex()

    def _check_credentials(self) -> None:
        """Sign every session out if the email or password is no longer what it was when they signed in.

        Changing the password is how an owner locks out someone who got hold of a session; it has
        to actually do that. state.json keeps a salted, slow hash of the credentials to compare with
        (not the password, and not something that makes guessing it cheap).
        """
        self._credentials_checked = True
        state = self.controller.store.state
        saved = state.get("credentials")
        if isinstance(saved, dict) and isinstance(saved.get("salt"), str) and isinstance(saved.get("mark"), str):
            try:
                mark = self._credentials_mark(bytes.fromhex(saved["salt"]))
                same = secrets.compare_digest(mark.encode(), saved["mark"].encode("utf-8", "surrogatepass"))
            except ValueError:
                same = False
            if same:
                return
            if self._tokens:
                _LOGGER.warning(
                    "the API email or password has changed: signing out %d existing session(s)", len(self._tokens)
                )
                self._tokens.clear()
        elif self._tokens:
            # Sessions from a version that kept no mark. Nothing says which password they were
            # signed in with (it may be the one that was just changed, in this very restart), and
            # their tokens may have travelled in URLs. Everyone signs in once more.
            _LOGGER.warning(
                "signing out %d session(s) saved by an earlier version: sign in again (Home Assistant does so itself)",
                len(self._tokens),
            )
            self._tokens.clear()
        salt = secrets.token_bytes(16)
        state["credentials"] = {"salt": salt.hex(), "mark": self._credentials_mark(salt)}
        self.controller.mark_dirty()

    @property
    def _tokens(self) -> dict[str, dict[str, Any]]:
        return self.controller.store.state["tokens"]

    def user(self) -> dict[str, Any]:
        return {
            "_id": "local",
            "email": self.controller.settings.api_email,
            "firstName": "Local",
            "lastName": "Server",
        }

    @staticmethod
    def _refresh_expiry(info: dict[str, Any]) -> float:
        # Sessions saved by an older version have no refresh expiry of their own.
        return info.get("refreshExpires") or info["expires"] + (REFRESH_TTL - TOKEN_TTL)

    def issue(self) -> dict[str, Any]:
        if not self._credentials_checked:
            self._check_credentials()
        self._gc()
        now = time.time()
        token, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._tokens[token] = {"refresh": refresh, "expires": now + TOKEN_TTL, "refreshExpires": now + REFRESH_TTL}
        while len(self._tokens) > MAX_TOKENS:
            del self._tokens[min(self._tokens, key=lambda t: self._tokens[t]["expires"])]
        self.controller.mark_dirty()
        return {"token": token, "refreshToken": refresh, "isVerified": True, "user": self.user()}

    def refresh(self, refresh_token: str) -> dict[str, Any] | None:
        now = time.time()
        for token, info in list(self._tokens.items()):
            if _same_secret(refresh_token, info["refresh"]):
                del self._tokens[token]
                self.controller.mark_dirty()
                return self.issue() if self._refresh_expiry(info) > now else None
        return None

    def valid(self, token: str) -> bool:
        info = self._tokens.get(token) if token else None
        return bool(info) and info["expires"] > time.time()

    def revoke(self, token: str = "", refresh_token: str = "") -> None:
        """Forget a session, named by its token or its refresh token: neither works afterwards."""
        doomed = [token] if token in self._tokens else []
        if refresh_token:
            doomed += [t for t, info in self._tokens.items() if _same_secret(refresh_token, info["refresh"])]
        for found in doomed:
            self._tokens.pop(found, None)
        if doomed:
            self.controller.mark_dirty()

    def _gc(self) -> None:
        now = time.time()
        for token in [t for t, info in self._tokens.items() if self._refresh_expiry(info) < now]:
            del self._tokens[token]


def _finite(value: Any) -> Any:
    """The same structure with NaN/Infinity replaced by None."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {key: _finite(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_finite(item) for item in value]
    return value


def _dumps(data: Any) -> str:
    """Strict JSON. Python would happily write NaN, which no browser (or Home Assistant) can parse."""
    try:
        return json.dumps(data, allow_nan=False)
    except ValueError:
        return json.dumps(_finite(data), allow_nan=False)


def _json(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> web.Response:
    return web.json_response(data, status=status, headers=headers, dumps=_dumps)


def _json_error(status: int, message: str, headers: dict[str, str] | None = None) -> web.Response:
    return _json({"message": message, "statusCode": status}, status=status, headers=headers)


def _bad_request(message: str) -> web.HTTPBadRequest:
    """An exception to raise from a handler: a 400 in the API's usual error shape."""
    return web.HTTPBadRequest(
        text=json.dumps({"message": message, "statusCode": 400}), content_type="application/json"
    )


def _bearer(request: web.Request) -> str:
    """The bearer token from the Authorization header ("" if there is none).

    Only the header: a token in the query string ends up in browser history, proxy logs and
    Referer headers.
    """
    header = request.headers.get("Authorization", "")
    return header[7:].strip() if header[:7].lower() == "bearer " else ""


@web.middleware
async def auth_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    path = request.path
    # Chargers connect outside /client and /local, so they never need a token. Do NOT exempt
    # requests by their Upgrade header: aiohttp still routes such a request to the REST handler
    # for its path, so a header check would let anyone skip authentication.
    api = path.startswith("/client/") or path.startswith("/local/")
    if api:
        refusal = _refuse_origin(request)  # before the public sign-in paths: they are what it protects most
        if refusal is not None:
            return refusal
    if path in PUBLIC_PATHS or not api:
        return await handler(request)
    auth: Auth = request.app["auth"]
    if not auth.valid(_bearer(request)):
        return _json_error(401, "Unauthorized")
    return await handler(request)


def _refuse_origin(request: web.Request) -> web.Response | None:
    """A 403 for an API request made by a web page we don't accept requests from, else None."""
    origin = request.headers.get("Origin")
    if origin is None:
        return None  # not a browser (Home Assistant, curl), or a same-origin read
    settings = request.app["settings"]
    if origin_allowed(origin, request.headers.get("Host", ""), settings.allowed_hosts):
        return None
    try:
        name = printable(urlsplit(origin).hostname or origin, 100)
    except ValueError:
        name = printable(origin, 100)
    _LOGGER.warning(
        "refused %s %s from a web page at %s. If that is how you open this server, set GRIZZLE_ALLOWED_HOSTS=%s "
        "(names with a dot that are not LAN-only by their ending have to be listed; it guards against DNS rebinding)",
        request.method,
        printable(request.path, 100),
        printable(origin, 100),
        name,
    )
    return _json_error(
        403,
        f"This server does not accept requests from a page opened as {name}. If that is how you open it, set "
        f"GRIZZLE_ALLOWED_HOSTS={name} in the server's configuration and restart it; opening the page by its IP "
        "address works without that.",
    )


# --- handlers -------------------------------------------------------------------


async def _body(request: web.Request) -> dict[str, Any]:
    if not request.can_read_body:
        return {}
    try:
        data = await request.json()
    except web.HTTPException:
        raise  # 413 for a body over the size limit, and the like
    except Exception:  # noqa: BLE001
        # Not JSON, thousands of nested brackets (RecursionError), "charset=no-such-codec"
        # (LookupError), a Content-Encoding the body doesn't match (aiohttp's payload errors)...
        # however a body fails to read, it is the sender's mistake, not a server error.
        raise _bad_request("invalid JSON") from None
    return data if isinstance(data, dict) else {}


def _controller(request: web.Request) -> Controller:
    return request.app["controller"]


def _station_or_404(request: web.Request) -> dict[str, Any]:
    station = _controller(request).station(request.match_info["station_id"])
    if station is None:
        raise web.HTTPNotFound(text="unknown station")
    return station


def _whole(value: Any, name: str, lo: int, hi: int, default: int | None = None) -> int:
    """An integer parameter in ``lo..hi`` (from JSON or a query string), or a 400."""
    if value is None or value == "":
        if default is not None:
            return default
        raise _bad_request(f"{name} is required")
    number: int | None = None
    if isinstance(value, bool):
        pass
    elif isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str) and _INTEGER_RE.fullmatch(value.strip()):
        number = int(value.strip())
    if number is None or not lo <= number <= hi:
        raise _bad_request(f"{name} must be a whole number from {lo} to {hi}")
    return number


def _row_limit(request: web.Request, default: int) -> int:
    """``?limit=``: any whole number, brought into 1..MAX_SESSION_ROWS (as before); anything else is a 400."""
    asked = _whole(request.query.get("limit"), "limit", -(10**9), 10**9, default=default)
    return max(1, min(asked, MAX_SESSION_ROWS))


async def login(request: web.Request) -> web.Response:
    auth: Auth = request.app["auth"]
    client = client_ip(request)
    # The body first. From here to the end nothing awaits, so checking the limit, comparing and
    # recording the outcome are one step: asked before the body was read, a hundred requests
    # held open together would all have been let through before any of them had failed.
    body = await _body(request)
    wait = auth.throttle.retry_after(client)
    if wait:
        return _json_error(
            429, "Too many failed sign-in attempts. Try again later.", headers={"Retry-After": str(wait)}
        )
    settings = _controller(request).settings
    email = str(body.get("emailOrPhone") or body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    # Both comparisons always run, in constant time and on bytes: nothing about the timing or the
    # outcome tells a right email from a wrong one, and no input (non-ASCII, say) can make them raise.
    # An empty configured password matches nothing.
    email_ok = _same_secret(email, settings.api_email.strip().lower())
    password_ok = _same_secret(password, settings.api_password)
    if not (email_ok and password_ok):
        auth.throttle.failed(client)
        _LOGGER.warning("failed sign-in from %s", printable(client, 64))
        return _json_error(401, "Invalid email or password")
    auth.throttle.succeeded(client)
    return _json(auth.issue())


async def refresh_token(request: web.Request) -> web.Response:
    body = await _body(request)
    result = request.app["auth"].refresh(str(body.get("refreshToken") or ""))
    if result is None:
        return _json_error(401, "Invalid refresh token")
    return _json(result)


async def logout(request: web.Request) -> web.Response:
    """End a session, given its token (the Authorization header) or ``{"refreshToken": ...}``.

    Always 200: an expired or unknown token simply has no session left to end.
    """
    body = await _body(request)
    refresh = body.get("refreshToken")
    request.app["auth"].revoke(_bearer(request), refresh if isinstance(refresh, str) else "")
    return _json({})


async def profile(request: web.Request) -> web.Response:
    return _json(request.app["auth"].user())


async def list_stations(request: web.Request) -> web.Response:
    controller = _controller(request)
    stations = [build_station(controller, s) for s in controller.stations.values()]
    return _json({"stations": stations, "groups": []})


async def get_station(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    return _json(build_station(_controller(request), station))


def _station_response(request: web.Request) -> web.Response:
    return _json(build_station(_controller(request), _station_or_404(request)))


async def set_mode(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    mode = body.get("mode")
    if not isinstance(mode, str) or mode not in MODES:
        return _json_error(400, f"mode must be one of {MODES}")
    connector_id = _whole(body.get("connectorId"), "connectorId", 0, MAX_CONNECTORS, default=0)
    try:
        await _controller(request).set_mode(station["id"], mode, connector_id)
    except ValueError as err:
        return _json_error(400, str(err))
    return _station_response(request)


async def set_current_limit(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    amps = _whole(body.get("value"), "value", 0, 1000)
    try:
        await _controller(request).set_current_limit(station["id"], amps)
    except (TypeError, ValueError) as err:
        return _json_error(400, str(err))
    return _station_response(request)


async def schedule_update(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    price = body.get("price")
    if not isinstance(price, dict):
        return _json_error(400, "price object required")
    if request.path.endswith("scheduleUpdate"):
        price["isSchedule"] = True
    try:
        zone = await _controller(request).upsert_zone(station["id"], price)
    except ValueError as err:
        return _json_error(400, str(err))
    data = build_station(_controller(request), station)
    data["price"] = zone
    data["_id"] = zone["_id"]  # the HA integration reads the new schedule id from here
    return _json(data)


async def schedule_enable(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    try:
        await _controller(request).set_zone_enabled(
            station["id"], str(body.get("_id")), bool(body.get("scheduleEnabled"))
        )
    except KeyError:
        return _json_error(404, "unknown schedule")
    return _station_response(request)


async def schedule_delete(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    try:
        await _controller(request).delete_zone(station["id"], request.match_info["zone_id"])
    except KeyError:
        return _json_error(404, "unknown schedule")
    return _station_response(request)


async def set_rate(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    try:
        await _controller(request).set_base_rate(station["id"], body.get("priceKW"))
    except (TypeError, ValueError):
        return _json_error(400, "priceKW must be a number, zero or more")
    return _station_response(request)


async def reboot(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    try:
        result = await _controller(request).reboot(station["id"])
    except OcppError as err:
        return _json_error(503, str(err))
    return _json(result)


async def events(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    limit = _row_limit(request, 50)
    return _json({"sessions": _controller(request).store.sessions(station["id"], limit)})


# --- local extras ----------------------------------------------------------------


async def local_samples(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    since = request.query.get("since")
    if since:
        moment = _parse_iso(since)
        if moment is None:
            raise _bad_request("since must be an ISO 8601 time such as 2026-11-08T00:00:00Z")
        since = _iso(moment)
    else:
        since = datetime.now(UTC).strftime("%Y-%m-%dT00:00:00Z")
    connector = request.query.get("connector")
    connector_id = _whole(connector, "connector", 1, MAX_CONNECTORS) if connector else None
    rows = _controller(request).store.samples(station["id"], since, connector_id)
    return _json({"samples": rows})


async def local_sessions(request: web.Request) -> web.Response:
    """Session history for the web page: finished sessions plus the ones in progress, with totals."""
    station = _station_or_404(request)
    controller = _controller(request)
    limit = _row_limit(request, 100)
    live = {
        int(c["transaction"]["id"]): c["transaction"] for c in station["connectors"].values() if c.get("transaction")
    }
    now = datetime.now(UTC)
    rows = controller.store.sessions(station["id"], 5000)
    for row in rows:
        tx = live.get(row["id"]) if row["stop_at"] is None else None
        row["active"] = tx is not None
        row["incomplete"] = row["stop_at"] is None and tx is None  # never closed, e.g. lost in a restart
        if tx is not None:
            start = _parse_iso(row["start_at"])
            row["energy_wh"] = tx.get("energy") or 0
            row["duration_s"] = max(0, int((now - start).total_seconds())) if start else None
            row["cost"] = round(float(tx.get("priceTotal") or 0), 4)
            row["price_kwh"] = tx.get("priceKW")

    local_now = datetime.now(controller.tz(station))
    periods = {
        "today": local_now.replace(hour=0, minute=0, second=0, microsecond=0),
        "week": local_now - timedelta(days=7),
        "month": local_now - timedelta(days=30),
        "all": None,
    }
    summary = {key: {"energy_wh": 0.0, "cost": 0.0, "count": 0} for key in periods}
    for row in rows:
        start = _parse_iso(row["start_at"])
        for key, since in periods.items():
            if since is None or (start is not None and start >= since):
                summary[key]["energy_wh"] += float(row["energy_wh"] or 0)
                summary[key]["cost"] += float(row["cost"] or 0)
                summary[key]["count"] += 1
    for totals in summary.values():
        totals["cost"] = round(totals["cost"], 4)
    return _json(
        {
            "sessions": rows[:limit],
            "summary": summary,
            "currency": station.get("currency"),
            "timezone": station.get("timezone"),
        }
    )


async def local_sessions_recalculate(request: web.Request) -> web.Response:
    """Reprice all recorded sessions with the current base price, rate zones and holidays."""
    station = _station_or_404(request)
    return _json(await _controller(request).recalculate_costs(station["id"]))


def _holiday_payload(controller: Controller, station: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    today = datetime.now(controller.tz(station)).date()
    return {
        "settings": settings,
        "upcoming": holiday_calendar.upcoming(settings, today, 370),
        "today": holiday_calendar.holiday_name(settings, today) if settings.get("enabled") else None,
    }


async def local_holidays_get(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    settings = {**holiday_calendar.DEFAULTS, **(station.get("holidaysSettings") or {})}
    return _json(_holiday_payload(_controller(request), station, settings))


async def local_holidays_put(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    try:
        settings = await _controller(request).set_holidays(station["id"], await _body(request))
    except (TypeError, ValueError) as err:
        return _json_error(400, str(err))
    return _json(_holiday_payload(_controller(request), station, settings))


async def local_holidays_preview(request: web.Request) -> web.Response:
    """What the calendar would look like with these settings, without saving them."""
    station = _station_or_404(request)
    try:
        settings = holiday_calendar.normalize(await _body(request))
    except (TypeError, ValueError) as err:
        return _json_error(400, str(err))
    return _json(_holiday_payload(_controller(request), station, settings))


async def local_holiday_countries(request: web.Request) -> web.Response:
    return _json({"countries": holiday_calendar.countries()})


async def local_log(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    conn = _controller(request).connections.get(station["id"])
    return _json({"online": conn is not None, "frames": conn.frames() if conn else []})


async def local_ocpp_call(request: web.Request) -> web.Response:
    """Send any OCPP call to the charger: {"action": "GetConfiguration", "payload": {}}."""
    station = _station_or_404(request)
    body = await _body(request)
    action = body.get("action")
    if not isinstance(action, str) or not action or len(action) > 64:
        return _json_error(400, "action required")
    payload = body.get("payload") if body.get("payload") is not None else {}
    if not isinstance(payload, dict):
        return _json_error(400, "payload must be an object")
    try:
        json.dumps(payload, allow_nan=False)
    except (ValueError, RecursionError):
        return _json_error(400, "payload must be plain JSON (no NaN or Infinity)")
    timeout = body.get("timeout")
    if timeout is None or timeout == "":
        timeout = 30.0
    elif isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_OCPP_CALL_TIMEOUT:
        return _json_error(400, f"timeout must be a number of seconds, at most {MAX_OCPP_CALL_TIMEOUT:g}")
    try:
        result = await _controller(request).call(station["id"], action, payload, float(timeout))
    except OcppError as err:
        return _json({"error": err.code, "description": err.description, "details": err.details}, status=502)
    return _json({"result": result})


async def local_settings(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    try:
        await _controller(request).update_settings(station["id"], body)
    except ValueError as err:
        return _json_error(400, str(err))
    return _station_response(request)


async def local_delete_station(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    if _controller(request).is_online(station["id"]):
        return _json_error(409, "station is connected; disconnect it first")
    _controller(request).delete_station(station["id"])
    return _json({})


async def local_clear_auth_key(request: web.Request) -> web.Response:
    """Forget the Auth key a charger is pinned to, so the next connection can pin a new one.

    Needed after changing the charger's Auth key, or replacing the charger under the same serial.
    """
    station = _station_or_404(request)
    await _controller(request).clear_auth_key(station["id"])
    return _json({})


async def health(request: web.Request) -> web.Response:
    """Liveness for the container health check: public, so it says nothing that identifies a charger.

    Serials are half of a charger's identity (all of it, for one that connects without an Auth
    key), so the per-station list is only added for a caller who is signed in.
    """
    controller = _controller(request)
    online = {sid: controller.is_online(sid) for sid in controller.stations}
    data: dict[str, Any] = {
        "status": "ok",
        "version": __version__,
        "time": _now_iso(),
        "stationCount": len(online),
        "stationsOnline": sum(online.values()),
    }
    if request.app["auth"].valid(_bearer(request)):
        data["stations"] = online
    return _json(data)


async def ext_ocpp_check(request: web.Request) -> web.Response:
    """Answer the Grizzl-E firmware's third-party-OCPP "unlock" check locally.

    The firmware GETs ``connect-api.unitedchargers.com/commercial/ext-ocpp-check/<serial>`` and
    expects the response body to equal the lowercase-hex MD5 of ``"<serial>;isUnlocked=true"``; on a
    match it sets its internal ``isUnlocked`` flag, keeping a custom OCPP backend enabled. The
    expected value contains no server-side secret (just the public serial + a constant), so we can
    return it ourselves. Reached only if ``connect-api.unitedchargers.com`` is DNS-overridden to
    this server as well (served over TLS; the charger does not verify the certificate). This
    endpoint is public and unauthenticated, exactly as the charger calls it.
    """
    if not _controller(request).settings.ocpp_unlock:
        raise web.HTTPNotFound()
    serial = request.match_info["serial"]
    if not CP_ID_RE.fullmatch(serial):  # not a serial: nothing to answer, and nothing fit to log
        raise web.HTTPNotFound()
    digest = hashlib.md5(f"{serial};isUnlocked=true".encode(), usedforsecurity=False).hexdigest()
    _LOGGER.info("ext-ocpp-check for %s -> isUnlocked (served %s)", serial, digest)
    return web.Response(text=digest, content_type="text/plain")


def add_routes(app: web.Application) -> None:
    app.router.add_get("/health", health)
    app.router.add_get("/commercial/ext-ocpp-check/{serial}", ext_ocpp_check)
    app.router.add_post("/client/auth/login", login)
    app.router.add_post("/client/auth/refresh-token", refresh_token)
    app.router.add_post("/client/auth/logout", logout)
    app.router.add_get("/client/auth/profile", profile)
    app.router.add_get("/client/stations", list_stations)
    app.router.add_get("/client/stations/{station_id}", get_station)
    app.router.add_post("/client/stations/{station_id}/mode", set_mode)
    app.router.add_put("/client/stations/{station_id}/currentLimit", set_current_limit)
    app.router.add_post("/client/stations/{station_id}/scheduleUpdate", schedule_update)
    app.router.add_post("/client/stations/{station_id}/pricesByZoneUpdate", schedule_update)
    app.router.add_post("/client/stations/{station_id}/scheduleEnable", schedule_enable)
    app.router.add_delete("/client/stations/{station_id}/scheduleDelete/{zone_id}", schedule_delete)
    app.router.add_delete("/client/stations/{station_id}/pricesByZoneDelete/{zone_id}", schedule_delete)
    app.router.add_put("/client/stations/{station_id}/rate", set_rate)
    app.router.add_post("/client/stations/{station_id}/reboot", reboot)
    app.router.add_get("/client/stations/{station_id}/events", events)
    app.router.add_get("/local/stations/{station_id}/samples", local_samples)
    app.router.add_get("/local/stations/{station_id}/sessions", local_sessions)
    app.router.add_post("/local/stations/{station_id}/sessions/recalculate", local_sessions_recalculate)
    app.router.add_get("/local/holidays/countries", local_holiday_countries)
    app.router.add_get("/local/stations/{station_id}/holidays", local_holidays_get)
    app.router.add_put("/local/stations/{station_id}/holidays", local_holidays_put)
    app.router.add_post("/local/stations/{station_id}/holidays/preview", local_holidays_preview)
    app.router.add_get("/local/stations/{station_id}/log", local_log)
    app.router.add_post("/local/stations/{station_id}/ocpp", local_ocpp_call)
    app.router.add_put("/local/stations/{station_id}/settings", local_settings)
    app.router.add_delete("/local/stations/{station_id}", local_delete_station)
    app.router.add_delete("/local/stations/{station_id}/auth-key", local_clear_auth_key)
