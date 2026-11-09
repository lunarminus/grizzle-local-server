"""REST API shaped like connect-api.unitedchargers.com, plus a few local extras.

Only the subset the Grizzl-E Connect app and the Home Assistant integration use is
implemented. Station ids are the charger serial (the cloud uses Mongo ids).
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from aiohttp import web

from . import __version__, holiday_calendar
from .controller import MODES, Controller, _parse_iso
from .ocpp import OcppError

_LOGGER = logging.getLogger(__name__)

TOKEN_TTL = 7 * 24 * 3600
PUBLIC_PATHS = ("/client/auth/login", "/client/auth/refresh-token", "/health", "/")


def _iso(value: str | None) -> str | None:
    return value


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
        for cid in range(1, int(station.get("connectorCount") or 1) + 1)
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


class Auth:
    def __init__(self, controller: Controller) -> None:
        self.controller = controller

    @property
    def _tokens(self) -> dict[str, dict[str, Any]]:
        return self.controller.store.state["tokens"]

    def issue(self) -> dict[str, Any]:
        self._gc()
        token, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._tokens[token] = {"refresh": refresh, "expires": time.time() + TOKEN_TTL}
        self.controller.mark_dirty()
        return {
            "token": token,
            "refreshToken": refresh,
            "isVerified": True,
            "user": {
                "_id": "local",
                "email": self.controller.settings.api_email,
                "firstName": "Local",
                "lastName": "Server",
            },
        }

    def refresh(self, refresh_token: str) -> dict[str, Any] | None:
        for token, info in list(self._tokens.items()):
            if secrets.compare_digest(info["refresh"], refresh_token):
                del self._tokens[token]
                return self.issue()
        return None

    def valid(self, token: str) -> bool:
        info = self._tokens.get(token)
        return bool(info) and info["expires"] > time.time()

    def _gc(self) -> None:
        now = time.time()
        for token in [t for t, info in self._tokens.items() if info["expires"] < now]:
            del self._tokens[token]


def _json_error(status: int, message: str) -> web.Response:
    return web.json_response({"message": message, "statusCode": status}, status=status)


@web.middleware
async def auth_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    path = request.path
    if path in PUBLIC_PATHS or request.headers.get("Upgrade", "").lower() == "websocket":
        return await handler(request)
    if not (path.startswith("/client/") or path.startswith("/local/")):
        return await handler(request)
    auth: Auth = request.app["auth"]
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else request.query.get("token", "")
    if not auth.valid(token):
        return _json_error(401, "Unauthorized")
    return await handler(request)


# --- handlers -------------------------------------------------------------------


async def _body(request: web.Request) -> dict[str, Any]:
    if not request.can_read_body:
        return {}
    try:
        data = await request.json()
    except ValueError:
        raise web.HTTPBadRequest(text="invalid JSON") from None
    return data if isinstance(data, dict) else {}


def _controller(request: web.Request) -> Controller:
    return request.app["controller"]


def _station_or_404(request: web.Request) -> dict[str, Any]:
    station = _controller(request).station(request.match_info["station_id"])
    if station is None:
        raise web.HTTPNotFound(text="unknown station")
    return station


async def login(request: web.Request) -> web.Response:
    body = await _body(request)
    settings = _controller(request).settings
    email = str(body.get("emailOrPhone") or body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    if email != settings.api_email.lower() or not secrets.compare_digest(password, settings.api_password):
        return _json_error(401, "Invalid email or password")
    return web.json_response(request.app["auth"].issue())


async def refresh_token(request: web.Request) -> web.Response:
    body = await _body(request)
    result = request.app["auth"].refresh(str(body.get("refreshToken") or ""))
    if result is None:
        return _json_error(401, "Invalid refresh token")
    return web.json_response(result)


async def logout(request: web.Request) -> web.Response:
    return web.json_response({})


async def profile(request: web.Request) -> web.Response:
    return web.json_response(request.app["auth"].issue()["user"])


async def list_stations(request: web.Request) -> web.Response:
    controller = _controller(request)
    stations = [build_station(controller, s) for s in controller.stations.values()]
    return web.json_response({"stations": stations, "groups": []})


async def get_station(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    return web.json_response(build_station(_controller(request), station))


def _station_response(request: web.Request) -> web.Response:
    return web.json_response(build_station(_controller(request), _station_or_404(request)))


async def set_mode(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    mode = body.get("mode")
    if mode not in MODES:
        return _json_error(400, f"mode must be one of {MODES}")
    await _controller(request).set_mode(station["id"], mode, int(body.get("connectorId") or 0))
    return _station_response(request)


async def set_current_limit(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    try:
        await _controller(request).set_current_limit(station["id"], int(body.get("value")))
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
    return web.json_response(data)


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
        await _controller(request).set_base_rate(station["id"], float(body.get("priceKW")))
    except (TypeError, ValueError):
        return _json_error(400, "priceKW must be a number")
    return _station_response(request)


async def reboot(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    try:
        result = await _controller(request).reboot(station["id"])
    except OcppError as err:
        return _json_error(503, str(err))
    return web.json_response(result)


async def events(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    sessions = _controller(request).store.sessions(station["id"], int(request.query.get("limit", 50)))
    return web.json_response({"sessions": sessions})


# --- local extras ----------------------------------------------------------------


async def local_samples(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    since = request.query.get("since") or datetime.now(UTC).strftime("%Y-%m-%dT00:00:00Z")
    connector = request.query.get("connector")
    rows = _controller(request).store.samples(station["id"], since, int(connector) if connector else None)
    return web.json_response({"samples": rows})


async def local_sessions(request: web.Request) -> web.Response:
    """Session history for the web page: finished sessions plus the ones in progress, with totals."""
    station = _station_or_404(request)
    controller = _controller(request)
    limit = max(1, min(int(request.query.get("limit", 100)), 1000))
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
            row["duration_s"] = int((now - start).total_seconds()) if start else None
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
    return web.json_response(
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
    return web.json_response(await _controller(request).recalculate_costs(station["id"]))


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
    return web.json_response(_holiday_payload(_controller(request), station, settings))


async def local_holidays_put(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    try:
        settings = await _controller(request).set_holidays(station["id"], await _body(request))
    except (TypeError, ValueError) as err:
        return _json_error(400, str(err))
    return web.json_response(_holiday_payload(_controller(request), station, settings))


async def local_holidays_preview(request: web.Request) -> web.Response:
    """What the calendar would look like with these settings, without saving them."""
    station = _station_or_404(request)
    try:
        settings = holiday_calendar.normalize(await _body(request))
    except (TypeError, ValueError) as err:
        return _json_error(400, str(err))
    return web.json_response(_holiday_payload(_controller(request), station, settings))


async def local_holiday_countries(request: web.Request) -> web.Response:
    return web.json_response({"countries": holiday_calendar.countries()})


async def local_log(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    conn = _controller(request).connections.get(station["id"])
    return web.json_response({"online": conn is not None, "frames": list(conn.log) if conn else []})


async def local_ocpp_call(request: web.Request) -> web.Response:
    """Send any OCPP call to the charger: {"action": "GetConfiguration", "payload": {}}."""
    station = _station_or_404(request)
    body = await _body(request)
    action = body.get("action")
    if not isinstance(action, str):
        return _json_error(400, "action required")
    try:
        result = await _controller(request).call(
            station["id"], action, body.get("payload") or {}, float(body.get("timeout") or 30)
        )
    except OcppError as err:
        return web.json_response(
            {"error": err.code, "description": err.description, "details": err.details}, status=502
        )
    return web.json_response({"result": result})


async def local_settings(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    body = await _body(request)
    try:
        await _controller(request).update_settings(station["id"], body)
    except Exception as err:  # noqa: BLE001 - validation
        return _json_error(400, str(err))
    return _station_response(request)


async def local_delete_station(request: web.Request) -> web.Response:
    station = _station_or_404(request)
    if _controller(request).is_online(station["id"]):
        return _json_error(409, "station is connected; disconnect it first")
    _controller(request).delete_station(station["id"])
    return web.json_response({})


async def health(request: web.Request) -> web.Response:
    controller = _controller(request)
    return web.json_response(
        {
            "status": "ok",
            "version": __version__,
            "time": _now_iso(),
            "stations": {sid: controller.is_online(sid) for sid in controller.stations},
        }
    )


def add_routes(app: web.Application) -> None:
    app.router.add_get("/health", health)
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
