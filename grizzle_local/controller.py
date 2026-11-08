"""The brain: charger state, OCPP message handling, and local mode/schedule enforcement.

How the Grizzl-E Connect family behaves (from evcc's and others' experience):
- It never starts a transaction on its own. When a car is plugged in it reports
  ``Preparing`` and waits for the server's ``RemoteStartTransaction``. That is how
  the cloud implements the Active / Inactive / Schedule modes, and so do we.
- It only honours charging profiles at ``stackLevel`` 0 and ignores limits below ~6-7 A.
- Some firmware replies to ``GetConfiguration`` with invalid JSON; see ``ocpp.py``.
"""

from __future__ import annotations

import asyncio
import logging
import time as _time
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from .config import Settings
from .ocpp import ChargePointConnection, OcppError, now_iso
from .schedules import charging_allowed, next_change, price_now
from .store import Store

_LOGGER = logging.getLogger(__name__)

MODES = ("Active", "Inactive", "Schedule")
PLUGGED_IN = {"Preparing", "Charging", "SuspendedEV", "SuspendedEVSE", "Finishing"}
WANTS_START = {"Preparing", "SuspendedEVSE"}
REMOTE_RETRY_SECONDS = 60

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


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _recent(last: float | None, now: float) -> bool:
    """Was the last attempt less than REMOTE_RETRY_SECONDS ago? (None = never attempted)"""
    return last is not None and now - last < REMOTE_RETRY_SECONDS


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class Controller:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        self.connections: dict[str, ChargePointConnection] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._dirty = False
        self._stopping = False

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
        for cid in range(1, int(station.get("connectorCount") or 1) + 1):
            self._ensure_connector(station, cid)
        return station

    def _ensure_connector(self, station: dict[str, Any], cid: int) -> dict[str, Any]:
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
            if cid > int(station.get("connectorCount") or 1):
                station["connectorCount"] = cid
            self._dirty = True
        return connectors[key]

    def tz(self, station: dict[str, Any]) -> ZoneInfo:
        try:
            return ZoneInfo(station.get("timezone") or self.settings.timezone)
        except Exception:  # noqa: BLE001 - bad tz name in state
            return ZoneInfo("UTC")

    def is_online(self, station_id: str) -> bool:
        conn = self.connections.get(station_id)
        return conn is not None and not conn.ws.closed

    def mark_dirty(self) -> None:
        self._dirty = True

    # --- connection lifecycle ------------------------------------------------

    async def on_connect(self, conn: ChargePointConnection) -> None:
        old = self.connections.get(conn.id)
        self.connections[conn.id] = conn
        station = self._ensure_station(conn.id)
        station["lastSeen"] = now_iso()
        self._dirty = True
        _LOGGER.info("%s connected", conn.id)
        if old is not None and old is not conn:
            # A reconnecting charger doesn't close its old socket first.
            self._spawn(old.close())

    async def on_disconnect(self, conn: ChargePointConnection) -> None:
        if self.connections.get(conn.id) is conn:
            del self.connections[conn.id]
            _LOGGER.info("%s disconnected", conn.id)
            station = self.station(conn.id)
            if station:
                station["lastSeen"] = now_iso()
                self._dirty = True

    def _spawn(self, coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # --- inbound OCPP --------------------------------------------------------

    async def handle(self, conn: ChargePointConnection, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        station = self._ensure_station(conn.id)
        station["lastSeen"] = now_iso()
        handler = getattr(self, f"_on_{action}", None)
        if handler is None:
            _LOGGER.info("%s: unhandled %s %s", conn.id, action, payload)
            raise NotImplementedError(action)
        result = await handler(station, payload)
        self._dirty = True
        return result

    async def _on_BootNotification(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        station["boot"] = {**payload, "timestamp": now_iso()}
        model = str(payload.get("chargePointModel") or "")
        hint = next((h for prefix, h in MODEL_HINTS if model.upper().startswith(prefix)), None)
        if hint:
            station["model"] = {"name": hint["name"], "code": model}
            if not station.get("modelLocked"):
                station["connectorCount"] = max(int(station.get("connectorCount") or 1), hint["connectors"])
                station["maxCurrent"] = hint["maxCurrent"]
                station["minCurrent"] = hint["minCurrent"]
        else:
            station["model"] = {"name": model or "Grizzl-E", "code": model}
        for cid in range(1, int(station["connectorCount"]) + 1):
            connector = self._ensure_connector(station, cid)
            connector["lastRemoteStart"] = None
        station["appliedLimit"] = None  # profiles may not survive a reboot
        _LOGGER.info("%s booted: %s fw %s", station["id"], model, payload.get("firmwareVersion"))
        self._spawn(self._after_boot(station["id"]))
        return {"status": "Accepted", "currentTime": now_iso(), "interval": self.settings.heartbeat_interval}

    async def _on_Heartbeat(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        return {"currentTime": now_iso()}

    async def _on_StatusNotification(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        cid = int(payload.get("connectorId") or 0)
        status = payload.get("status")
        if cid == 0:
            station["status"] = status
            station["errorCode"] = payload.get("errorCode") or "NoError"
            return {}
        connector = self._ensure_connector(station, cid)
        if connector.get("status") != status:
            connector["statusChangedAt"] = payload.get("timestamp") or now_iso()
            _LOGGER.info("%s connector %s: %s -> %s", station["id"], cid, connector.get("status"), status)
        connector["status"] = status
        connector["errorCode"] = payload.get("errorCode") or "NoError"
        connector["vendorErrorCode"] = payload.get("vendorErrorCode")
        connector["info"] = payload.get("info")
        if status == "Available":
            connector["power"] = 0
            if connector.get("transaction"):
                # Missed the StopTransaction; close the session so state doesn't stick.
                self._finish_transaction(station, connector, None, "Available", now_iso())
        self._spawn(self._enforce(station["id"], cid))
        return {}

    async def _on_Authorize(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        return {"idTagInfo": {"status": "Accepted"}}

    async def _on_StartTransaction(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        cid = int(payload.get("connectorId") or 1)
        connector = self._ensure_connector(station, cid)
        tid = self.store.next_transaction_id()
        started = payload.get("timestamp") or now_iso()
        meter_start = payload.get("meterStart")
        local_now = datetime.now(self.tz(station))
        price = price_now(station["pricesByZone"], local_now, _to_float(station.get("priceKW")))
        connector["transaction"] = {
            "id": tid,
            "idTag": payload.get("idTag"),
            "startAt": started,
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
            tid,
            station["id"],
            cid,
            payload.get("idTag"),
            started,
            int(meter_start) if isinstance(meter_start, (int, float)) else None,
            price,
        )
        _LOGGER.info("%s connector %s: transaction %s started (meter %s Wh)", station["id"], cid, tid, meter_start)
        return {"transactionId": tid, "idTagInfo": {"status": "Accepted"}}

    async def _on_StopTransaction(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        tid = payload.get("transactionId")
        connector = next(
            (c for c in station["connectors"].values() if (c.get("transaction") or {}).get("id") == tid), None
        )
        if connector is None:
            _LOGGER.warning("%s: StopTransaction for unknown transaction %s", station["id"], tid)
            return {"idTagInfo": {"status": "Accepted"}}
        self._finish_transaction(
            station, connector, payload.get("meterStop"), payload.get("reason"), payload.get("timestamp") or now_iso()
        )
        # transactionData may carry final meter values
        for mv in payload.get("transactionData") or []:
            self._apply_meter_values(station, connector, mv, tid=None)
        return {"idTagInfo": {"status": "Accepted"}}

    def _finish_transaction(
        self, station: dict[str, Any], connector: dict[str, Any], meter_stop: Any, reason: str | None, stopped_at: str
    ) -> None:
        tx = connector.get("transaction") or {}
        connector["transaction"] = None
        connector["power"] = 0
        if not tx:
            return
        energy = tx.get("energy")
        if isinstance(meter_stop, (int, float)) and isinstance(tx.get("meterStart"), (int, float)):
            if meter_stop < tx["meterStart"]:  # session-relative, like this firmware's MeterValues
                energy = float(meter_stop)
            else:
                energy = float(meter_stop) - float(tx["meterStart"])
            connector["totalEnergyWh"] = float(tx["meterStart"]) + energy
        start, stop = _parse_iso(tx.get("startAt")), _parse_iso(stopped_at)
        duration = int((stop - start).total_seconds()) if start and stop else None
        cost = tx.get("priceTotal")
        self.store.finish_session(
            int(tx["id"]),
            stopped_at,
            int(meter_stop) if isinstance(meter_stop, (int, float)) else None,
            energy,
            duration,
            cost,
            reason,
        )
        connector["lastSession"] = {
            **tx,
            "energy": energy,
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
            reason,
        )

    async def _on_MeterValues(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        cid = int(payload.get("connectorId") or 1)
        connector = self._ensure_connector(station, cid)
        tid = payload.get("transactionId")
        for mv in payload.get("meterValue") or []:
            self._apply_meter_values(station, connector, mv, tid)
        return {}

    def _apply_meter_values(
        self, station: dict[str, Any], connector: dict[str, Any], mv: dict[str, Any], tid: int | None
    ) -> None:
        at = mv.get("timestamp") or now_iso()
        values: dict[str, Any] = {}
        for sv in mv.get("sampledValue") or []:
            measurand = sv.get("measurand") or "Energy.Active.Import.Register"
            key = MEASURANDS.get(measurand)
            value = _to_float(sv.get("value"))
            if key is None or value is None:
                continue
            unit = sv.get("unit") or ("Wh" if key == "energy_wh" else None)
            if key == "energy_wh" and unit == "kWh":
                value *= 1000
            elif key == "power_w" and unit == "kW":
                value *= 1000
            if sv.get("phase") and key in values:
                values[key] = max(values[key], value)  # keep the hottest phase; Grizzl-E is single phase anyway
            else:
                values[key] = value
        if not values:
            return
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
                meter_start = tx.get("meterStart")
                if not isinstance(meter_start, (int, float)):
                    tx["meterStart"] = meter_start = register
                # Grizzl-E firmware reports Energy.Active.Import.Register relative to the start of
                # the session in MeterValues (it restarts at 0), while StartTransaction.meterStart is
                # the lifetime register. Detect which one we got.
                session_relative = register < meter_start
                session_energy = register if session_relative else register - meter_start
                previous = tx.get("lastSessionEnergy")
                tx["sessionRelativeRegister"] = session_relative
                tx["energy"] = max(0.0, session_energy)
                connector["totalEnergyWh"] = float(meter_start) + tx["energy"]
                values["energy_wh"] = connector["totalEnergyWh"]  # store lifetime Wh in history
                if isinstance(previous, (int, float)):
                    delta_kwh = max(0.0, tx["energy"] - previous) / 1000
                    local_now = datetime.now(self.tz(station))
                    price = price_now(station["pricesByZone"], local_now, _to_float(station.get("priceKW"))) or 0
                    tx["priceKW"] = price
                    tx["priceTotal"] = float(tx.get("priceTotal") or 0) + delta_kwh * price
                tx["lastSessionEnergy"] = tx["energy"]
        elif "energy_wh" in values and (connector.get("totalEnergyWh") or 0) <= values["energy_wh"]:
            connector["totalEnergyWh"] = values["energy_wh"]
        self.store.add_sample(station["id"], connector["id"], tid or (tx or {}).get("id"), at, values)

    async def _on_DataTransfer(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        _LOGGER.info("%s: DataTransfer %s", station["id"], payload)
        station.setdefault("dataTransfers", []).append({"at": now_iso(), **payload})
        station["dataTransfers"] = station["dataTransfers"][-20:]
        return {"status": "Accepted"}

    async def _on_DiagnosticsStatusNotification(
        self, station: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, Any]:
        station["diagnosticsStatus"] = payload.get("status")
        return {}

    async def _on_FirmwareStatusNotification(self, station: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        station["firmwareStatus"] = payload.get("status")
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
                _LOGGER.info("%s: ChangeConfiguration %s=%s -> %s", station_id, key, value, result.get("status"))
            except OcppError as err:
                _LOGGER.warning("%s: ChangeConfiguration %s failed: %s", station_id, key, err)
        try:
            result = await self.call(station_id, "GetConfiguration", {})
            config = {}
            for item in result.get("configurationKey") or []:
                if isinstance(item, dict) and "key" in item:
                    config[item["key"]] = item.get("value")
            if config:
                station["config"] = config
                self._learn_from_config(station, config)
                self._dirty = True
            _LOGGER.info("%s: %d configuration keys read", station_id, len(config))
        except OcppError as err:
            _LOGGER.warning("%s: GetConfiguration failed: %s", station_id, err)
        for cid in range(1, int(station["connectorCount"]) + 1):
            try:
                await self.call(
                    station_id, "TriggerMessage", {"requestedMessage": "StatusNotification", "connectorId": cid}
                )
            except OcppError as err:
                _LOGGER.debug("%s: TriggerMessage failed: %s", station_id, err)
        await self._apply_limit(station_id, force=True)
        for cid in range(1, int(station["connectorCount"]) + 1):
            await self._enforce(station_id, cid)

    def _learn_from_config(self, station: dict[str, Any], config: dict[str, Any]) -> None:
        """Pick up what the charger tells us about itself (seen on a Duo, firmware UDGRW070L-04.03.2)."""
        dip = config.get("DipSwitchCurrentLimit")
        if isinstance(dip, str) and dip.isdigit():
            station["dipSwitchCurrentLimit"] = int(dip)
        connectors = config.get("NumberOfConnectors")
        if isinstance(connectors, str) and connectors.isdigit() and not station.get("modelLocked"):
            station["connectorCount"] = max(1, int(connectors))
            for cid in range(1, station["connectorCount"] + 1):
                self._ensure_connector(station, cid)
        if isinstance(config.get("AuthTag"), str) and config["AuthTag"]:
            station["idTag"] = config["AuthTag"]

    def effective_limit(self, station: dict[str, Any]) -> int | None:
        """Station current limit, overridden by an active window's own limit."""
        limit = station.get("currentLimit")
        local_now = datetime.now(self.tz(station))
        for cid in range(1, int(station["connectorCount"]) + 1):
            zone = charging_allowed(station["pricesByZone"], local_now, cid)
            if zone and isinstance(zone.get("currentLimit"), (int, float)):
                limit = int(zone["currentLimit"])
        return int(limit) if limit is not None else None

    async def _apply_limit(self, station_id: str, force: bool = False) -> None:
        station = self.station(station_id)
        if station is None or not self.is_online(station_id):
            return
        limit = self.effective_limit(station)
        if limit is None or (not force and station.get("appliedLimit") == limit):
            return
        limit = max(int(station.get("minCurrent") or 6), min(limit, int(station.get("maxCurrent") or 80)))
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
            _LOGGER.info("%s: SetChargingProfile %s A -> %s", station_id, limit, result.get("status"))
            if result.get("status") == "Accepted":
                station["appliedLimit"] = limit
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
        window = charging_allowed(station["pricesByZone"], local_now, cid)
        connector["isActiveBySchedule"] = window is not None
        nxt = next_change(station["pricesByZone"], local_now, cid)
        connector["nextScheduleTime"] = nxt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z") if nxt else None
        mode = connector.get("mode") or "Active"
        allowed = mode == "Active" or (mode == "Schedule" and window is not None)
        self._dirty = True
        if not self.is_online(station_id):
            return
        status = connector.get("status")
        tx = connector.get("transaction")
        now = _time.monotonic()
        if allowed and tx is None and status in WANTS_START:
            if _recent(connector.get("lastRemoteStart"), now):
                return
            connector["lastRemoteStart"] = now
            try:
                result = await self.call(
                    station_id,
                    "RemoteStartTransaction",
                    {"connectorId": cid, "idTag": station.get("idTag") or self.settings.id_tag},
                )
                _LOGGER.info("%s connector %s: RemoteStartTransaction -> %s", station_id, cid, result.get("status"))
            except OcppError as err:
                _LOGGER.warning("%s connector %s: RemoteStartTransaction failed: %s", station_id, cid, err)
        elif not allowed and tx is not None:
            if _recent(connector.get("lastRemoteStop"), now):
                return
            connector["lastRemoteStop"] = now
            try:
                result = await self.call(station_id, "RemoteStopTransaction", {"transactionId": tx["id"]})
                _LOGGER.info("%s connector %s: RemoteStopTransaction -> %s", station_id, cid, result.get("status"))
            except OcppError as err:
                _LOGGER.warning("%s connector %s: RemoteStopTransaction failed: %s", station_id, cid, err)

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
        targets = [connector_id] if connector_id else range(1, int(station["connectorCount"]) + 1)
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
        station["priceKW"] = float(price_kwh)
        self._dirty = True

    async def upsert_zone(self, station_id: str, price: dict[str, Any]) -> dict[str, Any]:
        station = self._require(station_id)
        zones = station["pricesByZone"]
        zone_id = price.get("_id")
        existing = next((z for z in zones if z.get("_id") == zone_id), None) if zone_id else None
        if existing is None:
            import secrets

            price = {**price, "_id": zone_id or secrets.token_hex(12)}
            price.setdefault("scheduleEnabled", bool(price.get("isSchedule")))
            zones.append(price)
            zone = price
        else:
            existing.update({k: v for k, v in price.items() if k != "_id"})
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
        for cid in range(1, int(station["connectorCount"]) + 1):
            await self._enforce(station_id, cid)
        await self._apply_limit(station_id)

    async def reboot(self, station_id: str) -> dict[str, Any]:
        self._require(station_id)
        return await self.call(station_id, "Reset", {"type": "Soft"})

    async def update_settings(self, station_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        """Local-only tweaks: display name, timezone, connector count, current bounds."""
        station = self._require(station_id)
        for key in ("displayName", "timezone", "currency"):
            if isinstance(patch.get(key), str) and patch[key]:
                station[key] = patch[key]
        if "timezone" in patch:
            ZoneInfo(station["timezone"])  # validate
        for key in ("connectorCount", "maxCurrent", "minCurrent", "dipSwitchCurrentLimit"):
            if key in patch:
                station[key] = int(patch[key]) if patch[key] is not None else None
                if key != "dipSwitchCurrentLimit":
                    station["modelLocked"] = True
        if "connectorCount" in patch:
            for cid in range(1, int(station["connectorCount"]) + 1):
                self._ensure_connector(station, cid)
        self._dirty = True
        return station

    def delete_station(self, station_id: str) -> None:
        self.stations.pop(station_id, None)
        self._dirty = True

    # --- background loop ------------------------------------------------------

    async def run(self) -> None:
        last_prune = 0.0
        while not self._stopping:
            try:
                for station_id, station in list(self.stations.items()):
                    for cid in range(1, int(station.get("connectorCount") or 1) + 1):
                        await self._enforce(station_id, cid)
                    await self._apply_limit(station_id)
                    for connector in station["connectors"].values():
                        tx = connector.get("transaction")
                        if tx and connector.get("status") in PLUGGED_IN:
                            start = _parse_iso(tx.get("startAt"))
                            tx["duration"] = int((datetime.now(UTC) - start).total_seconds()) if start else None
                if _time.monotonic() - last_prune > 3600:
                    self.store.prune_samples()
                    last_prune = _time.monotonic()
                if self._dirty:
                    self.store.save()
                    self._dirty = False
            except Exception:  # noqa: BLE001
                _LOGGER.exception("controller tick failed")
            await asyncio.sleep(self.settings.tick_seconds)

    async def stop(self) -> None:
        self._stopping = True
        for task in list(self._tasks):
            task.cancel()
        for conn in list(self.connections.values()):
            await conn.close()
        self.store.save()
