"""Fake charger + in-process server + the same REST calls the HA integration makes."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from fake_charger import FakeCharger  # noqa: E402

from grizzle_local.config import Settings
from grizzle_local.main import create_app
from grizzle_local.store import Store

SERIAL = "GRD-L0000TEST1"


async def wait_for(predicate, timeout=10.0, step=0.05):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        result = predicate()
        if result:
            return result
        await asyncio.sleep(step)
    raise AssertionError("condition not met in time")


@pytest.fixture
async def server(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        timezone="America/Denver",
        api_email="ha@local",
        api_password="pw",
        tick_seconds=1,
        meter_interval=1,
    )
    app = create_app(settings, Store(settings.data_dir))
    async with TestServer(app) as test_server, TestClient(test_server) as client:
        yield client


@pytest.fixture
async def charger(server):
    url = f"ws://{server.host}:{server.port}/ocpp1.6/{SERIAL}"
    async with aiohttp.ClientSession() as session:
        cp = FakeCharger(url, SERIAL, connectors=2, meter_interval=0.5)
        await cp.connect(session)
        runner = asyncio.create_task(cp.run())
        await asyncio.wait_for(cp.booted.wait(), 10)
        yield cp
        runner.cancel()
        await cp.close()


class Api:
    """Mirrors GrizzlEConnectClient from the HA integration."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.token: str | None = None

    async def login(self, email="ha@local", password="pw") -> aiohttp.ClientResponse:
        resp = await self.client.post("/client/auth/login", json={"emailOrPhone": email, "password": password})
        if resp.status == 200:
            self.token = (await resp.json())["token"]
        return resp

    async def request(self, method: str, path: str, body: Any = None) -> Any:
        resp = await self.client.request(method, path, json=body, headers={"Authorization": f"Bearer {self.token}"})
        assert resp.status < 400, f"{method} {path} -> {resp.status} {await resp.text()}"
        return await resp.json()

    async def station(self) -> dict[str, Any]:
        data = await self.request("GET", "/client/stations")
        return next(s for s in data["stations"] if s["serialNumber"] == SERIAL)


async def test_login_and_station_shape(server, charger):
    api = Api(server)
    bad = await api.login(password="nope")
    assert bad.status == 401
    assert (await server.get("/client/stations")).status == 401
    assert (await api.login()).status == 200

    station = await api.station()
    assert station["id"] == SERIAL and station["online"] is True
    assert station["bootNotification"]["chargePointModel"] == "GRD 40A 2025"
    assert station["model"]["displayName"] == "Grizzl-E Duo"
    assert [c["connectorId"] for c in station["connectors"]] == [1, 2]
    assert station["connectors"][0]["status"] == "Available"
    assert station["connectors"][0]["mode"] == "Active"


async def test_malformed_get_configuration_is_survived(server, charger):
    # The after-boot task sends GetConfiguration; the fake replies with the firmware's broken JSON.
    await wait_for(lambda: any(a == "GetConfiguration" for a, _ in charger.received))
    await asyncio.sleep(0.5)
    assert not charger.ws.closed
    api = Api(server)
    await api.login()
    assert (await api.station())["online"] is True
    # Boot config was still pushed.
    assert charger.config["MeterValueSampleInterval"] == "1"
    assert "Energy.Active.Import.Register" in charger.config["MeterValuesSampledData"]


async def test_plug_in_starts_transaction_and_meter_values_flow(server, charger):
    api = Api(server)
    await api.login()
    await charger.plug_in(1)
    await wait_for(lambda: 1 in charger.transactions)
    assert any(a == "RemoteStartTransaction" and p["connectorId"] == 1 for a, p in charger.received)

    def charging():
        return (c := charger.status.get(1)) == "Charging" and c

    await wait_for(charging)
    await asyncio.sleep(1.5)  # a couple of MeterValues
    station = await api.station()
    connector = station["connectors"][0]
    assert connector["status"] == "Charging"
    charge = connector["charge"]
    assert charge is not None
    assert charge["meterStart"] == 501000
    assert charge["energy"] > 0
    assert charge["meterValues"]["voltage"][0] >= 237
    assert charge["meterValues"]["currentImport"][0] == 32
    assert connector["power"] == 32 * 240
    assert station["connectors"][1]["charge"] is None  # connector 2 untouched

    await charger.unplug(1)
    await wait_for(lambda: charger.status[1] == "Available")
    await asyncio.sleep(0.3)
    station = await api.station()
    assert station["connectors"][0]["charge"] is None
    events = await api.request("GET", f"/client/stations/{SERIAL}/events")
    assert len(events["sessions"]) == 1
    assert events["sessions"][0]["reason"] == "EVDisconnected"
    assert events["sessions"][0]["energy_wh"] > 0


async def test_inactive_mode_stops_and_blocks_charging(server, charger):
    api = Api(server)
    await api.login()
    await charger.plug_in(2)
    await wait_for(lambda: 2 in charger.transactions)

    await api.request("POST", f"/client/stations/{SERIAL}/mode", {"mode": "Inactive", "connectorId": 2})
    await wait_for(lambda: 2 not in charger.transactions)
    assert any(a == "RemoteStopTransaction" for a, _ in charger.received)
    await wait_for(lambda: charger.status[2] == "Preparing")
    await asyncio.sleep(1.5)
    assert 2 not in charger.transactions, "Inactive connector must not be restarted"
    station = await api.station()
    assert station["connectors"][1]["mode"] == "Inactive"

    await api.request("POST", f"/client/stations/{SERIAL}/mode", {"mode": "Active", "connectorId": 2})
    await wait_for(lambda: 2 in charger.transactions)


async def test_current_limit_sets_stack_level_zero_profile(server, charger):
    api = Api(server)
    await api.login()
    await api.request("PUT", f"/client/stations/{SERIAL}/currentLimit", {"value": 24})
    await wait_for(lambda: charger.limit_a == 24)
    action, payload = next((a, p) for a, p in reversed(charger.received) if a == "SetChargingProfile")
    profile = payload["csChargingProfiles"]
    assert payload["connectorId"] == 0 and profile["stackLevel"] == 0
    assert profile["chargingProfilePurpose"] == "TxDefaultProfile"
    assert profile["chargingSchedule"]["chargingRateUnit"] == "A"
    station = await api.station()
    assert station["smartCharging"]["currentLimit"] == 24

    resp = await server.put(
        f"/client/stations/{SERIAL}/currentLimit", json={"value": 99}, headers={"Authorization": f"Bearer {api.token}"}
    )
    assert resp.status == 400


async def test_schedule_mode_follows_windows(server, charger):
    api = Api(server)
    await api.login()
    # A window that is never active right now: tomorrow-only, 1 minute long. Build it from local time.
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo

    now = datetime.now(ZoneInfo("America/Denver"))
    later = now + timedelta(hours=2)
    closed = {
        "name": "Later",
        "startHours": later.hour,
        "startMinutes": later.minute,
        "endHours": (later + timedelta(minutes=30)).hour,
        "endMinutes": (later + timedelta(minutes=30)).minute,
        "allDay": False,
        "days": list(range(7)),
        "isSchedule": True,
        "currentLimit": None,
        "connectorId": 0,
    }
    created = await api.request("POST", f"/client/stations/{SERIAL}/scheduleUpdate", {"price": closed})
    zone_id = created["_id"]
    station = await api.station()
    assert [z["_id"] for z in station["pricesByZone"]] == [zone_id]
    assert station["pricesByZone"][0]["scheduleEnabled"] is True

    await api.request("POST", f"/client/stations/{SERIAL}/mode", {"mode": "Schedule", "connectorId": 0})
    await charger.plug_in(1)
    await asyncio.sleep(1.5)
    assert 1 not in charger.transactions, "outside the window nothing should start"
    station = await api.station()
    assert station["connectors"][0]["isActiveBySchedule"] is False
    assert station["connectors"][0]["nextScheduleTime"] is not None

    # Widen the window so it covers now, with its own current limit.
    open_window = {**closed, "_id": zone_id, "allDay": True, "currentLimit": 16}
    await api.request("POST", f"/client/stations/{SERIAL}/scheduleUpdate", {"price": open_window})
    await wait_for(lambda: 1 in charger.transactions)
    await wait_for(lambda: charger.limit_a == 16)
    station = await api.station()
    assert station["connectors"][0]["isActiveBySchedule"] is True

    # Disable the window: charging must stop.
    await api.request("POST", f"/client/stations/{SERIAL}/scheduleEnable", {"_id": zone_id, "scheduleEnabled": False})
    await wait_for(lambda: 1 not in charger.transactions)

    await api.request("DELETE", f"/client/stations/{SERIAL}/scheduleDelete/{zone_id}")
    assert (await api.station())["pricesByZone"] == []


async def test_rate_and_cost(server, charger):
    api = Api(server)
    await api.login()
    await api.request("PUT", f"/client/stations/{SERIAL}/rate", {"priceKW": 0.25})
    assert (await api.station())["priceKW"] == 0.25
    await charger.plug_in(1)
    await wait_for(lambda: charger.status[1] == "Charging")
    await asyncio.sleep(2)
    charge = (await api.station())["connectors"][0]["charge"]
    assert charge["priceKW"] == 0.25
    assert charge["priceTotal"] == pytest.approx(charge["energy"] / 1000 * 0.25, rel=0.05)


async def test_reboot_and_raw_call(server, charger):
    api = Api(server)
    await api.login()
    result = await api.request("POST", f"/client/stations/{SERIAL}/reboot", {})
    assert result == {"status": "Accepted"}
    assert charger.reset_requested.is_set()
    raw = await api.request(
        "POST",
        f"/local/stations/{SERIAL}/ocpp",
        {"action": "GetConfiguration", "payload": {"key": ["HeartbeatInterval"]}},
    )
    assert raw["result"]["configurationKey"][0]["key"] == "HeartbeatInterval"
    log = await api.request("GET", f"/local/stations/{SERIAL}/log")
    assert log["online"] and any(f["label"] == "<- BootNotification" for f in log["frames"])


async def test_token_refresh(server, charger):
    resp = await server.post("/client/auth/login", json={"emailOrPhone": "ha@local", "password": "pw"})
    tokens = await resp.json()
    resp = await server.post("/client/auth/refresh-token", json={"refreshToken": tokens["refreshToken"]})
    assert resp.status == 200
    new = await resp.json()
    assert new["token"] != tokens["token"]
    old = await server.get("/client/stations", headers={"Authorization": f"Bearer {tokens['token']}"})
    assert old.status == 401
    fresh = await server.get("/client/stations", headers={"Authorization": f"Bearer {new['token']}"})
    assert fresh.status == 200


async def test_state_survives_restart(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", api_email="a@b", api_password="x", tick_seconds=1)
    store = Store(settings.data_dir)
    app = create_app(settings, store)
    async with TestServer(app) as test_server, TestClient(test_server) as client, aiohttp.ClientSession() as session:
        cp = FakeCharger(f"ws://{client.host}:{client.port}/{SERIAL}", SERIAL, connectors=2, meter_interval=5)
        await cp.connect(session)
        runner = asyncio.create_task(cp.run())
        await asyncio.wait_for(cp.booted.wait(), 10)
        api = Api(client)
        assert (await api.login("a@b", "x")).status == 200
        await api.request("POST", f"/client/stations/{SERIAL}/mode", {"mode": "Inactive", "connectorId": 1})
        await api.request("PUT", f"/client/stations/{SERIAL}/currentLimit", {"value": 20})
        runner.cancel()
        await cp.close()
    store2 = Store(settings.data_dir)
    station = store2.state["stations"][SERIAL]
    assert station["connectors"]["1"]["mode"] == "Inactive"
    assert station["currentLimit"] == 20
    assert station["boot"]["chargePointModel"] == "GRD 40A 2025"


async def test_session_relative_energy_register(tmp_path):
    """Real Duo firmware: StartTransaction.meterStart is lifetime Wh, MeterValues restart at 0."""
    from grizzle_local.controller import Controller

    settings = Settings(data_dir=tmp_path / "data")
    controller = Controller(settings, Store(settings.data_dir))
    station = controller._ensure_station(SERIAL)
    await controller._on_StartTransaction(
        station,
        {"connectorId": 2, "idTag": "uc_default_auth", "meterStart": 819392, "timestamp": "2026-11-08T16:12:17Z"},
    )
    await controller.set_base_rate(SERIAL, 0.10)

    def sample(wh: float, watts: float) -> dict:
        return {
            "connectorId": 2,
            "transactionId": 1,
            "meterValue": [
                {
                    "timestamp": "2026-11-08T16:14:51Z",
                    "sampledValue": [
                        {"value": str(wh), "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
                        {"value": str(watts), "measurand": "Power.Active.Import", "unit": "W"},
                    ],
                }
            ],
        }

    await controller._on_MeterValues(station, sample(0, 0))
    await controller._on_MeterValues(station, sample(1500, 7200))
    connector = station["connectors"]["2"]
    tx = connector["transaction"]
    assert tx["energy"] == 1500
    assert tx["sessionRelativeRegister"] is True
    assert connector["totalEnergyWh"] == 819392 + 1500
    assert tx["priceTotal"] == pytest.approx(0.15)
    await controller._on_StopTransaction(
        station, {"transactionId": 1, "meterStop": 2000, "timestamp": "2026-11-08T17:00:00Z", "reason": "Remote"}
    )
    assert connector["lastSession"]["energy"] == 2000
    assert connector["totalEnergyWh"] == 819392 + 2000
    session = controller.store.sessions(SERIAL)[0]
    assert session["energy_wh"] == 2000 and session["duration_s"] == 2863


async def test_config_keys_teach_dip_switch_and_connectors(tmp_path):
    from grizzle_local.controller import Controller

    settings = Settings(data_dir=tmp_path / "data")
    controller = Controller(settings, Store(settings.data_dir))
    station = controller._ensure_station(SERIAL)
    controller._learn_from_config(
        station, {"DipSwitchCurrentLimit": "32", "NumberOfConnectors": "2", "AuthTag": "uc_default_auth"}
    )
    assert station["dipSwitchCurrentLimit"] == 32
    assert station["connectorCount"] == 2 and "2" in station["connectors"]
    assert station["idTag"] == "uc_default_auth"
    with pytest.raises(ValueError):
        await controller.set_current_limit(SERIAL, 36)  # above the DIP switch


async def test_web_page_is_served_without_login(server):
    resp = await server.get("/")
    assert resp.status == 200 and resp.content_type == "text/html"
    html = await resp.text()
    assert "<title>Grizzl-E local</title>" in html
    assert "http://" not in html.replace("http://www.w3.org", "") and "https://" not in html  # nothing external
    assert "frame-ancestors" in resp.headers["Content-Security-Policy"]
    assert (await server.get("/nope")).status == 404


async def test_session_history_with_live_and_finished_sessions(server, charger):
    api = Api(server)
    await api.login()
    await api.request("PUT", f"/client/stations/{SERIAL}/rate", {"priceKW": 0.5})
    await charger.plug_in(1)
    await wait_for(lambda: charger.status[1] == "Charging")
    await asyncio.sleep(1.6)

    data = await api.request("GET", f"/local/stations/{SERIAL}/sessions")
    live = data["sessions"][0]
    assert live["active"] is True and live["incomplete"] is False and live["stop_at"] is None
    assert live["energy_wh"] > 0 and live["duration_s"] >= 1
    assert live["cost"] == pytest.approx(live["energy_wh"] / 1000 * 0.5, rel=0.05)
    assert data["summary"]["today"]["count"] == 1 and data["summary"]["all"]["energy_wh"] == live["energy_wh"]
    assert data["timezone"] == "America/Denver" and data["currency"] == "USD"

    await charger.unplug(1)
    await wait_for(lambda: charger.status[1] == "Available")
    await asyncio.sleep(0.3)
    data = await api.request("GET", f"/local/stations/{SERIAL}/sessions?limit=5")
    done = data["sessions"][0]
    assert done["active"] is False and done["stop_at"] and done["reason"] == "EVDisconnected"
    assert done["cost"] == pytest.approx(done["energy_wh"] / 1000 * 0.5, rel=0.05)
    assert data["summary"]["week"]["cost"] == pytest.approx(done["cost"], abs=1e-4)
    assert (await server.get(f"/local/stations/{SERIAL}/sessions")).status == 401


async def test_recalculate_reprices_past_and_running_sessions(tmp_path):
    """Sessions recorded before any price existed get repriced from their stored meter samples."""
    from grizzle_local.controller import Controller

    settings = Settings(data_dir=tmp_path / "data", timezone="America/Denver")
    controller = Controller(settings, Store(settings.data_dir))
    station = controller._ensure_station(SERIAL)

    def sample(tid: int, stamp: str, wh: float) -> dict:
        value = {"value": str(wh), "measurand": "Energy.Active.Import.Register", "unit": "Wh"}
        return {"connectorId": 1, "transactionId": tid, "meterValue": [{"timestamp": stamp, "sampledValue": [value]}]}

    # Monday 2026-11-09, Denver is UTC-7: 08:00 -> 10:00 local, straddling the start of a 09:00 peak zone.
    await controller._on_StartTransaction(
        station, {"connectorId": 1, "idTag": "t", "meterStart": 500000, "timestamp": "2026-11-09T15:00:00Z"}
    )
    await controller._on_MeterValues(station, sample(1, "2026-11-09T15:30:00Z", 2000))  # 08:30, 2 kWh so far
    await controller._on_MeterValues(station, sample(1, "2026-11-09T16:30:00Z", 5000))  # 09:30, 5 kWh so far
    await controller._on_StopTransaction(
        station, {"transactionId": 1, "meterStop": 506000, "timestamp": "2026-11-09T17:00:00Z", "reason": "Remote"}
    )
    assert controller.store.sessions(SERIAL)[0]["cost"] == 0  # no price was set while it ran

    await controller.set_base_rate(SERIAL, 0.10)
    await controller.upsert_zone(
        SERIAL,
        {
            "name": "Peak",
            "priceKW": 0.30,
            "startHours": 9,
            "startMinutes": 0,
            "endHours": 17,
            "endMinutes": 0,
            "days": [1, 2, 3, 4, 5],
            "allDay": False,
        },
    )
    # a session still running, with one sample before the peak
    await controller._on_StartTransaction(
        station, {"connectorId": 2, "idTag": "t", "meterStart": 800000, "timestamp": "2026-11-09T14:00:00Z"}
    )
    await controller._on_MeterValues(station, {**sample(2, "2026-11-09T14:30:00Z", 4000), "connectorId": 2})
    station["connectors"]["2"]["transaction"]["priceTotal"] = 0.0  # as if it had been recorded at price 0

    result = await controller.recalculate_costs(SERIAL)
    assert result["sessions"] == 2 and result["cost_before"] == 0
    done = next(s for s in controller.store.sessions(SERIAL) if s["id"] == 1)
    # 2 kWh at 0.10 + 3 kWh at 0.30 + the last 1 kWh (after the final sample) at the stop-time price 0.30
    assert done["cost"] == pytest.approx(0.2 + 0.9 + 0.3)
    assert done["price_kwh"] == pytest.approx(1.4 / 6)
    live = station["connectors"]["2"]["transaction"]
    assert live["priceTotal"] == pytest.approx(0.4)  # 4 kWh at 07:30, base price
    assert result["cost_after"] == pytest.approx(1.8)

    # no samples at all (pruned after 90 days): the whole session is priced at its start time
    controller.store._db.execute("DELETE FROM samples")
    await controller.recalculate_costs(SERIAL)
    assert next(s for s in controller.store.sessions(SERIAL) if s["id"] == 1)["cost"] == pytest.approx(6 * 0.10)
