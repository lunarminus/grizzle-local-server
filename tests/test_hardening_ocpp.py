"""What a hostile or broken charger can no longer do.

Unless GRIZZLE_OCPP_PASSWORD is set, anyone who can reach the port may connect as a charger the
server has never seen. So everything here is, in effect, unauthenticated input: none of it may
exhaust memory, stop the controller for other stations, corrupt what the API returns, or be kept
without bound.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

from grizzle_local import controller as controller_module
from grizzle_local import ocpp
from grizzle_local.config import Settings
from grizzle_local.controller import MAX_CONNECTORS, Controller, _parse_iso, _recent, _timestamp, connector_count
from grizzle_local.main import SingleLineFormatter
from grizzle_local.ocpp import ChargePointConnection, OcppError, printable
from grizzle_local.store import Store

from .support import RawCharger, bearer, make_app, strict_json, wait_for

SERIAL = "GRD-L0000HARD1"
OK_STATUS = {"connectorId": 1, "status": "Available", "errorCode": "NoError"}


@pytest.fixture
async def server(tmp_path):
    async with TestServer(make_app(tmp_path)) as test_server, TestClient(test_server) as client:
        yield client


@pytest.fixture
async def session():
    async with aiohttp.ClientSession() as s:
        yield s


def _controller(tmp_path, **overrides) -> Controller:
    settings = Settings(data_dir=tmp_path / "data", **overrides)
    return Controller(settings, Store(settings.data_dir))


def _no_failures(caplog) -> None:
    bad = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert not bad, bad


# --- connector ids and counts are bounded -----------------------------------------------------


@pytest.mark.parametrize(
    "action,payload",
    [
        ("StatusNotification", {**OK_STATUS, "connectorId": 2_000_000_000}),
        ("StatusNotification", {**OK_STATUS, "connectorId": "9" * 40}),
        ("StatusNotification", {**OK_STATUS, "connectorId": MAX_CONNECTORS + 1}),
        ("StatusNotification", {**OK_STATUS, "connectorId": -1}),
        ("StatusNotification", {**OK_STATUS, "connectorId": [1]}),
        ("MeterValues", {"connectorId": 2_000_000_000, "meterValue": []}),
        ("StartTransaction", {"connectorId": 10**30, "idTag": "x", "meterStart": 0}),
    ],
)
async def test_out_of_range_connector_is_refused_and_changes_nothing(server, session, action, payload):
    """One frame with a huge connectorId used to set the station's connector count, and every
    later frame and tick then looped (and allocated) that many times."""
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)  # no credentials at all
    try:
        reply = await cp.call(action, payload)
        assert reply[0] == 4 and reply[2] == "PropertyConstraintViolation", reply
        station = controller.station(SERIAL)
        assert station["connectorCount"] == 1
        assert set(station["connectors"]) == {"1"}
        assert (await cp.call("Heartbeat", {}))[0] == 3  # and the server is still answering
    finally:
        await cp.close()


async def test_connector_ids_up_to_the_limit_still_work(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        reply = await cp.call("StatusNotification", {**OK_STATUS, "connectorId": MAX_CONNECTORS})
        assert reply[0] == 3
        assert controller.station(SERIAL)["connectorCount"] == MAX_CONNECTORS
        assert (await cp.call("StatusNotification", {**OK_STATUS, "connectorId": 0}))[0] == 3  # the station itself
    finally:
        await cp.close()


@pytest.mark.parametrize("claimed", ["999999999", "9" * 5000, "0", "-3", "two", 10**12, None, ["2"]])
def test_number_of_connectors_from_configuration_is_bounded(tmp_path, claimed):
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    controller._learn_from_config(station, {"NumberOfConnectors": claimed, "DipSwitchCurrentLimit": claimed})
    assert station["connectorCount"] == 1 and set(station["connectors"]) == {"1"}
    assert station["dipSwitchCurrentLimit"] is None
    controller._learn_from_config(station, {"NumberOfConnectors": "2", "DipSwitchCurrentLimit": "32"})
    assert station["connectorCount"] == 2 and station["dipSwitchCurrentLimit"] == 32


def test_ensure_connector_is_a_backstop(tmp_path):
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    for cid in (0, -1, MAX_CONNECTORS + 1, 10**9, True, "2", 1.0):
        with pytest.raises(ValueError):
            controller._ensure_connector(station, cid)
    assert station["connectorCount"] == 1


def test_connector_count_never_exceeds_the_limit():
    cases = [(2, 2), (0, 1), (-5, 1), (10**9, MAX_CONNECTORS), (None, 1), ("7", 1), (True, 1), (2.0, 1)]
    for stored, expected in cases:
        assert connector_count({"connectorCount": stored}) == expected


# --- a state file written by an older version (possibly under attack) ---------------------------


async def test_poisoned_state_file_is_repaired_at_startup(tmp_path, caplog):
    """The pre-fix server saved what it was sent. Loading such a file must not bring back the hang."""
    data = tmp_path / "data"
    data.mkdir()
    good_zone = {"_id": "abc123", "name": "Night", "isSchedule": True, "scheduleEnabled": True, "allDay": True}
    state = {
        "next_transaction_id": 7,
        "tokens": {"t": "not a session", "u": {"refresh": "r", "expires": "soon"}},
        "stations": {
            SERIAL: {
                "id": SERIAL,
                "displayName": ["not", "text"],
                "timezone": 5,
                "currency": None,
                "priceKW": "free",
                "connectorCount": 2_000_000_000,
                "maxCurrent": None,
                "minCurrent": "lots",
                "currentLimit": 10**9,
                "boot": {"chargePointModel": "GRD 40A 2025", "junk": "x" * 100_000},
                "config": {"NumberOfConnectors": "2", "Huge": "y" * 100_000, "Nested": {"a": [1, 2]}},
                "dataTransfers": [{"at": "2026-01-01T00:00:00Z", "vendorId": "v", "data": "z" * 100_000}],
                "connectors": {
                    "1": {
                        "id": 1,
                        "status": ["Charging"],
                        "mode": "Whenever",
                        "lastRemoteStart": 9e12,
                        "lastRemoteStop": 9e12,
                        "transaction": {"id": 3, "startAt": 12345, "energy": 0},
                    },
                    "2": {"id": 2, "status": "Available", "mode": "Schedule", "transaction": "none"},
                    "2000000000": {"id": 2_000_000_000, "status": "Available"},
                    "x": {},
                    "03": {"id": 3},
                },
                "pricesByZone": [
                    good_zone,
                    {"_id": "bad", "startHours": "soon"},
                    "junk",
                    {"name": "no id"},
                    # Values the old code accepted and coped with are mended, not thrown away:
                    {"_id": "mend1", "name": "n" * 300, "isSchedule": True, "currentLimit": 120, "days": [1, 7, 9]},
                ],
                "holidaysSettings": {"enabled": True, "country": 12},
            },
            "GRD-BROKEN": "not a station",
        },
    }
    (data / "state.json").write_text(json.dumps(state))

    caplog.set_level(logging.WARNING)
    async with TestServer(make_app(tmp_path)) as test_server, TestClient(test_server) as client:
        controller = client.app["controller"]
        station = controller.station(SERIAL)
        assert "GRD-BROKEN" not in controller.stations
        assert station["connectorCount"] == 2 and set(station["connectors"]) == {"1", "2"}
        one = station["connectors"]["1"]
        assert one["status"] is None and one["mode"] == "Active"
        assert one["lastRemoteStart"] is None and one["lastRemoteStop"] is None
        assert one["transaction"]["id"] == 3
        assert station["connectors"]["2"]["transaction"] is None
        assert station["displayName"] == SERIAL and station["priceKW"] == 0
        assert station["timezone"] == "UTC" and station["currency"] == "USD"
        assert station["maxCurrent"] == 40 and station["minCurrent"] == 6 and station["currentLimit"] is None
        assert station["boot"] == {"chargePointModel": "GRD 40A 2025", "timestamp": None}
        assert station["config"]["NumberOfConnectors"] == "2" and len(station["config"]["Huge"]) == 500
        assert station["config"]["Nested"] is None
        assert len(station["dataTransfers"][0]["data"]) == 1000
        assert [z["_id"] for z in station["pricesByZone"]] == ["abc123", "mend1"]
        mended = station["pricesByZone"][1]
        assert len(mended["name"]) == 100 and mended["currentLimit"] == 100 and mended["days"] == [1]
        assert "holidaysSettings" not in station
        assert client.app["controller"].store.state["tokens"] == {}

        # The controller runs on it: a couple of ticks, the API answers, nothing blows up.
        headers = await bearer(client)
        await asyncio.sleep(2.2)
        resp = await client.get("/client/stations", headers=headers)
        assert resp.status == 200
        listed = strict_json(await resp.text())["stations"][0]
        assert [c["connectorId"] for c in listed["connectors"]] == [1, 2]
        resp = await client.get(f"/local/stations/{SERIAL}/sessions", headers=headers)
        assert resp.status == 200
    _no_failures(caplog)
    assert len((data / "state.json").read_text()) < 20_000  # and what is written back is small again


# --- a bounded number of stations --------------------------------------------------------------


async def test_unknown_serials_cannot_create_stations_without_limit(tmp_path, session):
    async with TestServer(make_app(tmp_path, max_stations=2)) as ts, TestClient(ts) as server:
        controller = server.app["controller"]
        first = await RawCharger.connect(server, session, "GRD-ONE00001")
        second = await RawCharger.connect(server, session, "GRD-TWO00001", auth=("GRD-TWO00001", "key"))
        with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
            await RawCharger.connect(server, session, "GRD-THREE001")
        assert refused.value.status == 503
        assert set(controller.stations) == {"GRD-ONE00001", "GRD-TWO00001"}

        # Stations that exist are not affected, online or after a reconnect.
        await second.close()
        await wait_for(lambda: not controller.is_online("GRD-TWO00001"))
        second = await RawCharger.connect(server, session, "GRD-TWO00001", auth=("GRD-TWO00001", "key"))
        assert (await second.call("Heartbeat", {}))[0] == 3

        # Deleting one makes room again.
        await first.close()
        await wait_for(lambda: not controller.is_online("GRD-ONE00001"))
        resp = await server.delete("/local/stations/GRD-ONE00001", headers=await bearer(server))
        assert resp.status == 200
        third = await RawCharger.connect(server, session, "GRD-THREE001")
        assert set(controller.stations) == {"GRD-TWO00001", "GRD-THREE001"}
        await third.close()
        await second.close()


async def test_station_limit_also_holds_with_a_shared_ocpp_password(tmp_path, session):
    async with TestServer(make_app(tmp_path, max_stations=1, ocpp_password="shared")) as ts, TestClient(ts) as server:
        cp = await RawCharger.connect(server, session, "GRD-ONE00001", auth=("GRD-ONE00001", "shared"))
        with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
            await RawCharger.connect(server, session, "GRD-TWO00001", auth=("GRD-TWO00001", "shared"))
        assert refused.value.status == 503
        with pytest.raises(aiohttp.WSServerHandshakeError) as refused:  # the password is still checked first
            await RawCharger.connect(server, session, "GRD-TWO00001", auth=("GRD-TWO00001", "wrong"))
        assert refused.value.status == 401
        await cp.close()


def test_max_stations_setting(monkeypatch):
    assert Settings().max_stations == 16
    monkeypatch.setenv("GRIZZLE_MAX_STATIONS", "40")
    assert Settings().max_stations == 40
    assert Settings(max_stations=0).max_stations == 1


# --- numbers that are not numbers ------------------------------------------------------------


async def test_non_finite_meter_values_never_reach_the_api(server, session):
    """float("NaN") is a number to Python and a syntax error to every JSON parser but Python's.
    One such reading used to make /client/stations unparseable for the web page and Home Assistant."""
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        assert (await cp.call("StartTransaction", {"connectorId": 1, "idTag": "t", "meterStart": float("nan")}))[0] == 3
        for value in ["NaN", "nan", "Infinity", "-inf", "1e999", float("inf"), float("nan"), 1e300, "1" * 400, True]:
            sampled = [
                {"value": value, "measurand": "Power.Active.Import", "unit": "W"},
                {"value": value, "measurand": "Energy.Active.Import.Register", "unit": "kWh"},
                {"value": value, "measurand": "Voltage"},
                {"value": "7", "measurand": "Current.Import"},
            ]
            reply = await cp.call("MeterValues", {"connectorId": 1, "meterValue": [{"sampledValue": sampled}]})
            assert reply[0] == 3, reply
        assert (await cp.call("StopTransaction", {"transactionId": 1, "meterStop": float("inf")}))[0] == 3

        headers = await bearer(server)
        for path in ("/client/stations", f"/local/stations/{SERIAL}/sessions", f"/local/stations/{SERIAL}/samples"):
            resp = await server.get(path, headers=headers)
            assert resp.status == 200
            strict_json(await resp.text())
        station = strict_json(await (await server.get("/client/stations", headers=headers)).text())["stations"][0]
        meter = station["connectors"][0]["lastMeter"]
        assert meter["currentImport"] == 7 and meter["voltage"] is None
        assert station["connectors"][0]["power"] == 0
    finally:
        await cp.close()


async def test_api_output_is_strict_json_even_if_state_holds_nan(server, session):
    """Belt and braces: whatever gets into memory, a response is always parseable."""
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        assert (await cp.call("StatusNotification", OK_STATUS))[0] == 3
        station = server.app["controller"].station(SERIAL)
        station["priceKW"] = float("nan")
        station["connectors"]["1"]["power"] = float("inf")
        resp = await server.get("/client/stations", headers=await bearer(server))
        data = strict_json(await resp.text())["stations"][0]
        assert data["connectors"][0]["power"] is None
    finally:
        await cp.close()


def test_state_file_non_finite_numbers_are_dropped_on_load(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "state.json").write_text('{"stations": {"GRD-A": {"id": "GRD-A", "priceKW": NaN, "x": [Infinity, 1.5]}}}')
    store = Store(data)
    assert store.state["stations"]["GRD-A"]["priceKW"] is None
    assert store.state["stations"]["GRD-A"]["x"] == [None, 1.5]


# --- values of the wrong type -----------------------------------------------------------------


async def test_wrong_typed_messages_do_not_break_the_controller(server, session, caplog):
    """Each of these used to leave something in the station that made every later tick raise,
    for every station, which also skipped the periodic save."""
    controller = server.app["controller"]
    caplog.set_level(logging.ERROR)
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        for status in ([], {}, 5, None, ""):
            reply = await cp.call("StatusNotification", {"connectorId": 1, "status": status})
            assert reply[0] == 4 and reply[2] == "TypeConstraintViolation", (status, reply)
        assert (await cp.call("StatusNotification", {**OK_STATUS, "status": "Charging", "timestamp": [1]}))[0] == 3

        overflowing = ["9999-12-31T23:59:59-23:59", "0001-01-01T00:00:00+23:59"]
        for stamp in (5, "2026-01-01T00:00:00", *overflowing, "", [], "x" * 500):
            reply = await cp.call(
                "StartTransaction", {"connectorId": 1, "idTag": ["a"], "meterStart": "lots", "timestamp": stamp}
            )
            assert reply[0] == 3, (stamp, reply)
            tx = controller.station(SERIAL)["connectors"]["1"]["transaction"]
            assert _parse_iso(tx["startAt"]) is not None and tx["idTag"] is None and tx["meterStart"] is None

        odd_meter_values = [
            {"connectorId": 1, "meterValue": {"sampledValue": []}},
            {"connectorId": 1, "meterValue": ["x", 5, None]},
            {"connectorId": 1, "meterValue": [{"sampledValue": "nope"}]},
            {"connectorId": 1, "meterValue": [{"sampledValue": [5, "x", {"value": "1", "measurand": ["list"]}]}]},
            {"connectorId": 1, "transactionId": {"a": 1}, "meterValue": [{"timestamp": {}, "sampledValue": [
                {"value": "230", "measurand": "Voltage", "unit": ["V"], "phase": {}}]}]},
            {"connectorId": 1, "transactionId": 10**30, "meterValue": [{"sampledValue": [{"value": "5"}]}]},
        ]
        for payload in odd_meter_values:
            assert (await cp.call("MeterValues", payload))[0] == 3, payload
        assert (await cp.call("StopTransaction", {"transactionId": "seven", "transactionData": "x"}))[0] == 3
        # Lone surrogates are legal in JSON strings; SQLite and UTF-8 logs take neither.
        lone = "\udcff\ud800"
        assert (await cp.call("StartTransaction", {"connectorId": 1, "idTag": lone, "meterStart": 1}))[0] == 3
        tid = controller.station(SERIAL)["connectors"]["1"]["transaction"]["id"]
        assert (await cp.call("StopTransaction", {"transactionId": tid, "reason": lone, "meterStop": 2}))[0] == 3
        assert (await cp.call("StatusNotification", {**OK_STATUS, "status": lone, "info": lone}))[0] == 3
        assert (await cp.call(lone, {lone: lone}))[0] == 4
        assert (await cp.call("DataTransfer", {"vendorId": ["v"], "data": {"deep": [1, 2]}}))[0] == 3
        assert (await cp.call("FirmwareStatusNotification", {"status": {"a": 1}}))[0] == 3
        assert (await cp.call("BootNotification", {"chargePointModel": ["GRD"], "firmwareVersion": {"v": 1}}))[0] == 3

        await asyncio.sleep(2.5)  # a couple of ticks over all of that
        resp = await server.get("/client/stations", headers=await bearer(server))
        assert resp.status == 200
        strict_json(await resp.text())
        resp = await server.get(f"/local/stations/{SERIAL}/sessions", headers=await bearer(server))
        assert resp.status == 200
    finally:
        await cp.close()
    _no_failures(caplog)


def test_parse_iso_is_total():
    assert _parse_iso("2026-11-08T16:12:17Z").isoformat() == "2026-11-08T16:12:17+00:00"
    assert _parse_iso("2026-11-08T18:12:17+02:00").isoformat() == "2026-11-08T16:12:17+00:00"
    assert _parse_iso("2026-11-08T16:12:17").tzinfo is not None  # no offset: taken as UTC, never naive
    overflowing = ["9999-12-31T23:59:59-23:59", "0001-01-01T00:00:00+23:59"]
    for bad in (None, 5, 5.5, [], {}, "", "yesterday", *overflowing, "1" * 100):
        assert _parse_iso(bad) is None, bad


def test_charger_timestamps_are_normalised_and_sanity_checked():
    assert _timestamp("2026-11-08T16:12:17Z") == "2026-11-08T16:12:17.000Z"
    assert _timestamp("2026-11-08T18:12:17.5+02:00") == "2026-11-08T16:12:17.500Z"
    now = time.time()
    for implausible in ("1970-01-01T00:00:03Z", "2999-01-01T00:00:00Z", None, 17, "soon"):
        stamp = _parse_iso(_timestamp(implausible))
        assert abs(stamp.timestamp() - now) < 60, implausible  # the clock was never set, or is far off: use ours


# --- one station can't hold up the others ------------------------------------------------------


async def test_a_failing_station_does_not_stop_the_tick_or_the_save(tmp_path, monkeypatch, caplog):
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as server:
        controller = server.app["controller"]
        controller._ensure_station("GRD-BAD00001")
        controller._ensure_station("GRD-GOOD0001")
        enforced: list[str] = []
        original = Controller._enforce

        async def enforce(self, station_id, cid):
            if station_id == "GRD-BAD00001":
                raise RuntimeError("this station is broken")
            enforced.append(station_id)
            return await original(self, station_id, cid)

        monkeypatch.setattr(Controller, "_enforce", enforce)
        caplog.set_level(logging.ERROR)
        await wait_for(lambda: len(enforced) >= 2, timeout=5)
        controller.station("GRD-GOOD0001")["displayName"] = "saved despite the neighbour"
        controller.mark_dirty()
        state_path = controller.store._state_path
        await wait_for(lambda: state_path.exists() and "saved despite the neighbour" in state_path.read_text(), 5)
    assert any("background task failed" in r.getMessage() for r in caplog.records)  # reported, not swallowed


async def test_an_unresponsive_charger_does_not_stall_the_controller(server, session, monkeypatch):
    """The tick awaited every charger in turn (30 s per unanswered call). One silent peer with a car
    "plugged in" therefore froze enforcement and saving for everybody."""
    controller = server.app["controller"]
    monkeypatch.setattr(controller_module, "REMOTE_RETRY_SECONDS", 0.01)  # so every tick calls the silent one again
    silent = await RawCharger.connect(server, session, "GRD-SILENT01")
    silent.answer = False
    try:
        await silent.call("StatusNotification", {**OK_STATUS, "status": "Preparing"})
        await wait_for(lambda: len(silent.calls("RemoteStartTransaction")) >= 1)
        await asyncio.sleep(1.5)  # by now a tick is waiting on it

        # Meanwhile the controller still saves...
        controller._ensure_station("GRD-OTHER001")["displayName"] = "still being looked after"
        controller.mark_dirty()
        state_path = controller.store._state_path
        await wait_for(lambda: state_path.exists() and "still being looked after" in state_path.read_text(), 4)
        # ...and still enforces schedules for other stations.
        other = controller.station("GRD-OTHER001")
        other["connectors"]["1"]["isActiveBySchedule"] = None
        await wait_for(lambda: other["connectors"]["1"]["isActiveBySchedule"] is False, 4)
    finally:
        await silent.close()


async def test_boot_notification_spam_keeps_one_after_boot_task(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        for _ in range(40):
            assert (await cp.call("BootNotification", {"chargePointModel": "GRD 40A"}))[0] == 3
        await asyncio.sleep(0.1)
        boot_tasks = [t for t in controller._tasks if "_after_boot" in repr(t.get_coro()) and not t.done()]
        assert len(boot_tasks) == 1
        # ...and that one still does its job.
        await wait_for(lambda: cp.calls("GetConfiguration"), timeout=6)
        assert len(cp.calls("GetConfiguration")) == 1
    finally:
        await cp.close()


async def test_call_gives_up_when_the_peer_stops_reading():
    """The send used to be outside the deadline: a peer with a full receive window held the caller forever."""

    class StuckSocket:
        closed = False

        async def send_str(self, text):
            await asyncio.sleep(3600)

    conn = ChargePointConnection("GRD-STUCK001", StuckSocket(), handler=None)
    started = time.monotonic()
    with pytest.raises(OcppError) as failure:
        await conn.call("Reset", {"type": "Soft"}, timeout=0.2)
    assert failure.value.code == "Timeout" and time.monotonic() - started < 2
    assert conn._pending == {}


async def test_call_reports_a_dead_socket_as_disconnected():
    class DeadSocket:
        closed = False

        async def send_str(self, text):
            raise ConnectionResetError("Cannot write to closing transport")

    conn = ChargePointConnection("GRD-DEAD0001", DeadSocket(), handler=None)
    with pytest.raises(OcppError) as failure:
        await conn.call("Reset", {})
    assert failure.value.code == "Disconnected"


# --- bounded memory per connection --------------------------------------------------------------


async def test_oversized_frame_is_refused(server, session):
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        await cp.send_text(json.dumps([2, "big", "DataTransfer", {"data": "x" * (ocpp.MAX_FRAME_BYTES + 1)}]))
        await wait_for(lambda: cp.close_code is not None, timeout=5)
        assert cp.close_code == aiohttp.WSCloseCode.MESSAGE_TOO_BIG
    finally:
        await cp.close()


async def test_large_frames_are_not_kept_in_the_frame_log(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        for _ in range(5):
            assert (await cp.call("DataTransfer", {"vendorId": "v", "data": "x" * 100_000}))[0] == 3
        conn = controller.connections[SERIAL]
        assert sum(len(entry["text"]) for entry in conn.log) < 5_000  # what is actually held in memory
        frames = conn.frames()
        assert any(entry["data"].get("bytes", 0) > 100_000 for entry in frames if isinstance(entry["data"], dict))
        assert any(entry["label"] == "-> result DataTransfer" and entry["data"][0] == 3 for entry in frames)
        stored = controller.station(SERIAL)["dataTransfers"]
        assert len(stored) == 5 and all(len(item["data"]) == 1000 for item in stored)
    finally:
        await cp.close()


async def test_boot_and_configuration_payloads_are_stored_bounded(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    cp.replies["GetConfiguration"] = {  # about 150 KiB: under the frame limit, far more than we keep
        "configurationKey": [{"key": ["bad"], "value": "x"}, "junk", {"key": "Long", "value": "v" * 5000}]
        + [{"key": f"K{i}", "value": "v" * 40} for i in range(2000)]
    }
    try:
        boot = {"chargePointModel": "GRD " + "M" * 5000, "firmwareVersion": "1.0", "junk": "j" * 100_000}
        boot["deep"] = {"a": 1}
        assert (await cp.call("BootNotification", boot))[0] == 3
        station = controller.station(SERIAL)
        assert set(station["boot"]) == {"chargePointModel", "firmwareVersion", "timestamp"}
        assert len(station["boot"]["chargePointModel"]) == 100 and len(station["model"]["code"]) == 100
        await wait_for(lambda: station["config"], timeout=6)
        assert len(station["config"]) < controller_module.MAX_CONFIG_KEYS
        assert len(station["config"]["Long"]) == 500
        assert all(isinstance(k, str) and len(v) <= 500 for k, v in station["config"].items())
    finally:
        await cp.close()


async def test_many_meter_values_in_one_message_are_capped(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        one = {"sampledValue": [{"value": "230", "measurand": "Voltage"}]}
        assert (await cp.call("MeterValues", {"connectorId": 1, "meterValue": [one] * 500}))[0] == 3
        rows = controller.store._db.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        assert rows == controller_module.MAX_METER_VALUES
    finally:
        await cp.close()


async def test_read_rate_is_limited_after_the_burst(monkeypatch):
    clock = [1000.0]
    slept: list[float] = []

    async def fake_sleep(seconds):
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(ocpp.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(ocpp.asyncio, "sleep", fake_sleep)
    conn = ChargePointConnection("GRD-FLOOD001", ws=None, handler=None, rate_burst=5, rate_per_second=10)
    for _ in range(5):
        await conn._throttle()
    assert slept == []  # the burst is free
    for _ in range(20):
        await conn._throttle()
    assert len(slept) == 20 and all(s == pytest.approx(0.1) for s in slept)  # then one frame per 1/rate
    clock[0] += 60  # after a quiet minute the burst is available again, and no more than the burst
    slept.clear()
    for _ in range(6):
        await conn._throttle()
    assert len(slept) == 1


# --- frames that aren't quite OCPP ------------------------------------------------------------


async def test_unhashable_unique_ids_do_not_kill_the_connection(server, session, caplog):
    caplog.set_level(logging.ERROR)
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        odd = ([3, ["list"], {}], [3, {"a": 1}, {}], [4, [], "GenericError", "x", {}], [2, [1], "Heartbeat", {}])
        for frame in odd:
            await cp.send_text(json.dumps(frame))
        await cp.send_text("[" * 50_000)  # deeper than the parser's recursion limit
        assert (await cp.call("Heartbeat", {}))[0] == 3
        assert (await cp.call("Heartbeat", {}, uid=7))[:2] == [3, 7]  # a numeric id is echoed back
    finally:
        await cp.close()
    _no_failures(caplog)


async def test_pending_calls_fail_when_the_read_loop_ends_abnormally():
    class ExplodingSocket:
        closed = False

        def __aiter__(self):
            return self

        async def __anext__(self):
            raise RuntimeError("transport blew up")

    conn = ChargePointConnection("GRD-BOOM0001", ExplodingSocket(), handler=None)
    waiter = asyncio.get_running_loop().create_future()
    conn._pending["u1"] = waiter
    with pytest.raises(RuntimeError):
        await conn.run()
    assert isinstance(waiter.exception(), OcppError) and waiter.exception().code == "Disconnected"


# --- the RemoteStart/RemoteStop rate limiter and restarts -------------------------------------------


def test_recent_ignores_timestamps_from_an_earlier_boot():
    assert _recent(100.0, 130.0) is True
    assert _recent(100.0, 161.0) is False
    assert _recent(None, 5.0) is False
    assert _recent(500_000.0, 42.0) is False  # "last attempt" later than now: the host has rebooted since


async def test_remote_start_works_after_a_host_reboot(tmp_path, session):
    """lastRemoteStart is a monotonic-clock reading. Saved, then read back after the host rebooted
    (clock near zero again), it looked like "tried a moment ago" for days: no car could start."""
    data = tmp_path / "data"
    data.mkdir()
    connector = {"id": 1, "status": "Available", "mode": "Active", "transaction": None, "lastRemoteStart": 9e9}
    station = {"id": SERIAL, "connectorCount": 1, "connectors": {"1": connector}, "pricesByZone": []}
    (data / "state.json").write_text(json.dumps({"stations": {SERIAL: station}}))
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as server:
        # The charger reconnects; one that kept running sends no BootNotification (which would reset the limiter).
        cp = await RawCharger.connect(server, session, SERIAL)
        try:
            await cp.call("StatusNotification", {**OK_STATUS, "status": "Preparing"})
            await wait_for(lambda: cp.calls("RemoteStartTransaction"), timeout=4)
        finally:
            await cp.close()


# --- history survives a lost state file -----------------------------------------------------------


def test_transaction_ids_never_reuse_recorded_sessions(tmp_path):
    data = tmp_path / "data"
    store = Store(data)
    for _ in range(3):
        tid = store.next_transaction_id()
        store.start_session(tid, SERIAL, 1, "tag", "2026-11-01T10:00:00.000Z", 1000, 0.1)
        store.finish_session(tid, "2026-11-01T11:00:00.000Z", 2000, 1000.0, 3600, 0.1, "Local")
    store.close()
    (data / "state.json").unlink(missing_ok=True)  # state lost (or reset as corrupt); history.sqlite is still there

    store = Store(data)
    tid = store.next_transaction_id()
    assert tid == 4
    store.start_session(tid, SERIAL, 1, "tag", "2026-11-02T10:00:00.000Z", 2000, 0.1)
    sessions = store.sessions(SERIAL)
    assert len(sessions) == 4 and sum(1 for s in sessions if s["stop_at"]) == 3  # nothing was overwritten


@pytest.mark.parametrize("content", ["[]", '"text"', "12", "null", "{", "[" * 50_000])
def test_state_file_that_is_not_an_object_is_set_aside(tmp_path, content):
    data = tmp_path / "data"
    data.mkdir()
    (data / "state.json").write_text(content)
    store = Store(data)
    assert store.state["stations"] == {} and store.state["tokens"] == {}
    assert (data / "state.corrupt.json").read_text() == content


# --- logs --------------------------------------------------------------------------------------


def test_printable_cannot_span_lines():
    forged = "Heartbeat\n2026-11-13 00:00:00 INFO grizzle_local: GRD-REAL connected\r\x1b[31m\u2028\udcff"
    text = printable(forged)
    assert "\n" not in text and "\r" not in text and "\x1b" not in text and "\u2028" not in text
    assert text.startswith("Heartbeat\\n2026")
    text.encode("utf-8")  # and no lone surrogate is left either
    assert len(printable("x" * 10_000, 100)) < 140
    assert printable(["a", 1]) == "['a', 1]"


def test_log_formatter_escapes_whatever_reaches_it():
    formatter = SingleLineFormatter("%(levelname)s %(name)s: %(message)s")
    record = logging.LogRecord("grizzle_local", logging.INFO, __file__, 1, "serial %s", ("A\nINFO forged: line",), None)
    line = formatter.format(record)
    assert line == "INFO grizzle_local: serial A\\nINFO forged: line"
    long_record = logging.LogRecord("x", logging.INFO, __file__, 1, "%s", ("y" * 100_000,), None)
    assert len(formatter.format(long_record)) < 5_000


async def test_charger_controlled_text_is_logged_on_one_line(server, session, caplog):
    caplog.set_level(logging.DEBUG)
    evil = "X\n2026-11-13 00:00:00,000 INFO grizzle_local: GRD-REAL0001 connected"
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        assert (await cp.call(evil, {"k": evil}))[0] == 4  # an action nobody implements
        assert (await cp.call("StatusNotification", {**OK_STATUS, "status": evil, "errorCode": evil}))[0] == 3
        assert (await cp.call("BootNotification", {"chargePointModel": evil, "firmwareVersion": evil}))[0] == 3
        assert (await cp.call("DataTransfer", {"vendorId": evil, "data": evil}))[0] == 3
        assert (await cp.call("StopTransaction", {"transactionId": evil, "reason": evil}))[0] == 3
        await cp.send_text("not json at all\nINFO forged")
        await cp.send_text(json.dumps([2, 5.5, evil, {}]))
        cp.replies["ChangeConfiguration"] = {"status": evil}
        await wait_for(lambda: cp.calls("ChangeConfiguration"), timeout=6)
        await asyncio.sleep(0.3)
    finally:
        await cp.close()
    ours = [r for r in caplog.records if r.name.startswith("grizzle_local")]
    assert len(ours) > 5
    for record in ours:
        assert "\n" not in record.getMessage() and "\r" not in record.getMessage(), record.getMessage()


def test_call_errors_from_the_charger_are_sanitised():
    error = OcppError("Generic\nError", "boom\r\nINFO forged" + "x" * 5000)
    assert "\n" not in str(error) and "\r" not in str(error) and len(str(error)) < 500


# --- sessions: retransmissions, and a register that outgrows its starting point --------------------


async def test_retransmitted_start_transaction_gets_the_same_transaction(server, session):
    """OCPP tells a charger to repeat a request whose answer it never saw. Each repeat used to open
    another session and leave the previous one open in the history for ever."""
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        start = {"connectorId": 1, "idTag": "tag", "meterStart": 1000, "timestamp": "2026-11-08T16:12:17Z"}
        first = (await cp.call("StartTransaction", start))[2]["transactionId"]
        again = (await cp.call("StartTransaction", start))[2]["transactionId"]
        assert again == first
        assert len(controller.store.sessions(SERIAL)) == 1

        # A different session on the same connector: the open one is closed, not orphaned.
        other = {**start, "meterStart": 1500, "timestamp": "2026-11-08T17:00:00Z"}
        second = (await cp.call("StartTransaction", other))[2]["transactionId"]
        assert second != first
        sessions = {s["id"]: s for s in controller.store.sessions(SERIAL)}
        assert sessions[first]["stop_at"] == "2026-11-08T17:00:00.000Z" and sessions[first]["reason"] == "Superseded"
        assert sessions[second]["stop_at"] is None
        assert controller.station(SERIAL)["connectors"]["1"]["transaction"]["id"] == second
    finally:
        await cp.close()


async def test_session_relative_register_may_outgrow_meter_start(tmp_path):
    """A nearly new charger: 5 kWh on the lifetime register, then a 20 kWh session. The firmware's
    MeterValues count from 0; once they passed 5000 they were suddenly taken for lifetime readings
    and the session's energy fell back to almost nothing (and its cost with it)."""
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    await controller.set_base_rate(SERIAL, 0.10)
    await controller._on_StartTransaction(station, {"connectorId": 1, "idTag": "t", "meterStart": 5000})

    def reading(wh):
        sampled = [{"value": str(wh), "measurand": "Energy.Active.Import.Register", "unit": "Wh"}]
        return {"connectorId": 1, "transactionId": 1, "meterValue": [{"sampledValue": sampled}]}

    energies = []
    for wh in (0, 2500, 4999, 5000, 5001, 12000, 19950):
        await controller._on_MeterValues(station, reading(wh))
        energies.append(station["connectors"]["1"]["transaction"]["energy"])
    assert energies == [0, 2500, 4999, 5000, 5001, 12000, 19950]
    tx = station["connectors"]["1"]["transaction"]
    assert tx["sessionRelativeRegister"] is True and tx["priceTotal"] == pytest.approx(1.995)
    assert station["connectors"]["1"]["totalEnergyWh"] == 24950

    await controller._on_StopTransaction(station, {"transactionId": 1, "meterStop": 20000})  # session-relative too
    recorded = controller.store.sessions(SERIAL)[0]
    assert recorded["energy_wh"] == 20000 and station["connectors"]["1"]["totalEnergyWh"] == 25000


@pytest.mark.parametrize(
    "meter_start,readings,meter_stop,expected",
    [
        (819392, [0, 1500], 2000, 2000),  # the Duo: lifetime start, session-relative everything else
        (819392, [0, 1500], 821392, 2000),  # session-relative MeterValues, lifetime meterStop
        (500000, [500000, 501500], 502000, 2000),  # a charger that reports the lifetime register throughout
        (500000, [], 502000, 2000),  # no MeterValues at all
        (5000, [], 3000, 3000),  # ...and a meterStop that can only be session-relative
    ],
)
async def test_meter_stop_is_read_in_whichever_convention_fits(tmp_path, meter_start, readings, meter_stop, expected):
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    await controller._on_StartTransaction(station, {"connectorId": 1, "idTag": "t", "meterStart": meter_start})
    for wh in readings:
        sampled = [{"value": str(wh), "measurand": "Energy.Active.Import.Register", "unit": "Wh"}]
        await controller._on_MeterValues(station, {"connectorId": 1, "meterValue": [{"sampledValue": sampled}]})
    await controller._on_StopTransaction(station, {"transactionId": 1, "meterStop": meter_stop})
    assert controller.store.sessions(SERIAL)[0]["energy_wh"] == expected


# --- current limits ---------------------------------------------------------------------------------


def _limits_sent(cp: RawCharger) -> list[int]:
    return [
        call["csChargingProfiles"]["chargingSchedule"]["chargingSchedulePeriod"][0]["limit"]
        for call in cp.calls("SetChargingProfile")
    ]


async def test_a_windows_current_limit_is_lifted_when_the_window_ends(server, session):
    """A window with its own limit throttled the charger, and when the window ended (or was switched
    off, or deleted) nothing ever gave the current back: the charger stayed at 16 A for good."""
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        assert (await cp.call("StatusNotification", OK_STATUS))[0] == 3
        zone = await controller.upsert_zone(
            SERIAL, {"name": "Night", "isSchedule": True, "allDay": True, "days": [], "currentLimit": 16}
        )
        station = controller.station(SERIAL)
        assert _limits_sent(cp) == [16] and station["appliedLimit"] == 16 and station["limitInForce"] is True

        await controller.set_zone_enabled(SERIAL, zone["_id"], False)  # the window is over
        assert _limits_sent(cp) == [16, 40]  # back to the station's full current
        assert station["appliedLimit"] == 40 and station["limitInForce"] is False
        for _ in range(3):
            await controller._tick_station(SERIAL)
        assert _limits_sent(cp) == [16, 40]  # once; and a charger we never limited is left alone

        # With a station-wide limit, the end of the window falls back to that instead.
        await controller.set_current_limit(SERIAL, 24)
        await controller.set_zone_enabled(SERIAL, zone["_id"], True)
        await controller.set_zone_enabled(SERIAL, zone["_id"], False)
        assert _limits_sent(cp) == [16, 40, 24, 16, 24]
    finally:
        await cp.close()


async def test_a_limit_outside_the_chargers_range_is_sent_once(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        assert (await cp.call("StatusNotification", OK_STATUS))[0] == 3
        await controller.upsert_zone(
            SERIAL, {"name": "Trickle", "isSchedule": True, "allDay": True, "days": [], "currentLimit": 3}
        )
        for _ in range(4):
            await controller._tick_station(SERIAL)
        assert _limits_sent(cp) == [6]  # clamped to the minimum, and not repeated on every tick
    finally:
        await cp.close()


async def test_a_limit_left_in_force_by_an_older_version_is_lifted(tmp_path, session):
    data = tmp_path / "data"
    data.mkdir()
    connector = {"id": 1, "status": "Available", "mode": "Active", "transaction": None}
    station = {"id": SERIAL, "connectorCount": 1, "connectors": {"1": connector}, "pricesByZone": []}
    station["appliedLimit"] = 16  # applied for a window that has since ended; never lifted
    (data / "state.json").write_text(json.dumps({"stations": {SERIAL: station}}))
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as server:
        cp = await RawCharger.connect(server, session, SERIAL)
        try:
            await wait_for(lambda: _limits_sent(cp) == [40], timeout=4)
        finally:
            await cp.close()


# --- saving must survive whatever a charger reports --------------------------------------------------


async def test_non_string_configuration_keys_do_not_break_saving(server, session):
    """An integer key next to string keys made json.dumps(sort_keys=True) raise on every save from
    then on: nothing was persisted any more, while the server looked perfectly healthy."""
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    cp.replies["GetConfiguration"] = {
        "configurationKey": [
            {"key": 1, "value": "x"},
            {"key": 2.5, "value": "x"},
            {"key": True, "value": "x"},
            {"key": None, "value": "x"},
            {"key": "HeartbeatInterval", "value": 300},
        ]
    }
    try:
        assert (await cp.call("BootNotification", {"chargePointModel": "GRD 40A"}))[0] == 3
        await wait_for(lambda: controller.station(SERIAL)["config"], timeout=6)
        assert controller.station(SERIAL)["config"] == {"HeartbeatInterval": "300"}
        controller.store.save()
        assert SERIAL in json.loads(controller.store._state_path.read_text())["stations"]
    finally:
        await cp.close()


# --- repricing a deep history ---------------------------------------------------------------------------


async def test_recalculating_costs_uses_one_transaction_and_the_index(tmp_path):
    """Each session cost one full scan of the station's samples and one commit, all on the event
    loop: with a real history, every charger waited seconds for a button press."""
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    await controller.set_base_rate(SERIAL, 0.20)
    store = controller.store
    for tid in range(1, 201):
        tid = store.next_transaction_id()
        store.start_session(tid, SERIAL, 1, "t", f"2026-10-{1 + tid % 28:02d}T10:00:00.000Z", 0, 0.0)
        day = f"2026-10-{1 + tid % 28:02d}"
        store.add_samples([(SERIAL, 1, tid, f"{day}T10:{m:02d}:00.000Z", {"energy_wh": m * 100.0}) for m in range(30)])
        store.finish_session(tid, f"2026-10-{1 + tid % 28:02d}T11:00:00.000Z", 3000, 3000.0, 3600, 0.0, "Local")

    plan = store._db.execute(
        "EXPLAIN QUERY PLAN SELECT at, energy_wh FROM samples WHERE station=? AND transaction_id=?"
        " AND energy_wh IS NOT NULL ORDER BY at",
        (SERIAL, 5),
    ).fetchall()
    assert any("samples_station_tx" in row[-1] for row in plan), [row[-1] for row in plan]

    commits = []
    store._db.set_trace_callback(lambda sql: commits.append(sql) if sql.strip().upper().startswith("COMMIT") else None)
    result = await controller.recalculate_costs(SERIAL)
    store._db.set_trace_callback(None)
    assert result["sessions"] == 200 and result["cost_after"] == pytest.approx(200 * 3.0 * 0.20)
    assert len(commits) == 1
    assert all(s["cost"] == pytest.approx(0.6) for s in store.sessions(SERIAL, 1000))
    assert station["id"] == SERIAL


# --- found reviewing the fixes above ---------------------------------------------------------------


async def test_a_lifetime_reading_rounded_just_below_meter_start_is_still_lifetime(tmp_path):
    """Deciding the register convention once must not hinge on rounding: a charger that reports the
    lifetime register in kWh with one decimal starts a hair below the exact meterStart."""
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    await controller._on_StartTransaction(station, {"connectorId": 1, "idTag": "t", "meterStart": 819_392})

    def reading(kwh: str) -> dict:
        sampled = [{"value": kwh, "measurand": "Energy.Active.Import.Register", "unit": "kWh"}]
        return {"connectorId": 1, "meterValue": [{"sampledValue": sampled}]}

    await controller._on_MeterValues(station, reading("819.3"))  # 92 Wh "below" the start
    tx = station["connectors"]["1"]["transaction"]
    assert tx["sessionRelativeRegister"] is False and tx["energy"] == 0
    await controller._on_MeterValues(station, reading("821.4"))
    assert tx["energy"] == pytest.approx(2008)  # not 821 400

    # A register that really counts from zero is still recognised, next to a small lifetime total too.
    for meter_start, first in ((819_392, "0"), (5000, "0.01"), (300, "0")):
        controller = _controller(tmp_path / str(meter_start))
        station = controller._ensure_station(SERIAL)
        await controller._on_StartTransaction(station, {"connectorId": 1, "idTag": "t", "meterStart": meter_start})
        await controller._on_MeterValues(station, reading(first))
        assert station["connectors"]["1"]["transaction"]["sessionRelativeRegister"] is True, meter_start


async def test_a_session_reported_by_an_unset_clock_keeps_its_length(tmp_path):
    """A charger whose clock was never set (1970) reports a session after the fact. Both ends are
    stamped with the time we heard of them, milliseconds apart; the charger's clock, wrong date and
    all, still measured how long the session was."""
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    start = {"connectorId": 1, "idTag": "t", "meterStart": 1000, "timestamp": "1970-01-01T00:10:00Z"}
    await controller._on_StartTransaction(station, start)
    stop = {"transactionId": 1, "meterStop": 8000, "timestamp": "1970-01-01T01:40:00Z"}
    await controller._on_StopTransaction(station, stop)
    def recorded(tid: int) -> dict:
        return next(s for s in controller.store.sessions(SERIAL) if s["id"] == tid)

    assert recorded(1)["duration_s"] == 90 * 60
    assert abs(_parse_iso(recorded(1)["start_at"]).timestamp() - time.time()) < 60  # the dates are ours

    # With a sane clock nothing changes; and a clock that runs backwards is not believed.
    start = {"connectorId": 1, "idTag": "t", "meterStart": 8000, "timestamp": "2026-11-08T16:12:17Z"}
    await controller._on_StartTransaction(station, start)
    await controller._on_StopTransaction(station, {"transactionId": 2, "timestamp": "2026-11-08T17:00:00Z"})
    assert recorded(2)["duration_s"] == 2863
    start = {"connectorId": 1, "idTag": "t", "meterStart": 8000, "timestamp": "1970-01-02T00:00:00Z"}
    await controller._on_StartTransaction(station, start)
    await controller._on_StopTransaction(station, {"transactionId": 3, "timestamp": "1970-01-01T00:00:00Z"})
    assert recorded(3)["duration_s"] < 5


async def test_forgetting_a_station_removes_its_history(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    keep = await RawCharger.connect(server, session, "GRD-KEEP0001")
    try:
        for charger in (cp, keep):
            tid = (await charger.call("StartTransaction", {"connectorId": 1, "idTag": "t", "meterStart": 0}))[2]
            sampled = [{"value": "230", "measurand": "Voltage"}]
            await charger.call("MeterValues", {"connectorId": 1, "meterValue": [{"sampledValue": sampled}]})
            await charger.call("StopTransaction", {"transactionId": tid["transactionId"], "meterStop": 10})
    finally:
        await cp.close()
        await keep.close()
    await wait_for(lambda: not controller.is_online(SERIAL))
    assert (await server.delete(f"/local/stations/{SERIAL}", headers=await bearer(server))).status == 200
    db = controller.store._db
    for table in ("sessions", "samples"):
        left = db.execute(f"SELECT DISTINCT station FROM {table}").fetchall()  # noqa: S608 - fixed table names
        assert [row[0] for row in left] == ["GRD-KEEP0001"], table


async def test_history_per_station_is_bounded(tmp_path, monkeypatch):
    """Age was the only limit on stored samples, and sessions had none: a peer that keeps reporting
    could grow the database without end, and deleting its station did not give the space back."""
    from grizzle_local import store as store_module

    monkeypatch.setattr(store_module, "MAX_SAMPLES_PER_STATION", 100)
    monkeypatch.setattr(store_module, "MAX_SESSIONS_PER_STATION", 5)
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    other = controller._ensure_station("GRD-OTHER001")
    sampled = [{"value": "230", "measurand": "Voltage"}]
    await controller._on_MeterValues(other, {"connectorId": 1, "meterValue": [{"sampledValue": sampled}]})
    for n in range(400):
        stamp = f"2026-11-01T{n // 60:02d}:{n % 60:02d}:00Z"
        entry = {"timestamp": stamp, "sampledValue": sampled}
        await controller._on_MeterValues(station, {"connectorId": 1, "meterValue": [entry]})
    db = controller.store._db
    count = db.execute("SELECT COUNT(*) FROM samples WHERE station=?", (SERIAL,)).fetchone()[0]
    assert 100 <= count <= 110
    oldest = db.execute("SELECT MIN(at) FROM samples WHERE station=?", (SERIAL,)).fetchone()[0]
    assert oldest > "2026-11-01T04:40:00"  # the newest are the ones kept
    assert db.execute("SELECT COUNT(*) FROM samples WHERE station='GRD-OTHER001'").fetchone()[0] == 1

    for n in range(12):
        start = {"connectorId": 1, "idTag": "t", "meterStart": 0, "timestamp": f"2026-11-02T{n:02d}:00:00Z"}
        tid = (await controller._on_StartTransaction(station, start))["transactionId"]
        if n < 11:
            await controller._on_StopTransaction(station, {"transactionId": tid, "meterStop": 5})
    controller.store.prune_samples()
    sessions = controller.store.sessions(SERIAL, 100)
    assert len(sessions) == 5  # the newest; the oldest closed ones went, the one still running never does
    assert sessions[0]["stop_at"] is None and sessions[-1]["start_at"] == "2026-11-02T07:00:00.000Z"


def test_transaction_ids_follow_the_history_at_every_allocation(tmp_path):
    store = Store(tmp_path / "data")
    assert store.next_transaction_id() == 1
    store.start_session(50, SERIAL, 1, "t", "2026-11-01T10:00:00.000Z", 0, 0.1)  # the history is ahead of the counter
    assert store.next_transaction_id() == 51
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):  # and an id can no longer silently replace a session
        store.start_session(50, SERIAL, 1, "t", "2026-11-02T10:00:00.000Z", 0, 0.1)
    assert store.sessions(SERIAL)[0]["start_at"] == "2026-11-01T10:00:00.000Z"


async def test_saving_survives_odd_keys_and_a_failed_save_does_not_refuse_a_charger(server, session, monkeypatch):
    controller = server.app["controller"]
    controller._ensure_station(SERIAL)["oddKeys"] = {1: "a", "b": "c", 2.5: "d", None: "e"}
    controller.store.save()  # sorting these keys used to raise, on every save from then on
    assert SERIAL in json.loads(controller.store._state_path.read_text())["stations"]

    def full_disk():
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(controller.store, "save", full_disk)
    cp = await RawCharger.connect(server, session, "GRD-NEWPIN01", auth=("GRD-NEWPIN01", "its-key"))
    try:
        assert (await cp.call("Heartbeat", {}))[0] == 3  # connected, although the pin could not be saved yet
        assert controller.station("GRD-NEWPIN01")["ocppAuthKey"] == "its-key"
    finally:
        await cp.close()


async def test_frames_nested_absurdly_deep_are_dropped(server, session, caplog):
    assert ocpp._too_deep([2, "u", "Heartbeat", {}]) is False
    nested: object = "x"
    for _ in range(ocpp.MAX_FRAME_DEPTH + 5):
        nested = [nested]
    assert ocpp._too_deep(nested) is True
    assert ocpp.parse_frame(json.dumps([2, "u", "DataTransfer", {"data": nested}])) is None
    profile = {"csChargingProfiles": {"chargingSchedule": {"chargingSchedulePeriod": [{"limit": 16}]}}}
    # Real messages are nowhere near the limit.
    assert ocpp.parse_frame(json.dumps([2, "u", "SetChargingProfile", profile])) is not None

    caplog.set_level(logging.ERROR)
    cp = await RawCharger.connect(server, session, SERIAL)
    try:
        await cp.send_text(json.dumps([3, "u", {"a": nested}]))
        await cp.send_text(json.dumps([2, "v", "DataTransfer", {"vendorId": "x", "data": nested}]))
        assert (await cp.call("Heartbeat", {}))[0] == 3
        resp = await server.get(f"/local/stations/{SERIAL}/log", headers=await bearer(server))
        assert resp.status == 200
        strict_json(await resp.text())
    finally:
        await cp.close()
    _no_failures(caplog)


async def test_status_text_is_cleaned_like_every_other_field(server, session):
    controller = server.app["controller"]
    cp = await RawCharger.connect(server, session, SERIAL)
    cp.replies["GetConfiguration"] = {"configurationKey": [{"key": "Odd\udcffKey", "value": "v"}]}
    try:
        assert (await cp.call("StatusNotification", {**OK_STATUS, "status": "Odd\udcff"}))[0] == 3
        assert (await cp.call("StatusNotification", {"connectorId": 0, "status": "Odd\ud800"}))[0] == 3
        assert (await cp.call("BootNotification", {"chargePointModel": "GRD 40A"}))[0] == 3
        station = controller.station(SERIAL)
        await wait_for(lambda: station["config"], timeout=6)
        json.dumps(station, ensure_ascii=False).encode("utf-8")  # nothing left that UTF-8 cannot carry
    finally:
        await cp.close()


def test_a_charger_without_an_id_keeps_the_station_it_had(tmp_path):
    """Through the TLS front end such a charger used to be "unknown-127.0.0.1" (the front end's own
    address). Now that the real address is known it would have become a new station, without its
    mode, schedules or history."""
    from grizzle_local.main import _charge_point_id
    from grizzle_local.tls import PEERS_KEY

    class Transport:
        def get_extra_info(self, name):
            return ("127.0.0.1", 40001) if name == "peername" else None

    class Request:
        path, headers, remote, transport = "/ocpp1.6", {}, "127.0.0.1", Transport()
        app = {PEERS_KEY: {("127.0.0.1", 40001): "192.168.1.50"}}

    assert _charge_point_id(Request(), {}) == "unknown-192.168.1.50"
    assert _charge_point_id(Request(), {"unknown-127.0.0.1": {}}) == "unknown-127.0.0.1"
    assert _charge_point_id(Request(), {"unknown-127.0.0.1": {}, "unknown-192.168.1.50": {}}) == "unknown-192.168.1.50"
    assert _charge_point_id(Request()) == "unknown-192.168.1.50"


# --- gaps a reviewer found by reverting fixes and watching the suite stay green ---------------------


async def test_the_read_loop_applies_the_rate_limit():
    """The limiter was only ever tested on its own. Nothing noticed if run() stopped calling it."""
    from aiohttp import WSMsgType

    class Message:
        type, data = WSMsgType.TEXT, json.dumps([3, "nobody-asked", {}])

    class Socket:
        closed = False

        def __init__(self, frames):
            self.frames = frames

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self.frames:
                raise StopAsyncIteration
            self.frames -= 1
            return Message()

    conn = ChargePointConnection("GRD-FLOOD002", Socket(60), handler=None, rate_burst=10, rate_per_second=1000)
    started = time.monotonic()
    await conn.run()
    assert time.monotonic() - started >= 0.045  # 50 frames beyond the burst, at 1000 a second
    assert len(conn.log) == 60


def test_pruning_removes_what_is_older_than_the_limit_and_nothing_else(tmp_path):
    from datetime import UTC, datetime, timedelta

    store = Store(tmp_path / "data")

    def stamp(days: float) -> str:
        return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    ages = (120, 91, 90.01, 89.99, 89, 1, 0)
    store.add_samples([(SERIAL, 1, None, stamp(age), {"voltage_v": float(n)}) for n, age in enumerate(ages)])
    store.prune_samples(keep_days=90)
    left = [row["voltage_v"] for row in store.samples(SERIAL, "2000-01-01")]
    assert left == [3.0, 4.0, 5.0, 6.0]  # to the minute, not "the whole day of the cutoff"


def test_state_is_flushed_to_disk_before_it_replaces_the_old_file(tmp_path, monkeypatch):
    """Renamed without that, a power cut can leave an empty state.json: every station and every
    pinned Auth key forgotten."""
    import os as os_module

    store = Store(tmp_path / "data")
    order: list[str] = []
    real_fsync, real_replace = os_module.fsync, os_module.replace
    monkeypatch.setattr(os_module, "fsync", lambda fd: (order.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(os_module, "replace", lambda a, b: (order.append("replace"), real_replace(a, b))[1])
    store.state["stations"]["GRD-X"] = {"id": "GRD-X"}
    store.save()
    assert order == ["fsync", "replace"]
    assert "GRD-X" in (tmp_path / "data" / "state.json").read_text()


def test_the_first_save_after_a_crash_is_private_too(tmp_path):
    """A temporary file left by an older version is world-readable, and the save that reuses it
    used to hand that mode on to state.json."""
    import stat as stat_module

    data = tmp_path / "data"
    data.mkdir()
    (data / "state.tmp").write_text("left over from a crash")
    (data / "state.tmp").chmod(0o644)
    store = Store(data)
    store.state["tokens"]["secret-token"] = {"refresh": "r", "expires": 1e12}
    store.save()
    assert stat_module.S_IMODE((data / "state.json").stat().st_mode) == 0o600
    assert "secret-token" in (data / "state.json").read_text()


async def test_long_fields_and_many_sampled_values_are_cut_to_size(server, session):
    controller = server.app["controller"]
    long = "L" * 5000
    cp = await RawCharger.connect(server, session, SERIAL, path=f"/ocpp1.6/{SERIAL}?{'q' * 3000}")
    try:
        status = {"connectorId": 1, "status": long, "errorCode": long, "vendorErrorCode": long, "info": long}
        assert (await cp.call("StatusNotification", status))[0] == 3
        assert (await cp.call("StartTransaction", {"connectorId": 1, "idTag": long, "meterStart": 0}))[0] == 3
        many = [{"value": str(n), "measurand": "Voltage", "phase": "L1"} for n in range(500)]
        assert (await cp.call("MeterValues", {"connectorId": 1, "meterValue": [{"sampledValue": many}]}))[0] == 3
        station = controller.station(SERIAL)
        connector = station["connectors"]["1"]
        assert len(connector["status"]) == 32 and len(connector["errorCode"]) == 50
        assert len(connector["vendorErrorCode"]) == 50 and len(connector["info"]) == 255
        assert len(connector["transaction"]["idTag"]) == 64
        # Only the first MAX_SAMPLED_VALUES readings of a meter value are looked at.
        assert connector["lastMeter"]["voltage_v"] == controller_module.MAX_SAMPLED_VALUES - 1
        assert len(station["ocppHandshake"]["query"]) == 200 and len(json.dumps(station["ocppHandshake"])) < 1000
    finally:
        await cp.close()


async def test_a_charger_with_an_unset_clock_repeating_itself_is_still_recognised(tmp_path):
    controller = _controller(tmp_path)
    station = controller._ensure_station(SERIAL)
    start = {"connectorId": 1, "idTag": "t", "meterStart": 1000, "timestamp": "1970-01-01T00:10:00Z"}
    first = (await controller._on_StartTransaction(station, start))["transactionId"]
    again = (await controller._on_StartTransaction(station, start))["transactionId"]
    assert again == first and len(controller.store.sessions(SERIAL)) == 1
    later = {**start, "timestamp": "1970-01-01T05:00:00Z"}  # a different session by the charger's own clock
    assert (await controller._on_StartTransaction(station, later))["transactionId"] != first
