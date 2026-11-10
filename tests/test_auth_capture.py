"""The server records the charger's OCPP identity (serial + Auth key) for firmware_capture,
and never leaks it through the HTTP API."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from fake_charger import FakeCharger  # noqa: E402

from grizzle_local.config import Settings
from grizzle_local.controller import Controller
from grizzle_local.main import create_app
from grizzle_local.store import Store

SERIAL = "GRD-L0000TEST1"
AUTH_KEY = "s3cr3t-auth-key"  # what the fake charger presents over HTTP Basic


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
    settings = Settings(data_dir=tmp_path / "data", api_email="ha@local", api_password="pw", tick_seconds=1)
    app = create_app(settings, Store(settings.data_dir))
    async with TestServer(app) as test_server, TestClient(test_server) as client:
        yield client


@pytest.fixture
async def charger(server):
    url = f"ws://{server.host}:{server.port}/ocpp1.6/{SERIAL}"
    async with aiohttp.ClientSession() as session:
        cp = FakeCharger(url, SERIAL, connectors=2, meter_interval=0.5, auth_key=AUTH_KEY)
        await cp.connect(session)
        runner = asyncio.create_task(cp.run())
        await asyncio.wait_for(cp.booted.wait(), 10)
        yield cp
        runner.cancel()
        await cp.close()


async def _token(server):
    resp = await server.post("/client/auth/login", json={"emailOrPhone": "ha@local", "password": "pw"})
    assert resp.status == 200
    return (await resp.json())["token"]


async def test_handshake_and_auth_key_recorded(server, charger):
    controller = server.app["controller"]
    station = await wait_for(lambda: controller.station(SERIAL))

    assert station.get("ocppAuthKey") == AUTH_KEY
    handshake = station.get("ocppHandshake") or {}
    assert handshake.get("authUser") == SERIAL
    assert handshake.get("path", "").endswith(SERIAL)
    assert "ocpp1.6" in (handshake.get("protocols") or [])
    assert handshake.get("recordedAt")


async def test_auth_key_persisted_to_state(server, charger):
    controller = server.app["controller"]
    await wait_for(lambda: (controller.station(SERIAL) or {}).get("ocppAuthKey"))
    controller.store.save()  # atomic write to state.json

    saved = controller.store.state["stations"][SERIAL]
    assert saved["ocppAuthKey"] == AUTH_KEY
    assert saved["ocppHandshake"]["authUser"] == SERIAL


class _StubConn:
    def __init__(self, cp_id):
        self.id = cp_id


async def test_empty_or_missing_auth_key_does_not_wipe_captured_key(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    controller = Controller(settings, Store(settings.data_dir))
    conn = _StubConn(SERIAL)

    await controller.on_connect(conn, handshake={"authUser": SERIAL}, auth_key=AUTH_KEY)
    assert controller.station(SERIAL)["ocppAuthKey"] == AUTH_KEY

    # A later connection with an empty password (colon, no value) must NOT overwrite it.
    await controller.on_connect(conn, handshake={"authUser": SERIAL}, auth_key="")
    assert controller.station(SERIAL)["ocppAuthKey"] == AUTH_KEY

    # Nor a connection with no Basic auth at all.
    await controller.on_connect(conn, handshake={"authUser": None}, auth_key=None)
    assert controller.station(SERIAL)["ocppAuthKey"] == AUTH_KEY


async def test_auth_key_never_exposed_by_api(server, charger):
    controller = server.app["controller"]
    await wait_for(lambda: (controller.station(SERIAL) or {}).get("ocppAuthKey"))
    token = await _token(server)

    bodies = []
    for method, path in [
        ("GET", "/client/stations"),
        ("GET", f"/client/stations/{SERIAL}"),
        ("GET", f"/local/stations/{SERIAL}/log"),
        ("GET", f"/local/stations/{SERIAL}/sessions"),
    ]:
        resp = await server.request(method, path, headers={"Authorization": f"Bearer {token}"})
        assert resp.status < 400, f"{method} {path} -> {resp.status}"
        bodies.append(await resp.text())

    blob = "".join(bodies)
    assert AUTH_KEY not in blob
    assert "ocppAuthKey" not in blob
    assert "ocppHandshake" not in blob
