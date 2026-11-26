"""The server records the charger's OCPP identity (serial + Auth key) for firmware_capture,
and never leaks it through the HTTP API."""

from __future__ import annotations

import asyncio

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer
from fake_charger import FakeCharger

from .support import login, make_app, make_controller, wait_for

SERIAL = "GRD-L0000TEST1"
AUTH_KEY = "s3cr3t-auth-key"  # what the fake charger presents over HTTP Basic


@pytest.fixture
async def server(tmp_path):
    async with TestServer(make_app(tmp_path, api_password="pw")) as test_server, TestClient(test_server) as client:
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


async def test_handshake_and_auth_key_recorded(server, charger):
    controller = server.app["controller"]
    station = await wait_for(lambda: controller.station(SERIAL))

    assert station.get("ocppAuthKey") == AUTH_KEY
    handshake = station.get("ocppHandshake") or {}
    assert handshake.get("authUser") == SERIAL
    assert handshake.get("path", "").endswith(SERIAL)
    assert "ocpp1.6" in (handshake.get("protocols") or [])
    assert handshake.get("recordedAt")


class _StubConn:
    def __init__(self, cp_id):
        self.id = cp_id


async def test_empty_or_missing_auth_key_does_not_wipe_captured_key(tmp_path):
    controller = make_controller(tmp_path)
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
    token = (await login(server, password="pw"))["token"]

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
