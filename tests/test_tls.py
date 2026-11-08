"""The TLS frontend: self-signed cert, handshake logging, and pass-through to the plain port."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import subprocess
import sys
from pathlib import Path

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from fake_charger import FakeCharger  # noqa: E402

from grizzle_local.config import Settings
from grizzle_local.main import create_app
from grizzle_local.store import Store
from grizzle_local.tls import start_tls_frontend

SERIAL = "GRD-L0000TLS01"
ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    out = tmp_path_factory.mktemp("certs")
    subprocess.run([str(ROOT / "scripts/make-cert.sh"), str(out)], check=True, capture_output=True)
    return out / "fullchain.pem", out / "privkey.pem"


@pytest.fixture
async def stack(tmp_path, certs):
    settings = Settings(data_dir=tmp_path / "data", api_email="a@b", api_password="x", tick_seconds=1)
    app = create_app(settings, Store(settings.data_dir))
    async with TestServer(app) as server, TestClient(server) as client:
        tls_port = free_port()
        frontend = await start_tls_frontend("127.0.0.1", tls_port, str(certs[0]), str(certs[1]), server.port)
        try:
            yield client, tls_port
        finally:
            frontend.close()
            await frontend.wait_closed()


async def test_charger_over_wss_reaches_the_server(stack, caplog):
    client, tls_port = stack
    caplog.set_level(logging.INFO, logger="grizzle_local.tls")
    async with aiohttp.ClientSession() as session:
        cp = FakeCharger(f"wss://127.0.0.1:{tls_port}/ocpp1.6/{SERIAL}", SERIAL, connectors=1, insecure=True)
        await cp.connect(session)
        runner = asyncio.create_task(cp.run())
        await asyncio.wait_for(cp.booted.wait(), 10)
        resp = await client.post("/client/auth/login", json={"emailOrPhone": "a@b", "password": "x"})
        token = (await resp.json())["token"]
        resp = await client.get("/client/stations", headers={"Authorization": f"Bearer {token}"})
        station = (await resp.json())["stations"][0]
        assert station["serialNumber"] == SERIAL and station["online"] is True
        runner.cancel()
        await cp.close()
    assert any("handshake with 127.0.0.1" in r.message and "OK" in r.message for r in caplog.records)


async def test_rejected_certificate_is_logged(stack, caplog):
    _, tls_port = stack
    caplog.set_level(logging.INFO, logger="grizzle_local.tls")
    ctx = ssl.create_default_context()  # verifies, like a careful device would

    def connect() -> str:
        try:
            with (
                socket.create_connection(("127.0.0.1", tls_port), timeout=5) as sock,
                ctx.wrap_socket(sock, server_hostname="ocpp.unitedchargers.com"),
            ):
                return "connected"
        except ssl.SSLError as err:
            return err.reason or "error"

    assert await asyncio.get_running_loop().run_in_executor(None, connect) == "CERTIFICATE_VERIFY_FAILED"
    await asyncio.sleep(0.2)
    assert any("REJECTED OUR CERTIFICATE" in r.message for r in caplog.records), [r.message for r in caplog.records]
