"""The /commercial/ext-ocpp-check endpoint that keeps third-party OCPP unlocked.

The real firmware (reverse engineered) GETs this path and compares the body to
lowercase-hex MD5("<serial>;isUnlocked=true"); on a match it sets its isUnlocked flag.
"""

from __future__ import annotations

import hashlib

import pytest
from aiohttp.test_utils import TestClient, TestServer

from grizzle_local.config import Settings
from grizzle_local.main import create_app
from grizzle_local.store import Store

SERIAL = "GRD-L0000430161"


def expected(serial: str) -> str:
    return hashlib.md5(f"{serial};isUnlocked=true".encode(), usedforsecurity=False).hexdigest()


@pytest.fixture
async def client(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    app = create_app(settings, Store(settings.data_dir))
    async with TestServer(app) as server, TestClient(server) as c:
        yield c


async def test_unlock_returns_firmware_expected_md5(client):
    resp = await client.get(f"/commercial/ext-ocpp-check/{SERIAL}")
    assert resp.status == 200
    body = await resp.text()
    # exactly the 32-char lowercase hex, no trailing newline (firmware does a strcmp)
    assert body == expected(SERIAL)
    assert len(body) == 32 and body == body.lower() and "\n" not in body


async def test_unlock_is_public_no_auth(client):
    # no Authorization header, must not 401 (charger sends none)
    resp = await client.get(f"/commercial/ext-ocpp-check/{SERIAL}")
    assert resp.status == 200


async def test_unlock_per_serial(client):
    other = "GRD-L0000999999"
    resp = await client.get(f"/commercial/ext-ocpp-check/{other}")
    assert (await resp.text()) == expected(other) != expected(SERIAL)


async def test_unlock_can_be_disabled(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", ocpp_unlock=False)
    app = create_app(settings, Store(settings.data_dir))
    async with TestServer(app) as server, TestClient(server) as c:
        resp = await c.get(f"/commercial/ext-ocpp-check/{SERIAL}")
        assert resp.status == 404
