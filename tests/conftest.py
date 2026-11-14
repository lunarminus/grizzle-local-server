"""Suite-wide test settings and shared fixtures."""

import subprocess
from pathlib import Path

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

from grizzle_local import api

from .support import make_app


@pytest.fixture(autouse=True)
def _fast_credential_mark(monkeypatch):
    """The slow hash that marks which credentials sessions belong to is deliberately expensive
    (a tenth of a second); hundreds of tests sign in. Its cost is not what they are testing."""
    monkeypatch.setattr(api, "CREDENTIAL_ROUNDS", 1000)


@pytest.fixture(autouse=True)
def _no_proxy_for_loopback(monkeypatch):
    """Several tests talk to servers they start on 127.0.0.1 through urllib, which honours
    http_proxy. Wherever the suite runs, those requests must go to the test's own server."""
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost,::1")


@pytest.fixture
async def server(tmp_path):
    """The server with the settings of ``support.make_app``; a test module may define its own instead."""
    async with TestServer(make_app(tmp_path)) as test_server, TestClient(test_server) as client:
        yield client


@pytest.fixture
async def session():
    async with aiohttp.ClientSession() as s:
        yield s


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    """A self-signed certificate and key from scripts/make-cert.sh, one pair per test module."""
    out = tmp_path_factory.mktemp("certs")
    script = Path(__file__).resolve().parents[1] / "scripts/make-cert.sh"
    subprocess.run([str(script), str(out)], check=True, capture_output=True)
    return out / "fullchain.pem", out / "privkey.pem"
