"""Shared helpers for the hardening tests.

``FakeCharger`` behaves like a real Grizzl-E. These tests need the opposite: a peer that sends
exactly what a test tells it to, however wrong, and reports what came back.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import aiohttp
from aiohttp.test_utils import TestClient

from grizzle_local.config import Settings
from grizzle_local.main import create_app
from grizzle_local.store import Store

EMAIL = "ha@local"
PASSWORD = "correct horse battery"


def make_app(tmp_path, **overrides):
    values = {"data_dir": tmp_path / "data", "api_email": EMAIL, "api_password": PASSWORD, "tick_seconds": 1}
    values.update(overrides)
    settings = Settings(**values)
    return create_app(settings, Store(settings.data_dir))


async def login(client: TestClient, email: str = EMAIL, password: str = PASSWORD) -> dict[str, Any]:
    resp = await client.post("/client/auth/login", json={"emailOrPhone": email, "password": password})
    assert resp.status == 200, await resp.text()
    return await resp.json()


async def bearer(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {(await login(client))['token']}"}


def strict_json(text: str) -> Any:
    """Parse the way a browser does: NaN and Infinity are syntax errors, not numbers."""

    def refuse(constant: str) -> Any:
        raise AssertionError(f"response is not valid JSON: it contains {constant}")

    return json.loads(text, parse_constant=refuse)


async def wait_for(predicate, timeout: float = 10.0, step: float = 0.05):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        result = predicate()
        if result:
            return result
        await asyncio.sleep(step)
    raise AssertionError("condition not met in time")


class RawCharger:
    """A bare OCPP-J client. By default it answers the server's Calls with ``{"status": "Accepted"}``."""

    def __init__(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        self.ws = ws
        self.received: list[tuple[str, dict[str, Any]]] = []  # every Call the server sent us
        self.answer = True  # False: read the server's Calls and never reply (an unresponsive charger)
        self.replies: dict[str, dict[str, Any]] = {}  # action -> payload to answer with
        self.close_code: int | None = None
        self._pending: dict[Any, asyncio.Future[list[Any]]] = {}
        self._count = 0
        self._reader = asyncio.create_task(self._read())

    @classmethod
    async def connect(
        cls,
        server: TestClient,
        session: aiohttp.ClientSession,
        serial: str,
        auth: tuple[str, str] | None = None,
        path: str | None = None,
    ) -> RawCharger:
        headers = {"Authorization": aiohttp.BasicAuth(*auth).encode()} if auth is not None else {}
        url = f"ws://{server.host}:{server.port}{path or f'/ocpp1.6/{serial}'}"
        return cls(await session.ws_connect(url, protocols=("ocpp1.6",), headers=headers))

    async def _read(self) -> None:
        async for msg in self.ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            frame = json.loads(msg.data)
            if frame[0] == 2:
                self.received.append((frame[2], frame[3]))
                if self.answer:
                    reply = self.replies.get(frame[2], {"status": "Accepted"})
                    await self.ws.send_str(json.dumps([3, frame[1], reply]))
            elif isinstance(frame[1], (str, int)):
                waiter = self._pending.pop(frame[1], None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(frame)
        self.close_code = self.ws.close_code

    async def call(self, action: Any, payload: Any, timeout: float = 5.0, uid: Any = None) -> list[Any]:
        """Send a Call; returns the whole reply frame, ``[3, uid, payload]`` or ``[4, uid, code, description, {}]``."""
        self._count += 1
        uid = f"t{self._count}" if uid is None else uid
        waiter: asyncio.Future[list[Any]] = asyncio.get_running_loop().create_future()
        self._pending[uid] = waiter
        await self.ws.send_str(json.dumps([2, uid, action, payload]))
        return await asyncio.wait_for(waiter, timeout)

    async def send_text(self, text: str) -> None:
        await self.ws.send_str(text)

    def calls(self, action: str) -> list[dict[str, Any]]:
        return [payload for name, payload in self.received if name == action]

    async def close(self) -> None:
        self._reader.cancel()
        await self.ws.close()
