"""OCPP-J 1.6 framing over a WebSocket, written to be tolerant.

Grizzl-E firmware is known to send a few malformed frames (for example a
GetConfiguration reply containing ``"configurationKey":]``). The standard
``ocpp`` library rejects those and the charger then drops the connection, so this
module parses frames itself, repairs what it can and drops the rest without
closing the socket.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from aiohttp import WSMsgType, web

_LOGGER = logging.getLogger(__name__)

CALL = 2
CALLRESULT = 3
CALLERROR = 4

DEFAULT_CALL_TIMEOUT = 30


def now_iso() -> str:
    """OCPP timestamps: ISO 8601, UTC, millisecond precision, trailing Z."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(UTC).microsecond // 1000:03d}Z"


class OcppError(Exception):
    """A CallError received from the charger, or a call that timed out."""

    def __init__(self, code: str, description: str = "", details: Any = None) -> None:
        super().__init__(f"{code}: {description}" if description else code)
        self.code = code
        self.description = description
        self.details = details


def repair_json(text: str) -> str:
    """Fix the malformed shapes Grizzl-E firmware is known to emit."""
    # '"configurationKey":]'  ->  '"configurationKey":[]'
    text = re.sub(r":\s*\]", ":[]", text)
    # trailing commas before a closing bracket/brace
    text = re.sub(r",\s*([\]}])", r"\1", text)
    return text


def parse_frame(text: str) -> list[Any] | None:
    """Parse an OCPP-J frame, repairing it if needed. Returns None if hopeless."""
    for candidate in (text, repair_json(text)):
        try:
            frame = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(frame, list) and len(frame) >= 3 and frame[0] in (CALL, CALLRESULT, CALLERROR):
            return frame
    return None


_UID_RE = re.compile(r'^\s*\[\s*([234])\s*,\s*"([^"]+)"')


def peek_frame(text: str) -> tuple[int, str] | None:
    """Message type and unique id of a frame that didn't parse, if they are legible."""
    match = _UID_RE.match(text)
    return (int(match.group(1)), match.group(2)) if match else None


Handler = Callable[["ChargePointConnection", str, dict[str, Any]], Awaitable[dict[str, Any]]]


class ChargePointConnection:
    """One WebSocket from one charge point."""

    def __init__(
        self,
        cp_id: str,
        ws: web.WebSocketResponse,
        handler: Handler,
        *,
        log_size: int = 200,
        call_timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> None:
        self.id = cp_id
        self.ws = ws
        self._handler = handler
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._send_lock = asyncio.Lock()
        self._call_timeout = call_timeout
        self.connected_at = datetime.now(UTC)
        self.last_message_at = self.connected_at
        self.log: deque[dict[str, Any]] = deque(maxlen=log_size)  # recent frames, for debugging

    # --- outbound -----------------------------------------------------------

    async def call(
        self, action: str, payload: dict[str, Any] | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        """Send a Call and wait for its CallResult."""
        uid = uuid.uuid4().hex[:12]
        frame = [CALL, uid, action, payload or {}]
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[uid] = fut
        try:
            await self._send(frame, f"-> {action}")
            return await asyncio.wait_for(fut, timeout or self._call_timeout)
        except TimeoutError:
            raise OcppError("Timeout", f"{action} not answered by {self.id}") from None
        finally:
            self._pending.pop(uid, None)

    async def _send(self, frame: list[Any], label: str) -> None:
        text = json.dumps(frame, separators=(",", ":"))
        self._record("out", label, frame)
        async with self._send_lock:
            await self.ws.send_str(text)

    # --- inbound ------------------------------------------------------------

    async def run(self) -> None:
        """Pump messages until the socket closes."""
        async for msg in self.ws:
            if msg.type == WSMsgType.TEXT:
                self.last_message_at = datetime.now(UTC)
                await self._handle_text(msg.data)
            elif msg.type == WSMsgType.BINARY:
                _LOGGER.debug("%s: ignoring binary frame", self.id)
            elif msg.type == WSMsgType.ERROR:
                _LOGGER.warning("%s: websocket error %s", self.id, self.ws.exception())
        self._fail_pending("Disconnected")

    def _fail_pending(self, reason: str) -> None:
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(OcppError("Disconnected", reason))
        self._pending.clear()

    async def _handle_text(self, text: str) -> None:
        frame = parse_frame(text)
        if frame is None:
            self._record("in", "unparseable", text[:500])
            _LOGGER.warning("%s: dropping unparseable frame: %s", self.id, text[:200])
            peek = peek_frame(text)
            if peek and peek[0] in (CALLRESULT, CALLERROR):
                # Resolve the waiting call with nothing rather than letting it time out.
                fut = self._pending.get(peek[1])
                if fut and not fut.done():
                    fut.set_result({})
            return

        kind, uid = frame[0], frame[1]
        if kind == CALL:
            if len(frame) < 4 or not isinstance(frame[2], str):
                _LOGGER.warning("%s: malformed Call %s", self.id, text[:200])
                return
            action, payload = frame[2], frame[3] if isinstance(frame[3], dict) else {}
            self._record("in", f"<- {action}", frame)
            await self._dispatch(uid, action, payload)
        elif kind == CALLRESULT:
            self._record("in", "<- result", frame)
            fut = self._pending.get(uid)
            if fut and not fut.done():
                fut.set_result(frame[2] if isinstance(frame[2], dict) else {})
            else:
                _LOGGER.debug("%s: result for unknown call %s", self.id, uid)
        elif kind == CALLERROR:
            self._record("in", "<- error", frame)
            fut = self._pending.get(uid)
            if fut and not fut.done():
                code = frame[2] if len(frame) > 2 else "GenericError"
                desc = frame[3] if len(frame) > 3 else ""
                details = frame[4] if len(frame) > 4 else None
                fut.set_exception(OcppError(str(code), str(desc), details))

    async def _dispatch(self, uid: str, action: str, payload: dict[str, Any]) -> None:
        try:
            result = await self._handler(self, action, payload)
        except NotImplementedError:
            await self._send([CALLERROR, uid, "NotImplemented", f"{action} is not supported", {}], f"-> error {action}")
            return
        except Exception:  # noqa: BLE001 - never let a handler bug kill the socket
            _LOGGER.exception("%s: handler for %s failed", self.id, action)
            await self._send([CALLERROR, uid, "InternalError", "handler failed", {}], f"-> error {action}")
            return
        await self._send([CALLRESULT, uid, result if result is not None else {}], f"-> result {action}")

    def _record(self, direction: str, label: str, data: Any) -> None:
        self.log.append({"at": now_iso(), "dir": direction, "label": label, "data": data})

    async def close(self) -> None:
        if not self.ws.closed:
            await self.ws.close()
        self._fail_pending("Closed by server")
