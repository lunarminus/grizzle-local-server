"""OCPP-J 1.6 framing over a WebSocket, written to be tolerant.

Grizzl-E firmware is known to send a few malformed frames (for example a
GetConfiguration reply containing ``"configurationKey":]``). The standard
``ocpp`` library rejects those and the charger then drops the connection, so this
module parses frames itself, repairs what it can and drops the rest without
closing the socket.

Tolerant of a sloppy charger is not the same as trusting it: anyone on the network can
connect as a charger the server has never seen, so every frame is also bounded in size,
rate and what it may leave behind in memory.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
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

# OCPP frames are a few hundred bytes; the largest, a GetConfiguration reply, a few KiB.
MAX_FRAME_BYTES = 256 * 1024
# A frame bigger than this is noted in the debug log but not kept, and what is kept is kept as
# text: parsed, a few kilobytes of tiny JSON containers take a hundred times their size in memory,
# and 200 logged frames per connection would pin tens of megabytes.
LOG_FRAME_BYTES = 8 * 1024
# A charger sends a frame every few seconds. Past the burst, reading slows to this rate, which
# pushes back on a peer that floods us (every frame may cost a database write).
RATE_BURST = 120
RATE_PER_SECOND = 10.0
# OCPP messages nest five or six levels. Anything much deeper is not OCPP, and structures nested
# hundreds deep are exactly what makes a later json.dumps (of the frame log, say) hit the recursion limit.
MAX_FRAME_DEPTH = 32

# Control characters, the Unicode line separators, and lone surrogates (which a UTF-8 log can't encode).
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]")


def now_iso() -> str:
    """OCPP timestamps: ISO 8601, UTC, millisecond precision, trailing Z."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def printable(value: Any, limit: int = 200) -> str:
    """An untrusted value as one bounded line: safe to log, and unable to forge a second log line."""
    text = value if isinstance(value, str) else repr(value)
    if len(text) > limit:
        text = f"{text[:limit]}...(+{len(text) - limit} more)"
    return _CONTROL_RE.sub(lambda m: m.group().encode("unicode_escape").decode("ascii"), text)


class OcppError(Exception):
    """A CallError received from the charger, or a call that timed out."""

    def __init__(self, code: str, description: str = "", details: Any = None) -> None:
        # Both come from the charger when it answers with a CallError, and end up in logs.
        code, description = printable(code, 64), printable(description, 300)
        super().__init__(f"{code}: {description}" if description else code)
        self.code = code
        self.description = description
        self.details = details


class CallRejected(OcppError):
    """Raised by a handler to refuse a charger's Call with a specific CallError code."""


def repair_json(text: str) -> str:
    """Fix the malformed shapes Grizzl-E firmware is known to emit."""
    # '"configurationKey":]'  ->  '"configurationKey":[]'
    text = re.sub(r":\s*\]", ":[]", text)
    # trailing commas before a closing bracket/brace
    text = re.sub(r",\s*([\]}])", r"\1", text)
    return text


def _too_deep(value: Any, limit: int = MAX_FRAME_DEPTH) -> bool:
    """Is this JSON value nested more than ``limit`` levels? (Iterative: it must not itself recurse.)"""
    level = [value]
    for _ in range(limit):
        level = [
            child
            for item in level
            if isinstance(item, (list, dict))
            for child in (item.values() if isinstance(item, dict) else item)
        ]
        if not level:
            return False
    return any(isinstance(item, (list, dict)) for item in level)


def parse_frame(text: str) -> list[Any] | None:
    """Parse an OCPP-J frame, repairing it if needed. Returns None if hopeless."""
    for candidate in (text, repair_json(text)):
        try:
            frame = json.loads(candidate)
        except (ValueError, RecursionError):  # RecursionError: thousands of nested brackets
            continue
        if isinstance(frame, list) and len(frame) >= 3 and frame[0] in (CALL, CALLRESULT, CALLERROR):
            return None if _too_deep(frame) else frame
    return None


_UID_RE = re.compile(r'^\s*\[\s*([234])\s*,\s*"([^"]+)"')


def peek_frame(text: str) -> tuple[int, str] | None:
    """Message type and unique id of a frame that didn't parse, if they are legible."""
    match = _UID_RE.match(text)
    return (int(match.group(1)), match.group(2)) if match else None


def _echoable(uid: Any) -> bool:
    """Can this unique id be sent back in a reply? (The spec says string; a number does no harm.)"""
    return isinstance(uid, str) or (isinstance(uid, int) and not isinstance(uid, bool))


Handler = Callable[["ChargePointConnection", str, dict[str, Any]], Awaitable[dict[str, Any]]]


class ChargePointConnection:
    """One WebSocket from one charge point."""

    def __init__(
        self,
        cp_id: str,
        ws: web.WebSocketResponse,
        handler: Handler,
        *,
        rate_burst: int = RATE_BURST,
        rate_per_second: float = RATE_PER_SECOND,
    ) -> None:
        self.id = cp_id
        self.ws = ws
        self._handler = handler
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._send_lock = asyncio.Lock()
        self._rate_burst = float(rate_burst)
        self._rate = float(rate_per_second)
        self._allowance = self._rate_burst
        self._allowance_at = time.monotonic()
        self.log: deque[dict[str, Any]] = deque(maxlen=200)  # recent frames, for debugging

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
            # The send is inside the deadline too: a peer that stops reading must not be able to
            # hold a caller (and the send lock) for as long as it likes.
            async with asyncio.timeout(timeout or DEFAULT_CALL_TIMEOUT):
                await self._send(frame, f"-> {action}")
                return await fut
        except TimeoutError:
            raise OcppError("Timeout", f"{action} not answered by {self.id}") from None
        except ConnectionError as err:
            raise OcppError("Disconnected", f"{action} could not be sent to {self.id}: {err}") from None
        finally:
            self._pending.pop(uid, None)

    async def _send(self, frame: list[Any], label: str) -> None:
        text = json.dumps(frame, separators=(",", ":"))
        self._record("out", label, text)
        async with self._send_lock:
            await self.ws.send_str(text)

    # --- inbound ------------------------------------------------------------

    async def run(self) -> None:
        """Pump messages until the socket closes."""
        try:
            async for msg in self.ws:
                if msg.type == WSMsgType.TEXT:
                    await self._throttle()
                    try:
                        await self._handle_text(msg.data)
                    except ConnectionError:
                        break  # the reply couldn't be sent: the socket is gone
                    except Exception:  # noqa: BLE001 - one bad frame must not take the connection down
                        _LOGGER.exception("%s: handling a frame failed", self.id)
                elif msg.type == WSMsgType.BINARY:
                    _LOGGER.debug("%s: ignoring binary frame", self.id)
                elif msg.type == WSMsgType.ERROR:
                    _LOGGER.warning("%s: websocket error %s", self.id, printable(self.ws.exception()))
        finally:
            self._fail_pending("Disconnected")

    async def _throttle(self) -> None:
        """Token bucket: free up to the burst, then at most ``rate`` frames a second."""
        now = time.monotonic()
        self._allowance = min(self._rate_burst, self._allowance + (now - self._allowance_at) * self._rate)
        self._allowance_at = now
        self._allowance -= 1
        if self._allowance < 0:
            await asyncio.sleep(-self._allowance / self._rate)

    def _fail_pending(self, reason: str) -> None:
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(OcppError("Disconnected", reason))
        self._pending.clear()

    async def _handle_text(self, text: str) -> None:
        frame = parse_frame(text)
        if frame is None:
            self._record("in", "unparseable", text[:500], parsed=False)
            _LOGGER.warning("%s: dropping unparseable frame: %s", self.id, printable(text, 200))
            peek = peek_frame(text)
            if peek and peek[0] in (CALLRESULT, CALLERROR):
                # Resolve the waiting call with nothing rather than letting it time out.
                fut = self._pending.get(peek[1])
                if fut and not fut.done():
                    fut.set_result({})
            return

        kind, uid = frame[0], frame[1]
        if kind == CALL:
            if len(frame) < 4 or not isinstance(frame[2], str) or not _echoable(uid):
                _LOGGER.warning("%s: malformed Call %s", self.id, printable(text, 200))
                return
            action, payload = frame[2], frame[3] if isinstance(frame[3], dict) else {}
            self._record("in", f"<- {action[:64]}", text)
            await self._dispatch(uid, action, payload)
            return
        # Replies carry an id we made up ourselves, always a string; anything else matches nothing.
        fut = self._pending.get(uid) if isinstance(uid, str) else None
        if kind == CALLRESULT:
            self._record("in", "<- result", text)
            if fut and not fut.done():
                fut.set_result(frame[2] if isinstance(frame[2], dict) else {})
            else:
                _LOGGER.debug("%s: result for unknown call %s", self.id, printable(uid, 64))
        elif kind == CALLERROR:
            self._record("in", "<- error", text)
            if fut and not fut.done():
                code = frame[2]
                desc = frame[3] if len(frame) > 3 else ""
                details = frame[4] if len(frame) > 4 else None
                fut.set_exception(OcppError(str(code), str(desc), details))

    async def _dispatch(self, uid: str | int, action: str, payload: dict[str, Any]) -> None:
        name = printable(action, 64)
        try:
            result = await self._handler(self, action, payload)
        except NotImplementedError:
            await self._send([CALLERROR, uid, "NotImplemented", f"{name} is not supported", {}], f"-> error {name}")
            return
        except CallRejected as err:
            _LOGGER.warning("%s: refused %s: %s", self.id, name, err)
            await self._send([CALLERROR, uid, err.code, err.description, {}], f"-> error {name}")
            return
        except Exception:  # noqa: BLE001 - never let a handler bug kill the socket
            _LOGGER.exception("%s: handler for %s failed", self.id, name)
            await self._send([CALLERROR, uid, "InternalError", "handler failed", {}], f"-> error {name}")
            return
        await self._send([CALLRESULT, uid, result if result is not None else {}], f"-> result {name}")

    def _record(self, direction: str, label: str, text: str, parsed: bool = True) -> None:
        """Note a frame in the debug log, as text. ``parsed``: it is JSON, to be decoded when the log is read."""
        if len(text) > LOG_FRAME_BYTES:
            text, parsed = json.dumps({"omitted": "frame too large to keep in the log", "bytes": len(text)}), True
        self.log.append({"at": now_iso(), "dir": direction, "label": label, "text": text, "json": parsed})

    def frames(self) -> list[dict[str, Any]]:
        """The debug log for the API: each entry with its frame decoded (or as text, if it never was JSON)."""
        entries = []
        for entry in list(self.log):
            data: Any = entry["text"]
            if entry["json"]:
                try:
                    data = parse_frame(data) or json.loads(data)
                except (ValueError, RecursionError):
                    pass
            entries.append({"at": entry["at"], "dir": entry["dir"], "label": entry["label"], "data": data})
        return entries

    async def close(self) -> None:
        if not self.ws.closed:
            await self.ws.close()
        self._fail_pending("Closed by server")
