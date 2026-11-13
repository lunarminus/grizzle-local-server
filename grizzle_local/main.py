"""Entry point: one aiohttp application serving both OCPP WebSockets and the REST API."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import signal
import sys
from pathlib import Path

from aiohttp import web

from . import __version__
from .api import Auth, add_routes, auth_middleware
from .config import Settings
from .controller import Controller
from .ocpp import CP_ID_RE, MAX_FRAME_BYTES, ChargePointConnection, now_iso, printable
from .store import Store
from .tls import PEERS_KEY, client_ip, start_tls_frontend

_LOGGER = logging.getLogger("grizzle_local")

WEB_DIR = Path(__file__).parent / "web"
MAX_LOG_MESSAGE = 4000
_REFUSALS = {401: web.HTTPUnauthorized, 409: web.HTTPConflict, 503: web.HTTPServiceUnavailable}


def page_headers(settings: Settings) -> dict[str, str]:
    """Headers for the web page. It is fully self-contained (inline CSS/JS, no external requests)."""
    return {
        "Content-Security-Policy": (
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; "
            f"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors {settings.frame_ancestors}"
        ),
        "Cache-Control": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }


class SingleLineFormatter(logging.Formatter):
    """Escapes control characters in every message and bounds its length.

    Much of what is logged comes off the network (serials, OCPP actions, statuses). Without this
    a newline in such a value starts what looks like a new, genuine log line.
    """

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802 - logging's name
        record.message = printable(record.message, MAX_LOG_MESSAGE)
        return super().formatMessage(record)


def _charge_point_id(request: web.Request) -> str:
    """The charger's identity: last path segment, else the Basic auth user, else a placeholder."""
    tail = request.path.rstrip("/").rsplit("/", 1)[-1]
    if tail and tail not in ("ocpp1.6", "ocpp", "ocpp16"):
        return tail
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("basic "):
        try:
            user = base64.b64decode(header[6:]).decode(errors="replace").split(":", 1)[0]
            if user:
                return user
        except ValueError:
            pass
    return f"unknown-{client_ip(request)}"


def _basic_credentials(request: web.Request) -> tuple[str | None, str | None]:
    """The (user, password) from an HTTP Basic Authorization header, or (None, None)."""
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("basic "):
        return None, None
    try:
        decoded = base64.b64decode(header[6:]).decode(errors="replace")
    except ValueError:
        return None, None
    user, sep, password = decoded.partition(":")
    return user, (password if sep else None)


def _basic_password(request: web.Request) -> str | None:
    return _basic_credentials(request)[1]


def _clip(value: str | None, limit: int = 200) -> str | None:
    return value[:limit] if isinstance(value, str) else None


async def websocket_handler(request: web.Request) -> web.StreamResponse:
    controller: Controller = request.app["controller"]
    if request.headers.get("Upgrade", "").lower() != "websocket":
        if request.path in ("/", "/index.html"):
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            return web.Response(text=html, content_type="text/html", headers=page_headers(request.app["settings"]))
        raise web.HTTPNotFound()
    remote = client_ip(request)
    # Browsers always send Origin on a WebSocket handshake; the charger's firmware never does
    # (its handshake is GET/Upgrade/Sec-WebSocket-*/Authorization only). Refusing it stops any
    # web page the owner visits from connecting to the LAN server as a charger.
    if "Origin" in request.headers:
        _LOGGER.warning(
            "rejected websocket from %s: browser Origin %r (chargers don't send one)",
            remote,
            request.headers["Origin"],
        )
        raise web.HTTPForbidden()
    cp_id = _charge_point_id(request)
    if not CP_ID_RE.fullmatch(cp_id):
        _LOGGER.warning("rejected websocket from %s: invalid charge point id %r", remote, cp_id[:100])
        raise web.HTTPBadRequest()
    auth_user, auth_key = _basic_credentials(request)
    # Check and install under one lock, so a concurrent handshake can't slip in between.
    async with controller.admission(cp_id):
        refusal = await controller.connection_refusal(cp_id, auth_key)
        if refusal is not None:
            status, reason = refusal
            _LOGGER.warning("%s: rejected connection from %s: %s", cp_id, remote, reason)
            raise _REFUSALS.get(status, web.HTTPForbidden)()
        offered = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
        ws = web.WebSocketResponse(
            protocols=("ocpp1.6",) if "ocpp1.6" in offered else (),
            heartbeat=120,
            autoping=True,
            max_msg_size=MAX_FRAME_BYTES,  # OCPP frames are tiny; aiohttp's default would take 4 MiB each
        )
        await ws.prepare(request)
        _LOGGER.info("%s: websocket from %s path=%s subprotocol=%s", cp_id, remote, request.path, ws.ws_protocol)
        # Record how the charger connected, so its cloud identity (serial + Auth key) can be
        # reused by tools/firmware_capture.py. This is never exposed through the HTTP API.
        handshake = {
            "path": _clip(request.path),
            "query": _clip(request.query_string) or None,
            "authUser": _clip(auth_user, 100),
            "protocols": [p[:50] for p in offered[:8]],
            "userAgent": _clip(request.headers.get("User-Agent")),
            "remote": remote,
            "recordedAt": now_iso(),
        }
        conn = ChargePointConnection(cp_id, ws, controller.handle)
        await controller.on_connect(conn, handshake=handshake, auth_key=auth_key)
    try:
        await conn.run()
    finally:
        await controller.on_disconnect(conn)
    return ws


def create_app(settings: Settings, store: Store | None = None) -> web.Application:
    store = store or Store(settings.data_dir)
    controller = Controller(settings, store)
    app = web.Application(middlewares=[auth_middleware])
    app["settings"] = settings
    app["controller"] = controller
    app["auth"] = Auth(controller)
    app[PEERS_KEY] = {}  # filled in by the TLS frontend: its own socket's (address, port) -> the real client
    add_routes(app)
    app.router.add_get("/{tail:.*}", websocket_handler)

    async def start_background(app: web.Application) -> None:
        app["controller_task"] = asyncio.ensure_future(controller.run())

    async def close_connections(app: web.Application) -> None:
        # on_shutdown, not on_cleanup: aiohttp waits for open connections to finish *between* the
        # two, and a charger's WebSocket never finishes by itself. Closing them only in on_cleanup
        # meant waiting out that timeout first, by which time Docker had killed the process and
        # the final save below had never run.
        await controller.stop()

    async def stop_background(app: web.Application) -> None:
        app["controller_task"].cancel()
        controller.save()  # whatever the last requests changed after the connections were closed
        store.close()

    app.on_startup.append(start_background)
    app.on_shutdown.append(close_connections)
    app.on_cleanup.append(stop_background)
    return app


async def serve(settings: Settings) -> None:
    app = create_app(settings)
    # shutdown_timeout: how long a request still in flight gets at exit (Docker waits 10 s in all).
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=5.0)
    await runner.setup()
    await web.TCPSite(runner, settings.host, settings.port).start()
    tls_server = None
    if settings.tls_enabled:
        tls_server = await start_tls_frontend(
            settings.host, settings.tls_port, settings.tls_cert, settings.tls_key, settings.port, app[PEERS_KEY]
        )  # it reaches the plain listener on loopback, or on GRIZZLE_HOST if that is a specific address
    _LOGGER.info(
        "grizzle-local %s listening on %s:%s%s",
        __version__,
        settings.host,
        settings.port,
        f" and wss:// on {settings.tls_port}" if tls_server else " (no TLS: certificate not found)",
    )
    for warning in settings.security_warnings():
        _LOGGER.warning("SECURITY: %s", warning)
    # docker stop sends SIGTERM; without a handler the process dies before the shutdown save.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        await shutdown(runner, tls_server)


async def shutdown(runner: web.AppRunner, tls_server: asyncio.Server | None) -> None:
    """Stop listening, save, and close every connection, in an order that can't wait on itself.

    ``Server.wait_closed()`` waits for the frontend's live connections, and those only end when the
    application closes its side. So the application goes first: waiting on the frontend first would
    hang with a charger connected over TLS, until Docker gives up and kills us before the save.
    """
    if tls_server:
        tls_server.close()  # no new connections; the ones in flight are closed by the cleanup below
    await runner.cleanup()
    if tls_server:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(tls_server.wait_closed(), 5)


def main(argv: list[str] | None = None) -> None:
    settings = Settings()
    handler = logging.StreamHandler()
    handler.setFormatter(SingleLineFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO), handlers=[handler])
    try:
        asyncio.run(serve(settings))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main(sys.argv[1:])
