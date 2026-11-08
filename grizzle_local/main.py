"""Entry point: one aiohttp application serving both OCPP WebSockets and the REST API."""

from __future__ import annotations

import asyncio
import base64
import logging
import sys

from aiohttp import web

from . import __version__
from .api import Auth, add_routes, auth_middleware
from .config import Settings
from .controller import Controller
from .ocpp import ChargePointConnection
from .store import Store
from .tls import start_tls_frontend

_LOGGER = logging.getLogger("grizzle_local")

INDEX = """<!doctype html><title>Grizzl-E local server</title>
<h1>Grizzl-E local server</h1>
<p>OCPP 1.6-J endpoint: <code>wss://ocpp.unitedchargers.com/ocpp1.6</code>, reached through a DNS override
of that name to this host. Any path works; plain <code>ws://</code> on port {port} is accepted too.</p>
<p>REST API for the Home Assistant integration: <code>http://&lt;this host&gt;:{port}</code></p>
<p>Connected chargers: {stations}</p>
<p><a href="/health">health</a></p>
"""


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
    return f"unknown-{request.remote}"


def _basic_password(request: web.Request) -> str | None:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:]).decode(errors="replace")
    except ValueError:
        return None
    return decoded.split(":", 1)[1] if ":" in decoded else ""


async def websocket_handler(request: web.Request) -> web.StreamResponse:
    controller: Controller = request.app["controller"]
    settings: Settings = request.app["settings"]
    if request.headers.get("Upgrade", "").lower() != "websocket":
        if request.path == "/":
            html = INDEX.format(port=settings.port, stations=", ".join(controller.stations) or "none yet")
            return web.Response(text=html, content_type="text/html")
        raise web.HTTPNotFound()
    cp_id = _charge_point_id(request)
    if settings.ocpp_password is not None and _basic_password(request) != settings.ocpp_password:
        _LOGGER.warning("%s: rejected, wrong OCPP password (from %s)", cp_id, request.remote)
        raise web.HTTPUnauthorized()
    offered = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
    ws = web.WebSocketResponse(protocols=("ocpp1.6",) if "ocpp1.6" in offered else (), heartbeat=120, autoping=True)
    await ws.prepare(request)
    _LOGGER.info("%s: websocket from %s path=%s subprotocol=%s", cp_id, request.remote, request.path, ws.ws_protocol)
    conn = ChargePointConnection(cp_id, ws, controller.handle)
    await controller.on_connect(conn)
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
    add_routes(app)
    app.router.add_get("/{tail:.*}", websocket_handler)

    async def start_background(app: web.Application) -> None:
        app["controller_task"] = asyncio.ensure_future(controller.run())

    async def stop_background(app: web.Application) -> None:
        await controller.stop()
        app["controller_task"].cancel()
        store.close()

    app.on_startup.append(start_background)
    app.on_cleanup.append(stop_background)
    return app


async def serve(settings: Settings) -> None:
    app = create_app(settings)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, settings.host, settings.port).start()
    tls_server = None
    if settings.tls_enabled:
        tls_server = await start_tls_frontend(
            settings.host, settings.tls_port, settings.tls_cert, settings.tls_key, settings.port
        )
    _LOGGER.info(
        "grizzle-local %s listening on %s:%s%s",
        __version__,
        settings.host,
        settings.port,
        f" and wss:// on {settings.tls_port}" if tls_server else " (no TLS: certificate not found)",
    )
    try:
        await asyncio.Event().wait()
    finally:
        if tls_server:
            tls_server.close()
            await tls_server.wait_closed()
        await runner.cleanup()


def main(argv: list[str] | None = None) -> None:
    settings = Settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(serve(settings))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main(sys.argv[1:])
