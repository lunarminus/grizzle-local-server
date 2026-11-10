"""Entry point: one aiohttp application serving both OCPP WebSockets and the REST API."""

from __future__ import annotations

import asyncio
import base64
import logging
import sys
from pathlib import Path

from aiohttp import web

from . import __version__
from .api import Auth, add_routes, auth_middleware
from .config import Settings
from .controller import Controller
from .ocpp import ChargePointConnection, now_iso
from .store import Store
from .tls import start_tls_frontend

_LOGGER = logging.getLogger("grizzle_local")

WEB_DIR = Path(__file__).parent / "web"
# The page is fully self-contained (inline CSS/JS, no external requests).
PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "img-src 'self' data:; frame-ancestors *",
    "Cache-Control": "no-cache",
}


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


async def websocket_handler(request: web.Request) -> web.StreamResponse:
    controller: Controller = request.app["controller"]
    settings: Settings = request.app["settings"]
    if request.headers.get("Upgrade", "").lower() != "websocket":
        if request.path in ("/", "/index.html"):
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            return web.Response(text=html, content_type="text/html", headers=PAGE_HEADERS)
        raise web.HTTPNotFound()
    cp_id = _charge_point_id(request)
    auth_user, auth_key = _basic_credentials(request)
    if settings.ocpp_password is not None and auth_key != settings.ocpp_password:
        _LOGGER.warning("%s: rejected, wrong OCPP password (from %s)", cp_id, request.remote)
        raise web.HTTPUnauthorized()
    offered = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
    ws = web.WebSocketResponse(protocols=("ocpp1.6",) if "ocpp1.6" in offered else (), heartbeat=120, autoping=True)
    await ws.prepare(request)
    _LOGGER.info("%s: websocket from %s path=%s subprotocol=%s", cp_id, request.remote, request.path, ws.ws_protocol)
    # Record how the charger connected, so its cloud identity (serial + Auth key) can be
    # reused by tools/firmware_capture.py. This is never exposed through the HTTP API.
    handshake = {
        "path": request.path,
        "query": request.query_string or None,
        "authUser": auth_user,
        "protocols": offered,
        "userAgent": request.headers.get("User-Agent"),
        "remote": request.remote,
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
