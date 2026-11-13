"""TLS front door for the DNS-override setup, with loud handshake logging.

asyncio only logs failed TLS handshakes in debug mode, so a charger that rejects our
self-signed certificate would be invisible. This small frontend accepts the TCP
connection itself, runs the handshake, logs the outcome (including the TLS alert the
peer sent, which tells us whether it verifies certificates), and then pipes bytes to
the plain listener in the same process.

The plain listener sees those connections coming from this machine. So that logs, the sign-in
throttle and the ``unknown-<ip>`` charger id still mean the real client, the frontend notes
which of its own sockets carries which peer; :func:`client_ip` looks it up.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any

_LOGGER = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT = 20
CERT_ALERTS = ("CERTIFICATE", "UNKNOWN_CA", "CERTIFICATE_UNKNOWN", "BAD_CERTIFICATE")
PEERS_KEY = "tls_peers"  # app[PEERS_KEY]: {(address, port) of a proxied connection's socket: the real peer}


def make_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def client_ip(request: Any) -> str:
    """The address of whoever sent this request, seeing through our own TLS frontend."""
    remote = request.remote or "?"
    peers = request.app.get(PEERS_KEY)
    transport = request.transport
    if peers and transport is not None:
        peername = transport.get_extra_info("peername")
        if peername:
            # The key is the address and port of a socket this process opened itself, so nobody
            # else's connection can match it.
            return peers.get(tuple(peername[:2]), remote)
    return remote


def upstream_host(listen_host: str | None) -> str:
    """Where the frontend finds the plain listener, given the address that listener is bound to."""
    if not listen_host or listen_host == "0.0.0.0":
        return "127.0.0.1"
    if listen_host == "::":
        return "::1"  # asyncio binds "::" for IPv6 only, so 127.0.0.1 would reach nothing
    return listen_host  # a specific address: the listener is there and nowhere else


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
        pass
    finally:
        if not writer.is_closing():
            writer.close()


async def start_tls_frontend(
    host: str,
    port: int,
    cert: str,
    key: str,
    target_port: int,
    peers: dict[tuple[str, int], str] | None = None,
    target_host: str | None = None,
) -> asyncio.Server:
    ctx = make_context(cert, key)
    target_host = target_host or upstream_host(host)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "?"
        _LOGGER.info("TLS: connection from %s", peer_str)
        try:
            await asyncio.wait_for(writer.start_tls(ctx), HANDSHAKE_TIMEOUT)
        except TimeoutError:
            _LOGGER.warning("TLS: %s never completed the handshake (not speaking TLS, or waiting on us?)", peer_str)
            writer.close()
            return
        except (ssl.SSLError, OSError) as err:
            reason = getattr(err, "reason", None) or str(err)
            if any(word in str(reason).upper() for word in CERT_ALERTS):
                _LOGGER.warning(
                    "TLS: %s REJECTED OUR CERTIFICATE (%s). The device verifies certificates, so the DNS override "
                    "cannot work with a self-signed cert.",
                    peer_str,
                    reason,
                )
            else:
                _LOGGER.warning("TLS: handshake with %s failed: %s", peer_str, reason)
            writer.close()
            return
        ssl_obj = writer.get_extra_info("ssl_object")
        _LOGGER.info("TLS: handshake with %s OK (%s, %s)", peer_str, ssl_obj.version(), ssl_obj.cipher()[0])
        try:
            up_reader, up_writer = await asyncio.open_connection(target_host, target_port)
        except OSError as err:
            _LOGGER.error("TLS: cannot reach the plain listener on %s port %s: %s", target_host, target_port, err)
            writer.close()
            return
        local = up_writer.get_extra_info("sockname")
        local = tuple(local[:2]) if local else None
        if peers is not None and peer and local:
            peers[local] = peer[0]
        try:
            await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        finally:
            if peers is not None and local:
                peers.pop(local, None)
        _LOGGER.info("TLS: %s disconnected", peer_str)

    server = await asyncio.start_server(handle, host, port)
    return server
