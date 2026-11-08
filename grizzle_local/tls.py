"""TLS front door for the DNS-override setup, with loud handshake logging.

asyncio only logs failed TLS handshakes in debug mode, so a charger that rejects our
self-signed certificate would be invisible. This small frontend accepts the TCP
connection itself, runs the handshake, logs the outcome (including the TLS alert the
peer sent, which tells us whether it verifies certificates), and then pipes bytes to
the plain listener in the same process.
"""

from __future__ import annotations

import asyncio
import logging
import ssl

_LOGGER = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT = 20
CERT_ALERTS = ("CERTIFICATE", "UNKNOWN_CA", "CERTIFICATE_UNKNOWN", "BAD_CERTIFICATE")


def make_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


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


async def start_tls_frontend(host: str, port: int, cert: str, key: str, target_port: int) -> asyncio.Server:
    ctx = make_context(cert, key)

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
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", target_port)
        except OSError as err:
            _LOGGER.error("TLS: cannot reach the plain listener on %s: %s", target_port, err)
            writer.close()
            return
        await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        _LOGGER.info("TLS: %s disconnected", peer_str)

    server = await asyncio.start_server(handle, host, port)
    return server
