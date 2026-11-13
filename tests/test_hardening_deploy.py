"""Deployment-side behaviour: shutting down, the TLS front end, the container entrypoint, the firmware tool."""

from __future__ import annotations

import asyncio
import grp
import json
import os
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import firmware_capture as fc  # noqa: E402
from fake_charger import FakeCharger  # noqa: E402

from grizzle_local.config import Settings
from grizzle_local.main import serve
from grizzle_local.tls import PEERS_KEY, client_ip, start_tls_frontend, upstream_host

from .support import EMAIL, PASSWORD, RawCharger, make_app, wait_for

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker-entrypoint.sh"
SERIAL = "GRD-L0000HARD3"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    out = tmp_path_factory.mktemp("certs")
    subprocess.run([str(ROOT / "scripts/make-cert.sh"), str(out)], check=True, capture_output=True)
    return out / "fullchain.pem", out / "privkey.pem"


# --- shutting down ------------------------------------------------------------------------------


async def test_sigterm_with_chargers_connected_saves_and_exits_promptly(tmp_path, certs):
    """`docker stop` with a charger connected (that is: always). aiohttp waits for open connections
    before it runs cleanup handlers, and closing the chargers' sockets used to be a cleanup handler:
    the server sat out the timeout, Docker killed it, and the final save never ran."""
    settings = Settings(
        data_dir=tmp_path / "data", host="127.0.0.1", port=free_port(), tls_port=free_port(),
        tls_cert=str(certs[0]), tls_key=str(certs[1]), api_email=EMAIL, api_password=PASSWORD, tick_seconds=3600,
    )
    server = asyncio.create_task(serve(settings))
    async with aiohttp.ClientSession() as session:
        plain = FakeCharger(f"ws://127.0.0.1:{settings.port}/ocpp1.6/GRD-PLAIN001", "GRD-PLAIN001", connectors=2)
        secure = FakeCharger(
            f"wss://127.0.0.1:{settings.tls_port}/ocpp1.6/GRD-TLS00001", "GRD-TLS00001", connectors=2, insecure=True
        )
        runners = []
        for charger in (plain, secure):
            await wait_for_listener(charger, session)
            runners.append(asyncio.create_task(charger.run()))
            await asyncio.wait_for(charger.booted.wait(), 10)

        # Something only the shutdown save can have written: the tick is an hour away.
        resp = await session.post(
            f"http://127.0.0.1:{settings.port}/client/auth/login", json={"emailOrPhone": EMAIL, "password": PASSWORD}
        )
        token = (await resp.json())["token"]

        started = time.monotonic()
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(server, 8)  # Docker waits ten seconds, then kills
        assert time.monotonic() - started < 6
        for runner in runners:
            runner.cancel()

    state = json.loads((tmp_path / "data" / "state.json").read_text())
    assert token in state["tokens"]
    assert {"GRD-PLAIN001", "GRD-TLS00001"} <= set(state["stations"])
    assert state["stations"]["GRD-PLAIN001"]["boot"]["chargePointModel"] == "GRD 40A 2025"


async def wait_for_listener(charger: FakeCharger, session: aiohttp.ClientSession) -> None:
    for _ in range(100):
        try:
            await charger.connect(session)
            return
        except aiohttp.ClientConnectorError:
            await asyncio.sleep(0.05)
    raise AssertionError("the server never started listening")


async def test_stop_saves_before_it_waits_for_sockets_to_close(tmp_path):
    """A peer that never acknowledges the close must not stand between us and the save."""
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client:
        controller = client.app["controller"]
        saved_while_closing = []

        class SlowToClose:
            id = "GRD-SLOW0001"

            class ws:
                closed = False

            async def close(self):
                state = json.loads(controller.store._state_path.read_text())
                saved_while_closing.append("GRD-SLOW0001" in state["stations"])
                await asyncio.sleep(3600)

        controller._ensure_station("GRD-SLOW0001")
        controller.connections["GRD-SLOW0001"] = SlowToClose()
        controller.CLOSE_TIMEOUT = 0.3
        started = time.monotonic()
        await controller.stop()
        assert time.monotonic() - started < 2
        assert saved_while_closing == [True]
        del controller.connections["GRD-SLOW0001"]


# --- the TLS front end and who the client really is ---------------------------------------------------


async def test_tls_frontend_reports_the_real_peer(tmp_path, certs):
    async with TestServer(make_app(tmp_path)) as server, TestClient(server) as client:
        peers = client.app[PEERS_KEY]
        tls_port = free_port()
        frontend = await start_tls_frontend("127.0.0.1", tls_port, str(certs[0]), str(certs[1]), server.port, peers)
        try:
            async with aiohttp.ClientSession() as session:
                url = f"wss://127.0.0.1:{tls_port}/ocpp1.6/{SERIAL}"
                ws = await session.ws_connect(url, protocols=("ocpp1.6",), ssl=False)
                await wait_for(lambda: client.app["controller"].is_online(SERIAL))
                assert list(peers.values()) == ["127.0.0.1"]  # noted while the connection lives...
                handshake = client.app["controller"].station(SERIAL)["ocppHandshake"]
                assert handshake["remote"] == "127.0.0.1"
                await ws.close()
            await wait_for(lambda: not peers)  # ...and forgotten when it ends
        finally:
            frontend.close()
            await asyncio.wait_for(frontend.wait_closed(), 5)


def test_client_ip_sees_through_the_frontend_only():
    class Transport:
        def __init__(self, peername):
            self.peername = peername

        def get_extra_info(self, name):
            return self.peername if name == "peername" else None

    class Request:
        def __init__(self, remote, peername, peers):
            self.remote, self.transport, self.app = remote, Transport(peername), {PEERS_KEY: peers}

    peers = {("127.0.0.1", 40001): "192.168.1.77", ("::1", 40003): "fd00::77"}
    assert client_ip(Request("127.0.0.1", ("127.0.0.1", 40001), peers)) == "192.168.1.77"  # came through the frontend
    assert client_ip(Request("::1", ("::1", 40003, 0, 0), peers)) == "fd00::77"  # IPv6 peer names have four parts
    assert client_ip(Request("127.0.0.1", ("127.0.0.1", 40002), peers)) == "127.0.0.1"  # a local process, directly
    # The key is one of our own sockets, address and port: a remote client can't borrow an entry by its port.
    assert client_ip(Request("10.0.0.5", ("10.0.0.5", 40001), peers)) == "10.0.0.5"
    assert client_ip(Request(None, None, {})) == "?"
    request = Request("10.0.0.5", ("10.0.0.5", 1), peers)
    request.transport = None
    assert client_ip(request) == "10.0.0.5"


async def test_sign_in_throttle_counts_the_real_client_not_the_frontend(tmp_path, certs):
    """Through TLS every request arrives from loopback. Throttling "127.0.0.1" would let one client
    lock everyone else out (and make the placeholder charger id the same for every charger)."""
    async with TestServer(make_app(tmp_path)) as server, TestClient(server) as client:
        peers = client.app[PEERS_KEY]
        tls_port = free_port()
        frontend = await start_tls_frontend("127.0.0.1", tls_port, str(certs[0]), str(certs[1]), server.port, peers)
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://127.0.0.1:{tls_port}/client/auth/login"
                resp = await session.post(url, json={"emailOrPhone": EMAIL, "password": "wrong"}, ssl=False)
                assert resp.status == 401
                socket_name = next(iter(peers))
                peers[socket_name] = "192.168.1.77"  # as if this TLS client were another machine on the LAN
                for _ in range(20):
                    resp = await session.post(url, json={"emailOrPhone": EMAIL, "password": "wrong"}, ssl=False)
                assert resp.status == 429
            throttle = client.app["auth"].throttle
            assert throttle.retry_after("192.168.1.77") > 0
            # The same address without the frontend (a different client, as far as we can tell) is unaffected.
            resp = await client.post("/client/auth/login", json={"emailOrPhone": EMAIL, "password": PASSWORD})
            assert resp.status == 200
        finally:
            frontend.close()
            await asyncio.wait_for(frontend.wait_closed(), 5)


async def test_placeholder_charger_id_uses_the_real_address(tmp_path):
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client, aiohttp.ClientSession() as session:
        cp = await RawCharger.connect(client, session, "ignored", path="/ocpp1.6")  # no serial anywhere
        try:
            await wait_for(lambda: client.app["controller"].stations)
            assert list(client.app["controller"].stations) == ["unknown-127.0.0.1"]
        finally:
            await cp.close()


# --- the container entrypoint -------------------------------------------------------------------------


def _unprivileged_user() -> str | None:
    """A non-root account whose name is also a group (what `useradd --user-group` makes in the image)."""
    for entry in pwd.getpwall():
        if entry.pw_uid == 0:
            continue
        try:
            grp.getgrnam(entry.pw_name)
        except KeyError:
            continue
        return entry.pw_name
    return None


RUN_AS = _unprivileged_user()
needs_root = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("setpriv") is None or RUN_AS is None,
    reason="needs root, setpriv and an unprivileged account to drop to (as inside the container)",
)
REPORT = (
    'echo "uid=$(id -u) cert=${GRIZZLE_TLS_CERT:-}'
    ' key_readable=$([ -r "${GRIZZLE_TLS_KEY:-/nonexistent}" ] && echo yes || echo no)'
    ' data_writable=$([ -w "$GRIZZLE_DATA_DIR" ] && echo yes || echo no)'
    ' nnp=$(awk "/^NoNewPrivs:/{print \\$2}" /proc/self/status) caps=$(awk "/^CapEff:/{print \\$2}" /proc/self/status)"'
)


def _entrypoint(tmp_path, *command, **env) -> subprocess.CompletedProcess:
    base = {"PATH": os.environ["PATH"], "GRIZZLE_RUN_AS": RUN_AS or "", "GRIZZLE_DATA_DIR": str(tmp_path / "data"),
            "GRIZZLE_TLS_CERT": str(tmp_path / "certs" / "fullchain.pem"),
            "GRIZZLE_TLS_KEY": str(tmp_path / "certs" / "privkey.pem"),
            "GRIZZLE_CERT_COPY_DIR": str(tmp_path / "cert-copy")}
    base.update(env)
    command = command or ("sh", "-c", REPORT)
    return subprocess.run(["sh", str(ENTRYPOINT), *command], env=base, capture_output=True, text=True, timeout=30)


@pytest.fixture
def volumes(tmp_path):
    """Root-owned volumes as an earlier image (which ran as root) left them."""
    for parent in [tmp_path, *tmp_path.parents]:  # let the unprivileged user reach the directory at all
        if parent == Path("/"):
            break
        parent.chmod(parent.stat().st_mode | 0o011)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "state.json").write_text("{}")
    (tmp_path / "data" / "state.json").chmod(0o600)
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "fullchain.pem").write_text("CERT")
    (tmp_path / "certs" / "privkey.pem").write_text("KEY")
    (tmp_path / "certs" / "privkey.pem").chmod(0o600)
    return tmp_path


@needs_root
def test_entrypoint_drops_privileges_and_hands_over_the_volumes(volumes):
    result = _entrypoint(volumes)
    assert result.returncode == 0, result.stderr
    uid = pwd.getpwnam(RUN_AS).pw_uid
    fields = dict(part.split("=", 1) for part in result.stdout.split())
    assert fields["uid"] == str(uid) and fields["caps"] == "0000000000000000" and fields["nnp"] == "1"
    assert fields["data_writable"] == "yes" and fields["key_readable"] == "yes"
    assert (volumes / "data" / "state.json").stat().st_uid == uid
    # The key in the (read-only) certs volume is untouched; the server got a private copy.
    assert (volumes / "certs" / "privkey.pem").stat().st_uid == 0
    copy = volumes / "cert-copy" / "privkey.pem"
    assert fields["cert"] == str(volumes / "cert-copy" / "fullchain.pem")
    assert copy.read_text() == "KEY" and copy.stat().st_uid == uid and stat.S_IMODE(copy.stat().st_mode) == 0o600
    assert stat.S_IMODE(copy.parent.stat().st_mode) == 0o700
    assert result.stderr == ""


@needs_root
def test_entrypoint_passes_arguments_through_unchanged(volumes):
    result = _entrypoint(volumes, "sh", "-c", 'printf "[%s]" "$@"', "sh", "a b", "c  d", "")
    assert result.returncode == 0 and result.stdout == "[a b][c  d][]"


@needs_root
@pytest.mark.parametrize(
    "env,reason",
    [
        ({"GRIZZLE_RUN_AS": "no-such-user"}, "cannot switch to user"),
        ({"GRIZZLE_DATA_DIR": "/proc/sys/kernel"}, "is not writable"),
        ({"GRIZZLE_CERT_COPY_DIR": "/proc/nope/certs"}, "TLS key is not readable"),
    ],
)
def test_entrypoint_stays_root_rather_than_break_an_installation(volumes, env, reason):
    result = _entrypoint(volumes, **env)
    assert result.returncode == 0, result.stderr
    assert "uid=0 " in result.stdout
    assert reason in result.stderr and "running as root" in result.stderr


@needs_root
def test_entrypoint_does_nothing_when_told_to_stay_root_or_already_unprivileged(volumes):
    result = _entrypoint(volumes, GRIZZLE_RUN_AS="root")
    assert result.returncode == 0 and "uid=0 " in result.stdout and result.stderr == ""
    assert (volumes / "data" / "state.json").stat().st_uid == 0  # nothing was handed over

    uid = pwd.getpwnam(RUN_AS).pw_uid
    base = {"PATH": os.environ["PATH"], "GRIZZLE_DATA_DIR": str(volumes / "data")}
    as_user = ["setpriv", f"--reuid={RUN_AS}", f"--regid={RUN_AS}", "--init-groups"]
    result = subprocess.run(  # `user:` in compose: the container never is root
        [*as_user, "sh", str(ENTRYPOINT), "sh", "-c", REPORT], env=base, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0 and f"uid={uid} " in result.stdout and result.stderr == ""


def test_entrypoint_and_dockerfile_agree():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert 'ENTRYPOINT ["docker-entrypoint.sh"]' in dockerfile
    assert "--require-hashes" in dockerfile and "useradd" in dockerfile and "--user-group" in dockerfile
    assert os.access(ENTRYPOINT, os.X_OK)
    assert subprocess.run(["sh", "-n", str(ENTRYPOINT)]).returncode == 0  # parses as POSIX sh
    locked = (ROOT / "requirements.txt").read_text()
    for line in locked.splitlines():  # every requirement is pinned exactly, with a hash
        if line and not line.startswith((" ", "#")):
            assert "==" in line and line.rstrip().endswith("\\"), line
    assert locked.count("--hash=sha256:") > 50


# --- tools/firmware_capture.py --------------------------------------------------------------------


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/passwd",
        "FILE:///etc/shadow",
        "data:text/plain,hi",
        "gopher://x/1",
        "/etc/passwd",
        "",
        "None",
        "javascript:1",
    ],
)
def test_download_refuses_locations_that_are_not_ftp_or_http(tmp_path, location):
    """The location comes from the other end of the OCPP connection. urllib would happily "download"
    file:///etc/passwd into the output directory."""
    target = tmp_path / "out" / "image.bin"
    with pytest.raises(fc.CloudError, match="only ftp, http, https"):
        fc.download_image(location, target)
    assert not target.exists()


@pytest.mark.parametrize(
    "location,name",
    [
        ("ftp://host/files/UDGRW070L-04.03.2.bin", "UDGRW070L-04.03.2.bin"),
        ("http://host/fw/image.bin?token=1#frag", "image.bin"),
        ("ftp://host/..", "firmware.bin"),
        ("ftp://host/a/../../etc/passwd", "passwd"),
        ("http://host/%2e%2e%2f%2e%2e%2fetc%2fcron.d%2fevil", "evil"),
        ("http://host/a\\..\\..\\boot.ini", "boot.ini"),
        ("http://host/", "firmware.bin"),
        ("http://host/....", "firmware.bin"),
        ("http://host/na me;rm -rf.bin", "na_me_rm_-rf.bin"),
        ("http://host/" + "A" * 500, "A" * 128),
    ],
)
def test_image_filename_is_always_a_plain_name(location, name):
    result = fc.image_filename(location)
    assert result == name
    assert "/" not in result and "\\" not in result and result not in (".", "..") and result


class _Firmware(BaseHTTPRequestHandler):
    body = b"\xe9" + b"F" * 5000

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        if self.path == "/endless":
            try:
                while True:
                    self.wfile.write(b"x" * 65536)
            except OSError:
                return
        self.wfile.write(self.body)


@pytest.fixture
def firmware_host():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Firmware)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_download_stops_at_the_size_limit(tmp_path, firmware_host, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    info = fc.download_image(f"{firmware_host}/image.bin", tmp_path / "image.bin")
    assert info["size"] == 5001 and (tmp_path / "image.bin").read_bytes() == _Firmware.body

    endless = tmp_path / "endless.bin"
    with pytest.raises(fc.CloudError, match="larger than"):
        fc.download_image(f"{firmware_host}/endless", endless, max_bytes=300_000)
    assert not endless.exists()  # and nothing half-written is left behind


def test_token_file_is_never_readable_by_others(tmp_path):
    path = tmp_path / "config" / "tokens.json"
    client = fc.CloudClient(token="T0KEN", refresh_token="REFRESH")
    old_umask = os.umask(0o022)
    try:
        fc.save_token_file(path, client)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        path.chmod(0o644)  # an existing, too-open file is tightened as well
        fc.save_token_file(path, client)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        os.umask(old_umask)
    assert json.loads(path.read_text()) == {"token": "T0KEN", "refreshToken": "REFRESH"}


def test_station_id_from_the_cloud_is_quoted_into_the_path():
    seen = []

    class Client(fc.CloudClient):
        def request(self, method, path, body=None):
            seen.append(path)
            return {}

    Client().firmware("abc/../../admin?x=1")
    assert seen == ["/client/stations/abc%2F..%2F..%2Fadmin%3Fx%3D1/firmware"]


# --- the TLS front end and GRIZZLE_HOST ---------------------------------------------------------------


def test_upstream_host_follows_the_listen_address():
    assert upstream_host("0.0.0.0") == "127.0.0.1"
    assert upstream_host("") == "127.0.0.1" and upstream_host(None) == "127.0.0.1"
    assert upstream_host("::") == "::1"
    assert upstream_host("192.168.1.5") == "192.168.1.5"
    assert upstream_host("127.0.0.1") == "127.0.0.1"


def _has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@pytest.mark.parametrize(
    "host,url_host",
    [
        ("127.0.0.2", "127.0.0.2"),  # one specific address (any 127.x.x.x is local on Linux)
        pytest.param("::", "[::1]", marks=pytest.mark.skipif(not _has_ipv6_loopback(), reason="no IPv6 loopback")),
    ],
)
async def test_tls_reaches_a_plain_listener_that_is_not_on_ipv4_loopback(tmp_path, certs, host, url_host):
    """The front end always dialled 127.0.0.1. With GRIZZLE_HOST=:: or one specific address nothing
    listens there: every TLS client finished the handshake and was dropped."""
    settings = Settings(
        data_dir=tmp_path / "data", host=host, port=free_port(), tls_port=free_port(),
        tls_cert=str(certs[0]), tls_key=str(certs[1]), api_email=EMAIL, api_password=PASSWORD, tick_seconds=3600,
    )
    server = asyncio.create_task(serve(settings))
    try:
        async with aiohttp.ClientSession() as session:
            for _ in range(100):
                try:
                    resp = await session.get(f"https://{url_host}:{settings.tls_port}/health", ssl=False)
                    break
                except aiohttp.ClientError:
                    await asyncio.sleep(0.05)
            else:
                raise AssertionError("no answer through the TLS front end")
            assert resp.status == 200 and (await resp.json())["status"] == "ok"
    finally:
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(server, 8)


# --- the certificate script -------------------------------------------------------------------------


def test_generated_certificate_is_a_server_certificate_not_a_ca(certs):
    """`openssl req -x509` makes a CA by default: whoever copied privkey.pem could have signed
    certificates for any site, valid wherever this certificate had been trusted."""
    text = subprocess.run(
        ["openssl", "x509", "-in", str(certs[0]), "-noout", "-text"], check=True, capture_output=True, text=True
    ).stdout
    assert "CA:FALSE" in text and "CA:TRUE" not in text
    assert "TLS Web Server Authentication" in text
    assert "DNS:ocpp.unitedchargers.com" in text and "DNS:connect-api.unitedchargers.com" in text
    assert stat.S_IMODE(certs[1].stat().st_mode) == 0o600


# --- tools/poc_n1_unauth_webui.py --------------------------------------------------------------------


class _WebUi(BaseHTTPRequestHandler):
    control_status = 200

    def log_message(self, *args):
        pass

    def _answer(self):
        if self.path in ("/ocppconfig", "/service"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Please enter login and password"')
        elif self.control_status == 302:
            self.send_response(302)
            self.send_header("Location", "/login-page")
        elif self.path == "/login-page":
            self.send_response(200)
        else:
            self.send_response(self.control_status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = _answer  # noqa: N815


@pytest.mark.parametrize(
    "status,expected_exit,verdict",
    [
        (200, 2, "N1 CONFIRMED"),
        (401, 0, "N1 not reproduced"),
        (403, 3, "inconclusive"),  # refused is not "processed without auth"
        (404, 3, "inconclusive"),
        (500, 3, "inconclusive"),
        (302, 3, "inconclusive"),  # a redirect to a login page must not be followed and counted as 200
    ],
)
def test_n1_poc_only_counts_a_success_as_confirmation(monkeypatch, capsys, status, expected_exit, verdict):
    import poc_n1_unauth_webui as poc

    handler = type("Handler", (_WebUi,), {"control_status": status})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("NO_PROXY", "127.0.0.1")
        monkeypatch.setenv("no_proxy", "127.0.0.1")
        monkeypatch.setattr(sys, "argv", ["poc", "--host", "127.0.0.1", "--port", str(server.server_address[1])])
        assert poc.main() == expected_exit
    finally:
        server.shutdown()
    assert verdict in capsys.readouterr().out


# --- firmware_capture keeps a refreshed token ---------------------------------------------------------


def test_a_refreshed_cloud_token_is_written_back(tmp_path):
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"token": "expired", "refreshToken": "single-use"}))

    class Cloud(fc.CloudClient):
        def _raw(self, method, path, body=None, auth=True):
            if path == "/client/auth/refresh-token":
                return 200, {"token": "fresh", "refreshToken": "next"}
            return (200, {"stations": []}) if self.token == "fresh" else (401, {"message": "expired"})

    client = Cloud()
    client.token, client.refresh_token = fc.load_token_file(token_file)
    client.token_file = token_file
    assert client.stations() == []
    assert json.loads(token_file.read_text()) == {"token": "fresh", "refreshToken": "next"}
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600


# --- low ports, and the health check ------------------------------------------------------------------

BIND_PROBE = (
    "import socket, sys\n"
    "caps = [l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0]\n"
    "def bind(port):\n"
    "    try:\n"
    "        socket.socket().bind(('127.0.0.1', port)); return 'ok'\n"
    "    except OSError: return 'refused'\n"
    "print(caps, bind(int(sys.argv[1])))\n"
)


def _low_port() -> int | None:
    """A free port below the unprivileged range, if this system has one."""
    try:
        limit = int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text())
    except (OSError, ValueError):
        return None
    for port in range(min(limit, 1024) - 1, 0, -1):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return None


@needs_root
def test_entrypoint_keeps_only_the_bind_capability_for_a_low_port(volumes):
    """With host networking and GRIZZLE_TLS_PORT=443 the unprivileged server could not bind its
    port, and the container that started fine as root no longer started at all."""
    port = _low_port()
    if port is None:
        pytest.skip("every port is unprivileged here")
    result = _entrypoint(volumes, sys.executable, "-c", BIND_PROBE, str(port))
    assert result.stdout.split() == ["0000000000000000", "refused"], result.stderr  # default ports: nothing kept
    result = _entrypoint(volumes, sys.executable, "-c", BIND_PROBE, str(port), GRIZZLE_TLS_PORT="443")
    assert result.stdout.split() == ["0000000000000400", "ok"], result.stderr  # CAP_NET_BIND_SERVICE and nothing else
    result = _entrypoint(volumes, sys.executable, "-c", BIND_PROBE, str(port), GRIZZLE_PORT="80; echo injected")
    assert result.stdout.split() == ["0000000000000000", "refused"] and "injected" not in result.stdout


async def test_health_check_asks_where_the_server_listens(tmp_path, monkeypatch):
    from grizzle_local import healthcheck

    assert healthcheck.url(Settings(host="0.0.0.0", port=9000)) == "http://127.0.0.1:9000/health"
    assert healthcheck.url(Settings(host="::", port=9123)) == "http://[::1]:9123/health"
    assert healthcheck.url(Settings(host="192.168.1.5", port=80)) == "http://192.168.1.5:80/health"

    async with TestServer(make_app(tmp_path)) as server:
        monkeypatch.setenv("GRIZZLE_HOST", "127.0.0.1")
        monkeypatch.setenv("GRIZZLE_PORT", str(server.port))
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")  # a proxy setting must not come between us and ourselves
        assert await asyncio.to_thread(healthcheck.main) == 0
        monkeypatch.setenv("GRIZZLE_PORT", str(free_port()))
        assert await asyncio.to_thread(healthcheck.main) == 1
    assert 'CMD ["python", "-m", "grizzle_local.healthcheck"]' in (ROOT / "Dockerfile").read_text()


async def test_no_charger_is_admitted_once_shutdown_has_begun(tmp_path, monkeypatch):
    """A handshake that is waiting on the liveness probe when shutdown starts used to be connected
    after "every connection" had been closed: nothing closed that one, and exit waited ten seconds."""
    async with TestServer(make_app(tmp_path)) as ts, TestClient(ts) as client, aiohttp.ClientSession() as session:
        controller = client.app["controller"]
        original = type(controller)._refusal

        async def slow_check(self, cp_id, auth_key):  # as the probe of an unresponsive charger would be
            result = await original(self, cp_id, auth_key)
            await asyncio.sleep(0.5)
            return result

        monkeypatch.setattr(type(controller), "_refusal", slow_check)
        connecting = asyncio.create_task(RawCharger.connect(client, session, SERIAL))
        await asyncio.sleep(0.2)  # the handshake is inside the admission check...
        await controller.stop()  # ...when the server begins to stop
        with pytest.raises(aiohttp.WSServerHandshakeError) as refused:
            await connecting
        assert refused.value.status == 503
        assert controller.connections == {}
