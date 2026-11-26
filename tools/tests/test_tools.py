"""The tools against hostile or unusual peers, and against the real server."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import firmware_capture as fc
import pytest
from aiohttp.test_utils import TestServer
from conftest import ROOT, wait_for
from fake_charger import FakeCharger

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


def test_download_stops_at_the_size_limit(tmp_path, firmware_host):
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
        # And it is private from the moment it exists, not from a chmod afterwards: with that
        # chmod taken away, a file written first and restricted second would stay at 0644.
        path.unlink()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(Path, "chmod", lambda self, mode: None)
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


@pytest.fixture
async def update_cloud():
    """A stand-in for the vendor's OCPP cloud: answers every call, and sends one UpdateFirmware whose
    location the test chooses."""
    from aiohttp import web

    state = {"location": None, "body": b"\xe9" + b"FW" * 2000}

    async def firmware(request):
        return web.Response(body=state["body"])

    async def cloud(request):
        ws = web.WebSocketResponse(protocols=("ocpp1.6",))
        await ws.prepare(request)
        async for msg in ws:
            frame = json.loads(msg.data)
            if frame[0] != 2:
                continue
            await ws.send_str(json.dumps([3, frame[1], {"status": "Accepted", "interval": 300}]))
            if frame[2] == "BootNotification":
                location = state["location"] or str(request.url.with_path("/fw/image.bin"))
                await ws.send_str(json.dumps([2, "u1", "UpdateFirmware", {"location": location}]))
        return ws

    app = web.Application()
    app.router.add_get("/ocpp1.6", cloud)
    app.router.add_get("/{tail:.*}", firmware)
    server = TestServer(app)
    await server.start_server()
    server.state = state
    yield server
    await server.close()


def _capture_args(server, out, **overrides):
    import argparse

    values = dict(
        base_url="http://unused", token_file="/unused", email=None, save_tokens=False, state=None, serial="GRD-TEST",
        auth_key="s3cret", claim_firmware=None, cloud_ip=None, doh_url=fc.DOH_URL, timeout=10.0, out=str(out),
        ocpp_url=f"ws://{server.host}:{server.port}/ocpp1.6", name=None, no_trigger=True, no_download=False, json=False,
        max_size=fc.DEFAULT_MAX_DOWNLOAD,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


async def test_capture_saves_under_a_plain_name_whatever_the_location_says(update_cloud, tmp_path):
    out = tmp_path / "out"
    base = f"http://{update_cloud.host}:{update_cloud.port}"
    update_cloud.state["location"] = f"{base}/a/..%2f..%2f..%2fescaped.bin"
    assert await asyncio.to_thread(fc.cmd_capture, _capture_args(update_cloud, out)) == 0
    assert sorted(p.name for p in out.iterdir()) == ["escaped.bin", "escaped.bin.json"]
    assert not (tmp_path / "escaped.bin").exists()

    # --name is a file name: a path in it does not move the file out of the output directory.
    update_cloud.state["location"] = f"{base}/fw/image.bin"
    args = _capture_args(update_cloud, out, name="../../named.bin")
    assert await asyncio.to_thread(fc.cmd_capture, args) == 0
    assert (out / "named.bin").read_bytes() == update_cloud.state["body"] and not (tmp_path / "named.bin").exists()


@pytest.mark.parametrize("location", ["file:///etc/hostname", "http://[not-a-url", "/etc/hostname"])
async def test_capture_refuses_a_location_it_should_not_fetch(update_cloud, tmp_path, location):
    update_cloud.state["location"] = location
    with pytest.raises(fc.CloudError, match="only ftp, http, https"):
        await asyncio.to_thread(fc.cmd_capture, _capture_args(update_cloud, tmp_path / "out"))
    assert not list((tmp_path / "out").glob("*")) if (tmp_path / "out").exists() else True


async def test_capture_honours_max_size(update_cloud, tmp_path):
    with pytest.raises(fc.CloudError, match="larger than"):
        await asyncio.to_thread(fc.cmd_capture, _capture_args(update_cloud, tmp_path / "out", max_size=1000))
    assert not (tmp_path / "out" / "image.bin").exists()


def test_capture_explains_an_unreadable_state_file(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("{}")
    with pytest.MonkeyPatch.context() as patch:

        def refuse(self, *args, **kwargs):
            raise PermissionError(13, "Permission denied")

        patch.setattr(Path, "read_text", refuse)
        with pytest.raises(fc.CloudError, match="readable only by the user the server runs as"):
            fc.load_identity(state, None)


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
        monkeypatch.setattr(sys, "argv", ["poc", "--host", "127.0.0.1", "--port", str(server.server_address[1])])
        assert poc.main() == expected_exit
    finally:
        server.shutdown()
    assert verdict in capsys.readouterr().out


# --- tools/fake_charger.py ---------------------------------------------------------------------------


async def test_fake_charger_rejects_a_connector_it_does_not_have():
    """The server may assume a Duo's two connectors; the one-connector fake used to die of a KeyError."""

    class Socket:
        sent: list = []

        async def send_str(self, text):
            self.sent.append(json.loads(text))

    charger = FakeCharger("ws://unused", "GRD-ONE", connectors=1)
    charger.ws = Socket()
    await charger._handle_call("u1", "TriggerMessage", {"requestedMessage": "StatusNotification", "connectorId": 2})
    await charger._handle_call("u2", "RemoteStartTransaction", {"connectorId": 2, "idTag": "t"})
    assert charger.ws.sent == [[3, "u1", {"status": "Rejected"}], [3, "u2", {"status": "Rejected"}]]


def test_fake_charger_boots_plugs_in_and_charges_on_the_server(rust_server):
    """The command the README gives for trying the server without a charger, against the real server."""
    url = f"ws://127.0.0.1:{rust_server.port}/ocpp1.6/GRD-FAKE0001"
    command = [sys.executable, str(ROOT / "tools" / "fake_charger.py"), url, "--plug-in", "0.2"]
    charger = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for(lambda: rust_server.request("/health")["stationsOnline"] == 1)
        connector = lambda: rust_server.request("/client/stations/GRD-FAKE0001")["connectors"][0]  # noqa: E731
        charge = wait_for(lambda: connector()["charge"])  # the server started it: plugging in is all it takes
        assert charge["transactionId"] >= 1 and charge["meterStart"] == 501000
        wait_for(lambda: connector()["status"] == "Charging")
        assert charger.poll() is None  # and the charger stays connected
    finally:
        charger.terminate()
        charger.wait(10)
    wait_for(lambda: rust_server.request("/health")["stationsOnline"] == 0)


# --- tools/gen_holidays.py ---------------------------------------------------------------------------


@pytest.mark.slow
def test_committed_holiday_table_is_what_the_pinned_package_gives():
    """The table built into the server is the tool's output, at the path the tool writes by default."""
    command = [sys.executable, str(ROOT / "tools" / "gen_holidays.py"), "--check"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stderr
    assert f"{ROOT / 'src' / 'holidays.bin'} is up to date" in result.stdout
