"""firmware_capture check against a fake cloud (no real network)."""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import firmware_capture as fc
import pytest

SERIAL = "GRD-L0000430161"
STATION_ID = "abc123"


class FakeCloud(BaseHTTPRequestHandler):
    firmware = {
        "hasUpdates": True,
        "canUpdate": True,
        "latestFirmware": {"version": "UDGRW070L-04.04.0", "changelog": "Bug fixes"},
        "station": {"model": {"displayName": "Grizzl-E Duo"}},
    }

    def log_message(self, *args):  # silence
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)
        if self.path == "/client/auth/login":
            self._send(200, {"token": "T0KEN", "refreshToken": "REFRESH", "isVerified": True, "user": {}})
        elif self.path == "/client/auth/refresh-token":
            given = json.loads(body or b"{}").get("refreshToken")
            if given == "REFRESH":
                self._send(200, {"token": "T0KEN", "refreshToken": "REFRESH"})
            else:
                self._send(401, {"message": "bad refresh"})
        else:
            self._send(404, {"message": "no"})

    def do_GET(self):
        if self.headers.get("authorization") != "Bearer T0KEN":
            self._send(401, {"message": "Unauthorized"})
            return
        if self.path == "/client/stations":
            self._send(200, {"stations": [{
                "_id": STATION_ID, "serialNumber": SERIAL, "displayName": SERIAL,
                "bootNotification": {"firmwareVersion": "UDGRW070L-04.03.2"},
            }]})
        elif self.path == f"/client/stations/{STATION_ID}/firmware":
            self._send(200, self.firmware)
        else:
            self._send(404, {"message": "no"})


@pytest.fixture
def cloud():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeCloud)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://{server.server_address[0]}:{server.server_address[1]}"
    server.shutdown()


def _args(cloud, token_file, **kw):
    import argparse
    defaults = dict(base_url=cloud, token_file=str(token_file), email=None,
                    save_tokens=False, serial=None, json=False)
    defaults.update(kw)
    return argparse.Namespace(**defaults)


def test_check_with_token_file(cloud, tmp_path, capsys):
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"token": "T0KEN", "refreshToken": "REFRESH"}))
    assert fc.cmd_check(_args(cloud, token_file)) == 0
    out = capsys.readouterr().out
    assert "UDGRW070L-04.03.2" in out  # installed
    assert "UDGRW070L-04.04.0" in out  # offered
    assert "UPDATE" in out


def test_check_json_output(cloud, tmp_path, capsys):
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"token": "T0KEN", "refreshToken": "REFRESH"}))
    assert fc.cmd_check(_args(cloud, token_file, json=True)) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["serial"] == SERIAL
    assert data["installed"] == "UDGRW070L-04.03.2"
    assert data["firmware"]["latestFirmware"]["version"] == "UDGRW070L-04.04.0"


def test_check_login_with_email(cloud, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GRIZZLE_CLOUD_PASSWORD", "pw")
    assert fc.cmd_check(_args(cloud, tmp_path / "none.json", email="you@example.com")) == 0
    assert "UPDATE" in capsys.readouterr().out


def test_no_update_offered(cloud, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(FakeCloud, "firmware", {
        "hasUpdates": False, "canUpdate": False,
        "latestFirmware": {}, "station": {"model": {"displayName": "Grizzl-E Duo"}},
    })
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"token": "T0KEN", "refreshToken": "REFRESH"}))
    assert fc.cmd_check(_args(cloud, token_file)) == 0
    assert "NO update" in capsys.readouterr().out


def test_stale_token_is_refreshed(cloud, tmp_path, capsys):
    # The saved token is wrong, so the first GET gets 401; the tool must refresh once and retry.
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"token": "STALE", "refreshToken": "REFRESH"}))
    assert fc.cmd_check(_args(cloud, token_file)) == 0
    assert "UPDATE" in capsys.readouterr().out


def test_refresh_failure_raises(cloud, tmp_path):
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"token": "STALE", "refreshToken": "BAD"}))
    with pytest.raises(fc.CloudError, match="token refresh failed"):
        fc.cmd_check(_args(cloud, token_file))


def test_missing_token_file(cloud, tmp_path):
    with pytest.raises(fc.CloudError, match="no token file"):
        fc.cmd_check(_args(cloud, tmp_path / "absent.json"))


def test_unknown_serial(cloud, tmp_path):
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"token": "T0KEN", "refreshToken": "REFRESH"}))
    with pytest.raises(fc.CloudError, match="no station matching"):
        fc.cmd_check(_args(cloud, token_file, serial="GRD-NOPE"))


# --- capture (offline OCPP cloud + firmware host) ---------------------------

FW_BYTES = bytes([0xE9]) + b"PRETEND-GRIZZLE-FIRMWARE" * 10


def _cap_args(**kw):
    import argparse
    defaults = dict(base_url="http://unused", token_file="/unused", email=None, save_tokens=False,
                    state=None, serial=None, auth_key="s3cret", claim_firmware="UDGRW070L-00.00.1",
                    cloud_ip=None, doh_url=fc.DOH_URL, ocpp_url=None, timeout=10.0, out=None, name=None,
                    no_trigger=True, no_download=False, json=False)
    defaults.update(kw)
    return argparse.Namespace(**defaults)


@pytest.fixture
async def ocpp_cloud():
    """A fake United Chargers OCPP cloud: accepts BootNotification, then pushes UpdateFirmware."""
    from aiohttp import web
    from aiohttp.test_utils import TestServer

    captured = {}

    async def firmware(request):
        return web.Response(body=FW_BYTES, content_type="application/octet-stream")

    async def ws_handler(request):
        captured["authorization"] = request.headers.get("Authorization")
        ws = web.WebSocketResponse(protocols=("ocpp1.6",))
        await ws.prepare(request)
        fw_url = str(request.url.with_path("/fw/image.bin"))
        boot_seen = False
        async for msg in ws:
            frame = json.loads(msg.data)
            if frame[0] == 2:  # CALL from the "charger"
                action, payload = frame[2], frame[3]
                captured.setdefault("calls", []).append((action, payload))
                await ws.send_str(json.dumps([3, frame[1], {"status": "Accepted", "currentTime": "2026-01-01T00:00:00Z",
                                                            "interval": 300}]))
                if action == "BootNotification" and not boot_seen:
                    boot_seen = True
                    captured["claimed"] = payload.get("firmwareVersion")
                    await ws.send_str(json.dumps([2, "u1", "UpdateFirmware",
                                                  {"location": fw_url, "retrieveDate": "2026-01-01T00:00:00Z"}]))
            elif frame[0] == 3:  # CALLRESULT to our UpdateFirmware
                captured.setdefault("results", []).append(frame[2])
        return ws

    app = web.Application()
    app.router.add_get("/ocpp1.6", ws_handler)
    app.router.add_get("/fw/image.bin", firmware)
    server = TestServer(app)
    await server.start_server()
    server.captured = captured
    yield server
    await server.close()


async def test_capture_downloads_image(ocpp_cloud, tmp_path, capsys):
    out = tmp_path / "firmware"
    url = f"ws://{ocpp_cloud.host}:{ocpp_cloud.port}/ocpp1.6"
    rc = await asyncio.to_thread(fc.cmd_capture, _cap_args(ocpp_url=url, out=str(out), serial="GRD-TEST"))
    assert rc == 0

    saved = out / "image.bin"
    assert saved.read_bytes() == FW_BYTES
    sidecar = json.loads((out / "image.bin.json").read_text())
    assert sidecar["sha256"] == __import__("hashlib").sha256(FW_BYTES).hexdigest()
    assert sidecar["location"].endswith("/fw/image.bin")
    # The cloud was told the spoofed old version, and got the Basic-auth identity.
    assert ocpp_cloud.captured["claimed"] == "UDGRW070L-00.00.1"
    assert ocpp_cloud.captured["authorization"].startswith("Basic ")
    out_text = capsys.readouterr().out
    assert "ESP32 image" in out_text  # first byte 0xE9


async def test_capture_no_download_reports_location(ocpp_cloud, tmp_path, capsys):
    url = f"ws://{ocpp_cloud.host}:{ocpp_cloud.port}/ocpp1.6"
    rc = await asyncio.to_thread(fc.cmd_capture, _cap_args(ocpp_url=url, no_download=True, serial="GRD-TEST"))
    assert rc == 0
    assert "/fw/image.bin" in capsys.readouterr().out


def test_capture_requires_auth_key(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"stations": {"GRD-TEST": {"id": "GRD-TEST", "boot": {}}}}))
    with pytest.raises(fc.CloudError, match="no Auth key"):
        fc.cmd_capture(_cap_args(state=str(state), auth_key=None, ocpp_url="ws://unused/ocpp1.6"))
