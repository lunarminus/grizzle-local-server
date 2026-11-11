#!/usr/bin/env python3
"""Find out what firmware the United Chargers cloud has for your own charger.

This talks to the real cloud (https://connect-api.unitedchargers.com) with YOUR
account, read-only. It never touches the charger and never installs anything: the
``check`` subcommand only asks the cloud whether an update is offered and which
version. Capturing the actual image is a separate, later step.

The cloud's firmware endpoint (reverse engineered from the Grizzl-E Connect app):
    GET /client/stations/{id}/firmware
      -> {"hasUpdates": bool, "canUpdate": bool,
          "latestFirmware": {"version": str, "changelog": str},
          "station": {"model": {"displayName": str}}}
The app starts an update with POST to the same path and body {}; the cloud then
sends the charger an OCPP UpdateFirmware with the download URL. This tool does not
POST.

Auth: a bearer token saved by grizzle_connect.py (``~/.config/grizzle_connect/tokens.json``,
or $GRIZZLE_TOKEN_FILE / --token-file), or an email+password login. The password is
read from $GRIZZLE_CLOUD_PASSWORD or prompted; it is never stored unless --save-tokens
is given.

Examples:
    python -m tools.firmware_capture check --serial GRD-L0000430161
    python tools/firmware_capture.py check --token-file ~/.config/grizzle_connect/tokens.json
    GRIZZLE_CLOUD_PASSWORD=... python tools/firmware_capture.py check --email you@example.com
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLOUD_URL = "https://connect-api.unitedchargers.com"
OCPP_CLOUD_HOST = "ocpp.unitedchargers.com"
OCPP_CLOUD_PATH = "/ocpp1.6"
DOH_URL = "https://1.1.1.1/dns-query"
# Headers the Grizzl-E Connect app v1.6.1 (205) sends (see ../../grizzle_connect.py).
APP_HEADERS = {
    "x-app-version": "v1.6.1 (205)",
    "x-app-client": "Local Server, firmware_capture, Python",
    "x-application-name": "Grizzl-E Connect",
    "accept": "application/json",
    "content-type": "application/json",
}
DEFAULT_TOKEN_FILE = Path(
    os.environ.get("GRIZZLE_TOKEN_FILE", Path.home() / ".config" / "grizzle_connect" / "tokens.json")
)


class CloudError(Exception):
    pass


class CloudClient:
    """Minimal stdlib client for the United Chargers cloud REST API (no requests dependency)."""

    def __init__(self, base_url: str = CLOUD_URL, token: str | None = None, refresh_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.refresh_token = refresh_token

    # --- transport ---------------------------------------------------------

    def _raw(self, method: str, path: str, body: dict | None = None, auth: bool = True) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        for key, value in APP_HEADERS.items():
            req.add_header(key, value)
        if auth and self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, _parse(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, _parse(err.read())
        except urllib.error.URLError as err:
            raise CloudError(f"cannot reach {self.base_url}: {err.reason}") from err

    def request(self, method: str, path: str, body: dict | None = None) -> Any:
        """Like the app's baseQuery: on 401, refresh the token once and retry."""
        status, payload = self._raw(method, path, body)
        if status == 401 and self.token and self.refresh_token:
            self.refresh()
            status, payload = self._raw(method, path, body)
        if status >= 400:
            raise CloudError(f"{method} {path} -> HTTP {status}: {_short(payload)}")
        return payload

    # --- auth --------------------------------------------------------------

    def login(self, email_or_phone: str, password: str) -> dict:
        status, data = self._raw("POST", "/client/auth/login",
                                 {"emailOrPhone": email_or_phone, "password": password}, auth=False)
        if status >= 400 or not isinstance(data, dict) or "token" not in data:
            raise CloudError(f"login failed (HTTP {status}): {_short(data)}")
        if data.get("isVerified") is False:
            raise CloudError("account is not verified; finish verification in the app first")
        self._store(data)
        return data

    def refresh(self) -> dict:
        status, data = self._raw("POST", "/client/auth/refresh-token",
                                 {"refreshToken": self.refresh_token}, auth=False)
        if status >= 400 or not isinstance(data, dict) or "token" not in data:
            raise CloudError(f"token refresh failed (HTTP {status}); log in again")
        self._store(data)
        return data

    def _store(self, data: dict) -> None:
        self.token = data["token"]
        self.refresh_token = data.get("refreshToken") or self.refresh_token

    # --- endpoints ---------------------------------------------------------

    def stations(self) -> list[dict]:
        data = self.request("GET", "/client/stations")
        if isinstance(data, dict):
            return data.get("stations") or []
        return data if isinstance(data, list) else []

    def firmware(self, station_id: str) -> Any:
        return self.request("GET", f"/client/stations/{station_id}/firmware")


def _parse(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def _short(payload: Any) -> str:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return text[:400]


def load_token_file(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        raise CloudError(f"no token file at {path}; log in with grizzle_connect.py or pass --email")
    data = json.loads(path.read_text())
    return data.get("token"), data.get("refreshToken")


def save_token_file(path: Path, client: CloudClient) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"token": client.token, "refreshToken": client.refresh_token}))
    path.chmod(0o600)


def make_client(args: argparse.Namespace) -> CloudClient:
    client = CloudClient(base_url=args.base_url)
    if args.email:
        password = os.environ.get("GRIZZLE_CLOUD_PASSWORD") or getpass.getpass("Cloud password: ")
        client.login(args.email, password)
        if args.save_tokens:
            save_token_file(Path(args.token_file), client)
    else:
        client.token, client.refresh_token = load_token_file(Path(args.token_file))
    return client


def find_station(stations: list[dict], serial: str | None) -> dict:
    def ident(s: dict) -> str:
        return s.get("serialNumber") or s.get("identity") or s.get("_id") or s.get("id") or ""

    if serial:
        for s in stations:
            if serial in (ident(s), s.get("_id"), s.get("id")):
                return s
        raise CloudError(f"no station matching {serial!r} on this account (have: "
                         f"{', '.join(ident(s) for s in stations) or 'none'})")
    if len(stations) == 1:
        return stations[0]
    if not stations:
        raise CloudError("this account has no stations")
    raise CloudError("multiple stations on this account; pass --serial "
                     f"(one of: {', '.join(ident(s) for s in stations)})")


def cmd_check(args: argparse.Namespace) -> int:
    client = make_client(args)
    station = find_station(client.stations(), args.serial)
    station_id = station.get("_id") or station.get("id")
    if not station_id:
        raise CloudError(f"station {station.get('serialNumber') or '?'} has no id in the cloud response")
    serial = station.get("serialNumber") or station.get("identity") or station_id
    installed = (station.get("bootNotification") or {}).get("firmwareVersion")

    fw = client.firmware(station_id)
    if args.json:
        print(json.dumps({"serial": serial, "installed": installed, "firmware": fw}, indent=2))
        return 0

    latest = (fw or {}).get("latestFirmware") or {}
    model = ((fw or {}).get("station") or {}).get("model") or {}
    print(f"Station:   {serial}  ({model.get('displayName') or station.get('displayName') or 'unknown model'})")
    print(f"Installed: {installed or 'unknown'}")
    if (fw or {}).get("hasUpdates"):
        print(f"Cloud offers an UPDATE: version {latest.get('version') or 'unknown'}")
        if latest.get("changelog"):
            print("Changelog:")
            for line in str(latest["changelog"]).splitlines():
                print(f"  {line}")
        can = (fw or {}).get("canUpdate")
        print(f"canUpdate (cloud would push now): {can}")
        print("\nNote: the app never sees the download URL; the cloud sends it to the charger over OCPP.")
        print("To capture that URL without touching the charger, use the capture step (not yet run).")
    else:
        print("Cloud offers NO update; the charger is considered up to date.")
    # Show any extra fields the app ignores, which might hint at a download location.
    known = {"hasUpdates", "canUpdate", "latestFirmware", "station"}
    extra = {k: v for k, v in (fw or {}).items() if k not in known} if isinstance(fw, dict) else {}
    if extra:
        print(f"\nExtra response fields (not used by the app):\n{json.dumps(extra, indent=2)}")
    return 0


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def doh_resolve(host: str, doh_url: str = DOH_URL) -> str:
    """Resolve an A record over DNS-over-HTTPS, bypassing any LAN DNS override."""
    req = urllib.request.Request(f"{doh_url}?name={host}&type=A", headers={"accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, ValueError) as err:
        raise CloudError(f"DoH resolve of {host} via {doh_url} failed: {err}") from err
    ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1 and a.get("data")]
    if not ips:
        raise CloudError(f"DoH returned no A record for {host} (did the override leak into DoH?)")
    return ips[0]


def load_identity(state_path: Path, serial: str | None) -> dict[str, Any]:
    """Pull the charger's cloud identity (serial, boot fields, Auth key) from the server's state.json."""
    if not state_path.exists():
        raise CloudError(f"no server state at {state_path}; pass --state, or --serial/--auth-key explicitly")
    stations = (json.loads(state_path.read_text()) or {}).get("stations") or {}
    if not stations:
        raise CloudError(f"{state_path} has no stations")
    if serial:
        station = stations.get(serial)
        if station is None:
            raise CloudError(f"{serial} not in {state_path} (have: {', '.join(stations)})")
    elif len(stations) == 1:
        station = next(iter(stations.values()))
    else:
        raise CloudError(f"multiple stations in {state_path}; pass --serial (one of: {', '.join(stations)})")
    return station


def download_image(location: str, out_path: Path) -> dict[str, Any]:
    """Fetch the firmware image from an UpdateFirmware location (http/https/ftp) to disk."""
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        raise CloudError(f"cannot create {out_path.parent} ({err}); pass --out to a writable directory") from err
    sha = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(location, timeout=120) as resp, out_path.open("wb") as fh:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                fh.write(chunk)
                sha.update(chunk)
                size += len(chunk)
    except (urllib.error.URLError, OSError, ValueError) as err:
        raise CloudError(f"download from {location} failed: {err}") from err
    return {"path": str(out_path), "size": size, "sha256": sha.hexdigest()}


async def _capture(args: argparse.Namespace) -> int:
    import aiohttp  # lazy: only the capture path needs it
    from aiohttp import abc as aiohttp_abc

    state_path = Path(args.state) if args.state else None
    identity: dict[str, Any] = {}
    if state_path and state_path.exists():
        identity = load_identity(state_path, args.serial)
    serial = identity.get("id") or args.serial
    if not serial:
        raise CloudError("no serial: pass --serial, or a --state file with the charger's identity")
    boot = identity.get("boot") or {}
    auth_key = args.auth_key or identity.get("ocppAuthKey")
    if not auth_key:
        where = args.state if state_path else "the server state"
        raise CloudError(
            f"no Auth key for {serial}: it is not yet recorded in {where}. Deploy the updated server and let the "
            "charger reconnect once (then it appears as ocppAuthKey), or pass --auth-key."
        )
    claim = args.claim_firmware or "UDGRW070L-00.00.1"

    # Where to connect: an explicit --ocpp-url (for testing), else the real cloud pinned via DoH.
    captured: dict[str, Any] = {}
    update_seen = asyncio.Event()

    async def handle(action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if action == "UpdateFirmware":
            captured["location"] = payload.get("location")
            captured["retrieveDate"] = payload.get("retrieveDate")
            captured["raw"] = payload
            update_seen.set()
            return {}
        if action == "GetConfiguration":
            cfg = identity.get("config") or {}
            keys = payload.get("key") or list(cfg)
            return {"configurationKey": [{"key": k, "readonly": False, "value": str(cfg.get(k, ""))}
                                         for k in keys if k in cfg],
                    "unknownKey": [k for k in keys if k not in cfg]}
        if action in ("ChangeConfiguration", "TriggerMessage", "Reset", "ChangeAvailability"):
            return {"status": "Accepted"}
        if action == "GetDiagnostics":
            return {}
        raise _NotImplementedCall(action)

    ssl_param: Any
    if args.ocpp_url:
        url, resolver = args.ocpp_url, None
        ssl_param = False if url.startswith("ws://") else None
    else:
        ip = args.cloud_ip or doh_resolve(OCPP_CLOUD_HOST, args.doh_url)
        print(f"Resolved {OCPP_CLOUD_HOST} -> {ip} (via {'--cloud-ip' if args.cloud_ip else 'DoH'})")

        class _Pinned(aiohttp_abc.AbstractResolver):
            async def resolve(self, host, port=0, family=0):
                return [{"hostname": host, "host": ip if host == OCPP_CLOUD_HOST else host,
                         "port": port, "family": family, "proto": 0, "flags": 0}]

            async def close(self):
                pass

        # The real cloud routes by the chargeBoxId in the path (bare /ocpp1.6 is closed with 1002).
        url, resolver, ssl_param = f"wss://{OCPP_CLOUD_HOST}{OCPP_CLOUD_PATH}/{serial}", _Pinned(), None

    connector = aiohttp.TCPConnector(resolver=resolver) if resolver else None
    async with aiohttp.ClientSession(connector=connector) as session:
        client = OcppWsClient(session, serial, auth_key, handle)
        print(f"Connecting to {url} as {serial} (claiming firmware {claim}) ...")
        await client.connect(url, ssl_param)
        try:
            boot_conf = await client.call("BootNotification", {
                "chargePointVendor": boot.get("chargePointVendor") or "UnitedChargers",
                "chargePointModel": boot.get("chargePointModel") or "GRD 40A 2025",
                "chargePointSerialNumber": boot.get("chargePointSerialNumber") or serial,
                "firmwareVersion": claim,
                "meterType": boot.get("meterType") or "0",
            })
            print(f"BootNotification -> {boot_conf.get('status')}")
            for cid in range(0, int(identity.get("connectorCount") or 1) + 1):
                await client.call("StatusNotification",
                                  {"connectorId": cid, "status": "Available", "errorCode": "NoError",
                                   "timestamp": _iso_now()})

            if not args.no_trigger:
                def _trigger() -> str:
                    rest = make_client(args)
                    station = find_station(rest.stations(), serial)
                    sid = station.get("_id") or station.get("id")
                    rest.request("POST", f"/client/stations/{sid}/firmware", {})
                    return sid
                print("Triggering a firmware update via POST /client/stations/{id}/firmware ...")
                try:
                    await asyncio.to_thread(_trigger)
                except CloudError as err:
                    print(f"  (trigger POST returned: {err})")

            print(f"Waiting up to {args.timeout}s for the cloud to send UpdateFirmware ...")
            try:
                await asyncio.wait_for(update_seen.wait(), args.timeout)
            except asyncio.TimeoutError:
                raise CloudError("no UpdateFirmware received; the cloud may not consider the claimed version "
                                 "outdated. Try a lower --claim-firmware.") from None

            location = captured.get("location")
            print(f"\nCaptured UpdateFirmware location:\n  {location}")
            await client.call("FirmwareStatusNotification", {"status": "Downloading"})

            result: dict[str, Any] = {"serial": serial, "claimedFirmware": claim, **captured}
            if args.no_download:
                print("--no-download: not fetching the image.")
            else:
                if args.out:
                    out_dir = Path(args.out)
                elif state_path:
                    out_dir = state_path.resolve().parent / "firmware"
                else:
                    out_dir = Path.cwd() / "captured-firmware"
                name = args.name or location.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0] or "firmware.bin"
                info = await asyncio.to_thread(download_image, location, out_dir / name)
                await client.call("FirmwareStatusNotification", {"status": "Downloaded"})
                result.update(info)
                sidecar = Path(info["path"]).with_name(Path(info["path"]).name + ".json")
                meta = {"version": "latest-offered", "source": "cloud-capture", "location": location,
                        "sha256": info["sha256"], "size": info["size"], "capturedAt": _iso_now(),
                        "claimedFirmware": claim, "model": boot.get("chargePointModel")}
                sidecar.write_text(json.dumps(meta, indent=2))
                print(f"\nSaved {info['size']} bytes to {info['path']}")
                print(f"  sha256 {info['sha256']}")
                print(f"  metadata {sidecar}")
                head = Path(info["path"]).read_bytes()[:4]
                if head[:2] == b"UC":
                    kind = "United Chargers OTA container"
                elif head[:1] == bytes([0xE9]):
                    kind = "bare ESP32 image"
                else:
                    kind = "unrecognised"
                print(f"  magic {head.hex()} ({kind})")
        finally:
            await client.close()

    if args.json:
        print(json.dumps(result, indent=2))
    print("\nThe real charger was never contacted; nothing was installed on it.")
    return 0


class _NotImplementedCall(Exception):
    def __init__(self, action: str) -> None:
        super().__init__(action)
        self.action = action


class OcppWsClient:
    """A minimal OCPP 1.6-J WebSocket client, used to impersonate the user's own charger to the cloud."""

    def __init__(self, session: Any, serial: str, auth_key: str, handler: Any) -> None:
        self._session = session
        self._serial = serial
        self._auth_key = auth_key
        self._handler = handler
        self._ws: Any = None
        self._pending: dict[str, asyncio.Future] = {}
        self._reader: asyncio.Task | None = None

    async def connect(self, url: str, ssl_param: Any) -> None:
        import aiohttp
        self._ws = await self._session.ws_connect(
            url, protocols=("ocpp1.6",), heartbeat=120,
            headers={"Authorization": aiohttp.BasicAuth(self._serial, self._auth_key).encode()},
            ssl=ssl_param,
        )
        self._reader = asyncio.ensure_future(self._run())

    async def _run(self) -> None:
        import aiohttp
        async for msg in self._ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            frame = json.loads(msg.data)
            if frame[0] == 3:
                fut = self._pending.get(frame[1])
                if fut and not fut.done():
                    fut.set_result(frame[2])
            elif frame[0] == 4:
                fut = self._pending.get(frame[1])
                if fut and not fut.done():
                    fut.set_exception(CloudError(f"cloud CALLERROR {frame[2]}: {frame[3]}"))
            elif frame[0] == 2:
                await self._dispatch(frame[1], frame[2], frame[3])

    async def _dispatch(self, uid: str, action: str, payload: dict[str, Any]) -> None:
        try:
            reply = await self._handler(action, payload)
            await self._ws.send_str(json.dumps([3, uid, reply]))
        except _NotImplementedCall:
            await self._ws.send_str(json.dumps([4, uid, "NotImplemented", action, {}]))

    async def call(self, action: str, payload: dict[str, Any], timeout: float = 30) -> dict[str, Any]:
        import uuid
        uid = uuid.uuid4().hex[:12]
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[uid] = fut
        await self._ws.send_str(json.dumps([2, uid, action, payload]))
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(uid, None)

    async def close(self) -> None:
        if self._reader:
            self._reader.cancel()
        if self._ws:
            await self._ws.close()


def cmd_capture(args: argparse.Namespace) -> int:
    return asyncio.run(_capture(args))


def build_parser() -> argparse.ArgumentParser:
    # Auth options are shared by every subcommand and given after it (check --token-file ...).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--base-url", default=os.environ.get("GRIZZLE_CLOUD_URL", CLOUD_URL),
                        help="cloud base URL (default: the real United Chargers cloud)")
    common.add_argument("--token-file", default=str(DEFAULT_TOKEN_FILE),
                        help="bearer-token file saved by grizzle_connect.py")
    common.add_argument("--email", help="log in with this email instead of a saved token "
                                        "(password via $GRIZZLE_CLOUD_PASSWORD or prompt)")
    common.add_argument("--save-tokens", action="store_true",
                        help="after --email login, save tokens to --token-file")

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", parents=[common],
                       help="read-only: ask the cloud whether a firmware update is offered")
    c.add_argument("--serial", help="station serial (required only if the account has more than one)")
    c.add_argument("--json", action="store_true", help="print the raw cloud response as JSON")
    c.set_defaults(func=cmd_check)

    cap = sub.add_parser(
        "capture", parents=[common],
        help="impersonate YOUR charger to the cloud, claim an old firmware version, capture + download the image",
        description="Connects to the real cloud AS your station (never touches the charger), reports an older "
                    "firmware version so the cloud sends an UpdateFirmware, and downloads the image it points to.",
    )
    cap.add_argument("--state", default=os.environ.get("GRIZZLE_STATE_FILE")
                     or str(Path(os.environ.get("GRIZZLE_DATA_DIR", "/data")) / "state.json"),
                     help="server state.json holding the charger's identity + recorded Auth key")
    cap.add_argument("--serial", help="station serial (if state.json or the account has more than one)")
    cap.add_argument("--auth-key", help="charger's OCPP Auth key (overrides the one recorded in state.json)")
    cap.add_argument("--claim-firmware", help="the (older) firmware version to report (default a very low version)")
    cap.add_argument("--cloud-ip", help="pin the cloud IP instead of resolving over DoH")
    cap.add_argument("--doh-url", default=DOH_URL, help="DNS-over-HTTPS endpoint used to bypass the LAN override")
    cap.add_argument("--ocpp-url", help="connect to this ws(s):// URL directly instead of the real cloud (testing)")
    cap.add_argument("--timeout", type=float, default=180.0, help="seconds to wait for UpdateFirmware")
    cap.add_argument("--out", help="directory to save the image in (default <state dir>/firmware)")
    cap.add_argument("--name", help="filename to save the image as (default from the location URL)")
    cap.add_argument("--no-trigger", action="store_true",
                     help="do not POST the update trigger; just wait (e.g. trigger it from the app yourself)")
    cap.add_argument("--no-download", action="store_true", help="capture the location only; do not download")
    cap.add_argument("--json", action="store_true", help="print the capture result as JSON")
    cap.set_defaults(func=cmd_capture)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CloudError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
