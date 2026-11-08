#!/usr/bin/env python3
"""Read or change the OCPP server URL on a Grizzl-E through its local web interface.

The charger's web page is protected with HTTP Basic auth (the login you set on the
"Page Access" screen; the factory login is in the manual). Pass it with
``--username``/``--password``, or set ``GRIZZLE_WEB_PASSWORD`` to avoid typing it; the
script prompts if neither is given. No dependencies beyond Python 3.

    python scripts/configure-charger.py --host 192.168.1.50 status          # live readings (no login needed)
    python scripts/configure-charger.py --host 192.168.1.50 show            # OCPP settings
    python scripts/configure-charger.py --host 192.168.1.50 set ws://192.168.1.10:9000/ocpp1.6/
    python scripts/configure-charger.py --host 192.168.1.50 reset           # back to United Chargers' cloud

The charger appends its station ID to the URL you give it, so end it with a slash.
Endpoints: ``POST /main`` (status), ``GET /info`` and ``POST /ocpp`` (OCPP settings), as
on the Grizzl-E Smart. Whether a Connect/Duo exposes ``/info`` and ``/ocpp`` is firmware
dependent; ``show`` tells you.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class Charger:
    def __init__(self, host: str, username: str | None, password: str | None) -> None:
        self.base = f"http://{host.strip().removeprefix('http://').rstrip('/')}"
        self.headers: dict[str, str] = {}
        if username is not None and password is not None:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"

    def request(self, method: str, path: str, body: bytes | None = None, content_type: str | None = None) -> dict:
        headers = dict(self.headers)
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as err:
            if err.code == 401:
                sys.exit(f"{method} {path}: the charger rejected the login (HTTP 401). Check --username/--password.")
            if err.code == 404:
                sys.exit(f"{method} {path}: not found (HTTP 404). This firmware's web interface doesn't expose it.")
            sys.exit(f"{method} {path}: HTTP {err.code}")
        except urllib.error.URLError as err:
            sys.exit(f"could not reach {self.base}: {err.reason}")
        if not raw:
            return {}
        try:
            return json.loads(raw.decode())
        except ValueError:
            return {"raw": raw.decode(errors="replace")}

    def status(self) -> dict:
        return self.request("POST", "/main")

    def info(self) -> dict:
        return self.request("GET", "/info")

    def set_ocpp(self, url: str, auth_key: str, station_id: str) -> None:
        # The firmware wants a URL-encoded form body wrapped in JSON string quotes.
        form = urllib.parse.urlencode({"ocppUrl": url, "authKey": auth_key, "stationId": station_id})
        self.request("POST", "/ocpp", json.dumps(form).encode(), "application/x-www-form-urlencoded")
        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(2)
            info = self.info()
            if info.get("ocppUrl") == url:
                print(f"charger now uses {url} (station id {info.get('stationId')})")
                return
        print("warning: the charger has not confirmed the new URL yet; run 'show' again in a minute", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="charger IP or hostname")
    parser.add_argument(
        "--username",
        "-u",
        default=os.environ.get("GRIZZLE_WEB_USERNAME", "admin"),
        help="web interface login (default: admin, or $GRIZZLE_WEB_USERNAME)",
    )
    parser.add_argument(
        "--password",
        "-p",
        default=os.environ.get("GRIZZLE_WEB_PASSWORD"),
        help="web interface password (default: $GRIZZLE_WEB_PASSWORD, else prompted)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="live readings from POST /main (works without a login)")
    sub.add_parser("show", help="print the OCPP settings from GET /info")
    s = sub.add_parser("set", help="point the charger at a server")
    s.add_argument("url", help="e.g. ws://192.168.1.10:9000/ocpp1.6/")
    s.add_argument("--auth-key", help="OCPP auth key (default: keep the current one)")
    s.add_argument("--station-id", help="default: keep the current one")
    sub.add_parser("reset", help="restore the factory (United Chargers) server")
    args = parser.parse_args()

    password = args.password
    if args.cmd != "status" and password is None:
        password = getpass.getpass(f"Web interface password for {args.username}@{args.host}: ")
    charger = Charger(args.host, args.username, password)

    if args.cmd == "status":
        print(json.dumps(charger.status(), indent=2))
        return
    info = charger.info()
    if args.cmd == "show":
        print(json.dumps(info, indent=2))
    elif args.cmd == "set":
        charger.set_ocpp(
            args.url,
            args.auth_key or info.get("authKey") or "",
            args.station_id or info.get("stationId") or info.get("serialNumber") or "",
        )
    elif args.cmd == "reset":
        if not info.get("defaultOcppUrl"):
            sys.exit("the charger did not report a defaultOcppUrl; set the cloud URL explicitly with 'set'")
        charger.set_ocpp(info["defaultOcppUrl"], info.get("defaultAuthKey") or "", info.get("serialNumber") or "")


if __name__ == "__main__":
    main()
