#!/usr/bin/env python3
"""Read or change the OCPP server URL on a Grizzl-E through its local web interface.

Works on chargers whose web page has "Advanced OCPP Settings" (Smart/GRS firmware is
confirmed; try it on a Connect/Duo and see whether /info answers). No dependencies.

    python scripts/configure-charger.py --host 192.168.1.50 show
    python scripts/configure-charger.py --host 192.168.1.50 set ws://192.168.1.10:9000/ocpp1.6/
    python scripts/configure-charger.py --host 192.168.1.50 reset      # back to United Chargers' cloud

The charger appends its station ID to the URL you give it, so end it with a slash.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def get_info(host: str) -> dict:
    with urllib.request.urlopen(f"http://{host}/info", timeout=10) as resp:
        return json.loads(resp.read().decode())


def set_ocpp(host: str, url: str, auth_key: str, station_id: str) -> None:
    # The firmware wants a URL-encoded form body wrapped in JSON string quotes.
    form = urllib.parse.urlencode({"ocppUrl": url, "authKey": auth_key, "stationId": station_id})
    body = json.dumps(form).encode()
    req = urllib.request.Request(
        f"http://{host}/ocpp", data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()
    deadline = time.time() + 30
    while time.time() < deadline:
        time.sleep(2)
        try:
            info = get_info(host)
        except (urllib.error.URLError, ValueError):
            continue
        if info.get("ocppUrl") == url:
            print(f"charger now uses {url} (station id {info.get('stationId')})")
            return
    print("warning: the charger has not confirmed the new URL yet; check /info again in a minute", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="charger IP or hostname")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("show", help="print the charger's /info")
    s = sub.add_parser("set", help="point the charger at a server")
    s.add_argument("url", help="e.g. ws://192.168.1.10:9000/ocpp1.6/")
    s.add_argument("--auth-key", help="OCPP auth key (default: keep the current one)")
    s.add_argument("--station-id", help="default: keep the current one")
    sub.add_parser("reset", help="restore the factory (United Chargers) server")
    args = parser.parse_args()

    try:
        info = get_info(args.host)
    except (urllib.error.URLError, ValueError) as err:
        sys.exit(
            f"could not read http://{args.host}/info: {err}\n"
            "This charger may not expose the Smart-style web interface; use the app or DNS override instead."
        )
    if args.cmd == "show":
        print(json.dumps(info, indent=2))
    elif args.cmd == "set":
        set_ocpp(
            args.host,
            args.url,
            args.auth_key or info.get("authKey") or "",
            args.station_id or info.get("stationId") or info.get("serialNumber") or "",
        )
    elif args.cmd == "reset":
        set_ocpp(args.host, info["defaultOcppUrl"], info.get("defaultAuthKey") or "", info.get("serialNumber") or "")


if __name__ == "__main__":
    main()
