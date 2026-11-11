<!--
DRAFT vendor disclosure. Review before sending. Fill every [BRACKETED] placeholder.
Do NOT include personal contact details in any copy committed to a public repo.
Suggested channel: United Chargers support / security contact (security@ or support@
unitedchargers.com); request a security/PSIRT contact if none is published.
-->

# Security disclosure — Grizzl-E Duo (United Chargers)

**To:** United Chargers Inc. — Product Security / Engineering
**From:** [YOUR NAME] — independent security researcher — [YOUR CONTACT EMAIL]
**Date:** [SEND DATE]
**Disclosure policy:** Coordinated disclosure. I am reporting privately and will withhold
public details for **90 days** from this date (or until a fixed firmware ships, whichever
is sooner), and will adjust that timeline reasonably on request.

## Affected product

- **Device:** Grizzl-E Duo (dual-connector EVSE).
- **Wi-Fi / OCPP firmware:** `UDGRW070L-04.03.2` (ESP32, ESP-IDF v4.4.4).
- **Main-board firmware:** `GRD077L-01.10.0` (STM32F4 / Cortex-M4).
- **Tested on:** a single owned unit; the image was obtained from your own OTA cloud for
  that unit (not redistributed). The hardcoded values below are baked into the firmware
  image and therefore apply to **every unit** running it.

All findings were derived from static analysis of the firmware image; **Finding 1 (N1
below) was additionally confirmed at runtime against a live unit on the local network**
using only non-destructive requests.

## Summary of issues

| ID | Severity | Issue |
|----|----------|-------|
| 1 | **Critical** | Unauthenticated web control plane — LAN/SoftAP attacker can reboot, factory-reset, change current limits, and overwrite the web-admin credentials with no authentication. |
| 2 | **High** | OCPP (WebSocket/TLS) client does not validate the server certificate — a network MITM can impersonate the cloud and issue OCPP commands and `UpdateFirmware`. |
| 3 | **High** | Firmware update (OTA) is not cryptographically signed, is fetched over plaintext FTP, and its MD5 integrity check is runtime-skippable. |
| 4 | **High / potential RCE** | Unbounded `strcpy` of attacker-controlled OCPP JSON string fields into fixed stack buffers (memory corruption). |
| 5 | **Medium** | Hardcoded default web-UI credentials and hardcoded Wi-Fi station credentials shipped in firmware. |
| 6 | **Medium** | "OCPP unlock" authorization is computed locally with no server secret (forgeable); hardcoded shared API key + serial phone-home to a third party. |

---

## 1. Unauthenticated web control plane — Critical

The ESP32 HTTP server protects `/service` and `/ocppconfig` with HTTP Basic auth, but the
following handlers are registered in a **no-authentication** route table and perform state
changes with **no credential check whatsoever**:

- `POST /pageEvent` — `reboot`, `factoryReset`, `fullFactoryReset`, `stationCurrentLimit`,
  `maxCurrent`, `minCurrent`, `typeRelay`, `stationSN`, and `md5hash` (the stored web-UI
  password hash), among others.
- `POST /configHttp` — sets `httpUsername` / `httpPassword` (the web-UI admin credentials)
  **without requiring the current password**.
- `POST /config`, `POST /configAP` — change station / SoftAP network configuration.

**Impact.** Any device on the same LAN, or associated to the charger's SoftAP, can with a
single unauthenticated HTTP request factory-reset the charger, change charge-current
limits, rewrite the serial, and set the admin password to an attacker-chosen value — which
also defeats the Basic auth protecting `/service` and `/ocppconfig` (the attacker simply
sets the credentials first). No prior knowledge or credentials are required.

**Confirmed at runtime** on a live unit: `/ocppconfig` and `/service` returned `401`
(Basic-auth challenge), while `/pageEvent`, `/config`, `/configAP`, and `/configHttp`
returned `200` and processed the request with no credentials supplied. The confirmation was
non-destructive (no state-changing values were sent).

**Suggested fix.** Route every state-changing / configuration endpoint through the same
authentication check as `/service` and `/ocppconfig`; require the current password for any
credential change; prefer per-session tokens over HTTP Basic.

## 2. OCPP channel does not validate the server certificate — High

The firmware bundles a public CA (ISRG Root X1) but wires it only to the registration
client; the OCPP WebSocket (`wss`) client is configured with no trust anchor and does not
verify the server certificate.

**Impact.** A network attacker who can intercept or redirect the charger's connection to
the OCPP backend (ARP/DNS spoofing on the LAN, rogue upstream, etc.) can impersonate the
cloud and send arbitrary OCPP messages — including `UpdateFirmware` (see issue 3).

**Suggested fix.** Enable server-certificate verification on the OCPP TLS client against a
pinned CA / host; fail closed on validation errors.

## 3. Firmware update is unsigned (and integrity is weak) — High

- The update image is fetched over **plaintext FTP**; credentials, when present, are parsed
  from the URL, and anonymous login is accepted.
- Image acceptance relies on a CRC32, an MD5, and a magic byte. **None is a cryptographic
  signature.** CRC and MD5 are recomputable by whoever supplies the image.
- The MD5 check is gated by a runtime flag; when that flag is clear the code logs
  "MD5 disabled!" and proceeds as success, leaving only CRC + magic byte.

**Impact.** Combined with issue 2, an attacker able to present an OCPP `UpdateFirmware`
(or control the referenced FTP content) can flash **arbitrary firmware** — full persistent
device takeover.

**Suggested fix.** Require a digital signature (e.g. ECDSA/RSA over the image) verified
against a vendor public key held in the device, independent of CRC/MD5; serve updates over
authenticated TLS; remove the ability to disable integrity checks in production builds;
consider ESP32 Secure Boot / signed app images.

## 4. Unbounded copies of OCPP JSON fields into stack buffers — High (potential RCE)

Several OCPP message parsers copy attacker-sized JSON string values into small fixed-size
stack buffers using an unbounded `strcpy`, guarded only by null/type checks — for example
the `idTagInfo` fields (`status`, `expiryDate`, `parentIdTag`) of `StartTransaction`/
`Authorize` responses, and the `DataTransfer`/`Heartbeat` response fields. A string longer
than the destination overflows the stack frame.

**Impact.** The path from the network to the overflow has been traced end to end: inbound
WebSocket frame → `cJSON_Parse` → the OCPP action dispatcher → the vulnerable parser's
unbounded `strcpy` of a network-supplied JSON string. Because these parsers handle
**responses to the charger's own requests** (e.g. `Heartbeat`, `Authorize`,
`StartTransaction`), a malicious or MITM'd OCPP server (enabled by issue 2) only has to
answer a routine request with an oversized field (e.g. `idTagInfo.status`). The guaranteed
outcome is remote stack corruption (crash/DoS); remote code execution is plausible (no
ASLR, attacker-known image layout).

**Suggested fix.** Replace `strcpy` with length-bounded copies (`strlcpy`/`snprintf` with
the destination size) throughout the OCPP/HTTP parsers; validate field lengths before copy.

## 5. Shipped default / hardcoded credentials — Medium

- **Web UI:** built-in Basic-auth credentials for `/service` and `/ocppconfig` are present
  in firmware (and, per issue 1, can be overwritten unauthenticated anyway).
- **Wi-Fi:** two cleartext station SSID+password pairs are embedded and a live code path
  loads them into the Wi-Fi station config. Their arming appears tied to internal
  connectivity-recovery and production-test paths; we did **not** find a remote trigger, so
  we are **not** characterizing this as a remote backdoor — but shipping cleartext
  credentials that a code path will connect to is a defect, and the SSID/PSK values are
  trivially extractable from the image.

**Suggested fix.** Remove embedded Wi-Fi credentials from production images; make web-UI
credentials unique-per-device and user-set on first use.

## 6. Forgeable "OCPP unlock" + hardcoded third-party key — Medium

- The paid "OCPP unlock" check compares the server's reply against a value the device
  computes **locally** as an unkeyed digest of the public serial plus a constant string —
  no server-side secret — so the expected value is computable by anyone.
- A single shared API key is baked into every unit and sent, with the device serial, to a
  third-party backend. A shared, extractable key authenticates nothing device-specific.

**Suggested fix.** If the unlock is a licensing control, authenticate it with a server-held
secret / signed token bound to the serial; do not ship a shared static API key.

---

## Reproduction / technical detail

A detailed technical write-up with firmware addresses and a **non-destructive** proof-of-
concept for issue 1 is available on request. I have not published any exploit, and the
firmware image is not redistributed. I'm happy to work with your team, validate fixes, and
coordinate on timing and credit.

**Reporter:** [YOUR NAME], [YOUR CONTACT EMAIL], [OPTIONAL PGP KEY].
