# Grizzl-E Duo firmware — security analysis

Target: `UDGRW070L-04.03.2.bin` (captured from the United Chargers cloud; see `README.md`).
Scope of this pass: the **ESP32 Wi-Fi/OCPP application** (the networked attack surface).
Evidence is graded **CONFIRMED** (present in the binary, and the string is referenced by
code — a 32-bit pointer to it sits in an Xtensa literal pool in the `.text`/IROM segment) vs
**NEEDS-CODE** (runtime behavior that requires decompiling the Xtensa code to confirm — stock
Ghidra/REA can't disassemble Xtensa; see `GHIDRA-IMPORT.md`).

---

## Verification pass — 2026-11-11 (independent re-derivation)

The six findings below were independently re-derived from the same image using a
**separate Xtensa disassembler** — capstone 6.0 `CS_ARCH_XTENSA` (not the Ghidra Xtensa
extension) — plus REA for the ARM main board. Each finding was re-confirmed from raw
disassembly; a discovery sweep then hunted for new issues and each candidate was
adversarially re-checked. Tooling + method preserved in `firmware/analysis/` is not
required to read this; addresses below are real load addresses (IROM `0x400d0020+`).

### Verdicts on findings 1–6

| # | Verdict | Correction / refinement |
|---|---------|-------------------------|
| 1 | **Mechanism CONFIRMED; "remote backdoor" framing NOT supported** | The two credentials have **different, both-internal** arming paths (see below). No remote/attacker-inducible arming was proven. |
| 2 | **CONFIRMED** | Open questions resolved (creds/ordering/`/debug`) — but **made moot by new finding N1** (creds are rewritable without auth). |
| 3 | **CONFIRMED** | JSON key is `type:"register"` (no `"register"` key); transport is **HTTPS with CA validation**. |
| 4 | **CONFIRMED** | Forgeable as described. (Helper addresses in the v0.6.0 capture note were mis-offset: the hash is `0x4013ba44`, hex-encode `0x400e82e8`, main fn `0x400ef108`.) |
| 5 | **CONFIRMED (sharpened)** | Image *does* contain RSA/ECDSA (for TLS); the precise, confirmed claim is **"no signature gates the OTA."** See also N4 (MD5 is skippable). |
| 6 | **Part A CONFIRMED; Part B UNVERIFIABLE** | No embedded private key; ISRG Root X1 present. Main-board UART→relay gating **not proven** — REA mis-decoded the Thumb image (loaded as ARM mode), so that pass is low-confidence; needs the Ghidra Cortex-M import. |

### Corrections to finding 1 (important — changes the risk classification)

- The set-config helper `FUN_0001f834` (`0x400ef854`) is **confirmed**: `memset` of a
  `0x8c`-byte `wifi_config_t`, `strcpy` SSID at `buf+0`, `strcpy` password at `buf+0x20`,
  then `esp_wifi_set_config(WIFI_IF_STA, …)` at `0x400ef923`. The caller
  `FUN_0001f2d8` (`0x400ef2f8`) selects AndroidPapa on event bit `0x8000` and Pinpellets
  on `0x10000`. All four credential strings are referenced exactly once. **No change.**
- **But the doc conflates the two arming paths.** `FUN_0001d9a4` (`0x400ed9c4`) arms
  **only** the Pinpellets timer (`+0x800[0xf8]`), and its sole caller is `0x400d924d`
  inside TaskSys, gated on TaskSys event bit `0x10000`. The **AndroidPapa** timer
  (`+0x900[2]`) is armed by the **production-test routine `RunProdTest`** (entry
  `0x400da9ac`; also does "Set 8A"/"Set 16A"), called from TaskSys `0x400d92cd` and
  `0x400e4879` — **not** from `FUN_0001d9a4`.
- Both triggers are **internal state transitions** (a connectivity/service event and a
  production-test path); **no remote or attacker-inducible path to arm either bit was
  found** in the loaded segments. `FUN_0001f834` is a **general** Wi-Fi-config helper
  (6 call sites, incl. `0x400efa01`/`0x400efc69` for normal config), not a
  backdoor-dedicated routine.
- **Reclassification:** hardcoded cleartext STA credentials + a real credential-join
  code path, whose arming is internal and (one path) production-test. The
  "deauth-and-wait for an attacker-inducible fallback → remote takeover" model in the
  original note is **not supported by the static evidence** and should be treated as
  unproven. Still a genuine shipped-credential defect; just not a demonstrated remote
  backdoor.

### Resolved open questions from the original "Still open"

- **F2 `/ocppconfig` ordering:** username `UC_OCPP`, password `Uc_Ocpp` (dispatcher
  `0x400f0eba`, helper `0x400f0b9c`). `/service` cred `eveus`. **`/debug` is
  unauthenticated** (confirmed) and read-only telemetry. `/init` masks password fields
  (empty-string pointer) — no cred leak.
- **F1 trigger:** resolved as above (internal; two distinct paths), except the top-level
  condition that *enters* the production-test / connectivity-recovery state, which spans
  tasks and was not root-caused.

---

## Additional findings (second pass) — not in the original report

### N1. Unauthenticated web control plane — **CONFIRMED — CRITICAL (most exploitable)**
`/pageEvent` (`0x400f4974`), `/config` (`0x400f3f0c`), `/configHttp` (`0x400f44fc`) and
`/configAP` (`0x400f4710`) are registered in the **no-auth** route table (`0x400d21e0+`)
and make **zero** calls into the Basic-auth routine cluster (`0x400f0eba`–`0x400f13c0`) —
verified by disassembling each handler end to end. They perform real state changes:
- **`/pageEvent`** (POST) dispatches `reboot`, `factoryReset` (`0x400ed671`),
  `fullFactoryReset` (`0x400ed673`), `stationCurrentLimit` (`0x400ed6f5`), `maxCurrent`
  (`0x400ec85d`), `minCurrent` (`0x400ed73a`), `typeRelay` (`0x400ed786`), `stationSN`,
  **`md5hash`** (the stored web-UI password hash), `broadcastMode`, and many more.
- **`/configHttp`** sets `httpUsername` (`0x3f417054`) and `httpPassword` (`0x3f417038`)
  into the live config (`memcpy 0x4000c2c8` + field extract `0x40136e00`), with only
  length checks (`0x1f`/`0x3f`) — **no auth, and no need to present the current password.**
- **Impact:** any device on the LAN or the charger's SoftAP can, with a single
  unauthenticated POST, factory-reset the unit, change current limits, rewrite the serial,
  and **overwrite the web-admin credentials** — which **fully defeats finding 2's Basic
  auth**. No preconditions (unlike finding 1). A non-destructive confirmation PoC is in
  `tools/poc_n1_unauth_webui.py`.
- **Runtime-confirmed on hardware (2026-11-11):** the PoC was run against a live Duo on
  `UDGRW070L-04.03.2`. `/ocppconfig` and `/service` returned `401` (realm "Please enter
  login and password"), while `/pageEvent`, `/config`, `/configAP` and `/configHttp` all
  returned `200` with no credentials — N1 reproduced end to end, not just statically.

### N2. OCPP response-parser stack overflow — **CONFIRMED reachable from network — HIGH (RCE-plausible)**
Three OCPP central-system→charger response parsers `strcpy` attacker-sized cJSON
valuestrings into small fixed stack frames, guarded only by null/`cJSON_IsString`
(`0x4019b618`) checks — no length bound:
- `0x400e34c0` (`entry a1,0x70` = 112-byte frame) — `idTagInfo{status,expiryDate,
  parentIdTag}` (shape of `StartTransaction.conf` / `Authorize.conf`): `status`→`a1+0x2e`,
  `expiryDate`→`a1+0x00`, `parentIdTag`→`a1+0x19`, all via ROM `strcpy` (`0x400013ac`).
- `0x400e3064` — `DataTransfer.conf`: `status`→`a1+0x10` is **unbounded**; the `data`
  field copy at `0x400e30c0` **is** length-bounded (`0x80`), so only `status` overflows.
- `0x400e3268` (`entry a1,0x50`) — `Heartbeat.conf` `currentTime`→`a1+0x10`, unbounded.
- **Reachability — now traced end to end (correcting the first-pass "inferred" note).**
  An earlier scan missed the callers because of an Xtensa `call`-target alignment bug (the
  computed target lands +0..3 high; mask `&~3`). With that fixed, each parser has exactly
  **one** direct `call8` site, all inside a single dispatcher `0x400e38a4` that routes by an
  **OCPP action-string `strcmp` chain** (`StartTransaction`→`0x400e34c0`,
  `DataTransfer`→`0x400e3064`, `Heartbeat`→`0x400e3268`; `Authorize`→a *different*, safe
  parser `0x400e2d1d`). The full inbound chain is proven:
  `esp_websocket_client` (OCPP 1.6-J wss to `ocpp.unitedchargers.com`) →
  `TaskOcppController` (`0x400e1f78`) → `ProcessReceivedMessage` (`0x400e1a78`, copies the
  frame to a stack buffer) → `cJSON_Parse` (`0x400fee74`) at the RX router `0x400e6129` →
  messageTypeId switch → payload = cJSON array item[2] → dispatcher `0x400e38a4` → parser,
  which does `GetObjectItem`→`IsString`→`strcpy` of the **network-supplied** `valuestring`.
  The parser's JSON-root arg (`a3`) is wired from the dispatcher's payload (`a4`) via
  `or a11,a4,a4` at each call site — confirmed.
- **Trigger shape:** these are **CALLRESULT responses to charger-initiated requests**, so a
  malicious or MITM'd OCPP server (enabled by N3 — no cert validation) simply answers the
  charger's routine `Heartbeat`/`Authorize`/`StartTransaction` with an oversized field
  (e.g. `idTagInfo.status`). For `0x400e34c0` (112-byte frame, `status`→`a1+0x2e`) a value
  ≥ ~50 bytes reaches the register save area and ≥ 66 bytes overruns the frame top; there is
  no canary/length guard. **Guaranteed outcome: remote stack corruption (DoS).** RCE is
  plausible but conditional on the windowed-ABI spill state (ESP32 has no ASLR and the
  attacker has this exact image, which favors a crafted payload). Adversarially re-verified:
  verdict `REACHABLE_NETWORK`, impact `rce_plausible`.
- **Residual (not load-bearing):** the exact `WEBSOCKET_EVENT_DATA`→receive-buffer store
  inside `WebSocketEventHandler`, and `CheckInputRequestMessage`'s uniqueId→action recovery
  for CALLRESULTs, were inferred rather than instruction-traced — neither is required for
  network bytes to reach the `strcpy`.
- **Note for this project:** on your setup *your own* local server is the OCPP endpoint, so
  this is not a risk *from* your server — it is a vulnerability in the shipped firmware that
  a rogue/MITM OCPP server (or the cloud) could exploit.

### N3. OCPP (wss) channel does not validate the server certificate — **CONFIRMED — HIGH**
The bundled ISRG Root X1 CA is wired via accessor `0x400d8c48` **only** to the evse.center
`RegisterSn` client (`0x400db2ec`); the OCPP `wss` client is configured with **no trust
anchor** (no alternate anchor found). This is *why* the DNS-override local-server route
works — and it means a network MITM can impersonate the cloud and deliver OCPP commands
and `UpdateFirmware`. This is the enabler that governs finding 5's exploitability.

### N4. OTA MD5 integrity is runtime-skippable — **CONFIRMED — HIGH**
The OTA integrity routine `0x400db9e8` reads a one-byte flag at `ctx+0xa4`
(`l8ui` at `0x400dba60`) and, when zero, `beqz` (`0x400dba63`) branches past the entire
MD5 compute/compare to the **success** tail at `0x400dbaf0` (`"MD5 disabled!"`). With MD5
skipped, only CRC32 + a constant magic byte remain — both recomputable by whoever delivers
the image. Compounds finding 5.

### N5. Weak RNG for registration uid — **CONFIRMED — LOW**
The 10-char `uid` in `RegisterSn` is generated by `0x400db238` (called ×10 from
`0x400db328`) using the ROM libc `rand()` LCG (`0x40001058`), not `esp_random`. The `uid`
is a per-registration nonce, not an auth token, so impact is low (hygiene).

### N6. Plaintext SNTP — **CONFIRMED — LOW**
`time.google.com` (`0x3f40d314`) over unauthenticated SNTP; a network attacker can spoof
device time (could affect TLS validity windows or schedules). Low.

### Rejected during adversarial review (recorded to avoid re-reporting)
- *"`/pageEvent` injects commands to the STM32 over UART (`S_RX`)"* — **false positive**:
  `0x400905fc` is not the ESP32→main-board UART driver.
- *OCPP "host is operator-controlled" posture* — real facts, but no independent defect
  beyond N3.

---

## Image layout
- `UC\0\0` container (0x000–0x400 header incl. an ASCII SHA-256), then ~2 MiB region
  (littlefs/web assets + main-board `GRD077L-01.10.0` image), then the ESP32 app at
  `0x200400`.
- ESP32 app: ESP-IDF v4.4.4, chip_id 0 (ESP32), 5 segments (DROM `0x3f400020`, DRAM
  `0x3ffb0000`, IRAM `0x40080000`+`0x400870cc`, IROM/text `0x400d0020`), SHA-256 appended.

## Findings

### 1. Hardcoded Wi-Fi networks — **CONFIRMED by decompilation** — highest concern
Two hardcoded SSID + password pairs, set as the station Wi-Fi config by the firmware:

| SSID | password |
|------|----------|
| `AndroidPapa` | `321654987` |
| `Pinpellets`  | `17011976` |

Decompile (base-0 Ghidra addresses): the Wi-Fi event task `FUN_0001f2d8` (IROM `0x400ef2f8`)
waits on an event group and, on bit `0x8000`, calls `FUN_0001f834(ctx,"AndroidPapa","321654987",0)`;
on bit `0x10000`, `FUN_0001f834(ctx,"Pinpellets","17011976",0)`. `FUN_0001f834` memsets a
`0x8c`-byte `wifi_config_t`, `strcpy`s the SSID and (at +0x20) the password into it, then calls
`esp_wifi_set_config(STA, &cfg)` — i.e. it genuinely **configures the station to join that AP**.
- **Impact:** anyone within radio range who stands up an open-knowledge hotspot `AndroidPapa`
  (PSK `321654987`) or `Pinpellets` (PSK `17011976`) can get the charger onto an attacker network,
  then serve it DNS/OCPP/firmware — remote takeover, no cloud needed. The PSK `17011976` reads
  like a date; these are almost certainly **developer/support hotspots shipped in production**.
- **Trigger — traced to live timer/event logic (IRAM now loaded):** the connect fires when the
  Wi-Fi task (`FUN_0001f2d8`) receives event bit `0x8000` (→AndroidPapa) or `0x10000` (→Pinpellets).
  Those bits are posted by a periodic **countdown-timer tick handler** `FUN_40083300` (IRAM): when
  per-AP timer fields expire (`ctx+0x902`→`0x8000`, `ctx+0x8f8`→`0x10000`; `ctx+0x906`→`0x200` is
  the OCPP-unlock check on the same timer bank) it calls `FUN_400838b4(ctx, bit)` = set-bits. The
  timers are one-shot (reload to `0xffff`/disabled after firing). At least one is armed by running
  code: `FUN_0001d9a4` sets the `0x10000` timer to 150 or 1500 ticks, called from task
  `FUN_00009174` on its own `0x10000` event. **So this is NOT dead code or a one-time factory flag
  — it is wired into live RTOS task/timer logic.** The top-level condition that starts the arming
  (boot vs. connectivity-recovery vs. provisioning vs. a command) spans several tasks and event
  groups and was not fully root-caused. Combined with the earlier fact that the SSID strings are
  referenced only at the connect site (no scan-match), the exploitation model is: an attacker who
  can get the charger into the arming state (or simply waits for it) and stands up `AndroidPapa`
  (PSK `321654987`) / `Pinpellets` (PSK `17011976`) nearby can capture the charger onto their
  network. This is a real hardcoded-credential backdoor; the remaining open piece is exactly which
  runtime condition arms it.
- **Root cause — connectivity-recovery fallback (confirmed mechanism):** the poster
  `FUN_400838b4(ctx, bits)` calls `FUN_400838c8(ctx+0x170, bits)`, and the Wi-Fi task waits on
  `ctx+0x170` — proven same event group. The per-AP timers are armed by the connectivity/service
  task: `FUN_0001d9a4` sets the Pinpellets timer to 150 or 1500 ticks, invoked from task
  `FUN_00009174` on an internal event; and the STM32-firmware-updater `FUN_0001dc54` *disables*
  these timers (`=0xffff`) during flashing so the charger won't switch networks mid-update. That
  behavior pattern — armed by connectivity logic, suppressed during updates — is a **"join a known
  service hotspot when connectivity recovery is needed"** fallback (`AndroidPapa`/`Pinpellets` =
  the vendor's/installer's phone hotspots). The exact upstream condition that posts the arming
  event is an internal connectivity state transition (not a directly remote-injectable command),
  and the precise instruction wasn't isolated because the relevant dispatch is via indirect/
  computed pointers this Ghidra Xtensa pass doesn't cross-reference.
  - **Realistic exploitation:** an attacker does **not** need to trigger it remotely — they can
    **induce the fallback** by deauthing/jamming the charger off its configured Wi-Fi, then present
    an AP named `AndroidPapa` (PSK `321654987`) or `Pinpellets` (PSK `17011976`). The charger joins
    the attacker's network, after which the attacker controls its DNS/OCPP/firmware path. Hardcoded
    credentials + attacker-inducible join = a genuine remote-takeover backdoor; only the "join"
    uses a known PSK rather than open auth.
- **(original note)** the connect fires when event bits `0x8000`/`0x10000` are set on the
  Wi-Fi task's event group (`DAT_000006c8 = 0x3ffc69f4`). The standard esp Wi-Fi/IP events map to
  other bits (`FUN_0001f5a4`: SCAN_DONE→`0x20`, STA_START→`0x400`, STA_CONNECTED→`0x1000`,
  AP_STACONNECTED→`0x2000`, AP_STADISCONNECTED→`0x4000`) — **none to `0x8000`/`0x10000`**, so this
  is *not* an automatic response to a Wi-Fi event. Crucially, `"AndroidPapa"` and `"Pinpellets"`
  are each referenced **exactly once** in the whole image (only at this connect site) — so there is
  **no scan-result SSID match** that would auto-join them; the connect is driven solely by an
  internal event posted by other logic. The exact poster wasn't found in the loaded IROM (`seg3`);
  it most likely lives in a UART/command/debug path (IRAM `seg2`/`seg4`, not loaded). Best current
  read: a **factory/developer AP-switch**, reachable by whoever can set that event (local/debug),
  rather than a remote auto-join. The hardcoded credentials and the join capability are confirmed;
  the reachability is the one unresolved piece. To pin it, load `seg2`/`seg4`/`seg1` and xref
  `xEventGroupSetBits(0x3ffc69f4, 0x8000)`.

### 2. Hardcoded local web-UI credentials — **CONFIRMED (route/cred table reconstructed)**
The HTTP server (Basic auth, realm "Please enter login and password", `401 UNAUTHORIZED` /
"Not authenticated") is driven by a route table in rodata (seg3 `0x2260…`, pointers into seg0).
The reconstructed table pairs each protected page with its credential(s):
- `/service` → `/spiffs/service.html` → **`eveus`**
- `/ocppconfig` → `/spiffs/ocppconfig.html` → **`Uc_Ocpp` / `UC_OCPP`**

So the OCPP-config and service pages ship with built-in credentials (`eveus`; `Uc_Ocpp`/
`UC_OCPP`). The handler loops this table (and reads these as username/password); exact user-vs-
password ordering and whether they're user-overridable live in the dispatcher. Other routes in the
same table: `/update`, `/log`, `/limits`, `/schedule`, `/voltage-control`, `/current-session`,
`/network`, `/statistics`, `/settings`, `/oldupdate`, index/favicon/js/css/images.
- `/debug` is **not** in this seg3 auth table — it is referenced from a separate table in seg0
  (`0x3f416b9c`); whether that path enforces auth is not yet confirmed and is worth checking (an
  unauthenticated `/debug` on the LAN would be its own finding).
- **Endpoint map resolved (seg3 loads at base 0, so handler/table pointers use real `0x400d0020+`
  addresses — found by scanning for those values).** Two route tables:
  - **No-auth action/telemetry table** (seg0 `0x3f416b7c`, entries `{path, method, handler, 0}`):
    `/main`→`FUN_221a8` (status JSON), `/init`→`FUN_21804` (config JSON), `/debug`→`FUN_232d4`
    (diagnostic JSON), `/get_logResult`, `/scan`, `/scanResult`, `/cleanLogData`; plus (registered
    in `FUN_00020d10`) `/pageEvent`, `/config`, `/configHttp`, `/configAP`, `/update(/)`,
    `/oldupdate/`, `/updateEvent`, `/ocppEvent`, `/ocppData`, `/getLogData`. These carry **no
    per-handler auth** (matches the known "POST /main returns status without a login").
    - `/debug` = **read-only** JSON of control-pilot (`cp_p2`/`cp_d2`), `gridCurrent`,
      `stationCurrentLimit`, transformer/sensor telemetry. Unauthenticated **info disclosure** on
      the LAN, not control.
    - `/init` = unauthenticated config JSON (SSID names, MACs, serial, Wi-Fi mode, currents,
      `thirdPartyBackends`) but the password fields (`ssidPasswordAP`, `ssidPassword`,
      `httpPassword`) are **masked** — they point to a static empty string, so **no credentials
      leak**.
  - **Auth'd page table** (seg3 pool `0x2260`): `/service`→`/spiffs/service.html` with `eveus`;
    `/ocppconfig`→`/spiffs/ocppconfig.html` with `Uc_Ocpp`/`UC_OCPP`, behind the Basic-auth realm.
- **One micro-detail unresolved:** the Basic-auth routine that compares against those creds sits in
  a region Ghidra left un-disassembled (no xrefs to the cred pool from any segment; the MCP can't
  force disassembly), so the exact **username-vs-password ordering** for `/ocppconfig`
  (`Uc_Ocpp` vs `UC_OCPP`) isn't confirmed — only that those are the two values. Pinning it needs
  manual Xtensa disassembly of that function. Does not change the finding (shipped default creds).
- **Impact:** if the owner never changes them, any LAN device can log into the service/OCPP-config
  pages with these shipped credentials.

### 3. Hardcoded third-party API key + phone-home — **CONFIRMED by decompilation**
`FUN_0000b2cc` (RegisterSn) builds a cJSON object and POSTs it to
`https://evse.center/public/RegisterSn` (the Ukrainian **EVEUS** backend — confirms the
EVEUS≡Grizzl-E shared platform): `{"api_key":"ARMR092csma","sn":<serial>,"register":…,
"uid":<10-char random>}`. The key is **baked into every unit** (shared secret), referenced from
code at `0x400d0a38`.
- **Risk:** the shared key is extractable (it's right here) so it authenticates nothing
  meaningfully; and every charger discloses its serial to a third party. Privacy + weak-auth
  issue, not device takeover by itself.

### 4. Paid "OCPP unlock" is cryptographically broken / forgeable — **CONFIRMED by decompilation**
`FUN_0001f0e8` GETs `https://connect-api.unitedchargers.com/commercial/ext-ocpp-check/<serial>`,
then **builds the expected answer itself**: `strcpy(serial)` then append the 16-byte constant
`";isUnlocked=true"`, `md5(serial + ";isUnlocked=true")` over `strlen` bytes (no trailing NUL) via
the unkeyed digest `FUN_0006ba24`, lowercase-hex-encode the **16-byte** digest with `FUN_000182c8`
(uses the `"0123456789abcdef"` table, `len=0x10` ⇒ **MD5 confirmed**, 32 chars), then `strcmp`s
that against the server's response body. On match it sets the unlocked flag (`ctx+0x63c = 1`),
reported as `thirdPartyBackends` in `/main` and `/init`.
- **Because the expected value has no server-side secret** (just the public serial + a constant),
  anyone can compute it. The "unlock" is security-by-obscurity.
- **Implemented in the local server (v0.6.0):** `GET /commercial/ext-ocpp-check/{serial}` returns
  `md5("<serial>;isUnlocked=true")` lowercase hex, no trailing newline (the firmware does a
  `strcmp`). Requires DNS-overriding `connect-api.unitedchargers.com` to the server too; toggle
  with `GRIZZLE_OCPP_UNLOCK`. For serial `GRD-L0000430161` the value is
  `bf9e764a49121d4006c699d7b991314d`. This is a lock bypass *for* the owner, not a risk *to* them.

### 5. OTA trust model (CONFIRMED transport; strength NEEDS-CODE)
Firmware is fetched over **plaintext FTP** (`ftp://…`), credentials parsed from the URL
(`%[^:]:%[^@]`) or **anonymous** when absent (our captured URL had none). Integrity is checked
with CRC + MD5 + magic (`CheckFileCRC pass!`, `MD5 Pass!`, `Wrong Magic Byte`, `Update error
magic`) — **MD5/CRC are not signatures.** So the OTA's safety rests entirely on the authenticity
of the OCPP channel that delivers the `location` (and the expected hash). Anyone who can send the
charger an `UpdateFirmware` (the cloud, or whoever controls the OCPP endpoint it trusts — which,
on your setup, is your local server) can flash arbitrary firmware. No evidence of image signing
was found in strings; confirm in the decompile.

### 6. No embedded private keys; CA bundle present (CONFIRMED)
The `-----BEGIN … PRIVATE KEY-----` strings are mbedTLS's PEM-parser literals, **not** embedded
keys — no device private key is baked into this image. It bundles the Let's Encrypt **ISRG Root
X1** CA, so the charger is *capable* of verifying the cloud's TLS cert (note: your Duo currently
does not, which is what makes the DNS-override route work; a future build could enforce it).

## Still open
- **Wi-Fi backdoor trigger** (finding 1) — which code sets event bits `0x8000`/`0x10000` on the
  Wi-Fi task's event group (`ctx+0x170`). Governs exploitability.
- **Web-UI auth details** (finding 2) — exact username/password pairing for `/service` and
  `/ocppconfig`, and whether `/debug` requires auth. The creds table is in rodata; the handler
  loops it rather than L32R-ing each string, so it wasn't auto-cross-referenced.
- **Memory-safety bugs** — not assessable from strings; would need a pass over the HTTP/OCPP
  request parsers in the decompiler.
- **Main board `GRD077L-01.10.0` — identified.** One entry in the pre-app archive
  (`[u32 size][u8 flag][name\0][data]`; 63044 bytes). It is **ARM Cortex-M / Thumb-2** firmware
  (299 Thumb prologues, 0 ARM32; vector table at image offset `0xdc`: SP `0x20040000`, reset
  `0x0800f1e9`; linked at flash `0x08000000`), entropy 6.82 (not encrypted). Its only strings are
  FreeRTOS task names — `defaultTask`, `ADC TASK`, `EEPROM TASK`, `EVSE1 TASK`, `EVSE2 TASK`,
  `SYSTEM TASK`, `WATCHDOG TASK`, `UI TASK`: it's the **EVSE power controller** (two EVSE channels =
  the Duo's two connectors). **No credentials, URLs, or network strings** — it isn't network-facing
  (ESP32↔main board is UART), so it holds none of the backdoor/secret classes asked about. REA
  can't decode Thumb/Cortex-M; a full decompile goes in Ghidra as `ARM:LE:32:Cortex` from
  `firmware/mainboard/mainboard_code_08000000.bin` at `0x08000000` (see `MAINBOARD-GHIDRA.md`).
  **Analyzed in Ghidra (Cortex-M):** confirmed **STM32F4 / Cortex-M4** (SP `0x20040000` ⇒ 256 KB
  RAM; ADC at the F4 base `0x40012000`; a peripheral table at `0x0800d6a8` lists USART2/3, UART4/5,
  USART6). 189 functions, 8 strings (only the task names). Security posture: **no network stack,
  no credentials, no URLs, no self-update server** — it is updated by the ESP32 pushing the
  `GRD077L` image over UART, and holds none of the backdoor/password classes in this report.
  - **One trust-boundary caveat:** the main board takes commands from the ESP32 over a USART. Since
    the ESP32 has the Wi-Fi backdoor (#1) and default web creds (#2), a *compromised ESP32* could
    issue main-board commands. Whether that can force unsafe energization depends on the main board
    enforcing charging safety (control-pilot state, GFCI/RCD, over-current, weld detection) in
    hardware / independent logic rather than trusting the UART. This wasn't resolved: Ghidra's
    auto-analysis of the Thumb image is patchy (key functions decode as bad data; peripheral access
    is indexed with no xrefs), so confirming UART→relay gating needs manual Thumb cleanup. Standard
    EVSE designs enforce the critical trips in dedicated hardware independent of the comms MCU, so a
    UART command alone usually cannot defeat them — but that is not proven from this image.

## Decompiler setup
Image loaded in Ghidra as `Xtensa:LE:32`, `seg3` code at base `0x0` (so IROM `0x400d00xx` ≡ Ghidra
`0x…`), `seg0` rodata correctly at `0x3f400020`. See `GHIDRA-IMPORT.md` for addresses.
