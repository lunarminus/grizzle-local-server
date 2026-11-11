# Grizzl-E Duo firmware — security analysis

Target: `UDGRW070L-04.03.2.bin` (captured from the United Chargers cloud; see `README.md`).
Scope of this pass: the **ESP32 Wi-Fi/OCPP application** (the networked attack surface).
Evidence is graded **CONFIRMED** (present in the binary, and the string is referenced by
code — a 32-bit pointer to it sits in an Xtensa literal pool in the `.text`/IROM segment) vs
**NEEDS-CODE** (runtime behavior that requires decompiling the Xtensa code to confirm — stock
Ghidra/REA can't disassemble Xtensa; see `GHIDRA-IMPORT.md`).

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
