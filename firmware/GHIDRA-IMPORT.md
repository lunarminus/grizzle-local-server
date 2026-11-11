# Loading the ESP32 firmware into Ghidra

The captured image is Xtensa (ESP32, `chip_id=0`). **Stock Ghidra cannot disassemble
Xtensa** — install the Xtensa processor module first (e.g. the `ghidra-xtensa` /
Ebiroll extension, or build-tool's) via `File ▸ Install Extensions`, then restart.
REA and the host have no Xtensa support, which is why this must be your Ghidra.

Files (in `firmware/esp32-extracted/`, git-ignored):

| file | load address | kind |
|------|--------------|------|
| `seg0_3f400020.bin` | `0x3f400020` | DROM — rodata (strings/constants) — **non-exec** |
| `seg1_3ffb0000.bin` | `0x3ffb0000` | DRAM — data |
| `seg2_40080000.bin` | `0x40080000` | IRAM — code |
| `seg3_400d0020.bin` | `0x400d0020` | IROM — **main code, exec** |
| `seg4_400870cc.bin` | `0x400870cc` | IRAM — code, exec |

Entry point: `0x400814f0`.

## Import steps
1. `File ▸ Import File` → pick `seg3_400d0020.bin`.
2. Set **Format = Raw Binary**, **Language = Xtensa:LE:32** (from the extension),
   **Options ▸ Base Address = 0x400d0020**. Import.
3. For each other segment: `Window ▸ Memory Map ▸ + (Add Block)` → *Block Type:
   Byte Mapped / Initialized from File*, set the start address from the table and
   load the matching file. Add `seg0` at `0x3f400020` first (so string references
   resolve), then seg1/2/4.
4. `Analysis ▸ Auto Analyze` (accept defaults).

Alternatively, if you have an ESP32 image loader extension, just import
`esp32-app.bin` directly — it parses the 5-segment header and maps everything.

## Where to look (addresses of interest)
Once analyzed, tell me and I'll drive the Ghidra MCP. The functions to confirm:

- **Hardcoded Wi-Fi + unlock flag** — one literal pool at `0x400d1f00` references all of:
  `;isUnlocked=true` (str `0x3f415a6c`), pw `321654987` (`0x3f415ad8`), ssid
  `AndroidPapa` (`0x3f415ae4`), pw `17011976` (`0x3f415b1c`), ssid `Pinpellets`
  (`0x3f415b28`). Decompile the function owning that pool.
- **Web-UI auth** — pool at `0x400d22bc`: `eveus` (`0x3f416d8c`), `Uc_Ocpp`
  (`0x3f416dac`), `UC_OCPP` (`0x3f416db4`).
- **Hardcoded API key / phone-home** — `ARMR092csma` (`0x3f40de9c`) referenced at
  `0x400d0a38`; near `https://evse.center/public/RegisterSn`.
- **OCPP-unlock check** — string `connect-api.unitedchargers.com/commercial/ext-ocpp-check/`.
- **FTP firmware download** — `USER %s` / `PASS %s` builders; find the credential args.
- **`/debug` endpoint** — confirm whether it is behind Basic auth.
