# Captured firmware

Firmware images captured from the United Chargers cloud with `tools/firmware_capture.py`,
for **your own charger**. The `.bin` and `.bin.json` files here are **git-ignored** on purpose:
they are United Chargers' proprietary firmware and must not be redistributed (e.g. pushed to a
public repo). Keep your own local/offline backup.

## How a capture is obtained

The cloud never exposes a download URL to the app. Instead the cloud sends the charger an OCPP
`UpdateFirmware{location}` message, and the charger fetches the image itself. `firmware_capture
capture` impersonates **your** station to the cloud (serial + the OCPP Auth key recorded in
`data/state.json`), reports an older firmware version so the cloud offers an update, captures the
`location`, and downloads it. It never contacts or commands the real charger.

```
.venv/bin/python -m tools.firmware_capture capture \
    --state data/state.json --claim-firmware UDGRW070L-04.00.0 --out firmware
```

## What the Duo image is (UDGRW070L-04.03.2)

- Delivered over **FTP** (`ftp://<do-host>/files/UDGRW070L-04.03.2.bin`), ~3.29 MB.
- A United Chargers **"UC" OTA container** (first 4 bytes `55 43 00 00`), **not** a bare ESP32
  image (no `0xE9` at offset 0). It wraps, in one file:
  - the ESP32 Wi-Fi application (ESP-IDF v4.4.4) — version `UDGRW070L-04.03.2`;
  - a littlefs filesystem (`profilesDUO.bin`, logs);
  - the STM32 power-board image (`stm.bin` / `stm730.bin`);
  - the main-board image (`/update/GRD077L-01.10.0.bin`) — version `GRD077L-01.10.0`.
- Header carries a 64-char ASCII sha256 at offset 16 (covered region not reverse-engineered) and a
  32-byte trailer.
- Baked-in hosts: `ocpp.unitedchargers.com` (+ `-stage`, `-dev`), confirming the DNS-override route.

## ⚠️ Installing is a separate, risky step — not done here

This is a **backup / analysis** copy. Flashing firmware (via OCPP `UpdateFirmware` from the local
server, or any other way) can brick the unit or remove local OCPP, and past Grizzl-E releases have
done the latter. Do not install without a full-flash recovery backup and a deliberate decision.
