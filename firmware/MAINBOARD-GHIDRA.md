# Decompiling the main-board (GRD077L) firmware in Ghidra

The main board is **ARM Cortex-M / Thumb-2**, linked at flash `0x08000000`. Stock Ghidra has
the ARM Cortex module (no extension needed). Files in `firmware/mainboard/` (git-ignored):

- `mainboard_code_08000000.bin` — the image with its 0xDC wrapper header stripped, so the
  **vector table is at file offset 0** → loads cleanly at `0x08000000`. **Use this one.**
- `mainboard_GRD077L.bin` — the raw archive entry (0xDC header + image), for reference.

## Import steps
1. `File ▸ Import File` → `mainboard_code_08000000.bin`.
2. **Format:** Raw Binary.
3. **Language:** `ARM:LE:32:Cortex` (little-endian, Cortex). In the picker: Processor `ARM`,
   Variant **`Cortex`**, Size `32`, Endian `little`. (This selects Thumb — essential; a plain
   `ARM:LE:32` will mis-decode it as ARM mode.)
4. **Options ▸ Base Address:** `0x08000000`.
5. Open it; when asked, let it analyze. Before/after analysis you can mark the entry: the
   **reset handler is `0x0800f1e9`** (Thumb, so the real instruction is at `0x0800f1e8`). The
   initial SP is `0x20040000`. The vector table is at `0x08000000`.
6. `Analysis ▸ Auto Analyze` (defaults; the ARM Aggressive Instruction Finder helps on Thumb).

## What to expect
It's the EVSE power/controller MCU: FreeRTOS tasks `defaultTask`, `ADC TASK`, `EEPROM TASK`,
`EVSE1 TASK`, `EVSE2 TASK`, `SYSTEM TASK`, `WATCHDOG TASK`, `UI TASK`. No network stack, no
credentials/URLs in strings — it talks to the ESP32 over UART. Of interest if you want to
understand charge-control/relay/sensor logic (ADC current/voltage, the two EVSE channels, the
UART command protocol to the ESP32), not for secrets.

If you load it as a **second program** in the same Ghidra project, note the MCP drives whichever
program is *active*; switch the active program (or close the ESP32 one) before asking me to
analyze it, since I can only see the current program.
