# Decompiling the main-board (GRD077L) firmware in Ghidra — Finding 6 Part B

This is the guide for answering the **one unresolved question** in the report: *can a
compromised ESP32 (findings 1/2/N1) drive the EVSE main board into an unsafe state over
the UART, or does the main board enforce charging safety independently?*

> **Why Ghidra and not REA:** the main board is **ARM Cortex-M / Thumb-2**. REA's raw loader
> decodes it as plain **ARM mode**, which mis-decodes Thumb and produces garbage — that is
> why the first pass was low-confidence. You must import it into Ghidra as a **Cortex**
> variant (Thumb) to get correct disassembly. Stock Ghidra has the ARM Cortex module; no
> extension is needed.

## Files (in `firmware/mainboard/`, git-ignored)

- **`mainboard_code_08000000.bin`** — the image with its `0xDC`-byte wrapper header stripped,
  so the **vector table is at file offset 0** and it loads cleanly at `0x08000000`.
  **Use this one.**
- `mainboard_GRD077L.bin` — the raw archive entry (`0xDC` header + image), reference only.

## A. Import

1. `File ▸ Import File` → `mainboard_code_08000000.bin`.
2. **Format:** `Raw Binary`.
3. **Language:** `ARM:LE:32:Cortex` — in the picker: Processor `ARM`, Variant **`Cortex`**,
   Size `32`, Endian `little`. (The `Cortex` variant selects Thumb decoding — essential; a
   plain `ARM:LE:32` decodes it as ARM mode and is wrong.)
4. **Options ▸ Base Address:** `0x08000000`. Import, then open it.
5. Facts to confirm as you go (all from the vector table at `0x08000000`):
   - initial **SP = `0x20040000`** (⇒ 256 KB SRAM at `0x20000000` ⇒ STM32F4 class),
   - **reset handler = `0x0800f1e9`** (Thumb; the real first instruction is at `0x0800f1e8`),
   - a peripheral/base table at `0x0800d6a8` references USART2/3, UART4/5, USART6,
   - ADC at the STM32F4 base `0x40012000`.

## B. Make the Thumb analysis actually complete

STM32 Thumb images confuse Ghidra's default auto-analysis (constant pools and jump tables
get mis-typed as code/data). Do this so the safety-critical functions decompile:

1. `Analysis ▸ Auto Analyze…` — accept defaults **and additionally tick**:
   - **ARM Aggressive Instruction Finder** (recovers Thumb functions with no direct xref),
   - **ARM Symbol** / **Function Start Search**.
2. Set the entry so analysis has a seed: at `0x0800f1e8`, `D` to disassemble (Thumb), then
   `F` to create a function; mark it as the entry point.
3. Create the vector table as pointers: at `0x08000000`, define a sequence of `pointer`s
   (SP word first, then handler words). Each handler word has the Thumb LSB set — Ghidra's
   "Fixup ARM Thumb Pointers" (in auto-analysis) or manually clearing bit 0 gives the real
   handler address. The reset/NMI/HardFault/SysTick/IRQ handlers are your roots.
4. For any region that still shows as red "undefined" bytes but looks like code, select it
   and `D` (disassemble) in Thumb; re-run Auto Analyze. Iterate until the task functions
   below have clean decompilation.
5. Optional but helpful: import an **SVD** for the exact STM32F4 part (e.g. STM32F405/407)
   via a Ghidra SVD-loader plugin, or hand-label the peripheral bases (next section) so the
   decompiler shows `GPIOx->BSRR` / `ADC->DR` instead of raw addresses.

## C. Orient — the known structure

The only strings are the FreeRTOS task names — use them as anchors (`Search ▸ For Strings`,
then xref each to the task body / the `xTaskCreate` call that names it):

`defaultTask`, `ADC TASK`, `EEPROM TASK`, `EVSE1 TASK`, `EVSE2 TASK`, `SYSTEM TASK`,
`WATCHDOG TASK`, `UI TASK`.

`EVSE1 TASK` / `EVSE2 TASK` are the two connectors; `ADC TASK` reads current/voltage;
`WATCHDOG TASK` is the independent watchdog; `SYSTEM TASK` likely owns the UART link to the
ESP32.

### STM32F4 peripheral bases (label these to read the code)

| Peripheral | Base | What to watch |
|---|---|---|
| GPIOA…GPIOK | `0x40020000` + `0x400`×port | **`ODR` = base+0x14, `BSRR` = base+0x18** → the contactor/relay drive bit |
| ADC1/2/3 | `0x40012000` (+0x100/0x200) | `DR` = base+0x4C → measured current/voltage (over-current trip) |
| TIM1/8 (adv) | `0x40010000` / `0x40010400` | `CCRx` → the **control-pilot (CP) PWM** duty |
| TIM2–5 (gp) | `0x40000000`+ | CP read / timing |
| USART2/3, UART4/5, USART6 | `0x40004400`/`4800`/`4C00`/`5000`, `0x40011400` | the **ESP32↔main-board UART** (`DR`=base+0x04) |
| IWDG / WWDG | `0x40003000` / `0x40002C00` | independent watchdog (resets on hang) |
| EXTI | `0x40013C00` | edge interrupts (CP transitions, GFCI fault line) |

## D. The actual question — trace UART command → contactor

Goal: find the GPIO write that closes the charging contactor, then work out **what gates it**.

1. **Find the relay/contactor drive.** Search for writes to a GPIO `BSRR`/`ODR`
   (`base+0x18`/`base+0x14`). The pin that energizes the connector is the one toggled inside
   `EVSE1 TASK` / `EVSE2 TASK` around a state that also sets the CP PWM. Label that function
   `evse_set_contactor`.
2. **Find the UART command handler.** From the USART `DR` read (base+0x04) or the USART IRQ
   handler in the vector table, find the function that assembles ESP32→main-board frames and
   the dispatcher that acts on them (the ESP32 side sends things like `Station Current %d`;
   look for the matching parse). Label it `uart_cmd_handler`.
3. **Connect them and look for the gate.** Decompile the path from `uart_cmd_handler` to
   `evse_set_contactor`. The security question is whether, between a UART command and the
   contactor closing, the code **requires** independent conditions to hold, e.g.:
   - **Control-pilot state** = vehicle connected & ready (CP voltage/PWM state B/C), read from
     ADC/TIM — not from the UART;
   - **GFCI / RCD** fault line clear (a GPIO/EXTI input);
   - **Over-current** below limit (ADC current vs a threshold the main board owns);
   - **Contactor weld / feedback** check (an input confirming the relay state);
   - a **watchdog / fault latch** that opens the contactor on timeout.
4. **Decide the verdict:**
   - *Safe-by-design* — the contactor write is reached only after the task's own CP/ADC/fault
     checks, and a UART command merely **requests** a current limit or enable, which the task
     still validates. A malicious UART command then **cannot** energize an unsafe connector.
   - *UART-trusting* — the handler writes the contactor GPIO (or an "enable" flag the task
     obeys unconditionally) directly from UART input with no independent interlock. That would
     be a real safety finding and should be added to the report / disclosure.

## E. Report back

Note which it is, with the function addresses for `uart_cmd_handler`, `evse_set_contactor`,
and each interlock check you find (or confirm absent). If you load this as a **second
program** in the same Ghidra project alongside the ESP32 image, remember the REA/Ghidra MCP
drives whichever program is *active* — make the main-board program active (or close the
ESP32 one) before asking for MCP-driven analysis of it.
