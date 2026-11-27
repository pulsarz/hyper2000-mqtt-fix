# Zendure Hyper 2000 — Firmware Downloader & MQTT Fix

Unofficial community tools and technical documentation for downloading official Zendure Hyper 2000 firmware images for your own device, patching the MQTT hang/deadlock bugs in `MASTER_v2.1.47.bin`, and flashing or provisioning Wi-Fi/MQTT over Bluetooth.

> **Disclaimer & Warranty Notice:** This is an **unofficial community project** and is not affiliated with, endorsed by, or supported by Zendure. Flashing modified firmware is strictly **at your own risk** and may void your warranty.
> - **Scope:** This patch modifies **only** the STM32 `MASTER` communications/orchestration MCU (`MASTER_v2.1.47.bin`). It **never** modifies AC/DSP inverter power-stage firmware, power limits, grid-code protections, or BMS battery safety firmware.
> - **No Proprietary Binaries Distributed:** No Zendure firmware binaries are included in this repository. You download your own stock firmware from your own Zendure account and patch it locally.
> - **Reversible:** Reverting to stock `MASTER_v2.1.47.bin` is supported over Bluetooth at any time.

> **Hardware Status (2026-11-27):** Verified on physical Zendure Hyper 2000 hardware across **both hardware revisions** (`AC v2.1.17` / `dspversion 8465` and `AC v3.1.4` / `dspversion 12548`) — both a stock `MASTER_v2.1.47.bin` dry-run (`166,000 B`, `CRC16 0x10a2`) and the patched `MASTER_v2.1.47_mqttfix.bin` v2 (`166,176 B`, `CRC16 0x048c`, `CRC32 0x732db954`) flashed cleanly over the Web Bluetooth webapp, passed on-device SPI-flash CRC-16 verification (`55 25 ... 01`), and completed bootloader flash & reboot (~16–24 s). On a multi-day (~72-hour) continuous soak test on a local MQTT broker under active zero-export / Home Assistant automation, the patched unit had **zero** non-responsive dropouts (while an unpatched unit on the same broker continued freezing).

## Quick Start (3 Steps — All-in-One Webapp)

1. **Start the local webapp** (Python 3 standard library only for local patching/flashing; `pip install requests cryptography` if using the built-in Zendure cloud downloader):
   ```bash
   # Same machine (http://localhost:8080):
   python3 ble_ota_webapp/server.py

   # Or from another phone/laptop on your LAN (Chrome requires HTTPS for Web Bluetooth):
   python3 ble_ota_webapp/server.py --host 0.0.0.0 --port 8080 --https-port 8443
   ```
2. **Download & Patch:** Open the URL in Chrome, Edge, or Chromium → sign in to your Zendure account (credentials stay in local RAM only) and download `MASTER_v2.1.47.bin` (or drop a local `.bin` file) → click **Apply MQTT Fix v2 Patch** (verified to produce `166,176 B`, `CRC16 0x048c`, `CRC32 0x732db954`).
3. **Connect & Flash over Bluetooth:** Click **Connect Hyper 2000** (`ZenE1_XX`, where `XX` is the last 2 digits of the serial number — the UI also displays `deviceId`, `SN`, and `MASTER / AC` versions once connected) → check the risk acknowledgment → click **Start BLE OTA Upload**.
   - **Recommended first test:** Click **Use Stock .bin (Dry-Run / Rollback)** to flash stock `MASTER_v2.1.47.bin` first and verify your Bluetooth link before flashing the patched image.
   - **Rollback to stock anytime:** Select stock `MASTER_v2.1.47.bin` and flash with `Version = 8496`.

---

## What's Broken & What Each Patch Does (Plain English)

Inside the Hyper 2000 there are **two separate chips** for networking:
- **Master MCU (STM32):** Runs inverter/battery orchestration, scheduling, and automation logic.
- **Wi-Fi/Bluetooth chip (BL602):** Handles Wi-Fi, TLS, and the MQTT connection to your broker (e.g., EMQX, Mosquitto, or Zendure cloud).

They talk over a serial wire using text **"AT commands"** (like a walkie-talkie: STM32 sends a command, waits for `OK` or `>`, then sends the next thing). Because the BL602 sends MQTT `PINGREQ` keepalives in the background on its own, the serial link between the two chips can freeze completely while your broker still sees pings and thinks the Hyper 2000 is online.

This patch fixes **four interlocking bugs** in `MASTER_v2.1.47.bin` (without touching inverter, battery, or Bluetooth OTA code):

1. **Patch 1 — Stop the STM32 from talking over itself when publishing**
   - Publishing one MQTT message is a 2-step handshake: STM32 sends `AT+MQTTPUBRAW` (header), waits for `>` from BL602, then sends the raw JSON payload.
   - **Stock bug:** A 100 ms timer checks an `"IDLE"` flag before starting a publish, but forgets to turn `"IDLE"` OFF when Step 1 starts. If BL602 takes >100 ms to answer `>` (common on weaker Wi-Fi or under frequent Home Assistant writes), the timer fires again 100 ms later and jams a *second* `AT+MQTTPUBRAW` straight into BL602's raw-payload input mode — wedging the serial link while BL602 keeps sending `PINGREQ`.
   - **Fix:** Double-check the state machine is truly idle and **immediately flip `"IDLE"` OFF** when starting a publish so the 100 ms timer waits until the current publish finishes.

2. **Patch 2 — Stop incoming messages from freezing the timeout clock**
   - **Stock bug:** The STM32 only counts down an AT-command timeout after **1 full second of total silence** on the serial wire. Every incoming MQTT command (e.g., frequent `properties/write` from Home Assistant or local smart-meter traffic) resets that 1-second timer to zero, so timeouts *never* expire when messages arrive faster than once per second.
   - **Fix:** Track elapsed time using the STM32's real 1 ms clock (`xTickCount`) in an unused 4-byte RAM slot, so timeouts still tick down every 1,000 ms even under continuous inbound traffic (while leaving Bluetooth mode and fresh state-switches untouched).

3. **Patch 3 — Actually reset the Wi-Fi chip if a publish fails (and cut 10-minute waits)**
   - **Stock bug:** If sending the raw MQTT payload fails or times out (`AT_TABLE[39]`), stock firmware's table jumps back to `IDLE (56)` and pretends nothing happened instead of resetting the wedged BL602. Separately, MQTT connect (`AT_TABLE[35]`) waits **40 s × 15 retries = 10 minutes** before resetting BL602.
   - **Fix:** At boot, update three table entries in RAM: payload failure jumps to **`AT+RST (6)`** (clean BL602 reboot + reconnect) with a **10 s** timeout (was 20 s), publish header timeout becomes **10 s** (was 20 s), and MQTT connect becomes **15 s × 4 retries = 1 min max** (was 10 min).

4. **Patch 4 — Actually reconnect when MQTT disconnects**
   - **Stock bug:** When BL602 reports `MQTT_DISCONNECT` (Wi-Fi blip, router hiccup, or broker restart/kick), stock firmware clears its `"MQTT connected"` bit and sits in `IDLE` forever without reconnecting or re-subscribing (`AT+MQTTSUB`).
   - **Fix:** When `MQTT_DISCONNECT` arrives while connected/idle (ignoring disconnects during an in-progress login), trigger the firmware's own clean restart event (`0x1000` → `AT_TABLE[1]`) so it automatically reconnects and re-subscribes.

*(For exact addresses, register liveness, and Thumb-2 disassembly, see `docs/mqtt_analysis.md`.)*

## Repository Contents

- `download_hyper2000_fw.py` — Authenticates with your Zendure cloud account, lists bound devices, queries the batch/single OTA endpoints (`ota/batch/firmware` / `productModule/device/getFirmwareVersion`), and downloads firmware modules with fatal MD5 verification.
- `patch_mqtt_fix.py` — Applies the **v2 comprehensive Thumb-2 patch** to `MASTER_v2.1.47.bin` (`166,000` → `166,176` bytes, 16-byte aligned) with strict input/output SHA-256/CRC self-checks.
- `ble_ota_webapp/server.py` & `ble_ota_webapp/index.html` — All-in-one local webapp to **download** firmware from your Zendure account, **patch** `MASTER_v2.1.47.bin` in-browser (byte-identical to `patch_mqtt_fix.py`), **flash** over Web Bluetooth (`0xA002` / `0xC304` / `0xC305`, MASTER-only allowlist), and **provision Wi-Fi & local MQTT** (`method: "token"`, `FUN_08016048`) without the cloud app.
- `tests/emulate_patch.py` — ARM Cortex-M Thumb-2 Unicorn emulation suite verifying Keil `__scatterload` SRAM identity and all four patched code paths end-to-end against the generated binary.
- `ghidra_scripts/` — Headless Ghidra Java scripts used to map SRAM/flash (`0x08005000`) and decompile the Wi-Fi, MQTT, UART DMA, and BLE/HTTP OTA routines.
- `docs/mqtt_analysis.md` — Full technical writeup of the Hyper 2000 Master MCU AT-command state machine, root causes, verified Thumb-2 patch assembly, and OTA CRC validation format.

## Requirements

- **Patching & local BLE OTA webapp (with a local `.bin` file):** Python 3 standard library only (no external packages).
- **Cloud firmware downloader (`download_hyper2000_fw.py` / webapp cloud tab):**
  ```bash
  pip install requests cryptography
  ```
- **ARM Cortex-M emulation test suite (`tests/emulate_patch.py`, optional):**
  ```bash
  pip install -r tests/requirements.txt
  ```

## CLI Usage

### 1. Download Firmware
```bash
./download_hyper2000_fw.py --all --out-dir ./hyper2000_fw
```
Or print firmware URLs and metadata without downloading:
```bash
./download_hyper2000_fw.py --urls-only
```

### 2. Patch `MASTER_v2.1.47.bin`
```bash
./patch_mqtt_fix.py -i ./hyper2000_fw/MASTER_v2.1.47.bin -o ./hyper2000_fw/MASTER_v2.1.47_mqttfix.bin
```
The script verifies the input SHA-256 and original bytes before patching and prints the exact `size`, `CRC16` (for BLE `otareq`), `CRC32`, and `MD5`.

### 3. Optional Emulation Verification
```bash
python3 tests/emulate_patch.py --orig ./hyper2000_fw/MASTER_v2.1.47.bin --patched ./hyper2000_fw/MASTER_v2.1.47_mqttfix.bin
```

## License

MIT — see [LICENSE](LICENSE). Proprietary binaries (`.xapk`, `.apk`, `.bin`, `.lzma`) and Ghidra project databases are intentionally excluded via `.gitignore`.
