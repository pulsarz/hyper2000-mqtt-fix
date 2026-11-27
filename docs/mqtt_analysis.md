# Zendure Hyper 2000 Master Firmware (`v2.1.47`) — MQTT Analysis & v2 Patch

## 1. Firmware Layout & Architecture

- **Target:** ARM Cortex-M (Thumb-2, little-endian, Keil/ARMCC build, FreeRTOS)
- **File:** `MASTER_v2.1.47.bin` (`166,000` bytes / `0x28870`)
- **Flash base address:** `0x08005000` (`SCB->VTOR = 0x08005000`, `Reset_Handler` at `0x08005224`)
- **Initial SP:** `0x20017218` (SRAM at `0x20000000`)
- **`.data` scatter-load:** `0x0802d000..0x0802d86f` (LZ77-compressed via `0x08006822`) → `0x20000000` (`0x1d4c` bytes); `.bss` zero-init (`0x0801d0d8`) ignores `0x0802d870`, leaving `0x0802d870+` clean for appended trampolines.

### Key FreeRTOS Tasks & Globals
| Symbol | Address | Purpose |
| :--- | :--- | :--- |
| `main` | `0x08021e90` | Initializes peripherals and spawns RTOS tasks |
| `loop10ms_task` | `0x08029e38` | Main 10 ms control loop (calls `FUN_08019194` every 100 ms, `FUN_08012e1c` every 1 s) |
| `wifi_sendtask` | `0x0802afc8` | Priority 7; sends AT commands over UART (`115200` baud) on `wifi_send_sem` |
| `wifi_rectask` | `0x0802ad68` | Priority 6; receives UART DMA frames (1000 ms queue timeout) and drives AT state machine |
| `FUN_08018524` | `0x08018524` | SysTick ISR; flushes UART RX DMA buffer (`0x600` bytes) after 6 ms idle into 2-slot queue |
| `FUN_0801b484` | `0x0801b484` | MQTT publish trigger (called by `FUN_08019194` at priority 3); loads `AT_TABLE[38]` (`AT+MQTTPUBRAW`) |
| `FUN_0801b500` | `0x0801b500` | Unsolicited UART event parser (`MQTT_DISCONNECT`, `MQTT_CONNECT`, `MQTT_SUB`, `WIFI_DISCONNECT`) + AT response handler dispatch |
| `xTickCount` | `0x20000010` | FreeRTOS 1 ms tick counter (incremented in `FUN_0802c158`) |
| `AT_TABLE` | `0x2000013c` | 57-entry × 12-byte AT state table `{ id, wait_s, retries, fail_next, ok_next, handler }` |
| `cur_state` | `0x2000f014` | Active `[0..4]`, unused 4-byte slot `[8..11]` (`0x2000f01c`), pending `[0x0c..0x10]`, saved `[0x18..0x1c]` |
| `wifi_status` | `0x2000ed44` | `[1]` pending flag, `[2]` bitmask (`0x01`=idle, `0x04`=Wi-Fi, `0x08`=MQTT, `0x10`=WMODE), `[4]` BLE state, `[10]` link state (`1`=down, `2`=up) |
| `wifi_send_sem` | `0x200004a4` | Semaphore waking `wifi_sendtask` |

---

## 2. Root Causes of MQTT Freezes (Live-Connection Hang & Post-Disconnect Hang)

### Bug #1 (Primary live-connection freeze under frequent commands): 100 ms `AT+MQTTPUBRAW` double-publish race (`FUN_0801b484`)
`FUN_0801b484` (`0x0801b484`) copies `AT_TABLE[38]` (`AT+MQTTPUBRAW`) into `cur_state` and signals `wifi_send_sem` **without clearing `wifi_status[2]` bit 0 (`IDLE`)**. Only `wifi_rectask` clears bit 0 at the bottom of its loop (`0x0802af8c`), *after* the next UART RX frame or 1000 ms timeout.

When frequent `properties/write` commands arrive (each queuing a `properties/write/reply` into the 2-slot TX queue `0x200139be`):
1. `FUN_08019194` (100 ms tick) starts publish #1 (`AT+MQTTPUBRAW=...,0,0,N1,\r\n`).
2. If BL602 takes >100 ms to answer `>` (or is busy processing inbound `MQTT_SUB`), `FUN_08019194` fires again 100 ms later, sees `wifi_status[2] & 0x09 == 0x09` **still true**, and calls `FUN_0801b484` a **second time mid-flight**.
3. `FUN_0801b484` overwrites the payload buffer (`0x2000e5c8`) and sends `AT+MQTTPUBRAW=...,0,0,N2,\r\n` directly into BL602's active raw-payload UART input mode (which was waiting for `N1` bytes).
4. BL602 stalls waiting for raw input bytes (stopping both outbound publishes and `+MQTT_SUB` delivery on UART), **while BL602's background MQTT task continues sending `PINGREQ` to EMQX**. Kicking the client from EMQX forces a TCP close that breaks the stall.

### Bug #2: `wifi_rectask` timeout starvation under frequent `MQTT_SUB` (`0x0802ad68`)
`wifi_rectask` only decrements `cur_state.wait` when `xQueueReceive(uart_rx_queue, rx_buf, 1000)` times out (a full 1000 ms of UART silence). Continuous inbound `MQTT_SUB` or `SocketDown` packets (<1 s apart) prevent `cur_state.wait` from ever decrementing, freezing any active AT state (`38`, `39`, `12`) indefinitely.

### Bug #3: `AT_TABLE[39]` payload `ERROR`/timeout drops silently to `IDLE (56)` & 10-minute `AT+MQTT` timeout
- `AT_TABLE[39]` (`FUN_0800cb6c`, raw payload after `>`) has `wait = 20s`, `retry = 1`, **`fail_next = 56 (IDLE)`**. On `ERROR` or timeout, Master silently drops back to `IDLE (56)` with `MQTT_CONNECTED` still set and never resets BL602.
- `AT_TABLE[35]` (`AT+MQTT` connect) has `wait = 40s`, `retry = 15` (`600s` = 10 minutes) and ignores `ERROR`.

### Bug #4: `MQTT_DISCONNECT` indefinite deadlock in `IDLE (56)` (`FUN_0801b500`)
`FUN_0801b500` clears `wifi_status[2]` bit 3 (`0x08`) and sets `wifi_status[10] = 1` on `MQTT_DISCONNECT`, leaving `cur_state` in `IDLE (56)` with `uVar10 = 0` and no reconnect or `AT+MQTTSUB` scheduled.

---

## 3. Binary Patch v2 (`patch_mqtt_fix.py`)

Appends a 176-byte trampoline block (16-byte aligned, matching stock alignment) at `0x0802d870..0x0802d91f` (total size `166,176` bytes; stays in the same 4 KB SPI flash sector and 1 KB internal flash page as the stock tail):

1. **Hook 1 (`FUN_0801b484` @ `0x0801b49e` → `hook_publish` @ `0x0802d870`):**
   - Verifies `cur_state.id >= 0x35` (`IDLE`) and `wifi_status[2] & 1 == 1` (aborts if an AT command is already in flight).
   - Immediately clears `wifi_status[2] &= ~0x01` (`[r5, #0x77e]`) before touching the TX buffer or signaling `wifi_send_sem`.
   - Refreshes `cur_state.last_tick` (`[r5, #0xa54]` = `0x2000f01c`) from `xTickCount` (`0x20000010`).
2. **Hook 2 (`wifi_rectask` @ `0x0802aec6` → `hook_rectask_rx` @ `0x0802d8a4`):**
   - If `(uVar8 & 0xff) != 0` (handled AT response): refreshes `last_tick` and resumes at `0x0802aecc`.
   - If `uVar8 >= 0x400` (high-byte state-switch events `0x400 / 0x800 / 0x1000 / 0x2000 / 0x8000` that just loaded a new `cur_state` and woke `wifi_sendtask`): refreshes `last_tick` and exits cleanly to `0x0802af7c` so it never double-wakes `wifi_sendtask`.
   - Otherwise (`uVar8` is `0x0000` unsolicited RX, `0x0100` `properties/write`, or `0x0200` HTTP OTA) while `cur_state.id` is in `1..52`: checks `(xTickCount - cur_state.last_tick) >= 1000`, updates `last_tick`, and branches to `0x0802af10` (existing timeout decrement + retry/fail path).
   - While `cur_state.id >= 53` (including `IDLE 56` and BLE SPP `54`): only refreshes `last_tick = xTickCount`.
3. **Hook 3 (`FUN_0801bb5c` @ `0x0801bb70` → `hook_init_at_table` @ `0x0802d8e4`):**
   - Patches `AT_TABLE` (`0x2000013c`) in RAM once at task startup:
     - `AT_TABLE[39].fail_next = 6` (`AT+RST`, was `56 IDLE`), `wait = 10s` (was `20s`)
     - `AT_TABLE[38].wait = 10s` (was `20s`)
     - `AT_TABLE[35].wait = 15s` (was `40s`), `retry = 4` (was `15`; 60 s max vs 600 s)
4. **Hook 4 (`FUN_0801b500` @ `0x0801b572..0x0801b5a0`, in-place):**
   - Reuses the 14-byte duplicate dead branch so `MQTT_DISCONNECT` while `cur_state.id > 36` returns event `0x1000` (immediate clean reconnect + `AT+MQTTSUB`).

All 4 patches and Keil `__scatterload` startup decompression are verified via ARM Cortex-M Thumb-2 emulation in `tests/emulate_patch.py`.

---

## 4. OTA Verification Details (`MASTER_v2.1.47_mqttfix.bin` v2)

- `FUN_080079e8` (BLE `otareq`) and `FUN_080163c8` (MQTT OTA) require `version >= 0x2130` (`8496`, i.e. `2.1.48`, since `2.1.47` is `0x212F`).
- `FUN_0800bc74` verifies exact `size` and **CRC-16** (`FUN_0800a308`: byte-swapped CRC-16/Modbus, `poly = 0xA001`, `init = 0xFFFF`, table at `0x0802cc7c`), then computes **CRC-32** (`FUN_0801de94`, `0xEDB88320`) and writes a 22-byte header with magic `0xA580` to external SPI flash before triggering `NVIC_SystemReset`.
- Checksums for the v2 patched `MASTER_v2.1.47_mqttfix.bin` (16-byte aligned):
  - `size`: `166176`
  - `CRC16`: `0x048c` (`1164`)
  - `CRC32`: `0x732db954` (`1932376404`)
  - `MD5`: `8e1acd622cf94299fe164b672b4bc680`

---

## 5. Zendure Cloud OTA API Notes (`com.zendure.iot` v7.2.0)

- **Default Base URL:** `https://app.zendure.tech/v2/` (switches to `LoginBean.serverNodeUrl` after login)
- **Hyper 2000 `productType`:** `"17"`
- **Auth:** `POST auth/app/token` (`grantType="password"`, `tenantId=""`, `appType="Android"`, `account`, `password`)
- **Device List:** `POST productModule/device/queryDeviceListByConsumerId`
- **Batch Firmware Lookup:** `POST ota/batch/firmware` (`{"deviceId": <id>}`)
- **Fallback Lookup:** `POST productModule/device/getFirmwareVersion` (`{"deviceId": <id>, "productType": "17"}`)
- **Request Signing (`HeaderInterceptor`):** `timestamps` is Unix time in **seconds** (`MyTimeUtils.OooO()`), and `sign` is Base64(`RSA/ECB/PKCS1Padding` encrypt of `"7.2.0./<relative_path>/<timestamps>"` using the app's X.509 RSA public key).
