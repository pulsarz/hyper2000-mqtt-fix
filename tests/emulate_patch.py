#!/usr/bin/env python3
"""
ARM Cortex-M3/M4 (Thumb-2) CPU emulation test suite for MASTER_v2.1.47_mqttfix.bin
using Unicorn Engine.

Executes the actual patched binary image at 0x08005000 to verify:
  0. Keil RVCT __scatterload produces 100% byte-identical SRAM vs stock firmware
  1. Patch 3 (FUN_0801bb5c -> hook_init_at_table -> FUN_08012dc0) updates only
     AT_TABLE[35,38,39] fields and returns cleanly
  2. Patch 1 (FUN_0801b484 -> hook_publish) clears IDLE & records tick on normal
     publish, and safely aborts without corrupting buffers on busy/non-IDLE race
  3. Patch 2 (wifi_rectask @ 0x0802aec6 -> hook_rectask_rx) refreshes ticks on
     handled/IDLE RX, skips <1000 ms unsolicited RX, and decrements cur_state.wait
     at >=1000 ms (including 32-bit xTickCount wraparound)
  4. Patch 4 (FUN_0801b500) returns 0x1000 on MQTT_DISCONNECT when state > 36,
     returns 0 when connecting (<= 36), and preserves MQTT_CONNECT & WIFI_DISCONNECT
"""

import argparse
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

FLASH_BASE = 0x08000000
FLASH_SIZE = 0x00080000  # 512 KB
APP_BASE = 0x08005000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00030000   # 192 KB
SENTINEL_LR = 0x0807FFFE  # Even stop address (passed as | 1 in LR)

XTICK_ADDR = 0x20000010
AT_TABLE_ADDR = 0x2000013C
WIFI_CTX_BASE = 0x2000E5C8
WIFI_STATUS_ADDR = WIFI_CTX_BASE + 0x77C  # 0x2000ED44
CUR_STATE_ADDR = 0x2000F014               # WIFI_CTX_BASE + 0xA4C
CUR_STATE_TICK = CUR_STATE_ADDR + 8       # 0x2000F01C
SEM_GIVE_ADDR = 0x0802BC48


def make_emu(fw_bytes: bytes) -> Uc:
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    mu.mem_map(FLASH_BASE, FLASH_SIZE)
    mu.mem_map(SRAM_BASE, SRAM_SIZE)
    # Fill flash with 0xFF (erased flash) and load firmware at APP_BASE
    mu.mem_write(FLASH_BASE, b"\xff" * FLASH_SIZE)
    mu.mem_write(APP_BASE, fw_bytes)
    # Put a harmless NOP/BKPT at SENTINEL_LR
    mu.mem_write(SENTINEL_LR, b"\x00\xbf")
    return mu


def run_scatterload(fw_bytes: bytes) -> tuple[bytes, int]:
    """Execute Keil __main (0x08005150) -> __scatterload (0x080063f8) up to 0x08005158."""
    mu = make_emu(fw_bytes)
    sp, _ = struct.unpack_from("<II", fw_bytes, 0)
    main_entry_ptr = struct.unpack_from("<I", fw_bytes, 0x08005244 - APP_BASE)[0]
    mu.reg_write(UC_ARM_REG_SP, sp)

    # 0x08005154: bl 0x080063f8 (__scatterload); 0x08005158: ldr r0, =main; bx r0
    mu.emu_start(main_entry_ptr | 1, 0x08005158, count=500000)
    assert mu.reg_read(UC_ARM_REG_PC) == 0x08005158, (
        f"__scatterload did not reach 0x08005158 (PC=0x{mu.reg_read(UC_ARM_REG_PC):08x})"
    )
    main_addr = struct.unpack_from("<I", fw_bytes, 0x0800515C - APP_BASE)[0]
    return bytes(mu.mem_read(SRAM_BASE, SRAM_SIZE)), main_addr


def test_scatterload(orig: bytes, patched: bytes) -> bytes:
    sram_orig, entry_orig = run_scatterload(orig)
    sram_pat, entry_pat = run_scatterload(patched)
    assert entry_orig == entry_pat, f"Entry mismatch: 0x{entry_orig:08x} vs 0x{entry_pat:08x}"
    assert sram_orig == sram_pat, "Post-__scatterload SRAM differs between stock and patched!"
    # Sanity-check stock AT_TABLE[35,38,39] values in decompressed .data
    # Layout (12 bytes): [id, wait, retry, fail_next, ok_next, pad, pad, pad, fn_ptr(u32)]
    def at_entry(sram, idx):
        off = (AT_TABLE_ADDR - SRAM_BASE) + idx * 12
        return struct.unpack_from("<8BI", sram, off)
    e35 = at_entry(sram_pat, 35)
    e38 = at_entry(sram_pat, 38)
    e39 = at_entry(sram_pat, 39)
    assert e35[0] == 35 and e35[1] == 40 and e35[2] == 15, f"Unexpected stock AT_TABLE[35]: {e35}"
    assert e38[0] == 38 and e38[1] == 20, f"Unexpected stock AT_TABLE[38]: {e38}"
    assert e39[0] == 39 and e39[1] == 20 and e39[3] == 56, f"Unexpected stock AT_TABLE[39]: {e39}"
    print(f"[PASS] Test 0: Keil __scatterload identical to stock (entry=0x{entry_pat:08x}, stock AT_TABLE[39] id={e39[0]} wait={e39[1]} fail={e39[3]})")
    return sram_pat


def test_patch3_init_at_table(patched: bytes, init_sram: bytes) -> bytes:
    mu = make_emu(patched)
    mu.mem_write(SRAM_BASE, init_sram)
    sp0 = 0x20017000
    mu.reg_write(UC_ARM_REG_SP, sp0)
    mu.reg_write(UC_ARM_REG_LR, SENTINEL_LR | 1)
    # Seed callee-saved registers to verify ABI preservation
    saved_in = {UC_ARM_REG_R4: 0x44444444, UC_ARM_REG_R5: 0x55555555, UC_ARM_REG_R6: 0x66666666, UC_ARM_REG_R7: 0x77777777}
    for r, v in saved_in.items():
        mu.reg_write(r, v)

    mu.emu_start(0x0801BB5C | 1, SENTINEL_LR, count=5000)

    assert mu.reg_read(UC_ARM_REG_PC) == SENTINEL_LR, f"Did not return to LR: PC=0x{mu.reg_read(UC_ARM_REG_PC):08x}"
    assert mu.reg_read(UC_ARM_REG_SP) == sp0, "SP unbalanced after FUN_0801bb5c"
    for r, v in saved_in.items():
        assert mu.reg_read(r) == v, f"Callee-saved reg {r} clobbered!"

    sram_after = bytes(mu.mem_read(SRAM_BASE, SRAM_SIZE))

    def at_bytes(sram, idx):
        off = (AT_TABLE_ADDR - SRAM_BASE) + idx * 12
        return sram[off : off + 12]

    # Verify exact expected mutations (layout: [id, wait, retry, fail_next, ok_next, 0, 0, 0, fn_ptr])
    e35 = struct.unpack("<8BI", at_bytes(sram_after, 35))
    e38 = struct.unpack("<8BI", at_bytes(sram_after, 38))
    e39 = struct.unpack("<8BI", at_bytes(sram_after, 39))
    assert (e35[0], e35[1], e35[2]) == (35, 15, 4), f"AT_TABLE[35] wrong: {e35}"
    assert (e38[0], e38[1]) == (38, 10), f"AT_TABLE[38] wrong: {e38}"
    assert (e39[0], e39[1], e39[3]) == (39, 10, 6), f"AT_TABLE[39] wrong: {e39}"

    # Verify adjacent entries untouched
    for idx in (34, 36, 37, 40):
        assert at_bytes(sram_after, idx) == at_bytes(init_sram, idx), f"AT_TABLE[{idx}] unexpectedly modified!"

    print(f"[PASS] Test 1 (Patch 3): FUN_0801bb5c -> hook_init_at_table -> FUN_08012dc0 "
          f"(AT[35]={e35[1]}s/{e35[2]}x, AT[38]={e38[1]}s, AT[39]={e39[1]}s/fail->{e39[3]})")
    return sram_after


def test_patch1_publish(patched: bytes, post_init_sram: bytes):
    topic_addr = 0x20020000
    payload_addr = 0x20020100
    topic = b"/iot/test/properties/report\x00"
    payload = b'{"hello":"world","n":42}'

    def run_case(cur_id: int, idle_bit: int, tick: int):
        mu = make_emu(patched)
        mu.mem_write(SRAM_BASE, post_init_sram)
        mu.mem_write(topic_addr, topic)
        mu.mem_write(payload_addr, payload)
        # Pre-fill TX buffers with sentinel 0xAA to detect writes
        mu.mem_write(WIFI_CTX_BASE + 1, b"\xaa" * 0x40)
        mu.mem_write(WIFI_CTX_BASE + 0x44, b"\xaa" * 0x40)
        # Set cur_state.id, wifi_status[2], xTickCount, cur_state+8
        mu.mem_write(CUR_STATE_ADDR, bytes([cur_id]))
        mu.mem_write(WIFI_STATUS_ADDR + 2, bytes([0x08 | idle_bit]))  # MQTT_CONNECTED | idle_bit
        mu.mem_write(XTICK_ADDR, struct.pack("<I", tick))
        mu.mem_write(CUR_STATE_TICK, struct.pack("<I", 0xCAFEBABE))

        sp0 = 0x20017000
        mu.reg_write(UC_ARM_REG_SP, sp0)
        mu.reg_write(UC_ARM_REG_LR, SENTINEL_LR | 1)
        mu.reg_write(UC_ARM_REG_R0, topic_addr)
        mu.reg_write(UC_ARM_REG_R1, payload_addr)
        mu.reg_write(UC_ARM_REG_R2, len(payload))
        mu.reg_write(UC_ARM_REG_R3, 1)  # qos=1
        saved_in = {UC_ARM_REG_R4: 0x1111, UC_ARM_REG_R5: 0x2222, UC_ARM_REG_R6: 0x3333, UC_ARM_REG_R7: 0x4444, UC_ARM_REG_R8: 0x5555, UC_ARM_REG_R9: 0x6666, UC_ARM_REG_R10: 0x7777}
        for r, v in saved_in.items():
            mu.reg_write(r, v)

        sem_called = [False]
        idle_at_copy = [None]

        def hook(uc, addr, size, _):
            if addr == 0x0801B4A2:  # right before memset/memcpy of topic
                idle_at_copy[0] = uc.mem_read(WIFI_STATUS_ADDR + 2, 1)[0]
            elif addr == SEM_GIVE_ADDR:
                sem_called[0] = True
                uc.emu_stop()

        mu.hook_add(UC_HOOK_CODE, hook)
        mu.emu_start(0x0801B484 | 1, SENTINEL_LR, count=10000)

        assert mu.reg_read(UC_ARM_REG_SP) == sp0, f"SP unbalanced in FUN_0801b484 (cur_id={cur_id}, idle={idle_bit})"
        for r, v in saved_in.items():
            assert mu.reg_read(r) == v, f"Callee-saved reg {r} clobbered in FUN_0801b484!"
        return mu, sem_called[0], idle_at_copy[0]

    # Case 2a: Normal publish (cur_state=56, IDLE=1)
    mu, sem_called, idle_at_copy = run_case(56, 1, 0x00123456)
    assert sem_called is True, "Normal publish should tail-call xSemaphoreGive!"
    assert (idle_at_copy & 1) == 0 and (idle_at_copy & 8) == 8, f"IDLE bit not cleared before copy! status=0x{idle_at_copy:02x}"
    assert struct.unpack("<I", mu.mem_read(CUR_STATE_TICK, 4))[0] == 0x00123456, "cur_state.last_tick not refreshed!"
    assert bytes(mu.mem_read(WIFI_CTX_BASE + 1, len(topic))) == topic, "Topic not copied!"
    assert bytes(mu.mem_read(WIFI_CTX_BASE + 0x44, len(payload))) == payload, "Payload not copied!"
    new_cur = mu.mem_read(CUR_STATE_ADDR, 5)
    assert new_cur[0] == 38 and new_cur[1] == 10, f"cur_state not set to patched AT_TABLE[38]: {list(new_cur)}"

    # Case 2b: 100ms race while AT+MQTTPUBRAW active (cur_state=38, IDLE=1)
    mu, sem_called, _ = run_case(38, 1, 0x00123500)
    assert sem_called is False and mu.reg_read(UC_ARM_REG_PC) == SENTINEL_LR, "Busy cur_state=38 must abort!"
    assert bytes(mu.mem_read(WIFI_CTX_BASE + 1, 16)) == b"\xaa" * 16, "TX buffer overwritten on aborted race!"
    assert struct.unpack("<I", mu.mem_read(CUR_STATE_TICK, 4))[0] == 0xCAFEBABE

    # Case 2c: 100ms race while IDLE already cleared (cur_state=56, IDLE=0)
    mu, sem_called, _ = run_case(56, 0, 0x00123600)
    assert sem_called is False and mu.reg_read(UC_ARM_REG_PC) == SENTINEL_LR, "IDLE=0 must abort!"
    assert bytes(mu.mem_read(WIFI_CTX_BASE + 1, 16)) == b"\xaa" * 16, "TX buffer overwritten when IDLE=0!"

    print("[PASS] Test 2 (Patch 1): FUN_0801b484 normal publish + both 100ms race-abort paths verified")


def test_patch2_rectask(patched: bytes, post_init_sram: bytes):
    sem_ptr_addr = 0x20020200  # r7 points to semaphore handle pointer

    def run_case(uvar8: int, cur_id: int, cur_wait: int, last_tick: int, now_tick: int):
        mu = make_emu(patched)
        mu.mem_write(SRAM_BASE, post_init_sram)
        mu.mem_write(CUR_STATE_ADDR, bytes([cur_id, cur_wait, 0, 0, 0]))
        mu.mem_write(CUR_STATE_TICK, struct.pack("<I", last_tick))
        mu.mem_write(XTICK_ADDR, struct.pack("<I", now_tick))
        mu.mem_write(WIFI_STATUS_ADDR + 1, bytes([0]))  # wifi_status[1]
        mu.mem_write(sem_ptr_addr, struct.pack("<I", 0x20001234))

        sp0 = 0x20017000
        mu.reg_write(UC_ARM_REG_SP, sp0)
        mu.reg_write(UC_ARM_REG_R4, CUR_STATE_ADDR)
        mu.reg_write(UC_ARM_REG_R5, uvar8)
        mu.reg_write(UC_ARM_REG_R6, WIFI_STATUS_ADDR)
        mu.reg_write(UC_ARM_REG_R7, sem_ptr_addr)
        mu.reg_write(UC_ARM_REG_R9, 0)

        stop_pc = [0]
        sem_called = [False]

        def hook(uc, addr, size, _):
            if addr in (0x0802AECC, 0x0802AF7C):
                stop_pc[0] = addr
                uc.emu_stop()
            elif addr == SEM_GIVE_ADDR:
                sem_called[0] = True
                # Simulate return from BL 0x0802bc48 -> resume at LR (0x0802af50)
                uc.reg_write(UC_ARM_REG_PC, (uc.reg_read(UC_ARM_REG_LR) & ~1) | 1)

        mu.hook_add(UC_HOOK_CODE, hook)
        mu.emu_start(0x0802AEC6 | 1, SENTINEL_LR, count=2000)
        assert mu.reg_read(UC_ARM_REG_SP) == sp0
        return (
            stop_pc[0],
            mu.mem_read(CUR_STATE_ADDR + 1, 1)[0],
            struct.unpack("<I", mu.mem_read(CUR_STATE_TICK, 4))[0],
            sem_called[0],
        )

    # 3a: Handled AT response (uVar8 = 1)
    pc, wait, tick, sem = run_case(1, 38, 10, 1000, 1400)
    assert pc == 0x0802AECC and wait == 10 and tick == 1400 and not sem

    # 3b: Unsolicited RX while IDLE (state 56)
    pc, wait, tick, sem = run_case(0, 56, 5, 1000, 3500)
    assert pc == 0x0802AF7C and wait == 5 and tick == 3500 and not sem

    # 3c: Unsolicited RX while state=38, elapsed = 500 ms (< 1000 ms)
    pc, wait, tick, sem = run_case(0, 38, 10, 5000, 5500)
    assert pc == 0x0802AF7C and wait == 10 and tick == 5000 and not sem

    # 3d: Unsolicited RX while state=38, elapsed = 1050 ms across 32-bit wrap!
    pc, wait, tick, sem = run_case(0, 38, 10, 0xFFFFFE00, 0x0000021A)
    assert pc == 0x0802AF7C and wait == 9 and tick == 0x0000021A and not sem

    # 3e: Unsolicited RX while state=38, wait=0, elapsed = 1000 ms -> triggers timeout wakeup!
    pc, wait, tick, sem = run_case(0, 38, 0, 10000, 11000)
    assert pc == 0x0802AF7C and wait == 0 and tick == 11000 and sem is True

    # 3f: Inbound MQTT properties/write (uVar8 = 0x100) while state=38, elapsed >= 1000 ms -> MUST decrement wait!
    pc, wait, tick, sem = run_case(0x0100, 38, 10, 20000, 21100)
    assert pc == 0x0802AF7C and wait == 9 and tick == 21100 and not sem

    # 3g: High-byte state switch (uVar8 = 0x1000 -> AT_TABLE[1] wait=0) after >1s IDLE -> MUST refresh tick & NOT double-wake!
    pc, wait, tick, sem = run_case(0x1000, 1, 0, 10000, 50000)
    assert pc == 0x0802AF7C and wait == 0 and tick == 50000 and sem is False

    # 3h: BLE transparent mode (state=54) with frequent BLE OTA RX -> MUST NOT touch timeouts!
    pc, wait, tick, sem = run_case(0, 54, 0, 10000, 50000)
    assert pc == 0x0802AF7C and wait == 0 and tick == 50000 and sem is False

    print("[PASS] Test 3 (Patch 2): wifi_rectask hook verified across all 8 branches + 32-bit wraparound + 0x1000/0x100/BLE")


def test_patch4_disconnect(patched: bytes, post_init_sram: bytes):
    msg_addr = 0x20020300

    def run_case(cur_id: int, rx_msg: bytes, init_st2: int = 0x09):
        mu = make_emu(patched)
        mu.mem_write(SRAM_BASE, post_init_sram)
        mu.mem_write(msg_addr, rx_msg + b"\x00")
        # Ensure debug printf flag disabled and wifi_status[4] != 4 (not BLE mode)
        mu.mem_write(WIFI_STATUS_ADDR, bytes([0, 0, init_st2, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        sp0 = 0x20017000
        mu.reg_write(UC_ARM_REG_SP, sp0)
        mu.reg_write(UC_ARM_REG_LR, SENTINEL_LR | 1)
        mu.reg_write(UC_ARM_REG_R0, cur_id)
        mu.reg_write(UC_ARM_REG_R1, msg_addr)
        mu.reg_write(UC_ARM_REG_R2, len(rx_msg))
        saved_in = {UC_ARM_REG_R4: 0xA4, UC_ARM_REG_R5: 0xA5, UC_ARM_REG_R6: 0xA6, UC_ARM_REG_R7: 0xA7, UC_ARM_REG_R8: 0xA8, UC_ARM_REG_R9: 0xA9, UC_ARM_REG_R10: 0xAA, UC_ARM_REG_R11: 0xAB}
        for r, v in saved_in.items():
            mu.reg_write(r, v)

        mu.emu_start(0x0801B500 | 1, SENTINEL_LR, count=20000)
        assert mu.reg_read(UC_ARM_REG_PC) == SENTINEL_LR, f"FUN_0801b500 did not return cleanly: PC=0x{mu.reg_read(UC_ARM_REG_PC):08x}"
        assert mu.reg_read(UC_ARM_REG_SP) == sp0
        for r, v in saved_in.items():
            assert mu.reg_read(r) == v, f"Callee-saved reg {r} clobbered in FUN_0801b500!"
        return mu.reg_read(UC_ARM_REG_R0), bytes(mu.mem_read(WIFI_STATUS_ADDR, 12))

    # 4a: MQTT_DISCONNECT while IDLE (56) -> returns 0x1000, clears bit 3
    ret, st = run_case(56, b"+EVENT:MQTT_DISCONNECT\r\n")
    assert ret == 0x1000 and (st[2] & 8) == 0 and st[10] == 1, f"4a failed: ret=0x{ret:x} st={list(st)}"

    # 4b: MQTT_DISCONNECT while PUBRAW (38) -> returns 0x1000
    ret, st = run_case(38, b"+EVENT:MQTT_DISCONNECT\r\n")
    assert ret == 0x1000 and (st[2] & 8) == 0 and st[10] == 1

    # 4c: MQTT_DISCONNECT while connecting (35 <= 36) -> returns 0, clears bit 3
    ret, st = run_case(35, b"+EVENT:MQTT_DISCONNECT\r\n")
    assert ret == 0 and (st[2] & 8) == 0 and st[10] == 1

    # 4d: MQTT_CONNECT while connecting (35) -> sets bit 3 (0x01 -> 0x09), wifi_status[10]=2, returns 1 (AT matched)
    ret, st = run_case(35, b"+EVENT:MQTT_CONNECT\r\n", init_st2=0x01)
    assert ret == 1 and (st[2] & 8) == 8 and st[10] == 2, f"4d failed: ret=0x{ret:x} st={list(st)}"

    # 4e: BLE_DISCONNECT (cave at 0x0801b572) -> sets wifi_status[4]=2, [10]=1, returns 0x800
    ret, st = run_case(56, b"+EVENT:BLE_DISCONNECT\r\n")
    assert ret == 0x800 and st[4] == 2 and st[10] == 1, f"4e failed: ret=0x{ret:x} st={list(st)}"

    print("[PASS] Test 4 (Patch 4): FUN_0801b500 MQTT_DISCONNECT (IDLE/PUB/CONN), MQTT_CONNECT, and BLE_DISCONNECT verified")


def main():
    ap = argparse.ArgumentParser(description="Unicorn Cortex-M emulation verification for MASTER_v2.1.47_mqttfix.bin")
    ap.add_argument("--orig", default="./hyper2000_fw/MASTER_v2.1.47.bin")
    ap.add_argument("--patched", default="./hyper2000_fw/MASTER_v2.1.47_mqttfix.bin")
    args = ap.parse_args()

    orig = Path(args.orig).read_bytes()
    patched = Path(args.patched).read_bytes()
    assert len(patched) % 16 == 0, f"Patched binary not 16-byte aligned: {len(patched)}"

    init_sram = test_scatterload(orig, patched)
    post_init_sram = test_patch3_init_at_table(patched, init_sram)
    test_patch1_publish(patched, post_init_sram)
    test_patch2_rectask(patched, post_init_sram)
    test_patch4_disconnect(patched, post_init_sram)
    print("\nALL 5 CORTEX-M EMULATION TESTS PASSED!")


if __name__ == "__main__":
    main()
