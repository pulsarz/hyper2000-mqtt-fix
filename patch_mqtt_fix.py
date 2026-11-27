#!/usr/bin/env python3
"""
Comprehensive binary patch (v2) for Zendure Hyper 2000 MASTER_v2.1.47.bin.

Fixes four interlocking MQTT hang / stuck-connection bugs:
  1. FUN_0801b484 (100 ms double-publish race under frequent commands):
     - Stock firmware starts AT+MQTTPUBRAW (state 38) without clearing wifi_status[2]
       bit 0 (IDLE). Under frequent properties/write traffic, if BL602 takes >100 ms to
       respond, FUN_08019194 fires again 100 ms later and injects a second AT+MQTTPUBRAW
       into BL602's active raw-payload UART input mode (desyncing UART while BL602 still
       sends MQTT PINGREQ to EMQX).
     - Fix: Verify cur_state.id >= 53 and IDLE bit == 1, immediately clear IDLE bit 0,
       and refresh cur_state.last_tick before copying payload and waking wifi_sendtask.

  2. wifi_rectask @ 0x0802ad68 (timeout starvation under frequent MQTT_SUB):
     - Stock firmware only decrements cur_state.wait when xQueueReceive(..., 1000)
       times out (a full 1000 ms of UART silence). Frequent inbound MQTT_SUB or
       SocketDown traffic (<1 s interval) prevents any AT timeout from ever firing.
     - Fix: Track FreeRTOS xTickCount (0x20000010) in unused RAM slot cur_state+8
       (0x2000f01c) so cur_state.wait still decrements every 1000 ms during continuous
       unsolicited UART RX traffic.

  3. AT_TABLE timeouts & failure recovery (FUN_0801bb5c startup hook):
     - AT_TABLE[39] (AT+MQTTPUBRAW payload): fail_next changed from 56 (IDLE!) -> 6 (AT+RST),
       wait 20s -> 10s. Previously a payload ERROR/timeout silently dropped back to IDLE
       with MQTT still marked connected and never recovered.
     - AT_TABLE[38] (AT+MQTTPUBRAW header): wait 20s -> 10s (20s max before AT+RST).
     - AT_TABLE[35] (AT+MQTT connect): wait 40s -> 15s, retry 15 -> 4 (60s max vs 600s).

  4. FUN_0801b500 (MQTT_DISCONNECT indefinite deadlock in IDLE 56):
     - Stock firmware clears MQTT_CONNECTED bit and stays in IDLE (56) forever without
       reconnecting or re-running AT+MQTTSUB.
     - Fix: When MQTT_DISCONNECT arrives while cur_state.id > 36 (IDLE/PUB), return
       event 0x1000 so wifi_rectask immediately triggers a clean reconnect + AT+MQTTSUB.
"""

import argparse
import hashlib
import struct
import zlib
from pathlib import Path

BASE = 0x08005000
ORIG_SIZE = 166000
ORIG_CRC16 = 0x10A2
ORIG_CRC32 = 0xBB69502B
ORIG_MD5 = "38f613e4f5e8c146ce271e9cbafe0e58"
ORIG_SHA256 = "cbb8d6049c0f5e51bc82d1da32c83dc6866d7f213677415a56024462f51adae2"

EXPECTED_OUT_SIZE = 166176
EXPECTED_OUT_CRC16 = 0x048C
EXPECTED_OUT_CRC32 = 0x732DB954
EXPECTED_OUT_MD5 = "8e1acd622cf94299fe164b672b4bc680"

TRAMP_BASE = BASE + ORIG_SIZE  # 0x0802d870 (4-byte aligned, right after compressed .data)


def enc_bw(pc: int, target: int) -> bytes:
    """Encode 32-bit Thumb-2 unconditional branch B.W (T4)."""
    delta = target - (pc + 4)
    assert -16777216 <= delta <= 16777214 and (delta & 1) == 0, f"B.W out of range: {delta}"
    imm24 = (delta >> 1) & 0xFFFFFF
    s = (imm24 >> 23) & 1
    i1 = (imm24 >> 22) & 1
    i2 = (imm24 >> 21) & 1
    j1 = (~i1 ^ s) & 1
    j2 = (~i2 ^ s) & 1
    imm10 = (imm24 >> 11) & 0x3FF
    imm11 = imm24 & 0x7FF
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack("<HH", hw1, hw2)


def enc_b_cond16(pc: int, target: int, cond: int) -> bytes:
    """Encode 16-bit Thumb conditional branch B<cond> (T1)."""
    delta = target - (pc + 4)
    assert -256 <= delta <= 254 and (delta & 1) == 0, f"B<cond> out of range: {delta}"
    imm8 = (delta >> 1) & 0xFF
    return struct.pack("<H", 0xD000 | (cond << 8) | imm8)


def enc_ldr_lit16(pc: int, reg: int, lit_addr: int) -> bytes:
    """Encode 16-bit Thumb LDR Rt, [PC, #imm8*4] (T1)."""
    base = (pc + 4) & ~3
    delta = lit_addr - base
    assert 0 <= delta <= 1020 and (delta & 3) == 0, f"LDR lit out of range: {delta}"
    return struct.pack("<H", 0x4800 | (reg << 8) | (delta >> 2))


def crc16_zendure(buf: bytes, fw_data: bytes) -> int:
    """Exact CRC-16 matching FUN_0800a308 (byte-swapped CRC-16/Modbus)."""
    tbl_addr = struct.unpack_from("<I", fw_data, 0x0800A330 - BASE)[0]
    hi = fw_data[tbl_addr - BASE : tbl_addr - BASE + 256]
    lo = fw_data[tbl_addr - BASE + 256 : tbl_addr - BASE + 512]
    r3 = 0xFF
    r0 = 0xFF
    for b in buf:
        idx = b ^ r3
        r3 = hi[idx] ^ r0
        r0 = lo[idx]
    return (r3 << 8) | r0


def build_trampolines(base_addr: int) -> tuple[bytes, dict]:
    """Assemble the three helper trampolines placed at base_addr (0x0802d870)."""
    # Layout:
    #   +0x00: hook_publish       (FUN_0801b484 guard + immediate IDLE clear + last_tick refresh)
    #   +0x34: hook_rectask_rx    (wifi_rectask tick-based timeout check on unsolicited RX)
    #   +0x74: hook_init_at_table (FUN_0801bb5c AT_TABLE[35,38,39] startup patch)
    #   +0xa4: literal pool       (0x20000010 = &xTickCount, 0x2000013c = AT_TABLE)
    lit_tick = base_addr + 0xA4
    lit_attbl = base_addr + 0xA8
    code = bytearray()
    syms = {}

    # ---- 1. hook_publish @ base_addr + 0x00 ----
    syms["hook_publish"] = base_addr + len(code)
    # Entry: r5 = 0x2000e5c8; cur_state = [r5, #0xa4c]; cur_state+8 = [r5, #0xa54]; wifi_status[2] = [r5, #0x77e]
    code += bytes.fromhex("95f84c0a")                          # ldrb.w r0, [r5, #0xa4c]  (cur_state.id)
    code += bytes.fromhex("3528")                              # cmp    r0, #0x35
    p_blo = base_addr + len(code); code += b"\x00\x00"         # blo    .pub_abort
    code += bytes.fromhex("95f87e07")                          # ldrb.w r0, [r5, #0x77e]  (wifi_status[2])
    code += bytes.fromhex("10f0010f")                          # tst.w  r0, #1
    p_beq = base_addr + len(code); code += b"\x00\x00"         # beq    .pub_abort
    code += bytes.fromhex("20f00100")                          # bic.w  r0, r0, #1        (clear IDLE bit!)
    code += bytes.fromhex("85f87e07")                          # strb.w r0, [r5, #0x77e]
    code += enc_ldr_lit16(base_addr + len(code), 1, lit_tick)  # ldr    r1, =0x20000010   (&xTickCount)
    code += bytes.fromhex("0968")                              # ldr    r1, [r1]          (now_ms)
    code += bytes.fromhex("c5f8541a")                          # str.w  r1, [r5, #0xa54]  (cur_state.last_tick = now)
    code += bytes.fromhex("4021")                              # movs   r1, #0x40         (displaced)
    code += bytes.fromhex("681c")                              # adds   r0, r5, #1        (displaced)
    code += enc_bw(base_addr + len(code), 0x0801B4A2)          # b.w    0x0801b4a2        (resume FUN_0801b484)
    pub_abort = base_addr + len(code)
    code += enc_bw(base_addr + len(code), 0x0801B4F0)          # b.w    0x0801b4f0        (pop & return)
    # Patch short conditional branches in hook_publish
    code[p_blo - base_addr : p_blo - base_addr + 2] = enc_b_cond16(p_blo, pub_abort, 0x3)  # BLO (CC)
    code[p_beq - base_addr : p_beq - base_addr + 2] = enc_b_cond16(p_beq, pub_abort, 0x0)  # BEQ

    while len(code) < 0x34:
        code += b"\x00\xbf"  # nop

    # ---- 2. hook_rectask_rx @ base_addr + 0x34 ----
    syms["hook_rectask_rx"] = base_addr + len(code)
    # Entry from 0x0802aec6: r4 = cur_state (0x2000f014), r5 = uVar8, r0..r3 scratch
    code += bytes.fromhex("15f0ff0f")                          # tst.w  r5, #0xff
    p_handled = base_addr + len(code); code += b"\x00\x00"     # bne    .rx_handled
    code += bytes.fromhex("b5f5806f")                          # cmp.w  r5, #0x400        (state-switch event 0x400..0x8000?)
    p_hiev = base_addr + len(code); code += b"\x00\x00"        # bhs    .rx_idle_refresh  (refresh tick, no double-wake!)
    code += bytes.fromhex("2078")                              # ldrb   r0, [r4]          (cur_state.id)
    code += bytes.fromhex("411e")                              # subs   r1, r0, #1
    code += bytes.fromhex("3429")                              # cmp    r1, #0x34         (in 1..52?)
    p_idle = base_addr + len(code); code += b"\x00\x00"        # bhs    .rx_idle_refresh
    code += enc_ldr_lit16(base_addr + len(code), 2, lit_tick)  # ldr    r2, =0x20000010
    code += bytes.fromhex("1068")                              # ldr    r0, [r2]          (now_ms)
    code += bytes.fromhex("a168")                              # ldr    r1, [r4, #8]      (last_tick)
    code += bytes.fromhex("421a")                              # subs   r2, r0, r1        (elapsed_ms)
    code += bytes.fromhex("b2f57a7f")                          # cmp.w  r2, #1000
    p_lt1s = base_addr + len(code); code += b"\x00\x00"        # blo    .rx_exit
    code += bytes.fromhex("a060")                              # str    r0, [r4, #8]      (last_tick = now)
    code += enc_bw(base_addr + len(code), 0x0802AF10)          # b.w    0x0802af10        (run timeout decrement!)

    rx_handled = base_addr + len(code)
    code += enc_ldr_lit16(base_addr + len(code), 2, lit_tick)  # ldr    r2, =0x20000010
    code += bytes.fromhex("1068")                              # ldr    r0, [r2]
    code += bytes.fromhex("a060")                              # str    r0, [r4, #8]
    code += enc_bw(base_addr + len(code), 0x0802AECC)          # b.w    0x0802aecc        (resume original)

    rx_idle_refresh = base_addr + len(code)
    code += enc_ldr_lit16(base_addr + len(code), 2, lit_tick)  # ldr    r2, =0x20000010
    code += bytes.fromhex("1068")                              # ldr    r0, [r2]
    code += bytes.fromhex("a060")                              # str    r0, [r4, #8]
    rx_exit = base_addr + len(code)
    code += enc_bw(base_addr + len(code), 0x0802AF7C)          # b.w    0x0802af7c        (bottom of loop)

    code[p_handled - base_addr : p_handled - base_addr + 2] = enc_b_cond16(p_handled, rx_handled, 0x1)   # BNE
    code[p_hiev - base_addr : p_hiev - base_addr + 2] = enc_b_cond16(p_hiev, rx_idle_refresh, 0x2)       # BHS (CS)
    code[p_idle - base_addr : p_idle - base_addr + 2] = enc_b_cond16(p_idle, rx_idle_refresh, 0x2)       # BHS (CS)
    code[p_lt1s - base_addr : p_lt1s - base_addr + 2] = enc_b_cond16(p_lt1s, rx_exit, 0x3)               # BLO (CC)

    while len(code) < 0x74:
        code += b"\x00\xbf"  # nop

    # ---- 3. hook_init_at_table @ base_addr + 0x74 ----
    syms["hook_init_at_table"] = base_addr + len(code)
    # Entry from 0x0801bb70 (FUN_0801bb5c tail call to 0x08012dc0)
    code += enc_ldr_lit16(base_addr + len(code), 0, lit_attbl) # ldr    r0, =0x2000013c   (AT_TABLE)
    code += bytes.fromhex("0621")                              # movs   r1, #6
    code += bytes.fromhex("80f8d711")                          # strb.w r1, [r0, #0x1d7]  (AT_TABLE[39].fail_next = 6)
    code += bytes.fromhex("0a21")                              # movs   r1, #10
    code += bytes.fromhex("80f8d511")                          # strb.w r1, [r0, #0x1d5]  (AT_TABLE[39].wait = 10s)
    code += bytes.fromhex("80f8c911")                          # strb.w r1, [r0, #0x1c9]  (AT_TABLE[38].wait = 10s)
    code += bytes.fromhex("0f21")                              # movs   r1, #15
    code += bytes.fromhex("80f8a511")                          # strb.w r1, [r0, #0x1a5]  (AT_TABLE[35].wait = 15s)
    code += bytes.fromhex("0421")                              # movs   r1, #4
    code += bytes.fromhex("80f8a611")                          # strb.w r1, [r0, #0x1a6]  (AT_TABLE[35].retry = 4)
    code += enc_bw(base_addr + len(code), 0x08012DC0)          # b.w    0x08012dc0        (original tail call)

    while len(code) < 0xA4:
        code += b"\x00\xbf"  # nop

    assert base_addr + len(code) == lit_tick
    code += struct.pack("<I", 0x20000010)  # &xTickCount
    assert base_addr + len(code) == lit_attbl
    code += struct.pack("<I", 0x2000013C)  # AT_TABLE
    # Pad to 16-byte boundary (176 bytes total -> 166,176 B, matching stock 16-byte alignment)
    while len(code) % 16 != 0:
        code += b"\xff"

    return bytes(code), syms


def apply_patch(orig: bytes) -> tuple[bytes, dict]:
    assert len(orig) == ORIG_SIZE, f"Expected {ORIG_SIZE} bytes (MASTER_v2.1.47.bin), got {len(orig)}"
    in_crc16 = crc16_zendure(orig, orig)
    in_crc32 = zlib.crc32(orig) & 0xFFFFFFFF
    in_md5 = hashlib.md5(orig).hexdigest()
    in_sha256 = hashlib.sha256(orig).hexdigest()
    assert in_crc16 == ORIG_CRC16, f"Input CRC16 mismatch: expected 0x{ORIG_CRC16:04x}, got 0x{in_crc16:04x}"
    assert in_crc32 == ORIG_CRC32, f"Input CRC32 mismatch: expected 0x{ORIG_CRC32:08x}, got 0x{in_crc32:08x}"
    assert in_md5 == ORIG_MD5, f"Input MD5 mismatch: expected {ORIG_MD5}, got {in_md5}"
    assert in_sha256 == ORIG_SHA256, f"Input SHA256 mismatch: expected {ORIG_SHA256}, got {in_sha256}"

    buf = bytearray(orig)

    tramp_bytes, syms = build_trampolines(TRAMP_BASE)

    # --- Patch 1: FUN_0801b484 @ 0x0801b49e..0x0801b4a1 ---
    off1 = 0x0801B49E - BASE
    assert buf[off1 : off1 + 4] == bytes.fromhex("4021681c"), "Mismatch at FUN_0801b484 (0x0801b49e)"
    buf[off1 : off1 + 4] = enc_bw(0x0801B49E, syms["hook_publish"])

    # --- Patch 2: wifi_rectask @ 0x0802aec6..0x0802aecb ---
    off2 = 0x0802AEC6 - BASE
    assert buf[off2 : off2 + 6] == bytes.fromhex("15f0ff0f57d0"), "Mismatch at wifi_rectask (0x0802aec6)"
    buf[off2 : off2 + 6] = enc_bw(0x0802AEC6, syms["hook_rectask_rx"]) + bytes.fromhex("00bf")

    # --- Patch 3: FUN_0801bb5c @ 0x0801bb70..0x0801bb73 ---
    off3 = 0x0801BB70 - BASE
    assert buf[off3 : off3 + 4] == bytes.fromhex("f7f726b9"), "Mismatch at FUN_0801bb5c (0x0801bb70)"
    buf[off3 : off3 + 4] = enc_bw(0x0801BB70, syms["hook_init_at_table"])

    # --- Patch 4: FUN_0801b500 (MQTT_DISCONNECT -> 0x1000 reconnect) ---
    off4_cave = 0x0801B572 - BASE
    expected_cave = bytes.fromhex("98f80500012802d088f80a901de088f80a901ae0")
    assert buf[off4_cave : off4_cave + len(expected_cave)] == expected_cave, "Mismatch at 0x0801b572"
    buf[off4_cave : off4_cave + len(expected_cave)] = bytes.fromhex(
        "88f80a90"  # strb.w sb, [r8, #0xa]
        "21e0"      # b      0x0801b5bc
        "242f"      # cmp    r7, #0x24
        "1fdd"      # ble    0x0801b5bc
        "4ff48055"  # mov.w  r5, #0x1000
        "1ce0"      # b      0x0801b5bc
        "00bf00bf"  # nop; nop
    )
    off4_br = 0x0801B5A0 - BASE
    assert buf[off4_br : off4_br + 2] == bytes.fromhex("0ce0"), "Mismatch at 0x0801b5a0"
    buf[off4_br : off4_br + 2] = bytes.fromhex("eae7")  # b 0x0801b578

    # Append trampoline block at 0x0802d870
    buf += tramp_bytes
    patched = bytes(buf)

    out_crc16 = crc16_zendure(patched, orig)
    out_crc32 = zlib.crc32(patched) & 0xFFFFFFFF
    out_md5 = hashlib.md5(patched).hexdigest()
    assert len(patched) == EXPECTED_OUT_SIZE, f"Output size mismatch: {len(patched)}"
    assert out_crc16 == EXPECTED_OUT_CRC16, f"Output CRC16 mismatch: expected 0x{EXPECTED_OUT_CRC16:04x}, got 0x{out_crc16:04x}"
    assert out_crc32 == EXPECTED_OUT_CRC32, f"Output CRC32 mismatch: expected 0x{EXPECTED_OUT_CRC32:08x}, got 0x{out_crc32:08x}"
    assert out_md5 == EXPECTED_OUT_MD5, f"Output MD5 mismatch: expected {EXPECTED_OUT_MD5}, got {out_md5}"

    return patched, syms


def main():
    parser = argparse.ArgumentParser(description="Patch MASTER_v2.1.47.bin (v2 comprehensive MQTT fix).")
    parser.add_argument("-i", "--input", default="./hyper2000_fw/MASTER_v2.1.47.bin", help="Input MASTER_v2.1.47.bin")
    parser.add_argument("-o", "--output", default="./hyper2000_fw/MASTER_v2.1.47_mqttfix.bin", help="Output patched .bin")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    orig = in_path.read_bytes()
    patched, syms = apply_patch(orig)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(patched)

    crc16 = crc16_zendure(patched, orig)
    crc32 = zlib.crc32(patched) & 0xFFFFFFFF
    md5 = hashlib.md5(patched).hexdigest()
    print(f"Wrote patched firmware (v2): {out_path}")
    print(f"  Trampolines: {', '.join(f'{k}=0x{v:08x}' for k, v in syms.items())}")
    print(f"  Size       : {len(patched)} bytes (+{len(patched) - len(orig)} bytes)")
    print(f"  CRC16      : 0x{crc16:04x} ({crc16})  [FUN_0800a308 / BLE otareq CRC16]")
    print(f"  CRC32      : 0x{crc32:08x} ({crc32})  [FUN_0801de94]")
    print(f"  MD5        : {md5}")


if __name__ == "__main__":
    main()
