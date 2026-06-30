"""Per-protocol observation extractors.

These do not parse complete sessions — they pull the few facts that change how a
flow should be read: is it a read, a write, or a programming/control action?
Writes and programming to a controller are what an analyst actually wants flagged.
"""
from __future__ import annotations

_MODBUS_FC = {
    0x01: "read_coils", 0x02: "read_discrete_inputs",
    0x03: "read_holding_registers", 0x04: "read_input_registers",
    0x05: "write_single_coil", 0x06: "write_single_register",
    0x0F: "write_multiple_coils", 0x10: "write_multiple_registers",
    0x16: "mask_write_register", 0x17: "read_write_multiple",
    0x2B: "read_device_id",
}
_MODBUS_WRITES = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17}


def modbus_obs(payload: bytes) -> set[str]:
    obs: set[str] = set()
    if len(payload) < 8:
        return obs
    fc = payload[7]
    base = fc & 0x7F
    name = _MODBUS_FC.get(base)
    if name:
        obs.add(name)
    if base in _MODBUS_WRITES:
        obs.add("write")
    if fc & 0x80:
        obs.add("exception_reply")
    return obs


def s7_obs(payload: bytes) -> set[str]:
    obs: set[str] = set()
    if not payload or payload[0] != 0x03:
        return obs
    # COTP connection request
    if len(payload) > 5 and payload[5] == 0xE0:
        obs.add("s7_connect")
    # Locate S7 protocol id 0x32 after TPKT(4)+COTP
    idx = payload.find(b"\x32", 4, 12)
    if idx != -1 and len(payload) > idx + 1:
        rosctr = payload[idx + 1]
        # parameter function byte sits after header (10 bytes) -> idx+10
        func = payload[idx + 10] if len(payload) > idx + 10 else 0
        if func == 0xF0:
            obs.add("s7_setup")
        elif func == 0x04:
            obs.add("s7_read")
        elif func == 0x05:
            obs.add("s7_write"); obs.add("write")
        elif func in (0x1A, 0x1B, 0x1C, 0x1D, 0x28, 0x29):
            obs.add("s7_programming"); obs.add("write")  # upload/download blocks
        if rosctr == 0x07:
            obs.add("s7_szl")  # diagnostic / identification
    return obs


def enip_obs(payload: bytes) -> set[str]:
    obs: set[str] = set()
    if not payload:
        return obs
    cmd = payload[0]
    if cmd == 0x6F:  # SendRRData (explicit messaging, may carry writes)
        obs.add("enip_explicit")
    elif cmd == 0x65:
        obs.add("enip_register_session")
    return obs


DECODERS = {"modbus": modbus_obs, "s7comm": s7_obs, "enip": enip_obs}


def observe(short: str, payload: bytes) -> set[str]:
    fn = DECODERS.get(short)
    return fn(payload) if fn else set()
