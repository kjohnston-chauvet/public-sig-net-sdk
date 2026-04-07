"""Tests for signet.tlv — ports C++ self-tests 11-12."""

from __future__ import annotations

import struct

from signet.constants import TID
from signet.tlv import (
    build_dmx_level_payload,
    build_startup_announce_payload,
    encode_tid_level,
    encode_tid_sync,
    encode_tlv,
)


# ---- C++ Self-Test 11: Build DMX Payload ----

def test_build_dmx_payload():
    dmx_data = bytes([42] * 512)
    payload = build_dmx_level_payload(dmx_data)
    assert len(payload) > 0
    # TID_LEVEL header: 2 bytes type + 2 bytes length + 512 bytes data = 516
    assert len(payload) == 516
    # Check TID
    tid = struct.unpack_from("!H", payload, 0)[0]
    assert tid == TID.LEVEL
    # Check length
    length = struct.unpack_from("!H", payload, 2)[0]
    assert length == 512


# ---- C++ Self-Test 12: Build Announce Payload ----

def test_build_announce_payload():
    tuid = bytes.fromhex("534C00000001")
    payload = build_startup_announce_payload(
        tuid=tuid,
        mfg_code=0x534C,
        product_variant_id=0,
        firmware_version_id=0x0100BC,
        firmware_version_string="v1.0.0",
        protocol_version=1,
        role_capability_bits=0x01,
        change_count=0,
    )
    assert len(payload) > 0


# ---- Additional: TID_SYNC is zero-length ----

def test_tid_sync_zero_length():
    data = encode_tid_sync()
    assert len(data) == 4  # type(2) + length(2), no value
    tid = struct.unpack_from("!H", data, 0)[0]
    length = struct.unpack_from("!H", data, 2)[0]
    assert tid == TID.SYNC
    assert length == 0


# ---- Additional: Generic TLV encoding ----

def test_encode_tlv_generic():
    data = encode_tlv(0x1234, b"\x01\x02\x03")
    assert data == b"\x12\x34\x00\x03\x01\x02\x03"
