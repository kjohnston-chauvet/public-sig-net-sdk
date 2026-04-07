"""Sig-Net Protocol Framework - TLV Payload Construction.

Type-Length-Value encoding for application payloads.
Format: 2-byte Type | 2-byte Length | Variable Value data (all network byte order).
"""

from __future__ import annotations

import struct

from .constants import MAX_DMX_SLOTS, TID, TUID_LENGTH
from .exceptions import InvalidArgError


def encode_tlv(type_id: int, value: bytes) -> bytes:
    """Encode a generic TLV block: Type(2) + Length(2) + Value."""
    return struct.pack("!HH", type_id, len(value)) + value


def encode_tid_level(dmx_data: bytes) -> bytes:
    """Encode TID_LEVEL (DMX level data, 1-512 bytes)."""
    if not (1 <= len(dmx_data) <= MAX_DMX_SLOTS):
        raise InvalidArgError(f"DMX slot count {len(dmx_data)} out of range 1-{MAX_DMX_SLOTS}")
    return encode_tlv(TID.LEVEL, dmx_data)


def encode_tid_priority(priority_data: bytes) -> bytes:
    """Encode TID_PRIORITY (per-slot priority, 1-512 bytes)."""
    if not (1 <= len(priority_data) <= MAX_DMX_SLOTS):
        raise InvalidArgError(f"Priority slot count {len(priority_data)} out of range 1-{MAX_DMX_SLOTS}")
    return encode_tlv(TID.PRIORITY, priority_data)


def encode_tid_sync() -> bytes:
    """Encode TID_SYNC (zero-length sync trigger)."""
    return encode_tlv(TID.SYNC, b"")


def encode_tid_poll_reply(
    tuid: bytes,
    mfg_code: int,
    product_variant_id: int,
    change_count: int,
) -> bytes:
    """Encode TID_POLL_REPLY (12 bytes): TUID(6) + SOEM_CODE(4) + CHANGE_COUNT(2)."""
    if len(tuid) != TUID_LENGTH:
        raise InvalidArgError(f"TUID must be {TUID_LENGTH} bytes")
    soem_code = (mfg_code << 16) | product_variant_id
    value = tuid + struct.pack("!IH", soem_code, change_count)
    return encode_tlv(TID.POLL_REPLY, value)


def encode_tid_protocol_version(protocol_version: int) -> bytes:
    """Encode TID_RT_PROTOCOL_VERSION (1 byte)."""
    return encode_tlv(TID.RT_PROTOCOL_VERSION, bytes([protocol_version]))


def encode_tid_firmware_version(machine_version_id: int, version_string: str) -> bytes:
    """Encode TID_RT_FIRMWARE_VERSION: Machine Version ID (4 bytes) + UTF-8 string."""
    encoded_str = version_string.encode("utf-8")
    if len(encoded_str) > 64:
        raise InvalidArgError("Firmware version string exceeds 64 bytes")
    value = struct.pack("!I", machine_version_id) + encoded_str
    return encode_tlv(TID.RT_FIRMWARE_VERSION, value)


def encode_tid_role_capability(role_capability_bits: int) -> bytes:
    """Encode TID_RT_ROLE_CAPABILITY (1 byte)."""
    return encode_tlv(TID.RT_ROLE_CAPABILITY, bytes([role_capability_bits]))


def build_dmx_level_payload(dmx_data: bytes) -> bytes:
    """Build a complete DMX payload (single TID_LEVEL TLV)."""
    return encode_tid_level(dmx_data)


def build_startup_announce_payload(
    tuid: bytes,
    mfg_code: int,
    product_variant_id: int,
    firmware_version_id: int,
    firmware_version_string: str,
    protocol_version: int,
    role_capability_bits: int,
    change_count: int,
) -> bytes:
    """Build startup announce payload with fixed TLV ordering (Section 10.2.5)."""
    buf = bytearray()
    buf.extend(encode_tid_poll_reply(tuid, mfg_code, product_variant_id, change_count))
    buf.extend(encode_tid_firmware_version(firmware_version_id, firmware_version_string))
    buf.extend(encode_tid_protocol_version(protocol_version))
    buf.extend(encode_tid_role_capability(role_capability_bits))
    return bytes(buf)
