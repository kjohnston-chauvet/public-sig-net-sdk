"""Sig-Net Protocol Framework - Packet Assembly.

High-level packet construction orchestrating CoAP, security, HMAC, and TLV.
Includes multicast address calculation and sequence management.
"""

from __future__ import annotations

import struct

from .coap import (
    build_coap_header,
    build_node_uri_path_options,
    build_node_uri_string,
    build_uri_path_options,
    build_uri_string,
)
from .constants import (
    COAP_OPTION_URI_PATH,
    COAP_PAYLOAD_MARKER,
    MAX_DMX_SLOTS,
    MAX_UDP_PAYLOAD,
    MAX_UNIVERSE,
    MIN_UNIVERSE,
    MULTICAST_BASE_OCTET_0,
    MULTICAST_BASE_OCTET_1,
    MULTICAST_BASE_OCTET_2,
    SECURITY_MODE_HMAC_SHA256,
    SIGNET_OPTION_SEQ_NUM,
)
from .crypto import tuid_to_hex
from .exceptions import BufferFullError, InvalidArgError
from .security import (
    build_sender_id,
    build_signet_options_without_hmac,
    calculate_and_encode_hmac,
)
from .tlv import build_dmx_level_payload, build_startup_announce_payload
from .types import SigNetOptions


def calculate_multicast_address(universe: int) -> str:
    """Calculate multicast IP address for a universe (Section 9.2.3).

    Formula: 239.254.0.{((universe - 1) % 100) + 1}
    """
    if universe < MIN_UNIVERSE or universe > MAX_UNIVERSE:
        raise InvalidArgError(f"Universe {universe} out of range {MIN_UNIVERSE}-{MAX_UNIVERSE}")
    index = ((universe - 1) % 100) + 1
    return f"{MULTICAST_BASE_OCTET_0}.{MULTICAST_BASE_OCTET_1}.{MULTICAST_BASE_OCTET_2}.{index}"


def get_multicast_octets(universe: int) -> tuple[int, int, int, int]:
    """Get multicast IP octets for direct socket API use."""
    if universe < MIN_UNIVERSE or universe > MAX_UNIVERSE:
        raise InvalidArgError(f"Universe {universe} out of range {MIN_UNIVERSE}-{MAX_UNIVERSE}")
    index = ((universe - 1) % 100) + 1
    return (MULTICAST_BASE_OCTET_0, MULTICAST_BASE_OCTET_1, MULTICAST_BASE_OCTET_2, index)


def increment_sequence(current_seq: int) -> int:
    """Increment sequence number with rollover to 1 (not 0)."""
    if current_seq >= 0xFFFFFFFF:
        return 1
    return current_seq + 1


def should_increment_session(seq_num: int) -> bool:
    """Check if session should increment due to sequence rollover."""
    return seq_num == 0xFFFFFFFF


def build_dmx_packet(
    universe: int,
    dmx_data: bytes,
    tuid: bytes,
    endpoint: int,
    mfg_code: int,
    session_id: int,
    seq_num: int,
    sender_key: bytes,
    message_id: int,
) -> bytes:
    """Build a complete SigNet DMX level packet.

    Orchestrates: CoAP header → URI-Path → SigNet options → HMAC → payload.
    """
    if universe < MIN_UNIVERSE or universe > MAX_UNIVERSE:
        raise InvalidArgError(f"Universe {universe} out of range {MIN_UNIVERSE}-{MAX_UNIVERSE}")
    if not (1 <= len(dmx_data) <= MAX_DMX_SLOTS):
        raise InvalidArgError(f"DMX slot count {len(dmx_data)} out of range 1-{MAX_DMX_SLOTS}")

    # Build SigNetOptions struct
    options = SigNetOptions(
        security_mode=SECURITY_MODE_HMAC_SHA256,
        sender_id=build_sender_id(tuid, endpoint),
        mfg_code=mfg_code,
        session_id=session_id,
        seq_num=seq_num,
    )

    # Build TLV payload
    payload = build_dmx_level_payload(dmx_data)

    # Build URI string for HMAC
    uri_string = build_uri_string(universe)

    # Assemble packet
    buf = bytearray()
    buf.extend(build_coap_header(message_id))
    buf.extend(build_uri_path_options(universe))
    buf.extend(build_signet_options_without_hmac(options, COAP_OPTION_URI_PATH))

    # Calculate and append HMAC option
    hmac_option, computed_hmac = calculate_and_encode_hmac(
        uri_string, options, payload, sender_key, SIGNET_OPTION_SEQ_NUM
    )
    buf.extend(hmac_option)

    # Payload marker + payload
    buf.append(COAP_PAYLOAD_MARKER)
    buf.extend(payload)

    if len(buf) > MAX_UDP_PAYLOAD:
        raise BufferFullError(f"Packet size {len(buf)} exceeds {MAX_UDP_PAYLOAD}")

    return bytes(buf)


def build_announce_packet(
    tuid: bytes,
    mfg_code: int,
    product_variant_id: int,
    firmware_version_id: int,
    firmware_version_string: str,
    protocol_version: int,
    role_capability_bits: int,
    change_count: int,
    session_id: int,
    seq_num: int,
    citizen_key: bytes,
    message_id: int,
) -> bytes:
    """Build a startup announce packet (/sig-net/v1/node/{tuid}/0) signed with Kc."""
    tuid_hex = tuid_to_hex(tuid)

    options = SigNetOptions(
        security_mode=SECURITY_MODE_HMAC_SHA256,
        sender_id=build_sender_id(tuid, 0),
        mfg_code=mfg_code,
        session_id=session_id,
        seq_num=seq_num,
    )

    payload = build_startup_announce_payload(
        tuid, mfg_code, product_variant_id,
        firmware_version_id, firmware_version_string,
        protocol_version, role_capability_bits, change_count,
    )

    uri_string = build_node_uri_string(tuid_hex, 0)

    buf = bytearray()
    buf.extend(build_coap_header(message_id))
    buf.extend(build_node_uri_path_options(tuid_hex, 0))
    buf.extend(build_signet_options_without_hmac(options, COAP_OPTION_URI_PATH))

    hmac_option, computed_hmac = calculate_and_encode_hmac(
        uri_string, options, payload, citizen_key, SIGNET_OPTION_SEQ_NUM
    )
    buf.extend(hmac_option)

    buf.append(COAP_PAYLOAD_MARKER)
    buf.extend(payload)

    if len(buf) > MAX_UDP_PAYLOAD:
        raise BufferFullError(f"Packet size {len(buf)} exceeds {MAX_UDP_PAYLOAD}")

    return bytes(buf)
