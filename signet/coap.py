"""Sig-Net Protocol Framework - CoAP Packet Building.

CoAP header/option construction per RFC 7252, with extended delta encoding.
"""

from __future__ import annotations

import struct

from .constants import (
    COAP_CODE_POST,
    COAP_OPTION_EXT16_BASE,
    COAP_OPTION_EXT16_NIBBLE,
    COAP_OPTION_EXT8_BASE,
    COAP_OPTION_EXT8_NIBBLE,
    COAP_OPTION_INLINE_MAX,
    COAP_OPTION_URI_PATH,
    COAP_TYPE_NON,
    COAP_VERSION,
    MAX_UNIVERSE,
    MIN_UNIVERSE,
    SIGNET_URI_LEVEL,
    SIGNET_URI_PREFIX,
    SIGNET_URI_VERSION,
)
from .exceptions import EncodeError, InvalidArgError


def build_coap_header(message_id: int) -> bytes:
    """Build a 4-byte CoAP header for SigNet packets.

    Version=1, Type=NON, TKL=0, Code=POST.
    """
    byte0 = ((COAP_VERSION & 0x03) << 6) | ((COAP_TYPE_NON & 0x03) << 4)
    return struct.pack("!BBH", byte0, COAP_CODE_POST, message_id)


def encode_coap_option(
    option_number: int,
    prev_option: int,
    value: bytes,
) -> bytes:
    """Encode a single CoAP option with extended delta/length encoding (RFC 7252 Section 3.1)."""
    if option_number < prev_option:
        raise EncodeError("Options must be in ascending order")

    delta = option_number - prev_option
    length = len(value)

    # Encode delta
    delta_nibble, delta_ext = _encode_nibble(delta)
    # Encode length
    length_nibble, length_ext = _encode_nibble(length)

    buf = bytearray()
    buf.append((delta_nibble << 4) | length_nibble)
    buf.extend(delta_ext)
    buf.extend(length_ext)
    buf.extend(value)

    return bytes(buf)


def _encode_nibble(value: int) -> tuple[int, bytes]:
    """Encode a value into a CoAP option nibble + optional extended bytes."""
    if value <= COAP_OPTION_INLINE_MAX:
        return value, b""
    elif value < COAP_OPTION_EXT16_BASE:
        return COAP_OPTION_EXT8_NIBBLE, bytes([value - COAP_OPTION_EXT8_BASE])
    else:
        return COAP_OPTION_EXT16_NIBBLE, struct.pack("!H", value - COAP_OPTION_EXT16_BASE)


def build_uri_path_options(universe: int) -> bytes:
    """Build URI-Path options for /sig-net/v1/level/{universe}.

    Returns the concatenated encoded options (4 Uri-Path options).
    """
    if universe < MIN_UNIVERSE or universe > MAX_UNIVERSE:
        raise InvalidArgError(f"Universe {universe} out of range {MIN_UNIVERSE}-{MAX_UNIVERSE}")

    buf = bytearray()
    prev = 0

    for segment in [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_LEVEL, str(universe)]:
        buf.extend(encode_coap_option(COAP_OPTION_URI_PATH, prev, segment.encode("ascii")))
        prev = COAP_OPTION_URI_PATH

    return bytes(buf)


def build_uri_string(universe: int) -> str:
    """Build URI string for HMAC calculation: /sig-net/v1/level/{universe}."""
    if universe < MIN_UNIVERSE or universe > MAX_UNIVERSE:
        raise InvalidArgError(f"Universe {universe} out of range {MIN_UNIVERSE}-{MAX_UNIVERSE}")
    return f"/{SIGNET_URI_PREFIX}/{SIGNET_URI_VERSION}/{SIGNET_URI_LEVEL}/{universe}"


def build_node_uri_string(tuid_hex: str, endpoint: int) -> str:
    """Build node URI string: /sig-net/v1/node/{tuid}/{endpoint}."""
    from .constants import SIGNET_URI_NODE
    return f"/{SIGNET_URI_PREFIX}/{SIGNET_URI_VERSION}/{SIGNET_URI_NODE}/{tuid_hex}/{endpoint}"


def build_node_uri_path_options(tuid_hex: str, endpoint: int) -> bytes:
    """Build URI-Path options for /sig-net/v1/node/{tuid}/{endpoint}."""
    from .constants import SIGNET_URI_NODE

    buf = bytearray()
    prev = 0
    segments = [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_NODE, tuid_hex, str(endpoint)]

    for segment in segments:
        buf.extend(encode_coap_option(COAP_OPTION_URI_PATH, prev, segment.encode("ascii")))
        prev = COAP_OPTION_URI_PATH

    return bytes(buf)
