"""Sig-Net Protocol Framework - Security Layer.

SigNet custom CoAP options (2076-2236) encoding and HMAC-SHA256
signature calculation per Section 8.5 of the specification.
"""

from __future__ import annotations

import struct

from .coap import encode_coap_option
from .constants import (
    COAP_PAYLOAD_MARKER,
    DERIVED_KEY_LENGTH,
    HMAC_SHA256_LENGTH,
    SENDER_ID_LENGTH,
    SIGNET_OPTION_HMAC,
    SIGNET_OPTION_MFG_CODE,
    SIGNET_OPTION_SECURITY_MODE,
    SIGNET_OPTION_SENDER_ID,
    SIGNET_OPTION_SESSION_ID,
    SIGNET_OPTION_SEQ_NUM,
    TUID_LENGTH,
)
from .crypto import hmac_sha256
from .exceptions import InvalidArgError
from .types import SigNetOptions


def build_sender_id(tuid: bytes, endpoint: int) -> bytes:
    """Build 8-byte Sender-ID from TUID(6) + endpoint(2, network byte order)."""
    if len(tuid) != TUID_LENGTH:
        raise InvalidArgError(f"TUID must be {TUID_LENGTH} bytes")
    return tuid + struct.pack("!H", endpoint)


def build_signet_options_without_hmac(options: SigNetOptions, prev_option: int) -> bytes:
    """Encode the first 5 SigNet custom options (without HMAC) into bytes."""
    buf = bytearray()
    current = prev_option

    # Option 1: Security-Mode (2076) - 1 byte
    buf.extend(encode_coap_option(SIGNET_OPTION_SECURITY_MODE, current, bytes([options.security_mode])))
    current = SIGNET_OPTION_SECURITY_MODE

    # Option 2: Sender-ID (2108) - 8 bytes
    buf.extend(encode_coap_option(SIGNET_OPTION_SENDER_ID, current, options.sender_id))
    current = SIGNET_OPTION_SENDER_ID

    # Option 3: Mfg-Code (2140) - 2 bytes
    buf.extend(encode_coap_option(SIGNET_OPTION_MFG_CODE, current, struct.pack("!H", options.mfg_code)))
    current = SIGNET_OPTION_MFG_CODE

    # Option 4: Session-ID (2172) - 4 bytes
    buf.extend(encode_coap_option(SIGNET_OPTION_SESSION_ID, current, struct.pack("!I", options.session_id)))
    current = SIGNET_OPTION_SESSION_ID

    # Option 5: Seq-Num (2204) - 4 bytes
    buf.extend(encode_coap_option(SIGNET_OPTION_SEQ_NUM, current, struct.pack("!I", options.seq_num)))

    return bytes(buf)


def build_hmac_input(
    uri_string: str,
    options: SigNetOptions,
    payload: bytes,
) -> bytes:
    """Build the HMAC input buffer per Section 8.5.

    Concatenates: URI string + Security-Mode + Sender-ID + Mfg-Code +
    Session-ID + Seq-Num + Payload.
    """
    buf = bytearray()
    buf.extend(uri_string.encode("ascii"))
    buf.append(options.security_mode)
    buf.extend(options.sender_id)
    buf.extend(struct.pack("!H", options.mfg_code))
    buf.extend(struct.pack("!I", options.session_id))
    buf.extend(struct.pack("!I", options.seq_num))
    buf.extend(payload)
    return bytes(buf)


def calculate_hmac(
    uri_string: str,
    options: SigNetOptions,
    payload: bytes,
    signing_key: bytes,
) -> bytes:
    """Calculate HMAC-SHA256 for a packet."""
    hmac_input = build_hmac_input(uri_string, options, payload)
    return hmac_sha256(signing_key, hmac_input)


def calculate_and_encode_hmac(
    uri_string: str,
    options: SigNetOptions,
    payload: bytes,
    signing_key: bytes,
    prev_option: int,
) -> tuple[bytes, bytes]:
    """Calculate HMAC and encode as CoAP option 2236.

    Returns (encoded_option_bytes, computed_hmac).
    """
    computed_hmac = calculate_hmac(uri_string, options, payload, signing_key)
    option_bytes = encode_coap_option(SIGNET_OPTION_HMAC, prev_option, computed_hmac)
    return option_bytes, computed_hmac
