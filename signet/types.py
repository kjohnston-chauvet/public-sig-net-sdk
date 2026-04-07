"""Sig-Net Protocol Framework - Type Definitions.

Data structures including CoAP headers, TLV structures, and receiver state.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .constants import (
    COAP_VERSION,
    COAP_TYPE_NON,
    HMAC_SHA256_LENGTH,
    SENDER_ID_LENGTH,
)


@dataclass
class CoAPHeader:
    """CoAP header (RFC 7252 Section 3), 4 bytes packed."""

    version: int = COAP_VERSION
    type_: int = COAP_TYPE_NON
    token_length: int = 0
    code: int = 0
    message_id: int = 0

    def pack(self) -> bytes:
        byte0 = ((self.version & 0x03) << 6) | ((self.type_ & 0x03) << 4) | (self.token_length & 0x0F)
        return struct.pack("!BBH", byte0, self.code, self.message_id)

    @classmethod
    def unpack(cls, data: bytes) -> CoAPHeader:
        if len(data) < 4:
            raise ValueError("CoAP header requires at least 4 bytes")
        byte0, code, message_id = struct.unpack_from("!BBH", data)
        return cls(
            version=(byte0 >> 6) & 0x03,
            type_=(byte0 >> 4) & 0x03,
            token_length=byte0 & 0x0F,
            code=code,
            message_id=message_id,
        )


@dataclass
class TLVBlock:
    """Type-Length-Value block. Length is derived from len(value)."""

    type_id: int = 0
    value: bytes = b""

    @property
    def length(self) -> int:
        return len(self.value)


@dataclass
class SigNetOptions:
    """SigNet custom CoAP option values (options 2076-2236)."""

    security_mode: int = 0
    sender_id: bytes = field(default_factory=lambda: b"\x00" * SENDER_ID_LENGTH)
    mfg_code: int = 0
    session_id: int = 0
    seq_num: int = 0
    hmac: bytes = field(default_factory=lambda: b"\x00" * HMAC_SHA256_LENGTH)

    def __post_init__(self) -> None:
        if len(self.sender_id) != SENDER_ID_LENGTH:
            raise ValueError(f"sender_id must be {SENDER_ID_LENGTH} bytes")
        if len(self.hmac) != HMAC_SHA256_LENGTH:
            raise ValueError(f"hmac must be {HMAC_SHA256_LENGTH} bytes")


@dataclass
class ReceiverSenderState:
    """Tracks session/sequence state per sender for anti-replay protection."""

    sender_id: bytes = field(default_factory=lambda: b"\x00" * SENDER_ID_LENGTH)
    session_id: int = 0
    seq_num: int = 0
    last_packet_time_ms: int = 0
    total_packets_received: int = 0
    total_packets_accepted: int = 0


@dataclass
class ReceiverStatistics:
    """Global receiver statistics for diagnostics."""

    total_packets: int = 0
    accepted_packets: int = 0
    coap_version_errors: int = 0
    coap_type_errors: int = 0
    coap_code_errors: int = 0
    uri_mismatches: int = 0
    missing_options: int = 0
    hmac_failures: int = 0
    replay_detected: int = 0
    parse_errors: int = 0
    last_packet_time_ms: int = 0

    def reset(self) -> None:
        for f in self.__dataclass_fields__:
            setattr(self, f, 0)


@dataclass
class ReceivedPacketInfo:
    """Information about a received packet for logging and diagnostics."""

    message_id: int = 0
    sender_tuid: bytes = field(default_factory=lambda: b"\x00" * 6)
    endpoint: int = 0
    mfg_code: int = 0
    session_id: int = 0
    seq_num: int = 0
    dmx_slot_count: int = 0
    hmac_valid: bool = False
    session_fresh: bool = False
    rejection_reason: str | None = None
    timestamp_ms: int = 0


@dataclass
class PassphraseChecks:
    """Result of passphrase analysis - all individual check results."""

    length: int = 0
    length_ok: bool = False
    class_count: int = 0
    has_upper: bool = False
    has_lower: bool = False
    has_digit: bool = False
    has_symbol: bool = False
    classes_ok: bool = False
    no_identical: bool = False
    no_sequential: bool = False
