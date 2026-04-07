"""Sig-Net Protocol Framework - Packet Parsing.

Receiver-side parsing: CoAP header/option parsing, custom option extraction,
TLV parsing, HMAC verification. Complements send.py.
"""

from __future__ import annotations

import hmac as _hmac
import struct

from .constants import (
    COAP_OPTION_URI_PATH,
    HMAC_SHA256_LENGTH,
    MAX_DMX_SLOTS,
    SENDER_ID_LENGTH,
    SIGNET_OPTION_HMAC,
    SIGNET_OPTION_MFG_CODE,
    SIGNET_OPTION_SECURITY_MODE,
    SIGNET_OPTION_SENDER_ID,
    SIGNET_OPTION_SESSION_ID,
    SIGNET_OPTION_SEQ_NUM,
    TID,
)
from .exceptions import (
    BufferTooSmallError,
    HMACFailedError,
    InvalidOptionError,
    InvalidPacketError,
)
from .security import build_hmac_input, calculate_hmac
from .types import CoAPHeader, SigNetOptions, TLVBlock


class PacketReader:
    """Cursor-based reader over a bytes buffer."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def can_read(self, count: int) -> bool:
        return self._pos + count <= len(self._data)

    def read_byte(self) -> int:
        if not self.can_read(1):
            raise BufferTooSmallError("Cannot read byte: buffer exhausted")
        val = self._data[self._pos]
        self._pos += 1
        return val

    def read_uint16(self) -> int:
        if not self.can_read(2):
            raise BufferTooSmallError("Cannot read uint16: buffer exhausted")
        val = (self._data[self._pos] << 8) | self._data[self._pos + 1]
        self._pos += 2
        return val

    def read_uint32(self) -> int:
        if not self.can_read(4):
            raise BufferTooSmallError("Cannot read uint32: buffer exhausted")
        val = (
            (self._data[self._pos] << 24)
            | (self._data[self._pos + 1] << 16)
            | (self._data[self._pos + 2] << 8)
            | self._data[self._pos + 3]
        )
        self._pos += 4
        return val

    def read_bytes(self, count: int) -> bytes:
        if not self.can_read(count):
            raise BufferTooSmallError(f"Cannot read {count} bytes: buffer exhausted")
        val = self._data[self._pos : self._pos + count]
        self._pos += count
        return val

    def skip(self, count: int) -> None:
        if not self.can_read(count):
            raise BufferTooSmallError(f"Cannot skip {count} bytes: buffer exhausted")
        self._pos += count

    def peek_byte(self) -> int:
        if self._pos >= len(self._data):
            raise BufferTooSmallError("Cannot peek: buffer exhausted")
        return self._data[self._pos]

    @property
    def current_ptr(self) -> bytes:
        return self._data[self._pos :]


def parse_coap_header(reader: PacketReader) -> CoAPHeader:
    """Parse a 4-byte CoAP header."""
    byte0 = reader.read_byte()
    code = reader.read_byte()
    message_id = reader.read_uint16()
    return CoAPHeader(
        version=(byte0 >> 6) & 0x03,
        type_=(byte0 >> 4) & 0x03,
        token_length=byte0 & 0x0F,
        code=code,
        message_id=message_id,
    )


def skip_token(reader: PacketReader, token_length: int) -> None:
    """Skip over CoAP token bytes."""
    if token_length > 0:
        reader.skip(token_length)


def parse_coap_option(reader: PacketReader, prev_option: int) -> tuple[int, bytes]:
    """Parse a single CoAP option.

    Returns (option_number, option_value).
    Raises InvalidPacketError if payload marker (0xFF) is encountered.
    """
    header_byte = reader.peek_byte()
    if header_byte == 0xFF:
        raise InvalidPacketError("Payload marker encountered")

    reader.read_byte()  # consume the byte we peeked

    delta = (header_byte >> 4) & 0x0F
    length = header_byte & 0x0F

    # Extended delta
    if delta == 13:
        delta = 13 + reader.read_byte()
    elif delta == 14:
        delta = 269 + reader.read_uint16()
    elif delta == 15:
        raise InvalidPacketError("Reserved delta value 15")

    # Extended length
    if length == 13:
        length = 13 + reader.read_byte()
    elif length == 14:
        length = 269 + reader.read_uint16()
    elif length == 15:
        raise InvalidPacketError("Reserved length value 15")

    option_num = prev_option + delta
    value = reader.read_bytes(length) if length > 0 else b""

    return option_num, value


def extract_uri_string(reader: PacketReader) -> str:
    """Rebuild URI string from Uri-Path options.

    Returns the full URI (e.g., "/sig-net/v1/level/517").
    Stops when a non-Uri-Path option or payload marker is encountered.
    """
    segments: list[str] = []
    current_option = 0

    while reader.remaining > 0:
        try:
            option_num, value = parse_coap_option(reader, current_option)
        except InvalidPacketError:
            # Hit payload marker
            break

        if option_num == COAP_OPTION_URI_PATH:
            segments.append(value.decode("ascii"))
            current_option = option_num
        elif option_num > COAP_OPTION_URI_PATH:
            # Past Uri-Path options — stop
            break
        else:
            current_option = option_num

    return "/" + "/".join(segments) if segments else "/"


def parse_signet_options(reader: PacketReader) -> SigNetOptions:
    """Parse all 6 SigNet custom options (2076-2236).

    Reader should be positioned after CoAP header + token.
    This parses through all options (including Uri-Path) to find SigNet options.
    """
    options = SigNetOptions()
    current_option = 0
    found = {
        "security_mode": False,
        "sender_id": False,
        "mfg_code": False,
        "session_id": False,
        "seq_num": False,
        "hmac": False,
    }

    while reader.remaining > 0:
        try:
            option_num, value = parse_coap_option(reader, current_option)
        except InvalidPacketError:
            # Payload marker
            break

        if option_num == SIGNET_OPTION_SECURITY_MODE:
            if len(value) != 1:
                raise InvalidOptionError("Security-Mode must be 1 byte")
            options.security_mode = value[0]
            found["security_mode"] = True

        elif option_num == SIGNET_OPTION_SENDER_ID:
            if len(value) != SENDER_ID_LENGTH:
                raise InvalidOptionError(f"Sender-ID must be {SENDER_ID_LENGTH} bytes")
            options = SigNetOptions(
                security_mode=options.security_mode,
                sender_id=value,
                mfg_code=options.mfg_code,
                session_id=options.session_id,
                seq_num=options.seq_num,
                hmac=options.hmac,
            )
            found["sender_id"] = True

        elif option_num == SIGNET_OPTION_MFG_CODE:
            if len(value) != 2:
                raise InvalidOptionError("Mfg-Code must be 2 bytes")
            options.mfg_code = (value[0] << 8) | value[1]
            found["mfg_code"] = True

        elif option_num == SIGNET_OPTION_SESSION_ID:
            if len(value) != 4:
                raise InvalidOptionError("Session-ID must be 4 bytes")
            options.session_id = struct.unpack("!I", value)[0]
            found["session_id"] = True

        elif option_num == SIGNET_OPTION_SEQ_NUM:
            if len(value) != 4:
                raise InvalidOptionError("Seq-Num must be 4 bytes")
            options.seq_num = struct.unpack("!I", value)[0]
            found["seq_num"] = True

        elif option_num == SIGNET_OPTION_HMAC:
            if len(value) != HMAC_SHA256_LENGTH:
                raise InvalidOptionError(f"HMAC must be {HMAC_SHA256_LENGTH} bytes")
            options = SigNetOptions(
                security_mode=options.security_mode,
                sender_id=options.sender_id,
                mfg_code=options.mfg_code,
                session_id=options.session_id,
                seq_num=options.seq_num,
                hmac=value,
            )
            found["hmac"] = True

        current_option = option_num

    if not found["security_mode"]:
        raise InvalidOptionError("Missing Security-Mode option")

    # For normal packets (not beacons), all options required
    if options.security_mode != 0xFF:
        missing = [k for k, v in found.items() if not v]
        if missing:
            raise InvalidOptionError(f"Missing required options: {', '.join(missing)}")

    return options


def parse_tlv_block(reader: PacketReader) -> TLVBlock:
    """Parse a single TLV block from the payload."""
    type_id = reader.read_uint16()
    length = reader.read_uint16()
    value = reader.read_bytes(length) if length > 0 else b""
    return TLVBlock(type_id=type_id, value=value)


def parse_tid_level(tlv: TLVBlock) -> bytes:
    """Extract DMX level data from a TID_LEVEL TLV block."""
    if tlv.type_id != TID.LEVEL:
        raise InvalidPacketError(f"Expected TID_LEVEL (0x{TID.LEVEL:04X}), got 0x{tlv.type_id:04X}")
    if not (1 <= tlv.length <= MAX_DMX_SLOTS):
        raise InvalidPacketError(f"TID_LEVEL length {tlv.length} out of range 1-{MAX_DMX_SLOTS}")
    return tlv.value


def verify_packet_hmac(
    uri_string: str,
    options: SigNetOptions,
    payload: bytes,
    role_key: bytes,
) -> bool:
    """Verify packet HMAC using constant-time comparison.

    Returns True if HMAC matches, raises HMACFailedError otherwise.
    """
    computed = calculate_hmac(uri_string, options, payload, role_key)
    if not _hmac.compare_digest(computed, options.hmac):
        raise HMACFailedError("HMAC verification failed")
    return True
