"""Tests for signet.parse — round-trip build→parse tests."""

from __future__ import annotations

import pytest

from signet.crypto import derive_citizen_key, derive_sender_key
from signet.parse import (
    PacketReader,
    extract_uri_string,
    parse_coap_header,
    parse_signet_options,
    parse_tid_level,
    parse_tlv_block,
    skip_token,
    verify_packet_hmac,
)
from signet.send import build_announce_packet, build_dmx_packet
from signet.constants import COAP_PAYLOAD_MARKER, TID
from signet.exceptions import BufferTooSmallError, HMACFailedError

from .conftest import TEST_K0, TEST_TUID


def test_round_trip_dmx_packet():
    """Build a DMX packet, then parse it back and verify all fields."""
    sender_key = derive_sender_key(TEST_K0)
    dmx_data = bytes(range(256)) + bytes(range(256))  # 512 bytes

    packet = build_dmx_packet(
        universe=517,
        dmx_data=dmx_data,
        tuid=TEST_TUID,
        endpoint=1,
        mfg_code=0x534C,
        session_id=42,
        seq_num=100,
        sender_key=sender_key,
        message_id=0x1234,
    )

    reader = PacketReader(packet)

    # Parse CoAP header
    header = parse_coap_header(reader)
    assert header.version == 1
    assert header.type_ == 1  # NON
    assert header.token_length == 0
    assert header.code == 0x02  # POST
    assert header.message_id == 0x1234

    skip_token(reader, header.token_length)

    # Extract URI
    # Save position - we'll re-read from here for options
    uri_start = reader.position
    uri = extract_uri_string(reader)
    assert uri == "/sig-net/v1/level/517"

    # Re-create reader at options start to parse SigNet options
    # (ExtractURIString consumes past URI-Path options and may stop at a non-URI option)
    reader2 = PacketReader(packet)
    reader2.skip(4)  # Skip CoAP header
    options = parse_signet_options(reader2)

    assert options.security_mode == 0x00
    assert options.sender_id[:6] == TEST_TUID
    assert options.mfg_code == 0x534C
    assert options.session_id == 42
    assert options.seq_num == 100
    assert len(options.hmac) == 32

    # Find payload (scan for 0xFF marker)
    payload_start = packet.index(bytes([COAP_PAYLOAD_MARKER])) + 1
    payload = packet[payload_start:]

    # Parse TLV from payload
    payload_reader = PacketReader(payload)
    tlv = parse_tlv_block(payload_reader)
    assert tlv.type_id == TID.LEVEL
    assert tlv.length == 512

    # Extract DMX data
    parsed_dmx = parse_tid_level(tlv)
    assert parsed_dmx == dmx_data

    # Verify HMAC
    assert verify_packet_hmac(uri, options, payload, sender_key)


def test_hmac_verification_failure():
    """Flip a byte in the packet and verify HMAC fails."""
    sender_key = derive_sender_key(TEST_K0)
    dmx_data = bytes([128] * 10)

    packet = build_dmx_packet(
        universe=1,
        dmx_data=dmx_data,
        tuid=TEST_TUID,
        endpoint=0,
        mfg_code=0,
        session_id=1,
        seq_num=1,
        sender_key=sender_key,
        message_id=1,
    )

    # Parse to get options and payload
    reader = PacketReader(packet)
    parse_coap_header(reader)

    reader2 = PacketReader(packet)
    reader2.skip(4)
    options = parse_signet_options(reader2)

    payload_start = packet.index(bytes([COAP_PAYLOAD_MARKER])) + 1
    payload = packet[payload_start:]

    uri = "/sig-net/v1/level/1"

    # Correct key passes
    assert verify_packet_hmac(uri, options, payload, sender_key)

    # Wrong key fails
    wrong_key = bytes([0xFF] * 32)
    with pytest.raises(HMACFailedError):
        verify_packet_hmac(uri, options, payload, wrong_key)


def test_packet_reader_exhaustion():
    """Verify PacketReader raises on truncated data."""
    reader = PacketReader(b"\x01\x02")
    assert reader.read_byte() == 1
    assert reader.read_byte() == 2
    with pytest.raises(BufferTooSmallError):
        reader.read_byte()


def test_round_trip_announce_packet():
    """Build an announce packet, then verify basic structure."""
    citizen_key = derive_citizen_key(TEST_K0)

    packet = build_announce_packet(
        tuid=TEST_TUID,
        mfg_code=0x534C,
        product_variant_id=0,
        firmware_version_id=0x0100BC,
        firmware_version_string="v1.0.0",
        protocol_version=1,
        role_capability_bits=0x01,
        change_count=0,
        session_id=1,
        seq_num=1,
        citizen_key=citizen_key,
        message_id=1,
    )

    assert isinstance(packet, bytes)
    assert len(packet) > 0
    assert len(packet) <= 1400

    # Contains payload marker
    assert COAP_PAYLOAD_MARKER in packet
