"""Tests for signet.send — ports C++ self-tests 14-16."""

from __future__ import annotations

import pytest

from signet.send import (
    build_dmx_packet,
    calculate_multicast_address,
    increment_sequence,
    should_increment_session,
)

from .conftest import TEST_K0, TEST_TUID


# ---- C++ Self-Test 14: Multicast Address Calculation ----

def test_multicast_address():
    addr = calculate_multicast_address(517)
    assert addr.startswith("239.254.")
    # ((517 - 1) % 100) + 1 = 17
    assert addr == "239.254.0.17"


def test_multicast_address_universe_1():
    assert calculate_multicast_address(1) == "239.254.0.1"


def test_multicast_address_universe_100():
    assert calculate_multicast_address(100) == "239.254.0.100"


def test_multicast_address_universe_101():
    assert calculate_multicast_address(101) == "239.254.0.1"


# ---- C++ Self-Test 15: Sequence Increment ----

def test_sequence_increment():
    assert increment_sequence(1) == 2


# ---- C++ Self-Test 16: Sequence Rollover ----

def test_sequence_rollover():
    assert increment_sequence(0xFFFFFFFF) == 1


# ---- Additional ----

def test_should_increment_session():
    assert should_increment_session(0xFFFFFFFF) is True
    assert should_increment_session(1) is False


def test_build_dmx_packet():
    from signet.crypto import derive_sender_key

    sender_key = derive_sender_key(TEST_K0)
    dmx_data = bytes([128] * 512)

    packet = build_dmx_packet(
        universe=1,
        dmx_data=dmx_data,
        tuid=TEST_TUID,
        endpoint=1,
        mfg_code=0x0000,
        session_id=1,
        seq_num=1,
        sender_key=sender_key,
        message_id=1,
    )

    assert isinstance(packet, bytes)
    assert len(packet) > 0
    assert len(packet) <= 1400
    # Starts with CoAP header: version=1, type=NON → byte0 = 0x50
    assert packet[0] == 0x50
