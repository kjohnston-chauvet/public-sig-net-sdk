"""Tests for signet.security — ports C++ self-test 13."""

from __future__ import annotations

from signet.security import build_sender_id


# ---- C++ Self-Test 13: Build Sender ID ----

def test_build_sender_id():
    tuid = bytes.fromhex("534C00000001")
    sender_id = build_sender_id(tuid, 0)

    assert len(sender_id) == 8
    # First 6 bytes are TUID
    assert sender_id[:6] == tuid
    # Last 2 bytes are endpoint 0 in network byte order
    assert sender_id[6:] == b"\x00\x00"


def test_build_sender_id_with_endpoint():
    tuid = bytes.fromhex("534C00000001")
    sender_id = build_sender_id(tuid, 1)

    assert sender_id[:6] == tuid
    assert sender_id[6:] == b"\x00\x01"


def test_build_sender_id_high_endpoint():
    tuid = bytes.fromhex("534C00000001")
    sender_id = build_sender_id(tuid, 0x0102)

    assert sender_id[6:] == b"\x01\x02"
