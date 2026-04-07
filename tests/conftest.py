"""Shared test fixtures for Sig-Net SDK tests."""

from __future__ import annotations

import pytest

# Known test vectors from sig-net-constants.hpp / README
TEST_K0_HEX = "52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173"
TEST_K0 = bytes.fromhex(TEST_K0_HEX)
TEST_PASSPHRASE = "Ge2p$E$4*A"
TEST_TUID_HEX = "534C00000001"
TEST_TUID = bytes.fromhex(TEST_TUID_HEX)


@pytest.fixture
def test_k0() -> bytes:
    return TEST_K0


@pytest.fixture
def test_tuid() -> bytes:
    return TEST_TUID


@pytest.fixture
def test_sender_key() -> bytes:
    from signet.crypto import derive_sender_key
    return derive_sender_key(TEST_K0)


@pytest.fixture
def test_citizen_key() -> bytes:
    from signet.crypto import derive_citizen_key
    return derive_citizen_key(TEST_K0)
