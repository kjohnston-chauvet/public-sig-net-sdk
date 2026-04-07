"""Tests for signet.crypto — ports C++ self-tests 1-7 plus additional vectors."""

from __future__ import annotations

import pytest

from signet.crypto import (
    analyse_passphrase,
    derive_citizen_key,
    derive_k0_from_passphrase,
    derive_manager_global_key,
    derive_manager_local_key,
    derive_sender_key,
    generate_random_passphrase,
    generate_random_k0,
    hmac_sha256,
    tuid_from_hex,
    tuid_to_hex,
    validate_passphrase,
)
from signet.exceptions import (
    PassphraseConsecutiveIdenticalError,
    PassphraseConsecutiveSequentialError,
    PassphraseInsufficientClassesError,
    PassphraseTooShortError,
)
from signet.types import PassphraseChecks

from .conftest import TEST_K0, TEST_K0_HEX, TEST_PASSPHRASE, TEST_TUID, TEST_TUID_HEX


# ---- C++ Self-Test 1: K0 Derivation (32-byte input produces valid sender key) ----

def test_k0_derivation():
    k0 = bytes([0xAA] * 32)
    sender_key = derive_sender_key(k0)
    assert len(sender_key) == 32


# ---- C++ Self-Test 2: HMAC-SHA256 RFC 4231 Test Case 1 ----

def test_hmac_rfc4231_vector1():
    key = bytes([0x0B] * 20)
    data = b"Hi There"
    expected = bytes.fromhex(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    result = hmac_sha256(key, data)
    assert result == expected


# ---- C++ Self-Test 3: Passphrase Validation (valid complex) ----

def test_passphrase_valid():
    checks = validate_passphrase("Secure@Pass123!")
    assert checks.length_ok
    assert checks.has_upper
    assert checks.has_lower
    assert checks.has_digit
    assert checks.has_symbol
    assert checks.classes_ok
    assert checks.no_identical
    assert checks.no_sequential


# ---- C++ Self-Test 4: Passphrase Validation (too short) ----

def test_passphrase_too_short():
    checks = analyse_passphrase("Pass1!")
    assert not checks.length_ok

    with pytest.raises(PassphraseTooShortError):
        validate_passphrase("Pass1!")


# ---- C++ Self-Test 5: Passphrase Validation (3+ identical chars) ----

def test_passphrase_identical_run():
    checks = analyse_passphrase("Passyyy@123")
    assert not checks.no_identical

    with pytest.raises(PassphraseConsecutiveIdenticalError):
        validate_passphrase("Passyyy@123")


# ---- C++ Self-Test 6: Passphrase Validation (4+ sequential chars) ----

def test_passphrase_sequential_run():
    checks = analyse_passphrase("Pass1234abcd!@")
    assert not checks.no_sequential

    with pytest.raises(PassphraseConsecutiveSequentialError):
        validate_passphrase("Pass1234abcd!@")


# ---- C++ Self-Test 7: Random Passphrase Generation ----

def test_random_passphrase_generation():
    p1 = generate_random_passphrase()
    p2 = generate_random_passphrase()

    assert p1
    assert p2
    assert p1 != p2

    # Both should be valid
    validate_passphrase(p1)
    validate_passphrase(p2)


# ---- Additional: TUID conversion ----

def test_tuid_to_hex():
    assert tuid_to_hex(TEST_TUID) == TEST_TUID_HEX


def test_tuid_from_hex():
    assert tuid_from_hex(TEST_TUID_HEX) == TEST_TUID


# ---- Additional: K0 from passphrase matches known vector ----

def test_k0_from_passphrase():
    k0 = derive_k0_from_passphrase(TEST_PASSPHRASE)
    assert k0 == TEST_K0


# ---- Additional: Key derivation produces 32-byte keys ----

def test_key_derivation_lengths():
    ks = derive_sender_key(TEST_K0)
    kc = derive_citizen_key(TEST_K0)
    km = derive_manager_global_key(TEST_K0)
    km_local = derive_manager_local_key(TEST_K0, TEST_TUID)

    assert len(ks) == 32
    assert len(kc) == 32
    assert len(km) == 32
    assert len(km_local) == 32

    # All should be different
    assert len({ks, kc, km, km_local}) == 4


# ---- Additional: Random K0 ----

def test_random_k0():
    k1 = generate_random_k0()
    k2 = generate_random_k0()
    assert len(k1) == 32
    assert len(k2) == 32
    assert k1 != k2


# ---- Additional: Passphrase insufficient classes ----

def test_passphrase_insufficient_classes():
    with pytest.raises(PassphraseInsufficientClassesError):
        validate_passphrase("axbxcxdxfx")  # only lowercase, no sequential runs
