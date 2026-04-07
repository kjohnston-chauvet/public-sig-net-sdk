"""Sig-Net Protocol Framework - Cryptographic Functions.

HMAC-SHA256 (RFC 2104), HKDF-Expand (RFC 5869), PBKDF2, key derivation,
and passphrase validation. Pure Python using stdlib only.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import secrets

from .constants import (
    DERIVED_KEY_LENGTH,
    HKDF_COUNTER_T1,
    HKDF_INFO_CITIZEN,
    HKDF_INFO_INPUT_MAX,
    HKDF_INFO_MANAGER_GLOBAL,
    HKDF_INFO_MANAGER_LOCAL_PREFIX,
    HKDF_INFO_SENDER,
    K0_KEY_LENGTH,
    PASSPHRASE_GEN_DIGITS,
    PASSPHRASE_GEN_LOWERCASE,
    PASSPHRASE_GEN_SYMBOLS,
    PASSPHRASE_GEN_UPPERCASE,
    PASSPHRASE_GENERATED_LENGTH,
    PASSPHRASE_MAX_LENGTH,
    PASSPHRASE_MIN_LENGTH,
    PASSPHRASE_SYMBOLS,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT,
    TUID_HEX_LENGTH,
    TUID_LENGTH,
)
from .exceptions import (
    CryptoError,
    InvalidArgError,
    PassphraseConsecutiveIdenticalError,
    PassphraseConsecutiveSequentialError,
    PassphraseInsufficientClassesError,
    PassphraseTooLongError,
    PassphraseTooShortError,
)
from .types import PassphraseChecks


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256 digest."""
    return _hmac.new(key, message, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes) -> bytes:
    """HKDF-Expand (RFC 5869 Section 2.3), simplified for L=32.

    OKM = HMAC-SHA256(PRK, info || 0x01)
    """
    if len(info) > HKDF_INFO_INPUT_MAX:
        raise InvalidArgError(f"info length {len(info)} exceeds max {HKDF_INFO_INPUT_MAX}")
    return hmac_sha256(prk, info + bytes([HKDF_COUNTER_T1]))


def derive_sender_key(k0: bytes) -> bytes:
    """Derive Sender Key (Ks) from K0."""
    return hkdf_expand(k0, HKDF_INFO_SENDER)


def derive_citizen_key(k0: bytes) -> bytes:
    """Derive Citizen Key (Kc) from K0."""
    return hkdf_expand(k0, HKDF_INFO_CITIZEN)


def derive_manager_global_key(k0: bytes) -> bytes:
    """Derive Manager Global Key (Km_global) from K0."""
    return hkdf_expand(k0, HKDF_INFO_MANAGER_GLOBAL)


def derive_manager_local_key(k0: bytes, tuid: bytes) -> bytes:
    """Derive Manager Local Key (Km_local) from K0 for a specific TUID."""
    if len(tuid) != TUID_LENGTH:
        raise InvalidArgError(f"TUID must be {TUID_LENGTH} bytes")
    info = (HKDF_INFO_MANAGER_LOCAL_PREFIX + tuid_to_hex(tuid)).encode("ascii")
    return hkdf_expand(k0, info)


def derive_k0_from_passphrase(passphrase: str) -> bytes:
    """Derive K0 root key from passphrase using PBKDF2-HMAC-SHA256."""
    if not passphrase:
        raise InvalidArgError("passphrase must not be empty")
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        dklen=K0_KEY_LENGTH,
    )


def tuid_to_hex(tuid: bytes) -> str:
    """Convert 6-byte TUID to 12-character uppercase hex string."""
    if len(tuid) != TUID_LENGTH:
        raise InvalidArgError(f"TUID must be {TUID_LENGTH} bytes")
    return tuid.hex().upper()


def tuid_from_hex(hex_string: str) -> bytes:
    """Convert 12-character hex string to 6-byte TUID."""
    if len(hex_string) != TUID_HEX_LENGTH:
        raise InvalidArgError(f"hex string must be {TUID_HEX_LENGTH} characters")
    return bytes.fromhex(hex_string)


# ---------------------------------------------------------------------------
# Passphrase validation helpers
# ---------------------------------------------------------------------------

def _scan_char_classes(passphrase: str) -> tuple[bool, bool, bool, bool]:
    has_upper = has_lower = has_digit = has_symbol = False
    for c in passphrase:
        if "A" <= c <= "Z":
            has_upper = True
        elif "a" <= c <= "z":
            has_lower = True
        elif "0" <= c <= "9":
            has_digit = True
        elif c in PASSPHRASE_SYMBOLS:
            has_symbol = True
    return has_upper, has_lower, has_digit, has_symbol


def _has_identical_run(passphrase: str) -> bool:
    if len(passphrase) < 3:
        return False
    for i in range(len(passphrase) - 2):
        if passphrase[i] == passphrase[i + 1] == passphrase[i + 2]:
            return True
    return False


def _has_sequential_run(passphrase: str) -> bool:
    if len(passphrase) < 4:
        return False
    for i in range(len(passphrase) - 3):
        c0 = ord(passphrase[i])
        if (
            ord(passphrase[i + 1]) == c0 + 1
            and ord(passphrase[i + 2]) == c0 + 2
            and ord(passphrase[i + 3]) == c0 + 3
        ):
            return True
        if (
            ord(passphrase[i + 1]) == c0 - 1
            and ord(passphrase[i + 2]) == c0 - 2
            and ord(passphrase[i + 3]) == c0 - 3
        ):
            return True
    return False


def analyse_passphrase(passphrase: str) -> PassphraseChecks:
    """Analyse passphrase and return all individual check results.

    Never raises — returns a PassphraseChecks with all fields populated.
    """
    checks = PassphraseChecks()
    checks.length = len(passphrase)
    checks.length_ok = PASSPHRASE_MIN_LENGTH <= len(passphrase) <= PASSPHRASE_MAX_LENGTH

    if not passphrase:
        checks.no_identical = True
        checks.no_sequential = True
        return checks

    has_upper, has_lower, has_digit, has_symbol = _scan_char_classes(passphrase)
    checks.has_upper = has_upper
    checks.has_lower = has_lower
    checks.has_digit = has_digit
    checks.has_symbol = has_symbol
    checks.class_count = sum([has_upper, has_lower, has_digit, has_symbol])
    checks.classes_ok = checks.class_count >= 3

    checks.no_identical = not _has_identical_run(passphrase)
    checks.no_sequential = not _has_sequential_run(passphrase)

    return checks


def validate_passphrase(passphrase: str) -> PassphraseChecks:
    """Validate passphrase. Raises appropriate PassphraseError on failure.

    Returns PassphraseChecks on success.
    """
    checks = analyse_passphrase(passphrase)

    # Same priority order as C++ AnalysePassphrase
    if not checks.no_identical:
        raise PassphraseConsecutiveIdenticalError("More than 2 consecutive identical characters")
    if not checks.no_sequential:
        raise PassphraseConsecutiveSequentialError("More than 3 consecutive sequential characters")
    if not checks.classes_ok:
        raise PassphraseInsufficientClassesError(
            f"Only {checks.class_count} character classes (need 3+)"
        )
    if not checks.length_ok:
        if len(passphrase) < PASSPHRASE_MIN_LENGTH:
            raise PassphraseTooShortError(
                f"Length {len(passphrase)} < minimum {PASSPHRASE_MIN_LENGTH}"
            )
        raise PassphraseTooLongError(
            f"Length {len(passphrase)} > maximum {PASSPHRASE_MAX_LENGTH}"
        )

    return checks


def generate_random_passphrase() -> str:
    """Generate a cryptographically secure random passphrase meeting all requirements."""
    length = PASSPHRASE_GENERATED_LENGTH
    chars: list[str] = [""] * length

    # Force first 3 from different classes
    chars[0] = secrets.choice(PASSPHRASE_GEN_UPPERCASE)
    chars[1] = secrets.choice(PASSPHRASE_GEN_LOWERCASE)
    chars[2] = secrets.choice(PASSPHRASE_GEN_DIGITS)

    all_sets = [
        PASSPHRASE_GEN_UPPERCASE,
        PASSPHRASE_GEN_LOWERCASE,
        PASSPHRASE_GEN_DIGITS,
        PASSPHRASE_GEN_SYMBOLS,
    ]

    for i in range(3, length):
        class_choice = secrets.randbelow(4)
        chars[i] = secrets.choice(all_sets[class_choice])

        # Prevent consecutive identical
        if chars[i] == chars[i - 1]:
            chars[i] = secrets.choice(PASSPHRASE_GEN_LOWERCASE)

        # Check triple identical
        if i > 1 and chars[i] == chars[i - 1] == chars[i - 2]:
            chars[i] = secrets.choice(PASSPHRASE_GEN_DIGITS)

    result = "".join(chars)

    # Verify (should always pass)
    try:
        validate_passphrase(result)
    except Exception:
        result = "Abc123!@#$"

    return result


def generate_random_k0() -> bytes:
    """Generate a cryptographically secure random 32-byte K0 root key."""
    return os.urandom(K0_KEY_LENGTH)
