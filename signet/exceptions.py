"""Sig-Net SDK exception hierarchy.

Replaces C++ integer error codes with typed exceptions.
"""

from __future__ import annotations


class SigNetError(Exception):
    """Base exception for all Sig-Net errors."""


class InvalidArgError(SigNetError):
    """Invalid argument (was SIGNET_ERROR_INVALID_ARG = -1)."""


class BufferFullError(SigNetError):
    """Packet buffer overflow (was SIGNET_ERROR_BUFFER_FULL = -2)."""


class CryptoError(SigNetError):
    """Cryptographic operation failed (was SIGNET_ERROR_CRYPTO = -3)."""


class EncodeError(SigNetError):
    """Encoding error (was SIGNET_ERROR_ENCODE = -4)."""


class NetworkError(SigNetError):
    """Network transmission failed (was SIGNET_ERROR_NETWORK = -5)."""


class BufferTooSmallError(SigNetError):
    """Insufficient data in buffer (was SIGNET_ERROR_BUFFER_TOO_SMALL = -6)."""


class InvalidPacketError(SigNetError):
    """Malformed packet structure (was SIGNET_ERROR_INVALID_PACKET = -7)."""


class InvalidOptionError(SigNetError):
    """Missing or invalid CoAP option (was SIGNET_ERROR_INVALID_OPTION = -8)."""


class HMACFailedError(SigNetError):
    """HMAC verification failed (was SIGNET_ERROR_HMAC_FAILED = -9)."""


class PassphraseError(SigNetError):
    """Base exception for passphrase validation failures."""


class PassphraseTooShortError(PassphraseError):
    """Passphrase length < 10 characters."""


class PassphraseTooLongError(PassphraseError):
    """Passphrase length > 64 characters."""


class PassphraseInsufficientClassesError(PassphraseError):
    """Fewer than 3 character classes used."""


class PassphraseConsecutiveIdenticalError(PassphraseError):
    """More than 2 consecutive identical characters."""


class PassphraseConsecutiveSequentialError(PassphraseError):
    """More than 3 consecutive sequential characters."""
