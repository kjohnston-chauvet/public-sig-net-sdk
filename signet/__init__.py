"""Sig-Net Protocol Framework SDK - Python Edition.

A cross-platform, pure-Python implementation of the Sig-Net Protocol
Framework v0.15 for secure CoAP-based DMX512 lighting control.
"""

from __future__ import annotations

__version__ = "0.3.0"
PROTOCOL_VERSION = "0.15"

# Core types
from .types import (
    CoAPHeader,
    PassphraseChecks,
    ReceivedPacketInfo,
    ReceiverSenderState,
    ReceiverStatistics,
    SigNetOptions,
    TLVBlock,
)

# Exceptions
from .exceptions import (
    BufferFullError,
    BufferTooSmallError,
    CryptoError,
    EncodeError,
    HMACFailedError,
    InvalidArgError,
    InvalidOptionError,
    InvalidPacketError,
    NetworkError,
    PassphraseConsecutiveIdenticalError,
    PassphraseConsecutiveSequentialError,
    PassphraseError,
    PassphraseInsufficientClassesError,
    PassphraseTooLongError,
    PassphraseTooShortError,
    SigNetError,
)

# Constants
from .constants import TID

# Crypto
from .crypto import (
    analyse_passphrase,
    derive_citizen_key,
    derive_k0_from_passphrase,
    derive_manager_global_key,
    derive_manager_local_key,
    derive_sender_key,
    generate_random_k0,
    generate_random_passphrase,
    hmac_sha256,
    tuid_from_hex,
    tuid_to_hex,
    validate_passphrase,
)

# Send
from .send import (
    build_announce_packet,
    build_dmx_packet,
    calculate_multicast_address,
    get_multicast_octets,
    increment_sequence,
    should_increment_session,
)

# Parse
from .parse import (
    PacketReader,
    extract_uri_string,
    parse_coap_header,
    parse_coap_option,
    parse_signet_options,
    parse_tid_level,
    parse_tlv_block,
    verify_packet_hmac,
)

# Transport
from .transport import MulticastReceiver, MulticastSender
