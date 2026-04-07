"""Sig-Net Protocol Framework - Constants and Definitions.

Protocol constants, CoAP option numbers, TIDs, error codes,
and configuration parameters derived from the Sig-Net Protocol
Framework specification v0.15.
"""

from __future__ import annotations

from enum import IntEnum

# ==============================================================================
# CoAP Protocol Constants (RFC 7252)
# ==============================================================================

COAP_VERSION = 1

# CoAP Message Types
COAP_TYPE_CON = 0   # Confirmable
COAP_TYPE_NON = 1   # Non-confirmable (used by Sig-Net)
COAP_TYPE_ACK = 2   # Acknowledgement
COAP_TYPE_RST = 3   # Reset

# CoAP Method Codes
COAP_CODE_EMPTY = 0x00
COAP_CODE_GET = 0x01
COAP_CODE_POST = 0x02   # Used by Sig-Net
COAP_CODE_PUT = 0x03
COAP_CODE_DELETE = 0x04

# CoAP Standard Option Numbers
COAP_OPTION_URI_PATH = 11

# CoAP option extended encoding constants (RFC 7252)
COAP_OPTION_INLINE_MAX = 12
COAP_OPTION_EXT8_NIBBLE = 13
COAP_OPTION_EXT16_NIBBLE = 14
COAP_OPTION_EXT8_BASE = 13
COAP_OPTION_EXT16_BASE = 269

# CoAP Payload Marker
COAP_PAYLOAD_MARKER = 0xFF

# ==============================================================================
# Sig-Net Custom CoAP Options (Private Use Range 2048-64999)
# ==============================================================================

SIGNET_OPTION_SECURITY_MODE = 2076   # 1 byte
SIGNET_OPTION_SENDER_ID = 2108       # 8 bytes (TUID + endpoint)
SIGNET_OPTION_MFG_CODE = 2140        # 2 bytes (ESTA Manufacturer ID)
SIGNET_OPTION_SESSION_ID = 2172      # 4 bytes (boot counter)
SIGNET_OPTION_SEQ_NUM = 2204         # 4 bytes (sequence number)
SIGNET_OPTION_HMAC = 2236            # 32 bytes (HMAC-SHA256)

# ==============================================================================
# Sig-Net Security Modes
# ==============================================================================

SECURITY_MODE_HMAC_SHA256 = 0x00
SECURITY_MODE_UNPROVISIONED = 0xFF

# ==============================================================================
# Sig-Net Type ID (TID) Definitions - Application Layer (Section 11)
# ==============================================================================


class TID(IntEnum):
    # Node-Discovery (Section 11.1)
    POLL = 0x0001
    POLL_REPLY = 0x0002

    # Sender (Section 11.2)
    LEVEL = 0x0101
    PRIORITY = 0x0102
    SYNC = 0x0201
    TIMECODE = 0x0202

    # RDM (Section 11.3)
    RDM_COMMAND = 0x0301
    RDM_RESPONSE = 0x0302
    RDM_TOD_CONTROL = 0x0303
    RDM_TOD_DATA = 0x0304
    RDM_TOD_BACKGROUND = 0x0305

    # Provisioning (Section 11.4)
    RT_UNPROVISION = 0x0401

    # Network Configuration (Section 11.5)
    NW_MAC_ADDRESS = 0x0501
    NW_IPV4_MODE = 0x0502
    NW_IPV4_ADDRESS = 0x0503
    NW_IPV4_NETMASK = 0x0504
    NW_IPV4_GATEWAY = 0x0505
    NW_IPV4_CURRENT = 0x0506
    NW_IPV6_MODE = 0x0581
    NW_IPV6_ADDRESS = 0x0582
    NW_IPV6_PREFIX = 0x0583
    NW_IPV6_GATEWAY = 0x0584
    NW_IPV6_CURRENT = 0x0585

    # Root Endpoint (Section 11.6)
    RT_SUPPORTED_TIDS = 0x0601
    RT_ENDPOINT_COUNT = 0x0602
    RT_PROTOCOL_VERSION = 0x0603
    RT_FIRMWARE_VERSION = 0x0604
    RT_DEVICE_LABEL = 0x0605
    RT_MULT = 0x0606
    RT_IDENTIFY = 0x0607
    RT_STATUS = 0x0608
    RT_ROLE_CAPABILITY = 0x0609

    # Data Endpoint (Section 11.7)
    EP_UNIVERSE = 0x0901
    EP_LABEL = 0x0902
    EP_MULT_OVERRIDE = 0x0903
    EP_DIRECTION_CAPABILITY = 0x0904
    EP_DIRECTION = 0x0905
    EP_INPUT_PRIORITY = 0x0906
    EP_STATUS = 0x0907

    # Diagnostic (Section 11.8)
    DG_SECURITY_EVENT = 0xFF01
    DG_MESSAGE = 0xFF02
    DG_LEVEL_FOLDBACK = 0xFF03


# ==============================================================================
# Network Configuration
# ==============================================================================

SIGNET_UDP_PORT = 5683

MULTICAST_BASE_OCTET_0 = 239
MULTICAST_BASE_OCTET_1 = 254
MULTICAST_BASE_OCTET_2 = 0
MULTICAST_MIN_INDEX = 1
MULTICAST_MAX_INDEX = 100

MULTICAST_TTL = 32

# ==============================================================================
# Protocol Limits
# ==============================================================================

MAX_DMX_SLOTS = 512
MIN_UNIVERSE = 1
MAX_UNIVERSE = 63999
MAX_UDP_PAYLOAD = 1400
COAP_HEADER_SIZE = 4

# ==============================================================================
# Transmission Timing (Section 10.6.2)
# ==============================================================================

MAX_ACTIVE_RATE_HZ = 44
KEEPALIVE_RATE_HZ = 1
STREAM_LOSS_TIMEOUT_MS = 3000

# ==============================================================================
# Cryptographic Constants
# ==============================================================================

K0_KEY_LENGTH = 32
DERIVED_KEY_LENGTH = 32
HMAC_SHA256_LENGTH = 32
TUID_LENGTH = 6
TUID_HEX_LENGTH = 12
ENDPOINT_LENGTH = 2
SENDER_ID_LENGTH = 8
HKDF_INFO_INPUT_MAX = 63
HKDF_COUNTER_T1 = 0x01

# ==============================================================================
# URI Path Components
# ==============================================================================

SIGNET_URI_PREFIX = "sig-net"
SIGNET_URI_VERSION = "v1"
SIGNET_URI_LEVEL = "level"
SIGNET_URI_PRIORITY = "priority"
SIGNET_URI_SYNC = "sync"
SIGNET_URI_NODE = "node"

MULTICAST_NODE_SEND_IP = "239.254.255.253"

# ==============================================================================
# Key Derivation Info Strings (Section 7.3)
# ==============================================================================

HKDF_INFO_SENDER = b"Sig-Net-Sender-v1"
HKDF_INFO_CITIZEN = b"Sig-Net-Citizen-v1"
HKDF_INFO_MANAGER_GLOBAL = b"Sig-Net-Manager-v1"
HKDF_INFO_MANAGER_LOCAL_PREFIX = "Sig-Net-Manager-v1-"

# ==============================================================================
# Passphrase Parameters (Section 7.2.3)
# ==============================================================================

PBKDF2_SALT = b"Sig-Net-K0-Salt-v1"
PBKDF2_ITERATIONS = 100000
PASSPHRASE_MIN_LENGTH = 10
PASSPHRASE_MAX_LENGTH = 64
PASSPHRASE_GENERATED_LENGTH = 10

PASSPHRASE_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>?/"
PASSPHRASE_GEN_UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ"
PASSPHRASE_GEN_LOWERCASE = "abcdefghjkmnpqrstuvwxyz"
PASSPHRASE_GEN_DIGITS = "23456789"
PASSPHRASE_GEN_SYMBOLS = "!@#$%^&*-_=+"

# ==============================================================================
# Test Vectors
# ==============================================================================

TEST_K0 = "52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173"
TEST_PASSPHRASE = "Ge2p$E$4*A"
TEST_TUID = "534C00000001"
