//==============================================================================
// Sig-Net Protocol Framework - Constants and Definitions (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// Protocol constants, CoAP option numbers, TIDs, error codes,
// and configuration parameters for Sig-Net implementation.
//==============================================================================

// CoAP Protocol Constants (RFC 7252)
pub const COAP_VERSION: u8 = 1;

pub const COAP_TYPE_CON: u8 = 0;
pub const COAP_TYPE_NON: u8 = 1;
pub const COAP_TYPE_ACK: u8 = 2;
pub const COAP_TYPE_RST: u8 = 3;

pub const COAP_CODE_EMPTY: u8 = 0x00;
pub const COAP_CODE_GET: u8 = 0x01;
pub const COAP_CODE_POST: u8 = 0x02;
pub const COAP_CODE_PUT: u8 = 0x03;
pub const COAP_CODE_DELETE: u8 = 0x04;

pub const COAP_OPTION_URI_PATH: u16 = 11;

pub const COAP_OPTION_INLINE_MAX: u8 = 12;
pub const COAP_OPTION_EXT8_NIBBLE: u8 = 13;
pub const COAP_OPTION_EXT16_NIBBLE: u8 = 14;
pub const COAP_OPTION_EXT8_BASE: u16 = 13;
pub const COAP_OPTION_EXT16_BASE: u16 = 269;

pub const COAP_PAYLOAD_MARKER: u8 = 0xFF;

// Sig-Net Custom CoAP Options (Private Use Range 2048-64999)
pub const SIGNET_OPTION_SECURITY_MODE: u16 = 2076;
pub const SIGNET_OPTION_SENDER_ID: u16 = 2108;
pub const SIGNET_OPTION_MFG_CODE: u16 = 2140;
pub const SIGNET_OPTION_SESSION_ID: u16 = 2172;
pub const SIGNET_OPTION_SEQ_NUM: u16 = 2204;
pub const SIGNET_OPTION_HMAC: u16 = 2236;

// Security Modes
pub const SECURITY_MODE_HMAC_SHA256: u8 = 0x00;
pub const SECURITY_MODE_UNPROVISIONED: u8 = 0xFF;

// Type ID (TID) Definitions - Application Layer (Section 11)

// Section 11.1 - Node-Discovery
pub const TID_POLL: u16 = 0x0001;
pub const TID_POLL_REPLY: u16 = 0x0002;

// Section 11.2 - Sender
pub const TID_LEVEL: u16 = 0x0101;
pub const TID_PRIORITY: u16 = 0x0102;
pub const TID_SYNC: u16 = 0x0201;
pub const TID_TIMECODE: u16 = 0x0202;

// Section 11.3 - RDM
pub const TID_RDM_COMMAND: u16 = 0x0301;
pub const TID_RDM_RESPONSE: u16 = 0x0302;
pub const TID_RDM_TOD_CONTROL: u16 = 0x0303;
pub const TID_RDM_TOD_DATA: u16 = 0x0304;
pub const TID_RDM_TOD_BACKGROUND: u16 = 0x0305;

// Section 11.4 - Provisioning
pub const TID_RT_UNPROVISION: u16 = 0x0401;

// Section 11.5 - Network Configuration
pub const TID_NW_MAC_ADDRESS: u16 = 0x0501;
pub const TID_NW_IPV4_MODE: u16 = 0x0502;
pub const TID_NW_IPV4_ADDRESS: u16 = 0x0503;
pub const TID_NW_IPV4_NETMASK: u16 = 0x0504;
pub const TID_NW_IPV4_GATEWAY: u16 = 0x0505;
pub const TID_NW_IPV4_CURRENT: u16 = 0x0506;
pub const TID_NW_IPV6_MODE: u16 = 0x0581;
pub const TID_NW_IPV6_ADDRESS: u16 = 0x0582;
pub const TID_NW_IPV6_PREFIX: u16 = 0x0583;
pub const TID_NW_IPV6_GATEWAY: u16 = 0x0584;
pub const TID_NW_IPV6_CURRENT: u16 = 0x0585;

// Section 11.6 - Root Endpoint
pub const TID_RT_SUPPORTED_TIDS: u16 = 0x0601;
pub const TID_RT_ENDPOINT_COUNT: u16 = 0x0602;
pub const TID_RT_PROTOCOL_VERSION: u16 = 0x0603;
pub const TID_RT_FIRMWARE_VERSION: u16 = 0x0604;
pub const TID_RT_DEVICE_LABEL: u16 = 0x0605;
pub const TID_RT_MULT: u16 = 0x0606;
pub const TID_RT_IDENTIFY: u16 = 0x0607;
pub const TID_RT_STATUS: u16 = 0x0608;
pub const TID_RT_ROLE_CAPABILITY: u16 = 0x0609;

// Section 11.7 - Data Endpoint
pub const TID_EP_UNIVERSE: u16 = 0x0901;
pub const TID_EP_LABEL: u16 = 0x0902;
pub const TID_EP_MULT_OVERRIDE: u16 = 0x0903;
pub const TID_EP_DIRECTION_CAPABILITY: u16 = 0x0904;
pub const TID_EP_DIRECTION: u16 = 0x0905;
pub const TID_EP_INPUT_PRIORITY: u16 = 0x0906;
pub const TID_EP_STATUS: u16 = 0x0907;

// Section 11.8 - Diagnostic
pub const TID_DG_SECURITY_EVENT: u16 = 0xFF01;
pub const TID_DG_MESSAGE: u16 = 0xFF02;
pub const TID_DG_LEVEL_FOLDBACK: u16 = 0xFF03;

// Network Configuration
pub const SIGNET_UDP_PORT: u16 = 5683;

pub const MULTICAST_BASE_OCTET_0: u8 = 239;
pub const MULTICAST_BASE_OCTET_1: u8 = 254;
pub const MULTICAST_BASE_OCTET_2: u8 = 0;
pub const MULTICAST_MIN_INDEX: u8 = 1;
pub const MULTICAST_MAX_INDEX: u8 = 100;

pub const MULTICAST_TTL: u8 = 32;

// Protocol Limits
pub const MAX_DMX_SLOTS: u16 = 512;
pub const MIN_UNIVERSE: u16 = 1;
pub const MAX_UNIVERSE: u16 = 63999;
pub const MAX_UDP_PAYLOAD: usize = 1400;
pub const COAP_HEADER_SIZE: usize = 4;
pub const UNIVERSE_DECIMAL_BUFFER_SIZE: usize = 8;
pub const URI_STRING_MIN_BUFFER: usize = 32;

// Transmission Timing (Section 10.6.2)
pub const MAX_ACTIVE_RATE_HZ: u32 = 44;
pub const KEEPALIVE_RATE_HZ: u32 = 1;
pub const STREAM_LOSS_TIMEOUT_MS: u32 = 3000;

// Cryptographic Constants
pub const K0_KEY_LENGTH: usize = 32;
pub const DERIVED_KEY_LENGTH: usize = 32;
pub const HMAC_SHA256_LENGTH: usize = 32;
pub const TUID_LENGTH: usize = 6;
pub const TUID_HEX_LENGTH: usize = 12;
pub const ENDPOINT_LENGTH: usize = 2;
pub const SENDER_ID_LENGTH: usize = 8;
pub const HKDF_INFO_INPUT_MAX: usize = 63;
pub const HKDF_COUNTER_T1: u8 = 0x01;

// URI Path Components
pub const SIGNET_URI_PREFIX: &str = "sig-net";
pub const SIGNET_URI_VERSION: &str = "v1";
pub const SIGNET_URI_LEVEL: &str = "level";
pub const SIGNET_URI_PRIORITY: &str = "priority";
pub const SIGNET_URI_SYNC: &str = "sync";
pub const SIGNET_URI_NODE: &str = "node";

pub const MULTICAST_NODE_SEND_IP: &str = "239.254.255.253";

// Key Derivation Info Strings (Section 7.3)
pub const HKDF_INFO_SENDER: &str = "Sig-Net-Sender-v1";
pub const HKDF_INFO_CITIZEN: &str = "Sig-Net-Citizen-v1";
pub const HKDF_INFO_MANAGER_GLOBAL: &str = "Sig-Net-Manager-v1";
pub const HKDF_INFO_MANAGER_LOCAL_PREFIX: &str = "Sig-Net-Manager-v1-";

// Error Codes
pub const SIGNET_SUCCESS: i32 = 0;
pub const SIGNET_ERROR_INVALID_ARG: i32 = -1;
pub const SIGNET_ERROR_BUFFER_FULL: i32 = -2;
pub const SIGNET_ERROR_CRYPTO: i32 = -3;
pub const SIGNET_ERROR_ENCODE: i32 = -4;
pub const SIGNET_ERROR_NETWORK: i32 = -5;
pub const SIGNET_ERROR_BUFFER_TOO_SMALL: i32 = -6;
pub const SIGNET_ERROR_INVALID_PACKET: i32 = -7;
pub const SIGNET_ERROR_INVALID_OPTION: i32 = -8;
pub const SIGNET_ERROR_HMAC_FAILED: i32 = -9;
pub const SIGNET_TEST_FAILURE: i32 = -99;

// Passphrase Validation Return Codes (Section 7.2.3)
pub const SIGNET_PASSPHRASE_VALID: i32 = 0;
pub const SIGNET_PASSPHRASE_TOO_SHORT: i32 = -10;
pub const SIGNET_PASSPHRASE_TOO_LONG: i32 = -11;
pub const SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES: i32 = -12;
pub const SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL: i32 = -13;
pub const SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL: i32 = -14;

// Passphrase to K0 Derivation Parameters (Section 7.2.3)
pub const PBKDF2_SALT: &str = "Sig-Net-K0-Salt-v1";
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const PASSPHRASE_MIN_LENGTH: u32 = 10;
pub const PASSPHRASE_MAX_LENGTH: u32 = 64;
pub const PASSPHRASE_GENERATED_LENGTH: usize = 10;

pub const PASSPHRASE_SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:',.<>?/";
pub const PASSPHRASE_GEN_UPPERCASE: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
pub const PASSPHRASE_GEN_LOWERCASE: &str = "abcdefghjkmnpqrstuvwxyz";
pub const PASSPHRASE_GEN_DIGITS: &str = "23456789";
pub const PASSPHRASE_GEN_SYMBOLS: &str = "!@#$%^&*-_=+";

// Test K0 for Development/Testing
pub const TEST_K0: &str = "52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173";
pub const TEST_PASSPHRASE: &str = "Ge2p$E$4*A";

// Test TUID: 'S' 'L' (Singularity) = 0x534C + 000001
pub const TEST_TUID: &str = "534C00000001";
