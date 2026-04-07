//==============================================================================
// Sig-Net Protocol Framework - CoAP Packet Building (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// CoAP packet construction per RFC 7252, with extended delta encoding for
// large option number gaps. Handles URI-Path options and Sig-Net custom
// options in private use range (2048-64999).
//==============================================================================

use crate::constants::*;
use crate::types::*;

/// Build a CoAP header for SigNet packets.
///
/// - Version: 1
/// - Type: NON (Non-confirmable)
/// - Token Length: 0 (no token)
/// - Code: POST (0x02)
/// - Message ID: provided by caller
pub fn build_coap_header(buffer: &mut PacketBuffer, message_id: u16) -> i32 {
    let mut header = CoAPHeader::default();
    header.set_version(COAP_VERSION);
    header.set_type(COAP_TYPE_NON);
    header.set_token_length(0);
    header.code = COAP_CODE_POST;
    header.message_id = message_id;

    let bytes = header.to_bytes();
    buffer.write_bytes(&bytes)
}

/// Calculate the size needed for option delta encoding.
pub fn get_delta_extended_size(delta: u16) -> u8 {
    if delta <= COAP_OPTION_INLINE_MAX as u16 {
        0
    } else if delta < COAP_OPTION_EXT16_BASE {
        1
    } else {
        2
    }
}

/// Calculate the size needed for option length encoding.
pub fn get_length_extended_size(length: u16) -> u8 {
    if length <= COAP_OPTION_INLINE_MAX as u16 {
        0
    } else if length < COAP_OPTION_EXT16_BASE {
        1
    } else {
        2
    }
}

/// Encode a single CoAP option and write to buffer (RFC 7252 Section 3.1).
///
/// Handles extended delta and extended length encoding.
pub fn encode_coap_option(
    buffer: &mut PacketBuffer,
    option_number: u16,
    prev_option: u16,
    option_value: &[u8],
) -> i32 {
    if option_number < prev_option {
        return SIGNET_ERROR_ENCODE;
    }

    let delta = option_number - prev_option;
    let option_length = option_value.len() as u16;

    // Determine delta encoding
    let (delta_nibble, delta_ext_size, delta_ext_value) =
        if delta <= COAP_OPTION_INLINE_MAX as u16 {
            (delta as u8, 0u8, 0u16)
        } else if delta < COAP_OPTION_EXT16_BASE {
            (COAP_OPTION_EXT8_NIBBLE, 1u8, delta - COAP_OPTION_EXT8_BASE)
        } else {
            (
                COAP_OPTION_EXT16_NIBBLE,
                2u8,
                delta - COAP_OPTION_EXT16_BASE,
            )
        };

    // Determine length encoding
    let (length_nibble, length_ext_size, length_ext_value) =
        if option_length <= COAP_OPTION_INLINE_MAX as u16 {
            (option_length as u8, 0u8, 0u16)
        } else if option_length < COAP_OPTION_EXT16_BASE {
            (
                COAP_OPTION_EXT8_NIBBLE,
                1u8,
                option_length - COAP_OPTION_EXT8_BASE,
            )
        } else {
            (
                COAP_OPTION_EXT16_NIBBLE,
                2u8,
                option_length - COAP_OPTION_EXT16_BASE,
            )
        };

    // Write option header byte
    let header_byte = (delta_nibble << 4) | length_nibble;
    let mut result = buffer.write_byte(header_byte);
    if result != SIGNET_SUCCESS {
        return result;
    }

    // Write extended delta
    if delta_ext_size == 1 {
        result = buffer.write_byte(delta_ext_value as u8);
        if result != SIGNET_SUCCESS {
            return result;
        }
    } else if delta_ext_size == 2 {
        result = buffer.write_u16(delta_ext_value);
        if result != SIGNET_SUCCESS {
            return result;
        }
    }

    // Write extended length
    if length_ext_size == 1 {
        result = buffer.write_byte(length_ext_value as u8);
        if result != SIGNET_SUCCESS {
            return result;
        }
    } else if length_ext_size == 2 {
        result = buffer.write_u16(length_ext_value);
        if result != SIGNET_SUCCESS {
            return result;
        }
    }

    // Write option value
    if !option_value.is_empty() {
        result = buffer.write_bytes(option_value);
        if result != SIGNET_SUCCESS {
            return result;
        }
    }

    SIGNET_SUCCESS
}

/// Build URI-Path options for a Sig-Net level message.
///
/// Constructs: /sig-net/v1/level/{universe}
/// As 4 separate Uri-Path options (Option 11).
pub fn build_uri_path_options(buffer: &mut PacketBuffer, universe: u16) -> i32 {
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return SIGNET_ERROR_INVALID_ARG;
    }

    let mut prev_option: u16 = 0;

    // Option 1: "sig-net"
    let mut result = encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        SIGNET_URI_PREFIX.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return result;
    }
    prev_option = COAP_OPTION_URI_PATH;

    // Option 2: "v1"
    result = encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        SIGNET_URI_VERSION.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return result;
    }

    // Option 3: "level"
    result = encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        SIGNET_URI_LEVEL.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return result;
    }

    // Option 4: universe number as ASCII decimal string
    let universe_str = universe.to_string();
    encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        universe_str.as_bytes(),
    )
}

/// Build URI string for HMAC calculation (Section 8.5).
///
/// Returns: "/sig-net/v1/level/{universe}"
pub fn build_uri_string(universe: u16) -> Result<String, i32> {
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return Err(SIGNET_ERROR_INVALID_ARG);
    }

    Ok(format!(
        "/{}/{}/{}/{}",
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_LEVEL, universe
    ))
}
