//==============================================================================
// Sig-Net Protocol Framework - Packet Assembly and Transmission (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// High-level packet assembly orchestrating CoAP, security, HMAC, and TLV
// components. Includes multicast address calculation and sequence management.
//==============================================================================

use crate::coap;
use crate::constants::*;
use crate::crypto;
use crate::security;
use crate::tlv;
use crate::types::*;

/// Calculate multicast IP address for a given universe (Section 9.2.3).
///
/// Multicast Folding Formula:
///   Index = ((Universe - 1) % 100) + 1
///   IP Address = 239.254.0.{Index}
pub fn calculate_multicast_address(universe: u16) -> Result<String, i32> {
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return Err(SIGNET_ERROR_INVALID_ARG);
    }

    let index = ((universe - 1) % 100) + 1;
    Ok(format!(
        "{}.{}.{}.{}",
        MULTICAST_BASE_OCTET_0, MULTICAST_BASE_OCTET_1, MULTICAST_BASE_OCTET_2, index
    ))
}

/// Get multicast IP octets (for direct use with socket APIs).
pub fn get_multicast_octets(universe: u16) -> Result<(u8, u8, u8, u8), i32> {
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return Err(SIGNET_ERROR_INVALID_ARG);
    }

    let index = (((universe - 1) % 100) + 1) as u8;
    Ok((
        MULTICAST_BASE_OCTET_0,
        MULTICAST_BASE_OCTET_1,
        MULTICAST_BASE_OCTET_2,
        index,
    ))
}

/// Build common Sig-Net options (without HMAC) and return the filled SigNetOptions.
pub fn build_common_signet_options(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
) -> Result<SigNetOptions, i32> {
    let mut options = SigNetOptions::default();
    options.security_mode = SECURITY_MODE_HMAC_SHA256;
    options.mfg_code = mfg_code;
    options.session_id = session_id;
    options.seq_num = seq_num;
    options.sender_id = security::build_sender_id(tuid, endpoint);

    let result =
        security::build_signet_options_without_hmac(buffer, &options, COAP_OPTION_URI_PATH);
    if result != SIGNET_SUCCESS {
        return Err(result);
    }

    Ok(options)
}

/// Build URI-Path options for /sig-net/v1/node/{tuid}/{endpoint}
/// and also return the URI string for HMAC input.
pub fn build_node_uri_path_options(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
) -> Result<String, i32> {
    let tuid_hex = crypto::tuid_to_hex_string(tuid);
    let endpoint_str = endpoint.to_string();

    let uri_string = format!(
        "/{}/{}/{}/{}/{}",
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_NODE, tuid_hex, endpoint_str
    );

    let mut prev_option: u16 = 0;

    let mut result = coap::encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        SIGNET_URI_PREFIX.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return Err(result);
    }
    prev_option = COAP_OPTION_URI_PATH;

    result = coap::encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        SIGNET_URI_VERSION.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return Err(result);
    }

    result = coap::encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        SIGNET_URI_NODE.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return Err(result);
    }

    result = coap::encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        tuid_hex.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return Err(result);
    }

    result = coap::encode_coap_option(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        endpoint_str.as_bytes(),
    );
    if result != SIGNET_SUCCESS {
        return Err(result);
    }

    Ok(uri_string)
}

/// Finalize a packet by encoding HMAC option then payload marker + payload.
pub fn finalize_packet_with_hmac_and_payload(
    buffer: &mut PacketBuffer,
    uri_string: &str,
    options: &mut SigNetOptions,
    payload_data: &[u8],
    signing_key: &[u8; DERIVED_KEY_LENGTH],
) -> i32 {
    let result = security::calculate_and_encode_hmac(
        buffer,
        uri_string,
        options,
        payload_data,
        signing_key,
        SIGNET_OPTION_SEQ_NUM,
    );
    if result != SIGNET_SUCCESS {
        return result;
    }

    if !payload_data.is_empty() {
        let result = buffer.write_byte(COAP_PAYLOAD_MARKER);
        if result != SIGNET_SUCCESS {
            return result;
        }

        let result = buffer.write_bytes(payload_data);
        if result != SIGNET_SUCCESS {
            return result;
        }
    }

    SIGNET_SUCCESS
}

/// Build a complete SigNet packet for DMX level transmission.
///
/// Orchestrates the entire packet construction process:
///   1. CoAP header
///   2. Uri-Path options (/sig-net/v1/level/{universe})
///   3. SigNet custom options (Security-Mode, Sender-ID, Mfg-Code, Session-ID, Seq-Num)
///   4. TLV payload (TID_LEVEL with DMX data)
///   5. HMAC calculation and encoding
pub fn build_dmx_packet(
    buffer: &mut PacketBuffer,
    universe: u16,
    dmx_data: &[u8],
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
    sender_key: &[u8; DERIVED_KEY_LENGTH],
    message_id: u16,
) -> i32 {
    if dmx_data.is_empty() || dmx_data.len() > MAX_DMX_SLOTS as usize {
        return SIGNET_ERROR_INVALID_ARG;
    }
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return SIGNET_ERROR_INVALID_ARG;
    }

    buffer.reset();

    let mut result = coap::build_coap_header(buffer, message_id);
    if result != SIGNET_SUCCESS {
        return result;
    }

    result = coap::build_uri_path_options(buffer, universe);
    if result != SIGNET_SUCCESS {
        return result;
    }

    let mut options =
        match build_common_signet_options(buffer, tuid, endpoint, mfg_code, session_id, seq_num) {
            Ok(o) => o,
            Err(e) => return e,
        };

    let mut payload = PacketBuffer::new();
    result = tlv::build_dmx_level_payload(&mut payload, dmx_data);
    if result != SIGNET_SUCCESS {
        return result;
    }

    let uri_string = match coap::build_uri_string(universe) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let payload_bytes = payload.get_buffer().to_vec();
    finalize_packet_with_hmac_and_payload(buffer, &uri_string, &mut options, &payload_bytes, sender_key)
}

/// Build startup announce packet (/sig-net/v1/node/{tuid}/0) signed with Kc.
pub fn build_announce_packet(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    firmware_version_id: u16,
    firmware_version_string: &str,
    protocol_version: u8,
    role_capability_bits: u8,
    change_count: u16,
    session_id: u32,
    seq_num: u32,
    citizen_key: &[u8; DERIVED_KEY_LENGTH],
    message_id: u16,
) -> i32 {
    buffer.reset();

    let mut result = coap::build_coap_header(buffer, message_id);
    if result != SIGNET_SUCCESS {
        return result;
    }

    let uri_string = match build_node_uri_path_options(buffer, tuid, 0) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let mut options =
        match build_common_signet_options(buffer, tuid, 0, mfg_code, session_id, seq_num) {
            Ok(o) => o,
            Err(e) => return e,
        };

    let mut payload = PacketBuffer::new();
    result = tlv::build_startup_announce_payload(
        &mut payload,
        tuid,
        mfg_code,
        product_variant_id,
        firmware_version_id,
        firmware_version_string,
        protocol_version,
        role_capability_bits,
        change_count,
    );
    if result != SIGNET_SUCCESS {
        return result;
    }

    let payload_bytes = payload.get_buffer().to_vec();
    finalize_packet_with_hmac_and_payload(buffer, &uri_string, &mut options, &payload_bytes, citizen_key)
}

/// Increment sequence number with rollover handling.
///
/// When sequence reaches 0xFFFFFFFF, wraps to 1 (not 0).
pub fn increment_sequence(current_seq: u32) -> u32 {
    if current_seq == 0xFFFFFFFF {
        1
    } else {
        current_seq + 1
    }
}

/// Check if sequence number has rolled over and session should increment.
pub fn should_increment_session(seq_num: u32) -> bool {
    seq_num == 0xFFFFFFFF
}
