//==============================================================================
// Sig-Net Protocol Framework - Security Layer (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// Sig-Net custom CoAP options (2076-2236) encoding and HMAC-SHA256
// signature calculation. Implements security per Section 8.5.
//==============================================================================

use crate::coap;
use crate::constants::*;
use crate::crypto;
use crate::types::*;

/// Build SigNet custom options (without HMAC) into the packet buffer.
///
/// Encodes the first 5 SigNet custom options (Security-Mode through Seq-Num).
/// The HMAC option is added later by `calculate_and_encode_hmac()`.
pub fn build_signet_options_without_hmac(
    buffer: &mut PacketBuffer,
    options: &SigNetOptions,
    prev_option: u16,
) -> i32 {
    let mut prev = prev_option;

    // Option 1: Security-Mode (2076) - 1 byte
    let mut result = coap::encode_coap_option(
        buffer,
        SIGNET_OPTION_SECURITY_MODE,
        prev,
        &[options.security_mode],
    );
    if result != SIGNET_SUCCESS {
        return result;
    }
    prev = SIGNET_OPTION_SECURITY_MODE;

    // Option 2: Sender-ID (2108) - 8 bytes
    result = coap::encode_coap_option(buffer, SIGNET_OPTION_SENDER_ID, prev, &options.sender_id);
    if result != SIGNET_SUCCESS {
        return result;
    }
    prev = SIGNET_OPTION_SENDER_ID;

    // Option 3: Mfg-Code (2140) - 2 bytes (network byte order)
    let mfg_code_bytes = options.mfg_code.to_be_bytes();
    result = coap::encode_coap_option(buffer, SIGNET_OPTION_MFG_CODE, prev, &mfg_code_bytes);
    if result != SIGNET_SUCCESS {
        return result;
    }
    prev = SIGNET_OPTION_MFG_CODE;

    // Option 4: Session-ID (2172) - 4 bytes (network byte order)
    let session_id_bytes = options.session_id.to_be_bytes();
    result = coap::encode_coap_option(buffer, SIGNET_OPTION_SESSION_ID, prev, &session_id_bytes);
    if result != SIGNET_SUCCESS {
        return result;
    }
    prev = SIGNET_OPTION_SESSION_ID;

    // Option 5: Seq-Num (2204) - 4 bytes (network byte order)
    let seq_num_bytes = options.seq_num.to_be_bytes();
    result = coap::encode_coap_option(buffer, SIGNET_OPTION_SEQ_NUM, prev, &seq_num_bytes);
    if result != SIGNET_SUCCESS {
        return result;
    }

    SIGNET_SUCCESS
}

/// Build HMAC input buffer (Section 8.5).
///
/// Constructs the byte sequence that will be authenticated:
///   1. URI string (ASCII, including leading '/')
///   2. Security-Mode (1 byte)
///   3. Sender-ID (8 bytes)
///   4. Mfg-Code (2 bytes, network byte order)
///   5. Session-ID (4 bytes, network byte order)
///   6. Seq-Num (4 bytes, network byte order)
///   7. Application Payload (variable length)
pub fn build_hmac_input(
    uri_string: &str,
    options: &SigNetOptions,
    payload: &[u8],
) -> Result<Vec<u8>, i32> {
    let uri_bytes = uri_string.as_bytes();
    let total_len = uri_bytes.len() + 1 + SENDER_ID_LENGTH + 2 + 4 + 4 + payload.len();

    let mut output = Vec::with_capacity(total_len);

    // 1. URI string
    output.extend_from_slice(uri_bytes);

    // 2. Security-Mode
    output.push(options.security_mode);

    // 3. Sender-ID
    output.extend_from_slice(&options.sender_id);

    // 4. Mfg-Code (network byte order)
    output.extend_from_slice(&options.mfg_code.to_be_bytes());

    // 5. Session-ID (network byte order)
    output.extend_from_slice(&options.session_id.to_be_bytes());

    // 6. Seq-Num (network byte order)
    output.extend_from_slice(&options.seq_num.to_be_bytes());

    // 7. Application Payload
    output.extend_from_slice(payload);

    Ok(output)
}

/// Calculate and encode HMAC option.
///
/// 1. Builds the HMAC input buffer
/// 2. Computes HMAC-SHA256 using the sender key
/// 3. Encodes the HMAC as option 2236
pub fn calculate_and_encode_hmac(
    buffer: &mut PacketBuffer,
    uri_string: &str,
    options: &mut SigNetOptions,
    payload: &[u8],
    sender_key: &[u8; DERIVED_KEY_LENGTH],
    prev_option: u16,
) -> i32 {
    // Build HMAC input buffer
    let hmac_input = match build_hmac_input(uri_string, options, payload) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Calculate HMAC-SHA256
    let hmac = match crypto::hmac_sha256(sender_key, &hmac_input) {
        Ok(h) => h,
        Err(e) => return e,
    };
    options.hmac = hmac;

    // Encode HMAC as option 2236
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, prev_option, &options.hmac)
}

/// Build Sender-ID from TUID and Endpoint.
///
/// Sender-ID format (8 bytes):
///   Bytes 0-5: TUID (6 bytes)
///   Bytes 6-7: Endpoint (2 bytes, network byte order)
pub fn build_sender_id(tuid: &[u8; TUID_LENGTH], endpoint: u16) -> [u8; SENDER_ID_LENGTH] {
    let mut sender_id = [0u8; SENDER_ID_LENGTH];
    sender_id[..TUID_LENGTH].copy_from_slice(tuid);
    let ep_bytes = endpoint.to_be_bytes();
    sender_id[6] = ep_bytes[0];
    sender_id[7] = ep_bytes[1];
    sender_id
}
