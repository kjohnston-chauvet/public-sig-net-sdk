//==============================================================================
// Sig-Net Protocol Framework - Packet Parsing Functions (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// Parsing and verification for received Sig-Net packets. CoAP header/option
// parsing, custom option extraction, URI rebuild, TLV parsing, HMAC
// verification. Complements the send module.
//==============================================================================

use crate::constants::*;
use crate::crypto;
use crate::security;
use crate::types::*;

/// PacketReader - helper for reading from a const buffer.
pub struct PacketReader<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> PacketReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        PacketReader {
            buffer,
            position: 0,
        }
    }

    pub fn get_position(&self) -> usize {
        self.position
    }

    pub fn get_remaining(&self) -> usize {
        self.buffer.len() - self.position
    }

    pub fn can_read(&self, bytes: usize) -> bool {
        (self.position + bytes) <= self.buffer.len()
    }

    pub fn read_byte(&mut self) -> Option<u8> {
        if !self.can_read(1) {
            return None;
        }
        let value = self.buffer[self.position];
        self.position += 1;
        Some(value)
    }

    /// Read u16 in network byte order (big-endian).
    pub fn read_u16(&mut self) -> Option<u16> {
        if !self.can_read(2) {
            return None;
        }
        let value =
            ((self.buffer[self.position] as u16) << 8) | (self.buffer[self.position + 1] as u16);
        self.position += 2;
        Some(value)
    }

    /// Read u32 in network byte order (big-endian).
    pub fn read_u32(&mut self) -> Option<u32> {
        if !self.can_read(4) {
            return None;
        }
        let value = ((self.buffer[self.position] as u32) << 24)
            | ((self.buffer[self.position + 1] as u32) << 16)
            | ((self.buffer[self.position + 2] as u32) << 8)
            | (self.buffer[self.position + 3] as u32);
        self.position += 4;
        Some(value)
    }

    pub fn read_bytes(&mut self, count: usize) -> Option<&'a [u8]> {
        if !self.can_read(count) {
            return None;
        }
        let slice = &self.buffer[self.position..self.position + count];
        self.position += count;
        Some(slice)
    }

    pub fn skip(&mut self, count: usize) -> bool {
        if !self.can_read(count) {
            return false;
        }
        self.position += count;
        true
    }

    pub fn peek_byte(&self) -> Option<u8> {
        if self.position >= self.buffer.len() {
            return None;
        }
        Some(self.buffer[self.position])
    }

    pub fn get_current_slice(&self) -> &'a [u8] {
        &self.buffer[self.position..]
    }
}

/// Parse CoAP header from the reader.
pub fn parse_coap_header(reader: &mut PacketReader) -> Result<CoAPHeader, i32> {
    let byte0 = reader.read_byte().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;
    let byte1 = reader.read_byte().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;
    let message_id = reader.read_u16().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;

    Ok(CoAPHeader {
        version_type_tkl: byte0,
        code: byte1,
        message_id,
    })
}

/// Skip CoAP token bytes.
pub fn skip_token(reader: &mut PacketReader, token_length: u8) -> i32 {
    if token_length == 0 {
        return SIGNET_SUCCESS;
    }
    if !reader.skip(token_length as usize) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    SIGNET_SUCCESS
}

/// Parsed CoAP option result.
pub struct ParsedOption<'a> {
    pub option_num: u16,
    pub option_value: &'a [u8],
}

/// Parse a single CoAP option using delta encoding.
pub fn parse_coap_option<'a>(
    reader: &mut PacketReader<'a>,
    prev_option: u16,
) -> Result<ParsedOption<'a>, i32> {
    // Peek at next byte to check for payload marker
    let header_byte = reader.peek_byte().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;

    if header_byte == 0xFF {
        return Err(SIGNET_ERROR_INVALID_PACKET);
    }

    // Read option header
    let header_byte = reader.read_byte().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;

    let mut delta = ((header_byte >> 4) & 0x0F) as u16;
    let mut length = (header_byte & 0x0F) as u16;

    // Handle extended delta
    match delta {
        13 => {
            let ext = reader.read_byte().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;
            delta = 13 + ext as u16;
        }
        14 => {
            let ext = reader.read_u16().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;
            delta = 269 + ext;
        }
        15 => return Err(SIGNET_ERROR_INVALID_PACKET),
        _ => {}
    }

    // Handle extended length
    match length {
        13 => {
            let ext = reader.read_byte().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;
            length = 13 + ext as u16;
        }
        14 => {
            let ext = reader.read_u16().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;
            length = 269 + ext;
        }
        15 => return Err(SIGNET_ERROR_INVALID_PACKET),
        _ => {}
    }

    let option_num = prev_option + delta;

    let option_value = if length > 0 {
        reader
            .read_bytes(length as usize)
            .ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?
    } else {
        &[]
    };

    Ok(ParsedOption {
        option_num,
        option_value,
    })
}

/// Extract URI string from CoAP Uri-Path options.
///
/// Rebuilds the full URI string (e.g., "/sig-net/v1/level/517").
pub fn extract_uri_string(reader: &mut PacketReader) -> Result<String, i32> {
    let mut uri = String::from("/");
    let mut current_option: u16 = 0;
    let mut first_segment = true;

    loop {
        match parse_coap_option(reader, current_option) {
            Ok(opt) => {
                if opt.option_num == COAP_OPTION_URI_PATH {
                    if !first_segment {
                        uri.push('/');
                    }
                    first_segment = false;

                    let segment = std::str::from_utf8(opt.option_value)
                        .map_err(|_| SIGNET_ERROR_INVALID_PACKET)?;
                    uri.push_str(segment);
                } else if opt.option_num > COAP_OPTION_URI_PATH {
                    break;
                }
                current_option = opt.option_num;
            }
            Err(SIGNET_ERROR_INVALID_PACKET) => {
                // Hit payload marker or end of options
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(uri)
}

/// Parse SigNet custom options (2076-2236) from a packet.
pub fn parse_signet_options(reader: &mut PacketReader) -> Result<SigNetOptions, i32> {
    let mut options = SigNetOptions::default();
    let mut current_option: u16 = 0;

    let mut found_security_mode = false;
    let mut found_sender_id = false;
    let mut found_mfg_code = false;
    let mut found_session_id = false;
    let mut found_seq_num = false;
    let mut found_hmac = false;

    loop {
        match parse_coap_option(reader, current_option) {
            Ok(opt) => {
                match opt.option_num {
                    SIGNET_OPTION_SECURITY_MODE => {
                        if opt.option_value.len() != 1 {
                            return Err(SIGNET_ERROR_INVALID_OPTION);
                        }
                        options.security_mode = opt.option_value[0];
                        found_security_mode = true;
                    }
                    SIGNET_OPTION_SENDER_ID => {
                        if opt.option_value.len() != SENDER_ID_LENGTH {
                            return Err(SIGNET_ERROR_INVALID_OPTION);
                        }
                        options.sender_id.copy_from_slice(opt.option_value);
                        found_sender_id = true;
                    }
                    SIGNET_OPTION_MFG_CODE => {
                        if opt.option_value.len() != 2 {
                            return Err(SIGNET_ERROR_INVALID_OPTION);
                        }
                        options.mfg_code =
                            ((opt.option_value[0] as u16) << 8) | (opt.option_value[1] as u16);
                        found_mfg_code = true;
                    }
                    SIGNET_OPTION_SESSION_ID => {
                        if opt.option_value.len() != 4 {
                            return Err(SIGNET_ERROR_INVALID_OPTION);
                        }
                        options.session_id = ((opt.option_value[0] as u32) << 24)
                            | ((opt.option_value[1] as u32) << 16)
                            | ((opt.option_value[2] as u32) << 8)
                            | (opt.option_value[3] as u32);
                        found_session_id = true;
                    }
                    SIGNET_OPTION_SEQ_NUM => {
                        if opt.option_value.len() != 4 {
                            return Err(SIGNET_ERROR_INVALID_OPTION);
                        }
                        options.seq_num = ((opt.option_value[0] as u32) << 24)
                            | ((opt.option_value[1] as u32) << 16)
                            | ((opt.option_value[2] as u32) << 8)
                            | (opt.option_value[3] as u32);
                        found_seq_num = true;
                    }
                    SIGNET_OPTION_HMAC => {
                        if opt.option_value.len() != HMAC_SHA256_LENGTH {
                            return Err(SIGNET_ERROR_INVALID_OPTION);
                        }
                        options.hmac.copy_from_slice(opt.option_value);
                        found_hmac = true;
                    }
                    _ => {}
                }
                current_option = opt.option_num;
            }
            Err(SIGNET_ERROR_INVALID_PACKET) => {
                // Hit payload marker - done with options
                break;
            }
            Err(e) => return Err(e),
        }
    }

    if !found_security_mode {
        return Err(SIGNET_ERROR_INVALID_OPTION);
    }

    // For normal packets (not beacons), all options are required
    if options.security_mode != 0xFF
        && (!found_sender_id
            || !found_mfg_code
            || !found_session_id
            || !found_seq_num
            || !found_hmac)
    {
        return Err(SIGNET_ERROR_INVALID_OPTION);
    }

    Ok(options)
}

/// Parsed TLV block (owns the value reference into the original buffer).
pub struct ParsedTLVBlock<'a> {
    pub type_id: u16,
    pub length: u16,
    pub value: &'a [u8],
}

/// Parse the next TLV block from the payload.
pub fn parse_tlv_block<'a>(reader: &mut PacketReader<'a>) -> Result<ParsedTLVBlock<'a>, i32> {
    let type_id = reader.read_u16().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;
    let length = reader.read_u16().ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?;

    let value = if length > 0 {
        reader
            .read_bytes(length as usize)
            .ok_or(SIGNET_ERROR_BUFFER_TOO_SMALL)?
    } else {
        &[]
    };

    Ok(ParsedTLVBlock {
        type_id,
        length,
        value,
    })
}

/// Parse TID_LEVEL payload - extract DMX level data.
pub fn parse_tid_level(tlv: &ParsedTLVBlock) -> Result<Vec<u8>, i32> {
    if tlv.type_id != TID_LEVEL {
        return Err(SIGNET_ERROR_INVALID_ARG);
    }
    if tlv.length < 1 || tlv.length > 512 {
        return Err(SIGNET_ERROR_INVALID_PACKET);
    }

    Ok(tlv.value.to_vec())
}

/// Verify packet HMAC using constant-time comparison to prevent timing attacks.
pub fn verify_packet_hmac(
    uri_string: &str,
    options: &SigNetOptions,
    payload: &[u8],
    role_key: &[u8; DERIVED_KEY_LENGTH],
) -> i32 {
    // Build HMAC input buffer
    let hmac_input = match security::build_hmac_input(uri_string, options, payload) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Calculate expected HMAC
    let computed_hmac = match crypto::hmac_sha256(role_key, &hmac_input) {
        Ok(h) => h,
        Err(e) => return e,
    };

    // Constant-time comparison
    let mut diff: u8 = 0;
    for i in 0..HMAC_SHA256_LENGTH {
        diff |= computed_hmac[i] ^ options.hmac[i];
    }

    if diff != 0 {
        return SIGNET_ERROR_HMAC_FAILED;
    }

    SIGNET_SUCCESS
}
