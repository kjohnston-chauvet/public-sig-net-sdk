//==============================================================================
// Sig-Net Protocol Framework - Type Definitions (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// Data structures and type definitions including CoAP headers,
// TLV structures, packet buffers, and receiver state tracking.
//==============================================================================

use crate::constants::*;

/// CoAP Header Structure (RFC 7252 Section 3)
///
/// Packed 4-byte structure:
///  Ver(2) | Type(2) | TKL(4) | Code(8) | Message ID(16)
#[derive(Clone, Debug, Default)]
pub struct CoAPHeader {
    pub version_type_tkl: u8,
    pub code: u8,
    pub message_id: u16,
}

impl CoAPHeader {
    pub fn get_version(&self) -> u8 {
        (self.version_type_tkl >> 6) & 0x03
    }

    pub fn get_type(&self) -> u8 {
        (self.version_type_tkl >> 4) & 0x03
    }

    pub fn get_token_length(&self) -> u8 {
        self.version_type_tkl & 0x0F
    }

    pub fn set_version(&mut self, ver: u8) {
        self.version_type_tkl = (self.version_type_tkl & 0x3F) | ((ver & 0x03) << 6);
    }

    pub fn set_type(&mut self, msg_type: u8) {
        self.version_type_tkl = (self.version_type_tkl & 0xCF) | ((msg_type & 0x03) << 4);
    }

    pub fn set_token_length(&mut self, tkl: u8) {
        self.version_type_tkl = (self.version_type_tkl & 0xF0) | (tkl & 0x0F);
    }

    /// Serialize the header to 4 bytes (network byte order for message_id).
    pub fn to_bytes(&self) -> [u8; 4] {
        let msg_id_be = self.message_id.to_be_bytes();
        [self.version_type_tkl, self.code, msg_id_be[0], msg_id_be[1]]
    }
}

/// TLV (Type-Length-Value) Block Structure
#[derive(Clone, Debug)]
pub struct TLVBlock<'a> {
    pub type_id: u16,
    pub length: u16,
    pub value: &'a [u8],
}

impl<'a> TLVBlock<'a> {
    pub fn new(tid: u16, value: &'a [u8]) -> Self {
        TLVBlock {
            type_id: tid,
            length: value.len() as u16,
            value,
        }
    }

    pub fn empty(tid: u16) -> Self {
        TLVBlock {
            type_id: tid,
            length: 0,
            value: &[],
        }
    }
}

impl Default for TLVBlock<'_> {
    fn default() -> Self {
        TLVBlock {
            type_id: 0,
            length: 0,
            value: &[],
        }
    }
}

/// SigNet Custom Option Values
#[derive(Clone, Debug)]
pub struct SigNetOptions {
    pub security_mode: u8,
    pub sender_id: [u8; SENDER_ID_LENGTH],
    pub mfg_code: u16,
    pub session_id: u32,
    pub seq_num: u32,
    pub hmac: [u8; HMAC_SHA256_LENGTH],
}

impl Default for SigNetOptions {
    fn default() -> Self {
        SigNetOptions {
            security_mode: 0,
            sender_id: [0u8; SENDER_ID_LENGTH],
            mfg_code: 0,
            session_id: 0,
            seq_num: 0,
            hmac: [0u8; HMAC_SHA256_LENGTH],
        }
    }
}

/// Packet Buffer - manages a static 1400-byte buffer for constructing SigNet packets.
#[derive(Clone)]
pub struct PacketBuffer {
    buffer: [u8; MAX_UDP_PAYLOAD],
    write_position: usize,
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuffer {
    pub fn new() -> Self {
        PacketBuffer {
            buffer: [0u8; MAX_UDP_PAYLOAD],
            write_position: 0,
        }
    }

    pub fn reset(&mut self) {
        self.buffer = [0u8; MAX_UDP_PAYLOAD];
        self.write_position = 0;
    }

    pub fn get_position(&self) -> usize {
        self.write_position
    }

    pub fn get_size(&self) -> usize {
        self.write_position
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.write_position]
    }

    pub fn get_full_buffer(&self) -> &[u8; MAX_UDP_PAYLOAD] {
        &self.buffer
    }

    pub fn get_mutable_buffer(&mut self) -> &mut [u8; MAX_UDP_PAYLOAD] {
        &mut self.buffer
    }

    pub fn has_space(&self, size: usize) -> bool {
        (self.write_position + size) <= MAX_UDP_PAYLOAD
    }

    pub fn write_byte(&mut self, value: u8) -> i32 {
        if !self.has_space(1) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        self.buffer[self.write_position] = value;
        self.write_position += 1;
        SIGNET_SUCCESS
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> i32 {
        if !self.has_space(data.len()) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        self.buffer[self.write_position..self.write_position + data.len()].copy_from_slice(data);
        self.write_position += data.len();
        SIGNET_SUCCESS
    }

    /// Write a u16 in network byte order (big-endian).
    pub fn write_u16(&mut self, value: u16) -> i32 {
        if !self.has_space(2) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        let bytes = value.to_be_bytes();
        self.buffer[self.write_position] = bytes[0];
        self.buffer[self.write_position + 1] = bytes[1];
        self.write_position += 2;
        SIGNET_SUCCESS
    }

    /// Write a u32 in network byte order (big-endian).
    pub fn write_u32(&mut self, value: u32) -> i32 {
        if !self.has_space(4) {
            return SIGNET_ERROR_BUFFER_FULL;
        }
        let bytes = value.to_be_bytes();
        self.buffer[self.write_position..self.write_position + 4].copy_from_slice(&bytes);
        self.write_position += 4;
        SIGNET_SUCCESS
    }

    pub fn seek(&mut self, position: usize) -> i32 {
        if position > MAX_UDP_PAYLOAD {
            return SIGNET_ERROR_INVALID_ARG;
        }
        self.write_position = position;
        SIGNET_SUCCESS
    }
}

/// Receiver Sender State - tracks session/sequence state per unique Sender-ID
/// for anti-replay protection per Section 8.6 Step 9.
#[derive(Clone, Debug, Default)]
pub struct ReceiverSenderState {
    pub sender_id: [u8; SENDER_ID_LENGTH],
    pub session_id: u32,
    pub seq_num: u32,
    pub last_packet_time_ms: u32,
    pub total_packets_received: u32,
    pub total_packets_accepted: u32,
}

/// Receiver Statistics - global receiver statistics for diagnostics.
#[derive(Clone, Debug, Default)]
pub struct ReceiverStatistics {
    pub total_packets: u32,
    pub accepted_packets: u32,
    pub coap_version_errors: u32,
    pub coap_type_errors: u32,
    pub coap_code_errors: u32,
    pub uri_mismatches: u32,
    pub missing_options: u32,
    pub hmac_failures: u32,
    pub replay_detected: u32,
    pub parse_errors: u32,
    pub last_packet_time_ms: u32,
}

impl ReceiverStatistics {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Received Packet Info - information about a received packet for logging.
#[derive(Clone, Debug)]
pub struct ReceivedPacketInfo {
    pub message_id: u16,
    pub sender_tuid: [u8; 6],
    pub endpoint: u16,
    pub mfg_code: u16,
    pub session_id: u32,
    pub seq_num: u32,
    pub dmx_slot_count: u16,
    pub hmac_valid: bool,
    pub session_fresh: bool,
    pub rejection_reason: Option<&'static str>,
    pub timestamp_ms: u32,
}

impl Default for ReceivedPacketInfo {
    fn default() -> Self {
        ReceivedPacketInfo {
            message_id: 0,
            sender_tuid: [0u8; 6],
            endpoint: 0,
            mfg_code: 0,
            session_id: 0,
            seq_num: 0,
            dmx_slot_count: 0,
            hmac_valid: false,
            session_fresh: false,
            rejection_reason: None,
            timestamp_ms: 0,
        }
    }
}
