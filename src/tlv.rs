//==============================================================================
// Sig-Net Protocol Framework - TLV Payload Construction (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// Type-Length-Value (TLV) encoding for application payloads.
// Format: 2-byte Type | 2-byte Length | Variable Value data.
// All multi-byte fields in network byte order (big-endian).
//==============================================================================

use crate::constants::*;
use crate::types::*;

/// Encode a generic TLV block into a buffer.
pub fn encode_tlv(buffer: &mut PacketBuffer, tlv: &TLVBlock) -> i32 {
    // Write Type ID (2 bytes, network byte order)
    let mut result = buffer.write_u16(tlv.type_id);
    if result != SIGNET_SUCCESS {
        return result;
    }

    // Write Length (2 bytes, network byte order)
    result = buffer.write_u16(tlv.length);
    if result != SIGNET_SUCCESS {
        return result;
    }

    // Write Value (if length > 0)
    if tlv.length > 0 {
        result = buffer.write_bytes(tlv.value);
        if result != SIGNET_SUCCESS {
            return result;
        }
    }

    SIGNET_SUCCESS
}

/// Encode TID_LEVEL (DMX level data, 1-512 bytes).
pub fn encode_tid_level(buffer: &mut PacketBuffer, dmx_data: &[u8]) -> i32 {
    if dmx_data.is_empty() || dmx_data.len() > MAX_DMX_SLOTS as usize {
        return SIGNET_ERROR_INVALID_ARG;
    }

    let tlv = TLVBlock::new(TID_LEVEL, dmx_data);
    encode_tlv(buffer, &tlv)
}

/// Encode TID_PRIORITY (priority data per E1.31-1, 1-512 bytes).
pub fn encode_tid_priority(buffer: &mut PacketBuffer, priority_data: &[u8]) -> i32 {
    if priority_data.is_empty() || priority_data.len() > MAX_DMX_SLOTS as usize {
        return SIGNET_ERROR_INVALID_ARG;
    }

    let tlv = TLVBlock::new(TID_PRIORITY, priority_data);
    encode_tlv(buffer, &tlv)
}

/// Encode TID_SYNC (synchronization trigger, zero-length).
pub fn encode_tid_sync(buffer: &mut PacketBuffer) -> i32 {
    let tlv = TLVBlock::empty(TID_SYNC);
    encode_tlv(buffer, &tlv)
}

/// Encode TID_POLL_REPLY (0x0002, length 12).
///
/// Value layout: [0-5]=TUID, [6-9]=SOEM_CODE, [10-11]=CHANGE_COUNT
pub fn encode_tid_poll_reply(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    change_count: u16,
) -> i32 {
    let mut value = [0u8; 12];
    value[..TUID_LENGTH].copy_from_slice(tuid);

    let soem_code: u32 = ((mfg_code as u32) << 16) | (product_variant_id as u32);
    value[6..10].copy_from_slice(&soem_code.to_be_bytes());
    value[10..12].copy_from_slice(&change_count.to_be_bytes());

    let tlv = TLVBlock::new(TID_POLL_REPLY, &value);
    encode_tlv(buffer, &tlv)
}

/// Encode TID_RT_PROTOCOL_VERSION (0x0603, length 1).
pub fn encode_tid_rt_protocol_version(buffer: &mut PacketBuffer, protocol_version: u8) -> i32 {
    let value = [protocol_version];
    let tlv = TLVBlock::new(TID_RT_PROTOCOL_VERSION, &value);
    encode_tlv(buffer, &tlv)
}

/// Encode TID_RT_FIRMWARE_VERSION (0x0604, length 4-68).
///
/// Value layout: [0-3]=Machine Version ID (u32), [4..]=UTF-8 version string (max 64 bytes)
pub fn encode_tid_rt_firmware_version(
    buffer: &mut PacketBuffer,
    machine_version_id: u16,
    version_string: &str,
) -> i32 {
    let str_bytes = version_string.as_bytes();
    if str_bytes.len() > 64 {
        return SIGNET_ERROR_INVALID_ARG;
    }

    let mut value = vec![0u8; 4 + str_bytes.len()];
    let machine_version = machine_version_id as u32;
    value[..4].copy_from_slice(&machine_version.to_be_bytes());
    if !str_bytes.is_empty() {
        value[4..].copy_from_slice(str_bytes);
    }

    let tlv = TLVBlock::new(TID_RT_FIRMWARE_VERSION, &value);
    encode_tlv(buffer, &tlv)
}

/// Encode TID_RT_ROLE_CAPABILITY (0x0609, length 1).
pub fn encode_tid_rt_role_capability(
    buffer: &mut PacketBuffer,
    role_capability_bits: u8,
) -> i32 {
    let value = [role_capability_bits];
    let tlv = TLVBlock::new(TID_RT_ROLE_CAPABILITY, &value);
    encode_tlv(buffer, &tlv)
}

/// Build a complete DMX payload (single TID_LEVEL TLV).
pub fn build_dmx_level_payload(payload: &mut PacketBuffer, dmx_data: &[u8]) -> i32 {
    payload.reset();
    encode_tid_level(payload, dmx_data)
}

/// Build startup announce payload with fixed TLV ordering (Section 10.2.5):
///   1) TID_POLL_REPLY
///   2) TID_RT_FIRMWARE_VERSION
///   3) TID_RT_PROTOCOL_VERSION
///   4) TID_RT_ROLE_CAPABILITY
pub fn build_startup_announce_payload(
    payload: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    firmware_version_id: u16,
    firmware_version_string: &str,
    protocol_version: u8,
    role_capability_bits: u8,
    change_count: u16,
) -> i32 {
    payload.reset();

    let mut result =
        encode_tid_poll_reply(payload, tuid, mfg_code, product_variant_id, change_count);
    if result != SIGNET_SUCCESS {
        return result;
    }

    result = encode_tid_rt_firmware_version(payload, firmware_version_id, firmware_version_string);
    if result != SIGNET_SUCCESS {
        return result;
    }

    result = encode_tid_rt_protocol_version(payload, protocol_version);
    if result != SIGNET_SUCCESS {
        return result;
    }

    encode_tid_rt_role_capability(payload, role_capability_bits)
}

/// Build a complete payload with multiple TLV blocks.
pub fn build_payload(buffer: &mut PacketBuffer, tlv_blocks: &[TLVBlock]) -> i32 {
    for tlv in tlv_blocks {
        let result = encode_tlv(buffer, tlv);
        if result != SIGNET_SUCCESS {
            return result;
        }
    }
    SIGNET_SUCCESS
}
