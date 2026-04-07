//==============================================================================
// Sig-Net Protocol Framework - Master Module (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//==============================================================================
//
// Sig-Net Protocol Framework - Secure CoAP-based DMX512 control protocol.
//
// # Usage Example
//
// ```rust
// use sig_net_sdk::*;
//
// // 1. Derive sender key from K0 root key
// let k0 = [0u8; 32]; // your 256-bit root key
// let sender_key = crypto::derive_sender_key(&k0).unwrap();
//
// // 2. Prepare packet parameters
// let universe = 517u16;
// let dmx_data = [128u8; 512];
// let tuid = [0x53, 0x4C, 0x00, 0x00, 0x00, 0x01];
//
// // 3. Build packet
// let mut buffer = types::PacketBuffer::new();
// let result = send::build_dmx_packet(
//     &mut buffer, universe, &dmx_data,
//     &tuid, 0, 0x0000, 1, 1, &sender_key, 1,
// );
//
// // 4. Get multicast address
// let multicast_ip = send::calculate_multicast_address(universe).unwrap();
//
// // 5. Send via UDP (using your UDP library)
// if result == constants::SIGNET_SUCCESS {
//     // Send buffer.get_buffer() to multicast_ip:5683
// }
//
// // 6. Increment sequence for next packet
// let next_seq = send::increment_sequence(1);
// ```
//==============================================================================

pub mod constants;
pub mod types;
pub mod crypto;
pub mod coap;
pub mod security;
pub mod tlv;
pub mod send;
pub mod parse;
pub mod selftest;

/// Library version string.
pub const LIBRARY_VERSION: &str = "0.3";

/// Protocol version string.
pub const PROTOCOL_VERSION: &str = "0.15";

pub fn get_library_version() -> &'static str {
    LIBRARY_VERSION
}

pub fn get_protocol_version() -> &'static str {
    PROTOCOL_VERSION
}

/// Passphrase validation result codes (convenience enum mirroring constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseResult {
    Valid = 0,
    TooShort = -10,
    TooLong = -11,
    InsufficientClasses = -12,
    ConsecutiveIdentical = -13,
    ConsecutiveSequential = -14,
}

impl PassphraseResult {
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Valid),
            -10 => Some(Self::TooShort),
            -11 => Some(Self::TooLong),
            -12 => Some(Self::InsufficientClasses),
            -13 => Some(Self::ConsecutiveIdentical),
            -14 => Some(Self::ConsecutiveSequential),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_self_tests() {
        let (code, results) = selftest::run_all_tests();

        for test in &results.tests {
            if !test.passed {
                eprintln!("FAIL: {} - {}", test.name, test.error_message);
            }
        }

        assert_eq!(
            code,
            constants::SIGNET_SUCCESS,
            "{} of {} tests failed",
            results.failed_count,
            results.test_count()
        );
    }

    #[test]
    fn test_pbkdf2_known_vector() {
        // Test vector from sig-net-constants.hpp
        // Passphrase: "Ge2p$E$4*A"
        // Expected K0: 52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173
        let k0 = crypto::derive_k0_from_passphrase(constants::TEST_PASSPHRASE).unwrap();

        let expected_k0_hex = constants::TEST_K0;
        let actual_k0_hex: String = k0.iter().map(|b| format!("{:02x}", b)).collect();

        assert_eq!(actual_k0_hex, expected_k0_hex, "PBKDF2 K0 derivation mismatch");
    }

    #[test]
    fn test_key_derivation_chain() {
        // Derive K0 from test passphrase, then derive all role keys
        let k0 = crypto::derive_k0_from_passphrase(constants::TEST_PASSPHRASE).unwrap();

        let ks = crypto::derive_sender_key(&k0).unwrap();
        let kc = crypto::derive_citizen_key(&k0).unwrap();
        let km_global = crypto::derive_manager_global_key(&k0).unwrap();

        // Known expected values from the C++ implementation
        let expected_ks = "78981fe02576b2e9e47d916853d5967f34f8ae8aaae46db0495b178a75620e89";
        let expected_kc = "1973cecb72f2506f8b5c442c565f0c6a68aee8a873b8ef26e957b88a7fc54b80";
        let expected_km = "2f6b76ffe666dc65504be86828277ec9ef8a04fe329652c233ab537ad434fa0d";

        let ks_hex: String = ks.iter().map(|b| format!("{:02x}", b)).collect();
        let kc_hex: String = kc.iter().map(|b| format!("{:02x}", b)).collect();
        let km_hex: String = km_global.iter().map(|b| format!("{:02x}", b)).collect();

        assert_eq!(ks_hex, expected_ks, "Sender key mismatch");
        assert_eq!(kc_hex, expected_kc, "Citizen key mismatch");
        assert_eq!(km_hex, expected_km, "Manager global key mismatch");
    }

    #[test]
    fn test_build_and_parse_dmx_packet() {
        let k0 = crypto::derive_k0_from_passphrase(constants::TEST_PASSPHRASE).unwrap();
        let sender_key = crypto::derive_sender_key(&k0).unwrap();

        let tuid = crypto::tuid_from_hex_string(constants::TEST_TUID).unwrap();
        let dmx_data = [128u8; 512];

        let mut buffer = types::PacketBuffer::new();
        let result = send::build_dmx_packet(
            &mut buffer, 517, &dmx_data, &tuid, 0, 0x0000, 1, 1, &sender_key, 1,
        );
        assert_eq!(result, constants::SIGNET_SUCCESS, "Build DMX packet failed");
        assert!(buffer.get_size() > 0, "Packet buffer should not be empty");

        // Parse the packet back
        let packet_data = buffer.get_buffer();
        let mut reader = parse::PacketReader::new(packet_data);

        // Parse CoAP header
        let header = parse::parse_coap_header(&mut reader).unwrap();
        assert_eq!(header.get_version(), constants::COAP_VERSION);
        assert_eq!(header.get_type(), constants::COAP_TYPE_NON);
        assert_eq!(header.code, constants::COAP_CODE_POST);

        // Skip token
        let skip_result = parse::skip_token(&mut reader, header.get_token_length());
        assert_eq!(skip_result, constants::SIGNET_SUCCESS);
    }

    #[test]
    fn test_multicast_addresses() {
        assert_eq!(
            send::calculate_multicast_address(1).unwrap(),
            "239.254.0.1"
        );
        assert_eq!(
            send::calculate_multicast_address(100).unwrap(),
            "239.254.0.100"
        );
        assert_eq!(
            send::calculate_multicast_address(101).unwrap(),
            "239.254.0.1"
        );
        assert_eq!(
            send::calculate_multicast_address(517).unwrap(),
            "239.254.0.17"
        );
    }

    #[test]
    fn test_tuid_hex_roundtrip() {
        let tuid = crypto::tuid_from_hex_string("534C00000001").unwrap();
        assert_eq!(tuid, [0x53, 0x4C, 0x00, 0x00, 0x00, 0x01]);
        let hex = crypto::tuid_to_hex_string(&tuid);
        assert_eq!(hex, "534C00000001");
    }
}
