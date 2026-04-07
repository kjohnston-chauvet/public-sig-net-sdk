//==============================================================================
// Sig-Net Library Self-Test Module (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// Embedded self-test suite for the Sig-Net library. Tests all major
// components including crypto, CoAP encoding, TLV composition, security,
// and packet building.
//==============================================================================

use crate::coap;
use crate::constants::*;
use crate::crypto;
use crate::security;
use crate::send;
use crate::tlv;
use crate::types::*;

/// Individual test result.
#[derive(Clone, Debug)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub error_message: String,
}

/// Overall test suite results.
#[derive(Clone, Debug, Default)]
pub struct TestSuiteResults {
    pub tests: Vec<TestResult>,
    pub passed_count: usize,
    pub failed_count: usize,
}

impl TestSuiteResults {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.tests.clear();
        self.passed_count = 0;
        self.failed_count = 0;
    }

    pub fn test_count(&self) -> usize {
        self.tests.len()
    }

    pub fn add_result(&mut self, name: &str, passed: bool, error_message: &str) {
        self.tests.push(TestResult {
            name: name.to_string(),
            passed,
            error_message: error_message.to_string(),
        });
        if passed {
            self.passed_count += 1;
        } else {
            self.failed_count += 1;
        }
    }
}

/// Run all self-tests and populate results structure.
///
/// Returns `SIGNET_SUCCESS` if all tests pass, `SIGNET_TEST_FAILURE` if any fail.
pub fn run_all_tests() -> (i32, TestSuiteResults) {
    let mut results = TestSuiteResults::new();

    test_crypto_module(&mut results);
    test_coap_module(&mut results);
    test_tlv_module(&mut results);
    test_security_module(&mut results);
    test_send_module(&mut results);

    let code = if results.failed_count == 0 {
        SIGNET_SUCCESS
    } else {
        SIGNET_TEST_FAILURE
    };

    (code, results)
}

fn test_crypto_module(results: &mut TestSuiteResults) {
    // Test 1: K0 Derivation (32-byte input)
    {
        let test_k0 = [0xAAu8; 32];
        let passed = crypto::derive_sender_key(&test_k0).is_ok();
        results.add_result(
            "Crypto: K0 Derivation (32-byte input)",
            passed,
            if passed { "" } else { "DeriveSenderKey failed" },
        );
    }

    // Test 2: HMAC-SHA256 Known Vector (RFC 4231 - Test Case 1)
    {
        let key = [0x0Bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 32] = [
            0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53, 0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B,
            0xF1, 0x2B, 0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7, 0x26, 0xE9, 0x37, 0x6C,
            0x2E, 0x32, 0xCF, 0xF7,
        ];

        let passed = match crypto::hmac_sha256(&key, data) {
            Ok(hmac) => hmac == expected,
            Err(_) => false,
        };
        results.add_result(
            "Crypto: HMAC-SHA256 Vector #1",
            passed,
            if passed {
                ""
            } else {
                "HMAC mismatch or compute failed"
            },
        );
    }

    // Test 3: Passphrase Validation - Valid Complex Passphrase
    {
        let (result, checks) = crypto::analyse_passphrase("Secure@Pass123!");
        let all_checks_pass = result == SIGNET_PASSPHRASE_VALID
            && checks.length_ok
            && checks.has_upper
            && checks.has_lower
            && checks.has_digit
            && checks.has_symbol
            && checks.classes_ok
            && checks.no_identical
            && checks.no_sequential;
        results.add_result(
            "Crypto: Passphrase Validation (valid complex)",
            all_checks_pass,
            if all_checks_pass {
                ""
            } else {
                "Passphrase checks failed"
            },
        );
    }

    // Test 4: Passphrase Validation - Too Short
    {
        let (result, checks) = crypto::analyse_passphrase("Pass1!");
        let passed = result == SIGNET_PASSPHRASE_TOO_SHORT && !checks.length_ok;
        results.add_result(
            "Crypto: Passphrase Validation (too short)",
            passed,
            if passed {
                ""
            } else {
                "Should have rejected short passphrase"
            },
        );
    }

    // Test 5: Passphrase Validation - Runs (3+ identical chars)
    {
        let (result, checks) = crypto::analyse_passphrase("Passyyy@123");
        let passed = result == SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL && !checks.no_identical;
        results.add_result(
            "Crypto: Passphrase Validation (invalid runs)",
            passed,
            if passed {
                ""
            } else {
                "Should have detected run of 3 identical chars"
            },
        );
    }

    // Test 6: Passphrase Validation - Sequential (4+ sequential chars)
    {
        let (result, checks) = crypto::analyse_passphrase("Pass1234abcd!@");
        let passed = result == SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL && !checks.no_sequential;
        results.add_result(
            "Crypto: Passphrase Validation (invalid sequential)",
            passed,
            if passed {
                ""
            } else {
                "Should have detected 4+ sequential chars"
            },
        );
    }

    // Test 7: Random Passphrase Generation
    {
        let result1 = crypto::generate_random_passphrase();
        let result2 = crypto::generate_random_passphrase();

        let passed = match (&result1, &result2) {
            (Ok(p1), Ok(p2)) => {
                !p1.is_empty()
                    && !p2.is_empty()
                    && p1 != p2
                    && crypto::validate_passphrase(p1) == SIGNET_PASSPHRASE_VALID
                    && crypto::validate_passphrase(p2) == SIGNET_PASSPHRASE_VALID
            }
            _ => false,
        };
        results.add_result(
            "Crypto: Random Passphrase Generation",
            passed,
            if passed {
                ""
            } else {
                "Random generation failed or validation failed"
            },
        );
    }
}

fn test_coap_module(results: &mut TestSuiteResults) {
    // Test 1: CoAP header building
    {
        let mut buffer = PacketBuffer::new();
        let result = coap::build_coap_header(&mut buffer, 1);
        let passed = result == SIGNET_SUCCESS && buffer.get_size() > 0;
        results.add_result(
            "CoAP: Header Construction",
            passed,
            if passed {
                ""
            } else {
                "Header construction failed"
            },
        );
    }

    // Test 2: URI path building
    {
        let mut buffer = PacketBuffer::new();
        let result = coap::build_uri_path_options(&mut buffer, 517);
        let passed = result == SIGNET_SUCCESS && buffer.get_size() > 0;
        results.add_result(
            "CoAP: URI Path Encoding",
            passed,
            if passed {
                ""
            } else {
                "URI path encoding failed"
            },
        );
    }

    // Test 3: URI string building
    {
        let passed = match coap::build_uri_string(517) {
            Ok(uri) => !uri.is_empty(),
            Err(_) => false,
        };
        results.add_result(
            "CoAP: Build URI String",
            passed,
            if passed {
                ""
            } else {
                "URI string encoding failed"
            },
        );
    }
}

fn test_tlv_module(results: &mut TestSuiteResults) {
    // Test 1: Build DMX Payload
    {
        let mut payload = PacketBuffer::new();
        let dmx_data = [42u8; 512];
        let result = tlv::build_dmx_level_payload(&mut payload, &dmx_data);
        let passed = result == SIGNET_SUCCESS && payload.get_size() > 0;
        results.add_result(
            "TLV: Build DMX Payload",
            passed,
            if passed {
                ""
            } else {
                "DMX payload build failed"
            },
        );
    }

    // Test 2: Build Startup Announce Payload
    {
        let mut payload = PacketBuffer::new();
        let tuid: [u8; 6] = [0x53, 0x4C, 0x00, 0x00, 0x00, 0x01];
        let result = tlv::build_startup_announce_payload(
            &mut payload,
            &tuid,
            0x534C,
            0,
            0x0100,
            "v1.0.0",
            1,
            0x01,
            0,
        );
        let passed = result == SIGNET_SUCCESS && payload.get_size() > 0;
        results.add_result(
            "TLV: Build Announce Payload",
            passed,
            if passed {
                ""
            } else {
                "Announce payload build failed"
            },
        );
    }
}

fn test_security_module(results: &mut TestSuiteResults) {
    // Test 1: Sender ID building
    {
        let tuid: [u8; 6] = [0x53, 0x4C, 0x00, 0x00, 0x00, 0x01];
        let sender_id = security::build_sender_id(&tuid, 0);
        let passed = sender_id[..6] == tuid;
        results.add_result(
            "Security: Build Sender ID",
            passed,
            if passed {
                ""
            } else {
                "Sender ID building failed"
            },
        );
    }
}

fn test_send_module(results: &mut TestSuiteResults) {
    // Test 1: Multicast Address Calculation
    {
        let passed = match send::calculate_multicast_address(517) {
            Ok(ip) => !ip.is_empty() && ip.starts_with("239.254."),
            Err(_) => false,
        };
        results.add_result(
            "Send: Multicast Address Calculation",
            passed,
            if passed {
                ""
            } else {
                "Multicast address calculation failed"
            },
        );
    }

    // Test 2: Sequence Increment
    {
        let seq_next = send::increment_sequence(1);
        let passed = seq_next == 2;
        results.add_result(
            "Send: Sequence Increment",
            passed,
            if passed {
                ""
            } else {
                "Sequence increment failed"
            },
        );
    }

    // Test 3: Sequence Rollover
    {
        let seq_next = send::increment_sequence(0xFFFFFFFF);
        let passed = seq_next == 1; // Should wrap to 1 (not 0)
        results.add_result(
            "Send: Sequence Rollover",
            passed,
            if passed {
                ""
            } else {
                "Sequence rollover failed"
            },
        );
    }
}
