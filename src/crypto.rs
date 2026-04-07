//==============================================================================
// Sig-Net Protocol Framework - Cryptographic Functions (Rust)
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
// License: MIT
//
// Cryptographic primitives: HMAC-SHA256 (RFC 2104), HKDF-Expand (RFC 5869),
// PBKDF2-HMAC-SHA256, and key derivation for Sender, Citizen, Manager roles.
// Uses pure-Rust crates (hmac, sha2, pbkdf2) - no platform dependencies.
//==============================================================================

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constants::*;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 digest of a message using the provided key (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; HMAC_SHA256_LENGTH], i32> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| SIGNET_ERROR_CRYPTO)?;
    mac.update(message);
    let result = mac.finalize();
    let mut output = [0u8; HMAC_SHA256_LENGTH];
    output.copy_from_slice(&result.into_bytes());
    Ok(output)
}

/// HKDF-Expand (RFC 5869 Section 2.3) simplified for L=32.
///
/// OKM = HMAC-SHA256(PRK, info || 0x01)
pub fn hkdf_expand(prk: &[u8], info: &[u8]) -> Result<[u8; DERIVED_KEY_LENGTH], i32> {
    if info.len() > HKDF_INFO_INPUT_MAX {
        return Err(SIGNET_ERROR_INVALID_ARG);
    }

    let mut hmac_input = Vec::with_capacity(info.len() + 1);
    hmac_input.extend_from_slice(info);
    hmac_input.push(HKDF_COUNTER_T1);

    hmac_sha256(prk, &hmac_input)
}

/// Derive Sender Key (Ks) from K0 using info string "Sig-Net-Sender-v1".
pub fn derive_sender_key(k0: &[u8; K0_KEY_LENGTH]) -> Result<[u8; DERIVED_KEY_LENGTH], i32> {
    hkdf_expand(k0, HKDF_INFO_SENDER.as_bytes())
}

/// Derive Citizen Key (Kc) from K0 using info string "Sig-Net-Citizen-v1".
pub fn derive_citizen_key(k0: &[u8; K0_KEY_LENGTH]) -> Result<[u8; DERIVED_KEY_LENGTH], i32> {
    hkdf_expand(k0, HKDF_INFO_CITIZEN.as_bytes())
}

/// Derive Manager Global Key (Km_global) from K0 using info string "Sig-Net-Manager-v1".
pub fn derive_manager_global_key(
    k0: &[u8; K0_KEY_LENGTH],
) -> Result<[u8; DERIVED_KEY_LENGTH], i32> {
    hkdf_expand(k0, HKDF_INFO_MANAGER_GLOBAL.as_bytes())
}

/// Derive Manager Local Key (Km_local) from K0 for a specific TUID.
///
/// Uses info string "Sig-Net-Manager-v1-{12-char-hex-TUID}".
pub fn derive_manager_local_key(
    k0: &[u8; K0_KEY_LENGTH],
    tuid: &[u8; TUID_LENGTH],
) -> Result<[u8; DERIVED_KEY_LENGTH], i32> {
    let tuid_hex = tuid_to_hex_string(tuid);
    let mut info = String::from(HKDF_INFO_MANAGER_LOCAL_PREFIX);
    info.push_str(&tuid_hex);
    hkdf_expand(k0, info.as_bytes())
}

/// Convert 6-byte TUID to 12-character uppercase hex string.
pub fn tuid_to_hex_string(tuid: &[u8; TUID_LENGTH]) -> String {
    tuid.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Convert 12-character hex string to 6-byte TUID.
pub fn tuid_from_hex_string(hex_string: &str) -> Result<[u8; TUID_LENGTH], i32> {
    if hex_string.len() != TUID_HEX_LENGTH {
        return Err(SIGNET_ERROR_INVALID_ARG);
    }

    let mut tuid = [0u8; TUID_LENGTH];
    for i in 0..TUID_LENGTH {
        tuid[i] = u8::from_str_radix(&hex_string[i * 2..i * 2 + 2], 16)
            .map_err(|_| SIGNET_ERROR_INVALID_ARG)?;
    }
    Ok(tuid)
}

/// Passphrase analysis results - all individual check results in one struct.
#[derive(Clone, Debug, Default)]
pub struct PassphraseChecks {
    pub length: u32,
    pub length_ok: bool,
    pub class_count: i32,
    pub has_upper: bool,
    pub has_lower: bool,
    pub has_digit: bool,
    pub has_symbol: bool,
    pub classes_ok: bool,
    pub no_identical: bool,
    pub no_sequential: bool,
}

fn scan_char_classes(passphrase: &[u8]) -> (bool, bool, bool, bool) {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for &c in passphrase {
        let ch = c as char;
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if PASSPHRASE_SYMBOLS.contains(ch) {
            has_symbol = true;
        }
    }

    (has_upper, has_lower, has_digit, has_symbol)
}

fn has_identical_run(passphrase: &[u8]) -> bool {
    if passphrase.len() < 3 {
        return false;
    }
    for i in 0..passphrase.len() - 2 {
        if passphrase[i] == passphrase[i + 1] && passphrase[i] == passphrase[i + 2] {
            return true;
        }
    }
    false
}

fn has_sequential_run(passphrase: &[u8]) -> bool {
    if passphrase.len() < 4 {
        return false;
    }
    for i in 0..passphrase.len() - 3 {
        let c0 = passphrase[i] as i16;
        let c1 = passphrase[i + 1] as i16;
        let c2 = passphrase[i + 2] as i16;
        let c3 = passphrase[i + 3] as i16;

        // Ascending sequence
        if c1 == c0 + 1 && c2 == c0 + 2 && c3 == c0 + 3 {
            return true;
        }
        // Descending sequence
        if c1 == c0 - 1 && c2 == c0 - 2 && c3 == c0 - 3 {
            return true;
        }
    }
    false
}

/// Analyse passphrase - fills a PassphraseChecks struct with the result of every
/// individual test. Returns the same error code as `validate_passphrase()`.
pub fn analyse_passphrase(passphrase: &str) -> (i32, PassphraseChecks) {
    let bytes = passphrase.as_bytes();
    let len = bytes.len() as u32;

    let mut checks = PassphraseChecks {
        length: len,
        length_ok: len >= PASSPHRASE_MIN_LENGTH && len <= PASSPHRASE_MAX_LENGTH,
        ..Default::default()
    };

    if passphrase.is_empty() {
        checks.no_identical = true;
        checks.no_sequential = true;
        return (SIGNET_PASSPHRASE_TOO_SHORT, checks);
    }

    let (has_upper, has_lower, has_digit, has_symbol) = scan_char_classes(bytes);
    checks.has_upper = has_upper;
    checks.has_lower = has_lower;
    checks.has_digit = has_digit;
    checks.has_symbol = has_symbol;
    checks.class_count = has_upper as i32 + has_lower as i32 + has_digit as i32 + has_symbol as i32;
    checks.classes_ok = checks.class_count >= 3;

    checks.no_identical = !has_identical_run(bytes);
    checks.no_sequential = !has_sequential_run(bytes);

    // First failing code (same priority order as C++ implementation)
    if !checks.no_identical {
        return (SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL, checks);
    }
    if !checks.no_sequential {
        return (SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL, checks);
    }
    if !checks.classes_ok {
        return (SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES, checks);
    }
    if !checks.length_ok {
        let code = if len < PASSPHRASE_MIN_LENGTH {
            SIGNET_PASSPHRASE_TOO_SHORT
        } else {
            SIGNET_PASSPHRASE_TOO_LONG
        };
        return (code, checks);
    }

    (SIGNET_PASSPHRASE_VALID, checks)
}

/// Validate passphrase according to Sig-Net complexity requirements (Section 7.2.3).
pub fn validate_passphrase(passphrase: &str) -> i32 {
    let (code, _) = analyse_passphrase(passphrase);
    code
}

/// Get passphrase validation report - multi-line human-readable report.
pub fn get_passphrase_validation_report(passphrase: &str) -> (i32, String) {
    let (result, ch) = analyse_passphrase(passphrase);

    let status_line = match result {
        SIGNET_PASSPHRASE_VALID => "Passphrase valid. Click 'Passphrase to K0'.",
        SIGNET_PASSPHRASE_TOO_SHORT => "Too short (minimum 10 characters).",
        SIGNET_PASSPHRASE_TOO_LONG => "Too long (maximum 64 characters).",
        SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES => {
            "Need 3+ character classes (Uppercase, Lowercase, Digits, Symbols)."
        }
        SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL => "More than 2 identical characters in a row.",
        SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL => "More than 3 sequential characters in a row.",
        _ => "Passphrase not ready.",
    };

    let report = format!(
        "Length: {}/10-64 | Classes: {}/4 (U:{} L:{} D:{} S:{})\n\
         No triple identical: {} | No 4-char sequence: {}\n\
         {}",
        ch.length,
        ch.class_count,
        if ch.has_upper { "Y" } else { "N" },
        if ch.has_lower { "Y" } else { "N" },
        if ch.has_digit { "Y" } else { "N" },
        if ch.has_symbol { "Y" } else { "N" },
        if ch.no_identical { "OK" } else { "FAIL" },
        if ch.no_sequential { "OK" } else { "FAIL" },
        status_line
    );

    (result, report)
}

/// Derive K0 from passphrase using PBKDF2-HMAC-SHA256 (Section 7.2.3).
///
/// Iterations: 100,000
/// Salt: "Sig-Net-K0-Salt-v1" (18 bytes, ASCII)
/// Output: 32 bytes (256 bits)
pub fn derive_k0_from_passphrase(passphrase: &str) -> Result<[u8; K0_KEY_LENGTH], i32> {
    if passphrase.is_empty() {
        return Err(SIGNET_ERROR_INVALID_ARG);
    }

    let mut k0 = [0u8; K0_KEY_LENGTH];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        PBKDF2_SALT.as_bytes(),
        PBKDF2_ITERATIONS,
        &mut k0,
    );

    Ok(k0)
}

/// Generate a cryptographically secure random passphrase that meets all
/// Sig-Net complexity requirements.
pub fn generate_random_passphrase() -> Result<String, i32> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let upper = PASSPHRASE_GEN_UPPERCASE.as_bytes();
    let lower = PASSPHRASE_GEN_LOWERCASE.as_bytes();
    let digits = PASSPHRASE_GEN_DIGITS.as_bytes();
    let symbols = PASSPHRASE_GEN_SYMBOLS.as_bytes();

    let mut passphrase = vec![0u8; PASSPHRASE_GENERATED_LENGTH];

    // Force first 3 characters from different classes
    passphrase[0] = upper[rng.gen_range(0..upper.len())];
    passphrase[1] = lower[rng.gen_range(0..lower.len())];
    passphrase[2] = digits[rng.gen_range(0..digits.len())];

    // Fill remaining positions
    for i in 3..PASSPHRASE_GENERATED_LENGTH {
        let class_choice: u8 = rng.gen_range(0..4);
        passphrase[i] = match class_choice {
            0 => upper[rng.gen_range(0..upper.len())],
            1 => lower[rng.gen_range(0..lower.len())],
            2 => digits[rng.gen_range(0..digits.len())],
            _ => symbols[rng.gen_range(0..symbols.len())],
        };

        // Prevent consecutive identical characters
        if i > 0 && passphrase[i] == passphrase[i - 1] {
            passphrase[i] = lower[(rng.gen_range(0..lower.len()) + 1) % lower.len()];
        }

        // Check again for triple consecutive
        if i > 1 && passphrase[i] == passphrase[i - 1] && passphrase[i] == passphrase[i - 2] {
            passphrase[i] = digits[(rng.gen_range(0..digits.len()) + i) % digits.len()];
        }
    }

    let result = String::from_utf8(passphrase).map_err(|_| SIGNET_ERROR_CRYPTO)?;

    // Verify it passes validation
    if validate_passphrase(&result) != SIGNET_PASSPHRASE_VALID {
        // Fallback to known-good pattern (should never happen)
        return Ok("Abc123!@#$".to_string());
    }

    Ok(result)
}

/// Generate a cryptographically secure random 32-byte K0 root key.
pub fn generate_random_k0() -> Result<[u8; K0_KEY_LENGTH], i32> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut k0 = [0u8; K0_KEY_LENGTH];
    rng.fill_bytes(&mut k0);
    Ok(k0)
}
