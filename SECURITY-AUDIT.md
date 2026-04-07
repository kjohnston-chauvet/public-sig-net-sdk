# Security Audit: Sig-Net C++ SDK

## Critical Vulnerabilities

### 1. Integer overflow in bounds-checking functions
- **`PacketReader::CanRead()`** (`sig-net-parse.hpp:59`) — `position_ + bytes` are both `uint16_t`. If `position_` is 65530 and `bytes` is 10, the sum wraps to 4, bypassing the bounds check entirely. This enables **arbitrary out-of-bounds reads** on every parsing path.
- **`PacketBuffer::HasSpace()`** (`sig-net-types.hpp:158`) — Same `uint16_t` wraparound enables **out-of-bounds writes**.
- **Fix:** Cast to `uint32_t` before addition: `return (uint32_t)position_ + bytes <= size_;`

### 2. Hardcoded PBKDF2 salt (`sig-net-constants.hpp:263`)
```cpp
static const char* PBKDF2_SALT = "Sig-Net-K0-Salt-v1";
```
A fixed, publicly known salt shared across **all** deployments. An attacker can build one rainbow table that cracks every installation's passphrase-derived K0. This is a **protocol-level design flaw**.

### 3. Hardcoded fallback passphrase (`sig-net-crypto.cpp:481`)
```cpp
strcpy(passphrase_output, "Abc123!@#$");
```
If random passphrase generation fails validation, the code falls back to a publicly known passphrase. Any device hitting this path has a fully compromised K0.

### 4. Hardcoded test credentials in production headers (`sig-net-constants.hpp:280-281`)
```cpp
static const char* TEST_K0 = "52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173";
static const char* TEST_PASSPHRASE = "Ge2p$E$4*A";
```
No `#ifdef SIGNET_TESTING` guard — compiled into every binary. Any deployment accidentally using these has a known root key.

---

## High Severity

| # | Location | Issue |
|---|----------|-------|
| 5 | `sig-net-crypto.cpp:123-145` | **HKDF used without Extract step** — only Expand is implemented. If K0 has bias from a weak passphrase, that bias propagates into all derived keys. RFC 5869 requires Extract unless IKM is already uniformly random. |
| 6 | `sig-net-crypto.cpp` (entire file) | **No key material zeroization** — K0, derived keys, HMAC intermediates are never `SecureZeroMemory`'d. Recoverable from crash dumps, swap, cold boot. |
| 7 | `sig-net-security.cpp` (entire file) | **No constant-time HMAC verification function** — signing exists but no verify. Receivers likely use `memcmp`, enabling timing side-channel attacks to forge HMACs byte-by-byte. |
| 8 | `sig-net-security.cpp` | **No replay protection enforcement** — `ReceiverSenderState` tracks seq_num but no function enforces monotonicity. Left entirely to integrators. |
| 9 | `sig-net-parse.cpp:214-215` | **Option number overflow** — `option_num = prev_option + delta` wraps `uint16_t`, potentially causing an attacker-controlled option to be misinterpreted as a security-critical SigNet option (HMAC, security_mode). |
| 10 | `sig-net-parse.cpp:446-463` | **No destination buffer size check in `ParseTID_LEVEL`** — `memcpy(dmx_data, tlv.value, slot_count)` with attacker-controlled length up to 512 and no way to verify the caller's buffer size. |
| 11 | `sig-net-send.cpp:71,74` | **Unbounded `strcpy`/`sprintf`** into caller-provided buffer with no size parameter. Classic buffer overflow. |

---

## Medium Severity

| # | Location | Issue |
|---|----------|-------|
| 12 | `sig-net-crypto.cpp:438-458` | **Modulo bias** in random passphrase generation (`random_byte % charset_len`). Same byte used for class selection and character selection, creating correlation. |
| 13 | `sig-net-crypto.cpp:184` | **Fragile stack buffer** — `char info_str[40]` for a 33-byte string with no bounds check. |
| 14 | `sig-net-crypto.cpp:345` | **`sprintf` without bounds** in `GetPassphraseValidationReport` — output can exceed the `report_size` minimum check of 64. |
| 15 | `sig-net-parse.cpp:132` | **No CoAP TKL validation** — values 9-15 are reserved but accepted, causing parser misalignment. |
| 16 | `sig-net-send.cpp:69` | **Thread-unsafe `inet_ntoa`** — returns static buffer; concurrent calls corrupt results. |
| 17 | `sig-net-send.hpp:190-195` | **Sequence rollover wraps silently** without bumping session_id — enables replay if caller forgets to check. |
| 18 | `sig-net-security.cpp:146` | **Rejects NULL payload for zero-length messages** — blocks valid protocol messages (e.g., TID_SYNC). |
| 19 | Protocol design | **No payload confidentiality** — all DMX data transmitted in plaintext; HMAC provides authentication only. |
| 20 | `sig-net-send.cpp:59` | **Multicast folding** collapses 63,999 universes onto 100 addresses, amplifying DoS surface. |
| 21 | `sig-net-coap.cpp:52` | **Uninitialized `CoAPHeader`** — read-modify-write bitfield operations on garbage stack data. |

---

## Low Severity

- PBKDF2 iterations (100K) below current OWASP recommendation (600K) (`sig-net-constants.hpp:264`)
- `TLVBlock.value` stores non-owning pointer — dangling pointer risk (`sig-net-types.hpp:86`)
- `GetMutableBuffer()` bypasses all bounds checking (`sig-net-types.hpp:153`)
- `strlen()` on potentially unterminated string in `EncodeTID_RT_FIRMWARE_VERSION` (`sig-net-tlv.cpp:183`)
- `BuildPayload` doesn't reset buffer — potential stale data leak (`sig-net-tlv.cpp:268`)
- Large cumulative stack usage (~5KB+ per call chain) in embedded context

---

## Recommendations (Priority Order)

1. **Fix the `uint16_t` overflow in `CanRead()` and `HasSpace()`** — these are exploitable remotely via crafted packets.
2. **Add `#ifdef SIGNET_TESTING` guards** around `TEST_K0`, `TEST_PASSPHRASE`, `TEST_TUID`.
3. **Replace the hardcoded fallback passphrase** with an error return.
4. **Implement HKDF-Extract** before Expand, or document why IKM is guaranteed uniform.
5. **Add a constant-time `VerifyHMAC()` function** and enforce monotonic sequence numbers in the SDK, not just in caller code.
6. **Zero all key material** after use with `SecureZeroMemory` / `explicit_bzero`.
7. **Replace `sprintf`/`strcpy` with `snprintf`/bounded copies** throughout.
8. **Migrate to per-deployment random PBKDF2 salts** in the next protocol version.
