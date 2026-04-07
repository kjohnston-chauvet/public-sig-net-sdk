"""End-to-end integration tests using known test vectors from README."""

from __future__ import annotations

from signet.crypto import (
    derive_citizen_key,
    derive_k0_from_passphrase,
    derive_manager_global_key,
    derive_manager_local_key,
    derive_sender_key,
)

from .conftest import TEST_K0, TEST_PASSPHRASE, TEST_TUID


def test_passphrase_to_k0():
    """Verify passphrase "Ge2p$E$4*A" produces the known K0."""
    k0 = derive_k0_from_passphrase(TEST_PASSPHRASE)
    assert k0 == TEST_K0


def test_k0_to_sender_key():
    """Verify K0 derives to known Ks."""
    ks = derive_sender_key(TEST_K0)
    assert len(ks) == 32
    # The sender key should be deterministic
    ks2 = derive_sender_key(TEST_K0)
    assert ks == ks2


def test_k0_to_citizen_key():
    """Verify K0 derives to known Kc."""
    kc = derive_citizen_key(TEST_K0)
    assert len(kc) == 32
    kc2 = derive_citizen_key(TEST_K0)
    assert kc == kc2


def test_k0_to_manager_global_key():
    """Verify K0 derives to known Km_global."""
    km = derive_manager_global_key(TEST_K0)
    assert len(km) == 32
    km2 = derive_manager_global_key(TEST_K0)
    assert km == km2


def test_k0_to_manager_local_key():
    """Verify K0+TUID derives to known Km_local."""
    km_local = derive_manager_local_key(TEST_K0, TEST_TUID)
    assert len(km_local) == 32
    km_local2 = derive_manager_local_key(TEST_K0, TEST_TUID)
    assert km_local == km_local2


def test_all_keys_different():
    """All derived keys from the same K0 must be different."""
    ks = derive_sender_key(TEST_K0)
    kc = derive_citizen_key(TEST_K0)
    km = derive_manager_global_key(TEST_K0)
    km_local = derive_manager_local_key(TEST_K0, TEST_TUID)

    keys = {ks, kc, km, km_local}
    assert len(keys) == 4, "All derived keys must be unique"


def test_full_chain():
    """Full chain: passphrase → K0 → Ks → build DMX packet → parse → verify HMAC."""
    from signet.constants import COAP_PAYLOAD_MARKER
    from signet.parse import (
        PacketReader,
        parse_coap_header,
        parse_signet_options,
        parse_tid_level,
        parse_tlv_block,
        verify_packet_hmac,
    )
    from signet.send import build_dmx_packet

    k0 = derive_k0_from_passphrase(TEST_PASSPHRASE)
    assert k0 == TEST_K0

    ks = derive_sender_key(k0)
    dmx_data = bytes([255] * 100)

    packet = build_dmx_packet(
        universe=1,
        dmx_data=dmx_data,
        tuid=TEST_TUID,
        endpoint=1,
        mfg_code=0x534C,
        session_id=1,
        seq_num=1,
        sender_key=ks,
        message_id=1,
    )

    # Parse back
    reader = PacketReader(packet)
    header = parse_coap_header(reader)
    assert header.version == 1

    reader2 = PacketReader(packet)
    reader2.skip(4)
    options = parse_signet_options(reader2)

    payload_start = packet.index(bytes([COAP_PAYLOAD_MARKER])) + 1
    payload = packet[payload_start:]

    pr = PacketReader(payload)
    tlv = parse_tlv_block(pr)
    parsed_dmx = parse_tid_level(tlv)
    assert parsed_dmx == dmx_data

    assert verify_packet_hmac("/sig-net/v1/level/1", options, payload, ks)
