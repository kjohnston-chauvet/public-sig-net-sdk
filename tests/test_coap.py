"""Tests for signet.coap — ports C++ self-tests 8-10."""

from __future__ import annotations

from signet.coap import build_coap_header, build_uri_path_options, build_uri_string


# ---- C++ Self-Test 8: CoAP Header Construction ----

def test_header_construction():
    header = build_coap_header(1)
    assert len(header) == 4
    # Version=1, Type=NON(1), TKL=0 → byte0 = 0x50
    assert header[0] == 0x50
    # Code = POST (0x02)
    assert header[1] == 0x02


# ---- C++ Self-Test 9: URI Path Encoding ----

def test_uri_path_encoding():
    options = build_uri_path_options(517)
    assert len(options) > 0
    # Should contain "sig-net", "v1", "level", "517" as option values


# ---- C++ Self-Test 10: Build URI String ----

def test_build_uri_string():
    uri = build_uri_string(517)
    assert uri == "/sig-net/v1/level/517"


# ---- Additional: URI edge cases ----

def test_uri_string_universe_1():
    assert build_uri_string(1) == "/sig-net/v1/level/1"


def test_uri_string_universe_max():
    assert build_uri_string(63999) == "/sig-net/v1/level/63999"


def test_header_message_id():
    header = build_coap_header(0x1234)
    # message_id in network byte order at bytes 2-3
    assert header[2] == 0x12
    assert header[3] == 0x34
