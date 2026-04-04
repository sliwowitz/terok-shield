# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the shared netlink module (netlink.py)."""

from __future__ import annotations

import socket
import struct

from terok_shield.netlink import (
    AF_INET,
    IPPROTO_TCP,
    IPPROTO_UDP,
    NFA_HDR,
    NFGEN_HDR,
    NLM_F_ACK,
    NLM_F_REQUEST,
    NLMSG_HDR,
    extract_ip_dest,
    parse_nflog_attrs,
)

from ..testnet import TEST_IP1

# ── Struct sizes ────────────────────────────────────────


class TestStructSizes:
    """Verify netlink struct sizes match kernel ABI."""

    def test_nlmsg_hdr_size(self) -> None:
        """NLMSG_HDR is 16 bytes (4+2+2+4+4)."""
        assert NLMSG_HDR.size == 16

    def test_nfgen_hdr_size(self) -> None:
        """NFGEN_HDR is 4 bytes (1+1+2)."""
        assert NFGEN_HDR.size == 4

    def test_nfa_hdr_size(self) -> None:
        """NFA_HDR is 4 bytes (2+2)."""
        assert NFA_HDR.size == 4


# ── Constants ───────────────────────────────────────────


class TestConstants:
    """Verify netlink constants match expected kernel values."""

    def test_af_inet(self) -> None:
        """AF_INET is 2 on all Linux platforms."""
        assert AF_INET == 2

    def test_nlm_flags(self) -> None:
        """NLM_F_REQUEST and NLM_F_ACK match kernel definitions."""
        assert NLM_F_REQUEST == 1
        assert NLM_F_ACK == 4

    def test_ip_protocol_numbers(self) -> None:
        """IP protocol numbers match IANA assignments."""
        assert IPPROTO_TCP == 6
        assert IPPROTO_UDP == 17


# ── parse_nflog_attrs ──────────────────────────────────


class TestParseNflogAttrs:
    """Tests for TLV attribute parsing."""

    def test_empty_data(self) -> None:
        """Empty data returns empty dict."""
        assert parse_nflog_attrs(b"") == {}

    def test_single_attr(self) -> None:
        """Single TLV attribute is correctly parsed."""
        value = b"HELLO"
        attr = NFA_HDR.pack(NFA_HDR.size + len(value), 10) + value
        result = parse_nflog_attrs(attr)
        assert result[10] == value

    def test_multiple_attrs(self) -> None:
        """Multiple TLV attributes are correctly parsed with 4-byte alignment."""
        val1 = b"AB"
        val2 = b"CDEF"
        attr1 = NFA_HDR.pack(NFA_HDR.size + len(val1), 1) + val1
        # Pad attr1 to 4 bytes
        attr1 += b"\x00" * (4 - len(attr1) % 4) if len(attr1) % 4 else b""
        attr2 = NFA_HDR.pack(NFA_HDR.size + len(val2), 2) + val2
        result = parse_nflog_attrs(attr1 + attr2)
        assert result[1] == val1
        assert result[2] == val2

    def test_short_attr_stops(self) -> None:
        """Attribute with nfa_len < NFA_HDR.size stops parsing."""
        data = NFA_HDR.pack(2, 1)  # nfa_len=2 < NFA_HDR.size=4
        assert parse_nflog_attrs(data) == {}

    def test_masks_nested_flag(self) -> None:
        """Type field is masked to strip nested/byteorder flags (0x7FFF)."""
        value = b"X"
        attr_type = 0x8001  # nested flag set + type 1
        attr = NFA_HDR.pack(NFA_HDR.size + len(value), attr_type) + value
        result = parse_nflog_attrs(attr)
        assert 1 in result


# ── extract_ip_dest ────────────────────────────────────


class TestExtractIpDest:
    """Tests for IP packet destination extraction."""

    def test_ipv4_tcp(self) -> None:
        """Extracts dest IP, protocol, and port from IPv4 TCP packet."""
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version=4, IHL=5
        ip_header[9] = IPPROTO_TCP
        ip_header[16:20] = socket.inet_aton(TEST_IP1)
        transport = struct.pack("!HH", 12345, 443)
        dest, proto, port = extract_ip_dest(bytes(ip_header) + transport)
        assert dest == TEST_IP1
        assert proto == IPPROTO_TCP
        assert port == 443

    def test_ipv4_udp(self) -> None:
        """Extracts dest port from IPv4 UDP packet."""
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[9] = IPPROTO_UDP
        ip_header[16:20] = socket.inet_aton(TEST_IP1)
        transport = struct.pack("!HH", 12345, 53)
        dest, proto, port = extract_ip_dest(bytes(ip_header) + transport)
        assert dest == TEST_IP1
        assert proto == IPPROTO_UDP
        assert port == 53

    def test_ipv6_tcp(self) -> None:
        """Extracts dest IP and port from IPv6 TCP packet."""
        ip6_header = bytearray(40)
        ip6_header[0] = 0x60  # version=6
        ip6_header[6] = IPPROTO_TCP  # Next Header
        ip6_header[24:40] = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        transport = struct.pack("!HH", 12345, 8080)
        dest, proto, port = extract_ip_dest(bytes(ip6_header) + transport)
        assert dest == "2001:db8::1"
        assert proto == IPPROTO_TCP
        assert port == 8080

    def test_too_short(self) -> None:
        """Returns empty tuple for packets shorter than 20 bytes."""
        assert extract_ip_dest(b"\x45" * 10) == ("", 0, 0)

    def test_bad_ihl(self) -> None:
        """Returns empty tuple for IPv4 with IHL < 5 (20 bytes)."""
        pkt = bytearray(20)
        pkt[0] = 0x41  # version=4, IHL=1 (invalid)
        assert extract_ip_dest(bytes(pkt)) == ("", 0, 0)

    def test_unknown_version(self) -> None:
        """Returns empty tuple for non-IPv4/IPv6 packets."""
        pkt = bytearray(20)
        pkt[0] = 0x30  # version=3
        assert extract_ip_dest(bytes(pkt)) == ("", 0, 0)

    def test_non_tcp_udp_no_port(self) -> None:
        """Non-TCP/UDP protocol returns port=0."""
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[9] = 1  # ICMP
        ip_header[16:20] = socket.inet_aton(TEST_IP1)
        dest, proto, port = extract_ip_dest(bytes(ip_header))
        assert dest == TEST_IP1
        assert proto == 1
        assert port == 0
