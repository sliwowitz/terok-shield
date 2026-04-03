# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared netlink and IP packet parsing utilities.

Stdlib-only module used by both :mod:`watch` (NFLOG) and :mod:`nfqueue`
(NFQUEUE) to extract destination address, protocol, and port from raw
IP packets delivered via ``AF_NETLINK``.
"""

import socket
import struct

# ── IP protocol numbers ────────────────────────────────

IPPROTO_TCP = 6
IPPROTO_UDP = 17

# ── Netlink / nfnetlink struct formats ─────────────────

# Netlink message header: length(4) + type(2) + flags(2) + seq(4) + pid(4)
NLMSG_HDR = struct.Struct("=IHHII")
# nfgenmsg: family(1) + version(1) + res_id(2)
NFGEN_HDR = struct.Struct("=BBH")
# nflog/nfqueue TLV attribute header: length(2) + type(2)
NFA_HDR = struct.Struct("=HH")

NLM_F_REQUEST = 1
NLM_F_ACK = 4
AF_INET = 2

# Netlink netfilter protocol number
NETLINK_NETFILTER = 12


# ── Packet parsing ─────────────────────────────────────


def extract_ip_dest(payload: bytes) -> tuple[str, int, int]:
    """Extract destination IP, protocol, and port from a raw IP packet.

    Handles both IPv4 and IPv6 headers as delivered by nflog/nfqueue
    in ``inet`` family tables.

    Returns:
        Tuple of ``(dest_ip, protocol_number, dest_port)``.
        Returns ``("", 0, 0)`` if the packet cannot be parsed.
    """
    if len(payload) < 20:
        return ("", 0, 0)
    version = (payload[0] >> 4) & 0xF
    if version == 6:
        return _extract_ipv6_dest(payload)
    if version != 4:
        return ("", 0, 0)
    ihl = (payload[0] & 0xF) * 4
    if ihl < 20:
        return ("", 0, 0)
    proto = payload[9]
    dest = socket.inet_ntop(socket.AF_INET, payload[16:20])
    port = 0
    if proto in (IPPROTO_TCP, IPPROTO_UDP) and len(payload) >= ihl + 4:
        port = struct.unpack_from("!H", payload, ihl + 2)[0]  # dest port
    return (dest, proto, port)


def _extract_ipv6_dest(payload: bytes) -> tuple[str, int, int]:
    """Extract destination from an IPv6 packet (40-byte header minimum)."""
    if len(payload) < 40:
        return ("", 0, 0)
    dest = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    proto = payload[6]  # Next Header
    port = 0
    if proto in (IPPROTO_TCP, IPPROTO_UDP) and len(payload) >= 44:
        port = struct.unpack_from("!H", payload, 42)[0]  # dest port
    return (dest, proto, port)


def parse_nflog_attrs(data: bytes) -> dict[int, bytes]:
    """Parse TLV attributes from an nflog/nfqueue packet message.

    Returns a dict mapping attribute type to raw attribute value bytes.
    Attribute types are masked to strip nested/byteorder flags.
    """
    attrs: dict[int, bytes] = {}
    offset = 0
    while offset + NFA_HDR.size <= len(data):
        nfa_len, nfa_type = NFA_HDR.unpack_from(data, offset)
        if nfa_len < NFA_HDR.size:
            break
        nfa_type &= 0x7FFF
        value = data[offset + NFA_HDR.size : offset + nfa_len]
        attrs[nfa_type] = value
        # Attributes are 4-byte aligned
        offset += (nfa_len + 3) & ~3
    return attrs
