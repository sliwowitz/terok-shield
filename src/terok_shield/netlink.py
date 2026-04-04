# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared netlink struct definitions and IP packet parsing.

Provides the low-level netlink message structs (``NLMSG_HDR``, ``NFGEN_HDR``,
``NFA_HDR``) and packet-parsing helpers (``parse_nflog_attrs``,
``extract_ip_dest``) used by both the NFLOG watcher and the NFQUEUE handler.

These were originally defined in ``watch.py`` and are now shared so that
``nfqueue.py`` can reuse them without importing the full watch module.
"""

import socket
import struct

# IP protocol numbers
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# Netlink message header: length(4) + type(2) + flags(2) + seq(4) + pid(4)
NLMSG_HDR = struct.Struct("=IHHII")
# nfgenmsg: family(1) + version(1) + res_id(2)
NFGEN_HDR = struct.Struct("=BBH")
# nflog TLV attribute header: length(2) + type(2)
NFA_HDR = struct.Struct("=HH")


def parse_nflog_attrs(data: bytes) -> dict[int, bytes]:
    """Parse TLV attributes from an NFLOG/NFQUEUE packet message.

    Returns a dict mapping attribute type to raw attribute value bytes.
    """
    attrs: dict[int, bytes] = {}
    offset = 0
    while offset + NFA_HDR.size <= len(data):
        nfa_len, nfa_type = NFA_HDR.unpack_from(data, offset)
        if nfa_len < NFA_HDR.size:
            break
        # Mask out the nested/byteorder flags from the type field
        nfa_type &= 0x7FFF
        value = data[offset + NFA_HDR.size : offset + nfa_len]
        attrs[nfa_type] = value
        # Attributes are 4-byte aligned
        offset += (nfa_len + 3) & ~3
    return attrs


def extract_ip_dest(payload: bytes) -> tuple[str, int, int]:
    """Extract destination IP, protocol, and port from a raw IP packet.

    Handles both IPv4 and IPv6 headers (NFLOG/NFQUEUE in inet tables
    delivers the IP header).  Returns ``("", 0, 0)`` if the packet
    cannot be parsed.
    """
    if len(payload) < 20:
        return ("", 0, 0)
    version = (payload[0] >> 4) & 0xF
    if version != 4:
        # IPv6 parsing: 40-byte header, dest at offset 24
        if version == 6 and len(payload) >= 40:
            dest_bytes = payload[24:40]
            dest = socket.inet_ntop(socket.AF_INET6, dest_bytes)
            proto = payload[6]  # Next Header
            port = 0
            if proto in (IPPROTO_TCP, IPPROTO_UDP) and len(payload) >= 44:
                port = struct.unpack_from("!H", payload, 42)[0]  # dest port
            return (dest, proto, port)
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
