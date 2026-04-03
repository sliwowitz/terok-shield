# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the NFQUEUE netlink handler."""

from __future__ import annotations

import socket
import struct
from unittest import mock

import pytest

from terok_shield.netlink import NFA_HDR, NFGEN_HDR, NLMSG_HDR
from terok_shield.nfqueue import (
    _NFNL_SUBSYS_QUEUE,
    _NFQA_PACKET_HDR,
    _NFQA_PAYLOAD,
    _NFQNL_MSG_PACKET,
    _NFQNL_MSG_VERDICT,
    _NFQNL_PACKET_HDR,
    NF_ACCEPT,
    NF_DROP,
    NfqueueHandler,
    QueuedPacket,
    _build_verdict_msg,
)
from terok_shield.nft_constants import NFQUEUE_NUM

from ..testnet import TEST_IP1

# ── QueuedPacket ───────────────────────────────────────


class TestQueuedPacket:
    """QueuedPacket is a frozen dataclass with the expected fields."""

    def test_fields(self) -> None:
        """QueuedPacket stores packet_id, dest, port, proto."""
        pkt = QueuedPacket(packet_id=42, dest=TEST_IP1, port=443, proto=6)
        assert pkt.packet_id == 42
        assert pkt.dest == TEST_IP1
        assert pkt.port == 443
        assert pkt.proto == 6

    def test_frozen(self) -> None:
        """QueuedPacket is immutable."""
        pkt = QueuedPacket(packet_id=1, dest=TEST_IP1, port=80, proto=6)
        with pytest.raises(AttributeError):
            pkt.port = 8080  # type: ignore[misc]


# ── Message building ──────────────────────────────────


class TestVerdictMessage:
    """Verdict messages have the correct structure."""

    def test_verdict_msg_accept(self) -> None:
        """Accept verdict message is well-formed."""
        msg = _build_verdict_msg(NFQUEUE_NUM, 42, NF_ACCEPT)
        # Parse nlmsghdr
        assert len(msg) >= NLMSG_HDR.size
        nl_len, nl_type, _flags, _seq, _pid = NLMSG_HDR.unpack_from(msg, 0)
        assert nl_len == len(msg)
        subsys = (nl_type >> 8) & 0xFF
        msg_type = nl_type & 0xFF
        assert subsys == _NFNL_SUBSYS_QUEUE
        assert msg_type == _NFQNL_MSG_VERDICT

    def test_verdict_msg_drop(self) -> None:
        """Drop verdict message is well-formed."""
        msg = _build_verdict_msg(NFQUEUE_NUM, 99, NF_DROP)
        assert len(msg) >= NLMSG_HDR.size


# ── NfqueueHandler parsing ────────────────────────────


def _build_nfqueue_packet(packet_id: int, dest_ip: str, proto: int, dest_port: int) -> bytes:
    """Build a raw netlink message mimicking a NFQUEUE packet."""
    # Build packet header attribute: packet_id(4) + hw_protocol(2) + hook(1) + pad(1)
    pkt_hdr = _NFQNL_PACKET_HDR.pack(packet_id, 0x0800, 0)
    pkt_hdr_attr = NFA_HDR.pack(NFA_HDR.size + len(pkt_hdr), _NFQA_PACKET_HDR) + pkt_hdr
    # Pad to 4 bytes
    while len(pkt_hdr_attr) % 4:
        pkt_hdr_attr += b"\x00"

    # Build IP packet payload: minimal IPv4 with TCP dest port
    ip_parts = dest_ip.split(".")
    dest_bytes = bytes(int(p) for p in ip_parts)
    src_bytes = b"\x0a\x00\x00\x01"  # 10.0.0.1
    ip_header = bytearray(20)
    ip_header[0] = 0x45  # version=4, ihl=5
    ip_header[2:4] = struct.pack("!H", 40)  # total length
    ip_header[9] = proto
    ip_header[12:16] = src_bytes
    ip_header[16:20] = dest_bytes
    # TCP header (just dest port)
    transport = struct.pack("!HH", 12345, dest_port)
    raw_pkt = bytes(ip_header) + transport
    payload_attr = NFA_HDR.pack(NFA_HDR.size + len(raw_pkt), _NFQA_PAYLOAD) + raw_pkt
    while len(payload_attr) % 4:
        payload_attr += b"\x00"

    # Build nfgen header + attrs
    nfgen = NFGEN_HDR.pack(2, 0, socket.htons(NFQUEUE_NUM))
    attrs = pkt_hdr_attr + payload_attr
    payload = nfgen + attrs

    # Build nlmsghdr
    msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_PACKET
    nlmsg = NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), msg_type, 0, 0, 0) + payload
    return nlmsg


class TestNfqueueHandlerParsing:
    """NfqueueHandler._parse_messages() extracts QueuedPackets correctly."""

    def test_parse_single_packet(self) -> None:
        """A single NFQUEUE message is parsed into a QueuedPacket."""
        data = _build_nfqueue_packet(42, TEST_IP1, 6, 443)
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)

        packets = handler._parse_messages(data)

        assert len(packets) == 1
        assert packets[0].packet_id == 42
        assert packets[0].dest == TEST_IP1
        assert packets[0].port == 443
        assert packets[0].proto == 6

    def test_parse_empty_data(self) -> None:
        """Empty data returns no packets."""
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler._parse_messages(b"") == []

    def test_parse_truncated_data(self) -> None:
        """Truncated netlink message returns no packets."""
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler._parse_messages(b"\x01\x02") == []


# ── NfqueueHandler verdict ────────────────────────────


class TestNfqueueHandlerVerdict:
    """NfqueueHandler.verdict() sends the correct message."""

    def test_verdict_accept_sends_message(self) -> None:
        """verdict(accept=True) sends NF_ACCEPT message."""
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        handler.verdict(42, accept=True)
        sock.send.assert_called_once()
        msg = sock.send.call_args[0][0]
        assert len(msg) >= NLMSG_HDR.size

    def test_verdict_drop_sends_message(self) -> None:
        """verdict(accept=False) sends NF_DROP message."""
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        handler.verdict(99, accept=False)
        sock.send.assert_called_once()


# ── NfqueueHandler.create() failure ───────────────────


class TestNfqueueHandlerCreate:
    """NfqueueHandler.create() degrades gracefully."""

    def test_returns_none_on_oserror(self) -> None:
        """create() returns None when AF_NETLINK is unavailable."""
        with mock.patch("socket.socket", side_effect=OSError("no netlink")):
            assert NfqueueHandler.create() is None

    def test_returns_none_on_bind_error(self) -> None:
        """create() returns None when NFQUEUE bind is rejected."""
        mock_sock = mock.MagicMock(spec=socket.socket)
        # Simulate kernel rejection: NLMSG_ERROR with errno -1
        ack_payload = struct.pack("=i", -1)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack

        with mock.patch("socket.socket", return_value=mock_sock):
            result = NfqueueHandler.create()

        assert result is None
        mock_sock.close.assert_called()
