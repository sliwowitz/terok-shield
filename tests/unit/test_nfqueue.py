# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the NFQUEUE handler (nfqueue.py)."""

from __future__ import annotations

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from terok_shield.netlink import NFA_HDR, NFGEN_HDR, NLM_F_ACK, NLM_F_REQUEST, NLMSG_HDR
from terok_shield.nfqueue import (
    _NFNL_SUBSYS_QUEUE,
    _NFQA_PACKET_HDR,
    _NFQA_PAYLOAD,
    _NFQNL_CFG_CMD_BIND,
    _NFQNL_MSG_CONFIG,
    _NFQNL_MSG_PACKET,
    _NFQNL_MSG_VERDICT,
    _NFQNL_PACKET_HDR,
    NF_ACCEPT,
    NF_DROP,
    NfqueueHandler,
    QueuedPacket,
    _attrs_to_packet,
    _build_config_cmd,
    _build_config_params,
    _build_verdict_msg,
    _check_ack,
    _extract_packet_id,
)
from terok_shield.nft_constants import NFQUEUE_NUM

from ..testnet import TEST_IP1

# ── QueuedPacket ─────────────────────────────────────────


class TestQueuedPacket:
    """Tests for the QueuedPacket frozen dataclass."""

    def test_fields(self) -> None:
        """QueuedPacket stores all required fields."""
        pkt = QueuedPacket(packet_id=42, dest=TEST_IP1, port=443, proto=6)
        assert pkt.packet_id == 42
        assert pkt.dest == TEST_IP1
        assert pkt.port == 443
        assert pkt.proto == 6

    def test_frozen(self) -> None:
        """QueuedPacket is frozen (immutable)."""
        pkt = QueuedPacket(packet_id=1, dest=TEST_IP1, port=80, proto=6)
        with pytest.raises(AttributeError):
            pkt.packet_id = 2  # type: ignore[misc]


# ── _extract_packet_id ──────────────────────────────────


class TestExtractPacketId:
    """Tests for _extract_packet_id from NFQUEUE attributes."""

    def test_extracts_id(self) -> None:
        """Extracts packet_id from a valid NFQA_PACKET_HDR attribute."""
        hdr = _NFQNL_PACKET_HDR.pack(123, 0x0800, 3)
        attrs = {_NFQA_PACKET_HDR: hdr}
        assert _extract_packet_id(attrs) == 123

    def test_returns_none_on_missing_hdr(self) -> None:
        """Returns None when NFQA_PACKET_HDR is absent."""
        assert _extract_packet_id({}) is None

    def test_returns_none_on_short_hdr(self) -> None:
        """Returns None when NFQA_PACKET_HDR payload is too short."""
        assert _extract_packet_id({_NFQA_PACKET_HDR: b"\x00"}) is None


# ── _attrs_to_packet ────────────────────────────────────


class TestAttrsToPacket:
    """Tests for _attrs_to_packet conversion."""

    def test_valid_ipv4_tcp(self) -> None:
        """Converts valid NFQUEUE attributes with IPv4 TCP payload to QueuedPacket."""
        hdr = _NFQNL_PACKET_HDR.pack(7, 0x0800, 3)
        # Minimal IPv4 header: version=4, IHL=5, proto=TCP(6), dest=192.0.2.1
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version=4, IHL=5
        ip_header[9] = 6  # TCP
        ip_header[16:20] = socket.inet_aton(TEST_IP1)
        # TCP header: src_port=12345, dst_port=443
        transport = struct.pack("!HH", 12345, 443)
        attrs = {
            _NFQA_PACKET_HDR: hdr,
            _NFQA_PAYLOAD: bytes(ip_header) + transport,
        }
        pkt = _attrs_to_packet(attrs)
        assert pkt is not None
        assert pkt.packet_id == 7
        assert pkt.dest == TEST_IP1
        assert pkt.port == 443
        assert pkt.proto == 6

    def test_returns_none_without_packet_hdr(self) -> None:
        """Returns None when NFQA_PACKET_HDR is missing."""
        assert _attrs_to_packet({_NFQA_PAYLOAD: b"\x45" * 40}) is None

    def test_returns_none_on_empty_payload(self) -> None:
        """Returns None when payload is too short to parse."""
        hdr = _NFQNL_PACKET_HDR.pack(1, 0x0800, 3)
        assert _attrs_to_packet({_NFQA_PACKET_HDR: hdr}) is None


# ── Message builders ────────────────────────────────────


class TestMessageBuilders:
    """Tests for NFQUEUE netlink message construction."""

    def test_config_cmd_structure(self) -> None:
        """_build_config_cmd produces a valid netlink message with correct type."""
        msg = _build_config_cmd(NFQUEUE_NUM, _NFQNL_CFG_CMD_BIND)
        assert len(msg) >= NLMSG_HDR.size
        nl_len, nl_type, flags, _seq, _pid = NLMSG_HDR.unpack_from(msg, 0)
        assert nl_len == len(msg)
        assert nl_type == (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_CONFIG
        assert flags & NLM_F_REQUEST
        assert flags & NLM_F_ACK

    def test_config_params_structure(self) -> None:
        """_build_config_params produces a valid netlink message."""
        msg = _build_config_params(NFQUEUE_NUM, copy_range=256)
        assert len(msg) >= NLMSG_HDR.size
        nl_len, nl_type, flags, _seq, _pid = NLMSG_HDR.unpack_from(msg, 0)
        assert nl_len == len(msg)
        assert nl_type == (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_CONFIG

    def test_verdict_msg_structure(self) -> None:
        """_build_verdict_msg produces a valid netlink message with correct type."""
        msg = _build_verdict_msg(NFQUEUE_NUM, 42, NF_ACCEPT)
        assert len(msg) >= NLMSG_HDR.size
        nl_len, nl_type, flags, _seq, _pid = NLMSG_HDR.unpack_from(msg, 0)
        assert nl_len == len(msg)
        assert nl_type == (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_VERDICT
        assert flags & NLM_F_REQUEST

    def test_verdict_msg_contains_packet_id_and_verdict(self) -> None:
        """Verdict message payload contains the verdict code and packet ID."""
        msg = _build_verdict_msg(NFQUEUE_NUM, 99, NF_DROP)
        # After NLMSG_HDR + NFGEN_HDR + NFA_HDR, the payload has verdict(4) + packet_id(4)
        verdict_offset = NLMSG_HDR.size + NFGEN_HDR.size + NFA_HDR.size
        verdict_val, pkt_id = struct.unpack_from("!II", msg, verdict_offset)
        assert verdict_val == NF_DROP
        assert pkt_id == 99


# ── _check_ack ──────────────────────────────────────────


class TestCheckAck:
    """Tests for _check_ack netlink ACK verification."""

    def test_success_ack(self) -> None:
        """_check_ack returns True on error code 0 (success)."""
        ack_payload = struct.pack("=i", 0)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        sock = MagicMock()
        sock.recv.return_value = ack
        assert _check_ack(sock) is True

    def test_error_ack(self) -> None:
        """_check_ack returns False on negative error code."""
        ack_payload = struct.pack("=i", -1)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        sock = MagicMock()
        sock.recv.return_value = ack
        assert _check_ack(sock) is False

    def test_oserror_returns_false(self) -> None:
        """_check_ack returns False when recv raises OSError."""
        sock = MagicMock()
        sock.recv.side_effect = OSError("broken")
        assert _check_ack(sock) is False

    def test_short_ack_returns_true(self) -> None:
        """_check_ack returns True when ACK is too short to parse (benign)."""
        sock = MagicMock()
        sock.recv.return_value = b"\x00" * 4
        assert _check_ack(sock) is True


# ── NfqueueHandler ──────────────────────────────────────


class TestNfqueueHandler:
    """Tests for the NfqueueHandler class."""

    def test_create_returns_none_on_oserror(self) -> None:
        """create() returns None when socket creation fails."""
        with patch("terok_shield.nfqueue.socket.socket", side_effect=OSError("no netlink")):
            assert NfqueueHandler.create() is None

    def test_create_returns_none_on_bind_ack_failure(self) -> None:
        """create() returns None when bind ACK indicates failure."""
        mock_sock = MagicMock()
        # Bind ACK with negative error code
        ack_payload = struct.pack("=i", -1)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack
        with patch("terok_shield.nfqueue.socket.socket", return_value=mock_sock):
            handler = NfqueueHandler.create()
        assert handler is None
        mock_sock.close.assert_called()

    def test_create_returns_handler_on_success(self) -> None:
        """create() returns an NfqueueHandler on successful handshake."""
        mock_sock = MagicMock()
        # Success ACK (error code 0)
        ack_payload = struct.pack("=i", 0)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack
        with patch("terok_shield.nfqueue.socket.socket", return_value=mock_sock):
            handler = NfqueueHandler.create()
        assert handler is not None
        mock_sock.setblocking.assert_called_with(False)

    def test_fileno_delegates(self) -> None:
        """fileno() returns the socket's file descriptor."""
        mock_sock = MagicMock()
        mock_sock.fileno.return_value = 42
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        assert handler.fileno() == 42

    def test_close_delegates(self) -> None:
        """close() closes the underlying socket."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        handler.close()
        mock_sock.close.assert_called_once()

    def test_poll_returns_empty_on_oserror(self) -> None:
        """poll() returns empty list when recv raises OSError."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("would block")
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        assert handler.poll() == []

    def test_poll_returns_empty_on_empty_data(self) -> None:
        """poll() returns empty list on empty recv data."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        assert handler.poll() == []

    def test_verdict_sends_message(self) -> None:
        """verdict() sends a verdict message to the socket."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        handler.verdict(42, accept=True)
        mock_sock.send.assert_called_once()
        msg = mock_sock.send.call_args[0][0]
        assert len(msg) >= NLMSG_HDR.size

    def test_verdict_accept_uses_nf_accept(self) -> None:
        """verdict(accept=True) uses NF_ACCEPT code in the message."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        handler.verdict(7, accept=True)
        msg = mock_sock.send.call_args[0][0]
        verdict_offset = NLMSG_HDR.size + NFGEN_HDR.size + NFA_HDR.size
        verdict_val, _ = struct.unpack_from("!II", msg, verdict_offset)
        assert verdict_val == NF_ACCEPT

    def test_verdict_drop_uses_nf_drop(self) -> None:
        """verdict(accept=False) uses NF_DROP code in the message."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        handler.verdict(7, accept=False)
        msg = mock_sock.send.call_args[0][0]
        verdict_offset = NLMSG_HDR.size + NFGEN_HDR.size + NFA_HDR.size
        verdict_val, _ = struct.unpack_from("!II", msg, verdict_offset)
        assert verdict_val == NF_DROP

    def test_verdict_oserror_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """verdict() logs a warning on OSError."""
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        handler.verdict(1, accept=True)
        assert "Failed to send verdict" in caplog.text


# ── _parse_messages / _handle_one_message ──────────────


class TestParseMessages:
    """Tests for message parsing in NfqueueHandler."""

    @staticmethod
    def _build_nfqueue_msg(packet_id: int, dest_ip: str, port: int = 443) -> bytes:
        """Build a minimal NFQUEUE packet message for testing."""
        # NFQA_PACKET_HDR attribute
        pkt_hdr = _NFQNL_PACKET_HDR.pack(packet_id, 0x0800, 3)
        attr1 = NFA_HDR.pack(NFA_HDR.size + len(pkt_hdr), _NFQA_PACKET_HDR) + pkt_hdr
        # Pad to 4 bytes
        while len(attr1) % 4:
            attr1 += b"\x00"

        # NFQA_PAYLOAD attribute: IPv4 TCP packet
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version=4, IHL=5
        ip_header[9] = 6  # TCP
        ip_header[16:20] = socket.inet_aton(dest_ip)
        transport = struct.pack("!HH", 12345, port)
        payload = bytes(ip_header) + transport
        attr2 = NFA_HDR.pack(NFA_HDR.size + len(payload), _NFQA_PAYLOAD) + payload

        # nfgenmsg + attributes
        nfgen = NFGEN_HDR.pack(2, 0, socket.htons(NFQUEUE_NUM))
        body = nfgen + attr1 + attr2

        # netlink header
        msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_PACKET
        return NLMSG_HDR.pack(NLMSG_HDR.size + len(body), msg_type, 0, 0, 0) + body

    def test_parse_valid_packet(self) -> None:
        """_parse_messages extracts a QueuedPacket from a valid NFQUEUE message."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        data = self._build_nfqueue_msg(42, TEST_IP1, 443)
        packets = handler._parse_messages(data)
        assert len(packets) == 1
        assert packets[0].packet_id == 42
        assert packets[0].dest == TEST_IP1
        assert packets[0].port == 443

    def test_ignores_non_queue_messages(self) -> None:
        """_parse_messages ignores messages with wrong subsystem."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        # Build a message with wrong subsystem (ulog instead of queue)
        nfgen = NFGEN_HDR.pack(2, 0, 0)
        body = nfgen
        msg_type = (4 << 8) | 0  # ULOG subsystem
        data = NLMSG_HDR.pack(NLMSG_HDR.size + len(body), msg_type, 0, 0, 0) + body
        assert handler._parse_messages(data) == []

    def test_handle_one_message_drops_unparseable(self) -> None:
        """_handle_one_message issues a drop verdict for unparseable packets."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)

        # Build a message with a packet_hdr but no payload (unparseable)
        pkt_hdr = _NFQNL_PACKET_HDR.pack(99, 0x0800, 3)
        attr = NFA_HDR.pack(NFA_HDR.size + len(pkt_hdr), _NFQA_PACKET_HDR) + pkt_hdr
        nfgen = NFGEN_HDR.pack(2, 0, socket.htons(NFQUEUE_NUM))
        body = nfgen + attr
        msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_PACKET
        data = NLMSG_HDR.pack(NLMSG_HDR.size + len(body), msg_type, 0, 0, 0) + body

        result = handler._handle_one_message(data, 0, len(data), msg_type)
        assert result is None
        # Should have issued a drop verdict for packet 99
        mock_sock.send.assert_called_once()

    def test_short_message_ignored(self) -> None:
        """_parse_messages handles truncated data gracefully."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        # Too short for even a netlink header
        assert handler._parse_messages(b"\x00" * 4) == []

    def test_bad_length_stops_parsing(self) -> None:
        """_parse_messages stops when nl_len would read past data boundary."""
        mock_sock = MagicMock()
        handler = NfqueueHandler(mock_sock, NFQUEUE_NUM)
        # nl_len claims 1000 bytes but data is only 16
        data = NLMSG_HDR.pack(1000, 0, 0, 0, 0)
        assert handler._parse_messages(data) == []
