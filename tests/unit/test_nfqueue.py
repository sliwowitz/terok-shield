# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the raw AF_NETLINK NFQUEUE handler."""

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
        """QueuedPacket is immutable."""
        pkt = QueuedPacket(packet_id=1, dest=TEST_IP1, port=80, proto=6)
        with pytest.raises(AttributeError):
            pkt.packet_id = 2  # type: ignore[misc]


# ── _extract_packet_id ───────────────────────────────────


class TestExtractPacketId:
    """Tests for _extract_packet_id."""

    def test_valid_header(self) -> None:
        """Extracts packet_id from a valid NFQA_PACKET_HDR attribute."""
        pkt_hdr = _NFQNL_PACKET_HDR.pack(42, 0x0800, 3)
        attrs = {_NFQA_PACKET_HDR: pkt_hdr}
        assert _extract_packet_id(attrs) == 42

    def test_missing_header(self) -> None:
        """Returns None when NFQA_PACKET_HDR is absent."""
        assert _extract_packet_id({}) is None

    def test_truncated_header(self) -> None:
        """Returns None when the header is too short."""
        attrs = {_NFQA_PACKET_HDR: b"\x00\x00"}
        assert _extract_packet_id(attrs) is None


# ── _attrs_to_packet ─────────────────────────────────────


class TestAttrsToPacket:
    """Tests for _attrs_to_packet."""

    def test_valid_attrs(self) -> None:
        """Converts valid NFQUEUE attributes into a QueuedPacket."""
        pkt_hdr = _NFQNL_PACKET_HDR.pack(7, 0x0800, 3)
        # Minimal IPv4 header: version=4, ihl=5, proto=6 (TCP), dest=TEST_IP1
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version=4, ihl=5
        ip_header[9] = 6  # proto TCP
        ip_header[16:20] = socket.inet_aton(TEST_IP1)
        # TCP header with dest port 443
        transport = struct.pack("!HH", 12345, 443) + b"\x00" * 16
        attrs = {
            _NFQA_PACKET_HDR: pkt_hdr,
            _NFQA_PAYLOAD: bytes(ip_header) + transport,
        }
        pkt = _attrs_to_packet(attrs)
        assert pkt is not None
        assert pkt.packet_id == 7
        assert pkt.dest == TEST_IP1
        assert pkt.port == 443
        assert pkt.proto == 6

    def test_no_packet_id(self) -> None:
        """Returns None when packet_id cannot be extracted."""
        attrs = {_NFQA_PAYLOAD: b"\x45" + b"\x00" * 19}
        assert _attrs_to_packet(attrs) is None

    def test_no_dest(self) -> None:
        """Returns None when IP dest cannot be parsed."""
        pkt_hdr = _NFQNL_PACKET_HDR.pack(1, 0x0800, 3)
        attrs = {_NFQA_PACKET_HDR: pkt_hdr, _NFQA_PAYLOAD: b"\x00" * 5}
        assert _attrs_to_packet(attrs) is None


# ── Message builders ─────────────────────────────────────


class TestBuildConfigCmd:
    """Tests for _build_config_cmd."""

    def test_returns_bytes(self) -> None:
        """_build_config_cmd returns a valid netlink message."""
        msg = _build_config_cmd(NFQUEUE_NUM, 1)
        assert isinstance(msg, bytes)
        assert len(msg) >= NLMSG_HDR.size

    def test_nlmsg_type_has_queue_subsys(self) -> None:
        """The netlink message type embeds the QUEUE subsystem."""
        msg = _build_config_cmd(NFQUEUE_NUM, 1)
        _, nl_type, _, _, _ = NLMSG_HDR.unpack_from(msg, 0)
        subsys = (nl_type >> 8) & 0xFF
        assert subsys == _NFNL_SUBSYS_QUEUE


class TestBuildConfigParams:
    """Tests for _build_config_params."""

    def test_returns_bytes(self) -> None:
        """_build_config_params returns a valid netlink message."""
        msg = _build_config_params(NFQUEUE_NUM)
        assert isinstance(msg, bytes)
        assert len(msg) >= NLMSG_HDR.size


class TestBuildVerdictMsg:
    """Tests for _build_verdict_msg."""

    def test_accept_verdict(self) -> None:
        """_build_verdict_msg builds a valid accept verdict."""
        msg = _build_verdict_msg(NFQUEUE_NUM, packet_id=42, verdict=NF_ACCEPT)
        assert isinstance(msg, bytes)
        assert len(msg) >= NLMSG_HDR.size

    def test_drop_verdict(self) -> None:
        """_build_verdict_msg builds a valid drop verdict."""
        msg = _build_verdict_msg(NFQUEUE_NUM, packet_id=42, verdict=NF_DROP)
        assert isinstance(msg, bytes)


# ── _check_ack ───────────────────────────────────────────


class TestCheckAck:
    """Tests for _check_ack."""

    def test_success_ack(self) -> None:
        """Returns True when the kernel sends error code 0 (success)."""
        sock = mock.MagicMock()
        ack_payload = struct.pack("=i", 0)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        sock.recv.return_value = ack
        assert _check_ack(sock) is True

    def test_error_ack(self) -> None:
        """Returns False when the kernel sends a negative error code."""
        sock = mock.MagicMock()
        ack_payload = struct.pack("=i", -1)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        sock.recv.return_value = ack
        assert _check_ack(sock) is False

    def test_recv_oserror(self) -> None:
        """Returns False when recv raises OSError."""
        sock = mock.MagicMock()
        sock.recv.side_effect = OSError("broken")
        assert _check_ack(sock) is False

    def test_short_ack(self) -> None:
        """Returns True for a short ACK (no error field to read)."""
        sock = mock.MagicMock()
        sock.recv.return_value = b"\x00" * 4
        assert _check_ack(sock) is True


# ── NfqueueHandler.create ────────────────────────────────


class TestNfqueueHandlerCreate:
    """Tests for NfqueueHandler.create class method."""

    def test_returns_none_on_oserror(self) -> None:
        """Returns None when socket creation raises OSError."""
        with mock.patch("terok_shield.nfqueue.socket.socket", side_effect=OSError):
            assert NfqueueHandler.create() is None

    def test_returns_none_on_bind_nack(self) -> None:
        """Returns None when the bind config command is rejected."""
        mock_sock = mock.MagicMock()
        ack_payload = struct.pack("=i", -1)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack
        with mock.patch("terok_shield.nfqueue.socket.socket", return_value=mock_sock):
            result = NfqueueHandler.create()
        assert result is None
        mock_sock.close.assert_called()

    def test_returns_handler_on_success(self) -> None:
        """Returns an NfqueueHandler when bind + params ACKs succeed."""
        mock_sock = mock.MagicMock()
        ack_payload = struct.pack("=i", 0)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack
        with mock.patch("terok_shield.nfqueue.socket.socket", return_value=mock_sock):
            result = NfqueueHandler.create()
        assert isinstance(result, NfqueueHandler)
        mock_sock.setblocking.assert_called_with(False)


# ── NfqueueHandler.verdict ───────────────────────────────


class TestNfqueueHandlerVerdict:
    """Tests for NfqueueHandler.verdict."""

    def test_accept_sends_message(self) -> None:
        """verdict(accept=True) sends a netlink message."""
        sock = mock.MagicMock()
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        handler.verdict(42, accept=True)
        sock.send.assert_called_once()
        msg = sock.send.call_args[0][0]
        assert isinstance(msg, bytes)

    def test_drop_sends_message(self) -> None:
        """verdict(accept=False) sends a netlink message."""
        sock = mock.MagicMock()
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        handler.verdict(42, accept=False)
        sock.send.assert_called_once()

    def test_oserror_logged(self) -> None:
        """OSError from send is logged but not raised."""
        sock = mock.MagicMock()
        sock.send.side_effect = OSError("broken")
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        handler.verdict(42, accept=True)  # should not raise


# ── NfqueueHandler.poll ──────────────────────────────────


class TestNfqueueHandlerPoll:
    """Tests for NfqueueHandler.poll."""

    def test_oserror_returns_empty(self) -> None:
        """OSError from recv returns an empty list."""
        sock = mock.MagicMock()
        sock.recv.side_effect = OSError("would block")
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler.poll() == []

    def test_empty_data_returns_empty(self) -> None:
        """Empty recv data returns an empty list."""
        sock = mock.MagicMock()
        sock.recv.return_value = b""
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler.poll() == []


# ── NfqueueHandler._handle_one_message ───────────────────


class TestHandleOneMessage:
    """Tests for NfqueueHandler._handle_one_message."""

    def _build_nfqueue_msg(self, packet_id: int, ip_dest: str, port: int = 443) -> bytes:
        """Build a fake NFQUEUE netlink message with embedded IP packet."""
        # Build NFQA_PACKET_HDR attribute
        pkt_hdr_data = _NFQNL_PACKET_HDR.pack(packet_id, 0x0800, 3)
        pkt_hdr_attr = NFA_HDR.pack(NFA_HDR.size + len(pkt_hdr_data), _NFQA_PACKET_HDR)
        pkt_hdr_attr += pkt_hdr_data
        # Pad to 4-byte alignment
        while len(pkt_hdr_attr) % 4:
            pkt_hdr_attr += b"\x00"

        # Build IP payload
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[9] = 6  # TCP
        ip_header[16:20] = socket.inet_aton(ip_dest)
        transport = struct.pack("!HH", 12345, port) + b"\x00" * 16
        payload_data = bytes(ip_header) + transport
        payload_attr = NFA_HDR.pack(NFA_HDR.size + len(payload_data), _NFQA_PAYLOAD)
        payload_attr += payload_data
        while len(payload_attr) % 4:
            payload_attr += b"\x00"

        attrs = pkt_hdr_attr + payload_attr
        nfgen = NFGEN_HDR.pack(2, 0, socket.htons(NFQUEUE_NUM))
        msg_payload = nfgen + attrs
        msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_PACKET
        nlmsg = NLMSG_HDR.pack(NLMSG_HDR.size + len(msg_payload), msg_type, 0, 0, 0) + msg_payload
        return nlmsg

    def test_parses_valid_packet(self) -> None:
        """A valid NFQUEUE message is parsed into a QueuedPacket."""
        sock = mock.MagicMock()
        sock.recv.return_value = self._build_nfqueue_msg(42, TEST_IP1)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        packets = handler.poll()
        assert len(packets) == 1
        assert packets[0].packet_id == 42
        assert packets[0].dest == TEST_IP1
        assert packets[0].port == 443

    def test_wrong_subsystem_ignored(self) -> None:
        """Messages from wrong subsystem are ignored."""
        sock = mock.MagicMock()
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        # Build a message with wrong subsystem (ULOG=4 instead of QUEUE=3)
        nfgen = NFGEN_HDR.pack(2, 0, 0)
        payload = nfgen
        msg_type = (4 << 8) | 0  # subsys=4, msg=0
        nlmsg = NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), msg_type, 0, 0, 0) + payload
        result = handler._handle_one_message(nlmsg, 0, len(nlmsg), msg_type)
        assert result is None

    def test_unparseable_packet_auto_dropped(self) -> None:
        """Unparseable payload triggers auto-drop verdict."""
        sock = mock.MagicMock()
        handler = NfqueueHandler(sock, NFQUEUE_NUM)

        # Build a packet with valid header but unparseable payload
        pkt_hdr_data = _NFQNL_PACKET_HDR.pack(99, 0x0800, 3)
        pkt_hdr_attr = NFA_HDR.pack(NFA_HDR.size + len(pkt_hdr_data), _NFQA_PACKET_HDR)
        pkt_hdr_attr += pkt_hdr_data
        while len(pkt_hdr_attr) % 4:
            pkt_hdr_attr += b"\x00"

        # Truncated IP payload (< 20 bytes)
        short_payload = b"\x45" + b"\x00" * 10
        payload_attr = NFA_HDR.pack(NFA_HDR.size + len(short_payload), _NFQA_PAYLOAD)
        payload_attr += short_payload

        attrs = pkt_hdr_attr + payload_attr
        nfgen = NFGEN_HDR.pack(2, 0, socket.htons(NFQUEUE_NUM))
        msg_payload = nfgen + attrs
        msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_PACKET
        nlmsg = NLMSG_HDR.pack(NLMSG_HDR.size + len(msg_payload), msg_type, 0, 0, 0) + msg_payload

        result = handler._handle_one_message(nlmsg, 0, len(nlmsg), msg_type)
        assert result is None
        # Should have issued a drop verdict for the unparseable packet
        sock.send.assert_called_once()


# ── NfqueueHandler lifecycle ─────────────────────────────


class TestNfqueueHandlerLifecycle:
    """Tests for NfqueueHandler fileno and close."""

    def test_fileno(self) -> None:
        """fileno() delegates to the underlying socket."""
        sock = mock.MagicMock()
        sock.fileno.return_value = 7
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler.fileno() == 7

    def test_close(self) -> None:
        """close() closes the underlying socket."""
        sock = mock.MagicMock()
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        handler.close()
        sock.close.assert_called_once()
