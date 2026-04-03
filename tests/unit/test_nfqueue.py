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
    _build_config_cmd,
    _build_config_params,
    _build_verdict_msg,
    _check_ack,
    _extract_packet_id,
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
        ack_payload = struct.pack("=i", -1)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack

        with mock.patch("socket.socket", return_value=mock_sock):
            result = NfqueueHandler.create()

        assert result is None
        mock_sock.close.assert_called()

    def test_returns_none_on_params_error(self) -> None:
        """create() returns None when copy-mode config is rejected."""
        mock_sock = mock.MagicMock(spec=socket.socket)
        ok_ack = NLMSG_HDR.pack(NLMSG_HDR.size + 4, 2, 0, 0, 0) + struct.pack("=i", 0)
        err_ack = NLMSG_HDR.pack(NLMSG_HDR.size + 4, 2, 0, 0, 0) + struct.pack("=i", -1)
        mock_sock.recv.side_effect = [ok_ack, err_ack]

        with mock.patch("socket.socket", return_value=mock_sock):
            result = NfqueueHandler.create()

        assert result is None
        mock_sock.close.assert_called()

    def test_success_returns_handler(self) -> None:
        """create() returns NfqueueHandler when handshake succeeds."""
        mock_sock = mock.MagicMock(spec=socket.socket)
        ok_ack = NLMSG_HDR.pack(NLMSG_HDR.size + 4, 2, 0, 0, 0) + struct.pack("=i", 0)
        mock_sock.recv.return_value = ok_ack

        with mock.patch("socket.socket", return_value=mock_sock):
            handler = NfqueueHandler.create()

        assert handler is not None
        assert isinstance(handler, NfqueueHandler)


# ── NfqueueHandler.poll() ─────────────────────────────


class TestNfqueueHandlerPoll:
    """NfqueueHandler.poll() reads from the socket."""

    def test_poll_returns_packets(self) -> None:
        """poll() reads data and returns parsed packets."""
        data = _build_nfqueue_packet(1, TEST_IP1, 6, 80)
        sock = mock.MagicMock(spec=socket.socket)
        sock.recv.side_effect = [data, OSError("done")]
        handler = NfqueueHandler(sock, NFQUEUE_NUM)

        pkts = handler.poll()

        assert len(pkts) == 1
        assert pkts[0].packet_id == 1

    def test_poll_empty_on_oserror(self) -> None:
        """poll() returns empty list when socket raises OSError."""
        sock = mock.MagicMock(spec=socket.socket)
        sock.recv.side_effect = OSError
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler.poll() == []

    def test_poll_empty_on_no_data(self) -> None:
        """poll() returns empty list when socket returns empty bytes."""
        sock = mock.MagicMock(spec=socket.socket)
        sock.recv.return_value = b""
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler.poll() == []


# ── NfqueueHandler.fileno / close ──────────────────────


class TestNfqueueHandlerLifecycle:
    """fileno() and close() delegate to the socket."""

    def test_fileno(self) -> None:
        """fileno() returns the socket fd."""
        sock = mock.MagicMock(spec=socket.socket)
        sock.fileno.return_value = 7
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        assert handler.fileno() == 7

    def test_close(self) -> None:
        """close() closes the socket."""
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        handler.close()
        sock.close.assert_called_once()


# ── Verdict OSError path ───────────────────────────────


class TestVerdictOSError:
    """verdict() handles send failures gracefully."""

    def test_verdict_oserror_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """OSError during verdict send is logged, not raised."""
        import logging

        sock = mock.MagicMock(spec=socket.socket)
        sock.send.side_effect = OSError("send failed")
        handler = NfqueueHandler(sock, NFQUEUE_NUM)

        with caplog.at_level(logging.WARNING):
            handler.verdict(42, accept=True)

        assert "Failed to send verdict" in caplog.text


# ── Unparseable packet auto-drop ───────────────────────


class TestUnparseablePacketAutoDrop:
    """Unparseable packets with valid packet_id get auto-dropped."""

    def test_unparseable_payload_issues_drop(self) -> None:
        """Packet with header but no valid IP payload gets NF_DROP."""
        # Build a message with a valid packet header but garbage payload
        pkt_hdr = _NFQNL_PACKET_HDR.pack(99, 0x0800, 0)
        pkt_hdr_attr = NFA_HDR.pack(NFA_HDR.size + len(pkt_hdr), _NFQA_PACKET_HDR) + pkt_hdr
        while len(pkt_hdr_attr) % 4:
            pkt_hdr_attr += b"\x00"
        # Garbage payload (not a valid IP packet)
        garbage = b"\xff" * 4
        payload_attr = NFA_HDR.pack(NFA_HDR.size + len(garbage), _NFQA_PAYLOAD) + garbage
        while len(payload_attr) % 4:
            payload_attr += b"\x00"

        nfgen = NFGEN_HDR.pack(2, 0, socket.htons(NFQUEUE_NUM))
        attrs = pkt_hdr_attr + payload_attr
        payload = nfgen + attrs
        msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_PACKET
        nlmsg = NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), msg_type, 0, 0, 0) + payload

        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        packets = handler._parse_messages(nlmsg)

        # No parseable packets returned, but verdict was issued
        assert packets == []
        sock.send.assert_called_once()  # NF_DROP verdict sent


# ── _extract_packet_id ─────────────────────────────────


class TestExtractPacketId:
    """_extract_packet_id extracts just the ID from attrs."""

    def test_valid_header(self) -> None:
        """Extracts packet_id from a valid packet header."""
        pkt_hdr = _NFQNL_PACKET_HDR.pack(42, 0x0800, 0)
        attrs = {_NFQA_PACKET_HDR: pkt_hdr}
        assert _extract_packet_id(attrs) == 42

    def test_missing_header(self) -> None:
        """Returns None when packet header is missing."""
        assert _extract_packet_id({}) is None

    def test_truncated_header(self) -> None:
        """Returns None when packet header is too short."""
        assert _extract_packet_id({_NFQA_PACKET_HDR: b"\x00"}) is None


# ── _check_ack ─────────────────────────────────────────


class TestCheckAck:
    """_check_ack reads kernel ACK messages."""

    def test_success_ack(self) -> None:
        """Returns True on errno=0 ACK."""
        sock = mock.MagicMock(spec=socket.socket)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + 4, 2, 0, 0, 0) + struct.pack("=i", 0)
        sock.recv.return_value = ack
        assert _check_ack(sock) is True

    def test_error_ack(self) -> None:
        """Returns False on negative errno ACK."""
        sock = mock.MagicMock(spec=socket.socket)
        ack = NLMSG_HDR.pack(NLMSG_HDR.size + 4, 2, 0, 0, 0) + struct.pack("=i", -13)
        sock.recv.return_value = ack
        assert _check_ack(sock) is False

    def test_timeout_returns_false(self) -> None:
        """Returns False on socket timeout."""
        sock = mock.MagicMock(spec=socket.socket)
        sock.recv.side_effect = TimeoutError
        assert _check_ack(sock) is False

    def test_short_ack_treated_as_ok(self) -> None:
        """Short ACK (no errno field) treated as success."""
        sock = mock.MagicMock(spec=socket.socket)
        sock.recv.return_value = b"\x00" * 8  # too short for error field
        assert _check_ack(sock) is True


# ── Message builder coverage ───────────────────────────


class TestMessageBuilders:
    """Cover _build_config_cmd and _build_config_params."""

    def test_config_cmd_well_formed(self) -> None:
        """Config bind message starts with valid nlmsghdr."""
        msg = _build_config_cmd(NFQUEUE_NUM, 1)
        assert len(msg) >= NLMSG_HDR.size
        nl_len = NLMSG_HDR.unpack_from(msg, 0)[0]
        assert nl_len == len(msg)

    def test_config_params_well_formed(self) -> None:
        """Config params message starts with valid nlmsghdr."""
        msg = _build_config_params(NFQUEUE_NUM, copy_range=256)
        assert len(msg) >= NLMSG_HDR.size
        nl_len = NLMSG_HDR.unpack_from(msg, 0)[0]
        assert nl_len == len(msg)


# ── Edge cases for parse_messages ─────────────────────


class TestParseMessagesEdgeCases:
    """Cover parse_messages edge paths not hit by other tests."""

    def test_malformed_nl_len_breaks_loop(self) -> None:
        """Message with nl_len smaller than NLMSG_HDR.size triggers break."""
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        # nlmsghdr with nl_len = 4 (less than NLMSG_HDR.size=16)
        bad_msg = NLMSG_HDR.pack(4, 0, 0, 0, 0)
        assert handler._parse_messages(bad_msg) == []

    def test_nl_len_exceeds_data_breaks_loop(self) -> None:
        """Message claiming more bytes than available triggers break."""
        sock = mock.MagicMock(spec=socket.socket)
        handler = NfqueueHandler(sock, NFQUEUE_NUM)
        # nl_len says 1000 but data is only 16 bytes
        bad_msg = NLMSG_HDR.pack(1000, 0, 0, 0, 0)
        assert handler._parse_messages(bad_msg) == []


# ── _attrs_to_packet edge cases ───────────────────────


class TestAttrsToPacket:
    """Cover _attrs_to_packet returning None for missing packet_id."""

    def test_no_packet_header_returns_none(self) -> None:
        """Missing NFQA_PACKET_HDR → None."""
        from terok_shield.nfqueue import _attrs_to_packet

        assert _attrs_to_packet({}) is None

    def test_valid_header_no_payload_returns_none(self) -> None:
        """Packet header present but empty payload → None (no dest IP)."""
        from terok_shield.nfqueue import _attrs_to_packet

        pkt_hdr = _NFQNL_PACKET_HDR.pack(1, 0x0800, 0)
        attrs = {_NFQA_PACKET_HDR: pkt_hdr}
        # No NFQA_PAYLOAD → extract_ip_dest returns empty
        assert _attrs_to_packet(attrs) is None
