# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Raw AF_NETLINK NFQUEUE handler for interactive packet queuing.

Provides a pure-Python NFQUEUE subscriber that binds to a kernel queue,
receives queued packets, and issues accept/drop verdicts — all via raw
netlink without external C libraries.

Used by the NFQUEUE interactive tier when the ``nfnetlink_queue`` kernel
module is available.  Falls back to the NFLOG tier otherwise.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass

from .netlink import (
    NFA_HDR,
    NFGEN_HDR,
    NLM_F_ACK,
    NLM_F_REQUEST,
    NLMSG_HDR,
    extract_ip_dest,
    parse_nflog_attrs,
)
from .nft_constants import NFQUEUE_NUM

logger = logging.getLogger(__name__)

# ── Netlink constants (linux/netfilter/nfnetlink_queue.h) ─

_NETLINK_NETFILTER = 12

NF_ACCEPT = 1
NF_DROP = 0

_NFNL_SUBSYS_QUEUE = 3
_NFQNL_MSG_PACKET = 0
_NFQNL_MSG_VERDICT = 1
_NFQNL_MSG_CONFIG = 2

_NFQNL_CFG_CMD_BIND = 1
_NFQA_CFG_CMD = 1
_NFQA_CFG_PARAMS = 5
_NFQA_PACKET_HDR = 1
_NFQA_VERDICT_HDR = 3
_NFQA_PAYLOAD = 10

_NFQNL_COPY_PACKET = 2
_NFQNL_PACKET_HDR = struct.Struct("!IHB")  # packet_id, hw_protocol, hook
_NFQNL_CFG_CMD_STRUCT = struct.Struct("!BxH")  # command, padding, pf


@dataclass(frozen=True)
class QueuedPacket:
    """A packet queued by NFQUEUE awaiting a verdict."""

    packet_id: int
    dest: str
    port: int
    proto: int


# ── NfqueueHandler ────────────────────────────────────


class NfqueueHandler:
    """Raw AF_NETLINK NFQUEUE subscriber.

    Binds to a kernel NFQUEUE group, receives queued packets via
    ``poll()``, and issues verdicts via ``verdict()``.  The socket
    is non-blocking after the initial blocking handshake.

    Use :meth:`create` to construct; it handles the bind handshake
    and returns ``None`` if NFQUEUE is unavailable.
    """

    def __init__(self, sock: socket.socket, queue_num: int) -> None:
        """Wrap an already-bound NFQUEUE netlink socket.

        Use :meth:`create` instead of calling this directly.
        """
        self._sock = sock
        self._queue_num = queue_num

    @classmethod
    def create(cls, queue_num: int = NFQUEUE_NUM) -> NfqueueHandler | None:
        """Create and bind an NFQUEUE handler, or return ``None`` on failure.

        Binds to the specified queue number, sets copy mode to full packet,
        and configures a reasonable copy range for IP header extraction.

        Args:
            queue_num: NFQUEUE group number to bind to.
        """
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_NETFILTER)
            sock.bind((0, 0))

            # Handshake in blocking mode so ACKs are reliably received
            sock.settimeout(2.0)
            sock.send(_build_config_cmd(queue_num, _NFQNL_CFG_CMD_BIND))
            if not _check_ack(sock):
                sock.close()
                return None
            sock.send(_build_config_params(queue_num, copy_range=256))
            if not _check_ack(sock):
                sock.close()
                return None

            # Switch to non-blocking for the poll() loop
            sock.setblocking(False)
            return cls(sock, queue_num)
        except (OSError, AttributeError):
            logger.debug("NFQUEUE socket unavailable — interactive mode disabled")
            if sock is not None:
                sock.close()
            return None

    def fileno(self) -> int:
        """Return the file descriptor for ``select.select()`` multiplexing."""
        return self._sock.fileno()

    def close(self) -> None:
        """Close the netlink socket."""
        self._sock.close()

    def poll(self) -> list[QueuedPacket]:
        """Read available NFQUEUE messages and return parsed packets."""
        try:
            data = self._sock.recv(65536)
        except OSError:
            return []
        return self._parse_messages(data) if data else []

    def verdict(self, packet_id: int, *, accept: bool) -> None:
        """Issue a verdict for a queued packet.

        Args:
            packet_id: Kernel-assigned packet identifier.
            accept: ``True`` for NF_ACCEPT, ``False`` for NF_DROP.
        """
        msg = _build_verdict_msg(self._queue_num, packet_id, NF_ACCEPT if accept else NF_DROP)
        try:
            self._sock.send(msg)
        except OSError:
            logger.warning("Failed to send verdict for packet %d", packet_id)

    def _parse_messages(self, data: bytes) -> list[QueuedPacket]:
        """Parse one or more netlink messages from raw *data*."""
        packets: list[QueuedPacket] = []
        offset = 0
        while offset + NLMSG_HDR.size <= len(data):
            nl_len, nl_type, _flags, _seq, _pid = NLMSG_HDR.unpack_from(data, offset)
            if nl_len < NLMSG_HDR.size or offset + nl_len > len(data):
                break
            pkt = self._handle_one_message(data, offset, nl_len, nl_type)
            if pkt:
                packets.append(pkt)
            offset += (nl_len + 3) & ~3
        return packets

    def _handle_one_message(
        self, data: bytes, offset: int, nl_len: int, nl_type: int
    ) -> QueuedPacket | None:
        """Parse a single netlink message, auto-dropping unparseable packets."""
        subsys = (nl_type >> 8) & 0xFF
        msg = nl_type & 0xFF
        if subsys != _NFNL_SUBSYS_QUEUE or msg != _NFQNL_MSG_PACKET:
            return None
        attr_offset = NLMSG_HDR.size + NFGEN_HDR.size
        if offset + attr_offset >= offset + nl_len:
            return None
        attrs = parse_nflog_attrs(data[offset + attr_offset : offset + nl_len])
        pkt = _attrs_to_packet(attrs)
        if pkt:
            return pkt
        # Unparseable payload but we have a packet_id — must still issue
        # a verdict or the packet stays stuck in the kernel queue.
        pid = _extract_packet_id(attrs)
        if pid is not None:
            self.verdict(pid, accept=False)
        return None


# ── Packet parsing ────────────────────────────────────


def _extract_packet_id(attrs: dict[int, bytes]) -> int | None:
    """Extract just the packet_id from NFQUEUE attributes, or ``None``."""
    pkt_hdr = attrs.get(_NFQA_PACKET_HDR)
    if not pkt_hdr or len(pkt_hdr) < _NFQNL_PACKET_HDR.size:
        return None
    return _NFQNL_PACKET_HDR.unpack_from(pkt_hdr)[0]


def _attrs_to_packet(attrs: dict[int, bytes]) -> QueuedPacket | None:
    """Convert parsed NFQUEUE attributes into a :class:`QueuedPacket`."""
    packet_id = _extract_packet_id(attrs)
    if packet_id is None:
        return None
    payload = attrs.get(_NFQA_PAYLOAD, b"")
    dest, proto, port = extract_ip_dest(payload)
    if not dest:
        return None
    return QueuedPacket(packet_id=packet_id, dest=dest, port=port, proto=proto)


# ── Message builders ──────────────────────────────────


def _build_config_cmd(queue_num: int, command: int) -> bytes:
    """Build an NFQUEUE config command message (bind/unbind)."""
    cmd_attr = _NFQNL_CFG_CMD_STRUCT.pack(command, socket.AF_INET)
    nfa = NFA_HDR.pack(NFA_HDR.size + len(cmd_attr), _NFQA_CFG_CMD) + cmd_attr
    nfgen = NFGEN_HDR.pack(2, 0, socket.htons(queue_num))
    payload = nfgen + nfa
    msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_CONFIG
    return (
        NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), msg_type, NLM_F_REQUEST | NLM_F_ACK, 0, 0)
        + payload
    )


def _build_config_params(queue_num: int, *, copy_range: int = 256) -> bytes:
    """Build an NFQUEUE config params message (copy mode + range)."""
    params = struct.pack("!IB3x", copy_range, _NFQNL_COPY_PACKET)
    nfa = NFA_HDR.pack(NFA_HDR.size + len(params), _NFQA_CFG_PARAMS) + params
    nfgen = NFGEN_HDR.pack(2, 0, socket.htons(queue_num))
    payload = nfgen + nfa
    msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_CONFIG
    return (
        NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), msg_type, NLM_F_REQUEST | NLM_F_ACK, 0, 0)
        + payload
    )


def _build_verdict_msg(queue_num: int, packet_id: int, verdict: int) -> bytes:
    """Build an NFQUEUE verdict message."""
    nfgen = NFGEN_HDR.pack(2, 0, socket.htons(queue_num))
    msg_type = (_NFNL_SUBSYS_QUEUE << 8) | _NFQNL_MSG_VERDICT
    verdict_payload = struct.pack("!II", verdict, packet_id)
    attr = NFA_HDR.pack(NFA_HDR.size + len(verdict_payload), _NFQA_VERDICT_HDR) + verdict_payload
    payload = nfgen + attr
    return NLMSG_HDR.pack(NLMSG_HDR.size + len(payload), msg_type, NLM_F_REQUEST, 0, 0) + payload


def _check_ack(sock: socket.socket) -> bool:
    """Read and check an NLMSG_ERROR ACK from the kernel.

    Returns ``True`` if the ACK indicates success (error code 0),
    ``False`` otherwise.
    """
    try:
        ack = sock.recv(4096)
        if len(ack) >= NLMSG_HDR.size + 4:
            err = struct.unpack_from("=i", ack, NLMSG_HDR.size)[0]
            if err < 0:
                logger.debug("NFQUEUE config rejected (errno %d)", -err)
                return False
        return True
    except OSError:
        logger.debug("NFQUEUE ACK not received")
        return False
