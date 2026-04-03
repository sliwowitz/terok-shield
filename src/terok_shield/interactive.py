# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Interactive NFQUEUE verdict loop for operator-driven egress control.

Orchestrates :class:`~terok_shield.nfqueue.NfqueueHandler` with state
persistence, nft set updates, and a bidirectional JSON-lines protocol
on stdin/stdout for consumer integration.

Protocol::

    Handler → stdout:  {"type":"pending","id":42,"dest":"1.2.3.4","port":443,"proto":6,"domain":"..."}
    Consumer → stdin:  {"type":"verdict","id":42,"action":"accept"}
    Handler → stdout:  {"type":"verdict_applied","id":42,"action":"accept","dest":"1.2.3.4"}

Timeout: packets without a verdict within *nfqueue_timeout* seconds are
auto-dropped (NF_DROP) without persisting to the deny list.
"""

from __future__ import annotations

import json
import logging
import os
import re
import select
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import state
from .mode_hook import INTERACTIVE_TIER_NFQUEUE
from .nfqueue import NfqueueHandler, QueuedPacket
from .nft_constants import NFQUEUE_NUM
from .run import CommandRunner, SubprocessRunner
from .state import read_interactive_tier
from .watch import NflogWatcher, WatchEvent

logger = logging.getLogger(__name__)

# Matches dnsmasq log lines:  "... reply <domain> is <ip>"
_REPLY_RE = re.compile(r"reply\s+(\S+)\s+is\s+(\S+)")

# How often (seconds) to refresh the domain cache from dnsmasq log.
_DOMAIN_REFRESH_INTERVAL = 10.0

_running = True


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


# ── Pending packet tracking ────────────────────────────


@dataclass
class _PendingPacket:
    """A queued packet awaiting operator verdict."""

    packet: QueuedPacket
    queued_at: float
    domain: str = ""


# ── InteractiveSession ─────────────────────────────────


class InteractiveSession:
    """Orchestrates the NFQUEUE verdict loop with I/O and state.

    Reads queued packets from :class:`NfqueueHandler`, enriches them
    with domain information from the dnsmasq log, emits JSON-lines events
    to stdout, reads verdict commands from stdin, and issues nft set
    updates + kernel verdicts.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner,
        state_dir: Path,
        container: str,
        nfqueue_num: int = NFQUEUE_NUM,
        timeout: int = 5,
    ) -> None:
        """Initialise the session with validated parameters.

        Args:
            runner: Command runner for nft set modifications.
            state_dir: Per-container state directory.
            container: Container name (for nft_via_nsenter).
            nfqueue_num: NFQUEUE group number to bind.
            timeout: Seconds before auto-dropping queued packets.
        """
        self._runner = runner
        self._state_dir = state_dir
        self._container = container
        self._nfqueue_num = nfqueue_num
        self._timeout = timeout
        self._pending: dict[int, _PendingPacket] = {}
        self._ip_to_domain: dict[str, str] = {}
        self._last_domain_refresh = 0.0

    def run(self) -> None:
        """Enter the main verdict loop.

        Blocks until SIGINT/SIGTERM or stdin EOF.  Emits JSON-lines to stdout,
        reads verdict commands from stdin.
        """
        handler = NfqueueHandler.create(self._nfqueue_num)
        if handler is None:
            print(
                "Error: cannot bind to NFQUEUE — check permissions or kernel module.",
                file=sys.stderr,
            )
            raise SystemExit(1)

        self._refresh_domain_cache()
        stdin_fd = sys.stdin.fileno()
        _set_nonblocking(stdin_fd)

        global _running  # noqa: PLW0603
        _running = True
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        try:
            self._loop(handler, stdin_fd)
        finally:
            self._drain_pending(handler)
            handler.close()

    def _drain_pending(self, handler: NfqueueHandler) -> None:
        """Reject all remaining pending packets on shutdown."""
        for _pid, pending in self._pending.items():
            handler.verdict(pending.packet.packet_id, accept=False)
        self._pending.clear()

    def _loop(self, handler: NfqueueHandler, stdin_fd: int) -> None:
        """Core select() loop: NFQUEUE socket + stdin + timeout sweep."""
        stdin_buf = ""
        while _running:
            readable = self._select_readable(handler, stdin_fd)
            self._poll_nfqueue(handler, readable)
            stdin_buf = self._poll_stdin(handler, stdin_buf, readable)
            if stdin_buf is None:
                break
            self._sweep_timeouts(handler)
            self._maybe_refresh_domains()

    def _select_readable(self, handler: NfqueueHandler, stdin_fd: int) -> set[int]:
        """Run select() and return a set of ready file descriptors."""
        readable, _, _ = select.select([handler, stdin_fd], [], [], 1.0)
        return {r if isinstance(r, int) else r.fileno() for r in readable}

    def _poll_nfqueue(self, handler: NfqueueHandler, ready: set[int]) -> None:
        """Read queued packets if the NFQUEUE socket is ready."""
        if handler.fileno() in ready:
            for pkt in handler.poll():
                self._handle_queued(pkt)

    def _poll_stdin(self, handler: NfqueueHandler, buf: str, ready: set[int]) -> str | None:
        """Read and process stdin commands if stdin is ready."""
        if sys.stdin.fileno() not in ready:
            return buf
        return self._read_stdin(handler, buf)

    def _maybe_refresh_domains(self) -> None:
        """Refresh domain cache if the refresh interval has elapsed."""
        if time.monotonic() - self._last_domain_refresh > _DOMAIN_REFRESH_INTERVAL:
            self._refresh_domain_cache()

    def _handle_queued(self, pkt: QueuedPacket) -> None:
        """Process a newly queued packet: enrich, emit, track."""
        domain = self._ip_to_domain.get(pkt.dest, "")
        pending = _PendingPacket(packet=pkt, queued_at=time.monotonic(), domain=domain)
        self._pending[pkt.packet_id] = pending

        event: dict = {
            "type": "pending",
            "id": pkt.packet_id,
            "dest": pkt.dest,
            "port": pkt.port,
            "proto": pkt.proto,
        }
        if domain:
            event["domain"] = domain
        print(json.dumps(event, separators=(",", ":")), flush=True)

    def _read_stdin(self, handler: NfqueueHandler, buf: str) -> str | None:
        """Read available stdin data and process complete JSON lines.

        Returns updated buffer, or ``None`` if stdin was closed.
        """
        try:
            chunk = os.read(sys.stdin.fileno(), 4096).decode()
        except OSError:
            return buf
        if not chunk:
            return None  # EOF

        buf += chunk
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if line:
                self._process_command(handler, line)
        return buf

    def _process_command(self, handler: NfqueueHandler, line: str) -> None:
        """Parse and execute a single JSON verdict command."""
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring invalid JSON on stdin")
            return

        if not isinstance(cmd, dict) or cmd.get("type") != "verdict":
            return

        packet_id = cmd.get("id")
        action = cmd.get("action")
        if not isinstance(packet_id, int) or isinstance(packet_id, bool):
            return
        if not isinstance(action, str):
            return
        action = action.lower()
        if action not in ("accept", "deny"):
            return

        pending = self._pending.pop(packet_id, None)
        if pending is None:
            return  # already timed out or unknown

        accept = action == "accept"
        handler.verdict(pending.packet.packet_id, accept=accept)
        ok = self._apply_verdict(pending, accept=accept)

        result: dict = {
            "type": "verdict_applied" if ok else "verdict_failed",
            "id": packet_id,
            "action": action,
            "dest": pending.packet.dest,
        }
        if pending.domain:
            result["domain"] = pending.domain
        print(json.dumps(result, separators=(",", ":")), flush=True)

    def _apply_verdict(self, pending: _PendingPacket, *, accept: bool) -> bool:
        """Persist the verdict to nft sets and state files.

        Returns True on success, False if the nft update failed.
        """
        ip = pending.packet.dest
        if accept:
            from .nft import add_elements_dual

            nft_cmd = add_elements_dual([ip], permanent=True)
        else:
            from .nft import add_deny_elements_dual

            nft_cmd = add_deny_elements_dual([ip])

        if nft_cmd and not self._nft_apply(nft_cmd):
            return False

        target = (
            state.live_allowed_path(self._state_dir) if accept else state.deny_path(self._state_dir)
        )
        _append_unique(target, ip)
        return True

    def _nft_apply(self, nft_cmd: str) -> bool:
        """Apply nft commands via nsenter.  Returns True on success."""
        for line in nft_cmd.strip().splitlines():
            parts = line.strip().split()
            if parts:
                try:
                    self._runner.nft_via_nsenter(self._container, *parts)
                except Exception:
                    logger.warning("Failed to apply nft command: %s", line)
                    return False
        return True

    def _sweep_timeouts(self, handler: NfqueueHandler) -> None:
        """Drop packets that have exceeded the verdict timeout."""
        now = time.monotonic()
        expired = [pid for pid, p in self._pending.items() if now - p.queued_at > self._timeout]
        for pid in expired:
            pending = self._pending.pop(pid)
            handler.verdict(pending.packet.packet_id, accept=False)
            event: dict = {
                "type": "verdict_timeout",
                "id": pid,
                "dest": pending.packet.dest,
                "port": pending.packet.port,
            }
            if pending.domain:
                event["domain"] = pending.domain
            print(json.dumps(event, separators=(",", ":")), flush=True)

    def _refresh_domain_cache(self) -> None:
        """Refresh IP→domain cache from the dnsmasq query log.

        Builds a fresh cache on each call so log rotation doesn't leave
        stale entries.  Called periodically during the select loop.
        """
        log_path = state.dnsmasq_log_path(self._state_dir)
        if not log_path.is_file():
            self._last_domain_refresh = time.monotonic()
            return
        new_map: dict[str, str] = {}
        try:
            for line in log_path.read_text().splitlines():
                m = _REPLY_RE.search(line)
                if m:
                    domain, ip = m.group(1).lower().rstrip("."), m.group(2)
                    new_map[ip] = domain
        except OSError:
            pass  # keep previous cache intact
        else:
            self._ip_to_domain = new_map
        self._last_domain_refresh = time.monotonic()


# ── Helpers ────────────────────────────────────────────


def _set_nonblocking(fd: int) -> None:
    """Set a file descriptor to non-blocking mode."""
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def _append_unique(path: Path, value: str) -> None:
    """Append *value* to a newline-separated file if not already present."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = set(path.read_text().splitlines()) if path.is_file() else set()
    if value not in existing:
        with path.open("a") as f:
            f.write(f"{value}\n")


# ── NFLOG-based interactive session ───────────────────


class NflogInteractiveSession:
    """Interactive verdict session using NFLOG events (no NFQUEUE dependency).

    Reads rejected-but-logged packets from :class:`NflogWatcher` (host-side,
    no nsenter needed), deduplicates by destination IP, and emits the same
    JSON-lines protocol as the NFQUEUE session.

    Packets are already rejected by the nft rule — the operator's verdict
    updates allow/deny sets so *future* connections to that IP succeed or
    are explicitly denied.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner,
        state_dir: Path,
        container: str,
    ) -> None:
        """Initialise the NFLOG session.

        Args:
            runner: Command runner for nft set modifications.
            state_dir: Per-container state directory.
            container: Container name.
        """
        self._runner = runner
        self._state_dir = state_dir
        self._container = container
        self._seen_ips: set[str] = set()
        self._pending_by_ip: dict[str, _PendingPacket] = {}
        self._ip_to_domain: dict[str, str] = {}
        self._last_domain_refresh = 0.0
        self._next_id = 1

    def run(self) -> None:
        """Enter the NFLOG-based verdict loop."""
        watcher = NflogWatcher.create(self._container)
        if watcher is None:
            print(
                "Error: cannot bind to NFLOG — check permissions or kernel module.",
                file=sys.stderr,
            )
            raise SystemExit(1)

        self._refresh_domain_cache()
        stdin_fd = sys.stdin.fileno()
        _set_nonblocking(stdin_fd)

        global _running  # noqa: PLW0603
        _running = True
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        try:
            self._loop(watcher, stdin_fd)
        finally:
            watcher.close()

    def _loop(self, watcher: NflogWatcher, stdin_fd: int) -> None:
        """Core select loop: NFLOG socket + stdin."""
        stdin_buf = ""
        while _running:
            readable, _, _ = select.select([watcher, stdin_fd], [], [], 1.0)
            ready = {r if isinstance(r, int) else r.fileno() for r in readable}

            if watcher.fileno() in ready:
                for event in watcher.poll():
                    if event.action == "queued_connection" and event.dest:
                        self._handle_nflog_event(event)

            if stdin_fd in ready:
                stdin_buf = self._read_stdin(stdin_buf)
                if stdin_buf is None:
                    break

            if time.monotonic() - self._last_domain_refresh > _DOMAIN_REFRESH_INTERVAL:
                self._refresh_domain_cache()

    def _handle_nflog_event(self, event: WatchEvent) -> None:
        """Process an NFLOG event for a queued connection."""
        ip = event.dest
        if ip in self._seen_ips:
            return  # deduplicate — already presented to operator
        self._seen_ips.add(ip)

        domain = self._ip_to_domain.get(ip, "")
        pkt = QueuedPacket(packet_id=self._next_id, dest=ip, port=event.port, proto=event.proto)
        self._next_id += 1
        pending = _PendingPacket(packet=pkt, queued_at=time.monotonic(), domain=domain)
        self._pending_by_ip[ip] = pending

        out: dict = {
            "type": "pending",
            "id": pkt.packet_id,
            "dest": ip,
            "port": event.port,
            "proto": event.proto,
        }
        if domain:
            out["domain"] = domain
        print(json.dumps(out, separators=(",", ":")), flush=True)

    def _read_stdin(self, buf: str) -> str | None:
        """Read and process stdin verdict commands.  Returns None on EOF."""
        try:
            chunk = os.read(sys.stdin.fileno(), 4096).decode()
        except OSError:
            return buf
        if not chunk:
            return None
        buf += chunk
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if line:
                self._process_command(line)
        return buf

    def _process_command(self, line: str) -> None:
        """Parse and execute a verdict command."""
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring invalid JSON on stdin")
            return
        if not isinstance(cmd, dict) or cmd.get("type") != "verdict":
            return
        packet_id = cmd.get("id")
        action = cmd.get("action")
        if not isinstance(packet_id, int) or isinstance(packet_id, bool):
            return
        if not isinstance(action, str):
            return
        action = action.lower()
        if action not in ("accept", "deny"):
            return

        # Find pending by packet_id
        pending = next(
            (p for p in self._pending_by_ip.values() if p.packet.packet_id == packet_id), None
        )
        if pending is None:
            return
        del self._pending_by_ip[pending.packet.dest]

        accept = action == "accept"
        ok = self._apply_verdict(pending, accept=accept)

        result: dict = {
            "type": "verdict_applied" if ok else "verdict_failed",
            "id": packet_id,
            "action": action,
            "dest": pending.packet.dest,
        }
        if pending.domain:
            result["domain"] = pending.domain
        print(json.dumps(result, separators=(",", ":")), flush=True)

    def _apply_verdict(self, pending: _PendingPacket, *, accept: bool) -> bool:
        """Persist verdict to nft sets and state files."""
        ip = pending.packet.dest
        if accept:
            from .nft import add_elements_dual

            nft_cmd = add_elements_dual([ip], permanent=True)
        else:
            from .nft import add_deny_elements_dual

            nft_cmd = add_deny_elements_dual([ip])

        if nft_cmd:
            for line in nft_cmd.strip().splitlines():
                parts = line.strip().split()
                if parts:
                    try:
                        self._runner.nft_via_nsenter(self._container, *parts)
                    except Exception:
                        logger.warning("Failed to apply nft command: %s", line)
                        return False

        target = (
            state.live_allowed_path(self._state_dir) if accept else state.deny_path(self._state_dir)
        )
        _append_unique(target, ip)
        return True

    def _refresh_domain_cache(self) -> None:
        """Refresh IP→domain cache from the dnsmasq query log."""
        log_path = state.dnsmasq_log_path(self._state_dir)
        if not log_path.is_file():
            self._last_domain_refresh = time.monotonic()
            return
        new_map: dict[str, str] = {}
        try:
            for line in log_path.read_text().splitlines():
                m = _REPLY_RE.search(line)
                if m:
                    domain, ip = m.group(1).lower().rstrip("."), m.group(2)
                    new_map[ip] = domain
        except OSError:
            pass
        else:
            self._ip_to_domain = new_map
        self._last_domain_refresh = time.monotonic()


# ── Entry point ────────────────────────────────────────

_NSENTER_ENV = "_TEROK_SHIELD_NSENTER"


def run_interactive(state_dir: Path, container: str, *, timeout: int = 5) -> None:
    """Start the interactive verdict handler.

    Reads the interactive tier from the state dir and dispatches:
    - **nfqueue**: re-execs under ``nsenter`` into the container's netns,
      binds an NFQUEUE socket, and holds packets until operator verdict.
    - **nflog**: runs on the host, reads NFLOG events for rejected packets,
      and presents them for operator verdict (no kernel module needed).

    Args:
        state_dir: Per-container state directory.
        container: Container name.
        timeout: Seconds before auto-dropping queued packets (nfqueue tier only).

    Raises:
        SystemExit: If interactive mode is not enabled or handler cannot bind.
    """
    state_dir = state_dir.resolve()
    tier = read_interactive_tier(state_dir)
    if tier is None:
        print("Error: interactive mode is not enabled for this container.", file=sys.stderr)
        raise SystemExit(1)

    if tier == INTERACTIVE_TIER_NFQUEUE:
        if os.environ.get(_NSENTER_ENV) == "1":
            _run_nfqueue_loop(state_dir, container, timeout=timeout)
        else:
            _nsenter_reexec(state_dir, container, timeout=timeout)
    else:
        _run_nflog_loop(state_dir, container)


def _run_nfqueue_loop(state_dir: Path, container: str, *, timeout: int) -> None:
    """Run the NFQUEUE verdict loop (inside container netns)."""
    runner = SubprocessRunner()
    session = InteractiveSession(
        runner=runner,
        state_dir=state_dir,
        container=container,
        timeout=timeout,
    )
    session.run()


def _run_nflog_loop(state_dir: Path, container: str) -> None:
    """Run the NFLOG verdict loop (host-side, no nsenter)."""
    runner = SubprocessRunner()
    session = NflogInteractiveSession(
        runner=runner,
        state_dir=state_dir,
        container=container,
    )
    session.run()


def _nsenter_reexec(state_dir: Path, container: str, *, timeout: int) -> None:
    """Re-exec the handler inside the container's network namespace.

    Uses ``podman unshare nsenter -t PID -n`` to enter the rootless
    network namespace, then runs this module as ``python -m`` with
    stdin/stdout passed through for the JSON-lines protocol.
    """
    import subprocess

    runner = SubprocessRunner()
    pid = runner.podman_inspect(container, "{{.State.Pid}}")
    if not pid or pid == "0":
        print(f"Error: container {container!r} is not running.", file=sys.stderr)
        raise SystemExit(1)

    cmd = [
        "podman",
        "unshare",
        "nsenter",
        "-t",
        pid,
        "-n",
        "--",
        sys.executable,
        "-m",
        "terok_shield.interactive",
        str(state_dir),
        container,
        str(timeout),
    ]
    env = {**os.environ, _NSENTER_ENV: "1"}
    result = subprocess.run(cmd, env=env)  # noqa: S603 — argv list, no shell
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    # Re-exec entry point: python -m terok_shield.interactive <state_dir> <container> <timeout>
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.executable} -m terok_shield.interactive <state_dir> <container> <timeout>",
            file=sys.stderr,
        )
        raise SystemExit(2)
    _run_nfqueue_loop(Path(sys.argv[1]), sys.argv[2], timeout=int(sys.argv[3]))
