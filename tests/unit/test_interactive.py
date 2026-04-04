# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the NFLOG interactive connection handler."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.interactive import (
    _NSENTER_ENV,
    InteractiveSession,
    NfqueueInteractiveSession,
    _append_unique,
    _handle_signal,
    _PendingPacket,
    run_interactive,
)
from terok_shield.watch import WatchEvent

from ..testnet import (
    DNSMASQ_DOMAIN,
    DNSMASQ_DOMAIN2,
    KEPT_DOMAIN,
    TEST_IP1,
    TEST_IP2,
)

_CONTAINER = "test-ctr"


# ── Helpers ───────────────────────────────────────────────


def _make_session(tmp_path: Path) -> InteractiveSession:
    """Create an InteractiveSession with a mock runner rooted at tmp_path."""
    runner = mock.MagicMock()
    return InteractiveSession(
        runner=runner,
        state_dir=tmp_path,
        container=_CONTAINER,
    )


def _make_event(dest: str, port: int = 443, proto: int = 6) -> WatchEvent:
    """Build a minimal WatchEvent with action=queued_connection."""
    return WatchEvent(
        ts="2026-01-01T00:00:00",
        source="nflog",
        action="queued_connection",
        container=_CONTAINER,
        dest=dest,
        port=port,
        proto=proto,
    )


# ── _handle_signal ────────────────────────────────────────


class TestHandleSignal:
    """Tests for the module-level signal handler."""

    def test_sets_running_false(self) -> None:
        """_handle_signal sets the module-level _running flag to False."""
        import terok_shield.interactive as mod

        mod._running = True
        _handle_signal(2, None)
        assert mod._running is False


# ── _PendingPacket ────────────────────────────────────────


class TestPendingPacket:
    """Tests for the _PendingPacket dataclass."""

    def test_fields_and_defaults(self) -> None:
        """_PendingPacket stores all fields with correct defaults."""
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0)
        assert pkt.dest == TEST_IP1
        assert pkt.port == 443
        assert pkt.proto == 6
        assert pkt.queued_at == 1.0
        assert pkt.domain == ""
        assert pkt.packet_id == 0

    def test_explicit_optional_fields(self) -> None:
        """_PendingPacket accepts explicit domain and packet_id."""
        pkt = _PendingPacket(
            dest=TEST_IP2,
            port=80,
            proto=6,
            queued_at=2.0,
            domain=DNSMASQ_DOMAIN,
            packet_id=42,
        )
        assert pkt.domain == DNSMASQ_DOMAIN
        assert pkt.packet_id == 42


# ── _append_unique ────────────────────────────────────────


class TestAppendUnique:
    """Tests for the _append_unique helper."""

    def test_appends_new_value(self, tmp_path: Path) -> None:
        """_append_unique writes a value to a new file."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        assert TEST_IP1 in path.read_text()

    def test_deduplicates(self, tmp_path: Path) -> None:
        """_append_unique does not write the same value twice."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        _append_unique(path, TEST_IP1)
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        assert lines.count(TEST_IP1) == 1

    def test_appends_second_value(self, tmp_path: Path) -> None:
        """_append_unique adds distinct values to the same file."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        _append_unique(path, TEST_IP2)
        content = path.read_text()
        assert TEST_IP1 in content
        assert TEST_IP2 in content

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        """_append_unique creates the file (not parent dirs) as needed."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        assert path.is_file()


# ── InteractiveSession._handle_nflog_event ────────────────


class TestHandleNflogEvent:
    """Tests for InteractiveSession._handle_nflog_event."""

    def test_emits_pending_json(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_nflog_event emits a pending JSON line on stdout."""
        session = _make_session(tmp_path)
        event = _make_event(TEST_IP1)
        session._handle_nflog_event(event)
        out = json.loads(capsys.readouterr().out.strip())
        assert out["type"] == "pending"
        assert out["id"] == 1
        assert out["dest"] == TEST_IP1
        assert out["port"] == 443
        assert out["proto"] == 6

    def test_deduplicates_by_ip(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Second event to the same IP is silently dropped."""
        session = _make_session(tmp_path)
        session._handle_nflog_event(_make_event(TEST_IP1))
        capsys.readouterr()  # clear first output
        session._handle_nflog_event(_make_event(TEST_IP1, port=80))
        assert capsys.readouterr().out == ""

    def test_different_ips_get_different_ids(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Each unique IP gets a monotonically increasing id."""
        session = _make_session(tmp_path)
        session._handle_nflog_event(_make_event(TEST_IP1))
        out1 = json.loads(capsys.readouterr().out.strip())
        session._handle_nflog_event(_make_event(TEST_IP2))
        out2 = json.loads(capsys.readouterr().out.strip())
        assert out1["id"] == 1
        assert out2["id"] == 2

    def test_includes_domain_from_cache(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """_handle_nflog_event looks up domain from the IP-to-domain cache."""
        session = _make_session(tmp_path)
        session._ip_to_domain[TEST_IP1] = DNSMASQ_DOMAIN
        session._handle_nflog_event(_make_event(TEST_IP1))
        out = json.loads(capsys.readouterr().out.strip())
        assert out["domain"] == DNSMASQ_DOMAIN


# ── InteractiveSession._process_command ───────────────────


class TestProcessCommand:
    """Tests for InteractiveSession._process_command."""

    def _setup_pending(self, session: InteractiveSession) -> int:
        """Inject a pending packet with id=1 and return the id."""
        pkt = _PendingPacket(
            dest=TEST_IP1, port=443, proto=6, queued_at=time.monotonic(), packet_id=1
        )
        session._pending_by_ip[TEST_IP1] = pkt
        return 1

    def test_accept_verdict(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Accept verdict emits verdict_applied with ok=True."""
        session = _make_session(tmp_path)
        pkt_id = self._setup_pending(session)
        with mock.patch.object(session, "_apply_verdict", return_value=True):
            session._process_command(
                json.dumps({"type": "verdict", "id": pkt_id, "action": "accept"})
            )
        out = json.loads(capsys.readouterr().out.strip())
        assert out["type"] == "verdict_applied"
        assert out["action"] == "accept"
        assert out["ok"] is True

    def test_deny_verdict(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Deny verdict emits verdict_applied with ok=True."""
        session = _make_session(tmp_path)
        pkt_id = self._setup_pending(session)
        with mock.patch.object(session, "_apply_verdict", return_value=True):
            session._process_command(
                json.dumps({"type": "verdict", "id": pkt_id, "action": "deny"})
            )
        out = json.loads(capsys.readouterr().out.strip())
        assert out["action"] == "deny"
        assert out["ok"] is True

    def test_invalid_json_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Invalid JSON on stdin is logged as a warning."""
        session = _make_session(tmp_path)
        session._process_command("not json at all")
        assert "Invalid JSON" in caplog.text

    def test_non_dict_json_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """A JSON array (non-dict) is logged as a warning."""
        session = _make_session(tmp_path)
        session._process_command("[1, 2, 3]")
        assert "Expected JSON object" in caplog.text

    def test_unknown_type_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Unknown command type is logged as a warning."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "ping"}))
        assert "Unknown command type" in caplog.text

    def test_bool_id_rejected(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Boolean id is rejected (bool is subclass of int)."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": True, "action": "accept"}))
        assert "must be an integer" in caplog.text

    def test_string_id_rejected(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """String id is rejected."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": "one", "action": "accept"}))
        assert "must be an integer" in caplog.text

    def test_invalid_action_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Action other than accept/deny is rejected."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": 1, "action": "drop"}))
        assert "must be 'accept' or 'deny'" in caplog.text

    def test_unknown_id_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Verdict for a non-existent pending packet is logged."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": 999, "action": "accept"}))
        assert "No pending packet" in caplog.text


# ── InteractiveSession._apply_verdict ─────────────────────


class TestApplyVerdict:
    """Tests for InteractiveSession._apply_verdict."""

    def test_accept_persists_to_live_allowed(self, tmp_path: Path) -> None:
        """Accept verdict persists IP to live.allowed."""
        session = _make_session(tmp_path)
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch("terok_shield.interactive.add_elements_dual", return_value="nft add"):
            result = session._apply_verdict(pkt, accept=True)
        assert result is True
        assert TEST_IP1 in state.live_allowed_path(tmp_path).read_text()

    def test_deny_persists_to_deny_list(self, tmp_path: Path) -> None:
        """Deny verdict persists IP to deny.list."""
        session = _make_session(tmp_path)
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch("terok_shield.interactive.add_deny_elements_dual", return_value="nft add"):
            result = session._apply_verdict(pkt, accept=False)
        assert result is True
        assert TEST_IP1 in state.deny_path(tmp_path).read_text()

    def test_nft_failure_returns_false(self, tmp_path: Path) -> None:
        """nft command failure causes _apply_verdict to return False."""
        session = _make_session(tmp_path)
        session._runner.nft_via_nsenter.side_effect = RuntimeError("nft failed")
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch("terok_shield.interactive.add_elements_dual", return_value="nft add x\n"):
            result = session._apply_verdict(pkt, accept=True)
        assert result is False


# ── InteractiveSession._refresh_domain_cache ──────────────


class TestRefreshDomainCache:
    """Tests for InteractiveSession._refresh_domain_cache."""

    def test_parses_dnsmasq_log(self, tmp_path: Path) -> None:
        """_refresh_domain_cache parses dnsmasq 'reply' lines into IP-to-domain mapping."""
        session = _make_session(tmp_path)
        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(
            f"reply {DNSMASQ_DOMAIN} is {TEST_IP1}\nreply {DNSMASQ_DOMAIN2} is {TEST_IP2}\n"
        )
        session._refresh_domain_cache()
        assert session._ip_to_domain[TEST_IP1] == DNSMASQ_DOMAIN
        assert session._ip_to_domain[TEST_IP2] == DNSMASQ_DOMAIN2

    def test_oserror_preserves_cache(self, tmp_path: Path) -> None:
        """OSError when reading dnsmasq log preserves the previous cache."""
        session = _make_session(tmp_path)
        session._ip_to_domain = {TEST_IP1: KEPT_DOMAIN}
        # dnsmasq.log does not exist, so read_text raises OSError
        session._refresh_domain_cache()
        assert session._ip_to_domain == {TEST_IP1: KEPT_DOMAIN}

    def test_replaces_stale_entries(self, tmp_path: Path) -> None:
        """A new log replaces the entire cache (old entries disappear)."""
        session = _make_session(tmp_path)
        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(f"reply {DNSMASQ_DOMAIN} is {TEST_IP1}\n")
        session._refresh_domain_cache()
        assert TEST_IP1 in session._ip_to_domain
        # Write a new log without the old entry
        log_path.write_text(f"reply {DNSMASQ_DOMAIN2} is {TEST_IP2}\n")
        session._refresh_domain_cache()
        assert TEST_IP1 not in session._ip_to_domain
        assert session._ip_to_domain[TEST_IP2] == DNSMASQ_DOMAIN2

    def test_strips_trailing_dot(self, tmp_path: Path) -> None:
        """Trailing dots in domain names are stripped."""
        session = _make_session(tmp_path)
        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(f"reply {DNSMASQ_DOMAIN}. is {TEST_IP1}\n")
        session._refresh_domain_cache()
        assert session._ip_to_domain[TEST_IP1] == DNSMASQ_DOMAIN


# ── InteractiveSession._read_stdin ────────────────────────


class TestReadStdin:
    """Tests for InteractiveSession._read_stdin."""

    @staticmethod
    def _mock_stdin() -> mock.MagicMock:
        """Return a mock stdin with a stable fileno()."""
        fake_stdin = mock.MagicMock()
        fake_stdin.fileno.return_value = 0
        return fake_stdin

    def test_eof_returns_none(self, tmp_path: Path) -> None:
        """Empty read (EOF) returns None."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.interactive.sys.stdin", self._mock_stdin()),
            mock.patch("terok_shield.interactive.os.read", return_value=b""),
        ):
            result = session._read_stdin("")
        assert result is None

    def test_oserror_returns_buf(self, tmp_path: Path) -> None:
        """OSError from os.read returns the current buffer unchanged."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.interactive.sys.stdin", self._mock_stdin()),
            mock.patch("terok_shield.interactive.os.read", side_effect=OSError("broken pipe")),
        ):
            result = session._read_stdin("partial")
        assert result == "partial"

    def test_processes_complete_lines(self, tmp_path: Path) -> None:
        """Complete lines are passed to _process_command; remainder stays in buffer."""
        session = _make_session(tmp_path)
        line = json.dumps({"type": "verdict", "id": 1, "action": "accept"})
        data = (line + "\npartial").encode()
        with (
            mock.patch("terok_shield.interactive.sys.stdin", self._mock_stdin()),
            mock.patch("terok_shield.interactive.os.read", return_value=data),
        ):
            with mock.patch.object(session, "_process_command") as mock_cmd:
                result = session._read_stdin("")
        mock_cmd.assert_called_once_with(line)
        assert result == "partial"


# ── run_interactive ───────────────────────────────────────


class TestRunInteractive:
    """Tests for the run_interactive entry point."""

    def test_exits_if_not_interactive(self, tmp_path: Path) -> None:
        """run_interactive exits with code 1 if interactive tier is not configured."""
        with pytest.raises(SystemExit) as ctx:
            run_interactive(tmp_path, _CONTAINER)
        assert ctx.value.code == 1

    def test_dispatches_nflog_session(self, tmp_path: Path) -> None:
        """run_interactive creates an NFLOG session when tier is nflog."""
        state.interactive_path(tmp_path).write_text("nflog\n")
        with (
            mock.patch("terok_shield.interactive.SubprocessRunner") as mock_runner_cls,
            mock.patch("terok_shield.interactive.InteractiveSession") as mock_session_cls,
        ):
            run_interactive(tmp_path, _CONTAINER)
        mock_runner_cls.assert_called_once()
        mock_session_cls.assert_called_once()
        mock_session_cls.return_value.run.assert_called_once()

    def test_dispatches_nfqueue_nsenter(self, tmp_path: Path) -> None:
        """run_interactive calls nsenter reexec when tier is nfqueue and not in nsenter."""
        state.interactive_path(tmp_path).write_text("nfqueue\n")
        with mock.patch("terok_shield.interactive._nsenter_reexec") as mock_reexec:
            run_interactive(tmp_path, _CONTAINER, timeout=10)
        mock_reexec.assert_called_once_with(tmp_path, _CONTAINER, timeout=10)

    def test_dispatches_nfqueue_loop_in_nsenter(self, tmp_path: Path) -> None:
        """run_interactive runs the nfqueue loop when already inside nsenter."""
        state.interactive_path(tmp_path).write_text("nfqueue\n")
        with (
            mock.patch.dict("os.environ", {_NSENTER_ENV: "1"}),
            mock.patch("terok_shield.interactive._run_nfqueue_loop") as mock_loop,
        ):
            run_interactive(tmp_path, _CONTAINER, timeout=7)
        mock_loop.assert_called_once_with(tmp_path, _CONTAINER, timeout=7)

    def test_legacy_tier_1_treated_as_nflog(self, tmp_path: Path) -> None:
        """Legacy interactive marker '1' is treated as nflog tier."""
        state.interactive_path(tmp_path).write_text("1\n")
        with (
            mock.patch("terok_shield.interactive.SubprocessRunner"),
            mock.patch("terok_shield.interactive.InteractiveSession") as mock_session_cls,
        ):
            run_interactive(tmp_path, _CONTAINER)
        mock_session_cls.return_value.run.assert_called_once()


# ── NfqueueInteractiveSession ────────────────────────────


class TestNfqueueInteractiveSession:
    """Tests for the NfqueueInteractiveSession."""

    def test_construction(self, tmp_path: Path) -> None:
        """NfqueueInteractiveSession stores all parameters."""
        runner = mock.MagicMock()
        session = NfqueueInteractiveSession(
            runner=runner, state_dir=tmp_path, container=_CONTAINER, timeout=10
        )
        assert session._container == _CONTAINER
        assert session._timeout == 10

    def test_run_exits_if_handler_unavailable(self, tmp_path: Path) -> None:
        """run() exits with code 1 if NfqueueHandler.create() returns None."""
        runner = mock.MagicMock()
        session = NfqueueInteractiveSession(runner=runner, state_dir=tmp_path, container=_CONTAINER)
        with (
            mock.patch("terok_shield.nfqueue.NfqueueHandler.create", return_value=None),
            pytest.raises(SystemExit) as ctx,
        ):
            session.run()
        assert ctx.value.code == 1

    def test_drain_timed_out(self, tmp_path: Path) -> None:
        """Timed-out packets are auto-dropped and emit verdict_applied."""
        runner = mock.MagicMock()
        session = NfqueueInteractiveSession(
            runner=runner, state_dir=tmp_path, container=_CONTAINER, timeout=0
        )
        # Inject a stale pending packet
        pending = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=0.0, packet_id=42)
        session._pending_by_ip[TEST_IP1] = pending

        handler = mock.MagicMock()
        session._drain_timed_out(handler)

        handler.verdict.assert_called_once_with(42, accept=False)
        assert TEST_IP1 not in session._pending_by_ip
