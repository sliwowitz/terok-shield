# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the D-Bus event bridge (lib/dbus_bridge.py)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest import mock

import pytest

dbus_fast = pytest.importorskip("dbus_fast", reason="dbus-fast not installed")

from terok_shield.core.state import container_id_path
from terok_shield.lib.dbus_bridge import (
    BUS_NAME_PREFIX,
    ShieldBridge,
    _ShieldInterface,
    bus_name_for_container,
)

from ..testnet import TEST_DOMAIN, TEST_IP1

# ── Bus name construction ──────────────────────────────────


def test_bus_name_prefix_is_well_formed() -> None:
    """Bus name prefix follows MPRIS-style convention."""
    assert BUS_NAME_PREFIX == "org.terok.Shield1.Container_"


@pytest.mark.parametrize(
    ("short_id", "expected"),
    [
        pytest.param("abc123def456", "org.terok.Shield1.Container_abc123def456", id="hex-id"),
        pytest.param("0deadbeef12", "org.terok.Shield1.Container_0deadbeef12", id="starts-digit"),
    ],
)
def test_bus_name_for_container(short_id: str, expected: str) -> None:
    """bus_name_for_container() prefixes the short ID with Container_."""
    assert bus_name_for_container(short_id) == expected


# ── Container ID reading ───────────────────────────────────


def test_container_id_read_from_state_dir(tmp_path: Path) -> None:
    """ShieldBridge.container_id reads from state_dir/container.id."""
    container_id_path(tmp_path).write_text("abc123def456\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="test-ctr", bus=bus)
    assert bridge.container_id == "abc123def456"


def test_container_id_missing_raises(tmp_path: Path) -> None:
    """ShieldBridge.container_id raises FileNotFoundError if not persisted."""
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="test-ctr", bus=bus)
    with pytest.raises(FileNotFoundError, match="Container ID not found"):
        _ = bridge.container_id


def test_bus_name_property(tmp_path: Path) -> None:
    """ShieldBridge.bus_name derives from the persisted container ID."""
    container_id_path(tmp_path).write_text("0deadbeef12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="test-ctr", bus=bus)
    assert bridge.bus_name == "org.terok.Shield1.Container_0deadbeef12"


# ── Request ID mapping ─────────────────────────────────────


def test_submit_verdict_writes_stdin(tmp_path: Path) -> None:
    """submit_verdict() writes JSON to subprocess stdin."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    # Mock subprocess with a writable stdin
    mock_stdin = mock.MagicMock()
    mock_stdin.write = mock.MagicMock()
    mock_stdin.drain = mock.AsyncMock()
    mock_process = mock.MagicMock()
    mock_process.stdin = mock_stdin
    mock_process.returncode = None
    bridge._process = mock_process

    ok = asyncio.run(bridge.submit_verdict("myapp:42", "accept"))

    assert ok is True
    written = mock_stdin.write.call_args[0][0]
    parsed = json.loads(written.decode())
    assert parsed == {"type": "verdict", "id": 42, "action": "accept"}


def test_submit_verdict_invalid_request_id(tmp_path: Path) -> None:
    """submit_verdict() returns False for malformed request_id."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)
    bridge._process = mock.MagicMock()
    bridge._process.stdin = mock.MagicMock()

    assert asyncio.run(bridge.submit_verdict("no-colon", "accept")) is False
    assert asyncio.run(bridge.submit_verdict("myapp:notanumber", "deny")) is False


def test_submit_verdict_no_process(tmp_path: Path) -> None:
    """submit_verdict() returns False when subprocess is not running."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    assert asyncio.run(bridge.submit_verdict("myapp:1", "accept")) is False


# ── Event dispatch ─────────────────────────────────────────


def test_dispatch_pending_event(tmp_path: Path) -> None:
    """_dispatch_event() emits connection_blocked signal for 'pending' events."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    with mock.patch.object(bridge._interface, "connection_blocked") as sig:
        bridge._dispatch_event(
            {
                "type": "pending",
                "id": 7,
                "dest": TEST_IP1,
                "port": 443,
                "proto": 6,
                "domain": TEST_DOMAIN,
            }
        )
        sig.assert_called_once_with("myapp", TEST_IP1, 443, 6, TEST_DOMAIN, "myapp:7")


def test_dispatch_verdict_applied_event(tmp_path: Path) -> None:
    """_dispatch_event() emits verdict_applied signal for 'verdict_applied' events."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    with mock.patch.object(bridge._interface, "verdict_applied") as sig:
        bridge._dispatch_event(
            {
                "type": "verdict_applied",
                "id": 7,
                "dest": TEST_IP1,
                "action": "accept",
                "ok": True,
            }
        )
        sig.assert_called_once_with("myapp", TEST_IP1, "myapp:7", "accept", True)


def test_dispatch_unknown_event_type(tmp_path: Path) -> None:
    """_dispatch_event() silently ignores unknown event types."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    # Should not raise
    bridge._dispatch_event({"type": "unknown_thing", "data": 123})


# ── Interface class ────────────────────────────────────────


def test_shield_interface_name() -> None:
    """_ShieldInterface uses the canonical Shield1 interface name."""
    bridge = mock.MagicMock()
    iface = _ShieldInterface(bridge)
    assert iface.name == "org.terok.Shield1"


def test_shield_interface_stores_bridge_reference() -> None:
    """_ShieldInterface keeps a reference to the bridge for verdict routing."""
    bridge = mock.MagicMock()
    iface = _ShieldInterface(bridge)
    assert iface._bridge is bridge


# ── Lifecycle ──────────────────────────────────────────────


def test_stop_terminates_subprocess(tmp_path: Path) -> None:
    """stop() terminates the subprocess and unexports the interface."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    mock_process = mock.MagicMock()
    mock_process.returncode = None
    mock_process.terminate = mock.MagicMock()
    mock_process.kill = mock.MagicMock()
    mock_process.wait = mock.AsyncMock(return_value=0)
    bridge._process = mock_process
    bridge._read_task = None

    asyncio.run(bridge.stop())

    mock_process.terminate.assert_called_once()
    bus.unexport.assert_called_once()


def test_stop_without_process(tmp_path: Path) -> None:
    """stop() is safe to call when no subprocess has been started."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    # Should not raise
    asyncio.run(bridge.stop())
