# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests that ``confine_to_state`` isolates a reader to its state directory.

The live restriction is irreversible and process-wide, so that proof runs in a
fresh interpreter; the in-process suite keeps it stubbed (see ``conftest``).
Every matrix slot therefore exercises its distro's kernel, while kernels without
Landlock skip the live proof.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from unittest import mock

import pytest

import terok_shield._confine as _confine

from ..testfs import SYSTEM_RUNTIME_DIR

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Landlock is Linux-only")

_REAL_CONFINE_TO_STATE = _confine.confine_to_state


def test_state_policy_hardens_without_granting_system_runtime(tmp_path: Path) -> None:
    """The state-reader policy applies both floors without adding the runtime tree."""
    hardening = mock.Mock(fully_hardened=False)
    filesystem = mock.Mock(confined=False, reason="test fallback")
    with (
        mock.patch.object(_confine, "harden_self", return_value=hardening) as harden,
        mock.patch.object(_confine, "confine_filesystem", return_value=filesystem) as confine,
        mock.patch.object(_confine._logger, "debug") as debug,
    ):
        _REAL_CONFINE_TO_STATE(tmp_path)

    harden.assert_called_once_with()
    read_exec, read_write = confine.call_args.args
    assert SYSTEM_RUNTIME_DIR not in read_exec
    assert read_write == [tmp_path]
    assert debug.call_args_list == [
        mock.call("shield reader hardening partial: %s", hardening),
        mock.call("shield reader filesystem-confinement not applied: %s", filesystem.reason),
    ]


def test_watch_state_lane_excludes_sibling_state_and_system_runtime(tmp_path: Path) -> None:
    """Watch retains state access without exposing sibling state or runtime credentials."""
    state_dir = tmp_path / "container-a"
    sibling = tmp_path / "container-b"
    for directory in (state_dir, sibling):
        directory.mkdir()
    (sibling / "secret").write_text("another container's state")

    probe = textwrap.dedent(
        f"""
        from pathlib import Path
        from terok_util import hardening
        from terok_shield._confine import confine_to_state

        libc = hardening._libc()
        if libc is None or hardening._landlock_abi(libc) < 1:
            print("unsupported:no-landlock")
            raise SystemExit(0)

        confine_to_state(Path({str(state_dir)!r}))

        out = []
        state_file = Path({str(state_dir)!r}, "audit.jsonl")
        state_file.write_text("x")
        out.append(f"state-read-write-{{state_file.read_text()}}")
        try:
            Path({str(sibling)!r}, "secret").read_text()
            out.append("sibling-read-LEAK")
        except PermissionError:
            out.append("sibling-read-denied")
        try:
            list(Path({str(SYSTEM_RUNTIME_DIR)!r}).iterdir())
            out.append("runtime-read-LEAK")
        except PermissionError:
            out.append("runtime-read-denied")
        print(";".join(out))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    out = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if out.startswith("unsupported:"):
        pytest.skip(f"kernel without Landlock: {out}")
    assert out == "state-read-write-x;sibling-read-denied;runtime-read-denied", (
        f"watch confinement leaked: {out!r}"
    )
