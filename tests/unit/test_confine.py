# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Live-kernel proof that ``confine_to_state`` isolates a reader to its state dir.

The restriction is irreversible and process-wide, so it is applied in a fresh
interpreter; the in-process suite keeps it stubbed (see ``conftest``).  Runs on
every matrix slot, so each distro's kernel exercises the confinement; a kernel
without Landlock skips.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Landlock is Linux-only")


def test_reader_writes_its_state_dir_and_cannot_read_a_sibling(tmp_path: Path) -> None:
    """A confined reader writes its own state dir but cannot read another container's."""
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
        Path({str(state_dir)!r}, "audit.jsonl").write_text("x")   # own state → write OK
        out.append("state-write-ok")
        try:
            Path({str(sibling)!r}, "secret").read_text()
            out.append("sibling-read-LEAK")
        except (PermissionError, OSError):
            out.append("sibling-read-denied")                     # another container → unreadable
        print(";".join(out))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    out = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if out.startswith("unsupported:"):
        pytest.skip(f"kernel without Landlock: {out}")
    assert out == "state-write-ok;sibling-read-denied", f"reader confinement leaked: {out!r}"
