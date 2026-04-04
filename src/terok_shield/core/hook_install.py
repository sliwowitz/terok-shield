# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook file generation and installation.

Generates the hook entrypoint script (read from ``resources/hook_entrypoint.py``)
and the OCI hook JSON descriptors, then writes them to per-container or
global hooks directories.  Pure file I/O — no runtime container interaction.

Provides ``install_hooks()`` for per-container setup (called by
``HookMode.pre_start()``) and ``setup_global_hooks()`` for one-time
global installation (called by the ``setup`` CLI command).
"""

import json
import stat
from pathlib import Path

from ..common.config import ANNOTATION_KEY


def _generate_entrypoint() -> str:
    """Return the self-contained OCI hook entrypoint script.

    The script uses ``#!/usr/bin/env python3`` so it resolves Python at
    execution time — no virtualenv path is baked in at setup time.
    Works for all install methods: pip, pipx, Poetry, system package.
    """
    return (Path(__file__).parent.parent / "resources" / "hook_entrypoint.py").read_text()


def _generate_hook_json(entrypoint: str, stage: str) -> str:
    """Generate an OCI hook JSON descriptor for a given stage.

    Args:
        entrypoint: Absolute path to the hook entrypoint script.
        stage: OCI hook stage (``createRuntime`` or ``poststop``).
    """
    hook = {
        "version": "1.0.0",
        "hook": {"path": entrypoint, "args": ["terok-shield-hook", stage]},
        "when": {"annotations": {ANNOTATION_KEY: ".*"}},
        "stages": [stage],
    }
    return json.dumps(hook, indent=2) + "\n"


def _write_hook_files(
    hook_entrypoint: Path,
    hooks_dir: Path,
    json_entrypoint_path: Path | None = None,
) -> None:
    """Write entrypoint script and hook JSON files.

    Args:
        hook_entrypoint: Where to write the entrypoint script.
        hooks_dir: Where to write the hook JSON files.
        json_entrypoint_path: Path to embed in hook JSONs (defaults to
            *hook_entrypoint*).  Used when writing to a temp dir but
            the JSONs need to reference the final install location.
    """
    hook_entrypoint.write_text(_generate_entrypoint())
    hook_entrypoint.chmod(hook_entrypoint.stat().st_mode | stat.S_IEXEC)
    ref_path = str(json_entrypoint_path or hook_entrypoint)
    for stage_name in ("createRuntime", "poststop"):
        hook_json = _generate_hook_json(ref_path, stage_name)
        (hooks_dir / f"terok-shield-{stage_name}.json").write_text(hook_json)


def setup_global_hooks(target_dir: Path, *, use_sudo: bool = False) -> None:
    """Install OCI hooks in a global directory for restart persistence.

    Writes the entrypoint script and hook JSON files directly into
    *target_dir*.  When *use_sudo* is True, writes to a temp directory
    first and copies via ``sudo cp``.

    Args:
        target_dir: Global hooks directory to install into.
        use_sudo: Use ``sudo`` for writing to the target directory.
    """
    import subprocess
    import tempfile

    entrypoint_name = "terok-shield-hook"

    if use_sudo:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Generate JSONs referencing the FINAL entrypoint path
            final_entrypoint = target_dir / entrypoint_name
            _write_hook_files(tmp_path / entrypoint_name, tmp_path, final_entrypoint)
            subprocess.run(
                ["sudo", "mkdir", "-p", str(target_dir)],
                check=True,  # noqa: S603, S607
            )
            files = [str(tmp_path / entrypoint_name)]
            for stage in ("createRuntime", "poststop"):
                files.append(str(tmp_path / f"terok-shield-{stage}.json"))
            subprocess.run(
                ["sudo", "cp", *files, str(target_dir) + "/"],
                check=True,  # noqa: S603, S607
            )
            subprocess.run(
                ["sudo", "chmod", "+x", str(final_entrypoint)],  # noqa: S603, S607
                check=True,
            )
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
        _write_hook_files(target_dir / entrypoint_name, target_dir)


def install_hooks(*, hook_entrypoint: Path, hooks_dir: Path) -> None:
    """Install OCI hook entrypoint and hook JSON files.

    Installs hooks for the ``createRuntime`` and ``poststop`` stages.

    Args:
        hook_entrypoint: Path for the entrypoint script.
        hooks_dir: Directory for hook JSON files.
    """
    hook_entrypoint.parent.mkdir(parents=True, exist_ok=True)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    _write_hook_files(hook_entrypoint, hooks_dir)
