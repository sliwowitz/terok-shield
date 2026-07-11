# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Guard the lightweight import path of the package facade.

``import terok_shield`` exposes the public data vocabulary
(``ShieldConfig``, ``ShieldMode``, …) without dragging in the heavier
optional machinery.  Pydantic is the sole such dependency and is used
only by the CLI's ``config.yml`` schema
([`config_file`][terok_shield.config_file]); a bare package import must
not pull it in.  Runs in a fresh interpreter so a pydantic import
triggered elsewhere in the test session cannot mask a regression.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _child_env() -> dict[str, str]:
    """Return the parent environment with the package ``src`` on PYTHONPATH.

    Keeps the guard working from a source checkout (``PYTHONPATH=src``)
    as well as an installed package, where the src entry is simply
    redundant.
    """
    import terok_shield

    # …/src/terok_shield/__init__.py → …/src
    src_root = str(Path(terok_shield.__file__).resolve().parent.parent)
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_root}{os.pathsep}{existing}" if existing else src_root
    return env


def test_bare_import_does_not_pull_pydantic() -> None:
    """A bare ``import terok_shield`` must not import pydantic."""
    result = subprocess.run(
        [sys.executable, "-c", "import sys, terok_shield; print('pydantic' in sys.modules)"],
        capture_output=True,
        text=True,
        env=_child_env(),
        check=True,
    )
    assert result.stdout.strip() == "False", (
        "pydantic was imported by a bare `import terok_shield`.\n"
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_building_the_cli_parser_does_not_pull_pydantic() -> None:
    """Building the CLI parser (the ``--help`` / parse path) must not import pydantic.

    Config-file validation is the only pydantic user in the CLI and it
    lives behind ``_load_config_file``; wiring the parser must stay clear
    of it so ``terok-shield --help`` / ``--version`` / ``setup`` don't pay
    the pydantic import.
    """
    code = (
        "import sys, terok_shield.cli.main as m;"
        "m._build_parser(['allow', 'ctr', 'target']);"
        "print('pydantic' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=_child_env(),
        check=True,
    )
    assert result.stdout.strip() == "False", (
        f"pydantic was imported while building the CLI parser.\n"
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def _verb_modules_after_wire(argv: list[str] | None) -> set[str]:
    """Return the ``terok_shield.verbs.*`` modules imported by wiring *argv*.

    Builds the CLI parser for *argv* in a fresh interpreter — exactly what
    a ``terok-shield <verb> [--help]`` invocation does before dispatch —
    and reports which per-verb modules that pulled in.  The lazy wire
    resolves only the invoked verb's source module, so this is the
    load-bearing proof of per-verb isolation.
    """
    code = (
        "import sys, json;"
        "import terok_shield.cli.main as m;"
        f"m._build_parser({argv!r});"
        "print(json.dumps(sorted(k for k in sys.modules if k.startswith('terok_shield.verbs.')"
        " and k != 'terok_shield.verbs._common')))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=_child_env(),
        check=True,
    )
    return set(json.loads(result.stdout))


def test_invoking_one_verb_imports_only_its_module() -> None:
    """``terok-shield allow …`` wires in ``control`` and no other verb module."""
    imported = _verb_modules_after_wire(["allow", "ctr", "target"])
    assert imported == {"terok_shield.verbs.control"}, imported


def test_invoking_watch_does_not_import_light_verb_modules() -> None:
    """``terok-shield watch …`` pulls in ``stream`` and leaves the rest alone."""
    imported = _verb_modules_after_wire(["watch", "ctr"])
    assert imported == {"terok_shield.verbs.stream"}, imported


def test_light_verb_does_not_pull_the_stream_verb_module() -> None:
    """A light verb must not import the ``stream`` module (watch / simple-clearance)."""
    imported = _verb_modules_after_wire(["allow", "ctr", "target"])
    assert "terok_shield.verbs.stream" not in imported


def test_top_level_help_imports_no_verb_module() -> None:
    """``terok-shield --help`` lists every verb without importing any verb module."""
    imported = _verb_modules_after_wire(["--help"])
    assert imported == set(), imported
