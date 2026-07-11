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
