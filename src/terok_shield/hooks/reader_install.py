# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Installer for the standalone NFLOG reader resource.

Copies ``terok_shield/resources/nflog_reader.py`` out of the installed
package and onto disk at a caller-supplied path, where the OCI bridge
hook can execute it with ``/usr/bin/python3``.  The destination survives
terok-shield reinstalls (the OCI hook references it by absolute path
regardless of the package's virtual-environment location).
"""

from importlib import resources as importlib_resources
from pathlib import Path

_READER_PACKAGE = "terok_shield.resources"
_READER_RESOURCE = "nflog_reader.py"


def install_reader_resource(dest: Path) -> None:
    """Copy the NFLOG reader script to *dest* and make it executable.

    Overwrites any existing file so re-running after a terok-shield
    upgrade always picks up the latest reader code.

    Args:
        dest: Destination path for the reader script.
            Parents are created on demand.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    source = importlib_resources.files(_READER_PACKAGE).joinpath(_READER_RESOURCE)
    dest.write_bytes(source.read_bytes())
    dest.chmod(0o755)
