# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Self-confinement floor for shield's long-lived reader daemons.

``shield watch`` and ``shield simple-clearance`` are long-lived processes that
only ever read their per-container ``state_dir`` (dnsmasq/audit logs, the domain
cache, the DNS-tier marker) plus the shared runtime they import from, and write
nothing outside that directory.  Before the loop starts they pin themselves to
that lane with terok-util's process-hardening floor plus Landlock filesystem
confinement, so a bug in a reader can neither read another container's state nor
drop a payload outside its own.  NFLOG is a netlink socket, not a filesystem
access, so confinement leaves it untouched.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from terok_util import confine_filesystem, harden_self

_logger = logging.getLogger(__name__)

#: Directories a confined reader may read and execute from — the shared runtime
#: (interpreter, stdlib, site-packages) it keeps importing from.  Broad on
#: purpose: the payoff is the write-side and the cross-container read isolation,
#: not a minimal system-read surface.
_SYSTEM_READ_ROOTS: tuple[Path, ...] = (
    *(
        Path(p)
        for p in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev", "/run")
    ),
    Path(sys.prefix),
    Path(sys.base_prefix),
)


def confine_to_state(state_dir: Path) -> None:
    """Harden this process and pin its filesystem to *state_dir* plus system reads.

    Applies terok-util's hardening floor, then Landlock-confines the process to
    read+execute the system roots and read+write only *state_dir*.  Both are
    best-effort and never raise: an old kernel or a missing capability degrades
    to a debug line, so the daemon still runs (unconfined) rather than failing
    to start.
    """
    report = harden_self()
    if not report.fully_hardened:
        _logger.debug("shield reader hardening partial: %s", report)
    fs = confine_filesystem(_SYSTEM_READ_ROOTS, [state_dir])
    if not fs.confined:
        _logger.debug("shield reader filesystem-confinement not applied: %s", fs.reason)
