# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Self-confinement floor for shield's long-lived state reader.

``shield watch`` only reads its per-container ``state_dir`` (dnsmasq/audit logs,
the domain cache, and the DNS-tier marker) plus the shared runtime it imports
from, and writes nothing outside that directory.  Before the loop starts it pins
itself to that lane with terok-util's process-hardening floor plus Landlock
filesystem confinement, so a bug in the reader can neither read another
container's state nor drop a payload outside its own.  NFLOG is a netlink socket,
not a filesystem access, so confinement leaves it untouched.

``shield simple-clearance`` is deliberately outside this policy: it is a
controller that invokes Podman and verdict subprocesses, not a state-only reader.
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
    *(Path(p) for p in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev")),
    Path(sys.prefix),
    Path(sys.base_prefix),
)


def confine_to_state(state_dir: Path) -> None:
    """Harden this process and pin its filesystem to *state_dir* plus system reads.

    Applies terok-util's hardening floor, then Landlock-confines the process to
    read+execute the system roots and read+write only *state_dir*.  Both are
    best-effort and never raise: an old kernel may apply only its supported
    subset or leave the daemon unconfined, with either outcome logged at debug
    level rather than preventing startup.
    """
    report = harden_self()
    if not report.fully_hardened:
        _logger.debug("shield reader hardening partial: %s", report)
    fs = confine_filesystem(_SYSTEM_READ_ROOTS, [state_dir])
    if fs.partially_confined:
        _logger.debug("shield reader filesystem-confinement partially applied: %s", fs.reason)
    elif not fs.confined:
        _logger.debug("shield reader filesystem-confinement not applied: %s", fs.reason)
