# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Self-confinement floor for shield's long-lived state reader.

``shield watch`` reads only its per-container ``state_dir`` — dnsmasq and
audit logs, the domain cache, the DNS-tier marker — plus the shared runtime
it imports from.  It writes nothing outside ``state_dir``.  Before the loop
starts, the reader pins itself to that lane: terok-util's process-hardening
floor plus Landlock filesystem confinement.  A bug in the reader then cannot
read another container's state and cannot write outside its own lane.  NFLOG
is a netlink socket, not a filesystem access, so confinement leaves it
untouched.

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
#: (interpreter, stdlib, site-packages) it keeps importing from.  The roots are
#: deliberately broad: the payoff is write isolation and cross-container read
#: isolation, not a minimal system-read surface.
_SYSTEM_READ_ROOTS: tuple[Path, ...] = (
    *(Path(p) for p in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev")),
    Path(sys.prefix),
    Path(sys.base_prefix),
)


def confine_to_state(state_dir: Path) -> None:
    """Harden this process and pin its filesystem to *state_dir* plus system reads.

    Applies terok-util's hardening floor, then Landlock-confines the process:
    read and execute the system roots, read and write only *state_dir*.  Both
    steps are best-effort and never raise.  An old kernel may apply only its
    supported subset, or may leave the daemon unconfined.  The reader logs
    either outcome at debug level and starts anyway.
    """
    report = harden_self()
    if not report.fully_hardened:
        _logger.debug("shield reader hardening partial: %s", report)
    fs = confine_filesystem(_SYSTEM_READ_ROOTS, [state_dir])
    if fs.partially_confined:
        _logger.debug("shield reader filesystem-confinement partially applied: %s", fs.reason)
    elif not fs.confined:
        _logger.debug("shield reader filesystem-confinement not applied: %s", fs.reason)
