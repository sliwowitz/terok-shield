# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared OCI-hook ballast — used by both ``nft_hook`` and ``reader_hook``.

This module is shipped verbatim alongside the two role-specific hook
scripts and imported by them at runtime.  The role scripts add
``Path(__file__).parent`` to ``sys.path`` (Python does this implicitly
when ``python3 script.py`` is invoked, but the relative-import contract
is what the isolation test checks against), and from there ``from
_oci_state import …`` resolves to this file.

Stdlib-only by design (audited by ``test_hook_entrypoint_isolation``):
the OCI runtime executes us with ``/usr/bin/python3`` outside any
virtualenv, so a dependency on ``terok_shield`` would fail to import.

Keep in sync with the package-side definitions:

* ``BUNDLE_VERSION``    ↔ ``terok_shield.state.BUNDLE_VERSION``
* ``ANN_STATE_DIR``     ↔ ``terok_shield.config.ANNOTATION_STATE_DIR_KEY``
* ``ANN_VERSION``       ↔ ``terok_shield.config.ANNOTATION_VERSION_KEY``
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

# ── Annotation contract ──────────────────────────────────

ANN_STATE_DIR = "terok.shield.state_dir"
"""OCI annotation carrying the per-container shield state directory."""

ANN_VERSION = "terok.shield.version"
"""OCI annotation carrying the bundle version this container was prepared with."""

BUNDLE_VERSION = 11
"""Wire-protocol version for the hook ↔ pre_start state-bundle contract.

Bumped whenever the on-disk file layout, the hook → reader argv
shape, or the wire payload changes incompatibly.  The nft hook hard-
fails on a version mismatch — operator must re-run ``terok setup``.
"""


# ── OCI state parsing ────────────────────────────────────


def state_dir_from_oci(oci: object) -> Path | None:
    """Extract the ``terok.shield.state_dir`` annotation as an absolute Path.

    Returns ``None`` (and logs) on any validation failure so the caller
    can early-exit without hand-written boilerplate.
    """
    if not isinstance(oci, dict):
        log("terok-shield hook: OCI state must be a JSON object")
        return None
    ann = oci.get("annotations") or {}
    if not isinstance(ann, dict):
        log("terok-shield hook: annotations must be a JSON object")
        return None
    sd_str = ann.get(ANN_STATE_DIR, "")
    if not sd_str:
        log("terok-shield hook: missing state_dir annotation")
        return None
    try:
        path = Path(sd_str)
        if not path.is_absolute():
            raise ValueError(f"state_dir must be absolute: {sd_str!r}")
        return path.resolve()
    except (TypeError, ValueError, OSError) as exc:
        log(f"terok-shield hook: invalid state_dir: {exc}")
        return None


# ── Environment bootstrap ─────────────────────────────────


def bootstrap_env() -> None:
    """Ensure critical environment variables are set before running ``podman unshare``.

    OCI hooks (crun/runc) may be invoked with a stripped environment — no
    ``HOME``, no ``XDG_RUNTIME_DIR``, sometimes no ``PATH``.  Inside
    ``NS_ROOTLESS`` ``os.getuid()`` is the mapped 0; resolving resources
    naively would point at ``/root`` instead of the operator's real
    home.  ``outer_host_uid()`` parses ``/proc/self/uid_map`` to recover
    the host UID and we use that throughout.
    """
    uid = outer_host_uid()

    if not os.environ.get("HOME"):
        try:
            home = pwd.getpwuid(uid).pw_dir
        except KeyError:
            home = "/root" if uid == 0 else f"/home/{uid}"
        os.environ["HOME"] = home

    if not os.environ.get("XDG_RUNTIME_DIR"):
        os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"

    if not os.environ.get("PATH"):
        os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def outer_host_uid() -> int:
    """Return the invoking operator's host UID, even from inside ``NS_ROOTLESS``.

    Parses ``/proc/self/uid_map`` to find the outer-side UID that the
    current in-namespace UID maps to.  Each map line has the shape
    ``<inner_start> <outer_start> <length>`` — pick the mapping whose
    inner range covers ``os.getuid()`` and project through it.

    Falls back to ``os.getuid()`` on any parse trouble (init userns, no
    uid_map, unreadable, unexpected format) — that path is valid for
    non-rootless contexts where there's no userns layer to see through.
    """
    my_uid = os.getuid()
    try:
        raw = Path("/proc/self/uid_map").read_text()
    except OSError:
        return my_uid
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            inner_start = int(parts[0])
            outer_start = int(parts[1])
            length = int(parts[2])
        except ValueError:
            continue
        if inner_start <= my_uid < inner_start + length:
            return outer_start + (my_uid - inner_start)
    return my_uid


# ── Namespace execution ──────────────────────────────────


def nsenter(pid: str, *cmd: str, stdin: str | None = None) -> None:
    """Run *cmd* inside the container's network namespace.

    Two execution contexts are handled automatically:

    **OCI hook context (crun invokes the hook)** — crun runs inside
    podman's rootless user namespace (``NS_ROOTLESS``, where
    ``os.getuid() == 0`` and ``CAP_NET_ADMIN`` is available).  The hook
    inherits that namespace, so ``nsenter -n -t <pid>`` is sufficient.

    **Shell / manual invocation context** — the caller is in the
    initial user namespace (``NS_INIT``, uid != 0, no elevated caps).
    ``podman unshare`` enters ``NS_ROOTLESS`` first to gain
    ``CAP_NET_ADMIN``, then ``nsenter -n`` enters the container's
    network namespace.  Mirrors ``SubprocessRunner.nft_via_nsenter()``
    in run.py.

    Captures both stdout and stderr — some nft versions write errors
    to stdout.
    """
    if os.getuid() == 0:
        ns_cmd = [find_nsenter(), "-n", "-t", pid, "--", *cmd]
    else:
        ns_cmd = [find_podman(), "unshare", find_nsenter(), "-n", "-t", pid, "--", *cmd]
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            ns_cmd,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nsenter command timed out after 30 s: cmd={cmd!r}")
    if result.returncode != 0:
        combined = (result.stderr + result.stdout).strip()
        raise RuntimeError(
            f"nsenter command failed (exit {result.returncode}) cmd={cmd!r}"
            + (f":\n{combined}" if combined else " (no output)")
        )


def pid_exists(pid: int) -> bool:
    """Ask the kernel whether *pid* is still a running process."""
    try:
        # Signal 0 is an existence probe — never delivers a signal,
        # only triggers the kernel's PID-validity / permission check.
        os.kill(pid, 0)  # NOSONAR
    except ProcessLookupError:
        return False
    except OSError:
        # EPERM means the process exists but we don't own it — treat as alive.
        return True
    return True


# ── Binary finders ───────────────────────────────────────


def find_podman() -> str:
    """Path to the podman binary, falling back to ``/usr/bin/podman``."""
    return shutil.which("podman") or "/usr/bin/podman"


def find_nsenter() -> str:
    """Path to the nsenter binary, falling back to ``/usr/bin/nsenter``."""
    return shutil.which("nsenter") or "/usr/bin/nsenter"


def find_nft() -> str:
    """Path to the nft binary, falling back to ``/usr/sbin/nft``."""
    return shutil.which("nft") or "/usr/sbin/nft"


def find_dnsmasq() -> str:
    """Path to the dnsmasq binary, falling back to ``/usr/sbin/dnsmasq``."""
    return shutil.which("dnsmasq") or "/usr/sbin/dnsmasq"


# ── Logging ──────────────────────────────────────────────


def log(msg: str, log_path: Path | None = None) -> None:
    """Write *msg* to stderr and to a persistent log file (best-effort).

    The OCI runtime (crun/runc) typically swallows hook stderr.  Writing
    to a file in the state directory (or ``/tmp`` as fallback) makes
    errors visible.
    """
    print(msg, file=sys.stderr)
    path = log_path or Path("/tmp/terok-hook-error.log")  # nosec B108
    try:
        with path.open("a") as f:
            f.write(f"{msg}\n")
    except OSError:
        pass
