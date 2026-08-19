# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Long-running event-stream verbs — watch, simple-clearance.

``watch`` is a state-only reader that multiplexes the DNS/audit/NFLOG sources
into one JSON-lines feed; it runs confined to its ``state_dir`` lane.
``simple-clearance`` is a controller that invokes Podman and verdict
subprocesses, so it does not use the reader's filesystem policy.  Their heavy machinery
([`watch`][terok_shield.watch] / [`simple_clearance`][terok_shield.simple_clearance])
is imported inside the handler bodies, so wiring these verbs — or resolving
their group module for ``--help`` — pulls in none of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from terok_util import CommandDef

from ._common import CONTAINER_ARG, NEEDS_CTR

if TYPE_CHECKING:
    from terok_shield import Shield


def _handle_watch(shield: Shield, container: str) -> None:
    """Stream blocked-access events as JSON lines."""
    from .._confine import confine_to_state
    from ..watch import run_watch

    confine_to_state(shield.config.state_dir)
    run_watch(shield.config.state_dir, container)


def _handle_simple_clearance(shield: Shield, container: str) -> None:
    """Run the terminal clearance fallback for hosts without the D-Bus hub."""
    from ..simple_clearance import run_simple_clearance

    run_simple_clearance(shield.config.state_dir, container)


WATCH = CommandDef(
    name="watch",
    help="Stream shield events — DNS blocks, audit log, NFLOG packets (requires dnsmasq tier)",
    handler=_handle_watch,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)

SIMPLE_CLEARANCE = CommandDef(
    name="simple-clearance",
    help="Terminal clearance fallback — prompts operator for each blocked connection (no D-Bus)",
    handler=_handle_simple_clearance,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)
