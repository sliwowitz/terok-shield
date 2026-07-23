# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Long-running event-reader verbs — watch, simple-clearance.

Both stream per-container events: ``watch`` multiplexes the DNS/audit/NFLOG
sources into a JSON-lines feed, and ``simple-clearance`` runs the terminal
verdict loop for hosts without the D-Bus hub.  Their heavy machinery
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
    from .._confine import confine_to_state
    from ..simple_clearance import run_simple_clearance

    confine_to_state(shield.config.state_dir)
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
