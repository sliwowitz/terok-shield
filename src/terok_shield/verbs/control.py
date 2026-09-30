# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Live nft-mutation verbs — allow, deny, override, up, down, bypass, quarantine, rules, preview.

Each verb mutates or inspects a running container's shield ruleset.  The
handlers accept ``(shield, [container], **kwargs)`` and print to stdout;
the CLI dispatcher builds the [`Shield`][terok_shield.Shield] and forwards
the parsed argv.
"""

from __future__ import annotations

import argparse
import re
from datetime import date
from typing import TYPE_CHECKING

from terok_util import ArgDef, CommandDef

from ..config import OverrideRevocation, ShieldState
from ..state import SecurityTierRefusal
from ._common import (
    CONTAINER_ARG,
    CONTAINER_ID_ARG,
    NEEDS_CTR,
    PROFILES_ARG,
    format_seconds,
    print_rotation_risk,
)

if TYPE_CHECKING:
    from terok_shield import Shield


def _handle_allow(shield: Shield, container: str, *, target: str) -> None:
    """Allow a domain or IP — live on a running container, from the next start on a stopped one.

    A target the security tier refuses fails the verb with the reason, the
    shared address when that is it, and the one way through: a clearance
    popup shows exactly this stderr line, so it must say what to do next.
    """
    try:
        result = shield.allow(container, target)
    except SecurityTierRefusal as refusal:
        raise RuntimeError(
            f"{refusal}: use a shield.override (reason + expires) to reach it directly"
        ) from refusal
    if not result.live:
        print(
            f"{container} is not running: recorded {target} in its runtime overlay, "
            "which applies at its next start"
        )
    elif result.ips:
        print(f"Allowed {target} -> {', '.join(result.ips)} for {container}")
    else:
        raise RuntimeError(f"No IPs allowed for {container}")


_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
"""The one ``--expires`` spelling the verb takes: a calendar date, ``YYYY-MM-DD``."""

_ESTABLISHED_KEEP_RUNNING = (
    "That stops new connections only: any already open keep running until they close"
)
"""What an override's end leaves alone, said wherever the verb reports one.

The ruleset accepts established traffic ahead of every tier, so neither an
expiry nor a revoke cuts a connection the override let through — a tunnel or
a keep-alive keeps the direct route.  An operator, or an agent, told only
"closed" would expect otherwise.
"""


def _expiry_date(value: str) -> date:
    """Parse ``--expires`` — the last day an override holds — as a calendar date.

    Only the form an operator writes is taken here.  The ISO timestamp the
    policy grammar also accepts stays for authored policy, so the record a
    live grant leaves is always a plain date.  Whether the date is still
    ahead is the shield's call: a date already past reaches it and is
    refused in the shield's own words.

    Raises:
        argparse.ArgumentTypeError: When *value* is not ``YYYY-MM-DD`` or
            names no day of the calendar.
    """
    text = value.strip()
    if _ISO_DATE.fullmatch(text):
        try:
            return date.fromisoformat(text)
        except ValueError:  # 2026-02-30 and the like
            pass
    raise argparse.ArgumentTypeError(f"{value!r} is not a date: expected YYYY-MM-DD")


def _handle_override(
    shield: Shield,
    container: str,
    *,
    target: str,
    expires: date | None = None,
    reason: str | None = None,
    off: bool = False,
) -> None:
    """Grant a break-glass override above the security tier, or revoke one with ``--off``.

    A grant needs both ``--expires`` and ``--reason``, because a break-glass
    says until when it holds and why it exists, and the shield records both.
    ``--off`` ends the override now, so it takes neither.  Every refusal —
    the hard-deny floor, the host's own loopback, a date already past, a
    target with no override to revoke — is the shield's own, word for word.
    The verb adds no rule of its own on top.

    Raises:
        ValueError: When a grant is missing a flag, when ``--off`` is given
            either, and for each refusal of the target or the date.
        RuntimeError: When the container has no running ruleset to take a
            grant, or no override in force to revoke.
    """
    if off:
        if expires is not None or reason is not None:
            raise ValueError("--off revokes the override now: it takes no --expires or --reason")
        _print_revocation(container, shield.revoke_override(container, target))
        return
    if expires is None or reason is None:
        missing = " and ".join(
            flag for flag, given in (("--expires", expires), ("--reason", reason)) if given is None
        )
        raise ValueError(
            f"granting an override needs {missing}: a break-glass says until when it holds "
            "and why it exists (--off revokes one instead)"
        )
    opened = shield.override(container, target, expires, reason=reason)
    print(f"Override open for {container}: {target} -> {', '.join(opened)}")
    print(
        f"Valid through {expires.isoformat()}: the kernel closes it at the end of that day, "
        "host local time"
    )
    print(_ESTABLISHED_KEEP_RUNNING)


def _print_revocation(container: str, revoked: OverrideRevocation) -> None:
    """Say what a revoke closed, when it holds, and what another override keeps open.

    A running container also hears that connections already open survive the
    revoke: only new ones are refused.  A stopped one has none to keep.
    """
    if revoked.live:
        closed = f"closed {', '.join(revoked.closed)}" if revoked.closed else "no address closed"
        print(f"Override of {revoked.target} revoked for {container}: {closed}")
        print(_ESTABLISHED_KEEP_RUNNING)
    else:
        print(
            f"{container} is not running: revoked the override of {revoked.target} from its "
            "bundle, so its next start does not open it"
        )
    if revoked.kept:
        print(
            "Still open above the security tier through another override: "
            f"{', '.join(revoked.kept)}"
        )


def _handle_deny(shield: Shield, container: str, *, target: str) -> None:
    """Live-deny a domain or IP."""
    ips = shield.deny(container, target)
    if ips:
        print(f"Denied {target} ({', '.join(ips)}) for {container}")
    else:
        raise RuntimeError(f"No IPs denied for {container}")


def _handle_down(
    shield: Shield,
    container: str,
    *,
    container_id: str,
    disengaged: bool = False,
) -> None:
    """Switch container to the DOWN posture.

    *container_id* — full podman UUID; supplied by the orchestrator at
    the call site, used to route the hub event to the supervisor's
    per-container socket.  Required, no default.

    Plain DOWN still enforces the security tier, so a tier that pins its
    names gets the deny warning on stderr; DISENGAGED enforces nothing to
    warn about.
    """
    shield.down(container, container_id, disengaged=disengaged)
    label = " (disengaged)" if disengaged else ""
    print(f"Shield down for {container}{label}")
    if not disengaged:
        print_rotation_risk(shield, ShieldState.DOWN)


def _handle_up(shield: Shield, container: str, *, container_id: str) -> None:
    """Restore deny-all mode.

    *container_id* — see ``_handle_down``.  The names the DNS tier pins to
    resolved addresses — allowlisted, break-glass, denied — follow on stderr.
    """
    shield.up(container, container_id)
    print(f"Shield up for {container}")
    print_rotation_risk(shield, ShieldState.UP)


def _handle_bypass(
    shield: Shield,
    container: str,
    *,
    duration: str | None = None,
    off: bool = False,
) -> None:
    """Show, open or close the timed allow-all window.

    With no flag the verb reports the kernel's own countdown, because that is
    the only record the window keeps — read with the posture from one listing.
    A ruleset that fails verification gets no window reading at all: it may
    hold a window element with no timeout, which has no countdown to show, and
    "no window open" would be the one answer it must not give.

    Raises:
        RuntimeError: When the container's ruleset is in the error state.
    """
    if off:
        shield.bypass_off(container)
        print(f"Bypass window closed for {container}")
        return
    if duration is None:
        reading = shield.inspect(container)
        if reading.state is ShieldState.ERROR:
            raise RuntimeError(
                f"{container}'s ruleset fails verification, so its window cannot be read — "
                f"inspect it with 'terok-shield rules {container}'; "
                f"'terok-shield bypass {container} --off' closes any window it holds"
            )
        remaining = reading.bypass_remaining
        print(
            f"No bypass window open for {container}"
            if remaining is None
            else f"Bypass window open for {container}, {format_seconds(remaining)} left"
        )
        return
    granted = shield.bypass(container, duration)
    print(
        f"Bypass window open for {container} for {granted} — what the allowlist refuses is "
        "accepted and logged; the security tier and private ranges stay refused"
    )


def _handle_reset(shield: Shield, container: str) -> None:
    """Forget DNS-learned allow state."""
    shield.reset(container)
    print(f"Shield reset for {container} — learned allow state forgotten")


def _handle_quarantine(shield: Shield, container: str) -> None:
    """Total network blackout."""
    shield.quarantine(container)
    print(f"Shield QUARANTINED for {container} — all traffic dropped")


def _handle_rules(shield: Shield, container: str) -> None:
    """Show nft rules for a container."""
    st = shield.state(container)
    print(f"State: {st.value}")
    rules = shield.rules(container)
    if rules.strip():
        print(rules)
    else:
        print(f"No rules found for {container}")


def _handle_preview(
    shield: Shield,
    *,
    down: bool = False,
    disengaged: bool = False,
    profiles: list[str] | None = None,
) -> None:
    """Show ruleset that would be applied."""
    if disengaged and not down:
        raise ValueError("--disengage requires --down")
    ruleset = shield.preview(down=down, disengaged=disengaged, profiles=profiles)
    label = ("disengaged" if disengaged else "down") if down else "up"
    print(f"# Ruleset preview ({label}):")
    print(ruleset)


ALLOW = CommandDef(
    name="allow",
    help="Allow a domain or IP for a container (live, or at its next start when stopped)",
    handler=_handle_allow,
    extras=NEEDS_CTR,
    epilog=(
        "A host the security tier denies (a vault-relayed provider host, or anything "
        "sharing its address) is refused: break-glass only, through an override."
    ),
    args=(CONTAINER_ARG, ArgDef(name="target", help="Domain name or IP address to allow")),
)

DENY = CommandDef(
    name="deny",
    help="Live-deny a domain or IP for a container",
    handler=_handle_deny,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG, ArgDef(name="target", help="Domain name or IP address to deny")),
)

OVERRIDE = CommandDef(
    name="override",
    help="Open a break-glass override above the security tier until a date, or revoke it",
    handler=_handle_override,
    extras=NEEDS_CTR,
    epilog=(
        "Grant (both flags are required):\n\n"
        "  terok-shield override my-ctr api.example.net --expires 2026-11-30 "
        '--reason "vendor outage"\n\n'
        "Revoke:\n\n"
        "  terok-shield override my-ctr api.example.net --off\n\n"
        "The override holds through the --expires date: the kernel closes it at\n"
        "the end of that day, host local time.  Closing it, then or with --off,\n"
        "stops new connections only: any already open keep running until they\n"
        "close.  The reason is recorded on the tier entry and in the audit log.\n"
        "No override opens the hard-deny floor (link-local, cloud metadata) or\n"
        "the host's own loopback, which a +localhost:PORT grant reaches one port\n"
        "at a time.  A grant lasts until it expires or a restart re-derives the\n"
        "policy: author it as shield.override to keep it."
    ),
    args=(
        CONTAINER_ARG,
        ArgDef(name="target", help="Domain name, IP address or CIDR to open (or close with --off)"),
        ArgDef(
            name="--expires",
            type=_expiry_date,
            help="Last day the override holds, YYYY-MM-DD, host local time (required to grant)",
        ),
        ArgDef(
            name="--reason",
            help="Why the break-glass is needed; recorded and audited (required to grant)",
        ),
        ArgDef(name="--off", action="store_true", help="Revoke the override now"),
    ),
)

DOWN = CommandDef(
    name="down",
    help="Switch container to the DOWN posture (accept + log; private ranges still rejected)",
    handler=_handle_down,
    extras=NEEDS_CTR,
    args=(
        CONTAINER_ARG,
        CONTAINER_ID_ARG,
        ArgDef(
            name="--disengage",
            action="store_true",
            dest="disengaged",
            help="Enforce nothing — lift the deny set and every range reject (DISENGAGED posture)",
        ),
    ),
)

UP = CommandDef(
    name="up",
    help="Restore deny-all mode for a container",
    handler=_handle_up,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG, CONTAINER_ID_ARG),
)

BYPASS = CommandDef(
    name="bypass",
    help="Open, close or show the timed allow-all window for a container",
    handler=_handle_bypass,
    extras=NEEDS_CTR,
    args=(
        CONTAINER_ARG,
        ArgDef(
            name="--for",
            dest="duration",
            help="Open the window for this long (an nft timeout such as 5m; default: bypass_duration)",
        ),
        ArgDef(name="--off", action="store_true", help="Close the window now"),
    ),
)

RESET = CommandDef(
    name="reset",
    help="Forget DNS-learned allow state (back to authored policy seeds)",
    handler=_handle_reset,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)

QUARANTINE = CommandDef(
    name="quarantine",
    help="Total network blackout (drop all, log dropped traffic)",
    handler=_handle_quarantine,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)

RULES = CommandDef(
    name="rules",
    help="Show current nft rules for a container",
    handler=_handle_rules,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)

PREVIEW = CommandDef(
    name="preview",
    help="Show ruleset that would be applied",
    handler=_handle_preview,
    epilog=(
        "With --profiles, the ruleset the hook applies at createRuntime for those "
        "profiles: their +localhost:PORT grants in the preamble, their literal IPs "
        "seeding the project-allow set.  Domains are learned by dnsmasq at runtime, "
        "not resolved here.  Needs no setup, podman or state:\n\n"
        "  terok-shield preview --profiles my-project > rules.nft"
    ),
    args=(
        PROFILES_ARG,
        ArgDef(name="--down", action="store_true", help="Show the DOWN-posture ruleset"),
        ArgDef(
            name="--disengage",
            action="store_true",
            dest="disengaged",
            help="Show the DISENGAGED ruleset: no deny set, no range rejects (requires --down)",
        ),
    ),
)
