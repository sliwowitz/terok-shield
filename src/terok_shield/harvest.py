# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""What a task reached for, read back out of its audit log.

A deny-by-default box is only workable if the operator can find out what the
policy refused and decide whether it should have.  That record already exists:
the NFLOG reader writes one line per refusal, one per accept through the timed
allow-all window, and one per connection the DOWN postures accepted only
because the shield was down, into the container's ``audit.jsonl``.  Harvest is
a *reader* over that file, not a second mechanism — nothing new is collected,
and nothing here writes policy.

Grouping is by target, the way a promotion decision is made: a domain when the
reader recovered one from the DNS cache, the address otherwise.  Counts come
from the log, and the reader records at most one line per target per 30 s, so a
count is a floor on how often the workload tried, never a connection count.

Every entry also says which tier stands between the task and the target, and
what could change that — classified by *destination*, not by the log line's
action alone.  The action cannot carry it: one prefix covers the hard-deny
floor and the private ranges alike, a DISENGAGED shield logs a vault host, IMDS
and a LAN address all as ``down``, and quarantine logs its drops as
``blocked``.  The destination, checked against the bundle's own tiers, can.
"""

import ipaddress
import json
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from itertools import chain
from pathlib import Path

from .nft.constants import HARD_DENY_RANGES, PASTA_HOST_LOOPBACK_MAP, PRIVATE_RANGES
from .policy import is_ip
from .state import SecurityTier, StateBundle

#: Audit actions the workload's own traffic produces, in review order.
#: Everything else in the log is the operator's or the shield's own doing —
#: setup steps, posture changes, runtime allow/deny verdicts — and says nothing
#: about what the task needed.  ``security_deny`` is not ``denied``: the latter
#: is the operator's own ``Shield.deny()`` verdict, never a candidate.
HARVESTED_ACTIONS = ("blocked", "bypass", "down", "security_deny", "private_range")

# ── Tiers: what stands between the task and the target ──

TIER_ALLOWLIST = "t40"
"""No refusing tier claims the target: the allowlist simply does not name it."""
TIER_OPERATOR_DENY = "t20_operator"
"""The operator's own runtime deny (a ``-`` line in ``policy/live``) refuses it."""
TIER_SECURITY = "t20_security"
"""The security tier refuses it — by name, by a domain above it, or by address."""
TIER_PRIVATE = "t20_private"
"""A private range (RFC 1918, RFC 4193 ULA) refuses it."""
TIER_HARD_DENY = "t00"
"""The hard-deny floor (link-local, IMDS) refuses it — above every override."""

# ── Remedies: what could let the task reach it, in preference order ──

REMEDY_TASK = "task"
"""Allow it for this task — live, or from its next start when it is stopped."""
REMEDY_PROJECT = "project"
"""Allow it for every task of the project (``shield.allow``)."""
REMEDY_SET = "set"
"""Enable a curated egress set that names it, or add it to a user set."""
REMEDY_OVERRIDE = "override"
"""A break-glass ``shield.override``, with a reason and an expiry."""
REMEDY_HOST_PORT = "host_port"
"""A ``+localhost:PORT`` grant — the target is the host's own loopback, mapped."""

#: Every standing a destination can have, most restrictive first.  A target
#: several destinations stand behind (a name with more than one address) takes
#: the most restrictive of them: a remedy has to work for all of its addresses.
#: The host's own loopback — pasta's map inside the link-local floor, or the
#: slirp4netns gateway, which the ruleset refuses beside it — stands in t00,
#: above every override: only a ``+localhost:PORT`` grant reaches it, one port
#: at a time.
_STANDINGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (TIER_HARD_DENY, ()),
    (TIER_HARD_DENY, (REMEDY_HOST_PORT,)),
    (TIER_SECURITY, (REMEDY_OVERRIDE,)),
    (TIER_PRIVATE, (REMEDY_OVERRIDE,)),
    (TIER_OPERATOR_DENY, (REMEDY_TASK, REMEDY_PROJECT)),
    (TIER_ALLOWLIST, (REMEDY_TASK, REMEDY_PROJECT, REMEDY_SET)),
)
(
    _HARD_DENY,
    _HOST_LOOPBACK,
    _SECURITY,
    _PRIVATE,
    _OPERATOR_DENY,
    _ALLOWLIST,
) = _STANDINGS

#: Review order: what an operator can promote outright first, break-glass
#: next, the floor last.
_TIER_ORDER = (TIER_ALLOWLIST, TIER_OPERATOR_DENY, TIER_SECURITY, TIER_PRIVATE, TIER_HARD_DENY)

_HARD_DENY_NETS = tuple(ipaddress.ip_network(net) for net in HARD_DENY_RANGES)
_PRIVATE_NETS = tuple(ipaddress.ip_network(net) for net in PRIVATE_RANGES)


@dataclass(frozen=True, slots=True)
class HarvestEntry:
    """One destination a task reached for, what the shield did, and what could change it."""

    action: str
    """What the shield did, as the reader recorded it: ``blocked`` — refused by
    the terminal rule; ``bypass`` — let through by the timed allow-all window;
    ``down`` — accepted only because the shield was down; ``security_deny`` —
    refused by the t20 deny set; ``private_range`` — refused by a range floor."""
    target: str
    """The domain the reader recovered, or the address when it had none.

    This is what a promotion would name, which is why it is the grouping key:
    an allowlist entry for a rotating CDN is worth nothing as an IP.
    """
    count: int
    """Audit lines seen for this target.

    A floor on attempts, not a connection count: the reader records one line
    per target per 30 s, so a tight retry loop and a single request can both
    land as one.
    """
    first_seen: str
    last_seen: str
    ports: tuple[int, ...]
    """Destination ports, ascending — a promotion candidate on 443 and one on
    25 deserve different scrutiny."""
    addresses: tuple[str, ...]
    """Addresses seen behind *target*, in first-seen order; empty when the
    target is itself an address."""
    tier: str = TIER_ALLOWLIST
    """The tier that stands between the task and the target: ``t40`` when no
    refusing tier claims it (the allowlist just does not name it),
    ``t20_operator`` for the operator's own runtime deny, ``t20_security`` for
    the security tier (vault-relayed hosts above all), ``t20_private`` for a
    private range, ``t00`` for the hard-deny floor.  Read from the
    destination against the container's bundle, so a ``down`` line from a
    DISENGAGED shield lands in the tier that would refuse it once the shield
    is back up.  Defaults to the ordinary ``t40`` case."""
    remedies: tuple[str, ...] = (REMEDY_TASK, REMEDY_PROJECT, REMEDY_SET)
    """What could let the task reach the target, in preference order: ``task``
    / ``project`` (an allow), ``set`` (a curated or user set), ``override``
    (break-glass, with a reason and an expiry), ``host_port`` (a
    ``+localhost:PORT`` grant for the host's own loopback — pasta's map or
    the slirp4netns gateway, both refused in ``t00``, above every override).
    Empty for the rest of the hard-deny floor, which nothing reaches.
    Defaults to the remedies of the ordinary ``t40`` case."""


@dataclass(frozen=True, slots=True)
class HarvestReport:
    """What [`harvest`][terok_shield.harvest.harvest] found, and whether it could find anything.

    An empty harvest means two different things depending on
    ``audit_enabled``: with audit on, the task reached for nothing it could
    not have; with audit off, the reader recorded nothing to begin with, so
    the emptiness says nothing about the task.  A caller shows the second as
    such rather than as an all-clear.

    Iterating the report yields its entries, and its length is theirs, so a
    caller that only ever listed the entries reads it unchanged.
    """

    entries: tuple[HarvestEntry, ...] = ()
    """The harvested entries, in review order."""
    audit_enabled: bool = True
    """Whether audit was on when the container was created — the flag its
    NFLOG reader honoured."""

    def __iter__(self) -> Iterator[HarvestEntry]:
        """Yield the entries, in review order."""
        return iter(self.entries)

    def __len__(self) -> int:
        """Return how many entries were harvested."""
        return len(self.entries)


@dataclass
class _Tally:
    """Mutable accumulator for one ``(action, target)`` pair."""

    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    ports: set[int] = field(default_factory=set)
    addresses: dict[str, None] = field(default_factory=dict)

    def add(self, record: dict) -> None:
        """Fold one reader line (``_records`` vouches for its port) into the tally.

        Keeps first/last seen honest whatever order the lines come in.
        """
        timestamp = str(record.get("ts", ""))
        self.count += 1
        self.first_seen = min(self.first_seen, timestamp) if self.first_seen else timestamp
        self.last_seen = max(self.last_seen, timestamp)
        self.ports.add(record["port"])
        dest = record.get("dest")
        if record.get("domain") and isinstance(dest, str):
            self.addresses[dest] = None


@dataclass(frozen=True)
class _Tiers:
    """The refusing tiers a container's bundle records, read once per harvest."""

    security: SecurityTier
    """The t20 security tier — what only a break-glass override gets past."""
    operator: SecurityTier
    """The operator's runtime denies (``-`` lines of ``policy/live``), matched
    the way the security tier is — by name, by a domain above it, by address —
    but liftable by an ordinary allow."""
    host: frozenset[str] = frozenset()
    """The addresses through which the container reaches the host's own
    loopback under its recorded network mode — what ``host.containers.internal``
    names.  A ``+localhost:PORT`` grant reaches them; an override never may."""

    @classmethod
    def read(cls, bundle: StateBundle) -> "_Tiers":
        """Read both deny sources, and the host's loopback addresses, out of *bundle*."""
        return cls(
            security=bundle.read_security_tier(),
            operator=SecurityTier(
                names=tuple(bundle.read_effective().live_deny_targets()),
                addresses=tuple(sorted(bundle.read_live_denied_ips())),
            ),
            host=bundle.host_loopback(),
        )

    def standing(
        self, action: str, target: str, addresses: Sequence[str]
    ) -> tuple[str, tuple[str, ...]]:
        """The tier between the task and *target*, and its remedies — the most restrictive found.

        The name is checked against both deny sources, then every address
        behind it: the hard-deny floor first (``fd00:ec2::254`` is inside the
        ULA range, and only the floor reaches it), then the security tier,
        the private ranges and the operator's denies.  A ``security_deny``
        line no destination accounts for any more — a cache rotated since —
        stays with the security tier: the t20 set refused it, and the half
        that an ordinary allow may lift is the half the bundle still names.
        """
        found = [self._name_standing(target), *(self._address_standing(a) for a in addresses)]
        standings = [standing for standing in found if standing is not None]
        if action == "security_deny" and not standings:
            standings.append(_SECURITY)
        elif action == "private_range" and not standings:
            standings.append(_PRIVATE)
        return min(standings, key=_STANDINGS.index, default=_ALLOWLIST)

    def _name_standing(self, target: str) -> tuple[str, tuple[str, ...]] | None:
        """The standing a domain *target* has by name alone; ``None`` for an address."""
        if is_ip(target):
            return None
        if self.security.name_refusing(target) is not None:
            return _SECURITY
        if self.operator.name_refusing(target) is not None:
            return _OPERATOR_DENY
        return None

    def _address_standing(self, address: str) -> tuple[str, tuple[str, ...]] | None:
        """The standing one destination address has, or ``None`` when no tier claims it."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if any(ip in net for net in _HARD_DENY_NETS):
            # The pasta map is the host's own loopback, reached through a
            # ``+localhost:PORT`` grant in the preamble, above the floor.
            return _HOST_LOOPBACK if str(ip) == PASTA_HOST_LOOPBACK_MAP else _HARD_DENY
        if any(ip == ipaddress.ip_address(host) for host in self.host):
            # The slirp4netns gateway is the host's loopback too.  It lies in
            # a private range, but the ruleset refuses it in t00, above every
            # override — an override there would open every port the host
            # listens on locally — so the per-port grant is the remedy.
            return _HOST_LOOPBACK
        if self.security.address_refusing(address) is not None:
            return _SECURITY
        if any(ip in net for net in _PRIVATE_NETS):
            return _PRIVATE
        if self.operator.address_refusing(address) is not None:
            return _OPERATOR_DENY
        return None


def harvest(state_dir: Path) -> HarvestReport:
    """Summarise what the container in *state_dir* reached for.

    Entries come in review order: what an operator can promote outright first,
    then break-glass, then what nothing reaches — and within each tier
    refusals before window accepts before what the DOWN posture let through,
    then by how often the target appeared and by name.  A missing audit log
    yields no entries: a task that never tried anything has none.  A log that
    exists but cannot be read is an error, never an empty harvest — the
    operator decides what to allow from this report, and a false all-clear
    would mislead that decision.  The report says whether audit was on at
    all, which is the one reason an empty harvest is not an answer.

    Raises:
        RuntimeError: The audit log exists but cannot be read; the message
            names its path.
    """
    bundle = StateBundle(state_dir)
    tallies = _tally(_records(bundle.audit))
    entries = _entries(tallies, _Tiers.read(bundle)) if tallies else []
    return HarvestReport(entries=tuple(entries), audit_enabled=bundle.read_audit_enabled())


def _records(path: Path) -> Iterator[dict]:
    """Yield the harvestable records of an audit log, skipping what it cannot parse.

    The log is appended by two writers — the host-side shield and the in-netns
    NFLOG reader — so a truncated final line is an ordinary sight after a kill,
    not corruption to report.  Lines break where a text-mode read breaks them,
    a lone carriage return included, and each is decoded and parsed on its
    own, strictly: a stray non-UTF-8 byte or a line nested deeper than the
    parser follows costs that line alone, and a bad byte never reaches a
    target as a replacement character.  Only the reader's own lines count, and
    those always carry a port: a host-side line never does, so no host action
    that happens to share a harvested name can pass for one.
    """
    try:
        with path.open("rb") as handle:
            for line in chain.from_iterable(map(bytes.splitlines, handle)):
                try:
                    record = json.loads(line.decode("utf-8"))
                except (ValueError, RecursionError):
                    continue
                if (
                    isinstance(record, dict)
                    and record.get("action") in HARVESTED_ACTIONS
                    and isinstance(record.get("port"), int)
                ):
                    yield record
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError(f"the audit log {path} cannot be read: {exc}") from exc


def _tally(records: Iterable[dict]) -> dict[tuple[str, str], _Tally]:
    """Fold records into one tally per ``(action, target)``."""
    tallies: dict[tuple[str, str], _Tally] = {}
    for record in records:
        target = record.get("domain") or record.get("dest")
        if not isinstance(target, str) or not target:
            continue
        tallies.setdefault((str(record["action"]), target), _Tally()).add(record)
    return tallies


def _entries(tallies: dict[tuple[str, str], _Tally], tiers: _Tiers) -> list[HarvestEntry]:
    """Turn tallies into classified entries, ordered for review."""
    entries: list[HarvestEntry] = []
    for (action, target), tally in tallies.items():
        addresses = tuple(tally.addresses)
        destinations = addresses or ((target,) if is_ip(target) else ())
        tier, remedies = tiers.standing(action, target, destinations)
        entries.append(
            HarvestEntry(
                action=action,
                target=target,
                count=tally.count,
                first_seen=tally.first_seen,
                last_seen=tally.last_seen,
                ports=tuple(sorted(tally.ports)),
                addresses=addresses,
                tier=tier,
                remedies=remedies,
            )
        )
    entries.sort(key=_review_key)
    return entries


def _review_key(entry: HarvestEntry) -> tuple[int, bool, int, int, str]:
    """Sort key: tier, then remedy-less last, then action, loudest first, then name."""
    return (
        _rank(_TIER_ORDER, entry.tier),
        not entry.remedies,
        _rank(HARVESTED_ACTIONS, entry.action),
        -entry.count,
        entry.target,
    )


def _rank(order: Sequence[str], value: str) -> int:
    """Position of *value* in *order*; anything unknown sorts after every known value."""
    return order.index(value) if value in order else len(order)
