# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Reading a task's audit log back as promotion candidates.

Harvest collects nothing new — it folds the lines the NFLOG reader already
wrote into one entry per target, which is the unit a promotion decision is
made in.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from terok_shield.harvest import (
    HARVESTED_ACTIONS,
    REMEDY_HOST_PORT,
    REMEDY_OVERRIDE,
    REMEDY_PROJECT,
    REMEDY_SET,
    REMEDY_TASK,
    TIER_ALLOWLIST,
    TIER_HARD_DENY,
    TIER_OPERATOR_DENY,
    TIER_PRIVATE,
    TIER_SECURITY,
    HarvestEntry,
    HarvestReport,
    harvest,
)
from terok_shield.nft.constants import PASTA_HOST_LOOPBACK_MAP
from terok_shield.resources import nflog_reader as reader
from terok_shield.state import StateBundle

from ..testfs import AUDIT_FILENAME
from ..testnet import (
    AWS_IMDS_V4,
    AWS_IMDS_V6,
    BLOCKED_DOMAIN,
    BLOCKED_SUBDOMAIN,
    BROAD_CIDR_8,
    IPV6_LINK_LOCAL,
    IPV6_ULA,
    PASTA_LINK_LOCAL_DNS,
    RFC1918_HOST,
    SLIRP4NETNS_GATEWAY,
    SLIRP4NETNS_GATEWAY_V6,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_IP1,
    TEST_IP2,
    TEST_IP3,
    TEST_IP4,
    TEST_IP99,
    VAULT_HOST,
    VAULT_SUBDOMAIN,
)

CONTAINER = "test-ctr"


def _write_log(state_dir: Path, *records: dict) -> None:
    """Write *records* as the container's audit log, one JSON object per line."""
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / AUDIT_FILENAME).write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )


def _blocked(ts: str, dest: str = TEST_IP1, *, domain: str = "", port: int = 443) -> dict:
    """One refusal, the shape the reader appends."""
    return _line("blocked", ts, dest, domain=domain, port=port)


def _line(action: str, ts: str, dest: str, *, domain: str = "", port: int = 443) -> dict:
    """One reader line for *action*, the shape the reader appends."""
    record: dict = {
        "ts": ts,
        "container": CONTAINER,
        "action": action,
        "dest": dest,
        "port": port,
        "proto": "tcp",
    }
    if domain:
        record["domain"] = domain
    return record


_TS = "2026-09-30T10:00:00+00:00"
_ORDINARY = (TIER_ALLOWLIST, (REMEDY_TASK, REMEDY_PROJECT, REMEDY_SET))
_OPERATOR = (TIER_OPERATOR_DENY, (REMEDY_TASK, REMEDY_PROJECT))
_SECURITY = (TIER_SECURITY, (REMEDY_OVERRIDE,))
_PRIVATE = (TIER_PRIVATE, (REMEDY_OVERRIDE,))
_FLOOR = (TIER_HARD_DENY, ())
_HOST_LOOPBACK = (TIER_HARD_DENY, (REMEDY_HOST_PORT,))


def _standing(entry: HarvestEntry) -> tuple[str, tuple[str, ...]]:
    """*entry*'s tier and the remedies it offers — the pair the standings above spell out."""
    return entry.tier, entry.remedies


def _bundle_with_tiers(state_dir: Path) -> StateBundle:
    """A bundle whose refusing tiers the classification reads.

    The security tier denies ``VAULT_HOST``, resolved to ``TEST_IP3``; the
    operator denied ``TEST_IP4`` outright and ``BLOCKED_DOMAIN``, which
    resolved to ``TEST_IP99``.
    """
    bundle = StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n")
    bundle.deny_resolved.write_text(f"{VAULT_HOST} {TEST_IP3}\n")
    bundle.overlay_set("-", TEST_IP4)
    bundle.overlay_set("-", BLOCKED_DOMAIN)
    bundle.live_deny_resolved.write_text(f"{BLOCKED_DOMAIN} {TEST_IP99}\n")
    return bundle


def test_no_log_harvests_nothing(tmp_path: Path) -> None:
    """A task that never tried anything has no log, and no entries."""
    report = harvest(tmp_path)

    assert report.entries == ()
    assert report.audit_enabled


def test_a_log_that_cannot_be_read_is_an_error_never_an_empty_harvest(tmp_path: Path) -> None:
    """An empty report would read as an all-clear; the error names the log instead."""
    log = StateBundle(tmp_path).audit
    log.mkdir(
        parents=True
    )  # a directory where the log belongs: open() fails, not FileNotFoundError

    with pytest.raises(RuntimeError, match=f"the audit log {re.escape(str(log))} cannot be read"):
        harvest(tmp_path)


def test_refusals_group_by_target(tmp_path: Path) -> None:
    """Repeated refusals to one host are one entry with a count, not three rows."""
    _write_log(
        tmp_path,
        _blocked("2026-09-30T10:00:00+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:00:31+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:01:02+00:00", domain=TEST_DOMAIN),
    )

    (entry,) = harvest(tmp_path)

    assert entry == HarvestEntry(
        action="blocked",
        target=TEST_DOMAIN,
        count=3,
        first_seen="2026-09-30T10:00:00+00:00",
        last_seen="2026-09-30T10:01:02+00:00",
        ports=(443,),
        addresses=(TEST_IP1,),
    )


def test_the_domain_is_the_target_when_the_reader_recovered_one(tmp_path: Path) -> None:
    """An allowlist entry for a rotating CDN is worth nothing as an IP."""
    _write_log(
        tmp_path,
        _blocked("2026-09-30T10:00:00+00:00", dest=TEST_IP1, domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:05:00+00:00", dest=TEST_IP2, domain=TEST_DOMAIN),
    )

    (entry,) = harvest(tmp_path)

    assert entry.target == TEST_DOMAIN
    assert entry.addresses == (TEST_IP1, TEST_IP2)


def test_an_address_stands_in_when_no_domain_was_recovered(tmp_path: Path) -> None:
    """Without a domain the address is all there is to promote."""
    _write_log(tmp_path, _blocked("2026-09-30T10:00:00+00:00", dest=TEST_IP1))

    (entry,) = harvest(tmp_path)

    assert entry.target == TEST_IP1
    assert entry.addresses == ()


def test_window_accepts_are_harvested_too(tmp_path: Path) -> None:
    """What the bypass window let through is exactly what the task turned out to need."""
    _write_log(
        tmp_path,
        {
            "ts": "2026-09-30T10:00:00+00:00",
            "container": CONTAINER,
            "action": "bypass",
            "dest": TEST_IP2,
            "port": 80,
            "proto": "tcp",
            "domain": TEST_DOMAIN2,
        },
    )

    (entry,) = harvest(tmp_path)

    assert (entry.action, entry.target, entry.ports) == ("bypass", TEST_DOMAIN2, (80,))


def test_refusals_come_first_then_the_loudest(tmp_path: Path) -> None:
    """Ordering puts the entry an operator is most likely to act on at the top."""
    _write_log(
        tmp_path,
        {
            "ts": "2026-09-30T10:00:00+00:00",
            "container": CONTAINER,
            "action": "bypass",
            "dest": TEST_IP2,
            "port": 80,
            "proto": "tcp",
        },
        _blocked("2026-09-30T10:00:00+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:01:00+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:02:00+00:00", dest=TEST_IP1),
    )

    entries = harvest(tmp_path)

    assert [(e.action, e.target) for e in entries] == [
        ("blocked", TEST_DOMAIN),
        ("blocked", TEST_IP1),
        ("bypass", TEST_IP2),
    ]


@pytest.mark.parametrize(
    "action",
    ["setup", "allowed", "denied", "shield_down", "bypass_armed", "note", "error"],
)
def test_the_operators_own_entries_are_not_candidates(tmp_path: Path, action: str) -> None:
    """Posture changes and verdicts say nothing about what the task reached for."""
    _write_log(
        tmp_path,
        {"ts": "2026-09-30T10:00:00+00:00", "container": CONTAINER, "action": action},
    )

    assert harvest(tmp_path).entries == ()


def test_a_truncated_line_does_not_stop_the_read(tmp_path: Path) -> None:
    """Two writers append to this log; a half-written final line is ordinary."""
    state_dir = tmp_path
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / AUDIT_FILENAME).write_text(
        json.dumps(_blocked("2026-09-30T10:00:00+00:00", domain=TEST_DOMAIN)) + '\n{"ts": "2026'
    )

    (entry,) = harvest(state_dir)

    assert entry.target == TEST_DOMAIN


def test_a_stray_byte_costs_only_its_own_line(tmp_path: Path) -> None:
    """A non-UTF-8 byte mid-log drops its line — not the rest, nor as a mangled target."""
    good = json.dumps(_blocked(_TS, domain=TEST_DOMAIN)).encode()
    stray = (
        json.dumps(_blocked(_TS, domain=TEST_DOMAIN2))
        .encode()
        .replace(TEST_DOMAIN2.encode(), TEST_DOMAIN2.encode() + b"\xff")
    )
    (tmp_path / AUDIT_FILENAME).write_bytes(b"\n".join((good, stray, good)) + b"\n")

    (entry,) = harvest(tmp_path)

    assert entry.target == TEST_DOMAIN
    assert entry.count == 2


def test_a_bare_carriage_return_still_ends_a_line(tmp_path: Path) -> None:
    """A lone CR separates records, as it always did for a text-mode read."""
    records = (_blocked(_TS, domain=TEST_DOMAIN), _blocked(_TS, domain=TEST_DOMAIN2))
    (tmp_path / AUDIT_FILENAME).write_bytes(
        b"".join(json.dumps(record).encode() + b"\r" for record in records)
    )

    assert {entry.target for entry in harvest(tmp_path)} == {TEST_DOMAIN, TEST_DOMAIN2}


def test_a_line_nested_past_the_parser_costs_only_its_own_line(tmp_path: Path) -> None:
    """Nesting too deep for the JSON parser is one more line it cannot read, not a crash."""
    good = json.dumps(_blocked(_TS, domain=TEST_DOMAIN)).encode()
    too_deep = b"[" * 200_000
    (tmp_path / AUDIT_FILENAME).write_bytes(b"\n".join((good, too_deep, good)) + b"\n")

    (entry,) = harvest(tmp_path)

    assert entry.count == 2


def test_a_record_without_a_target_is_skipped(tmp_path: Path) -> None:
    """Nothing to promote, nothing to show — a refusal with a port but no destination either."""
    _write_log(
        tmp_path,
        {
            "ts": "2026-09-30T10:00:00+00:00",
            "container": CONTAINER,
            "action": "blocked",
            "port": 443,
            "proto": "tcp",
        },
    )

    assert harvest(tmp_path).entries == ()


# ── What else the reader records ─────────────────────────


@pytest.mark.parametrize("action", ["down", "security_deny", "private_range"])
def test_the_newer_reader_actions_are_harvested(tmp_path: Path, action: str) -> None:
    """What DOWN let through and what the t20 set and the floors refused are candidates too."""
    _write_log(tmp_path, _line(action, _TS, TEST_IP1, domain=TEST_DOMAIN))

    (entry,) = harvest(tmp_path)

    assert (entry.action, entry.target, entry.addresses) == (action, TEST_DOMAIN, (TEST_IP1,))


def test_a_host_line_named_like_a_reader_action_is_not_a_candidate(tmp_path: Path) -> None:
    """Only the reader's own lines count, and those always carry a port."""
    _write_log(
        tmp_path,
        {"ts": _TS, "container": CONTAINER, "action": "down", "dest": TEST_IP1},
    )

    assert harvest(tmp_path).entries == ()


# ── Classification: by destination, against the bundle ──


@pytest.mark.parametrize(
    ("action", "dest", "domain", "expected"),
    [
        pytest.param("blocked", TEST_IP1, "", _ORDINARY, id="blocked-ordinary"),
        pytest.param("bypass", TEST_IP1, TEST_DOMAIN, _ORDINARY, id="bypass-ordinary"),
        pytest.param("down", TEST_IP2, "", _ORDINARY, id="down-ordinary"),
        pytest.param("down", AWS_IMDS_V4, "", _FLOOR, id="down-imds"),
        pytest.param("private_range", AWS_IMDS_V6, "", _FLOOR, id="v6-imds-before-ula"),
        pytest.param("private_range", IPV6_LINK_LOCAL, "", _FLOOR, id="v6-link-local"),
        pytest.param(
            "private_range", PASTA_HOST_LOOPBACK_MAP, "", _HOST_LOOPBACK, id="host-loopback-map"
        ),
        pytest.param("blocked", PASTA_LINK_LOCAL_DNS, "", _FLOOR, id="quarantine-era-dns"),
        pytest.param("private_range", RFC1918_HOST, "", _PRIVATE, id="rfc1918"),
        pytest.param("private_range", IPV6_ULA, "", _PRIVATE, id="ula"),
        pytest.param("down", RFC1918_HOST, "", _PRIVATE, id="disengaged-lan"),
        pytest.param("security_deny", TEST_IP3, "", _SECURITY, id="vault-address"),
        pytest.param("down", TEST_IP3, "", _SECURITY, id="disengaged-vault-address"),
        pytest.param("blocked", TEST_IP1, VAULT_HOST, _SECURITY, id="vault-by-name"),
        pytest.param("down", TEST_IP1, VAULT_SUBDOMAIN, _SECURITY, id="vault-by-suffix"),
        pytest.param("security_deny", TEST_IP2, "", _SECURITY, id="deny-set-unaccounted"),
        pytest.param("security_deny", TEST_IP4, "", _OPERATOR, id="operator-address"),
        pytest.param("security_deny", TEST_IP99, BLOCKED_DOMAIN, _OPERATOR, id="operator-by-name"),
        pytest.param("blocked", TEST_IP1, BLOCKED_SUBDOMAIN, _OPERATOR, id="operator-by-suffix"),
    ],
)
def test_entries_are_classified_by_destination(
    tmp_path: Path,
    action: str,
    dest: str,
    domain: str,
    expected: tuple[str, tuple[str, ...]],
) -> None:
    """The tier that stands in the way, and what could lift it, follow from where the task went.

    The action alone cannot tell: one prefix covers the hard-deny floor and
    the private ranges, a DISENGAGED shield logs everything as ``down``, and
    quarantine logs its drops as ``blocked``.
    """
    _bundle_with_tiers(tmp_path)
    _write_log(tmp_path, _line(action, _TS, dest, domain=domain))

    (entry,) = harvest(tmp_path)

    assert _standing(entry) == expected


def test_a_name_takes_the_most_restrictive_standing_of_its_addresses(tmp_path: Path) -> None:
    """A CDN front sharing a vault host's address is break-glass, whatever else it resolves to.

    An allow has to work for every address behind the name, and an ordinary
    allow cannot lift the security tier.
    """
    _bundle_with_tiers(tmp_path)
    _write_log(
        tmp_path,
        _line("down", _TS, TEST_IP1, domain=TEST_DOMAIN),
        _line("down", _TS, TEST_IP3, domain=TEST_DOMAIN),
    )

    (entry,) = harvest(tmp_path)

    assert entry.addresses == (TEST_IP1, TEST_IP3)
    assert _standing(entry) == _SECURITY


def test_the_security_tier_outranks_an_operator_deny_of_the_same_address(tmp_path: Path) -> None:
    """Lifting the operator's own deny would not get past a security-tier range around it."""
    bundle = _bundle_with_tiers(tmp_path)
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n-{BROAD_CIDR_8}\n")
    _write_log(tmp_path, _line("security_deny", _TS, TEST_IP4))

    (entry,) = harvest(tmp_path)

    assert _standing(entry) == _SECURITY


@pytest.mark.parametrize(
    ("network_mode", "dest", "expected"),
    [
        pytest.param("slirp4netns", SLIRP4NETNS_GATEWAY, _HOST_LOOPBACK, id="slirp-gateway"),
        pytest.param("slirp4netns", SLIRP4NETNS_GATEWAY_V6, _HOST_LOOPBACK, id="slirp-gateway-v6"),
        pytest.param("slirp4netns", RFC1918_HOST, _PRIVATE, id="slirp-lan"),
        pytest.param("pasta", SLIRP4NETNS_GATEWAY, _PRIVATE, id="pasta-lan"),
        pytest.param("pasta", PASTA_HOST_LOOPBACK_MAP, _HOST_LOOPBACK, id="pasta-map"),
    ],
)
def test_the_hosts_own_loopback_is_offered_the_host_port_grant_under_either_network_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    network_mode: str,
    dest: str,
    expected: tuple[str, tuple[str, ...]],
) -> None:
    """``host.containers.internal`` is the host's loopback, whatever address it maps to.

    Under slirp4netns that is the gateway, inside a private range — but the
    ruleset refuses it in t00, above every override, as pasta's map is: an
    override there would open every host-loopback port where a
    ``+localhost:PORT`` grant opens one.  The same address under pasta is an
    ordinary LAN host.
    """
    monkeypatch.setattr("terok_shield.podman_info.network._SYSTEM_CONF_PATHS", ())
    bundle = _bundle_with_tiers(tmp_path)
    bundle.network_mode.write_text(f"{network_mode}\n")
    if network_mode == "slirp4netns":
        bundle.record_gateways(SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6)
    _write_log(tmp_path, _line("private_range", _TS, dest))

    (entry,) = harvest(tmp_path)

    assert _standing(entry) == expected


def test_the_tier_and_remedy_names_are_a_contract() -> None:
    """An orchestrator matches on these strings, so a rename fails here first.

    Pinned as literals: built from the module's own constants on both sides,
    every other harvest test would pass a renamed value.
    """
    tiers = (TIER_ALLOWLIST, TIER_OPERATOR_DENY, TIER_SECURITY, TIER_PRIVATE, TIER_HARD_DENY)
    assert tiers == ("t40", "t20_operator", "t20_security", "t20_private", "t00")
    remedies = (REMEDY_TASK, REMEDY_PROJECT, REMEDY_SET, REMEDY_OVERRIDE, REMEDY_HOST_PORT)
    assert remedies == ("task", "project", "set", "override", "host_port")


def test_harvest_reads_every_action_the_reader_records() -> None:
    """A new reader action must be harvested too, or its lines are filtered out without a word."""
    assert set(HARVESTED_ACTIONS) == set(reader._TAG_ACTIONS.values())


def test_a_reader_line_without_a_destination_is_skipped(tmp_path: Path) -> None:
    """A line with a port but neither a domain nor an address names nothing to promote."""
    _write_log(
        tmp_path,
        {"ts": _TS, "container": CONTAINER, "action": "down", "port": 443, "proto": "tcp"},
    )

    assert harvest(tmp_path).entries == ()


def test_an_unparsable_address_leaves_the_name_to_decide(tmp_path: Path) -> None:
    """A garbled address claims no tier; the name behind it still does."""
    _bundle_with_tiers(tmp_path)
    _write_log(
        tmp_path,
        _line("down", _TS, "not-an-address", domain=TEST_DOMAIN),
        _line("down", _TS, "not-an-address", domain=VAULT_HOST),
    )

    standings = {e.target: _standing(e) for e in harvest(tmp_path)}

    assert standings == {TEST_DOMAIN: _ORDINARY, VAULT_HOST: _SECURITY}


def test_entries_built_without_a_classification_read_as_ordinary() -> None:
    """``tier`` and ``remedies`` default to the ordinary allowlist miss, so old constructors work."""
    entry = HarvestEntry(
        action="blocked",
        target=TEST_DOMAIN,
        count=1,
        first_seen=_TS,
        last_seen=_TS,
        ports=(443,),
        addresses=(),
    )

    assert _standing(entry) == _ORDINARY


def test_review_order_puts_what_can_be_promoted_first_and_the_floor_last(tmp_path: Path) -> None:
    """Tier first, then within it refusals before window accepts before DOWN accepts, loudest first."""
    _bundle_with_tiers(tmp_path)
    _write_log(
        tmp_path,
        _line("private_range", _TS, AWS_IMDS_V4),
        _line("private_range", _TS, PASTA_HOST_LOOPBACK_MAP),
        _line("private_range", _TS, RFC1918_HOST),
        _line("security_deny", _TS, TEST_IP3),
        _line("security_deny", _TS, TEST_IP4),
        _line("down", _TS, TEST_IP2),
        _line("bypass", _TS, TEST_IP2),
        _blocked(_TS, TEST_IP1),
        _blocked(_TS, domain=TEST_DOMAIN),
        _blocked(_TS, domain=TEST_DOMAIN),
    )

    entries = harvest(tmp_path)

    assert [(e.action, e.target, e.tier) for e in entries] == [
        ("blocked", TEST_DOMAIN, TIER_ALLOWLIST),
        ("blocked", TEST_IP1, TIER_ALLOWLIST),
        ("bypass", TEST_IP2, TIER_ALLOWLIST),
        ("down", TEST_IP2, TIER_ALLOWLIST),
        ("security_deny", TEST_IP4, TIER_OPERATOR_DENY),
        ("security_deny", TEST_IP3, TIER_SECURITY),
        ("private_range", RFC1918_HOST, TIER_PRIVATE),
        ("private_range", PASTA_HOST_LOOPBACK_MAP, TIER_HARD_DENY),
        ("private_range", AWS_IMDS_V4, TIER_HARD_DENY),
    ]


# ── The report: audit on, or an empty harvest is no answer ──


def test_the_report_says_when_audit_was_disabled(tmp_path: Path) -> None:
    """With audit off the reader records nothing — "nothing harvested" would be a false all-clear."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.audit_flag.write_text("false\n")

    report = harvest(tmp_path)

    assert report == HarvestReport(entries=(), audit_enabled=False)


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        pytest.param("true\n", True, id="on"),
        pytest.param(None, True, id="never-recorded"),
        pytest.param("garbled\n", True, id="unreadable-value"),
    ],
)
def test_audit_counts_as_on_unless_the_bundle_says_off(
    tmp_path: Path, flag: str | None, expected: bool
) -> None:
    """Only an explicit ``false`` is off — the shield's default, and the reader's behaviour."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    if flag is not None:
        bundle.audit_flag.write_text(flag)

    assert harvest(tmp_path).audit_enabled is expected


def test_the_report_reads_as_its_entries(tmp_path: Path) -> None:
    """A caller that only ever listed the entries iterates and sizes the report unchanged."""
    _write_log(tmp_path, _blocked(_TS, domain=TEST_DOMAIN), _blocked(_TS, TEST_IP1))

    report = harvest(tmp_path)

    assert len(report) == 2
    assert list(report) == list(report.entries)
