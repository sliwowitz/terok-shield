# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the unified ``+``/``-`` policy line format (``terok_shield.policy``)."""

from datetime import UTC, date, datetime, time, timedelta
from urllib.parse import unquote

import pytest

from terok_shield.policy import (
    EXPIRES_MARKER,
    LOCALHOST,
    REASON_MARKER,
    PolicyEntry,
    domain_targets,
    entry_deadline,
    expiry_deadline,
    ip_targets,
    is_ip,
    localhost_ports,
    marker_value,
    parse_policy,
    render_policy,
    render_target,
    validate_target,
)
from tests.testfs import FORBIDDEN_TRAVERSAL
from tests.testnet import (
    DEV_PYPI_DOMAIN,
    IPV6_NET1,
    IPV6_VERBOSE_CANONICAL,
    LINK_LOCAL_DNS,
    RFC1918_CIDR_10,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_DOMAIN_ATTACK,
    TEST_IP1,
    TEST_NET1,
)

WILDCARD = f"*.{TEST_DOMAIN2}"


def test_parses_allow_and_deny() -> None:
    """A leading ``+``/``-`` becomes the entry action."""
    assert parse_policy(f"+{TEST_DOMAIN}\n-{DEV_PYPI_DOMAIN}\n") == [
        PolicyEntry("+", TEST_DOMAIN),
        PolicyEntry("-", DEV_PYPI_DOMAIN),
    ]


def test_ignores_blank_and_comment_lines() -> None:
    """Blank lines and full-line ``#`` comments are skipped."""
    assert parse_policy(f"\n# a comment\n   \n+{TEST_DOMAIN}\n") == [PolicyEntry("+", TEST_DOMAIN)]


@pytest.mark.parametrize(
    "target",
    [
        TEST_DOMAIN,
        WILDCARD,
        TEST_IP1,
        TEST_NET1,
        RFC1918_CIDR_10,
        LINK_LOCAL_DNS,
        IPV6_VERBOSE_CANONICAL,
        IPV6_NET1,
    ],
)
def test_accepts_valid_targets(target: str) -> None:
    """Domains, wildcards, IP literals, and CIDRs (v4 and v6) all parse."""
    assert parse_policy(f"+{target}") == [PolicyEntry("+", target)]


def test_parses_ipv4_port() -> None:
    """A trailing ``:port`` on an IPv4/host target is split off."""
    assert parse_policy(f"+{TEST_IP1}:8080") == [PolicyEntry("+", TEST_IP1, 8080)]


def test_parses_bracketed_ipv6_port() -> None:
    """An IPv6 literal carries a port only when bracketed."""
    assert parse_policy(f"+[{IPV6_VERBOSE_CANONICAL}]:443") == [
        PolicyEntry("+", IPV6_VERBOSE_CANONICAL, 443)
    ]


def test_bracketed_ipv6_without_port() -> None:
    """A bracketed IPv6 literal with no ``:port`` parses with ``port=None``."""
    (entry,) = parse_policy(f"+[{IPV6_VERBOSE_CANONICAL}]")
    assert entry == PolicyEntry("+", IPV6_VERBOSE_CANONICAL)


def test_bare_ipv6_has_no_port() -> None:
    """A bare (unbracketed) IPv6 literal is never split on its colons."""
    (entry,) = parse_policy(f"+{IPV6_VERBOSE_CANONICAL}")
    assert entry.port is None
    assert entry.target == IPV6_VERBOSE_CANONICAL


def test_metadata_markers() -> None:
    """``%key=value`` markers are parsed into ``meta``; values may contain ``=``."""
    (entry,) = parse_policy(f"+{TEST_DOMAIN}  %reason=test %expires=2026-06-09 %c=x=y")
    assert entry.meta == {"reason": "test", "expires": "2026-06-09", "c": "x=y"}


def test_comment_bears_zero_load() -> None:
    """Everything after ``#`` is ignored — including stray ``%`` markers."""
    (entry,) = parse_policy(f"+{TEST_DOMAIN}  %reason=keep  # free text %ignored=marker")
    assert entry == PolicyEntry("+", TEST_DOMAIN, None, {"reason": "keep"})


def test_localhost_grant_parses_with_port() -> None:
    """``+localhost:PORT`` parses as the reserved host-service grant."""
    assert parse_policy("+localhost:8000") == [PolicyEntry("+", LOCALHOST, 8000)]


def test_localhost_ports_extracts_grants() -> None:
    """``localhost_ports`` collects every ``+localhost:PORT`` port, skipping other entries."""
    entries = parse_policy(f"+localhost:8000\n+{TEST_DOMAIN}\n+localhost:9090\n")
    assert localhost_ports(entries) == (8000, 9090)


def test_ip_and_domain_targets_partition_entries() -> None:
    """``ip_targets``/``domain_targets`` split entries by kind, excluding ``localhost``."""
    entries = parse_policy(
        f"+{TEST_DOMAIN}\n+{TEST_IP1}\n+{RFC1918_CIDR_10}\n+localhost:8000\n-{TEST_DOMAIN2}\n"
    )
    assert ip_targets(entries) == [TEST_IP1, RFC1918_CIDR_10]
    assert domain_targets(entries) == [TEST_DOMAIN, TEST_DOMAIN2]


def test_is_ip_classifies_literals_cidrs_and_domains() -> None:
    """``is_ip`` accepts IP literals and CIDRs (v4/v6) and rejects domains/localhost."""
    assert is_ip(TEST_IP1)
    assert is_ip(RFC1918_CIDR_10)
    assert is_ip(IPV6_VERBOSE_CANONICAL)
    assert not is_ip(TEST_DOMAIN)
    assert not is_ip(LOCALHOST)


def test_round_trip_render_parse() -> None:
    """``parse_policy(render_policy(x)) == x`` — including bracketed IPv6 ports and metadata."""
    text = (
        f"+{TEST_DOMAIN}\n"
        f"+{WILDCARD}\n"
        f"+{TEST_IP1}:8080\n"
        f"-{DEV_PYPI_DOMAIN}\n"
        f"+{RFC1918_CIDR_10}\n"
        f"+[{IPV6_VERBOSE_CANONICAL}]:443\n"
        f"+{TEST_DOMAIN}  %reason=keep\n"
    )
    entries = parse_policy(text)
    assert parse_policy(render_policy(entries)) == entries


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (PolicyEntry("+", TEST_DOMAIN), TEST_DOMAIN),
        (PolicyEntry("+", TEST_IP1, 8080), f"{TEST_IP1}:8080"),
        (PolicyEntry("+", LOCALHOST, 8000), f"{LOCALHOST}:8000"),
        (PolicyEntry("+", IPV6_VERBOSE_CANONICAL, 443), f"[{IPV6_VERBOSE_CANONICAL}]:443"),
        (PolicyEntry("+", IPV6_VERBOSE_CANONICAL), IPV6_VERBOSE_CANONICAL),
    ],
)
def test_render_target_keeps_the_port_and_brackets_ipv6(entry: PolicyEntry, expected: str) -> None:
    """``render_target`` is the line minus action and markers: ``target[:port]``, v6 bracketed."""
    assert render_target(entry) == expected


@pytest.mark.parametrize(
    "bad",
    [
        TEST_DOMAIN,  # missing +/- prefix
        "+",  # empty target
        "+   ",  # empty target (whitespace only)
        f"+{TEST_DOMAIN}:99999",  # port out of range (high)
        f"+{TEST_DOMAIN}:0",  # port out of range (low)
        f"+{TEST_DOMAIN_ATTACK}",  # control bytes in target
        f"+{FORBIDDEN_TRAVERSAL}",  # path-traversal shape
        "+a/b",  # slash (path-ish) in target
        f"+[{IPV6_VERBOSE_CANONICAL}",  # unterminated IPv6 bracket
        f"+[{IPV6_VERBOSE_CANONICAL}]junk",  # trailing junk after ']'
        f"+{TEST_DOMAIN} bar",  # bare token without a '%' prefix
        f"+{TEST_DOMAIN} %nokey",  # metadata marker missing '=value'
        "+localhost",  # reserved 'localhost' grant needs an explicit port
        "-localhost:8000",  # 'localhost' is allow-only
    ],
)
def test_rejects_malformed(bad: str) -> None:
    """Malformed lines fail fast with a ``ValueError``."""
    with pytest.raises(ValueError):
        parse_policy(bad)


@pytest.mark.parametrize(
    "target", [TEST_DOMAIN, WILDCARD, TEST_IP1, TEST_NET1, IPV6_VERBOSE_CANONICAL, IPV6_NET1]
)
def test_validate_target_accepts_what_a_policy_line_may_name(target: str) -> None:
    """The public target rule is the line grammar's own: domains, wildcards, IPs, CIDRs."""
    validate_target(target)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("", id="empty"),
        pytest.param(f"+{TEST_DOMAIN}", id="action-prefix"),
        pytest.param(f"{TEST_DOMAIN}:443", id="port"),
        pytest.param(TEST_DOMAIN_ATTACK, id="control-bytes"),
        pytest.param(FORBIDDEN_TRAVERSAL, id="path-traversal"),
        pytest.param("a/b", id="slash"),
    ],
)
def test_validate_target_rejects_anything_else(bad: str) -> None:
    """A bare target carries no action, port or path — anything of the sort is a ValueError."""
    with pytest.raises(ValueError, match="invalid target"):
        validate_target(bad)


def test_validate_target_is_the_packages_public_rule() -> None:
    """Exported at the top level, for callers that keep host lists of their own."""
    import terok_shield

    assert terok_shield.validate_target is validate_target


# ── %expires ─────────────────────────────────────────────

_A_DAY = date(2026, 6, 9)


def test_an_expiry_date_holds_through_that_day_in_host_local_time() -> None:
    """``%expires=<date>`` runs out at the local midnight that ends the day — not at its start."""
    deadline = expiry_deadline(_A_DAY.isoformat())
    assert deadline == datetime.combine(_A_DAY + timedelta(days=1), time.min).astimezone()
    assert deadline.tzinfo is not None


def test_an_expiry_timestamp_runs_out_at_that_instant() -> None:
    """A full ISO timestamp is taken as given; one without an offset is host local time."""
    noon = datetime.combine(_A_DAY, time(12, 0))
    assert expiry_deadline(f"{noon.isoformat()}Z") == noon.replace(tzinfo=UTC)
    assert expiry_deadline(noon.isoformat()) == noon.astimezone()


def test_an_expiry_on_the_calendars_last_days_saturates() -> None:
    """No midnight follows 9999-12-31 — the deadline is the last instant there is, not an error."""
    for day in (date.max, date.max - timedelta(days=1)):
        assert expiry_deadline(day.isoformat()).year == date.max.year


@pytest.mark.parametrize("bad", ["", "soon", "2026-13-01", "2026-06-09 noon"])
def test_an_expiry_that_names_no_date_is_refused(bad: str) -> None:
    """Anything but an ISO date or timestamp raises — never a guess."""
    with pytest.raises(ValueError):
        expiry_deadline(bad)


def test_entry_deadline_reads_the_marker() -> None:
    """An entry without ``%expires`` never runs out; one with it runs out at its deadline."""
    (forever, dated) = parse_policy(
        f"+{TEST_DOMAIN}\n+{TEST_DOMAIN2} %{EXPIRES_MARKER}={_A_DAY.isoformat()}\n"
    )
    assert entry_deadline(forever) is None
    assert entry_deadline(dated) == expiry_deadline(_A_DAY.isoformat())


def test_entry_deadline_names_the_entry_and_the_bad_value() -> None:
    """A malformed marker says which entry carries it and what was written."""
    (entry,) = parse_policy(f"+{TEST_DOMAIN} %{EXPIRES_MARKER}=someday\n")
    with pytest.raises(ValueError, match=f"someday.*{TEST_DOMAIN}"):
        entry_deadline(entry)


# ── marker values: free text in one token ─────────────────


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("vendor outage", id="spaces"),
        pytest.param("ticket #42", id="comment-char"),
        pytest.param("100% down", id="percent"),
        pytest.param("a=b, c: (d)", id="punctuation"),
        pytest.param("plain", id="plain"),
    ],
)
def test_a_marker_value_survives_the_line_it_rides_on(text: str) -> None:
    """Spaces end a marker and ``#`` starts a comment: encoded, the text comes back whole."""
    (entry,) = parse_policy(f"+{TEST_DOMAIN} %{REASON_MARKER}={marker_value(text)} %expires=x")
    assert unquote(entry.meta[REASON_MARKER]) == text
    assert entry.meta[EXPIRES_MARKER] == "x"
