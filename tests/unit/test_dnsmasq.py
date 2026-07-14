# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dnsmasq lifecycle module."""

from pathlib import Path
from unittest import mock

import pytest

from terok_shield.dns.dnsmasq import (
    _validate_domain,
    deny_config_lines,
    generate_config,
    has_nftset_support,
    nftset_entry,
    read_denied_domains,
    read_merged_domains,
    reload,
)
from terok_shield.nft.constants import (
    DNSMASQ_BIND_DEFAULT,
    DNSMASQ_BIND_KRUN,
    NFT_TABLE_NAME,
    PASTA_DNS,
)
from terok_shield.state import StateBundle

from ..testnet import TEST_DOMAIN, TEST_DOMAIN2

# ── _validate_domain ────────────────────────────────────


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        pytest.param("github.com", "github.com", id="simple"),
        pytest.param("GITHUB.COM", "github.com", id="uppercase"),
        pytest.param("api.github.com", "api.github.com", id="subdomain"),
        pytest.param("*.github.com", "*.github.com", id="wildcard"),
        pytest.param("a-b.example.org", "a-b.example.org", id="hyphen"),
    ],
)
def test_validate_domain_accepts_valid(domain: str, expected: str) -> None:
    """Valid domain names are accepted and lowercased."""
    assert _validate_domain(domain) == expected


@pytest.mark.parametrize(
    "domain",
    [
        pytest.param("", id="empty"),
        pytest.param("192.0.2.1", id="ip-address"),
        pytest.param("-bad.com", id="leading-hyphen"),
        pytest.param("no spaces.com", id="spaces"),
        pytest.param("; rm -rf /", id="injection-attempt"),
        pytest.param("../../etc/passwd", id="traversal"),
        pytest.param("com", id="tld-only"),
        pytest.param("*.com", id="wildcard-tld-only"),
        pytest.param("org", id="tld-only-org"),
    ],
)
def test_validate_domain_rejects_invalid(domain: str) -> None:
    """Invalid or dangerous domain names are rejected."""
    with pytest.raises(ValueError):
        _validate_domain(domain)


# ── nftset_entry ─────────────────────────────────────────


def test_nftset_entry_format() -> None:
    """nftset_entry() generates the correct dnsmasq nftset config line."""
    result = nftset_entry("github.com")
    assert result == (
        f"nftset=/github.com/4#inet#{NFT_TABLE_NAME}#t40_project_allow_v4"
        f",6#inet#{NFT_TABLE_NAME}#t40_project_allow_v6"
    )


def test_nftset_entry_strips_wildcard() -> None:
    """Wildcard prefix is stripped (dnsmasq nftset matches subdomains inherently)."""
    result = nftset_entry("*.github.com")
    assert "*.github.com" not in result
    assert "nftset=/github.com/" in result


def test_nftset_entry_rejects_invalid_domain() -> None:
    """Invalid domain raises ValueError."""
    with pytest.raises(ValueError):
        nftset_entry("; injection")


# ── generate_config ──────────────────────────────────────


def test_generate_config_basic(tmp_path: Path) -> None:
    """generate_config() produces valid dnsmasq config with nftset entries."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS, [TEST_DOMAIN, TEST_DOMAIN2], pid_path, listen_address=DNSMASQ_BIND_DEFAULT
    )

    assert f"server={PASTA_DNS}" in config
    assert f"listen-address={DNSMASQ_BIND_DEFAULT}" in config
    assert "port=53" in config
    assert "bind-interfaces" in config
    assert "no-resolv" in config
    assert f"pid-file={pid_path}" in config
    assert f"nftset=/{TEST_DOMAIN}/" in config
    assert f"nftset=/{TEST_DOMAIN2}/" in config


def test_generate_config_krun_listen_address(tmp_path: Path) -> None:
    """generate_config(listen_address=DNSMASQ_BIND_KRUN) emits the krun bind."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(PASTA_DNS, [TEST_DOMAIN], pid_path, listen_address=DNSMASQ_BIND_KRUN)

    assert f"listen-address={DNSMASQ_BIND_KRUN}" in config
    assert "listen-address=127.0.0.1" not in config


def test_generate_config_rejects_invalid_listen_address(tmp_path: Path) -> None:
    """generate_config() raises ValueError when listen_address isn't an IP."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    with pytest.raises(ValueError):
        generate_config(PASTA_DNS, [], pid_path, listen_address="not-an-ip")


def test_generate_config_skips_invalid_domains(tmp_path: Path) -> None:
    """Invalid domains are silently skipped."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS,
        [TEST_DOMAIN, "; rm -rf /", TEST_DOMAIN2],
        pid_path,
        listen_address=DNSMASQ_BIND_DEFAULT,
    )

    assert f"nftset=/{TEST_DOMAIN}/" in config
    assert f"nftset=/{TEST_DOMAIN2}/" in config
    assert "rm -rf" not in config


def test_generate_config_empty_domains(tmp_path: Path) -> None:
    """Empty domain list produces config without nftset lines."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(PASTA_DNS, [], pid_path, listen_address=DNSMASQ_BIND_DEFAULT)

    assert "nftset" not in config
    assert f"server={PASTA_DNS}" in config


def test_generate_config_with_log_path(tmp_path: Path) -> None:
    """log_path enables query logging directives."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    log_path = StateBundle(tmp_path).dnsmasq_log
    config = generate_config(
        PASTA_DNS, [TEST_DOMAIN], pid_path, listen_address=DNSMASQ_BIND_DEFAULT, log_path=log_path
    )

    assert "log-queries" in config
    assert f"log-facility={log_path}" in config


def test_generate_config_without_log_path(tmp_path: Path) -> None:
    """Default (no log_path) omits query logging directives."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS, [TEST_DOMAIN], pid_path, listen_address=DNSMASQ_BIND_DEFAULT
    )

    assert "log-queries" not in config
    assert "log-facility" not in config


# ── _is_our_dnsmasq / _clear_pid_file ────────────────────


def test_is_our_dnsmasq_true(tmp_path: Path) -> None:
    """_is_our_dnsmasq returns True when argv[0]=='dnsmasq' and --conf-file= matches exactly."""
    from terok_shield.dns.dnsmasq import _is_our_dnsmasq

    conf_path = str(StateBundle(tmp_path).dnsmasq_conf)
    fake_proc = tmp_path / "cmdline"
    fake_proc.write_bytes(f"dnsmasq\x00--conf-file={conf_path}\x00".encode())
    with mock.patch("terok_shield.dns.dnsmasq.Path", return_value=fake_proc):
        assert _is_our_dnsmasq(12345, tmp_path) is True


def test_is_our_dnsmasq_true_absolute_path_binary(tmp_path: Path) -> None:
    """_is_our_dnsmasq returns True when argv[0] is an absolute path ending with /dnsmasq."""
    from terok_shield.dns.dnsmasq import _is_our_dnsmasq

    conf_path = str(StateBundle(tmp_path).dnsmasq_conf)
    fake_proc = tmp_path / "cmdline"
    fake_proc.write_bytes(f"/usr/sbin/dnsmasq\x00--conf-file={conf_path}\x00".encode())
    with mock.patch("terok_shield.dns.dnsmasq.Path", return_value=fake_proc):
        assert _is_our_dnsmasq(12345, tmp_path) is True


def test_is_our_dnsmasq_false_different_container(tmp_path: Path) -> None:
    """_is_our_dnsmasq returns False for another container's dnsmasq."""
    from terok_shield.dns.dnsmasq import _is_our_dnsmasq

    fake_proc = tmp_path / "cmdline"
    fake_proc.write_bytes(b"dnsmasq\x00--conf-file=/other/state/dnsmasq.conf\x00")
    with mock.patch("terok_shield.dns.dnsmasq.Path", return_value=fake_proc):
        assert _is_our_dnsmasq(12345, tmp_path) is False


def test_is_our_dnsmasq_false_conf_path_as_substring(tmp_path: Path) -> None:
    """_is_our_dnsmasq returns False when our conf path is embedded inside a longer arg."""
    from terok_shield.dns.dnsmasq import _is_our_dnsmasq

    conf_path = str(StateBundle(tmp_path).dnsmasq_conf)
    longer_path = f"/other{conf_path}"
    fake_proc = tmp_path / "cmdline"
    fake_proc.write_bytes(f"dnsmasq\x00--conf-file={longer_path}\x00".encode())
    with mock.patch("terok_shield.dns.dnsmasq.Path", return_value=fake_proc):
        assert _is_our_dnsmasq(12345, tmp_path) is False


def test_is_our_dnsmasq_false_different_process(tmp_path: Path) -> None:
    """_is_our_dnsmasq returns False when argv[0] is not dnsmasq."""
    from terok_shield.dns.dnsmasq import _is_our_dnsmasq

    fake_proc = tmp_path / "cmdline"
    fake_proc.write_bytes(b"nginx\x00-g\x00daemon off;\x00")
    with mock.patch("terok_shield.dns.dnsmasq.Path", return_value=fake_proc):
        assert _is_our_dnsmasq(12345, tmp_path) is False


def test_is_our_dnsmasq_false_missing_proc(tmp_path: Path) -> None:
    """_is_our_dnsmasq returns False when /proc/{pid} doesn't exist."""
    from terok_shield.dns.dnsmasq import _is_our_dnsmasq

    assert _is_our_dnsmasq(999999999, tmp_path) is False


def test_is_our_dnsmasq_false_empty_args(tmp_path: Path) -> None:
    """_is_our_dnsmasq returns False when cmdline parsing yields an empty arg list."""
    from terok_shield.dns.dnsmasq import _is_our_dnsmasq

    mock_path_instance = mock.MagicMock()
    mock_path_instance.read_bytes.return_value.rstrip.return_value.split.return_value = []

    with mock.patch("terok_shield.dns.dnsmasq.Path", return_value=mock_path_instance):
        assert _is_our_dnsmasq(12345, tmp_path) is False


def test_clear_pid_file_removes_file(tmp_path: Path) -> None:
    """_clear_pid_file removes the PID file."""
    from terok_shield.dns.dnsmasq import _clear_pid_file

    StateBundle(tmp_path).dnsmasq_pid.write_text("12345\n")
    _clear_pid_file(tmp_path)
    assert not StateBundle(tmp_path).dnsmasq_pid.exists()


def test_clear_pid_file_ignores_missing(tmp_path: Path) -> None:
    """_clear_pid_file silently ignores missing PID file."""
    from terok_shield.dns.dnsmasq import _clear_pid_file

    _clear_pid_file(tmp_path)  # should not raise


# ── read_merged_domains (policy-backed) ──────────────────


def test_read_merged_domains_empty(tmp_path: Path) -> None:
    """read_merged_domains() returns empty list when no policy exists."""
    StateBundle(tmp_path).ensure_dirs()
    assert read_merged_domains(tmp_path) == []


def test_read_merged_domains_project_tier(tmp_path: Path) -> None:
    """Admitted domains from the project-allow tier are returned in order."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n+{TEST_DOMAIN2}\n")
    assert read_merged_domains(tmp_path) == [TEST_DOMAIN, TEST_DOMAIN2]


def test_read_merged_domains_merges_live_overlay(tmp_path: Path) -> None:
    """The runtime overlay (policy/live) adds to the admitted domains."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
    bundle.overlay_set("+", TEST_DOMAIN2)
    merged = read_merged_domains(tmp_path)
    assert TEST_DOMAIN in merged
    assert TEST_DOMAIN2 in merged


def test_read_merged_domains_subtracts_denied(tmp_path: Path) -> None:
    """A '-' overlay entry removes a domain from the dnsmasq list."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n+{TEST_DOMAIN2}\n")
    bundle.overlay_set("-", TEST_DOMAIN)
    merged = read_merged_domains(tmp_path)
    assert TEST_DOMAIN not in merged
    assert TEST_DOMAIN2 in merged


# ── reload ───────────────────────────────────────────────


def test_reload_regenerates_config_and_sends_sighup(tmp_path: Path) -> None:
    """reload() regenerates config and sends SIGHUP to dnsmasq."""
    StateBundle(tmp_path).ensure_dirs()
    StateBundle(tmp_path).dnsmasq_pid.write_text("12345\n")

    with (
        mock.patch("terok_shield.dns.dnsmasq._is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.dns.dnsmasq.os.kill") as mock_kill,
    ):
        reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])

    # Config was regenerated
    assert TEST_DOMAIN in StateBundle(tmp_path).dnsmasq_conf.read_text()
    # SIGHUP sent (not SIGTERM)
    import signal

    mock_kill.assert_called_once_with(12345, signal.SIGHUP)


def test_reload_preserves_krun_listen_address(tmp_path: Path) -> None:
    """reload() reads the existing conf's listen-address and re-emits it.

    Without this, a krun-runtime container's live reload would silently
    rebind dnsmasq onto netns ``127.0.0.1`` and break DNS for the guest.
    """
    StateBundle(tmp_path).ensure_dirs()
    StateBundle(tmp_path).dnsmasq_pid.write_text("12345\n")
    # Pre-existing conf was generated for the krun runtime.
    StateBundle(tmp_path).dnsmasq_conf.write_text(
        f"listen-address={DNSMASQ_BIND_KRUN}\nport=53\nbind-interfaces\n"
    )

    with (
        mock.patch("terok_shield.dns.dnsmasq._is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.dns.dnsmasq.os.kill"),
    ):
        reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])

    new_conf = StateBundle(tmp_path).dnsmasq_conf.read_text()
    assert f"listen-address={DNSMASQ_BIND_KRUN}" in new_conf
    assert f"listen-address={DNSMASQ_BIND_DEFAULT}" not in new_conf


def test_reload_falls_back_to_default_when_listen_address_missing(tmp_path: Path) -> None:
    """reload() emits the default bind when the prior conf had no ``listen-address=`` line.

    Defensive against hand-written or truncated configs — never crash, fall back
    to the safe default-runtime bind.
    """
    StateBundle(tmp_path).ensure_dirs()
    StateBundle(tmp_path).dnsmasq_pid.write_text("12345\n")
    # No listen-address line in the old conf.
    StateBundle(tmp_path).dnsmasq_conf.write_text("port=53\nbind-interfaces\n")

    with (
        mock.patch("terok_shield.dns.dnsmasq._is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.dns.dnsmasq.os.kill"),
    ):
        reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])

    new_conf = StateBundle(tmp_path).dnsmasq_conf.read_text()
    assert f"listen-address={DNSMASQ_BIND_DEFAULT}" in new_conf


def test_reload_noop_when_not_running(tmp_path: Path) -> None:
    """reload() is a no-op when dnsmasq PID file is absent."""
    StateBundle(tmp_path).ensure_dirs()
    with mock.patch("terok_shield.dns.dnsmasq.os.kill") as mock_kill:
        reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])
    mock_kill.assert_not_called()


def test_reload_raises_on_stale_pid(tmp_path: Path) -> None:
    """reload() raises RuntimeError when PID is not dnsmasq (stale)."""
    StateBundle(tmp_path).ensure_dirs()
    StateBundle(tmp_path).dnsmasq_pid.write_text("12345\n")

    with mock.patch("terok_shield.dns.dnsmasq._is_our_dnsmasq", return_value=False):
        with pytest.raises(RuntimeError, match="not dnsmasq"):
            reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])


def test_reload_raises_on_dead_process(tmp_path: Path) -> None:
    """reload() raises RuntimeError when SIGHUP fails (process dead)."""
    StateBundle(tmp_path).ensure_dirs()
    StateBundle(tmp_path).dnsmasq_pid.write_text("12345\n")

    with (
        mock.patch("terok_shield.dns.dnsmasq._is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.dns.dnsmasq.os.kill", side_effect=ProcessLookupError),
    ):
        with pytest.raises(RuntimeError, match="dead"):
            reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])


# ── generate_config validation ───────────────────────────


def test_generate_config_rejects_invalid_upstream(tmp_path: Path) -> None:
    """generate_config() raises ValueError for non-IP upstream."""
    with pytest.raises(ValueError):
        generate_config(
            "not-an-ip", [], tmp_path / "dnsmasq.pid", listen_address=DNSMASQ_BIND_DEFAULT
        )


# ── has_nftset_support ───────────────────────────────────


def test_has_nftset_support_detects_support() -> None:
    """has_nftset_support() returns True when version output lists 'nftset'."""
    runner = mock.MagicMock()
    runner.run.return_value = (
        "Dnsmasq version 2.92  Copyright (c) 2000-2025 Simon Kelley\n"
        "Compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 "
        "no-Lua TFTP conntrack ipset nftset auth DNSSEC loop-detect inotify dumpfile\n"
    )
    assert has_nftset_support(runner) is True


def test_has_nftset_support_detects_no_support() -> None:
    """has_nftset_support() returns False when version output lists 'no-nftset'."""
    runner = mock.MagicMock()
    runner.run.return_value = (
        "Dnsmasq version 2.90\n"
        "Compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 "
        "no-Lua TFTP conntrack ipset no-nftset auth DNSSEC loop-detect inotify dumpfile\n"
    )
    assert has_nftset_support(runner) is False


def test_has_nftset_support_missing_dnsmasq() -> None:
    """has_nftset_support() returns False when dnsmasq is not installed."""
    runner = mock.MagicMock()
    runner.run.return_value = (
        ""  # SubprocessRunner returns "" on FileNotFoundError with check=False
    )
    assert has_nftset_support(runner) is False


# ── cache-size + DNS-plane deny ─────────────────────────


def test_generate_config_disables_dnsmasq_cache(tmp_path: Path) -> None:
    """cache-size=0: a cached answer would skip the --nftset add and hand the
    workload an IP whose (timed) allow-set element was never re-armed."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(PASTA_DNS, [], pid_path, listen_address=DNSMASQ_BIND_DEFAULT)
    assert "cache-size=0" in config


def test_generate_config_sinkholes_denied_domains(tmp_path: Path) -> None:
    """A denied domain gets a local=/dom/ NXDOMAIN sinkhole line."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS,
        [TEST_DOMAIN],
        pid_path,
        listen_address=DNSMASQ_BIND_DEFAULT,
        deny_domains=[TEST_DOMAIN2],
    )
    assert f"local=/{TEST_DOMAIN2}/" in config
    assert f"nftset=/{TEST_DOMAIN}/" in config


class TestDenyConfigLines:
    """deny_config_lines() — sinkholes, punch-throughs, and their edge cases."""

    def test_denied_domain_is_sinkholed(self) -> None:
        """Plain deny → one local=/dom/ line, nothing else."""
        assert deny_config_lines([], [TEST_DOMAIN], PASTA_DNS) == [f"local=/{TEST_DOMAIN}/"]

    def test_allowed_subdomain_of_denied_ancestor_gets_punch_through(self) -> None:
        """dnsmasq matches by longest suffix — the specific allow must outrank
        the ancestor sinkhole, mirroring the policy engine's composition."""
        sub = f"api.{TEST_DOMAIN}"
        lines = deny_config_lines([sub], [TEST_DOMAIN], PASTA_DNS)
        assert f"local=/{TEST_DOMAIN}/" in lines
        assert f"server=/{sub}/{PASTA_DNS}" in lines

    def test_wildcards_are_stripped_on_both_sides(self) -> None:
        """*.dom deny and *.sub allow behave as their base domains."""
        sub = f"api.{TEST_DOMAIN}"
        lines = deny_config_lines([f"*.{sub}"], [f"*.{TEST_DOMAIN}"], PASTA_DNS)
        assert f"local=/{TEST_DOMAIN}/" in lines
        assert f"server=/{sub}/{PASTA_DNS}" in lines

    def test_same_name_conflict_emits_no_sinkhole(self) -> None:
        """Deny at exactly an allowed name: a same-specificity dnsmasq directive
        conflict has no defined winner — leave the verdict to the IP tiers."""
        assert deny_config_lines([TEST_DOMAIN], [TEST_DOMAIN], PASTA_DNS) == []

    def test_unrelated_allow_gets_no_punch_through(self) -> None:
        """Only strict subdomains of the denied base punch through."""
        lines = deny_config_lines([TEST_DOMAIN2], [TEST_DOMAIN], PASTA_DNS)
        assert lines == [f"local=/{TEST_DOMAIN}/"]

    def test_invalid_deny_entries_are_skipped(self) -> None:
        """Malformed deny entries are dropped with a warning, like the nftset path."""
        assert deny_config_lines([], ["not a domain!"], PASTA_DNS) == []

    def test_duplicate_lines_are_deduplicated(self) -> None:
        """Two denied ancestors of one allow yield a single punch-through."""
        sub_base = f"sub.{TEST_DOMAIN}"
        allowed = f"api.{sub_base}"
        lines = deny_config_lines([allowed], [TEST_DOMAIN, sub_base], PASTA_DNS)
        assert lines.count(f"server=/{allowed}/{PASTA_DNS}") == 1


def test_read_denied_domains_composes_from_policy(tmp_path: Path) -> None:
    """read_denied_domains() surfaces '-' domains from the tiered bundle."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
    bundle.overlay_set("-", TEST_DOMAIN2)
    assert read_denied_domains(tmp_path) == [TEST_DOMAIN2]


def test_reload_writes_deny_sinkholes(tmp_path: Path) -> None:
    """reload() regenerates the config with the deny sinkholes included."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.dnsmasq_pid.write_text("12345\n")
    bundle.dnsmasq_conf.write_text(f"listen-address={DNSMASQ_BIND_DEFAULT}\n")

    with (
        mock.patch("terok_shield.dns.dnsmasq._is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.dns.dnsmasq.os.kill"),
    ):
        reload(tmp_path, PASTA_DNS, [TEST_DOMAIN], [TEST_DOMAIN2])

    conf = bundle.dnsmasq_conf.read_text()
    assert f"nftset=/{TEST_DOMAIN}/" in conf
    assert f"local=/{TEST_DOMAIN2}/" in conf
