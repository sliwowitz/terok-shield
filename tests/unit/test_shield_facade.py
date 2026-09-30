# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield facade class (__init__.py)."""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

import pytest
from terok_util import SetupCheck, SetupStatus

from terok_shield import (
    AllowResult,
    DnsTier,
    ExecError,
    OverrideRevocation,
    SecurityTierRefusal,
    Shield,
    ShieldConfig,
    ShieldReading,
    ShieldState,
    state,
)
from terok_shield.dns import dnsmasq
from terok_shield.hooks.mode import HookMode
from terok_shield.nft.constants import PASTA_DNS
from terok_shield.run import ShieldNeedsSetup

from ..testfs import AUDIT_FILENAME, NFT_BINARY
from ..testnet import TEST_DOMAIN, TEST_DOMAIN2, TEST_IP1, TEST_IP2, TEST_IP3, VAULT_HOST

ConfigFactory = Callable[..., ShieldConfig]


@dataclass
class ShieldHarness:
    """A ``Shield`` instance plus its mock collaborators."""

    shield: Shield
    runner: mock.MagicMock
    audit: mock.MagicMock
    dns: mock.MagicMock
    profiles: mock.MagicMock
    ruleset: mock.MagicMock
    mode: mock.MagicMock
    hub_events: mock.MagicMock


ShieldHarnessFactory = Callable[..., ShieldHarness]


@pytest.fixture
def make_shield(make_config: ConfigFactory) -> ShieldHarnessFactory:
    """Create a ``Shield`` with injected mocks while bypassing ``_create_mode``."""

    def _make_shield(
        config: ShieldConfig | None = None,
        *,
        mode: mock.MagicMock | None = None,
        audit: mock.MagicMock | None = None,
        dns: mock.MagicMock | None = None,
        profiles: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
        hub_events: mock.MagicMock | None = None,
    ) -> ShieldHarness:
        harness = ShieldHarness(
            shield=Shield.__new__(Shield),
            runner=mock.MagicMock(),
            audit=audit or mock.MagicMock(),
            dns=dns or mock.MagicMock(),
            profiles=profiles or mock.MagicMock(),
            ruleset=ruleset or mock.MagicMock(),
            mode=mode or mock.MagicMock(),
            hub_events=hub_events or mock.MagicMock(),
        )
        harness.shield.config = config or make_config()
        harness.shield.runner = harness.runner
        harness.shield.audit = harness.audit
        harness.shield.dns = harness.dns
        harness.shield.profiles = harness.profiles
        harness.shield.ruleset = harness.ruleset
        harness.shield.hub_events = harness.hub_events
        harness.shield._mode = harness.mode
        return harness

    return _make_shield


@mock.patch("terok_shield.run.find_nft", return_value=NFT_BINARY)
def test_shield_default_collaborators(_find: mock.Mock, tmp_path: Path) -> None:
    """Shield creates default collaborators when none are injected."""
    shield = Shield(ShieldConfig(state_dir=tmp_path))
    assert shield.runner is not None
    assert shield.audit is not None
    assert shield.dns is not None
    assert shield.profiles is not None
    assert shield.ruleset is not None
    assert shield.hub_events is not None


def test_shield_uses_injected_collaborators(tmp_path: Path) -> None:
    """Shield keeps explicitly injected collaborators."""
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    dns = mock.MagicMock()
    profiles = mock.MagicMock()
    ruleset = mock.MagicMock()
    hub_events = mock.MagicMock()

    shield = Shield(
        ShieldConfig(state_dir=tmp_path),
        runner=runner,
        audit=audit,
        dns=dns,
        profiles=profiles,
        ruleset=ruleset,
        hub_events=hub_events,
    )

    assert shield.runner is runner
    assert shield.audit is audit
    assert shield.dns is dns
    assert shield.profiles is profiles
    assert shield.ruleset is ruleset
    assert shield.hub_events is hub_events


def test_create_mode_rejects_unsupported_value(
    tmp_path: Path, make_shield: ShieldHarnessFactory
) -> None:
    """_create_mode raises ValueError for unsupported modes."""
    harness = make_shield(config=ShieldConfig(state_dir=tmp_path))
    fake_mode = mock.MagicMock()
    fake_mode.__eq__ = lambda self, other: False
    with pytest.raises(ValueError):
        harness.shield._create_mode(fake_mode)


def test_status_returns_mode_profiles_and_audit(make_shield: ShieldHarnessFactory) -> None:
    """status() reports the facade configuration and available profiles."""
    harness = make_shield()
    harness.profiles.list_profiles.return_value = ["base", "dev-standard"]
    result = harness.shield.status()
    assert result == {
        "mode": "hook",
        "profiles": ["base", "dev-standard"],
        "audit_enabled": True,
    }


def test_pre_start_dispatches_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """pre_start() delegates to the backend and logs the chosen profiles."""
    harness = make_shield()
    harness.mode.pre_start.return_value = ["--network", "pasta:"]

    result = harness.shield.pre_start("test-ctr", ["dev-standard"])

    harness.mode.pre_start.assert_called_once_with(
        "test-ctr",
        ["dev-standard"],
        security_deny=(),
        provider_allow=(),
        project_allow=(),
        override=(),
    )
    assert result == ["--network", "pasta:"]
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "setup", detail="profiles=dev-standard"
    )


def test_pre_start_uses_default_profiles(
    make_shield: ShieldHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() falls back to config.default_profiles when profiles is None."""
    harness = make_shield(config=make_config(default_profiles=("base",)))
    harness.mode.pre_start.return_value = []

    harness.shield.pre_start("test-ctr")
    harness.mode.pre_start.assert_called_once_with(
        "test-ctr", ["base"], security_deny=(), provider_allow=(), project_allow=(), override=()
    )


def test_pre_start_composes_no_profile_unless_named(make_shield: ShieldHarnessFactory) -> None:
    """pre_start() passes no profile when neither the call nor the config names one."""
    harness = make_shield()
    harness.mode.pre_start.return_value = []

    harness.shield.pre_start("test-ctr")
    harness.mode.pre_start.assert_called_once_with(
        "test-ctr", [], security_deny=(), provider_allow=(), project_allow=(), override=()
    )


def test_refresh_dispatches_and_logs(
    make_shield: ShieldHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """refresh() delegates the tier data to the backend and audit-logs the event.

    Same default-profiles fallback as pre_start — the restart path passes
    ``None`` and gets the config's composed profile set.
    """
    harness = make_shield(config=make_config(default_profiles=("base",)))

    harness.shield.refresh("test-ctr", security_deny=(TEST_DOMAIN,), override=(TEST_DOMAIN2,))

    harness.mode.refresh.assert_called_once_with(
        "test-ctr",
        ["base"],
        security_deny=(TEST_DOMAIN,),
        provider_allow=(),
        project_allow=(),
        override=(TEST_DOMAIN2,),
    )
    harness.audit.log_event.assert_called_once_with("test-ctr", "refresh", detail="profiles=base")


@pytest.mark.parametrize(
    ("method", "target", "resolver_method", "backend_method", "expected"),
    [
        pytest.param("allow", TEST_IP1, None, "allow_ip", [TEST_IP1], id="allow-ip"),
        pytest.param("deny", TEST_IP1, None, "deny_ip", [TEST_IP1], id="deny-ip"),
        pytest.param(
            "allow",
            TEST_DOMAIN,
            "resolve_domains",
            "allow_ip",
            [TEST_IP1, TEST_IP2],
            id="allow-domain",
        ),
        pytest.param(
            "deny",
            TEST_DOMAIN,
            "resolve_domains",
            "deny_ip",
            [TEST_IP1, TEST_IP2],
            id="deny-domain",
        ),
    ],
)
def test_allow_and_deny_resolve_targets_and_delegate(
    make_shield: ShieldHarnessFactory,
    method: str,
    target: str,
    resolver_method: str | None,
    backend_method: str,
    expected: list[str],
) -> None:
    """allow()/deny() either use the target directly or resolve domains first."""
    harness = make_shield()
    harness.dns.resolve_domains.return_value = [TEST_IP1, TEST_IP2]

    result = getattr(harness.shield, method)("test-ctr", target)

    if resolver_method is None:
        harness.dns.resolve_domains.assert_not_called()
    else:
        getattr(harness.dns, resolver_method).assert_called_once_with([target])
    assert getattr(harness.mode, backend_method).call_args_list == [
        mock.call("test-ctr", ip) for ip in expected
    ]
    granted = result.ips if method == "allow" else result
    assert list(granted) == expected
    assert harness.audit.log_event.call_count == len(expected)


@pytest.mark.parametrize(
    ("method", "backend_method", "target"),
    [
        pytest.param("allow", "allow_ip", TEST_IP1, id="allow"),
        pytest.param("deny", "deny_ip", TEST_IP1, id="deny"),
    ],
)
def test_allow_and_deny_swallow_backend_exceptions(
    make_shield: ShieldHarnessFactory,
    method: str,
    backend_method: str,
    target: str,
) -> None:
    """allow()/deny() are best-effort when backend IP operations fail."""
    harness = make_shield()
    getattr(harness.mode, backend_method).side_effect = ExecError(["nft"], 1, "nft failed")
    outcome = getattr(harness.shield, method)("test-ctr", target)
    assert list(outcome.ips if method == "allow" else outcome) == []


@pytest.mark.parametrize("method", ["allow", "deny"])
def test_allow_and_deny_refuse_a_wildcard_on_a_static_tier(
    make_shield: ShieldHarnessFactory, method: str, tmp_path: Path
) -> None:
    """A ``*.`` target names no address where names resolve once, so it is refused up front."""
    harness = make_shield(ShieldConfig(state_dir=tmp_path))
    state.StateBundle(tmp_path).dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")
    verdict = getattr(harness.shield, method)

    with pytest.raises(ShieldNeedsSetup, match=r"lookup tier: \*\."):
        verdict("test-ctr", f"*.{TEST_DOMAIN}")

    harness.dns.resolve_domains.assert_not_called()


def test_allow_settles_tier_authority_before_granting_anything(
    make_shield: ShieldHarnessFactory,
) -> None:
    """Every resolved address is checked first; only then does any address reach the backend."""
    harness = make_shield()
    harness.dns.resolve_domains.return_value = [TEST_IP1, TEST_IP2]

    result = harness.shield.allow("test-ctr", TEST_DOMAIN)

    assert harness.mode.mock_calls[0] == mock.call.check_security_tier(
        TEST_DOMAIN, [TEST_IP1, TEST_IP2]
    )
    assert result == AllowResult(TEST_DOMAIN, (TEST_IP1, TEST_IP2))
    assert result.live


def test_allow_refused_by_the_security_tier_grants_nothing_and_is_audited(
    make_shield: ShieldHarnessFactory,
) -> None:
    """A refusal is all or nothing, raised past the per-address error handling, and recorded."""
    harness = make_shield()
    harness.dns.resolve_domains.return_value = [TEST_IP3, TEST_IP1]
    refusal = SecurityTierRefusal(TEST_DOMAIN, entry=TEST_IP1, address=TEST_IP1)
    harness.mode.check_security_tier.side_effect = refusal

    with pytest.raises(SecurityTierRefusal) as ctx:
        harness.shield.allow("test-ctr", TEST_DOMAIN)

    assert ctx.value is refusal
    harness.mode.allow_ip.assert_not_called()
    harness.mode.allow_offline.assert_not_called()
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "allow_refused", dest=TEST_IP1, detail=str(refusal)
    )


def test_allow_on_a_stopped_container_records_it_for_the_next_start(
    make_shield: ShieldHarnessFactory,
) -> None:
    """No live ruleset: the target goes to the overlay, and the result says it waits."""
    harness = make_shield()
    harness.dns.resolve_domains.return_value = [TEST_IP1]
    harness.mode.confirmed_posture.return_value = ShieldState.OFFLINE

    result = harness.shield.allow("test-ctr", TEST_DOMAIN)

    assert result == AllowResult(TEST_DOMAIN, live=False)
    harness.mode.allow_offline.assert_called_once_with(TEST_DOMAIN)
    harness.mode.allow_ip.assert_not_called()
    harness.mode.allow_domain.assert_not_called()
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "allowed", dest=TEST_DOMAIN, detail="at next start"
    )


def test_allow_refuses_a_vault_address_end_to_end_without_lifting_the_deny(
    tmp_path: Path,
) -> None:
    """The probed hole, through the real backend: no ``delete element`` ever reaches t20.

    The old un-deny path deleted any denied address from the live t20 set;
    a clearance Allow verdict on a vault address went exactly that way.
    """
    runner = mock.MagicMock()
    dns = mock.MagicMock()
    shield = Shield(
        ShieldConfig(state_dir=tmp_path),
        runner=runner,
        audit=mock.MagicMock(),
        dns=dns,
        profiles=mock.MagicMock(),
        ruleset=mock.MagicMock(),
        hub_events=mock.MagicMock(),
    )
    bundle = state.StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n")
    bundle.deny_resolved.write_text(f"{TEST_IP1}\n")

    with pytest.raises(SecurityTierRefusal, match=TEST_IP1):
        shield.allow("test-ctr", TEST_IP1)

    runner.nft_via_nsenter.assert_not_called()
    assert TEST_IP1 in bundle.read_denied_ips()
    assert not bundle.policy_live.exists()


_RUNNING_PID = "4242"
"""What ``podman inspect --format {{.State.Pid}}`` prints for a running container."""

_NO_PROCESS = "0"
"""What ``podman inspect --format {{.State.Pid}}`` prints for a container with no process."""

_PODMAN_KNOWS_NO_SUCH_CONTAINER = 1
"""``podman container exists``'s exit status for a container podman has no record of."""

_PODMAN_CANNOT_LOOK = 125
"""``podman container exists``'s exit status when podman itself failed."""


@dataclass
class UnreadableRuleset:
    """A ``Shield`` on the real backend over a launched bundle whose ruleset listing fails."""

    shield: Shield
    runner: mock.MagicMock
    audit: mock.MagicMock
    bundle: state.StateBundle
    dnsmasq_conf: str


def _unreadable_ruleset(
    state_dir: Path, podman_pid: str | ExecError, *, exists_status: int = 0
) -> UnreadableRuleset:
    """Every ruleset listing fails, as a podman or nsenter hiccup leaves it; podman answers *podman_pid*.

    A *podman_pid* error fails the listing too, as the runner's own
    ``podman inspect`` does before it enters the netns, and
    ``podman container exists`` then exits *exists_status*.  The bundle is
    a ``dnsmasq-live`` launch with its dnsmasq config on disk, and every
    name resolves to TEST_IP1.
    """
    runner = mock.MagicMock()
    listing_error = (
        podman_pid if isinstance(podman_pid, ExecError) else ExecError(["nsenter"], 1, "transient")
    )

    def _nft(_container: str, *args: str, **_kwargs: object) -> str:
        if "list" in args:
            raise listing_error
        return ""

    def _run(cmd: list[str], **_kwargs: object) -> object:
        if cmd[:3] == ["podman", "container", "exists"] and exists_status:
            raise ExecError(cmd, exists_status, "")
        return mock.DEFAULT

    runner.nft_via_nsenter.side_effect = _nft
    runner.run.side_effect = _run
    if isinstance(podman_pid, ExecError):
        runner.podman_inspect.side_effect = podman_pid
    else:
        runner.podman_inspect.return_value = podman_pid
    dns = mock.MagicMock()
    dns.resolve_domains.return_value = [TEST_IP1]
    audit = mock.MagicMock()
    shield = Shield(
        ShieldConfig(state_dir=state_dir),
        runner=runner,
        audit=audit,
        dns=dns,
        profiles=mock.MagicMock(),
        ruleset=mock.MagicMock(),
        hub_events=mock.MagicMock(),
    )
    bundle = state.StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")
    bundle.network_mode.write_text("pasta\n")
    bundle.upstream_dns.write_text(f"{PASTA_DNS}\n")
    dnsmasq.rewrite_config(state_dir, PASTA_DNS, [])
    return UnreadableRuleset(shield, runner, audit, bundle, bundle.dnsmasq_conf.read_text())


def _nft_changes(runner: mock.MagicMock) -> list[tuple[object, ...]]:
    """The arguments of every nft call that was no listing — what reached the running ruleset."""
    return [c.args for c in runner.nft_via_nsenter.call_args_list if "list" not in c.args]


def test_allow_on_a_running_container_whose_ruleset_cannot_be_read_goes_live(
    tmp_path: Path,
) -> None:
    """A failed listing reads as OFFLINE; podman says the container runs, so the grant goes live.

    Taken for stopped, the grant would sit in the overlay alone, reported as
    waiting for a start the container already had.  The dnsmasq config on
    disk would take the name, which the running dnsmasq never reads, and no
    later reconcile would find a difference left to reload.  The live path
    adds the address to the running ruleset and reloads dnsmasq instead.
    """
    case = _unreadable_ruleset(tmp_path, _RUNNING_PID)

    with mock.patch.object(HookMode, "_reload_dnsmasq", return_value=True) as reload_dnsmasq:
        result = case.shield.allow("test-ctr", TEST_DOMAIN)

    assert result == AllowResult(TEST_DOMAIN, (TEST_IP1,))
    case.runner.podman_inspect.assert_called_once_with("test-ctr", "{{.State.Pid}}")
    (added,) = _nft_changes(case.runner)
    assert added[1:3] == ("add", "element")
    reload_dnsmasq.assert_called_once()
    assert case.bundle.dnsmasq_conf.read_text() == case.dnsmasq_conf
    assert not case.bundle.ruleset.exists()
    case.audit.log_event.assert_called_once_with(
        "test-ctr", "allowed", dest=TEST_IP1, detail=f"target={TEST_DOMAIN}"
    )


def test_allow_on_a_container_podman_says_is_stopped_waits_for_its_next_start(
    tmp_path: Path,
) -> None:
    """No process: the grant goes to the overlay and the files the next start replays, never to nft."""
    case = _unreadable_ruleset(tmp_path, _NO_PROCESS)

    with mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq:
        result = case.shield.allow("test-ctr", TEST_DOMAIN)

    assert result == AllowResult(TEST_DOMAIN, live=False)
    assert f"+{TEST_DOMAIN}" in case.bundle.policy_live.read_text().splitlines()
    assert any(
        line.startswith(f"nftset=/{TEST_DOMAIN}/")
        for line in case.bundle.dnsmasq_conf.read_text().splitlines()
    )
    assert case.bundle.ruleset.is_file()
    assert _nft_changes(case.runner) == []
    reload_dnsmasq.assert_not_called()
    case.audit.log_event.assert_called_once_with(
        "test-ctr", "allowed", dest=TEST_DOMAIN, detail="at next start"
    )


def test_allow_on_a_container_podman_has_no_record_of_waits_for_its_next_start(
    tmp_path: Path,
) -> None:
    """A removed container runs nothing: the grant goes to the bundle a recreate under its name starts from."""
    case = _unreadable_ruleset(
        tmp_path,
        ExecError(["podman", "inspect"], 125, 'Error: no such object: "test-ctr"'),
        exists_status=_PODMAN_KNOWS_NO_SUCH_CONTAINER,
    )

    result = case.shield.allow("test-ctr", TEST_DOMAIN)

    assert result == AllowResult(TEST_DOMAIN, live=False)
    assert f"+{TEST_DOMAIN}" in case.bundle.policy_live.read_text().splitlines()
    assert case.bundle.ruleset.is_file()
    assert _nft_changes(case.runner) == []
    case.audit.log_event.assert_called_once_with(
        "test-ctr", "allowed", dest=TEST_DOMAIN, detail="at next start"
    )


def test_allow_changes_nothing_when_nothing_says_whether_the_container_runs(
    tmp_path: Path,
) -> None:
    """No listing and no podman answer: the allow refuses to guess, so it can simply be retried."""
    case = _unreadable_ruleset(
        tmp_path,
        ExecError(["podman", "inspect"], 125, "database is locked"),
        exists_status=_PODMAN_CANNOT_LOOK,
    )

    with pytest.raises(
        RuntimeError, match="podman cannot say whether it is running.*database is locked"
    ):
        case.shield.allow("test-ctr", TEST_DOMAIN)

    assert not case.bundle.policy_live.exists()
    assert case.bundle.dnsmasq_conf.read_text() == case.dnsmasq_conf
    assert not case.bundle.ruleset.exists()
    assert _nft_changes(case.runner) == []
    case.audit.log_event.assert_not_called()


def test_rules_delegates_to_mode(make_shield: ShieldHarnessFactory) -> None:
    """rules() returns the backend ruleset text."""
    harness = make_shield()
    harness.mode.list_rules.return_value = "table inet terok_shield {}"
    assert "terok_shield" in harness.shield.rules("test-ctr")
    harness.mode.list_rules.assert_called_once_with("test-ctr")


@pytest.mark.parametrize(
    ("disengaged", "expected_detail"),
    [
        pytest.param(False, None, id="default"),
        pytest.param(True, "disengaged=True", id="disengaged"),
    ],
)
def test_down_delegates_and_logs(
    make_shield: ShieldHarnessFactory,
    disengaged: bool,
    expected_detail: str | None,
) -> None:
    """down() delegates to the backend, logs, and pings the hub."""
    harness = make_shield()
    harness.shield.down("test-ctr", "ctr-uuid-1", disengaged=disengaged)
    harness.mode.shield_down.assert_called_once_with("test-ctr", disengaged=disengaged)
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "shield_down", detail=expected_detail
    )
    harness.hub_events.shield_down.assert_called_once_with(
        "test-ctr", "ctr-uuid-1", disengaged=disengaged, dossier={}
    )


def test_up_delegates_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """up() delegates to the backend, logs, and pings the hub."""
    harness = make_shield()
    harness.shield.up("test-ctr", "ctr-uuid-1")
    harness.mode.shield_up.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "shield_up")
    harness.hub_events.shield_up.assert_called_once_with("test-ctr", "ctr-uuid-1", dossier={})


def test_up_resolves_dossier_via_meta_path(
    make_shield: ShieldHarnessFactory, state_dir: Path, tmp_path: Path
) -> None:
    """``Shield.up()`` resolves its hub-event dossier by following ``state_dir/meta_path`` into the orchestrator's wire-dossier file.

    Single source of truth: the wire-dossier JSON file the orchestrator
    maintains.  Without this the clearance UI rendered shield state
    changes with a bare container slug while block popups carried the
    full ``project/task · name`` triple — the same container, two
    visual identities in one session.
    """
    meta = tmp_path / "abc.json"
    meta.write_text(json.dumps({"project": "terok", "task": "abc", "name": "diligent-octopus"}))
    StateBundle(state_dir).meta_path.write_text(str(meta))
    harness = make_shield()
    harness.shield.up("test-ctr", "ctr-uuid-1")
    harness.hub_events.shield_up.assert_called_once_with(
        "test-ctr",
        "ctr-uuid-1",
        dossier={"project": "terok", "task": "abc", "name": "diligent-octopus"},
    )


def test_down_resolves_dossier_via_meta_path(
    make_shield: ShieldHarnessFactory, state_dir: Path, tmp_path: Path
) -> None:
    """``Shield.down()`` carries the same identity bundle as ``up()`` (resolved live each call)."""
    meta = tmp_path / "xyz.json"
    meta.write_text(json.dumps({"project": "terok", "task": "xyz"}))
    StateBundle(state_dir).meta_path.write_text(str(meta))
    harness = make_shield()
    harness.shield.down("test-ctr", "ctr-uuid-1", disengaged=True)
    harness.hub_events.shield_down.assert_called_once_with(
        "test-ctr",
        "ctr-uuid-1",
        disengaged=True,
        dossier={"project": "terok", "task": "xyz"},
    )


def test_quarantine_delegates_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """quarantine() delegates to the backend and logs the transition."""
    harness = make_shield()
    harness.shield.quarantine("test-ctr")
    harness.mode.shield_quarantine.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "shield_quarantine")


def test_state_delegates_to_mode(make_shield: ShieldHarnessFactory) -> None:
    """state() returns the backend shield state."""
    harness = make_shield()
    harness.mode.shield_state.return_value = ShieldState.UP
    assert harness.shield.state("test-ctr") == ShieldState.UP


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        pytest.param({}, "table inet terok_shield { policy drop }", id="default"),
        pytest.param({"down": True, "disengaged": True}, "disengaged", id="down-disengaged"),
    ],
)
def test_preview_delegates_to_mode(
    make_shield: ShieldHarnessFactory,
    kwargs: dict[str, bool],
    expected: str,
) -> None:
    """preview() passes through the requested preview mode."""
    harness = make_shield()
    harness.mode.preview.return_value = expected
    assert harness.shield.preview(**kwargs) == expected
    harness.mode.preview.assert_called_once_with(
        down=kwargs.get("down", False), disengaged=kwargs.get("disengaged", False), profiles=[]
    )


@pytest.mark.parametrize(
    ("profiles", "composed"),
    [
        pytest.param(None, ["base"], id="default-profiles"),
        pytest.param(["my-project"], ["my-project"], id="explicit-profiles"),
    ],
)
def test_preview_profiles_fall_back_to_default_profiles_like_pre_start(
    make_shield: ShieldHarnessFactory,
    make_config: ConfigFactory,
    profiles: list[str] | None,
    composed: list[str],
) -> None:
    """preview() composes the config's default_profiles when none are named — as a launch would."""
    harness = make_shield(config=make_config(default_profiles=("base",)))
    harness.mode.preview.return_value = ""
    harness.shield.preview(profiles=profiles)
    harness.mode.preview.assert_called_once_with(down=False, disengaged=False, profiles=composed)


@pytest.mark.parametrize("force", [False, True], ids=["fresh-cache", "force"])
def test_resolve_delegates_to_the_mode_backend(
    make_shield: ShieldHarnessFactory, force: bool
) -> None:
    """resolve() hands the force flag to the mode backend and returns its allow IPs."""
    harness = make_shield()
    harness.mode.resolve.return_value = [TEST_IP1]

    assert harness.shield.resolve(force=force) == [TEST_IP1]
    harness.mode.resolve.assert_called_once_with(force=force)


@pytest.mark.parametrize(
    ("method", "return_value", "args"),
    [
        pytest.param("profiles_list", ["base", "dev"], (), id="profiles-list"),
        pytest.param("compose_profiles", [TEST_DOMAIN], (["dev-standard"],), id="compose-profiles"),
    ],
)
def test_simple_profile_delegations(
    make_shield: ShieldHarnessFactory,
    method: str,
    return_value: list[str],
    args: tuple[list[str], ...],
) -> None:
    """Small profile-related helpers delegate directly to the collaborator."""
    harness = make_shield()
    target = (
        harness.profiles.list_profiles
        if method == "profiles_list"
        else harness.profiles.compose_profiles
    )
    target.return_value = return_value
    assert getattr(harness.shield, method)(*args) == return_value


def test_tail_log_delegates_to_audit(make_shield: ShieldHarnessFactory) -> None:
    """tail_log() delegates to audit.tail_log()."""
    harness = make_shield()
    harness.audit.tail_log.return_value = iter([{"action": "setup"}])
    result = harness.shield.tail_log(10)
    harness.audit.tail_log.assert_called_once_with(10)
    assert isinstance(result, Iterator)


# ── check_environment tests ──────────────────────────────


def _podman_info_json(version: str = "5.8.0", **host_extra: object) -> str:
    """Build a mock podman info JSON string."""
    return json.dumps({"host": {**host_extra}, "version": {"Version": version}})


def _run_side_effect(podman_version: str = "5.8.0"):
    """Return a runner.run side_effect that handles both podman info and dnsmasq version.

    Needed because check_environment() calls runner.run() for both podman info
    and dnsmasq --version (nftset capability probe).
    """

    def _effect(cmd: list[str], **_kw: object) -> str:
        if Path(cmd[0]).name == "dnsmasq":
            return "Dnsmasq version 2.92\nCompile time options: nftset\n"
        return _podman_info_json(podman_version)

    return _effect


@mock.patch(
    "terok_shield.hooks.install.HooksInstaller.check_setup",
    return_value=(SetupCheck("terok-shield", "hooks", SetupStatus.READY),),
)
class TestCheckEnvironment:
    """Environment diagnostics with owned setup checks isolated from the host."""

    def test_no_lookup_tool_reports_issue(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """No lookup tool and no dnsmasq reports getent degradation in the environment check."""
        harness = make_shield()
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        harness.runner.has.side_effect = lambda cmd: cmd not in ("dig", "drill", "dnsmasq")
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert any(DnsTier.GETENT.hint in i for i in env.issues)
        assert env.dns_tier == DnsTier.GETENT.value

    def test_missing_configured_dnsmasq_reports_issue(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
        tmp_path: Path,
    ) -> None:
        """A configured dnsmasq path that is not executable is an issue, and the host's tiers still resolve."""
        missing = tmp_path / "dnsmasq-missing"
        harness = make_shield(ShieldConfig(state_dir=tmp_path, dnsmasq_path=missing))
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        harness.runner.has.side_effect = lambda cmd: cmd == "dig"
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert any(str(missing) in i for i in env.issues)
        assert env.dns_tier == DnsTier.LOOKUP.value

    def test_apparmor_confined_dnsmasq_reports_issue(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
        tmp_path: Path,
    ) -> None:
        """dnsmasq present but AppArmor-confined from the state dir → dig + advisory."""
        harness = make_shield(ShieldConfig(state_dir=tmp_path))
        harness.runner.has.side_effect = lambda cmd: cmd in ("dnsmasq", "dig")

        def _run(cmd: list[str], **_kw: object) -> str:
            if cmd[0] == "podman":
                return _podman_info_json("5.8.0")
            if "--version" in cmd:
                return "Dnsmasq version 2.92\nCompile time options: nftset\n"
            if "--test" in cmd:
                raise ExecError(cmd, 3, "dnsmasq: cannot read config: Permission denied\n")
            return ""

        harness.runner.run.side_effect = _run
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert env.dns_tier == DnsTier.LOOKUP.value
        assert any("AppArmor" in i for i in env.issues)

    def test_no_global_hooks(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """No global hooks → setup-needed."""
        missing = SetupCheck("terok-shield", "hooks", SetupStatus.MISSING, "No global hooks")
        check_setup.return_value = (missing,)
        harness = make_shield()
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert not env.ok
        assert missing.diagnostic in env.issues
        assert env.health == "setup-needed"
        assert env.hooks == "not-installed"
        assert env.needs_setup
        assert env.setup_hint


from terok_shield.state import StateBundle


def test_reset_dispatches_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """reset() delegates to the backend and writes a shield_reset audit event."""
    harness = make_shield()

    harness.shield.reset("test-ctr")

    harness.mode.shield_reset.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "shield_reset")


@pytest.mark.parametrize(
    "status", [SetupStatus.READY, SetupStatus.STALE, SetupStatus.INVALID, SetupStatus.DOWNGRADE]
)
def test_environment_uses_owner_checks(status, make_shield: ShieldHarnessFactory) -> None:
    """Environment diagnostics use the owner's receipt API, not child file internals."""
    harness = make_shield()
    harness.runner.run.side_effect = _run_side_effect("5.8.0")
    with mock.patch(
        "terok_shield.hooks.install.HooksInstaller.check_setup",
        return_value=(SetupCheck("terok-shield", "hooks", status, "diagnostic"),),
    ):
        env = harness.shield.check_environment()
    assert env.needs_setup == (status != SetupStatus.READY)
    assert env.hooks == ("global" if status == SetupStatus.READY else "not-installed")


# ── the timed allow-all window ───────────────────────────────────────────


def test_bypass_arms_the_window_and_logs_the_duration(
    make_shield: ShieldHarnessFactory,
) -> None:
    """bypass() delegates to the backend and records what was granted."""
    harness = make_shield()
    assert harness.shield.bypass("test-ctr", "30s") == "30s"
    harness.mode.arm_window.assert_called_once_with("test-ctr", "30s")
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "bypass_armed", detail="duration=30s"
    )


def test_bypass_without_a_duration_takes_the_configured_one(
    make_shield: ShieldHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """A caller that names no duration gets ``ShieldConfig.bypass_duration``."""
    harness = make_shield(make_config(bypass_duration="2h"))
    assert harness.shield.bypass("test-ctr") == "2h"
    harness.mode.arm_window.assert_called_once_with("test-ctr", "2h")


def test_bypass_refused_outside_up_records_no_window(make_shield: ShieldHarnessFactory) -> None:
    """A refusal from the backend reaches the caller, and the audit trail claims no window."""
    harness = make_shield()
    harness.mode.arm_window.side_effect = RuntimeError("not UP")

    with pytest.raises(RuntimeError, match="not UP"):
        harness.shield.bypass("test-ctr", "30s")

    harness.audit.log_event.assert_not_called()


def test_override_delegates_with_its_expiry_and_reason(
    make_shield: ShieldHarnessFactory,
) -> None:
    """A live break-glass hands the backend its expiry, as a date, and why it is needed.

    The facade writes no audit line of its own: the backend audits the grant
    the moment the kernel takes it — before a dnsmasq reload that may still
    fail — so a second line here would only double it.
    """
    harness = make_shield()
    harness.mode.override.return_value = [TEST_IP1]
    expires = date.today() + timedelta(days=7)

    assert harness.shield.override("ctr", TEST_DOMAIN, expires, reason="vendor outage") == [
        TEST_IP1
    ]

    harness.mode.override.assert_called_once_with(
        "ctr", TEST_DOMAIN, expires.isoformat(), reason="vendor outage"
    )
    harness.audit.log_event.assert_not_called()


def test_override_without_a_reason_is_no_call(make_shield: ShieldHarnessFactory) -> None:
    """A break-glass needs both a reason and an expiry: leaving the reason out fails the call."""
    harness = make_shield()
    with pytest.raises(TypeError, match="reason"):
        harness.shield.override("ctr", TEST_IP1, "2999-01-01")  # type: ignore[call-arg]
    harness.mode.override.assert_not_called()


def test_a_refused_override_records_nothing(make_shield: ShieldHarnessFactory) -> None:
    """A refusal changes nothing, so the trail has no grant to show."""
    harness = make_shield()
    harness.mode.override.side_effect = ValueError("hard-deny floor")
    with pytest.raises(ValueError, match="hard-deny floor"):
        harness.shield.override("ctr", TEST_IP1, "2999-01-01", reason="vendor outage")
    harness.audit.log_event.assert_not_called()


def test_revoke_override_hands_back_what_the_backend_closed(
    make_shield: ShieldHarnessFactory,
) -> None:
    """The backend audits the revoke once nothing running holds it; the facade adds no second line."""
    harness = make_shield()
    revoked = OverrideRevocation(target=TEST_DOMAIN, closed=(TEST_IP1,), kept=(TEST_IP2,))
    harness.mode.revoke_override.return_value = revoked

    assert harness.shield.revoke_override("ctr", TEST_DOMAIN) is revoked

    harness.mode.revoke_override.assert_called_once_with("ctr", TEST_DOMAIN)
    harness.audit.log_event.assert_not_called()


def test_a_failed_revoke_reaches_the_caller(make_shield: ShieldHarnessFactory) -> None:
    """Nothing to revoke, or a kernel that kept it: the caller hears it, never a quiet success."""
    harness = make_shield()
    harness.mode.revoke_override.side_effect = RuntimeError("no override of it to revoke")
    with pytest.raises(RuntimeError, match="no override of it to revoke"):
        harness.shield.revoke_override("ctr", TEST_IP1)


def test_bypass_off_disarms_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """bypass_off() closes the window early and records it."""
    harness = make_shield()
    harness.shield.bypass_off("test-ctr")
    harness.mode.disarm_window.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "bypass_disarmed")


def test_bypass_remaining_is_the_readings_window(make_shield: ShieldHarnessFactory) -> None:
    """bypass_remaining() reports the backend's one-listing reading in seconds, with no audit entry."""
    harness = make_shield()
    harness.mode.inspect.return_value = ShieldReading(state=ShieldState.UP, bypass_remaining=252)
    assert harness.shield.bypass_remaining("test-ctr") == 252
    harness.mode.inspect.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_not_called()


def test_inspect_delegates_to_the_backend(make_shield: ShieldHarnessFactory) -> None:
    """inspect() hands back the backend's reading untouched."""
    harness = make_shield()
    reading = ShieldReading(state=ShieldState.DOWN)
    harness.mode.inspect.return_value = reading
    assert harness.shield.inspect("test-ctr") is reading


def test_harvest_reads_the_containers_audit_log(
    make_shield: ShieldHarnessFactory, tmp_path: Path
) -> None:
    """``Shield.harvest()`` is a read over this container's own state dir."""
    import json

    from terok_shield.config import ShieldConfig

    (tmp_path / AUDIT_FILENAME).write_text(
        json.dumps(
            {
                "ts": "2026-09-30T10:00:00+00:00",
                "container": "test-ctr",
                "action": "blocked",
                "dest": TEST_IP1,
                "port": 443,
                "proto": "tcp",
            }
        )
        + "\n"
    )
    harness = make_shield(ShieldConfig(state_dir=tmp_path))

    (entry,) = harness.shield.harvest()

    assert (entry.action, entry.target) == ("blocked", TEST_IP1)
    harness.audit.log_event.assert_not_called()


def test_harvest_reports_the_bundles_audit_flag(
    make_shield: ShieldHarnessFactory, tmp_path: Path
) -> None:
    """The report says audit was off when the bundle says so — whatever this Shield's config says.

    The reader honoured the flag recorded at creation, so that flag, not the
    config of whoever asks later, says whether an empty harvest means anything.
    """
    from terok_shield import HarvestReport
    from terok_shield.config import ShieldConfig
    from terok_shield.state import StateBundle

    StateBundle(tmp_path).audit_flag.write_text("false\n")
    harness = make_shield(ShieldConfig(state_dir=tmp_path, audit_enabled=True))

    assert harness.shield.harvest() == HarvestReport(entries=(), audit_enabled=False)
