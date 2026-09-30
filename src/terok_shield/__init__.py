# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""terok-shield: nftables-based egress firewalling for Podman containers.

Public API facade.  The ``Shield`` class coordinates collaborators:

- **HookMode** (``hooks.mode``) — per-container nft ruleset lifecycle
- **DnsResolver** (``dns.resolver``) — domain resolution and caching
- **ProfileLoader** (``profiles``) — allowlist profile composition
- **RulesetBuilder** (``nft.rules``) — nftables ruleset generation
- **AuditLogger** (``audit``) — per-container JSONL audit trail
- **CommandRunner** (``run``) — subprocess execution boundary

Core and support modules are imported lazily — ``from terok_shield
import ShieldConfig`` does not pull in nft, dnsmasq, or subprocess
helpers.  Heavy imports are deferred until ``Shield`` is instantiated.
"""

import importlib as _importlib
import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import date
from importlib.metadata import PackageNotFoundError, version as _meta_version
from pathlib import Path
from typing import TYPE_CHECKING

# ── Eager: foundation layer (zero-cost, pure data) ─────
from .config import (
    WILDCARDS_NEED_LIVE_TIER,
    DnsTier,
    OverrideRevocation,
    ShieldConfig,
    ShieldMode,
    ShieldModeBackend,
    ShieldReading,
    ShieldRuntime,
    ShieldState,
)
from .paths import HOOK_ENTRYPOINT_NAME
from .policy import validate_target
from .state import (
    RotationRisk,
    SecurityTierRefusal,
    StateBundle,
    recorded_container_id,
    recorded_dns_tier,
    recorded_rotation_risk,
)
from .util import is_ip as _is_ip

if TYPE_CHECKING:
    from terok_util import ArgDef, CommandDef

    from ._hub_events import HubEventEmitter
    from .audit import AuditLogger
    from .commands import COMMANDS
    from .dns.resolver import DnsResolver
    from .harvest import HarvestEntry, HarvestReport
    from .hooks.install import (
        HooksInstaller,
        ensure_user_hooks_dir_configured,
        user_hooks_dir_configured,
    )
    from .nft.rules import RulesetBuilder
    from .profiles import ProfileLoader
    from .run import CommandRunner, ExecError

# ── Lazy: core + support layer ──────────────────────────
# Re-exported names from __all__ that are deferred until first access.
# Keeps ``from terok_shield import ShieldConfig`` lightweight.

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "BinaryCheck": ("terok_shield.prereqs", "BinaryCheck"),
    "ExecError": ("terok_shield.run", "ExecError"),
    "HarvestEntry": ("terok_shield.harvest", "HarvestEntry"),
    "HarvestReport": ("terok_shield.harvest", "HarvestReport"),
    "HooksInstaller": ("terok_shield.hooks.install", "HooksInstaller"),
    "ensure_user_hooks_dir_configured": (
        "terok_shield.hooks.install",
        "ensure_user_hooks_dir_configured",
    ),
    "user_hooks_dir_configured": ("terok_shield.hooks.install", "user_hooks_dir_configured"),
    "NftNotFoundError": ("terok_shield.run", "NftNotFoundError"),
    "ShieldNeedsSetup": ("terok_shield.run", "ShieldNeedsSetup"),
    "check_firewall_binaries": ("terok_shield.prereqs", "check_firewall_binaries"),
    "check_krun_binaries": ("terok_shield.prereqs", "check_krun_binaries"),
    # Command registry — re-exported for the terok integration layer.
    # ArgDef/CommandDef now live in terok-util; we route through it so
    # existing consumers (terok.lib.integrations.shield) keep working.
    "ArgDef": ("terok_util", "ArgDef"),
    "COMMANDS": ("terok_shield.commands", "COMMANDS"),
    "CommandDef": ("terok_util", "CommandDef"),
}


def __getattr__(name: str) -> object:
    """Lazy import for re-exported core/support layer names."""
    if name in _LAZY_IMPORTS:
        mod_path, attr = _LAZY_IMPORTS[name]
        mod = _importlib.import_module(mod_path)
        value = getattr(mod, attr)
        globals()[name] = value  # cache for subsequent access
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


logger = logging.getLogger(__name__)

__version__: str = "0.0.0"  # placeholder; replaced at build time
try:
    __version__ = _meta_version("terok-shield")
except PackageNotFoundError:
    pass  # editable install or running from source without metadata


@dataclass(frozen=True)
class EnvironmentCheck:
    """Result of [`Shield.check_environment`][terok_shield.Shield.check_environment].

    Machine-readable fields for programmatic consumers (terok TUI, scripts).
    Human-readable ``issues`` and ``setup_hint`` for CLI display.

    Attributes:
        ok: True if no issues found.
        podman_version: Detected podman version tuple.
        hooks: Hook installation type (``per-container``, ``global``,
            ``not-installed``).
        health: Environment health (``ok``, ``setup-needed``, ``stale-hooks``).
        dns_tier: Active DNS resolution tier, a [`DnsTier`][terok_shield.config.DnsTier] value.
        issues: List of human-readable issue descriptions.
        needs_setup: True if one-time setup is required.
        setup_hint: Setup instructions (empty if not needed).
    """

    dns_tier: str = ""
    ok: bool = True
    podman_version: tuple[int, ...] = (0,)
    hooks: str = "not-installed"
    health: str = "ok"
    issues: list[str] = field(default_factory=list)
    needs_setup: bool = False
    setup_hint: str = ""


@dataclass(frozen=True)
class AllowResult:
    """What [`Shield.allow`][terok_shield.Shield.allow] granted, and when it takes effect.

    A grant lands one of two ways, and a caller reporting it to an operator
    has to say which: a running container takes it live, a stopped one only
    at its next start.

    Attributes:
        target: The domain or IP the caller asked to allow.
        ips: The addresses the running ruleset admits now.  Empty when the
            grant waits for the next start — or when every live attempt
            failed, which a caller should treat as nothing allowed.
        live: True when the grant went to the container's running ruleset;
            False when podman said no process runs for the container — it is
            stopped, or gone — so the grant sits in its runtime overlay and
            applies at its next start.
    """

    target: str
    ips: tuple[str, ...] = ()
    live: bool = True


class Shield:
    """Public API facade — coordinates collaborators per container.

    Delegates to ``HookMode`` for netns/nft operations, ``DnsResolver``
    for name resolution, ``ProfileLoader`` for allowlists,
    ``RulesetBuilder`` for ruleset generation, and ``AuditLogger`` for
    the audit trail.  All collaborators are injectable for testing.
    """

    def __init__(
        self,
        config: ShieldConfig,
        *,
        runner: "CommandRunner | None" = None,
        audit: "AuditLogger | None" = None,
        dns: "DnsResolver | None" = None,
        profiles: "ProfileLoader | None" = None,
        ruleset: "RulesetBuilder | None" = None,
        hub_events: "HubEventEmitter | None" = None,
    ) -> None:
        """Create the shield facade.

        Args:
            config: Shield configuration (must include state_dir).
            runner: Command runner (default: ``SubprocessRunner``).
            audit: Audit logger (default: from config.state_dir).
            dns: DNS resolver (default: from runner).
            profiles: Profile loader (default: from config.profiles_dir).
            ruleset: Ruleset builder (default: from config loopback_ports).
            hub_events: Best-effort emitter for ``shield_up`` / ``shield_down``
                events bound for the terok-clearance hub (default: a fresh
                [`HubEventEmitter`][terok_shield._hub_events.HubEventEmitter]).  The
                emitter routes each event to the supervisor's
                per-container socket using the ``container_id`` supplied
                on every [`up`][terok_shield.Shield.up] /
                [`down`][terok_shield.Shield.down] call.  Pass a no-op
                stub in tests that should not touch the socket.
        """
        from ._hub_events import HubEventEmitter
        from .audit import AuditLogger
        from .dns.resolver import DnsResolver
        from .nft.rules import RulesetBuilder
        from .profiles import ProfileLoader
        from .run import SubprocessRunner

        self.config = config
        self.runner = runner or SubprocessRunner()
        self.audit = audit or AuditLogger(
            audit_path=StateBundle(config.state_dir).audit,
            enabled=config.audit_enabled,
        )
        self.dns = dns or DnsResolver(runner=self.runner, host_cache_dir=config.dns_cache_dir)
        self.profiles = profiles or ProfileLoader(
            user_dir=config.profiles_dir or Path("/nonexistent"),
        )
        self.ruleset = ruleset or RulesetBuilder(loopback_ports=config.loopback_ports)
        self.hub_events = hub_events or HubEventEmitter()
        self._mode = self._create_mode(config.mode)

    def _create_mode(self, mode: ShieldMode) -> ShieldModeBackend:
        """Create the mode backend for the given mode."""
        if mode == ShieldMode.HOOK:
            from .hooks.mode import HookMode

            return HookMode(
                config=self.config,
                runner=self.runner,
                audit=self.audit,
                dns=self.dns,
                profiles=self.profiles,
                ruleset=self.ruleset,
            )
        raise ValueError(f"Unsupported shield mode: {mode!r}")

    def check_environment(self) -> EnvironmentCheck:
        """Check the podman environment for compatibility issues.

        Proactive check for API consumers (e.g. terok).  Returns an
        [`EnvironmentCheck`][terok_shield.EnvironmentCheck] with detected issues and setup hints.
        Does not raise — the caller decides how to handle issues.
        """
        from terok_util import SetupStatus

        from .dns import apparmor, dnsmasq
        from .hooks.install import HooksInstaller
        from .podman_info import parse_podman_info
        from .run import ShieldNeedsSetup

        output = self.runner.run(["podman", "info", "-f", "json"], check=False)
        info = parse_podman_info(output)
        issues: list[str] = []
        needs_setup = False
        setup_hint = ""
        health = "ok"

        try:
            dnsmasq_bin = dnsmasq.locate(self.config.dnsmasq_path, self.runner)
        except ShieldNeedsSetup as exc:
            issues.append(str(exc))
            dnsmasq_bin = ""
        tier, apparmor_blocked = apparmor.detect_dns_tier_under_apparmor(
            self.runner, self.config.state_dir, dnsmasq_bin
        )
        dns_tier = tier.value
        if apparmor_blocked:
            issues.append(
                f"AppArmor confines {dnsmasq_bin} from the shield state directory. "
                "Install the terok AppArmor profile addendum (docs/apparmor.md)."
            )
        if not tier.live:
            issues.append(f"DNS tier {tier.value}: {tier.hint}")

        checks = HooksInstaller().check_setup()
        failed = [check for check in checks if check.status != SetupStatus.READY]
        hooks = "global" if not failed else "not-installed"
        if failed:
            health = "setup-needed"
            needs_setup = True
            setup_hint = "Run 'terok-shield setup' to refresh global hooks."
            issues.extend(check.diagnostic for check in failed)

        return EnvironmentCheck(
            ok=not issues,
            podman_version=info.version,
            hooks=hooks,
            health=health,
            dns_tier=dns_tier,
            issues=issues,
            needs_setup=needs_setup,
            setup_hint=setup_hint,
        )

    def status(self) -> dict:
        """Return current shield status information."""
        return {
            "mode": self.config.mode.value,
            "profiles": self.profiles.list_profiles(),
            "audit_enabled": self.config.audit_enabled,
        }

    def pre_start(
        self,
        container: str,
        profiles: list[str] | None = None,
        *,
        security_deny: Sequence[str] = (),
        provider_allow: Sequence[str] = (),
        project_allow: Sequence[str] = (),
        override: Sequence[str] = (),
    ) -> list[str]:
        """Prepare shield for container start.  Returns extra podman args.

        The four tier arguments are the orchestrator-generated policy tiers,
        which shield writes into the bundle so callers pass data and never touch
        the layout: *security_deny* → t20 (vault hosts denied direct),
        *provider_allow* → t30 (provider egress), *project_allow* → t40 (git
        remote + custom, merged with the composed profiles), *override* → t10
        (break-glass allow above the deny; a CIDR is accepted but logged as a warning).
        """
        if profiles is None:
            profiles = list(self.config.default_profiles)
        result = self._mode.pre_start(
            container,
            profiles,
            security_deny=security_deny,
            provider_allow=provider_allow,
            project_allow=project_allow,
            override=override,
        )
        self.audit.log_event(container, "setup", detail=f"profiles={','.join(profiles)}")
        return result

    def refresh(
        self,
        container: str,
        profiles: list[str] | None = None,
        *,
        security_deny: Sequence[str] = (),
        provider_allow: Sequence[str] = (),
        project_allow: Sequence[str] = (),
        override: Sequence[str] = (),
    ) -> None:
        """Recompute an existing container's policy bundle before a plain restart.

        Same tier arguments as [`pre_start`][terok_shield.Shield.pre_start],
        but for a container that already exists: rewrites the tiers and
        static-resolution caches and regenerates the pre-applied artifacts
        (``ruleset.nft``, dnsmasq config), so the next ``podman start``
        enforces *current* policy instead of the bundle frozen at creation.
        Returns nothing — the container keeps its launch-time podman args.
        """
        if profiles is None:
            profiles = list(self.config.default_profiles)
        self._mode.refresh(
            container,
            profiles,
            security_deny=security_deny,
            provider_allow=provider_allow,
            project_allow=project_allow,
            override=override,
        )
        self.audit.log_event(container, "refresh", detail=f"profiles={','.join(profiles)}")

    def allow(self, container: str, target: str) -> AllowResult:
        """Allow a domain or IP for *container*: live when it runs, from its next start when not.

        Tier authority is settled before anything changes.  A target the t20
        security tier refuses — that very host, a name under one of its
        domains, or anything that resolves to one of its addresses — raises
        [`SecurityTierRefusal`][terok_shield.state.SecurityTierRefusal] and
        nothing is granted, not even the addresses that were not shared: a
        security-tier host is reachable through a break-glass override only.
        The refusal lands in the audit trail as ``allow_refused``.

        A running container takes the grant live, address by address — an nft
        failure is logged and skipped — and a domain also joins its dnsmasq
        config, so the addresses the name rotates to follow.  A stopped
        container gets the target recorded in its runtime overlay instead, for
        its next start to apply.  The
        [`AllowResult`][terok_shield.AllowResult] says which of the two happened.
        A container counts as stopped only when podman says it has no process
        — or has no such container, which a recreate under the same name
        starts from the same bundle — never because its ruleset could not be
        read: a running one whose listing failed, or that carries no ruleset,
        takes the live path, where a failure is reported.

        Raises:
            SecurityTierRefusal: When the security tier refuses the target.
            ShieldNeedsSetup: A ``*.`` target on a tier that resolves names once.
            RuntimeError: When neither the ruleset nor podman says whether the
                container runs — with nothing changed — or a stopped
                container's bundle was never prepared by a launch.  Also, on
                a running container with the addresses already added, when
                its dnsmasq cannot reload to follow the name.
        """
        from .run import ExecError

        self._refuse_static_wildcard(target)
        is_domain = not _is_ip(target)
        ips = [target] if not is_domain else self.dns.resolve_domains([target])
        try:
            self._mode.check_security_tier(target, ips)
        except SecurityTierRefusal as refusal:
            self.audit.log_event(
                container, "allow_refused", dest=refusal.address or target, detail=str(refusal)
            )
            raise
        if self._mode.confirmed_posture(container) is ShieldState.OFFLINE:
            self._mode.allow_offline(target)
            self.audit.log_event(container, "allowed", dest=target, detail="at next start")
            return AllowResult(target=target, live=False)
        allowed: list[str] = []
        for ip in ips:
            try:
                self._mode.allow_ip(container, ip)
            except (ExecError, OSError) as exc:
                logger.warning("allow_ip failed for %s on %s: %s", ip, container, exc)
                continue
            allowed.append(ip)
            self.audit.log_event(container, "allowed", dest=ip, detail=f"target={target}")
        # Update dnsmasq config for domain targets (so future IP rotations are captured)
        if is_domain and allowed:
            self._mode.allow_domain(container, target)
        return AllowResult(target=target, ips=tuple(allowed))

    def override(
        self, container: str, target: str, expires: date | str, *, reason: str
    ) -> list[str]:
        """Break glass for *target* on a running container, valid through *expires*, for *reason*.

        The one way past the security tier on a live task — direct reach to a
        vault-relayed provider host, a LAN service in a private range — and
        deliberately narrow: *target* joins the t10 override set with a kernel
        timeout, so the kernel itself ends it when *expires* runs out (a date
        holds through that day, host local time).  Agents keep using the
        vault for key relaying; the override only adds the direct route.  The
        hard-deny floor (link-local, cloud metadata) is never overridden, nor
        is the host's own loopback, which a ``+localhost:PORT`` grant reaches.

        A break-glass needs both a reason and an expiry, and the shield
        enforces both: an empty *reason* is refused like a passed *expires*.
        The reason is recorded on the tier entry and in the audit trail
        (``override``), which takes the grant the moment the kernel does —
        before the dnsmasq reload a domain needs, so a failed reload never
        leaves a grant that holds without a record.  The tier entry is
        written only after that: the swap is computed from the tier as the
        grant will leave it, held in memory, so the tier never records a
        grant the kernel did not take.  A grant and a
        [`revoke_override`][terok_shield.Shield.revoke_override] never
        interleave: each holds the container's t10 lock from its read of the
        tier through its swap, and a grant resolves its names before taking
        it, so a revoke never waits on a resolver.

        The grant survives ``shield down``/``up``, re-timed at each rebuild,
        until it expires or the next restart re-derives the tier from the
        orchestrator's policy — persist it there (``shield.override``) for it
        to outlive the task's run.

        Returns:
            The addresses opened: the target itself for an IP or a CIDR.

        Raises:
            ValueError: For a target no override can carry, an *expires*
                that is no date or already passed, or an empty *reason*.
            RuntimeError: When *container* has no running ruleset to take it,
                or the target resolves to no address — or, with the grant
                already holding in the kernel, when the tier or the override
                cache cannot record it (the message says what the next
                rebuild seeds in its place) or dnsmasq cannot reload to open
                the name.
        """
        when = expires.isoformat() if isinstance(expires, date) else expires
        return self._mode.override(container, target, when, reason=reason)

    def revoke_override(self, container: str, target: str) -> OverrideRevocation:
        """End *target*'s break-glass on *container* now, before its expiry runs out.

        The way to close a door [`override`][terok_shield.Shield.override]
        opened, or one the orchestrator authored as ``shield.override``.  Only
        an override still in force can be revoked: a target with none, or
        one whose expiry already passed, raises instead of passing for a
        success.

        The revoke is ordered to fail closed.  The tier entry goes first, so
        no ``shield down``/``up`` re-opens the override, and the files a
        plain ``podman start`` replays are rewritten without it.  Only then
        is it dropped from the running ruleset's t10 set, in one nft
        transaction that keeps every other override.  A name's dnsmasq
        sinkhole punch-through closes too.  The revoke is audited as
        ``override_revoked`` once nothing running holds the override.  A
        stopped container's bundle is rewritten for its next start — and a
        container counts as stopped only when podman says it has no process,
        or has no such container, never because its ruleset could not be read.

        A revoke stops new connections; connections already open keep running
        until they close, as they do when the override expires.  It holds
        until the next restart re-derives the tier from the orchestrator's
        policy: an override authored there comes back unless it is removed
        there too.

        Returns:
            An [`OverrideRevocation`][terok_shield.config.OverrideRevocation]
            naming the addresses closed, those another override still holds
            open, and whether the container was running.

        Raises:
            ValueError: For text that is no domain, IP or CIDR, and for
                ``localhost``, whose ``+localhost:PORT`` grants are no override.
            RuntimeError: When *target* has no override in force, or neither
                the ruleset nor podman says whether the container runs —
                with nothing changed, in both cases.  Also, with the record
                already gone, when nft cannot drop it from the running
                ruleset, or no dnsmasq reloads to sinkhole its name again —
                the message says which.
        """
        return self._mode.revoke_override(container, target)

    def deny(self, container: str, target: str) -> list[str]:
        """Live-deny a domain or IP for a running container."""
        from .run import ExecError

        self._refuse_static_wildcard(target)
        is_domain = not _is_ip(target)
        ips = [target] if not is_domain else self.dns.resolve_domains([target])
        denied: list[str] = []
        for ip in ips:
            try:
                self._mode.deny_ip(container, ip)
            except (ExecError, OSError) as exc:
                logger.warning("deny_ip failed for %s on %s: %s", ip, container, exc)
                continue
            denied.append(ip)
            self.audit.log_event(container, "denied", dest=ip, detail=f"target={target}")
        # Remove domain from dnsmasq config (stops future auto-population)
        if is_domain and denied:
            self._mode.deny_domain(container, target)
        return denied

    def _refuse_static_wildcard(self, target: str) -> None:
        """Refuse a ``*.`` target on a tier that resolves once: it names no address.

        Raises:
            ShieldNeedsSetup: With the tier and the remedies named.
        """
        from .run import ShieldNeedsSetup

        tier = recorded_dns_tier(self.config.state_dir)
        if target.startswith("*.") and tier is not None and not tier.live:
            raise ShieldNeedsSetup(WILDCARDS_NEED_LIVE_TIER.format(tier=tier.value, names=target))

    def rules(self, container: str) -> str:
        """Return current nft rules for a container."""
        return self._mode.list_rules(container)

    def down(self, container: str, container_id: str, *, disengaged: bool = False) -> None:
        """Switch a running container to the DOWN posture.

        *container* is the operator-facing podman name (audit log key);
        *container_id* is the full podman UUID — the routing key for
        the per-container hub socket the supervisor listens on.  The
        caller knows both at every emit site, so neither carries a
        default.

        With *disengaged*, the container takes the DISENGAGED posture
        instead: nothing is enforced — no deny set, no private-range or
        hard-deny reject — and every new connection is only logged.
        """
        self._mode.shield_down(container, disengaged=disengaged)
        self.audit.log_event(
            container,
            "shield_down",
            detail="disengaged=True" if disengaged else None,
        )
        self.hub_events.shield_down(
            container,
            container_id,
            disengaged=disengaged,
            dossier=self._read_dossier(),
        )

    def quarantine(self, container: str) -> None:
        """Total network blackout — drop all traffic, log dropped traffic."""
        self._mode.shield_quarantine(container)
        self.audit.log_event(container, "shield_quarantine")

    def up(self, container: str, container_id: str) -> None:
        """Restore normal deny-all mode for a running container.

        *container* / *container_id* — see
        [`down`][terok_shield.Shield.down].
        """
        self._mode.shield_up(container)
        self.audit.log_event(container, "shield_up")
        self.hub_events.shield_up(container, container_id, dossier=self._read_dossier())

    def harvest(self) -> "HarvestReport":
        """Summarise what this container reached for, from its audit log.

        A read, not a policy change: the entries say what was refused, what
        the timed window let through and what the DOWN posture accepted only
        because the shield was down — each with the tier that stands in the
        way and the remedies that could lift it — and promoting any of them
        stays an explicit act elsewhere.  The report also says whether audit
        was on for this container at all: with it off, the reader recorded
        nothing, and an empty harvest is no all-clear.

        Raises:
            RuntimeError: The audit log exists but cannot be read.
        """
        from .harvest import harvest

        return harvest(self.config.state_dir)

    def bypass(self, container: str, duration: str | None = None) -> str:
        """Open the timed allow-all window and return the duration granted.

        *duration* is an nft timeout; ``None`` takes
        [`bypass_duration`][terok_shield.ShieldConfig.bypass_duration] from the
        config.  The window lives in the kernel: it closes when the element
        expires, a rebuild or a restart closes it sooner, and nothing renews it.
        It accepts what the allowlist would refuse — never the security tier,
        the private ranges or the hard-deny floor, which all sit above it in
        the chain — and it opens in the UP posture only, the one chain that
        reads it.

        Raises:
            RuntimeError: When the container's posture is not UP.
            ValueError: When *duration* is not an nft timeout.
        """
        duration = duration or self.config.bypass_duration
        self._mode.arm_window(container, duration)
        self.audit.log_event(container, "bypass_armed", detail=f"duration={duration}")
        return duration

    def bypass_off(self, container: str) -> None:
        """Close the timed allow-all window before its timeout runs out."""
        self._mode.disarm_window(container)
        self.audit.log_event(container, "bypass_disarmed")

    def bypass_remaining(self, container: str) -> int | None:
        """Whole seconds left on the timed allow-all window, or ``None`` when none is open.

        The window half of [`inspect`][terok_shield.Shield.inspect]; a caller
        that also shows the posture reads both from that one listing instead.
        """
        return self.inspect(container).bypass_remaining

    def inspect(self, container: str) -> ShieldReading:
        """Read *container*'s posture and its timed window from one ruleset listing.

        One ``nft -T list table`` inside the container's netns answers both, so
        a surface showing both — a status line, a task pane — pays for one
        listing, and the two are never read a moment apart.  The countdown is
        the kernel's own, in whole seconds, and reported only for UP: the one
        posture whose chain reads the window set.
        """
        return self._mode.inspect(container)

    def reset(self, container: str) -> None:
        """Forget DNS-learned allow state, keeping the authored policy seeds.

        The live tier accumulates every IP the workload legitimately
        resolved; ``reset`` returns the allow sets to their just-launched
        contents (policy literals only) without touching the deny tier or
        the operator's runtime overlay.
        """
        self._mode.shield_reset(container)
        self.audit.log_event(container, "shield_reset")

    def _read_dossier(self) -> dict[str, str]:
        """Resolve the wire dossier for this container by reading the orchestrator's task meta.

        The bridge ``createRuntime`` hook writes the ``dossier.meta_path``
        OCI annotation to ``state_dir/meta_path``; ``Shield.up()`` /
        ``Shield.down()`` follow that pointer, open the orchestrator's
        live task-meta JSON, and project it to the wire-dossier shape
        ``{project, task, name}`` — the same projection the per-container
        reader applies to every block event, so every event for one
        container renders identically in the clearance UI.

        Empty meta_path (standalone container, no orchestrator) →
        ``{}`` → bare-container-name popup.  No staleness window: the
        meta JSON is the orchestrator's live state and is re-read on
        every call.
        """
        from .resources._oci_state import read_meta_path, resolve_dossier_from_meta

        return resolve_dossier_from_meta(read_meta_path(self.config.state_dir))

    def state(self, container: str) -> ShieldState:
        """Query the live nft ruleset to determine a container's shield state."""
        return self._mode.shield_state(container)

    def preview(
        self,
        *,
        down: bool = False,
        disengaged: bool = False,
        profiles: list[str] | None = None,
    ) -> str:
        """Generate the ruleset that would be applied to a container.

        *profiles* compose into the preview exactly as they would into a
        launch (``None`` means the config's ``default_profiles``, as in
        [`pre_start`][terok_shield.Shield.pre_start]): their host-service
        grants join the preamble and their literal IPs seed the allow set.
        See [`HookMode.preview`][terok_shield.hooks.mode.HookMode.preview].
        """
        if profiles is None:
            profiles = list(self.config.default_profiles)
        return self._mode.preview(down=down, disengaged=disengaged, profiles=profiles)

    def resolve(self, *, force: bool = False) -> list[str]:
        """Re-resolve the container's authored policy into its static-resolution caches.

        Refreshes the caches [`pre_start`][terok_shield.Shield.pre_start] and
        [`refresh`][terok_shield.Shield.refresh] fill — the allow cache on the
        tiers without DNS interception, the t10 override cache and the two t20
        deny caches (the security tier's, the runtime overlay's) — without
        rewriting any tier.  *force* re-resolves even
        when a cache is fresh.  Returns the resolved allow IPs; the
        ``dnsmasq-live`` tier resolves per query, so it returns none.

        Raises:
            RuntimeError: When pre_start never completed for this state dir.
        """
        return self._mode.resolve(force=force)

    def profiles_list(self) -> list[str]:
        """List available profile names."""
        return self.profiles.list_profiles()

    def tail_log(self, n: int = 50) -> Iterator[dict]:
        """Yield the last *n* audit events."""
        return self.audit.tail_log(n)

    def compose_profiles(self, names: list[str]) -> list[str]:
        """Load and merge multiple profiles."""
        return self.profiles.compose_profiles(names)


# The stable public contract.  Kept deliberately small: a symbol earns
# its place here only when consumed cross-package from the top-level
# ``terok_shield`` namespace.  Names still reachable via ``_LAZY_IMPORTS``
# but absent here (``BinaryCheck``, ``NftNotFoundError``,
# ``ShieldNeedsSetup``, ``check_firewall_binaries``,
# ``check_krun_binaries``) are
# internal: their only consumers import them from the owning submodule
# (``terok_shield.prereqs`` / ``.run`` / ``.hooks.install``) for concrete
# types, so they need not be part of the stable facade.
__all__ = [
    "AllowResult",
    "ArgDef",
    "COMMANDS",
    "CommandDef",
    "DnsTier",
    "EnvironmentCheck",
    "ExecError",
    "HOOK_ENTRYPOINT_NAME",
    "HarvestEntry",
    "HarvestReport",
    "HooksInstaller",
    "OverrideRevocation",
    "RotationRisk",
    "SecurityTierRefusal",
    "Shield",
    "ShieldConfig",
    "ShieldMode",
    "ShieldReading",
    "ShieldRuntime",
    "ShieldState",
    "ensure_user_hooks_dir_configured",
    "recorded_container_id",
    "recorded_dns_tier",
    "recorded_rotation_risk",
    "user_hooks_dir_configured",
    "validate_target",
]
