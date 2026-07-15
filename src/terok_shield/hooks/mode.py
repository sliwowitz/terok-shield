# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Hook mode: OCI hooks + per-container netns.

Uses OCI hooks to apply per-container nftables rules inside each
container's network namespace.  No root required — only podman and nft.

Orchestrates collaborators per lifecycle phase:

- **RulesetBuilder** (``nft.rules``) — generates and verifies nft rulesets
- **DnsResolver** (``dns.resolver``) — pre-start domain resolution
- **ProfileLoader** (``profiles``) — allowlist profile composition
- **AuditLogger** (``audit``) — event logging
- **CommandRunner** (``run``) — subprocess execution (nft, nsenter)
- **dnsmasq** (``dns.dnsmasq``) — runtime DNS with nftset auto-population
- **hook_install** (``hooks.install``) — OCI hook file generation
- **state** (``state``) — per-container state bundle I/O
"""
# WAYPOINT: Shield (__init__)

import ipaddress
import logging
import os
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from .. import state
from ..config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_DNS_TIER_KEY,
    ANNOTATION_KEY,
    ANNOTATION_LIST_SEP,
    ANNOTATION_NAME_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_UPSTREAM_DNS_KEY,
    ANNOTATION_VERSION_KEY,
    DnsTier,
    ShieldConfig,
    ShieldRuntime,
    ShieldState,
)
from ..dns import apparmor, dnsmasq
from ..nft.constants import (
    DNSMASQ_BIND_DEFAULT,
    DNSMASQ_BIND_KRUN,
    NFT_SET_TIMEOUT_DNSMASQ,
    NFT_TABLE,
    NFT_TABLE_NAME,
    PASTA_DNS,
    PASTA_HOST_LOOPBACK_MAP,
    SLIRP4NETNS_DNS,
    SLIRP4NETNS_GATEWAY_V6,
    TIER_PROJECT_ALLOW,
)
from ..nft.rules import (
    RulesetBuilder,
    add_deny_elements_dual,
    delete_deny_elements_dual,
    parse_set_elements,
    restore_elements,
    safe_ip,
)
from ..podman_info.hooks_dir import global_hooks_hint, has_global_hooks
from ..podman_info.info import PodmanInfo, parse_podman_info
from ..podman_info.network import parse_resolv_conf, slirp4netns_gateway
from ..run import ExecError, ShieldNeedsSetup
from ..state import StateBundle
from ..util import is_ipv4
from .install import install_hooks

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..audit import AuditLogger
    from ..dns.resolver import DnsResolver
    from ..profiles import ProfileLoader
    from ..run import CommandRunner


class HookMode:
    """Hook-mode shield backend (Strategy, implements ``ShieldModeBackend``).

    Coordinates the full lifecycle of OCI-hook-based container firewalling.
    Delegates to ``RulesetBuilder`` for nft generation, ``DnsResolver`` for
    name resolution, ``ProfileLoader`` for allowlists, ``dnsmasq`` for
    runtime DNS, and ``state`` for per-container persistence.
    """

    def __init__(
        self,
        *,
        config: ShieldConfig,
        runner: "CommandRunner",
        audit: "AuditLogger",
        dns: "DnsResolver",
        profiles: "ProfileLoader",
        ruleset: RulesetBuilder,
    ) -> None:
        """Create a hook mode backend with all collaborators.

        Args:
            config: Shield configuration (provides state_dir).
            runner: Command runner for subprocess calls.
            audit: Audit logger for event logging.
            dns: DNS resolver for domain resolution and caching.
            profiles: Profile loader for allowlist profiles.
            ruleset: Ruleset builder for nft generation and verification.
        """
        self._config = config
        self._runner = runner
        self._audit = audit
        self._dns = dns
        self._profiles = profiles
        self._ruleset = ruleset
        self._podman_info: PodmanInfo | None = None
        self._gateways: tuple[str, str] | None = None

    # ── Setup (pre_start) ───────────────────────────────

    def pre_start(self, container: str, profiles: list[str]) -> list[str]:
        """Prepare for container start in hook mode.

        Installs hooks, composes profiles, resolves DNS, writes
        allowlist, detects DNS tier, sets annotations, and returns
        the podman CLI arguments needed for shield protection.

        Raises:
            ShieldNeedsSetup: When global hooks are not installed
                (see ``WORKAROUND(hooks-dir-persist)``).
        """
        sd = self._config.state_dir.resolve()
        info = self._get_podman_info()

        # Ensure state dirs and install hooks (idempotent)
        StateBundle(sd).ensure_dirs()
        install_hooks(
            hook_entrypoint=StateBundle(sd).hook_entrypoint,
            hooks_dir=StateBundle(sd).hooks_dir,
        )

        # Detect DNS tier, upstream DNS, and gateway addresses
        tier = self._detect_dns_tier(container, sd)
        mode = info.network_mode or "pasta"
        upstream_dns = _upstream_dns_for_mode(mode)
        gw_v4, gw_v6 = self._gateways = _gateways_for_mode(mode)

        # Resolve DNS, write allowlists, generate ruleset + dnsmasq config.
        # ``loopback.ports`` is persisted before ``_write_ruleset`` runs so
        # the builder reads ports from the bundle (SSOT): later up/down
        # rebuilds use the same source.
        entries = self._profiles.compose_profiles(profiles)
        self._write_policy_and_resolve(sd, entries, tier)
        StateBundle(sd).upstream_dns.write_text(f"{upstream_dns}\n")
        StateBundle(sd).dns_tier.write_text(f"{tier.value}\n")
        StateBundle(sd).write_bundle_version()
        StateBundle(sd).loopback_ports.write_text(
            "".join(f"{p}\n" for p in self._config.loopback_ports)
        )
        self._write_ruleset(sd, tier, upstream_dns, gw_v4, gw_v6)
        self._write_dnsmasq_config_or_scrub(sd, tier, upstream_dns)

        # Build podman args
        args = self._build_network_args(mode)

        # Redirect container DNS through per-container dnsmasq via volume mount.
        # See commit history for detailed rationale on why --dns cannot be used.
        if tier == DnsTier.DNSMASQ:
            args += ["--volume", f"{StateBundle(sd).resolv_conf}:/etc/resolv.conf:ro,Z"]

        # Annotations: profiles, name, state_dir, version, dns.  loopback_ports
        # lives in the state bundle (per-container, written above), not as an
        # annotation — annotations are write-only on shield's side.
        args += [
            "--annotation",
            f"{ANNOTATION_KEY}={ANNOTATION_LIST_SEP.join(profiles)}",
            "--annotation",
            f"{ANNOTATION_NAME_KEY}={container}",
            "--annotation",
            f"{ANNOTATION_STATE_DIR_KEY}={sd}",
            "--annotation",
            f"{ANNOTATION_VERSION_KEY}={state.BUNDLE_VERSION}",
            "--annotation",
            f"{ANNOTATION_AUDIT_ENABLED_KEY}={str(self._config.audit_enabled).lower()}",
            "--annotation",
            f"{ANNOTATION_UPSTREAM_DNS_KEY}={upstream_dns}",
            "--annotation",
            f"{ANNOTATION_DNS_TIER_KEY}={tier.value}",
        ]

        # WORKAROUND(hooks-dir-persist): currently always takes the global path
        if info.hooks_dir_persists:
            args += ["--hooks-dir", str(StateBundle(sd).hooks_dir)]
        elif has_global_hooks():
            self._audit.log_event(
                container,
                "setup",
                detail=(
                    f"podman {'.'.join(str(v) for v in info.version)}: "
                    "using global hooks dir (--hooks-dir does not persist on restart)"
                ),
            )
        else:
            raise ShieldNeedsSetup(
                f"Podman {'.'.join(str(v) for v in info.version)} detected.\n\n"
                + global_hooks_hint()
            )

        args += [
            "--cap-drop",
            "NET_ADMIN",
            "--cap-drop",
            "NET_RAW",
        ]
        return args

    def _write_policy_and_resolve(self, sd: Path, entries: list[str], tier: DnsTier) -> None:
        """Write the composed profiles as the project-allow tier; statically resolve only where needed.

        The authored ``policy/40-project-allow`` is the source of truth
        (domains + literal IPs).  On the dnsmasq tier there is **no**
        pre-resolution: dnsmasq commits every answered A/AAAA record to the
        allow sets *before* forwarding the reply (``forward.c`` calls the
        nftset add synchronously while processing the upstream response), so
        a workload can never race its own answer.  The kernel set is
        populated on demand, per query — launch cost stays O(1) in allowlist
        size, and CDN rotation is tracked for free.  Any stale
        ``resolved.ips`` is removed so the ruleset seeds from literal IPs
        only.

        The dig/getent fallback tiers have no DNS interception point, so
        statically resolving every admitted target into ``resolved.ips``
        (refreshed when stale or older than the authored policy) remains
        their only domain-enforcement mechanism.
        """
        bundle = StateBundle(sd)
        bundle.write_tier("project_allow", "".join(f"+{e}\n" for e in entries))
        if tier == DnsTier.DNSMASQ:
            bundle.resolved_cache.unlink(missing_ok=True)
            return
        self._dns.resolve_and_cache(
            bundle.read_effective().allow_targets(),
            bundle.resolved_cache,
            source_mtime=bundle.policy_mtime(),
        )

    def _write_ruleset(
        self, sd: Path, tier: DnsTier, upstream_dns: str, gw_v4: str = "", gw_v6: str = ""
    ) -> None:
        """Pre-generate the complete nft ruleset into the state bundle."""
        set_timeout = NFT_SET_TIMEOUT_DNSMASQ if tier == DnsTier.DNSMASQ else ""
        ruleset_builder = RulesetBuilder(
            dns=upstream_dns,
            loopback_ports=StateBundle(sd).read_loopback_ports(),
            gateway_v4=gw_v4,
            gateway_v6=gw_v6,
            set_timeout=set_timeout,
        )
        ips = StateBundle(sd).read_effective_ips()
        denied_ips = list(StateBundle(sd).read_denied_ips())
        ruleset = ruleset_builder.build_hook()
        ruleset += ruleset_builder.add_elements_dual(ips)
        if denied_ips:
            ruleset += add_deny_elements_dual(denied_ips)
        StateBundle(sd).ruleset.write_text(ruleset)

    def _write_dnsmasq_config_or_scrub(self, sd: Path, tier: DnsTier, upstream_dns: str) -> None:
        """Pre-generate dnsmasq config for dnsmasq tier, or scrub stale artifacts."""
        if tier == DnsTier.DNSMASQ:
            bind = _dnsmasq_bind(self._config.runtime)
            domains = dnsmasq.read_merged_domains(sd)
            conf = dnsmasq.generate_config(
                upstream_dns,
                domains,
                StateBundle(sd).dnsmasq_pid,
                listen_address=bind,
                log_path=StateBundle(sd).dnsmasq_log,
                deny_domains=dnsmasq.read_denied_domains(sd),
            )
            StateBundle(sd).dnsmasq_conf.write_text(conf)
            StateBundle(sd).resolv_conf.write_text(f"nameserver {bind}\noptions ndots:0\n")
        else:
            for stale in (
                StateBundle(sd).dnsmasq_conf,
                StateBundle(sd).dnsmasq_pid,
                StateBundle(sd).resolv_conf,
            ):
                stale.unlink(missing_ok=True)

    def _build_network_args(self, mode: str) -> list[str]:
        """Build rootless network arguments (pasta or slirp4netns)."""
        if os.geteuid() == 0:
            return []
        if mode == "slirp4netns":
            gw = slirp4netns_gateway()
            return [
                "--network",
                "slirp4netns:allow_host_loopback=true",
                "--add-host",
                f"host.containers.internal:{gw}",
            ]
        # Use pasta --map-host-loopback unconditionally so that
        # host.containers.internal always resolves to an address
        # pasta actually forwards to the host's 127.0.0.1.
        return [
            "--network",
            f"pasta:--map-host-loopback,{PASTA_HOST_LOOPBACK_MAP}",
            "--add-host",
            f"host.containers.internal:{PASTA_HOST_LOOPBACK_MAP}",
        ]

    def _detect_dns_tier(self, container: str, state_dir: Path) -> DnsTier:
        """Pick the DNS tier, logging an advisory when AppArmor downgrades dnsmasq."""
        tier, apparmor_blocked = apparmor.detect_dns_tier_under_apparmor(self._runner, state_dir)
        if apparmor_blocked:
            self._audit.log_event(
                container,
                "setup",
                detail=(
                    f"DNS tier fell back to {tier.value}: AppArmor confines dnsmasq "
                    f"from {state_dir}. Install the terok AppArmor profile to keep "
                    "the dnsmasq tier — see docs/apparmor.md."
                ),
            )
        return tier

    def _get_podman_info(self) -> PodmanInfo:
        """Get podman info, caching the result for the lifetime of this instance."""
        if self._podman_info is None:
            output = self._runner.run(["podman", "info", "-f", "json"], check=False)
            self._podman_info = parse_podman_info(output)
        return self._podman_info

    # ── Live operations (domain) ───────────────────────

    def allow_domain(self, domain: str) -> None:
        """Record ``+domain`` in the runtime overlay and signal a dnsmasq reload.

        The overlay (``policy/live``) flips any prior deny of *domain* and
        survives reloads; dnsmasq re-reads the composed domain list on SIGHUP
        so the change takes effect without a container restart.  The IP-level
        allow (nft set update) is handled separately by ``allow_ip()``.

        No-op when the container is not using the dnsmasq DNS tier (the static
        IP-level allow already happened via ``allow_ip()``).
        """
        sd = self._config.state_dir.resolve()
        if not _is_dnsmasq_tier(sd):
            return
        StateBundle(sd).overlay_set("+", domain)
        self._reload_dnsmasq(sd)

    def deny_domain(self, domain: str) -> None:
        """Record ``-domain`` in the runtime overlay and signal a dnsmasq reload.

        Counterpart of ``allow_domain()``: dnsmasq stops auto-populating nft
        sets for *domain* and sinkholes its queries (NXDOMAIN), so the deny
        fails fast in the DNS plane instead of timing out against the filter.

        No-op when the container is not using the dnsmasq DNS tier.
        """
        sd = self._config.state_dir.resolve()
        if not _is_dnsmasq_tier(sd):
            return
        StateBundle(sd).overlay_set("-", domain)
        self._reload_dnsmasq(sd)

    def _reload_dnsmasq(self, state_dir: Path) -> None:
        """Regenerate dnsmasq config and send SIGHUP.

        No-op if dnsmasq is not running (PID file absent).
        Raises RuntimeError if dnsmasq is dead (stale PID).
        """
        upstream = self._read_upstream_dns()
        if not upstream:
            raise RuntimeError("Cannot reload dnsmasq: upstream DNS not persisted in state")

        domains = dnsmasq.read_merged_domains(state_dir)
        dnsmasq.reload(state_dir, upstream, domains, dnsmasq.read_denied_domains(state_dir))

    # ── Live operations (IP) ────────────────────────────

    def allow_ip(self, container: str, ip: str) -> None:
        """Live-allow an IP for a running container via nsenter."""
        ip = safe_ip(ip)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)

        # Un-deny: drop from the nft deny set if it is currently denied.
        if ip in bundle.read_denied_ips():
            nft_cmd = delete_deny_elements_dual([ip])
            if nft_cmd:
                self._nft_apply_best_effort(container, nft_cmd)

        # When the dnsmasq set has a default timeout (30 m), permanent IPs must use
        # 'timeout 0s' so they are never evicted by the set's per-element expiry clock.
        tier_path = bundle.dns_tier
        if tier_path.is_file() and tier_path.read_text().strip() == DnsTier.DNSMASQ.value:
            element = f"{{ {ip} timeout 0s }}"
        else:
            element = f"{{ {ip} }}"

        self._runner.nft_via_nsenter(
            container,
            "add",
            "element",
            "inet",
            "terok_shield",
            self._set_for_ip(ip),
            element,
        )
        # Persist to the runtime overlay (flips any prior deny of this IP).
        bundle.overlay_set("+", ip)

    def deny_ip(self, container: str, ip: str) -> None:
        """Live-deny an IP for a running container via nsenter.

        Removes from the nft allow set (best-effort), adds to the nft deny set,
        and records ``-ip`` in ``policy/live`` so the deny sticks across
        ``shield up`` / restart and flips any prior allow.
        """
        ip = safe_ip(ip)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)

        # Best-effort nft delete (IP may not be in the set)
        try:
            self._runner.nft_via_nsenter(
                container,
                "delete",
                "element",
                "inet",
                "terok_shield",
                self._set_for_ip(ip),
                f"{{ {ip} }}",
            )
        except ExecError as e:
            stderr = str(e).lower()
            if not any(
                pat in stderr for pat in ("no such file", "element does not exist", "not in set")
            ):
                logger.warning("nft delete element failed for %s: %s", ip, e)

        # Add to nft deny set (prevents dnsmasq from re-allowing)
        nft_cmd = add_deny_elements_dual([ip])
        if nft_cmd:
            self._nft_apply_best_effort(container, nft_cmd)

        # Persist to the runtime overlay (flips any prior allow; sticks across restart).
        bundle.overlay_set("-", ip)

    def _set_for_ip(self, ip: str) -> str:
        """Return the tier-40 project-allow nft set for an IP address (by family)."""
        return f"{TIER_PROJECT_ALLOW}_v4" if is_ipv4(ip) else f"{TIER_PROJECT_ALLOW}_v6"

    def _nft_apply_best_effort(self, container: str, nft_cmd: str) -> None:
        """Run multi-line nft commands via nsenter, swallowing errors."""
        for line in nft_cmd.strip().splitlines():
            parts = line.strip().split()
            if parts:
                try:
                    self._runner.nft_via_nsenter(container, *parts)
                except ExecError:
                    pass

    # ── State transitions ───────────────────────────────

    def shield_down(self, container: str, *, allow_all: bool = False) -> None:
        """Switch a running container to shield-down (accept-all + deny.list)."""
        sd = self._config.state_dir.resolve()
        ruleset = self._container_ruleset(container)
        rs = ruleset.build_bypass(allow_all=allow_all)
        current = self.shield_state(container)
        if current == ShieldState.OFFLINE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        snapshot = [] if current == ShieldState.OFFLINE else self._snapshot_allow_sets(container)
        self._runner.nft_via_nsenter(container, stdin=stdin)

        # Carry the allow-set contents (seeds + dnsmasq-learned IPs) across
        # the rebuild — bypass mode does not evaluate them, but the later
        # ``shield up`` snapshots this table, so dropping them here would
        # forget every learned IP after one down/up round trip.
        self._restore_allow_sets(container, snapshot, skip=())

        # Repopulate deny sets so deny.list is enforced even when shield is down.
        denied_ips = list(StateBundle(sd).read_denied_ips())
        if denied_ips:
            deny_cmd = add_deny_elements_dual(denied_ips)
            if deny_cmd:
                self._runner.nft_via_nsenter(container, stdin=deny_cmd)

        output = self._runner.nft_via_nsenter(
            container,
            "list",
            "table",
            "inet",
            NFT_TABLE_NAME,
        )
        errors = ruleset.verify_bypass(output, allow_all=allow_all)
        if errors:
            raise RuntimeError(f"Shield-down ruleset verification failed: {'; '.join(errors)}")

    def shield_quarantine(self, container: str) -> None:
        """Total network blackout — drop all traffic, log dropped traffic.

        Reads no settings — no DNS, no allowlists, no loopback ports,
        no gateway probe, no profile lookup.  ``build_quarantine`` /
        ``verify_quarantine`` are static; the only inputs are the
        container name and the live ruleset state (table-or-no-table).
        Any config-conditional branch added here is a bug.
        """
        rs = RulesetBuilder.build_quarantine()
        current = self.shield_state(container)
        stdin = rs if current == ShieldState.OFFLINE else f"delete table {NFT_TABLE}\n{rs}"
        self._runner.nft_via_nsenter(container, stdin=stdin)
        output = self._runner.nft_via_nsenter(
            container,
            "list",
            "table",
            "inet",
            NFT_TABLE_NAME,
        )
        errors = RulesetBuilder.verify_quarantine(output)
        if errors:
            raise RuntimeError(f"Quarantine ruleset verification failed: {'; '.join(errors)}")

    def shield_up(self, container: str) -> None:
        """Restore normal deny-all mode for a running container.

        The rebuild is ``delete table`` + re-apply, which would forget every
        dnsmasq-learned allow-set element — a container coming out of a bypass
        window would suddenly lose IPs its workload already resolved (clients
        cache answers, so they do not necessarily re-query).  The allow sets
        are therefore snapshotted before the rebuild and restored after it.
        """
        sd = self._config.state_dir.resolve()

        ruleset = self._container_ruleset(container)
        rs = ruleset.build_hook()
        current = self.shield_state(container)
        if current == ShieldState.OFFLINE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        snapshot = [] if current == ShieldState.OFFLINE else self._snapshot_allow_sets(container)
        self._runner.nft_via_nsenter(container, stdin=stdin)

        # Re-add effective IPs (allowed minus denied)
        unique_ips = StateBundle(sd).read_effective_ips()
        if unique_ips:
            elements_cmd = ruleset.add_elements_dual(unique_ips)
            if elements_cmd:
                self._runner.nft_via_nsenter(container, stdin=elements_cmd)

        # Repopulate deny sets from deny.list
        denied_ips = list(StateBundle(sd).read_denied_ips())
        if denied_ips:
            deny_cmd = add_deny_elements_dual(denied_ips)
            if deny_cmd:
                self._runner.nft_via_nsenter(container, stdin=deny_cmd)

        # Restore the snapshot, minus everything the rebuild already re-added
        # (a duplicate/overlapping element would abort the nft transaction)
        # and minus denied entries (deny_ip() removed them from the allow set
        # deliberately — a bypass round trip must not resurrect them).
        self._restore_allow_sets(container, snapshot, skip=[*unique_ips, *denied_ips])

        # Gateway addresses are baked into the ruleset — no repopulation needed.

        output = self._runner.nft_via_nsenter(
            container,
            "list",
            "table",
            "inet",
            NFT_TABLE_NAME,
        )
        errors = ruleset.verify_hook(output)
        if errors:
            raise RuntimeError(f"Ruleset verification failed: {'; '.join(errors)}")

    def shield_reset(self, container: str) -> None:
        """Forget learned allow-set state — back to the just-launched contents.

        Flushes both tier-40 project-allow sets and re-seeds them from the
        effective policy in a single nft transaction, so authored literals
        never blink out.  dnsmasq-learned IPs vanish until the workload
        resolves the corresponding names again; the operator overlay
        (``policy/live``) and the deny tier are untouched.
        """
        sd = self._config.state_dir.resolve()
        ruleset = self._container_ruleset(container)
        stdin = (
            f"flush set {NFT_TABLE} {TIER_PROJECT_ALLOW}_v4\n"
            f"flush set {NFT_TABLE} {TIER_PROJECT_ALLOW}_v6\n"
        )
        stdin += ruleset.add_elements_dual(StateBundle(sd).read_effective_ips())
        self._runner.nft_via_nsenter(container, stdin=stdin)

    def migrate_state(self) -> bool:
        """One-way migration of a pre-v15 state bundle to the current layout.

        Called before restarting a task container that predates the current
        terok-shield: translates the legacy policy files
        ([`migrate_legacy_policy`][terok_shield.state.migrate_legacy_policy]),
        regenerates the artifacts the OCI hook consumes (``ruleset.nft``,
        ``dnsmasq.conf``, ``resolv.conf``) from the persisted tier/upstream/
        ports, and stamps ``bundle.version`` so the hook's restart gate opens.
        Rules reset to the migrated policy — dnsmasq-learned state and (on the
        dnsmasq tier) previously resolved seeds are not carried over.

        Returns True when a migration ran, False when the bundle is already
        current.  Raises RuntimeError when the bundle was never prepared
        (no persisted upstream DNS) — there is nothing to migrate.
        """
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)
        if bundle.read_bundle_version() == state.BUNDLE_VERSION:
            return False
        state.migrate_legacy_policy(sd)
        upstream = bundle.upstream_dns.read_text().strip() if bundle.upstream_dns.is_file() else ""
        if not upstream:
            raise RuntimeError(
                "Cannot migrate: upstream DNS not persisted — this state dir was never prepared."
            )
        tier_txt = bundle.dns_tier.read_text().strip() if bundle.dns_tier.is_file() else ""
        tier = DnsTier(tier_txt) if tier_txt else DnsTier.DIG
        if tier == DnsTier.DNSMASQ:
            bundle.resolved_cache.unlink(missing_ok=True)  # learned-first: no seed
        gw_v4, gw_v6 = _gateways_for_mode(self._get_podman_info().network_mode or "pasta")
        self._write_ruleset(sd, tier, upstream, gw_v4, gw_v6)
        self._write_dnsmasq_config_or_scrub(sd, tier, upstream)
        bundle.write_bundle_version()
        return True

    # ── Allow-set snapshot/restore (down/up round trips) ─

    def _snapshot_allow_sets(self, container: str) -> list[tuple[str, str, str]]:
        """Dump the tier-40 allow sets as ``(set_name, ip, timeout)`` rows.

        Captures seeds and dnsmasq-learned elements right before a table
        rebuild.  A missing table or set yields no rows — there was nothing
        to keep.  (Tiers 10/30 have no runtime population yet; extend this
        snapshot when they gain one.)
        """
        rows: list[tuple[str, str, str]] = []
        for fam in ("v4", "v6"):
            name = f"{TIER_PROJECT_ALLOW}_{fam}"
            try:
                out = self._runner.nft_via_nsenter(
                    container, "list", "set", "inet", NFT_TABLE_NAME, name
                )
            except ExecError:
                continue
            rows += [(name, ip, timeout) for ip, timeout in parse_set_elements(out)]
        return rows

    def _restore_allow_sets(
        self, container: str, rows: list[tuple[str, str, str]], *, skip: Iterable[str]
    ) -> None:
        """Re-add snapshot *rows*, minus IPs already covered by *skip* entries.

        *skip* holds the IPs/CIDRs the rebuild re-added through its own
        channels — restoring one of those would collide inside the nft
        transaction (a duplicate or overlapping interval aborts the whole
        batch).  Restore failure is logged, never raised: coming up with a
        cold allow set beats staying in bypass.
        """
        keep = [row for row in rows if not _covered(row[1], skip)]
        if not keep:
            return
        by_set: dict[str, list[tuple[str, str]]] = {}
        for name, ip, timeout in keep:
            by_set.setdefault(name, []).append((ip, timeout))
        stdin = "".join(restore_elements(name, els) for name, els in by_set.items())
        try:
            self._runner.nft_via_nsenter(container, stdin=stdin)
        except ExecError as exc:
            logger.warning(
                "allow-set restore failed for %s (workload re-learns via DNS): %s", container, exc
            )

    def _container_ruleset(self, container: str) -> RulesetBuilder:
        """Build a RulesetBuilder with the container's actual DNS settings.

        Prefers persisted upstream DNS (from pre_start) over resolv.conf,
        because dnsmasq mode rewrites resolv.conf to the runtime-specific
        dnsmasq listen address (``127.0.0.1`` by default; a link-local
        address under krun).
        """
        upstream = self._read_upstream_dns()
        dns = upstream if upstream else self._read_container_dns(container)

        # Read persisted DNS tier to determine if set timeouts are needed
        sd = self._config.state_dir.resolve()
        tier_path = StateBundle(sd).dns_tier
        set_timeout = ""
        if tier_path.is_file():
            tier_str = tier_path.read_text().strip()
            if tier_str == DnsTier.DNSMASQ.value:
                set_timeout = NFT_SET_TIMEOUT_DNSMASQ

        if self._gateways is None:
            self._gateways = _gateways_for_mode(self._get_podman_info().network_mode or "pasta")
        gw_v4, gw_v6 = self._gateways
        return RulesetBuilder(
            dns=dns,
            loopback_ports=StateBundle(sd).read_loopback_ports(),
            gateway_v4=gw_v4,
            gateway_v6=gw_v6,
            set_timeout=set_timeout,
        )

    def _read_upstream_dns(self) -> str | None:
        """Read persisted upstream DNS from state (written by pre_start).

        Returns None if the file is absent (pre-dnsmasq container or
        container started before this feature).
        """
        sd = self._config.state_dir.resolve()
        path = StateBundle(sd).upstream_dns
        if not path.is_file():
            return None
        value = path.read_text().strip()
        return value or None

    def _read_container_dns(self, container: str) -> str:
        """Read DNS nameserver from a running container's resolv.conf.

        Uses ``/proc/{pid}/root/etc/resolv.conf`` via ``podman unshare``
        to access the container's rootfs without entering its mount
        namespace (avoids requiring ``cat`` inside the container).
        """
        pid = self._runner.podman_inspect(container, "{{.State.Pid}}")
        output = self._runner.run(
            ["podman", "unshare", "cat", f"/proc/{pid}/root/etc/resolv.conf"],
            check=False,
        )
        dns = parse_resolv_conf(output)
        if not dns:
            raise RuntimeError(
                f"Cannot determine DNS for container {container}: no nameserver in resolv.conf"
            )
        return dns

    # ── Queries ─────────────────────────────────────────

    def shield_state(self, container: str) -> ShieldState:
        """Query the live nft ruleset to determine the container's shield state."""
        output = self.list_rules(container)
        if not output.strip():
            return ShieldState.OFFLINE

        # verify_* returns a list of errors; empty list = ruleset is valid.
        # Block is checked first: its minimal ruleset (no sets, no DNS)
        # would fail all other verifiers.
        if not self._ruleset.verify_quarantine(output):
            return ShieldState.QUARANTINE

        if not self._ruleset.verify_bypass(output, allow_all=False):
            return ShieldState.DOWN
        if not self._ruleset.verify_bypass(output, allow_all=True):
            return ShieldState.DISENGAGED

        if not self._ruleset.verify_hook(output):
            return ShieldState.UP

        return ShieldState.ERROR

    def list_rules(self, container: str) -> str:
        """List current nft rules for a running container."""
        try:
            return self._runner.nft_via_nsenter(
                container,
                "list",
                "table",
                "inet",
                "terok_shield",
                check=False,
            )
        except ExecError:
            return ""

    def preview(self, *, down: bool = False, allow_all: bool = False) -> str:
        """Generate the ruleset that would be applied to a container."""
        if down:
            return self._ruleset.build_bypass(allow_all=allow_all)
        return self._ruleset.build_hook()


# ── Module-level helpers ────────────────────────────────


def _dnsmasq_bind(runtime: ShieldRuntime) -> str:
    """Return the dnsmasq listen address for *runtime*."""
    return DNSMASQ_BIND_KRUN if runtime is ShieldRuntime.KRUN else DNSMASQ_BIND_DEFAULT


def _upstream_dns_for_mode(network_mode: str) -> str:
    """Return the upstream DNS forwarder address for a network mode.

    Raises ValueError for unrecognised modes so new modes (e.g. bridge)
    get an explicit implementation rather than a silent wrong default.
    """
    if network_mode == "slirp4netns":
        return SLIRP4NETNS_DNS
    if network_mode == "pasta":
        return PASTA_DNS
    raise ValueError(
        f"Cannot determine upstream DNS for network mode {network_mode!r}. "
        "Add support for this mode in _upstream_dns_for_mode()."
    )


def _gateways_for_mode(network_mode: str) -> tuple[str, str]:
    """Return ``(gateway_v4, gateway_v6)`` for a network mode.

    slirp4netns uses a virtual 10.0.2.0/24 network; the gateway is
    deterministically ``CIDR base + 2`` (reads ``containers.conf`` for a
    custom ``cidr=`` override).  pasta host-service access is handled by
    ``_loopback_port_rules()`` (literal 169.254.1.2) and needs no gateway.
    """
    if network_mode == "slirp4netns":
        return slirp4netns_gateway(), SLIRP4NETNS_GATEWAY_V6
    if network_mode == "pasta":
        return "", ""
    raise ValueError(
        f"Cannot determine gateways for network mode {network_mode!r}. "
        "Add support for this mode in _gateways_for_mode()."
    )


def _covered(ip: str, skip: Iterable[str]) -> bool:
    """True when *ip* overlaps any IP/CIDR entry of *skip*.

    Overlap matters, not just equality: re-adding a snapshot element that
    intersects an interval the rebuild already re-added would abort the
    whole nft restore transaction.  Unparseable *skip* entries are ignored.
    """
    addr = ipaddress.ip_network(ip, strict=False)
    for entry in skip:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if isinstance(net, type(addr)) and addr.overlaps(net):
            return True
    return False


def _is_dnsmasq_tier(state_dir: Path) -> bool:
    """Return True when the container's DNS tier is dnsmasq (or unknown).

    ``allow_domain`` / ``deny_domain`` are dnsmasq-specific enhancements
    (future IP rotation tracking via ``--nftset``).  On dig/getent tiers
    the static IP-level allow/deny in ``allow_ip``/``deny_ip`` already ran;
    the domain-tracking step is simply not available and callers skip it.

    Returns True when ``dns_tier_path`` is absent (pre_start not yet run —
    pass-through so the caller can still attempt the dnsmasq operation).
    """
    tier_path = StateBundle(state_dir).dns_tier
    if not tier_path.is_file():
        return True
    return tier_path.read_text().strip() == DnsTier.DNSMASQ.value
