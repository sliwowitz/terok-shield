# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""``shield watch`` — stream blocked-access events as JSON lines.

Tails the per-container audit log, (optionally) the NFLOG netlink socket,
and the dnsmasq query log on the tiers that run dnsmasq.  Clean exit on
SIGINT or SIGTERM.
"""

import select
import signal
import sys
from pathlib import Path

from .config import DnsTier
from .state import StateBundle
from .watchers import AuditLogWatcher, DnsLogWatcher, DomainCache, NflogWatcher, WatchEvent

_running = True


# ── Entry point ─────────────────────────────────────────


def run_watch(state_dir: Path, container: str) -> None:
    """Stream blocked-access events as JSON lines to stdout.

    The audit log and the NFLOG socket feed every tier; the dnsmasq query
    log feeds only the tiers that run dnsmasq, so elsewhere the events carry
    IP addresses and no domain.  Uses ``select`` so a single thread can
    multiplex the sources without blocking on any one of them.

    Args:
        state_dir: Per-container state directory.
        container: Container name (for event metadata).

    Raises:
        SystemExit: If the container recorded no DNS tier.
    """
    bundle = StateBundle(state_dir)
    tier = bundle.read_dns_tier()
    if tier is None:
        print("Error: DNS tier not set — container may not be shielded.", file=sys.stderr)
        raise SystemExit(1)

    _install_signal_handlers()

    dns_watcher = _dns_log_watcher(bundle, tier, container)
    audit_watcher = AuditLogWatcher(bundle.audit, container)
    nflog_watcher = NflogWatcher.create(container)
    domain_cache = DomainCache(state_dir)

    try:
        while _running:
            _poll_nflog_or_sleep(nflog_watcher, domain_cache)
            if dns_watcher:
                _emit_events(dns_watcher.poll())
            _emit_events(audit_watcher.poll())
    finally:
        if dns_watcher:
            dns_watcher.close()
        audit_watcher.close()
        if nflog_watcher:
            nflog_watcher.close()


def _dns_log_watcher(bundle: StateBundle, tier: DnsTier, container: str) -> DnsLogWatcher | None:
    """The query-log source on a tier that runs dnsmasq; ``None`` elsewhere, said on stderr.

    ``pre_start()`` configures ``log-facility=<path>``, but dnsmasq may not
    have written any queries yet when ``shield watch`` starts, so the file
    is created here.
    """
    if not tier.runs_dnsmasq:
        print(f"DNS tier {tier.value}: events carry IP addresses only.", file=sys.stderr)
        return None
    bundle.dnsmasq_log.touch(exist_ok=True)
    return DnsLogWatcher(bundle.dnsmasq_log, bundle.state_dir, container)


# ── Event loop mechanics ────────────────────────────────


def _install_signal_handlers() -> None:
    """Reset the stop flag and register SIGINT/SIGTERM for clean shutdown."""
    global _running  # noqa: PLW0603
    _running = True
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


def _poll_nflog_or_sleep(nflog_watcher: NflogWatcher | None, domain_cache: DomainCache) -> None:
    """Wait on the NFLOG socket (or sleep 1s) and emit any packets."""
    if nflog_watcher:
        readable, _, _ = select.select([nflog_watcher], [], [], 1.0)
        if readable:
            _emit_events(_enrich_nflog(nflog_watcher.poll(), domain_cache))
    else:
        select.select([], [], [], 1.0)


def _emit_events(events: list[WatchEvent]) -> None:
    """Print each event as a JSON line to stdout."""
    for event in events:
        print(event.to_json(), flush=True)


def _enrich_nflog(events: list[WatchEvent], cache: DomainCache) -> list[WatchEvent]:
    """Attach cached domain names to NFLOG events that have a dest IP.

    Refreshes the cache at most once per batch to avoid reparsing the
    entire dnsmasq log for every cache miss.
    """
    enriched: list[WatchEvent] = []
    refreshed = False
    for ev in events:
        if ev.dest and not ev.domain:
            domain = cache.lookup(ev.dest)
            if not domain and not refreshed:
                cache.refresh()
                refreshed = True
                domain = cache.lookup(ev.dest)
            if domain:
                from dataclasses import replace

                ev = replace(ev, domain=domain)
        enriched.append(ev)
    return enriched
