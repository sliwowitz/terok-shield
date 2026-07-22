# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution with timestamp-based caching.

Resolves allowlist domains via ``dig`` (``getent`` fallback) and caches
the IPs so containers do not block on DNS at every start.

Two cache layers:

- **per-container file** (``cache_path``): the view the nft ruleset reads.
  Scoped to one container, so a fresh container never reuses another's.
- **host cache** (``host_cache_dir``, opt-in, off by default): shared across
  containers, keyed by the allowlist's content hash. The first task resolves;
  the rest read.

Domains resolve concurrently with a per-lookup timeout, so a batch costs
about one lookup and one dead domain cannot stall startup.

Only the dig/getent tiers use this module at launch. On the dnsmasq tier
domains resolve on-demand at runtime via ``--nftset``; this module then
handles raw IPs only.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

import hashlib
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..run import CommandRunner
from ..state import STATE_DIR_MODE
from ..util import is_ip as _is_ip

logger = logging.getLogger(__name__)

RESOLVE_TIMEOUT = 2
"""Per-subprocess DNS budget in seconds.

Best-effort: an answer slower than this counts as no answer. The old 10s
budget let one dead domain (times the getent retry) stall a start by ~20s.
"""

MAX_RESOLVE_WORKERS = 16
"""Upper bound on concurrent resolver subprocesses per batch."""

_HOST_CACHE_KEY_LEN = 16
"""Hex digits of the entry-list hash used as the host-cache filename."""


class DnsResolver:
    """Stateless DNS resolver — all persistence lives in the cache files.

    Depends on a [`CommandRunner`][terok_shield.dns.resolver.CommandRunner]
    for ``dig`` / ``getent`` subprocess calls and, optionally, a host-level
    cache directory shared across containers.
    """

    def __init__(self, *, runner: CommandRunner, host_cache_dir: Path | None = None) -> None:
        """Inject the command runner and the optional shared cache location.

        Args:
            runner: Command runner used for all DNS subprocess calls.
            host_cache_dir: Cross-container cache directory. ``None`` (the
                default) disables the shared layer.
        """
        self._runner = runner
        self._host_cache_dir = host_cache_dir

    # ── Public API ──────────────────────────────────────────

    def resolve_and_cache(
        self,
        entries: list[str],
        cache_path: Path,
        *,
        max_age: int = 3600,
        source_mtime: float = 0.0,
    ) -> list[str]:
        """Resolve profile entries and cache the result.

        Reads the per-container file first, then the shared host cache
        (materializing a hit into the per-container file), and only resolves
        when both miss.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: Per-container file the nft ruleset reads.
            max_age: Cache freshness threshold in seconds (default: 1 hour).
            source_mtime: mtime of the authored policy; a per-container cache
                older than it is re-resolved even within ``max_age``, so an
                edited allowlist takes effect on the next task start. The host
                cache ignores this — its content-hash key already makes it
                edit-aware.

        Returns:
            Resolved IPv4/IPv6 addresses combined with raw IPs/CIDRs.
        """
        if self._cache_fresh(cache_path, max_age, source_mtime):
            return self._read_cache(cache_path)

        host_path = self._host_cache_path(entries)
        if host_path is not None and self._cache_fresh(host_path, max_age):
            ips = self._read_cache(host_path)
            self._write_cache(cache_path, ips)
            return ips

        domains, raw_ips = self._split_entries(entries)
        resolved = self.resolve_domains(domains)
        all_ips = raw_ips + resolved

        self._write_cache(cache_path, all_ips)
        # An all-domains-failed resolve (DNS outage, broken resolver) is fine
        # for one container but must not poison every task on the host for
        # max_age: share only when at least one domain resolved (or there were
        # none to resolve).
        if host_path is not None and (resolved or not domains):
            self._write_cache(host_path, all_ips)
        return all_ips

    def resolve_domains(self, domains: list[str]) -> list[str]:
        """Resolve domain names to IPs (A + AAAA), best-effort and concurrent.

        Probes for ``dig`` once, then resolves every domain on a small thread
        pool — a batch costs about its slowest single lookup. Unresolvable
        domains are skipped with a warning; results are deduplicated in
        first-seen (input) order.
        """
        if not domains:
            return []
        if self._runner.has("dig"):
            resolve = self._resolve_via_dig
        else:
            logger.warning("dig not found — using getent for DNS resolution")
            resolve = self._resolve_via_getent
        with ThreadPoolExecutor(max_workers=min(len(domains), MAX_RESOLVE_WORKERS)) as pool:
            per_domain = pool.map(resolve, domains)
        return list(dict.fromkeys(ip for ips in per_domain for ip in ips))

    # ── Resolution detail ───────────────────────────────────

    def _resolve_via_dig(self, domain: str) -> list[str]:
        """Resolve via ``dig``, retrying one domain through NSS when dig answers empty.

        An empty ``dig`` answer is usually not a dead domain: some environments
        break ``dig`` specifically (an EDNS-hostile forwarder, a hardened path)
        while glibc resolution still works, so we retry that one domain through
        ``getent`` before giving up (terok#1119).
        """
        ips = self._runner.dig_all(domain, timeout=RESOLVE_TIMEOUT)
        if not ips:
            ips = self._runner.getent_hosts(domain, timeout=RESOLVE_TIMEOUT)
            if ips:
                logger.warning(
                    "dig returned nothing for %r but NSS resolved it — dig is broken here", domain
                )
        return self._warn_if_empty(domain, ips)

    def _resolve_via_getent(self, domain: str) -> list[str]:
        """Resolve via NSS (``getent``) — the path taken when ``dig`` is absent."""
        ips = self._runner.getent_hosts(domain, timeout=RESOLVE_TIMEOUT)
        return self._warn_if_empty(domain, ips)

    @staticmethod
    def _warn_if_empty(domain: str, ips: list[str]) -> list[str]:
        """Warn on an empty resolution (typo or DNS failure); pass the IPs through."""
        if not ips:
            logger.warning("Domain %r resolved to no IPs (typo or DNS failure?)", domain)
        return ips

    # ── Cache mechanics ─────────────────────────────────────

    def _host_cache_path(self, entries: list[str]) -> Path | None:
        """Shared cache file for this exact entry list, or ``None`` when off.

        Keyed by the content hash of the entry list: any allowlist edit lands
        on a fresh key and re-resolves. Creates the directory ``0700`` on first
        use.
        """
        if self._host_cache_dir is None:
            return None
        self._host_cache_dir.mkdir(parents=True, exist_ok=True)
        self._host_cache_dir.chmod(STATE_DIR_MODE)
        digest = hashlib.sha256("\n".join(entries).encode()).hexdigest()
        return self._host_cache_dir / f"{digest[:_HOST_CACHE_KEY_LEN]}.resolved"

    @staticmethod
    def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
        """Separate entries into (domains, raw_ips)."""
        domains: list[str] = []
        ips: list[str] = []
        for entry in entries:
            (ips if _is_ip(entry) else domains).append(entry)
        return domains, ips

    @staticmethod
    def _cache_fresh(path: Path, max_age: int, source_mtime: float = 0.0) -> bool:
        """True when *path* exists, is younger than *max_age*, and post-dates *source_mtime*.

        A cache older than *source_mtime* (the authored policy's mtime) is
        stale even within *max_age* — the allowlist changed since we resolved.
        """
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return False
        # future: jitter max_age per-container so many tasks don't re-resolve
        # in a synchronized wave at the hour boundary.
        if mtime < source_mtime:
            return False
        return (time.time() - mtime) < max_age

    @staticmethod
    def _read_cache(path: Path) -> list[str]:
        """Read cached IPs from a resolved file."""
        if not path.is_file():
            return []
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]

    @staticmethod
    def _write_cache(path: Path, ips: list[str]) -> None:
        """Write resolved IPs atomically (write + rename).

        The host-level file is read by concurrently starting tasks, and a torn
        read there would seed a container with a truncated allowlist.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text("\n".join(ips) + "\n" if ips else "")
        tmp.replace(path)
