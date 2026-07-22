# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution with timestamp-based caching.

Resolves domain names from allowlist profiles via ``dig`` and caches
the results so containers do not block on DNS at every start.  Profiles
prefer domain names over raw IPs because CDN addresses rotate.

Falls back to ``getent hosts`` when ``dig`` is not installed, and
per-domain when ``dig`` runs but yields nothing (some environments break
``dig`` while glibc resolution still works) — fewer IPs are captured
(no parallel A + AAAA query), but resolution still works.  The dnsmasq tier does not use this module at launch at all —
domain resolution happens at runtime via ``--nftset``; static resolution
is the fallback tiers' (dig/getent) enforcement mechanism and the
``shield resolve`` warm-up path.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

import logging
import time
from pathlib import Path

from ..run import CommandRunner, DigNotFoundError
from ..util import is_ip as _is_ip

logger = logging.getLogger(__name__)


class DnsResolver:
    """Stateless DNS resolver — all persistence lives in the cache file.

    The only dependency is a [`CommandRunner`][terok_shield.dns.resolver.CommandRunner] for ``dig`` / ``getent``
    subprocess calls.
    """

    def __init__(self, *, runner: CommandRunner) -> None:
        """Inject the command runner used for all DNS subprocess calls."""
        self._runner = runner

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

        Profiles mix domain names with literal IPs/CIDRs — domains go
        through DNS resolution, literals pass through unchanged.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: File to store resolved IPs in, per-container scoped.
            max_age: Cache freshness threshold in seconds (default: 1 hour).
            source_mtime: mtime of the authored policy the entries came from;
                a cache older than this is re-resolved even when still within
                ``max_age``, so an edited allowlist takes effect on the next
                task start instead of waiting out the timer.

        Returns:
            Resolved IPv4/IPv6 addresses combined with raw IPs/CIDRs.
        """
        if self._cache_fresh(cache_path, max_age, source_mtime):
            return self._read_cache(cache_path)

        domains, raw_ips = self._split_entries(entries)
        resolved = self.resolve_domains(domains)
        all_ips = raw_ips + resolved

        self._write_cache(cache_path, all_ips)
        return all_ips

    def resolve_domains(self, domains: list[str]) -> list[str]:
        """Resolve domain names to IP addresses (A + AAAA), best-effort.

        Unresolvable domains are skipped with a warning.  Results are
        deduplicated in first-seen order.
        """
        seen: set[str] = set()
        result: list[str] = []
        use_getent = False
        for domain in domains:
            try:
                ips = self._resolve_one(domain, use_getent=use_getent)
            except DigNotFoundError:
                # dig missing — degrade gracefully for the rest of this batch
                logger.warning("dig not found — falling back to getent for DNS resolution")
                use_getent = True
                ips = self._resolve_one(domain, use_getent=True)
            if not ips and not use_getent:
                # dig ran but produced nothing.  That is usually not a dead
                # domain: some environments break dig specifically (a DNS
                # forwarder rejecting its EDNS options, a hardened container
                # path) while glibc resolution still works — so retry this
                # one domain through getent before giving up.  Per-domain,
                # not batch-wide: one genuinely dead domain must not demote
                # the resolver for the rest.
                ips = self._resolve_one(domain, use_getent=True)
                if ips:
                    # NSS resolving what dig could not is the proof that dig
                    # itself is broken here (crashed, EDNS-hostile forwarder)
                    # -- worth a warning, since dig's own stderr is not
                    # surfaced (the mageia/64K jemalloc SIGABRT hid behind
                    # this exact silence, terok#1119).
                    logger.warning(
                        "dig returned nothing for %r but NSS resolved it — "
                        "dig is broken in this environment",
                        domain,
                    )
            if not ips:
                logger.warning("Domain %r resolved to no IPs (typo or DNS failure?)", domain)
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
        return result

    # ── Resolution detail ───────────────────────────────────

    def _resolve_one(self, domain: str, *, use_getent: bool = False) -> list[str]:
        """Resolve a single domain using dig or getent."""
        if use_getent:
            return self._runner.getent_hosts(domain)
        return self._runner.dig_all(domain)

    # ── Cache mechanics ─────────────────────────────────────

    @staticmethod
    def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
        """Separate entries into (domains, raw_ips)."""
        domains: list[str] = []
        ips: list[str] = []
        for entry in entries:
            (_ips := ips if _is_ip(entry) else domains).append(entry)
        return domains, ips

    @staticmethod
    def _cache_fresh(path: Path, max_age: int, source_mtime: float = 0.0) -> bool:
        """Check whether the cache exists, is younger than *max_age*, and post-dates its source.

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
        """Write resolved IPs to a cache file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(ips) + "\n" if ips else "")
