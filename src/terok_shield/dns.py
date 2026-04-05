# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution with timestamp-based caching.

Given a mix of domain names and raw IP addresses, resolve the domains
via ``dig``, combine with the pass-through IPs, and cache the result.
On subsequent calls the cache is returned if still fresh.

The entry point is :meth:`DnsResolver.resolve_and_cache`.
"""

import logging
import time
from pathlib import Path

from .run import CommandRunner
from .util import is_ip as _is_ip

logger = logging.getLogger(__name__)


class DnsResolver:
    """Stateless DNS resolver with file-based caching.

    All state lives on the filesystem (the cache file).  The only
    dependency is a :class:`CommandRunner` for ``dig`` calls.
    """

    def __init__(self, *, runner: CommandRunner) -> None:
        """Create a resolver.

        Args:
            runner: Command runner for ``dig`` subprocess calls.
        """
        self._runner = runner

    # ── Main story ──────────────────────────────────────────

    def resolve_and_cache(
        self,
        entries: list[str],
        cache_path: Path,
        *,
        max_age: int = 3600,
    ) -> list[str]:
        """Resolve profile entries and cache the result.

        This is the single entry point for callers.  The flow:

        1. If the cache is fresh, return it immediately.
        2. Otherwise split entries into domains and raw IPs/CIDRs.
        3. Resolve the domains via dig (A + AAAA).
        4. Combine raw IPs with resolved IPs, write cache, return.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: Path to the cache file for this container.
            max_age: Cache freshness threshold in seconds (default: 1 hour).

        Returns:
            List of resolved IPv4/IPv6 addresses + raw IPs/CIDRs.
        """
        if self._cache_fresh(cache_path, max_age):
            return self._read_cache(cache_path)

        # Profiles mix domains and literal IPs — split so we only resolve the domains
        domains, raw_ips = self._split_entries(entries)
        resolved = self.resolve_domains(domains)
        all_ips = raw_ips + resolved

        self._write_cache(cache_path, all_ips)
        return all_ips

    # ── Resolution detail ───────────────────────────────────

    def resolve_domains(self, domains: list[str]) -> list[str]:
        """Resolve domain names to IPv4 and IPv6 addresses.

        Queries both A and AAAA records for each domain.
        Skips domains that fail to resolve (best-effort).
        Returns deduplicated IPs in first-seen order.
        """
        seen: set[str] = set()
        result: list[str] = []
        for domain in domains:
            ips = self._runner.dig_all(domain)
            if not ips:
                logger.warning("Domain %r resolved to no IPs (typo or DNS failure?)", domain)
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
        return result

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
        """Separate entries into (domains, raw_ips)."""
        domains, ips = [], []
        for entry in entries:
            (_ips := ips if _is_ip(entry) else domains).append(entry)
        return domains, ips

    @staticmethod
    def _cache_fresh(path: Path, max_age: int) -> bool:
        """Return True if the cache file exists and is younger than *max_age* seconds."""
        try:
            mtime = path.stat().st_mtime
        except OSError:
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
