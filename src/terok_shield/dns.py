# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution with timestamp-based caching.

Allowlist profiles use domain names rather than raw IPs because CDN and
cloud addresses rotate.  This module resolves those names via ``dig``
and caches the results so containers do not wait on DNS at every start.
"""

import logging
import time
from pathlib import Path

from .run import CommandRunner
from .util import is_ip as _is_ip

logger = logging.getLogger(__name__)


class DnsResolver:
    """Stateless DNS resolver — all persistence is in the cache file.

    The only dependency is a :class:`CommandRunner` for ``dig`` calls.
    """

    def __init__(self, *, runner: CommandRunner) -> None:
        """Inject the command runner used for all ``dig`` calls."""
        self._runner = runner

    def resolve_and_cache(
        self,
        entries: list[str],
        cache_path: Path,
        *,
        max_age: int = 3600,
    ) -> list[str]:
        """Resolve profile entries and cache the result.

        Profiles mix domain names with literal IPs/CIDRs — domains go
        through ``dig``, literals pass through unchanged.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: Per-container (one resolver may serve many containers).
            max_age: Cache freshness threshold in seconds (default: 1 hour).

        Returns:
            Resolved IPv4/IPv6 addresses combined with raw IPs/CIDRs.
        """
        if self._cache_fresh(cache_path, max_age):
            return self._read_cache(cache_path)

        domains, raw_ips = self._split_entries(entries)
        resolved = self.resolve_domains(domains)
        all_ips = raw_ips + resolved

        self._write_cache(cache_path, all_ips)
        return all_ips

    def resolve_domains(self, domains: list[str]) -> list[str]:
        """Best-effort resolution; deduplicated in first-seen order."""
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

    @staticmethod
    def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
        """Separate entries into (domains, raw_ips)."""
        domains, ips = [], []
        for entry in entries:
            (_ips := ips if _is_ip(entry) else domains).append(entry)
        return domains, ips

    @staticmethod
    def _cache_fresh(path: Path, max_age: int) -> bool:
        """Check whether the cache file exists and is younger than *max_age* seconds."""
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
