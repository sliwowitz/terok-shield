# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution with timestamp-based caching.

Resolves allowlist domains via ``dig`` (``getent`` fallback) and caches
the IPs so containers do not block on DNS at every start.

Two cache layers:

- **per-container file** (``cache_path``): the view the nft ruleset reads.
  Scoped to one container, so a fresh container never reuses another's.
- **host cache** (``host_cache_dir``): shared across containers, keyed by
  the allowlist's content hash. The first task resolves; the rest read.

Domains resolve concurrently with a per-lookup timeout, so a batch costs
about one lookup and one dead domain cannot stall startup.  A batch that
does run says so on stderr, before and after: the launcher is waiting on
it, and a silent wait reads as a hang.

Every tier but ``dnsmasq-live`` uses this module at launch.  On that tier
domains resolve on-demand at runtime via ``--nftset``; this module then
handles raw IPs only.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

import contextlib
import hashlib
import logging
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..paths import dns_cache_dir
from ..run import CommandRunner
from ..state import STATE_DIR_MODE, read_name_resolution, render_name_resolution
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


_CACHE_MAX_AGE = 3600
"""Seconds a resolution cache stays fresh, per container and on the host alike."""


class DnsResolver:
    """Stateless DNS resolver — all persistence lives in the cache files.

    Depends on a [`CommandRunner`][terok_shield.dns.resolver.CommandRunner]
    for lookup-tool (``dig``/``drill``) and ``getent`` subprocess calls
    and a host-level cache directory shared across containers.
    """

    def __init__(self, *, runner: CommandRunner, host_cache_dir: Path | None = None) -> None:
        """Inject the command runner and the shared cache location.

        Args:
            runner: Command runner used for all DNS subprocess calls.
            host_cache_dir: Cross-container cache directory; ``None`` selects
                [`dns_cache_dir`][terok_shield.paths.dns_cache_dir].
        """
        self._runner = runner
        self._host_cache_dir = host_cache_dir or dns_cache_dir()

    # ── Public API ──────────────────────────────────────────

    def resolve_and_cache(
        self,
        entries: list[str],
        cache_path: Path,
        *,
        force: bool = False,
        source_mtime: float = 0.0,
    ) -> list[str]:
        """Resolve profile entries and cache the result.

        Reads the per-container file first, then the shared host cache
        (materializing a hit into the per-container file), and only resolves
        when both miss.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: Per-container file the nft ruleset reads.
            force: Re-resolve even when a cache is younger than the one-hour
                freshness window.
            source_mtime: mtime of the authored policy; a per-container cache
                older than it is re-resolved even within the freshness window,
                so an edited allowlist takes effect on the next task start. The
                host cache ignores this — its content-hash key already makes it
                edit-aware.

        Returns:
            Resolved IPv4/IPv6 addresses combined with raw IPs/CIDRs.
        """
        max_age = 0 if force else _CACHE_MAX_AGE
        if self._cache_fresh(cache_path, max_age, source_mtime):
            return self._read_cache(cache_path)

        host_path = self._host_cache_path(entries)
        if self._cache_fresh(host_path, max_age):
            ips = self._read_cache(host_path)
            self._write_cache(cache_path, ips)
            return ips

        domains, raw_ips = self._split_entries(entries)
        resolved = self._resolve_announced(domains)
        all_ips = raw_ips + resolved

        if domains and not resolved and self._cache_current(cache_path, source_mtime):
            # Not one name answered (a DNS outage, a broken resolver) while the
            # cache holds an answer for this very policy that merely aged out:
            # keep it — stale addresses beat none.  Left untouched, the cache
            # stays stale, so the next resolve tries again.  (The deny caches
            # need more than this — a name that fails *alone* must keep its
            # addresses too — so they resolve per name, through
            # ``resolve_names_and_cache`` with ``keep_unanswered``.)
            logger.warning("no name in %s resolved — keeping the previous answer", cache_path.name)
            return self._read_cache(cache_path)
        self._write_cache(cache_path, all_ips)
        # An all-domains-failed resolve (DNS outage, broken resolver) is fine
        # for one container but must not poison every task on the host for
        # max_age: share only when at least one domain resolved (or there were
        # none to resolve).
        if resolved or not domains:
            self._write_cache(host_path, all_ips)
        return all_ips

    def resolve_names_and_cache(
        self,
        names: list[str],
        cache_path: Path,
        *,
        force: bool = False,
        source_mtime: float = 0.0,
        keep_unanswered: bool = False,
        kind: str = "override",
    ) -> dict[str, list[str]]:
        """Resolve each of *names* on its own and cache which addresses came from which name.

        The name-keyed sibling of
        [`resolve_and_cache`][terok_shield.dns.resolver.DnsResolver.resolve_and_cache],
        for a tier whose entries need more than a pool of addresses: the t10
        override, where every entry carries its own expiry and an address must
        be timed to the expiry of the name it came from, and the two t20 deny
        caches.  The same freshness rules hold (one hour, and never older than
        *source_mtime*), and a resolve in which not one name answered keeps a
        cache that merely aged out.  No host-wide cache: such names are few,
        and a deny must never take a partial answer from another container.

        *keep_unanswered* is the deny caches' rule: a name that answers
        nothing this time keeps the addresses it had, where an answering name
        takes its new ones.  One lookup timing out must not drop a vault
        host's addresses out of the t20 set at the next rebuild — in the DOWN
        posture, and wherever nothing sinkholes the name, that would open the
        host — so for a deny a stale answer beats none.  An override keeps
        nothing: an address its name no longer answers with is not reached.
        *kind* names the names in the stderr announcement.

        Returns:
            Each name with addresses, after *keep_unanswered*; a name left
            with none is absent.
        """
        resolved = self.resolve_names(
            names,
            cache_path,
            force=force,
            source_mtime=source_mtime,
            keep_unanswered=keep_unanswered,
            kind=kind,
        )
        if resolved is None:
            cached = read_name_resolution(cache_path) or {}
            return {name: cached[name] for name in names if name in cached}
        self._write_text(cache_path, render_name_resolution(resolved))
        return resolved

    def resolve_names(
        self,
        names: list[str],
        cache_path: Path,
        *,
        force: bool = False,
        source_mtime: float = 0.0,
        keep_unanswered: bool = False,
        kind: str = "override",
    ) -> dict[str, list[str]] | None:
        """What [`resolve_names_and_cache`][terok_shield.dns.resolver.DnsResolver.resolve_names_and_cache] would cache — without writing it.

        The same rules, with *cache_path* only read: for a caller that may
        persist an answer only once something else has taken it.  A live
        override grant resolves its names, swaps the running t10 set, and
        only then records the grant and caches what it seeded — a grant
        refused for want of an answer must leave the cache as it was.

        Returns:
            Each name with addresses, as the cache would hold them after
            *keep_unanswered* — or ``None`` when the cache stands as it is:
            fresh, or kept through a resolve in which not one name answered.
        """
        max_age = 0 if force else _CACHE_MAX_AGE
        cached = read_name_resolution(cache_path)
        if cached is not None and self._cache_fresh(cache_path, max_age, source_mtime):
            return None
        answers = self._resolve_each_announced(names, kind)
        if (
            names
            and not any(answers.values())
            and cached is not None
            and self._cache_current(cache_path, source_mtime)
        ):
            logger.warning("no name in %s resolved — keeping the previous answer", cache_path.name)
            return None
        if keep_unanswered and cached:
            for name in (n for n in names if not answers.get(n) and cached.get(n)):
                logger.warning(
                    "%s answered nothing — %s keeps its previous addresses", name, cache_path.name
                )
                answers[name] = cached[name]
        return {name: ips for name, ips in answers.items() if ips}

    def _resolve_each_announced(self, names: list[str], kind: str) -> dict[str, list[str]]:
        """[`resolve_each`][terok_shield.dns.resolver.DnsResolver.resolve_each], announced on stderr like a batch."""
        if not names:
            return {}
        rounds = -(-len(names) // MAX_RESOLVE_WORKERS)
        bound = rounds * RESOLVE_TIMEOUT * 2
        print(f"Resolving {len(names)} {kind} names, up to {bound} s.", file=sys.stderr)
        answers = self.resolve_each(names)
        print(f"Resolved {sum(1 for ips in answers.values() if ips)} names.", file=sys.stderr)
        return answers

    def _resolve_announced(self, domains: list[str]) -> list[str]:
        """Resolve *domains* and tell the operator what the wait is for.

        The bound is the worst case of the thread pool: every lookup timing
        out, each followed by its ``getent`` retry.
        """
        if not domains:
            return []
        rounds = -(-len(domains) // MAX_RESOLVE_WORKERS)
        bound = rounds * RESOLVE_TIMEOUT * 2
        print(f"Resolving {len(domains)} allowlist names, up to {bound} s.", file=sys.stderr)
        started = time.monotonic()
        ips = self.resolve_domains(domains)
        elapsed = time.monotonic() - started
        print(f"Resolved to {len(ips)} addresses in {elapsed:.1f} s.", file=sys.stderr)
        return ips

    def resolve_domains(self, domains: list[str], *, quiet: bool = False) -> list[str]:
        """Resolve domain names to IPs (A + AAAA), best-effort and concurrent.

        Probes for a lookup tool once, then resolves every domain on a small thread
        pool — a batch costs about its slowest single lookup. Unresolvable
        domains are skipped with a warning (a typo or a DNS failure), logged
        always and printed to stderr unless *quiet*: a background check — the
        security-tier refresh before a live allow — must not crowd out the
        one line its own caller prints there.  Results are deduplicated in
        first-seen (input) order.
        """
        per_domain = self.resolve_each(domains, quiet=quiet)
        return list(dict.fromkeys(ip for ips in per_domain.values() for ip in ips))

    def resolve_each(self, domains: list[str], *, quiet: bool = False) -> dict[str, list[str]]:
        """Resolve every domain on its own: the addresses per name, in input order.

        The per-name form of [`resolve_domains`][terok_shield.dns.resolver.DnsResolver.resolve_domains],
        with the same lookup-tool probe, thread pool and warnings; a name that
        resolved to nothing maps to an empty list.
        """
        if not domains:
            return {}
        if self._runner.has("dig") or self._runner.has("drill"):
            resolve = self._resolve_via_lookup
        else:
            logger.warning("neither dig nor drill found — using getent for DNS resolution")
            resolve = self._resolve_via_getent
        with ThreadPoolExecutor(max_workers=min(len(domains), MAX_RESOLVE_WORKERS)) as pool:
            per_domain = list(pool.map(resolve, domains))
        for domain in (d for d, ips in zip(domains, per_domain, strict=True) if not ips):
            message = f"No address for {domain}."
            logger.warning(message)
            if not quiet:
                print(message, file=sys.stderr)
        return dict(zip(domains, per_domain, strict=True))

    # ── Resolution detail ───────────────────────────────────

    def _resolve_via_lookup(self, domain: str) -> list[str]:
        """Resolve via the lookup tool, retrying through NSS on an empty answer.

        An empty answer is usually not a dead domain: some environments
        break the tool specifically (an EDNS-hostile forwarder, a hardened
        path) while glibc resolution still works, so we retry that one
        domain through ``getent`` before giving up (terok#1119).
        """
        ips = self._runner.lookup_all(domain, timeout=RESOLVE_TIMEOUT)
        if not ips:
            ips = self._runner.getent_hosts(domain, timeout=RESOLVE_TIMEOUT)
            if ips:
                logger.warning(
                    "lookup returned nothing for %r but NSS resolved it — the tool is broken here",
                    domain,
                )
        return ips

    def _resolve_via_getent(self, domain: str) -> list[str]:
        """Resolve via NSS (``getent``) — the path taken when ``dig`` is absent."""
        return self._runner.getent_hosts(domain, timeout=RESOLVE_TIMEOUT)

    # ── Cache mechanics ─────────────────────────────────────

    def _host_cache_path(self, entries: list[str]) -> Path:
        """Shared cache file for this exact entry list.

        Keyed by the content hash of the entry list: any allowlist edit lands
        on a fresh key and re-resolves. Creates the directory ``0700`` on first
        use.
        """
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
    def _cache_current(path: Path, source_mtime: float) -> bool:
        """True when *path* holds an answer for the current policy — stale by age at most.

        Unlike ``_cache_fresh`` it ignores age: a cache that post-dates the
        authored policy still answers for it, however long ago it was written.
        """
        try:
            return path.stat().st_mtime >= source_mtime
        except OSError:
            return False

    @staticmethod
    def _read_cache(path: Path) -> list[str]:
        """Read cached IPs from a resolved file."""
        if not path.is_file():
            return []
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]

    @classmethod
    def _write_cache(cls, path: Path, ips: list[str]) -> None:
        """Write resolved IPs atomically, one per line."""
        cls._write_text(path, "\n".join(ips) + "\n" if ips else "")

    @staticmethod
    def _write_text(path: Path, text: str) -> None:
        """Write a cache file atomically (unique temp file + rename).

        The host-level file is shared across concurrently starting tasks — a
        torn read would seed a container with a truncated allowlist — and two
        threads of one process can write the same (content-hash-keyed) file at
        once, so each write goes to its own ``mkstemp`` temp before the rename.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(text)
            os.replace(tmp, path)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
