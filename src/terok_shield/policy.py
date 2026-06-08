# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The unified ``+``/``-`` policy line format — one grammar for every tier.

A policy file is one entry per line::

    +pypi.org                       # allow a domain
    +*.pythonhosted.org             # allow every subdomain
    +192.168.1.50:8080              # allow one host:port
    -telemetry.vendor.com           # deny
    +api.anthropic.com   # reason=harness-test expires=2026-06-09T12:00Z

The leading ``+`` (allow) or ``-`` (deny) is **mandatory** — there is no
bare-line shortcut and no ``Pass`` token (a tier's Pass behaviour is
structural, not per-line).  ``#`` starts a comment; a trailing comment may
carry optional ``key=value`` metadata (``reason``, ``expires``, ``from``,
``first``/``last``, ``hits``).  Blank and comment-only lines are ignored.

This module is the single parser for shipped, generated, and authored
policy alike — replacing the old allow-only ``parse_entries`` and the split
``allow``/``deny`` files.  Stdlib-only, so it is cheap to audit and safe to
import from anywhere.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

Action = Literal["+", "-"]
"""A policy verdict prefix: ``"+"`` (allow) or ``"-"`` (deny)."""

# A DNS name: dot-separated labels of alphanumerics/hyphen/underscore, with an
# optional leading ``*.`` standing for "any subdomain".  Deliberately
# permissive about the TLD (internal names like ``metadata.google.internal``
# are valid targets) but strict about shape, so no whitespace, slash, or
# path-traversal character can slip into a target.
_DOMAIN = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$")
_MAX_PORT = 65535


@dataclass(frozen=True, slots=True)
class PolicyEntry:
    """One parsed policy line.

    Attributes:
        action: ``"+"`` (allow) or ``"-"`` (deny).
        target: a domain (optionally ``*.``-prefixed), an IP literal, or a CIDR.
        port: the optional ``:port`` (``None`` when unspecified).
        comment: the raw trailing comment text (sans ``#``), or ``None``.
    """

    action: Action
    target: str
    port: int | None = None
    comment: str | None = None

    def meta(self) -> dict[str, str]:
        """Parse the ``key=value`` metadata tokens out of the trailing comment."""
        return parse_meta(self.comment)


def parse_policy(text: str) -> list[PolicyEntry]:
    """Parse policy text into entries, failing fast on a malformed line.

    Raises:
        ValueError: on a missing ``+``/``-`` prefix, an empty or invalid
            target, or an out-of-range port — annotated with the line number.
    """
    entries: list[PolicyEntry] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body, _, comment = line.partition("#")
        try:
            entries.append(_parse_line(body.strip(), comment.strip() or None))
        except ValueError as exc:
            raise ValueError(f"line {lineno}: {exc} ({raw!r})") from exc
    return entries


def render_policy(entries: list[PolicyEntry]) -> str:
    """Render entries back to canonical text (round-trips [`parse_policy`][terok_shield.policy.parse_policy])."""
    lines = []
    for e in entries:
        # An IPv6 literal carrying a port must be bracketed, else ``addr:port``
        # is indistinguishable from a longer IPv6 address on re-parse.
        host = f"[{e.target}]" if (e.port is not None and ":" in e.target) else e.target
        line = f"{e.action}{host}" + (f":{e.port}" if e.port is not None else "")
        if e.comment:
            line += f"  # {e.comment}"
        lines.append(line)
    return "\n".join(lines) + "\n" if lines else ""


def parse_meta(comment: str | None) -> dict[str, str]:
    """Extract ``key=value`` tokens from a comment; non-``key=value`` tokens are ignored."""
    if not comment:
        return {}
    return dict(token.split("=", 1) for token in comment.split() if "=" in token)


def _parse_line(body: str, comment: str | None) -> PolicyEntry:
    """Parse one non-comment ``body`` (a ``+``/``-`` prefix plus ``target[:port]``)."""
    if not body or body[0] not in "+-":
        raise ValueError("entry must start with '+' (allow) or '-' (deny)")
    action: Action = body[0]  # type: ignore[assignment]
    target, port = _split_port(body[1:].strip())
    if not target:
        raise ValueError("empty target")
    _validate_target(target)
    return PolicyEntry(action, target, port, comment)


def _split_port(spec: str) -> tuple[str, int | None]:
    """Split an optional ``:port``, handling bracketed and bare IPv6 literals."""
    if spec.startswith("["):  # [ipv6] or [ipv6]:port
        host, sep, rest = spec[1:].partition("]")
        if not sep:
            raise ValueError("unterminated '[' in IPv6 literal")
        return host, (_parse_port(rest[1:]) if rest.startswith(":") else None)
    if spec.count(":") >= 2:  # bare IPv6 literal — a port needs brackets
        return spec, None
    host, sep, maybe_port = spec.rpartition(":")
    if sep and maybe_port.isdigit():
        return host, _parse_port(maybe_port)
    return spec, None


def _parse_port(text: str) -> int:
    """Parse and range-check a 1..65535 port number."""
    if not text.isdigit() or not 1 <= (port := int(text)) <= _MAX_PORT:
        raise ValueError(f"invalid port: {text!r}")
    return port


def _validate_target(target: str) -> None:
    """Accept a domain (optionally ``*.``-prefixed), an IP literal, or a CIDR."""
    try:
        ipaddress.ip_network(target, strict=False)
        return
    except ValueError:
        pass
    if not _DOMAIN.fullmatch(target):
        raise ValueError(f"invalid target: {target!r}")


__all__ = ["Action", "PolicyEntry", "parse_meta", "parse_policy", "render_policy"]
