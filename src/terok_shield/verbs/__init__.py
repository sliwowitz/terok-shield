# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-verb command modules — the lazy targets of the top-level registry.

Each module here defines the fully-populated
[`CommandDef`][terok_util.cli_types.CommandDef] for a cohesive group of
verbs, together with the handler bodies they dispatch to.  The top-level
registry ([`terok_shield.commands`][terok_shield.commands]) references
each verb by a ``"module:CONST"`` source string, so building the
registry — and wiring ``terok-shield --help`` — imports none of these
modules; only the one verb actually invoked is resolved, and with it
only its module.

The split is by cohesion, not one-file-per-verb: ``control`` (live nft
mutation), ``observe`` (read-only queries), ``stream`` (long-running
event readers), and ``launch`` (standalone container-launch verbs, whose
CLI-specific bodies live in [`terok_shield.cli.main`][terok_shield.cli.main]).
"""
