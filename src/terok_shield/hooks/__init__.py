# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook system — install, configure, and execute container hooks.

Collaborators:
    install — hook file generation and directory setup
    mode — hook-mode lifecycle (pre_start, apply, up/down/block)
"""
