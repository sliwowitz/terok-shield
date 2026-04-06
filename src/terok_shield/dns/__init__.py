# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution and caching subsystem.

Collaborators:
    resolver — stateless DNS resolution with dig/getent
    dnsmasq — dnsmasq lifecycle, config generation, nftset integration
"""
