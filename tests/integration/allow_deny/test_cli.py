# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: CLI allow/deny subcommands."""

import tempfile
from pathlib import Path

import pytest

from terok_shield import Shield, ShieldConfig
from terok_shield.cli.main import main
from tests.testnet import ALLOWED_TARGET_HTTPS_PORT, ALLOWED_TARGET_IPS

from ..conftest import nft_missing, podman_missing
from ..helpers import assert_connectable, assert_not_connectable


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestAllowDenyCLI:
    """End-to-end CLI allow/deny tests with a real shielded container."""

    def test_cli_allow(self, shielded_container: str) -> None:
        """``main(["allow", container, ip])`` makes IP reachable."""
        for ip in ALLOWED_TARGET_IPS:
            main(["allow", shielded_container, ip])
        assert_connectable(
            shielded_container, ALLOWED_TARGET_IPS[0], port=ALLOWED_TARGET_HTTPS_PORT
        )

    def test_cli_deny(self, shielded_container: str) -> None:
        """``main(["deny", container, ip])`` blocks the IP."""
        # First allow, then deny
        with tempfile.TemporaryDirectory() as tmp:
            shield = Shield(ShieldConfig(state_dir=Path(tmp)))
            for ip in ALLOWED_TARGET_IPS:
                shield.allow(shielded_container, ip)
            assert_connectable(
                shielded_container, ALLOWED_TARGET_IPS[0], port=ALLOWED_TARGET_HTTPS_PORT
            )

            for ip in ALLOWED_TARGET_IPS:
                main(["deny", shielded_container, ip])
            assert_not_connectable(
                shielded_container, ALLOWED_TARGET_IPS[0], port=ALLOWED_TARGET_HTTPS_PORT
            )
