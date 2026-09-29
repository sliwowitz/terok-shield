# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""TCP integration probes distinguish connectivity from command-launch errors."""

import subprocess
from collections.abc import Callable
from unittest import mock

import pytest

from tests.integration import helpers
from tests.testnet import ALLOWED_TARGET_HTTPS_PORT, ALLOWED_TARGET_IPS


@pytest.mark.parametrize(
    ("probe", "returncode"),
    [(helpers.assert_connectable, 0), (helpers.assert_not_connectable, 1)],
)
def test_tcp_probe_expected_outcome(probe: Callable[..., None], returncode: int) -> None:
    """Both assertions inspect the container and run a fresh TCP probe."""
    results = [
        subprocess.CompletedProcess([], 0, stdout="true\n", stderr=""),
        subprocess.CompletedProcess([], returncode, stdout="", stderr=""),
    ]
    with mock.patch.object(helpers.subprocess, "run", side_effect=results) as run:
        probe("test-container", ALLOWED_TARGET_IPS[0], port=ALLOWED_TARGET_HTTPS_PORT, timeout=2)

    assert run.call_count == 2
    run.assert_called_with(
        [
            "podman",
            "exec",
            "test-container",
            "nc",
            "-z",
            "-w",
            "2",
            ALLOWED_TARGET_IPS[0],
            str(ALLOWED_TARGET_HTTPS_PORT),
        ],
        capture_output=True,
        text=True,
        timeout=7,
    )


@pytest.mark.parametrize(
    ("probe", "returncode"),
    [
        (helpers.assert_connectable, 1),
        (helpers.assert_not_connectable, 0),
        (helpers.assert_not_connectable, 125),
        (helpers.assert_not_connectable, 126),
        (helpers.assert_not_connectable, 127),
    ],
)
def test_tcp_probe_failure_diagnostics(probe: Callable[..., None], returncode: int) -> None:
    """Unexpected results include both streams; exec failures never mean blocked."""
    results = [
        subprocess.CompletedProcess([], 0, stdout="true\n", stderr=""),
        subprocess.CompletedProcess([], returncode, stdout="probe output", stderr="probe error"),
    ]
    with (
        mock.patch.object(helpers.subprocess, "run", side_effect=results),
        pytest.raises(AssertionError) as error,
    ):
        probe("test-container", ALLOWED_TARGET_IPS[0], port=ALLOWED_TARGET_HTTPS_PORT)

    message = str(error.value)
    assert f"{ALLOWED_TARGET_IPS[0]}:{ALLOWED_TARGET_HTTPS_PORT}" in message
    assert f"exit {returncode}" in message
    assert "stdout: 'probe output'" in message
    assert "stderr: 'probe error'" in message
