# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-container state bundle layout (state.py)."""

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from terok_shield.state import BUNDLE_VERSION, STATE_DIR_MODE, StateBundle

from ..testfs import FAKE_STATE_DIR, READER_PID_FILENAME
from ..testnet import TEST_DOMAIN, TEST_DOMAIN2, TEST_IP1, TEST_IP2, TEST_IP3


def test_bundle_version_is_positive_int() -> None:
    """BUNDLE_VERSION is a positive integer."""
    assert isinstance(BUNDLE_VERSION, int)
    assert BUNDLE_VERSION > 0


@pytest.mark.parametrize(
    ("attr", "expected"),
    [
        pytest.param("hooks_dir", FAKE_STATE_DIR / "hooks", id="hooks-dir"),
        pytest.param("hook_entrypoint", FAKE_STATE_DIR / "terok-shield-hook", id="hook-entrypoint"),
        pytest.param("profile_allowed", FAKE_STATE_DIR / "profile.allowed", id="profile-allowed"),
        pytest.param("live_allowed", FAKE_STATE_DIR / "live.allowed", id="live-allowed"),
        pytest.param("deny", FAKE_STATE_DIR / "deny.list", id="deny-path"),
        pytest.param("audit", FAKE_STATE_DIR / "audit.jsonl", id="audit-path"),
        pytest.param("profile_domains", FAKE_STATE_DIR / "profile.domains", id="profile-domains"),
        pytest.param("dnsmasq_conf", FAKE_STATE_DIR / "dnsmasq.conf", id="dnsmasq-conf"),
        pytest.param("dnsmasq_pid", FAKE_STATE_DIR / "dnsmasq.pid", id="dnsmasq-pid"),
        pytest.param("dns_tier", FAKE_STATE_DIR / "dns.tier", id="dns-tier"),
        pytest.param("live_domains", FAKE_STATE_DIR / "live.domains", id="live-domains"),
        pytest.param("denied_domains", FAKE_STATE_DIR / "denied.domains", id="denied-domains"),
        pytest.param("container_id", FAKE_STATE_DIR / "container.id", id="container-id"),
        pytest.param("reader_pid", FAKE_STATE_DIR / READER_PID_FILENAME, id="reader-pid"),
    ],
)
def test_path_property(attr: str, expected: Path) -> None:
    """Pure path properties derive deterministic paths under the state dir."""
    assert getattr(StateBundle(FAKE_STATE_DIR), attr) == expected


@pytest.mark.parametrize(
    ("stage", "expected_name"),
    [
        pytest.param("createRuntime", "terok-shield-createRuntime.json", id="create-runtime"),
        pytest.param("poststop", "terok-shield-poststop.json", id="poststop"),
    ],
)
def test_hook_json(stage: str, expected_name: str) -> None:
    """``StateBundle.hook_json(stage)`` derives the per-stage OCI hook JSON filenames."""
    assert StateBundle(FAKE_STATE_DIR).hook_json(stage) == FAKE_STATE_DIR / "hooks" / expected_name


@pytest.mark.parametrize(
    "relative_state_dir",
    [
        pytest.param(Path("container-1"), id="single-level"),
        pytest.param(Path("deep") / "nested" / "state", id="nested"),
    ],
)
def test_ensure_dirs_creates_required_directories(
    tmp_path: Path,
    relative_state_dir: Path,
) -> None:
    """``StateBundle.ensure_dirs()`` creates the state dir and hooks subdirectory."""
    bundle = StateBundle(tmp_path / relative_state_dir)
    bundle.ensure_dirs()

    assert bundle.state_dir.is_dir()
    assert bundle.hooks_dir.is_dir()


def test_ensure_dirs_is_idempotent(tmp_path: Path) -> None:
    """``StateBundle.ensure_dirs()`` is safe to call repeatedly."""
    bundle = StateBundle(tmp_path / "container-1")
    bundle.ensure_dirs()
    bundle.ensure_dirs()
    assert bundle.state_dir.is_dir()


@pytest.fixture
def loose_umask() -> Iterator[None]:
    """Run the test body under ``umask 0o002`` (Fedora's USERGROUPS_ENAB default)."""
    old = os.umask(0o002)
    try:
        yield
    finally:
        os.umask(old)


def _mode(path: Path) -> int:
    """Return permission bits of *path* (``st_mode & 0o7777``)."""
    return stat.S_IMODE(path.stat().st_mode)


def test_ensure_dirs_forces_owner_only_mode(
    tmp_path: Path,
    loose_umask: None,
) -> None:
    """Fresh dirs land at 0o700 even when the caller's umask would relax them.

    Regression test for the v0.6.35 ``_oci_state`` validator rejecting
    bundles created under ``umask 0o002`` (group-writable).  ``mkdir``
    alone is umask-masked, so ``StateBundle.ensure_dirs()`` must ``chmod``.
    """
    bundle = StateBundle(tmp_path / "container-1")
    bundle.ensure_dirs()

    assert _mode(bundle.state_dir) == STATE_DIR_MODE
    assert _mode(bundle.hooks_dir) == STATE_DIR_MODE
    # Validator-side invariant: no group/world write bits.
    assert bundle.state_dir.stat().st_mode & 0o022 == 0
    assert bundle.hooks_dir.stat().st_mode & 0o022 == 0


def test_ensure_dirs_repairs_loose_existing_mode(tmp_path: Path) -> None:
    """A pre-existing too-permissive bundle is tightened on next call.

    Users hit by v0.6.35 with a 0o775 dir from a prior 0.6.34 run
    should recover automatically — no manual ``chmod`` required.
    """
    bundle = StateBundle(tmp_path / "container-1")
    bundle.state_dir.mkdir()
    bundle.hooks_dir.mkdir()
    bundle.state_dir.chmod(0o775)
    bundle.hooks_dir.chmod(0o775)

    bundle.ensure_dirs()

    assert _mode(bundle.state_dir) == STATE_DIR_MODE
    assert _mode(bundle.hooks_dir) == STATE_DIR_MODE


def test_read_denied_ips_empty_when_file_missing(tmp_path: Path) -> None:
    """``StateBundle.read_denied_ips()`` returns an empty set when deny.list is absent."""
    assert StateBundle(tmp_path).read_denied_ips() == set()


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param(f"{TEST_IP1}\n{TEST_IP2}\n", {TEST_IP1, TEST_IP2}, id="multiple"),
        pytest.param(f"\n{TEST_IP1}\n\n", {TEST_IP1}, id="skip-blanks"),
    ],
)
def test_read_denied_ips(tmp_path: Path, content: str, expected: set[str]) -> None:
    """``read_denied_ips()`` ignores blank lines while preserving denied entries."""
    bundle = StateBundle(tmp_path)
    bundle.deny.write_text(content)
    assert bundle.read_denied_ips() == expected


def test_read_effective_ips_subtracts_denied(tmp_path: Path) -> None:
    """Denied IPs are removed from the effective allow list."""
    bundle = StateBundle(tmp_path)
    bundle.profile_allowed.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
    bundle.deny.write_text(f"{TEST_IP1}\n")
    assert bundle.read_effective_ips() == [TEST_IP2]


def test_read_effective_ips_without_deny_file_includes_live_entries(tmp_path: Path) -> None:
    """Without deny.list, effective IPs include both profile and live entries."""
    bundle = StateBundle(tmp_path)
    bundle.profile_allowed.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
    bundle.live_allowed.write_text(f"{TEST_IP3}\n")
    assert bundle.read_effective_ips() == [TEST_IP1, TEST_IP2, TEST_IP3]


def test_read_effective_ips_ignores_denied_entries_not_in_allowed_set(tmp_path: Path) -> None:
    """Unmatched deny.list entries do not affect the effective allow list."""
    bundle = StateBundle(tmp_path)
    bundle.profile_allowed.write_text(f"{TEST_IP1}\n")
    bundle.deny.write_text(f"{TEST_IP3}\n")
    assert bundle.read_effective_ips() == [TEST_IP1]


# ── ballast sync contract ────────────────────────────────────────────────────


def test_oci_state_bundle_version_matches_state() -> None:
    """``_oci_state.BUNDLE_VERSION`` must equal ``state.BUNDLE_VERSION``.

    The stdlib-only ballast can't import state.py, so it duplicates the
    constant.  This test is the enforcement mechanism — both role
    scripts read ``BUNDLE_VERSION`` from the same ballast.
    """
    from terok_shield.resources import _oci_state as _ep

    assert _ep.BUNDLE_VERSION == BUNDLE_VERSION, (
        f"_oci_state.BUNDLE_VERSION={_ep.BUNDLE_VERSION!r} "
        f"!= state.BUNDLE_VERSION={BUNDLE_VERSION!r}. "
        "Update the duplicate in _oci_state.py."
    )


def test_nft_hook_path_strings_match_state_attributes() -> None:
    """Path-name literals in ``nft_hook.py`` must match ``StateBundle`` properties.

    The stdlib-only script uses inline string literals for filenames
    that ``StateBundle`` derives via properties.  This test parses the
    script with ``ast`` to collect only *code* string constants (not
    comment text), so a rename in ``state.py`` triggers a failure here
    rather than a silent mismatch at runtime.
    """
    import ast

    from terok_shield.resources import nft_hook as _ep

    source = Path(_ep.__file__).read_text()
    tree = ast.parse(source)

    # Collect the AST nodes that are docstrings (Expr wrapping a Constant string
    # at the start of a module/class/function body) so we can exclude them.
    docstring_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstring_nodes.add(id(body[0].value))

    literals: set[str] = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstring_nodes
    }
    bundle = StateBundle(Path("x"))

    for attr in ("ruleset", "dnsmasq_conf", "dnsmasq_pid"):
        filename = getattr(bundle, attr).name
        assert filename in literals, (
            f"nft_hook.py has no code string literal {filename!r} but "
            f"StateBundle.{attr} returns that filename. "
            "Update nft_hook.py to match."
        )


# ── v15 tiered policy bundle ─────────────────────────────────────────────────


def test_policy_tier_paths_live_under_policy_dir(tmp_path: Path) -> None:
    """Tier files and the runtime overlay resolve under ``policy/``."""
    bundle = StateBundle(tmp_path)
    assert bundle.policy_dir == tmp_path / "policy"
    assert bundle.tier_path("project_allow") == tmp_path / "policy" / "40-project-allow"
    assert bundle.tier_path("security_deny") == tmp_path / "policy" / "20-security-deny"
    assert bundle.policy_live == tmp_path / "policy" / "live"


def test_read_tier_parses_present_and_empties_absent(tmp_path: Path) -> None:
    """``read_tier`` parses a written file and treats an absent one as empty."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n")
    entries = bundle.read_tier(bundle.tier_path("project_allow"))
    assert [(e.action, e.target) for e in entries] == [("+", TEST_DOMAIN), ("+", TEST_IP1)]
    assert bundle.read_tier(bundle.tier_path("override")) == []


def test_read_effective_composes_tiers_in_authority_order(tmp_path: Path) -> None:
    """``read_effective`` reads every tier; ``all_entries`` is override→live order."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP2}\n")
    bundle.tier_path("project_allow").write_text(f"+{TEST_IP1}\n")
    bundle.policy_live.write_text(f"+{TEST_IP3}\n")

    eff = bundle.read_effective()
    assert [e.target for e in eff.security_deny] == [TEST_IP2]
    assert [e.target for e in eff.project_allow] == [TEST_IP1]
    assert [e.target for e in eff.live] == [TEST_IP3]
    # authority order: override, security_deny, provider_allow, project_allow, live
    assert [(e.action, e.target) for e in eff.all_entries()] == [
        ("-", TEST_IP2),
        ("+", TEST_IP1),
        ("+", TEST_IP3),
    ]


def test_effective_policy_localhost_ports_span_every_tier(tmp_path: Path) -> None:
    """``+localhost:PORT`` grants are collected from all tiers via the overlay."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text("+localhost:8000\n")
    bundle.policy_live.write_text("+localhost:9090\n")
    assert bundle.read_effective().localhost_ports() == (8000, 9090)


def test_effective_policy_composes_ips_and_domains_by_action(tmp_path: Path) -> None:
    """Compose folds live into its tiers and splits IPs/domains, allow minus deny."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n+{TEST_IP2}\n")
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP2}\n-{TEST_DOMAIN2}\n")
    bundle.policy_live.write_text(f"+{TEST_IP3}\n")

    eff = bundle.read_effective()
    assert eff.effective_ips() == [TEST_IP1, TEST_IP3]  # TEST_IP2 subtracted by the deny
    assert eff.deny_ips() == [TEST_IP2]
    assert eff.allow_domains() == [TEST_DOMAIN]
    assert eff.deny_domains() == [TEST_DOMAIN2]


def test_allow_targets_lists_domains_and_ips_excluding_localhost(tmp_path: Path) -> None:
    """``allow_targets`` is the resolver input: admitted domains + IPs, no localhost."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n+localhost:8000\n")
    assert bundle.read_effective().allow_targets() == [TEST_DOMAIN, TEST_IP1]


def test_policy_mtime_is_zero_without_files_and_tracks_writes(tmp_path: Path) -> None:
    """``policy_mtime`` is 0.0 with no policy files and the file mtime once written."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    assert bundle.policy_mtime() == 0.0
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n")
    assert bundle.policy_mtime() == bundle.tier_path("project_allow").stat().st_mtime


def test_resolved_cache_is_a_derived_top_level_file(tmp_path: Path) -> None:
    """The resolved-IP cache lives outside ``policy/`` (it is derived, not authored)."""
    bundle = StateBundle(tmp_path)
    assert bundle.resolved_cache == tmp_path / "resolved.ips"
    assert bundle.policy_dir not in bundle.resolved_cache.parents


def test_ensure_dirs_creates_policy_dir_owner_only(tmp_path: Path) -> None:
    """``ensure_dirs`` creates ``policy/`` at the owner-only bundle mode."""
    bundle = StateBundle(tmp_path / "sd")
    bundle.ensure_dirs()
    assert bundle.policy_dir.is_dir()
    assert stat.S_IMODE(bundle.policy_dir.stat().st_mode) == STATE_DIR_MODE
