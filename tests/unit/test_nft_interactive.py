# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for interactive-mode nft ruleset generation (deny sets + NFQUEUE)."""

from __future__ import annotations

import pytest

from terok_shield.nft import (
    RulesetBuilder,
    add_deny_elements_dual,
    bypass_ruleset,
    delete_deny_elements_dual,
    hook_ruleset,
    verify_bypass_ruleset,
    verify_ruleset,
)
from terok_shield.nft_constants import (
    DENIED_LOG_PREFIX,
    NFQUEUE_NUM,
    QUEUED_LOG_PREFIX,
)

from ..testnet import IPV6_CLOUDFLARE, TEST_IP1

# ── Deny sets in both modes ───────────────────────────


class TestDenySetsPresent:
    """Deny sets are always generated in hook and bypass rulesets."""

    def test_hook_strict_has_deny_sets(self) -> None:
        """Strict-mode hook ruleset includes deny_v4/deny_v6 set declarations."""
        rs = hook_ruleset()
        assert "set deny_v4 {" in rs
        assert "set deny_v6 {" in rs

    def test_hook_interactive_has_deny_sets(self) -> None:
        """Interactive-mode hook ruleset includes deny_v4/deny_v6 set declarations."""
        rs = hook_ruleset(interactive=True)
        assert "set deny_v4 {" in rs
        assert "set deny_v6 {" in rs

    def test_bypass_has_deny_sets(self) -> None:
        """Bypass ruleset includes deny_v4/deny_v6 set declarations."""
        rs = bypass_ruleset()
        assert "set deny_v4 {" in rs
        assert "set deny_v6 {" in rs

    def test_deny_set_match_rules_in_strict(self) -> None:
        """Strict mode includes deny-set match rules with reject."""
        rs = hook_ruleset()
        assert "@deny_v4" in rs
        assert "@deny_v6" in rs
        assert DENIED_LOG_PREFIX in rs

    def test_deny_set_match_rules_in_interactive(self) -> None:
        """Interactive mode includes deny-set match rules with reject."""
        rs = hook_ruleset(interactive=True)
        assert "@deny_v4" in rs
        assert "@deny_v6" in rs


# ── Interactive mode specifics ─────────────────────────


class TestInteractiveRuleset:
    """Interactive mode uses NFQUEUE as terminal rule."""

    def test_has_queue_rule(self) -> None:
        """Interactive ruleset contains queue num directive."""
        rs = hook_ruleset(interactive=True)
        assert f"queue num {NFQUEUE_NUM}" in rs

    def test_has_queued_prefix(self) -> None:
        """Interactive ruleset logs with QUEUED prefix."""
        rs = hook_ruleset(interactive=True)
        assert QUEUED_LOG_PREFIX in rs

    def test_custom_nfqueue_num(self) -> None:
        """Custom NFQUEUE number is honoured."""
        rs = hook_ruleset(interactive=True, nfqueue_num=42)
        assert "queue num 42" in rs

    def test_strict_has_no_queue(self) -> None:
        """Strict mode does not contain queue directive."""
        rs = hook_ruleset(interactive=False)
        assert "queue num" not in rs
        assert QUEUED_LOG_PREFIX not in rs


# ── Verify interactive ruleset ────────────────────────


class TestVerifyInteractive:
    """verify_ruleset(interactive=True) checks NFQUEUE-specific invariants."""

    def test_valid_interactive_passes(self) -> None:
        """A correctly generated interactive ruleset passes verification."""
        rs = hook_ruleset(interactive=True)
        assert verify_ruleset(rs, interactive=True) == []

    def test_valid_strict_passes(self) -> None:
        """A correctly generated strict ruleset passes verification."""
        rs = hook_ruleset()
        assert verify_ruleset(rs) == []

    def test_strict_fails_interactive_check(self) -> None:
        """A strict ruleset fails interactive verification (no queue)."""
        rs = hook_ruleset()
        errors = verify_ruleset(rs, interactive=True)
        assert any("queue" in e for e in errors)

    def test_bypass_has_deny_sets(self) -> None:
        """Bypass ruleset passes verification including deny sets."""
        rs = bypass_ruleset()
        assert verify_bypass_ruleset(rs) == []

    def test_verify_checks_deny_sets(self) -> None:
        """verify_ruleset checks that deny sets are present."""
        # A ruleset without deny sets should fail
        bad = hook_ruleset().replace("deny_v4", "xxx_v4").replace("deny_v6", "xxx_v6")
        errors = verify_ruleset(bad)
        assert any("deny_v4" in e for e in errors)
        assert any("deny_v6" in e for e in errors)


# ── Deny set operations ────────────────────────────────


class TestDenySetOperations:
    """add_deny_elements_dual / delete_deny_elements_dual."""

    def test_add_v4(self) -> None:
        """IPv4 goes to deny_v4."""
        cmd = add_deny_elements_dual([TEST_IP1])
        assert "deny_v4" in cmd
        assert TEST_IP1 in cmd

    def test_add_v6(self) -> None:
        """IPv6 goes to deny_v6."""
        cmd = add_deny_elements_dual([IPV6_CLOUDFLARE])
        assert "deny_v6" in cmd
        assert IPV6_CLOUDFLARE in cmd

    def test_delete_v4(self) -> None:
        """delete generates delete element command."""
        cmd = delete_deny_elements_dual([TEST_IP1])
        assert "delete element" in cmd
        assert "deny_v4" in cmd

    def test_empty_input(self) -> None:
        """Empty input returns empty string."""
        assert add_deny_elements_dual([]) == ""
        assert delete_deny_elements_dual([]) == ""


# ── RulesetBuilder interactive ────────────────────────


class TestRulesetBuilderInteractive:
    """RulesetBuilder.build_hook(interactive=True) integration."""

    def test_builder_interactive(self) -> None:
        """Builder passes interactive flag through correctly."""
        builder = RulesetBuilder()
        rs = builder.build_hook(interactive=True)
        assert "queue num" in rs
        assert QUEUED_LOG_PREFIX in rs

    def test_builder_strict(self) -> None:
        """Builder strict mode has no queue."""
        builder = RulesetBuilder()
        rs = builder.build_hook(interactive=False)
        assert "queue num" not in rs

    def test_builder_custom_nfqueue(self) -> None:
        """Builder respects custom nfqueue_num."""
        builder = RulesetBuilder(nfqueue_num=99)
        rs = builder.build_hook(interactive=True)
        assert "queue num 99" in rs

    def test_verify_interactive(self) -> None:
        """Builder verify_hook passes interactive flag."""
        builder = RulesetBuilder()
        rs = builder.build_hook(interactive=True)
        assert builder.verify_hook(rs, interactive=True) == []


# ── Validation ─────────────────────────────────────────


class TestNfqueueValidation:
    """NFQUEUE number validation."""

    def test_invalid_nfqueue_num_bool(self) -> None:
        """Boolean nfqueue_num is rejected."""
        with pytest.raises(ValueError, match="integer"):
            RulesetBuilder(nfqueue_num=True)

    def test_invalid_nfqueue_num_negative(self) -> None:
        """Negative nfqueue_num is rejected."""
        with pytest.raises(ValueError, match="range"):
            RulesetBuilder(nfqueue_num=-1)

    def test_invalid_nfqueue_num_too_large(self) -> None:
        """nfqueue_num > 65535 is rejected."""
        with pytest.raises(ValueError, match="range"):
            RulesetBuilder(nfqueue_num=70000)
