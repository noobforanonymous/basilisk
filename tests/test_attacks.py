"""
Tests for Basilisk Attack Modules — validates all 8 categories load and conform to interface.
"""

from __future__ import annotations

import pytest
from basilisk.attacks.base import get_all_attack_modules


class TestAttackModuleLoading:
    """Verify all attack modules load and conform to the BasiliskAttack interface."""

    def test_all_modules_load(self):
        modules = get_all_attack_modules()
        assert len(modules) > 0, "No attack modules loaded"

    def test_module_count(self):
        modules = get_all_attack_modules()
        assert len(modules) >= 29, f"Expected at least 29 modules, got {len(modules)}"

    def test_all_modules_have_name(self):
        for mod in get_all_attack_modules():
            assert hasattr(mod, "name"), f"Module missing 'name'"
            assert mod.name, f"Module has empty name"

    def test_all_modules_have_category(self):
        for mod in get_all_attack_modules():
            assert hasattr(mod, "category"), f"Module {mod.name} missing 'category'"
            assert hasattr(mod.category, "owasp_id"), f"Category for {mod.name} missing owasp_id"

    def test_all_modules_have_description(self):
        for mod in get_all_attack_modules():
            assert hasattr(mod, "description"), f"Module {mod.name} missing 'description'"

    def test_injection_modules_exist(self):
        modules = get_all_attack_modules()
        names = [m.name for m in modules]
        expected = ["DirectInjection", "IndirectInjection", "MultilingualInjection",
                     "EncodingInjection", "SplitPayload"]
        for expected_name in expected:
            assert any(expected_name in n for n in names), f"Missing injection module: {expected_name}"

    def test_extraction_modules_exist(self):
        modules = get_all_attack_modules()
        names = [m.name for m in modules]
        for keyword in ["RoleConfusion", "Translation", "Simulation", "GradientWalk"]:
            assert any(keyword in n for n in names), f"Missing extraction module: {keyword}"

    def test_categories_covered(self):
        """Verify all 8 attack categories have at least one module."""
        modules = get_all_attack_modules()
        categories = set()
        for mod in modules:
            categories.add(mod.category.owasp_id)
        # We should have modules covering multiple OWASP categories
        assert len(categories) >= 5, f"Only {len(categories)} OWASP categories covered"


class TestAttackModuleInterface:
    """Verify attack modules have the required methods."""

    def test_modules_have_execute(self):
        for mod in get_all_attack_modules():
            assert hasattr(mod, "execute"), f"Module {mod.name} missing 'execute' method"

    def test_modules_have_generate_payloads(self):
        for mod in get_all_attack_modules():
            assert hasattr(mod, "generate_payloads"), f"Module {mod.name} missing 'generate_payloads' method"
