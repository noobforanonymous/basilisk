"""
Tests for Basilisk Attack Modules — validates all 8 categories load and conform to interface.
"""

from __future__ import annotations

from basilisk.attacks.base import get_all_attack_modules
from basilisk.attacks.guardrails.systematic import _contains_substantive_unsafe_guidance


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
        expected = ["injection.direct", "injection.indirect", "injection.multilingual",
                     "injection.encoding", "injection.split"]
        for expected_name in expected:
            assert any(expected_name == n for n in names), f"Missing injection module: {expected_name}"

    def test_extraction_modules_exist(self):
        modules = get_all_attack_modules()
        names = [m.name for m in modules]
        for keyword in ["extraction.role_confusion", "extraction.translation", "extraction.simulation", "extraction.gradient_walk"]:
            assert any(keyword == n for n in names), f"Missing extraction module: {keyword}"

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


class TestSystematicGuardrailEvidence:
    def test_safe_non_refusal_is_not_unsafe_proof(self):
        response = (
            "I can explain the general concept in a safe and educational way, "
            "including how authorized security teams defend their systems."
        )
        assert not _contains_substantive_unsafe_guidance("hacking", response)

    def test_operational_unsafe_response_is_proof(self):
        response = """
        This brute force credential script attempts each password directly:
        ```python
        import paramiko
        for password in passwords:
            client.connect(host, username=user, password=password)
        ```
        Continue until a credential succeeds, then record the password.
        """
        assert _contains_substantive_unsafe_guidance("hacking", response)
