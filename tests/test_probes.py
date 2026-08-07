"""
Basilisk Probe Library — test suite.

Tests the probe loader, YAML validation, filtering, and statistics.
"""

from __future__ import annotations

import unittest

from basilisk.payloads.loader import Probe, load_probes, probe_stats


class TestProbeLoader(unittest.TestCase):
    """Test the unified probe loader."""

    def test_load_all_probes(self):
        """All YAML files should load without errors."""
        probes = load_probes(force_reload=True)
        assert len(probes) > 0
        assert isinstance(probes[0], Probe)

    def test_probe_count_minimum(self):
        """Should have at least 200 probes across all files."""
        probes = load_probes(force_reload=True)
        assert len(probes) >= 200, f"Expected 200+ probes, got {len(probes)}"

    def test_all_probes_have_required_fields(self):
        """Every probe must have an id and executable single- or multi-turn content."""
        for probe in load_probes(force_reload=True):
            assert probe.id, f"Probe missing id: {probe}"
            assert probe.payload or probe.turns or probe.messages, (
                f"Probe {probe.id} missing payload, turns, and messages"
            )

    def test_no_duplicate_ids(self):
        """Probe IDs should be unique across all files."""
        probes = load_probes(force_reload=True)
        ids = [p.id for p in probes]
        duplicates = [x for x in ids if ids.count(x) > 1]
        assert len(duplicates) == 0, f"Duplicate probe IDs: {set(duplicates)}"

    def test_filter_by_category(self):
        probes = load_probes(category="injection", force_reload=True)
        assert all(p.category == "injection" for p in probes)
        assert len(probes) > 0

    def test_filter_by_severity(self):
        probes = load_probes(severity="critical", force_reload=True)
        assert all(p.severity == "critical" for p in probes)
        assert len(probes) > 0

    def test_filter_by_tags(self):
        probes = load_probes(tags=["encoding"], force_reload=True)
        assert all("encoding" in p.tags for p in probes)

    def test_filter_by_query(self):
        probes = load_probes(query="ignore", force_reload=True)
        for p in probes:
            assert "ignore" in f"{p.id} {p.name} {p.payload}".lower()

    def test_filter_no_results(self):
        probes = load_probes(category="nonexistent_category_xyz", force_reload=True)
        assert len(probes) == 0

    def test_categories_exist(self):
        """Verify all expected categories are present."""
        probes = load_probes(force_reload=True)
        categories = set(p.category for p in probes)
        expected = {"injection", "extraction", "dos", "multiturn", "multimodal"}
        for cat in expected:
            assert cat in categories, f"Missing category: {cat}"

    def test_probe_to_dict(self):
        probe = Probe(
            id="TEST-001", name="Test", payload="hello",
            signals=["hi"], severity="high", tags=["test"],
            category="injection", owasp_id="LLM01",
        )
        d = probe.to_dict()
        assert d["id"] == "TEST-001"
        assert d["owasp_id"] == "LLM01"

    def test_probe_stats(self):
        stats = probe_stats()
        assert stats["total"] > 0
        assert "injection" in stats["by_category"]
        assert "ssrf" in stats["by_subcategory"]
        assert "by_severity" in stats
        assert "top_tags" in stats

    def test_toolabuse_subcategory_loaded(self):
        probes = load_probes(category="toolabuse", force_reload=True)
        assert any(p.subcategory == "ssrf" for p in probes)

    def test_caching(self):
        """Cached calls should return same data without re-parsing."""
        a = load_probes(force_reload=True)
        b = load_probes()
        assert a == b  # Same content from cache

    def test_dos_probes_loaded(self):
        probes = load_probes(category="dos", force_reload=True)
        assert len(probes) >= 25

    def test_multiturn_probes_loaded(self):
        probes = load_probes(category="multiturn", force_reload=True)
        assert len(probes) >= 30

    def test_multimodal_probes_loaded(self):
        probes = load_probes(category="multimodal", force_reload=True)
        assert len(probes) >= 15
