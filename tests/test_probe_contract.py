"""Canonical probe-corpus and module-manifest contract tests."""

from __future__ import annotations

import ast
from pathlib import Path

from basilisk.attacks.base import describe_attack_module, resolve_attack_modules
from basilisk.core.config import BasiliskConfig
from basilisk.payloads.loader import (
    load_probe_scenarios,
    load_probes,
    probe_corpus_version,
)


def test_canonical_corpus_has_exactly_263_unique_probes():
    probes = load_probes(force_reload=True)
    ids = [probe.id for probe in probes]
    assert len(ids) == 263
    assert len(set(ids)) == 263
    assert probe_corpus_version().startswith("3-")


def test_sequence_and_fabricated_history_probes_are_typed_and_loadable():
    probes = {probe.id: probe for probe in load_probes()}
    assert len(probes["SPI-001"].turns) == 4
    assert len(probes["EXT-GRAD-001"].turns) == 8
    assert len(probes["GRD-GRAD-001"].turns) == 9
    assert len(probes["MTR-003"].turns) == 5
    assert [message.role for message in probes["MTR-005"].messages] == [
        "user", "assistant", "user",
    ]
    assert len(probes["TOOL-014"].turns) == 2


def test_advanced_multiturn_scenarios_are_loaded_from_canonical_yaml():
    groups = {
        "MTC": (13, "multiturn.cultivation"),
        "MTS": (5, "multiturn.sycophancy"),
        "MTA": (8, "multiturn.authority_escalation"),
    }
    modules = {module.name: module for module in resolve_attack_modules(include_research=True)}
    for prefix, (count, module_name) in groups.items():
        ids = [f"{prefix}-{index:03d}" for index in range(1, count + 1)]
        scenarios = load_probe_scenarios(ids)
        assert len(scenarios) == count
        assert modules[module_name].applicable_probe_ids == ids
        for scenario in scenarios:
            assert scenario["name"]
            assert scenario["description"]
            assert len(scenario["turns"]) >= 3
            assert all(turn["content"] for turn in scenario["turns"])


def test_every_module_manifest_resolves_only_canonical_probe_ids():
    canonical = {probe.id for probe in load_probes()}
    modules = resolve_attack_modules(include_research=True)
    assert len(modules) == 33
    for module in modules:
        descriptor = describe_attack_module(module)
        assert descriptor.applicable_probe_ids, module.name
        assert set(descriptor.applicable_probe_ids) <= canonical, module.name
        assert descriptor.success_criteria, module.name
        assert descriptor.evidence_requirements, module.name


def test_explicit_probe_filter_limits_module_payload_generation():
    module = resolve_attack_modules(selected=["injection.direct"])[0]
    module.probe_filter = ("INJ-001",)
    probes = {probe.id: probe for probe in load_probes()}
    assert module.generate_payloads() == [probes["INJ-001"].payload]


def test_unknown_probe_id_is_rejected_during_config_validation():
    cfg = BasiliskConfig.from_dict({
        "target": {"url": "https://example.test", "provider": "custom"},
        "probe_ids": ["DOES-NOT-EXIST"],
    })
    assert any("Unknown canonical probe IDs" in error for error in cfg.validate())


def test_attack_modules_do_not_reintroduce_named_hard_coded_probe_collections():
    attack_root = Path(__file__).resolve().parents[1] / "basilisk" / "attacks"
    forbidden = {
        "SPLIT_SEQUENCES", "GRADIENT_SEQUENCE", "SCENARIOS",
        "PERSONA_SEQUENCE", "SEQUENCES", "CHAINS", "GRADIENT_TOPICS",
    }
    advanced_sequence_constants = {
        "CULTIVATION_SCENARIOS", "SYCOPHANCY_SEQUENCES", "AUTHORITY_SEQUENCES",
    }
    found: set[str] = set()
    for path in attack_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if target.id in forbidden:
                        found.add(target.id)
                    if (
                        target.id in advanced_sequence_constants
                        and isinstance(node.value, (ast.List, ast.Tuple, ast.Dict))
                    ):
                        found.add(target.id)
    assert found == set()
