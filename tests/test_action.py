"""Regression tests for the composite GitHub Action helpers."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.compare_sarif import compare


def _sarif(*results):
    return {"version": "2.1.0", "runs": [{"results": list(results)}]}


def test_action_does_not_interpolate_inputs_inside_shell_scripts():
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))
    for step in action["runs"]["steps"]:
        assert "${{ inputs." not in step.get("run", "")


def test_action_outputs_have_values():
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))
    assert all(output.get("value") for output in action["outputs"].values())


def test_sarif_comparison_detects_same_rule_with_new_location(tmp_path):
    baseline = tmp_path / "baseline.sarif"
    current = tmp_path / "current.sarif"
    base_result = {
        "ruleId": "BASILISK-001",
        "message": {"text": "same finding"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "one"}}}],
    }
    new_result = {
        **base_result,
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "two"}}}],
    }
    baseline.write_text(json.dumps(_sarif(base_result)), encoding="utf-8")
    current.write_text(json.dumps(_sarif(base_result, new_result)), encoding="utf-8")
    assert compare(baseline, current) == [new_result]
