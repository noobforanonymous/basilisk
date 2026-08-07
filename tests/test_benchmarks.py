"""Ground-truth benchmark scoring and coverage contracts."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.common import (
    auth_scenario_results,
    http_scenario_results,
    scenario_coverage,
)

ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    return json.loads((ROOT / "lab" / "ground_truth.json").read_text("utf-8"))


def _auth_report(manifest: dict, control: str) -> dict:
    status_classes = {200: "success", 401: "unauthenticated", 403: "forbidden"}
    resource_probes = {"tenant-a": "tenant-a-rag", "tenant-b": "tenant-b-rag"}
    observations = []
    for scenario in manifest["scenarios"]:
        if scenario["surface"] != "http-auth" or scenario["control"] != control:
            continue
        observations.append({
            "persona": {"id": scenario["credential"]},
            "probe": {"id": resource_probes[scenario["resource"]]},
            "status_class": status_classes[scenario["expected"]],
            "response_sha256": "a" * 64,
            "response_bytes": 17,
            "canary_hits": [],
            "error_type": "",
        })
    return {"observations": observations}


def test_expanded_manifest_has_exact_duplicate_free_coverage():
    manifest = _manifest()
    results = []
    results.extend(http_scenario_results(
        manifest,
        control="vulnerable",
        detected={module: True for module in manifest["expected"]["vulnerable_http"]},
        report_sha256="b" * 64,
    ))
    results.extend(http_scenario_results(
        manifest,
        control="secure",
        detected={module: False for module in manifest["expected"]["secure_http"]},
        report_sha256="c" * 64,
    ))
    results.extend(auth_scenario_results(
        manifest,
        control="secure",
        report=_auth_report(manifest, "secure"),
    ))
    results.extend(auth_scenario_results(
        manifest,
        control="vulnerable",
        report=_auth_report(manifest, "vulnerable"),
    ))
    results.extend({
        "id": scenario["id"],
        "surface": scenario["surface"],
        "control": scenario["control"],
        "expected": scenario["expected"],
        "actual": scenario["expected"],
        "passed": True,
    } for scenario in manifest["scenarios"] if scenario["surface"] in {
        "websocket", "websocket-auth", "hostile-http",
    })

    coverage = scenario_coverage(manifest, results)
    assert coverage == {
        "expected_count": 46,
        "observed_count": 46,
        "passed": 46,
        "failed": 0,
        "missing": [],
        "unexpected": [],
        "duplicates": [],
        "all_declared_scenarios_covered": True,
        "all_declared_scenarios_passed": True,
    }
    assert all("body" not in result for result in results)


def test_coverage_rejects_duplicates_even_when_every_record_passes():
    manifest = {"scenarios": [{"id": "one"}, {"id": "two"}]}
    coverage = scenario_coverage(manifest, [
        {"id": "one", "passed": True},
        {"id": "one", "passed": True},
        {"id": "two", "passed": True},
    ])
    assert coverage["duplicates"] == ["one"]
    assert coverage["all_declared_scenarios_covered"] is False
    assert coverage["all_declared_scenarios_passed"] is False
