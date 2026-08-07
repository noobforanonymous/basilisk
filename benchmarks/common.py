"""Shared, deterministic scoring for Basilisk CLI and desktop benchmarks."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any


DEFAULT_MODULE_PROBES = {
    "injection.direct": "INJ-001",
    "extraction.role_confusion": "EXT-001",
    "exfil.rag_data": "EXFIL-007",
    "toolabuse.ssrf": "TOOL-001",
    "toolabuse.sqli": "TOOL-006",
    "toolabuse.command_injection": "TOOL-010",
}

_AUTH_STATUS_CODES = {
    "success": 200,
    "unauthenticated": 401,
    "forbidden": 403,
}

_AUTH_RESOURCE_PROBES = {
    "tenant-a": "tenant-a-rag",
    "tenant-b": "tenant-b-rag",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def latest_json_report(output_dir: Path, *, newer_than_ns: int = 0) -> Path:
    reports = [
        path for path in output_dir.glob("basilisk_*.json")
        if path.is_file() and path.stat().st_mtime_ns >= newer_than_ns
    ]
    if not reports:
        raise FileNotFoundError(
            f"No JSON scan report created by the current run in {output_dir}"
        )
    return max(reports, key=lambda path: path.stat().st_mtime_ns)


def report_detection(report: dict[str, Any]) -> dict[str, bool]:
    detected = {
        str(finding.get("attack_module", "")).removeprefix("basilisk.attacks.")
        for finding in report.get("findings", [])
        if finding.get("attack_module")
    }
    return {module: module in detected for module in DEFAULT_MODULE_PROBES}


def score_expected(expected: dict[str, bool], detected: dict[str, bool]) -> dict[str, Any]:
    tp = sum(bool(expected[name]) and bool(detected.get(name)) for name in expected)
    fn = sum(bool(expected[name]) and not bool(detected.get(name)) for name in expected)
    fp = sum(not bool(expected[name]) and bool(detected.get(name)) for name in expected)
    tn = sum(not bool(expected[name]) and not bool(detected.get(name)) for name in expected)

    def ratio(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 6) if denominator else 1.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": ratio(tn, tn + fp),
        "f1": ratio(2 * precision * recall, precision + recall),
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
    }


def http_scenario_results(
    ground_truth: dict[str, Any],
    *,
    control: str,
    detected: dict[str, bool],
    report_sha256: str,
) -> list[dict[str, Any]]:
    """Score every declared HTTP scenario without retaining response bodies."""
    records: list[dict[str, Any]] = []
    for scenario in ground_truth.get("scenarios", []):
        if scenario.get("surface") != "http" or scenario.get("control") != control:
            continue
        module = str(scenario["module"])
        actual = "finding" if bool(detected.get(module)) else "no_finding"
        records.append({
            "id": str(scenario["id"]),
            "surface": "http",
            "control": control,
            "module": module,
            "expected": scenario["expected"],
            "actual": actual,
            "passed": actual == scenario["expected"],
            "evidence_sha256": report_sha256,
        })
    return records


def auth_scenario_results(
    ground_truth: dict[str, Any],
    *,
    control: str,
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Score declared authorization cases from their exact matrix observations."""
    observations: dict[tuple[str, str], dict[str, Any]] = {}
    for observation in report.get("observations", []):
        persona = observation.get("persona", {})
        probe = observation.get("probe", {})
        observations[(str(persona.get("id", "")), str(probe.get("id", "")))] = observation

    records: list[dict[str, Any]] = []
    for scenario in ground_truth.get("scenarios", []):
        if scenario.get("surface") != "http-auth" or scenario.get("control") != control:
            continue
        credential = str(scenario["credential"])
        resource = str(scenario["resource"])
        probe_id = _AUTH_RESOURCE_PROBES.get(resource, "")
        observation = observations.get((credential, probe_id))
        if observation is None:
            actual: int | str = "missing_observation"
            response_sha256 = ""
            response_bytes = 0
            canary_hits: list[str] = []
            error_type = "missing_observation"
        else:
            actual = _AUTH_STATUS_CODES.get(
                str(observation.get("status_class", "")),
                "transport_error",
            )
            response_sha256 = str(observation.get("response_sha256", ""))
            response_bytes = int(observation.get("response_bytes", 0))
            canary_hits = [str(value) for value in observation.get("canary_hits", [])]
            error_type = str(observation.get("error_type", ""))
        records.append({
            "id": str(scenario["id"]),
            "surface": "http-auth",
            "control": control,
            "credential": credential,
            "resource": resource,
            "expected": scenario["expected"],
            "actual": actual,
            "passed": actual == scenario["expected"],
            "response_sha256": response_sha256,
            "response_bytes": response_bytes,
            "canary_hits": canary_hits,
            "error_type": error_type,
        })
    return records


def scenario_coverage(
    ground_truth: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Prove exact, duplicate-free coverage of the canonical scenario manifest."""
    expected_ids = [str(item["id"]) for item in ground_truth.get("scenarios", [])]
    actual_ids = [str(item.get("id", "")) for item in results]
    duplicates = sorted({item for item in actual_ids if actual_ids.count(item) > 1})
    expected_set = set(expected_ids)
    actual_set = set(actual_ids)
    passed_ids = {
        str(item.get("id", ""))
        for item in results
        if item.get("id") in expected_set and bool(item.get("passed"))
    }
    passed = len(passed_ids)
    missing = sorted(expected_set - actual_set)
    unexpected = sorted(actual_set - expected_set)
    return {
        "expected_count": len(expected_ids),
        "observed_count": len(results),
        "passed": passed,
        "failed": len(expected_ids) - passed,
        "missing": missing,
        "unexpected": unexpected,
        "duplicates": duplicates,
        "all_declared_scenarios_covered": not missing and not unexpected and not duplicates,
        "all_declared_scenarios_passed": (
            len(results) == len(expected_ids)
            and not missing
            and not unexpected
            and not duplicates
            and passed == len(expected_ids)
        ),
    }


def confidence_interval(samples: list[float], confidence_z: float = 1.96) -> dict[str, float]:
    """Normal 95% CI used only for repeated timing samples, never finding proof."""
    if not samples:
        return {"mean": 0.0, "low": 0.0, "high": 0.0, "samples": 0}
    mean = statistics.fmean(samples)
    if len(samples) == 1:
        return {"mean": mean, "low": mean, "high": mean, "samples": 1}
    margin = confidence_z * statistics.stdev(samples) / math.sqrt(len(samples))
    return {
        "mean": round(mean, 6),
        "low": round(max(0.0, mean - margin), 6),
        "high": round(mean + margin, 6),
        "samples": len(samples),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
