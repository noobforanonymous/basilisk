"""Compare SARIF findings using stable rule, location, and message identities."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _result_identity(result: dict[str, Any]) -> str:
    payload = {
        "rule": result.get("ruleId", ""),
        "message": result.get("message", {}).get("text", ""),
        "locations": result.get("locations", []),
        "fingerprints": result.get("partialFingerprints") or result.get("fingerprints") or {},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _results(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        result
        for run in document.get("runs", [])
        for result in run.get("results", [])
        if isinstance(result, dict)
    ]


def compare(baseline_path: Path, current_path: Path) -> list[dict[str, Any]]:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = json.loads(current_path.read_text(encoding="utf-8"))
    baseline_ids = {_result_identity(result) for result in _results(baseline)}
    return [
        result
        for result in _results(current)
        if _result_identity(result) not in baseline_ids
    ]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: compare_sarif.py BASELINE CURRENT", file=sys.stderr)
        return 2
    new_findings = compare(Path(sys.argv[1]), Path(sys.argv[2]))
    if not new_findings:
        print("No regressions detected.")
        return 0
    print(f"REGRESSION: {len(new_findings)} new finding(s) not in baseline!")
    for finding in new_findings:
        level = finding.get("level", "warning")
        rule = finding.get("ruleId", "unknown")
        message = finding.get("message", {}).get("text", "")[:100]
        print(f"  [{level}] {rule}: {message}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
