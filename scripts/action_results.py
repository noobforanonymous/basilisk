"""Collect stable outputs for the Basilisk composite GitHub Action."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any


def _latest(pattern: str) -> Path | None:
    candidates = list(Path("basilisk-reports").glob(pattern))
    return max(candidates, key=lambda path: path.stat().st_mtime) if candidates else None


def _sarif_counts(path: Path) -> Counter[str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return Counter(
        str(result.get("properties", {}).get("severity", "")).lower()
        for run in document.get("runs", [])
        for result in run.get("results", [])
    )


def _json_counts(path: Path) -> Counter[str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return Counter(
        str(finding.get("severity", "")).lower()
        for finding in document.get("findings", [])
    )


def _audit_counts() -> Counter[str]:
    path = _latest("audit_*.jsonl")
    counts: Counter[str] = Counter()
    if path is None:
        return counts
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            entry: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("event") == "finding_discovered":
            counts[str(entry.get("data", {}).get("severity", "")).lower()] += 1
    return counts


def main() -> int:
    posture_only = os.environ.get("BASILISK_POSTURE_ONLY") == "true"
    scan_exit = os.environ.get("BASILISK_SCAN_EXIT", "")
    posture_exit = os.environ.get("BASILISK_POSTURE_EXIT", "")
    exit_code = posture_exit if posture_only else scan_exit
    exit_code = exit_code or "1"

    report_value = os.environ.get("BASILISK_REPORT", "").strip()
    report = Path(report_value) if report_value else None
    posture_grade = ""
    counts: Counter[str] = Counter()

    if posture_only:
        report = _latest("posture_*.json")
        if report:
            document = json.loads(report.read_text(encoding="utf-8"))
            posture_grade = str(document.get("overall_grade", ""))
    elif report and report.exists() and report.suffix == ".sarif":
        counts = _sarif_counts(report)
    elif report and report.exists() and report.suffix == ".json":
        counts = _json_counts(report)
    else:
        counts = _audit_counts()

    total = sum(counts.values())
    output_path = Path(os.environ["GITHUB_OUTPUT"])
    with output_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"exit-code={exit_code}\n")
        handle.write(f"findings-count={total}\n")
        handle.write(f"critical-count={counts['critical']}\n")
        handle.write(f"high-count={counts['high']}\n")
        handle.write(f"report-path={report or ''}\n")
        handle.write(f"posture-grade={posture_grade}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
