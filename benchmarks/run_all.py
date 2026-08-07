"""Run CLI and desktop benchmarks and compare their detection parity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--skip-desktop", action="store_true")
    parser.add_argument(
        "--compare-only",
        action="store_true",
        help="Compare existing fresh CLI/desktop results without rerunning them.",
    )
    args = parser.parse_args()

    benchmark_env = {
        **os.environ,
        "BASILISK_PYTHON": str(Path(args.python).resolve()),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    if not args.compare_only:
        try:
            cli = subprocess.run(
                [args.python, str(ROOT / "benchmarks" / "cli" / "run.py"), "--python", args.python],
                cwd=ROOT,
                env=benchmark_env,
                timeout=360,
            )
        except subprocess.TimeoutExpired:
            print("CLI benchmark exceeded its 360-second lifecycle limit", file=sys.stderr)
            return 124
        if cli.returncode:
            return cli.returncode
        if args.skip_desktop:
            return 0
        desktop_command = ["npm.cmd" if sys.platform == "win32" else "npm", "run", "benchmark"]
        try:
            desktop = subprocess.run(
                desktop_command,
                cwd=ROOT / "desktop",
                env=benchmark_env,
                timeout=360,
            )
        except subprocess.TimeoutExpired:
            print("Desktop benchmark exceeded its 360-second lifecycle limit", file=sys.stderr)
            return 124
        if desktop.returncode:
            return desktop.returncode
    elif args.skip_desktop:
        parser.error("--compare-only cannot be combined with --skip-desktop")

    cli_summary = json.loads((ROOT / "benchmarks" / "results" / "cli" / "summary.json").read_text())
    desktop_summary = json.loads((ROOT / "benchmarks" / "results" / "desktop" / "summary.json").read_text())
    cli_sets = {run["target"]: run["detection"] for run in cli_summary["runs"] if run["repetition"] == 1}
    desktop_sets = {run["target"]: run["detection"] for run in desktop_summary["runs"]}
    detection_parity = cli_sets == desktop_sets
    current_ground_truth = hashlib.sha256(
        (ROOT / "lab" / "ground_truth.json").read_bytes()
    ).hexdigest()
    cli_scenarios = {
        item["id"]: {"actual": item.get("actual"), "passed": item.get("passed")}
        for item in cli_summary["scenario_runs"][0]["results"]
    }
    desktop_scenarios = {
        item["id"]: {"actual": item.get("actual"), "passed": item.get("passed")}
        for item in desktop_summary["scenario_results"]
    }
    scenario_parity = cli_scenarios == desktop_scenarios
    ground_truth_current = (
        cli_summary.get("ground_truth_sha256") == current_ground_truth
        and desktop_summary.get("ground_truth_sha256") == current_ground_truth
    )
    output = {
        "schema_version": 2,
        "ground_truth_sha256": current_ground_truth,
        "ground_truth_current": ground_truth_current,
        "cli_desktop_detection_parity": detection_parity,
        "cli_desktop_scenario_parity": scenario_parity,
        "scenario_count": len(cli_scenarios),
        "cli": cli_sets,
        "desktop": desktop_sets,
        "scenario_results": {
            "cli": cli_scenarios,
            "desktop": desktop_scenarios,
        },
    }
    parity_path = ROOT / "benchmarks" / "results" / "parity.json"
    parity_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    gates = {
        "ground_truth_current": ground_truth_current,
        "cli_desktop_detection_parity": detection_parity,
        "cli_desktop_scenario_parity": scenario_parity,
        "cli_quality_gate": all(cli_summary.get("quality_gate", {}).values()),
        "desktop_quality_gate": all(desktop_summary.get("quality_gate", {}).values()),
    }
    print(json.dumps(gates, sort_keys=True))
    return 0 if all(gates.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
