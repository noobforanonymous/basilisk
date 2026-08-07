"""Run the installed Basilisk CLI against the isolated ground-truth lab."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from benchmarks.common import (  # noqa: E402
    DEFAULT_MODULE_PROBES,
    auth_scenario_results,
    confidence_interval,
    http_scenario_results,
    latest_json_report,
    report_detection,
    scenario_coverage,
    score_expected,
    sha256_file,
    write_json,
)


def wait_for_lab(base_url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.1)
    raise TimeoutError(f"Ground-truth lab did not start at {base_url}")


def _rss_bytes(pid: int) -> int:
    if sys.platform.startswith("linux"):
        try:
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (FileNotFoundError, ProcessLookupError, ValueError):
            return 0
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            handle = ctypes.windll.kernel32.OpenProcess(0x0410, False, pid)
            if not handle:
                return 0
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
            ctypes.windll.kernel32.CloseHandle(handle)
            return int(counters.WorkingSetSize) if ok else 0
        except Exception:
            return 0
    return 0


def run_process(command: list[str], *, cwd: Path, env: dict[str, str]) -> dict[str, object]:
    started_wall_ns = time.time_ns()
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    peak_rss = 0
    done = threading.Event()

    def sample() -> None:
        nonlocal peak_rss
        while not done.wait(0.05):
            peak_rss = max(peak_rss, _rss_bytes(process.pid))

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    stdout, stderr = process.communicate()
    done.set()
    sampler.join(timeout=1)
    return {
        "exit_code": process.returncode,
        "started_wall_ns": started_wall_ns,
        "duration_seconds": round(time.perf_counter() - started, 6),
        "peak_rss_bytes": peak_rss,
        "stdout": stdout,
        "stderr": stderr,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--results", type=Path, default=ROOT / "benchmarks" / "results" / "cli")
    parser.add_argument("--no-start-lab", action="store_true")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")

    args.results = args.results.resolve()
    base_url = f"http://{args.host}:{args.port}"
    lab_process = None
    execution_cwd = Path(tempfile.mkdtemp(prefix="basilisk-cli-benchmark-"))
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["BASILISK_BENCHMARK"] = "1"
    if not args.no_start_lab:
        lab_process = subprocess.Popen(
            [args.python, "-m", "uvicorn", "lab.app:app", "--host", args.host, "--port", str(args.port), "--log-level", "warning"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    try:
        wait_for_lab(base_url)
        ground_truth = json.loads((ROOT / "lab" / "ground_truth.json").read_text(encoding="utf-8"))
        all_runs: list[dict[str, object]] = []
        auth_runs: list[dict[str, object]] = []
        protocol_runs: list[dict[str, object]] = []
        scenario_runs: list[dict[str, object]] = []
        durations: list[float] = []
        for repetition in range(args.repetitions):
            scenario_results: list[dict[str, object]] = []
            for target_name in ("vulnerable_http", "secure_http"):
                output_dir = args.results / f"run-{repetition + 1}" / target_name
                output_dir.mkdir(parents=True, exist_ok=True)
                command = [
                    args.python, "-m", "basilisk", "scan",
                    "--target", f"{base_url}/{target_name.split('_')[0]}/v1/chat/completions",
                    "--provider", "custom", "--mode", "standard", "--no-evolve",
                    "--output", "json", "--output-dir", str(output_dir), "--no-dashboard",
                    "--allow-private-targets", "--allow-insecure-http", "--isolated-environment",
                    "--recon-module", "rag", "--recon-module", "tools",
                ]
                for module, probe_id in DEFAULT_MODULE_PROBES.items():
                    command.extend(("--module", module, "--probe-id", probe_id))
                process_result = run_process(command, cwd=execution_cwd, env=env)
                # A finding-threshold exit code of 1 is an expected benchmark result.
                if int(process_result["exit_code"]) not in (0, 1):
                    raise RuntimeError(
                        f"CLI benchmark failed for {target_name}: {process_result['stderr']}"
                    )
                try:
                    report_path = latest_json_report(
                        output_dir,
                        newer_than_ns=int(process_result["started_wall_ns"]),
                    )
                except FileNotFoundError as exc:
                    raise RuntimeError(
                        f"CLI scan produced no fresh report for {target_name} "
                        f"(exit {process_result['exit_code']}): {process_result['stderr']}"
                    ) from exc
                report = json.loads(report_path.read_text(encoding="utf-8"))
                detected = report_detection(report)
                scores = score_expected(ground_truth["expected"][target_name], detected)
                report_hash = sha256_file(report_path)
                control = target_name.split("_", maxsplit=1)[0]
                scenario_results.extend(http_scenario_results(
                    ground_truth,
                    control=control,
                    detected=detected,
                    report_sha256=report_hash,
                ))
                run_record = {
                    "surface": "cli",
                    "repetition": repetition + 1,
                    "target": target_name,
                    "command": [part if "key" not in part.casefold() else "[redacted]" for part in command],
                    "detection": detected,
                    "scores": scores,
                    "duration_seconds": process_result["duration_seconds"],
                    "peak_rss_bytes": process_result["peak_rss_bytes"],
                    "report": str(report_path.relative_to(ROOT)),
                    "report_sha256": report_hash,
                    "session": report.get("session", {}),
                }
                durations.append(float(process_result["duration_seconds"]))
                all_runs.append(run_record)
                write_json(output_dir / "benchmark.json", run_record)

            for control in ("secure", "vulnerable"):
                target_name = f"{control}_http"
                output_dir = args.results / f"run-{repetition + 1}" / f"auth_{control}"
                output_dir.mkdir(parents=True, exist_ok=True)
                report_path = output_dir / "authorization-matrix.json"
                command = [
                    args.python, "-m", "basilisk", "auth-test",
                    "--target", f"{base_url}/auth/{control}/v1/chat/completions",
                    "--provider", "custom", "--lab-personas", "--isolated-environment",
                    "--json-output", str(report_path),
                ]
                process_result = run_process(command, cwd=execution_cwd, env=env)
                if int(process_result["exit_code"]) != 0:
                    raise RuntimeError(
                        f"CLI authorization benchmark failed for {control}: {process_result['stderr']}"
                    )
                report = json.loads(report_path.read_text(encoding="utf-8"))
                scenario_results.extend(auth_scenario_results(
                    ground_truth,
                    control=control,
                    report=report,
                ))
                violation_detected = bool(report.get("violations"))
                expected_violation = bool(
                    ground_truth["authorization_expected"][target_name]
                )
                auth_record = {
                    "surface": "cli-auth",
                    "repetition": repetition + 1,
                    "target": target_name,
                    "expected_violation": expected_violation,
                    "violation_detected": violation_detected,
                    "correct": violation_detected == expected_violation,
                    "violation_count": len(report.get("violations", [])),
                    "request_count": report.get("summary", {}).get("request_count", 0),
                    "duration_seconds": process_result["duration_seconds"],
                    "report": str(report_path.relative_to(ROOT)),
                    "report_sha256": sha256_file(report_path),
                }
                auth_runs.append(auth_record)
                durations.append(float(process_result["duration_seconds"]))
                write_json(output_dir / "benchmark.json", auth_record)

            protocol_path = args.results / f"run-{repetition + 1}" / "protocol.json"
            protocol_command = [
                args.python,
                str(ROOT / "benchmarks" / "protocol_suite.py"),
                "--base-url",
                base_url,
                "--output",
                str(protocol_path),
            ]
            protocol_process = run_process(protocol_command, cwd=execution_cwd, env=env)
            if int(protocol_process["exit_code"]) != 0:
                raise RuntimeError(
                    "CLI protocol benchmark failed: "
                    f"{protocol_process['stderr']}\n{protocol_process['stdout']}"
                )
            protocol_report = json.loads(protocol_path.read_text(encoding="utf-8"))
            scenario_results.extend(protocol_report.get("results", []))
            durations.append(float(protocol_process["duration_seconds"]))
            protocol_record = {
                "surface": "cli-protocol",
                "repetition": repetition + 1,
                "duration_seconds": protocol_process["duration_seconds"],
                "peak_rss_bytes": protocol_process["peak_rss_bytes"],
                "report": str(protocol_path.relative_to(ROOT)),
                "report_sha256": sha256_file(protocol_path),
                "summary": protocol_report.get("summary", {}),
            }
            protocol_runs.append(protocol_record)

            coverage = scenario_coverage(ground_truth, scenario_results)
            scenario_record = {
                "repetition": repetition + 1,
                "coverage": coverage,
                "results": scenario_results,
            }
            scenario_runs.append(scenario_record)
            write_json(
                args.results / f"run-{repetition + 1}" / "scenarios.json",
                scenario_record,
            )

        aggregate = {
            "schema_version": 2,
            "surface": "cli",
            "ground_truth_sha256": sha256_file(ROOT / "lab" / "ground_truth.json"),
            "module_probes": DEFAULT_MODULE_PROBES,
            "runs": all_runs,
            "authorization_runs": auth_runs,
            "protocol_runs": protocol_runs,
            "scenario_runs": scenario_runs,
            "timing_95_percent_ci_seconds": confidence_interval(durations),
            "quality_gate": {
                "all_precision_1": all(run["scores"]["precision"] == 1.0 for run in all_runs),
                "all_recall_1": all(run["scores"]["recall"] == 1.0 for run in all_runs),
                "no_scanner_errors": all(not run["session"].get("errors") for run in all_runs),
                "authorization_controls_correct": all(
                    run["correct"] for run in auth_runs
                ),
                "protocol_controls_pass": all(
                    run["summary"].get("all_passed") for run in protocol_runs
                ),
                "all_declared_scenarios_covered": all(
                    run["coverage"]["all_declared_scenarios_covered"]
                    for run in scenario_runs
                ),
                "all_declared_scenarios_passed": all(
                    run["coverage"]["all_declared_scenarios_passed"]
                    for run in scenario_runs
                ),
            },
        }
        write_json(args.results / "summary.json", aggregate)
        print(json.dumps(aggregate["quality_gate"], sort_keys=True))
        return 0 if all(aggregate["quality_gate"].values()) else 2
    finally:
        shutil.rmtree(execution_cwd, ignore_errors=True)
        if lab_process is not None:
            lab_process.terminate()
            try:
                lab_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                lab_process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
