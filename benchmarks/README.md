# Basilisk Ground-Truth Benchmarks

This directory contains separate end-to-end benchmarks for the installed CLI
and Electron desktop application. Both surfaces run the same pinned canonical
probes against the isolated lab in `lab/` and score their reports against
`lab/ground_truth.json`.

The benchmark never uses a public target. The lab only simulates tool effects;
it does not perform network fetches, database queries, or shell commands.

## CLI

```bash
python benchmarks/cli/run.py --repetitions 3
```

The runner starts the lab from the source tree, then invokes the installed
`python -m basilisk scan`, `python -m basilisk auth-test`, and protocol
validation commands from a neutral temporary directory. It writes per-run reports plus
`benchmarks/results/cli/summary.json`. Secure and deliberately vulnerable
tenant controls must be classified correctly. A report must have been created
by the current subprocess; stale output from an earlier run is never accepted.

## Desktop

```bash
cd desktop
npm ci
npm run benchmark
```

The desktop runner starts the lab and launches Electron twice, once for the
vulnerable target and once for the secure target. Scan, authorization-matrix,
hostile HTTP, and WebSocket requests travel through the preload IPC allowlist
and the authenticated FastAPI sidecar. Results are written under
`benchmarks/results/desktop/`.

## Metrics and gates

Each surface must cover exactly 46 duplicate-free scenarios: 12 HTTP finding
controls, 14 authorization-persona controls, 10 WebSocket controls, and 10
hostile HTTP controls. Each surface records true/false positives and negatives, precision, recall,
specificity, F1, accuracy, wall time, peak memory where supported, report
SHA-256, scanner errors, and a 95% timing confidence interval for repeated
runs. Release gates require precision and recall of 1.0 for the deterministic
lab, correct authorization-control classification, no scanner errors, all
protocol controls passing, and identical scenario outcomes from the CLI and
desktop surfaces. Compare fresh results without rerunning them with:

```bash
python benchmarks/run_all.py --compare-only
```

