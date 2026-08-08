'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const RESULTS = path.join(ROOT, 'benchmarks', 'results', 'desktop');
const MODULES = [
    'injection.direct', 'extraction.role_confusion', 'exfil.rag_data',
    'toolabuse.ssrf', 'toolabuse.sqli', 'toolabuse.command_injection',
];

function terminateProcessTree(child) {
    if (!child) return;
    if (process.platform === 'win32') {
        spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
            windowsHide: true,
            stdio: 'ignore',
        });
        return;
    }
    if (child.exitCode !== null || child.signalCode !== null) return;
    try {
        process.kill(-child.pid, 'SIGTERM');
    } catch {
        try { child.kill('SIGTERM'); } catch { /* already exited */ }
    }
}

function closeChildStreams(child) {
    child?.stdout?.destroy();
    child?.stderr?.destroy();
}

function sha256(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function sha256Json(value) {
    return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function writeJson(filePath, value) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function httpScenarioResults(groundTruth, control, detection, reportHash) {
    return groundTruth.scenarios
        .filter((scenario) => scenario.surface === 'http' && scenario.control === control)
        .map((scenario) => {
            const actual = detection[scenario.module] ? 'finding' : 'no_finding';
            return {
                id: scenario.id,
                surface: scenario.surface,
                control,
                module: scenario.module,
                expected: scenario.expected,
                actual,
                passed: actual === scenario.expected,
                evidence_sha256: reportHash,
            };
        });
}

function authScenarioResults(groundTruth, control, report) {
    const statusCodes = { success: 200, unauthenticated: 401, forbidden: 403 };
    const resourceProbes = { 'tenant-a': 'tenant-a-rag', 'tenant-b': 'tenant-b-rag' };
    const observations = new Map((report.observations || []).map((observation) => [
        `${observation.persona?.id || ''}\0${observation.probe?.id || ''}`,
        observation,
    ]));
    return groundTruth.scenarios
        .filter((scenario) => scenario.surface === 'http-auth' && scenario.control === control)
        .map((scenario) => {
            const observation = observations.get(`${scenario.credential}\0${resourceProbes[scenario.resource] || ''}`);
            const actual = observation
                ? (statusCodes[observation.status_class] || 'transport_error')
                : 'missing_observation';
            return {
                id: scenario.id,
                surface: scenario.surface,
                control,
                credential: scenario.credential,
                resource: scenario.resource,
                expected: scenario.expected,
                actual,
                passed: actual === scenario.expected,
                response_sha256: observation?.response_sha256 || '',
                response_bytes: observation?.response_bytes || 0,
                canary_hits: observation?.canary_hits || [],
                error_type: observation?.error_type || (observation ? '' : 'missing_observation'),
            };
        });
}

function scenarioCoverage(groundTruth, results) {
    const expectedIds = groundTruth.scenarios.map((scenario) => scenario.id);
    const actualIds = results.map((result) => result.id);
    const expectedSet = new Set(expectedIds);
    const actualSet = new Set(actualIds);
    const duplicates = [...new Set(actualIds.filter((id, index) => actualIds.indexOf(id) !== index))].sort();
    const missing = expectedIds.filter((id) => !actualSet.has(id)).sort();
    const unexpected = [...actualSet].filter((id) => !expectedSet.has(id)).sort();
    const passed = results.filter((result) => expectedSet.has(result.id) && result.passed).length;
    return {
        expected_count: expectedIds.length,
        observed_count: results.length,
        passed,
        failed: expectedIds.length - passed,
        missing,
        unexpected,
        duplicates,
        all_declared_scenarios_covered: !missing.length && !unexpected.length && !duplicates.length,
        all_declared_scenarios_passed: results.length === expectedIds.length
            && !missing.length && !unexpected.length && !duplicates.length
            && passed === expectedIds.length,
    };
}

function score(expected, detectedModules) {
    const detected = new Set(detectedModules);
    let tp = 0; let fp = 0; let tn = 0; let fn = 0;
    for (const [moduleName, shouldDetect] of Object.entries(expected)) {
        const didDetect = detected.has(moduleName);
        if (shouldDetect && didDetect) tp += 1;
        else if (shouldDetect) fn += 1;
        else if (didDetect) fp += 1;
        else tn += 1;
    }
    const ratio = (a, b) => b ? Number((a / b).toFixed(6)) : 1;
    const precision = ratio(tp, tp + fp);
    const recall = ratio(tp, tp + fn);
    return {
        tp, fp, tn, fn, precision, recall,
        specificity: ratio(tn, tn + fp),
        f1: ratio(2 * precision * recall, precision + recall),
        accuracy: ratio(tp + tn, tp + tn + fp + fn),
    };
}

async function waitForHealth(baseUrl, timeoutMs = 20000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            const response = await fetch(`${baseUrl}/health`);
            if (response.ok) return;
        } catch { /* retry */ }
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Ground-truth lab did not start at ${baseUrl}`);
}

function waitForResult(child, outputPath, timeoutMs = 150000) {
    const started = Date.now();
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    return new Promise((resolve, reject) => {
        const timer = setInterval(() => {
            if (fs.existsSync(outputPath)) {
                const data = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
                if (data.stage === 'benchmark_complete') {
                    clearInterval(timer);
                    resolve({ data, stdout, stderr });
                    return;
                }
                if (['ui_error', 'backend_error', 'backend_exit', 'backend_timeout', 'startup_error'].includes(data.stage)) {
                    clearInterval(timer);
                    reject(new Error(`${data.stage}: ${data.error || 'unknown error'}\n${stderr}`));
                    return;
                }
            }
            if (Date.now() - started > timeoutMs) {
                clearInterval(timer);
                reject(new Error(`Desktop benchmark timed out\n${stdout}\n${stderr}`));
            }
        }, 200);
        child.once('exit', (code) => {
            if (!fs.existsSync(outputPath)) {
                clearInterval(timer);
                reject(new Error(`Electron exited before writing a benchmark result (${code})\n${stderr}`));
            }
        });
    });
}

async function runElectron(electronBinary, target, authTarget, baseUrl, runProtocol, pythonBinary) {
    const outputPath = path.join(os.tmpdir(), `basilisk-desktop-benchmark-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.json`);
    const childEnv = { ...process.env };
    delete childEnv.ELECTRON_RUN_AS_NODE;
    const child = spawn(electronBinary, ['--no-sandbox', '--disable-setuid-sandbox', '.'], {
        cwd: path.join(ROOT, 'desktop'),
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
        env: {
            ...childEnv,
            BASILISK_E2E: '1',
            // Keep the Electron parent alive until the benchmark supervisor
            // terminates its complete process tree in the finally block.
            BASILISK_E2E_AUTOEXIT: '0',
            BASILISK_E2E_OUT: outputPath,
            BASILISK_BENCHMARK_TARGET: target,
            BASILISK_BENCHMARK_AUTH_TARGET: authTarget,
            BASILISK_BENCHMARK_BASE_URL: baseUrl,
            BASILISK_BENCHMARK_PROTOCOL: runProtocol ? '1' : '0',
            BASILISK_BENCHMARK: '1',
            BASILISK_PYTHON: pythonBinary,
            PYTHONPATH: [ROOT, childEnv.PYTHONPATH].filter(Boolean).join(path.delimiter),
            PYTHONDONTWRITEBYTECODE: '1',
        },
    });
    try {
        return await waitForResult(child, outputPath);
    } finally {
        terminateProcessTree(child);
        closeChildStreams(child);
        fs.rmSync(outputPath, { force: true });
    }
}

async function main() {
    let electronBinary;
    try {
        electronBinary = require(path.join(ROOT, 'desktop', 'node_modules', 'electron'));
    } catch {
        throw new Error('Electron is not installed. Run npm ci in desktop/ first.');
    }
    const pythonBinary = process.env.BASILISK_PYTHON || (process.platform === 'win32' ? 'python.exe' : 'python3');
    const host = process.env.BASILISK_LAB_HOST || '127.0.0.1';
    const port = process.env.BASILISK_LAB_PORT || '8765';
    const baseUrl = `http://${host}:${port}`;
    const groundTruthPath = path.join(ROOT, 'lab', 'ground_truth.json');
    const groundTruth = JSON.parse(fs.readFileSync(groundTruthPath, 'utf8'));
    fs.mkdirSync(RESULTS, { recursive: true });

    const lab = spawn(pythonBinary, ['-m', 'uvicorn', 'lab.app:app', '--host', host, '--port', port, '--log-level', 'warning'], {
        cwd: ROOT,
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    });
    try {
        await waitForHealth(baseUrl);
        const runs = [];
        const scenarioResults = [];
        let protocolReport = null;
        for (const targetName of ['vulnerable_http', 'secure_http']) {
            const route = targetName.startsWith('vulnerable') ? 'vulnerable' : 'secure';
            const result = await runElectron(
                electronBinary,
                `${baseUrl}/${route}/v1/chat/completions`,
                `${baseUrl}/auth/${route}/v1/chat/completions`,
                baseUrl,
                route === 'vulnerable',
                pythonBinary,
            );
            const benchmark = result.data.benchmark;
            const detection = Object.fromEntries(MODULES.map((name) => [
                name,
                benchmark.detectedModules.some((value) => value.replace(/^basilisk\.attacks\./, '') === name),
            ]));
            const scanEvidenceHash = sha256Json({
                target: benchmark.target,
                session_id: benchmark.sessionId,
                detected_modules: benchmark.detectedModules,
            });
            scenarioResults.push(...httpScenarioResults(groundTruth, route, detection, scanEvidenceHash));
            scenarioResults.push(...authScenarioResults(groundTruth, route, benchmark.authReport));
            writeJson(path.join(RESULTS, `auth_${route}.json`), benchmark.authReport);
            if (benchmark.protocolReport) protocolReport = benchmark.protocolReport;
            const run = {
                surface: 'desktop',
                target: targetName,
                detection,
                scores: score(groundTruth.expected[targetName], benchmark.detectedModules.map((value) => value.replace(/^basilisk\.attacks\./, ''))),
                duration_seconds: benchmark.durationSeconds,
                findings_count: benchmark.findingsCount,
                backend_ready: result.data.backendReady,
                renderer_ready: result.data.uiReady,
                session_id: benchmark.sessionId,
                cost_preview: benchmark.costPreview,
                auth_report_sha256: sha256Json(benchmark.authReport),
                auth_request_count: benchmark.authReport.summary?.request_count || 0,
            };
            runs.push(run);
            writeJson(path.join(RESULTS, `${targetName}.json`), run);
        }
        if (!protocolReport) throw new Error('Electron did not return the protocol benchmark report');
        scenarioResults.push(...protocolReport.results);
        writeJson(path.join(RESULTS, 'protocol.json'), protocolReport);
        const coverage = scenarioCoverage(groundTruth, scenarioResults);
        writeJson(path.join(RESULTS, 'scenarios.json'), { coverage, results: scenarioResults });
        const summary = {
            schema_version: 2,
            surface: 'desktop',
            ground_truth_sha256: sha256(groundTruthPath),
            runs,
            protocol_run: {
                report: 'benchmarks/results/desktop/protocol.json',
                report_sha256: sha256(path.join(RESULTS, 'protocol.json')),
                summary: protocolReport.summary,
            },
            scenario_coverage: coverage,
            scenario_results: scenarioResults,
            quality_gate: {
                all_precision_1: runs.every((run) => run.scores.precision === 1),
                all_recall_1: runs.every((run) => run.scores.recall === 1),
                backend_and_renderer_ready: runs.every((run) => run.backend_ready && run.renderer_ready),
                cost_previews_bounded: runs.every((run) => run.cost_preview && run.cost_preview.estimated_requests <= run.cost_preview.request_maximum),
                protocol_controls_pass: protocolReport.summary.all_passed,
                all_declared_scenarios_covered: coverage.all_declared_scenarios_covered,
                all_declared_scenarios_passed: coverage.all_declared_scenarios_passed,
            },
        };
        writeJson(path.join(RESULTS, 'summary.json'), summary);
        console.log(JSON.stringify(summary.quality_gate));
        if (!Object.values(summary.quality_gate).every(Boolean)) process.exitCode = 2;
    } finally {
        terminateProcessTree(lab);
        closeChildStreams(lab);
    }
}

main().catch((error) => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
});
