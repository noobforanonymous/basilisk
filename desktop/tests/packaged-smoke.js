'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

function terminateProcessTree(child) {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    if (process.platform === 'win32') {
        spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
            windowsHide: true,
            stdio: 'ignore',
        });
        return;
    }
    try {
        process.kill(-child.pid, 'SIGTERM');
    } catch {
        try { child.kill('SIGTERM'); } catch { /* already exited */ }
    }
}

async function waitForTerminalSnapshot(child, outputPath, timeoutMs = 90000) {
    const startedAt = Date.now();
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    while (Date.now() - startedAt < timeoutMs) {
        if (fs.existsSync(outputPath)) {
            try {
                const snapshot = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
                if (snapshot.stage === 'ui_ready') return snapshot;
                if (['ui_error', 'backend_error', 'backend_exit', 'backend_timeout', 'startup_error'].includes(snapshot.stage)) {
                    throw new Error(`${snapshot.stage}: ${snapshot.error || 'unknown error'}\n${stderr}`);
                }
            } catch (error) {
                if (!(error instanceof SyntaxError)) throw error;
            }
        }
        if (child.exitCode !== null && !fs.existsSync(outputPath)) {
            throw new Error(`Packaged app exited before writing E2E evidence (${child.exitCode})\n${stderr}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error(`Packaged app smoke timed out\n${stdout}\n${stderr}`);
}

async function main() {
    const executable = path.resolve(process.argv[2] || '');
    if (!process.argv[2] || !fs.existsSync(executable)) {
        throw new Error(`Packaged executable does not exist: ${executable}`);
    }
    const outputPath = path.join(
        os.tmpdir(),
        `basilisk-packaged-smoke-${Date.now()}-${process.pid}.json`,
    );
    const childEnv = { ...process.env };
    delete childEnv.ELECTRON_RUN_AS_NODE;
    const child = spawn(executable, ['--no-sandbox', '--disable-setuid-sandbox'], {
        cwd: path.dirname(executable),
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
            ...childEnv,
            APPIMAGE_EXTRACT_AND_RUN: childEnv.APPIMAGE_EXTRACT_AND_RUN || '1',
            BASILISK_E2E: '1',
            BASILISK_E2E_AUTOEXIT: '1',
            BASILISK_E2E_OUT: outputPath,
        },
    });

    try {
        const data = await waitForTerminalSnapshot(child, outputPath);
        assert.equal(data.backendReady, true, JSON.stringify(data, null, 2));
        assert.equal(data.uiReady, true, JSON.stringify(data, null, 2));
        assert.equal(data.stage, 'ui_ready');
        assert.ok(data.backendPort);
        assert.ok(data.tabCount >= 10);
        assert.equal(data.reportExported, true);
        assert.equal(data.stopWorked, true);
        assert.equal(data.logCapturedCompletion, true);
        assert.equal(data.costPreviewVisible, true);
        console.log(JSON.stringify({
            packaged_smoke: true,
            executable,
            backend_ready: data.backendReady,
            renderer_ready: data.uiReady,
        }));
    } finally {
        terminateProcessTree(child);
        child.stdout?.destroy();
        child.stderr?.destroy();
        fs.rmSync(outputPath, { force: true });
    }
}

main().catch((error) => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
});
