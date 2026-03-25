const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const net = require('net');

// Generate a random token for backend authentication
const BASILISK_TOKEN = crypto.randomBytes(32).toString('hex');
const E2E_MODE = process.env.BASILISK_E2E === '1';
const E2E_OUT = process.env.BASILISK_E2E_OUT || '';

// Fix GPU crashes on Wayland/Intel (prevents 30s startup delay)
if (process.platform === 'linux') {
    app.commandLine.appendSwitch('ozone-platform-hint', 'auto');
    if (process.env.WAYLAND_DISPLAY || process.env.XDG_SESSION_TYPE === 'wayland') {
        app.commandLine.appendSwitch('disable-gpu-sandbox');
        app.commandLine.appendSwitch('disable-software-rasterizer');
    }
}
if (E2E_MODE) {
    app.commandLine.appendSwitch('no-sandbox');
    app.commandLine.appendSwitch('disable-setuid-sandbox');
    app.commandLine.appendSwitch('disable-gpu');
    app.commandLine.appendSwitch('disable-dev-shm-usage');
}

let mainWindow;
let pythonProcess;
let backendPort = '8741';
let autoUpdater = null;
let shuttingDown = false;
let backendSocket = null;
let backendSocketReconnectTimer = null;
let releaseChannelInfo = {
    trust_model: 'community-build',
    display_label: 'Community Build',
    vendor_signed: false,
    notarized: false,
    warning: 'Build trust metadata unavailable.',
};
const ALLOWED_EXTERNAL_HOSTS = new Set([
    'github.com',
    'www.github.com',
    'regaan.rothackers.com',
    'rothackers.com',
]);

const BACKEND_ALLOWLIST = {
    GET: [
        '/health',
        '/api/native/status',
        '/api/modules',
        '/api/modules/multiturn',
        '/api/evolution/operators',
        '/api/mutations',
        '/api/settings/secrets',
        /^\/api\/sessions$/,
        /^\/api\/sessions\/[^/]+$/,
        /^\/api\/scan\/[^/]+$/,
        /^\/api\/audit\/[^/]+$/,
        /^\/api\/probes(?:$|\?)/,
        /^\/api\/probes\/stats$/,
        /^\/api\/probes\/leaderboard(?:$|\?)/,
        /^\/api\/probes\/effectiveness(?:\/[^/?]+)?(?:$|\?)/,
    ],
    POST: [
        '/api/scan',
        /^\/api\/scan\/[^/]+\/stop$/,
        /^\/api\/scan\/[^/]+\/resume$/,
        /^\/api\/diff$/,
        /^\/api\/posture$/,
        /^\/api\/settings\/apikey$/,
        /^\/api\/eval\/run$/,
        /^\/api\/report\/[^/]+$/,
    ],
};

function writeE2EStatus(data) {
    if (!E2E_MODE || !E2E_OUT) return;
    try {
        fs.writeFileSync(E2E_OUT, JSON.stringify({
            timestamp: new Date().toISOString(),
            ...data,
        }, null, 2));
        const terminalStage = data.uiReady || ['backend_timeout', 'ui_error', 'backend_error', 'startup_error'].includes(data.stage);
        if (process.env.BASILISK_E2E_AUTOEXIT === '1' && terminalStage) {
            setTimeout(() => app.quit(), 300);
        }
    } catch (e) {
        console.error(`[E2E] Failed to write status file: ${e.message}`);
    }
}

function resolveGeneratedReportPath(sourcePath) {
    if (!sourcePath || typeof sourcePath !== 'string') {
        return null;
    }
    const projectRoot = path.join(__dirname, '..');
    const candidateInputs = path.isAbsolute(sourcePath)
        ? [sourcePath]
        : [
            sourcePath,
            path.join(process.cwd(), sourcePath),
            path.join(projectRoot, sourcePath),
            path.join(app.getAppPath(), sourcePath),
        ];
    const resolved = [];
    for (const candidate of candidateInputs) {
        const absolute = path.resolve(candidate);
        if (!resolved.includes(absolute)) {
            resolved.push(absolute);
        }
    }
    return resolved.find((candidate) => fs.existsSync(candidate)) || resolved[0] || null;
}

function clearBackendSocketReconnect() {
    if (backendSocketReconnectTimer) {
        clearTimeout(backendSocketReconnectTimer);
        backendSocketReconnectTimer = null;
    }
}

function closeBackendEventBridge() {
    clearBackendSocketReconnect();
    if (backendSocket) {
        try {
            backendSocket.close();
        } catch {
            // best-effort shutdown
        }
        backendSocket = null;
    }
}

/**
 * Authenticated backend request from the main process only.
 */
function backendRequest(endpoint, { method = 'GET', body = null } = {}) {
    return new Promise((resolve, reject) => {
        if (!isAllowedBackendRequest(method, endpoint)) {
            reject(new Error(`Blocked backend request: ${method} ${endpoint}`));
            return;
        }

        const url = new URL(endpoint, `http://127.0.0.1:${backendPort}`);
        const payload = body == null ? null : JSON.stringify(body);
        const headers = { 'X-Basilisk-Token': BASILISK_TOKEN };
        if (payload) {
            headers['Content-Type'] = 'application/json';
            headers['Content-Length'] = Buffer.byteLength(payload);
        }

        const req = http.request(url, { method, headers }, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => {
                let parsed;
                try { parsed = body ? JSON.parse(body) : {}; }
                catch { parsed = { raw: body }; }
                if (res.statusCode >= 400) {
                    resolve({
                        ...parsed,
                        error: parsed.error || `HTTP ${res.statusCode}`,
                        status_code: res.statusCode,
                    });
                    return;
                }
                resolve(parsed);
            });
        });
        req.on('error', (e) => reject(e));
        req.setTimeout(10000, () => { req.destroy(); reject(new Error('Timeout')); });
        if (payload) {
            req.write(payload);
        }
        req.end();
    });
}

function backendGet(endpoint) {
    return backendRequest(endpoint, { method: 'GET' });
}

function isAllowedBackendRequest(method, endpoint) {
    const normalizedMethod = String(method || 'GET').toUpperCase();
    const base = String(endpoint || '').split('#')[0];
    const rules = BACKEND_ALLOWLIST[normalizedMethod] || [];
    return rules.some((rule) => {
        if (typeof rule === 'string') {
            return base === rule;
        }
        return rule.test(base);
    });
}

function loadReleaseChannelInfo() {
    const candidates = [
        path.join(process.resourcesPath || '', 'metadata', 'release-channel.json'),
        path.join(__dirname, 'build', 'release-channel.json'),
    ].filter(Boolean);
    for (const candidate of candidates) {
        try {
            if (!fs.existsSync(candidate)) continue;
            return JSON.parse(fs.readFileSync(candidate, 'utf8'));
        } catch (e) {
            console.warn(`[Main] Failed to parse release metadata ${candidate}: ${e.message}`);
        }
    }
    return {
        trust_model: 'community-build',
        display_label: 'Community Build',
        vendor_signed: false,
        notarized: false,
        warning: 'Build trust metadata unavailable.',
    };
}

function updatesAllowed() {
    return !!(releaseChannelInfo && releaseChannelInfo.trust_model === 'vendor-signed');
}

function backendEnv() {
    const env = {
        ...process.env,
        BASILISK_PORT: backendPort,
        BASILISK_TOKEN: BASILISK_TOKEN,
    };
    if (app.isPackaged && releaseChannelInfo && releaseChannelInfo.trust_model === 'community-build') {
        env.BASILISK_SKIP_NATIVE_INTEGRITY_CHECK = 'true';
    }
    return env;
}

function normalizeExternalUrl(url) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol === 'mailto:') {
            return parsed.toString();
        }
        if (parsed.protocol !== 'https:') {
            return null;
        }
        if (!ALLOWED_EXTERNAL_HOSTS.has(parsed.hostname)) {
            return null;
        }
        return parsed.toString();
    } catch {
        return null;
    }
}

async function safeOpenExternal(url) {
    const normalized = normalizeExternalUrl(url);
    if (!normalized) {
        return { success: false, error: 'URL not allowlisted' };
    }
    await shell.openExternal(normalized);
    return { success: true };
}

function connectBackendEventBridge() {
    if (backendSocket || shuttingDown) return;
    if (typeof WebSocket !== 'function') return;
    const wsUrl = `ws://127.0.0.1:${backendPort}/ws?token=${BASILISK_TOKEN}`;
    try {
        const socket = new WebSocket(wsUrl);
        backendSocket = socket;

        socket.addEventListener('message', (event) => {
            try {
                const message = JSON.parse(String(event.data || '{}'));
                sendToRenderer('backend:event', message);
            } catch (e) {
                console.warn(`[Main] Failed to parse backend event: ${e.message}`);
            }
        });

        socket.addEventListener('close', () => {
            if (backendSocket === socket) {
                backendSocket = null;
            }
            if (!shuttingDown) {
                clearBackendSocketReconnect();
                backendSocketReconnectTimer = setTimeout(() => {
                    connectBackendEventBridge();
                }, 1000);
            }
        });

        socket.addEventListener('error', (event) => {
            const msg = event?.message || 'Backend event bridge error';
            console.warn(`[Main] ${msg}`);
        });
    } catch (e) {
        console.warn(`[Main] Failed to connect backend event bridge: ${e.message}`);
    }
}

function probePort(port) {
    return new Promise((resolve) => {
        const server = net.createServer();
        server.unref();
        server.on('error', () => resolve(null));
        server.listen({ host: '127.0.0.1', port: Number(port) }, () => {
            const address = server.address();
            const resolved = address && typeof address === 'object' ? String(address.port) : String(port);
            server.close(() => resolve(resolved));
        });
    });
}

async function findAvailablePort(preferredPort) {
    const requested = Number(preferredPort);
    if (Number.isInteger(requested) && requested > 0) {
        const exact = await probePort(requested);
        if (exact) return exact;

        for (let offset = 1; offset <= 20; offset++) {
            const candidate = await probePort(requested + offset);
            if (candidate) {
                console.warn(`[Main] Preferred port ${requested} unavailable, using ${candidate} instead.`);
                return candidate;
            }
        }
    }

    const ephemeral = await probePort(0);
    if (ephemeral) return ephemeral;
    throw new Error('Unable to reserve a local backend port');
}

function createWindow() {
    // Remove the native menu bar completely
    Menu.setApplicationMenu(null);

    // Resolve icon path: build/icon.png > src/assets/logo.jpg
    const iconPng = path.join(__dirname, 'build', 'icon.png');
    const iconJpg = path.join(__dirname, 'src', 'assets', 'logo.jpg');
    const iconPath = fs.existsSync(iconPng) ? iconPng : iconJpg;

    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1024,
        minHeight: 700,
        icon: iconPath,
        frame: false,
        autoHideMenuBar: true,
        backgroundColor: '#09090b',
        show: false, // Don't show until ready
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: !E2E_MODE,
            webSecurity: true,
            allowRunningInsecureContent: false,
            offscreen: false,
        },
    });

    mainWindow.loadFile('src/index.html');
    mainWindow.webContents.once('did-finish-load', () => {
        writeE2EStatus({
            stage: 'window_loaded',
            backendPort,
            windowLoaded: true,
            backendReady: false,
        });
    });

    const windowUrl = mainWindow.webContents.getURL.bind(mainWindow.webContents);
    mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    mainWindow.webContents.on('will-navigate', (event, url) => {
        if (url !== windowUrl()) {
            event.preventDefault();
        }
    });
    mainWindow.webContents.on('will-attach-webview', (event) => {
        event.preventDefault();
    });
    const { session } = mainWindow.webContents;
    session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
    if (session.setPermissionCheckHandler) {
        session.setPermissionCheckHandler(() => false);
    }

    // Show window as soon as the page is ready (don't wait for backend)
    mainWindow.once('ready-to-show', () => {
        if (!E2E_MODE) mainWindow.show();
    });
}

// Start FastAPI backend sidecar
function startBackend() {
    console.log('[*] Starting Basilisk Python backend...');

    let executablePath;
    let args = [];
    let options = {};
    const bridgePort = backendPort;
    backendPort = bridgePort;

    if (app.isPackaged) {
        if (process.platform === 'win32') {
            executablePath = path.join(process.resourcesPath, 'bin', 'basilisk-backend.exe');
        } else {
            const bundled = path.join(process.resourcesPath, 'bin', 'basilisk-backend');
            const system = path.join(__dirname, 'bin', 'basilisk-backend');
            executablePath = fs.existsSync(system) ? system : bundled;
        }

        if (!fs.existsSync(executablePath)) {
            console.error(`[FATAL] Backend binary not found: ${executablePath}`);
            dialog.showErrorBox('Basilisk Backend Missing', `Could not find backend at:\n${executablePath}\n\nPlease reinstall Basilisk.`);
            return;
        }

        if (process.platform !== 'win32') {
            try {
                fs.accessSync(executablePath, fs.constants.W_OK);
                fs.chmodSync(executablePath, 0o755);
            } catch (e) { /* system install, already +x */ }
        }

        options = { stdio: 'pipe', env: backendEnv() };
    } else {
        // Dev mode — use venv python if available
        const projectRoot = path.join(__dirname, '..');
        const venvPython = path.join(projectRoot, 'venv', 'bin', 'python');
        const venvPythonWin = path.join(projectRoot, 'venv', 'Scripts', 'python.exe');

        if (process.platform === 'win32' && fs.existsSync(venvPythonWin)) {
            executablePath = venvPythonWin;
        } else if (fs.existsSync(venvPython)) {
            executablePath = venvPython;
        } else {
            executablePath = process.platform === 'win32' ? 'python' : 'python3';
        }

        options = {
            cwd: projectRoot,
            stdio: 'pipe',
            env: backendEnv(),
        };
        args = ['-m', 'basilisk.desktop_backend'];
    }

    console.log(`[Main] Spawning: ${executablePath} ${args.join(' ')}`);

    try {
        pythonProcess = spawn(executablePath, args, options);
    } catch (e) {
        console.error(`[FATAL] Failed to spawn backend: ${e.message}`);
        dialog.showErrorBox('Basilisk Backend Error', `Failed to start backend:\n${e.message}`);
        return;
    }

    pythonProcess.stdout.on('data', (data) => {
        const msg = data.toString();
        console.log(`[Python] ${msg}`);
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-log', msg);
        }
    });

    pythonProcess.stderr.on('data', (data) => {
        const msg = data.toString();
        console.error(`[Python] ${msg}`);
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-log', msg);
        }
    });

    pythonProcess.on('exit', (code, signal) => {
        console.error(`[Main] Backend exited code=${code} signal=${signal}`);
        writeE2EStatus({
            stage: 'backend_exit',
            backendPort,
            backendReady: false,
            exitCode: code,
            signal,
        });
        if (code !== 0 && code !== null && mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-error', `Backend crashed (exit code ${code})`);
        }
    });

    pythonProcess.on('error', (err) => {
        console.error(`[FATAL] Backend error: ${err.message}`);
        writeE2EStatus({
            stage: 'backend_error',
            backendPort,
            backendReady: false,
            error: err.message,
        });
        dialog.showErrorBox('Basilisk Backend Error', `Backend failed:\n${err.message}`);
    });
}

async function waitForBackendReady(attempts = 40) {
    for (let i = 0; i < attempts; i++) {
        try {
            const health = await backendGet('/health');
            if (health && health.status === 'online') {
                connectBackendEventBridge();
                writeE2EStatus({
                    stage: 'backend_ready',
                    backendPort,
                    backendReady: true,
                    health,
                });
                if (E2E_MODE) {
                    await new Promise((resolve) => setTimeout(resolve, 300));
                    await runE2ESmoke();
                }
                return;
            }
        } catch (e) {
            // retry
        }
        await new Promise(resolve => setTimeout(resolve, 250));
    }
    writeE2EStatus({
        stage: 'backend_timeout',
        backendPort,
        backendReady: false,
    });
}

async function runE2ESmoke() {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    for (let i = 0; i < 40; i++) {
        if (mainWindow.webContents && !mainWindow.webContents.isLoading()) break;
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    try {
        const snapshot = await mainWindow.webContents.executeJavaScript(`
            (async () => {
                const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                const clickTab = (name) => document.querySelector('.tab[data-v="' + name + '"]')?.click();
                let step = 'bootstrap';
                const waitFor = async (predicate, timeout = 8000, label = 'condition') => {
                    const started = Date.now();
                    while (Date.now() - started < timeout) {
                        const result = predicate();
                        if (result) return result;
                        await sleep(100);
                    }
                    throw new Error(label + ': Timed out waiting for UI condition');
                };

                await sleep(300);
                step = 'settings';
                clickTab('settings');
                await sleep(500);
                const secretStoreStatus = document.getElementById('secret-store-status')?.innerText?.trim() || '';
                const updateTrust = document.getElementById('update-build-trust')?.innerText?.trim() || '';
                const hasLegacyTokenGetter = typeof window.basilisk?._getToken === 'function';
                step = 'modules';
                clickTab('modules');
                await sleep(600);
                const activeView = document.querySelector('.view.active')?.id || '';
                const moduleCards = document.querySelectorAll('#mod-grid .mod-card').length;
                const tabCount = document.querySelectorAll('.tab').length;
                const hasRetentionInput = !!document.getElementById('s-retain-days');

                step = 'scan_complete_start';
                clickTab('scan');
                await sleep(300);
                document.getElementById('s-target').value = 'e2e://complete';
                document.getElementById('s-provider').value = 'custom';
                document.getElementById('s-operator').value = 'e2e-operator';
                document.getElementById('s-ticket').value = 'E2E-100';
                document.getElementById('s-approval-confirmed').checked = true;
                document.getElementById('btn-scan-start').click();
                await waitFor(() => document.querySelectorAll('#live-findings .fc').length >= 1 || document.getElementById('live-count')?.innerText?.includes('1 detected'), 12000, 'finding_visible');
                await waitFor(() => document.getElementById('btn-scan-stop')?.classList.contains('is-hidden'), 12000, 'scan_complete');
                const liveFindingsCount = document.querySelectorAll('#live-findings .fc').length;

                step = 'sessions';
                clickTab('sessions');
                await waitFor(() => document.querySelectorAll('#sess-list .sess-item').length >= 1, 12000, 'session_list');
                document.querySelector('#sess-list .sess-item')?.click();
                await sleep(500);
                const sessionRows = document.querySelectorAll('#sess-detail table tbody tr').length;
                const cleanAuditVisible = document.getElementById('sess-detail')?.innerText?.includes('Campaign:') || false;

                step = 'reports';
                clickTab('reports');
                await waitFor(() => document.getElementById('rpt-sess')?.options?.length > 1, 12000, 'report_session_list');
                const reportSelect = document.getElementById('rpt-sess');
                if (reportSelect && reportSelect.options.length > 1) {
                    reportSelect.selectedIndex = 1;
                }
                document.getElementById('btn-gen-report')?.click();
                await waitFor(() => document.getElementById('full-log')?.innerText?.includes('Exported:'), 12000, 'report_export');
                const reportExported = document.getElementById('full-log')?.innerText?.includes('Exported:') || false;
                const reportOptions = document.getElementById('rpt-sess')?.options?.length || 0;

                step = 'scan_stop_start';
                clickTab('scan');
                await sleep(250);
                document.getElementById('s-target').value = 'e2e://long';
                document.getElementById('s-provider').value = 'custom';
                document.getElementById('s-operator').value = 'e2e-operator';
                document.getElementById('s-ticket').value = 'E2E-101';
                document.getElementById('s-approval-confirmed').checked = true;
                document.getElementById('btn-scan-start').click();
                await waitFor(() => !document.getElementById('btn-scan-stop')?.classList.contains('is-hidden'), 6000, 'stop_button_visible');
                document.getElementById('btn-scan-stop')?.click();
                await waitFor(() => document.getElementById('btn-scan-stop')?.classList.contains('is-hidden'), 8000, 'scan_stopped');
                const stopWorked = document.getElementById('full-log')?.innerText?.includes('Scan stopped.') || false;
                const logCapturedCompletion = document.getElementById('full-log')?.innerText?.includes('Scan complete.') || false;

                return {
                    step,
                    activeView,
                    moduleCards,
                    tabCount,
                    hasRetentionInput,
                    secretStoreStatus,
                    updateTrust,
                    hasLegacyTokenGetter,
                    liveFindingsCount,
                    sessionRows,
                    cleanAuditVisible,
                    reportExported,
                    reportOptions,
                    stopWorked,
                    logCapturedCompletion,
                };
            })();
        `, true);
        writeE2EStatus({
            stage: 'ui_ready',
            backendPort,
            backendReady: true,
            uiReady: true,
            ...snapshot,
        });
    } catch (e) {
        writeE2EStatus({
            stage: 'ui_error',
            backendPort,
            backendReady: true,
            uiReady: false,
            error: e.message,
        });
    }
}

function killBackend() {
    if (pythonProcess) {
        console.log('[*] Terminating backend process...');
        try {
            if (process.platform === 'win32') {
                execSync(`taskkill /F /PID ${pythonProcess.pid} /T`);
            } else {
                // Try SIGTERM first (graceful)
                pythonProcess.kill('SIGTERM');

                // Hard kill after 2 seconds if still running
                const pid = pythonProcess.pid;
                setTimeout(() => {
                    try {
                        process.kill(pid, 0); // Check if exists
                        console.log(`[*] Backend PID ${pid} still alive, sending SIGKILL...`);
                        process.kill(pid, 'SIGKILL');
                    } catch (e) {
                        // Process already gone, which is what we want
                    }
                }, 2000);
            }
        } catch (e) {
            console.error(`[!] Error killing backend: ${e.message}`);
        }
        pythonProcess = null;
    }
}

function getAutoUpdater() {
    if (autoUpdater) return autoUpdater;
    try {
        ({ autoUpdater } = require('electron-updater'));
        return autoUpdater;
    } catch (e) {
        console.error(`[Updater] Failed to load electron-updater: ${e.message}`);
        return null;
    }
}

app.whenReady().then(async () => {
    try {
        releaseChannelInfo = loadReleaseChannelInfo();
        backendPort = await findAvailablePort(process.env.BASILISK_PORT || backendPort);
        startBackend();
        createWindow();
        waitForBackendReady();
        if (!E2E_MODE) {
            setupAutoUpdater();
        }
    } catch (err) {
        console.error(`[FATAL] Failed to reserve backend port: ${err.message}`);
        writeE2EStatus({
            stage: 'startup_error',
            backendReady: false,
            error: err.message,
        });
        dialog.showErrorBox('Basilisk Startup Error', `Failed to reserve a local backend port:\n${err.message}`);
        return;
    }

    // ── IPC: Dialog Handlers ─────────────────────────────────────────────
    ipcMain.handle('dialog:exportReport', async (event, htmlContent) => {
        if (E2E_MODE) {
            const autoPath = path.join(app.getPath('temp'), `basilisk-report-${Date.now()}.html`);
            try {
                fs.writeFileSync(autoPath, htmlContent, 'utf-8');
                return { success: true, path: autoPath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export Report',
            filters: [
                { name: 'HTML Report', extensions: ['html'] },
                { name: 'JSON Report', extensions: ['json'] },
                { name: 'SARIF Report', extensions: ['sarif'] },
                { name: 'Markdown', extensions: ['md'] },
                { name: 'PDF Report', extensions: ['pdf'] },
            ],
            defaultPath: `basilisk_report_${Date.now()}.html`,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, htmlContent, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:saveFile', async (event, { content, defaultName, filters }) => {
        if (E2E_MODE) {
            const autoPath = path.join(app.getPath('temp'), defaultName || `basilisk-file-${Date.now()}.txt`);
            try {
                fs.writeFileSync(autoPath, content, 'utf-8');
                return { success: true, path: autoPath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Save File',
            filters: filters || [{ name: 'All Files', extensions: ['*'] }],
            defaultPath: defaultName,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, content, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:copyFile', async (event, { sourcePath, defaultName, filters }) => {
        const resolvedSource = resolveGeneratedReportPath(sourcePath);
        if (!resolvedSource) {
            return { success: false, error: 'Generated report path was missing' };
        }
        if (!resolvedSource.includes(`${path.sep}basilisk-reports${path.sep}`)) {
            return { success: false, error: 'Only generated Basilisk reports can be exported' };
        }
        if (E2E_MODE) {
            const autoPath = path.join(app.getPath('temp'), defaultName || `basilisk-e2e-${Date.now()}.html`);
            try {
                fs.copyFileSync(resolvedSource, autoPath);
                return { success: true, path: autoPath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }

        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export Report',
            filters: filters || [{ name: 'All Files', extensions: ['*'] }],
            defaultPath: defaultName,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.copyFileSync(resolvedSource, result.filePath);
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    // ── IPC: Window Controls ─────────────────────────────────────────────
    ipcMain.on('window:minimize', () => { if (mainWindow) mainWindow.minimize(); });
    ipcMain.on('window:maximize', () => {
        if (mainWindow) {
            mainWindow.isMaximized() ? mainWindow.restore() : mainWindow.maximize();
        }
    });
    ipcMain.on('window:close', () => { if (mainWindow) mainWindow.close(); });
    ipcMain.handle('backend:request', async (_event, payload = {}) => {
        const endpoint = typeof payload.path === 'string' ? payload.path : '';
        const method = typeof payload.method === 'string' ? payload.method.toUpperCase() : 'GET';
        const body = payload.body ?? null;
        try {
            return await backendRequest(endpoint, { method, body });
        } catch (e) {
            return { error: e.message };
        }
    });

    // ── IPC: Backend Proxies ─────────────────────────────────────────────
    // These let the renderer fetch data through main process when needed
    ipcMain.handle('backend:multiturnModules', async () => {
        try { return await backendGet('/api/modules/multiturn'); }
        catch (e) { return { error: e.message }; }
    });

    ipcMain.handle('backend:evolutionOperators', async () => {
        try { return await backendGet('/api/evolution/operators'); }
        catch (e) { return { error: e.message }; }
    });

    ipcMain.handle('backend:moduleList', async () => {
        try { return await backendGet('/api/modules'); }
        catch (e) { return { error: e.message }; }
    });

    // ── IPC: Shell ────────────────────────────────────────────────────────
    ipcMain.handle('shell:openExternal', async (event, url) => {
        return safeOpenExternal(url);
    });

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

/**
 * Auto-updater: checks GitHub Releases for new versions on startup.
 * Events are forwarded to renderer for in-app notifications.
 */
function setupAutoUpdater() {
    // Don't check for updates in dev mode
    if (!app.isPackaged) {
        console.log('[Updater] Skipping update check in dev mode');
        return;
    }
    if (!updatesAllowed()) {
        console.log('[Updater] Auto-update disabled for non vendor-signed builds');
        return;
    }

    const updater = getAutoUpdater();
    if (!updater) {
        return;
    }

    updater.autoDownload = false;  // Ask user before downloading
    updater.autoInstallOnAppQuit = true;

    updater.on('checking-for-update', () => {
        console.log('[Updater] Checking for updates...');
        sendToRenderer('update:checking');
    });

    updater.on('update-available', (info) => {
        console.log(`[Updater] Update available: v${info.version}`);
        sendToRenderer('update:available', {
            version: info.version,
            releaseDate: info.releaseDate,
            releaseNotes: info.releaseNotes,
        });
    });

    updater.on('update-not-available', (info) => {
        console.log(`[Updater] Already on latest: v${info.version}`);
        sendToRenderer('update:not-available', { version: info.version });
    });

    updater.on('download-progress', (progress) => {
        sendToRenderer('update:progress', {
            percent: Math.round(progress.percent),
            transferred: progress.transferred,
            total: progress.total,
            bytesPerSecond: progress.bytesPerSecond,
        });
    });

    updater.on('update-downloaded', (info) => {
        console.log(`[Updater] Update downloaded: v${info.version}`);
        sendToRenderer('update:downloaded', { version: info.version });
    });

    updater.on('error', (err) => {
        console.error(`[Updater] Error: ${err.message}`);
        sendToRenderer('update:error', { error: err.message });
    });

    // Check after a short delay to not block startup
    setTimeout(() => {
        updater.checkForUpdates().catch(err => {
            console.error(`[Updater] Check failed: ${err.message}`);
        });
    }, 3000);
}

function sendToRenderer(channel, data) {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send(channel, data);
    }
}

// IPC: Update controls
ipcMain.handle('update:check', async () => {
    if (!updatesAllowed()) {
        return { success: false, error: 'Manual updates only for community builds', manual_only: true };
    }
    const updater = getAutoUpdater();
    if (!updater) return { success: false, error: 'Auto-updater unavailable' };
    try {
        const result = await updater.checkForUpdates();
        return { success: true, version: result?.updateInfo?.version };
    } catch (e) {
        return { success: false, error: e.message };
    }
});

ipcMain.handle('update:download', async () => {
    if (!updatesAllowed()) {
        return { success: false, error: 'Manual updates only for community builds', manual_only: true };
    }
    const updater = getAutoUpdater();
    if (!updater) return { success: false, error: 'Auto-updater unavailable' };
    try {
        await updater.downloadUpdate();
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
});

ipcMain.handle('update:install', () => {
    if (!updatesAllowed()) return { success: false, error: 'Manual updates only for community builds', manual_only: true };
    const updater = getAutoUpdater();
    if (!updater) return { success: false, error: 'Auto-updater unavailable' };
    updater.quitAndInstall(false, true);
    return { success: true };
});

ipcMain.handle('update:getStatus', () => ({
    packaged: app.isPackaged,
    enabled: updatesAllowed(),
    trust_model: releaseChannelInfo.trust_model,
    display_label: releaseChannelInfo.display_label,
    vendor_signed: !!releaseChannelInfo.vendor_signed,
    notarized: !!releaseChannelInfo.notarized,
    warning: releaseChannelInfo.warning || '',
}));

app.on('window-all-closed', () => {
    shuttingDown = true;
    closeBackendEventBridge();
    killBackend();
    if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
    shuttingDown = true;
    closeBackendEventBridge();
    killBackend();
});

// ── Uncaught error handlers (prevent silent crashes) ─────────────────────
process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught exception:', err.message);
    console.error(err.stack);
});

process.on('unhandledRejection', (reason) => {
    console.error('[WARN] Unhandled rejection:', reason);
});
