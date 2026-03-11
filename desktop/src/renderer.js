/**
 * Basilisk Desktop Renderer
 * Unique top-tab navigation, wired to FastAPI backend on :8741
 */

// ── Window controls ──
document.getElementById('btn-min')?.addEventListener('click', () => (window.basilisk?.send || window.api?.send)?.('window:minimize'));
document.getElementById('btn-max')?.addEventListener('click', () => (window.basilisk?.send || window.api?.send)?.('window:maximize'));
document.getElementById('btn-close')?.addEventListener('click', () => (window.basilisk?.send || window.api?.send)?.('window:close'));

// ── State ──
const BRIDGE = 'http://127.0.0.1:8741';
let currentSession = null;
let allFindings = [];
let scanning = false;
let timerInterval = null;
let timerStart = null;
let authToken = null;

// ── Navigation ──
const tabs = document.querySelectorAll('.tab');
const views = document.querySelectorAll('.view');

tabs.forEach(t => {
    t.addEventListener('click', () => {
        tabs.forEach(x => x.classList.remove('active'));
        views.forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        const v = document.getElementById(`v-${t.dataset.v}`);
        if (v) v.classList.add('active');
        // lazy load
        if (t.dataset.v === 'modules') { loadModules(); loadMultiturnModules(); }
        if (t.dataset.v === 'evolution') loadEvolutionOperators();
        if (t.dataset.v === 'sessions' || t.dataset.v === 'reports') loadSessions();
        if (t.dataset.v === 'settings') loadNative();
    });
});

// ── Helpers ──
const esc = s => { const d = document.createElement('div'); d.innerText = s || ''; return d.innerHTML; };
const trunc = (s, n = 100) => { const x = typeof s === 'string' ? s : JSON.stringify(s || ''); return x.length > n ? x.slice(0, n) + '…' : x; };
const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });

function log(type, msg) {
    [document.getElementById('sys-log'), document.getElementById('full-log')].forEach(el => {
        if (!el) return;
        const d = document.createElement('div');
        d.className = `ll ${type}`;
        d.innerText = `[${ts()}] ${msg}`;
        el.appendChild(d);
        el.scrollTop = el.scrollHeight;
    });
    // For critical visual feedback, also toast
    if (type === 'err') toast('error', msg);
}

function toast(type, msg) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    const iconMap = { error: '✕', ok: '✓', inf: 'ℹ' };
    const icon = iconMap[type] || '•';
    t.innerHTML = `
        <div class="toast-icon">${icon}</div>
        <div class="toast-msg">${esc(msg)}</div>
    `;
    container.appendChild(t);
    setTimeout(() => {
        t.classList.add('removing');
        setTimeout(() => t.remove(), 200);
    }, 4000);
}

async function apiFetch(path, opts = {}) {
    try {
        if (!authToken && window.basilisk?._getToken) {
            authToken = await window.basilisk._getToken();
        }
        const headers = { 'Content-Type': 'application/json' };
        if (authToken) headers['X-Basilisk-Token'] = authToken;

        const r = await fetch(`${BRIDGE}${path}`, { headers, ...opts });
        const data = await r.json();
        if (!r.ok || data.error) {
            const err = data.error || `HTTP ${r.status}`;
            toast('error', err);
            return data;
        }
        return data;
    } catch (e) {
        if (backendReady) {
            log('err', `API: ${e.message}`);
            toast('error', `Connection failed: ${e.message}`);
        }
        return { error: e.message };
    }
}

// ── Backend Connection ──
const connDot = document.getElementById('conn-dot');
const connLabel = document.getElementById('conn-label');
let backendReady = false;

async function checkBackend(silent = false) {
    try {
        const r = await fetch(`${BRIDGE}/health`);
        if (r.ok) {
            connDot.classList.add('on');
            connDot.classList.remove('err');
            connLabel.innerText = 'Connected';
            if (!backendReady) {
                log('ok', 'Backend connected.');
                toast('ok', 'Basilisk engine connected.');
                backendReady = true;
            }
            return true;
        }
    } catch {
        if (!silent) {
            connDot.classList.remove('on');
            connDot.classList.add('err');
            connLabel.innerText = 'Offline';
        }
    }
    return false;
}

let poll = setInterval(async () => {
    if (!authToken && window.basilisk?._getToken) {
        authToken = await window.basilisk._getToken();
    }
    if (await checkBackend()) {
        clearInterval(poll);
        loadNative();
        loadModules();
        connectWebSocket();
    }
}, 500);
checkBackend(true); // silent first attempt — backend is still starting

// ── WebSocket for real-time scan events ──
let ws = null;
let wsRetries = 0;

function connectWebSocket() {
    if (wsRetries >= 5) return;
    try {
        const url = `ws://127.0.0.1:8741/ws${authToken ? `?token=${authToken}` : ''}`;
        ws = new WebSocket(url);
        ws.onopen = () => { wsRetries = 0; log('ok', 'WebSocket connected.'); };
        ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                if (msg.event === 'auth_error') {
                    log('err', 'WebSocket Authentication failed.');
                    return;
                }
                handleWSEvent(msg.event, msg.data);
            } catch { }
        };
        ws.onclose = () => {
            wsRetries++;
            if (wsRetries === 1) log('dim', 'WebSocket disconnected — using HTTP polling.');
            if (wsRetries < 5) setTimeout(connectWebSocket, 5000);
        };
        ws.onerror = () => { };
    } catch { }
}

function handleWSEvent(event, data) {
    switch (event) {
        case 'scan:status':
            log('inf', `Scan phase: ${data.phase}`);
            if (data.phase === 'evolving') {
                const phase = document.getElementById('scan-phase');
                if (phase) phase.innerText = 'Smart Prompt Evolution...';
                log('inf', 'Starting AI-powered prompt evolution loop...');
            }
            break;
        case 'scan:progress':
            if (data.progress !== undefined) {
                const bar = document.getElementById('scan-bar');
                if (bar) bar.style.width = `${Math.round(data.progress * 100)}%`;
            }
            if (data.module) {
                const phase = document.getElementById('scan-phase');
                if (phase) phase.innerText = data.module;
            }
            break;
        case 'scan:evolution_stats':
            if (data.stats) {
                const s = data.stats;
                const phase = document.getElementById('scan-phase');
                if (phase) phase.innerText = `Evolution Gen ${s.generation} | Best: ${s.best_fitness?.toFixed(2)} | BT: ${s.breakthroughs}`;

                // Jump progress bar slightly more with each generation
                const bar = document.getElementById('scan-bar');
                if (bar && s.generation && s.total_generations) {
                    bar.style.width = `${Math.round((s.generation / s.total_generations) * 100)}%`;
                }

                // Update evolution KPIs in realtime
                const safe = (id, val) => { const el = document.getElementById(id); if (el && val !== undefined) el.innerText = val; };
                safe('evo-gen', s.generation);
                safe('evo-pop', s.population_size || s.pop_size);
                safe('evo-fit', s.best_fitness?.toFixed(3));
                safe('evo-mean', s.mean_fitness?.toFixed(3));
                safe('evo-diversity', s.diversity !== undefined ? `${(s.diversity * 100).toFixed(0)}%` : undefined);
                safe('evo-stagnation', s.stagnation_counter);
                safe('evo-mutrate', s.mutation_rate !== undefined ? `${(s.mutation_rate * 100).toFixed(0)}%` : undefined);
            }
            break;
        case 'scan:finding':
            if (data.finding) {
                if (!allFindings.find(x => x.title === data.finding.title && x.attack_module === data.finding.attack_module)) {
                    allFindings.push(data.finding);
                    addFinding(document.getElementById('live-findings'), data.finding);
                    addFinding(document.getElementById('dash-findings'), data.finding);
                    log('err', `VULN [${data.finding.severity}] ${data.finding.title}`);
                    updateSev();
                    updateTable();
                    const lc = document.getElementById('live-count');
                    if (lc) lc.innerText = `${allFindings.length} detected`;
                    document.getElementById('k-findings').innerText = allFindings.length;
                }
            }
            break;
        case 'scan:profile':
            if (data.profile) updateRecon(data.profile);
            break;
        case 'scan:complete':
            log('ok', `Scan complete. ${data.total_findings} findings.`);
            const barFinal = document.getElementById('scan-bar');
            if (barFinal) barFinal.style.width = '100%';
            resetScan();
            const p = document.getElementById('k-posture');
            if (allFindings.length === 0) { p.innerText = 'SECURE'; p.className = 'kpi-value safe'; }
            else {
                const hasCrit = allFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
                p.innerText = hasCrit ? 'COMPROMISED' : 'AT RISK';
                p.className = `kpi-value ${hasCrit ? 'danger' : 'warn'}`;
            }
            break;
        case 'scan:error':
            log('err', `Scan error: ${data.error}`);
            resetScan();
            break;
    }
}

function updateRecon(profile) {
    const safe = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val || '—'; };
    safe('r-model', profile.model_family);
    safe('r-creator', profile.creator);
    safe('r-ctx', profile.context_window ? `${profile.context_window}` : null);
    safe('r-guard', profile.has_guardrails ? 'Yes' : 'No');
    safe('r-tools', profile.has_tools ? 'Yes' : 'No');
    safe('r-rag', profile.has_rag ? 'Yes' : 'No');
}

// ── Timer ──
const timerEl = document.getElementById('scan-timer');
function startTimer() {
    timerStart = Date.now();
    timerEl.classList.add('on');
    timerInterval = setInterval(() => {
        const s = Math.floor((Date.now() - timerStart) / 1000);
        timerEl.innerText = `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
    }, 1000);
}
function stopTimer() { clearInterval(timerInterval); timerEl.classList.remove('on'); }

// ── Scan ──
const btnStart = document.getElementById('btn-scan-start');
const btnStop = document.getElementById('btn-scan-stop');
const progressPane = document.getElementById('scan-progress-pane');
const scanBar = document.getElementById('scan-bar');
const scanPhase = document.getElementById('scan-phase');
const scanPill = document.getElementById('scan-mode-pill');
const liveFindings = document.getElementById('live-findings');
const liveCount = document.getElementById('live-count');
const scanDot = document.getElementById('scan-dot');

btnStart.addEventListener('click', async () => {
    const target = document.getElementById('s-target').value.trim();
    if (!target) { log('err', 'Target URL required.'); return; }

    const cfg = {
        target,
        provider: document.getElementById('s-provider').value,
        model: document.getElementById('s-model').value,
        api_key: document.getElementById('s-apikey').value,
        mode: document.getElementById('s-mode').value,
        evolve: true,
        generations: parseInt(document.getElementById('s-gens').value) || 5,
        output_format: document.getElementById('s-format').value,
        skip_recon: document.getElementById('s-skip-recon').checked,
        recon_modules: Array.from(document.querySelectorAll('.recon-mod:checked')).map(el => el.value),
        modules: [], // Run all attack modules by default
        attacker_provider: document.getElementById('s-attacker-provider').value,
        attacker_model: document.getElementById('s-attacker-model').value,
        attacker_api_key: document.getElementById('s-attacker-key').value,
        population_size: parseInt(document.getElementById('s-pop-size').value) || 10,
        fitness_threshold: parseFloat(document.getElementById('s-fitness-threshold').value) || 0.9,
        stagnation_limit: parseInt(document.getElementById('s-stagnation').value) || 3,
    };

    btnStart.style.display = 'none';
    btnStop.style.display = 'flex';
    progressPane.style.display = 'block';
    scanBar.style.width = '0%';
    liveFindings.innerHTML = '';
    allFindings = [];
    scanning = true;
    scanDot.classList.remove('hidden');
    scanPill.className = `mode-pill ${cfg.mode}`;
    scanPill.innerText = cfg.mode.toUpperCase();
    startTimer();
    log('inf', `Starting ${cfg.mode} scan → ${target}`);

    const res = await apiFetch('/api/scan', { method: 'POST', body: JSON.stringify(cfg) });
    if (res.session_id) {
        currentSession = res.session_id;
        log('ok', `Session: ${currentSession}`);
        toast('ok', `Scan started successfully! (Session: ${currentSession.slice(0, 8)})`);
        pollScan();
    } else {
        log('err', `Scan failed: ${res.error || 'Unknown'}`);
        resetScan();
    }
});

btnStop.addEventListener('click', async () => {
    if (currentSession) {
        await apiFetch(`/api/scan/${currentSession}/stop`, { method: 'POST' });
        log('inf', 'Scan stopped.');
        toast('inf', 'Scan stopped by user.');
        resetScan();
    }
});

window.toggleReconDetails = () => {
    const el = document.getElementById('recon-details');
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
};

window.toggleAttackerDetails = () => {
    const el = document.getElementById('attacker-details');
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
};

function resetScan() {
    btnStart.style.display = 'flex';
    btnStop.style.display = 'none';
    scanning = false;
    stopTimer();
    scanDot.classList.add('hidden');
}

async function pollScan() {
    if (!scanning || !currentSession) return;
    const st = await apiFetch(`/api/scan/${currentSession}`);
    if (st.error) { setTimeout(pollScan, 3000); return; }

    if (st.findings_count !== undefined) {
        liveCount.innerText = `${st.findings_count} detected`;
        document.getElementById('k-findings').innerText = st.findings_count;
    }

    if (st.findings) {
        st.findings.forEach(f => {
            if (!allFindings.find(x => x.title === f.title && x.attack_module === f.attack_module)) {
                allFindings.push(f);
                addFinding(liveFindings, f);
                addFinding(document.getElementById('dash-findings'), f);
                log('err', `VULN [${f.severity}] ${f.title}`);
            }
        });
        updateSev();
        updateTable();
    }

    if (st.status === 'complete' || st.status === 'completed') {
        scanBar.style.width = '100%';
        log('ok', `Done. ${allFindings.length} findings.`);
        resetScan();
        const p = document.getElementById('k-posture');
        if (allFindings.length === 0) { p.innerText = 'SECURE'; p.className = 'kpi-value safe'; }
        else {
            const crit = allFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
            p.innerText = crit ? 'COMPROMISED' : 'AT RISK';
            p.className = `kpi-value ${crit ? 'danger' : 'warn'}`;
        }
        return;
    }

    if (st.status?.startsWith('attacking:')) scanPhase.innerText = st.status.split(':')[1];
    setTimeout(pollScan, 2000);
}

// ── Finding Card ──
function addFinding(container, f) {
    if (container.querySelector('.empty-msg')) container.innerHTML = '';
    const sev = f.severity || 'MEDIUM';
    const el = document.createElement('div');
    el.className = `fc ${sev}`;
    el.dataset.severity = sev;
    el.innerHTML = `
        <div class="fc-top"><span class="fc-name">${esc(f.title || f.type || 'Finding')}</span><div class="fc-tags"><span class="badge-owasp">${esc(f.owasp_id || f.category || '')}</span><span class="badge-sev ${sev}">${sev}</span></div></div>
        <div class="fc-desc">${esc(f.description || '')}</div>
        ${f.payload ? `<div class="fc-payload">${esc(trunc(f.payload, 200))}</div>` : ''}
        ${f.confidence !== undefined ? `<div class="fc-conf">Confidence: ${(f.confidence * 100).toFixed(0)}%</div>` : ''}
    `;
    container.insertBefore(el, container.firstChild);
}

// ── Severity Counts ──
function updateSev() {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    allFindings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
    document.getElementById('sc-crit').innerText = c.CRITICAL;
    document.getElementById('sc-high').innerText = c.HIGH;
    document.getElementById('sc-med').innerText = c.MEDIUM;
    document.getElementById('sc-low').innerText = c.LOW;
    const b = document.getElementById('b-findings');
    if (allFindings.length > 0) { b.innerText = allFindings.length; b.classList.remove('hidden'); }
}

// ── Findings Table ──
function updateTable() {
    const tb = document.getElementById('find-tbody');
    tb.innerHTML = '';
    if (!allFindings.length) { tb.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-3);padding:24px">No findings.</td></tr>'; return; }
    allFindings.forEach(f => {
        const tr = document.createElement('tr');
        tr.dataset.severity = f.severity;
        tr.innerHTML = `<td><span class="badge-sev ${f.severity}">${f.severity}</span></td><td><span class="badge-owasp">${esc(f.owasp_id || f.category || '—')}</span></td><td>${esc(f.attack_module || '—')}</td><td style="color:var(--text-1)">${esc(f.title || '—')}</td><td>${f.confidence ? `${(f.confidence * 100).toFixed(0)}%` : '—'}</td>`;
        tb.appendChild(tr);
    });
}

// ── Filters ──
document.querySelectorAll('.filters').forEach(bar => {
    bar.querySelectorAll('.fbtn').forEach(btn => {
        btn.addEventListener('click', () => {
            bar.querySelectorAll('.fbtn').forEach(b => b.classList.remove('on'));
            btn.classList.add('on');
            const sev = btn.dataset.sev;
            const container = bar.closest('.pane')?.querySelector('.pane-body, tbody');
            if (!container) return;
            container.querySelectorAll('.fc, tr[data-severity]').forEach(el => {
                el.style.display = sev === 'all' ? '' : (el.dataset.severity === sev ? '' : 'none');
            });
        });
    });
});

// ── Modules ──
async function loadModules() {
    const grid = document.getElementById('mod-grid');
    if (!grid) return;
    grid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding: 20px;">Loading modules...</div>';

    // 1. Load Attack Modules
    let moduleList = [];
    try {
        const data = await apiFetch('/api/modules');
        if (data && data.modules) {
            moduleList = data.modules.map(m => ({
                name: m.name, cat: m.category, owasp: m.owasp_id || '', desc: m.description
            }));
        }
    } catch (e) {
        console.error('Failed to load modules:', e);
        grid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; color: var(--danger);">Failed to load modules.</div>';
    }

    if (moduleList.length) {
        grid.innerHTML = '';
        moduleList.forEach(m => {
            const el = document.createElement('div');
            el.className = 'mod-card';
            el.innerHTML = `<div class="mod-top"><span class="mod-name">${esc(m.name)}</span><span class="badge-owasp">${esc(m.owasp)}</span></div><div class="mod-cat">${esc(m.cat)}</div><div class="mod-desc">${esc(m.desc)}</div>`;
            el.addEventListener('click', () => {
                const existing = el.querySelector('.mod-detail');
                if (existing) { existing.remove(); return; }
                const detail = document.createElement('div');
                detail.className = 'mod-detail';
                detail.style.cssText = 'margin-top:8px;padding:8px 10px;background:var(--bg-surface);border-radius:4px;font-size:11px;color:var(--text-2);border:1px solid var(--border)';
                detail.innerHTML = `<div style="margin-bottom:4px;color:var(--text-1);font-weight:600">Category: ${esc(m.cat)}</div><div>OWASP ID: <span class="badge-owasp">${esc(m.owasp)}</span></div><div style="margin-top:4px">${esc(m.desc)}</div>`;
                el.appendChild(detail);
            });
            grid.appendChild(el);
        });
        document.getElementById('k-modules').innerText = moduleList.length;
        const countLabel = document.getElementById('mod-count-label');
        if (countLabel) countLabel.innerText = moduleList.length;
    }

    // 2. Load Mutation Operators
    const mg = document.getElementById('mut-grid');
    if (mg) {
        mg.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding: 20px;">Loading mutations...</div>';
        try {
            const data = await apiFetch('/api/mutations');
            if (data && data.mutations) {
                mg.innerHTML = '';
                data.mutations.forEach(m => {
                    const el = document.createElement('div');
                    el.className = 'mod-card';
                    el.innerHTML = `<div class="mod-top"><span class="mod-name">${esc(m.name)}</span><span class="badge-sev LOW">${esc(m.lang || 'Go')}</span></div><div class="mod-desc">${esc(m.description)}</div>`;
                    mg.appendChild(el);
                });
            }
        } catch (e) {
            console.error('Failed to load mutations:', e);
            mg.innerHTML = '<div style="grid-column: 1/-1; text-align:center; color: var(--danger);">Failed to load mutations.</div>';
        }
    }

    // 3. Load Multi-turn data alongside modules
    loadMultiturnModules();
}

// ── Multi-turn Module Breakdown ──
let mtLoaded = false;
async function loadMultiturnModules() {
    if (mtLoaded) return;
    try {
        const data = await apiFetch('/api/modules/multiturn');
        if (data.error) return;
        mtLoaded = true;

        // Update KPI counts
        const safe = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
        if (data.cultivation) safe('mt-cultivation-count', data.cultivation.total_scenarios || 0);
        if (data.authority_escalation) safe('mt-authority-count', data.authority_escalation.total_sequences || 0);
        if (data.sycophancy) safe('mt-sycophancy-count', data.sycophancy.total_sequences || 0);

        // Scenario/Sequence list
        const sl = document.getElementById('mt-scenario-list');
        if (sl) {
            sl.innerHTML = '';
            const sections = [
                { label: 'Cultivation', items: data.cultivation?.scenarios || [], color: 'var(--accent)' },
                { label: 'Authority Escalation', items: data.authority_escalation?.sequences || [], color: '#ef4444' },
                { label: 'Sycophancy', items: data.sycophancy?.sequences || [], color: '#eab308' },
            ];
            sections.forEach(sec => {
                const h = document.createElement('div');
                h.style.cssText = `padding:8px 12px;font-size:11px;font-weight:600;color:${sec.color};border-bottom:1px solid var(--border);background:rgba(0,0,0,0.1)`;
                h.innerText = `${sec.label} (${sec.items.length})`;
                sl.appendChild(h);
                sec.items.forEach(name => {
                    const r = document.createElement('div');
                    r.style.cssText = 'padding:4px 12px 4px 20px;font-size:10px;color:var(--text-2);border-bottom:1px solid var(--border)';
                    r.innerText = name;
                    sl.appendChild(r);
                });
            });
        }

        // Feature matrix
        const fl = document.getElementById('mt-feature-list');
        if (fl) {
            fl.innerHTML = '';
            const allFeatures = {};
            ['cultivation', 'authority_escalation', 'sycophancy'].forEach(mod => {
                if (data[mod]?.features) {
                    data[mod].features.forEach(f => {
                        if (!allFeatures[f]) allFeatures[f] = [];
                        allFeatures[f].push(mod);
                    });
                }
            });
            const tbl = document.createElement('table');
            tbl.className = 'tbl';
            tbl.innerHTML = `<thead><tr><th>Feature</th><th>Cult</th><th>Auth</th><th>Syco</th></tr></thead>
                <tbody>${Object.entries(allFeatures).map(([feat, mods]) => `<tr>
                    <td style="font-size:10px;color:var(--text-1)">${esc(feat.replace(/_/g, ' '))}</td>
                    <td>${mods.includes('cultivation') ? '<span style="color:var(--safe)">\u2713</span>' : '<span style="color:var(--text-3)">\u2014</span>'}</td>
                    <td>${mods.includes('authority_escalation') ? '<span style="color:var(--safe)">\u2713</span>' : '<span style="color:var(--text-3)">\u2014</span>'}</td>
                    <td>${mods.includes('sycophancy') ? '<span style="color:var(--safe)">\u2713</span>' : '<span style="color:var(--text-3)">\u2014</span>'}</td>
                </tr>`).join('')}</tbody>`;
            fl.appendChild(tbl);
        }
    } catch (e) {
        console.error('Failed to load multiturn data:', e);
    }
}

// ── Evolution Engine Operators ──
let evoLoaded = false;
async function loadEvolutionOperators() {
    if (evoLoaded) return;
    try {
        const data = await apiFetch('/api/evolution/operators');
        if (data.error) return;
        evoLoaded = true;

        // Vocabulary KPIs
        const safe = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
        safe('evo-vocab', data.metaphor_vocabulary_size);
        safe('evo-openers', data.opener_variants);
        safe('evo-closers', data.closer_variants);

        // Feature tags
        const fc = document.getElementById('evo-features');
        if (fc && data.features) {
            fc.innerHTML = '';
            data.features.forEach(f => {
                const tag = document.createElement('span');
                tag.className = 'badge-sev LOW';
                tag.style.cssText = 'margin:2px 4px;display:inline-block;font-size:10px';
                tag.innerText = f.replace(/_/g, ' ');
                fc.appendChild(tag);
            });
        }
    } catch (e) {
        console.error('Failed to load evolution operators:', e);
    }
}

// Module search
document.getElementById('mod-search')?.addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('#mod-grid .mod-card').forEach(c => {
        c.style.display = c.innerText.toLowerCase().includes(q) ? '' : 'none';
    });
});

// ── Sessions ──
async function loadSessions() {
    const data = await apiFetch('/api/sessions');
    const list = document.getElementById('sess-list');
    list.innerHTML = '';
    if (!data.sessions?.length) { list.innerHTML = '<div class="empty-msg">No sessions.</div>'; return; }
    const b = document.getElementById('b-sessions');
    b.innerText = data.sessions.length; b.classList.remove('hidden');
    document.getElementById('k-scans').innerText = data.sessions.length;

    // Also populate Reports session dropdown
    const rptSel = document.getElementById('rpt-sess');
    if (rptSel) {
        rptSel.innerHTML = '<option value="">Select…</option>';
        data.sessions.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.id;
            opt.innerText = `${s.target || s.id.slice(0, 12)} (${s.status})`;
            rptSel.appendChild(opt);
        });
    }

    data.sessions.forEach(s => {
        const el = document.createElement('div');
        el.className = 'sess-item';
        el.innerHTML = `<div class="sess-target">${esc(s.target || s.id?.slice(0, 16))}</div><div class="sess-meta"><span class="badge-sev ${s.status === 'completed' ? 'LOW' : 'MEDIUM'}">${s.status}</span>${s.total_findings ? `<span>${s.total_findings} findings</span>` : ''}</div>`;
        el.addEventListener('click', () => loadSessionDetail(s.id, el));
        list.appendChild(el);
    });
}

async function loadSessionDetail(id, el) {
    const data = await apiFetch(`/api/sessions/${id}`);
    const det = document.getElementById('sess-detail');
    det.innerHTML = '';
    document.querySelectorAll('.sess-item').forEach(i => i.classList.remove('active'));
    el?.classList.add('active');
    if (!data.findings?.length) { det.innerHTML = '<div class="empty-msg">No findings.</div>'; return; }
    const tbl = document.createElement('table');
    tbl.className = 'tbl';
    tbl.innerHTML = `<thead><tr><th>Severity</th><th>Module</th><th>Title</th><th>Conf</th></tr></thead><tbody>${data.findings.map(f => `<tr><td><span class="badge-sev ${f.severity}">${f.severity}</span></td><td style="font-size:10px">${esc(f.attack_module || '—')}</td><td style="color:var(--text-1)">${esc(f.title)}</td><td>${f.confidence ? `${(f.confidence * 100).toFixed(0)}%` : '—'}</td></tr>`).join('')}</tbody>`;
    det.appendChild(tbl);
}

document.getElementById('btn-refresh-sess')?.addEventListener('click', loadSessions);

// ── Native Status ──
async function loadNative() {
    const d = await apiFetch('/api/native/status');
    if (d.error) return;
    const map = { fuzzer_go: 'ns-fuzzer', matcher_go: 'ns-matcher', tokens_c: 'ns-tokens', encoder_c: 'ns-encoder' };
    Object.entries(map).forEach(([k, id]) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (d[k]) { el.innerText = 'LOADED'; el.className = 'native-val ok'; }
        else { el.innerText = 'FALLBACK'; el.className = 'native-val fb'; }
    });
    const loaded = Object.values(d).filter(Boolean).length;
    log(loaded > 0 ? 'ok' : 'dim', `Native: ${loaded}/${Object.keys(d).length} loaded`);
}

// ── API Keys ──
window.saveKey = async function (prov) {
    const inp = document.getElementById(`key-${prov}`);
    if (!inp) return;
    const res = await apiFetch('/api/settings/apikey', { method: 'POST', body: JSON.stringify({ provider: prov, key: inp.value }) });
    if (!res.error) {
        log('ok', `Key saved: ${prov}`);
        toast('ok', `${prov.toUpperCase()} API key saved.`);
    }
};

// ── Reports ──
document.getElementById('btn-gen-report')?.addEventListener('click', async () => {
    const sid = document.getElementById('rpt-sess')?.value;
    const fmt = document.getElementById('rpt-fmt')?.value;
    if (!sid) { log('err', 'Select a session first.'); return; }
    log('inf', `Generating ${fmt} report…`);
    if (window.basilisk?.report) {
        const r = await window.basilisk.report.export(sid, fmt);
        if (r.path) {
            log('ok', `Exported: ${r.path}`);
            toast('ok', `Report exported to ${r.path}`);
        }
    } else {
        const r = await apiFetch(`/api/report/${sid}`, { method: 'POST', body: JSON.stringify({ format: fmt, open_browser: true }) });
        if (r.path) {
            log('ok', `Generated: ${r.path}`);
            toast('ok', `Report generated and opening in browser...`);
        }
    }
});

// ── Differential Scan ──
let diffTargetCount = 2;

document.getElementById('btn-diff-add')?.addEventListener('click', () => {
    const container = document.getElementById('diff-targets');
    const idx = diffTargetCount++;
    const row = document.createElement('div');
    row.className = 'diff-target-row';
    row.dataset.idx = idx;
    row.innerHTML = `
        <select class="sel" id="diff-prov-${idx}" style="width:130px">
            <option value="openai">OpenAI</option><option value="anthropic">Anthropic</option>
            <option value="google" ${idx === 2 ? 'selected' : ''}>Google</option><option value="azure">Azure</option><option value="ollama">Ollama</option>
        </select>
        <input class="inp" id="diff-model-${idx}" placeholder="${idx === 2 ? 'gemini/gemini-2.0-flash' : ''}" style="flex:1">
        <button class="btn ghost sm" onclick="this.parentElement.remove()">✗</button>
    `;
    container.appendChild(row);
});

document.getElementById('btn-diff-start')?.addEventListener('click', async () => {
    const rows = document.querySelectorAll('.diff-target-row');
    const targets = [];
    rows.forEach(row => {
        const idx = row.dataset.idx;
        const prov = document.getElementById(`diff-prov-${idx}`)?.value;
        const model = document.getElementById(`diff-model-${idx}`)?.value || '';
        if (prov) targets.push({ provider: prov, model, api_key: '' });
    });

    if (targets.length < 2) {
        log('err', 'Need at least 2 targets for differential scan.');
        return;
    }

    const btn = document.getElementById('btn-diff-start');
    btn.disabled = true;
    btn.innerText = 'Scanning…';
    log('inf', `Starting differential scan across ${targets.length} models…`);

    try {
        const result = await apiFetch('/api/diff', {
            method: 'POST',
            body: JSON.stringify({ targets, categories: [] }),
        });

        const container = document.getElementById('diff-results');
        const summary = document.getElementById('diff-summary');

        if (result.error) {
            container.innerHTML = `<div class="empty-msg" style="color:var(--danger)">${esc(result.error)}</div>`;
            log('err', result.error);
            return;
        }

        summary.innerText = `${result.total_divergences} divergences / ${result.total_probes} probes (${result.divergence_rate})`;

        const tbl = document.createElement('table');
        tbl.className = 'tbl';
        tbl.innerHTML = `<thead><tr><th>Category</th><th>Probe</th><th>Divergence</th><th style="color:var(--danger)">Vulnerable</th><th style="color:var(--safe)">Resistant</th></tr></thead><tbody>
            ${(result.probes || []).map(p => `<tr>
                <td style="font-size:10px">${esc(p.category)}</td>
                <td style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.probe.slice(0, 60))}</td>
                <td><span class="badge-sev ${p.has_divergence ? 'CRITICAL' : 'INFO'}">${p.has_divergence ? 'YES' : 'no'}</span></td>
                <td style="font-size:10px;color:var(--danger)">${p.vulnerable_models?.join(', ') || '—'}</td>
                <td style="font-size:10px;color:var(--safe)">${p.resistant_models?.join(', ') || '—'}</td>
            </tr>`).join('')}</tbody>`;
        container.innerHTML = '';
        container.appendChild(tbl);

        log('ok', `Differential scan complete: ${result.total_divergences} divergences found`);
    } catch (e) {
        log('err', `Diff scan failed: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3" /></svg>Run Differential';
    }
});

// ── Posture Scan ──
document.getElementById('btn-posture-start')?.addEventListener('click', async () => {
    const provider = document.getElementById('post-provider')?.value || 'openai';
    const model = document.getElementById('post-model')?.value || '';

    const btn = document.getElementById('btn-posture-start');
    btn.disabled = true;
    btn.innerText = 'Scanning…';
    log('inf', `Running posture scan: ${provider}/${model || 'default'}…`);

    try {
        const result = await apiFetch('/api/posture', {
            method: 'POST',
            body: JSON.stringify({ target: '', provider, model, api_key: '' }),
        });

        if (result.error) {
            log('err', result.error);
            return;
        }

        // Update grade
        const gradeEl = document.getElementById('posture-grade');
        const scoreEl = document.getElementById('posture-score');
        const kPosture = document.getElementById('k-posture');
        const gradeColors = { 'A+': '#22c55e', 'A': '#22c55e', 'B': '#3b82f6', 'C': '#eab308', 'D': '#ef4444', 'F': '#dc2626' };
        gradeEl.innerText = result.overall_grade || '—';
        gradeEl.style.color = gradeColors[result.overall_grade] || 'var(--text-3)';
        scoreEl.innerText = `${(result.overall_score * 100).toFixed(0)}% coverage`;
        if (kPosture) { kPosture.innerText = result.overall_grade; kPosture.style.color = gradeColors[result.overall_grade]; }

        // Category table
        const container = document.getElementById('posture-results');
        const strengthColors = { none: 'CRITICAL', weak: 'HIGH', moderate: 'MEDIUM', strong: 'LOW', aggressive: 'INFO' };
        const tbl = document.createElement('table');
        tbl.className = 'tbl';
        tbl.innerHTML = `<thead><tr><th>Category</th><th>Strength</th><th>Score</th><th>Benign OK</th><th>Mod Block</th><th>Adv Block</th></tr></thead><tbody>
            ${(result.categories || []).map(c => `<tr>
                <td style="color:var(--text-1)">${esc(c.name)}</td>
                <td><span class="badge-sev ${strengthColors[c.strength] || 'INFO'}">${c.strength.toUpperCase()}</span></td>
                <td>${(c.score * 100).toFixed(0)}%</td>
                <td>${c.benign_allowed ? '✓' : '✗'}</td>
                <td>${c.moderate_blocked ? '✓' : '✗'}</td>
                <td>${c.adversarial_blocked ? '✓' : '✗'}</td>
            </tr>`).join('')}</tbody>`;
        container.innerHTML = '';
        container.appendChild(tbl);

        // Recommendations
        if (result.recommendations?.length) {
            const recs = document.createElement('div');
            recs.style.cssText = 'padding:12px 16px;font-size:11px;color:var(--text-2);border-top:1px solid var(--border)';
            recs.innerHTML = '<div style="font-weight:600;margin-bottom:6px;color:var(--text-1)">📋 Recommendations</div>' +
                result.recommendations.map(r => `<div style="margin-bottom:4px">• ${esc(r)}</div>`).join('');
            container.appendChild(recs);
        }

        log('ok', `Posture scan complete: Grade ${result.overall_grade} (${(result.overall_score * 100).toFixed(0)}%)`);
    } catch (e) {
        log('err', `Posture scan failed: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>Run Posture Scan';
    }
});

// ── Audit Log ──
document.getElementById('btn-audit-load')?.addEventListener('click', async () => {
    const sessionId = document.getElementById('audit-session')?.value?.trim();
    if (!sessionId) { log('err', 'Enter a session ID.'); return; }

    try {
        const result = await apiFetch(`/api/audit/${sessionId}`);
        const container = document.getElementById('audit-log');
        const integrity = document.getElementById('audit-integrity');

        if (result.error) {
            container.innerHTML = `<div class="empty-msg" style="color:var(--danger)">${esc(result.error)}</div>`;
            return;
        }

        container.innerHTML = '';
        const entries = result.entries || [];
        const eventColors = {
            session_start: 'dim', scan_config: 'dim', prompt_sent: 'inf',
            response_received: 'dim', finding_discovered: 'ok', evolution_generation: 'inf',
            error: 'err', report_generated: 'ok', session_end: 'dim',
        };

        entries.forEach(entry => {
            const el = document.createElement('div');
            const cls = eventColors[entry.event] || 'dim';
            el.className = `ll ${cls}`;
            const t = entry.timestamp?.slice(11, 19) || '';
            let detail = '';
            if (entry.event === 'finding_discovered') {
                detail = `[${entry.data?.severity}] ${entry.data?.title || ''}`;
            } else if (entry.event === 'prompt_sent') {
                detail = `${entry.data?.module} → ${entry.data?.provider}/${entry.data?.model}`;
            } else if (entry.event === 'error') {
                detail = `${entry.data?.module}: ${entry.data?.error?.slice(0, 80)}`;
            } else if (entry.event === 'evolution_generation') {
                detail = `Gen ${entry.data?.generation} best=${entry.data?.best_fitness} breakthroughs=${entry.data?.breakthroughs}`;
            } else {
                detail = JSON.stringify(entry.data || {}).slice(0, 100);
            }
            el.innerText = `[${t}] ${entry.event}: ${detail}`;
            container.appendChild(el);
        });

        integrity.innerText = `${entries.length} entries | File: ${result.path || '?'} | Chain integrity: SHA-256 checksummed`;
        log('ok', `Loaded ${entries.length} audit entries for session ${sessionId}`);
    } catch (e) {
        log('err', `Audit load failed: ${e.message}`);
    }
});

// ── Clear Log ──
document.getElementById('btn-clear-log')?.addEventListener('click', () => {
    const l = document.getElementById('full-log');
    if (l) l.innerHTML = '<div class="ll dim">[system] Log cleared</div>';
});

// ── Keyboard Shortcuts ──
document.addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey) {
        const map = { '1': 'dashboard', '2': 'scan', '3': 'sessions', '4': 'modules', '5': 'evolution', '6': 'findings', '7': 'diff', '8': 'posture' };
        if (map[e.key]) { document.querySelector(`[data-v="${map[e.key]}"]`)?.click(); e.preventDefault(); }
    }
});

// ── Backend log forwarding (from main process) ──
if (window.basilisk?.onBackendLog) {
    window.basilisk.onBackendLog(msg => log('dim', msg.trim()));
}
if (window.basilisk?.onBackendError) {
    window.basilisk.onBackendError(msg => log('err', `Backend: ${msg}`));
}

// ── Init ──
loadModules();
loadMultiturnModules();
loadEvolutionOperators();
log('inf', 'Basilisk Desktop initialized.');
