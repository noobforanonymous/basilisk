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
        if (t.dataset.v === 'modules') loadModules();
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
}

async function apiFetch(path, opts = {}) {
    try {
        const r = await fetch(`${BRIDGE}${path}`, { headers: { 'Content-Type': 'application/json' }, ...opts });
        return await r.json();
    } catch (e) {
        log('err', `API: ${e.message}`);
        return { error: e.message };
    }
}

// ── Backend Connection ──
const connDot = document.getElementById('conn-dot');
const connLabel = document.getElementById('conn-label');

async function checkBackend() {
    try {
        const r = await fetch(`${BRIDGE}/health`);
        if (r.ok) {
            connDot.classList.add('on');
            connDot.classList.remove('err');
            connLabel.innerText = 'Connected';
            log('ok', 'Backend connected.');
            return true;
        }
    } catch { }
    connDot.classList.remove('on');
    connDot.classList.add('err');
    connLabel.innerText = 'Offline';
    return false;
}

let poll = setInterval(async () => {
    if (await checkBackend()) {
        clearInterval(poll);
        loadNative();
        loadModules();
        connectWebSocket();
    }
}, 2000);
checkBackend();

// ── WebSocket for real-time scan events ──
let ws = null;
let wsRetries = 0;

function connectWebSocket() {
    if (wsRetries >= 5) return;
    try {
        ws = new WebSocket('ws://127.0.0.1:8741/ws');
        ws.onopen = () => { wsRetries = 0; log('ok', 'WebSocket connected.'); };
        ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
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
        resetScan();
    }
});

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
const MODULES = [
    { name: 'Direct Injection', cat: 'Injection', owasp: 'LLM01', desc: 'Direct prompt override and instruction hijacking' },
    { name: 'Indirect Injection', cat: 'Injection', owasp: 'LLM01', desc: 'Embedded instructions in external data sources' },
    { name: 'Multilingual Injection', cat: 'Injection', owasp: 'LLM01', desc: 'Cross-language payload delivery in 12+ languages' },
    { name: 'Encoding Injection', cat: 'Injection', owasp: 'LLM01', desc: 'Base64, hex, ROT13, and Unicode encoding attacks' },
    { name: 'Split Payload', cat: 'Injection', owasp: 'LLM01', desc: 'Multi-turn distributed injection sequences' },
    { name: 'Role Confusion', cat: 'Extraction', owasp: 'LLM07', desc: 'System prompt extraction via identity confusion' },
    { name: 'Translation', cat: 'Extraction', owasp: 'LLM07', desc: 'System prompt leak via translation requests' },
    { name: 'Simulation', cat: 'Extraction', owasp: 'LLM07', desc: 'Debug/diagnostic mode pretexts' },
    { name: 'Gradient Walk', cat: 'Extraction', owasp: 'LLM07', desc: '8-step escalation from benign to adversarial' },
    { name: 'Training Data', cat: 'Exfiltration', owasp: 'LLM06', desc: 'Memorized PII, credentials, API key extraction' },
    { name: 'RAG Data', cat: 'Exfiltration', owasp: 'LLM06', desc: 'Knowledge base document leakage' },
    { name: 'Tool Schema', cat: 'Exfiltration', owasp: 'LLM06', desc: 'Tool config and endpoint extraction' },
    { name: 'SSRF', cat: 'Tool Abuse', owasp: 'LLM08', desc: 'Server-side request forgery via AI tools' },
    { name: 'SQLi', cat: 'Tool Abuse', owasp: 'LLM08', desc: 'SQL injection through AI-generated queries' },
    { name: 'Command Injection', cat: 'Tool Abuse', owasp: 'LLM08', desc: 'OS command injection via code execution tools' },
    { name: 'Chained Abuse', cat: 'Tool Abuse', owasp: 'LLM08', desc: 'Multi-step tool chain privilege escalation' },
    { name: 'Roleplay Bypass', cat: 'Guardrails', owasp: 'LLM09', desc: 'DAN-style persona injection attacks' },
    { name: 'Encoding Bypass', cat: 'Guardrails', owasp: 'LLM09', desc: 'Encoded content to evade safety filters' },
    { name: 'Logic Trap', cat: 'Guardrails', owasp: 'LLM09', desc: 'Paradox and coercion-based bypass' },
    { name: 'Token Flood', cat: 'DoS', owasp: 'LLM04', desc: 'Context window exhaustion and token amplification' },
    { name: 'Recursive Expansion', cat: 'DoS', owasp: 'LLM04', desc: 'Self-referential prompts for resource exhaustion' },
    { name: 'Regex Bomb', cat: 'DoS', owasp: 'LLM04', desc: 'Catastrophic backtracking in regex-based filters' },
    { name: 'Infinite Loop', cat: 'DoS', owasp: 'LLM04', desc: 'Agent loop triggers and recursive tool calls' },
    { name: 'Authority Escalation', cat: 'Multi-Turn', owasp: 'LLM02', desc: 'Progressive trust building across conversations' },
    { name: 'Memory Injection', cat: 'Multi-Turn', owasp: 'LLM02', desc: 'Persistent context poisoning attacks' },
    { name: 'Context Confusion', cat: 'Multi-Turn', owasp: 'LLM02', desc: 'Cross-conversation context manipulation' },
    { name: 'RAG Poisoning', cat: 'RAG', owasp: 'LLM03', desc: 'Injecting malicious content into knowledge bases' },
    { name: 'RAG Override', cat: 'RAG', owasp: 'LLM03', desc: 'Priority manipulation of retrieved documents' },
    { name: 'Retrieval Hijack', cat: 'RAG', owasp: 'LLM03', desc: 'Manipulating retrieval to serve attacker content' },
];

const MUTATIONS = [
    { name: 'Homoglyph', lang: 'Go', desc: 'Unicode confusable character substitution' },
    { name: 'Zero-Width', lang: 'Go', desc: 'ZWC character injection between tokens' },
    { name: 'Base64 Wrap', lang: 'Go', desc: 'Partial payload base64 encoding' },
    { name: 'Hex Wrap', lang: 'Go', desc: 'Full hex-encoded payload wrapping' },
    { name: 'Case Alternate', lang: 'Go', desc: 'aLtErNaTiNg case for filter bypass' },
    { name: 'Token Split', lang: 'Go', desc: 'Word splitting to break tokenization' },
    { name: 'Invisible Pad', lang: 'Go', desc: 'Unicode invisible character padding' },
    { name: 'Context Pad', lang: 'Go', desc: 'Benign context wrapper injection' },
    { name: 'Reverse', lang: 'Go', desc: 'Payload reversal with decode instruction' },
    { name: 'Fragment Split', lang: 'Go', desc: 'Numbered fragment reassembly attack' },
    { name: 'Delimiter', lang: 'Go', desc: 'System instruction delimiter injection' },
];

async function loadModules() {
    const grid = document.getElementById('mod-grid');
    grid.innerHTML = '';

    // Try fetching from backend, fallback to hardcoded
    let moduleList = MODULES;
    try {
        const data = await apiFetch('/api/modules');
        if (data.modules?.length) {
            moduleList = data.modules.map(m => ({
                name: m.name, cat: m.category, owasp: m.owasp_id || '', desc: m.description
            }));
        }
    } catch { }

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

    // Mutation grid
    const mg = document.getElementById('mut-grid');
    if (mg) {
        mg.innerHTML = '';
        MUTATIONS.forEach(m => {
            const el = document.createElement('div');
            el.className = 'mod-card';
            el.innerHTML = `<div class="mod-top"><span class="mod-name">${esc(m.name)}</span><span class="badge-sev LOW">${esc(m.lang)}</span></div><div class="mod-desc">${esc(m.desc)}</div>`;
            mg.appendChild(el);
        });
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
    await apiFetch('/api/settings/apikey', { method: 'POST', body: JSON.stringify({ provider: prov, key: inp.value }) });
    log('ok', `Key saved: ${prov}`);
};

// ── Reports ──
document.getElementById('btn-gen-report')?.addEventListener('click', async () => {
    const sid = document.getElementById('rpt-sess')?.value;
    const fmt = document.getElementById('rpt-fmt')?.value;
    if (!sid) { log('err', 'Select a session first.'); return; }
    log('inf', `Generating ${fmt} report…`);
    if (window.basilisk?.report) {
        const r = await window.basilisk.report.export(sid, fmt);
        if (r.path) log('ok', `Exported: ${r.path}`);
    } else {
        const r = await apiFetch(`/api/report/${sid}`, { method: 'POST', body: JSON.stringify({ format: fmt }) });
        if (r.path) log('ok', `Generated: ${r.path}`);
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
        const map = { '1': 'dashboard', '2': 'scan', '3': 'sessions', '4': 'modules', '5': 'findings' };
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
log('inf', 'Basilisk Desktop initialized.');
