/**
 * Basilisk Desktop — Scan Module
 * Scan lifecycle, real-time events, findings, severity, and timer.
 */

import {
    appState,
    csvList,
    esc,
    normalizeSeverity,
    severityClass,
    setHidden,
    setProgress,
    toggleVisibility,
} from './shared.js';
import { apiFetch, log, toast } from './core.js';

const timerEl = document.getElementById('scan-timer');
const btnPreview = document.getElementById('btn-scan-preview');
const btnStart = document.getElementById('btn-scan-start');
const btnStop = document.getElementById('btn-scan-stop');
const progressPane = document.getElementById('scan-progress-pane');
const scanBar = document.getElementById('scan-bar');
const scanPhase = document.getElementById('scan-phase');
const scanPill = document.getElementById('scan-mode-pill');
const liveFindings = document.getElementById('live-findings');
const liveCount = document.getElementById('live-count');
const scanDot = document.getElementById('scan-dot');
const previewSummary = document.getElementById('scan-preview-summary');
const previewCost = document.getElementById('scan-preview-cost');

function collectScanConfig() {
    return {
        target: document.getElementById('s-target').value.trim(),
        provider: document.getElementById('s-provider').value,
        model: document.getElementById('s-model').value,
        mode: document.getElementById('s-mode').value,
        evolve: true,
        generations: parseInt(document.getElementById('s-gens').value, 10) || 5,
        output_format: document.getElementById('s-format').value,
        include_research_modules: document.getElementById('s-include-research').checked,
        skip_recon: document.getElementById('s-skip-recon').checked,
        recon_modules: Array.from(document.querySelectorAll('.recon-mod:checked')).map((el) => el.value),
        modules: [],
        probe_ids: [],
        attacker_provider: document.getElementById('s-attacker-provider').value,
        attacker_model: document.getElementById('s-attacker-model').value,
        population_size: parseInt(document.getElementById('s-pop-size').value, 10) || 10,
        fitness_threshold: parseFloat(document.getElementById('s-fitness-threshold').value) || 0.9,
        stagnation_limit: parseInt(document.getElementById('s-stagnation').value, 10) || 3,
        exit_on_first: document.getElementById('s-exit-on-first').checked,
        enable_cache: document.getElementById('s-cache').checked,
        diversity_mode: document.getElementById('s-diversity-mode').value,
        intent_weight: parseFloat(document.getElementById('s-intent-weight').value) || 0.15,
        campaign: {
            name: document.getElementById('s-campaign-name').value.trim(),
            objective: {
                name: document.getElementById('s-objective').value.trim(),
                hypothesis: document.getElementById('s-hypothesis').value.trim(),
            },
            authorization: {
                operator: document.getElementById('s-operator').value.trim(),
                ticket_id: document.getElementById('s-ticket').value.trim(),
                target_owner: document.getElementById('s-target-owner').value.trim(),
                scope_targets: csvList(document.getElementById('s-scope-targets').value),
                approved: document.getElementById('s-approval-confirmed').checked,
            },
        },
        policy: {
            execution_mode: document.getElementById('s-execution-mode').value,
            evidence_threshold: document.getElementById('s-evidence-threshold').value,
            aggression: parseInt(document.getElementById('s-aggression').value, 10) || 3,
            max_concurrency: parseInt(document.getElementById('s-max-concurrency').value, 10) || 5,
            request_budget: parseInt(document.getElementById('s-request-budget').value, 10) || 0,
            rate_limit_delay: parseFloat(document.getElementById('s-rate-limit-delay').value) || 0,
            raw_evidence_mode: document.getElementById('s-raw-evidence-mode').value,
            retain_days: parseInt(document.getElementById('s-retain-days').value, 10) || 30,
            allow_modules: csvList(document.getElementById('s-allow-modules').value),
            deny_modules: csvList(document.getElementById('s-deny-modules').value),
            dry_run: document.getElementById('s-dry-run').checked,
            approval_required: document.getElementById('s-approval-required').checked,
            approval_confirmed: document.getElementById('s-approval-confirmed').checked,
            retain_raw_findings: document.getElementById('s-retain-raw').checked,
            retain_conversations: document.getElementById('s-retain-conversations').checked,
            stop_on_severity: document.getElementById('s-stop-on-severity').value,
            isolated_environment: document.getElementById('s-isolated-environment').checked,
            allow_private_targets: document.getElementById('s-isolated-environment').checked,
            allow_insecure_http: document.getElementById('s-isolated-environment').checked,
        },
        max_findings: parseInt(document.getElementById('s-max-findings').value, 10) || 0,
    };
}

function renderCostPreview(preview) {
    const bounded = preview.bounded_by_mode_ceiling ? ' (capped by mode)' : '';
    previewSummary.innerText = `${preview.mode.toUpperCase()} â€” ${preview.module_count} modules, ${preview.probe_executions} probe executions, ${preview.estimated_requests}/${preview.request_maximum} planned requests${bounded}.`;
    const cost = preview.estimated_cost_usd === null
        ? 'USD unavailable until provider/model rates are supplied'
        : `$${Number(preview.estimated_cost_usd).toFixed(6)} USD`;
    previewCost.innerText = `${preview.estimated_input_tokens.toLocaleString()} input + ${preview.estimated_output_tokens.toLocaleString()} output tokens; ${cost}.`;
}

function updateRecon(profile) {
    const safe = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.innerText = value || '—';
    };
    safe('r-model', profile.detected_model);
    safe('r-creator', profile.provider);
    safe('r-ctx', profile.context_window ? `${profile.context_window}` : null);
    safe('r-guard', profile.guardrails?.level || 'unknown');
    safe('r-tools', profile.detected_tools ? `${profile.detected_tools.length}` : '0');
    safe('r-rag', profile.rag_detected ? 'Yes' : 'No');
}

function startTimer() {
    appState.timerStart = Date.now();
    timerEl.classList.add('on');
    appState.timerInterval = setInterval(() => {
        const seconds = Math.floor((Date.now() - appState.timerStart) / 1000);
        timerEl.innerText = `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
    }, 1000);
}

function stopTimer() {
    clearInterval(appState.timerInterval);
    appState.timerInterval = null;
    timerEl.classList.remove('on');
}

function addFinding(container, finding) {
    if (container.querySelector('.empty-msg')) container.innerHTML = '';
    const sev = normalizeSeverity(finding.severity);
    const el = document.createElement('div');
    el.className = `fc ${sev.toLowerCase()}`;
    el.dataset.severity = sev.toLowerCase();
    el.innerHTML = `
        <div class="fc-top"><span class="fc-name">${esc(finding.title || finding.type || 'Finding')}</span><div class="fc-tags"><span class="badge-owasp">${esc(finding.owasp_id || finding.category || '')}</span><span class="badge-sev ${severityClass(finding.severity)}">${severityClass(finding.severity)}</span></div></div>
        <div class="fc-desc">${esc(finding.description || '')}</div>
        ${finding.payload ? `<div class="fc-payload">${esc(String(finding.payload).slice(0, 200))}</div>` : ''}
        ${finding.confidence !== undefined ? `<div class="fc-conf">Confidence: ${(finding.confidence * 100).toFixed(0)}%</div>` : ''}
    `;
    container.insertBefore(el, container.firstChild);
}

function updateSeverityCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    appState.allFindings.forEach((finding) => {
        const key = normalizeSeverity(finding.severity).toLowerCase();
        if (counts[key] !== undefined) counts[key] += 1;
    });
    document.getElementById('sc-crit').innerText = counts.critical;
    document.getElementById('sc-high').innerText = counts.high;
    document.getElementById('sc-med').innerText = counts.medium;
    document.getElementById('sc-low').innerText = counts.low;
    const badge = document.getElementById('b-findings');
    if (appState.allFindings.length > 0) {
        badge.innerText = appState.allFindings.length;
        badge.classList.remove('hidden');
    }
}

function updateFindingsTable() {
    const tbody = document.getElementById('find-tbody');
    tbody.innerHTML = '';
    if (!appState.allFindings.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-table-cell">No findings.</td></tr>';
        return;
    }
    appState.allFindings.forEach((finding) => {
        const sev = normalizeSeverity(finding.severity);
        const tr = document.createElement('tr');
        tr.dataset.severity = sev.toLowerCase();
        tr.innerHTML = `
            <td><span class="badge-sev ${severityClass(finding.severity)}">${severityClass(finding.severity)}</span></td>
            <td><span class="badge-owasp">${esc(finding.owasp_id || finding.category || '—')}</span></td>
            <td>${esc(finding.attack_module || '—')}</td>
            <td class="table-text-primary">${esc(finding.title || '—')}</td>
            <td>${finding.confidence ? `${(finding.confidence * 100).toFixed(0)}%` : '—'}</td>
        `;
        tbody.appendChild(tr);
    });
}

function resetScan() {
    setHidden(btnStart, false);
    btnStart.classList.add('display-flex');
    setHidden(btnStop, true);
    btnStop.classList.remove('display-flex');
    appState.scanning = false;
    appState.pendingStop = false;
    stopTimer();
    scanDot.classList.add('hidden');
}

function updatePostureSummary() {
    const posture = document.getElementById('k-posture');
    if (!posture) return;
    if (appState.allFindings.length === 0) {
        posture.innerText = 'SECURE';
        posture.className = 'kpi-value safe';
        return;
    }
    const critical = appState.allFindings.some((finding) => ['CRITICAL', 'HIGH'].includes(normalizeSeverity(finding.severity)));
    posture.innerText = critical ? 'COMPROMISED' : 'AT RISK';
    posture.className = `kpi-value ${critical ? 'danger' : 'warn'}`;
}

async function pollScan() {
    if (!appState.scanning || !appState.currentSession) return;
    const status = await apiFetch(`/api/scan/${appState.currentSession}`);
    if (status.error) {
        setTimeout(pollScan, 3000);
        return;
    }

    if (status.profile) updateRecon(status.profile);

    if (status.progress && typeof status.progress.progress === 'number') {
        setProgress(scanBar, status.progress.progress * 100);
    }
    if (status.progress?.module) {
        scanPhase.innerText = status.progress.module;
    } else if (status.progress?.phase) {
        scanPhase.innerText = status.progress.phase;
    } else if (status.current_phase) {
        scanPhase.innerText = status.current_phase;
    }

    const findingsCount = status.findings_count ?? status.total_findings ?? status.summary?.total_findings;
    if (findingsCount !== undefined) {
        liveCount.innerText = `${findingsCount} detected`;
        document.getElementById('k-findings').innerText = findingsCount;
    }

    if (Array.isArray(status.findings)) {
        status.findings.forEach((finding) => {
            if (!appState.allFindings.find((existing) => existing.title === finding.title && existing.attack_module === finding.attack_module)) {
                appState.allFindings.push(finding);
                addFinding(liveFindings, finding);
                addFinding(document.getElementById('dash-findings'), finding);
                log('err', `VULN [${normalizeSeverity(finding.severity)}] ${finding.title}`);
            }
        });
        updateSeverityCounts();
        updateFindingsTable();
    }

    if (status.status === 'complete' || status.status === 'completed') {
        setProgress(scanBar, 100);
        log('ok', `Scan complete. ${findingsCount ?? appState.allFindings.length} findings.`);
        resetScan();
        updatePostureSummary();
        return;
    }
    if (status.status === 'stopped') {
        log('inf', 'Scan stopped.');
        resetScan();
        return;
    }
    if (status.status === 'error' || status.status === 'failed') {
        log('err', 'Scan failed.');
        resetScan();
        return;
    }

    if (status.status?.startsWith('attacking:')) {
        scanPhase.innerText = status.status.split(':')[1];
    }
    setTimeout(pollScan, 2000);
}

export function handleScanEvent(event, data) {
    switch (event) {
        case 'scan:status':
            log('inf', `Scan phase: ${data.phase}`);
            if (data.phase === 'evolving') {
                scanPhase.innerText = 'Smart Prompt Evolution...';
                log('inf', 'Starting AI-powered prompt evolution loop...');
            }
            break;
        case 'scan:progress':
            if (data.progress !== undefined) {
                setProgress(scanBar, data.progress * 100);
            }
            if (data.module) {
                scanPhase.innerText = data.module;
            }
            break;
        case 'scan:evolution_stats':
            if (data.stats) {
                const stats = data.stats;
                scanPhase.innerText = `Evolution Gen ${stats.generation} | Best: ${stats.best_fitness?.toFixed(2)} | BT: ${stats.breakthroughs}`;
                if (scanBar && stats.generation && stats.total_generations) {
                    setProgress(scanBar, (stats.generation / stats.total_generations) * 100);
                }
                const safe = (id, value) => {
                    const el = document.getElementById(id);
                    if (el && value !== undefined) el.innerText = value;
                };
                safe('evo-gen', stats.generation);
                safe('evo-pop', stats.population_size || stats.pop_size);
                safe('evo-fit', stats.best_fitness?.toFixed(3));
                safe('evo-mean', stats.mean_fitness?.toFixed(3));
                safe('evo-diversity', stats.diversity !== undefined ? `${(stats.diversity * 100).toFixed(0)}%` : undefined);
                safe('evo-stagnation', stats.stagnation_counter);
                safe('evo-mutrate', stats.mutation_rate !== undefined ? `${(stats.mutation_rate * 100).toFixed(0)}%` : undefined);
                safe('evo-cache-hits', stats.cache_hits);
                safe('evo-novelty', stats.novelty_score !== undefined ? stats.novelty_score.toFixed(3) : undefined);
                safe('evo-intent-drift', stats.intent_drift !== undefined ? `${(stats.intent_drift * 100).toFixed(0)}%` : undefined);
                safe('evo-saved', stats.api_calls_saved);
            }
            break;
        case 'scan:finding':
            if (data.finding && !appState.allFindings.find((existing) => existing.title === data.finding.title && existing.attack_module === data.finding.attack_module)) {
                appState.allFindings.push(data.finding);
                addFinding(document.getElementById('live-findings'), data.finding);
                addFinding(document.getElementById('dash-findings'), data.finding);
                log('err', `VULN [${normalizeSeverity(data.finding.severity)}] ${data.finding.title}`);
                updateSeverityCounts();
                updateFindingsTable();
                liveCount.innerText = `${appState.allFindings.length} detected`;
                document.getElementById('k-findings').innerText = appState.allFindings.length;
            }
            break;
        case 'scan:profile':
            if (data.profile) updateRecon(data.profile);
            break;
        case 'scan:complete':
            log('ok', `Scan complete. ${data.total_findings} findings.`);
            setProgress(scanBar, 100);
            resetScan();
            updatePostureSummary();
            break;
        case 'scan:error':
            log('err', `Scan error: ${data.error}`);
            resetScan();
            break;
        default:
            break;
    }
}

export function initScan() {
    let previewFingerprint = '';
    const invalidatePreview = () => {
        previewFingerprint = '';
        btnStart.disabled = true;
        previewSummary.innerText = 'Configuration changed. Calculate the plan again before starting.';
        previewCost.innerText = 'No target request will be sent by preview.';
    };
    document.querySelector('#v-scan .cfg-grid')?.addEventListener('input', invalidatePreview);
    document.querySelector('#v-scan .cfg-grid')?.addEventListener('change', invalidatePreview);

    btnPreview?.addEventListener('click', async () => {
        const cfg = collectScanConfig();
        if (!cfg.target) {
            log('err', 'Target URL required before calculating the plan.');
            return;
        }
        previewFingerprint = '';
        btnStart.disabled = true;
        btnPreview.disabled = true;
        try {
            const result = await apiFetch('/api/scan/preview', { method: 'POST', body: cfg });
            if (!result.preview) {
                throw new Error(result.error || result.detail?.error || 'Unable to calculate scan plan');
            }
            renderCostPreview(result.preview);
            previewFingerprint = JSON.stringify(cfg);
            btnStart.disabled = false;
            log('ok', `Preflight ready: ${result.preview.estimated_requests}/${result.preview.request_maximum} planned requests.`);
        } catch (error) {
            previewFingerprint = '';
            btnStart.disabled = true;
            log('err', `Cost preview failed: ${error.message || 'Unknown error'}`);
        } finally {
            btnPreview.disabled = false;
        }
    });

    btnStart?.addEventListener('click', async () => {
        const cfg = collectScanConfig();
        const target = cfg.target;
        if (!target) {
            log('err', 'Target URL required.');
            return;
        }
        if (!previewFingerprint || previewFingerprint !== JSON.stringify(cfg)) {
            invalidatePreview();
            log('err', 'Calculate the current scan plan before starting.');
            return;
        }
        previewFingerprint = '';
        btnStart.disabled = true;

        const provider = cfg.provider;
        const inlineKey = document.getElementById('s-apikey').value;
        if (inlineKey) {
            const saved = await apiFetch('/api/settings/apikey', { method: 'POST', body: { provider, key: inlineKey } });
            if (saved.error) {
                log('err', `Unable to store API key securely: ${saved.error}`);
                return;
            }
            document.getElementById('s-apikey').value = '';
        }
        const attackerProvider = cfg.attacker_provider;
        const attackerKey = document.getElementById('s-attacker-key').value;
        if (attackerKey && attackerProvider) {
            const saved = await apiFetch('/api/settings/apikey', { method: 'POST', body: { provider: attackerProvider, key: attackerKey } });
            if (saved.error) {
                log('err', `Unable to store attacker API key securely: ${saved.error}`);
                return;
            }
            document.getElementById('s-attacker-key').value = '';
        }

        setHidden(btnStart, true);
        setHidden(btnStop, false);
        btnStop.classList.add('display-flex');
        setHidden(progressPane, false);
        appState.currentSession = null;
        appState.pendingStop = false;
        appState.allFindings = [];
        liveFindings.innerHTML = '';
        liveFindings.innerHTML = '<div class="empty-msg">Findings appear here during scan.</div>';
        setProgress(scanBar, 0);
        appState.scanning = true;
        scanDot.classList.remove('hidden');
        scanPill.className = `mode-pill ${cfg.mode}`;
        scanPill.innerText = cfg.mode.toUpperCase();
        const governance = document.getElementById('scan-governance');
        if (governance) {
            const ticket = cfg.campaign.authorization.ticket_id || 'no-ticket';
            const operator = cfg.campaign.authorization.operator || 'unassigned';
            governance.innerText = `${cfg.policy.execution_mode} | ${cfg.policy.evidence_threshold} evidence | retain ${cfg.policy.retain_days}d | ${operator} | ${ticket}`;
        }
        startTimer();
        log('inf', `Starting ${cfg.mode} scan → ${target}`);

        const result = await apiFetch('/api/scan', { method: 'POST', body: cfg });
        if (result.session_id) {
            appState.currentSession = result.session_id;
            log('ok', `Session: ${appState.currentSession}`);
            toast('ok', `Scan started successfully! (Session: ${appState.currentSession.slice(0, 8)})`);
            if (appState.pendingStop) {
                await apiFetch(`/api/scan/${appState.currentSession}/stop`, { method: 'POST' });
                appState.pendingStop = false;
                log('inf', 'Scan stopped.');
                toast('inf', 'Scan stopped by user.');
                resetScan();
                return;
            }
            pollScan();
        } else {
            log('err', `Scan failed: ${result.error || 'Unknown'}`);
            resetScan();
        }
    });

    btnStop?.addEventListener('click', async () => {
        if (appState.currentSession) {
            await apiFetch(`/api/scan/${appState.currentSession}/stop`, { method: 'POST' });
            log('inf', 'Scan stopped.');
            toast('inf', 'Scan stopped by user.');
            resetScan();
        } else if (appState.scanning) {
            appState.pendingStop = true;
            log('inf', 'Stop requested. Waiting for scan session to initialize...');
        }
    });

    document.getElementById('btn-toggle-recon')?.addEventListener('click', () => {
        toggleVisibility(document.getElementById('recon-details'), 'display-block');
    });
    document.getElementById('btn-toggle-attacker')?.addEventListener('click', () => {
        toggleVisibility(document.getElementById('attacker-details'), 'display-block');
    });

    document.querySelectorAll('.filters').forEach((bar) => {
        bar.querySelectorAll('.fbtn').forEach((btn) => {
            btn.addEventListener('click', () => {
                bar.querySelectorAll('.fbtn').forEach((entry) => entry.classList.remove('on'));
                btn.classList.add('on');
                const sev = btn.dataset.sev;
                const container = bar.closest('.pane')?.querySelector('.pane-body, tbody');
                if (!container) return;
                container.querySelectorAll('.fc, tr[data-severity]').forEach((el) => {
                    el.classList.toggle('is-hidden', sev !== 'all' && el.dataset.severity !== sev.toLowerCase());
                });
            });
        });
    });
}
