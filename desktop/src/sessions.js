/**
 * Basilisk Desktop — Sessions, reports, audit, and settings.
 */

import { esc, normalizeSeverity, severityClass, statusBadgeClass } from './shared.js';
import { apiFetch, log, toast } from './core.js';

export async function loadSessions() {
    const data = await apiFetch('/api/sessions');
    const list = document.getElementById('sess-list');
    list.innerHTML = '';
    if (!data.sessions?.length) {
        list.innerHTML = '<div class="empty-msg">No sessions.</div>';
        const badge = document.getElementById('b-sessions');
        badge?.classList.add('hidden');
        if (badge) badge.innerText = '0';
        document.getElementById('k-scans').innerText = '0';
        const reportSelect = document.getElementById('rpt-sess');
        if (reportSelect) {
            reportSelect.innerHTML = '<option value="">Select…</option>';
        }
        return;
    }

    const sessionBadge = document.getElementById('b-sessions');
    sessionBadge.innerText = data.sessions.length;
    sessionBadge.classList.remove('hidden');
    document.getElementById('k-scans').innerText = data.sessions.length;

    const reportSelect = document.getElementById('rpt-sess');
    if (reportSelect) {
        reportSelect.innerHTML = '<option value="">Select…</option>';
        data.sessions.forEach((session) => {
            const opt = document.createElement('option');
            opt.value = session.id;
            opt.innerText = `${session.target || session.id.slice(0, 12)} (${session.status})`;
            reportSelect.appendChild(opt);
        });
    }

    data.sessions.forEach((session) => {
        const el = document.createElement('div');
        el.className = 'sess-item';
        const campaignName = session.campaign?.name ? `<span>${esc(session.campaign.name)}</span>` : '';
        const execMode = session.policy?.execution_mode ? `<span>${esc(session.policy.execution_mode)}</span>` : '';
        el.innerHTML = `<div class="sess-target">${esc(session.target || session.id?.slice(0, 16))}</div><div class="sess-meta"><span class="badge-sev ${statusBadgeClass(session.status)}">${esc(session.status || 'unknown')}</span>${campaignName}${execMode}${session.total_findings ? `<span>${session.total_findings} findings</span>` : ''}</div>`;
        el.addEventListener('click', () => loadSessionDetail(session.id, el));
        list.appendChild(el);
    });
}

async function loadSessionDetail(id, activeEl) {
    const data = await apiFetch(`/api/sessions/${id}`);
    const detail = document.getElementById('sess-detail');
    detail.innerHTML = '';
    document.querySelectorAll('.sess-item').forEach((item) => item.classList.remove('active'));
    activeEl?.classList.add('active');

    if (data.summary?.campaign || data.summary?.policy || data.summary?.attack_memory || data.summary?.phase_history?.length) {
        const meta = document.createElement('div');
        meta.className = 'session-meta-panel';
        const evidenceCounts = Object.entries(data.summary?.attack_memory?.evidence_verdict_counts || {})
            .map(([verdict, count]) => `${esc(verdict)}=${count}`)
            .join(' | ') || 'none';
        const attackGraph = data.summary?.attack_memory?.attack_graph;
        const graphHtml = (attackGraph?.stages || []).map((stage) => `
            <div class="session-graph-stage">
                <div><strong class="table-text-primary">${esc(stage.name)}</strong> <span class="text-muted">(${esc(stage.confidence_goal || 'probable')})</span></div>
                <div class="session-detail-copy session-detail-gap">${esc(stage.objective || '')}</div>
                <div class="text-muted session-detail-gap">${esc((stage.module_names || []).join(', ') || 'no modules')}</div>
            </div>
        `).join('');
        const phases = (data.summary?.phase_history || [])
            .map((phase) => `<div class="session-phase-item"><strong class="table-text-primary">${esc(phase.phase)}</strong> <span class="text-muted">${esc((phase.timestamp || '').slice(11, 19))}</span></div>`)
            .join('');
        meta.innerHTML = `
            <div><strong class="table-text-primary">Campaign:</strong> ${esc(data.summary?.campaign?.name || '—')}</div>
            <div><strong class="table-text-primary">Operator:</strong> ${esc(data.summary?.campaign?.authorization?.operator || '—')}</div>
            <div><strong class="table-text-primary">Ticket:</strong> ${esc(data.summary?.campaign?.authorization?.ticket_id || '—')}</div>
            <div><strong class="table-text-primary">Execution:</strong> ${esc(data.summary?.policy?.execution_mode || '—')} / ${esc(data.summary?.policy?.evidence_threshold || '—')}</div>
            <div><strong class="table-text-primary">Retention:</strong> ${esc(String(data.summary?.policy?.retain_days || '—'))} days | raw=${esc(String(data.summary?.policy?.retain_raw_findings || false))} | conv=${esc(String(data.summary?.policy?.retain_conversations || false))}</div>
            <div><strong class="table-text-primary">Evidence:</strong> ${evidenceCounts}</div>
            <div class="session-section"><strong class="table-text-primary">Exploit Graph:</strong>${graphHtml || '<div class="session-placeholder">No phased graph.</div>'}</div>
            <div class="session-section"><strong class="table-text-primary">Phase Timeline:</strong>${phases || '<div class="session-placeholder">No phase history.</div>'}</div>
        `;
        detail.appendChild(meta);
    }

    if (!data.findings?.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-msg';
        empty.innerText = 'No findings.';
        detail.appendChild(empty);
        return;
    }

    const tbl = document.createElement('table');
    tbl.className = 'tbl';
    tbl.innerHTML = `<thead><tr><th>Severity</th><th>Evidence</th><th>Tier</th><th>Policy</th><th>Module</th><th>Title</th><th>Conf</th></tr></thead><tbody>${data.findings.map((finding) => `<tr><td><span class="badge-sev ${severityClass(finding.severity)}">${severityClass(finding.severity)}</span></td><td class="table-font-small">${esc(finding.evidence?.verdict || '—')}</td><td class="table-font-small">${esc((finding.module_trust_tier || 'beta').toUpperCase())}</td><td class="table-font-small">${finding.policy_downgraded ? '<span class="danger-text">downgraded</span>' : '<span class="safe-text">pass</span>'}</td><td class="table-font-small">${esc(finding.attack_module || '—')}</td><td class="table-text-primary">${esc(finding.title)}</td><td>${finding.confidence ? `${(finding.confidence * 100).toFixed(0)}%` : '—'}</td></tr>`).join('')}</tbody>`;
    detail.appendChild(tbl);

    const downgraded = data.findings.filter((finding) => finding.policy_downgraded);
    if (downgraded.length) {
        const summary = document.createElement('div');
        summary.className = 'session-meta-panel';
        summary.innerHTML = `<div><strong class="table-text-primary">Downgraded Findings:</strong> ${downgraded.length}</div>${downgraded.map((finding) => `<div class="session-detail-copy"><strong>${esc(finding.title)}</strong> <span class="danger-text">(${esc(finding.metadata?.original_severity || 'unknown')}→${esc(finding.severity)})</span><br><span class="text-muted">${esc((finding.metadata?.missing_evidence_requirements || []).join(', ') || 'missing structured proof')}</span></div>`).join('')}`;
        detail.appendChild(summary);
    }
}

export async function loadNative() {
    const status = await apiFetch('/api/native/status');
    if (status.error) return;
    const mapping = { fuzzer_go: 'ns-fuzzer', matcher_go: 'ns-matcher', tokens_c: 'ns-tokens', encoder_c: 'ns-encoder' };
    Object.entries(mapping).forEach(([key, id]) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (status[key]) {
            el.innerText = 'LOADED';
            el.className = 'native-val ok';
        } else {
            el.innerText = 'FALLBACK';
            el.className = 'native-val fb';
        }
    });
    const loaded = Object.values(status).filter(Boolean).length;
    log(loaded > 0 ? 'ok' : 'dim', `Native: ${loaded}/${Object.keys(status).length} loaded`);
}

async function saveKey(provider) {
    const input = document.getElementById(`key-${provider}`);
    if (!input) return;
    const result = await apiFetch('/api/settings/apikey', { method: 'POST', body: { provider, key: input.value } });
    if (!result.error) {
        log('ok', `Key saved: ${provider}`);
        toast('ok', `${provider.toUpperCase()} API key saved.`);
    }
}

export async function loadSecretStoreStatus() {
    const status = await apiFetch('/api/settings/secrets');
    const el = document.getElementById('secret-store-status');
    if (!el || status.error) return;
    const stored = (status.providers || []).filter((provider) => provider.stored).map((provider) => provider.provider).join(', ') || 'none';
    el.innerHTML = `Storage: <strong class="table-text-primary">${esc(status.backend)}</strong> via <strong class="table-text-primary">${esc(status.key_backend)}</strong> | Stored providers: ${esc(stored)}`;
}

async function generateReport() {
    const sessionId = document.getElementById('rpt-sess')?.value;
    const format = document.getElementById('rpt-fmt')?.value;
    if (!sessionId) {
        log('err', 'Select a session first.');
        return;
    }
    log('inf', `Generating ${format} report…`);
    if (window.basilisk?.report) {
        const result = await window.basilisk.report.export(sessionId, format);
        if (result.path) {
            log('ok', `Exported: ${result.path}`);
            toast('ok', `Report exported to ${result.path}`);
        } else if (result.error) {
            log('err', `Report export failed: ${result.error}`);
            toast('error', result.error);
        }
    } else {
        const result = await apiFetch(`/api/report/${sessionId}`, { method: 'POST', body: { format, open_browser: true } });
        if (result.path) {
            log('ok', `Generated: ${result.path}`);
            toast('ok', 'Report generated and opening in browser...');
        } else if (result.error) {
            log('err', `Report generation failed: ${result.error}`);
            toast('error', result.error);
        }
    }
}

async function loadAudit() {
    const sessionId = document.getElementById('audit-session')?.value?.trim();
    if (!sessionId) {
        log('err', 'Enter a session ID.');
        return;
    }
    try {
        const result = await apiFetch(`/api/audit/${sessionId}`);
        const container = document.getElementById('audit-log');
        const integrity = document.getElementById('audit-integrity');

        if (result.error) {
            container.innerHTML = `<div class="empty-msg danger-text">${esc(result.error)}</div>`;
            return;
        }

        container.innerHTML = '';
        const entries = result.entries || [];
        const eventColors = {
            session_start: 'dim',
            scan_config: 'dim',
            prompt_sent: 'inf',
            response_received: 'dim',
            finding_discovered: 'ok',
            evolution_generation: 'inf',
            error: 'err',
            report_generated: 'ok',
            session_end: 'dim',
        };

        entries.forEach((entry) => {
            const el = document.createElement('div');
            el.className = `ll ${eventColors[entry.event] || 'dim'}`;
            const timestamp = entry.timestamp?.slice(11, 19) || '';
            let detail = '';
            if (entry.event === 'finding_discovered') {
                detail = `[${normalizeSeverity(entry.data?.severity)}] ${entry.data?.title || ''}`;
            } else if (entry.event === 'prompt_sent') {
                detail = `${entry.data?.module} → ${entry.data?.provider}/${entry.data?.model}`;
            } else if (entry.event === 'error') {
                detail = `${entry.data?.module}: ${entry.data?.error?.slice(0, 80)}`;
            } else if (entry.event === 'evolution_generation') {
                detail = `Gen ${entry.data?.generation} best=${entry.data?.best_fitness} breakthroughs=${entry.data?.breakthroughs}`;
            } else {
                detail = JSON.stringify(entry.data || {}).slice(0, 100);
            }
            el.innerText = `[${timestamp}] ${entry.event}: ${detail}`;
            container.appendChild(el);
        });

        const verification = result.verification || {};
        if (verification.valid) {
            const signature = verification.signed
                ? 'Ed25519 signatures valid (embedded key)'
                : 'unsigned';
            integrity.innerText = `${entries.length} entries | Hash chain valid | ${signature} | File: ${result.path || '?'}`;
            integrity.classList.remove('danger-text');
        } else {
            const reason = (verification.errors || []).join('; ') || 'verification failed';
            integrity.innerText = `${entries.length} entries | INVALID AUDIT TRAIL: ${reason}`;
            integrity.classList.add('danger-text');
        }
        log('ok', `Loaded ${entries.length} audit entries for session ${sessionId}`);
    } catch (e) {
        log('err', `Audit load failed: ${e.message}`);
    }
}

async function clearSessionHistory() {
    const confirmed = window.confirm(
        'Clear local Basilisk session history?\n\nThis removes stored session metadata from the desktop workspace. Active scans must be stopped first.'
    );
    if (!confirmed) return;

    const result = await apiFetch('/api/sessions/clear', { method: 'POST' });
    if (result.error) {
        log('err', `History clear failed: ${result.error}`);
        toast('error', result.error);
        return;
    }

    const list = document.getElementById('sess-list');
    if (list) list.innerHTML = '<div class="empty-msg">No sessions.</div>';
    const detail = document.getElementById('sess-detail');
    if (detail) detail.innerHTML = '<div class="empty-msg">Select a session.</div>';
    const reportSelect = document.getElementById('rpt-sess');
    if (reportSelect) reportSelect.innerHTML = '<option value="">Select…</option>';
    const badge = document.getElementById('b-sessions');
    if (badge) {
        badge.innerText = '0';
        badge.classList.add('hidden');
    }
    document.getElementById('k-scans').innerText = '0';

    log('ok', `Cleared ${result.cleared_sessions || 0} stored sessions.`);
    toast('ok', 'Local session history cleared.');
    await loadSessions();
}

export function initSessions() {
    document.getElementById('btn-refresh-sess')?.addEventListener('click', loadSessions);
    document.getElementById('btn-clear-sess')?.addEventListener('click', clearSessionHistory);
    ['openai', 'anthropic', 'google', 'github', 'xai', 'groq', 'nvidia'].forEach((provider) => {
        document.getElementById(`btn-save-key-${provider}`)?.addEventListener('click', () => saveKey(provider));
    });
    document.getElementById('btn-gen-report')?.addEventListener('click', generateReport);
    document.getElementById('btn-audit-load')?.addEventListener('click', loadAudit);
}
