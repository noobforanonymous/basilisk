/**
 * Basilisk Desktop — Differential and posture scans.
 */

import { esc } from './shared.js';
import { apiFetch, log } from './core.js';

let diffTargetCount = 2;

function diffRow(idx) {
    return `
        <select class="sel diff-target-select" id="diff-prov-${idx}">
            <option value="openai">OpenAI</option><option value="anthropic">Anthropic</option>
            <option value="google" ${idx === 2 ? 'selected' : ''}>Google</option><option value="nvidia">NVIDIA</option><option value="xai">xAI (Grok)</option><option value="azure">Azure</option><option value="ollama">Ollama</option>
        </select>
        <input class="inp flex-fill" id="diff-model-${idx}" placeholder="${idx === 2 ? 'gemini/gemini-2.0-flash' : ''}">
        <button class="btn ghost sm diff-target-remove" type="button">✗</button>
    `;
}

async function runDifferential() {
    const rows = document.querySelectorAll('.diff-target-row');
    const targets = [];
    rows.forEach((row) => {
        const idx = row.dataset.idx;
        const provider = document.getElementById(`diff-prov-${idx}`)?.value;
        const model = document.getElementById(`diff-model-${idx}`)?.value || '';
        if (provider) targets.push({ provider, model });
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
        const result = await apiFetch('/api/diff', { method: 'POST', body: { targets, categories: [] } });
        const container = document.getElementById('diff-results');
        const summary = document.getElementById('diff-summary');

        if (result.error) {
            container.innerHTML = `<div class="empty-msg danger-text">${esc(result.error)}</div>`;
            log('err', result.error);
            return;
        }

        summary.innerText = `${result.total_divergences} divergences / ${result.total_probes} probes (${result.divergence_rate})`;
        const tbl = document.createElement('table');
        tbl.className = 'tbl';
        tbl.innerHTML = `<thead><tr><th>Category</th><th>Probe</th><th>Divergence</th><th class="danger-text">Vulnerable</th><th class="safe-text">Resistant</th></tr></thead><tbody>${(result.probes || []).map((probe) => `<tr><td class="table-font-small">${esc(probe.category)}</td><td class="table-font-small table-ellipsis">${esc(probe.probe.slice(0, 60))}</td><td><span class="badge-sev ${probe.has_divergence ? 'CRITICAL' : 'INFO'}">${probe.has_divergence ? 'YES' : 'no'}</span></td><td class="table-font-small danger-text">${esc((probe.vulnerable_models || []).join(', ') || '—')}</td><td class="table-font-small safe-text">${esc((probe.resistant_models || []).join(', ') || '—')}</td></tr>`).join('')}</tbody>`;
        container.innerHTML = '';
        container.appendChild(tbl);
        log('ok', `Differential scan complete: ${result.total_divergences} divergences found`);
    } catch (e) {
        log('err', `Diff scan failed: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3" /></svg>Run Differential';
    }
}

async function runPosture() {
    const provider = document.getElementById('post-provider')?.value || 'openai';
    const model = document.getElementById('post-model')?.value || '';
    const btn = document.getElementById('btn-posture-start');
    btn.disabled = true;
    btn.innerText = 'Scanning…';
    log('inf', `Running posture scan: ${provider}/${model || 'default'}…`);

    try {
        const result = await apiFetch('/api/posture', { method: 'POST', body: { target: '', provider, model } });
        if (result.error) {
            log('err', result.error);
            return;
        }
        const gradeEl = document.getElementById('posture-grade');
        const scoreEl = document.getElementById('posture-score');
        const kPosture = document.getElementById('k-posture');
        const gradeClass = `posture-grade-${String(result.overall_grade || '').toLowerCase().replace('+', 'plus')}`;
        gradeEl.innerText = result.overall_grade || '—';
        gradeEl.className = `grade-display ${gradeClass}`;
        scoreEl.innerText = `${(result.overall_score * 100).toFixed(0)}% coverage`;
        if (kPosture) {
            kPosture.innerText = result.overall_grade;
            kPosture.className = `kpi-value ${gradeClass}`;
        }

        const container = document.getElementById('posture-results');
        const strengthColors = { none: 'CRITICAL', weak: 'HIGH', moderate: 'MEDIUM', strong: 'LOW', aggressive: 'INFO' };
        const tbl = document.createElement('table');
        tbl.className = 'tbl';
        tbl.innerHTML = `<thead><tr><th>Category</th><th>Strength</th><th>Score</th><th>Benign OK</th><th>Mod Block</th><th>Adv Block</th></tr></thead><tbody>${(result.categories || []).map((category) => `<tr><td class="table-text-primary">${esc(category.name)}</td><td><span class="badge-sev ${strengthColors[category.strength] || 'INFO'}">${String(category.strength || '').toUpperCase()}</span></td><td>${(category.score * 100).toFixed(0)}%</td><td>${category.benign_allowed ? '✓' : '✗'}</td><td>${category.moderate_blocked ? '✓' : '✗'}</td><td>${category.adversarial_blocked ? '✓' : '✗'}</td></tr>`).join('')}</tbody>`;
        container.innerHTML = '';
        container.appendChild(tbl);

        if (result.recommendations?.length) {
            const recs = document.createElement('div');
            recs.className = 'posture-recommendations';
            recs.innerHTML = '<div class="posture-recommendations-title">Recommendations</div>' + result.recommendations.map((rec) => `<div class="posture-recommendation-item">${esc(rec)}</div>`).join('');
            container.appendChild(recs);
        }

        log('ok', `Posture scan complete: Grade ${result.overall_grade} (${(result.overall_score * 100).toFixed(0)}%)`);
    } catch (e) {
        log('err', `Posture scan failed: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>Run Posture Scan';
    }
}

export function initAdvanced() {
    document.getElementById('btn-diff-add')?.addEventListener('click', () => {
        const container = document.getElementById('diff-targets');
        const idx = diffTargetCount++;
        const row = document.createElement('div');
        row.className = 'diff-target-row';
        row.dataset.idx = idx;
        row.innerHTML = diffRow(idx);
        container.appendChild(row);
        row.querySelector('.diff-target-remove')?.addEventListener('click', () => row.remove());
    });

    document.getElementById('btn-diff-start')?.addEventListener('click', runDifferential);
    document.getElementById('btn-posture-start')?.addEventListener('click', runPosture);
}
