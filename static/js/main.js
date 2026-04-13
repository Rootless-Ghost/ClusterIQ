/* ClusterIQ — Main JavaScript */

'use strict';

// ── Utility ───────────────────────────────────────────────────────────────────

function esc(str) {
    return String(str)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function countAlerts(text) {
    if (!text.trim()) return 0;
    const t = text.trim();
    if (t.startsWith('[')) {
        try { return JSON.parse(t).length; } catch { return '?'; }
    }
    return t.split('\n').filter(l => l.trim()).length;
}

// ── File upload ────────────────────────────────────────────────────────────────

function setupDropZone(zoneId, fileInputId, textareaId, counterId) {
    const zone  = document.getElementById(zoneId);
    const input = document.getElementById(fileInputId);
    const ta    = document.getElementById(textareaId);
    const ctr   = document.getElementById(counterId);
    if (!zone || !input || !ta) return;

    function updateCount(text) {
        if (!ctr) return;
        const n = countAlerts(text);
        ctr.textContent = `${n} alert${n !== 1 ? 's' : ''} loaded`;
    }

    function readFile(file) {
        const reader = new FileReader();
        reader.onload = e => {
            ta.value = e.target.result;
            updateCount(e.target.result);
        };
        reader.readAsText(file);
    }

    zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop',      e => { e.preventDefault(); zone.classList.remove('drag-over'); if (e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]); });
    zone.addEventListener('click',     () => input.click());
    input.addEventListener('change',   () => { if (input.files[0]) readFile(input.files[0]); });
    ta.addEventListener('input',       () => updateCount(ta.value));
}

// ── Threshold slider ───────────────────────────────────────────────────────────

const thresholdSlider  = document.getElementById('thresholdSlider');
const thresholdDisplay = document.getElementById('thresholdDisplay');

if (thresholdSlider) {
    thresholdSlider.addEventListener('input', () => {
        if (thresholdDisplay) thresholdDisplay.textContent = parseFloat(thresholdSlider.value).toFixed(2);
    });
}

// ── Field checkboxes + custom field ───────────────────────────────────────────

function getSelectedFields() {
    const checked = [...document.querySelectorAll('.field-check input[type="checkbox"]:checked')]
        .map(cb => cb.value);
    // Also grab any dynamically-added field tags
    const extra = [...document.querySelectorAll('.extra-field-tag')]
        .map(el => el.getAttribute('data-field'));
    return [...new Set([...checked, ...extra])];
}

const addFieldBtn      = document.getElementById('addFieldBtn');
const customFieldInput = document.getElementById('customFieldInput');
const selectedFields   = document.getElementById('selectedFields');

if (addFieldBtn && customFieldInput) {
    addFieldBtn.addEventListener('click', () => {
        const val = customFieldInput.value.trim();
        if (!val) return;
        // Add to display
        if (selectedFields) {
            const span = document.createElement('span');
            span.className = 'extra-field-tag field-tag';
            span.setAttribute('data-field', val);
            span.textContent = val + ' ✕';
            span.style.cursor = 'pointer';
            span.addEventListener('click', () => span.remove());
            selectedFields.appendChild(span);
        }
        customFieldInput.value = '';
    });

    customFieldInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') addFieldBtn.click();
    });
}

// ── Verdict filter (index page) ────────────────────────────────────────────────

let _currentVerdictFilter = 'all';

function applyVerdictFilter(verdict) {
    _currentVerdictFilter = verdict;
    document.querySelectorAll('.vfilter-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-verdict') === verdict);
    });
    document.querySelectorAll('.cluster-card').forEach(card => {
        const cv = card.getAttribute('data-verdict');
        card.style.display = (verdict === 'all' || cv === verdict) ? '' : 'none';
    });
    updateClusterCountDisplay();
}

function updateClusterCountDisplay() {
    const display = document.getElementById('clusterCountDisplay');
    if (!display) return;
    const visible = document.querySelectorAll('.cluster-card:not([style*="display: none"])').length;
    display.textContent = `${visible} cluster${visible !== 1 ? 's' : ''} shown`;
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.vfilter-btn').forEach(btn => {
        btn.addEventListener('click', () => applyVerdictFilter(btn.getAttribute('data-verdict')));
    });
});

// ── Cluster button ─────────────────────────────────────────────────────────────

let _lastSession = null;

const clusterBtn    = document.getElementById('clusterBtn');
const clusterStatus = document.getElementById('clusterStatus');
const clusterText   = document.getElementById('clusterStatusText');

if (clusterBtn) {
    clusterBtn.addEventListener('click', runClustering);
}

async function runClustering() {
    const alertsJson = (document.getElementById('alertsJson') || {}).value || '';
    if (!alertsJson.trim()) {
        alert('Please enter or upload alerts first.');
        return;
    }

    const threshold  = parseFloat((thresholdSlider || {}).value || '0.75');
    const cluster_by = getSelectedFields();
    const label      = (document.getElementById('sessionLabel') || {}).value || '';

    if (!cluster_by.length) {
        alert('Select at least one cluster-by field.');
        return;
    }

    clusterBtn.disabled = true;
    if (clusterStatus) clusterStatus.classList.remove('hidden');
    if (clusterText)   clusterText.textContent = 'Clustering…';

    try {
        const resp = await fetch('/api/cluster', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                alerts_json:          alertsJson,
                similarity_threshold: threshold,
                cluster_by:           cluster_by,
                label:                label,
            }),
        });

        const data = await resp.json();
        if (!data.success) throw new Error(data.error || 'Clustering failed');

        _lastSession = data;
        renderResults(data);

    } catch (err) {
        alert(`Clustering error: ${err.message}`);
    } finally {
        clusterBtn.disabled = false;
        if (clusterStatus) clusterStatus.classList.add('hidden');
    }
}

// ── Render results ─────────────────────────────────────────────────────────────

function renderResults(data) {
    const section = document.getElementById('resultsSection');
    if (section) section.classList.remove('hidden');

    setText('sumOriginal',  (data.original_count || 0).toLocaleString());
    setText('sumClusters',  data.cluster_count || 0);
    setText('sumEscalate',  (data.escalate_count || 0).toLocaleString());
    setText('sumReview',    (data.review_count   || 0).toLocaleString());
    setText('sumSuppressed',(data.suppressed_count || 0).toLocaleString());
    setText('sumReduction', ((data.noise_reduction_pct || 0).toFixed(1)) + '%');

    // View session link
    if (data.session_id) {
        const link = document.getElementById('viewSessionBtn');
        if (link) {
            link.href = `/session/${data.session_id}`;
            link.classList.remove('hidden');
        }
    }

    // Export
    const exportJson = document.getElementById('exportJsonBtn');
    const exportMd   = document.getElementById('exportMdBtn');
    if (exportJson) exportJson.onclick = () => {
        if (data.session_id) window.location.href = `/api/session/${data.session_id}/export?format=json`;
        else downloadText(JSON.stringify(data, null, 2), 'clusteriq_session.json', 'application/json');
    };
    if (exportMd) exportMd.onclick = () => {
        if (data.session_id) window.location.href = `/api/session/${data.session_id}/export?format=markdown`;
    };

    // Render cluster grid
    const grid = document.getElementById('clusterGrid');
    if (!grid) return;
    grid.innerHTML = '';

    const clusters = data.clusters || [];
    if (!clusters.length) {
        grid.innerHTML = '<div class="no-clusters">No clusters produced.</div>';
        return;
    }

    clusters.forEach(c => {
        const div = document.createElement('div');
        div.className = `cluster-card cluster-${c.noise_verdict}`;
        div.setAttribute('data-verdict', c.noise_verdict);
        const ctx = c.context_scores || {};
        const fpHtml = Object.entries(c.fingerprint || {}).map(([k, v]) =>
            `<div class="fp-row"><span class="fp-key">${esc(k)}</span><span class="fp-val">${esc(String(v).slice(0,40))}</span></div>`
        ).join('') || '<div class="fp-row fp-empty">(no fingerprint fields)</div>';

        div.innerHTML = `
            <div class="cluster-card-top">
                <div class="cluster-id-badge">${esc(c.cluster_id)}</div>
                <div class="verdict-pill verdict-${c.noise_verdict}">${esc(c.noise_verdict)}</div>
                ${ctx.ti_tags            ? '<span class="ti-tag-badge">TI</span>'   : ''}
                ${ctx.has_critical_asset ? '<span class="crit-badge">CRIT</span>'  : ''}
            </div>
            <div class="cluster-fp">${fpHtml}</div>
            <div class="cluster-stats">
                <span class="cstat">${c.size} alerts</span>
                <span class="cstat">sim ${(c.similarity_score || 0).toFixed(2)}</span>
                <span class="cstat">${ctx.unique_users || 0} user(s)</span>
                ${ctx.off_hours_count ? `<span class="cstat cstat-warn">${ctx.off_hours_count} off-hrs</span>` : ''}
            </div>
            <div class="cluster-reason">${esc((c.verdict_reason || '').slice(0, 80))}${(c.verdict_reason || '').length > 80 ? '…' : ''}</div>
        `;
        div.addEventListener('click', () => openClusterModal(c));
        grid.appendChild(div);
    });

    // Re-apply current filter
    applyVerdictFilter(_currentVerdictFilter);

    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ── Cluster detail modal ───────────────────────────────────────────────────────

function openClusterModal(cluster) {
    const modal = document.getElementById('clusterModal');
    if (!modal) return;

    document.getElementById('modalClusterId').textContent = cluster.cluster_id || '';

    // Fingerprint lines
    const fpLines = Object.entries(cluster.fingerprint || {})
        .map(([k, v]) => `${k} = ${v}`)
        .join('\n');
    document.getElementById('modalClusterFp').textContent = fpLines || '(no fingerprint fields)';

    // Verdict badge
    const vBadge = document.getElementById('modalVerdict');
    if (vBadge) {
        vBadge.className = `verdict-badge verdict-${cluster.noise_verdict}`;
        vBadge.textContent = cluster.noise_verdict || '';
    }

    // ── Overview tab
    const ctx   = cluster.context_scores || {};
    const ovHtml = `
        <div class="modal-stats-grid">
            <div class="mstat"><div class="mstat-val">${cluster.size}</div><div class="mstat-lbl">Size</div></div>
            <div class="mstat"><div class="mstat-val">${(cluster.similarity_score || 0).toFixed(3)}</div><div class="mstat-lbl">Similarity</div></div>
            <div class="mstat"><div class="mstat-val">${ctx.unique_users || 0}</div><div class="mstat-lbl">Users</div></div>
            <div class="mstat"><div class="mstat-val">${ctx.unique_assets || 0}</div><div class="mstat-lbl">Assets</div></div>
        </div>
        <div class="ctx-summary">${esc(cluster.verdict_reason || 'No verdict reason recorded.')}</div>
    `;
    document.getElementById('mtab-overview').innerHTML = ovHtml;

    // ── Context scores tab
    function scoreBar(val, colorVar) {
        const pct = Math.round((val || 0) * 100);
        return `<div class="ctx-bar" style="width:${pct}%;background:${colorVar}"></div>`;
    }

    function boolBadge(val) {
        return val
            ? '<span class="ctx-bool ctx-bool-yes">Yes</span>'
            : '<span class="ctx-bool ctx-bool-no">No</span>';
    }

    const ctxHtml = `
        <div class="ctx-grid">
            <div class="ctx-row">
                <div class="ctx-label">TI Indicators</div>
                <div>${boolBadge(ctx.ti_tags)}</div>
                ${ctx.ti_member_count ? `<div class="ctx-val">${ctx.ti_member_count} member(s)</div>` : ''}
            </div>
            <div class="ctx-row">
                <div class="ctx-label">Critical Asset</div>
                <div>${boolBadge(ctx.has_critical_asset)}</div>
            </div>
            <div class="ctx-row">
                <div class="ctx-label">User Anomaly</div>
                <div class="ctx-bar-wrap">${scoreBar(ctx.user_anomaly, 'var(--accent-red)')}</div>
                <div class="ctx-val">${((ctx.user_anomaly || 0) * 100).toFixed(0)}%</div>
            </div>
            <div class="ctx-row">
                <div class="ctx-label">Asset Risk</div>
                <div class="ctx-bar-wrap">${scoreBar(ctx.asset_risk, 'var(--accent-orange)')}</div>
                <div class="ctx-val">${((ctx.asset_risk || 0) * 100).toFixed(0)}%</div>
            </div>
            <div class="ctx-row">
                <div class="ctx-label">Time Anomaly</div>
                <div class="ctx-bar-wrap">${scoreBar(ctx.time_anomaly, 'var(--accent-yellow)')}</div>
                <div class="ctx-val">${((ctx.time_anomaly || 0) * 100).toFixed(0)}%</div>
            </div>
            <div class="ctx-row">
                <div class="ctx-label">Hit Rate Anomaly</div>
                <div class="ctx-bar-wrap">${scoreBar(ctx.hit_rate_anomaly, 'var(--accent-purple)')}</div>
                <div class="ctx-val">${((ctx.hit_rate_anomaly || 0) * 100).toFixed(0)}%</div>
            </div>
            <div class="ctx-row">
                <div class="ctx-label">Off-hours Alerts</div>
                <div class="ctx-val">${ctx.off_hours_count || 0}</div>
            </div>
            <div class="ctx-row">
                <div class="ctx-label">Unique Users</div>
                <div class="ctx-val">${ctx.unique_users || 0}</div>
            </div>
            <div class="ctx-row">
                <div class="ctx-label">Unique Assets</div>
                <div class="ctx-val">${ctx.unique_assets || 0}</div>
            </div>
        </div>
    `;
    document.getElementById('mtab-context').innerHTML = ctxHtml;

    // ── Members tab
    const members = cluster.members || [];
    const membersHtml = members.length
        ? `<div class="members-count">${members.length} member event(s) stored</div>` +
          members.slice(0, 10).map(e =>
              `<pre class="event-pre">${esc(JSON.stringify(e, null, 2))}</pre>`
          ).join('') +
          (members.length > 10 ? `<div class="modal-empty">… ${members.length - 10} more not shown</div>` : '')
        : '<div class="modal-empty">No member events stored</div>';
    document.getElementById('mtab-members').innerHTML = membersHtml;

    // Reset to overview
    document.querySelectorAll('.mtab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.mtab-content').forEach(c => c.classList.remove('active'));
    const ovBtn = document.querySelector('.mtab-btn[data-mtab="overview"]');
    if (ovBtn) ovBtn.classList.add('active');
    const ovContent = document.getElementById('mtab-overview');
    if (ovContent) ovContent.classList.add('active');

    modal.classList.remove('hidden');
}

// ── Modal wiring ───────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Close modal
    const closeBtn = document.getElementById('closeModalBtn');
    if (closeBtn) closeBtn.addEventListener('click', () => {
        const m = document.getElementById('clusterModal');
        if (m) m.classList.add('hidden');
    });

    const modal = document.getElementById('clusterModal');
    if (modal) modal.addEventListener('click', e => {
        if (e.target === modal) modal.classList.add('hidden');
    });

    // Tab switching
    document.querySelectorAll('.mtab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.getAttribute('data-mtab');
            document.querySelectorAll('.mtab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.mtab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const el = document.getElementById('mtab-' + tab);
            if (el) el.classList.add('active');
        });
    });

    // Setup file drop zone
    setupDropZone('alertsDropZone', 'alertsFile', 'alertsJson', 'alertsCounter');

    // Textarea live counter
    const ta = document.getElementById('alertsJson');
    if (ta) {
        ta.addEventListener('input', () => {
            const ctr = document.getElementById('alertsCounter');
            if (ctr) {
                const n = countAlerts(ta.value);
                ctr.textContent = `${n} alert${n !== 1 ? 's' : ''} loaded`;
            }
        });
    }
});

// ── Download helper ────────────────────────────────────────────────────────────

function downloadText(content, filename, mime) {
    const blob = new Blob([content], { type: mime || 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
