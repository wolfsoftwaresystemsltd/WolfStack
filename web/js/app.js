// WolfStack Dashboard — app.js

// ─── State ───
let currentPage = 'dashboard';
let cpuHistory = [];
let memHistory = [];
const MAX_HISTORY = 60;

// ─── Page Navigation ───
document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        navigateTo(item.dataset.page);
    });
});

function navigateTo(page) {
    currentPage = page;
    document.querySelectorAll('.page-view').forEach(p => p.style.display = 'none');
    document.getElementById(`page-${page}`).style.display = 'block';
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');

    const titles = {
        dashboard: 'Dashboard',
        servers: 'Servers',
        components: 'Components',
        services: 'Services',
        certificates: 'Certificates',
        monitoring: 'Live Metrics',
    };
    document.getElementById('page-title').textContent = titles[page] || page;

    // Refresh data for the page
    if (page === 'components') loadComponents();
    if (page === 'services') loadComponents();
    if (page === 'monitoring') initCharts();
}

// Handle hash navigation
window.addEventListener('hashchange', () => {
    const page = location.hash.replace('#', '') || 'dashboard';
    navigateTo(page);
});
if (location.hash) navigateTo(location.hash.replace('#', ''));

// ─── Formatting Helpers ───
function formatBytes(bytes) {
    if (bytes >= 1e12) return (bytes / 1e12).toFixed(1) + ' TB';
    if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB';
    if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
    if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB';
    return bytes + ' B';
}

function formatUptime(secs) {
    if (secs >= 86400) return Math.floor(secs / 86400) + 'd ' + Math.floor((secs % 86400) / 3600) + 'h';
    if (secs >= 3600) return Math.floor(secs / 3600) + 'h ' + Math.floor((secs % 3600) / 60) + 'm';
    if (secs >= 60) return Math.floor(secs / 60) + 'm ' + (secs % 60) + 's';
    return secs + 's';
}

function progressClass(percent) {
    if (percent > 90) return 'danger';
    if (percent > 70) return 'warning';
    return 'success';
}

// ─── Gauge Helper ───
function setGauge(id, percent, valId, display) {
    const circumference = 2 * Math.PI * 52; // r=52
    const dashLen = (percent / 100) * circumference;
    const el = document.getElementById(id);
    if (el) el.setAttribute('stroke-dasharray', `${dashLen} ${circumference}`);
    const valEl = document.getElementById(valId);
    if (valEl) valEl.textContent = display || `${Math.round(percent)}%`;
}

// ─── Metrics Polling ───
async function fetchMetrics() {
    try {
        const resp = await fetch('/api/metrics');
        const m = await resp.json();
        updateDashboard(m);
    } catch (e) {
        console.error('Failed to fetch metrics:', e);
    }
}

function updateDashboard(m) {
    // Hostname
    document.getElementById('hostname-display').textContent = m.hostname;

    // CPU
    const cpuPct = m.cpu_usage_percent.toFixed(1);
    document.getElementById('cpu-value').textContent = cpuPct + '%';
    document.getElementById('cpu-model').textContent = m.cpu_model + ` (${m.cpu_count} cores)`;
    document.getElementById('cpu-bar').style.width = cpuPct + '%';
    document.getElementById('cpu-bar').className = 'fill ' + progressClass(m.cpu_usage_percent);
    setGauge('cpu-gauge', m.cpu_usage_percent, 'cpu-gauge-val');

    // Memory
    const memPct = m.memory_percent.toFixed(1);
    document.getElementById('mem-value').textContent = memPct + '%';
    document.getElementById('mem-detail').textContent =
        `${formatBytes(m.memory_used_bytes)} / ${formatBytes(m.memory_total_bytes)}`;
    document.getElementById('mem-bar').style.width = memPct + '%';
    document.getElementById('mem-bar').className = 'fill ' + progressClass(m.memory_percent);
    setGauge('mem-gauge', m.memory_percent, 'mem-gauge-val');

    // Load
    const loadPct = Math.min((m.load_avg.one / m.cpu_count) * 100, 100);
    setGauge('load-gauge', loadPct, 'load-gauge-val', m.load_avg.one.toFixed(2));

    // Disk (primary)
    if (m.disks.length > 0) {
        const root = m.disks.find(d => d.mount_point === '/') || m.disks[0];
        document.getElementById('disk-value').textContent = root.usage_percent.toFixed(1) + '%';
        document.getElementById('disk-detail').textContent =
            `${formatBytes(root.used_bytes)} / ${formatBytes(root.total_bytes)}`;
        document.getElementById('disk-bar').style.width = root.usage_percent + '%';
        document.getElementById('disk-bar').className = 'fill ' + progressClass(root.usage_percent);
    }

    // Disk table
    const diskTable = document.getElementById('disk-table');
    diskTable.innerHTML = m.disks.map(d => `
        <tr>
            <td style="font-family: 'JetBrains Mono', monospace; font-size: 12px;">${d.mount_point}</td>
            <td>${d.fs_type}</td>
            <td>${formatBytes(d.total_bytes)}</td>
            <td>${formatBytes(d.used_bytes)}</td>
            <td>${formatBytes(d.available_bytes)}</td>
            <td>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div class="progress-bar" style="width: 100px; margin: 0;">
                        <div class="fill ${progressClass(d.usage_percent)}" style="width: ${d.usage_percent}%"></div>
                    </div>
                    <span style="font-size: 12px; min-width: 35px;">${d.usage_percent.toFixed(0)}%</span>
                </div>
            </td>
        </tr>
    `).join('');

    // Network
    if (m.network.length > 0) {
        const totalRx = m.network.reduce((a, n) => a + n.rx_bytes, 0);
        const totalTx = m.network.reduce((a, n) => a + n.tx_bytes, 0);
        document.getElementById('net-value').textContent = '↓' + formatBytes(totalRx);
        document.getElementById('net-detail').textContent = '↑' + formatBytes(totalTx) + ' sent';
    }

    // Network table (monitoring page)
    const netTable = document.getElementById('network-table');
    if (netTable) {
        netTable.innerHTML = m.network.map(n => `
            <tr>
                <td style="font-family: 'JetBrains Mono', monospace;">${n.interface}</td>
                <td>${formatBytes(n.rx_bytes)}</td>
                <td>${formatBytes(n.tx_bytes)}</td>
                <td>${n.rx_packets.toLocaleString()}</td>
                <td>${n.tx_packets.toLocaleString()}</td>
            </tr>
        `).join('');
    }

    // System info table (monitoring page)
    const sysTable = document.getElementById('sysinfo-table');
    if (sysTable) {
        sysTable.querySelector('tbody').innerHTML = `
            <tr><td style="color: var(--text-secondary);">Hostname</td><td>${m.hostname}</td></tr>
            <tr><td style="color: var(--text-secondary);">CPU</td><td>${m.cpu_model} (${m.cpu_count} cores)</td></tr>
            <tr><td style="color: var(--text-secondary);">Uptime</td><td>${formatUptime(m.uptime_secs)}</td></tr>
            <tr><td style="color: var(--text-secondary);">Load Average</td><td>${m.load_avg.one.toFixed(2)} / ${m.load_avg.five.toFixed(2)} / ${m.load_avg.fifteen.toFixed(2)}</td></tr>
            <tr><td style="color: var(--text-secondary);">Processes</td><td>${m.processes}</td></tr>
            <tr><td style="color: var(--text-secondary);">Swap</td><td>${formatBytes(m.swap_used_bytes)} / ${formatBytes(m.swap_total_bytes)}</td></tr>
        `;
    }

    // Chart history
    cpuHistory.push(m.cpu_usage_percent);
    memHistory.push(m.memory_percent);
    if (cpuHistory.length > MAX_HISTORY) cpuHistory.shift();
    if (memHistory.length > MAX_HISTORY) memHistory.shift();
    drawChart('cpu-chart', cpuHistory, 'rgba(99, 102, 241, 0.8)', 'rgba(99, 102, 241, 0.1)');
    drawChart('mem-chart', memHistory, 'rgba(16, 185, 129, 0.8)', 'rgba(16, 185, 129, 0.1)');
}

// ─── Simple Canvas Charts ───
function drawChart(canvasId, data, strokeColor, fillColor) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (data.length < 2) return;

    const padding = 10;
    const w = canvas.width - padding * 2;
    const h = canvas.height - padding * 2;
    const step = w / (MAX_HISTORY - 1);

    ctx.beginPath();
    ctx.moveTo(padding, padding + h - (data[0] / 100) * h);
    for (let i = 1; i < data.length; i++) {
        const x = padding + i * step;
        const y = padding + h - (data[i] / 100) * h;
        const prevX = padding + (i - 1) * step;
        const prevY = padding + h - (data[i - 1] / 100) * h;
        const cpX = (prevX + x) / 2;
        ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
    }
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Fill
    ctx.lineTo(padding + (data.length - 1) * step, padding + h);
    ctx.lineTo(padding, padding + h);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();

    // Grid lines
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = padding + (h / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(padding + w, y);
        ctx.stroke();
    }
}

function initCharts() {
    drawChart('cpu-chart', cpuHistory, 'rgba(99, 102, 241, 0.8)', 'rgba(99, 102, 241, 0.1)');
    drawChart('mem-chart', memHistory, 'rgba(16, 185, 129, 0.8)', 'rgba(16, 185, 129, 0.1)');
}

// ─── Nodes / Servers ───
async function fetchNodes() {
    try {
        const resp = await fetch('/api/nodes');
        const nodes = await resp.json();
        updateNodesList(nodes);
    } catch (e) {
        console.error('Failed to fetch nodes:', e);
    }
}

function updateNodesList(nodes) {
    document.getElementById('server-count').textContent = nodes.length;
    document.getElementById('total-servers-val').textContent = nodes.length;
    document.getElementById('online-servers-val').textContent = nodes.filter(n => n.online).length;
    document.getElementById('offline-servers-val').textContent = nodes.filter(n => !n.online).length;

    // Dashboard server list
    const list = document.getElementById('server-list');
    if (nodes.length === 0) {
        list.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 30px;">
            No servers added yet. Click "+ Add Server" to get started.
        </div>`;
    } else {
        list.innerHTML = nodes.map(n => renderServerRow(n)).join('');
    }

    // Full server list
    const fullList = document.getElementById('servers-full-list');
    if (fullList) {
        if (nodes.length === 0) {
            fullList.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 30px;">
                No servers added yet.
            </div>`;
        } else {
            fullList.innerHTML = nodes.map(n => renderServerRow(n, true)).join('');
        }
    }
}

function renderServerRow(node, showActions = false) {
    const cpuPct = node.metrics ? node.metrics.cpu_usage_percent.toFixed(0) + '%' : '—';
    const memPct = node.metrics ? node.metrics.memory_percent.toFixed(0) + '%' : '—';
    const selfBadge = node.is_self ? ' <span style="color: var(--accent-light); font-size: 11px;">(this)</span>' : '';
    const actions = showActions && !node.is_self ?
        `<button class="btn btn-danger btn-sm" onclick="removeServer('${node.id}')">Remove</button>` : '';

    return `
        <div class="server-row">
            <div class="server-status ${node.online ? 'online' : 'offline'}"></div>
            <div class="server-info">
                <h4>${node.hostname}${selfBadge}</h4>
                <div class="address">${node.address}:${node.port}</div>
            </div>
            <div class="server-metric">
                <div class="value">${cpuPct}</div>
                <div class="label">CPU</div>
            </div>
            <div class="server-metric">
                <div class="value">${memPct}</div>
                <div class="label">Memory</div>
            </div>
            <div>${actions}</div>
        </div>
    `;
}

// ─── Components ───
async function loadComponents() {
    try {
        const resp = await fetch('/api/components');
        const components = await resp.json();
        renderComponents(components);
        renderServices(components);
    } catch (e) {
        console.error('Failed to load components:', e);
    }
}

const componentIcons = {
    wolfnet: '🌐', wolfproxy: '🛡️', wolfserve: '📡',
    wolfdisk: '💾', wolfscale: '⚖️', mariadb: '🗄️', certbot: '🔒'
};

function renderComponents(components) {
    const grid = document.getElementById('components-grid');
    grid.innerHTML = components.map(c => {
        const icon = componentIcons[c.component] || '📦';
        const statusClass = c.running ? 'running' : c.installed ? 'stopped' : 'not-installed';
        const statusText = c.running ? 'Running' : c.installed ? 'Stopped' : 'Not Installed';
        const statusColor = c.running ? 'var(--success)' : c.installed ? 'var(--text-muted)' : 'var(--warning)';

        return `
            <div class="component-card">
                <div class="component-header">
                    <div class="component-icon">${icon}</div>
                    <div>
                        <div class="component-name">${c.component.charAt(0).toUpperCase() + c.component.slice(1)}</div>
                        <div class="component-desc">${c.version || ''}</div>
                    </div>
                </div>
                <div class="component-status">
                    <div class="status-dot ${statusClass}"></div>
                    <span style="color: ${statusColor};">${statusText}</span>
                </div>
                <div class="component-actions">
                    ${!c.installed ?
                `<button class="btn btn-primary btn-sm" onclick="installComponent('${c.component}')">Install</button>` :
                c.running ?
                    `<button class="btn btn-sm" onclick="serviceAction('${c.component}', 'restart')">Restart</button>
                             <button class="btn btn-danger btn-sm" onclick="serviceAction('${c.component}', 'stop')">Stop</button>` :
                    `<button class="btn btn-success btn-sm" onclick="serviceAction('${c.component}', 'start')">Start</button>`
            }
                </div>
            </div>
        `;
    }).join('');
}

function renderServices(components) {
    const table = document.getElementById('services-table');
    if (!table) return;
    table.innerHTML = components.filter(c => c.installed).map(c => {
        const statusColor = c.running ? 'var(--success)' : 'var(--danger)';
        const statusText = c.running ? 'Active' : 'Inactive';
        return `
            <tr>
                <td>
                    <span style="margin-right: 8px;">${componentIcons[c.component] || '📦'}</span>
                    ${c.component}
                </td>
                <td><span style="color: ${statusColor};">● ${statusText}</span></td>
                <td>${c.enabled ? '✓ Yes' : '✗ No'}</td>
                <td style="color: var(--text-muted);">${c.version || '—'}</td>
                <td>
                    ${c.running ?
                `<button class="btn btn-sm" onclick="serviceAction('${c.component}', 'restart')">Restart</button>
                         <button class="btn btn-danger btn-sm" onclick="serviceAction('${c.component}', 'stop')">Stop</button>` :
                `<button class="btn btn-success btn-sm" onclick="serviceAction('${c.component}', 'start')">Start</button>`
            }
                </td>
            </tr>
        `;
    }).join('');
}

async function installComponent(name) {
    showToast(`Installing ${name}...`, 'info');
    try {
        const resp = await fetch(`/api/components/${name}/install`, { method: 'POST' });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message, 'success');
        } else {
            showToast(data.error || 'Installation failed', 'error');
        }
        loadComponents();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function serviceAction(service, action) {
    try {
        const resp = await fetch(`/api/services/${service}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message, 'success');
        } else {
            showToast(data.error || 'Action failed', 'error');
        }
        loadComponents();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

// ─── Certificates ───
async function requestCertificate() {
    const domain = document.getElementById('cert-domain').value.trim();
    if (!domain) { showToast('Enter a domain name', 'error'); return; }

    showToast(`Requesting certificate for ${domain}...`, 'info');
    try {
        const resp = await fetch('/api/certificates', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message, 'success');
        } else {
            showToast(data.error || 'Certificate request failed', 'error');
        }
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

// ─── Modals ───
function openAddServerModal() {
    document.getElementById('add-server-modal').classList.add('active');
}

function closeModal() {
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
}

async function addServer() {
    const address = document.getElementById('new-server-address').value.trim();
    const port = parseInt(document.getElementById('new-server-port').value) || 8553;

    if (!address) { showToast('Enter a server address', 'error'); return; }

    try {
        const resp = await fetch('/api/nodes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, port })
        });
        const data = await resp.json();
        showToast(`Server ${address} added`, 'success');
        closeModal();
        document.getElementById('new-server-address').value = '';
        fetchNodes();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function removeServer(id) {
    try {
        await fetch(`/api/nodes/${id}`, { method: 'DELETE' });
        showToast('Server removed', 'success');
        fetchNodes();
    } catch (e) {
        showToast('Failed to remove server', 'error');
    }
}

// ─── Toast Notifications ───
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: '✓', error: '✗', info: 'ℹ' };
    toast.innerHTML = `<span style="font-size: 16px;">${icons[type] || 'ℹ'}</span> ${message}`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ─── Polling Loop ───
fetchMetrics();
fetchNodes();
setInterval(fetchMetrics, 2000);
setInterval(fetchNodes, 10000);
