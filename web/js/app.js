// WolfStack Dashboard — app.js

// ─── State ───
let currentPage = 'dashboard';
let currentComponent = null;
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
        'component-detail': 'Component Detail',
        services: 'Services',
        certificates: 'Certificates',
        monitoring: 'Live Metrics',
        containers: 'Docker Containers',
        lxc: 'LXC Containers',
    };
    document.getElementById('page-title').textContent = titles[page] || page;

    // Refresh data for the page
    if (page === 'components') loadComponents();
    if (page === 'services') loadComponents();
    if (page === 'monitoring') initCharts();
    if (page === 'containers') loadDockerContainers();
    if (page === 'lxc') loadLxcContainers();
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

// ─── Auth redirect on 401 ───
function handleAuthError(resp) {
    if (resp.status === 401) {
        window.location.href = '/login.html';
        return true;
    }
    return false;
}

// ─── Metrics Polling ───
async function fetchMetrics() {
    try {
        const resp = await fetch('/api/metrics');
        if (handleAuthError(resp)) return;
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
            <div class="component-card" onclick="openComponentDetail('${c.component}')">
                <div class="component-header">
                    <div class="component-icon">${icon}</div>
                    <div style="flex: 1;">
                        <div class="component-name">${c.component.charAt(0).toUpperCase() + c.component.slice(1)}</div>
                        <div class="component-desc">${c.version || ''}</div>
                    </div>
                    <span class="detail-arrow">→</span>
                </div>
                <div class="component-status">
                    <div class="status-dot ${statusClass}"></div>
                    <span style="color: ${statusColor};">${statusText}</span>
                </div>
                <div class="component-actions" onclick="event.stopPropagation()">
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

// ─── Component Detail ───
async function openComponentDetail(name) {
    currentComponent = name;
    navigateTo('component-detail');
    const pageTitle = document.getElementById('page-title');
    const cName = name.charAt(0).toUpperCase() + name.slice(1);
    pageTitle.textContent = cName;
    await refreshComponentDetail(name);
}

async function refreshComponentDetail(name) {
    try {
        const resp = await fetch(`/api/components/${name}/detail`);
        if (handleAuthError(resp)) return;
        const d = await resp.json();

        // Header
        document.getElementById('detail-component-icon').textContent = componentIcons[name] || '📦';
        document.getElementById('detail-component-name').textContent = d.name;
        document.getElementById('detail-component-desc').textContent = d.description;

        // Status cards
        const state = d.unit_info?.active_state || 'unknown';
        const sub = d.unit_info?.sub_state || '';
        document.getElementById('detail-status').textContent = state === 'active' ? 'Active' : state;
        document.getElementById('detail-active-since').textContent = sub ? `(${sub})` : '';

        const statusIcon = document.getElementById('detail-status-icon');
        if (d.running) {
            statusIcon.style.background = 'var(--success-bg)';
            statusIcon.style.color = 'var(--success)';
        } else {
            statusIcon.style.background = 'var(--danger-bg)';
            statusIcon.style.color = 'var(--danger)';
        }

        // Memory
        const memBytes = parseInt(d.unit_info?.memory_current) || 0;
        document.getElementById('detail-memory').textContent = memBytes > 0 ? formatBytes(memBytes) : '—';

        // PID
        const pid = d.unit_info?.main_pid || '0';
        document.getElementById('detail-pid').textContent = pid !== '0' ? pid : '—';

        // Restarts
        document.getElementById('detail-restarts').textContent = d.unit_info?.restart_count || '0';

        // Action buttons
        document.getElementById('detail-btn-start').style.display = d.running ? 'none' : '';
        document.getElementById('detail-btn-restart').style.display = d.running ? '' : 'none';
        document.getElementById('detail-btn-stop').style.display = d.running ? '' : 'none';

        // Config
        const configSection = document.getElementById('detail-config-section');
        if (d.config_path && d.config !== null) {
            configSection.style.display = '';
            document.getElementById('detail-config-path').textContent = d.config_path;
            document.getElementById('detail-config-editor').value = d.config || '';
        } else if (d.config_path && d.config === null) {
            configSection.style.display = '';
            document.getElementById('detail-config-path').textContent = d.config_path + ' (not found)';
            document.getElementById('detail-config-editor').value = '# Config file not found at ' + d.config_path;
        } else {
            configSection.style.display = 'none';
        }

        // Logs
        const logsEl = document.getElementById('detail-logs');
        if (d.logs && d.logs.length > 0) {
            logsEl.innerHTML = d.logs.map(line => {
                const escaped = line.replace(/</g, '&lt;').replace(/>/g, '&gt;');
                return `<div class="log-line">${escaped}</div>`;
            }).join('');
            logsEl.scrollTop = logsEl.scrollHeight;
        } else {
            logsEl.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">No logs available</div>';
        }
    } catch (e) {
        console.error('Failed to load component detail:', e);
        showToast('Failed to load component details', 'error');
    }
}

async function detailServiceAction(action) {
    if (!currentComponent) return;
    showToast(`${action}ing ${currentComponent}...`, 'info');
    try {
        const resp = await fetch(`/api/services/${currentComponent}/action`, {
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
        setTimeout(() => refreshComponentDetail(currentComponent), 1000);
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function saveConfig() {
    if (!currentComponent) return;
    const content = document.getElementById('detail-config-editor').value;
    showToast('Saving config...', 'info');
    try {
        const resp = await fetch(`/api/components/${currentComponent}/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message, 'success');
        } else {
            showToast(data.error || 'Save failed', 'error');
        }
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

// ─── Polling Loop ───
fetchMetrics();
fetchNodes();
fetchContainerStatus();
setInterval(fetchMetrics, 2000);
setInterval(fetchNodes, 10000);
setInterval(fetchContainerStatus, 15000);

// ─── Container Management ───

let dockerStats = {};
let containerPollTimer = null;

async function fetchContainerStatus() {
    try {
        const resp = await fetch('/api/containers/status');
        if (!resp.ok) return;
        const data = await resp.json();

        // Update Docker sidebar badge
        const dockerBadge = document.getElementById('docker-count');
        if (data.docker.installed) {
            dockerBadge.textContent = data.docker.container_count;
            dockerBadge.style.display = data.docker.container_count > 0 ? '' : 'none';
        } else {
            dockerBadge.style.display = 'none';
        }

        // Update LXC sidebar badge
        const lxcBadge = document.getElementById('lxc-count');
        if (data.lxc.installed) {
            lxcBadge.textContent = data.lxc.container_count;
            lxcBadge.style.display = data.lxc.container_count > 0 ? '' : 'none';
        } else {
            lxcBadge.style.display = 'none';
        }

        // Update Docker banner
        updateRuntimeBanner('docker', data.docker);
        updateRuntimeBanner('lxc', data.lxc);
    } catch (e) {
        // Silently fail
    }
}

function updateRuntimeBanner(runtime, status) {
    const badge = document.getElementById(`${runtime}-status-badge`);
    const version = document.getElementById(`${runtime}-version`);
    const installBtn = document.getElementById(`${runtime}-install-btn`);

    if (!badge) return;

    if (status.installed && status.running) {
        badge.textContent = `Running (${status.running_count}/${status.container_count})`;
        badge.style.background = 'rgba(16, 185, 129, 0.2)';
        badge.style.color = '#10b981';
        version.textContent = `v${status.version}`;
        installBtn.style.display = 'none';
    } else if (status.installed) {
        badge.textContent = 'Installed';
        badge.style.background = 'rgba(245, 158, 11, 0.2)';
        badge.style.color = '#f59e0b';
        version.textContent = `v${status.version}`;
        installBtn.style.display = 'none';
    } else {
        badge.textContent = 'Not Installed';
        badge.style.background = 'rgba(107, 114, 128, 0.2)';
        badge.style.color = '#6b7280';
        version.textContent = '';
        installBtn.style.display = '';
    }
}

async function installRuntime(runtime) {
    const btn = document.getElementById(`${runtime}-install-btn`);
    btn.textContent = 'Installing...';
    btn.disabled = true;

    try {
        const resp = await fetch('/api/containers/install', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ runtime }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message, 'success');
            fetchContainerStatus();
        } else {
            showToast(data.error || 'Installation failed', 'error');
        }
    } catch (e) {
        showToast('Installation failed: ' + e.message, 'error');
    } finally {
        btn.textContent = `Install ${runtime.charAt(0).toUpperCase() + runtime.slice(1)}`;
        btn.disabled = false;
    }
}

// ─── Docker ───

async function loadDockerContainers() {
    // Fetch runtime status first
    fetchContainerStatus();

    try {
        // Fetch containers and stats in parallel
        const [containersResp, statsResp, imagesResp] = await Promise.all([
            fetch('/api/containers/docker'),
            fetch('/api/containers/docker/stats'),
            fetch('/api/containers/docker/images'),
        ]);

        const containers = await containersResp.json();
        const stats = await statsResp.json();
        const images = await imagesResp.json();

        // Index stats by name
        dockerStats = {};
        stats.forEach(s => { dockerStats[s.name] = s; });

        renderDockerContainers(containers);
        renderDockerStats(stats);
        renderDockerImages(images);
    } catch (e) {
        console.error('Failed to load Docker containers:', e);
    }

    // Start polling for container stats
    if (containerPollTimer) clearInterval(containerPollTimer);
    containerPollTimer = setInterval(refreshDockerStats, 5000);
}

async function refreshDockerStats() {
    if (currentPage !== 'containers') {
        clearInterval(containerPollTimer);
        containerPollTimer = null;
        return;
    }
    try {
        const resp = await fetch('/api/containers/docker/stats');
        const stats = await resp.json();
        dockerStats = {};
        stats.forEach(s => { dockerStats[s.name] = s; });
        renderDockerStats(stats);

        // Update stats in table rows
        const rows = document.querySelectorAll('#docker-containers-table tr[data-name]');
        rows.forEach(row => {
            const name = row.dataset.name;
            const s = dockerStats[name];
            if (s) {
                const cpuCell = row.querySelector('.cpu-cell');
                const memCell = row.querySelector('.mem-cell');
                if (cpuCell) cpuCell.textContent = s.cpu_percent.toFixed(1) + '%';
                if (memCell) memCell.textContent = formatBytes(s.memory_usage);
            }
        });
    } catch (e) { /* silent */ }
}

function renderDockerContainers(containers) {
    const table = document.getElementById('docker-containers-table');
    const empty = document.getElementById('docker-empty');

    if (containers.length === 0) {
        table.innerHTML = '';
        empty.style.display = '';
        return;
    }
    empty.style.display = 'none';

    table.innerHTML = containers.map(c => {
        const s = dockerStats[c.name] || {};
        const isRunning = c.state === 'running';
        const isPaused = c.state === 'paused';
        const stateColor = isRunning ? '#10b981' : (isPaused ? '#f59e0b' : '#6b7280');
        const ports = c.ports.length > 0 ? c.ports.join('<br>') : '-';

        return `<tr data-name="${c.name}">
            <td><strong>${c.name}</strong><br><span style="font-size:11px;color:var(--text-muted)">${c.id.substring(0, 12)}</span></td>
            <td>${c.image}</td>
            <td><span style="color:${stateColor}">●</span> ${c.status}</td>
            <td class="cpu-cell">${s.cpu_percent !== undefined ? s.cpu_percent.toFixed(1) + '%' : '-'}</td>
            <td class="mem-cell">${s.memory_usage ? formatBytes(s.memory_usage) : '-'}</td>
            <td style="font-size:11px;">${ports}</td>
            <td>
                ${isRunning ? `
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'stop')" title="Stop">⏹</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'restart')" title="Restart">🔄</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'pause')" title="Pause">⏸</button>
                ` : isPaused ? `
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'unpause')" title="Unpause">▶</button>
                ` : `
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'start')" title="Start">▶</button>
                    <button class="btn btn-sm" style="margin:2px;color:#ef4444;" onclick="dockerAction('${c.name}', 'remove')" title="Remove">🗑</button>
                `}
                <button class="btn btn-sm" style="margin:2px;" onclick="viewContainerLogs('docker', '${c.name}')" title="Logs">📜</button>
                <button class="btn btn-sm" style="margin:2px;" onclick="cloneDockerContainer('${c.name}')" title="Clone">📋</button>
                <button class="btn btn-sm" style="margin:2px;" onclick="migrateDockerContainer('${c.name}')" title="Migrate">🚀</button>
            </td>
        </tr>`;
    }).join('');
}

function renderDockerStats(stats) {
    const summary = document.getElementById('docker-stats-summary');
    if (!stats || stats.length === 0) {
        summary.innerHTML = '';
        return;
    }

    const totalCpu = stats.reduce((sum, s) => sum + s.cpu_percent, 0);
    const totalMem = stats.reduce((sum, s) => sum + s.memory_usage, 0);
    const totalPids = stats.reduce((sum, s) => sum + s.pids, 0);
    const running = stats.length;

    summary.innerHTML = `
        <div class="stat-card">
            <div class="stat-icon">🐳</div>
            <div class="stat-info">
                <div class="stat-value">${running}</div>
                <div class="stat-label">Running</div>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">⚡</div>
            <div class="stat-info">
                <div class="stat-value">${totalCpu.toFixed(1)}%</div>
                <div class="stat-label">Total CPU</div>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">💾</div>
            <div class="stat-info">
                <div class="stat-value">${formatBytes(totalMem)}</div>
                <div class="stat-label">Total Memory</div>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon">🔧</div>
            <div class="stat-info">
                <div class="stat-value">${totalPids}</div>
                <div class="stat-label">Total PIDs</div>
            </div>
        </div>
    `;
}

function renderDockerImages(images) {
    const table = document.getElementById('docker-images-table');
    if (!images || images.length === 0) {
        table.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No images found</td></tr>';
        return;
    }
    table.innerHTML = images.map(img => `
        <tr>
            <td>${img.repository}</td>
            <td>${img.tag}</td>
            <td style="font-family:monospace;font-size:12px;">${img.id.substring(0, 12)}</td>
            <td>${img.size}</td>
            <td>${img.created}</td>
        </tr>
    `).join('');
}

async function dockerAction(container, action) {
    if (action === 'remove' && !confirm(`Remove container '${container}'? This cannot be undone.`)) return;

    try {
        const resp = await fetch(`/api/containers/docker/${container}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`${action} ${container}: OK`, 'success');
            setTimeout(loadDockerContainers, 500);
        } else {
            showToast(data.error || `Failed to ${action}`, 'error');
        }
    } catch (e) {
        showToast(`Failed: ${e.message}`, 'error');
    }
}

// ─── LXC ───

let lxcPollTimer = null;

async function loadLxcContainers() {
    fetchContainerStatus();

    try {
        const [containersResp, statsResp] = await Promise.all([
            fetch('/api/containers/lxc'),
            fetch('/api/containers/lxc/stats'),
        ]);

        const containers = await containersResp.json();
        const stats = await statsResp.json();

        // Index stats by name
        const lxcStats = {};
        stats.forEach(s => { lxcStats[s.name] = s; });

        renderLxcContainers(containers, lxcStats);
    } catch (e) {
        console.error('Failed to load LXC containers:', e);
    }

    if (lxcPollTimer) clearInterval(lxcPollTimer);
    lxcPollTimer = setInterval(async () => {
        if (currentPage !== 'lxc') { clearInterval(lxcPollTimer); lxcPollTimer = null; return; }
        loadLxcContainers();
    }, 10000);
}

function renderLxcContainers(containers, stats) {
    const table = document.getElementById('lxc-containers-table');
    const empty = document.getElementById('lxc-empty');

    if (containers.length === 0) {
        table.innerHTML = '';
        empty.style.display = '';
        return;
    }
    empty.style.display = 'none';

    table.innerHTML = containers.map(c => {
        const s = stats[c.name] || {};
        const isRunning = c.state === 'running';
        const stateColor = isRunning ? '#10b981' : '#6b7280';

        return `<tr>
            <td><strong>${c.name}</strong></td>
            <td><span style="color:${stateColor}">●</span> ${c.state}</td>
            <td>${s.cpu_percent !== undefined ? s.cpu_percent.toFixed(1) + '%' : '-'}</td>
            <td>${s.memory_usage ? formatBytes(s.memory_usage) + (s.memory_limit ? ' / ' + formatBytes(s.memory_limit) : '') : '-'}</td>
            <td>
                ${isRunning ? `
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'stop')" title="Stop">⏹</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'restart')" title="Restart">🔄</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'freeze')" title="Freeze">⏸</button>
                ` : `
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'start')" title="Start">▶</button>
                    <button class="btn btn-sm" style="margin:2px;color:#ef4444;" onclick="lxcAction('${c.name}', 'destroy')" title="Destroy">🗑</button>
                `}
                <button class="btn btn-sm" style="margin:2px;" onclick="viewContainerLogs('lxc', '${c.name}')" title="Logs">📜</button>
                <button class="btn btn-sm" style="margin:2px;" onclick="cloneLxcContainer('${c.name}')" title="Clone">📋</button>
            </td>
        </tr>`;
    }).join('');
}

async function lxcAction(container, action) {
    if (action === 'destroy' && !confirm(`Destroy LXC container '${container}'? This cannot be undone.`)) return;

    try {
        const resp = await fetch(`/api/containers/lxc/${container}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`${action} ${container}: OK`, 'success');
            setTimeout(loadLxcContainers, 500);
        } else {
            showToast(data.error || `Failed to ${action}`, 'error');
        }
    } catch (e) {
        showToast(`Failed: ${e.message}`, 'error');
    }
}

// ─── Shared Container Functions ───

async function viewContainerLogs(runtime, container) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `${container} — Logs`;
    body.innerHTML = '<p style="color:var(--text-muted);">Loading logs...</p>';
    modal.classList.add('active');

    try {
        const resp = await fetch(`/api/containers/${runtime}/${container}/logs`);
        const data = await resp.json();
        const logs = data.logs || [];

        body.innerHTML = `
            <pre style="background: var(--bg-primary); border: 1px solid var(--border); border-radius: 8px; padding: 12px;
                font-family: 'JetBrains Mono', monospace; font-size: 12px; max-height: 400px; overflow-y: auto;
                color: var(--text-primary); white-space: pre-wrap; word-break: break-all;">${logs.length > 0 ? logs.join('\n') : 'No logs available'}</pre>
        `;
    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Failed to load logs: ${e.message}</p>`;
    }
}

function closeContainerDetail() {
    document.getElementById('container-detail-modal').classList.remove('active');
}

// ─── Clone & Migrate Functions ───

async function cloneDockerContainer(name) {
    const newName = prompt(`Clone Docker container '${name}' — enter a name for the clone:`, name + '-clone');
    if (!newName) return;

    showToast(`Cloning ${name}...`, 'info');
    try {
        const resp = await fetch(`/api/containers/docker/${name}/clone`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_name: newName }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || `Cloned as '${newName}'`, 'success');
            setTimeout(loadDockerContainers, 500);
        } else {
            showToast(data.error || 'Clone failed', 'error');
        }
    } catch (e) {
        showToast(`Clone failed: ${e.message}`, 'error');
    }
}

async function migrateDockerContainer(name) {
    // Show a modal with node selection
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `Migrate Container: ${name}`;
    body.innerHTML = '<p style="color:var(--text-muted);">Loading cluster nodes...</p>';
    modal.classList.add('active');

    try {
        const resp = await fetch('/api/nodes');
        const nodes = await resp.json();

        let nodeOpts = '';
        if (nodes && nodes.length > 0) {
            nodeOpts = nodes.map(n => `<option value="${n.url || 'http://' + n.address + ':8553'}">${n.name || n.address} (${n.address})</option>`).join('');
        }

        body.innerHTML = `
            <div style="padding: 1rem;">
                <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                    This will export the container, transfer it to the target WolfStack node, and import it there.
                    The container will be stopped during migration.
                </p>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block; margin-bottom:4px; font-weight:600;">Target Node</label>
                    ${nodeOpts ? `<select id="migrate-target" style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                        ${nodeOpts}
                    </select>` : `<input id="migrate-target" type="text" placeholder="http://10.10.10.2:8553" style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">`}
                </div>
                <div style="margin-bottom: 1rem;">
                    <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                        <input type="checkbox" id="migrate-remove" checked>
                        Remove container from this machine after migration
                    </label>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-primary" onclick="doMigrate('${name}')">🚀 Migrate</button>
                    <button class="btn" onclick="closeContainerDetail()">Cancel</button>
                </div>
            </div>
        `;
    } catch (e) {
        body.innerHTML = `
            <div style="padding: 1rem;">
                <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                    Enter the URL of the target WolfStack node.
                </p>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block; margin-bottom:4px; font-weight:600;">Target URL</label>
                    <input id="migrate-target" type="text" placeholder="http://10.10.10.2:8553" style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                </div>
                <div style="margin-bottom: 1rem;">
                    <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                        <input type="checkbox" id="migrate-remove" checked>
                        Remove container from this machine after migration
                    </label>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-primary" onclick="doMigrate('${name}')">🚀 Migrate</button>
                    <button class="btn" onclick="closeContainerDetail()">Cancel</button>
                </div>
            </div>
        `;
    }
}

async function doMigrate(name) {
    const targetEl = document.getElementById('migrate-target');
    const removeEl = document.getElementById('migrate-remove');
    const targetUrl = targetEl.value.trim();
    const removeSource = removeEl.checked;

    if (!targetUrl) {
        showToast('Please enter a target URL', 'error');
        return;
    }

    closeContainerDetail();
    showToast(`Migrating ${name} to ${targetUrl}... This may take a while.`, 'info');

    try {
        const resp = await fetch(`/api/containers/docker/${name}/migrate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: targetUrl, remove_source: removeSource }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Migration complete', 'success');
            setTimeout(loadDockerContainers, 500);
        } else {
            showToast(data.error || 'Migration failed', 'error');
        }
    } catch (e) {
        showToast(`Migration failed: ${e.message}`, 'error');
    }
}

async function cloneLxcContainer(name) {
    const newName = prompt(`Clone LXC container '${name}' — enter a name for the clone:`, name + '-clone');
    if (!newName) return;

    showToast(`Cloning ${name}...`, 'info');
    try {
        const resp = await fetch(`/api/containers/lxc/${name}/clone`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_name: newName }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || `Cloned as '${newName}'`, 'success');
            setTimeout(loadLxcContainers, 500);
        } else {
            showToast(data.error || 'Clone failed', 'error');
        }
    } catch (e) {
        showToast(`Clone failed: ${e.message}`, 'error');
    }
}
