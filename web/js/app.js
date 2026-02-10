// WolfStack Dashboard — app.js

// ─── State ───
let currentPage = 'datacenter';
let currentComponent = null;
let currentNodeId = null;  // null = datacenter, node ID = specific server
let allNodes = [];         // cached node list
let cpuHistory = [];
let memHistory = [];
const MAX_HISTORY = 60;

// ─── API URL helper — route through proxy for remote nodes ───
function apiUrl(path) {
    if (!currentNodeId) return path; // datacenter view
    const node = allNodes.find(n => n.id === currentNodeId);
    if (!node) return path;
    if (node.is_self) return path;
    // Proxy through local server — strip leading /api/ from path
    const cleanPath = path.replace(/^\/api\//, '');
    return `/api/nodes/${currentNodeId}/proxy/${cleanPath}`;
}

// ─── Page Navigation ───
function selectView(page) {
    currentPage = page;
    currentNodeId = null;

    document.querySelectorAll('.page-view').forEach(p => p.style.display = 'none');
    const el = document.getElementById(`page-${page}`);
    if (el) el.style.display = 'block';

    // Highlight active nav item
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');

    document.getElementById('page-title').textContent = page === 'datacenter' ? 'Datacenter' : page;

    if (page === 'datacenter') {
        renderDatacenterOverview();
    }
}

function selectServerView(nodeId, view) {
    currentNodeId = nodeId;
    currentPage = view;

    const node = allNodes.find(n => n.id === nodeId);
    const hostname = node ? node.hostname : nodeId;

    document.querySelectorAll('.page-view').forEach(p => p.style.display = 'none');
    const el = document.getElementById(`page-${view}`);
    if (el) el.style.display = 'block';

    // Highlight active tree item
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const treeItem = document.querySelector(`.server-child-item[data-node="${nodeId}"][data-view="${view}"]`);
    if (treeItem) treeItem.classList.add('active');

    const viewTitles = {
        dashboard: 'Dashboard',
        components: 'Components',
        services: 'Services',
        containers: 'Docker',
        lxc: 'LXC',
        certificates: 'Certificates',
        monitoring: 'Live Metrics',
    };
    document.getElementById('page-title').textContent = `${hostname} — ${viewTitles[view] || view}`;
    document.getElementById('hostname-display').textContent = `${hostname} (${node?.address}:${node?.port})`;

    // Load data for the view
    if (view === 'dashboard') {
        if (node?.metrics) updateDashboard(node.metrics);
    }
    if (view === 'components') { loadComponents(); loadRunningContainers(); }
    if (view === 'services') loadComponents();
    if (view === 'containers') loadDockerContainers();
    if (view === 'lxc') loadLxcContainers();
    if (view === 'monitoring') initCharts();
}

// ─── Server Tree ───
function buildServerTree(nodes) {
    allNodes = nodes;
    const tree = document.getElementById('server-tree');
    if (!tree) return;

    if (nodes.length === 0) {
        tree.innerHTML = '<div style="padding: 8px 16px; color: var(--text-muted); font-size: 12px;">No servers yet. Click + Add Server.</div>';
        return;
    }

    // Preserve expanded state before rebuild
    const expandedNodes = new Set();
    document.querySelectorAll('.server-node-children.expanded').forEach(el => {
        const id = el.id?.replace('children-', '');
        if (id) expandedNodes.add(id);
    });

    // Sort: self first, then alphabetically
    const sorted = [...nodes].sort((a, b) => {
        if (a.is_self) return -1;
        if (b.is_self) return 1;
        return a.hostname.localeCompare(b.hostname);
    });

    // On first build (no expanded state saved yet), expand self node
    const isFirstBuild = expandedNodes.size === 0;

    tree.innerHTML = sorted.map(node => {
        const shouldExpand = isFirstBuild ? node.is_self : expandedNodes.has(node.id);
        return `
        <div class="server-tree-node">
            <div class="server-node-header" onclick="toggleServerNode('${node.id}')">
                <span class="tree-toggle ${shouldExpand ? 'expanded' : ''}" id="toggle-${node.id}">▶</span>
                <span class="server-dot ${node.online ? 'online' : 'offline'}"></span>
                <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">🖥️ ${node.hostname}</span>
                ${node.is_self ? '<span class="self-badge">this</span>' : `<span class="remove-server-btn" onclick="event.stopPropagation(); confirmRemoveServer('${node.id}', '${node.hostname}')" title="Remove server">🗑️</span>`}
            </div>
            <div class="server-node-children ${shouldExpand ? 'expanded' : ''}" id="children-${node.id}">
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="dashboard" onclick="selectServerView('${node.id}', 'dashboard')">
                    <span class="icon">📊</span> Dashboard
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="components" onclick="selectServerView('${node.id}', 'components')">
                    <span class="icon">📦</span> Components
                    <span class="badge" style="font-size:10px; padding:1px 6px;">${node.components.filter(c => c.installed).length}</span>
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="services" onclick="selectServerView('${node.id}', 'services')">
                    <span class="icon">⚡</span> Services
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="containers" onclick="selectServerView('${node.id}', 'containers')">
                    <span class="icon">🐳</span> Docker
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="lxc" onclick="selectServerView('${node.id}', 'lxc')">
                    <span class="icon">📦</span> LXC
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="certificates" onclick="selectServerView('${node.id}', 'certificates')">
                    <span class="icon">🔒</span> Certificates
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="monitoring" onclick="selectServerView('${node.id}', 'monitoring')">
                    <span class="icon">📈</span> Metrics
                </a>
            </div>
        </div>
    `}).join('');

    // Restore active highlight
    if (currentNodeId && currentPage) {
        const active = document.querySelector(`.server-child-item[data-node="${currentNodeId}"][data-view="${currentPage}"]`);
        if (active) active.classList.add('active');
    }
}

function toggleServerNode(nodeId) {
    const children = document.getElementById(`children-${nodeId}`);
    const toggle = document.getElementById(`toggle-${nodeId}`);
    if (children && toggle) {
        children.classList.toggle('expanded');
        toggle.classList.toggle('expanded');
    }
}

// ─── Datacenter Overview ───
function renderDatacenterOverview() {
    const nodes = allNodes;
    const onlineCount = nodes.filter(n => n.online).length;
    const totalComponents = nodes.reduce((sum, n) => sum + n.components.filter(c => c.installed).length, 0);

    document.getElementById('dc-total-servers').textContent = nodes.length;
    document.getElementById('dc-online-servers').textContent = onlineCount;
    document.getElementById('dc-offline-servers').textContent = nodes.length - onlineCount;
    document.getElementById('dc-total-components').textContent = totalComponents;

    const container = document.getElementById('datacenter-servers');
    if (nodes.length === 0) {
        container.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:40px; grid-column:1/-1;">No servers added yet. Click <strong>+ Add Server</strong> in the sidebar.</div>';
        return;
    }

    container.innerHTML = nodes.map(node => {
        const m = node.metrics;
        if (!m) {
            return `<div class="card">
                <div class="card-header"><h3>🖥️ ${node.hostname}${node.is_self ? ' <span style="color:var(--accent-light); font-size:12px;">(this)</span>' : ''}</h3></div>
                <div class="card-body" style="text-align:center; color:var(--text-muted); padding:30px;">
                    <span style="color:var(--danger);">● Offline</span>
                </div>
            </div>`;
        }

        const cpuPct = m.cpu_usage_percent.toFixed(1);
        const memPct = m.memory_percent.toFixed(1);
        const root = m.disks?.find(d => d.mount_point === '/') || m.disks?.[0];
        const diskPct = root ? root.usage_percent.toFixed(1) : '—';

        return `<div class="card" style="cursor:pointer;" onclick="selectServerView('${node.id}', 'dashboard')">
            <div class="card-header">
                <h3>
                    <span class="server-dot online" style="display:inline-block; vertical-align:middle; margin-right:8px;"></span>
                    🖥️ ${node.hostname}${node.is_self ? ' <span style="color:var(--accent-light); font-size:12px;">(this)</span>' : ''}
                </h3>
                <span style="color:var(--text-muted); font-size:12px;">${node.address}:${node.port}</span>
            </div>
            <div class="card-body">
                <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; text-align:center;">
                    <div>
                        <div style="font-size:24px; font-weight:700; color:var(--accent-light);">${cpuPct}%</div>
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">CPU</div>
                        <div class="progress-bar" style="margin-top:6px;"><div class="fill ${progressClass(m.cpu_usage_percent)}" style="width:${cpuPct}%"></div></div>
                    </div>
                    <div>
                        <div style="font-size:24px; font-weight:700; color:var(--success);">${memPct}%</div>
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Memory</div>
                        <div class="progress-bar" style="margin-top:6px;"><div class="fill ${progressClass(m.memory_percent)}" style="width:${memPct}%"></div></div>
                    </div>
                    <div>
                        <div style="font-size:24px; font-weight:700; color:var(--warning);">${diskPct}%</div>
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Disk</div>
                        <div class="progress-bar" style="margin-top:6px;"><div class="fill ${progressClass(parseFloat(diskPct) || 0)}" style="width:${diskPct}%"></div></div>
                    </div>
                </div>
                <div style="margin-top:12px; display:flex; gap:6px; flex-wrap:wrap;">
                    ${node.components.filter(c => c.installed).map(c =>
            `<span style="font-size:11px; padding:2px 8px; border-radius:4px; background:${c.running ? 'var(--success-bg)' : 'var(--danger-bg)'}; color:${c.running ? 'var(--success)' : 'var(--danger)'};">
                            ${c.component}
                        </span>`
        ).join('')}
                </div>
            </div>
        </div>`;
    }).join('');
}

// Handle hash navigation
window.addEventListener('hashchange', () => {
    const page = location.hash.replace('#', '') || 'datacenter';
    selectView(page);
});
if (location.hash) selectView(location.hash.replace('#', ''));

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
        const resp = await fetch(apiUrl('/api/metrics'));
        if (handleAuthError(resp)) return;
        const m = await resp.json();
        // Only update dashboard if we're viewing a server's dashboard
        if (currentPage === 'dashboard' && currentNodeId) {
            updateDashboard(m);
        }
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
        allNodes = nodes;
        buildServerTree(nodes);

        // Refresh datacenter overview if we're viewing it
        if (currentPage === 'datacenter') {
            renderDatacenterOverview();
        }

        // Update current node metrics if viewing a server dashboard
        if (currentPage === 'dashboard' && currentNodeId) {
            const node = nodes.find(n => n.id === currentNodeId);
            if (node?.metrics) updateDashboard(node.metrics);
        }
    } catch (e) {
        console.error('Failed to fetch nodes:', e);
    }
}

// ─── Components ───
async function loadComponents() {
    try {
        // If we have a node selected and it has components cached, use those for initial render
        if (currentNodeId) {
            const node = allNodes.find(n => n.id === currentNodeId);
            if (node?.components) {
                renderComponents(node.components);
                renderServices(node.components);
            }
        }
        // Also fetch live data
        const resp = await fetch(apiUrl('/api/components'));
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

function confirmRemoveServer(id, hostname) {
    if (confirm(`Remove server "${hostname}" from the cluster?`)) {
        removeServer(id);
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
    // Show the component-detail page directly
    document.querySelectorAll('.page-view').forEach(p => p.style.display = 'none');
    const el = document.getElementById('page-component-detail');
    if (el) el.style.display = 'block';
    currentPage = 'component-detail';
    const cName = name.charAt(0).toUpperCase() + name.slice(1);
    document.getElementById('page-title').textContent = cName;
    await refreshComponentDetail(name);
}

async function refreshComponentDetail(name) {
    try {
        const resp = await fetch(apiUrl(`/api/components/${name}/detail`));
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
        const resp = await fetch(apiUrl(`/api/services/${currentComponent}/action`), {
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
        const resp = await fetch(apiUrl(`/api/components/${currentComponent}/config`), {
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
fetchNodes();  // This builds the server tree and populates allNodes
setInterval(fetchNodes, 10000);  // Refresh tree + metrics every 10s

// ─── Container Management ───

let dockerStats = {};
let containerPollTimer = null;

async function fetchContainerStatus() {
    try {
        const resp = await fetch(apiUrl('/api/containers/status'));
        if (!resp.ok) return;
        const data = await resp.json();

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
            fetch(apiUrl('/api/containers/docker')),
            fetch(apiUrl('/api/containers/docker/stats')),
            fetch(apiUrl('/api/containers/docker/images')),
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
        const resp = await fetch(apiUrl('/api/containers/docker/stats'));
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
            <td style="font-size:12px; font-family:monospace;">${c.ip_address || '-'}</td>
            <td class="cpu-cell">${s.cpu_percent !== undefined ? s.cpu_percent.toFixed(1) + '%' : '-'}</td>
            <td class="mem-cell">${s.memory_usage ? formatBytes(s.memory_usage) : '-'}</td>
            <td style="font-size:11px;">${ports}</td>
            <td>
                ${isRunning ? `
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'stop')" title="Stop">⏹</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'restart')" title="Restart">🔄</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="dockerAction('${c.name}', 'pause')" title="Pause">⏸</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="openConsole('docker', '${c.name}')" title="Console">💻</button>
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
            fetch(apiUrl('/api/containers/lxc')),
            fetch(apiUrl('/api/containers/lxc/stats')),
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
            <td style="font-size:12px; font-family:monospace;">${c.ip_address || '-'}</td>
            <td>${s.cpu_percent !== undefined ? s.cpu_percent.toFixed(1) + '%' : '-'}</td>
            <td>${s.memory_usage ? formatBytes(s.memory_usage) + (s.memory_limit ? ' / ' + formatBytes(s.memory_limit) : '') : '-'}</td>
            <td>
                ${isRunning ? `
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'stop')" title="Stop">⏹</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'restart')" title="Restart">🔄</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'freeze')" title="Freeze">⏸</button>
                    <button class="btn btn-sm" style="margin:2px;" onclick="openConsole('lxc', '${c.name}')" title="Console">💻</button>
                ` : `
                    <button class="btn btn-sm" style="margin:2px;" onclick="lxcAction('${c.name}', 'start')" title="Start">▶</button>
                    <button class="btn btn-sm" style="margin:2px;color:#ef4444;" onclick="lxcAction('${c.name}', 'destroy')" title="Destroy">🗑</button>
                `}
                <button class="btn btn-sm" style="margin:2px;" onclick="viewContainerLogs('lxc', '${c.name}')" title="Logs">📜</button>
                <button class="btn btn-sm" style="margin:2px;" onclick="openLxcSettings('${c.name}')" title="Settings">⚙️</button>
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

// ─── LXC Settings Editor ───

async function openLxcSettings(name) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `${name} — Settings`;
    body.innerHTML = '<p style="color:var(--text-muted);">Loading config...</p>';
    modal.classList.add('active');

    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${name}/config`));
        const data = await resp.json();
        const config = data.config || '';

        body.innerHTML = `
            <div style="margin-bottom: 12px;">
                <div style="display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap;">
                    <button class="btn btn-sm" onclick="addMountPoint('${name}')">📁 Add Mount Point</button>
                    <button class="btn btn-sm" onclick="addWolfDiskMount('${name}')">🐺 Mount WolfDisk</button>
                    <button class="btn btn-sm" onclick="addMemoryLimit('${name}')">💾 Set Memory Limit</button>
                    <button class="btn btn-sm" onclick="addCpuLimit('${name}')">⚡ Set CPU Limit</button>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
                    Edit the raw LXC config below. Changes take effect after container restart.
                </div>
            </div>
            <textarea id="lxc-config-editor" style="width:100%; height:350px; background:var(--bg-primary); color:var(--text-primary);
                border:1px solid var(--border); border-radius:8px; padding:12px; font-family:'JetBrains Mono', monospace;
                font-size:12px; resize:vertical; line-height:1.5;">${escapeHtml(config)}</textarea>
            <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:12px;">
                <button class="btn btn-sm" onclick="closeContainerDetail()">Cancel</button>
                <button class="btn btn-sm btn-primary" onclick="saveLxcSettings('${name}')">💾 Save Config</button>
            </div>
        `;
    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Failed to load config: ${e.message}</p>`;
    }
}

function addMountPoint(name) {
    const src = prompt('Host path (e.g. /mnt/data):');
    if (!src) return;
    const dest = prompt('Container path (e.g. /mnt/data):', src);
    if (!dest) return;
    const editor = document.getElementById('lxc-config-editor');
    editor.value += `\nlxc.mount.entry = ${src} ${dest.replace(/^\//, '')} none bind,create=dir 0 0\n`;
}

function addWolfDiskMount(name) {
    const src = prompt('WolfDisk mount path on host (e.g. /mnt/wolfdisk):', '/mnt/wolfdisk');
    if (!src) return;
    const dest = prompt('Mount path inside container:', '/mnt/shared');
    if (!dest) return;
    const editor = document.getElementById('lxc-config-editor');
    editor.value += `\n# WolfDisk shared folder\nlxc.mount.entry = ${src} ${dest.replace(/^\//, '')} none bind,create=dir 0 0\n`;
}

function addMemoryLimit(name) {
    const mem = prompt('Memory limit (e.g. 512M, 1G, 2G):', '1G');
    if (!mem) return;
    const editor = document.getElementById('lxc-config-editor');
    // Remove existing memory limit if present
    editor.value = editor.value.replace(/\nlxc\.cgroup.*memory.*\n/g, '\n');
    editor.value += `\nlxc.cgroup2.memory.max = ${mem}\n`;
}

function addCpuLimit(name) {
    const cpus = prompt('CPU cores (e.g. 1, 2, 4):', '2');
    if (!cpus) return;
    const editor = document.getElementById('lxc-config-editor');
    editor.value = editor.value.replace(/\nlxc\.cgroup.*cpu.*\n/g, '\n');
    // cpuset: 0 = 1 core, 0-1 = 2 cores, etc.
    const max = parseInt(cpus) - 1;
    const cpuset = max <= 0 ? '0' : `0-${max}`;
    editor.value += `\nlxc.cgroup2.cpuset.cpus = ${cpuset}\n`;
}

async function saveLxcSettings(name) {
    const content = document.getElementById('lxc-config-editor').value;
    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${name}/config`), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`Config saved for ${name}. Restart container to apply.`, 'success');
            closeContainerDetail();
        } else {
            showToast(data.error || 'Failed to save config', 'error');
        }
    } catch (e) {
        showToast(`Failed: ${e.message}`, 'error');
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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

// ─── Container Creation ───

function showDockerCreate() {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = 'Create Docker Container — Step 1: Select Image';
    body.innerHTML = `
        <div style="padding: 1rem;">
            <div style="margin-bottom: 1rem;">
                <p style="color:var(--text-muted); font-size:13px; margin-bottom:12px;">
                    Search Docker Hub for an image, or type a custom image name below.
                </p>
                <div style="display:flex; gap:8px; margin-bottom:12px;">
                    <input id="docker-search-input" type="text" placeholder="Search for images (e.g. debian, nginx, postgres...)"
                        style="flex:1; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:14px;"
                        onkeypress="if(event.key==='Enter') searchDockerHub()">
                    <button class="btn btn-primary" onclick="searchDockerHub()">Search</button>
                </div>
                <div id="docker-search-results"></div>
                <div style="margin-top:12px; padding-top:12px; border-top:1px solid var(--border);">
                    <p style="font-size:13px; color:var(--text-muted); margin-bottom:8px;">Or enter a custom image name:</p>
                    <div style="display:flex; gap:8px;">
                        <input id="docker-custom-image" type="text" placeholder="e.g. myregistry/myimage:latest"
                            style="flex:1; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:14px;">
                        <button class="btn btn-primary" onclick="selectDockerImage(document.getElementById('docker-custom-image').value.trim())" style="font-size:12px;">Use This →</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    modal.classList.add('active');
    setTimeout(() => document.getElementById('docker-search-input').focus(), 100);
}

async function searchDockerHub() {
    const query = document.getElementById('docker-search-input').value.trim();
    if (!query) return;

    const results = document.getElementById('docker-search-results');
    results.innerHTML = '<p style="color:var(--text-muted); text-align:center; padding:12px;">Searching Docker Hub...</p>';

    try {
        const resp = await fetch(`/api/containers/docker/search?q=${encodeURIComponent(query)}`);
        const data = await resp.json();

        if (!data.length) {
            results.innerHTML = '<p style="color:var(--text-muted); text-align:center; padding:12px;">No images found.</p>';
            return;
        }

        results.innerHTML = `
            <div style="max-height:250px; overflow-y:auto; border:1px solid var(--border); border-radius:8px;">
                <table class="data-table" style="margin:0;">
                    <thead><tr><th>Image</th><th>Description</th><th>⭐</th><th></th></tr></thead>
                    <tbody>
                        ${data.map(r => `<tr>
                            <td><strong>${r.name}</strong>${r.official ? ' <span style="color:#10b981; font-size:11px;">✓ Official</span>' : ''}</td>
                            <td style="font-size:12px; max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.description}</td>
                            <td style="text-align:center;">${r.stars}</td>
                            <td><button class="btn btn-sm btn-primary" onclick="selectDockerImage('${r.name}')" style="font-size:11px;">Select →</button></td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (e) {
        results.innerHTML = `<p style="color:#ef4444; text-align:center; padding:12px;">Search failed: ${e.message}</p>`;
    }
}

function selectDockerImage(imageName) {
    if (!imageName) { showToast('Please enter an image name', 'error'); return; }

    // Move to Step 2: Configuration
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = 'Create Docker Container — Step 2: Configure';

    const safeName = imageName.replace(/[\/:.]/g, '-');

    body.innerHTML = `
        <div style="padding: 1rem;">
            <div style="margin-bottom:16px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                <div style="display:flex; align-items:center; gap:12px;">
                    <span style="font-size:24px;">🐳</span>
                    <div style="flex:1;">
                        <strong style="font-size:15px;">${imageName}</strong>
                        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">Docker Hub image</div>
                    </div>
                    <button class="btn btn-sm" onclick="showDockerCreate()" style="font-size:11px;">← Change</button>
                </div>
            </div>
            <input type="hidden" id="docker-create-image" value="${imageName}">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">Container Name</label>
                    <input id="docker-create-name" type="text" value="${safeName}" placeholder="my-container"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                </div>
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">Image Tag</label>
                    <input id="docker-create-tag" type="text" value="latest" placeholder="latest"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                </div>
            </div>
            <div style="margin-bottom:12px;">
                <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">Port Mappings <span style="font-weight:400; color:var(--text-muted);">(comma-separated, e.g. 8080:80, 443:443)</span></label>
                <input id="docker-create-ports" type="text" placeholder="8080:80"
                    style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
            </div>
            <div style="margin-bottom:12px;">
                <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">Environment Variables <span style="font-weight:400; color:var(--text-muted);">(comma-separated, e.g. KEY=val)</span></label>
                <input id="docker-create-env" type="text" placeholder="MYSQL_ROOT_PASSWORD=secret"
                    style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:12px;">
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">🧠 Memory Limit</label>
                    <select id="docker-create-memory"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:13px;">
                        <option value="">Unlimited</option>
                        <option value="256m">256 MB</option>
                        <option value="512m">512 MB</option>
                        <option value="1g" selected>1 GB</option>
                        <option value="2g">2 GB</option>
                        <option value="4g">4 GB</option>
                        <option value="8g">8 GB</option>
                        <option value="16g">16 GB</option>
                    </select>
                </div>
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">⚡ CPU Cores</label>
                    <select id="docker-create-cpus"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:13px;">
                        <option value="">Unlimited</option>
                        <option value="1" selected>1 core</option>
                        <option value="2">2 cores</option>
                        <option value="4">4 cores</option>
                        <option value="8">8 cores</option>
                    </select>
                </div>
            </div>
            <div id="docker-wolfnet-section" style="margin-bottom:12px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                    <span>🐺</span>
                    <strong style="font-size:13px;">WolfNet Networking</strong>
                    <span id="docker-wolfnet-status" style="font-size:12px; color:var(--text-muted);">Checking...</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <label style="font-size:13px; white-space:nowrap;">Assign IP:</label>
                    <input id="docker-wolfnet-ip" type="text" placeholder="auto"
                        style="flex:1; padding:6px 10px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:13px;">
                    <span style="font-size:12px; color:var(--text-muted);">Leave empty for no WolfNet</span>
                </div>
            </div>
            <div style="display:flex; gap:8px;">
                <button class="btn btn-primary" onclick="createDockerContainer()">🐳 Pull & Create</button>
                <button class="btn" onclick="showDockerCreate()">← Back</button>
                <button class="btn" onclick="closeContainerDetail()">Cancel</button>
            </div>
        </div>
    `;

    document.getElementById('docker-create-name').focus();

    // Fetch WolfNet status
    fetch(apiUrl('/api/wolfnet/status'))
        .then(r => r.json())
        .then(status => {
            const statusEl = document.getElementById('docker-wolfnet-status');
            const ipInput = document.getElementById('docker-wolfnet-ip');
            if (status.available) {
                statusEl.innerHTML = '<span style="color:var(--success);">● Active</span> — ' + status.subnet;
                ipInput.value = status.next_available_ip;
                ipInput.placeholder = status.next_available_ip;
            } else {
                statusEl.innerHTML = '<span style="color:var(--text-muted);">● Not available</span>';
                ipInput.value = '';
                ipInput.placeholder = 'WolfNet not running';
                ipInput.disabled = true;
            }
        })
        .catch(() => {
            document.getElementById('docker-wolfnet-status').textContent = 'unavailable';
        });
}

async function createDockerContainer() {
    const name = document.getElementById('docker-create-name').value.trim();
    const image = document.getElementById('docker-create-image').value.trim();
    const portsStr = document.getElementById('docker-create-ports').value.trim();
    const envStr = document.getElementById('docker-create-env').value.trim();
    const wolfnet_ip = document.getElementById('docker-wolfnet-ip')?.value?.trim() || '';
    const memory_limit = document.getElementById('docker-create-memory')?.value || '';
    const cpu_cores = document.getElementById('docker-create-cpus')?.value || '';
    const storage_limit = document.getElementById('docker-create-storage')?.value || '';

    if (!name || !image) {
        showToast('Please enter a container name and image', 'error');
        return;
    }

    const ports = portsStr ? portsStr.split(',').map(s => s.trim()) : [];
    const env = envStr ? envStr.split(',').map(s => s.trim()) : [];

    closeContainerDetail();
    showToast(`Pulling image '${image}' and creating container...`, 'info');

    try {
        // Pull the image first
        const pullResp = await fetch(apiUrl('/api/containers/docker/pull'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image }),
        });
        const pullData = await pullResp.json();
        if (!pullResp.ok) {
            showToast(pullData.error || 'Failed to pull image', 'error');
            return;
        }
        showToast(pullData.message || `Image ${image} pulled`, 'success');

        // Create the container
        const createResp = await fetch(apiUrl('/api/containers/docker/create'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, image, ports, env, wolfnet_ip, memory_limit, cpu_cores, storage_limit }),
        });
        const createData = await createResp.json();
        if (createResp.ok) {
            showToast(createData.message || `Container '${name}' created!`, 'success');
            setTimeout(loadDockerContainers, 500);
        } else {
            showToast(createData.error || 'Failed to create container', 'error');
        }
    } catch (e) {
        showToast(`Create failed: ${e.message}`, 'error');
    }
}

// ─── LXC Container Creation ───

let lxcTemplatesCache = null;

function showLxcCreate() {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = 'Create LXC Container — Step 1: Select Template';
    body.innerHTML = '<p style="color:var(--text-muted); text-align:center; padding:2rem;">Loading available templates...</p>';
    modal.classList.add('active');

    loadLxcTemplates();
}

async function loadLxcTemplates() {
    const body = document.getElementById('container-detail-body');

    try {
        if (!lxcTemplatesCache) {
            const resp = await fetch('/api/containers/lxc/templates');
            lxcTemplatesCache = await resp.json();
        }

        const templates = lxcTemplatesCache;

        body.innerHTML = `
            <div style="padding: 1rem;">
                <div style="margin-bottom: 1rem;">
                    <p style="color:var(--text-muted); font-size:13px; margin-bottom:12px;">
                        ${templates.length} templates available from the LXC image server.
                        <strong>Variant</strong> indicates the image type: <span style="color:#10b981;">server</span> (default/minimal), <span style="color:#3b82f6;">cloud</span> (cloud-init), or <span style="color:#f59e0b;">desktop</span> (GUI — not recommended for containers).
                    </p>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input id="lxc-template-filter" type="text" placeholder="Filter templates (e.g. debian, ubuntu, alpine, default, cloud...)"
                            style="flex:1; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:14px;"
                            oninput="filterLxcTemplates()">
                    </div>
                    <div id="lxc-template-list" style="max-height:350px; overflow-y:auto; border:1px solid var(--border); border-radius:8px;">
                        <table class="data-table" style="margin:0;">
                            <thead><tr><th>Distribution</th><th>Release</th><th>Variant</th><th>Arch</th><th>Image Path</th><th></th></tr></thead>
                            <tbody id="lxc-template-tbody">
                                ${renderLxcTemplateRows(templates)}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
        setTimeout(() => document.getElementById('lxc-template-filter').focus(), 100);
    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444; padding:2rem; text-align:center;">Failed to load templates: ${e.message}</p>`;
    }
}

function variantBadge(variant) {
    const v = (variant || 'default').toLowerCase();
    if (v === 'cloud') return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:#3b82f620;color:#3b82f6;">☁ cloud</span>';
    if (v === 'desktop' || v === 'gui') return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:#f59e0b20;color:#f59e0b;">🖥 desktop</span>';
    return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:#10b98120;color:#10b981;">⚙ server</span>';
}

function variantDescription(variant) {
    const v = (variant || 'default').toLowerCase();
    if (v === 'cloud') return 'Cloud-init enabled image for automated provisioning';
    if (v === 'desktop' || v === 'gui') return '⚠️ Full desktop environment — heavy, not recommended for containers';
    return 'Minimal server image — recommended for containers';
}

function renderLxcTemplateRows(templates) {
    return templates.slice(0, 100).map(t => {
        const imagePath = `${t.distribution}/${t.release}/${t.architecture}/${t.variant || 'default'}`;
        return `<tr>
            <td><strong>${t.distribution}</strong></td>
            <td>${t.release}</td>
            <td>${variantBadge(t.variant)}</td>
            <td>${t.architecture}</td>
            <td style="font-size:11px; font-family:monospace; color:var(--text-muted);">${imagePath}</td>
            <td><button class="btn btn-sm btn-primary" onclick="selectLxcTemplate('${t.distribution}','${t.release}','${t.architecture}','${t.variant || 'default'}')" style="font-size:11px;">Select →</button></td>
        </tr>`;
    }).join('');
}

function filterLxcTemplates() {
    const query = document.getElementById('lxc-template-filter').value.toLowerCase();
    const filtered = (lxcTemplatesCache || []).filter(t =>
        t.distribution.toLowerCase().includes(query) ||
        t.release.toLowerCase().includes(query) ||
        t.architecture.toLowerCase().includes(query) ||
        (t.variant || 'default').toLowerCase().includes(query)
    );
    document.getElementById('lxc-template-tbody').innerHTML = renderLxcTemplateRows(filtered);
}

function selectLxcTemplate(distro, release, arch, variant) {
    // Move to Step 2: Configuration
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = 'Create LXC Container — Step 2: Configure';

    body.innerHTML = `
        <div style="padding: 1rem;">
            <div style="margin-bottom:16px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                <div style="display:flex; align-items:center; gap:12px; margin-bottom:8px;">
                    <span style="font-size:24px;">📦</span>
                    <div style="flex:1;">
                        <strong style="font-size:15px;">${distro} ${release}</strong>
                        <span style="margin-left:8px;">${variantBadge(variant)}</span>
                        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">${variantDescription(variant)}</div>
                        <div style="font-size:11px; font-family:monospace; color:var(--text-muted); margin-top:2px;">Image: ${distro}/${release}/${arch}/${variant}</div>
                    </div>
                    <button class="btn btn-sm" onclick="showLxcCreate()" style="font-size:11px;">← Change</button>
                </div>
            </div>
            <input type="hidden" id="lxc-create-distro" value="${distro}">
            <input type="hidden" id="lxc-create-release" value="${release}">
            <input type="hidden" id="lxc-create-arch" value="${arch}">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">Container Name</label>
                    <input id="lxc-create-name" type="text" value="${distro}-${release}" placeholder="my-container"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                </div>
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">🔑 Root Password</label>
                    <input id="lxc-create-password" type="password" placeholder="Set root password"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                </div>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">💾 Storage Location</label>
                    <select id="lxc-create-storage"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:13px;">
                        <option value="/var/lib/lxc">/var/lib/lxc (default)</option>
                    </select>
                </div>
                <div style="display:flex; align-items:end;">
                    <span id="lxc-storage-info" style="font-size:12px; color:var(--text-muted); padding-bottom:10px;"></span>
                </div>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">🧠 Memory Limit</label>
                    <select id="lxc-create-memory"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:13px;">
                        <option value="">Unlimited</option>
                        <option value="256M">256 MB</option>
                        <option value="512M">512 MB</option>
                        <option value="1G" selected>1 GB</option>
                        <option value="2G">2 GB</option>
                        <option value="4G">4 GB</option>
                        <option value="8G">8 GB</option>
                        <option value="16G">16 GB</option>
                    </select>
                </div>
                <div>
                    <label style="display:block; margin-bottom:4px; font-weight:600; font-size:13px;">⚡ CPU Cores</label>
                    <select id="lxc-create-cpus"
                        style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:13px;">
                        <option value="">Unlimited</option>
                        <option value="1" selected>1 core</option>
                        <option value="2">2 cores</option>
                        <option value="4">4 cores</option>
                        <option value="8">8 cores</option>
                        <option value="16">16 cores</option>
                    </select>
                </div>
            </div>
            <div id="lxc-wolfnet-section" style="margin-bottom:12px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                    <span>🐺</span>
                    <strong style="font-size:13px;">WolfNet Networking</strong>
                    <span id="lxc-wolfnet-status" style="font-size:12px; color:var(--text-muted);">Checking...</span>
                </div>
                <div id="lxc-wolfnet-ip-row" style="display:flex; align-items:center; gap:8px;">
                    <label style="font-size:13px; white-space:nowrap;">Assign IP:</label>
                    <input id="lxc-wolfnet-ip" type="text" placeholder="auto"
                        style="flex:1; padding:6px 10px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:13px;">
                    <span style="font-size:12px; color:var(--text-muted);">Leave empty for no WolfNet</span>
                </div>
            </div>
            <div style="display:flex; gap:8px;">
                <button class="btn btn-primary" onclick="createLxcContainer()">📦 Create Container</button>
                <button class="btn" onclick="showLxcCreate()">← Back</button>
                <button class="btn" onclick="closeContainerDetail()">Cancel</button>
            </div>
        </div>
    `;

    document.getElementById('lxc-create-name').focus();

    // Populate storage dropdown from disk metrics
    const node = currentNodeId ? allNodes.find(n => n.id === currentNodeId) : null;
    const storageSelect = document.getElementById('lxc-create-storage');
    const storageInfo = document.getElementById('lxc-storage-info');
    if (node?.metrics?.disks && node.metrics.disks.length > 0) {
        storageSelect.innerHTML = '';
        const rootDisk = node.metrics.disks.find(d => d.mount_point === '/');
        const rootFree = rootDisk ? ` (${formatBytes(rootDisk.available_bytes)} free)` : '';
        storageSelect.innerHTML += `<option value="/var/lib/lxc">/var/lib/lxc (default)${rootFree}</option>`;
        node.metrics.disks.forEach(d => {
            if (d.mount_point !== '/' && d.available_bytes > 1073741824) {
                const free = formatBytes(d.available_bytes);
                const path = d.mount_point + '/lxc';
                storageSelect.innerHTML += `<option value="${path}">${path} (${free} free)</option>`;
            }
        });
        if (rootDisk) {
            storageInfo.textContent = `Root: ${formatBytes(rootDisk.available_bytes)} free`;
        }
        storageSelect.onchange = () => {
            const sel = storageSelect.value;
            const disk = node.metrics.disks.find(d => sel.startsWith(d.mount_point));
            storageInfo.textContent = disk ? `${formatBytes(disk.available_bytes)} free` : '';
        };
    }

    // Fetch WolfNet status and suggest an IP
    fetch(apiUrl('/api/wolfnet/status'))
        .then(r => r.json())
        .then(status => {
            const statusEl = document.getElementById('lxc-wolfnet-status');
            const ipInput = document.getElementById('lxc-wolfnet-ip');
            if (status.available) {
                statusEl.innerHTML = '<span style="color:var(--success);">● Active</span> — ' + status.subnet;
                ipInput.value = status.next_available_ip;
                ipInput.placeholder = status.next_available_ip;
            } else {
                statusEl.innerHTML = '<span style="color:var(--text-muted);">● Not available</span>';
                ipInput.value = '';
                ipInput.placeholder = 'WolfNet not running';
                ipInput.disabled = true;
            }
        })
        .catch(() => {
            document.getElementById('lxc-wolfnet-status').textContent = 'unavailable';
        });
}

async function createLxcContainer() {
    const name = document.getElementById('lxc-create-name').value.trim();
    const distribution = document.getElementById('lxc-create-distro').value.trim();
    const release = document.getElementById('lxc-create-release').value.trim();
    const architecture = document.getElementById('lxc-create-arch').value.trim();
    const wolfnet_ip = document.getElementById('lxc-wolfnet-ip')?.value?.trim() || '';
    const storage_path = document.getElementById('lxc-create-storage')?.value || '';
    const root_password = document.getElementById('lxc-create-password')?.value?.trim() || '';
    const memory_limit = document.getElementById('lxc-create-memory')?.value || '';
    const cpu_cores = document.getElementById('lxc-create-cpus')?.value || '';

    if (!name || !distribution || !release || !architecture) {
        showToast('Please select a template and enter a container name', 'error');
        return;
    }

    if (!root_password) {
        showToast('Please set a root password for the container', 'error');
        return;
    }

    closeContainerDetail();
    showToast(`Creating LXC container '${name}' (${distribution} ${release})... This may take a minute.`, 'info');

    try {
        const resp = await fetch(apiUrl('/api/containers/lxc/create'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, distribution, release, architecture, wolfnet_ip, storage_path, root_password, memory_limit, cpu_cores }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || `Container '${name}' created!`, 'success');
            setTimeout(loadLxcContainers, 500);
        } else {
            showToast(data.error || 'Failed to create container', 'error');
        }
    } catch (e) {
        showToast(`Create failed: ${e.message}`, 'error');
    }
}

// ─── Console Logic ───
let consoleTerm = null;
let consoleWs = null;
let consoleFitAddon = null;

function openConsole(type, name) {
    window.open('/console.html?type=' + encodeURIComponent(type) + '&name=' + encodeURIComponent(name),
        'console_' + name, 'width=960,height=600,menubar=no,toolbar=no');
}

function fitConsole() { }
function consoleKeyHandler() { }
function closeConsole() { }

// ─── Container Component Installation ───

async function loadRunningContainers() {
    const select = document.getElementById('container-install-target');
    if (!select) return;

    try {
        const resp = await fetch(apiUrl('/api/containers/running'));
        const containers = await resp.json();

        if (containers.length === 0) {
            select.innerHTML = '<option value="">No running containers found</option>';
            return;
        }

        select.innerHTML = '<option value="">— Select a container —</option>' +
            containers.map(c => {
                const icon = c.runtime === 'docker' ? '🐳' : '📦';
                const detail = c.image ? ` (${c.image})` : '';
                return `<option value="${c.runtime}|${c.name}">${icon} ${c.name}${detail}</option>`;
            }).join('');
    } catch (e) {
        select.innerHTML = '<option value="">Failed to load containers</option>';
    }
}

async function installComponentInContainer() {
    const targetSelect = document.getElementById('container-install-target');
    const componentSelect = document.getElementById('container-install-component');
    const btn = document.getElementById('container-install-btn');
    const statusEl = document.getElementById('container-install-status');

    const targetVal = targetSelect?.value;
    const component = componentSelect?.value;

    if (!targetVal) {
        showToast('Please select a target container', 'error');
        return;
    }

    const [runtime, container] = targetVal.split('|');
    const componentName = componentSelect.options[componentSelect.selectedIndex].text;

    btn.disabled = true;
    btn.textContent = '⏳ Installing...';
    statusEl.style.display = 'block';
    statusEl.innerHTML = `<div style="padding: 10px; border-radius: 8px; background: var(--bg-primary); border: 1px solid var(--border);">
        <span style="color: var(--text-muted);">Installing ${componentName} into ${container}... This may take a minute.</span>
    </div>`;

    try {
        const resp = await fetch(apiUrl('/api/containers/install-component'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ runtime, container, component }),
        });
        const data = await resp.json();

        if (resp.ok) {
            showToast(data.message || 'Component installed successfully', 'success');
            statusEl.innerHTML = `<div style="padding: 10px; border-radius: 8px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); color: #10b981;">
                ✓ ${data.message || 'Installed successfully'}
            </div>`;
        } else {
            showToast(data.error || 'Installation failed', 'error');
            statusEl.innerHTML = `<div style="padding: 10px; border-radius: 8px; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #ef4444;">
                ✗ ${data.error || 'Installation failed'}
            </div>`;
        }
    } catch (e) {
        showToast('Install failed: ' + e.message, 'error');
        statusEl.innerHTML = `<div style="padding: 10px; border-radius: 8px; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #ef4444;">
            ✗ ${e.message}
        </div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = '📦 Install';
    }
}
