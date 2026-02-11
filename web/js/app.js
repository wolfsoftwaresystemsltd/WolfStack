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
        storage: 'Storage',
        certificates: 'Certificates',
        monitoring: 'Live Metrics',
    };
    document.getElementById('page-title').textContent = `${hostname} — ${viewTitles[view] || view}`;
    document.getElementById('hostname-display').textContent = `${hostname} (${node?.address}:${node?.port})`;

    // Load data for the view
    if (view === 'dashboard') {
        if (node?.metrics) updateDashboard(node.metrics);
    }
    if (view === 'components') loadComponents();
    if (view === 'services') loadComponents();
    if (view === 'containers') loadDockerContainers();
    if (view === 'lxc') loadLxcContainers();
    if (view === 'monitoring') initCharts();
    if (view === 'terminal') {
        // Open host terminal directly
        openConsole('host', hostname);
    }
    if (view === 'vms') loadVms();
    if (view === 'storage') loadStorageMounts();
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
                    ${node.docker_count ? `<span class="badge" style="font-size:10px; padding:1px 6px;">${node.docker_count}</span>` : ''}
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="lxc" onclick="selectServerView('${node.id}', 'lxc')">
                    <span class="icon">📦</span> LXC
                    ${node.lxc_count ? `<span class="badge" style="font-size:10px; padding:1px 6px;">${node.lxc_count}</span>` : ''}
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="vms" onclick="selectServerView('${node.id}', 'vms')">
                    <span class="icon">🖥️</span> Virtual Machines
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="storage" onclick="selectServerView('${node.id}', 'storage')">
                    <span class="icon">💾</span> Storage
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="certificates" onclick="selectServerView('${node.id}', 'certificates')">
                    <span class="icon">🔒</span> Certificates
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="monitoring" onclick="selectServerView('${node.id}', 'monitoring')">
                    <span class="icon">📈</span> Metrics
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="terminal" onclick="selectServerView('${node.id}', 'terminal')">
                    <span class="icon">💻</span> Terminal
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

    // Add Patreon support card after server cards
    container.innerHTML += `<div class="card" style="cursor:pointer; border: 1px dashed var(--border-color); display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:180px;" onclick="window.open('https://www.patreon.com/15362110/join', '_blank')">
        <div style="font-size:40px; margin-bottom:12px;">❤️</div>
        <h3 style="margin:0 0 8px 0; font-size:16px; color:var(--text-primary);">Support WolfStack</h3>
        <p style="margin:0; color:var(--text-muted); font-size:13px; text-align:center; padding:0 20px;">Help us build amazing open source infrastructure tools</p>
        <div style="margin-top:12px; padding:6px 16px; border-radius:6px; background:linear-gradient(135deg, #ff424d, #f96854); color:white; font-size:13px; font-weight:600;">Join on Patreon</div>
    </div>`;
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

const componentDocs = {
    wolfnet: 'https://wolfstack.org/wolfnet.html',
    wolfproxy: 'https://wolfstack.org/wolfproxy.html',
    wolfserve: 'https://wolfstack.org/wolfserve.html',
    wolfdisk: 'https://wolfstack.org/wolfdisk.html',
    wolfscale: 'https://wolfstack.org/wolfstack.html',
    certbot: 'https://wolfstack.org/quickstart.html',
};

function renderComponents(components) {
    const grid = document.getElementById('components-grid');
    grid.innerHTML = components.map(c => {
        const icon = componentIcons[c.component] || '📦';
        const statusClass = c.running ? 'running' : c.installed ? 'stopped' : 'not-installed';
        const statusText = c.running ? 'Running' : c.installed ? 'Stopped' : 'Not Installed';
        const statusColor = c.running ? 'var(--success)' : c.installed ? 'var(--text-muted)' : 'var(--warning)';
        const docUrl = componentDocs[c.component];
        const docLink = docUrl
            ? `<a href="${docUrl}" target="_blank" rel="noopener" onclick="event.stopPropagation()" 
                style="font-size: 12px; color: var(--accent-light); text-decoration: none; display: inline-flex; align-items: center; gap: 4px;">
                📖 Docs</a>`
            : '';

        return `
            <div class="component-card" onclick="openComponentDetail('${c.component}')">
                <div class="component-header">
                    <div class="component-icon">${icon}</div>
                    <div style="flex: 1;">
                        <div class="component-name">${c.component.charAt(0).toUpperCase() + c.component.slice(1)}</div>
                        <div class="component-desc">${c.version || ''}</div>
                    </div>
                    ${docLink}
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

// ─── Virtual Machines ───
async function loadVms() {
    try {
        const resp = await fetch(apiUrl('/api/vms'));
        if (handleAuthError(resp)) return;
        const vms = await resp.json();
        renderVms(vms);
    } catch (e) {
        console.error('Failed to load VMs:', e);
        showToast('Failed to load VMs', 'error');
    }
}

function renderVms(vms) {
    const table = document.getElementById('vms-table');
    const empty = document.getElementById('vms-empty');
    if (!table || !empty) return;

    if (vms.length === 0) {
        table.parentElement.style.display = 'none';
        empty.style.display = 'block';
        return;
    }

    table.parentElement.style.display = '';
    empty.style.display = 'none';

    table.innerHTML = vms.map(vm => {
        const statusText = vm.running ? 'Running' : 'Stopped';
        const statusColor = vm.running ? 'var(--success)' : 'var(--danger)';

        const vncText = (vm.running && vm.vnc_port)
            ? (vm.vnc_ws_port
                ? `<a href="/vnc.html?name=${encodeURIComponent(vm.name)}&port=${vm.vnc_ws_port}" target="_blank" 
                    class="badge" style="cursor:pointer; text-decoration:none;" title="Open console in browser">🖥️ :${vm.vnc_port}</a>`
                : `<span class="badge" title="Connect with VNC client to port ${vm.vnc_port}">:${vm.vnc_port}</span>`)
            : '—';

        const wolfnetIp = vm.wolfnet_ip || '—';

        return `
            <tr>
                <td><strong>${vm.name}</strong>${vm.iso_path ? `<br><small style="color:var(--text-muted);">💿 ${vm.iso_path.split('/').pop()}</small>` : ''}</td>
                <td><span style="color:${statusColor}">● ${statusText}</span></td>
                <td>${vm.cpus} vCPU / ${vm.memory_mb} MB</td>
                <td>${vm.disk_size_gb} GiB${(vm.extra_disks && vm.extra_disks.length > 0) ? ` <span class="badge" style="font-size:10px;">+${vm.extra_disks.length} vol${vm.extra_disks.length > 1 ? 's' : ''}</span>` : ''}</td>
                <td>${wolfnetIp !== '—' ? `<span class="badge" style="background:var(--accent-bg); color:var(--accent);">${wolfnetIp}</span>` : '—'}</td>
                <td>${vncText}</td>
                <td>
                    <button class="btn btn-sm" style="margin:2px;" onclick="showVmLogs('${vm.name}')" title="Logs">📋</button>
                    ${vm.running ?
                `${vm.vnc_ws_port ? `<button class="btn btn-sm" style="margin:2px;" onclick="openVmVnc('${vm.name}', ${vm.vnc_ws_port})" title="Console">🖥️</button>` : ''}
                         <button class="btn btn-danger btn-sm" style="margin:2px;" onclick="vmAction('${vm.name}', 'stop')">Stop</button>` :
                `<button class="btn btn-sm" style="margin:2px;" onclick="showVmSettings('${vm.name}')" title="Settings">⚙️</button>
                         <button class="btn btn-success btn-sm" style="margin:2px;" onclick="vmAction('${vm.name}', 'start')">Start</button>
                         <button class="btn btn-danger btn-sm" style="margin:2px;" onclick="deleteVm('${vm.name}')">Delete</button>`
            }
                </td>
            </tr>
        `;
    }).join('');
}

// ─── Storage Manager ───

const MOUNT_TYPE_ICONS = { s3: '☁️', nfs: '🗄️', directory: '📁', wolfdisk: '🐺' };
const MOUNT_TYPE_LABELS = { s3: 'S3', nfs: 'NFS', directory: 'Directory', wolfdisk: 'WolfDisk' };
let allStorageMounts = [];  // cache for edit modal

async function loadStorageMounts() {
    try {
        const resp = await fetch(apiUrl('/api/storage/mounts'));
        if (!resp.ok) throw new Error('Failed to fetch mounts');
        const mounts = await resp.json();
        allStorageMounts = mounts;
        renderStorageMounts(mounts);
    } catch (e) {
        console.error('Failed to load storage mounts:', e);
        document.getElementById('storage-mounts-table').innerHTML = '';
        document.getElementById('storage-empty').style.display = 'block';
    }
}

function renderStorageMounts(mounts) {
    const tbody = document.getElementById('storage-mounts-table');
    const empty = document.getElementById('storage-empty');
    if (!tbody) return;

    if (mounts.length === 0) {
        tbody.innerHTML = '';
        empty.style.display = 'block';
        return;
    }
    empty.style.display = 'none';

    tbody.innerHTML = mounts.map(m => {
        const icon = MOUNT_TYPE_ICONS[m.type] || '📦';
        const typeLabel = MOUNT_TYPE_LABELS[m.type] || m.type;
        const isMounted = m.status === 'mounted';
        const isError = m.status === 'error';

        const statusBadge = isMounted
            ? '<span class="badge" style="background:var(--success); color:#fff; font-size:11px;">● Mounted</span>'
            : isError
                ? `<span class="badge" style="background:#ef4444; color:#fff; font-size:11px;" title="${m.error_message || ''}">✗ Error</span>`
                : '<span class="badge" style="background:var(--bg-tertiary); color:var(--text-muted); font-size:11px;">○ Unmounted</span>';

        const globalBadge = m.global
            ? '<span class="badge" style="background:rgba(59,130,246,0.15); color:#60a5fa; font-size:10px; margin-left:4px;">🌐 Global</span>'
            : '';
        const autoBadge = m.auto_mount
            ? '<span class="badge" style="background:rgba(234,179,8,0.15); color:#fbbf24; font-size:10px; margin-left:4px;">⚡ Auto</span>'
            : '';

        const mountBtn = isMounted
            ? `<button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border); font-size:11px; padding:2px 8px;" onclick="unmountStorage('${m.id}')">⏏ Unmount</button>`
            : `<button class="btn btn-sm btn-success" style="font-size:11px; padding:2px 8px;" onclick="mountStorage('${m.id}')">▶ Mount</button>`;

        const syncBtn = m.global
            ? `<button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border); font-size:11px; padding:2px 8px;" onclick="syncStorageMount('${m.id}')" title="Sync to all cluster nodes">🔄 Sync</button>`
            : '';

        // Source display — show bucket prominently for S3
        let sourceDisplay = m.source;
        if (m.type === 's3' && m.s3_config) {
            const bucket = m.s3_config.bucket || '(no bucket)';
            const provider = m.s3_config.provider || 'S3';
            const endpoint = m.s3_config.endpoint ? `<br><small style="color:var(--text-muted); font-size:10px;">${m.s3_config.endpoint}</small>` : '';
            sourceDisplay = `<span class="badge" style="background:rgba(59,130,246,0.15); color:#60a5fa; font-size:10px; margin-right:4px;">${provider}</span><strong>${bucket}</strong>${endpoint}`;
        }

        return `<tr>
            <td style="font-weight:600;">${icon} ${m.name}</td>
            <td>${typeLabel}</td>
            <td style="font-size:12px; max-width:240px; overflow:hidden; text-overflow:ellipsis;" title="${m.source}">${sourceDisplay}</td>
            <td style="font-family:var(--font-mono); font-size:12px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${m.mount_point}">${m.mount_point}</td>
            <td>${statusBadge}</td>
            <td>${globalBadge}${autoBadge}</td>
            <td style="white-space:nowrap;">
                <button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border); font-size:11px; padding:2px 8px;" onclick="openEditMount('${m.id}')" title="Settings">⚙️</button>
                <button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border); font-size:11px; padding:2px 8px;" onclick="duplicateStorageMount('${m.id}')" title="Duplicate">📋</button>
                ${mountBtn}
                ${syncBtn}
                <button class="btn btn-sm btn-danger" style="font-size:11px; padding:2px 8px;" onclick="deleteStorageMount('${m.id}', '${m.name}')">🗑️</button>
            </td>
        </tr>`;
    }).join('');
}

// ─── Modal Control ───

function showCreateMountModal() {
    document.getElementById('create-mount-modal').classList.add('active');
    onMountTypeChange();
}

function closeMountModal() {
    document.getElementById('create-mount-modal').classList.remove('active');
    // Reset form
    document.getElementById('mount-name').value = '';
    document.getElementById('mount-point').value = '';
    document.getElementById('mount-type').value = 's3';
    document.getElementById('s3-bucket').value = '';
    document.getElementById('s3-access-key').value = '';
    document.getElementById('s3-secret-key').value = '';
    document.getElementById('s3-region').value = '';
    document.getElementById('s3-endpoint').value = '';
    document.getElementById('mount-global').checked = false;
    document.getElementById('mount-auto').checked = true;
    onMountTypeChange();
}

function showImportRcloneModal() {
    document.getElementById('import-rclone-modal').classList.add('active');
}

function closeImportRcloneModal() {
    document.getElementById('import-rclone-modal').classList.remove('active');
    document.getElementById('rclone-config-paste').value = '';
}

function onMountTypeChange() {
    const type = document.getElementById('mount-type').value;
    document.getElementById('s3-fields').style.display = type === 's3' ? 'block' : 'none';
    document.getElementById('nfs-fields').style.display = type === 'nfs' ? 'block' : 'none';
    document.getElementById('dir-fields').style.display = type === 'directory' ? 'block' : 'none';
    document.getElementById('wolfdisk-fields').style.display = type === 'wolfdisk' ? 'block' : 'none';
}

// ─── CRUD Operations ───

async function createStorageMount() {
    const name = document.getElementById('mount-name').value.trim();
    const type = document.getElementById('mount-type').value;
    const mount_point = document.getElementById('mount-point').value.trim();
    const global = document.getElementById('mount-global').checked;
    const auto_mount = document.getElementById('mount-auto').checked;

    if (!name) return alert('Name is required');

    let source = '';
    let s3_config = null;
    let nfs_options = null;

    if (type === 's3') {
        const bucket = document.getElementById('s3-bucket').value.trim();
        const access_key_id = document.getElementById('s3-access-key').value.trim();
        const secret_access_key = document.getElementById('s3-secret-key').value.trim();
        if (!access_key_id || !secret_access_key) return alert('S3 Access Key and Secret Key are required');
        s3_config = {
            access_key_id,
            secret_access_key,
            region: document.getElementById('s3-region').value.trim(),
            endpoint: document.getElementById('s3-endpoint').value.trim(),
            provider: document.getElementById('s3-provider').value,
            bucket
        };
        source = bucket ? `s3:${bucket}` : 's3:';
    } else if (type === 'nfs') {
        source = document.getElementById('nfs-source').value.trim();
        nfs_options = document.getElementById('nfs-options').value.trim() || null;
        if (!source) return alert('NFS source is required (e.g. 192.168.1.100:/data)');
    } else if (type === 'directory') {
        source = document.getElementById('dir-source').value.trim();
        if (!source) return alert('Source directory is required');
    } else if (type === 'wolfdisk') {
        source = document.getElementById('wolfdisk-source').value.trim();
        if (!source) return alert('WolfDisk path is required');
    }

    const payload = { name, type, source, mount_point, global, auto_mount, s3_config, nfs_options, do_mount: true };

    try {
        const resp = await fetch(apiUrl('/api/storage/mounts'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to create mount');
        closeMountModal();
        loadStorageMounts();
    } catch (e) {
        alert('Error creating mount: ' + e.message);
    }
}

async function mountStorage(id) {
    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}/mount`), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Mount failed');
        loadStorageMounts();
    } catch (e) {
        alert('Mount error: ' + e.message);
    }
}

async function unmountStorage(id) {
    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}/unmount`), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Unmount failed');
        loadStorageMounts();
    } catch (e) {
        alert('Unmount error: ' + e.message);
    }
}

async function deleteStorageMount(id, name) {
    if (!confirm(`Delete storage mount "${name}"? This will unmount and remove the configuration.`)) return;
    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}`), { method: 'DELETE' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Delete failed');
        loadStorageMounts();
    } catch (e) {
        alert('Delete error: ' + e.message);
    }
}

async function syncStorageMount(id) {
    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}/sync`), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Sync failed');
        const results = data.results || [];
        const summary = results.map(r => `${r.node}: ${r.status}`).join('\n');
        alert(`Sync complete:\n${summary || 'No remote nodes'}`);
        loadStorageMounts();
    } catch (e) {
        alert('Sync error: ' + e.message);
    }
}

async function duplicateStorageMount(id) {
    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}/duplicate`), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Duplicate failed');
        showToast('Mount duplicated — edit the copy to change bucket/settings', 'success');
        await loadStorageMounts();
        // Open the edit modal for the newly created duplicate
        openEditMount(data.id);
    } catch (e) {
        alert('Duplicate error: ' + e.message);
    }
}

// ─── Edit Storage Mount ───

function openEditMount(id) {
    const m = allStorageMounts.find(x => x.id === id);
    if (!m) return alert('Mount not found');

    document.getElementById('edit-mount-id').value = m.id;
    document.getElementById('edit-mount-name').value = m.name;
    document.getElementById('edit-mount-type-value').value = m.type;
    document.getElementById('edit-mount-type-display').value = (MOUNT_TYPE_ICONS[m.type] || '📦') + ' ' + (MOUNT_TYPE_LABELS[m.type] || m.type);
    document.getElementById('edit-mount-point').value = m.mount_point;
    document.getElementById('edit-mount-global').checked = !!m.global;
    document.getElementById('edit-mount-auto').checked = !!m.auto_mount;

    // Hide all type-specific sections
    document.getElementById('edit-s3-fields').style.display = 'none';
    document.getElementById('edit-nfs-fields').style.display = 'none';
    document.getElementById('edit-dir-fields').style.display = 'none';
    document.getElementById('edit-wolfdisk-fields').style.display = 'none';

    if (m.type === 's3') {
        document.getElementById('edit-s3-fields').style.display = 'block';
        const s3 = m.s3_config || {};
        document.getElementById('edit-s3-provider').value = s3.provider || 'AWS';
        document.getElementById('edit-s3-bucket').value = s3.bucket || '';
        document.getElementById('edit-s3-access-key').value = s3.access_key_id || '';
        document.getElementById('edit-s3-secret-key').value = '';
        document.getElementById('edit-s3-secret-key').placeholder = s3.access_key_id ? 'Leave blank to keep unchanged' : 'Enter secret key';
        document.getElementById('edit-s3-region').value = s3.region || '';
        document.getElementById('edit-s3-endpoint').value = s3.endpoint || '';
    } else if (m.type === 'nfs') {
        document.getElementById('edit-nfs-fields').style.display = 'block';
        document.getElementById('edit-nfs-source').value = m.source || '';
        document.getElementById('edit-nfs-options').value = m.nfs_options || '';
    } else if (m.type === 'directory') {
        document.getElementById('edit-dir-fields').style.display = 'block';
        document.getElementById('edit-dir-source').value = m.source || '';
    } else if (m.type === 'wolfdisk') {
        document.getElementById('edit-wolfdisk-fields').style.display = 'block';
        document.getElementById('edit-wolfdisk-source').value = m.source || '';
    }

    document.getElementById('edit-mount-modal').classList.add('active');
}

function closeEditMountModal() {
    document.getElementById('edit-mount-modal').classList.remove('active');
}

async function saveStorageMountEdit() {
    const id = document.getElementById('edit-mount-id').value;
    const type = document.getElementById('edit-mount-type-value').value;
    const name = document.getElementById('edit-mount-name').value.trim();
    const mount_point = document.getElementById('edit-mount-point').value.trim();
    const global = document.getElementById('edit-mount-global').checked;
    const auto_mount = document.getElementById('edit-mount-auto').checked;

    if (!name) return alert('Name is required');

    const payload = { name, mount_point, global, auto_mount };

    if (type === 's3') {
        const secretVal = document.getElementById('edit-s3-secret-key').value;
        payload.s3_config = {
            provider: document.getElementById('edit-s3-provider').value,
            bucket: document.getElementById('edit-s3-bucket').value.trim(),
            access_key_id: document.getElementById('edit-s3-access-key').value.trim(),
            secret_access_key: secretVal || '••••••••',
            region: document.getElementById('edit-s3-region').value.trim(),
            endpoint: document.getElementById('edit-s3-endpoint').value.trim(),
        };
    } else if (type === 'nfs') {
        payload.source = document.getElementById('edit-nfs-source').value.trim();
        payload.nfs_options = document.getElementById('edit-nfs-options').value.trim();
    } else if (type === 'directory') {
        payload.source = document.getElementById('edit-dir-source').value.trim();
    } else if (type === 'wolfdisk') {
        payload.source = document.getElementById('edit-wolfdisk-source').value.trim();
    }

    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}`), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to save mount');
        closeEditMountModal();
        showToast('Storage mount updated', 'success');
        loadStorageMounts();

        // If global was set, auto-sync to cluster
        if (global) {
            try {
                await fetch(apiUrl(`/api/storage/mounts/${id}/sync`), { method: 'POST' });
                showToast('Mount synced to cluster nodes', 'success');
            } catch (e) {
                // Sync failure is non-critical
            }
        }
    } catch (e) {
        alert('Error saving mount: ' + e.message);
    }
}

async function importRcloneConfig() {
    const config = document.getElementById('rclone-config-paste').value.trim();
    if (!config) return alert('Please paste your rclone.conf contents');

    try {
        const resp = await fetch(apiUrl('/api/storage/import-rclone'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config })
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Import failed');
        closeImportRcloneModal();
        alert(data.message || 'Import complete');
        loadStorageMounts();
    } catch (e) {
        alert('Import error: ' + e.message);
    }
}

// ─── VM Storage Management ───
let vmStorageLocations = [];
let vmExtraDiskCounter = 0;

async function fetchStorageLocations() {
    try {
        const resp = await fetch(apiUrl('/api/vms/storage'));
        if (resp.ok) {
            vmStorageLocations = await resp.json();
        }
    } catch (e) {
        console.error('Failed to fetch storage locations:', e);
    }
}

function buildStorageOptions(selectedPath) {
    let html = '<option value="">/var/lib/wolfstack/vms (default)</option>';
    for (const loc of vmStorageLocations) {
        const label = `${loc.path} (${loc.available_gb}G free, ${loc.fs_type})`;
        const sel = loc.path === selectedPath ? ' selected' : '';
        html += `<option value="${loc.path}"${sel}>${label}</option>`;
    }
    return html;
}

function addVmDiskRow() {
    vmExtraDiskCounter++;
    const container = document.getElementById('vm-extra-disks-container');
    const id = vmExtraDiskCounter;
    const row = document.createElement('div');
    row.id = `vm-extra-disk-${id}`;
    row.style.cssText = 'padding:10px; background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; margin-bottom:8px;';
    row.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
            <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-weight:600; font-size:13px; color:var(--text-primary);">Disk ${id}</span>
            </div>
            <button class="btn btn-sm btn-danger" onclick="removeVmDiskRow(${id})" style="font-size:11px; padding:2px 8px;">✕</button>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:6px;">
            <div>
                <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Name</label>
                <input type="text" class="form-control vm-disk-name" value="data${id}" style="font-size:13px;">
            </div>
            <div>
                <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Size (GiB)</label>
                <input type="number" class="form-control vm-disk-size" value="10" min="1" style="font-size:13px;">
            </div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px;">
            <div>
                <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Storage</label>
                <select class="form-control vm-disk-storage" style="font-size:13px;">${buildStorageOptions('')}</select>
            </div>
            <div>
                <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Format</label>
                <select class="form-control vm-disk-format" style="font-size:13px;">
                    <option value="qcow2" selected>qcow2</option>
                    <option value="raw">raw</option>
                </select>
            </div>
            <div>
                <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Bus</label>
                <select class="form-control vm-disk-bus" style="font-size:13px;">
                    <option value="virtio" selected>VirtIO</option>
                    <option value="scsi">SCSI</option>
                    <option value="ide">IDE</option>
                </select>
            </div>
        </div>
    `;
    container.appendChild(row);
}

function removeVmDiskRow(id) {
    const row = document.getElementById(`vm-extra-disk-${id}`);
    if (row) row.remove();
}

async function showVmCreate() {
    // Fetch storage locations before showing the modal
    await fetchStorageLocations();
    // Populate OS disk storage dropdown
    const storageSelect = document.getElementById('new-vm-storage');
    if (storageSelect) {
        storageSelect.innerHTML = buildStorageOptions('');
    }
    // Clear extra disks from previous use
    document.getElementById('vm-extra-disks-container').innerHTML = '';
    vmExtraDiskCounter = 0;
    // Reset bus selector and drivers ISO
    const busSelect = document.getElementById('new-vm-os-bus');
    if (busSelect) busSelect.value = 'virtio';
    const driversInput = document.getElementById('new-vm-drivers-iso');
    if (driversInput) driversInput.value = '';
    const netSelect = document.getElementById('new-vm-net-model');
    if (netSelect) netSelect.value = 'virtio';
    const busWarning = document.getElementById('vm-bus-warning');
    if (busWarning) busWarning.style.display = 'none';
    // Wire up bus warning
    if (busSelect && !busSelect._listenerAdded) {
        busSelect.addEventListener('change', () => {
            const warn = document.getElementById('vm-bus-warning');
            if (warn) warn.style.display = busSelect.value === 'virtio' ? 'block' : 'none';
        });
        busSelect._listenerAdded = true;
    }
    // Reset to tab 1
    switchVmTab(1);
    document.getElementById('create-vm-modal').classList.add('active');
}

let currentVmTab = 1;

function switchVmTab(tab) {
    const totalTabs = 3;

    if (tab === 'next') {
        tab = Math.min(currentVmTab + 1, totalTabs);
    } else if (tab === 'prev') {
        tab = Math.max(currentVmTab - 1, 1);
    }

    currentVmTab = tab;

    // Show/hide tab pages
    for (let i = 1; i <= totalTabs; i++) {
        const page = document.getElementById(`vm-tab-${i}`);
        if (page) page.style.display = i === tab ? 'block' : 'none';
    }

    // Update tab buttons styling
    document.querySelectorAll('.vm-tab-btn').forEach(btn => {
        const btnTab = parseInt(btn.getAttribute('data-tab'));
        if (btnTab === tab) {
            btn.classList.add('active');
            btn.style.color = 'var(--text-primary)';
            btn.style.borderBottomColor = 'var(--accent)';
        } else {
            btn.classList.remove('active');
            btn.style.color = 'var(--text-muted)';
            btn.style.borderBottomColor = 'transparent';
        }
    });

    // Update footer buttons
    const backBtn = document.getElementById('vm-tab-back-btn');
    const nextBtn = document.getElementById('vm-tab-next-btn');
    const createBtn = document.getElementById('vm-tab-create-btn');

    if (backBtn) backBtn.style.display = tab > 1 ? 'inline-block' : 'none';
    if (nextBtn) nextBtn.style.display = tab < totalTabs ? 'inline-block' : 'none';
    if (createBtn) createBtn.style.display = tab === totalTabs ? 'inline-block' : 'none';
}

function closeVmCreate() {
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
}

async function createVm() {
    const name = document.getElementById('new-vm-name').value.trim();
    const cpus = parseInt(document.getElementById('new-vm-cpus').value);
    const memory = parseInt(document.getElementById('new-vm-memory').value);
    const disk = parseInt(document.getElementById('new-vm-disk').value);
    const iso = document.getElementById('new-vm-iso').value.trim() || null;
    const wolfnetIp = document.getElementById('new-vm-wolfnet-ip').value.trim() || null;
    const storagePath = document.getElementById('new-vm-storage').value || null;
    const osDiskBus = document.getElementById('new-vm-os-bus').value || 'virtio';
    const netModel = document.getElementById('new-vm-net-model').value || 'virtio';
    const driversIso = document.getElementById('new-vm-drivers-iso').value.trim() || null;

    if (!name) { showToast('Enter VM name', 'error'); return; }

    // Collect extra disks
    const extraDisks = [];
    const diskRows = document.getElementById('vm-extra-disks-container').children;
    for (const row of diskRows) {
        const diskName = row.querySelector('.vm-disk-name')?.value.trim();
        const diskSize = parseInt(row.querySelector('.vm-disk-size')?.value) || 10;
        const diskStorage = row.querySelector('.vm-disk-storage')?.value || '/var/lib/wolfstack/vms';
        const diskFormat = row.querySelector('.vm-disk-format')?.value || 'qcow2';
        const diskBus = row.querySelector('.vm-disk-bus')?.value || 'virtio';
        if (diskName) {
            extraDisks.push({ name: diskName, size_gb: diskSize, storage_path: diskStorage, format: diskFormat, bus: diskBus });
        }
    }

    try {
        showToast('Creating VM...', 'info');
        const resp = await fetch(apiUrl('/api/vms/create'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                cpus,
                memory_mb: memory,
                disk_size_gb: disk,
                iso_path: iso,
                wolfnet_ip: wolfnetIp,
                storage_path: storagePath,
                os_disk_bus: osDiskBus,
                net_model: netModel,
                drivers_iso: driversIso,
                extra_disks: extraDisks
            })
        });
        const data = await resp.json();

        if (resp.ok) {
            showToast('VM created successfully', 'success');
            closeVmCreate();
            loadVms();
        } else {
            showToast(data.error || 'Failed to create VM', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function vmAction(name, action) {
    try {
        showToast(`${action}ing VM...`, 'info');
        const resp = await fetch(apiUrl(`/api/vms/${name}/action`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`VM ${action}ed`, 'success');
            setTimeout(loadVms, 2000); // Wait for state change
        } else {
            showToast(data.error || 'Action failed', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function deleteVm(name) {
    if (!confirm(`Delete VM "${name}"? This will delete the disk image permanently.`)) return;

    try {
        const resp = await fetch(apiUrl(`/api/vms/${name}`), { method: 'DELETE' });
        if (resp.ok) {
            showToast('VM deleted', 'success');
            loadVms();
        } else {
            const data = await resp.json();
            showToast(data.error || 'Failed to delete VM', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
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
        const resp = await fetch(apiUrl('/api/containers/install'), {
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
                <button class="btn btn-sm" style="margin:2px;" onclick="viewDockerVolumes('${c.name}')" title="Volumes">📁</button>
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
        table.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No images found</td></tr>';
        return;
    }
    table.innerHTML = images.map(img => {
        const imageRef = img.repository + (img.tag && img.tag !== '<none>' ? ':' + img.tag : '');
        return `
        <tr>
            <td>${img.repository}</td>
            <td>${img.tag}</td>
            <td style="font-family:monospace;font-size:12px;">${img.id.substring(0, 12)}</td>
            <td>${img.size}</td>
            <td>${img.created}</td>
            <td>
                <button class="btn btn-sm btn-primary" style="margin:2px;font-size:11px;" onclick="selectDockerImage('${imageRef.replace(/'/g, "\\'")}')" title="Create container from this image">▶ Use</button>
                <button class="btn btn-sm" style="margin:2px;font-size:11px;color:#ef4444;" onclick="deleteDockerImage('${img.id}', '${imageRef.replace(/'/g, "\\'")}')" title="Delete image">🗑 Delete</button>
            </td>
        </tr>`;
    }).join('');
}

async function deleteDockerImage(id, name) {
    if (!confirm(`Delete Docker image '${name}'?\n\nThis will fail if the image is used by any container.`)) return;

    try {
        const resp = await fetch(apiUrl(`/api/containers/docker/images/${encodeURIComponent(id)}`), {
            method: 'DELETE',
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`Image '${name}' deleted`, 'success');
            setTimeout(loadDockerContainers, 500);
        } else {
            showToast(data.error || 'Failed to delete image', 'error');
        }
    } catch (e) {
        showToast(`Failed: ${e.message}`, 'error');
    }
}


async function dockerAction(container, action) {
    if (action === 'remove' && !confirm(`Remove container '${container}'? This cannot be undone.`)) return;

    try {
        const resp = await fetch(apiUrl(`/api/containers/docker/${container}/action`), {
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

async function viewDockerVolumes(container) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `${container} — Volumes`;
    body.innerHTML = '<p style="color:var(--text-muted);">Loading volumes...</p>';
    modal.classList.add('active');

    try {
        const resp = await fetch(apiUrl(`/api/containers/docker/${encodeURIComponent(container)}/volumes`));
        const mounts = await resp.json();

        if (mounts.length === 0) {
            body.innerHTML = `
                <div style="text-align:center; padding:2rem; color:var(--text-muted);">
                    <div style="font-size:32px; margin-bottom:8px;">📁</div>
                    <p>No volumes mounted on this container.</p>
                    <p style="font-size:12px;">Add volumes when creating the container using the Volumes section.</p>
                </div>
            `;
        } else {
            body.innerHTML = `
                <div style="padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:10px;">
                        <span>📁</span>
                        <strong style="font-size:13px;">Volume Mounts (${mounts.length})</strong>
                    </div>
                    ${mounts.map(m => `
                        <div style="display:flex; align-items:center; gap:8px; padding:8px; margin-bottom:4px; background:var(--bg-primary); border-radius:6px; border:1px solid var(--border);">
                            <span class="badge" style="font-size:10px; min-width:45px; text-align:center;">${m.mount_type}</span>
                            <code style="flex:1; font-size:12px; color:var(--accent); word-break:break-all;">${m.host_path}</code>
                            <span style="color:var(--text-muted); font-size:12px;">→</span>
                            <code style="flex:1; font-size:12px; color:var(--text-primary);">${m.container_path}</code>
                            ${m.read_only ? '<span class="badge" style="font-size:10px; background:var(--warning-bg); color:var(--warning);">RO</span>' : '<span class="badge" style="font-size:10px;">RW</span>'}
                        </div>
                    `).join('')}
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:8px;">
                    ⚠️ Docker volumes can only be modified by recreating the container.
                </div>
            `;
        }
    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Failed to load volumes: ${e.message}</p>`;
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
        const resp = await fetch(apiUrl(`/api/containers/lxc/${container}/action`), {
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
        const resp = await fetch(apiUrl(`/api/containers/${runtime}/${container}/logs`));
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

        // Also fetch current mounts
        let mountsHtml = '';
        try {
            const mountResp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`));
            const mounts = await mountResp.json();
            if (mounts.length > 0) {
                mountsHtml = `
                    <div style="margin-bottom:12px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                            <span>📁</span>
                            <strong style="font-size:13px;">Bind Mounts (${mounts.length})</strong>
                        </div>
                        ${mounts.map(m => `
                            <div style="display:flex; align-items:center; gap:8px; padding:6px 8px; margin-bottom:4px; background:var(--bg-primary); border-radius:6px; border:1px solid var(--border);">
                                <code style="flex:1; font-size:12px; color:var(--accent);">${m.host_path}</code>
                                <span style="color:var(--text-muted); font-size:12px;">→</span>
                                <code style="flex:1; font-size:12px; color:var(--text-primary);">${m.container_path}</code>
                                ${m.read_only ? '<span class="badge" style="font-size:10px;">RO</span>' : ''}
                                <button class="btn btn-sm" style="font-size:11px; padding:2px 6px; color:var(--danger);"
                                    onclick="removeLxcMount('${name}', '${m.host_path.replace(/'/g, "\\'")}')" title="Remove mount">✕</button>
                            </div>
                        `).join('')}
                    </div>
                `;
            }
        } catch (e) { /* ignore mount fetch errors */ }

        body.innerHTML = `
            ${mountsHtml}
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

async function addMountPoint(name) {
    const src = prompt('Host path (e.g. /mnt/data):');
    if (!src) return;
    const dest = prompt('Container path (e.g. /mnt/data):', src);
    if (!dest) return;
    // Use the API to add the mount properly
    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host_path: src, container_path: dest, read_only: false }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Mount added', 'success');
            // Refresh the config editor
            openLxcSettings(name);
        } else {
            showToast(data.error || 'Failed to add mount', 'error');
        }
    } catch (e) {
        // Fallback to raw config
        const editor = document.getElementById('lxc-config-editor');
        editor.value += `\nlxc.mount.entry = ${src} ${dest.replace(/^\//, '')} none bind,create=dir 0 0\n`;
        showToast('Added to config (save to apply)', 'info');
    }
}

async function addWolfDiskMount(name) {
    const src = prompt('WolfDisk mount path on host (e.g. /mnt/wolfdisk):', '/mnt/wolfdisk');
    if (!src) return;
    const dest = prompt('Mount path inside container:', '/mnt/shared');
    if (!dest) return;
    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host_path: src, container_path: dest, read_only: false }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'WolfDisk mount added', 'success');
            openLxcSettings(name);
        } else {
            showToast(data.error || 'Failed to add mount', 'error');
        }
    } catch (e) {
        const editor = document.getElementById('lxc-config-editor');
        editor.value += `\n# WolfDisk shared folder\nlxc.mount.entry = ${src} ${dest.replace(/^\//, '')} none bind,create=dir 0 0\n`;
        showToast('Added to config (save to apply)', 'info');
    }
}

async function removeLxcMount(name, hostPath) {
    if (!confirm(`Remove mount ${hostPath}?`)) return;
    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host_path: hostPath }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Mount removed', 'success');
            openLxcSettings(name);
        } else {
            showToast(data.error || 'Failed to remove mount', 'error');
        }
    } catch (e) {
        showToast(`Remove failed: ${e.message}`, 'error');
    }
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
        const resp = await fetch(apiUrl(`/api/containers/docker/${name}/clone`), {
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
        const resp = await fetch(apiUrl(`/api/containers/docker/${name}/migrate`), {
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
        const resp = await fetch(apiUrl(`/api/containers/lxc/${name}/clone`), {
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
        const resp = await fetch(apiUrl(`/api/containers/docker/search?q=${encodeURIComponent(query)}`));
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
            <div style="margin-bottom:12px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span>📁</span>
                        <strong style="font-size:13px;">Volumes / Bind Mounts</strong>
                    </div>
                    <button class="btn btn-sm" onclick="addDockerVolumeRow()" style="font-size:11px;">➕ Add Mount</button>
                </div>
                <div id="docker-volumes-list" style="display:flex; flex-direction:column; gap:6px;"></div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Map host directories or named volumes into the container</div>
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

    // Collect volume mounts
    const volumeRows = document.querySelectorAll('.docker-volume-row');
    const volumes = [];
    volumeRows.forEach(row => {
        const host = row.querySelector('.docker-vol-host')?.value?.trim();
        const container = row.querySelector('.docker-vol-container')?.value?.trim();
        const ro = row.querySelector('.docker-vol-ro')?.checked;
        if (host && container) {
            let mount = `${host}:${container}`;
            if (ro) mount += ':ro';
            volumes.push(mount);
        }
    });

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
            body: JSON.stringify({ name, image, ports, env, wolfnet_ip, memory_limit, cpu_cores, storage_limit, volumes }),
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
// ─── Docker / LXC Volume Mount Helpers ───

let cachedAvailableMounts = null;

async function fetchAvailableMounts() {
    try {
        const resp = await fetch(apiUrl('/api/storage/available'));
        if (resp.ok) cachedAvailableMounts = await resp.json();
    } catch (e) {
        cachedAvailableMounts = [];
    }
    return cachedAvailableMounts || [];
}

function buildMountPickerOptions() {
    if (!cachedAvailableMounts || cachedAvailableMounts.length === 0) return '';
    return cachedAvailableMounts.map(m => {
        const icon = MOUNT_TYPE_ICONS[m.type] || '📦';
        return `<option value="${m.mount_point}">${icon} ${m.name} (${m.mount_point})</option>`;
    }).join('');
}

async function addDockerVolumeRow() {
    const list = document.getElementById('docker-volumes-list');
    if (!list) return;

    // Fetch available mounts if not cached
    if (cachedAvailableMounts === null) await fetchAvailableMounts();

    const row = document.createElement('div');
    row.className = 'docker-volume-row';
    row.style.cssText = 'display:flex; gap:6px; align-items:center; flex-wrap:wrap;';

    const mountOptions = buildMountPickerOptions();
    const pickerHtml = mountOptions
        ? `<select class="docker-vol-picker" onchange="fillVolFromPicker(this)"
            style="width:100%; margin-bottom:4px; padding:4px 6px; border-radius:4px; border:1px solid var(--border); background:var(--bg-secondary); color:var(--text-secondary); font-size:11px;">
            <option value="">📂 Or pick from Storage Manager...</option>
            ${mountOptions}
          </select>`
        : '';

    row.innerHTML = `
        <div style="flex:2; min-width:120px;">
            ${pickerHtml}
            <input class="docker-vol-host" type="text" placeholder="/host/path or volume-name"
                style="width:100%; padding:6px 8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:12px;">
        </div>
        <span style="color:var(--text-muted); font-weight:600;">→</span>
        <input class="docker-vol-container" type="text" placeholder="/container/path"
            style="flex:2; padding:6px 8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:12px;">
        <label style="display:flex; align-items:center; gap:3px; font-size:11px; color:var(--text-muted); white-space:nowrap; cursor:pointer;">
            <input class="docker-vol-ro" type="checkbox" style="margin:0;"> RO
        </label>
        <button class="btn btn-sm" onclick="removeDockerVolumeRow(this)" style="font-size:11px; padding:4px 8px; color:var(--danger);">✕</button>
    `;
    list.appendChild(row);
}

function fillVolFromPicker(select) {
    const row = select.closest('.docker-volume-row') || select.closest('.lxc-mount-row');
    if (!row) return;
    const hostInput = row.querySelector('.docker-vol-host') || row.querySelector('.lxc-mount-host');
    if (hostInput && select.value) {
        hostInput.value = select.value;
    }
}

function removeDockerVolumeRow(btn) {
    btn.closest('.docker-volume-row')?.remove();
}

async function addLxcMountRow() {
    const list = document.getElementById('lxc-mounts-list');
    if (!list) return;

    // Fetch available mounts if not cached
    if (cachedAvailableMounts === null) await fetchAvailableMounts();

    const row = document.createElement('div');
    row.className = 'lxc-mount-row';
    row.style.cssText = 'display:flex; gap:6px; align-items:center; flex-wrap:wrap;';

    const mountOptions = buildMountPickerOptions();
    const pickerHtml = mountOptions
        ? `<select class="lxc-vol-picker" onchange="fillVolFromPicker(this)"
            style="width:100%; margin-bottom:4px; padding:4px 6px; border-radius:4px; border:1px solid var(--border); background:var(--bg-secondary); color:var(--text-secondary); font-size:11px;">
            <option value="">📂 Or pick from Storage Manager...</option>
            ${mountOptions}
          </select>`
        : '';

    row.innerHTML = `
        <div style="flex:2; min-width:120px;">
            ${pickerHtml}
            <input class="lxc-mount-host" type="text" placeholder="/host/path"
                style="width:100%; padding:6px 8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:12px;">
        </div>
        <span style="color:var(--text-muted); font-weight:600;">→</span>
        <input class="lxc-mount-container" type="text" placeholder="/container/path"
            style="flex:2; padding:6px 8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary); font-size:12px;">
        <label style="display:flex; align-items:center; gap:3px; font-size:11px; color:var(--text-muted); white-space:nowrap; cursor:pointer;">
            <input class="lxc-mount-ro" type="checkbox" style="margin:0;"> RO
        </label>
        <button class="btn btn-sm" onclick="removeLxcMountRow(this)" style="font-size:11px; padding:4px 8px; color:var(--danger);">✕</button>
    `;
    list.appendChild(row);
}

function removeLxcMountRow(btn) {
    btn.closest('.lxc-mount-row')?.remove();
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
            const resp = await fetch(apiUrl('/api/containers/lxc/templates'));
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
            <div style="margin-bottom:12px; padding:12px; background:var(--bg-tertiary); border-radius:8px; border:1px solid var(--border);">
                <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span>📁</span>
                        <strong style="font-size:13px;">Bind Mounts</strong>
                    </div>
                    <button class="btn btn-sm" onclick="addLxcMountRow()" style="font-size:11px;">➕ Add Mount</button>
                </div>
                <div id="lxc-mounts-list" style="display:flex; flex-direction:column; gap:6px;"></div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Map host directories into the container (applied on start, requires restart)</div>
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

    // Collect bind mounts
    const mountRows = document.querySelectorAll('.lxc-mount-row');
    const mounts = [];
    mountRows.forEach(row => {
        const host = row.querySelector('.lxc-mount-host')?.value?.trim();
        const container = row.querySelector('.lxc-mount-container')?.value?.trim();
        const ro = row.querySelector('.lxc-mount-ro')?.checked || false;
        if (host && container) {
            mounts.push({ host_path: host, container_path: container, read_only: ro });
        }
    });

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
            // Apply bind mounts after creation
            for (const mount of mounts) {
                try {
                    await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(mount),
                    });
                } catch (e) {
                    showToast(`Mount warning: ${e.message}`, 'warning');
                }
            }
            const mountMsg = mounts.length > 0 ? ` with ${mounts.length} mount(s)` : '';
            showToast(data.message || `Container '${name}' created${mountMsg}!`, 'success');
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
    let url = '/console.html?type=' + encodeURIComponent(type) + '&name=' + encodeURIComponent(name);
    // For remote nodes, pass the remote server's host so the WebSocket connects there
    if (currentNodeId) {
        const node = allNodes.find(n => n.id === currentNodeId);
        if (node && !node.is_self) {
            url += '&host=' + encodeURIComponent(node.address) + '&port=' + encodeURIComponent(node.port);
        }
    }
    window.open(url, 'console_' + name, 'width=960,height=600,menubar=no,toolbar=no');
}

function fitConsole() { }
function consoleKeyHandler() { }
function closeConsole() { }

function openVmConsole(name) {
    openConsole('vm', name);
}

function openVmVnc(name, wsPort) {
    const host = window.location.hostname;
    window.open(`/vnc.html?name=${encodeURIComponent(name)}&port=${wsPort}&host=${host}`,
        'vnc_' + name, 'width=1024,height=768,menubar=no,toolbar=no');
}

async function showVmLogs(name) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `VM Logs: ${name}`;
    body.innerHTML = '<p style="color:var(--text-muted);">Loading...</p>';
    modal.classList.add('active');

    try {
        const resp = await fetch(apiUrl(`/api/vms/${name}/logs`));
        const data = await resp.json();

        body.innerHTML = `
            <div style="padding: 1rem;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <label style="color:var(--text-muted); font-size:13px;">QEMU output log</label>
                    <button class="btn btn-sm" onclick="showVmLogs('${name}')">🔄 Refresh</button>
                </div>
                <pre style="background:#0d1117; color:#c9d1d9; padding:16px; border-radius:8px; 
                            max-height:400px; overflow:auto; font-size:13px; line-height:1.5;
                            border:1px solid #21262d; white-space:pre-wrap; word-break:break-all;">${data.logs ? data.logs.replace(/</g, '&lt;').replace(/>/g, '&gt;') : 'No logs available.'}</pre>
                <div style="margin-top:12px;">
                    <button class="btn" onclick="closeContainerDetail()">Close</button>
                </div>
            </div>
        `;
    } catch (e) {
        body.innerHTML = `<p style="color:var(--danger); padding:1rem;">Failed to load logs: ${e.message}</p>`;
    }
}

async function showVmSettings(name) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `VM Settings: ${name}`;
    body.innerHTML = '<p style="color:var(--text-muted);">Loading...</p>';
    modal.classList.add('active');

    try {
        const [vmResp, storageResp] = await Promise.all([
            fetch(apiUrl(`/api/vms/${name}`)),
            fetch(apiUrl('/api/vms/storage'))
        ]);
        const vm = await vmResp.json();
        const storageLocations = storageResp.ok ? await storageResp.json() : [];

        // Build storage options for the add-volume dropdown
        let storageOpts = '<option value="">/var/lib/wolfstack/vms (default)</option>';
        for (const loc of storageLocations) {
            storageOpts += `<option value="${loc.path}">${loc.path} (${loc.available_gb}G free)</option>`;
        }

        // Build volumes list
        const volumes = vm.extra_disks || [];
        let volumesHtml = '';
        if (volumes.length > 0) {
            volumesHtml = volumes.map((vol, i) => `
                <div style="display:flex; align-items:center; justify-content:space-between; padding:8px 10px; 
                    background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; margin-bottom:6px;">
                    <div style="flex:1;">
                        <span style="font-weight:600; font-size:13px;">${vol.name}</span>
                        <span style="color:var(--text-muted); font-size:12px; margin-left:8px;">
                            ${vol.size_gb}G · ${vol.format} · ${vol.bus} · ${vol.storage_path}
                        </span>
                    </div>
                    <div style="display:flex; gap:4px;">
                        <button class="btn btn-sm" onclick="resizeVmVolume('${name}', '${vol.name}', ${vol.size_gb})" 
                            style="font-size:11px; padding:2px 8px;" title="Resize">📐</button>
                        <button class="btn btn-sm btn-danger" onclick="removeVmVolume('${name}', '${vol.name}')" 
                            style="font-size:11px; padding:2px 8px;" title="Delete">✕</button>
                    </div>
                </div>
            `).join('');
        } else {
            volumesHtml = '<div style="color:var(--text-muted); font-size:13px; padding:8px;">No extra volumes attached</div>';
        }

        body.innerHTML = `
            <!-- Tab Nav -->
            <div style="display:flex; border-bottom:1px solid var(--border); background:var(--bg-secondary); margin:-24px -24px 16px -24px;">
                <button class="vms-tab-btn active" data-stab="1" onclick="switchVmSettingsTab(1)"
                    style="flex:1; padding:10px 16px; border:none; background:none; color:var(--text-primary); font-size:13px; font-weight:600; cursor:pointer; border-bottom:2px solid var(--accent); transition:all .2s;">
                    ⚙️ General
                </button>
                <button class="vms-tab-btn" data-stab="2" onclick="switchVmSettingsTab(2)"
                    style="flex:1; padding:10px 16px; border:none; background:none; color:var(--text-muted); font-size:13px; font-weight:600; cursor:pointer; border-bottom:2px solid transparent; transition:all .2s;">
                    💾 Disks
                </button>
                <button class="vms-tab-btn" data-stab="3" onclick="switchVmSettingsTab(3)"
                    style="flex:1; padding:10px 16px; border:none; background:none; color:var(--text-muted); font-size:13px; font-weight:600; cursor:pointer; border-bottom:2px solid transparent; transition:all .2s;">
                    🌐 Network & Boot
                </button>
            </div>

            <!-- ═══ Tab 1: General ═══ -->
            <div class="vms-tab-page" id="vms-tab-1">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" class="form-control" value="${vm.name}" disabled style="opacity:0.6;">
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                    <div class="form-group">
                        <label>CPUs</label>
                        <input type="number" class="form-control" id="edit-vm-cpus" value="${vm.cpus}" min="1">
                    </div>
                    <div class="form-group">
                        <label>Memory (MB)</label>
                        <input type="number" class="form-control" id="edit-vm-memory" value="${vm.memory_mb}" min="256">
                    </div>
                </div>
                <div class="form-group">
                    <label>OS Disk Size (GiB) <small style="color:var(--text-muted);">(can only grow)</small></label>
                    <input type="number" class="form-control" id="edit-vm-disk" value="${vm.disk_size_gb}" min="${vm.disk_size_gb}">
                </div>
                <div class="form-group" style="margin-top:4px;">
                    <label style="color:var(--text-muted); font-size:13px;">MAC Address: ${vm.mac_address || 'auto'}</label>
                </div>
            </div>

            <!-- ═══ Tab 2: Disks ═══ -->
            <div class="vms-tab-page" id="vms-tab-2" style="display:none;">
                <div style="margin-bottom:10px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <h4 style="margin:0; font-size:14px;">💾 Storage Volumes</h4>
                    </div>
                    <div id="vm-settings-volumes" style="max-height:200px; overflow-y:auto;">${volumesHtml}</div>
                </div>

                <!-- Add Volume Form -->
                <div style="padding:10px; background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px;">
                    <div style="font-weight:600; font-size:12px; margin-bottom:8px; color:var(--text-secondary);">Add New Volume</div>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:6px;">
                        <div>
                            <label style="display:block; font-size:11px; color:var(--text-muted); margin-bottom:2px;">Name</label>
                            <input type="text" class="form-control" id="add-vol-name" placeholder="data1" style="font-size:13px;">
                        </div>
                        <div>
                            <label style="display:block; font-size:11px; color:var(--text-muted); margin-bottom:2px;">Size (GiB)</label>
                            <input type="number" class="form-control" id="add-vol-size" value="10" min="1" style="font-size:13px;">
                        </div>
                    </div>
                    <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; margin-bottom:8px;">
                        <div>
                            <label style="display:block; font-size:11px; color:var(--text-muted); margin-bottom:2px;">Storage</label>
                            <select class="form-control" id="add-vol-storage" style="font-size:13px;">${storageOpts}</select>
                        </div>
                        <div>
                            <label style="display:block; font-size:11px; color:var(--text-muted); margin-bottom:2px;">Format</label>
                            <select class="form-control" id="add-vol-format" style="font-size:13px;">
                                <option value="qcow2">qcow2</option>
                                <option value="raw">raw</option>
                            </select>
                        </div>
                        <div>
                            <label style="display:block; font-size:11px; color:var(--text-muted); margin-bottom:2px;">Bus</label>
                            <select class="form-control" id="add-vol-bus" style="font-size:13px;">
                                <option value="virtio">VirtIO</option>
                                <option value="scsi">SCSI</option>
                                <option value="ide">IDE</option>
                            </select>
                        </div>
                    </div>
                    <button class="btn btn-sm btn-primary" onclick="addVmVolume('${name}')" style="font-size:12px;">➕ Add Volume</button>
                </div>
            </div>

            <!-- ═══ Tab 3: Network & Boot ═══ -->
            <div class="vms-tab-page" id="vms-tab-3" style="display:none;">
                <div class="form-group">
                    <label>ISO Path</label>
                    <input type="text" class="form-control" id="edit-vm-iso" value="${vm.iso_path || ''}" 
                        placeholder="Leave empty to detach ISO">
                    <small style="color:var(--text-muted);">Set to empty to boot from disk on next start</small>
                </div>
                <div class="form-group" style="margin-top:12px;">
                    <label>VirtIO Drivers ISO</label>
                    <input type="text" class="form-control" id="edit-vm-drivers-iso" value="${vm.drivers_iso || ''}" 
                        placeholder="/var/lib/wolfstack/isos/virtio-win.iso">
                    <small style="color:var(--text-muted);">Secondary CD-ROM for VirtIO drivers (Windows)</small>
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:12px;">
                    <div class="form-group">
                        <label>OS Disk Bus</label>
                        <select class="form-control" id="edit-vm-os-bus" style="font-size:13px;">
                            <option value="virtio"${vm.os_disk_bus === 'virtio' ? ' selected' : ''}>VirtIO (fastest)</option>
                            <option value="ide"${vm.os_disk_bus === 'ide' ? ' selected' : ''}>IDE (Windows)</option>
                            <option value="sata"${vm.os_disk_bus === 'sata' ? ' selected' : ''}>SATA</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Network Adapter</label>
                        <select class="form-control" id="edit-vm-net-model" style="font-size:13px;">
                            <option value="virtio"${vm.net_model === 'virtio' || !vm.net_model ? ' selected' : ''}>VirtIO (Linux)</option>
                            <option value="e1000"${vm.net_model === 'e1000' ? ' selected' : ''}>Intel e1000 (Windows)</option>
                            <option value="rtl8139"${vm.net_model === 'rtl8139' ? ' selected' : ''}>Realtek RTL8139</option>
                        </select>
                    </div>
                </div>
                <div class="form-group" style="margin-top:12px;">
                    <label>WolfNet IP</label>
                    <input type="text" class="form-control" id="edit-vm-wolfnet-ip" value="${vm.wolfnet_ip || ''}"
                        placeholder="Leave empty for user-mode networking">
                </div>
            </div>

            <!-- Footer (always visible) -->
            <div style="display:flex; gap:8px; margin-top:16px; padding-top:12px; border-top:1px solid var(--border);">
                <button class="btn btn-primary" onclick="saveVmSettings('${vm.name}')">💾 Save</button>
                <button class="btn" onclick="closeContainerDetail()">Cancel</button>
            </div>
        `;
    } catch (e) {
        body.innerHTML = `<p style="color:var(--danger); padding:1rem;">Failed to load VM: ${e.message}</p>`;
    }
}

async function addVmVolume(vmName) {
    const volName = document.getElementById('add-vol-name').value.trim();
    const volSize = parseInt(document.getElementById('add-vol-size').value) || 10;
    const volStorage = document.getElementById('add-vol-storage').value || null;
    const volFormat = document.getElementById('add-vol-format').value || 'qcow2';
    const volBus = document.getElementById('add-vol-bus').value || 'virtio';

    if (!volName) { showToast('Enter a volume name', 'error'); return; }

    try {
        showToast('Adding volume...', 'info');
        const resp = await fetch(apiUrl(`/api/vms/${vmName}/volumes`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: volName, size_gb: volSize, storage_path: volStorage, format: volFormat, bus: volBus })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`Volume '${volName}' added`, 'success');
            showVmSettings(vmName); // Refresh
        } else {
            showToast(data.error || 'Failed to add volume', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function removeVmVolume(vmName, volName) {
    if (!confirm(`Delete volume '${volName}'? This will permanently delete the disk file.`)) return;
    try {
        const resp = await fetch(apiUrl(`/api/vms/${vmName}/volumes/${encodeURIComponent(volName)}`), { method: 'DELETE' });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`Volume '${volName}' removed`, 'success');
            showVmSettings(vmName);
        } else {
            showToast(data.error || 'Failed to remove volume', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function resizeVmVolume(vmName, volName, currentSize) {
    const newSize = prompt(`Resize volume '${volName}' (currently ${currentSize}G).\nEnter new size in GiB (must be larger):`, currentSize + 10);
    if (!newSize) return;
    const size = parseInt(newSize);
    if (isNaN(size) || size <= currentSize) {
        showToast(`Size must be larger than current ${currentSize}G`, 'error');
        return;
    }
    try {
        const resp = await fetch(apiUrl(`/api/vms/${vmName}/volumes/${encodeURIComponent(volName)}/resize`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ size_gb: size })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`Volume resized to ${size}G`, 'success');
            showVmSettings(vmName);
        } else {
            showToast(data.error || 'Resize failed', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function switchVmSettingsTab(tab) {
    // Hide all tab pages
    document.querySelectorAll('.vms-tab-page').forEach(p => p.style.display = 'none');
    // Show selected
    const page = document.getElementById(`vms-tab-${tab}`);
    if (page) page.style.display = 'block';
    // Update tab button styles
    document.querySelectorAll('.vms-tab-btn').forEach(btn => {
        const isActive = parseInt(btn.dataset.stab) === tab;
        btn.style.color = isActive ? 'var(--text-primary)' : 'var(--text-muted)';
        btn.style.borderBottomColor = isActive ? 'var(--accent)' : 'transparent';
        btn.classList.toggle('active', isActive);
    });
}

async function saveVmSettings(name) {
    const cpus = parseInt(document.getElementById('edit-vm-cpus').value);
    const memory = parseInt(document.getElementById('edit-vm-memory').value);
    const disk = parseInt(document.getElementById('edit-vm-disk').value);
    const iso = document.getElementById('edit-vm-iso').value.trim();
    const wolfnetIp = document.getElementById('edit-vm-wolfnet-ip').value.trim();
    const osDiskBus = document.getElementById('edit-vm-os-bus')?.value || undefined;
    const netModel = document.getElementById('edit-vm-net-model')?.value || undefined;
    const driversIso = document.getElementById('edit-vm-drivers-iso')?.value.trim() ?? undefined;

    try {
        const resp = await fetch(apiUrl(`/api/vms/${name}`), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                cpus,
                memory_mb: memory,
                disk_size_gb: disk,
                iso_path: iso,
                wolfnet_ip: wolfnetIp,
                os_disk_bus: osDiskBus,
                net_model: netModel,
                drivers_iso: driversIso,
            })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast('VM settings saved', 'success');
            closeContainerDetail();
            loadVms();
        } else {
            showToast(data.error || 'Failed to save', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

const installCmds = {
    wolfnet: 'curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/wolfnet/setup.sh | sudo bash',
    wolfproxy: 'curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfProxy/main/setup.sh | sudo bash',
    wolfserve: 'curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfServe/main/setup.sh | sudo bash',
    wolfdisk: 'curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup.sh | sudo bash',
    wolfscale: 'curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup_lb.sh | sudo bash',
};

function copyInstallCmd(component) {
    const cmd = installCmds[component];
    if (cmd) {
        navigator.clipboard.writeText(cmd).then(() => {
            showToast('Install command copied to clipboard', 'success');
        }).catch(() => {
            // Fallback for non-HTTPS contexts
            const ta = document.createElement('textarea');
            ta.value = cmd;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showToast('Install command copied to clipboard', 'success');
        });
    }
}
