// WolfStack Dashboard — app.js

// ─── State ───
let currentPage = 'datacenter';
let currentComponent = null;
let currentNodeId = null;  // null = datacenter, node ID = specific server
let allNodes = [];         // cached node list
let cpuHistory = [];
let memHistory = [];
let netHistory = []; // { timestamp, rx_bytes, tx_bytes } — cumulative
let diskHistory = {}; // mount_point -> array of {timestamp, usage_percent}
const MAX_HISTORY = 300; // 10 minutes at 2s intervals
let displayRange = 150; // default 5 minutes (150 samples at 2s)

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

    const titles = { datacenter: 'Datacenter', 'ai-settings': 'AI Agent' };
    document.getElementById('page-title').textContent = titles[page] || page;

    if (page === 'datacenter') {
        renderDatacenterOverview();
    } else if (page === 'ai-settings') {
        loadAiConfig();
        loadAiStatus();
        loadAiAlerts();
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
        networking: 'Networking',
        wolfnet: 'WolfNet',
        certificates: 'Certificates',
    };
    document.getElementById('page-title').textContent = `${hostname} — ${viewTitles[view] || view}`;
    document.getElementById('hostname-display').textContent = `${hostname} (${node?.address}:${node?.port})`;

    // Update Header Info
    const headerHostname = document.getElementById('server-header-hostname');
    if (headerHostname) headerHostname.textContent = hostname;

    const headerIp = document.getElementById('server-header-ip');
    if (headerIp) {
        let ipText = node?.address || '—';
        if (node?.public_ip) ipText = `${node.public_ip} (Public) • ${ipText}`;
        headerIp.textContent = ipText;
    }

    const headerOs = document.getElementById('server-header-os');
    if (headerOs && node?.metrics?.os_name) headerOs.textContent = node.metrics.os_name;

    // Load data for the view
    if (view === 'dashboard') {
        // Clear history for new server view to show fresh data
        cpuHistory = [];
        memHistory = [];
        diskHistory = {};

        // Clear canvases if they exist
        const cpuCtx = document.getElementById('cpu-chart-canvas')?.getContext('2d');
        if (cpuCtx) cpuCtx.clearRect(0, 0, cpuCtx.canvas.width, cpuCtx.canvas.height);

        const memCtx = document.getElementById('mem-chart-canvas')?.getContext('2d');
        if (memCtx) memCtx.clearRect(0, 0, memCtx.canvas.width, memCtx.canvas.height);

        const diskCtx = document.getElementById('disk-chart-canvas')?.getContext('2d');
        if (diskCtx) diskCtx.clearRect(0, 0, diskCtx.canvas.width, diskCtx.canvas.height);

        if (node?.metrics) updateDashboard(node.metrics);

        // If it's the local node (is_self), we could fetch history, but for now we'll build it live
        if (node?.is_self) fetchMetricsHistory();
    }
    if (view === 'components') loadComponents();
    if (view === 'services') loadComponents();
    if (view === 'containers') loadDockerContainers();
    if (view === 'lxc') loadLxcContainers();

    if (view === 'terminal') {
        // Open host terminal directly
        openConsole('host', hostname);
    }
    if (view === 'vms') loadVms();
    if (view === 'storage') loadStorageMounts();
    if (view === 'networking') loadNetworking();
    if (view === 'backups') loadBackups();
    if (view === 'wolfnet') loadWolfNet();
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
                    ${node.vm_count ? `<span class="badge" style="font-size:10px; padding:1px 6px;">${node.vm_count}</span>` : ''}
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="storage" onclick="selectServerView('${node.id}', 'storage')">
                    <span class="icon">💾</span> Storage
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="networking" onclick="selectServerView('${node.id}', 'networking')">
                    <span class="icon">🌐</span> Networking
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="backups" onclick="selectServerView('${node.id}', 'backups')">
                    <span class="icon">🛡️</span> Backups
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="wolfnet" onclick="selectServerView('${node.id}', 'wolfnet')">
                    <span class="icon">🔗</span> WolfNet
                </a>
                <a class="nav-item server-child-item" data-node="${node.id}" data-view="certificates" onclick="selectServerView('${node.id}', 'certificates')">
                    <span class="icon">🔒</span> Certificates
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
                <div style="display:flex; align-items:center; gap:10px;">
                    <span style="font-size:11px; padding:2px 8px; border-radius:4px; background:rgba(16,185,129,0.1); color:var(--success); font-family:'JetBrains Mono',monospace;">
                        ▲ ${formatUptimeShort(m.uptime_secs)}
                    </span>
                    <span style="color:var(--text-muted); font-size:12px;">${node.address}:${node.port}</span>
                </div>
            </div>
            <div class="card-body">
                <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; text-align:center;">
                    <div>
                        <div style="font-size:24px; font-weight:700; color:var(--accent-light);">${cpuPct}%</div>
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">CPU</div>
                        <div class="progress-bar" style="margin-top:6px;"><div class="fill ${progressClass(m.cpu_usage_percent)}" style="width:${cpuPct}%"></div></div>
                        <canvas id="spark-cpu-${node.id}" width="80" height="24" style="margin-top:4px; width:100%; height:24px;"></canvas>
                    </div>
                    <div>
                        <div style="font-size:24px; font-weight:700; color:var(--success);">${memPct}%</div>
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Memory</div>
                        <div class="progress-bar" style="margin-top:6px;"><div class="fill ${progressClass(m.memory_percent)}" style="width:${memPct}%"></div></div>
                        <canvas id="spark-mem-${node.id}" width="80" height="24" style="margin-top:4px; width:100%; height:24px;"></canvas>
                    </div>
                    <div>
                        <div style="font-size:24px; font-weight:700; color:var(--warning);">${diskPct}%</div>
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px;">Disk</div>
                        <div class="progress-bar" style="margin-top:6px;"><div class="fill ${progressClass(parseFloat(diskPct) || 0)}" style="width:${diskPct}%"></div></div>
                    </div>
                </div>
                <div style="margin-top:12px; display:flex; gap:6px; flex-wrap:wrap;">
                    ${node.components.filter(c => c.installed).map(c =>
            `<span style="font-size:11px; padding:2px 8px; border-radius:4px; background:${c.running ? 'var(--success-bg)' : 'var(--danger-bg)'}; color:${c.running ? 'var(--success)' : 'var(--danger)'};">                            ${c.component}
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

    // Draw sparklines on server cards
    setTimeout(() => drawServerSparklines(nodes), 50);

    // Initialize Map
    setTimeout(() => updateMap(nodes), 100);
}

// ─── Sparkline mini-charts for datacenter cards ───
let sparkHistory = {}; // nodeId -> { cpu: [], mem: [] }

function drawServerSparklines(nodes) {
    nodes.forEach(node => {
        if (!node.metrics) return;
        const id = node.id;
        if (!sparkHistory[id]) sparkHistory[id] = { cpu: [], mem: [] };
        sparkHistory[id].cpu.push(node.metrics.cpu_usage_percent);
        sparkHistory[id].mem.push(node.metrics.memory_percent);
        if (sparkHistory[id].cpu.length > 30) sparkHistory[id].cpu.shift();
        if (sparkHistory[id].mem.length > 30) sparkHistory[id].mem.shift();

        drawSparkline(`spark-cpu-${id}`, sparkHistory[id].cpu, 'rgba(99,102,241,0.8)', 'rgba(99,102,241,0.15)');
        drawSparkline(`spark-mem-${id}`, sparkHistory[id].mem, 'rgba(16,185,129,0.8)', 'rgba(16,185,129,0.15)');
    });
}

function drawSparkline(canvasId, data, stroke, fill) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || data.length < 2) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth;
    const H = canvas.clientHeight;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);

    const step = W / (data.length - 1);
    ctx.beginPath();
    ctx.moveTo(0, H - (data[0] / 100) * H);
    for (let i = 1; i < data.length; i++) {
        const x = i * step;
        const y = H - (Math.max(0, Math.min(100, data[i])) / 100) * H;
        const px = (i - 1) * step;
        const py = H - (Math.max(0, Math.min(100, data[i - 1])) / 100) * H;
        ctx.bezierCurveTo((px + x) / 2, py, (px + x) / 2, y, x, y);
    }
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Fill
    ctx.lineTo((data.length - 1) * step, H);
    ctx.lineTo(0, H);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
}

// ─── Map Logic ───
let worldMap = null;
let mapMarkers = {};
let geoCache = {};
let fetchingGeo = {};

function initMap() {
    if (worldMap) return;
    const mapEl = document.getElementById('world-map');
    if (!mapEl) return;

    worldMap = L.map('world-map', {
        attributionControl: false,
        zoomControl: false
    }).setView([20, 0], 2);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19
    }).addTo(worldMap);
}

function updateMap(nodes) {
    if (!document.getElementById('world-map')) return;
    if (!worldMap) initMap();
    if (!worldMap) return;

    // Fix map size if it was hidden
    worldMap.invalidateSize();

    // Find the self node (local server) — its public_ip is the best geolocation reference
    const selfNode = nodes.find(n => n.is_self);
    const selfPublicIp = selfNode?.public_ip;

    // Helper: resolve a node's location, then call placeMarker
    const resolveAndPlace = (node, placeMarker) => {
        const ipToGeolocate = node.public_ip || selfPublicIp;

        if (ipToGeolocate) {
            // Check cache first
            if (geoCache[ipToGeolocate]) {
                const [baseLat, baseLon] = geoCache[ipToGeolocate];
                const [lat, lon] = jitterCoords(baseLat, baseLon, node.hostname);
                placeMarker(lat, lon);
                return;
            }

            // Fetch geolocation if not already fetching
            if (!fetchingGeo[ipToGeolocate]) {
                fetchingGeo[ipToGeolocate] = true;
                fetch(`http://ip-api.com/json/${ipToGeolocate}`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'success') {
                            geoCache[ipToGeolocate] = [data.lat, data.lon];
                            const [lat, lon] = jitterCoords(data.lat, data.lon, node.hostname);
                            placeMarker(lat, lon);
                        } else {
                            // API failed — use London as last resort
                            const [lat, lon] = jitterCoords(51.5074, -0.1278, node.hostname);
                            placeMarker(lat, lon);
                        }
                    })
                    .catch(() => {
                        const [lat, lon] = jitterCoords(51.5074, -0.1278, node.hostname);
                        placeMarker(lat, lon);
                    });
            } else {
                // Already fetching — wait a moment and retry from cache
                setTimeout(() => resolveAndPlace(node, placeMarker), 1000);
            }
            return;
        }

        // No public IP at all — use London as last resort with jitter
        const [lat, lon] = jitterCoords(51.5074, -0.1278, node.hostname);
        placeMarker(lat, lon);
    };

    nodes.forEach(node => {
        if (mapMarkers[node.id]) return;

        // Function to place marker
        const placeMarker = (lat, lon) => {
            const icon = L.divIcon({
                className: 'custom-map-marker',
                html: `<div style="width:12px; height:12px; background:${node.online ? '#10b981' : '#ef4444'}; border-radius:50%; border:2px solid #ffffff; box-shadow:0 0 10px ${node.online ? '#10b981' : '#ef4444'};"></div>`,
                iconSize: [12, 12]
            });
            const marker = L.marker([lat, lon], { icon: icon }).addTo(worldMap);
            let popupContent = `<b>${node.hostname}</b><br>${node.address}`;
            if (node.public_ip) popupContent += `<br>Public: ${node.public_ip}`;
            popupContent += `<br>${node.online ? 'Online' : 'Offline'}`;
            marker.bindPopup(popupContent);
            mapMarkers[node.id] = marker;
        };

        resolveAndPlace(node, placeMarker);
    });

    // Draw connection lines between online servers after markers settle
    setTimeout(() => drawMapConnections(), 2000);
}

let mapConnectionLines = [];
function drawMapConnections() {
    if (!worldMap) return;
    // Clear previous lines
    mapConnectionLines.forEach(l => worldMap.removeLayer(l));
    mapConnectionLines = [];

    const markerIds = Object.keys(mapMarkers);
    if (markerIds.length < 2) return;

    // Draw lines between all pairs
    for (let i = 0; i < markerIds.length; i++) {
        for (let j = i + 1; j < markerIds.length; j++) {
            const m1 = mapMarkers[markerIds[i]];
            const m2 = mapMarkers[markerIds[j]];
            if (!m1 || !m2) continue;
            const line = L.polyline(
                [m1.getLatLng(), m2.getLatLng()],
                {
                    color: '#6366f1',
                    weight: 1.5,
                    opacity: 0.4,
                    dashArray: '6, 8',
                    className: 'map-connection-line'
                }
            ).addTo(worldMap);
            mapConnectionLines.push(line);
        }
    }
}

// Deterministic jitter based on hostname so co-located servers spread visually
function jitterCoords(baseLat, baseLon, hostname) {
    let hash = 0;
    for (let i = 0; i < hostname.length; i++) hash = hostname.charCodeAt(i) + ((hash << 5) - hash);
    const jitter = 0.08;
    const latOffset = ((Math.abs(hash) % 1000) / 1000 - 0.5) * jitter;
    const lonOffset = ((Math.abs(hash >> 8) % 1000) / 1000 - 0.5) * jitter;
    return [baseLat + latOffset, baseLon + lonOffset];
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

function formatUptimeShort(secs) {
    if (secs >= 86400) return Math.floor(secs / 86400) + 'd ' + Math.floor((secs % 86400) / 3600) + 'h';
    if (secs >= 3600) return Math.floor(secs / 3600) + 'h ' + Math.floor((secs % 3600) / 60) + 'm';
    return Math.floor(secs / 60) + 'm';
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
        } else if (currentPage === 'dashboard' && !currentNodeId) {
            // If viewing local dashboard
            updateDashboard(m);
        }
    } catch (e) {
        console.error('Failed to fetch metrics:', e);
    }
}

function updateDashboard(m) {
    // ─── Neofetch Card ───
    const neoOs = document.getElementById('neo-os');
    if (neoOs) {
        neoOs.textContent = (m.os_name || 'Linux') + ' ' + (m.os_version || '');
        const neoHost = document.getElementById('neo-host');
        if (neoHost) neoHost.textContent = m.hostname;
        const neoKernel = document.getElementById('neo-kernel');
        if (neoKernel) neoKernel.textContent = m.kernel_version || 'unknown';

        // Format Uptime
        const up = m.uptime_secs;
        const days = Math.floor(up / 86400);
        const hours = Math.floor((up % 86400) / 3600);
        const mins = Math.floor((up % 3600) / 60);
        let uptimeStr = '';
        if (days > 0) uptimeStr += `${days}d `;
        if (hours > 0) uptimeStr += `${hours}h `;
        uptimeStr += `${mins}m`;
        const neoUptime = document.getElementById('neo-uptime');
        if (neoUptime) neoUptime.textContent = uptimeStr;

        const neoCpu = document.getElementById('neo-cpu');
        if (neoCpu) {
            neoCpu.textContent = m.cpu_model || 'Unknown CPU';
            neoCpu.title = m.cpu_model || '';
        }

        const neoMem = document.getElementById('neo-memory');
        if (neoMem) neoMem.textContent = `${formatBytes(m.memory_used_bytes)} / ${formatBytes(m.memory_total_bytes)}`;

        // Public IP (Need to access currentNode public ip)
        const neoIp = document.getElementById('neo-ip');
        if (neoIp) {
            // Find current node in global nodes list
            const currentNode = allNodes.find(n => n.id === currentNodeId);
            neoIp.textContent = currentNode?.public_ip || '— (private)';
        }
    }

    // Header Uptime
    const headerUptime = document.getElementById('server-header-uptime');
    if (headerUptime) headerUptime.textContent = 'Up: ' + formatUptime(m.uptime_secs);

    // CPU
    const cpuPct = m.cpu_usage_percent.toFixed(1);
    const cpuVal = document.getElementById('cpu-value');
    if (cpuVal) cpuVal.textContent = cpuPct + '%';

    const cpuModel = document.getElementById('cpu-model');
    if (cpuModel) cpuModel.textContent = m.cpu_model + ` (${m.cpu_count} cores)`;

    const cpuBar = document.getElementById('cpu-bar');
    if (cpuBar) {
        cpuBar.style.width = cpuPct + '%';
        cpuBar.className = 'fill ' + progressClass(m.cpu_usage_percent);
    }

    // Memory
    const memPct = m.memory_percent.toFixed(1);
    const memVal = document.getElementById('mem-value');
    if (memVal) memVal.textContent = memPct + '%';

    const memDetail = document.getElementById('mem-detail');
    if (memDetail) memDetail.textContent = `${formatBytes(m.memory_used_bytes)} / ${formatBytes(m.memory_total_bytes)}`;

    const memBar = document.getElementById('mem-bar');
    if (memBar) {
        memBar.style.width = memPct + '%';
        memBar.className = 'fill ' + progressClass(m.memory_percent);
    }

    // Disk (primary)
    if (m.disks.length > 0) {
        const root = m.disks.find(d => d.mount_point === '/') || m.disks[0];
        const rootPct = root.usage_percent.toFixed(1);

        const diskVal = document.getElementById('disk-value');
        if (diskVal) diskVal.textContent = rootPct + '%';

        const diskDetail = document.getElementById('disk-detail');
        if (diskDetail) diskDetail.textContent = `${formatBytes(root.used_bytes)} / ${formatBytes(root.total_bytes)}`;

        const diskBar = document.getElementById('disk-bar');
        if (diskBar) {
            diskBar.style.width = rootPct + '%';
            diskBar.className = 'fill ' + progressClass(root.usage_percent);
        }
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
    const now = Math.floor(Date.now() / 1000);

    // CPU & Memory
    cpuHistory.push({ timestamp: now, value: m.cpu_usage_percent });
    memHistory.push({ timestamp: now, value: m.memory_percent });
    if (cpuHistory.length > MAX_HISTORY) cpuHistory.shift();
    if (memHistory.length > MAX_HISTORY) memHistory.shift();

    // Network I/O (cumulative totals — we'll calc rates in the chart)
    const totalRx = m.network.reduce((s, n) => s + n.rx_bytes, 0);
    const totalTx = m.network.reduce((s, n) => s + n.tx_bytes, 0);
    netHistory.push({ timestamp: now, rx_bytes: totalRx, tx_bytes: totalTx });
    if (netHistory.length > MAX_HISTORY) netHistory.shift();

    // Disk history
    m.disks.forEach(d => {
        if (!diskHistory[d.mount_point]) diskHistory[d.mount_point] = [];
        diskHistory[d.mount_point].push({ timestamp: now, value: d.usage_percent });
        if (diskHistory[d.mount_point].length > MAX_HISTORY) diskHistory[d.mount_point].shift();
    });

    // Update live values
    const cpuLive = document.getElementById('cpu-live-value');
    if (cpuLive) cpuLive.textContent = m.cpu_usage_percent.toFixed(1) + '%';
    const memLive = document.getElementById('mem-live-value');
    if (memLive) memLive.textContent = m.memory_percent.toFixed(1) + '%';
    // Network live value (rate)
    if (netHistory.length >= 2) {
        const prev = netHistory[netHistory.length - 2];
        const cur = netHistory[netHistory.length - 1];
        const dt = Math.max(1, cur.timestamp - prev.timestamp);
        const rxRate = (cur.rx_bytes - prev.rx_bytes) / dt;
        const txRate = (cur.tx_bytes - prev.tx_bytes) / dt;
        const netLive = document.getElementById('net-live-value');
        if (netLive) netLive.textContent = `↓${formatRate(rxRate)}  ↑${formatRate(txRate)}`;
    }

    redrawAllCharts();
}

async function fetchMetricsHistory() {
    try {
        const resp = await fetch(apiUrl('/api/metrics/history'));
        if (!resp.ok) return;
        const history = await resp.json();

        // Clear existing
        cpuHistory = [];
        memHistory = [];
        netHistory = [];
        diskHistory = {};

        // Populate
        history.forEach(snap => {
            cpuHistory.push({ timestamp: snap.timestamp, value: snap.cpu_percent });
            memHistory.push({ timestamp: snap.timestamp, value: snap.memory_percent });

            // Network (cumulative totals from backend)
            if (snap.network_rx_bytes !== undefined) {
                netHistory.push({
                    timestamp: snap.timestamp,
                    rx_bytes: snap.network_rx_bytes,
                    tx_bytes: snap.network_tx_bytes
                });
            }

            snap.disks.forEach(d => {
                if (!diskHistory[d.mount_point]) diskHistory[d.mount_point] = [];
                diskHistory[d.mount_point].push({ timestamp: snap.timestamp, value: d.usage_percent });
            });
        });

        // Initial draw
        redrawAllCharts();
    } catch (e) {
        console.error('Failed to fetch history:', e);
    }
}

// ─── Enhanced Canvas Charts ───

function formatRate(bytesPerSec) {
    if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
    if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
    if (bytesPerSec < 1024 * 1024 * 1024) return (bytesPerSec / (1024 * 1024)).toFixed(1) + ' MB/s';
    return (bytesPerSec / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
}

function setTimeRange(samples) {
    displayRange = samples;
    document.querySelectorAll('.time-range-btn').forEach(b => {
        b.classList.toggle('active', parseInt(b.dataset.range) === samples);
    });
    redrawAllCharts();
}

function redrawAllCharts() {
    if (!document.getElementById('cpu-chart-canvas')) return;
    drawChart('cpu-chart-canvas', cpuHistory, 'rgba(99, 102, 241, 1)', 'rgba(99, 102, 241, 0.2)');
    drawChart('mem-chart-canvas', memHistory, 'rgba(16, 185, 129, 1)', 'rgba(16, 185, 129, 0.2)');
    drawNetChart('net-chart-canvas', netHistory);
    drawMultiLineChart('disk-chart-canvas', 'disk-chart-legend', diskHistory);
}

function sliceForRange(data) {
    if (!data || data.length <= displayRange) return data;
    return data.slice(data.length - displayRange);
}

function setupCanvas(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    const ctx = canvas.getContext('2d');
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;
    ctx.clearRect(0, 0, rect.width, rect.height);
    return { canvas, ctx, rect, dpr };
}

function drawGrid(ctx, padding, w, h) {
    ctx.strokeStyle = 'rgba(255,255,255,0.06)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let i = 0; i <= 4; i++) {
        const y = padding.top + (h / 4) * i;
        ctx.moveTo(padding.left, y);
        ctx.lineTo(padding.left + w, y);
    }
    ctx.stroke();
}

function drawYLabels(ctx, padding, h, labels) {
    ctx.fillStyle = 'rgba(255,255,255,0.35)';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= 4; i++) {
        const y = padding.top + (h / 4) * i;
        ctx.fillText(labels[i], padding.left - 6, y);
    }
}

function drawXTimeLabels(ctx, padding, w, h, dataLen) {
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const totalSecs = dataLen * 2;
    const xLabelCount = 5;
    for (let i = 0; i <= xLabelCount; i++) {
        const frac = i / xLabelCount;
        const x = padding.left + frac * w;
        const secsAgo = Math.round(totalSecs * (1 - frac));
        const label = secsAgo >= 60 ? `-${Math.round(secsAgo / 60)}m` : `-${secsAgo}s`;
        ctx.fillText(label, x, padding.top + h + 6);
    }
}

function drawThresholdLines(ctx, padding, w, h) {
    // 80% warning
    const y80 = padding.top + h * 0.2;
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = 'rgba(245, 158, 11, 0.25)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padding.left, y80);
    ctx.lineTo(padding.left + w, y80);
    ctx.stroke();

    // 95% critical
    const y95 = padding.top + h * 0.05;
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.3)';
    ctx.beginPath();
    ctx.moveTo(padding.left, y95);
    ctx.lineTo(padding.left + w, y95);
    ctx.stroke();
    ctx.setLineDash([]);
}

function drawChart(canvasId, fullData, strokeColor, fillColor) {
    const setup = setupCanvas(canvasId);
    if (!setup) return;
    const { canvas, ctx, rect } = setup;

    const data = sliceForRange(fullData);
    if (!data || data.length < 2) return;

    const padding = { top: 20, right: 10, bottom: 30, left: 40 };
    const w = rect.width - padding.left - padding.right;
    const h = rect.height - padding.top - padding.bottom;

    // Store chart metadata for hover
    canvas._chartMeta = { padding, w, h, data, type: 'percent', strokeColor };

    drawGrid(ctx, padding, w, h);
    drawYLabels(ctx, padding, h, ['100%', '75%', '50%', '25%', '0%']);
    drawXTimeLabels(ctx, padding, w, h, data.length);
    drawThresholdLines(ctx, padding, w, h);

    // Draw bezier path
    const step = w / (data.length - 1);
    ctx.beginPath();
    const firstY = padding.top + h - (data[0].value / 100) * h;
    ctx.moveTo(padding.left, firstY);

    for (let i = 1; i < data.length; i++) {
        const x = padding.left + i * step;
        const val = Math.max(0, Math.min(100, data[i].value));
        const y = padding.top + h - (val / 100) * h;
        const prevX = padding.left + (i - 1) * step;
        const prevVal = Math.max(0, Math.min(100, data[i - 1].value));
        const prevY = padding.top + h - (prevVal / 100) * h;
        const cpX = (prevX + x) / 2;
        ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
    }

    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Fill gradient
    ctx.lineTo(padding.left + (data.length - 1) * step, padding.top + h);
    ctx.lineTo(padding.left, padding.top + h);
    ctx.closePath();
    const gradient = ctx.createLinearGradient(0, padding.top, 0, padding.top + h);
    gradient.addColorStop(0, fillColor);
    gradient.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = gradient;
    ctx.fill();
}

function drawNetChart(canvasId, fullData) {
    const setup = setupCanvas(canvasId);
    if (!setup) return;
    const { canvas, ctx, rect } = setup;

    const rawData = sliceForRange(fullData);
    if (!rawData || rawData.length < 3) return;

    // Calculate rates (bytes/sec)
    const rates = [];
    for (let i = 1; i < rawData.length; i++) {
        const dt = Math.max(1, rawData[i].timestamp - rawData[i - 1].timestamp);
        rates.push({
            timestamp: rawData[i].timestamp,
            rx: Math.max(0, (rawData[i].rx_bytes - rawData[i - 1].rx_bytes) / dt),
            tx: Math.max(0, (rawData[i].tx_bytes - rawData[i - 1].tx_bytes) / dt)
        });
    }
    if (rates.length < 2) return;

    const padding = { top: 20, right: 10, bottom: 30, left: 55 };
    const w = rect.width - padding.left - padding.right;
    const h = rect.height - padding.top - padding.bottom;

    // Find max rate for auto-scaling
    const maxRate = Math.max(1024, ...rates.map(r => Math.max(r.rx, r.tx))) * 1.15;

    // Store chart metadata for hover
    canvas._chartMeta = { padding, w, h, data: rates, type: 'network', maxRate };

    drawGrid(ctx, padding, w, h);

    // Y-axis labels (auto-scaled)
    ctx.fillStyle = 'rgba(255,255,255,0.35)';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= 4; i++) {
        const y = padding.top + (h / 4) * i;
        const val = maxRate * (1 - i / 4);
        ctx.fillText(formatRate(val), padding.left - 6, y);
    }

    drawXTimeLabels(ctx, padding, w, h, rates.length);

    const step = w / (rates.length - 1);

    // Draw RX line (download — cyan)
    ctx.beginPath();
    ctx.moveTo(padding.left, padding.top + h - (rates[0].rx / maxRate) * h);
    for (let i = 1; i < rates.length; i++) {
        const x = padding.left + i * step;
        const y = padding.top + h - (rates[i].rx / maxRate) * h;
        const prevX = padding.left + (i - 1) * step;
        const prevY = padding.top + h - (rates[i - 1].rx / maxRate) * h;
        ctx.bezierCurveTo((prevX + x) / 2, prevY, (prevX + x) / 2, y, x, y);
    }
    ctx.strokeStyle = '#06b6d4';
    ctx.lineWidth = 2;
    ctx.stroke();

    // RX fill
    ctx.lineTo(padding.left + (rates.length - 1) * step, padding.top + h);
    ctx.lineTo(padding.left, padding.top + h);
    ctx.closePath();
    const rxGrad = ctx.createLinearGradient(0, padding.top, 0, padding.top + h);
    rxGrad.addColorStop(0, 'rgba(6, 182, 212, 0.2)');
    rxGrad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = rxGrad;
    ctx.fill();

    // Draw TX line (upload — pink/magenta)
    ctx.beginPath();
    ctx.moveTo(padding.left, padding.top + h - (rates[0].tx / maxRate) * h);
    for (let i = 1; i < rates.length; i++) {
        const x = padding.left + i * step;
        const y = padding.top + h - (rates[i].tx / maxRate) * h;
        const prevX = padding.left + (i - 1) * step;
        const prevY = padding.top + h - (rates[i - 1].tx / maxRate) * h;
        ctx.bezierCurveTo((prevX + x) / 2, prevY, (prevX + x) / 2, y, x, y);
    }
    ctx.strokeStyle = '#e879f9';
    ctx.lineWidth = 2;
    ctx.stroke();

    // TX fill
    ctx.lineTo(padding.left + (rates.length - 1) * step, padding.top + h);
    ctx.lineTo(padding.left, padding.top + h);
    ctx.closePath();
    const txGrad = ctx.createLinearGradient(0, padding.top, 0, padding.top + h);
    txGrad.addColorStop(0, 'rgba(232, 121, 249, 0.15)');
    txGrad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = txGrad;
    ctx.fill();

    // Legend
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    const lx = padding.left + w - 100;
    const ly = padding.top + 10;
    ctx.fillStyle = '#06b6d4';
    ctx.fillRect(lx, ly - 4, 12, 3);
    ctx.fillStyle = 'rgba(255,255,255,0.5)';
    ctx.fillText('↓ Download', lx + 16, ly);
    ctx.fillStyle = '#e879f9';
    ctx.fillRect(lx, ly + 12, 12, 3);
    ctx.fillStyle = 'rgba(255,255,255,0.5)';
    ctx.fillText('↑ Upload', lx + 16, ly + 16);
}

function drawMultiLineChart(canvasId, legendId, historyMap) {
    const setup = setupCanvas(canvasId);
    if (!setup) return;
    const { canvas, ctx, rect } = setup;

    const padding = { top: 20, right: 10, bottom: 30, left: 40 };
    const w = rect.width - padding.left - padding.right;
    const h = rect.height - padding.top - padding.bottom;

    // Store chart metadata for hover
    canvas._chartMeta = { padding, w, h, type: 'multi', historyMap };

    drawGrid(ctx, padding, w, h);
    drawYLabels(ctx, padding, h, ['100%', '75%', '50%', '25%', '0%']);

    // Find data for x-axis labels
    const firstData = Object.values(historyMap).find(d => d && d.length >= 2);
    if (firstData) {
        const sliced = sliceForRange(firstData);
        drawXTimeLabels(ctx, padding, w, h, sliced.length);
    }

    drawThresholdLines(ctx, padding, w, h);

    const colors = [
        '#f59e0b', '#3b82f6', '#ef4444', '#10b981', '#8b5cf6', '#ec4899',
    ];

    const legend = document.getElementById(legendId);
    if (legend) legend.innerHTML = '';

    let colorIdx = 0;
    for (const [mount, rawData] of Object.entries(historyMap)) {
        const data = sliceForRange(rawData);
        if (!data || data.length < 2) continue;

        const color = colors[colorIdx % colors.length];
        const step = w / (data.length - 1);

        if (legend) {
            legend.innerHTML += `
                <div class="chart-legend-item">
                    <div class="chart-legend-dot" style="background: ${color}"></div>
                    <span style="color: var(--text-muted);">${mount}</span>
                </div>
            `;
        }

        ctx.beginPath();
        const firstY = padding.top + h - (data[0].value / 100) * h;
        ctx.moveTo(padding.left, firstY);

        for (let i = 1; i < data.length; i++) {
            const x = padding.left + i * step;
            const val = Math.max(0, Math.min(100, data[i].value));
            const y = padding.top + h - (val / 100) * h;
            const prevX = padding.left + (i - 1) * step;
            const prevVal = Math.max(0, Math.min(100, data[i - 1].value));
            const prevY = padding.top + h - (prevVal / 100) * h;
            const cpX = (prevX + x) / 2;
            ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
        }

        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();
        colorIdx++;
    }
}

// ─── Chart Hover Tooltip System ───
(function initChartHover() {
    const tooltip = document.getElementById('chart-tooltip');
    if (!tooltip) {
        // Will be initialized on page load
        document.addEventListener('DOMContentLoaded', initChartHover);
        return;
    }

    document.addEventListener('mousemove', e => {
        const canvas = e.target.closest('canvas');
        if (!canvas || !canvas._chartMeta) {
            tooltip.style.display = 'none';
            return;
        }
        const meta = canvas._chartMeta;
        const cRect = canvas.getBoundingClientRect();
        const mx = e.clientX - cRect.left;
        const my = e.clientY - cRect.top;
        const { padding, w, h, data } = meta;

        // Check bounds
        if (mx < padding.left || mx > padding.left + w || my < padding.top || my > padding.top + h) {
            tooltip.style.display = 'none';
            return;
        }

        const frac = (mx - padding.left) / w;

        if (meta.type === 'percent') {
            const idx = Math.round(frac * (data.length - 1));
            if (idx < 0 || idx >= data.length) { tooltip.style.display = 'none'; return; }
            const val = data[idx].value.toFixed(1);
            const secsAgo = Math.round((data.length - 1 - idx) * 2);
            const timeLabel = secsAgo >= 60 ? `${Math.round(secsAgo / 60)}m ago` : `${secsAgo}s ago`;
            tooltip.innerHTML = `<span style="color:${meta.strokeColor}; font-weight:700;">${val}%</span><br><span style="color:var(--text-muted);">${timeLabel}</span>`;
        } else if (meta.type === 'network') {
            const idx = Math.round(frac * (data.length - 1));
            if (idx < 0 || idx >= data.length) { tooltip.style.display = 'none'; return; }
            const r = data[idx];
            const secsAgo = Math.round((data.length - 1 - idx) * 2);
            const timeLabel = secsAgo >= 60 ? `${Math.round(secsAgo / 60)}m ago` : `${secsAgo}s ago`;
            tooltip.innerHTML = `<span style="color:#06b6d4;">↓ ${formatRate(r.rx)}</span><br><span style="color:#e879f9;">↑ ${formatRate(r.tx)}</span><br><span style="color:var(--text-muted);">${timeLabel}</span>`;
        } else if (meta.type === 'multi') {
            let html = '';
            for (const [mount, rawData] of Object.entries(meta.historyMap)) {
                const sliced = sliceForRange(rawData);
                if (!sliced || sliced.length < 2) continue;
                const idx = Math.round(frac * (sliced.length - 1));
                if (idx < 0 || idx >= sliced.length) continue;
                html += `<div>${mount}: ${sliced[idx].value.toFixed(1)}%</div>`;
            }
            if (!html) { tooltip.style.display = 'none'; return; }
            tooltip.innerHTML = html;
        }

        tooltip.style.display = 'block';
        tooltip.style.left = (e.clientX + 12) + 'px';
        tooltip.style.top = (e.clientY - 10) + 'px';

        // Draw crosshair on canvas
        const dpr = window.devicePixelRatio || 1;
        const ctx = canvas.getContext('2d');
        // We need to redraw the chart to clear previous crosshair, but that's expensive.
        // Instead, we'll just overlay a thin vertical line
    });

    document.addEventListener('mouseout', e => {
        if (e.target.tagName === 'CANVAS') {
            tooltip.style.display = 'none';
        }
    });
})();

function initCharts() {
    if (!document.getElementById('cpu-chart-canvas')) return;
    redrawAllCharts();
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

        // Determine the correct host for VNC connections (remote node vs local)
        let vncHost = window.location.hostname;
        if (currentNodeId) {
            const node = allNodes.find(n => n.id === currentNodeId);
            if (node && !node.is_self) vncHost = node.address;
        }

        const vncText = (vm.running && vm.vnc_port)
            ? (vm.vnc_ws_port
                ? `<a href="/vnc.html?name=${encodeURIComponent(vm.name)}&port=${vm.vnc_ws_port}&host=${encodeURIComponent(vncHost)}" target="_blank" 
                    class="badge" style="cursor:pointer; text-decoration:none; background:rgba(234,179,8,0.15); color:#eab308;" title="Open console in browser">🖥️ :${vm.vnc_port}</a>`
                : `<span class="badge" style="background:rgba(234,179,8,0.15); color:#eab308;" title="Connect with VNC client to port ${vm.vnc_port}">:${vm.vnc_port}</span>`)
            : '—';

        const wolfnetIp = vm.wolfnet_ip || '—';
        const autostart = vm.auto_start ? 'checked' : '';

        return `
            <tr>
                <td><strong>${vm.name}</strong>${vm.iso_path ? `<br><small style="color:var(--text-muted);">💿 ${vm.iso_path.split('/').pop()}</small>` : ''}</td>
                <td><span style="color:${statusColor}">● ${statusText}</span></td>
                <td>${vm.cpus} vCPU / ${vm.memory_mb} MB</td>
                <td>${vm.disk_size_gb} GiB${(vm.extra_disks && vm.extra_disks.length > 0) ? ` <span class="badge" style="font-size:10px;">+${vm.extra_disks.length} vol${vm.extra_disks.length > 1 ? 's' : ''}</span>` : ''}</td>
                <td>${wolfnetIp !== '—' ? `<span class="badge" style="background:var(--accent-bg); color:var(--accent);">${wolfnetIp}</span>` : '—'}</td>
                <td>${vncText}</td>
                <td><input type="checkbox" ${autostart} onchange="toggleVmAutostart('${vm.name}', this.checked)"></td>
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
    // Find mount name for the title
    const mount = allStorageMounts.find(m => m.id === id);
    const name = mount ? mount.name : id;

    // Show progress modal
    const modal = document.getElementById('mount-progress-modal');
    document.getElementById('mount-progress-title').textContent = `💾 Mounting: ${name}`;
    document.getElementById('mount-progress-spinner').textContent = '⏳';
    document.getElementById('mount-progress-status').textContent = 'Connecting...';
    document.getElementById('mount-progress-status').style.color = '';
    document.getElementById('mount-progress-detail').textContent = mount?.type === 's3'
        ? `Connecting to S3 endpoint and syncing bucket...`
        : 'Mounting storage...';
    document.getElementById('mount-progress-footer').style.display = 'none';
    modal.classList.add('active');

    // Brief delay so user sees "Connecting..."
    await new Promise(r => setTimeout(r, 300));
    document.getElementById('mount-progress-status').textContent = 'Waiting for response...';

    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}/mount`), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Mount failed');

        // Success
        document.getElementById('mount-progress-spinner').textContent = '✅';
        document.getElementById('mount-progress-status').textContent = 'Mounted successfully!';
        document.getElementById('mount-progress-status').style.color = 'var(--success)';
        document.getElementById('mount-progress-detail').textContent = data.message || '';
    } catch (e) {
        // Error
        document.getElementById('mount-progress-spinner').textContent = '❌';
        document.getElementById('mount-progress-status').textContent = 'Mount Failed';
        document.getElementById('mount-progress-status').style.color = '#ef4444';
        document.getElementById('mount-progress-detail').textContent = e.message;
    }
    // Show OK button
    document.getElementById('mount-progress-footer').style.display = '';
}

function closeMountProgress() {
    document.getElementById('mount-progress-modal').classList.remove('active');
    loadStorageMounts();
}

async function unmountStorage(id) {
    try {
        showToast('Unmounting...', 'info');
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}/unmount`), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Unmount failed');
        showToast(data.message || 'Unmounted', 'success');
        loadStorageMounts();
    } catch (e) {
        showToast('Unmount error: ' + e.message, 'error');
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
fetchNodes();
fetchMetricsHistory(); // Initial history load
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

// ─── Networking ───

let cachedInterfaces = [];

async function loadNetworking() {
    try {
        const [ifResp, dnsResp, wnResp, mappingsResp] = await Promise.all([
            fetch(apiUrl('/api/networking/interfaces')),
            fetch(apiUrl('/api/networking/dns')),
            fetch(apiUrl('/api/networking/wolfnet')),
            fetch(apiUrl('/api/networking/ip-mappings')),
        ]);
        const interfaces = await ifResp.json();
        const dns = await dnsResp.json();
        const wolfnet = await wnResp.json();
        const mappings = mappingsResp.ok ? await mappingsResp.json() : [];

        cachedInterfaces = interfaces;
        renderNetInterfaces(interfaces);
        renderDnsConfig(dns);
        renderWolfNetStatus(wolfnet);
        renderIpMappings(mappings);
    } catch (e) {
        console.error('Failed to load networking:', e);
    }
}

function renderNetInterfaces(interfaces) {
    const tbody = document.getElementById('net-interfaces-table');
    if (!tbody) return;

    if (interfaces.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No interfaces found</td></tr>';
        return;
    }

    tbody.innerHTML = interfaces.map(iface => {
        const stateColor = iface.state === 'up' ? 'var(--success)' : iface.state === 'down' ? 'var(--danger)' : 'var(--text-muted)';
        const stateBadge = `<span class="badge" style="background:${stateColor}20; color:${stateColor}; font-size:11px;">${iface.state.toUpperCase()}</span>`;

        // Addresses
        const addrs = iface.addresses
            .filter(a => a.scope !== 'link' || a.family === 'inet')
            .map(a => {
                const isV6 = a.family === 'inet6';
                const label = `${a.address}/${a.prefix}`;
                const removeBtn = `<span style="cursor:pointer; color:var(--danger); margin-left:4px; font-size:10px;" onclick="removeIpAddress('${iface.name}', '${a.address}', ${a.prefix})" title="Remove">✕</span>`;
                return `<div style="font-size:12px; font-family:var(--font-mono); ${isV6 ? 'color:var(--text-muted); font-size:11px;' : ''}">
                    ${label}${removeBtn}
                </div>`;
            }).join('');
        const addrCell = addrs || '<span style="color:var(--text-muted); font-size:12px;">—</span>';

        // Name styling
        let nameLabel = `<strong>${iface.name}</strong>`;
        if (iface.is_vlan) {
            nameLabel += ` <span class="badge" style="background:rgba(168,85,247,0.15); color:#a855f7; font-size:9px; margin-left:4px;">VLAN ${iface.vlan_id || ''}</span>`;
        }
        if (iface.name.startsWith('docker') || iface.name.startsWith('br-') || iface.name.startsWith('veth')) {
            nameLabel += ` <span class="badge" style="background:rgba(59,130,246,0.15); color:#60a5fa; font-size:9px; margin-left:4px;">Docker</span>`;
        }
        if (iface.name.startsWith('wn') || iface.name.startsWith('wolfnet')) {
            nameLabel += ` <span class="badge" style="background:rgba(34,197,94,0.15); color:#22c55e; font-size:9px; margin-left:4px;">WolfNet</span>`;
        }

        const speed = iface.speed || '—';
        const mtu = iface.mtu || '—';
        const driver = iface.driver || '—';
        const mac = iface.mac ? `<span style="font-family:var(--font-mono); font-size:11px;">${iface.mac}</span>` : '—';

        // Actions
        const toggleBtn = iface.state === 'up'
            ? `<button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--danger); border:1px solid var(--border); font-size:11px; padding:2px 8px;" onclick="toggleInterface('${iface.name}', false)" title="Bring down">⏸️</button>`
            : `<button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--success); border:1px solid var(--border); font-size:11px; padding:2px 8px;" onclick="toggleInterface('${iface.name}', true)" title="Bring up">▶️</button>`;

        const addIpBtn = `<button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border); font-size:11px; padding:2px 8px;" onclick="showAddIpModal('${iface.name}')" title="Add IP">➕</button>`;

        const vlanDeleteBtn = iface.is_vlan
            ? `<button class="btn btn-sm btn-danger" style="font-size:11px; padding:2px 8px;" onclick="deleteVlan('${iface.name}')" title="Delete VLAN">🗑️</button>`
            : '';

        return `<tr>
            <td>${nameLabel}</td>
            <td>${stateBadge}</td>
            <td>${addrCell}</td>
            <td>${mac}</td>
            <td style="font-size:12px;">${speed}</td>
            <td style="font-size:12px;">${mtu}</td>
            <td style="font-size:12px;">${driver}</td>
            <td style="white-space:nowrap;">
                ${toggleBtn} ${addIpBtn} ${vlanDeleteBtn}
            </td>
        </tr>`;
    }).join('');
}

function renderWolfNetStatus(wn) {
    const body = document.getElementById('wolfnet-status-body');
    const actions = document.getElementById('wolfnet-actions');
    if (!body) return;

    if (!wn.installed) {
        body.innerHTML = '<p style="color:var(--text-muted);">WolfNet is not installed. Install it from the Components page.</p>';
        if (actions) actions.innerHTML = '';
        return;
    }

    const statusBadge = wn.running
        ? '<span class="badge" style="background:rgba(34,197,94,0.15); color:#22c55e;">RUNNING</span>'
        : '<span class="badge" style="background:rgba(239,68,68,0.15); color:#ef4444;">STOPPED</span>';

    let peersHtml = '';
    if (wn.peers.length > 0) {
        peersHtml = `
            <table class="data-table" style="margin-top:12px;">
                <thead><tr><th>Peer</th><th>IP</th><th>Endpoint</th><th>Status</th></tr></thead>
                <tbody>
                    ${wn.peers.map(p => `<tr>
                        <td style="font-weight:600;">${p.name}</td>
                        <td style="font-family:var(--font-mono); font-size:12px;">${p.ip || '—'}</td>
                        <td style="font-family:var(--font-mono); font-size:12px;">${p.endpoint || '—'}</td>
                        <td>${p.connected
                ? '<span class="badge" style="background:rgba(34,197,94,0.15); color:#22c55e;">Connected</span>'
                : '<span class="badge" style="background:rgba(239,68,68,0.15); color:#ef4444;">Unreachable</span>'
            }</td>
                    </tr>`).join('')}
                </tbody>
            </table>`;
    } else {
        peersHtml = '<p style="color:var(--text-muted); margin-top:8px; font-size:13px;">No peers configured.</p>';
    }

    body.innerHTML = `
        <div style="display:flex; gap:24px; align-items:center; flex-wrap:wrap; margin-bottom:8px;">
            <div>Status: ${statusBadge}</div>
            ${wn.interface ? `<div>Interface: <code>${wn.interface}</code></div>` : ''}
            ${wn.ip ? `<div>IP: <code>${wn.ip}</code></div>` : ''}
        </div>
        ${peersHtml}`;

    if (actions) {
        actions.innerHTML = wn.running
            ? '<button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border); font-size:11px;" onclick="wolfnetAction(\'restart\')">🔄 Restart</button>'
            : '<button class="btn btn-sm" style="background:var(--bg-tertiary); color:var(--success); border:1px solid var(--border); font-size:11px;" onclick="wolfnetAction(\'start\')">▶️ Start</button>';
    }
}

let currentDns = { nameservers: [], search_domains: [], method: 'resolv.conf', editable: true };

function renderDnsConfig(dns) {
    currentDns = dns;
    const body = document.getElementById('dns-config-body');
    if (!body) return;

    const methodLabel = {
        'netplan': 'Netplan',
        'networkmanager': 'NetworkManager',
        'systemd-resolved': 'systemd-resolved',
        'resolv.conf': '/etc/resolv.conf'
    }[dns.method] || dns.method;

    const servers = dns.nameservers.length > 0
        ? dns.nameservers.map((s, i) => `
            <div style="display:flex; align-items:center; gap:8px; font-family:var(--font-mono); font-size:13px; padding:4px 0;">
                <span>🔹 ${s}</span>
                ${dns.editable ? `<button onclick="removeDnsNameserver(${i})" title="Remove" style="background:none; border:none; color:var(--danger); cursor:pointer; font-size:14px; padding:0 4px;">✕</button>` : ''}
            </div>`).join('')
        : '<span style="color:var(--text-muted);">No nameservers configured</span>';

    const domains = dns.search_domains.length > 0
        ? dns.search_domains.map((d, i) => `
            <span class="badge" style="background:var(--bg-tertiary); color:var(--text-primary); font-size:11px; margin-right:4px; display:inline-flex; align-items:center; gap:4px;">
                ${d}
                ${dns.editable ? `<button onclick="removeDnsSearchDomain(${i})" style="background:none; border:none; color:var(--danger); cursor:pointer; font-size:12px; padding:0; line-height:1;">✕</button>` : ''}
            </span>`).join('')
        : '<span style="color:var(--text-muted);">None</span>';

    body.innerHTML = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 24px;">
            <div>
                <h4 style="margin-bottom:8px; font-size:13px; color:var(--text-secondary);">Nameservers</h4>
                ${servers}
                ${dns.editable ? `
                <div style="display:flex; gap:6px; margin-top:8px;">
                    <input type="text" id="dns-new-ns" placeholder="e.g. 1.1.1.1" style="flex:1; padding:6px 10px; border:1px solid var(--border-color); border-radius:6px; background:var(--bg-primary); color:var(--text-primary); font-family:var(--font-mono); font-size:12px;">
                    <button onclick="addDnsNameserver()" class="btn-sm" style="padding:6px 12px; background:var(--accent-primary); color:white; border:none; border-radius:6px; cursor:pointer; font-size:12px; white-space:nowrap;">+ Add</button>
                </div>` : ''}
            </div>
            <div>
                <h4 style="margin-bottom:8px; font-size:13px; color:var(--text-secondary);">Search Domains</h4>
                <div style="display:flex; flex-wrap:wrap; gap:4px;">${domains}</div>
                ${dns.editable ? `
                <div style="display:flex; gap:6px; margin-top:8px;">
                    <input type="text" id="dns-new-domain" placeholder="e.g. example.com" style="flex:1; padding:6px 10px; border:1px solid var(--border-color); border-radius:6px; background:var(--bg-primary); color:var(--text-primary); font-family:var(--font-mono); font-size:12px;">
                    <button onclick="addDnsSearchDomain()" class="btn-sm" style="padding:6px 12px; background:var(--accent-primary); color:white; border:none; border-radius:6px; cursor:pointer; font-size:12px; white-space:nowrap;">+ Add</button>
                </div>` : ''}
            </div>
        </div>
        <p style="margin-top:12px; font-size:11px; color:var(--text-muted);">
            Managed via <strong>${methodLabel}</strong>${dns.method === 'netplan' ? ' (writes to /etc/netplan/99-wolfstack-dns.yaml)' : dns.method === 'systemd-resolved' ? ' (writes to /etc/systemd/resolved.conf.d/wolfstack-dns.conf)' : dns.method === 'networkmanager' ? ' (sets via nmcli)' : ''}.
        </p>`;
}

async function saveDns(nameservers, searchDomains) {
    try {
        const resp = await fetch(apiUrl('/api/networking/dns'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nameservers, search_domains: searchDomains }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to update DNS');
        showToast(data.message || 'DNS updated', 'success');
        loadNetworking();
    } catch (e) {
        alert('DNS update failed: ' + e.message);
    }
}

function addDnsNameserver() {
    const input = document.getElementById('dns-new-ns');
    const ns = input.value.trim();
    if (!ns) return;
    // Basic IP validation
    if (!/^[\d.:a-fA-F]+$/.test(ns)) { alert('Invalid IP address'); return; }
    if (currentDns.nameservers.includes(ns)) { alert('Already exists'); return; }
    const updated = [...currentDns.nameservers, ns];
    saveDns(updated, currentDns.search_domains);
}

function removeDnsNameserver(index) {
    const ns = currentDns.nameservers[index];
    if (!confirm(`Remove nameserver ${ns}?`)) return;
    const updated = currentDns.nameservers.filter((_, i) => i !== index);
    saveDns(updated, currentDns.search_domains);
}

function addDnsSearchDomain() {
    const input = document.getElementById('dns-new-domain');
    const domain = input.value.trim();
    if (!domain) return;
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) { alert('Invalid domain'); return; }
    if (currentDns.search_domains.includes(domain)) { alert('Already exists'); return; }
    const updated = [...currentDns.search_domains, domain];
    saveDns(currentDns.nameservers, updated);
}

function removeDnsSearchDomain(index) {
    const domain = currentDns.search_domains[index];
    if (!confirm(`Remove search domain ${domain}?`)) return;
    const updated = currentDns.search_domains.filter((_, i) => i !== index);
    saveDns(currentDns.nameservers, updated);
}

async function toggleInterface(name, up) {
    if (!confirm(`${up ? 'Bring up' : 'Bring down'} interface ${name}?`)) return;
    try {
        const resp = await fetch(apiUrl(`/api/networking/interfaces/${name}/state`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ up }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        showToast(data.message, 'success');
        loadNetworking();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

function showAddIpModal(ifaceName) {
    document.getElementById('add-ip-interface').value = ifaceName;
    document.getElementById('add-ip-iface-name').textContent = ifaceName;
    document.getElementById('add-ip-address').value = '';
    document.getElementById('add-ip-prefix').value = '24';
    document.getElementById('add-ip-modal').classList.add('active');
}
function closeAddIpModal() {
    document.getElementById('add-ip-modal').classList.remove('active');
}

async function addIpAddress() {
    const iface = document.getElementById('add-ip-interface').value;
    const address = document.getElementById('add-ip-address').value.trim();
    const prefix = parseInt(document.getElementById('add-ip-prefix').value);
    if (!address) { alert('Please enter an IP address'); return; }

    try {
        const resp = await fetch(apiUrl(`/api/networking/interfaces/${iface}/ip`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, prefix }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        closeAddIpModal();
        showToast(data.message, 'success');
        loadNetworking();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function removeIpAddress(iface, address, prefix) {
    if (!confirm(`Remove ${address}/${prefix} from ${iface}?`)) return;
    try {
        const resp = await fetch(apiUrl(`/api/networking/interfaces/${iface}/ip`), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, prefix }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        showToast(data.message, 'success');
        loadNetworking();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

function showCreateVlanModal() {
    const select = document.getElementById('vlan-parent');
    // Populate with physical interfaces (non-VLAN, non-docker, non-virtual)
    const physicalIfaces = cachedInterfaces.filter(i =>
        !i.is_vlan && !i.name.startsWith('docker') && !i.name.startsWith('br-')
        && !i.name.startsWith('veth') && !i.name.startsWith('wn') && !i.name.startsWith('virbr')
    );
    select.innerHTML = physicalIfaces.map(i => `<option value="${i.name}">${i.name}</option>`).join('');
    document.getElementById('vlan-id').value = '';
    document.getElementById('vlan-name').value = '';
    document.getElementById('create-vlan-modal').classList.add('active');
}
function closeCreateVlanModal() {
    document.getElementById('create-vlan-modal').classList.remove('active');
}

async function createVlan() {
    const parent = document.getElementById('vlan-parent').value;
    const vlan_id = parseInt(document.getElementById('vlan-id').value);
    const name = document.getElementById('vlan-name').value.trim() || null;
    if (!parent || !vlan_id || vlan_id < 1 || vlan_id > 4094) { alert('Please select a parent and enter a valid VLAN ID (1-4094)'); return; }

    try {
        const resp = await fetch(apiUrl('/api/networking/vlans'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ parent, vlan_id, name }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        closeCreateVlanModal();
        showToast(data.message, 'success');
        loadNetworking();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function deleteVlan(name) {
    if (!confirm(`Delete VLAN interface ${name}? This will remove the interface immediately.`)) return;
    try {
        const resp = await fetch(apiUrl(`/api/networking/vlans/${name}`), { method: 'DELETE' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        showToast(data.message, 'success');
        loadNetworking();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function wolfnetAction(action) {
    try {
        const resp = await fetch(apiUrl(`/api/services/wolfnet`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        showToast(`WolfNet ${action}: ${data.message}`, 'success');
        setTimeout(loadNetworking, 2000);
    } catch (e) {
        alert('WolfNet error: ' + e.message);
    }
}

// ─── Public IP Mappings ───

function renderIpMappings(mappings) {
    const tbody = document.getElementById('ip-mappings-table');
    const empty = document.getElementById('ip-mappings-empty');
    if (!tbody) return;

    if (!mappings || mappings.length === 0) {
        tbody.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';

    tbody.innerHTML = mappings.map(m => {
        const statusBadge = m.enabled
            ? '<span class="badge" style="background:rgba(34,197,94,0.15); color:#22c55e; font-size:11px;">Active</span>'
            : '<span class="badge" style="background:rgba(107,114,128,0.2); color:#6b7280; font-size:11px;">Disabled</span>';

        const portsLabel = m.ports || '<span style="color:var(--text-muted);">all</span>';
        const protoLabel = m.protocol === 'all' ? 'TCP+UDP' : m.protocol.toUpperCase();
        const label = m.label || '<span style="color:var(--text-muted);">—</span>';

        return `<tr>
            <td style="font-family:var(--font-mono); font-size:13px; font-weight:600;">${m.public_ip}</td>
            <td style="font-family:var(--font-mono); font-size:13px;">${m.wolfnet_ip}</td>
            <td style="font-family:var(--font-mono); font-size:12px;">${portsLabel}</td>
            <td style="font-size:12px;">${protoLabel}</td>
            <td style="font-size:12px;">${label}</td>
            <td>${statusBadge}</td>
            <td>
                <button class="btn btn-sm btn-danger" style="font-size:11px; padding:2px 8px;" onclick="removeIpMapping('${m.id}', '${m.public_ip}', '${m.wolfnet_ip}')" title="Remove mapping">🗑️</button>
            </td>
        </tr>`;
    }).join('');
}

async function showCreateMappingModal() {
    // Reset fields
    document.getElementById('mapping-public-ip').value = '';
    document.getElementById('mapping-wolfnet-ip').value = '';
    document.getElementById('mapping-ports').value = '';
    document.getElementById('mapping-protocol').value = 'all';
    document.getElementById('mapping-label').value = '';

    // Fetch available IPs for dropdowns
    try {
        const resp = await fetch(apiUrl('/api/networking/available-ips'));
        if (resp.ok) {
            const data = await resp.json();

            // Populate public IP dropdown
            const pubSelect = document.getElementById('mapping-public-ip-select');
            pubSelect.innerHTML = '<option value="">— Select or enter manually —</option>';
            (data.public_ips || []).forEach(ip => {
                pubSelect.innerHTML += `<option value="${ip}">${ip}</option>`;
            });

            // Populate WolfNet IP dropdown
            const wnSelect = document.getElementById('mapping-wolfnet-ip-select');
            wnSelect.innerHTML = '<option value="">— Select or enter manually —</option>';
            (data.wolfnet_ips || []).forEach(entry => {
                wnSelect.innerHTML += `<option value="${entry.ip}">${entry.ip} (${entry.source})</option>`;
            });
        }
    } catch (e) {
        console.error('Failed to fetch available IPs:', e);
    }

    document.getElementById('create-mapping-modal').classList.add('active');
}

function closeCreateMappingModal() {
    document.getElementById('create-mapping-modal').classList.remove('active');
}

function onMappingPublicIpSelect() {
    const val = document.getElementById('mapping-public-ip-select').value;
    if (val) document.getElementById('mapping-public-ip').value = val;
}

function onMappingWolfnetIpSelect() {
    const val = document.getElementById('mapping-wolfnet-ip-select').value;
    if (val) document.getElementById('mapping-wolfnet-ip').value = val;
}

async function createIpMapping() {
    const public_ip = document.getElementById('mapping-public-ip').value.trim();
    const wolfnet_ip = document.getElementById('mapping-wolfnet-ip').value.trim();
    const ports = document.getElementById('mapping-ports').value.trim() || null;
    const protocol = document.getElementById('mapping-protocol').value;
    const label = document.getElementById('mapping-label').value.trim() || null;

    if (!public_ip) { alert('Please enter a public IP address'); return; }
    if (!wolfnet_ip) { alert('Please enter a WolfNet IP address'); return; }

    try {
        const resp = await fetch(apiUrl('/api/networking/ip-mappings'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ public_ip, wolfnet_ip, ports, protocol, label }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to create mapping');
        closeCreateMappingModal();
        showToast(data.message, 'success');
        loadNetworking();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function removeIpMapping(id, publicIp, wolfnetIp) {
    if (!confirm(`Remove mapping ${publicIp} → ${wolfnetIp}? This will also remove the iptables rules.`)) return;
    try {
        const resp = await fetch(apiUrl(`/api/networking/ip-mappings/${id}`), { method: 'DELETE' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        showToast(data.message, 'success');
        loadNetworking();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// ─── WolfNet Management Page ───

let wolfnetData = null;

async function loadWolfNet() {
    try {
        const [statusResp, configResp, localInfoResp, fullStatusResp] = await Promise.all([
            fetch(apiUrl('/api/networking/wolfnet')),
            fetch(apiUrl('/api/networking/wolfnet/config')),
            fetch(apiUrl('/api/networking/wolfnet/local-info')),
            fetch(apiUrl('/api/networking/wolfnet/status-full')),
        ]);
        const status = await statusResp.json();
        let config = '';
        if (configResp.ok) {
            const configData = await configResp.json();
            config = configData.config || '';
        }
        let localInfo = null;
        if (localInfoResp.ok) {
            localInfo = await localInfoResp.json();
            if (localInfo.error) localInfo = null;
        }
        let fullStatus = null;
        if (fullStatusResp.ok) {
            fullStatus = await fullStatusResp.json();
        }
        wolfnetData = status;
        wolfnetLocalInfo = localInfo;
        renderWolfNetPage(status, config, localInfo, fullStatus);
    } catch (e) {
        console.error('Failed to load WolfNet:', e);
    }
}

let wolfnetLocalInfo = null;

function formatDuration(secs) {
    if (secs === undefined || secs === null || secs >= 18446744073709551615) return 'never';
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m ago`;
    return `${Math.floor(secs / 86400)}d ago`;
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function renderWolfNetPage(wn, config, localInfo, fullStatus) {
    // Status cards
    const statusEl = document.getElementById('wn-status-val');
    const statusIcon = document.getElementById('wn-status-icon');
    const enabledEl = document.getElementById('wn-enabled-val');
    const ifaceEl = document.getElementById('wn-interface-val');
    const ipEl = document.getElementById('wn-ip-val');
    const connectedEl = document.getElementById('wn-connected-val');
    const totalPeersEl = document.getElementById('wn-total-peers-val');

    if (!wn.installed) {
        if (statusEl) statusEl.textContent = 'Not Installed';
        if (statusIcon) { statusIcon.style.background = 'var(--danger-bg)'; statusIcon.style.color = 'var(--danger)'; }
        if (enabledEl) enabledEl.textContent = 'Install from Components page';
        if (ifaceEl) ifaceEl.textContent = '—';
        if (ipEl) ipEl.textContent = '';
        if (connectedEl) connectedEl.textContent = '0';
        if (totalPeersEl) totalPeersEl.textContent = '';
        return;
    }

    if (statusEl) statusEl.textContent = wn.running ? 'Running' : 'Stopped';
    if (statusIcon) {
        statusIcon.style.background = wn.running ? 'var(--success-bg)' : 'var(--danger-bg)';
        statusIcon.style.color = wn.running ? 'var(--success)' : 'var(--danger)';
    }
    if (enabledEl) enabledEl.textContent = wn.running ? 'Service active' : 'Service inactive';
    if (ifaceEl) ifaceEl.textContent = wn.interface || '—';
    if (ipEl) ipEl.textContent = wn.ip || '';

    // Merge config peers with live data
    const livePeers = (fullStatus && fullStatus.live_peers) || [];
    const configPeers = wn.peers || [];

    // Build merged peer list: start from config, enrich with live data
    const mergedPeers = configPeers.map(cp => {
        // Find matching live peer by IP address
        const live = livePeers.find(lp =>
            lp.address === cp.ip || lp.address === cp.ip.split('/')[0]
        );
        return {
            name: cp.name || (live ? live.hostname : '—'),
            ip: cp.ip,
            endpoint: (live ? live.endpoint : cp.endpoint) || '',
            connected: live ? live.connected : cp.connected,
            last_seen_secs: live ? live.last_seen_secs : null,
            rx_bytes: live ? live.rx_bytes : 0,
            tx_bytes: live ? live.tx_bytes : 0,
            relay_via: live ? live.relay_via : null,
            is_gateway: live ? live.is_gateway : false,
            hostname: live ? live.hostname : '',
        };
    });

    // Also add any live peers not in config (discovered via PEX)
    for (const lp of livePeers) {
        if (!mergedPeers.find(mp => mp.ip === lp.address)) {
            mergedPeers.push({
                name: lp.hostname || 'discovered',
                ip: lp.address,
                endpoint: lp.endpoint || '',
                connected: lp.connected,
                last_seen_secs: lp.last_seen_secs,
                rx_bytes: lp.rx_bytes || 0,
                tx_bytes: lp.tx_bytes || 0,
                relay_via: lp.relay_via,
                is_gateway: lp.is_gateway,
                hostname: lp.hostname || '',
            });
        }
    }

    const connectedCount = mergedPeers.filter(p => p.connected).length;
    if (connectedEl) connectedEl.textContent = connectedCount;
    if (totalPeersEl) totalPeersEl.textContent = `of ${mergedPeers.length} total`;

    // Peers table
    const table = document.getElementById('wolfnet-peers-table');
    const empty = document.getElementById('wolfnet-peers-empty');
    if (table) {
        if (mergedPeers.length === 0) {
            table.innerHTML = '';
            if (empty) empty.style.display = 'block';
        } else {
            if (empty) empty.style.display = 'none';
            table.innerHTML = mergedPeers.map(p => {
                const statusBadge = p.connected
                    ? '<span class="badge" style="background:rgba(34,197,94,0.15); color:#22c55e;">● Connected</span>'
                    : p.relay_via
                        ? `<span class="badge" style="background:rgba(168,85,247,0.15); color:#a855f7;">◉ Relay via ${escapeHtml(p.relay_via)}</span>`
                        : '<span class="badge" style="background:rgba(239,68,68,0.15); color:#ef4444;">○ Offline</span>';

                const lastSeen = p.last_seen_secs !== null && p.last_seen_secs !== undefined
                    ? `<span style="font-size:11px; color:var(--text-muted);">${formatDuration(p.last_seen_secs)}</span>`
                    : '';

                const traffic = (p.rx_bytes || p.tx_bytes)
                    ? `<span style="font-size:11px; color:var(--text-muted);">↓${formatBytes(p.rx_bytes)} ↑${formatBytes(p.tx_bytes)}</span>`
                    : '';

                const role = p.is_gateway
                    ? '<span class="badge" style="background:rgba(59,130,246,0.15); color:#3b82f6; font-size:10px; margin-left:4px;">GW</span>'
                    : '';

                return `
                <tr>
                    <td style="font-weight:600;">${escapeHtml(p.name)}${role}</td>
                    <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(p.ip) || '—'}</td>
                    <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(p.endpoint) || '<span style="color:var(--text-muted);">auto-discovery</span>'}</td>
                    <td>${statusBadge}<br>${lastSeen}</td>
                    <td>${traffic}</td>
                    <td>
                        <div style="display:flex; gap:4px;">
                            <button class="btn btn-sm btn-danger" onclick="removeWolfNetPeer('${escapeHtml(p.name)}')" style="font-size:11px; padding:3px 8px;" title="Remove peer">🗑️</button>
                        </div>
                    </td>
                </tr>
            `;
            }).join('');
        }
    }

    // Populate structured settings from config
    if (config) {
        const getVal = (key) => {
            const m = config.match(new RegExp(`^${key}\\s*=\\s*["']?([^"'\\n]+)["']?`, 'm'));
            return m ? m[1].trim() : '';
        };
        const el = (id) => document.getElementById(id);
        if (el('wn-cfg-interface')) el('wn-cfg-interface').value = getVal('interface');
        if (el('wn-cfg-address')) el('wn-cfg-address').value = getVal('address');
        if (el('wn-cfg-subnet')) el('wn-cfg-subnet').value = getVal('subnet') || '24';
        if (el('wn-cfg-port')) el('wn-cfg-port').value = getVal('listen_port') || '9600';
        if (el('wn-cfg-mtu')) el('wn-cfg-mtu').value = getVal('mtu') || '1400';
        if (el('wn-cfg-gateway')) el('wn-cfg-gateway').checked = getVal('gateway') === 'true';
        if (el('wn-cfg-discovery')) el('wn-cfg-discovery').checked = getVal('discovery') !== 'false';
    }

    // Config editor (raw)
    const editor = document.getElementById('wolfnet-config-editor');
    if (editor && config !== undefined) {
        editor.value = config;
    }

    // Node identity
    if (localInfo && localInfo.public_key) {
        const identEl = document.getElementById('wn-node-identity');
        if (identEl) identEl.style.display = '';
        const hostnameEl = document.getElementById('wn-local-hostname');
        const pubkeyEl = document.getElementById('wn-local-pubkey');
        if (hostnameEl) hostnameEl.textContent = localInfo.hostname || '—';
        if (pubkeyEl) pubkeyEl.textContent = localInfo.public_key;
    }
}

// ─── Peer Mode Switching ───

let currentPeerMode = 'lan';

function setPeerMode(mode) {
    currentPeerMode = mode;
    const lanTab = document.getElementById('peer-tab-lan');
    const netTab = document.getElementById('peer-tab-internet');
    const lanMode = document.getElementById('peer-mode-lan');
    const netMode = document.getElementById('peer-mode-internet');
    const lanFooter = document.getElementById('peer-modal-footer-lan');
    const netFooter = document.getElementById('peer-modal-footer-internet');

    if (mode === 'lan') {
        lanTab.style.background = 'var(--accent-primary)'; lanTab.style.color = 'white';
        netTab.style.background = 'var(--bg-tertiary)'; netTab.style.color = 'var(--text-secondary)';
        lanMode.style.display = '';
        netMode.style.display = 'none';
        lanFooter.style.display = '';
        netFooter.style.display = 'none';
    } else {
        netTab.style.background = 'var(--accent-primary)'; netTab.style.color = 'white';
        lanTab.style.background = 'var(--bg-tertiary)'; lanTab.style.color = 'var(--text-secondary)';
        lanMode.style.display = 'none';
        netMode.style.display = '';
        lanFooter.style.display = 'none';
        netFooter.style.display = '';
        // Generate invite token
        generateInviteToken();
    }
}

function showAddPeerModal() {
    document.getElementById('peer-name').value = '';
    document.getElementById('peer-ip').value = '';
    document.getElementById('peer-endpoint').value = '';
    document.getElementById('peer-public-key').value = '';
    setPeerMode('lan');
    document.getElementById('add-peer-modal').classList.add('active');
}
function closeAddPeerModal() {
    document.getElementById('add-peer-modal').classList.remove('active');
}

async function generateInviteToken() {
    const loading = document.getElementById('invite-loading');
    const result = document.getElementById('invite-result');
    const errorEl = document.getElementById('invite-error');
    loading.style.display = '';
    result.style.display = 'none';
    errorEl.style.display = 'none';
    try {
        const resp = await fetch(apiUrl('/api/networking/wolfnet/invite'));
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to generate invite');
        loading.style.display = 'none';
        result.style.display = '';
        document.getElementById('invite-command').textContent = data.join_command;
        document.getElementById('invite-public-ip').textContent = data.public_ip || 'Could not detect';
        document.getElementById('invite-endpoint').textContent = data.endpoint || '—';
    } catch (e) {
        loading.style.display = 'none';
        errorEl.style.display = '';
        document.getElementById('invite-error-msg').textContent = e.message;
    }
}

function copyInviteCommand() {
    const el = document.getElementById('invite-command');
    if (el) {
        navigator.clipboard.writeText(el.textContent).then(() => {
            showToast('Join command copied to clipboard', 'success');
        });
    }
}

async function addWolfNetPeer() {
    const name = document.getElementById('peer-name').value.trim();
    const ip = document.getElementById('peer-ip').value.trim();
    const endpoint = document.getElementById('peer-endpoint').value.trim();
    const public_key = document.getElementById('peer-public-key').value.trim();

    if (!name) { alert('Please enter a peer name'); return; }
    if (!ip) { alert('Please enter the peer\'s WolfNet IP address'); return; }

    try {
        const resp = await fetch(apiUrl('/api/networking/wolfnet/peers'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, ip: ip || null, endpoint: endpoint || null, public_key: public_key || null }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to add peer');
        closeAddPeerModal();
        showToast(data.message || 'Peer added', 'success');

        // Show join command modal with reverse config
        const info = data.local_info;
        if (info && info.public_key) {
            let configSnippet = `[[peers]]\nname = "${info.hostname || 'remote-node'}"\npublic_key = "${info.public_key}"\nallowed_ip = "${info.address}"\n`;
            if (info.listen_port) {
                configSnippet += `# endpoint = "YOUR_PUBLIC_IP:${info.listen_port}"\n`;
            }
            const joinEl = document.getElementById('wolfnet-join-config');
            if (joinEl) joinEl.textContent = configSnippet;
            document.getElementById('wolfnet-join-modal').classList.add('active');
        }
        setTimeout(loadWolfNet, 2000);
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

function closeJoinModal() {
    document.getElementById('wolfnet-join-modal').classList.remove('active');
}

function copyJoinConfig() {
    const el = document.getElementById('wolfnet-join-config');
    if (el) {
        navigator.clipboard.writeText(el.textContent).then(() => {
            showToast('Copied to clipboard', 'success');
        });
    }
}

async function removeWolfNetPeer(name) {
    if (!confirm(`Remove peer "${name}"? WolfNet will be restarted.`)) return;
    try {
        const resp = await fetch(apiUrl('/api/networking/wolfnet/peers'), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to remove peer');
        showToast(data.message || 'Peer removed', 'success');
        setTimeout(loadWolfNet, 2000);
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function saveWolfNetSettings() {
    if (!confirm('Save settings and restart WolfNet?')) return;
    // Read current config and update the [network] section values
    const editor = document.getElementById('wolfnet-config-editor');
    let config = editor ? editor.value : '';
    const el = (id) => document.getElementById(id);

    // Update values in TOML
    const updates = {
        'interface': el('wn-cfg-interface')?.value || 'wolfnet0',
        'address': el('wn-cfg-address')?.value || '10.10.10.1',
        'subnet': el('wn-cfg-subnet')?.value || '24',
        'listen_port': el('wn-cfg-port')?.value || '9600',
        'mtu': el('wn-cfg-mtu')?.value || '1400',
        'gateway': el('wn-cfg-gateway')?.checked ? 'true' : 'false',
        'discovery': el('wn-cfg-discovery')?.checked ? 'true' : 'false',
    };
    for (const [key, val] of Object.entries(updates)) {
        const isStr = ['interface', 'address'].includes(key);
        const replacement = isStr ? `${key} = "${val}"` : `${key} = ${val}`;
        const regex = new RegExp(`^${key}\\s*=.*`, 'm');
        if (regex.test(config)) {
            config = config.replace(regex, replacement);
        }
    }
    // Also update the raw editor
    if (editor) editor.value = config;

    try {
        const resp = await fetch(apiUrl('/api/networking/wolfnet/config'), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to save');
        showToast(data.message || 'Config saved', 'success');
        await fetch(apiUrl('/api/networking/wolfnet/action'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'restart' }),
        });
        showToast('WolfNet restarted', 'success');
        setTimeout(loadWolfNet, 2000);
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function saveWolfNetConfig() {
    const editor = document.getElementById('wolfnet-config-editor');
    const config = editor.value;
    if (!confirm('Save raw configuration and restart WolfNet?')) return;
    try {
        const resp = await fetch(apiUrl('/api/networking/wolfnet/config'), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to save');
        showToast(data.message || 'Config saved', 'success');
        await fetch(apiUrl('/api/networking/wolfnet/action'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'restart' }),
        });
        showToast('WolfNet restarted', 'success');
        setTimeout(loadWolfNet, 2000);
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function wolfnetServiceAction(action) {
    try {
        const resp = await fetch(apiUrl('/api/networking/wolfnet/action'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed');
        showToast(`WolfNet ${action}: success`, 'success');
        setTimeout(loadWolfNet, 2000);
    } catch (e) {
        alert('WolfNet error: ' + e.message);
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
            <td><input type="checkbox" ${c.autostart ? 'checked' : ''} onchange="toggleDockerAutostart('${c.id}', this.checked)"></td>
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
            <td><input type="checkbox" ${c.autostart ? 'checked' : ''} onchange="toggleLxcAutostart('${c.name}', this.checked)"></td>
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

// ─── LXC Settings Editor (Tabbed) ───

var _lxcSettingsTab = 1;
var _lxcParsedCfg = null;

function switchLxcTab(tab) {
    _lxcSettingsTab = tab;
    document.querySelectorAll('.lxc-tab-page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.lxc-tab-btn').forEach(b => {
        b.style.borderBottomColor = 'transparent';
        b.style.color = 'var(--text-muted)';
    });
    var page = document.getElementById('lxc-tab-' + tab);
    var btn = document.querySelector('.lxc-tab-btn[data-ltab="' + tab + '"]');
    if (page) page.style.display = 'block';
    if (btn) { btn.style.borderBottomColor = 'var(--accent)'; btn.style.color = 'var(--text-primary)'; }
}

function generateMac() {
    var hex = '0123456789ABCDEF';
    var mac = '02';
    for (var i = 0; i < 5; i++) {
        mac += ':' + hex[Math.floor(Math.random() * 16)] + hex[Math.floor(Math.random() * 16)];
    }
    var el = document.getElementById('lxc-net-hwaddr');
    if (el) el.value = mac;
}

function toggleIpv4Mode() {
    var mode = document.querySelector('input[name="lxc-ipv4-mode"]:checked');
    var staticFields = document.getElementById('lxc-ipv4-static-fields');
    if (staticFields) staticFields.style.display = (mode && mode.value === 'static') ? 'block' : 'none';
}

function toggleIpv6Mode() {
    var mode = document.querySelector('input[name="lxc-ipv6-mode"]:checked');
    var staticFields = document.getElementById('lxc-ipv6-static-fields');
    if (staticFields) staticFields.style.display = (mode && mode.value === 'static') ? 'block' : 'none';
}

async function findNextWolfnetIp() {
    try {
        var resp = await fetch(apiUrl('/api/wolfnet/next-ip'));
        var data = await resp.json();
        if (data.ip) {
            var el = document.getElementById('lxc-wolfnet-ip');
            if (el) el.value = data.ip;
            showToast('Next available: ' + data.ip, 'success');
        } else {
            showToast('No available WolfNet IPs (10.10.10.2-254 all used)', 'error');
        }
    } catch (e) {
        showToast('Failed to check available IPs: ' + e.message, 'error');
    }
}

async function openLxcSettings(name) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `${name} — Settings`;
    body.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:40px;">Loading config...</p>';
    modal.classList.add('active');
    _lxcSettingsTab = 1;

    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/parsed-config`));
        if (!resp.ok) throw new Error('Failed to load config');
        const cfg = await resp.json();
        _lxcParsedCfg = cfg;

        // Auto-generate MAC if missing or invalid
        var macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
        if (!cfg.net_hwaddr || !macRegex.test(cfg.net_hwaddr.trim())) {
            var hex = '0123456789ABCDEF';
            cfg.net_hwaddr = '02';
            for (var mi = 0; mi < 5; mi++) {
                cfg.net_hwaddr += ':' + hex[Math.floor(Math.random() * 16)] + hex[Math.floor(Math.random() * 16)];
            }
        }

        var ipv4Mode = cfg.net_ipv4 ? 'static' : 'dhcp';
        var ipv6Mode = cfg.net_ipv6 ? 'static' : (cfg.net_ipv6_gw ? 'static' : 'none');

        // Fetch mounts
        var mounts = [];
        try {
            const mr = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`));
            mounts = await mr.json();
        } catch (e) { }

        var mountRows = mounts.length > 0 ? mounts.map(m => `
            <div style="display:flex;align-items:center;gap:8px;padding:6px 8px;margin-bottom:4px;background:var(--bg-primary);border-radius:6px;border:1px solid var(--border);">
                <code style="flex:1;font-size:12px;color:var(--accent);">${escapeHtml(m.host_path)}</code>
                <span style="color:var(--text-muted);font-size:12px;">→</span>
                <code style="flex:1;font-size:12px;color:var(--text-primary);">${escapeHtml(m.container_path)}</code>
                ${m.read_only ? '<span class="badge" style="font-size:10px;">RO</span>' : ''}
                <button class="btn btn-sm" style="font-size:11px;padding:2px 6px;color:var(--danger);"
                    onclick="removeLxcMount('${name}','${m.host_path.replace(/'/g, "\\'")}')" title="Remove">✕</button>
            </div>
        `).join('') : '<div style="color:var(--text-muted);font-size:12px;padding:8px;">No bind mounts configured</div>';

        var tabBtnStyle = 'flex:1;padding:10px 12px;border:none;background:none;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;';

        body.innerHTML = `
            <!-- Tab Bar -->
            <div style="display:flex;border-bottom:1px solid var(--border);background:var(--bg-secondary);margin:-24px -24px 16px -24px;">
                <button class="lxc-tab-btn" data-ltab="1" onclick="switchLxcTab(1)"
                    style="${tabBtnStyle}border-bottom:2px solid var(--accent);color:var(--text-primary);">
                    ⚙️ General
                </button>
                <button class="lxc-tab-btn" data-ltab="2" onclick="switchLxcTab(2)"
                    style="${tabBtnStyle}border-bottom:2px solid transparent;color:var(--text-muted);">
                    🌐 Network
                </button>
                <button class="lxc-tab-btn" data-ltab="3" onclick="switchLxcTab(3)"
                    style="${tabBtnStyle}border-bottom:2px solid transparent;color:var(--text-muted);">
                    💻 Resources
                </button>
                <button class="lxc-tab-btn" data-ltab="4" onclick="switchLxcTab(4)"
                    style="${tabBtnStyle}border-bottom:2px solid transparent;color:var(--text-muted);">
                    🔧 Features
                </button>
            </div>

            <!-- ═══ Tab 1: General ═══ -->
            <div class="lxc-tab-page" id="lxc-tab-1">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                    <div class="form-group">
                        <label>Container Name</label>
                        <input type="text" class="form-control" value="${escapeHtml(name)}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                    </div>
                    <div class="form-group">
                        <label>Hostname</label>
                        <input type="text" id="lxc-hostname" class="form-control" value="${escapeHtml(cfg.hostname)}"
                            placeholder="Same as container name">
                    </div>
                    <div class="form-group">
                        <label>Architecture</label>
                        <input type="text" class="form-control" value="${escapeHtml(cfg.arch || 'auto')}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                    </div>
                    <div class="form-group">
                        <label>Privilege Mode</label>
                        <input type="text" class="form-control" value="${cfg.unprivileged ? 'Unprivileged' : 'Privileged'}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                    </div>
                </div>
                <div style="margin-top:12px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <h4 style="margin:0 0 8px 0;font-size:13px;color:var(--text-primary);">🚀 Boot Options</h4>
                    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
                        <div class="form-group" style="margin:0;">
                            <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                                <input type="checkbox" id="lxc-autostart" ${cfg.autostart ? 'checked' : ''}>
                                Autostart on Boot
                            </label>
                        </div>
                        <div class="form-group" style="margin:0;">
                            <label>Start Delay (s)</label>
                            <input type="number" id="lxc-start-delay" class="form-control" value="${cfg.start_delay}" min="0">
                        </div>
                        <div class="form-group" style="margin:0;">
                            <label>Start Order</label>
                            <input type="number" id="lxc-start-order" class="form-control" value="${cfg.start_order}" min="0"
                                placeholder="Higher = starts first">
                        </div>
                    </div>
                </div>
            </div>

            <!-- ═══ Tab 2: Network ═══ -->
            <div class="lxc-tab-page" id="lxc-tab-2" style="display:none;">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                    <div class="form-group">
                        <label>Interface Name</label>
                        <input type="text" id="lxc-net-name" class="form-control" value="${escapeHtml(cfg.net_name || 'eth0')}"
                            placeholder="eth0">
                    </div>
                    <div class="form-group">
                        <label>Bridge / Link</label>
                        <input type="text" id="lxc-net-link" class="form-control" value="${escapeHtml(cfg.net_link)}"
                            placeholder="e.g. lxcbr0, vmbr0">
                    </div>
                    <div class="form-group">
                        <label>MAC Address</label>
                        <div style="display:flex;gap:4px;">
                            <input type="text" id="lxc-net-hwaddr" class="form-control" value="${escapeHtml(cfg.net_hwaddr)}"
                                placeholder="AA:BB:CC:DD:EE:FF" style="flex:1;">
                            <button class="btn btn-sm" onclick="generateMac()" title="Generate random MAC"
                                style="padding:4px 8px;font-size:11px;">🎲</button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>VLAN Tag</label>
                        <input type="text" id="lxc-net-vlan" class="form-control" value="${escapeHtml(cfg.net_vlan)}"
                            placeholder="No VLAN">
                    </div>
                    <div class="form-group">
                        <label>MTU</label>
                        <input type="text" id="lxc-net-mtu" class="form-control" value="${escapeHtml(cfg.net_mtu)}"
                            placeholder="Same as bridge">
                    </div>
                </div>

                    <div style="margin-top:12px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <h4 style="margin:0 0 8px 0;font-size:13px;">🐺 WolfNet</h4>
                    <div style="display:grid;grid-template-columns:1fr auto;gap:8px;align-items:end;">
                        <div class="form-group" style="margin:0;">
                            <label>WolfNet IP</label>
                            <input type="text" id="lxc-wolfnet-ip" class="form-control" value="${escapeHtml(cfg.wolfnet_ip || '')}"
                                placeholder="e.g. 10.10.10.50 (leave blank for none)">
                        </div>
                        <div style="display:flex;gap:4px;padding-bottom:2px;">
                            <button class="btn btn-sm" onclick="findNextWolfnetIp()" title="Find next available WolfNet IP"
                                style="padding:6px 10px;font-size:11px;">🔍 Next Available</button>
                        </div>
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:6px;">Gateway is handled automatically by WolfNet — no need to configure it here.</div>
                    <div id="wolfnet-ip-warning" style="display:none;font-size:11px;color:var(--warning);margin-top:4px;"></div>
                </div>

                <div style="margin-top:12px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <h4 style="margin:0 0 8px 0;font-size:13px;">IPv4</h4>
                    <div style="display:flex;gap:16px;margin-bottom:8px;">
                        <label style="cursor:pointer;display:flex;align-items:center;gap:4px;">
                            <input type="radio" name="lxc-ipv4-mode" value="static" onchange="toggleIpv4Mode()"
                                ${ipv4Mode === 'static' ? 'checked' : ''}> Static
                        </label>
                        <label style="cursor:pointer;display:flex;align-items:center;gap:4px;">
                            <input type="radio" name="lxc-ipv4-mode" value="dhcp" onchange="toggleIpv4Mode()"
                                ${ipv4Mode === 'dhcp' ? 'checked' : ''}> DHCP
                        </label>
                    </div>
                    <div id="lxc-ipv4-static-fields" style="display:${ipv4Mode === 'static' ? 'block' : 'none'};">
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                            <div class="form-group" style="margin:0;">
                                <label>IPv4/CIDR</label>
                                <input type="text" id="lxc-net-ipv4" class="form-control" value="${escapeHtml(cfg.net_ipv4)}"
                                    placeholder="192.168.1.100/24">
                            </div>
                            <div class="form-group" style="margin:0;">
                                <label>Gateway</label>
                                <input type="text" id="lxc-net-ipv4-gw" class="form-control" value="${escapeHtml(cfg.net_ipv4_gw)}"
                                    placeholder="192.168.1.1">
                            </div>
                        </div>
                    </div>
                </div>

                <div style="margin-top:8px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <h4 style="margin:0 0 8px 0;font-size:13px;">IPv6</h4>
                    <div style="display:flex;gap:16px;margin-bottom:8px;">
                        <label style="cursor:pointer;display:flex;align-items:center;gap:4px;">
                            <input type="radio" name="lxc-ipv6-mode" value="static" onchange="toggleIpv6Mode()"
                                ${ipv6Mode === 'static' ? 'checked' : ''}> Static
                        </label>
                        <label style="cursor:pointer;display:flex;align-items:center;gap:4px;">
                            <input type="radio" name="lxc-ipv6-mode" value="dhcp" onchange="toggleIpv6Mode()"
                                ${ipv6Mode === 'dhcp' ? 'checked' : ''}> DHCP
                        </label>
                        <label style="cursor:pointer;display:flex;align-items:center;gap:4px;">
                            <input type="radio" name="lxc-ipv6-mode" value="none" onchange="toggleIpv6Mode()"
                                ${ipv6Mode === 'none' ? 'checked' : ''}> None
                        </label>
                    </div>
                    <div id="lxc-ipv6-static-fields" style="display:${ipv6Mode === 'static' ? 'block' : 'none'};">
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                            <div class="form-group" style="margin:0;">
                                <label>IPv6/CIDR</label>
                                <input type="text" id="lxc-net-ipv6" class="form-control" value="${escapeHtml(cfg.net_ipv6)}"
                                    placeholder="fd00::100/64">
                            </div>
                            <div class="form-group" style="margin:0;">
                                <label>Gateway</label>
                                <input type="text" id="lxc-net-ipv6-gw" class="form-control" value="${escapeHtml(cfg.net_ipv6_gw)}"
                                    placeholder="fd00::1">
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ═══ Tab 3: Resources ═══ -->
            <div class="lxc-tab-page" id="lxc-tab-3" style="display:none;">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                    <div class="form-group">
                        <label>Memory Limit</label>
                        <select id="lxc-memory" class="form-control">
                            <option value="">Unlimited</option>
                            ${['256M', '512M', '1G', '2G', '4G', '8G', '16G', '32G'].map(v =>
            '<option value="' + v + '" ' + (cfg.memory_limit === v ? 'selected' : '') + '>' + v + '</option>'
        ).join('')}
                        </select>
                        ${cfg.memory_limit && !['256M', '512M', '1G', '2G', '4G', '8G', '16G', '32G'].includes(cfg.memory_limit)
                ? '<small style="color:var(--accent);margin-top:4px;display:block;">Current: ' + escapeHtml(cfg.memory_limit) + '</small>' : ''}
                    </div>
                    <div class="form-group">
                        <label>Swap Limit</label>
                        <select id="lxc-swap" class="form-control">
                            <option value="">Unlimited</option>
                            ${['0', '256M', '512M', '1G', '2G', '4G'].map(v =>
                    '<option value="' + v + '" ' + (cfg.swap_limit === v ? 'selected' : '') + '>' + (v === '0' ? 'Disabled' : v) + '</option>'
                ).join('')}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>CPU Cores (cpuset)</label>
                        <input type="text" id="lxc-cpus" class="form-control" value="${escapeHtml(cfg.cpus)}"
                            placeholder="e.g. 0-3 for 4 cores, or 0,2 for specific">
                        <small style="color:var(--text-muted);margin-top:4px;display:block;">Leave blank for unlimited</small>
                    </div>
                </div>

                <div style="margin-top:16px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                        <h4 style="margin:0;font-size:13px;">📁 Bind Mounts (${mounts.length})</h4>
                        <div style="display:flex;gap:4px;">
                            <button class="btn btn-sm" onclick="addMountPoint('${name}')"
                                style="font-size:11px;padding:4px 8px;">+ Mount</button>
                            <button class="btn btn-sm" onclick="addWolfDiskMount('${name}')"
                                style="font-size:11px;padding:4px 8px;">🐺 WolfDisk</button>
                        </div>
                    </div>
                    ${mountRows}
                </div>
            </div>

            <!-- ═══ Tab 4: Features & Advanced ═══ -->
            <div class="lxc-tab-page" id="lxc-tab-4" style="display:none;">
                <div style="padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);margin-bottom:12px;">
                    <h4 style="margin:0 0 12px 0;font-size:13px;color:var(--text-primary);">🔌 Device & Feature Toggles</h4>
                    <div style="display:grid;gap:10px;">
                        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:8px;border-radius:6px;background:var(--bg-primary);border:1px solid var(--border);">
                            <input type="checkbox" id="lxc-feat-tun" ${cfg.tun_enabled ? 'checked' : ''} style="margin-top:2px;">
                            <div>
                                <strong style="font-size:13px;">TUN/TAP Device</strong>
                                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
                                    Required for Tailscale, WireGuard, OpenVPN, and other VPN software.
                                    Enables <code>/dev/net/tun</code> inside the container.
                                </div>
                            </div>
                        </label>
                        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:8px;border-radius:6px;background:var(--bg-primary);border:1px solid var(--border);">
                            <input type="checkbox" id="lxc-feat-fuse" ${cfg.fuse_enabled ? 'checked' : ''} style="margin-top:2px;">
                            <div>
                                <strong style="font-size:13px;">FUSE</strong>
                                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
                                    Required for AppImage, sshfs, rclone mount, and other FUSE-based filesystems.
                                </div>
                            </div>
                        </label>
                        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:8px;border-radius:6px;background:var(--bg-primary);border:1px solid var(--border);">
                            <input type="checkbox" id="lxc-feat-nesting" ${cfg.nesting_enabled ? 'checked' : ''} style="margin-top:2px;">
                            <div>
                                <strong style="font-size:13px;">Nesting (LXC/Docker inside container)</strong>
                                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
                                    Allows running Docker or LXC containers inside this container.
                                    Required for Docker-in-LXC setups.
                                </div>
                            </div>
                        </label>
                        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:8px;border-radius:6px;background:var(--bg-primary);border:1px solid var(--border);">
                            <input type="checkbox" id="lxc-feat-nfs" ${cfg.nfs_enabled ? 'checked' : ''} style="margin-top:2px;">
                            <div>
                                <strong style="font-size:13px;">NFS</strong>
                                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
                                    Allow mounting NFS shares inside the container.
                                </div>
                            </div>
                        </label>
                        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:8px;border-radius:6px;background:var(--bg-primary);border:1px solid var(--border);">
                            <input type="checkbox" id="lxc-feat-keyctl" ${cfg.keyctl_enabled ? 'checked' : ''} style="margin-top:2px;">
                            <div>
                                <strong style="font-size:13px;">Keyctl (systemd support)</strong>
                                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
                                    Required for full systemd functionality in unprivileged containers.
                                    Enables proc and sys read-write mounts.
                                </div>
                            </div>
                        </label>
                    </div>
                </div>

                <details>
                    <summary style="cursor:pointer;color:var(--accent);font-size:12px;margin-bottom:8px;">
                        📝 Raw Config Editor
                    </summary>
                    <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">
                        Advanced: Edit the raw LXC config. Changes here override the structured settings above.
                        A backup is created automatically before saving.
                    </div>
                    <textarea id="lxc-config-editor" style="width:100%;height:250px;background:var(--bg-primary);color:var(--text-primary);
                        border:1px solid var(--border);border-radius:8px;padding:12px;font-family:'JetBrains Mono',monospace;
                        font-size:12px;resize:vertical;line-height:1.5;">${escapeHtml(cfg.raw_config)}</textarea>
                </details>
            </div>

            <!-- Save/Cancel Bar -->
            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--border);">
                <button class="btn btn-sm" onclick="closeContainerDetail()">Cancel</button>
                <button class="btn btn-sm btn-primary" onclick="saveLxcSettings('${name}')">💾 Save Settings</button>
            </div>
        `;
    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Failed to load config: ${e.message}</p>`;
    }
}

async function saveLxcSettings(name) {
    // Check if raw config editor was used (tab 4, details open)
    var rawEditor = document.getElementById('lxc-config-editor');
    var rawDetails = rawEditor ? rawEditor.closest('details') : null;
    var useRaw = rawDetails && rawDetails.open && rawEditor.value !== _lxcParsedCfg?.raw_config;

    if (useRaw) {
        try {
            const resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/config`), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: rawEditor.value })
            });
            if (!resp.ok) throw new Error('Failed to save raw config');
            showToast('Raw config saved (restart container to apply)', 'success');
            closeContainerDetail();
            return;
        } catch (e) {
            showToast('Error: ' + e.message, 'error');
            return;
        }
    }

    // Build structured settings from all tabs
    var ipv4Mode = document.querySelector('input[name="lxc-ipv4-mode"]:checked');
    var ipv6Mode = document.querySelector('input[name="lxc-ipv6-mode"]:checked');

    var settings = {
        hostname: (document.getElementById('lxc-hostname') || {}).value || '',
        autostart: (document.getElementById('lxc-autostart') || {}).checked || false,
        start_delay: parseInt((document.getElementById('lxc-start-delay') || {}).value) || 0,
        start_order: parseInt((document.getElementById('lxc-start-order') || {}).value) || 0,
        net_link: (document.getElementById('lxc-net-link') || {}).value || '',
        net_name: (document.getElementById('lxc-net-name') || {}).value || '',
        net_hwaddr: (document.getElementById('lxc-net-hwaddr') || {}).value || '',
        net_ipv4: (ipv4Mode && ipv4Mode.value === 'static') ? ((document.getElementById('lxc-net-ipv4') || {}).value || '') : '',
        net_ipv4_gw: (ipv4Mode && ipv4Mode.value === 'static') ? ((document.getElementById('lxc-net-ipv4-gw') || {}).value || '') : '',
        net_ipv6: (ipv6Mode && ipv6Mode.value === 'static') ? ((document.getElementById('lxc-net-ipv6') || {}).value || '') : '',
        net_ipv6_gw: (ipv6Mode && ipv6Mode.value === 'static') ? ((document.getElementById('lxc-net-ipv6-gw') || {}).value || '') : '',
        net_mtu: (document.getElementById('lxc-net-mtu') || {}).value || '',
        net_vlan: (document.getElementById('lxc-net-vlan') || {}).value || '',
        memory_limit: (document.getElementById('lxc-memory') || {}).value || '',
        swap_limit: (document.getElementById('lxc-swap') || {}).value || '',
        cpus: (document.getElementById('lxc-cpus') || {}).value || '',
        tun_enabled: (document.getElementById('lxc-feat-tun') || {}).checked || false,
        fuse_enabled: (document.getElementById('lxc-feat-fuse') || {}).checked || false,
        nesting_enabled: (document.getElementById('lxc-feat-nesting') || {}).checked || false,
        nfs_enabled: (document.getElementById('lxc-feat-nfs') || {}).checked || false,
        keyctl_enabled: (document.getElementById('lxc-feat-keyctl') || {}).checked || false,
        wolfnet_ip: (document.getElementById('lxc-wolfnet-ip') || {}).value || '',
    };

    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/settings`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Settings saved — restart container to apply changes', 'success');
            closeContainerDetail();
            // Refresh the container list
            if (typeof loadLxcContainers === 'function') loadLxcContainers();
            // Check for network conflicts
            try {
                var cr = await fetch(apiUrl('/api/network/conflicts'));
                var conflicts = await cr.json();
                conflicts.forEach(function (c) {
                    if (c.severity === 'error') {
                        showToast('⛔ Duplicate MAC ' + c.value + ' on: ' + c.containers.join(', '), 'error');
                    } else {
                        showToast('⚠️ Duplicate IP ' + c.value + ' on: ' + c.containers.join(', '), 'warning');
                    }
                });
            } catch (e) { /* ignore conflict check errors */ }
        } else {
            showToast(data.error || 'Failed to save settings', 'error');
        }
    } catch (e) {
        showToast('Error saving settings: ' + e.message, 'error');
    }
}

async function addMountPoint(name) {
    var src = prompt('Host path (e.g. /mnt/data):');
    if (!src) return;
    var dest = prompt('Container path (e.g. /mnt/data):', src);
    if (!dest) return;
    try {
        var resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host_path: src, container_path: dest, read_only: false }),
        });
        var data = await resp.json();
        if (resp.ok) { showToast(data.message || 'Mount added', 'success'); openLxcSettings(name); }
        else { showToast(data.error || 'Failed', 'error'); }
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

async function addWolfDiskMount(name) {
    var src = prompt('WolfDisk mount path on host:', '/mnt/wolfdisk');
    if (!src) return;
    var dest = prompt('Mount path inside container:', '/mnt/shared');
    if (!dest) return;
    try {
        var resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host_path: src, container_path: dest, read_only: false }),
        });
        var data = await resp.json();
        if (resp.ok) { showToast(data.message || 'WolfDisk mount added', 'success'); openLxcSettings(name); }
        else { showToast(data.error || 'Failed', 'error'); }
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

async function removeLxcMount(name, hostPath) {
    if (!confirm(`Remove mount ${hostPath}?`)) return;
    try {
        var resp = await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
            method: 'DELETE', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host_path: hostPath }),
        });
        var data = await resp.json();
        if (resp.ok) { showToast(data.message || 'Mount removed', 'success'); openLxcSettings(name); }
        else { showToast(data.error || 'Failed', 'error'); }
    } catch (e) { showToast('Failed: ' + e.message, 'error'); }
}

function escapeHtml(text) {
    if (text == null) return '';
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
    let host = window.location.hostname;
    // For remote nodes, connect to the node actually running the VM
    if (currentNodeId) {
        const node = allNodes.find(n => n.id === currentNodeId);
        if (node && !node.is_self) {
            host = node.address;
        }
    }
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

async function toggleDockerAutostart(id, enabled) {
    try {
        await fetch(apiUrl(`/api/containers/docker/${encodeURIComponent(id)}/config`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ autostart: enabled })
        });
        showToast(`Docker autostart ${enabled ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function toggleLxcAutostart(name, enabled) {
    try {
        await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/autostart`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        });
        showToast(`LXC autostart ${enabled ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function toggleVmAutostart(name, enabled) {
    try {
        await fetch(apiUrl(`/api/vms/${encodeURIComponent(name)}`), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ auto_start: enabled })
        });
        showToast(`VM autostart ${enabled ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function openDockerSettings(id) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `Docker Settings — ${id.substring(0, 12)}`;
    body.innerHTML = '<p>Loading container details...</p>';
    modal.classList.add('active');

    try {
        const resp = await fetch(apiUrl(`/api/containers/docker/${encodeURIComponent(id)}/inspect`));
        if (!resp.ok) throw new Error('Failed to fetch container info');
        const info = await resp.json();

        const restartPolicy = info.HostConfig?.RestartPolicy?.Name || 'no';
        const autostart = restartPolicy === 'unless-stopped' || restartPolicy === 'always';

        const memoryBytes = info.HostConfig?.Memory || 0;
        const memoryMb = memoryBytes ? Math.round(memoryBytes / 1024 / 1024) : 0;

        const nanoCpus = info.HostConfig?.NanoCpus || 0;
        const cpus = nanoCpus ? nanoCpus / 1000000000 : 0;

        body.innerHTML = `
            <div style="margin-bottom:12px;">
                <div class="card" style="padding:12px; background:var(--bg-tertiary); margin-bottom:12px;">
                    <h4 style="margin-top:0; font-size:14px;">Resources</h4>
                    <div class="form-group" style="margin-bottom:12px;">
                        <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                            <input type="checkbox" id="docker-autostart-modal" ${autostart ? 'checked' : ''}>
                            Autostart on Boot (Restart Policy: unless-stopped)
                        </label>
                    </div>
                    <div class="form-group" style="margin-bottom:8px;">
                         <label style="font-size:12px; font-weight:600;">Memory Limit (MB) <span style="font-weight:400; color:var(--text-muted);">(0 = no change/limit)</span></label>
                         <input type="number" id="docker-memory" class="form-control" value="${memoryMb}" min="0">
                    </div>
                    <div class="form-group">
                         <label style="font-size:12px; font-weight:600;">CPUs <span style="font-weight:400; color:var(--text-muted);">(0 = no change/limit)</span></label>
                         <input type="number" id="docker-cpus" class="form-control" value="${cpus}" min="0" step="0.1">
                    </div>
                </div>
                
                <div style="font-size:11px; color:var(--text-primary); background:var(--bg-primary); padding:8px; border-radius:4px; border:1px solid var(--border);">
                    <strong>Environment Variables:</strong>
                    <div style="max-height:100px; overflow-y:auto; font-family:monospace; color:var(--text-muted); margin-top:4px;">
                        ${(info.Config?.Env || []).map(e => `<div>${escapeHtml(e)}</div>`).join('') || 'None'}
                    </div>
                </div>
            </div>

            <div style="display:flex; justify-content:flex-end; gap:8px;">
                <button class="btn btn-sm" onclick="closeContainerDetail()">Cancel</button>
                <button class="btn btn-sm btn-primary" onclick="saveDockerSettings('${id}')">💾 Save Settings</button>
            </div>
        `;
    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Error: ${e.message}</p>
        <div style="margin-top:12px; text-align:right;">
             <button class="btn btn-sm" onclick="closeContainerDetail()">Close</button>
        </div>`;
    }
}

async function saveDockerSettings(id) {
    const autostart = document.getElementById('docker-autostart-modal').checked;
    const memoryMb = parseInt(document.getElementById('docker-memory').value) || 0;
    const cpus = parseFloat(document.getElementById('docker-cpus').value) || 0;

    try {
        const resp = await fetch(apiUrl(`/api/containers/docker/${encodeURIComponent(id)}/config`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                autostart: autostart,
                memory_mb: memoryMb > 0 ? memoryMb : null,
                cpus: cpus > 0 ? cpus : null
            })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Docker settings updated', 'success');
            closeContainerDetail();
        } else {
            showToast(data.error || 'Failed to update', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ─── Backup Management ───

async function loadBackups() {
    try {
        const [backupsRes, schedulesRes, targetsRes] = await Promise.all([
            fetch('/api/backups'),
            fetch('/api/backups/schedules'),
            fetch('/api/backups/targets'),
        ]);
        const backups = await backupsRes.json();
        const schedules = await schedulesRes.json();
        const targets = await targetsRes.json();
        renderBackupTargets(targets);
        renderBackupHistory(backups);
        renderSchedules(schedules);
        populateStorageDropdown();
        loadPbsConfig();
    } catch (e) {
        console.error('Failed to load backups:', e);
    }
}

async function populateStorageDropdown() {
    const sel = document.getElementById('backup-storage-select');
    if (!sel) return;
    sel.innerHTML = '<option value="local:/var/lib/wolfstack/backups">📁 Local — /var/lib/wolfstack/backups</option>';
    try {
        const resp = await fetch(apiUrl('/api/storage/mounts'));
        if (resp.ok) {
            const mounts = await resp.json();
            const ICONS = { s3: '☁️', nfs: '📂', directory: '📁', wolfdisk: '💾', smb: '🖧' };
            mounts.filter(m => m.status === 'mounted' && m.mount_point).forEach(m => {
                const icon = ICONS[m.type] || '📦';
                const label = `${icon} ${m.name} — ${m.mount_point}`;
                const val = `mount:${m.mount_point}`;
                sel.innerHTML += `<option value="${escapeHtml(val)}">${escapeHtml(label)}</option>`;
            });
        }
    } catch (e) {
        console.error('Failed to load storage mounts for backup dropdown:', e);
    }
    // Add PBS option if configured
    try {
        const pbsResp = await fetch(apiUrl('/api/backups/pbs/config'));
        if (pbsResp.ok) {
            const pbs = await pbsResp.json();
            if (pbs.pbs_server) {
                sel.innerHTML += `<option value="pbs:${escapeHtml(pbs.pbs_server)}">📦 PBS — ${escapeHtml(pbs.pbs_server)}/${escapeHtml(pbs.pbs_datastore)}</option>`;
            }
        }
    } catch (e) { /* PBS not configured, skip */ }
}

function renderBackupTargets(targets) {
    const container = document.getElementById('backup-targets-list');
    if (!container) return;

    if (!targets || targets.length === 0) {
        container.innerHTML = '<p style="text-align:center; padding:20px; color:var(--text-muted); grid-column:1/-1;">No containers, VMs, or configs found to backup.</p>';
        return;
    }

    const EMOJIS = { docker: '🐳', lxc: '📦', vm: '🖥️', config: '⚙️' };

    container.innerHTML = targets.map(t => {
        const emoji = EMOJIS[t.type] || '📄';
        const label = t.type === 'config' ? 'WolfStack Config' : (t.name || t.type);
        const typeLabel = t.type.toUpperCase();
        const val = JSON.stringify(t).replace(/"/g, '&quot;');
        return `<label style="display:flex; align-items:center; gap:10px; padding:10px 14px;
            background:var(--bg-input); border:1px solid var(--border); border-radius:var(--radius-sm);
            cursor:pointer; transition:var(--transition); font-size:13px;"
            onmouseover="this.style.borderColor='var(--border-light)'; this.style.background='var(--bg-card-hover)'"
            onmouseout="this.style.borderColor='var(--border)'; this.style.background='var(--bg-input)'">
            <input type="checkbox" class="backup-target-cb" value="${val}" onchange="updateBackupSelectedCount()">
            <span style="font-size:18px;">${emoji}</span>
            <span style="flex:1;">
                <span style="font-weight:500;">${escapeHtml(label)}</span>
                <span style="color:var(--text-muted); font-size:11px; margin-left:6px;">${typeLabel}</span>
            </span>
        </label>`;
    }).join('');
}

function toggleAllBackupTargets(checked) {
    document.querySelectorAll('.backup-target-cb').forEach(cb => cb.checked = checked);
    updateBackupSelectedCount();
}

function updateBackupSelectedCount() {
    const checked = document.querySelectorAll('.backup-target-cb:checked').length;
    const total = document.querySelectorAll('.backup-target-cb').length;
    const countEl = document.getElementById('backup-selected-count');
    if (countEl) countEl.textContent = `${checked} of ${total} selected`;
    const selectAll = document.getElementById('backup-select-all');
    if (selectAll) selectAll.checked = checked === total && total > 0;
}

function getSelectedTargets() {
    const checked = document.querySelectorAll('.backup-target-cb:checked');
    const targets = [];
    checked.forEach(cb => {
        try { targets.push(JSON.parse(cb.value)); } catch (e) { }
    });
    return targets;
}

// Cached PBS config for use as storage target
let _cachedPbsConfig = null;

async function getSelectedStorage() {
    const sel = document.getElementById('backup-storage-select');
    if (!sel) return { type: 'local', path: '/var/lib/wolfstack/backups' };
    const val = sel.value;
    if (val.startsWith('local:')) {
        return { type: 'local', path: val.substring(6) };
    } else if (val.startsWith('mount:')) {
        return { type: 'local', path: val.substring(6) };
    } else if (val.startsWith('pbs:')) {
        // Load the full PBS config so the backend has all fields
        if (!_cachedPbsConfig) {
            try {
                const res = await fetch(apiUrl('/api/backups/pbs/config'));
                if (res.ok) _cachedPbsConfig = await res.json();
            } catch (e) { /* fall through */ }
        }
        if (_cachedPbsConfig) {
            return {
                type: 'pbs',
                pbs_server: _cachedPbsConfig.pbs_server || '',
                pbs_datastore: _cachedPbsConfig.pbs_datastore || '',
                pbs_user: _cachedPbsConfig.pbs_user || '',
                pbs_token_name: _cachedPbsConfig.pbs_token_name || '',
                pbs_fingerprint: _cachedPbsConfig.pbs_fingerprint || '',
                pbs_namespace: _cachedPbsConfig.pbs_namespace || '',
                // Secrets are stored on server, leave empty so backend preserves them
                pbs_token_secret: '',
                pbs_password: '',
            };
        }
    }
    return { type: 'local', path: '/var/lib/wolfstack/backups' };
}

function renderBackupHistory(backups) {
    const tbody = document.getElementById('backups-table');
    const empty = document.getElementById('backups-empty');
    if (!tbody) return;

    if (!backups || backups.length === 0) {
        tbody.innerHTML = '';
        if (empty) empty.style.display = 'block';
        return;
    }
    if (empty) empty.style.display = 'none';

    backups.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));

    tbody.innerHTML = backups.map(b => {
        const typeEmoji = { docker: '🐳', lxc: '📦', vm: '🖥️', config: '⚙️' }[b.target?.type] || '📄';
        const typeName = (b.target?.type || 'unknown').toUpperCase();
        const targetName = b.target?.name || (b.target?.type === 'config' ? 'WolfStack Config' : 'Unknown');
        const storageLabel = formatStorageLabel(b.storage);
        const size = formatBytes(b.size_bytes || 0);
        const date = b.created_at ? new Date(b.created_at).toLocaleString() : '—';
        const statusBadge = b.status === 'completed'
            ? '<span class="badge" style="background:#22c55e; color:#fff;">✓ Completed</span>'
            : b.status === 'failed'
                ? `<span class="badge" style="background:#ef4444; color:#fff;">✗ Failed</span>`
                : '<span class="badge" style="background:#f59e0b; color:#000;">⏳ In Progress</span>';

        return `<tr>
            <td>${typeEmoji} ${escapeHtml(targetName)}</td>
            <td>${typeName}</td>
            <td>${escapeHtml(storageLabel)}</td>
            <td>${size}</td>
            <td>${date}</td>
            <td>${statusBadge}</td>
            <td style="text-align:right; white-space:nowrap;">
                ${b.status === 'completed' ? `<button class="btn btn-sm btn-primary" onclick="restoreBackup('${b.id}')" style="margin-right:4px;">🔄 Restore</button>` : ''}
                <button class="btn btn-sm" onclick="deleteBackup('${b.id}')" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border);">🗑️</button>
            </td>
        </tr>`;
    }).join('');
}

function renderSchedules(schedules) {
    const tbody = document.getElementById('schedules-table');
    const empty = document.getElementById('schedules-empty');
    if (!tbody) return;

    if (!schedules || schedules.length === 0) {
        tbody.innerHTML = '';
        if (empty) empty.style.display = 'block';
        return;
    }
    if (empty) empty.style.display = 'none';

    tbody.innerHTML = schedules.map(s => {
        const targets = s.backup_all ? '🌐 All' : (s.targets || []).map(t => `${t.type}:${t.name}`).join(', ');
        const storageLabel = formatStorageLabel(s.storage);
        const retention = s.retention > 0 ? `Keep ${s.retention}` : 'Unlimited';
        const enabled = s.enabled
            ? '<span class="badge" style="background:#22c55e; color:#fff;">Active</span>'
            : '<span class="badge" style="background:#6b7280; color:#fff;">Disabled</span>';

        return `<tr>
            <td>${escapeHtml(s.name)}</td>
            <td style="text-transform:capitalize;">${s.frequency}</td>
            <td>${s.time}</td>
            <td>${escapeHtml(targets)}</td>
            <td>${escapeHtml(storageLabel)}</td>
            <td>${retention}</td>
            <td>${enabled}</td>
            <td style="text-align:right;">
                <button class="btn btn-sm" onclick="deleteSchedule('${s.id}')" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border);">🗑️</button>
            </td>
        </tr>`;
    }).join('');
}

function formatStorageLabel(storage) {
    if (!storage) return '—';
    switch (storage.type) {
        case 'local': return `📁 ${storage.path || '/var/lib/wolfstack/backups'}`;
        case 's3': return `☁️ s3://${storage.bucket || '?'}`;
        case 'remote': return `🌐 ${storage.remote_url || '?'}`;
        case 'wolfdisk': return `💾 ${storage.path || '?'}`;
        default: return storage.type || '—';
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ─── Backup Now (selected targets) ───

function showBackupProgress(container, items, title) {
    const EMOJIS = { docker: '🐳', lxc: '📦', vm: '🖥️', config: '⚙️' };
    container.innerHTML = `
        <tr><td colspan="7" style="padding:0; border:none;">
            <div style="padding:20px; background:var(--bg-primary); border-radius:var(--radius-sm); border:1px solid var(--border);">
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:16px;">
                    <div class="spinner" style="width:20px; height:20px; border:3px solid var(--border); border-top-color:var(--accent); border-radius:50%; animation:spin 0.8s linear infinite;"></div>
                    <strong id="backup-progress-title">${title}</strong>
                </div>
                <div id="backup-progress-items" style="display:grid; gap:6px;">
                    ${items.map((t, i) => {
        const emoji = EMOJIS[t.type || t.target_type] || '📄';
        const name = t.name || t.type || 'item';
        return `<div id="backup-item-${i}" style="display:flex; align-items:center; gap:8px; padding:6px 10px; background:var(--bg-tertiary); border-radius:var(--radius-sm); font-size:13px;">
                            <span style="width:20px; text-align:center;" id="backup-icon-${i}">⏳</span>
                            <span>${emoji} <strong>${escapeHtml(name)}</strong></span>
                            <span id="backup-status-${i}" style="margin-left:auto; color:var(--text-muted); font-size:12px;">Waiting...</span>
                        </div>`;
    }).join('')}
                </div>
            </div>
        </td></tr>`;
}

function updateBackupItemStatus(index, status, success) {
    const icon = document.getElementById(`backup-icon-${index}`);
    const statusEl = document.getElementById(`backup-status-${index}`);
    const row = document.getElementById(`backup-item-${index}`);
    if (icon) icon.textContent = success === true ? '✅' : success === false ? '❌' : '⏳';
    if (statusEl) {
        statusEl.textContent = status;
        statusEl.style.color = success === true ? 'var(--success)' : success === false ? '#ef4444' : 'var(--accent)';
    }
    if (row && success !== null) {
        row.style.borderLeft = `3px solid ${success ? 'var(--success)' : '#ef4444'}`;
    }
}

async function backupSelected() {
    const targets = getSelectedTargets();
    if (targets.length === 0) {
        showToast('Please select at least one item to backup', 'error');
        return;
    }

    const storage = await getSelectedStorage();
    const storageLabel = storage.type === 'pbs' ? `PBS (${storage.pbs_server})` : (storage.path || storage.type);

    // Disable backup button
    const backupBtn = document.querySelector('[onclick="backupSelected()"]');
    if (backupBtn) { backupBtn.disabled = true; backupBtn.textContent = '⏳ Backing up...'; }

    const tbody = document.getElementById('backups-table');
    const allTargets = targets.length === document.querySelectorAll('.backup-target-cb').length;

    try {
        if (allTargets) {
            // All targets — single request
            if (tbody) showBackupProgress(tbody, targets, `Backing up all ${targets.length} items to ${storageLabel}...`);

            // Mark all as in-progress
            targets.forEach((_, i) => updateBackupItemStatus(i, 'Backing up...', null));

            const res = await fetch('/api/backups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ storage }),
            });
            const data = await res.json();

            if (data.error) {
                targets.forEach((_, i) => updateBackupItemStatus(i, 'Failed', false));
                showToast(`Backup failed: ${data.error}`, 'error');
            } else {
                // Mark individual results
                const entries = data.entries || [];
                targets.forEach((t, i) => {
                    const entry = entries[i];
                    if (entry && entry.status === 'completed') {
                        updateBackupItemStatus(i, `Done (${formatBytes(entry.size_bytes || 0)})`, true);
                    } else if (entry) {
                        updateBackupItemStatus(i, entry.error || 'Failed', false);
                    } else {
                        updateBackupItemStatus(i, 'Done', true);
                    }
                });
                showToast(data.message || 'Backup completed', 'success');
            }
        } else {
            // Individual targets — sequential requests with per-item progress
            if (tbody) showBackupProgress(tbody, targets, `Backing up ${targets.length} item${targets.length > 1 ? 's' : ''} to ${storageLabel}...`);

            let ok = 0, fail = 0;
            for (let i = 0; i < targets.length; i++) {
                const t = targets[i];
                const name = t.name || t.type || 'item';
                updateBackupItemStatus(i, 'Backing up...', null);
                const titleEl = document.getElementById('backup-progress-title');
                if (titleEl) titleEl.textContent = `Backing up ${name} (${i + 1}/${targets.length})...`;

                try {
                    const res = await fetch('/api/backups', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target: t, storage }),
                    });
                    const data = await res.json();
                    if (data.error) {
                        fail++;
                        updateBackupItemStatus(i, data.error, false);
                    } else {
                        ok++;
                        const entry = (data.entries || [])[0];
                        const sizeStr = entry ? formatBytes(entry.size_bytes || 0) : '';
                        updateBackupItemStatus(i, `Done${sizeStr ? ' (' + sizeStr + ')' : ''}`, true);
                    }
                } catch (e) {
                    fail++;
                    updateBackupItemStatus(i, e.message, false);
                }
            }
            const titleEl = document.getElementById('backup-progress-title');
            if (titleEl) titleEl.textContent = fail === 0 ? `✅ All ${ok} backups completed!` : `Done: ${ok} succeeded, ${fail} failed`;
            if (fail === 0) showToast(`All ${ok} backups completed`, 'success');
            else showToast(`${ok} succeeded, ${fail} failed`, 'error');
        }
    } catch (e) {
        showToast(`Backup error: ${e.message}`, 'error');
    }

    // Re-enable button
    if (backupBtn) { backupBtn.disabled = false; backupBtn.textContent = '⚡ Backup Now'; }
    // Refresh after a short delay so user can see the final status
    setTimeout(() => loadBackups(), 2000);
}

async function deleteBackup(id) {
    if (!confirm('Delete this backup? The backup file will be permanently removed.')) return;
    try {
        const res = await fetch(`/api/backups/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.error) showToast(`Delete failed: ${data.error}`, 'error');
        else showToast('Backup deleted', 'success');
    } catch (e) {
        showToast(`Delete error: ${e.message}`, 'error');
    }
    loadBackups();
}

async function restoreBackup(id) {
    if (!confirm('Restore from this backup? This will overwrite existing data for the target.')) return;
    // Find the button and show progress
    const btn = event && event.target;
    const origText = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner" style="display:inline-block; width:12px; height:12px; border:2px solid var(--border); border-top-color:#fff; border-radius:50%; animation:spin 0.8s linear infinite; vertical-align:middle;"></span> Restoring...'; }
    showToast('🔄 Restore in progress... This may take a while.', 'info');
    try {
        const res = await fetch(`/api/backups/${id}/restore`, { method: 'POST' });
        const data = await res.json();
        if (data.error) showToast(`Restore failed: ${data.error}`, 'error');
        else showToast(data.message || '✅ Restore completed!', 'success');
    } catch (e) {
        showToast(`Restore error: ${e.message}`, 'error');
    }
    if (btn) { btn.disabled = false; btn.textContent = origText; }
    loadBackups();
}

// ─── Schedule Modal ───

function showScheduleSelectedModal() {
    const targets = getSelectedTargets();
    if (targets.length === 0) {
        showToast('Please select at least one item to schedule', 'error');
        return;
    }

    const summary = document.getElementById('schedule-selected-summary');
    const allSelected = targets.length === document.querySelectorAll('.backup-target-cb').length;
    if (summary) {
        const storage = getSelectedStorage();
        const storageLabel = storage.path || 'local';
        if (allSelected) {
            summary.textContent = `Will schedule backup of all ${targets.length} items to ${storageLabel}`;
        } else {
            const names = targets.map(t => t.name || t.type).join(', ');
            summary.textContent = `Will schedule: ${names} → ${storageLabel}`;
        }
    }

    document.getElementById('schedule-name').value = '';
    document.getElementById('create-schedule-modal').classList.add('active');
}

async function createSchedule() {
    const name = document.getElementById('schedule-name').value.trim();
    if (!name) { showToast('Please enter a schedule name', 'error'); return; }

    const frequency = document.getElementById('schedule-frequency').value;
    const time = document.getElementById('schedule-time').value.trim();
    const retention = parseInt(document.getElementById('schedule-retention').value) || 0;
    const targets = getSelectedTargets();
    const storage = getSelectedStorage();
    const allSelected = targets.length === document.querySelectorAll('.backup-target-cb').length;

    const body = {
        name,
        frequency,
        time,
        retention,
        backup_all: allSelected,
        targets: allSelected ? [] : targets,
        storage,
        enabled: true,
    };

    closeModal();
    try {
        const res = await fetch('/api/backups/schedules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.error) showToast(`Schedule creation failed: ${data.error}`, 'error');
        else showToast('Schedule created', 'success');
    } catch (e) {
        showToast(`Schedule error: ${e.message}`, 'error');
    }
    loadBackups();
}

async function deleteSchedule(id) {
    if (!confirm('Delete this backup schedule?')) return;
    try {
        const res = await fetch(`/api/backups/schedules/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.error) showToast(`Delete failed: ${data.error}`, 'error');
        else showToast('Schedule deleted', 'success');
    } catch (e) {
        showToast(`Delete error: ${e.message}`, 'error');
    }
    loadBackups();
}

// ─── Proxmox Backup Server (PBS) Frontend ───

async function loadPbsConfig() {
    try {
        const res = await fetch(apiUrl('/api/backups/pbs/config'));
        if (!res.ok) return;
        const cfg = await res.json();
        const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
        setVal('pbs-server', cfg.pbs_server);
        setVal('pbs-datastore', cfg.pbs_datastore);
        setVal('pbs-user', cfg.pbs_user);
        setVal('pbs-token-name', cfg.pbs_token_name);
        setVal('pbs-fingerprint', cfg.pbs_fingerprint);
        setVal('pbs-namespace', cfg.pbs_namespace);
        if (cfg.has_token_secret) {
            const el = document.getElementById('pbs-token-secret');
            if (el) el.placeholder = '(saved — enter new value to change)';
        }
        if (cfg.has_password) {
            const el = document.getElementById('pbs-password');
            if (el) el.placeholder = '(saved — enter new value to change)';
        }
        if (cfg.pbs_server) {
            // Show saved summary, hide form
            showPbsConfigSaved(cfg);
            updatePbsStatusBadge();
            loadPbsSnapshots();
        } else {
            // No config yet — show the form
            showPbsConfigForm();
            setPbsBadge('Not configured', 'var(--bg-tertiary)', 'var(--text-muted)');
        }
    } catch (e) {
        console.error('Failed to load PBS config:', e);
    }
}

function showPbsConfigSaved(cfg) {
    const saved = document.getElementById('pbs-config-saved');
    const form = document.getElementById('pbs-config-form');
    if (saved) {
        // Populate summary
        const setS = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val || '—'; };
        if (cfg) {
            setS('pbs-saved-server', cfg.pbs_server);
            setS('pbs-saved-datastore', cfg.pbs_datastore);
            setS('pbs-saved-user', cfg.pbs_user);
            var authType = cfg.has_token_secret ? '🔑 API Token' : (cfg.has_password ? '🔒 Password' : '⚠️ None');
            if (cfg.pbs_token_name) authType += ' (' + cfg.pbs_token_name + ')';
            setS('pbs-saved-auth', authType);
        }
        saved.style.display = '';
    }
    if (form) form.style.display = 'none';
}

function showPbsConfigForm() {
    const saved = document.getElementById('pbs-config-saved');
    const form = document.getElementById('pbs-config-form');
    if (saved) saved.style.display = 'none';
    if (form) form.style.display = '';
}

function setPbsBadge(text, bg, color) {
    const badge = document.getElementById('pbs-status-badge');
    if (badge) {
        badge.textContent = text;
        badge.style.background = bg;
        badge.style.color = color;
    }
}

async function updatePbsStatusBadge() {
    try {
        const res = await fetch(apiUrl('/api/backups/pbs/status'));
        if (!res.ok) { setPbsBadge('Error', '#dc3545', '#fff'); return; }
        const status = await res.json();
        if (!status.installed) {
            setPbsBadge('Client not installed', '#dc3545', '#fff');
        } else if (status.connected) {
            setPbsBadge('\u2713 Connected (' + status.snapshot_count + ' snapshots)', '#28a745', '#fff');
        } else {
            console.error('PBS connection failed:', status.error);
            setPbsBadge('Disconnected: ' + (status.error || 'unknown'), '#ffc107', '#333');
        }
    } catch (e) {
        setPbsBadge('Error', '#dc3545', '#fff');
    }
}

async function savePbsConfig() {
    const getVal = id => (document.getElementById(id) || {}).value || '';
    const body = {
        pbs_server: getVal('pbs-server'),
        pbs_datastore: getVal('pbs-datastore'),
        pbs_user: getVal('pbs-user'),
        pbs_password: getVal('pbs-password'),
        pbs_token_name: getVal('pbs-token-name'),
        pbs_token_secret: getVal('pbs-token-secret'),
        pbs_fingerprint: getVal('pbs-fingerprint'),
        pbs_namespace: getVal('pbs-namespace'),
    };
    if (!body.pbs_server || !body.pbs_datastore || !body.pbs_user) {
        showToast('Server, datastore, and user are required', 'error');
        return;
    }
    try {
        const res = await fetch(apiUrl('/api/backups/pbs/config'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!res.ok) {
            const text = await res.text();
            console.error('PBS config save failed:', res.status, text);
            showToast('PBS save failed: ' + text, 'error');
            return;
        }
        const data = await res.json();
        if (data.error) showToast('PBS save failed: ' + data.error, 'error');
        else {
            showToast('PBS configuration saved', 'success');
            // Switch to saved summary view with credentials hidden
            showPbsConfigSaved({
                pbs_server: body.pbs_server,
                pbs_datastore: body.pbs_datastore,
                pbs_user: body.pbs_user,
                pbs_token_name: body.pbs_token_name,
                has_token_secret: !!body.pbs_token_secret,
                has_password: !!body.pbs_password,
            });
            updatePbsStatusBadge();
            populateStorageDropdown();
            loadPbsSnapshots();
        }
    } catch (e) {
        showToast('PBS save error: ' + e.message, 'error');
    }
}

async function testPbsConnection() {
    setPbsBadge('Testing...', 'var(--bg-tertiary)', 'var(--text-muted)');
    try {
        const res = await fetch(apiUrl('/api/backups/pbs/status'));
        const status = await res.json();
        if (!status.installed) {
            showToast('proxmox-backup-client is not installed', 'error');
            setPbsBadge('Client not installed', '#dc3545', '#fff');
        } else if (status.connected) {
            showToast('Connected to PBS! ' + status.snapshot_count + ' snapshots found.', 'success');
            setPbsBadge('\u2713 Connected (' + status.snapshot_count + ' snapshots)', '#28a745', '#fff');
            loadPbsSnapshots();
        } else {
            showToast('PBS connection failed: ' + (status.error || 'Unknown error'), 'error');
            setPbsBadge('Disconnected', '#ffc107', '#333');
        }
    } catch (e) {
        showToast('Test failed: ' + e.message, 'error');
        setPbsBadge('Error', '#dc3545', '#fff');
    }
}

function formatPbsSize(bytes) {
    if (!bytes || bytes === 0) return '\u2014';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let size = Number(bytes);
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return size.toFixed(1) + ' ' + units[i];
}

async function loadPbsSnapshots() {
    const card = document.getElementById('pbs-snapshots-card');
    const tbody = document.getElementById('pbs-snapshots-table');
    const empty = document.getElementById('pbs-snapshots-empty');

    try {
        const res = await fetch(apiUrl('/api/backups/pbs/snapshots'));
        const snapshots = await res.json();
        if (snapshots.error) { card.style.display = 'none'; return; }

        card.style.display = '';
        const list = Array.isArray(snapshots) ? snapshots : [];

        if (list.length === 0) {
            tbody.innerHTML = '';
            if (empty) empty.style.display = '';
            return;
        }
        if (empty) empty.style.display = 'none';

        const TYPE_EMOJIS = { vm: '🖥️', ct: '📦', host: '🏠' };
        const TYPE_LABELS = { vm: 'VM', ct: 'Container', host: 'Host' };

        // Sort newest first by backup-time
        list.sort(function (a, b) {
            var ta = a['backup-time'] || a.backup_time || 0;
            var tb = b['backup-time'] || b.backup_time || 0;
            return (typeof tb === 'number' ? tb : new Date(tb).getTime()) -
                (typeof ta === 'number' ? ta : new Date(ta).getTime());
        });

        tbody.innerHTML = list.map(function (s) {
            var btype = s['backup-type'] || s.backup_type || 'host';
            var bid = s['backup-id'] || s.backup_id || '—';
            var btime = s['backup-time'] || s.backup_time || '';
            var size = s.size || 0;
            var comment = s.comment || s.notes || '';
            var emoji = TYPE_EMOJIS[btype] || '📄';
            var typeLabel = TYPE_LABELS[btype] || btype;

            var timeStr = '—';
            if (btime) {
                var d = typeof btime === 'number' ? new Date(btime * 1000) : new Date(btime);
                timeStr = d.toLocaleString();
            }

            // Show name: use comment if available, otherwise backup-id
            var displayName = comment ? escapeHtml(comment) : escapeHtml(bid);

            var snapshot = btype + '/' + bid + '/' + btime;
            var snapEsc = escapeHtml(snapshot);
            var btypeEsc = escapeHtml(btype);

            return '<tr>' +
                '<td>' + emoji + ' ' + escapeHtml(typeLabel) + '</td>' +
                '<td><strong>' + displayName + '</strong>' +
                (comment ? '<br><span style="font-size:11px; color:var(--text-muted);">ID: ' + escapeHtml(bid) + '</span>' : '') +
                '</td>' +
                '<td style="font-size:12px;">' + timeStr + '</td>' +
                '<td>' + formatPbsSize(size) + '</td>' +
                '<td style="text-align:right;">' +
                '<button class="btn btn-sm btn-primary" onclick="restorePbsSnapshot(\x27' + snapEsc + '\x27, \x27' + btypeEsc + '\x27)"' +
                ' style="font-size:11px; padding:3px 10px;">⬇️ Restore</button>' +
                '</td>' +
                '</tr>';
        }).join('');
    } catch (e) {
        console.error('Failed to load PBS snapshots:', e);
        card.style.display = 'none';
    }
}

async function restorePbsSnapshot(snapshot, backupType) {
    // Choose sensible restore target based on backup type
    var targetDir = '/var/lib/wolfstack/restored';
    if (backupType === 'ct') targetDir = '/var/lib/lxc';
    else if (backupType === 'vm') targetDir = '/var/lib/wolfstack/vms';

    if (!confirm('Restore PBS snapshot:\n' + snapshot + '\n\nRestore to: ' + targetDir + '\n\nThis will download and restore the data to this node.')) return;

    // Find the clicked button and show progress
    var btn = event && event.target;
    var origText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span style="display:inline-block; width:12px; height:12px; border:2px solid rgba(255,255,255,0.3); border-top-color:#fff; border-radius:50%; animation:spin 0.8s linear infinite; vertical-align:middle;"></span> Starting...';
    }
    showToast('🔄 Starting PBS restore... Progress will update live.', 'info');

    try {
        var res = await fetch(apiUrl('/api/backups/pbs/restore'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                snapshot: snapshot,
                archive: '',
                target_dir: targetDir,
            }),
        });
        var data = await res.json();
        if (data.error) {
            console.error('PBS restore error:', data.error);
            showToast('PBS restore failed: ' + data.error, 'error');
            if (btn) { btn.disabled = false; btn.innerHTML = origText; }
            return;
        }

        // Start polling for progress
        var pollInterval = setInterval(async function () {
            try {
                var pres = await fetch(apiUrl('/api/backups/pbs/restore/progress'));
                if (!pres.ok) return;
                var progress = await pres.json();

                // Update button with progress
                if (btn && progress.active) {
                    var label = progress.progress_text || 'Working...';
                    if (progress.percentage != null) {
                        label = progress.percentage.toFixed(1) + '% — ' + label;
                    }
                    btn.innerHTML =
                        '<div style="position:relative; min-width:120px; padding:3px 8px; text-align:center;">' +
                        '<span style="position:relative; font-size:11px;">' +
                        '<span style="display:inline-block; width:12px; height:12px; border:2px solid rgba(255,255,255,0.3); border-top-color:#fff; border-radius:50%; animation:spin 0.8s linear infinite; vertical-align:middle; margin-right:6px;"></span>' +
                        label + '</span></div>';
                }

                if (progress.finished) {
                    clearInterval(pollInterval);
                    if (progress.success) {
                        showToast('✅ PBS restore complete: ' + progress.message, 'success');
                        if (typeof loadContainers === 'function') loadContainers();
                        if (typeof loadVMs === 'function') loadVMs();
                    } else {
                        showToast('❌ PBS restore failed: ' + progress.message, 'error');
                    }
                    if (btn) { btn.disabled = false; btn.innerHTML = origText; }
                }
            } catch (e) {
                // Polling error — keep trying
                console.warn('Progress poll error:', e);
            }
        }, 2000);

    } catch (e) {
        showToast('PBS restore error: ' + e.message, 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = origText; }
    }
}

// ═══════════════════════════════════════════════════
// Version Check
// ═══════════════════════════════════════════════════

function checkForUpdates() {
    var currentVersion = '';
    var versionEl = document.querySelector('.version');
    if (versionEl) currentVersion = versionEl.textContent.replace(/^v/i, '').trim();
    if (!currentVersion) return;

    fetch('https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/main/Cargo.toml')
        .then(function (r) { return r.text(); })
        .then(function (text) {
            var match = text.match(/^version\s*=\s*"([^"]+)"/m);
            if (!match) return;
            var latestVersion = match[1];
            if (latestVersion !== currentVersion) {
                var banner = document.getElementById('update-banner');
                var bannerText = document.getElementById('update-banner-text');
                if (banner) {
                    banner.style.display = 'block';
                    if (bannerText) bannerText.textContent = 'Update available: v' + latestVersion + ' (current: v' + currentVersion + ')';
                }
            }
        })
        .catch(function () { /* silently ignore — no internet or private repo */ });
}

// Check for updates on page load, then every 6 hours
setTimeout(checkForUpdates, 5000);
setInterval(checkForUpdates, 6 * 60 * 60 * 1000);

// ═══════════════════════════════════════════════════
// AI Agent — Chat & Settings
// ═══════════════════════════════════════════════════

var aiChatOpen = false;

function toggleAiChat() {
    aiChatOpen = !aiChatOpen;
    var panel = document.getElementById('ai-chat-panel');
    var bubble = document.getElementById('ai-chat-bubble');
    if (panel) {
        panel.style.display = aiChatOpen ? 'flex' : 'none';
    }
    if (bubble) {
        bubble.style.transform = aiChatOpen ? 'scale(0.9)' : 'scale(1)';
    }
    if (aiChatOpen) {
        var input = document.getElementById('ai-chat-input');
        if (input) input.focus();
    }
}

async function sendAiMessage() {
    var input = document.getElementById('ai-chat-input');
    var msg = (input.value || '').trim();
    if (!msg) return;
    input.value = '';

    var messages = document.getElementById('ai-chat-messages');

    // Add user message
    var userDiv = document.createElement('div');
    userDiv.style.cssText = 'background:var(--accent);color:#fff;border-radius:12px;padding:12px 16px;max-width:85%;align-self:flex-end;font-size:13px;line-height:1.5;';
    userDiv.textContent = msg;
    messages.appendChild(userDiv);

    // Add typing indicator
    var typing = document.createElement('div');
    typing.id = 'ai-typing';
    typing.style.cssText = 'background:var(--bg-tertiary);border-radius:12px;padding:12px 16px;max-width:85%;align-self:flex-start;font-size:13px;color:var(--text-muted);';
    typing.innerHTML = '<span style="animation:pulse 1s infinite;">🐺 Thinking...</span>';
    messages.appendChild(typing);
    messages.scrollTop = messages.scrollHeight;

    // Update status
    var statusEl = document.getElementById('ai-chat-status');
    if (statusEl) statusEl.textContent = 'Thinking...';

    try {
        var resp = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg })
        });
        var data = await resp.json();

        // Remove typing indicator
        var t = document.getElementById('ai-typing');
        if (t) t.remove();

        // Add response
        var aiDiv = document.createElement('div');
        aiDiv.style.cssText = 'background:var(--bg-tertiary);border-radius:12px;padding:12px 16px;max-width:85%;align-self:flex-start;font-size:13px;line-height:1.5;color:var(--text);';

        if (data.error) {
            aiDiv.innerHTML = '<span style="color:var(--danger);">⚠️ ' + escapeHtml(data.error) + '</span>';
        } else {
            aiDiv.innerHTML = formatAiResponse(data.response || '');
        }
        messages.appendChild(aiDiv);
        if (statusEl) statusEl.textContent = 'Ready';
    } catch (e) {
        var t = document.getElementById('ai-typing');
        if (t) t.remove();
        var errDiv = document.createElement('div');
        errDiv.style.cssText = 'background:var(--bg-tertiary);border-radius:12px;padding:12px 16px;max-width:85%;align-self:flex-start;font-size:13px;color:var(--danger);';
        errDiv.textContent = '⚠️ ' + e.message;
        messages.appendChild(errDiv);
        if (statusEl) statusEl.textContent = 'Error';
    }

    messages.scrollTop = messages.scrollHeight;
}

// Basic markdown formatting for AI responses
function formatAiResponse(text) {
    var html = escapeHtml(text);
    // Bold: **text**
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Italic: *text*
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    // Code blocks: ```code```
    html = html.replace(/```([\s\S]*?)```/g, '<pre style="background:var(--bg-primary);padding:8px 12px;border-radius:8px;overflow-x:auto;margin:8px 0;font-size:12px;"><code>$1</code></pre>');
    // Inline code: `code`
    html = html.replace(/`([^`]+)`/g, '<code style="background:var(--bg-primary);padding:2px 6px;border-radius:4px;font-size:12px;">$1</code>');
    // Newlines
    html = html.replace(/\n/g, '<br>');
    // Lists: - item
    html = html.replace(/<br>- (.*?)(?=<br>|$)/g, '<br>• $1');
    return html;
}

function openAiSettings() {
    if (aiChatOpen) toggleAiChat();
    selectView('ai-settings');
}

async function loadAiConfig() {
    try {
        var resp = await fetch('/api/ai/config'));
        var cfg = await resp.json();
        var el;
        if ((el = document.getElementById('ai-provider'))) el.value = cfg.provider || 'claude';
        if ((el = document.getElementById('ai-claude-key'))) el.value = cfg.has_claude_key ? cfg.claude_api_key : '';
        if ((el = document.getElementById('ai-gemini-key'))) el.value = cfg.has_gemini_key ? cfg.gemini_api_key : '';
        if ((el = document.getElementById('ai-email-enabled'))) el.checked = cfg.email_enabled || false;
        if ((el = document.getElementById('ai-email-to'))) el.value = cfg.email_to || '';
        if ((el = document.getElementById('ai-smtp-host'))) el.value = cfg.smtp_host || '';
        if ((el = document.getElementById('ai-smtp-port'))) el.value = cfg.smtp_port || 587;
        if ((el = document.getElementById('ai-smtp-user'))) el.value = cfg.smtp_user || '';
        if ((el = document.getElementById('ai-smtp-pass'))) el.value = cfg.has_smtp_pass ? cfg.smtp_pass : '';
        if ((el = document.getElementById('ai-check-interval'))) el.value = cfg.check_interval_minutes || 60;
        // Fetch models for the current provider, then select the saved model
        await fetchAiModels(cfg.provider || 'claude', cfg.model || '');
    } catch (e) {
        console.error('Failed to load AI config:', e);
    }
}

async function fetchAiModels(provider, selectedModel) {
    var select = document.getElementById('ai-model');
    if (!select) return;
    select.innerHTML = '<option value="">Loading models...</option>';
    try {
        var resp = await fetch('/api/ai/models?provider=' + encodeURIComponent(provider)));
        var data = await resp.json();
        if (data.error && (!data.models || !data.models.length)) {
            select.innerHTML = '<option value="">Enter API key and save to load models</option>';
            return;
        }
        var models = data.models || [];
        if (!models.length) {
            select.innerHTML = '<option value="">No models found — check API key</option>';
            return;
        }
        select.innerHTML = '';
        models.forEach(function (m) {
            var opt = document.createElement('option');
            opt.value = m;
            opt.textContent = m;
            select.appendChild(opt);
        });
        // Select the saved model if it exists in the list
        if (selectedModel) {
            select.value = selectedModel;
            // If the saved model isn't in the list, add it
            if (select.value !== selectedModel) {
                var opt = document.createElement('option');
                opt.value = selectedModel;
                opt.textContent = selectedModel + ' (saved)';
                select.insertBefore(opt, select.firstChild);
                select.value = selectedModel;
            }
        }
    } catch (e) {
        select.innerHTML = '<option value="">Error loading models</option>';
        console.error('Failed to fetch models:', e);
    }
}

async function saveAiConfig() {
    var config = {
        provider: (document.getElementById('ai-provider') || {}).value || 'claude',
        claude_api_key: (document.getElementById('ai-claude-key') || {}).value || '',
        gemini_api_key: (document.getElementById('ai-gemini-key') || {}).value || '',
        model: (document.getElementById('ai-model') || {}).value || '',
        email_enabled: (document.getElementById('ai-email-enabled') || {}).checked || false,
        email_to: (document.getElementById('ai-email-to') || {}).value || '',
        smtp_host: (document.getElementById('ai-smtp-host') || {}).value || '',
        smtp_port: parseInt((document.getElementById('ai-smtp-port') || {}).value) || 587,
        smtp_user: (document.getElementById('ai-smtp-user') || {}).value || '',
        smtp_pass: (document.getElementById('ai-smtp-pass') || {}).value || '',
        check_interval_minutes: parseInt((document.getElementById('ai-check-interval') || {}).value) || 60,
    };
    try {
        var resp = await fetch('/api/ai/config'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        var data = await resp.json();
        if (data.status === 'saved') {
            alert('Settings Saved');
            loadAiStatus();
            // Refresh models list after save (in case key changed)
            fetchAiModels(config.provider, config.model);
        } else {
            alert('Error: ' + (data.error || 'Failed to save'));
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function loadAiStatus() {
    try {
        var resp = await fetch('/api/ai/status'));
        var status = await resp.json();
        var textEl = document.getElementById('ai-status-text');
        var detailEl = document.getElementById('ai-status-detail');
        if (textEl) {
            if (status.configured) {
                textEl.textContent = '✅ AI Agent Active — ' + status.provider + ' (' + status.model + ')';
            } else {
                textEl.textContent = '⚠️ Not Configured — add an API key to enable';
            }
        }
        if (detailEl) {
            var parts = [];
            parts.push('Knowledge: ' + Math.round(status.knowledge_base_size / 1024) + 'KB');
            parts.push('Alerts: ' + status.alert_count);
            parts.push('Messages: ' + status.chat_message_count);
            if (status.last_health_check) {
                parts.push('Last check: ' + (status.last_health_check === 'ALL_OK' ? '✅ OK' : '⚠️ Issues found'));
            }
            detailEl.textContent = parts.join(' • ');
        }
    } catch (e) {
        console.error('AI status error:', e);
    }
}

async function loadAiAlerts() {
    try {
        var resp = await fetch('/api/ai/alerts'));
        var alerts = await resp.json();
        var container = document.getElementById('ai-alerts-list');
        if (!container) return;
        if (!alerts.length) {
            container.innerHTML = '<div style="color:var(--text-muted);padding:12px;">No alerts yet — the AI will check your servers periodically</div>';
            return;
        }
        container.innerHTML = alerts.slice(-20).reverse().map(function (a) {
            var icon = a.severity === 'critical' ? '🔴' : a.severity === 'warning' ? '🟡' : '🔵';
            var time = new Date(a.timestamp * 1000).toLocaleString();
            return '<div style="padding:8px;border-bottom:1px solid var(--border);">' +
                '<div style="display:flex;justify-content:space-between;">' +
                '<span>' + icon + ' ' + a.severity.toUpperCase() + '</span>' +
                '<span style="color:var(--text-muted);">' + time + '</span></div>' +
                '<div style="margin-top:4px;color:var(--text-secondary);">' + escapeHtml(a.message).substring(0, 200) + '</div></div>';
        }).join('');
    } catch (e) {
        console.error('AI alerts error:', e);
    }
}

async function testAiConnection() {
    // First save settings so the backend has the latest keys
    var config = {
        provider: (document.getElementById('ai-provider') || {}).value || 'claude',
        claude_api_key: (document.getElementById('ai-claude-key') || {}).value || '',
        gemini_api_key: (document.getElementById('ai-gemini-key') || {}).value || '',
        model: (document.getElementById('ai-model') || {}).value || '',
        email_enabled: (document.getElementById('ai-email-enabled') || {}).checked || false,
        email_to: (document.getElementById('ai-email-to') || {}).value || '',
        smtp_host: (document.getElementById('ai-smtp-host') || {}).value || '',
        smtp_port: parseInt((document.getElementById('ai-smtp-port') || {}).value) || 587,
        smtp_user: (document.getElementById('ai-smtp-user') || {}).value || '',
        smtp_pass: (document.getElementById('ai-smtp-pass') || {}).value || '',
        check_interval_minutes: parseInt((document.getElementById('ai-check-interval') || {}).value) || 60,
    };
    try {
        // Save first
        await fetch('/api/ai/config'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        // Now test
        var resp = await fetch('/api/ai/chat'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: 'Say "Hello! AI Agent is working." in one short sentence.' })
        });
        var data = await resp.json();
        if (data.error) {
            alert('AI Error: ' + data.error);
        } else {
            alert('✅ AI responded: ' + (data.response || '').substring(0, 200));
        }
    } catch (e) {
        alert('Connection failed: ' + e.message);
    }
}

function onAiProviderChange() {
    var provider = (document.getElementById('ai-provider') || {}).value || 'claude';
    fetchAiModels(provider, '');
}

