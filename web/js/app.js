// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

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

// ─── Modal Dialog (replaces alert()) ───
function showModal(message, title) {
    title = title || 'WolfStack';
    var overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:100000;display:flex;align-items:center;justify-content:center;animation:fadeIn 0.15s ease';
    var modal = document.createElement('div');
    modal.style.cssText = 'background:var(--bg-card,#1e2028);border:1px solid var(--border-color,#2d2f3a);border-radius:12px;padding:24px 28px;max-width:480px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.5);color:var(--text-primary,#e4e4e7);font-family:inherit';
    var h = document.createElement('div');
    h.style.cssText = 'font-size:15px;font-weight:600;margin-bottom:14px;color:var(--accent-light,#60a5fa);display:flex;align-items:center;gap:8px';
    h.textContent = title;
    var body = document.createElement('div');
    body.style.cssText = 'font-size:13px;line-height:1.6;color:var(--text-secondary,#a1a1aa);white-space:pre-wrap;word-break:break-word;max-height:300px;overflow-y:auto';
    body.textContent = message;
    var btnWrap = document.createElement('div');
    btnWrap.style.cssText = 'margin-top:18px;text-align:right';
    var btn = document.createElement('button');
    btn.textContent = 'OK';
    btn.style.cssText = 'background:var(--accent,#3b82f6);color:#fff;border:none;border-radius:6px;padding:8px 24px;cursor:pointer;font-size:13px;font-weight:500;transition:background 0.2s';
    btn.onmouseenter = function () { btn.style.background = 'var(--accent-light,#60a5fa)'; };
    btn.onmouseleave = function () { btn.style.background = 'var(--accent,#3b82f6)'; };
    btn.onclick = function () { overlay.remove(); };
    overlay.onclick = function (e) { if (e.target === overlay) overlay.remove(); };
    btnWrap.appendChild(btn);
    modal.appendChild(h);
    modal.appendChild(body);
    modal.appendChild(btnWrap);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    btn.focus();
}

// ─── Page Loading Overlay (modern blur + spinner) ───
function showPageLoadingOverlay(pageEl) {
    // Remove any existing overlay first
    hidePageLoadingOverlay(pageEl);
    // Ensure parent is positioned for the absolute overlay
    if (getComputedStyle(pageEl).position === 'static') {
        pageEl.style.position = 'relative';
    }
    const overlay = document.createElement('div');
    overlay.className = 'page-loading-overlay';
    overlay.innerHTML = `
        <div class="page-loading-spinner"></div>
        <div class="page-loading-text">Loading...</div>
    `;
    pageEl.appendChild(overlay);
}

function hidePageLoadingOverlay(pageEl) {
    if (!pageEl) return;
    const overlay = pageEl.querySelector('.page-loading-overlay');
    if (overlay) {
        overlay.style.opacity = '0';
        setTimeout(() => overlay.remove(), 200);
    }
}

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

    const titles = { datacenter: 'Datacenter', settings: 'Settings', docs: 'Help & Documentation', appstore: 'App Store', issues: 'Issues', 'global-wolfnet': 'Global WolfNet' };
    document.getElementById('page-title').textContent = titles[page] || page;

    if (page === 'datacenter') {
        renderDatacenterOverview();
    } else if (page === 'settings') {
        // If AI tab is active, load AI data
        const aiTab = document.getElementById('settings-tab-ai');
        if (aiTab && aiTab.classList.contains('active')) {
            loadAiConfig();
            loadAiStatus();
            loadAiAlerts();
        }
    } else if (page === 'appstore') {
        loadAppStoreApps();
    } else if (page === 'issues') {
        checkIssuesAiBadge();
        loadIssueSchedule();
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
        files: 'File Manager',
        networking: 'Networking',
        wolfnet: 'WolfNet',
        certificates: 'Certificates',
        cron: 'Cron Jobs',
        'pve-resources': 'VMs & Containers',
        'mysql-editor': 'MariaDB/MySQL',
        'terminal': 'Terminal',
        'security': 'Security',
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
    // Show a modern loading overlay for views that fetch data asynchronously
    const asyncViews = ['components', 'services', 'containers', 'lxc', 'vms', 'storage', 'networking', 'backups', 'wolfnet', 'certificates', 'cron', 'pve-resources', 'mysql-editor', 'security'];
    if (asyncViews.includes(view) && el) {
        // Clear table bodies to prevent stale data showing
        el.querySelectorAll('tbody').forEach(tb => { tb.innerHTML = ''; });
        // Show blur overlay over the page content
        showPageLoadingOverlay(el);
    }
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
    if (view === 'components' || view === 'services') loadComponents().finally(() => hidePageLoadingOverlay(el));
    if (view === 'containers') loadDockerContainers().finally(() => hidePageLoadingOverlay(el));
    if (view === 'lxc') loadLxcContainers().finally(() => hidePageLoadingOverlay(el));

    if (view === 'terminal') {
        // Open terminal inline in the content area
        const node = allNodes.find(n => n.id === currentNodeId);
        const isPve = node && node.node_type === 'proxmox';
        if (isPve) {
            openInlineTerminal('pve', node.hostname || 'PVE Shell', { pve_node_id: currentNodeId, pve_vmid: 0 });
        } else {
            openInlineTerminal('host', hostname);
        }
    }
    if (view === 'vms') loadVms().finally(() => hidePageLoadingOverlay(el));
    if (view === 'storage') Promise.all([loadStorageMounts(), loadZfsStatus(), loadDiskInfo()]).finally(() => hidePageLoadingOverlay(el));
    if (view === 'files') { if (!window._skipFileReset) { containerFileMode = null; currentFilePath = '/'; } window._skipFileReset = false; loadFiles().finally(() => hidePageLoadingOverlay(el)); }
    if (view === 'networking') loadNetworking().finally(() => hidePageLoadingOverlay(el));
    if (view === 'backups') loadBackups().finally(() => hidePageLoadingOverlay(el));
    if (view === 'wolfnet') loadWolfNet().finally(() => hidePageLoadingOverlay(el));
    if (view === 'certificates') loadCertificates().finally(() => hidePageLoadingOverlay(el));
    if (view === 'cron') loadCronJobs().finally(() => hidePageLoadingOverlay(el));
    if (view === 'pve-resources') { renderPveResourcesView(nodeId); hidePageLoadingOverlay(el); }
    if (view === 'mysql-editor') { loadMySQLEditor(); hidePageLoadingOverlay(el); }
    if (view === 'security') loadNodeSecurity().finally(() => hidePageLoadingOverlay(el));
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

    // Separate WolfStack and PVE nodes
    const wsNodes = sorted.filter(n => n.node_type !== 'proxmox');
    const pveNodes = sorted.filter(n => n.node_type === 'proxmox');

    // Group PVE nodes by cluster name (or address as fallback)
    const pveClusters = {};
    pveNodes.forEach(n => {
        const key = n.pve_cluster_name || n.address;
        if (!pveClusters[key]) pveClusters[key] = [];
        pveClusters[key].push(n);
    });

    let html = '';

    // 2. Render WolfStack Clusters
    const wsClusters = {};
    wsNodes.forEach(n => {
        const key = n.cluster_name || "WolfStack";
        if (!wsClusters[key]) wsClusters[key] = [];
        wsClusters[key].push(n);
    });

    // Sort WolfStack clusters: "WolfStack" first, then alphabetical
    const wsKeys = Object.keys(wsClusters).sort((a, b) => {
        if (a === 'WolfStack') return -1;
        if (b === 'WolfStack') return 1;
        return a.localeCompare(b);
    });

    wsKeys.forEach(clusterName => {
        const clusterNodes = wsClusters[clusterName];
        const clusterId = 'cluster-' + clusterName.replace(/[^a-z0-9]/gi, '-');
        const shouldExpandCluster = isFirstBuild ? true : (expandedNodes.has(clusterId) || clusterNodes.some(n => n.id === currentNodeId || expandedNodes.has(n.id)));
        const anyOnline = clusterNodes.some(n => n.online);
        const nodeIds = clusterNodes.map(n => `'${n.id}'`).join(',');
        const escapedName = clusterName.replace(/'/g, "\\'");

        html += `
        <div class="server-tree-node">
            <div class="server-node-header" data-cluster-id="${clusterId}" onclick="toggleServerNode('${clusterId}')" style="background: linear-gradient(90deg, rgba(99,102,241,0.05), transparent);">
                <span class="tree-toggle ${shouldExpandCluster ? 'expanded' : ''}" id="toggle-${clusterId}">▶</span>
                <span class="server-dot ${anyOnline ? 'online' : 'offline'}"></span>
                <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><span style="position:relative;display:inline-block;margin-right:6px;">☁️<span style="position:absolute;bottom:-4px;right:-6px;min-width:15px;height:15px;line-height:15px;text-align:center;font-size:9px;font-weight:700;color:#fff;background:#16a34a;border-radius:50%;z-index:2;">${clusterNodes.length}</span></span>${clusterName}</span>
                <span class="remove-server-btn" onclick="event.stopPropagation(); openWsClusterSettings('${escapedName}')" title="Cluster settings" style="margin-left:4px;">⚙️</span>
            </div>
            <div class="server-node-children ${shouldExpandCluster ? 'expanded' : ''}" id="children-${clusterId}">`;

        // Each node within the cluster
        clusterNodes.forEach(node => {
            const shouldExpandNode = expandedNodes.has(node.id);
            html += `
                <div class="server-tree-node" style="margin-left: 8px;">
                    <div class="server-node-header" data-node-id="${node.id}" onclick="toggleServerNode('${node.id}')" style="padding-left: 8px;">
                        <span class="tree-toggle ${shouldExpandNode ? 'expanded' : ''}" id="toggle-${node.id}">▶</span>
                        <span class="server-dot ${node.online ? 'online' : 'offline'}"></span>
                        <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${node.hostname}</span>
                        <span class="remove-server-btn" onclick="event.stopPropagation(); openNodeSettings('${node.id}')" title="Node settings" style="margin-left:4px;">⚙️</span>
                        ${node.is_self ? '<span class="self-badge">this</span>' : `<span class="remove-server-btn" onclick="event.stopPropagation(); confirmRemoveServer('${node.id}', '${node.hostname}')" title="Remove server">🗑️</span>`}
                    </div>
                    <div class="server-node-children ${shouldExpandNode ? 'expanded' : ''}" id="children-${node.id}">
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
                        <a class="nav-item server-child-item" data-node="${node.id}" data-view="files" onclick="selectServerView('${node.id}', 'files')">
                            <span class="icon">📂</span> Files
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
                        <a class="nav-item server-child-item" data-node="${node.id}" data-view="cron" onclick="selectServerView('${node.id}', 'cron')">
                            <span class="icon">🕐</span> Cron Jobs
                        </a>
                        <a class="nav-item server-child-item" data-node="${node.id}" data-view="security" onclick="selectServerView('${node.id}', 'security')">
                            <span class="icon">🛡️</span> Security
                        </a>
                        <a class="nav-item server-child-item" data-node="${node.id}" data-view="terminal" onclick="selectServerView('${node.id}', 'terminal')">
                            <span class="icon">💻</span> Terminal
                        </a>
                        <a class="nav-item server-child-item" data-node="${node.id}" data-view="mysql-editor" onclick="selectServerView('${node.id}', 'mysql-editor')">
                            <span class="icon">🗄️</span> MariaDB/MySQL
                        </a>
                    </div>
                </div>`;
        });

        html += `
            </div>
        </div>`;
    });

    // Render PVE clusters (grouped)
    // Sort PVE clusters alphabetically
    const pveKeys = Object.keys(pveClusters).sort((a, b) => a.localeCompare(b));

    pveKeys.forEach(clusterName => {
        const clusterNodes = pveClusters[clusterName];
        const clusterId = 'pve-cluster-' + clusterName.replace(/[^a-zA-Z0-9]/g, '_');
        const shouldExpandCluster = isFirstBuild ? false : expandedNodes.has(clusterId);
        const anyOnline = clusterNodes.some(n => n.online);
        const nodeIds = clusterNodes.map(n => `'${n.id}'`).join(',');

        html += `
        <div class="server-tree-node">
            <div class="server-node-header" data-cluster-id="${clusterId}" onclick="toggleServerNode('${clusterId}')" style="background: linear-gradient(90deg, rgba(99,102,241,0.05), transparent);">
                <span class="tree-toggle ${shouldExpandCluster ? 'expanded' : ''}" id="toggle-${clusterId}">▶</span>
                <span class="server-dot ${anyOnline ? 'online' : 'offline'}"></span>
                <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><span style="position:relative;display:inline-block;width:20px;height:18px;vertical-align:middle;margin-right:6px;"><span style="display:inline-block;width:15px;height:15px;opacity:0.9;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="2" width="18" height="6" rx="1"/><rect x="3" y="10" width="18" height="6" rx="1"/><rect x="3" y="18" width="18" height="4" rx="1"/><circle cx="7" cy="5" r="1" fill="currentColor"/><circle cx="7" cy="13" r="1" fill="currentColor"/><circle cx="7" cy="20" r="1" fill="currentColor"/></svg></span><span style="position:absolute;bottom:-3px;right:-4px;min-width:15px;height:15px;line-height:15px;text-align:center;font-size:9px;font-weight:700;color:#fff;background:#16a34a;border-radius:50%;z-index:2;">${clusterNodes.length}</span></span>${clusterName}</span>
                <span class="remove-server-btn" onclick="event.stopPropagation(); openPveClusterSettings('${clusterName}')" title="Cluster settings" style="margin-left:4px;">⚙️</span>
                <span class="remove-server-btn" onclick="event.stopPropagation(); confirmRemovePveCluster('${clusterName}', [${nodeIds}])" title="Remove cluster">🗑️</span>
            </div>
            <div class="server-node-children ${shouldExpandCluster ? 'expanded' : ''}" id="children-${clusterId}">`;

        // Each node within the cluster
        clusterNodes.forEach(node => {
            const shouldExpandNode = expandedNodes.has(node.id);
            html += `
                <div class="server-tree-node" style="margin-left: 8px;">
                    <div class="server-node-header" data-node-id="${node.id}" onclick="toggleServerNode('${node.id}')" style="padding-left: 8px;">
                        <span class="tree-toggle ${shouldExpandNode ? 'expanded' : ''}" id="toggle-${node.id}">▶</span>
                        <span class="server-dot ${node.online ? 'online' : 'offline'}"></span>
                        <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${node.pve_node_name || node.hostname}</span>
                    </div>
                    <div class="server-node-children ${shouldExpandNode ? 'expanded' : ''}" id="children-${node.id}">
                        <a class="nav-item server-child-item" data-node="${node.id}" data-view="dashboard" onclick="selectServerView('${node.id}', 'dashboard')">
                            <span class="icon">📊</span> Dashboard
                        </a>
                        <a class="nav-item server-child-item" data-node="${node.id}" data-view="pve-resources" onclick="selectServerView('${node.id}', 'pve-resources')">
                            <span class="icon">🖥️</span> VMs & Containers
                            ${(node.vm_count || node.lxc_count) ? `<span class="badge" style="font-size:10px; padding:1px 6px;">${(node.vm_count || 0) + (node.lxc_count || 0)}</span>` : ''}
                        </a>
                    </div>
                </div>`;
        });

        html += `
            </div>
        </div>`;
    });

    tree.innerHTML = html;

    // Restore active highlight
    if (currentNodeId && currentPage) {
        const active = document.querySelector(`.server-child-item[data-node="${currentNodeId}"][data-view="${currentPage}"]`);
        if (active) active.classList.add('active');
    }

    // Re-apply search filter if active
    filterSidebarNodes();
}

function toggleServerNode(nodeId) {
    const children = document.getElementById(`children-${nodeId}`);
    const toggle = document.getElementById(`toggle-${nodeId}`);
    if (children && toggle) {
        children.classList.toggle('expanded');
        toggle.classList.toggle('expanded');
    }
}

function filterSidebarNodes() {
    const query = (document.getElementById('sidebar-node-search')?.value || '').toLowerCase().trim();
    const tree = document.getElementById('server-tree');
    if (!tree) return;

    // Get all top-level cluster/node groups
    const topNodes = tree.querySelectorAll(':scope > .server-tree-node');

    topNodes.forEach(clusterDiv => {
        const header = clusterDiv.querySelector('.server-node-header');
        const childContainer = clusterDiv.querySelector('.server-node-children');
        if (!childContainer) return;

        const childNodes = childContainer.querySelectorAll(':scope > .server-tree-node');

        if (!query) {
            // No filter — show everything, restore default collapse state
            clusterDiv.style.display = '';
            childNodes.forEach(cn => cn.style.display = '');
            return;
        }

        // Check cluster name match
        const clusterText = (header?.textContent || '').toLowerCase();
        const clusterMatch = clusterText.includes(query);

        // Check child node matches
        let anyChildMatch = false;
        childNodes.forEach(childNode => {
            const childText = (childNode.textContent || '').toLowerCase();
            if (childText.includes(query) || clusterMatch) {
                childNode.style.display = '';
                anyChildMatch = true;
            } else {
                childNode.style.display = 'none';
            }
        });

        if (clusterMatch || anyChildMatch) {
            clusterDiv.style.display = '';
            // Auto-expand when filtering
            if (childContainer && !childContainer.classList.contains('expanded')) {
                childContainer.classList.add('expanded');
                const toggle = clusterDiv.querySelector('.tree-toggle');
                if (toggle) toggle.classList.add('expanded');
            }
        } else {
            clusterDiv.style.display = 'none';
        }
    });
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

    // Helper to render a single node card
    const renderCard = (node) => {
        const m = node.metrics;
        const isPve = node.node_type === 'proxmox';
        const nodeIcon = isPve ? '<span style="display:inline-block;width:14px;height:14px;vertical-align:middle;opacity:0.9;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><circle cx="12" cy="10" r="1" fill="currentColor"/></svg></span>' : '🖥️';
        const pveBadge = isPve ? ' <span style="font-size:10px; padding:1px 6px; border-radius:3px; background:rgba(99,102,241,0.15); color:var(--accent-light); margin-left:6px;">PVE</span>' : '';

        // If offline or no metrics
        if (!m || !node.online) {
            return `<div class="card" style="cursor:pointer; opacity:0.8;" onclick="selectServerView('${node.id}', 'dashboard')">
                <div class="card-header">
                    <h3>
                        <span class="server-dot offline" style="display:inline-block; vertical-align:middle; margin-right:8px;"></span>
                        ${nodeIcon} ${node.hostname}${pveBadge}
                    </h3>
                    <div style="color:var(--text-muted); font-size:12px;">${node.address}:${node.port}</div>
                </div>
                <div class="card-body" style="text-align:center; color:var(--text-muted); padding:30px;">
                    ● Offline / No Data
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
                    ${nodeIcon} ${node.hostname}${pveBadge}${node.is_self ? ' <span style="color:var(--accent-light); font-size:12px;">(this)</span>' : ''}
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
                    ${isPve
                ? `<span style="font-size:11px; padding:2px 8px; border-radius:4px; background:rgba(99,102,241,0.1); color:var(--accent-light);">🖥️ ${node.vm_count || 0} VMs</span><span style="font-size:11px; padding:2px 8px; border-radius:4px; background:rgba(99,102,241,0.1); color:var(--accent-light);">📦 ${node.lxc_count || 0} CTs</span>`
                : node.components.filter(c => c.installed).map(c =>
                    `<span style="font-size:11px; padding:2px 8px; border-radius:4px; background:${c.running ? 'var(--success-bg)' : 'var(--danger-bg)'}; color:${c.running ? 'var(--success)' : 'var(--danger)'};">${c.component}</span>`
                ).join('')}
                </div>
            </div>
        </div>`;
    };

    let html = '';

    // 1. Group nodes
    const wsNodes = nodes.filter(n => n.node_type !== 'proxmox');
    const pveNodes = nodes.filter(n => n.node_type === 'proxmox');

    // 2. Render WolfStack Clusters
    const wsClusters = {};
    wsNodes.forEach(n => {
        const key = n.cluster_name || "WolfStack";
        if (!wsClusters[key]) wsClusters[key] = [];
        wsClusters[key].push(n);
    });

    // Sort WolfStack clusters: "WolfStack" first, then alphabetical
    const wsKeys = Object.keys(wsClusters).sort((a, b) => {
        if (a === 'WolfStack') return -1;
        if (b === 'WolfStack') return 1;
        return a.localeCompare(b);
    });

    wsKeys.forEach(clusterName => {
        const clusterNodes = wsClusters[clusterName];
        html += `<div style="grid-column:1/-1; margin-bottom:8px; display:flex; align-items:baseline; ${html ? 'border-top:1px solid var(--border); padding-top:24px; margin-top:24px;' : ''}">
            <h3 style="margin:0; font-size:20px;">${clusterName}</h3>
            <span style="margin-left:10px; font-size:12px; color:var(--text-muted); font-weight:400;">WolfStack cluster — ${clusterNodes.length} nodes</span>
        </div>`;
        html += clusterNodes.map(renderCard).join('');
    });

    // 3. Render PVE Clusters
    const pveClusters = {};
    pveNodes.forEach(n => {
        const key = n.pve_cluster_name || n.cluster_name || n.address; // Group by name or address
        if (!pveClusters[key]) pveClusters[key] = [];
        pveClusters[key].push(n);
    });

    // Sort PVE clusters alphabetically
    const pveKeys = Object.keys(pveClusters).sort((a, b) => a.localeCompare(b));

    pveKeys.forEach(clusterName => {
        const clusterNodes = pveClusters[clusterName];
        html += `<div style="grid-column:1/-1; margin-bottom:8px; display:flex; align-items:baseline; ${html ? 'border-top:1px solid var(--border); padding-top:24px; margin-top:24px;' : ''}">
            <h3 style="margin:0; font-size:20px;"><span style="display:inline-block;width:20px;height:20px;vertical-align:middle;margin-right:4px;opacity:0.9;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="2" width="18" height="6" rx="1"/><rect x="3" y="10" width="18" height="6" rx="1"/><rect x="3" y="18" width="18" height="4" rx="1"/><circle cx="7" cy="5" r="1" fill="currentColor"/><circle cx="7" cy="13" r="1" fill="currentColor"/><circle cx="7" cy="20" r="1" fill="currentColor"/></svg></span> ${clusterName}</h3>
            <span style="margin-left:10px; font-size:12px; color:var(--text-muted); font-weight:400;">Proxmox cluster — ${clusterNodes.length} nodes</span>
        </div>`;
        html += clusterNodes.map(renderCard).join('');
    });



    container.innerHTML = html;

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
let mapNodePositions = {};   // node.id -> { lat, lon, cluster, isPve }
let mapClusterLines = [];    // Leaflet polylines for cleanup
let mapClusterLabels = [];   // Leaflet markers (labels) for cleanup

// Vibrant palette for distinguishing clusters on the dark map
const CLUSTER_COLORS = [
    { marker: '#10b981', label: '#34d399', border: 'rgba(52,211,153,0.3)' },   // emerald
    { marker: '#3b82f6', label: '#60a5fa', border: 'rgba(96,165,250,0.3)' },   // blue
    { marker: '#f59e0b', label: '#fbbf24', border: 'rgba(251,191,36,0.3)' },   // amber
    { marker: '#ef4444', label: '#f87171', border: 'rgba(248,113,113,0.3)' },  // red
    { marker: '#a855f7', label: '#c084fc', border: 'rgba(192,132,252,0.3)' },  // purple
    { marker: '#ec4899', label: '#f472b6', border: 'rgba(244,114,182,0.3)' },  // pink
    { marker: '#14b8a6', label: '#2dd4bf', border: 'rgba(45,212,191,0.3)' },   // teal
    { marker: '#f97316', label: '#fb923c', border: 'rgba(251,146,60,0.3)' },   // orange
    { marker: '#06b6d4', label: '#22d3ee', border: 'rgba(34,211,238,0.3)' },   // cyan
    { marker: '#84cc16', label: '#a3e635', border: 'rgba(163,230,53,0.3)' },   // lime
];
let clusterColorMap = {};  // clusterKey -> index
function getClusterColor(clusterKey) {
    if (!(clusterKey in clusterColorMap)) {
        clusterColorMap[clusterKey] = Object.keys(clusterColorMap).length % CLUSTER_COLORS.length;
    }
    return CLUSTER_COLORS[clusterColorMap[clusterKey]];
}

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

    // Helper: check if an IP is a private/local address
    const isPrivateIp = (ip) => {
        if (!ip) return true;
        return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|fd[0-9a-f]{2}:|fe80:)/.test(ip);
    };

    // Helper: resolve a node's location, then call placeMarker
    const resolveAndPlace = (node, placeMarker) => {
        // Priority: public_ip > node.address (if public) > selfPublicIp > London fallback
        // NOTE: Do NOT use hostname for geolocation — names like "Sophie" return random locations
        let ipToGeolocate = node.public_ip;
        if (!ipToGeolocate && node.address && !isPrivateIp(node.address)) {
            ipToGeolocate = node.address;
        }
        if (!ipToGeolocate) {
            // Node is on the same LAN or has no public IP — use self node's public IP
            // so it appears at the correct datacenter location
            ipToGeolocate = selfPublicIp;
        }

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
                fetch(apiUrl(`/api/geolocate?ip=${encodeURIComponent(ipToGeolocate)}`))
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

        // Determine cluster and get unique color
        const isPve = node.node_type === 'proxmox';
        const clusterKey = isPve
            ? (node.pve_cluster_name || node.cluster_name || node.address)
            : (node.cluster_name || 'WolfStack');
        const cc = getClusterColor(clusterKey);

        // Function to place marker
        const placeMarker = (lat, lon) => {
            const icon = L.divIcon({
                className: 'custom-map-marker',
                html: `<div style="width:12px; height:12px; background:${cc.marker}; border-radius:50%; border:2px solid #ffffff; box-shadow:0 0 10px ${cc.marker};"></div>`,
                iconSize: [12, 12]
            });
            const marker = L.marker([lat, lon], { icon: icon }).addTo(worldMap);
            let popupContent = `<b>${node.hostname}</b><br>${node.address}`;
            if (node.public_ip) popupContent += `<br>Public: ${node.public_ip}`;
            popupContent += `<br><span style="color:${cc.marker}">${isPve ? '● Proxmox' : '● WolfStack'}</span>`;
            popupContent += ` — ${node.online ? 'Online' : 'Offline'}`;
            popupContent += `<br><span style="font-size:10px;color:${cc.label};">Cluster: ${clusterKey}</span>`;
            marker.bindPopup(popupContent);
            mapMarkers[node.id] = marker;

            // Track position for cluster lines
            mapNodePositions[node.id] = { lat, lon, cluster: clusterKey, isPve };

            // Auto-fit map and redraw cluster connections
            fitMapToMarkers();
            drawClusterConnections();
        };

        resolveAndPlace(node, placeMarker);
    });
}

// Draw lines between nodes in the same cluster + cluster labels
function drawClusterConnections() {
    if (!worldMap) return;

    // Remove old lines and labels
    mapClusterLines.forEach(l => worldMap.removeLayer(l));
    mapClusterLabels.forEach(l => worldMap.removeLayer(l));
    mapClusterLines = [];
    mapClusterLabels = [];

    // Group node positions by cluster
    const clusters = {};
    Object.values(mapNodePositions).forEach(pos => {
        if (!clusters[pos.cluster]) clusters[pos.cluster] = [];
        clusters[pos.cluster].push(pos);
    });

    Object.entries(clusters).forEach(([clusterName, positions]) => {
        const cc = getClusterColor(clusterName);
        const lineColor = cc.marker;
        const labelColor = cc.label;
        const borderColor = cc.border;

        // Draw lines between all pairs (mesh) if >1 node
        if (positions.length >= 2) {
            for (let i = 0; i < positions.length; i++) {
                for (let j = i + 1; j < positions.length; j++) {
                    const line = L.polyline(
                        [[positions[i].lat, positions[i].lon], [positions[j].lat, positions[j].lon]],
                        { color: lineColor, weight: 1.5, opacity: 0.5, dashArray: '6, 4', interactive: false }
                    ).addTo(worldMap);
                    mapClusterLines.push(line);
                }
            }
        }

        // Place cluster label at centroid
        const centLat = positions.reduce((s, p) => s + p.lat, 0) / positions.length;
        const centLon = positions.reduce((s, p) => s + p.lon, 0) / positions.length;
        const countText = positions.length > 1 ? ` (${positions.length})` : '';
        const labelIcon = L.divIcon({
            className: 'cluster-label',
            html: `<div style="background:rgba(0,0,0,0.7);color:${labelColor};font-size:10px;font-weight:600;padding:2px 8px;border-radius:10px;border:1px solid ${borderColor};white-space:nowrap;text-shadow:0 1px 3px rgba(0,0,0,0.5);pointer-events:none;">${clusterName}${countText}</div>`,
            iconSize: [0, 0],
            iconAnchor: [0, -14]
        });
        const label = L.marker([centLat, centLon], { icon: labelIcon, interactive: false }).addTo(worldMap);
        mapClusterLabels.push(label);
    });
}

// Fit map bounds to show all placed markers
function fitMapToMarkers() {
    if (!worldMap) return;
    const markers = Object.values(mapMarkers);
    if (markers.length === 0) return;
    const group = L.featureGroup(markers);
    worldMap.fitBounds(group.getBounds().pad(0.3), { maxZoom: 10 });
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
            <td>${formatBytes(d.used_bytes)}</td>
            <td>${formatBytes(d.available_bytes)}</td>
            <td>${formatBytes(d.total_bytes)}</td>
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
        const data = await resp.json();
        // Support both new { version, nodes } format and legacy array format
        const nodes = Array.isArray(data) ? data : (data.nodes || []);
        // Update version display from backend
        if (data.version) {
            var versionEl = document.querySelector('.version');
            if (versionEl) versionEl.textContent = 'v' + data.version;
        }

        // Only rebuild sidebar tree if node list structure changed (NOT online status)
        var treeChanged = false;
        if (!allNodes || allNodes.length !== nodes.length) {
            treeChanged = true;
        } else {
            for (var i = 0; i < nodes.length; i++) {
                var old = allNodes.find(function (n) { return n.id === nodes[i].id; });
                if (!old ||
                    old.docker_count !== nodes[i].docker_count ||
                    old.lxc_count !== nodes[i].lxc_count ||
                    old.vm_count !== nodes[i].vm_count ||
                    old.hostname !== nodes[i].hostname ||
                    old.cluster_name !== nodes[i].cluster_name ||
                    (old.components || []).filter(function (c) { return c.installed; }).length !==
                    (nodes[i].components || []).filter(function (c) { return c.installed; }).length) {
                    treeChanged = true;
                    break;
                }
            }
        }

        allNodes = nodes;
        if (treeChanged) {
            buildServerTree(nodes);
        } else {
            // Update online/offline dots in-place without rebuilding the tree
            nodes.forEach(function (n) {
                // Update individual node dots (child items share the node header dot)
                var nodeHeader = document.querySelector(`.server-node-header[data-node-id="${n.id}"]`);
                if (nodeHeader) {
                    var dot = nodeHeader.querySelector('.server-dot');
                    if (dot) {
                        dot.className = 'server-dot ' + (n.online ? 'online' : 'offline');
                    }
                }
            });
            // Update cluster-level dots (any online = green)
            document.querySelectorAll('.server-node-header[data-cluster-id]').forEach(function (header) {
                var dot = header.querySelector('.server-dot');
                if (!dot) return;
                var childContainer = header.nextElementSibling;
                if (!childContainer) return;
                var childDots = childContainer.querySelectorAll('.server-dot');
                var anyOnline = Array.from(childDots).some(function (d) { return d.classList.contains('online'); });
                dot.className = 'server-dot ' + (anyOnline ? 'online' : 'offline');
            });
        }

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
    // Show a progress overlay during component install
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay active';
    overlay.style.cssText = 'display:flex; z-index:10001;';
    overlay.innerHTML = `
        <div style="background:var(--bg-card); border:1px solid var(--border); border-radius:16px; padding:32px; max-width:380px; width:90%; text-align:center; box-shadow:0 20px 60px rgba(0,0,0,0.5); animation:modalSlideIn 0.3s ease;">
            <div style="width:56px; height:56px; border:3px solid var(--border); border-top-color:var(--accent); border-radius:50%; animation:spin 0.8s linear infinite; margin:0 auto 20px;"></div>
            <h3 style="color:var(--text-primary); font-size:17px; margin-bottom:8px; font-weight:700;">Installing ${escapeHtml(name)}</h3>
            <p style="color:var(--text-secondary); font-size:13px; margin-bottom:16px;">This may take a minute…</p>
            <div style="height:4px; background:var(--bg-secondary); border-radius:4px; overflow:hidden;">
                <div style="height:100%; width:30%; background:linear-gradient(90deg,var(--accent),var(--accent-light)); border-radius:4px; animation:progressPulse 1.5s ease-in-out infinite;"></div>
            </div>
        </div>`;
    document.body.appendChild(overlay);
    try {
        const resp = await fetch(apiUrl(`/api/components/${name}/install`), { method: 'POST' });
        const data = await resp.json();
        overlay.remove();
        if (resp.ok) {
            showToast(`✅ ${name} installed successfully`, 'success');
        } else {
            showToast(data.error || 'Installation failed', 'error');
        }
        loadComponents();
    } catch (e) {
        overlay.remove();
        showToast('Failed: ' + e.message, 'error');
    }
}

async function serviceAction(service, action) {
    try {
        const resp = await fetch(apiUrl(`/api/services/${service}/action`), {
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

        const extraDisksHtml = (vm.extra_disks && vm.extra_disks.length > 0)
            ? vm.extra_disks.map(d => `<span style="margin-left:12px;">+ ${d.size_gb || '?'} GiB${d.path ? ` <span style="color:var(--text-muted);font-size:10px;">${d.path}</span>` : ''}</span>`).join('')
            : '';
        const storageSubRow = `<tr class="storage-sub-row" style="background:var(--bg-secondary);"><td colspan="7" style="padding:4px 16px 6px 24px;border-top:none;">
            <div style="display:flex;align-items:center;gap:8px;font-size:11px;">
                <span>💾</span>
                <span>${vm.disk_size_gb} GiB primary</span>
                ${extraDisksHtml}
            </div>
        </td></tr>`;

        return `
            <tr>
                <td><strong>${vm.name}</strong>${vm.iso_path ? `<br><small style="color:var(--text-muted);">💿 ${vm.iso_path.split('/').pop()}</small>` : ''}</td>
                <td><span style="color:${statusColor}">● ${statusText}</span></td>
                <td>${vm.cpus} vCPU / ${vm.memory_mb} MB</td>
                <td>${wolfnetIp !== '—' ? `<span class="badge" style="background:var(--accent-bg); color:var(--accent);">${wolfnetIp}</span>` : '—'}</td>
                <td>${vncText}</td>
                <td><input type="checkbox" ${autostart} onchange="toggleVmAutostart('${vm.name}', this.checked)"></td>
                <td style="white-space:nowrap;">
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="showVmLogs('${vm.name}')" title="Logs">📋</button>
                    ${vm.running ?
                `${vm.vnc_ws_port ? `<button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="openVmVnc('${vm.name}', ${vm.vnc_ws_port})" title="Console">🖥️</button>` : ''}
                         <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;color:#ef4444;" onclick="vmAction('${vm.name}', 'stop')" title="Stop">⏹️</button>` :
                `<button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="showVmSettings('${vm.name}')" title="Settings">⚙️</button>
                         <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;color:#22c55e;" onclick="vmAction('${vm.name}', 'start')" title="Start">▶️</button>
                         <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;color:#ef4444;" onclick="deleteVm('${vm.name}')" title="Delete">🗑️</button>`
            }
                </td>
            </tr>${storageSubRow}
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

    if (!name) return showModal('Name is required');

    let source = '';
    let s3_config = null;
    let nfs_options = null;

    if (type === 's3') {
        const bucket = document.getElementById('s3-bucket').value.trim();
        const access_key_id = document.getElementById('s3-access-key').value.trim();
        const secret_access_key = document.getElementById('s3-secret-key').value.trim();
        if (!access_key_id || !secret_access_key) return showModal('S3 Access Key and Secret Key are required');
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
        if (!source) return showModal('NFS source is required (e.g. 192.168.1.100:/data)');
    } else if (type === 'directory') {
        source = document.getElementById('dir-source').value.trim();
        if (!source) return showModal('Source directory is required');
    } else if (type === 'wolfdisk') {
        source = document.getElementById('wolfdisk-source').value.trim();
        if (!source) return showModal('WolfDisk path is required');
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
        showModal('Error creating mount: ' + e.message);
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
        showModal('Delete error: ' + e.message);
    }
}

async function syncStorageMount(id) {
    try {
        const resp = await fetch(apiUrl(`/api/storage/mounts/${id}/sync`), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Sync failed');
        const results = data.results || [];
        const summary = results.map(r => `${r.node}: ${r.status}`).join('\n');
        showModal('Sync complete:\n' + (summary || 'No remote nodes'), 'Storage Sync');
        loadStorageMounts();
    } catch (e) {
        showModal('Sync error: ' + e.message);
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
        showModal('Duplicate error: ' + e.message);
    }
}

// ─── Edit Storage Mount ───

function openEditMount(id) {
    const m = allStorageMounts.find(x => x.id === id);
    if (!m) return showModal('Mount not found');

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

    if (!name) return showModal('Name is required');

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
        showModal('Error saving mount: ' + e.message);
    }
}

async function importRcloneConfig() {
    const config = document.getElementById('rclone-config-paste').value.trim();
    if (!config) return showModal('Please paste your rclone.conf contents');

    try {
        const resp = await fetch(apiUrl('/api/storage/import-rclone'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config })
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Import failed');
        closeImportRcloneModal();
        showModal(data.message || 'Import complete', 'Import');
        loadStorageMounts();
    } catch (e) {
        showModal('Import error: ' + e.message);
    }
}

// ─── File Manager ───

let currentFilePath = '/';
let containerFileMode = null;  // null = host, {type:'docker', name:'xxx'} or {type:'lxc', name:'xxx', rootfs:'/path'}

function browseContainerFiles(type, name, storagePath) {
    // Always browse inside the container's filesystem starting at /
    if (type === 'lxc') {
        containerFileMode = { type: 'lxc', name };
        currentFilePath = '/';
    } else {
        containerFileMode = { type: 'docker', name };
        currentFilePath = '/';
    }

    // Set flag so selectServerView doesn't reset our state
    window._skipFileReset = true;

    // Switch to files view (this triggers loadFiles via selectServerView)
    selectServerView(currentNodeId, 'files');
}

async function loadFiles(path) {
    if (path !== undefined) currentFilePath = path;
    const table = document.getElementById('file-list-table');
    const empty = document.getElementById('file-empty');
    if (!table) return;

    // Show loading spinner
    table.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px 0;">
        <div class="page-loading-spinner" style="margin:0 auto 12px;"></div>
        <div style="color:var(--text-muted);font-size:13px;">Loading files…</div>
    </td></tr>`;
    if (empty) empty.style.display = 'none';

    // Update header to show container context
    const header = document.querySelector('#page-files .card-header h3');
    if (header) {
        if (containerFileMode && containerFileMode.type === 'docker') {
            header.textContent = `📂 Files — 🐳 ${containerFileMode.name}`;
        } else if (containerFileMode && containerFileMode.type === 'lxc') {
            header.textContent = `📂 Files — 📦 ${containerFileMode.name}`;
        } else {
            header.textContent = '📂 File Manager';
        }
    }

    try {
        let resp;
        if (containerFileMode && containerFileMode.type === 'docker') {
            resp = await fetch(apiUrl(`/api/files/docker/browse?container=${encodeURIComponent(containerFileMode.name)}&path=${encodeURIComponent(currentFilePath)}`));
        } else if (containerFileMode && containerFileMode.type === 'lxc') {
            resp = await fetch(apiUrl(`/api/files/lxc/browse?container=${encodeURIComponent(containerFileMode.name)}&path=${encodeURIComponent(currentFilePath)}`));
        } else {
            resp = await fetch(apiUrl(`/api/files/browse?path=${encodeURIComponent(currentFilePath)}`));
        }
        const data = await resp.json();
        if (!resp.ok) {
            showToast(data.error || 'Failed to browse', 'error');
            table.innerHTML = '';
            return;
        }

        currentFilePath = data.path || currentFilePath;
        renderFileBreadcrumb(currentFilePath);

        const entries = data.entries || [];
        if (entries.length === 0) {
            table.innerHTML = '';
            if (empty) empty.style.display = '';
            return;
        }
        if (empty) empty.style.display = 'none';
        renderFileList(entries);
    } catch (e) {
        console.error('File browse failed:', e);
        showToast('Failed to load files', 'error');
        table.innerHTML = '';
    }
}

function renderFileBreadcrumb(path) {
    const bc = document.getElementById('file-breadcrumb');
    if (!bc) return;

    const parts = path.split('/').filter(Boolean);
    let html = `<a href="#" onclick="navigateToDir('/');return false;" style="color:var(--accent);text-decoration:none;font-weight:600;">🏠 /</a>`;
    let accumulated = '';
    for (const part of parts) {
        accumulated += '/' + part;
        const p = accumulated;
        html += `<span style="color:var(--text-muted);">/</span>`;
        html += `<a href="#" onclick="navigateToDir('${p.replace(/'/g, "\\'")}');return false;" style="color:var(--accent);text-decoration:none;">${escapeHtml(part)}</a>`;
    }
    bc.innerHTML = html;
}

let cachedFileEntries = [];
let fileSearchTimer = null;

function renderFileList(entries) {
    const table = document.getElementById('file-list-table');
    if (!table) return;

    cachedFileEntries = entries;
    renderFilteredFileList(entries, false);
}

function renderFilteredFileList(entries, isSearch) {
    const table = document.getElementById('file-list-table');
    if (!table) return;

    table.innerHTML = entries.map(e => {
        const icon = e.is_dir ? '📁' : getFileIcon(e.name);
        const sizeStr = e.is_dir ? '—' : formatFileSize(e.size);
        const modStr = e.modified ? new Date(e.modified * 1000).toLocaleString() : '—';
        const nameClick = e.is_dir
            ? `onclick="navigateToDir('${e.path.replace(/'/g, "\\'")}')" style="cursor:pointer;color:#f5b731;font-weight:600;"`
            : '';
        const displayName = isSearch ? e.path : e.name;

        return `<tr>
            <td style="font-size:14px;"><input type="checkbox" class="file-checkbox" data-path="${escapeHtml(e.path)}" onchange="updateFileSelection()"></td>
            <td style="font-size:14px;"><span ${nameClick}>${icon} ${escapeHtml(displayName)}</span></td>
            <td style="font-size:13px;color:var(--text-muted);">${sizeStr}</td>
            <td style="font-size:13px;color:var(--text-muted);">${modStr}</td>
            <td style="font-family:var(--font-mono);font-size:13px;cursor:pointer;color:var(--accent);" onclick="changePermissions('${e.path.replace(/'/g, "\\'")}')" title="Click to change permissions">${escapeHtml(e.permissions)}</td>
            <td style="white-space:nowrap;">
                ${!e.is_dir ? `<button class="btn btn-sm" style="font-size:12px;padding:3px 8px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);" onclick="downloadFile('${e.path.replace(/'/g, "\\'")}')">⬇️</button>` : ''}
                <button class="btn btn-sm" style="font-size:12px;padding:3px 8px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);" onclick="renameFile('${e.path.replace(/'/g, "\\'")}', '${e.name.replace(/'/g, "\\'")}')">✏️</button>
                <button class="btn btn-sm" style="font-size:12px;padding:3px 8px;background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.3);" onclick="deleteFile('${e.path.replace(/'/g, "\\'")}', '${e.name.replace(/'/g, "\\'")}')">🗑️</button>
            </td>
        </tr>`;
    }).join('');

    updateFileSelection();
}

function toggleSelectAll(cb) {
    document.querySelectorAll('.file-checkbox').forEach(c => c.checked = cb.checked);
    updateFileSelection();
}

function getSelectedFiles() {
    return Array.from(document.querySelectorAll('.file-checkbox:checked')).map(c => c.dataset.path);
}

function updateFileSelection() {
    const selected = getSelectedFiles();
    const bar = document.getElementById('file-selection-bar');
    if (bar) {
        if (selected.length > 0) {
            bar.style.display = 'flex';
            bar.querySelector('.sel-count').textContent = `${selected.length} selected`;
        } else {
            bar.style.display = 'none';
        }
    }
}

async function bulkDeleteFiles() {
    const paths = getSelectedFiles();
    if (paths.length === 0) return;
    if (!confirm(`Delete ${paths.length} item(s)?\n\nThis cannot be undone.`)) return;
    for (const p of paths) {
        try {
            const endpoint = containerFileMode && containerFileMode.type === 'docker'
                ? '/api/files/docker/delete' : containerFileMode && containerFileMode.type === 'lxc'
                    ? '/api/files/lxc/delete' : '/api/files/delete';
            const body = (containerFileMode && (containerFileMode.type === 'docker' || containerFileMode.type === 'lxc'))
                ? { container: containerFileMode.name, path: p } : { path: p };
            await fetch(apiUrl(endpoint), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
        } catch (e) { /* continue */ }
    }
    showToast(`Deleted ${paths.length} item(s)`, 'success');
    loadFiles();
}

async function bulkChmod() {
    const paths = getSelectedFiles();
    if (paths.length === 0) return;
    const mode = prompt(`Set permissions for ${paths.length} item(s):\n\nExamples: 755, 644, u+x, go-w`, '644');
    if (!mode) return;
    try {
        const resp = await fetch(apiUrl('/api/files/chmod'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode, paths }),
        });
        const data = await resp.json();
        if (resp.ok) {
            const errs = (data.results || []).filter(r => r.error);
            if (errs.length > 0) {
                showToast(`${paths.length - errs.length} OK, ${errs.length} failed`, 'warning');
            } else {
                showToast(`Permissions set to ${mode}`, 'success');
            }
            loadFiles();
        } else {
            showToast(data.error || 'Failed', 'error');
        }
    } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
}

async function changePermissions(path) {
    const mode = prompt(`Set permissions for this item:\n\nExamples: 755, 644, u+x, go-w`, '644');
    if (!mode) return;
    try {
        const resp = await fetch(apiUrl('/api/files/chmod'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode, paths: [path] }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(`Permissions set to ${mode}`, 'success');
            loadFiles();
        } else {
            showToast(data.error || 'Failed', 'error');
        }
    } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
}

function filterFileList(query) {
    clearTimeout(fileSearchTimer);
    if (!query || query.trim() === '') {
        renderFilteredFileList(cachedFileEntries, false);
        return;
    }
    // Debounce 400ms then call server-side recursive search
    fileSearchTimer = setTimeout(async () => {
        try {
            let resp;
            if (containerFileMode && (containerFileMode.type === 'docker' || containerFileMode.type === 'lxc')) {
                // For containers, do client-side filter (find may not be available)
                const q = query.toLowerCase();
                const filtered = cachedFileEntries.filter(e => e.name.toLowerCase().includes(q));
                renderFilteredFileList(filtered, false);
                return;
            }
            resp = await fetch(apiUrl(`/api/files/search?path=${encodeURIComponent(currentFilePath)}&query=${encodeURIComponent(query)}`));
            const data = await resp.json();
            if (resp.ok) {
                renderFilteredFileList(data.entries || [], true);
            }
        } catch (e) {
            console.error('Search failed:', e);
        }
    }, 400);
}

function getFileIcon(name) {
    const ext = name.split('.').pop().toLowerCase();
    const icons = {
        'js': '📜', 'ts': '📜', 'rs': '🦀', 'py': '🐍', 'go': '🔵',
        'html': '🌐', 'css': '🎨', 'json': '📋', 'xml': '📋', 'yaml': '📋', 'yml': '📋', 'toml': '📋',
        'md': '📝', 'txt': '📄', 'log': '📄', 'conf': '⚙️', 'cfg': '⚙️', 'ini': '⚙️',
        'sh': '⚡', 'bash': '⚡', 'zsh': '⚡',
        'png': '🖼️', 'jpg': '🖼️', 'jpeg': '🖼️', 'gif': '🖼️', 'svg': '🖼️', 'webp': '🖼️',
        'zip': '📦', 'tar': '📦', 'gz': '📦', 'bz2': '📦', 'xz': '📦', 'rar': '📦',
        'db': '🗃️', 'sql': '🗃️', 'sqlite': '🗃️',
    };
    return icons[ext] || '📄';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function navigateToDir(path) {
    const searchInput = document.getElementById('file-search-input');
    if (searchInput) searchInput.value = '';
    loadFiles(path);
}

function downloadFile(path) {
    if (containerFileMode && containerFileMode.type === 'docker') {
        window.open(apiUrl(`/api/files/docker/download?container=${encodeURIComponent(containerFileMode.name)}&path=${encodeURIComponent(path)}`), '_blank');
    } else if (containerFileMode && containerFileMode.type === 'lxc') {
        window.open(apiUrl(`/api/files/lxc/download?container=${encodeURIComponent(containerFileMode.name)}&path=${encodeURIComponent(path)}`), '_blank');
    } else {
        window.open(apiUrl(`/api/files/download?path=${encodeURIComponent(path)}`), '_blank');
    }
}

async function deleteFile(path, name) {
    if (!confirm(`Delete '${name}'?\n\nThis cannot be undone.`)) return;
    try {
        let resp;
        if (containerFileMode && containerFileMode.type === 'docker') {
            resp = await fetch(apiUrl('/api/files/docker/delete'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container: containerFileMode.name, path }),
            });
        } else if (containerFileMode && containerFileMode.type === 'lxc') {
            resp = await fetch(apiUrl('/api/files/lxc/delete'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container: containerFileMode.name, path }),
            });
        } else {
            resp = await fetch(apiUrl('/api/files/delete'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path }),
            });
        }
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Deleted', 'success');
            loadFiles();
        } else {
            showToast(data.error || 'Failed to delete', 'error');
        }
    } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
}

async function renameFile(path, oldName) {
    const newName = prompt(`Rename '${oldName}' to:`, oldName);
    if (!newName || newName === oldName) return;
    const parentDir = path.substring(0, path.lastIndexOf('/'));
    const newPath = parentDir + '/' + newName;
    try {
        let resp;
        if (containerFileMode && containerFileMode.type === 'docker') {
            resp = await fetch(apiUrl('/api/files/docker/rename'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container: containerFileMode.name, from: path, to: newPath }),
            });
        } else if (containerFileMode && containerFileMode.type === 'lxc') {
            resp = await fetch(apiUrl('/api/files/lxc/rename'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container: containerFileMode.name, from: path, to: newPath }),
            });
        } else {
            resp = await fetch(apiUrl('/api/files/rename'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ from: path, to: newPath }),
            });
        }
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Renamed', 'success');
            loadFiles();
        } else {
            showToast(data.error || 'Failed to rename', 'error');
        }
    } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
}

function showNewFolderModal() {
    const name = prompt('Enter folder name:');
    if (!name) return;
    createNewFolder(name);
}

async function createNewFolder(name) {
    const path = currentFilePath.endsWith('/') ? currentFilePath + name : currentFilePath + '/' + name;
    try {
        let resp;
        if (containerFileMode && containerFileMode.type === 'docker') {
            resp = await fetch(apiUrl('/api/files/docker/mkdir'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container: containerFileMode.name, path }),
            });
        } else if (containerFileMode && containerFileMode.type === 'lxc') {
            resp = await fetch(apiUrl('/api/files/lxc/mkdir'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container: containerFileMode.name, path }),
            });
        } else {
            resp = await fetch(apiUrl('/api/files/mkdir'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path }),
            });
        }
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Folder created', 'success');
            loadFiles();
        } else {
            showToast(data.error || 'Failed to create folder', 'error');
        }
    } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
}

function triggerFileUpload() {
    document.getElementById('file-upload-input').click();
}

async function uploadFiles(files) {
    if (!files || files.length === 0) return;
    const formData = new FormData();
    for (const file of files) {
        formData.append('file', file, file.name);
    }
    try {
        const resp = await fetch(apiUrl(`/api/files/upload?path=${encodeURIComponent(currentFilePath)}`), {
            method: 'POST',
            body: formData,
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Uploaded', 'success');
            loadFiles();
        } else {
            showToast(data.error || 'Upload failed', 'error');
        }
    } catch (e) { showToast(`Upload failed: ${e.message}`, 'error'); }
    // Reset the input
    document.getElementById('file-upload-input').value = '';
}

// ─── ZFS Storage ───

async function loadZfsStatus() {
    try {
        const resp = await fetch(apiUrl('/api/storage/zfs/status'));
        const data = await resp.json();
        const section = document.getElementById('zfs-section');
        if (!section) return;

        if (!data.available) {
            section.style.display = 'none';
            return;
        }
        section.style.display = '';
        renderZfsPools(data.pools || []);
    } catch (e) {
        console.error('Failed to load ZFS status:', e);
        const section = document.getElementById('zfs-section');
        if (section) section.style.display = 'none';
    }
}

function renderZfsPools(pools) {
    const table = document.getElementById('zfs-pools-table');
    if (!table) return;

    if (pools.length === 0) {
        table.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No ZFS pools found</td></tr>';
        return;
    }

    table.innerHTML = pools.map(p => {
        const healthColor = p.health === 'ONLINE' ? '#10b981' : p.health === 'DEGRADED' ? '#f59e0b' : '#ef4444';
        const isScrubbing = (p.scan || '').toLowerCase().includes('scrub in progress');
        const scanInfo = p.scan || 'none requested';
        const errorsInfo = p.errors || 'No known data errors';
        const errorsColor = errorsInfo.toLowerCase().includes('no known') ? '#10b981' : '#ef4444';

        return `<tr>
            <td><strong>${escapeHtml(p.name)}</strong></td>
            <td>${escapeHtml(p.size)}</td>
            <td>${escapeHtml(p.alloc)}</td>
            <td>${escapeHtml(p.free)}</td>
            <td><span style="color:${healthColor};font-weight:600;">● ${escapeHtml(p.health)}</span></td>
            <td>${escapeHtml(p.fragmentation)}</td>
            <td>${escapeHtml(p.capacity)}</td>
            <td style="white-space:nowrap;">
                <button class="btn btn-sm" style="font-size:11px;padding:2px 8px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);" onclick="expandZfsPool('${escapeHtml(p.name)}')" title="Datasets">📂 Datasets</button>
                <button class="btn btn-sm" style="font-size:11px;padding:2px 8px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);" onclick="showZfsSnapshots('${escapeHtml(p.name)}')" title="Snapshots">📸 Snapshots</button>
                ${isScrubbing
                ? `<button class="btn btn-sm" style="font-size:11px;padding:2px 8px;background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.3);" onclick="zfsPoolScrub('${escapeHtml(p.name)}', true)" title="Stop Scrub">⏹️ Stop Scrub</button>`
                : `<button class="btn btn-sm" style="font-size:11px;padding:2px 8px;background:rgba(16,185,129,0.1);color:#10b981;border:1px solid rgba(16,185,129,0.3);" onclick="zfsPoolScrub('${escapeHtml(p.name)}', false)" title="Start Scrub">🔍 Scrub</button>`
            }
                <button class="btn btn-sm" style="font-size:11px;padding:2px 8px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);" onclick="showZfsPoolStatus('${escapeHtml(p.name)}')" title="Detailed Status">📋 Status</button>
                <button class="btn btn-sm" style="font-size:11px;padding:2px 8px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);" onclick="showZfsPoolIostat('${escapeHtml(p.name)}')" title="IO Statistics">📊 IO Stats</button>
            </td>
        </tr>
        <tr class="storage-sub-row" style="background:var(--bg-secondary);">
            <td colspan="8" style="padding:4px 16px 6px 24px;border-top:none;">
                <div style="display:flex;align-items:center;gap:16px;font-size:11px;flex-wrap:wrap;">
                    <span>🔄 <strong>Scan:</strong> ${escapeHtml(scanInfo.length > 80 ? scanInfo.substring(0, 80) + '…' : scanInfo)}</span>
                    <span style="color:${errorsColor};">⚠️ <strong>Errors:</strong> ${escapeHtml(errorsInfo)}</span>
                    <span>🔢 <strong>Dedup:</strong> ${escapeHtml(p.dedup || '1.00x')}</span>
                </div>
            </td>
        </tr>`;
    }).join('');
}

async function expandZfsPool(pool) {
    const detailSection = document.getElementById('zfs-detail-section');
    if (!detailSection) return;

    detailSection.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);">Loading datasets...</div>';

    try {
        const resp = await fetch(apiUrl(`/api/storage/zfs/datasets?pool=${encodeURIComponent(pool)}`));
        const datasets = await resp.json();

        if (!Array.isArray(datasets) || datasets.length === 0) {
            detailSection.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);">No datasets found</div>';
            return;
        }

        detailSection.innerHTML = `
            <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;padding:16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <h4 style="margin:0;font-size:14px;">📁 Datasets — ${escapeHtml(pool)}</h4>
                    <button class="btn btn-sm" onclick="document.getElementById('zfs-detail-section').innerHTML=''" style="font-size:11px;padding:2px 8px;">✕ Close</button>
                </div>
                <table class="data-table">
                    <thead><tr><th>Name</th><th>Used</th><th>Available</th><th>Refer</th><th>Mountpoint</th><th>Compression</th><th>Ratio</th><th>Actions</th></tr></thead>
                    <tbody>
                    ${datasets.map(d => `<tr>
                        <td style="font-family:var(--font-mono);font-size:12px;">${escapeHtml(d.name)}</td>
                        <td>${escapeHtml(d.used)}</td>
                        <td>${escapeHtml(d.available)}</td>
                        <td>${escapeHtml(d.refer)}</td>
                        <td style="font-family:var(--font-mono);font-size:12px;">${escapeHtml(d.mountpoint)}</td>
                        <td>${escapeHtml(d.compression)}</td>
                        <td>${escapeHtml(d.compressratio)}</td>
                        <td>
                            <button class="btn btn-sm btn-primary" style="font-size:11px;padding:2px 8px;" onclick="createZfsSnapshot('${escapeHtml(d.name)}')">📸 Snapshot</button>
                        </td>
                    </tr>`).join('')}
                    </tbody>
                </table>
            </div>`;
    } catch (e) {
        detailSection.innerHTML = `<div style="text-align:center;padding:20px;color:#ef4444;">Failed to load datasets: ${e.message}</div>`;
    }
}

async function showZfsSnapshots(pool) {
    const detailSection = document.getElementById('zfs-detail-section');
    if (!detailSection) return;

    detailSection.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);">Loading snapshots...</div>';

    try {
        const resp = await fetch(apiUrl(`/api/storage/zfs/snapshots?dataset=${encodeURIComponent(pool)}`));
        const snapshots = await resp.json();

        if (!Array.isArray(snapshots) || snapshots.length === 0) {
            detailSection.innerHTML = `
                <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;padding:16px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <h4 style="margin:0;font-size:14px;">📸 Snapshots — ${escapeHtml(pool)}</h4>
                        <button class="btn btn-sm" onclick="document.getElementById('zfs-detail-section').innerHTML=''" style="font-size:11px;padding:2px 8px;">✕ Close</button>
                    </div>
                    <div style="text-align:center;padding:20px;color:var(--text-muted);">No snapshots found for this pool</div>
                </div>`;
            return;
        }

        detailSection.innerHTML = `
            <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;padding:16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <h4 style="margin:0;font-size:14px;">📸 Snapshots — ${escapeHtml(pool)} (${snapshots.length})</h4>
                    <button class="btn btn-sm" onclick="document.getElementById('zfs-detail-section').innerHTML=''" style="font-size:11px;padding:2px 8px;">✕ Close</button>
                </div>
                <table class="data-table">
                    <thead><tr><th>Snapshot</th><th>Created</th><th>Used</th><th>Refer</th><th>Actions</th></tr></thead>
                    <tbody>
                    ${snapshots.map(s => `<tr>
                        <td style="font-family:var(--font-mono);font-size:12px;">${escapeHtml(s.name)}</td>
                        <td style="font-size:12px;">${escapeHtml(s.creation)}</td>
                        <td>${escapeHtml(s.used)}</td>
                        <td>${escapeHtml(s.refer)}</td>
                        <td>
                            <button class="btn btn-sm btn-danger" style="font-size:11px;padding:2px 8px;" onclick="deleteZfsSnapshot('${escapeHtml(s.name)}')">🗑️ Delete</button>
                        </td>
                    </tr>`).join('')}
                    </tbody>
                </table>
            </div>`;
    } catch (e) {
        detailSection.innerHTML = `<div style="text-align:center;padding:20px;color:#ef4444;">Failed to load snapshots: ${e.message}</div>`;
    }
}

async function createZfsSnapshot(dataset) {
    const name = await wolfPrompt(`Enter snapshot name for ${dataset}:`, `snap-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`, 'Create Snapshot', { okText: 'Create' });
    if (!name) return;

    try {
        const resp = await fetch(apiUrl('/api/storage/zfs/snapshot'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dataset, name }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Snapshot created', 'success');
            // Refresh the pool's snapshot list
            const pool = dataset.split('/')[0];
            showZfsSnapshots(pool);
        } else {
            showToast(data.error || 'Failed to create snapshot', 'error');
        }
    } catch (e) {
        showToast(`Failed: ${e.message}`, 'error');
    }
}

async function deleteZfsSnapshot(snapshot) {
    const confirmed = await wolfConfirm(`Delete ZFS snapshot '${snapshot}'?\n\nThis cannot be undone.`, 'Delete Snapshot', { okText: 'Delete', danger: true });
    if (!confirmed) return;

    try {
        const resp = await fetch(apiUrl('/api/storage/zfs/snapshot'), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ snapshot }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'Snapshot deleted', 'success');
            // Refresh
            const pool = snapshot.split('@')[0].split('/')[0];
            showZfsSnapshots(pool);
        } else {
            showToast(data.error || 'Failed to delete snapshot', 'error');
        }
    } catch (e) {
        showToast(`Failed: ${e.message}`, 'error');
    }
}

async function zfsPoolScrub(pool, stop) {
    const action = stop ? 'Stop scrub on' : 'Start scrub on';
    const confirmed = await wolfConfirm(`${action} pool '${pool}'?`, stop ? 'Stop Scrub' : 'Start Scrub', { okText: stop ? 'Stop' : 'Start', danger: stop });
    if (!confirmed) return;
    try {
        const resp = await fetch(apiUrl('/api/storage/zfs/pool/scrub'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pool, stop }),
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message || 'OK', 'success');
            setTimeout(loadZfsStatus, 1000); // refresh to show updated scan status
        } else {
            showToast(data.error || 'Failed', 'error');
        }
    } catch (e) { showToast(`Failed: ${e.message}`, 'error'); }
}

async function showZfsPoolStatus(pool) {
    const detailSection = document.getElementById('zfs-detail-section');
    if (!detailSection) return;

    detailSection.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);">Loading pool status...</div>';

    try {
        const resp = await fetch(apiUrl(`/api/storage/zfs/pool/status?pool=${encodeURIComponent(pool)}`));
        const data = await resp.json();

        if (!resp.ok) {
            detailSection.innerHTML = `<div style="text-align:center;padding:20px;color:#ef4444;">${data.error || 'Failed'}</div>`;
            return;
        }

        detailSection.innerHTML = `
            <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;padding:16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <h4 style="margin:0;font-size:14px;">📋 Pool Status — ${escapeHtml(pool)}</h4>
                    <button class="btn btn-sm" onclick="document.getElementById('zfs-detail-section').innerHTML=''" style="font-size:11px;padding:2px 8px;">✕ Close</button>
                </div>
                <pre style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:12px;
                    font-family:'JetBrains Mono',monospace;font-size:12px;max-height:400px;overflow-y:auto;
                    color:var(--text-primary);white-space:pre-wrap;word-break:break-all;">${escapeHtml(data.status_text)}</pre>
            </div>`;
    } catch (e) {
        detailSection.innerHTML = `<div style="text-align:center;padding:20px;color:#ef4444;">Failed: ${e.message}</div>`;
    }
}

async function showZfsPoolIostat(pool) {
    const detailSection = document.getElementById('zfs-detail-section');
    if (!detailSection) return;

    detailSection.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);">Loading IO stats...</div>';

    try {
        const resp = await fetch(apiUrl(`/api/storage/zfs/pool/iostat?pool=${encodeURIComponent(pool)}`));
        const data = await resp.json();

        if (!resp.ok) {
            detailSection.innerHTML = `<div style="text-align:center;padding:20px;color:#ef4444;">${data.error || 'Failed'}</div>`;
            return;
        }

        detailSection.innerHTML = `
            <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;padding:16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <h4 style="margin:0;font-size:14px;">📊 IO Statistics — ${escapeHtml(pool)}</h4>
                    <button class="btn btn-sm" onclick="document.getElementById('zfs-detail-section').innerHTML=''" style="font-size:11px;padding:2px 8px;">✕ Close</button>
                </div>
                <pre style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:12px;
                    font-family:'JetBrains Mono',monospace;font-size:12px;max-height:400px;overflow-y:auto;
                    color:var(--text-primary);white-space:pre-wrap;word-break:break-all;">${escapeHtml(data.iostat_text)}</pre>
            </div>`;
    } catch (e) {
        detailSection.innerHTML = `<div style="text-align:center;padding:20px;color:#ef4444;">Failed: ${e.message}</div>`;
    }
}

// ─── Disk Partition Info ───

async function loadDiskInfo() {
    const tbody = document.getElementById('disk-info-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">Loading…</td></tr>';
    try {
        const resp = await fetch(apiUrl('/api/storage/disk-info'));
        if (!resp.ok) throw new Error(await resp.text());
        const data = await resp.json();
        renderDiskInfo(data.devices || []);
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#ef4444; padding:20px;">Failed to load disk info: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function renderDiskInfo(devices) {
    const tbody = document.getElementById('disk-info-tbody');
    if (!tbody) return;

    if (!devices || devices.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">No block devices found</td></tr>';
        return;
    }

    tbody.innerHTML = devices.map(d => {
        const typeIcon = d.type === 'disk' ? '🖴' : d.type === 'part' ? '📌' : d.type === 'lvm' ? '🗂️' : '📦';
        const typeLabel = d.type === 'disk' ? 'Disk' : d.type === 'part' ? 'Partition'
            : d.type === 'lvm' ? 'LVM' : d.type === 'loop' ? 'Loop' : d.type || '—';

        const indent = d.type !== 'disk' ? 'padding-left:20px;' : 'font-weight:600;';
        const fstype = d.fstype || '<span style="color:var(--text-muted)">—</span>';

        const mounts = (d.mountpoints || []).length > 0
            ? d.mountpoints.map(m => `<code style="font-size:11px; background:var(--bg-secondary); padding:1px 5px; border-radius:3px;">${escapeHtml(m)}</code>`).join(' ')
            : '<span style="color:var(--text-muted)">—</span>';

        let freeCell = '<span style="color:var(--text-muted)">—</span>';
        if (d.df && d.df.total_bytes > 0) {
            const freePct = d.df.free_pct;
            const usePct = d.df.use_pct;
            const freeBytes = d.df.avail_bytes;
            const freeStr = formatStorageBytes(freeBytes);
            const barColor = freePct < 10 ? '#ef4444' : freePct < 25 ? '#f59e0b' : '#10b981';
            freeCell = `
                <div style="display:flex; align-items:center; gap:8px; min-width:120px;">
                    <div style="flex:1; background:var(--bg-secondary); border-radius:3px; height:6px; overflow:hidden;">
                        <div style="width:${usePct}%; background:${barColor}; height:100%; border-radius:3px; transition:width 0.3s;"></div>
                    </div>
                    <span style="font-size:12px; white-space:nowrap; color:${barColor};">${escapeHtml(freeStr)} free</span>
                </div>`;
        }

        const modelInfo = d.type === 'disk'
            ? (d.model ? escapeHtml(d.model) : '<span style="color:var(--text-muted)">—</span>')
            : `<span style="color:var(--text-muted);font-size:11px;">${escapeHtml(d.disk)}</span>`;

        const rotate = d.rotational ? '🔄 HDD' : '⚡ SSD';
        const deviceLabel = `<code style="font-size:12px;">${escapeHtml(d.device)}</code>`;

        return `<tr>
            <td style="${indent}${d.type !== 'disk' ? 'color:var(--text-secondary);' : ''}">${deviceLabel}</td>
            <td>${typeIcon} <span style="font-size:12px;">${typeLabel}${d.type === 'disk' ? ' · ' + rotate : ''}</span></td>
            <td style="font-size:12px;">${modelInfo}</td>
            <td style="font-family:var(--font-mono); font-size:12px;">${fstype}</td>
            <td style="font-size:13px; white-space:nowrap;">${escapeHtml(d.size)}</td>
            <td>${mounts}</td>
            <td>${freeCell}</td>
        </tr>`;
    }).join('');
}

function formatStorageBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
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
    const email = document.getElementById('cert-email').value.trim();
    if (!domain) { showToast('Enter a domain name', 'error'); return; }
    if (!email) { showToast('Enter an email address (required by Let\'s Encrypt)', 'error'); return; }

    showToast(`Requesting certificate for ${domain}... This may take a moment.`, 'info');
    try {
        const resp = await fetch(apiUrl('/api/certificates'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, email })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast(data.message, 'success');
            loadCertificates();
        } else {
            showToast(data.error || 'Certificate request failed', 'error');
        }
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function loadCertificates() {
    const el = document.getElementById('cert-list');
    if (!el) return;
    try {
        const resp = await fetch(apiUrl('/api/certificates/list'));
        const data = await resp.json();
        const certs = data.certs || data; // handle both new {certs,diagnostics} and legacy array format
        const diagnostics = data.diagnostics || [];

        let html = '';
        if (!certs || certs.length === 0) {
            html += '<p style="color: var(--text-muted);">No certificates installed. Request one above.</p>';
        } else {
            html += certs.map(c => `
                <div style="padding: 10px; margin-bottom: 8px; background: var(--bg-tertiary); border-radius: 8px; display: flex; align-items: center; gap: 12px;">
                    <span style="font-size: 20px;">${c.valid ? '✅' : '⚠️'}</span>
                    <div style="flex:1;">
                        <strong>${c.domain}</strong><br>
                        <span style="font-size: 12px; color: var(--text-muted);">${c.cert_path}</span>
                        ${c.source ? `<br><span style="font-size: 11px; color: var(--text-muted);">Source: ${c.source}</span>` : ''}
                        ${c.expiry ? `<br><span style="font-size: 12px; color: var(--text-muted);">Expires: ${c.expiry}</span>` : ''}
                    </div>
                </div>
            `).join('');
        }

        if (diagnostics.length > 0) {
            html += `
                <details style="margin-top: 12px; font-size: 13px;">
                    <summary style="cursor: pointer; color: var(--text-muted); user-select: none;">🔍 Discovery diagnostics</summary>
                    <div style="margin-top: 8px; padding: 10px; background: var(--bg-tertiary); border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.8;">
                        ${diagnostics.map(d => `<div>${d}</div>`).join('')}
                    </div>
                </details>`;
        }

        el.innerHTML = html;
    } catch (e) {
        el.innerHTML = '<p style="color: var(--text-muted);">Could not load certificates.</p>';
    }
}

// ─── Cron Job Management ───

async function loadCronJobs() {
    var container = document.getElementById('cron-entries-container');
    if (!container) return;
    container.innerHTML = '<div style="color:var(--text-muted);">Loading cron jobs...</div>';
    try {
        var resp = await fetch(apiUrl('/api/cron'));
        var data = await resp.json();
        var entries = data.entries || [];
        var raw = data.raw || '';

        // Update raw crontab
        var rawEl = document.getElementById('raw-crontab-content');
        if (rawEl) rawEl.textContent = raw || '(empty crontab)';

        if (entries.length === 0) {
            container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:14px;">No cron jobs found. Add one above or use a Quick Action.</div>';
            return;
        }

        var html = '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:13px;">';
        html += '<thead><tr style="border-bottom:2px solid var(--border,#333);text-align:left;">' +
            '<th style="padding:10px 12px;color:var(--text-muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">Status</th>' +
            '<th style="padding:10px 12px;color:var(--text-muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">Schedule</th>' +
            '<th style="padding:10px 12px;color:var(--text-muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">Command</th>' +
            '<th style="padding:10px 12px;color:var(--text-muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">Comment</th>' +
            '<th style="padding:10px 12px;color:var(--text-muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;text-align:right;">Actions</th>' +
            '</tr></thead><tbody>';

        entries.forEach(function (e) {
            var statusBadge = e.enabled
                ? '<span style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(34,197,94,0.15);color:#22c55e;">Active</span>'
                : '<span style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(239,68,68,0.15);color:#ef4444;">Disabled</span>';

            html += '<tr style="border-bottom:1px solid var(--border,#333);">' +
                '<td style="padding:10px 12px;">' + statusBadge + '</td>' +
                '<td style="padding:10px 12px;"><div style="font-weight:600;color:var(--text);">' + escapeHtml(e.human) + '</div>' +
                '<div style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">' + escapeHtml(e.schedule) + '</div></td>' +
                '<td style="padding:10px 12px;font-family:var(--font-mono);font-size:12px;color:var(--text);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(e.command) + '">' + escapeHtml(e.command) + '</td>' +
                '<td style="padding:10px 12px;color:var(--text-muted);font-size:12px;">' + escapeHtml(e.comment || '—') + '</td>' +
                '<td style="padding:10px 12px;text-align:right;white-space:nowrap;">' +
                '<button class="btn btn-sm" onclick="toggleCronJob(' + e.index + ', ' + e.enabled + ', \'' + escapeHtml(e.schedule).replace(/'/g, "\\'") + '\', \'' + escapeHtml(e.command).replace(/'/g, "\\'") + '\', \'' + escapeHtml(e.comment).replace(/'/g, "\\'") + '\')" title="' + (e.enabled ? 'Disable' : 'Enable') + '" style="margin-right:4px;">' + (e.enabled ? '⏸️' : '▶️') + '</button>' +
                '<button class="btn btn-sm" onclick="deleteCronJob(' + e.index + ')" title="Delete" style="color:var(--danger,#ef4444);">🗑️</button>' +
                '</td></tr>';
        });
        html += '</tbody></table></div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<div style="color:var(--danger,#ef4444);">Failed to load cron jobs: ' + e.message + '</div>';
    }
}


function onCronPresetChange() {
    var sel = document.getElementById('cron-schedule-preset');
    var custom = document.getElementById('cron-custom-schedule-group');
    if (sel && custom) {
        custom.hidden = (sel.value !== 'custom');
    }
}

async function addCronJob() {
    var sel = document.getElementById('cron-schedule-preset');
    var schedule = sel.value;
    if (schedule === 'custom') {
        schedule = (document.getElementById('cron-custom-schedule') || {}).value || '';
    }
    var command = (document.getElementById('cron-command') || {}).value || '';
    var comment = (document.getElementById('cron-comment') || {}).value || '';

    if (!schedule || !command) {
        showToast('Please enter both a schedule and a command.', 'warning');
        return;
    }

    try {
        var resp = await fetch(apiUrl('/api/cron'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ schedule: schedule, command: command, comment: comment, enabled: true })
        });
        var data = await resp.json();
        if (data.status === 'saved') {
            showToast('Cron job added!', 'success');
            document.getElementById('cron-command').value = '';
            document.getElementById('cron-comment').value = '';
            if (document.getElementById('cron-custom-schedule')) document.getElementById('cron-custom-schedule').value = '';
            loadCronJobs();
        } else {
            showToast('Error: ' + (data.error || 'Failed to save'), 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function deleteCronJob(index) {
    if (!confirm('Delete this cron job?')) return;
    try {
        var resp = await fetch(apiUrl('/api/cron/' + index), { method: 'DELETE' });
        var data = await resp.json();
        if (data.status === 'deleted') {
            showToast('Cron job deleted.', 'success');
            loadCronJobs();
        } else {
            showToast('Error: ' + (data.error || 'Failed to delete'), 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function toggleCronJob(index, currentlyEnabled, schedule, command, comment) {
    try {
        var resp = await fetch(apiUrl('/api/cron'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                schedule: schedule,
                command: command,
                comment: comment || '',
                index: index,
                enabled: !currentlyEnabled
            })
        });
        var data = await resp.json();
        if (data.status === 'saved') {
            showToast(currentlyEnabled ? 'Cron job disabled.' : 'Cron job enabled.', 'success');
            loadCronJobs();
        } else {
            showToast('Error: ' + (data.error || 'Failed'), 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

var PREMADE_CRON_JOBS = {
    'wolfstack-update': { schedule: '0 3 * * *', command: 'curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/setup.sh | bash', comment: 'Auto-update WolfStack (daily 3AM)' },
    'docker-prune': { schedule: '0 4 * * 0', command: 'docker image prune -af 2>/dev/null; docker system prune -f 2>/dev/null', comment: 'Clean Docker images (weekly)' },
    'apt-update': { schedule: '0 2 * * 1', command: 'apt-get update -qq && apt-get upgrade -y -qq', comment: 'System updates (weekly Mon 2AM)' },
    'certbot-renew': { schedule: '0 5 * * *', command: 'certbot renew --quiet', comment: 'Renew SSL certificates' },
    'tmpclean': { schedule: '0 6 * * *', command: 'find /tmp -type f -atime +7 -delete 2>/dev/null', comment: 'Clean /tmp files older than 7 days' }
};

async function addPremadeCron(type) {
    var job = PREMADE_CRON_JOBS[type];
    if (!job) return;
    if (!confirm('Add premade cron job?\n\nSchedule: ' + job.schedule + '\nCommand: ' + job.command + '\nComment: ' + job.comment)) return;
    try {
        var resp = await fetch(apiUrl('/api/cron'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ schedule: job.schedule, command: job.command, comment: job.comment, enabled: true })
        });
        var data = await resp.json();
        if (data.status === 'saved') {
            showToast('Premade cron job added!', 'success');
            loadCronJobs();
        } else {
            showToast('Error: ' + (data.error || 'Failed'), 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function toggleRawCrontab() {
    var body = document.getElementById('raw-crontab-body');
    var arrow = document.getElementById('raw-crontab-arrow');
    if (!body) return;
    var isHidden = body.style.display === 'none';
    body.style.display = isHidden ? 'block' : 'none';
    if (arrow) arrow.style.transform = isHidden ? 'rotate(90deg)' : 'rotate(0deg)';
}

// ─── Modals ───
function openAddServerModal() {
    document.getElementById('add-server-modal').classList.add('active');
    fetchOwnJoinToken();
}

function closeModal() {
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
}

async function addServer() {
    const nodeType = (document.getElementById('new-server-type') || {}).value || 'wolfstack';
    const address = document.getElementById('new-server-address').value.trim();
    const port = parseInt(document.getElementById('new-server-port').value) || (nodeType === 'proxmox' ? 8006 : 8553);

    const clusterName = (document.getElementById('new-server-cluster-name') || {}).value?.trim() || '';

    if (!address) { showToast('Enter a server address', 'error'); return; }

    var payload = { address, port, node_type: nodeType, cluster_name: clusterName || null };

    if (nodeType === 'proxmox') {
        var pveTokenId = (document.getElementById('new-pve-token-id') || {}).value.trim();
        var pveTokenSecret = (document.getElementById('new-pve-token-secret') || {}).value.trim();
        var pveName = (document.getElementById('new-pve-node-name') || {}).value.trim();
        var pveFingerprint = (document.getElementById('new-pve-fingerprint') || {}).value.trim();
        var pveClusterName = (document.getElementById('new-pve-cluster-name') || {}).value.trim();

        if (!pveTokenId || !pveTokenSecret || !pveName) {
            showToast('PVE Node Name, Token ID, and Token Secret are required', 'error');
            return;
        }
        // Combine into PVE API token format: user@pam!tokenid=secret-uuid
        payload.pve_token = pveTokenId + '=' + pveTokenSecret;
        payload.pve_node_name = pveName;
        if (pveFingerprint) payload.pve_fingerprint = pveFingerprint;
        if (pveClusterName) payload.pve_cluster_name = pveClusterName;
    } else {
        // Standard WolfStack node
        var wsClusterName = (document.getElementById('new-server-cluster-name') || {}).value.trim();
        var joinToken = (document.getElementById('new-server-join-token') || {}).value.trim();
        // Default to "WolfStack" if empty, as requested
        payload.cluster_name = wsClusterName || "WolfStack";
        if (!joinToken) {
            showToast('Join token is required. Get it from the remote server.', 'error');
            return;
        }
        payload.join_token = joinToken;
    }

    try {
        var resp = await fetch('/api/nodes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        var data = await resp.json();
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }
        if (nodeType === 'proxmox' && data.nodes_discovered) {
            showToast('Proxmox cluster added — ' + data.nodes_discovered.length + ' node(s) discovered: ' + data.nodes_discovered.join(', '), 'success');
        } else {
            showToast('Server ' + address + ' added', 'success');
            setTimeout(() => showToast('💡 When done adding nodes, use "Update WolfNet Connections" in Cluster Settings to sync networking', 'info'), 1500);
        }
        closeModal();
        document.getElementById('new-server-address').value = '';
        if (document.getElementById('new-pve-token-id')) document.getElementById('new-pve-token-id').value = '';
        if (document.getElementById('new-pve-token-secret')) document.getElementById('new-pve-token-secret').value = '';
        if (document.getElementById('new-pve-node-name')) document.getElementById('new-pve-node-name').value = '';
        if (document.getElementById('new-pve-fingerprint')) document.getElementById('new-pve-fingerprint').value = '';
        if (document.getElementById('new-pve-cluster-name')) document.getElementById('new-pve-cluster-name').value = '';
        if (document.getElementById('new-server-join-token')) document.getElementById('new-server-join-token').value = '';
        fetchNodes();
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

function updateServerForm() {
    var sel = (document.getElementById('new-server-type') || {}).value;
    var pveFields = document.getElementById('pve-fields');
    var wsClusterField = document.getElementById('ws-cluster-field');
    var wsHint = document.getElementById('wolfstack-hint');
    var portLabel = document.getElementById('new-server-port-label');
    var portInput = document.getElementById('new-server-port');

    if (sel === 'proxmox') {
        if (pveFields) pveFields.style.display = 'block';
        if (wsClusterField) wsClusterField.style.display = 'none';
        if (wsHint) wsHint.style.display = 'none';
        if (portLabel) portLabel.textContent = 'Port (default: 8006)';
        if (portInput) portInput.value = '8006';
        var joinField = document.getElementById('ws-join-token-field');
        var ownTokenDisplay = document.getElementById('ws-own-token-display');
        if (joinField) joinField.style.display = 'none';
        if (ownTokenDisplay) ownTokenDisplay.style.display = 'none';
    } else {
        if (pveFields) pveFields.style.display = 'none';
        if (wsClusterField) wsClusterField.style.display = 'block';
        if (wsHint) wsHint.style.display = 'block';
        if (portLabel) portLabel.textContent = 'Port (default: 8553)';
        if (portInput) portInput.value = '8553';
        var joinField = document.getElementById('ws-join-token-field');
        var ownTokenDisplay = document.getElementById('ws-own-token-display');
        if (joinField) joinField.style.display = 'block';
        if (ownTokenDisplay) ownTokenDisplay.style.display = 'block';
    }
}

async function fetchOwnJoinToken() {
    try {
        var resp = await fetch('/api/auth/join-token');
        var data = await resp.json();
        var el = document.getElementById('own-join-token');
        if (el && data.join_token) el.textContent = data.join_token;
    } catch (e) { /* ignore */ }
}

function copyOwnJoinToken() {
    var el = document.getElementById('own-join-token');
    if (el && el.textContent && el.textContent !== 'Loading...') {
        navigator.clipboard.writeText(el.textContent);
        showToast('Join token copied to clipboard', 'success');
    }
}

// ─── Proxmox Resource Management ───
async function loadPveResources(nodeId) {
    try {
        var resp = await fetch('/api/nodes/' + nodeId + '/pve/resources');
        var data = await resp.json();
        if (data.error) { showToast(data.error, 'error'); return []; }
        return data;
    } catch (e) {
        showToast('Failed to load PVE resources: ' + e.message, 'error');
        return [];
    }
}

async function renderPveResourcesView(nodeId) {
    const container = document.getElementById('pve-resources-content');
    if (!container) return;
    container.innerHTML = '<div style="text-align:center; padding:40px; color:var(--text-muted);">Loading PVE resources...</div>';

    // Find the node to get address for console links
    const node = allNodes.find(n => n.id === nodeId);
    const pveHost = node ? node.address : '';
    const pvePort = node ? node.port : 8006;

    const guests = await loadPveResources(nodeId);
    if (!guests || guests.length === 0) {
        container.innerHTML = `<div class="card"><div class="card-body" style="text-align:center; padding:60px;">
            <div style="font-size:48px;margin-bottom:16px;">📭</div>
            <div style="color:var(--text-muted);font-size:14px;">No VMs or containers found on this Proxmox node.</div>
        </div></div>`;
        return;
    }

    const vms = guests.filter(g => g.guest_type === 'qemu');
    const cts = guests.filter(g => g.guest_type === 'lxc');

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + ' ' + units[i];
    }

    function formatUptime(seconds) {
        if (!seconds || seconds === 0) return '—';
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        if (d > 0) return d + 'd ' + h + 'h';
        if (h > 0) return h + 'h ' + m + 'm';
        return m + 'm';
    }

    function progressBar(used, total) {
        const pct = total > 0 ? Math.round((used / total) * 100) : 0;
        const color = pct > 90 ? 'var(--danger)' : pct > 70 ? 'var(--warning)' : 'var(--accent)';
        return `<div style="display:flex;align-items:center;gap:6px;">
            <div style="flex:1;height:6px;background:var(--bg-tertiary);border-radius:3px;overflow:hidden;min-width:50px;">
                <div style="height:100%;width:${pct}%;background:${color};border-radius:3px;transition:width 0.3s;"></div>
            </div>
            <span style="font-size:11px;color:var(--text-muted);min-width:32px;text-align:right;">${pct}%</span>
        </div>`;
    }

    function statusBadge(status) {
        const colors = {
            running: { bg: 'rgba(34,197,94,0.15)', color: 'var(--success)', dot: '●' },
            stopped: { bg: 'rgba(156,163,175,0.15)', color: 'var(--text-muted)', dot: '○' },
            paused: { bg: 'rgba(234,179,8,0.15)', color: 'var(--warning)', dot: '⏸' },
        };
        const s = colors[status] || colors.stopped;
        return `<span style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;background:${s.bg};color:${s.color};text-transform:capitalize;">${s.dot} ${status}</span>`;
    }

    function consoleLink(g) {
        if (g.status !== 'running') return '';
        return `<button class="btn btn-sm" onclick="openPveConsole('${nodeId}', ${g.vmid}, '${g.name || 'VMID ' + g.vmid}')" style="font-size:11px;padding:3px 10px;">🖥 Console</button>`;
    }

    function guestCard(g) {
        const typeIcon = g.guest_type === 'qemu' ? '🖥️' : '📦';
        const typeLabel = g.guest_type === 'qemu' ? 'VM' : 'CT';
        const isRunning = g.status === 'running';
        const isPaused = g.status === 'paused';

        let actionBtns = '';
        if (isRunning) {
            actionBtns = `
                <button class="btn btn-sm" onclick="pveGuestAction('${nodeId}', ${g.vmid}, 'reboot')" title="Reboot" style="font-size:11px;padding:3px 10px;">🔄 Restart</button>
                <button class="btn btn-sm" onclick="pveGuestAction('${nodeId}', ${g.vmid}, 'shutdown')" title="Graceful shutdown" style="font-size:11px;padding:3px 10px;">⏹ Shutdown</button>
                <button class="btn btn-sm" onclick="pveGuestAction('${nodeId}', ${g.vmid}, 'stop')" title="Force stop" style="font-size:11px;padding:3px 10px;">⛔ Stop</button>
                ${g.guest_type === 'qemu' ? `<button class="btn btn-sm" onclick="pveGuestAction('${nodeId}', ${g.vmid}, 'suspend')" title="Suspend" style="font-size:11px;padding:3px 10px;">⏸ Suspend</button>` : ''}
                ${consoleLink(g)}`;
        } else if (isPaused) {
            actionBtns = `
                <button class="btn btn-sm btn-primary" onclick="pveGuestAction('${nodeId}', ${g.vmid}, 'resume')" style="font-size:11px;padding:3px 10px;">▶ Resume</button>
                <button class="btn btn-sm" onclick="pveGuestAction('${nodeId}', ${g.vmid}, 'stop')" title="Force stop" style="font-size:11px;padding:3px 10px;">⛔ Stop</button>`;
        } else {
            actionBtns = `<button class="btn btn-sm btn-primary" onclick="pveGuestAction('${nodeId}', ${g.vmid}, 'start')" style="font-size:11px;padding:3px 10px;">▶ Start</button>`;
        }

        return `<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:10px;padding:16px;display:flex;flex-direction:column;gap:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="font-size:20px;">${typeIcon}</span>
                    <div>
                        <div style="font-weight:600;font-size:14px;">${g.name || (typeLabel + ' ' + g.vmid)}</div>
                        <div style="font-size:11px;color:var(--text-muted);">${typeLabel} ${g.vmid}${g.name ? ' · ' + g.node : ' · ' + g.node}</div>
                    </div>
                </div>
                ${statusBadge(g.status)}
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(120px, 1fr));gap:12px;">
                <div>
                    <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">CPU</div>
                    <div style="font-size:13px;font-weight:500;">${g.cpus} vCPU${g.cpus > 1 ? 's' : ''}</div>
                </div>
                <div>
                    <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">Memory</div>
                    ${progressBar(g.mem, g.maxmem)}
                    <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${formatBytes(g.mem)} / ${formatBytes(g.maxmem)}</div>
                </div>
                <div>
                    <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">Uptime</div>
                    <div style="font-size:13px;font-weight:500;">${formatUptime(g.uptime)}</div>
                </div>
            </div>
            ${g.maxdisk > 0 ? (() => {
                const diskPct = Math.round((g.disk / g.maxdisk) * 100);
                const diskBarColor = diskPct > 90 ? '#ef4444' : diskPct > 70 ? '#f59e0b' : '#10b981';
                return `<div style="display:flex;align-items:center;gap:8px;font-size:11px;padding:8px 0 0;border-top:1px solid var(--border);margin-top:4px;">
                    <span>💾</span>
                    <div style="flex:1;max-width:220px;height:8px;background:var(--bg-tertiary,#333);border-radius:4px;overflow:hidden;">
                        <div style="width:${diskPct}%;height:100%;background:${diskBarColor};border-radius:4px;transition:width 0.3s;"></div>
                    </div>
                    <span style="min-width:110px;">${formatBytes(g.disk)} / ${formatBytes(g.maxdisk)} (${diskPct}%)</span>
                </div>`;
            })() : ''}
            <div style="display:flex;gap:6px;flex-wrap:wrap;border-top:1px solid var(--border);padding-top:10px;">
                ${actionBtns}
            </div>
        </div>`;
    }

    function buildSection(items, title, icon) {
        const running = items.filter(g => g.status === 'running').length;
        const stopped = items.length - running;
        return `<div class="card" style="margin-bottom:16px;">
            <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">
                <h3>${icon} ${title} (${items.length})</h3>
                <div style="font-size:12px;color:var(--text-muted);">
                    <span style="color:var(--success);">● ${running} running</span>
                    ${stopped > 0 ? `<span style="margin-left:12px;color:var(--text-muted);">○ ${stopped} stopped</span>` : ''}
                </div>
            </div>
            <div class="card-body">
                <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(320px, 1fr));gap:12px;">
                    ${items.map(guestCard).join('')}
                </div>
            </div>
        </div>`;
    }

    let html = '';
    if (vms.length > 0) html += buildSection(vms, 'Virtual Machines', '🖥️');
    if (cts.length > 0) html += buildSection(cts, 'LXC Containers', '📦');

    container.innerHTML = html;
}

async function pveGuestAction(nodeId, vmid, action) {
    try {
        var resp = await fetch('/api/nodes/' + nodeId + '/pve/' + vmid + '/' + action, { method: 'POST' });
        var data = await resp.json();
        if (data.error) {
            showToast('PVE action failed: ' + data.error, 'error');
        } else {
            showToast('VMID ' + vmid + ': ' + action + ' sent', 'success');
        }
    } catch (e) {
        showToast('PVE action failed: ' + e.message, 'error');
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

async function confirmRemovePveCluster(clusterName, nodeIds) {
    if (!confirm(`Remove Proxmox cluster "${clusterName}" and all ${nodeIds.length} node(s)?`)) return;
    for (const id of nodeIds) {
        try {
            await fetch(`/api/nodes/${id}`, { method: 'DELETE' });
        } catch (e) { /* continue */ }
    }
    showToast(`Proxmox cluster "${clusterName}" removed`, 'success');
    fetchNodes();
}

function openPveClusterSettings(clusterName) {
    // Find all PVE nodes in this cluster
    const clusterNodes = allNodes.filter(n => n.node_type === 'proxmox' && (n.cluster_name || n.pve_cluster_name || n.address) === clusterName);
    if (clusterNodes.length === 0) return;

    const first = clusterNodes[0];
    const nodeNames = clusterNodes.map(n => n.pve_node_name || n.hostname).join(', ');

    // Build a settings modal dynamically
    let existing = document.getElementById('pve-settings-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'pve-settings-modal';
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <h3>⚙️ ${clusterName} — Cluster Settings</h3>
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
            </div>
            <div class="modal-body">
                <p style="color: var(--text-muted); margin-bottom:16px;">
                    <strong>Nodes:</strong> ${nodeNames}<br>
                    <strong>Address:</strong> ${first.address}:${first.port}
                </p>
                <div class="form-group">
                    <label>Cluster Name</label>
                    <input type="text" class="form-control" id="pve-settings-cluster-name" value="${clusterName}">
                </div>
                <div class="form-group">
                    <label>Token ID</label>
                    <input type="text" class="form-control" id="pve-settings-token-id"
                        placeholder="root@pam!wolfstack" value="${first.pve_token ? first.pve_token.split('=')[0] + '!' + first.pve_token.split('!')[1]?.split('=')[0] : ''}">
                    <small style="color: var(--text-muted);">Leave blank to keep current</small>
                </div>
                <div class="form-group">
                    <label>Token Secret</label>
                    <input type="text" class="form-control" id="pve-settings-token-secret" placeholder="Leave blank to keep current">
                </div>
                <div class="form-group">
                    <label>TLS Fingerprint</label>
                    <input type="text" class="form-control" id="pve-settings-fingerprint" value="${first.pve_fingerprint || ''}">
                </div>

                <div style="margin-top:16px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                        <h4 style="margin:0;font-size:13px;">🌐 WolfNet Cluster Status</h4>
                        <button class="btn btn-sm" onclick="checkClusterWolfnetStatus()" style="font-size:11px;padding:4px 10px;">🔍 Check Status</button>
                    </div>
                    <div id="pve-wolfnet-status" style="font-size:12px;color:var(--text-muted);">
                        ${clusterNodes.map(n => `
                            <div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);" data-wolfnet-node="${n.id}">
                                <span style="font-size:14px;">❓</span>
                                <strong>${n.pve_node_name || n.hostname}</strong>
                                <span style="font-family:monospace;color:var(--text-muted);">${n.address}</span>
                                <span class="wolfnet-badge" style="margin-left:auto;padding:2px 8px;border-radius:4px;font-size:11px;background:var(--bg-secondary);color:var(--text-muted);">Unknown</span>
                            </div>
                        `).join('')}
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:8px;">
                        WolfNet connects your cluster nodes over a secure overlay network. Nodes need WolfNet installed and peered to communicate.
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                <button class="btn btn-primary" onclick="savePveClusterSettings()">Save Changes</button>
            </div>
        </div>`;
    // Store node IDs on the modal so save doesn't need to re-query by name
    modal._nodeIds = clusterNodes.map(n => n.id);
    modal._originalName = clusterName;
    document.body.appendChild(modal);
}

async function savePveClusterSettings() {
    const modal = document.getElementById('pve-settings-modal');
    if (!modal) return;
    const nodeIds = modal._nodeIds || [];
    const originalClusterName = modal._originalName || '';
    const newName = document.getElementById('pve-settings-cluster-name')?.value.trim();
    const tokenId = document.getElementById('pve-settings-token-id')?.value.trim();
    const tokenSecret = document.getElementById('pve-settings-token-secret')?.value.trim();
    const fingerprint = document.getElementById('pve-settings-fingerprint')?.value.trim();

    // Build update payload
    const updates = {};
    if (newName && newName !== originalClusterName) updates.cluster_name = newName;
    if (tokenId && tokenSecret) updates.pve_token = tokenId + '=' + tokenSecret;
    if (fingerprint !== undefined) updates.pve_fingerprint = fingerprint || null;

    if (Object.keys(updates).length === 0) {
        showToast('No changes to save', 'info');
        return;
    }

    // Update each node by stored ID
    for (const id of nodeIds) {
        try {
            await fetch(`/api/nodes/${id}/settings`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updates)
            });
        } catch (e) { /* continue */ }
    }

    modal.remove();
    showToast('Cluster settings updated', 'success');
    fetchNodes();
}

async function checkClusterWolfnetStatus() {
    const modal = document.getElementById('pve-settings-modal');
    if (!modal) return;
    const nodeRows = modal.querySelectorAll('[data-wolfnet-node]');

    for (const row of nodeRows) {
        const nodeId = row.getAttribute('data-wolfnet-node');
        const node = allNodes.find(n => n.id === nodeId);
        if (!node) continue;

        const icon = row.querySelector('span:first-child');
        const badge = row.querySelector('.wolfnet-badge');

        // Show loading
        icon.textContent = '⏳';
        badge.textContent = 'Checking...';
        badge.style.background = 'var(--bg-secondary)';
        badge.style.color = 'var(--text-muted)';

        try {
            // Use the node's API to check network interfaces
            const baseUrl = node.is_self ? '' : `http://${node.address}:${node.port}`;
            const resp = await fetch(`${baseUrl}/api/networking/interfaces`, {
                signal: AbortSignal.timeout(5000)
            });
            if (resp.ok) {
                const ifaces = await resp.json();
                const wolfnet = (Array.isArray(ifaces) ? ifaces : []).find(i =>
                    i.name === 'wolfnet0' || (i.name && i.name.startsWith('wolfnet'))
                );
                if (wolfnet) {
                    icon.textContent = '✅';
                    badge.textContent = 'Connected';
                    badge.style.background = '#10b98122';
                    badge.style.color = '#10b981';
                } else {
                    icon.textContent = '❌';
                    badge.textContent = 'Not Installed';
                    badge.style.background = '#ef444422';
                    badge.style.color = '#ef4444';
                }
            } else {
                icon.textContent = '⚠️';
                badge.textContent = 'Unreachable';
                badge.style.background = '#f59e0b22';
                badge.style.color = '#f59e0b';
            }
        } catch (e) {
            icon.textContent = '⚠️';
            badge.textContent = 'Offline';
            badge.style.background = '#f59e0b22';
            badge.style.color = '#f59e0b';
        }
    }
}

// ─── WolfStack Cluster Settings ───
function openWsClusterSettings(clusterName) {
    const clusterNodes = allNodes.filter(n => n.node_type !== 'proxmox' && (n.cluster_name || 'WolfStack') === clusterName);
    if (clusterNodes.length === 0) return;

    const nodeNames = clusterNodes.map(n => n.hostname).join(', ');

    let existing = document.getElementById('ws-settings-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'ws-settings-modal';
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <h3>⚙️ ${clusterName} — Cluster Settings</h3>
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
            </div>
            <div class="modal-body">
                <p style="color: var(--text-muted); margin-bottom:16px;">
                    <strong>Nodes:</strong> ${nodeNames}
                </p>
                <div class="form-group">
                    <label>Cluster Name</label>
                    <input type="text" class="form-control" id="ws-settings-cluster-name" value="${clusterName}">
                </div>
                <hr style="border-color: var(--border); margin: 20px 0;">
                <div class="form-group">
                    <label>🔗 WolfNet Mesh Connectivity</label>
                    <p style="color: var(--text-muted); font-size: 12px; margin: 4px 0 12px;">
                        Ensures all nodes in this cluster know about each other's WolfNet connections.<br>
                        Run this after adding new nodes to automatically set up peer-to-peer networking.
                    </p>
                    <button class="btn" id="ws-wolfnet-sync-btn" style="background: var(--accent); color: #fff; font-size: 13px;" onclick="syncWolfNetCluster()">
                        🔗 Update WolfNet Connections
                    </button>
                    <span id="ws-wolfnet-sync-status" style="margin-left: 10px; font-size: 12px; color: var(--text-muted);"></span>
                </div>
                <hr style="border-color: var(--border); margin: 20px 0;">
                <div class="form-group">
                    <label>🔍 Cluster Check</label>
                    <p style="color: var(--text-muted); font-size: 12px; margin: 4px 0 12px;">
                        Diagnose connectivity to all nodes — checks WolfStack API reachability and WolfNet tunnel status.
                    </p>
                    <button class="btn" id="ws-diagnose-btn" style="background: var(--accent); color: #fff; font-size: 13px;" onclick="runClusterDiagnostics()">
                        🔍 Run Diagnostics
                    </button>
                    <div id="ws-diagnose-results" style="margin-top: 12px;"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                <button class="btn btn-primary" onclick="saveWsClusterSettings()">Save Changes</button>
            </div>
        </div>`;
    modal._nodeIds = clusterNodes.map(n => n.id);
    modal._originalName = clusterName;
    document.body.appendChild(modal);
}

async function saveWsClusterSettings() {
    const modal = document.getElementById('ws-settings-modal');
    if (!modal) return;
    const nodeIds = modal._nodeIds || [];
    const originalName = modal._originalName || '';
    const newName = document.getElementById('ws-settings-cluster-name')?.value.trim();

    if (!newName || newName === originalName) {
        modal.remove();
        return;
    }

    for (const id of nodeIds) {
        try {
            await fetch(`/api/nodes/${id}/settings`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cluster_name: newName })
            });
        } catch (e) { /* continue */ }
    }

    modal.remove();
    showToast('Cluster renamed to "' + newName + '"', 'success');
    fetchNodes();
}

async function syncWolfNetCluster() {
    const modal = document.getElementById('ws-settings-modal');
    if (!modal) return;
    const nodeIds = modal._nodeIds || [];
    if (nodeIds.length < 2) {
        showToast('Need at least 2 nodes in the cluster to sync WolfNet', 'error');
        return;
    }

    const btn = document.getElementById('ws-wolfnet-sync-btn');
    const status = document.getElementById('ws-wolfnet-sync-status');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Syncing...'; }
    if (status) status.textContent = 'Connecting to nodes...';

    try {
        const resp = await fetch('/api/cluster/wolfnet-sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ node_ids: nodeIds })
        });
        const data = await resp.json();

        if (data.error) {
            showToast('WolfNet sync failed: ' + data.error, 'error');
            if (status) status.textContent = '❌ ' + data.error;
        } else if (data.status === 'error') {
            showToast('WolfNet sync: ' + data.message, 'error');
            if (status) status.textContent = '❌ ' + data.message;
        } else {
            let msg = `✅ ${data.nodes_reached} nodes reached`;
            if (data.synced > 0) msg += `, ${data.synced} new peer(s) added`;
            if (data.skipped > 0) msg += `, ${data.skipped} already connected`;
            showToast(msg, 'success');
            if (status) status.textContent = msg;
            if (data.errors && data.errors.length > 0) {
                showToast('Some issues: ' + data.errors.join('; '), 'warning');
            }
        }
    } catch (e) {
        showToast('WolfNet sync error: ' + e.message, 'error');
        if (status) status.textContent = '❌ ' + e.message;
    }

    if (btn) { btn.disabled = false; btn.textContent = '🔗 Update WolfNet Connections'; }
}

async function runClusterDiagnostics() {
    const modal = document.getElementById('ws-settings-modal');
    if (!modal) return;
    const nodeIds = modal._nodeIds || [];
    if (nodeIds.length === 0) return;

    const btn = document.getElementById('ws-diagnose-btn');
    const resultsDiv = document.getElementById('ws-diagnose-results');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Checking...'; }
    if (resultsDiv) resultsDiv.innerHTML = '<span style="color:var(--text-muted);font-size:12px;">Polling nodes...</span>';

    try {
        const resp = await fetch('/api/cluster/diagnose', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ node_ids: nodeIds })
        });
        const data = await resp.json();

        if (data.error) {
            if (resultsDiv) resultsDiv.innerHTML = `<span style="color:var(--danger);font-size:12px;">❌ ${data.error}</span>`;
            if (btn) { btn.disabled = false; btn.textContent = '🔍 Run Diagnostics'; }
            return;
        }

        // Count results
        const results = data.results || [];
        const okCount = results.filter(r => r.is_self || (r.wolfstack_api && r.wolfstack_api.reachable)).length;
        const failCount = results.length - okCount;

        // Show summary in the settings modal
        if (resultsDiv) {
            resultsDiv.innerHTML = failCount === 0
                ? `<span style="color:#10b981;font-size:12px;">✅ All ${okCount} nodes reachable</span>`
                : `<span style="color:#ef4444;font-size:12px;">❌ ${failCount} node(s) unreachable, ${okCount} OK</span>`;
        }

        // Open results in a new popup
        showDiagnosticsPopup(results);

    } catch (e) {
        if (resultsDiv) resultsDiv.innerHTML = `<span style="color:var(--danger);font-size:12px;">❌ ${e.message}</span>`;
    }

    if (btn) { btn.disabled = false; btn.textContent = '🔍 Run Diagnostics'; }
}

function showDiagnosticsPopup(results) {
    let existing = document.getElementById('diagnostics-popup');
    if (existing) existing.remove();

    let html = `<div style="border:1px solid var(--border); border-radius:8px; overflow:hidden; font-size:13px;">
        <table style="width:100%; border-collapse:collapse;">
            <thead>
                <tr style="background:var(--bg-tertiary); text-align:left;">
                    <th style="padding:10px 12px;">Node</th>
                    <th style="padding:10px 8px;">Address</th>
                    <th style="padding:10px 8px;">API Status</th>
                    <th style="padding:10px 8px;">WolfNet</th>
                    <th style="padding:10px 8px;">Latency</th>
                    <th style="padding:10px 8px;">Last Seen</th>
                </tr>
            </thead>
            <tbody>`;

    for (const r of results) {
        const api = r.wolfstack_api || {};
        const wn = r.wolfnet || {};
        const apiOk = api.reachable;
        const wnOk = wn.reachable;
        const isSelf = r.is_self;

        // API status
        let apiCell;
        if (isSelf) {
            apiCell = '<span style="color:#10b981;">✅ Self</span>';
        } else if (apiOk) {
            apiCell = `<span style="color:#10b981;">✅ OK</span> <span style="opacity:0.5;font-size:11px;">(${api.status_code})</span>`;
        } else {
            const statusBadge = api.status_code ? ` <span style="opacity:0.7;">(${api.status_code})</span>` : '';
            apiCell = `<span style="color:#ef4444;">❌ Fail${statusBadge}</span>`;
        }

        // WolfNet status
        let wnCell;
        if (isSelf) {
            wnCell = '<span style="color:#10b981;">✅ Self</span>';
        } else if (wn.ip === null) {
            wnCell = '<span style="color:#f59e0b;" title="No WolfNet peer configured for this node">⚠️ No peer</span>';
        } else if (wnOk) {
            wnCell = `<span style="color:#10b981;">✅ ${wn.ip}</span>`;
        } else {
            wnCell = `<span style="color:#ef4444;">❌ ${wn.ip}</span>`;
        }

        // Latency
        let latency = '—';
        if (isSelf) latency = '<1ms';
        else if (apiOk && api.latency_ms != null) latency = `${api.latency_ms}ms`;
        else if (wn.latency_ms) latency = `${wn.latency_ms}ms <span style="opacity:0.5;">(wn)</span>`;

        // Last seen
        let lastSeen = '—';
        if (isSelf) {
            lastSeen = '<span style="color:#10b981;">now</span>';
        } else if (r.last_seen_ago_secs != null) {
            const secs = r.last_seen_ago_secs;
            if (secs < 60) lastSeen = `${secs}s ago`;
            else if (secs < 3600) lastSeen = `${Math.floor(secs / 60)}m ago`;
            else if (secs < 86400) lastSeen = `${Math.floor(secs / 3600)}h ago`;
            else lastSeen = `${Math.floor(secs / 86400)}d ago`;

            if (secs > 120 && !apiOk) lastSeen = `<span style="color:#ef4444;">${lastSeen}</span>`;
            else if (secs > 60) lastSeen = `<span style="color:#f59e0b;">${lastSeen}</span>`;
        }

        const rowBg = (!apiOk && !isSelf) ? 'background:rgba(239,68,68,0.05);' : '';

        html += `<tr style="border-top:1px solid var(--border);${rowBg}">
            <td style="padding:8px 12px;font-weight:600;">${r.hostname}${isSelf ? ' <span style="color:var(--accent-light);font-size:10px;">(this)</span>' : ''}</td>
            <td style="padding:8px;font-family:monospace;font-size:11px;color:var(--text-muted);">${r.address}:${r.port}</td>
            <td style="padding:8px;">${apiCell}</td>
            <td style="padding:8px;">${wnCell}</td>
            <td style="padding:8px;font-family:monospace;">${latency}</td>
            <td style="padding:8px;">${lastSeen}</td>
        </tr>`;

        if (!apiOk && !isSelf && api.error) {
            html += `<tr style="border-top:none;${rowBg}">
                <td colspan="6" style="padding:2px 12px 10px;font-size:11px;color:var(--text-muted);font-family:monospace;word-break:break-all;">
                    ↳ <strong>URL:</strong> ${api.url_used || 'N/A'}<br>
                    ↳ <strong>Error:</strong> ${api.error}
                </td>
            </tr>`;
        }
    }

    html += '</tbody></table></div>';

    const popup = document.createElement('div');
    popup.id = 'diagnostics-popup';
    popup.className = 'modal-overlay active';
    popup.style.zIndex = '10001';
    popup.innerHTML = `
        <div class="modal" style="max-width:900px;width:95%;">
            <div class="modal-header">
                <h3>🔍 Cluster Diagnostics</h3>
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
            </div>
            <div class="modal-body" style="padding:16px;max-height:70vh;overflow-y:auto;">
                ${html}
            </div>
            <div class="modal-footer" style="justify-content:space-between;">
                <span style="font-size:11px;color:var(--text-muted);">Checked ${results.length} nodes at ${new Date().toLocaleTimeString()}</span>
                <button class="btn" onclick="this.closest('.modal-overlay').remove()">Close</button>
            </div>
        </div>`;
    document.body.appendChild(popup);
}

// ─── Individual Node Settings ───
function openNodeSettings(nodeId) {
    const node = allNodes.find(n => n.id === nodeId);
    if (!node) return;

    let existing = document.getElementById('node-settings-modal');
    if (existing) existing.remove();

    const clusterName = node.cluster_name || 'WolfStack';
    const isPve = node.node_type === 'proxmox';
    const isSelf = node.is_self;

    const modal = document.createElement('div');
    modal.id = 'node-settings-modal';
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <h3>⚙️ ${node.hostname} — Node Settings</h3>
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
            </div>
            <div class="modal-body">
                <div style="display:grid; grid-template-columns:auto 1fr; gap:8px 16px; margin-bottom:16px; font-size:13px; align-items:center;">
                    <span style="color:var(--text-muted);">Hostname</span>
                    ${isSelf
            ? `<span>${node.hostname} <span style="color:var(--accent-light);font-size:11px;">(this server)</span></span>`
            : `<input type="text" class="form-control" id="node-settings-hostname" value="${node.hostname}" style="font-size:13px;padding:4px 8px;">`}
                    <span style="color:var(--text-muted);">Address</span>
                    ${isSelf
            ? `<span style="font-family:'JetBrains Mono',monospace;font-size:12px;">${node.address}</span>`
            : `<input type="text" class="form-control" id="node-settings-address" value="${node.address}" style="font-family:'JetBrains Mono',monospace;font-size:12px;padding:4px 8px;">`}
                    <span style="color:var(--text-muted);">Port</span>
                    ${isSelf
            ? `<span style="font-family:'JetBrains Mono',monospace;font-size:12px;">${node.port}</span>`
            : `<input type="number" class="form-control" id="node-settings-port" value="${node.port}" style="font-family:'JetBrains Mono',monospace;font-size:12px;padding:4px 8px;width:100px;">`}
                    <span style="color:var(--text-muted);">Node ID</span>
                    <span style="font-family:'JetBrains Mono',monospace;font-size:12px;">${node.id}</span>
                    <span style="color:var(--text-muted);">Type</span>
                    <span>${isPve ? '🖥️ Proxmox VE' : '☁️ WolfStack'}</span>
                    <span style="color:var(--text-muted);">Status</span>
                    <span>${node.online ? '<span style="color:var(--success);">● Online</span>' : '<span style="color:var(--danger);">● Offline</span>'}</span>
                </div>

                <div id="node-version-section" style="background:var(--bg-secondary,#161622);border:1px solid var(--border,#333);border-radius:8px;padding:14px 16px;margin-bottom:16px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                        <span style="font-weight:600;font-size:13px;color:var(--text,#fff);">📦 WolfStack Version</span>
                        <span id="node-version-badge" style="font-size:11px;padding:2px 8px;border-radius:4px;background:var(--bg-primary,#111);color:var(--text-muted,#888);">checking...</span>
                    </div>
                    <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12px;margin-top:8px;">
                        <span style="color:var(--text-muted);">Installed:</span>
                        <span id="node-version-installed" style="font-family:'JetBrains Mono',monospace;color:var(--text-muted,#888);">—</span>
                        <span style="color:var(--text-muted);">Latest:</span>
                        <span id="node-version-latest" style="font-family:'JetBrains Mono',monospace;color:var(--text-muted,#888);">—</span>
                    </div>
                    <div id="node-upgrade-action" style="display:none;margin-top:12px;"></div>
                </div>

                <hr style="border-color:var(--border);margin:16px 0;">
                <div class="form-group">
                    <label>Cluster Name</label>
                    <input type="text" class="form-control" id="node-settings-cluster-name" value="${clusterName}">
                    <small style="color: var(--text-muted);">Change to move this node to a different cluster group</small>
                </div>
                ${isPve ? `
                <div class="form-group">
                    <label>PVE Token</label>
                    <input type="text" class="form-control" id="node-settings-pve-token" placeholder="Leave blank to keep current"
                        value="">
                    <small style="color: var(--text-muted);">Format: user@realm!tokenid=secret</small>
                </div>
                <div class="form-group">
                    <label>TLS Fingerprint</label>
                    <input type="text" class="form-control" id="node-settings-pve-fingerprint" value="${node.pve_fingerprint || ''}">
                </div>` : ''}

                <div style="background:var(--bg-secondary,#161622);border:1px solid var(--border,#333);border-radius:8px;padding:14px 16px;margin-top:12px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;">
                        <div>
                            <span style="font-weight:600;font-size:13px;color:var(--text,#fff);">🔒 Disable Direct Login</span>
                            <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">Prevent users from logging in directly. The server will still be accessible via the primary dashboard.</div>
                        </div>
                        <label style="position:relative;display:inline-block;width:44px;height:24px;flex-shrink:0;margin-left:16px;">
                            <input type="checkbox" id="node-settings-login-disabled" ${node.login_disabled ? 'checked' : ''}
                                style="opacity:0;width:0;height:0;position:absolute;">
                            <span onclick="this.previousElementSibling.checked=!this.previousElementSibling.checked" style="position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:${node.login_disabled ? 'var(--accent,#6366f1)' : 'var(--bg-input,#1e1e2e)'};transition:.3s;border-radius:24px;border:1px solid var(--border,#333);"></span>
                            <span onclick="this.previousElementSibling.previousElementSibling.checked=!this.previousElementSibling.previousElementSibling.checked" style="position:absolute;content:'';height:18px;width:18px;left:${node.login_disabled ? '22px' : '3px'};bottom:3px;background:white;transition:.3s;border-radius:50%;pointer-events:none;"></span>
                        </label>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                <button class="btn btn-primary" onclick="saveNodeSettings()">Save Changes</button>
            </div>
        </div>`;
    modal._nodeId = nodeId;
    modal._originalClusterName = clusterName;
    modal._originalHostname = node.hostname;
    modal._originalAddress = node.address;
    modal._originalPort = node.port;
    document.body.appendChild(modal);

    // Fetch version info asynchronously
    loadNodeVersionInfo(node);
}

async function loadNodeVersionInfo(node) {
    const installedEl = document.getElementById('node-version-installed');
    const latestEl = document.getElementById('node-version-latest');
    const badgeEl = document.getElementById('node-version-badge');
    const actionEl = document.getElementById('node-upgrade-action');
    if (!installedEl) return;

    let installedVersion = '';
    let latestVersion = '';

    // 1. Get installed version from the node
    try {
        if (node.is_self) {
            // Local: read from the version element on the page
            const vEl = document.querySelector('.version');
            if (vEl) installedVersion = vEl.textContent.replace(/^v/i, '').trim();
        } else {
            // Remote: fetch /api/nodes through the proxy to get the remote server's version
            const resp = await fetch(`/api/nodes/${node.id}/proxy/nodes`);
            if (resp.ok) {
                const data = await resp.json();
                installedVersion = data.version || '';
            }
        }
    } catch (e) { }

    if (installedVersion) {
        installedEl.textContent = 'v' + installedVersion;
        installedEl.style.color = 'var(--text,#fff)';
    } else {
        installedEl.textContent = 'unknown';
        installedEl.style.color = '#ef4444';
    }

    // 2. Get latest version from GitHub
    try {
        const resp = await fetch('https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/Cargo.toml');
        const text = await resp.text();
        const match = text.match(/^version\s*=\s*"([^"]+)"/m);
        if (match) latestVersion = match[1];
    } catch (e) { }

    if (latestVersion) {
        latestEl.textContent = 'v' + latestVersion;
        latestEl.style.color = 'var(--text,#fff)';
    } else {
        latestEl.textContent = 'unable to check';
        latestEl.style.color = 'var(--text-muted,#888)';
    }

    // 3. Compare and show badge + upgrade button
    if (installedVersion && latestVersion) {
        if (installedVersion === latestVersion || !isNewerVersion(latestVersion, installedVersion)) {
            badgeEl.textContent = '✅ Up to date';
            badgeEl.style.background = 'rgba(16,185,129,0.15)';
            badgeEl.style.color = '#10b981';
        } else {
            badgeEl.textContent = '⬆️ Update available';
            badgeEl.style.background = 'rgba(239,168,68,0.15)';
            badgeEl.style.color = '#f59e0b';

            const targetLabel = node.is_self ? 'this server' : node.hostname;
            actionEl.style.display = 'block';
            actionEl.innerHTML = `
                <div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:8px;padding:10px 12px;margin-bottom:8px;font-size:0.82em;color:#f59e0b;line-height:1.5;">
                    ⚡ <strong>v${latestVersion}</strong> is available (installed: v${installedVersion}).
                    Upgrading will download and install the latest WolfStack binary on <strong>${targetLabel}</strong>.
                    A terminal window will open to show progress.
                </div>
                <button class="btn" style="background:#f59e0b;color:#000;font-weight:600;width:100%;" onclick="upgradeNode('${node.id}')">
                    ⬆️ Upgrade ${targetLabel} to v${latestVersion}
                </button>
            `;
        }
    } else {
        badgeEl.textContent = '❓ Unknown';
        badgeEl.style.color = 'var(--text-muted,#888)';

        // Still offer upgrade button when version can't be determined
        const targetLabel = node.is_self ? 'this server' : node.hostname;
        const versionNote = latestVersion ? `Latest: v${latestVersion}. ` : '';
        actionEl.style.display = 'block';
        actionEl.innerHTML = `
            <div style="background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.2);border-radius:8px;padding:10px 12px;margin-bottom:8px;font-size:0.82em;color:#60a5fa;line-height:1.5;">
                ℹ️ ${versionNote}Could not detect the installed version on <strong>${targetLabel}</strong>.
                You can still run the upgrade script to install or update WolfStack.
            </div>
            <button class="btn" style="background:#3b82f6;color:#fff;font-weight:600;width:100%;" onclick="upgradeNode('${node.id}')">
                ⬆️ Install / Upgrade WolfStack on ${targetLabel}
            </button>
        `;
    }
}

function upgradeNode(nodeId) {
    const node = allNodes.find(n => n.id === nodeId);
    if (!node) return;

    const machine = node.is_self ? 'this machine (local)' : (node.hostname + ' (' + node.address + ')');
    if (!confirm('⚡ Upgrade WolfStack on ' + machine + '?\n\nThis will run the upgrade script. A terminal window will open so you can monitor progress.\n\nThe service will restart after upgrading — refresh your browser when done.\n\nProceed?')) return;

    // Open console popup with type=upgrade
    let url = '/console.html?type=upgrade&name=wolfstack';
    if (!node.is_self) {
        url += '&node_id=' + encodeURIComponent(nodeId);
    }
    window.open(url, 'upgrade_console_' + nodeId, 'width=960,height=600,menubar=no,toolbar=no');

    showToast('Upgrade started — watch the terminal window for progress.', 'info');

    // Close the settings modal
    const modal = document.getElementById('node-settings-modal');
    if (modal) modal.remove();
}

async function saveNodeSettings() {
    const modal = document.getElementById('node-settings-modal');
    if (!modal) return;
    const nodeId = modal._nodeId;
    const originalName = modal._originalClusterName || '';
    const newName = document.getElementById('node-settings-cluster-name')?.value.trim();

    const updates = {};
    if (newName && newName !== originalName) updates.cluster_name = newName;

    // Hostname, address, port (only present for non-self nodes)
    const hostnameEl = document.getElementById('node-settings-hostname');
    const addressEl = document.getElementById('node-settings-address');
    const portEl = document.getElementById('node-settings-port');
    if (hostnameEl) {
        const h = hostnameEl.value.trim();
        if (h && h !== modal._originalHostname) updates.hostname = h;
    }
    if (addressEl) {
        const a = addressEl.value.trim();
        if (a && a !== modal._originalAddress) updates.address = a;
    }
    if (portEl) {
        const p = parseInt(portEl.value, 10);
        if (p && p !== modal._originalPort) updates.port = p;
    }

    // PVE-specific fields
    const pveToken = document.getElementById('node-settings-pve-token')?.value.trim();
    const pveFingerprint = document.getElementById('node-settings-pve-fingerprint')?.value.trim();
    if (pveToken) updates.pve_token = pveToken;
    if (pveFingerprint !== undefined && document.getElementById('node-settings-pve-fingerprint')) {
        updates.pve_fingerprint = pveFingerprint || null;
    }

    // Login disabled toggle
    const loginDisabledEl = document.getElementById('node-settings-login-disabled');
    if (loginDisabledEl) {
        const node = allNodes.find(n => n.id === nodeId);
        const wasDisabled = node ? !!node.login_disabled : false;
        if (loginDisabledEl.checked !== wasDisabled) {
            updates.login_disabled = loginDisabledEl.checked;
        }
    }

    if (Object.keys(updates).length === 0) {
        showToast('No changes to save', 'info');
        return;
    }

    try {
        const resp = await fetch(`/api/nodes/${nodeId}/settings`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updates)
        });
        if (resp.ok) {
            showToast('Node settings updated', 'success');
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(err.error || 'Failed to update settings', 'error');
        }
    } catch (e) {
        showToast('Failed to save: ' + e.message, 'error');
    }

    modal.remove();
    fetchNodes();
}

// ─── Modal Confirm / Prompt Dialogs ───
let _wolfDialogResolve = null;
let _wolfDialogMode = 'confirm'; // 'confirm' or 'prompt'

function wolfConfirm(message, title = 'Confirm', { okText = 'Confirm', cancelText = 'Cancel', danger = false } = {}) {
    return new Promise(resolve => {
        _wolfDialogResolve = resolve;
        _wolfDialogMode = 'confirm';
        document.getElementById('wolf-dialog-title').textContent = title;
        document.getElementById('wolf-dialog-message').textContent = message;
        document.getElementById('wolf-dialog-input-wrap').style.display = 'none';
        const okBtn = document.getElementById('wolf-dialog-ok-btn');
        okBtn.textContent = okText;
        okBtn.className = danger ? 'btn btn-danger' : 'btn btn-primary';
        document.getElementById('wolf-dialog-cancel-btn').textContent = cancelText;
        document.getElementById('wolf-dialog-modal').classList.add('active');
    });
}

function wolfPrompt(message, defaultValue = '', title = 'Input', { okText = 'OK', cancelText = 'Cancel', placeholder = '' } = {}) {
    return new Promise(resolve => {
        _wolfDialogResolve = resolve;
        _wolfDialogMode = 'prompt';
        document.getElementById('wolf-dialog-title').textContent = title;
        document.getElementById('wolf-dialog-message').textContent = message;
        const inputWrap = document.getElementById('wolf-dialog-input-wrap');
        const input = document.getElementById('wolf-dialog-input');
        inputWrap.style.display = 'block';
        input.value = defaultValue;
        input.placeholder = placeholder || '';
        document.getElementById('wolf-dialog-ok-btn').textContent = okText;
        document.getElementById('wolf-dialog-ok-btn').className = 'btn btn-primary';
        document.getElementById('wolf-dialog-cancel-btn').textContent = cancelText;
        document.getElementById('wolf-dialog-modal').classList.add('active');
        setTimeout(() => input.focus(), 100);
    });
}

function wolfDialogOk() {
    document.getElementById('wolf-dialog-modal').classList.remove('active');
    if (_wolfDialogResolve) {
        _wolfDialogResolve(_wolfDialogMode === 'prompt' ? document.getElementById('wolf-dialog-input').value : true);
        _wolfDialogResolve = null;
    }
}

function wolfDialogCancel() {
    document.getElementById('wolf-dialog-modal').classList.remove('active');
    if (_wolfDialogResolve) {
        _wolfDialogResolve(_wolfDialogMode === 'prompt' ? null : false);
        _wolfDialogResolve = null;
    }
}

// Handle Enter/Escape keys for dialog
document.addEventListener('keydown', (e) => {
    if (!_wolfDialogResolve) return;
    if (e.key === 'Enter') { e.preventDefault(); wolfDialogOk(); }
    if (e.key === 'Escape') { e.preventDefault(); wolfDialogCancel(); }
});

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
        showModal('DNS update failed: ' + e.message);
    }
}

function addDnsNameserver() {
    const input = document.getElementById('dns-new-ns');
    const ns = input.value.trim();
    if (!ns) return;
    // Basic IP validation
    if (!/^[\d.:a-fA-F]+$/.test(ns)) { showModal('Invalid IP address'); return; }
    if (currentDns.nameservers.includes(ns)) { showModal('Already exists'); return; }
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
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) { showModal('Invalid domain'); return; }
    if (currentDns.search_domains.includes(domain)) { showModal('Already exists'); return; }
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
        showModal('Error: ' + e.message);
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
    if (!address) { showModal('Please enter an IP address'); return; }

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
        showModal('Error: ' + e.message);
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
        showModal('Error: ' + e.message);
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
    if (!parent || !vlan_id || vlan_id < 1 || vlan_id > 4094) { showModal('Please select a parent and enter a valid VLAN ID (1-4094)'); return; }

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
        showModal('Error: ' + e.message);
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
        showModal('Error: ' + e.message);
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
        showModal('WolfNet error: ' + e.message);
    }
}

// ─── Public IP Mappings ───

function renderIpMappings(mappings) {
    const grid = document.getElementById('ip-mappings-grid');
    const empty = document.getElementById('ip-mappings-empty');
    if (!grid) return;

    if (!mappings || mappings.length === 0) {
        grid.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';

    grid.innerHTML = mappings.map(m => {
        const statusBadge = m.enabled
            ? '<span class="badge" style="background:rgba(34,197,94,0.15); color:#22c55e; font-size:10px;">Active</span>'
            : '<span class="badge" style="background:rgba(107,114,128,0.2); color:#6b7280; font-size:10px;">Disabled</span>';

        const portsLabel = m.ports || '<span style="color:var(--text-muted);">all</span>';
        const protoLabel = m.protocol === 'all' ? 'TCP+UDP' : m.protocol.toUpperCase();
        const label = m.label || '';

        return `<div class="card" style="padding:12px; position:relative;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                <div style="font-size:11px; font-weight:600; color:var(--text-muted);">${label || 'IP Mapping'}</div>
                <div style="display:flex; align-items:center; gap:6px;">
                    ${statusBadge}
                    <button class="btn btn-sm btn-danger" style="font-size:10px; padding:1px 6px;" onclick="removeIpMapping('${m.id}', '${m.public_ip}', '${m.wolfnet_ip}')" title="Remove">🗑️</button>
                </div>
            </div>
            <div style="font-family:var(--font-mono); font-size:13px; font-weight:600; margin-bottom:6px;">
                ${m.public_ip} <span style="color:var(--accent);">→</span> ${m.wolfnet_ip}
            </div>
            <div style="font-size:11px; color:var(--text-muted);">
                Ports: <span style="font-family:var(--font-mono);">${portsLabel}</span> · ${protoLabel}
            </div>
        </div>`;
    }).join('');
}

let _mappingPortData = null; // cached listening + blocked ports

async function showCreateMappingModal() {
    // Reset fields
    document.getElementById('mapping-public-ip').value = '';
    document.getElementById('mapping-wolfnet-ip').value = '';
    document.getElementById('mapping-ports').value = '';
    document.getElementById('mapping-protocol').value = 'all';
    document.getElementById('mapping-label').value = '';

    // Clear any previous warnings
    let warn = document.getElementById('mapping-port-warnings');
    if (warn) warn.innerHTML = '';

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

    // Fetch listening/blocked ports for validation
    try {
        const resp = await fetch(apiUrl('/api/networking/listening-ports'));
        if (resp.ok) _mappingPortData = await resp.json();
    } catch (e) {
        console.error('Failed to fetch listening ports:', e);
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

// Known blocked ports (mirrors backend BLOCKED_PORTS)
const MAPPING_BLOCKED_PORTS = {
    22: 'SSH', 111: 'NFS portmapper', 2049: 'NFS', 3128: 'Proxmox CONNECT proxy',
    5900: 'Proxmox VNC', 5901: 'Proxmox VNC', 5902: 'Proxmox VNC', 5903: 'Proxmox VNC',
    5999: 'Proxmox SPICE', 8006: 'Proxmox Web UI', 8007: 'Proxmox Spiceproxy',
    8443: 'Proxmox API', 8552: 'WolfStack API', 8553: 'WolfStack cluster', 9600: 'WolfNet',
};

/** Parse port string → array of port numbers, or null on error */
function parseMappingPorts(str) {
    const ports = [];
    for (const part of str.split(',')) {
        const s = part.trim();
        if (!s) continue;
        if (s.includes(':')) {
            const [lo, hi] = s.split(':').map(x => parseInt(x.trim(), 10));
            if (isNaN(lo) || isNaN(hi) || lo < 1 || hi > 65535 || lo > hi) return null;
            if (hi - lo > 1000) return null;
            for (let p = lo; p <= hi; p++) ports.push(p);
        } else {
            const p = parseInt(s, 10);
            if (isNaN(p) || p < 1 || p > 65535) return null;
            ports.push(p);
        }
    }
    return ports;
}

/** Live-check ports as user types and show warnings */
function onMappingPortsInput() {
    const warnDiv = document.getElementById('mapping-port-warnings');
    if (!warnDiv) return;
    const portStr = document.getElementById('mapping-ports').value.trim();
    if (!portStr) { warnDiv.innerHTML = ''; return; }

    // Auto-switch protocol from 'all' to 'tcp' when ports are entered
    const protoEl = document.getElementById('mapping-protocol');
    if (protoEl.value === 'all') protoEl.value = 'tcp';

    const ports = parseMappingPorts(portStr);
    if (!ports) {
        warnDiv.innerHTML = '<div style="color:#ef4444;font-size:12px;margin-top:6px;">⚠️ Invalid port format. Use: 80 or 80,443 or 8000:8100</div>';
        return;
    }

    const warnings = [];
    // Check blocked
    for (const p of ports) {
        if (MAPPING_BLOCKED_PORTS[p]) {
            warnings.push(`🚫 Port <strong>${p}</strong> is used by <strong>${MAPPING_BLOCKED_PORTS[p]}</strong> — mapping will be rejected`);
        }
    }
    // Check in-use
    if (_mappingPortData && _mappingPortData.listening) {
        const listening = _mappingPortData.listening;
        for (const p of ports) {
            if (MAPPING_BLOCKED_PORTS[p]) continue; // already warned
            const match = listening.find(l => l.port === p);
            if (match) {
                warnings.push(`⚠️ Port <strong>${p}</strong> is in use by <strong>${match.process || 'unknown'}</strong> — traffic will be intercepted`);
            }
        }
    }

    if (warnings.length > 0) {
        warnDiv.innerHTML = `<div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.3);border-radius:6px;padding:8px 12px;margin-top:8px;font-size:12px;line-height:1.7;">
            ${warnings.join('<br>')}
        </div>`;
    } else {
        warnDiv.innerHTML = '<div style="color:#22c55e;font-size:12px;margin-top:6px;">✅ No port conflicts detected</div>';
    }
}

async function createIpMapping() {
    const public_ip = document.getElementById('mapping-public-ip').value.trim();
    const wolfnet_ip = document.getElementById('mapping-wolfnet-ip').value.trim();
    const ports = document.getElementById('mapping-ports').value.trim() || null;
    const protocol = document.getElementById('mapping-protocol').value;
    const label = document.getElementById('mapping-label').value.trim() || null;

    if (!public_ip) { showModal('Please enter a public IP address'); return; }
    if (!wolfnet_ip) { showModal('Please enter a WolfNet IP address'); return; }

    // Client-side port validation
    if (ports) {
        const parsed = parseMappingPorts(ports);
        if (!parsed) {
            showModal('Invalid port format. Use: 80, 80,443, or 8000:8100');
            return;
        }
        if (protocol === 'all') {
            showModal('When specifying ports, you must select TCP or UDP (not "All"). iptables requires a specific protocol for port-based rules.');
            return;
        }
        // Check for blocked ports
        for (const p of parsed) {
            if (MAPPING_BLOCKED_PORTS[p]) {
                showModal(`Port ${p} is used by ${MAPPING_BLOCKED_PORTS[p]} and cannot be mapped. This would break critical system access.`);
                return;
            }
        }
    }

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
        showModal('Error: ' + e.message);
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
        showModal('Error: ' + e.message);
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

    if (!name) { showModal('Please enter a peer name'); return; }
    if (!ip) { showModal('Please enter the peer\'s WolfNet IP address'); return; }

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
        showModal('Error: ' + e.message);
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
        showModal('Error: ' + e.message);
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
        showModal('Error: ' + e.message);
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
        showModal('Error: ' + e.message);
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
        showModal('WolfNet error: ' + e.message);
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
    if (!table) return;

    if (containers.length === 0) {
        table.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';

    table.innerHTML = containers.map(c => {
        const s = dockerStats[c.name] || {};
        const isRunning = c.state === 'running';
        const isPaused = c.state === 'paused';
        const stateColor = isRunning ? '#10b981' : (isPaused ? '#f59e0b' : '#6b7280');
        const ports = c.ports.length > 0 ? c.ports.join('<br>') : '-';
        const hasStorage = c.disk_usage !== undefined && c.disk_total;
        const pct = hasStorage ? Math.round((c.disk_usage / c.disk_total) * 100) : 0;
        const barColor = pct > 90 ? '#ef4444' : pct > 70 ? '#f59e0b' : '#10b981';
        const fsLabel = c.fs_type ? `<span style="color:var(--text-muted);font-size:10px;margin-left:8px;">${c.fs_type}</span>` : '';
        const pathLabel = c.storage_path ? `<span style="color:var(--text-muted);font-size:10px;" title="${c.storage_path}">${c.storage_path.length > 30 ? '...' + c.storage_path.slice(-27) : c.storage_path}</span>` : '';
        const storageSubRow = hasStorage ? `<tr class="storage-sub-row" style="background:var(--bg-secondary);"><td colspan="9" style="padding:4px 16px 6px 24px;border-top:none;">
            <div style="display:flex;align-items:center;gap:8px;font-size:11px;">
                <span>💾</span>
                <div style="flex:1;max-width:220px;height:8px;background:var(--bg-tertiary,#333);border-radius:4px;overflow:hidden;">
                    <div style="width:${pct}%;height:100%;background:${barColor};border-radius:4px;transition:width 0.3s;"></div>
                </div>
                <span style="min-width:110px;">${formatBytes(c.disk_usage)} / ${formatBytes(c.disk_total)} (${pct}%)</span>
                ${fsLabel}${pathLabel}
            </div>
        </td></tr>` : '';

        return `<tr data-name="${c.name}">
            <td><strong>${c.name}</strong><br><span style="font-size:11px;color:var(--text-muted)">${c.id.substring(0, 12)}</span></td>
            <td>${c.image}</td>
            <td><span style="color:${stateColor}">●</span> ${c.status}</td>
            <td style="font-size:12px; font-family:monospace;">${c.ip_address || '-'}</td>
            <td class="cpu-cell">${s.cpu_percent !== undefined ? s.cpu_percent.toFixed(1) + '%' : '-'}</td>
            <td class="mem-cell">${s.memory_usage ? formatBytes(s.memory_usage) : '-'}</td>
            <td style="font-size:11px;">${ports}</td>
            <td><input type="checkbox" ${c.autostart ? 'checked' : ''} onchange="toggleDockerAutostart('${c.id}', this.checked)"></td>
            <td style="white-space:nowrap;">
                ${isRunning ? `
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;opacity:0.4;cursor:not-allowed;pointer-events:none;" disabled title="Start">▶️</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="dockerAction('${c.name}', 'stop')" title="Stop">⏹️</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="dockerAction('${c.name}', 'restart')" title="Restart">🔄</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="dockerAction('${c.name}', 'pause')" title="Pause">⏸️</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="openConsole('docker', '${c.name}')" title="Console">💻</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;opacity:0.4;cursor:not-allowed;pointer-events:none;" disabled title="Remove">🗑️</button>
                ` : isPaused ? `
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="dockerAction('${c.name}', 'unpause')" title="Unpause">▶️</button>
                ` : `
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="dockerAction('${c.name}', 'start')" title="Start">▶️</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;opacity:0.4;cursor:not-allowed;pointer-events:none;" disabled title="Stop">⏹️</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;opacity:0.4;cursor:not-allowed;pointer-events:none;" disabled title="Restart">🔄</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;opacity:0.4;cursor:not-allowed;pointer-events:none;" disabled title="Freeze">⏸️</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;opacity:0.4;cursor:not-allowed;pointer-events:none;" disabled title="Console">💻</button>
                    <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;color:#ef4444;" onclick="dockerAction('${c.name}', 'remove')" title="Remove">🗑️</button>
                `}
                <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="viewContainerLogs('docker', '${c.name}')" title="Logs">📜</button>
                <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="viewDockerVolumes('${c.name}')" title="Volumes">📁</button>
                <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="browseContainerFiles('docker', '${c.name}')" title="Browse Files">📂</button>
                <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="openDockerSettings('${c.name}')" title="Settings">⚙️</button>
                <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="cloneDockerContainer('${c.name}')" title="Clone">📋</button>
                <button class="btn btn-sm" style="margin:2px;font-size:20px;line-height:1;padding:4px 6px;" onclick="migrateDockerContainer('${c.name}')" title="Migrate">🚀</button>
            </td>
        </tr>${storageSubRow}`;
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

// ─── Docker Settings Editor ───

var _dockerSettingsTab = 1;

function switchDockerTab(tab) {
    _dockerSettingsTab = tab;
    document.querySelectorAll('.docker-tab-page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.docker-tab-btn').forEach(b => {
        b.style.borderBottomColor = 'transparent';
        b.style.color = 'var(--text-muted)';
    });
    var page = document.getElementById('docker-tab-' + tab);
    var btn = document.querySelector('.docker-tab-btn[data-dtab="' + tab + '"]');
    if (page) page.style.display = 'block';
    if (btn) { btn.style.borderBottomColor = 'var(--accent)'; btn.style.color = 'var(--text-primary)'; }
}

async function openDockerSettings(name) {
    const modal = document.getElementById('container-detail-modal');
    const title = document.getElementById('container-detail-title');
    const body = document.getElementById('container-detail-body');

    title.textContent = `${name} — Settings`;
    body.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:40px;">Loading config...</p>';
    modal.classList.add('active');
    _dockerSettingsTab = 1;

    try {
        const resp = await fetch(apiUrl(`/api/containers/docker/${encodeURIComponent(name)}/inspect`));
        if (!resp.ok) throw new Error('Failed to load config');
        const cfg = await resp.json();

        // Extract useful fields from docker inspect JSON
        const hostname = cfg.Config?.Hostname || '';
        const image = cfg.Config?.Image || '';
        const restartPolicy = cfg.HostConfig?.RestartPolicy?.Name || 'no';
        const isAutostart = restartPolicy === 'always' || restartPolicy === 'unless-stopped';
        const memoryBytes = cfg.HostConfig?.Memory || 0;
        const memoryMb = memoryBytes > 0 ? Math.round(memoryBytes / 1048576) : '';
        const nanoCpus = cfg.HostConfig?.NanoCpus || 0;
        const cpus = nanoCpus > 0 ? (nanoCpus / 1e9).toFixed(1) : '';
        const cpuShares = cfg.HostConfig?.CpuShares || 0;
        const cpusetCpus = cfg.HostConfig?.CpusetCpus || '';
        const env = (cfg.Config?.Env || []);
        const ports = cfg.HostConfig?.PortBindings || {};
        const networks = cfg.NetworkSettings?.Networks || {};

        // Format port bindings for display
        var portRows = '';
        for (const [containerPort, bindings] of Object.entries(ports)) {
            if (bindings && bindings.length > 0) {
                bindings.forEach(b => {
                    const hostPort = b.HostPort || '';
                    const hostIp = b.HostIp || '0.0.0.0';
                    portRows += `<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;margin-bottom:4px;background:var(--bg-primary);border-radius:6px;border:1px solid var(--border);">
                        <code style="font-size:12px;color:var(--accent);">${hostIp}:${hostPort}</code>
                        <span style="color:var(--text-muted);font-size:12px;">→</span>
                        <code style="font-size:12px;color:var(--text-primary);">${containerPort}</code>
                    </div>`;
                });
            }
        }
        if (!portRows) portRows = '<div style="color:var(--text-muted);font-size:12px;padding:8px;">No port mappings configured</div>';

        // Format network info
        var networkRows = '';
        for (const [netName, netInfo] of Object.entries(networks)) {
            networkRows += `<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;margin-bottom:4px;background:var(--bg-primary);border-radius:6px;border:1px solid var(--border);">
                <span style="font-size:14px;">🔌</span>
                <div style="flex:1;">
                    <div style="font-weight:600;font-size:12px;">${escapeHtml(netName)}</div>
                    <div style="font-size:11px;color:var(--text-muted);font-family:monospace;">
                        IP: ${netInfo.IPAddress || '-'} · MAC: ${netInfo.MacAddress || '-'} · Gateway: ${netInfo.Gateway || '-'}
                    </div>
                </div>
            </div>`;
        }
        if (!networkRows) networkRows = '<div style="color:var(--text-muted);font-size:12px;padding:8px;">No networks connected</div>';

        // Format env vars for display
        var envRows = env.filter(e => !e.startsWith('PATH=')).slice(0, 20).map(e => {
            const [key, ...val] = e.split('=');
            return `<div style="display:flex;align-items:center;gap:8px;padding:4px 8px;margin-bottom:2px;background:var(--bg-primary);border-radius:4px;">
                <code style="font-size:11px;color:var(--accent);min-width:120px;">${escapeHtml(key)}</code>
                <code style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(val.join('='))}</code>
            </div>`;
        }).join('');
        if (!envRows) envRows = '<div style="color:var(--text-muted);font-size:12px;padding:8px;">No environment variables</div>';

        // WolfNet IP from labels
        const labels = cfg.Config?.Labels || {};
        const wolfnetIp = labels['wolfnet.ip'] || '';

        var tabBtnStyle = 'flex:1;padding:10px 12px;border:none;background:none;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;';

        body.innerHTML = `
            <!-- Tab Bar -->
            <div style="display:flex;border-bottom:1px solid var(--border);background:var(--bg-secondary);margin:-24px -24px 16px -24px;">
                <button class="docker-tab-btn" data-dtab="1" onclick="switchDockerTab(1)"
                    style="${tabBtnStyle}border-bottom:2px solid var(--accent);color:var(--text-primary);">
                    ⚙️ General
                </button>
                <button class="docker-tab-btn" data-dtab="2" onclick="switchDockerTab(2)"
                    style="${tabBtnStyle}border-bottom:2px solid transparent;color:var(--text-muted);">
                    🌐 Network
                </button>
                <button class="docker-tab-btn" data-dtab="3" onclick="switchDockerTab(3)"
                    style="${tabBtnStyle}border-bottom:2px solid transparent;color:var(--text-muted);">
                    💻 Resources
                </button>
            </div>

            <!-- ═══ Tab 1: General ═══ -->
            <div class="docker-tab-page" id="docker-tab-1">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                    <div class="form-group">
                        <label>Container Name</label>
                        <input type="text" class="form-control" value="${escapeHtml(name)}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                    </div>
                    <div class="form-group">
                        <label>Image</label>
                        <input type="text" class="form-control" value="${escapeHtml(image)}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                    </div>
                    <div class="form-group">
                        <label>Hostname</label>
                        <input type="text" class="form-control" value="${escapeHtml(hostname)}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                        <small style="color:var(--text-muted);margin-top:4px;display:block;">Set automatically by Docker</small>
                    </div>
                    <div class="form-group">
                        <label>Restart Policy</label>
                        <select id="docker-restart-policy" class="form-control">
                            <option value="no" ${restartPolicy === 'no' ? 'selected' : ''}>No (manual only)</option>
                            <option value="always" ${restartPolicy === 'always' ? 'selected' : ''}>Always</option>
                            <option value="unless-stopped" ${restartPolicy === 'unless-stopped' ? 'selected' : ''}>Unless Stopped</option>
                            <option value="on-failure" ${restartPolicy === 'on-failure' ? 'selected' : ''}>On Failure</option>
                        </select>
                    </div>
                </div>

                <div style="margin-top:12px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <h4 style="margin:0 0 8px 0;font-size:13px;color:var(--text-primary);">📦 Environment Variables (${env.filter(e => !e.startsWith('PATH=')).length})</h4>
                    <div style="max-height:160px;overflow-y:auto;">
                        ${envRows}
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:6px;">⚠️ Environment variables can only be changed by recreating the container.</div>
                </div>
            </div>

            <!-- ═══ Tab 2: Network ═══ -->
            <div class="docker-tab-page" id="docker-tab-2" style="display:none;">
                <div style="padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);margin-bottom:12px;">
                    <h4 style="margin:0 0 8px 0;font-size:13px;">🔌 Networks</h4>
                    ${networkRows}
                </div>
                <div style="padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);margin-bottom:12px;">
                    <h4 style="margin:0 0 8px 0;font-size:13px;">🔗 Port Mappings</h4>
                    ${portRows}
                    <div style="font-size:11px;color:var(--text-muted);margin-top:6px;">⚠️ Port mappings can only be changed by recreating the container.</div>
                </div>
                <div style="padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <h4 style="margin:0 0 8px 0;font-size:13px;">🐺 WolfNet</h4>
                    <div style="display:grid;grid-template-columns:1fr auto;gap:8px;align-items:end;">
                        <div class="form-group" style="margin:0;">
                            <label>WolfNet IP</label>
                            <input type="text" id="docker-wolfnet-ip" class="form-control" value="${escapeHtml(wolfnetIp)}"
                                placeholder="e.g. 10.10.10.50 (leave blank for none)">
                        </div>
                        <div style="display:flex;gap:4px;padding-bottom:2px;">
                            <button class="btn btn-sm" onclick="findNextWolfnetIp()" title="Find next available WolfNet IP"
                                style="padding:6px 10px;font-size:11px;">🔍 Next Available</button>
                        </div>
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:6px;">WolfNet IP is applied at container start time via host routing.</div>
                </div>
            </div>

            <!-- ═══ Tab 3: Resources ═══ -->
            <div class="docker-tab-page" id="docker-tab-3" style="display:none;">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                    <div class="form-group">
                        <label>Memory Limit (MB)</label>
                        <input type="number" id="docker-memory" class="form-control" value="${memoryMb}"
                            placeholder="Leave blank for unlimited" min="0">
                        <small style="color:var(--text-muted);margin-top:4px;display:block;">Enter value in MB. Leave blank for unlimited. Can be changed live.</small>
                    </div>
                    <div class="form-group">
                        <label>CPU Limit (cores)</label>
                        <input type="number" id="docker-cpus" class="form-control" value="${cpus}"
                            placeholder="Leave blank for unlimited" min="0" step="0.1">
                        <small style="color:var(--text-muted);margin-top:4px;display:block;">e.g. 2.0 for 2 cores. Can be changed live.</small>
                    </div>
                    <div class="form-group">
                        <label>CPU Shares</label>
                        <input type="text" class="form-control" value="${cpuShares || 'Default (1024)'}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                    </div>
                    <div class="form-group">
                        <label>CPU Set (pinned cores)</label>
                        <input type="text" class="form-control" value="${escapeHtml(cpusetCpus) || 'All cores'}" readonly
                            style="opacity:0.7;cursor:not-allowed;">
                    </div>
                </div>

                <div style="margin-top:12px;padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">
                    <details>
                        <summary style="cursor:pointer;color:var(--accent);font-size:12px;margin-bottom:8px;">
                            📝 Raw Docker Inspect (JSON)
                        </summary>
                        <pre style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:12px;
                            font-family:'JetBrains Mono',monospace;font-size:11px;max-height:300px;overflow-y:auto;
                            color:var(--text-primary);white-space:pre-wrap;word-break:break-all;">${escapeHtml(JSON.stringify(cfg, null, 2))}</pre>
                    </details>
                </div>
            </div>

            <!-- Save/Cancel Bar -->
            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--border);">
                <button class="btn btn-sm" onclick="closeContainerDetail()">Cancel</button>
                <button class="btn btn-sm btn-primary" onclick="saveDockerSettings('${name}')">💾 Save Settings</button>
            </div>
        `;
    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Failed to load config: ${e.message}</p>`;
    }
}

async function saveDockerSettings(name) {
    var restartPolicy = (document.getElementById('docker-restart-policy') || {}).value || 'no';
    var autostart = restartPolicy === 'always' || restartPolicy === 'unless-stopped';
    var memoryStr = (document.getElementById('docker-memory') || {}).value || '';
    var cpusStr = (document.getElementById('docker-cpus') || {}).value || '';

    var memoryMb = memoryStr ? parseInt(memoryStr) : null;
    var cpus = cpusStr ? parseFloat(cpusStr) : null;

    // Validate
    if (memoryMb !== null && (isNaN(memoryMb) || memoryMb < 0)) {
        showToast('Invalid memory value', 'error');
        return;
    }
    if (cpus !== null && (isNaN(cpus) || cpus < 0)) {
        showToast('Invalid CPU value', 'error');
        return;
    }

    try {
        const resp = await fetch(apiUrl(`/api/containers/docker/${encodeURIComponent(name)}/config`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                autostart: autostart,
                memory_mb: memoryMb,
                cpus: cpus,
            })
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast('Settings saved — changes applied immediately', 'success');
            closeContainerDetail();
            if (typeof loadDockerContainers === 'function') loadDockerContainers();
        } else {
            showToast(data.error || 'Failed to save settings', 'error');
        }
    } catch (e) {
        showToast('Error saving settings: ' + e.message, 'error');
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

        const containersData = containersResp.ok ? await containersResp.json() : [];
        const statsData = statsResp.ok ? await statsResp.json() : [];
        const containers = Array.isArray(containersData) ? containersData : [];
        const stats = Array.isArray(statsData) ? statsData : [];

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
    if (!table) return;

    if (containers.length === 0) {
        table.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';

    const btnStyle = 'margin:2px;font-size:20px;line-height:1;padding:4px 6px;';
    const disStyle = 'margin:2px;font-size:20px;line-height:1;padding:4px 6px;color:#ef4444;opacity:0.4;cursor:not-allowed;pointer-events:none;';

    table.innerHTML = containers.map(c => {
        const s = stats[c.name] || {};
        const isRunning = c.state === 'running';
        const isFrozen = c.state === 'frozen';
        const stateColor = isRunning ? '#10b981' : isFrozen ? '#f59e0b' : '#6b7280';
        const hasStorage = c.disk_usage !== undefined && c.disk_total;
        const pct = hasStorage ? Math.round((c.disk_usage / c.disk_total) * 100) : 0;
        const barColor = pct > 90 ? '#ef4444' : pct > 70 ? '#f59e0b' : '#10b981';
        const fsLabel = c.fs_type ? `<span style="color:var(--text-muted);font-size:10px;margin-left:8px;">${c.fs_type}</span>` : '';
        const pathLabel = c.storage_path ? `<span style="color:var(--text-muted);font-size:10px;" title="${c.storage_path}">${c.storage_path.length > 30 ? '...' + c.storage_path.slice(-27) : c.storage_path}</span>` : '';
        const storageSubRow = hasStorage ? `<tr class="storage-sub-row" style="background:var(--bg-secondary);"><td colspan="8" style="padding:4px 16px 6px 24px;border-top:none;">
            <div style="display:flex;align-items:center;gap:8px;font-size:11px;">
                <span>💾</span>
                <div style="flex:1;max-width:220px;height:8px;background:var(--bg-tertiary,#333);border-radius:4px;overflow:hidden;">
                    <div style="width:${pct}%;height:100%;background:${barColor};border-radius:4px;transition:width 0.3s;"></div>
                </div>
                <span style="min-width:110px;">${formatBytes(c.disk_usage)} / ${formatBytes(c.disk_total)} (${pct}%)</span>
                ${fsLabel}${pathLabel}
            </div>
        </td></tr>` : '';

        return `<tr>
            <td><strong>${c.hostname || c.name}</strong>${c.hostname ? `<div style="font-size:11px;color:var(--text-muted);">CT ${c.name}</div>` : ''}</td>
            <td style="font-size:12px;color:var(--text-secondary);">${c.version || '<span style="color:var(--text-muted)">—</span>'}</td>
            <td><span style="color:${stateColor}">●</span> ${c.state}</td>
            <td style="font-size:12px; font-family:monospace;">${c.ip_address || '-'}</td>
            <td>${s.cpu_percent !== undefined ? s.cpu_percent.toFixed(1) + '%' : '-'}</td>
            <td>${s.memory_usage ? formatBytes(s.memory_usage) + (s.memory_limit ? ' / ' + formatBytes(s.memory_limit) : '') : '-'}</td>
            <td><input type="checkbox" ${c.autostart ? 'checked' : ''} onchange="toggleLxcAutostart('${c.name}', this.checked)"></td>
            <td style="white-space:nowrap;">
                <button class="btn btn-sm" style="${isRunning ? disStyle : btnStyle}" ${isRunning ? 'disabled' : ''} ${!isRunning ? `onclick="lxcAction('${c.name}', 'start')"` : ''} title="Start">▶️</button>
                <button class="btn btn-sm" style="${!isRunning ? disStyle : btnStyle}" ${!isRunning ? 'disabled' : ''} ${isRunning ? `onclick="lxcAction('${c.name}', 'stop')"` : ''} title="Stop">⏹️</button>
                <button class="btn btn-sm" style="${!isRunning ? disStyle : btnStyle}" ${!isRunning ? 'disabled' : ''} ${isRunning ? `onclick="lxcAction('${c.name}', 'restart')"` : ''} title="Restart">🔄</button>
                <button class="btn btn-sm" style="${!isRunning ? disStyle : btnStyle}" ${!isRunning ? 'disabled' : ''} ${isRunning ? `onclick="lxcAction('${c.name}', 'freeze')"` : ''} title="Freeze">⏸️</button>
                <button class="btn btn-sm" style="${!isRunning ? disStyle : btnStyle}" ${!isRunning ? 'disabled' : ''} ${isRunning ? `onclick="openLxcConsole('${c.name}', '${c.hostname || c.name}')"` : ''} title="Console">💻</button>
                <button class="btn btn-sm" style="${isRunning ? disStyle : btnStyle}" ${isRunning ? 'disabled' : ''} ${!isRunning ? `onclick="lxcAction('${c.name}', 'destroy')"` : ''} title="Destroy">🗑️</button>
                <button class="btn btn-sm" style="${btnStyle}" onclick="viewContainerLogs('lxc', '${c.name}')" title="Logs">📜</button>
                <button class="btn btn-sm" style="${btnStyle}" onclick="browseContainerFiles('lxc', '${c.name}', '${(c.storage_path || '').replace(/'/g, "\\'")}')" title="Browse Files">📂</button>
                <button class="btn btn-sm" style="${btnStyle}" onclick="openLxcSettings('${c.name}')" title="Settings">⚙️</button>
                <button class="btn btn-sm" style="${btnStyle}" onclick="cloneLxcContainer('${c.name}')" title="Clone">📋</button>
                <button class="btn btn-sm" style="${btnStyle}" onclick="migrateLxcContainer('${c.name}')" title="Migrate">🚀</button>
                <button class="btn btn-sm" style="${btnStyle}" onclick="exportLxcContainer('${c.name}')" title="Export">📦</button>
            </td>
        </tr>${storageSubRow}`;
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

function generateMacFor(nicIndex) {
    var hex = '0123456789ABCDEF';
    var mac = '02';
    for (var i = 0; i < 5; i++) {
        mac += ':' + hex[Math.floor(Math.random() * 16)] + hex[Math.floor(Math.random() * 16)];
    }
    var el = document.querySelector(`.lxc-nic-field[data-nic="${nicIndex}"][data-field="hwaddr"]`);
    if (el) el.value = mac;
}

function toggleNicEditor(nicIndex) {
    var editor = document.getElementById('lxc-nic-editor-' + nicIndex);
    if (!editor) return;

    // If already showing, close it
    if (editor.style.display === 'block') {
        closeNicEditor();
        return;
    }

    // Close any other open editor first
    closeNicEditor();

    // Show as popup overlay
    var backdrop = document.getElementById('lxc-nic-backdrop');
    if (!backdrop) {
        backdrop = document.createElement('div');
        backdrop.id = 'lxc-nic-backdrop';
        backdrop.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:10001;display:flex;align-items:center;justify-content:center;';
        backdrop.onclick = function (e) { if (e.target === backdrop) closeNicEditor(); };
        document.body.appendChild(backdrop);
    }
    backdrop.style.display = 'flex';

    // Move the editor into the backdrop as a popup
    editor.style.display = 'block';
    editor.style.cssText = 'display:block;background:var(--bg-primary);border:1px solid var(--border);border-radius:12px;padding:20px;width:520px;max-width:90vw;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.4);';
    editor.setAttribute('data-was-nic', nicIndex);
    backdrop.innerHTML = '';
    backdrop.appendChild(editor);

    // Mark arrow
    var arrow = document.getElementById('lxc-nic-arrow-' + nicIndex);
    if (arrow) arrow.style.transform = 'rotate(90deg)';
}

function closeNicEditor() {
    var backdrop = document.getElementById('lxc-nic-backdrop');
    if (backdrop) {
        // Move editor back to its NIC item
        var editor = backdrop.querySelector('.lxc-nic-editor');
        if (editor) {
            var nicIdx = editor.getAttribute('data-was-nic');
            var nicItem = document.querySelector('.lxc-nic-item[data-nic-index="' + nicIdx + '"]');
            if (nicItem) {
                editor.style.cssText = 'display:none;padding:14px;border-top:1px solid var(--border);background:var(--bg-primary);';
                nicItem.appendChild(editor);
            }
            var arrow = document.getElementById('lxc-nic-arrow-' + nicIdx);
            if (arrow) arrow.style.transform = 'rotate(0deg)';
        }
        backdrop.style.display = 'none';
    }
}

function addLxcNic() {
    var list = document.getElementById('lxc-nic-list');
    if (!list) return;
    // Find the next available index
    var existing = list.querySelectorAll('.lxc-nic-item');
    var maxIdx = -1;
    existing.forEach(function (item) {
        var idx = parseInt(item.getAttribute('data-nic-index'));
        if (idx > maxIdx) maxIdx = idx;
    });
    var newIdx = maxIdx + 1;
    var html = `
        <div class="lxc-nic-item" data-nic-index="${newIdx}" style="margin-bottom:8px;border:1px solid var(--border);border-radius:8px;overflow:hidden;">
            <div class="lxc-nic-summary" onclick="toggleNicEditor(${newIdx})" style="display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;background:var(--bg-tertiary);transition:background .15s;"
                 onmouseenter="this.style.background='var(--bg-secondary)'" onmouseleave="this.style.background='var(--bg-tertiary)'">
                <span style="font-size:16px;">🔌</span>
                <div style="flex:1;min-width:0;">
                    <div style="font-weight:600;font-size:13px;">net${newIdx} — eth${newIdx}</div>
                    <div style="font-size:11px;color:var(--text-muted);font-family:monospace;">New interface</div>
                </div>
                <span class="lxc-nic-arrow" id="lxc-nic-arrow-${newIdx}" style="font-size:12px;color:var(--text-muted);transition:transform .2s;">▶</span>
            </div>
            <div class="lxc-nic-editor" id="lxc-nic-editor-${newIdx}" style="display:none;padding:14px;border-top:1px solid var(--border);background:var(--bg-primary);">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
                    <h4 style="margin:0;font-size:14px;">🔌 Edit net${newIdx} — eth${newIdx}</h4>
                    <button class="btn btn-sm" onclick="closeNicEditor()" style="font-size:16px;padding:2px 8px;line-height:1;" title="Close">✕</button>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">Interface Name</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="name" value="eth${newIdx}" placeholder="eth${newIdx}">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">Type</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="net_type" value="veth" placeholder="veth">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">Bridge / Link</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="link" value="" placeholder="e.g. lxcbr0, vmbr0">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">MAC Address</label>
                        <div style="display:flex;gap:4px;">
                            <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="hwaddr" value="" placeholder="AA:BB:CC:DD:EE:FF" style="flex:1;">
                            <button class="btn btn-sm" onclick="generateMacFor(${newIdx})" title="Generate MAC" style="padding:4px 6px;font-size:10px;">🎲</button>
                        </div>
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">IPv4 Address / CIDR</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="ipv4" value="" placeholder="192.168.1.100/24 or blank for DHCP">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">IPv4 Gateway</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="ipv4_gw" value="" placeholder="192.168.1.1">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">IPv6 Address / CIDR</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="ipv6" value="" placeholder="fd00::100/64 or blank">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">IPv6 Gateway</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="ipv6_gw" value="" placeholder="fd00::1">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">MTU</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="mtu" value="" placeholder="Default">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label style="font-size:11px;">VLAN Tag</label>
                        <input type="text" class="form-control lxc-nic-field" data-nic="${newIdx}" data-field="vlan" value="" placeholder="None">
                    </div>
                </div>
            </div>
        </div>`;
    list.insertAdjacentHTML('beforeend', html);
    // Auto-open the editor popup for the new NIC
    toggleNicEditor(newIdx);
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
                        <select id="lxc-unprivileged" class="form-control">
                            <option value="false" ${cfg.unprivileged ? '' : 'selected'}>Privileged</option>
                            <option value="true" ${cfg.unprivileged ? 'selected' : ''}>Unprivileged</option>
                        </select>
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
                <div id="lxc-nic-list">
                ${((cfg.network_interfaces || []).length > 0 ? cfg.network_interfaces : [{ index: 0, net_type: 'veth', name: 'eth0', link: '', hwaddr: '', ipv4: '', ipv4_gw: '', ipv6: '', ipv6_gw: '', mtu: '', vlan: '' }]).map(nic => `
                    <div class="lxc-nic-item" data-nic-index="${nic.index}" style="margin-bottom:8px;border:1px solid var(--border);border-radius:8px;overflow:hidden;">
                        <div class="lxc-nic-summary" onclick="toggleNicEditor(${nic.index})" style="display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;background:var(--bg-tertiary);transition:background .15s;"
                             onmouseenter="this.style.background='var(--bg-secondary)'" onmouseleave="this.style.background='var(--bg-tertiary)'">
                            <span style="font-size:16px;">🔌</span>
                            <div style="flex:1;min-width:0;">
                                <div style="font-weight:600;font-size:13px;">net${nic.index} — ${escapeHtml(nic.name || 'eth' + nic.index)}</div>
                                <div style="font-size:11px;color:var(--text-muted);font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                                    ${escapeHtml(nic.ipv4) || 'DHCP'} · ${escapeHtml(nic.link) || 'no bridge'} · ${escapeHtml(nic.hwaddr) || 'no MAC'}
                                </div>
                            </div>
                            <span class="lxc-nic-arrow" id="lxc-nic-arrow-${nic.index}" style="font-size:12px;color:var(--text-muted);transition:transform .2s;">▶</span>
                        </div>
                        <div class="lxc-nic-editor" id="lxc-nic-editor-${nic.index}" style="display:none;padding:14px;border-top:1px solid var(--border);background:var(--bg-primary);">
                            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
                                <h4 style="margin:0;font-size:14px;">🔌 Edit net${nic.index} — ${escapeHtml(nic.name || 'eth' + nic.index)}</h4>
                                <button class="btn btn-sm" onclick="closeNicEditor()" style="font-size:16px;padding:2px 8px;line-height:1;" title="Close">✕</button>
                            </div>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">Interface Name</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="name" value="${escapeHtml(nic.name || 'eth' + nic.index)}" placeholder="eth${nic.index}">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">Type</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="net_type" value="${escapeHtml(nic.net_type || 'veth')}" placeholder="veth">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">Bridge / Link</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="link" value="${escapeHtml(nic.link)}" placeholder="e.g. lxcbr0, vmbr0">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">MAC Address</label>
                                    <div style="display:flex;gap:4px;">
                                        <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="hwaddr" value="${escapeHtml(nic.hwaddr)}" placeholder="AA:BB:CC:DD:EE:FF" style="flex:1;">
                                        <button class="btn btn-sm" onclick="generateMacFor(${nic.index})" title="Generate MAC" style="padding:4px 6px;font-size:10px;">🎲</button>
                                    </div>
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">IPv4 Address / CIDR</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="ipv4" value="${escapeHtml(nic.ipv4)}" placeholder="192.168.1.100/24 or blank for DHCP">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">IPv4 Gateway</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="ipv4_gw" value="${escapeHtml(nic.ipv4_gw)}" placeholder="192.168.1.1">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">IPv6 Address / CIDR</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="ipv6" value="${escapeHtml(nic.ipv6)}" placeholder="fd00::100/64 or blank">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">IPv6 Gateway</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="ipv6_gw" value="${escapeHtml(nic.ipv6_gw)}" placeholder="fd00::1">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">MTU</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="mtu" value="${escapeHtml(nic.mtu)}" placeholder="Default">
                                </div>
                                <div class="form-group" style="margin:0;">
                                    <label style="font-size:11px;">VLAN Tag</label>
                                    <input type="text" class="form-control lxc-nic-field" data-nic="${nic.index}" data-field="vlan" value="${escapeHtml(nic.vlan)}" placeholder="None">
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('')}
                </div>

                <button class="btn btn-sm" onclick="addLxcNic()" style="margin-top:4px;font-size:11px;padding:6px 12px;">+ Add Interface</button>

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
            </div>

            <!-- ═══ Tab 3: Resources ═══ -->
            <div class="lxc-tab-page" id="lxc-tab-3" style="display:none;">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                    <div class="form-group">
                        <label>Memory Limit (MB)</label>
                        <input type="text" id="lxc-memory" class="form-control" value="${escapeHtml(cfg.memory_limit)}"
                            placeholder="e.g. 2048 (leave blank for unlimited)">
                        <small style="color:var(--text-muted);margin-top:4px;display:block;">Enter value in MB. Leave blank for unlimited.</small>
                    </div>
                    <div class="form-group">
                        <label>Swap Limit (MB)</label>
                        <input type="text" id="lxc-swap" class="form-control" value="${escapeHtml(cfg.swap_limit)}"
                            placeholder="e.g. 512 (0 to disable, blank for unlimited)">
                        <small style="color:var(--text-muted);margin-top:4px;display:block;">Enter value in MB. 0 to disable, blank for unlimited.</small>
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

    // Collect all network interfaces from NIC editors
    var networkInterfaces = [];
    var nicItems = document.querySelectorAll('.lxc-nic-item');
    nicItems.forEach(function (item) {
        var idx = parseInt(item.getAttribute('data-nic-index'));
        var getField = function (field) {
            var el = item.querySelector(`.lxc-nic-field[data-field="${field}"]`);
            return el ? el.value.trim() : '';
        };
        networkInterfaces.push({
            index: idx,
            net_type: getField('net_type') || 'veth',
            name: getField('name') || ('eth' + idx),
            link: getField('link'),
            hwaddr: getField('hwaddr'),
            ipv4: getField('ipv4'),
            ipv4_gw: getField('ipv4_gw'),
            ipv6: getField('ipv6'),
            ipv6_gw: getField('ipv6_gw'),
            mtu: getField('mtu'),
            vlan: getField('vlan'),
            firewall: false,
            flags: 'up'
        });
    });

    var settings = {
        hostname: (document.getElementById('lxc-hostname') || {}).value || '',
        autostart: (document.getElementById('lxc-autostart') || {}).checked || false,
        start_delay: parseInt((document.getElementById('lxc-start-delay') || {}).value) || 0,
        start_order: parseInt((document.getElementById('lxc-start-order') || {}).value) || 0,
        unprivileged: (document.getElementById('lxc-unprivileged') || {}).value === 'true',
        network_interfaces: networkInterfaces,
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
        const data = await resp.json();
        const nodes = Array.isArray(data) ? data : (data.nodes || []);

        let nodeOpts = '';
        if (nodes && nodes.length > 0) {
            nodeOpts = nodes
                .sort((a, b) => (a.name || a.address).localeCompare(b.name || b.address))
                .map(n => `<option value="${n.url || 'http://' + n.address + ':8553'}">${n.name || n.address} (${n.address})</option>`).join('');
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
                    <label style="display:block; margin-bottom:4px; font-weight:600;">Target Storage</label>
                    <select id="docker-migrate-storage" style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                        <option value="">Auto (default)</option>
                    </select>
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
                    <label style="display:block; margin-bottom:4px; font-weight:600;">Target Storage</label>
                    <select id="docker-migrate-storage" style="width:100%; padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--bg-primary); color:var(--text-primary);">
                        <option value="">Auto (default)</option>
                    </select>
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
    const storageVal = document.getElementById('docker-migrate-storage')?.value || '';

    if (!targetUrl) {
        showToast('Please enter a target URL', 'error');
        return;
    }

    closeContainerDetail();
    showToast(`Migrating ${name} to ${targetUrl}... This may take a while.`, 'info');

    try {
        const migrateBody = { target_url: targetUrl, remove_source: removeSource };
        if (storageVal) migrateBody.storage = storageVal;
        const resp = await fetch(apiUrl(`/api/containers/docker/${name}/migrate`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(migrateBody),
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
    // Fetch cluster nodes from LOCAL server (not proxied) for the target selector
    let nodes = [];
    try {
        const resp = await fetch('/api/nodes');
        if (resp.ok) {
            const data = await resp.json();
            nodes = Array.isArray(data) ? data : (data.nodes || []);
        }
    } catch (e) { }

    const modal = document.createElement('div');
    modal.id = 'lxc-clone-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:10000;backdrop-filter:blur(4px);';
    modal.innerHTML = `
        <div style="background:var(--card-bg,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;padding:28px 36px;min-width:400px;max-width:500px;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
            <h3 style="margin:0 0 16px;color:var(--text,#fff);">📋 Clone Container</h3>
            <p style="margin:0 0 16px;color:var(--text-muted,#aaa);font-size:0.9em;">Clone <strong>${name}</strong> to a new container.</p>
            <div style="display:flex;flex-direction:column;gap:12px;">
                <div><label style="font-size:13px;color:var(--text-muted,#aaa);">New Name</label>
                    <input id="clone-new-name" type="text" value="${name}-clone" style="width:100%;padding:8px 12px;background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:6px;color:var(--text,#fff);margin-top:4px;"></div>
                <div><label style="font-size:13px;color:var(--text-muted,#aaa);">Target Node</label>
                    <select id="clone-target-node" style="width:100%;padding:8px 12px;background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:6px;color:var(--text,#fff);margin-top:4px;">
                        <option value="">This node (local clone)</option>
                        ${nodes.filter(n => !n.is_self && n.online).sort((a, b) => (a.hostname || a.address).localeCompare(b.hostname || b.address)).map(n => `<option value="${n.id}">${n.hostname} (${n.address})</option>`).join('')}
                    </select></div>
                <div><label style="font-size:13px;color:var(--text-muted,#aaa);">Storage</label>
                    <select id="clone-storage" style="width:100%;padding:8px 12px;background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:6px;color:var(--text,#fff);margin-top:4px;">
                        <option value="">Auto (default)</option>
                    </select></div>
                <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px;">
                    <button class="btn" onclick="document.getElementById('lxc-clone-modal')?.remove()">Cancel</button>
                    <button class="btn" style="background:var(--primary,#7c3aed);color:#fff;" onclick="doCloneLxc('${name}')">Clone</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Populate storage dropdown from /api/storage/list (proxied to the target node)
    try {
        const storageResp = await fetch(apiUrl('/api/storage/list'));
        if (storageResp.ok) {
            const storageData = await storageResp.json();
            const sel = document.getElementById('clone-storage');
            if (storageData.proxmox) {
                const stores = storageData.storages.filter(s =>
                    s.content && s.content.some(c => c === 'rootdir' || c === 'images')
                );
                (stores.length ? stores : storageData.storages.filter(s => s.status === 'active')).forEach(s => {
                    const free = formatBytes(s.available_bytes);
                    sel.insertAdjacentHTML('beforeend', `<option value="${s.id}">${s.id} (${s.storage_type}, ${free} free)</option>`);
                });
            } else if (storageData.paths) {
                storageData.paths.forEach(p => {
                    sel.insertAdjacentHTML('beforeend', `<option value="${p.path}">${p.path} (${formatBytes(p.free_bytes)} free)</option>`);
                });
            }
        }
    } catch (e) { }
}

async function doCloneLxc(name) {
    const newName = document.getElementById('clone-new-name').value.trim();
    const targetNode = document.getElementById('clone-target-node').value;
    const storage = document.getElementById('clone-storage').value.trim();
    if (!newName) { showToast('Enter a name for the clone', 'error'); return; }

    document.getElementById('lxc-clone-modal')?.remove();

    // Show progress modal
    const modal = document.createElement('div');
    modal.id = 'lxc-op-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:10000;backdrop-filter:blur(4px);';
    modal.innerHTML = `
        <div style="background:var(--card-bg,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;padding:28px 36px;min-width:400px;max-width:500px;box-shadow:0 20px 60px rgba(0,0,0,0.5);text-align:center;">
            <div style="width:48px;height:48px;border:4px solid var(--border,#555);border-top:4px solid var(--primary,#7c3aed);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 16px;"></div>
            <h3 style="margin:0 0 8px;color:var(--text,#fff);">Cloning Container</h3>
            <p id="lxc-op-status" style="margin:0;color:var(--text-muted,#aaa);font-size:0.9em;">Cloning <strong>${name}</strong> → <strong>${newName}</strong>${targetNode ? ' (remote)' : ''}...</p>
            <div id="lxc-op-result" style="display:none;margin-top:16px;padding:12px;border-radius:8px;text-align:left;font-size:0.9em;"></div>
            <button id="lxc-op-close" style="display:none;margin-top:12px;" class="btn" onclick="document.getElementById('lxc-op-modal')?.remove()">Close</button>
        </div>
    `;
    if (!document.getElementById('lxc-spin-style')) {
        const s = document.createElement('style'); s.id = 'lxc-spin-style';
        s.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
        document.head.appendChild(s);
    }
    document.body.appendChild(modal);

    try {
        const body = { new_name: newName };
        if (targetNode) body.target_node = targetNode;
        if (storage) body.storage = storage;

        const resp = await fetch(apiUrl(`/api/containers/lxc/${name}/clone`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        let data;
        try { data = await resp.json(); } catch { data = {}; }

        const resultEl = document.getElementById('lxc-op-result');
        const statusEl = document.getElementById('lxc-op-status');
        const spinner = modal.querySelector('div > div:first-child');
        if (spinner) spinner.style.display = 'none';
        document.getElementById('lxc-op-close').style.display = '';

        if (resp.ok) {
            statusEl.textContent = '✅ Clone complete!';
            resultEl.style.display = 'block';
            resultEl.style.background = 'rgba(16,185,129,0.15)';
            resultEl.style.color = '#10b981';
            resultEl.textContent = data.message || `Cloned as '${newName}'`;
            setTimeout(loadLxcContainers, 500);
        } else {
            statusEl.textContent = '❌ Clone failed';
            resultEl.style.display = 'block';
            resultEl.style.background = 'rgba(239,68,68,0.15)';
            resultEl.style.color = '#ef4444';
            resultEl.textContent = data.error || 'Unknown error';
        }
    } catch (e) {
        const resultEl = document.getElementById('lxc-op-result');
        const statusEl = document.getElementById('lxc-op-status');
        statusEl.textContent = '❌ Clone failed';
        resultEl.style.display = 'block';
        resultEl.style.background = 'rgba(239,68,68,0.15)';
        resultEl.style.color = '#ef4444';
        resultEl.textContent = e.message;
        document.getElementById('lxc-op-close').style.display = '';
    }
}

async function migrateLxcContainer(name) {
    // Fetch cluster nodes from LOCAL server (not proxied) — remote nodes don't have cluster info
    let nodes = [];
    try {
        const resp = await fetch('/api/nodes');
        if (resp.ok) {
            const data = await resp.json();
            nodes = Array.isArray(data) ? data : (data.nodes || []);
        }
    } catch (e) { }
    const remoteNodes = nodes.filter(n => !n.is_self && n.online)
        .sort((a, b) => (a.hostname || a.address).localeCompare(b.hostname || b.address));

    const modal = document.createElement('div');
    modal.id = 'lxc-migrate-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:10000;backdrop-filter:blur(4px);';
    modal.innerHTML = `
        <div style="background:var(--card-bg,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;padding:28px 36px;min-width:420px;max-width:520px;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
            <h3 style="margin:0 0 16px;color:var(--text,#fff);">🚀 Migrate Container</h3>
            <p style="margin:0 0 12px;color:var(--text-muted,#aaa);font-size:0.9em;">Move <strong>${name}</strong> to another node. The container will be stopped, transferred, and destroyed on this node.</p>
            <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:10px 12px;margin-bottom:16px;color:#ef4444;font-size:0.85em;">
                ⚠️ The container will experience downtime during migration.
            </div>
            <div style="display:flex;flex-direction:column;gap:12px;">
                <div><label style="font-size:13px;color:var(--text-muted,#aaa);">Migrate to</label>
                    <select id="migrate-target" style="width:100%;padding:8px 12px;background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:6px;color:var(--text,#fff);margin-top:4px;">
                        <option value="">— Select a cluster node —</option>
                        ${remoteNodes.map(n => `<option value="${n.id}">${n.hostname} (${n.address})</option>`).join('')}
                        <option value="__external__">External cluster...</option>
                    </select></div>
                <div><label style="font-size:13px;color:var(--text-muted,#aaa);">Target Storage</label>
                    <select id="migrate-storage" style="width:100%;padding:8px 12px;background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:6px;color:var(--text,#fff);margin-top:4px;">
                        <option value="">Auto (default)</option>
                    </select>
                    <span id="migrate-storage-hint" style="font-size:11px;color:var(--text-muted,#666);margin-top:2px;display:block;">Select a target node to load available storages</span></div>
                <div id="migrate-external-fields" style="display:none;">
                    <div style="background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:8px;padding:10px 12px;margin-bottom:12px;color:#60a5fa;font-size:0.82em;line-height:1.5;">
                        💡 <strong>Cross-cluster migration</strong> lets you move a container to a WolfStack instance on a different network.
                        On the <em>destination</em> cluster, go to <strong>LXC Containers → Generate Transfer Token</strong> to create a one-time token.
                        The token is valid for 30 minutes and authorises this node to push the container to that cluster.
                    </div>
                    <label style="font-size:13px;color:var(--text-muted,#aaa);">Target URL</label>
                    <input id="migrate-ext-url" type="text" placeholder="https://target.example.com:8553" style="width:100%;padding:8px 12px;background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:6px;color:var(--text,#fff);margin-top:4px;margin-bottom:8px;">
                    <label style="font-size:13px;color:var(--text-muted,#aaa);">Transfer Token</label>
                    <input id="migrate-ext-token" type="text" placeholder="wst_..." style="width:100%;padding:8px 12px;background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:6px;color:var(--text,#fff);margin-top:4px;">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px;">
                    <button class="btn" onclick="document.getElementById('lxc-migrate-modal')?.remove()">Cancel</button>
                    <button class="btn" style="background:#ef4444;color:#fff;" onclick="doMigrateLxc('${name}')">Migrate</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Show/hide external fields + fetch storages from selected target node
    document.getElementById('migrate-target').addEventListener('change', async (e) => {
        const val = e.target.value;
        document.getElementById('migrate-external-fields').style.display = val === '__external__' ? 'block' : 'none';

        // Fetch storages from the selected target node
        const sel = document.getElementById('migrate-storage');
        const hint = document.getElementById('migrate-storage-hint');
        sel.innerHTML = '<option value="">Auto (default)</option>';
        if (!val || val === '__external__') {
            hint.textContent = 'Select a target node to load available storages';
            return;
        }
        hint.textContent = 'Loading storages...';
        try {
            const resp = await fetch(`/api/nodes/${val}/proxy/storage/list`);
            if (resp.ok) {
                const data = await resp.json();
                const storages = data.storages || [];
                const suitable = storages.filter(s =>
                    s.content && s.content.some(c => c === 'rootdir' || c === 'images')
                );
                (suitable.length ? suitable : storages.filter(s => s.status === 'active')).forEach(s => {
                    const free = typeof formatBytes === 'function' ? formatBytes(s.available_bytes) : Math.round(s.available_bytes / 1073741824) + ' GB';
                    sel.insertAdjacentHTML('beforeend', `<option value="${s.id}">${s.id} (${s.type || ''}, ${free} free)</option>`);
                });
                hint.textContent = '';
            } else {
                hint.textContent = 'Could not load storages from target node';
            }
        } catch (err) {
            hint.textContent = 'Could not reach target node for storage list';
        }
    });
}

async function doMigrateLxc(name) {
    const target = document.getElementById('migrate-target').value;
    if (!target) { showToast('Select a target node', 'error'); return; }

    // Read values BEFORE removing the modal
    const extUrl = document.getElementById('migrate-ext-url')?.value.trim() || '';
    const extToken = document.getElementById('migrate-ext-token')?.value.trim() || '';
    const migrateStorage = document.getElementById('migrate-storage')?.value || '';
    document.getElementById('lxc-migrate-modal')?.remove();

    const isExternal = target === '__external__';
    if (isExternal && (!extUrl || !extToken)) { showToast('Enter URL and token', 'error'); return; }

    // Step definitions
    const steps = [
        { id: 'stop', label: 'Stopping container', icon: '⏹️' },
        { id: 'export', label: 'Creating archive (vzdump/tar)', icon: '📦' },
        { id: 'upload', label: isExternal ? `Uploading to ${extUrl.replace(/https?:\/\//, '').split('/')[0]}` : 'Transferring to target node', icon: '📤' },
        { id: 'import', label: 'Importing on target node', icon: '📥' },
        { id: 'cleanup', label: 'Cleaning up source', icon: '🧹' },
    ];

    // Progress modal with step list
    const modal = document.createElement('div');
    modal.id = 'lxc-op-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:10000;backdrop-filter:blur(4px);';
    modal.innerHTML = `
        <div style="background:var(--card-bg,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;padding:28px 36px;min-width:440px;max-width:540px;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
            <h3 style="margin:0 0 6px;color:var(--text,#fff);">🚀 Migrating Container</h3>
            <p style="margin:0 0 16px;color:var(--text-muted,#aaa);font-size:0.85em;">Moving <strong>${name}</strong> — this may take several minutes for large containers.</p>
            <div id="migrate-steps" style="display:flex;flex-direction:column;gap:6px;margin-bottom:16px;">
                ${steps.map((s, i) => `
                    <div id="mstep-${s.id}" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;background:var(--bg-secondary,#161622);transition:all 0.3s;">
                        <span class="mstep-icon" style="width:24px;text-align:center;font-size:14px;color:var(--text-muted,#555);">${s.icon}</span>
                        <span style="flex:1;font-size:0.88em;color:var(--text-muted,#666);">${s.label}</span>
                        <span class="mstep-status" style="font-size:12px;color:var(--text-muted,#555);min-width:20px;text-align:center;">⬜</span>
                    </div>
                `).join('')}
            </div>
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                <div id="migrate-spinner" style="width:20px;height:20px;border:3px solid var(--border,#555);border-top:3px solid #ef4444;border-radius:50%;animation:spin 1s linear infinite;flex-shrink:0;"></div>
                <span id="migrate-elapsed" style="font-size:0.82em;color:var(--text-muted,#888);">Elapsed: 0s</span>
            </div>
            <div id="lxc-op-result" style="display:none;margin-top:12px;padding:12px;border-radius:8px;text-align:left;font-size:0.9em;"></div>
            <button id="lxc-op-close" style="display:none;margin-top:12px;" class="btn" onclick="document.getElementById('lxc-op-modal')?.remove()">Close</button>
        </div>
    `;
    if (!document.getElementById('lxc-spin-style')) {
        const s = document.createElement('style'); s.id = 'lxc-spin-style';
        s.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
        document.head.appendChild(s);
    }
    document.body.appendChild(modal);

    // Elapsed timer
    const startTime = Date.now();
    const elapsedEl = document.getElementById('migrate-elapsed');
    const elapsedTimer = setInterval(() => {
        const secs = Math.floor((Date.now() - startTime) / 1000);
        const mins = Math.floor(secs / 60);
        elapsedEl.textContent = mins > 0 ? `Elapsed: ${mins}m ${secs % 60}s` : `Elapsed: ${secs}s`;
    }, 1000);

    // Step progress animation — advance through steps on realistic timers
    function setStepActive(stepId) {
        const el = document.getElementById('mstep-' + stepId);
        if (!el) return;
        el.style.background = 'rgba(124,58,237,0.15)';
        el.style.border = '1px solid rgba(124,58,237,0.3)';
        el.querySelector('.mstep-status').innerHTML = '<div style="width:14px;height:14px;border:2px solid var(--border,#555);border-top:2px solid #7c3aed;border-radius:50%;animation:spin 1s linear infinite;display:inline-block;"></div>';
        el.querySelector('span:nth-child(2)').style.color = 'var(--text,#fff)';
    }
    function setStepDone(stepId) {
        const el = document.getElementById('mstep-' + stepId);
        if (!el) return;
        el.style.background = 'rgba(16,185,129,0.08)';
        el.style.border = '1px solid rgba(16,185,129,0.2)';
        el.querySelector('.mstep-status').textContent = '✅';
        el.querySelector('span:nth-child(2)').style.color = '#10b981';
    }
    function setStepFailed(stepId) {
        const el = document.getElementById('mstep-' + stepId);
        if (!el) return;
        el.style.background = 'rgba(239,68,68,0.1)';
        el.style.border = '1px solid rgba(239,68,68,0.2)';
        el.querySelector('.mstep-status').textContent = '❌';
        el.querySelector('span:nth-child(2)').style.color = '#ef4444';
    }

    // Animate steps on realistic timers (the backend is doing these steps sequentially)
    let currentStep = 0;
    const stepTimings = [2000, 8000, 15000, 20000]; // cumulative approximate timings; upload is the longest
    const stepTimers = [];

    setStepActive(steps[0].id);
    for (let i = 0; i < stepTimings.length; i++) {
        stepTimers.push(setTimeout(() => {
            setStepDone(steps[i].id);
            if (i + 1 < steps.length) {
                setStepActive(steps[i + 1].id);
                currentStep = i + 1;
            }
        }, stepTimings[i]));
    }

    try {
        let resp;
        if (isExternal) {
            resp = await fetch(apiUrl(`/api/containers/lxc/${name}/migrate-external`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url: extUrl, target_token: extToken, delete_source: true }),
            });
        } else {
            const migrateBody = { target_node: target };
            if (migrateStorage) migrateBody.storage = migrateStorage;
            resp = await fetch(apiUrl(`/api/containers/lxc/${name}/migrate`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(migrateBody),
            });
        }

        // Clear step timers — backend has finished
        stepTimers.forEach(t => clearTimeout(t));
        clearInterval(elapsedTimer);
        const totalSecs = Math.floor((Date.now() - startTime) / 1000);
        const totalMins = Math.floor(totalSecs / 60);
        elapsedEl.textContent = totalMins > 0 ? `Completed in ${totalMins}m ${totalSecs % 60}s` : `Completed in ${totalSecs}s`;

        let data;
        try { data = await resp.json(); } catch { data = {}; }

        const resultEl = document.getElementById('lxc-op-result');
        const spinner = document.getElementById('migrate-spinner');
        if (spinner) spinner.style.display = 'none';
        document.getElementById('lxc-op-close').style.display = '';

        if (resp.ok) {
            // Mark all steps done
            steps.forEach(s => setStepDone(s.id));
            resultEl.style.display = 'block';
            resultEl.style.background = 'rgba(16,185,129,0.15)';
            resultEl.style.color = '#10b981';
            resultEl.textContent = data.message || 'Migrated successfully';
            setTimeout(loadLxcContainers, 500);
        } else {
            // Mark current step as failed, leave rest as pending
            steps.slice(0, currentStep).forEach(s => setStepDone(s.id));
            setStepFailed(steps[currentStep].id);
            resultEl.style.display = 'block';
            resultEl.style.background = 'rgba(239,68,68,0.15)';
            resultEl.style.color = '#ef4444';
            resultEl.textContent = data.error || 'Unknown error';
        }
    } catch (e) {
        stepTimers.forEach(t => clearTimeout(t));
        clearInterval(elapsedTimer);
        steps.slice(0, currentStep).forEach(s => setStepDone(s.id));
        setStepFailed(steps[currentStep].id);
        const spinner = document.getElementById('migrate-spinner');
        if (spinner) spinner.style.display = 'none';
        const r = document.getElementById('lxc-op-result');
        r.style.display = 'block'; r.style.background = 'rgba(239,68,68,0.15)'; r.style.color = '#ef4444';
        r.textContent = e.message;
        document.getElementById('lxc-op-close').style.display = '';
    }
}

async function exportLxcContainer(name) {
    if (!confirm(`Export container '${name}'? The container will be briefly stopped.`)) return;
    showToast(`Exporting ${name}...`, 'info');

    try {
        const resp = await fetch(apiUrl(`/api/containers/lxc/${name}/export`), { method: 'POST' });
        if (!resp.ok) {
            let data;
            try { data = await resp.json(); } catch { data = {}; }
            showToast(data.error || 'Export failed', 'error');
            return;
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}-export.tar.gz`;
        a.click();
        URL.revokeObjectURL(url);
        showToast(`Exported ${name} — downloading...`, 'success');
    } catch (e) {
        showToast(`Export failed: ${e.message}`, 'error');
    }
}

async function generateTransferToken() {
    try {
        const resp = await fetch(apiUrl('/api/containers/transfer-token'), { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) { showToast(data.error || 'Failed', 'error'); return; }

        const modal = document.createElement('div');
        modal.id = 'transfer-token-modal';
        modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:10000;backdrop-filter:blur(4px);';
        modal.innerHTML = `
            <div style="background:var(--card-bg,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;padding:28px 36px;min-width:400px;max-width:500px;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
                <h3 style="margin:0 0 12px;color:var(--text,#fff);">🔑 Transfer Token Generated</h3>
                <p style="color:var(--text-muted,#aaa);font-size:0.9em;margin-bottom:16px;">
                    Share this token with the source cluster admin. It expires in 30 minutes and can only be used once.
                </p>
                <div style="background:var(--bg-primary,#111);border:1px solid var(--border,#444);border-radius:8px;padding:12px;font-family:monospace;font-size:13px;color:var(--text,#fff);word-break:break-all;margin-bottom:12px;">${data.token}</div>
                <div style="display:flex;gap:8px;justify-content:flex-end;">
                    <button class="btn" onclick="navigator.clipboard.writeText('${data.token}');showToast('Token copied!','success')">📋 Copy</button>
                    <button class="btn" onclick="document.getElementById('transfer-token-modal')?.remove()">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
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
let lxcTemplatesCacheNodeId = null;

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
        // Invalidate cache when switching nodes (Proxmox vs standalone have different templates)
        if (!lxcTemplatesCache || lxcTemplatesCacheNodeId !== currentNodeId) {
            const resp = await fetch(apiUrl('/api/containers/lxc/templates'));
            lxcTemplatesCache = await resp.json();
            lxcTemplatesCacheNodeId = currentNodeId;
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
    return templates.map(t => {
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

    // Populate storage dropdown from /api/storage/list (Proxmox-aware)
    const storageSelect = document.getElementById('lxc-create-storage');
    const storageInfo = document.getElementById('lxc-storage-info');
    fetch(apiUrl('/api/storage/list'))
        .then(r => r.json())
        .then(data => {
            storageSelect.innerHTML = '';
            if (data.proxmox) {
                // Proxmox: show PVE storage IDs
                const rootdirStorages = data.storages.filter(s =>
                    s.content && s.content.some(c => c === 'rootdir' || c === 'images')
                );
                if (rootdirStorages.length === 0) {
                    // Fallback: show all active storages
                    data.storages.filter(s => s.status === 'active').forEach(s => {
                        const free = formatBytes(s.available_bytes);
                        storageSelect.innerHTML += `<option value="${s.id}">${s.id} (${s.type}, ${free} free)</option>`;
                    });
                } else {
                    rootdirStorages.forEach(s => {
                        const free = formatBytes(s.available_bytes);
                        const def = s.id === 'local-lvm' ? ' (default)' : '';
                        storageSelect.innerHTML += `<option value="${s.id}"${def ? ' selected' : ''}>${s.id} (${s.type}, ${free} free)${def}</option>`;
                    });
                }
                storageInfo.textContent = 'Proxmox storage';
            } else {
                // Standalone: show filesystem mount points
                const defaultOpt = `<option value="/var/lib/lxc">/var/lib/lxc (default)</option>`;
                storageSelect.innerHTML = defaultOpt;
                data.storages.forEach(s => {
                    if (s.id !== '/') {
                        const free = formatBytes(s.available_bytes);
                        const path = s.id + '/lxc';
                        storageSelect.innerHTML += `<option value="${path}">${path} (${free} free)</option>`;
                    }
                });
            }
            storageSelect.onchange = () => {
                const sel = storageSelect.value;
                const match = data.storages.find(s => sel.startsWith(s.id));
                storageInfo.textContent = match ? `${formatBytes(match.available_bytes)} free` : '';
            };
        })
        .catch(() => {
            // Fallback to old disk metrics approach
            const node = currentNodeId ? allNodes.find(n => n.id === currentNodeId) : null;
            if (node?.metrics?.disks) {
                storageSelect.innerHTML = '<option value="/var/lib/lxc">/var/lib/lxc (default)</option>';
                node.metrics.disks.forEach(d => {
                    if (d.mount_point !== '/' && d.available_bytes > 1073741824) {
                        const free = formatBytes(d.available_bytes);
                        const path = d.mount_point + '/lxc';
                        storageSelect.innerHTML += `<option value="${path}">${path} (${free} free)</option>`;
                    }
                });
            }
        });

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

    // Show progress modal
    closeContainerDetail();
    const modal = document.createElement('div');
    modal.id = 'lxc-create-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:10000;backdrop-filter:blur(4px);';
    modal.innerHTML = `
        <div style="background:var(--card-bg,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;padding:32px 40px;min-width:420px;max-width:520px;box-shadow:0 20px 60px rgba(0,0,0,0.5);text-align:center;">
            <div id="lxc-create-spinner" style="margin-bottom:16px;">
                <div style="width:48px;height:48px;border:4px solid var(--border,#555);border-top:4px solid var(--primary,#7c3aed);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto;"></div>
            </div>
            <h3 id="lxc-create-title" style="margin:0 0 8px 0;color:var(--text,#fff);font-size:1.2em;">Creating Container</h3>
            <p id="lxc-create-status" style="margin:0 0 16px 0;color:var(--text-muted,#aaa);font-size:0.95em;">
                Preparing <strong>${name}</strong> (${distribution} ${release})...
            </p>
            <div id="lxc-create-steps" style="text-align:left;font-size:0.85em;color:var(--text-muted,#999);line-height:1.8;margin-bottom:16px;">
                <div id="step-template" style="opacity:1;">⏳ Downloading template...</div>
                <div id="step-create" style="opacity:0.4;">⬜ Creating container...</div>
                <div id="step-config" style="opacity:0.4;">⬜ Applying configuration...</div>
            </div>
            <div id="lxc-create-result" style="display:none;padding:12px;border-radius:8px;margin-bottom:16px;text-align:left;font-size:0.9em;word-break:break-word;max-height:200px;overflow-y:auto;"></div>
            <button id="lxc-create-close-btn" style="display:none;" class="btn" onclick="document.getElementById('lxc-create-modal')?.remove()">Close</button>
        </div>
    `;
    // Add spin animation if not already present
    if (!document.getElementById('lxc-spin-style')) {
        const style = document.createElement('style');
        style.id = 'lxc-spin-style';
        style.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
        document.head.appendChild(style);
    }
    document.body.appendChild(modal);

    const updateStep = (stepId, icon, text, active) => {
        const el = document.getElementById(stepId);
        if (el) { el.innerHTML = `${icon} ${text}`; el.style.opacity = active ? '1' : '0.4'; }
    };
    const setStatus = (text) => {
        const el = document.getElementById('lxc-create-status');
        if (el) el.innerHTML = text;
    };
    const showResult = (success, message) => {
        const spinner = document.getElementById('lxc-create-spinner');
        const title = document.getElementById('lxc-create-title');
        const result = document.getElementById('lxc-create-result');
        const closeBtn = document.getElementById('lxc-create-close-btn');
        if (spinner) spinner.innerHTML = success
            ? '<div style="font-size:48px;">✅</div>'
            : '<div style="font-size:48px;">❌</div>';
        if (title) title.textContent = success ? 'Container Created' : 'Creation Failed';
        if (result) {
            result.style.display = 'block';
            result.style.background = success ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)';
            result.style.border = success ? '1px solid rgba(34,197,94,0.3)' : '1px solid rgba(239,68,68,0.3)';
            result.style.color = success ? 'var(--success,#22c55e)' : 'var(--error,#ef4444)';
            result.textContent = message;
        }
        if (closeBtn) closeBtn.style.display = 'inline-block';
    };

    // Step 1: Template & creation (all happens server-side in one call)
    updateStep('step-template', '⏳', 'Downloading template (this may take a minute)...', true);
    setStatus(`Creating <strong>${name}</strong> on ${storage_path || 'default storage'}...`);

    try {
        const resp = await fetch(apiUrl('/api/containers/lxc/create'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, distribution, release, architecture, wolfnet_ip, storage_path, root_password, memory_limit, cpu_cores }),
        });

        let data;
        const contentType = resp.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            data = await resp.json();
        } else {
            const text = await resp.text();
            data = { error: text || `HTTP ${resp.status}: ${resp.statusText}` };
        }

        if (resp.ok) {
            updateStep('step-template', '✅', 'Template ready', true);
            updateStep('step-create', '✅', 'Container created', true);

            // Step 3: Apply mounts if any
            if (mounts.length > 0) {
                updateStep('step-config', '⏳', `Applying ${mounts.length} mount(s)...`, true);
                for (const mount of mounts) {
                    try {
                        await fetch(apiUrl(`/api/containers/lxc/${encodeURIComponent(name)}/mounts`), {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(mount),
                        });
                    } catch (e) { /* mount warning */ }
                }
            }
            updateStep('step-config', '✅', 'Configuration applied', true);

            const msg = data.message || `Container '${name}' created successfully`;
            showResult(true, msg);
            setTimeout(loadLxcContainers, 500);
        } else {
            updateStep('step-template', '❌', 'Failed', true);
            const errMsg = data.error || data.message || `HTTP ${resp.status}: Creation failed`;
            showResult(false, errMsg);
        }
    } catch (e) {
        updateStep('step-template', '❌', 'Connection error', true);
        let errMsg = e.message || 'Unknown error';
        if (errMsg.includes('Failed to fetch') || errMsg.includes('NetworkError')) {
            errMsg = 'Request timed out or connection lost. The template download may still be running on the server. Check the Proxmox UI or try again in a few minutes.';
        }
        showResult(false, errMsg);
    }
}

// ─── Console Logic ───
let consoleTerm = null;
let consoleWs = null;
let consoleFitAddon = null;

function openConsole(type, name) {
    let url = '/console.html?type=' + encodeURIComponent(type) + '&name=' + encodeURIComponent(name);
    // For remote nodes, pass the node_id so the console proxies through the local server
    if (currentNodeId) {
        const node = allNodes.find(n => n.id === currentNodeId);
        if (node && !node.is_self) {
            url += '&node_id=' + encodeURIComponent(node.id);
        }
    }
    window.open(url, 'console_' + name, 'width=960,height=600,menubar=no,toolbar=no');
}

// ─── Inline Terminal (rendered inside the page content area) ───
let inlineTerminal = null;
let inlineTermWs = null;
let inlineTermType = '';
let inlineTermName = '';

function openInlineTerminal(type, name, opts = {}) {
    inlineTermType = type;
    inlineTermName = name;

    // Clean up previous terminal
    if (inlineTermWs) { try { inlineTermWs.close(); } catch (e) { } inlineTermWs = null; }
    if (inlineTerminal) { inlineTerminal.dispose(); inlineTerminal = null; }

    const container = document.getElementById('inline-terminal-container');
    if (!container) return;
    container.innerHTML = '';

    const nameEl = document.getElementById('inline-term-name');
    if (nameEl) nameEl.textContent = name + (type !== 'host' ? ` (${type})` : '');

    const statusEl = document.getElementById('inline-term-status');
    if (statusEl) { statusEl.textContent = 'Connecting...'; statusEl.style.background = '#333'; statusEl.style.color = '#888'; }

    // Create xterm.js terminal
    const term = new Terminal({
        cursorBlink: true,
        fontSize: 15,
        fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", "Courier New", monospace',
        theme: { background: '#0a0a0a', foreground: '#f0f0f0', cursor: '#10b981', selectionBackground: 'rgba(16, 185, 129, 0.3)' },
        scrollback: 5000
    });
    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);
    inlineTerminal = term;

    function doFit() { try { fitAddon.fit(); } catch (e) { } }
    setTimeout(doFit, 100);
    window._inlineTermFitHandler = () => { if (currentPage === 'terminal') doFit(); };
    window.addEventListener('resize', window._inlineTermFitHandler);

    term.writeln('\x1b[33mConnecting to ' + type + ': ' + name + '...\x1b[0m');

    // Build WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let wsUrl;
    if (opts.pve_node_id && opts.pve_vmid !== undefined) {
        wsUrl = protocol + '//' + window.location.host + '/ws/pve-console/' + opts.pve_node_id + '/' + opts.pve_vmid;
    } else if (currentNodeId) {
        const node = allNodes.find(n => n.id === currentNodeId);
        if (node && !node.is_self) {
            wsUrl = protocol + '//' + window.location.host + '/ws/remote-console/' + encodeURIComponent(currentNodeId) + '/' + type + '/' + encodeURIComponent(name);
        } else {
            wsUrl = protocol + '//' + window.location.host + '/ws/console/' + type + '/' + encodeURIComponent(name);
        }
    } else {
        wsUrl = protocol + '//' + window.location.host + '/ws/console/' + type + '/' + encodeURIComponent(name);
    }

    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    inlineTermWs = ws;

    ws.onopen = () => {
        if (statusEl) { statusEl.textContent = 'Connected'; statusEl.style.background = 'rgba(16,185,129,0.15)'; statusEl.style.color = '#10b981'; }
        term.writeln('\x1b[32mConnected!\x1b[0m\r\n');
        doFit();
        term.focus();
    };
    ws.onmessage = (event) => {
        if (typeof event.data === 'string') term.write(event.data);
        else term.write(new Uint8Array(event.data));
    };
    ws.onclose = () => {
        if (statusEl) { statusEl.textContent = 'Disconnected'; statusEl.style.background = 'rgba(239,68,68,0.15)'; statusEl.style.color = '#ef4444'; }
        term.writeln('\r\n\x1b[31mConnection closed.\x1b[0m');
    };
    ws.onerror = () => {
        if (statusEl) { statusEl.textContent = 'Error'; statusEl.style.background = 'rgba(239,68,68,0.15)'; statusEl.style.color = '#ef4444'; }
        term.writeln('\r\n\x1b[31mWebSocket connection failed.\x1b[0m');
    };
    term.onData(data => { if (ws.readyState === WebSocket.OPEN) ws.send(data); });
}

function openLxcConsole(vmidOrName, displayName) {
    // For Proxmox nodes, use PVE console proxy with the VMID
    if (currentNodeId) {
        const node = allNodes.find(n => n.id === currentNodeId);
        if (node && node.node_type === 'proxmox') {
            openPveConsole(currentNodeId, vmidOrName, displayName || vmidOrName);
            return;
        }
    }
    // Native LXC — use standard console
    openConsole('lxc', vmidOrName);
}

function openVmConsole(name) {
    openConsole('vm', name);
}

function openPveConsole(nodeId, vmid, displayName) {
    const url = '/console.html?type=pve&name=' + encodeURIComponent(displayName || 'VMID ' + vmid)
        + '&pve_node_id=' + encodeURIComponent(nodeId)
        + '&pve_vmid=' + encodeURIComponent(vmid);
    window.open(url, 'pve_console_' + vmid, 'width=960,height=600,menubar=no,toolbar=no');
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

// ─── Backup Management ───

async function loadBackups() {
    try {
        const [backupsRes, schedulesRes, targetsRes] = await Promise.all([
            fetch(apiUrl('/api/backups')),
            fetch(apiUrl('/api/backups/schedules')),
            fetch(apiUrl('/api/backups/targets')),
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

            const res = await fetch(apiUrl('/api/backups'), {
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
                    const res = await fetch(apiUrl('/api/backups'), {
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
        const res = await fetch(apiUrl(`/api/backups/${id}`), { method: 'DELETE' });
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
        const res = await fetch(apiUrl(`/api/backups/${id}/restore`), { method: 'POST' });
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
        const res = await fetch(apiUrl('/api/backups/schedules'), {
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
        const res = await fetch(apiUrl(`/api/backups/schedules/${id}`), { method: 'DELETE' });
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

    fetch('https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/Cargo.toml')
        .then(function (r) { return r.text(); })
        .then(function (text) {
            var match = text.match(/^version\s*=\s*"([^"]+)"/m);
            if (!match) return;
            var latestVersion = match[1];
            if (isNewerVersion(latestVersion, currentVersion)) {
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

// Returns true if 'latest' is strictly newer than 'current' (semver comparison)
function isNewerVersion(latest, current) {
    var l = latest.split('.').map(Number);
    var c = current.split('.').map(Number);
    for (var i = 0; i < Math.max(l.length, c.length); i++) {
        var lv = l[i] || 0;
        var cv = c[i] || 0;
        if (lv > cv) return true;
        if (lv < cv) return false;
    }
    return false;
}

// Check for updates on page load, then every 6 hours
setTimeout(checkForUpdates, 5000);
setInterval(checkForUpdates, 6 * 60 * 60 * 1000);

function triggerUpgrade() {
    var bannerText = document.getElementById('update-banner-text');
    var msg = bannerText ? bannerText.textContent : 'Update available';

    // Determine which node we're upgrading
    var targetNode = null;
    var isLocal = true;
    if (currentNodeId) {
        targetNode = allNodes.find(n => n.id === currentNodeId);
        if (targetNode && !targetNode.is_self) {
            isLocal = false;
        }
    }

    var machine = isLocal ? 'this machine (local)' : (targetNode ? targetNode.hostname + ' (' + targetNode.address + ')' : 'this machine');
    if (!confirm('⚡ ' + msg + '\n\nThis will run the WolfStack upgrade script on ' + machine + '.\nA terminal window will open so you can monitor the progress.\n\nProceed?')) return;

    // Open console popup with type=upgrade to stream live output
    var url = '/console.html?type=upgrade&name=wolfstack';
    if (targetNode && !targetNode.is_self) {
        url += '&node_id=' + encodeURIComponent(targetNode.id);
    }
    window.open(url, 'upgrade_console', 'width=960,height=600,menubar=no,toolbar=no');

    // Hide the update banner
    var banner = document.getElementById('update-banner');
    if (banner) banner.style.display = 'none';

    showToast('Upgrade started — watch the terminal window for progress.', 'info');
}

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
    selectView('settings');
    switchSettingsTab('ai');
}

async function loadAiConfig() {
    try {
        var resp = await fetch('/api/ai/config');
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
        if ((el = document.getElementById('ai-smtp-tls'))) el.value = cfg.smtp_tls || 'starttls';
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
        var resp = await fetch('/api/ai/models?provider=' + encodeURIComponent(provider));
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
        smtp_tls: (document.getElementById('ai-smtp-tls') || {}).value || 'starttls',
        check_interval_minutes: parseInt((document.getElementById('ai-check-interval') || {}).value) || 60,
    };
    try {
        var resp = await fetch('/api/ai/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        var data = await resp.json();
        if (data.status === 'saved') {
            showModal('Settings Saved');
            loadAiStatus();
            // Show the AI chat bubble now that it's configured
            var bubble = document.getElementById('ai-chat-bubble');
            if (bubble) bubble.style.display = 'flex';
            // Refresh models list after save (in case key changed)
            fetchAiModels(config.provider, config.model);
        } else {
            showModal('Error: ' + (data.error || 'Failed to save'));
        }
    } catch (e) {
        showModal('Error: ' + e.message);
    }
}

async function loadAiStatus() {
    try {
        var resp = await fetch('/api/ai/status');
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
        var resp = await fetch('/api/ai/alerts');
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
        smtp_tls: (document.getElementById('ai-smtp-tls') || {}).value || 'starttls',
        check_interval_minutes: parseInt((document.getElementById('ai-check-interval') || {}).value) || 60,
    };
    try {
        // Save first
        await fetch('/api/ai/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        // Now test
        var resp = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: 'Say "Hello! AI Agent is working." in one short sentence.' })
        });
        var data = await resp.json();
        if (data.error) {
            showModal('AI Error: ' + data.error);
        } else {
            showModal('✅ AI responded: ' + (data.response || '').substring(0, 200));
        }
    } catch (e) {
        showModal('Connection failed: ' + e.message);
    }
}

async function sendTestEmail() {
    try {
        var resp = await fetch('/api/ai/test-email', { method: 'POST' });
        var data = await resp.json();
        if (data.error) {
            showModal('❌ ' + data.error, 'Email Error');
        } else {
            showModal('✅ ' + (data.message || 'Test email sent!'), 'Email Sent');
        }
    } catch (e) {
        showModal('Failed to send test email: ' + e.message, 'Email Error');
    }
}

function onAiProviderChange() {
    var provider = (document.getElementById('ai-provider') || {}).value || 'claude';
    fetchAiModels(provider, '');
}

// ─── Config Export / Import ───

async function exportConfig() {
    try {
        const res = await fetch('/api/config/export', { credentials: 'include' });
        if (!res.ok) throw new Error('Export failed: ' + res.status);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'wolfstack-config.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Config exported successfully', 'success');
    } catch (e) {
        showToast('Export failed: ' + e.message, 'error');
    }
}

async function importConfigFile(input) {
    const file = input.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const json = JSON.parse(text);

        if (!confirm('Import config from "' + (json.exported_from || 'unknown') +
            '" (exported ' + (json.exported_at || 'unknown') + ')?\n\n' +
            'This will merge cluster nodes and overwrite settings.')) {
            input.value = '';
            return;
        }

        const res = await fetch('/api/config/import', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: text,
        });

        const result = await res.json();
        if (res.ok) {
            showToast(result.message || 'Config imported successfully', 'success');
            // Refresh the node list
            setTimeout(() => fetchNodes(), 1000);
        } else {
            showToast(result.error || 'Import failed', 'error');
        }
    } catch (e) {
        showToast('Import failed: ' + e.message, 'error');
    }

    input.value = '';
}

// ─── MySQL Database Editor ───

let mysqlCreds = null; // { host, port, user, password }
let mysqlCurrentDb = null;
let mysqlCurrentTable = null;
let mysqlCurrentPage = 0;
let mysqlPageSize = 50;
let mysqlTotalPages = 0;
let mysqlDatabases = [];

function loadMySQLEditor() {
    // ── Full state reset when switching nodes ──
    mysqlDisconnect();

    const banner = document.getElementById('mysql-detect-banner');
    banner.style.display = 'none';

    // Always use localhost — API calls are proxied to the target node via
    // /api/nodes/{id}/proxy/..., so the backend connects to MySQL locally.
    const hostInput = document.getElementById('mysql-host');
    hostInput.value = 'localhost';
    document.getElementById('mysql-port').value = '3306';
    document.getElementById('mysql-user').value = '';
    document.getElementById('mysql-pass').value = '';

    // Reset container dropdown
    const containerSelect = document.getElementById('mysql-container-select');
    containerSelect.style.display = 'none';
    containerSelect.innerHTML = '<option value="">Manual connection</option>';

    // Detect MySQL on this node
    const nodeId = currentNodeId;
    const baseUrl = nodeId ? getNodeApiBase(nodeId) : '';
    fetch(`${baseUrl}/api/mysql/detect`, { credentials: 'include' })
        .then(r => r.json())
        .then(data => {
            banner.style.display = 'block';
            if (data.installed) {
                banner.innerHTML = `<div style="padding:8px 14px; background:rgba(46,204,113,0.1); border:1px solid rgba(46,204,113,0.3); border-radius:6px; font-size:12px; color:#2ecc71;">
                    ✅ MySQL detected — ${data.version || 'installed'} ${data.service_running ? '• Service running' : '• Service not running'}
                </div>`;
            } else {
                banner.innerHTML = `<div style="padding:8px 14px; background:rgba(231,76,60,0.1); border:1px solid rgba(231,76,60,0.3); border-radius:6px; font-size:12px; color:#e74c3c;">
                    ⚠️ MySQL not detected on this node. You can still connect to a remote MySQL server using the connection bar above.
                </div>`;
            }
        })
        .catch(() => { });

    // Detect MySQL containers (Docker/LXC)
    fetch(`${baseUrl}/api/mysql/detect-containers`, { credentials: 'include' })
        .then(r => r.json())
        .then(data => {
            const containers = data.containers || [];
            if (containers.length === 0) return;

            containerSelect.innerHTML = '<option value="">Manual connection</option>';
            containers.forEach((c, i) => {
                const label = `🐳 ${c.name} (${c.image}) — ${c.host}:${c.port}`;
                containerSelect.innerHTML += `<option value="${i}">${label}</option>`;
            });
            containerSelect.style.display = 'inline-block';

            // Store for selection handler
            containerSelect._containers = containers;
        })
        .catch(() => { });
}

/** When user selects a container from the dropdown, auto-fill connection fields */
function mysqlSelectContainer(idx) {
    const containerSelect = document.getElementById('mysql-container-select');
    const containers = containerSelect._containers || [];
    if (idx === '' || !containers[idx]) {
        // "Manual connection" selected — reset to localhost
        document.getElementById('mysql-host').value = 'localhost';
        document.getElementById('mysql-port').value = '3306';
        return;
    }
    const c = containers[idx];
    document.getElementById('mysql-host').value = c.host;
    document.getElementById('mysql-port').value = c.port;
}


function getNodeApiBase(nodeId) {
    if (!nodeId) return '';
    const node = allNodes.find(n => n.id === nodeId);
    if (node && node.is_self) return '';
    return `/api/nodes/${nodeId}/proxy`;
}

async function mysqlConnect() {
    const host = document.getElementById('mysql-host').value.trim() || 'localhost';
    const port = parseInt(document.getElementById('mysql-port').value) || 3306;
    const user = document.getElementById('mysql-user').value.trim();
    const pass = document.getElementById('mysql-pass').value;

    if (!user) {
        showToast('Please enter a MySQL username', 'error');
        return;
    }

    const btn = document.getElementById('mysql-connect-btn');
    btn.disabled = true;
    btn.textContent = '⏳ Connecting...';

    const badge = document.getElementById('mysql-status-badge');
    badge.textContent = 'Connecting...';
    badge.style.background = 'rgba(241,196,15,0.15)';
    badge.style.color = '#f1c40f';

    // 8-second timeout so the UI never gets stuck
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/connect`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host, port, user, password: pass }),
            signal: controller.signal,
        });
        clearTimeout(timeoutId);

        // Try to parse JSON — handle non-200 responses too
        let data;
        try {
            data = await resp.json();
        } catch (jsonErr) {
            const text = 'Server returned non-JSON response (HTTP ' + resp.status + ')';
            badge.textContent = 'Error';
            badge.style.background = 'rgba(231,76,60,0.15)';
            badge.style.color = '#e74c3c';
            showToast(text, 'error');
            return;
        }

        // If the HTTP response itself failed (proxy error, server error, etc.)
        if (!resp.ok) {
            const errMsg = data.error || ('Server error: HTTP ' + resp.status);
            badge.textContent = 'Connection failed';
            badge.style.background = 'rgba(231,76,60,0.15)';
            badge.style.color = '#e74c3c';
            showToast(errMsg, 'error');
            return;
        }

        if (data.connected) {
            mysqlCreds = { host, port, user, password: pass };
            badge.textContent = `Connected — MySQL ${data.version}`;
            badge.style.background = 'rgba(46,204,113,0.15)';
            badge.style.color = '#2ecc71';

            btn.style.display = 'none';
            document.getElementById('mysql-disconnect-btn').style.display = '';

            // Show main editor
            const main = document.getElementById('mysql-editor-main');
            main.style.display = 'flex';

            // Load databases
            await mysqlLoadDatabases();
            showToast('Connected to MySQL ' + data.version, 'success');
        } else {
            badge.textContent = 'Connection failed';
            badge.style.background = 'rgba(231,76,60,0.15)';
            badge.style.color = '#e74c3c';
            showToast(data.error || 'Connection failed — no details returned by server', 'error');
        }
    } catch (e) {
        clearTimeout(timeoutId);
        const msg = e.name === 'AbortError'
            ? 'Connection timed out after 8s — check host/port and ensure MySQL is reachable'
            : 'Network error: ' + (e.message || e);
        badge.textContent = 'Error';
        badge.style.background = 'rgba(231,76,60,0.15)';
        badge.style.color = '#e74c3c';
        showToast(msg, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = '🔌 Connect';
    }
}

function mysqlDisconnect() {
    mysqlCreds = null;
    mysqlCurrentDb = null;
    mysqlCurrentTable = null;
    mysqlDatabases = [];

    const badge = document.getElementById('mysql-status-badge');
    badge.textContent = 'Not connected';
    badge.style.background = 'var(--bg-tertiary)';
    badge.style.color = 'var(--text-muted)';

    document.getElementById('mysql-connect-btn').style.display = '';
    document.getElementById('mysql-disconnect-btn').style.display = 'none';
    document.getElementById('mysql-editor-main').style.display = 'none';

    // Reset panels
    document.getElementById('mysql-db-tree').innerHTML =
        '<div style="padding:16px; color:var(--text-muted); text-align:center; font-size:12px;">Connect to see databases</div>';
    document.getElementById('mysql-data-grid').innerHTML =
        '<div style="padding:40px; text-align:center; color:var(--text-muted);">Select a table from the left panel to view data</div>';
    document.getElementById('mysql-struct-columns').innerHTML =
        '<div style="padding:40px; text-align:center; color:var(--text-muted);">Select a table to view its structure</div>';
    document.getElementById('mysql-struct-indexes').innerHTML = '';
    document.getElementById('mysql-struct-triggers').innerHTML = '';
    document.getElementById('mysql-pagination').style.display = 'none';
    document.getElementById('mysql-table-info').innerHTML = '';

    showToast('Disconnected from MySQL', 'info');
}

async function mysqlLoadDatabases() {
    if (!mysqlCreds) return;

    const tree = document.getElementById('mysql-db-tree');
    tree.innerHTML = '<div style="padding:16px; text-align:center; color:var(--text-muted); font-size:12px;">Loading...</div>';

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/databases`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(mysqlCreds),
        });

        let data;
        try {
            data = await resp.json();
        } catch (jsonErr) {
            tree.innerHTML = `<div style="padding:16px; text-align:center; color:#e74c3c; font-size:12px;">Server returned non-JSON response (HTTP ${resp.status})</div>`;
            return;
        }

        if (!resp.ok || data.error) {
            tree.innerHTML = `<div style="padding:16px; text-align:center; color:#e74c3c; font-size:12px;">${data.error || 'Server error: HTTP ' + resp.status}</div>`;
            return;
        }

        mysqlDatabases = data.databases || [];

        // Update query tab database selector
        const queryDbSelect = document.getElementById('mysql-query-db');
        queryDbSelect.innerHTML = '<option value="">-- select --</option>' +
            mysqlDatabases.map(db => `<option value="${db}">${db}</option>`).join('');

        // Render tree
        let html = '';
        for (const db of mysqlDatabases) {
            const isSystem = ['information_schema', 'performance_schema', 'mysql', 'sys'].includes(db);
            html += `<div class="mysql-db-node" data-db="${db}">
                <div style="padding:5px 14px; cursor:pointer; display:flex; align-items:center; gap:6px; transition:background 0.15s;"
                     onmouseover="this.style.background='var(--bg-tertiary)'" onmouseout="this.style.background='none'">
                    <span onclick="mysqlToggleDb('${db}')" style="display:flex; align-items:center; gap:6px; flex:1;">
                        <span class="mysql-db-arrow" id="mysql-arrow-${db}" style="font-size:10px; transition:transform 0.2s; display:inline-block;">▶</span>
                        <span style="font-size:14px;">${isSystem ? '🔧' : '📁'}</span>
                        <span style="color:var(--text-primary); font-size:12px; ${isSystem ? 'opacity:0.6;' : ''}">${db}</span>
                    </span>
                    <button onclick="event.stopPropagation(); mysqlDumpDatabase('${db}')" style="background:none; border:none; cursor:pointer; font-size:12px; opacity:0.5; padding:2px 4px;" title="Dump SQL" onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.5'">💾</button>
                </div>
                <div id="mysql-tables-${db}" style="display:none; padding-left:28px;"></div>
            </div>`;
        }
        tree.innerHTML = html || '<div style="padding:16px; text-align:center; color:var(--text-muted); font-size:12px;">No databases found</div>';

    } catch (e) {
        tree.innerHTML = `<div style="padding:16px; text-align:center; color:#e74c3c; font-size:12px;">Error: ${e.message}</div>`;
    }
}

async function mysqlToggleDb(db) {
    const container = document.getElementById(`mysql-tables-${db}`);
    const arrow = document.getElementById(`mysql-arrow-${db}`);

    if (container.style.display !== 'none') {
        container.style.display = 'none';
        arrow.style.transform = 'rotate(0deg)';
        return;
    }

    arrow.style.transform = 'rotate(90deg)';
    container.style.display = 'block';
    container.innerHTML = '<div style="padding:6px 0; font-size:11px; color:var(--text-muted);">Loading tables...</div>';

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/tables`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...mysqlCreds, database: db }),
        });
        const data = await resp.json();

        if (data.error) {
            container.innerHTML = `<div style="padding:6px 0; font-size:11px; color:#e74c3c;">${data.error}</div>`;
            return;
        }

        const tables = data.tables || [];
        if (tables.length === 0) {
            container.innerHTML = '<div style="padding:6px 0; font-size:11px; color:var(--text-muted);">No tables</div>';
            return;
        }

        let html = '';
        for (const t of tables) {
            const icon = t.type === 'VIEW' ? '👁️' : '📄';
            const rows = t.rows != null ? ` (${Number(t.rows).toLocaleString()})` : '';
            const isActive = (mysqlCurrentDb === db && mysqlCurrentTable === t.name);
            html += `<div onclick="mysqlSelectTable('${db}', '${t.name.replace(/'/g, "\\'")}')" 
                style="padding:4px 8px; cursor:pointer; display:flex; align-items:center; gap:6px; border-radius:4px; transition:background 0.15s; ${isActive ? 'background:var(--accent-primary-15);' : ''}"
                onmouseover="this.style.background='var(--bg-tertiary)'" 
                onmouseout="this.style.background='${isActive ? 'var(--accent-primary-15)' : 'none'}'"
                class="mysql-table-item" data-db="${db}" data-table="${t.name}">
                <span style="font-size:12px;">${icon}</span>
                <span style="color:var(--text-secondary); font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${t.name}<span style="color:var(--text-muted);">${rows}</span></span>
            </div>`;
        }
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div style="padding:6px 0; font-size:11px; color:#e74c3c;">Error: ${e.message}</div>`;
    }
}

async function mysqlSelectTable(db, table) {
    mysqlCurrentDb = db;
    mysqlCurrentTable = table;
    mysqlCurrentPage = 0;

    // Update table info in header
    document.getElementById('mysql-table-info').innerHTML =
        `<span style="font-size:14px;">📄</span> <strong>${db}</strong>.<strong>${table}</strong>`;

    // Highlight active table in tree
    document.querySelectorAll('.mysql-table-item').forEach(el => {
        const isActive = el.dataset.db === db && el.dataset.table === table;
        el.style.background = isActive ? 'var(--accent-primary-15)' : 'none';
    });

    // Switch to data tab and load data
    mysqlSwitchTab('data');
    await mysqlLoadTableData();

    // Also update the query db selector
    document.getElementById('mysql-query-db').value = db;
}

async function mysqlLoadTableData() {
    if (!mysqlCreds || !mysqlCurrentDb || !mysqlCurrentTable) return;

    const grid = document.getElementById('mysql-data-grid');
    grid.innerHTML = '<div style="padding:40px; text-align:center; color:var(--text-muted);"><div class="spinner-sm"></div> Loading data...</div>';

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/data`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...mysqlCreds,
                database: mysqlCurrentDb,
                table: mysqlCurrentTable,
                page: mysqlCurrentPage,
                page_size: mysqlPageSize,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            grid.innerHTML = `<div style="padding:40px; text-align:center; color:#e74c3c;">${data.error}</div>`;
            return;
        }

        mysqlTotalPages = data.total_pages || 1;
        mysqlRenderGrid(data.columns || [], data.rows || [], grid);

        // Update pagination
        const pagination = document.getElementById('mysql-pagination');
        pagination.style.display = 'flex';
        document.getElementById('mysql-row-info').textContent =
            `${Number(data.total_rows || 0).toLocaleString()} rows total`;
        document.getElementById('mysql-page-info').textContent =
            `Page ${(data.page || 0) + 1} / ${data.total_pages || 1}`;
        document.getElementById('mysql-prev-btn').disabled = (data.page || 0) === 0;
        document.getElementById('mysql-next-btn').disabled = ((data.page || 0) + 1) >= (data.total_pages || 1);

    } catch (e) {
        grid.innerHTML = `<div style="padding:40px; text-align:center; color:#e74c3c;">Error: ${e.message}</div>`;
    }
}

function mysqlRenderGrid(columns, rows, container) {
    if (columns.length === 0) {
        container.innerHTML = '<div style="padding:40px; text-align:center; color:var(--text-muted);">No data</div>';
        return;
    }

    let html = `<table style="width:100%; border-collapse:collapse; font-family:var(--font-mono); font-size:12px;">
        <thead>
            <tr style="position:sticky; top:0; z-index:1;">`;

    // Header
    html += '<th style="padding:8px 12px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; white-space:nowrap; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">#</th>';
    for (const col of columns) {
        html += `<th style="padding:8px 12px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; white-space:nowrap; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">${escapeHtml(col)}</th>`;
    }
    html += '</tr></thead><tbody>';

    // Rows
    const offset = mysqlCurrentPage * mysqlPageSize;
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const rowNum = offset + i + 1;
        const bgColor = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';
        html += `<tr style="background:${bgColor}; transition:background 0.1s;" onmouseover="this.style.background='var(--accent-primary-10)'" onmouseout="this.style.background='${bgColor}'">`;
        html += `<td style="padding:6px 12px; border-bottom:1px solid var(--border); color:var(--text-muted); font-size:11px;">${rowNum}</td>`;
        for (let j = 0; j < columns.length; j++) {
            const val = j < row.length ? row[j] : null;
            let display, style = 'padding:6px 12px; border-bottom:1px solid var(--border); max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
            if (val === null) {
                display = '<span style="color:var(--text-muted); font-style:italic;">NULL</span>';
            } else if (typeof val === 'number') {
                display = `<span style="color:#3498db;">${val}</span>`;
                style += ' text-align:right;';
            } else {
                display = escapeHtml(String(val));
            }
            html += `<td style="${style}" title="${escapeHtml(String(val ?? 'NULL'))}">${display}</td>`;
        }
        html += '</tr>';
    }

    html += '</tbody></table>';
    container.innerHTML = html;
}

function mysqlChangePage(delta) {
    const newPage = mysqlCurrentPage + delta;
    if (newPage < 0 || newPage >= mysqlTotalPages) return;
    mysqlCurrentPage = newPage;
    mysqlLoadTableData();
}

function mysqlSwitchTab(tab) {
    // Update tab buttons
    document.querySelectorAll('.mysql-tab').forEach(btn => {
        const isActive = btn.dataset.tab === tab;
        btn.style.color = isActive ? 'var(--text-primary)' : 'var(--text-muted)';
        btn.style.fontWeight = isActive ? '500' : '400';
        btn.style.borderBottom = isActive ? '2px solid var(--accent-primary)' : '2px solid transparent';
        if (isActive) btn.classList.add('active');
        else btn.classList.remove('active');
    });

    // Show/hide tab content
    document.getElementById('mysql-tab-data').style.display = tab === 'data' ? 'flex' : 'none';
    document.getElementById('mysql-tab-structure').style.display = tab === 'structure' ? 'flex' : 'none';
    document.getElementById('mysql-tab-query').style.display = tab === 'query' ? 'flex' : 'none';

    // Load content for the selected tab
    if (tab === 'structure' && mysqlCurrentDb && mysqlCurrentTable) {
        mysqlLoadStructure();
        mysqlLoadIndexes();
        mysqlLoadTriggers();
    }
}

async function mysqlLoadStructure() {
    if (!mysqlCreds || !mysqlCurrentDb || !mysqlCurrentTable) return;

    const container = document.getElementById('mysql-struct-columns');
    container.innerHTML = '<div style="padding:40px; text-align:center; color:var(--text-muted);"><div class="spinner-sm"></div> Loading structure...</div>';

    const baseUrl = getNodeApiBase(currentNodeId);
    const url = `${baseUrl}/api/mysql/query`;
    const structureQuery = `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '${mysqlCurrentDb.replace(/'/g, "''")}' AND TABLE_NAME = '${mysqlCurrentTable.replace(/'/g, "''")}' ORDER BY ORDINAL_POSITION`;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000);

        const resp = await fetch(url, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...mysqlCreds,
                database: mysqlCurrentDb,
                query: structureQuery,
            }),
            signal: controller.signal,
        });
        clearTimeout(timeoutId);

        let data;
        try {
            data = await resp.json();
        } catch (jsonErr) {
            container.innerHTML = `<div style="padding:40px; text-align:center; color:#e74c3c;">Server returned non-JSON response (HTTP ${resp.status})</div>`;
            return;
        }

        if (!resp.ok || data.error) {
            container.innerHTML = `<div style="padding:40px; text-align:center; color:#e74c3c;">${data.error || 'Server error: HTTP ' + resp.status}</div>`;
            return;
        }

        // Map query result rows to column objects
        const rows = data.rows || [];
        const cols = rows.map(r => ({
            name: r[0] || '',
            type: r[1] || '',
            nullable: r[2] === 'YES',
            key: r[3] || '',
            default: r[4],
            extra: r[5] || '',
        }));

        // Toolbar
        let html = `<div style="padding:10px 14px; display:flex; gap:8px; border-bottom:1px solid var(--border); align-items:center;">
            <button onclick="mysqlAddColumnDialog()" style="background:var(--accent-primary); color:#fff; border:none; padding:6px 14px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:500;">➕ Add Column</button>
            <button onclick="mysqlRenameTableDialog()" style="background:var(--bg-tertiary); color:var(--text-primary); border:1px solid var(--border); padding:6px 14px; border-radius:6px; cursor:pointer; font-size:12px;">✏️ Rename Table</button>
            <div style="flex:1;"></div>
            <span style="color:var(--text-muted); font-size:11px;">${cols.length} column${cols.length !== 1 ? 's' : ''} · ${mysqlCurrentDb}.${mysqlCurrentTable}</span>
        </div>`;

        // Table
        html += `<div style="overflow-x:auto; flex:1;"><table style="width:100%; border-collapse:collapse; font-size:13px;">
            <thead>
                <tr>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Column</th>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Type</th>
                    <th style="padding:10px 14px; text-align:center; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Nullable</th>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Key</th>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Default</th>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Extra</th>
                    <th style="padding:10px 14px; text-align:center; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; width:120px;">Actions</th>
                </tr>
            </thead>
            <tbody>`;

        for (let i = 0; i < cols.length; i++) {
            const c = cols[i];
            const bgColor = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';
            const keyBadge = c.key === 'PRI' ? '<span style="background:rgba(241,196,15,0.2); color:#f1c40f; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;">PRI</span>'
                : c.key === 'UNI' ? '<span style="background:rgba(52,152,219,0.2); color:#3498db; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;">UNI</span>'
                    : c.key === 'MUL' ? '<span style="background:rgba(155,89,182,0.2); color:#9b59b6; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;">MUL</span>'
                        : c.key || '';

            const colJson = JSON.stringify(c).replace(/'/g, "\\'").replace(/"/g, '&quot;');
            html += `<tr style="background:${bgColor};">
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); font-weight:500; color:var(--text-primary);">${escapeHtml(c.name)}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); color:#e67e22;">${escapeHtml(c.type)}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); text-align:center;">${c.nullable ? '✅' : '❌'}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border);">${keyBadge}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); color:var(--text-muted);">${c.default != null ? escapeHtml(String(c.default)) : '<span style="font-style:italic;">NULL</span>'}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(c.extra || '')}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); text-align:center;">
                    <button onclick='mysqlModifyColumnDialog(${colJson})' style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:3px 8px; border-radius:4px; cursor:pointer; font-size:11px; margin-right:4px;" title="Modify column">✏️</button>
                    <button onclick="mysqlDropColumn('${escapeHtml(c.name)}')" style="background:rgba(231,76,60,0.1); border:1px solid rgba(231,76,60,0.3); color:#e74c3c; padding:3px 8px; border-radius:4px; cursor:pointer; font-size:11px;" title="Drop column">🗑️</button>
                </td>
            </tr>`;
        }

        html += '</tbody></table></div>';
        container.innerHTML = html;

    } catch (e) {
        const isTimeout = e.name === 'AbortError';
        const detail = isTimeout
            ? 'Request timed out after 20 seconds.'
            : `${e.message || e}`;
        container.innerHTML = `<div style="padding:40px; text-align:center; color:#e74c3c;">
            <div style="font-size:14px; font-weight:500; margin-bottom:8px;">${isTimeout ? 'Request Timed Out' : 'Connection Error'}</div>
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">${detail}</div>
            <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">URL: ${escapeHtml(url)}</div>
            <button onclick="mysqlLoadStructure()" style="margin-top:12px; background:var(--accent-primary); color:#fff; border:none; padding:6px 14px; border-radius:6px; cursor:pointer; font-size:12px;">🔄 Retry</button>
        </div>`;
    }
}

// ─── Structure Sub-tab Switching ───
function mysqlStructSwitchTab(tab) {
    document.querySelectorAll('.mysql-struct-tab').forEach(btn => {
        const isActive = btn.dataset.stab === tab;
        btn.style.color = isActive ? 'var(--text-primary)' : 'var(--text-muted)';
        btn.style.fontWeight = isActive ? '500' : '400';
        btn.style.borderBottom = isActive ? '2px solid var(--accent-primary)' : '2px solid transparent';
    });
    document.getElementById('mysql-struct-columns').style.display = tab === 'columns' ? 'block' : 'none';
    document.getElementById('mysql-struct-indexes').style.display = tab === 'indexes' ? 'block' : 'none';
    document.getElementById('mysql-struct-triggers').style.display = tab === 'triggers' ? 'block' : 'none';
}

// ─── Indexes ───
async function mysqlLoadIndexes() {
    if (!mysqlCreds || !mysqlCurrentDb || !mysqlCurrentTable) return;
    const container = document.getElementById('mysql-struct-indexes');
    container.innerHTML = '<div style="padding:30px; text-align:center; color:var(--text-muted);"><div class="spinner-sm"></div> Loading indexes...</div>';

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/query`, {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...mysqlCreds, database: mysqlCurrentDb,
                query: `SHOW INDEX FROM \`${mysqlCurrentDb.replace(/`/g, '``')}\`.\`${mysqlCurrentTable.replace(/`/g, '``')}\``
            }),
        });
        const data = await resp.json();
        if (data.error) { container.innerHTML = `<div style="padding:30px; text-align:center; color:#e74c3c;">${data.error}</div>`; return; }

        const rows = data.rows || [];
        const colIdx = {};
        (data.columns || []).forEach((c, i) => colIdx[c] = i);

        // Group by key name
        const indexes = {};
        for (const r of rows) {
            const keyName = r[colIdx['Key_name']] || r[2];
            if (!indexes[keyName]) indexes[keyName] = { name: keyName, unique: r[colIdx['Non_unique']] == 0 || r[1] == 0, columns: [], type: r[colIdx['Index_type']] || r[10] || 'BTREE' };
            indexes[keyName].columns.push({ col: r[colIdx['Column_name']] || r[4], seq: r[colIdx['Seq_in_index']] || r[3] });
        }

        let html = `<div style="padding:10px 14px; display:flex; gap:8px; border-bottom:1px solid var(--border); align-items:center;">
            <button onclick="mysqlAddIndexDialog()" style="background:var(--accent-primary); color:#fff; border:none; padding:6px 14px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:500;">➕ Add Index</button>
            <div style="flex:1;"></div>
            <span style="color:var(--text-muted); font-size:11px;">${Object.keys(indexes).length} index${Object.keys(indexes).length !== 1 ? 'es' : ''}</span>
        </div>`;

        html += `<div style="overflow-x:auto;"><table style="width:100%; border-collapse:collapse; font-size:13px;">
            <thead><tr>
                <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Name</th>
                <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Columns</th>
                <th style="padding:10px 14px; text-align:center; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Type</th>
                <th style="padding:10px 14px; text-align:center; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Unique</th>
                <th style="padding:10px 14px; text-align:center; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; width:80px;">Actions</th>
            </tr></thead><tbody>`;

        let i = 0;
        for (const [name, idx] of Object.entries(indexes)) {
            const bg = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';
            const isPrimary = name === 'PRIMARY';
            const badge = isPrimary
                ? '<span style="background:rgba(241,196,15,0.2); color:#f1c40f; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;">PRIMARY</span>'
                : idx.unique ? '<span style="background:rgba(52,152,219,0.2); color:#3498db; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;">UNIQUE</span>' : '';
            const cols = idx.columns.sort((a, b) => a.seq - b.seq).map(c => escapeHtml(c.col)).join(', ');
            html += `<tr style="background:${bg};">
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); font-weight:500; color:var(--text-primary);">${escapeHtml(name)}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); color:#e67e22;">${cols}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); text-align:center; color:var(--text-muted);">${escapeHtml(idx.type)}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); text-align:center;">${badge || '—'}</td>
                <td style="padding:8px 14px; border-bottom:1px solid var(--border); text-align:center;">
                    ${isPrimary ? '' : `<button onclick="mysqlDropIndex('${escapeHtml(name)}')" style="background:rgba(231,76,60,0.1); border:1px solid rgba(231,76,60,0.3); color:#e74c3c; padding:3px 8px; border-radius:4px; cursor:pointer; font-size:11px;" title="Drop index">🗑️</button>`}
                </td>
            </tr>`;
            i++;
        }
        html += '</tbody></table></div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div style="padding:30px; text-align:center; color:#e74c3c;">Error: ${e.message}</div>`;
    }
}

function mysqlAddIndexDialog() {
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; z-index:10000;';
    modal.innerHTML = `<div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; padding:24px; width:420px; max-width:90vw;">
        <h3 style="margin:0 0 16px; font-size:16px; color:var(--text-primary);">🔑 Add Index to ${escapeHtml(mysqlCurrentTable)}</h3>
        <div style="display:flex; flex-direction:column; gap:12px;">
            <div>
                <label style="font-size:12px; color:var(--text-secondary); display:block; margin-bottom:4px;">Index Name</label>
                <input id="idx-name" type="text" placeholder="idx_column_name" style="width:100%; padding:8px 10px; font-size:13px; border:1px solid var(--border); border-radius:6px; background:var(--bg-primary); color:var(--text-primary); box-sizing:border-box;">
            </div>
            <div>
                <label style="font-size:12px; color:var(--text-secondary); display:block; margin-bottom:4px;">Columns (comma-separated)</label>
                <input id="idx-cols" type="text" placeholder="col1, col2" style="width:100%; padding:8px 10px; font-size:13px; font-family:var(--font-mono); border:1px solid var(--border); border-radius:6px; background:var(--bg-primary); color:var(--text-primary); box-sizing:border-box;">
            </div>
            <div>
                <label style="font-size:12px; color:var(--text-secondary); display:block; margin-bottom:4px;">Index Type</label>
                <select id="idx-type" style="width:100%; padding:8px 10px; font-size:13px; border:1px solid var(--border); border-radius:6px; background:var(--bg-primary); color:var(--text-primary);">
                    <option value="INDEX">INDEX</option>
                    <option value="UNIQUE">UNIQUE</option>
                    <option value="FULLTEXT">FULLTEXT</option>
                </select>
            </div>
        </div>
        <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:16px;">
            <button onclick="this.closest('div[style*=fixed]').remove()" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:8px 16px; border-radius:6px; cursor:pointer; font-size:13px;">Cancel</button>
            <button onclick="mysqlDoAddIndex(this.closest('div[style*=fixed]'))" style="background:var(--accent-primary); border:none; color:#fff; padding:8px 16px; border-radius:6px; cursor:pointer; font-size:13px; font-weight:500;">Create Index</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
    modal.querySelector('#idx-name').focus();
}

async function mysqlDoAddIndex(modal) {
    const name = modal.querySelector('#idx-name').value.trim();
    const cols = modal.querySelector('#idx-cols').value.trim();
    const type = modal.querySelector('#idx-type').value;
    if (!name || !cols) { showToast('Index name and columns are required', 'error'); return; }

    const colList = cols.split(',').map(c => `\`${c.trim().replace(/`/g, '``')}\``).join(', ');
    const sql = `CREATE ${type} \`${name.replace(/`/g, '``')}\` ON \`${mysqlCurrentDb.replace(/`/g, '``')}\`.\`${mysqlCurrentTable.replace(/`/g, '``')}\` (${colList})`;

    modal.remove();

    // Non-blocking: show spinner in indexes panel
    const container = document.getElementById('mysql-struct-indexes');
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:absolute; inset:0; background:rgba(0,0,0,0.4); display:flex; align-items:center; justify-content:center; z-index:5;';
    overlay.innerHTML = '<div style="background:var(--bg-secondary); padding:16px 24px; border-radius:8px; font-size:13px; color:var(--text-primary);"><div class="spinner-sm" style="display:inline-block; margin-right:8px;"></div>Creating index...</div>';
    container.style.position = 'relative';
    container.appendChild(overlay);

    try {
        await mysqlAlterTable(sql);
        showToast(`Index '${name}' created`, 'success');
        mysqlLoadIndexes();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
        overlay.remove();
    }
}

async function mysqlDropIndex(indexName) {
    const confirmed = await mysqlConfirmDestructive(
        `Drop index <strong>${escapeHtml(indexName)}</strong> from <strong>${escapeHtml(mysqlCurrentTable)}</strong>?`,
        `DROP INDEX \`${indexName}\` ON \`${mysqlCurrentDb}\`.\`${mysqlCurrentTable}\``
    );
    if (!confirmed) return;

    const container = document.getElementById('mysql-struct-indexes');
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:absolute; inset:0; background:rgba(0,0,0,0.4); display:flex; align-items:center; justify-content:center; z-index:5;';
    overlay.innerHTML = '<div style="background:var(--bg-secondary); padding:16px 24px; border-radius:8px; font-size:13px; color:var(--text-primary);"><div class="spinner-sm" style="display:inline-block; margin-right:8px;"></div>Dropping index...</div>';
    container.style.position = 'relative';
    container.appendChild(overlay);

    try {
        await mysqlAlterTable(`DROP INDEX \`${indexName.replace(/`/g, '``')}\` ON \`${mysqlCurrentDb.replace(/`/g, '``')}\`.\`${mysqlCurrentTable.replace(/`/g, '``')}\``);
        showToast(`Index '${indexName}' dropped`, 'success');
        mysqlLoadIndexes();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
        overlay.remove();
    }
}

// ─── Triggers ───
async function mysqlLoadTriggers() {
    if (!mysqlCreds || !mysqlCurrentDb || !mysqlCurrentTable) return;
    const container = document.getElementById('mysql-struct-triggers');
    container.innerHTML = '<div style="padding:30px; text-align:center; color:var(--text-muted);"><div class="spinner-sm"></div> Loading triggers...</div>';

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/query`, {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...mysqlCreds, database: mysqlCurrentDb,
                query: `SELECT TRIGGER_NAME, EVENT_MANIPULATION, ACTION_TIMING, ACTION_STATEMENT, CREATED FROM information_schema.TRIGGERS WHERE EVENT_OBJECT_SCHEMA = '${mysqlCurrentDb.replace(/'/g, "''")}' AND EVENT_OBJECT_TABLE = '${mysqlCurrentTable.replace(/'/g, "''")}' ORDER BY TRIGGER_NAME`
            }),
        });
        const data = await resp.json();
        if (data.error) { container.innerHTML = `<div style="padding:30px; text-align:center; color:#e74c3c;">${data.error}</div>`; return; }

        const rows = data.rows || [];

        let html = `<div style="padding:10px 14px; display:flex; gap:8px; border-bottom:1px solid var(--border); align-items:center;">
            <button onclick="mysqlAddTriggerDialog()" style="background:var(--accent-primary); color:#fff; border:none; padding:6px 14px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:500;">➕ Add Trigger</button>
            <div style="flex:1;"></div>
            <span style="color:var(--text-muted); font-size:11px;">${rows.length} trigger${rows.length !== 1 ? 's' : ''}</span>
        </div>`;

        if (rows.length === 0) {
            html += '<div style="padding:30px; text-align:center; color:var(--text-muted); font-size:13px;">No triggers on this table</div>';
        } else {
            html += `<div style="overflow-x:auto;"><table style="width:100%; border-collapse:collapse; font-size:13px;">
                <thead><tr>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Name</th>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Timing</th>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Event</th>
                    <th style="padding:10px 14px; text-align:left; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Statement</th>
                    <th style="padding:10px 14px; text-align:center; background:var(--bg-tertiary); border-bottom:2px solid var(--border); color:var(--text-secondary); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; width:80px;">Actions</th>
                </tr></thead><tbody>`;

            rows.forEach((r, i) => {
                const bg = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';
                const name = r[0] || '', event = r[1] || '', timing = r[2] || '', stmt = r[3] || '';
                const timingBadge = timing === 'BEFORE'
                    ? '<span style="background:rgba(241,196,15,0.2); color:#f1c40f; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;">BEFORE</span>'
                    : '<span style="background:rgba(46,204,113,0.2); color:#2ecc71; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600;">AFTER</span>';
                html += `<tr style="background:${bg};">
                    <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); font-weight:500; color:var(--text-primary);">${escapeHtml(name)}</td>
                    <td style="padding:8px 14px; border-bottom:1px solid var(--border);">${timingBadge}</td>
                    <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); color:#e67e22;">${escapeHtml(event)}</td>
                    <td style="padding:8px 14px; border-bottom:1px solid var(--border); font-family:var(--font-mono); color:var(--text-muted); font-size:12px; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(stmt)}">${escapeHtml(stmt)}</td>
                    <td style="padding:8px 14px; border-bottom:1px solid var(--border); text-align:center;">
                        <button onclick="mysqlDropTrigger('${escapeHtml(name)}')" style="background:rgba(231,76,60,0.1); border:1px solid rgba(231,76,60,0.3); color:#e74c3c; padding:3px 8px; border-radius:4px; cursor:pointer; font-size:11px;" title="Drop trigger">🗑️</button>
                    </td>
                </tr>`;
            });
            html += '</tbody></table></div>';
        }
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<div style="padding:30px; text-align:center; color:#e74c3c;">Error: ${e.message}</div>`;
    }
}

function mysqlAddTriggerDialog() {
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; z-index:10000;';
    modal.innerHTML = `<div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; padding:24px; width:500px; max-width:90vw;">
        <h3 style="margin:0 0 16px; font-size:16px; color:var(--text-primary);">⚡ Create Trigger on ${escapeHtml(mysqlCurrentTable)}</h3>
        <div style="display:flex; flex-direction:column; gap:12px;">
            <div>
                <label style="font-size:12px; color:var(--text-secondary); display:block; margin-bottom:4px;">Trigger Name</label>
                <input id="trg-name" type="text" placeholder="trg_before_insert" style="width:100%; padding:8px 10px; font-size:13px; border:1px solid var(--border); border-radius:6px; background:var(--bg-primary); color:var(--text-primary); box-sizing:border-box;">
            </div>
            <div style="display:flex; gap:12px;">
                <div style="flex:1;">
                    <label style="font-size:12px; color:var(--text-secondary); display:block; margin-bottom:4px;">Timing</label>
                    <select id="trg-timing" style="width:100%; padding:8px 10px; font-size:13px; border:1px solid var(--border); border-radius:6px; background:var(--bg-primary); color:var(--text-primary);">
                        <option value="BEFORE">BEFORE</option>
                        <option value="AFTER">AFTER</option>
                    </select>
                </div>
                <div style="flex:1;">
                    <label style="font-size:12px; color:var(--text-secondary); display:block; margin-bottom:4px;">Event</label>
                    <select id="trg-event" style="width:100%; padding:8px 10px; font-size:13px; border:1px solid var(--border); border-radius:6px; background:var(--bg-primary); color:var(--text-primary);">
                        <option value="INSERT">INSERT</option>
                        <option value="UPDATE">UPDATE</option>
                        <option value="DELETE">DELETE</option>
                    </select>
                </div>
            </div>
            <div>
                <label style="font-size:12px; color:var(--text-secondary); display:block; margin-bottom:4px;">Statement Body</label>
                <textarea id="trg-body" placeholder="BEGIN\n  SET NEW.updated_at = NOW();\nEND" style="width:100%; height:120px; padding:8px 10px; font-size:13px; font-family:var(--font-mono); border:1px solid var(--border); border-radius:6px; background:var(--bg-primary); color:var(--text-primary); resize:vertical; box-sizing:border-box;"></textarea>
            </div>
        </div>
        <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:16px;">
            <button onclick="this.closest('div[style*=fixed]').remove()" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:8px 16px; border-radius:6px; cursor:pointer; font-size:13px;">Cancel</button>
            <button onclick="mysqlDoAddTrigger(this.closest('div[style*=fixed]'))" style="background:var(--accent-primary); border:none; color:#fff; padding:8px 16px; border-radius:6px; cursor:pointer; font-size:13px; font-weight:500;">Create Trigger</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
    modal.querySelector('#trg-name').focus();
}

async function mysqlDoAddTrigger(modal) {
    const name = modal.querySelector('#trg-name').value.trim();
    const timing = modal.querySelector('#trg-timing').value;
    const event = modal.querySelector('#trg-event').value;
    const body = modal.querySelector('#trg-body').value.trim();
    if (!name || !body) { showToast('Trigger name and body are required', 'error'); return; }

    const sql = `CREATE TRIGGER \`${name.replace(/`/g, '``')}\` ${timing} ${event} ON \`${mysqlCurrentDb.replace(/`/g, '``')}\`.\`${mysqlCurrentTable.replace(/`/g, '``')}\` FOR EACH ROW ${body}`;
    modal.remove();

    try {
        await mysqlAlterTable(sql);
        showToast(`Trigger '${name}' created`, 'success');
        mysqlLoadTriggers();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function mysqlDropTrigger(triggerName) {
    const confirmed = await mysqlConfirmDestructive(
        `Drop trigger <strong>${escapeHtml(triggerName)}</strong> from <strong>${escapeHtml(mysqlCurrentTable)}</strong>?`,
        `DROP TRIGGER \`${mysqlCurrentDb}\`.\`${triggerName}\``
    );
    if (!confirmed) return;

    try {
        await mysqlAlterTable(`DROP TRIGGER \`${mysqlCurrentDb.replace(/`/g, '``')}\`.\`${triggerName.replace(/`/g, '``')}\``);
        showToast(`Trigger '${triggerName}' dropped`, 'success');
        mysqlLoadTriggers();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}


async function mysqlAlterTable(sql) {
    const baseUrl = getNodeApiBase(currentNodeId);
    const resp = await fetch(`${baseUrl}/api/mysql/query`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...mysqlCreds, database: mysqlCurrentDb, query: sql }),
    });
    let data;
    try { data = await resp.json(); } catch { data = { error: 'Server returned non-JSON (HTTP ' + resp.status + ')' }; }
    if (!resp.ok || data.error) throw new Error(data.error || 'HTTP ' + resp.status);
    return data;
}

// Nice confirmation dialog requiring user to type YES for destructive actions
function mysqlConfirmDestructive(message, detail) {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; z-index:10001;';
        modal.innerHTML = `<div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; padding:24px; width:420px; max-width:90vw;">
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:16px;">
                <span style="font-size:28px;">⚠️</span>
                <h3 style="margin:0; font-size:16px; color:#e74c3c;">Confirm Destructive Operation</h3>
            </div>
            <p style="color:var(--text-primary); font-size:13px; margin:0 0 8px; line-height:1.5;">${message}</p>
            ${detail ? `<div style="background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; padding:10px 12px; margin:12px 0; font-family:var(--font-mono); font-size:12px; color:#e67e22; word-break:break-all; max-height:80px; overflow-y:auto;">${escapeHtml(detail)}</div>` : ''}
            <p style="color:var(--text-muted); font-size:12px; margin:12px 0 8px;">Type <strong style="color:#e74c3c;">YES</strong> to confirm:</p>
            <input id="confirm-destructive-input" style="width:100%; padding:10px; background:var(--bg-primary); border:2px solid var(--border); border-radius:6px; color:var(--text-primary); font-size:14px; font-weight:600; text-align:center; box-sizing:border-box; letter-spacing:2px;" placeholder="YES" autocomplete="off">
            <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                <button id="confirm-destructive-cancel" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:8px 20px; border-radius:6px; cursor:pointer; font-size:13px;">Cancel</button>
                <button id="confirm-destructive-ok" style="background:#e74c3c; color:#fff; border:none; padding:8px 20px; border-radius:6px; cursor:pointer; font-size:13px; font-weight:500; opacity:0.4;" disabled>Confirm</button>
            </div>
        </div>`;
        document.body.appendChild(modal);

        const input = modal.querySelector('#confirm-destructive-input');
        const okBtn = modal.querySelector('#confirm-destructive-ok');
        input.focus();

        input.addEventListener('input', () => {
            const match = input.value.trim().toUpperCase() === 'YES';
            okBtn.disabled = !match;
            okBtn.style.opacity = match ? '1' : '0.4';
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && input.value.trim().toUpperCase() === 'YES') { modal.remove(); resolve(true); }
            if (e.key === 'Escape') { modal.remove(); resolve(false); }
        });
        okBtn.addEventListener('click', () => { modal.remove(); resolve(true); });
        modal.querySelector('#confirm-destructive-cancel').addEventListener('click', () => { modal.remove(); resolve(false); });
    });
}

// Check if a SQL query is destructive
function isMysqlDestructiveQuery(sql) {
    const upper = sql.trim().toUpperCase();
    const patterns = [
        'DROP TABLE', 'DROP DATABASE', 'DROP SCHEMA', 'DROP INDEX', 'DROP VIEW',
        'TRUNCATE', 'DELETE', 'ALTER TABLE',
        'GRANT', 'REVOKE', 'CREATE USER', 'DROP USER', 'ALTER USER',
    ];
    return patterns.some(p => upper.startsWith(p) || upper.includes(p));
}

function mysqlAddColumnDialog() {
    const db = mysqlCurrentDb, tbl = mysqlCurrentTable;
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; z-index:10000;';
    modal.innerHTML = `<div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; padding:24px; width:420px; max-width:90vw;">
        <h3 style="margin:0 0 16px; font-size:16px; color:var(--text-primary);">Add Column to ${escapeHtml(tbl)}</h3>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
            <div>
                <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Column Name</label>
                <input id="add-col-name" style="width:100%; padding:8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; color:var(--text-primary); font-family:var(--font-mono); box-sizing:border-box;" placeholder="column_name">
            </div>
            <div>
                <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Type</label>
                <input id="add-col-type" style="width:100%; padding:8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; color:var(--text-primary); font-family:var(--font-mono); box-sizing:border-box;" placeholder="VARCHAR(255)" value="VARCHAR(255)">
            </div>
            <div>
                <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Default Value</label>
                <input id="add-col-default" style="width:100%; padding:8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; color:var(--text-primary); font-family:var(--font-mono); box-sizing:border-box;" placeholder="NULL">
            </div>
            <div style="display:flex; align-items:end; gap:12px; padding-bottom:4px;">
                <label style="display:flex; align-items:center; gap:6px; cursor:pointer; font-size:12px; color:var(--text-primary);">
                    <input type="checkbox" id="add-col-nullable" checked> Nullable
                </label>
            </div>
        </div>
        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:20px;">
            <button onclick="this.closest('div[style*=fixed]').remove()" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:8px 16px; border-radius:6px; cursor:pointer;">Cancel</button>
            <button id="add-col-confirm" style="background:var(--accent-primary); color:#fff; border:none; padding:8px 16px; border-radius:6px; cursor:pointer; font-weight:500;">Add Column</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
    modal.querySelector('#add-col-name').focus();

    modal.querySelector('#add-col-confirm').onclick = async () => {
        const name = document.getElementById('add-col-name').value.trim();
        const type = document.getElementById('add-col-type').value.trim();
        const defVal = document.getElementById('add-col-default').value.trim();
        const nullable = document.getElementById('add-col-nullable').checked;
        if (!name || !type) { showToast('Name and type are required', 'error'); return; }

        let sql = `ALTER TABLE \`${db}\`.\`${tbl}\` ADD COLUMN \`${name}\` ${type}`;
        if (!nullable) sql += ' NOT NULL';
        if (defVal && defVal.toUpperCase() !== 'NULL') sql += ` DEFAULT '${defVal.replace(/'/g, "''")}'`;
        else if (nullable) sql += ' DEFAULT NULL';

        try {
            await mysqlAlterTable(sql);
            modal.remove();
            showToast(`Column '${name}' added`, 'success');
            mysqlLoadStructure();
        } catch (e) {
            showToast('Error: ' + e.message, 'error');
        }
    };
}

function mysqlModifyColumnDialog(col) {
    const db = mysqlCurrentDb, tbl = mysqlCurrentTable;
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; z-index:10000;';
    modal.innerHTML = `<div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; padding:24px; width:440px; max-width:90vw;">
        <h3 style="margin:0 0 16px; font-size:16px; color:var(--text-primary);">Modify Column: ${escapeHtml(col.name)}</h3>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
            <div>
                <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Column Name</label>
                <input id="mod-col-name" style="width:100%; padding:8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; color:var(--text-primary); font-family:var(--font-mono); box-sizing:border-box;" value="${escapeHtml(col.name)}">
            </div>
            <div>
                <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Type</label>
                <input id="mod-col-type" style="width:100%; padding:8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; color:var(--text-primary); font-family:var(--font-mono); box-sizing:border-box;" value="${escapeHtml(col.type)}">
            </div>
            <div>
                <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Default Value</label>
                <input id="mod-col-default" style="width:100%; padding:8px; background:var(--bg-primary); border:1px solid var(--border); border-radius:6px; color:var(--text-primary); font-family:var(--font-mono); box-sizing:border-box;" value="${col.default != null ? escapeHtml(String(col.default)) : ''}" placeholder="NULL">
            </div>
            <div style="display:flex; align-items:end; gap:12px; padding-bottom:4px;">
                <label style="display:flex; align-items:center; gap:6px; cursor:pointer; font-size:12px; color:var(--text-primary);">
                    <input type="checkbox" id="mod-col-nullable" ${col.nullable ? 'checked' : ''}> Nullable
                </label>
            </div>
        </div>
        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:20px;">
            <button onclick="this.closest('div[style*=fixed]').remove()" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:8px 16px; border-radius:6px; cursor:pointer;">Cancel</button>
            <button id="mod-col-confirm" style="background:var(--accent-primary); color:#fff; border:none; padding:8px 16px; border-radius:6px; cursor:pointer; font-weight:500;">Save Changes</button>
        </div>
    </div>`;
    document.body.appendChild(modal);

    modal.querySelector('#mod-col-confirm').onclick = async () => {
        const newName = document.getElementById('mod-col-name').value.trim();
        const newType = document.getElementById('mod-col-type').value.trim();
        const defVal = document.getElementById('mod-col-default').value.trim();
        const nullable = document.getElementById('mod-col-nullable').checked;
        if (!newName || !newType) { showToast('Name and type are required', 'error'); return; }

        // Use CHANGE if renaming, MODIFY if just changing type/properties
        let sql;
        if (newName !== col.name) {
            sql = `ALTER TABLE \`${db}\`.\`${tbl}\` CHANGE COLUMN \`${col.name}\` \`${newName}\` ${newType}`;
        } else {
            sql = `ALTER TABLE \`${db}\`.\`${tbl}\` MODIFY COLUMN \`${col.name}\` ${newType}`;
        }
        if (!nullable) sql += ' NOT NULL';
        if (defVal && defVal.toUpperCase() !== 'NULL') sql += ` DEFAULT '${defVal.replace(/'/g, "''")}'`;
        else if (nullable) sql += ' DEFAULT NULL';

        try {
            await mysqlAlterTable(sql);
            modal.remove();
            showToast(`Column '${col.name}' modified`, 'success');
            mysqlLoadStructure();
        } catch (e) {
            showToast('Error: ' + e.message, 'error');
        }
    };
}

async function mysqlDropColumn(colName) {
    const confirmed = await mysqlConfirmDestructive(
        `Drop column <strong>${escapeHtml(colName)}</strong> from <strong>${escapeHtml(mysqlCurrentTable)}</strong>?<br>This will permanently delete the column and all its data.`,
        `ALTER TABLE \`${mysqlCurrentDb}\`.\`${mysqlCurrentTable}\` DROP COLUMN \`${colName}\``
    );
    if (!confirmed) return;

    try {
        await mysqlAlterTable(`ALTER TABLE \`${mysqlCurrentDb}\`.\`${mysqlCurrentTable}\` DROP COLUMN \`${colName}\``);
        showToast(`Column '${colName}' dropped`, 'success');
        mysqlLoadStructure();
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function mysqlRenameTableDialog() {
    const db = mysqlCurrentDb, tbl = mysqlCurrentTable;
    const newName = prompt(`Rename table '${tbl}' to:`, tbl);
    if (!newName || newName === tbl) return;

    mysqlConfirmDestructive(
        `Rename table <strong>${escapeHtml(tbl)}</strong> to <strong>${escapeHtml(newName)}</strong>?<br>This may break queries, views, or stored procedures that reference this table.`,
        `ALTER TABLE \`${db}\`.\`${tbl}\` RENAME TO \`${db}\`.\`${newName}\``
    ).then(async (confirmed) => {
        if (!confirmed) return;
        try {
            await mysqlAlterTable(`ALTER TABLE \`${db}\`.\`${tbl}\` RENAME TO \`${db}\`.\`${newName}\``);
            mysqlCurrentTable = newName;
            showToast(`Table renamed to '${newName}'`, 'success');
            mysqlLoadStructure();
            mysqlToggleDb(db);
        } catch (e) {
            showToast('Error: ' + e.message, 'error');
        }
    });
}

function mysqlDumpDatabase(db) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; z-index:10000;';
    modal.innerHTML = `<div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; padding:24px; width:380px; max-width:90vw;">
        <h3 style="margin:0 0 16px; font-size:16px; color:var(--text-primary);">💾 Dump Database: ${escapeHtml(db)}</h3>
        <p style="color:var(--text-muted); font-size:12px; margin:0 0 16px;">Choose what to include in the SQL dump file:</p>
        <div style="display:flex; flex-direction:column; gap:8px;">
            <button onclick="mysqlDoDump('${db}', false, this.closest('div[style*=fixed]'))" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:14px 16px; border-radius:8px; cursor:pointer; text-align:left; transition:background 0.15s;" onmouseover="this.style.background='var(--bg-primary)'" onmouseout="this.style.background='var(--bg-tertiary)'">
                <div style="font-size:13px; font-weight:500;">📐 Structure Only</div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">CREATE TABLE statements only — no row data</div>
            </button>
            <button onclick="mysqlDoDump('${db}', true, this.closest('div[style*=fixed]'))" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:14px 16px; border-radius:8px; cursor:pointer; text-align:left; transition:background 0.15s;" onmouseover="this.style.background='var(--bg-primary)'" onmouseout="this.style.background='var(--bg-tertiary)'">
                <div style="font-size:13px; font-weight:500;">📦 Structure + Data</div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Full dump with CREATE TABLE and INSERT statements</div>
            </button>
        </div>
        <div style="display:flex; justify-content:flex-end; margin-top:16px;">
            <button onclick="this.closest('div[style*=fixed]').remove()" style="background:var(--bg-tertiary); border:1px solid var(--border); color:var(--text-primary); padding:8px 16px; border-radius:6px; cursor:pointer; font-size:13px;">Cancel</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
}

async function mysqlDoDump(db, includeData, modal) {
    // Replace modal content with loading
    const inner = modal.querySelector('div');
    inner.innerHTML = `<div style="padding:40px; text-align:center;">
        <div class="spinner-sm" style="margin:0 auto 12px;"></div>
        <div style="color:var(--text-muted); font-size:13px;">Generating ${includeData ? 'full' : 'structure'} dump for ${escapeHtml(db)}...</div>
    </div>`;

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/dump`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...mysqlCreds, database: db, include_data: includeData }),
        });

        if (!resp.ok) {
            let errMsg;
            try { const err = await resp.json(); errMsg = err.error; } catch { errMsg = 'HTTP ' + resp.status; }
            throw new Error(errMsg);
        }

        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${db}${includeData ? '_full' : '_structure'}.sql`;
        a.click();
        URL.revokeObjectURL(url);
        modal.remove();
        showToast(`SQL dump downloaded: ${a.download}`, 'success');
    } catch (e) {
        modal.remove();
        showToast('Dump failed: ' + e.message, 'error');
    }
}

async function mysqlExecuteQuery() {
    if (!mysqlCreds) {
        showToast('Not connected to MySQL', 'error');
        return;
    }

    const query = document.getElementById('mysql-query-input').value.trim();
    if (!query) {
        showToast('Please enter a SQL query', 'error');
        return;
    }

    // Check for destructive queries and require confirmation
    if (isMysqlDestructiveQuery(query)) {
        const confirmed = await mysqlConfirmDestructive(
            'You are about to execute a potentially destructive SQL statement.',
            query
        );
        if (!confirmed) return;
    }

    const db = document.getElementById('mysql-query-db').value || '';
    const resultDiv = document.getElementById('mysql-query-result');
    resultDiv.innerHTML = '<div style="padding:30px; text-align:center; color:var(--text-muted);"><div class="spinner-sm"></div> Executing query...</div>';

    const startTime = performance.now();

    try {
        const baseUrl = getNodeApiBase(currentNodeId);
        const resp = await fetch(`${baseUrl}/api/mysql/query`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...mysqlCreds, database: db, query }),
        });
        const data = await resp.json();
        const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);

        if (data.error) {
            resultDiv.innerHTML = `<div style="padding:20px;">
                <div style="padding:12px 16px; background:rgba(231,76,60,0.1); border:1px solid rgba(231,76,60,0.3); border-radius:6px; font-family:var(--font-mono); font-size:12px; color:#e74c3c;">${escapeHtml(data.error)}</div>
                <div style="margin-top:8px; font-size:11px; color:var(--text-muted);">Executed in ${elapsed}s</div>
            </div>`;
            return;
        }

        if (data.type === 'resultset') {
            let html = `<div style="padding:8px 14px; font-size:11px; color:var(--text-muted); border-bottom:1px solid var(--border); background:var(--bg-secondary);">
                ${data.row_count} row(s) returned in ${elapsed}s
            </div>`;
            const gridDiv = document.createElement('div');
            gridDiv.style.cssText = 'flex:1; overflow:auto;';
            resultDiv.innerHTML = html;
            resultDiv.appendChild(gridDiv);
            // Reuse the grid renderer with page 0
            const savedPage = mysqlCurrentPage;
            const savedPageSize = mysqlPageSize;
            mysqlCurrentPage = 0;
            mysqlPageSize = data.rows.length;
            mysqlRenderGrid(data.columns || [], data.rows || [], gridDiv);
            mysqlCurrentPage = savedPage;
            mysqlPageSize = savedPageSize;
        } else {
            // Modification result
            resultDiv.innerHTML = `<div style="padding:20px;">
                <div style="padding:12px 16px; background:rgba(46,204,113,0.1); border:1px solid rgba(46,204,113,0.3); border-radius:6px; font-size:13px; color:#2ecc71;">
                    ✅ ${escapeHtml(data.message || 'Query executed successfully')}
                    ${data.last_insert_id ? `<br><span style="font-size:12px; color:var(--text-muted);">Last insert ID: ${data.last_insert_id}</span>` : ''}
                </div>
                <div style="margin-top:8px; font-size:11px; color:var(--text-muted);">Executed in ${elapsed}s</div>
            </div>`;
        }
    } catch (e) {
        resultDiv.innerHTML = `<div style="padding:20px;">
            <div style="padding:12px 16px; background:rgba(231,76,60,0.1); border:1px solid rgba(231,76,60,0.3); border-radius:6px; font-family:var(--font-mono); font-size:12px; color:#e74c3c;">Error: ${escapeHtml(e.message)}</div>
        </div>`;
    }
}

// Helper: escape HTML
function escapeHtml(str) {
    if (str == null) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ═══════════════════════════════════════════════
// ─── Issues Scanner ───
// ═══════════════════════════════════════════════

var issuesScanResults = []; // cached for upgrade-all
var issuesLatestVersion = '0.0.0'; // GitHub-resolved latest, cached after each scan

async function checkIssuesAiBadge() {
    try {
        var resp = await fetch('/api/ai/status');
        var status = await resp.json();
        var badge = document.getElementById('issues-ai-badge');
        if (badge) badge.style.display = status.configured ? 'inline-block' : 'none';
    } catch (e) {
        // silently ignore
    }
}

async function loadIssueSchedule() {
    try {
        var resp = await fetch('/api/ai/config', { credentials: 'include' });
        if (!resp.ok) return;
        var cfg = await resp.json();
        var sel = document.getElementById('issues-schedule-select');
        if (sel && cfg.scan_schedule) sel.value = cfg.scan_schedule;
    } catch (e) { /* ignore */ }
}

async function saveIssueSchedule(value) {
    try {
        var resp = await fetch('/api/ai/config', { credentials: 'include' });
        if (!resp.ok) throw new Error('Failed to read config: HTTP ' + resp.status);
        var cfg = await resp.json();
        cfg.scan_schedule = value;
        var saveResp = await fetch('/api/ai/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(cfg)
        });
        if (!saveResp.ok) throw new Error('HTTP ' + saveResp.status);
        var labels = { off: 'Off', hourly: 'Every Hour', '6h': 'Every 6 Hours', '12h': 'Every 12 Hours', daily: 'Daily' };
        showToast('🔔 Auto scan: ' + (labels[value] || value), 'success');
    } catch (e) {
        console.error('Failed to save scan schedule:', e);
        showToast('Failed to save scan schedule: ' + e.message, 'error');
    }
}

async function scanForIssues() {
    var btn = document.getElementById('issues-scan-btn');
    var listEl = document.getElementById('issues-list');
    var upgradeAllBtn = document.getElementById('issues-upgrade-all-btn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span style="display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.2);border-top-color:#fff;border-radius:50%;animation:spin 0.7s linear infinite;vertical-align:middle;margin-right:6px;"></span> Scanning...'; }
    if (upgradeAllBtn) upgradeAllBtn.style.display = 'none';

    var aiSection = document.getElementById('issues-ai-section');
    if (aiSection) aiSection.style.display = 'none';

    var results = [];
    var counts = { critical: 0, warning: 0, info: 0 };

    // Gather nodes and group by cluster
    var localNode = (typeof allNodes !== 'undefined') ? allNodes.find(function (n) { return n.is_self; }) : null;
    var wsNodes = (typeof allNodes !== 'undefined' && allNodes.length) ? allNodes.filter(function (n) { return n.node_type !== 'proxmox'; }) : [];
    if (wsNodes.length === 0 && localNode) wsNodes = [localNode];
    else if (wsNodes.length === 0) wsNodes = [{ id: 'local', hostname: 'local', is_self: true, cluster_name: 'WolfStack' }];

    // Build cluster groups
    var clusters = {};
    wsNodes.forEach(function (n) {
        var key = n.cluster_name || 'WolfStack';
        if (!clusters[key]) clusters[key] = [];
        clusters[key].push(n);
    });
    var clusterKeys = Object.keys(clusters).sort(function (a, b) {
        if (a === 'WolfStack') return -1;
        if (b === 'WolfStack') return 1;
        return a.localeCompare(b);
    });

    var totalNodes = wsNodes.length;
    var completedNodes = 0;

    // Render cluster-grouped layout with placeholder "Scanning..." rows
    if (listEl) {
        var scaffoldHtml = '';
        // Global progress bar
        scaffoldHtml += '<div id="issues-progress" style="padding:12px 16px; background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; margin-bottom:16px; display:flex; align-items:center; gap:12px;">'
            + '<div style="flex:1; height:6px; background:var(--bg-tertiary); border-radius:3px; overflow:hidden;">'
            + '<div id="issues-progress-bar" style="width:0%; height:100%; background:var(--accent-primary); border-radius:3px; transition:width 0.3s ease;"></div></div>'
            + '<span id="issues-progress-text" style="font-size:12px; color:var(--text-muted); white-space:nowrap;">Scanning 0/' + totalNodes + ' nodes...</span></div>';

        clusterKeys.forEach(function (clusterName) {
            var clusterNodes = clusters[clusterName];
            var clusterId = 'issues-cluster-' + clusterName.replace(/[^a-z0-9]/gi, '-');
            scaffoldHtml += '<div class="card" style="margin-bottom:16px;">';
            // Cluster header
            scaffoldHtml += '<div style="padding:12px 16px; background:linear-gradient(90deg, rgba(99,102,241,0.06), transparent); border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px;">';
            scaffoldHtml += '<span style="font-size:18px;">☁️</span>';
            scaffoldHtml += '<span style="font-weight:600; font-size:14px; color:var(--text-primary);">' + escapeHtml(clusterName) + '</span>';
            scaffoldHtml += '<span style="font-size:12px; color:var(--text-muted);">' + clusterNodes.length + ' node' + (clusterNodes.length !== 1 ? 's' : '') + '</span>';
            scaffoldHtml += '</div>';
            // Table
            scaffoldHtml += '<div class="card-body" style="padding:0; overflow-x:auto;">';
            scaffoldHtml += '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
            scaffoldHtml += '<thead><tr style="background:var(--bg-secondary); border-bottom:1px solid var(--border);">';
            scaffoldHtml += '<th style="padding:10px 16px; text-align:left; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Node</th>';
            scaffoldHtml += '<th style="padding:10px 16px; text-align:left; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">WolfStack</th>';
            scaffoldHtml += '<th style="padding:10px 16px; text-align:left; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Issues</th>';
            scaffoldHtml += '<th style="padding:10px 16px; text-align:right; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Action</th>';
            scaffoldHtml += '</tr></thead><tbody id="' + clusterId + '-tbody">';
            // Placeholder rows for each node
            clusterNodes.forEach(function (node) {
                var safeId = 'issue-row-' + (node.id || 'local').replace(/[^a-z0-9_-]/gi, '-');
                scaffoldHtml += '<tr id="' + safeId + '" style="border-bottom:1px solid var(--border);">';
                scaffoldHtml += '<td style="padding:12px 16px; white-space:nowrap;">';
                scaffoldHtml += '<div style="display:flex; align-items:center; gap:8px;">';
                scaffoldHtml += '<span style="font-size:16px;">🖥️</span>';
                scaffoldHtml += '<div>';
                scaffoldHtml += '<div style="font-weight:600; color:var(--text-primary);">' + escapeHtml(node.hostname || node.id || 'local') + '</div>';
                if (node.is_self) scaffoldHtml += '<div style="font-size:11px; color:var(--text-muted);">local</div>';
                scaffoldHtml += '</div></div></td>';
                scaffoldHtml += '<td style="padding:12px 16px;" colspan="3">';
                scaffoldHtml += '<div style="display:flex; align-items:center; gap:8px; color:var(--text-muted); font-size:13px;">';
                scaffoldHtml += '<span style="display:inline-block;width:14px;height:14px;border:2px solid rgba(99,102,241,0.2);border-top-color:rgba(99,102,241,0.8);border-radius:50%;animation:spin 0.7s linear infinite;"></span>';
                scaffoldHtml += 'Scanning ' + escapeHtml(node.hostname || node.id || 'local') + '...</div>';
                scaffoldHtml += '</td></tr>';
            });
            scaffoldHtml += '</tbody></table></div></div>';
        });
        listEl.innerHTML = scaffoldHtml;
    }

    // Helper to update progress
    function updateProgress() {
        completedNodes++;
        var pct = Math.round((completedNodes / totalNodes) * 100);
        var bar = document.getElementById('issues-progress-bar');
        var text = document.getElementById('issues-progress-text');
        if (bar) bar.style.width = pct + '%';
        if (text) text.textContent = completedNodes < totalNodes ? ('Scanning ' + completedNodes + '/' + totalNodes + ' nodes...') : (totalNodes + ' nodes scanned ✓');
    }

    // Helper to update summary counters
    function updateCounts() {
        var critEl = document.getElementById('issues-count-critical');
        var warnEl = document.getElementById('issues-count-warning');
        var infoEl = document.getElementById('issues-count-info');
        var nodesEl = document.getElementById('issues-count-nodes');
        if (critEl) critEl.textContent = counts.critical;
        if (warnEl) warnEl.textContent = counts.warning;
        if (infoEl) infoEl.textContent = counts.info;
        if (nodesEl) nodesEl.textContent = completedNodes;
    }

    // Replace a placeholder row with actual result
    function replaceNodeRow(nodeId, data) {
        results.push(data);
        (data.issues || []).forEach(function (issue) {
            if (counts[issue.severity] !== undefined) counts[issue.severity]++;
        });
        updateProgress();
        updateCounts();

        var safeId = 'issue-row-' + (nodeId || 'local').replace(/[^a-z0-9_-]/gi, '-');
        var tr = document.getElementById(safeId);
        if (!tr) return;

        var issues = data.issues || [];
        var nodeVersion = data.version || '?';

        var severityBadge = function (sev) {
            var colors = { critical: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', icon: '🔴' }, warning: { bg: 'rgba(234,179,8,0.15)', text: '#eab308', icon: '🟡' }, info: { bg: 'rgba(59,130,246,0.15)', text: '#3b82f6', icon: '🔵' } };
            var c = colors[sev] || colors.info;
            return '<span style="display:inline-flex; align-items:center; gap:4px; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; background:' + c.bg + '; color:' + c.text + ';">' + c.icon + ' ' + sev.toUpperCase() + '</span>';
        };
        var categoryIcons = { cpu: '⚡', memory: '🧠', disk: '💾', swap: '🔄', load: '📈', service: '⚙️', container: '📦', scan: '🔍' };

        var html = '';
        // Node
        html += '<td style="padding:12px 16px; white-space:nowrap;">';
        html += '<div style="display:flex; align-items:center; gap:8px;">';
        html += '<span style="font-size:16px;">🖥️</span><div>';
        html += '<div style="font-weight:600; color:var(--text-primary);">' + escapeHtml(data.hostname || 'Unknown') + '</div>';
        if (data.is_self) html += '<div style="font-size:11px; color:var(--text-muted);">local</div>';
        html += '</div></div></td>';

        // Version
        html += '<td style="padding:12px 16px; white-space:nowrap;">';
        html += '<span style="padding:3px 10px; border-radius:6px; font-size:12px; font-weight:500; background:rgba(255,255,255,0.06); color:var(--text-secondary); border:1px solid var(--border);">v' + escapeHtml(nodeVersion) + '</span>';
        html += '</td>';

        // Issues
        html += '<td style="padding:12px 16px;">';
        if (issues.length === 0) {
            html += '<span style="color:#10b981; font-weight:500;">✅ All clear</span>';
        } else {
            var order = { critical: 0, warning: 1, info: 2 };
            var sorted = issues.slice().sort(function (a, b) { return (order[a.severity] || 9) - (order[b.severity] || 9); });
            sorted.forEach(function (issue) {
                var catIcon = categoryIcons[issue.category] || '❓';
                html += '<div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">';
                html += severityBadge(issue.severity);
                html += '<span style="font-size:14px;">' + catIcon + '</span>';
                html += '<span style="color:var(--text-primary); font-weight:500;">' + escapeHtml(issue.title) + '</span>';
                html += '<span style="color:var(--text-muted); font-size:12px;"> — ' + escapeHtml(issue.detail) + '</span>';
                html += '</div>';
            });
        }
        html += '</td>';

        // Action placeholder (final render adds upgrade buttons)
        html += '<td style="padding:12px 16px; text-align:right; white-space:nowrap;">';
        html += '<span style="color:var(--text-muted); font-size:12px;">—</span></td>';

        tr.innerHTML = html;
        tr.style.animation = 'fadeIn 0.3s ease';
    }

    // Scan all nodes concurrently, replacing placeholder rows as results arrive
    var scanPromises = wsNodes.map(function (node) {
        var isLocal = !!node.is_self;
        var url = isLocal ? '/api/issues/scan' : '/api/nodes/' + encodeURIComponent(node.id) + '/proxy/issues/scan';
        return fetch(url)
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status + (r.status === 404 ? ' — node may need WolfStack update' : ''));
                return r.json();
            })
            .then(function (data) {
                data.node_id = node.id || 'local';
                data.is_self = isLocal;
                replaceNodeRow(data.node_id, data);
            })
            .catch(function (e) {
                replaceNodeRow(node.id || 'local', { node_id: node.id || 'local', hostname: node.hostname || node.id || 'local', version: '?', issues: [{ severity: 'info', category: 'scan', title: 'Could not scan', detail: e.message }], ai_analysis: null, is_self: isLocal });
            });
    });
    await Promise.all(scanPromises);

    issuesScanResults = results;
    issuesLatestVersion = latestVersion; // cache GitHub-resolved version for upgrade-all

    // Hide progress bar
    var progressEl = document.getElementById('issues-progress');
    if (progressEl) progressEl.style.display = 'none';

    // Final re-render with version badges and upgrade buttons
    var latestVersion = '0.0.0';
    results.forEach(function (r) {
        if (r.version && r.version !== '?' && compareVersions(r.version, latestVersion) > 0) latestVersion = r.version;
    });

    // Also check GitHub for the actual latest release version
    try {
        var ghResp = await fetch('https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/Cargo.toml');
        var ghText = await ghResp.text();
        var ghMatch = ghText.match(/^version\s*=\s*"([^"]+)"/m);
        if (ghMatch && ghMatch[1] && compareVersions(ghMatch[1], latestVersion) > 0) {
            latestVersion = ghMatch[1];
        }
    } catch (e) { /* GitHub unreachable, fall back to cluster comparison */ }

    renderIssueResults(results, latestVersion, clusters, clusterKeys);

    // Upgrade All button — always visible after scan
    if (upgradeAllBtn) {
        upgradeAllBtn.style.display = 'inline-block';
        upgradeAllBtn.innerHTML = '⚡ Upgrade All (' + results.length + ')';
    }

    // AI analysis
    var aiTexts = results.map(function (r) {
        if (r.ai_analysis) return '**' + escapeHtml(r.hostname) + ':** ' + r.ai_analysis;
        return null;
    }).filter(Boolean);
    if (aiTexts.length > 0 && aiSection) {
        aiSection.style.display = 'block';
        var aiContent = document.getElementById('issues-ai-content');
        if (aiContent) aiContent.innerHTML = aiTexts.map(function (t) { return formatAiResponse(t); }).join('<hr style="border-color:var(--border); margin:16px 0;">');
    }

    if (btn) { btn.disabled = false; btn.innerHTML = '🔄 Scan Now'; }
}

function compareVersions(a, b) {
    var pa = a.split('.').map(Number);
    var pb = b.split('.').map(Number);
    for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
        var na = pa[i] || 0;
        var nb = pb[i] || 0;
        if (na > nb) return 1;
        if (na < nb) return -1;
    }
    return 0;
}

function renderIssueResults(results, latestVersion, clusters, clusterKeys) {
    var listEl = document.getElementById('issues-list');
    if (!listEl) return;

    // Build a lookup by node_id
    var resultMap = {};
    results.forEach(function (r) { resultMap[r.node_id] = r; });

    var severityBadge = function (sev) {
        var colors = { critical: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', icon: '🔴' }, warning: { bg: 'rgba(234,179,8,0.15)', text: '#eab308', icon: '🟡' }, info: { bg: 'rgba(59,130,246,0.15)', text: '#3b82f6', icon: '🔵' } };
        var c = colors[sev] || colors.info;
        return '<span style="display:inline-flex; align-items:center; gap:4px; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; background:' + c.bg + '; color:' + c.text + ';">' + c.icon + ' ' + sev.toUpperCase() + '</span>';
    };
    var categoryIcons = { cpu: '⚡', memory: '🧠', disk: '💾', swap: '🔄', load: '📈', service: '⚙️', container: '📦', scan: '🔍' };

    var html = '';
    // If no cluster info, fall back to a simple list
    if (!clusters || !clusterKeys) {
        clusters = { 'WolfStack': results.map(function (r) { return { id: r.node_id, hostname: r.hostname, is_self: r.is_self }; }) };
        clusterKeys = ['WolfStack'];
    }

    clusterKeys.forEach(function (clusterName) {
        var clusterNodes = clusters[clusterName] || [];
        var clusterIssueCount = 0;
        clusterNodes.forEach(function (n) {
            var r = resultMap[n.id || 'local'];
            if (r) clusterIssueCount += (r.issues || []).length;
        });

        html += '<div class="card" style="margin-bottom:16px;">';
        // Cluster header
        html += '<div style="padding:12px 16px; background:linear-gradient(90deg, rgba(99,102,241,0.06), transparent); border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px;">';
        html += '<span style="font-size:18px;">☁️</span>';
        html += '<span style="font-weight:600; font-size:14px; color:var(--text-primary);">' + escapeHtml(clusterName) + '</span>';
        html += '<span style="font-size:12px; color:var(--text-muted);">' + clusterNodes.length + ' node' + (clusterNodes.length !== 1 ? 's' : '') + '</span>';
        if (clusterIssueCount === 0) {
            html += '<span style="margin-left:auto; font-size:12px; color:#10b981; font-weight:500;">✅ All clear</span>';
        } else {
            html += '<span style="margin-left:auto; font-size:12px; color:#eab308; font-weight:500;">' + clusterIssueCount + ' issue' + (clusterIssueCount !== 1 ? 's' : '') + '</span>';
        }
        html += '</div>';
        // Table
        html += '<div class="card-body" style="padding:0; overflow-x:auto;">';
        html += '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
        html += '<thead><tr style="background:var(--bg-secondary); border-bottom:1px solid var(--border);">';
        html += '<th style="padding:10px 16px; text-align:left; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Node</th>';
        html += '<th style="padding:10px 16px; text-align:left; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">WolfStack</th>';
        html += '<th style="padding:10px 16px; text-align:left; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Issues</th>';
        html += '<th style="padding:10px 16px; text-align:right; font-weight:600; color:var(--text-secondary); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Action</th>';
        html += '</tr></thead><tbody>';

        var rowIdx = 0;
        clusterNodes.forEach(function (node) {
            var r = resultMap[node.id || 'local'];
            if (!r) return;
            var issues = r.issues || [];
            var rowBg = rowIdx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';
            var nodeVersion = r.version || '?';
            var isBehind = nodeVersion !== '?' && latestVersion !== '0.0.0' && compareVersions(nodeVersion, latestVersion) < 0;

            html += '<tr style="border-bottom:1px solid var(--border); background:' + rowBg + ';">';

            // Node
            html += '<td style="padding:12px 16px; white-space:nowrap;">';
            html += '<div style="display:flex; align-items:center; gap:8px;">';
            html += '<span style="font-size:16px;">🖥️</span><div>';
            html += '<div style="font-weight:600; color:var(--text-primary);">' + escapeHtml(r.hostname || 'Unknown') + '</div>';
            if (r.is_self) html += '<div style="font-size:11px; color:var(--text-muted);">local</div>';
            html += '</div></div></td>';

            // Version
            html += '<td style="padding:12px 16px; white-space:nowrap;">';
            if (isBehind) {
                html += '<span style="padding:3px 10px; border-radius:6px; font-size:12px; font-weight:500; background:rgba(234,179,8,0.15); color:#eab308; border:1px solid rgba(234,179,8,0.3);">v' + escapeHtml(nodeVersion) + ' ↑</span>';
                html += '<div style="font-size:10px; color:var(--text-muted); margin-top:2px;">latest: v' + escapeHtml(latestVersion) + '</div>';
            } else {
                html += '<span style="padding:3px 10px; border-radius:6px; font-size:12px; font-weight:500; background:rgba(16,185,129,0.12); color:#10b981; border:1px solid rgba(16,185,129,0.3);">v' + escapeHtml(nodeVersion) + ' ✓</span>';
            }
            html += '</td>';

            // Issues
            html += '<td style="padding:12px 16px;">';
            if (issues.length === 0) {
                html += '<span style="color:#10b981; font-weight:500;">✅ All clear</span>';
            } else {
                var order = { critical: 0, warning: 1, info: 2 };
                var sorted = issues.slice().sort(function (a, b) { return (order[a.severity] || 9) - (order[b.severity] || 9); });
                sorted.forEach(function (issue) {
                    var catIcon = categoryIcons[issue.category] || '❓';
                    html += '<div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">';
                    html += severityBadge(issue.severity);
                    html += '<span style="font-size:14px;">' + catIcon + '</span>';
                    html += '<span style="color:var(--text-primary); font-weight:500;">' + escapeHtml(issue.title) + '</span>';
                    html += '<span style="color:var(--text-muted); font-size:12px;"> — ' + escapeHtml(issue.detail) + '</span>';
                    html += '</div>';
                });
            }
            html += '</td>';

            // Action
            html += '<td style="padding:12px 16px; text-align:right; white-space:nowrap;">';
            if (isBehind) {
                html += '<button class="btn" onclick="issuesUpgradeNode(\'' + escapeHtml(r.node_id) + '\')" ';
                html += 'style="padding:6px 14px; font-size:12px; background:rgba(16,185,129,0.12); color:#10b981; border:1px solid rgba(16,185,129,0.3); border-radius:6px; cursor:pointer;">';
                html += '⚡ Upgrade WolfStack</button>';
            } else {
                html += '<span style="color:var(--text-muted); font-size:12px;">Up to date</span>';
            }
            html += '</td>';
            html += '</tr>';
            rowIdx++;
        });

        html += '</tbody></table></div></div>';
    });

    listEl.innerHTML = html;
}

// ── Reusable modal confirm for issues page ──
function showIssuesConfirm(icon, title, description, items, confirmLabel, confirmColor) {
    return new Promise(function (resolve, reject) {
        var overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:100000;display:flex;align-items:center;justify-content:center;animation:fadeIn 0.15s ease';
        var itemsHtml = items.length ? '<div style="padding:12px 16px; background:var(--bg-secondary); border-radius:10px; margin-bottom:20px;">'
            + items.map(function (i) { return '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;color:var(--text-primary);font-size:13px;">' + i + '</div>'; }).join('')
            + '</div>' : '';
        overlay.innerHTML = '<div style="background:var(--bg-card); border:1px solid var(--border); border-radius:16px; padding:32px; max-width:480px; width:90%; box-shadow:0 20px 60px rgba(0,0,0,0.5);">'
            + '<div style="text-align:center; margin-bottom:20px;">'
            + '<div style="font-size:48px; margin-bottom:8px;">' + icon + '</div>'
            + '<h3 style="font-size:18px; font-weight:700; color:var(--text-primary); margin:0 0 10px;">' + title + '</h3>'
            + (description ? '<p style="font-size:13px; color:var(--text-secondary); margin:0; line-height:1.6;">' + description + '</p>' : '')
            + '</div>' + itemsHtml
            + '<div style="display:flex; gap:10px; justify-content:center;">'
            + '<button class="ic-cancel" style="padding:10px 24px; background:var(--bg-secondary); color:var(--text-secondary); border:1px solid var(--border); border-radius:8px; cursor:pointer; font-weight:600; font-size:14px;">Cancel</button>'
            + '<button class="ic-confirm" style="padding:10px 24px; background:' + (confirmColor || 'var(--accent-primary)') + '; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:600; font-size:14px;">' + confirmLabel + '</button>'
            + '</div></div>';
        document.body.appendChild(overlay);
        overlay.onclick = function (e) { if (e.target === overlay) { overlay.remove(); reject('cancelled'); } };
        overlay.querySelector('.ic-cancel').onclick = function () { overlay.remove(); reject('cancelled'); };
        overlay.querySelector('.ic-confirm').onclick = function () { overlay.remove(); resolve(); };
    });
}

// ── Live progress modal ──
function showProgressModal(icon, title) {
    var overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:100000;display:flex;align-items:center;justify-content:center;animation:fadeIn 0.15s ease';
    overlay.innerHTML = '<div style="background:var(--bg-card); border:1px solid var(--border); border-radius:16px; padding:32px; max-width:520px; width:90%; box-shadow:0 20px 60px rgba(0,0,0,0.5);">'
        + '<div style="text-align:center; margin-bottom:16px;">'
        + '<div style="font-size:48px; margin-bottom:8px;">' + icon + '</div>'
        + '<h3 class="pm-title" style="font-size:18px; font-weight:700; color:var(--text-primary); margin:0 0 6px;">' + title + '</h3>'
        + '</div>'
        + '<div class="pm-list" style="max-height:350px; overflow-y:auto;"></div>'
        + '<div class="pm-footer" style="display:none; margin-top:16px;"></div>'
        + '<div class="pm-actions" style="display:none; margin-top:20px; text-align:center;">'
        + '<button class="pm-done" style="padding:10px 28px; background:var(--accent-primary); color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:600; font-size:14px;">Done</button>'
        + '</div></div>';
    document.body.appendChild(overlay);
    overlay.querySelector('.pm-done').onclick = function () { overlay.remove(); };
    return {
        el: overlay,
        addRow: function (id, hostname) {
            var row = document.createElement('div');
            row.id = 'pm-row-' + id;
            row.style.cssText = 'display:flex; align-items:center; gap:10px; padding:10px 0; border-bottom:1px solid var(--border);';
            row.innerHTML = '<span class="pm-icon" style="display:inline-block;width:18px;height:18px;border:2px solid rgba(99,102,241,0.2);border-top-color:rgba(99,102,241,0.8);border-radius:50%;animation:spin 0.7s linear infinite;flex-shrink:0;"></span>'
                + '<span style="font-weight:600; color:var(--text-primary); font-size:14px;">\uD83D\uDDA5\uFE0F ' + escapeHtml(hostname) + '</span>'
                + '<span class="pm-status" style="margin-left:auto; font-size:12px; color:var(--text-muted);">Sending command...</span>';
            overlay.querySelector('.pm-list').appendChild(row);
        },
        updateRow: function (id, success, statusText) {
            var row = document.getElementById('pm-row-' + id);
            if (!row) return;
            var ic = row.querySelector('.pm-icon');
            if (ic) { ic.style.cssText = 'font-size:18px; flex-shrink:0;'; ic.textContent = success ? '\u2705' : '\u274C'; }
            var st = row.querySelector('.pm-status');
            if (st) { st.style.color = success ? '#10b981' : '#ef4444'; st.textContent = statusText; }
        },
        setTitle: function (text) { overlay.querySelector('.pm-title').innerHTML = text; },
        setFooter: function (html) { var f = overlay.querySelector('.pm-footer'); f.innerHTML = html; f.style.display = 'block'; },
        showDone: function () { overlay.querySelector('.pm-actions').style.display = 'block'; },
        remove: function () { overlay.remove(); }
    };
}

async function issuesUpgradeNode(nodeId) {
    var node = allNodes.find(function (n) { return n.id === nodeId; });
    var name = node ? node.hostname : nodeId;

    try {
        await showIssuesConfirm('\u26A1', 'Upgrade WolfStack on ' + escapeHtml(name) + '?',
            'This will run the upgrade script in the background. The server will restart automatically when complete.',
            [], '\u26A1 Upgrade', '#f59e0b');
    } catch (e) { return; }

    var modal = showProgressModal('\u26A1', 'Upgrading WolfStack');
    var safeId = (nodeId || 'local').replace(/[^a-z0-9_-]/gi, '-');
    modal.addRow(safeId, name);

    var url = (node && !node.is_self) ? '/api/nodes/' + encodeURIComponent(nodeId) + '/proxy/upgrade' : '/api/upgrade';

    try {
        await fetch(url, { method: 'POST' });
        modal.updateRow(safeId, true, 'Command sent \u2713');
    } catch (e) {
        modal.updateRow(safeId, false, 'Failed: ' + e.message);
    }

    modal.setTitle('Upgrade In Progress');
    modal.setFooter('<div style="background:rgba(234,179,8,0.1); border:1px solid rgba(234,179,8,0.3); border-radius:10px; padding:16px; text-align:center;">'
        + '<div style="font-size:24px; margin-bottom:8px;">\u23F3</div>'
        + '<div style="font-weight:600; color:var(--text-primary); font-size:14px; margin-bottom:4px;">Please wait approximately 5 minutes</div>'
        + '<div style="color:var(--text-secondary); font-size:12px;">The server is upgrading and will restart automatically.<br>Refresh your browser once complete.</div>'
        + '</div>');
    modal.showDone();
}

async function issuesUpgradeAll() {
    if (!issuesScanResults || issuesScanResults.length === 0) {
        showToast('Run a scan first.', 'warning');
        return;
    }

    // Upgrade ALL scanned nodes (force reinstall regardless of version)
    var targets = issuesScanResults.filter(function (r) { return r.node_id; });

    if (targets.length === 0) {
        showToast('No nodes found — run a scan first.', 'warning');
        return;
    }

    var nodeList = targets.map(function (r) { return '\uD83D\uDDA5\uFE0F ' + escapeHtml(r.hostname || r.node_id) + ' (v' + (r.version || '?') + ')'; });
    try {
        await showIssuesConfirm('\u26A1', 'Upgrade ' + targets.length + ' Server' + (targets.length !== 1 ? 's' : '') + '?',
            'This will trigger a background upgrade on <strong>all</strong> nodes.', nodeList, '\u26A1 Upgrade All', '#f59e0b');
    } catch (e) { return; }

    var modal = showProgressModal('\u26A1', 'Upgrading ' + targets.length + ' Server' + (targets.length !== 1 ? 's' : ''));

    targets.forEach(function (r) {
        var safeId = (r.node_id || 'local').replace(/[^a-z0-9_-]/gi, '-');
        modal.addRow(safeId, r.hostname || r.node_id);
    });

    var channel = (document.getElementById('issues-channel-select') || {}).value || 'master';
    for (var i = 0; i < targets.length; i++) {
        var r = targets[i];
        var node = allNodes.find(function (n) { return n.id === r.node_id; });
        var safeId = (r.node_id || 'local').replace(/[^a-z0-9_-]/gi, '-');
        var url = (node && !node.is_self) ? '/api/nodes/' + encodeURIComponent(r.node_id) + '/proxy/upgrade?channel=' + channel : '/api/upgrade?channel=' + channel;
        try {
            await fetch(url, { method: 'POST' });
            modal.updateRow(safeId, true, 'Command sent \u2713');
        } catch (e) {
            modal.updateRow(safeId, false, 'Failed: ' + e.message);
        }
    }

    modal.setTitle('Upgrades In Progress');
    modal.setFooter('<div style="background:rgba(234,179,8,0.1); border:1px solid rgba(234,179,8,0.3); border-radius:10px; padding:16px; text-align:center;">'
        + '<div style="font-size:24px; margin-bottom:8px;">\u23F3</div>'
        + '<div style="font-weight:600; color:var(--text-primary); font-size:14px; margin-bottom:4px;">Please wait approximately 5 minutes</div>'
        + '<div style="color:var(--text-secondary); font-size:12px;">All servers are upgrading and will restart automatically.<br>Refresh your browser once complete.</div>'
        + '</div>');
    modal.showDone();
}

async function cleanSystem() {
    try {
        await showIssuesConfirm('\uD83E\uDDF9', 'Clean All Servers?',
            'This will safely free disk space on <strong>all nodes</strong> by:',
            ['\uD83D\uDCCB Vacuuming journal logs to 200 MB', '\uD83D\uDCE6 Clearing package cache (apt/dnf)',
                '\uD83D\uDC33 Pruning unused Docker resources', '\uD83D\uDDD1\uFE0F Removing old kernels', '\uD83D\uDCC1 Deleting old /tmp files (>7 days)'],
            '\uD83E\uDDF9 Clean All Servers');
    } catch (e) { return; }

    var btn = document.getElementById('issues-clean-btn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span style="display:inline-block;width:14px;height:14px;border:2px solid rgba(59,130,246,0.2);border-top-color:#3b82f6;border-radius:50%;animation:spin 0.7s linear infinite;vertical-align:middle;margin-right:6px;"></span> Cleaning...'; }

    var wsNodes = (typeof allNodes !== 'undefined' && allNodes.length) ? allNodes.filter(function (n) { return n.node_type !== 'proxmox'; }) : [];
    if (wsNodes.length === 0) wsNodes = [{ id: 'local', hostname: 'local', is_self: true }];

    var modal = showProgressModal('\uD83E\uDDF9', 'Cleaning ' + wsNodes.length + ' Server' + (wsNodes.length !== 1 ? 's' : ''));
    wsNodes.forEach(function (node) {
        var safeId = (node.id || 'local').replace(/[^a-z0-9_-]/gi, '-');
        modal.addRow(safeId, node.hostname || node.id || 'local');
    });

    var totalFreed = 0;
    var successCount = 0;
    for (var i = 0; i < wsNodes.length; i++) {
        var node = wsNodes[i];
        var safeId = (node.id || 'local').replace(/[^a-z0-9_-]/gi, '-');
        var isLocal = !!node.is_self;
        var url = isLocal ? '/api/issues/clean' : '/api/nodes/' + encodeURIComponent(node.id) + '/proxy/issues/clean';
        try {
            var resp = await fetch(url, { method: 'POST', credentials: 'include' });
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            var data = await resp.json();
            var freed = data.freed_mb || 0;
            totalFreed += freed;
            successCount++;
            var freedStr = freed > 0 ? 'Freed ' + (freed > 1024 ? (freed / 1024).toFixed(1) + ' GB' : freed + ' MB') : 'Already clean';
            modal.updateRow(safeId, true, freedStr);
        } catch (e) {
            modal.updateRow(safeId, false, 'Error: ' + e.message);
        }
    }

    var summaryText = totalFreed > 0
        ? '\uD83C\uDF89 Freed ~' + (totalFreed > 1024 ? (totalFreed / 1024).toFixed(1) + ' GB' : totalFreed + ' MB') + ' across ' + successCount + ' server' + (successCount !== 1 ? 's' : '')
        : '\u2705 All servers are clean';
    modal.setTitle(summaryText);
    modal.showDone();

    if (btn) { btn.disabled = false; btn.innerHTML = '\uD83E\uDDF9 Clean'; }
}


// ═══════════════════════════════════════════════
// ─── Global WolfNet Page ───
// ═══════════════════════════════════════════════

var gwnScanData = []; // flat list of { server, type, name, ip, state }
var gwnSortCol = 0;   // default sort by Cluster column (Cluster|Server|Type|Name|IP|Peers|State)
var gwnSortAsc = true;

function ipToNum(ip) {
    if (!ip) return 0;
    var parts = ip.split('.');
    if (parts.length !== 4) return 0;
    return ((+parts[0]) * 16777216) + ((+parts[1]) * 65536) + ((+parts[2]) * 256) + (+parts[3]);
}

function gwnSortBy(col) {
    if (gwnSortCol === col) { gwnSortAsc = !gwnSortAsc; } else { gwnSortCol = col; gwnSortAsc = true; }
    renderGwnTable();
}

function renderGwnTable() {
    var content = document.getElementById('gwn-content');
    if (!content || gwnScanData.length === 0) return;
    var q = (document.getElementById('gwn-filter').value || '').toLowerCase();
    var filtered = gwnScanData.filter(function (r) {
        return ((r.cluster || '') + ' ' + r.server + ' ' + r.type + ' ' + r.name + ' ' + r.ip + ' ' + (r.peers || '') + ' ' + r.state).toLowerCase().includes(q);
    });
    var sorted = filtered.slice().sort(function (a, b) {
        var keys = ['cluster', 'server', 'type', 'name', 'ip', 'peers', 'state'];
        var key = keys[gwnSortCol] || 'ip';
        var va = a[key] || '', vb = b[key] || '';
        if (key === 'ip') { va = ipToNum(va); vb = ipToNum(vb); return gwnSortAsc ? va - vb : vb - va; }
        return gwnSortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    });
    var arrows = ['', '', '', '', '', '', ''];
    arrows[gwnSortCol] = gwnSortAsc ? ' ▲' : ' ▼';
    var html = '<div class="card"><div class="card-body" style="padding:0; overflow-x:auto;">';
    html += '<table class="data-table" id="gwn-main-table"><thead><tr>';
    html += '<th onclick="gwnSortBy(0)" style="cursor:pointer;">Cluster' + arrows[0] + '</th>';
    html += '<th onclick="gwnSortBy(1)" style="cursor:pointer;">Server' + arrows[1] + '</th>';
    html += '<th onclick="gwnSortBy(2)" style="cursor:pointer;">Type' + arrows[2] + '</th>';
    html += '<th onclick="gwnSortBy(3)" style="cursor:pointer;">Name' + arrows[3] + '</th>';
    html += '<th onclick="gwnSortBy(4)" style="cursor:pointer;">WolfNet IP' + arrows[4] + '</th>';
    html += '<th onclick="gwnSortBy(5)" style="cursor:pointer;">Peers' + arrows[5] + '</th>';
    html += '<th onclick="gwnSortBy(6)" style="cursor:pointer;">State' + arrows[6] + '</th>';
    html += '</tr></thead><tbody>';
    if (sorted.length === 0) {
        html += '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:24px;">No results</td></tr>';
    } else {
        sorted.forEach(function (r) {
            var typeIcon = r.type === 'WolfNet' ? '\uD83C\uDF10' : r.type === 'Peer' ? '\uD83D\uDD17' : r.type === 'LXC' ? '\uD83D\uDCE6' : r.type === 'Docker' ? '\uD83D\uDC33' : r.type === 'VM' ? '\uD83D\uDDA5\uFE0F' : '\u2796';
            var bg = r.type === 'WolfNet' ? 'rgba(59,130,246,0.08)' : r.type === 'LXC' ? 'rgba(234,179,8,0.08)' : r.type === 'Docker' ? 'rgba(99,102,241,0.08)' : r.type === 'VM' ? 'rgba(16,185,129,0.08)' : r.type === 'Peer' ? 'rgba(59,130,246,0.04)' : 'transparent';
            html += '<tr style="background:' + bg + ';"><td>' + escapeHtml(r.cluster || '') + '</td><td>' + escapeHtml(r.server) + '</td><td>' + typeIcon + ' ' + escapeHtml(r.type) + '</td><td>' + escapeHtml(r.name) + '</td><td><code>' + escapeHtml(r.ip || '—') + '</code></td><td style="font-size:11px;">' + escapeHtml(r.peers || '') + '</td><td>' + escapeHtml(r.state) + '</td></tr>';
        });
    }
    html += '</tbody></table></div></div>';
    content.innerHTML = html;
}

async function scanGlobalWolfNet() {
    var btn = document.getElementById('gwn-scan-btn');
    var content = document.getElementById('gwn-content');
    if (btn) { btn.disabled = true; btn.innerHTML = '<span style="display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.2);border-top-color:#fff;border-radius:50%;animation:spin 0.7s linear infinite;vertical-align:middle;margin-right:6px;"></span> Scanning...'; }

    var wsNodes = (typeof allNodes !== 'undefined' && allNodes.length) ? allNodes : [];
    if (wsNodes.length === 0) wsNodes = [{ id: 'local', hostname: 'local', is_self: true, cluster_name: 'WolfStack' }];

    gwnScanData = [];
    var totalNodes = wsNodes.length, scannedNodes = 0;

    // Render table with placeholders immediately
    var arrows = ['', '', '', '', '', '', ''];
    arrows[gwnSortCol] = gwnSortAsc ? ' \u25b2' : ' \u25bc';
    var tableHtml = '<div class="card"><div class="card-body" style="padding:0; overflow-x:auto;">';
    tableHtml += '<table class="data-table" id="gwn-main-table"><thead><tr>';
    tableHtml += '<th onclick="gwnSortBy(0)" style="cursor:pointer;">Cluster' + arrows[0] + '</th>';
    tableHtml += '<th onclick="gwnSortBy(1)" style="cursor:pointer;">Server' + arrows[1] + '</th>';
    tableHtml += '<th onclick="gwnSortBy(2)" style="cursor:pointer;">Type' + arrows[2] + '</th>';
    tableHtml += '<th onclick="gwnSortBy(3)" style="cursor:pointer;">Name' + arrows[3] + '</th>';
    tableHtml += '<th onclick="gwnSortBy(4)" style="cursor:pointer;">WolfNet IP' + arrows[4] + '</th>';
    tableHtml += '<th onclick="gwnSortBy(5)" style="cursor:pointer;">Peers' + arrows[5] + '</th>';
    tableHtml += '<th onclick="gwnSortBy(6)" style="cursor:pointer;">State' + arrows[6] + '</th>';
    tableHtml += '</tr></thead><tbody id="gwn-tbody">';
    wsNodes.forEach(function (n) {
        var safeId = (n.id || 'local').replace(/[^a-z0-9_-]/gi, '-');
        tableHtml += '<tr id="gwn-ph-' + safeId + '" style="color:var(--text-muted);"><td>' + escapeHtml(n.hostname || n.id || 'local') + '</td><td colspan="6"><span style="display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,0.15);border-top-color:var(--text-muted);border-radius:50%;animation:spin 0.7s linear infinite;vertical-align:middle;margin-right:6px;"></span> Scanning...</td></tr>';
    });
    tableHtml += '</tbody></table></div></div>';
    if (content) content.innerHTML = tableHtml;
    var elN = document.getElementById('gwn-count-nodes'); if (elN) elN.textContent = totalNodes;

    function addRowsForNode(nodeId, rows) {
        var tbody = document.getElementById('gwn-tbody');
        if (!tbody) return;
        var ph = document.getElementById('gwn-ph-' + (nodeId || 'local').replace(/[^a-z0-9_-]/gi, '-'));
        if (ph) ph.remove();
        rows.forEach(function (r) {
            gwnScanData.push(r);
            var typeIcon = r.type === 'WolfNet' ? '\uD83C\uDF10' : r.type === 'Peer' ? '\uD83D\uDD17' : r.type === 'LXC' ? '\uD83D\uDCE6' : r.type === 'Docker' ? '\uD83D\uDC33' : r.type === 'VM' ? '\uD83D\uDDA5\uFE0F' : '\u2796';
            var bg = r.type === 'WolfNet' ? 'rgba(59,130,246,0.08)' : r.type === 'LXC' ? 'rgba(234,179,8,0.08)' : r.type === 'Docker' ? 'rgba(99,102,241,0.08)' : r.type === 'VM' ? 'rgba(16,185,129,0.08)' : r.type === 'Peer' ? 'rgba(59,130,246,0.04)' : 'transparent';
            var tr = document.createElement('tr');
            tr.style.background = bg;
            tr.innerHTML = '<td>' + escapeHtml(r.cluster || '') + '</td><td>' + escapeHtml(r.server) + '</td><td>' + typeIcon + ' ' + escapeHtml(r.type) + '</td><td>' + escapeHtml(r.name) + '</td><td><code>' + escapeHtml(r.ip || '\u2014') + '</code></td><td style="font-size:11px;">' + escapeHtml(r.peers || '') + '</td><td>' + escapeHtml(r.state) + '</td>';
            tbody.appendChild(tr);
        });
        var el;
        el = document.getElementById('gwn-count-peers'); if (el) el.textContent = gwnScanData.filter(function (r) { return r.type === 'WolfNet'; }).length;
        el = document.getElementById('gwn-count-lxc'); if (el) el.textContent = gwnScanData.filter(function (r) { return r.type === 'LXC'; }).length;
        el = document.getElementById('gwn-count-docker'); if (el) el.textContent = gwnScanData.filter(function (r) { return r.type === 'Docker'; }).length;
    }

    async function scanNode(node) {
        var isLocal = !!node.is_self;
        var urlBase = isLocal ? '/api/' : '/api/nodes/' + encodeURIComponent(node.id) + '/proxy/';
        var serverName = node.hostname || node.id || 'local';
        var clusterName = node.cluster_name || '';
        var rows = [];
        try {
            var wn = await fetch(urlBase + 'networking/wolfnet', { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : null; });
            if (wn) {
                var selfIp = (wn.ip || '').split('/')[0];
                if (selfIp) {
                    var peerList = (wn.peers || []).map(function (p) { return (p.name || '') + ':' + ((p.ip || '').split('/')[0]); }).join(', ');
                    rows.push({ cluster: clusterName, server: serverName, type: 'WolfNet', name: serverName, ip: selfIp, peers: peerList, state: wn.running ? 'Running' : 'Stopped' });
                }
            }
        } catch (e) { }
        try {
            var lxcData = await fetch(urlBase + 'containers/lxc', { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : null; });
            if (lxcData) {
                var list = Array.isArray(lxcData) ? lxcData : (lxcData.containers || []);
                list.forEach(function (c) {
                    var ip = String(c.ip || c.ipv4 || '').split('/')[0];
                    if (ip) rows.push({ cluster: clusterName, server: serverName, type: 'LXC', name: c.name || c.id || '?', ip: ip, peers: '', state: c.state || c.status || '?' });
                });
            }
        } catch (e) { }
        try {
            var dockerData = await fetch(urlBase + 'containers/docker', { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : null; });
            if (dockerData) {
                var list = Array.isArray(dockerData) ? dockerData : (dockerData.containers || []);
                list.forEach(function (c) {
                    var name = ((c.names && c.names[0]) || c.name || c.id || '?').replace(/^\//, '');
                    var state = c.state || c.status || '?';
                    var nets = (c.networks || (c.NetworkSettings && c.NetworkSettings.Networks) || {});
                    var entries = Object.entries(nets);
                    if (entries.length === 0) {
                        if (c.ip) rows.push({ cluster: clusterName, server: serverName, type: 'Docker', name: name, ip: c.ip, peers: '', state: state });
                    } else {
                        entries.forEach(function (entry) {
                            var netInfo = entry[1];
                            var ip = ((netInfo && (netInfo.IPAddress || netInfo.ip_address)) || c.ip || '').split('/')[0];
                            if (ip) rows.push({ cluster: clusterName, server: serverName, type: 'Docker', name: name + ' (' + entry[0] + ')', ip: ip, peers: '', state: state });
                        });
                    }
                });
            }
        } catch (e) { }
        try {
            var vmData = await fetch(urlBase + 'vms', { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : null; });
            if (vmData) {
                var list = Array.isArray(vmData) ? vmData : (vmData.vms || []);
                list.forEach(function (v) {
                    var raw = v.ips || v.ip_addresses || (v.ip ? [v.ip] : []);
                    var ips = Array.isArray(raw) ? raw : [raw];
                    ips.filter(function (x) { return x && !String(x).startsWith('127.'); }).forEach(function (ip) {
                        rows.push({ cluster: clusterName, server: serverName, type: 'VM', name: v.name || v.vmid || v.id || '?', ip: String(ip).split('/')[0], peers: '', state: v.state || v.status || '?' });
                    });
                });
            }
        } catch (e) { }
        if (rows.length === 0) rows.push({ cluster: clusterName, server: serverName, type: '-', name: '-', ip: '-', peers: '', state: 'No data' });
        addRowsForNode(node.id, rows);
    }

    // Fire ALL node scans in parallel
    await Promise.all(wsNodes.map(function (node) { return scanNode(node); }));
    if (btn) { btn.disabled = false; btn.innerHTML = '\uD83D\uDD0D Scan'; }
}

function filterGlobalWolfNet() {
    renderGwnTable();
}


// ═══════════════════════════════════════════════
// ─── App Store ───
// ═══════════════════════════════════════════════
let appStoreApps = [];
let appStoreCategory = 'All';
let appStoreInstallAppId = null;
let appStoreInstallTarget = 'docker';

const APP_ICONS = {
    'wordpress': '📝', 'nextcloud': '☁️', 'gitea': '🦊', 'grafana': '📊',
    'prometheus': '🔥', 'postgresql': '🐘', 'mariadb': '🗄️', 'redis': '⚡',
    'nginx': '🌐', 'traefik': '🔀', 'pihole': '🛡️', 'jellyfin': '🎬',
    'portainer': '🐳', 'minio': '💾', 'code-server': '💻', 'homeassistant': '🏠',
};

async function loadAppStoreApps() {
    try {
        const res = await fetch('/api/appstore/apps');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        appStoreApps = data.apps || [];
        renderAppStoreGrid();
    } catch (e) {
        const grid = document.getElementById('appstore-grid');
        if (grid) grid.innerHTML = `<div style="padding:40px; text-align:center; color:var(--text-muted); grid-column:1/-1;">Failed to load apps: ${escapeHtml(e.message)}</div>`;
    }
}

function renderAppStoreGrid() {
    const grid = document.getElementById('appstore-grid');
    if (!grid) return;

    const query = (document.getElementById('appstore-search')?.value || '').toLowerCase();
    const filtered = appStoreApps.filter(app => {
        if (appStoreCategory !== 'All' && app.category !== appStoreCategory) return false;
        if (query && !app.name.toLowerCase().includes(query) && !app.description.toLowerCase().includes(query)) return false;
        return true;
    });

    if (filtered.length === 0) {
        grid.innerHTML = '<div style="padding:40px; text-align:center; color:var(--text-muted); grid-column:1/-1;">No apps match your search.</div>';
        return;
    }

    filtered.sort((a, b) => a.name.localeCompare(b.name));

    grid.innerHTML = filtered.map(app => {
        const icon = APP_ICONS[app.id] || '📦';
        const targets = [];
        if (app.docker) targets.push('Docker');
        if (app.lxc) targets.push('LXC');
        if (app.bare_metal) targets.push('Host');

        const docsLink = app.website ? `<a href="${escapeHtml(app.website)}" target="_blank" rel="noopener" title="Documentation" style="color:var(--text-muted); font-size:16px; text-decoration:none; padding:4px 6px; border-radius:6px; transition:color 0.2s, background 0.2s;" onmouseover="this.style.color='var(--accent-light)'; this.style.background='var(--accent-glow)'" onmouseout="this.style.color='var(--text-muted)'; this.style.background='none'">🔗</a>` : '';

        return `<div class="appstore-card">
            <div class="appstore-card-header">
                <div class="appstore-card-icon">${icon}</div>
                <div>
                    <div class="appstore-card-title">${escapeHtml(app.name)}</div>
                    <span class="appstore-card-category">${escapeHtml(app.category)}</span>
                </div>
            </div>
            <div class="appstore-card-desc">${escapeHtml(app.description)}</div>
            <div class="appstore-card-footer">
                <div class="appstore-card-targets">
                    ${targets.map(t => `<span class="appstore-target-badge">${t}</span>`).join('')}
                </div>
                <div style="display:flex; align-items:center; gap:6px;">
                    ${docsLink}
                    <button class="appstore-install-btn" onclick="openAppStoreInstallModal('${app.id}')">Install</button>
                </div>
            </div>
        </div>`;
    }).join('');
}

function filterAppStore() {
    renderAppStoreGrid();
}

function filterAppStoreCategory(cat) {
    appStoreCategory = cat;
    document.querySelectorAll('.appstore-cat-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    renderAppStoreGrid();
}

function switchAppStoreTab(tab) {
    document.querySelectorAll('.appstore-tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`appstore-tab-${tab}`)?.classList.add('active');

    if (tab === 'browse') {
        document.getElementById('appstore-browse-tab').style.display = '';
        document.getElementById('appstore-installed-tab').style.display = 'none';
    } else {
        document.getElementById('appstore-browse-tab').style.display = 'none';
        document.getElementById('appstore-installed-tab').style.display = '';
        loadInstalledApps();
    }
}

// ─── Install Modal ───
function openAppStoreInstallModal(appId) {
    appStoreInstallAppId = appId;
    const app = appStoreApps.find(a => a.id === appId);
    if (!app) return;

    document.getElementById('appstore-install-title').textContent = `Install ${app.name}`;
    document.getElementById('appstore-install-name').value = app.id.replace(/_/g, '-');

    // Populate host selector from allNodes (show all, mark offline) — sorted alphabetically
    const hostSelect = document.getElementById('appstore-install-host');
    const sortedNodes = [...allNodes].sort((a, b) => a.hostname.localeCompare(b.hostname));
    hostSelect.innerHTML = sortedNodes.map(n => {
        const status = n.online ? '' : ' [offline]';
        const self = n.is_self ? ' — this server' : '';
        const label = `${n.hostname} (${n.address})${self}${status}`;
        return `<option value="${n.id}" ${n.is_self ? 'selected' : ''}>${escapeHtml(label)}</option>`;
    }).join('');
    if (allNodes.length === 0) {
        hostSelect.innerHTML = '<option value="">No servers found</option>';
    }

    // Build target buttons
    const targetsEl = document.getElementById('appstore-install-targets');
    let targetHtml = '';
    const targets = [];
    if (app.docker) targets.push({ key: 'docker', label: '🐳 Docker' });
    if (app.lxc) targets.push({ key: 'lxc', label: '📦 LXC' });
    if (app.bare_metal) targets.push({ key: 'bare_metal', label: '🖥️ Host' });

    appStoreInstallTarget = targets[0]?.key || 'docker';
    targetHtml = targets.map(t =>
        `<button class="appstore-target-pill ${t.key === appStoreInstallTarget ? 'active' : ''}" onclick="selectInstallTarget('${t.key}')">${t.label}</button>`
    ).join('');
    targetsEl.innerHTML = targetHtml;

    // Build user input fields
    const inputsEl = document.getElementById('appstore-install-inputs');
    if (app.user_inputs && app.user_inputs.length > 0) {
        inputsEl.innerHTML = app.user_inputs.map(inp => `
            <div style="margin-bottom:12px;">
                <label style="font-size:13px; font-weight:500; display:block; margin-bottom:4px; color:var(--text-secondary);">${escapeHtml(inp.label)}</label>
                <input type="${inp.input_type === 'password' ? 'password' : 'text'}" class="form-control appstore-user-input"
                    data-key="${escapeHtml(inp.id)}" placeholder="${escapeHtml(inp.placeholder || inp.default || '')}" value="${escapeHtml(inp.default || '')}">
            </div>
        `).join('');
    } else {
        inputsEl.innerHTML = '';
    }

    // Show modal
    const modal = document.getElementById('appstore-install-modal');
    modal.style.display = 'flex';
    setTimeout(() => modal.classList.add('active'), 10);
}

function selectInstallTarget(target) {
    appStoreInstallTarget = target;
    document.querySelectorAll('#appstore-install-targets .appstore-target-pill').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
}

function closeAppStoreInstallModal() {
    const modal = document.getElementById('appstore-install-modal');
    modal.classList.remove('active');
    setTimeout(() => modal.style.display = 'none', 200);
}

async function executeAppStoreInstall() {
    const name = document.getElementById('appstore-install-name').value.trim();
    if (!name) { showToast('Please enter a container name', 'error'); return; }

    // Gather user inputs
    const userInputs = {};
    document.querySelectorAll('.appstore-user-input').forEach(el => {
        userInputs[el.dataset.key] = el.value;
    });

    // Determine the install URL based on selected host
    const selectedNodeId = document.getElementById('appstore-install-host').value;
    const selectedNode = allNodes.find(n => n.id === selectedNodeId);
    const hostName = selectedNode ? selectedNode.hostname : 'this server';
    const targetLabel = appStoreInstallTarget === 'docker' ? '🐳 Docker' : appStoreInstallTarget === 'lxc' ? '📦 LXC' : '🖥️ Host';
    const appName = (appStoreApps.find(a => a.id === appStoreInstallAppId) || {}).name || appStoreInstallAppId;

    // Close the install modal and show progress overlay
    closeAppStoreInstallModal();

    const progressOverlay = document.createElement('div');
    progressOverlay.className = 'modal-overlay active';
    progressOverlay.style.cssText = 'display:flex; z-index:10001;';
    progressOverlay.innerHTML = `
        <div style="background:var(--bg-card); border:1px solid var(--border); border-radius:16px; padding:32px; max-width:420px; width:90%; text-align:center; box-shadow:0 20px 60px rgba(0,0,0,0.5); animation:modalSlideIn 0.3s ease;">
            <div style="width:64px; height:64px; border:3px solid var(--border); border-top-color:var(--accent); border-radius:50%; animation:spin 0.8s linear infinite; margin:0 auto 20px;"></div>
            <h3 style="color:var(--text-primary); font-size:18px; margin-bottom:6px; font-weight:700;">Installing ${escapeHtml(appName)}</h3>
            <p style="color:var(--text-secondary); font-size:13px; margin-bottom:20px;">Deploying to <strong>${escapeHtml(hostName)}</strong> via ${targetLabel}</p>
            <div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:10px; padding:12px; margin-bottom:20px; text-align:left;">
                <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                    <span style="color:var(--text-muted); font-size:12px;">Container</span>
                    <span style="color:var(--text-primary); font-size:12px; font-weight:600;">${escapeHtml(name)}</span>
                </div>
                <div style="display:flex; justify-content:space-between;">
                    <span style="color:var(--text-muted); font-size:12px;">Status</span>
                    <span id="install-progress-status" style="color:var(--accent-light); font-size:12px; font-weight:600;">⏳ Pulling image & configuring…</span>
                </div>
            </div>
            <div style="height:4px; background:var(--bg-secondary); border-radius:4px; overflow:hidden;">
                <div style="height:100%; width:30%; background:linear-gradient(90deg,var(--accent),var(--accent-light)); border-radius:4px; animation:progressPulse 1.5s ease-in-out infinite;"></div>
            </div>
            <p style="color:var(--text-muted); font-size:11px; margin-top:12px;">This may take a minute depending on image size…</p>
        </div>`;
    document.body.appendChild(progressOverlay);

    try {
        let installUrl;
        if (!selectedNode || selectedNode.is_self) {
            installUrl = `/api/appstore/apps/${appStoreInstallAppId}/install`;
        } else {
            installUrl = `/api/nodes/${selectedNodeId}/proxy/appstore/apps/${appStoreInstallAppId}/install`;
        }

        const res = await fetch(installUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                container_name: name,
                target: appStoreInstallTarget,
                inputs: userInputs,
            }),
        });
        const data = await res.json().catch(() => ({}));
        progressOverlay.remove();

        if (res.ok) {
            const message = data.message || 'App deployed successfully';
            const alertOverlay = document.createElement('div');
            alertOverlay.className = 'modal-overlay active';
            alertOverlay.style.cssText = 'display:flex; z-index:10001;';
            alertOverlay.innerHTML = `
                <div style="background:var(--bg-card); border:1px solid var(--border); border-radius:16px; padding:32px; max-width:440px; width:90%; text-align:center; box-shadow:0 20px 60px rgba(0,0,0,0.5); animation: modalSlideIn 0.3s ease;">
                    <div style="width:72px; height:72px; background:linear-gradient(135deg, #10b981, #34d399); border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 20px; font-size:36px; box-shadow:0 4px 20px rgba(16,185,129,0.4);">✅</div>
                    <h3 style="color:var(--text-primary); font-size:20px; margin-bottom:8px; font-weight:700;">Deployed Successfully</h3>
                    <p style="color:var(--text-secondary); font-size:14px; margin-bottom:20px; line-height:1.6;">${escapeHtml(message)}</p>
                    <div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:10px; padding:14px; margin-bottom:24px; text-align:left;">
                        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                            <span style="color:var(--text-muted); font-size:12px;">Container</span>
                            <span style="color:var(--text-primary); font-size:12px; font-weight:600;">${escapeHtml(name)}</span>
                        </div>
                        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                            <span style="color:var(--text-muted); font-size:12px;">Host</span>
                            <span style="color:var(--text-primary); font-size:12px; font-weight:600;">${escapeHtml(hostName)}</span>
                        </div>
                        <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                            <span style="color:var(--text-muted); font-size:12px;">Target</span>
                            <span style="color:var(--text-primary); font-size:12px; font-weight:600;">${targetLabel}</span>
                        </div>
                        <div style="display:flex; justify-content:space-between;">
                            <span style="color:var(--text-muted); font-size:12px;">Status</span>
                            <span style="color:#f59e0b; font-size:12px; font-weight:600;">⏸ Stopped — ready to start</span>
                        </div>
                    </div>
                    <button onclick="this.closest('.modal-overlay').remove()" style="background:linear-gradient(135deg, #10b981, #34d399); color:white; border:none; padding:10px 40px; border-radius:10px; font-size:14px; font-weight:600; cursor:pointer; font-family:inherit; transition:transform 0.15s, box-shadow 0.15s; box-shadow:0 4px 15px rgba(16,185,129,0.3);"
                        onmouseover="this.style.transform='translateY(-1px)'; this.style.boxShadow='0 6px 20px rgba(16,185,129,0.4)'"
                        onmouseout="this.style.transform=''; this.style.boxShadow='0 4px 15px rgba(16,185,129,0.3)'">👍 Got it</button>
                </div>
            `;
            document.body.appendChild(alertOverlay);
        } else {
            showToast(data.error || `Installation failed (HTTP ${res.status})`, 'error');
        }
    } catch (e) {
        progressOverlay.remove();
        showToast('Installation failed: ' + e.message, 'error');
    }
}

// ─── Installed Apps ───
async function loadInstalledApps() {
    const listEl = document.getElementById('appstore-installed-list');
    if (!listEl) return;

    try {
        const res = await fetch('/api/appstore/installed');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const installed = data.installed || [];

        if (installed.length === 0) {
            listEl.innerHTML = '<div style="padding:40px; text-align:center; color:var(--text-muted);">No apps installed yet. Browse the store and install your first app!</div>';
            return;
        }

        listEl.innerHTML = installed.map(app => {
            const icon = APP_ICONS[app.app_id] || '📦';
            const date = new Date(app.installed_at).toLocaleString();
            return `<div class="appstore-installed-card">
                <div style="font-size:28px;">${icon}</div>
                <div style="flex:1;">
                    <div style="font-weight:600; font-size:14px;">${escapeHtml(app.name)}</div>
                    <div style="font-size:12px; color:var(--text-muted);">
                        ${escapeHtml(app.app_id)} · ${escapeHtml(app.target)} · Installed ${date}
                    </div>
                </div>
                <button class="btn btn-danger btn-sm" onclick="uninstallApp('${escapeHtml(app.id)}', '${escapeHtml(app.name)}')">🗑️ Uninstall</button>
            </div>`;
        }).join('');
    } catch (e) {
        listEl.innerHTML = `<div style="padding:40px; text-align:center; color:var(--text-muted);">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
}

async function uninstallApp(installId, name) {
    if (!confirm(`Uninstall ${name}? This will remove the container or service.`)) return;
    try {
        const res = await fetch(`/api/appstore/installed/${installId}`, { method: 'DELETE' });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message || `${name} uninstalled`, 'success');
            loadInstalledApps();
        } else {
            showToast(data.error || 'Uninstall failed', 'error');
        }
    } catch (e) {
        showToast('Uninstall failed: ' + e.message, 'error');
    }
}

// ═══════════════════════════════════════════════
// ─── Security Page (per-node) ───
// ═══════════════════════════════════════════════

async function loadNodeSecurity() {
    const container = document.getElementById('security-node-content');
    if (!container) return;

    const node = allNodes.find(n => n.id === currentNodeId);
    if (!node) {
        container.innerHTML = '<div style="padding:40px; text-align:center; color:var(--text-muted);">No node selected.</div>';
        return;
    }

    const url = node.is_self
        ? '/api/security/status'
        : `/api/nodes/${node.id}/proxy/security/status`;

    try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        container.innerHTML = renderNodeSecurity(node, data);
    } catch (e) {
        container.innerHTML = `<div class="card" style="border-color:rgba(239,68,68,0.3);"><div class="card-body" style="padding:24px;"><div style="color:#ef4444; font-size:14px;">⚠️ Failed to retrieve security status: ${escapeHtml(e.message)}</div></div></div>`;
    }
}

function renderNodeSecurity(node, data) {
    const nodePrefix = node.is_self ? '' : `nodes/${node.id}/proxy/`;

    // ── Fail2ban ──
    let f2bHtml;
    if (data.fail2ban.installed) {
        const jails = data.fail2ban.jails || 'none';
        const banned = (data.fail2ban.banned || '').trim();
        const bannedLines = banned ? banned.split('\n').filter(l => l.trim()).map(l => `<div style="font-size:12px; color:#ef4444; padding:2px 0;">${escapeHtml(l.trim())}</div>`).join('') : '<span style="color:#22c55e; font-size:12px;">No banned IPs</span>';
        const jailExists = data.fail2ban.jail_local_exists;

        const settingRow = (label, value, hint) => `
            <div style="display:flex; align-items:center; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--border);">
                <div>
                    <span style="font-weight:600; font-size:13px; color:var(--text-primary);">${label}</span>
                    <div style="font-size:11px; color:var(--text-muted);">${hint}</div>
                </div>
                <span style="font-size:13px; color:var(--text-secondary); font-family:monospace; background:var(--bg-primary); padding:4px 10px; border-radius:6px; border:1px solid var(--border);">${escapeHtml(value || '\u2014')}</span>
            </div>`;

        const settingsHtml = jailExists ? `
            <div style="margin-top:12px;">
                ${settingRow('Ban Time', data.fail2ban.bantime, 'How long an IP stays banned')}
                ${settingRow('Find Time', data.fail2ban.findtime, 'Window to count failures')}
                ${settingRow('Max Retry', data.fail2ban.maxretry, 'Failed attempts before ban')}
                ${settingRow('Ignore IPs', data.fail2ban.ignoreip, 'IPs that are never banned')}
            </div>
            <div style="display:flex; gap:8px; margin-top:12px;">
                <button onclick="editJailLocal('${nodePrefix}')" class="btn btn-sm" style="font-size:12px;">📝 Edit jail.local</button>
                <button onclick="securityAction('${nodePrefix}security/fail2ban/rebuild', 'POST', {}, this)" class="btn btn-sm" style="font-size:12px;">🔄 Rebuild jail.local</button>
            </div>` : `
            <div style="margin-top:12px; padding:12px; background:var(--bg-primary); border-radius:8px; border:1px solid var(--border);">
                <div style="display:flex; align-items:center; justify-content:space-between;">
                    <div>
                        <div style="font-weight:600; font-size:13px; color:#f59e0b;">\u26a0\ufe0f No jail.local found</div>
                        <div style="font-size:12px; color:var(--text-muted);">Using defaults from jail.conf. Create jail.local for custom settings.</div>
                    </div>
                    <button onclick="securityAction('${nodePrefix}security/fail2ban/install', 'POST', {}, this)" class="btn btn-sm btn-primary" style="font-size:12px;">Create jail.local</button>
                </div>
            </div>`;

        f2bHtml = `
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header" style="display:flex; align-items:center; justify-content:space-between;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:20px;">\ud83d\udee1\ufe0f</span>
                    <h3 style="margin:0;">Fail2ban</h3>
                    <span style="background:#22c55e20; color:#22c55e; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">Installed</span>
                </div>
                <button onclick="securityAction('${nodePrefix}security/fail2ban/install', 'POST', {}, this)" class="btn btn-sm" style="font-size:12px;">\ud83d\udd04 Update</button>
            </div>
            <div class="card-body">
                <div style="font-size:13px; color:var(--text-secondary); margin-bottom:8px;"><strong>Active Jails:</strong> ${escapeHtml(jails)}</div>
                <div style="margin-bottom:4px;">${bannedLines}</div>
                ${settingsHtml}
            </div>
        </div>`;
    } else {
        f2bHtml = `
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header" style="display:flex; align-items:center; justify-content:space-between;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:20px;">\ud83d\udee1\ufe0f</span>
                    <h3 style="margin:0;">Fail2ban</h3>
                    <span style="background:#ef444420; color:#ef4444; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">Not Installed</span>
                </div>
                <button onclick="securityAction('${nodePrefix}security/fail2ban/install', 'POST', {}, this)" class="btn btn-sm btn-primary" style="font-size:12px;">Install Fail2ban</button>
            </div>
            <div class="card-body">
                <p style="color:var(--text-secondary); font-size:13px; margin:0;">Fail2ban protects against brute-force attacks by banning IPs with too many failed login attempts. Installing will also create a default jail.local with sensible settings.</p>
            </div>
        </div>`;
    }

    // ── UFW ──
    let ufwHtml;
    if (data.ufw.installed) {
        const ufwStatus = (data.ufw.status || '').trim();
        const isActive = ufwStatus.toLowerCase().includes('active');
        const statusBadge = isActive
            ? '<span style="background:#22c55e20; color:#22c55e; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">Active</span>'
            : '<span style="background:#f59e0b20; color:#f59e0b; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">Inactive</span>';

        ufwHtml = `
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header" style="display:flex; align-items:center; justify-content:space-between;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:20px;">🔥</span>
                    <h3 style="margin:0;">UFW Firewall</h3>
                    ${statusBadge}
                </div>
                <button onclick="securityAction('${nodePrefix}security/ufw/toggle', 'POST', {enable: ${!isActive}}, this)" class="btn btn-sm" style="font-size:12px;">${isActive ? '⏸️ Disable' : '▶️ Enable'}</button>
            </div>
            <div class="card-body">
                <pre style="font-size:11px; color:var(--text-secondary); background:var(--bg-primary); padding:10px; border-radius:6px; max-height:180px; overflow-y:auto; white-space:pre-wrap; margin:0 0 12px; border:1px solid var(--border);">${escapeHtml(ufwStatus)}</pre>
                <div style="display:flex; gap:8px;">
                    <input type="text" id="ufw-rule-input" placeholder="e.g. allow 443/tcp" style="flex:1; padding:8px 12px; font-size:13px; border-radius:8px; background:var(--bg-secondary); border:1px solid var(--border); color:var(--text-primary); outline:none; font-family:inherit;">
                    <button onclick="addUfwRule('${nodePrefix}')" class="btn btn-sm btn-primary" style="font-size:12px;">Add Rule</button>
                </div>
            </div>
        </div>`;
    } else {
        ufwHtml = `
        <div class="card" style="margin-bottom:16px;">
            <div class="card-header" style="display:flex; align-items:center; justify-content:space-between;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:20px;">🔥</span>
                    <h3 style="margin:0;">UFW Firewall</h3>
                    <span style="background:#ef444420; color:#ef4444; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">Not Installed</span>
                </div>
                <button onclick="securityAction('${nodePrefix}security/ufw/install', 'POST', {}, this)" class="btn btn-sm btn-primary" style="font-size:12px;">Install UFW</button>
            </div>
            <div class="card-body">
                <p style="color:var(--text-secondary); font-size:13px; margin:0;">UFW (Uncomplicated Firewall) provides an easy-to-use interface for managing iptables firewall rules.</p>
            </div>
        </div>`;
    }

    // ── iptables ──
    const iptRules = (data.iptables.rules || '').trim();
    const iptHtml = `
    <div class="card">
        <div class="card-header" style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:20px;">📋</span>
            <h3 style="margin:0;">iptables Rules</h3>
            <span style="background:#3b82f620; color:#3b82f6; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">System</span>
        </div>
        <div class="card-body">
            <pre style="font-size:11px; color:var(--text-secondary); background:var(--bg-primary); padding:10px; border-radius:6px; max-height:300px; overflow-y:auto; white-space:pre-wrap; margin:0; border:1px solid var(--border);">${escapeHtml(iptRules)}</pre>
        </div>
    </div>`;

    // ── System Updates ──
    const updates = data.updates || {};
    const updCount = updates.count || 0;
    const updList = (updates.list || '').trim();
    const pkgMgr = updates.package_manager || 'unknown';
    const updBadge = updCount > 0
        ? `<span style="background:#f59e0b20; color:#f59e0b; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">${updCount} update${updCount !== 1 ? 's' : ''} available</span>`
        : '<span style="background:#22c55e20; color:#22c55e; padding:2px 10px; border-radius:6px; font-size:11px; font-weight:600;">Up to date</span>';

    const updHtml = `
    <div class="card" style="margin-bottom:16px;">
        <div class="card-header" style="display:flex; align-items:center; justify-content:space-between;">
            <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-size:20px;">📦</span>
                <h3 style="margin:0;">System Updates</h3>
                ${updBadge}
                <span style="color:var(--text-muted); font-size:11px;">(${pkgMgr})</span>
            </div>
            <div style="display:flex; gap:6px;">
                <button onclick="securityAction('${nodePrefix}security/updates/check', 'POST', {}, this)" class="btn btn-sm" style="font-size:12px;">🔍 Check</button>
                ${updCount > 0 ? `<button onclick="securityAction('${nodePrefix}security/updates/apply', 'POST', {}, this)" class="btn btn-sm btn-primary" style="font-size:12px;">⬆️ Update All</button>` : ''}
            </div>
        </div>
        ${updList ? `<div class="card-body"><pre style="font-size:11px; color:var(--text-secondary); background:var(--bg-primary); padding:10px; border-radius:6px; max-height:200px; overflow-y:auto; white-space:pre-wrap; margin:0; border:1px solid var(--border);">${escapeHtml(updList)}</pre></div>` : ''}
    </div>`;

    return updHtml + f2bHtml + ufwHtml + iptHtml;
}

async function securityAction(path, method, body, btn) {
    const orig = btn.textContent;
    btn.textContent = '⏳ Working...';
    btn.disabled = true;
    try {
        const opts = { method, headers: { 'Content-Type': 'application/json' } };
        if (method !== 'GET') opts.body = JSON.stringify(body);
        const res = await fetch(`/api/${path}`, opts);
        const data = await res.json();
        if (res.ok) {
            showToast(data.output ? 'Action completed' : 'Done', 'success');
            loadNodeSecurity();
        } else {
            showToast(data.error || 'Action failed', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    } finally {
        btn.textContent = orig;
        btn.disabled = false;
    }
}

async function addUfwRule(nodePrefix) {
    const input = document.getElementById('ufw-rule-input');
    const rule = (input?.value || '').trim();
    if (!rule) { showToast('Please enter a UFW rule', 'error'); return; }
    try {
        const res = await fetch(`/api/${nodePrefix}security/ufw/rule`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule }),
        });
        const data = await res.json();
        if (res.ok) {
            showToast('Rule added', 'success');
            input.value = '';
            loadNodeSecurity();
        } else {
            showToast(data.error || 'Failed to add rule', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

async function editJailLocal(nodePrefix) {
    try {
        const res = await fetch(`/api/${nodePrefix}security/fail2ban/config`);
        const data = await res.json();
        const content = data.content || `[DEFAULT]\nbantime  = 1h\nfindtime = 10m\nmaxretry = 5\nignoreip = 127.0.0.1/8 ::1\nbanaction = iptables-multiport\n\n[sshd]\nenabled = true\nport    = ssh\nfilter  = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\n`;
        const modal = document.createElement('div');
        modal.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.6); backdrop-filter:blur(4px); z-index:10000; display:flex; align-items:center; justify-content:center;';
        modal.innerHTML = `
            <div style="background:var(--bg-card); border:1px solid var(--border); border-radius:16px; width:640px; max-width:90vw; max-height:85vh; display:flex; flex-direction:column; box-shadow:0 20px 60px rgba(0,0,0,0.4);">
                <div style="padding:20px 24px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span style="font-size:20px;">📝</span>
                        <h3 style="margin:0; font-size:16px;">Edit jail.local</h3>
                    </div>
                    <button onclick="this.closest('div[style*=fixed]').remove()" style="background:none; border:none; color:var(--text-muted); font-size:20px; cursor:pointer; padding:4px;">✕</button>
                </div>
                <div style="padding:16px 24px; flex:1; overflow:auto;">
                    <textarea id="jail-local-editor" spellcheck="false" style="width:100%; height:400px; font-family:'JetBrains Mono','Fira Code',monospace; font-size:13px; line-height:1.6; background:var(--bg-primary); color:var(--text-primary); border:1px solid var(--border); border-radius:8px; padding:12px; resize:vertical; outline:none; tab-size:4;">${escapeHtml(content)}</textarea>
                </div>
                <div style="padding:16px 24px; border-top:1px solid var(--border); display:flex; justify-content:flex-end; gap:8px;">
                    <button onclick="this.closest('div[style*=fixed]').remove()" class="btn btn-sm" style="font-size:13px;">Cancel</button>
                    <button onclick="saveFail2banConfig('${nodePrefix}', this)" class="btn btn-sm btn-primary" style="font-size:13px;">💾 Save & Restart</button>
                </div>
            </div>`;
        document.body.appendChild(modal);
        modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    } catch (e) {
        showToast('Error loading config: ' + e.message, 'error');
    }
}

async function saveFail2banConfig(nodePrefix, btn) {
    const editor = document.getElementById('jail-local-editor');
    const content = editor?.value || '';
    if (!content.trim()) { showToast('Config cannot be empty', 'error'); return; }
    const orig = btn.textContent;
    btn.textContent = '⏳ Saving...';
    btn.disabled = true;
    try {
        const res = await fetch(`/api/${nodePrefix}security/fail2ban/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content }),
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.warning || 'Saved & restarted fail2ban', 'success');
            btn.closest('div[style*=fixed]').remove();
            loadNodeSecurity();
        } else {
            showToast(data.error || 'Save failed', 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    } finally {
        btn.textContent = orig;
        btn.disabled = false;
    }
}

// ─── Theme System ───
function applyTheme(themeId) {
    const validThemes = ['dark', 'light', 'midnight', 'datacenter', 'forest', 'amber', 'glass'];
    if (!validThemes.includes(themeId)) themeId = 'dark';

    // Apply to root element
    if (themeId === 'dark') {
        document.documentElement.removeAttribute('data-theme');
    } else {
        document.documentElement.setAttribute('data-theme', themeId);
    }

    // Save preference
    localStorage.setItem('wolfstack-theme', themeId);

    // Update theme picker cards (highlight active)
    document.querySelectorAll('.theme-card').forEach(card => {
        card.classList.toggle('active', card.getAttribute('data-theme-id') === themeId);
    });
}

function initTheme() {
    const saved = localStorage.getItem('wolfstack-theme') || 'dark';
    applyTheme(saved);
}

function switchSettingsTab(tabName) {
    // Deactivate all tabs and panels
    document.querySelectorAll('.settings-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.settings-tab-panel').forEach(p => p.classList.remove('active'));

    // Activate the selected tab
    const panel = document.getElementById(`settings-tab-${tabName}`);
    if (panel) panel.classList.add('active');

    // Highlight the correct button
    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
        const btnText = btn.textContent.trim().toLowerCase();
        const tabMap = { 'appearance': '\ud83c\udfa8 appearance', 'alerting': '\ud83d\udd14 alerting', 'ai': '\ud83e\udd16 ai agent', 'backup': '\ud83d\udce6 config backup' };
        if (btnText === (tabMap[tabName] || '').trim()) {
            btn.classList.add('active');
        }
    });

    // Lazy-load data when switching tabs
    if (tabName === 'ai') {
        loadAiConfig();
        loadAiStatus();
        loadAiAlerts();
    } else if (tabName === 'alerting') {
        loadAlertingConfig();
    }
}

// \u2500\u2500\u2500 Alerting & Notifications \u2500\u2500\u2500
async function loadAlertingConfig() {
    try {
        const resp = await fetch('/api/alerts/config');
        if (!resp.ok) return;
        const c = await resp.json();
        document.getElementById('alerting-enabled').checked = c.enabled;
        if (c.has_discord) document.getElementById('alerting-discord').placeholder = '\u2705 Configured (hidden)';
        if (c.has_slack) document.getElementById('alerting-slack').placeholder = '\u2705 Configured (hidden)';
        if (c.has_telegram) {
            document.getElementById('alerting-tg-token').placeholder = '\u2705 Configured (hidden)';
            document.getElementById('alerting-tg-chat').value = c.telegram_chat_id || '';
        }
        const cpuEl = document.getElementById('alerting-cpu');
        const memEl = document.getElementById('alerting-memory');
        const diskEl = document.getElementById('alerting-disk');
        cpuEl.value = c.cpu_threshold || 90; cpuEl.nextElementSibling.textContent = cpuEl.value + '%';
        memEl.value = c.memory_threshold || 90; memEl.nextElementSibling.textContent = memEl.value + '%';
        diskEl.value = c.disk_threshold || 90; diskEl.nextElementSibling.textContent = diskEl.value + '%';
        document.getElementById('alerting-evt-offline').checked = c.alert_node_offline !== false;
        document.getElementById('alerting-evt-restored').checked = c.alert_node_restored !== false;
        document.getElementById('alerting-evt-cpu').checked = c.alert_cpu !== false;
        document.getElementById('alerting-evt-memory').checked = c.alert_memory !== false;
        document.getElementById('alerting-evt-disk').checked = c.alert_disk !== false;
        const channels = [];
        if (c.has_discord) channels.push('\u2705 Discord');
        if (c.has_slack) channels.push('\u2705 Slack');
        if (c.has_telegram) channels.push('\u2705 Telegram');
        const statusEl = document.getElementById('alerting-channel-status');
        statusEl.innerHTML = channels.length
            ? `<span style="color:var(--success);">${channels.join(' &nbsp;\u00b7&nbsp; ')}</span>`
            : '<span style="color:var(--text-muted);">No channels configured yet</span>';
    } catch (e) { /* ignore */ }
}

async function saveAlertingConfig() {
    const payload = {
        enabled: document.getElementById('alerting-enabled').checked,
        cpu_threshold: parseInt(document.getElementById('alerting-cpu').value),
        memory_threshold: parseInt(document.getElementById('alerting-memory').value),
        disk_threshold: parseInt(document.getElementById('alerting-disk').value),
        alert_node_offline: document.getElementById('alerting-evt-offline').checked,
        alert_node_restored: document.getElementById('alerting-evt-restored').checked,
        alert_cpu: document.getElementById('alerting-evt-cpu').checked,
        alert_memory: document.getElementById('alerting-evt-memory').checked,
        alert_disk: document.getElementById('alerting-evt-disk').checked,
    };
    const discord = document.getElementById('alerting-discord').value.trim();
    const slack = document.getElementById('alerting-slack').value.trim();
    const tgToken = document.getElementById('alerting-tg-token').value.trim();
    const tgChat = document.getElementById('alerting-tg-chat').value.trim();
    if (discord) payload.discord_webhook = discord;
    if (slack) payload.slack_webhook = slack;
    if (tgToken) payload.telegram_bot_token = tgToken;
    if (tgChat) payload.telegram_chat_id = tgChat;

    try {
        const resp = await fetch('/api/alerts/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            showToast('Alerting settings saved', 'success');
            loadAlertingConfig();
        } else {
            const data = await resp.json().catch(() => ({}));
            showToast(data.error || 'Failed to save', 'error');
        }
    } catch (e) {
        showToast('Failed: ' + e.message, 'error');
    }
}

async function testAlerting() {
    showToast('Sending test alert\u2026', 'info');
    try {
        const resp = await fetch('/api/alerts/test', { method: 'POST' });
        const data = await resp.json();
        if (data.sent > 0) {
            const details = data.results.map(r => `${r.channel}: ${r.success ? '\u2705' : '\u274c ' + (r.error || 'failed')}`).join(', ');
            showToast(`Test sent to ${data.sent} channel(s): ${details}`, 'success');
        } else {
            showToast('No channels configured \u2014 add a Discord, Slack, or Telegram webhook first', 'error');
        }
    } catch (e) {
        showToast('Test failed: ' + e.message, 'error');
    }
}

// Apply saved theme immediately on load
initTheme();

