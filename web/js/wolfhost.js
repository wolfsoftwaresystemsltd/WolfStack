/* WolfHost — Admin Panel Plugin for WolfStack */
/* (C) Wolf Software Systems Ltd */

(function() {
    'use strict';

    const PLUGIN_ID = 'wolfhost';
    const API = `/api/wolfhost`;

    let currentTab = 'dashboard';
    let customers = [];
    let plans = [];
    let services = [];
    let invoices = [];
    let tickets = [];
    // The cluster this screen is scoped to. Driven by WolfStack's shared
    // top-bar cluster selector (not a dropdown of our own) — see the
    // registerClusterScopedView() call in init(). Empty = current scope.
    let whCurrentCluster = '';
    // Runtime info about the wolfhost plugin itself — fetched once on
    // init from `/info`. Used to construct the public customer-portal
    // URL (separate port, separate TLS state) so the admin UI's
    // "Open Portal" links don't hard-code anything.
    let portalInfo = null;

    // ─── Utilities ───

    function esc(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    async function api(path, opts = {}) {
        const url = typeof apiUrl === 'function' ? apiUrl(`${API}${path}`) : `${API}${path}`;
        try {
            const r = await fetch(url, {
                ...opts,
                headers: { 'Content-Type': 'application/json', ...opts.headers },
                body: opts.body ? JSON.stringify(opts.body) : undefined,
            });
            if (!r.ok) {
                const text = await r.text().catch(() => '');
                throw new Error(text || `HTTP ${r.status}`);
            }
            return await r.json();
        } catch (e) {
            console.warn('WolfHost API error:', path, e.message);
            throw e;
        }
    }

    function toast(msg, type = 'success') {
        const el = document.createElement('div');
        el.className = `wh-toast ${type}`;
        el.textContent = msg;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 3000);
    }

    function formatDate(iso) {
        if (!iso) return '—';
        try {
            return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch { return iso; }
    }

    function formatCurrency(amount, currency = 'USD') {
        return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(amount || 0);
    }

    function badge(status) {
        const s = (status || '').toLowerCase().replace(/\s+/g, '_');
        return `<span class="wh-badge-status wh-badge-${esc(s)}">${esc(status)}</span>`;
    }

    function priorityBadge(p) {
        return `<span class="wh-badge-priority wh-priority-${esc(p)}">${esc(p)}</span>`;
    }

    function usageBar(used, total, label) {
        const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
        const cls = pct > 90 ? 'danger' : pct > 70 ? 'warning' : '';
        return `<div>
            <div class="wh-usage-label"><span>${esc(label)}</span><span>${used} / ${total} MB</span></div>
            <div class="wh-usage-bar"><div class="wh-usage-fill ${cls}" style="width:${pct}%"></div></div>
        </div>`;
    }

    function whConfirm(title, message, onYes) {
        showModal(title, `<p style="font-size:14px;color:var(--text-secondary);line-height:1.6">${message}</p>`, () => { closeModal(); onYes(); }, 'Confirm');
    }

    // ─── Main Render ───

    function init() {
        const container = document.getElementById('wolfhost-content');
        if (!container) return;
        // Re-opening the screen resets to the current WolfStack scope
        // (selectView clears currentNodeId), so start with no explicit
        // cluster override and let the label derive it.
        whCurrentCluster = '';
        container.innerHTML = `
            <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
                <div class="wh-tabs" id="wh-tabs"></div>
                <div id="wh-cluster-label" style="font-size:12px;color:var(--text-secondary,#8892a8);white-space:nowrap;" title="Use the cluster selector at the top of WolfStack to switch clusters"></div>
            </div>
            <div id="wh-content"></div>
        `;
        renderTabs();
        switchTab('dashboard');
        // Fire-and-forget — every consumer of `portalInfo` falls back
        // gracefully when it's still null, so we don't gate the first
        // tab render on the round-trip.
        api('/info').then(info => { portalInfo = info; }).catch(() => {});

        // Honour WolfStack's shared top-bar cluster selector: when the
        // operator switches clusters up top, WolfStack points the API
        // scope at that cluster's node and calls this handler, so we just
        // re-render the current tab — every /api/plugins/wolfhost call is
        // then proxied to that cluster automatically (apiUrl → node proxy).
        if (typeof registerClusterScopedView === 'function') {
            registerClusterScopedView('wolfhost', function (cluster) {
                whCurrentCluster = cluster || '';
                updateClusterLabel();
                switchTab(currentTab);
            });
        }
        updateClusterLabel();
    }

    // Show which cluster the screen is currently scoped to. Falls back to
    // the current WolfStack scope (selected node's cluster, else the self
    // node's) when we don't have an explicit selection yet.
    function updateClusterLabel() {
        const el = document.getElementById('wh-cluster-label');
        if (!el) return;
        let cluster = whCurrentCluster;
        if (!cluster) {
            try {
                const cur = (typeof currentNodeId !== 'undefined' && currentNodeId) ? currentNodeId : null;
                const list = (typeof allNodes !== 'undefined' && Array.isArray(allNodes)) ? allNodes : [];
                const n = cur ? list.find(x => x.id === cur) : (list.find(x => x.is_self) || null);
                cluster = n ? (n.cluster_name || 'WolfStack') : '';
            } catch (_) { cluster = ''; }
        }
        el.textContent = cluster ? `🖧 Cluster: ${cluster}` : '';
    }

    // Build the public customer-portal URL from `/info`. Returns null
    // if `/info` hasn't responded yet (rare — only the moment between
    // init firing the request and the response landing). Callers that
    // need a clickable link should bail out / hide the link in that
    // case rather than render a broken href.
    function getPortalUrl(query) {
        if (!portalInfo || !portalInfo.portal_port) return null;
        const proto = portalInfo.portal_has_tls ? 'https' : 'http';
        const host = window.location.hostname;
        const qs = query ? ('?' + new URLSearchParams(query).toString()) : '';
        return `${proto}://${host}:${portalInfo.portal_port}/${qs}`;
    }

    window.wolfhostOpenPortal = function(email) {
        const url = getPortalUrl(email ? { email } : null);
        if (!url) {
            toast('Portal info not loaded yet — try again in a moment', 'error');
            return;
        }
        window.open(url, '_blank', 'noopener');
    };

    // Per-row helper: look up the customer's email from the cached
    // list at click time so we don't have to interpolate user-supplied
    // strings into an inline onclick handler. Avoids the entire class
    // of quote-escape bugs for emails like `"a b"@example.com`.
    window.wolfhostOpenPortalForCustomer = function(id) {
        const c = customers.find(x => x.id === id);
        wolfhostOpenPortal(c ? c.email : null);
    };

    function renderTabs() {
        const tabs = [
            { id: 'dashboard', label: 'Dashboard', icon: '📊' },
            { id: 'customers', label: 'Customers', icon: '👥' },
            { id: 'plans', label: 'Plans', icon: '📦' },
            { id: 'services', label: 'Services', icon: '🌐' },
            { id: 'servers', label: 'Servers', icon: '🖥️' },
            { id: 'billing', label: 'Billing', icon: '💳' },
            { id: 'tickets', label: 'Tickets', icon: '🎫' },
            { id: 'dns', label: 'DNS', icon: '🌍' },
            { id: 'branding', label: 'Branding', icon: '🎨' },
            { id: 'database', label: 'Database', icon: '🗄️' },
            { id: 'da-tools',  label: 'DA Tools', icon: '🔧' },
            { id: 'migrations', label: 'Migrations', icon: '⇨' },
        ];
        document.getElementById('wh-tabs').innerHTML = tabs.map(t =>
            `<button class="wh-tab${t.id === currentTab ? ' active' : ''}" onclick="wolfhostTab('${t.id}')">${t.icon} ${t.label}</button>`
        ).join('');
    }

    window.wolfhostTab = function(tab) {
        currentTab = tab;
        renderTabs();
        switchTab(tab);
    };

    async function switchTab(tab) {
        const content = document.getElementById('wh-content');
        if (!content) return;
        content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)">Loading...</div>';

        try {
            switch (tab) {
                case 'dashboard': await renderDashboard(content); break;
                case 'customers': await renderCustomers(content); break;
                case 'plans': await renderPlans(content); break;
                case 'services': await renderServices(content); break;
                case 'servers': await renderServers(content); break;
                case 'billing': await renderBilling(content); break;
                case 'tickets': await renderTickets(content); break;
                case 'dns': await renderDns(content); break;
                case 'branding': await renderBranding(content); break;
                case 'database': await renderDatabase(content); break;
                case 'da-tools': await renderDaTools(content); break;
                case 'migrations': await renderMigrations(content); break;
            }
        } catch (e) {
            content.innerHTML = `<div class="wh-empty"><span class="wh-empty-icon">⚠️</span><div class="wh-empty-text">Error loading data: ${esc(e.message)}</div></div>`;
        }
    }

    // ─── Dashboard ───

    async function renderDashboard(el) {
        let stats = {}, activity = [];
        try {
            const results = await Promise.all([
                api('/dashboard/stats').catch(() => ({})),
                api('/dashboard/activity').catch(() => []),
            ]);
            stats = results[0] || {};
            activity = Array.isArray(results[1]) ? results[1] : [];
        } catch (e) {
            el.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-muted);">
                <div style="font-size:48px;margin-bottom:12px;">⚠️</div>
                <div>WolfHost backend not running. Start the plugin backend from Settings → Plugins.</div>
                <div style="font-size:12px;margin-top:8px;color:var(--text-muted);">${esc(e.message)}</div>
            </div>`;
            return;
        }

        el.innerHTML = `
            <div class="wh-stats">
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">👥</span>
                    <div class="wh-stat-value">${stats.total_customers || 0}</div>
                    <div class="wh-stat-label">Total Customers <span style="color:var(--success)">(${stats.active_customers || 0} active)</span></div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">🌐</span>
                    <div class="wh-stat-value">${stats.active_services || 0}</div>
                    <div class="wh-stat-label">Active Services</div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">💰</span>
                    <div class="wh-stat-value">${formatCurrency(stats.monthly_revenue, stats.currency)}</div>
                    <div class="wh-stat-label">Total Revenue</div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">🎫</span>
                    <div class="wh-stat-value">${stats.open_tickets || 0}</div>
                    <div class="wh-stat-label">Open Tickets</div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">⚠️</span>
                    <div class="wh-stat-value">${stats.overdue_invoices || 0}</div>
                    <div class="wh-stat-label">Overdue Invoices</div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">💾</span>
                    <div class="wh-stat-value">${stats.total_disk_mb || 0} MB</div>
                    <div class="wh-stat-label">Disk Usage</div>
                </div>
            </div>
            <div class="wh-activity">
                <h3>Recent Activity</h3>
                ${(activity || []).length === 0
                    ? '<div style="color:var(--text-muted);font-size:13px;padding:12px 0;">No recent activity</div>'
                    : (activity || []).map(a => `
                        <div class="wh-activity-item">
                            <div class="wh-activity-dot ${esc(a.type)}"></div>
                            <div style="flex:1">
                                <div>${esc(a.message)}</div>
                                <div class="wh-activity-time">${formatDate(a.time)}</div>
                            </div>
                            ${a.status ? badge(a.status) : ''}
                        </div>
                    `).join('')
                }
            </div>
        `;
    }

    // ─── Customers ───

    async function renderCustomers(el) {
        customers = await api('/customers');

        el.innerHTML = `
            <div class="wh-table-container">
                <div class="wh-table-header">
                    <h3>Customers (${customers.length})</h3>
                    <div style="display:flex;gap:10px;align-items:center">
                        <input class="wh-search" id="wh-cust-search" placeholder="Search customers..." oninput="wolfhostFilterCustomers()">
                        <button class="wh-btn" onclick="wolfhostOpenPortal()" title="Open the customer portal in a new tab">🔗 Open Portal</button>
                        <button class="wh-btn wh-btn-primary" onclick="wolfhostCreateCustomer()">+ Add Customer</button>
                    </div>
                </div>
                <table class="wh-table">
                    <thead><tr>
                        <th>Name</th><th>Email</th><th>Company</th><th>Status</th><th>Created</th><th>Actions</th>
                    </tr></thead>
                    <tbody id="wh-cust-body">${renderCustomerRows(customers)}</tbody>
                </table>
            </div>
        `;
    }

    function renderCustomerRows(list) {
        if (list.length === 0) return '<tr><td colspan="6"><div class="wh-empty"><span class="wh-empty-icon">👥</span><div class="wh-empty-text">No customers yet</div></div></td></tr>';
        return list.map(c => `
            <tr>
                <td><strong>${esc(c.first_name)} ${esc(c.last_name)}</strong></td>
                <td>${esc(c.email)}</td>
                <td>${esc(c.company) || '<span style="color:var(--text-muted)">—</span>'}</td>
                <td>${badge(c.status)}</td>
                <td>${formatDate(c.created_at)}</td>
                <td>
                    <div style="display:flex;gap:6px">
                        <button class="wh-btn wh-btn-sm" onclick="wolfhostEditCustomer('${c.id}')" title="Edit">Edit</button>
                        <button class="wh-btn wh-btn-sm" onclick="wolfhostOpenPortalForCustomer('${c.id}')" title="Open the portal in a new tab with this customer's email pre-filled">Portal</button>
                        ${c.status === 'active'
                            ? `<button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostSuspendCustomer('${c.id}')" title="Suspend">Suspend</button>`
                            : `<button class="wh-btn wh-btn-sm" onclick="wolfhostUnsuspendCustomer('${c.id}')" title="Unsuspend">Activate</button>`
                        }
                        <button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostDeleteCustomer('${c.id}')" title="Delete">Del</button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    window.wolfhostFilterCustomers = function() {
        const q = (document.getElementById('wh-cust-search')?.value || '').toLowerCase();
        const filtered = customers.filter(c =>
            `${c.first_name} ${c.last_name} ${c.email} ${c.company}`.toLowerCase().includes(q)
        );
        document.getElementById('wh-cust-body').innerHTML = renderCustomerRows(filtered);
    };

    window.wolfhostCreateCustomer = function() {
        showModal('Add Customer', `
            <div class="wh-form-row">
                <div class="wh-form-group"><label>First Name</label><input class="wh-input" id="wh-c-fn"></div>
                <div class="wh-form-group"><label>Last Name</label><input class="wh-input" id="wh-c-ln"></div>
            </div>
            <div class="wh-form-group"><label>Email</label><input class="wh-input" type="email" id="wh-c-email"></div>
            <div class="wh-form-group"><label>Password</label><input class="wh-input" type="password" id="wh-c-pass"></div>
            <div class="wh-form-group"><label>Company</label><input class="wh-input" id="wh-c-company"></div>
            <div class="wh-form-group"><label>Phone</label><input class="wh-input" id="wh-c-phone"></div>
            <div class="wh-form-group"><label>Notes</label><textarea class="wh-textarea" id="wh-c-notes"></textarea></div>
        `, async () => {
            await api('/customers', { method: 'POST', body: {
                email: document.getElementById('wh-c-email').value,
                password: document.getElementById('wh-c-pass').value,
                first_name: document.getElementById('wh-c-fn').value,
                last_name: document.getElementById('wh-c-ln').value,
                company: document.getElementById('wh-c-company').value,
                phone: document.getElementById('wh-c-phone').value,
                notes: document.getElementById('wh-c-notes').value,
            }});
            toast('Customer created');
            closeModal();
            switchTab('customers');
        });
    };

    window.wolfhostEditCustomer = async function(id) {
        const c = await api(`/customers/${id}`);
        showModal('Edit Customer', `
            <div class="wh-form-row">
                <div class="wh-form-group"><label>First Name</label><input class="wh-input" id="wh-ce-fn" value="${esc(c.first_name)}"></div>
                <div class="wh-form-group"><label>Last Name</label><input class="wh-input" id="wh-ce-ln" value="${esc(c.last_name)}"></div>
            </div>
            <div class="wh-form-group"><label>Email</label><input class="wh-input" type="email" id="wh-ce-email" value="${esc(c.email)}"></div>
            <div class="wh-form-group"><label>New Password (leave blank to keep current)</label><input class="wh-input" type="password" id="wh-ce-pass" placeholder="Leave blank to keep current"></div>
            <div class="wh-form-group"><label>Company</label><input class="wh-input" id="wh-ce-company" value="${esc(c.company)}"></div>
            <div class="wh-form-group"><label>Phone</label><input class="wh-input" id="wh-ce-phone" value="${esc(c.phone)}"></div>
            <div class="wh-form-group"><label>Notes</label><textarea class="wh-textarea" id="wh-ce-notes">${esc(c.notes)}</textarea></div>
        `, async () => {
            const updateBody = {
                email: document.getElementById('wh-ce-email').value,
                first_name: document.getElementById('wh-ce-fn').value,
                last_name: document.getElementById('wh-ce-ln').value,
                company: document.getElementById('wh-ce-company').value,
                phone: document.getElementById('wh-ce-phone').value,
                notes: document.getElementById('wh-ce-notes').value,
            };
            const newPass = document.getElementById('wh-ce-pass').value;
            if (newPass) updateBody.password = newPass;
            await api(`/customers/${id}`, { method: 'PUT', body: updateBody });
            toast('Customer updated');
            closeModal();
            switchTab('customers');
        });
    };

    window.wolfhostSuspendCustomer = function(id) {
        whConfirm('Suspend Customer', 'Suspend this customer? Their services will be affected.', async () => {
            await api(`/customers/${id}/suspend`, { method: 'POST' });
            toast('Customer suspended');
            switchTab('customers');
        });
    };

    window.wolfhostUnsuspendCustomer = async function(id) {
        await api(`/customers/${id}/unsuspend`, { method: 'POST' });
        toast('Customer activated');
        switchTab('customers');
    };

    window.wolfhostDeleteCustomer = function(id) {
        whConfirm('Delete Customer', 'Permanently delete this customer? This <strong>cannot be undone</strong>.', async () => {
            await api(`/customers/${id}`, { method: 'DELETE' });
            toast('Customer deleted');
            switchTab('customers');
        });
    };

    // ─── Plans ───

    async function renderPlans(el) {
        plans = await api('/plans');

        el.innerHTML = `
            <div class="wh-section-header">
                <h3>Hosting Plans</h3>
                <button class="wh-btn wh-btn-primary" onclick="wolfhostCreatePlan()">+ Create Plan</button>
            </div>
            <div class="wh-plans-grid" id="wh-plans-grid">
                ${plans.length === 0
                    ? '<div class="wh-empty" style="grid-column:1/-1"><span class="wh-empty-icon">📦</span><div class="wh-empty-text">No hosting plans yet. Create your first plan!</div></div>'
                    : plans.sort((a,b) => a.sort_order - b.sort_order).map(p => renderPlanCard(p)).join('')
                }
            </div>
        `;
    }

    function renderPlanCard(p) {
        return `
            <div class="wh-plan-card ${p.active ? '' : 'wh-plan-inactive'}">
                ${!p.active ? '<div style="position:absolute;top:12px;right:12px;font-size:11px;color:var(--text-muted);background:var(--bg-secondary);padding:3px 10px;border-radius:6px;">Inactive</div>' : ''}
                <div class="wh-plan-name">${esc(p.name)}</div>
                <div style="font-size:12px;color:var(--text-secondary)">${esc(p.description)}</div>
                <div class="wh-plan-price">${formatCurrency(p.price_monthly)} <span>/mo</span></div>
                ${p.price_yearly ? `<div style="font-size:12px;color:var(--text-muted);margin-top:-8px">${formatCurrency(p.price_yearly)}/year</div>` : ''}
                <ul class="wh-plan-features">
                    <li>${p.disk_mb >= 1024 ? (p.disk_mb / 1024).toFixed(0) + ' GB' : p.disk_mb + ' MB'} Disk Space</li>
                    <li>${p.bandwidth_mb >= 1024 ? (p.bandwidth_mb / 1024).toFixed(0) + ' GB' : p.bandwidth_mb + ' MB'} Bandwidth</li>
                    <li>${p.domains} Domains</li>
                    <li>${p.email_accounts} Email Accounts</li>
                    <li>${p.databases} Databases</li>
                    <li>${p.ftp_accounts} FTP Accounts</li>
                    <li>${p.ssl_certificates} SSL Certificates</li>
                    ${p.backups ? '<li>Automated Backups</li>' : ''}
                    ${(p.features || []).map(f => `<li>${esc(f)}</li>`).join('')}
                </ul>
                <div style="display:flex;gap:8px;margin-top:16px">
                    <button class="wh-btn wh-btn-sm" onclick="wolfhostEditPlan('${p.id}')">Edit</button>
                    <button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostDeletePlan('${p.id}')">Delete</button>
                </div>
            </div>
        `;
    }

    window.wolfhostCreatePlan = function() {
        showPlanModal();
    };

    window.wolfhostEditPlan = async function(id) {
        const p = await api(`/plans/${id}`);
        showPlanModal(p);
    };

    function showPlanModal(existing) {
        const p = existing || {};
        const title = p.id ? 'Edit Plan' : 'Create Plan';
        showModal(title, `
            <div class="wh-form-group"><label>Plan Name</label><input class="wh-input" id="wh-p-name" value="${esc(p.name || '')}"></div>
            <div class="wh-form-group"><label>Description</label><textarea class="wh-textarea" id="wh-p-desc">${esc(p.description || '')}</textarea></div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Monthly Price</label><input class="wh-input" type="number" step="0.01" id="wh-p-monthly" value="${p.price_monthly || ''}"></div>
                <div class="wh-form-group"><label>Yearly Price</label><input class="wh-input" type="number" step="0.01" id="wh-p-yearly" value="${p.price_yearly || ''}"></div>
            </div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Disk (MB)</label><input class="wh-input" type="number" id="wh-p-disk" value="${p.disk_mb || 10240}"></div>
                <div class="wh-form-group"><label>Bandwidth (MB)</label><input class="wh-input" type="number" id="wh-p-bw" value="${p.bandwidth_mb || 102400}"></div>
            </div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Domains</label><input class="wh-input" type="number" id="wh-p-domains" value="${p.domains || 5}"></div>
                <div class="wh-form-group"><label>Email Accounts</label><input class="wh-input" type="number" id="wh-p-emails" value="${p.email_accounts || 10}"></div>
            </div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Databases</label><input class="wh-input" type="number" id="wh-p-dbs" value="${p.databases || 3}"></div>
                <div class="wh-form-group"><label>FTP Accounts</label><input class="wh-input" type="number" id="wh-p-ftp" value="${p.ftp_accounts || 5}"></div>
            </div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>SSL Certificates</label><input class="wh-input" type="number" id="wh-p-ssl" value="${p.ssl_certificates || 5}"></div>
                <div class="wh-form-group"><label>Sort Order</label><input class="wh-input" type="number" id="wh-p-sort" value="${p.sort_order || 0}"></div>
            </div>
            <div class="wh-form-group"><label>Features (comma-separated)</label><input class="wh-input" id="wh-p-features" value="${esc((p.features || []).join(', '))}"></div>
        `, async () => {
            const data = {
                name: document.getElementById('wh-p-name').value,
                description: document.getElementById('wh-p-desc').value,
                price_monthly: parseFloat(document.getElementById('wh-p-monthly').value) || 0,
                price_yearly: parseFloat(document.getElementById('wh-p-yearly').value) || 0,
                disk_mb: parseInt(document.getElementById('wh-p-disk').value) || 10240,
                bandwidth_mb: parseInt(document.getElementById('wh-p-bw').value) || 102400,
                domains: parseInt(document.getElementById('wh-p-domains').value) || 5,
                email_accounts: parseInt(document.getElementById('wh-p-emails').value) || 10,
                databases: parseInt(document.getElementById('wh-p-dbs').value) || 3,
                ftp_accounts: parseInt(document.getElementById('wh-p-ftp').value) || 5,
                ssl_certificates: parseInt(document.getElementById('wh-p-ssl').value) || 5,
                sort_order: parseInt(document.getElementById('wh-p-sort').value) || 0,
                features: document.getElementById('wh-p-features').value.split(',').map(s => s.trim()).filter(Boolean),
            };
            if (p.id) {
                await api(`/plans/${p.id}`, { method: 'PUT', body: data });
                toast('Plan updated');
            } else {
                await api('/plans', { method: 'POST', body: data });
                toast('Plan created');
            }
            closeModal();
            switchTab('plans');
        });
    }

    window.wolfhostDeletePlan = function(id) {
        whConfirm('Delete Plan', 'Are you sure you want to delete this hosting plan?', async () => {
            await api(`/plans/${id}`, { method: 'DELETE' });
            toast('Plan deleted');
            switchTab('plans');
        });
    };

    // ─── Services ───

    async function renderServices(el) {
        [services, customers, plans] = await Promise.all([
            api('/services'), api('/customers'), api('/plans'),
        ]);

        const getCustomer = id => customers.find(c => c.id === id);
        const getPlan = id => plans.find(p => p.id === id);

        el.innerHTML = `
            <div class="wh-table-container">
                <div class="wh-table-header">
                    <h3>Services (${services.length})</h3>
                    <button class="wh-btn wh-btn-primary" onclick="wolfhostCreateService()">+ Create Service</button>
                </div>
                <table class="wh-table">
                    <thead><tr>
                        <th>Domain</th><th>Customer</th><th>Plan</th><th>Backend</th><th>Status</th><th>Disk</th><th>Bandwidth</th><th>Next Billing</th><th>Actions</th>
                    </tr></thead>
                    <tbody>
                        ${services.length === 0
                            ? '<tr><td colspan="9"><div class="wh-empty"><span class="wh-empty-icon">🌐</span><div class="wh-empty-text">No services yet</div></div></td></tr>'
                            : services.map(s => {
                                const cust = getCustomer(s.customer_id);
                                const plan = getPlan(s.plan_id);
                                const diskPct = plan ? Math.min(100, (s.usage.disk_mb / plan.disk_mb) * 100).toFixed(0) : 0;
                                const bwPct = plan ? Math.min(100, (s.usage.bandwidth_mb / plan.bandwidth_mb) * 100).toFixed(0) : 0;
                                return `<tr>
                                    <td><strong>${esc(s.domain) || '<em style="color:var(--text-muted)">No domain</em>'}</strong></td>
                                    <td>${cust ? esc(cust.first_name + ' ' + cust.last_name) : '<span style="color:var(--text-muted)">Unknown</span>'}</td>
                                    <td>${plan ? esc(plan.name) : '—'}</td>
                                    <td>${s.backend === 'directadmin' ? '<span style="font-size:10px;background:rgba(99,102,241,0.15);color:#818cf8;padding:2px 6px;border-radius:3px;">DirectAdmin</span>' : '<span style="font-size:10px;background:rgba(34,197,94,0.15);color:#4ade80;padding:2px 6px;border-radius:3px;">Native</span>'}</td>
                                    <td>${badge(s.status)}</td>
                                    <td><div style="min-width:100px">${usageBar(s.usage.disk_mb, plan?.disk_mb || 0, '')}</div></td>
                                    <td><div style="min-width:100px">${usageBar(s.usage.bandwidth_mb, plan?.bandwidth_mb || 0, '')}</div></td>
                                    <td>${formatDate(s.next_billing)}</td>
                                    <td>
                                        <div style="display:flex;gap:6px;flex-wrap:wrap">
                                            ${s.backend === 'directadmin' ? `<button class="wh-btn wh-btn-sm" onclick="wolfhostStartMigration('${s.id}')" title="Migrate this DirectAdmin account onto a fresh WolfStack LXC">⇨ Migrate</button>` : ''}
                                            ${s.backend === 'directadmin' && s.status !== 'suspended' ? `<button class="wh-btn wh-btn-sm" onclick="wolfhostSuspendDA('${s.id}')" title="Suspend the underlying DA user — reversible kill-switch, customer can't log in / mail flow stops">Disable DA</button>` : ''}
                                            ${s.backend === 'directadmin' && s.status === 'suspended' ? `<button class="wh-btn wh-btn-sm" onclick="wolfhostUnsuspendDA('${s.id}')" title="Re-enable the DA user">Re-enable DA</button>` : ''}
                                            <button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostDeleteService('${s.id}')">Del</button>
                                        </div>
                                    </td>
                                </tr>`;
                            }).join('')
                        }
                    </tbody>
                </table>
            </div>
        `;
    }

    window.wolfhostCreateService = async function() {
        const custOpts = customers.map(c => `<option value="${c.id}">${esc(c.first_name)} ${esc(c.last_name)} (${esc(c.email)})</option>`).join('');
        const planOpts = plans.filter(p => p.active).map(p => `<option value="${p.id}">${esc(p.name)} — ${formatCurrency(p.price_monthly)}/mo</option>`).join('');

        // Fetch DA instances for the attach option
        let daInstances = [];
        try { daInstances = await api('/directadmin'); } catch(e) {}
        const daOpts = daInstances.map(d => `<option value="${d.id}">${esc(d.name)} (${esc(d.url)})</option>`).join('');

        showModal('Create Service', `
            <div class="wh-form-group"><label>Customer</label><select class="wh-select" id="wh-s-cust">${custOpts}</select></div>
            <div class="wh-form-group"><label>Plan</label><select class="wh-select" id="wh-s-plan">${planOpts}</select></div>
            <div class="wh-form-group"><label>Domain</label><input class="wh-input" id="wh-s-domain" placeholder="example.com"></div>
            <div class="wh-form-group"><label>Billing Cycle</label><select class="wh-select" id="wh-s-cycle"><option value="monthly">Monthly</option><option value="yearly">Yearly</option></select></div>

            <div style="border-top:1px solid var(--border);margin-top:16px;padding-top:16px;">
                <div class="wh-form-group">
                    <label>Backend</label>
                    <select class="wh-select" id="wh-s-backend" onchange="wolfhostToggleDAFields()">
                        <option value="native">Native (WolfHost manages directly)</option>
                        <option value="directadmin">DirectAdmin (proxy to existing DA server)</option>
                    </select>
                </div>
                <div id="wh-da-fields" style="display:none;">
                    ${daInstances.length > 0 ? `
                        <div class="wh-form-group">
                            <label>DirectAdmin Instance</label>
                            <select class="wh-select" id="wh-s-da-inst">${daOpts}</select>
                        </div>
                        <div class="wh-form-group">
                            <label>DA Username (existing account on DA)</label>
                            <input class="wh-input" id="wh-s-da-user" placeholder="e.g. john or leave empty to create new">
                            <small style="color:var(--text-muted);">Leave empty to auto-create a DA user for this service</small>
                        </div>
                    ` : `
                        <div style="padding:12px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:8px;font-size:13px;">
                            <strong>No DirectAdmin instances attached.</strong> Add one first:
                            <button class="wh-btn" onclick="closeModal();wolfhostAttachDA()" style="margin-top:8px;">Attach DirectAdmin Server</button>
                        </div>
                    `}
                </div>
            </div>
        `, async () => {
            const body = {
                customer_id: document.getElementById('wh-s-cust').value,
                plan_id: document.getElementById('wh-s-plan').value,
                domain: document.getElementById('wh-s-domain').value,
                billing_cycle: document.getElementById('wh-s-cycle').value,
            };
            const backend = document.getElementById('wh-s-backend').value;
            if (backend === 'directadmin') {
                body.backend = 'directadmin';
                body.da_instance_id = document.getElementById('wh-s-da-inst')?.value || '';
                body.da_username = document.getElementById('wh-s-da-user')?.value || '';
            }
            await api('/services', { method: 'POST', body });
            toast('Service created');
            closeModal();
            switchTab('services');
        });
    };

    window.wolfhostToggleDAFields = function() {
        const backend = document.getElementById('wh-s-backend').value;
        const fields = document.getElementById('wh-da-fields');
        if (fields) fields.style.display = backend === 'directadmin' ? 'block' : 'none';
    };

    window.wolfhostAttachDA = function() {
        showModal('Attach DirectAdmin Server', `
            <p style="font-size:13px;color:var(--text-muted);margin-bottom:16px;">Connect a DirectAdmin instance running in a container or VM. WolfHost will proxy all hosting operations through the DA API.</p>
            <div class="wh-form-group"><label>Name</label><input class="wh-input" id="wh-da-name" placeholder="e.g. DA Server 1"></div>
            <div class="wh-form-group"><label>DirectAdmin URL</label><input class="wh-input" id="wh-da-url" placeholder="https://10.0.0.5:2222"></div>
            <div class="wh-form-group"><label>Admin Username</label><input class="wh-input" id="wh-da-user" placeholder="admin"></div>
            <div class="wh-form-group"><label>Admin Password</label><input class="wh-input" type="password" id="wh-da-pass"></div>
            <div id="wh-da-detect-result"></div>
            <button class="wh-btn" onclick="wolfhostDetectDA()" style="margin-bottom:12px;">Test Connection</button>
        `, async () => {
            await api('/directadmin', { method: 'POST', body: {
                name: document.getElementById('wh-da-name').value,
                url: document.getElementById('wh-da-url').value,
                admin_user: document.getElementById('wh-da-user').value,
                admin_password: document.getElementById('wh-da-pass').value,
            }});
            toast('DirectAdmin server attached');
            closeModal();
        });
    };

    window.wolfhostDetectDA = async function() {
        const result = document.getElementById('wh-da-detect-result');
        result.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:8px;">Testing connection...</div>';
        try {
            const data = await api('/directadmin/detect', { method: 'POST', body: {
                name: 'test',
                url: document.getElementById('wh-da-url').value,
                admin_user: document.getElementById('wh-da-user').value,
                admin_password: document.getElementById('wh-da-pass').value,
            }});
            if (data.detected) {
                result.innerHTML = `<div style="padding:8px 12px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:6px;font-size:12px;margin:8px 0;">✓ DirectAdmin detected — ${data.user_count || 0} users found</div>`;
            } else {
                result.innerHTML = `<div style="padding:8px 12px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;font-size:12px;margin:8px 0;">✗ ${esc(data.error || 'Could not connect')}</div>`;
            }
        } catch(e) {
            result.innerHTML = `<div style="padding:8px 12px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;font-size:12px;margin:8px 0;">✗ ${esc(e.message)}</div>`;
        }
    };

    // Import all DA accounts for an instance
    window.wolfhostImportDA = async function(instanceId) {
        toast('Importing DirectAdmin accounts...', 'info');
        try {
            const data = await api(`/directadmin/${instanceId}/import`, { method: 'POST' });
            toast(`Imported: ${data.users_imported || 0} users, ${data.domains_imported || 0} domains, ${data.emails_imported || 0} emails, ${data.databases_imported || 0} databases`);
            switchTab('services');
        } catch(e) {
            toast('Import failed: ' + e.message, 'error');
        }
    };

    window.wolfhostDeleteService = function(id) {
        whConfirm('Delete Service', 'Are you sure you want to delete this service?', async () => {
            await api(`/services/${id}`, { method: 'DELETE' });
            toast('Service deleted');
            switchTab('services');
        });
    };

    // ─── Billing ───

    async function renderBilling(el) {
        [invoices, customers] = await Promise.all([
            api('/invoices'), api('/customers'),
        ]);

        const getCustomer = id => customers.find(c => c.id === id);

        el.innerHTML = `
            <div class="wh-table-container">
                <div class="wh-table-header">
                    <h3>Invoices (${invoices.length})</h3>
                    <div style="display:flex;gap:10px;align-items:center">
                        <input class="wh-search" id="wh-inv-search" placeholder="Search invoices..." oninput="wolfhostFilterInvoices()">
                        <button class="wh-btn wh-btn-primary" onclick="wolfhostCreateInvoice()">+ Create Invoice</button>
                    </div>
                </div>
                <table class="wh-table">
                    <thead><tr>
                        <th>Invoice</th><th>Customer</th><th>Description</th><th>Amount</th><th>Status</th><th>Due</th><th>Actions</th>
                    </tr></thead>
                    <tbody id="wh-inv-body">${renderInvoiceRows(invoices)}</tbody>
                </table>
            </div>
        `;
    }

    function renderInvoiceRows(list) {
        if (list.length === 0) return '<tr><td colspan="7"><div class="wh-empty"><span class="wh-empty-icon">💳</span><div class="wh-empty-text">No invoices yet</div></div></td></tr>';
        const getCustomer = id => customers.find(c => c.id === id);
        return list.map(i => {
            const cust = getCustomer(i.customer_id);
            return `<tr>
                <td><code style="font-size:11px;color:var(--text-muted)">${esc(i.id.substring(0, 8))}</code></td>
                <td>${cust ? esc(cust.first_name + ' ' + cust.last_name) : '—'}</td>
                <td>${esc(i.description)}</td>
                <td><strong>${formatCurrency(i.amount, i.currency)}</strong></td>
                <td>${badge(i.status)}</td>
                <td>${formatDate(i.due_at)}</td>
                <td>
                    <div style="display:flex;gap:6px">
                        ${i.status === 'pending' || i.status === 'overdue' ? `<button class="wh-btn wh-btn-sm" onclick="wolfhostMarkPaid('${i.id}')">Mark Paid</button>` : ''}
                    </div>
                </td>
            </tr>`;
        }).join('');
    }

    window.wolfhostFilterInvoices = function() {
        const q = (document.getElementById('wh-inv-search')?.value || '').toLowerCase();
        const filtered = invoices.filter(i => {
            const cust = customers.find(c => c.id === i.customer_id);
            return `${i.description} ${cust?.first_name} ${cust?.last_name} ${i.status}`.toLowerCase().includes(q);
        });
        document.getElementById('wh-inv-body').innerHTML = renderInvoiceRows(filtered);
    };

    window.wolfhostMarkPaid = async function(id) {
        await api(`/invoices/${id}`, { method: 'PUT', body: { status: 'paid' } });
        toast('Invoice marked as paid');
        switchTab('billing');
    };

    window.wolfhostCreateInvoice = function() {
        const custOpts = customers.map(c => `<option value="${c.id}">${esc(c.first_name)} ${esc(c.last_name)}</option>`).join('');
        showModal('Create Invoice', `
            <div class="wh-form-group"><label>Customer</label><select class="wh-select" id="wh-i-cust">${custOpts}</select></div>
            <div class="wh-form-group"><label>Description</label><input class="wh-input" id="wh-i-desc" placeholder="Hosting — Monthly"></div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Amount</label><input class="wh-input" type="number" step="0.01" id="wh-i-amount"></div>
                <div class="wh-form-group"><label>Due Date</label><input class="wh-input" type="date" id="wh-i-due"></div>
            </div>
        `, async () => {
            await api('/invoices', { method: 'POST', body: {
                customer_id: document.getElementById('wh-i-cust').value,
                description: document.getElementById('wh-i-desc').value,
                amount: parseFloat(document.getElementById('wh-i-amount').value) || 0,
                due_at: document.getElementById('wh-i-due').value,
            }});
            toast('Invoice created');
            closeModal();
            switchTab('billing');
        });
    };

    // ─── Tickets ───

    async function renderTickets(el) {
        [tickets, customers] = await Promise.all([
            api('/tickets'), api('/customers'),
        ]);
        const getCustomer = id => customers.find(c => c.id === id);

        el.innerHTML = `
            <div class="wh-table-container">
                <div class="wh-table-header">
                    <h3>Support Tickets (${tickets.length})</h3>
                    <input class="wh-search" placeholder="Search tickets..." oninput="wolfhostFilterTickets(this.value)">
                </div>
                <table class="wh-table">
                    <thead><tr>
                        <th>Subject</th><th>Customer</th><th>Status</th><th>Priority</th><th>Messages</th><th>Updated</th><th>Actions</th>
                    </tr></thead>
                    <tbody id="wh-ticket-body">${renderTicketRows(tickets)}</tbody>
                </table>
            </div>
            <div id="wh-ticket-detail" style="margin-top:20px"></div>
        `;
    }

    function renderTicketRows(list) {
        if (list.length === 0) return '<tr><td colspan="7"><div class="wh-empty"><span class="wh-empty-icon">🎫</span><div class="wh-empty-text">No support tickets</div></div></td></tr>';
        const getCustomer = id => customers.find(c => c.id === id);
        return list.map(t => {
            const cust = getCustomer(t.customer_id);
            return `<tr style="cursor:pointer" onclick="wolfhostViewTicket('${t.id}')">
                <td><strong>${esc(t.subject)}</strong></td>
                <td>${cust ? esc(cust.first_name + ' ' + cust.last_name) : '—'}</td>
                <td>${badge(t.status)}</td>
                <td>${priorityBadge(t.priority)}</td>
                <td>${t.message_count}</td>
                <td>${formatDate(t.updated_at)}</td>
                <td>
                    <select class="wh-select" style="width:auto;padding:4px 8px;font-size:12px" onchange="wolfhostUpdateTicketStatus('${t.id}', this.value); event.stopPropagation();">
                        ${['open','in_progress','waiting','resolved','closed'].map(s => `<option value="${s}" ${t.status === s ? 'selected' : ''}>${s.replace('_',' ')}</option>`).join('')}
                    </select>
                </td>
            </tr>`;
        }).join('');
    }

    window.wolfhostFilterTickets = function(q) {
        q = (q || '').toLowerCase();
        const filtered = tickets.filter(t => {
            const cust = customers.find(c => c.id === t.customer_id);
            return `${t.subject} ${cust?.first_name} ${cust?.last_name} ${t.status} ${t.priority}`.toLowerCase().includes(q);
        });
        document.getElementById('wh-ticket-body').innerHTML = renderTicketRows(filtered);
    };

    window.wolfhostViewTicket = async function(id) {
        const ticket = await api(`/tickets/${id}`);
        const detail = document.getElementById('wh-ticket-detail');
        if (!detail) return;

        detail.innerHTML = `
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                    <h3 style="margin:0">${esc(ticket.subject)}</h3>
                    <div style="display:flex;gap:8px">${badge(ticket.status)} ${priorityBadge(ticket.priority)}</div>
                </div>
                <div class="wh-ticket-messages">
                    ${ticket.messages.map(m => `
                        <div class="wh-message">
                            <div class="wh-message-avatar ${m.author}">${esc(m.author_name?.[0] || '?')}</div>
                            <div class="wh-message-body">
                                <div class="wh-message-meta">
                                    <span class="wh-message-author">${esc(m.author_name)}</span>
                                    <span class="wh-message-time">${formatDate(m.created_at)}</span>
                                </div>
                                <div class="wh-message-content">${esc(m.content)}</div>
                            </div>
                        </div>
                    `).join('')}
                </div>
                <div style="margin-top:16px;display:flex;gap:10px">
                    <textarea class="wh-textarea" id="wh-ticket-reply" style="flex:1;min-height:60px" placeholder="Type your reply..."></textarea>
                    <button class="wh-btn wh-btn-primary" style="align-self:flex-end" onclick="wolfhostReplyTicket('${ticket.id}')">Reply</button>
                </div>
            </div>
        `;
        detail.scrollIntoView({ behavior: 'smooth' });
    };

    window.wolfhostReplyTicket = async function(id) {
        const content = document.getElementById('wh-ticket-reply')?.value;
        if (!content?.trim()) return;
        await api(`/tickets/${id}/reply`, { method: 'POST', body: {
            content: content,
            author: 'admin',
            author_name: 'Admin',
        }});
        toast('Reply sent');
        wolfhostViewTicket(id);
    };

    window.wolfhostUpdateTicketStatus = async function(id, status) {
        await api(`/tickets/${id}`, { method: 'PUT', body: { status } });
        toast('Ticket status updated');
    };

    // ─── Servers ───

    async function renderServers(el) {
        let nodesData, customerContainers, nodeIpOverrides;
        try {
            [nodesData, customerContainers, nodeIpOverrides] = await Promise.all([
                api('/servers/nodes'),
                api('/servers/customer-containers'),
                api('/servers/node-ips'),
            ]);
        } catch (e) {
            el.innerHTML = `<div class="wh-empty"><span class="wh-empty-icon">⚠️</span><div class="wh-empty-text">Failed to connect to WolfStack cluster: ${esc(e.message)}</div></div>`;
            return;
        }

        const nodes = nodesData.nodes || [];
        const containers = customerContainers || [];
        const ipOverrides = nodeIpOverrides || {};

        el.innerHTML = `
            <div class="wh-stats">
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">🖥️</span>
                    <div class="wh-stat-value">${nodes.length}</div>
                    <div class="wh-stat-label">Cluster Nodes</div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">✅</span>
                    <div class="wh-stat-value">${nodes.filter(n => n.online).length}</div>
                    <div class="wh-stat-label">Online</div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">📦</span>
                    <div class="wh-stat-value">${containers.length}</div>
                    <div class="wh-stat-label">Customer Containers</div>
                </div>
                <div class="wh-stat-card">
                    <span class="wh-stat-icon">🟢</span>
                    <div class="wh-stat-value">${containers.filter(c => c.state === 'running' || (c.status && c.status.includes('RUNNING'))).length}</div>
                    <div class="wh-stat-label">Running</div>
                </div>
            </div>

            <!-- Nodes -->
            <div class="wh-section-header"><h3>Cluster Nodes</h3></div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin-bottom:24px">
                ${nodes.map(n => {
                    const m = n.metrics || {};
                    const cpuPct = m.cpu_usage_percent != null ? Math.round(m.cpu_usage_percent) : (m.cpu_percent != null ? Math.round(m.cpu_percent) : '—');
                    const memUsedBytes = m.memory_used_bytes || m.memory_used || 0;
                    const memTotalBytes = m.memory_total_bytes || m.memory_total || 0;
                    const memPct = memTotalBytes ? Math.round((memUsedBytes / memTotalBytes) * 100) : (m.memory_percent ? Math.round(m.memory_percent) : 0);
                    const memUsed = memUsedBytes ? (memUsedBytes / 1073741824).toFixed(1) : '0';
                    const memTotal = memTotalBytes ? (memTotalBytes / 1073741824).toFixed(1) : '0';
                    // Disk: use the root mount from the disks array
                    const rootDisk = (m.disks || []).find(d => d.mount_point === '/') || {};
                    const diskUsedBytes = rootDisk.used_bytes || m.disk_used || 0;
                    const diskTotalBytes = rootDisk.total_bytes || m.disk_total || 0;
                    const diskPct = diskTotalBytes ? Math.round((diskUsedBytes / diskTotalBytes) * 100) : (rootDisk.usage_percent ? Math.round(rootDisk.usage_percent) : 0);
                    const diskUsed = diskUsedBytes ? (diskUsedBytes / 1073741824).toFixed(0) : '0';
                    const diskTotal = diskTotalBytes ? (diskTotalBytes / 1073741824).toFixed(0) : '0';
                    const lxcCount = n.lxc_count || 0;
                    const hasLxc = n.has_lxc !== false;
                    const nodeType = n.node_type || 'wolfstack';
                    const isProxmox = nodeType === 'proxmox';
                    const externalIp = ipOverrides[n.id] || n.public_ip || n.address || '';
                    const hasOverride = !!ipOverrides[n.id];

                    return `<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;transition:var(--transition);position:relative;overflow:hidden">
                        <div style="position:absolute;top:0;left:0;right:0;height:3px;background:${n.online ? 'var(--success)' : 'var(--danger)'}"></div>
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
                            <div>
                                <div style="font-size:15px;font-weight:600">${esc(n.hostname || n.address)}</div>
                                <div style="font-size:12px;color:var(--text-muted)">${esc(n.address)}:${n.port} ${n.is_self ? '<span style="color:var(--accent)">(this node)</span>' : ''}</div>
                                <div style="font-size:12px;margin-top:3px;display:flex;align-items:center;gap:6px">
                                    <span style="color:var(--text-muted)">External IP:</span>
                                    <span style="color:${hasOverride ? 'var(--success)' : 'var(--text-secondary)'};font-weight:500">${esc(externalIp) || 'Not set'}</span>
                                    <button class="wh-btn wh-btn-sm" style="padding:2px 8px;font-size:11px" onclick="event.stopPropagation();wolfhostSetNodeIp('${esc(n.id)}','${esc(n.hostname || n.address)}','${esc(externalIp)}')">Edit</button>
                                </div>
                            </div>
                            <div>
                                ${n.online
                                    ? '<span class="wh-badge-status wh-badge-active">Online</span>'
                                    : '<span class="wh-badge-status wh-badge-suspended">Offline</span>'
                                }
                            </div>
                        </div>
                        ${n.online ? `
                            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px">
                                <div style="text-align:center">
                                    <div style="font-size:18px;font-weight:700">${cpuPct}%</div>
                                    <div style="font-size:11px;color:var(--text-muted)">CPU</div>
                                </div>
                                <div style="text-align:center">
                                    <div style="font-size:18px;font-weight:700">${memPct}%</div>
                                    <div style="font-size:11px;color:var(--text-muted)">RAM ${memUsed}/${memTotal}G</div>
                                </div>
                                <div style="text-align:center">
                                    <div style="font-size:18px;font-weight:700">${diskPct}%</div>
                                    <div style="font-size:11px;color:var(--text-muted)">Disk ${diskUsed}/${diskTotal}G</div>
                                </div>
                            </div>
                            <div style="display:flex;gap:12px;font-size:12px;color:var(--text-secondary);border-top:1px solid var(--border);padding-top:12px">
                                <span>📦 ${lxcCount} containers</span>
                                <span style="color:${isProxmox ? '#e5a00d' : 'var(--info)'}">${isProxmox ? '🟧 Proxmox' : '🟦 WolfStack'}</span>
                                ${hasLxc
                                    ? '<span style="color:var(--success)">LXC ready</span>'
                                    : '<span style="color:var(--text-muted)">No LXC</span>'
                                }
                            </div>
                        ` : '<div style="font-size:13px;color:var(--text-muted);padding:8px 0">Node is offline</div>'}
                    </div>`;
                }).join('')}
            </div>

            <!-- Customer Containers -->
            <div class="wh-section-header">
                <h3>Customer Containers</h3>
                <button class="wh-btn wh-btn-primary" onclick="wolfhostProvisionContainer()">+ Provision Container</button>
            </div>
            <div class="wh-table-container">
                <table class="wh-table">
                    <thead><tr><th>Container</th><th>Status</th><th>CPU</th><th>Memory</th><th>Network I/O</th><th>PIDs</th><th>Actions</th></tr></thead>
                    <tbody>
                        ${containers.length === 0
                            ? '<tr><td colspan="7"><div class="wh-empty"><span class="wh-empty-icon">📦</span><div class="wh-empty-text">No customer containers yet. Provision one from a service.</div></div></td></tr>'
                            : containers.map(c => {
                                const st = c.stats || {};
                                const isRunning = c.state === 'running' || (c.status && c.status.includes('RUNNING'));
                                const memMb = st.memory_usage ? (st.memory_usage / 1048576).toFixed(0) : '0';
                                const memLimMb = st.memory_limit ? (st.memory_limit / 1048576).toFixed(0) : '—';
                                const netIn = st.net_input ? (st.net_input / 1048576).toFixed(1) : '0';
                                const netOut = st.net_output ? (st.net_output / 1048576).toFixed(1) : '0';
                                return `<tr>
                                    <td>
                                        <strong>${esc(c.name)}</strong>
                                        ${c.ip_address ? `<div style="font-size:11px;color:var(--text-muted)">${esc(c.ip_address)}</div>` : ''}
                                    </td>
                                    <td>${isRunning ? badge('active') : badge('suspended')}</td>
                                    <td>${st.cpu_percent != null ? st.cpu_percent.toFixed(1) + '%' : '—'}</td>
                                    <td>${memMb} / ${memLimMb} MB</td>
                                    <td style="font-size:12px">↓${netIn} MB ↑${netOut} MB</td>
                                    <td>${st.pids || '—'}</td>
                                    <td>
                                        <div style="display:flex;gap:6px">
                                            <button class="wh-btn wh-btn-sm" onclick="wolfhostOpenConsole('${esc(c.name)}')" title="Terminal">Terminal</button>
                                            ${isRunning
                                                ? `<button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostContainerAction('${esc(c.name)}','stop')">Stop</button>
                                                   <button class="wh-btn wh-btn-sm" onclick="wolfhostContainerAction('${esc(c.name)}','restart')">Restart</button>`
                                                : `<button class="wh-btn wh-btn-sm" onclick="wolfhostContainerAction('${esc(c.name)}','start')">Start</button>`
                                            }
                                            <button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostDeleteContainer('${esc(c.name)}')">Delete</button>
                                        </div>
                                    </td>
                                </tr>`;
                            }).join('')
                        }
                    </tbody>
                </table>
            </div>
        `;
    }

    window.wolfhostContainerAction = async function(name, action) {
        await api(`/servers/containers/${name}/action`, { method: 'POST', body: { action } });
        toast(`Container ${action}ed`);
        setTimeout(() => switchTab('servers'), 2000);
    };

    window.wolfhostDeleteContainer = function(name) {
        showModal('Delete Container', `
            <div style="text-align:center;margin-bottom:16px">
                <div style="font-size:36px;margin-bottom:8px">⚠️</div>
                <div style="font-size:15px;font-weight:600;margin-bottom:8px">Permanently delete <code>${esc(name)}</code>?</div>
                <p style="font-size:13px;color:var(--text-secondary)">This will stop and destroy the container and all its data. This action cannot be undone.</p>
            </div>
            <div class="wh-form-group">
                <label>Type the container name to confirm</label>
                <input class="wh-input" id="wh-del-confirm" placeholder="${esc(name)}">
            </div>
        `, async () => {
            const typed = document.getElementById('wh-del-confirm')?.value;
            if (typed !== name) {
                toast('Container name does not match', 'error');
                return;
            }
            const btn = document.getElementById('wh-modal-save');
            btn.textContent = 'Deleting...';
            btn.disabled = true;
            try {
                // Stop first, then destroy
                await api(`/servers/containers/${name}/action`, { method: 'POST', body: { action: 'stop' } }).catch(() => {});
                await api(`/servers/containers/${name}/action`, { method: 'POST', body: { action: 'destroy' } });
                // Remove container reference from the service
                const svcList = await api('/services');
                const svc = svcList.find(s => s.container_name === name);
                if (svc) {
                    await api(`/services/${svc.id}`, { method: 'PUT', body: {
                        server_node: '',
                        domain: svc.domain || '',
                    }});
                }
                toast('Container deleted');
                closeModal();
                switchTab('servers');
            } catch (e) {
                toast('Delete failed: ' + e.message, 'error');
                btn.textContent = 'Delete';
                btn.disabled = false;
            }
        }, 'Delete');
    };

    window.wolfhostSetNodeIp = function(nodeId, hostname, currentIp) {
        showModal(`Set External IP — ${hostname}`, `
            <div class="wh-form-group">
                <label>External / Public IP Address</label>
                <input class="wh-input" id="wh-nodeip-val" value="${esc(currentIp)}" placeholder="e.g. 203.0.113.50">
                <div style="font-size:11px;color:var(--text-muted);margin-top:6px">
                    This is the public IP that customers will point their domain's A record to.
                    When a container is provisioned on this node, this IP is shown in the customer portal
                    and used for DNS configuration.
                </div>
            </div>
            <div style="font-size:12px;color:var(--text-secondary);background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;margin-top:8px">
                <strong>DNS Instructions for customers:</strong><br>
                Point your domain's <strong>A record</strong> to the external IP, then the reverse proxy
                on this node will route traffic to their container.
            </div>
        `, async () => {
            const ip = document.getElementById('wh-nodeip-val').value.trim();
            await api('/servers/node-ips', { method: 'PUT', body: { node_id: nodeId, external_ip: ip } });
            toast(ip ? `External IP set to ${ip}` : 'External IP cleared');
            closeModal();
            switchTab('servers');
        });
    };

    window.wolfhostProvisionContainer = async function() {
        // Load services and nodes
        const [svcList, nodesData, templateData] = await Promise.all([
            api('/services'),
            api('/servers/nodes'),
            api('/servers/templates').catch(() => []),
        ]);

        const nodes = (nodesData.nodes || []).filter(n => n.online && (n.node_type === 'proxmox' || n.has_lxc !== false));
        const unprovisioned = svcList.filter(s => !s.server_node);
        const templates = Array.isArray(templateData) ? templateData : [];

        if (nodes.length === 0) {
            toast('No online nodes with LXC support available', 'error');
            return;
        }

        const svcOpts = (unprovisioned.length > 0 ? unprovisioned : svcList).map(s => {
            const cust = customers.find(c => c.id === s.customer_id);
            const custName = cust ? `${cust.first_name} ${cust.last_name}` : 'Unknown';
            return `<option value="${s.id}">${esc(s.domain || 'No domain')} — ${esc(custName)}</option>`;
        }).join('');

        const nodeOpts = `<option value="">Auto-balance (recommended)</option>` + nodes.map(n => {
            const type = n.node_type === 'proxmox' ? 'PVE' : 'WS';
            return `<option value="${n.id}">[${type}] ${esc(n.hostname || n.address)} (${n.lxc_count || 0} containers)</option>`;
        }).join('');

        showModal('Provision Customer Container', `
            <div class="wh-form-group"><label>Service</label><select class="wh-select" id="wh-prov-svc">${svcOpts}</select></div>
            <div class="wh-form-group"><label>Target Node</label><select class="wh-select" id="wh-prov-node">${nodeOpts}</select></div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Distribution</label>
                    <select class="wh-select" id="wh-prov-dist">
                        <option value="ubuntu" selected>Ubuntu</option>
                        <option value="debian">Debian</option>
                        <option value="alpine">Alpine</option>
                        <option value="almalinux">AlmaLinux</option>
                    </select>
                </div>
                <div class="wh-form-group"><label>Release</label>
                    <select class="wh-select" id="wh-prov-rel">
                        <option value="jammy" selected>22.04 (Jammy)</option>
                        <option value="noble">24.04 (Noble)</option>
                        <option value="bookworm">Bookworm</option>
                        <option value="bullseye">Bullseye</option>
                    </select>
                </div>
            </div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Memory</label>
                    <select class="wh-select" id="wh-prov-mem">
                        <option value="256m">256 MB</option>
                        <option value="512m" selected>512 MB</option>
                        <option value="1g">1 GB</option>
                        <option value="2g">2 GB</option>
                        <option value="4g">4 GB</option>
                    </select>
                </div>
                <div class="wh-form-group"><label>CPU Cores</label>
                    <select class="wh-select" id="wh-prov-cpu">
                        <option value="1" selected>1 core</option>
                        <option value="2">2 cores</option>
                        <option value="4">4 cores</option>
                    </select>
                </div>
            </div>
            <div style="background:var(--info-bg);border:1px solid rgba(59,130,246,0.2);border-radius:var(--radius-sm);padding:10px 14px;font-size:12px;color:var(--info)">
                This will create an isolated LXC container for the customer's service on the selected node.
            </div>
        `, async () => {
            const btn = document.getElementById('wh-modal-save');
            btn.textContent = 'Provisioning...';
            btn.disabled = true;

            // Capture values before closing modal
            const provData = {
                service_id: document.getElementById('wh-prov-svc').value,
                node_id: document.getElementById('wh-prov-node').value || undefined,
                distribution: document.getElementById('wh-prov-dist').value,
                release: document.getElementById('wh-prov-rel').value,
                memory_limit: document.getElementById('wh-prov-mem').value,
                cpu_cores: document.getElementById('wh-prov-cpu').value,
            };

            // Close modal immediately
            closeModal();

            try {
                const result = await api('/servers/provision', { method: 'POST', body: provData });
                if (result.error) {
                    toast(result.error, 'error');
                    switchTab('servers');
                } else {
                    wolfhostShowProvisionTerminal(result.task_id, result.container_name);
                }
            } catch (e) {
                toast('Provisioning failed: ' + e.message, 'error');
                switchTab('servers');
            }
        });
    };

    // ─── Provision Terminal ───

    window.wolfhostShowProvisionTerminal = function(taskId, containerName) {
        const content = document.getElementById('wh-content');
        if (!content) return;

        content.innerHTML = `
            <div style="margin-bottom:16px;display:flex;justify-content:space-between;align-items:center">
                <div>
                    <h3 style="margin:0;font-size:16px;font-weight:600">Provisioning: ${esc(containerName)}</h3>
                    <div style="font-size:12px;color:var(--text-muted);margin-top:4px" id="wh-term-status">Connecting...</div>
                </div>
                <button class="wh-btn" onclick="wolfhostTab('servers')">Back to Servers</button>
            </div>
            <div id="wh-terminal" style="background:#0a0e14;border:1px solid var(--border);border-radius:var(--radius);padding:16px;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.8;min-height:400px;max-height:600px;overflow-y:auto;color:#c5c8c6"></div>
        `;

        const term = document.getElementById('wh-terminal');
        const status = document.getElementById('wh-term-status');

        const colors = {
            info: '#8892a8',
            cmd: '#61afef',
            ok: '#98c379',
            err: '#e06c75',
            done: '#c678dd',
        };

        const icons = {
            info: 'i',
            cmd: '$',
            ok: '\u2713',
            err: '\u2717',
            done: '\u2605',
        };

        status.textContent = 'Live — polling provisioning logs...';
        status.style.color = 'var(--success)';

        let lastCount = 0;
        let finished = false;

        const pollInterval = setInterval(async () => {
            try {
                const logs = await api(`/servers/provision/${taskId}/logs`);
                if (!Array.isArray(logs)) return;

                // Render new entries
                for (let i = lastCount; i < logs.length; i++) {
                    const d = logs[i];
                    const color = colors[d.level] || '#c5c8c6';
                    const icon = icons[d.level] || '>';
                    const line = document.createElement('div');
                    line.innerHTML = `<span style="color:${color};opacity:0.5;margin-right:8px">${d.time}</span><span style="color:${color};font-weight:700;margin-right:8px">${icon}</span><span style="color:${color}">${esc(d.msg)}</span>`;
                    term.appendChild(line);
                    term.scrollTop = term.scrollHeight;

                    if (d.level === 'done') {
                        finished = true;
                    }
                }
                lastCount = logs.length;

                if (finished) {
                    clearInterval(pollInterval);
                    status.textContent = 'Complete!';
                    status.style.color = 'var(--success)';
                    const actions = document.createElement('div');
                    actions.style.cssText = 'margin-top:16px;display:flex;gap:10px';
                    actions.innerHTML = `
                        <button class="wh-btn wh-btn-primary" onclick="wolfhostTab('servers')">View Servers</button>
                        <button class="wh-btn" onclick="wolfhostOpenConsole('${esc(containerName)}')">Open Terminal</button>
                    `;
                    term.after(actions);
                }
            } catch (e) {
                // Keep polling — might be a transient error
            }
        }, 2000);
    };

    // Open WolfStack console for a container
    window.wolfhostOpenConsole = async function(containerName) {
        // Find which node this container is on
        let nodeId = '';
        try {
            const svcList = await api('/services');
            const svc = svcList.find(s => s.container_name === containerName);
            if (svc) nodeId = svc.server_node || '';
        } catch {}

        // Use WolfStack's console.html with proper parameters
        let url = `/console.html?type=lxc&name=${encodeURIComponent(containerName)}`;
        if (nodeId) url += `&node_id=${encodeURIComponent(nodeId)}`;
        window.open(url, 'console_' + containerName, 'width=960,height=600,menubar=no,toolbar=no');
    };

    // ─── DNS ───

    async function renderDns(el) {
        let dnsStatus;
        try { dnsStatus = await api('/dns/status'); } catch { dnsStatus = { running: false }; }

        if (!dnsStatus.running) {
            el.innerHTML = `
                <div class="wh-empty">
                    <span class="wh-empty-icon">🌍</span>
                    <div class="wh-empty-text">PowerDNS is not installed or not running.</div>
                    <p style="color:var(--text-secondary);font-size:13px;margin-bottom:16px">Install PowerDNS to host DNS zones for your customers. This lets customers point their domain nameservers to your servers.</p>
                    <button class="wh-btn wh-btn-primary" onclick="wolfhostInstallDns()">Install PowerDNS</button>
                </div>
            `;
            return;
        }

        const zones = dnsStatus.zones || [];
        const branding = await api('/branding');

        el.innerHTML = `
            <div class="wh-stats" style="margin-bottom:20px">
                <div class="wh-stat-card"><span class="wh-stat-icon">🟢</span><div class="wh-stat-value">Running</div><div class="wh-stat-label">PowerDNS Status</div></div>
                <div class="wh-stat-card"><span class="wh-stat-icon">🌍</span><div class="wh-stat-value">${zones.length}</div><div class="wh-stat-label">DNS Zones</div></div>
                <div class="wh-stat-card"><span class="wh-stat-icon">📡</span><div class="wh-stat-value">${esc(branding.ns1 || 'Not set')}</div><div class="wh-stat-label">NS1</div></div>
                <div class="wh-stat-card"><span class="wh-stat-icon">📡</span><div class="wh-stat-value">${esc(branding.ns2 || 'Not set')}</div><div class="wh-stat-label">NS2</div></div>
            </div>

            ${!branding.ns1 ? '<div style="background:var(--warning-bg);border:1px solid rgba(245,158,11,0.3);border-radius:var(--radius-sm);padding:12px 16px;margin-bottom:16px;font-size:13px;color:var(--warning)">Set your nameservers in the <strong>Branding</strong> tab (e.g. ns1.myhosting.com, ns2.myhosting.com). These must have A records pointing to your server IPs.</div>' : ''}

            <div class="wh-table-container">
                <div class="wh-table-header">
                    <h3>DNS Zones (${zones.length})</h3>
                    <button class="wh-btn wh-btn-primary" onclick="wolfhostCreateZone()">+ Create Zone</button>
                </div>
                <table class="wh-table">
                    <thead><tr><th>Domain</th><th>Actions</th></tr></thead>
                    <tbody>
                        ${zones.length === 0
                            ? '<tr><td colspan="2"><div class="wh-empty"><span class="wh-empty-icon">🌍</span><div class="wh-empty-text">No DNS zones. Zones are created automatically when you provision a service with a domain.</div></div></td></tr>'
                            : zones.map(z => {
                                const name = (z || '').replace(/\.$/, '');
                                return `<tr>
                                    <td><strong>${esc(name)}</strong></td>
                                    <td>
                                        <div style="display:flex;gap:6px">
                                            <button class="wh-btn wh-btn-sm" onclick="wolfhostViewZone('${esc(name)}')">Records</button>
                                            <button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostDeleteZone('${esc(name)}')">Delete</button>
                                        </div>
                                    </td>
                                </tr>`;
                            }).join('')
                        }
                    </tbody>
                </table>
            </div>
            <div id="wh-zone-detail" style="margin-top:20px"></div>
        `;
    }

    window.wolfhostInstallDns = async function() {
        whConfirm('Install PowerDNS', 'This will install an authoritative DNS server on this host.', async () => {
            toast('Installing PowerDNS...');
            const result = await api('/dns/install', { method: 'POST' });
            if (result.error) { toast(result.error, 'error'); } else { toast('PowerDNS installed!'); }
            switchTab('dns');
        });
    };

    window.wolfhostCreateZone = async function() {
        showModal('Create DNS Zone', `
            <div class="wh-form-group"><label>Domain</label><input class="wh-input" id="wh-dns-domain" placeholder="example.com"></div>
            <div class="wh-form-group"><label>Host IP (A record)</label><input class="wh-input" id="wh-dns-ip" placeholder="203.0.113.50"></div>
        `, async () => {
            await api('/dns/zones', { method: 'POST', body: {
                domain: document.getElementById('wh-dns-domain').value,
                host_ip: document.getElementById('wh-dns-ip').value,
            }});
            toast('Zone created');
            closeModal();
            switchTab('dns');
        });
    };

    window.wolfhostDeleteZone = async function(domain) {
        whConfirm('Delete DNS Zone', `Delete the DNS zone for <strong>${esc(domain)}</strong>?`, async () => {
            await api(`/dns/zones/${domain}`, { method: 'DELETE' });
            toast('Zone deleted');
            switchTab('dns');
        });
    };

    window.wolfhostViewZone = async function(domain) {
        const zone = await api(`/dns/zones/${domain}`);
        const rrsets = zone.rrsets || [];
        const detail = document.getElementById('wh-zone-detail');
        if (!detail) return;

        detail.innerHTML = `
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                    <h3 style="margin:0">${esc(domain)} — DNS Records</h3>
                    <button class="wh-btn wh-btn-primary wh-btn-sm" onclick="wolfhostAddRecord('${esc(domain)}')">+ Add Record</button>
                </div>
                <table class="wh-table">
                    <thead><tr><th>Name</th><th>Type</th><th>Content</th><th>TTL</th><th>Actions</th></tr></thead>
                    <tbody>
                        ${rrsets.map(rr => {
                            const records = rr.records || [];
                            return records.map(r => `
                                <tr>
                                    <td><code style="font-size:12px">${esc((rr.name || '').replace(/\.$/, ''))}</code></td>
                                    <td><strong>${esc(rr.type)}</strong></td>
                                    <td style="max-width:300px;word-break:break-all;font-size:12px">${esc(r.content)}</td>
                                    <td>${rr.ttl || 3600}</td>
                                    <td>${rr.type !== 'SOA' && rr.type !== 'NS' ? `<button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostDelRecord('${esc(domain)}','${esc((rr.name||'').replace(/\.$/, ''))}','${esc(rr.type)}')">Del</button>` : ''}</td>
                                </tr>
                            `).join('');
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
        detail.scrollIntoView({ behavior: 'smooth' });
    };

    window.wolfhostAddRecord = function(domain) {
        showModal('Add DNS Record', `
            <div class="wh-form-group"><label>Name</label><input class="wh-input" id="wh-rr-name" placeholder="@ or subdomain"></div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Type</label>
                    <select class="wh-select" id="wh-rr-type"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>SRV</option></select>
                </div>
                <div class="wh-form-group"><label>TTL</label><input class="wh-input" type="number" id="wh-rr-ttl" value="3600"></div>
            </div>
            <div class="wh-form-group"><label>Content</label><input class="wh-input" id="wh-rr-content" placeholder="1.2.3.4 or target.example.com."></div>
        `, async () => {
            await api(`/dns/zones/${domain}/records`, { method: 'PUT', body: {
                name: document.getElementById('wh-rr-name').value,
                type: document.getElementById('wh-rr-type').value,
                content: document.getElementById('wh-rr-content').value,
                ttl: parseInt(document.getElementById('wh-rr-ttl').value) || 3600,
            }});
            toast('Record added');
            closeModal();
            wolfhostViewZone(domain);
        });
    };

    window.wolfhostDelRecord = async function(domain, name, rtype) {
        whConfirm('Delete DNS Record', `Delete <strong>${esc(rtype)}</strong> record for <strong>${esc(name)}</strong>?`, async () => {
            await api(`/dns/zones/${domain}/records`, { method: 'DELETE', body: { name, type: rtype } });
            toast('Record deleted');
            wolfhostViewZone(domain);
        });
    };

    // ─── Branding ───

    async function renderBranding(el) {
        const b = await api('/branding');

        el.innerHTML = `
            <div style="display:grid;grid-template-columns:1fr 380px;gap:24px;align-items:start">
                <div>
                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px">
                        <h3 style="margin:0 0 20px;font-size:16px;font-weight:600">Company Identity</h3>
                        <div class="wh-form-group">
                            <label>Company Name</label>
                            <input class="wh-input" id="wh-b-name" value="${esc(b.company_name || '')}" placeholder="My Hosting Company">
                        </div>
                        <div class="wh-form-group">
                            <label>Tagline</label>
                            <input class="wh-input" id="wh-b-tagline" value="${esc(b.tagline || '')}" placeholder="Fast, reliable web hosting you can trust">
                        </div>
                        <div class="wh-form-group">
                            <label>Logo URL</label>
                            <input class="wh-input" id="wh-b-logo" value="${esc(b.logo_url || '')}" placeholder="https://example.com/logo.png">
                            <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Recommended: 200x50px PNG or SVG with transparent background. Leave empty to use the emoji icon.</div>
                        </div>
                        <div class="wh-form-row">
                            <div class="wh-form-group">
                                <label>Favicon Emoji</label>
                                <input class="wh-input" id="wh-b-icon" value="${esc(b.favicon_emoji || '🌐')}" placeholder="🌐" maxlength="4">
                            </div>
                            <div class="wh-form-group">
                                <label>Currency</label>
                                <select class="wh-input" id="wh-b-currency" style="padding:10px 14px">
                                    ${['USD','EUR','GBP','CAD','AUD','NZD','CHF','JPY','INR','BRL'].map(c =>
                                        `<option value="${c}" ${(b.currency || 'USD') === c ? 'selected' : ''}>${c}</option>`
                                    ).join('')}
                                </select>
                            </div>
                        </div>
                    </div>

                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px">
                        <h3 style="margin:0 0 20px;font-size:16px;font-weight:600">Theme Colors</h3>
                        <div class="wh-form-row">
                            <div class="wh-form-group">
                                <label>Accent Color</label>
                                <div style="display:flex;gap:10px;align-items:center">
                                    <input type="color" id="wh-b-accent-picker" value="${esc(b.accent_color || '#dc2626')}"
                                        style="width:48px;height:38px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--bg-input);cursor:pointer;padding:2px"
                                        oninput="document.getElementById('wh-b-accent').value=this.value;wolfhostPreviewBranding()">
                                    <input class="wh-input" id="wh-b-accent" value="${esc(b.accent_color || '#dc2626')}" placeholder="#dc2626" style="flex:1"
                                        oninput="document.getElementById('wh-b-accent-picker').value=this.value;wolfhostPreviewBranding()">
                                </div>
                            </div>
                            <div class="wh-form-group">
                                <label>Accent Light (hover)</label>
                                <div style="display:flex;gap:10px;align-items:center">
                                    <input type="color" id="wh-b-accentl-picker" value="${esc(b.accent_light || '#f87171')}"
                                        style="width:48px;height:38px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--bg-input);cursor:pointer;padding:2px"
                                        oninput="document.getElementById('wh-b-accentl').value=this.value">
                                    <input class="wh-input" id="wh-b-accentl" value="${esc(b.accent_light || '#f87171')}" placeholder="#f87171" style="flex:1"
                                        oninput="document.getElementById('wh-b-accentl-picker').value=this.value">
                                </div>
                            </div>
                        </div>
                        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
                            ${[
                                { label: 'Red', color: '#dc2626', light: '#f87171' },
                                { label: 'Blue', color: '#2563eb', light: '#60a5fa' },
                                { label: 'Green', color: '#059669', light: '#34d399' },
                                { label: 'Purple', color: '#7c3aed', light: '#a78bfa' },
                                { label: 'Orange', color: '#ea580c', light: '#fb923c' },
                                { label: 'Pink', color: '#db2777', light: '#f472b6' },
                                { label: 'Cyan', color: '#0891b2', light: '#22d3ee' },
                                { label: 'Amber', color: '#d97706', light: '#fbbf24' },
                            ].map(p => `
                                <button class="wh-btn wh-btn-sm" style="border-color:${p.color};color:${p.color}"
                                    onclick="document.getElementById('wh-b-accent').value='${p.color}';document.getElementById('wh-b-accent-picker').value='${p.color}';document.getElementById('wh-b-accentl').value='${p.light}';document.getElementById('wh-b-accentl-picker').value='${p.light}';wolfhostPreviewBranding()">
                                    <span style="width:12px;height:12px;border-radius:50%;background:${p.color};display:inline-block"></span> ${p.label}
                                </button>
                            `).join('')}
                        </div>
                    </div>

                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px">
                        <h3 style="margin:0 0 20px;font-size:16px;font-weight:600">Support & Links</h3>
                        <div class="wh-form-row">
                            <div class="wh-form-group">
                                <label>Support Email</label>
                                <input class="wh-input" id="wh-b-email" value="${esc(b.support_email || '')}" placeholder="support@myhosting.com">
                            </div>
                            <div class="wh-form-group">
                                <label>Support URL</label>
                                <input class="wh-input" id="wh-b-url" value="${esc(b.support_url || '')}" placeholder="https://help.myhosting.com">
                            </div>
                        </div>
                        <div class="wh-form-group">
                            <label>Terms of Service URL</label>
                            <input class="wh-input" id="wh-b-terms" value="${esc(b.terms_url || '')}" placeholder="https://myhosting.com/terms">
                        </div>
                        <div class="wh-form-group">
                            <label>Footer Text</label>
                            <input class="wh-input" id="wh-b-footer" value="${esc(b.footer_text || '')}" placeholder="&copy; 2026 My Hosting Company. All rights reserved.">
                        </div>
                    </div>

                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px">
                        <h3 style="margin:0 0 20px;font-size:16px;font-weight:600">Nameservers</h3>
                        <p style="font-size:12px;color:var(--text-muted);margin-bottom:16px">Customers will point their domains to these nameservers. They must resolve to IPs running PowerDNS (see DNS tab).</p>
                        <div class="wh-form-row">
                            <div class="wh-form-group">
                                <label>Primary Nameserver (NS1)</label>
                                <input class="wh-input" id="wh-b-ns1" value="${esc(b.ns1 || '')}" placeholder="ns1.myhosting.com">
                            </div>
                            <div class="wh-form-group">
                                <label>Secondary Nameserver (NS2)</label>
                                <input class="wh-input" id="wh-b-ns2" value="${esc(b.ns2 || '')}" placeholder="ns2.myhosting.com">
                            </div>
                        </div>
                    </div>

                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px">
                        <h3 style="margin:0 0 20px;font-size:16px;font-weight:600">Custom CSS</h3>
                        <div class="wh-form-group">
                            <label>Additional CSS for the customer portal</label>
                            <textarea class="wh-textarea" id="wh-b-css" rows="6" style="font-family:'JetBrains Mono',monospace;font-size:12px" placeholder="/* Custom styles for the portal */\n.login-title { font-style: italic; }">${esc(b.custom_css || '')}</textarea>
                        </div>
                    </div>

                    <button class="wh-btn wh-btn-primary" style="padding:12px 32px;font-size:14px" onclick="wolfhostSaveBranding()">
                        Save Branding
                    </button>
                </div>

                <!-- Live Preview -->
                <div style="position:sticky;top:20px">
                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
                        <div style="padding:12px 16px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px">
                            Portal Preview
                        </div>
                        <div id="wh-brand-preview" style="padding:0;background:#0a0e1a;min-height:400px">
                        </div>
                    </div>
                </div>
            </div>
        `;
        wolfhostPreviewBranding();
    }

    window.wolfhostPreviewBranding = function() {
        const preview = document.getElementById('wh-brand-preview');
        if (!preview) return;

        const name = document.getElementById('wh-b-name')?.value || 'My Hosting';
        const tagline = document.getElementById('wh-b-tagline')?.value || 'Customer Portal';
        const logo = document.getElementById('wh-b-logo')?.value || '';
        const icon = document.getElementById('wh-b-icon')?.value || '🌐';
        const accent = document.getElementById('wh-b-accent')?.value || '#dc2626';
        const footer = document.getElementById('wh-b-footer')?.value || '';

        preview.innerHTML = `
            <div style="padding:30px 24px;text-align:center;background:linear-gradient(135deg, rgba(${hexToRgb(accent)},0.08) 0%, transparent 50%)">
                ${logo
                    ? `<img src="${esc(logo)}" alt="" style="max-height:48px;margin-bottom:12px;display:block;margin-left:auto;margin-right:auto">`
                    : `<div style="font-size:40px;margin-bottom:8px">${esc(icon)}</div>`
                }
                <div style="font-size:20px;font-weight:700;background:linear-gradient(135deg,${accent},${accent}cc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">${esc(name)}</div>
                <div style="font-size:12px;color:#8892a8;margin-top:4px">${esc(tagline)}</div>
            </div>
            <div style="padding:0 20px">
                <div style="background:#111827;border:1px solid #1e2a4a;border-radius:8px;padding:14px;margin-bottom:12px">
                    <div style="font-size:11px;color:#5a6378;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px">Email Address</div>
                    <div style="background:#0d1225;border:1px solid #1e2a4a;border-radius:6px;padding:10px 12px;color:#5a6378;font-size:13px">you@example.com</div>
                </div>
                <div style="background:#111827;border:1px solid #1e2a4a;border-radius:8px;padding:14px;margin-bottom:16px">
                    <div style="font-size:11px;color:#5a6378;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px">Password</div>
                    <div style="background:#0d1225;border:1px solid #1e2a4a;border-radius:6px;padding:10px 12px;color:#5a6378;font-size:13px">••••••••</div>
                </div>
                <div style="background:linear-gradient(135deg,${accent},${accent}dd);color:#fff;text-align:center;padding:12px;border-radius:8px;font-weight:600;font-size:14px;cursor:default;box-shadow:0 4px 12px rgba(${hexToRgb(accent)},0.3)">Sign In</div>
            </div>
            <div style="padding:16px 20px">
                <div style="display:flex;gap:8px;margin-bottom:12px">
                    <div style="flex:1;background:#1a1f35;border:1px solid #1e2a4a;border-radius:8px;padding:12px;text-align:center">
                        <div style="font-size:11px;color:#5a6378">Services</div>
                        <div style="font-size:18px;font-weight:700;color:#e8ecf4">3</div>
                    </div>
                    <div style="flex:1;background:#1a1f35;border:1px solid #1e2a4a;border-radius:8px;padding:12px;text-align:center">
                        <div style="font-size:11px;color:#5a6378">Domains</div>
                        <div style="font-size:18px;font-weight:700;color:#e8ecf4">5</div>
                    </div>
                </div>
                <div style="background:#1a1f35;border:1px solid #1e2a4a;border-radius:8px;padding:12px">
                    <div style="display:flex;justify-content:space-between;font-size:12px;color:#8892a8;margin-bottom:6px"><span>Disk</span><span>2.1 / 10 GB</span></div>
                    <div style="height:6px;background:#0d1225;border-radius:3px;overflow:hidden"><div style="width:21%;height:100%;border-radius:3px;background:linear-gradient(135deg,${accent},${accent}cc)"></div></div>
                </div>
            </div>
            ${footer ? `<div style="padding:12px 20px;border-top:1px solid #1e2a4a;font-size:11px;color:#5a6378;text-align:center">${esc(footer)}</div>` : ''}
        `;
    };

    function hexToRgb(hex) {
        hex = hex.replace('#', '');
        if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
        const r = parseInt(hex.substring(0, 2), 16);
        const g = parseInt(hex.substring(2, 4), 16);
        const b = parseInt(hex.substring(4, 6), 16);
        return `${r},${g},${b}`;
    }

    // ─── Database Settings ───

    async function renderDatabase(el) {
        const db = await api('/database');

        el.innerHTML = `
            <div style="max-width:700px">
                <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
                        <h3 style="margin:0;font-size:16px;font-weight:600">Storage Backend</h3>
                        <div id="wh-db-status">
                            ${db.connected
                                ? '<span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;background:rgba(16,185,129,0.1);color:#10b981"><span style="width:7px;height:7px;border-radius:50%;background:#10b981"></span>Connected to MariaDB</span>'
                                : db.enabled
                                    ? '<span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;background:rgba(239,68,68,0.1);color:#ef4444"><span style="width:7px;height:7px;border-radius:50%;background:#ef4444"></span>Not Connected</span>'
                                    : '<span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;background:rgba(138,143,160,0.1);color:var(--text-muted)"><span style="width:7px;height:7px;border-radius:50%;background:var(--text-muted)"></span>Using JSON Files</span>'
                            }
                        </div>
                    </div>
                    <div style="display:flex;gap:12px;margin-bottom:20px">
                        <label style="display:flex;align-items:center;gap:10px;padding:16px 20px;background:${!db.enabled ? 'var(--accent-glow)' : 'var(--bg-input)'};border:1px solid ${!db.enabled ? 'var(--accent)' : 'var(--border)'};border-radius:var(--radius-sm);cursor:pointer;flex:1" onclick="document.getElementById('wh-db-enable').checked=false;document.getElementById('wh-db-fields').style.opacity='0.4';document.getElementById('wh-db-fields').style.pointerEvents='none';this.style.background='var(--accent-glow)';this.style.borderColor='var(--accent)';this.nextElementSibling.style.background='var(--bg-input)';this.nextElementSibling.style.borderColor='var(--border)'">
                            <input type="radio" name="wh-db-mode" ${!db.enabled ? 'checked' : ''} style="display:none">
                            <div>
                                <div style="font-size:20px;margin-bottom:4px">📄</div>
                                <div style="font-size:13px;font-weight:600">JSON Files</div>
                                <div style="font-size:11px;color:var(--text-muted)">Simple, no setup required</div>
                            </div>
                        </label>
                        <label style="display:flex;align-items:center;gap:10px;padding:16px 20px;background:${db.enabled ? 'var(--accent-glow)' : 'var(--bg-input)'};border:1px solid ${db.enabled ? 'var(--accent)' : 'var(--border)'};border-radius:var(--radius-sm);cursor:pointer;flex:1" onclick="document.getElementById('wh-db-enable').checked=true;document.getElementById('wh-db-fields').style.opacity='1';document.getElementById('wh-db-fields').style.pointerEvents='auto';this.style.background='var(--accent-glow)';this.style.borderColor='var(--accent)';this.previousElementSibling.style.background='var(--bg-input)';this.previousElementSibling.style.borderColor='var(--border)'">
                            <input type="radio" name="wh-db-mode" ${db.enabled ? 'checked' : ''} style="display:none">
                            <div>
                                <div style="font-size:20px;margin-bottom:4px">🗄️</div>
                                <div style="font-size:13px;font-weight:600">MariaDB</div>
                                <div style="font-size:11px;color:var(--text-muted)">Scalable, production-ready</div>
                            </div>
                        </label>
                    </div>
                    <input type="checkbox" id="wh-db-enable" ${db.enabled ? 'checked' : ''} style="display:none">
                </div>

                <div id="wh-db-fields" style="opacity:${db.enabled ? '1' : '0.4'};pointer-events:${db.enabled ? 'auto' : 'none'};transition:opacity 0.3s">
                    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px">
                        <h3 style="margin:0 0 20px;font-size:16px;font-weight:600">Connection Settings</h3>
                        <div class="wh-form-row">
                            <div class="wh-form-group">
                                <label>Host</label>
                                <input class="wh-input" id="wh-db-host" value="${esc(db.host || '127.0.0.1')}" placeholder="127.0.0.1">
                            </div>
                            <div class="wh-form-group">
                                <label>Port</label>
                                <input class="wh-input" type="number" id="wh-db-port" value="${db.port || 3306}" placeholder="3306">
                            </div>
                        </div>
                        <div class="wh-form-row">
                            <div class="wh-form-group">
                                <label>Username</label>
                                <input class="wh-input" id="wh-db-user" value="${esc(db.username || '')}" placeholder="wolfhost">
                            </div>
                            <div class="wh-form-group">
                                <label>Password</label>
                                <input class="wh-input" type="password" id="wh-db-pass" placeholder="${db.password_set ? '(unchanged)' : 'Enter password'}">
                            </div>
                        </div>
                        <div class="wh-form-group">
                            <label>Database Name</label>
                            <input class="wh-input" id="wh-db-name" value="${esc(db.database || 'wolfhost')}" placeholder="wolfhost">
                        </div>
                        <div style="display:flex;gap:10px;margin-top:16px">
                            <button class="wh-btn" onclick="wolfhostTestDb()">
                                Test Connection
                            </button>
                            <div id="wh-db-test-result" style="display:flex;align-items:center;font-size:13px"></div>
                        </div>
                    </div>
                </div>

                <button class="wh-btn wh-btn-primary" style="padding:12px 32px;font-size:14px" onclick="wolfhostSaveDb()">
                    Save Database Settings
                </button>
                <div style="margin-top:12px;font-size:12px;color:var(--text-muted)">
                    After saving, you must restart the WolfHost handler for the storage backend change to take effect.
                    Existing JSON data is not automatically migrated to the database.
                </div>
            </div>
        `;
    }

    window.wolfhostTestDb = async function() {
        const result = document.getElementById('wh-db-test-result');
        result.innerHTML = '<span style="color:var(--text-muted)">Testing...</span>';
        try {
            const resp = await api('/database/test', { method: 'POST', body: {
                host: document.getElementById('wh-db-host').value,
                port: parseInt(document.getElementById('wh-db-port').value) || 3306,
                username: document.getElementById('wh-db-user').value,
                password: document.getElementById('wh-db-pass').value,
                database: document.getElementById('wh-db-name').value,
            }});
            if (resp.status === 'connected') {
                result.innerHTML = `<span style="color:var(--success)">Connected — ${esc(resp.version)}</span>`;
            } else {
                result.innerHTML = `<span style="color:var(--danger)">${esc(resp.error)}</span>`;
            }
        } catch (e) {
            result.innerHTML = `<span style="color:var(--danger)">Request failed</span>`;
        }
    };

    window.wolfhostSaveDb = async function() {
        const enabled = document.getElementById('wh-db-enable').checked;
        const password = document.getElementById('wh-db-pass').value;
        const data = {
            enabled: enabled,
            host: document.getElementById('wh-db-host').value,
            port: parseInt(document.getElementById('wh-db-port').value) || 3306,
            username: document.getElementById('wh-db-user').value,
            password: password,
            database: document.getElementById('wh-db-name').value,
        };
        await api('/database', { method: 'PUT', body: data });
        toast('Database settings saved. Restart the handler to apply.');
    };

    window.wolfhostSaveBranding = async function() {
        const data = {
            company_name: document.getElementById('wh-b-name').value,
            tagline: document.getElementById('wh-b-tagline').value,
            logo_url: document.getElementById('wh-b-logo').value,
            favicon_emoji: document.getElementById('wh-b-icon').value,
            accent_color: document.getElementById('wh-b-accent').value,
            accent_light: document.getElementById('wh-b-accentl').value,
            support_email: document.getElementById('wh-b-email').value,
            support_url: document.getElementById('wh-b-url').value,
            terms_url: document.getElementById('wh-b-terms').value,
            footer_text: document.getElementById('wh-b-footer').value,
            currency: document.getElementById('wh-b-currency').value,
            custom_css: document.getElementById('wh-b-css').value,
            ns1: document.getElementById('wh-b-ns1').value,
            ns2: document.getElementById('wh-b-ns2').value,
        };
        await api('/branding', { method: 'PUT', body: data });
        toast('Branding saved! Changes will appear in the customer portal.');
    };

    // ─── Modal System ───

    function showModal(title, body, onSave, saveLabel) {
        closeModal();
        const overlay = document.createElement('div');
        overlay.className = 'wh-modal-overlay';
        overlay.id = 'wh-modal';
        overlay.onclick = e => { if (e.target === overlay) closeModal(); };
        overlay.innerHTML = `
            <div class="wh-modal">
                <div class="wh-modal-header">
                    <h3>${title}</h3>
                    <button class="wh-modal-close" onclick="wolfhostCloseModal()">&times;</button>
                </div>
                <div class="wh-modal-body">${body}</div>
                <div class="wh-modal-footer">
                    <button class="wh-btn" onclick="wolfhostCloseModal()">Cancel</button>
                    <button class="wh-btn wh-btn-primary" id="wh-modal-save">${saveLabel || 'Save'}</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
        document.getElementById('wh-modal-save').onclick = onSave;
        // Focus first input
        setTimeout(() => overlay.querySelector('input,select,textarea')?.focus(), 100);
    }

    function closeModal() {
        document.getElementById('wh-modal')?.remove();
    }

    window.wolfhostCloseModal = closeModal;

    // ─── Initialize ───

    // ─── DA Tools — admin-side controls per DirectAdmin instance ───
    //
    // Three things on this tab:
    //   1. Sync local Plans onto the picked DA instance as packages.
    //   2. Service control (Apache / Nginx / Exim / MySQL restart).
    //   3. System info readout (load, memory, disk, DA version).
    //
    // Every action is scoped to the selected instance id; if the
    // operator hasn't added one yet we tell them to do that first.

    let _daToolsInstanceId = '';

    async function renderDaTools(el) {
        const instances = await api('/directadmin').catch(() => []);
        if (!instances.length) {
            el.innerHTML = `<div class="wh-empty"><span class="wh-empty-icon">🛠️</span>
                <div class="wh-empty-text">No DirectAdmin instances configured yet.<br>
                Go to <strong>Servers</strong> and add one first.</div></div>`;
            return;
        }
        if (!_daToolsInstanceId || !instances.find(i => i.id === _daToolsInstanceId)) {
            _daToolsInstanceId = instances[0].id;
        }
        const opts = instances.map(i =>
            `<option value="${esc(i.id)}"${i.id === _daToolsInstanceId ? ' selected' : ''}>${esc(i.name)} — ${esc(i.url)}</option>`
        ).join('');
        el.innerHTML = `
            <div class="wh-card" style="margin-bottom:14px;">
                <label style="display:block;margin-bottom:6px;font-weight:600;">DirectAdmin instance</label>
                <select id="da-instance-pick" onchange="adminDaToolsSetInstance(this.value)" style="width:100%;">
                    ${opts}
                </select>
            </div>

            <div class="wh-card" style="margin-bottom:14px;">
                <h3 style="margin-top:0;">Sync hosting plans → DirectAdmin packages</h3>
                <p style="color:var(--text-muted);font-size:13px;">
                    Push every plan from this WolfHost installation onto the selected
                    DirectAdmin server as a user package. Existing packages with the
                    same name are updated in place, missing ones are created.
                </p>
                <button class="wh-btn wh-btn-primary" onclick="adminDaSyncPackages()">⬆️ Sync packages</button>
                <button class="wh-btn" onclick="adminDaListPackages()">📋 List existing</button>
                <pre id="da-pkg-result" style="margin-top:10px;background:var(--bg-secondary);padding:10px;border-radius:6px;font-size:11px;max-height:300px;overflow:auto;"></pre>
            </div>

            <div class="wh-card" style="margin-bottom:14px;">
                <h3 style="margin-top:0;">Service control</h3>
                <p style="color:var(--text-muted);font-size:13px;">
                    Restart, start, or stop services on the DirectAdmin host.
                    Use sparingly — restarting Exim during business hours interrupts mail flow.
                </p>
                <div id="da-services" style="font-size:13px;"><em>Loading…</em></div>
            </div>

            <div class="wh-card">
                <h3 style="margin-top:0;">System info</h3>
                <div id="da-sysinfo" style="font-size:13px;"><em>Loading…</em></div>
            </div>
        `;
        adminDaLoadServices();
        adminDaLoadSysInfo();
    }

    window.adminDaToolsSetInstance = function(id) {
        _daToolsInstanceId = id;
        renderDaTools(document.getElementById('wh-content'));
    };

    window.adminDaSyncPackages = async function() {
        const out = document.getElementById('da-pkg-result');
        out.textContent = 'Syncing…';
        try {
            const resp = await api(`/directadmin/${encodeURIComponent(_daToolsInstanceId)}/packages/sync`, { method: 'POST' });
            out.textContent = JSON.stringify(resp, null, 2);
            toast(`${resp.synced} synced, ${resp.failed} failed`);
        } catch (e) { out.textContent = 'Failed: ' + e.message; }
    };

    window.adminDaListPackages = async function() {
        const out = document.getElementById('da-pkg-result');
        out.textContent = 'Loading…';
        try {
            const resp = await api(`/directadmin/${encodeURIComponent(_daToolsInstanceId)}/packages`);
            out.textContent = (resp.packages || []).join('\n') || '(none)';
        } catch (e) { out.textContent = 'Failed: ' + e.message; }
    };

    window.adminDaLoadServices = async function() {
        const host = document.getElementById('da-services');
        if (!host) return;
        try {
            const list = await api(`/directadmin/${encodeURIComponent(_daToolsInstanceId)}/services`);
            host.innerHTML = `<table class="wh-table" style="width:100%;">
                <thead><tr><th align="left">Service</th><th>Status</th><th>Auto-start</th><th></th></tr></thead>
                <tbody>${(list||[]).map(s => `<tr>
                    <td><code>${esc(s.name)}</code></td>
                    <td>${s.running ? '<span style="color:#4ade80;">running</span>' : '<span style="color:#fca5a5;">stopped</span>'}</td>
                    <td>${s.auto_start ? '✓' : '—'}</td>
                    <td>
                        <button class="wh-btn wh-btn-sm" onclick="adminDaServiceAction('${esc(s.name)}', 'restart')">Restart</button>
                        ${s.running
                            ? `<button class="wh-btn wh-btn-sm" onclick="adminDaServiceAction('${esc(s.name)}', 'stop')">Stop</button>`
                            : `<button class="wh-btn wh-btn-sm" onclick="adminDaServiceAction('${esc(s.name)}', 'start')">Start</button>`}
                    </td>
                </tr>`).join('')}</tbody></table>`;
        } catch (e) {
            host.innerHTML = `<em style="color:#fca5a5;">Failed: ${esc(e.message)}</em>`;
        }
    };

    window.adminDaServiceAction = async function(name, action) {
        if ((action === 'stop' || action === 'restart')
            && !confirm(`${action.charAt(0).toUpperCase()+action.slice(1)} ${name}?`)) return;
        try {
            await api(`/directadmin/${encodeURIComponent(_daToolsInstanceId)}/services/action`, {
                method: 'POST',
                body: { service: name, action },
            });
            toast(`${name}: ${action} ok`);
            adminDaLoadServices();
        } catch (e) { toast('Failed: ' + e.message, 'error'); }
    };

    window.adminDaLoadSysInfo = async function() {
        const host = document.getElementById('da-sysinfo');
        if (!host) return;
        try {
            const i = await api(`/directadmin/${encodeURIComponent(_daToolsInstanceId)}/system-info`);
            const days = Math.floor((i.uptime_seconds||0) / 86400);
            host.innerHTML = `
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                    <div><strong>DA version:</strong> ${esc(i.directadmin_version||'')}</div>
                    <div><strong>Kernel:</strong> ${esc(i.kernel||'')}</div>
                    <div><strong>Uptime:</strong> ${days} day${days===1?'':'s'}</div>
                    <div><strong>Load:</strong> ${i.load_1m||0} / ${i.load_5m||0} / ${i.load_15m||0}</div>
                    <div><strong>Memory:</strong> ${i.mem_used_mb||0} / ${i.mem_total_mb||0} MB</div>
                    <div><strong>Disk used:</strong> ${i.disk_used_pct||0}%</div>
                </div>`;
        } catch (e) {
            host.innerHTML = `<em style="color:#fca5a5;">Failed: ${esc(e.message)}</em>`;
        }
    };

    // ─── Migrations ─────────────────────────────────────────────
    //
    // Migration is admin-driven: pick a DA-backed service, choose
    // (or auto-balance) a target node, kick off a backend job. The
    // worker runs in the wolfhost backend; this UI just polls
    // `/migrations/{id}` for status and surfaces a progress bar
    // and the per-step log.

    let _migrationsPollTimer = null;

    async function renderMigrations(el) {
        const migs = await api('/migrations').catch(() => []);
        const stats = {
            running: migs.filter(m => !['complete','failed','cancelled'].includes(m.status)).length,
            done: migs.filter(m => m.status === 'complete').length,
            failed: migs.filter(m => m.status === 'failed' || m.status === 'cancelled').length,
        };
        el.innerHTML = `
            <div class="wh-table-container">
                <div class="wh-table-header">
                    <h3>Migrations
                        <span style="font-size:11px;color:var(--text-muted);margin-left:8px;">${stats.running} running · ${stats.done} complete · ${stats.failed} failed/cancelled</span>
                    </h3>
                    <div style="font-size:12px;color:var(--text-muted);max-width:540px;line-height:1.5;">
                        Pick a DirectAdmin-backed service from the Services tab and click <strong>Migrate</strong>. The job will appear here.
                    </div>
                </div>
                ${migs.length === 0
                    ? '<div class="wh-empty"><span class="wh-empty-icon">⇨</span><div class="wh-empty-text">No migrations yet. Start one from the Services tab.</div></div>'
                    : `<table class="wh-table">
                        <thead><tr>
                            <th>Started</th><th>Service / DA user</th><th>Target LXC</th><th>Status</th><th>Progress</th><th>Actions</th>
                        </tr></thead>
                        <tbody>${migs.map(m => migrationRow(m)).join('')}</tbody>
                    </table>`
                }
            </div>
        `;

        // Auto-refresh every 4 seconds while any migration is
        // non-terminal. The poll is on the LIST endpoint so we don't
        // need to track which row the user is interested in.
        if (_migrationsPollTimer) { clearInterval(_migrationsPollTimer); _migrationsPollTimer = null; }
        if (stats.running > 0) {
            _migrationsPollTimer = setInterval(async () => {
                if (currentTab !== 'migrations') {
                    clearInterval(_migrationsPollTimer); _migrationsPollTimer = null; return;
                }
                try {
                    const fresh = await api('/migrations');
                    const body = el.querySelector('tbody');
                    if (body) body.innerHTML = fresh.map(m => migrationRow(m)).join('');
                    if (!fresh.some(m => !['complete','failed','cancelled'].includes(m.status))) {
                        clearInterval(_migrationsPollTimer); _migrationsPollTimer = null;
                    }
                } catch(_) {}
            }, 4000);
        }
    }

    function migrationRow(m) {
        const terminal = ['complete','failed','cancelled','rolled_back'].includes(m.status);
        const colour = m.status === 'complete'    ? 'var(--success)' :
                       m.status === 'failed'      ? 'var(--danger)' :
                       m.status === 'cancelled'   ? 'var(--text-muted)' :
                       m.status === 'rolled_back' ? 'var(--warning,#f59e0b)' :
                                                    'var(--accent)';
        const pct = migrationProgressPct(m.status);
        const label = migrationStatusLabel(m.status);
        return `<tr>
            <td>${formatDate(m.started_at)} <span style="font-size:11px;color:var(--text-muted)">${esc((m.started_at||'').split('T')[1]?.slice(0,5) || '')}</span></td>
            <td>
                <div style="font-weight:600;">${esc(m.source_domain || '<no-domain>')}</div>
                <div style="font-size:11px;color:var(--text-muted)">DA user: <code>${esc(m.source_da_username)}</code></div>
            </td>
            <td>
                ${m.new_container_name
                    ? `<code>${esc(m.new_container_name)}</code><div style="font-size:11px;color:var(--text-muted)">${esc(m.new_container_node)}</div>`
                    : '<span style="color:var(--text-muted)">pending</span>'}
            </td>
            <td><span style="color:${colour};font-weight:600;font-size:12px;">${esc(label)}</span></td>
            <td>
                <div style="background:var(--bg-input);border-radius:3px;height:6px;width:140px;overflow:hidden;">
                    <div style="background:${colour};height:100%;width:${pct}%;transition:width 0.3s ease;"></div>
                </div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${pct}%</div>
            </td>
            <td>
                <div style="display:flex;gap:6px;flex-wrap:wrap">
                    <button class="wh-btn wh-btn-sm" onclick="wolfhostShowMigration('${m.id}')">Details</button>
                    ${m.status === 'complete' ? `<button class="wh-btn wh-btn-sm" style="border-color:var(--warning,#f59e0b);color:var(--warning,#f59e0b)" onclick="wolfhostRollbackMigration('${m.id}')" title="Revert: flip the service back to DirectAdmin and unsuspend the DA user. Customer-portal calls reroute instantly. The new LXC is left in place.">↩ Rollback</button>` : ''}
                    ${terminal ? '' : `<button class="wh-btn wh-btn-sm wh-btn-danger" onclick="wolfhostCancelMigration('${m.id}')">Cancel</button>`}
                </div>
            </td>
        </tr>`;
    }

    window.wolfhostRollbackMigration = function(id) {
        whConfirm('Roll back this migration?',
            'The customer\'s service record flips back to DirectAdmin and (if it was suspended at finalize) the DA user is unsuspended. Customer-portal calls route through DA again on the next request — no portal restart needed. The new LXC is <strong>not</strong> destroyed; clean it up by hand once you\'ve decided.',
            async () => {
                const r = await api(`/migrations/${id}/rollback`, { method: 'POST' });
                toast('Rolled back to DirectAdmin');
                if (r.warnings && r.warnings.length) {
                    r.warnings.forEach(w => toast(w, 'error'));
                }
                switchTab('migrations');
            });
    };

    function migrationStatusLabel(s) {
        return ({
            pending: 'Pending',
            creating_backup: 'Creating backup',
            waiting_backup: 'Waiting for backup',
            provisioning_lxc: 'Provisioning LXC',
            waiting_lxc: 'Waiting for LXC',
            downloading_backup: 'Downloading backup',
            uploading_to_lxc: 'Uploading to LXC',
            extracting: 'Extracting',
            restoring_databases: 'Restoring databases',
            verifying: 'Verifying',
            finalizing: 'Finalising',
            complete: 'Complete',
            failed: 'Failed',
            cancelled: 'Cancelled',
            rolled_back: 'Rolled back',
        })[s] || s;
    }

    function migrationProgressPct(s) {
        return ({
            pending: 0, creating_backup: 5, waiting_backup: 15,
            provisioning_lxc: 30, waiting_lxc: 45, downloading_backup: 55,
            uploading_to_lxc: 70, extracting: 80, restoring_databases: 88,
            verifying: 94, finalizing: 97,
            complete: 100, failed: 100, cancelled: 100, rolled_back: 100,
        })[s] || 0;
    }

    window.wolfhostSuspendDA = function(serviceId) {
        whConfirm('Disable DirectAdmin account?',
            'The underlying DA user will be suspended — customer can\'t log in, mail flow stops, files stay on disk. Reversible: hit "Re-enable DA" to undo.',
            async () => {
                await api(`/services/${serviceId}/da/suspend`, { method: 'POST' });
                toast('DirectAdmin user suspended');
                switchTab('services');
            });
    };

    window.wolfhostUnsuspendDA = function(serviceId) {
        whConfirm('Re-enable DirectAdmin account?',
            'The underlying DA user will be unsuspended — customer can log in again, mail flow resumes.',
            async () => {
                await api(`/services/${serviceId}/da/unsuspend`, { method: 'POST' });
                toast('DirectAdmin user re-enabled');
                switchTab('services');
            });
    };

    window.wolfhostStartMigration = async function(serviceId) {
        // Pull cluster nodes so the operator can pin to a specific
        // node — `auto` (empty value) is the default and the backend
        // picks the least-loaded LXC-capable node.
        let nodes = [];
        try { const r = await api('/servers/nodes'); nodes = r.nodes || r || []; } catch(_) {}
        const nodeOpts = ['<option value="">Auto-balance (recommended)</option>']
            .concat(nodes.filter(n => n.online !== false).map(n =>
                `<option value="${esc(n.id)}">${esc(n.hostname || n.name || n.id)}</option>`
            )).join('');
        const svc = (services || []).find(s => s.id === serviceId);
        const label = svc ? (svc.domain || svc.id) : serviceId;
        showModal('Migrate to WolfStack LXC', `
            <p style="font-size:13px;color:var(--text-secondary);margin-bottom:16px;line-height:1.5;">
                Migrate <strong>${esc(label)}</strong> from DirectAdmin onto a fresh WolfStack-managed LXC.
                The pipeline runs in the background — files, databases, email, FTP, and DNS settings ride
                along inside DA's <code>SITE_BACKUP</code> archive. Once finalised, the service flips to
                Native and customer-portal calls route through the new container.
            </p>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Target Node</label><select class="wh-select" id="wh-mig-node">${nodeOpts}</select></div>
                <div class="wh-form-group"><label>Template</label><input class="wh-input" id="wh-mig-template" value="ubuntu-22.04" placeholder="ubuntu-22.04"></div>
            </div>
            <div class="wh-form-row">
                <div class="wh-form-group"><label>Memory (MB)</label><input class="wh-input" type="number" id="wh-mig-mem" value="2048" min="512"></div>
                <div class="wh-form-group"><label>Disk (GB)</label><input class="wh-input" type="number" id="wh-mig-disk" value="20" min="5"></div>
                <div class="wh-form-group"><label>CPU cores</label><input class="wh-input" type="number" id="wh-mig-cpu" value="2" min="1"></div>
            </div>
            <div class="wh-form-group" style="margin-top:14px;background:var(--bg-secondary,#1a1f35);padding:10px 14px;border-radius:4px;border:1px solid var(--border);">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:13px;">
                    <input type="checkbox" id="wh-mig-suspend" checked style="margin:0;">
                    <span>Suspend source DirectAdmin account when finalised</span>
                </label>
                <div style="font-size:11px;color:var(--text-muted);margin-top:6px;margin-left:24px;">
                    Recommended: stops the customer accidentally writing to two places after the cutover.
                    Reversible — Rollback un-suspends automatically.
                </div>
            </div>
            <div style="background:var(--bg-secondary,#1a1f35);border-left:3px solid var(--accent);padding:10px 14px;font-size:12px;color:var(--text-secondary);border-radius:4px;margin-top:8px;">
                ⚠️ The migration creates a backup on the source DA box and downloads it. Plan for ~10–30 minutes
                depending on account size and network. The source DA stays serving customer traffic until the
                final Verify step succeeds — failures before that point are invisible to the customer.
                You can watch progress on the Migrations tab.
            </div>
        `, async () => {
            await api('/migrations', { method: 'POST', body: {
                service_id: serviceId,
                node_id: document.getElementById('wh-mig-node').value,
                template: document.getElementById('wh-mig-template').value,
                memory_mb: parseInt(document.getElementById('wh-mig-mem').value) || 2048,
                disk_gb: parseInt(document.getElementById('wh-mig-disk').value) || 20,
                cpu_cores: parseInt(document.getElementById('wh-mig-cpu').value) || 2,
                suspend_source_after: document.getElementById('wh-mig-suspend').checked,
            }});
            toast('Migration started — check the Migrations tab for progress');
            closeModal();
            wolfhostTab('migrations');
        });
    };

    window.wolfhostCancelMigration = function(id) {
        whConfirm('Cancel migration?', 'The worker stops at the next checkpoint. Anything already provisioned (the new LXC, downloaded backup) is left in place — clean it up by hand if needed.', async () => {
            await api(`/migrations/${id}`, { method: 'DELETE' });
            toast('Migration cancellation requested');
            switchTab('migrations');
        });
    };

    window.wolfhostShowMigration = async function(id) {
        const m = await api(`/migrations/${id}`);
        const logHtml = (m.log || []).map(e => `
            <div style="display:flex;gap:10px;padding:6px 0;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:11px;">
                <span style="color:var(--text-muted);white-space:nowrap;">${esc((e.at||'').split('T')[1]?.slice(0,8) || '')}</span>
                <span style="color:${e.kind==='error'?'var(--danger)':e.kind==='warn'?'var(--warning,#f59e0b)':'var(--text-secondary)'};font-weight:600;text-transform:uppercase;font-size:10px;min-width:48px;">${esc(e.kind)}</span>
                <span style="color:var(--text-primary);word-break:break-word;">${esc(e.message)}</span>
            </div>
        `).join('') || '<div style="color:var(--text-muted);text-align:center;padding:20px;">No log entries yet.</div>';
        showModal(`Migration ${id.slice(0, 8)}…`, `
            <div style="font-size:12px;color:var(--text-secondary);margin-bottom:14px;line-height:1.6">
                <div><strong>Service:</strong> ${esc(m.source_domain || '<no-domain>')} (DA user <code>${esc(m.source_da_username)}</code>)</div>
                <div><strong>Status:</strong> <span style="color:${m.status==='complete'?'var(--success)':m.status==='failed'?'var(--danger)':'var(--accent)'};font-weight:600;">${esc(migrationStatusLabel(m.status))}</span></div>
                ${m.new_container_name ? `<div><strong>LXC:</strong> <code>${esc(m.new_container_name)}</code> on <code>${esc(m.new_container_node)}</code></div>` : ''}
                ${m.backup_filename ? `<div><strong>Backup:</strong> <code>${esc(m.backup_filename)}</code></div>` : ''}
                ${m.error ? `<div style="margin-top:8px;color:var(--danger);"><strong>Error:</strong> ${esc(m.error)}</div>` : ''}
            </div>
            <h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);">Log</h4>
            <div style="max-height:360px;overflow-y:auto;background:var(--bg-input);border-radius:6px;padding:12px;border:1px solid var(--border);">
                ${logHtml}
            </div>
        `, () => closeModal(), 'Close');
    };

    // Built-in view entry point. app.js's selectView dispatch calls this
    // when the operator opens WolfHost from the Apps & Tools drawer (the
    // `page-wolfhost` view). No selectView monkey-patching — app.js owns
    // navigation now that WolfHost is a core view, not a plugin.
    window.wolfhostInit = init;

})();
