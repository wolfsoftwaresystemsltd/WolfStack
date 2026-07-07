/* WolfHost Customer Portal */
/* (C) Wolf Software Systems Ltd */

(function() {
    'use strict';

    let customer = null;
    let token = null;
    let currentView = 'dashboard';
    let dashboardData = null;
    let config = {};

    // ─── Utilities ───

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    async function api(path, opts = {}) {
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        // Callers pass `body` either as an object or already
        // JSON.stringify'd (the Hosting Tools panels do the latter) —
        // stringifying a string again double-encodes it and the
        // backend rejects the request, so pass strings through.
        const body = opts.body === undefined ? undefined
            : (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body));
        const resp = await fetch(`/api${path}`, {
            ...opts,
            headers: { ...headers, ...opts.headers },
            body,
        });
        if (resp.status === 401) {
            logout();
            throw new Error('Session expired');
        }
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            // Surface the server's message so failures never toast
            // as successes in the calling code.
            throw new Error((data && data.error) || `Request failed (${resp.status})`);
        }
        return data;
    }

    function toast(msg, type = 'success') {
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        el.textContent = msg;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 3000);
    }

    function fmtDate(iso) {
        if (!iso) return '—';
        try { return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); }
        catch { return iso; }
    }

    function fmtCurrency(amount) {
        return new Intl.NumberFormat('en-US', { style: 'currency', currency: config.currency || 'USD' }).format(amount || 0);
    }

    function badge(status) {
        const s = (status || '').toLowerCase().replace(/\s+/g, '_');
        return `<span class="badge badge-${esc(s)}">${esc(status)}</span>`;
    }

    function fmtSize(bytes) {
        if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
        if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return bytes + ' B';
    }

    function usageMeter(used, total, label) {
        const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
        const cls = pct > 90 ? 'danger' : pct > 70 ? 'warning' : '';
        const usedStr = used >= 1024 ? (used / 1024).toFixed(1) + ' GB' : used + ' MB';
        const totalStr = total >= 1024 ? (total / 1024).toFixed(1) + ' GB' : total + ' MB';
        return `<div class="usage-meter">
            <div class="usage-header"><span class="label">${esc(label)}</span><span class="value">${usedStr} / ${totalStr}</span></div>
            <div class="usage-bar"><div class="usage-fill ${cls}" style="width:${pct}%"></div></div>
        </div>`;
    }

    // ─── Auth ───

    window.portalLogin = async function(e) {
        e.preventDefault();
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const btn = document.getElementById('login-btn');
        const errDiv = document.getElementById('login-error');

        btn.disabled = true;
        btn.textContent = 'Signing in...';
        errDiv.style.display = 'none';

        try {
            const resp = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });
            const data = await resp.json();
            if (!resp.ok) {
                errDiv.textContent = data.error || 'Login failed';
                errDiv.style.display = 'block';
                return;
            }
            token = data.token;
            customer = data.customer;
            localStorage.setItem('wolfhost_token', token);
            localStorage.setItem('wolfhost_customer', JSON.stringify(customer));
            showApp();
        } catch (err) {
            errDiv.textContent = 'Connection error. Please try again.';
            errDiv.style.display = 'block';
        } finally {
            btn.disabled = false;
            btn.textContent = 'Sign In';
        }
    };

    window.portalLogout = function() {
        logout();
    };

    function logout() {
        api('/auth/logout', { method: 'POST' }).catch(() => {});
        token = null;
        customer = null;
        localStorage.removeItem('wolfhost_token');
        localStorage.removeItem('wolfhost_customer');
        document.getElementById('login-screen').style.display = '';
        document.getElementById('app-shell').style.display = 'none';
    }

    // ─── Navigation ───

    window.portalView = function(view) {
        currentView = view;
        document.querySelectorAll('.nav-link').forEach(el => {
            el.classList.toggle('active', el.dataset.view === view);
        });

        const titles = {
            dashboard: 'Dashboard', apps: 'App Installer', websites: 'Websites & Domains', ftp: 'FTP Accounts',
            ssl: 'SSL Certificates', databases: 'Databases', email: 'Email Accounts',
            files: 'File Manager', backups: 'Backups', usage: 'Resource Usage',
            'da-tools': 'Hosting Tools',
            support: 'Support', billing: 'Billing', settings: 'Account Settings',
        };
        document.getElementById('page-title').textContent = titles[view] || view;

        const content = document.getElementById('content-area');
        content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)">Loading...</div>';
        renderView(view, content).catch(err => {
            content.innerHTML = `<div class="empty-state"><span class="empty-icon">⚠️</span><div class="empty-text">${esc(err.message)}</div></div>`;
        });

        // Close sidebar on mobile
        document.getElementById('sidebar').classList.remove('open');
    };

    window.toggleSidebar = function() {
        document.getElementById('sidebar').classList.toggle('open');
    };

    async function renderView(view, el) {
        switch (view) {
            case 'dashboard': return renderDashboard(el);
            case 'apps': return renderApps(el);
            case 'websites': return renderWebsites(el);
            case 'ftp': return renderFtp(el);
            case 'ssl': return renderSsl(el);
            case 'databases': return renderDatabases(el);
            case 'email': return renderEmail(el);
            case 'files': return renderFiles(el);
            case 'backups': return renderBackups(el);
            case 'usage': return renderUsage(el);
            case 'da-tools': return renderDaTools(el);
            case 'support': return renderSupport(el);
            case 'billing': return renderBilling(el);
            case 'settings': return renderSettings(el);
        }
    }

    // ─── Dashboard ───

    async function renderDashboard(el) {
        let containerStats = [];
        const [dashData] = await Promise.all([
            api('/dashboard'),
            api('/container-stats').then(s => { containerStats = s || []; }).catch(() => {}),
        ]);
        dashboardData = dashData;
        const d = dashboardData;

        el.innerHTML = `
            <div style="margin-bottom:24px">
                <h2 style="font-size:22px;font-weight:700;margin-bottom:4px">Welcome back, ${esc(customer?.first_name || '')} 👋</h2>
                <p style="color:var(--text-secondary);font-size:14px">Here's an overview of your hosting services.</p>
            </div>

            <div class="stats-grid">
                <div class="stat-card"><span class="stat-icon">🌐</span><div class="stat-value">${d.active_services}</div><div class="stat-label">Active Services</div></div>
                <div class="stat-card"><span class="stat-icon">🌍</span><div class="stat-value">${d.total_domains}</div><div class="stat-label">Domains</div></div>
                <div class="stat-card"><span class="stat-icon">🎫</span><div class="stat-value">${d.open_tickets}</div><div class="stat-label">Open Tickets</div></div>
                <div class="stat-card"><span class="stat-icon">💳</span><div class="stat-value">${d.pending_invoices}</div><div class="stat-label">Pending Invoices</div></div>
            </div>

            ${containerStats.length > 0 ? `
                <h3 style="font-size:15px;font-weight:600;margin-bottom:12px">Server Status</h3>
                <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-bottom:24px">
                    ${containerStats.map(c => {
                        const memMb = c.memory_usage ? (c.memory_usage / 1048576).toFixed(0) : 0;
                        const memLimMb = c.memory_limit ? (c.memory_limit / 1048576).toFixed(0) : 0;
                        const memPct = c.memory_percent ? c.memory_percent.toFixed(1) : 0;
                        const cpuPct = c.cpu_percent ? c.cpu_percent.toFixed(1) : 0;
                        const netIn = c.net_input ? (c.net_input / 1048576).toFixed(1) : 0;
                        const netOut = c.net_output ? (c.net_output / 1048576).toFixed(1) : 0;
                        return `<div class="card" style="padding:16px">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                                <div>
                                    <div style="font-size:14px;font-weight:600">${esc(c.domain || c.container)}</div>
                                    <div style="font-size:11px;color:var(--text-muted)">${esc(c.container)}</div>
                                </div>
                                ${badge(c.status || 'active')}
                            </div>
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                                <div style="text-align:center;padding:10px;background:var(--bg-input);border-radius:var(--radius-sm)">
                                    <div style="font-size:20px;font-weight:700;color:var(--text-primary)">${cpuPct}%</div>
                                    <div style="font-size:11px;color:var(--text-muted)">CPU</div>
                                </div>
                                <div style="text-align:center;padding:10px;background:var(--bg-input);border-radius:var(--radius-sm)">
                                    <div style="font-size:20px;font-weight:700;color:var(--text-primary)">${memMb} MB</div>
                                    <div style="font-size:11px;color:var(--text-muted)">Memory (${memPct}%)</div>
                                </div>
                            </div>
                            <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-secondary);margin-top:10px;padding-top:10px;border-top:1px solid var(--border)">
                                <span>↓ ${netIn} MB in</span>
                                <span>↑ ${netOut} MB out</span>
                                <span>${c.pids || 0} processes</span>
                            </div>
                        </div>`;
                    }).join('')}
                </div>
            ` : ''}

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px">
                <div class="card">
                    <h3 style="margin-bottom:16px;font-size:15px;font-weight:600">Resource Usage</h3>
                    ${usageMeter(d.disk_used_mb, d.disk_limit_mb, 'Disk Space')}
                    ${usageMeter(d.bandwidth_used_mb, d.bandwidth_limit_mb, 'Bandwidth')}
                </div>
                <div class="card">
                    <h3 style="margin-bottom:16px;font-size:15px;font-weight:600">Quick Actions</h3>
                    <div class="quick-actions">
                        <div class="quick-action" onclick="portalView('websites')"><span class="quick-action-icon">🌍</span>Add Domain</div>
                        <div class="quick-action" onclick="portalView('ftp')"><span class="quick-action-icon">📁</span>FTP Access</div>
                        <div class="quick-action" onclick="portalView('ssl')"><span class="quick-action-icon">🔒</span>SSL Cert</div>
                        <div class="quick-action" onclick="portalView('support')"><span class="quick-action-icon">🎫</span>Get Help</div>
                    </div>
                </div>
            </div>

            ${d.services.length > 0 ? `
                <h3 style="font-size:15px;font-weight:600;margin-bottom:12px">Your Services</h3>
                <div class="service-cards">
                    ${d.services.map(s => `
                        <div class="service-card">
                            <div class="service-domain">${esc(s.domain) || 'No domain'}</div>
                            <div class="service-plan">${esc(s.plan)} ${badge(s.status)}</div>
                            ${usageMeter(s.disk_used_mb, s.disk_limit_mb || 0, 'Disk')}
                            ${s.host_ip ? `
                                <div class="info-box" style="margin-top:12px;font-size:12px">
                                    <div class="info-row"><span class="info-label">Server IP</span><span class="info-value">${esc(s.host_ip)}</span></div>
                                    ${s.host_hostname ? `<div class="info-row"><span class="info-label">Server</span><span class="info-value">${esc(s.host_hostname)}</span></div>` : ''}
                                    ${s.ftp_port ? `<div class="info-row"><span class="info-label">FTP Port</span><span class="info-value">${s.ftp_port}</span></div>` : ''}
                                </div>
                            ` : ''}
                            <div style="font-size:12px;color:var(--text-muted);margin-top:8px">Next billing: ${fmtDate(s.next_billing)}</div>
                        </div>
                    `).join('')}
                </div>
            ` : '<div class="empty-state"><span class="empty-icon">🌐</span><div class="empty-text">No active services</div></div>'}
        `;
    }

    // ─── Apps ───

    async function renderApps(el) {
        const apps = await api('/apps');
        const services = dashboardData?.services || [];

        // Group by category
        const categories = {};
        for (const app of apps) {
            if (!categories[app.category]) categories[app.category] = [];
            categories[app.category].push(app);
        }

        el.innerHTML = `
            <div style="margin-bottom:20px">
                <p style="color:var(--text-secondary);font-size:14px">Install popular web applications into your hosting with one click.</p>
            </div>
            ${Object.entries(categories).map(([cat, catApps]) => `
                <h3 style="font-size:14px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin:24px 0 12px">${esc(cat)}</h3>
                <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px">
                    ${catApps.map(app => `
                        <div class="card" style="padding:18px;display:flex;gap:14px;align-items:flex-start;cursor:pointer;transition:var(--transition)"
                             onmouseover="this.style.borderColor='var(--accent)';this.style.boxShadow='var(--shadow-glow)'"
                             onmouseout="this.style.borderColor='var(--border)';this.style.boxShadow='none'"
                             onclick="portalInstallApp('${esc(app.id)}')">
                            <div style="font-size:32px;flex-shrink:0;width:44px;height:44px;display:flex;align-items:center;justify-content:center;background:var(--bg-input);border-radius:var(--radius-sm)">${app.icon}</div>
                            <div style="flex:1;min-width:0">
                                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                                    <div style="font-size:14px;font-weight:600">${esc(app.name)}</div>
                                    ${app.requires_db ? '<span style="font-size:10px;padding:2px 6px;border-radius:4px;background:var(--info-bg);color:var(--info)">DB</span>' : ''}
                                </div>
                                <div style="font-size:12px;color:var(--text-secondary);line-height:1.5">${esc(app.description)}</div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `).join('')}
        `;
    }

    window.portalInstallApp = function(appId) {
        const services = dashboardData?.services || [];
        if (services.length === 0) {
            toast('No active services. Contact support to get started.', 'error');
            return;
        }

        const apps = []; // We'll fetch fresh
        api('/apps').then(allApps => {
            const app = allApps.find(a => a.id === appId);
            if (!app) return;

            const svcOpts = services.map(s =>
                `<option value="${s.id}">${esc(s.domain || s.plan)}</option>`
            ).join('');

            showModal(`Install ${app.name}`, `
                <div style="display:flex;gap:14px;align-items:center;margin-bottom:20px;padding:16px;background:var(--bg-input);border-radius:var(--radius-sm)">
                    <div style="font-size:36px">${app.icon}</div>
                    <div>
                        <div style="font-size:16px;font-weight:600">${esc(app.name)}</div>
                        <div style="font-size:12px;color:var(--text-secondary)">${esc(app.description)}</div>
                    </div>
                </div>
                <div class="form-group">
                    <label>Install On</label>
                    <select class="form-select" id="p-app-svc">${svcOpts}</select>
                </div>
                ${app.requires_db ? `
                    <div style="background:var(--info-bg);border:1px solid rgba(59,130,246,0.2);border-radius:var(--radius-sm);padding:10px 14px;font-size:12px;color:var(--info)">
                        A MariaDB database will be created automatically for this application.
                    </div>
                ` : ''}
                <div style="background:var(--warning-bg);border:1px solid rgba(245,158,11,0.2);border-radius:var(--radius-sm);padding:10px 14px;font-size:12px;color:var(--warning);margin-top:12px">
                    This will replace the current website files. Make sure to backup first!
                </div>
            `, async () => {
                const btn = document.getElementById('p-modal-save');
                btn.textContent = 'Installing...';
                btn.disabled = true;
                try {
                    const result = await api('/apps/install', { method: 'POST', body: {
                        app_id: appId,
                        service_id: document.getElementById('p-app-svc').value,
                    }});
                    if (result.error) {
                        toast(result.error, 'error');
                        btn.textContent = 'Save';
                        btn.disabled = false;
                        return;
                    }
                    closeModal();

                    // Show success with DB credentials if applicable
                    let msg = result.message;
                    if (result.db_name) {
                        showModal(`${app.name} Installing`, `
                            <div style="text-align:center;margin-bottom:20px">
                                <div style="font-size:48px;margin-bottom:12px">${app.icon}</div>
                                <div style="font-size:15px;font-weight:600;margin-bottom:4px">${esc(msg)}</div>
                            </div>
                            <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;font-family:monospace;font-size:13px">
                                <div style="margin-bottom:8px;font-family:inherit;font-weight:600;color:var(--text-secondary);font-size:12px">Database Credentials (save these!)</div>
                                <div style="display:flex;justify-content:space-between;padding:3px 0"><span style="color:var(--text-muted)">Database</span><span>${esc(result.db_name)}</span></div>
                                <div style="display:flex;justify-content:space-between;padding:3px 0"><span style="color:var(--text-muted)">Username</span><span>${esc(result.db_user)}</span></div>
                                <div style="display:flex;justify-content:space-between;padding:3px 0"><span style="color:var(--text-muted)">Password</span><span>${esc(result.db_pass)}</span></div>
                                <div style="display:flex;justify-content:space-between;padding:3px 0"><span style="color:var(--text-muted)">Host</span><span>localhost</span></div>
                            </div>
                        `, () => { closeModal(); });
                    } else {
                        toast(msg);
                    }
                } catch (e) {
                    toast('Installation failed: ' + e.message, 'error');
                    btn.textContent = 'Save';
                    btn.disabled = false;
                }
            });
        });
    };

    // ─── Websites ───

    let _dnsCache = null;
    let _selectedDnsDomain = null;

    async function renderWebsites(el) {
        const domains = await api('/domains');
        try { _dnsCache = await api('/dns/records'); } catch { _dnsCache = { domains: [], records: [], nameservers: [] }; }

        const nameservers = _dnsCache?.nameservers?.filter(n => n) || [];

        if (_selectedDnsDomain) {
            // Show DNS records + subdomains for the selected domain.
            // Subdomains come from DA's CMD_API_SUBDOMAINS endpoint
            // (returns []/error for native services); we render the
            // section optimistically and only show it when DA actually
            // returned a list (or empty). Parent record list is the
            // existing _dnsCache filter — same fetch as before.
            const records = (_dnsCache?.records || []).filter(r => r.domain === _selectedDnsDomain);
            let subdomains = null;
            try {
                subdomains = await api('/subdomains?domain=' + encodeURIComponent(_selectedDnsDomain));
            } catch (_) {
                subdomains = null; // native or error — hide section
            }
            el.innerHTML = `
                <div style="margin-bottom:16px">
                    <button class="btn btn-sm" onclick="portalBackToDomains()" style="margin-bottom:12px">&larr; Back to Domains</button>
                    <h2 style="font-size:18px;font-weight:700;margin:0">${esc(_selectedDnsDomain)}</h2>
                    <p style="font-size:13px;color:var(--text-muted)">DNS Records${subdomains !== null ? ' &amp; Subdomains' : ''}</p>
                </div>

                ${nameservers.length > 0 ? `
                    <div class="card" style="margin-bottom:16px;border-left:3px solid var(--accent)">
                        <p style="font-size:12px;color:var(--text-secondary);margin:0">Point <strong>${esc(_selectedDnsDomain)}</strong> to these nameservers:</p>
                        <div style="display:flex;gap:16px;margin-top:8px;">
                            <code style="font-weight:700">${esc(nameservers[0] || '')}</code>
                            ${nameservers[1] ? `<code style="font-weight:700">${esc(nameservers[1])}</code>` : ''}
                        </div>
                    </div>
                ` : ''}

                ${subdomains !== null ? `
                    <div class="card" style="margin-bottom:16px">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                            <h3 style="margin:0;font-size:14px;font-weight:600">${subdomains.length} Subdomain${subdomains.length !== 1 ? 's' : ''}</h3>
                            <button class="btn btn-primary btn-sm" onclick="portalAddSubdomain('${esc(_selectedDnsDomain)}')">+ Add Subdomain</button>
                        </div>
                        ${subdomains.length === 0
                            ? '<div class="empty-state"><span class="empty-icon">🌐</span><div class="empty-text">No subdomains. Add one to host content at <code>label.' + esc(_selectedDnsDomain) + '</code>.</div></div>'
                            : `<table class="data-table" style="font-size:12px">
                                <thead><tr><th>Subdomain</th><th>FQDN</th><th></th></tr></thead>
                                <tbody>${subdomains.map(s => `
                                    <tr>
                                        <td><code>${esc(s.name)}</code></td>
                                        <td><code>${esc(s.fqdn)}</code></td>
                                        <td><button class="btn btn-sm btn-danger" onclick="portalDelSubdomain('${esc(_selectedDnsDomain)}','${esc(s.name)}')">Del</button></td>
                                    </tr>
                                `).join('')}</tbody>
                            </table>`
                        }
                    </div>
                ` : ''}

                <div class="card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                        <h3 style="margin:0;font-size:14px;font-weight:600">${records.length} DNS Record${records.length !== 1 ? 's' : ''}</h3>
                        <button class="btn btn-primary btn-sm" onclick="portalAddDnsRecord()">+ Add Record</button>
                    </div>
                    ${records.length === 0
                        ? '<div class="empty-state"><span class="empty-icon">📋</span><div class="empty-text">No DNS records yet</div></div>'
                        : `<table class="data-table" style="font-size:12px">
                            <thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th></th></tr></thead>
                            <tbody>${records.map(r => `
                                <tr>
                                    <td><code>${esc((r.name || '').replace(/\.$/, ''))}</code></td>
                                    <td><strong>${esc(r.type)}</strong></td>
                                    <td style="max-width:250px;word-break:break-all">${esc(r.content)}</td>
                                    <td>${r.ttl || 3600}</td>
                                    <td>${r.type !== 'SOA' && r.type !== 'NS' ? `
                                        <button class="btn btn-sm" onclick="portalEditDnsRecord('${esc(r.domain)}','${esc(r.name)}','${esc(r.type)}','${esc(r.content)}',${r.ttl || 3600})">Edit</button>
                                        <button class="btn btn-sm btn-danger" onclick="portalDelDnsRecord('${esc(r.domain)}','${esc(r.name)}','${esc(r.type)}','${esc(r.content)}')">Del</button>
                                    ` : ''}</td>
                                </tr>
                            `).join('')}</tbody>
                        </table>`
                    }
                </div>
            `;
            return;
        }

        // Show domain list with click-through to DNS
        el.innerHTML = `
            <div class="card-header" style="margin-bottom:16px">
                <h3>Your Domains (${domains.length})</h3>
                <button class="btn btn-primary" onclick="portalAddDomain()">+ Add Domain</button>
            </div>

            ${nameservers.length > 0 ? `
                <div class="card" style="margin-bottom:16px;border-left:3px solid var(--accent)">
                    <h3 style="margin-bottom:8px;font-size:14px;font-weight:600">Nameserver Setup</h3>
                    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">Point your domains to these nameservers at your registrar:</p>
                    <div style="display:flex;gap:16px;">
                        <code style="font-weight:700;font-size:14px">${esc(nameservers[0] || '')}</code>
                        ${nameservers[1] ? `<code style="font-weight:700;font-size:14px">${esc(nameservers[1])}</code>` : ''}
                    </div>
                </div>
            ` : ''}

            <div class="card">
                ${domains.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">🌍</span><div class="empty-text">No domains added yet</div></div>'
                    : domains.map(d => `
                        <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;" onclick="portalSelectDomain('${esc(d.name)}')" onmouseover="this.style.background='var(--bg-hover)'" onmouseout="this.style.background=''">
                            <div>
                                <div style="font-weight:600;font-size:14px">${esc(d.name)}</div>
                                <div style="font-size:12px;color:var(--text-muted)">${esc(d.domain_type)} &middot; ${esc(d.document_root || '')}</div>
                            </div>
                            <div style="display:flex;gap:8px;align-items:center">
                                ${badge(d.status)}
                                <span style="font-size:12px;color:var(--text-muted)">DNS &rarr;</span>
                            </div>
                        </div>
                    `).join('')
                }
            </div>
        `;
    }

    window.portalSelectDomain = function(domain) {
        _selectedDnsDomain = domain;
        portalView('websites');
    };

    window.portalBackToDomains = function() {
        _selectedDnsDomain = null;
        portalView('websites');
    };

    window.portalAddDnsRecord = function() {
        const domain = _selectedDnsDomain || '';
        showModal('Add DNS Record', `
            <div class="form-group"><label>Domain</label><input class="form-input" id="p-dns-domain" value="${esc(domain)}" readonly style="opacity:0.7"></div>
            <div class="form-row">
                <div class="form-group"><label>Name</label><input class="form-input" id="p-dns-name" placeholder="@ or subdomain (e.g. www, mail)"></div>
                <div class="form-group"><label>Type</label><select class="form-select" id="p-dns-type"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>SRV</option><option>CAA</option><option>NS</option><option>PTR</option></select></div>
            </div>
            <div class="form-group"><label>Value</label><input class="form-input" id="p-dns-content" placeholder="1.2.3.4"></div>
            <div class="form-group"><label>TTL</label><input class="form-input" type="number" id="p-dns-ttl" value="3600"></div>
        `, async () => {
            await api('/dns/records', { method: 'PUT', body: {
                domain: document.getElementById('p-dns-domain').value,
                name: document.getElementById('p-dns-name').value,
                type: document.getElementById('p-dns-type').value,
                content: document.getElementById('p-dns-content').value,
                ttl: parseInt(document.getElementById('p-dns-ttl').value) || 3600,
            }});
            toast('DNS record added');
            closeModal();
            _dnsCache = null; // force refresh
            portalView('websites');
        });
    };

    window.portalEditDnsRecord = function(domain, name, rtype, content, ttl) {
        const shortName = name.replace(/\.$/, '').replace(new RegExp('\\.?' + domain.replace(/\./g, '\\.') + '$'), '') || '@';
        showModal('Edit DNS Record', `
            <div class="form-group"><label>Domain</label><input class="form-input" value="${esc(domain)}" readonly style="opacity:0.7"></div>
            <div class="form-row">
                <div class="form-group"><label>Name</label><input class="form-input" id="p-edns-name" value="${esc(shortName)}"></div>
                <div class="form-group"><label>Type</label><select class="form-select" id="p-edns-type">
                    ${['A','AAAA','CNAME','MX','TXT','SRV','CAA','NS','PTR'].map(t => `<option${t===rtype?' selected':''}>${t}</option>`).join('')}
                </select></div>
            </div>
            <div class="form-group"><label>Value</label><input class="form-input" id="p-edns-content" value="${esc(content)}"></div>
            <div class="form-group"><label>TTL</label><input class="form-input" type="number" id="p-edns-ttl" value="${ttl}"></div>
        `, async () => {
            // Delete old record then create new one
            try {
                await api('/dns/records', { method: 'DELETE', body: { domain, name, type: rtype, content } });
            } catch(e) { /* old record may not exist if type changed */ }
            await api('/dns/records', { method: 'PUT', body: {
                domain,
                name: document.getElementById('p-edns-name').value,
                type: document.getElementById('p-edns-type').value,
                content: document.getElementById('p-edns-content').value,
                ttl: parseInt(document.getElementById('p-edns-ttl').value) || 3600,
            }});
            toast('DNS record updated');
            closeModal();
            _dnsCache = null;
            portalView('websites');
        });
    };

    window.portalDelDnsRecord = async function(domain, name, rtype, content) {
        showConfirm('Delete DNS Record', `Delete <strong>${esc(rtype)}</strong> record for <strong>${esc(name)}</strong>?`, async () => {
            await api('/dns/records', { method: 'DELETE', body: { domain, name, type: rtype, content: content || '' } });
            toast('DNS record deleted');
            _dnsCache = null;
            portalView('websites');
        });
    };

    window.portalAddSubdomain = function(parent) {
        showModal('Add Subdomain', `
            <div class="form-group"><label>Parent Domain</label><input class="form-input" value="${esc(parent)}" readonly style="opacity:0.7"></div>
            <div class="form-group">
                <label>Subdomain Label</label>
                <input class="form-input" id="p-sub-label" placeholder="e.g. dev, staging, blog">
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">A single label only — no dots. The full hostname will be <code>label.${esc(parent)}</code>.</div>
            </div>
        `, async () => {
            const label = (document.getElementById('p-sub-label').value || '').trim();
            if (!label) { toast('Subdomain label is required', 'error'); return; }
            await api('/subdomains', { method: 'POST', body: { domain: parent, subdomain: label } });
            toast(`Subdomain ${label}.${parent} created`);
            closeModal();
            portalView('websites');
        });
    };

    window.portalDelSubdomain = function(parent, label) {
        showConfirm('Delete Subdomain', `Delete <strong>${esc(label)}.${esc(parent)}</strong>? Files under this subdomain will be removed.`, async () => {
            await api('/subdomains', { method: 'DELETE', body: { domain: parent, subdomain: label } });
            toast('Subdomain deleted');
            portalView('websites');
        });
    };

    window.portalAddDomain = function() {
        const services = dashboardData?.services || [];
        const opts = services.map(s => `<option value="${s.id}">${esc(s.domain || s.plan)}</option>`).join('');
        showModal('Add Domain', `
            <div class="form-group"><label>Service</label><select class="form-select" id="p-d-svc">${opts}</select></div>
            <div class="form-group"><label>Domain Name</label><input class="form-input" id="p-d-name" placeholder="example.com"></div>
            <div class="form-group"><label>Type</label><select class="form-select" id="p-d-type"><option value="addon">Addon Domain</option><option value="subdomain">Subdomain</option></select></div>
        `, async () => {
            await api('/domains', { method: 'POST', body: {
                service_id: document.getElementById('p-d-svc').value,
                name: document.getElementById('p-d-name').value,
                domain_type: document.getElementById('p-d-type').value,
            }});
            toast('Domain added');
            closeModal();
            portalView('websites');
        });
    };

    window.portalDeleteDomain = async function(id) {
        showConfirm('Delete Domain', 'Are you sure you want to delete this domain?', async () => {
            await api(`/domains/${id}`, { method: 'DELETE' });
            toast('Domain deleted');
            portalView('websites');
        });
    };

    // ─── FTP ───

    async function renderFtp(el) {
        const accounts = await api('/ftp-accounts');
        el.innerHTML = `
            <div class="card-header" style="margin-bottom:16px">
                <h3>FTP Accounts (${accounts.length})</h3>
                <button class="btn btn-primary" onclick="portalAddFtp()">+ Create FTP Account</button>
            </div>
            <div class="card">
                ${accounts.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">📁</span><div class="empty-text">No FTP accounts yet</div></div>'
                    : `<table class="data-table">
                        <thead><tr><th>Username</th><th>Home Directory</th><th>Quota</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>${accounts.map(a => `
                            <tr>
                                <td><strong>${esc(a.username)}</strong></td>
                                <td><code style="font-size:12px;color:var(--text-muted)">${esc(a.home_dir)}</code></td>
                                <td>${a.quota_mb} MB</td>
                                <td>${badge(a.status)}</td>
                                <td><button class="btn btn-sm btn-danger" onclick="portalDeleteFtp('${a.id}')">Delete</button></td>
                            </tr>
                        `).join('')}</tbody>
                    </table>`
                }
            </div>
            ${accounts.length > 0 ? `
                <div class="card" style="margin-top:16px">
                    <h3 style="margin-bottom:12px;font-size:14px;font-weight:600">Connection Details</h3>
                    ${(dashboardData?.services || []).map(s => s.host_ip ? `
                        <div class="info-box" style="margin-bottom:8px">
                            <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px">${esc(s.domain || 'Service')}</div>
                            <div class="info-row"><span class="info-label">Host</span><span class="info-value">${esc(s.host_ip)}</span></div>
                            <div class="info-row"><span class="info-label">Port</span><span class="info-value">${s.ftp_port || 21}</span></div>
                            <div class="info-row"><span class="info-label">Username</span><span class="info-value">webmaster</span></div>
                            <div class="info-row"><span class="info-label">Protocol</span><span class="info-value">FTP / FTPS</span></div>
                        </div>
                    ` : '').join('') || '<div class="info-box"><div class="info-row"><span class="info-label">Host</span><span class="info-value">' + location.hostname + '</span></div><div class="info-row"><span class="info-label">Port</span><span class="info-value">21</span></div></div>'}
                </div>
            ` : ''}
        `;
    }

    window.portalAddFtp = function() {
        const services = dashboardData?.services || [];
        const opts = services.map(s => `<option value="${s.id}">${esc(s.domain || s.plan)}</option>`).join('');
        showModal('Create FTP Account', `
            <div class="form-group"><label>Service</label><select class="form-select" id="p-f-svc">${opts}</select></div>
            <div class="form-group"><label>Username</label><input class="form-input" id="p-f-user" placeholder="ftp_user"></div>
            <div class="form-group"><label>Password</label><input class="form-input" type="password" id="p-f-pass"></div>
            <div class="form-group"><label>Quota (MB)</label><input class="form-input" type="number" id="p-f-quota" value="1024"></div>
        `, async () => {
            await api('/ftp-accounts', { method: 'POST', body: {
                service_id: document.getElementById('p-f-svc').value,
                username: document.getElementById('p-f-user').value,
                password: document.getElementById('p-f-pass').value,
                quota_mb: parseInt(document.getElementById('p-f-quota').value) || 1024,
            }});
            toast('FTP account created');
            closeModal();
            portalView('ftp');
        });
    };

    window.portalDeleteFtp = async function(id) {
        showConfirm('Delete FTP Account', 'Are you sure you want to delete this FTP account?', async () => {
            await api(`/ftp-accounts/${id}`, { method: 'DELETE' });
            toast('FTP account deleted');
            portalView('ftp');
        });
    };

    // ─── SSL ───

    async function renderSsl(el) {
        const certs = await api('/certificates');
        const services = dashboardData?.services || [];

        // DNS instructions
        const dnsHtml = services.filter(s => s.host_ip).map(s => `
            <div class="info-box" style="margin-bottom:8px">
                <div style="font-size:12px;font-weight:600;margin-bottom:6px">${esc(s.domain || 'Service')}</div>
                <div class="info-row"><span class="info-label">Point A record to</span><span class="info-value">${esc(s.host_ip)}</span></div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Your domain must resolve to this IP before SSL can be issued.</div>
            </div>
        `).join('');

        el.innerHTML = `
            ${dnsHtml ? `<div class="card" style="margin-bottom:16px"><h3 style="margin-bottom:12px;font-size:14px;font-weight:600">DNS Setup Required</h3>${dnsHtml}</div>` : ''}
            <div class="card-header" style="margin-bottom:16px">
                <h3>SSL Certificates (${certs.length})</h3>
                <div style="display:flex;gap:8px">
                    <button class="btn" onclick="portalUploadSsl()" title="Paste a certificate you obtained elsewhere (e.g. a wildcard, an EV cert, or one from your registrar)">Upload Custom</button>
                    <button class="btn btn-primary" onclick="portalRequestSsl()">+ Request Certificate</button>
                </div>
            </div>
            <div class="card">
                ${certs.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">🔒</span><div class="empty-text">No SSL certificates. Set up your DNS first, then request a free Let\'s Encrypt certificate.</div></div>'
                    : `<table class="data-table">
                        <thead><tr><th>Domain</th><th>Type</th><th>Status</th><th>Expires</th><th>Auto Renew</th><th>Actions</th></tr></thead>
                        <tbody>${certs.map(c => `
                            <tr>
                                <td><strong>${esc(c.domain)}</strong>${c.ssl_live ? '<div style="font-size:11px;color:var(--success)">HTTPS active</div>' : ''}</td>
                                <td>${esc(c.cert_type)}</td>
                                <td>${badge(c.status)}</td>
                                <td>${fmtDate(c.expires_at) || '—'}</td>
                                <td>${c.auto_renew ? '<span style="color:var(--success)">Yes</span>' : '<span style="color:var(--text-muted)">No</span>'}</td>
                                <td>
                                    <button class="btn btn-sm" onclick="portalRenewSsl('${c.id}')">Renew</button>
                                    <button class="btn btn-sm btn-danger" onclick="portalDeleteSsl('${esc(c.service_id || '')}','${esc(c.domain)}')" title="Remove this certificate">Del</button>
                                </td>
                            </tr>
                        `).join('')}</tbody>
                    </table>`
                }
            </div>
        `;
    }

    window.portalUploadSsl = function() {
        // DA services proxy the upload to DirectAdmin; native services
        // install the PEM into their container — both work now.
        const services = (dashboardData?.services || []).filter(s =>
            (s.backend || '').toLowerCase() === 'directadmin' || s.container_name);
        if (services.length === 0) {
            toast('Custom certificate upload needs a provisioned hosting service', 'error');
            return;
        }
        const opts = services.map(s => `<option value="${s.id}">${esc(s.domain || s.plan)}</option>`).join('');
        showModal('Upload Custom SSL Certificate', `
            <div class="form-group"><label>Service</label><select class="form-select" id="p-ssl-up-svc">${opts}</select></div>
            <div class="form-group"><label>Domain</label><input class="form-input" id="p-ssl-up-domain" placeholder="example.com"></div>
            <div class="form-group">
                <label>Certificate (PEM)</label>
                <textarea class="form-textarea" id="p-ssl-up-cert" rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;MII...&#10;-----END CERTIFICATE-----" style="font-family:monospace;font-size:11px"></textarea>
            </div>
            <div class="form-group">
                <label>Private Key (PEM)</label>
                <textarea class="form-textarea" id="p-ssl-up-key" rows="6" placeholder="-----BEGIN PRIVATE KEY-----&#10;MII...&#10;-----END PRIVATE KEY-----" style="font-family:monospace;font-size:11px"></textarea>
            </div>
            <div class="form-group">
                <label>CA Bundle / Intermediate Chain (optional, PEM)</label>
                <textarea class="form-textarea" id="p-ssl-up-ca" rows="4" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" style="font-family:monospace;font-size:11px"></textarea>
            </div>
            <div style="font-size:11px;color:var(--text-muted)">The certificate is sent directly to DirectAdmin. The private key is never stored here.</div>
        `, async () => {
            const cert = document.getElementById('p-ssl-up-cert').value.trim();
            const key = document.getElementById('p-ssl-up-key').value.trim();
            if (!cert || !key) { toast('Certificate and private key are required', 'error'); return; }
            await api('/certificates/upload', { method: 'POST', body: {
                service_id: document.getElementById('p-ssl-up-svc').value,
                domain: document.getElementById('p-ssl-up-domain').value,
                certificate_pem: cert,
                private_key_pem: key,
                ca_bundle_pem: document.getElementById('p-ssl-up-ca').value.trim(),
            }});
            toast('Certificate uploaded');
            closeModal();
            portalView('ssl');
        });
    };

    window.portalDeleteSsl = function(serviceId, domain) {
        if (!serviceId) {
            toast('This certificate has no service mapping — renew or contact support', 'error');
            return;
        }
        showConfirm('Remove SSL Certificate', `Remove the active certificate for <strong>${esc(domain)}</strong>? Visitors will fall back to HTTP until a new certificate is issued.`, async () => {
            await api('/certificates', { method: 'DELETE', body: { service_id: serviceId, domain } });
            toast('Certificate removed');
            portalView('ssl');
        });
    };

    window.portalRequestSsl = function() {
        const services = dashboardData?.services || [];
        const opts = services.map(s => `<option value="${s.id}">${esc(s.domain || s.plan)}</option>`).join('');
        showModal('Request SSL Certificate', `
            <div class="form-group"><label>Service</label><select class="form-select" id="p-ssl-svc">${opts}</select></div>
            <div class="form-group"><label>Domain</label><input class="form-input" id="p-ssl-domain" placeholder="example.com"></div>
            <div class="form-group"><label>Type</label><select class="form-select" id="p-ssl-type"><option value="letsencrypt">Let's Encrypt (Free)</option><option value="custom">Custom Certificate</option></select></div>
        `, async () => {
            await api('/certificates', { method: 'POST', body: {
                service_id: document.getElementById('p-ssl-svc').value,
                domain: document.getElementById('p-ssl-domain').value,
                cert_type: document.getElementById('p-ssl-type').value,
            }});
            toast('SSL certificate requested');
            closeModal();
            portalView('ssl');
        });
    };

    window.portalRenewSsl = async function(id) {
        await api(`/certificates/${id}/renew`, { method: 'POST' });
        toast('Renewal requested');
        portalView('ssl');
    };

    // ─── Databases ───

    async function renderDatabases(el) {
        const dbs = await api('/databases');
        el.innerHTML = `
            <div class="card-header" style="margin-bottom:16px">
                <h3>Databases (${dbs.length})</h3>
                <button class="btn btn-primary" onclick="portalCreateDb()">+ Create Database</button>
            </div>
            <div class="card">
                ${dbs.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">🗃️</span><div class="empty-text">No databases yet</div></div>'
                    : `<table class="data-table">
                        <thead><tr><th>Database</th><th>Type</th><th>Username</th><th>Size</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>${dbs.map(d => `
                            <tr>
                                <td><strong>${esc(d.name)}</strong></td>
                                <td>${esc(d.db_type)}</td>
                                <td><code style="font-size:12px">${esc(d.username)}</code></td>
                                <td>${d.size_mb} MB</td>
                                <td>${badge(d.status)}</td>
                                <td><button class="btn btn-sm btn-danger" onclick="portalDeleteDb('${d.id}')">Delete</button></td>
                            </tr>
                        `).join('')}</tbody>
                    </table>`
                }
            </div>
            ${dbs.length > 0 ? `
                <div class="card" style="margin-top:16px">
                    <h3 style="margin-bottom:12px;font-size:14px;font-weight:600">Connection Details</h3>
                    <div class="info-box">
                        <div class="info-row"><span class="info-label">Host</span><span class="info-value">localhost</span></div>
                        <div class="info-row"><span class="info-label">MariaDB Port</span><span class="info-value">3306</span></div>
                        <div class="info-row"><span class="info-label">PostgreSQL Port</span><span class="info-value">5432</span></div>
                    </div>
                </div>
            ` : ''}
        `;
    }

    window.portalCreateDb = function() {
        const services = dashboardData?.services || [];
        const opts = services.map(s => `<option value="${s.id}" data-backend="${esc(s.backend || 'native')}" data-da-user="${esc(s.da_username || '')}">${esc(s.domain || s.plan || s.id)} ${s.backend === 'directadmin' ? '(DA)' : '(Native)'}</option>`).join('');
        showModal('Create Database', `
            <div class="form-group"><label>Service</label><select class="form-select" id="p-db-svc" onchange="portalDbPrefixHint()">${opts}</select></div>
            <div class="form-group">
                <label>Database Name</label>
                <div style="display:flex;align-items:center;gap:0;">
                    <span id="p-db-prefix" style="background:var(--bg-input);border:1px solid var(--border);border-right:0;border-radius:var(--radius-sm) 0 0 var(--radius-sm);padding:12px 14px;font-size:13px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;"></span>
                    <input class="form-input" id="p-db-name" placeholder="wordpress" style="border-top-left-radius:0;border-bottom-left-radius:0;">
                </div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">DirectAdmin requires a per-account prefix on every database. The grey prefix is added automatically.</div>
            </div>
            <div class="form-group"><label>Type</label><select class="form-select" id="p-db-type"></select><div id="p-db-type-hint" style="font-size:11px;color:var(--text-muted);margin-top:4px;"></div></div>
            <div class="form-group">
                <label>Username</label>
                <div style="display:flex;align-items:center;gap:0;">
                    <span id="p-db-uprefix" style="background:var(--bg-input);border:1px solid var(--border);border-right:0;border-radius:var(--radius-sm) 0 0 var(--radius-sm);padding:12px 14px;font-size:13px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;"></span>
                    <input class="form-input" id="p-db-user" placeholder="user" style="border-top-left-radius:0;border-bottom-left-radius:0;">
                </div>
            </div>
            <div class="form-group"><label>Password</label><input class="form-input" type="password" id="p-db-pass"></div>
        `, async () => {
            await api('/databases', { method: 'POST', body: {
                service_id: document.getElementById('p-db-svc').value,
                name: document.getElementById('p-db-name').value,
                db_type: document.getElementById('p-db-type').value,
                username: document.getElementById('p-db-user').value,
                password: document.getElementById('p-db-pass').value,
            }});
            toast('Database created');
            closeModal();
            portalView('databases');
        });
        portalDbPrefixHint();
    };

    window.portalDbPrefixHint = function() {
        const sel = document.getElementById('p-db-svc');
        if (!sel) return;
        const opt = sel.options[sel.selectedIndex];
        const isDa = opt.getAttribute('data-backend') === 'directadmin';
        const daUser = opt.getAttribute('data-da-user') || '';
        const prefix = isDa && daUser ? `${daUser}_` : '';
        const pEl = document.getElementById('p-db-prefix');
        const uEl = document.getElementById('p-db-uprefix');
        if (pEl) { pEl.textContent = prefix; pEl.style.display = prefix ? '' : 'none'; }
        if (uEl) { uEl.textContent = prefix; uEl.style.display = prefix ? '' : 'none'; }

        // DA only supports MySQL/MariaDB for customer accounts —
        // PostgreSQL via DA's customer API is essentially never
        // wired. Hide the option entirely for DA services so the
        // customer can't pick a path that's destined to fail. For
        // native services both backends are real.
        const tEl = document.getElementById('p-db-type');
        const tHint = document.getElementById('p-db-type-hint');
        if (tEl) {
            if (isDa) {
                tEl.innerHTML = '<option value="mariadb">MariaDB</option>';
                if (tHint) tHint.textContent = 'DirectAdmin only supports MariaDB / MySQL for customer accounts.';
            } else {
                tEl.innerHTML = '<option value="mariadb">MariaDB</option><option value="postgresql">PostgreSQL</option>';
                if (tHint) tHint.textContent = '';
            }
        }
    };

    window.portalDeleteDb = async function(id) {
        showConfirm('Delete Database', 'Are you sure? <strong>All data will be permanently lost.</strong>', async () => {
            await api(`/databases/${id}`, { method: 'DELETE' });
            toast('Database deleted');
            portalView('databases');
        });
    };

    // ─── Email ───

    async function renderEmail(el) {
        const data = await api('/email-accounts');
        const accounts = data.accounts || [];
        const emailServices = data.services || [];

        // Check if any service needs mail setup
        const needsSetup = emailServices.filter(s => s.email_ready && s.container_name);
        const firstSvc = needsSetup[0];

        // Try to load DNS records for first service
        let dnsData = null;
        if (firstSvc) {
            try { dnsData = await api(`/email-dns/${firstSvc.service_id}`); } catch {}
        }

        el.innerHTML = `
            ${firstSvc ? `
                <div class="card" style="margin-bottom:16px">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                        <h3 style="margin:0;font-size:15px;font-weight:600">Email Hosting Setup</h3>
                        <button class="btn btn-primary btn-sm" onclick="portalSetupMail('${esc(firstSvc.service_id)}')">Enable Email Hosting</button>
                    </div>
                    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">Click "Enable Email Hosting" to install the mail server (Postfix + Dovecot + DKIM) on your container. Then set up the DNS records below.</p>
                </div>
            ` : ''}

            ${dnsData ? `
                <div class="card" style="margin-bottom:16px;border-left:3px solid var(--info);border-color:var(--info)">
                    <h3 style="margin-bottom:12px;font-size:14px;font-weight:600">Required DNS Records for ${esc(dnsData.domain)}</h3>
                    <p style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">Add these records at your domain registrar for email to work correctly:</p>
                    <table class="data-table" style="font-size:12px">
                        <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Purpose</th></tr></thead>
                        <tbody>${dnsData.records.map(r => `
                            <tr>
                                <td><strong>${esc(r.type)}</strong></td>
                                <td><code>${esc(r.name)}</code></td>
                                <td><code style="word-break:break-all;max-width:300px;display:inline-block">${esc(typeof r.value === 'string' ? r.value : JSON.stringify(r.value))}</code>${r.priority ? ` (priority: ${r.priority})` : ''}</td>
                                <td style="color:var(--text-muted)">${esc(r.description)}</td>
                            </tr>
                        `).join('')}</tbody>
                    </table>
                </div>

                <div class="card" style="margin-bottom:16px">
                    <h3 style="margin-bottom:12px;font-size:14px;font-weight:600">Mail Client Settings</h3>
                    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
                        <div class="info-box">
                            <div style="font-size:12px;font-weight:600;margin-bottom:6px;color:var(--text-secondary)">Incoming (IMAP)</div>
                            <div class="info-row"><span class="info-label">Server</span><span class="info-value">${esc(dnsData.imap.host)}</span></div>
                            <div class="info-row"><span class="info-label">Port</span><span class="info-value">${dnsData.imap.port}</span></div>
                            <div class="info-row"><span class="info-label">Security</span><span class="info-value">${esc(dnsData.imap.encryption)}</span></div>
                        </div>
                        <div class="info-box">
                            <div style="font-size:12px;font-weight:600;margin-bottom:6px;color:var(--text-secondary)">Outgoing (SMTP)</div>
                            <div class="info-row"><span class="info-label">Server</span><span class="info-value">${esc(dnsData.smtp.host)}</span></div>
                            <div class="info-row"><span class="info-label">Port</span><span class="info-value">${dnsData.smtp.port}</span></div>
                            <div class="info-row"><span class="info-label">Security</span><span class="info-value">${esc(dnsData.smtp.encryption)}</span></div>
                        </div>
                        <div class="info-box">
                            <div style="font-size:12px;font-weight:600;margin-bottom:6px;color:var(--text-secondary)">POP3 (alternative)</div>
                            <div class="info-row"><span class="info-label">Server</span><span class="info-value">${esc(dnsData.pop3.host)}</span></div>
                            <div class="info-row"><span class="info-label">Port</span><span class="info-value">${dnsData.pop3.port}</span></div>
                            <div class="info-row"><span class="info-label">Security</span><span class="info-value">${esc(dnsData.pop3.encryption)}</span></div>
                        </div>
                    </div>
                </div>
            ` : ''}

            <div class="card-header" style="margin-bottom:16px">
                <h3>Email Accounts (${accounts.length})</h3>
                <button class="btn btn-primary" onclick="portalCreateEmail()">+ Create Email</button>
            </div>
            <div class="card">
                ${accounts.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">📧</span><div class="empty-text">No email accounts yet. Enable email hosting first, then create accounts.</div></div>'
                    : `<table class="data-table">
                        <thead><tr><th>Email Address</th><th>Quota</th><th>Forwarding</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>${accounts.map(a => `
                            <tr>
                                <td><strong>${esc(a.address)}</strong></td>
                                <td>${a.quota_mb} MB</td>
                                <td>${(a.forwarding || []).length > 0 ? esc(a.forwarding.join(', ')) : '<span style="color:var(--text-muted)">None</span>'}</td>
                                <td>${badge(a.status)}</td>
                                <td><button class="btn btn-sm btn-danger" onclick="portalDeleteEmail('${a.id}')">Delete</button></td>
                            </tr>
                        `).join('')}</tbody>
                    </table>`
                }
            </div>
        `;
    }

    window.portalSetupMail = async function(serviceId) {
        showConfirm('Enable Email Hosting', 'Install mail server (Postfix + Dovecot + DKIM) on your container? This takes 1-2 minutes.', async () => {
            const result = await api('/email-setup', { method: 'POST', body: { service_id: serviceId } });
            toast(result.message || 'Email server is being installed...');
            setTimeout(() => portalView('email'), 3000);
        });
    };

    window.portalCreateEmail = async function() {
        // Show domain (not just service name) so the customer knows
        // which side of the @ they'll get. Pull the live domain
        // list (DA + native) so addon domains appear too — the
        // service.domain field is just the primary.
        const services = dashboardData?.services || [];
        let allDomains = [];
        try {
            const dnsResp = await api('/dns/records');
            allDomains = (dnsResp.domains || []).filter(Boolean);
        } catch (_) {
            allDomains = services.map(s => s.domain).filter(Boolean);
        }
        if (allDomains.length === 0) {
            toast('Add a domain before creating an email account', 'error');
            return;
        }
        const svcOpts = services.map(s => `<option value="${s.id}">${esc(s.domain || s.plan || s.id)}</option>`).join('');
        const domOpts = allDomains.map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('');
        showModal('Create Email Account', `
            <div class="form-group"><label>Service</label><select class="form-select" id="p-em-svc">${svcOpts}</select></div>
            <div class="form-row">
                <div class="form-group"><label>Username</label><input class="form-input" id="p-em-user" placeholder="info"></div>
                <div class="form-group"><label>@ Domain</label><select class="form-select" id="p-em-domain">${domOpts}</select></div>
            </div>
            <div class="form-group"><label>Password</label><input class="form-input" type="password" id="p-em-pass"></div>
            <div class="form-group"><label>Quota (MB)</label><input class="form-input" type="number" id="p-em-quota" value="500"></div>
        `, async () => {
            const user = document.getElementById('p-em-user').value.trim();
            const domain = document.getElementById('p-em-domain').value;
            if (!user || !domain) { toast('Username and domain are required', 'error'); return; }
            await api('/email-accounts', { method: 'POST', body: {
                service_id: document.getElementById('p-em-svc').value,
                address: `${user}@${domain}`,
                password: document.getElementById('p-em-pass').value,
                quota_mb: parseInt(document.getElementById('p-em-quota').value) || 500,
            }});
            toast(`Email ${user}@${domain} created`);
            closeModal();
            portalView('email');
        });
    };

    window.portalDeleteEmail = async function(id) {
        showConfirm('Delete Email Account', 'Are you sure you want to delete this email account?', async () => {
            await api(`/email-accounts/${id}`, { method: 'DELETE' });
            toast('Email account deleted');
            portalView('email');
        });
    };

    // ─── Files ───
    //
    // Two-level landing: with no domain selected the page shows
    // a tile per domain. Clicking a tile drops the customer into
    // that domain's web-root (`/domains/<domain>/public_html` for
    // DA-backed services, `/var/www/html` for native), which is
    // where 99% of file-management actually happens. There's a
    // "browse home" escape hatch on each tile for advanced users
    // who genuinely need to poke around `/home/<user>/`.

    let currentFilePath = '';   // '' = show domain landing tiles
    let currentFileService = '';
    let currentFileDomain = ''; // the domain whose root we're inside

    async function renderFiles(el) {
        const services = (dashboardData?.services || []).filter(s => s.container_name || s.backend === 'directadmin');
        if (services.length === 0) {
            el.innerHTML = '<div class="empty-state"><span class="empty-icon">📂</span><div class="empty-text">No services yet. Create one before opening the file manager.</div></div>';
            return;
        }

        // No domain chosen yet → render the picker.
        if (!currentFilePath) {
            return renderFilesDomainPicker(el, services);
        }
        return renderFilesBrowser(el);
    }

    async function renderFilesDomainPicker(el, services) {
        // Pull the live domain list (DA primaries + addons + native
        // primaries) so addon domains get tiles too.
        let allDomains = [];
        try {
            const dnsResp = await api('/dns/records');
            allDomains = (dnsResp.domains || []).filter(Boolean);
        } catch (_) {
            allDomains = services.map(s => s.domain).filter(Boolean);
        }

        // Map each domain to the service that owns it. For DA the
        // primary + every addon belongs to the same DA service;
        // for native each service has one primary domain.
        const domainToService = {};
        for (const d of allDomains) {
            const owner = services.find(s =>
                s.domain === d
                || (s.backend === 'directadmin')  // DA service catches all addons
            );
            if (owner) domainToService[d] = owner;
        }

        const tiles = allDomains.map(d => {
            const svc = domainToService[d];
            if (!svc) return '';
            const isDa = svc.backend === 'directadmin';
            const badge = isDa
                ? '<span style="font-size:10px;background:rgba(99,102,241,0.15);color:#818cf8;padding:2px 6px;border-radius:3px;">DirectAdmin</span>'
                : '<span style="font-size:10px;background:rgba(34,197,94,0.15);color:#4ade80;padding:2px 6px;border-radius:3px;">Native</span>';
            return `<div class="card" style="cursor:pointer;transition:transform 0.15s ease, border-color 0.15s ease;padding:18px;display:flex;flex-direction:column;gap:8px;"
                onclick="portalFileEnterDomain('${esc(svc.id)}','${esc(d)}','${isDa ? 'da' : 'native'}')"
                onmouseover="this.style.borderColor='var(--accent)';this.style.transform='translateY(-1px)';"
                onmouseout="this.style.borderColor='';this.style.transform='';">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                    <div style="font-size:24px;">📁</div>
                    ${badge}
                </div>
                <div style="font-size:15px;font-weight:600;word-break:break-all;">${esc(d)}</div>
                <div style="font-size:11px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;word-break:break-all;">
                    ${isDa ? `/domains/${esc(d)}/public_html` : '/var/www/html'}
                </div>
                <div style="margin-top:auto;font-size:11px;color:var(--accent);">Open files →</div>
            </div>`;
        }).join('');

        el.innerHTML = `
            <div class="card-header" style="margin-bottom:16px">
                <h3>Domain Files</h3>
                <div style="display:flex;gap:8px;align-items:center;">
                    <button class="btn btn-sm" onclick="portalFileEnterHome()" title="Open the account's home directory — ~/mail, ~/backups, ~/.cpanel etc. Advanced.">🏠 Home directory</button>
                </div>
            </div>
            <p style="font-size:13px;color:var(--text-secondary);margin-bottom:16px;">
                Pick a domain to manage its website files. Each tile drops you straight into that domain's web root —
                this is where you upload your <code>index.html</code>, WordPress install, etc.
            </p>
            ${allDomains.length === 0
                ? '<div class="empty-state"><span class="empty-icon">🌍</span><div class="empty-text">No domains yet. Add one from the Websites &amp; Domains tab first.</div></div>'
                : `<div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(260px, 1fr));gap:14px;">${tiles}</div>`
            }
        `;
    }

    function renderFilesBrowser(el) {
        const services = dashboardData?.services || [];
        const svc = services.find(s => s.id === currentFileService);

        // Build breadcrumb. "← Domains" replaces the bare slash so
        // there's a clear way back to the picker.
        const pathParts = currentFilePath.split('/').filter(Boolean);
        let breadcrumb = `<span style="cursor:pointer;color:var(--accent);font-weight:600;" onclick="portalFileBackToDomains()">← Domains</span>`;
        let accumulated = '';
        for (const part of pathParts) {
            accumulated += '/' + part;
            breadcrumb += ` <span style="color:var(--text-muted)">/</span> <span style="cursor:pointer;color:var(--accent)" onclick="portalFileNav('${esc(accumulated)}')">${esc(part)}</span>`;
        }

        const titleBits = [];
        if (currentFileDomain) titleBits.push(esc(currentFileDomain));
        else if (svc) titleBits.push(esc(svc.domain || svc.plan || svc.id));

        el.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:10px">
                <div>
                    <h3 style="margin:0 0 4px;font-size:18px;">${titleBits.join(' · ') || 'Files'}</h3>
                    <div style="font-size:12px;color:var(--text-secondary);">📂 ${breadcrumb}</div>
                </div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    ${currentFilePath && currentFilePath !== '/' ? '<button class="btn btn-sm" onclick="portalFileUp()">⬆ Up</button>' : ''}
                    <button class="btn btn-sm" onclick="portalFileMkdir()">+ Folder</button>
                    <button class="btn btn-sm" onclick="portalFileNew()">+ File</button>
                    <button class="btn btn-sm btn-primary" onclick="portalFileUpload()">⬆ Upload</button>
                </div>
            </div>
            <div class="card" id="p-file-list" style="padding:0;margin-top:12px;">
                <div style="text-align:center;padding:30px;color:var(--text-muted)">Loading...</div>
            </div>
        `;
        loadFileList();
    }

    window.portalFileEnterDomain = function(serviceId, domain, kind) {
        currentFileService = serviceId;
        currentFileDomain = domain;
        currentFilePath = kind === 'da' ? `/domains/${domain}/public_html` : '/var/www/html';
        renderFiles(document.getElementById('content-area'));
    };

    window.portalFileEnterHome = function() {
        // Use the first available service. The customer can switch
        // service later via the picker again. Path '/' is the
        // service home — DA's CMD_API_FILE_MANAGER reads it as
        // `/home/<user>/`; native reads it as the container's `/`.
        const services = (dashboardData?.services || []).filter(s => s.container_name || s.backend === 'directadmin');
        if (services.length === 0) { toast('No services', 'error'); return; }
        currentFileService = services[0].id;
        currentFileDomain = '';
        currentFilePath = '/';
        renderFiles(document.getElementById('content-area'));
    };

    window.portalFileBackToDomains = function() {
        currentFilePath = '';
        currentFileDomain = '';
        // currentFileService kept so re-entering the same domain
        // doesn't have to re-pick the service it implies.
        renderFiles(document.getElementById('content-area'));
    };

    async function loadFileList() {
        try {
            const data = await api(`/files/list?service_id=${currentFileService}&path=${encodeURIComponent(currentFilePath)}`);
            const listEl = document.getElementById('p-file-list');
            if (!listEl) return;

            const files = data.files || [];
            if (files.length === 0) {
                listEl.innerHTML = '<div class="empty-state" style="padding:30px"><span class="empty-icon">📂</span><div class="empty-text">Empty directory</div></div>';
                return;
            }

            listEl.innerHTML = `<table class="data-table" style="font-size:13px">
                <thead><tr><th style="width:24px"></th><th>Name</th><th style="width:80px">Size</th><th style="width:200px">Actions</th></tr></thead>
                <tbody>${files.map(f => {
                    const icon = f.is_dir ? '📁' : (f.is_symlink ? '🔗' : getFileIcon(f.name));
                    const escapedPath = (f.path || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
                    const escapedName = (f.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
                    return `<tr style="cursor:${f.is_dir ? 'pointer' : 'default'}" ${f.is_dir ? `onclick="portalFileNav('${escapedPath}')"` : ''}>
                        <td style="text-align:center">${icon}</td>
                        <td><strong>${esc(f.name)}</strong></td>
                        <td style="color:var(--text-muted)">${f.is_dir ? '—' : fmtSize(f.size)}</td>
                        <td>
                            <div style="display:flex;gap:4px" onclick="event.stopPropagation()">
                                ${!f.is_dir && f.size < 2097152 ? `<button class="btn btn-sm" onclick="portalFileEdit('${escapedPath}','${escapedName}')">Edit</button>` : ''}
                                ${!f.is_dir ? `<button class="btn btn-sm" onclick="portalFileDownload('${escapedPath}')">⬇</button>` : ''}
                                <button class="btn btn-sm" onclick="portalFileRename('${escapedPath}','${escapedName}')">✏️</button>
                                <button class="btn btn-sm btn-danger" onclick="portalFileDelete('${escapedPath}','${escapedName}')">🗑️</button>
                            </div>
                        </td>
                    </tr>`;
                }).join('')}</tbody>
            </table>`;
        } catch (e) {
            const listEl = document.getElementById('p-file-list');
            if (listEl) listEl.innerHTML = `<div class="empty-state" style="padding:20px"><span class="empty-icon">⚠️</span><div class="empty-text">${esc(e.message)}</div></div>`;
        }
    }

    function getFileIcon(name) {
        const ext = (name || '').split('.').pop().toLowerCase();
        const icons = { html:'🌐', htm:'🌐', css:'🎨', js:'⚡', php:'🐘', py:'🐍', rb:'💎', go:'🔷', rs:'🦀', json:'📋', xml:'📋', yml:'📋', yaml:'📋', md:'📝', txt:'📄', conf:'⚙️', cfg:'⚙️', ini:'⚙️', env:'⚙️', sh:'🖥️', bash:'🖥️', jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🖼️', svg:'🖼️', ico:'🖼️', webp:'🖼️', pdf:'📄', zip:'📦', gz:'📦', tar:'📦', sql:'🗃️', log:'📋', htaccess:'🔒' };
        return icons[ext] || '📄';
    }

    window.portalFileService = function(id) {
        currentFileService = id;
        // For DA-backed services, jump straight to the primary
        // domain's public_html rather than the bare `/` (which
        // dumps the customer into `/home/<user>/` with mail spool,
        // backups dir, etc. — confusing for non-technical users).
        const services = dashboardData?.services || [];
        const svc = services.find(s => s.id === id);
        if (svc && svc.backend === 'directadmin' && svc.domain) {
            currentFilePath = `/domains/${svc.domain}/public_html`;
        } else {
            currentFilePath = '/';
        }
        renderFiles(document.getElementById('content-area'));
    };

    window.portalFileNav = function(path) {
        currentFilePath = path;
        renderFiles(document.getElementById('content-area'));
    };

    window.portalFileUp = function() {
        const parts = currentFilePath.split('/').filter(Boolean);
        parts.pop();
        currentFilePath = parts.length > 0 ? '/' + parts.join('/') : '/';
        renderFiles(document.getElementById('content-area'));
    };

    window.portalFileDownload = function(path) {
        window.open(`/api/files/download?service_id=${currentFileService}&path=${encodeURIComponent(path)}`, '_blank');
    };

    window.portalFileDelete = function(path, name) {
        showConfirm('Delete File', `Are you sure you want to delete <strong>${esc(name)}</strong>? This cannot be undone.`, async () => {
            await api('/files/delete', { method: 'POST', body: { service_id: currentFileService, path } });
            toast('Deleted');
            loadFileList();
        });
    };

    window.portalFileRename = function(path, name) {
        showPrompt('Rename', 'New name', name, async (newName) => {
            if (!newName || newName === name) return;
            const dir = path.substring(0, path.lastIndexOf('/'));
            const newPath = dir + '/' + newName;
            await api('/files/rename', { method: 'POST', body: { service_id: currentFileService, from: path, to: newPath } });
            toast('Renamed');
            loadFileList();
        });
    };

    window.portalFileMkdir = function() {
        showPrompt('Create Folder', 'Folder name', '', async (name) => {
            if (!name) return;
            const path = currentFilePath + '/' + name;
            try {
                await api('/files/mkdir', { method: 'POST', body: { service_id: currentFileService, path } });
                toast('Folder created');
                loadFileList();
            } catch (e) { toast('Failed: ' + e.message, 'error'); }
        });
    };

    window.portalFileNew = function() {
        showPrompt('Create File', 'File name (e.g. page.html)', '', async (name) => {
            if (!name) return;
            const path = currentFilePath + '/' + name;
            await api('/files/save', { method: 'POST', body: { service_id: currentFileService, path, content: '' } });
            toast('File created');
            loadFileList();
        });
    };

    window.portalFileUpload = function() {
        showModal('Upload Files', `
            <div style="border:2px dashed var(--border);border-radius:var(--radius);padding:40px 20px;text-align:center;cursor:pointer;transition:border-color 0.2s"
                 id="p-upload-zone"
                 onclick="document.getElementById('p-upload-input').click()"
                 ondragover="event.preventDefault();this.style.borderColor='var(--accent)'"
                 ondragleave="this.style.borderColor='var(--border)'"
                 ondrop="event.preventDefault();this.style.borderColor='var(--border)';portalHandleDrop(event)">
                <div style="font-size:36px;margin-bottom:12px">📤</div>
                <div style="font-size:14px;font-weight:500;margin-bottom:4px">Click to browse or drag files here</div>
                <div style="font-size:12px;color:var(--text-muted)">Upload to: ${esc(currentFilePath)}</div>
                <input type="file" id="p-upload-input" multiple style="display:none" onchange="portalHandleFiles(this.files)">
            </div>
            <div id="p-upload-list" style="margin-top:12px"></div>
            <div id="p-upload-progress" style="display:none;margin-top:12px">
                <div class="usage-bar"><div class="usage-fill" id="p-upload-bar" style="width:0%"></div></div>
                <div style="font-size:12px;color:var(--text-muted);margin-top:4px" id="p-upload-status">Uploading...</div>
            </div>
        `, async () => {
            const input = document.getElementById('p-upload-input');
            if (!input.files.length && !window._portalDroppedFiles?.length) { toast('No files selected', 'error'); return; }
            const files = window._portalDroppedFiles || Array.from(input.files);
            await portalDoUpload(files);
        }, 'Upload');
        window._portalDroppedFiles = null;
    };

    window.portalHandleDrop = function(e) {
        const files = Array.from(e.dataTransfer.files);
        window._portalDroppedFiles = files;
        portalShowFileList(files);
    };

    window.portalHandleFiles = function(fileList) {
        const files = Array.from(fileList);
        window._portalDroppedFiles = files;
        portalShowFileList(files);
    };

    function portalShowFileList(files) {
        const listEl = document.getElementById('p-upload-list');
        if (!listEl) return;
        listEl.innerHTML = files.map(f => `
            <div style="display:flex;justify-content:space-between;padding:6px 0;font-size:13px;border-bottom:1px solid var(--border)">
                <span>${esc(f.name)}</span>
                <span style="color:var(--text-muted)">${fmtSize(f.size)}</span>
            </div>
        `).join('');
    }

    async function portalDoUpload(files) {
        const progress = document.getElementById('p-upload-progress');
        const bar = document.getElementById('p-upload-bar');
        const status = document.getElementById('p-upload-status');
        if (progress) progress.style.display = '';

        let uploaded = 0;
        for (const file of files) {
            if (status) status.textContent = `Uploading ${file.name}... (${uploaded + 1}/${files.length})`;
            if (bar) bar.style.width = `${(uploaded / files.length) * 100}%`;

            try {
                // Use text() for text files, arrayBuffer+base64 for binary
                const isText = /\.(html?|css|js|json|xml|txt|md|php|py|rb|sh|yml|yaml|conf|cfg|ini|env|htaccess|sql|csv|svg|log)$/i.test(file.name);
                let content;
                if (isText) {
                    content = await file.text();
                } else {
                    // Binary: read as base64, we'll need to decode on the server
                    // For now send as text — binary files should use the WolfStack upload API
                    content = await file.text();
                }
                const path = currentFilePath + '/' + file.name;
                await api('/files/save', { method: 'POST', body: { service_id: currentFileService, path, content } });
                uploaded++;
            } catch (e) {
                toast(`Failed to upload ${file.name}`, 'error');
            }
        }
        if (bar) bar.style.width = '100%';
        if (status) status.textContent = `Uploaded ${uploaded} file(s)`;
        toast(`${uploaded} file(s) uploaded`);
        closeModal();
        loadFileList();
        window._portalDroppedFiles = null;
    }

    window.portalFileEdit = async function(path, name) {
        const data = await api(`/files/read?service_id=${currentFileService}&path=${encodeURIComponent(path)}`);
        const content = data.content || '';

        showModal(`Edit: ${name}`, `
            <textarea id="p-file-editor" style="
                width:100%;min-height:400px;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.6;
                background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:var(--radius-sm);
                padding:14px;resize:vertical;tab-size:4;white-space:pre;overflow-wrap:normal;overflow-x:auto;
            ">${esc(content)}</textarea>
            <div style="display:flex;justify-content:space-between;margin-top:8px;font-size:12px;color:var(--text-muted)">
                <span>${esc(path)}</span>
                <span>${content.length} bytes</span>
            </div>
        `, async () => {
            const newContent = document.getElementById('p-file-editor').value;
            await api('/files/save', { method: 'POST', body: { service_id: currentFileService, path, content: newContent } });
            toast('File saved');
            closeModal();
            loadFileList();
        });

        // Tab key inserts spaces
        setTimeout(() => {
            const editor = document.getElementById('p-file-editor');
            if (editor) {
                editor.addEventListener('keydown', function(e) {
                    if (e.key === 'Tab') {
                        e.preventDefault();
                        const s = this.selectionStart, end = this.selectionEnd;
                        this.value = this.value.substring(0, s) + '    ' + this.value.substring(end);
                        this.selectionStart = this.selectionEnd = s + 4;
                    }
                });
            }
        }, 200);
    };

    // ─── Backups ───

    async function renderBackups(el) {
        // Fetch from BOTH endpoints in parallel — `/api/backups` is
        // the LXC/native side, `/api/da-backups` is DirectAdmin
        // SITE_BACKUP files. They merge cleanly because each row
        // carries a `source` tag the action handlers key off.
        const services = dashboardData?.services || [];
        const hasNative = services.some(s => s.container_name);
        const hasDA = services.some(s => s.backend === 'directadmin');
        let backups = [];
        try {
            const [native, daBackups] = await Promise.all([
                hasNative ? api('/backups').catch(() => []) : Promise.resolve([]),
                hasDA ? api('/da-backups').catch(() => []) : Promise.resolve([]),
            ]);
            backups = [
                ...(native || []).map(b => ({ ...b, source: 'native' })),
                ...(daBackups || []).map(b => ({
                    id: `da:${b.filename}`,
                    domain: b.domain || '',
                    filename: b.filename,
                    size_bytes: b.size_bytes || 0,
                    created_at: b.created_at || '',
                    includes_db: true, // DA SITE_BACKUP always includes everything
                    source: 'da',
                })),
            ];
        } catch (e) {
            backups = [];
        }

        if (services.length === 0) {
            el.innerHTML = '<div class="empty-state"><span class="empty-icon">💾</span><div class="empty-text">No services yet. Create one before taking a backup.</div></div>';
            return;
        }

        el.innerHTML = `
            <div class="card-header" style="margin-bottom:16px">
                <h3>Backups (${backups.length})</h3>
                <div style="display:flex;gap:8px">
                    <button class="btn btn-primary" onclick="portalCreateBackup(true)">+ Create Backup</button>
                </div>
            </div>
            <div class="card">
                ${backups.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">💾</span><div class="empty-text">No backups yet. Click "Create Backup" to take your first one.</div></div>'
                    : `<table class="data-table">
                        <thead><tr><th>Source</th><th>Domain</th><th>File</th><th>Size</th><th>Date</th><th>Actions</th></tr></thead>
                        <tbody>${backups.map(b => `
                            <tr>
                                <td><span style="font-size:11px;background:${b.source === 'da' ? 'rgba(99,102,241,0.15)' : 'rgba(34,197,94,0.15)'};color:${b.source === 'da' ? '#818cf8' : '#4ade80'};padding:2px 6px;border-radius:3px;">${b.source === 'da' ? 'DirectAdmin' : 'Native'}</span></td>
                                <td>${esc(b.domain || '—')}</td>
                                <td><code style="font-size:12px">${esc(b.filename)}</code></td>
                                <td>${fmtSize(b.size_bytes)}</td>
                                <td>${b.created_at ? (typeof b.created_at === 'number' ? new Date(b.created_at * 1000).toLocaleString() : esc(b.created_at)) : '—'}</td>
                                <td>
                                    <div style="display:flex;gap:6px">
                                        <button class="btn btn-sm btn-primary" onclick="portalRestore('${esc(b.id)}','${esc(b.source)}','${esc(b.filename)}')">Restore</button>
                                        ${b.source === 'native' ? `<button class="btn btn-sm" onclick="portalDownloadBackup('${esc(b.id)}')">Download</button>` : ''}
                                        <button class="btn btn-sm btn-danger" onclick="portalDeleteBackup('${esc(b.id)}','${esc(b.source)}','${esc(b.filename)}')">Del</button>
                                    </div>
                                </td>
                            </tr>
                        `).join('')}</tbody>
                    </table>`
                }
            </div>
        `;
    }

    window.portalCreateBackup = function(_) {
        const services = dashboardData?.services || [];
        if (services.length === 0) { toast('No services', 'error'); return; }
        const svcOpts = services.map(s => `<option value="${s.id}" data-backend="${esc(s.backend || 'native')}">${esc(s.domain || s.plan || s.id)} ${s.backend === 'directadmin' ? '(DirectAdmin)' : '(Native)'}</option>`).join('');
        showModal('Create Backup', `
            <div class="form-group"><label>Service</label><select class="form-select" id="p-bk-svc">${svcOpts}</select></div>
            <p style="font-size:13px;color:var(--text-secondary)">
                The backup includes website files, databases, email, and DNS settings.
                For DirectAdmin services, DA's <code>SITE_BACKUP</code> archive is created on the source host. For native services, files are tarballed from the container and databases are dumped into the same archive.
            </p>
        `, async () => {
            const sel = document.getElementById('p-bk-svc');
            const service_id = sel.value;
            const backend = sel.options[sel.selectedIndex].getAttribute('data-backend');
            if (backend === 'directadmin') {
                const result = await api('/da-backups/create', { method: 'POST', body: { service_id }});
                toast(result.message || 'DA backup requested — appears under Backups when ready');
            } else {
                const result = await api('/backups/create', { method: 'POST', body: { service_id, include_db: true }});
                toast(result.message || 'Backup started');
            }
            closeModal();
            setTimeout(() => portalView('backups'), 4000);
        });
    };

    window.portalRestore = async function(id, source, filename) {
        showConfirm('Restore Backup', 'Restore this backup? Current files (and database) will be <strong>overwritten</strong>.', async () => {
            if (source === 'da') {
                const services = dashboardData?.services || [];
                const svc = services.find(s => s.backend === 'directadmin');
                if (!svc) { toast('No DA service to restore into', 'error'); return; }
                const result = await api('/da-backups/restore', { method: 'POST', body: { service_id: svc.id, filename }});
                toast(result.message || 'Restore started');
            } else {
                const result = await api(`/backups/${encodeURIComponent(id)}/restore`, { method: 'POST' });
                toast(result.message || 'Restore started');
            }
        });
    };

    window.portalDeleteBackup = function(id, source, filename) {
        showConfirm('Delete Backup', 'Permanently remove this backup? This cannot be undone.', async () => {
            if (source === 'da') {
                const services = dashboardData?.services || [];
                const svc = services.find(s => s.backend === 'directadmin');
                if (!svc) { toast('No DA service', 'error'); return; }
                await api('/da-backups', { method: 'DELETE', body: { service_id: svc.id, filename }});
            } else {
                await api(`/backups/${encodeURIComponent(id)}`, { method: 'DELETE' });
            }
            toast('Backup deleted');
            portalView('backups');
        });
    };

    window.portalDownloadBackup = async function(id) {
        try {
            const resp = await fetch('/api/backups/download', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ backup_id: id }),
            });
            if (!resp.ok) { toast('Download failed', 'error'); return; }
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = id.split(':')[1] || 'backup.tar.gz';
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) { toast('Download failed', 'error'); }
    };

    // ─── Usage ───

    async function renderUsage(el) {
        // Always pull fresh — DA's CMD_API_SHOW_USER_USAGE updates as
        // sites run, and the customer landing on this tab expects to
        // see right-now numbers, not whatever was on the dashboard
        // when they first logged in. Reuse from cache hides genuine
        // server-side updates and makes the page feel broken.
        const d = await api('/dashboard');
        dashboardData = d;
        el.innerHTML = `
            <div class="card" style="margin-bottom:20px">
                <h3 style="margin-bottom:20px;font-size:16px;font-weight:600">Resource Usage Overview</h3>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
                    <div>
                        ${usageMeter(d.disk_used_mb, d.disk_limit_mb, 'Disk Space')}
                        <div style="text-align:center;margin-top:8px">
                            <span style="font-size:32px;font-weight:700">${d.disk_limit_mb > 0 ? Math.round((d.disk_used_mb / d.disk_limit_mb) * 100) : 0}%</span>
                            <div style="font-size:12px;color:var(--text-muted);margin-top:4px">of disk quota used</div>
                        </div>
                    </div>
                    <div>
                        ${usageMeter(d.bandwidth_used_mb, d.bandwidth_limit_mb, 'Bandwidth')}
                        <div style="text-align:center;margin-top:8px">
                            <span style="font-size:32px;font-weight:700">${d.bandwidth_limit_mb > 0 ? Math.round((d.bandwidth_used_mb / d.bandwidth_limit_mb) * 100) : 0}%</span>
                            <div style="font-size:12px;color:var(--text-muted);margin-top:4px">of bandwidth used</div>
                        </div>
                    </div>
                </div>
            </div>
            ${d.services.length > 0 ? `
                <h3 style="margin-bottom:12px;font-size:15px;font-weight:600">Per-Service Breakdown</h3>
                <div class="card" style="padding:0">
                    <table class="data-table">
                        <thead><tr><th>Service</th><th>Plan</th><th>Disk Used</th><th>Bandwidth Used</th></tr></thead>
                        <tbody>${d.services.map(s => `
                            <tr>
                                <td><strong>${esc(s.domain || 'No domain')}</strong></td>
                                <td>${esc(s.plan)}</td>
                                <td>${s.disk_used_mb} MB</td>
                                <td>${s.bandwidth_used_mb} MB</td>
                            </tr>
                        `).join('')}</tbody>
                    </table>
                </div>
            ` : ''}
        `;
    }

    // ─── Support ───

    async function renderSupport(el) {
        const tickets = await api('/tickets');
        el.innerHTML = `
            <div class="card-header" style="margin-bottom:16px">
                <h3>Support Tickets (${tickets.length})</h3>
                <button class="btn btn-primary" onclick="portalCreateTicket()">+ New Ticket</button>
            </div>
            <div class="card" style="padding:0">
                ${tickets.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">🎫</span><div class="empty-text">No support tickets. Need help? Create a ticket!</div></div>'
                    : `<table class="data-table">
                        <thead><tr><th>Subject</th><th>Status</th><th>Priority</th><th>Messages</th><th>Updated</th></tr></thead>
                        <tbody>${tickets.map(t => `
                            <tr style="cursor:pointer" onclick="portalViewTicket('${t.id}')">
                                <td><strong>${esc(t.subject)}</strong></td>
                                <td>${badge(t.status)}</td>
                                <td><span class="badge" style="background:var(--bg-secondary)">${esc(t.priority)}</span></td>
                                <td>${t.message_count}</td>
                                <td>${fmtDate(t.updated_at)}</td>
                            </tr>
                        `).join('')}</tbody>
                    </table>`
                }
            </div>
            <div id="p-ticket-detail" style="margin-top:20px"></div>
        `;
    }

    window.portalCreateTicket = function() {
        showModal('Create Support Ticket', `
            <div class="form-group"><label>Subject</label><input class="form-input" id="p-t-subject"></div>
            <div class="form-group"><label>Priority</label><select class="form-select" id="p-t-priority"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option><option value="urgent">Urgent</option></select></div>
            <div class="form-group"><label>Message</label><textarea class="form-textarea" id="p-t-message" rows="5" placeholder="Describe your issue..."></textarea></div>
        `, async () => {
            await api('/tickets', { method: 'POST', body: {
                customer_id: customer.id,
                subject: document.getElementById('p-t-subject').value,
                priority: document.getElementById('p-t-priority').value,
                message: document.getElementById('p-t-message').value,
            }});
            toast('Ticket created');
            closeModal();
            portalView('support');
        });
    };

    window.portalViewTicket = async function(id) {
        const ticket = await api(`/tickets/${id}`);
        const detail = document.getElementById('p-ticket-detail');
        if (!detail) return;

        detail.innerHTML = `
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                    <h3 style="margin:0">${esc(ticket.subject)}</h3>
                    ${badge(ticket.status)}
                </div>
                <div style="max-height:400px;overflow-y:auto;margin-bottom:16px">
                    ${ticket.messages.map(m => `
                        <div class="message">
                            <div class="message-avatar ${m.author}">${esc(m.author_name?.[0] || '?')}</div>
                            <div class="message-body">
                                <div class="message-meta">
                                    <span class="message-author">${esc(m.author_name)}</span>
                                    <span class="message-time">${fmtDate(m.created_at)}</span>
                                </div>
                                <div class="message-content">${esc(m.content)}</div>
                            </div>
                        </div>
                    `).join('')}
                </div>
                <div style="display:flex;gap:10px">
                    <textarea class="form-textarea" id="p-ticket-reply" style="flex:1;min-height:60px" placeholder="Type your reply..."></textarea>
                    <button class="btn btn-primary" style="align-self:flex-end" onclick="portalReplyTicket('${ticket.id}')">Reply</button>
                </div>
            </div>
        `;
        detail.scrollIntoView({ behavior: 'smooth' });
    };

    window.portalReplyTicket = async function(id) {
        const content = document.getElementById('p-ticket-reply')?.value;
        if (!content?.trim()) return;
        await api(`/tickets/${id}/reply`, { method: 'POST', body: {
            content: content,
            author: 'customer',
            author_name: `${customer.first_name} ${customer.last_name}`,
        }});
        toast('Reply sent');
        portalViewTicket(id);
    };

    // ─── Billing ───

    async function renderBilling(el) {
        const invoices = await api('/invoices');
        el.innerHTML = `
            <div class="card-header" style="margin-bottom:16px"><h3>Invoices (${invoices.length})</h3></div>
            <div class="card" style="padding:0">
                ${invoices.length === 0
                    ? '<div class="empty-state"><span class="empty-icon">💳</span><div class="empty-text">No invoices</div></div>'
                    : `<table class="data-table">
                        <thead><tr><th>Invoice</th><th>Description</th><th>Amount</th><th>Status</th><th>Issued</th><th>Due</th></tr></thead>
                        <tbody>${invoices.map(i => `
                            <tr>
                                <td><code style="font-size:11px;color:var(--text-muted)">${esc(i.id.substring(0, 8))}</code></td>
                                <td>${esc(i.description)}</td>
                                <td><strong>${fmtCurrency(i.amount)}</strong></td>
                                <td>${badge(i.status)}</td>
                                <td>${fmtDate(i.issued_at)}</td>
                                <td>${fmtDate(i.due_at)}</td>
                            </tr>
                        `).join('')}</tbody>
                    </table>`
                }
            </div>
        `;
    }

    // ─── Settings ───

    async function renderSettings(el) {
        const profile = await api('/account');
        el.innerHTML = `
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
                <div class="card">
                    <h3 style="margin-bottom:20px;font-size:16px;font-weight:600">Profile</h3>
                    <div class="form-row">
                        <div class="form-group"><label>First Name</label><input class="form-input" id="p-s-fn" value="${esc(profile.first_name)}"></div>
                        <div class="form-group"><label>Last Name</label><input class="form-input" id="p-s-ln" value="${esc(profile.last_name)}"></div>
                    </div>
                    <div class="form-group"><label>Email</label><input class="form-input" value="${esc(profile.email)}" disabled style="opacity:0.6"></div>
                    <div class="form-group"><label>Company</label><input class="form-input" id="p-s-co" value="${esc(profile.company || '')}"></div>
                    <div class="form-group"><label>Phone</label><input class="form-input" id="p-s-ph" value="${esc(profile.phone || '')}"></div>
                    <button class="btn btn-primary" onclick="portalSaveProfile()">Save Changes</button>
                </div>
                <div class="card">
                    <h3 style="margin-bottom:20px;font-size:16px;font-weight:600">Change Password</h3>
                    <div class="form-group"><label>Current Password</label><input class="form-input" type="password" id="p-s-curpw"></div>
                    <div class="form-group"><label>New Password</label><input class="form-input" type="password" id="p-s-newpw"></div>
                    <div class="form-group"><label>Confirm New Password</label><input class="form-input" type="password" id="p-s-cfmpw"></div>
                    <button class="btn btn-primary" onclick="portalChangePassword()">Change Password</button>
                    <div style="margin-top:24px;padding-top:20px;border-top:1px solid var(--border)">
                        <h4 style="font-size:14px;font-weight:600;margin-bottom:8px">Two-Factor Authentication</h4>
                        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">
                            ${profile.totp_enabled
                                ? '<span style="color:var(--success)">2FA is enabled</span>'
                                : '<span style="color:var(--text-muted)">2FA is not enabled</span>'
                            }
                        </p>
                    </div>
                </div>
            </div>
        `;
    }

    window.portalSaveProfile = async function() {
        await api('/account', { method: 'PUT', body: {
            first_name: document.getElementById('p-s-fn').value,
            last_name: document.getElementById('p-s-ln').value,
            company: document.getElementById('p-s-co').value,
            phone: document.getElementById('p-s-ph').value,
        }});
        customer.first_name = document.getElementById('p-s-fn').value;
        customer.last_name = document.getElementById('p-s-ln').value;
        localStorage.setItem('wolfhost_customer', JSON.stringify(customer));
        toast('Profile updated');
    };

    window.portalChangePassword = async function() {
        const newPw = document.getElementById('p-s-newpw').value;
        const cfmPw = document.getElementById('p-s-cfmpw').value;
        if (newPw !== cfmPw) { toast('Passwords do not match', 'error'); return; }
        try {
            const result = await api('/account/password', { method: 'POST', body: {
                current_password: document.getElementById('p-s-curpw').value,
                new_password: newPw,
            }});
            if (result.error) { toast(result.error, 'error'); return; }
            toast('Password changed');
            document.getElementById('p-s-curpw').value = '';
            document.getElementById('p-s-newpw').value = '';
            document.getElementById('p-s-cfmpw').value = '';
        } catch (e) {
            // api() now throws the backend reason (e.g. "Current
            // password is incorrect") — surface it, don't swallow it.
            toast(e && e.message ? e.message : 'Failed to change password', 'error');
        }
    };

    // ─── Modal System ───

    function showModal(title, body, onSave, saveLabel) {
        closeModal();
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.id = 'portal-modal';
        overlay.onclick = e => { if (e.target === overlay) closeModal(); };
        overlay.innerHTML = `
            <div class="modal">
                <div class="modal-header"><h3>${title}</h3><button class="modal-close" onclick="portalCloseModal()">&times;</button></div>
                <div class="modal-body">${body}</div>
                <div class="modal-footer">
                    <button class="btn" onclick="portalCloseModal()">Cancel</button>
                    <button class="btn btn-primary" id="p-modal-save">${saveLabel || 'Save'}</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
        // Wrap the save handler so any rejection (api() now throws on
        // non-2xx) always produces a visible toast, even for the many
        // callbacks that don't wrap their own api() calls in try/catch.
        document.getElementById('p-modal-save').onclick = async (ev) => {
            try {
                await onSave(ev);
            } catch (e) {
                toast(e && e.message ? e.message : 'Action failed', 'error');
            }
        };
        setTimeout(() => overlay.querySelector('input,select,textarea')?.focus(), 100);
    }

    function closeModal() { document.getElementById('portal-modal')?.remove(); }
    window.portalCloseModal = closeModal;

    /// Modal-based prompt (replaces window.prompt)
    function showPrompt(title, label, defaultVal, onSubmit) {
        showModal(title, `
            <div class="form-group"><label>${label}</label><input class="form-input" id="p-prompt-val" value="${esc(defaultVal || '')}"></div>
        `, () => {
            const val = document.getElementById('p-prompt-val').value;
            closeModal();
            onSubmit(val);
        });
    }

    /// Modal-based confirm (replaces window.confirm)
    function showConfirm(title, message, onYes) {
        // `await onYes()` so a rejected action propagates to the
        // showModal save-wrapper and gets a visible error toast.
        showModal(title, `
            <p style="font-size:14px;color:var(--text-secondary);line-height:1.6">${message}</p>
        `, async () => { closeModal(); await onYes(); }, 'Confirm');
    }

    // ─── Branding Application ───

    function applyBranding() {
        const c = config;
        const root = document.documentElement;

        // Apply accent color
        if (c.accent_color) {
            root.style.setProperty('--accent', c.accent_color);
            root.style.setProperty('--accent-glow', c.accent_color + '26');
            // Generate gradient
            const light = c.accent_light || lightenColor(c.accent_color, 40);
            root.style.setProperty('--accent-light', light);
            root.style.setProperty('--gradient-main', `linear-gradient(135deg, ${c.accent_color} 0%, ${light} 100%)`);
            root.style.setProperty('--shadow-glow', `0 0 30px ${c.accent_color}26`);
        }

        // Company name
        const companyName = c.company_name || 'WolfHost';
        document.getElementById('login-company').textContent = companyName;
        document.getElementById('portal-company').textContent = companyName;
        document.title = `${companyName} — Customer Portal`;

        // Tagline
        const subtitle = document.querySelector('.login-subtitle');
        if (subtitle) subtitle.textContent = c.tagline || 'Customer Portal';

        // Logo
        const loginLogo = document.querySelector('.login-logo');
        const brandIcon = document.querySelector('.brand-icon');
        if (c.logo_url) {
            if (loginLogo) loginLogo.innerHTML = `<img src="${esc(c.logo_url)}" alt="${esc(companyName)}" style="max-height:56px;max-width:200px">`;
            if (brandIcon) brandIcon.innerHTML = `<img src="${esc(c.logo_url)}" alt="" style="height:28px">`;
        } else {
            const emoji = c.favicon_emoji || '🌐';
            if (loginLogo) loginLogo.textContent = emoji;
            if (brandIcon) brandIcon.textContent = emoji;
        }

        // Favicon
        if (c.favicon_emoji) {
            const link = document.querySelector("link[rel='icon']") || document.createElement('link');
            link.rel = 'icon';
            link.href = `data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>${encodeURIComponent(c.favicon_emoji)}</text></svg>`;
            document.head.appendChild(link);
        }

        // Footer
        const loginFooter = document.querySelector('.login-footer');
        if (loginFooter) {
            if (c.footer_text) {
                loginFooter.innerHTML = esc(c.footer_text);
            } else {
                loginFooter.innerHTML = `Powered by <strong>${esc(companyName)}</strong>`;
            }
        }

        // Support links in sidebar
        if (c.support_email || c.support_url) {
            const nav = document.querySelector('.sidebar-nav');
            if (nav && !document.getElementById('p-nav-help')) {
                const helpLink = document.createElement('a');
                helpLink.id = 'p-nav-help';
                helpLink.className = 'nav-link';
                helpLink.innerHTML = '<span class="nav-icon">❓</span> Help';
                helpLink.href = c.support_url || `mailto:${c.support_email}`;
                helpLink.target = '_blank';
                helpLink.style.marginTop = '4px';
                const divider = nav.querySelector('.nav-divider');
                if (divider) divider.before(helpLink);
            }
        }

        // Custom CSS
        if (c.custom_css) {
            let styleEl = document.getElementById('wolfhost-custom-css');
            if (!styleEl) {
                styleEl = document.createElement('style');
                styleEl.id = 'wolfhost-custom-css';
                document.head.appendChild(styleEl);
            }
            styleEl.textContent = c.custom_css;
        }
    }

    function lightenColor(hex, percent) {
        hex = hex.replace('#', '');
        const r = Math.min(255, parseInt(hex.substring(0, 2), 16) + Math.round(255 * percent / 100));
        const g = Math.min(255, parseInt(hex.substring(2, 4), 16) + Math.round(255 * percent / 100));
        const b = Math.min(255, parseInt(hex.substring(4, 6), 16) + Math.round(255 * percent / 100));
        return `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`;
    }

    // ─── App Init ───

    function showApp() {
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('app-shell').style.display = 'flex';
        document.getElementById('user-info').textContent = `${customer.first_name} ${customer.last_name}`;
        applyBranding();
        portalView('dashboard');
    }

    async function checkSession() {
        // Load config/branding
        try { config = await (await fetch('/api/config')).json(); } catch {}

        // Apply branding immediately (for login screen)
        applyBranding();

        // Check stored session
        token = localStorage.getItem('wolfhost_token');
        const stored = localStorage.getItem('wolfhost_customer');
        if (token && stored) {
            try {
                const resp = await api('/auth/check');
                if (resp.authenticated) {
                    customer = resp.customer;
                    showApp();
                    return;
                }
            } catch {}
        }
        // Show login
        document.getElementById('login-screen').style.display = '';
        document.getElementById('app-shell').style.display = 'none';

        // Pre-fill the email field from `?email=` in the URL. The
        // admin-side wolfhost UI links here with the customer's email
        // already known, which saves operators retyping it during
        // support sessions. We never auto-submit — only fill — so
        // there's no credential-leak risk if a stale link is shared.
        try {
            const params = new URLSearchParams(window.location.search);
            const presetEmail = params.get('email');
            if (presetEmail) {
                const emailInput = document.getElementById('login-email');
                if (emailInput) {
                    emailInput.value = presetEmail;
                    const passInput = document.getElementById('login-password');
                    if (passInput) passInput.focus();
                }
            }
        } catch (_) {}
    }

    document.addEventListener('DOMContentLoaded', checkSession);

    // ─── Hosting Tools (DirectAdmin extras) ───
    //
    // One-stop page wiring the DA-side features that don't have
    // dedicated nav entries yet: SSO, password rotations, email
    // forwarders/autoresponders/vacation/catch-all, PHP version,
    // pointers, redirects, cron, SSH keys, mailing lists, spam,
    // protected directories, security toggles, logs.
    //
    // Each panel makes one API call on demand (lazy — no pre-load
    // until the operator clicks the section header) so the page
    // loads fast and only hits DA for what's actually needed.

    let daToolsDomain = '';

    async function renderDaTools(el) {
        // Pull the customer's domain list once so every section that
        // needs a domain (forwarders, autoresponders, etc.) can pick
        // from the same list.
        let domains = [];
        try {
            const resp = await api('/dns/records');
            domains = (resp.domains || []);
        } catch {}
        if (domains.length && !daToolsDomain) daToolsDomain = domains[0];
        const domainOpts = domains.map(d =>
            `<option value="${esc(d)}"${d === daToolsDomain ? ' selected' : ''}>${esc(d)}</option>`
        ).join('');

        // Group tools by user-mental-model category. Each group's
        // accent colour is set in CSS via `data-cat`. Cards inside
        // a group share the same icon-bubble tint and open-state
        // border colour, so the grouping is visually obvious without
        // a heavyweight section divider.
        const groups = [
            { cat: 'email', label: 'Email', tools: [
                ['email-forwarders', '📨', 'Email Forwarders',  'Forward incoming mail to other addresses.'],
                ['autoresponders',   '✉️', 'Autoresponders',    'Auto-reply to messages while you\'re busy.'],
                ['vacation',         '🏖️', 'Vacation Messages', 'Time-windowed away replies.'],
                ['catchall',         '📮', 'Catch-all Routing', 'Where mail to unknown addresses on this domain ends up.'],
                ['mailinglists',     '📋', 'Mailing Lists',     'Majordomo-style discussion lists.'],
                ['spam',             '🛡️', 'Spam Filter',      'SpamAssassin score threshold and action.'],
            ]},
            { cat: 'domain', label: 'Domain & Site', tools: [
                ['php',          '🐘', 'PHP Version',         'Pick which PHP version this domain runs.'],
                ['redirects',    '↪️', 'HTTP Redirects',      'Path-based 301 / 302 redirects.'],
                ['pointers',     '🌐', 'Domain Aliases',      'Park additional domains on the same site.'],
                ['protectdirs',  '🚪', 'Protected Directories', 'Basic-auth gate on a directory.'],
            ]},
            { cat: 'security', label: 'Security', tools: [
                ['security',  '🔒', 'Security Toggles',  'Force HTTPS, HSTS, 2FA status.'],
                ['passwords', '🔐', 'Change Passwords',  'DA account, email, and FTP passwords.'],
            ]},
            { cat: 'server', label: 'Server Access', tools: [
                ['cron', '⏰', 'Cron Jobs',  'Scheduled commands on your account.'],
                ['ssh',  '🔑', 'SSH Keys',   'Public keys authorised for shell access.'],
                ['logs', '📜', 'Logs',       'Tail web, error, and mail logs.'],
            ]},
        ];

        const groupHtml = groups.map(g => `
            <div class="tools-group" data-cat="${g.cat}">
                <div class="tools-group-header"><span class="swatch"></span>${esc(g.label)}</div>
                <div class="tools-grid">
                    ${g.tools.map(([id, icon, title, hint]) => daToolCard(id, icon, title, hint)).join('')}
                </div>
            </div>
        `).join('');

        el.innerHTML = `
            <div class="tools-hero">
                <div class="tools-hero-content">
                    <h2>Hosting Tools</h2>
                    <p>The advanced controls behind your hosting account — email routing, domain settings, security, and server access. Most settings below apply to whichever domain you pick on the right.</p>
                </div>
                <div class="tools-hero-actions">
                    ${(dashboardData?.services || []).some(s => s.backend === 'directadmin') ? '<button class="btn-sso" onclick="daSsoOpen()">🔓 Open DirectAdmin</button>' : ''}
                    <div class="domain-pill">
                        <span>Domain</span>
                        <select id="da-tools-domain" onchange="daToolsSetDomain(this.value)">
                            ${domainOpts || '<option>(no domains)</option>'}
                        </select>
                    </div>
                </div>
            </div>
            ${groupHtml}
        `;
    }

    function daToolCard(id, icon, title, hint) {
        return `<details class="tool-card" ontoggle="if(this.open) daToolsLoad('${id}');">
            <summary>
                <div class="tool-icon">${icon}</div>
                <div class="tool-text">
                    <div class="tool-title">${esc(title)}</div>
                    <div class="tool-hint">${esc(hint)}</div>
                </div>
                <div class="tool-chev">›</div>
            </summary>
            <div class="tool-body" id="da-section-${id}">
                <div style="text-align:center;padding:18px;color:var(--text-muted);">Loading…</div>
            </div>
        </details>`;
    }

    window.daToolsSetDomain = function(d) {
        daToolsDomain = d;
        // Re-render every open section so it reloads against the
        // newly-selected domain.
        document.querySelectorAll('details[open]').forEach(d => {
            const m = d.querySelector('[id^=da-section-]');
            if (m) {
                const id = m.id.replace('da-section-', '');
                daToolsLoad(id);
            }
        });
    };

    window.daSsoOpen = async function() {
        try {
            const resp = await api('/sso/directadmin', { method: 'POST' });
            if (resp.url) {
                window.open(resp.url, '_blank', 'noopener');
            } else {
                toast('Could not generate login link', 'error');
            }
        } catch (e) { toast(e.message || 'Failed', 'error'); }
    };

    window.daToolsLoad = async function(section) {
        const host = document.getElementById('da-section-' + section);
        if (!host) return;
        host.innerHTML = '<div style="text-align:center;padding:12px;color:var(--text-muted);">Loading…</div>';
        try {
            switch (section) {
                case 'email-forwarders': return daRenderForwarders(host);
                case 'autoresponders':   return daRenderAutoresponders(host);
                case 'vacation':         return daRenderVacation(host);
                case 'catchall':         return daRenderCatchAll(host);
                case 'php':              return daRenderPhp(host);
                case 'redirects':        return daRenderRedirects(host);
                case 'pointers':         return daRenderPointers(host);
                case 'cron':             return daRenderCron(host);
                case 'ssh':              return daRenderSsh(host);
                case 'mailinglists':     return daRenderMailingLists(host);
                case 'spam':             return daRenderSpam(host);
                case 'security':         return daRenderSecurity(host);
                case 'protectdirs':      return daRenderProtectedDirs(host);
                case 'passwords':        return daRenderPasswords(host);
                case 'logs':             return daRenderLogs(host);
            }
        } catch (e) {
            host.innerHTML = `<div style="color:#ef4444;">Failed to load: ${esc(e.message || String(e))}</div>`;
        }
    };

    // ─── Forwarders ───

    async function daRenderForwarders(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const list = await api(`/email-forwarders?domain=${encodeURIComponent(daToolsDomain)}`);
        host.innerHTML = `
            <table style="width:100%;font-size:13px;">
                <thead><tr><th align="left">Address</th><th align="left">Destinations</th><th></th></tr></thead>
                <tbody>${(list||[]).map(f => `<tr>
                    <td>${esc(f.user)}@${esc(daToolsDomain)}</td>
                    <td>${(f.destinations||[]).map(esc).join(', ')}</td>
                    <td><button class="btn-sm" onclick="daForwarderDelete('${esc(f.user)}')">Delete</button></td>
                </tr>`).join('') || '<tr><td colspan="3"><em>None.</em></td></tr>'}</tbody>
            </table>
            <div style="margin-top:10px;display:flex;gap:6px;">
                <input id="fwd-user" placeholder="newuser" style="flex:1;">
                <input id="fwd-dest" placeholder="dest@example.com,another@…" style="flex:2;">
                <button class="btn-primary" onclick="daForwarderCreate()">Create</button>
            </div>`;
    }
    window.daForwarderCreate = async function() {
        const user = document.getElementById('fwd-user').value.trim();
        const dest = document.getElementById('fwd-dest').value.split(',').map(s => s.trim()).filter(Boolean);
        if (!user || !dest.length) return toast('Need user + at least one destination', 'error');
        try {
            await api('/email-forwarders', { method: 'POST',
                body: JSON.stringify({ domain: daToolsDomain, user, destinations: dest })});
            toast('Forwarder created'); daToolsLoad('email-forwarders');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daForwarderDelete = async function(user) {
        if (!confirm(`Delete forwarder ${user}@${daToolsDomain}?`)) return;
        try {
            await api('/email-forwarders', { method: 'DELETE',
                body: JSON.stringify({ domain: daToolsDomain, user })});
            toast('Deleted'); daToolsLoad('email-forwarders');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Autoresponders ───

    async function daRenderAutoresponders(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const list = await api(`/autoresponders?domain=${encodeURIComponent(daToolsDomain)}`);
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th align="left">User</th><th align="left">Subject</th><th></th></tr>
            </thead><tbody>${(list||[]).map(r => `<tr>
                <td>${esc(r.user)}</td><td>${esc(r.subject||'')}</td>
                <td><button class="btn-sm" onclick="daAutoDelete('${esc(r.user)}')">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="3"><em>None.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:grid;grid-template-columns:1fr 2fr;gap:6px;">
                <input id="ar-user" placeholder="user">
                <input id="ar-subject" placeholder="Subject">
                <input id="ar-cc" placeholder="cc (optional)">
                <textarea id="ar-body" placeholder="Body" rows="3"></textarea>
            </div>
            <button class="btn-primary" style="margin-top:6px;" onclick="daAutoCreate()">Create</button>`;
    }
    window.daAutoCreate = async function() {
        try {
            await api('/autoresponders', { method: 'POST', body: JSON.stringify({
                domain: daToolsDomain,
                user: document.getElementById('ar-user').value,
                subject: document.getElementById('ar-subject').value,
                body: document.getElementById('ar-body').value,
                cc: document.getElementById('ar-cc').value,
            })});
            toast('Autoresponder created'); daToolsLoad('autoresponders');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daAutoDelete = async function(user) {
        if (!confirm(`Delete autoresponder for ${user}?`)) return;
        try {
            await api('/autoresponders', { method: 'DELETE',
                body: JSON.stringify({ domain: daToolsDomain, user })});
            toast('Deleted'); daToolsLoad('autoresponders');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Vacation ───

    async function daRenderVacation(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const list = await api(`/vacation?domain=${encodeURIComponent(daToolsDomain)}`);
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th align="left">User</th><th align="left">Start</th><th align="left">End</th><th></th></tr>
            </thead><tbody>${(list||[]).map(r => `<tr>
                <td>${esc(r.user)}</td><td>${esc(r.start)}</td><td>${esc(r.end)}</td>
                <td><button class="btn-sm" onclick="daVacDelete('${esc(r.user)}')">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="4"><em>None.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;">
                <input id="v-user" placeholder="user">
                <input id="v-start" type="datetime-local">
                <input id="v-end" type="datetime-local">
                <textarea id="v-msg" placeholder="Out-of-office message" rows="2" style="grid-column:1 / -1;"></textarea>
            </div>
            <button class="btn-primary" style="margin-top:6px;" onclick="daVacCreate()">Create</button>`;
    }
    window.daVacCreate = async function() {
        const fmt = v => v.replace('T', ' ');
        try {
            await api('/vacation', { method: 'POST', body: JSON.stringify({
                domain: daToolsDomain,
                user: document.getElementById('v-user').value,
                message: document.getElementById('v-msg').value,
                start: fmt(document.getElementById('v-start').value),
                end:   fmt(document.getElementById('v-end').value),
            })});
            toast('Vacation message saved'); daToolsLoad('vacation');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daVacDelete = async function(user) {
        if (!confirm(`Delete vacation for ${user}?`)) return;
        try {
            await api('/vacation', { method: 'DELETE',
                body: JSON.stringify({ domain: daToolsDomain, user })});
            toast('Deleted'); daToolsLoad('vacation');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Catch-all ───

    async function daRenderCatchAll(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const c = await api(`/catch-all?domain=${encodeURIComponent(daToolsDomain)}`);
        host.innerHTML = `
            <p>Where should mail to unknown addresses on <strong>${esc(daToolsDomain)}</strong> go?</p>
            <select id="ca-mode">
                <option value="ignore"${c.mode==='ignore'?' selected':''}>Default routing (ignore)</option>
                <option value="address"${c.mode==='address'?' selected':''}>Forward to a single address</option>
                <option value="fail"${c.mode==='fail'?' selected':''}>Reject (550)</option>
                <option value="blackhole"${c.mode==='blackhole'?' selected':''}>Silently drop</option>
            </select>
            <input id="ca-dest" placeholder="dest@example.com" value="${esc(c.destination||'')}" style="margin-left:6px;">
            <button class="btn-primary" style="margin-left:6px;" onclick="daCatchAllSave()">Save</button>`;
    }
    window.daCatchAllSave = async function() {
        try {
            await api('/catch-all', { method: 'PUT', body: JSON.stringify({
                domain: daToolsDomain,
                mode: document.getElementById('ca-mode').value,
                destination: document.getElementById('ca-dest').value,
            })});
            toast('Saved'); daToolsLoad('catchall');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── PHP version ───

    async function daRenderPhp(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const [{versions}, current] = await Promise.all([
            api('/php/versions'),
            api(`/php/domain?domain=${encodeURIComponent(daToolsDomain)}`),
        ]);
        host.innerHTML = `
            <p>Domain: <strong>${esc(daToolsDomain)}</strong> — currently using <strong>PHP ${esc(current.version || 'unknown')}</strong></p>
            <select id="php-version">
                ${(versions||[]).map(v => `<option value="${esc(v)}"${v === current.version ? ' selected' : ''}>PHP ${esc(v)}</option>`).join('')}
            </select>
            <button class="btn-primary" style="margin-left:6px;" onclick="daPhpSave()">Save</button>`;
    }
    window.daPhpSave = async function() {
        try {
            await api('/php/domain', { method: 'PUT', body: JSON.stringify({
                domain: daToolsDomain,
                version: document.getElementById('php-version').value,
            })});
            toast('PHP version updated');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Redirects ───

    async function daRenderRedirects(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const list = await api(`/redirects?domain=${encodeURIComponent(daToolsDomain)}`);
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th align="left">Path</th><th align="left">→</th><th>Code</th><th></th></tr>
            </thead><tbody>${(list||[]).map(r => `<tr>
                <td>${esc(r.path)}</td><td>${esc(r.destination)}</td><td>${r.code}</td>
                <td><button class="btn-sm" onclick="daRedirDelete('${esc(r.path).replace(/'/g,'&apos;')}')">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="4"><em>None.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:grid;grid-template-columns:1fr 2fr 100px;gap:6px;">
                <input id="rd-path" placeholder="/old">
                <input id="rd-dest" placeholder="https://example.com/new">
                <select id="rd-code"><option value="301">301</option><option value="302">302</option></select>
            </div>
            <button class="btn-primary" style="margin-top:6px;" onclick="daRedirCreate()">Create</button>`;
    }
    window.daRedirCreate = async function() {
        try {
            await api('/redirects', { method: 'POST', body: JSON.stringify({
                domain: daToolsDomain,
                path: document.getElementById('rd-path').value,
                destination: document.getElementById('rd-dest').value,
                code: parseInt(document.getElementById('rd-code').value, 10),
            })});
            toast('Redirect created'); daToolsLoad('redirects');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daRedirDelete = async function(path) {
        if (!confirm(`Delete redirect ${path}?`)) return;
        try {
            await api('/redirects', { method: 'DELETE',
                body: JSON.stringify({ domain: daToolsDomain, path })});
            toast('Deleted'); daToolsLoad('redirects');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Pointers ───

    async function daRenderPointers(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const list = await api(`/pointers?domain=${encodeURIComponent(daToolsDomain)}`);
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th align="left">Alias</th><th>Type</th><th></th></tr>
            </thead><tbody>${(list||[]).map(p => `<tr>
                <td>${esc(p.from)}</td><td>${p.alias?'alias':'pointer'}</td>
                <td><button class="btn-sm" onclick="daPointerDelete('${esc(p.from)}')">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="3"><em>None.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:flex;gap:6px;">
                <input id="ptr-from" placeholder="alias.example.com" style="flex:1;">
                <label style="font-size:12px;color:var(--text-muted);">
                    <input id="ptr-alias" type="checkbox"> alias (full)
                </label>
                <button class="btn-primary" onclick="daPointerCreate()">Create</button>
            </div>`;
    }
    window.daPointerCreate = async function() {
        try {
            await api('/pointers', { method: 'POST', body: JSON.stringify({
                target: daToolsDomain,
                from: document.getElementById('ptr-from').value,
                is_alias: document.getElementById('ptr-alias').checked,
            })});
            toast('Pointer created'); daToolsLoad('pointers');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daPointerDelete = async function(from) {
        if (!confirm(`Delete pointer ${from}?`)) return;
        try {
            await api('/pointers', { method: 'DELETE',
                body: JSON.stringify({ target: daToolsDomain, from })});
            toast('Deleted'); daToolsLoad('pointers');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Cron ───

    async function daRenderCron(host) {
        const list = await api('/cron');
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th>Min</th><th>Hr</th><th>Day</th><th>Mon</th><th>DOW</th><th align="left">Command</th><th></th></tr>
            </thead><tbody>${(list||[]).map(j => `<tr>
                <td>${esc(j.minute)}</td><td>${esc(j.hour)}</td><td>${esc(j.day_of_month)}</td>
                <td>${esc(j.month)}</td><td>${esc(j.day_of_week)}</td>
                <td><code>${esc(j.command)}</code></td>
                <td><button class="btn-sm" onclick="daCronDelete('${esc(j.id)}')">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="7"><em>No cron jobs.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:grid;grid-template-columns:repeat(5,80px) 1fr;gap:6px;">
                <input id="cr-min"  placeholder="*" value="*">
                <input id="cr-hr"   placeholder="*" value="*">
                <input id="cr-day"  placeholder="*" value="*">
                <input id="cr-mon"  placeholder="*" value="*">
                <input id="cr-dow"  placeholder="*" value="*">
                <input id="cr-cmd"  placeholder="/path/to/script">
            </div>
            <button class="btn-primary" style="margin-top:6px;" onclick="daCronCreate()">Create</button>`;
    }
    window.daCronCreate = async function() {
        try {
            await api('/cron', { method: 'POST', body: JSON.stringify({
                command: document.getElementById('cr-cmd').value,
                minute: document.getElementById('cr-min').value,
                hour: document.getElementById('cr-hr').value,
                day_of_month: document.getElementById('cr-day').value,
                month: document.getElementById('cr-mon').value,
                day_of_week: document.getElementById('cr-dow').value,
            })});
            toast('Cron job added'); daToolsLoad('cron');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daCronDelete = async function(id) {
        if (!confirm('Delete cron job?')) return;
        try {
            await api(`/cron/${encodeURIComponent(id)}`, { method: 'DELETE' });
            toast('Deleted'); daToolsLoad('cron');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── SSH keys ───

    async function daRenderSsh(host) {
        const list = await api('/ssh-keys');
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th align="left">Label</th><th align="left">Fingerprint</th><th></th></tr>
            </thead><tbody>${(list||[]).map(k => `<tr>
                <td>${esc(k.label)}</td><td><code>${esc(k.fingerprint)}</code></td>
                <td><button class="btn-sm" onclick="daSshDelete('${esc(k.key_id)}')">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="3"><em>No keys.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:grid;grid-template-columns:1fr 3fr;gap:6px;">
                <input id="sk-label" placeholder="laptop">
                <textarea id="sk-key" placeholder="ssh-ed25519 AAAA…" rows="2"></textarea>
            </div>
            <button class="btn-primary" style="margin-top:6px;" onclick="daSshAdd()">Add key</button>`;
    }
    window.daSshAdd = async function() {
        try {
            await api('/ssh-keys', { method: 'POST', body: JSON.stringify({
                label: document.getElementById('sk-label').value,
                public_key: document.getElementById('sk-key').value,
            })});
            toast('Key added'); daToolsLoad('ssh');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daSshDelete = async function(id) {
        if (!confirm('Delete SSH key?')) return;
        try {
            await api(`/ssh-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
            toast('Deleted'); daToolsLoad('ssh');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Mailing lists ───

    async function daRenderMailingLists(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const resp = await api(`/mailing-lists?domain=${encodeURIComponent(daToolsDomain)}`);
        // Native services respond `{lists: [], unsupported: "…"}` —
        // show the explanation instead of an empty broken form.
        if (resp && !Array.isArray(resp) && resp.unsupported) {
            host.innerHTML = `<p style="font-size:13px;color:var(--text-secondary);">${esc(resp.unsupported)}</p>`;
            return;
        }
        const list = Array.isArray(resp) ? resp : (resp.lists || []);
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th align="left">Name</th><th align="left">Address</th><th></th></tr>
            </thead><tbody>${(list||[]).map(l => `<tr>
                <td>${esc(l.name)}</td><td>${esc(l.address)}</td>
                <td><button class="btn-sm" onclick="daMlDelete('${esc(l.name)}')">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="3"><em>None.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:flex;gap:6px;">
                <input id="ml-name" placeholder="discuss" style="flex:1;">
                <button class="btn-primary" onclick="daMlCreate()">Create</button>
            </div>`;
    }
    window.daMlCreate = async function() {
        try {
            await api('/mailing-lists', { method: 'POST', body: JSON.stringify({
                domain: daToolsDomain,
                name: document.getElementById('ml-name').value,
            })});
            toast('Mailing list created'); daToolsLoad('mailinglists');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daMlDelete = async function(name) {
        if (!confirm(`Delete list ${name}?`)) return;
        try {
            await api('/mailing-lists', { method: 'DELETE',
                body: JSON.stringify({ domain: daToolsDomain, name })});
            toast('Deleted'); daToolsLoad('mailinglists');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Spam ───

    async function daRenderSpam(host) {
        const s = await api('/spam');
        host.innerHTML = `
            <p>SpamAssassin filter — affects every mailbox on your account.</p>
            <label><input type="checkbox" id="sp-en"${s.enabled?' checked':''}> Enabled</label>
            <div style="margin-top:8px;display:flex;gap:8px;align-items:center;">
                <span>Score threshold</span>
                <input id="sp-score" type="number" min="0" max="15" step="0.5" value="${s.score_threshold || 5}">
                <span>Action</span>
                <select id="sp-act">
                    <option value="tag"${s.action==='tag'?' selected':''}>Tag (X-Spam header)</option>
                    <option value="subject"${s.action==='subject'?' selected':''}>Rewrite Subject</option>
                    <option value="deliver"${s.action==='deliver'?' selected':''}>Deliver as-is</option>
                    <option value="delete"${s.action==='delete'?' selected':''}>Delete</option>
                </select>
            </div>
            <button class="btn-primary" style="margin-top:8px;" onclick="daSpamSave()">Save</button>`;
    }
    window.daSpamSave = async function() {
        try {
            await api('/spam', { method: 'PUT', body: JSON.stringify({
                enabled: document.getElementById('sp-en').checked,
                score_threshold: parseFloat(document.getElementById('sp-score').value),
                action: document.getElementById('sp-act').value,
            })});
            toast('Saved');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Security ───

    async function daRenderSecurity(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const tfa = await api('/security/2fa-status').catch(() => ({}));
        host.innerHTML = `
            <p>Domain: <strong>${esc(daToolsDomain)}</strong></p>
            <label><input type="checkbox" id="sec-https"> Force HTTPS (redirect HTTP → HTTPS)</label><br>
            <label><input type="checkbox" id="sec-hsts"> Enable HSTS</label>
            <div style="margin-top:10px;">
                <button class="btn-primary" onclick="daSecForce()">Apply force-HTTPS</button>
                <button class="btn-primary" onclick="daSecHsts()">Apply HSTS</button>
            </div>
            <hr style="margin:14px 0;">
            ${(dashboardData?.services || []).some(s => s.backend === 'directadmin') ? `
            <p>Two-factor authentication on the DA panel: <strong>${tfa.enabled ? 'Enabled' : 'Disabled'}</strong>${tfa.method ? ' ('+esc(tfa.method)+')' : ''}</p>
            <p style="font-size:12px;color:var(--text-muted);">2FA is enrolled inside DirectAdmin itself. Use the "Open DirectAdmin" button at the top of this page to set it up. Lost your authenticator? Contact support — admin can reset it.</p>` : `
            <p style="font-size:12px;color:var(--text-muted);">Two-factor authentication for the portal login is not available yet on this service.</p>`}`;
    }
    window.daSecForce = async function() {
        try {
            await api('/security/force-https', { method: 'PUT', body: JSON.stringify({
                domain: daToolsDomain,
                force: document.getElementById('sec-https').checked,
            })});
            toast('Saved');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daSecHsts = async function() {
        try {
            await api('/security/hsts', { method: 'PUT', body: JSON.stringify({
                domain: daToolsDomain,
                enabled: document.getElementById('sec-hsts').checked,
            })});
            toast('Saved');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Protected directories ───

    async function daRenderProtectedDirs(host) {
        if (!daToolsDomain) { host.innerHTML = '<em>Pick a domain first.</em>'; return; }
        const list = await api(`/protected-dirs?domain=${encodeURIComponent(daToolsDomain)}`);
        host.innerHTML = `
            <table style="width:100%;font-size:13px;"><thead>
                <tr><th align="left">Path</th><th align="left">Realm</th><th></th></tr>
            </thead><tbody>${(list||[]).map(p => `<tr>
                <td>${esc(p.path)}</td><td>${esc(p.realm)}</td>
                <td><button class="btn-sm" onclick="daPdUnprotect('${esc(p.path)}')">Remove</button></td>
            </tr>`).join('') || '<tr><td colspan="3"><em>None.</em></td></tr>'}</tbody></table>
            <div style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr;gap:6px;">
                <input id="pd-path" placeholder="/admin">
                <input id="pd-realm" placeholder="Restricted">
            </div>
            <button class="btn-primary" style="margin-top:6px;" onclick="daPdProtect()">Protect</button>
            <hr style="margin:14px 0;">
            <p style="font-size:12px;color:var(--text-muted);">After creating a protected directory, add at least one user/password pair so visitors can authenticate:</p>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;">
                <input id="pd-upath" placeholder="/admin">
                <input id="pd-uname" placeholder="username">
                <input id="pd-upass" type="password" placeholder="password">
            </div>
            <button class="btn-primary" style="margin-top:6px;" onclick="daPdAddUser()">Add user</button>`;
    }
    window.daPdProtect = async function() {
        try {
            await api('/protected-dirs', { method: 'POST', body: JSON.stringify({
                domain: daToolsDomain,
                path: document.getElementById('pd-path').value,
                realm: document.getElementById('pd-realm').value,
            })});
            toast('Protected'); daToolsLoad('protectdirs');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daPdAddUser = async function() {
        try {
            await api('/protected-dirs/users', { method: 'POST', body: JSON.stringify({
                domain: daToolsDomain,
                path: document.getElementById('pd-upath').value,
                username: document.getElementById('pd-uname').value,
                password: document.getElementById('pd-upass').value,
            })});
            toast('User added');
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daPdUnprotect = async function(path) {
        if (!confirm(`Remove protection on ${path}?`)) return;
        try {
            await api('/protected-dirs', { method: 'DELETE',
                body: JSON.stringify({ domain: daToolsDomain, path })});
            toast('Removed'); daToolsLoad('protectdirs');
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Passwords ───

    async function daRenderPasswords(host) {
        host.innerHTML = `
            <h4>Account password</h4>
            <input id="pw-acc" type="password" placeholder="New password">
            <button class="btn-primary" style="margin-left:6px;" onclick="daPwAccount()">Change</button>
            <hr style="margin:14px 0;">
            <h4>Email mailbox password</h4>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr 100px;gap:6px;">
                <select id="pw-em-domain">${(window._daDomainOptions||[]).map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('')}</select>
                <input id="pw-em-user" placeholder="user">
                <input id="pw-em-pass" type="password" placeholder="New password">
                <button class="btn-primary" onclick="daPwEmail()">Change</button>
            </div>
            <hr style="margin:14px 0;">
            <h4>FTP password</h4>
            <div style="display:flex;gap:6px;">
                <input id="pw-ftp-user" placeholder="ftp user" style="flex:1;">
                <input id="pw-ftp-pass" type="password" placeholder="New password" style="flex:1;">
                <button class="btn-primary" onclick="daPwFtp()">Change</button>
            </div>`;
        // Populate the email-domain dropdown lazily.
        try {
            const dr = await api('/dns/records');
            const opts = (dr.domains || []).map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('');
            document.getElementById('pw-em-domain').innerHTML = opts;
        } catch {}
    }
    window.daPwAccount = async function() {
        const np = document.getElementById('pw-acc').value;
        if (np.length < 8) return toast('Password must be at least 8 characters', 'error');
        try {
            await api('/password/account', { method: 'POST', body: JSON.stringify({ new_password: np })});
            toast('Account password updated');
            document.getElementById('pw-acc').value = '';
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daPwEmail = async function() {
        try {
            await api('/password/email', { method: 'POST', body: JSON.stringify({
                domain: document.getElementById('pw-em-domain').value,
                user:   document.getElementById('pw-em-user').value,
                new_password: document.getElementById('pw-em-pass').value,
            })});
            toast('Email password updated');
            document.getElementById('pw-em-pass').value = '';
        } catch (e) { toast(e.message, 'error'); }
    };
    window.daPwFtp = async function() {
        try {
            await api('/password/ftp', { method: 'POST', body: JSON.stringify({
                ftp_user: document.getElementById('pw-ftp-user').value,
                new_password: document.getElementById('pw-ftp-pass').value,
            })});
            toast('FTP password updated');
            document.getElementById('pw-ftp-pass').value = '';
        } catch (e) { toast(e.message, 'error'); }
    };

    // ─── Logs ───

    async function daRenderLogs(host) {
        host.innerHTML = `
            <div style="display:flex;gap:6px;margin-bottom:8px;">
                <select id="log-kind">
                    <option value="access">Access log</option>
                    <option value="error">Error log</option>
                    <option value="access_ssl">Access (SSL)</option>
                    <option value="error_ssl">Error (SSL)</option>
                    <option value="mail">Mail log</option>
                </select>
                <input id="log-lines" type="number" min="20" max="5000" value="200" style="width:90px;">
                <button class="btn-primary" onclick="daLogsLoad()">Show</button>
            </div>
            <pre id="log-body" style="max-height:500px;overflow:auto;background:#0a0a0a;color:#e4e4e4;padding:10px;font-size:11px;line-height:1.45;border-radius:6px;">(click Show)</pre>`;
    }
    window.daLogsLoad = async function() {
        const kind = document.getElementById('log-kind').value;
        const lines = parseInt(document.getElementById('log-lines').value, 10);
        try {
            const resp = await fetch(`/api/logs?kind=${encodeURIComponent(kind)}&lines=${lines}`, {
                credentials: 'same-origin',
                headers: { 'Authorization': 'Bearer ' + (token||'') },
            });
            const text = await resp.text();
            document.getElementById('log-body').textContent = text;
        } catch (e) { toast(e.message, 'error'); }
    };

})();
