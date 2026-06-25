// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com
//
// WolfTermConsole — a reusable, self-contained KDE-Konsole-style terminal
// surface. A single instance lives inside a host element and owns a tab
// bar (one tab = one session), splittable panes (xterm + WebSocket per
// pane), reconnect-with-backoff, and a node/type/target picker for adding
// further tabs.
//
// This is a GENERALISATION of the original page-bound fleetConsole* engine.
// It depends on NO app.js globals — everything it needs (the node list, the
// self-node id, the WS base, a target fetcher) is passed in via mount()
// options. That lets the SAME engine drive the in-app per-node Terminal
// panel AND the standalone pop-out window (console.html).
//
// Backend WS protocol (console.rs — unchanged):
//   local : /ws/console/{type}/{name}
//   remote: /ws/remote-console/{node_id}/{type}/{name}
//   output = WS Text/binary frames (raw bytes); keystrokes sent verbatim;
//   resize sent as Text JSON {"type":"resize","cols":N,"rows":N}.
//
// Public API (window.WolfTermConsole):
//   mount(containerEl, opts) -> handle
//     opts = {
//       initial:   { nodeId, type, name, label }   // opened as tab 1
//       nodes:     [..] | () => [..]               // node objects {id,...}
//       selfNodeId: <id>                           // which node is local
//       wsBase:    'wss://host'                    // optional; defaults to
//                                                  // current page origin
//       fetchTargets: (nodeId, type) => Promise<[{value,label}]>
//       onAfterInitialConnect: (pane) => void      // e.g. auto-run command
//     }
//   handle.addTab({nodeId,type,name,label}) -> windowId
//   handle.splitActive('h'|'v')
//   handle.closeActivePane()
//   handle.onShow()       // re-fit panes after the host becomes visible
//   handle.dispose()      // tear everything down (terms, sockets, listeners)
//
// Phase-2 note: server-side detach/reattach would slot in at connectPane()
// — instead of opening a fresh shell it would reattach to the existing
// session identified by pane.sessionKey. The WS-URL builder and the single
// connect path are centralised here for exactly that reason.

(function () {
    'use strict';

    if (window.WolfTermConsole) return; // load-once guard

    // ─── small local helpers (no app.js dependency) ───
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function escAttr(s) {
        return String(s == null ? '' : s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function toast(msg, kind) {
        // Use the app's toast if present; otherwise a minimal inline fallback
        // so the engine still surfaces failures when embedded in console.html.
        if (typeof window.showToast === 'function') { window.showToast(msg, kind || 'info'); return; }
        try {
            let host = document.getElementById('wtc-toast-host');
            if (!host) {
                host = document.createElement('div');
                host.id = 'wtc-toast-host';
                host.setAttribute('role', kind === 'error' ? 'alert' : 'status');
                host.setAttribute('aria-live', kind === 'error' ? 'assertive' : 'polite');
                host.style.cssText = 'position:fixed;bottom:16px;right:16px;z-index:99999;display:flex;flex-direction:column;gap:8px;max-width:360px;';
                document.body.appendChild(host);
            }
            const t = document.createElement('div');
            t.textContent = msg;
            const isErr = kind === 'error';
            t.style.cssText = 'padding:10px 14px;border-radius:8px;font-size:13px;'
                + 'background:var(--bg-card,#1b1b2b);color:var(--text-primary,#f0f0f0);'
                + 'border:1px solid ' + (isErr ? '#ef4444' : 'var(--border,#333)') + ';'
                + 'box-shadow:0 8px 28px rgba(0,0,0,0.5);';
            host.appendChild(t);
            // Errors persist (must be readable/copyable); confirmations fade.
            if (!isErr) setTimeout(() => { if (t.parentElement) t.remove(); }, 3500);
            else { t.style.cursor = 'pointer'; t.title = 'Click to dismiss'; t.onclick = () => t.remove(); }
        } catch (_) { /* last-resort: swallow */ }
    }

    // ─── instance factory ───
    function mount(containerEl, opts) {
        opts = opts || {};
        if (!containerEl) { toast('Terminal mount target missing', 'error'); return null; }

        const inst = {
            root: containerEl,
            opts: opts,
            windows: [],
            activeWindow: null,
            nextWin: 1,
            nextPane: 1,
            keyHandler: null,
            resizeHandler: null,
            disposed: false,
            firstConnectFired: false,
            els: {},
        };

        // ── option accessors ──
        function getNodes() {
            const n = opts.nodes;
            const list = (typeof n === 'function') ? n() : n;
            return Array.isArray(list) ? list : [];
        }
        // Resolve the self-node id lazily on every call — opts.selfNodeId may
        // be a value OR a function, and the node list can populate/refresh
        // after mount. A stale snapshot here would route local sessions
        // through the remote-console proxy.
        function selfNodeId() {
            const v = opts.selfNodeId;
            return (typeof v === 'function') ? v() : v;
        }
        function selfNode() {
            const nodes = getNodes();
            const id = selfNodeId();
            return (id && nodes.find(x => x.id === id))
                || nodes.find(x => x.is_self)
                || nodes[0] || null;
        }
        function nodeById(id) {
            const nodes = getNodes();
            return nodes.find(x => x.id === id) || null;
        }
        function isSelf(node) {
            if (!node) return false;
            const id = selfNodeId();
            if (id) return node.id === id;
            return !!node.is_self;
        }
        // Resolve the node for a session descriptor. An EXPLICIT nodeId must
        // NEVER be silently downgraded to selfNode()/nodes[0]: if it isn't in
        // this window's (possibly stale or popup-local) node list, honour it as
        // a remote node by id so the socket routes to /ws/remote-console/<id>
        // and the right runtime runs on the right host. Without this, a 2nd tab
        // whose node wasn't resolvable fell back to the 1st tab's / self node
        // and ran the wrong command — pct enter on a native LXC, or lxc-attach
        // on a Proxmox LXC ("Failed to get init pid" / "vmid type check failed
        // - got 'gateway'"). A bare nodeId (none given) means the local session.
        function resolveNode(nodeId) {
            if (!nodeId) return selfNode() || null;
            const found = nodeById(nodeId);
            if (found) return found;
            const sid = selfNodeId();
            if (sid && nodeId === sid) return selfNode() || null;
            return { id: nodeId }; // explicit remote node we can't (yet) resolve
        }
        function wsBase() {
            if (opts.wsBase) return opts.wsBase.replace(/\/+$/, '');
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            return `${protocol}//${window.location.host}`;
        }
        function nodeLabel(node) {
            if (!node) return 'local';
            return node.hostname || node.address || node.id;
        }

        // Centralised WS-URL builder. type ∈ host|docker|lxc|vm, plus the
        // special 'pve' type (Proxmox host/guest shell) which routes through
        // the dedicated pve-console proxy and carries pve fields on the pane.
        function wsUrlForPane(pane) {
            if (pane.type === 'pve') {
                return `${wsBase()}/ws/pve-console/${encodeURIComponent(pane.pveNodeId)}/${encodeURIComponent(pane.pveVmid)}`;
            }
            const node = pane.node, type = pane.type, target = pane.target;
            const name = (type === 'host') ? 'host' : target;
            // No node object (e.g. node list not loaded) means the local
            // serving node — local sessions don't need a node id.
            if (!node || isSelf(node)) {
                return `${wsBase()}/ws/console/${encodeURIComponent(type)}/${encodeURIComponent(name)}`;
            }
            return `${wsBase()}/ws/remote-console/${encodeURIComponent(node.id)}/${encodeURIComponent(type)}/${encodeURIComponent(name)}`;
        }

        // ── shell ──
        function buildShell() {
            containerEl.classList.add('wtc-host');
            containerEl.innerHTML = `
                <div class="fleet-console-shell" role="application" aria-label="Terminal console">
                    <div class="fc-tabstrip" role="tablist" aria-label="Terminal sessions" id="wtc-tabstrip"></div>
                    <div class="fc-stage" id="wtc-stage"></div>
                    <div class="fc-statusbar" role="status" aria-live="polite">
                        <div class="fc-status-left" id="wtc-status-windows"></div>
                        <div class="fc-status-right">
                            <button class="fc-status-help" id="wtc-help-btn" type="button" aria-haspopup="dialog"
                                aria-expanded="false" title="Keyboard shortcuts">? shortcuts</button>
                            <span class="fc-status-node" id="wtc-status-node"></span>
                        </div>
                    </div>
                    <div class="fc-help-popover" id="wtc-help-popover" role="dialog" aria-label="Keyboard shortcuts" hidden>
                        <div class="fc-help-title">Keyboard shortcuts</div>
                        <ul class="fc-help-list">
                            <li><kbd>+</kbd> New tab (same server)</li>
                            <li><kbd>Alt</kbd>+<kbd>T</kbd> New tab (pick a server)</li>
                            <li><kbd>Alt</kbd>+<kbd>1</kbd>…<kbd>9</kbd> Switch tab</li>
                            <li><kbd>Alt</kbd>+<kbd>\\</kbd> Split vertical</li>
                            <li><kbd>Alt</kbd>+<kbd>-</kbd> Split horizontal</li>
                            <li><kbd>Alt</kbd>+<kbd>W</kbd> Close pane</li>
                            <li><kbd>Alt</kbd>+<kbd>R</kbd> Rename tab</li>
                        </ul>
                        <div class="fc-help-foot">Shortcuts fire while the terminal has focus.</div>
                    </div>
                </div>`;
            inst.els.tabstrip = containerEl.querySelector('#wtc-tabstrip');
            inst.els.stage = containerEl.querySelector('#wtc-stage');
            inst.els.statusWindows = containerEl.querySelector('#wtc-status-windows');
            inst.els.statusNode = containerEl.querySelector('#wtc-status-node');
            inst.els.helpBtn = containerEl.querySelector('#wtc-help-btn');
            inst.els.helpPopover = containerEl.querySelector('#wtc-help-popover');
            inst.els.helpBtn.addEventListener('click', toggleHelp);

            inst.keyHandler = onKeydown;
            // Scoped to this instance's host element — never hijacks keys
            // elsewhere on the page.
            containerEl.addEventListener('keydown', inst.keyHandler, true);

            inst.resizeHandler = () => {
                if (inst.disposed) return;
                if (containerEl.offsetParent === null && containerEl.clientHeight === 0) return;
                const win = activeWindow();
                if (win) win.panes.forEach(fitPane);
            };
            window.addEventListener('resize', inst.resizeHandler);
        }

        function toggleHelp() {
            const pop = inst.els.helpPopover;
            if (!pop) return;
            const show = pop.hidden;
            pop.hidden = !show;
            if (inst.els.helpBtn) inst.els.helpBtn.setAttribute('aria-expanded', show ? 'true' : 'false');
        }

        function activeWindow() {
            return inst.windows.find(w => w.id === inst.activeWindow) || null;
        }

        // ── windows (tabs) ──
        function newWindow(o) {
            o = o || {};
            // A null node means the local serving node (local /ws/console);
            // wsUrlForPane handles that. Don't refuse to open a terminal just
            // because the node list isn't available — a local host shell needs
            // no node id.
            const node = o.node || selfNode() || null;
            const type = o.type || 'host';
            const target = (type === 'host') ? 'host' : (o.target || '');
            const extra = { pveNodeId: o.pveNodeId, pveVmid: o.pveVmid, noReconnect: o.noReconnect };
            const winId = 'wtcw-' + (inst.nextWin++);
            const defaultName = o.label
                || (type === 'pve'
                    ? `${nodeLabel(node)}:pve`
                    : `${node ? nodeLabel(node) + ':' : ''}${type}${type === 'host' ? '' : ':' + target}`);

            const stage = inst.els.stage;
            if (!stage) return null;
            const placeholder = stage.querySelector('.fc-empty');
            if (placeholder && placeholder.parentElement === stage) stage.removeChild(placeholder);

            const grid = document.createElement('div');
            grid.className = 'fc-grid fc-grid-single';
            grid.dataset.win = winId;
            stage.appendChild(grid);

            const win = {
                id: winId, name: defaultName, node: node,
                panes: [], layout: 'single', activePaneId: null, gridEl: grid,
                _splitterCleanups: [],
                // Remembered so "+ New Tab" can reopen the SAME server without
                // re-prompting (the operator just wants another shell to where
                // they already are).
                _origin: { node, type, target, pveNodeId: o.pveNodeId, pveVmid: o.pveVmid, noReconnect: o.noReconnect },
            };
            inst.windows.push(win);

            const pane = createPane(win, node, type, target, extra);
            win.panes.push(pane);
            win.activePaneId = pane.id;
            mountPane(pane);
            layoutWindow(win);

            switchWindow(winId);
            return win;
        }

        function closeWindow(winId) {
            const idx = inst.windows.findIndex(w => w.id === winId);
            if (idx < 0) return;
            const win = inst.windows[idx];
            if (win._splitterCleanups) { win._splitterCleanups.forEach(fn => { try { fn(); } catch (_) {} }); win._splitterCleanups = []; }
            win.panes.forEach(p => destroyPane(p, true));
            if (win.gridEl && win.gridEl.parentElement) win.gridEl.parentElement.removeChild(win.gridEl);
            inst.windows.splice(idx, 1);
            if (inst.activeWindow === winId) {
                const next = inst.windows[Math.max(0, idx - 1)];
                inst.activeWindow = next ? next.id : null;
            }
            if (inst.windows.length === 0) showEmptyStage();
            renderTabs();
            showActiveGrid();
            if (inst.activeWindow) onShow();
        }

        // Detach a tab into its OWN standalone window (console.html). Because a
        // live WebSocket can't move between windows, the pop-out opens a fresh
        // session to the same target and then closes the source tab — unless the
        // browser blocks the popup, in which case we keep the tab.
        function popoutWindow(winId) {
            const win = inst.windows.find(w => w.id === winId);
            if (!win || !win._origin) return;
            const o = win._origin;
            // host/pve carry no connection-significant target (host always
            // connects as 'host'; pve uses pveNodeId+vmid), so use the tab's
            // display name for a friendly window title. Other types MUST pass
            // the real target name — that's what the socket connects to.
            const nm = (o.type === 'pve' || o.type === 'host') ? (win.name || o.target || '') : (o.target || '');
            let url = '/console.html?type=' + encodeURIComponent(o.type) + '&name=' + encodeURIComponent(nm);
            if (o.node && o.node.id && !isSelf(o.node)) url += '&node_id=' + encodeURIComponent(o.node.id);
            if (o.pveNodeId) url += '&pve_node_id=' + encodeURIComponent(o.pveNodeId);
            if (o.pveVmid) url += '&pve_vmid=' + encodeURIComponent(o.pveVmid);
            // A UNIQUE window name so each pop-out is its own window — never the
            // shared 'wolfstack_terminal' popup.
            const w = window.open(url, 'wtc_popout_' + (inst.nextWin++), 'width=1000,height=640,menubar=no,toolbar=no');
            if (w) { closeWindow(winId); try { w.focus(); } catch (_) {} }
            else { toast('Pop-out blocked — allow pop-ups for this site', 'error'); }
        }

        function showEmptyStage() {
            const stage = inst.els.stage;
            if (!stage) return;
            if (!stage.querySelector('.fc-empty')) {
                const div = document.createElement('div');
                div.className = 'fc-empty';
                div.innerHTML = 'No tabs open. <button class="btn btn-sm btn-primary" type="button" data-act="new-tab">➕ New Tab</button>';
                const btn = div.querySelector('[data-act="new-tab"]');
                if (btn) btn.addEventListener('click', openPicker);
                stage.appendChild(div);
            }
        }

        function showActiveGrid() {
            inst.windows.forEach(w => {
                if (w.gridEl) w.gridEl.style.display = (w.id === inst.activeWindow) ? 'flex' : 'none';
            });
            renderStatusWindows();
            renderStatusNode();
        }

        function switchWindow(winId) {
            if (!inst.windows.some(w => w.id === winId)) return;
            inst.activeWindow = winId;
            renderTabs();
            showActiveGrid();
            onShow();
        }

        function renameWindow(winId) {
            const win = inst.windows.find(w => w.id === winId);
            if (!win) return;
            const name = window.prompt('Rename tab', win.name);
            if (name === null) return;
            win.name = name.trim() || win.name;
            renderTabs();
            renderStatusWindows();
        }

        // ── panes ──
        function createPane(win, node, type, target, extra) {
            extra = extra || {};
            const paneId = 'wtcp-' + (inst.nextPane++);
            const name = (type === 'host') ? 'host' : target;
            const nodeKey = (node && node.id) || 'local';
            const sessionKey = (type === 'pve')
                ? `${nodeKey}|pve|${extra.pveNodeId}|${extra.pveVmid}`
                : `${nodeKey}|${type}|${name}`;
            return {
                id: paneId, term: null, fit: null, ws: null,
                type: type, target: target, node: node,
                pveNodeId: extra.pveNodeId, pveVmid: extra.pveVmid,
                sessionKey: sessionKey,
                // One-shot streams (package installs, upgrades) close their
                // socket when the job ends — auto-reconnecting would just spin
                // forever, so the caller can opt out of reconnect for them.
                noReconnect: !!extra.noReconnect,
                userClosing: false,
                reconnect: { attempts: 0, timer: null },
                el: null, cell: null,
                isInitial: false,
            };
        }

        function mountPane(pane) {
            const cell = document.createElement('div');
            cell.className = 'fc-cell';
            cell.dataset.cell = pane.id;
            pane.cell = cell;

            const wrap = document.createElement('div');
            wrap.className = 'fc-pane';
            wrap.dataset.pane = pane.id;
            wrap.setAttribute('role', 'group');
            wrap.setAttribute('aria-label', `Terminal ${pane.type} ${pane.target || ''} on ${nodeLabel(pane.node)}`);
            wrap.innerHTML = `
                <div class="fc-pane-head">
                    <span class="fc-pane-title">${esc(nodeLabel(pane.node) + ' · ' + pane.type + (pane.target && pane.type !== 'host' && pane.type !== 'pve' ? ' · ' + pane.target : ''))}</span>
                    <span class="fc-pane-actions">
                        <button class="fc-pane-btn" type="button" title="Split top / bottom" data-act="split-h" aria-label="Split this pane horizontally">▤</button>
                        <button class="fc-pane-btn" type="button" title="Split left / right" data-act="split-v" aria-label="Split this pane vertically">▥</button>
                        <button class="fc-pane-btn" type="button" title="Reconnect" data-act="reconnect" aria-label="Reconnect this terminal">↻</button>
                        <button class="fc-pane-btn" type="button" title="Close pane" data-act="close" aria-label="Close this terminal">✕</button>
                    </span>
                </div>
                <div class="fc-pane-term" id="${pane.id}-term"></div>
                <div class="fc-pane-overlay" id="${pane.id}-overlay" hidden role="status" aria-live="polite"></div>`;
            cell.appendChild(wrap);
            pane.el = wrap;

            wrap.addEventListener('mousedown', () => setActivePane(pane.id));
            wrap.querySelector('[data-act="close"]').addEventListener('click', (e) => { e.stopPropagation(); closePane(pane.id); });
            wrap.querySelector('[data-act="reconnect"]').addEventListener('click', (e) => { e.stopPropagation(); manualReconnect(pane); });
            wrap.querySelector('[data-act="split-h"]').addEventListener('click', (e) => { e.stopPropagation(); setActivePane(pane.id); split('h'); });
            wrap.querySelector('[data-act="split-v"]').addEventListener('click', (e) => { e.stopPropagation(); setActivePane(pane.id); split('v'); });

            if (typeof Terminal === 'undefined') {
                wrap.querySelector('.fc-pane-term').innerHTML =
                    '<div class="fc-empty">xterm.js failed to load — refresh the page.</div>';
                return;
            }

            const term = new Terminal({
                cursorBlink: true,
                fontSize: 13,
                fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", "Courier New", monospace',
                theme: { background: '#0a0a0a', foreground: '#f0f0f0', cursor: '#10b981', selectionBackground: 'rgba(16,185,129,0.3)' },
                scrollback: 5000,
            });
            let fit = null;
            if (typeof FitAddon !== 'undefined') {
                fit = new FitAddon.FitAddon();
                term.loadAddon(fit);
            }
            term.open(wrap.querySelector('.fc-pane-term'));
            pane.term = term;
            pane.fit = fit;

            const refit = () => fitPane(pane);
            setTimeout(refit, 50);
            setTimeout(refit, 250);
            if (document.fonts && document.fonts.ready) document.fonts.ready.then(refit).catch(() => {});

            term.onData(d => { if (pane.ws && pane.ws.readyState === WebSocket.OPEN) pane.ws.send(d); });

            connectPane(pane);
        }

        // Centralised (re)connect. Phase-2 reattach-by-sessionKey lives here.
        function connectPane(pane) {
            if (!pane.term) return;
            if (pane.ws && (pane.ws.readyState === WebSocket.OPEN || pane.ws.readyState === WebSocket.CONNECTING)) return;
            const url = wsUrlForPane(pane);
            let ws;
            try { ws = new WebSocket(url); }
            catch (e) { showOverlay(pane, 'Connection failed — bad URL'); return; }
            ws.binaryType = 'arraybuffer';
            pane.ws = ws;

            ws.onopen = () => {
                pane.reconnect.attempts = 0;
                hideOverlay(pane);
                fitPane(pane); // sends resize frame too
                // Fire the after-initial-connect hook once, for the very
                // first pane (tab 1) — used by console.html to auto-run an
                // AI-action / predictive command against the opening shell.
                if (pane.isInitial && !inst.firstConnectFired) {
                    inst.firstConnectFired = true;
                    if (typeof opts.onAfterInitialConnect === 'function') {
                        try { opts.onAfterInitialConnect(pane); } catch (_) {}
                    }
                }
            };
            ws.onmessage = (event) => {
                if (typeof event.data === 'string') pane.term.write(event.data);
                else pane.term.write(new Uint8Array(event.data));
            };
            ws.onerror = () => { /* onclose handles reconnect */ };
            ws.onclose = () => {
                if (pane.userClosing) return;
                if (pane.noReconnect) {
                    // One-shot stream finished — leave the output on screen and
                    // tell the operator, rather than spinning the reconnect UI.
                    if (pane.term) { try { pane.term.writeln('\r\n\x1b[33m── session ended ──\x1b[0m'); } catch (_) {} }
                    return;
                }
                scheduleReconnect(pane);
            };
        }

        function scheduleReconnect(pane) {
            if (pane.reconnect.timer) return;
            const attempt = pane.reconnect.attempts || 0;
            const delay = Math.min(10000, 1000 * Math.pow(2, attempt));
            pane.reconnect.attempts = attempt + 1;
            showOverlay(pane, `Disconnected — reconnecting in ${Math.round(delay / 1000)}s… (attempt ${pane.reconnect.attempts})`);
            pane.reconnect.timer = setTimeout(() => {
                pane.reconnect.timer = null;
                if (pane.userClosing) return;
                showOverlay(pane, 'Reconnecting…');
                connectPane(pane);
            }, delay);
        }

        function manualReconnect(pane) {
            if (pane.reconnect.timer) { clearTimeout(pane.reconnect.timer); pane.reconnect.timer = null; }
            pane.reconnect.attempts = 0;
            if (pane.ws && pane.ws.readyState !== WebSocket.CLOSED) {
                try { pane.ws.onclose = null; pane.ws.close(); } catch (_) {}
                pane.ws = null;
            }
            showOverlay(pane, 'Reconnecting…');
            connectPane(pane);
        }

        function showOverlay(pane, msg) {
            if (!pane.el) return;
            const ov = pane.el.querySelector('.fc-pane-overlay');
            if (!ov) return;
            ov.hidden = false;
            ov.innerHTML = `<div class="fc-overlay-inner">
                <div class="fc-overlay-spin"></div>
                <div>${esc(msg)}</div>
                <button class="btn btn-sm" type="button" data-act="ov-reconnect">Reconnect now</button>
            </div>`;
            const btn = ov.querySelector('[data-act="ov-reconnect"]');
            if (btn) btn.onclick = (e) => { e.stopPropagation(); manualReconnect(pane); };
        }

        function hideOverlay(pane) {
            if (!pane.el) return;
            const ov = pane.el.querySelector('.fc-pane-overlay');
            if (ov) { ov.hidden = true; ov.innerHTML = ''; }
        }

        function fitPane(pane) {
            if (!pane.fit || !pane.term) return;
            try { pane.fit.fit(); } catch (_) { return; }
            if (pane.ws && pane.ws.readyState === WebSocket.OPEN) {
                try { pane.ws.send(JSON.stringify({ type: 'resize', cols: pane.term.cols, rows: pane.term.rows })); } catch (_) {}
            }
        }

        function destroyPane(pane, userClosing) {
            pane.userClosing = !!userClosing;
            if (pane.reconnect.timer) { clearTimeout(pane.reconnect.timer); pane.reconnect.timer = null; }
            if (pane.ws) {
                try { pane.ws.onclose = null; pane.ws.onmessage = null; pane.ws.onerror = null; pane.ws.close(); } catch (_) {}
                pane.ws = null;
            }
            if (pane.term) { try { pane.term.dispose(); } catch (_) {} pane.term = null; }
            pane.fit = null;
            if (pane.cell && pane.cell.parentElement) pane.cell.parentElement.removeChild(pane.cell);
            pane.cell = null;
            pane.el = null;
        }

        function closePane(paneId) {
            const win = inst.windows.find(w => w.panes.some(p => p.id === paneId));
            if (!win) return;
            const idx = win.panes.findIndex(p => p.id === paneId);
            if (idx < 0) return;
            if (win.panes.length === 1) { closeWindow(win.id); return; }
            destroyPane(win.panes[idx], true);
            win.panes.splice(idx, 1);
            if (win.activePaneId === paneId) win.activePaneId = win.panes[Math.max(0, idx - 1)].id;
            if (win.panes.length === 1) win.layout = 'single';
            layoutWindow(win);
        }

        function setActivePane(paneId) {
            const win = activeWindow();
            if (!win) return;
            win.activePaneId = paneId;
            win.panes.forEach(p => { if (p.el) p.el.classList.toggle('fc-pane-active', p.id === paneId); });
            const active = win.panes.find(p => p.id === paneId);
            if (active && active.term) { try { active.term.focus(); } catch (_) {} }
        }

        // Split the active pane. dir = 'v' (side-by-side) | 'h' (stacked).
        function split(dir) {
            const win = activeWindow();
            if (!win) return;
            const active = win.panes.find(p => p.id === win.activePaneId) || win.panes[0];
            if (!active) return;
            const pane = createPane(win, active.node, active.type, active.target,
                { pveNodeId: active.pveNodeId, pveVmid: active.pveVmid, noReconnect: active.noReconnect });
            win.panes.push(pane);
            win.layout = dir;
            win.activePaneId = pane.id;
            mountPane(pane);
            layoutWindow(win);
        }

        // ── rendering ──
        function renderTabs() {
            const strip = inst.els.tabstrip;
            if (!strip) return;
            strip.innerHTML = '';
            inst.windows.forEach((w, i) => {
                const tab = document.createElement('div');
                tab.className = 'fc-tab' + (w.id === inst.activeWindow ? ' fc-tab-active' : '');
                tab.setAttribute('role', 'tab');
                tab.setAttribute('tabindex', w.id === inst.activeWindow ? '0' : '-1');
                tab.setAttribute('aria-selected', w.id === inst.activeWindow ? 'true' : 'false');
                tab.innerHTML = `
                    <span class="fc-tab-num">${i + 1}</span>
                    <span class="fc-tab-name" title="Double-click to rename">${esc(w.name)}</span>
                    <button class="fc-tab-popout" type="button" title="Pop out into its own window" aria-label="Pop out tab ${escAttr(w.name)}">⧉</button>
                    <button class="fc-tab-close" type="button" title="Close tab" aria-label="Close tab ${escAttr(w.name)}">✕</button>`;
                tab.addEventListener('click', () => switchWindow(w.id));
                tab.querySelector('.fc-tab-name').addEventListener('dblclick', (e) => { e.stopPropagation(); renameWindow(w.id); });
                tab.querySelector('.fc-tab-popout').addEventListener('click', (e) => { e.stopPropagation(); popoutWindow(w.id); });
                tab.querySelector('.fc-tab-close').addEventListener('click', (e) => { e.stopPropagation(); closeWindow(w.id); });
                strip.appendChild(tab);
            });

            const add = document.createElement('button');
            add.className = 'fc-tab-add';
            add.type = 'button';
            add.title = 'New tab — same server (Alt+T to pick a different one)';
            add.setAttribute('aria-label', 'New terminal tab for the same server');
            add.textContent = '➕ New Tab';
            // Default: open another tab to the SAME server as the active tab, no
            // prompt. Only fall back to the picker when there's nothing open to
            // duplicate (the picker is still on Alt+T for a different server).
            add.addEventListener('click', () => {
                const w = activeWindow();
                if (w && w._origin) newWindow(w._origin);
                else openPicker();
            });
            strip.appendChild(add);

            // Split controls live on the right of the tab strip so they are
            // ALWAYS visible (the #1 complaint was not finding split).
            const tools = document.createElement('div');
            tools.className = 'fc-tabstrip-tools';
            tools.innerHTML = `
                <button class="fc-tool-btn" type="button" data-act="split-h" title="Split top / bottom (Alt+-)" aria-label="Split horizontally">Split ▤</button>
                <button class="fc-tool-btn" type="button" data-act="split-v" title="Split left / right (Alt+\\)" aria-label="Split vertically">Split ▥</button>`;
            tools.querySelector('[data-act="split-h"]').addEventListener('click', () => split('h'));
            tools.querySelector('[data-act="split-v"]').addEventListener('click', () => split('v'));
            strip.appendChild(tools);

            renderStatusWindows();
        }

        function layoutWindow(win) {
            const grid = win.gridEl;
            if (!grid) return;
            if (win._splitterCleanups) win._splitterCleanups.forEach(fn => { try { fn(); } catch (_) {} });
            win._splitterCleanups = [];

            win.panes.forEach(p => { if (p.cell && p.cell.parentElement) p.cell.parentElement.removeChild(p.cell); });
            Array.from(grid.querySelectorAll('.fc-splitter')).forEach(s => s.remove());

            const layout = (win.panes.length === 1) ? 'single' : win.layout;
            grid.className = 'fc-grid fc-grid-' + layout;

            win.panes.forEach((pane, i) => {
                if (i > 0) {
                    const sp = document.createElement('div');
                    sp.className = 'fc-splitter fc-splitter-' + win.layout;
                    sp.setAttribute('role', 'separator');
                    sp.setAttribute('aria-orientation', win.layout === 'v' ? 'vertical' : 'horizontal');
                    sp.title = 'Drag to resize';
                    wireSplitter(sp, win, i);
                    grid.appendChild(sp);
                }
                pane.cell.style.flex = '1 1 0';
                grid.appendChild(pane.cell);
            });

            setActivePane(win.activePaneId || (win.panes[0] && win.panes[0].id));
            const refit = () => win.panes.forEach(fitPane);
            requestAnimationFrame(refit);
            setTimeout(refit, 120);
            renderStatusWindows();
            renderStatusNode();
        }

        function wireSplitter(sp, win, paneIndex) {
            let dragging = false;
            const onDown = (e) => {
                dragging = true;
                sp.classList.add('fc-splitter-drag');
                document.body.style.cursor = win.layout === 'v' ? 'col-resize' : 'row-resize';
                e.preventDefault();
            };
            const onMove = (e) => {
                if (!dragging) return;
                const pa = win.panes[paneIndex - 1], pb = win.panes[paneIndex];
                const a = pa && pa.cell, b = pb && pb.cell;
                if (!a || !b) return;
                const rectA = a.getBoundingClientRect(), rectB = b.getBoundingClientRect();
                const total = (win.layout === 'v') ? (rectA.width + rectB.width) : (rectA.height + rectB.height);
                if (total <= 0) return;
                const pos = (win.layout === 'v') ? e.clientX : e.clientY;
                const start = (win.layout === 'v') ? rectA.left : rectA.top;
                let fracA = (pos - start) / total;
                fracA = Math.max(0.12, Math.min(0.88, fracA));
                a.style.flex = `${fracA} 1 0`;
                b.style.flex = `${1 - fracA} 1 0`;
                fitPane(pa);
                fitPane(pb);
            };
            const onUp = () => {
                if (!dragging) return;
                dragging = false;
                sp.classList.remove('fc-splitter-drag');
                document.body.style.cursor = '';
                win.panes.forEach(fitPane);
            };
            sp.addEventListener('mousedown', onDown);
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
            win._splitterCleanups.push(() => {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
            });
        }

        function renderStatusWindows() {
            const el = inst.els.statusWindows;
            if (!el) return;
            el.innerHTML = inst.windows.map((w, i) => {
                const active = w.id === inst.activeWindow;
                return `<span class="fc-statwin${active ? ' fc-statwin-active' : ''}">${i + 1}:${esc(w.name)}</span>`;
            }).join(' ') || '<span class="fc-statwin">no tabs</span>';
        }

        function renderStatusNode() {
            const el = inst.els.statusNode;
            if (!el) return;
            const win = activeWindow();
            el.textContent = win ? nodeLabel(win.node) : '';
        }

        // ── new-tab picker ──
        function defaultFetchTargets(nodeId, type) {
            // Used when the caller doesn't supply fetchTargets (e.g. the
            // pop-out window). Routes self-node directly, others via proxy.
            const node = nodeById(nodeId);
            const self = isSelf(node);
            const proxy = (p) => self ? p : `/api/nodes/${encodeURIComponent(nodeId)}/proxy${p}`;
            const get = (p) => fetch(proxy(p)).then(r => r.ok ? r.json() : []).catch(() => []);
            if (type === 'vm') {
                return get('/api/vms').then(vms =>
                    (Array.isArray(vms) ? vms : []).map(v => v.name).filter(Boolean)
                        .map(n => ({ value: n, label: n })));
            }
            return get('/api/containers/running').then(cs =>
                (Array.isArray(cs) ? cs : []).filter(c => c.runtime === type).map(c => c.name).filter(Boolean)
                    .map(n => ({ value: n, label: n })));
        }

        function loadTargets(nodeId, type) {
            const fn = (typeof opts.fetchTargets === 'function') ? opts.fetchTargets : defaultFetchTargets;
            try {
                const r = fn(nodeId, type);
                return Promise.resolve(r).then(list => Array.isArray(list) ? list : []).catch(() => []);
            } catch (_) { return Promise.resolve([]); }
        }

        function openPicker() {
            // Guard against a second overlay from rapid Alt+T / double-click.
            if (document.querySelector('.wtc-picker-overlay')) return;
            const nodes = getNodes().filter(n => n.node_type !== 'proxmox');
            const self = selfNode();
            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay active wtc-picker-overlay';
            overlay.style.cssText = 'display:flex; z-index:10060;';
            const nodeOpts = nodes.map(n => {
                const label = (n.hostname || n.address || n.id) + (isSelf(n) ? ' (this node)' : '') + (n.online === false ? ' — offline' : '');
                const sel = (self && n.id === self.id) ? ' selected' : '';
                return `<option value="${escAttr(n.id)}"${sel}>${esc(label)}</option>`;
            }).join('');
            overlay.innerHTML = `
                <div class="fc-picker" role="dialog" aria-label="Open a new terminal tab" aria-modal="true"
                     style="background:var(--bg-card); border:1px solid var(--border); border-radius:14px; padding:24px; max-width:440px; width:92%; box-shadow:0 20px 60px rgba(0,0,0,0.5);">
                    <h3 style="color:var(--text-primary); font-size:16px; font-weight:700; margin:0 0 14px;">New terminal tab</h3>
                    <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Node</label>
                    <select id="wtc-pick-node" style="width:100%; padding:8px 10px; border-radius:8px; border:1px solid var(--border); background:var(--bg-secondary); color:var(--text-primary); margin-bottom:12px;">${nodeOpts}</select>
                    <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Type</label>
                    <select id="wtc-pick-type" style="width:100%; padding:8px 10px; border-radius:8px; border:1px solid var(--border); background:var(--bg-secondary); color:var(--text-primary); margin-bottom:12px;">
                        <option value="host">Host shell</option>
                        <option value="docker">Docker container</option>
                        <option value="lxc">LXC container</option>
                        <option value="vm">Virtual machine</option>
                    </select>
                    <div id="wtc-pick-target-wrap" style="display:none; margin-bottom:12px;">
                        <label style="display:block; font-size:12px; color:var(--text-secondary); margin-bottom:4px;">Target</label>
                        <select id="wtc-pick-target" style="width:100%; padding:8px 10px; border-radius:8px; border:1px solid var(--border); background:var(--bg-secondary); color:var(--text-primary);">
                            <option value="">Loading…</option>
                        </select>
                    </div>
                    <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:6px;">
                        <button class="btn btn-sm" type="button" id="wtc-pick-cancel">Cancel</button>
                        <button class="btn btn-primary btn-sm" type="button" id="wtc-pick-open">Open tab</button>
                    </div>
                </div>`;
            document.body.appendChild(overlay);

            const typeSel = overlay.querySelector('#wtc-pick-type');
            const nodeSel = overlay.querySelector('#wtc-pick-node');
            const targetWrap = overlay.querySelector('#wtc-pick-target-wrap');
            const targetSel = overlay.querySelector('#wtc-pick-target');

            const refreshTargets = () => {
                const type = typeSel.value;
                if (type === 'host') { targetWrap.style.display = 'none'; return; }
                targetWrap.style.display = 'block';
                targetSel.innerHTML = '<option value="">Loading…</option>';
                loadTargets(nodeSel.value, type).then(list => {
                    if (!list.length) { targetSel.innerHTML = '<option value="">None found</option>'; return; }
                    targetSel.innerHTML = list.map(t => `<option value="${escAttr(t.value)}">${esc(t.label)}</option>`).join('');
                });
            };
            typeSel.addEventListener('change', refreshTargets);
            nodeSel.addEventListener('change', refreshTargets);

            const closePicker = () => {
                document.removeEventListener('keydown', escHandler, true);
                if (overlay.parentElement) overlay.remove();
            };
            const escHandler = (e) => { if (e.key === 'Escape') { e.stopPropagation(); closePicker(); } };
            document.addEventListener('keydown', escHandler, true);

            overlay.querySelector('#wtc-pick-cancel').addEventListener('click', closePicker);
            overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) closePicker(); });
            overlay.querySelector('#wtc-pick-open').addEventListener('click', () => {
                const node = nodes.find(n => n.id === nodeSel.value) || self;
                const type = typeSel.value;
                const target = (type === 'host') ? 'host' : targetSel.value;
                if (type !== 'host' && !target) { toast('Pick a target', 'error'); return; }
                closePicker();
                newWindow({ node, type, target });
            });
            nodeSel.focus();
        }

        // ── keyboard ──
        function onKeydown(e) {
            if (!e.altKey || e.ctrlKey || e.metaKey) return;
            const k = e.key;
            if (k === 't' || k === 'T') { e.preventDefault(); openPicker(); return; }
            if (k === 'w' || k === 'W') { e.preventDefault(); const w = activeWindow(); if (w) closePane(w.activePaneId); return; }
            if (k === 'r' || k === 'R') { e.preventDefault(); const w = activeWindow(); if (w) renameWindow(w.id); return; }
            if (k === '\\') { e.preventDefault(); split('v'); return; }
            if (k === '-') { e.preventDefault(); split('h'); return; }
            if (k >= '1' && k <= '9') {
                const idx = parseInt(k, 10) - 1;
                if (inst.windows[idx]) { e.preventDefault(); switchWindow(inst.windows[idx].id); }
                return;
            }
        }

        // ── lifecycle / public ──
        function onShow() {
            const win = activeWindow();
            if (!win) return;
            const refit = () => win.panes.forEach(fitPane);
            requestAnimationFrame(refit);
            setTimeout(refit, 120);
            const active = win.panes.find(p => p.id === win.activePaneId) || win.panes[0];
            if (active && active.term) { try { active.term.focus(); } catch (_) {} }
        }

        // Compute the session key a descriptor would produce, so callers can
        // dedupe (re-navigation to an already-open session focuses its tab
        // instead of spawning a duplicate).
        function descriptorKey(o) {
            o = o || {};
            const node = resolveNode((o || {}).nodeId);
            const nodeKey = (node && node.id) || 'local';
            const type = o.type || 'host';
            if (type === 'pve') return `${nodeKey}|pve|${o.pveNodeId}|${o.pveVmid}`;
            const name = (type === 'host') ? 'host' : (o.name || o.target || '');
            return `${nodeKey}|${type}|${name}`;
        }

        // Focus an existing tab whose tab-1 pane matches the descriptor.
        // Returns the window id if found, else null.
        function focusTab(o) {
            const key = descriptorKey(o);
            if (!key) return null;
            const win = inst.windows.find(w => w.panes[0] && w.panes[0].sessionKey === key);
            if (!win) return null;
            switchWindow(win.id);
            return win.id;
        }

        function addTab(o) {
            o = o || {};
            // Honour an explicit nodeId even if it isn't in this window's node
            // list (see resolveNode) — never fall back to the wrong host, which
            // ran pct/lxc-attach against the previous tab's node.
            const node = resolveNode(o.nodeId);
            const type = o.type || 'host';
            const target = (type === 'host' || type === 'pve') ? '' : (o.name || o.target || '');
            const win = newWindow({
                node, type, target, label: o.label,
                pveNodeId: o.pveNodeId, pveVmid: o.pveVmid, noReconnect: o.noReconnect,
            });
            return win ? win.id : null;
        }

        function dispose() {
            if (inst.disposed) return;
            inst.disposed = true;
            if (inst.keyHandler) { try { containerEl.removeEventListener('keydown', inst.keyHandler, true); } catch (_) {} }
            if (inst.resizeHandler) { try { window.removeEventListener('resize', inst.resizeHandler); } catch (_) {} }
            inst.windows.slice().forEach(w => {
                if (w._splitterCleanups) { w._splitterCleanups.forEach(fn => { try { fn(); } catch (_) {} }); }
                w.panes.forEach(p => destroyPane(p, true));
                if (w.gridEl && w.gridEl.parentElement) w.gridEl.parentElement.removeChild(w.gridEl);
            });
            inst.windows = [];
            inst.activeWindow = null;
            // Drop the shell chrome (tabstrip / statusbar / help popover and
            // their listeners) so a later mount() on the same element starts
            // clean.
            try { containerEl.classList.remove('wtc-host'); containerEl.innerHTML = ''; } catch (_) {}
        }

        // ── build + open the initial tab ──
        buildShell();
        const initial = opts.initial || {};
        // A session was requested if the URL/caller gave us a type, name, or PVE
        // target — open it as tab 1 even when no node object resolves (a local
        // host shell needs no node id; the node list is only for the picker).
        const hasInitial = !!(initial.type || initial.name || initial.pveVmid);
        const initialNode = resolveNode(initial.nodeId);
        if (hasInitial) {
            const type = initial.type || 'host';
            const target = (type === 'host' || type === 'pve') ? '' : (initial.name || initial.target || '');
            const win = newWindow({
                node: initialNode, type, target, label: initial.label,
                pveNodeId: initial.pveNodeId, pveVmid: initial.pveVmid,
                noReconnect: initial.noReconnect,
            });
            if (win && win.panes[0]) win.panes[0].isInitial = true;
        } else {
            // Nothing requested — show an empty stage with a New Tab button.
            showEmptyStage();
            renderTabs();
        }

        return {
            addTab: addTab,
            focusTab: focusTab,
            splitActive: (dir) => split(dir === 'h' ? 'h' : 'v'),
            closeActivePane: () => { const w = activeWindow(); if (w) closePane(w.activePaneId); },
            openPicker: openPicker,
            onShow: onShow,
            dispose: dispose,
            get activeWindowId() { return inst.activeWindow; },
        };
    }

    window.WolfTermConsole = { mount: mount };
})();
