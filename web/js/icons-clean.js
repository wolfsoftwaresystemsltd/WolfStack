/* Written by Paul Clevett */
/* (C)Copyright Wolf Software Systems Ltd */
/* https://wolf.uk.com */

// ─── Clean Icon Theme — Lucide-backed ─────────────────────────────────
// Two render paths, both produce inline SVG using the bundled Lucide
// library (web/js/vendor/lucide.min.js, ISC). currentColor + small box
// model so icons inherit theme palette.
//
//   1. fillDataIconPlaceholders(root)
//        Walks `[data-icon]` placeholders inserted in static markup and
//        injects the Lucide SVG. Runs once at boot AND on every DOM
//        mutation so dynamically-injected placeholders fill themselves.
//        Theme-independent — runs on every icon theme including
//        `standard` (emoji), because emoji-as-icons in source got
//        replaced with these placeholders.
//
//   2. translateEmojisToCleanSvg(root)
//        Walks text nodes for any emoji glyph that maps to a semantic
//        name via EMOJI_TO_SEMANTIC, replaces with a wrapped Lucide
//        SVG. Active only when the user's icon theme is `clean`.
//        Used to render emoji values stored in data tables
//        (MOUNT_TYPE_ICONS, BOOKMARK_ICONS, etc.).
//
// Klas-readable design note: each semantic name we use in the codebase
// maps to a Lucide icon name. The map exists because Lucide names some
// concepts differently (`zap` vs `lightning`, `bar-chart-2` vs `chart`).

// Semantic → Lucide name. Lucide expects kebab-case in the data
// attribute when using createIcons; the same conventions are used here.
const LUCIDE_NAME_MAP = {
    // Core chrome
    'home':         'home',
    'package':      'package',
    'settings':     'settings',
    'computer':     'monitor',
    'save':         'save',
    'globe':        'globe',
    'lock':         'lock',
    'key':          'key',
    'chart':        'bar-chart-2',
    'chart-up':     'trending-up',
    'wrench':       'wrench',
    'tools':        'wrench',
    'edit':         'pencil',
    'clipboard':    'clipboard',
    'database':     'database',
    'satellite':    'satellite',
    'cloud':        'cloud',
    'fire':         'flame',
    'chat':         'message-circle',
    'email':        'mail',
    'rocket':       'rocket',
    'appstore':     'store',
    'lightning':    'zap',
    'laptop':       'laptop',
    'brain':        'brain',
    'folder':       'folder',
    'folder-open':  'folder-open',
    'lightbulb':    'lightbulb',
    'document':     'file-text',
    'pin':          'pin',
    'shield':       'shield',
    'link':         'link-2',
    'file-data':    'database',
    'bell':         'bell',
    'megaphone':    'megaphone',
    'image':        'image',
    'camera':       'camera',
    'scale':        'scale',
    'money':        'dollar-sign',
    'palette':      'palette',
    'robot':        'bot',
    'heart':        'heart',
    'warning':      'alert-triangle',
    'help':         'circle-help',
    'add':          'plus',
    'door':         'door-open',
    'search':       'search',
    'gamepad':      'gamepad-2',
    'music':        'music',
    'cart':         'shopping-cart',
    'book':         'book-open',
    'lab':          'flask-conical',
    'star':         'star',
    'runner':       'activity',
    'movie':        'film',
    'target':       'target',
    'file-code':    'file-code',
    'refresh':      'refresh-ccw',
    'refresh-cw':   'refresh-cw',
    'clock':        'clock',
    'cluster':      'boxes',
    'box':          'box',
    'cpu':          'cpu',
    'memory':       'memory-stick',
    'list':         'list',
    'trash':        'trash-2',
    'plug':         'plug',
    'calendar':     'calendar',
    'download':     'download',
    'upload':       'upload',
    'menu':         'menu',
    'fullscreen':   'maximize',
    'health':       'activity',
    'compass':      'compass',
    'broom':        'sparkles',
    'docker':       'container',
    'bookmark':     'bookmark',
    'minus':        'minus',
    'inbox':        'inbox',
    'hard-drive':   'hard-drive',
    'disc':         'disc',
    'sliders':      'sliders-horizontal',
    'puzzle':       'puzzle',
    'smartphone':   'smartphone',
    'eye':          'eye',
    'user':         'user',
    'siren':        'siren',
    // Container action buttons (start / stop / restart / etc.)
    'play':         'play',
    'stop':         'square',
    'power':        'power',
    'restart':      'rotate-ccw',
    'pause':        'pause',
    'snowflake':    'snowflake',
    'terminal':     'terminal',
    'monitor':      'monitor',
    'copy':         'copy',
    'migrate':      'arrow-left-right',
    'configure':    'sliders-horizontal',
    'updates':      'download',
    'export':       'upload',
    'logs':         'file-text',
    'arrow-right':  'arrow-right',
    'arrow-left':   'arrow-left',
    'share-2':      'share-2',
    'maximize':     'maximize',
    'minimize':     'minimize',
    // Fallbacks for decorative-emoji-as-data entries (MOUNT_TYPE_ICONS,
    // EMOJI_TO_SEMANTIC, etc.). Lucide doesn't ship a wolf — paw-print
    // is the closest "animal mascot" glyph and renders consistently
    // alongside the other line icons.
    'wolf':         'paw-print',
    'penguin':      'feather',
    'fox':          'paw-print',
    'elephant':     'database',
    'whale':        'container',
    'alien':        'ghost',

    // Status indicators
    'check':         'check',
    'check-circle':  'circle-check',
    'close':         'x',
    'x-circle':      'circle-x',
    'circle-red':    'circle',
    'circle-green':  'circle',
    'circle-yellow': 'circle',
    'circle-blue':   'circle',
};

// Filled status circles keep their semantic colour even when used in
// a generic text context.
const CLEAN_ICON_COLOURS = {
    'circle-red':    'var(--danger)',
    'circle-green':  'var(--success)',
    'circle-yellow': 'var(--warning)',
    'circle-blue':   'var(--info)',
};

// Extra emoji → semantic mappings the app.js table doesn't carry.
// Merged into EMOJI_TO_SEMANTIC at boot if the global exists.
const CLEAN_EXTRA_EMOJI_MAP = {
    '🔄': 'refresh',
    '🗑': 'trash', '🗑️': 'trash',
    '🔌': 'plug',
    '✅': 'check-circle',
    '❌': 'x-circle',
    '✓': 'check',
    '✗': 'close', '✕': 'close',
    '➕': 'add',
    '🔴': 'circle-red',
    '🟢': 'circle-green',
    '🟡': 'circle-yellow',
    '🔵': 'circle-blue',
    '✏️': 'edit', '✏': 'edit', '✎': 'edit',
    '🔍': 'search',
};

// Lucide's icon definitions are [tag, attrs, children] arrays. Pure
// recursive serialiser — no DOM, just string concatenation so we can
// produce an SVG without touching document.createElement.
function lucideNodeToSvg(node) {
    if (Array.isArray(node)) {
        const [tag, attrs, children] = node;
        const attrStr = Object.entries(attrs || {})
            .map(([k, v]) => ` ${k}="${String(v).replace(/"/g, '&quot;')}"`)
            .join('');
        const childStr = Array.isArray(children)
            ? children.map(lucideNodeToSvg).join('')
            : '';
        return `<${tag}${attrStr}>${childStr}</${tag}>`;
    }
    return '';
}

// Memoise the SVG-string lookups — Lucide tree walking is repeated
// thousands of times per page on a 14-node dashboard otherwise.
const _CLEAN_ICON_SVG_CACHE = Object.create(null);

// Resolve a semantic name to an SVG string via Lucide. Returns '' if
// Lucide hasn't loaded yet (boot-order safety) or the icon doesn't
// exist — callers should treat empty as "leave the placeholder alone
// this tick, fillDataIconPlaceholders will retry on the next mutation".
function cleanIconSvg(semantic) {
    if (semantic in _CLEAN_ICON_SVG_CACHE) {
        const v = _CLEAN_ICON_SVG_CACHE[semantic];
        if (v !== '') return v;
        // Empty might be a "Lucide not loaded yet" miss — fall through
        // and retry. Once we have a real SVG it sticks.
    }
    const lucideName = LUCIDE_NAME_MAP[semantic];
    if (!lucideName) return '';
    const lib = (typeof window !== 'undefined' && window.lucide) ? window.lucide : null;
    if (!lib || !lib.icons) return '';
    // Lucide v1+ exposes `icons` keyed by both PascalCase and kebab-case.
    // We use kebab-case for predictability.
    const def = lib.icons[lucideName]
        || lib.icons[toPascal(lucideName)];
    if (!def) return '';
    // Lucide v1+ icon definitions are an array of [tag, attrs] children
    // (no outer <svg> wrapper) — we wrap them ourselves so we control
    // viewBox / stroke / aria attrs uniformly across themes.
    const children = Array.isArray(def) ? def : (def.default || []);
    if (!Array.isArray(children) || children.length === 0) return '';
    const colour = CLEAN_ICON_COLOURS[semantic];
    const style = colour ? ` style="color:${colour}"` : '';
    const svg = `<svg class="ws-icon-clean" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"${style}>${
        children.map(lucideNodeToSvg).join('')
    }</svg>`;
    _CLEAN_ICON_SVG_CACHE[semantic] = svg;
    return svg;
}

function toPascal(kebab) {
    return kebab.split('-').map(s => s ? s[0].toUpperCase() + s.slice(1) : '').join('');
}

function cleanIconAvailable(semantic) {
    if (!Object.prototype.hasOwnProperty.call(LUCIDE_NAME_MAP, semantic)) return false;
    return cleanIconSvg(semantic) !== '';
}

// Drop-in for use inside template literals: `${wsIcon('refresh')} Refresh`
function wsIcon(semantic) {
    const body = cleanIconSvg(semantic);
    if (!body) return '';
    return `<span class="ws-icon-clean-wrap" data-icon="${semantic}">${body}</span>`;
}

// ─── data-icon placeholder filler ────────────────────────────────────

// Inverse lookup: semantic name → emoji glyph. Built lazily from
// EMOJI_TO_SEMANTIC the first time we need it (after app.js has had a
// chance to define that table). Lets the `standard` and `candy_emoji`
// themes render their glyph in static `[data-icon]` placeholders so
// switching themes actually changes what users see.
let _semanticToEmoji = null;
function semanticToEmoji(semantic) {
    if (typeof EMOJI_TO_SEMANTIC === 'undefined') return '';
    if (!_semanticToEmoji) {
        _semanticToEmoji = {};
        for (const [emoji, sem] of Object.entries(EMOJI_TO_SEMANTIC)) {
            // First-write wins so a single canonical emoji per semantic.
            if (!(sem in _semanticToEmoji)) _semanticToEmoji[sem] = emoji;
        }
        // Fill in the extras icons-clean knows about that aren't in app.js's table.
        for (const [emoji, sem] of Object.entries(CLEAN_EXTRA_EMOJI_MAP)) {
            if (!(sem in _semanticToEmoji)) _semanticToEmoji[sem] = emoji;
        }
    }
    return _semanticToEmoji[semantic] || '';
}

function fillDataIconPlaceholders(root) {
    const scope = root || document.body;
    const theme = (typeof currentIconTheme !== 'undefined') ? currentIconTheme : 'clean';
    // klasSponsor 2026-05-11: switching to an installed icon pack
    // (BeautyLine) was a no-op because this function unconditionally
    // filled every [data-icon] placeholder with Lucide for non-emoji
    // themes — there was no icon-pack branch. The runtime emoji-
    // translator (`replaceEmojisWithPackIcons`) only handles emoji
    // glyphs in text nodes, not the empty [data-icon] spans that
    // make up most of the chrome. Net effect: pack themes looked
    // identical to `clean`. The new branch below renders each
    // placeholder as <img src="/api/icon-packs/{pack}/icon/{semantic}">
    // when the active pack lists that semantic in its `available`
    // set, and falls back to Lucide on load error (so a
    // pack-not-installed-on-this-cluster-node case still renders
    // something rather than a broken-image icon).
    const isPackTheme = !(theme in BUILTIN_ICON_THEMES);
    const packAvailable = (typeof _activePackAvailable !== 'undefined') ? _activePackAvailable : null;
    scope.querySelectorAll('[data-icon]').forEach(el => {
        const semantic = el.getAttribute('data-icon');
        if (!semantic) return;
        // Try theme-specific render first. For `standard` / `candy_emoji`,
        // if the semantic doesn't have an emoji glyph mapping, fall back
        // to Lucide so the placeholder never ends up blank — better a
        // line icon than missing chrome.
        if (theme === 'standard' || theme === 'candy_emoji') {
            let glyph = semanticToEmoji(semantic);
            if (glyph) {
                if (theme === 'candy_emoji' && typeof CANDY_ICON_MAP !== 'undefined' && CANDY_ICON_MAP[glyph]) {
                    glyph = CANDY_ICON_MAP[glyph];
                }
                el.textContent = glyph;
                el.classList.remove('ws-icon-clean-wrap');
                return;
            }
            // No emoji for this semantic — fall through to Lucide below.
        } else if (isPackTheme && packAvailable && packAvailable.has(semantic)) {
            // Pack-icon branch — see comment block above.
            if (el.querySelector('img.ws-icon-pack-img')) return;
            const url = `/api/icon-packs/${encodeURIComponent(theme)}/icon/${encodeURIComponent(semantic)}`;
            const img = document.createElement('img');
            img.className = 'ws-icon-pack-img';
            img.src = url;
            img.alt = semantic;
            img.style.cssText = 'width:1em;height:1em;vertical-align:-0.125em;display:inline-block;';
            img.onerror = function () {
                // Pack file missing for this semantic (e.g. pack not
                // installed on the node serving this request — cluster
                // setups where icon-pack install is per-node). Fall
                // back to Lucide rather than showing a broken-image.
                if (cleanIconAvailable(semantic)) {
                    el.innerHTML = cleanIconSvg(semantic);
                    if (!el.classList.contains('ws-icon-clean-wrap')) el.classList.add('ws-icon-clean-wrap');
                } else {
                    el.innerHTML = '';
                }
            };
            // Clear any prior Lucide content so the pack image replaces it.
            el.innerHTML = '';
            el.appendChild(img);
            if (!el.classList.contains('ws-icon-clean-wrap')) el.classList.add('ws-icon-clean-wrap');
            return;
        }
        // Lucide fallback (clean theme, or pack theme where the pack
        // doesn't have this semantic, or pack data hasn't loaded yet
        // — `initIconTheme` re-runs this function after fetching the
        // pack's available set, which is when packAvailable populates).
        if (el.querySelector('svg.ws-icon-clean')) return;
        if (el.querySelector('img.ws-icon-pack-img')) return;
        if (!cleanIconAvailable(semantic)) return;
        if (!el.classList.contains('ws-icon-clean-wrap')) el.classList.add('ws-icon-clean-wrap');
        el.innerHTML = cleanIconSvg(semantic);
    });
}

let _dataIconObserver = null;
function observeForDataIcons() {
    if (_dataIconObserver) return;
    _dataIconObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;
                if (node.matches?.('[data-icon]') || node.querySelector?.('[data-icon]')) {
                    fillDataIconPlaceholders(node);
                }
            }
        }
    });
    _dataIconObserver.observe(document.body, { childList: true, subtree: true });
}

// ─── Emoji-in-text-node → SVG translator (active on `clean` theme) ──

let _cleanIconReplacing = false;

function translateEmojisToCleanSvg(root) {
    if (_cleanIconReplacing) return;
    if (typeof EMOJI_TO_SEMANTIC === 'undefined') return;
    // Cheap pre-check: if the subtree's textContent has no known emoji
    // at all, skip the full TreeWalker. Saves an enormous amount of
    // work on 14-node dashboards where most DOM updates carry no emoji.
    buildEmojiRegex();
    if (_emojiMatchRegex && root.textContent && !_emojiMatchRegex.test(root.textContent)) return;
    _cleanIconReplacing = true;
    try {
        const textNodes = [];
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
            acceptNode(node) {
                const p = node.parentElement;
                if (!p) return NodeFilter.FILTER_REJECT;
                if (p.closest('[data-no-translate]')) return NodeFilter.FILTER_REJECT;
                if (p.classList?.contains('ws-icon-clean-wrap')) return NodeFilter.FILTER_REJECT;
                const tag = p.tagName;
                if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'INPUT' || tag === 'TEXTAREA') return NodeFilter.FILTER_REJECT;
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        while (walker.nextNode()) textNodes.push(walker.currentNode);

        for (const textNode of textNodes) {
            replaceEmojiNodeWithCleanSvg(textNode);
        }
    } finally {
        _cleanIconReplacing = false;
    }
}

// Build a single regex that matches ANY known emoji, plus a fast
// lookup from glyph → semantic. The pre-v22.14.5 path iterated
// Object.entries(EMOJI_TO_SEMANTIC) (200+ keys) and called
// `text.indexOf(emoji)` for each — 200× the work per text node, which
// on a 14-node dashboard with frequent mutation observers added up to
// observable lag. The regex test below short-circuits in one pass.
let _emojiMatchRegex = null;
let _emojiToSemanticCache = null;
function buildEmojiRegex() {
    if (_emojiMatchRegex && _emojiToSemanticCache) return;
    if (typeof EMOJI_TO_SEMANTIC === 'undefined') return;
    const glyphs = [];
    const map = {};
    for (const [emoji, semantic] of Object.entries(EMOJI_TO_SEMANTIC)) {
        if (!cleanIconAvailable(semantic)) continue;
        glyphs.push(emoji);
        map[emoji] = semantic;
    }
    if (glyphs.length === 0) return;
    // Longest-first ensures composite emojis (e.g. `⚙️` with VS16) match
    // before their bare-codepoint prefix.
    glyphs.sort((a, b) => b.length - a.length);
    const pattern = glyphs.map(g => g.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    _emojiMatchRegex = new RegExp(pattern);
    _emojiToSemanticCache = map;
}

function replaceEmojiNodeWithCleanSvg(textNode) {
    buildEmojiRegex();
    if (!_emojiMatchRegex) return;
    let node = textNode;
    let safety = 50;
    while (node && node.parentNode && safety-- > 0) {
        const text = node.nodeValue;
        if (!text) return;
        const m = _emojiMatchRegex.exec(text);
        if (!m) return;
        const foundAt = m.index;
        const foundEmoji = m[0];
        const foundSemantic = _emojiToSemanticCache[foundEmoji];
        if (!foundSemantic) return;

        const parent = node.parentNode;
        const before = text.substring(0, foundAt);
        const after = text.substring(foundAt + foundEmoji.length);

        const span = document.createElement('span');
        span.className = 'ws-icon-clean-wrap';
        span.setAttribute('data-emoji', foundEmoji);
        span.setAttribute('data-icon', foundSemantic);
        span.innerHTML = cleanIconSvg(foundSemantic);

        if (before) parent.insertBefore(document.createTextNode(before), node);
        parent.insertBefore(span, node);
        if (after) {
            const afterNode = document.createTextNode(after);
            parent.insertBefore(afterNode, node);
            parent.removeChild(node);
            node = afterNode;
        } else {
            parent.removeChild(node);
            return;
        }
    }
}

let _cleanIconObserver = null;
function observeForCleanIcons() {
    if (_cleanIconObserver) return;
    _cleanIconObserver = new MutationObserver((mutations) => {
        if (_cleanIconReplacing) return;
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    if (node.closest?.('[data-no-translate]')) continue;
                    if (node.classList?.contains('ws-icon-clean-wrap')) continue;
                    translateEmojisToCleanSvg(node);
                } else if (node.nodeType === Node.TEXT_NODE) {
                    if (node.parentElement?.closest('[data-no-translate]')) continue;
                    replaceEmojiNodeWithCleanSvg(node);
                }
            }
        }
    });
    _cleanIconObserver.observe(document.body, { childList: true, subtree: true });
}

function mergeCleanEmojiMappings() {
    if (typeof EMOJI_TO_SEMANTIC === 'undefined') return;
    for (const [emoji, semantic] of Object.entries(CLEAN_EXTRA_EMOJI_MAP)) {
        if (!(emoji in EMOJI_TO_SEMANTIC)) EMOJI_TO_SEMANTIC[emoji] = semantic;
    }
}
