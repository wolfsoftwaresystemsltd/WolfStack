// ESLint gate for the WolfStack web UI.
//
// WHY THIS EXISTS: `node --check` only parses. On 2026-08-07 a released
// build shipped a template literal referencing an undefined variable
// (`copyable` in app.js) — parse-clean, but every container with mounts
// threw ReferenceError at runtime and the migrate dialog hung on its
// placeholder forever. setup.sh installs web/ straight from the git
// branch, so a bad master reaches every new install and upgrade
// immediately, without a release in between. This config is the gate
// that class of bug has to pass.
//
// SCOPE: correctness-only rules — every rule here flags something that
// is a runtime error or unambiguously dead/wrong code. Deliberately NOT
// style rules and NOT eslint:recommended (no-unused-vars etc. would
// flood a 90k-line legacy surface and the noise would get the gate
// deleted).
//
// The UI is classic multi-file browser-global code: each of the five
// files in js/ defines top-level functions the other files (and inline
// onclick="" attributes) call. `no-undef` therefore needs the union of
// every file's top-level declarations as globals. Hand-maintaining that
// list (~2000 names) would rot in a week, so it is computed here, at
// config load, by parsing each file with espree and walking the
// top-level statements. `sourceType: "script"` matches how the browser
// actually loads these files (plain <script>, no modules).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as espree from 'espree';
import globals from 'globals';

const here = path.dirname(fileURLToPath(import.meta.url));
const jsDir = path.join(here, 'js');

// Collect every name a top-level statement binds in classic-script
// scope: function/class declarations and var/let/const (including
// destructuring patterns).
function bindingNames(node, out) {
    switch (node.type) {
        case 'Identifier': out.add(node.name); break;
        case 'ObjectPattern':
            for (const p of node.properties) bindingNames(p.value ?? p.argument, out);
            break;
        case 'ArrayPattern':
            for (const el of node.elements) if (el) bindingNames(el, out);
            break;
        case 'AssignmentPattern': bindingNames(node.left, out); break;
        case 'RestElement': bindingNames(node.argument, out); break;
        default: break;
    }
}

// Walk the whole AST collecting `window.NAME = …` / `globalThis.NAME = …`
// assignments. Several files export their API this way from inside an IIFE
// (wolfhost.js, wolfrouter.js, terminal-console.js), so top-level statement
// walking alone misses them.
function collectWindowAssignments(node, out) {
    if (!node || typeof node.type !== 'string') return;
    if (node.type === 'AssignmentExpression'
        && node.left.type === 'MemberExpression'
        && !node.left.computed
        && node.left.object.type === 'Identifier'
        && (node.left.object.name === 'window' || node.left.object.name === 'globalThis')
        && node.left.property.type === 'Identifier') {
        out.add(node.left.property.name);
    }
    for (const key of Object.keys(node)) {
        const v = node[key];
        if (Array.isArray(v)) {
            for (const el of v) if (el && typeof el.type === 'string') collectWindowAssignments(el, out);
        } else if (v && typeof v.type === 'string') {
            collectWindowAssignments(v, out);
        }
    }
}

function topLevelDeclarations(file) {
    const names = new Set();
    const src = fs.readFileSync(file, 'utf8');
    // ecmaVersion must keep pace with syntax used in the files; espree
    // throws on syntax it doesn't know, and a throw here fails the
    // whole lint run loudly (good — that's a parse error anyway).
    const ast = espree.parse(src, { ecmaVersion: 2024, sourceType: 'script' });
    for (const stmt of ast.body) {
        if (stmt.type === 'FunctionDeclaration' || stmt.type === 'ClassDeclaration') {
            if (stmt.id) names.add(stmt.id.name);
        } else if (stmt.type === 'VariableDeclaration') {
            for (const d of stmt.declarations) bindingNames(d.id, names);
        }
    }
    collectWindowAssignments(ast, names);
    return names;
}

const appFiles = fs.readdirSync(jsDir)
    .filter(f => f.endsWith('.js'))
    .map(f => path.join(jsDir, f));

const crossFileGlobals = {};
for (const f of appFiles) {
    for (const name of topLevelDeclarations(f)) {
        crossFileGlobals[name] = 'writable';
    }
}

// Globals defined outside js/*.js. Each entry cites where the name
// actually comes from — do not add names here without checking.
const externalGlobals = {
    // js/vendor/xterm.min.js — UMD wrapper copies exports onto `self`;
    // xterm 5.3.0 exports `Terminal`.
    Terminal: 'readonly',
    // js/vendor/xterm-addon-fit.min.js — same UMD shape, exports FitAddon.
    FitAddon: 'readonly',
    // js/vendor/lucide.min.js — assigns `.lucide=` on the global.
    lucide: 'readonly',
    // js/vendor/three.min.js — assigns `.THREE=` on the global.
    THREE: 'readonly',
    // index.html loads leaflet 1.9.4 from unpkg; leaflet's dist build
    // sets window.L.
    L: 'readonly',
};

// Inline <script> blocks in the served pages also declare globals that
// js/*.js may call (e.g. wsAssetFailed in index.html). Parse them the
// same way instead of hand-listing. Blocks that fail to parse in
// isolation (document.write string tricks) are skipped — they don't
// declare anything.
const htmlPages = ['index.html', 'login.html', 'console.html', 'vnc.html']
    .map(f => path.join(here, f))
    .filter(f => fs.existsSync(f));

for (const page of htmlPages) {
    const html = fs.readFileSync(page, 'utf8');
    // Non-module inline scripts only: src= scripts are files handled
    // above, and type="module" scripts don't create globals.
    const re = /<script(?![^>]*\bsrc=)(?![^>]*type="module")[^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
        let ast;
        try {
            ast = espree.parse(m[1], { ecmaVersion: 2024, sourceType: 'script' });
        } catch {
            continue;
        }
        for (const stmt of ast.body) {
            if (stmt.type === 'FunctionDeclaration' || stmt.type === 'ClassDeclaration') {
                if (stmt.id) crossFileGlobals[stmt.id.name] = 'writable';
            } else if (stmt.type === 'VariableDeclaration') {
                const names = new Set();
                for (const d of stmt.declarations) bindingNames(d.id, names);
                for (const n of names) crossFileGlobals[n] = 'writable';
            }
        }
    }
}

export default [
    {
        files: ['js/*.js'],
        ignores: ['js/vendor/**'],
        languageOptions: {
            ecmaVersion: 2024,
            sourceType: 'script',
            globals: {
                ...globals.browser,
                ...crossFileGlobals,
                ...externalGlobals,
            },
        },
        rules: {
            // The class that shipped: an identifier that exists nowhere.
            'no-undef': 'error',
            // The rest are all guaranteed-or-near-guaranteed runtime
            // errors that `node --check` also cannot see.
            'no-const-assign': 'error',
            'no-dupe-args': 'error',
            'no-dupe-keys': 'error',
            'no-dupe-class-members': 'error',
            'no-func-assign': 'error',
            'no-class-assign': 'error',
            'no-obj-calls': 'error',
            'no-unsafe-negation': 'error',
            'use-isnan': 'error',
            'valid-typeof': 'error',
            'no-unreachable': 'error',
            'no-cond-assign': ['error', 'except-parens'],
            'no-self-assign': 'error',
            'no-setter-return': 'error',
            'getter-return': 'error',
            'for-direction': 'error',
            'no-async-promise-executor': 'error',
            'no-compare-neg-zero': 'error',
            'no-sparse-arrays': 'error',
            'no-unsafe-optional-chaining': 'error',
        },
    },
];
