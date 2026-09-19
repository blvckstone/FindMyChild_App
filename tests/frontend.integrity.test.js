// Whole-app static integrity checks: script syntax, asset references, XSS regressions
// and frontend <-> API route integration. No server or database required.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const SERVER_SOURCE = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');

const readPage = (name) => fs.readFileSync(path.join(PUBLIC_DIR, name), 'utf8');
const PAGES = { 'index.html': readPage('index.html'), 'admin.html': readPage('admin.html') };

// ------------------------------------------------------------------ script syntax

for (const [name, html] of Object.entries(PAGES)) {
    test(`${name}: every inline script block parses as valid JavaScript`, () => {
        const blocks = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)];
        assert.ok(blocks.length > 0, `no inline script found in ${name}`);
        blocks.forEach((match, index) => {
            try {
                new vm.Script(match[1], { filename: `${name}#script${index + 1}` });
            } catch (error) {
                assert.fail(`${name} inline script #${index + 1} has a syntax error: ${error.message}`);
            }
        });
    });
}

// ------------------------------------------------------------- local asset refs

for (const [name, html] of Object.entries(PAGES)) {
    test(`${name}: every locally referenced asset exists on disk`, () => {
        const refs = [...html.matchAll(/(?:src|href)="(\/[^"]+)"/g)].map((m) => m[1]);
        const missing = refs.filter((ref) => {
            const clean = ref.split('?')[0];
            return !fs.existsSync(path.join(PUBLIC_DIR, clean.replace(/^\//, '')));
        });
        // These are express routes, not static files: /socket.io/* and links such as /api/auth/google.
        const unexpected = missing.filter((ref) => !ref.startsWith('/socket.io/') && !ref.startsWith('/api/'));
        assert.deepEqual(unexpected, [], `${name} references missing local assets`);
    });
}

test('index.html loads the shared escaping helper before using jsArg', () => {
    const html = PAGES['index.html'];
    const helperIdx = html.indexOf('/js/fmc-escape.js');
    const firstUse = html.indexOf('jsArg(');
    assert.ok(helperIdx > -1, 'fmc-escape.js is not included');
    assert.ok(firstUse > helperIdx, 'helper must load before its first use');
});

// ---------------------------------------------------------------- XSS regression

const USER_DATA_ESCAPED_IN_HANDLER = [
    'esc(detail.fullName',
    'esc(c.fullName',
    'esc(p.text',
    'esc(c.childName',
    'esc(c.address',
    'esc(c.parentContact',
    'esc(c.medicalInfo',
    'esc(c.gender)'
];

for (const [name, html] of Object.entries(PAGES)) {
    test(`${name}: no user text is escaped into an inline handler string literal`, () => {
        const handlers = [...html.matchAll(/onclick="([^"]*)"/g)].map((m) => m[1]);
        const offenders = [];
        for (const handler of handlers) {
            for (const pattern of USER_DATA_ESCAPED_IN_HANDLER) {
                if (handler.includes(pattern)) offenders.push(handler.slice(0, 120));
            }
        }
        assert.deepEqual(offenders, [], `user data still interpolated into inline handlers in ${name}`);
    });
}

test('index.html passes user text through jsArg inside every inline handler', () => {
    const html = PAGES['index.html'];
    for (const fn of ['openFoundForm', 'openPraiseForm', 'openGiftForm', 'editMyPraise', 'openSafeChildEdit']) {
        // Only handler call sites matter — the function definitions live outside onclicks.
        const handlers = [...html.matchAll(new RegExp('onclick="[^"]*' + fn + '\\(', 'g'))]
            .map((match) => html.slice(match.index, match.index + 400));
        assert.ok(handlers.length > 0, `${fn} is not used by any inline handler`);
        for (const handler of handlers) {
            assert.match(handler, /jsArg\(/, `${fn} handler still interpolates raw user text`);
        }
    }
});

// ----------------------------------------------------- frontend <-> API integration

const serverRoutes = [...SERVER_SOURCE.matchAll(/app\.(get|post|put|delete)\(\s*'([^']+)'/g)]
    .map((m) => m[2])
    .filter((routePath) => routePath.startsWith('/api/'));

const routeRegex = (routePath) => new RegExp(
    '^' + routePath
        .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        .replace(/:[A-Za-z0-9_]+/g, '[^/]+') + '/?$'
);

const routeExists = (frontendPath) => serverRoutes.some((routePath) =>
    routeRegex(routePath).test(frontendPath) || routePath.startsWith(frontendPath)
);

for (const [name, html] of Object.entries(PAGES)) {
    test(`${name}: every API path it calls exists on the server`, () => {
        const referenced = [...new Set([...html.matchAll(/['"`](\/api\/[A-Za-z0-9_\-/:]*)['"`+?]/g)].map((m) => m[1]))];
        const unknown = referenced.filter((ref) => !routeExists(ref.split('?')[0]));
        assert.deepEqual(unknown, [], `${name} calls API paths that do not exist`);
    });
}

test('the API route table is not empty (guards the integration check itself)', () => {
    assert.ok(serverRoutes.length > 50, `only ${serverRoutes.length} API routes parsed from server.js`);
});
