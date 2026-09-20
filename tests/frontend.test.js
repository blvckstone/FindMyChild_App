// Guards for what the browser is allowed to load and run.
//
// The user panel used to load https://cdn.tailwindcss.com — a third-party script that compiles
// CSS inside the visitor's browser. Tailwind warns against it in production, and on a page that
// already keeps a login token in browser storage it was a third party with full access to that
// token. The stylesheet is now built locally, and a Content-Security-Policy stops a script or an
// upload to any other origin from working even if one were reintroduced.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const servedPages = ['public/index.html', 'public/admin.html'];

test('pages: no served page loads a script or stylesheet from another origin', () => {
    const offenders = [];
    for (const page of servedPages) {
        const html = fs.readFileSync(path.join(ROOT, page), 'utf8');
        // Only <script src> and stylesheet <link> pull in and *run* someone else's code.
        for (const match of html.matchAll(/<script[^>]+src="(https?:\/\/[^"]+)"/g)) {
            offenders.push(`${page}: ${match[1]}`);
        }
        for (const match of html.matchAll(/<link[^>]+rel="stylesheet"[^>]+href="(https?:\/\/[^"]+)"/g)) {
            offenders.push(`${page}: ${match[1]}`);
        }
    }
    assert.deepEqual(offenders, [], 'third-party code must not run in the panels');
});

test('pages: the Tailwind CDN is gone and the built stylesheet is linked instead', () => {
    const html = fs.readFileSync(path.join(ROOT, 'public/index.html'), 'utf8');
    assert.doesNotMatch(html, /<script[^>]+cdn\.tailwindcss\.com/, 'the CDN script must not come back');
    assert.match(html, /<link rel="stylesheet" href="\/css\/tailwind\.css">/, 'the built stylesheet must be linked');

    // Order matters: the CDN injected its CSS after the page's own <style>, so Tailwind won
    // conflicts. The <link> has to keep that position or parts of the page restyle silently.
    const styleEnd = html.indexOf('</style>');
    const linkAt = html.indexOf('<link rel="stylesheet" href="/css/tailwind.css">');
    assert.ok(styleEnd > -1 && linkAt > styleEnd, 'the stylesheet link must come after the page CSS');
});

test('stylesheet: every Tailwind class used by the pages is in the built file', () => {
    // This is the failure mode of a static build: someone adds a utility class to the markup and
    // forgets to rerun `npm run build:css`, so the element silently loses its styling.
    const css = fs.readFileSync(path.join(ROOT, 'public/css/tailwind.css'), 'utf8');
    const html = fs.readFileSync(path.join(ROOT, 'public/index.html'), 'utf8');

    const utility = /^(flex|grid|hidden|block|inline|items-|justify-|gap-|p[xytrbl]?-|m[xytrbl]?-|w-|h-|text-|bg-|border|rounded|shadow|font-|max-w-|min-h-|opacity-|leading-|tracking-|whitespace-|shrink|grow|relative|absolute|fixed|overflow-)/;
    const used = new Set();
    for (const match of html.matchAll(/class="([^"]*)"/g)) {
        for (const cls of match[1].split(/\s+/)) if (cls && utility.test(cls)) used.add(cls);
    }
    assert.ok(used.size > 20, `expected the panel to use Tailwind utilities, found ${used.size}`);

    // The page also carries its own hand-written CSS, and a handful of its class names happen to
    // start like a utility (`pr-btn`, `inline-spinner`). Those are styled by the page itself, so
    // only classes that nothing defines are a real gap.
    const pageCss = html.slice(html.indexOf('<style>'), html.indexOf('</style>'));
    const missing = [...used].filter((cls) => {
        if (pageCss.includes('.' + cls)) return false;
        // Tailwind escapes anything that is not a name character in the selector.
        const selector = '.' + cls.replace(/[^a-zA-Z0-9_-]/g, (ch) => '\\' + ch);
        return !css.includes(selector);
    });
    assert.deepEqual(missing, [], 'these classes are used but missing from the built stylesheet — run npm run build:css');
});

// ----------------------------------------------------------- live: the header itself

const PORT = 9900 + Math.floor(Math.random() * 90);

test('CSP: the served page carries a policy that blocks other origins and exfiltration', async (t) => {
    const server = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: {
            ...process.env,
            PORT: String(PORT),
            JWT_SECRET: 'test-secret',
            NODE_ENV: 'test',
            DB_ATLAS: 'mongodb://127.0.0.1:1/fmc_test?serverSelectionTimeoutMS=300&connectTimeoutMS=300'
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    t.after(() => server.kill());

    const deadline = Date.now() + 25000;
    let res;
    while (Date.now() < deadline) {
        try {
            res = await fetch(`http://127.0.0.1:${PORT}/`);
            if (res.ok) break;
        } catch { /* still starting */ }
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    assert.ok(res && res.ok, 'the server did not start');

    const csp = res.headers.get('content-security-policy');
    assert.ok(csp, 'no Content-Security-Policy header');

    const directive = (name) => (csp.split(';').map((part) => part.trim()).find((part) => part.startsWith(name + ' ')) || '');
    assert.equal(directive("default-src"), "default-src 'self'", 'the default must not be a wildcard');
    assert.equal(directive('script-src'), "script-src 'self' 'unsafe-inline'", 'a script from another origin must not load');
    assert.equal(directive('connect-src'), "connect-src 'self'", 'data must have nowhere else to go');
    assert.equal(directive('object-src'), "object-src 'none'");
    assert.equal(directive('frame-ancestors'), "frame-ancestors 'none'");
    // No directive may be a blanket wildcard. (A specific subdomain wildcard such as
    // https://*.googleusercontent.com for Google avatars is deliberate.)
    assert.doesNotMatch(
        csp,
        /(^|;\s*)(default-src|script-src|connect-src|style-src|img-src) \*/,
        'no directive may allow every origin'
    );

    // The images the app legitimately shows must still be allowed.
    const imgSrc = directive('img-src');
    assert.match(imgSrc, /https:\/\/res\.cloudinary\.com/);
    assert.match(imgSrc, /blob:/);
});
