// Whole-application smoke tests: boots the real server (with no database available)
// and checks the HTTP surface still behaves, including every auth guard.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { freePort } = require('./helpers/ports');

const ROOT = path.resolve(__dirname, '..');
const SERVER_SOURCE = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');

// ----------------------------------------------------------- static guards

test('A1: /api/praise is wired to the public projection, not a raw document', () => {
    const start = SERVER_SOURCE.indexOf("app.get('/api/praise'");
    assert.ok(start > -1, 'the praise route is missing');
    const route = SERVER_SOURCE.slice(start, start + 900);
    assert.match(route, /pickFields\(child, PRAISE_CHILD_FIELDS\)/, 'praise route must project the child');
    assert.doesNotMatch(route, /data:\s*\{\s*child,\s*praises,\s*gifts\s*\}/, 'raw child document is still returned');
});

test('A2/A5: the admin login route is rate limited and blocked users are revoked', () => {
    assert.match(SERVER_SOURCE, /app\.post\('\/api\/admin\/login',\s*adminLoginLimiter/, 'admin login is not rate limited');
    // Built by the shared-store factory (see tests/rateLimitStore.test.js for the backing store).
    assert.match(SERVER_SOURCE, /const adminLoginLimiter = limiter\(\{ name: 'admin-login'/, 'admin login limiter is not defined');
    assert.ok(SERVER_SOURCE.includes('revokeUserTokens(req.params.id)'), 'blocking/deleting a user does not revoke sessions');
});

// ----------------------------------------------------------- live smoke tests

// Assigned per boot from the OS, so parallel test files cannot land on the same port.
let PORT = 0;
let server;
let output = '';

const bootServer = async () => {
    PORT = await freePort();
    server = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: {
            ...process.env,
            PORT: String(PORT),
            JWT_SECRET: 'test-secret',
            NODE_ENV: 'test',
            DB_ATLAS: 'mongodb://127.0.0.1:1/fmc_test?serverSelectionTimeoutMS=300&connectTimeoutMS=300'
            // RESEND_API_KEY / GOOGLE_* / CLOUDINARY_* deliberately unset: the app must boot anyway.
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    server.stdout.on('data', (chunk) => { output += chunk; });
    server.stderr.on('data', (chunk) => { output += chunk; });

    const deadline = Date.now() + 25000;
    while (Date.now() < deadline) {
        if (server.exitCode !== null) throw new Error(`server exited early (${server.exitCode}):\n${output}`);
        try {
            const res = await fetch(`http://127.0.0.1:${PORT}/admin`);
            if (res.ok) return;
        } catch { /* still starting */ }
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`server never became ready:\n${output}`);
};

const url = (p) => `http://127.0.0.1:${PORT}${p}`;

test('whole app: boots and serves the frontends, assets and socket client', async (t) => {
    await bootServer();
    t.after(() => server.kill());

    for (const [routeName, expected] of [
        ['/', 'Find My Child'],
        ['/admin', 'Admin'],
        ['/js/fmc-escape.js', 'jsArg'],
        ['/js/fmc-face.js', 'fmcFace'],
        ['/js/face-api.js', 'faceapi'],
        ['/models/face_recognition_model-weights_manifest.json', ''],
        ['/models/ssd_mobilenetv1_model-weights_manifest.json', ''],
        ['/socket.io/socket.io.js', 'io']
    ]) {
        const res = await fetch(url(routeName));
        assert.equal(res.status, 200, `${routeName} did not return 200`);
        if (expected) {
            const body = await res.text();
            assert.ok(body.includes(expected), `${routeName} body does not contain "${expected}"`);
        }
    }

    // B2: the served homepage must not pull the 13 MB face stack during page load.
    const home = await (await fetch(url('/'))).text();
    assert.ok(home.includes('/js/fmc-face.js'), 'homepage is missing the lazy face helper');
    assert.ok(
        !/<script[^>]+src=["']\/js\/face-api\.js["']/.test(home),
        'homepage still eagerly loads face-api.js'
    );
});

test('whole app: security headers are set on responses', async (t) => {
    await bootServer();
    t.after(() => server.kill());

    const res = await fetch(url('/'));
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');

    const admin = await fetch(url('/admin'));
    assert.match(admin.headers.get('cache-control') || '', /no-store/, 'admin.html must not be cached');
});

test('whole app: /api/health answers while the database is unavailable', async (t) => {
    await bootServer();
    t.after(() => server.kill());

    const res = await fetch(url('/api/health'));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.database, 'error', 'health must report the outage instead of crashing');
    assert.equal(body.status, 'degraded');
});

test('whole app: every protected endpoint rejects anonymous callers with 401', async (t) => {
    await bootServer();
    t.after(() => server.kill());

    const protectedCalls = [
        ['GET', '/api/auth/me'],
        ['PUT', '/api/auth/me'],
        ['GET', '/api/auth/activity'],
        ['GET', '/api/found-requests/me'],
        ['POST', '/api/children'],
        ['GET', '/api/children/000000000000000000000000/detail'],
        ['POST', '/api/found-requests'],
        ['POST', '/api/praise'],
        ['PUT', '/api/praise/000000000000000000000000'],
        ['DELETE', '/api/praise/000000000000000000000000'],
        ['POST', '/api/gifts'],
        ['POST', '/api/safechild/register'],
        ['GET', '/api/safechild/children'],
        ['PUT', '/api/safechild/children/000000000000000000000000'],
        ['DELETE', '/api/safechild/children/000000000000000000000000'],
        ['GET', '/api/admin/me'],
        ['GET', '/api/admin/stats'],
        ['GET', '/api/admin/children'],
        ['GET', '/api/admin/users'],
        ['GET', '/api/admin/users/000000000000000000000000/activity'],
        ['GET', '/api/admin/users/000000000000000000000000/safe-children'],
        ['GET', '/api/admin/found-requests'],
        ['GET', '/api/admin/praise'],
        ['GET', '/api/admin/gifts'],
        ['GET', '/api/admin/donations'],
        ['GET', '/api/admin/revenue'],
        ['GET', '/api/admin/ads'],
        ['GET', '/api/admin/analytics'],
        ['GET', '/api/admin/admins'],
        ['GET', '/api/admin/pages'],
        ['GET', '/api/admin/legal'],
        ['GET', '/api/admin/ngo-contacts'],
        ['GET', '/api/admin/payment-settings'],
        ['PUT', '/api/admin/payment-settings'],
        ['DELETE', '/api/admin/users/000000000000000000000000'],
        ['PUT', '/api/admin/users/000000000000000000000000'],
        ['DELETE', '/api/admin/children/000000000000000000000000']
    ];

    const failures = [];
    for (const [method, routeName] of protectedCalls) {
        const res = await fetch(url(routeName), { method, headers: { 'Content-Type': 'application/json' }, body: method === 'GET' ? undefined : '{}' });
        if (res.status !== 401) failures.push(`${method} ${routeName} -> ${res.status} (expected 401)`);
    }
    assert.deepEqual(failures, [], 'endpoints that are not protected');
});

test('whole app: public endpoints degrade cleanly without a database', async (t) => {
    await bootServer();
    t.after(() => server.kill());

    const publicCalls = ['/api/ads', '/api/donations', '/api/payment-config', '/api/ngo-contacts', '/api/pages/about-us', '/api/legal', '/api/analytics/active', '/api/data', '/api/messages'];
    for (const routeName of publicCalls) {
        const res = await fetch(url(routeName));
        const body = await res.text();
        assert.ok([200, 404, 500, 503].includes(res.status), `${routeName} returned ${res.status}`);
        assert.ok(body.length > 0, `${routeName} returned an empty body`);
    }

    // The process must still be healthy after all of those failures.
    const alive = await fetch(url('/admin'));
    assert.equal(alive.status, 200, 'server died while degrading');
});

test('whole app: unknown API paths return a 404 instead of HTML', async (t) => {
    await bootServer();
    t.after(() => server.kill());

    const res = await fetch(url('/api/definitely-not-a-route'));
    assert.equal(res.status, 404);
});
