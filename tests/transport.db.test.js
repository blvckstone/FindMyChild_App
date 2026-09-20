// Transport-level hardening, proven against the real server and a real database:
// CORS is no longer wide open, the unauthenticated admin debug route is gone, and an upload
// that is not genuinely an image is refused before any route (and any database write) sees it.
const test = require('node:test');
const assert = require('node:assert/strict');
const sharp = require('sharp');
const { spawn } = require('node:child_process');
const path = require('node:path');

const { startDbServer } = require('./helpers/dbServer');

const ROOT = path.resolve(__dirname, '..');
let ctx;
let adminToken;
let userToken;

test.before(async () => {
    ctx = await startDbServer();
    adminToken = await ctx.adminToken();

    const { hashPassword } = require('../functions/passwords');
    await ctx.models.User.create({
        userFullName: 'Transport Tester',
        userContactNumber: '9876500099',
        emailId: 'transport@example.com',
        password: hashPassword('pass1234'),
        createdAt: new Date()
    });
    const login = await ctx.api('/api/auth/login', { method: 'POST', body: { identifier: '9876500099', password: 'pass1234' } });
    assert.equal(login.status, 200, 'the seeded user must be able to log in');
    userToken = login.json.token;
});

test.after(async () => { await ctx.stop(); });

const origin = () => ctx.base; // e.g. http://127.0.0.1:9601

test('the origin policy is applied: same-origin is echoed, a foreign site is not', async () => {
    const same = await fetch(`${ctx.base}/api/health`, { headers: { Origin: origin() } });
    assert.equal(same.headers.get('access-control-allow-origin'), origin(), 'same-origin must be allowed');

    const foreign = await fetch(`${ctx.base}/api/health`, { headers: { Origin: 'https://evil.example' } });
    assert.equal(foreign.headers.get('access-control-allow-origin'), null, 'a foreign origin must not be echoed back');
    assert.equal(foreign.status, 200, 'the request is still served — CORS is enforced by the browser, not by us');

    // A request with no Origin (curl, health probe, native app) is untouched by CORS.
    const plain = await fetch(`${ctx.base}/api/health`);
    assert.equal(plain.status, 200);
});

test('a preflight from a foreign origin is not granted permission', async () => {
    const res = await fetch(`${ctx.base}/api/admin/login`, {
        method: 'OPTIONS',
        headers: {
            Origin: 'https://evil.example',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type'
        }
    });
    assert.equal(res.headers.get('access-control-allow-origin'), null, 'preflight must not be approved');
});

test('ALLOWED_ORIGINS lets an explicitly listed site through', async () => {
    const port = 9800 + Math.floor(Math.random() * 100);
    const child = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: {
            ...process.env,
            PORT: String(port),
            DB_ATLAS: ctx.uri,
            JWT_SECRET: 'test-secret',
            ALLOWED_ORIGINS: 'https://partner.example',
            RESEND_API_KEY: '',
            GOOGLE_CLIENT_ID: '',
            GOOGLE_CLIENT_SECRET: ''
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    const base = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
        try {
            if ((await fetch(`${base}/admin`)).ok) break;
        } catch { /* still starting */ }
        await new Promise((resolve) => setTimeout(resolve, 200));
    }
    try {
        const allowed = await fetch(`${base}/api/health`, { headers: { Origin: 'https://partner.example' } });
        assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://partner.example');

        const stillBlocked = await fetch(`${base}/api/health`, { headers: { Origin: 'https://unlisted.example' } });
        assert.equal(stillBlocked.headers.get('access-control-allow-origin'), null);
    } finally {
        child.kill();
    }
});

test('the unauthenticated /api/admin/debug route no longer exists', async () => {
    const jwt = require('jsonwebtoken');
    const forged = jwt.sign({ role: 'super_admin' }, 'test-secret');
    const res = await fetch(`${ctx.base}/api/admin/debug`, { headers: { Authorization: `Bearer ${forged}` } });
    assert.equal(res.status, 404, 'the debug route must be gone, even for a valid admin token');

    const bare = await fetch(`${ctx.base}/api/admin/debug`);
    assert.equal(bare.status, 404, 'the debug route must not answer anonymous callers');
});

test('a text file wearing an image MIME type is refused before the route runs', async () => {
    const form = new FormData();
    form.append('fullName', 'Upload Victim');
    form.append('address', 'Nowhere');
    form.append('image', new Blob([Buffer.from('<html><script>alert(1)</script></html>')], { type: 'image/jpeg' }), 'photo.jpg');

    const res = await fetch(`${ctx.base}/api/children`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}` },
        body: form
    });
    assert.equal(res.status, 400, 'an upload that is not an image must be a 400, not stored');
    const body = await res.json();
    assert.match(body.message, /not a JPG, PNG, WEBP or GIF/);

    const children = await ctx.models.Child.countDocuments({ fullName: 'Upload Victim' });
    assert.equal(children, 0, 'the rejected upload must not have created a record');
});

test('an image whose declared type disagrees with its bytes is refused', async () => {
    const jpeg = await sharp({ create: { width: 20, height: 20, channels: 3, background: { r: 9, g: 9, b: 9 } } }).jpeg().toBuffer();
    const form = new FormData();
    form.append('fullName', 'Type Liar');
    form.append('address', 'Nowhere');
    form.append('image', new Blob([jpeg], { type: 'image/png' }), 'photo.png');

    const res = await fetch(`${ctx.base}/api/children`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}` },
        body: form
    });
    assert.equal(res.status, 400);
    assert.match((await res.json()).message, /contents are image\/jpeg/);
    assert.equal(await ctx.models.Child.countDocuments({ fullName: 'Type Liar' }), 0);
});

test('a genuinely valid image passes validation (the failure, if any, is downstream)', async () => {
    // Cloudinary is deliberately unconfigured in tests, so an accepted image must fail at the
    // upload step rather than at validation — that is what proves the bytes were accepted.
    const png = await sharp({ create: { width: 30, height: 30, channels: 3, background: { r: 3, g: 3, b: 3 } } }).png().toBuffer();
    const form = new FormData();
    form.append('fullName', 'Validity Proof');
    form.append('address', 'Nowhere');
    form.append('image', new Blob([png], { type: 'image/png' }), 'photo.png');

    const res = await fetch(`${ctx.base}/api/children`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${userToken}` },
        body: form
    });
    const body = await res.json();
    assert.equal(res.status, 500);
    assert.match(String(body.message), /Cloudinary/, 'the request must reach the upload step, not be rejected as a bad image');
});

test('validation runs for every upload-bearing route, not just the report form', async () => {
    // A login form with a file attached still goes through the upload guard, so this proves
    // the check is global rather than remembered per route.
    const form = new FormData();
    form.append('identifier', 'nobody@example.com');
    form.append('password', 'whatever');
    form.append('image', new Blob([Buffer.from('GIF89a definitely not a gif')], { type: 'image/gif' }), 'x.gif');

    const res = await fetch(`${ctx.base}/api/auth/login`, { method: 'POST', body: form });
    assert.equal(res.status, 400, 'the global upload guard must reject it before the login handler runs');
});

test('the socket handshake refuses a cross-origin browser', async () => {
    const { io } = require('socket.io-client');

    const foreign = io(ctx.base, { transports: ['websocket'], extraHeaders: { Origin: 'https://evil.example' }, reconnection: false, timeout: 4000 });
    const foreignError = await new Promise((resolve) => {
        foreign.on('connect_error', (err) => resolve(err));
        foreign.on('connect', () => resolve(null));
        setTimeout(() => resolve(new Error('no answer')), 5000);
    });
    foreign.close();
    assert.ok(foreignError, 'a cross-origin socket handshake must be rejected');

    const sameOrigin = io(ctx.base, { transports: ['websocket'], reconnection: false, timeout: 4000 });
    const connected = await new Promise((resolve) => {
        sameOrigin.on('connect', () => resolve(true));
        sameOrigin.on('connect_error', () => resolve(false));
        setTimeout(() => resolve(false), 5000);
    });
    sameOrigin.close();
    assert.equal(connected, true, 'a same-origin/native client must still be able to connect');
});
