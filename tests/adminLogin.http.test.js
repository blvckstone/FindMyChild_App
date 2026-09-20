// Live-server integration tests for the admin login endpoint.
// The server is started for real (no database needed) so these cover routing + middleware order.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { MongoMemoryServer } = require('mongodb-memory-server-core');

const ROOT = path.resolve(__dirname, '..');
let portCursor = 9200 + Math.floor(Math.random() * 300);

// An admin login now records a revocable session, so a successful login needs storage. Tests
// that only assert a *rejection* still run against an unreachable database on purpose.
const UNREACHABLE_DB = 'mongodb://127.0.0.1:1/fmc_test?serverSelectionTimeoutMS=300&connectTimeoutMS=300';
let mongo;
let dbUri;

test.before(async () => {
    mongo = await MongoMemoryServer.create();
    dbUri = mongo.getUri('fmc_test');
});

test.after(async () => { await mongo.stop(); });

const startServer = async (port, { db = dbUri } = {}) => {
    const child = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: {
            ...process.env,
            PORT: String(port),
            JWT_SECRET: 'test-secret',
            ADMIN_USERNAME: 'Shoeb',
            ADMIN_PASS: 'S3cret!',
            NODE_ENV: 'test',
            DB_ATLAS: db
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });

    const deadline = Date.now() + 25000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`server exited early (${child.exitCode}):\n${output}`);
        try {
            const res = await fetch(`http://127.0.0.1:${port}/admin`);
            if (res.ok) return { child, output: () => output };
        } catch { /* not listening yet */ }
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    child.kill();
    throw new Error(`server did not start within 25s:\n${output}`);
};

const withServer = async (fn, options = {}) => {
    const port = portCursor++;
    const { child, output } = await startServer(port, options);
    const base = `http://127.0.0.1:${port}`;
    const postLogin = (body) => fetch(`${base}/api/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    try {
        await fn({ base, postLogin, output });
    } finally {
        child.kill();
        await new Promise((resolve) => setTimeout(resolve, 150));
    }
};

test('A2 (HTTP): the "undefined" credential payload cannot log in', async () => {
    // No database on purpose: a wrong credential must be refused without any storage access.
    await withServer(async ({ postLogin }) => {
        const res = await postLogin({ username: 'undefined', password: 'undefined' });
        assert.equal(res.status, 401);
        const body = await res.json();
        assert.equal(body.success, false);
        assert.equal(body.token, undefined, 'no admin token may be issued');
    }, { db: UNREACHABLE_DB });
});

test('FI: a correct credential issues no token when the session store is unavailable', async () => {
    // Fail closed: without shared storage there is nothing to revoke, so there is no login.
    await withServer(async ({ postLogin }) => {
        const res = await postLogin({ username: 'Shoeb', password: 'S3cret!' });
        assert.equal(res.status, 503);
        const body = await res.json();
        assert.equal(body.success, false);
        assert.equal(body.token, undefined, 'a token that cannot be revoked must not be issued');
    }, { db: UNREACHABLE_DB });
});

test('A2 (HTTP): real configured credentials still log in', async () => {
    await withServer(async ({ postLogin }) => {
        const res = await postLogin({ username: 'Shoeb', password: 'S3cret!' });
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.ok(body.token, 'valid admin credentials return a token');
        assert.equal(body.role, 'super_admin');
    });
});

test('A3 (HTTP): admin login is rate limited after 10 attempts', async () => {
    // Counters live in shared storage now (the ceiling is global and survives a restart), so
    // this test needs its own database: the logins the other tests perform are the same key.
    await withServer(async ({ postLogin }) => {
        const first = await postLogin({ username: 'Shoeb', password: 'S3cret!' });
        assert.equal(first.status, 200, 'first attempt allowed');
        for (let attempt = 2; attempt <= 10; attempt++) {
            const res = await postLogin({ username: 'Shoeb', password: `wrong-${attempt}` });
            assert.equal(res.status, 401, `attempt ${attempt} should be a normal auth failure`);
        }
        const limited = await postLogin({ username: 'Shoeb', password: 'S3cret!' });
        assert.equal(limited.status, 429, 'the 11th attempt must be throttled');
        const body = await limited.json();
        assert.equal(body.success, false);
    }, { db: mongo.getUri('fmc_rate_limit') });
});
