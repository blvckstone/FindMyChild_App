// Live-server integration tests for the admin login endpoint.
// The server is started for real (no database needed) so these cover routing + middleware order.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
let portCursor = 9200 + Math.floor(Math.random() * 300);

const startServer = async (port) => {
    const child = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: {
            ...process.env,
            PORT: String(port),
            JWT_SECRET: 'test-secret',
            ADMIN_USERNAME: 'Shoeb',
            ADMIN_PASS: 'S3cret!',
            NODE_ENV: 'test',
            // Deliberately unreachable: these tests must not touch a real database.
            DB_ATLAS: 'mongodb://127.0.0.1:1/fmc_test?serverSelectionTimeoutMS=300&connectTimeoutMS=300'
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

const withServer = async (fn) => {
    const port = portCursor++;
    const { child, output } = await startServer(port);
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
    await withServer(async ({ postLogin }) => {
        const res = await postLogin({ username: 'undefined', password: 'undefined' });
        assert.equal(res.status, 401);
        const body = await res.json();
        assert.equal(body.success, false);
        assert.equal(body.token, undefined, 'no admin token may be issued');
    });
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
    });
});
