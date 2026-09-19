// Test helper: start an in-memory MongoDB, boot the real server against it,
// and expose the app's own mongoose models for seeding and assertions.
const { spawn } = require('node:child_process');
const path = require('node:path');
// The -core package has no install script, so a production `npm install` never downloads a
// MongoDB binary to run the tests. It fetches the binary on first test run instead.
const { MongoMemoryServer } = require('mongodb-memory-server-core');

const ROOT = path.resolve(__dirname, '../..');

const ADMIN = { username: 'Shoeb', password: 'S3cret!' };
const JWT_SECRET = 'test-secret';

let portCursor = 9600 + Math.floor(Math.random() * 200);

const startDbServer = async () => {
    const mongo = await MongoMemoryServer.create();
    const uri = mongo.getUri('fmc_test');
    const port = portCursor++;
    const base = `http://127.0.0.1:${port}`;

    const child = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: {
            ...process.env,
            PORT: String(port),
            DB_ATLAS: uri,
            JWT_SECRET,
            ADMIN_USERNAME: ADMIN.username,
            ADMIN_PASS: ADMIN.password,
            NODE_ENV: 'test',
            RESEND_API_KEY: '',          // OTP stays disabled, the server must still boot
            GOOGLE_CLIENT_ID: '',
            GOOGLE_CLIENT_SECRET: ''
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let log = '';
    child.stdout.on('data', (chunk) => { log += chunk; });
    child.stderr.on('data', (chunk) => { log += chunk; });

    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`server exited early (${child.exitCode}):\n${log}`);
        try {
            const res = await fetch(`${base}/admin`);
            if (res.ok) break;
        } catch { /* still starting */ }
        await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (Date.now() >= deadline) {
        child.kill();
        throw new Error(`server never became ready:\n${log}`);
    }

    // Connect this process to the same database using the app's own schemas.
    process.env.DB_ATLAS = uri;
    const fmcConnectMongoDB = require('../../functions/fmcDB/fmcMongoDB');
    const connection = await fmcConnectMongoDB();
    if (!connection.success) throw new Error('test process could not connect to the in-memory database');
    const models = await require('../../functions/dbModels')();

    const stop = async () => {
        child.kill();
        await new Promise((resolve) => setTimeout(resolve, 200));
        try {
            const mongoose = require('mongoose');
            await mongoose.disconnect();
        } catch { /* already closed */ }
        await mongo.stop();
    };

    const api = async (path, { method = 'GET', token, body } = {}) => {
        const headers = {};
        if (token) headers.Authorization = `Bearer ${token}`;
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        const res = await fetch(`${base}${path}`, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body)
        });
        let json = null;
        try { json = await res.json(); } catch { /* non-JSON response */ }
        return { status: res.status, json };
    };

    const adminToken = async () => {
        const res = await fetch(`${base}/api/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(ADMIN)
        });
        if (!res.ok) throw new Error(`admin login failed with ${res.status}`);
        return (await res.json()).token;
    };

    return { mongo, child, base, models, api, adminToken, uri, log: () => log, stop };
};

/**
 * Spawn an additional server process against the same database.
 *
 * Used to prove that state which must be shared really is shared: a session minted by one
 * instance has to work on another, and a revocation has to apply everywhere.
 */
const startSecondInstance = async (ctx, { label = 'B' } = {}) => {
    const port = portCursor++;
    const base = `http://127.0.0.1:${port}`;
    const child = spawn(process.execPath, ['server.js'], {
        cwd: ROOT,
        env: {
            ...process.env,
            PORT: String(port),
            DB_ATLAS: ctx.uri,
            JWT_SECRET,
            ADMIN_USERNAME: ADMIN.username,
            ADMIN_PASS: ADMIN.password,
            NODE_ENV: 'test',
            INSTANCE_LABEL: label,
            RESEND_API_KEY: '',
            GOOGLE_CLIENT_ID: '',
            GOOGLE_CLIENT_SECRET: ''
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let log = '';
    child.stdout.on('data', (chunk) => { log += chunk; });
    child.stderr.on('data', (chunk) => { log += chunk; });

    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`instance ${label} exited early (${child.exitCode}):\n${log}`);
        try {
            const res = await fetch(`${base}/admin`);
            if (res.ok) break;
        } catch { /* still starting */ }
        await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (Date.now() >= deadline) {
        child.kill();
        throw new Error(`instance ${label} never became ready:\n${log}`);
    }

    const api = async (path, { method = 'GET', token, body } = {}) => {
        const headers = {};
        if (token) headers.Authorization = `Bearer ${token}`;
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        const res = await fetch(`${base}${path}`, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body)
        });
        let json = null;
        try { json = await res.json(); } catch { /* non-JSON response */ }
        return { status: res.status, json };
    };

    return { base, child, api, log: () => log, stop: () => child.kill() };
};

// A deterministic 128-dimension descriptor; `seed` shifts every value so two
// descriptors are close when their seeds are close.
const describeFace = (seed = 0) => Array.from({ length: 128 }, (_, index) => 0.001 * (index % 10) + seed * 0.0001);

module.exports = { startDbServer, startSecondInstance, describeFace, ADMIN, JWT_SECRET };
