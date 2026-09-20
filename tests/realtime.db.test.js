/**
 * C2 — end-to-end proof against the real server and a real socket.io client.
 *
 * The old behaviour was one `dataChanged` per write; the admin panel answered each one with a
 * full reload of everything it displays. This connects a genuine client, performs several
 * writes in a burst, and asserts the client receives exactly one notification carrying the
 * scopes that changed.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { io } = require('socket.io-client');
const { startDbServer } = require('./helpers/dbServer');

let ctx;
let adminToken;

test.before(async () => {
    ctx = await startDbServer();
    adminToken = await ctx.adminToken();
});

test.after(async () => { await ctx.stop(); });

const openClient = () => new Promise((resolve, reject) => {
    const socket = io(ctx.base, { transports: ['websocket'], reconnection: false });
    const timer = setTimeout(() => { socket.close(); reject(new Error('client never connected')); }, 10000);
    socket.on('connect', () => { clearTimeout(timer); resolve(socket); });
    socket.on('connect_error', (error) => { clearTimeout(timer); socket.close(); reject(error); });
});

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test('C2: a burst of admin writes reaches clients as one scoped notification', async () => {
    const socket = await openClient();
    const received = [];
    socket.on('dataChanged', (payload) => received.push(payload));

    // Three writes on two different scopes, all inside one coalescing window.
    const first = await ctx.models.Child.create({ fullName: 'Burst One', status: 'pending' });
    const second = await ctx.models.Child.create({ fullName: 'Burst Two', status: 'pending' });
    const user = await ctx.models.User.create({ userFullName: 'Burst User', userContactNumber: '9876501977' });

    const approveOne = await ctx.api(`/api/admin/children/${first._id}`, { method: 'PUT', token: adminToken, body: { status: 'approved' } });
    const approveTwo = await ctx.api(`/api/admin/children/${second._id}`, { method: 'PUT', token: adminToken, body: { status: 'approved' } });
    const block = await ctx.api(`/api/admin/users/${user._id}`, { method: 'PUT', token: adminToken, body: { blocked: true } });

    assert.equal(approveOne.status, 200);
    assert.equal(approveTwo.status, 200);
    assert.equal(block.status, 200, JSON.stringify(block.json));

    await wait(2000);
    socket.close();

    assert.equal(received.length, 1, `three writes must collapse into one notification, got ${received.length}`);
    assert.ok(Array.isArray(received[0].scopes), 'the payload must carry scopes');
    assert.ok(received[0].scopes.includes('children'), `expected the children scope, got ${JSON.stringify(received[0].scopes)}`);
    assert.ok(received[0].scopes.includes('users'), `expected the users scope, got ${JSON.stringify(received[0].scopes)}`);
    assert.equal(typeof received[0].at, 'number');
});

test('C2: writes far apart in time still notify (the coalescer must not swallow changes)', async () => {
    const socket = await openClient();
    const received = [];
    socket.on('dataChanged', (payload) => received.push(payload));

    const child = await ctx.models.Child.create({ fullName: 'Spaced Write', status: 'pending' });
    const first = await ctx.api(`/api/admin/children/${child._id}`, { method: 'PUT', token: adminToken, body: { status: 'approved' } });
    assert.equal(first.status, 200);
    await wait(1500);

    const second = await ctx.api(`/api/admin/children/${child._id}`, { method: 'PUT', token: adminToken, body: { status: 'pending' } });
    assert.equal(second.status, 200);
    await wait(1500);
    socket.close();

    assert.equal(received.length, 2, 'separate windows must each produce a notification');
});

test('C2: the counts endpoint is what keeps admin badges fresh', async () => {
    const pending = await ctx.models.Child.countDocuments({ status: 'pending' });
    const res = await ctx.api('/api/admin/counts', { token: adminToken });
    assert.equal(res.status, 200);
    assert.equal(res.json.data.pendingChildren, pending);
});
