/**
 * A8 — the realtime query surface, end to end.
 *
 * Runs the real server against a real database and talks to it with a real socket.io client.
 * Before the fix, every one of these events went straight to a query with no shape check and no
 * budget: a loop of emits was a loop of database queries, and a flood of log lines.
 *
 * The budget is lowered for this file (the server reads the environment at boot).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { io } = require('socket.io-client');
const { startDbServer } = require('./helpers/dbServer');

process.env.SOCKET_QUERY_LIMIT = '10';
process.env.SOCKET_QUERY_WINDOW_MS = '1500';

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let ctx;
let adminToken;

const child = (overrides = {}) => ({
    fullName: 'Child',
    status: 'approved',
    found: false,
    gender: 'Female',
    age: 7,
    address: 'Malegaon, Nashik',
    state: 'Maharashtra',
    missingDate: '2026-09-01',
    createdAt: new Date(),
    contactNumber: '9876501234',
    faceDescriptor: Array.from({ length: 128 }, () => 0.5),
    ...overrides
});

test.before(async () => {
    ctx = await startDbServer();
    adminToken = await ctx.adminToken();

    await ctx.models.Child.deleteMany({});
    await ctx.models.Child.insertMany([
        child({ fullName: "Aamna \"Khan\" O'Brien", gender: 'Female' }),
        child({ fullName: 'Rafiq Shaikh', gender: 'Male', location: 'Malegaon' }),
        child({ fullName: 'Third Record', gender: 'Male', address: 'Pune' })
    ]);
    assert.ok(adminToken);
});

test.after(async () => { await ctx.stop(); });

const openClient = () => new Promise((resolve, reject) => {
    const socket = io(ctx.base, { transports: ['websocket'], reconnection: false });
    const timer = setTimeout(() => { socket.close(); reject(new Error('client never connected')); }, 10000);
    socket.on('connect', () => { clearTimeout(timer); resolve(socket); });
    socket.on('connect_error', (error) => { clearTimeout(timer); socket.close(); reject(error); });
});

/** Resolve with the next payload for an event. */
const once = (socket, event, timeoutMs = 8000) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no ${event} within ${timeoutMs}ms`)), timeoutMs);
    socket.once(event, (payload) => { clearTimeout(timer); resolve(payload); });
});

test('A8: a socket listing is paginated and carries no private fields', async () => {
    const socket = await openClient();
    try {
        socket.emit('load', { page: 2, limit: 1 });
        const result = await once(socket, 'getAllData');

        assert.equal(result.total, 3, 'the total must count every approved record, not one page');
        assert.equal(result.page, 2);
        assert.equal(result.limit, 1);
        assert.equal(result.data.length, 1, 'the page size must be honoured');

        for (const row of result.data) {
            assert.ok(!('contactNumber' in row), 'a contact number must never leave over a socket');
            assert.ok(!('faceDescriptor' in row), 'biometrics must never leave over a socket');
            assert.ok(!('finderContact' in row));
            assert.ok(!('userId' in row));
        }
    } finally {
        socket.close();
    }
});

test('A8: a hostile search term is treated as literal text, not a pattern', async () => {
    const socket = await openClient();
    try {
        socket.emit('searchChildren', { query: '.*' });
        const everything = await once(socket, 'getSearchData');
        assert.equal(everything.total, 0, 'a regex must not match every record');

        socket.emit('searchChildren', { query: 'Aamna' });
        const match = await once(socket, 'getSearchData');
        assert.equal(match.total, 1);
        assert.equal(match.data[0].fullName, "Aamna \"Khan\" O'Brien");
    } finally {
        socket.close();
    }
});

test('A8: junk input is refused instead of querying the database', async () => {
    const socket = await openClient();
    try {
        const rejected = once(socket, 'queryRejected');
        const answeredEmpty = once(socket, 'getByDateData');
        socket.emit('searchByDate', 'nonsense');

        const [notice, empty] = await Promise.all([rejected, answeredEmpty]);
        assert.equal(notice.event, 'searchByDate');
        assert.equal(notice.reason, 'invalid-date');
        assert.match(notice.message, /valid date/i);

        // An older client only listens for its own event, so it still gets a failed empty answer
        // rather than hanging on "Searching...".
        assert.equal(empty.success, false);
        assert.equal(empty.error, true);
        assert.deepEqual(empty.data, []);
    } finally {
        socket.close();
    }
});

test('A8: valid searches still work, including the date range', async () => {
    const socket = await openClient();
    try {
        socket.emit('searchByDate', '2026-09-01T09:00:00Z');
        const byDate = await once(socket, 'getByDateData');
        assert.equal(byDate.total, 3, 'an ISO timestamp is normalized to the stored date');

        socket.emit('searchByRange', { searchingDateFrom: '2026-08-01', searchingDateTo: '2026-09-30' });
        const byRange = await once(socket, 'getByRangeData');
        assert.equal(byRange.total, 3);

        socket.emit('searchByName', 'Rafiq');
        const byName = await once(socket, 'getByNameData');
        assert.equal(byName.total, 1);

        socket.emit('searchByAddress', 'Malegaon');
        const byAddress = await once(socket, 'getByAddressData');
        assert.equal(byAddress.total, 2);
    } finally {
        socket.close();
    }
});

test('A8: a flooding client is throttled, and a new connection still works', async () => {
    const flooder = await openClient();
    const received = [];
    const rejections = [];
    flooder.on('getAllData', (payload) => received.push(payload));
    flooder.on('queryRejected', (payload) => rejections.push(payload));

    try {
        for (let i = 0; i < 100; i++) flooder.emit('load', {});

        const deadline = Date.now() + 8000;
        while (Date.now() < deadline && rejections.length < 80) await wait(50);

        assert.ok(rejections.length >= 80, `the flood must be throttled, got ${rejections.length} rejections`);
        // A blast with no waiting is stopped by the in-flight cap first, then by the budget.
        assert.ok(
            rejections.every((payload) => ['rate-limited', 'busy'].includes(payload.reason)),
            `every refusal must be a throttle, got ${JSON.stringify([...new Set(rejections.map((p) => p.reason))])}`
        );
        assert.ok(
            received.filter((payload) => payload.throttled).length >= 80,
            'each throttled request must answer the event the client listens for'
        );
        assert.equal(received.filter((payload) => payload.throttled).every((payload) => payload.success === false), true);
        // Every request is answered, so `received` counts refusals too; what must stay bounded
        // is the number of queries that actually reached the database.
        const served = () => received.filter((payload) => !payload.throttled);
        assert.ok(served().length > 0, 'the flood starts by being served');
        assert.ok(
            served().length <= 12,
            `the budget must bound the queries (10 per window), got ${served().length}`
        );

        // Once the blast has drained, the budget itself is what refuses — a client that paces
        // its requests still cannot exceed the allow-listed number of queries per window.
        await wait(500);
        const paced = [];
        for (let i = 0; i < 20; i++) {
            flooder.emit('load', {});
            await wait(20);
        }
        await wait(300);
        paced.push(...rejections.filter((payload) => payload.reason === 'rate-limited'));
        assert.ok(paced.length > 0, 'the per-window budget must refuse a paced client once it is spent');

        // A throttled client must not be able to starve anyone else: the budget is per connection.
        const quiet = await openClient();
        try {
            quiet.emit('load', {});
            const answer = await once(quiet, 'getAllData');
            assert.equal(answer.total, 3, 'a fresh connection has its own budget');

            // And the flooder recovers once its window rolls over.
            await wait(1600);
            const before = served().length;
            flooder.emit('load', {});
            const deadline2 = Date.now() + 5000;
            while (Date.now() < deadline2 && served().length === before) await wait(50);
            assert.ok(served().length > before, 'the connection must be served again after the window');
        } finally {
            quiet.close();
        }
    } finally {
        flooder.close();
    }
});
