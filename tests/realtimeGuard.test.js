/**
 * A8 — the realtime query surface.
 *
 * The sockets are anonymous, so the payload is untrusted input: before the fix, every event went
 * straight to a query (a list plus a count) with no shape check, no budget and a verbatim log
 * line. These tests pin what a client may and may not do.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { attachQueryHandlers, createConnectionGuard, validateQuery, QUERY_ROUTES } = require('../functions/realtimeGuard');

const ROOT = path.join(__dirname, '..');

/** A socket that records what the server emitted, with no transport involved. */
const fakeSocket = () => {
    const handlers = new Map();
    const emitted = [];
    return {
        handlers,
        emitted,
        on(event, handler) { handlers.set(event, handler); },
        emit(event, payload) { emitted.push({ event, payload }); },
        async send(event, payload) {
            const handler = handlers.get(event);
            assert.ok(handler, `no handler attached for ${event}`);
            await handler(payload);
        },
        last(event) { return [...emitted].reverse().find((item) => item.event === event); }
    };
};

const queries = () => {
    const calls = [];
    const record = (name) => (args) => { calls.push({ name, args }); return { success: true, data: [name], total: 0 }; };
    return {
        calls,
        impl: {
            load: record('load'),
            loadMessages: record('loadMessages'),
            searchByDate: record('searchByDate'),
            searchByName: record('searchByName'),
            searchByRange: record('searchByRange'),
            searchByAddress: record('searchByAddress'),
            searchChildren: record('searchChildren')
        }
    };
};

// ------------------------------------------------------------------ validation

test('A8: unknown keys are dropped and pagination is clamped before a query sees them', () => {
    const parsed = validateQuery('load', { page: '2', limit: 1000, q: 'Aamna', sortBy: 'name', admin: true, $where: 'this.password' });
    assert.equal(parsed.ok, true);
    assert.equal(parsed.args.page, 2);
    assert.equal(parsed.args.limit, 50, 'the page size is capped');
    assert.equal(parsed.args.q, 'Aamna');
    assert.equal(parsed.args.sortBy, 'name');
    assert.equal('admin' in parsed.args, false, 'an unknown key must not reach the query');
    assert.equal('$where' in parsed.args, false, 'a query operator must not reach the query');
});

test('A8: free text is length-capped and non-text values are rejected', () => {
    const long = validateQuery('searchByName', { searchingName: 'x'.repeat(500) });
    assert.equal(long.ok, true);
    assert.equal(long.args.value.length, 60, 'search text is capped');

    const object = validateQuery('searchByName', { searchingName: { $ne: null } });
    assert.equal(object.ok, false, 'an object where text belongs is not a search');
    assert.equal(object.reason, 'invalid-query');

    const blank = validateQuery('searchByName', '   ');
    assert.equal(blank.ok, false);
});

test('A8: a date search only accepts a real date and returns it canonical', () => {
    assert.equal(validateQuery('searchByDate', '2026-09-01').args.value, '2026-09-01');
    assert.equal(validateQuery('searchByDate', '2026-09-01T10:00:00Z').args.value, '2026-09-01');
    assert.equal(validateQuery('searchByDate', { date: '2026/07/15' }).args.value, '2026-07-15', 'an unambiguous date is normalized');
    // DD/MM vs MM/DD cannot be told apart, so a search must not guess the wrong day.
    assert.equal(validateQuery('searchByDate', { date: '15/07/2026' }).ok, false, 'an ambiguous date is refused rather than guessed');

    for (const junk of ['', 'not-a-date', '2026-13-45', null, undefined, { $gt: '' }]) {
        const parsed = validateQuery('searchByDate', junk);
        assert.equal(parsed.ok, false, `${JSON.stringify(junk)} must not become a date query`);
    }
});

test('A8: a range needs two real dates in the right order', () => {
    const good = validateQuery('searchByRange', { searchingDateFrom: '2026-01-01', searchingDateTo: '2026-02-01' });
    assert.deepEqual([good.args.from, good.args.to], ['2026-01-01', '2026-02-01']);

    assert.equal(validateQuery('searchByRange', { searchingDateFrom: '2026-02-01', searchingDateTo: '2026-01-01' }).ok, false);
    assert.equal(validateQuery('searchByRange', { searchingDateFrom: '2026-01-01' }).ok, false);
    assert.equal(validateQuery('searchByRange', {}).ok, false);
});

test('A8: enums and ages are accepted only from their known values', () => {
    const ok = validateQuery('searchChildren', { query: 'aamna', filter: 'missing', sortBy: 'age', ageMin: 5, ageMax: 10 });
    assert.equal(ok.ok, true);
    assert.deepEqual({ filter: ok.args.filter, sortBy: ok.args.sortBy, ageMin: ok.args.ageMin, ageMax: ok.args.ageMax }, { filter: 'missing', sortBy: 'age', ageMin: 5, ageMax: 10 });

    assert.equal(validateQuery('searchChildren', { filter: 'everything' }).ok, false, 'an unknown filter is not a filter');
    assert.equal(validateQuery('searchChildren', { sortBy: 'createdAt' }).ok, false);
    assert.equal(validateQuery('searchChildren', { ageMin: 999 }).ok, false);
    assert.equal(validateQuery('searchChildren', { ageMin: { $gt: 0 } }).ok, false);
});

test('A8: an unknown event has no route at all', () => {
    assert.equal(validateQuery('adminDeleteEverything', {}).ok, false);
    assert.equal('adminDeleteEverything' in QUERY_ROUTES, false);
});

// ------------------------------------------------------------------ budget

test('A8: a connection gets a fixed budget per window, then recovers', () => {
    let clock = 1_000_000;
    const guard = createConnectionGuard({ windowMs: 1000, maxQueries: 3, maxInFlight: 2, now: () => clock });

    assert.deepEqual([guard.check().ok, guard.check().ok, guard.check().ok], [true, true, true]);
    const denied = guard.check();
    assert.equal(denied.ok, false);
    assert.equal(denied.reason, 'rate-limited');
    assert.equal(denied.retryAfterMs, 1000);

    clock += 1001;
    assert.equal(guard.check().ok, true, 'the next window starts fresh');
});

test('A8: a connection cannot have unlimited queries in flight', () => {
    const guard = createConnectionGuard({ windowMs: 1000, maxQueries: 100, maxInFlight: 2 });
    guard.check(); guard.begin();
    guard.check(); guard.begin();
    const busy = guard.check();
    assert.equal(busy.ok, false);
    assert.equal(busy.reason, 'busy', 'a pipelining client is told to wait, not served');
    guard.end();
    assert.equal(guard.check().ok, true);
});

// ------------------------------------------------------------------ wiring

test('A8: a rejected payload never reaches the query, and the client is answered', async () => {
    const socket = fakeSocket();
    const { calls, impl } = queries();
    attachQueryHandlers(socket, impl);

    await socket.send('searchByDate', 'nonsense');
    assert.equal(calls.length, 0, 'an invalid date must not query the database');
    const rejected = socket.last('queryRejected');
    assert.ok(rejected, 'the client must be told the query was rejected');
    assert.equal(rejected.payload.reason, 'invalid-date');
    assert.match(rejected.payload.message, /valid date/i);

    // The event the client listens for is answered too, as a failed empty result, so an older
    // client cannot be left waiting on "Searching...".
    const answer = socket.last('getByDateData').payload;
    assert.equal(answer.success, false);
    assert.equal(answer.error, true);
    assert.deepEqual(answer.data, []);
    assert.ok(!answer.throttled, 'this is a rejected payload, not a throttled one');

    await socket.send('searchByDate', '2026-09-01');
    assert.deepEqual(calls, [{ name: 'searchByDate', args: { value: '2026-09-01', page: 1, limit: 50 } }]);
    assert.equal(socket.last('getByDateData').payload.data[0], 'searchByDate');
});

test('A8: a flooding client is throttled instead of being served every request', async () => {
    const socket = fakeSocket();
    const { calls, impl } = queries();
    attachQueryHandlers(socket, impl);

    for (let i = 0; i < 500; i++) await socket.send('load', {});
    await new Promise((resolve) => setImmediate(resolve));

    assert.ok(calls.length <= 60 + 1, `expected the budget to bound the queries, got ${calls.length}`);
    const rejected = socket.emitted.filter((item) => item.event === 'queryRejected');
    assert.ok(rejected.length > 400, 'the flood must be answered with rejections');
    assert.equal(rejected[0].payload.reason, 'rate-limited');

    // An older client is listening for its own event, not for the rejection, so it must still
    // receive a well-formed empty result rather than hanging on "Searching...".
    const throttledResults = socket.emitted.filter((item) => item.event === 'getAllData' && item.payload.throttled);
    assert.ok(throttledResults.length > 400, 'a throttled client must receive an empty result with a message');
    assert.equal(throttledResults[0].payload.success, false);
    assert.deepEqual(throttledResults[0].payload.data, []);
    assert.match(throttledResults[0].payload.message, /too many|still running/i);
});

test('A8: a failing query answers with an empty result instead of crashing the connection', async () => {
    const socket = fakeSocket();
    attachQueryHandlers(socket, {
        ...queries().impl,
        load: () => { throw new Error('database exploded'); }
    });

    await socket.send('load', {});
    const answer = socket.last('getAllData').payload;
    assert.equal(answer.success, false);
    assert.deepEqual(answer.data, []);
});

// ------------------------------------------------------------------ wiring, statically

test('A8: the server attaches no raw socket handler and never logs a payload', () => {
    const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    const connection = server.slice(server.indexOf('io.on("connection"'), server.indexOf('//-----------------------------------------------Start server'));

    assert.match(connection, /attachQueryHandlers\(socket/, 'the connection must use the guarded handler');
    for (const event of Object.keys(QUERY_ROUTES)) {
        assert.doesNotMatch(connection, new RegExp(`socket\\.on\\("${event}"`), `${event} must not be handled raw`);
    }
    assert.doesNotMatch(connection, /console\.log\("search|console\.log\("load/, 'a client payload must never be logged');
});
