/**
 * Rate-limit counters used to live in each process (express-rate-limit's default store):
 * the configured ceiling was therefore multiplied by the number of replicas, and a deploy
 * cleared an attacker's progress against the admin login.
 *
 * These tests pin the shared store's behaviour: keys are namespaced per limiter, counting
 * is shared, and a database outage degrades to per-process counting instead of disabling
 * the limit or failing the request.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const createRateLimitStore = require('../functions/rateLimitStore');

const ROOT = path.join(__dirname, '..');
const WINDOW_MS = 15 * 60 * 1000;

/**
 * Minimal RateLimit model: just enough of the Mongoose surface the store uses.
 *
 * The window decision the store pushes into MongoDB is read back out of the pipeline it
 * built (`now` and the fresh reset time), so the simulation follows the real query rather
 * than a copy of the logic.
 */
const fakeModel = () => {
    const rows = new Map();
    return {
        rows,
        findOneAndUpdate(filter, pipeline) {
            const now = pipeline[0].$set.count.$cond[0].$gt[1];
            const freshReset = pipeline[0].$set.resetAt.$cond[2];
            const existing = rows.get(filter.key);
            const live = existing && existing.resetAt.getTime() > now.getTime();
            const doc = live
                ? { ...existing, count: existing.count + 1 }
                : { key: filter.key, count: 1, resetAt: freshReset };
            rows.set(filter.key, doc);
            return { lean: async () => ({ ...doc }) };
        },
        async updateOne(filter, update) {
            const doc = rows.get(filter.key);
            if (doc) doc.count += update.$inc.count;
        },
        async deleteOne(filter) {
            rows.delete(filter.key);
        }
    };
};

test('shared store: a limiter counts every hit and reports the window it belongs to', async () => {
    const store = createRateLimitStore({ prefix: 'admin-login', windowMs: WINDOW_MS, model: fakeModel() });
    const first = await store.increment('1.2.3.4');
    const second = await store.increment('1.2.3.4');
    const other = await store.increment('5.6.7.8');

    assert.equal(first.totalHits, 1);
    assert.equal(second.totalHits, 2);
    assert.equal(other.totalHits, 1, 'clients are counted separately');
    assert.ok(first.resetTime instanceof Date);
    assert.equal(first.resetTime.getTime() - Date.now() > 0, true, 'the window ends in the future');
});

test('shared store: two limiters sharing one collection do not share counters', async () => {
    const model = fakeModel();
    const auth = createRateLimitStore({ prefix: 'auth', windowMs: WINDOW_MS, model });
    const admin = createRateLimitStore({ prefix: 'admin-login', windowMs: WINDOW_MS, model });

    await auth.increment('1.2.3.4');
    await auth.increment('1.2.3.4');
    const adminFirst = await admin.increment('1.2.3.4');

    assert.equal(adminFirst.totalHits, 1, 'the admin limiter must not inherit the auth limiter hits');
    assert.deepEqual([...model.rows.keys()].sort(), ['admin-login:1.2.3.4', 'auth:1.2.3.4']);
});

test('shared store: a new process continues the window instead of resetting it', async () => {
    const model = fakeModel();
    const instanceA = createRateLimitStore({ prefix: 'admin-login', windowMs: WINDOW_MS, model });
    await instanceA.increment('1.2.3.4');
    await instanceA.increment('1.2.3.4');

    // A restart is a fresh store reading the same collection — this is the deploy case.
    const instanceB = createRateLimitStore({ prefix: 'admin-login', windowMs: WINDOW_MS, model });
    const afterRestart = await instanceB.increment('1.2.3.4');
    assert.equal(afterRestart.totalHits, 3, 'a deploy must not clear an attacker\'s progress');
});

test('shared store: resetKey forgets exactly one client', async () => {
    const model = fakeModel();
    const store = createRateLimitStore({ prefix: 'auth', windowMs: WINDOW_MS, model });
    await store.increment('1.2.3.4');
    await store.increment('5.6.7.8');

    await store.resetKey('1.2.3.4');
    assert.equal((await store.increment('1.2.3.4')).totalHits, 1);
    assert.equal((await store.increment('5.6.7.8')).totalHits, 2, 'other clients keep their count');
});

test('shared store: a database outage counts per process instead of removing the limit', async () => {
    const broken = () => { throw new Error('not connected'); };
    const store = createRateLimitStore({ prefix: 'admin-login', windowMs: WINDOW_MS, getModel: broken });

    const hits = [];
    for (let attempt = 0; attempt < 3; attempt++) hits.push((await store.increment('1.2.3.4')).totalHits);

    assert.deepEqual(hits, [1, 2, 3], 'requests must still be counted, never allowed unlimited');
    assert.equal(store.degraded, true);
});

test('shared store: counting returns to shared storage once the database is back', async () => {
    const model = fakeModel();
    let broken = true;
    const store = createRateLimitStore({
        prefix: 'admin-login',
        windowMs: WINDOW_MS,
        getModel: async () => {
            if (broken) throw new Error('not connected');
            return model;
        }
    });

    assert.equal((await store.increment('1.2.3.4')).totalHits, 1, 'degraded hit');
    assert.equal(store.degraded, true);

    // The outage ends: the next hit after the backoff must go back to shared storage.
    broken = false;
    store.retryAt = Date.now() - 1;
    const recovered = await store.increment('1.2.3.4');

    assert.equal(store.degraded, false);
    assert.equal(recovered.totalHits, 1, 'the shared counter starts clean and takes over');
    assert.equal(model.rows.get('admin-login:1.2.3.4').count, 1);
});

test('shared store: nonsense configuration is rejected instead of silently unshared', () => {
    assert.throws(() => createRateLimitStore({ windowMs: WINDOW_MS, model: fakeModel() }), /prefix/);
    assert.throws(() => createRateLimitStore({ prefix: 'auth', model: fakeModel() }), /windowMs/);
    assert.throws(() => createRateLimitStore({ prefix: 'auth', windowMs: WINDOW_MS }), /model or getModel/);
});

test('wiring: every limiter is backed by the shared store and the counter schema is indexed', () => {
    const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    assert.match(server, /require\('\.\/functions\/rateLimitStore'\)/);
    // Every limiter must go through the one factory, so none of them can silently keep the
    // default in-process store.
    const limiterCalls = server.match(/rateLimit\(\{/g) || [];
    assert.equal(limiterCalls.length, 1, 'limiters must be built in exactly one place');
    assert.match(server, /store: rateLimitStore\(/, 'that place must attach the shared store');
    const namedLimiters = ['auth', 'face-scan', 'report', 'donation', 'admin-login', 'public'];
    for (const name of namedLimiters) {
        assert.match(server, new RegExp(`name: '${name}'`), `${name} limiter must use the shared store`);
    }

    const models = fs.readFileSync(path.join(ROOT, 'functions/dbModels.js'), 'utf8');
    assert.match(models, /key: \{ type: String, required: true, unique: true \}/, 'the counter key must be unique');
    assert.match(models, /rateLimitSchema\.index\(\{ resetAt: 1 \}, \{ expireAfterSeconds: 0 \}\)/, 'expired windows must be reaped');
    assert.match(models, /mongoose\.models\.RateLimit \|\| mongoose\.model\('RateLimit', rateLimitSchema\)/);
});
