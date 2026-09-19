/**
 * A3/G1 — the admin login ceiling.
 *
 * The limit used to be counted inside each process: two replicas allowed 20 attempts, and any
 * deploy restarted the count from zero, which is exactly what a brute-force attempt needs.
 *
 * This starts two real server processes against one real database, spends the quota across
 * both, and then checks a third, freshly started process — the deploy case — is still blocked.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const { startDbServer, startSecondInstance, ADMIN } = require('./helpers/dbServer');

const MAX_ATTEMPTS = 10;

test('A3/G1: admin login is throttled across replicas and across a restart', async (t) => {
    const instanceA = await startDbServer();
    const instanceB = await startSecondInstance(instanceA, { label: 'RL-B' });
    t.after(async () => {
        await instanceB.stop();
        await instanceA.stop();
    });

    const attempt = (instance, password) => instance.api('/api/admin/login', {
        method: 'POST',
        body: { username: ADMIN.username, password }
    });

    // Spend the whole quota, split between the two replicas.
    const half = MAX_ATTEMPTS / 2;
    for (let i = 1; i <= half; i++) {
        const res = await attempt(instanceA, `wrong-a-${i}`);
        assert.equal(res.status, 401, `replica A attempt ${i} is a normal credential failure`);
    }
    for (let i = 1; i <= half; i++) {
        const res = await attempt(instanceB, `wrong-b-${i}`);
        assert.equal(res.status, 401, `replica B attempt ${i} is a normal credential failure`);
    }

    // The quota is spent globally, so the next attempt is throttled on either replica.
    const blockedOnA = await attempt(instanceA, 'wrong-a-extra');
    const blockedOnB = await attempt(instanceB, 'wrong-b-extra');
    assert.equal(blockedOnA.status, 429, 'replica A must see the hits replica B counted');
    assert.equal(blockedOnB.status, 429, 'replica B must see the hits replica A counted');

    // And the counter really is a shared row, not a coincidentally equal per-process count.
    const rows = await instanceA.models.RateLimit.find({}).lean();
    const adminRow = rows.find((row) => String(row.key).startsWith('admin-login:'));
    assert.ok(adminRow, 'the admin login counter must be stored in MongoDB');
    assert.ok(adminRow.count > MAX_ATTEMPTS, `the shared counter must exceed one replica's quota (got ${adminRow && adminRow.count})`);

    const indexes = await instanceA.models.RateLimit.collection.indexes();
    const ttl = indexes.find((index) => index.key && index.key.resetAt === 1 && index.expireAfterSeconds === 0);
    assert.ok(ttl, 'expired windows must be reaped by a TTL index');

    // A brand-new process — what a deploy looks like — must not get a clean slate.
    const instanceC = await startSecondInstance(instanceA, { label: 'RL-C' });
    t.after(() => instanceC.stop());
    const afterRestart = await attempt(instanceC, 'wrong-c-1');
    assert.equal(afterRestart.status, 429, 'a restarted instance must continue the shared window');

    // A correct credential is throttled too: the limiter sits in front of authentication.
    const correctPassword = await attempt(instanceC, ADMIN.password);
    assert.equal(correctPassword.status, 429, 'the throttle must not be bypassable with a guessed valid password');
});
