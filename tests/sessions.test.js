/**
 * G1 — sessions used to live in a module-level Map: a restart logged everyone out, and a second
 * instance recognised no token minted by the first (and could not revoke one). These tests pin
 * the shared store's behaviour, including expiry.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sessions = require('../functions/sessions');

const ROOT = path.join(__dirname, '..');

/** Minimal Session model: enough of the Mongoose surface the store uses. */
const fakeSessionModel = (rows = []) => {
    const state = { rows };
    return {
        state,
        async updateOne(filter, update) {
            const existing = state.rows.find((row) => row.token === filter.token);
            if (existing) Object.assign(existing, update.$set);
            else state.rows.push({ ...update.$set });
            return { acknowledged: true };
        },
        findOne(filter) {
            const row = state.rows.find((item) => item.token === filter.token);
            return { lean: async () => (row ? { ...row } : null) };
        },
        async deleteOne(filter) {
            const before = state.rows.length;
            state.rows = state.rows.filter((row) => row.token !== filter.token);
            return { deletedCount: before - state.rows.length };
        },
        async deleteMany(filter) {
            const before = state.rows.length;
            if (filter.userId !== undefined) {
                state.rows = state.rows.filter((row) => row.userId !== filter.userId);
            } else if (filter.expiresAt && filter.expiresAt.$lte) {
                const cutoff = filter.expiresAt.$lte.getTime();
                state.rows = state.rows.filter((row) => new Date(row.expiresAt).getTime() > cutoff);
            } else {
                state.rows = [];
            }
            return { deletedCount: before - state.rows.length };
        }
    };
};

test('G1: a session is stored with an owner, a kind and a real expiry', async () => {
    const Session = fakeSessionModel();
    const created = await sessions.createSession(Session, { token: 'tok-1', userId: 'user-1', now: 1_000_000 });

    assert.equal(created.userId, 'user-1');
    assert.equal(created.kind, 'user');
    assert.equal(Session.state.rows.length, 1);
    assert.equal(new Date(Session.state.rows[0].expiresAt).getTime(), 1_000_000 + sessions.SESSION_TTL_MS);
});

test('G1: re-issuing a token updates the row instead of duplicating it', async () => {
    const Session = fakeSessionModel();
    await sessions.createSession(Session, { token: 'tok-1', userId: 'user-1' });
    await sessions.createSession(Session, { token: 'tok-1', userId: 'user-1' });
    assert.equal(Session.state.rows.length, 1, 'the token is the unique key');
});

test('G1: an unknown token resolves to nothing', async () => {
    const Session = fakeSessionModel();
    assert.equal(await sessions.lookupSession(Session, 'nope'), null);
    assert.equal(await sessions.lookupSession(Session, ''), null);
    assert.equal(await sessions.lookupSession(null, 'tok'), null);
});

test('G1: an expired session stops working even before the TTL monitor runs', async () => {
    const Session = fakeSessionModel();
    await sessions.createSession(Session, { token: 'tok-1', userId: 'user-1', now: 1_000_000 });

    const stillValid = await sessions.lookupSession(Session, 'tok-1', 1_000_000 + sessions.SESSION_TTL_MS - 1000);
    assert.ok(stillValid, 'the session must be valid up to its expiry');

    const expired = await sessions.lookupSession(Session, 'tok-1', 1_000_000 + sessions.SESSION_TTL_MS + 1);
    assert.equal(expired, null, 'an expired token must never authenticate');
});

test('G1: revoking a user removes every session they hold', async () => {
    const Session = fakeSessionModel();
    await sessions.createSession(Session, { token: 'a', userId: 'user-1' });
    await sessions.createSession(Session, { token: 'b', userId: 'user-1' });
    await sessions.createSession(Session, { token: 'c', userId: 'user-2' });

    const removed = await sessions.deleteUserSessions(Session, 'user-1');
    assert.equal(removed, 2);
    assert.deepEqual(Session.state.rows.map((row) => row.token), ['c']);
});

test('G1: logging out removes exactly one token', async () => {
    const Session = fakeSessionModel();
    await sessions.createSession(Session, { token: 'a', userId: 'user-1' });
    await sessions.createSession(Session, { token: 'b', userId: 'user-1' });

    assert.equal(await sessions.deleteSession(Session, 'a'), 1);
    assert.deepEqual(Session.state.rows.map((row) => row.token), ['b']);
    assert.equal(await sessions.deleteSession(Session, 'missing'), 0);
});

test('G1: pruning clears only the expired rows', async () => {
    const Session = fakeSessionModel();
    await sessions.createSession(Session, { token: 'old', userId: 'user-1', now: 1_000_000 });
    await sessions.createSession(Session, { token: 'fresh', userId: 'user-1', now: 1_000_000 + sessions.SESSION_TTL_MS });

    const removed = await sessions.pruneExpiredSessions(Session, 1_000_000 + sessions.SESSION_TTL_MS + 1);
    assert.equal(removed, 1);
    assert.deepEqual(Session.state.rows.map((row) => row.token), ['fresh']);
});

test('G1: the store refuses nonsense instead of storing it', async () => {
    const Session = fakeSessionModel();
    await assert.rejects(() => sessions.createSession(Session, { userId: 'u' }), /token is required/);
    await assert.rejects(() => sessions.createSession(Session, { token: 't', userId: 'u', kind: 'root' }), /Unknown session kind/);
    await assert.rejects(() => sessions.createSession(null, { token: 't', userId: 'u' }), /unavailable/);
});

test('G1: the session schema carries a TTL index and the app no longer keeps tokens in memory', () => {
    const models = fs.readFileSync(path.join(ROOT, 'functions/dbModels.js'), 'utf8');
    assert.match(models, /sessionSchema\.index\(\{ expiresAt: 1 \}, \{ expireAfterSeconds: 0 \}\)/, 'expired sessions must be reaped automatically');
    assert.match(models, /const Session = mongoose\.models\.Session \|\| mongoose\.model\('Session', sessionSchema\)/);

    const auth = fs.readFileSync(path.join(ROOT, 'functions/auth.js'), 'utf8');
    assert.doesNotMatch(auth, /const userTokens = new Map\(\)/, 'user tokens must not live in process memory');
    assert.match(auth, /await lookupSession\(Session, token\)/);
    assert.match(auth, /await registerUserToken\(token, user\._id\)/);

    const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    assert.match(server, /await revokeUserTokens\(req\.params\.id\)/, 'revocation must be awaited so the write completes');
});
