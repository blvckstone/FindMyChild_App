/**
 * G1 — the app used to keep sessions in process memory, which made a second instance useless:
 * it did not recognise logins minted elsewhere, and blocking an account on one instance left
 * the account working on another.
 *
 * These tests run TWO real server processes against one database and check the properties that
 * matter for horizontal scaling: a shared login, a shared logout, and a shared revocation.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { startDbServer, startSecondInstance } = require('./helpers/dbServer');

let ctx;
let instanceB;
let adminToken;

const user = {
    name: 'Multi Instance User',
    phone: '9876502211',
    email: 'multi@example.com',
    password: 'pass1234'
};

test.before(async () => {
    ctx = await startDbServer();
    instanceB = await startSecondInstance(ctx, { label: 'B' });
    adminToken = await ctx.adminToken();

    const { hashPassword } = require('../functions/passwords');
    await ctx.models.User.deleteMany({ userContactNumber: user.phone });
    await ctx.models.User.create({
        userFullName: user.name,
        userContactNumber: user.phone,
        emailId: user.email,
        password: hashPassword(user.password)
    });
});

test.after(async () => {
    if (instanceB) instanceB.stop();
    if (ctx) await ctx.stop();
});

const login = async (api) => {
    const res = await api('/api/auth/login', {
        method: 'POST',
        body: { identifier: user.phone, password: user.password }
    });
    assert.equal(res.status, 200, JSON.stringify(res.json));
    return res.json.token;
};

test('G1: a login made on one instance works on another', async () => {
    const token = await login(ctx.api);

    const onA = await ctx.api('/api/auth/me', { token });
    assert.equal(onA.status, 200, 'the issuing instance must accept its own token');

    const onB = await instanceB.api('/api/auth/me', { token });
    assert.equal(onB.status, 200, 'a second instance must recognise a token it never issued');
    assert.equal(onB.json.user.userContactNumber, user.phone);
});

test('G1: a session survives a restart of the instance that issued it', async () => {
    // A throwaway instance issues the login, then dies; a fresh instance must still accept it.
    const first = await startSecondInstance(ctx, { label: 'temp-1' });
    let restarted = null;
    try {
        const token = await login(first.api);
        assert.equal((await first.api('/api/auth/me', { token })).status, 200);

        first.stop();
        await new Promise((resolve) => setTimeout(resolve, 300));

        restarted = await startSecondInstance(ctx, { label: 'temp-2' });
        const afterRestart = await restarted.api('/api/auth/me', { token });
        assert.equal(afterRestart.status, 200, 'a restart must not log users out');
    } finally {
        if (restarted) restarted.stop();
        first.stop();
    }
});

test('G1: logging out on one instance ends the session everywhere', async () => {
    const token = await login(ctx.api);

    const logout = await instanceB.api('/api/auth/logout', { method: 'POST', token });
    assert.equal(logout.status, 200);

    const onA = await ctx.api('/api/auth/me', { token });
    assert.equal(onA.status, 401, 'the other instance must stop honouring the token');
    const onB = await instanceB.api('/api/auth/me', { token });
    assert.equal(onB.status, 401);
});

test('G1: blocking a user on one instance revokes their session on the other', async () => {
    const token = await login(ctx.api);
    assert.equal((await instanceB.api('/api/auth/me', { token })).status, 200);

    const stored = await ctx.models.User.findOne({ userContactNumber: user.phone });
    const blocked = await instanceB.api(`/api/admin/users/${stored._id}`, {
        method: 'PUT',
        token: adminToken,
        body: { blocked: true }
    });
    assert.equal(blocked.status, 200, JSON.stringify(blocked.json));

    const onB = await instanceB.api('/api/auth/me', { token });
    assert.equal(onB.status, 401, 'the blocking instance must reject immediately');
    const onA = await ctx.api('/api/auth/me', { token });
    assert.equal(onA.status, 401, 'and so must the instance that issued the token');

    const relogin = await ctx.api('/api/auth/login', {
        method: 'POST',
        body: { identifier: user.phone, password: user.password }
    });
    assert.equal(relogin.status, 401, 'a blocked account must not be able to log back in');

    await ctx.models.User.updateOne({ _id: stored._id }, { $set: { blocked: false } });
});

test('G1: sessions are rows in the database, one per login', async () => {
    const token = await login(ctx.api);
    const row = await ctx.models.Session.findOne({ token }).lean();

    assert.ok(row, 'the login must have created a session row');
    assert.equal(row.kind, 'user');
    assert.ok(new Date(row.expiresAt).getTime() > Date.now(), 'the session must carry a future expiry');

    // A second login adds a second row rather than replacing the first: two devices, two sessions.
    const secondToken = await login(ctx.api);
    assert.notEqual(secondToken, token);
    const count = await ctx.models.Session.countDocuments({ token: { $in: [token, secondToken] } });
    assert.equal(count, 2);
});
