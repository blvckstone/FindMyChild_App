/**
 * F1 — admin tokens used to be trusted statelessly: requireAdmin fell back to JWT verification
 * when its in-process Map missed, so logging out, removing an admin from the whitelist, or
 * changing their permissions had no effect until their 7-day token expired.
 *
 * These tests run the real server (and a second real instance) against one database and assert
 * the change is immediate and shared.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { startDbServer, startSecondInstance, JWT_SECRET } = require('./helpers/dbServer');

// The spawned server gets this from the helper's env; this process needs it to mint tokens
// that the server will accept (and to sign the deliberately unissued one).
process.env.JWT_SECRET = JWT_SECRET;

let ctx;
let adminToken;

test.before(async () => {
    ctx = await startDbServer();
    adminToken = await ctx.adminToken();
});

test.after(async () => { await ctx.stop(); });

const otherAdmins = () => ctx.models.AdminUser.find({ email: { $regex: /@f1\.example$/ } }).lean();

/** Mint and register a live admin token the same way the login routes do. */
const mintAdmin = async (email, overrides = {}) => {
    const { signAdminToken, registerAdminToken } = require('../functions/auth');
    const admin = await ctx.models.AdminUser.create({
        email,
        role: 'admin',
        name: email.split('@')[0],
        active: true,
        canManageChildren: true,
        ...overrides
    });
    const token = signAdminToken({
        id: admin._id,
        email,
        role: admin.role,
        permissions: { all: false, children: !!admin.canManageChildren }
    });
    await registerAdminToken(token, admin._id);
    return { admin, token };
};

test('F1: a login token works, and logging out kills it immediately', async () => {
    const token = adminToken;
    assert.equal((await ctx.api('/api/admin/counts', { token })).status, 200, 'the login token must work');

    const out = await ctx.api('/api/admin/logout', { method: 'POST', token });
    assert.equal(out.status, 200);

    const after = await ctx.api('/api/admin/counts', { token });
    assert.equal(after.status, 401, 'logout must revoke the token, not just forget it locally');

    // Re-establish the suite's admin session for the tests that follow.
    const relogin = await ctx.api('/api/admin/login', { method: 'POST', body: { username: 'Shoeb', password: 'S3cret!' } });
    assert.equal(relogin.status, 200);
    adminToken = relogin.json.token;
    assert.equal((await ctx.api('/api/admin/counts', { token: adminToken })).status, 200);
});

test('F1: removing an admin from the whitelist revokes their access at once', async () => {
    const { admin, token } = await mintAdmin('doomed@f1.example');
    const survivor = await mintAdmin('survivor@f1.example');

    assert.equal((await ctx.api('/api/admin/counts', { token })).status, 200);

    const removed = await ctx.api(`/api/admin/admins/${admin._id}`, { method: 'DELETE', token: adminToken });
    assert.equal(removed.status, 200);
    assert.ok(removed.json.revokedSessions >= 1, 'the server must report the revoked sessions');

    assert.equal((await ctx.api('/api/admin/children', { token })).status, 401, 'a removed admin must lose access now');
    assert.equal((await ctx.api('/api/admin/children', { token: survivor.token })).status, 200, 'other admins are unaffected');
});

test('F1: demoting or disabling an admin also revokes their live token', async () => {
    const { admin, token } = await mintAdmin('demoted@f1.example');
    assert.equal((await ctx.api('/api/admin/counts', { token })).status, 200);

    const update = await ctx.api(`/api/admin/admins/${admin._id}`, {
        method: 'PUT',
        token: adminToken,
        body: { canManageChildren: false }
    });
    assert.equal(update.status, 200);

    assert.equal((await ctx.api('/api/admin/children', { token })).status, 401, 'a permission change must retire the token');
});

test('F1: the env-configured super admin can write records that reference it', async () => {
    // This admin logs in with the sentinel id 'super_admin_legacy', which is not an ObjectId.
    // Casting it into an ObjectId ref made both these actions answer 500.
    const contact = await ctx.api('/api/admin/ngo-contacts', {
        method: 'POST',
        token: adminToken,
        body: { displayName: 'Test "Contact"', phone: '8055137761', priority: 0, active: true }
    });
    assert.equal(contact.status, 201, `creating an NGO contact failed: ${JSON.stringify(contact.json)}`);
    assert.equal(contact.json.data.createdBy, undefined, 'an unusable admin id must be left unset, not stored as a string');

    const preRegistered = await ctx.models.PreRegisteredChild.create({
        parentId: new mongoose.Types.ObjectId(),
        childName: 'Pre Registered',
        faceDescriptor: Array.from({ length: 128 }, (_, i) => 0.001 * (i % 10)),
        status: 'pending'
    });
    const reviewed = await ctx.api(`/api/admin/safe-children/${preRegistered._id}`, {
        method: 'PUT',
        token: adminToken,
        body: { status: 'approved' }
    });
    assert.equal(reviewed.status, 200, `reviewing a SafeChild failed: ${JSON.stringify(reviewed.json)}`);
    assert.equal(reviewed.json.data.status, 'approved');
});

test('F1: a signed token that was never issued by this server is refused', async () => {
    // Exactly what the old stateless fallback accepted: a correctly signed JWT with no session.
    const { signAdminToken } = require('../functions/auth');
    const forged = signAdminToken({ id: 'ghost', email: 'ghost@f1.example', role: 'super_admin', permissions: { all: true } });
    assert.equal((await ctx.api('/api/admin/counts', { token: forged })).status, 401);
});

test('F1: revocation is shared, so a token minted on one instance dies on another', async () => {
    const { token } = await mintAdmin('shared@f1.example');
    const second = await startSecondInstance(ctx, { label: 'adminB' });
    try {
        // Same database, different process: the session is visible there too.
        assert.equal((await second.api('/api/admin/counts', { token })).status, 200, 'the second instance must honour the session');

        const login = await ctx.api('/api/admin/login', { method: 'POST', body: { username: 'Shoeb', password: 'S3cret!' } });
        const revoker = login.json.token;

        // Revoke through the second instance; the first must refuse it immediately.
        const admins = await otherAdmins();
        const target = admins.find((a) => a.email === 'shared@f1.example');
        const removed = await second.api(`/api/admin/admins/${target._id}`, { method: 'DELETE', token: revoker });
        assert.equal(removed.status, 200);

        assert.equal((await ctx.api('/api/admin/counts', { token })).status, 401, 'instance A must see the revocation');
        assert.equal((await second.api('/api/admin/counts', { token })).status, 401, 'instance B must see it too');
    } finally {
        second.stop();
    }
});
