const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { hashPassword } = require('../functions/passwords');
const { loadAuth, bearerStatus } = require('./helpers/loadAuth');

const TEST_SECRET = 'test-secret';
process.env.JWT_SECRET = TEST_SECRET;

// ---------------------------------------------------------------- A2 (fail-open)

test('A2: legacy admin login is refused when ADMIN_USERNAME / ADMIN_PASS are unset', () => {
    const prevUser = process.env.ADMIN_USERNAME;
    const prevPass = process.env.ADMIN_PASS;
    delete process.env.ADMIN_USERNAME;
    delete process.env.ADMIN_PASS;
    const { auth, restore } = loadAuth();
    try {
        // Before the fix this payload authenticated as super_admin, because
        // safeEqual() compares String(undefined) === "undefined" on both sides.
        assert.equal(auth.loginAdmin('undefined', 'undefined'), null, 'literal "undefined" credentials must be rejected');
        assert.equal(auth.loginAdmin('undefined', ''), null);
        assert.equal(auth.loginAdmin('', ''), null);
        assert.equal(auth.loginAdmin('Shoeb', 'undefined'), null);
    } finally {
        restore();
        if (prevUser === undefined) delete process.env.ADMIN_USERNAME; else process.env.ADMIN_USERNAME = prevUser;
        if (prevPass === undefined) delete process.env.ADMIN_PASS; else process.env.ADMIN_PASS = prevPass;
    }
});

test('A2: legacy admin login still works when both credentials are configured', () => {
    process.env.ADMIN_USERNAME = 'Shoeb';
    process.env.ADMIN_PASS = 'S3cret!';
    const { auth, restore } = loadAuth();
    try {
        assert.equal(auth.loginAdmin('Shoeb', 'nope'), null, 'wrong password rejected');
        assert.equal(auth.loginAdmin('someone', 'S3cret!'), null, 'wrong username rejected');
        assert.equal(auth.loginAdmin('undefined', 'undefined'), null, 'literal "undefined" still rejected');
        const result = auth.loginAdmin('Shoeb', 'S3cret!');
        assert.ok(result && result.token, 'valid credentials return a token');
        assert.equal(jwt.verify(result.token, TEST_SECRET).role, 'super_admin');
    } finally {
        restore();
        delete process.env.ADMIN_USERNAME;
        delete process.env.ADMIN_PASS;
    }
});

// ---------------------------------------------------------------- A5 (blocking)

test('A5: a blocked account cannot obtain a login token', async () => {
    const blocked = { _id: 'user-1', userContactNumber: '9876543210', blocked: true, password: hashPassword('pass1234') };
    const { auth, restore } = loadAuth({ User: { findOne: async () => blocked } });
    try {
        const result = await auth.loginUser('9876543210', 'pass1234');
        assert.match(String(result.error), /blocked/i);
        assert.equal(result.token, undefined);
    } finally {
        restore();
    }
});

test('A5: an unblocked account still logs in normally', async () => {
    const active = { _id: 'user-2', userContactNumber: '9876543210', blocked: false, password: hashPassword('pass1234') };
    const { auth, restore } = loadAuth({ User: { findOne: async () => active } });
    try {
        const result = await auth.loginUser('9876543210', 'pass1234');
        assert.equal(result.error, undefined);
        assert.ok(result.token);
    } finally {
        restore();
    }
});

test('A5: wrong password is reported as invalid credentials, not as blocked', async () => {
    const blocked = { _id: 'user-1', blocked: true, password: hashPassword('pass1234') };
    const { auth, restore } = loadAuth({ User: { findOne: async () => blocked } });
    try {
        const result = await auth.loginUser('9876543210', 'wrong-password');
        assert.equal(result.error, 'Invalid credentials.');
    } finally {
        restore();
    }
});

test('A5: revokeUserTokens closes every session the user holds and nothing else', async () => {
    // Sessions are shared state now, so this exercises the store rather than a process Map.
    const { auth, restore } = loadAuth();
    try {
        await auth.registerUserToken('token-a', 'user-1');
        await auth.registerUserToken('token-b', 'user-1');
        await auth.registerUserToken('token-c', 'user-2');
        assert.equal(await bearerStatus(auth, 'token-a'), 200);
        assert.equal(await bearerStatus(auth, 'token-c'), 200);

        assert.equal(await auth.revokeUserTokens('user-1'), 2, 'both of user-1 sessions removed');

        assert.equal(await bearerStatus(auth, 'token-a'), 401);
        assert.equal(await bearerStatus(auth, 'token-b'), 401);
        assert.equal(await bearerStatus(auth, 'token-c'), 200, 'other users stay logged in');
        assert.equal(await bearerStatus(auth, 'not-a-real-token'), 401);
    } finally {
        restore();
    }
});


// ---------------------------------------------------- signup regression guard

test('signup validation still rejects bad name, phone and password', async () => {
    const created = [];
    const models = { User: { findOne: async () => null, create: async (doc) => { created.push(doc); return { _id: 'new-user', ...doc }; } } };
    const { auth, restore } = loadAuth(models);
    try {
        // API contract is "name must not be blank"; the 2-character minimum is a UI-only rule.
        assert.match((await auth.signupUser({ fullName: '   ', contactNumber: '9876543210', password: 'longenough' })).error, /Full name/i);
        assert.match((await auth.signupUser({ fullName: 'Aamna', contactNumber: '12345', password: 'longenough' })).error, /valid phone/i);
        assert.match((await auth.signupUser({ fullName: 'Aamna', contactNumber: '9876543210', password: '123' })).error, /Password/i);
        assert.equal(created.length, 0, 'nothing written for invalid signups');
    } finally {
        restore();
    }
});

test('signup normalizes phone/email and hashes the password', async () => {
    const created = [];
    const models = { User: { findOne: async () => null, create: async (doc) => { created.push(doc); return { _id: 'new-user', ...doc }; } } };
    const { auth, restore } = loadAuth(models);
    try {
        const result = await auth.signupUser({
            fullName: 'Aamna Khan',
            contactNumber: '+91 98765 43210',
            emailId: 'Aamna@Example.COM',
            password: 'longenough'
        });
        assert.ok(result.token);
        assert.equal(created.length, 1);
        assert.equal(created[0].emailId, 'aamna@example.com');
        assert.equal(created[0].userContactNumber, '9876543210');
        assert.match(created[0].password, /^scrypt\$/, 'password is hashed, never stored raw');
    } finally {
        restore();
    }
});

test('signup still refuses a duplicate phone or email', async () => {
    const models = { User: { findOne: async () => ({ _id: 'existing' }) } };
    const { auth, restore } = loadAuth(models);
    try {
        const result = await auth.signupUser({ fullName: 'Aamna', contactNumber: '9876543210', password: 'longenough' });
        assert.match(result.error, /already exists/i);
    } finally {
        restore();
    }
});
