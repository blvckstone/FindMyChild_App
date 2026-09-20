/**
 * The login token used to reach the browser three ways, two of which leaked it:
 *
 *   - `/?google_token=<token>` and `/admin?admin_token=<token>` — a token in a URL is written
 *     into browser history, the Referer header of every request the page makes, and any proxy
 *     or CDN access log. It also carries into screenshots and shared links.
 *   - `localStorage` and a cookie with `httpOnly: false` — readable by any script on the page,
 *     so one bad dependency (or one injected line) handed over every account.
 *
 * The token now arrives as an httpOnly cookie the page cannot read, and the URLs carry nothing.
 * These tests run the real server against a real database and behave like a browser that keeps
 * cookies, including the cases that are easy to get wrong: logging out when the cookie is the
 * only credential, a cross-site write, and a cookie-only session saving its own profile.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startDbServer } = require('./helpers/dbServer');

let ctx;

test.before(async () => { ctx = await startDbServer(); });
test.after(async () => { await ctx.stop(); });

/** Minimal browser-like cookie jar: absorbs Set-Cookie, replays it on the next request. */
const jar = () => {
    const store = new Map();
    return {
        absorb(setCookie = []) {
            for (const raw of setCookie) {
                const [pair] = raw.split(';');
                const eq = pair.indexOf('=');
                const name = pair.slice(0, eq).trim();
                const value = pair.slice(eq + 1).trim();
                const expired = /expires=thu, 01 jan 1970/i.test(raw) || /max-age=0/i.test(raw);
                if (!value || expired) store.delete(name);
                else store.set(name, value);
            }
        },
        header() { return [...store.entries()].map(([k, v]) => `${k}=${v}`).join('; '); },
        has(name) { return store.has(name); }
    };
};

/** Register a user through the real API. Signup needs a verified email, so seed an account. */
const seedUser = async (contactNumber) => {
    const { hashPassword } = require('../functions/passwords');
    await ctx.models.User.create({
        userFullName: 'Cookie Test',
        userContactNumber: contactNumber,
        emailId: '',
        password: hashPassword('CorrectHorse1!'),
        createdAt: new Date().toISOString()
    });
    return contactNumber;
};

test('a user login hands the token over as an httpOnly cookie, not a readable one', async () => {
    const contact = await seedUser('9800000001');
    const login = await ctx.api('/api/auth/login', {
        method: 'POST',
        body: { identifier: contact, password: 'CorrectHorse1!' }
    });
    assert.equal(login.status, 200);

    const cookie = login.setCookie.find((c) => c.startsWith('fmc_user_token='));
    assert.ok(cookie, `login must set the auth cookie, got: ${JSON.stringify(login.setCookie)}`);
    assert.match(cookie, /HttpOnly/i, 'a script must not be able to read the token');
    assert.match(cookie, /SameSite=Lax/i, 'the browser must not attach it to cross-site writes');
    assert.match(cookie, /Path=\//i);
    assert.doesNotMatch(cookie, /Secure/i, 'over plain http the cookie must still be accepted in tests');
});

test('the cookie alone authenticates a request, and a Bearer token still works too', async () => {
    const contact = await seedUser('9800000002');
    const login = await ctx.api('/api/auth/login', {
        method: 'POST',
        body: { identifier: contact, password: 'CorrectHorse1!' }
    });
    const j = jar();
    j.absorb(login.setCookie);

    const withCookie = await ctx.api('/api/auth/me', { cookie: j.header() });
    assert.equal(withCookie.status, 200, 'the browser sends the cookie by itself; no header needed');
    assert.equal(withCookie.json.user.userContactNumber, contact);

    // Non-browser clients are unaffected: the token is still returned and still accepted.
    const withHeader = await ctx.api('/api/auth/me', { token: login.json.token });
    assert.equal(withHeader.status, 200, 'the Bearer path must keep working');

    const anonymous = await ctx.api('/api/auth/me');
    assert.equal(anonymous.status, 401);
});

test('logging out with only a cookie kills the session and expires the cookie', async () => {
    const contact = await seedUser('9800000003');
    const login = await ctx.api('/api/auth/login', {
        method: 'POST',
        body: { identifier: contact, password: 'CorrectHorse1!' }
    });
    const j = jar();
    j.absorb(login.setCookie);
    assert.ok(j.has('fmc_user_token'));

    const out = await ctx.api('/api/auth/logout', { method: 'POST', cookie: j.header() });
    assert.equal(out.status, 200);

    // The old code read the token from the Authorization header only, so a cookie session looked
    // logged out on the page while remaining alive on the server.
    const after = await ctx.api('/api/auth/me', { cookie: j.header() });
    assert.equal(after.status, 401, 'the session must be revoked, not just forgotten by the page');

    const expired = out.setCookie.find((c) => c.startsWith('fmc_user_token='));
    assert.ok(expired, 'logout must clear the cookie in the same reply');
    assert.match(expired, /(Expires=Thu, 01 Jan 1970|Max-Age=0)/i);
});

test('an admin logs in by cookie and the panel can identify itself without holding a token', async () => {
    const login = await ctx.api('/api/admin/login', {
        method: 'POST',
        body: { username: 'Shoeb', password: 'S3cret!' }
    });
    assert.equal(login.status, 200);

    const cookie = login.setCookie.find((c) => c.startsWith('fmc_admin_token='));
    assert.ok(cookie, 'admin login must set the auth cookie');
    assert.match(cookie, /HttpOnly/i, 'the admin cookie used to be httpOnly:false');

    const j = jar();
    j.absorb(login.setCookie);

    // This is exactly what the panel now does on load when it has no stored token.
    const me = await ctx.api('/api/admin/me', { cookie: j.header() });
    assert.equal(me.status, 200);
    assert.equal(me.json.admin.email, 'iblvckstone@gmail.com');
    assert.equal(me.json.admin.role, 'super_admin');

    const counts = await ctx.api('/api/admin/counts', { cookie: j.header() });
    assert.equal(counts.status, 200, 'a cookie session must reach admin data');
});

test('a browser acting for another site cannot drive a logged-in write, but this site can', async () => {
    const login = await ctx.api('/api/admin/login', {
        method: 'POST',
        body: { username: 'Shoeb', password: 'S3cret!' }
    });
    const j = jar();
    j.absorb(login.setCookie);

    const host = new URL(ctx.base).host;
    const crossSite = await ctx.api('/api/admin/me', {
        method: 'PUT',
        cookie: j.header(),
        headers: { origin: 'https://evil.example' },
        body: { name: 'Hijacked' }
    });
    assert.equal(crossSite.status, 403, 'another site must not be able to write with this cookie');

    const sameSite = await ctx.api('/api/admin/me', {
        method: 'PUT',
        cookie: j.header(),
        headers: { origin: `http://${host}` },
        body: { name: 'Legit' }
    });
    assert.equal(sameSite.status, 200, `same-origin writes must still work: ${JSON.stringify(sameSite.json)}`);
    // A successful profile save retires the old token and issues a new one, exactly as the panel
    // does with the returned token. Track it, or the next request would be using a dead token.
    j.absorb(sameSite.setCookie);

    // A read is never blocked: a cross-site GET cannot change anything.
    const read = await ctx.api('/api/admin/counts', { cookie: j.header(), headers: { origin: 'https://evil.example' } });
    assert.equal(read.status, 200);
});

test('a cookie-only admin stays logged in after saving their profile', async () => {
    // Saving the profile retires the old token and issues a new one. If the reply did not replace
    // the cookie, a browser that holds no token would have been logged out by its own save.
    const login = await ctx.api('/api/admin/login', {
        method: 'POST',
        body: { username: 'Shoeb', password: 'S3cret!' }
    });
    const j = jar();
    j.absorb(login.setCookie);

    const saved = await ctx.api('/api/admin/me', {
        method: 'PUT',
        cookie: j.header(),
        headers: { origin: `http://${new URL(ctx.base).host}` },
        body: { name: 'Renamed Admin' }
    });
    assert.equal(saved.status, 200);
    assert.ok(saved.setCookie.some((c) => c.startsWith('fmc_admin_token=')), 'the reply must replace the cookie');

    j.absorb(saved.setCookie);
    assert.equal((await ctx.api('/api/admin/counts', { cookie: j.header() })).status, 200, 'the new cookie must work');
    assert.equal((await ctx.api('/api/admin/counts', { cookie: `${'fmc_admin_token='}${login.json.token}` })).status, 401,
        'the replaced token must be retired');
});

test('an admin logged out by cookie is refused immediately', async () => {
    const login = await ctx.api('/api/admin/login', {
        method: 'POST',
        body: { username: 'Shoeb', password: 'S3cret!' }
    });
    const j = jar();
    j.absorb(login.setCookie);

    const out = await ctx.api('/api/admin/logout', { method: 'POST', cookie: j.header() });
    assert.equal(out.status, 200);
    assert.ok(out.setCookie.some((c) => c.startsWith('fmc_admin_token=')), 'logout must clear the cookie');
    assert.equal((await ctx.api('/api/admin/counts', { cookie: j.header() })).status, 401);
});

/**
 * Strip comments before matching, so the explanatory comments that describe the old behaviour
 * (which necessarily quote it) do not read as the behaviour itself.
 */
const codeOnly = (source) => source
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');

test('no route puts a token in a URL any more, and no panel expects one', async () => {
    // The OAuth callbacks cannot be driven end-to-end without Google, so this pins the code
    // itself: no redirect may carry a token or the admin's name/role as a query parameter.
    const server = codeOnly(fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8'));
    assert.doesNotMatch(server, /google_token=/, 'the user Google callback must not put the token in the URL');
    assert.doesNotMatch(server, /admin_token=/, 'the admin Google callback must not put the token in the URL');
    assert.doesNotMatch(server, /[?&]admin_role=/, 'the admin role does not belong in a URL either');
    assert.match(server, /setAuthCookie\(res, req, USER_COOKIE/, 'the user Google callback must set the cookie');
    assert.match(server, /setAuthCookie\(res, req, ADMIN_COOKIE/, 'the admin Google callback must set the cookie');

    const admin = codeOnly(fs.readFileSync(path.join(__dirname, '..', 'public', 'admin.html'), 'utf8'));
    assert.doesNotMatch(admin, /getCookie\(\s*['"]fmc_admin_token/, 'the panel must not read a cookie that is httpOnly');
    // `fmc_admin_token` is the cookie's name and may still be referenced; a *query parameter*
    // named admin_token is what must not exist.
    assert.doesNotMatch(admin, /[?&]admin_token|adminTokenParam/, 'the panel must not expect a token in the URL');

    const index = codeOnly(fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8'));
    assert.doesNotMatch(index, /google_token/, 'the user panel must not read a token from the URL');
});
