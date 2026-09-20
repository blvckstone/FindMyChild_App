/**
 * Login tokens moved from a URL parameter and JavaScript-readable storage into httpOnly cookies.
 * These tests pin the properties that make that a security improvement rather than a rename:
 * the cookie is never readable by script, is not attached to cross-site writes, and its
 * attributes match on the way out so a logout really deletes it.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const {
    USER_COOKIE,
    ADMIN_COOKIE,
    parseCookies,
    isSecureRequest,
    cookieOptions,
    setAuthCookie,
    clearAuthCookie,
    bearerToken,
    readAuth
} = require('../functions/cookies');
const { isCrossSiteWrite, isStateChanging } = require('../functions/csrf');

const fakeRes = () => ({
    cookies: {},
    cleared: {},
    cookie(name, value, options) { this.cookies[name] = { value, options }; return this; },
    clearCookie(name, options) { this.cleared[name] = options; return this; }
});

const reqWith = (headers = {}) => ({ headers, secure: false });

test('cookie names are distinct, so a user session can never be read as an admin one', () => {
    assert.notEqual(USER_COOKIE, ADMIN_COOKIE);
});

test('parseCookies reads a real Cookie header', () => {
    const parsed = parseCookies('a=1; fmc_user_token=abc%2Bdef; spaced = 2 ; empty=');
    assert.equal(parsed.a, '1');
    assert.equal(parsed.fmc_user_token, 'abc+def', 'values are URL-decoded');
    assert.equal(parsed.spaced, '2', 'names and values are trimmed');
    assert.equal(parsed.empty, '');
});

test('parseCookies survives a malformed header instead of throwing', () => {
    // A bare % throws inside decodeURIComponent, and the Cookie header is attacker-controlled.
    assert.doesNotThrow(() => parseCookies('x=%E0%A4%A'));
    assert.equal(parseCookies('x=%E0%A4%A').x, '%E0%A4%A', 'an undecodable value is kept verbatim');
    // Spread because parseCookies returns a prototype-less object (it must not inherit keys like
    // `constructor` from Object.prototype, since a cookie can be named anything).
    assert.deepEqual({ ...parseCookies('garbage') }, {});
    assert.deepEqual({ ...parseCookies('') }, {});
    assert.deepEqual({ ...parseCookies(undefined) }, {});
    assert.deepEqual({ ...parseCookies(42) }, {});
});

test('bearerToken accepts the scheme and rejects an empty one', () => {
    assert.equal(bearerToken(reqWith({ authorization: 'Bearer abc' })), 'abc');
    assert.equal(bearerToken(reqWith({ authorization: 'bearer abc' })), 'abc', 'the scheme is case-insensitive');
    assert.equal(bearerToken(reqWith({ authorization: 'Bearer ' })), '', 'a bare scheme is not a token');
    assert.equal(bearerToken(reqWith({ authorization: 'Basic abc' })), '');
    assert.equal(bearerToken(reqWith({})), '');
});

test('readAuth prefers the Authorization header, then falls back to the cookie', () => {
    const both = reqWith({ authorization: 'Bearer from-header', cookie: `${USER_COOKIE}=from-cookie` });
    assert.deepEqual(readAuth(both, USER_COOKIE), { token: 'from-header', viaCookie: false });

    const cookieOnly = reqWith({ cookie: `${USER_COOKIE}=from-cookie` });
    assert.deepEqual(readAuth(cookieOnly, USER_COOKIE), { token: 'from-cookie', viaCookie: true });

    // The user cookie must not authenticate an admin request.
    assert.deepEqual(readAuth(cookieOnly, ADMIN_COOKIE), { token: '', viaCookie: false });

    assert.deepEqual(readAuth(reqWith({}), USER_COOKIE), { token: '', viaCookie: false });
    assert.deepEqual(readAuth({}, USER_COOKIE), { token: '', viaCookie: false });
});

test('the auth cookie is httpOnly, SameSite=Lax and path-wide', () => {
    const options = cookieOptions(reqWith({}));
    assert.equal(options.httpOnly, true, 'JavaScript must not be able to read the token');
    assert.equal(options.sameSite, 'lax', 'the browser must not attach it to cross-site writes');
    assert.equal(options.path, '/', 'one cookie for the whole app, not a per-path duplicate');
    assert.ok(options.maxAge > 0);
});

test('the cookie is marked Secure behind the proxy and plain over http', () => {
    assert.equal(cookieOptions(reqWith({})).secure, false);
    assert.equal(cookieOptions(reqWith({ 'x-forwarded-proto': 'https' })).secure, true, 'Northflank terminates TLS');
    assert.equal(cookieOptions({ headers: {}, secure: true }).secure, true);
    assert.equal(isSecureRequest(reqWith({ 'x-forwarded-proto': 'https' })), true);
});

test('logging out expires the cookie with the attributes it was set with', () => {
    const req = reqWith({ 'x-forwarded-proto': 'https' });
    const res = fakeRes();
    setAuthCookie(res, req, ADMIN_COOKIE, 'tok');
    clearAuthCookie(res, req, ADMIN_COOKIE);

    const set = res.cookies[ADMIN_COOKIE].options;
    const cleared = res.cleared[ADMIN_COOKIE];
    // A browser deletes a cookie only when the attributes match; the panel used to clear two
    // same-named cookies on other paths while the real one survived.
    assert.equal(cleared.path, set.path);
    assert.equal(cleared.secure, set.secure);
    assert.equal(cleared.httpOnly, set.httpOnly);
    assert.equal(cleared.sameSite, set.sameSite);
    assert.equal(cleared.maxAge, undefined, 'express sets an expiry in the past instead');
});

test('setAuthCookie refuses to write an empty token', () => {
    const res = fakeRes();
    setAuthCookie(res, reqWith({}), USER_COOKIE, '');
    assert.deepEqual(res.cookies, {});
});

test('state-changing methods are the only ones a cookie write is checked for', () => {
    assert.equal(isStateChanging('GET'), false);
    assert.equal(isStateChanging('head'), false);
    assert.equal(isStateChanging('OPTIONS'), false);
    assert.equal(isStateChanging('POST'), true);
    assert.equal(isStateChanging('PUT'), true);
    assert.equal(isStateChanging('DELETE'), true);
    assert.equal(isStateChanging(undefined), false);
});

test('a cross-site write is refused and a same-origin one is allowed', () => {
    const host = 'findmychild.example';
    const sameSite = { method: 'POST', headers: { origin: `https://${host}`, host } };
    assert.equal(isCrossSiteWrite(sameSite), false);

    const crossSite = { method: 'POST', headers: { origin: 'https://evil.example', host } };
    assert.equal(isCrossSiteWrite(crossSite), true, 'another site must not drive a logged-in write');

    const nullOrigin = { method: 'POST', headers: { origin: 'null', host } };
    assert.equal(isCrossSiteWrite(nullOrigin), true, 'a sandboxed iframe is never trusted');

    // No Origin means no browser: nothing to be tricked into sending a cookie.
    assert.equal(isCrossSiteWrite({ method: 'POST', headers: { host } }), false);

    // Reads are not affected — a cross-site GET cannot change anything.
    assert.equal(isCrossSiteWrite({ method: 'GET', headers: { origin: 'https://evil.example', host } }), false);
});
