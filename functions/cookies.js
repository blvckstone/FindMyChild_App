/**
 * Cookie-based authentication.
 *
 * Login tokens used to travel to the browser in two leaky ways:
 *
 *   1. In a redirect URL (`/?google_token=...`, `/admin?admin_token=...`). A URL is written
 *      into browser history, the `Referer` header of every request the page then makes, and
 *      any proxy/CDN access log along the way — so the token escaped the page it was meant
 *      for. Screenshots, support tickets and shared links take it with them too.
 *   2. In a cookie that JavaScript could read (`httpOnly: false`) plus `localStorage`. Any
 *      script that ends up on the page can read both, so one bad dependency was enough to
 *      hand over every account. (That path is now much harder to reach because the third-party
 *      script was removed and the CSP forbids external scripts — but the token itself was
 *      still sitting where any future mistake could read it.)
 *
 * The token is now delivered as an `httpOnly` cookie: the browser sends it automatically and
 * JavaScript cannot read it. The URL carries no token at all.
 *
 * The `Authorization: Bearer` header still works and the token is still returned in the JSON
 * reply, because a client that cannot hold cookies (a script, a CLI, a future mobile app)
 * must not be broken by this. Bearer is the safer of the two for non-browser clients anyway:
 * nothing is stored anywhere on the machine.
 */

// Cookie names. Prefixed and separate so a user session can never be mistaken for an admin one.
const USER_COOKIE = 'fmc_user_token';
const ADMIN_COOKIE = 'fmc_admin_token';

// Matches JWT_EXPIRES_IN's default (7d). The session row expires on its own regardless; this
// only stops the browser from holding a cookie that is already useless.
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Parse a Cookie header into a plain object.
 *
 * `decodeURIComponent` throws on a malformed escape (a bare `%`), and the Cookie header is
 * attacker-controlled, so a bad value is kept verbatim instead of crashing the request.
 */
const parseCookies = (header) => {
    const out = Object.create(null);
    if (!header || typeof header !== 'string') return out;
    for (const part of header.split(';')) {
        const eq = part.indexOf('=');
        if (eq < 0) continue;
        const name = part.slice(0, eq).trim();
        if (!name) continue;
        const raw = part.slice(eq + 1).trim();
        try {
            out[name] = decodeURIComponent(raw);
        } catch {
            out[name] = raw;
        }
    }
    return out;
};

/**
 * True when the connection is HTTPS. Northflank terminates TLS in front of the app, so the
 * forwarded header is the reliable signal (`app.set('trust proxy', 1)` also fills `req.secure`).
 */
const isSecureRequest = (req) => Boolean(
    req && (req.secure || (req.headers && req.headers['x-forwarded-proto'] === 'https'))
);

/**
 * Attributes for the auth cookie.
 *
 * - `httpOnly`  — JavaScript cannot read it, which is the entire point.
 * - `sameSite: 'lax'` — the browser refuses to attach it to cross-site POSTs, so another site
 *   cannot make a logged-in visitor's browser perform a write on their behalf (CSRF).
 * - `secure`    — sent over HTTPS only, so it never appears on a plaintext request.
 * - `path: '/'` — valid for the whole app; the Google callback previously scoped a stale copy
 *   to `/api/admin/auth/google/callback`, which is why the panel had to delete two cookies.
 */
const cookieOptions = (req) => ({
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(req),
    path: '/',
    maxAge: COOKIE_MAX_AGE_MS
});

/** Issue the auth cookie. */
const setAuthCookie = (res, req, name, token) => {
    if (!token) return res;
    return res.cookie(name, token, cookieOptions(req));
};

/**
 * Expire the auth cookie.
 *
 * The attributes must match the ones it was set with, otherwise the browser treats it as a
 * different cookie and keeps the original — which is exactly the bug that left the admin panel
 * with a live cookie after logout.
 */
const clearAuthCookie = (res, req, name) => res.clearCookie(name, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(req),
    path: '/'
});

/** The bearer token from the Authorization header, or '' (also handles lowercase schemes). */
const bearerToken = (req) => {
    const header = (req && req.headers && req.headers.authorization) || '';
    if (typeof header !== 'string') return '';
    const match = /^Bearer[ \t]+(.+)$/i.exec(header.trim());
    return match ? match[1].trim() : '';
};

/**
 * Resolve the caller's token: the Authorization header wins, then the named cookie.
 *
 * Returns `{ token, viaCookie }`. The header wins deliberately — a client that explicitly sends
 * a token means that one, and it keeps a stale cookie from shadowing a fresh login.
 */
const readAuth = (req, name) => {
    const bearer = bearerToken(req);
    if (bearer) return { token: bearer, viaCookie: false };
    const fromCookie = parseCookies(req && req.headers && req.headers.cookie)[name];
    return fromCookie ? { token: fromCookie, viaCookie: true } : { token: '', viaCookie: false };
};

module.exports = {
    USER_COOKIE,
    ADMIN_COOKIE,
    COOKIE_MAX_AGE_MS,
    parseCookies,
    isSecureRequest,
    cookieOptions,
    setAuthCookie,
    clearAuthCookie,
    bearerToken,
    readAuth
};
