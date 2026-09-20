/**
 * CSRF guard for cookie-authenticated writes.
 *
 * Moving the login token into a cookie means the browser attaches it to requests automatically.
 * That is what we want for reads, but it also means a request could be triggered *by another
 * site* while a visitor is logged in — the classic CSRF shape.
 *
 * Two independent things stop that here:
 *
 *   1. The cookie is `SameSite=Lax`, so a browser does not attach it to a cross-site POST/PUT/
 *      DELETE at all. That alone is the main defence and it is enforced by the browser.
 *   2. This check, which is the server's own view: a state-changing request that arrived with a
 *      cookie must also carry an `Origin` that this app trusts. It costs nothing and does not
 *      depend on the browser honouring SameSite correctly.
 *
 * Requests authenticated by an `Authorization` header are not affected. A non-browser client
 * has no cookie to be tricked into sending, and can simply omit `Origin`.
 */

const { createOriginPolicy } = require('./origins');

// Same policy the CORS layer uses, so `ALLOWED_ORIGINS` means one thing in both places.
const policy = createOriginPolicy(process.env.ALLOWED_ORIGINS);

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const isStateChanging = (method) => !SAFE_METHODS.has(String(method || 'GET').toUpperCase());

/**
 * True when a cookie-authenticated request looks like a cross-site write.
 *
 * A missing `Origin` is allowed on purpose: browsers always send it for cross-site writes, so
 * its absence means the caller is not a browser (curl, server-to-server, a test).
 */
const isCrossSiteWrite = (req) => {
    if (!req || !isStateChanging(req.method)) return false;
    const origin = req.headers && req.headers.origin;
    if (!origin) return false;
    return !policy.isAllowed(origin, req.headers.host);
};

module.exports = { isStateChanging, isCrossSiteWrite, policy };
