/**
 * CORS origin policy.
 *
 * Before this existed the app answered every request with `Access-Control-Allow-Origin: *`
 * (and socket.io advertised `origin: "*"`), so any page on the internet could call the API
 * from a visitor's browser and read the responses.
 *
 * The policy is deliberately same-origin by default, because that is what this app actually
 * needs: the user panel and the admin panel are served by this same Express server, and
 * same-origin requests are not subject to CORS at all. Extra origins must be opted into
 * explicitly through ALLOWED_ORIGINS.
 *
 *   ALLOWED_ORIGINS unset          -> same-origin only
 *   ALLOWED_ORIGINS=https://a.com  -> same-origin + https://a.com
 *   ALLOWED_ORIGINS=a.com,b.com    -> same-origin + those hosts (scheme optional, file:// works too)
 *   ALLOWED_ORIGINS=*              -> any origin (explicit opt-out; credentials stay off)
 *
 * Requests with no Origin header (curl, server-to-server, plain navigations, the WebSocket
 * handshake from a native client) are allowed, because CORS is a browser control and there is
 * no cross-site risk to protect against without a browser origin to compare.
 */

const ALLOW_ANY = '*';

/** Turn an ALLOWED_ORIGINS value into a predicate. */
const parseAllowedOrigins = (raw) => {
    const value = typeof raw === 'string' ? raw.trim() : '';
    if (!value) return { mode: 'same-origin', hosts: new Set(), raw: '' };
    if (value === ALLOW_ANY) return { mode: 'any', hosts: new Set(), raw: value };

    const hosts = new Set();
    for (const entry of value.split(',')) {
        const trimmed = entry.trim().toLowerCase();
        if (!trimmed) continue;
        const host = hostOf(trimmed.startsWith('http') ? trimmed : `https://${trimmed}`);
        if (host) hosts.add(host);
    }
    return { mode: hosts.size ? 'list' : 'same-origin', hosts, raw: value };
};

/** Extract the lowercase host (host:port) from an origin string, or null if it is not a URL. */
const hostOf = (value) => {
    if (!value || typeof value !== 'string') return null;
    try {
        return new URL(value).host.toLowerCase() || null;
    } catch {
        return null;
    }
};

const normalizeHost = (value) => {
    if (!value || typeof value !== 'string') return null;
    const host = value.trim().toLowerCase().replace(/\/+$/, '');
    return host || null;
};

const createOriginPolicy = (raw) => {
    const { mode, hosts } = parseAllowedOrigins(raw);

    /**
     * @param {string|undefined} origin       the request's Origin header (absent for non-browser clients)
     * @param {string|undefined} requestHost  the request's Host header, used for the same-origin check
     */
    const isAllowed = (origin, requestHost) => {
        // Not a browser request — CORS does not apply, and blocking it would break
        // server-to-server calls, health checks and the native-app handshake.
        if (!origin) return true;
        if (origin === 'null') return false; // sandboxed iframe / file://: never trust it

        // A malformed header is refused first, so even ALLOWED_ORIGINS=* never echoes back
        // something that is not a URL.
        const originHost = hostOf(origin);
        if (!originHost) return false;
        if (mode === 'any') return true;
        if (hosts.has(originHost)) return true;

        const host = normalizeHost(requestHost);
        return Boolean(host && originHost === host);
    };

    return { mode, hosts: [...hosts], isAllowed };
};

/** Expression that tells the `cors` package whether to echo the origin back. */
const corsOriginCheck = (policy) => (origin, callback) => callback(null, policy.isAllowed(origin, null));

module.exports = { parseAllowedOrigins, createOriginPolicy, corsOriginCheck, hostOf };
