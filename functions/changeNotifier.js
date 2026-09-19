// Coalescing, scope-aware change notifications.
//
// Every write used to broadcast a bare `dataChanged` to every connected client, and each
// client answered with a full reload of everything it shows. One admin action is cheap, but
// a bulk action (approve-all loops, a seed script, several moderators at once) turns into
// N writes × M clients × a full dataset query: the classic thundering herd, and it is exactly
// what a single 0.1 vCPU instance cannot absorb.
//
// Instead, writes mark their scope dirty and one notification goes out per window, carrying
// the scopes that actually changed. Clients can then refresh just what they display.

const SCOPE_ALL = 'all';
const SCOPE_OTHER = 'other';

// Which slice of the data a route can touch. Derived from the request path so no call site
// has to remember to pass it.
const SCOPES = {
    children: 'children',
    safechild: 'safechildren',
    'safe-children': 'safechildren',
    users: 'users',
    auth: 'users',
    praise: 'praise',
    gifts: 'gifts',
    'found-requests': 'found-requests',
    donations: 'donations',
    ads: 'ads',
    analytics: 'analytics',
    pages: 'pages',
    legal: 'legal',
    revenue: 'revenue',
    admins: 'admins',
    'ngo-contacts': 'ngo-contacts',
    'payment-settings': 'payment-settings',
    messages: 'messages',
    stats: 'children',
    logout: 'users'
};

/**
 * Map a request path to the data scope it writes to.
 * `/api/admin/children/123` -> 'children', `/api/praise` -> 'praise', anything unmapped -> 'other'.
 */
const scopeForPath = (pathname) => {
    const path = String(pathname || '').split('?')[0].replace(/^\/+/, '');
    const parts = path.split('/').filter(Boolean);
    // Skip the 'api' prefix and the 'admin' segment: /api/admin/children/1 -> ['children', '1']
    if (parts[0] === 'api') parts.shift();
    if (parts[0] === 'admin') parts.shift();
    const first = parts[0] || '';
    return SCOPES[first] || SCOPE_OTHER;
};

/**
 * Create a notifier that batches writes.
 *
 * @param {object}   options
 * @param {Function} options.emit      called once per window with { scopes, at }
 * @param {number}   [options.windowMs] coalescing window (default 750 ms)
 * @param {Function} [options.schedule] injectable scheduler (defaults to setTimeout)
 * @param {Function} [options.cancel]   injectable canceller
 * @param {Function} [options.now]      injectable clock
 * @param {Function} [options.onError]  called when emit throws
 */
const createChangeNotifier = ({
    emit,
    windowMs = 750,
    schedule = (fn, ms) => setTimeout(fn, ms),
    cancel = (timer) => clearTimeout(timer),
    now = () => Date.now(),
    onError = (error) => console.error('[changeNotifier] emit failed:', error.message)
} = {}) => {
    if (typeof emit !== 'function') throw new Error('createChangeNotifier needs an emit function');

    let dirty = new Set();
    let timer = null;
    let notifications = 0;
    let flushes = 0;

    const flush = () => {
        timer = null;
        if (!dirty.size) return null;
        const scopes = [...dirty].sort();
        dirty = new Set();
        flushes++;
        const payload = { scopes, at: now() };
        try {
            emit(payload);
        } catch (error) {
            // A broken listener must never break the write that triggered it.
            onError(error);
        }
        return payload;
    };

    /**
     * Mark a scope (or everything) as changed. Returns the number of distinct scopes currently
     * waiting for the next flush.
     */
    const notify = (scope = SCOPE_ALL) => {
        notifications++;
        const name = String(scope || SCOPE_ALL);
        if (name === SCOPE_ALL) {
            // 'all' supersedes anything narrower that is already queued.
            dirty = new Set([SCOPE_ALL]);
        } else if (!dirty.has(SCOPE_ALL)) {
            dirty.add(name);
        }
        if (!timer) {
            timer = schedule(flush, windowMs);
            // Never hold the process open just to send a notification.
            if (timer && typeof timer.unref === 'function') timer.unref();
        }
        return dirty.size;
    };

    const stats = () => ({ notifications, flushes, pending: dirty.size, windowMs });

    /** Drop queued work without emitting (used on shutdown). */
    const stop = () => {
        if (timer) cancel(timer);
        timer = null;
        dirty = new Set();
    };

    return { notify, flush, stats, stop };
};

module.exports = { createChangeNotifier, scopeForPath, SCOPE_ALL, SCOPE_OTHER, SCOPES };
