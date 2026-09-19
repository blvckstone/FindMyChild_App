// Realtime query guard.
//
// The sockets are anonymous by design: the home page uses them to list public records, and the
// public REST endpoints carry a 300/min ceiling that sockets bypassed entirely. Any connected
// client could emit `load` in a tight loop and each emit ran a database query (a list plus a
// count), so one client could drive unlimited database work, and every payload was logged
// verbatim, which turned the log itself into a filling target.
//
// Two things now stand between a client and the database:
//   1. Every payload is validated into an allow-listed shape before a query sees it. Unknown
//      keys are dropped, free text is length-capped, dates must be real ISO dates, and enums
//      must be one of the known values.
//   2. Every connection gets a query budget and a cap on queries in flight, so a loop is
//      throttled instead of amplified.
//
// Rejections are answered with the event the client is already listening for (an empty result
// plus a message) so an older client degrades quietly instead of hanging on "Searching...".

const { normalizeYmd } = require('./dates');

const PAGE_MAX_LIMIT = 50;
const TEXT_MAX = 60;
const MAX_AGE = 120;
const SEARCH_FILTERS = ['all', 'missing', 'found', 'recent', 'week'];
const SORT_ORDERS = ['recent', 'oldest', 'name', 'age'];

const positiveInt = (value, fallback, { max = Number.MAX_SAFE_INTEGER } = {}) => {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > max) return fallback;
    return parsed;
};

const limitFromEnv = (name, fallback) => positiveInt(process.env[name], fallback);

const LIMITS = {
    windowMs: limitFromEnv('SOCKET_QUERY_WINDOW_MS', 60000),
    maxQueries: limitFromEnv('SOCKET_QUERY_LIMIT', 60),
    maxInFlight: limitFromEnv('SOCKET_MAX_IN_FLIGHT', 4)
};

const MESSAGES = {
    'rate-limited': 'Too many searches too quickly. Please wait a moment and try again.',
    busy: 'Your previous search is still running. Please wait a moment.',
    malformed: 'That search could not be understood.',
    'invalid-date': 'Please provide a valid date.',
    'invalid-range': 'Please provide a valid date range.',
    'invalid-query': 'Please enter a longer search term.'
};

/** A trimmed, length-capped string; null when the value is not text at all. */
const asText = (value, max = TEXT_MAX) => {
    const type = typeof value;
    if (type !== 'string' && type !== 'number') return null;
    return String(value).trim().slice(0, max);
};

/** A non-empty string, or null when missing, blank or not text. */
const asRequiredText = (value, max = TEXT_MAX) => {
    const text = asText(value, max);
    return text ? text : null;
};

const asAge = (value) => {
    if (value === undefined || value === null || value === '') return undefined;
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > MAX_AGE) return null;
    return parsed;
};

const asFoundFilter = (value) => {
    if (value === undefined || value === null || value === '' || value === 'all') return undefined;
    if (value === true || value === 'true') return true;
    if (value === false || value === 'false') return false;
    return null;
};

const asEnum = (value, allowed) => {
    if (value === undefined || value === null || value === '') return undefined;
    const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
    return allowed.includes(text) ? text : null;
};

/** Scalar payloads (`socket.emit('searchByName', 'aamna')`) stay supported. */
const fieldOf = (payload, ...names) => {
    if (typeof payload === 'string' || typeof payload === 'number') return payload;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return undefined;
    for (const name of names) {
        if (payload[name] !== undefined) return payload[name];
    }
    return undefined;
};

const pagination = (payload = {}) => ({
    page: positiveInt(payload.page, 1, { max: 10000 }),
    limit: positiveInt(payload.limit, PAGE_MAX_LIMIT, { max: PAGE_MAX_LIMIT })
});

const invalid = (reason) => ({ ok: false, reason });

/**
 * Is this a real calendar day? `normalizeYmd` keeps anything shaped `YYYY-MM-DD` (a write-path
 * rule, so an existing value is never mangled), so a date-shaped nonsense such as 2026-13-45
 * has to be caught here — otherwise it becomes a guaranteed-empty query and a wasted scan.
 */
const isRealDate = (value) => {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ''));
    if (!match) return false;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const probe = new Date(Date.UTC(year, month - 1, day));
    return probe.getUTCFullYear() === year && probe.getUTCMonth() === month - 1 && probe.getUTCDate() === day;
};

/**
 * Turn an untrusted socket payload into the exact arguments a query may receive.
 * Returns `{ ok: true, args }` or `{ ok: false, reason }` — never partial input.
 */
const validateQuery = (event, payload) => {
    switch (event) {
        case 'load': {
            const body = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
            return {
                ok: true,
                args: {
                    ...pagination(body),
                    found: asFoundFilter(body.found),
                    gender: asText(body.gender, 20) || undefined,
                    q: asText(body.q, TEXT_MAX) || undefined,
                    ageMin: asAge(body.ageMin) ?? undefined,
                    ageMax: asAge(body.ageMax) ?? undefined,
                    sortBy: asEnum(body.sortBy, SORT_ORDERS)
                }
            };
        }
        case 'loadMessages':
            return { ok: true, args: {} };
        case 'searchByDate':
        case 'searchByName':
        case 'searchByAddress': {
            const { page, limit } = pagination(payload && typeof payload === 'object' ? payload : {});
            const raw = fieldOf(payload, 'date', 'searchingDate', 'searchingName', 'searchingAddress', 'name', 'address', 'query');
            // A date may arrive as a full ISO timestamp, so it gets more room than a search box,
            // then it is normalized to the canonical YYYY-MM-DD the records are stored in.
            const text = asRequiredText(raw, event === 'searchByDate' ? 40 : TEXT_MAX);
            if (!text) return invalid('invalid-query');
            if (event === 'searchByDate') {
                const date = normalizeYmd(text);
                if (!isRealDate(date)) return invalid('invalid-date');
                return { ok: true, args: { value: date, page, limit } };
            }
            return { ok: true, args: { value: text, page, limit } };
        }
        case 'searchByRange': {
            const { page, limit } = pagination(payload && typeof payload === 'object' ? payload : {});
            const from = normalizeYmd(fieldOf(payload, 'from', 'searchingDateFrom', 'dateFrom'));
            const to = normalizeYmd(fieldOf(payload, 'to', 'searchingDateTo', 'dateTo'));
            if (!isRealDate(from) || !isRealDate(to)) return invalid('invalid-range');
            if (from > to) return invalid('invalid-range');
            return { ok: true, args: { from, to, page, limit } };
        }
        case 'searchChildren': {
            const body = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
            const query = asText(body.query, TEXT_MAX) || undefined;
            const gender = asText(body.gender, 20) || undefined;
            const ageMin = asAge(body.ageMin);
            const ageMax = asAge(body.ageMax);
            const filter = asEnum(body.filter, SEARCH_FILTERS);
            const sortBy = asEnum(body.sortBy, SORT_ORDERS);
            if (ageMin === null || ageMax === null || filter === null || sortBy === null) return invalid('malformed');
            if (gender !== undefined && !gender) return invalid('malformed');
            return { ok: true, args: { ...pagination(body), query, gender, ageMin, ageMax, filter, sortBy } };
        }
        default:
            return invalid('malformed');
    }
};

/**
 * Per-connection budget. `now` is injectable so the window can be tested without waiting.
 */
const createConnectionGuard = ({ windowMs = LIMITS.windowMs, maxQueries = LIMITS.maxQueries, maxInFlight = LIMITS.maxInFlight, now = Date.now } = {}) => {
    let windowStart = now();
    let used = 0;
    let inFlight = 0;
    let denied = 0;

    const rollWindow = () => {
        const current = now();
        if (current - windowStart >= windowMs) {
            windowStart = current;
            used = 0;
        }
    };

    return {
        /** May this connection start a query right now? */
        check() {
            rollWindow();
            if (inFlight >= maxInFlight) return { ok: false, reason: 'busy' };
            if (used >= maxQueries) {
                denied += 1;
                return { ok: false, reason: 'rate-limited', retryAfterMs: windowStart + windowMs - now() };
            }
            used += 1;
            return { ok: true };
        },
        begin() { inFlight += 1; },
        end() { inFlight = Math.max(0, inFlight - 1); },
        stats() { return { used, inFlight, denied, windowStart }; }
    };
};

/**
 * Attach every realtime query to a socket, validated and throttled.
 *
 * `queries` is injected so the whole surface can be exercised without a server; each entry is
 * `{ inEvent, outEvent, run(args), empty }` where `empty` is the payload an older client
 * receives instead of a result (it expects the event it listens for).
 */
const QUERY_ROUTES = {
    load: { out: 'getAllData', empty: () => ({ success: true, error: false, message: '', data: [], total: 0, page: 1, limit: 0, pages: 1 }) },
    loadMessages: { out: 'getMessages', empty: () => ({ success: true, error: false, message: '', data: [] }) },
    searchByDate: { out: 'getByDateData', empty: () => ({ success: true, error: false, message: '', data: [], total: 0 }) },
    searchByName: { out: 'getByNameData', empty: () => ({ success: true, error: false, message: '', data: [], total: 0 }) },
    searchByRange: { out: 'getByRangeData', empty: () => ({ success: true, error: false, message: '', data: [], total: 0 }) },
    searchByAddress: { out: 'getByAddressData', empty: () => ({ success: true, error: false, message: '', data: [], total: 0 }) },
    searchChildren: { out: 'getSearchData', empty: () => ({ success: true, error: false, message: '', data: [], total: 0 }) }
};

const attachQueryHandlers = (socket, queries = {}, { debug = process.env.DEBUG_SOCKET === '1' } = {}) => {
    const guard = createConnectionGuard();

    for (const event of Object.keys(QUERY_ROUTES)) {
        const { out, empty } = QUERY_ROUTES[event];
        const run = queries[event];
        if (typeof run !== 'function') {
            console.error(`[socket] no query implementation for ${event} — the event is disabled`);
            continue;
        }

        socket.on(event, async (payload) => {
            // A rejected request is answered twice on purpose: the event the client is listening
            // for gets an empty, failed result (an older client would otherwise sit on
            // "Searching..." forever), and `queryRejected` carries the reason.
            const refuse = (reason, extra = {}) => {
                const message = MESSAGES[reason] || MESSAGES.malformed;
                socket.emit(out, { ...empty(), success: false, error: true, message, ...extra });
                socket.emit('queryRejected', { event, reason, message, ...extra });
                if (debug) console.warn(`[socket] ${event} rejected (${reason})`);
            };

            const budget = guard.check();
            if (!budget.ok) {
                refuse(budget.reason, {
                    throttled: true,
                    ...(budget.retryAfterMs ? { retryAfterMs: budget.retryAfterMs } : {})
                });
                return;
            }

            const parsed = validateQuery(event, payload);
            if (!parsed.ok) {
                refuse(parsed.reason);
                return;
            }

            guard.begin();
            try {
                const result = await run(parsed.args);
                socket.emit(out, result);
            } catch (error) {
                // The message is logged, the payload never is: search text is user data.
                console.error(`[socket] ${event} failed:`, error && error.message);
                socket.emit(out, { ...empty(), success: false, error: true, message: 'Something went wrong. Please try again.' });
            } finally {
                guard.end();
            }
        });
    }

    return guard;
};

module.exports = {
    attachQueryHandlers,
    createConnectionGuard,
    validateQuery,
    QUERY_ROUTES,
    LIMITS,
    MESSAGES,
    PAGE_MAX_LIMIT,
    TEXT_MAX,
    SEARCH_FILTERS,
    SORT_ORDERS
};
