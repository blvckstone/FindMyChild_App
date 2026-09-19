// Session store.
//
// Login tokens used to live in a module-level Map: a restart logged everyone out, and a second
// instance would not recognise any token minted by the first (and could not revoke one either,
// which matters most — blocking an abusive account has to take effect everywhere).
//
// Sessions now live in MongoDB, which gives all instances one source of truth, a real expiry
// (they previously never expired at all), and automatic cleanup through a TTL index.
//
// Cost: one indexed lookup per authenticated request. The public, unauthenticated endpoints
// are unaffected, and authed traffic is a small fraction of the load.

const DEFAULT_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const configuredTtl = Number(process.env.SESSION_TTL_MS);
const SESSION_TTL_MS = Number.isFinite(configuredTtl) && configuredTtl > 0 ? configuredTtl : DEFAULT_SESSION_TTL_MS;

const TOKEN_KINDS = ['user', 'admin'];

const sessionExpiry = (now = Date.now()) => new Date(now + SESSION_TTL_MS);

/** Record a freshly issued token. Upsert keeps a re-issued token from colliding. */
const createSession = async (Session, { token, userId, kind = 'user', now = Date.now() }) => {
    if (!Session) throw new Error('Session store is unavailable.');
    if (!token) throw new Error('A session token is required.');
    if (!TOKEN_KINDS.includes(kind)) throw new Error(`Unknown session kind: ${kind}`);
    const expiresAt = sessionExpiry(now);
    await Session.updateOne(
        { token },
        { $set: { token, userId, kind, expiresAt, lastSeenAt: new Date(now) } },
        { upsert: true }
    );
    return { token, userId, kind, expiresAt };
};

/**
 * Resolve a token to its owner, or null when it is unknown or expired.
 * `now` is injectable so tests do not have to wait for a real clock.
 */
const lookupSession = async (Session, token, now = Date.now()) => {
    if (!Session || !token) return null;
    const session = await Session.findOne({ token }).lean();
    if (!session) return null;
    if (session.expiresAt && new Date(session.expiresAt).getTime() <= now) return null;
    return session;
};

/** Forget one token (logout). */
const deleteSession = async (Session, token) => {
    if (!Session || !token) return 0;
    const result = await Session.deleteOne({ token });
    return result && typeof result.deletedCount === 'number' ? result.deletedCount : 0;
};

/** Forget every token belonging to a user or admin (block/delete/role change). */
const deleteUserSessions = async (Session, userId) => {
    if (!Session || !userId) return 0;
    const result = await Session.deleteMany({ userId: String(userId) });
    return result && typeof result.deletedCount === 'number' ? result.deletedCount : 0;
};

/** Housekeeping for environments where the TTL monitor has not run yet. */
const pruneExpiredSessions = async (Session, now = Date.now()) => {
    if (!Session) return 0;
    const result = await Session.deleteMany({ expiresAt: { $lte: new Date(now) } });
    return result && typeof result.deletedCount === 'number' ? result.deletedCount : 0;
};

module.exports = {
    SESSION_TTL_MS,
    sessionExpiry,
    createSession,
    lookupSession,
    deleteSession,
    deleteUserSessions,
    pruneExpiredSessions
};
