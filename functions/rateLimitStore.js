// Shared rate-limit counters for express-rate-limit.
//
// The library's default store keeps counters in this process. That means the configured
// ceiling is multiplied by the number of running instances (10 attempts becomes 10 per
// replica), and every deploy or restart hands an attacker a clean slate on a route that
// is brute-force sensitive, like the admin login.
//
// This store keeps the counter in MongoDB, so the limit is global and survives restarts.
// It never fails a request and never silently disables limiting: if the database is
// unreachable, counting continues per process via express-rate-limit's MemoryStore, and
// the shared counter is retried after a short backoff.

const { MemoryStore } = require('express-rate-limit');

const DEGRADE_RETRY_MS = 30 * 1000;

/**
 * @param {object} config
 * @param {string} config.prefix      namespaces the keys of one limiter from another.
 * @param {number} config.windowMs    the limiter's window, used for the counter's reset time.
 * @param {Function} [config.getModel] async () => mongoose model for the counters.
 * @param {object} [config.model]     a model to use directly (tests, or a pre-resolved model).
 */
const createRateLimitStore = (config = {}) => new MongoRateLimitStore(config);

class MongoRateLimitStore {
    constructor(config = {}) {
        if (!config.prefix) throw new Error('createRateLimitStore requires a prefix');
        if (!Number.isFinite(config.windowMs) || config.windowMs <= 0) throw new Error('createRateLimitStore requires windowMs');
        if (!config.getModel && !config.model) throw new Error('createRateLimitStore requires a model or getModel');

        this.prefix = config.prefix;
        this.windowMs = config.windowMs;
        this.getModelFn = config.getModel || null;
        this.model = config.model || null;
        // Shared across instances: the same request on another replica must count against
        // the same key, so keys are not instance-local.
        this.localKeys = false;
        this.fallback = new MemoryStore();
        this.degraded = false;
        this.retryAt = 0;
        this.loggedDegrade = false;
    }

    scope(key) {
        return `${this.prefix}:${key}`;
    }

    async resolveModel() {
        if (!this.model) this.model = await this.getModelFn();
        return this.model;
    }

    // Stop touching the database for a while after a failure, but keep retrying so a
    // brief outage does not leave the limit permanently per-process.
    degrade(error) {
        this.degraded = true;
        this.retryAt = Date.now() + DEGRADE_RETRY_MS;
        if (!this.loggedDegrade) {
            this.loggedDegrade = true;
            console.error(`[ratelimit] ${this.prefix}: shared counter store unavailable (${error.message}). Counting per process until it returns.`);
        }
    }

    recover() {
        if (this.degraded) {
            this.degraded = false;
            this.loggedDegrade = false;
        }
    }

    async increment(key) {
        if (this.degraded && Date.now() < this.retryAt) return this.fallback.increment(key);
        try {
            const model = await this.resolveModel();
            const now = new Date();
            const freshReset = new Date(now.getTime() + this.windowMs);
            // One atomic upsert: a live window is incremented in place, an expired or
            // missing one starts again at 1. The aggregation pipeline makes that decision
            // inside the database, so two replicas cannot both "start" the same window.
            for (let attempt = 0; attempt < 2; attempt++) {
                try {
                    const doc = await model.findOneAndUpdate(
                        { key: this.scope(key) },
                        [{
                            $set: {
                                count: { $cond: [{ $gt: ['$resetAt', now] }, { $add: [{ $ifNull: ['$count', 0] }, 1] }, 1] },
                                resetAt: { $cond: [{ $gt: ['$resetAt', now] }, '$resetAt', freshReset] }
                            }
                        }],
                        { upsert: true, new: true, projection: { count: 1, resetAt: 1 } }
                    ).lean();
                    this.recover();
                    return { totalHits: doc.count, resetTime: doc.resetAt };
                } catch (error) {
                    // Two simultaneous first hits can both insert; the unique index rejects
                    // one of them, so it is retried as a normal increment.
                    if (error && error.code === 11000 && attempt === 0) continue;
                    throw error;
                }
            }
            throw new Error('rate limit counter upsert did not settle');
        } catch (error) {
            this.degrade(error);
            return this.fallback.increment(key);
        }
    }

    async decrement(key) {
        if (this.degraded && Date.now() < this.retryAt) return this.fallback.decrement(key);
        try {
            const model = await this.resolveModel();
            await model.updateOne({ key: this.scope(key) }, { $inc: { count: -1 } });
            this.recover();
        } catch (error) {
            this.degrade(error);
            return this.fallback.decrement(key);
        }
    }

    async resetKey(key) {
        if (this.degraded && Date.now() < this.retryAt) return this.fallback.resetKey(key);
        try {
            const model = await this.resolveModel();
            await model.deleteOne({ key: this.scope(key) });
            this.recover();
        } catch (error) {
            this.degrade(error);
            return this.fallback.resetKey(key);
        }
    }
}

module.exports = createRateLimitStore;
module.exports.MongoRateLimitStore = MongoRateLimitStore;
