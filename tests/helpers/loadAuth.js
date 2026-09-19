// Test helper: load functions/auth.js with functions/dbModels swapped for an in-memory fake,
// so auth logic can be exercised without a MongoDB instance.
//
// Sessions live in shared storage now, so the fake models include an in-memory Session store —
// otherwise every login would fail with "Session store is unavailable."
const { makeSessionModel } = require('./fakeSession');

const AUTH_PATH = require.resolve('../../functions/auth');
const DB_MODELS_PATH = require.resolve('../../functions/dbModels');

/**
 * @param {object} models Fake mongoose models, e.g. { User: { findOne, create } }
 *                      A fake Session model is supplied automatically.
 * @returns {{ auth: object, models: object, restore: () => void }}
 */
const loadAuth = (models = {}) => {
    const previousDbModels = require.cache[DB_MODELS_PATH];
    const resolved = { Session: makeSessionModel(), ...models };
    delete require.cache[AUTH_PATH];
    require.cache[DB_MODELS_PATH] = {
        id: DB_MODELS_PATH,
        filename: DB_MODELS_PATH,
        loaded: true,
        exports: async () => resolved
    };
    const auth = require('../../functions/auth');
    const restore = () => {
        if (previousDbModels) require.cache[DB_MODELS_PATH] = previousDbModels;
        else delete require.cache[DB_MODELS_PATH];
        delete require.cache[AUTH_PATH];
    };
    return { auth, models: resolved, restore };
};

// Run requireAuth with a bearer token and report the HTTP status it produced.
// requireAuth is async (it resolves the session from shared storage), so this awaits it.
const bearerStatus = async (auth, token) => {
    let status = 200;
    const req = { headers: token ? { authorization: 'Bearer ' + token } : {} };
    const res = { status(code) { status = code; return { json() {} }; } };
    await auth.requireAuth(req, res, () => {});
    return status;
};

module.exports = { loadAuth, bearerStatus };
