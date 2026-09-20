// In-memory stand-in for the mongoose Session model, so session-dependent code can be tested
// without a database. Mirrors the surface functions/sessions.js uses.

const makeSessionModel = (rows = []) => {
    const state = { rows };

    return {
        state,
        async updateOne(filter, update) {
            const existing = state.rows.find((row) => row.token === filter.token);
            if (existing) Object.assign(existing, update.$set);
            else state.rows.push({ ...update.$set });
            return { acknowledged: true };
        },
        findOne(filter) {
            const row = state.rows.find((item) => item.token === filter.token);
            return { lean: async () => (row ? { ...row } : null) };
        },
        async deleteOne(filter) {
            const before = state.rows.length;
            state.rows = state.rows.filter((row) => row.token !== filter.token);
            return { deletedCount: before - state.rows.length };
        },
        async deleteMany(filter) {
            const before = state.rows.length;
            if (filter.userId !== undefined) {
                // `kind` narrows the delete the same way it does in MongoDB, so an admin
                // revocation must never take a user's sessions with it.
                state.rows = state.rows.filter((row) => row.userId !== filter.userId || (filter.kind !== undefined && row.kind !== filter.kind));
            } else if (filter.expiresAt && filter.expiresAt.$lte) {
                const cutoff = filter.expiresAt.$lte.getTime();
                state.rows = state.rows.filter((row) => new Date(row.expiresAt).getTime() > cutoff);
            } else {
                state.rows = [];
            }
            return { deletedCount: before - state.rows.length };
        }
    };
};

module.exports = { makeSessionModel };
