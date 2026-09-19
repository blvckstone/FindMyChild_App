/**
 * B1 — the AI scan used to load the whole population into memory and scan it linearly on
 * every request. These tests pin down the replacement: a bounded cached pool that streams
 * whatever did not fit, so the closest child is still found no matter how big the table is.
 *
 * The fake model below implements exactly the query surface faceMatch.js uses
 * (.find().sort().limit().select().lean() and .find().sort().select().lean().cursor()),
 * with string ids that sort the way real ObjectIds do.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

let moduleCounter = 0;
/** faceMatch keeps its pool in module state, so each scenario gets a fresh copy of the module. */
const freshFaceMatch = (env = {}) => {
    const saved = {};
    for (const [key, value] of Object.entries(env)) {
        saved[key] = process.env[key];
        process.env[key] = String(value);
    }
    const modulePath = require.resolve('../functions/faceMatch.js');
    delete require.cache[modulePath];
    const loaded = require(modulePath);
    moduleCounter += 1;
    if (moduleCounter > 0) {
        for (const [key, value] of Object.entries(saved)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
        }
    }
    return loaded;
};

const id = (n) => String(n).padStart(24, '0');

/**
 * A descriptor whose values move with `seed`: equal seeds are a perfect match, and seeds a few
 * steps apart are far enough to fall outside the 0.65 match threshold.
 */
const FACE_SPREAD = 0.02;
const describeFace = (seed = 0) =>
    Array.from({ length: 128 }, (_, index) => 0.001 * (index % 10) + seed * FACE_SPREAD);

const matchesFilter = (doc, filter, schema) => {
    for (const [key, condition] of Object.entries(filter)) {
        if (condition && typeof condition === 'object' && !Array.isArray(condition)) {
            for (const [op, value] of Object.entries(condition)) {
                if (op === '$exists' && Boolean(doc[key]) !== value) return false;
                if (op === '$ne' && JSON.stringify(doc[key]) === JSON.stringify(value)) return false;
                if (op === '$lt' && !(doc[key] < value)) return false;
                if (op === '$gt' && !(doc[key] > value)) return false;
            }
        } else if (doc[key] !== condition) {
            return false;
        }
    }
    const face = doc.faceDescriptor;
    if (schema === 'Child') {
        if (!Array.isArray(face) || face.length === 0) return false;
    }
    return true;
};

const makeModel = (name, docs) => {
    const state = { queries: 0, poolQueries: 0, edgeQueries: 0, streamedDocs: 0 };
    const run = (filter, { sort, limit, cursor } = {}) => {
        state.queries += 1;
        if (limit) state.poolQueries += 1;
        else state.edgeQueries += 1;
        let rows = docs.filter((doc) => matchesFilter(doc, filter));
        if (sort && sort._id === -1) rows = rows.slice().sort((a, b) => (a._id < b._id ? 1 : a._id > b._id ? -1 : 0));
        if (limit) rows = rows.slice(0, limit);
        if (!cursor) return Promise.resolve(rows);
        return (async function* iterate() {
            for (const row of rows) {
                state.streamedDocs += 1;
                yield row;
            }
        })();
    };
    const query = (filter = {}) => {
        const options = {};
        const api = {
            sort(spec) { options.sort = spec; return api; },
            limit(n) { options.limit = n; return api; },
            select() { return api; },
            lean() { return api; },
            cursor(config) { options.cursor = config || {}; return run(filter, options); },
            then(resolve, reject) { return run(filter, options).then(resolve, reject); }
        };
        return api;
    };
    return { name, state, find: (filter) => query(filter) };
};

const buildModels = (preRegDocs, childDocs = []) => ({
    PreRegisteredChild: makeModel('PreRegisteredChild', preRegDocs),
    Child: makeModel('Child', childDocs)
});

const preReg = (n, seed, name) => ({
    _id: id(n),
    childName: name || `Child ${n}`,
    age: 6,
    gender: 'Male',
    status: 'approved',
    photoUrl: `https://cdn/${n}.jpg`,
    faceDescriptor: describeFace(seed)
});

test('B1: matching scans the pool and streams nothing when the population fits', async () => {
    const { findBestMatch, poolStats } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const models = buildModels(
        [preReg(1, 0), preReg(2, 5), preReg(3, 9)],
        [{ _id: id(50), fullName: 'Reported', status: 'approved', faceDescriptor: describeFace(1) }]
    );

    const result = await findBestMatch(describeFace(5), models);
    assert.equal(result.entry.childName, 'Child 2');
    assert.equal(result.streamed, 0, 'nothing should be streamed when everything fits in the pool');
    assert.equal(result.truncated, false, 'nothing is beyond the cap');
    assert.equal(result.streamAll, false, 'both collections have a cached window');
    assert.equal(result.scanned, 4);

    const stats = poolStats();
    assert.equal(stats.size, 4);
    assert.equal(stats.maxPool, 10);
    assert.equal(stats.skipped, 0);
});

test('B1: the pool is cached — later scans never re-read the table', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const models = buildModels([preReg(1, 0), preReg(2, 5)]);
    const state = models.PreRegisteredChild.state;

    await findBestMatch(describeFace(0), models);
    assert.equal(state.poolQueries, 1, 'the first scan must read the table once');

    await findBestMatch(describeFace(5), models);
    await findBestMatch(describeFace(0), models);

    assert.equal(state.poolQueries, 1, 'later scans must reuse the cached pool');
    assert.equal(state.edgeQueries, 3, 'only the cheap window query may repeat (one per scan)');
});

test('B1: a descriptor edited in place is picked up once the pool is rebuilt', async () => {
    const { findBestMatch, invalidateFacePool } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const docs = [preReg(1, 0)];
    const models = buildModels(docs);

    assert.equal((await findBestMatch(describeFace(0), models)).matched, true);

    // Same record, new face data. The cached window still holds the old descriptor, and the
    // record is inside the window (not on either edge), so only a rebuild can see the change.
    docs[0].faceDescriptor = describeFace(9);
    const stale = await findBestMatch(describeFace(0), models);
    assert.equal(stale.matched, true, 'the cached descriptor is still the one in the window');

    invalidateFacePool();
    assert.equal((await findBestMatch(describeFace(0), models)).matched, false, 'the edited descriptor must win');
    assert.equal((await findBestMatch(describeFace(9), models)).matched, true);
});

test('B1: a child registered after an empty pool was built is still found', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const docs = [];
    const models = buildModels(docs);

    assert.equal((await findBestMatch(describeFace(2), models)).matched, false);

    // The registry was empty at build time, so there is no cached window to extend: the
    // collection itself must be streamed until the next rebuild.
    docs.push(preReg(1, 2));
    const result = await findBestMatch(describeFace(2), models);
    assert.equal(result.matched, true, 'an empty pool must not mean an endless blind spot');
    assert.equal(result.entry.childName, 'Child 1');
    assert.equal(result.streamAll, true, 'a collection with no cached window is streamed whole');
    assert.equal(result.truncated, false, 'no record was pushed beyond the cap');
});

test('B1: a child registered after the pool was built is matchable immediately', async () => {
    const { findBestMatch, poolStats } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const docs = [preReg(1, 0)];
    const models = buildModels(docs);

    assert.equal((await findBestMatch(describeFace(9), models)).matched, false);

    // Inserted straight into the database with no API write and no invalidation.
    docs.push(preReg(2, 9));
    const result = await findBestMatch(describeFace(9), models);

    assert.equal(result.matched, true, 'a brand-new record must never be invisible');
    assert.equal(result.entry.childName, 'Child 2');
    assert.equal(poolStats().size, 1, 'the new record was streamed, not cached');
});

test('B1: concurrent scans share one pool build (no duplicate full-table reads)', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const models = buildModels([preReg(1, 0), preReg(2, 5)]);

    const results = await Promise.all([
        findBestMatch(describeFace(0), models),
        findBestMatch(describeFace(5), models),
        findBestMatch(describeFace(0), models)
    ]);
    assert.deepEqual(results.map((r) => r.entry.childName), ['Child 1', 'Child 2', 'Child 1']);
    assert.equal(models.PreRegisteredChild.state.poolQueries, 1, 'only one full-table read may happen');
});

test('B1: a match older than the pool cap is still found, by streaming the overflow', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 2 });
    // Newest first by _id: 5 and 4 fit in the pool, 3/2/1 must be streamed.
    const models = buildModels([preReg(1, 42), preReg(2, 7), preReg(3, 8), preReg(4, 9), preReg(5, 10)]);

    const result = await findBestMatch(describeFace(42), models);

    assert.equal(result.truncated, true, 'the pool must report that it is truncated');
    assert.equal(result.entry.childName, 'Child 1', 'the only true match lives outside the cached pool');
    assert.equal(result.streamed, 3);
    assert.equal(result.scanned, 5, 'every registered child must be compared');
    assert.equal(models.PreRegisteredChild.state.streamedDocs, 3, 'only the overflow may be streamed');
    assert.ok(result.distance < 0.001, `expected a near-exact match, got distance ${result.distance}`);
});

test('B1: the missing-children pool is searched too, and identifies its source', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const childDocs = [{
        _id: id(90),
        fullName: 'Reported Child',
        status: 'approved',
        contactNumber: '9999999999',
        faceDescriptor: describeFace(3)
    }];
    const models = buildModels([preReg(1, 0)], childDocs);

    const result = await findBestMatch(describeFace(3), models);
    assert.equal(result.entry.childName, 'Reported Child');
    assert.equal(result.entry.source, 'missing_report');
    assert.equal(result.entry.parentContact, '9999999999');
});

test('B1: records without a usable descriptor are skipped, not fatal', async () => {
    const { findBestMatch, poolStats } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const models = buildModels([
        { ...preReg(1, 0), faceDescriptor: [] },
        { ...preReg(2, 0), faceDescriptor: [1, 2, 3] },
        { ...preReg(3, 0), faceDescriptor: 'not-a-descriptor' },
        preReg(4, 4)
    ]);

    const result = await findBestMatch(describeFace(4), models);
    assert.equal(result.entry.childName, 'Child 4');
    assert.equal(result.scanned, 1, 'only the valid descriptor should be part of the pool');
    assert.equal(poolStats().skipped, 3);
});

test('B1: an unparsable query descriptor is rejected instead of silently matching', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const models = buildModels([preReg(1, 0)]);
    await assert.rejects(() => findBestMatch([1, 2, 3], models), /valid face descriptor/);
    await assert.rejects(() => findBestMatch('nope', models), /valid face descriptor/);
});

test('B1: an empty registry reports no comparison, not a false match', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const result = await findBestMatch(describeFace(1), buildModels([]));
    assert.equal(result.entry, null);
    assert.equal(result.scanned, 0);
});

test('B1: a face nobody is close to is reported as unmatched, however small the registry', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const models = buildModels([preReg(1, 0)]);

    const result = await findBestMatch(describeFace(9), models);
    assert.equal(result.matched, false, 'the matcher must apply the threshold itself');
    assert.ok(result.distance > 0.65, `expected a far distance, got ${result.distance}`);

    const same = await findBestMatch(describeFace(0), models);
    assert.equal(same.matched, true);
});

test('B1: invalidating the pool picks up newly added children', async () => {
    const { findBestMatch, invalidateFacePool, poolStats } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10 });
    const docs = [preReg(1, 0)];
    const models = buildModels(docs);

    assert.equal((await findBestMatch(describeFace(9), models)).matched, false);

    docs[0].faceDescriptor = describeFace(9);
    assert.equal((await findBestMatch(describeFace(9), models)).matched, false, 'the cached pool must still be used');

    invalidateFacePool();
    const after = await findBestMatch(describeFace(9), models);
    assert.equal(after.matched, true);
    assert.equal(after.entry.childName, 'Child 1');
    assert.equal(poolStats().size, 1);
});

test('B1: the pool expires on its own so out-of-band edits are eventually seen', async () => {
    const { findBestMatch } = freshFaceMatch({ FACEMATCH_MAX_POOL: 10, FACEMATCH_POOL_TTL_MS: 1 });
    const docs = [preReg(1, 0)];
    const models = buildModels(docs);

    assert.equal((await findBestMatch(describeFace(0), models)).matched, true);
    docs[0].faceDescriptor = describeFace(9);
    await new Promise((resolve) => setTimeout(resolve, 5));

    const result = await findBestMatch(describeFace(9), models);
    assert.equal(result.matched, true, 'a stale pool must be rebuilt after its TTL');
    assert.equal(result.entry.childName, 'Child 1');
});

test('B1: the pool is bounded — only the cap is ever held in memory', async () => {
    const { findBestMatch, poolStats } = freshFaceMatch({ FACEMATCH_MAX_POOL: 3 });
    const docs = Array.from({ length: 25 }, (_, index) => preReg(index + 1, index));
    const models = buildModels(docs);

    const result = await findBestMatch(describeFace(24), models);
    assert.equal(poolStats().size, 3, 'memory must stay capped no matter how many records exist');
    assert.equal(result.entry.childName, 'Child 25', 'the newest record is the pool');
    assert.equal(result.scanned, 25);
});

test('B1: the route delegates to the shared matcher instead of its own scan', () => {
    const faceMatch = freshFaceMatch({});
    assert.equal(typeof faceMatch.MATCH_THRESHOLD, 'number');
    assert.ok(faceMatch.MATCH_THRESHOLD > 0 && faceMatch.MATCH_THRESHOLD < 1);
    assert.equal(typeof faceMatch.invalidateFacePool, 'function');
    assert.equal(typeof faceMatch.poolStats, 'function');

    const fs = require('node:fs');
    const serverSource = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    assert.match(
        serverSource,
        /findBestMatch\(parsedDescriptor, \{ Child, PreRegisteredChild \}\)/,
        'the route must delegate to the shared matcher'
    );
    assert.match(serverSource, /if \(result\.matched\)/, 'the route must use the matcher verdict');
    assert.match(serverSource, /invalidateFacePool\(\)/, 'data changes must invalidate the pool');
    assert.doesNotMatch(serverSource, /const THRESHOLD = 0\.65/, 'the old hard-coded threshold must be gone');
    assert.doesNotMatch(
        serverSource,
        /PreRegisteredChild\.find\(\{ status: 'approved' \}\)\.lean\(\)/,
        'the naive full-table read must be gone from the route'
    );
});
