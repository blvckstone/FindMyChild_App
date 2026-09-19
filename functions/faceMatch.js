// Efficient face matching for the public AI scan (and anything else that needs it).
//
// The previous implementation loaded every approved pre-registered child and every missing
// child with a descriptor into memory and compared them linearly on every single scan. At a
// few hundred records that is fine; at real volume each scan would pull tens of megabytes off
// Atlas and hold it in a 256 MB container.
//
// This module keeps a bounded, cached pool of descriptors stored as Float32Array (~512 bytes
// each, so 20 000 children ≈ 10 MB) and, when the population is bigger than the pool, streams
// only the records that did not fit. Memory stays flat and *every* record is still compared,
// so a real match can never be missed just because it fell out of the cache.
//
// Scaling note: this is exact brute-force search - the correct first step. When the population
// grows past a few hundred thousand descriptors, move the search to a vector index (Atlas Vector
// Search or a dedicated service) and keep this module as the fallback path.

const { parseFaceDescriptor, faceDistance } = require('./face');

const DEFAULT_MAX_POOL = 20000;
const configuredMaxPool = Number(process.env.FACEMATCH_MAX_POOL);
const MAX_POOL = Number.isFinite(configuredMaxPool) && configuredMaxPool > 0
    ? Math.floor(configuredMaxPool)
    : DEFAULT_MAX_POOL;

// Rebuild the pool at most this often, even without an explicit invalidation. This is the
// safety net for *edits and deletes* made outside this process (another instance, a script, or
// the Mongo shell); every write made through the API invalidates the pool immediately, and
// brand-new records are always seen because the window below is scanned live at both ends.
const POOL_TTL_MS = Number(process.env.FACEMATCH_POOL_TTL_MS) > 0
    ? Number(process.env.FACEMATCH_POOL_TTL_MS)
    : 5 * 60 * 1000;

const STREAM_BATCH_SIZE = 500;
const MATCH_THRESHOLD = 0.65;

const PRE_REG_FIELDS = 'childName age gender address parentContact medicalInfo photoUrl faceDescriptor';
const CHILD_FIELDS = 'fullName age gender address contactNumber info image faceDescriptor';
const PRE_REG_QUERY = { status: 'approved' };
const CHILD_QUERY = { status: 'approved', faceDescriptor: { $exists: true, $ne: [] } };

let pool = null;
let building = null;

const toTypedDescriptor = (raw) => {
    const parsed = parseFaceDescriptor(raw);
    return parsed ? Float32Array.from(parsed) : null;
};

const entryFromPreRegistered = (doc, descriptor) => ({
    id: doc._id,
    childName: doc.childName || 'Unknown',
    age: doc.age,
    gender: doc.gender || '',
    address: doc.address || '',
    parentContact: doc.parentContact || '',
    medicalInfo: doc.medicalInfo || '',
    photoUrl: doc.photoUrl || '',
    source: 'safechild',
    detailType: 'safechild',
    descriptor
});

const entryFromChild = (doc, descriptor) => ({
    id: doc._id,
    childName: doc.fullName || 'Unknown',
    age: doc.age,
    gender: doc.gender || '',
    address: doc.address || '',
    parentContact: doc.contactNumber || '',
    medicalInfo: doc.info || '',
    photoUrl: doc.image || '',
    source: 'missing_report',
    detailType: 'child',
    descriptor
});

// Load the newest MAX_POOL descriptors for one collection.
//
// The pool is a *window*, not a copy of the table: the newest id seen (`newerThanId`) and the
// oldest id kept (`olderThanId`) mark its two open ends. Everything newer than the window is
// streamed on every scan, so a child registered a second ago is matchable immediately, and
// everything older than the window is streamed too, so nothing is ever invisible.
const loadSlice = async (Model, query, fields, pick) => {
    const docs = await Model.find(query)
        .sort({ _id: -1 })
        .limit(MAX_POOL + 1)
        .select(fields)
        .lean();

    const entries = [];
    let skipped = 0;
    let olderThanId = null;

    for (let i = 0; i < docs.length; i++) {
        if (i >= MAX_POOL) {
            olderThanId = docs[i - 1]._id;
            break;
        }
        const descriptor = toTypedDescriptor(docs[i].faceDescriptor);
        if (!descriptor) {
            skipped++;
            continue;
        }
        entries.push(pick(docs[i], descriptor));
    }

    return {
        entries,
        skipped,
        remainder: docs.length
            ? { Model, query, fields, pick, olderThanId, newerThanId: docs[0]._id }
            // Empty when the pool was built: there is no window at all, so every record added
            // afterwards has to be streamed. Without this, a child registered in the minute
            // between an empty build and the next invalidation would be invisible.
            : { Model, query, fields, pick, olderThanId: null, newerThanId: null, streamAll: true }
    };
};

const buildPool = async ({ Child, PreRegisteredChild }) => {
    const slices = [];
    if (PreRegisteredChild) slices.push(await loadSlice(PreRegisteredChild, PRE_REG_QUERY, PRE_REG_FIELDS, entryFromPreRegistered));
    if (Child) slices.push(await loadSlice(Child, CHILD_QUERY, CHILD_FIELDS, entryFromChild));

    const entries = slices.flatMap((slice) => slice.entries);
    const remainders = slices.map((slice) => slice.remainder).filter(Boolean);

    return {
        builtAt: Date.now(),
        entries,
        skipped: slices.reduce((total, slice) => total + slice.skipped, 0),
        remainders,
        // `truncated` means records exist beyond the cached window (the cap was hit).
        // `streamAll` means a collection had no cached window at all when the pool was built.
        truncated: slices.some((slice) => slice.remainder && slice.remainder.olderThanId),
        streamAll: slices.some((slice) => slice.remainder && slice.remainder.streamAll)
    };
};

/** Get the cached pool, rebuilding it when stale. Concurrent callers share one build. */
const getPool = async (models) => {
    if (!models || (!models.Child && !models.PreRegisteredChild)) {
        throw new Error('Face matching needs the database models.');
    }
    if (pool && Date.now() - pool.builtAt < POOL_TTL_MS) return pool;
    if (building) return building;

    building = buildPool(models)
        .then((built) => {
            pool = built;
            building = null;
            return pool;
        })
        .catch((error) => {
            building = null; // never cache a failed build
            throw error;
        });

    return building;
};

/** Drop the cached pool so the next scan sees fresh data. Called on every data change. */
const invalidateFacePool = () => {
    pool = null;
};

const poolStats = () => ({
    size: pool ? pool.entries.length : 0,
    truncated: pool ? pool.truncated : false,
    skipped: pool ? pool.skipped : 0,
    builtAt: pool ? pool.builtAt : null,
    ageMs: pool ? Date.now() - pool.builtAt : null,
    maxPool: MAX_POOL
});

// Walk one range of records, keeping only the running best match — memory stays flat.
const scanRange = async (Model, query, fields, pick, idFilter, parsed, best) => {
    const cursor = Model.find(idFilter ? { ...query, _id: idFilter } : query)
        .sort({ _id: -1 })
        .select(fields)
        .lean()
        .cursor({ batchSize: STREAM_BATCH_SIZE });

    let scanned = 0;
    for await (const doc of cursor) {
        scanned++;
        const descriptor = toTypedDescriptor(doc.faceDescriptor);
        if (!descriptor) continue;
        const distance = faceDistance(parsed, descriptor);
        if (distance < best.distance) {
            best.distance = distance;
            best.entry = pick(doc, descriptor);
        }
    }
    return scanned;
};

// Scan the records outside the cached window: newer than it (always empty in steady state,
// because API writes invalidate the pool) and older than it.
const scanRemainder = async ({ Model, query, fields, pick, olderThanId, newerThanId, streamAll }, parsed, best) => {
    if (streamAll) return scanRange(Model, query, fields, pick, null, parsed, best);
    let scanned = 0;
    if (newerThanId) scanned += await scanRange(Model, query, fields, pick, { $gt: newerThanId }, parsed, best);
    if (olderThanId) scanned += await scanRange(Model, query, fields, pick, { $lt: olderThanId }, parsed, best);
    return scanned;
};

/**
 * Find the closest registered child to `descriptorInput` (a 128-number array, typed array or
 * JSON string). Resolves `{ entry, distance, matched, scanned, streamed, truncated, streamAll }`
 * where `entry` is null when there is nothing to compare against.
 *
 * `scanned` always equals the number of comparable records in the database, so callers (and
 * tests) can assert that the cached window plus the streamed edges covers the whole table.
 */
const findBestMatch = async (descriptorInput, models) => {
    const parsed = descriptorInput instanceof Float32Array
        ? descriptorInput
        : toTypedDescriptor(descriptorInput);
    if (!parsed) throw new Error('A valid face descriptor (128 numbers) is required.');

    const current = await getPool(models);
    const best = { entry: null, distance: Infinity };

    for (const entry of current.entries) {
        const distance = faceDistance(parsed, entry.descriptor);
        if (distance < best.distance) {
            best.distance = distance;
            best.entry = entry;
        }
    }

    let streamed = 0;
    for (const remainder of current.remainders) {
        streamed += await scanRemainder(remainder, parsed, best);
    }

    const distance = Number.isFinite(best.distance) ? best.distance : null;
    return {
        entry: best.entry,
        distance,
        // `matched` is computed here so no caller can forget to apply the threshold.
        matched: distance !== null && distance < MATCH_THRESHOLD,
        scanned: current.entries.length + streamed,
        streamed,
        truncated: current.truncated,
        streamAll: current.streamAll
    };
};

module.exports = {
    findBestMatch,
    invalidateFacePool,
    poolStats,
    MATCH_THRESHOLD,
    MAX_POOL,
    POOL_TTL_MS
};
