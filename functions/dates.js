// The child records keep their dates as strings (`missingDate`, `missingTime`).
//
// That is workable only while every value is canonical ISO (`YYYY-MM-DD`, `HH:MM`), because
// the search endpoints compare them with plain string operators ($eq/$gte/$lte). A single
// record written as "15/07/2026" silently drops out of every date search, so every write now
// goes through these helpers and the one-off migration below repairs the legacy rows.

const YMD = /^\d{4}-\d{2}-\d{2}$/;
const HM = /^\d{2}:\d{2}$/;

/**
 * Normalize a date to `YYYY-MM-DD`. Returns:
 *   - undefined when the value was not supplied (so updates leave the field alone)
 *   - '' when the value is empty or unparsable (stored as "unknown", never as junk)
 *   - a canonical `YYYY-MM-DD` string otherwise
 */
const normalizeYmd = (value) => {
    if (value === undefined) return undefined;
    if (value === null) return '';
    const raw = String(value).trim();
    if (!raw) return '';

    // Already a date, or an ISO timestamp: take the date part verbatim. Converting through
    // Date/toISOString here would shift the day for anyone east or west of UTC.
    const isoHead = raw.match(/^(\d{4}-\d{2}-\d{2})(?:[T\s].*)?$/);
    if (isoHead) return isoHead[1];

    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) return '';
    // Local calendar components, so "July 15, 2026" stays the 15th.
    const pad = (n) => String(n).padStart(2, '0');
    return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())}`;
};

/** Normalize a clock time to `HH:MM`; `undefined` unsupplied, `''` empty or unparsable. */
const normalizeTime = (value) => {
    if (value === undefined) return undefined;
    if (value === null) return '';
    const raw = String(value).trim();
    if (!raw) return '';
    if (HM.test(raw)) {
        const [hours, minutes] = raw.split(':').map(Number);
        return hours <= 23 && minutes <= 59 ? raw : '';
    }

    const match = raw.match(/^(\d{1,2}):(\d{2})(?::\d{2})?\s*([AaPp][Mm])?$/);
    if (!match) return '';
    let hours = Number(match[1]);
    const minutes = Number(match[2]);
    const meridiem = match[3] ? match[3].toLowerCase() : null;
    if (meridiem === 'pm' && hours < 12) hours += 12;
    if (meridiem === 'am' && hours === 12) hours = 0;
    if (hours > 23 || minutes > 59) return '';
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
};

/**
 * Is this stored value already canonical (or legitimately empty)? Defined by round-tripping
 * through the normalizer, so the "needs repair" check can never disagree with the repair,
 * and an impossible value like "25:00" counts as needing repair even though it matches the
 * shape of a time.
 */
const isCanonicalYmd = (value) => value === undefined || value === null || normalizeYmd(value) === String(value);
const isCanonicalTime = (value) => value === undefined || value === null || normalizeTime(value) === String(value);

/**
 * One-off repair for rows written before normalization existed. Idempotent: it only ever
 * updates rows whose stored value is not already canonical. Returns a summary.
 */
const migrateChildDates = async (Child, { batchSize = 200 } = {}) => {
    const summary = { scanned: 0, dateFixed: 0, timeFixed: 0, unmatched: 0 };

    const cursor = Child.find({})
        .select('_id missingDate missingTime')
        .lean()
        .cursor({ batchSize });

    let operations = [];
    const flush = async () => {
        if (!operations.length) return;
        await Child.bulkWrite(operations, { ordered: false });
        operations = [];
    };

    for await (const doc of cursor) {
        summary.scanned++;
        const update = {};

        if (!isCanonicalYmd(doc.missingDate)) {
            const normalized = normalizeYmd(doc.missingDate);
            update.missingDate = normalized;
            if (normalized) summary.dateFixed++;
            else summary.unmatched++;
        }
        if (!isCanonicalTime(doc.missingTime)) {
            const normalized = normalizeTime(doc.missingTime);
            update.missingTime = normalized;
            if (normalized) summary.timeFixed++;
            else summary.unmatched++;
        }

        if (Object.keys(update).length) {
            operations.push({ updateOne: { filter: { _id: doc._id }, update: { $set: update } } });
        }
        if (operations.length >= batchSize) await flush();
    }

    await flush();
    return summary;
};

module.exports = {
    normalizeYmd,
    normalizeTime,
    isCanonicalYmd,
    isCanonicalTime,
    migrateChildDates,
    YMD,
    HM
};
