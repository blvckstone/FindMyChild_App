/**
 * D2 — `missingDate`/`missingTime` are strings compared with string operators, so only
 * canonical values work: one record written as "15/07/2026" disappears from every date and
 * range search. These tests pin the normalization (and the timezone trap) down.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { normalizeYmd, normalizeTime, isCanonicalYmd, isCanonicalTime } = require('../functions/dates');

const ROOT = path.join(__dirname, '..');

test('D2: a canonical date is never rewritten', () => {
    assert.equal(normalizeYmd('2026-07-15'), '2026-07-15');
    assert.equal(normalizeYmd(' 2026-01-02 '), '2026-01-02');
});

test('D2: an ISO timestamp keeps its own calendar day', () => {
    // Converting a timestamp through toISOString() would shift the day for most timezones.
    assert.equal(normalizeYmd('2026-07-15T10:30:00Z'), '2026-07-15');
    assert.equal(normalizeYmd('2026-07-15T22:30:00Z'), '2026-07-15');
    assert.equal(normalizeYmd('2026-07-15T00:30:00+05:30'), '2026-07-15');
    assert.equal(normalizeYmd('2026-07-15 10:30'), '2026-07-15');
});

test('D2: parseable human dates are accepted and stay on the same day', () => {
    assert.equal(normalizeYmd('July 15, 2026'), '2026-07-15');
    assert.equal(normalizeYmd('2026/07/15'), '2026-07-15');
    assert.equal(normalizeYmd('2026-7-5'), '2026-07-05');
});

test('D2: empty input means "unknown", never junk', () => {
    assert.equal(normalizeYmd(''), '');
    assert.equal(normalizeYmd(null), '');
    assert.equal(normalizeYmd('not a date'), '');
    assert.equal(normalizeYmd('15/07/2026'), '', 'ambiguous day-first input must not be guessed');
    assert.equal(normalizeYmd(undefined), undefined, 'an unsupplied field must not be overwritten');
});

test('D2: times normalize to 24-hour HH:MM', () => {
    assert.equal(normalizeTime('14:30'), '14:30');
    assert.equal(normalizeTime('2:30 PM'), '14:30');
    assert.equal(normalizeTime('2:30pm'), '14:30');
    assert.equal(normalizeTime('12:05 am'), '00:05');
    assert.equal(normalizeTime('12:05 pm'), '12:05');
    assert.equal(normalizeTime('14:30:00'), '14:30');
    assert.equal(normalizeTime('25:00'), '', 'an impossible clock time must be rejected');
    assert.equal(normalizeTime('14:75'), '');
    assert.equal(normalizeTime(''), '');
    assert.equal(normalizeTime(undefined), undefined);
});

test('D2: the canonical checks agree with the normalizers', () => {
    for (const value of ['2026-07-15', '', null, undefined]) {
        assert.equal(isCanonicalYmd(value), true, `${value} should be canonical`);
        assert.equal(normalizeYmd(value), value === undefined ? undefined : value === null ? '' : value);
    }
    for (const value of ['15/07/2026', '2026-7-5', 'not a date']) {
        assert.equal(isCanonicalYmd(value), false, `${value} needs repair`);
    }
    for (const value of ['14:30', '', null, undefined]) assert.equal(isCanonicalTime(value), true);
    for (const value of ['2:30 PM', '14:30:00', '25:00']) assert.equal(isCanonicalTime(value), false);
});

test('D2: every child write path normalizes the date fields', () => {
    const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    assert.match(server, /const \{ normalizeYmd, normalizeTime \} = require\('\.\/functions\/dates'\)/);

    // pickChildFields is the single funnel used by the public report route and both admin
    // child routes, so normalizing there covers every writer.
    const pick = server.slice(server.indexOf('const pickChildFields'), server.indexOf('// ---- Submit a missing child report'));
    assert.match(pick, /data\.missingDate = normalizeYmd\(data\.missingDate\)/);
    assert.match(pick, /data\.missingTime = normalizeTime\(data\.missingTime\)/);

    const writers = server.match(/pickChildFields\(req\.body\)/g) || [];
    assert.ok(writers.length >= 3, `expected the report + admin routes to use pickChildFields, found ${writers.length}`);
});
