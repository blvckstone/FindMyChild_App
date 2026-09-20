// End-to-end data-layer tests: a real in-memory MongoDB plus the real server.
// These cover the Phase 2 work (indexes, matchability, pagination/counters) and the
// Phase 1 fixes that could only be proven with actual data (praise leak, session revocation).
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { startDbServer, describeFace } = require('./helpers/dbServer');

// B1: keep the cached match window tiny so the streaming path is what these tests exercise.
// (Must be set before the server is spawned in test.before below.)
process.env.FACEMATCH_MAX_POOL = '2';

let ctx;
let adminToken;

const approvedChild = (overrides = {}) => ({
    fullName: 'Child',
    status: 'approved',
    found: false,
    gender: 'Male',
    age: 8,
    address: 'Malegaon',
    state: 'Maharashtra',
    missingDate: '2026-09-01',
    image: 'https://res.cloudinary.com/demo/image/upload/v1/fmc-children/x.webp',
    createdAt: new Date(),
    ...overrides
});

test.before(async () => {
    ctx = await startDbServer();
    adminToken = await ctx.adminToken();

    await ctx.models.Child.deleteMany({});
    await ctx.models.Praise.deleteMany({});

    // 120 approved (100 missing + 20 found), plus records that must NOT be counted.
    const approved = [];
    for (let i = 0; i < 100; i++) approved.push(approvedChild({ fullName: `Missing ${String(i).padStart(3, '0')}`, gender: i % 2 ? 'Female' : 'Male', age: 5 + (i % 6) }));
    for (let i = 0; i < 20; i++) approved.push(approvedChild({ fullName: `Recovered ${String(i).padStart(3, '0')}`, found: true, gender: 'Female', finderName: 'Rahul' }));
    await ctx.models.Child.insertMany(approved);
    await ctx.models.Child.insertMany([
        approvedChild({ fullName: 'Pending One', status: 'pending' }),
        approvedChild({ fullName: 'Pending Two', status: 'pending' }),
        approvedChild({ fullName: 'Rejected One', status: 'rejected' })
    ]);
});

test.after(async () => { await ctx.stop(); });

// ------------------------------------------------------------------ D1: indexes

test('D1: the schemas declare the compound indexes the queries need, and they build cleanly', async () => {
    const childIndexes = await ctx.models.Child.syncIndexes().then(() => ctx.models.Child.collection.indexes());
    const childKeys = childIndexes.map((index) => JSON.stringify(index.key));

    assert.ok(childKeys.includes(JSON.stringify({ status: 1, createdAt: -1, _id: -1 })), 'listing/pagination index missing');
    assert.ok(childKeys.includes(JSON.stringify({ status: 1, found: 1, createdAt: -1 })), 'found-filter index missing');
    assert.ok(childKeys.includes(JSON.stringify({ userId: 1, createdAt: -1 })), 'own-reports index missing');
    assert.ok(childKeys.includes(JSON.stringify({ finderUserId: 1 })), 'finder lookup index missing');

    const praiseKeys = (await ctx.models.Praise.syncIndexes().then(() => ctx.models.Praise.collection.indexes())).map((index) => JSON.stringify(index.key));
    assert.ok(praiseKeys.includes(JSON.stringify({ childId: 1, status: 1, createdAt: -1 })), 'praise listing index missing');

    // syncIndexes() throwing is exactly what a TTL/plain-index conflict looks like.
    const analyticsIndexes = await ctx.models.Analytics.syncIndexes().then(() => ctx.models.Analytics.collection.indexes());
    const ttl = analyticsIndexes.find((index) => index.expireAfterSeconds);
    assert.ok(ttl, 'analytics retention (TTL) index missing');
});

test('D1: the main listing query is served by an index instead of a collection scan', async () => {
    const explain = await ctx.models.Child
        .find({ status: 'approved', found: false })
        .sort({ createdAt: -1, _id: -1 })
        .limit(50)
        .explain('queryPlanner');

    const stages = [];
    const walk = (plan) => {
        if (!plan) return;
        stages.push(plan.stage);
        walk(plan.inputStage);
        walk(plan.child);
    };
    walk(explain.queryPlanner.winningPlan);

    assert.ok(stages.includes('IXSCAN'), `expected an index scan, got: ${stages.join(' > ')}`);
    assert.ok(!stages.includes('COLLSCAN'), 'the listing query still scans the whole collection');
});

// ------------------------------------------------- C1: counters and pagination

test('C1: /api/stats counts every approved record, not just the first page', async () => {
    const res = await ctx.api('/api/stats');
    assert.equal(res.status, 200);
    assert.equal(res.json.data.total, 120);
    assert.equal(res.json.data.missing, 100);
    assert.equal(res.json.data.found, 20);
});

test('C1: /api/children paginates past the old 50-record ceiling', async () => {
    const first = await ctx.api('/api/children?limit=50&page=1');
    assert.equal(first.status, 200);
    assert.equal(first.json.data.length, 50);
    assert.equal(first.json.total, 120, 'total is returned alongside the page, not inside data');
    assert.equal(first.json.pages, 3);

    const third = await ctx.api('/api/children?limit=50&page=3');
    assert.equal(third.json.data.length, 20, 'the final page must still be reachable');

    const ids = new Set([...first.json.data, ...third.json.data].map((c) => String(c._id)));
    assert.equal(ids.size, 70, 'pages must not repeat records');
});

test('C1: filters and sorting work server-side', async () => {
    const found = await ctx.api('/api/children?found=true&limit=100');
    assert.equal(found.json.total, 20);
    assert.ok(found.json.data.every((c) => c.found === true));

    const female = await ctx.api('/api/children?gender=Female&limit=5');
    assert.ok(female.json.data.every((c) => c.gender === 'Female'));

    const aged = await ctx.api('/api/children?ageMin=10&ageMax=12&limit=100');
    assert.ok(aged.json.data.every((c) => c.age >= 10 && c.age <= 12));

    const named = await ctx.api('/api/children?q=Recovered&limit=100');
    assert.equal(named.json.total, 20);

    const byAge = await ctx.api('/api/children?sortBy=age&limit=5');
    const ages = byAge.json.data.map((c) => c.age);
    assert.deepEqual(ages.slice().sort((a, b) => a - b), ages, 'sortBy=age must return ascending ages');
});

test('C1: a regex-looking search is treated as literal text (no runaway query)', async () => {
    const res = await ctx.api('/api/children?q=.*&limit=100');
    assert.equal(res.status, 200);
    assert.equal(res.json.total, 0, 'a regex payload must not match every record');
});

test('C1: the public listing never exposes contacts or biometrics', async () => {
    await ctx.models.Child.create(approvedChild({
        fullName: 'Secret Keeper',
        contactNumber: '9999999999',
        finderContact: '8888888888',
        faceDescriptor: describeFace(1)
    }));

    const res = await ctx.api('/api/children?q=Secret%20Keeper');
    assert.equal(res.json.data.length, 1);
    const child = res.json.data[0];
    for (const field of ['contactNumber', 'finderContact', 'finderUserId', 'userId', 'faceDescriptor']) {
        assert.ok(!(field in child), `public listing leaked ${field}`);
    }
});

// ------------------------------------------------------- A1: the praise leak

test('A1: /api/praise returns only the child identity — with real data containing secrets', async () => {
    const child = await ctx.models.Child.create(approvedChild({
        fullName: 'Aamna Khan',
        found: true,
        contactNumber: '9999999999',
        finderContact: '8888888888',
        finderUserId: new mongoose.Types.ObjectId(),
        faceDescriptor: describeFace(2)
    }));
    await ctx.models.Praise.create({
        childId: child._id,
        userName: 'Well wisher',
        childName: child.fullName,
        text: 'Thank you',
        status: 'approved'
    });

    const res = await ctx.api(`/api/praise?childId=${child._id}`);
    assert.equal(res.status, 200);
    const returned = res.json.data.child;

    assert.equal(returned.fullName, 'Aamna Khan');
    for (const field of ['contactNumber', 'finderContact', 'finderUserId', 'userId', 'faceDescriptor']) {
        assert.ok(!(field in returned), `praise endpoint leaked ${field}`);
    }
    assert.equal(res.json.data.praises.length, 1);
    assert.equal(res.json.data.praises[0].text, 'Thank you');
});

// ------------------------------------------------ B3: admin records are matchable

test('B3: a child saved with face data is found by the AI match, and one without is not', async () => {
    const withFace = await ctx.models.Child.create(approvedChild({
        fullName: 'Matchable Minal',
        faceDescriptor: describeFace(3)
    }));
    await ctx.models.Child.create(approvedChild({ fullName: 'Faceless Farid' }));

    const res = await ctx.api('/api/safechild/match', {
        method: 'POST',
        body: { faceDescriptor: describeFace(3) }
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.matched, true, 'the record with a descriptor must match');
    assert.equal(String(res.json.data.id), String(withFace._id));
    assert.equal(res.json.data.childName, 'Matchable Minal');
    assert.ok(!('parentContact' in res.json.data), 'match response must not leak contact details');
});

test('B3: admin-created records with face data enter the match pool', async () => {
    const created = await ctx.api('/api/admin/children', {
        method: 'POST',
        token: adminToken,
        body: { fullName: 'Admin Added Aisha', status: 'approved', faceDescriptor: JSON.stringify(describeFace(4)) }
    });
    assert.equal(created.status, 201);

    const res = await ctx.api('/api/safechild/match', { method: 'POST', body: { faceDescriptor: describeFace(4) } });
    assert.equal(res.json.matched, true, 'admin-created records must be matchable');
    assert.equal(res.json.data.childName, 'Admin Added Aisha');
});

test('B3: an unparsable descriptor on edit never wipes existing face data', async () => {
    const child = await ctx.models.Child.create(approvedChild({
        fullName: 'Descriptor Keeper',
        faceDescriptor: describeFace(5)
    }));

    const update = await ctx.api(`/api/admin/children/${child._id}`, {
        method: 'PUT',
        token: adminToken,
        body: { faceDescriptor: 'not-a-descriptor', info: 'edited' }
    });
    assert.equal(update.status, 200);

    const stored = await ctx.models.Child.findById(child._id).lean();
    assert.equal(stored.faceDescriptor.length, 128, 'existing descriptor was destroyed by a bad edit');
    assert.equal(stored.info, 'edited', 'the rest of the edit must still be applied');
});

// ------------------------------------- A5: blocking really kills live sessions

test('A5: blocking a user through the admin API revokes the session they already hold', async () => {
    const { hashPassword } = require('../functions/passwords');
    const user = await ctx.models.User.create({
        userFullName: 'Blockable Bina',
        userContactNumber: '9876500011',
        emailId: 'bina@example.com',
        password: hashPassword('pass1234'),
        createdAt: new Date()
    });

    const login = await ctx.api('/api/auth/login', { method: 'POST', body: { identifier: '9876500011', password: 'pass1234' } });
    assert.equal(login.status, 200);
    const userToken = login.json.token;

    const before = await ctx.api('/api/auth/me', { token: userToken });
    assert.equal(before.status, 200, 'the user should be logged in before blocking');

    const block = await ctx.api(`/api/admin/users/${user._id}`, { method: 'PUT', token: adminToken, body: { blocked: true } });
    assert.equal(block.status, 200);

    const after = await ctx.api('/api/auth/me', { token: userToken });
    assert.equal(after.status, 401, 'the blocked user\'s existing token must stop working');

    const relogin = await ctx.api('/api/auth/login', { method: 'POST', body: { identifier: '9876500011', password: 'pass1234' } });
    assert.equal(relogin.status, 401);
    assert.match(String(relogin.json.message), /blocked/i);
});

// ------------------------------------------------------------------ C3: admin users + counts

test('C3: the admin user list is paginated, searchable and counts activity in one page-worth of queries', async () => {
    const { hashPassword } = require('../functions/passwords');
    await ctx.models.User.deleteMany({ emailId: /@c3\.example\.com$/ });

    const users = [];
    for (let i = 0; i < 12; i++) {
        users.push({
            userFullName: `C3 User ${String(i).padStart(2, '0')}`,
            userContactNumber: `98765010${String(i).padStart(2, '0')}`,
            emailId: `user${i}@c3.example.com`,
            password: hashPassword('pass1234')
        });
    }
    await ctx.models.User.insertMany(users);

    // Activity for one of them, so the grouped counts have something to find.
    const target = await ctx.models.User.findOne({ emailId: 'user3@c3.example.com' });
    await ctx.models.Child.insertMany([
        approvedChild({ fullName: 'C3 Report One', userId: target._id }),
        approvedChild({ fullName: 'C3 Report Two', userId: target._id })
    ]);
    await ctx.models.PreRegisteredChild.create({
        parentId: target._id, childName: 'C3 SafeChild', status: 'approved', faceDescriptor: describeFace(81)
    });

    const first = await ctx.api('/api/admin/users?page=1&limit=5', { token: adminToken });
    assert.equal(first.status, 200);
    assert.equal(first.json.limit, 5);
    assert.ok(first.json.total >= 12, `expected at least 12 users, got ${first.json.total}`);
    assert.equal(first.json.pages, Math.ceil(first.json.total / 5));
    assert.equal(first.json.data.length, 5, 'the page must be capped at the requested size');

    const second = await ctx.api('/api/admin/users?page=2&limit=5', { token: adminToken });
    const firstIds = first.json.data.map((user) => String(user._id));
    const secondIds = second.json.data.map((user) => String(user._id));
    assert.equal(secondIds.some((id) => firstIds.includes(id)), false, 'pages must not overlap');

    const searched = await ctx.api('/api/admin/users?q=user7%40c3.example.com', { token: adminToken });
    assert.equal(searched.json.total, 1, 'search must run server-side');
    assert.equal(searched.json.data[0].emailId, 'user7@c3.example.com');

    const noPassword = first.json.data.every((user) => !('password' in user));
    assert.ok(noPassword, 'password hashes must never be listed');

    // Grouped counts: the user with activity reports it, everyone else reports zeroes.
    const foundTarget = first.json.data.concat(second.json.data).find((user) => String(user._id) === String(target._id));
    if (foundTarget) {
        assert.equal(foundTarget.activity.reports, 2);
        assert.equal(foundTarget.activity.safeChildren, 1);
    } else {
        const paged = await ctx.api(`/api/admin/users?q=${encodeURIComponent('user3@c3.example.com')}`, { token: adminToken });
        assert.equal(paged.json.data[0].activity.reports, 2);
        assert.equal(paged.json.data[0].activity.safeChildren, 1);
    }
    const plain = first.json.data.find((user) => String(user._id) !== String(target._id));
    if (plain) assert.deepEqual(plain.activity, { reports: 0, foundRequests: 0, praise: 0, gifts: 0, safeChildren: 0 });

    // A regex-looking search must stay literal.
    const hostile = await ctx.api('/api/admin/users?q=' + encodeURIComponent('.*'), { token: adminToken });
    assert.equal(hostile.status, 200);
    assert.equal(hostile.json.total, 0, 'a regex injection must not match every user');
});

test('C3: SafeChild registrations come back with their owner in one request', async () => {
    const res = await ctx.api('/api/admin/safe-children?limit=50', { token: adminToken });
    assert.equal(res.status, 200);
    assert.ok(res.json.data.length >= 1, 'the seeded registration must be listed');
    assert.ok(!('faceDescriptor' in res.json.data[0]), 'biometrics must not be sent to the panel list');

    const seeded = res.json.data.find((row) => row.childName === 'C3 SafeChild');
    assert.ok(seeded, 'the seeded row must be present');
    assert.equal(seeded.user && seeded.user.emailId, 'user3@c3.example.com', 'the owner must be embedded');

    const filtered = await ctx.api('/api/admin/safe-children?status=pending', { token: adminToken });
    assert.equal(filtered.status, 200);
    assert.ok(filtered.json.data.every((row) => row.status === 'pending'), 'the status filter must be server-side');
});

test('C3: badge counters answer with counts instead of full lists', async () => {
    const res = await ctx.api('/api/admin/counts', { token: adminToken });
    assert.equal(res.status, 200);
    for (const key of ['pendingChildren', 'pendingFound', 'pendingPraise', 'pendingGifts', 'activeAdmins', 'pendingDonations']) {
        assert.equal(typeof res.json.data[key], 'number', `${key} must be a number`);
    }

    const expectedPending = await ctx.models.Child.countDocuments({ status: 'pending' });
    assert.equal(res.json.data.pendingChildren, expectedPending);

    const anonymous = await ctx.api('/api/admin/counts');
    assert.equal(anonymous.status, 401, 'the counters must stay behind admin auth');
});

// ------------------------------------------------------------------ D2: date storage

test('D2: legacy non-ISO dates are repaired so date searches can see them again', async () => {
    const { migrateChildDates } = require('../functions/dates');
    // The date and range searches are socket.io handlers in server.js that call these two
    // functions, so exercising them here is exercising the real query path.
    const getByDateData = require('../functions/getByDateData/getByDateData.js');
    const getByRangeData = require('../functions/getByRangeData/getByRangeData.js');

    const legacy = await ctx.models.Child.insertMany([
        approvedChild({ fullName: 'Legacy Slash Date', missingDate: '15/07/2026' }),
        approvedChild({ fullName: 'Legacy Timestamp', missingDate: '2026-07-15T10:30:00Z' }),
        approvedChild({ fullName: 'Legacy Short Date', missingDate: '2026-7-5' }),
        approvedChild({ fullName: 'Legacy Junk', missingDate: 'sometime last year' }),
        approvedChild({ fullName: 'Legacy Time', missingDate: '2026-07-20', missingTime: '3:45 PM' })
    ]);

    // Before the repair neither the exact-date nor the range search can see the messy rows.
    const beforeDates = (await getByDateData('2026-07-15')).data.map((item) => item.fullName);
    assert.ok(!beforeDates.includes('Legacy Timestamp'), 'a timestamp is invisible to an exact-date search');
    const beforeRange = (await getByRangeData({ searchingDateFrom: '2026-07-01', searchingDateTo: '2026-07-31' })).data.map((item) => item.fullName);
    assert.ok(!beforeRange.includes('Legacy Short Date'), 'a non-canonical date is invisible to a range search');

    const summary = await migrateChildDates(ctx.models.Child);
    assert.equal(summary.dateFixed, 2, 'the timestamp and the short date are recoverable');
    assert.equal(summary.unmatched, 2, 'the ambiguous and unparsable dates are cleared and reported');
    assert.equal(summary.timeFixed, 1);

    const stored = await ctx.models.Child.find({ _id: { $in: legacy.map((doc) => doc._id) } }).lean();
    const byName = Object.fromEntries(stored.map((doc) => [doc.fullName, doc]));
    assert.equal(byName['Legacy Slash Date'].missingDate, '', 'an ambiguous day-first date is cleared, never guessed');
    assert.equal(byName['Legacy Timestamp'].missingDate, '2026-07-15');
    assert.equal(byName['Legacy Short Date'].missingDate, '2026-07-05');
    assert.equal(byName['Legacy Junk'].missingDate, '');
    assert.equal(byName['Legacy Time'].missingTime, '15:45');

    // The repaired rows are now findable by both searches, and the repair is idempotent.
    const afterDates = (await getByDateData('2026-07-15')).data.map((item) => item.fullName);
    assert.ok(afterDates.includes('Legacy Timestamp'), 'the repaired timestamp is searchable by its day');
    const afterRange = (await getByRangeData({ searchingDateFrom: '2026-07-01', searchingDateTo: '2026-07-31' })).data.map((item) => item.fullName);
    assert.ok(afterRange.includes('Legacy Short Date'), 'the repaired date is inside the range');
    assert.ok(!afterRange.includes('Legacy Slash Date'), 'a cleared date must not appear in a range');

    const second = await migrateChildDates(ctx.models.Child);
    assert.equal(second.dateFixed, 0, 'a second run must not change anything');
    assert.equal(second.timeFixed, 0);

    await ctx.models.Child.deleteMany({ _id: { $in: legacy.map((doc) => doc._id) } });
});

test('D2: a report submitted through the API stores canonical date and time', async () => {
    const { hashPassword } = require('../functions/passwords');
    await ctx.models.User.create({
        userFullName: 'Date Reporter',
        userContactNumber: '9876500044',
        emailId: 'dates@example.com',
        password: hashPassword('pass1234')
    });
    const login = await ctx.api('/api/auth/login', { method: 'POST', body: { identifier: '9876500044', password: 'pass1234' } });
    assert.equal(login.status, 200);

    const body = {
        fullName: 'Canonical Kid',
        missingDate: '2026-07-15T10:30:00Z',
        missingTime: '2:30 PM'
    };
    const res = await ctx.api('/api/children', { method: 'POST', token: login.json.token, body });
    assert.equal(res.status, 201, JSON.stringify(res.json));

    const created = await ctx.models.Child.findOne({ fullName: 'Canonical Kid' }).lean();
    assert.equal(created.missingDate, '2026-07-15', 'the report must store a canonical date');
    assert.equal(created.missingTime, '14:30', 'the report must store a canonical time');

    // A report starts as pending; once approved it must be findable by its date.
    const approved = await ctx.api(`/api/admin/children/${created._id}`, { method: 'PUT', token: adminToken, body: { status: 'approved' } });
    assert.equal(approved.status, 200, JSON.stringify(approved.json));
    const found = (await require('../functions/getByDateData/getByDateData.js')('2026-07-15')).data.map((item) => item.fullName);
    assert.ok(found.includes('Canonical Kid'), 'the new report must be findable by date');
});

// ------------------------------------------------------------------ D3: orphaned activity

test('D3: activity keeps a readable child name after the child record is deleted', async () => {
    const { hashPassword } = require('../functions/passwords');

    // A missing child can receive a found request; a recovered one can receive praise.
    const child = await ctx.models.Child.create(approvedChild({ fullName: 'Orphan Target' }));
    const foundChild = await ctx.models.Child.create(approvedChild({ fullName: 'Praise Target', found: true, finderUserId: new mongoose.Types.ObjectId() }));
    await ctx.models.User.create({
        userFullName: 'Orphan Tester',
        userContactNumber: '9876500033',
        emailId: 'orphan@example.com',
        password: hashPassword('pass1234')
    });
    const login = await ctx.api('/api/auth/login', { method: 'POST', body: { identifier: '9876500033', password: 'pass1234' } });
    assert.equal(login.status, 200);
    const userToken = login.json.token;

    const found = await ctx.api('/api/found-requests', {
        method: 'POST',
        token: userToken,
        body: { childId: String(child._id), finderName: 'Finder One' }
    });
    assert.equal(found.status, 201, JSON.stringify(found.json));

    const praise = await ctx.api('/api/praise', {
        method: 'POST',
        token: userToken,
        body: { childId: String(foundChild._id), text: 'Brave work' }
    });
    assert.equal(praise.status, 201, JSON.stringify(praise.json));

    // Both children are removed (admin delete). The activity rows outlive them.
    const removed = await ctx.api(`/api/admin/children/${child._id}`, { method: 'DELETE', token: adminToken });
    assert.ok([200, 204].includes(removed.status), `child delete failed with ${removed.status}`);
    const removedFound = await ctx.api(`/api/admin/children/${foundChild._id}`, { method: 'DELETE', token: adminToken });
    assert.ok([200, 204].includes(removedFound.status), `child delete failed with ${removedFound.status}`);

    const foundReqs = await ctx.api('/api/admin/found-requests', { token: adminToken });
    assert.equal(foundReqs.status, 200);
    const storedRequest = foundReqs.json.data.find((item) => String(item._id) === String(found.json.data._id));
    assert.ok(storedRequest, 'the found request must still be listed');
    assert.equal(storedRequest.childId, null, 'the child reference is expected to dangle after deletion');
    assert.equal(storedRequest.childName, 'Orphan Target', 'the name snapshot must survive the delete');

    const praiseList = await ctx.api('/api/admin/praise', { token: adminToken });
    assert.equal(praiseList.status, 200);
    const storedPraise = praiseList.json.data.find((item) => String(item._id) === String(praise.json.data._id));
    assert.ok(storedPraise, 'the praise must still be listed');
    assert.equal(storedPraise.childName, 'Praise Target', 'the praise keeps the name it was written for');
});

test('D3: the admin panel renders the snapshot instead of "Unknown"', () => {
    const fs = require('node:fs');
    const admin = fs.readFileSync(require('node:path').join(__dirname, '../public/admin.html'), 'utf8');
    assert.match(admin, /function childLabel\(record\)/, 'the shared name resolver is missing');
    assert.ok(
        !/childId&&\s*\w+\.childId\.fullName\|\|'Unknown'/.test(admin),
        'a render path still ignores the stored name snapshot'
    );
});

// ------------------------------------------------------------------ B1: AI match at scale

test('B1: the live scan matches a child who is outside the cached pool', async () => {
    await ctx.models.PreRegisteredChild.deleteMany({});

    // Oldest first by _id; the pool only holds the newest two.
    const streamed = await ctx.models.PreRegisteredChild.create({
        parentId: new mongoose.Types.ObjectId(),
        childName: 'Streamed SafeChild',
        age: 6,
        gender: 'Female',
        parentContact: '9000000001',
        status: 'approved',
        photoUrl: 'https://res.cloudinary.com/demo/image/upload/v1/fmc-children/old.webp',
        faceDescriptor: describeFace(61)
    });
    await ctx.models.PreRegisteredChild.insertMany([
        { parentId: new mongoose.Types.ObjectId(), childName: 'Pooled B', status: 'approved', faceDescriptor: describeFace(62) },
        { parentId: new mongoose.Types.ObjectId(), childName: 'Pooled C', status: 'approved', faceDescriptor: describeFace(63) }
    ]);

    const res = await ctx.api('/api/safechild/match', { method: 'POST', body: { faceDescriptor: describeFace(61) } });
    assert.equal(res.status, 200);
    assert.equal(res.json.matched, true, 'the oldest record must still be matchable through the streamed overflow');
    assert.equal(String(res.json.data.id), String(streamed._id));
    assert.equal(res.json.data.childName, 'Streamed SafeChild');
    assert.ok(res.json.distance < 0.01, `expected a near-exact match, got ${res.json.distance}`);

    // The public match response must stay free of private data.
    assert.ok(!('parentContact' in res.json.data), 'match response must not leak the parent contact');
    assert.ok(!('faceDescriptor' in res.json.data), 'match response must not leak biometrics');
    assert.deepEqual(
        Object.keys(res.json.data).sort(),
        ['age', 'childName', 'confidence', 'detailType', 'gender', 'id', 'photoUrl', 'source'],
        'the match response must keep its minimal public shape'
    );
});

// ------------------------------------------------------------------ C4: dashboard figures

test('C4: the dashboard counts are database counts, not the length of a fetched page', async () => {
    const { Child, User, FoundRequest } = ctx.models;

    // The truth, straight from the database.
    const expected = {
        pending: await Child.countDocuments({ status: 'pending' }),
        approved: await Child.countDocuments({ status: 'approved' }),
        rejected: await Child.countDocuments({ status: 'rejected' }),
        total: await Child.countDocuments({}),
        missing: await Child.countDocuments({ status: 'approved', found: { $ne: true } }),
        found: await Child.countDocuments({ status: 'approved', found: true }),
        users: await User.countDocuments({}),
        foundRequests: await FoundRequest.countDocuments({ status: 'pending' })
    };

    const res = await ctx.api('/api/admin/stats', { token: adminToken });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json.data, expected, 'every dashboard figure must equal the database count');

    // Proof the figures cannot be derived from a page of records: the listing is capped well
    // below the number of approved children, so anything computed from it would be wrong.
    const listing = await ctx.api('/api/admin/children', { token: adminToken });
    assert.equal(listing.status, 200);
    assert.ok(listing.json.data.length <= 50, 'the admin listing is still capped per request');
    assert.ok(expected.total > listing.json.data.length, 'this database is larger than one page on purpose');
    assert.notEqual(res.json.data.total, listing.json.data.length, 'the total must not be a page length');

    // And the panel must actually read those fields instead of recomputing them from the page.
    const fs = require('node:fs');
    const path = require('node:path');
    const admin = fs.readFileSync(path.join(__dirname, '../public/admin.html'), 'utf8');
    assert.match(admin, /\$\{s\.missing \?\? '-'\}/, 'the missing-children card must use the server figure');
    assert.match(admin, /\$\{s\.found \?\? '-'\}/, 'the found-children card must use the server figure');
    assert.match(admin, /\$\{s\.users \?\? '-'\}/, 'the users card must use the server figure');
    assert.match(admin, /\$\{s\.foundRequests \?\? '-'\}/, 'the pending found-requests card must use the server figure');
    assert.doesNotMatch(
        admin,
        /allChildren\.filter\(c=>!c\.found\)/,
        'the dashboard must not count from the fetched page'
    );
});

test('B1: a child registered after the pool was built is immediately matchable', async () => {
    // The previous test built the cached window; this write bypasses the API entirely.
    await ctx.models.PreRegisteredChild.create({
        parentId: new mongoose.Types.ObjectId(),
        childName: 'Freshly Registered',
        status: 'approved',
        faceDescriptor: describeFace(71)
    });

    const res = await ctx.api('/api/safechild/match', { method: 'POST', body: { faceDescriptor: describeFace(71) } });
    assert.equal(res.status, 200);
    assert.equal(res.json.matched, true, 'a brand-new registration must never be invisible to a scan');
    assert.equal(res.json.data.childName, 'Freshly Registered');
});
