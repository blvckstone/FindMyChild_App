const test = require('node:test');
const assert = require('node:assert/strict');
const {
    pickFields,
    PUBLIC_CHILD_FIELDS,
    AUTHENTICATED_CHILD_FIELDS,
    PRAISE_CHILD_FIELDS
} = require('../functions/publicProjection');

// A record shaped like a real Child document, including every private field.
const fullChild = {
    _id: 'child-1',
    fullName: 'Aamna Khan',
    age: 9,
    gender: 'Female',
    image: 'https://res.cloudinary.com/demo/image/upload/v1/fmc-children/child_1.webp',
    found: true,
    foundLocation: 'Malegaon bus stand',
    finderName: 'Rahul',
    foundDate: new Date('2026-09-05'),
    missingDate: '2026-09-01',
    missingTime: '18:30',
    missingLocation: 'Malegaon',
    state: 'Maharashtra',
    info: '',
    disability: '',
    disabilityInfo: '',
    ngoContacts: [{ _id: 'ngo-1', displayName: 'Helpline', phone: '1800123456' }],
    createdAt: new Date('2026-09-01'),
    // ---- must never leave the server ----
    contactNumber: '9999999999',
    finderContact: '8888888888',
    finderUserId: 'user-2',
    userId: 'user-1',
    faceDescriptor: [0.1, 0.2, 0.3],
    contactNumberConsent: true,
    contactNumberConsentDate: new Date()
};

const PRIVATE_FIELDS = ['contactNumber', 'finderContact', 'finderUserId', 'userId', 'faceDescriptor', 'contactNumberConsent', 'contactNumberConsentDate'];

test('A1: the public child projection strips every private and biometric field', () => {
    const safe = pickFields(fullChild, PUBLIC_CHILD_FIELDS);
    for (const field of PRIVATE_FIELDS) {
        assert.ok(!(field in safe), `public projection leaked "${field}"`);
    }
    assert.equal(safe.fullName, 'Aamna Khan');
    assert.equal(safe.found, true);
});

test('A1: the praise/gift listing exposes only the child identity', () => {
    const safe = pickFields(fullChild, PRAISE_CHILD_FIELDS);
    assert.deepEqual(Object.keys(safe).sort(), ['_id', 'found', 'fullName']);
    for (const field of PRIVATE_FIELDS) {
        assert.ok(!(field in safe), `praise listing leaked "${field}"`);
    }
});

test('A1: the report owner projection adds contact fields but still hides biometrics', () => {
    const safe = pickFields(fullChild, AUTHENTICATED_CHILD_FIELDS);
    assert.equal(safe.contactNumber, '9999999999', 'owner still sees the report contact');
    assert.ok(!('faceDescriptor' in safe), 'biometric data is never projected');
    assert.ok(!('finderContact' in safe));
});

test('pickFields ignores missing fields and tolerates empty input', () => {
    assert.deepEqual(pickFields({ _id: 'x' }, '_id fullName'), { _id: 'x' });
    assert.deepEqual(pickFields(null, PUBLIC_CHILD_FIELDS), {});
    assert.deepEqual(pickFields({ a: 1 }, ''), {});
});
