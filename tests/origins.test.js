// CORS policy: the app is same-origin by default; extra browser origins must be opted in.
const test = require('node:test');
const assert = require('node:assert/strict');

const { parseAllowedOrigins, createOriginPolicy } = require('../functions/origins');

test('an unset ALLOWED_ORIGINS means same-origin only', () => {
    const policy = createOriginPolicy('');
    assert.equal(policy.mode, 'same-origin');
    assert.equal(policy.isAllowed('https://findmychild.dpdns.org', 'findmychild.dpdns.org'), true);
    assert.equal(policy.isAllowed('https://evil.example', 'findmychild.dpdns.org'), false);
});

test('requests without an Origin are allowed (curl, health checks, native clients)', () => {
    const policy = createOriginPolicy('');
    assert.equal(policy.isAllowed(undefined, 'findmychild.dpdns.org'), true);
    assert.equal(policy.isAllowed(null, 'findmychild.dpdns.org'), true);
});

test('a literal "null" origin is never trusted', () => {
    const policy = createOriginPolicy('');
    assert.equal(policy.isAllowed('null', 'findmychild.dpdns.org'), false);
});

test('the same host on a different port is treated as cross-origin', () => {
    const policy = createOriginPolicy('');
    assert.equal(policy.isAllowed('http://localhost:3000', 'localhost:8080'), false);
    assert.equal(policy.isAllowed('http://localhost:8080', 'localhost:8080'), true);
});

test('explicit origins are accepted in either form and matched by host', () => {
    const policy = createOriginPolicy('https://partner.example, app.ngo.org/');
    assert.equal(policy.mode, 'list');
    assert.equal(policy.isAllowed('https://partner.example', 'findmychild.dpdns.org'), true);
    assert.equal(policy.isAllowed('https://app.ngo.org', 'findmychild.dpdns.org'), true);
    assert.equal(policy.isAllowed('https://other.ngo.org', 'findmychild.dpdns.org'), false);
    assert.equal(policy.isAllowed('https://partner.example.evil.com', 'findmychild.dpdns.org'), false);
});

test('"*" opts out explicitly and is reported as such', () => {
    const policy = createOriginPolicy('*');
    assert.equal(policy.mode, 'any');
    assert.equal(policy.isAllowed('https://anything.example', 'findmychild.dpdns.org'), true);
});

test('a malformed Origin header is refused rather than allowed', () => {
    const policy = createOriginPolicy('*');
    assert.equal(policy.isAllowed('not-a-url', 'findmychild.dpdns.org'), false);
});

test('parseAllowedOrigins ignores blank entries', () => {
    assert.equal(parseAllowedOrigins('   ').mode, 'same-origin');
    assert.equal(parseAllowedOrigins(',,,').mode, 'same-origin');
});
