// Guards for the test harness itself and for the CI gate.
//
// Both are easy to break invisibly: a reintroduced hardcoded port range only shows up as an
// occasional unrelated failure, and a CI workflow that stops running its steps still shows a
// green tick.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

const testFiles = () => {
    const dir = path.join(ROOT, 'tests');
    const files = [];
    const walk = (current) => {
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const full = path.join(current, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.js')) files.push(full);
        }
    };
    walk(dir);
    return files;
};

test('harness: no test file allocates ports from a fixed numeric range', () => {
    // Two files previously drew from overlapping ranges (9450-9650 and 9600-9800). Under
    // parallel execution that could bind the same port, and a test would then talk to another
    // file's server — a failure with no relation to the code under test.
    const offenders = [];
    for (const file of testFiles()) {
        const source = fs.readFileSync(file, 'utf8');
        if (/9\d{3}\s*\+\s*Math\.random\(\)/.test(source)) {
            offenders.push(path.relative(ROOT, file));
        }
    }
    assert.deepEqual(offenders, [], 'test files must take their port from tests/helpers/ports.js');
});

test('harness: the port helper asks the OS rather than guessing', () => {
    const helper = fs.readFileSync(path.join(ROOT, 'tests/helpers/ports.js'), 'utf8');
    assert.match(helper, /listen\(0, '127\.0\.0\.1'/, 'the helper must let the OS assign the port');
    assert.match(helper, /probe\.close\(/, 'the probe socket must be released before the server binds');
});

test('CI: the workflow runs the syntax check, the lint pass and the suite', () => {
    const workflow = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');

    assert.match(workflow, /^on:/m, 'the workflow must have a trigger');
    assert.match(workflow, /push:/, 'it must run on push');
    assert.match(workflow, /pull_request:/, 'it must run on pull requests');

    // `npm ci` installs exactly package-lock.json, so CI and production resolve the same tree.
    assert.match(workflow, /run: npm ci/);
    assert.match(workflow, /run: npm run check/);
    assert.match(workflow, /run: npm run lint/);
    assert.match(workflow, /run: node --test/, 'the suite must actually run');
});

test('CI: the check command runs all three gates locally too', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    assert.equal(pkg.scripts.ci, 'npm run check && npm run lint && npm test');
    assert.ok(pkg.scripts.lint, 'a lint script must exist');
    assert.ok(pkg.engines && pkg.engines.node, 'the supported Node version must be declared');
});
