/**
 * C2 — every write used to broadcast a bare `dataChanged`, and every client answered with a
 * full reload. A bulk action therefore produced one full dataset query per write per client.
 * These tests pin the replacement: one notification per window, carrying the scopes that
 * actually changed.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { createChangeNotifier, scopeForPath, SCOPE_ALL } = require('../functions/changeNotifier');

const ROOT = path.join(__dirname, '..');

/** A notifier with a manual clock so the coalescing window can be controlled exactly. */
const harness = (options = {}) => {
    const emitted = [];
    let queued = null;
    const notifier = createChangeNotifier({
        emit: (payload) => emitted.push(payload),
        windowMs: 750,
        schedule: (fn) => {
            queued = fn;
            return { unref() {} };
        },
        cancel: () => { queued = null; },
        now: () => 1000,
        ...options
    });
    const tick = () => {
        const fn = queued;
        queued = null;
        if (fn) fn();
    };
    return { notifier, emitted, tick, isScheduled: () => queued !== null };
};

test('C2: a burst of writes produces one notification, not one per write', () => {
    const { notifier, emitted, tick } = harness();

    for (let i = 0; i < 50; i++) notifier.notify('children');
    assert.equal(emitted.length, 0, 'nothing may be sent before the window closes');

    tick();
    assert.equal(emitted.length, 1, 'the whole burst must collapse into a single notification');
    assert.deepEqual(emitted[0].scopes, ['children']);
    assert.equal(notifier.stats().notifications, 50);
    assert.equal(notifier.stats().flushes, 1);
});

test('C2: the notification carries every scope that changed', () => {
    const { notifier, emitted, tick } = harness();
    notifier.notify('children');
    notifier.notify('praise');
    notifier.notify('children');
    notifier.notify('users');
    tick();

    assert.equal(emitted.length, 1);
    assert.deepEqual(emitted[0].scopes, ['children', 'praise', 'users']);
});

test('C2: "all" supersedes narrower scopes', () => {
    const { notifier, emitted, tick } = harness();
    notifier.notify('praise');
    notifier.notify(SCOPE_ALL);
    notifier.notify('users');
    tick();

    assert.deepEqual(emitted[0].scopes, [SCOPE_ALL], 'a global change must not be narrowed');
});

test('C2: the next window starts clean', () => {
    const { notifier, emitted, tick } = harness();
    notifier.notify('children');
    tick();
    notifier.notify('praise');
    tick();

    assert.equal(emitted.length, 2);
    assert.deepEqual(emitted.map((payload) => payload.scopes), [['children'], ['praise']]);
});

test('C2: a write with no notification listener error can break the write', () => {
    // emit() throwing must be reported and swallowed: the HTTP request already succeeded.
    const errors = [];
    const { notifier } = harness({
        emit: () => { throw new Error('socket exploded'); },
        onError: (error) => errors.push(error.message)
    });
    assert.equal(notifier.notify('children'), 1);
    assert.doesNotThrow(() => notifier.flush());
    assert.deepEqual(errors, ['socket exploded']);
});

test('C2: stats and stop behave', () => {
    const { notifier, emitted, tick, isScheduled } = harness();
    notifier.notify('ads');
    assert.equal(isScheduled(), true);
    assert.equal(notifier.stats().pending, 1);

    notifier.stop();
    assert.equal(isScheduled(), false, 'stop must cancel the pending flush');
    assert.equal(notifier.stats().pending, 0);
    tick();
    assert.equal(emitted.length, 0);
});

test('C2: a notifier cannot be created without somewhere to emit', () => {
    assert.throws(() => createChangeNotifier({}), /emit/);
});

test('C2: the two-argument flush path is safe to call twice', () => {
    const { notifier, emitted } = harness();
    notifier.notify('children');
    assert.ok(notifier.flush());
    assert.equal(notifier.flush(), null, 'a second flush with nothing queued must be a no-op');
    assert.equal(emitted.length, 1);
});

test('C2: request paths map to the data they can touch', () => {
    assert.equal(scopeForPath('/api/children/68f1'), 'children');
    assert.equal(scopeForPath('/api/admin/children/68f1'), 'children');
    assert.equal(scopeForPath('/api/praise'), 'praise');
    assert.equal(scopeForPath('/api/gifts'), 'gifts');
    assert.equal(scopeForPath('/api/found-requests'), 'found-requests');
    assert.equal(scopeForPath('/api/safechild/register'), 'safechildren');
    assert.equal(scopeForPath('/api/admin/safe-children'), 'safechildren');
    assert.equal(scopeForPath('/api/admin/users/1'), 'users');
    assert.equal(scopeForPath('/api/auth/login'), 'users', 'a signup/login changes the user list');
    assert.equal(scopeForPath('/api/admin/ads/9/click'), 'ads');
    assert.equal(scopeForPath('/api/admin/counts'), 'other');
    assert.equal(scopeForPath(''), 'other');
    assert.equal(scopeForPath(undefined), 'other');
});

test('C2: the server never broadcasts an unscoped change event directly', () => {
    const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    const rawEmits = server.match(/io\.emit\('dataChanged'\)/g) || [];
    assert.equal(rawEmits.length, 0, 'every write must go through notifyDataChanged()');
    assert.match(
        server,
        /changeNotifier\.notify\(scope \|\| changeScope\.getStore\(\) \|\| SCOPE_ALL\)/,
        'the notifier must be told which scope changed'
    );
    assert.match(server, /require\('node:async_hooks'\)/, 'the request scope must come from AsyncLocalStorage');
    assert.match(server, /emit: \(payload\) => io\.emit\('dataChanged', payload\)/);

    const notifier = fs.readFileSync(path.join(ROOT, 'functions/changeNotifier.js'), 'utf8');
    assert.match(notifier, /if \(timer && typeof timer\.unref === 'function'\) timer\.unref\(\)/);
});

test('C2: the admin panel stops downloading full lists just to update badges', () => {
    const admin = fs.readFileSync(path.join(ROOT, 'public/admin.html'), 'utf8');
    assert.match(admin, /api\('\/api\/admin\/counts'\)/, 'badges must use the counts endpoint');
    assert.doesNotMatch(admin, /_doSocketRefresh\(\)/i, 'the refresh must receive change scopes');
    assert.match(admin, /_doSocketRefresh\(batch\)/);
    assert.match(admin, /PAGE_SCOPES/, 'the active tab must be matched against the scopes');
});

test('C2: the user panel coalesces refreshes and stops polling hidden tabs', () => {
    const index = fs.readFileSync(path.join(ROOT, 'public/index.html'), 'utf8');
    assert.doesNotMatch(
        index,
        /socket\.on\('dataChanged',\(\)=>socket\.emit\('load'\)\)/,
        'the old one-reload-per-event handler must be gone'
    );
    assert.match(index, /socket\.on\('dataChanged',\(\)=>\{clearTimeout\(liveRefreshTimer\)/);
    assert.match(index, /if\(document\.hidden\|\|liveRefreshBusy\)/, 'hidden tabs and busy refreshes must queue, not storm');
    assert.match(index, /30000\+Math\.floor\(Math\.random\(\)\*20000\)/, 'the background poll must be jittered');
    assert.match(index, /if\(!document\.hidden\)\{socket\.emit\('load'\)/, 'hidden tabs must not poll');
});
