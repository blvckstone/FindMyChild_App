const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { jsArg, escapeHtml } = require('../public/js/fmc-escape');

// Reproduce what the browser does with an HTML attribute value before the JS engine sees it.
const decodeAttribute = (value) => String(value)
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');

// The escaping helper the app used before the fix (still used for HTML text contexts).
const legacyEsc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[ch]));

// Execute an emitted handler string with spies, exactly like a click would.
const runHandler = (decodedSource, fnName = 'openX') => {
    const calls = [];
    const alerts = [];
    // eslint-disable-next-line no-new-func
    new Function(fnName, 'alert', decodedSource)(
        (...args) => calls.push(args),
        (message) => alerts.push(message)
    );
    return { calls, alerts };
};

const PAYLOADS = [
    "O'Brien",
    'back\\slash',
    'line\nbreak',
    "');alert('xss');//",
    '";alert(1);//',
    '</script><script>alert(1)</script>',
    '` + alert(1) + `',
    '${alert(1)}',
    'café — ünïcode ✓'
];

test('A4: the old esc()-only pattern really was exploitable (issue reproduced)', () => {
    const payload = "');alert('xss');//";
    const emittedAsBefore = `openX('${legacyEsc(payload)}')`;
    const { calls, alerts } = runHandler(decodeAttribute(emittedAsBefore));

    assert.deepEqual(alerts, ['xss'], 'the injected code executed — this is the vulnerability being fixed');
    assert.notEqual(calls[0][0], payload, 'the original value was destroyed by the breakout');
});

test('A4: jsArg output cannot break out of the handler for any hostile payload', () => {
    for (const payload of PAYLOADS) {
        const emitted = `openX(${jsArg(payload)})`;
        assert.doesNotMatch(emitted, /['"<>]/, `emitted handler still contains a raw quote or bracket for ${JSON.stringify(payload)}`);

        const { calls, alerts } = runHandler(decodeAttribute(emitted));
        assert.deepEqual(alerts, [], `payload executed code: ${JSON.stringify(payload)}`);
        assert.equal(calls.length, 1, `payload changed the call shape: ${JSON.stringify(payload)}`);
        assert.deepEqual(calls[0], [payload], `payload did not round-trip: ${JSON.stringify(payload)}`);
    }
});

test('A4: jsArg round-trips values embedded in multi-argument handlers', () => {
    const id = '507f1f77bcf86cd799439011';
    const name = "Aamna \"Khan\" O'Brien <script>";
    const emitted = `openSafeChildEdit(${jsArg(id)},${jsArg(name)},9)`;
    const { calls, alerts } = runHandler(decodeAttribute(emitted), 'openSafeChildEdit');

    assert.deepEqual(alerts, []);
    assert.deepEqual(calls[0], [id, name, 9]);
});

test('A4: no user panel handler interpolates a value by hand', () => {
    const page = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
    const handlers = [...page.matchAll(/onclick="[^"]*"/g)].map((match) => match[0]);
    assert.ok(handlers.length > 50, `expected many handlers, found ${handlers.length}`);

    const escaped = handlers.filter((handler) => handler.includes('esc('));
    assert.deepEqual(escaped, [], 'esc() decodes to a raw quote inside the handler — jsArg() is required');

    // The only values allowed to be interpolated without jsArg() are page/carousel counters,
    // which are numbers built by the page itself.
    const raw = handlers.filter((handler) => /'\+|\$\{/.test(handler) && !handler.includes('jsArg('));
    for (const handler of raw) {
        assert.match(
            handler,
            /^onclick="(foundPage=|profPages\.|moveCarousel\()/,
            `a non-numeric value is interpolated into a handler: ${handler}`
        );
    }
    assert.ok(
        handlers.filter((handler) => handler.includes('jsArg(')).length >= 20,
        'the panel is expected to build its handler arguments through jsArg()'
    );
});

test('A6: the same breakout is closed in the admin panel', () => {
    const adminPage = fs.readFileSync(path.join(__dirname, '../public/admin.html'), 'utf8');

    // The panel now depends on the helper, so it must actually load it.
    assert.match(adminPage, /<script src="\/js\/fmc-escape\.js"><\/script>/, 'admin.html must load the escaping helper');

    const handlers = [...adminPage.matchAll(/on(?:click|change|input)="[^"]*"/g)].map((match) => match[0]);
    assert.ok(handlers.length > 50, `expected many handlers, found ${handlers.length}`);

    assert.deepEqual(
        handlers.filter((handler) => handler.includes('esc(')),
        [],
        'esc() decodes to a raw quote inside the handler — jsArg() is required'
    );

    // Only the helper's own placeholder and the two pagers (a function name plus a numeric
    // expression) may be interpolated without jsArg().
    const allowed = /^onclick="(?:\$\{onclick\}|\$\{(?:goFn|loader)\}\(\$\{(?:page|current)[+-]1\}\))"$/;
    for (const handler of handlers.filter((h) => /'\+|\$\{/.test(h) && !h.includes('jsArg('))) {
        assert.match(handler, allowed, `a non-numeric value is interpolated into an admin handler: ${handler}`);
    }

    assert.ok(
        handlers.filter((handler) => handler.includes('jsArg(')).length >= 25,
        'the admin panel is expected to build its handler arguments through jsArg()'
    );
});

test('A6: admin handler values survive miniBtn and hostile slugs', () => {
    // miniBtn embeds the source it is handed straight into the attribute, so the escaping has to
    // happen where the value is placed. This reproduces that path end to end.
    const miniBtn = (source) => `<button onclick="${source}">x</button>`;
    const attrOf = (html) => html.match(/onclick="([^"]*)"/)[1];

    const payload = "');alert('xss');//";
    const { calls, alerts } = runHandler(decodeAttribute(attrOf(miniBtn(`deleteSafeChildAdmin(${jsArg(payload)})`))), 'deleteSafeChildAdmin');
    assert.deepEqual(alerts, [], 'the payload executed');
    assert.deepEqual(calls[0], [payload], 'the value did not round-trip');

    // An admin-editable slug is the one admin value a user can influence indirectly.
    const slug = 'privacy");alert(1);//';
    const emitted = `editLegalPage(&quot;${legacyEsc(slug)}&quot;)`;
    const emittedFixed = `editLegalPage(${jsArg(slug)})`;
    assert.deepEqual(runHandler(decodeAttribute(emitted), 'editLegalPage').alerts, [1], 'the old entity-quoted pattern was exploitable');
    const fixed = runHandler(decodeAttribute(attrOf(miniBtn(emittedFixed))), 'editLegalPage');
    assert.deepEqual(fixed.alerts, []);
    assert.deepEqual(fixed.calls[0], [slug]);
});

test('A4: escapeHtml still escapes for HTML text contexts', () => {
    assert.equal(escapeHtml('<b>&"\'</b>'), '&lt;b&gt;&amp;&quot;&#39;&lt;/b&gt;');
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
});

test('A4: jsArg handles non-string input without throwing', () => {
    assert.equal(decodeAttribute(jsArg(0)), '"0"');
    assert.equal(decodeAttribute(jsArg(null)), '""');
    assert.equal(decodeAttribute(jsArg(undefined)), '""');
    assert.equal(decodeAttribute(jsArg(false)), '"false"');
});
