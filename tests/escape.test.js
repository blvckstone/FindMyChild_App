const test = require('node:test');
const assert = require('node:assert/strict');
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
