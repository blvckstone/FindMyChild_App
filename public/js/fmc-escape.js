/* Shared escaping helper for values embedded in HTML attributes and inline JS handlers. */
(function (global) {
    'use strict';

    // Escape a value for HTML text or attribute contexts.
    const escapeHtml = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[ch]));

    /**
     * Build a JavaScript string literal that is safe to place inside an HTML attribute,
     * e.g. onclick="openX(<jsArg(name)>)".
     *
     * The browser decodes HTML entities BEFORE the JS engine parses the handler, so any
     * quote that survives as a raw character can break out of the string. Encoding the
     * value as JSON first (which escapes backslashes and control characters) and then
     * HTML-escaping the whole literal keeps it inert: a payload like `');alert(1)//`
     * decodes back to a single quoted string that still holds the original text.
     */
    const jsArg = (value) => escapeHtml(JSON.stringify(String(value == null ? '' : value)));

    const api = { escapeHtml, jsArg };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (global) global.jsArg = jsArg;
})(typeof window !== 'undefined' ? window : null);
