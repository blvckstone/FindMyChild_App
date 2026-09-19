// User-supplied search text -> a safe Mongo regex.
//
// Escaping is not optional: an unescaped pattern is both a runaway query (ReDoS) and a way to
// turn a plain search box into a full-collection scan. Every search filter in the app builds
// its regex through here so there is exactly one definition of "literal text".

const MAX_SEARCH_LENGTH = 60;

const escapeRegex = (value) => String(value ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** A case-insensitive literal-match regex, or null when there is nothing to search for. */
const searchRegex = (value, maxLength = MAX_SEARCH_LENGTH) => {
    const text = String(value ?? '').trim().slice(0, maxLength);
    if (!text) return null;
    return { $regex: escapeRegex(text), $options: 'i' };
};

module.exports = { escapeRegex, searchRegex, MAX_SEARCH_LENGTH };
