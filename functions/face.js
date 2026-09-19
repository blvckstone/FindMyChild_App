// Face descriptor helpers shared by the report, admin and SafeChild routes.
// Descriptors are 128-dimensional float arrays produced by face-api.js.

const DESCRIPTOR_LENGTH = 128;

/**
 * Parse a face descriptor from a JSON string, a comma-separated string, or an array.
 * Returns a clean number[] of exactly DESCRIPTOR_LENGTH finite values, or null.
 */
const parseFaceDescriptor = (raw) => {
    if (raw === undefined || raw === null || raw === '') return null;
    let value = raw;
    if (typeof value === 'string') {
        try {
            value = JSON.parse(value);
        } catch (error) {
            value = value.split(',').map(Number);
        }
    }
    if (!Array.isArray(value) || value.length !== DESCRIPTOR_LENGTH) return null;
    const numbers = value.map(Number);
    if (numbers.some((n) => !Number.isFinite(n))) return null;
    return numbers;
};

// Euclidean distance between two descriptors of equal length.
const faceDistance = (a, b) => {
    let sumSquared = 0;
    for (let i = 0; i < a.length; i++) {
        const diff = a[i] - b[i];
        sumSquared += diff * diff;
    }
    return Math.sqrt(sumSquared);
};

module.exports = { parseFaceDescriptor, faceDistance, DESCRIPTOR_LENGTH };
