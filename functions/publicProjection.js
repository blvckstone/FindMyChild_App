// Public child fields safe for anonymous clients via Socket.io
// Excludes biometric data, internal user references, and private fields
const PUBLIC_CHILD_FIELDS = '_id fullName age gender address image found foundLocation finderName finderContact foundDate missingDate missingTime missingLocation state info disability disabilityInfo contactNumber createdAt';

module.exports = { PUBLIC_CHILD_FIELDS };
