// Public child fields safe for anonymous clients (Socket.io + REST)
// NO parent phone, NO finder contact, NO faceDescriptor, NO internal IDs
const PUBLIC_CHILD_FIELDS = '_id fullName age gender image found foundLocation finderName foundDate missingDate missingTime missingLocation state info disability disabilityInfo ngoContacts createdAt';

// Authenticated user sees additional fields (contact number for their own reports, etc.)
const AUTHENTICATED_CHILD_FIELDS = PUBLIC_CHILD_FIELDS + ' contactNumber contactNumberConsent contactNumberConsentDate';

// Admin sees everything (for management)
const ADMIN_CHILD_FIELDS = '-faceDescriptor'; // Exclude only biometric data

// NGO Contact public fields
const NGO_CONTACT_FIELDS = '_id displayName organization phone whatsapp label priority active description';

// NGO Contact admin fields (everything)
const NGO_ADMIN_FIELDS = '';

module.exports = { PUBLIC_CHILD_FIELDS, AUTHENTICATED_CHILD_FIELDS, ADMIN_CHILD_FIELDS, NGO_CONTACT_FIELDS, NGO_ADMIN_FIELDS };
