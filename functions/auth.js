const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { hashPassword, verifyPassword } = require('./passwords');
const getModels = require('./dbModels');
const {
    createSession,
    lookupSession,
    deleteSession,
    deleteUserSessions,
    deleteAdminSessions
} = require('./sessions');
const { USER_COOKIE, ADMIN_COOKIE, readAuth } = require('./cookies');
const { isCrossSiteWrite } = require('./csrf');

// Legacy admin login (username/password) — MUST be set in environment variables
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASS = process.env.ADMIN_PASS || '';

// Legacy login is only usable when BOTH credentials are explicitly configured.
// Without this guard an unset ADMIN_PASS compares equal to the literal string "undefined,"
// which would let anyone sign in as super admin (safeEqual does String(undefined)).
const LEGACY_ADMIN_ENABLED = ADMIN_USERNAME.length > 0 && ADMIN_PASS.length > 0;

if (!LEGACY_ADMIN_ENABLED) {
    console.error('[SECURITY] CRITICAL: ADMIN_USERNAME and/or ADMIN_PASS not set in environment. Legacy admin login will be DISABLED.');
}

// Super admin email - cannot be removed or demoted
const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL || 'iblvckstone@gmail.com';

// Owner id for the env-configured super admin, who has no AdminUser row.
const LEGACY_ADMIN_ID = 'super_admin_legacy';

// JWT config for admin tokens — MUST be set in environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '7d';

if (!JWT_SECRET) {
    console.error('[SECURITY] CRITICAL: JWT_SECRET not set in environment. Auth tokens will fail.');
}

// Admin tokens used to be tracked in a module-level Map whose only purpose was to be *bypassed*:
// requireAdmin fell back to stateless JWT verification, so the Map was per-process and
// revocation never actually worked — an admin removed from the whitelist, disabled, or demoted
// kept full access until their 7-day token expired, and logging out only deleted the local
// copy. Admin tokens are now sessions in shared storage, exactly like user tokens, and the
// stateless fallback is gone.

// Record an admin session so the token can be revoked later. `adminId` is the AdminUser id, or
// the literal 'super_admin_legacy' for the env-configured super admin.
const registerAdminToken = async (token, adminId) => {
    const { Session } = await getModels();
    await createSession(Session, { token, userId: String(adminId || 'unknown'), kind: 'admin' });
    return token;
};

// Create admin JWT token
function signAdminToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// Verify admin JWT token
function verifyAdminToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return null;
    }
}

const safeEqual = (a, b) => {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
};

// Legacy admin login (username/password)
const loginAdmin = async (username, password) => {
    if (!LEGACY_ADMIN_ENABLED) return null;
    if (!username || !password) return null;
    if (safeEqual(username, ADMIN_USERNAME) && safeEqual(password, ADMIN_PASS)) {
        const adminPayload = {
            id: LEGACY_ADMIN_ID,
            email: SUPER_ADMIN_EMAIL,
            role: 'super_admin',
            permissions: { all: true }
        };
        const token = signAdminToken(adminPayload);
        await registerAdminToken(token, LEGACY_ADMIN_ID);
        console.log('[AUTH] Legacy admin login succeeded for', adminPayload.email);
        return { token, role: 'super_admin', email: SUPER_ADMIN_EMAIL, name: 'Admin' };
    }
    return null;
};

// Admin Google login - check whitelist
const loginAdminGoogle = async (profile) => {
    const { AdminUser } = await getModels();
    const email = (profile.emails && profile.emails[0] && profile.emails[0].value || '').toLowerCase();
    const name = profile.displayName || '';
    const photo = (profile.photos && profile.photos[0] && profile.photos[0].value) || '';
    const googleId = profile.id;

    // Super admin always gets access
    if (email === SUPER_ADMIN_EMAIL) {
        // Ensure super admin exists in whitelist
        let admin = await AdminUser.findOne({ email: SUPER_ADMIN_EMAIL });
        if (!admin) {
            admin = await AdminUser.create({
                email: SUPER_ADMIN_EMAIL,
                role: 'super_admin',
                name: name || 'Super Admin',
                photo,
                googleId,
                active: true,
                canManageAdmins: true,
                canManageChildren: true,
                canManageUsers: true,
                canManageAds: true,
                canManageAnalytics: true,
                canManageDonations: true
            });
        } else if (!admin.googleId) {
            admin.googleId = googleId;
            if (photo) admin.photo = photo;
            if (name) admin.name = name;
            await admin.save();
        }
        const adminPayload = { id: admin._id, email, role: 'super_admin', permissions: { all: true } };
        const token = signAdminToken(adminPayload);
        await registerAdminToken(token, admin._id);
        return { token, admin: { id: admin._id, email, name: admin.name, photo: admin.photo, role: 'super_admin', permissions: { all: true } } };
    }

    // Check whitelist for other emails
    let admin = await AdminUser.findOne({ email });
    if (!admin) {
        return null; // Not whitelisted
    }
    // Reject inactive admins immediately
    if (admin.active === false) {
        return null; // Account disabled
    }

    // Update Google ID if not set
    if (!admin.googleId) {
        admin.googleId = googleId;
        if (photo) admin.photo = photo;
        if (name) admin.name = name;
        await admin.save();
    }

    // Build normalized permissions for JWT (use short keys: children, users, ads, etc.)
    const permissions = {
        all: false,
        children: !!admin.canManageChildren,
        users: !!admin.canManageUsers,
        ads: !!admin.canManageAds,
        analytics: !!admin.canManageAnalytics,
        donations: !!admin.canManageDonations,
        admins: !!admin.canManageAdmins
    };

    const adminPayload = { id: admin._id, email, role: admin.role, permissions };
    const token = signAdminToken(adminPayload);
    await registerAdminToken(token, admin._id);

    return { token, admin: { id: admin._id, email, name: admin.name, photo: admin.photo, role: admin.role, permissions } };
};

const signupUser = async ({ fullName, contactNumber, emailId, password } = {}) => {
    const { User } = await getModels();
    if (!fullName || !String(fullName).trim()) return { error: "Full name is required." };
    if (!contactNumber || !String(contactNumber).trim()) return { error: "Contact number is required." };
    if (!isValidPhone(contactNumber)) return { error: "Please enter a valid phone number." };
    if (!password || String(password).length < 6) return { error: "Password must be at least 6 characters." };

    const rawContact = String(contactNumber).trim();
    const normalizedPhone = normalizePhone(rawContact);
    const phoneVariants = [...new Set([rawContact, normalizedPhone, '+91' + normalizedPhone, '91' + normalizedPhone, '0' + normalizedPhone].filter(Boolean))];
    const email = emailId ? String(emailId).trim().toLowerCase() : '';
    const duplicateChecks = [{ userContactNumber: { $in: phoneVariants } }];
    if (email) duplicateChecks.push({ emailId: email });
    const exists = await User.findOne({ $or: duplicateChecks });
    if (exists) return { error: "An account with this contact number or email already exists." };

    const user = await User.create({
        userFullName: String(fullName).trim(),
        userContactNumber: normalizedPhone || rawContact,
        emailId: email,
        password: hashPassword(password),
        createdAt: new Date().toISOString()
    });
    const token = crypto.randomBytes(24).toString('hex');
    await registerUserToken(token, user._id);
    return { user, token };
};

const loginUser = async (identifier, password) => {
    const { User } = await getModels();
    if (!identifier || !password) return { error: "Contact number / email and password are required." };
    const raw = String(identifier).trim();
    const isEmail = raw.includes('@');
    let query;
    if (isEmail) {
        query = { emailId: raw.toLowerCase() };
    } else {
        const cleaned = normalizePhone(raw);
        const phoneVariants = [...new Set([raw, cleaned, '+91' + cleaned, '91' + cleaned, '0' + cleaned].filter(Boolean))];
        query = { $or: [{ userContactNumber: { $in: phoneVariants } }, { emailId: raw.toLowerCase() }] };
    }
    const user = await User.findOne(query);
    if (!user || !verifyPassword(password, user.password)) return { error: "Invalid credentials." };
    if (user.blocked) return { error: "This account has been blocked. Please contact support." };
    const token = crypto.randomBytes(24).toString('hex');
    await registerUserToken(token, user._id);
    return { user, token };
};

const logout = async (token) => {
    if (!token) return 0;
    try {
        const { Session } = await getModels();
        return await deleteSession(Session, token);
    } catch (error) {
        // Logging out must never fail loudly; the token still expires on its own.
        console.error('[auth] logout could not clear the session:', error.message);
        return 0;
    }
};

// Record a user session token. Sessions live in shared storage, so every instance sees the
// same login and a revocation applies everywhere (and survives a restart).
const registerUserToken = async (token, userId) => {
    const { Session } = await getModels();
    await createSession(Session, { token, userId: String(userId), kind: 'user' });
    return token;
};

// Drop every live session token belonging to a user (used when an admin blocks/deletes them).
const revokeUserTokens = async (userId) => {
    const { Session } = await getModels();
    return deleteUserSessions(Session, String(userId));
};

// Drop every live admin token belonging to one admin. Called whenever the admin record changes
// in a way that affects authorisation — removing them from the whitelist, disabling them, or
// changing their role/permissions — so the change takes effect on the next request instead of
// when their 7-day token happens to expire.
const revokeAdminTokens = async (adminId) => {
    const { Session } = await getModels();
    return deleteAdminSessions(Session, String(adminId));
};

// Express middleware: requires a valid USER token. Sets req.userId.
//
// The token is accepted from the Authorization header OR from the httpOnly auth cookie, so the
// browser can stay logged in without JavaScript ever handling the token.
const requireAuth = async (req, res, next) => {
    const { token, viaCookie } = readAuth(req, USER_COOKIE);
    if (!token) return res.status(401).json({ success: false, message: "Please log in first." });
    if (viaCookie && isCrossSiteWrite(req)) {
        return res.status(403).json({ success: false, message: "Request blocked: cross-site write." });
    }
    try {
        const { Session } = await getModels();
        const session = await lookupSession(Session, token);
        if (!session) return res.status(401).json({ success: false, message: "Please log in first." });
        req.userId = session.userId;
        req.token = token;
        return next();
    } catch (error) {
        // Fail closed: an unreachable session store must never mean "authenticated".
        console.error('[auth] session lookup failed:', error.message);
        return res.status(401).json({ success: false, message: "Please log in first." });
    }
};

// Express middleware: requires a valid ADMIN token with a live session. Sets req.adminInfo.
//
// The signature check stays (it rejects garbage cheaply and pins the payload), but a session row
// must also exist: that is what makes logout, removal and demotion take effect immediately.
// There is deliberately no stateless fallback — that was the bug.
const requireAdmin = async (req, res, next) => {
    const { token, viaCookie } = readAuth(req, ADMIN_COOKIE);
    if (!token) {
        return res.status(401).json({ success: false, message: "Unauthorized. Please log in as admin." });
    }
    if (viaCookie && isCrossSiteWrite(req)) {
        return res.status(403).json({ success: false, message: "Request blocked: cross-site write." });
    }
    const decoded = verifyAdminToken(token);
    if (!decoded || !decoded.email) {
        return res.status(401).json({ success: false, message: "Unauthorized. Please log in as admin." });
    }
    try {
        const { Session } = await getModels();
        const session = await lookupSession(Session, token);
        if (!session || session.kind !== 'admin') {
            return res.status(401).json({ success: false, message: "Session expired. Please log in again." });
        }
        req.token = token;
        req.adminInfo = {
            id: decoded.id || null,
            email: decoded.email,
            role: decoded.role,
            permissions: decoded.permissions
        };
        return next();
    } catch (error) {
        // Fail closed: an unreachable session store must never mean "authenticated".
        console.error('[auth] admin session lookup failed:', error.message);
        return res.status(401).json({ success: false, message: "Unauthorized. Please log in as admin." });
    }
};

// Middleware: requires super_admin role
const requireSuperAdmin = (req, res, next) => {
    if (req.adminInfo && req.adminInfo.role === 'super_admin') {
        return next();
    }
    return res.status(403).json({ success: false, message: "Super admin access required." });
};

// Check specific permission (perm key: 'children', 'users', 'ads', 'analytics', 'donations', 'admins')
const hasPermission = (req, perm) => {
    if (!req.adminInfo) return false;
    // Super admin has all permissions
    if (req.adminInfo.role === 'super_admin') return true;
    if (req.adminInfo.permissions && req.adminInfo.permissions.all) return true;
    if (req.adminInfo.permissions && req.adminInfo.permissions[perm]) return true;
    return false;
};

// Normalize common Indian phone formats while preserving other international numbers.
const normalizePhone = (phone) => {
    if (!phone) return '';
    let cleaned = String(phone).trim().replace(/[\s\-().]/g, '');
    if (cleaned.startsWith('+91') && cleaned.length === 13) {
        cleaned = cleaned.slice(3);
    } else if (cleaned.startsWith('91') && cleaned.length === 12 && /^[6-9]/.test(cleaned.slice(2))) {
        cleaned = cleaned.slice(2);
    } else if (cleaned.startsWith('0') && cleaned.length === 11) {
        cleaned = cleaned.slice(1);
    }
    return cleaned;
};

const isValidPhone = (phone) => {
    if (!phone) return false;
    const cleaned = normalizePhone(phone);
    if (/^[6-9]\d{9}$/.test(cleaned)) return true;
    const intl = String(phone).trim().replace(/[\s\-()]/g, '');
    return /^\+?[1-9]\d{6,14}$/.test(intl);
};

const sanitize = (str) => {
    if (!str) return '';
    return String(str).trim().replace(/<[^>]*>/g, '').slice(0, 500);
};

// Google OAuth: find or create user (for regular users)
const findOrCreateGoogleUser = async (profile) => {
    const { User } = await getModels();
    const googleId = profile.id;
    const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || '';
    const name = profile.displayName || 'Google User';
    const photo = (profile.photos && profile.photos[0] && profile.photos[0].value) || '';

    let user = await User.findOne({ googleId: googleId });
    if (!user && email) {
        user = await User.findOne({ emailId: email.toLowerCase() });
        if (user) {
            user.googleId = googleId;
            if (photo) user.photo = photo;
            await user.save();
        }
    }
    if (!user) {
        try {
            user = await User.create({
                userFullName: name,
                emailId: email.toLowerCase(),
                googleId: googleId,
                photo: photo,
                verified: true,
                createdAt: new Date().toISOString()
            });
        } catch (createErr) {
            if (createErr.code === 11000) {
                user = await User.create({
                    userFullName: name,
                    userContactNumber: 'google_' + googleId,
                    emailId: email.toLowerCase(),
                    googleId: googleId,
                    photo: photo,
                    verified: true,
                    createdAt: new Date().toISOString()
                });
            } else {
                throw createErr;
            }
        }
    }
    const token = crypto.randomBytes(24).toString('hex');
    await registerUserToken(token, user._id);
    return { user: { _id: user._id, userFullName: user.userFullName, emailId: user.emailId, photo: user.photo }, token };
};

module.exports = {
    loginAdmin, loginAdminGoogle, signupUser, loginUser, findOrCreateGoogleUser,
    logout, registerUserToken, registerAdminToken, revokeUserTokens, revokeAdminTokens,
    requireAuth, requireAdmin, requireSuperAdmin, hasPermission,
    signAdminToken, normalizePhone, isValidPhone, sanitize, SUPER_ADMIN_EMAIL, LEGACY_ADMIN_ID
};
