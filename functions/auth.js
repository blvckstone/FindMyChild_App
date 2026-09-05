const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { hashPassword, verifyPassword } = require('./passwords');
const getModels = require('./dbModels');

// Legacy admin login (username/password) — MUST be set in environment variables
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASS = process.env.ADMIN_PASS;

if (!ADMIN_USERNAME || !ADMIN_PASS) {
    console.error('[SECURITY] CRITICAL: ADMIN_USERNAME and/or ADMIN_PASS not set in environment. Legacy admin login will be DISABLED.');
}

// Super admin email - cannot be removed or demoted
const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL || 'iblvckstone@gmail.com';

// JWT config for admin tokens — MUST be set in environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '7d';

if (!JWT_SECRET) {
    console.error('[SECURITY] CRITICAL: JWT_SECRET not set in environment. Auth tokens will fail.');
}

// Admin tokens: token -> { email, role, permissions } (kept as cache, but JWT is primary)
const adminTokens = new Map();
const userTokens = new Map();

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
const loginAdmin = (username, password) => {
    if (safeEqual(username, ADMIN_USERNAME) && safeEqual(password, ADMIN_PASS)) {
        const adminPayload = {
            id: 'super_admin_legacy',
            email: SUPER_ADMIN_EMAIL,
            role: 'super_admin',
            permissions: { all: true }
        };
        const token = signAdminToken(adminPayload);
        // Also cache in Map for backward compat
        adminTokens.set(token, adminPayload);
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
        adminTokens.set(token, adminPayload);
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
    adminTokens.set(token, adminPayload);

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
    userTokens.set(token, String(user._id));
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
    const token = crypto.randomBytes(24).toString('hex');
    userTokens.set(token, String(user._id));
    return { user, token };
};

const logout = (token) => {
    adminTokens.delete(token);
    userTokens.delete(token);
};

// Express middleware: requires a valid USER token. Sets req.userId.
const requireAuth = (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const userId = userTokens.get(token);
    if (userId) {
        req.userId = userId;
        req.token = token;
        return next();
    }
    return res.status(401).json({ success: false, message: "Please log in first." });
};

// Express middleware: requires a valid ADMIN token. Sets req.adminInfo.
const requireAdmin = (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!token) {
        return res.status(401).json({ success: false, message: "Unauthorized. Please log in as admin." });
    }
    // Try in-memory cache first (fast path)
    let adminInfo = adminTokens.get(token);
    if (!adminInfo) {
        // Fall back to JWT verification (survives server restarts)
        const decoded = verifyAdminToken(token);
        if (decoded && decoded.email) {
            adminInfo = {
                id: decoded.id || null,
                email: decoded.email,
                role: decoded.role,
                permissions: decoded.permissions
            };
            // Re-cache for future requests
            adminTokens.set(token, adminInfo);
        } else {
            return res.status(401).json({ success: false, message: "Unauthorized. Please log in as admin." });
        }
    }
    if (adminInfo) {
        req.token = token;
        req.adminInfo = adminInfo;
        return next();
    }
    return res.status(401).json({ success: false, message: "Unauthorized. Please log in as admin." });
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
    userTokens.set(token, String(user._id));
    return { user: { _id: user._id, userFullName: user.userFullName, emailId: user.emailId, photo: user.photo }, token };
};

module.exports = {
    loginAdmin, loginAdminGoogle, signupUser, loginUser, findOrCreateGoogleUser,
    logout, requireAuth, requireAdmin, requireSuperAdmin, hasPermission,
    normalizePhone, isValidPhone, sanitize, SUPER_ADMIN_EMAIL
};
