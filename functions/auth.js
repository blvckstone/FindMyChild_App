const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { hashPassword, verifyPassword } = require('./passwords');
const getModels = require('./dbModels');

// Legacy admin login (username/password)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASS) {
    console.warn("WARNING: Using default admin credentials (admin / admin123). Set ADMIN_USERNAME and ADMIN_PASS in .env to change them.");
}

// Super admin email - cannot be removed or demoted
const SUPER_ADMIN_EMAIL = 'iblvckstone@gmail.com';

// JWT config for admin tokens (persistent - survives server restarts)
const JWT_SECRET = process.env.JWT_SECRET || 'findmychild_jwt_secret_k4x9m2';
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '7d';

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
        const adminPayload = { email, role: 'super_admin', permissions: { all: true } };
        const token = signAdminToken(adminPayload);
        adminTokens.set(token, adminPayload);
        return { token, admin: { email, name: admin.name, photo: admin.photo, role: 'super_admin', permissions: { all: true } } };
    }

    // Check whitelist for other emails
    let admin = await AdminUser.findOne({ email, active: true });
    if (!admin) {
        return null; // Not whitelisted
    }

    // Update Google ID if not set
    if (!admin.googleId) {
        admin.googleId = googleId;
        if (photo) admin.photo = photo;
        if (name) admin.name = name;
        await admin.save();
    }

    const permissions = {
        canManageChildren: admin.canManageChildren,
        canManageUsers: admin.canManageUsers,
        canManageAds: admin.canManageAds,
        canManageAnalytics: admin.canManageAnalytics,
        canManageDonations: admin.canManageDonations,
        canManageAdmins: admin.canManageAdmins
    };

    const adminPayload = { email, role: admin.role, permissions };
    const token = signAdminToken(adminPayload);
    adminTokens.set(token, adminPayload);

    return { token, admin: { email, name: admin.name, photo: admin.photo, role: admin.role, permissions } };
};

const signupUser = async ({ fullName, contactNumber, emailId, password } = {}) => {
    const { User } = await getModels();
    if (!fullName || !String(fullName).trim()) return { error: "Full name is required." };
    if (!contactNumber || !String(contactNumber).trim()) return { error: "Contact number is required." };
    if (!password || String(password).length < 6) return { error: "Password must be at least 6 characters." };

    const contact = String(contactNumber).trim();
    const exists = await User.findOne({ userContactNumber: contact });
    if (exists) return { error: "An account with this contact number already exists." };

    const user = await User.create({
        userFullName: String(fullName).trim(),
        userContactNumber: contact,
        emailId: emailId ? String(emailId).trim() : '',
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
    const user = await User.findOne({
        $or: [{ userContactNumber: String(identifier).trim() }, { emailId: String(identifier).trim() }]
    });
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
                email: decoded.email,
                role: decoded.role,
                permissions: decoded.permissions
            };
            // Re-cache for future requests
            adminTokens.set(token, adminInfo);
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

// Check specific permission
const hasPermission = (req, perm) => {
    if (!req.adminInfo) return false;
    if (req.adminInfo.permissions && req.adminInfo.permissions.all) return true;
    if (req.adminInfo.permissions && req.adminInfo.permissions[perm]) return true;
    return false;
};

// Phone validation (Indian format)
const isValidPhone = (phone) => {
    const cleaned = String(phone).replace(/[\s\-()]/g, '');
    return /^(\+91|91|0)?[6-9]\d{9}$/.test(cleaned);
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
    isValidPhone, sanitize, SUPER_ADMIN_EMAIL
};
