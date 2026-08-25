const crypto = require('crypto');
const { hashPassword, verifyPassword } = require('./passwords');
const getModels = require('./dbModels');

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASS) {
    console.warn("WARNING: Using default admin credentials (admin / admin123). Set ADMIN_USERNAME and ADMIN_PASS in .env to change them.");
}

const adminTokens = new Set();          // token -> (admin)
const userTokens = new Map();           // token -> userId

const safeEqual = (a, b) => {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
};

const loginAdmin = (username, password) => {
    if (safeEqual(username, ADMIN_USERNAME) && safeEqual(password, ADMIN_PASS)) {
        const token = crypto.randomBytes(24).toString('hex');
        adminTokens.add(token);
        return token;
    }
    return null;
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

// Express middleware: requires a valid ADMIN token.
const requireAdmin = (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (token && adminTokens.has(token)) {
        req.token = token;
        return next();
    }
    return res.status(401).json({ success: false, message: "Unauthorized. Please log in as admin." });
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

// Google OAuth: find or create user
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
            // If duplicate contactNumber issue, try creating with a unique placeholder
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

module.exports = { loginAdmin, signupUser, loginUser, findOrCreateGoogleUser, logout, requireAuth, requireAdmin, isValidPhone, sanitize };
