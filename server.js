const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const { Server } = require('socket.io');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// ── Startup Security Audit ──────────────────────────────────────────────────────
const criticalEnvVars = ['JWT_SECRET', 'DB_ATLAS', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'];
const missingVars = criticalEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
    console.error(`[SECURITY] CRITICAL: Missing environment variables: ${missingVars.join(', ')}`);
    console.error('[SECURITY] The application may not function correctly. Set these in your .env file or hosting dashboard.');
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASS) {
    console.error('[SECURITY] WARNING: ADMIN_USERNAME / ADMIN_PASS not set. Legacy admin login disabled.');
}
console.log('[STARTUP] Environment audit complete.');
// ───────────────────────────────────────────────────────────────────────────────

const app = express();
const server = http.createServer(app);

//-----------------------------------------------Middleware-------------------------------------------------------------------->
app.set('trust proxy', 1); // Trust Northflank proxy - fixes http/https protocol detection
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('admin.html')) {
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
        }
        if (filePath.endsWith('.html')) {
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
        }
    }
}));

// Session for Passport
const SESSION_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
    console.error('[SECURITY] CRITICAL: No JWT_SECRET or SESSION_SECRET set. Session security is disabled.');
}
app.use(require('express-session')({ secret: SESSION_SECRET || 'insecure-fallback-do-not-deploy', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Rate limiting
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { success: false, message: 'Too many attempts. Try again in 15 minutes.' } });

//-----------------------------------------------Functions Module--------------------------------------------------------------->
const fmcConnectMongoDB = require('./functions/fmcDB/fmcMongoDB');
const getModels = require('./functions/dbModels');
const { loginAdmin, loginAdminGoogle, signupUser, loginUser, findOrCreateGoogleUser, logout, requireAuth, requireAdmin, requireSuperAdmin, hasPermission, isValidPhone, sanitize, SUPER_ADMIN_EMAIL } = require('./functions/auth');
const { sendOTP, verifyOTP, sendWelcomeEmail } = require('./functions/email');
// const userConnectMongoDB = require('./functions/userDB/userMongoDB');
const getAllData = require('./functions/getAllData/getAllData.js');
const getByDateData = require('./functions/getByDateData/getByDateData.js');
const getByNameData = require('./functions/getByNameData/getByNameData.js');
const getByRangeData = require('./functions/getByRangeData/getByRangeData.js');
const getByAddressData = require('./functions/getByAddressData/getByAddressData.js');
const getBySearchData = require('./functions/getBySearchData/getBySearchData.js');
const getMessages = require('./functions/getMessages/getMessages.js');

// ---- Server-side cache for instant responses ----
const dataCache = { data: null, ts: 0, messages: null, mts: 0, ads: null, ats: 0 };
const CACHE_TTL = 30000; // 30 seconds
function getCached(key) { return dataCache[key] && (Date.now() - dataCache[key + 'Ts'] < CACHE_TTL) ? dataCache[key] : null; }
function setCache(key, val) { dataCache[key] = val; dataCache[key + 'Ts'] = Date.now(); }
function clearDataCache() { dataCache.data = null; dataCache.messages = null; dataCache.ads = null; }

//-----------------------------------------------Google OAuth (optional)---------------------------------------------------------->
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
if (googleClientId && googleClientSecret) {
    passport.use(new GoogleStrategy({
        clientID: googleClientId,
        clientSecret: googleClientSecret,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || 'https://findmychild.dpdns.org/api/auth/google/callback',
        scope: ['profile', 'email'],
        passReqToCallback: true
    }, async (req, accessToken, refreshToken, profile, done) => {
        try {
            // Detect admin vs user by checking the callback URL path
            const isAdmin = req.originalUrl && req.originalUrl.startsWith('/api/admin/auth/google/callback');
            console.log('[GOOGLE-STRATEGY] Callback URL:', req.originalUrl, '| isAdmin:', isAdmin);
            if (isAdmin) {
                const result = await loginAdminGoogle(profile);
                return done(null, result);
            }
            const result = await findOrCreateGoogleUser(profile);
            return done(null, result);
        } catch (error) { return done(error, null); }
    }));
    console.log('Google OAuth configured');
} else {
    console.warn('Google OAuth disabled — env vars not set');
}
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Admin Google login handled via state parameter in strategy callback
//-----------------------------------------------Socket.io---------------------------------------------------------------------->
const io = new Server(server, { cors: { origin: "*" } });

//-----------------------------------------------Cloudinary image storage------------------------------------------------------>
const { uploadImage, deleteImage, replaceImage } = require('./functions/cloudinary');
//------------------------------------------------------------------------------------------------------------------------------>

//-----------------------------------------------Routes------------------------------------------------------------------------->
// uploadsDir removed — images now stored on Cloudinary

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/health', async (req, res) => {
    const dbStatus = await fmcConnectMongoDB();
    const dbOk = dbStatus && dbStatus.success;
    res.json({
        status: 'ok',
        database: dbOk ? 'connected' : 'error',
        mode: dbOk ? 'live' : 'demo',
        port: process.env.PORT || 9002,
        time: new Date().toISOString()
    });
});

// Save an uploaded photo to Cloudinary and return its URL.
const ALLOWED_IMG = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const saveImage = async (file) => {
    if (!file) return '';
    if (!ALLOWED_IMG.includes(file.mimetype)) {
        const err = new Error("Only JPG, PNG, WEBP or GIF images are allowed.");
        err.status = 400;
        throw err;
    }
    if (file.size > 5 * 1024 * 1024) {
        const err = new Error("Image must be smaller than 5 MB.");
        err.status = 400;
        throw err;
    }
    const url = await uploadImage(file);
    if (!url) {
        const err = new Error("Image upload to Cloudinary failed.");
        err.status = 500;
        throw err;
    }
    return url;
};

// Child fields accepted from forms (status/found handled separately).
const childFields = [
    'fullName', 'address', 'contactNumber', 'uploadedBy', 'state', 'found',
    'image', 'missingDate', 'missingTime', 'gender', 'age', 'info',
    'disability', 'missingLocation', 'missingDateTime', 'foundLocation', 'disabilityInfo', 'status',
    'faceDescriptor', 'finderName', 'finderContact', 'finderUserId', 'foundDate'
];

const pickChildFields = (body) => {
    const data = {};
    for (const f of childFields) {
        if (body[f] !== undefined) data[f] = body[f];
    }
    return data;
};

// ---- Submit a missing child report (goes to the pending queue) — login required ----
app.post('/api/children', requireAuth, async (req, res) => {
    try {
        const data = pickChildFields(req.body);
        if (!data.fullName || !String(data.fullName).trim()) {
            return res.status(400).json({ success: false, message: "Child's full name is required." });
        }
        if (!data.contactNumber || !String(data.contactNumber).trim()) {
            return res.status(400).json({ success: false, message: "A contact number is required so people can reach the family." });
        }
        data.fullName = String(data.fullName).trim();
        data.contactNumber = String(data.contactNumber).trim();
        if (data.age !== undefined && data.age !== '') {
            data.age = Number(data.age);
            if (data.age < 0) {
                return res.status(400).json({ success: false, message: "Age cannot be negative." });
            }
        }

        // Parse face descriptor if provided (from AI face detection)
        if (data.faceDescriptor) {
            const parsed = parseFaceDescriptor(data.faceDescriptor);
            data.faceDescriptor = parsed || [];
        } else {
            data.faceDescriptor = [];
        }

        const imagePath = await saveImage(req.files && req.files.image);
        if (imagePath) data.image = imagePath;

        data.status = 'pending';
        data.found = false;
        data.uploadedBy = data.uploadedBy || 'User';
        data.userId = req.userId;

        const db = await fmcConnectMongoDB();
        if (!db.success) return res.status(500).json({ success: false, message: "Database unavailable." });
        const Child = db.data;
        const child = await Child.create(data);
        io.emit('dataChanged'); clearDataCache();
        dataCache.data = null; dataCache.messages = null;
        res.status(201).json({ success: true, message: "Report submitted! It will be published after admin approval.", data: child });
    } catch (error) {
        console.error("POST /api/children error:", error.message);
        res.status(error.status || 500).json({ success: false, message: error.message || "Something went wrong." });
    }
});

// ---- User auth: signup / login / logout / me ----
app.post('/api/auth/signup', authLimiter, async (req, res) => {
    try {
        const r = await signupUser(req.body);
        if (r.error) return res.status(400).json({ success: false, message: r.error });
        res.status(201).json({ success: true, message: "Account created! Welcome to Find My Child.", token: r.token, user: r.user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const r = await loginUser(req.body.identifier, req.body.password);
        if (r.error) return res.status(401).json({ success: false, message: r.error });
        res.json({ success: true, message: "Welcome back!", token: r.token, user: r.user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/auth/logout', (req, res) => {
    const header = req.headers.authorization || '';
    logout(header.slice(7));
    res.json({ success: true });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
    try {
        const { User } = await getModels();
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ success: false, message: "User not found." });
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/auth/me', requireAuth, async (req, res) => {
    try {
        const { userFullName, userContactNumber } = req.body;
        const { User } = await getModels();
        const update = {};
        if (userFullName !== undefined) update.userFullName = String(userFullName).trim().slice(0, 100);
        if (userContactNumber !== undefined) update.userContactNumber = String(userContactNumber).trim().slice(0, 20);
        if (Object.keys(update).length === 0) return res.status(400).json({ success: false, message: 'No fields to update.' });
        const user = await User.findByIdAndUpdate(req.userId, { $set: update }, { new: true });
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        res.json({ success: true, message: 'Profile updated successfully.', user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/auth/activity', requireAuth, async (req, res) => {
    try {
        const { Child, FoundRequest, Praise, Gift, PreRegisteredChild } = await getModels();
        const userId = req.userId;
        const [children, foundReqs, praises, gifts, safeChildren] = await Promise.all([
            Child.find({ userId: userId }).sort({ createdAt: -1 }).lean().catch(() => []),
            FoundRequest.find({ userId }).sort({ createdAt: -1 }).populate('childId', 'fullName childName').lean().catch(() => []),
            Praise.find({ userId }).sort({ createdAt: -1 }).populate('childId', 'fullName childName').lean().catch(() => []),
            Gift.find({ userId }).sort({ createdAt: -1 }).populate('childId', 'fullName childName').lean().catch(() => []),
            PreRegisteredChild.find({ parentId: userId }).sort({ createdAt: -1 }).lean().catch(() => [])
        ]);
        res.json({ success: true, data: { children, foundReqs, praises, gifts, safeChildren } });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Google OAuth ----
if (googleClientId && googleClientSecret) {
    app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
    app.get('/api/auth/google/callback', (req, res, next) => {
        console.log('[USER-GOOGLE-CB] Callback hit, originalUrl:', req.originalUrl);
        passport.authenticate('google', { failureRedirect: '/?error=google_failed', session: false }, (err, user, info) => {
            if (err || !user) {
                console.error('[USER-GOOGLE-CB] Error:', err ? err.message : 'No user');
                return res.redirect('/?error=' + encodeURIComponent(err ? err.message : 'google_failed'));
            }
            res.redirect('/?google_token=' + user.token);
        })(req, res, next);
    });
}

// ---- OTP (email verification via Resend) ----
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ success: false, message: "Valid email required." });
        }
        const r = await sendOTP(email.trim().toLowerCase());
        res.json(r.success ? { success: true, message: "OTP sent to your email." } : { success: false, message: r.error });
    } catch (error) {
        res.status(500).json({ success: false, message: "Failed to send OTP." });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ success: false, message: "Email and code required." });
        const r = verifyOTP(email.trim().toLowerCase(), code);
        if (r.valid) {
            const { User } = await getModels();
            await User.updateOne({ email: email.toLowerCase() }, { $set: { verified: true } });
            res.json({ success: true, message: "Email verified!" });
        } else {
            res.status(400).json({ success: false, message: r.error });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: "Verification failed." });
    }
});

// ---- Public: found requests (user raises a flag that a child has been found) ----
app.post('/api/found-requests', requireAuth, async (req, res) => {
    try {
        const { FoundRequest, Child } = await getModels();
        const child = await Child.findById(req.body.childId);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        if (child.found) return res.status(400).json({ success: false, message: "This child is already marked as found." });
        const dup = await FoundRequest.findOne({ childId: child._id, userId: req.userId, status: 'pending' });
        if (dup) return res.status(400).json({ success: false, message: "You already have a pending found-request for this child." });

        const fr = await FoundRequest.create({
            childId: child._id,
            userId: req.userId,
            finderName: String(req.body.finderName || 'Anonymous').trim().slice(0, 80),
            claimType: req.body.claimType === 'someone' ? 'someone' : 'me',
            contactNumber: req.body.contactNumber ? String(req.body.contactNumber).trim() : '',
            details: req.body.details ? String(req.body.details).trim().slice(0, 500) : ''
        });
        io.emit('dataChanged'); clearDataCache();
        res.status(201).json({ success: true, message: "Found request submitted! Admin will verify and approve it.", data: fr });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/found-requests/me', requireAuth, async (req, res) => {
    try {
        const { FoundRequest, Child } = await getModels();
        const data = await FoundRequest.find({ userId: req.userId }).sort({ createdAt: -1 }).populate('childId', 'fullName childName');
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Public: praise & gifts for people who found children ----
app.get('/api/praise', async (req, res) => {
    try {
        const { Praise, Gift, Child } = await getModels();
        const child = await Child.findById(req.query.childId);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        const [praises, gifts] = await Promise.all([
            Praise.find({ childId: child._id, status: 'approved' }).sort({ createdAt: -1 }).limit(100),
            Gift.find({ childId: child._id, status: 'approved' }).sort({ createdAt: -1 }).limit(100)
        ]);
        res.json({ success: true, data: { child, praises, gifts } });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// NOTE: /api/praise and /api/gifts POST routes are defined later with requireAuth middleware

// ---- Public: donations ----
app.post('/api/donations', async (req, res) => {
    try {
        const { Donation } = await getModels();
        const donorName = req.body.donorName ? String(req.body.donorName).trim() : '';
        const amount = Number(req.body.amount);
        if (!donorName) return res.status(400).json({ success: false, message: "Please enter your name." });
        if (!amount || amount <= 0) return res.status(400).json({ success: false, message: "Please enter a valid amount." });
        const donation = await Donation.create({
            donorName: donorName.slice(0, 60),
            emailId: req.body.emailId ? String(req.body.emailId).trim().slice(0, 80) : '',
            amount,
            message: req.body.message ? String(req.body.message).trim().slice(0, 500) : '',
            utrNumber: req.body.utrNumber ? String(req.body.utrNumber).trim().slice(0, 30) : '',
            paymentMethod: req.body.paymentMethod || 'upi',
            status: 'pending'
        });
        io.emit('dataChanged'); clearDataCache();
        res.status(201).json({ success: true, message: "Thank you for your generous support! ❤️", data: donation });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/donations', async (req, res) => {
    try {
        const { Donation } = await getModels();
        const [data, totalAgg] = await Promise.all([
            Donation.find().sort({ createdAt: -1 }).limit(50),
            Donation.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }])
        ]);
        res.json({ success: true, data, total: (totalAgg[0] && totalAgg[0].total) || 0 });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Public: payment configuration ----
app.get('/api/payment-config', async (req, res) => {
    try {
        const { PaymentSettings } = await getModels();
        const settings = await PaymentSettings.findOne() || await PaymentSettings.create({});
        res.json({
            success: true,
            data: {
                upiId: settings.upiId,
                payeeName: settings.payeeName,
                bankAccountName: settings.bankAccountName,
                bankAccountNumber: settings.bankAccountNumber,
                bankIfscCode: settings.bankIfscCode,
                bankName: settings.bankName,
                adminPhone: settings.adminPhone,
                qrImageUrl: settings.qrImageUrl
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: payment settings ----
app.get('/api/admin/payment-settings', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { PaymentSettings } = await getModels();
        const settings = await PaymentSettings.findOne() || await PaymentSettings.create({});
        res.json({ success: true, data: settings });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/payment-settings', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { PaymentSettings } = await getModels();
        const allowed = ['upiId', 'payeeName', 'bankAccountName', 'bankAccountNumber', 'bankIfscCode', 'bankName', 'adminPhone', 'qrImageUrl'];
        const updates = {};
        allowed.forEach(field => {
            if (req.body[field] !== undefined) updates[field] = String(req.body[field]).trim();
        });
        updates.updatedAt = new Date();
        const settings = await PaymentSettings.findOneAndUpdate({}, { $set: updates }, { new: true, upsert: true });
        res.json({ success: true, message: 'Payment settings saved.', data: settings });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- SafeChild: Pre-Registration & AI Face Matching ----
// Safely parse face descriptor from FormData string, JSON string, or array
function parseFaceDescriptor(raw) {
    let d = raw;
    if (typeof d === 'string') {
        try { d = JSON.parse(d); } catch (e) { d = d.split(',').map(Number); }
    }
    if (!Array.isArray(d) || d.length !== 128 || d.some(isNaN)) return null;
    return d.map(Number);
}

// Public: no auth needed for matching
app.get('/api/safechild/config', async (req, res) => {
    res.json({ success: true, message: 'SafeChild AI is active', version: '1.0' });
});

// Register a child with face descriptor (requires auth)
app.post('/api/safechild/register', requireAuth, async (req, res) => {
    try {
        const { childName, age, gender, address, parentContact, medicalInfo, faceDescriptor, photoUrl } = req.body;
        if (!childName || !String(childName).trim()) {
            return res.status(400).json({ success: false, message: "Child's name is required." });
        }
        const parsedDescriptor = parseFaceDescriptor(faceDescriptor);
        if (!parsedDescriptor) {
            return res.status(400).json({ success: false, message: 'A valid face descriptor (128 numbers) is required.' });
        }
        // Upload photo to Cloudinary if provided as base64 or file
        let finalPhotoUrl = photoUrl || '';
        if (req.files && req.files.photo) {
            finalPhotoUrl = await saveImage(req.files.photo);
        }
        const { PreRegisteredChild } = await getModels();
        const child = await PreRegisteredChild.create({
            parentId: req.userId,
            childName: String(childName).trim(),
            age: age ? Number(age) : undefined,
            gender: gender || '',
            address: address || '',
            parentContact: parentContact || '',
            medicalInfo: medicalInfo || '',
            photoUrl: finalPhotoUrl,
            faceDescriptor: parsedDescriptor
        });
        res.status(201).json({ success: true, message: 'Child pre-registered successfully!', data: { id: child._id, childName: child.childName } });
    } catch (error) {
        console.error('SafeChild register error:', error.message);
        res.status(500).json({ success: false, message: error.message || 'Registration failed.' });
    }
});

// Get all pre-registered children for the logged-in parent
app.get('/api/safechild/children', requireAuth, async (req, res) => {
    try {
        const { PreRegisteredChild } = await getModels();
        const children = await PreRegisteredChild.find({ parentId: req.userId }).select('-faceDescriptor').sort({ createdAt: -1 });
        res.json({ success: true, data: children });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Delete a pre-registered child
app.put('/api/safechild/children/:id', requireAuth, async (req, res) => {
    try {
        const { childName, age, gender, address, parentContact, medicalInfo, faceDescriptor } = req.body;
        const { PreRegisteredChild } = await getModels();
        const updateData = {};
        if (childName !== undefined) updateData.childName = String(childName).trim();
        if (age !== undefined) updateData.age = age === '' || age === null ? undefined : Number(age);
        if (gender !== undefined) updateData.gender = String(gender).trim();
        if (address !== undefined) updateData.address = String(address).trim();
        if (parentContact !== undefined) updateData.parentContact = String(parentContact).trim();
        if (medicalInfo !== undefined) updateData.medicalInfo = String(medicalInfo).trim();
        // Handle new AI descriptor if a new photo was processed
        if (faceDescriptor) {
            const parsedDescriptor = parseFaceDescriptor(faceDescriptor);
            if (parsedDescriptor) updateData.faceDescriptor = parsedDescriptor;
        }
        // Handle new photo upload
        if (req.files && req.files.photo) {
            const existingChild = await PreRegisteredChild.findOne({ _id: req.params.id, parentId: req.userId });
            if (existingChild && existingChild.photoUrl) {
                await deleteImage(existingChild.photoUrl);
            }
            const imagePath = await saveImage(req.files.photo);
            if (imagePath) updateData.photoUrl = imagePath;
        }
        const child = await PreRegisteredChild.findOneAndUpdate(
            { _id: req.params.id, parentId: req.userId },
            { $set: updateData },
            { new: true }
        );
        if (!child) return res.status(404).json({ success: false, message: 'Child not found or access denied.' });
        res.json({ success: true, message: 'Child details updated.', data: { id: child._id, childName: child.childName } });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/safechild/children/:id', requireAuth, async (req, res) => {
    try {
        const { PreRegisteredChild } = await getModels();
        const child = await PreRegisteredChild.findOne({ _id: req.params.id, parentId: req.userId });
        if (!child) return res.status(404).json({ success: false, message: 'Child not found.' });
        await PreRegisteredChild.deleteOne({ _id: child._id });
        res.json({ success: true, message: 'Child removed from SafeChild registry.' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// AI Face Match — PUBLIC, no auth required
app.post('/api/safechild/match', async (req, res) => {
    try {
        const { faceDescriptor } = req.body;
        const parsedDescriptor = parseFaceDescriptor(faceDescriptor);
        if (!parsedDescriptor) {
            return res.status(400).json({ success: false, message: 'A valid face descriptor (128 numbers) is required.' });
        }
        const { PreRegisteredChild } = await getModels();
        const db = await fmcConnectMongoDB();
        const Child = db.success ? db.data : null;

        // 1. Fetch pre-registered children
        const preReg = await PreRegisteredChild.find({}).lean();

        // 2. Fetch standard missing children (not yet found, with valid face data)
        let missing = [];
        if (Child) {
            missing = await Child.find({ faceDescriptor: { $exists: true, $ne: [] } }).lean();
        }

        // 3. Normalize into a single combined pool
        const combinedList = [
            ...preReg.map(c => ({ ...c, source: 'safechild' })),
            ...missing.map(c => ({
                _id: c._id,
                childName: c.fullName,
                age: c.age,
                gender: c.gender,
                address: c.address,
                parentContact: c.contactNumber,
                medicalInfo: c.info || '',
                photoUrl: c.image,
                faceDescriptor: c.faceDescriptor,
                source: 'missing_report'
            }))
        ];
        if (!combinedList.length) {
            return res.json({ success: true, matched: false, message: 'No records available for matching.' });
        }
        // Euclidean distance matching across both pools
        let bestMatch = null;
        let bestDistance = Infinity;
        const THRESHOLD = 0.65;
        const uploaded = parsedDescriptor;
        for (const child of combinedList) {
            if (!child.faceDescriptor || child.faceDescriptor.length !== 128) continue;
            let sumSq = 0;
            for (let i = 0; i < 128; i++) {
                const diff = uploaded[i] - child.faceDescriptor[i];
                sumSq += diff * diff;
            }
            const dist = Math.sqrt(sumSq);
            if (dist < bestDistance) {
                bestDistance = dist;
                bestMatch = child;
            }
        }
        if (bestMatch && bestDistance < THRESHOLD) {
            res.json({
                success: true,
                matched: true,
                distance: Math.round(bestDistance * 1000) / 1000,
                data: {
                    id: bestMatch._id,
                    childName: bestMatch.childName,
                    age: bestMatch.age,
                    gender: bestMatch.gender,
                    address: bestMatch.address,
                    parentContact: bestMatch.parentContact,
                    medicalInfo: bestMatch.medicalInfo,
                    photoUrl: bestMatch.photoUrl,
                    confidence: Math.round((1 - bestDistance) * 100),
                    source: bestMatch.source || 'safechild'
                }
            });
        } else {
            res.json({ success: true, matched: false, message: 'No matching child found.', bestDistance: bestDistance ? Math.round(bestDistance * 1000) / 1000 : null });
        }
    } catch (error) {
        console.error('SafeChild match error:', error.message);
        res.status(500).json({ success: false, message: 'Matching failed. Please try again.' });
    }
});

// ---- Admin: login / logout ----
app.post('/api/admin/login', (req, res) => {
    const result = loginAdmin(req.body.username, req.body.password);
    if (result) {
        res.json({ success: true, token: result.token, role: result.role, name: result.name });
    } else {
        res.status(401).json({ success: false, message: "Invalid username or password." });
    }
});

// Admin Google OAuth routes
if (googleClientId && googleClientSecret) {
    // Admin Google login — uses SEPARATE callback URL for clean admin flow
    app.get('/api/admin/auth/google', (req, res, next) => {
        console.log('[ADMIN-GOOGLE] Initiating admin login, protocol:', req.protocol, 'host:', req.get('host'));
        passport.authenticate('google', {
            scope: ['profile', 'email'],
            callbackURL: '/api/admin/auth/google/callback'
        })(req, res, next);
    });
    app.get('/api/admin/auth/google/callback', (req, res, next) => {
        console.log('[ADMIN-GOOGLE-CB] Callback hit, protocol:', req.protocol, 'host:', req.get('host'), 'originalUrl:', req.originalUrl);
        passport.authenticate('google', {
            failureRedirect: '/admin?error=google_failed',
            session: false,
            callbackURL: '/api/admin/auth/google/callback'
        }, (err, result, info) => {
            if (err || !result) {
                console.error('[ADMIN-GOOGLE-CB] Auth error:', err ? err.message : 'No result (not whitelisted?)');
                return res.redirect('/admin?error=' + encodeURIComponent(err ? err.message : 'not_whitelisted'));
            }
            console.log('[ADMIN-GOOGLE-CB] Success! Redirecting to admin panel');
            res.cookie('fmc_admin_token', result.token, { httpOnly: false, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax', path: '/' });
            res.redirect('/admin?v=a8f2e7c1&t=' + Date.now() + '&admin_token=' + result.token + '&admin_name=' + encodeURIComponent(result.admin.name || '') + '&admin_role=' + (result.admin.role || 'admin'));
        })(req, res, next);
    });
}

// Get current admin info
app.get('/api/admin/me', requireAdmin, async (req, res) => {
    try {
        // Return the decoded JWT payload with normalized permissions (children, users, etc.)
        // This ensures frontend receives the SAME permission keys used in hasPermission checks
        const tokenAdmin = {
            id: req.adminInfo.id || null,
            email: req.adminInfo.email,
            role: req.adminInfo.role,
            permissions: req.adminInfo.permissions || {}
        };
        // Also fetch DB record for display fields (name, photo, etc.)
        try {
            const { AdminUser } = await getModels();
            const admin = await AdminUser.findOne({ email: req.adminInfo.email }).lean();
            if (admin) {
                tokenAdmin.name = admin.name || '';
                tokenAdmin.photo = admin.photo || '';
                tokenAdmin.createdAt = admin.createdAt;
                tokenAdmin.id = admin._id;
            }
        } catch (e) { /* use token payload only */ }
        res.json({ success: true, admin: tokenAdmin });
    } catch (e) {
        res.json({ success: true, admin: req.adminInfo });
    }
});

// Update current admin profile
app.put('/api/admin/me', requireAdmin, async (req, res) => {
    try {
        const { AdminUser } = await getModels();
        const { name, photo } = req.body;
        const update = {};
        if (name !== undefined) update.name = String(name).trim();
        if (photo !== undefined) update.photo = String(photo).trim();
        const admin = await AdminUser.findOneAndUpdate(
            { email: req.adminInfo.email },
            { $set: update },
            { new: true }
        ).lean();
        if (!admin) return res.status(404).json({ success: false, message: 'Admin not found in whitelist.' });
        // Re-sign token with updated info (normalized permission keys)
        const isSuperAdmin = admin.role === 'super_admin';
        const newPerms = isSuperAdmin ? { all: true } : {
            all: false,
            children: !!admin.canManageChildren,
            users: !!admin.canManageUsers,
            ads: !!admin.canManageAds,
            analytics: !!admin.canManageAnalytics,
            donations: !!admin.canManageDonations,
            admins: !!admin.canManageAdmins
        };
        const newToken = signAdminToken({
            id: admin._id,
            email: admin.email,
            role: admin.role,
            permissions: newPerms
        });
        adminTokens.set(newToken, { id: admin._id, email: admin.email, role: admin.role, permissions: newPerms });
        res.json({ success: true, admin, token: newToken });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Debug endpoint - test admin auth without middleware
app.get('/api/admin/debug', (req, res) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    console.log('[DEBUG] /api/admin/debug called | token length:', token.length, '| token start:', token.substring(0, 30));
    if (!token) return res.json({ ok: false, reason: 'no token in header', headers: Object.keys(req.headers) });
    try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('[DEBUG] JWT verified OK:', JSON.stringify(decoded));
        res.json({ ok: true, decoded });
    } catch (e) {
        console.log('[DEBUG] JWT verification FAILED:', e.message);
        res.json({ ok: false, reason: e.message });
    }
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
    logout(req.token);
    res.clearCookie('fmc_admin_token', { path: '/' });
    res.json({ success: true });
});

// ---- Admin: statistics ----
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const db = await fmcConnectMongoDB();
        if (!db.success) return res.status(500).json({ success: false, message: "Database unavailable." });
        const Child = db.data;
        const [pending, approved, rejected, total] = await Promise.all([
            Child.countDocuments({ status: 'pending' }),
            Child.countDocuments({ status: 'approved' }),
            Child.countDocuments({ status: 'rejected' }),
            Child.countDocuments({})
        ]);
        res.json({ success: true, data: { pending, approved, rejected, total } });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: list all children (including pending/rejected) ----
app.get('/api/admin/children', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'children')) return res.status(403).json({ success: false, message: 'Permission denied: Children management.' });
    try {
        const db = await fmcConnectMongoDB();
        if (!db.success) return res.status(500).json({ success: false, message: "Database unavailable." });
        const Child = db.data;
        const filter = {};
        if (req.query.status) filter.status = req.query.status;
        if (req.query.q) {
            const re = { $regex: String(req.query.q), $options: "i" };
            filter.$or = [{ fullName: re }, { address: re }, { contactNumber: re }];
        }
        const data = await Child.find(filter).sort({ createdAt: -1 }).populate('userId', 'userFullName emailId userContactNumber');
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: add a child directly ----
app.post('/api/admin/children', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'children')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const data = pickChildFields(req.body);
        if (!data.fullName || !String(data.fullName).trim()) {
            return res.status(400).json({ success: false, message: "Child's full name is required." });
        }
        data.fullName = String(data.fullName).trim();
        if (data.contactNumber !== undefined && data.contactNumber !== '') data.contactNumber = String(data.contactNumber).trim();
        if (data.age !== undefined && data.age !== '') data.age = Number(data.age);
        if (!['pending', 'approved', 'rejected'].includes(data.status)) data.status = 'approved';
        if (data.found === undefined) data.found = false;
        data.uploadedBy = data.uploadedBy || 'Admin';

        const imagePath = await saveImage(req.files && req.files.image);
        if (imagePath) data.image = imagePath;

        const db = await fmcConnectMongoDB();
        if (!db.success) return res.status(500).json({ success: false, message: "Database unavailable." });
        const child = await db.data.create(data);
        io.emit('dataChanged'); clearDataCache();
        res.status(201).json({ success: true, message: "Child added.", data: child });
    } catch (error) {
        console.error("POST /api/admin/children error:", error.message);
        res.status(error.status || 500).json({ success: false, message: error.message || "Something went wrong." });
    }
});

// ---- Admin: update / approve / reject a child ----
app.put('/api/admin/children/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'children')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const db = await fmcConnectMongoDB();
        if (!db.success) return res.status(500).json({ success: false, message: "Database unavailable." });
        const Child = db.data;

        const data = pickChildFields(req.body);
        if (data.fullName !== undefined) data.fullName = String(data.fullName).trim();
        if (data.contactNumber !== undefined) data.contactNumber = String(data.contactNumber).trim();
        if (data.age !== undefined && data.age !== '') data.age = Number(data.age);
        if (data.found !== undefined && typeof data.found === 'string') data.found = data.found === 'true';
        if (data.status !== undefined && !['pending', 'approved', 'rejected'].includes(data.status)) {
            delete data.status;
        }
        // Parse face descriptor if provided by admin
        if (data.faceDescriptor) {
            const parsed = parseFaceDescriptor(data.faceDescriptor);
            data.faceDescriptor = parsed || [];
        }

        // Handle image replacement: upload new, delete old from Cloudinary
        const imagePath = await saveImage(req.files && req.files.image);
        if (imagePath) {
            // Fetch current child to clean up old image
            const existingChild = await Child.findById(req.params.id);
            if (existingChild && existingChild.image) {
                await deleteImage(existingChild.image);
            }
            data.image = imagePath;
        }

        const child = await Child.findByIdAndUpdate(req.params.id, data, { new: true, runValidators: true });
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        io.emit('dataChanged'); clearDataCache();
        res.json({ success: true, message: "Child updated.", data: child });
    } catch (error) {
        console.error("PUT /api/admin/children error:", error.message);
        res.status(error.status || 500).json({ success: false, message: error.message || "Something went wrong." });
    }
});

// ---- Admin: delete a child ----
app.delete('/api/admin/children/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'children')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const db = await fmcConnectMongoDB();
        if (!db.success) return res.status(500).json({ success: false, message: "Database unavailable." });
        const child = await db.data.findByIdAndDelete(req.params.id);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        // Clean up Cloudinary image to save storage
        if (child.image) await deleteImage(child.image);
        io.emit('dataChanged'); clearDataCache();
        res.json({ success: true, message: "Child deleted." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: found requests ----
app.get('/api/admin/found-requests', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'children')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { FoundRequest, Child } = await getModels();
        const filter = {};
        if (req.query.status) filter.status = req.query.status;
        const data = await FoundRequest.find(filter).sort({ createdAt: -1 }).populate('childId', 'fullName image');
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/found-requests/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'children')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { FoundRequest, Child } = await getModels();
        const fr = await FoundRequest.findById(req.params.id);
        if (!fr) return res.status(404).json({ success: false, message: "Request not found." });
        const status = req.body.status;
        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ success: false, message: "Status must be approved or rejected." });
        }
        fr.status = status;
        await fr.save();
        if (status === 'approved') {
            await Child.updateOne(
                { _id: fr.childId },
                {
                    found: true,
                    foundLocation: fr.details || 'Reported found',
                    finderName: fr.finderName,
                    finderContact: fr.contactNumber,
                    finderUserId: fr.userId,
                    foundDate: new Date()
                }
            );
        }
        io.emit('dataChanged'); clearDataCache();
        res.json({ success: true, message: status === 'approved' ? "Marked as found. The finder is now praised on the Found page." : "Found request rejected." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: praises ----
app.get('/api/admin/praise', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Praise } = await getModels();
        const filter = {};
        if (req.query.status) filter.status = req.query.status;
        const data = await Praise.find(filter).sort({ createdAt: -1 }).populate('childId', 'fullName');
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/praise/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Praise } = await getModels();
        const p = await Praise.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        if (!p) return res.status(404).json({ success: false, message: "Praise not found." });
        io.emit('dataChanged'); clearDataCache();
        res.json({ success: true, message: "Praise updated." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/praise/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Praise } = await getModels();
        const p = await Praise.findByIdAndDelete(req.params.id);
        if (!p) return res.status(404).json({ success: false, message: "Praise not found." });
        res.json({ success: true, message: "Praise deleted." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: gifts ----
app.get('/api/admin/gifts', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Gift } = await getModels();
        const filter = {};
        if (req.query.status) filter.status = req.query.status;
        const data = await Gift.find(filter).sort({ createdAt: -1 }).populate('childId', 'fullName');
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/gifts/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Gift } = await getModels();
        const g = await Gift.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        if (!g) return res.status(404).json({ success: false, message: "Gift not found." });
        io.emit('dataChanged'); clearDataCache();
        res.json({ success: true, message: "Gift updated." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/gifts/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Gift } = await getModels();
        const g = await Gift.findByIdAndDelete(req.params.id);
        if (!g) return res.status(404).json({ success: false, message: "Gift not found." });
        res.json({ success: true, message: "Gift deleted." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: donations ----
app.get('/api/admin/donations', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Donation } = await getModels();
        const data = await Donation.find().sort({ createdAt: -1 });
        const totalAgg = await Donation.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]);
        res.json({ success: true, data, total: (totalAgg[0] && totalAgg[0].total) || 0 });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/donations/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Donation } = await getModels();
        const d = await Donation.findByIdAndDelete(req.params.id);
        if (!d) return res.status(404).json({ success: false, message: "Donation not found." });
        res.json({ success: true, message: "Donation deleted." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Analytics tracking ----
app.post('/api/analytics', async (req, res) => {
    try {
        const { Analytics } = await getModels();
        const { type, page, section, data, sessionId } = req.body;
        if (!type) return res.status(400).json({ success: false, message: 'type required' });
        await Analytics.create({
            sessionId: sessionId || req.ip,
            type, page, section, data,
            userAgent: (req.headers['user-agent'] || '').slice(0, 200),
            ip: req.ip
        });
        res.json({ success: true });
    } catch (e) { res.json({ success: true }); }
});

app.get('/api/analytics/active', async (req, res) => {
    try {
        const { Analytics } = await getModels();
        const since = new Date(Date.now() - 15 * 60 * 1000);
        const active = await Analytics.distinct('sessionId', { createdAt: { $gte: since } });
        res.json({ success: true, count: active.length });
    } catch (e) { res.json({ success: true, count: 0 }); }
});

// ---- Public: active ads ----
app.get('/api/ads', async (req, res) => {
    try {
        const cached = getCached('ads');
        if (cached) return res.json(cached);
        const { Advertisement } = await getModels();
        const now = new Date();
        const ads = await Advertisement.find({
            active: true,
            $and: [
                { $or: [{ startDate: { $exists: false } }, { startDate: { $lte: now } }] },
                { $or: [{ endDate: { $exists: false } }, { endDate: { $gte: now } }] }
            ]
        }).sort({ priority: -1 }).limit(20).lean();
        const result = { success: true, data: ads };
        setCache('ads', result);
        res.json(result);
    } catch (e) { res.json({ success: true, data: [] }); }
});

app.post('/api/ads/:id/click', async (req, res) => {
    try {
        const { Advertisement } = await getModels();
        await Advertisement.findByIdAndUpdate(req.params.id, { $inc: { clicks: 1 } });
        res.json({ success: true });
    } catch (e) { res.json({ success: true }); }
});

app.post('/api/ads/:id/impression', async (req, res) => {
    try {
        const { Advertisement } = await getModels();
        await Advertisement.findByIdAndUpdate(req.params.id, { $inc: { impressions: 1 } });
        res.json({ success: true });
    } catch (e) { res.json({ success: true }); }
});

// ---- Cached data endpoint for instant load ----
app.get('/api/data', async (req, res) => {
    try {
        const cached = getCached('data');
        if (cached) return res.json(cached);
        const data = await getAllData();
        const result = { success: true, data };
        setCache('data', result);
        res.json(result);
    } catch (e) { res.json({ success: true, data: [] }); }
});

app.get('/api/messages', async (req, res) => {
    try {
        const cached = getCached('messages');
        if (cached) return res.json(cached);
        const data = await getMessages();
        const result = { success: true, data };
        setCache('messages', result);
        res.json(result);
    } catch (e) { res.json({ success: true, data: [] }); }
});

// ---- Admin: analytics dashboard ----
app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'analytics')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Analytics, User, Child, Donation, FoundRequest } = await getModels();
        const now = Date.now();
        const day = 24 * 60 * 60 * 1000;
        const [totalVisits, todayVisits, uniqueSessions, sectionViews, pageViews, recentVisits, userCount, childCount, donationTotal, donationAgg, foundCount] = await Promise.all([
            Analytics.countDocuments({}),
            Analytics.countDocuments({ createdAt: { $gte: new Date(now - day) } }),
            Analytics.distinct('sessionId', { createdAt: { $gte: new Date(now - 30 * day) } }),
            Analytics.aggregate([
                { $match: { type: 'section_view', createdAt: { $gte: new Date(now - 7 * day) } } },
                { $group: { _id: '$section', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 20 }
            ]),
            Analytics.aggregate([
                { $match: { createdAt: { $gte: new Date(now - 7 * day) } } },
                { $group: { _id: '$type', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ]),
            Analytics.find().sort({ createdAt: -1 }).limit(50).lean(),
            User.countDocuments({}),
            Child.countDocuments({}),
            Donation.countDocuments({}),
            Donation.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]),
            FoundRequest.countDocuments({})
        ]);
        const weekVisits = await Analytics.countDocuments({ createdAt: { $gte: new Date(now - 7 * day) } });
        res.json({ success: true, data: {
            totalVisits, todayVisits, weekVisits,
            uniqueUsers: uniqueSessions.length,
            sectionViews, pageViews, recentVisits,
            userCount, childCount, donationCount: donationTotal,
            donationTotal: (donationAgg[0] && donationAgg[0].total) || 0,
            foundCount
        }});
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: advertisements ----
app.get('/api/admin/ads', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'ads')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Advertisement } = await getModels();
        const ads = await Advertisement.find().sort({ createdAt: -1 });
        res.json({ success: true, data: ads });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/ads', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'ads')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Advertisement } = await getModels();
        const b = req.body;
        let imageUrl = '';
        let imageUrls = [];
        // Collect all uploaded files from both 'images' and 'image' fields
        if (req.files) {
            const allFiles = [];
            if (req.files.images) {
                const imgs = Array.isArray(req.files.images) ? req.files.images : [req.files.images];
                allFiles.push(...imgs);
            }
            if (req.files.image) {
                const img = Array.isArray(req.files.image) ? req.files.image : [req.files.image];
                allFiles.push(...img);
            }
            for (const file of allFiles) {
                try { const p = await saveImage(file); if (p) imageUrls.push(p); } catch(e) { /* skip */ }
            }
            if (imageUrls.length) imageUrl = imageUrls[0];
        }
        const ad = await Advertisement.create({
            title: String(b.title || '').trim().slice(0, 100),
            imageUrl: imageUrl || String(b.imageUrl || '').trim(),
            imageUrls: imageUrls,
            linkUrl: String(b.linkUrl || '').trim(),
            type: b.type || 'banner',
            position: b.position || 'home',
            active: b.active !== 'false',
            priority: Number(b.priority) || 0,
            advertiserName: String(b.advertiserName || '').trim().slice(0, 100),
            startDate: b.startDate || null,
            endDate: b.endDate || null
        });
        dataCache.ads = null;
        res.status(201).json({ success: true, message: 'Ad created.', data: ad });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/ads/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'ads')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Advertisement } = await getModels();
        const b = req.body;
        const update = {};
        if (b.title !== undefined) update.title = String(b.title).trim().slice(0, 100);
        if (b.linkUrl !== undefined) update.linkUrl = String(b.linkUrl).trim();
        if (b.type !== undefined) update.type = b.type;
        if (b.position !== undefined) update.position = b.position;
        if (b.active !== undefined) update.active = b.active === 'true' || b.active === true;
        if (b.priority !== undefined) update.priority = Number(b.priority);
        if (b.advertiserName !== undefined) update.advertiserName = String(b.advertiserName).trim().slice(0, 100);
        if (b.startDate !== undefined) update.startDate = b.startDate;
        if (b.endDate !== undefined) update.endDate = b.endDate;
        if (b.imageUrl !== undefined) update.imageUrl = String(b.imageUrl).trim();
        const imagePath = await saveImage(req.files && req.files.image);
        if (imagePath) update.imageUrl = imagePath;
        const putFiles = [];
        if (req.files) {
            if (req.files.images) {
                const imgs = Array.isArray(req.files.images) ? req.files.images : [req.files.images];
                putFiles.push(...imgs);
            }
            if (req.files.image) {
                const img = Array.isArray(req.files.image) ? req.files.image : [req.files.image];
                putFiles.push(...img);
            }
        }
        if (putFiles.length) {
            const urls = [];
            for (const file of putFiles) {
                try { const p = await saveImage(file); if (p) urls.push(p); } catch(e) {}
            }
            if (urls.length) { update.imageUrls = urls; update.imageUrl = urls[0]; }
        }
        const ad = await Advertisement.findByIdAndUpdate(req.params.id, update, { new: true });
        if (!ad) return res.status(404).json({ success: false, message: 'Ad not found.' });
        dataCache.ads = null;
        res.json({ success: true, message: 'Ad updated.', data: ad });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/ads/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'ads')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Advertisement } = await getModels();
        const ad = await Advertisement.findByIdAndDelete(req.params.id);
        if (!ad) return res.status(404).json({ success: false, message: 'Ad not found.' });
        if (ad.imageUrl) await deleteImage(ad.imageUrl);
        dataCache.ads = null;
        res.json({ success: true, message: 'Ad deleted.' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});
//------------------------------------------------------------------------------------------------------------------------------>

// ---- Admin: admin whitelist management ----
// List all whitelisted admins (super_admin only)
app.get('/api/admin/admins', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { AdminUser } = await getModels();
        const admins = await AdminUser.find().sort({ createdAt: -1 }).lean();
        res.json({ success: true, data: admins });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Add admin to whitelist (super_admin only)
app.post('/api/admin/admins', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { AdminUser } = await getModels();
        const { email, role, name, canManageChildren, canManageUsers, canManageAds, canManageAnalytics, canManageDonations, canManageAdmins } = req.body;
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ success: false, message: 'Valid email required.' });
        }
        const existing = await AdminUser.findOne({ email: email.toLowerCase() });
        if (existing) return res.status(400).json({ success: false, message: 'Email already whitelisted.' });
        const admin = await AdminUser.create({
            email: email.toLowerCase(),
            role: role || 'editor',
            name: name || '',
            canManageChildren: canManageChildren !== false,
            canManageUsers: canManageUsers !== false,
            canManageAds: canManageAds !== false,
            canManageAnalytics: canManageAnalytics !== false,
            canManageDonations: canManageDonations !== false,
            canManageAdmins: canManageAdmins === true
        });
        res.status(201).json({ success: true, data: admin });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Update admin in whitelist (super_admin only)
app.put('/api/admin/admins/:id', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { AdminUser } = await getModels();
        const { role, name, active, canManageChildren, canManageUsers, canManageAds, canManageAnalytics, canManageDonations, canManageAdmins } = req.body;
        const admin = await AdminUser.findById(req.params.id);
        if (!admin) return res.status(404).json({ success: false, message: 'Admin not found.' });
        // Cannot deactivate or demote super admin
        if (admin.email === process.env.SUPER_ADMIN_EMAIL || admin.email === 'iblvckstone@gmail.com') {
            if (active === false || (role && role !== 'super_admin')) {
                return res.status(403).json({ success: false, message: 'Cannot modify super admin.' });
            }
            // Block permission flag changes for super admin — they always have full access
            delete req.body.canManageChildren;
            delete req.body.canManageUsers;
            delete req.body.canManageAds;
            delete req.body.canManageAnalytics;
            delete req.body.canManageDonations;
            delete req.body.canManageAdmins;
        }
        if (role !== undefined) admin.role = role;
        if (name !== undefined) admin.name = name;
        if (active !== undefined) admin.active = active;
        if (canManageChildren !== undefined) admin.canManageChildren = canManageChildren;
        if (canManageUsers !== undefined) admin.canManageUsers = canManageUsers;
        if (canManageAds !== undefined) admin.canManageAds = canManageAds;
        if (canManageAnalytics !== undefined) admin.canManageAnalytics = canManageAnalytics;
        if (canManageDonations !== undefined) admin.canManageDonations = canManageDonations;
        if (canManageAdmins !== undefined) admin.canManageAdmins = canManageAdmins;
        await admin.save();
        res.json({ success: true, data: admin });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Delete admin from whitelist (super_admin only, cannot delete self)
app.delete('/api/admin/admins/:id', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { AdminUser } = await getModels();
        const admin = await AdminUser.findById(req.params.id);
        if (!admin) return res.status(404).json({ success: false, message: 'Admin not found.' });
        if (admin.email === 'iblvckstone@gmail.com') {
            return res.status(403).json({ success: false, message: 'Cannot delete the super admin.' });
        }
        await AdminUser.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Admin removed.' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Ensure super admin exists in whitelist
app.get('/api/admin/ensure-super-admin', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { AdminUser } = await getModels();
        let superAdmin = await AdminUser.findOne({ email: 'iblvckstone@gmail.com' });
        if (!superAdmin) {
            superAdmin = await AdminUser.create({
                email: 'iblvckstone@gmail.com',
                role: 'super_admin',
                name: 'Super Admin',
                active: true,
                canManageChildren: true,
                canManageUsers: true,
                canManageAds: true,
                canManageAnalytics: true,
                canManageDonations: true,
                canManageAdmins: true
            });
        }
        res.json({ success: true, data: superAdmin });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: user management ----
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'users')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { User } = await getModels();
        const users = await User.find().sort({ createdAt: -1 }).select('-password').lean();
        res.json({ success: true, data: users });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'users')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { User } = await getModels();
        const b = req.body;
        const update = {};
        if (b.userFullName !== undefined) update.userFullName = String(b.userFullName).trim();
        if (b.userContactNumber !== undefined) update.userContactNumber = String(b.userContactNumber).trim();
        if (b.emailId !== undefined) update.emailId = String(b.emailId).trim();
        if (b.blocked !== undefined) update.blocked = b.blocked === true || b.blocked === 'true';
        const user = await User.findByIdAndUpdate(req.params.id, update, { new: true }).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        res.json({ success: true, message: 'User updated.', data: user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'users')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { User } = await getModels();
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        res.json({ success: true, message: 'User deleted.' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/admin/users/:id/activity', requireAdmin, async (req, res) => {
    try {
        const { Analytics, Praise, Gift, FoundRequest } = await getModels();
        const userId = req.params.id;
        const [praises, gifts, foundReqs, analytics] = await Promise.all([
            Praise.find({ userId }).sort({ createdAt: -1 }).limit(20).lean(),
            Gift.find({ userId }).sort({ createdAt: -1 }).limit(20).lean(),
            FoundRequest.find({ userId }).sort({ createdAt: -1 }).limit(20).populate('childId', 'fullName').lean(),
            Analytics.find({ userId }).sort({ createdAt: -1 }).limit(20).lean()
        ]);
        res.json({ success: true, data: { praises, gifts, foundReqs, analytics } });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Ad click tracking
app.get('/api/ads/click/:id', async (req, res) => {
    try {
        const { Advertisement } = await getModels();
        const ad = await Advertisement.findByIdAndUpdate(req.params.id, { $inc: { clicks: 1 } });
        if (ad && ad.linkUrl) return res.redirect(ad.linkUrl);
        res.redirect('/');
    } catch (e) { res.redirect('/'); }
});

// ---- Public: require login for praise & gifts ----
// Update a user's own praise
app.put('/api/praise/:id', requireAuth, async (req, res) => {
    try {
        const { Praise } = await getModels();
        const { text } = req.body;
        if (!text || !text.trim()) return res.status(400).json({ success: false, message: 'Praise text is required.' });
        const praise = await Praise.findOneAndUpdate(
            { _id: req.params.id, userId: req.userId },
            { $set: { text: String(text).trim().slice(0, 500), status: 'pending' } },
            { new: true }
        );
        if (!praise) return res.status(404).json({ success: false, message: 'Praise not found or unauthorized.' });
        io.emit('dataChanged'); clearDataCache();
        res.json({ success: true, message: 'Praise updated and pending approval.', data: praise });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Delete a user's own praise
app.delete('/api/praise/:id', requireAuth, async (req, res) => {
    try {
        const { Praise } = await getModels();
        const praise = await Praise.findOneAndDelete({ _id: req.params.id, userId: req.userId });
        if (!praise) return res.status(404).json({ success: false, message: 'Praise not found or unauthorized.' });
        io.emit('dataChanged'); clearDataCache();
        res.json({ success: true, message: 'Praise deleted.' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/praise', requireAuth, async (req, res) => {
    try {
        const { Praise, Child } = await getModels();
        const child = await Child.findById(req.body.childId);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        if (!child.found) return res.status(400).json({ success: false, message: "This child is not marked as found yet." });
        if (child.finderUserId && child.finderUserId.toString() === req.userId) {
            return res.status(400).json({ success: false, message: "You cannot praise yourself." });
        }
        const text = req.body.text ? String(req.body.text).trim() : '';
        if (!text) return res.status(400).json({ success: false, message: "Write something to praise the hero." });
        const praise = await Praise.create({
            childId: child._id,
            userId: req.userId,
            userName: String(req.body.userName || 'Anonymous').trim().slice(0, 60),
            text: text.slice(0, 500),
            status: 'pending'
        });
        io.emit('dataChanged'); clearDataCache();
        res.status(201).json({ success: true, message: "Thank you! Your praise will appear after admin approval.", data: praise });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/gifts', requireAuth, async (req, res) => {
    try {
        const { Gift, Child } = await getModels();
        const child = await Child.findById(req.body.childId);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        if (!child.found) return res.status(400).json({ success: false, message: "This child is not marked as found yet." });
        if (child.finderUserId && child.finderUserId.toString() === req.userId) {
            return res.status(400).json({ success: false, message: "You cannot send a gift to yourself." });
        }
        const message = req.body.message ? String(req.body.message).trim() : '';
        if (!message) return res.status(400).json({ success: false, message: "Add a short message with your gift." });
        const amount = Number(req.body.amount);
        if (amount && amount <= 0) return res.status(400).json({ success: false, message: "Gift amount must be greater than zero." });
        const gift = await Gift.create({
            childId: child._id,
            userId: req.userId,
            giverName: String(req.body.giverName || 'Anonymous').trim().slice(0, 60),
            message: message.slice(0, 500),
            amount: amount || 0,
            status: 'pending'
        });
        io.emit('dataChanged'); clearDataCache();
        res.status(201).json({ success: true, message: "Thank you for your generous gift!", data: gift });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: Revenue management ----
app.get('/api/admin/revenue', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Revenue } = await getModels();
        const data = await Revenue.find().sort({ date: -1 }).lean();
        res.json({ success: true, data });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.post('/api/admin/revenue', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Revenue } = await getModels();
        const { source, type, amount, description, donorName, emailId, status, date } = req.body;
        if (!source || !amount) return res.status(400).json({ success: false, message: 'Source and amount are required.' });
        const record = await Revenue.create({ source, type: type || 'other', amount: Number(amount), description, donorName, emailId, status: status || 'received', date: date || new Date() });
        res.status(201).json({ success: true, data: record });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.put('/api/admin/revenue/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Revenue } = await getModels();
        const record = await Revenue.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!record) return res.status(404).json({ success: false, message: 'Record not found.' });
        res.json({ success: true, data: record });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.delete('/api/admin/revenue/:id', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Revenue } = await getModels();
        await Revenue.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.get('/api/admin/revenue/summary', requireAdmin, async (req, res) => {
    if (!hasPermission(req, 'donations')) return res.status(403).json({ success: false, message: 'Permission denied.' });
    try {
        const { Revenue } = await getModels();
        const all = await Revenue.find().lean();
        const total = all.reduce((s, r) => s + (r.amount || 0), 0);
        const byType = {};
        all.forEach(r => { byType[r.type] = (byType[r.type] || 0) + (r.amount || 0); });
        const bySource = {};
        all.forEach(r => { bySource[r.source] = (bySource[r.source] || 0) + (r.amount || 0); });
        const thisMonth = all.filter(r => { const d = new Date(r.date); const now = new Date(); return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear(); });
        const monthTotal = thisMonth.reduce((s, r) => s + (r.amount || 0), 0);
        res.json({ success: true, data: { total, monthTotal, byType, bySource, count: all.length } });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ---- Public: page content (About Us, Contact Us) ----
app.get('/api/pages/:slug', async (req, res) => {
    try {
        const { PageContent } = await getModels();
        const page = await PageContent.findOne({ slug: req.params.slug }).lean();
        if (!page) return res.status(404).json({ success: false, message: 'Page not found.' });
        res.json({ success: true, data: page });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ---- Admin: page content CRUD ----
app.get('/api/admin/pages', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { PageContent } = await getModels();
        const data = await PageContent.find().sort({ updatedAt: -1 }).lean();
        res.json({ success: true, data });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.get('/api/admin/pages/:slug', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { PageContent } = await getModels();
        const page = await PageContent.findOne({ slug: req.params.slug }).lean();
        if (!page) return res.status(404).json({ success: false, message: 'Page not found.' });
        res.json({ success: true, data: page });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.put('/api/admin/pages/:slug', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { PageContent } = await getModels();
        const { title, content, metaDescription, extra } = req.body;
        const update = { updatedAt: new Date() };
        if (title !== undefined) update.title = title;
        if (content !== undefined) update.content = content;
        if (metaDescription !== undefined) update.metaDescription = metaDescription;
        if (extra !== undefined) update.extra = extra;
        const page = await PageContent.findOneAndUpdate(
            { slug: req.params.slug },
            { $set: update },
            { new: true, upsert: true }
        );
        res.json({ success: true, data: page });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.delete('/api/admin/pages/:slug', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { PageContent } = await getModels();
        await PageContent.findOneAndDelete({ slug: req.params.slug });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ---- Public: legal pages ----
app.get('/api/legal/:slug', async (req, res) => {
    try {
        const { LegalPage } = await getModels();
        const page = await LegalPage.findOne({ slug: req.params.slug }).lean();
        if (!page) return res.status(404).json({ success: false, message: 'Page not found.' });
        res.json({ success: true, data: page });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.get('/api/legal', async (req, res) => {
    try {
        const { LegalPage } = await getModels();
        const data = await LegalPage.find().sort({ updatedAt: -1 }).select('slug title effectiveDate').lean();
        res.json({ success: true, data });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ---- Admin: legal pages CRUD ----
app.get('/api/admin/legal', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { LegalPage } = await getModels();
        const data = await LegalPage.find().sort({ updatedAt: -1 }).lean();
        res.json({ success: true, data });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.get('/api/admin/legal/:slug', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { LegalPage } = await getModels();
        const page = await LegalPage.findOne({ slug: req.params.slug }).lean();
        if (!page) return res.status(404).json({ success: false, message: 'Page not found.' });
        res.json({ success: true, data: page });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.put('/api/admin/legal/:slug', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { LegalPage } = await getModels();
        const { title, content, effectiveDate } = req.body;
        const update = { updatedAt: new Date() };
        if (title !== undefined) update.title = title;
        if (content !== undefined) update.content = content;
        if (effectiveDate !== undefined) update.effectiveDate = effectiveDate;
        const page = await LegalPage.findOneAndUpdate(
            { slug: req.params.slug },
            { $set: update },
            { new: true, upsert: true }
        );
        res.json({ success: true, data: page });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.delete('/api/admin/legal/:slug', requireAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const { LegalPage } = await getModels();
        await LegalPage.findOneAndDelete({ slug: req.params.slug });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

io.on("connection", function (socket) {
    console.log("New socket user found", socket.id);

    socket.on("load", () => {
        getAllData()
            .then(function (data) {
                socket.emit('getAllData', data)
            })
            .catch(function (error) {
                console.error("load error:", error);
                socket.emit('error', { message: "Failed to load data" });
            })
    });

    socket.on("searchByDate", (searchingDate) => {
        console.log("searchByDate:", searchingDate);
        getByDateData(searchingDate)
            .then(function (data) {
                socket.emit('getByDateData', data)
            })
            .catch(function (error) {
                console.error("searchByDate error:", error);
                socket.emit('error', { message: "Failed to search by date" });
            })
    });

    socket.on("searchByName", (searchingName) => {
        console.log("searchByName:", searchingName);
        getByNameData(searchingName)
            .then(function (data) {
                socket.emit('getByNameData', data)
            })
            .catch(function (error) {
                console.error("searchByName error:", error);
                socket.emit('error', { message: "Failed to search by name" });
            })
    });

    socket.on("searchByRange", (obj) => {
        console.log("searchByRange:", obj);
        getByRangeData(obj)
            .then(function (data) {
                socket.emit('getByRangeData', data)
            })
            .catch(function (error) {
                console.error("searchByRange error:", error);
                socket.emit('error', { message: "Failed to search by range" });
            })
    });

    socket.on("searchByAddress", (obj) => {
        console.log("searchByAddress:", obj);
        getByAddressData(obj)
            .then(function (data) {
                socket.emit('getByAddressData', data)
            })
            .catch(function (error) {
                console.error("searchByAddress error:", error);
                socket.emit('error', { message: "Failed to search by address" });
            })
    });

    // Flexible search: name / address / age / anything.
    socket.on("searchChildren", (obj) => {
        console.log("searchChildren:", obj);
        getBySearchData(obj)
            .then(function (data) {
                socket.emit('getSearchData', data)
            })
            .catch(function (error) {
                console.error("searchChildren error:", error);
                socket.emit('error', { message: "Failed to search" });
            })
    });

    // Important messages / notices for the home page.
    socket.on("loadMessages", () => {
        getMessages()
            .then(function (data) {
                socket.emit('getMessages', data)
            })
            .catch(function (error) {
                console.error("loadMessages error:", error);
                socket.emit('error', { message: "Failed to load messages" });
            })
    });

    socket.on("disconnect", () => {
        console.log(`${socket.id} User Disconnected!`);
    })
});

//-----------------------------------------------Start server------------------------------------------------------------------->
let PORT = process.env.PORT && Number(process.env.PORT) > 0 ? Number(process.env.PORT) : 9002;
const portArgIdx = process.argv.indexOf('--port');
if (portArgIdx !== -1 && process.argv[portArgIdx + 1]) {
    PORT = Number(process.argv[portArgIdx + 1]);
}

// Connect to the database once at startup so failures surface early.
fmcConnectMongoDB().then(async (res) => {
    if (!res.success) {
        console.error("WARNING: Database connection failed at startup:", res.data && res.data.message);
        return;
    }
    // Auto-create and enforce super admin whitelist entry
    try {
        const { AdminUser } = await getModels();
        const superEmail = 'iblvckstone@gmail.com';
        let superAdmin = await AdminUser.findOne({ email: superEmail });
        if (!superAdmin) {
            superAdmin = await AdminUser.create({
                email: superEmail,
                role: 'super_admin',
                name: 'Super Admin',
                active: true,
                canManageChildren: true,
                canManageUsers: true,
                canManageAds: true,
                canManageAnalytics: true,
                canManageDonations: true,
                canManageAdmins: true
            });
            console.log('Super admin auto-created:', superEmail);
        } else {
            // Enforce super admin always has full access
            const needsUpdate = superAdmin.role !== 'super_admin' || !superAdmin.active ||
                !superAdmin.canManageChildren || !superAdmin.canManageUsers ||
                !superAdmin.canManageAds || !superAdmin.canManageAnalytics ||
                !superAdmin.canManageDonations || !superAdmin.canManageAdmins;
            if (needsUpdate) {
                await AdminUser.updateOne({ email: superEmail }, { $set: {
                    role: 'super_admin', active: true,
                    canManageChildren: true, canManageUsers: true,
                    canManageAds: true, canManageAnalytics: true,
                    canManageDonations: true, canManageAdmins: true
                }});
                console.log('Super admin permissions enforced:', superEmail);
            }
        }
    } catch (e) { console.error('Super admin init error:', e.message); }

    // Seed default page content if none exists
    try {
        const { PageContent, LegalPage } = await getModels();

        // About Us
        const aboutExists = await PageContent.findOne({ slug: 'about-us' });
        if (!aboutExists) {
            await PageContent.create({
                slug: 'about-us',
                title: 'About Us',
                content: '<h2>Gumshuda Bacho Ki Talash</h2><p>Find My Child (Gumshuda Bacho Ki Talash) is a non-profit social initiative dedicated to reuniting missing children with their families. We provide a free, publicly accessible platform where concerned citizens can report missing children and help locate them.</p><h3>Our Mission</h3><p>To create a community-driven network that helps locate missing children quickly and reunite them with their families. Every child deserves to be safe at home.</p><h3>How It Works</h3><ul><li><strong>Report:</strong> Anyone can submit a missing child report with details and photos.</li><li><strong>Verify:</strong> Our admin team reviews and verifies every submission.</li><li><strong>Publish:</strong> Verified reports are made public so the community can help.</li><li><strong>Reunite:</strong> When someone spots the child, they submit a Found Request.</li></ul><h3>Who We Are</h3><p>We are a volunteer-driven group based in Malegaon, Maharashtra. This platform was built with the sole purpose of social good — no commercial interest whatsoever.</p>',
                metaDescription: 'Learn about Find My Child - a non-profit initiative to reunite missing children with their families.',
                extra: { mission: 'To create a community-driven network that helps locate missing children quickly.', vision: 'A world where no child is lost and every family is whole.', foundedYear: 2026, location: 'Malegaon, Maharashtra, India' }
            });
            console.log('Seeded: About Us page');
        }

        // Contact Us
        const contactExists = await PageContent.findOne({ slug: 'contact-us' });
        if (!contactExists) {
            await PageContent.create({
                slug: 'contact-us',
                title: 'Contact Us',
                content: '<h2>Get In Touch</h2><p>We are here to help. Reach out to us for any queries, support, or to report a missing child.</p>',
                extra: {
                    phone: '+91 98765 43210',
                    email: 'contact@findmychild.dpdns.org',
                    altEmail: 'support@findmychild.dpdns.org',
                    whatsapp: '+91 98765 43210',
                    address: 'Malegaon, Maharashtra, India',
                    socialMedia: {
                        facebook: 'https://facebook.com/findmychild',
                        instagram: 'https://instagram.com/findmychild',
                        youtube: 'https://youtube.com/@findmychild',
                        whatsapp: 'https://wa.me/919876543210'
                    },
                    helplineHours: '24/7 - We never stop looking',
                    emergencyNote: 'If a child is in immediate danger, please call 112 (Emergency) or 1098 (Child Helpline) immediately.'
                }
            });
            console.log('Seeded: Contact Us page');
        }

        // Legal Pages
        const legalPages = [
            {
                slug: 'privacy-policy',
                title: 'Privacy Policy',
                content: '<h1>Privacy Policy</h1><p><em>Last Updated: August 2026</em></p><h2>1. Introduction</h2><p>Find My Child ("we", "our", or "us") operates the findmychild.dpdns.org website and mobile application (the "Service"). This page informs you of our policies regarding the collection, use, and disclosure of personal information when you use our Service.</p><h2>2. Information We Collect</h2><p>We collect several types of information for various purposes to provide and improve our Service:</p><h3>2.1 Personal Data</h3><ul><li>Full name</li><li>Contact number (phone number)</li><li>Email address (optional)</li><li>Google account information (if you sign in via Google OAuth)</li></ul><h3>2.2 Child Report Data</h3><ul><li>Child\'s full name, age, gender</li><li>Address and location details</li><li>Photo(s) of the missing child</li><li>Date and time of disappearance</li><li>Description of the circumstances</li></ul><h3>2.3 Found Request Data</h3><ul><li>Finder\'s name and contact information</li><li>Details about the sighting</li></ul><h3>2.4 Usage Data</h3><p>We automatically collect information such as your IP address, browser type, pages visited, and time spent on pages for analytics purposes.</p><h2>3. How We Use Your Information</h2><ul><li>To operate and maintain the platform</li><li>To verify and publish missing child reports</li><li>To match found requests with missing children</li><li>To contact you regarding a report or request</li><li>To improve our platform and user experience</li><li>To ensure the safety and integrity of our platform</li></ul><h2>4. Data Sharing</h2><p>We do NOT sell, trade, or rent your personal information. We may share information only:</p><ul><li>When required by law or legal process</li><li>When we believe disclosure is necessary to protect the safety of a child</li><li>With law enforcement agencies upon valid request</li><li>With child helpline services (1098) when appropriate</li></ul><h2>5. Data Storage & Security</h2><p>Your data is stored on secure cloud servers (MongoDB Atlas). We implement industry-standard security measures to protect your information. However, no method of transmission over the Internet is 100% secure.</p><h2>6. Children\'s Privacy</h2><p>This platform is specifically designed to help children. We take extra care with children\'s data. Child report information is publicly visible only after admin verification, to prevent misuse.</p><h2>7. Your Rights</h2><ul><li><strong>Access:</strong> You can request a copy of your personal data.</li><li><strong>Correction:</strong> You can request correction of inaccurate data.</li><li><strong>Deletion:</strong> You can request deletion of your account and data.</li><li><strong>Opt-out:</strong> You can opt out of non-essential data collection.</li></ul><h2>8. Cookies</h2><p>We use essential cookies for authentication and session management. We do not use third-party advertising cookies.</p><h2>9. Third-Party Services</h2><ul><li><strong>Google OAuth:</strong> For optional sign-in functionality. Subject to <a href="https://policies.google.com/privacy">Google\'s Privacy Policy</a>.</li><li><strong>Cloudinary:</strong> For image storage and management.</li><li><strong>Resend:</strong> For sending OTP verification emails.</li></ul><h2>10. Changes to This Policy</h2><p>We may update this Privacy Policy from time to time. Changes will be posted on this page with an updated "Last Updated" date.</p><h2>11. Contact Us</h2><p>If you have questions about this Privacy Policy, please contact us at:</p><ul><li>Email: privacy@findmychild.dpdns.org</li><li>Phone: +91 98765 43210</li></ul>'
            },
            {
                slug: 'terms-and-conditions',
                title: 'Terms and Conditions',
                content: '<h1>Terms and Conditions</h1><p><em>Last Updated: August 2026</em></p><h2>1. Acceptance of Terms</h2><p>By accessing or using Find My Child (findmychild.dpdns.org) and related services (the "Service"), you agree to be bound by these Terms and Conditions. If you do not agree, please do not use the Service.</p><h2>2. Description of Service</h2><p>Find My Child is a free, non-profit social platform that helps locate missing children by connecting communities. It allows users to submit missing child reports and found requests.</p><h2>3. User Responsibilities</h2><ul><li><strong>Accuracy:</strong> You must provide accurate and truthful information in all reports and requests.</li><li><strong>Good Faith:</strong> The platform must only be used for genuine purposes of finding missing children.</li><li><strong>No Misuse:</strong> You must NOT use the platform to harass, threaten, defame, or harm any individual.</li><li><strong>No False Reports:</strong> Submitting false or fabricated missing child reports is a serious offense and may be reported to law enforcement.</li></ul><h2>4. Prohibited Activities</h2><ul><li>Submitting false, misleading, or fabricated reports</li><li>Using the platform for commercial or advertising purposes without authorization</li><li>Attempting to access other users\' accounts or personal data</li><li>Using automated tools (bots, scrapers) to access the Service</li><li>Uploading content that is offensive, inappropriate, or violates any law</li><li>Impersonating any person or entity</li><li>Interfering with the proper functioning of the Service</li></ul><h2>5. User Content</h2><p>By submitting content (reports, images, messages) to the Service, you:</p><ul><li>Represent that you have the right to submit such content</li><li>Grant us a non-exclusive license to use, display, and distribute the content for the purpose of operating the Service</li><li>Understand that all reports are reviewed by administrators before publication</li></ul><h2>6. Intellectual Property</h2><p>The Service, including its design, code, logos, and original content, is the intellectual property of the Find My Child team. Unauthorized reproduction or distribution is prohibited.</p><h2>7. Disclaimer of Warranties</h2><p>THE SERVICE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND. WE DO NOT GUARANTEE THAT:</p><ul><li>The Service will be available at all times</li><li>Missing children will be found</li><li>The information on the platform is always accurate or complete</li><li>The Service will be free from errors or interruptions</li></ul><h2>8. Limitation of Liability</h2><p>Find My Child and its operators shall NOT be liable for:</p><ul><li>Any direct, indirect, or consequential damages arising from use of the Service</li><li>Any harm resulting from reliance on information posted on the platform</li><li>Any actions taken by users based on information found on the platform</li></ul><h2>9. Emergency Situations</h2><p>This platform is NOT a substitute for emergency services. In case of immediate danger or emergency:</p><ul><li>Call <strong>112</strong> (Emergency Services)</li><li>Call <strong>1098</strong> (Child Helpline India)</li><li>Call <strong>100</strong> (Police)</li><li>Contact your nearest police station immediately</li></ul><h2>10. Account Termination</h2><p>We reserve the right to suspend or terminate accounts that violate these terms, without prior notice.</p><h2>11. Governing Law</h2><p>These Terms are governed by the laws of India. Any disputes shall be subject to the exclusive jurisdiction of courts in Maharashtra, India.</p><h2>12. Changes to Terms</h2><p>We reserve the right to modify these Terms at any time. Continued use of the Service after changes constitutes acceptance of the new Terms.</p><h2>13. Contact</h2><p>For questions about these Terms, contact: legal@findmychild.dpdns.org</p>'
            },
            {
                slug: 'disclaimer',
                title: 'Disclaimer',
                content: '<h1>Disclaimer</h1><p><em>Last Updated: August 2026</em></p><h2>General Disclaimer</h2><p>The information on Find My Child (findmychild.dpdns.org) is provided in good faith for the purpose of helping reunite missing children with their families. While we strive to keep information accurate and up-to-date, we make no representations or warranties about the completeness, reliability, or accuracy of this information.</p><h2>No Guarantee of Results</h2><p>Find My Child is a community-driven initiative. While we work hard to help locate missing children, we do NOT guarantee that:</p><ul><li>Any missing child will be found</li><li>Reports will be processed within a specific timeframe</li><li>Information provided by users is accurate or verified</li></ul><h2>User-Generated Content</h2><p>All missing child reports and found requests are submitted by users. While our admin team reviews submissions before publishing:</p><ul><li>We are not responsible for inaccurate or misleading information</li><li>User-submitted photos may not always be current or accurate representations</li><li>Contact details provided by users are verified to a limited extent only</li></ul><h2>Third-Party Links</h2><p>The Service may contain links to external websites or services. We are not responsible for the content or privacy practices of these external sites.</p><h2>Not a Law Enforcement Agency</h2><p>Find My Child is a civilian volunteer initiative. We are NOT:</p><ul><li>A law enforcement agency</li><li>A government body</li><li>A licensed private investigation firm</li></ul><p>Our role is to facilitate community awareness and help connect people who have information about missing children.</p><h2>Emergency Notice</h2><p><strong>IMPORTANT:</strong> This platform is NOT a substitute for emergency services. If a child is in immediate danger:</p><ul><li><strong>Call 112</strong> (Emergency)</li><li><strong>Call 1098</strong> (Child Helpline)</li><li><strong>Call 100</strong> (Police)</li></ul><p>Please report to your nearest police station immediately. Do not wait for online responses in emergency situations.</p><h2>Limitation of Liability</h2><p>In no event shall Find My Child, its operators, volunteers, or affiliates be liable for any loss or damage including indirect or consequential loss or damage arising from the use of this platform.</p><h2>Fair Use</h2><p>This platform is operated as a non-profit social initiative. No commercial activities are conducted through this platform. Any donations received are used solely for maintaining and operating the platform.</p><h2>Contact</h2><p>For any concerns about the information on this platform, contact: legal@findmychild.dpdns.org</p>'
            }
        ];
        for (const lp of legalPages) {
            const exists = await LegalPage.findOne({ slug: lp.slug });
            if (!exists) {
                await LegalPage.create(lp);
                console.log('Seeded: Legal page -', lp.title);
            }
        }
    } catch (e) { console.error('Seed data error:', e.message); }
});

server.listen(PORT, '0.0.0.0', function () {
    console.log('Server started at port', PORT);
});
