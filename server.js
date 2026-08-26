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

const app = express();
const server = http.createServer(app);

//-----------------------------------------------Middleware-------------------------------------------------------------------->
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'public')));

// Session for Passport
app.use(require('express-session')({ secret: process.env.JWT_SECRET || 'session_secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Rate limiting
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { success: false, message: 'Too many attempts. Try again in 15 minutes.' } });

//-----------------------------------------------Functions Module--------------------------------------------------------------->
const fmcConnectMongoDB = require('./functions/fmcDB/fmcMongoDB');
const getModels = require('./functions/dbModels');
const { loginAdmin, loginUser, signupUser, findOrCreateGoogleUser, logout, requireAuth, requireAdmin, isValidPhone, sanitize } = require('./functions/auth');
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
        scope: ['profile', 'email']
    }, async (accessToken, refreshToken, profile, done) => {
        try {
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
    'disability', 'missingLocation', 'missingDateTime', 'foundLocation', 'disabilityInfo', 'status'
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
        if (data.age !== undefined && data.age !== '') data.age = Number(data.age);

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

// ---- Google OAuth ----
if (googleClientId && googleClientSecret) {
    app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
    app.get('/api/auth/google/callback', (req, res, next) => {
        passport.authenticate('google', { failureRedirect: '/?error=google_failed', session: false }, (err, user, info) => {
            if (err || !user) {
                console.error('Google auth error:', err ? err.message : 'No user returned');
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
        const data = await FoundRequest.find({ userId: req.userId }).sort({ createdAt: -1 });
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
            message: req.body.message ? String(req.body.message).trim().slice(0, 500) : ''
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

// ---- Admin: login / logout ----
app.post('/api/admin/login', (req, res) => {
    const token = loginAdmin(req.body.username, req.body.password);
    if (token) {
        res.json({ success: true, token });
    } else {
        res.status(401).json({ success: false, message: "Invalid username or password." });
    }
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
    logout(req.token);
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
        const data = await Child.find(filter).sort({ createdAt: -1 });
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ---- Admin: add a child directly ----
app.post('/api/admin/children', requireAdmin, async (req, res) => {
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
    try {
        const { Advertisement } = await getModels();
        const ads = await Advertisement.find().sort({ createdAt: -1 });
        res.json({ success: true, data: ads });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/admin/ads', requireAdmin, async (req, res) => {
    try {
        const { Advertisement } = await getModels();
        const b = req.body;
        const imagePath = await saveImage(req.files && req.files.image);
        const ad = await Advertisement.create({
            title: String(b.title || '').trim().slice(0, 100),
            imageUrl: imagePath || String(b.imageUrl || '').trim(),
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
        const ad = await Advertisement.findByIdAndUpdate(req.params.id, update, { new: true });
        if (!ad) return res.status(404).json({ success: false, message: 'Ad not found.' });
        dataCache.ads = null;
        res.json({ success: true, message: 'Ad updated.', data: ad });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/ads/:id', requireAdmin, async (req, res) => {
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

// ---- Admin: user management ----
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const { User } = await getModels();
        const users = await User.find().sort({ createdAt: -1 }).select('-password').lean();
        res.json({ success: true, data: users });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
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
app.post('/api/praise', requireAuth, async (req, res) => {
    try {
        const { Praise, Child } = await getModels();
        const child = await Child.findById(req.body.childId);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        if (!child.found) return res.status(400).json({ success: false, message: "This child is not marked as found yet." });
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
        const message = req.body.message ? String(req.body.message).trim() : '';
        if (!message) return res.status(400).json({ success: false, message: "Add a short message with your gift." });
        const gift = await Gift.create({
            childId: child._id,
            userId: req.userId,
            giverName: String(req.body.giverName || 'Anonymous').trim().slice(0, 60),
            message: message.slice(0, 500),
            amount: Number(req.body.amount) || 0,
            status: 'pending'
        });
        io.emit('dataChanged'); clearDataCache();
        res.status(201).json({ success: true, message: "Thank you for your generous gift!", data: gift });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
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
const PORT = process.env.PORT && Number(process.env.PORT) > 0 ? Number(process.env.PORT) : 9002;

// Connect to the database once at startup so failures surface early.
fmcConnectMongoDB().then((res) => {
    if (!res.success) {
        console.error("WARNING: Database connection failed at startup:", res.data && res.data.message);
    }
});

server.listen(PORT, '0.0.0.0', function () {
    console.log('Server started at port', PORT);
});
