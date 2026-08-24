const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const { Server } = require('socket.io');
require('dotenv').config(); // For .env files availability like this process.env.SECRET_KEY

const app = express();
const server = http.createServer(app);

//-----------------------------------------------Middleware-------------------------------------------------------------------->
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'public')));

//-----------------------------------------------Functions Module--------------------------------------------------------------->
const fmcConnectMongoDB = require('./functions/fmcDB/fmcMongoDB');
const getModels = require('./functions/dbModels');
const { loginAdmin, loginUser, signupUser, logout, requireAuth, requireAdmin } = require('./functions/auth');
// const userConnectMongoDB = require('./functions/userDB/userMongoDB');
const getAllData = require('./functions/getAllData/getAllData.js');
const getByDateData = require('./functions/getByDateData/getByDateData.js');
const getByNameData = require('./functions/getByNameData/getByNameData.js');
const getByRangeData = require('./functions/getByRangeData/getByRangeData.js');
const getByAddressData = require('./functions/getByAddressData/getByAddressData.js');
const getBySearchData = require('./functions/getBySearchData/getBySearchData.js');
const getMessages = require('./functions/getMessages/getMessages.js');

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

// ---- Public: submit a missing child report (goes to the pending queue) ----
app.post('/api/children', async (req, res) => {
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
        data.uploadedBy = data.uploadedBy || 'Public';

        const db = await fmcConnectMongoDB();
        if (!db.success) return res.status(500).json({ success: false, message: "Database unavailable." });
        const Child = db.data;
        const child = await Child.create(data);
        io.emit('dataChanged');
        res.status(201).json({ success: true, message: "Report submitted! It will be published after admin approval.", data: child });
    } catch (error) {
        console.error("POST /api/children error:", error.message);
        res.status(error.status || 500).json({ success: false, message: error.message || "Something went wrong." });
    }
});

// ---- User auth: signup / login / logout / me ----
app.post('/api/auth/signup', async (req, res) => {
    try {
        const r = await signupUser(req.body);
        if (r.error) return res.status(400).json({ success: false, message: r.error });
        res.status(201).json({ success: true, message: "Account created! Welcome to Find My Child.", token: r.token, user: r.user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
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
        io.emit('dataChanged');
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

app.post('/api/praise', async (req, res) => {
    try {
        const { Praise, Child } = await getModels();
        const child = await Child.findById(req.body.childId);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        if (!child.found) return res.status(400).json({ success: false, message: "This child is not marked as found yet." });
        const text = req.body.text ? String(req.body.text).trim() : '';
        if (!text) return res.status(400).json({ success: false, message: "Write something to praise the hero." });
        const praise = await Praise.create({
            childId: child._id,
            userName: String(req.body.userName || 'Anonymous').trim().slice(0, 60),
            text: text.slice(0, 500),
            status: 'pending'
        });
        io.emit('dataChanged');
        res.status(201).json({ success: true, message: "Thank you! Your praise will appear after admin approval.", data: praise });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/gifts', async (req, res) => {
    try {
        const { Gift, Child } = await getModels();
        const child = await Child.findById(req.body.childId);
        if (!child) return res.status(404).json({ success: false, message: "Child not found." });
        if (!child.found) return res.status(400).json({ success: false, message: "This child is not marked as found yet." });
        const message = req.body.message ? String(req.body.message).trim() : '';
        if (!message) return res.status(400).json({ success: false, message: "Add a short message with your gift." });
        const gift = await Gift.create({
            childId: child._id,
            giverName: String(req.body.giverName || 'Anonymous').trim().slice(0, 60),
            message: message.slice(0, 500),
            amount: req.body.amount && !isNaN(Number(req.body.amount)) ? Number(req.body.amount) : undefined,
            status: 'pending'
        });
        io.emit('dataChanged');
        res.status(201).json({ success: true, message: "Gift sent! It will appear after admin approval.", data: gift });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

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
        io.emit('dataChanged');
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
        io.emit('dataChanged');
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
        io.emit('dataChanged');
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
        io.emit('dataChanged');
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
        io.emit('dataChanged');
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
        io.emit('dataChanged');
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
        io.emit('dataChanged');
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
//------------------------------------------------------------------------------------------------------------------------------>

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
