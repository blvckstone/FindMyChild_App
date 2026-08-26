const mongoose = require('mongoose');
const fmcConnectMongoDB = require('./fmcDB/fmcMongoDB');

const userSchema = mongoose.Schema({
    userFullName: String,
    userContactNumber: { type: String, unique: true, sparse: true },
    password: String,
    emailId: String,
    googleId: String,
    photo: String,
    verified: { type: Boolean, default: false },
    blocked: { type: Boolean, default: false },
    createdAt: String,
});

const foundRequestSchema = mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    finderName: String,
    claimType: { type: String, enum: ['me', 'someone'], default: 'me' },
    contactNumber: String,
    details: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const praiseSchema = mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    userName: String,
    text: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const giftSchema = mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    giverName: String,
    message: String,
    amount: Number,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const donationSchema = mongoose.Schema({
    donorName: String,
    emailId: String,
    amount: Number,
    message: String,
    createdAt: { type: Date, default: Date.now }
});

const analyticsSchema = mongoose.Schema({
    sessionId: String,
    type: { type: String, enum: ['pageview', 'section_view', 'search', 'detail_open', 'login', 'signup', 'report'], required: true },
    page: String,
    section: String,
    data: mongoose.Schema.Types.Mixed,
    userAgent: String,
    ip: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

const adSchema = mongoose.Schema({
    title: String,
    imageUrl: String,
    linkUrl: String,
    type: { type: String, enum: ['carousel', 'fullscreen', 'banner', 'small_banner', 'header', 'sidebar', 'popup', 'interstitial'], default: 'banner' },
    position: { type: String, default: 'home' },
    active: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    clicks: { type: Number, default: 0 },
    impressions: { type: Number, default: 0 },
    advertiserName: String,
    description: String,
    startDate: Date,
    endDate: Date,
    createdAt: { type: Date, default: Date.now }
});

let modelsPromise = null;

const getModels = async () => {
    if (!modelsPromise) {
        modelsPromise = (async () => {
            const db = await fmcConnectMongoDB();
            if (!db.success) throw new Error("Database unavailable");
            const User = mongoose.models.User || mongoose.model('User', userSchema);
            const FoundRequest = mongoose.models.FoundRequest || mongoose.model('FoundRequest', foundRequestSchema);
            const Praise = mongoose.models.Praise || mongoose.model('Praise', praiseSchema);
            const Gift = mongoose.models.Gift || mongoose.model('Gift', giftSchema);
            const Donation = mongoose.models.Donation || mongoose.model('Donation', donationSchema);
            const Analytics = mongoose.models.Analytics || mongoose.model('Analytics', analyticsSchema);
            const Advertisement = mongoose.models.Advertisement || mongoose.model('Advertisement', adSchema);
            return { Child: db.data, User, FoundRequest, Praise, Gift, Donation, Analytics, Advertisement };
        })();
    }
    return modelsPromise;
};

module.exports = getModels;
