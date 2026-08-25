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
    userName: String,
    text: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const giftSchema = mongoose.Schema({
    childId: { type: mongoose.Schema.Types.ObjectId, ref: 'Child' },
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
            return { Child: db.data, User, FoundRequest, Praise, Gift, Donation };
        })();
    }
    return modelsPromise;
};

module.exports = getModels;
