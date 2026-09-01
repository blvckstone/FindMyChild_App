const mongoose = require('mongoose');
const fmcConnectMongoDB = require('./fmcDB/fmcMongoDB');

const userSchema = mongoose.Schema({
    userFullName: { type: String, default: '' },
    userContactNumber: { type: String, unique: true, sparse: true },
    password: String,
    emailId: String,
    googleId: String,
    photo: String,
    verified: { type: Boolean, default: false },
    blocked: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
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
    utrNumber: { type: String, default: '' },
    paymentMethod: { type: String, enum: ['upi', 'bank_transfer', 'other'], default: 'upi' },
    status: { type: String, enum: ['pending', 'verified', 'failed'], default: 'pending' },
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

// Admin whitelist schema - emails allowed to access admin panel
const adminUserSchema = mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    role: { type: String, enum: ['super_admin', 'admin', 'editor'], default: 'admin' },
    name: { type: String, default: '' },
    photo: { type: String, default: '' },
    googleId: { type: String, default: '' },
    // Permissions for non-super_admin roles
    canManageChildren: { type: Boolean, default: true },
    canManageUsers: { type: Boolean, default: true },
    canManageAds: { type: Boolean, default: true },
    canManageAnalytics: { type: Boolean, default: true },
    canManageDonations: { type: Boolean, default: true },
    canManageAdmins: { type: Boolean, default: false },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

// Page content schema (About Us, Contact Us, etc.)
const pageContentSchema = mongoose.Schema({
    slug: { type: String, required: true, unique: true, lowercase: true },
    title: { type: String, default: '' },
    content: { type: String, default: '' },
    metaDescription: { type: String, default: '' },
    extra: mongoose.Schema.Types.Mixed,
    updatedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

// Legal pages schema (Privacy Policy, Terms, Disclaimer)
const legalPageSchema = mongoose.Schema({
    slug: { type: String, required: true, unique: true, lowercase: true },
    title: { type: String, default: '' },
    content: { type: String, default: '' },
    effectiveDate: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

// Revenue / income tracking schema
const revenueSchema = mongoose.Schema({
    source: { type: String, required: true },
    type: { type: String, enum: ['donation', 'ad_revenue', 'grant', 'sponsorship', 'membership', 'other'], default: 'other' },
    amount: { type: Number, required: true },
    description: { type: String, default: '' },
    donorName: { type: String, default: '' },
    emailId: { type: String, default: '' },
    referenceId: { type: String, default: '' },
    status: { type: String, enum: ['received', 'pending', 'confirmed'], default: 'received' },
    date: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

const adSchema = mongoose.Schema({
    title: String,
    imageUrl: String,
    imageUrls: [String],
    linkUrl: String,
    type: { type: String, enum: ['carousel', 'fullscreen', 'banner', 'small_banner', 'header', 'popup', 'interstitial'], default: 'banner' },
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

const paymentSettingsSchema = mongoose.Schema({
    upiId: { type: String, default: '' },
    payeeName: { type: String, default: '' },
    bankAccountName: { type: String, default: '' },
    bankAccountNumber: { type: String, default: '' },
    bankIfscCode: { type: String, default: '' },
    bankName: { type: String, default: '' },
    adminPhone: { type: String, default: '' },
    qrImageUrl: { type: String, default: '' },
    updatedAt: { type: Date, default: Date.now }
});

// SafeChild — pre-registered children with AI face descriptors
const preRegisteredChildSchema = mongoose.Schema({
    parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    childName: { type: String, required: true },
    age: { type: Number },
    gender: { type: String, default: '' },
    address: { type: String, default: '' },
    parentContact: { type: String, default: '' },
    medicalInfo: { type: String, default: '' },
    photoUrl: { type: String, default: '' },
    faceDescriptor: { type: [Number], required: true }, // 128D face descriptor array
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// NGO Contact — centrally managed contact numbers for the application
const ngoContactSchema = mongoose.Schema({
    displayName: { type: String, required: true, trim: true },
    organization: { type: String, default: '' },
    phone: { type: String, required: true },
    whatsapp: { type: String, default: '' },
    label: { type: String, default: '' },
    description: { type: String, default: '' },
    priority: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    primary: { type: Boolean, default: false },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'AdminUser' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
ngoContactSchema.index({ active: 1, priority: -1 });

// Audit log — lightweight admin action tracking
const auditLogSchema = mongoose.Schema({
    action: { type: String, required: true },
    entityType: { type: String, default: '' },
    entityId: { type: mongoose.Schema.Types.ObjectId },
    performedBy: { type: String, default: '' },
    details: { type: mongoose.Schema.Types.Mixed },
    createdAt: { type: Date, default: Date.now }
});
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ entityType: 1, createdAt: -1 });

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
            const AdminUser = mongoose.models.AdminUser || mongoose.model('AdminUser', adminUserSchema);
            const PageContent = mongoose.models.PageContent || mongoose.model('PageContent', pageContentSchema);
            const LegalPage = mongoose.models.LegalPage || mongoose.model('LegalPage', legalPageSchema);
            const Revenue = mongoose.models.Revenue || mongoose.model('Revenue', revenueSchema);
            const PaymentSettings = mongoose.models.PaymentSettings || mongoose.model('PaymentSettings', paymentSettingsSchema);
            const PreRegisteredChild = mongoose.models.PreRegisteredChild || mongoose.model('PreRegisteredChild', preRegisteredChildSchema);
            const NGOContact = mongoose.models.NGOContact || mongoose.model('NGOContact', ngoContactSchema);
            const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', auditLogSchema);
            // Seed default payment settings if none exist
            const psCount = await PaymentSettings.countDocuments();
            if (psCount === 0) {
                await PaymentSettings.create({});
            }
            return { Child: db.data, User, FoundRequest, Praise, Gift, Donation, Analytics, Advertisement, AdminUser, PageContent, LegalPage, Revenue, PaymentSettings, PreRegisteredChild, NGOContact, AuditLog };
        })();
    }
    return modelsPromise;
};

module.exports = getModels;
