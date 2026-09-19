const mongoose = require('mongoose');
require('dotenv').config();

const dataSchema = mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    fullName: String,
    address: String,
    contactNumber: String,
    uploadedBy: String,
    state: String,
    found: Boolean,
    image: String,
    missingDate: String,
    missingTime: String,
    gender: String,
    age: Number,
    info: String,
    disability: String,
    missingLocation: String,
    missingDateTime: String,
    foundLocation: String,
    finderName: String,
    finderContact: String,
    finderUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    foundDate: Date,
    disabilityInfo: String,
    faceDescriptor: { type: [Number], default: [] },
    contactNumberConsent: { type: Boolean, default: false },
    contactNumberConsentDate: { type: Date },
    ngoContacts: [{ ngoId: { type: mongoose.Schema.Types.ObjectId, ref: 'NGOContact' }, displayName: String, phone: String, whatsapp: String, label: String, description: String, organization: String }],
    // pending = waiting for admin approval, approved = visible publicly, rejected = denied
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
}, { timestamps: true });
// Public listing, admin lists and pagination all filter status then sort by createdAt/_id.
dataSchema.index({ status: 1, createdAt: -1, _id: -1 });
// Found/missing tabs, stat counters and the found filter.
dataSchema.index({ status: 1, found: 1, createdAt: -1 });
// Search filters.
dataSchema.index({ status: 1, gender: 1 });
dataSchema.index({ status: 1, age: 1 });
dataSchema.index({ status: 1, missingDate: 1 });
// "My reports" and the admin user-activity view.
dataSchema.index({ userId: 1, createdAt: -1 });
// Praise/gift self-action checks compare finderUserId.
dataSchema.index({ finderUserId: 1 });
// Existing text index — left exactly as-is: MongoDB allows only one text index per
// collection, so changing its fields would require a drop + rebuild on the live database.
dataSchema.index({ fullName: 'text', address: 'text', contactNumber: 'text' });

// Cache the connection so we only connect to the database once.
let connectionPromise = null;

const connectMongoDB = async () => {
    if (!connectionPromise) {
        connectionPromise = mongoose.connect(process.env.DB_ATLAS)
            .then(async () => {
                console.log("Connected to Database successfully");
                const Child = mongoose.models.Child || mongoose.model('Child', dataSchema);
                // Existing records were created before the status field existed — treat them as approved.
                await Child.updateMany({ status: { $exists: false } }, { $set: { status: 'approved' } });
                // Fix: drop old non-sparse unique index on userContactNumber so multiple nulls are allowed
                try {
                    const User = mongoose.models.User;
                    if (User) {
                        const indexes = await User.collection.indexes();
                        const badIdx = indexes.find(i => i.key && i.key.userContactNumber === 1 && !i.sparse);
                        if (badIdx) {
                            await User.collection.dropIndex(badIdx.name);
                            console.log('Dropped old non-sparse userContactNumber index');
                        }
                    }
                } catch (e) { /* index may not exist */ }
                return { success: true, error: false, message: "Successfully fetched model!", data: Child };
            })
            .catch((error) => {
                console.error("Database connection error:", error.message);
                connectionPromise = null; // allow retry on next call
                return { success: false, error: true, message: "Error during fetching model!", data: error };
            });
    }

    return connectionPromise;
};

module.exports = connectMongoDB;
