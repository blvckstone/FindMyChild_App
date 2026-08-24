const mongoose = require('mongoose');
require('dotenv').config();

const dataSchema = mongoose.Schema({
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
    finderUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    foundDate: Date,
    disabilityInfo: String,
    // pending = waiting for admin approval, approved = visible publicly, rejected = denied
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
});

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
