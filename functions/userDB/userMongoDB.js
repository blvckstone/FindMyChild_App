const mongoose = require('mongoose');
require('dotenv').config();

const dataSchemaUser = mongoose.Schema({
    userFullName: String,
    userContactNumber: { type: String, unique: true },
    password: String,
    emailId: String,
    createdAt: String,
});

// Cache the connection so we only connect to the database once.
let connectionPromise = null;

const connectMongoDB = async () => {
    if (!connectionPromise) {
        connectionPromise = mongoose.connect(process.env.DB_ATLAS)
            .then(() => {
                console.log("Connected to User Database successfully");
                const User = mongoose.models.User || mongoose.model('User', dataSchemaUser);
                return { success: true, error: false, message: "Successfully fetched model!", data: User };
            })
            .catch((error) => {
                console.error("User database connection error:", error.message);
                connectionPromise = null; // allow retry on next call
                return { success: false, error: true, message: "Error during fetching model!", data: error };
            });
    }

    return connectionPromise;
};

module.exports = connectMongoDB;
