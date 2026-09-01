const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { getAllDemo } = require('../demoData/demoData');

const getAllData = async () => {
    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const data = await Child.find({ status: 'approved' }).select('-faceDescriptor -userId -uploadedBy').lean();
            return { success: true, error: false, message: "Successfully found data!", data };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    console.warn("Database unavailable — returning demo data for 'getAllData'");
    return getAllDemo();
};

module.exports = getAllData;
