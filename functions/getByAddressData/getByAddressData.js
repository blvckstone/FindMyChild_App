const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { getByAddressDemo } = require('../demoData/demoData');

const getByAddressData = async (searchingAddress) => {
    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const data = await Child.find({ "address": { $regex: searchingAddress, $options: "i" }, status: 'approved' });
            return { success: true, error: false, message: "Successfully found data!", data };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    console.warn("Database unavailable — returning demo data for 'getByAddressData'");
    return getByAddressDemo(searchingAddress);
};

module.exports = getByAddressData;
