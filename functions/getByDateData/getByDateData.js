const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { getByDateDemo } = require('../demoData/demoData');

const getByDateData = async (searchingDate) => {
    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const data = await Child.find({ "missingDate": { $eq: searchingDate }, status: 'approved' });
            return { success: true, error: false, message: "Successfully found data!", data };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    console.warn("Database unavailable — returning demo data for 'getByDateData'");
    return getByDateDemo(searchingDate);
};

module.exports = getByDateData;
