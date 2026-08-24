const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { getByNameDemo } = require('../demoData/demoData');

const getByNameData = async (searchingName) => {
    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const data = await Child.find({ "fullName": { $regex: searchingName, $options: "i" }, status: 'approved' });
            return { success: true, error: false, message: "Successfully found data!", data };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    console.warn("Database unavailable — returning demo data for 'getByNameData'");
    return getByNameDemo(searchingName);
};

module.exports = getByNameData;
