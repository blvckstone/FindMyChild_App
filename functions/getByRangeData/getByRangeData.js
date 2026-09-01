const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { getByRangeDemo } = require('../demoData/demoData');
const { PUBLIC_CHILD_FIELDS } = require('../publicProjection');

const getByRangeData = async (obj) => {
    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const data = await Child.find({
                "missingDate": { $gte: obj.searchingDateFrom, $lte: obj.searchingDateTo },
                status: 'approved'
            }).select(PUBLIC_CHILD_FIELDS).lean();
            return { success: true, error: false, message: "Successfully found data!", data };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    console.warn("Database unavailable — returning demo data for 'getByRangeData'");
    return getByRangeDemo(obj);
};

module.exports = getByRangeData;
