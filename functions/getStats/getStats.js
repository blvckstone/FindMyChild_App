const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');

// Counters are computed in the database (one aggregation, index-assisted) so the
// figures stay correct no matter how many records exist.
const getStats = async () => {
    const responseObj = await fmcConnectMongoDB();
    if (!responseObj.success) {
        return { success: false, error: true, message: 'Child records are temporarily unavailable. Please try again shortly.', data: { total: 0, missing: 0, found: 0 } };
    }

    try {
        const Child = responseObj.data;
        const rows = await Child.aggregate([
            { $match: { status: 'approved' } },
            { $group: { _id: { $cond: ['$found', 'found', 'missing'] }, count: { $sum: 1 } } }
        ]);
        let missing = 0;
        let found = 0;
        for (const row of rows) {
            if (row._id === 'found') found = row.count;
            else missing = row.count;
        }
        return { success: true, error: false, message: 'Successfully counted records!', data: { missing, found, total: missing + found } };
    } catch (error) {
        return { success: false, error: true, message: 'Error while counting records!', data: { total: 0, missing: 0, found: 0 } };
    }
};

module.exports = getStats;
