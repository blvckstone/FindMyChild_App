const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { PUBLIC_CHILD_FIELDS } = require('../publicProjection');

const MAX_PAGE_SIZE = 100;

const getByAddressData = async (searchingAddress, { page = 1, limit = 50 } = {}) => {
    const safeLimit = Math.min(Math.max(1, parseInt(limit) || 50), MAX_PAGE_SIZE);
    const safePage = Math.max(1, parseInt(page) || 1);
    const skip = (safePage - 1) * safeLimit;

    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const filter = { "address": { $regex: String(searchingAddress || '').slice(0, 200), $options: "i" }, status: 'approved' };
            const [data, total] = await Promise.all([
                Child.find(filter).select(PUBLIC_CHILD_FIELDS).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(safeLimit).lean(),
                Child.countDocuments(filter)
            ]);
            return { success: true, error: false, message: "Successfully found data!", data, total, page: safePage, limit: safeLimit, pages: Math.ceil(total / safeLimit) };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    return { success: false, error: true, message: "Child records are temporarily unavailable. Please try again shortly.", data: [] };
};

module.exports = getByAddressData;
