const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { PUBLIC_CHILD_FIELDS } = require('../publicProjection');

const MAX_PAGE_SIZE = 100;

const getBySearchData = async ({ query, age, gender, ageMin, ageMax, filter, sortBy, page, limit } = {}) => {
    const safeLimit = Math.min(Math.max(1, parseInt(limit) || 50), MAX_PAGE_SIZE);
    const safePage = Math.max(1, parseInt(page) || 1);
    const skip = (safePage - 1) * safeLimit;

    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const conditions = [];

            if (query && String(query).trim() !== "") {
                const q = String(query).trim().slice(0, 200);
                const regex = { $regex: q, $options: "i" };
                conditions.push({
                    $or: [
                        { fullName: regex },
                        { address: regex },
                        { state: regex },
                        { missingLocation: regex },
                        { gender: regex },
                        { info: regex },
                        { disability: regex }
                    ]
                });
                if (!isNaN(Number(q))) {
                    conditions.push({ age: Number(q) });
                }
            }

            if (age && !isNaN(Number(age))) {
                conditions.push({ age: Number(age) });
            }

            if (ageMin && !isNaN(Number(ageMin))) {
                conditions.push({ age: { $gte: Number(ageMin) } });
            }
            if (ageMax && !isNaN(Number(ageMax))) {
                conditions.push({ age: { $lte: Number(ageMax) } });
            }

            if (gender && String(gender).trim() !== "") {
                conditions.push({ gender: { $regex: String(gender).slice(0, 20), $options: "i" } });
            }

            if (filter === 'missing') {
                conditions.push({ found: false });
            } else if (filter === 'found') {
                conditions.push({ found: true });
            }

            if (filter === 'recent' || filter === 'week') {
                const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                conditions.push({ createdAt: { $gte: weekAgo } });
            }

            conditions.push({ status: 'approved' });

            const mongoFilter = conditions.length ? { $and: conditions } : {};

            // Build MongoDB sort
            let mongoSort = { createdAt: -1, _id: -1 };
            if (sortBy === 'oldest') mongoSort = { createdAt: 1, _id: 1 };
            else if (sortBy === 'name') mongoSort = { fullName: 1, _id: 1 };
            else if (sortBy === 'age') mongoSort = { age: 1, _id: 1 };

            const [data, total] = await Promise.all([
                Child.find(mongoFilter).select(PUBLIC_CHILD_FIELDS).sort(mongoSort).skip(skip).limit(safeLimit).lean(),
                Child.countDocuments(mongoFilter)
            ]);

            return { success: true, error: false, message: "Successfully found data!", data, total, page: safePage, limit: safeLimit, pages: Math.ceil(total / safeLimit) };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    return { success: false, error: true, message: "Child records are temporarily unavailable. Please try again shortly.", data: [] };
};

module.exports = getBySearchData;
