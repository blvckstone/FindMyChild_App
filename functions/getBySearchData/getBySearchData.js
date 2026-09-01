const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { getBySearchDemo } = require('../demoData/demoData');
const { PUBLIC_CHILD_FIELDS } = require('../publicProjection');

const getBySearchData = async ({ query, age, gender, ageMin, ageMax, filter, sortBy } = {}) => {
    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const conditions = [];

            if (query && String(query).trim() !== "") {
                const q = String(query).trim();
                const regex = { $regex: q, $options: "i" };
                conditions.push({
                    $or: [
                        { fullName: regex },
                        { address: regex },
                        { state: regex },
                        { missingLocation: regex },
                        { gender: regex },
                        { info: regex },
                        { disability: regex },
                        { contactNumber: regex }
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
                conditions.push({ gender: { $regex: String(gender), $options: "i" } });
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

            const data = await Child.find(conditions.length ? { $and: conditions } : {}).select(PUBLIC_CHILD_FIELDS).lean();

            let sorted = data;
            if (sortBy === 'oldest') {
                sorted.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
            } else if (sortBy === 'name') {
                sorted.sort((a, b) => (a.fullName || '').localeCompare(b.fullName || ''));
            } else if (sortBy === 'age') {
                sorted.sort((a, b) => (a.age || 0) - (b.age || 0));
            } else {
                sorted.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
            }

            return { success: true, error: false, message: "Successfully found data!", data: sorted };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    console.warn("Database unavailable — returning demo data for 'getBySearchData'");
    return getBySearchDemo({ query, age, gender });
};

module.exports = getBySearchData;
