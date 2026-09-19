const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { PUBLIC_CHILD_FIELDS } = require('../publicProjection');

const MAX_PAGE_SIZE = 100;

// Literal-text search helpers live in functions/textSearch.js so every filter in the app
// escapes user input the same way.
const { escapeRegex, searchRegex } = require('../textSearch');

const buildFilter = ({ found, gender, ageMin, ageMax, q } = {}) => {
    const filter = { status: 'approved' };

    if (found !== undefined && found !== null && found !== '' && found !== 'all') {
        filter.found = found === true || found === 'true';
    }

    const genderSearch = searchRegex(gender, 20);
    if (genderSearch) filter.gender = genderSearch;

    const minAge = Number(ageMin);
    const maxAge = Number(ageMax);
    if (Number.isFinite(minAge) && minAge > 0) filter.age = { $gte: minAge };
    if (Number.isFinite(maxAge) && maxAge > 0) filter.age = { ...(filter.age || {}), $lte: maxAge };

    const textSearch = searchRegex(q, 100);
    if (textSearch) {
        filter.$or = [{ fullName: textSearch }, { address: textSearch }, { state: textSearch }, { missingLocation: textSearch }];
    }

    return filter;
};

const buildSort = (sortBy) => {
    if (sortBy === 'oldest') return { createdAt: 1, _id: 1 };
    if (sortBy === 'name') return { fullName: 1, _id: 1 };
    if (sortBy === 'age') return { age: 1, _id: 1 };
    return { createdAt: -1, _id: -1 };
};

const getAllData = async ({ page = 1, limit = 50, ...filters } = {}) => {
    const safeLimit = Math.min(Math.max(1, parseInt(limit) || 50), MAX_PAGE_SIZE);
    const safePage = Math.max(1, parseInt(page) || 1);
    const skip = (safePage - 1) * safeLimit;

    const responseObj = await fmcConnectMongoDB();

    if (responseObj.success) {
        const Child = responseObj.data;
        try {
            const filter = buildFilter(filters);
            const [data, total] = await Promise.all([
                Child.find(filter).select(PUBLIC_CHILD_FIELDS).sort(buildSort(filters.sortBy)).skip(skip).limit(safeLimit).lean(),
                Child.countDocuments(filter)
            ]);
            return { success: true, error: false, message: "Successfully found data!", data, total, page: safePage, limit: safeLimit, pages: Math.max(1, Math.ceil(total / safeLimit)) };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    return { success: false, error: true, message: "Child records are temporarily unavailable. Please try again shortly.", data: [] };
};

module.exports = getAllData;
module.exports.buildFilter = buildFilter;
module.exports.buildSort = buildSort;
module.exports.escapeRegex = escapeRegex;
