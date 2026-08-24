const fmcConnectMongoDB = require('../fmcDB/fmcMongoDB');
const { getBySearchDemo } = require('../demoData/demoData');

const getBySearchData = async ({ query, age, gender } = {}) => {
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
                        { disability: regex }
                    ]
                });
                // If the query looks like a number, also match by age.
                if (!isNaN(Number(q))) {
                    conditions.push({ age: Number(q) });
                }
            }

            if (age && !isNaN(Number(age))) {
                conditions.push({ age: Number(age) });
            }

            if (gender && String(gender).trim() !== "") {
                conditions.push({ gender: { $regex: String(gender), $options: "i" } });
            }

            // Only approved records are visible to the public.
            conditions.push({ status: 'approved' });

            const data = await Child.find(conditions.length ? { $and: conditions } : {});
            return { success: true, error: false, message: "Successfully found data!", data };
        } catch (error) {
            return { success: false, error: true, message: "Error during fetching with database!", data: error };
        }
    }

    console.warn("Database unavailable — returning demo data for 'getBySearchData'");
    return getBySearchDemo({ query, age, gender });
};

module.exports = getBySearchData;
