// Sample records used ONLY when the MongoDB database cannot be reached,
// so the dashboard is still viewable. Remove this fallback (or it simply
// never triggers) once a working DB_ATLAS is configured.
const demoRecords = [
    {
        fullName: "Ayesha Khan",
        address: "Model Town, Lahore",
        contactNumber: "03001234567",
        uploadedBy: "Demo Admin",
        state: "Punjab",
        found: false,
        image: "",
        missingDate: "2026-07-15",
        missingTime: "14:30",
        gender: "Female",
        age: 7,
        info: "Was last seen near the park wearing a red dress.",
        disability: "None",
        missingLocation: "Model Town Park, Lahore",
        missingDateTime: "2026-07-15 14:30",
        foundLocation: "",
        disabilityInfo: ""
    },
    {
        fullName: "Hassan Ali",
        address: "Gulshan-e-Iqbal, Karachi",
        contactNumber: "03119876543",
        uploadedBy: "Demo Admin",
        state: "Sindh",
        found: true,
        image: "",
        missingDate: "2026-06-02",
        missingTime: "18:10",
        gender: "Male",
        age: 10,
        info: "Found safe and returned home.",
        disability: "None",
        missingLocation: "Gulshan Chowrangi, Karachi",
        missingDateTime: "2026-06-02 18:10",
        foundLocation: "Saddar Police Station, Karachi",
        disabilityInfo: ""
    },
    {
        fullName: "Fatima Bibi",
        address: "Satellite Town, Rawalpindi",
        contactNumber: "03335551234",
        uploadedBy: "Demo Admin",
        state: "Punjab",
        found: false,
        image: "",
        missingDate: "2026-08-01",
        missingTime: "11:00",
        gender: "Female",
        age: 5,
        info: "Hearing impaired. Last seen near the bus stop.",
        disability: "Hearing impaired",
        missingLocation: "6th Road, Satellite Town",
        missingDateTime: "2026-08-01 11:00",
        foundLocation: "",
        disabilityInfo: "Needs sign language to communicate."
    },
    {
        fullName: "Bilal Ahmed",
        address: "F-8, Islamabad",
        contactNumber: "03451234567",
        uploadedBy: "Demo Admin",
        state: "Islamabad",
        found: false,
        image: "",
        missingDate: "2026-05-20",
        missingTime: "16:45",
        gender: "Male",
        age: 12,
        info: "Was wearing a blue school uniform.",
        disability: "None",
        missingLocation: "F-8 Markaz, Islamabad",
        missingDateTime: "2026-05-20 16:45",
        foundLocation: "",
        disabilityInfo: ""
    }
];

const demoResponse = (data, message) => ({
    success: true,
    error: false,
    demo: true,
    message: message || "Demo data (database unavailable)",
    data
});

const getAllDemo = () => demoResponse(demoRecords, "Demo data (database unavailable)");

const getByNameDemo = (name) => {
    const filtered = demoRecords.filter((r) =>
        r.fullName.toLowerCase().includes(String(name || "").toLowerCase())
    );
    return demoResponse(filtered, `Demo data (database unavailable) — ${filtered.length} match(es) for "${name}"`);
};

const getByDateDemo = (date) => {
    const filtered = demoRecords.filter((r) => r.missingDate === String(date));
    return demoResponse(filtered, `Demo data (database unavailable) — ${filtered.length} match(es) for "${date}"`);
};

const getByAddressDemo = (address) => {
    const filtered = demoRecords.filter((r) =>
        (r.address || "").toLowerCase().includes(String(address || "").toLowerCase())
    );
    return demoResponse(filtered, `Demo data (database unavailable) — ${filtered.length} match(es) for "${address}"`);
};

const getByRangeDemo = (obj) => {
    const from = obj && obj.searchingDateFrom;
    const to = obj && obj.searchingDateTo;
    const filtered = demoRecords.filter((r) => r.missingDate >= from && r.missingDate <= to);
    return demoResponse(filtered, `Demo data (database unavailable) — ${filtered.length} match(es) in range ${from} → ${to}`);
};

const getBySearchDemo = ({ query, age, gender } = {}) => {
    let filtered = demoRecords.slice();
    if (query) {
        const q = String(query).toLowerCase();
        filtered = filtered.filter((r) =>
            [r.fullName, r.address, r.state, r.missingLocation, r.gender, r.info, r.disability]
                .filter(Boolean)
                .some((f) => f.toLowerCase().includes(q)) ||
            (!isNaN(Number(q)) && r.age === Number(q))
        );
    }
    if (age && !isNaN(Number(age))) filtered = filtered.filter((r) => r.age === Number(age));
    if (gender) filtered = filtered.filter((r) =>
        (r.gender || "").toLowerCase().includes(String(gender).toLowerCase())
    );
    return demoResponse(filtered, `Demo data (database unavailable) — ${filtered.length} match(es)`);
};

module.exports = {
    getAllDemo,
    getByNameDemo,
    getByDateDemo,
    getByAddressDemo,
    getByRangeDemo,
    getBySearchDemo
};
