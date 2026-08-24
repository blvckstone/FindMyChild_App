// Important messages / notices shown on the home page.
// These are editorial messages — edit this file to change them.
const messages = [
    {
        type: "alert",
        title: "Emergency: Call police immediately",
        body: "If you spot a missing child, do not approach them alone. Contact the nearest police station or the number on their card right away."
    },
    {
        type: "notice",
        title: "Report a missing child",
        body: "Have a missing child in your family? Fill the report form with a recent photo and full details so we can post it on this portal."
    },
    {
        type: "info",
        title: "Verified information only",
        body: "All child records are verified by our team before publishing. Please report any outdated or incorrect information to us."
    }
];

const getMessages = async () => {
    return { success: true, error: false, message: "Successfully found messages!", data: messages };
};

module.exports = getMessages;
