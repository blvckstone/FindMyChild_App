const crypto = require('crypto');

// Hash a password: scrypt$<salt>$<hash> (64-byte hash, hex)
const hashPassword = (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return `scrypt$${salt}$${hash}`;
};

const verifyPassword = (password, stored) => {
    if (!stored) return false;
    if (String(stored).startsWith('scrypt$')) {
        const [, salt, hash] = String(stored).split('$');
        const test = crypto.scryptSync(String(password), salt, 64).toString('hex');
        const a = Buffer.from(test, 'hex');
        const b = Buffer.from(hash, 'hex');
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
    }
    // Legacy plaintext passwords stored before hashing was introduced.
    const a = Buffer.from(String(password));
    const b = Buffer.from(String(stored));
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
};

module.exports = { hashPassword, verifyPassword };
