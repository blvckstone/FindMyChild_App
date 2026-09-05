const crypto = require('crypto');
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);
const fromAddress = process.env.EMAIL_FROM || 'Find My Child <onboarding@resend.dev>';
const otpStore = new Map();
const requestStore = new Map();
const ipRequestStore = new Map();
const OTP_TTL = 10 * 60 * 1000;
const COOLDOWN = 60 * 1000;
const REQUEST_WINDOW = 15 * 60 * 1000;
const MAX_REQUESTS = 3;
const MAX_ATTEMPTS = 5;

const normalizeEmail = email => String(email || '').trim().toLowerCase();
const cleanupRequests = now => {
    for (const store of [requestStore, ipRequestStore]) {
        for (const [key, timestamps] of store) {
            const recent = timestamps.filter(ts => now - ts < REQUEST_WINDOW);
            if (recent.length) store.set(key, recent);
            else store.delete(key);
        }
    }
};

const generateOTP = () => String(crypto.randomInt(100000, 1000000));

const sendOTP = async (email, { ip = 'unknown' } = {}) => {
    const normalizedEmail = normalizeEmail(email);
    const now = Date.now();
    cleanupRequests(now);
    const emailHistory = requestStore.get(normalizedEmail) || [];
    const lastEmailRequest = emailHistory[emailHistory.length - 1] || 0;
    if (now - lastEmailRequest < COOLDOWN) {
        return { success: false, error: 'Please wait 60 seconds before requesting another OTP.', retryAfter: Math.ceil((COOLDOWN - (now - lastEmailRequest)) / 1000) };
    }
    if (emailHistory.length >= MAX_REQUESTS) {
        return { success: false, error: 'Too many OTP requests. Please try again later.' };
    }
    const ipKey = `ip:${String(ip)}`;
    const requestKey = `${String(ip)}:${normalizedEmail}`;
    const ipHistory = ipRequestStore.get(ipKey) || [];
    const requestHistory = requestStore.get(requestKey) || [];
    if (ipHistory.length >= MAX_REQUESTS || requestHistory.length >= MAX_REQUESTS) {
        return { success: false, error: 'Too many OTP requests. Please try again later.' };
    }

    const code = generateOTP();
    const entry = { code, expiresAt: now + OTP_TTL, attempts: 0 };
    otpStore.set(normalizedEmail, entry);
    requestStore.set(normalizedEmail, [...emailHistory, now]);
    ipRequestStore.set(ipKey, [...ipHistory, now]);
    requestStore.set(requestKey, [...requestHistory, now]);

    try {
        await resend.emails.send({
            from: fromAddress,
            to: normalizedEmail,
            subject: 'Your Find My Child verification code',
            html: `<!doctype html><html><body style="margin:0;background:#f5f5f7;font-family:Arial,sans-serif;color:#1d1d1f;padding:24px 12px"><div style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #e5e5ea;border-radius:18px;overflow:hidden;box-shadow:0 4px 18px rgba(0,0,0,.08)"><div style="background:#1d1d1f;color:#fff;padding:24px 28px"><div style="font-size:20px;font-weight:800">Gumshuda Bacho Ki Talash</div><div style="font-size:13px;color:rgba(255,255,255,.65);margin-top:5px">Find My Child</div></div><div style="padding:30px 28px;text-align:center"><h2 style="margin:0 0 10px;font-size:22px;color:#1d1d1f">Verify your email</h2><p style="margin:0;color:#636366;font-size:14px;line-height:1.6">Use the verification code below to complete your Find My Child signup.</p><div style="margin:24px 0;background:#f0f7ff;border-radius:12px;padding:14px;color:#0071e3;font:bold 32px/1 monospace;letter-spacing:6px">${code}</div><p style="margin:0;color:#636366;font-size:13px">Valid for 10 minutes.</p><p style="margin:18px 0 0;color:#636366;font-size:12px;line-height:1.6">Do not share this OTP with anyone. If you did not request this, please ignore this email.</p></div></div></body></html>`
        });
        return { success: true };
    } catch (e) {
        otpStore.delete(normalizedEmail);
        return { success: false, error: 'Failed to send email.' };
    }
};

const verifyOTP = (email, code) => {
    const normalizedEmail = normalizeEmail(email);
    const entry = otpStore.get(normalizedEmail);
    if (!entry) return { valid: false, error: 'No OTP found.' };
    if (Date.now() > entry.expiresAt) {
        otpStore.delete(normalizedEmail);
        return { valid: false, error: 'OTP expired.' };
    }
    if (entry.code !== String(code).trim()) {
        entry.attempts += 1;
        if (entry.attempts >= MAX_ATTEMPTS) {
            otpStore.delete(normalizedEmail);
            return { valid: false, error: 'Too many invalid attempts. Please request a new OTP.' };
        }
        return { valid: false, error: `Invalid OTP. ${MAX_ATTEMPTS - entry.attempts} attempts remaining.` };
    }
    otpStore.delete(normalizedEmail);
    return { valid: true };
};

const sendWelcomeEmail = async (email, name) => {
    try {
        await resend.emails.send({
            from: fromAddress,
            to: email,
            subject: 'Welcome to Find My Child!',
            html: '<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;text-align:center"><h2 style="color:#1d1d1f">Welcome, ' + String(name || '').replace(/[<>]/g, '') + '!</h2><p style="color:#636366;line-height:1.6">Thank you for joining. Together we help reunite missing children with their families.</p></div>'
        });
    } catch (e) { /* non-critical */ }
};

module.exports = { sendOTP, verifyOTP, sendWelcomeEmail, normalizeEmail };
