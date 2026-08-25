const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM = process.env.EMAIL_FROM || 'FindMyChild <onboarding@resend.dev>';
const otpStore = new Map();

const generateOTP = () => String(Math.floor(100000 + Math.random() * 900000));

const sendOTP = async (email) => {
    const code = generateOTP();
    otpStore.set(email, { code, expiresAt: Date.now() + 10 * 60 * 1000 });
    try {
        await resend.emails.send({
            from: FROM, to: email,
            subject: 'Your FindMyChild verification code',
            html: '<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;text-align:center"><h2>Find My Child</h2><p>Your verification code:</p><div style="background:#f5f5f7;border-radius:12px;padding:20px;margin:20px 0"><span style="font-size:32px;font-weight:800;letter-spacing:8px">' + code + '</span></div><p style="color:#999;font-size:13px">Expires in 10 minutes. Ignore if you didn\'t request this.</p></div>'
        });
        return { success: true };
    } catch (e) {
        return { success: false, error: 'Failed to send email.' };
    }
};

const verifyOTP = (email, code) => {
    const entry = otpStore.get(email);
    if (!entry) return { valid: false, error: 'No OTP found.' };
    if (Date.now() > entry.expiresAt) { otpStore.delete(email); return { valid: false, error: 'OTP expired.' }; }
    if (entry.code !== String(code).trim()) return { valid: false, error: 'Invalid OTP.' };
    otpStore.delete(email);
    return { valid: true };
};

const sendWelcomeEmail = async (email, name) => {
    try {
        await resend.emails.send({
            from: FROM, to: email, subject: 'Welcome to Find My Child!',
            html: '<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;text-align:center"><h2>Welcome, ' + name + '!</h2><p>Thank you for joining. Together we help reunite missing children with their families.</p></div>'
        });
    } catch (e) { /* non-critical */ }
};

module.exports = { sendOTP, verifyOTP, sendWelcomeEmail };
