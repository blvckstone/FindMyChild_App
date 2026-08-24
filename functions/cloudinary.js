const cloudinary = require('cloudinary').v2;
const path = require('path');

// Configure Cloudinary from environment
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const FOLDER = 'fmc-children'; // single folder for all child images (saves storage)

/**
 * Upload an image file to Cloudinary.
 * Returns the secure URL string, or empty string on failure.
 * Optimised: auto quality, max 800px wide, webp preferred — keeps storage lean.
 */
const uploadImage = async (file) => {
    if (!file) return '';
    try {
        // Upload from buffer (express-fileupload gives us file.data)
        const result = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                {
                    folder: FOLDER,
                    resource_type: 'image',
                    transformation: [
                        { width: 800, height: 800, crop: 'limit' },  // cap dimensions
                        { quality: 'auto:good' },                       // auto compress
                        { fetch_format: 'auto' },                       // serve webp/avif when supported
                    ],
                    public_id: `child_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
                },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(file.data);
        });
        return result.secure_url;
    } catch (err) {
        console.error('Cloudinary upload error:', err.message);
        return '';
    }
};

/**
 * Delete an image by its full Cloudinary URL.
 * Safe to call with empty string or null (no-op).
 */
const deleteImage = async (imageUrl) => {
    if (!imageUrl) return;
    try {
        const publicId = extractPublicId(imageUrl);
        if (publicId) {
            await cloudinary.uploader.destroy(publicId, { resource_type: 'image' });
        }
    } catch (err) {
        console.error('Cloudinary delete error:', err.message);
    }
};

/**
 * Replace an image: upload new, delete old.
 * Returns the new URL (or old URL if upload failed).
 */
const replaceImage = async (oldImageUrl, newFile) => {
    if (!newFile) return oldImageUrl || '';
    const newUrl = await uploadImage(newFile);
    if (newUrl && oldUrlIsCloudinary(oldImageUrl)) {
        await deleteImage(oldImageUrl);
    }
    return newUrl || oldImageUrl || '';
};

/**
 * Extract Cloudinary public_id from a full URL.
 * e.g. "https://res.cloudinary.com/ugt7qiyn/image/upload/v123/fmc-children/child_xxx.webp"
 *   => "fmc-children/child_xxx"
 */
const extractPublicId = (url) => {
    if (!url || typeof url !== 'string') return null;
    // Match the pattern after /upload/ and before the file extension
    const match = url.match(/\/upload\/(?:v\d+\/)?(.+?)\.[^.]+$/);
    return match ? match[1] : null;
};

const oldUrlIsCloudinary = (url) => {
    return url && typeof url === 'string' && url.includes('res.cloudinary.com');
};

module.exports = { uploadImage, deleteImage, replaceImage, extractPublicId };
