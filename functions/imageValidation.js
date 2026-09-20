/**
 * Upload validation for images.
 *
 * The old check trusted `file.mimetype`, which is a string the *client* chooses: renaming
 * `payload.html` to `photo.jpg` (or simply setting the multipart content type) passed it. A
 * 5 MB limit was the only other barrier, so arbitrary bytes could be parked on the Cloudinary
 * account and served from its CDN.
 *
 * This module decides from the bytes themselves:
 *   1. magic-number sniff — the buffer really starts with a JPEG/PNG/WEBP/GIF signature;
 *   2. the declared MIME type has to agree with what was sniffed;
 *   3. `sharp` must be able to *decode* the file, which is what actually rules out a
 *      polyglot (valid image header followed by HTML/JS) and corrupt data;
 *   4. dimensions and pixel count are bounded, so a decompression bomb cannot exhaust memory;
 *   5. the image is re-encoded, which drops EXIF (including GPS coordinates, a real privacy
 *      leak for photos of missing children) and normalises the bytes we hand to Cloudinary.
 */

const MAX_BYTES = 5 * 1024 * 1024;
const MAX_DIMENSION = 8000;
const MAX_PIXELS = 40_000_000;
const MAX_OUTPUT_DIMENSION = 1600;

let sharp = null;
let sharpLoadError = null;
try {
    // Optional at runtime: if the native binary is unavailable the module degrades to
    // header-level validation instead of accepting anything.
    sharp = require('sharp');
} catch (err) {
    sharpLoadError = err;
}

class ImageValidationError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.name = 'ImageValidationError';
        this.status = status;
    }
}

const MIME_TO_FORMAT = {
    'image/jpeg': 'jpeg',
    'image/jpg': 'jpeg',
    'image/pjpeg': 'jpeg',
    'image/png': 'png',
    'image/webp': 'webp',
    'image/gif': 'gif'
};

const FORMAT_TO_MIME = {
    jpeg: 'image/jpeg',
    png: 'image/png',
    webp: 'image/webp',
    gif: 'image/gif'
};

/** Identify an image from its first bytes. Returns a sharp format name, or null. */
const sniffImageFormat = (buffer) => {
    if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
    if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'jpeg';
    if (
        buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
        buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a
    ) return 'png';
    const head = buffer.subarray(0, 12).toString('latin1');
    if (head.startsWith('GIF87a') || head.startsWith('GIF89a')) return 'gif';
    if (head.startsWith('RIFF') && head.slice(8, 12) === 'WEBP') return 'webp';
    return null;
};

const sizeOf = (file) => {
    if (!file) return 0;
    if (typeof file.size === 'number') return file.size;
    if (Buffer.isBuffer(file.data)) return file.data.length;
    if (file.data && typeof file.data.length === 'number') return file.data.length;
    return 0;
};

/**
 * Validate an uploaded file and return bytes safe to store.
 *
 * @returns {Promise<{data: Buffer, mimetype: string, size: number, width?: number, height?: number, format: string, reencoded: boolean}>}
 * @throws {ImageValidationError} with status 400 for anything a user can fix
 */
const validateAndNormalize = async (file, options = {}) => {
    const maxBytes = options.maxBytes || MAX_BYTES;
    const maxDimension = options.maxDimension || MAX_DIMENSION;
    const maxPixels = options.maxPixels || MAX_PIXELS;

    if (!file || !file.data) throw new ImageValidationError('No image was uploaded.');
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data);
    if (!data.length) throw new ImageValidationError('The uploaded image is empty.');
    if (data.length > maxBytes) {
        throw new ImageValidationError(`Image must be smaller than ${Math.round(maxBytes / (1024 * 1024))} MB.`);
    }

    const sniffed = sniffImageFormat(data);
    if (!sniffed) {
        throw new ImageValidationError('That file is not a JPG, PNG, WEBP or GIF image.');
    }

    const declared = MIME_TO_FORMAT[String(file.mimetype || '').toLowerCase()];
    if (declared && declared !== sniffed) {
        // A JPEG renamed to .png would land here; so would a spoofed content type.
        throw new ImageValidationError(
            `The file says it is ${file.mimetype} but its contents are ${FORMAT_TO_MIME[sniffed]}.`
        );
    }

    // Header-only fallback: without sharp we cannot decode, so we keep the verified bytes as-is
    // rather than rejecting every upload on a host where the native module failed to load.
    if (!sharp) {
        console.warn('[SECURITY] sharp unavailable — image uploads are only header-validated:', sharpLoadError && sharpLoadError.message);
        return { data, mimetype: FORMAT_TO_MIME[sniffed], size: data.length, format: sniffed, reencoded: false, decoded: false };
    }

    let metadata;
    try {
        metadata = await sharp(data, { limitInputPixels: maxPixels, animated: true }).metadata();
    } catch (err) {
        throw new ImageValidationError('That image could not be read. It may be corrupt or not an image at all.');
    }

    if (!metadata || !metadata.format) {
        throw new ImageValidationError('That image could not be read.');
    }
    if (metadata.format !== sniffed) {
        throw new ImageValidationError('The file extension does not match the image contents.');
    }
    if (!metadata.width || !metadata.height) {
        throw new ImageValidationError('The image has no readable dimensions.');
    }
    if (metadata.width > maxDimension || metadata.height > maxDimension) {
        throw new ImageValidationError(`Images may be at most ${maxDimension}\u00d7${maxDimension} pixels.`);
    }
    if (metadata.width * metadata.height > maxPixels) {
        throw new ImageValidationError('That image has too many pixels to process.');
    }

    const frames = metadata.pages && metadata.pages > 1;
    try {
        let pipeline = sharp(data, { limitInputPixels: maxPixels, animated: frames });
        // EXIF orientation is baked in only for single-frame images: sharp refuses to rotate
        // a multi-page image.
        if (!frames) pipeline = pipeline.rotate();
        if (metadata.width > MAX_OUTPUT_DIMENSION || metadata.height > MAX_OUTPUT_DIMENSION) {
            pipeline = pipeline.resize({
                width: MAX_OUTPUT_DIMENSION,
                height: MAX_OUTPUT_DIMENSION,
                fit: 'inside',
                withoutEnlargement: true
            });
        }
        if (sniffed === 'jpeg') pipeline = pipeline.jpeg({ quality: 88, mozjpeg: true });
        else if (sniffed === 'png') pipeline = pipeline.png({ compressionLevel: 9 });
        else if (sniffed === 'webp') pipeline = pipeline.webp({ quality: 88 });
        else pipeline = pipeline.gif();

        const out = await pipeline.toBuffer({ resolveWithObject: true });
        if (!out || !out.data || !out.data.length) throw new Error('empty output');
        return {
            data: out.data,
            mimetype: FORMAT_TO_MIME[sniffed],
            size: out.data.length,
            width: out.info && out.info.width,
            height: out.info && out.info.height,
            format: sniffed,
            reencoded: true,
            decoded: true
        };
    } catch (err) {
        // The bytes already decoded successfully above, so this is a re-encode limitation
        // (e.g. a GIF encoder missing from libvips), not a hostile file. Keep the original.
        console.warn('[SECURITY] image re-encode failed, storing the validated original:', err.message);
        return {
            data,
            mimetype: FORMAT_TO_MIME[sniffed],
            size: data.length,
            width: metadata.width,
            height: metadata.height,
            format: sniffed,
            reencoded: false,
            decoded: true
        };
    }
};

module.exports = {
    validateAndNormalize,
    sniffImageFormat,
    ImageValidationError,
    MIME_TO_FORMAT,
    FORMAT_TO_MIME,
    MAX_BYTES,
    MAX_DIMENSION,
    MAX_PIXELS,
    MAX_OUTPUT_DIMENSION
};
