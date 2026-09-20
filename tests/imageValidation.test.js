// Upload validation: the decision must come from the bytes, not from the client's MIME type.
const test = require('node:test');
const assert = require('node:assert/strict');
const sharp = require('sharp');

const {
    validateAndNormalize,
    sniffImageFormat,
    ImageValidationError
} = require('../functions/imageValidation');

const makeImage = (format, width = 40, height = 30) => {
    let pipeline = sharp({ create: { width, height, channels: 3, background: { r: 120, g: 60, b: 200 } } });
    if (format === 'jpeg') return pipeline.jpeg().toBuffer();
    if (format === 'png') return pipeline.png().toBuffer();
    if (format === 'webp') return pipeline.webp().toBuffer();
    if (format === 'gif') return pipeline.gif().toBuffer();
    throw new Error(`unsupported test format ${format}`);
};

const asFile = (data, mimetype) => ({ data, mimetype, size: data.length });

test('sniffImageFormat identifies real images from their signature alone', async () => {
    assert.equal(sniffImageFormat(await makeImage('jpeg')), 'jpeg');
    assert.equal(sniffImageFormat(await makeImage('png')), 'png');
    assert.equal(sniffImageFormat(await makeImage('webp')), 'webp');
    assert.equal(sniffImageFormat(await makeImage('gif')), 'gif');
});

test('sniffImageFormat does not mistake text, HTML or empty data for an image', () => {
    assert.equal(sniffImageFormat(Buffer.from('<html><script>alert(1)</script></html>')), null);
    assert.equal(sniffImageFormat(Buffer.from('GIF89a-not-really')), 'gif'); // header-only: the decode below must catch it
    assert.equal(sniffImageFormat(Buffer.alloc(0)), null);
    assert.equal(sniffImageFormat(Buffer.from('RIFF____NOPE')), null);
    assert.equal(sniffImageFormat(null), null);
});

test('a text file wearing an image MIME type is refused', async () => {
    const payload = Buffer.from('<html><body>not an image at all</body></html>');
    await assert.rejects(
        () => validateAndNormalize(asFile(payload, 'image/jpeg')),
        (err) => err instanceof ImageValidationError && err.status === 400 && /not a JPG, PNG, WEBP or GIF/.test(err.message)
    );
});

test('a real image whose declared type disagrees with its contents is refused', async () => {
    const jpeg = await makeImage('jpeg');
    await assert.rejects(
        () => validateAndNormalize(asFile(jpeg, 'image/png')),
        (err) => err instanceof ImageValidationError && /contents are image\/jpeg/.test(err.message)
    );
});

test('a file that merely starts with a GIF header but cannot be decoded is refused', async () => {
    const fake = Buffer.concat([Buffer.from('GIF89a'), Buffer.alloc(64, 0x41)]);
    await assert.rejects(
        () => validateAndNormalize(asFile(fake, 'image/gif')),
        (err) => err instanceof ImageValidationError
    );
});

test('empty and oversized uploads are refused', async () => {
    await assert.rejects(
        () => validateAndNormalize(asFile(Buffer.alloc(0), 'image/jpeg')),
        (err) => err instanceof ImageValidationError && /empty/.test(err.message)
    );
    const png = await makeImage('png');
    await assert.rejects(
        () => validateAndNormalize(asFile(png, 'image/png'), { maxBytes: 16 }),
        (err) => err instanceof ImageValidationError && /smaller than/.test(err.message)
    );
});

test('an image with absurd dimensions is refused before it can exhaust memory', async () => {
    const wide = await sharp({ create: { width: 9000, height: 12, channels: 3, background: { r: 1, g: 1, b: 1 } } }).png().toBuffer();
    await assert.rejects(
        () => validateAndNormalize(asFile(wide, 'image/png')),
        (err) => err instanceof ImageValidationError && /at most 8000/.test(err.message)
    );
    await assert.rejects(
        () => validateAndNormalize(asFile(wide, 'image/png'), { maxDimension: 5000 }),
        (err) => err instanceof ImageValidationError && /at most 5000/.test(err.message)
    );
});

test('a real image is accepted, downscaled and re-encoded', async () => {
    const png = await makeImage('png', 3000, 1500);
    const result = await validateAndNormalize(asFile(png, 'image/png'));
    assert.equal(result.format, 'png');
    assert.equal(result.reencoded, true);
    assert.equal(result.width, 1600);
    assert.equal(result.height, 800);
    assert.ok(result.data.length < png.length, 'the stored bytes should be smaller than the upload');
    assert.equal(sniffImageFormat(result.data), 'png');
});

test('a small image keeps its dimensions (no upscaling)', async () => {
    const jpeg = await makeImage('jpeg', 64, 48);
    const result = await validateAndNormalize(asFile(jpeg, 'image/jpeg'));
    assert.equal(result.width, 64);
    assert.equal(result.height, 48);
});

test('EXIF metadata is stripped, so a photo cannot leak its capture location', async () => {
    const withExif = await sharp({ create: { width: 30, height: 30, channels: 3, background: { r: 5, g: 5, b: 5 } } })
        .jpeg()
        .withMetadata({ exif: { IFD0: { Copyright: 'GPS-SECRET' } } })
        .toBuffer();
    assert.ok((await sharp(withExif).metadata()).exif, 'the fixture must actually carry EXIF');

    const result = await validateAndNormalize(asFile(withExif, 'image/jpeg'));
    const outputMeta = await sharp(result.data).metadata();
    assert.equal(outputMeta.exif, undefined, 'EXIF survived the re-encode');
    assert.ok(!result.data.includes(Buffer.from('GPS-SECRET')), 'the metadata payload is still in the stored bytes');
});

test('trailing content after a valid image is not stored (polyglot upload)', async () => {
    const png = await makeImage('png');
    const polyglot = Buffer.concat([png, Buffer.from('<script>alert(1)</script>')]);
    const result = await validateAndNormalize(asFile(polyglot, 'image/png'));
    assert.ok(!result.data.includes(Buffer.from('<script>')), 'the appended script is still in the stored bytes');
    assert.equal(sniffImageFormat(result.data), 'png');
});

test('GIF uploads are accepted', async () => {
    const gif = await makeImage('gif');
    const result = await validateAndNormalize(asFile(gif, 'image/gif'));
    assert.equal(result.format, 'gif');
    assert.equal(result.mimetype, 'image/gif');
});

test('a missing file and a non-buffer payload are handled without throwing raw errors', async () => {
    await assert.rejects(() => validateAndNormalize(null), (err) => err instanceof ImageValidationError);
    await assert.rejects(() => validateAndNormalize({ mimetype: 'image/jpeg' }), (err) => err instanceof ImageValidationError);
});
