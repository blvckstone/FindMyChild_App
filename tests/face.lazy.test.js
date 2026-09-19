/**
 * B2 — the face stack used to be pulled in eagerly: /js/face-api.js (1.3 MB) was a static
 * <script> tag and 12 MB of model weights were fetched during page load, even for visitors
 * who never touched the AI feature. These tests load the real public/js/fmc-face.js in a
 * sandbox and prove (a) importing it downloads nothing, (b) the first real use loads the
 * library + models exactly once, (c) extraction still downscales and returns 128 floats.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

function makeFaceapi(log) {
    const net = (name) => ({
        loadFromUri(uri) {
            log.modelLoads.push(`${name}:${uri}`);
            return Promise.resolve();
        },
    });
    return {
        nets: {
            ssdMobilenetv1: net('ssdMobilenetv1'),
            faceLandmark68Net: net('faceLandmark68Net'),
            faceRecognitionNet: net('faceRecognitionNet'),
        },
        SsdMobilenetv1Options: function SsdMobilenetv1Options(opts) {
            this.minConfidence = opts && opts.minConfidence;
        },
        detectSingleFace(canvas) {
            log.detections.push({ width: canvas.width, height: canvas.height });
            return {
                withFaceLandmarks() { return this; },
                withFaceDescriptor() {
                    return Promise.resolve(
                        log.noFace ? null : { descriptor: new Float32Array(128).fill(0.5) }
                    );
                },
            };
        },
    };
}

/** Build a sandbox with a fake window/document/Image/URL and the real fmc-face.js inside it. */
function loadModule() {
    const log = { scriptAppends: 0, modelLoads: [], detections: [], revoked: 0, noFace: false };
    const appended = [];

    const sandbox = {};
    sandbox.window = sandbox;
    sandbox.console = console;
    sandbox.setTimeout = setTimeout;
    sandbox.Promise = Promise;

    let imageSize = { width: 4000, height: 3000 };
    sandbox.Image = class FakeImage {
        constructor() {
            this.width = 0;
            this.height = 0;
            setTimeout(() => { if (this.onload) this.onload(); }, 0);
        }
        set src(value) { this._src = value; this.width = imageSize.width; this.height = imageSize.height; }
        get src() { return this._src; }
    };
    sandbox.URL = {
        createObjectURL: () => 'blob:fake',
        revokeObjectURL: () => { log.revoked += 1; },
    };
    sandbox.document = {
        createElement(tag) {
            if (tag === 'canvas') {
                const canvas = { width: 0, height: 0 };
                canvas.getContext = () => ({ drawImage: () => {} });
                return canvas;
            }
            return { tagName: tag.toUpperCase(), src: '', async: false, onload: null, onerror: null };
        },
        head: {
            appendChild(node) {
                log.scriptAppends += 1;
                appended.push(node);
                // Simulate the browser fetching /js/face-api.js: the global appears, then onload fires.
                sandbox.faceapi = makeFaceapi(log);
                setTimeout(() => { if (node.onload) node.onload(); }, 0);
            },
        },
    };

    const context = vm.createContext(sandbox);
    vm.runInContext(read('public/js/fmc-face.js'), context, { filename: 'public/js/fmc-face.js' });

    return {
        api: sandbox.fmcFace,
        sandbox,
        log,
        appended,
        setImageSize(size) { imageSize = size; },
    };
}

test('B2: the face module is importable and still uses fmcFace test hooks', () => {
    const { api } = loadModule();
    assert.ok(api, 'fmc-face.js must expose window.fmcFace');
    assert.equal(typeof api.loadFaceApi, 'function');
    assert.equal(typeof api.extractFaceDescriptor, 'function');
    assert.equal(typeof api.isFaceApiLoaded, 'function');
});

test('B2: importing the face module downloads nothing (the old eager 13 MB is gone)', () => {
    const { log, api } = loadModule();
    assert.equal(log.scriptAppends, 0, 'no face-api script may be injected at import time');
    assert.equal(log.modelLoads.length, 0, 'no model weights may be fetched at import time');
    assert.equal(api.isFaceApiLoaded(), false);
});

test('B2: the library and models load once, on first use, and later calls are free', async () => {
    const { log, api } = loadModule();

    assert.equal(await api.loadFaceApi(), true);
    assert.equal(log.scriptAppends, 1, 'face-api.js must be injected exactly once');
    assert.deepEqual(
        log.modelLoads.slice().sort(),
        ['faceLandmark68Net:/models', 'faceRecognitionNet:/models', 'ssdMobilenetv1:/models'],
        'all three nets must load from /models'
    );

    // Second and third calls must not re-download anything.
    assert.equal(await api.loadFaceApi(), true);
    await api.loadFaceApi();
    assert.equal(log.scriptAppends, 1);
    assert.equal(log.modelLoads.length, 3);
    assert.equal(api.isFaceApiLoaded(), true);
});

test('B2: concurrent first-use calls share one load (no duplicate 13 MB requests)', async () => {
    const { log, api } = loadModule();
    const results = await Promise.all([api.loadFaceApi(), api.loadFaceApi(), api.loadFaceApi()]);
    assert.deepEqual(results, [true, true, true]);
    assert.equal(log.scriptAppends, 1);
    assert.equal(log.modelLoads.length, 3);
});

test('B2: extraction downscales huge photos to 800 px and returns 128 floats', async () => {
    const { api, log, setImageSize } = loadModule();
    await api.loadFaceApi();

    setImageSize({ width: 4000, height: 3000 });
    const descriptor = await api.extractFaceDescriptor({ name: 'photo.jpg' });
    assert.equal(descriptor.length, 128);
    assert.equal(log.detections.at(-1).width, 800, 'wide photo must be scaled to 800 px wide');
    assert.equal(log.detections.at(-1).height, 600, 'aspect ratio must be preserved');
    assert.equal(log.revoked, 1, 'the object URL must be released');

    setImageSize({ width: 600, height: 1200 });
    await api.extractFaceDescriptor({ name: 'tall.jpg' });
    assert.equal(log.detections.at(-1).height, 800, 'tall photo must be scaled to 800 px tall');
    assert.equal(log.detections.at(-1).width, 400);
});

test('B2: a photo with no face resolves null and still releases the object URL', async () => {
    const { api, log } = loadModule();
    await api.loadFaceApi();
    log.noFace = true;
    assert.equal(await api.extractFaceDescriptor({ name: 'noface.jpg' }), null);
    assert.equal(log.revoked, 1);
});

test('B2: extraction before the library is ready rejects with a readable message', async () => {
    const { api } = loadModule();
    await assert.rejects(() => api.extractFaceDescriptor({}), /Face detection is not ready/);
});

test('B2: neither page eagerly references the face stack anymore', () => {
    const index = read('public/index.html');
    const admin = read('public/admin.html');

    assert.ok(
        !/<script[^>]+src=["']\/js\/face-api\.js["']/.test(index),
        'index.html must not include face-api.js as a static script tag'
    );
    assert.ok(
        !/loadFaceApi\(\)\s*\.catch/.test(index),
        'index.html must not preload the face models during page init (the old eager call)'
    );
    assert.ok(
        !/faceapi\./.test(index),
        'index.html must go through window.fmcFace instead of touching the raw faceapi global'
    );
    assert.equal(admin.includes('faceapi'), false, 'admin.html does not need the face stack yet');

    // The shared helper must be present and loaded before the inline script that uses it.
    const helperAt = index.indexOf('/js/fmc-face.js');
    const inlineAt = index.indexOf('fmcFace.loadFaceApi');
    assert.ok(helperAt !== -1, 'index.html must include the shared face helper');
    assert.ok(inlineAt === -1 || helperAt < inlineAt, 'fmc-face.js must load before its first use');
});
