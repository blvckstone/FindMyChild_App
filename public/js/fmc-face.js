/* Shared, lazy face-detection helper.
 *
 * The face-api script and its model weights are ~13 MB, so nothing is loaded until a
 * feature actually needs face detection. Both the public site and the admin panel use
 * this file, which keeps descriptor extraction identical on both sides.
 */
(function (global) {
    'use strict';

    const SCRIPT_SRC = '/js/face-api.js';
    const MODELS_URI = '/models';
    const MAX_DIMENSION = 800;
    const MIN_CONFIDENCE = 0.35;

    let scriptPromise = null;
    let modelsPromise = null;
    let modelsLoaded = false;

    const hasLibrary = () => !!(global && global.faceapi);

    // Inject /js/face-api.js on demand (idempotent).
    const loadFaceApiScript = () => {
        if (hasLibrary()) return Promise.resolve(true);
        if (scriptPromise) return scriptPromise;
        scriptPromise = new Promise((resolve, reject) => {
            if (!global || !global.document) {
                reject(new Error('Face detection is not available in this environment.'));
                return;
            }
            const script = global.document.createElement('script');
            script.src = SCRIPT_SRC;
            script.async = true;
            script.onload = () => resolve(true);
            script.onerror = () => {
                scriptPromise = null;
                reject(new Error('Could not load face detection. Check your connection.'));
            };
            global.document.head.appendChild(script);
        });
        return scriptPromise;
    };

    // Load the three models once. Resolves true when ready; rejects with a readable message.
    const loadFaceApi = () => {
        if (modelsLoaded) return Promise.resolve(true);
        if (modelsPromise) return modelsPromise;
        modelsPromise = (async () => {
            await loadFaceApiScript();
            const faceapi = global.faceapi;
            if (!faceapi) throw new Error('Face detection is unavailable.');
            await faceapi.nets.ssdMobilenetv1.loadFromUri(MODELS_URI);
            await faceapi.nets.faceLandmark68Net.loadFromUri(MODELS_URI);
            await faceapi.nets.faceRecognitionNet.loadFromUri(MODELS_URI);
            modelsLoaded = true;
            return true;
        })().finally(() => { modelsPromise = null; });
        return modelsPromise;
    };

    const isFaceApiLoaded = () => modelsLoaded;

    // Extract a 128-value descriptor from an image File/Blob. Resolves null when no face is found.
    const extractFaceDescriptor = (file) => new Promise((resolve, reject) => {
        const faceapi = global.faceapi;
        if (!faceapi) {
            reject(new Error('Face detection is not ready.'));
            return;
        }
        const image = new global.Image();
        const objectUrl = global.URL.createObjectURL(file);
        image.onload = async () => {
            try {
                // Downscale huge smartphone photos so the WebGL backend does not crash.
                const canvas = global.document.createElement('canvas');
                let width = image.width;
                let height = image.height;
                if (width > height && width > MAX_DIMENSION) {
                    height *= MAX_DIMENSION / width;
                    width = MAX_DIMENSION;
                } else if (height > MAX_DIMENSION) {
                    width *= MAX_DIMENSION / height;
                    height = MAX_DIMENSION;
                }
                canvas.width = width;
                canvas.height = height;
                canvas.getContext('2d').drawImage(image, 0, 0, width, height);

                const detection = await faceapi
                    .detectSingleFace(canvas, new faceapi.SsdMobilenetv1Options({ minConfidence: MIN_CONFIDENCE }))
                    .withFaceLandmarks()
                    .withFaceDescriptor();

                global.URL.revokeObjectURL(objectUrl);
                resolve(detection ? Array.from(detection.descriptor) : null);
            } catch (error) {
                global.URL.revokeObjectURL(objectUrl);
                reject(error);
            }
        };
        image.onerror = () => {
            global.URL.revokeObjectURL(objectUrl);
            reject(new Error('Failed to load image file.'));
        };
        image.src = objectUrl;
    });

    const api = { loadFaceApiScript, loadFaceApi, isFaceApiLoaded, extractFaceDescriptor };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (global) global.fmcFace = api;
})(typeof window !== 'undefined' ? window : null);
