// Lint configuration.
//
// Deliberately narrow: this checks for *mistakes*, not style. Formatting choices are left alone
// so the config cannot start failing the build over whitespace — the rules here are the ones
// that catch real defects, e.g. calling a function that was never imported (which is exactly
// how `signAdminToken` was silently missing in server.js) or a variable that is never used.
const rules = {
    'no-undef': 'error',
    'no-unused-vars': ['error', {
        args: 'none',                       // unused callback params are common and harmless
        caughtErrors: 'none',
        varsIgnorePattern: '^_',
        ignoreRestSiblings: true
    }],
    'no-dupe-keys': 'error',
    'no-dupe-args': 'error',
    'no-dupe-class-members': 'error',
    'no-duplicate-case': 'error',
    'no-unreachable': 'error',
    'no-const-assign': 'error',
    'no-func-assign': 'error',
    'no-redeclare': 'error',
    'no-self-assign': 'error',
    'no-self-compare': 'error',
    'no-cond-assign': ['error', 'except-parens'],
    'no-unsafe-negation': 'error',
    'no-unsafe-optional-chaining': 'error',
    'no-fallthrough': 'error',
    'no-case-declarations': 'error',
    'no-empty': ['error', { allowEmptyCatch: true }],
    'no-obj-calls': 'error',
    'no-sparse-arrays': 'error',
    'valid-typeof': 'error',
    'use-isnan': 'error',
    'no-async-promise-executor': 'error',
    'no-await-in-loop': 'off',              // deliberate in ordered migrations
    'require-atomic-updates': 'off'         // noisy for the request/response style used here
};

module.exports = [
    {
        // Third-party code we do not maintain: vendored verbatim, so linting it only produces
        // noise about its coding style.
        ignores: ['node_modules/**', 'public/js/face-api.js', 'public/models/**']
    },
    {
        // Server, tooling and tests: Node with CommonJS.
        files: ['**/*.js'],
        languageOptions: {
            ecmaVersion: 2023,
            sourceType: 'commonjs',
            globals: {
                require: 'readonly',
                module: 'writable',
                exports: 'writable',
                process: 'readonly',
                console: 'readonly',
                Buffer: 'readonly',
                __dirname: 'readonly',
                __filename: 'readonly',
                setTimeout: 'readonly',
                clearTimeout: 'readonly',
                setInterval: 'readonly',
                clearInterval: 'readonly',
                setImmediate: 'readonly',
                URL: 'readonly',
                TextEncoder: 'readonly',
                TextDecoder: 'readonly',
                fetch: 'readonly',
                FormData: 'readonly',
                Blob: 'readonly',
                AbortController: 'readonly',
                structuredClone: 'readonly',
                global: 'readonly'
            }
        },
        rules
    },
    {
        // Front-end scripts: browser globals, still no bundler.
        files: ['public/js/**/*.js'],
        ignores: ['public/js/face-api.js'],
        languageOptions: {
            ecmaVersion: 2023,
            sourceType: 'script',
            globals: {
                window: 'readonly',
                document: 'readonly',
                navigator: 'readonly',
                location: 'readonly',
                localStorage: 'readonly',
                sessionStorage: 'readonly',
                console: 'readonly',
                fetch: 'readonly',
                URL: 'readonly',
                URLSearchParams: 'readonly',
                FormData: 'readonly',
                Blob: 'readonly',
                FileReader: 'readonly',
                Image: 'readonly',
                alert: 'readonly',
                confirm: 'readonly',
                setTimeout: 'readonly',
                clearTimeout: 'readonly',
                setInterval: 'readonly',
                clearInterval: 'readonly',
                requestAnimationFrame: 'readonly',
                io: 'readonly',
                faceapi: 'readonly',
                module: 'writable'
            }
        },
        rules
    }
];
