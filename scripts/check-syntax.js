// Syntax-check every JavaScript file in the project.
//
// Cheap and dependency-free: it catches a file that cannot even be parsed (a broken edit, a
// stray brace, a truncated file) before the test suite — or a deploy — spends time loading it.
// Front-end scripts are included, since a syntax error there takes down the whole panel.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const SKIP_DIRS = new Set(['node_modules', '.git', '.github', '.freebuff', 'tmp']);
const EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);

const walk = (dir, files = []) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name)) continue;
            walk(path.join(dir, entry.name), files);
        } else if (entry.isFile() && EXTENSIONS.has(path.extname(entry.name))) {
            files.push(path.join(dir, entry.name));
        }
    }
    return files;
};

const files = walk(ROOT).sort();
const failures = [];

for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    try {
        // Compiles without running: exactly a syntax check.
        new vm.Script(source, { filename: file });
    } catch (error) {
        failures.push({ file: path.relative(ROOT, file), message: error.message });
    }
}

if (failures.length) {
    console.error(`✖ ${failures.length} file(s) failed to parse:\n`);
    for (const failure of failures) console.error(`  ${failure.file}\n    ${failure.message}`);
    process.exit(1);
}

console.log(`✔ ${files.length} JavaScript files parse cleanly.`);
