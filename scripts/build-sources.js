'use strict';

// Generates lib/sources.js: the sandbox bootstrap files embedded as string
// literals, so that the runtime never reads package files from disk and
// single-file bundlers (Bun compile, esbuild, pkg, ...) can ship vm2.
//
// Run with `npm run build:sources` after editing any of the EMBEDDED files.
// `npm test` runs it automatically (pretest); test/sources.js fails with a
// clear message if the committed lib/sources.js is stale.

const fs = require('fs');
const path = require('path');

const LIB_DIR = path.join(__dirname, '..', 'lib');
const OUTPUT = path.join(LIB_DIR, 'sources.js');
const EMBEDDED = ['bridge.js', 'setup-sandbox.js', 'setup-node-sandbox.js', 'events.js'];

// JSON.stringify yields a valid JS string literal except for U+2028/U+2029,
// which older engines reject inside string literals. Escape them explicitly
// so the output stays byte-for-byte faithful on every supported Node.
function toLiteral(text) {
	return JSON.stringify(text).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

let out = '';
out += '/* eslint-disable */\n';
out += "'use strict';\n\n";
out += '// GENERATED FILE -- do not edit by hand.\n';
out += '// Built by scripts/build-sources.js from the files named below.\n';
out += '// Regenerate with `npm run build:sources`.\n\n';
out += 'module.exports = Object.freeze({\n';
for (let i = 0; i < EMBEDDED.length; i++) {
	const name = EMBEDDED[i];
	const text = fs.readFileSync(path.join(LIB_DIR, name), 'utf8');
	out += '\t' + toLiteral(name) + ': ' + toLiteral(text) + ',\n';
}
out += '});\n';

const previous = fs.existsSync(OUTPUT) ? fs.readFileSync(OUTPUT, 'utf8') : null;
if (previous === out) {
	console.log('lib/sources.js is up to date');
} else {
	fs.writeFileSync(OUTPUT, out);
	console.log('lib/sources.js ' + (previous === null ? 'created' : 'updated'));
}
