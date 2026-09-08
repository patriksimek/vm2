'use strict';

/**
 * GHSA-489w-w794-jq94 helper for Test 17. Removes BOTH routes the bridge has to
 * host `ArrayBuffer.isView` (the global `ArrayBuffer` and
 * `ArrayBuffer.prototype.constructor`) and checks that reading a pooled host
 * buffer's backing store is REFUSED rather than delivered. Replacing a global
 * intrinsic is why this runs in its own process.
 */

// Loaded directly by Test 17 via `spawnSync`. Mocha globs every `.js` in this
// directory, so bail out immediately unless this file IS the entry point —
// otherwise the global mutation below would run inside the test process.
if (require.main !== module) return;

const { VM } = require('../../../lib/main.js');

const MARKER = 'DEGRADEDISVIEWMARK';
const kept = [];
for (let i = 0; i < 400; i++) {
	const b = Buffer.allocUnsafe(64);
	b.fill(0x2e);
	b.write(MARKER, 0, 'latin1');
	kept.push(b);
}

const RealArrayBuffer = ArrayBuffer;
Object.defineProperty(ArrayBuffer.prototype, 'constructor', {
	value: {}, writable: true, enumerable: false, configurable: true
});
Object.defineProperty(global, 'ArrayBuffer', {
	value: { prototype: RealArrayBuffer.prototype }, writable: true, configurable: true
});

const b = Buffer.from('hello');
let out;
try {
	out = new VM({ sandbox: { b } }).run(
		'(function () {\n' +
		'	const res = {marker: -1};\n' +
		'	try {\n' +
		'		const ab = b.buffer;\n' +
		'		res.abByteLength = ab.byteLength;\n' +
		'		res.marker = Buffer.from(ab, 0, ab.byteLength).toString("latin1").indexOf("' + MARKER + '");\n' +
		'		Buffer.from(ab, 0, ab.byteLength).fill(0x41);\n' +
		'	} catch (e) {\n' +
		'		res.error = e.message;\n' +
		'	}\n' +
		'	return res;\n' +
		'})()'
	);
} catch (e) {
	out = { marker: -1, error: e.message };
}

Object.defineProperty(global, 'ArrayBuffer', {
	value: RealArrayBuffer, writable: true, configurable: true
});

let intact = true;
for (let i = 0; i < kept.length; i++) {
	if (kept[i].toString('latin1').indexOf(MARKER) !== 0) intact = false;
}

process.stdout.write(JSON.stringify({
	marker: out.marker === undefined ? -1 : out.marker,
	abByteLength: out.abByteLength,
	error: out.error,
	intact: intact
}) + '\n');
