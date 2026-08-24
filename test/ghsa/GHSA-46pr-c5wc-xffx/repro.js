/**
 * GHSA-46pr-c5wc-xffx — crypto.setEngine loads attacker native code
 *
 * ## Vulnerability
 * A NodeVM that allows only the `crypto` builtin exposes the host crypto module
 * through vm.readonly(). Read-only blocks property assignment but forwards calls
 * to host functions with full host authority. `crypto.setEngine(path)` hands the
 * path to OpenSSL's ENGINE loader, which asks the OS dynamic loader to load the
 * named shared library — running its constructor as native code BEFORE OpenSSL
 * validates the file. A bundled native library in the plugin package therefore
 * executes in the host process with only `crypto` allowed.
 *
 * ## Fix
 * lib/builtin.js sanitizes the crypto module before the read-only wrap, replacing
 * `setEngine` with a stub that throws instead of forwarding to host OpenSSL.
 *
 * Sound oracle: a native constructor writes a marker file. With the fix the
 * marker must never appear (the library is never loaded).
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { NodeVM } = require('../../../lib/main.js');
const {rmrfSync} = require('../../fs-compat.js');

// Build a tiny native library whose constructor writes a marker file. Skip the
// whole suite if a C compiler / platform support is unavailable.
function tryBuildProbe(dir) {
	const platform = process.platform;
	if (platform !== 'darwin' && platform !== 'linux') return null;
	const marker = path.join(dir, 'native-marker.txt');
	const src = path.join(dir, 'engine_probe.c');
	fs.writeFileSync(src, `
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor))
static void vm2_probe_ctor(void) {
    const char *p = getenv("VM2_46PR_MARKER");
    if (!p) return;
    FILE *f = fopen(p, "w");
    if (f) { fputs("VM2_SETENGINE_NATIVE_CODE_EXECUTED", f); fclose(f); }
}
`);
	const lib = path.join(dir, platform === 'darwin' ? 'probe-engine.dylib' : 'probe-engine.so');
	const args = platform === 'darwin'
		? ['-dynamiclib', '-O2', '-o', lib, src]
		: ['-shared', '-fPIC', '-O2', '-o', lib, src];
	try {
		execFileSync('cc', args, { stdio: 'ignore' });
	} catch (e) { return null; }
	if (!fs.existsSync(lib)) return null;
	return { lib, marker };
}

describe('GHSA-46pr-c5wc-xffx — crypto.setEngine native code load', function () {
	this.timeout(20000);
	let probe, dir;

	before(function () {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm2-46pr-'));
		probe = tryBuildProbe(dir);
		if (!probe) this.skip();
		process.env.VM2_46PR_MARKER = probe.marker;
	});

	after(function () {
		delete process.env.VM2_46PR_MARKER;
		if (dir) try { rmrfSync(dir); } catch (e) {}
	});

	it('crypto.setEngine is disabled and never loads the native library', function () {
		const vm = new NodeVM({ require: { builtin: ['crypto'] } });
		let threw = false;
		try {
			vm.run(`require('crypto').setEngine(${JSON.stringify(probe.lib)});`, 'attack.js');
		} catch (e) { threw = true; }
		assert.strictEqual(threw, true, 'crypto.setEngine should throw (neutralized)');
		assert.strictEqual(fs.existsSync(probe.marker), false,
			'native constructor ran — setEngine loaded the library into the host process');
	});

	it('does not over-block: the rest of crypto still works', function () {
		const vm = new NodeVM({ require: { builtin: ['crypto'] } });
		const digest = vm.run(
			`module.exports = require('crypto').createHash('sha256').update('vm2').digest('hex');`,
			'ok.js');
		assert.strictEqual(typeof digest, 'string');
		assert.strictEqual(digest.length, 64);
		// setEngine is present but throws (not silently missing).
		const setEngineType = vm.run(`module.exports = typeof require('crypto').setEngine;`, 't.js');
		assert.strictEqual(setEngineType, 'function');
	});
});
