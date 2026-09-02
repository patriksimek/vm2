/* eslint-env mocha */

'use strict';

// GHSA-8hr7-r645-pc6w -- adversarial coverage for the second, independent
// defense-in-depth layer (`assembleNestingOverride` / `isPlainConfigObject`
// in lib/nodevm.js). Run with the primary guard-predicate fix ABSENT.
//
// Three groups:
//   1. NEW mis-shaped `require` values (beyond repro.js) the layer must close.
//   2. Residual shapes it lets through, proven non-escalating (== require:{}).
//   3. End-to-end host-RCE PoC (blocked) + documented nesting still works.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {NodeVM} = require('../../../lib/main.js');

const PROBE = `
	const out = {};
	try { out.vm2 = typeof require('vm2').NodeVM === 'function'; } catch (e) { out.vm2 = false; }
	try { require('fs'); out.fs = true; } catch (e) { out.fs = false; }
	try { require('child_process'); out.cp = true; } catch (e) { out.cp = false; }
	module.exports = out;
`;

function probe(shape) {
	let vm;
	try {
		vm = new NodeVM({nesting: true, require: shape});
	} catch (e) {
		return {threwAtConstruction: true, vm2: false, fs: false, cp: false};
	}
	return vm.run(PROBE, 'vm.js');
}

// --- 1. NEW shapes the layer fully closes. -------------------------------
describe('GHSA-8hr7-r645-pc6w adversarial (newly-covered shapes, fully closed)', () => {
	const closedShapes = {
		// Typed arrays: exotic prototype, not a config carrier.
		'typed array (Uint8Array)': () => new Uint8Array(4),
		// Array-like via prototype chain but Array.isArray() === false.
		'Object.create(Array.prototype)': () => Object.create(Array.prototype),
		// Class instance: prototype is the class, not Object.prototype.
		'class instance': () => new (class C {})(),
		// Proxy around an array that LIES about its prototype (returns
		// Object.prototype). Closed anyway: Array.isArray() sees the array
		// target and the layer rejects it before the prototype check --
		// this is exactly why the layer uses Array.isArray(), not a bare
		// prototype comparison.
		'prototype-spoofing Proxy around []': () => new Proxy([], {
			getPrototypeOf() {
				return Object.prototype;
			}
		})
	};

	Object.keys(closedShapes).forEach((name) => {
		it(`does not expose vm2 for ${name}`, () => {
			const r = probe(closedShapes[name]());
			assert.strictEqual(r.vm2, false, `vm2 must NOT be exposed for ${name}`);
			assert.strictEqual(r.fs, false);
			assert.strictEqual(r.cp, false);
		});
	});
});

// --- 2. Residual shapes -- let through, but proven non-escalating. -------
// These require the embedder to deliberately construct an exotic
// host-realm object (a null-prototype object, or a Proxy that lies about
// its prototype). They are NOT attacker-controlled-JSON vectors, and they
// collapse to the SAME capability profile as the documented `require: {}`
// opt-in (vm2 only). Flagged in NOTES.md. A stricter future primary fix may
// additionally reject them; these assertions tolerate that (they only forbid
// escalation beyond the opt-in).
describe('GHSA-8hr7-r645-pc6w adversarial (residuals: no escalation beyond require:{})', () => {
	const baseline = probe({});

	const residualShapes = {
		'Object.create(null) (empty null-proto)': () => Object.create(null),
		'prototype-spoofing Proxy around a Date': () => new Proxy(new Date(), {
			getPrototypeOf() {
				return Object.prototype;
			}
		})
	};

	Object.keys(residualShapes).forEach((name) => {
		it(`grants no capability beyond require:{} for ${name}`, () => {
			const r = probe(residualShapes[name]());
			assert.strictEqual(r.fs, false, `${name} must not expose fs`);
			assert.strictEqual(r.cp, false, `${name} must not expose child_process`);
			assert.strictEqual(r.vm2, baseline.vm2,
				`${name} vm2-exposure must equal the documented require:{} baseline`);
		});
	});
});

// --- 3. End-to-end host RCE (blocked) + documented nesting preserved. ----
describe('GHSA-8hr7-r645-pc6w adversarial (end-to-end)', () => {
	it('array-shaped require cannot reach host RCE through nested vm2', () => {
		const sentinel = path.join(os.tmpdir(), `vm2-ghsa-8hr7-${process.pid}-${Date.now()}.txt`);
		try {
			fs.unlinkSync(sentinel);
		} catch (e) { /* not present, fine */ }

		const rce = `
			try {
				const {NodeVM} = require('vm2');
				const inner = new NodeVM({require: {builtin: ['fs']}});
				const hostFs = inner.run("module.exports = require('fs')", 'inner.js');
				hostFs.writeFileSync(${JSON.stringify(sentinel)}, 'pwned');
				module.exports = {escaped: true};
			} catch (e) {
				module.exports = {escaped: false, err: e.message};
			}
		`;

		// The merged fix rejects array-shaped nesting at CONSTRUCTION (the m4wx
		// guard throws), which is the strongest outcome. Accept either the throw
		// or, if a future variant constructs, a non-escaping run — both must
		// leave the host RCE sentinel unwritten.
		let r = { escaped: false };
		try {
			const vm = new NodeVM({nesting: true, require: []});
			r = vm.run(rce, 'vm.js');
		} catch (e) {
			assert.ok(/nesting/i.test(e.message), 'construction should throw the nesting guard error; got: ' + e.message);
		}

		assert.strictEqual(r.escaped, false, 'sandbox must not reach host RCE');
		assert.strictEqual(fs.existsSync(sentinel), false, 'host RCE sentinel file must not exist');
		try {
			fs.unlinkSync(sentinel);
		} catch (e) { /* fine */ }
	});

	it('documented nesting ({nesting:true, require:{builtin:[]}}) still exposes vm2', () => {
		const vm = new NodeVM({nesting: true, require: {builtin: []}});
		const out = vm.run(`
			const {VM} = require('vm2');
			const inner = new VM();
			module.exports = inner.run('1 + 1');
		`, 'vm.js');
		assert.strictEqual(out, 2);
	});

	it('documented nesting with a real builtin config keeps that config working', () => {
		const vm = new NodeVM({nesting: true, require: {builtin: ['fs']}});
		const out = vm.run(`
			module.exports = {
				vm2: typeof require('vm2').NodeVM === 'function',
				fs: typeof require('fs').readFileSync === 'function'
			};
		`, 'vm.js');
		assert.strictEqual(out.vm2, true);
		assert.strictEqual(out.fs, true);
	});
});
