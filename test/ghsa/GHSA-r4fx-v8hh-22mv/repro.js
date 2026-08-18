'use strict';
/**
 * GHSA-r4fx-v8hh-22mv — FinalizationRegistry GC-callback timeout bypass
 *
 * Regression test suite.  Run with:
 *   node test/ghsa/GHSA-r4fx-v8hh-22mv/repro.js
 * (--expose-gc is NOT needed — the fix prevents registration entirely)
 *
 * Pass criteria
 * =============
 *   [1] VM:       typeof FinalizationRegistry inside a VM sandbox is "undefined"
 *   [2] VM:       new FinalizationRegistry(...) throws ReferenceError
 *   [3] NodeVM:   typeof FinalizationRegistry inside a NodeVM sandbox is "undefined"
 *   [4] NodeVM:   new FinalizationRegistry(...) throws ReferenceError
 *   [5] VM:       typeof WeakRef inside a VM sandbox is "undefined"
 *   [6] VM:       new WeakRef({}) throws ReferenceError
 *   [7] PoC:      vm.run() throws (ReferenceError) and returns quickly (< 1 s)
 *   [8] No bleed: WeakMap, WeakSet, Promise still work normally in the sandbox
 *   [9] Recovery: No FinalizationRegistry via Function/eval/constructor chain
 */

const assert = require('assert');
const { VM, NodeVM } = require('../../../lib/main.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
	try {
		fn();
		console.log('  ✓', name);
		passed++;
	} catch (e) {
		console.error('  ✗', name);
		console.error('    ', e.message || e);
		failed++;
	}
}

console.log('\nGHSA-r4fx-v8hh-22mv — FinalizationRegistry / WeakRef removal\n');

// ─── [1] VM: FinalizationRegistry is undefined ────────────────────────────
test('[1] VM: typeof FinalizationRegistry === "undefined"', () => {
	const vm = new VM({ timeout: 500 });
	const result = vm.run('typeof FinalizationRegistry');
	assert.strictEqual(result, 'undefined',
		`Expected "undefined", got "${result}"`);
});

// ─── [2] VM: new FinalizationRegistry throws ReferenceError ───────────────
test('[2] VM: new FinalizationRegistry() throws ReferenceError', () => {
	const vm = new VM({ timeout: 500 });
	assert.throws(
		() => vm.run('new FinalizationRegistry(() => {})'),
		/ReferenceError/,
		'Expected ReferenceError when constructing FinalizationRegistry',
	);
});

// ─── [3] NodeVM: FinalizationRegistry is undefined ────────────────────────
test('[3] NodeVM: typeof FinalizationRegistry === "undefined"', () => {
	const nodeVm = new NodeVM({ timeout: 500 });
	const result = nodeVm.run('module.exports = typeof FinalizationRegistry;');
	assert.strictEqual(result, 'undefined',
		`Expected "undefined", got "${result}"`);
});

// ─── [4] NodeVM: new FinalizationRegistry throws ReferenceError ───────────
test('[4] NodeVM: new FinalizationRegistry() throws ReferenceError', () => {
	const nodeVm = new NodeVM({ timeout: 500 });
	assert.throws(
		() => nodeVm.run('module.exports = new FinalizationRegistry(() => {});'),
		/ReferenceError/,
		'Expected ReferenceError when constructing FinalizationRegistry in NodeVM',
	);
});

// ─── [5] VM: WeakRef is undefined ─────────────────────────────────────────
test('[5] VM: typeof WeakRef === "undefined"', () => {
	const vm = new VM({ timeout: 500 });
	const result = vm.run('typeof WeakRef');
	assert.strictEqual(result, 'undefined',
		`Expected "undefined", got "${result}"`);
});

// ─── [6] VM: new WeakRef throws ReferenceError ────────────────────────────
test('[6] VM: new WeakRef({}) throws ReferenceError', () => {
	const vm = new VM({ timeout: 500 });
	assert.throws(
		() => vm.run('new WeakRef({})'),
		/ReferenceError/,
		'Expected ReferenceError when constructing WeakRef',
	);
});

// ─── [7] PoC: run() throws quickly; host event loop is NOT blocked ─────────
test('[7] PoC: vm.run() throws ReferenceError and completes in < 1 s', () => {
	const vm = new VM({ timeout: 200 });
	const t0 = Date.now();
	let threw = false;
	let errorMsg = '';
	try {
		vm.run(`
			let target = {};
			const registry = new FinalizationRegistry(() => {
				const start = Date.now();
				while (Date.now() - start < 3000) { /* would block event loop */ }
			});
			registry.register(target, 'held-value');
			target = null;
		`);
	} catch (e) {
		threw = true;
		errorMsg = e.message || String(e);
	}
	const elapsed = Date.now() - t0;
	assert.ok(threw, 'vm.run() should have thrown (FinalizationRegistry must be undefined)');
	assert.ok(
		/ReferenceError/i.test(errorMsg) || /FinalizationRegistry/.test(errorMsg),
		`Expected ReferenceError mentioning FinalizationRegistry, got: "${errorMsg}"`,
	);
	assert.ok(elapsed < 1000,
		`vm.run() should complete in < 1 s but took ${elapsed} ms — event loop may be blocked`);
});

// ─── [8] No bleed: WeakMap, WeakSet, Promise still work ───────────────────
test('[8] WeakMap, WeakSet, and Promise still function normally', () => {
	const vm = new VM({ timeout: 500 });

	const wm = vm.run(`
		const m = new WeakMap();
		const k = {};
		m.set(k, 42);
		m.get(k);
	`);
	assert.strictEqual(wm, 42, 'WeakMap.get should return 42');

	const ws = vm.run(`
		const s = new WeakSet();
		const o = {};
		s.add(o);
		s.has(o);
	`);
	assert.strictEqual(ws, true, 'WeakSet.has should return true');

	// allowAsync must be true to get a Promise result back
	const vmAsync = new VM({ timeout: 500, allowAsync: true });
	const p = vmAsync.run('Promise.resolve(99)');
	assert.ok(p instanceof Promise, 'Promise.resolve should return a Promise');
	return p.then(v => assert.strictEqual(v, 99, 'Promise should resolve to 99'));
});

// ─── [9] No recovery via Function / eval / constructor chain ──────────────
test('[9] FinalizationRegistry cannot be reconstructed via eval / Function / constructor chain', () => {
	const vm = new VM({ timeout: 500 });

	// Direct eval path
	assert.throws(
		() => vm.run('eval("new FinalizationRegistry(() => {})")'),
		/ReferenceError/,
		'eval path should throw ReferenceError',
	);

	// Function constructor path
	assert.throws(
		() => vm.run('new Function("return new FinalizationRegistry(() => {})")()')  ,
		/ReferenceError/,
		'Function constructor path should throw ReferenceError',
	);

	// Constructor chain climb via WeakMap
	assert.throws(
		() => vm.run(`
			const F = new WeakMap().constructor.constructor;
			new F('return new FinalizationRegistry(() => {})')();
		`),
		/ReferenceError/,
		'Constructor chain via WeakMap should throw ReferenceError',
	);
});

// ─── Summary ──────────────────────────────────────────────────────────────
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
