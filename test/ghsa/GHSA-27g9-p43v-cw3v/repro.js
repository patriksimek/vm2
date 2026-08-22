/**
 * GHSA-27g9-p43v-cw3v — VM sandbox escape on Node 26 via a stale
 * `PromiseThenLookupChain` protector across `Promise.prototype.finally`.
 *
 * ## Vulnerability class
 * Sibling of GHSA-76w7-j9cq-rx2j (Promise species). vm2 installs its
 * `Promise.prototype.then` / `catch` wrappers (which call
 * `resetPromiseSpecies(this)`) by DIRECT ASSIGNMENT. On Node 26 / V8 14.6 the
 * `SetPrototypeProperties` path updates those existing data properties WITHOUT
 * invalidating the `PromiseThenLookupChain` protector. `Promise.prototype.finally`
 * then trusts the stale protector and uses an internal `InvokeThen` fast path
 * that calls the ORIGINAL native `then`, bypassing vm2's wrapper and its
 * `resetPromiseSpecies` hardening. An ordinary async-function Promise can
 * therefore retain an attacker-controlled `constructor[Symbol.species]` across
 * `p.finally()`; V8's `SpeciesConstructor` then hands the attacker species
 * control of a native Promise reaction's resolve/reject. A calibrated stack
 * overflow at that boundary yields a raw host `RangeError` →
 * `e.constructor.constructor` → host `Function` → host `process`.
 *
 * ## Fix
 * `lib/setup-sandbox.js`: (1) install the `then` / `catch` wrappers via
 * `localReflectDefineProperty` instead of plain assignment, so V8 invalidates
 * the `PromiseThenLookupChain` protector and `finally` no longer takes the
 * stale native-`then` fast path; (2) additionally wrap
 * `globalPromise.prototype.finally` to run `resetPromiseSpecies(this)` before
 * delegating to the cached native `finally`, so the species channel is
 * neutralized on the `finally` path regardless of any future protector quirk.
 *
 * ## Sound oracle
 * The escape primitive is: the attacker `constructor[Symbol.species]` gains
 * control of the native reaction (its constructor executor runs with the
 * reaction's resolve/reject). The test observes that HOST-SIDE via a frozen
 * callback the sandbox species constructor invokes; if `resetPromiseSpecies`
 * ran, the species is `localPromise` and the attacker constructor is never
 * called. No reliance on `process.version` (identical across realms).
 */

'use strict';

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

describe('GHSA-27g9-p43v-cw3v (stale PromiseThenLookupChain protector across finally)', function () {
	it('attacker Promise species does not survive p.finally()', function (done) {
		this.timeout(4000);
		let speciesCalled = false;
		const vm = new VM({ allowAsync: true, eval: false, wasm: false, timeout: 3000 });
		vm.freeze(() => { speciesCalled = true; }, '__speciesMark');
		vm.run(`
			class Evil { constructor(executor) { __speciesMark(); executor(() => {}, () => {}); } }
			const p = (async () => 1)();
			Object.defineProperty(p, 'constructor', { value: { [Symbol.species]: Evil }, configurable: true });
			p.finally();
		`);
		setTimeout(() => {
			assert.strictEqual(speciesCalled, false, 'attacker Promise species gained control of a native reaction across finally');
			done();
		}, 250);
	});

	it('attacker species also blocked on the .then / .catch paths (regression)', function (done) {
		this.timeout(4000);
		let speciesCalled = false;
		const vm = new VM({ allowAsync: true, eval: false, wasm: false, timeout: 3000 });
		vm.freeze(() => { speciesCalled = true; }, '__speciesMark');
		vm.run(`
			class Evil { constructor(executor) { __speciesMark(); executor(() => {}, () => {}); } }
			const p = (async () => 1)();
			Object.defineProperty(p, 'constructor', { value: { [Symbol.species]: Evil }, configurable: true });
			p.then(() => {});
			p.catch(() => {});
		`);
		setTimeout(() => {
			assert.strictEqual(speciesCalled, false, 'attacker species survived then/catch');
			done();
		}, 250);
	});

	it('finally still works correctly for legitimate sandbox code', function (done) {
		this.timeout(4000);
		let finallyRan = false;
		let resolvedValue = null;
		const vm = new VM({ allowAsync: true, timeout: 3000 });
		vm.freeze((ran, val) => { finallyRan = ran; resolvedValue = val; }, '__report');
		vm.run(`
			(async () => 42)()
				.finally(() => { /* side effect */ })
				.then(v => __report(true, v));
		`);
		setTimeout(() => {
			assert.strictEqual(finallyRan, true, 'finally callback / chaining broke');
			assert.strictEqual(resolvedValue, 42, 'finally did not pass the resolved value through');
			done();
		}, 250);
	});
});
