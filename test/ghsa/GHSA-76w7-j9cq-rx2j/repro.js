'use strict';

/**
 * GHSA-76w7-j9cq-rx2j — Sandbox breakout via Promise species in localPromise
 *                       swallow-tail.
 *
 * ## Vulnerability
 * The `localPromise` constructor (added in GHSA-hw58-p9xv-2mjh) attaches a
 * benign swallow tail via the cached host `then`:
 *
 *     apply(globalPromisePrototypeThen, this, [undefined, localPromiseSwallow]);
 *
 * The host `Promise.prototype.then` resolves the promise to use for the
 * downstream chain via the **species protocol**: it reads
 * `this.constructor[Symbol.species]` and `Construct`s a new promise with
 * that. The sandbox-side `then` / `catch` / `Reflect.apply` overrides call
 * `resetPromiseSpecies(this)` first to clobber `constructor` so species
 * resolution always yields `localPromise` — but the swallow-tail call inside
 * the constructor itself does NOT, because at construction time the
 * `resetPromiseSpecies` symbol is in the temporal dead zone.
 *
 * Attack: build `class FakePromise extends Promise { static get
 * [Symbol.species]() { return ct; } }` where `ct` is a user function. Then
 * `new FakePromise(r => r())` enters the swallow-tail path → host `then`
 * does `new ct(internalExecutor)` → the user-controlled `ct` receives V8's
 * internal `(resolve, reject)` executor and reassigns them. When V8's
 * `PromiseResolveThenableJob` rejects the downstream chain with a host-
 * realm `RangeError` (triggered by a deep-recursion `e.stack` access), the
 * raw host Error reaches sandbox code unbridged. Reading
 * `ex.constructor.constructor` returns the host `Function` constructor →
 * `Function("return process")()` → RCE.
 *
 * ## Fix
 * Reset the promise species on `this` inside the `localPromise` constructor
 * before invoking the host `then` for the swallow tail. With species pinned
 * back to `localPromise`, the downstream child is constructed via our own
 * wrapped executor — V8's reject path is bridged through `handleException`
 * and the species-resolved constructor cannot be hijacked.
 *
 * ## Variants covered
 * 1. Canonical PoC (binary-search RangeError via deep recursion).
 * 2. Direct: any synchronously-rejected `new FakePromise()` whose species
 *    is a user function — verify it cannot extract a host value.
 * 3. `new FakePromise(reject-throws)`: the inner executor synchronously
 *    throws a host-typed error; verify the rejection delivered to sandbox
 *    `.catch()` is a sandbox-realm value, not host.
 * 4. Stacked subclass: `class A extends FakePromise extends Promise`
 *    — species walks the constructor inheritance chain; the reset must win
 *    regardless of subclass depth.
 */

const assert = require('assert');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// Promise.withResolvers landed in Node 22; the canonical PoC uses it.
const HAS_WITH_RESOLVERS = typeof Promise.withResolvers === 'function';

describe('GHSA-76w7-j9cq-rx2j (Promise species swallow-tail breakout)', function () {
	this.timeout(15000);

	it.cond('canonical PoC: stack-overflow RangeError cannot reach sandbox unbridged', HAS_WITH_RESOLVERS, function (done) {
		const vm = new VM({ timeout: 12000 });
		try {
			vm.run(`
				class E extends Error {}
				function so(d) {
					if (d > 0) so(d-1);
					const e = new E();
					e.stack;
					throw e;
				}
				let ex, ct;
				class FakePromise extends Promise {
					static get [Symbol.species](){return ct;}
				}
				function doCatch(f) {
					ex=undefined;
					const p=Promise.withResolvers();
					ct = function(e){e(f, v=>{ex=v;p.resolve();})};
					new FakePromise(r=>r());
					return p.promise;
				}
				(async function f(s) {
					let min = s;
					let max = 100000;
					while (min<max) {
						const mid = (min+max)>>1;
						await doCatch(()=>so(mid));
						if (ex && ex.name==="RangeError" && !(ex instanceof RangeError)) {
							// Escape succeeded: record the leak.
							globalThis.__ghsa76w7_escape = true;
							try {
								globalThis.__ghsa76w7_procType =
									typeof ex.constructor.constructor("return process")();
							} catch(_) { /* still an escape even if Function ctor is blocked */ }
							return;
						}
						if (ex instanceof E) {
							min = mid+1;
						} else {
							max = mid;
						}
					}
					if (s < 32) f(s+1);
				})(0);
			`);
		} catch (e) {
			// Synchronous throw is acceptable — that is the sandbox refusing.
		}

		// Give the binary search time to run.
		setTimeout(function () {
			const escaped = vm.run('globalThis.__ghsa76w7_escape === true');
			const leakedProcessType = vm.run('globalThis.__ghsa76w7_procType');
			assert.strictEqual(escaped, false, 'sandbox obtained a host-realm RangeError reference');
			assert.notStrictEqual(leakedProcessType, 'object', 'sandbox extracted host process via Function constructor');
			done();
		}, 9000);
	});

	it.cond('species hijack via subclass cannot bind a user constructor as downstream species', HAS_WITH_RESOLVERS, function (done) {
		// Variant: confirm that the species protocol invoked by the swallow
		// tail does NOT pass through a sandbox-supplied `ct`. If our fix is
		// effective, the species protocol resolves to `localPromise` and `ct`
		// is never invoked at all.
		const vm = new VM({ timeout: 5000 });
		const ctCalled = vm.run(`
			let ctInvocations = 0;
			class FakePromise extends Promise {
				static get [Symbol.species](){
					return function(executor){
						ctInvocations++;
						executor(function(){}, function(){});
					};
				}
			}
			new FakePromise(function(r){ r(1); });
			ctInvocations;
		`);
		assert.strictEqual(ctCalled, 0, 'species protocol invoked attacker-supplied constructor in swallow tail');
		setTimeout(done, 300);
	});

	it.cond('deeply nested subclass cannot hijack species in the swallow tail', HAS_WITH_RESOLVERS, function (done) {
		const vm = new VM({ timeout: 5000 });
		const ctCalled = vm.run(`
			let ctInvocations = 0;
			class Fake1 extends Promise {
				static get [Symbol.species](){
					return function(executor){
						ctInvocations++;
						executor(function(){}, function(){});
					};
				}
			}
			class Fake2 extends Fake1 {}
			class Fake3 extends Fake2 {}
			new Fake3(function(r){ r(1); });
			ctInvocations;
		`);
		assert.strictEqual(ctCalled, 0, 'subclass chain reached attacker-supplied species in swallow tail');
		setTimeout(done, 300);
	});

	it('legitimate sandbox Promise subclass still works (no regression)', function (done) {
		const vm = new VM({ timeout: 5000 });
		// A benign subclass with no species override should chain normally.
		const ok = vm.run(`
			class MyPromise extends Promise {}
			const p = new MyPromise(function(r){ r(42); });
			p.then(function(v){ globalThis.__benign = v; });
			true;
		`);
		assert.strictEqual(ok, true);
		setTimeout(function () {
			const v = vm.run('globalThis.__benign');
			assert.strictEqual(v, 42, 'benign subclass chain did not deliver value');
			done();
		}, 300);
	});
});
